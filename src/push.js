// SPDX-License-Identifier: AGPL-3.0-or-later
import { change_push_rule, default_push_rules, push_actions } from '../room-v10/pkg/relay_room_v10.js';
import { clientEvent, domain, eventId } from './graph.js';
import { fail, isObject, missing, ok, openParty } from './rooms.js';
import { limited } from './media.js';

export function pushSchema(sql) {
  sql.exec(`CREATE TABLE IF NOT EXISTS pushers(id INTEGER PRIMARY KEY AUTOINCREMENT,user TEXT NOT NULL,device TEXT NOT NULL,app TEXT NOT NULL,pushkey TEXT NOT NULL,config TEXT NOT NULL,UNIQUE(user,app,pushkey));
    CREATE TABLE IF NOT EXISTS push_jobs(pusher INTEGER NOT NULL,event TEXT NOT NULL,room TEXT NOT NULL,sender TEXT NOT NULL,due INTEGER NOT NULL,expires INTEGER NOT NULL,attempt INTEGER DEFAULT 0,PRIMARY KEY(pusher,event));
    CREATE INDEX IF NOT EXISTS push_due ON push_jobs(due);
    CREATE TRIGGER IF NOT EXISTS retire_push_jobs AFTER DELETE ON pushers BEGIN DELETE FROM push_jobs WHERE pusher=OLD.id; END;`);
}

const invalid = (msg) => fail(400, 'M_INVALID_PARAM', msg);
const bytes = (s) => typeof s === 'string' && new TextEncoder().encode(s).length;
function gatewayAllowed(home, url) {
  return typeof url === 'string' && url.startsWith('https://') && home.env.PUSH_GATEWAYS?.includes(url);
}

export function pusherApi(home, auth, method, parts, body) {
  const { sql } = home,
    { user_id: user, device_id: device } = auth;
  if (method === 'GET' && parts.length === 1)
    return ok({
      pushers: sql
        .exec('SELECT config FROM pushers WHERE user=?', user)
        .toArray()
        .map((r) => JSON.parse(r.config))
    });
  if (method !== 'POST' || parts.length !== 2 || parts[1] !== 'set') missing();
  const { app_id: app, pushkey, kind, data } = body;
  if (!bytes(app) || bytes(app) > 64 || !bytes(pushkey) || bytes(pushkey) > 512)
    invalid('Invalid pusher identifiers');
  if (kind === null) {
    sql.exec('DELETE FROM pushers WHERE user=? AND app=? AND pushkey=?', user, app, pushkey);
    return ok();
  }
  if (kind !== 'http' || !isObject(data) || !gatewayAllowed(home, data.url))
    invalid('Unsupported push gateway');
  if (data.format !== 'event_id_only') invalid('Unsupported push format');
  if (bytes(JSON.stringify(data)) > 4096 || (body.append !== undefined && typeof body.append !== 'boolean'))
    invalid('Invalid pusher data');
  const config = { kind, app_id: app, pushkey, data };
  for (const key of ['app_display_name', 'device_display_name', 'lang', 'profile_tag']) {
    if (key === 'profile_tag' && body[key] === undefined) continue;
    if (typeof body[key] !== 'string' || bytes(body[key]) > 512) invalid('Invalid ' + key);
    config[key] = body[key];
  }
  home.ctx.storage.transactionSync(() => {
    if (!sql.exec('SELECT 1 FROM devices WHERE user=? AND device=?', user, device).toArray().length)
      fail(401, 'M_UNKNOWN_TOKEN', 'Device signed out');
    const count = sql
      .exec(
        'SELECT COUNT(*) AS n FROM pushers WHERE user=? AND NOT (app=? AND pushkey=?)',
        user,
        app,
        pushkey
      )
      .one().n;
    if (count >= 64) fail(400, 'M_INVALID_PARAM', 'Too many push registrations');
    if (!body.append)
      sql.exec('DELETE FROM pushers WHERE user<>? AND app=? AND pushkey=?', user, app, pushkey);
    sql.exec(
      'DELETE FROM pushers WHERE user=? AND app=? AND pushkey=? AND device<>?',
      user,
      app,
      pushkey,
      device
    );
    sql.exec(
      'INSERT INTO pushers(user,device,app,pushkey,config) VALUES(?,?,?,?,?) ON CONFLICT(user,app,pushkey) DO UPDATE SET config=excluded.config',
      user,
      device,
      app,
      pushkey,
      JSON.stringify(config)
    );
  });
  return ok();
}

export function rulesFor(sql, user) {
  const row = sql
    .exec("SELECT content FROM user_data WHERE user=? AND kind='m.push_rules'", user)
    .toArray()[0];
  return fullRules(row ? JSON.parse(row.content).global : JSON.parse(default_push_rules(user)));
}
const kinds = ['override', 'content', 'room', 'sender', 'underride'];
function fullRules(rules) {
  return Object.fromEntries(kinds.map((kind) => [kind, rules[kind] ?? []]));
}
export function rulesApi(home, user, method, parts, params, body) {
  const [, scope, kind, id, field] = parts;
  const rules = rulesFor(home.sql, user);
  if (
    parts.length > 5 ||
    (scope && scope !== 'global') ||
    (kind && !kinds.includes(kind)) ||
    (field && !['actions', 'enabled'].includes(field))
  )
    missing();
  const rule = kind && rules[kind].find((r) => r.rule_id === id);
  if (method === 'GET') {
    if (!scope) return ok({ global: rules });
    if (!kind) return ok(rules);
    if (!id) return ok(rules[kind]);
    if (!rule) missing();
    return ok(field ? { [field]: rule[field] } : rule);
  }
  if (!id || (method !== 'PUT' && method !== 'DELETE') || (method === 'DELETE' && field)) missing();
  if ((field || method === 'DELETE') && !rule) missing();
  if (bytes(JSON.stringify(body ?? {})) > 8192) invalid('Push rule too large');
  let updated;
  try {
    updated = change_push_rule(
      JSON.stringify(rules),
      kind,
      id,
      method === 'DELETE' ? 'delete' : field || 'insert',
      JSON.stringify(body ?? {}),
      params.get('after') ?? undefined,
      params.get('before') ?? undefined
    );
  } catch {
    invalid('Invalid push rule');
  }
  if (bytes(updated) > 131072) invalid('Too many push rules');
  home.sql.exec(
    "INSERT OR REPLACE INTO user_data(user,kind,content) VALUES(?,'m.push_rules',?)",
    user,
    JSON.stringify({ global: fullRules(JSON.parse(updated)) })
  );
  return ok();
}

function ignored(sql, user, sender) {
  const row = sql
    .exec("SELECT content FROM user_data WHERE user=? AND kind='m.ignored_user_list'", user)
    .toArray()[0];
  return row && Object.hasOwn(JSON.parse(row.content).ignored_users ?? {}, sender);
}

// Called once for the live head, in the transaction that commits it. Historical catch-up
// and soft-failed PDUs do not generate a burst of old alerts.
export function queuePush(home, server, g, pdu) {
  if (
    !['m.room.message', 'm.room.encrypted'].includes(pdu.type) ||
    pdu.state_key !== undefined ||
    !home.sql.exec('SELECT 1 FROM pushers LIMIT 1').toArray().length
  )
    return;
  const id = eventId(pdu, g.version);
  if (g.softFailed.has(id)) return;
  const state = g.before([id]),
    members = state.filter((e) => e.type === 'm.room.member' && e.content.membership === 'join');
  const powers = state.find((e) => e.type === 'm.room.power_levels' && e.state_key === '')?.content ?? {};
  for (const member of members) {
    const user = member.state_key;
    if (
      domain(user) !== server ||
      user === pdu.sender ||
      g.get('m.room.member', user)?.content.membership !== 'join'
    )
      continue;
    const pushers = home.sql.exec('SELECT id FROM pushers WHERE user=?', user).toArray();
    if (!pushers.length || ignored(home.sql, user, pdu.sender)) continue;
    let actions;
    try {
      actions = JSON.parse(
        push_actions(
          JSON.stringify(rulesFor(home.sql, user)),
          JSON.stringify(clientEvent(pdu, id)),
          g.room,
          user,
          typeof member.content.displayname === 'string'
            ? member.content.displayname
            : user.slice(1, user.indexOf(':')),
          members.length,
          JSON.stringify(powers)
        )
      );
    } catch {
      // An unreadable legacy rule must not stop the room transaction or alert this recipient.
      continue;
    }
    if (!actions.includes('notify')) continue;
    const now = Date.now();
    for (const p of pushers)
      home.sql.exec(
        'INSERT OR IGNORE INTO push_jobs(pusher,event,room,sender,due,expires) VALUES(?,?,?,?,?,?)',
        p.id,
        id,
        g.room,
        pdu.sender,
        now,
        now + 86400000
      );
  }
}

export async function dispatchPush(home, send = fetch) {
  const { sql } = home;
  const rows = sql
    .exec(
      'SELECT j.*,p.user,p.config FROM push_jobs j JOIN pushers p ON p.id=j.pusher WHERE j.due<=? ORDER BY j.due LIMIT 16',
      Date.now()
    )
    .toArray();
  for (const job of rows) {
    const { data, app_id, pushkey } = JSON.parse(job.config),
      server = domain(job.user);
    const done = () => sql.exec('DELETE FROM push_jobs WHERE pusher=? AND event=?', job.pusher, job.event);
    const member = sql
      .exec(
        "SELECT json_extract(e.pdu,'$.content.membership') AS membership FROM room_state s JOIN room_known_events e ON e.eid=s.eid AND e.room=s.room WHERE s.room=? AND s.kind='m.room.member' AND s.skey=?",
        job.room,
        job.user
      )
      .toArray()[0];
    if (
      job.expires <= Date.now() ||
      !gatewayAllowed(home, data.url) ||
      member?.membership !== 'join' ||
      ignored(sql, job.user, job.sender)
    ) {
      done();
      continue;
    }
    let stage = 'policy', status = 0;
    try {
      await openParty(home, server, job.user);
      await openParty(home, server, job.sender);
      if (!sql.exec('SELECT 1 FROM push_jobs j JOIN pushers p ON p.id=j.pusher WHERE j.pusher=? AND j.event=? AND p.config=?', job.pusher, job.event, job.config).toArray().length)
        continue;
      if (ignored(sql, job.user, job.sender)) {
        done();
        continue;
      }
      const { url, ...deviceData } = data;
      stage = 'gateway';
      const response = await send(url, {
        method: 'POST',
        redirect: 'manual',
        signal: AbortSignal.timeout(7000),
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          notification: {
            event_id: job.event,
            room_id: job.room,
            prio: 'high',
            counts: {},
            devices: [{ app_id, pushkey, data: deviceData }]
          }
        })
      });
      status = response.status;
      if (!response.ok) throw Error('Gateway unavailable');
      const answer = JSON.parse(new TextDecoder().decode(await limited(response.body, 65536)));
      if (!Array.isArray(answer.rejected)) throw Error('Invalid gateway response');
      console.info('Matrix push gateway', status, answer.rejected.includes(pushkey) ? 'rejected' : 'accepted');
      if (answer.rejected.includes(pushkey))
        sql.exec('DELETE FROM pushers WHERE id=? AND config=?', job.pusher, job.config);
      done();
    } catch {
      if (!job.attempt || job.attempt === 5) console.warn('Matrix push retry', stage, status);
      sql.exec(
        'UPDATE push_jobs SET attempt=attempt+1,due=? WHERE pusher=? AND event=?',
        Date.now() + Math.min(300000, 2000 * 2 ** Math.min(job.attempt, 8)),
        job.pusher,
        job.event
      );
    }
  }
}
