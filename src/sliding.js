// SPDX-License-Identifier: AGPL-3.0-or-later
import { projectedState } from './redactions.js';
import { clientEvent } from './graph.js';
import { fail, isObject, joinFloor, openParty, pageToken } from './rooms.js';
import { permittedDeviceEvents } from './device.js';

export const slidingPath = '/_matrix/client/unstable/org.matrix.simplified_msc3575/sync';
const invalid = () => fail(400, 'M_INVALID_PARAM', 'Invalid sliding sync request');
const unknown = () => fail(400, 'M_UNKNOWN_POS', 'Restart this sync connection');
const own = (object, key) => (Object.hasOwn(object, key) ? object[key] : undefined);

export function slidingSchema(sql) {
  sql.exec(
    'CREATE TABLE IF NOT EXISTS sliding_positions(pos TEXT PRIMARY KEY,user TEXT,device TEXT,conn TEXT,snapshot TEXT,expires INTEGER); CREATE INDEX IF NOT EXISTS sliding_client ON sliding_positions(user,device,conn); CREATE INDEX IF NOT EXISTS sliding_expiry ON sliding_positions(expires); CREATE TABLE IF NOT EXISTS sliding_device_cursors(user TEXT,device TEXT,high INTEGER,PRIMARY KEY(user,device))'
  );
}

function config(value) {
  if (!isObject(value)) invalid();
  const { required_state: state = [], timeline_limit: limit = 0 } = value;
  if (
    !Number.isSafeInteger(limit) ||
    limit < 0 ||
    !Array.isArray(state) ||
    state.length > 256 ||
    !state.every((p) => Array.isArray(p) && p.length === 2 && p.every((s) => typeof s === 'string'))
  )
    invalid();
  return { state, limit: Math.min(limit, 100) };
}

function selectRooms(body, entries) {
  const lists = Object.create(null),
    selected = new Map();
  const add = (r, conf) => {
    const other = selected.get(r.id);
    selected.set(
      r.id,
      other ? { limit: Math.max(conf.limit, other.limit), state: [...other.state, ...conf.state] } : conf
    );
  };
  for (const [key, list] of Object.entries(body.lists ?? {})) {
    const conf = config(list);
    const filters = list.filters ?? {};
    if (
      !isObject(filters) ||
      Object.keys(filters).some(
        (k) => !['is_invite', 'is_dm', 'is_encrypted', 'room_types', 'not_room_types'].includes(k)
      )
    )
      invalid();
    const matching = entries.filter(
      (e) =>
        (filters.is_invite === undefined || filters.is_invite === (e.membership === 'invite')) &&
        (filters.is_dm === undefined || filters.is_dm === e.dm) &&
        (filters.is_encrypted === undefined || filters.is_encrypted === e.encrypted) &&
        (!filters.room_types || filters.room_types.includes(e.type)) &&
        (!filters.not_room_types || !filters.not_room_types.includes(e.type))
    );
    const ranges = list.ranges ?? (list.range ? [list.range] : [[0, Math.max(0, matching.length - 1)]]);
    if (!Array.isArray(ranges) || ranges.length > 100) invalid();
    const ops = [];
    for (const pair of ranges) {
      if (
        !Array.isArray(pair) ||
        pair.length !== 2 ||
        !pair.every(Number.isSafeInteger) ||
        pair[0] < 0 ||
        pair[1] < pair[0]
      )
        invalid();
      const window = matching.slice(pair[0], pair[1] + 1);
      window.forEach((r) => add(r, conf));
      if (window.length)
        ops.push({
          op: 'SYNC',
          range: [pair[0], pair[0] + window.length - 1],
          room_ids: window.map((r) => r.id)
        });
    }
    lists[key] = { count: matching.length, ops };
  }
  for (const [id, sub] of Object.entries(body.room_subscriptions ?? {})) {
    const conf = config(sub),
      entry = entries.find((r) => r.id === id);
    if (entry) add(entry, conf);
  }
  return { lists, selected };
}

function roomEntries(home, user, seen) {
  const { sql } = home;
  const direct = sql
    .exec("SELECT content FROM user_data WHERE user=? AND kind='m.direct'", user)
    .toArray()[0];
  const dms = new Set(
    Object.values(JSON.parse(direct?.content ?? '{}'))
      .filter(Array.isArray)
      .flat()
  );
  const entries = new Map();
  const read = (id, state, membership, seq) => {
    const content = (kind) => state.find((e) => e.type === kind && e.state_key === '')?.content;
    entries.set(id, {
      id,
      state,
      membership,
      seq,
      dm: dms.has(id),
      encrypted: !!content('m.room.encryption'),
      type: content('m.room.create')?.type ?? null
    });
  };
  for (const row of sql.exec('SELECT room,seq,stripped FROM remote_invites WHERE user=?', user).toArray()) {
    read(row.room, JSON.parse(row.stripped), 'invite', row.seq);
  }
  for (const row of sql
    .exec(
      "SELECT s.room,s.eid,e.pdu FROM room_state s JOIN room_known_events e ON e.eid=s.eid AND e.room=s.room WHERE s.kind='m.room.member' AND s.skey=? AND NOT EXISTS(SELECT 1 FROM room_forgets f WHERE f.room=s.room AND f.user=s.skey AND f.member_eid=s.eid)",
      user
    )
    .toArray()) {
    const member = JSON.parse(row.pdu),
      membership = member.content.membership;
    if (!['join', 'invite'].includes(membership) && !own(seen, row.room) && member.sender === user) continue;
    if (!['join', 'invite', 'ban', 'leave'].includes(membership)) continue;
    const full = membership === 'join' || membership === 'invite';
    const state = full
      ? sql
          .exec(
            'SELECT s.eid,e.pdu FROM room_state s JOIN room_known_events e ON e.eid=s.eid AND e.room=s.room WHERE s.room=?',
            row.room
          )
          .toArray()
          .map((r) => projectedState(sql, row.room, r.eid, JSON.parse(r.pdu)))
      : [clientEvent(member, row.eid)];
    const seq =
      full && membership === 'join'
        ? sql.exec('SELECT MAX(seq) AS n FROM room_client_events WHERE room=?', row.room).one().n
        : sql
            .exec(
              "SELECT MAX(seq) AS n FROM room_client_events WHERE room=? AND json_extract(pdu,'$.state_key')=? AND json_extract(pdu,'$.type')='m.room.member'",
              row.room,
              user
            )
            .one().n;
    read(row.room, state, membership, seq ?? 0);
  }
  return [...entries.values()].sort((a, b) => b.seq - a.seq || a.id.localeCompare(b.id));
}

async function renderRoom(home, server, user, r, conf, prior) {
  const members = r.state.filter((e) => e.type === 'm.room.member');
  if (r.membership === 'invite') {
    const me = members.find((e) => e.state_key === user);
    const events = r.state.filter(
      (e) =>
        [
          'm.room.create',
          'm.room.join_rules',
          'm.room.name',
          'm.room.encryption',
          'm.room.avatar',
          'm.room.canonical_alias'
        ].includes(e.type) ||
        (e.type === 'm.room.member' && [user, me?.sender].includes(e.state_key))
    );
    return {
      initial: true,
      invite_state: events.map(({ sender, type, state_key, content }) => ({
        sender,
        type,
        state_key,
        content
      })),
      membership: 'invite',
      bump_stamp: r.seq
    };
  }
  if (r.membership !== 'join')
    return { membership: r.membership, required_state: r.state, timeline: r.state, bump_stamp: r.seq };
  const floor = joinFloor(home, r.id, user);
  if (floor === null) return;
  const initial = prior?.membership !== 'join' || floor > prior.seq;
  const expanded = !initial && conf.limit > prior.limit;
  const oldest = initial || expanded ? floor : Math.max(floor, prior.seq + 1);
  const rows = home.sql
    .exec(
      'SELECT seq,eid,pdu,cause FROM room_visible_events WHERE room=? AND seq>=? AND seq<=? ORDER BY seq DESC LIMIT ?',
      r.id,
      oldest,
      r.seq,
      conf.limit + 1
    )
    .toArray();
  const limited = rows.length > conf.limit;
  if (limited) rows.pop();
  rows.reverse();
  const timeline = rows.map((e) => clientEvent(JSON.parse(e.pdu), e.eid, e.cause));
  const senders = new Set(timeline.map((e) => e.sender));
  const required = r.state.filter((e) =>
    conf.state.some(
      ([type, key]) =>
        (type === '*' || type === e.type) &&
        (key === '*' ||
          (key === '$ME' ? user : key) === e.state_key ||
          (key === '$LAZY' && e.type === 'm.room.member' && senders.has(e.state_key)))
    )
  );
  const field = (type, key) =>
    r.state.find((e) => e.type === type && e.state_key === '')?.content[key] ?? null;
  const name = field('m.room.name', 'name');
  const active = members.filter((m) => ['join', 'invite'].includes(m.content.membership));
  const heroes = active
    .filter((m) => m.state_key !== user)
    .slice(0, 5)
    .map((m) => ({
      user_id: m.state_key,
      displayname: m.content.displayname,
      avatar_url: m.content.avatar_url
    }));
  return {
    membership: 'join',
    initial,
    name,
    avatar: field('m.room.avatar', 'url'),
    heroes: name ? [] : heroes,
    joined_count: active.filter((m) => m.content.membership === 'join').length,
    invited_count: active.filter((m) => m.content.membership === 'invite').length,
    is_dm: r.dm,
    bump_stamp: r.seq,
    required_state: required,
    timeline,
    limited,
    num_live: prior ? rows.filter((e) => e.seq > prior.seq).length : 0,
    ...(rows.length ? { prev_batch: pageToken(r.id, rows[0].seq) } : {}),
    ...(expanded ? { unstable_expanded_timeline: true } : {})
  };
}

export async function slidingSync(home, server, auth, body, query) {
  const { user_id: user, device_id: device } = auth,
    params = new URLSearchParams(query);
  const conn = body.conn_id ?? '',
    pos = params.get('pos') ?? body.pos;
  if (
    typeof conn !== 'string' ||
    conn.length > 64 ||
    ![body.lists, body.extensions, body.room_subscriptions].every((v) => v === undefined || isObject(v)) ||
    [body.lists, body.room_subscriptions].some((v) => Object.keys(v ?? {}).length > 100)
  )
    invalid();
  const ctx = home.sql;
  ctx.exec('DELETE FROM sliding_positions WHERE expires < ?', Date.now());
  const row =
    pos &&
    ctx
      .exec(
        'SELECT snapshot FROM sliding_positions WHERE pos=? AND user=? AND device=? AND conn=?',
        pos,
        user,
        device,
        conn
      )
      .toArray()[0];
  if (pos && !row) unknown();
  const old = row ? JSON.parse(row.snapshot) : { rooms: {}, key: 0, account: 0 };
  const ext = body.extensions ?? {},
    td = ext.to_device;
  const since = td?.since ?? '0';
  if (typeof since !== 'string' || !/^\d{1,15}$/.test(since)) invalid();
  const deviceLimit = td?.limit ?? 100;
  if (td?.enabled && (!Number.isSafeInteger(deviceLimit) || deviceLimit < 1)) invalid();
  if (
    td?.enabled &&
    Number(since) >
      (ctx
        .exec('SELECT high FROM sliding_device_cursors WHERE user=? AND device=?', user, device)
        .toArray()[0]?.high ?? 0)
  )
    invalid();
  await openParty(home, server, user);
  const read = async () => {
    const seen = Object.create(null),
      rooms = Object.create(null),
      extensions = {};
    const entries =
      Object.keys(body.lists ?? {}).length || Object.keys(body.room_subscriptions ?? {}).length
        ? roomEntries(home, user, old.rooms)
        : [];
    const { lists, selected } = selectRooms(body, entries);
    for (const r of entries) {
      const conf = selected.get(r.id);
      if (!conf) continue;
      for (const member of r.state.filter(
        (e) => e.type === 'm.room.member' && ['join', 'invite'].includes(e.content.membership)
      ))
        await openParty(home, server, member.state_key);
      const prior = own(old.rooms, r.id);
      const track = { seq: r.seq, membership: r.membership, dm: r.dm, limit: conf.limit, state: conf.state };
      seen[r.id] = track;
      if (JSON.stringify(prior) === JSON.stringify(track)) continue;
      const result = await renderRoom(home, server, user, r, conf, prior);
      if (result) rooms[r.id] = result;
    }
    let key = old.key,
      account = old.account,
      activity = Object.keys(rooms).length > 0;
    if (ext.account_data?.enabled) {
      const data = home.userUpdates(user, old.account);
      account = data.high;
      extensions.account_data = { global: data.events, rooms: {} };
      activity ||= data.events.length > 0;
    }
    if (ext.e2ee?.enabled) {
      const keys = home.cryptoUpdates(user, device, old.key);
      key = keys.high;
      const counts = JSON.stringify([keys.counts, keys.fallback]);
      activity ||= keys.changed.length > 0 || counts !== old.counts;
      extensions.e2ee = {
        device_lists: { changed: keys.changed, left: [] },
        device_one_time_keys_count: keys.counts,
        device_unused_fallback_key_types: keys.fallback
      };
    }
    if (td?.enabled) {
      const rows = home.pending(user, device, Number(since)).slice(0, Math.min(deviceLimit, 100));
      extensions.to_device = {
        next_batch: String(rows.at(-1)?.sequence ?? since),
        events: await permittedDeviceEvents(home.env, user, rows)
      };
      activity ||= rows.length > 0;
    }
    const counts = extensions.e2ee
      ? JSON.stringify([
          extensions.e2ee.device_one_time_keys_count,
          extensions.e2ee.device_unused_fallback_key_types
        ])
      : old.counts;
    return { snapshot: { rooms: seen, key, account, counts }, lists, rooms, extensions, activity };
  };
  if (td?.enabled && td.since) home.acknowledge(user, device, Number(since));
  let result = await read();
  const timeout = Math.min(2500, Number(params.get('timeout') ?? body.timeout) || 0);
  if (pos && timeout > 0 && !result.activity) {
    await home.waitForDevice(user, device, td?.enabled ? Number(since) : Number.MAX_SAFE_INTEGER, timeout);
    result = await read();
  }
  if (pos && !ctx.exec('SELECT 1 FROM sliding_positions WHERE pos=?', pos).toArray().length) unknown();
  if (td?.enabled)
    ctx.exec(
      'INSERT INTO sliding_device_cursors VALUES(?,?,?) ON CONFLICT(user,device) DO UPDATE SET high=MAX(high,excluded.high)',
      user,
      device,
      Number(result.extensions.to_device.next_batch)
    );
  const next = crypto.randomUUID();
  // Keep the last acknowledged position usable if this response is lost or cancelled.
  ctx.exec(
    'DELETE FROM sliding_positions WHERE user=? AND device=? AND conn=? AND pos!=?',
    user,
    device,
    conn,
    pos ?? ''
  );
  ctx.exec(
    'INSERT INTO sliding_positions VALUES(?,?,?,?,?,?)',
    next,
    user,
    device,
    conn,
    JSON.stringify(result.snapshot),
    Date.now() + 86400000
  );
  return {
    pos: next,
    lists: result.lists,
    rooms: result.rooms,
    extensions: result.extensions,
    ...(typeof body.txn_id === 'string' ? { txn_id: body.txn_id } : {})
  };
}
