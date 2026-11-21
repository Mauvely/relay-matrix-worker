// SPDX-License-Identifier: AGPL-3.0-or-later
import { canonical } from './identity.js';
import { domain } from './graph.js';
import { ok, fail, isObject, openParty, queue } from './rooms.js';
import { remote } from './federation.js';

export function keySchema(sql) {
  sql.exec(`CREATE TABLE IF NOT EXISTS device_keys(user TEXT,device TEXT,body TEXT,PRIMARY KEY(user,device));
  CREATE TABLE IF NOT EXISTS otk(user TEXT,device TEXT,id TEXT,alg TEXT,fallback INTEGER,body TEXT,used INTEGER DEFAULT 0,PRIMARY KEY(user,device,id));
  CREATE TABLE IF NOT EXISTS signing(user TEXT,usage TEXT,body TEXT,PRIMARY KEY(user,usage));
  CREATE TABLE IF NOT EXISTS key_changes(seq INTEGER PRIMARY KEY AUTOINCREMENT,user TEXT);
  CREATE TABLE IF NOT EXISTS key_signatures(signer TEXT,target TEXT,id TEXT,body TEXT,PRIMARY KEY(signer,target,id));`);
}
export function keyCounts(home, user, device) {
  const counts = { signed_curve25519: 0 };
  for (const { alg, n } of home.sql.exec(
    'SELECT alg,count(*) AS n FROM otk WHERE user=? AND device=? AND fallback=0 GROUP BY alg',
    user,
    device
  ))
    counts[alg] = n;
  const fallback = home.sql
    .exec('SELECT DISTINCT alg FROM otk WHERE user=? AND device=? AND fallback=1 AND used=0', user, device)
    .toArray()
    .map((r) => r.alg);
  return { counts, fallback };
}
export function sharedUsers(home, user) {
  const rows = home.sql.exec(
    `SELECT DISTINCT b.skey AS user FROM room_state a JOIN room_state b ON b.room=a.room
  JOIN room_events ea ON ea.eid=a.eid JOIN room_events eb ON eb.eid=b.eid
  WHERE a.kind='m.room.member' AND b.kind=a.kind AND a.skey=? AND json_extract(ea.pdu,'$.content.membership')='join' AND json_extract(eb.pdu,'$.content.membership')='join'`,
    user
  );
  return new Set([user, ...rows.toArray().map((r) => r.user)]);
}
function changed(home, server, user, device, keys) {
  const last = home.sql.exec('SELECT MAX(seq) AS n FROM key_changes WHERE user=?', user).one().n;
  home.sql.exec('INSERT INTO key_changes(user) VALUES(?)', user);
  const stream = home.sql.exec('SELECT last_insert_rowid() AS n').one().n;
  for (const peer of new Set([...sharedUsers(home, user)].map(domain)))
    if (peer !== server)
      queue(
        home,
        server,
        peer,
        [],
        [
          {
            edu_type: 'm.device_list_update',
            content: {
              user_id: user,
              device_id: device,
              stream_id: stream,
              prev_id: last ? [last] : [],
              keys
            }
          }
        ]
      );
}
const bad = () => fail(400, 'M_INVALID_PARAM', 'Key identity or format is invalid');
const usageMap = { master_key: 'master', self_signing_key: 'self_signing', user_signing_key: 'user_signing' };
function unsigned(object) {
  const { signatures, unsigned, ...signed } = object;
  return signed;
}
async function validSignature(key, object, signature) {
  try {
    const bytes = (value) => Uint8Array.from(atob(value), (c) => c.charCodeAt(0));
    const pub = await crypto.subtle.importKey('raw', bytes(key), 'Ed25519', false, ['verify']);
    return await crypto.subtle.verify(
      'Ed25519',
      pub,
      bytes(signature),
      new TextEncoder().encode(canonical(unsigned(object)))
    );
  } catch {
    return false;
  }
}
async function storeSignatures(home, user, body) {
  const publicKeys = new Map();
  for (const r of home.sql.exec(
    'SELECT body FROM device_keys WHERE user=? UNION ALL SELECT body FROM signing WHERE user=?',
    user,
    user
  )) {
    for (const [id, key] of Object.entries(JSON.parse(r.body).keys))
      if (id.startsWith('ed25519:')) publicKeys.set(id, key);
  }
  const failures = Object.create(null);
  for (const [target, entries] of Object.entries(body))
    for (const [id, obj] of Object.entries(entries)) {
      const sigs = obj.signatures?.[user];
      if (!isObject(sigs) || obj.user_id !== target) bad();
      const verified = Object.create(null);
      for (const [key, sig] of Object.entries(sigs))
        if (publicKeys.has(key) && (await validSignature(publicKeys.get(key), obj, sig))) verified[key] = sig;
      if (!Object.keys(verified).length) {
        failures[target] ??= Object.create(null);
        failures[target][id] = {
          errcode: 'M_INVALID_SIGNATURE',
          error: 'No valid signature from the authenticated user'
        };
      } else {
        const prior = home.sql
          .exec('SELECT body FROM key_signatures WHERE signer=? AND target=? AND id=?', user, target, id)
          .toArray()[0];
        home.sql.exec(
          'INSERT OR REPLACE INTO key_signatures VALUES(?,?,?,?)',
          user,
          target,
          id,
          JSON.stringify({ ...JSON.parse(prior?.body ?? '{}'), ...verified })
        );
      }
    }
  return failures;
}
export function upload(home, server, user, device, body) {
  const key = body.device_keys;
  if (key && (key.user_id !== user || key.device_id !== device || !isObject(key.keys))) bad();
  for (const name of ['one_time_keys', 'fallback_keys'])
    if (body[name] && (!isObject(body[name]) || Object.keys(body[name]).length > 200)) bad();
  home.ctx.storage.transactionSync(() => {
    if (key) {
      const encoded = JSON.stringify(key);
      const old = home.sql
        .exec('SELECT body FROM device_keys WHERE user=? AND device=?', user, device)
        .toArray()[0];
      if (old?.body !== encoded) {
        home.sql.exec('INSERT OR REPLACE INTO device_keys VALUES(?,?,?)', user, device, encoded);
        changed(home, server, user, device, key);
      }
    }
    for (const [fallback, list] of [
      [0, body.one_time_keys],
      [1, body.fallback_keys]
    ])
      for (const [id, value] of Object.entries(list ?? {})) {
        const sep = id.indexOf(':');
        if (sep <= 0 || sep === id.length - 1) bad();
        const alg = id.slice(0, sep);
        if (fallback)
          home.sql.exec(
            'DELETE FROM otk WHERE user=? AND device=? AND alg=? AND fallback=1 AND id!=?',
            user,
            device,
            alg,
            id
          );
        home.sql.exec(
          'INSERT OR IGNORE INTO otk(user,device,id,alg,fallback,body) VALUES(?,?,?,?,?,?)',
          user,
          device,
          id,
          alg,
          fallback,
          JSON.stringify(value)
        );
      }
  });
  return ok({ one_time_key_counts: keyCounts(home, user, device).counts });
}
export function localKeys(home, server, kind, query, requester) {
  const claim = kind === 'claim',
    out = claim
      ? { one_time_keys: Object.create(null) }
      : {
          device_keys: Object.create(null),
          master_keys: Object.create(null),
          self_signing_keys: Object.create(null),
          user_signing_keys: Object.create(null)
        };
  home.ctx.storage.transactionSync(() => {
    for (const [user, wanted] of Object.entries(query)) {
      if (domain(user) !== server) bad();
      if (claim) {
        if (!isObject(wanted)) bad();
        const result = Object.create(null);
        for (const [device, alg] of Object.entries(wanted)) {
          const r = home.sql
            .exec(
              'SELECT * FROM otk WHERE user=? AND device=? AND alg=? ORDER BY fallback,id LIMIT 1',
              user,
              device,
              alg
            )
            .toArray()[0];
          if (!r) continue;
          result[device] = { [r.id]: JSON.parse(r.body) };
          home.sql.exec(
            r.fallback
              ? 'UPDATE otk SET used=1 WHERE user=? AND device=? AND id=?'
              : 'DELETE FROM otk WHERE user=? AND device=? AND id=?',
            user,
            device,
            r.id
          );
        }
        out.one_time_keys[user] = result;
        continue;
      }
      if (!Array.isArray(wanted)) bad();
      const devices = (out.device_keys[user] = Object.create(null));
      const addSigs = (obj, id) => {
        for (const row of home.sql.exec(
          'SELECT signer,body FROM key_signatures WHERE target=? AND id=? AND (signer=? OR signer=?)',
          user,
          id,
          user,
          requester ?? ''
        )) {
          obj.signatures ??= {};
          obj.signatures[row.signer] = { ...obj.signatures[row.signer], ...JSON.parse(row.body) };
        }
        return obj;
      };
      for (const r of home.sql.exec('SELECT device,body FROM device_keys WHERE user=?', user)) {
        if (!wanted.length || wanted.includes(r.device))
          devices[r.device] = addSigs(JSON.parse(r.body), r.device);
      }
      for (const r of home.sql.exec('SELECT usage,body FROM signing WHERE user=?', user)) {
        if (r.usage === 'user_signing' && requester !== user) continue;
        const obj = JSON.parse(r.body);
        out[r.usage + '_keys'][user] = addSigs(obj, Object.values(obj.keys)[0]);
      }
    }
  });
  return out;
}
export async function clientKeys(home, server, auth, kind, body) {
  const user = auth.user_id;
  if (kind === 'upload') return upload(home, server, user, auth.device_id, body);
  if (kind === 'device_signing/upload') {
    // Replacing a published identity needs password confirmation, including on a logged-in device.
    if (home.sql.exec('SELECT 1 FROM signing WHERE user=?', user).toArray().length) {
      const { password } = body.auth ?? {};
      const account = await home.ctx.storage.get('account/' + user.slice(1, -server.length - 1));
      const digest =
        typeof password === 'string'
          ? Array.from(
              new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(password))),
              (b) => b.toString(16).padStart(2, '0')
            ).join('')
          : '';
      if (account?.passwordHash !== digest)
        return {
          status: 401,
          body: { flows: [{ stages: ['m.login.password'] }], params: {}, session: 'replace-signing-keys' }
        };
    }
    for (const [name, usage] of Object.entries(usageMap)) {
      const key = body[name];
      if (
        key &&
        (key.user_id !== user ||
          key.usage?.length !== 1 ||
          key.usage[0] !== usage ||
          !isObject(key.keys) ||
          Object.keys(key.keys).length !== 1)
      )
        bad();
    }
    home.ctx.storage.transactionSync(() => {
      for (const [name, usage] of Object.entries(usageMap))
        if (body[name])
          home.sql.exec(
            'INSERT OR REPLACE INTO signing VALUES(?,?,?)',
            user,
            usage,
            JSON.stringify(body[name])
          );
      if (body.master_key || body.self_signing_key) {
        const content = {
          user_id: user,
          master_key: body.master_key,
          self_signing_key: body.self_signing_key
        };
        for (const peer of new Set([...sharedUsers(home, user)].map(domain))) {
          if (peer !== server) queue(home, server, peer, [], [{ edu_type: 'm.signing_key_update', content }]);
        }
      }
      changed(home, server, user, auth.device_id, undefined);
    });
    return ok();
  }
  if (kind === 'signatures/upload') {
    const failures = await storeSignatures(home, user, body);
    changed(home, server, user, auth.device_id, undefined);
    return ok({ failures });
  }
  if (!['query', 'claim'].includes(kind)) fail(404, 'M_NOT_FOUND', 'Unknown key operation');
  const field = kind === 'query' ? 'device_keys' : 'one_time_keys',
    query = body[field];
  if (!isObject(query) || Object.keys(query).length > 100) bad();
  const groups = new Map();
  for (const [id, ids] of Object.entries(query)) {
    const d = domain(id);
    if (!d) bad();
    if (!groups.has(d)) groups.set(d, Object.create(null));
    groups.get(d)[id] = ids;
  }
  const out = {
    ...localKeys(home, server, kind, groups.get(server) ?? {}, user),
    failures: Object.create(null)
  };
  for (const [peer, queries] of groups)
    if (peer !== server) {
      try {
        await openParty(home, server, user);
        const resp = await (
          await remote(home, server, peer, 'POST', '/_matrix/federation/v1/user/keys/' + kind, {
            [field]: queries
          })
        ).json();
        for (const k of [field, 'master_keys', 'self_signing_keys'])
          for (const [id, keys] of Object.entries(resp[k] ?? {}))
            if (domain(id) === peer && Object.hasOwn(queries, id) && out[k]) out[k][id] = keys;
        // A user's private signatures on a remote master key are stored by their own homeserver.
        for (const [target, obj] of Object.entries(out.master_keys ?? {})) {
          const id = Object.values(obj.keys)[0],
            row = home.sql
              .exec('SELECT body FROM key_signatures WHERE signer=? AND target=? AND id=?', user, target, id)
              .toArray()[0];
          if (row) {
            obj.signatures ??= {};
            obj.signatures[user] = JSON.parse(row.body);
          }
        }
      } catch {
        out.failures[peer] = { errcode: 'M_UNAVAILABLE', error: 'Key request failed' };
      }
    }
  return ok(out);
}
