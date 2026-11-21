// SPDX-License-Identifier: AGPL-3.0-or-later
import test from 'node:test';
import assert from 'node:assert/strict';
import { digest, session } from './src/accounts.js';
import { logoutSession, reconcileSessions } from './src/device-sessions.js';
import { clientApi, federationApi } from './src/api.js';
import { upload, localKeys } from './src/keys.js';
import { sessionHome } from './fixtures/session-home.js';

test('existing logins survive reconciliation and retiring one device reaches other clients and peers', async () => {
  const h = sessionHome(),
    { sql } = h,
    { kv } = h.ctx.storage;
  const user = '@sam:a.test',
    peer = '@lee:b.test',
    server = 'a.test';
  h.party = () => ({ organisationId: null });
  for (const member of [user, peer]) {
    sql.exec(
      'INSERT INTO room_events(room,eid,pdu) VALUES(?,?,?)',
      'room',
      member,
      JSON.stringify({ content: { membership: 'join' } })
    );
    sql.exec('INSERT INTO room_state VALUES(?,?,?,?)', 'room', 'm.room.member', member, member);
  }
  for (const device of ['WEB', 'PHONE', 'STALE']) {
    sql.exec('INSERT INTO devices VALUES(?,?)', user, device);
    upload(h, server, user, device, {
      device_keys: { user_id: user, device_id: device, keys: { ed25519: device } },
      one_time_keys: { 'signed_curve25519:1': 'one' },
      fallback_keys: { 'signed_curve25519:2': 'fallback' }
    });
  }
  // Two classic tokens share one device. The phone has an expired access token but a live refresh token.
  const token = 'a'.repeat(64),
    other = 'b'.repeat(64);
  for (const t of [token, other]) kv.put('session/' + (await digest(t)), { user_id: user, device_id: 'WEB' });
  sql.exec(
    'INSERT INTO oauth_sessions VALUES(?,?,?,?,?,?,?,?)',
    'oauth',
    'refresh',
    'client',
    user,
    'PHONE',
    'scope',
    0,
    Date.now() + 3600000
  );
  reconcileSessions(h);
  reconcileSessions(h);
  const keys = () => Object.keys(localKeys(h, server, 'query', { [user]: [] }).device_keys[user]).sort();
  assert.deepEqual(keys(), ['PHONE', 'WEB']);
  assert.equal((await session(h.ctx.storage, 'Bearer ' + token)).status, 200);
  const auth = { user_id: user, device_id: 'WEB' };
  const logout = await logoutSession(h, 'Bearer ' + token);
  assert.equal(logout.status, 200);
  assert.equal((await session(h.ctx.storage, 'Bearer ' + other)).status, 401);
  assert.equal((await logoutSession(h, 'Bearer ' + token)).status, 401);
  assert.deepEqual(keys(), ['PHONE']);
  assert.deepEqual(
    (await federationApi(h, server, 'b.test', 'GET', ['user', 'devices', user], {}, {})).body.devices.map(
      (d) => d.device_id
    ),
    ['PHONE']
  );
  assert.equal(sql.exec('SELECT COUNT(*) AS n FROM otk WHERE device=?', 'WEB').one().n, 0);
  assert.equal(sql.exec('SELECT refresh FROM oauth_sessions').one().refresh, 'refresh');
  await assert.rejects(clientApi(h, server, auth, 'POST', ['keys', 'upload'], {}, {}), {
    errcode: 'M_UNKNOWN_TOKEN'
  });
  const deltas = sql
    .exec('SELECT content FROM outbound ORDER BY rowid')
    .toArray()
    .map((r) => JSON.parse(r.content).edus[0].content)
    .filter((c) => c.deleted);
  assert.deepEqual(
    deltas.map((d) => d.device_id),
    ['STALE', 'WEB']
  );
  assert.ok(deltas.every((d) => d.prev_id.length && !d.keys));
});
