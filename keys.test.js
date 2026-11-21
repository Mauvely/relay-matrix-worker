// SPDX-License-Identifier: AGPL-3.0-or-later
import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { keySchema, upload, localKeys, clientKeys, announceJoinedDevices } from './src/keys.js';
import { schema } from './src/rooms.js';
function testHome() {
  const db = new DatabaseSync(':memory:');
  const sql = {
    exec(q, ...args) {
      if (q.includes(';')) {
        db.exec(q);
        return;
      }
      const rows = db.prepare(q).all(...args);
      return { toArray: () => rows, one: () => rows[0], [Symbol.iterator]: () => rows.values() };
    }
  };
  schema(sql);
  keySchema(sql);
  return { sql, ctx: { storage: { transactionSync: (f) => f() } } };
}
test('one-time keys are consumed once and fallback keys are retained per device', () => {
  const home = testHome(),
    server = 'a.test',
    user = '@sam:a.test',
    device = 'ONE';
  assert.equal(
    upload(home, server, user, device, {
      one_time_keys: { 'signed_curve25519:1': { key: 'one' } },
      fallback_keys: { 'signed_curve25519:2': { key: 'fallback' } }
    }).body.one_time_key_counts.signed_curve25519,
    1
  );
  const claim = () =>
    Object.values(
      localKeys(home, server, 'claim', { [user]: { [device]: 'signed_curve25519' } }).one_time_keys[user][
        device
      ]
    )[0].key;
  assert.deepEqual([claim(), claim(), claim()], ['one', 'fallback', 'fallback']);
  assert.throws(() => localKeys(home, server, 'claim', { '@sam:b.test': { ONE: 'signed_curve25519' } }));
});
test('federated joins and cross-signing updates preserve the published device keys on the peer', async () => {
  const home = testHome(),
    server = 'a.test',
    user = '@sam:a.test';
  for (const [id, member] of [
    ['a', user],
    ['b', '@lee:b.test']
  ]) {
    home.sql.exec(
      'INSERT INTO room_events(room,eid,pdu) VALUES(?,?,?)',
      'room',
      id,
      JSON.stringify({ content: { membership: 'join' } })
    );
    home.sql.exec('INSERT INTO room_state VALUES(?,?,?,?)', 'room', 'm.room.member', member, id);
  }
  const device = { user_id: user, device_id: 'ONE', keys: { 'ed25519:ONE': 'public' } };
  upload(home, server, user, 'ONE', { device_keys: device });
  await clientKeys(home, server, { user_id: user, device_id: 'ONE' }, 'signatures/upload', {});
  announceJoinedDevices(home, server, 'room');
  const rows = home.sql.exec('SELECT content FROM outbound ORDER BY rowid').toArray();
  assert.equal(rows.length, 3);
  for (const row of rows) {
    const edu = JSON.parse(row.content).edus[0];
    assert.equal(edu.edu_type, 'm.device_list_update');
    assert.deepEqual(edu.content.keys, device);
  }
  assert.deepEqual(JSON.parse(rows[2].content).edus[0].content.prev_id, []);
});
