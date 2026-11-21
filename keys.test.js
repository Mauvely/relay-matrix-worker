// SPDX-License-Identifier: AGPL-3.0-or-later
import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { keySchema, upload, localKeys } from './src/keys.js';
import { schema } from './src/rooms.js';
test('one-time keys are consumed once and fallback keys are retained per device', () => {
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
  const home = { sql, ctx: { storage: { transactionSync: (f) => f() } } },
    server = 'a.test',
    user = '@sam:a.test',
    device = 'ONE';
  schema(sql);
  keySchema(sql);
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
