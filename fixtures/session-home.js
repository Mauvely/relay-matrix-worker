// SPDX-License-Identifier: AGPL-3.0-or-later
import { DatabaseSync } from 'node:sqlite';
import { sessionSchema } from '../src/device-sessions.js';
import { oauthSchema } from '../src/oauth.js';
import { slidingSchema } from '../src/sliding.js';
import { keySchema } from '../src/keys.js';
import { schema } from '../src/rooms.js';

export function sessionHome() {
  const db = new DatabaseSync(':memory:');
  const sql = {
    exec(query, ...args) {
      if (query.includes(';')) return db.exec(query);
      const rows = db.prepare(query).all(...args);
      return { one: () => rows[0], toArray: () => rows, [Symbol.iterator]: () => rows.values() };
    }
  };
  const values = new Map();
  const kv = {
    get: (k) => values.get(k),
    put: (k, v) => values.set(k, v),
    delete: (k) => values.delete(k),
    list: ({ prefix, startAfter = '', limit }) =>
      [...values]
        .filter(([k]) => k.startsWith(prefix) && k > startAfter)
        .sort(([a], [b]) => (a < b ? -1 : 1))
        .slice(0, limit)
  };
  const storage = {
    ...kv,
    kv,
    sql,
    transaction(fn) {
      return fn(this);
    },
    transactionSync(fn) {
      db.exec('BEGIN');
      try {
        const result = fn();
        db.exec('COMMIT');
        return result;
      } catch (e) {
        db.exec('ROLLBACK');
        throw e;
      }
    }
  };
  sql.exec(
    'CREATE TABLE devices(user TEXT,device TEXT,PRIMARY KEY(user,device)); CREATE TABLE delivery(user TEXT,device TEXT)'
  );
  oauthSchema(sql);
  sessionSchema(sql);
  keySchema(sql);
  slidingSchema(sql);
  schema(sql);
  return { sql, ctx: { storage } };
}
