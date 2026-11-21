// SPDX-License-Identifier: AGPL-3.0-or-later
import { ok, missing, fail, isObject } from './rooms.js';

export function backupSchema(sql) {
  sql.exec(`CREATE TABLE IF NOT EXISTS backups(id INTEGER PRIMARY KEY AUTOINCREMENT,user TEXT,algorithm TEXT,auth TEXT,etag INTEGER DEFAULT 0);
  CREATE TABLE IF NOT EXISTS sessions_backup(version INTEGER,room TEXT,session TEXT,data TEXT,PRIMARY KEY(version,room,session));`);
}
export function backup(home, user, method, [action, room, session], query, body) {
  const sql = home.sql,
    latest = sql.exec('SELECT * FROM backups WHERE user=? ORDER BY id DESC LIMIT 1', user).toArray()[0];
  if (action === 'version' && method === 'POST') {
    if (!isObject(body.auth_data) || body.algorithm !== 'm.megolm_backup.v1.curve25519-aes-sha2')
      fail(400, 'M_INVALID_PARAM', 'Unsupported backup algorithm');
    const row = sql
      .exec(
        'INSERT INTO backups(user,algorithm,auth) VALUES(?,?,?) RETURNING id',
        user,
        body.algorithm,
        JSON.stringify(body.auth_data)
      )
      .one();
    return ok({ version: String(row.id) });
  }
  const version = action === 'version' ? room : query.get('version');
  const entry = version
    ? sql.exec('SELECT * FROM backups WHERE user=? AND id=?', user, version).toArray()[0]
    : latest;
  if (!entry) missing();
  const count = () => sql.exec('SELECT count(*) AS n FROM sessions_backup WHERE version=?', entry.id).one().n;
  if (action === 'version') {
    if (method === 'GET')
      return ok({
        version: String(entry.id),
        algorithm: entry.algorithm,
        auth_data: JSON.parse(entry.auth),
        etag: String(entry.etag),
        count: count()
      });
    if (method === 'PUT' && body.algorithm === entry.algorithm && isObject(body.auth_data)) {
      sql.exec('UPDATE backups SET auth=? WHERE id=?', JSON.stringify(body.auth_data), entry.id);
      return ok();
    }
    if (method === 'DELETE' && version) {
      home.ctx.storage.transactionSync(() => {
        sql.exec('DELETE FROM sessions_backup WHERE version=?', entry.id);
        sql.exec('DELETE FROM backups WHERE id=?', entry.id);
      });
      return ok();
    }
    missing();
  }
  if (action !== 'keys' || !version) missing();
  if (method === 'GET') {
    const rows = sql
      .exec(
        'SELECT room,session,data FROM sessions_backup WHERE version=? AND (? IS NULL OR room=?) AND (? IS NULL OR session=?)',
        entry.id,
        room ?? null,
        room ?? null,
        session ?? null,
        session ?? null
      )
      .toArray();
    if (session) return rows.length ? ok(JSON.parse(rows[0].data)) : missing();
    const rooms = Object.create(null);
    for (const r of rows) {
      rooms[r.room] ??= { sessions: Object.create(null) };
      rooms[r.room].sessions[r.session] = JSON.parse(r.data);
    }
    return ok(room ? (rooms[room] ?? { sessions: {} }) : { rooms });
  }
  if (entry.id !== latest?.id)
    return {
      status: 403,
      body: {
        errcode: 'M_WRONG_ROOM_KEYS_VERSION',
        current_version: String(latest.id),
        error: 'Use the current backup'
      }
    };
  if (method === 'PUT') {
    const rooms = room ? { [room]: session ? { sessions: { [session]: body } } : body } : body.rooms;
    if (!isObject(rooms)) fail(400, 'M_BAD_JSON', 'Expected room backup');
    home.ctx.storage.transactionSync(() => {
      for (const [rid, r] of Object.entries(rooms))
        for (const [sid, data] of Object.entries(r.sessions)) {
          if (
            !isObject(data.session_data) ||
            !Number.isSafeInteger(data.first_message_index) ||
            !Number.isSafeInteger(data.forwarded_count) ||
            typeof data.is_verified !== 'boolean'
          )
            fail(400, 'M_BAD_JSON', 'Invalid backup session');
          const prev = sql
            .exec(
              'SELECT data FROM sessions_backup WHERE version=? AND room=? AND session=?',
              entry.id,
              rid,
              sid
            )
            .toArray()[0];
          if (prev) {
            const old = JSON.parse(prev.data);
            if (
              !(
                (!old.is_verified && data.is_verified) ||
                data.first_message_index < old.first_message_index ||
                data.forwarded_count < old.forwarded_count
              )
            )
              continue;
          }
          sql.exec(
            'INSERT OR REPLACE INTO sessions_backup VALUES(?,?,?,?)',
            entry.id,
            rid,
            sid,
            JSON.stringify(data)
          );
        }
      sql.exec('UPDATE backups SET etag=etag+1 WHERE id=?', entry.id);
    });
  } else if (method === 'DELETE') {
    home.ctx.storage.transactionSync(() => {
      sql.exec(
        'DELETE FROM sessions_backup WHERE version=? AND (? IS NULL OR room=?) AND (? IS NULL OR session=?)',
        entry.id,
        room ?? null,
        room ?? null,
        session ?? null,
        session ?? null
      );
      sql.exec('UPDATE backups SET etag=etag+1 WHERE id=?', entry.id);
    });
  } else missing();
  return ok({ count: count(), etag: String(entry.etag + 1) });
}
