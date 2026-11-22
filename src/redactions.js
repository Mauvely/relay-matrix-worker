// SPDX-License-Identifier: AGPL-3.0-or-later
import { redact_event } from '../room-v10/pkg/relay_room_v10.js';
import { clientEvent, domain } from './graph.js';
import { StoredEvents } from './stored-events.js';

export function redactionSchema(sql) {
  sql.exec(`CREATE TABLE IF NOT EXISTS room_redactions(room TEXT,id TEXT,target TEXT,sender TEXT,moderator INTEGER,
      applied INTEGER NOT NULL DEFAULT 0,PRIMARY KEY(room,id));
    CREATE TABLE IF NOT EXISTS room_data_upgrades(name TEXT PRIMARY KEY);
    CREATE INDEX IF NOT EXISTS redaction_target ON room_redactions(room,target);
    CREATE TABLE IF NOT EXISTS room_pruned(room TEXT,target TEXT,pdu TEXT NOT NULL,cause TEXT NOT NULL,PRIMARY KEY(room,target));
    CREATE VIEW IF NOT EXISTS room_visible_events AS SELECT e.room,e.eid,e.seq,COALESCE(p.pdu,e.pdu) AS pdu,p.cause
      FROM room_client_events e LEFT JOIN room_pruned p ON p.room=e.room AND p.target=e.eid
      WHERE json_extract(e.pdu,'$.type')!='m.room.redaction' OR EXISTS (
        SELECT 1 FROM room_redactions r WHERE r.room=e.room AND r.id=e.eid AND r.applied=1);`);
}

export function mayModerate(authEvents, sender) {
  const levels = authEvents.find(e => e?.type === 'm.room.power_levels' && e.state_key === '')?.content;
  const level = levels ? levels.users?.[sender] ?? levels.users_default ?? 0 :
    authEvents.some(e => e?.type === 'm.room.create' && e.sender === sender) ? 100 : 0;
  return level >= (levels?.redact ?? 50);
}

export function recordRedactions(sql, graph, entries) {
  const room = graph.room;
  for (const [id, event] of entries) {
    if (event.type !== 'm.room.redaction' || event.state_key !== undefined) continue;
    const target = graph.version === 11 ? event.content.redacts : event.redacts;
    if (typeof target !== 'string' || !/^\$[\w-]{43}$/.test(target)) continue;
    const auth = event.auth_events.map(eid => graph.events.get(eid));
    sql.exec('INSERT OR IGNORE INTO room_redactions(room,id,target,sender,moderator) VALUES(?,?,?,?,?)',
      room, id, target, event.sender, Number(mayModerate(auth, event.sender)));
  }
  // Federation can deliver either half first. Match only accepted PDUs in this room.
  for (const [id, event] of entries) {
    const lookup = event.type === 'm.room.redaction' ? '(r.target=?2 OR r.id=?2)' : 'r.target=?2';
    const candidates = sql.exec(`SELECT r.*, e.pdu FROM room_redactions r JOIN room_known_events e
      ON e.room=r.room AND e.eid=r.target WHERE r.room=?1 AND ${lookup} AND r.applied=0
      AND NOT EXISTS(SELECT 1 FROM room_soft_failures f WHERE f.room=e.room AND f.eid=e.eid)`, room, id);
    for (const row of candidates.toArray()) {
      const original = JSON.parse(row.pdu);
      // Room versions 10 and 11 trust an originating server to enforce its own users' permissions.
      if (!row.moderator && domain(row.sender) !== domain(original.sender)) continue;
      const pruned = redact_event(row.pdu, graph.version);
      sql.exec('INSERT OR IGNORE INTO room_pruned VALUES(?,?,?,?)', room, row.target, pruned, row.id);
      sql.exec('DELETE FROM cloud_file_receipts WHERE room=? AND event=?',room,row.target);
      sql.exec('UPDATE room_redactions SET applied=1 WHERE room=? AND id=?', room, row.id);
    }
  }
}

// Older Workers accepted generic room sends. Index any existing signed redactions once.
export function indexExistingRedactions(sql) {
  if (sql.exec("SELECT 1 FROM room_data_upgrades WHERE name='redactions-v1'").toArray().length) return;
  const rooms = sql.exec(`SELECT DISTINCT e.room,COALESCE(v.version,10) AS version
    FROM room_client_events e LEFT JOIN room_versions v ON e.room=v.room WHERE json_extract(e.pdu,'$.type')='m.room.redaction'`).toArray();
  for (const {room,version} of rooms) {
    const events = new StoredEvents(sql,room);
    const rows = sql.exec("SELECT eid,pdu FROM room_client_events WHERE room=? AND json_extract(pdu,'$.type')='m.room.redaction'",room);
    recordRedactions(sql,{room,version,events},rows.toArray().map(r=>[r.eid,JSON.parse(r.pdu)]));
  }
  sql.exec("INSERT OR IGNORE INTO room_data_upgrades VALUES('redactions-v1')");
}

export function prunedEvent(sql, room, id) {
  return sql.exec('SELECT pdu,cause FROM room_pruned WHERE room=? AND target=?', room, id).toArray()[0];
}

export function projectedState(sql, room, id, pdu) {
  const changed = prunedEvent(sql, room, id);
  return changed ? clientEvent(JSON.parse(changed.pdu), id, changed.cause) : clientEvent(pdu, id);
}
