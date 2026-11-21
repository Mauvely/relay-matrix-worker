// SPDX-License-Identifier: AGPL-3.0-or-later
// New PDUs are buffered until their room state and delivery queue commit together.
export class StoredEvents {
  constructor(sql, room) {
    this.sql = sql;
    this.room = room;
    this.pending = new Map();
    this.cached = new Map();
  }
  get(id) {
    if (!id) return undefined;
    if (this.pending.has(id)) return this.pending.get(id);
    if (this.cached.has(id)) return this.cached.get(id);
    const row = this.sql.exec('SELECT pdu FROM room_events WHERE room=? AND eid=?', this.room, id).toArray()[0];
    if (!row) return undefined;
    const pdu = JSON.parse(row.pdu);
    this.cached.set(id, pdu);
    return pdu;
  }
  has(id) { return this.get(id) !== undefined; }
  set(id, pdu) { this.pending.set(id, pdu); }
  delete(id) { this.pending.delete(id); }
  *entries() {
    for (const row of this.sql.exec('SELECT eid,pdu FROM room_events WHERE room=? ORDER BY seq', this.room).toArray())
      yield [row.eid, JSON.parse(row.pdu)];
    yield* this.pending;
  }
  *values() { for (const [, event] of this.entries()) yield event; }
}
