// SPDX-License-Identifier: AGPL-3.0-or-later
// New PDUs are buffered until their room state and delivery queue commit together.
export class StoredEvents {
  constructor(sql, room) {
    this.sql = sql;
    this.room = room;
    this.pending = new Map();
    this.cached = new Map();
    this.pendingHistory = new Map();
    this.complete = !!sql.exec('SELECT 1 FROM room_ancestry WHERE room=? LIMIT 1',room).toArray().length;
  }
  get(id) {
    if (!id) return undefined;
    if (this.pendingHistory.has(id)) return this.pendingHistory.get(id);
    if (this.pending.has(id)) return this.pending.get(id);
    if (this.cached.has(id)) return this.cached.get(id);
    const row = this.sql.exec('SELECT pdu FROM room_known_events WHERE room=? AND eid=?', this.room, id).toArray()[0];
    if (!row) return undefined;
    const pdu = JSON.parse(row.pdu);
    this.cached.set(id, pdu);
    return pdu;
  }
  inTimeline(id) {
    return this.pending.has(id) || !!this.sql.exec('SELECT 1 FROM room_events WHERE room=? AND eid=?',this.room,id).toArray().length;
  }
  knownPredecessor(id) {
    return this.inTimeline(id) || this.pendingHistory.has(id) || (this.complete &&
      !!this.sql.exec('SELECT 1 FROM room_ancestry WHERE room=? AND eid=?',this.room,id).toArray().length);
  }
  historyRows() {
    return this.sql.exec('SELECT a.eid,o.pdu FROM room_ancestry a JOIN room_outliers o ON o.eid=a.eid AND o.room=a.room WHERE a.room=? ORDER BY a.seq',this.room).toArray();
  }
  joinBase(original = false) {
    if (this.complete && !original) return null;
    const row = this.sql.exec('SELECT join_id,state_ids FROM room_bases WHERE room=?',this.room).toArray()[0];
    if (!row) return null;
    const auth = this.sql.exec('SELECT pdu FROM room_outliers WHERE room=? AND position>=0 ORDER BY position',this.room).toArray().map((r) => JSON.parse(r.pdu));
    return {join:this.get(row.join_id),stateIds:JSON.parse(row.state_ids),auth};
  }
  has(id) { return this.get(id) !== undefined; }
  set(id, pdu) { this.pending.set(id, pdu); }
  delete(id) { this.pending.delete(id); }
  *entries() {
    if (this.complete) {
      for (const row of this.historyRows()) yield [row.eid,JSON.parse(row.pdu)];
      yield* this.pendingHistory;
    }
    for (const row of this.sql.exec('SELECT eid,pdu FROM room_events WHERE room=? ORDER BY seq', this.room).toArray())
      yield [row.eid, JSON.parse(row.pdu)];
    yield* this.pending;
  }
  *values() { for (const [, event] of this.entries()) yield event; }
}
