// SPDX-License-Identifier: AGPL-3.0-or-later
import {
  check_current,
  auth_fields,
  prepare_event,
  reference_id,
  replay
} from '../room-v10/pkg/relay_room_v10.js';
import { sign } from './federation.js';

export const domain = (user) => /^@[^:]+:(.+)$/.exec(user)?.[1];
export const eventId = (pdu) => reference_id(JSON.stringify(pdu));
export function clientEvent(pdu, id = eventId(pdu)) {
  const { sender, type, content, origin_server_ts, room_id, state_key } = pdu;
  return {
    event_id: id,
    sender,
    type,
    content,
    origin_server_ts,
    room_id,
    ...(state_key === undefined ? {} : { state_key })
  };
}
export async function signPdu(identity, server, pdu) {
  const [hash, redacted] = JSON.parse(prepare_event(JSON.stringify(pdu)));
  return {
    ...pdu,
    hashes: { sha256: hash },
    signatures: { ...pdu.signatures, [server]: { 'ed25519:1': await sign(identity, redacted) } }
  };
}
export class RoomGraph {
  constructor(room, keys, rows = []) {
    this.room = room;
    this.keys = keys;
    this.events = new Map(rows.map(({ eid, pdu }) => [eid, JSON.parse(pdu)]));
    this.tips = new Set(this.events.keys());
    for (const event of this.events.values()) for (const id of event.prev_events) this.tips.delete(id);
    this.resolve();
  }
  resolve() {
    const state = JSON.parse(replay(JSON.stringify([...this.events.values()]), JSON.stringify(this.keys)));
    this.state = new Map(state.map(([type, key, id]) => [JSON.stringify([type, key]), id]));
  }
  get(type, key = '') {
    return this.events.get(this.state.get(JSON.stringify([type, key])));
  }
  members(membership) {
    return [...this.state.values()]
      .map((id) => this.events.get(id))
      .filter((e) => e.type === 'm.room.member' && (!membership || e.content.membership === membership));
  }
  template(sender, type, content, stateKey) {
    const fields = JSON.parse(auth_fields(type, sender, stateKey, JSON.stringify(content)));
    return {
      type,
      room_id: this.room,
      sender,
      content,
      origin: domain(sender),
      origin_server_ts: Date.now(),
      depth: 1 + Math.max(0, ...[...this.tips].map((id) => this.events.get(id).depth)),
      auth_events: fields.map(([t, k]) => this.state.get(JSON.stringify([t, k]))).filter(Boolean),
      prev_events: [...this.tips],
      ...(stateKey === undefined ? {} : { state_key: stateKey })
    };
  }
  async local(identity, sender, type, content, stateKey) {
    const pdu = await signPdu(identity, domain(sender), this.template(sender, type, content, stateKey));
    this.add(pdu);
    return pdu;
  }
  before(parents) {
    const ancestors = new Set(),
      pending = [...parents];
    while (pending.length) {
      const id = pending.pop();
      if (!ancestors.has(id)) {
        const p = this.events.get(id);
        if (!p) throw Error('Missing predecessor');
        ancestors.add(id);
        pending.push(...p.prev_events);
      }
    }
    const events = [...this.events.entries()].filter(([id]) => ancestors.has(id)).map(([, p]) => p);
    return JSON.parse(replay(JSON.stringify(events), JSON.stringify(this.keys))).map(([, , id]) =>
      this.events.get(id)
    );
  }
  checkCurrent(pdu) {
    const state = [...this.state.values()].map((id) => ({ ...this.events.get(id), event_id: id }));
    check_current(JSON.stringify({ ...pdu, event_id: eventId(pdu) }), JSON.stringify(state));
  }
  add(pdu) {
    if (pdu.room_id !== this.room) throw Error('Room ID mismatch');
    const id = eventId(pdu);
    if (this.events.has(id)) return;
    if (this.events.size >= 512) throw Error('Room reached spike history limit');
    this.events.set(id, pdu);
    this.resolve();
    for (const prev of pdu.prev_events) this.tips.delete(prev);
    this.tips.add(id);
  }
}
