// SPDX-License-Identifier: AGPL-3.0-or-later
import { eventId, domain } from './graph.js';
import { remote } from './federation.js';
import { limited } from './media.js';
import { verify_signed_pdu } from '../room-v10/pkg/relay_room_v10.js';
import { graphKeys, peerRecord } from './discovery.js';
import { verificationKeys } from './identity.js';
import { load, requireRoomAccess } from './rooms.js';

// Network reads take place outside the room's serialized write. The write checks
// the current graph and policy again, including every recovered event's signature.
export async function recoverPredecessors(home, server, peer, pdu, request = remote) {
  const room = pdu.room_id;
  const graph = load(home, server, room);
  if (
    !graph.tips.size ||
    !Array.isArray(pdu.prev_events) ||
    pdu.prev_events.every((id) => graph.events.has(id))
  )
    return [];
  requireRoomAccess(graph.get('m.room.server_acl'), peer);
  if (!graph.members('join').some((m) => domain(m.state_key) === peer))
    throw Error('Only resident servers can supply missing history');
  const author = domain(pdu.sender);
  if (author !== server) await peerRecord(home, author);
  verify_signed_pdu(
    JSON.stringify(pdu),
    JSON.stringify({ ...graphKeys(home), [server]: verificationKeys(home.identity) }),
    graph.version
  );
  const pool = new Map();
  let bytesRemaining = 4 * 1024 * 1024;
  const head = eventId(pdu, graph.version);
  let frontier = [head];
  const roots = [...graph.tips];
  for (let page = 0; page < 8; page++) {
    const res = await request(
      home,
      server,
      peer,
      'POST',
      '/_matrix/federation/v1/get_missing_events/' + encodeURIComponent(room),
      { earliest_events: roots, latest_events: frontier, limit: 64, min_depth: 0 }
    );
    const buffer = await limited(res.body, bytesRemaining);
    bytesRemaining -= buffer.byteLength;
    const { events } = JSON.parse(new TextDecoder().decode(buffer));
    if (!Array.isArray(events) || events.length > 64) throw Error('Invalid missing-events response');
    let added = false;
    for (const e of events) {
      if (e.room_id !== room || !Array.isArray(e.prev_events)) throw Error('Invalid missing predecessor');
      const id = eventId(e, graph.version);
      if (!pool.has(id)) {
        pool.set(id, e);
        added = true;
      }
    }
    const following = new Set(),
      ordered = [],
      needs = new Set(),
      visiting = new Set();
    function visit(id, child) {
      if (graph.events.has(id) || following.has(id)) return;
      const e = pool.get(id);
      if (!e) {
        needs.add(child);
        return;
      }
      if (visiting.has(id)) throw Error('Cyclic missing history');
      visiting.add(id);
      for (const parent of e.prev_events) visit(parent, id);
      visiting.delete(id);
      following.add(id);
      ordered.push(e);
    }
    for (const id of pdu.prev_events) visit(id, head);
    if (!needs.size) {
      for (const name of new Set(ordered.map((p) => domain(p.sender))))
        if (name !== server) await peerRecord(home, name);
      return ordered;
    }
    if (!added) break;
    frontier = [...needs];
    if (frontier.length > 256) break;
  }
  throw Error('Peer did not supply a complete predecessor chain');
}
