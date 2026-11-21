// SPDX-License-Identifier: AGPL-3.0-or-later
import { eventId, domain } from './graph.js';
import { remote } from './federation.js';
import { limited } from './media.js';
import { verify_signed_pdu } from '../room-v10/pkg/relay_room_v10.js';
import { graphKeys, keysForEvent } from './discovery.js';
import { verificationKeys } from './identity.js';
import { load, requireRoomAccess } from './rooms.js';

const gapLimit = 4 * 1024 * 1024;
const byteSize = new TextEncoder();

// Walk the signed tip's ancestry iteratively: a long offline interval can exceed
// the JavaScript call stack. Only reachable events enter the returned batch.
function predecessors(graph, tip, head, pool) {
  const ordered = [], needs = new Set(), seen = new Set(), visiting = new Set();
  const stack = tip.prev_events.map(id => [id, head, false]);
  while (stack.length) {
    const [id, child, expanded] = stack.pop();
    if (seen.has(id) || graph.events.has(id)) continue;
    const event = pool.get(id);
    if (!event) { needs.add(child); continue; }
    if (expanded) {
      visiting.delete(id);
      seen.add(id);
      ordered.push(event);
      continue;
    }
    if (visiting.has(id)) throw Error('Cyclic missing history');
    visiting.add(id);
    stack.push([id,child,true]);
    for (const parent of event.prev_events) stack.push([parent,id,false]);
  }
  return {ordered, needs};
}

export function clearGap(sql, room, peer, head) {
  sql.exec('DELETE FROM federation_gap_events WHERE room=? AND peer=? AND head=?',room,peer,head);
}

function saveProgress(home, room, peer, head, additions) {
  const now = Date.now();
  home.ctx.storage.transactionSync(() => {
    home.sql.exec('DELETE FROM federation_gap_events WHERE expires<=?',now);
    const used = home.sql.exec('SELECT COALESCE(SUM(length(CAST(pdu AS BLOB))),0) AS bytes FROM federation_gap_events').one().bytes;
    if (used + additions.reduce((n,row) => n + row.size, 0) > 4 * gapLimit)
      throw Error('Pending federation history store is full');
    for (const {id,raw} of additions)
      home.sql.exec('INSERT OR IGNORE INTO federation_gap_events VALUES(?,?,?,?,?,?)',room,peer,head,id,raw,now+86400000);
  });
}

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
  if (author !== server) await keysForEvent(home, author, pdu);
  verify_signed_pdu(
    JSON.stringify(pdu),
    JSON.stringify({ ...graphKeys(home), [server]: verificationKeys(home.identity) }),
    graph.version
  );
  const pool = new Map(), additions = [];
  const head = eventId(pdu, graph.version);
  if (graph.events.has(head)) return [];
  const now = Date.now();
  let bytesRemaining = gapLimit;
  for (const {eid,pdu:raw,bytes} of home.sql.exec(
    'SELECT eid,pdu,length(CAST(pdu AS BLOB)) AS bytes FROM federation_gap_events WHERE room=? AND peer=? AND head=? AND expires>?',
    room,peer,head,now).toArray()) {
    pool.set(eid,JSON.parse(raw));
    bytesRemaining -= bytes;
  }
  let {ordered,needs} = predecessors(graph,pdu,head,pool);
  if (!needs.size) return ordered;
  let frontier = [...needs];
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
        const raw = JSON.stringify(e);
        pool.set(id, e);
        additions.push({id, raw, size:byteSize.encode(raw).byteLength});
        added = true;
      }
    }
    ({ordered,needs} = predecessors(graph,pdu,head,pool));
    if (!needs.size) return ordered;
    if (!added || needs.size > 256) throw Error('Incomplete predecessor chain');
    frontier = [...needs];
  }
  // A retry starts at this frontier, including after the Durable Object restarts.
  // Pending data is separate from accepted room history. receiveEvent verifies
  // all signatures and membership before committing any of it to the timeline.
  if (additions.length) saveProgress(home,room,peer,head,additions);
  throw Error('Peer did not supply a complete predecessor chain');
}
