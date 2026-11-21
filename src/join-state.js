// SPDX-License-Identifier: AGPL-3.0-or-later
import { replay_join } from '../room-v10/pkg/relay_room_v10.js';
import { eventId } from './graph.js';

// send_join supplies resolved state and the transitive auth chain. Order only the
// reachable auth events for Ruma. Timeline predecessors are not auth dependencies.
export function joinBase(room, state, chain, join, version = 10) {
  const pool = new Map();
  for (const event of [...chain, ...state]) {
    if (event.room_id !== room || typeof event.state_key !== 'string' || event.type === 'm.room.server_acl')
      throw Error('Unsupported remote room state');
    const {unsigned, ...signed} = event;
    pool.set(eventId(event,version), signed);
  }
  const stateIds = state.map((p) => eventId(p,version));
  const pending = [...new Set([...stateIds, ...join.auth_events])].map((id) => [id, false]);
  const visited = new Set(), visiting = new Set(), auth = [];
  while (pending.length) {
    const [id, expanded] = pending.pop();
    if (visited.has(id)) continue;
    const event = pool.get(id);
    if (!event) throw Error('Incomplete remote authorization chain');
    if (expanded) {
      visiting.delete(id);
      visited.add(id);
      auth.push(event);
    } else {
      if (visiting.has(id)) throw Error('Cyclic remote authorization chain');
      visiting.add(id);
      pending.push([id, true]);
      for (const dep of event.auth_events) pending.push([dep, false]);
    }
  }
  return {stateIds, auth, join};
}

export function resolveJoin(room, keys, base, following, version = 10) {
  return JSON.parse(replay_join(room, JSON.stringify(base.auth), JSON.stringify(base.stateIds),
    JSON.stringify(base.join), JSON.stringify(following), JSON.stringify(keys),version));
}
