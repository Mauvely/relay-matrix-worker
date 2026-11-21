// SPDX-License-Identifier: AGPL-3.0-or-later
import { redact_event } from '../room-v10/pkg/relay_room_v10.js';
import { domain } from './graph.js';

function audience(events) {
  const joined = new Set(),
    invited = new Set();
  let visibility = 'shared';
  for (const p of events) {
    if (p.type === 'm.room.history_visibility' && p.state_key === '')
      visibility = p.content.history_visibility;
    if (p.type !== 'm.room.member') continue;
    const host = domain(p.state_key);
    if (p.content.membership === 'join') joined.add(host);
    if (p.content.membership === 'invite') invited.add(host);
  }
  return { visibility, joined: [...joined], invited: [...invited] };
}

// Link ordinary messages to the same disclosure state as their predecessor.
// A fork merge uses the resolved state of that exact branch, independent of arrival order.
export function saveAudience(sql, graph, id, pdu) {
  if (
    pdu.prev_events.length === 1 &&
    pdu.type !== 'm.room.history_visibility' &&
    pdu.type !== 'm.room.member'
  ) {
    const inherited = sql
      .exec(
        'INSERT INTO history_audience_refs(room,eid,source) SELECT room,?,source FROM history_audience_refs WHERE room=? AND eid=? RETURNING source',
        id,
        graph.room,
        pdu.prev_events[0]
      )
      .toArray();
    if (inherited.length) return;
  }
  const after =
    graph.tips.size === 1 && graph.tips.has(id)
      ? [...graph.state.values()].map(
          (eid) =>
            graph.events?.get(eid) ??
            JSON.parse(
              sql.exec('SELECT pdu FROM room_known_events WHERE room=? AND eid=?', graph.room, eid).one()
                .pdu
            )
        )
      : graph.before([id]);
  sql.exec('INSERT INTO history_audiences VALUES(?,?,?)', graph.room, id, JSON.stringify(audience(after)));
  sql.exec('INSERT INTO history_audience_refs VALUES(?,?,?)', graph.room, id, id);
}

function visible(group, peer) {
  return (
    group.visibility === 'shared' ||
    group.visibility === 'world_readable' ||
    group.joined.includes(peer) ||
    (group.visibility === 'invited' && group.invited.includes(peer))
  );
}

function audienceAt(sql, graph, id, groups) {
  const row = sql.exec(
    'SELECT r.source,a.audience FROM history_audience_refs r JOIN history_audiences a ON a.room=r.room AND a.source=r.source WHERE r.room=? AND r.eid=?',
    graph.room, id
  ).toArray()[0];
  const key = row?.source ?? id;
  if (!groups.has(key)) groups.set(key, row ? JSON.parse(row.audience) : audience(graph.before([id])));
  return groups.get(key);
}

export function disclosedEvent(sql, graph, peer, id, pdu, groups = new Map()) {
  const { unsigned, ...signed } = pdu;
  let disclose = visible(audienceAt(sql, graph, id, groups), peer) ||
    (pdu.type === 'm.room.member' && domain(pdu.state_key) === peer);
  if (!disclose && pdu.type === 'm.room.history_visibility' && pdu.state_key === '')
    disclose = visible(audience(graph.before(pdu.prev_events)), peer);
  return disclose ? signed : JSON.parse(redact_event(JSON.stringify(signed), graph.version));
}

export function missingEvents(sql, graph, peer, body, includeLatest = false) {
  const { earliest_events: earliest, latest_events: latest, min_depth: minDepth = 0, limit = 10 } = body;
  if (
    ![earliest, latest].every(
      (list) => Array.isArray(list) && list.length <= 256 && list.every((s) => typeof s === 'string')
    ) ||
    !Number.isSafeInteger(minDepth) ||
    minDepth < 0 ||
    !Number.isSafeInteger(limit) ||
    limit < 0
  )
    throw Object.assign(Error('Invalid history request'), { status: 400, errcode: 'M_INVALID_PARAM' });
  const groups = new Map();
  const timeline = (id) => {
    const row = sql.exec('SELECT pdu FROM room_events WHERE room=? AND eid=?', graph.room, id).toArray()[0];
    return row && JSON.parse(row.pdu);
  };
  const seen = new Set(includeLatest ? earliest : [...earliest, ...latest]);
  const queue = includeLatest ? latest.filter(id => !graph.softFailed.has(id))
    : latest.flatMap((id) => timeline(id)?.prev_events ?? []);
  const result = [];
  for (let i = 0; i < queue.length && result.length < Math.min(limit, 100); i++) {
    const id = queue[i];
    if (seen.has(id)) continue;
    seen.add(id);
    const p = timeline(id);
    if (!p || p.depth < minDepth) continue;
    result.push(disclosedEvent(sql,graph,peer,id,p,groups));
    queue.push(...p.prev_events);
  }
  return result.sort((a, b) => a.depth - b.depth);
}
