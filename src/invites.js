// SPDX-License-Identifier: AGPL-3.0-or-later
import { graphKeys, peerRecord } from './discovery.js';
import { limited } from './media.js';
import { verify_signed_pdu } from '../room-v10/pkg/relay_room_v10.js';
import { RoomGraph, domain, eventId, signPdu } from './graph.js';
import { openParty, ok, fail, missing, save, receiveEvent } from './rooms.js';
import { remote } from './federation.js';

export function inviteSchema(sql) {
  sql.exec(
    'CREATE TABLE IF NOT EXISTS remote_invites(seq INTEGER PRIMARY KEY AUTOINCREMENT,user TEXT,room TEXT,peer TEXT,signed TEXT,stripped TEXT,joining TEXT,UNIQUE(user,room))'
  );
}
export async function receiveInvite(home, server, peer, room, id, body) {
  const p = body.event;
  if (body.room_version !== '10')
    fail(400, 'M_INCOMPATIBLE_ROOM_VERSION', 'The spike supports room version 10');
  if (
    !p ||
    p.type !== 'm.room.member' ||
    p.content?.membership !== 'invite' ||
    domain(p.sender) !== peer ||
    p.room_id !== room ||
    domain(p.state_key) !== server ||
    eventId(p) !== id
  )
    fail(400, 'M_INVALID_PARAM', 'Invalid invite event');
  await openParty(home, server, p.state_key);
  verify_signed_pdu(JSON.stringify(p), JSON.stringify(graphKeys(home)));
  const signed = await signPdu(home.identity, server, p);
  if (home.sql.exec('SELECT 1 FROM room_events WHERE room=? LIMIT 1', room).toArray().length)
    await receiveEvent(home, server, peer, signed);
  else {
    const prior = home.sql
      .exec('SELECT signed FROM remote_invites WHERE user=? AND room=?', p.state_key, room)
      .toArray()[0];
    if (prior && eventId(JSON.parse(prior.signed)) === id) return ok({ event: JSON.parse(prior.signed) });
    const preview = (body.invite_room_state ?? [])
      .filter(
        (e) =>
          ([
            'm.room.name',
            'm.room.avatar',
            'm.room.create',
            'm.room.encryption',
            'm.room.join_rules'
          ].includes(e.type) &&
            e.state_key === '') ||
          (e.type === 'm.room.member' && e.state_key === p.sender)
      )
      .slice(0, 8);
    preview.push({
      type: p.type,
      state_key: p.state_key,
      sender: p.sender,
      content: p.content
    });
    home.sql.exec(
      'INSERT OR REPLACE INTO remote_invites(user,room,peer,signed,stripped) VALUES(?,?,?,?,?)',
      p.state_key,
      room,
      peer,
      JSON.stringify(signed),
      JSON.stringify(preview)
    );
  }
  return ok({ event: signed });
}
export function remoteInvites(home, user, cursor, initial) {
  const rows = home.sql
    .exec(
      'SELECT room,seq,stripped FROM remote_invites WHERE user=? AND seq>? ORDER BY seq',
      user,
      initial ? 0 : cursor
    )
    .toArray();
  return {
    high: Math.max(cursor, rows.at(-1)?.seq ?? 0),
    rooms: Object.fromEntries(rows.map((r) => [r.room, { invite_state: { events: JSON.parse(r.stripped) } }]))
  };
}
export async function joinRemote(home, server, user, room, invite) {
  await openParty(home, server, user);
  const peer = invite.peer,
    prefix = '/_matrix/federation/',
    rid = encodeURIComponent(room);
  const request = async (method, path, content) => {
    const response = await remote(home, server, peer, method, prefix + path, content);
    return JSON.parse(new TextDecoder().decode(await limited(response.body, 4 * 1024 * 1024)));
  };
  // Save the exact signed join before the first remote write; retries use the same v10 event ID.
  let join = invite.joining && JSON.parse(invite.joining);
  if (!join) {
    const template = await request('GET', 'v1/make_join/' + rid + '/' + encodeURIComponent(user) + '?ver=10');
    if (template.room_version !== '10') fail(400, 'M_INCOMPATIBLE_ROOM_VERSION', 'Room version 10 required');
    const p = template.event;
    if (
      p.room_id !== room ||
      p.sender !== user ||
      p.type !== 'm.room.member' ||
      p.state_key !== user ||
      p.content?.membership !== 'join'
    )
      fail(502, 'M_BAD_JSON', 'Invalid join template');
    const proposal = {
      room_id: room,
      sender: user,
      state_key: user,
      type: p.type,
      content: { membership: 'join' },
      origin: server,
      origin_server_ts: Date.now(),
      depth: p.depth,
      prev_events: p.prev_events,
      auth_events: p.auth_events
    };
    join = await signPdu(home.identity, server, proposal);
    home.sql.exec(
      'UPDATE remote_invites SET joining=COALESCE(joining,?) WHERE user=? AND room=? AND signed=?',
      JSON.stringify(join),
      user,
      room,
      invite.signed
    );
    const winner = home.sql
      .exec(
        'SELECT joining FROM remote_invites WHERE user=? AND room=? AND signed=?',
        user,
        room,
        invite.signed
      )
      .toArray()[0];
    if (!winner?.joining) fail(409, 'M_UNKNOWN', 'Invitation changed during join');
    join = JSON.parse(winner.joining);
  }
  const response = await request(
    'PUT',
    'v2/send_join/' + rid + '/' + encodeURIComponent(eventId(join)),
    join
  );
  if (
    response.members_omitted ||
    !Array.isArray(response.auth_chain) ||
    !Array.isArray(response.state) ||
    (response.origin !== undefined && response.origin !== peer)
  )
    fail(502, 'M_BAD_JSON', 'Full room state required');
  const pool = new Map(),
    ordered = [],
    done = new Set(),
    visiting = new Set();
  for (const p of [...response.auth_chain, ...response.state, join]) pool.set(eventId(p), p);
  if (pool.size > 512) fail(503, 'M_RESOURCE_LIMIT_EXCEEDED', 'Peer room exceeds spike limit');
  let fetched = 0;
  async function visit(id, child) {
    if (done.has(id)) return;
    if (visiting.has(id)) fail(502, 'M_BAD_JSON', 'Cyclic remote history');
    visiting.add(id);
    let p = pool.get(id);
    if (!p) {
      if (++fetched > 32 || pool.size >= 512)
        fail(503, 'M_RESOURCE_LIMIT_EXCEEDED', 'Peer room exceeds backfill limit');
      if (child?.prev_events.includes(id)) {
        // Matrix peers may hide old history. Only feed reachable, signed ancestors into room replay.
        const limit = Math.min(64, 512 - pool.size);
        const batch = await request('POST', 'v1/get_missing_events/' + rid, {
          earliest_events: [...done].slice(-10), latest_events: [eventId(child)], limit
        }).catch(() => null);
        if (Array.isArray(batch?.events) && batch.events.length <= limit)
          for (const event of batch.events)
            if (event.room_id === room && !pool.has(eventId(event))) pool.set(eventId(event), event);
        p = pool.get(id);
      }
      if (!p) {
        if (pool.size >= 512) fail(503, 'M_RESOURCE_LIMIT_EXCEEDED', 'Peer room exceeds backfill limit');
        const transaction = await request('GET', 'v1/event/' + encodeURIComponent(id));
        p = transaction.pdus?.find((e) => eventId(e) === id);
      }
      if (!p) fail(502, 'M_BAD_JSON', 'Peer did not return the requested predecessor');
      pool.set(id, p);
    }
    if (p.room_id !== room || p.type === 'm.room.server_acl')
      fail(403, 'M_FORBIDDEN', 'Unsupported federated state');
    for (const prev of [...p.prev_events, ...p.auth_events]) await visit(prev, p);
    visiting.delete(id);
    done.add(id);
    const { unsigned, ...signed } = p;
    ordered.push(signed);
  }
  await visit(eventId(join));
  // Reconstruct the room from signed history. Unsigned invite previews are never promoted to state.
  const origins = new Set(ordered.map((p) => domain(p.sender)));
  origins.delete(server);
  if (origins.size > 32) fail(503, 'M_RESOURCE_LIMIT_EXCEEDED', 'Peer room has too many signing origins');
  for (const origin of origins) await peerRecord(home, origin);
  const keys = {
    ...graphKeys(home),
    [server]: { 'ed25519:1': home.identity.publicKey }
  };
  const imported = ordered.map((p) => ({
    eid: eventId(p),
    pdu: JSON.stringify(p)
  }));
  const graph = new RoomGraph(room, keys, imported);
  if (
    graph.get('m.room.create')?.content['m.federate'] === false ||
    graph.get('m.room.member', user)?.content.membership !== 'join'
  )
    fail(403, 'M_FORBIDDEN', 'Remote room did not admit the local user');
  for (const m of graph.members())
    if (['join', 'invite'].includes(m.content.membership)) await openParty(home, server, m.state_key);
  home.ctx.storage.transactionSync(() => {
    const current = home.sql
      .exec('SELECT eid,pdu FROM room_events WHERE room=? ORDER BY seq', room)
      .toArray();
    const ids = new Set(current.map((r) => r.eid));
    const combined = current.length
      ? new RoomGraph(room, keys, current.concat(imported.filter((r) => !ids.has(r.eid))))
      : graph;
    if (combined.get('m.room.member', user)?.content.membership !== 'join')
      fail(403, 'M_FORBIDDEN', 'Membership changed during join');
    save(home, combined, ordered);
    home.sql.exec(
      'DELETE FROM remote_invites WHERE user=? AND room=? AND signed=?',
      user,
      room,
      invite.signed
    );
  });
  return ok({ room_id: room });
}
