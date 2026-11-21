// SPDX-License-Identifier: AGPL-3.0-or-later
import { verificationKeys } from './identity.js';
import { graphKeys, peerRecord } from './discovery.js';
import { limited } from './media.js';
import { verify_signed_pdu } from '../room-v10/pkg/relay_room_v10.js';
import { joinBase, resolveJoin } from './join-state.js';
import { domain, eventId, signPdu } from './graph.js';
import { openParty, ok, fail, missing, save, receiveEvent, load, requireRoomAccess } from './rooms.js';
import { remote } from './federation.js';

export function inviteSchema(sql) {
  sql.exec(
    'CREATE TABLE IF NOT EXISTS remote_invites(seq INTEGER PRIMARY KEY AUTOINCREMENT,user TEXT,room TEXT,peer TEXT,signed TEXT,stripped TEXT,joining TEXT,UNIQUE(user,room))'
  );
  if (!sql.exec('PRAGMA table_info(remote_invites)').toArray().some((col) => col.name === 'version'))
    sql.exec('ALTER TABLE remote_invites ADD COLUMN version INTEGER NOT NULL DEFAULT 10');
}
export async function receiveInvite(home, server, peer, room, id, body) {
  const p = body.event;
  const version = Number(body.room_version);
  if (!['10','11'].includes(body.room_version))
    fail(400, 'M_INCOMPATIBLE_ROOM_VERSION', 'The spike supports room versions 10 and 11');
  if (
    !p ||
    p.type !== 'm.room.member' ||
    p.content?.membership !== 'invite' ||
    domain(p.sender) !== peer ||
    p.room_id !== room ||
    domain(p.state_key) !== server ||
    eventId(p,version) !== id
  )
    fail(400, 'M_INVALID_PARAM', 'Invalid invite event');
  const existing = load(home,server,room);
  if (existing.tips.size) {
    requireRoomAccess(existing.get('m.room.server_acl'),peer);
    if (existing.version !== version) fail(400,'M_INCOMPATIBLE_ROOM_VERSION','Room version differs from local state');
  }
  await openParty(home, server, p.state_key);
  verify_signed_pdu(JSON.stringify(p), JSON.stringify(graphKeys(home)),version);
  const signed = await signPdu(home.identity, server, p,version);
  if (home.sql.exec('SELECT 1 FROM room_events WHERE room=? LIMIT 1', room).toArray().length)
    await receiveEvent(home, server, peer, signed);
  else {
    const prior = home.sql
      .exec('SELECT signed,version FROM remote_invites WHERE user=? AND room=?', p.state_key, room)
      .toArray()[0];
    if (prior && eventId(JSON.parse(prior.signed),prior.version) === id) return ok({ event: JSON.parse(prior.signed) });
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
      'INSERT OR REPLACE INTO remote_invites(user,room,peer,signed,stripped,version) VALUES(?,?,?,?,?,?)',
      p.state_key,
      room,
      peer,
      JSON.stringify(signed),
      JSON.stringify(preview),version
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
  const version = invite.version ?? 10;
  const peer = invite.peer,
    prefix = '/_matrix/federation/',
    rid = encodeURIComponent(room);
  const request = async (method, path, content) => {
    const response = await remote(home, server, peer, method, prefix + path, content);
    return JSON.parse(new TextDecoder().decode(await limited(response.body, 4 * 1024 * 1024)));
  };
  // Save the exact signed join before the first remote write; retries use the same signed event ID.
  let join = invite.joining && JSON.parse(invite.joining);
  if (!join) {
    const template = await request('GET', 'v1/make_join/' + rid + '/' + encodeURIComponent(user) + '?ver=10&ver=11');
    if (template.room_version !== String(version)) fail(400, 'M_INCOMPATIBLE_ROOM_VERSION', 'Room version differs from the signed invitation');
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
      content: { membership: 'join', ...await home.profile?.(user,server) },
      origin: server,
      origin_server_ts: Date.now(),
      depth: p.depth,
      prev_events: p.prev_events,
      auth_events: p.auth_events
    };
    join = await signPdu(home.identity, server, proposal,version);
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
    'v2/send_join/' + rid + '/' + encodeURIComponent(eventId(join,version)),
    join
  );
  if (
    response.members_omitted ||
    !Array.isArray(response.auth_chain) ||
    !Array.isArray(response.state) ||
    (response.origin !== undefined && response.origin !== peer)
  )
    fail(502, 'M_BAD_JSON', 'Full room state required');
  const base = joinBase(room, response.state, response.auth_chain, join,version);
  const origins = new Set(base.auth.map((p) => domain(p.sender)));
  for (const origin of origins) if (origin !== server) await peerRecord(home, origin);
  const keys = { ...graphKeys(home), [server]: verificationKeys(home.identity) };
  const state = new Map(resolveJoin(room, keys, base, [],version).map(([type,key,id]) => [JSON.stringify([type,key]),id]));
  const acl = response.state.find((p) => p.type === 'm.room.server_acl' && p.state_key === '');
  requireRoomAccess(acl,server);
  requireRoomAccess(acl,peer);
  const members = response.state.filter((p) => p.type === 'm.room.member');
  if (!members.some((m) => domain(m.state_key) === peer && m.content.membership === 'join'))
    fail(403, 'M_FORBIDDEN', 'The assisting server is not resident in this room');
  if (!members.some((m) => m.state_key === user && eventId(m,version) === eventId(JSON.parse(invite.signed),version)))
    fail(403, 'M_FORBIDDEN', 'The room state does not include the accepted invitation');
  for (const m of members)
    if (['join','invite'].includes(m.content.membership)) await openParty(home,server,m.state_key);

  home.ctx.storage.transactionSync(() => {
    const pending = home.sql.exec('SELECT signed FROM remote_invites WHERE user=? AND room=?',user,room).toArray()[0];
    const current = load(home,server,room);
    if (current.get('m.room.member',user)?.content.membership === 'join') return;
    if (pending?.signed !== invite.signed) fail(409,'M_UNKNOWN','Invitation changed during join');
    if (current.tips.size) {
      if (current.version !== version) fail(400,'M_INCOMPATIBLE_ROOM_VERSION','Room version changed');
      current.checkCurrent(join);
      current.add(join);
      save(home,current,[join]);
    } else {
      // Outliers supply signatures, authorization and state. Only the join and its
      // descendants belong to the local timeline and drive pagination or sync.
      for (const [position,event] of base.auth.entries())
        home.sql.exec('INSERT INTO room_outliers VALUES(?,?,?,?)',room,eventId(event,version),position,JSON.stringify(event));
      const id = eventId(join,version);
      home.sql.exec('INSERT INTO room_bases VALUES(?,?,?)',room,id,JSON.stringify(base.stateIds));
      save(home,{room,state,version,tips:new Set([id])},[join]);
    }
    home.sql.exec(
      'DELETE FROM remote_invites WHERE user=? AND room=? AND signed=?',
      user,
      room,
      invite.signed
    );
  });
  return ok({ room_id: room });
}
