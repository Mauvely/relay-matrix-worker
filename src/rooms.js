// SPDX-License-Identifier: AGPL-3.0-or-later
import { saveAudience, missingEvents } from './history.js';
import { acl_allows } from '../room-v10/pkg/relay_room_v10.js';
import { verificationKeys } from './identity.js';
import { StoredEvents } from './stored-events.js';
import { graphKeys, peerRecord } from './discovery.js';
import { clientEvent, domain, eventId, RoomGraph } from './graph.js';

export const ok = (body = {}) => ({ status: 200, body });
export function fail(status, errcode, error) {
  throw Object.assign(new Error(error), { status, errcode });
}
const denied = (msg) => fail(403, 'M_FORBIDDEN', msg);
export const missing = () => fail(404, 'M_NOT_FOUND', 'Unknown room or resource');
const invalid = (msg) => fail(400, 'M_INVALID_PARAM', msg);
const unready = (msg) => fail(503, 'M_UNAVAILABLE', msg);
export const isObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
export function schema(sql) {
  sql.exec(`CREATE TABLE IF NOT EXISTS room_events(seq INTEGER PRIMARY KEY AUTOINCREMENT,room TEXT,eid TEXT UNIQUE,pdu TEXT);
    CREATE TABLE IF NOT EXISTS history_audience_refs(room TEXT,eid TEXT,source TEXT,PRIMARY KEY(room,eid));
    CREATE TABLE IF NOT EXISTS history_audiences(room TEXT,source TEXT,audience TEXT,PRIMARY KEY(room,source));
    CREATE TABLE IF NOT EXISTS room_versions(room TEXT PRIMARY KEY,version INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS room_outliers(room TEXT,eid TEXT PRIMARY KEY,position INTEGER,pdu TEXT);
    CREATE INDEX IF NOT EXISTS room_outlier_order ON room_outliers(room,position);
    CREATE TABLE IF NOT EXISTS room_bases(room TEXT PRIMARY KEY,join_id TEXT,state_ids TEXT);
    CREATE VIEW IF NOT EXISTS room_known_events AS SELECT room,eid,pdu FROM room_events UNION ALL SELECT room,eid,pdu FROM room_outliers;
    CREATE INDEX IF NOT EXISTS room_history ON room_events(room,seq);
    CREATE TABLE IF NOT EXISTS room_state(room TEXT,kind TEXT,skey TEXT,eid TEXT,PRIMARY KEY(room,kind,skey));
    CREATE TABLE IF NOT EXISTS room_checkpoints(room TEXT,first_seq INTEGER,last_seq INTEGER,state TEXT,PRIMARY KEY(room,last_seq));
    CREATE TABLE IF NOT EXISTS room_tips(room TEXT,eid TEXT,PRIMARY KEY(room,eid));
    CREATE TABLE IF NOT EXISTS profile_updates(server TEXT,user TEXT,room TEXT,due INTEGER DEFAULT 0,PRIMARY KEY(user,room));
    CREATE TABLE IF NOT EXISTS room_tx(id TEXT PRIMARY KEY,eid TEXT);
    CREATE TABLE IF NOT EXISTS outbound(id TEXT PRIMARY KEY,server TEXT,peer TEXT,path TEXT,content TEXT);
    CREATE TABLE IF NOT EXISTS received(id TEXT PRIMARY KEY,response TEXT);
    CREATE TABLE IF NOT EXISTS retry(id TEXT PRIMARY KEY,attempt INTEGER NOT NULL,due INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS user_data(seq INTEGER PRIMARY KEY AUTOINCREMENT,user TEXT,kind TEXT,content TEXT,UNIQUE(user,kind));`);
}
export function roomVersion(sql, room) {
  return sql.exec('SELECT version FROM room_versions WHERE room=?', room).toArray()[0]?.version ?? 10;
}
export function load(home, server, room) {
  const version = roomVersion(home.sql,room);
  const sql = home.sql;
  const keys = { ...graphKeys(home), [server]: verificationKeys(home.identity) };
  const tips = new Set(sql.exec('SELECT eid FROM room_tips WHERE room=?', room).toArray().map((r) => r.eid));
  if (!tips.size) {
    // Rooms from before the checkpoint schema have at most 512 PDUs. Rebuild their tips once.
    const rows = sql.exec('SELECT eid,pdu FROM room_events WHERE room=? ORDER BY seq', room).toArray();
    const graph = new RoomGraph(room, keys, rows, undefined, undefined, version);
    if (rows.length) home.ctx.storage.transactionSync(() => {
      for (const id of graph.tips) sql.exec('INSERT OR IGNORE INTO room_tips VALUES(?,?)', room, id);
    });
    return graph;
  }
  const state = new Map(sql.exec('SELECT kind,skey,eid FROM room_state WHERE room=?', room).toArray()
    .map((r) => [JSON.stringify([r.kind, r.skey]), r.eid]));
  return new RoomGraph(room, keys, [], {state, tips, events: new StoredEvents(sql, room)},undefined,version);

}
// Until managed-room reconciliations can run atomically, these new live room routes
// admit only personal and explicitly open accounts. Existing device rules still apply.
export async function openParty(home, server, user) {
  const host = domain(user);
  if (!host) invalid('A full Matrix user ID is required');
  // Local room reads and writes can continue while an independent peer is offline.
  // Resolve hosted account policy via the account's tenant. The transport verifies
  // the independent server's identity when delivering or accepting federation.
  if (host !== server && !Object.values(home.env.DOMAINS ?? {}).includes(host)) return;
  const p = host === server ? await home.party(user, server)
    : await home.env.HOMESERVERS.getByName(host).party(user, host);
  if (!p) missing();
  if (p.organisationId !== null && home.env.ORGANISATIONS?.[p.organisationId]?.policy !== 'open')
    denied('Managed room operations are unavailable for this account');
}
// Room ACLs govern network participation independently of Matrix event authorization.
export function requireRoomAccess(acl, server) {
  if (acl && !acl_allows(JSON.stringify(acl.content),server))
    denied('Server is denied by the room access control list');
}
async function checkParties(home, server, g) {
  for (const e of g.members())
    if (['join', 'invite'].includes(e.content.membership)) await openParty(home, server, e.state_key);
}
export function save(home, g, pdus) {
  if (g.version === 11) home.sql.exec('INSERT OR IGNORE INTO room_versions VALUES(?,?)',g.room,g.version);
  let firstInserted;
  let lastInserted;
  for (const p of pdus) {
    const id = eventId(p,g.version);
    const row = home.sql.exec(
      'INSERT OR IGNORE INTO room_events(room,eid,pdu) VALUES(?,?,?) RETURNING seq',
      g.room,
      id,
      JSON.stringify(p)
    ).toArray()[0];
    if (row) {
      saveAudience(home.sql,g,id,p);
      firstInserted ??= row.seq;
      lastInserted = row.seq;
    }
  }
  home.sql.exec('DELETE FROM room_tips WHERE room=?', g.room);
  for (const tip of g.tips) home.sql.exec('INSERT INTO room_tips VALUES(?,?)', g.room, tip);
  if (g.unchangedState) return;
  if (lastInserted !== undefined)
    home.sql.exec('INSERT INTO room_checkpoints VALUES(?,?,?,?)', g.room, firstInserted, lastInserted,
      JSON.stringify([...g.state.values()]));
  home.sql.exec('DELETE FROM room_state WHERE room=?', g.room);
  for (const [key, id] of g.state)
    home.sql.exec('INSERT INTO room_state VALUES(?,?,?,?)', g.room, ...JSON.parse(key), id);
}
export function queue(home, server, peer, pdus, edus = []) {
  const id = crypto.randomUUID(),
    path = '/_matrix/federation/v1/send/' + id;
  home.sql.exec(
    'INSERT INTO outbound VALUES(?,?,?,?,?)',
    id,
    server,
    peer,
    path,
    JSON.stringify({
      origin: server,
      origin_server_ts: Date.now(),
      pdus,
      edus
    })
  );
}
function commit(home, server, g, events, extra) {
  home.ctx.storage.transactionSync(() => {
    save(home, g, events);
    for (const peer of new Set(g.members('join').map((e) => domain(e.state_key))))
      if (peer !== server && events.some((e) => domain(e.sender) === server))
        queue(
          home,
          server,
          peer,
          events.filter((e) => domain(e.sender) === server)
        );
    for (const event of events) {
      if (
        event.type !== 'm.room.member' ||
        event.content.membership !== 'invite' ||
        domain(event.sender) !== server ||
        domain(event.state_key) === server
      )
        continue;
      const state = [...g.state.values()]
        .map((id) => g.events.get(id))
        .filter(
          (e) =>
            [
              'm.room.create',
              'm.room.name',
              'm.room.avatar',
              'm.room.join_rules',
              'm.room.encryption'
            ].includes(e.type) ||
            e === event ||
            (e.type === 'm.room.member' && e.state_key === event.sender)
        )
        .map(({ type, sender, state_key, content }) => ({
          type,
          sender,
          state_key,
          content
        }));
      const id = eventId(event,g.version);
      home.sql.exec(
        'INSERT INTO outbound VALUES(?,?,?,?,?)',
        id,
        server,
        domain(event.state_key),
        '/_matrix/federation/v2/invite/' + encodeURIComponent(g.room) + '/' + encodeURIComponent(id),
        JSON.stringify({ room_version: String(g.version), event, invite_room_state: state })
      );
    }
    extra?.();
  });
  for (const set of home.waiters.values()) for (const wake of set) wake();
}
export function queueProfileUpdates(home, server, user, profile) {
  home.sql.exec(`INSERT OR IGNORE INTO profile_updates(server,user,room)
    SELECT ?,?,s.room FROM room_state s JOIN room_known_events e ON e.eid=s.eid
    WHERE kind='m.room.member' AND skey=? AND json_extract(pdu,'$.content.membership')='join'
    AND (json_extract(pdu,'$.content.displayname') IS NOT ? OR json_extract(pdu,'$.content.avatar_url') IS NOT ?)`,
    server,user,user,profile.displayname ?? null,profile.avatar_url ?? null);
}
export async function publishProfile(home,server,user,room) {
  const g = load(home,server,room);
  const old = g.get('m.room.member',user)?.content;
  if (old?.membership !== 'join') return;
  await checkParties(home,server,g);
  const profile = await home.profile(user,server);
  if (!profile || (old.displayname === profile.displayname && old.avatar_url === profile.avatar_url)) return;
  const {displayname,avatar_url,...member} = old;
  const pdu = await g.local(home.identity,user,'m.room.member',{...member,...profile},user);
  commit(home,server,g,[pdu]);
}

export async function create(home, server, user, data) {
  await openParty(home, server, user);
  if (data.room_version !== undefined && !['10','11'].includes(data.room_version))
    fail(400, 'M_UNSUPPORTED_ROOM_VERSION', 'This homeserver implements room versions 10 and 11');
  if (data.room_alias_name || data.invite_3pid?.length || data.creation_content?.predecessor)
    invalid('Aliases, third-party invitations and room upgrades are unavailable');
  const invites = data.invite ?? [],
    initial = data.initial_state ?? [];
  if (!Array.isArray(invites) || invites.length > 16 || !Array.isArray(initial) || initial.length > 32)
    invalid('Invalid initial room state');
  for (const target of invites) await openParty(home, server, target);
  const room = '!' + crypto.randomUUID() + ':' + server,
    g = load(home, server, room);
  g.version = Number(data.room_version ?? 10);
  const add = (t, c, k = '') => g.local(home.identity, user, t, c, k);
  await add('m.room.create', {
    ...data.creation_content,
    ...(g.version === 10 ? {creator:user} : {}),
    room_version: String(g.version)
  });
  await add('m.room.member', { membership: 'join', ...await home.profile?.(user,server) }, user);
  await add('m.room.power_levels', {
    users: { [user]: 100 },
    state_default: 50,
    events_default: 0,
    users_default: 0,
    invite: 0,
    kick: 50,
    ban: 50,
    redact: 50,
    ...data.power_level_content_override
  });
  const defaults = new Map([
    [
      'm.room.join_rules',
      {
        join_rule:
          data.preset === 'public_chat' || (!data.preset && data.visibility === 'public')
            ? 'public'
            : 'invite'
      }
    ],
    ['m.room.history_visibility', { history_visibility: 'joined' }]
  ]);
  for (const e of initial) if (e?.state_key === '' || e?.state_key === undefined) defaults.delete(e?.type);
  for (const [type, content] of defaults) await add(type, content);
  for (const e of initial) {
    if (
      !isObject(e) ||
      !isObject(e.content) ||
      typeof e.type !== 'string' ||
      ['m.room.create', 'm.room.member', 'm.room.power_levels'].includes(e.type)
    )
      invalid('Invalid initial state event');
    await add(e.type, e.content, e.state_key ?? '');
  }
  if (data.name) await add('m.room.name', { name: data.name });
  if (data.topic) await add('m.room.topic', { topic: data.topic });
  for (const id of new Set(invites))
    if (id !== user)
      await add('m.room.member', { membership: 'invite', is_direct: data.is_direct === true }, id);
  commit(home, server, g, [...g.events.values()]);
  return ok({ room_id: room });
}
function pageToken(room, seq) {
  return room + '/' + seq;
}

function pagePosition(room, value, fallback) {
  if (value === null || value === '') return fallback;
  const prefix = room + '/';
  const seq = value.startsWith(prefix) ? value.slice(prefix.length) : '';
  if (!/^\d+$/.test(seq) || !Number.isSafeInteger(Number(seq))) invalid('Invalid room history token');
  return Number(seq);
}

// A profile update is another membership event with membership=join. It must not
// move the history boundary. A leave followed by a rejoin establishes a new one.
function joinFloor(home, room, user) {
  return home.sql.exec(`SELECT MIN(seq) AS floor FROM room_events WHERE room=?1
    AND json_extract(pdu,'$.type')='m.room.member' AND json_extract(pdu,'$.state_key')=?2
    AND json_extract(pdu,'$.content.membership')='join' AND seq>COALESCE((
      SELECT MAX(seq) FROM room_events WHERE room=?1 AND json_extract(pdu,'$.type')='m.room.member'
      AND json_extract(pdu,'$.state_key')=?2 AND json_extract(pdu,'$.content.membership')!='join'),0)`,room,user).one().floor;
}

function messagePage(home, room, user, params) {
  const dir = params.get('dir');
  if (!['b', 'f'].includes(dir)) invalid('Expected a history direction');
  const backwards = dir === 'b';
  const floor = joinFloor(home, room, user);
  if (floor === null) denied('No local room membership');
  const ceiling = home.sql.exec('SELECT MAX(seq)+1 AS n FROM room_events WHERE room=?', room).one().n;
  const from = pagePosition(room, params.get('from'), backwards ? ceiling : floor);
  const to = pagePosition(room, params.get('to'), backwards ? floor : ceiling);
  const limit = Number(params.get('limit') ?? 10);
  if (!Number.isSafeInteger(limit) || limit < 0) invalid('Invalid history limit');
  const filter = JSON.parse(params.get('filter') || '{}');
  if (!isObject(filter)) invalid('Invalid room filter');
  const rows = home.sql
    .exec(
      'SELECT seq,eid,pdu FROM room_events WHERE room=? AND seq>=? AND seq<? ORDER BY seq ' +
        (backwards ? 'DESC' : 'ASC') + ' LIMIT 101',
      room,
      Math.max(floor, backwards ? to : from),
      Math.min(ceiling, backwards ? from : to)
    )
    .toArray();
  const matches = (patterns, text, glob) =>
    patterns?.some((pattern) => {
      if (typeof pattern !== 'string') invalid('Invalid room filter');
      if (!glob) return pattern === text;
      const pieces = pattern.split('*');
      if (pieces.length === 1) return text === pattern;
      const first = pieces.shift(),
        last = pieces.pop();
      if (!text.startsWith(first) || !text.endsWith(last)) return false;
      let pos = first.length;
      for (const part of pieces) {
        const match = text.indexOf(part, pos);
        if (match < 0) return false;
        pos = match + part.length;
      }
      return pos <= text.length - last.length;
    });
  const page = [];
  let last;
  let more = false;
  for (const row of rows) {
    if (page.length >= Math.min(limit, 100) || (rows.length === 101 && row === rows[100])) { more = true; break; }
    last = row.seq;
    const e = clientEvent(JSON.parse(row.pdu), row.eid);
    if (
      (filter.types && !matches(filter.types, e.type, true)) ||
      matches(filter.not_types, e.type, true) ||
      (filter.senders && !matches(filter.senders, e.sender)) ||
      matches(filter.not_senders, e.sender) ||
      (filter.rooms && !matches(filter.rooms, room)) ||
      matches(filter.not_rooms, room) ||
      ('contains_url' in filter && filter.contains_url !== (typeof e.content?.url === 'string'))
    )
      continue;

    page.push(e);
  }
  return ok({
    start: pageToken(room, from),
    chunk: page,
    ...(more && last !== undefined ? { end: pageToken(room, backwards ? last : last + 1) } : {})
  });
}

export async function roomClient(home, server, auth, method, parts, data, params = new URLSearchParams()) {
  const [room, action, kind, key] = parts,
    user = auth.user_id;
  await openParty(home, server, user);
  const g = load(home, server, room);
  if (!g.tips.size) missing();
  await checkParties(home, server, g);
  const membership = g.get('m.room.member', user)?.content.membership;
  if (method === 'POST' && action === 'join' && membership === 'join') return ok({ room_id: room });
  if (
    membership !== 'join' &&
    !(
      method === 'POST' &&
      action === 'join' &&
      (membership === 'invite' || g.get('m.room.join_rules')?.content.join_rule === 'public')
    )
  )
    denied('Room membership required');
  if (method === 'GET' && action === 'messages')
    return messagePage(home, room, user, params);
  if (method === 'GET' && action === 'state') {
    if (kind) {
      const e = g.get(kind, key ?? '');
      return e ? ok(e.content) : missing();
    }
    return ok([...g.state.values()].map((id) => clientEvent(g.events.get(id), id)));
  }
  if (method === 'GET' && action === 'joined_members') {
    const joined = Object.fromEntries(g.members('join').map(({state_key, content}) => [state_key, {
      ...(typeof content.displayname === 'string' && {display_name: content.displayname}),
      ...(typeof content.avatar_url === 'string' && {avatar_url: content.avatar_url})
    }]));
    return ok({joined});
  }
  if (method === 'GET' && action === 'members') return ok({ chunk: g.members().map((e) => clientEvent(e,eventId(e,g.version))) });
  if (method !== 'GET') requireRoomAccess(g.get('m.room.server_acl'), server);
  let type,
    content = data,
    stateKey,
    tx;
  if (method === 'POST' && ['join', 'invite', 'leave'].includes(action)) {
    stateKey = action === 'invite' ? data.user_id : user;
    if (action === 'invite') requireRoomAccess(g.get('m.room.server_acl'),domain(stateKey));
    await openParty(home, server, stateKey);
    type = 'm.room.member';
    content = { membership: action, ...(action === 'join' && await home.profile?.(user,server)) };
  } else if (method === 'PUT' && action === 'send' && kind && key) {
    type = kind;
    tx = JSON.stringify([user, auth.device_id, room, kind, key]);
    const prior = home.sql.exec('SELECT eid FROM room_tx WHERE id=?', tx).toArray()[0];
    if (prior) return ok({ event_id: prior.eid });
  } else if (
    method === 'PUT' &&
    action === 'state' &&
    kind &&
    !['m.room.member', 'm.room.create'].includes(kind)
  ) {
    type = kind;
    stateKey = key ?? '';
  } else missing();
  if (!isObject(content)) invalid('Expected event content');
  const event = await g.local(home.identity, user, type, content, stateKey),
    id = eventId(event,g.version);
  commit(home, server, g, [event], () => {
    if (tx) home.sql.exec('INSERT INTO room_tx VALUES(?,?)', tx, id);
  });
  return ok(
    action === 'join' ? { room_id: room } : action === 'send' || action === 'state' ? { event_id: id } : {}
  );
}
export async function fedRoom(home, server, peer, method, parts, params, body) {
  const [action, room, value] = parts,
    g = load(home, server, room);
  if (!g.tips.size) missing();
  await checkParties(home, server, g);
  requireRoomAccess(g.get('m.room.server_acl'),peer);
  if (g.get('m.room.create')?.content['m.federate'] === false) denied('Federation disabled');
  if (action === 'get_missing_events' && method === 'POST') {
    if (!g.members('join').some((e) => domain(e.state_key) === peer)) denied('Server is not joined');
    return ok({events:missingEvents(home.sql,g,peer,body)});
  }
  if (action === 'make_join' && method === 'GET') {
    if (domain(value) !== peer) denied('Origin must own user');
    if (!params.getAll('ver').includes(String(g.version)))
      fail(400, 'M_INCOMPATIBLE_ROOM_VERSION', 'Peer does not support this room version');
    const membership = g.get('m.room.member', value)?.content.membership;
    if (
      membership === 'ban' ||
      (!['invite', 'join'].includes(membership) && g.get('m.room.join_rules')?.content.join_rule !== 'public')
    )
      denied('An invitation is required');
    return ok({
      room_version: String(g.version),
      event: g.template(value, 'm.room.member', { membership: 'join' }, value)
    });
  }
  if (action === 'send_join' && method === 'PUT') {
    const cache = 'join/' + peer + '/' + room + '/' + value;
    if (
      body.room_id !== room ||
      body.type !== 'm.room.member' ||
      body.state_key !== body.sender ||
      domain(body.sender) !== peer ||
      body.content?.membership !== 'join' ||
      eventId(body,g.version) !== value
    )
      invalid('Invalid join event');
    const prior = home.sql.exec('SELECT response FROM received WHERE id=?', cache).toArray()[0];
    if (prior) return ok(JSON.parse(prior.response));
    const state = g.before(body.prev_events);
    const ids = new Set(),
      pending = state.flatMap((e) => e.auth_events);
    while (pending.length) {
      const id = pending.pop();
      if (!ids.has(id)) {
        ids.add(id);
        pending.push(...g.events.get(id).auth_events);
      }
    }
    const result = {
      origin: server,
      state,
      auth_chain: [...ids].map((id) => g.events.get(id)),
      event: body,
      members_omitted: false
    };
    g.checkCurrent(body);
    if (
      !['invite', 'join'].includes(g.get('m.room.member', body.sender)?.content.membership) &&
      g.get('m.room.join_rules')?.content.join_rule !== 'public'
    )
      denied('An invitation is required');
    g.add(body);
    commit(home, server, g, [body], () =>
      home.sql.exec('INSERT INTO received VALUES(?,?)', cache, JSON.stringify(result))
    );
    return ok(result);
  }
  missing();
}

export async function receiveEvent(home, server, peer, pdu, recovered = []) {
  const g = load(home, server, pdu.room_id);
  if (!g.tips.size || !g.members('join').some((e) => domain(e.state_key) === server)) missing();
  requireRoomAccess(g.get('m.room.server_acl'),peer);
  if (g.events.has(eventId(pdu,g.version))) return;
  if (!g.members('join').some((m) => domain(m.state_key) === peer)) denied('Sending server is not resident');
  await checkParties(home, server, g);
  const additions = [];
  for (const event of [...recovered,pdu]) {
    if (event.room_id !== g.room) invalid('Room ID mismatch');
    if (g.events.has(eventId(event,g.version))) continue;
    requireRoomAccess(g.get('m.room.server_acl'),peer);
    requireRoomAccess(g.get('m.room.server_acl'),domain(event.sender));
    if (!Array.isArray(event.prev_events) || event.prev_events.some((id) => !g.events.has(id)))
      unready('Missing predecessor');
    if (event.type === 'm.room.member') await openParty(home,server,event.state_key);
    const author = domain(event.sender);
    if (author !== server && !g.keys[author]) g.keys[author] = (await peerRecord(home,author)).keys;
    g.checkCurrent(event);
    g.add(event);
    additions.push(event);
  }
  if (additions.length) commit(home,server,g,additions);
}
// The timeline is in local stream order. Its starting state must reflect all branches
// already committed at that point, including when an older device missed a fork.
function stateBeforeStream(home, server, room, firstSeq) {
  const checkpoint = home.sql.exec(
    'SELECT last_seq,state FROM room_checkpoints WHERE room=? AND first_seq<? ORDER BY last_seq DESC LIMIT 1',
    room, firstSeq
  ).toArray()[0];
  if (checkpoint && checkpoint.last_seq < firstSeq) {
    const store = new StoredEvents(home.sql, room);
    return JSON.parse(checkpoint.state).map((id) => clientEvent(store.get(id), id));
  }
  // Older rooms lack checkpoints. A sync may also start inside an imported multi-event batch.
  const prior = home.sql.exec('SELECT eid,pdu FROM room_events WHERE room=? AND seq<? ORDER BY seq', room, firstSeq).toArray();
  const keys = { ...graphKeys(home), [server]: verificationKeys(home.identity) };
  const store = new StoredEvents(home.sql, room);
  const base = store.joinBase();
  if (base && !prior.length) return base.stateIds.map((id) => clientEvent(store.get(id),id));
  const prefix = new RoomGraph(room, keys, prior, undefined, base,roomVersion(home.sql,room));
  return [...prefix.state.values()].map((id) => clientEvent(prefix.events.get(id) ?? store.get(id), id));
}
export async function roomSync(home, server, user, cursor, initial) {
  const high = home.sql.exec('SELECT COALESCE(MAX(seq),0) AS n FROM room_events').one().n;
  const rooms = { join: {}, invite: {}, leave: {} },
    changed = new Set();
  const memberships = home.sql.exec(
    'SELECT s.room,e.pdu FROM room_state s JOIN room_known_events e ON e.eid=s.eid WHERE kind=? AND skey=?',
    'm.room.member',
    user
  );
  for (const row of memberships.toArray()) {
    const membership = JSON.parse(row.pdu).content.membership;
    if (
      !initial &&
      !home.sql.exec('SELECT 1 FROM room_events WHERE room=? AND seq>? LIMIT 1', row.room, cursor).toArray()
        .length
    )
      continue;
    const stateRows = home.sql
      .exec('SELECT s.eid,e.pdu FROM room_state s JOIN room_known_events e ON e.eid=s.eid WHERE s.room=?', row.room)
      .toArray();
    const stateEvents = stateRows.map((r) => clientEvent(JSON.parse(r.pdu), r.eid));
    const members = stateEvents.filter((e) => e.type === 'm.room.member');
    for (const m of members)
      if (['join', 'invite'].includes(m.content.membership)) await openParty(home, server, m.state_key);
    const own = members.find((e) => e.state_key === user);
    if (membership === 'invite') {
      const allowed = [
        'm.room.create',
        'm.room.join_rules',
        'm.room.name',
        'm.room.encryption',
        'm.room.avatar',
        'm.room.canonical_alias'
      ];
      rooms.invite[row.room] = {
        invite_state: {
          events: stateEvents
            .filter(
              (e) =>
                allowed.includes(e.type) ||
                (e.type === 'm.room.member' && (e.state_key === user || e.state_key === own.sender))
            )
            .map(({ sender, type, state_key, content }) => ({
              sender,
              type,
              state_key,
              content
            }))
        }
      };
    } else if (membership === 'join') {
      const sinceJoin = joinFloor(home, row.room, user);
      if (sinceJoin === null) continue;
      const joinedNow = initial || sinceJoin > cursor;
      const rows = home.sql
        .exec(
          'SELECT seq,pdu,eid FROM room_events WHERE room=? AND seq>=? ORDER BY seq DESC LIMIT 51',
          row.room,
          Math.max(sinceJoin, cursor + 1)
        )
        .toArray();
      const limited = rows.length > 50;
      if (limited) rows.pop();
      rows.reverse();
      const events = rows.map((r) => clientEvent(JSON.parse(r.pdu), r.eid));
      const state = (joinedNow || limited) && rows.length ? stateBeforeStream(home, server, row.room, rows[0].seq) : [];
      rooms.join[row.room] = {
        state: { events: state },
        timeline: {
          events,
          limited,
          ...(rows.length ? { prev_batch: pageToken(row.room, rows[0].seq) } : {})
        },
        ephemeral: { events: [] },
        account_data: { events: [] }
      };
      if (limited && !joinedNow) {
        const skipped = home.sql.exec(
          "SELECT DISTINCT json_extract(pdu,'$.state_key') AS member FROM room_events WHERE room=? AND seq>? AND seq<? AND json_extract(pdu,'$.type')='m.room.member'",
          row.room, cursor, rows[0].seq
        ).toArray();
        for (const m of skipped) changed.add(m.member);
      }
      for (const m of joinedNow
        ? members.filter((m) => m.content.membership === 'join')
        : events.filter((e) => e.type === 'm.room.member'))
        changed.add(m.state_key);
    } else if (!initial)
      rooms.leave[row.room] = {
        timeline: { events: [own], limited: false },
        state: { events: [] }
      };
  }
  return { rooms, high, changed: [...changed] };
}
