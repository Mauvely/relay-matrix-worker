// SPDX-License-Identifier: AGPL-3.0-or-later
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
    CREATE INDEX IF NOT EXISTS room_history ON room_events(room,seq);
    CREATE TABLE IF NOT EXISTS room_state(room TEXT,kind TEXT,skey TEXT,eid TEXT,PRIMARY KEY(room,kind,skey));
    CREATE TABLE IF NOT EXISTS room_tx(id TEXT PRIMARY KEY,eid TEXT);
    CREATE TABLE IF NOT EXISTS outbound(id TEXT PRIMARY KEY,server TEXT,peer TEXT,path TEXT,content TEXT);
    CREATE TABLE IF NOT EXISTS received(id TEXT PRIMARY KEY,response TEXT);
    CREATE TABLE IF NOT EXISTS retry(id TEXT PRIMARY KEY,attempt INTEGER NOT NULL,due INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS user_data(seq INTEGER PRIMARY KEY AUTOINCREMENT,user TEXT,kind TEXT,content TEXT,UNIQUE(user,kind));`);
}
function load(home, server, room) {
  return new RoomGraph(
    room,
    { ...home.env.PEER_KEYS, [server]: { 'ed25519:1': home.identity.publicKey } },
    home.sql.exec('SELECT eid,pdu FROM room_events WHERE room=? ORDER BY seq', room).toArray()
  );
}
// Until managed-room reconciliations can run atomically, these new live room routes
// admit only personal and explicitly open accounts. Existing device rules still apply.
export async function openParty(home, server, user) {
  if (!domain(user)) invalid('A full Matrix user ID is required');
  if (domain(user) !== server) {
    if (!home.env.PEER_KEYS?.[domain(user)] || !home.env.PEER_URLS?.[domain(user)])
      unready('Federation peer is not configured');
    return;
  }
  const p = await home.party(user, server);
  if (!p) missing();
  if (p.organisationId !== null && home.env.ORGANISATIONS?.[p.organisationId]?.policy !== 'open')
    denied('Managed room operations are unavailable for this account');
}
async function checkParties(home, server, g) {
  for (const e of g.members())
    if (['join', 'invite'].includes(e.content.membership)) await openParty(home, server, e.state_key);
}
export function save(home, g, pdus) {
  for (const p of pdus)
    home.sql.exec(
      'INSERT OR IGNORE INTO room_events(room,eid,pdu) VALUES(?,?,?)',
      g.room,
      eventId(p),
      JSON.stringify(p)
    );
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
    JSON.stringify({ origin: server, origin_server_ts: Date.now(), pdus, edus })
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
        .map(({ type, sender, state_key, content }) => ({ type, sender, state_key, content }));
      const id = eventId(event);
      home.sql.exec(
        'INSERT INTO outbound VALUES(?,?,?,?,?)',
        id,
        server,
        domain(event.state_key),
        '/_matrix/federation/v2/invite/' + encodeURIComponent(g.room) + '/' + encodeURIComponent(id),
        JSON.stringify({ room_version: '10', event, invite_room_state: state })
      );
    }
    extra?.();
  });
  for (const set of home.waiters.values()) for (const wake of set) wake();
}
export async function create(home, server, user, data) {
  await openParty(home, server, user);
  if (data.room_version && data.room_version !== '10')
    fail(400, 'M_UNSUPPORTED_ROOM_VERSION', 'This homeserver implements room version 10');
  if (data.room_alias_name || data.invite_3pid?.length || data.creation_content?.predecessor)
    invalid('Aliases, third-party invitations and room upgrades are unavailable');
  const invites = data.invite ?? [],
    initial = data.initial_state ?? [];
  if (!Array.isArray(invites) || invites.length > 16 || !Array.isArray(initial) || initial.length > 32)
    invalid('Invalid initial room state');
  for (const target of invites) await openParty(home, server, target);
  const room = '!' + crypto.randomUUID() + ':' + server,
    g = load(home, server, room);
  const add = (t, c, k = '') => g.local(home.identity, user, t, c, k);
  await add('m.room.create', { ...data.creation_content, creator: user, room_version: '10' });
  await add('m.room.member', { membership: 'join' }, user);
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
      ['m.room.create', 'm.room.member', 'm.room.server_acl', 'm.room.power_levels'].includes(e.type)
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

function messagePage(home, room, joinId, params) {
  const dir = params.get('dir');
  if (!['b', 'f'].includes(dir)) invalid('Expected a history direction');
  const backwards = dir === 'b';
  const floor = home.sql.exec('SELECT seq FROM room_events WHERE eid=?', joinId).one().seq;
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
        (backwards ? 'DESC' : 'ASC'),
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
  for (const row of rows) {
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
    if (page.length >= Math.min(limit, 100)) break;
    last = row.seq;
    page.push(e);
  }
  const more = last !== undefined && rows.at(-1)?.seq !== last;
  return ok({
    start: pageToken(room, from),
    chunk: page,
    ...(more ? { end: pageToken(room, backwards ? last : last + 1) } : {})
  });
}

export async function roomClient(home, server, auth, method, parts, data, params = new URLSearchParams()) {
  const [room, action, kind, key] = parts,
    user = auth.user_id;
  await openParty(home, server, user);
  const g = load(home, server, room);
  if (!g.events.size) missing();
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
    return messagePage(home, room, eventId(g.get('m.room.member', user)), params);
  if (method === 'GET' && action === 'state') {
    if (kind) {
      const e = g.get(kind, key ?? '');
      return e ? ok(e.content) : missing();
    }
    return ok([...g.state.values()].map((id) => clientEvent(g.events.get(id), id)));
  }
  if (method === 'GET' && action === 'members') return ok({ chunk: g.members().map((e) => clientEvent(e)) });
  let type,
    content = data,
    stateKey,
    tx;
  if (method === 'POST' && ['join', 'invite', 'leave'].includes(action)) {
    stateKey = action === 'invite' ? data.user_id : user;
    await openParty(home, server, stateKey);
    type = 'm.room.member';
    content = { membership: action };
  } else if (method === 'PUT' && action === 'send' && kind && key) {
    type = kind;
    tx = JSON.stringify([user, auth.device_id, room, kind, key]);
    const prior = home.sql.exec('SELECT eid FROM room_tx WHERE id=?', tx).toArray()[0];
    if (prior) return ok({ event_id: prior.eid });
  } else if (
    method === 'PUT' &&
    action === 'state' &&
    kind &&
    !['m.room.member', 'm.room.create', 'm.room.server_acl'].includes(kind)
  ) {
    type = kind;
    stateKey = key ?? '';
  } else missing();
  if (!isObject(content)) invalid('Expected event content');
  const event = await g.local(home.identity, user, type, content, stateKey),
    id = eventId(event);
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
  if (!g.events.size) missing();
  await checkParties(home, server, g);
  if (g.get('m.room.create')?.content['m.federate'] === false) denied('Federation disabled');
  if (action === 'make_join' && method === 'GET') {
    if (domain(value) !== peer) denied('Origin must own user');
    if (!params.getAll('ver').includes('10'))
      fail(400, 'M_INCOMPATIBLE_ROOM_VERSION', 'Room version 10 required');
    const membership = g.get('m.room.member', value)?.content.membership;
    if (
      membership === 'ban' ||
      (!['invite', 'join'].includes(membership) && g.get('m.room.join_rules')?.content.join_rule !== 'public')
    )
      denied('An invitation is required');
    return ok({
      room_version: '10',
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
      eventId(body) !== value
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

export async function receiveEvent(home, server, peer, pdu) {
  if (domain(pdu.sender) !== peer) denied('Unsupported relayed origin');
  const g = load(home, server, pdu.room_id);
  if (!g.events.size || !g.members('join').some((e) => domain(e.state_key) === server)) missing();
  if (g.events.has(eventId(pdu))) return;
  await checkParties(home, server, g);
  if (g.get('m.room.member', pdu.sender)?.content.membership !== 'join')
    denied('Sender is not currently joined');
  if (pdu.type === 'm.room.server_acl') denied('Server ACLs are unavailable on the spike');
  if (pdu.type === 'm.room.member') await openParty(home, server, pdu.state_key);
  // A stale branch can have valid historical authorization and still fail current
  // authorization. Check both snapshots before making its event visible to clients.
  g.checkCurrent(pdu);
  g.add(pdu);
  commit(home, server, g, [pdu]);
}
export async function roomSync(home, server, user, cursor, initial) {
  const high = home.sql.exec('SELECT COALESCE(MAX(seq),0) AS n FROM room_events').one().n;
  const rooms = { join: {}, invite: {}, leave: {} },
    changed = new Set();
  const memberships = home.sql.exec(
    'SELECT s.room,e.pdu FROM room_state s JOIN room_events e ON e.eid=s.eid WHERE kind=? AND skey=?',
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
      .exec('SELECT s.eid,e.pdu FROM room_state s JOIN room_events e ON e.eid=s.eid WHERE s.room=?', row.room)
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
            .map(({ sender, type, state_key, content }) => ({ sender, type, state_key, content }))
        }
      };
    } else if (membership === 'join') {
      const sinceJoin = home.sql.exec('SELECT seq FROM room_events WHERE eid=?', own.event_id).one().seq;
      const joinedNow = initial || sinceJoin > cursor;
      const rows = home.sql
        .exec(
          'SELECT seq,pdu,eid FROM room_events WHERE room=? AND seq>=? ORDER BY seq',
          row.room,
          Math.max(sinceJoin, cursor + 1)
        )
        .toArray();
      const events = rows.map((r) => clientEvent(JSON.parse(r.pdu), r.eid));
      const timelineIds = new Set(rows.map((row) => row.eid));
      const state = joinedNow ? stateEvents.filter((e) => !timelineIds.has(e.event_id)) : [];
      rooms.join[row.room] = {
        state: { events: state },
        timeline: {
          events,
          limited: false,
          ...(rows.length ? { prev_batch: pageToken(row.room, rows[0].seq) } : {})
        },
        ephemeral: { events: [] },
        account_data: { events: [] }
      };
      for (const m of joinedNow
        ? members.filter((m) => m.content.membership === 'join')
        : events.filter((e) => e.type === 'm.room.member'))
        changed.add(m.state_key);
    } else if (!initial)
      rooms.leave[row.room] = { timeline: { events: [own], limited: false }, state: { events: [] } };
  }
  return { rooms, high, changed: [...changed] };
}
