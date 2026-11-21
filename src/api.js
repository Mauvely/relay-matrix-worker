// SPDX-License-Identifier: AGPL-3.0-or-later
import {
  create,
  roomClient,
  fedRoom,
  openParty,
  receiveEvent,
  roomVersion,
  ok,
  fail,
  missing,
  isObject
} from './rooms.js';
import { remote } from './federation.js';
import { limited } from './media.js';
import { clearGap } from './gaps.js';
import { receiveInvite } from './invites.js';
import { backup } from './backup.js';
import { clientKeys, localKeys } from './keys.js';
import { eventId, domain } from './graph.js';

export async function clientApi(home, server, auth, method, parts, params, body) {
  const user = auth.user_id;
  if (parts[0] === 'room_keys') return backup(home, user, method, parts.slice(1), params, body);
  if (parts[0] === 'pushrules' && method === 'GET')
    return ok({
      global: {
        override: [],
        content: [],
        room: [],
        sender: [],
        underride: []
      }
    });
  if (parts[0] === 'thirdparty' && parts[1] === 'protocols' && method === 'GET') return ok({});
  if (parts[0] === 'voip' && parts[1] === 'turnServer' && method === 'GET') {
    if (!home.env.TURN_PROVIDER) return ok({uris:[]});
    await openParty(home,server,user);
    const cacheKey = 'turn/' + user;
    const cached = await home.ctx.storage.get(cacheKey);
    const now = Math.floor(Date.now()/1000);
    if (cached && cached.expires > now+300) return ok({...cached.answer, ttl:cached.expires-now});
    try {
      const answer = await home.env.TURN_PROVIDER.credentials();
      if (!answer.uris?.length || !answer.username || !answer.password || !(answer.ttl > 0))
        throw Error('No relay credentials');
      await home.ctx.storage.put(cacheKey,{answer, expires:now+answer.ttl});
      return ok(answer);
    } catch {
      fail(503,'M_UNAVAILABLE','Call relay temporarily unavailable');
    }
  }
  if (parts[0] === 'keys' && method === 'POST') {
    if (parts[1] === 'upload' && !home.sql.exec('SELECT 1 FROM devices WHERE user=? AND device=?', user, auth.device_id).toArray().length)
      fail(401, 'M_UNKNOWN_TOKEN', 'Device signed out');
    return clientKeys(home, server, auth, parts.slice(1).join('/'), body);
  }
  if (parts[0] === 'devices' && method === 'GET') {
    const rows = home.sql.exec('SELECT device AS device_id FROM devices WHERE user=?', user).toArray();
    return ok(parts[1] ? (rows.find((r) => r.device_id === parts[1]) ?? missing()) : { devices: rows });
  }
  if (method === 'POST' && parts[0] === 'createRoom') return create(home, server, user, body);
  if (method === 'POST' && parts[0] === 'join')
    return roomClient(home, server, auth, method, [parts[1], 'join'], body);
  if (parts[0] === 'rooms') return roomClient(home, server, auth, method, parts.slice(1), body, params);
  if (parts[0] === 'joined_rooms' && method === 'GET') {
    const rows = home.sql
      .exec(
        "SELECT s.room FROM room_state s JOIN room_known_events e ON e.eid=s.eid WHERE kind='m.room.member' AND skey=? AND json_extract(e.pdu,'$.content.membership')='join'",
        user
      )
      .toArray();
    return ok({ joined_rooms: rows.map((r) => r.room) });
  }
  if (parts[0] === 'capabilities' && method === 'GET')
    return ok({
      capabilities: {
        'm.room_versions': { default: '10', available: { 10: 'stable', 11: 'stable' } },
        'm.change_password': { enabled: false }
      }
    });
  if (parts[0] === 'profile' && parts[1] && method === 'GET' && domain(parts[1]) !== server) {
    await openParty(home, server, user);
    await openParty(home, server, parts[1]);
    const params = new URLSearchParams({ user_id: parts[1] });
    if (parts[2]) params.set('field', parts[2]);
    const response = await remote(
      home,
      server,
      domain(parts[1]),
      'GET',
      '/_matrix/federation/v1/query/profile?' + params
    );
    const profile = JSON.parse(new TextDecoder().decode(await limited(response.body, 65536)));
    return ok(
      Object.fromEntries(
        Object.entries(profile).filter(
          ([key, value]) =>
            ['displayname', 'avatar_url'].includes(key) &&
            typeof value === 'string' &&
            (!parts[2] || key === parts[2])
        )
      )
    );
  }
  if (parts[0] === 'profile' && method === 'GET' && domain(parts[1]) === server) {
    const profile = await home.profile(parts[1], server);
    if (!profile) missing();
    return ok(
      parts[2] ? (Object.hasOwn(profile, parts[2]) ? { [parts[2]]: profile[parts[2]] } : {}) : profile
    );
  }
  if (parts[0] === 'user' && parts[1] === user) {
    if (parts[2] === 'filter') {
      const prefix = 'filter/' + user + '/';
      if (method === 'POST') {
        const id = crypto.randomUUID();
        await home.ctx.storage.put(prefix + id, body);
        return ok({ filter_id: id });
      }
      const filter = await home.ctx.storage.get(prefix + parts[3]);
      if (filter && method === 'GET') return ok(filter);
    }
    if (parts[2] === 'account_data' && parts[3]) {
      if (method === 'PUT') {
        home.sql.exec(
          'INSERT OR REPLACE INTO user_data(user,kind,content) VALUES(?,?,?)',
          user,
          parts[3],
          JSON.stringify(body)
        );
        return ok();
      }
      const row = home.sql
        .exec('SELECT content FROM user_data WHERE user=? AND kind=?', user, parts[3])
        .toArray()[0];
      if (row && method === 'GET') return ok(JSON.parse(row.content));
    }
  }
  missing();
}
export async function federationApi(home, server, peer, method, parts, params, body, gaps = new Map()) {
  if (
    parts[0] === 'user' &&
    parts[1] === 'keys' &&
    method === 'POST' &&
    ['query', 'claim'].includes(parts[2])
  ) {
    const kind = parts[2],
      query = body[kind === 'claim' ? 'one_time_keys' : 'device_keys'];
    if (!isObject(query)) fail(400, 'M_BAD_JSON', 'Expected key query');
    for (const user of Object.keys(query)) await openParty(home, server, user);
    return ok(localKeys(home, server, kind, query));
  }
  if (parts[0] === 'user' && parts[1] === 'devices' && method === 'GET') {
    const user = parts[2];
    await openParty(home, server, user);
    const q = localKeys(home, server, 'query', { [user]: [] });
    return ok({
      user_id: user,
      stream_id: home.sql.exec('SELECT COALESCE(MAX(seq),0) AS n FROM key_changes WHERE user=?', user).one()
        .n,
      devices: Object.entries(q.device_keys[user]).map(([device_id, keys]) => ({
        device_id,
        keys
      })),
      master_key: q.master_keys[user],
      self_signing_key: q.self_signing_keys[user]
    });
  }
  if (parts[0] === 'invite' && method === 'PUT')
    return receiveInvite(home, server, peer, parts[1], parts[2], body);
  if (parts[0] === 'event' && method === 'GET') {
    const row = home.sql.exec('SELECT room FROM room_known_events WHERE eid=? LIMIT 1',parts[1]).toArray()[0];
    if (!row) missing();
    return fedRoom(home,server,peer,method,['event',row.room,parts[1]],params);
  }
  if (['make_join','send_join','get_missing_events','backfill','state_ids','state','event_auth'].includes(parts[0]))
    return fedRoom(home, server, peer, method, parts, params, body);
  if (parts[0] === 'send' && method === 'PUT') {
    if (
      body.origin !== peer ||
      !Array.isArray(body.pdus) ||
      body.pdus.length > 50 ||
      (body.edus?.length ?? 0) > 100
    )
      fail(400, 'M_BAD_JSON', 'Invalid federation transaction');
    const cache = JSON.stringify(['txn', peer, parts[1]]);
    const prior = home.sql.exec('SELECT response FROM received WHERE id=?', cache).toArray()[0];
    if (prior) return ok(JSON.parse(prior.response));
    // The remote host may start sending events immediately after our send_join.
    // Have it retry the transaction as soon as the signed history is committed.
    for (const p of body.pdus) {
      if (
        p && typeof p.room_id === 'string' &&
        home.sql
          .exec('SELECT 1 FROM remote_invites WHERE room=? AND joining IS NOT NULL LIMIT 1', p.room_id)
          .toArray().length
      )
        return {
          status: 503,
          body: { errcode: 'M_UNAVAILABLE', error: 'Room join in progress' }
        };
    }
    const pdus = {};
    for (const p of body.pdus) {
      let id;
      try {
        id = eventId(p,roomVersion(home.sql,p.room_id));
        const recovered = gaps.get(p);
        // Other PDUs in this transaction may already have filled the gap.
        await receiveEvent(home, server, peer, p, Array.isArray(recovered) ? recovered : []);
        if (Array.isArray(recovered) && recovered.length) clearGap(home.sql,p.room_id,peer,id);
        pdus[id] = {};
      } catch (e) {
        if (e.status === 503)
          return {status:503,body:{errcode:'M_UNAVAILABLE',error:'Predecessor recovery pending'}};
        if (id) {
          if (gaps.get(p)?.length) clearGap(home.sql,p.room_id,peer,id);
          pdus[id] = { error: e.message ?? String(e) };
        }
      }
    }
    for (const { edu_type, content } of body.edus ?? []) {
      if (
        edu_type === 'm.direct_to_device' &&
        domain(content.sender) === peer &&
        isObject(content.messages) &&
        typeof content.message_id === 'string'
      ) {
        for (const [user, targets] of Object.entries(content.messages)) {
          if (domain(user) !== server || !isObject(targets)) continue;
          try {
            await openParty(home, server, user);
          } catch {
            continue;
          }
          for (const [device, payload] of Object.entries(targets))
            home.enqueue(
              JSON.stringify([peer, content.sender, content.message_id]),
              user,
              device,
              content.sender,
              content.type,
              payload
            );
        }
      }
      if (
        ['m.device_list_update', 'm.signing_key_update'].includes(edu_type) &&
        domain(content.user_id) === peer
      )
        home.sql.exec('INSERT INTO key_changes(user) VALUES(?)', content.user_id);
    }
    const result = { pdus };
    home.sql.exec('INSERT INTO received VALUES(?,?)', cache, JSON.stringify(result));
    return ok(result);
  }
  missing();
}
