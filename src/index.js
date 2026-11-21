// SPDX-License-Identifier: AGPL-3.0-or-later
import { logoutSession, reconcileSessions, sessionSchema } from './device-sessions.js';
import { deliver, syncDevices } from './device.js';
import { slidingPath, slidingSchema, slidingSync } from './sliding.js';
import { approveOAuth, oauthOperation, oauthRoute, oauthSchema, oauthSession } from './oauth.js';
import { exchange, rendezvousSchema, rendezvousRoute } from './rendezvous.js';
import module from '../room-v10/pkg/relay_room_v10_bg.wasm';
import { initSync } from '../room-v10/pkg/relay_room_v10.js';
import { inviteSchema, joinRemote, joinServers, lookupAlias, remoteInvites } from './invites.js';
import { backupSchema } from './backup.js';
import { announceJoinedDevices, keySchema, keyCounts, sharedUsers } from './keys.js';
import { clientApi, federationApi } from './api.js';
import { getRemote, limited, mediaSchema, mediaRoute } from './media.js';
import { openParty, queue, schema, roomSync, queueProfileUpdates, publishProfile } from './rooms.js';
import { authenticatedOrigin, remote, authenticateQuery } from './federation.js';
import { delegated, ensureManagedAccount, issueLoginCode, redeemLoginCode, ssoRedirect, login, provision, session } from './accounts.js';
import { replayProbe, verifyFixtureHistory } from './probe.js';
import { recoverPredecessors } from './gaps.js';
import { DurableObject, WorkerEntrypoint } from 'cloudflare:workers';
import { discoverPeer, mergePeerKeys } from './discovery.js';
import { initializeIdentity, signServerKeys } from './identity.js';

// Private RPC binding for the account owner. The public fetch handler has no equivalent route.
export class AccountDirectory extends WorkerEntrypoint {
  async grant(server, accountId, redirect) {
    const endpoint = this.env.ACCOUNT_ENDPOINT;
    if (endpoint && this.env.DOMAINS?.[endpoint] === server && typeof redirect === 'string' && redirect.startsWith('https://'+endpoint+'/_matrix/oauth/approve?'))
      return this.env.HOMESERVERS.getByName(server).approveOAuth(server,accountId,redirect);
    const target = ssoRedirect(redirect, this.env.SSO_CLIENTS);
    if (!endpoint || this.env.DOMAINS?.[endpoint] !== server || !target) throw Error('Matrix sign-in unavailable');
    target.searchParams.set('loginToken', await this.env.HOMESERVERS.getByName(server).loginCode(accountId));
    return target.href;
  }

  async ensure(server, accountId, localpart, organisationId, profile) {
    const endpoint = this.env.ACCOUNT_ENDPOINT;
    // The first-party apex is itself a Worker. Its binding serves the same discovery documents
    // without a same-zone public subrequest hitting the zone's bot challenge.
    const read = this.env.ACCOUNT_DISCOVERY ? (url, init) => this.env.ACCOUNT_DISCOVERY.fetch(url, init) : fetch;
    if (!endpoint || this.env.DOMAINS?.[endpoint] !== server || !(await delegated(server, endpoint, read)))
      throw Error('Account homeserver is not active');
    return this.env.HOMESERVERS.getByName(server).ensureAccount(server, accountId, localpart, organisationId, profile);
  }
}

export class Homeserver extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    initSync({ module });
    this.waiters = new Map();
    this.sql = ctx.storage.sql;
    this.sql.exec(
      'CREATE TABLE IF NOT EXISTS devices (user TEXT, device TEXT, PRIMARY KEY(user,device)); CREATE TABLE IF NOT EXISTS delivery (sequence INTEGER PRIMARY KEY AUTOINCREMENT, txn TEXT, user TEXT, device TEXT, sender TEXT, kind TEXT, content TEXT, UNIQUE(txn,user,device)); CREATE INDEX IF NOT EXISTS delivery_device ON delivery(user,device,sequence)'
    );
    this.sql.exec('CREATE TABLE IF NOT EXISTS federation_peers(name TEXT PRIMARY KEY, record TEXT NOT NULL)');
    this.discoveredKeys = Object.create(null);
    this.peerRequests = new Map();
    for (const row of this.sql.exec('SELECT name,record FROM federation_peers').toArray()) {
      const record = JSON.parse(row.record);
      this.discoveredKeys[row.name] = record.eventKeys ?? Object.fromEntries(
        Object.entries(record.keys).map(([id,key]) => [id,{key,until:record.expires}]));
    }
    this.sql.exec('CREATE TABLE IF NOT EXISTS sso_codes(hash TEXT PRIMARY KEY,user TEXT NOT NULL,expires INTEGER NOT NULL)');
    schema(this.sql);
    inviteSchema(this.sql);
    slidingSchema(this.sql);
    oauthSchema(this.sql);
    sessionSchema(this.sql);
    rendezvousSchema(this.sql);
    keySchema(this.sql);
    backupSchema(this.sql);
    mediaSchema(this.sql);
    ctx.blockConcurrencyWhile(async () => {
      reconcileSessions(this);
      await this.scheduleOutbound();
      const restoring = Boolean(env.SIGNING_KEY_SERVER) && ctx.id.equals(env.HOMESERVERS.idFromName(env.SIGNING_KEY_SERVER));
      this.identity = await initializeIdentity(ctx.storage, restoring, env.SYNAPSE_SIGNING_KEY);
    });
  }

  async resolvePeer(name, requestedKey) {
    if (Object.hasOwn(this.env.PEER_KEYS ?? {}, name) && Object.hasOwn(this.env.PEER_URLS ?? {}, name))
      return {
        keys: this.env.PEER_KEYS[name],
        endpoint: this.env.PEER_URLS[name]
      };
    if (!this.env.DISCOVER_PEERS) throw Error('Federation discovery is disabled');
    // A restarting peer often sends device and room transactions simultaneously.
    // They must all wait for the new key before authenticating their requests.
    if (this.peerRequests.has(name)) return this.peerRequests.get(name);
    const row = this.sql.exec('SELECT record FROM federation_peers WHERE name=?', name).toArray()[0];
    const cached = row && JSON.parse(row.record);
    const now = Date.now();
    const unknown = requestedKey && !Object.hasOwn(cached?.keys ?? {}, requestedKey);
    if (cached?.expires > now) {
      if (!unknown || (cached.lastKeyMiss ?? 0) > now - 60_000) return cached;
      cached.lastKeyMiss = now;
      this.sql.exec('UPDATE federation_peers SET record=? WHERE name=?', JSON.stringify(cached), name);
    }
    const refresh = discoverPeer(name).then((discovered) => {
      const fresh = mergePeerKeys(cached, discovered);
      if (cached?.lastKeyMiss) fresh.lastKeyMiss = cached.lastKeyMiss;
      this.sql.exec('INSERT OR REPLACE INTO federation_peers VALUES(?,?)', name, JSON.stringify(fresh));
      this.discoveredKeys[name] = fresh.eventKeys;
      return fresh;
    });
    this.peerRequests.set(name, refresh);
    try {
      return await refresh;
    } finally {
      this.peerRequests.delete(name);
    }
  }

  async api(server, auth, peer, method, parts, query, body) {
    const joining =
      !peer && method === 'POST' && (parts[0] === 'join' || (parts[0] === 'rooms' && parts[2] === 'join'));
    const lookup = !peer && method === 'GET' && parts.length === 3 && parts[0] === 'directory' && parts[1] === 'room';
    if (lookup || (joining && parts[1]?.startsWith('#'))) {
      try {
        const target = await lookupAlias(this, server, auth.user_id, parts[lookup ? 2 : 1]);
        if (lookup) return {status: 200, body: target};
        parts[1] = target.room_id;
        const routes = new URLSearchParams(query);
        for (const via of target.servers) routes.append('via', via);
        query = routes.toString();
      } catch (error) {
        return {status: error.status ?? 502, body: {errcode: error.errcode ?? 'M_UNKNOWN', error: error.message}};
      }
    }
    const invite =
      joining &&
      this.sql
        .exec(
          'SELECT peer,signed,joining,version FROM remote_invites WHERE user=? AND room=?',
          auth.user_id,
          parts[1]
        )
        .toArray()[0];
    const params = new URLSearchParams(query);
    const candidates = joining && !invite &&
      !this.sql.exec('SELECT 1 FROM room_tips WHERE room=? LIMIT 1', parts[1]).toArray().length
      ? joinServers(parts[1], params, server) : [];
    const gaps = new Map();
    if (peer && parts[0] === 'send' && method === 'PUT' && body.origin === peer &&
        Array.isArray(body.pdus) && body.pdus.length <= 50 && (body.edus?.length ?? 0) <= 100 &&
        !this.sql.exec('SELECT 1 FROM received WHERE id=?',JSON.stringify(['txn',peer,parts[1]])).toArray().length) {
      for (const pdu of body.pdus) {
        if (!pdu || typeof pdu.room_id !== 'string') continue;
        try {
          gaps.set(pdu,await recoverPredecessors(this,server,peer,pdu));
        } catch (error) {
          gaps.set(pdu,error);
        }
      }
    }
    const run = async () => {
      try {
        if (invite || candidates.length) return await joinRemote(this, server, auth.user_id, parts[1], invite, candidates);
        const args = [this, server, peer || auth, method, parts, params, body];
        return peer ? await federationApi(...args,gaps) : await clientApi(...args);
      } catch (e) {
        return {
          status: e.status ?? 400,
          body: {
            errcode: e.errcode ?? 'M_BAD_JSON',
            error: e.message ?? String(e)
          }
        };
      }
    };
    // Peers may call back for our signing key while answering a join or key query.
    const callsPeer =
      invite || candidates.length ||
      (!peer && parts[0] === 'profile') ||
      (!peer && parts[0] === 'keys' && ['claim', 'query'].includes(parts[1]));
    const result = callsPeer ? await run() : await this.ctx.blockConcurrencyWhile(run);
    if (result.status === 200 && (joining || (peer && parts[0] === 'send_join')))
      this.ctx.storage.transactionSync(() => announceJoinedDevices(this, server, parts[1]));
    await this.scheduleOutbound();
    return JSON.parse(JSON.stringify(result));
  }
  async scheduleOutbound() {
    if (
      this.sql.exec('SELECT 1 FROM outbound LIMIT 1').toArray().length &&
      (await this.ctx.storage.getAlarm()) === null
    )
      await this.ctx.storage.setAlarm(Date.now() + 20);
  }
  async mediaAccount(server, user) {
    if (!user.endsWith(':' + server)) throw Error('Wrong homeserver for upload');
    const account = await this.ctx.storage.get('account/' + user.slice(1, -server.length - 1));
    if (account?.userId !== user) throw Error('Unknown uploader');
    return account.accountId ?? null;
  }

  async mediaAllowed(server, user) {
    try {
      await openParty(this, server, user);
      return true;
    } catch {
      return false;
    }
  }
  async mediaRead(id) {
    if (id.startsWith('avatar-') && this.env.ACCOUNT_DISCOVERY) {
      const key = await this.ctx.storage.get('avatar-source/'+id.slice(7));
      if (!key) return null;
      const response = await this.env.ACCOUNT_DISCOVERY.fetch('https://' + this.env.DOMAINS[this.env.ACCOUNT_ENDPOINT] + '/api/account/avatar/'+key);
      const type = response.headers.get('content-type');
      if (!response.ok || !['image/png','image/jpeg','image/webp'].includes(type)) return null;
      return {body:await limited(response.body,2*1024*1024),type};
    }
    return this.sql.exec('SELECT body,type FROM media WHERE id=?', id).toArray()[0] ?? null;
  }
  mediaWrite(buffer, type) {
    const id = crypto.randomUUID();
    this.sql.exec('INSERT INTO media VALUES(?,?,?)', id, buffer, type);
    return id;
  }
  async mediaRemote(server, peer, id) {
    return getRemote(this, server, peer, id);
  }
  // Operator-only Durable Object binding. This never returns event bodies or credentials.
  federationDeliveryStatus(peer) {
    const backlog = this.sql.exec('SELECT COUNT(*) AS pending FROM outbound WHERE peer=?',peer).one().pending;
    const next = this.sql.exec(
      'SELECT o.path LIKE ? AS is_invite,COALESCE(r.attempt,0) AS retries,COALESCE(r.due,0) AS due FROM outbound o LEFT JOIN retry r ON r.id=o.id WHERE o.peer=? ORDER BY o.rowid LIMIT 1',
      '/_matrix/federation/v2/invite/%',peer).toArray()[0];
    const rejected = this.sql.exec('SELECT events FROM federation_delivery_failures WHERE peer=?',peer).toArray()[0]?.events ?? 0;
    return {backlog,next:next ? {...next} : null,rejected};
  }
  async alarm() {
    for (const {server,user,room} of this.sql.exec('SELECT * FROM profile_updates WHERE due<=? LIMIT 8', Date.now()).toArray()) {
      try {
        await this.ctx.blockConcurrencyWhile(async () => {
          await publishProfile(this,server,user,room);
          this.sql.exec('DELETE FROM profile_updates WHERE user=? AND room=?',user,room);
        });
      } catch {
        this.sql.exec('UPDATE profile_updates SET due=? WHERE user=? AND room=?',Date.now()+60000,user,room);
      }
    }
    const sql = this.sql;
    const ready = sql
      .exec(
        'SELECT o.*,COALESCE(r.attempt,0) AS attempt FROM outbound o LEFT JOIN retry r ON o.id=r.id WHERE COALESCE(r.due,0)<=? AND NOT EXISTS (SELECT 1 FROM outbound earlier WHERE earlier.peer=o.peer AND earlier.rowid<o.rowid) ORDER BY o.rowid LIMIT 8',
        Date.now()
      )
      .toArray();
    for (const r of ready) {
      try {
        const content = JSON.parse(r.content),
          people = new Set();
        for (const event of content.pdus ?? (content.event ? [content.event] : [])) {
          const members = sql.exec(
            "SELECT s.skey FROM room_state s JOIN room_known_events e ON e.eid=s.eid WHERE s.room=? AND kind='m.room.member' AND json_extract(e.pdu,'$.content.membership') IN ('join','invite')",
            event.room_id
          );
          for (const m of members) people.add(m.skey);
          people.add(event.sender);
        }
        for (const edu of content.edus ?? []) people.add(edu.content.sender ?? edu.content.user_id);
        for (const user of people) await openParty(this, r.server, user);
        const response = await remote(this, r.server, r.peer, 'PUT', r.path, content);
        const body = await response.json();
        // A successful /send response completes this transaction. The recipient
        // caches its per-event decisions under the transaction ID. Resending
        // that ID cannot change them and would block every later room on that peer.
        const rejected = Object.values(body.pdus ?? {}).filter(p => p?.error).length;
        this.ctx.storage.transactionSync(() => {
          if (rejected) sql.exec(
            'INSERT INTO federation_delivery_failures VALUES(?,?,?) ON CONFLICT(peer) DO UPDATE SET events=events+excluded.events,last_at=excluded.last_at',
            r.peer,rejected,Date.now());
          sql.exec('DELETE FROM outbound WHERE id=?', r.id);
          sql.exec('DELETE FROM retry WHERE id=?', r.id);
        });
        if (rejected) console.warn('Federation delivery completed with rejected events',r.peer,rejected);
      } catch (e) {
        const delay = Math.min(300000, 2000 * 2 ** Math.min(8, r.attempt));
        sql.exec('INSERT OR REPLACE INTO retry VALUES(?,?,?)', r.id, r.attempt + 1, Date.now() + delay);
        console.warn('Federation delivery pending', r.peer, e.message);
      }
    }
    const next = sql
      .exec(
        'SELECT MIN(COALESCE(r.due,0)) AS due FROM outbound o LEFT JOIN retry r ON o.id=r.id WHERE NOT EXISTS (SELECT 1 FROM outbound earlier WHERE earlier.peer=o.peer AND earlier.rowid<o.rowid)'
      )
      .one().due;
    const profiles = sql.exec('SELECT MIN(due) AS due FROM profile_updates').one().due;
    const due = [next, profiles].filter((value) => value !== null);
    if (due.length) await this.ctx.storage.setAlarm(Math.max(Date.now()+10,Math.min(...due)));
  }
  rendezvous(method,id,data,tag) { return exchange(this.sql,method,id,data,tag); }
  approveOAuth(server,accountId,target) {
    return approveOAuth(this,server,accountId,target);
  }
  async oauth(server,op,input) {
    try {
      const result = await oauthOperation(this,server,op,input);
      if (op === 'revoke' || op === 'token') await this.scheduleOutbound();
      return result;
    }
    catch(e) { return {status:e.status ?? 400,body:{error:e.oauth ?? 'invalid_request'}}; }
  }
  async sliding(server,auth,body,query) {
    try {
      return {status:200,body:JSON.parse(JSON.stringify(await slidingSync(this,server,auth,body,query)))};
    } catch (e) {
      return {status:e.status ?? 503,body:{errcode:e.errcode ?? 'M_UNAVAILABLE',error:e.status ? e.message : 'Sync unavailable'}};
    }
  }

  async roomUpdates(server, user, cursor, initial) {
    return roomSync(this, server, user, cursor, initial);
  }
  cryptoUpdates(user, device, cursor) {
    const shared = sharedUsers(this, user);
    const high = this.sql.exec('SELECT COALESCE(MAX(seq),0) AS n FROM key_changes').one().n;
    const changed = this.sql
      .exec('SELECT DISTINCT user FROM key_changes WHERE seq>?', cursor)
      .toArray()
      .map((r) => r.user)
      .filter((u) => shared.has(u));
    return { ...keyCounts(this, user, device), high, changed };
  }
  inviteUpdates(user, cursor, initial) {
    return remoteInvites(this, user, cursor, initial);
  }
  userUpdates(user, cursor) {
    const rows = this.sql
      .exec('SELECT * FROM user_data WHERE user=? AND seq>? ORDER BY seq', user, cursor)
      .toArray();
    return {
      high: rows.at(-1)?.seq ?? cursor,
      events: rows.map((r) => ({
        type: r.kind,
        content: JSON.parse(r.content)
      }))
    };
  }

  async ensureAccount(server, accountId, localpart, organisationId, profile) {
    const id = await ensureManagedAccount(this.ctx.storage, server, accountId, localpart, organisationId, profile);
    if (profile) await this.profileChanged(server,id);
    return id;
  }
  async profileChanged(server,user) {
    queueProfileUpdates(this,server,user,await this.profile(user,server));
    if (this.sql.exec('SELECT 1 FROM profile_updates LIMIT 1').toArray().length)
      await this.ctx.storage.setAlarm(Date.now()+10);
  }

  async provision(server, localpart, organisationId) {
    return provision(this.ctx.storage, server, localpart, organisationId);
  }

  loginCode(accountId) {
    return issueLoginCode(this.ctx.storage, this.sql, accountId);
  }

  async login(server, data) {
    return data?.type === 'm.login.token'
      ? await redeemLoginCode(this.ctx.storage, this.sql, server, data)
      : await login(this.ctx.storage, server, data);
  }

  async session(authorization, logout) {
    if (logout) {
      const result = await logoutSession(this, authorization);
      if (result.status === 200) await this.scheduleOutbound();
      return result;
    }
    const legacy = await session(this.ctx.storage, authorization);
    return legacy.status === 200 ? legacy : (await oauthSession(this,authorization)) ?? legacy;
  }

  async party(userId, server) {
    const match = /^@([^:]+):(.+)$/.exec(userId);
    if (!match || match[2] !== server) return null;
    const account = await this.ctx.storage.get('account/' + match[1]);
    return account?.userId === userId ? { organisationId: account.organisationId } : null;
  }

  async completed(txKey) {
    return !!(await this.ctx.storage.get('complete/' + txKey));
  }
  async transactionBody(txKey, proposed) {
    return this.ctx.storage.transaction(async (t) => {
      const key = 'transaction/' + txKey,
        previous = await t.get(key);
      if (previous) return previous;
      await t.put(key, proposed);
      return proposed;
    });
  }
  async finishDevice(txKey, server, sender, kind, remotes) {
    const id = 'device/' + txKey;
    this.ctx.storage.transactionSync(() => {
      if (this.sql.exec('SELECT id FROM received WHERE id=?', id).toArray().length) return;
      for (const [peer, messages] of remotes)
        queue(
          this,
          server,
          peer,
          [],
          [
            {
              edu_type: 'm.direct_to_device',
              content: {
                sender,
                type: kind,
                message_id: crypto.randomUUID(),
                messages
              }
            }
          ]
        );
      this.sql.exec('INSERT INTO received VALUES(?,?)', id, '{}');
    });
    if (remotes.length) await this.ctx.storage.setAlarm(Date.now() + 25);
    await this.complete(txKey);
  }
  async complete(txKey) {
    await this.ctx.storage.transaction(async (t) => {
      await t.put('complete/' + txKey, true);
      await t.delete('transaction/' + txKey);
    });
  }
  enqueue(txKey, user, id, sender, kind, content) {
    const targets = this.sql
      .exec('SELECT device FROM devices WHERE user=? AND (device=? OR ?=?)', user, id, id, '*')
      .toArray();
    for (const { device } of targets) {
      this.sql.exec(
        'INSERT OR IGNORE INTO delivery(txn,user,device,sender,kind,content) VALUES(?,?,?,?,?,?)',
        txKey,
        user,
        device,
        sender,
        kind,
        JSON.stringify(content)
      );
      for (const wake of this.waiters.get(JSON.stringify([user, device])) ?? []) wake();
    }
  }
  acknowledge(user, device, cursor) {
    this.sql.exec(
      'UPDATE delivery SET content=NULL WHERE user=? AND device=? AND sequence<=? AND content IS NOT NULL',
      user,
      device,
      cursor
    );
  }
  pending(user, device, cursor) {
    return this.sql
      .exec(
        'SELECT sequence,sender,kind,content FROM delivery WHERE user=? AND device=? AND sequence>? AND content IS NOT NULL ORDER BY sequence LIMIT 100',
        user,
        device,
        cursor
      )
      .toArray();
  }
  async waitForDevice(user, device, cursor, timeout) {
    if (this.pending(user, device, cursor).length) return;
    const key = JSON.stringify([user, device]),
      waiters = this.waiters.get(key) ?? new Set();
    this.waiters.set(key, waiters);
    await new Promise((resolve) => {
      const done = () => {
        clearTimeout(timer);
        waiters.delete(done);
        if (!waiters.size) this.waiters.delete(key);
        resolve();
      };
      const timer = setTimeout(done, timeout);
      waiters.add(done);
    });
  }

  catchup(additions) {
    this.sql.exec(
      'CREATE TABLE IF NOT EXISTS fixture_history (position INTEGER PRIMARY KEY, pdu TEXT NOT NULL)'
    );
    const prior = this.sql
      .exec('SELECT pdu FROM fixture_history ORDER BY position')
      .toArray()
      .map((row) => JSON.parse(row.pdu));
    if (additions.start !== prior.length)
      return {
        status: 409,
        body: { stored: prior.length, error: 'Checkpoint changed' }
      };
    if (
      !Array.isArray(additions.events) ||
      !additions.events.length ||
      prior.length + additions.events.length > 512
    )
      return { status: 400, body: { error: 'Invalid fixture batch' } };
    const history = prior.concat(additions.events);
    try {
      verifyFixtureHistory(history);
    } catch {
      return {
        status: 400,
        body: { error: 'Signed history could not be authorised' }
      };
    }
    this.ctx.storage.transactionSync(() => {
      for (const [i, event] of additions.events.entries())
        this.sql.exec('INSERT INTO fixture_history VALUES(?,?)', prior.length + i, JSON.stringify(event));
    });
    return {
      status: 200,
      body: { stored: history.length, database_bytes: this.sql.databaseSize }
    };
  }

  async profile(userId, server) {
    const local = /^@([^:]+):(.+)$/.exec(userId);
    if (!local || local[2] !== server) return null;
    const account = await this.ctx.storage.get('account/' + local[1]);
    return account?.userId === userId ? account.profile ?? { displayname: local[1] } : null;
  }

  async keys(serverName) {
    return signServerKeys(serverName, this.identity);
  }
}

function json(body, status = 200) {
  return Response.json(body, {
    status,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Authorization, Content-Type, If-Match, If-None-Match',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Cache-Control': 'no-store'
    }
  });
}

export default {
  async fetch(request, env) {
    const { hostname, pathname } = new URL(request.url);
    if (!Object.hasOwn(env.DOMAINS, hostname))
      return json({ errcode: 'M_NOT_FOUND', error: 'Unknown endpoint' }, 404);
    const server = env.DOMAINS[hostname];
    if (request.method === 'OPTIONS') return json({});
    const homeserver = env.HOMESERVERS.getByName(server);
    if (
      request.method === 'POST' &&
      pathname === '/_relay/spike/catchup' &&
      env.PROBE_TOKEN &&
      request.headers.get('Authorization') === 'Bearer ' + env.PROBE_TOKEN
    ) {
      const len = Number(request.headers.get('Content-Length'));
      if (!Number.isInteger(len) || len < 1 || len > 1024 * 1024)
        return json({ error: 'Bounded fixture body required' }, 413);
      let data;
      try {
        data = await request.json();
      } catch {
        return json({ error: 'Invalid JSON' }, 400);
      }
      if (!data || typeof data !== 'object') return json({ error: 'Invalid batch' }, 400);
      const result = await homeserver.catchup(data);
      return json(result.body, result.status);
    }
    if (env.ACCOUNT_ENDPOINT === hostname) {
      const authResponse = await oauthRoute(request,homeserver,server);
      if (authResponse) return authResponse;
      const channel = await rendezvousRoute(request,homeserver);
      if (channel) return channel;
    }
    if (
      pathname === '/_matrix/client/v1/auth_metadata' ||
      pathname.startsWith('/_matrix/client/unstable/org.matrix.msc3814.v1/')
    )
      return json({ errcode: 'M_UNRECOGNIZED', error: 'Unsupported endpoint' }, 404);
    if (request.method === 'POST' && pathname === slidingPath) {
      const auth = await homeserver.session(request.headers.get('Authorization'),false);
      if (auth.status !== 200) return json(auth.body,auth.status);
      let body;
      try {
        body = JSON.parse(new TextDecoder().decode(await limited(request.body,65536)));
        if (!body || typeof body !== 'object' || Array.isArray(body)) throw Error();
      } catch { return json({errcode:'M_BAD_JSON',error:'Invalid sliding sync body'},400); }
      const result = await homeserver.sliding(server,auth.body,body,new URL(request.url).search);
      return json(result.body,result.status);
    }
    const media = await mediaRoute(request, env, server, homeserver, pathname, json);
    if (media) return media;
    const devicePath = /^\/_matrix\/client\/(?:v3|r0)\/sendToDevice\/([^/]+)\/([^/]+)$/.exec(pathname);
    if (devicePath && request.method === 'PUT') {
      let kind, txn;
      try {
        kind = decodeURIComponent(devicePath[1]);
        txn = decodeURIComponent(devicePath[2]);
      } catch {
        return json({ errcode: 'M_INVALID_PARAM', error: 'Invalid path' }, 400);
      }
      const result = await deliver(request, env, server, kind, txn);
      return json(result.body, result.status);
    }
    if (/^\/_matrix\/client\/(?:v3|r0)\/sync$/.test(pathname) && request.method === 'GET') {
      const result = await syncDevices(request, env, server);
      return json(result.body, result.status);
    }
    if (pathname === '/_matrix/federation/v1/query/profile' && request.method === 'GET') {
      if (
        !(await authenticateQuery(request, server, async (name, key) => (await homeserver.resolvePeer(name, key)).keys))
      )
        return json(
          {
            errcode: 'M_UNAUTHORIZED',
            error: 'Federation signature or destination rejected'
          },
          401
        );
      const params = new URL(request.url).searchParams;
      const profile = await homeserver.profile(params.get('user_id'), server);
      if (!profile) return json({ errcode: 'M_NOT_FOUND', error: 'Unknown user' }, 404);
      const field = params.get('field');
      return json(!field ? profile : Object.hasOwn(profile,field) ? {[field]:profile[field]} : {});
    }
    const client = /^\/_matrix\/client\/(?:v3|r0)\/(login|account\/whoami|logout)$/.exec(pathname)?.[1];
    const managed = env.ACCOUNT_ENDPOINT === hostname;
    if (client === 'login' && request.method === 'GET')
      return json({ flows: managed ? [{ type: 'm.login.sso' }, { type: 'm.login.token' }] : [{ type: 'm.login.password' }] });
    if (managed && /^\/_matrix\/client\/(?:v3|r0)\/login\/sso\/redirect$/.test(pathname) && request.method === 'GET') {
      const target = ssoRedirect(new URL(request.url).searchParams.get('redirectUrl'), env.SSO_CLIENTS);
      if (!target) return json({errcode:'M_INVALID_PARAM', error:'Unsupported client return address'}, 400);
      const approval = new URL('/matrix-signin', 'https://' + server);
      approval.searchParams.set('client', target.href);
      return Response.redirect(approval, 302);
    }
    if (
      (client === 'account/whoami' && request.method === 'GET') ||
      (client === 'logout' && request.method === 'POST')
    ) {
      const result = await homeserver.session(request.headers.get('Authorization'), client === 'logout');
      return json(result.body, result.status);
    }
    if (request.method === 'POST' && (client === 'login' || pathname === '/_relay/spike/provision')) {
      const provisioning = !client;
      if (
        provisioning &&
        (!env.PROVISION_TOKEN || request.headers.get('Authorization') !== 'Bearer ' + env.PROVISION_TOKEN)
      )
        return json({ errcode: 'M_FORBIDDEN', error: 'Operator credentials required' }, 403);
      let body;
      try {
        body = await request.json();
      } catch {
        return json({ errcode: 'M_BAD_JSON', error: 'Invalid JSON' }, 400);
      }
      if (provisioning) {
        try {
          if (!(await delegated(server, hostname))) throw Error('Unexpected Matrix endpoint');
        } catch (error) {
          return json(
            {
              errcode: 'M_FORBIDDEN',
              error: 'Domain delegation is unverified: ' + error.message
            },
            403
          );
        }
      }
      const result = provisioning
        ? await homeserver.provision(server, body?.localpart, body?.organisation_id)
        : await homeserver.login(server, body);
      return json(result.body, result.status);
    }
    if (request.method === 'GET' && server === hostname) {
      if (pathname === '/.well-known/matrix/client')
        return json({ 'm.homeserver': { base_url: 'https://' + hostname } });
      if (pathname === '/.well-known/matrix/server') return json({ 'm.server': hostname + ':443' });
    }
    if (
      request.method === 'POST' &&
      pathname === '/_relay/spike/replay' &&
      env.PROBE_TOKEN &&
      request.headers.get('Authorization') === 'Bearer ' + env.PROBE_TOKEN
    ) {
      const result = replayProbe();
      return json(result, result.converged ? 200 : 500);
    }
    if (request.method === 'GET') {
      if (/^\/_matrix\/key\/v2\/server(?:\/ed25519(?::|%3a)[a-z0-9_]+)?$/i.test(pathname)) {
        const identity = env.HOMESERVERS.getByName(server);
        return json(await identity.keys(server));
      }
      if (pathname === '/_matrix/federation/v1/version')
        return json({
          server: { name: 'Mauvely Relay spike', version: '0.1.0' }
        });
      // Clients use these API generations for login and authenticated media.
      if (pathname === '/_matrix/client/versions')
        return json({
          versions: ['v1.1', 'v1.11'],
          unstable_features: { 'com.mauvely.interop_spike': true, 'org.matrix.simplified_msc3575': true, ...(env.ACCOUNT_ENDPOINT === hostname ? {'org.matrix.msc4108':true} : {}) }
        });
    }
    const path = /^\/_matrix\/(client|federation)\/(?:v[123]|r0|unstable)\/(.+)$/.exec(pathname);
    if (path) {
      const federation = path[1] === 'federation';
      const auth = federation ? null : await homeserver.session(request.headers.get('Authorization'), false);
      if (auth && auth.status !== 200) return json(auth.body, auth.status);
      let parts, body;
      try {
        parts = path[2].split('/').map(decodeURIComponent);
        if (['POST', 'PUT'].includes(request.method)) {
          let bytes;
          try {
            bytes = await limited(request.body, 1024 * 1024);
          } catch {
            return json({ errcode: 'M_TOO_LARGE', error: 'Request exceeds spike limit' }, 413);
          }
          const raw = new TextDecoder().decode(bytes);
          body = JSON.parse(raw || '{}');
          if (!body || typeof body !== 'object' || Array.isArray(body)) throw Error();
        }
      } catch {
        return json({ errcode: 'M_BAD_JSON', error: 'Invalid request' }, 400);
      }
      const peer = federation
        ? await authenticatedOrigin(
            request,
            server,
            async (name, key) => (await homeserver.resolvePeer(name, key)).keys,
            body
          )
        : null;
      if (federation && !peer)
        return json({ errcode: 'M_UNAUTHORIZED', error: 'Invalid federation signature' }, 401);
      const result = await homeserver.api(
        server,
        auth?.body,
        peer,
        request.method,
        parts,
        new URL(request.url).search,
        body
      );
      return json(result.body, result.status);
    }
    return json({ errcode: 'M_UNRECOGNIZED', error: 'Unsupported endpoint' }, 404);
  }
};
