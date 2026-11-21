// SPDX-License-Identifier: AGPL-3.0-or-later
import { deliver, syncDevices } from './device.js';
import { authenticateQuery } from './federation.js';
import { delegated, login, provision, session } from './accounts.js';
import { replayProbe, verifyFixtureHistory } from './probe.js';
import { DurableObject } from 'cloudflare:workers';
import { createIdentity, signServerKeys } from './identity.js';

export class Homeserver extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.waiters = new Map();
    this.sql = ctx.storage.sql;
    this.sql.exec(
      'CREATE TABLE IF NOT EXISTS devices (user TEXT, device TEXT, PRIMARY KEY(user,device)); CREATE TABLE IF NOT EXISTS delivery (sequence INTEGER PRIMARY KEY AUTOINCREMENT, txn TEXT, user TEXT, device TEXT, sender TEXT, kind TEXT, content TEXT, UNIQUE(txn,user,device)); CREATE INDEX IF NOT EXISTS delivery_device ON delivery(user,device,sequence)'
    );
    ctx.blockConcurrencyWhile(async () => {
      this.identity = await ctx.storage.get('ed25519:1');
      if (!this.identity) {
        this.identity = await createIdentity();
        await ctx.storage.put('ed25519:1', this.identity);
      }
    });
  }

  async provision(server, localpart, organisationId) {
    return provision(this.ctx.storage, server, localpart, organisationId);
  }

  async login(server, data) {
    const result = await login(this.ctx.storage, server, data);
    if (result.status === 200)
      this.sql.exec('INSERT OR IGNORE INTO devices VALUES (?,?)', result.body.user_id, result.body.device_id);
    return result;
  }

  async session(authorization, logout) {
    return session(this.ctx.storage, authorization, logout);
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
      return { status: 409, body: { stored: prior.length, error: 'Checkpoint changed' } };
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
      return { status: 400, body: { error: 'Signed history could not be authorised' } };
    }
    this.ctx.storage.transactionSync(() => {
      for (const [i, event] of additions.events.entries())
        this.sql.exec('INSERT INTO fixture_history VALUES(?,?)', prior.length + i, JSON.stringify(event));
    });
    return { status: 200, body: { stored: history.length, database_bytes: this.sql.databaseSize } };
  }

  async profile(userId, server) {
    const local = /^@([^:]+):(.+)$/.exec(userId);
    if (!local || local[2] !== server) return null;
    const account = await this.ctx.storage.get('account/' + local[1]);
    return account?.userId === userId ? { displayname: local[1] } : null;
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
      'Access-Control-Allow-Headers': 'Authorization, Content-Type',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, OPTIONS',
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
      if (!(await authenticateQuery(request, server, env.PEER_KEYS ?? {})))
        return json(
          { errcode: 'M_UNAUTHORIZED', error: 'Federation signature or destination rejected' },
          401
        );
      const params = new URL(request.url).searchParams;
      const profile = await homeserver.profile(params.get('user_id'), server);
      if (!profile) return json({ errcode: 'M_NOT_FOUND', error: 'Unknown user' }, 404);
      return json(!params.has('field') || params.get('field') === 'displayname' ? profile : {});
    }
    const client = /^\/_matrix\/client\/(?:v3|r0)\/(login|account\/whoami|logout)$/.exec(pathname)?.[1];
    if (client === 'login' && request.method === 'GET')
      return json({ flows: [{ type: 'm.login.password' }] });
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
            { errcode: 'M_FORBIDDEN', error: 'Domain delegation is unverified: ' + error.message },
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
      if (pathname === '/_matrix/key/v2/server' || pathname === '/_matrix/key/v2/server/ed25519:1') {
        const identity = env.HOMESERVERS.getByName(server);
        return json(await identity.keys(server));
      }
      if (pathname === '/_matrix/federation/v1/version')
        return json({ server: { name: 'Mauvely Relay spike', version: '0.1.0' } });
      // Discovery is available before a complete client-server version can be advertised.
      if (pathname === '/_matrix/client/versions') return json({ versions: [], unstable_features: {} });
    }
    return json({ errcode: 'M_UNRECOGNIZED', error: 'Unsupported endpoint' }, 404);
  }
};
