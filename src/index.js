// SPDX-License-Identifier: AGPL-3.0-or-later
import { delegated, login, provision, session } from './accounts.js';
import { replayProbe } from './probe.js';
import { DurableObject } from 'cloudflare:workers';
import { createIdentity, signServerKeys } from './identity.js';

export class Homeserver extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
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
    return login(this.ctx.storage, server, data);
  }

  async session(authorization, logout) {
    return session(this.ctx.storage, authorization, logout);
  }

  async keys(serverName) {
    return signServerKeys(serverName, this.identity);
  }
}

function json(body, status = 200) {
  return Response.json(body, { status, headers: { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Authorization, Content-Type', 'Access-Control-Allow-Methods': 'GET, POST, OPTIONS', 'Cache-Control': 'no-store' } });
}

export default {
  async fetch(request, env) {
    const { hostname, pathname } = new URL(request.url);
    if (!Object.hasOwn(env.DOMAINS, hostname)) return json({errcode: 'M_NOT_FOUND', error: 'Unknown endpoint'}, 404);
    const server = env.DOMAINS[hostname];
    if (request.method === 'OPTIONS') return json({});
    const homeserver = env.HOMESERVERS.getByName(server);
    const client = /^\/_matrix\/client\/(?:v3|r0)\/(login|account\/whoami|logout)$/.exec(pathname)?.[1];
    if (client === 'login' && request.method === 'GET') return json({flows: [{type: 'm.login.password'}]});
    if ((client === 'account/whoami' && request.method === 'GET') || (client === 'logout' && request.method === 'POST')) {
      const result = await homeserver.session(request.headers.get('Authorization'), client === 'logout');
      return json(result.body, result.status);
    }
    if (request.method === 'POST' && (client === 'login' || pathname === '/_relay/spike/provision')) {
      const provisioning = !client;
      if (provisioning && (!env.PROVISION_TOKEN || request.headers.get('Authorization') !== 'Bearer ' + env.PROVISION_TOKEN))
        return json({errcode: 'M_FORBIDDEN', error: 'Operator credentials required'}, 403);
      let body;
      try { body = await request.json(); } catch { return json({errcode: 'M_BAD_JSON', error: 'Invalid JSON'}, 400); }
      if (provisioning) {
        try {
          if (!await delegated(server, hostname)) throw Error('Unexpected Matrix endpoint');
        } catch (error) {
          return json({errcode: 'M_FORBIDDEN', error: 'Domain delegation is unverified: ' + error.message}, 403);
        }
      }
      const result = provisioning ? await homeserver.provision(server, body?.localpart, body?.organisation_id)
                                  : await homeserver.login(server, body);
      return json(result.body, result.status);
    }
    if (request.method === 'GET' && server === hostname) {
      if (pathname === '/.well-known/matrix/client') return json({'m.homeserver': {base_url: 'https://' + hostname}});
      if (pathname === '/.well-known/matrix/server') return json({'m.server': hostname + ':443'});
    }
    if (request.method === 'POST' && pathname === '/_relay/spike/replay' && env.PROBE_TOKEN
        && request.headers.get('Authorization') === 'Bearer ' + env.PROBE_TOKEN) {
      const result = replayProbe();
      return json(result, result.converged ? 200 : 500);
    }
    if (request.method === 'GET') {
      if (pathname === '/_matrix/key/v2/server' || pathname === '/_matrix/key/v2/server/ed25519:1') {
        const identity = env.HOMESERVERS.getByName(server);
        return json(await identity.keys(server));
      }
      if (pathname === '/_matrix/federation/v1/version') return json({server: {name: 'Mauvely Relay spike', version: '0.1.0'}});
      // Discovery is available before a complete client-server version can be advertised.
      if (pathname === '/_matrix/client/versions') return json({versions: [], unstable_features: {}});
    }
    return json({errcode: 'M_UNRECOGNIZED', error: 'Unsupported endpoint'}, 404);
  }
};
