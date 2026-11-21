// SPDX-License-Identifier: AGPL-3.0-or-later
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

  async keys(serverName) {
    return signServerKeys(serverName, this.identity);
  }
}

function json(body, status = 200) {
  return Response.json(body, { status, headers: { 'Access-Control-Allow-Origin': '*' } });
}

export default {
  async fetch(request, env) {
    const { hostname, pathname } = new URL(request.url);
    if (!Object.hasOwn(env.DOMAINS, hostname)) return json({errcode: 'M_NOT_FOUND', error: 'Unknown endpoint'}, 404);
    const server = env.DOMAINS[hostname];
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
