// SPDX-License-Identifier: AGPL-3.0-or-later
import test from 'node:test';
import assert from 'node:assert/strict';
import { canonical, base64 } from './src/identity.js';
import { authenticateQuery } from './src/federation.js';

test('federation authenticates the full request URI and intended logical server', async () => {
  const { privateKey, publicKey } = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);
  const origin = 'remote.example',
    destination = 'tenant.example',
    key = 'ed25519:test';
  const peers = { [origin]: { [key]: base64(await crypto.subtle.exportKey('raw', publicKey)) } };
  const uri = '/_matrix/federation/v1/query/profile?user_id=%40test%3Atenant.example';
  const signature = await crypto.subtle.sign(
    'Ed25519',
    privateKey,
    new TextEncoder().encode(canonical({ origin, destination, method: 'GET', uri }))
  );
  const headers = {
    Authorization: `X-Matrix origin="${origin}",key="${key}",sig="${base64(signature)}",destination="${destination}"`
  };
  const request = new Request('https://endpoint.example' + uri, { headers });
  assert.ok(await authenticateQuery(request, destination, peers));
  assert.equal(await authenticateQuery(request, 'different.example', peers), false);
  assert.equal(
    await authenticateQuery(new Request(request.url + '&field=displayname', { headers }), destination, peers),
    false
  );
});

test('signed federation writes bind the body, destination and transaction path', async () => {
  const { createIdentity } = await import('./src/identity.js');
  const { sign, authenticatedOrigin } = await import('./src/federation.js');
  const identity = await createIdentity(),
    origin = 'synapse.test',
    destination = 'worker.test',
    uri = '/_matrix/federation/v1/send/10',
    content = { origin, pdus: [], edus: [] };
  const sig = await sign(identity, canonical({ method: 'PUT', uri, origin, destination, content }));
  const request = new Request('https://matrix.example' + uri, {
    method: 'PUT',
    headers: {
      Authorization: `X-Matrix origin="${origin}",destination="${destination}",key="ed25519:1",sig="${sig}"`
    }
  });
  const peers = { [origin]: { 'ed25519:1': identity.publicKey } };
  assert.equal(await authenticatedOrigin(request, destination, peers, content), origin);
  assert.equal(
    await authenticatedOrigin(request, destination, peers, { ...content, origin: destination }),
    false
  );
});
