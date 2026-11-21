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
  const peers = {
    [origin]: {
      [key]: base64(await crypto.subtle.exportKey('raw', publicKey))
    }
  };
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
    await authenticatedOrigin(request, destination, peers, {
      ...content,
      origin: destination
    }),
    false
  );
});

test('HTTPS delegation authenticates a fresh key document for the exact canonical name', async () => {
  const { discoverPeer } = await import('./src/discovery.js');
  const { createIdentity, signServerKeys } = await import('./src/identity.js');
  const name = 'independent.example',
    now = Date.now();
  const document = await signServerKeys(name, await createIdentity(), now);
  const seen = [];
  let answer = document;
  const read = async (url, options) => {
    seen.push(url);
    assert.equal(options.redirect, 'manual');
    return Response.json(url.includes('/.well-known/') ? { 'm.server': 'edge.example:443' } : answer);
  };
  const peer = await discoverPeer(name, read, now);
  assert.deepEqual(seen, [
    'https://independent.example/.well-known/matrix/server',
    'https://edge.example/_matrix/key/v2/server'
  ]);
  assert.equal(peer.keys['ed25519:1'], document.verify_keys['ed25519:1'].key);
  assert.ok(peer.expires <= document.valid_until_ts);
  for (answer of [
    { ...document, server_name: 'other.example' },
    { ...document, valid_until_ts: now },
    { ...document, signatures: {} }
  ])
    await assert.rejects(discoverPeer(name, read, now));
});

test('discovery preserves signatures from before rotation and limits current federation credentials', async () => {
  const { discoverPeer, mergePeerKeys, keysForEvent } = await import('./src/discovery.js');
  const { createIdentity, signServerKeys } = await import('./src/identity.js');
  const { sign } = await import('./src/federation.js');
  const name = 'rotating.example:443', now = Date.now();
  const first = await createIdentity(), second = { ...await createIdentity(), keyId: 'ed25519:second' };
  const oldId = 'ed25519:1', newId = second.keyId;
  const discover = (doc, t) => discoverPeer(name, async () => Response.json(doc), t);
  const prior = await discover(await signServerKeys(name, first, now), now);
  const next = await signServerKeys(name, second, now + 1000);
  const { signatures, ...body } = next;
  body.old_verify_keys = { [oldId]: { key: first.publicKey, expired_ts: now + 500 } };
  const doc = { ...body, signatures: { [name]: { [newId]: await sign(second, canonical(body)) } } };
  const rotated = mergePeerKeys(prior, await discover(doc, now + 1000));
  assert.deepEqual(Object.keys(rotated.keys), [newId]);
  assert.deepEqual(rotated.eventKeys[oldId], { key: first.publicKey, until: now + 500 });
  const omitted = mergePeerKeys(prior, await discover(next, now + 1000));
  assert.equal(omitted.eventKeys[oldId].until, now + 1000);
  const later = mergePeerKeys(rotated, await discover(next, now + 1001));
  assert.equal(later.eventKeys[oldId].until, now + 500);
  const reused = await discover(await signServerKeys(name, { ...second, keyId: oldId }, now + 2000), now + 2000);
  assert.throws(() => mergePeerKeys(rotated, reused), /reused/);
  const requested = [];
  const home = { env: { DISCOVER_PEERS:true }, discoveredKeys:{[name]:prior.eventKeys},
    async resolvePeer(author,id) { requested.push([author,id]); return rotated; } };
  const signedBy = id => ({ signatures:{[name]:{[id]:'signature'}},origin_server_ts:now });
  await keysForEvent(home,name,signedBy(oldId));
  assert.deepEqual(requested,[]);
  assert.equal((await keysForEvent(home,name,signedBy(newId)))[newId].key,second.publicKey);
  assert.deepEqual(requested,[[name,newId]]);
});
