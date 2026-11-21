import {test} from 'node:test';
import assert from 'node:assert/strict';
import {canonical, createIdentity, signServerKeys} from './src/identity.js';

test('independent Ed25519 verification binds server name, expiry and key to this tenant', async () => {
  const identity = await createIdentity();
  const {signatures, ...keys} = await signServerKeys('company.example', identity, 1000);
  const signature = Buffer.from(signatures['company.example']['ed25519:1'], 'base64');
  assert.equal(keys.valid_until_ts, 86401000);
  const key = await crypto.subtle.importKey('raw', Buffer.from(keys.verify_keys['ed25519:1'].key, 'base64'), 'Ed25519', false, ['verify']);
  const verify = doc => crypto.subtle.verify('Ed25519', key, signature, new TextEncoder().encode(canonical(doc)));
  assert.ok(await verify(keys));
  assert.equal(await verify({...keys, server_name: 'other.example'}), false);
  assert.notEqual((await createIdentity()).publicKey, identity.publicKey);
});

test('restores a Synapse seed and key ID only to its designated tenant, preserving prior identities', async () => {
  const {initializeIdentity, signingKeyId} = await import('./src/identity.js');
  const original = await createIdentity();
  const secret = 'ed25519 test_version ' + Buffer.from(original.privateKey.d,'base64url').toString('base64').replace(/=+$/,'');
  const store = () => {
    const data = new Map();
    return {get: key => data.get(key), put: (key,value) => data.set(key,value)};
  };
  const storage = store();
  await assert.rejects(initializeIdentity(storage,true,undefined), /missing/);
  const restored = await initializeIdentity(storage,true,secret);
  assert.equal(restored.publicKey, original.publicKey);
  assert.equal(signingKeyId(restored), 'ed25519:test_version');
  const {signatures,...doc} = await signServerKeys('old.example',restored);
  const id = signingKeyId(restored);
  const pub = await crypto.subtle.importKey('raw',Buffer.from(original.publicKey,'base64'),'Ed25519',false,['verify']);
  assert.ok(await crypto.subtle.verify('Ed25519',pub,Buffer.from(signatures['old.example'][id],'base64'),new TextEncoder().encode(canonical(doc))));
  assert.deepEqual(await initializeIdentity(storage,true,undefined),restored);
  await assert.rejects(initializeIdentity(storage,true,secret.replace('test_version','other')), /conflicts/);
  const other = store();
  assert.notEqual((await initializeIdentity(other,false,secret)).publicKey,original.publicKey);
  await assert.rejects(initializeIdentity(other,true,secret), /conflicts/);
});
