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
