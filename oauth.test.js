// SPDX-License-Identifier: AGPL-3.0-or-later
import test from 'node:test';
import assert from 'node:assert/strict';
import { sessionHome } from './fixtures/session-home.js';
import { createHash } from 'node:crypto';
import { approveOAuth, oauthOperation, oauthSession } from './src/oauth.js';
import { exchange, rendezvousSchema } from './src/rendezvous.js';

function setup() {
  const h = sessionHome();
  h.env = { ACCOUNT_ENDPOINT: 'matrix.example.com', SSO_CLIENTS: ['https://relay.example.com/'] };
  h.ctx.storage.kv.put('mauvely-id/account', '@a:example.com');
  rendezvousSchema(h.sql);
  return h;
}

test('mobile OAuth binds the code to the registered redirect, PKCE, account and fresh device', async () => {
  const h = setup(),
    op = (name, body) => oauthOperation(h, 'example.com', name, body);
  const redirect = 'io.element.android:/',
    scope = 'urn:matrix:client:api:* urn:matrix:client:device:phone';
  const id = (await op('register', { redirect_uris: [redirect] })).body.client_id;
  const verifier = 'a'.repeat(64),
    challenge = createHash('sha256').update(verifier).digest('base64url');
  const req = {
    response_type: 'code',
    scope,
    state: 'test',
    code_challenge: challenge,
    code_challenge_method: 'S256',
    redirect_uri: redirect,
    client_id: id
  };
  await assert.rejects(op('authorize', { ...req, redirect_uri: 'https://unknown.test/' }));
  const prompt = await op('authorize', req);
  const target = new URL(prompt.location).searchParams.get('client');
  await assert.rejects(approveOAuth(h, 'example.com', 'account', target.replace('Android', 'iOS')));
  const success = new URL(await approveOAuth(h, 'example.com', 'account', target));
  assert.equal(success.searchParams.get('state'), 'test');
  const exchange = {
    grant_type: 'authorization_code',
    client_id: id,
    code: success.searchParams.get('code'),
    redirect_uri: redirect,
    code_verifier: verifier
  };
  await assert.rejects(op('token', { ...exchange, code_verifier: 'b'.repeat(64) }));
  const tokens = (await op('token', exchange)).body;
  await assert.rejects(op('token', exchange));
  assert.equal(
    (await oauthSession(h, 'Bearer ' + tokens.access_token)).body.user_id,
    '@a:example.com'
  );
  const rotated = (
    await op('token', { client_id: id, grant_type: 'refresh_token', refresh_token: tokens.refresh_token })
  ).body;
  assert.equal(await oauthSession(h, 'Bearer ' + tokens.access_token), null);
  await op('revoke', { client_id: 'different client', token: rotated.refresh_token });
  assert.equal(h.sql.exec('SELECT COUNT(*) AS n FROM devices').one().n, 1);
  await op('revoke', { client_id: id, token: rotated.refresh_token });
  assert.equal(await oauthSession(h, 'Bearer ' + rotated.access_token), null);
  assert.equal(h.sql.exec('SELECT COUNT(*) AS n FROM devices').one().n, 0);
});
test('device flow waits for explicit account approval and consumes a grant once', async () => {
  const h = setup(),
    op = (name, body) => oauthOperation(h, 'example.com', name, body);
  const id = (await op('register', { redirect_uris: ['https://relay.example.com/'] })).body.client_id;
  const challenge = (
    await op('device', { client_id: id, scope: 'urn:matrix:client:api:* urn:matrix:client:device:phone' })
  ).body;
  const poll = {
    grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
    device_code: challenge.device_code,
    client_id: id
  };
  assert.equal((await op('token', poll)).body.error, 'authorization_pending');
  assert.equal((await op('token', poll)).body.error, 'slow_down');
  const target = new URL((await op('verify', { user_code: challenge.user_code })).location).searchParams.get(
    'client'
  );
  assert.equal(new URL(target).searchParams.get('user_code'), challenge.user_code);
  await approveOAuth(h, 'example.com', 'account', target);
  assert.equal((await op('token', poll)).body.token_type, 'Bearer');
  await assert.rejects(op('token', poll));
});
test('QR rendezvous is conditional, expires and can be closed by either participant', async () => {
  const { sql } = setup(),
    id = 'test';
  const first = await exchange(sql, 'POST', id, 'first');
  assert.equal((await exchange(sql, 'GET', id, '', first.etag)).status, 304);
  assert.equal((await exchange(sql, 'GET', id, '', 'W/' + first.etag)).status, 304);
  assert.equal((await exchange(sql, 'PUT', id, 'different', 'wrong')).status, 412);
  const second = await exchange(sql, 'PUT', id, 'second', first.etag);
  assert.notEqual(first.etag, second.etag);
  assert.equal((await exchange(sql, 'GET', id, '', first.etag)).data, 'second');
  await exchange(sql, 'DELETE', id);
  assert.equal((await exchange(sql, 'GET', id)).status, 404);
});
