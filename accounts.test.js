// SPDX-License-Identifier: AGPL-3.0-or-later
import test from 'node:test';
import assert from 'node:assert/strict';
import { delegated, ensureManagedAccount, login, provision, session } from './src/accounts.js';

function store() {
  const data = new Map();
  return {
    get: (k) => data.get(k),
    put: (k, v) => data.set(k, v),
    delete: (k) => data.delete(k),
    transaction(fn) {
      return fn(this);
    }
  };
}

test('the same localpart can sign into two tenant stores independently', async () => {
  const a = store(),
    b = store();
  const first = await provision(a, 'a.example', 'alex', 'org-1');
  const second = await provision(b, 'b.example', 'alex', 'org-2');
  assert.equal(first.status, 201);
  assert.equal(second.status, 201);
  assert.equal((await provision(a, 'a.example', 'alex', 'org-2')).status, 409);
  const form = {
    type: 'm.login.password',
    identifier: { type: 'm.id.user', user: 'alex' },
    password: first.body.password
  };
  assert.equal((await login(b, 'b.example', form)).status, 403);
  const result = await login(a, 'a.example', form);
  const token = 'Bearer ' + result.body.access_token;
  assert.equal((await session(a, token)).body.user_id, '@alex:a.example');
  assert.equal((await session(b, token)).status, 401);
  assert.equal((await session(a, token, true)).status, 200);
  assert.equal((await session(a, token)).status, 401);
});

test('both delegated records must identify the preassigned endpoint', async () => {
  const mock = (client, server) => (url) =>
    Response.json(
      url.endsWith('/client') ? { 'm.homeserver': { base_url: client } } : { 'm.server': server }
    );
  assert.ok(await delegated('a.example', 'hs.example', mock('https://hs.example', 'hs.example:443')));
  assert.equal(
    await delegated('a.example', 'hs.example', mock('https://other.example', 'hs.example:443')),
    false
  );
  assert.equal(
    await delegated('a.example', 'hs.example', mock('https://hs.example', 'other.example:443')),
    false
  );
});

test('directory retries retain the account owner and immutable Matrix ID', async () => {
  const db = store();
  const ensure = (owner, local) => ensureManagedAccount(db, 'testing.example', owner, local, null);
  assert.equal(await ensure('usr_1', 'alex'), '@alex:testing.example');
  assert.equal(await ensure('usr_1', 'alex'), '@alex:testing.example');
  await assert.rejects(ensure('usr_2', 'alex'));
  await assert.rejects(ensure('usr_1', 'different'));
  assert.equal(db.get('account/alex').passwordHash, undefined);
  await provision(db, 'testing.example', 'existing', null);
  await assert.rejects(ensure('usr_3', 'existing'));
});

test('SSO codes expire, can be redeemed once and cannot cross homeservers', async () => {
  const { DatabaseSync } = await import('node:sqlite');
  const { issueLoginCode, redeemLoginCode, ssoRedirect } = await import('./src/accounts.js');
  const db = new DatabaseSync(':memory:');
  db.exec('CREATE TABLE sso_codes(hash TEXT PRIMARY KEY,user TEXT NOT NULL,expires INTEGER NOT NULL)');
  const sql = { exec(query, ...values) { const result = db.prepare(query).all(...values); return {toArray: () => result}; } };
  const storage = store(), server = 'a.example';
  await ensureManagedAccount(storage, server, 'usr_1', 'alex', null);
  const code = await issueLoginCode(storage, sql, 'usr_1');
  assert.equal((await redeemLoginCode(storage, sql, server, {token:code})).body.user_id, '@alex:a.example');
  assert.equal((await redeemLoginCode(storage, sql, server, {token:code})).status, 403);
  const old = await issueLoginCode(storage, sql, 'usr_1');
  db.exec('UPDATE sso_codes SET expires=0');
  assert.equal((await redeemLoginCode(storage, sql, server, {token:old})).status, 403);
  const foreign = await issueLoginCode(storage, sql, 'usr_1');
  assert.equal((await redeemLoginCode(storage, sql, 'b.example', {token:foreign})).status, 403);
  assert.equal(ssoRedirect('https://unlisted.example/matrix', ['https://relay.example/matrix']), null);
  assert.equal(ssoRedirect('https://relay.example/matrix?state=1', ['https://relay.example/matrix']).search, '?state=1');
  db.close();
});
