// SPDX-License-Identifier: AGPL-3.0-or-later
import test from 'node:test';
import assert from 'node:assert/strict';
import {delegated, login, provision, session} from './src/accounts.js';

function store() {
  const data = new Map();
  return {get: k => data.get(k), put: (k,v) => data.set(k,v), delete: k => data.delete(k), transaction(fn) { return fn(this); }};
}

test('the same localpart can sign into two tenant stores independently', async () => {
  const a = store(), b = store();
  const first = await provision(a, 'a.example', 'alex', 'org-1');
  const second = await provision(b, 'b.example', 'alex', 'org-2');
  assert.equal(first.status, 201);
  assert.equal(second.status, 201);
  assert.equal((await provision(a, 'a.example', 'alex', 'org-2')).status, 409);
  const form = {type:'m.login.password', identifier:{type:'m.id.user',user:'alex'}, password:first.body.password};
  assert.equal((await login(b,'b.example',form)).status,403);
  const result = await login(a,'a.example',form);
  const token = 'Bearer ' + result.body.access_token;
  assert.equal((await session(a,token)).body.user_id,'@alex:a.example');
  assert.equal((await session(b,token)).status,401);
  assert.equal((await session(a,token,true)).status,200);
  assert.equal((await session(a,token)).status,401);
});

test('both delegated records must identify the preassigned endpoint', async () => {
  const mock = (client,server) => url => Response.json(url.endsWith('/client') ? {'m.homeserver':{base_url:client}} : {'m.server':server});
  assert.ok(await delegated('a.example','hs.example',mock('https://hs.example','hs.example:443')));
  assert.equal(await delegated('a.example','hs.example',mock('https://other.example','hs.example:443')),false);
  assert.equal(await delegated('a.example','hs.example',mock('https://hs.example','other.example:443')),false);
});
