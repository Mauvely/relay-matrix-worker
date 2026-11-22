// SPDX-License-Identifier: AGPL-3.0-or-later
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { initSync } from './room-v10/pkg/relay_room_v10.js';
import { sessionHome } from './fixtures/session-home.js';
import { createIdentity } from './src/identity.js';
import { create, roomClient } from './src/rooms.js';
import { pusherApi, rulesApi, dispatchPush } from './src/push.js';
initSync({ module: readFileSync(new URL('./room-v10/pkg/relay_room_v10_bg.wasm', import.meta.url)) });
const gateway = 'https://gateway.test/_matrix/push/v1/notify',
  server = 'local.test';
const alice = { user_id: '@alice:local.test', device_id: 'A' },
  bob = { user_id: '@bob:local.test', device_id: 'B' };
const registration = {
  app_id: 'app',
  pushkey: 'test-key',
  kind: 'http',
  app_display_name: 'app',
  device_display_name: 'Phone',
  lang: 'en',
  data: { url: gateway, format: 'event_id_only', default_payload: { cs: 'test-routing-label' } }
};
async function setup() {
  const home = sessionHome();
  home.env = { DOMAINS: { 'local.test': server }, PUSH_GATEWAYS: [gateway] };
  home.identity = await createIdentity();
  home.party = async () => ({ organisationId: null });
  home.waiters = new Map();
  for (const auth of [alice, bob])
    home.sql.exec('INSERT INTO devices VALUES(?,?)', auth.user_id, auth.device_id);
  return home;
}
test('push registrations obey account, append, expiry and removal semantics', async () => {
  const home = await setup();
  const set = (a, body) => pusherApi(home, a, 'POST', ['pushers', 'set'], body);
  const get = (a) => pusherApi(home, a, 'GET', ['pushers']).body.pushers;
  set(alice, registration);
  set(bob, { ...registration, append: true });
  assert.equal(get(alice).length, 1);
  assert.equal(get(bob).length, 1);
  set(bob, registration);
  assert.deepEqual(get(alice), []);
  assert.throws(() =>
    set(bob, { ...registration, data: { url: 'https://other.test/_matrix/push/v1/notify' } })
  );
  set(bob, { kind: null, pushkey: registration.pushkey, app_id: 'app' });
  assert.deepEqual(get(bob), []);
});
test('encrypted room events notify once, preserve client routing data and respect mute, leave and rejected keys', async () => {
  const home = await setup(),
    sql = home.sql;
  pusherApi(home, bob, 'POST', ['pushers', 'set'], registration);
  const room = (await create(home, server, alice.user_id, { invite: [bob.user_id] })).body.room_id;
  await roomClient(home, server, bob, 'POST', [room, 'join'], {});
  const send = (who, txn) =>
    roomClient(home, server, who, 'PUT', [room, 'send', 'm.room.encrypted', txn], { ciphertext: 'private' });
  const count = () => sql.exec('SELECT COUNT(*) AS n FROM push_jobs').one().n;
  await send(bob, 'self');
  assert.equal(count(), 0);
  const event = (await send(alice, 'one')).body.event_id;
  await send(alice, 'one');
  assert.equal(count(), 1);
  await dispatchPush(home, async () => new Response('', { status: 503 }));
  assert.equal(sql.exec('SELECT attempt FROM push_jobs').one().attempt, 1);
  sql.exec('UPDATE push_jobs SET due=0');
  let payload;
  await dispatchPush(home, async (url, req) => {
    assert.equal(url, gateway);
    assert.equal(req.redirect, 'manual');
    payload = JSON.parse(req.body).notification;
    return Response.json({ rejected: [] });
  });
  assert.deepEqual(payload, {
    room_id: room,
    event_id: event,
    prio: 'high',
    counts: {},
    devices: [
      {
        app_id: 'app',
        pushkey: 'test-key',
        data: { format: 'event_id_only', default_payload: { cs: 'test-routing-label' } }
      }
    ]
  });
  assert.equal(count(), 0);
  const path = ['pushrules', 'global', 'room', room],
    params = new URLSearchParams();
  rulesApi(home, bob.user_id, 'PUT', path, params, { actions: [] });
  await send(alice, 'muted');
  assert.equal(count(), 0);
  rulesApi(home, bob.user_id, 'DELETE', path, params, {});
  await send(alice, 'resumed');
  assert.equal(count(), 1);
  await dispatchPush(home, async () => Response.json({ rejected: ['test-key'] }));
  assert.equal(count(), 0);
  assert.deepEqual(pusherApi(home, bob, 'GET', ['pushers']).body.pushers, []);
  pusherApi(home, bob, 'POST', ['pushers', 'set'], registration);
  await send(alice, 'leaving');
  await roomClient(home, server, bob, 'POST', [room, 'leave'], {});
  let called = false;
  await dispatchPush(home, async () => {
    called = true;
  });
  assert.equal(called, false);
  assert.equal(count(), 0);
});

test('notification tap looks up the exact message and context within joined history', async () => {
  const home = await setup();
  const room = (await create(home, server, alice.user_id, { invite: [bob.user_id] })).body.room_id;
  const send = async (txn) => (await roomClient(home, server, alice, 'PUT',
    [room, 'send', 'm.room.encrypted', txn], { ciphertext: txn })).body.event_id;
  const prior = await send('before-membership');
  await roomClient(home, server, bob, 'POST', [room, 'join'], {});
  const first = await send('first'), target = await send('second'), last = await send('third');
  const read = async (action, id, params = {}) => (await roomClient(home, server, bob, 'GET',
    [room, action, id], {}, new URLSearchParams(params))).body;
  for (const action of ['event', 'context']) await assert.rejects(read(action, prior), { status: 404 });
  assert.equal((await read('event', target)).event_id, target);
  const results = await read('context', target, { limit: '2', filter: JSON.stringify({ lazy_load_members: true }) });
  assert.deepEqual(results.events_before.map(e => e.event_id), [first]);
  assert.deepEqual(results.events_after.map(e => e.event_id), [last]);
  assert.deepEqual(results.state.filter(e => e.type === 'm.room.member').map(e => e.state_key), [alice.user_id]);
  const minimal = await read('context', target, { limit: '0', filter: JSON.stringify({ types: ['m.room.name'] }) });
  assert.equal(minimal.event.event_id, target);
  assert.deepEqual([minimal.events_before, minimal.events_after, minimal.state], [[], [], []]);
  await roomClient(home, server, bob, 'POST', [room, 'leave'], {});
  await assert.rejects(read('context', target), { status: 403 });
});

test('leaving while the push policy is resolved cancels the pending delivery', async () => {
  const home = await setup();
  const room = (await create(home, server, alice.user_id, { invite: [bob.user_id] })).body.room_id;
  await roomClient(home, server, bob, 'POST', [room, 'join'], {});
  pusherApi(home, bob, 'POST', ['pushers', 'set'], registration);
  await roomClient(home, server, alice, 'PUT', [room, 'send', 'm.room.encrypted', '1'], { ciphertext: 'one' });
  const original = home.party;
  home.party = async () => {
    home.party = original;
    await roomClient(home, server, bob, 'POST', [room, 'leave'], {});
    return { organisationId: null };
  };
  let sends = 0;
  await dispatchPush(home, async () => { sends++; return Response.json({ rejected: [] }); });
  assert.equal(sends, 0);
});
