// SPDX-License-Identifier: AGPL-3.0-or-later
import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { readFileSync } from 'node:fs';
import { initSync, prepare_event } from './room-v10/pkg/relay_room_v10.js';
import { createIdentity } from './src/identity.js';
import { sign } from './src/federation.js';
import { schema, create, fedRoom, roomClient, roomSync } from './src/rooms.js';
import { eventId } from './src/graph.js';
initSync({ module: readFileSync(new URL('./room-v10/pkg/relay_room_v10_bg.wasm', import.meta.url)) });
test('private v10 room requires an invitation and accepts a signed remote join exactly once', async () => {
  const db = new DatabaseSync(':memory:');
  const sql = {
    exec(query, ...args) {
      if (query.includes(';')) {
        db.exec(query);
        return;
      }
      const rows = db.prepare(query).all(...args);
      return { toArray: () => rows, one: () => rows[0] };
    }
  };
  const server = 'worker.test',
    peer = 'synapse.test',
    user = '@a:' + server,
    other = '@b:' + peer;
  const identity = await createIdentity(),
    remote = await createIdentity();
  const home = {
    identity,
    sql,
    ctx: { storage: { transactionSync: (f) => f() } },
    waiters: new Map(),
    party: async () => ({ organisationId: null }),
    env: {
      PEER_KEYS: { [peer]: { 'ed25519:1': remote.publicKey } },
      PEER_URLS: { [peer]: 'https://peer.test' }
    }
  };
  schema(sql);
  const {
    body: { room_id: room }
  } = await create(home, server, user, {
    initial_state: [{ type: 'm.room.encryption', content: { algorithm: 'm.megolm.v1.aes-sha2' } }]
  });
  const make = () =>
    fedRoom(home, server, peer, 'GET', ['make_join', room, other], new URLSearchParams('ver=10'));
  await assert.rejects(make, /invitation/);
  await roomClient(home, server, { user_id: user }, 'POST', [room, 'invite'], { user_id: other });
  const {
    body: { event: p }
  } = await make();
  const [hash, redacted] = JSON.parse(prepare_event(JSON.stringify(p)));
  p.hashes = { sha256: hash };
  p.signatures = { [peer]: { 'ed25519:1': await sign(remote, redacted) } };
  const join = () =>
    fedRoom(home, server, peer, 'PUT', ['send_join', room, eventId(p)], new URLSearchParams(), p);
  assert.deepEqual(await join(), await join());
  const initial = await roomSync(home, server, user, 0, true);
  const timeline = initial.rooms.join[room].timeline;
  assert.ok(timeline.events.some((e) => e.sender === other));
  const messages = (user_id, opts) =>
    roomClient(
      home,
      server,
      { user_id },
      'GET',
      [room, 'messages'],
      undefined,
      new URLSearchParams(opts)
    ).then((r) => r.body);
  const oldest = await messages(user, { dir: 'b', from: timeline.prev_batch });
  assert.deepEqual(oldest.chunk, []);
  assert.equal(oldest.end, undefined);
  const newest = await messages(user, { dir: 'b', limit: 1 });
  assert.equal(newest.chunk[0].event_id, timeline.events.at(-1).event_id);
  const rest = await messages(user, { dir: 'b', from: newest.end });
  assert.deepEqual(
    [newest.chunk[0], ...rest.chunk].map((e) => e.event_id),
    timeline.events.map((e) => e.event_id).reverse()
  );
  assert.deepEqual(
    (await messages(other, { dir: 'f' })).chunk.map((e) => e.event_id),
    [eventId(p)]
  );
  await assert.rejects(messages(user, { dir: 'b', from: '!another:server/9' }), /history token/);
  await assert.rejects(messages('@stranger:' + server, { dir: 'b' }), /membership/i);
});

test('linear rooms grow beyond 512 events without replaying every prior message', async () => {
  const db = new DatabaseSync(':memory:');
  let historyReads = 0;
  const sql = {exec(q, ...args) {
    if (q.includes(';')) return db.exec(q);
    if (q.includes('SELECT eid,pdu FROM room_events WHERE room=? ORDER BY seq')) historyReads++;
    const rows = db.prepare(q).all(...args);
    return {toArray: () => rows, one: () => rows[0]};
  }};
  schema(sql);
  const server = 'worker.example', user = '@grow:' + server;
  const home = {sql, waiters:new Map(), identity: await createIdentity(), ctx:{storage:{transactionSync: fn => fn()}},
    env:{}, party: async () => ({organisationId:null})};
  const auth = {user_id:user,device_id:'TEST'};
  const room = (await create(home,server,user,{})).body.room_id;
  const baseline = historyReads;
  let last;
  for (let i=0; i<520; i++) last = await roomClient(home,server,auth,'PUT',[room,'send','m.room.message',String(i)],{msgtype:'m.text',body:String(i)});
  assert.equal(last.status, 200);
  assert.equal(historyReads,baseline);
  const sync = await roomSync(home,server,user,0,true);
  const joined = sync.rooms.join[room];
  assert.equal(joined.timeline.events.at(-1).event_id,last.body.event_id);
  assert.equal(joined.timeline.limited, true);
  assert.equal(joined.timeline.events.length, 50);
  assert.equal(joined.timeline.events[0].content.body, '470');
  assert.ok(joined.state.events.some((e) => e.type === 'm.room.member' && e.state_key === user));
  const earlier = await roomClient(home,server,auth,'GET',[room,'messages'],undefined,
    new URLSearchParams({dir:'b',from:joined.timeline.prev_batch,limit:'1'}));
  assert.equal(earlier.body.chunk[0].content.body,'469');
  assert.equal(historyReads,baseline);
  const page = await roomClient(home,server,auth,'GET',[room,'messages'],undefined,new URLSearchParams({dir:'b',limit:'100'}));
  assert.equal(page.body.chunk.length,100);
  assert.ok(page.body.end);
  db.close();
});
