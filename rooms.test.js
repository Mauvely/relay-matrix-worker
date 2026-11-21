// SPDX-License-Identifier: AGPL-3.0-or-later
import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { readFileSync } from 'node:fs';
import { initSync, prepare_event } from './room-v10/pkg/relay_room_v10.js';
import { createIdentity } from './src/identity.js';
import { sign } from './src/federation.js';
import { schema, create, fedRoom, load, requireRoomAccess, receiveEvent, roomClient, roomSync } from './src/rooms.js';
import { eventId, signPdu } from './src/graph.js';
initSync({ module: readFileSync(new URL('./room-v10/pkg/relay_room_v10_bg.wasm', import.meta.url)) });
for (const version of [10,11]) test(`private v${version} room checks invitations, signed state and join retries`, async () => {
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
    room_version: String(version),
    initial_state: [{ type: 'm.room.encryption', content: { algorithm: 'm.megolm.v1.aes-sha2' } }]
  });
  await roomClient(home,server,{user_id:user},'PUT',[room,'send','m.room.message','before'],{msgtype:'m.text',body:'before membership'});
  const make = () =>
    fedRoom(home, server, peer, 'GET', ['make_join', room, other], new URLSearchParams({ver:String(version)}));
  await assert.rejects(make, /invitation/);
  await roomClient(home, server, { user_id: user }, 'POST', [room, 'invite'], { user_id: other });
  const {
    body: { event: p }
  } = await make();
  const [hash, redacted] = JSON.parse(prepare_event(JSON.stringify(p),version));
  p.hashes = { sha256: hash };
  p.signatures = { [peer]: { 'ed25519:1': await sign(remote, redacted) } };
  const join = () =>
    fedRoom(home, server, peer, 'PUT', ['send_join', room, eventId(p,version)], new URLSearchParams(), p);
  const first = await join();
  assert.deepEqual(first, await join());
  const {joinBase,resolveJoin} = await import('./src/join-state.js');
  const {state,auth_chain} = first.body;
  const base = joinBase(room,state,auth_chain,p,version);
  const keys = {[peer]:{'ed25519:1':remote.publicKey},[server]:{'ed25519:1':identity.publicKey}};
  assert.ok(resolveJoin(room,keys,base,[],version).some(([type,key,id]) =>
    type === 'm.room.member' && key === other && id === eventId(p,version)));
  assert.throws(() => resolveJoin(room,keys,{...base,stateIds:[...base.stateIds,base.stateIds[0]]},[],version),/duplicate/i);
  assert.throws(() => resolveJoin(room,keys,{...base,join:{...p,signatures:{}}},[],version));
  assert.throws(() => resolveJoin(room,keys,base,[],version===10 ? 11 : 10));
  await assert.rejects(fedRoom(home,server,peer,'GET',['make_join',room,other],new URLSearchParams('ver=9')),/support/i);
  // Each signed topic references the join anchor, so they form a genuine fork.
  const graph = load(home,server,room);
  const forks = await Promise.all(['First','Second'].map((topic) =>
    signPdu(identity,server,graph.template(user,'m.room.topic',{topic},''),version)));
  const resolved = resolveJoin(room,keys,base,forks,version);
  assert.deepEqual(resolved,resolveJoin(room,keys,base,forks.toReversed(),version));
  assert.ok(resolved.some(([type,key,id]) =>
    type === 'm.room.topic' && forks.some((pdu) => eventId(pdu,version) === id)));
  const joinedMembers = (who) => roomClient(home,server,{user_id:who},'GET',[room,'joined_members']);
  assert.deepEqual(Object.keys((await joinedMembers(user)).body.joined).sort(),[user,other].sort());
  await assert.rejects(joinedMembers('@unknown:'+server),/membership/i);
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
    [eventId(p,version)]
  );
  await assert.rejects(messages(user, { dir: 'b', from: '!another:server/9' }), /history token/);
  await assert.rejects(messages('@stranger:' + server, { dir: 'b' }), /membership/i);
  const one = await roomClient(home,server,{user_id:user},'PUT',[room,'send','m.room.message','seen'],{msgtype:'m.text',body:'visible'});
  const tail = await roomClient(home,server,{user_id:user},'PUT',[room,'send','m.room.message','tail'],{msgtype:'m.text',body:'tip'});
  const gapRequest={earliest_events:[], latest_events:[tail.body.event_id],limit:50};
  const gap = await fedRoom(home,server,peer,'POST',['get_missing_events',room],new URLSearchParams(),gapRequest);
  assert.equal(gap.body.events.at(-1).content.body,'visible');
  const text = gap.body.events.filter((e) => e.type === 'm.room.message');
  assert.deepEqual(text.map((e) => e.content.body),[undefined,'visible']);
  assert.ok(text[0].signatures[server]);
  assert.ok(gap.body.events.every((e) => eventId(e,version) !== tail.body.event_id));
  const afterFirst = {...gapRequest,earliest_events:[one.body.event_id]};
  assert.deepEqual((await fedRoom(home,server,peer,'POST',['get_missing_events',room],new URLSearchParams(),afterFirst)).body.events,[]);
  await assert.rejects(fedRoom(home,server,'stranger.test','POST',['get_missing_events',room],new URLSearchParams(),gapRequest),/joined/);

  const {recoverPredecessors} = await import('./src/gaps.js');
  const branch = load(home,server,room);
  const branchEvents=[];
  for (const body of ['first missing','second missing','last received']) {
    branchEvents.push(await branch.local(remote,other,'m.room.message',{msgtype:'m.text',body}));
  }
  const arriving=branchEvents.at(-1);
  const recovered=await recoverPredecessors(home,server,peer,arriving,async (_h,_s,_p,method,uri,body) => {
    assert.equal(method,'POST');
    assert.ok(uri.includes('get_missing_events'));
    assert.deepEqual(body.latest_events,[eventId(arriving,version)]);
    return Response.json({events:branchEvents.slice(0,2).toReversed()});
  });
  assert.deepEqual(recovered,branchEvents.slice(0,2));
  await assert.rejects(recoverPredecessors(home,server,peer,arriving,async () =>
    Response.json({events:[]})),/complete predecessor chain/);
  const wrongSignature={...recovered[1],signatures:{}};
  await assert.rejects(receiveEvent(home,server,peer,arriving,[recovered[0],wrongSignature]));
  assert.equal(load(home,server,room).events.has(eventId(recovered[0],version)),false);
  await receiveEvent(home,server,peer,arriving,recovered);
  await receiveEvent(home,server,peer,arriving,recovered);
  assert.equal((await messages(user,{dir:'b',limit:1})).chunk[0].content.body,'last received');
  const acl = (allow,deny) => roomClient(home,server,{user_id:user},'PUT',[room,'state','m.room.server_acl',''],{allow,deny});
  await acl(['*'],['synapse.*']);
  await assert.rejects(make,(e) => e.status===403 && e.errcode==='M_FORBIDDEN');
  await assert.rejects(join(),(e) => e.status===403);
  await assert.rejects(receiveEvent(home,server,peer,p),(e) => e.status===403);
  await acl(['*'],[]);
  assert.equal((await make()).status,200);
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

test('ACLs use the server hostname, prefer deny rules and support case-insensitive globs and IP rules', () => {
  const acl={content:{allow:['*.example'],deny:['b?.example'],allow_ip_literals:false}};
  requireRoomAccess(acl,'chat.EXAMPLE:8448');
  for (const name of ['bb.example','another.test','127.0.0.1:443','[::1]:8448']) {
    assert.throws(() => requireRoomAccess(acl,name),(e) => e.status===403);
  }
  assert.throws(() => requireRoomAccess({content:{}},'chat.example'));
});
