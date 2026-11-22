// SPDX-License-Identifier: AGPL-3.0-or-later
import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { readFileSync } from 'node:fs';
import { initSync, prepare_event } from './room-v10/pkg/relay_room_v10.js';
import { createIdentity } from './src/identity.js';
import { sign } from './src/federation.js';
import { schema, create, fedRoom, load, requireRoomAccess, receiveEvent, roomClient, roomSync, save } from './src/rooms.js';
import { eventId, signPdu } from './src/graph.js';
initSync({ module: readFileSync(new URL('./room-v10/pkg/relay_room_v10_bg.wasm', import.meta.url)) });
function memorySql() {
  const db = new DatabaseSync(':memory:');
  return {
    exec(query, ...args) {
      if (query.includes(';')) {
        db.exec(query);
        return;
      }
      const rows = db.prepare(query).all(...args);
      return { toArray: () => rows, one: () => rows[0] };
    }
  };
}
for (const version of [10,11]) test(`private v${version} room checks invitations, signed state and join retries`, async () => {
  const sql = memorySql();
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
  // A branch forked before the remote join, then merged with the join. The
  // new home knows the join snapshot but has never seen the old messages.
  const remoteSql = memorySql();
  schema(remoteSql);
  const replica = {...home,sql:remoteSql,identity:remote,
    env:{PEER_KEYS:{[server]:{'ed25519:1':identity.publicKey}},PEER_URLS:{[server]:'https://worker.test'}}};
  for (const [pos,e] of base.auth.entries())
    remoteSql.exec('INSERT INTO room_outliers VALUES(?,?,?,?)',room,eventId(e,version),pos,JSON.stringify(e));
  const joinId = eventId(p,version);
  remoteSql.exec('INSERT INTO room_bases VALUES(?,?,?)',room,joinId,JSON.stringify(base.stateIds));
  const snapshot = new Map(resolveJoin(room,keys,base,[],version).map(([t,k,id])=>[JSON.stringify([t,k]),id]));
  save(replica,{room,version,state:snapshot,tips:new Set([joinId])},[p]);
  const origin = load(home,server,room);
  const oldTimeline = [...origin.events.entries()].filter(([id])=>id!==joinId).map(([,e])=>e);
  const hidden = {...origin.template(user,'m.room.message',{msgtype:'m.text',body:'Before join'}),
    prev_events:p.prev_events, depth:p.depth};
  const oldMessage = await signPdu(identity,server,hidden,version);
  const successor = await signPdu(identity,server,{...origin.template(user,'m.room.message',{msgtype:'m.text',body:'After merge'}),
    prev_events:[joinId,eventId(oldMessage,version)],depth:p.depth+1},version);
  const {recoverPredecessors:recover} = await import('./src/gaps.js');
  const proof = await recover(replica,peer,server,successor,async()=>Response.json({events:[...oldTimeline,oldMessage]}));
  const actualState = base.stateIds;
  remoteSql.exec('UPDATE room_bases SET state_ids=? WHERE room=?',JSON.stringify(actualState.slice(1)),room);
  await assert.rejects(receiveEvent(replica,peer,server,successor,proof),/disagrees/);
  assert.equal(remoteSql.exec('SELECT COUNT(*) AS n FROM room_ancestry').one().n,0);
  remoteSql.exec('UPDATE room_bases SET state_ids=? WHERE room=?',JSON.stringify(actualState),room);
  await receiveEvent(replica,peer,server,successor,proof);
  const visible = await roomClient(replica,peer,{user_id:other},'GET',[room,'messages'],null,new URLSearchParams({dir:'b'}));
  assert.deepEqual(visible.body.chunk.map(e=>e.event_id),[eventId(successor,version),joinId]);
  assert.deepEqual([...load(replica,peer,room).tips],[eventId(successor,version)]);
  const priorId = eventId(oldMessage,version);
  const stateParams = new URLSearchParams({event_id:priorId});
  const priorIds = (await fedRoom(replica,peer,server,'GET',['state_ids',room],stateParams)).body;
  const priorState = (await fedRoom(replica,peer,server,'GET',['state',room],stateParams)).body;
  assert.deepEqual(priorIds.pdu_ids,priorState.pdus.map(e=>eventId(e,version)));
  assert.deepEqual(priorIds.auth_chain_ids,priorState.auth_chain.map(e=>eventId(e,version)));
  assert.equal(priorState.pdus.find(e=>e.type==='m.room.member' && e.state_key===other).content.membership,'invite');
  assert.ok((await fedRoom(replica,peer,server,'GET',['event_auth',room,priorId],stateParams)).body.auth_chain.length);
  await assert.rejects(fedRoom(replica,peer,'stranger.test','GET',['state_ids',room],stateParams));
  const early = oldTimeline.find(e=>e.type==='m.room.message');
  const preJoin = (await fedRoom(home,server,peer,'GET',['backfill',room],
    new URLSearchParams({v:eventId(early,version),limit:'1'}))).body;
  assert.equal(preJoin.pdus[0].content.body,undefined);
  const dated = until => ({...keys,[peer]:{'ed25519:1':{key:remote.publicKey,until}}});
  assert.deepEqual(resolveJoin(room,dated(p.origin_server_ts),base,[],version),
    resolveJoin(room,keys,base,[],version));
  assert.throws(() => resolveJoin(room,dated(p.origin_server_ts-1),base,[],version));
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

  // An authorized redaction reaches the client and the federated history endpoint
  // for exactly one event. Reusing the transaction returns the same signed event.
  const redact = (sender,id,tx) => roomClient(home,server,{user_id:sender,device_id:'web'},
    'PUT',[room,'redact',id,tx],{reason:'Remove attachment'});
  await assert.rejects(redact(other,one.body.event_id,'no'),e=>e.status===403);
  const removal = (await redact(user,one.body.event_id,'remove')).body.event_id;
  assert.equal((await redact(user,one.body.event_id,'remove')).body.event_id,removal);
  const get = async id => (await roomClient(home,server,{user_id:user},'GET',[room,'event',id])).body;
  assert.equal((await get(removal)).redacts,one.body.event_id);
  assert.equal((await get(one.body.event_id)).unsigned.redacted_because.event_id,removal);
  assert.deepEqual((await get(one.body.event_id)).content,{});
  assert.equal((await get(tail.body.event_id)).content.body,'tip');
  const fedRead = async id => (await fedRoom(home,server,peer,'GET',['event',room,id],new URLSearchParams())).body.pdus[0];
  assert.deepEqual((await fedRead(one.body.event_id)).content,{});
  const pdu = await fedRead(removal);
  assert.equal(version === 10 ? pdu.redacts : pdu.content.redacts,one.body.event_id);
  // A peer can send a valid redaction before its independently arriving target.
  const pending = load(home,server,room);
  const targetPdu = await signPdu(remote,peer,pending.template(other,'m.room.encrypted',{ciphertext:'file'}),version);
  const targetId = eventId(targetPdu,version);
  const pendingRedact = await pending.local(remote,other,'m.room.redaction',version === 11 ? {redacts:targetId} : {},undefined,targetId);
  await receiveEvent(home,server,peer,pendingRedact);
  await assert.rejects(get(eventId(pendingRedact,version)),e=>e.status===404);
  await receiveEvent(home,server,peer,targetPdu);
  assert.deepEqual((await get(targetId)).content,{});
  assert.equal((await get(eventId(pendingRedact,version))).redacts,targetId);
  const syncRedacted = (await roomSync(home,server,user,0,true)).rooms.join[room].timeline.events.find(e=>e.event_id===targetId);
  assert.equal(syncRedacted.unsigned.redacted_because.event_id,eventId(pendingRedact,version));
  const remoteDenied = await load(home,server,room).local(remote,other,'m.room.redaction',
    version === 11 ? {redacts:tail.body.event_id} : {},undefined,tail.body.event_id);
  await receiveEvent(home,server,peer,remoteDenied);
  await assert.rejects(get(eventId(remoteDenied,version)),e=>e.status===404);
  assert.equal((await get(tail.body.event_id)).content.body,'tip');

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
  // The peer returns one predecessor per page, forcing a retry after eight.
  const offline = load(home,server,room);
  const chain = [];
  for (let i = 0; i < 11; i++) {
    chain.push(await offline.local(remote,other,'m.room.message',{msgtype:'m.text',body:String(i)}));
  }
  const last = chain.at(-1);
  const pages = new Map(chain.slice(1).map((event, i) => [eventId(event,version), chain[i]]));
  const requested = [];
  const page = async (_home, _server, _peer, _method, _uri, body) => {
    const [from] = body.latest_events;
    requested.push(from);
    return Response.json({events:[pages.get(from)]});
  };
  await assert.rejects(recoverPredecessors(home,server,peer,last,page),/complete predecessor chain/);
  assert.equal(requested.length, 8);
  assert.equal((await messages(user,{dir:'b',limit:1})).chunk[0].content.body,'last received');
  const resumed = {...home, waiters:new Map()};
  const complete = await recoverPredecessors(resumed,server,peer,last,page);
  assert.deepEqual(complete,chain.slice(0,-1));
  assert.equal(requested.length,10);
  assert.equal(new Set(requested).size,10);
  const { inviteSchema } = await import('./src/invites.js');
  inviteSchema(sql);
  const { federationApi } = await import('./src/api.js');
  const deliver = () => federationApi(resumed,server,peer,'PUT',['send','resumed'],new URLSearchParams(),
    {origin:peer,pdus:[last],edus:[]},new Map([[last,complete]]));
  assert.deepEqual((await deliver()).body.pdus[eventId(last,version)],{});
  assert.deepEqual((await deliver()).body.pdus[eventId(last,version)],{});
  assert.equal(sql.exec('SELECT COUNT(*) AS n FROM federation_gap_events').one().n,0);
  assert.deepEqual((await messages(user,{dir:'b',limit:11})).chunk.map(e => e.content.body),
    chain.map(e=>e.content.body).reverse());
  // The remote topic was valid when authored. While its server was offline,
  // the local admin raised the power needed to change the topic.
  const power = load(home,server,room).get('m.room.power_levels').content;
  const topicPower = level => roomClient(home,server,{user_id:user},'PUT',[room,'state','m.room.power_levels',''],
    {...power, events:{...power.events,'m.room.topic':level}});
  await topicPower(0);
  const delayed = await load(home,server,room).local(remote,other,'m.room.topic',{topic:'Before permission changed'},'');
  const delayedId = eventId(delayed,version);
  await topicPower(50);
  const checkpoint = await roomSync(home,server,user,0,true);
  await assert.rejects(receiveEvent(home,server,peer,{...delayed,signatures:{}}));
  await receiveEvent(home,server,peer,delayed);
  const current = load(home,server,room);
  assert.ok(current.softFailed.has(delayedId));
  assert.ok(!current.tips.has(delayedId));
  assert.notEqual(current.get('m.room.topic')?.content.topic,delayed.content.topic);
  assert.ok(!(await messages(user,{dir:'b',limit:100})).chunk.some(e=>e.event_id===delayedId));
  assert.equal((await roomSync(home,server,user,checkpoint.high,false)).rooms.join[room],undefined);
  const child = current.template(other,'m.room.message',{msgtype:'m.text',body:'After reconnect'});
  assert.ok(!child.prev_events.includes(delayedId));
  child.prev_events.push(delayedId);
  child.depth = 1 + Math.max(...child.prev_events.map(id=>current.events.get(id).depth));
  const merged = await signPdu(remote,peer,child,version);
  await receiveEvent(home,server,peer,merged);
  assert.deepEqual([...load(home,server,room).tips],[eventId(merged,version)]);
  assert.equal((await messages(user,{dir:'b',limit:1})).chunk[0].content.body,'After reconnect');
  const history=await fedRoom(home,server,peer,'POST',['get_missing_events',room],new URLSearchParams(),
    {earliest_events:[],latest_events:[eventId(merged,version)],limit:10});
  assert.ok(history.body.events.some(e=>eventId(e,version)===delayedId));
  const direct = () => federationApi(home,server,peer,'GET',['event',delayedId],new URLSearchParams());
  assert.equal((await direct()).body.pdus[0].content.topic,delayed.content.topic);
  await assert.rejects(federationApi(home,server,'outsider.test','GET',['event',delayedId],new URLSearchParams()));
  const backfill = (id,limit) => fedRoom(home,server,peer,'GET',['backfill',room],new URLSearchParams({v:id,limit}));
  assert.deepEqual((await backfill(delayedId,'5')).body.pdus,[]);
  assert.ok((await backfill(eventId(merged,version),'5')).body.pdus.some(e=>eventId(e,version)===delayedId));
  assert.deepEqual((await backfill(eventId(merged,version),'1')).body.pdus,[merged]);
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

test('Matrix TURN credentials are scoped to the authenticated account and reused until refresh', async () => {
  const {clientApi} = await import('./src/api.js');
  const storage = new Map();
  let issued = 0;
  const home = {env:{TURN_PROVIDER:{credentials:async () => ({
    uris:['turns:relay.test:443'],username:'temporary'+(++issued),password:'ephemeral',ttl:7200
  })}}, party:async () => ({organisationId:null}),ctx:{storage:{get:key=>storage.get(key),put:(key,v)=>storage.set(key,v)}}};
  const get = user => clientApi(home,'worker.test',{user_id:user},'GET',['voip','turnServer'],new URLSearchParams());
  const first = await get('@a:worker.test');
  assert.equal((await get('@a:worker.test')).body.username,first.body.username);
  assert.notEqual((await get('@b:worker.test')).body.username,first.body.username);
  home.party = async () => ({organisationId:'restricted'});
  await assert.rejects(get('@a:worker.test'),e=>e.status===403);
});

test('public room joins use via hints, legacy hints and the room ID domain in order', async () => {
  const {joinServers} = await import('./src/invites.js');
  const hints = new URLSearchParams('via=local.test&via=resident.test&server_name=second.test&via=resident.test');
  assert.deepEqual(joinServers('!id:creator.test:8448',hints,'local.test'), ['resident.test','second.test','creator.test:8448']);
  assert.deepEqual(joinServers('!id:local.test',new URLSearchParams(),'local.test'), []);
  assert.deepEqual(joinServers('#alias:creator.test',hints,'local.test'), []);
});

test('Element X gets a window, authorised room state and incremental timeline tied to its device', async () => {
  const {slidingSchema,slidingSync} = await import('./src/sliding.js');
  const {inviteSchema} = await import('./src/invites.js');
  const sql = memorySql(), server = 'worker.test', user='@a:'+server;
  const home = {sql,identity:await createIdentity(),ctx:{storage:{transactionSync:fn=>fn()}},env:{DOMAINS:{}},
    waiters:new Map(),party:async()=>({organisationId:null})};
  schema(sql); inviteSchema(sql); slidingSchema(sql);
  const auth = {user_id:user,device_id:'phone'};
  const room = (await create(home,server,user,{name:'Example'})).body.room_id;
  const req = {lists:{all_rooms:{ranges:[[0,19]],timeline_limit:1,required_state:[['m.room.name','']]}},conn_id:'rooms'};
  const first = await slidingSync(home,server,auth,req,'');
  assert.equal(first.lists.all_rooms.count,1);
  assert.equal(first.rooms[room].name,'Example');
  assert.equal(first.rooms[room].timeline.length,1);
  assert.equal(first.rooms[room].required_state[0].content.name,'Example');
  const query = 'pos='+first.pos;
  await assert.rejects(slidingSync(home,server,{...auth,device_id:'other'},req,query),{errcode:'M_UNKNOWN_POS'});
  assert.deepEqual(Object.keys((await slidingSync(home,server,auth,req,query)).rooms),[]);
  await roomClient(home,server,auth,'PUT',[room,'send','m.room.message','one'],{msgtype:'m.text',body:'Hello'});
  const second = await slidingSync(home,server,auth,req,query);
  assert.equal(second.rooms[room].timeline[0].content.body,'Hello');
  assert.equal(second.rooms[room].num_live,1);
  const stranger=await slidingSync(home,server,{...auth,user_id:'@outside:'+server},{room_subscriptions:{[room]:{timeline_limit:20}}},'');
  assert.deepEqual(Object.keys(stranger.rooms),[]);
});

test('leaving retains a bounded attachment history and forgetting removes it for that account', async () => {
  const sql = memorySql(), server = 'worker.test', owner = '@owner:'+server, guest = '@guest:'+server;
  const home = {sql, waiters:new Map(), identity:await createIdentity(),
    ctx:{storage:{transactionSync:f=>f()}}, party:async()=>({organisationId:null}), env:{}};
  schema(sql);
  const {body:{room_id:room}} = await create(home,server,owner,{room_version:'11'});
  const request = (user, method, parts, data={}, params=new URLSearchParams()) =>
    roomClient(home,server,{user_id:user,device_id:'device'},method,[room,...parts],data,params);
  const send = async label => (await request(owner,'PUT',['send','m.room.encrypted',label],{ciphertext:label})).body.event_id;
  const before = await send('before');
  await request(owner,'POST',['invite'],{user_id:guest});
  await request(guest,'POST',['join']);
  const visible = await send('shared');
  await assert.rejects(request(guest,'POST',['forget']), e => e.status===400);
  await request(guest,'POST',['leave']);
  const later = await send('after');
  const history = async () => (await request(guest,'GET',['messages'],{},new URLSearchParams({dir:'b'}))).body.chunk;
  assert.deepEqual((await history()).filter(e=>e.type==='m.room.encrypted').map(e=>e.event_id),[visible]);
  const context = (await request(guest,'GET',['context',visible])).body;
  assert.equal(context.event.content.ciphertext,'shared');
  assert.ok(![...context.events_before,...context.events_after].some(e=>e.event_id===later || e.event_id===before));
  await assert.rejects(request(guest,'GET',['event',later]), e=>e.status===404);
  await assert.rejects(request(guest,'PUT',['send','m.room.encrypted','left'],{}),e=>e.status===403);
  await request(guest,'POST',['forget']);
  await request(guest,'POST',['forget']);
  await assert.rejects(history(),e=>e.status===403);
  assert.equal((await roomSync(home,server,guest,0,false)).rooms.leave[room],undefined);
  assert.equal((await request(owner,'GET',['event',visible])).body.content.ciphertext,'shared');
  await request(owner,'POST',['invite'],{user_id:guest});
  assert.ok((await roomSync(home,server,guest,0,true)).rooms.invite[room]);
  await request(guest,'POST',['join']);
  await assert.rejects(request(guest,'GET',['event',visible]),e=>e.status===404);
  const fresh = await send('new');
  assert.equal((await request(guest,'GET',['event',fresh])).body.content.ciphertext,'new');
});

test('Cloud receipts belong to an account and one encrypted event, through leave, forget and redaction', async () => {
  const {authorizeFile,visibleReceipts,releaseReceipts} = await import('./src/cloud-references.js');
  const sql=memorySql(), server='worker.test', a='@alice:'+server, b='@bob:'+server;
  const ids=new Map([['mauvely-id/a',a],['mauvely-id/b',b]]);
  const home={sql,waiters:new Map(),identity:await createIdentity(),env:{},party:async()=>({organisationId:null}),
    ctx:{storage:{transactionSync:f=>f(),get:key=>ids.get(key)}}};
  schema(sql);
  const {body:{room_id:room}}=await create(home,server,a,{invite:[b]});
  const call=(user,method,path,data={})=>roomClient(home,server,{user_id:user},method,[room,...path],data);
  const send=async tx=>(await call(a,'PUT',['send','m.room.encrypted',tx],{ciphertext:'fixture'})).body.event_id;
  const mxc='mxc://worker.test/vault-fixture';
  const grant=(account,viewer,event,source=mxc)=>authorizeFile(home,server,account,{viewer,room,event,mxc:source});
  const before=await send('before');
  await call(b,'POST',['join']);
  assert.equal(await grant('b',b,before),null);
  const one=await send('1'), two=await send('2');
  const first=await grant('b',b,one), second=await grant('b',b,two), mine=await grant('a',a,one);
  assert.ok(first && second && mine);
  assert.equal(await grant('b',b,one),first);
  assert.equal(await grant('a',b,one),null);
  assert.equal(await grant('b',b,one,'mxc://other.example/different'),null);
  assert.notEqual(first,second);
  assert.deepEqual(await visibleReceipts(home,server,'a',[first]),[]);
  await call(b,'POST',['leave']);
  assert.equal((await visibleReceipts(home,server,'b',[first,second])).length,2);
  assert.equal(await grant('b',b,await send('after')),null);
  await call(a,'PUT',['redact',two,'remove']);
  assert.deepEqual(await visibleReceipts(home,server,'b',[second]),[]);
  assert.equal(await grant('b',b,two),null);
  await call(b,'POST',['forget']);
  assert.deepEqual(await visibleReceipts(home,server,'b',[first]),[]);
  assert.equal((await visibleReceipts(home,server,'a',[mine]))[0].mxc,mxc);
  const delivered = [];
  let online = false;
  home.mediaAccount = async (destination, viewer) => destination === server && viewer === b ? 'b' : null;
  home.env.CLOUD_MEDIA = { revokeReceipt: async (destination, account, id) => {
    if (!online) throw Error('Cloud offline');
    delivered.push({ destination, account, id });
  } };
  await releaseReceipts(home);
  assert.equal(sql.exec('SELECT count(*) AS n FROM cloud_receipt_removals WHERE attempt=1 AND due>0').one().n,2);
  online = true;
  sql.exec('UPDATE cloud_receipt_removals SET due=0');
  await releaseReceipts(home);
  await releaseReceipts(home);
  assert.deepEqual(delivered.map(d => d.id).sort(), [first,second].sort());
  assert.ok(delivered.every(d => d.account==='b' && d.destination===server));
  assert.equal(sql.exec('SELECT count(*) AS n FROM cloud_receipt_removals').one().n,0);
});
