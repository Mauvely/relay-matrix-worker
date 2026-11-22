import assert from 'node:assert/strict';
import test from 'node:test';
import { packMedia, unpackMedia } from './src/media.js';
test('federation media keeps ciphertext byte-exact with a MIME preamble', async () => {
  const data = Uint8Array.from({ length: 256 }, (_, i) => i),
    boundary = 'test-boundary';
  const mixed = packMedia(data, 'application/octet-stream', boundary);
  for (const prefix of ['', '\r\n']) {
    const response = await new Blob([prefix, mixed]).arrayBuffer();
    assert.deepEqual(
      new Uint8Array(unpackMedia(response, 'multipart/mixed; boundary=' + boundary).body),
      data
    );
  }
});

test('hosted media uses the authenticated payer and downloads from the origin namespace', async () => {
  const {mediaRoute} = await import('./src/media.js');
  const server = 'host.test', user = '@alice:host.test';
  const buffer = new Uint8Array(1050000).fill(37);
  const home = {
    session: async () => ({status:200,body:{user_id:user}}),
    mediaAccount: async (s,u) => { assert.equal(s,server); assert.equal(u,user); return 'account-a'; },
    mediaAllowed: async () => true,
    mediaWrite: () => assert.fail('A managed upload must be billed')
  };
  const objects = new Map();
  const env = {CLOUD_MEDIA:{
    write: async (s,id,payer,type,body) => {
      assert.equal(payer,'account-a'); objects.set(s+'/'+id,{type,body}); return 201;
    },
    read: async (s,id) => objects.get(s+'/'+id)
  }};
  const json = (body,status=200) => Response.json(body,{status});
  const call = (path,init) => mediaRoute(new Request('https://host.test'+path,init),env,server,home,path,json);
  const upload = '/_matrix/media/v3/upload';
  assert.equal((await (await call('/_matrix/media/v3/config')).json())['m.upload.size'],16*1024*1024);
  const res = await call(upload,{method:'POST',body:buffer});
  const url = new URL((await res.json()).content_uri);
  assert.equal(url.host,server);
  const download = await call('/_matrix/client/v1/media/download/host.test'+url.pathname);
  assert.deepEqual(new Uint8Array(await download.arrayBuffer()),buffer);
  env.CLOUD_MEDIA.write = async () => 507;
  assert.equal((await call(upload,{method:'POST',body:'quota'})).status,507);
  delete env.CLOUD_MEDIA;
  assert.equal((await call(upload,{method:'POST',body:'no storage binding'})).status,503);
});

test('a hosted account publishes an existing revision and downloads its ciphertext', async () => {
  const {mediaRoute} = await import('./src/media.js');
  const server = 'home.test', owner = '@owner:home.test';
  const source = new Uint8Array([0, 255, 7]);
  const path = '/_matrix/client/unstable/com.mauvely.cloud/publish';
  const home = {session:async()=>({status:200,body:{user_id:owner}}),
    mediaAccount:async()=> 'account-owner', mediaAllowed:async()=>true};
  const env = {CLOUD_MEDIA:{
    publishRevision: async (...args) => {
      assert.deepEqual(args,[server,'account-owner','nod_known','rev_known']);
      return 'first';
    },
    readRevision: async (origin,id) => {
      assert.equal(origin,server);
      assert.equal(id,'first');
      return {type:'application/octet-stream',length:3,body:new Blob([source]).stream()};
    }
  }};
  const route = (path, init) => mediaRoute(new Request('https://home.test'+path,init),env,server,home,path,
    (data,status=200)=>Response.json(data,{status}));
  const init={method:'POST',body:JSON.stringify({nodeId:'nod_known',revisionId:'rev_known'})};
  assert.deepEqual(await (await route(path,init)).json(), {content_uri:'mxc://home.test/vault-first'});
  const get = await route('/_matrix/client/v1/media/download/home.test/vault-first');
  assert.deepEqual(new Uint8Array(await get.arrayBuffer()),source);
  home.mediaAllowed=async()=>false;
  assert.equal((await route(path,init)).status,403);
  home.mediaAccount=async()=>null;
  assert.equal((await route(path,init)).status,403);
});
