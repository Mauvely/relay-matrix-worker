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
