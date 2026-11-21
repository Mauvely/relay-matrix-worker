// SPDX-License-Identifier: AGPL-3.0-or-later
import { remote, authenticatedOrigin } from './federation.js';

export const mediaLimit = 1024 * 1024;
const hostedLimit = 16 * mediaLimit;
const rawHeaders = {
  'Access-Control-Allow-Origin': '*',
  'X-Content-Type-Options': 'nosniff',
  'Content-Disposition': 'attachment',
  'Cache-Control': 'private, no-store'
};
export function mediaSchema(sql) {
  sql.exec('CREATE TABLE IF NOT EXISTS media(id TEXT PRIMARY KEY,body BLOB NOT NULL,type TEXT NOT NULL)');
}
export function packMedia(bytes, type, boundary) {
  const safeType = /^[a-zA-Z0-9.+-]+\/[a-zA-Z0-9.+-]+$/.test(type) ? type : 'application/octet-stream';
  return new Blob([
    '--' +
      boundary +
      '\r\nContent-Type: application/json\r\n\r\n{}\r\n--' +
      boundary +
      '\r\nContent-Type: ' +
      safeType +
      '\r\n\r\n',
    bytes,
    '\r\n--' + boundary + '--\r\n'
  ]);
}
export function unpackMedia(buffer, type) {
  const boundary = /(?:^|;)\s*boundary=(?:"([^"]+)"|([^;\s]+))/i.exec(type);
  if (!boundary) throw Error('Missing media boundary');
  const marker = boundary[1] ?? boundary[2];
  // One code unit per byte, so offsets also index the original ciphertext.
  const raw = new TextDecoder('iso-8859-1').decode(buffer);
  const first = raw.indexOf('--' + marker + '\r\n');
  if (first < 0) throw Error('Missing metadata boundary');
  const part = raw.indexOf('\r\n--' + marker + '\r\n', first + marker.length + 4);
  if (part === -1) throw Error('Missing media part');
  const start = raw.indexOf('\r\n\r\n', part + marker.length + 6),
    end = raw.indexOf('\r\n--' + marker + '--', start + 4);
  if (start < 0 || end < start + 4) throw Error('Malformed media');
  const mime =
    /\r\nContent-Type:\s*([^;\r\n]+)/i.exec(raw.slice(part, start))?.[1] ?? 'application/octet-stream';
  return { body: buffer.slice(start + 4, end), type: mime };
}
export async function limited(stream, limit) {
  const reader = stream?.getReader();
  if (!reader) return new ArrayBuffer(0);
  const chunks = [];
  let size = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.length;
    if (size > limit) {
      await reader.cancel();
      throw Error('Too large');
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.length;
  }
  return bytes.buffer;
}
async function readLocal(env, home, server, id) {
  if (!id.startsWith('cloud-')) return home.mediaRead(id);
  if (!env.CLOUD_MEDIA) throw Error('Hosted media storage unavailable');
  return env.CLOUD_MEDIA.read(server, id.slice(6));
}

export async function mediaRoute(request, env, server, home, path, json) {
  const fed = /^\/_matrix\/federation\/v1\/media\/download\/([^/]+)$/.exec(path);
  const client =
    /^\/_matrix\/(?:media\/(?:v3|r0)|client\/v1\/media)\/(config|upload|download|thumbnail)(?:\/([^/]+)\/([^/]+)(?:\/[^/]*)?)?$/.exec(
      path
    );
  if (!fed && !client) return;
  if (fed) {
    if (
      request.method !== 'GET' ||
      !(await authenticatedOrigin(request, server, async (name, key) => (await home.resolvePeer(name, key)).keys))
    )
      return json({ errcode: 'M_UNAUTHORIZED', error: 'Signed media request required' }, 401);
    const m = await readLocal(env, home, server, fed[1]);
    if (!m) return json({ errcode: 'M_NOT_FOUND', error: 'Unknown media' }, 404);
    const boundary = crypto.randomUUID();
    return new Response(packMedia(m.body, m.type, boundary), {
      headers: { 'Content-Type': 'multipart/mixed; boundary=' + boundary }
    });
  }
  const auth = await home.session(request.headers.get('Authorization'), false);
  if (auth.status !== 200) return json(auth.body, auth.status);
  if (client[1] === 'config' || client[1] === 'upload') {
    const payer = await home.mediaAccount(server, auth.body.user_id);
    const limit = payer ? hostedLimit : mediaLimit;
    if (payer && !env.CLOUD_MEDIA)
      return json({errcode:'M_UNAVAILABLE',error:'Hosted media storage unavailable'},503);
    if (client[1] === 'config' && request.method === 'GET') return json({'m.upload.size':limit});
    if (client[1] === 'upload' && request.method === 'POST') {
      if (!(await home.mediaAllowed(server, auth.body.user_id)))
        return json({errcode:'M_FORBIDDEN',error:'This account cannot share media'},403);
      let buffer;
      try {
        buffer = await limited(request.body, limit);
      } catch {
        return json({errcode:'M_TOO_LARGE',error:'Attachment exceeds the media size limit'},413);
      }
      const mime = request.headers.get('Content-Type') ?? 'application/octet-stream';
      let id;
      if (payer) {
        const key = crypto.randomUUID();
        let status;
        try {
          status = await env.CLOUD_MEDIA.write(server,key,payer,mime,buffer);
        } catch {
          return json({errcode:'M_UNAVAILABLE',error:'Attachment storage unavailable'},503);
        }
        if (status === 507) return json({errcode:'M_RESOURCE_LIMIT_EXCEEDED',error:'Cloud storage is full'},507);
        if (status !== 201 && status !== 200)
          return json({errcode:'M_UNAVAILABLE',error:'Attachment could not be stored'},503);
        id = 'cloud-' + key;
      } else {
        id = await home.mediaWrite(buffer,mime);
      }
      return json({content_uri:'mxc://' + server + '/' + id});
    }
  }
  if (['download','thumbnail'].includes(client[1]) && request.method === 'GET' && client[3]) {
    const peer = decodeURIComponent(client[2]),
      id = decodeURIComponent(client[3]);
    let m;
    if (server === peer) m = await readLocal(env, home, server, id);
    else {
      if (!(await home.mediaAllowed(server, auth.body.user_id)))
        return json(
          {
            errcode: 'M_FORBIDDEN',
            error: 'This account cannot access remote media'
          },
          403
        );
      try {
        m = await home.mediaRemote(server, peer, id);
      } catch {
        return json({ errcode: 'M_NOT_FOUND', error: 'Remote media unavailable' }, 404);
      }
    }
    if (!m) return json({ errcode: 'M_NOT_FOUND', error: 'Unknown media' }, 404);
    const image = ['image/png','image/jpeg','image/webp','image/gif','image/avif'].includes(m.type);
    if (client[1] === 'thumbnail' && !image) return json({errcode:'M_NOT_FOUND',error:'No thumbnail'},404);
    return new Response(m.body, {
      headers: { ...rawHeaders, 'Content-Type': image ? m.type : 'application/octet-stream' }
    });
  }
  return json({ errcode: 'M_UNRECOGNIZED', error: 'Unknown media method' }, 405);
}
export async function getRemote(home, server, peer, id) {
  const r = await remote(
    home,
    server,
    peer,
    'GET',
    '/_matrix/federation/v1/media/download/' + encodeURIComponent(id)
  );
  return unpackMedia(await limited(r.body, hostedLimit + 32768), r.headers.get('Content-Type') ?? '');
}
