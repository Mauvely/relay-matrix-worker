// SPDX-License-Identifier: AGPL-3.0-or-later
import { remote, authenticatedOrigin } from './federation.js';

export const mediaLimit = 1024 * 1024;
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
export async function mediaRoute(request, env, server, home, path, json) {
  const fed = /^\/_matrix\/federation\/v1\/media\/download\/([^/]+)$/.exec(path);
  const client =
    /^\/_matrix\/(?:media\/(?:v3|r0)|client\/v1\/media)\/(config|upload|download)(?:\/([^/]+)\/([^/]+)(?:\/[^/]*)?)?$/.exec(
      path
    );
  if (!fed && !client) return;
  if (fed) {
    if (request.method !== 'GET' || !(await authenticatedOrigin(request, server, env.PEER_KEYS ?? {})))
      return json({ errcode: 'M_UNAUTHORIZED', error: 'Signed media request required' }, 401);
    const m = await home.mediaRead(fed[1]);
    if (!m) return json({ errcode: 'M_NOT_FOUND', error: 'Unknown media' }, 404);
    const boundary = crypto.randomUUID();
    return new Response(packMedia(m.body, m.type, boundary), {
      headers: { 'Content-Type': 'multipart/mixed; boundary=' + boundary }
    });
  }
  const auth = await home.session(request.headers.get('Authorization'), false);
  if (auth.status !== 200) return json(auth.body, auth.status);
  if (client[1] === 'config' && request.method === 'GET') return json({ 'm.upload.size': mediaLimit });
  if (client[1] === 'upload' && request.method === 'POST') {
    let buffer;
    try {
      buffer = await limited(request.body, mediaLimit);
    } catch {
      return json({ errcode: 'M_TOO_LARGE', error: 'Spike upload limit is 1 MiB' }, 413);
    }
    const allowed = await home.mediaAllowed(server, auth.body.user_id);
    if (!allowed) return json({ errcode: 'M_FORBIDDEN', error: 'This account cannot share media' }, 403);
    return json({
      content_uri:
        'mxc://' +
        server +
        '/' +
        (await home.mediaWrite(buffer, request.headers.get('Content-Type') ?? 'application/octet-stream'))
    });
  }
  if (client[1] === 'download' && request.method === 'GET' && client[3]) {
    const peer = decodeURIComponent(client[2]),
      id = decodeURIComponent(client[3]);
    let m;
    if (server === peer) m = await home.mediaRead(id);
    else {
      if (!(await home.mediaAllowed(server, auth.body.user_id)))
        return json({ errcode: 'M_FORBIDDEN', error: 'This account cannot access remote media' }, 403);
      try {
        m = await home.mediaRemote(server, peer, id);
      } catch {
        return json({ errcode: 'M_NOT_FOUND', error: 'Remote media unavailable' }, 404);
      }
    }
    if (!m) return json({ errcode: 'M_NOT_FOUND', error: 'Unknown media' }, 404);
    return new Response(m.body, { headers: { ...rawHeaders, 'Content-Type': 'application/octet-stream' } });
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
  return unpackMedia(await limited(r.body, mediaLimit + 32768), r.headers.get('Content-Type') ?? '');
}
