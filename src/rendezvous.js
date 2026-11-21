// SPDX-License-Identifier: AGPL-3.0-or-later
import { limited } from './media.js';
import { secret, digest } from './accounts.js';

const path = '/_matrix/client/unstable/org.matrix.msc4108/rendezvous';
export function rendezvousSchema(sql) {
  sql.exec(
    'CREATE TABLE IF NOT EXISTS rendezvous(id TEXT PRIMARY KEY,data TEXT,etag TEXT,modified INTEGER,expires INTEGER); CREATE INDEX IF NOT EXISTS rendezvous_expiry ON rendezvous(expires)'
  );
}
export async function exchange(sql, method, id, data, tag) {
  const now = Date.now(),
    key = await digest(id);
  sql.exec('DELETE FROM rendezvous WHERE expires<=?', now);
  if (method === 'POST') {
    if (sql.exec('SELECT COUNT(*) AS n FROM rendezvous').one().n >= 2048) return { status: 429 };
    sql.exec('INSERT INTO rendezvous VALUES(?,?,?,?,?)', key, data, '"1"', now, now + 600000);
  }
  let r = sql.exec('SELECT etag,modified,expires,data FROM rendezvous WHERE id=?', key).toArray()[0];
  if (!r) return { status: 404 };
  if (method === 'DELETE') {
    sql.exec('DELETE FROM rendezvous WHERE id=?', key);
    return { status: 204 };
  }
  let status = method === 'POST' ? 201 : 200;
  if (method === 'PUT') {
    if (r.etag !== tag) status = 412;
    else {
      r.etag = '"' + (Number(r.etag.slice(1, -1)) + 1) + '"';
      r.modified = now;
      sql.exec('UPDATE rendezvous SET data=?,etag=?,modified=? WHERE id=?', data, r.etag, now, key);
    }
  }
  if (method === 'GET' && tag === r.etag) status = 304;
  return {
    status,
    etag: r.etag,
    modified: r.modified,
    expires: r.expires,
    data: method === 'GET' && status === 200 ? r.data : undefined
  };
}
export async function rendezvousRoute(req, home) {
  const url = new URL(req.url);
  if (url.pathname !== path && !url.pathname.startsWith(path + '/')) return null;
  const method = req.method,
    creating = method === 'POST';
  const id = creating ? secret() : url.pathname.slice(path.length + 1);
  if (
    (creating && url.pathname !== path) ||
    !['GET', 'PUT', 'POST', 'DELETE'].includes(method) ||
    !/^[a-f0-9]{64}$/.test(id)
  )
    return new Response(null, { status: 404 });
  let data = '';
  if (creating || method === 'PUT') {
    if ((req.headers.get('Content-Type') ?? '').split(';')[0] !== 'text/plain')
      return new Response(null, { status: 415 });
    try {
      data = new TextDecoder('utf-8', { fatal: true }).decode(await limited(req.body, 65536));
    } catch {
      return new Response(null, { status: 413 });
    }
  }
  const r = await home.rendezvous(
    method,
    id,
    data,
    req.headers.get(method === 'GET' ? 'If-None-Match' : 'If-Match')
  );
  const headers = {
    'Cache-Control': 'no-store',
    'Referrer-Policy': 'no-referrer',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Expose-Headers': 'ETag, Expires, Last-Modified, Location',
    'Content-Type': creating ? 'application/json' : 'text/plain',
    'X-Content-Type-Options': 'nosniff'
  };
  if (r.etag)
    Object.assign(headers, {
      ETag: r.etag,
      Expires: new Date(r.expires).toUTCString(),
      'Last-Modified': new Date(r.modified).toUTCString()
    });
  const address = url.origin + path + '/' + id;
  if (creating && r.status === 201) headers.Location = address;
  return new Response(creating && r.status === 201 ? JSON.stringify({ url: address }) : (r.data ?? null), {
    status: r.status,
    headers
  });
}
