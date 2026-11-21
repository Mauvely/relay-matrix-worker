// SPDX-License-Identifier: AGPL-3.0-or-later
import { peerRecord } from './discovery.js';
import { canonical, base64, signingKeyId } from './identity.js';

// In the interoperability deployment the operator pins the reference servers' keys.
// The transport destination is operator-configured separately from the canonical name.
export async function authenticatedOrigin(request, destination, peers, content) {
  const header = request.headers.get('Authorization') ?? '';
  if (!header.startsWith('X-Matrix ')) return false;
  const fields = new Map();
  for (const part of header.slice(9).split(',')) {
    const match = /^\s*([a-z]+)=(?:"([^"]*)"|([^\s",]+))\s*$/.exec(part);
    if (!match || fields.has(match[1])) return false;
    fields.set(match[1], match[2] ?? match[3]);
  }
  if (fields.get('destination') !== destination) return false;
  const origin = fields.get('origin'),
    keyId = fields.get('key'),
    sig = fields.get('sig');
  if (!origin || !keyId?.startsWith('ed25519:') || !sig) return false;
  let keys;
  try {
    keys = typeof peers === 'function' ? await peers(origin,keyId) : Object.hasOwn(peers, origin) && peers[origin];
  } catch {
    return false;
  }
  if (!keys) return false;
  if (!Object.hasOwn(keys, keyId)) return false;
  const url = new URL(request.url);
  const message = {
    method: request.method,
    uri: url.pathname + url.search,
    origin,
    destination
  };
  if (content !== undefined) message.content = content;
  try {
    const decode = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
    const key = await crypto.subtle.importKey('raw', decode(keys[keyId]), 'Ed25519', false, ['verify']);
    return (
      (await crypto.subtle.verify(
        'Ed25519',
        key,
        decode(sig),
        new TextEncoder().encode(canonical(message))
      )) && origin
    );
  } catch {
    return false;
  }
}

export async function authenticateQuery(request, destination, peers) {
  return request.method === 'GET' && Boolean(await authenticatedOrigin(request, destination, peers));
}

export async function sign(identity, text) {
  const key = await crypto.subtle.importKey('jwk', identity.privateKey, 'Ed25519', false, ['sign']);
  return base64(await crypto.subtle.sign('Ed25519', key, new TextEncoder().encode(text)));
}

export async function remote(home, origin, destination, method, uri, content) {
  const { endpoint } = await peerRecord(home, destination);
  const signed = { origin, destination, method, uri };
  if (content !== undefined) signed.content = content;
  const signature = await sign(home.identity, canonical(signed));
  const response = await fetch(endpoint + uri, {
    method,
    redirect: 'manual',
    signal: AbortSignal.timeout(15000),
    headers: {
      Authorization: `X-Matrix origin="${origin}",destination="${destination}",key="${signingKeyId(home.identity)}",sig="${signature}"`,
      'Content-Type': 'application/json'
    },
    body: content === undefined ? undefined : JSON.stringify(content)
  });
  if (!response.ok)
    throw Object.assign(Error('Federation returned HTTP ' + response.status), { federationStatus: response.status });
  return response;
}
