// SPDX-License-Identifier: AGPL-3.0-or-later
import { canonical } from './identity.js';

// In the interoperability deployment the operator pins the reference servers' keys.
// Only the signed GET routes are accepted until outbound key discovery is implemented.
export async function authenticateQuery(request, destination, peers) {
  const header = request.headers.get('Authorization') ?? '';
  if (!header.startsWith('X-Matrix ')) return false;
  const fields = new Map();
  for (const part of header.slice(9).split(',')) {
    const match = /^\s*([a-z]+)=(?:"([^"]*)"|([^\s",]+))\s*$/.exec(part);
    if (!match || fields.has(match[1])) return false;
    fields.set(match[1], match[2] ?? match[3]);
  }
  if (fields.get('destination') !== destination || request.method !== 'GET') return false;
  const origin = fields.get('origin'),
    keyId = fields.get('key'),
    sig = fields.get('sig');
  if (!origin || !keyId?.startsWith('ed25519:') || !sig || !Object.hasOwn(peers, origin)) return false;
  const keys = peers[origin];
  if (!Object.hasOwn(keys, keyId)) return false;
  const url = new URL(request.url);
  const message = { method: request.method, uri: url.pathname + url.search, origin, destination };
  try {
    const decode = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
    const key = await crypto.subtle.importKey('raw', decode(keys[keyId]), 'Ed25519', false, ['verify']);
    return crypto.subtle.verify('Ed25519', key, decode(sig), new TextEncoder().encode(canonical(message)));
  } catch {
    return false;
  }
}
