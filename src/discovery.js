// SPDX-License-Identifier: AGPL-3.0-or-later
import { canonical } from './identity.js';
import { limited } from './media.js';

const serverName =
  /^(?=.{1,255}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]*(?::[0-9]{1,5})?$/i;
const raw = (value) => Uint8Array.from(atob(value), (c) => c.charCodeAt(0));

async function readJson(read, url) {
  const res = await read(url, {
    redirect: 'manual',
    signal: AbortSignal.timeout(5000)
  });
  if (!res.ok) throw Error('Matrix discovery failed: HTTP ' + res.status);
  return JSON.parse(new TextDecoder().decode(await limited(res.body, 65536)));
}

// Discover DNS names with an explicit federation port, directly or through HTTPS delegation.
// Fail closed on other discovery methods until the transport supports SRV with the correct TLS name.
export async function discoverPeer(name, read = fetch, now = Date.now()) {
  if (!serverName.test(name)) throw Error('Unsupported federation server name');
  const target = name.includes(':')
    ? name
    : (await readJson(read, 'https://' + name + '/.well-known/matrix/server'))?.['m.server'];
  if (typeof target !== 'string' || !serverName.test(target) || !target.includes(':'))
    throw Error('An explicit federation port is required');
  const endpoint = new URL('https://' + target).origin;
  const doc = await readJson(read, endpoint + '/_matrix/key/v2/server');
  if (doc.server_name !== name || !Number.isSafeInteger(doc.valid_until_ts) || doc.valid_until_ts <= now)
    throw Error('Invalid signing-key identity or expiry');
  const { signatures, unsigned, ...signed } = doc;
  const message = new TextEncoder().encode(canonical(signed));
  // These dictionaries cross the Durable Object RPC boundary on a cache miss.
  // IDs are validated below and always start with the algorithm prefix.
  const keys = {};
  const eventKeys = {};
  const until = Math.min(doc.valid_until_ts, now + 7 * 24 * 3600 * 1000);
  for (const [id, value] of Object.entries(doc.old_verify_keys ?? {})) {
    if (!/^ed25519:[A-Za-z0-9_]+$/.test(id)) continue;
    if (!Number.isSafeInteger(value?.expired_ts) || value.expired_ts < 0 ||
        typeof value?.key !== 'string' || raw(value.key).length !== 32) throw Error('Invalid retired key');
    eventKeys[id] = {key:value.key,until:Math.min(value.expired_ts,until)};
  }
  let verified = false;
  for (const [id, value] of Object.entries(doc.verify_keys ?? {})) {
    if (!/^ed25519:[A-Za-z0-9_]+$/.test(id)) continue;
    if (typeof value?.key !== 'string' || raw(value.key).length !== 32) throw Error('Invalid Ed25519 key');
    if (eventKeys[id]) throw Error('Duplicate active and retired key');
    keys[id] = value.key;
    eventKeys[id] = {key:value.key,until};
    const signature = signatures?.[name]?.[id];
    if (typeof signature !== 'string') continue;
    const key = await crypto.subtle.importKey('raw', raw(value.key), 'Ed25519', false, ['verify']);
    if (await crypto.subtle.verify('Ed25519', key, raw(signature), message)) verified = true;
  }
  if (!verified) throw Error('Homeserver key document has no valid self-signature');
  return {
    endpoint,
    keys,
    eventKeys,
    fetchedAt:now,
    expires: Math.min(doc.valid_until_ts, now + 60 * 60 * 1000)
  };
}

// A newer document may omit an old key entirely. Keep its bytes for historical
// events and cap its validity at the first observation of its removal.
export function mergePeerKeys(previous, fresh) {
  if (!previous) return fresh;
  const historical = previous.eventKeys ?? Object.fromEntries(
    Object.entries(previous.keys).map(([id, key]) => [id, { key, until: previous.expires }])
  );
  const eventKeys = { ...fresh.eventKeys };
  for (const [id, old] of Object.entries(historical)) {
    if (Object.hasOwn(eventKeys, id)) {
      if (eventKeys[id].key !== old.key) throw Error('Signing key ID reused');
    } else {
      eventKeys[id] = { key: old.key, until: Math.min(old.until, fresh.fetchedAt) };
    }
  }
  return { ...fresh, eventKeys };
}

export async function peerRecord(home, name, requestedKey) {
  const { PEER_KEYS = {}, PEER_URLS = {} } = home.env;
  if (Object.hasOwn(PEER_KEYS, name) && Object.hasOwn(PEER_URLS, name))
    return { keys: PEER_KEYS[name], endpoint: PEER_URLS[name] };
  if (!home.env.DISCOVER_PEERS || !home.resolvePeer) throw Error('Federation peer is not configured');
  return home.resolvePeer(name, requestedKey);
}

// The transaction sender may be forwarding a PDU signed by a different
// homeserver. Refresh that author's document when none of its keys are known.
export async function keysForEvent(home, author, event) {
  const signatures = Object.keys(event.signatures?.[author] ?? {}).filter(id => /^ed25519:[A-Za-z0-9_]+$/.test(id));
  const known = home.env.PEER_KEYS?.[author] ?? home.discoveredKeys?.[author];
  if (known && signatures.some(id => Object.hasOwn(known, id) &&
      (typeof known[id] === 'string' || event.origin_server_ts <= known[id].until))) return known;
  const record = await peerRecord(home, author, signatures[0]);
  return record.eventKeys ?? home.discoveredKeys?.[author] ?? record.keys;
}

export function graphKeys(home) {
  return { ...home.discoveredKeys, ...home.env.PEER_KEYS };
}
