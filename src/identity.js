// SPDX-License-Identifier: AGPL-3.0-or-later
// Matrix canonical JSON sorts Unicode keys by scalar value.
function compareKeys(a, b) {
  const left = Array.from(a),
    right = Array.from(b);
  for (let i = 0; i < Math.min(left.length, right.length); i++) {
    const difference = left[i].codePointAt(0) - right[i].codePointAt(0);
    if (difference) return difference;
  }
  return left.length - right.length;
}
export function canonical(value) {
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  if (value !== null && typeof value === 'object') {
    return (
      '{' +
      Object.keys(value)
        .sort(compareKeys)
        .map((key) => JSON.stringify(key) + ':' + canonical(value[key]))
        .join(',') +
      '}'
    );
  }
  return JSON.stringify(value);
}

export function base64(bytes) {
  return btoa(String.fromCharCode(...new Uint8Array(bytes))).replace(/=+$/, '');
}

export async function createIdentity() {
  const pair = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);
  return {
    privateKey: await crypto.subtle.exportKey('jwk', pair.privateKey),
    publicKey: base64(await crypto.subtle.exportKey('raw', pair.publicKey))
  };
}

// Older tenants stored only the key pair and used the initial key ID.
export const signingKeyId = (identity) => identity.keyId ?? 'ed25519:1';
export const verificationKeys = (identity) => ({ [signingKeyId(identity)]: identity.publicKey });

export async function initializeIdentity(storage, restoring, signingFile) {
  const slot = 'ed25519:1';
  const current = await storage.get(slot);
  if (!restoring || !signingFile) {
    if (current) return current;
    if (restoring) throw Error('Signing identity is missing for the designated server');
    const fresh = await createIdentity();
    await storage.put(slot, fresh);
    return fresh;
  }
  // Synapse's signing file stores an unpadded base64 Ed25519 seed.
  const line = /^ed25519[ \t]+([a-zA-Z0-9_]+)[ \t]+([A-Za-z0-9+/]{43}=?)$/.exec(signingFile.trim());
  if (!line) throw Error('Expected a single Synapse Ed25519 signing key');
  const seed = Uint8Array.from(atob(line[2]), (c) => c.charCodeAt(0));
  // RFC 8410 PKCS#8 PrivateKeyInfo for a 32-byte Ed25519 private key.
  const pkcs8 = Uint8Array.from([0x30, 46, 2, 1, 0, 0x30, 5, 6, 3, 0x2b, 0x65, 0x70, 4, 34, 4, 32, ...seed]);
  const key = await crypto.subtle.importKey('pkcs8', pkcs8, 'Ed25519', true, ['sign']);
  const privateKey = await crypto.subtle.exportKey('jwk', key);
  const publicKey = privateKey.x.replace(/-/g, '+').replace(/_/g, '/');
  const keyId = 'ed25519:' + line[1];
  if (current) {
    if (current.publicKey !== publicKey || signingKeyId(current) !== keyId)
      throw Error('The supplied signing identity conflicts with the stored identity');
    return current;
  }
  const identity = { keyId, privateKey, publicKey };
  await storage.put(slot, identity);
  return identity;
}

export async function signServerKeys(serverName, identity, now = Date.now()) {
  const id = signingKeyId(identity);
  const body = {
    server_name: serverName,
    valid_until_ts: now + 86400000,
    verify_keys: { [id]: { key: identity.publicKey } },
    old_verify_keys: {}
  };
  const privateKey = await crypto.subtle.importKey('jwk', identity.privateKey, 'Ed25519', false, ['sign']);
  const signature = await crypto.subtle.sign(
    'Ed25519',
    privateKey,
    new TextEncoder().encode(canonical(body))
  );
  return { ...body, signatures: { [serverName]: { [id]: base64(signature) } } };
}
