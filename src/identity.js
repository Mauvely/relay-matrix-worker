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

export async function signServerKeys(serverName, identity, now = Date.now()) {
  const id = 'ed25519:1';
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
