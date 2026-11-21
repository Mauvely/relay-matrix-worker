// SPDX-License-Identifier: AGPL-3.0-or-later
import { canonical } from "./identity.js";
import { limited } from "./media.js";

const serverName =
  /^(?=.{1,255}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]*(?::[0-9]{1,5})?$/i;
const raw = (value) => Uint8Array.from(atob(value), (c) => c.charCodeAt(0));

async function readJson(read, url) {
  const res = await read(url, {
    redirect: "manual",
    signal: AbortSignal.timeout(5000),
  });
  if (!res.ok) throw Error("Matrix discovery failed: HTTP " + res.status);
  return JSON.parse(new TextDecoder().decode(await limited(res.body, 65536)));
}

// Discover DNS names with an explicit federation port, directly or through HTTPS delegation.
// Fail closed on other discovery methods until the transport supports SRV with the correct TLS name.
export async function discoverPeer(name, read = fetch, now = Date.now()) {
  if (!serverName.test(name)) throw Error("Unsupported federation server name");
  const target = name.includes(":")
    ? name
    : (
        await readJson(read, "https://" + name + "/.well-known/matrix/server")
      )?.["m.server"];
  if (
    typeof target !== "string" ||
    !serverName.test(target) ||
    !target.includes(":")
  )
    throw Error("An explicit federation port is required");
  const endpoint = new URL("https://" + target).origin;
  const doc = await readJson(read, endpoint + "/_matrix/key/v2/server");
  if (
    doc.server_name !== name ||
    !Number.isSafeInteger(doc.valid_until_ts) ||
    doc.valid_until_ts <= now
  )
    throw Error("Invalid signing-key identity or expiry");
  const { signatures, unsigned, ...signed } = doc;
  const message = new TextEncoder().encode(canonical(signed));
  const keys = {};
  let verified = false;
  for (const [id, value] of Object.entries(doc.verify_keys ?? {})) {
    if (!/^ed25519:[A-Za-z0-9_]+$/.test(id)) continue;
    if (typeof value?.key !== "string" || raw(value.key).length !== 32)
      throw Error("Invalid Ed25519 key");
    keys[id] = value.key;
    const signature = signatures?.[name]?.[id];
    if (typeof signature !== "string") continue;
    const key = await crypto.subtle.importKey(
      "raw",
      raw(value.key),
      "Ed25519",
      false,
      ["verify"],
    );
    if (await crypto.subtle.verify("Ed25519", key, raw(signature), message))
      verified = true;
  }
  if (!verified)
    throw Error("Homeserver key document has no valid self-signature");
  return {
    endpoint,
    keys,
    expires: Math.min(doc.valid_until_ts, now + 60 * 60 * 1000),
  };
}

export async function peerRecord(home, name) {
  const { PEER_KEYS = {}, PEER_URLS = {} } = home.env;
  if (Object.hasOwn(PEER_KEYS, name) && Object.hasOwn(PEER_URLS, name))
    return { keys: PEER_KEYS[name], endpoint: PEER_URLS[name] };
  if (!home.env.DISCOVER_PEERS || !home.resolvePeer)
    throw Error("Federation peer is not configured");
  return home.resolvePeer(name);
}

export function graphKeys(home) {
  return { ...home.discoveredKeys, ...home.env.PEER_KEYS };
}
