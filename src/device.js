// SPDX-License-Identifier: AGPL-3.0-or-later
import { domain } from './graph.js';
import { matrixError } from './accounts.js';

export function canShare(a, b, policies) {
  function accepts(recipient, sender) {
    if (recipient.organisationId === null) return true;
    if (!Object.hasOwn(policies, recipient.organisationId)) throw Error('Organisation policy unavailable');
    const rules = policies[recipient.organisationId];
    if (!['open', 'allowlist', 'closed'].includes(rules?.policy)) throw Error('Unknown organisation policy');
    if (rules.policy === 'allowlist' && !Array.isArray(rules.allow)) throw Error('Partner list unavailable');
    if (rules.policy === 'open') return true;
    if (!sender.managed || !recipient.managed) return false;
    return (
      recipient.organisationId === sender.organisationId ||
      (rules.policy === 'allowlist' && rules.allow.includes(sender.organisationId))
    );
  }
  const left = accepts(a, b),
    right = accepts(b, a);
  return left && right;
}

async function lookup(env, user) {
  const domain = /^@[^:]+:(.+)$/.exec(user)?.[1];
  if (!domain) throw Error('Invalid Matrix ID');
  if (!Object.values(env.DOMAINS).includes(domain)) return { managed: false, organisationId: null };
  const account = await env.HOMESERVERS.getByName(domain).party(user, domain);
  if (!account) throw Error('Unprovisioned account');
  return { managed: true, organisationId: account.organisationId, domain };
}

export async function deliver(request, env, server, kind, txn) {
  const home = env.HOMESERVERS.getByName(server);
  const auth = await home.session(request.headers.get('Authorization'), false);
  if (auth.status !== 200) return auth;
  if (!txn || !kind || txn.length > 255 || kind.length > 255)
    return matrixError(400, 'M_INVALID_PARAM', 'Invalid transaction');
  const device = auth.body;
  const txKey = JSON.stringify([device.user_id, device.device_id, kind, txn]);
  if (await home.completed(txKey)) return { status: 200, body: {} };
  let data;
  try {
    data = await request.json();
  } catch {
    return matrixError(400, 'M_BAD_JSON', 'Invalid JSON');
  }
  if (!object(data?.messages) || JSON.stringify(data.messages).length > 65536)
    return matrixError(400, 'M_BAD_JSON', 'Expected bounded device messages');
  const stored = await home.transactionBody(txKey, data.messages);
  const deliveries = [];
  const remotes = new Map();
  try {
    const from = await lookup(env, device.user_id);
    for (const [user, targets] of Object.entries(stored)) {
      if (!object(targets)) return matrixError(400, 'M_BAD_JSON', 'Invalid recipient devices');
      const to = await lookup(env, user);
      if (!canShare(from, to, env.ORGANISATIONS ?? {}))
        return matrixError(403, 'M_FORBIDDEN', 'The two organisations do not both permit contact');
      if (!to.managed) {
        const peer = domain(user);
        if (!env.PEER_URLS?.[peer] || !env.PEER_KEYS?.[peer])
          return matrixError(503, 'M_UNAVAILABLE', 'Unknown peer');
        if (!remotes.has(peer)) remotes.set(peer, Object.create(null));
        remotes.get(peer)[user] = targets;
      }
      for (const [id, content] of Object.entries(targets)) {
        if (!id || id.length > 255 || !object(content))
          return matrixError(400, 'M_BAD_JSON', 'Invalid device content');
        if (to.managed) deliveries.push({ domain: to.domain, user, id, content });
      }
    }
  } catch {
    return matrixError(503, 'M_UNAVAILABLE', 'Could not establish recipient policy');
  }
  for (const { domain, user, id, content } of deliveries)
    await env.HOMESERVERS.getByName(domain).enqueue(txKey, user, id, device.user_id, kind, content);
  await home.finishDevice(txKey, server, device.user_id, kind, JSON.parse(JSON.stringify([...remotes])));
  return { status: 200, body: {} };
}

function object(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

export async function syncDevices(request, env, server) {
  const home = env.HOMESERVERS.getByName(server);
  const auth = await home.session(request.headers.get('Authorization'), false);
  if (auth.status !== 200) return auth;
  const params = new URL(request.url).searchParams,
    since = params.get('since') ?? 'd0';
  const match = /^d(\d{1,15})(?:r(\d{1,15})a(\d{1,15})(?:k(\d{1,15})(?:i(\d{1,15}))?)?)?$/.exec(since);
  if (!match) return matrixError(400, 'M_INVALID_PARAM', 'Invalid sync token');
  const { user_id: user, device_id: device } = auth.body;
  const cursor = Number(match[1]),
    roomCursor = Number(match[2] ?? 0),
    accountCursor = Number(match[3] ?? 0);
  const initial = !params.has('since') || !match[2] || params.get('full_state') === 'true';
  if (params.has('since')) await home.acknowledge(user, device, cursor);
  let rows, room, account, keys, invites;
  const read = async () => {
    [invites, keys, rows, room, account] = await Promise.all([
      home.inviteUpdates(user, Number(match[5] ?? 0), initial),
      home.cryptoUpdates(user, device, Number(match[4] ?? 0)),
      home.pending(user, device, cursor),
      home.roomUpdates(server, user, roomCursor, initial),
      home.userUpdates(user, accountCursor)
    ]);
  };
  try {
    await read();
    if (
      !initial &&
      !rows.length &&
      room.high === roomCursor &&
      !account.events.length &&
      !keys.changed.length &&
      !Object.keys(invites.rooms).length
    ) {
      const timeout = Math.min(Number(params.get('timeout')) || 0, 2500);
      if (timeout > 0) {
        await home.waitForDevice(user, device, cursor, timeout);
        await read();
      }
    }
  } catch {
    return matrixError(503, 'M_UNAVAILABLE', 'Room state or organisation policy unavailable');
  }
  const events = [];
  try {
    const recipient = await lookup(env, user),
      parties = new Map();
    for (const row of rows) {
      if (!parties.has(row.sender)) parties.set(row.sender, await lookup(env, row.sender));
      if (canShare(parties.get(row.sender), recipient, env.ORGANISATIONS ?? {}))
        events.push({ sender: row.sender, type: row.kind, content: JSON.parse(row.content) });
    }
  } catch {
    return matrixError(503, 'M_UNAVAILABLE', 'Could not establish delivery policy');
  }
  return {
    status: 200,
    body: {
      next_batch:
        'd' +
        (rows.at(-1)?.sequence ?? cursor) +
        'r' +
        room.high +
        'a' +
        account.high +
        'k' +
        keys.high +
        'i' +
        invites.high,
      device_one_time_keys_count: keys.counts,
      device_unused_fallback_key_types: keys.fallback,
      rooms: { ...room.rooms, invite: { ...room.rooms.invite, ...invites.rooms } },
      account_data: { events: account.events },
      device_lists: { changed: [...new Set([...room.changed, ...keys.changed])], left: [] },
      to_device: { events }
    }
  };
}
