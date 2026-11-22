// SPDX-License-Identifier: AGPL-3.0-or-later
import { digest, matrixError } from './accounts.js';
import { domain } from './graph.js';
import { deviceRemoved } from './keys.js';

export function sessionSchema(sql) {
  sql.exec(
    'CREATE TABLE IF NOT EXISTS legacy_device_tokens(hash TEXT PRIMARY KEY,user TEXT,device TEXT); CREATE INDEX IF NOT EXISTS tokens_by_device ON legacy_device_tokens(user,device); CREATE INDEX IF NOT EXISTS oauth_by_device ON oauth_sessions(user,device); CREATE INDEX IF NOT EXISTS oauth_expiry ON oauth_sessions(renew)'
  );
}

// Called inside the same storage transaction that authenticates the logout.
function removeDevice(home, user, device) {
  const { sql } = home;
  for (const { hash } of sql.exec(
    'SELECT hash FROM legacy_device_tokens WHERE user=? AND device=?',
    user,
    device
  ))
    home.ctx.storage.kv.delete('session/' + hash);
  for (const table of [
    'pushers',
    'legacy_device_tokens',
    'oauth_sessions',
    'devices',
    'device_keys',
    'otk',
    'delivery',
    'sliding_positions',
    'sliding_device_cursors'
  ])
    sql.exec('DELETE FROM ' + table + ' WHERE user=? AND device=?', user, device);
  sql.exec('DELETE FROM key_signatures WHERE target=? AND id=?', user, device);
  deviceRemoved(home, domain(user), user, device);
}

export function reconcileSessions(home) {
  const storage = home.ctx.storage;
  if (storage.kv.get('schema/device-sessions-v1')) return;
  // Previous versions stored classic login tokens only in KV. Index every live token
  // before considering a device orphaned. An expired access token can still be refreshed.
  storage.transactionSync(() => {
    let after;
    do {
      const batch = [
        ...storage.kv.list({ prefix: 'session/', limit: 256, ...(after ? { startAfter: after } : {}) })
      ];
      for (const [key, value] of batch)
        home.sql.exec(
          'INSERT OR IGNORE INTO legacy_device_tokens VALUES(?,?,?)',
          key.slice(8),
          value.user_id,
          value.device_id
        );
      after = batch.length === 256 ? batch.at(-1)[0] : null;
    } while (after);
    const orphaned = home.sql
      .exec(
        `SELECT user,device FROM devices d
      WHERE NOT EXISTS (SELECT 1 FROM legacy_device_tokens t WHERE t.user=d.user AND t.device=d.device)
      AND NOT EXISTS (SELECT 1 FROM oauth_sessions s WHERE s.user=d.user AND s.device=d.device AND s.renew>?)`,
        Date.now()
      )
      .toArray();
    for (const { user, device } of orphaned) removeDevice(home, user, device);
    storage.kv.put('schema/device-sessions-v1', true);
  });
}

export async function logoutSession(home, authorization) {
  const token = /^Bearer ([a-f0-9]{64})$/i.exec(authorization ?? '')?.[1];
  if (!token) return matrixError(401, 'M_MISSING_TOKEN', 'A bearer token is required');
  const hash = await digest(token);
  return home.ctx.storage.transactionSync(() => {
    const legacy = home.ctx.storage.kv.get('session/' + hash);
    const session = legacy
      ? { user: legacy.user_id, device: legacy.device_id }
      : home.sql
          .exec(
            'SELECT user,device FROM oauth_sessions WHERE access=? AND expires>? AND renew>?',
            hash,
            Date.now(),
            Date.now()
          )
          .toArray()[0];
    if (!session) return matrixError(401, 'M_UNKNOWN_TOKEN', 'Unknown access token');
    removeDevice(home, session.user, session.device);
    return { status: 200, body: {} };
  });
}

// Revocation is idempotent and bound to the OAuth client that issued the token.
export function revokeOAuthSession(home, hash, client) {
  home.ctx.storage.transactionSync(() => {
    const session = home.sql
      .exec(
        'SELECT user,device FROM oauth_sessions WHERE (access=? OR refresh=?) AND client=?',
        hash,
        hash,
        client
      )
      .toArray()[0];
    if (session) removeDevice(home, session.user, session.device);
  });
}

export function expireOAuthSessions(home, now) {
  home.ctx.storage.transactionSync(() => {
    for (const { user, device, access } of home.sql
      .exec('SELECT user,device,access FROM oauth_sessions WHERE renew<=? LIMIT 32', now)
      .toArray()) {
      home.sql.exec('DELETE FROM oauth_sessions WHERE access=?', access);
      if (
        !home.sql
          .exec(
            'SELECT 1 FROM legacy_device_tokens WHERE user=? AND device=? UNION ALL SELECT 1 FROM oauth_sessions WHERE user=? AND device=? LIMIT 1',
            user,
            device,
            user,
            device
          )
          .toArray().length
      )
        removeDevice(home, user, device);
    }
  });
}
