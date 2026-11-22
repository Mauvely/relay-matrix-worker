// SPDX-License-Identifier: AGPL-3.0-or-later
import { checkParties, historyWindow, load, openParty } from './rooms.js';

// The descriptor, name and keys live in the viewer's encrypted vault. Each receipt names
// one send, for one viewer, and only ever grants the standard Matrix media representation.
export function referenceSchema(sql) {
  sql.exec(`CREATE TABLE IF NOT EXISTS cloud_file_receipts (
    id TEXT PRIMARY KEY, user TEXT NOT NULL, room TEXT NOT NULL, event TEXT NOT NULL, mxc TEXT NOT NULL,
    UNIQUE(user,room,event));
    CREATE INDEX IF NOT EXISTS cloud_receipt_event ON cloud_file_receipts(room,event);
    CREATE TABLE IF NOT EXISTS cloud_receipt_removals(id TEXT PRIMARY KEY,user TEXT NOT NULL,due INTEGER NOT NULL DEFAULT 0,attempt INTEGER NOT NULL DEFAULT 0);
    CREATE INDEX IF NOT EXISTS cloud_receipt_removals_due ON cloud_receipt_removals(due);
    CREATE TRIGGER IF NOT EXISTS cloud_receipt_removed AFTER DELETE ON cloud_file_receipts BEGIN
      INSERT OR IGNORE INTO cloud_receipt_removals(id,user) VALUES(OLD.id,OLD.user);
    END;`);
}

export async function authorizeFile(home, server, account, { viewer, room, event, mxc }) {
  if (
    typeof viewer !== 'string' ||
    !viewer.endsWith(':' + server) ||
    typeof room !== 'string' ||
    room.length > 255 ||
    !room.startsWith('!') ||
    typeof event !== 'string' ||
    !/^\$[\w-]{43}$/.test(event) ||
    typeof mxc !== 'string' ||
    mxc.length > 530 ||
    !/^mxc:\/\/[A-Za-z0-9.:[\]-]+\/[A-Za-z0-9._~-]{1,255}$/.test(mxc)
  )
    return null;
  if ((await home.ctx.storage.get('mauvely-id/' + account)) !== viewer) return null;
  await openParty(home, server, viewer);
  await checkParties(home, server, load(home, server, room));
  // Bind the claim to an actual encrypted event inside this viewer's readable interval.
  // Only the client can recover its MXC and key. The receipt cannot grant access to the source Cloud node.
  let window;
  try {
    window = historyWindow(home, room, viewer);
  } catch (error) {
    if (error.status === 403) return null;
    throw error;
  }
  const receipt = home.sql
    .exec(
      `INSERT INTO cloud_file_receipts(id,user,room,event,mxc)
    SELECT ?1,?2,?3,?4,?5 FROM room_visible_events e WHERE e.room=?3 AND e.eid=?4 AND e.cause IS NULL
      AND e.seq>=?6 AND e.seq<?7 AND json_extract(e.pdu,'$.type')='m.room.encrypted'
    ON CONFLICT(user,room,event) DO UPDATE SET mxc=excluded.mxc WHERE mxc=excluded.mxc RETURNING id`,
      crypto.randomUUID(),
      viewer,
      room,
      event,
      mxc,
      window.floor,
      window.ceiling
    )
    .toArray()[0];
  return receipt?.id ?? null;
}

export async function visibleReceipts(home, server, account, ids) {
  if (!Array.isArray(ids) || ids.length > 64 || ids.some((id) => typeof id !== 'string' || id.length !== 36))
    return [];
  const viewer = await home.ctx.storage.get('mauvely-id/' + account);
  if (!viewer || !viewer.endsWith(':' + server) || !ids.length) return [];
  await openParty(home, server, viewer);
  const read = () =>
    home.sql
      .exec(
        'SELECT id,mxc,room FROM cloud_file_receipts WHERE user=? AND id IN (' +
          ids.map(() => '?').join(',') +
          ')',
        viewer,
        ...ids
      )
      .toArray();
  const result = read();
  for (const room of new Set(result.map((entry) => entry.room)))
    await checkParties(home, server, load(home, server, room));
  return read();
}

export async function releaseReceipts(home) {
  if (!home.env.CLOUD_MEDIA) return;
  const rows = home.sql
    .exec('SELECT * FROM cloud_receipt_removals WHERE due<=? ORDER BY due LIMIT 32', Date.now())
    .toArray();
  for (const row of rows) {
    try {
      const server = row.user.slice(row.user.indexOf(':') + 1);
      const account = await home.mediaAccount(server, row.user);
      if (!account) throw Error('Missing receipt owner');
      await home.env.CLOUD_MEDIA.revokeReceipt(server, account, row.id);
      home.sql.exec('DELETE FROM cloud_receipt_removals WHERE id=?', row.id);
    } catch {
      const delay = Math.min(3600000, 1000 * 2 ** Math.min(12, row.attempt));
      home.sql.exec(
        'UPDATE cloud_receipt_removals SET due=?,attempt=attempt+1 WHERE id=?',
        Date.now() + delay,
        row.id
      );
    }
  }
}
