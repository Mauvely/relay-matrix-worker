// SPDX-License-Identifier: AGPL-3.0-or-later
import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { readFileSync } from 'node:fs';
import { initSync, prepare_event } from './room-v10/pkg/relay_room_v10.js';
import { createIdentity } from './src/identity.js';
import { sign } from './src/federation.js';
import { schema, create, fedRoom, roomClient, roomSync } from './src/rooms.js';
import { eventId } from './src/graph.js';
initSync({ module: readFileSync(new URL('./room-v10/pkg/relay_room_v10_bg.wasm', import.meta.url)) });
test('private v10 room requires an invitation and accepts a signed remote join exactly once', async () => {
  const db = new DatabaseSync(':memory:');
  const sql = {
    exec(query, ...args) {
      if (query.includes(';')) {
        db.exec(query);
        return;
      }
      const rows = db.prepare(query).all(...args);
      return { toArray: () => rows, one: () => rows[0] };
    }
  };
  const server = 'worker.test',
    peer = 'synapse.test',
    user = '@a:' + server,
    other = '@b:' + peer;
  const identity = await createIdentity(),
    remote = await createIdentity();
  const home = {
    identity,
    sql,
    ctx: { storage: { transactionSync: (f) => f() } },
    waiters: new Map(),
    party: async () => ({ organisationId: null }),
    env: {
      PEER_KEYS: { [peer]: { 'ed25519:1': remote.publicKey } },
      PEER_URLS: { [peer]: 'https://peer.test' }
    }
  };
  schema(sql);
  const {
    body: { room_id: room }
  } = await create(home, server, user, {
    initial_state: [{ type: 'm.room.encryption', content: { algorithm: 'm.megolm.v1.aes-sha2' } }]
  });
  const make = () =>
    fedRoom(home, server, peer, 'GET', ['make_join', room, other], new URLSearchParams('ver=10'));
  await assert.rejects(make, /invitation/);
  await roomClient(home, server, { user_id: user }, 'POST', [room, 'invite'], { user_id: other });
  const {
    body: { event: p }
  } = await make();
  const [hash, redacted] = JSON.parse(prepare_event(JSON.stringify(p)));
  p.hashes = { sha256: hash };
  p.signatures = { [peer]: { 'ed25519:1': await sign(remote, redacted) } };
  const join = () =>
    fedRoom(home, server, peer, 'PUT', ['send_join', room, eventId(p)], new URLSearchParams(), p);
  assert.deepEqual(await join(), await join());
  const initial = await roomSync(home, server, user, 0, true);
  assert.ok(initial.rooms.join[room].timeline.events.some((e) => e.sender === other));
});
