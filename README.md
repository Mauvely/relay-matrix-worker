# Relay Matrix Worker

A Workers-native Matrix interoperability spike, licensed under AGPL-3.0-or-later. A single deployment serves multiple canonical server names. Each name selects its own SQLite-backed Durable Object, Ed25519 signing key, provisioned accounts and device queues.

## Run the spike

Install stable Rust with the wasm32-unknown-unknown target and wasm-bindgen-cli 0.2.130. Run `npm ci`, `./build-room.sh`, and `npm test`. Copy `wrangler.jsonc` to a private configuration. Add your own HTTPS custom-domain routes and set `DOMAINS` to a mapping from preassigned endpoint hostname to canonical server name. A canonical name must remain bound to its original storage. Back up signing keys and storage before replacing a tenant.

For a delegated name, its web administrator publishes `/.well-known/matrix/client` with an `m.homeserver.base_url` of `https://<endpoint>`, and `/.well-known/matrix/server` with an `m.server` of `<endpoint>:443`. A name served at its own endpoint answers both documents itself. The operator chooses the mapping before provisioning. Keep each custom endpoint exclusive to its assigned name.

Set `PROVISION_TOKEN` with Wrangler. An authenticated operator can POST a JSON object containing `localpart` and `organisation_id` (a stable ID, or null for a personal account) to `/_relay/spike/provision`. Both live discovery documents must match the endpoint before a new ID can be issued. The operator receives a generated high-entropy credential once. The spike exposes password login, device-scoped access tokens, whoami and logout.

For hosted to-device traffic, `ORGANISATIONS` maps stable organisation IDs to a policy of `open`, `closed` or `allowlist`. An allowlisted organisation supplies `allow` with its partner IDs. Both directions must permit communication. A missing policy stops delivery. Each device sync reads its own queue, rechecks policy and acknowledges the preceding sync token. Retries of a completed transaction do not enqueue another event. Open accounts can also exchange to-device messages with a configured federation peer. The live room APIs currently admit personal accounts and accounts in explicitly open organisations. `fixtures/policy-cases.json` is the same contract exercised by the Synapse distribution.

For federation, set `PEER_KEYS` to a map from the peer's canonical server name to its verified Ed25519 key IDs and unpadded Base64 public keys. Set `PEER_URLS` to a map from that name to its HTTPS federation origin. The Worker publishes its own signing key at `/_matrix/key/v2/server`. Configure the independent peer to resolve the Worker's canonical name through Matrix delegation. Federation requests sign the method, path, query, destination and JSON body.

## Room replay

Ruma, compiled to WebAssembly, verifies v10 PDUs, checks event authorisation, tracks predecessors and resolves signed state forks. The checked-in synthetic fixture contains a room from Synapse and two concurrent topic events. An authenticated POST to `/_relay/spike/replay` using `PROBE_TOKEN` checks convergence under both arrival orders. The catch-up probe accepts `{start, events}` at `/_relay/spike/catchup`, verifies the entire candidate history and commits an authorised batch atomically. It checks the durable prefix length, room ID, pinned fixture keys, a 1 MiB body limit and a 512-event cap. This endpoint is for the synthetic fixture only.

## Interoperability status, 21 November 2026

Independent Synapse successfully queried a provisioned user's profile over signed federation. The live deployment isolated identical usernames and tokens in two tenants. Reciprocal to-device traffic crossed tenants exactly once on retry. A closed recipient got zero events. A 512-event signed fixture persisted and resolved on Workers, including disconnected branches. These checks use isolated test server names.

The four catch-up checkpoints contained 9, 11, 128, and 512 signed events. HTTPS wall times for the respective append requests were 241, 127, 217 and 434 ms. The final tenant SQLite database occupied 462,848 bytes, including its other tables. Replaying an old checkpoint returned 409 with the current stored count. Cloudflare reported 0.599 ms median and 4.407 ms p99 Worker CPU across a separate 80-request sample of mixed traffic. This sample does not isolate Durable Object replay CPU. A five-second sampling profile had only 9 ms of samples and gave no function-level replay timing.

### Desktop interoperability

On 21 November, Element 1.12.35 used the deployed Worker while Relay used a separately running PostgreSQL-backed Synapse 1.165.0. Each client decrypted the other's message and downloaded an encrypted attachment that matched the original bytes. Their seven SAS emoji matched in order and both clients confirmed verification. NeoChat 26.08.2 and Relay exchanged encrypted messages on the Worker. A fresh Relay device restored a prior encrypted message from a Worker account's key backup.

To repeat the walkthrough:

1. Configure a pinned Synapse peer as described above. Set its default room version to `10` for new conversations it originates. Provision two personal Worker accounts and one Synapse account.
2. Sign in to Element and NeoChat with the Worker accounts. Sign in to Relay's `/matrix` page with the Synapse account. Use each client's recovery setup before verifying.
3. Invite the other account to an encrypted conversation. Accept in the other client. Compare all seven SAS emoji, confirm on each device, send a distinct message and download a file in each direction. Compare downloaded bytes with the originals.
4. Start a second encrypted room from Synapse. The Worker signs the invite, requests a join template, submits its signed join and verifies the room history before syncing the conversation.
5. Sign in to Relay on the Worker and repeat with NeoChat. Use a fresh browser profile and the saved recovery key to check restoration.

The deployment supports a bounded v10 room graph of 512 events, up to 32 missing predecessors when joining an existing room, and 1 MiB attachments. The Worker stores encrypted media as client-supplied bytes and serves authenticated Matrix media downloads. Complement's version-response and private-room-creation assertions passed against both servers using a remote deployment adapter.

General peer discovery and key rotation, recovery of arbitrary gaps after disconnection, distributed restricted-room admission, and the full Complement suite remain cutover work. This deployment is for interoperability testing.
