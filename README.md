# Relay Matrix Worker

Workers-native interoperability spike, AGPL-3.0-or-later. Each configured endpoint maps to one durable Matrix server name and one persistent Ed25519 signing identity. The endpoints implement server key publication, server version and client version discovery. The client version list is empty until a full client-server version is supported.

The v10 replay probe uses Ruma in WebAssembly to verify original signed PDUs, check declared authorisation and predecessor state, and resolve a complete room graph. The reference fixture comes from a local Synapse 1.165.0 test room and two signed concurrent topic changes. The probe is offline replay; it does not accept live room traffic. Its keys are public verification keys.

Install stable Rust with target wasm32-unknown-unknown and wasm-bindgen-cli 0.2.130. Run `npm ci`, `./build-room.sh`, then `npm test`. Use a private Wrangler configuration based on wrangler.jsonc. Set DOMAINS to a map from endpoint hostnames to canonical Matrix names, and add the corresponding custom domains as Worker routes. Keep each server name bound to its original Durable Object and back up its signing identity before replacing storage. Publish the two Matrix discovery files on the canonical domain. Set PROBE_TOKEN with Wrangler to run the bounded fork replay by authenticated POST to /_relay/spike/replay.

Pending interoperability work includes live federation transactions, room joins, user authentication, sync, device-key APIs, and encrypted media. Advertise supported versions after exercising the complete client and federation paths.
