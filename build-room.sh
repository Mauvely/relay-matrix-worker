#!/bin/sh
set -eu
cargo build --manifest-path room-v10/Cargo.toml --locked --release --target wasm32-unknown-unknown
wasm-bindgen room-v10/target/wasm32-unknown-unknown/release/relay_room_v10.wasm --target web --out-dir room-v10/pkg
