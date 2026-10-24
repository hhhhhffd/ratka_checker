#!/usr/bin/env sh
# Builds the browser scanner into web/pkg. Requires the wasm32-unknown-unknown
# target and a wasm-bindgen CLI matching the wasm-bindgen version in Cargo.lock.
set -eu

cargo build --locked -p ratscan-wasm --target wasm32-unknown-unknown --release
wasm-bindgen --target web --no-typescript --out-dir web/pkg \
    target/wasm32-unknown-unknown/release/ratscan_wasm.wasm
