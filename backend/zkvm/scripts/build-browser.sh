#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/../.."
RUSTFLAGS="${RUSTFLAGS:-} -C link-arg=--max-memory=134217728" cargo build --manifest-path backend/zkvm/Cargo.toml -p huma-replay-browser --target wasm32-unknown-unknown --release --locked
build/toolchains/wasm-bindgen/bin/wasm-bindgen backend/zkvm/target/wasm32-unknown-unknown/release/huma_replay_browser.wasm \
  --target web --out-dir frontend/dist/replay --no-typescript
node backend/integrations/attestation/build-browser.mjs
