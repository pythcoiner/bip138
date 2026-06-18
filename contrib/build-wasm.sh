#!/usr/bin/env sh
# wasm build. Shared by CI and `just build-wasm`.
set -eu
rustup target add wasm32-unknown-unknown
rustup target add wasm32-wasip1
cargo build --target wasm32-unknown-unknown --no-default-features --features "miniscript_latest"
