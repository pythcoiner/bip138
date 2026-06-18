#!/usr/bin/env sh
# Release builds for the supported feature sets. Shared by CI and `just build`.
set -eu
cargo build --release --features "cli miniscript_latest"
cargo build --release --no-default-features --features "miniscript_12_0"
