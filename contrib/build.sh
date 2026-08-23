#!/usr/bin/env sh
# Release builds for the supported feature sets. Shared by CI and `just build`.
set -eu
# the core must build with zero dependencies
cargo build --release -p bip138-ll
cargo build --release --features "cli miniscript_latest"
cargo build --release --no-default-features --features "miniscript_12_0"
