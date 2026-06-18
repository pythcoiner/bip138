#!/usr/bin/env sh
# Test suite. Shared by CI and `just test`.
set -eu
cargo test --verbose --color always -- --nocapture
cargo test --no-default-features --features "miniscript_latest rand base64 v0" --verbose --color always -- --nocapture
