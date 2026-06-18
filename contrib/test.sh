#!/usr/bin/env sh
# Test suite. Shared by CI and `just test`.
set -eu
cargo test --verbose --color always -- --nocapture
