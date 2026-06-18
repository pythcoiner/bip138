#!/usr/bin/env sh
# Formatting and clippy checks. Shared by CI and `just lint`.
set -eu
cargo fmt -- --check
cargo clippy --all-targets -- -D warnings
