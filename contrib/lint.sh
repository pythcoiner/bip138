#!/usr/bin/env sh
# Formatting and clippy checks. Shared by CI and `just lint`.
set -eu
cargo fmt -- --check
cargo clippy --all-targets -- -D warnings
cargo clippy --all-targets --no-default-features --features "miniscript_latest rand base64 v0" -- -D warnings
# the beb bin needs the cli feature, without it the binary is never linted
cargo clippy --all-targets --features cli -- -D warnings
# device support is feature gated too, and the cfg(not(devices)) arms only
# compile in the pass above, so both are needed
cargo clippy --all-targets --features "cli devices" -- -D warnings
