#!/usr/bin/env sh
# Formatting and clippy checks. Shared by CI and `just lint`.
set -eu
cargo fmt -- --check
# dependency-free core: default (no deps), then with the C binding and providers
cargo clippy -p bip138-ll --all-targets -- -D warnings
cargo clippy -p bip138-ll --all-targets --features "ffi os-rng" -- -D warnings
cargo clippy --all-targets -- -D warnings
cargo clippy --all-targets --no-default-features --features "miniscript_latest rand base64 v0" -- -D warnings
# the bip138 bin needs the cli feature, without it the binary is never linted
cargo clippy --all-targets --features cli -- -D warnings
# device support is feature gated too, and the cfg(not(devices)) arms only
# compile in the pass above, so both are needed
cargo clippy --all-targets --features "cli devices" -- -D warnings
# the miniscript 13 backend, with and without the bip138 bin (v0 is 12-only)
cargo clippy --all-targets --no-default-features --features "miniscript_13 rand base64 descriptor_backup" -- -D warnings
cargo clippy --all-targets --no-default-features --features "miniscript_13 rand base64 descriptor_backup cli" -- -D warnings
# downstream crates built against each miniscript backend
cargo clippy --manifest-path examples/miniscript_12_0/Cargo.toml -- -D warnings
cargo clippy --manifest-path examples/miniscript_12_3_5/Cargo.toml -- -D warnings
cargo clippy --manifest-path examples/miniscript_13_0/Cargo.toml -- -D warnings
