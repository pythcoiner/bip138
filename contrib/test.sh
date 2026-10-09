#!/usr/bin/env sh
# Test suite. Shared by CI and `just test`.
set -eu
# dependency-free core: default build, then providers plus the C binding tests
cargo test -p bip138-ll --verbose --color always -- --nocapture
cargo test -p bip138-ll --features "ffi os-rng" --verbose --color always -- --nocapture
cargo test --verbose --color always -- --nocapture
cargo test --no-default-features --features "miniscript_latest rand base64 v0" --verbose --color always -- --nocapture
# the bip138 bin needs the cli feature, without it its tests never run
cargo test --features cli --verbose --color always -- --nocapture
# device support is feature gated too, and its tests need no device
cargo test --features "cli devices" --verbose --color always -- --nocapture
# the miniscript 13 backend, with and without the bip138 bin (v0 is 12-only)
cargo test --no-default-features --features "miniscript_13 rand base64 descriptor_backup" --verbose --color always -- --nocapture
cargo test --no-default-features --features "miniscript_13 rand base64 descriptor_backup cli" --verbose --color always -- --nocapture
# downstream crates built against each miniscript backend
cargo run --manifest-path examples/miniscript_12_0/Cargo.toml
cargo run --manifest-path examples/miniscript_12_3_5/Cargo.toml
cargo run --manifest-path examples/miniscript_13_0/Cargo.toml
