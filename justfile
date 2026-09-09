# Run all CI checks locally (lint, test, build, wasm build).
ci:
    ./contrib/lint.sh
    ./contrib/test.sh
    ./contrib/build.sh
    ./contrib/build-wasm.sh

# Remove all build artifacts, for the crate and the fuzz workspace.
clean:
    cargo clean
    cargo clean --manifest-path fuzz/Cargo.toml

# Fetch the vendored impls and build Bitcoin Core for the differential fuzzers.
# Run once, and again after bumping a submodule.
# Needs: libmbedtls-dev cmake ninja-build clang lld libboost-dev libevent-dev libsqlite3-dev
[doc("Set up the differential fuzzers (submodules + Bitcoin Core build).")]
fuzz-init:
    git submodule update --init fuzz/vendor/bip138-c fuzz/vendor/bitcoin
    cmake -S fuzz/vendor/bitcoin -B fuzz/vendor/bitcoin/build -G Ninja \
        -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
        -DCMAKE_BUILD_TYPE=Release -DENABLE_WALLET=ON \
        -DBUILD_TESTS=OFF -DBUILD_TX=OFF -DBUILD_UTIL=OFF -DBUILD_GUI=OFF \
        -DENABLE_IPC=OFF -DWITH_ZMQ=OFF -DBUILD_DAEMON=OFF -DBUILD_CLI=OFF
    # Build the static libraries the C++ arm links. A bare `ninja` builds none of
    # them: they are only pulled in as a side effect of linking an executable, so
    # name each library target the shim needs.
    ninja -C fuzz/vendor/bitcoin/build \
        bitcoin_wallet bitcoin_common bitcoin_consensus bitcoin_crypto \
        bitcoin_util bitcoin_clientversion univalue secp256k1

# Run every fuzz target for `seconds` seconds each; stop and report on the first crash.
# The differential targets (diff_*) need `just fuzz-init` first.
[doc("Run every fuzz target for `seconds` each.")]
fuzz seconds:
    #!/usr/bin/env sh
    set -u
    for target in $(cargo fuzz list); do
        echo "=== fuzzing $target for {{seconds}}s ==="
        if ! cargo +nightly fuzz build "$target"; then
            echo "!!! build failed for $target (differential targets need 'just fuzz-init')" >&2
            exit 1
        fi
        if ! cargo +nightly fuzz run "$target" -- -max_total_time={{seconds}}; then
            echo "!!! crash in $target, artifact in fuzz/artifacts/$target/" >&2
            exit 1
        fi
    done

# Run the cross-implementation differential fuzzers (Rust vs C vs C++) for
# `seconds` each; stop and report on the first divergence. Needs `just fuzz-init`.
[doc("Run the Rust/C/C++ differential fuzzers for `seconds` each.")]
diff-fuzz seconds:
    #!/usr/bin/env sh
    set -u
    for target in diff_decode diff_decrypt diff_encode; do
        echo "=== differential fuzzing $target for {{seconds}}s ==="
        if ! cargo +nightly fuzz build "$target"; then
            echo "!!! build failed for $target (did you run 'just fuzz-init'?)" >&2
            exit 1
        fi
        if ! cargo +nightly fuzz run "$target" -- -max_total_time={{seconds}}; then
            echo "!!! divergence in $target, artifact in fuzz/artifacts/$target/" >&2
            exit 1
        fi
    done
