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

# Run every fuzz target for `seconds` seconds each; stop and report on the first crash.
fuzz seconds:
    #!/usr/bin/env sh
    set -u
    for target in $(cargo fuzz list); do
        echo "=== fuzzing $target for {{seconds}}s ==="
        if ! cargo +nightly fuzz run "$target" -- -max_total_time={{seconds}}; then
            echo "!!! crash in $target, artifact in fuzz/artifacts/$target/" >&2
            exit 1
        fi
    done
