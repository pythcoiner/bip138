// Builds the C arm (odudex/bip138) and its production crypto backend for the
// differential fuzzer. The C library is compiled from the `bip138-c` submodule;
// its crypto is mbedTLS via the PSA API (the reference callbacks in
// `test/test_crypto.c`, byte-identical to what Kern wires in), linked against the
// host libmbedcrypto.

use std::env;
use std::path::Path;

fn main() {
    let c = Path::new("vendor/bip138-c");
    if !c.join("include/bip138.h").exists() {
        panic!(
            "vendor/bip138-c is empty; run `git submodule update --init fuzz/vendor/bip138-c`"
        );
    }

    let mut build = cc::Build::new();
    build.compiler("clang");
    build.std("c99");
    build.include(c.join("include"));
    build.include(c.join("src"));
    build.include(c.join("test"));
    for src in [
        "src/bip138_base64.c",
        "src/bip138_container.c",
        "src/bip138_paths.c",
        "src/bip138_payload.c",
        "src/bip138_secret.c",
        "src/bip138_varint.c",
        "test/test_crypto.c",
    ] {
        build.file(c.join(src));
    }

    // Under cargo-fuzz, instrument the C code so libFuzzer explores its parser
    // and it shares the sanitizer runtime the Rust side links.
    if env::var_os("CARGO_CFG_FUZZING").is_some() {
        build.flag("-fsanitize=fuzzer-no-link");
        build.flag("-fsanitize=address");
    }

    build.compile("bip138c");

    // The C arm's real-world crypto: mbedTLS via PSA.
    println!("cargo:rustc-link-lib=mbedcrypto");
    println!("cargo:rerun-if-changed=vendor/bip138-c/src");
    println!("cargo:rerun-if-changed=vendor/bip138-c/test/test_crypto.c");
}
