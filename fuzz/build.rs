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

    build_cpp_arm();
}

// C++ arm: compile the cxx shim over Sjors/bitcoin's wallet/encrypted_backup and
// link its static libraries. Bitcoin Core is built out of band (see fuzz/README);
// its own crypto (CSHA256, AEADChaCha20Poly1305) is what the C++ impl ships.
fn build_cpp_arm() {
    let core = Path::new("vendor/bitcoin");
    let core_build = core.join("build");
    if !core_build.join("lib/libbitcoin_wallet.a").exists() {
        panic!(
            "vendor/bitcoin is not built; configure and build it first (see fuzz/README.md), \
             e.g. `cmake -B vendor/bitcoin/build -G Ninja -DENABLE_WALLET=ON ...` then \
             `ninja -C vendor/bitcoin/build`"
        );
    }

    cxx_build::bridge("src/cpp_impl.rs")
        .file("shim/shim.cpp")
        // Bitcoin Core is built with clang; match it for a clean link.
        .compiler("clang++")
        .std("c++20")
        .include(core.join("src"))
        .include(core_build.join("src"))
        .include(core.join("src/univalue/include"))
        .include(core.join("src/secp256k1/include"))
        .include("shim")
        .warnings(false)
        .compile("bip138cppshim");

    // Linking the whole Core static-lib set into the sanitizer fuzz binary is
    // heavy; lld keeps peak memory far below the default linker.
    println!("cargo:rustc-link-arg=-fuse-ld=lld");

    // Core's static libraries have circular references, so wrap them in one link
    // group. Full paths keep them independent of the linker's search order.
    let libs = [
        "lib/libbitcoin_wallet.a",
        "lib/libbitcoin_common.a",
        "lib/libbitcoin_consensus.a",
        "lib/libbitcoin_crypto.a",
        "lib/libbitcoin_util.a",
        "lib/libbitcoin_clientversion.a",
        "src/univalue/libunivalue.a",
        "src/secp256k1/lib/libsecp256k1.a",
    ];
    println!("cargo:rustc-link-arg=-Wl,--start-group");
    for lib in libs {
        println!("cargo:rustc-link-arg={}", core_build.join(lib).display());
    }
    println!("cargo:rustc-link-arg=-Wl,--end-group");
    println!("cargo:rustc-link-lib=sqlite3");
    println!("cargo:rustc-link-lib=event");
    println!("cargo:rustc-link-lib=stdc++");
    println!("cargo:rerun-if-changed=shim/shim.cpp");
    println!("cargo:rerun-if-changed=shim/shim.h");
    println!("cargo:rerun-if-changed=src/cpp_impl.rs");
}
