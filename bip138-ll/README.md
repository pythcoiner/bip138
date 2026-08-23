# bip138-ll

The dependency-free core of [`bip138`](../README.md): the BIP138 wire format and
the crypto orchestration, with no external dependency of its own. Every external
primitive (SHA-256, the ChaCha20-Poly1305 AEAD, randomness) is supplied by the
caller through a trait, and public keys cross the API as raw 32-byte x-only keys,
so nothing here pulls in an elliptic-curve, hashing, cipher, or RNG crate. That
keeps `secp256k1-sys` and its vendored C off a firmware build, and lets a C
consumer plug in its own crypto.

The `bip138` crate sits on top of this one and supplies the concrete pieces:
secp256k1 public-key handling, descriptor and miniscript parsing, base64, the v0
(AES-GCM) decrypt fallback, and the `beb` CLI.

## Supplying the crypto (Rust)

Implement two traits and pass them in:

```rust
pub trait Crypto {
    fn sha256(&self, data: &[u8]) -> [u8; 32];
    fn aead_encrypt(&self, key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8]) -> Result<Vec<u8>, ()>;
    fn aead_decrypt(&self, key: &[u8; 32], nonce: &[u8; 12], ciphertext: &[u8]) -> Option<Vec<u8>>;
}
pub trait Rng {
    fn fill_bytes(&mut self, buf: &mut [u8]);
}
```

Two bundled implementations are available behind features for callers that do not
bring their own:

- `rust-bitcoin` provides `RustBitcoin` (SHA-256 and ChaCha20-Poly1305 from the
  rust-bitcoin crates).
- `os-rng` provides `OsRandom` (the OS entropy source) and implies `rust-bitcoin`.
  It is off by default so a platform with no OS CSPRNG supplies its own `Rng`.

`SliceRng` (always available, no dependency) yields bytes from a fixed buffer, for
deterministic encryption such as test vectors.

## Supplying the crypto (C)

Enable the `ffi` feature. The C consumer fills a `bip138_crypto_vtable` of four
function pointers (SHA-256, AEAD encrypt, AEAD decrypt, fill-random) and calls
`bip138_encrypt` / `bip138_decrypt`. The header is
[`include/bip138.h`](include/bip138.h), kept in sync by hand with `src/ffi.rs`;
[`tests/layout.rs`](tests/layout.rs) pins the size, alignment, and field offsets
of every struct so a Rust-side change fails the tests until the header follows.
See [`examples/consumer.c`](examples/consumer.c) for a full encrypt/decrypt/free
cycle with a libsodium-backed vtable.

`bip138-ll` stays a plain `rlib`: a `staticlib` needs a global allocator and a
panic handler, which a library cannot supply. Link it from a thin shim crate that
provides those and re-exports the binding. On a hosted target `std` supplies both:

```toml
# libbip138_shim/Cargo.toml
[package]
name = "bip138-shim"
version = "0.0.0"
edition = "2024"

[lib]
crate-type = ["staticlib"]

[dependencies]
bip138-ll = { path = "../bip138-ll", features = ["ffi"] }
```

```rust
// libbip138_shim/src/lib.rs
pub use bip138_ll::ffi::*;
```

```sh
cargo build --release --manifest-path libbip138_shim/Cargo.toml
cc -I bip138-ll/include bip138-ll/examples/consumer.c \
   target/release/libbip138_shim.a -lsodium -o consumer
```

On a bare-metal target, keep the crate `no_std` and have the shim provide the
allocator and `#[panic_handler]` itself.

Build the crypto and the shim yourself and verify them; this crate ships no
prebuilt binaries. The only ownership rule across the boundary: Rust never frees
your memory, and you never free Rust memory except through `bip138_buf_free` and
`bip138_decrypt_free`.

## Feature summary

| Feature        | Effect                                                        |
|----------------|---------------------------------------------------------------|
| (none)         | Dependency-free `no_std` core; caller supplies `Crypto`/`Rng`. |
| `rust-bitcoin` | Bundled `RustBitcoin` (SHA-256, ChaCha20-Poly1305).           |
| `os-rng`       | Bundled `OsRandom`; implies `rust-bitcoin`.                   |
| `ffi`          | The C binding (`src/ffi.rs`, exported symbols).               |
