# bip138 fuzzing

Two kinds of targets live here:

- The original single-implementation parser fuzzers (`decode`, `encode`,
  `parse_deriv_paths`, `parse_individual_secrets`, `parse_encrypted_payload`).
- **Differential fuzzers** (`diff_decode`, `diff_decrypt`, `diff_encode`) that run
  the same input through three independent BIP138 implementations and flag any
  divergence.

## The three arms

Each arm links the crypto it ships in production, so the fuzzer also exercises
real crypto-stack interop:

| Arm  | Implementation | Crypto |
|------|----------------|--------|
| Rust | `bip138` / `bip138-ll` (this repo), called natively | `RustBitcoin` (bitcoin_hashes, chacha20-poly1305) |
| C    | [odudex/bip138](https://github.com/odudex/bip138) (`vendor/bip138-c` submodule), via `cc` + `extern "C"` | mbedTLS PSA, the backend [Kern](https://github.com/odudex/Kern/pull/168) injects (`test/test_crypto.c`) |
| C++  | [Sjors/bitcoin#109](https://github.com/Sjors/bitcoin/pull/109) `wallet/encrypted_backup` (`vendor/bitcoin` submodule), via `cxx` | Bitcoin Core's own (`CSHA256`, `AEADChaCha20Poly1305`) |

SHA-256 and ChaCha20-Poly1305 (IETF) are deterministic standards, so three correct
implementations must produce identical bytes; a mismatch is a bug.

## Targets

- **`diff_decode`** (3-way): decode raw bytes in every arm, compare accept/reject
  and the parsed fields (paths, secrets, nonce, ciphertext). Pure framing, no
  crypto.
- **`diff_decrypt`** (3-way): encode a container, decrypt it in every arm, compare
  the recovered item data.
- **`diff_encode`** (Rust vs C): encode the same input with an explicit nonce and
  decoys, compare the container byte-for-byte. The C++ arm is not byte-compared:
  `CreateEncryptedBackup` draws its own randomness and parses a descriptor, so there
  is no deterministic low-level encode entry to drive.

### Known normalizations

The three parsers draw the parse-vs-interpret line for ciphertext length
differently (Rust rejects an empty ciphertext, C rejects anything not longer than
the 16-byte tag, C++ accepts either and fails at decrypt). The serialization is
well framed in every case, so `diff_decode` skips inputs whose ciphertext is not a
valid AEAD shape rather than flagging that layering difference.

## Building and running

Prerequisites:

```sh
# C arm crypto (mbedTLS with PSA) and the Core build toolchain:
sudo apt install libmbedtls-dev cmake ninja-build clang lld \
                 libboost-dev libevent-dev libsqlite3-dev
git submodule update --init fuzz/vendor/bip138-c fuzz/vendor/bitcoin
```

The C arm is built automatically by `build.rs`. The C++ arm links Bitcoin Core's
static libraries, which you build once out of band:

```sh
cmake -B fuzz/vendor/bitcoin/build -G Ninja \
      -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
      -DCMAKE_BUILD_TYPE=Release -DENABLE_WALLET=ON \
      -DBUILD_TESTS=OFF -DBUILD_TX=OFF -DBUILD_UTIL=OFF -DBUILD_GUI=OFF \
      -DENABLE_IPC=OFF -DWITH_ZMQ=OFF -DBUILD_DAEMON=OFF -DBUILD_CLI=OFF
ninja -C fuzz/vendor/bitcoin/build
```

Then run a target (`build.rs` compiles the shim with `clang++` to match Core and
links the whole Core static-lib set into the sanitizer binary with `lld` to keep
link memory down):

```sh
cargo +nightly fuzz run diff_decode  -- -max_total_time=60
cargo +nightly fuzz run diff_decrypt -- -max_total_time=60
cargo +nightly fuzz run diff_encode  -- -max_total_time=60
```

To keep tracking upstream, bump a submodule and rebuild:

```sh
git -C fuzz/vendor/bitcoin fetch origin wip-encrypted-backup && \
  git -C fuzz/vendor/bitcoin checkout FETCH_HEAD && \
  ninja -C fuzz/vendor/bitcoin/build
```
