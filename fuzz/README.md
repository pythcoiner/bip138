# bip138 fuzzing

Two kinds of targets live here:

- The original single-implementation parser fuzzers (`decode`, `encode`,
  `parse_deriv_paths`, `parse_individual_secrets`, `parse_encrypted_payload`).
- **Differential fuzzers** (`diff_decode`, `diff_decrypt`, `diff_encode`,
  `diff_plaintext`, `diff_components`, `diff_reencode`) that run the same input
  through three independent BIP138 implementations and flag any divergence.

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
  and the parsed fields (paths and secrets sorted and deduplicated, nonce,
  ciphertext). Pure framing, no crypto.
- **`diff_decrypt`** (3-way): encode a container, decrypt it in every arm, compare
  the recovered items (content type and data; the C++ arm reports data only).
- **`diff_encode`** (Rust vs C): encode the same input (up to 4 items) with an
  explicit nonce and decoys, compare the container byte-for-byte. The C++ arm is
  not byte-compared: `CreateEncryptedBackup` draws its own randomness and parses a
  descriptor, so there is no deterministic low-level encode entry to drive.
- **`diff_plaintext`** (3-way): wrap raw bytes as the plaintext of a valid
  container (fixed key and nonce), decrypt it in every arm, compare accept/reject
  and the recovered items. Covers malformed payloads the encoders never produce.
- **`diff_components`** (3-way): run each arm's field codecs on the same input.
  Decode raw bytes as a content type (3-way), derivation paths and individual
  secrets (Rust vs C++: C only parses them inside a container); encode a content
  type, paths and secrets (3-way) and compare the bytes.
- **`diff_reencode`** (3-way): on raw bytes every arm decodes, re-serialize each
  arm's own parse (Rust `encode_v1`, C++ `EncodeEncryptedBackup`, C composed from
  its field encoders since it has no container serializer) and compare the bytes.

### Convergence note

The three parsers once drew the parse-vs-interpret line for ciphertext length
differently: C rejected any ciphertext not longer than the 16-byte AEAD tag, Rust
rejected only an empty one, and C++ accepted either and failed at decrypt. The
length is opaque framing (the AEAD gates it at decrypt), so this was a layering
difference, not a framing divergence. Rust (`bip138-ll`) and odudex/bip138 now both
defer that check to decrypt, matching C++, so `diff_decode` compares the full
ciphertext-length range with no normalization.

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
cmake -S fuzz/vendor/bitcoin -B fuzz/vendor/bitcoin/build -G Ninja \
      -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
      -DCMAKE_BUILD_TYPE=Release -DENABLE_WALLET=ON \
      -DBUILD_TESTS=OFF -DBUILD_TX=OFF -DBUILD_UTIL=OFF -DBUILD_GUI=OFF \
      -DENABLE_IPC=OFF -DWITH_ZMQ=OFF -DBUILD_DAEMON=OFF -DBUILD_CLI=OFF
# Name the library targets: a bare `ninja` builds none of the static libs, since
# they are only pulled in when an executable is linked.
ninja -C fuzz/vendor/bitcoin/build \
      bitcoin_wallet bitcoin_common bitcoin_consensus bitcoin_crypto \
      bitcoin_util bitcoin_clientversion univalue secp256k1
```

Then run a target (`build.rs` compiles the shim with `clang++` to match Core and
links the whole Core static-lib set into the sanitizer binary with `lld` to keep
link memory down):

```sh
cargo +nightly fuzz run diff_decode  -- -max_total_time=60
cargo +nightly fuzz run diff_decrypt -- -max_total_time=60
cargo +nightly fuzz run diff_encode  -- -max_total_time=60
cargo +nightly fuzz run diff_plaintext -- -max_total_time=60
cargo +nightly fuzz run diff_components -- -max_total_time=60
cargo +nightly fuzz run diff_reencode -- -max_total_time=60
```

To keep tracking upstream, bump a submodule and rebuild:

```sh
git -C fuzz/vendor/bitcoin fetch origin wip-encrypted-backup && \
  git -C fuzz/vendor/bitcoin checkout FETCH_HEAD && \
  just fuzz-init
```
