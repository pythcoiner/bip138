Command-line tool & Rust crate that lets you **encrypt descriptors (or arbitrary
data)** with a set of **public** keys (or xpubs) and later decrypt when **at least
one** of them is physically present—either via a local file containing the key or
automatically fetched from a signing device.
Devices are **not mandatory**; you can use the tool completely off-device.

## CLI

### Install

To install the cli without device support:

```
cargo install bip138 --features cli
```

or with devices support, which needs `libudev-dev` and `pkg-config` installed:

```
cargo install bip138 --features cli,devices
```

From a checkout, `cargo build --bin bip138 --release --features cli` builds it
in place.

Note: if a signing device supported by
[`bwk-hwi`](https://docs.rs/bwk-hwi/0.1.0) is connected and unlocked,
the CLI will automatically try to fetch a set of xpubs from it.


### Usage:

```
$ bip138 --help
BIP138 Compact encryption scheme for Non-seed wallet data

Usage: bip138 [OPTIONS] <COMMAND>

Commands:
  encrypt  Encrypt some descriptor
  decrypt  Decrypt an encrypted descriptor with a given xpub
  inspect  Inspect an encrypted descriptor without decrypting it
  help     Print this message or the help of the given subcommand(s)

Options:
  -o, --output <OUTPUT>  Write command output to file instead of stdout
  -h, --help             Print help
  -V, --version          Print version
```
```
$ bip138 encrypt --help
Encrypt some descriptor

Usage: bip138 encrypt [OPTIONS]

Options:
  -f, --file <FILE>
          Input file containing the descriptor

      --msg <MSG>
          Message to add before the descriptor payload

      --keys <KEYS>
          File listing outer-to-inner wrapping key levels

          One level per line, outermost first: each level encrypts the one
          below it, and the last line encrypts the descriptor itself.

          A line is one key, several keys separated by `|`, or a note and its
          keys separated by `||`:

              [48bfdc46/48h/1h/10h/2h]tpubDF6MC...
              [c658b283/48h/1h/10h/2h]tpubDFHe6... | [748f7513/48h/1h/10h/2h]tpubDEwiF...
              backup 2026 || [c658b283/48h/1h/10h/2h]tpubDFHe6...

          Each key must carry its origin, as `[fingerprint/derivation]xpub`,
          and any one key of a level decrypts that level. The separator before
          a note is `||`, not `|`: with a single `|`, `Coldcard | xpub...`
          reads `Coldcard` as a key and fails.

          A note is stored encrypted at its level and shows up when that level
          is decrypted. Blank lines and lines starting with `#` are ignored.
          Cannot be used with --device.

          Example:

              # outer level, either signer can unwrap it
              backup 2026 || [c658b283/48h/1h/10h/2h]tpubDFHe6... | [748f7513/48h/1h/10h/2h]tpubDEwiF...
              # inner level, holds the descriptor
              [48bfdc46/48h/1h/10h/2h]tpubDF6MC...

  -o, --output <OUTPUT>
          Write command output to file instead of stdout

  -h, --help
          Print help (see a summary with '-h')

```
```
$ bip138 decrypt --help
Decrypt an encrypted descriptor with a given xpub

Usage: bip138 decrypt [OPTIONS]

Options:
  -f, --file <FILE>      Input file to be decrypted
  -k, --key <KEY>        File containing a xpub
  -o, --output <OUTPUT>  Write command output to file instead of stdout
  -h, --help             Print help

```
## Library usage

### Encryption
```rust
let descriptor = Descriptor::<DescriptorPublicKey>::from_str("<descriptor
string>").unwrap();
let backp = EncryptedBackup::new().set_payload(&descriptor).unwrap();
let encrypted_blob = backp.encrypt().unwrap();
```

### Decryption
```rust

let encrypted_blob: Vec<u8> = vec![/* your encrypted descriptor*/];
let key = DescriptorPublicKey::from_str("<your xpub>").unwrap();
let descriptor = EncryptedBackup::new()
    .set_encrypted_payload(&encrypted_blob)
    .unwrap()
    .set_keys(vec![key])
    .decrypt()
    .unwrap();
```

## WASM support

This carate can be build against these wasm targets:
 - `wasm32-unknown-unknown`
 - `wasm32-wasip1`

Note: `rand` feature must be disabled for these target:

```
cargo build --target wasm32-unknown-unknown --no-default-features --features "miniscript_latest"
```

## C bindings

The wire format and crypto orchestration live in a dependency-free core crate,
[`bip138-ll`](bip138-ll/README.md). It keeps `secp256k1`, the cipher, the hash,
and the RNG behind traits (public keys cross as raw 32-byte x-only keys), so a C
or firmware consumer supplies its own crypto and never links this crate's
dependencies. This `bip138` crate is the Rust front end: it depends on
`bip138-ll` and fills in secp256k1, descriptor parsing, base64, the v0 fallback,
and the CLI.

Enable the core's `ffi` feature for a hand-written C binding (`bip138_encrypt` /
`bip138_decrypt` over a crypto vtable). See
[`bip138-ll/README.md`](bip138-ll/README.md) and
[`bip138-ll/examples/consumer.c`](bip138-ll/examples/consumer.c).

## Features

| Feature flag        | Default | Description                                            |
|---------------------|---------|--------------------------------------------------------|
| `miniscript_12`     | –       | Compile against `miniscript` 12 (12.0 or later)        |
| `miniscript_13`     | –       | Compile against `miniscript` 13 (not with `v0`)        |
| `miniscript_latest` | ✓       | Alias for `miniscript_12`                              |
| `rand`              | ✓       | Draw nonces from the OS random source                  |
| `base64`            | ✓       | Accept and produce base64 encoded backups              |
| `v0`                | ✓       | Decrypt backups made by bitcoin-encrypted-backup 0.0.2 |
| `descriptor_backup` | ✓       | Parse BIP380/BIP388 backup documents                   |
| `devices`           | –       | Fetch xpubs from signing devices                       |
| `cli`               | –       | Build the `bip138` binary                              |

Select exactly one backend: `miniscript_12` (or `miniscript_latest`) or `miniscript_13`.

Note: the `devices` feature uses
[`bwk-hwi`](https://docs.rs/bwk-hwi/0.1.0) crate, see
[there](https://docs.rs/bwk-hwi/0.1.0) for supported signing devices.

## Regenerating test vectors

The crate ships JSON test vectors under `test_vectors/` that are checked
against the current implementation by the standard test suite. Whenever
the spec or the crypto changes (cipher, tag strings, key width, TYPE
encoding, …), the `expected` fields in those JSON files must be
recomputed.

Three `#[ignore]` helpers are provided for that purpose; each rewrites a
single vector file in place from the current code:

| Test                                            | File rewritten                              |
|-------------------------------------------------|---------------------------------------------|
| `ll::encryption_secret::regenerate_vectors`     | `test_vectors/encryption_secret.json`       |
| `ll::encryption_vectors::regenerate_vectors`    | `test_vectors/chacha20poly1305_encryption.json` |
| `ll::encrypted_backup::regenerate_vectors`      | `test_vectors/encrypted_backup.json`        |

Run them all at once:

```
cargo test regenerate_vectors -- --ignored
```

They are gated with `#[ignore]` so `cargo test` never touches the
committed vectors. After running, inspect `git diff test_vectors/` and
only commit the change when it reflects an intentional spec update.
