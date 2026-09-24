//! Cross-implementation differential fuzzing of BIP138.
//!
//! Each arm runs the crypto it ships in production: the Rust arm uses
//! `bip138`'s `RustBitcoin` (bitcoin_hashes + chacha20-poly1305), the C arm
//! the mbedTLS PSA backend Kern injects (see `c_impl`). Correct-but-independent
//! implementations of the same spec must agree; a divergence is a bug.

use std::collections::BTreeSet;

use arbitrary::Arbitrary;

pub mod c_impl;
pub mod cpp_impl;

use bip138::ll::{self, Content, DerivationPath, Encryption, Padding, Version, crypto::RustBitcoin};

/// x-only BIP341 NUMS point, dropped from the key set by both encoders. Feeding
/// it would make the arms diverge on how many real keys remain, so the encode
/// fuzzer filters it out of the input.
const NUMS_XONLY: [u8; 32] = [
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
];

/// Fixed recipient and nonce `diff_plaintext` wraps its plaintext with.
const PLAINTEXT_KEY: [u8; 32] = [0x02; 32];
const PLAINTEXT_NONCE: [u8; 12] = [0x01; 12];

/// Normalized decode result, compared field-by-field across arms. Paths and
/// secrets keep each arm's parse order; compare them through `canonical`.
#[derive(Debug, PartialEq, Eq)]
pub struct Decoded {
    pub paths: Vec<Vec<u32>>,
    pub secrets: Vec<[u8; 32]>,
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

impl Decoded {
    /// Sort and dedup paths and secrets. Rust's parser returns them sorted and
    /// deduplicated, C and C++ in wire order. BIP138 allows dedup at parse and
    /// the order carries no meaning; what matters is that every encoder sorts,
    /// which the encode targets check byte-for-byte.
    fn canonical(self) -> Self {
        Self {
            paths: sorted_unique(self.paths),
            secrets: sorted_unique(self.secrets),
            ..self
        }
    }
}

fn sorted_unique<T: Ord>(mut v: Vec<T>) -> Vec<T> {
    v.sort();
    v.dedup();
    v
}

/// A content type as the arms report it. An unknown type keeps neither its TYPE
/// byte nor its params, as Rust's `Content::Unknown` carries neither.
#[derive(Debug, PartialEq, Eq)]
pub enum ContentType {
    Bip(u16),
    Proprietary(Vec<u8>),
    String,
    Unknown,
}

/// A recovered plaintext item: its content type and data.
pub type Item = (ContentType, Vec<u8>);

// --- Rust arm (native) ---

fn rust_decode(bytes: &[u8]) -> Option<Decoded> {
    let (paths, secrets, encryption, nonce, ciphertext) = ll::decode_v1(bytes).ok()?;
    // The C `bip138_parse` rejects any encryption byte other than ChaCha20-Poly1305,
    // while Rust's low-level `decode_v1` returns it verbatim; normalize to match.
    if encryption != u8::from(ll::Encryption::ChaCha20Poly1305) {
        return None;
    }
    Some(Decoded {
        paths: paths.iter().map(|p| p.to_u32_vec().to_vec()).collect(),
        secrets: secrets.into_iter().collect(),
        nonce,
        ciphertext,
    })
}

fn rust_content_type(content: Content) -> ContentType {
    match content {
        Content::Bip138 => ContentType::Bip(138),
        Content::Bip139 => ContentType::Bip(139),
        Content::Bip380 => ContentType::Bip(380),
        Content::Bip388 => ContentType::Bip(388),
        Content::Bip329 => ContentType::Bip(329),
        Content::BIP(n) => ContentType::Bip(n),
        Content::Proprietary(tag) => ContentType::Proprietary(tag),
        Content::String => ContentType::String,
        Content::Unknown => ContentType::Unknown,
        Content::None => unreachable!("the parser never yields Content::None"),
    }
}

fn rust_decrypt_items(bytes: &[u8], key: &[u8; 32]) -> Option<Vec<Item>> {
    let (_paths, secrets, _enc, nonce, ciphertext) = ll::decode_v1(bytes).ok()?;
    let items = ll::decrypt_chacha20_poly1305_v1(&RustBitcoin, *key, &secrets, ciphertext, nonce)
        .ok()?;
    // C and C++ step over unknown items without reporting them, Rust returns them
    // as `Content::Unknown`; the spec only asks decoders to skip them, so drop them.
    Some(
        items
            .into_iter()
            .map(|(content, data)| (rust_content_type(content), data))
            .filter(|(ctype, _)| *ctype != ContentType::Unknown)
            .collect(),
    )
}

/// Wrap `plaintext` byte-exact as the payload of a container for
/// `PLAINTEXT_KEY`, with no paths and no decoys. `None` for an empty plaintext,
/// which cannot be encrypted.
fn rust_wrap_plaintext(plaintext: &[u8]) -> Option<Vec<u8>> {
    let keys = [PLAINTEXT_KEY];
    let secret = ll::decryption_secret(&RustBitcoin, &keys);
    let secrets = ll::individual_secrets(&RustBitcoin, &secret, &keys);
    let (nonce, ciphertext) =
        ll::encrypt_with_nonce(&RustBitcoin, secret, plaintext.to_vec(), PLAINTEXT_NONCE).ok()?;
    Some(ll::encode_v1(
        Version::V1.into(),
        ll::encode_derivation_paths(Vec::new()).ok()?,
        ll::encode_individual_secrets(&secrets).ok()?,
        Encryption::ChaCha20Poly1305.into(),
        ll::encode_encrypted_payload(nonce, &ciphertext).ok()?,
    ))
}

/// The data of each item, for the C++ arm which reports no content types.
fn item_data(items: &[Item]) -> Vec<Vec<u8>> {
    items.iter().map(|(_ctype, data)| data.clone()).collect()
}

fn rust_encode(input: &Normalized) -> Option<Vec<u8>> {
    let paths: Vec<DerivationPath> = input
        .paths
        .iter()
        .map(|p| DerivationPath::from(p.clone()))
        .collect();
    let items: Vec<(Content, &[u8])> = input
        .items
        .iter()
        .map(|item| (item.content.content.clone(), item.data.as_slice()))
        .collect();
    let padding = if input.geometric_pad {
        Padding::Geometric
    } else {
        Padding::None
    };
    ll::encrypt_chacha20_poly1305_v1_items_with_decoys(
        &RustBitcoin,
        paths,
        &items,
        input.keys.clone(),
        padding,
        input.nonce,
        &input.decoys,
    )
    .ok()
}

// --- Fuzz input, normalized so a mismatch is a bug, not a shape difference ---

#[derive(Arbitrary, Debug)]
pub enum ContentChoice {
    Bip(u16),
    Proprietary(Vec<u8>),
    Str(String),
}

#[derive(Arbitrary, Debug)]
struct ItemChoice {
    content: ContentChoice,
    data: Vec<u8>,
}

/// Raw structured input the fuzzer mutates.
#[derive(Arbitrary, Debug)]
pub struct EncodeInput {
    keys: Vec<[u8; 32]>,
    paths: Vec<Vec<u32>>,
    items: Vec<ItemChoice>,
    nonce: [u8; 12],
    geometric_pad: bool,
    decoy_seed: u64,
}

/// A content type and its C representation.
pub(crate) struct EncodeContent {
    content: Content,
    pub(crate) ctype: u8,
    pub(crate) bip: u16,
    pub(crate) tag: Vec<u8>,
}

impl From<ContentChoice> for EncodeContent {
    fn from(content: ContentChoice) -> Self {
        match content {
            ContentChoice::Bip(n) => EncodeContent {
                content: Content::BIP(n),
                ctype: c_impl::BIP138_CONTENT_BIP,
                bip: n,
                tag: Vec::new(),
            },
            ContentChoice::Proprietary(mut tag) => {
                tag.truncate(64);
                EncodeContent {
                    content: Content::Proprietary(tag.clone()),
                    ctype: c_impl::BIP138_CONTENT_PROPRIETARY,
                    bip: 0,
                    tag,
                }
            }
            ContentChoice::Str(_) => EncodeContent {
                content: Content::String,
                ctype: c_impl::BIP138_CONTENT_STRING,
                bip: 0,
                tag: Vec::new(),
            },
        }
    }
}

/// One content item and its C representation.
pub(crate) struct EncodeItem {
    pub(crate) content: EncodeContent,
    pub(crate) data: Vec<u8>,
}

impl From<ItemChoice> for EncodeItem {
    fn from(item: ItemChoice) -> Self {
        // A string item carries its text as data.
        let data = match &item.content {
            ContentChoice::Str(s) => cap(s.clone().into_bytes()),
            _ => cap(item.data),
        };
        EncodeItem {
            content: EncodeContent::from(item.content),
            data,
        }
    }
}

/// Structured input for `diff_components`.
#[derive(Arbitrary, Debug)]
pub enum ComponentInput {
    /// Raw bytes fed to every content-type, paths and secrets parser.
    Decode(Vec<u8>),
    EncodeContent(ContentChoice),
    EncodePaths(Vec<Vec<u32>>),
    EncodeSecrets(Vec<[u8; 32]>),
}

/// Input after canonicalization: distinct non-NUMS keys, a non-zero nonce, and
/// exactly the bucket's worth of distinct non-zero decoys, so both encoders take
/// the same path. Paths and items are passed through as-is, so both encoders'
/// drop (common paths) and reject (empty path, empty item list or data) logic is
/// compared.
struct Normalized {
    keys: Vec<[u8; 32]>,
    paths: Vec<Vec<u32>>,
    items: Vec<EncodeItem>,
    nonce: [u8; 12],
    geometric_pad: bool,
    decoys: Vec<[u8; 32]>,
}

fn normalize(input: EncodeInput) -> Option<Normalized> {
    // Distinct, non-NUMS keys, capped for speed.
    let mut seen = BTreeSet::new();
    let keys: Vec<[u8; 32]> = input
        .keys
        .into_iter()
        .filter(|k| *k != NUMS_XONLY && seen.insert(*k))
        .take(8)
        .collect();
    if keys.is_empty() {
        return None;
    }

    // The C binding carries a path depth as a u8, so longer paths cannot cross it.
    let paths: Vec<Vec<u32>> = input
        .paths
        .into_iter()
        .filter(|p| p.len() <= 255)
        .take(16)
        .collect();

    let items: Vec<EncodeItem> = input
        .items
        .into_iter()
        .take(4)
        .map(EncodeItem::from)
        .collect();

    let nonce = if input.nonce == [0u8; 12] {
        [1u8; 12]
    } else {
        input.nonce
    };

    // Exactly bucket - n_keys distinct non-zero decoys, from a seeded LCG.
    let bucket = c_impl::secret_bucket(keys.len());
    if bucket < keys.len() {
        return None;
    }
    let need = bucket - keys.len();
    let mut decoys = BTreeSet::new();
    let mut state = input.decoy_seed | 1;
    while decoys.len() < need {
        let mut d = [0u8; 32];
        for byte in d.iter_mut() {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            *byte = (state >> 56) as u8;
        }
        if d != [0u8; 32] {
            decoys.insert(d);
        }
    }
    let decoys: Vec<[u8; 32]> = decoys.into_iter().collect();

    Some(Normalized {
        keys,
        paths,
        items,
        nonce,
        geometric_pad: input.geometric_pad,
        decoys,
    })
}

fn cap(mut data: Vec<u8>) -> Vec<u8> {
    data.truncate(4096);
    data
}

// --- Differential entry points ---

/// Compare the three decoders (pure framing, no crypto) on raw bytes. All three
/// treat the ciphertext as opaque length-delimited framing and defer the AEAD
/// size check to decrypt, so no ciphertext-length normalization is needed.
pub fn diff_decode(data: &[u8]) {
    let rust = rust_decode(data).map(Decoded::canonical);
    let c = c_impl::decode(data).map(Decoded::canonical);
    let cpp = cpp_impl::decode(data).map(Decoded::canonical);
    if rust != c || rust != cpp {
        panic!(
            "decode divergence:\n  rust={:?}\n  c={:?}\n  cpp={:?}",
            rust, c, cpp,
        );
    }
}

/// Encode the same input in both arms and compare the container byte-for-byte.
pub fn diff_encode(input: EncodeInput) {
    let Some(n) = normalize(input) else {
        return;
    };
    let rust = rust_encode(&n);
    let c = c_impl::encode(
        &n.keys,
        &n.paths,
        &n.items,
        n.geometric_pad,
        &n.nonce,
        &n.decoys,
    );
    if rust != c {
        panic!(
            "encode divergence: rust_ok={} c_ok={} rust_len={:?} c_len={:?}",
            rust.is_some(),
            c.is_some(),
            rust.as_ref().map(|v| v.len()),
            c.as_ref().map(|v| v.len()),
        );
    }
}

/// Encode a valid container, then decrypt it in every arm and compare the
/// recovered items (cross-implementation encrypt/decrypt interop).
pub fn diff_decrypt(input: EncodeInput) {
    let Some(n) = normalize(input) else {
        return;
    };
    let Some(blob) = rust_encode(&n) else {
        return;
    };
    compare_decrypt(&blob, &n.keys[0]);
}

/// Wrap arbitrary bytes as the plaintext of a valid container, then decrypt it in
/// every arm and compare accept/reject and the recovered items. Covers malformed
/// payloads the encoders never produce.
pub fn diff_plaintext(plaintext: &[u8]) {
    let Some(blob) = rust_wrap_plaintext(plaintext) else {
        return;
    };
    compare_decrypt(&blob, &PLAINTEXT_KEY);
}

/// Decrypt `blob` with `key` in every arm and compare the recovered items. C++'s
/// `DecryptBackupContentsWithKey` returns only each item's data and its payload
/// walker is private, so content types are compared between Rust and C only.
fn compare_decrypt(blob: &[u8], key: &[u8; 32]) {
    let rust = rust_decrypt_items(blob, key);
    let c = c_impl::decrypt_items(blob, key);
    let cpp = cpp_impl::decrypt_data(blob, key);
    // Rust's `decode_plaintext` only frames the items: bip138's `extract` checks
    // that a string item is UTF-8. C and C++ check it while walking the payload
    // and reject the whole payload.
    let bad_utf8 = rust.as_ref().is_some_and(|items| {
        items
            .iter()
            .any(|(ty, data)| *ty == ContentType::String && core::str::from_utf8(data).is_err())
    });
    // C++ is Bitcoin Core's wallet code, not a library: it rejects a payload with
    // no known item, as the wallet has nothing to import. Rust and C return an
    // empty list and leave that call to the caller.
    let cpp_agrees = (bad_utf8 && cpp.is_none())
        || match rust.as_deref() {
            Some([]) => matches!(cpp.as_deref(), None | Some([])),
            rust => rust.map(item_data) == cpp,
        };
    // C's contract rejects the whole payload when a known item has empty content;
    // Rust and C++ return the item with empty data.
    let has_empty = rust
        .as_ref()
        .is_some_and(|items| items.iter().any(|(_, data)| data.is_empty()));
    let c_agrees = rust == c || ((has_empty || bad_utf8) && c.is_none());
    if !c_agrees || !cpp_agrees {
        panic!(
            "decrypt divergence:\n  rust={:?}\n  c={:?}\n  cpp={:?}",
            rust, c, cpp,
        );
    }
}

/// Run each arm's component codecs (CONTENT_TYPE, DERIVATION_PATHS,
/// INDIVIDUAL_SECRETS) on the same input and compare accept/reject and results.
pub fn diff_components(input: ComponentInput) {
    match input {
        ComponentInput::Decode(bytes) => {
            compare_parse_content(&bytes);
            compare_decode_paths(&bytes);
            compare_decode_secrets(&bytes);
        }
        ComponentInput::EncodeContent(content) => compare_encode_content(content),
        ComponentInput::EncodePaths(paths) => compare_encode_paths(paths),
        ComponentInput::EncodeSecrets(secrets) => compare_encode_secrets(&secrets),
    }
}

fn compare_parse_content(bytes: &[u8]) {
    let rust = ll::parse_content(bytes)
        .ok()
        .map(|(consumed, content)| (consumed, rust_content_type(content)));
    let c = c_impl::parse_content(bytes);
    let cpp = cpp_impl::parse_content(bytes);
    if rust != c || rust != cpp {
        panic!(
            "content parse divergence:\n  rust={:?}\n  c={:?}\n  cpp={:?}",
            rust, c, cpp,
        );
    }
}

// C has no standalone paths or secrets parser: both live inside `bip138_parse`,
// which `diff_decode` already covers, so only Rust and C++ are compared here.
// C++ reports no consumed length, so only the parsed lists are compared.

fn compare_decode_paths(bytes: &[u8]) {
    // Order and duplicates carry no meaning at parse, see `Decoded::canonical`.
    let rust = ll::parse_derivation_paths(bytes)
        .ok()
        .map(|(_, paths)| sorted_unique(paths.iter().map(|p| p.to_u32_vec().to_vec()).collect()));
    let cpp = cpp_impl::decode_paths(bytes).map(sorted_unique);
    if rust != cpp {
        panic!(
            "paths decode divergence:\n  rust={:?}\n  cpp={:?}",
            rust, cpp
        );
    }
}

fn compare_decode_secrets(bytes: &[u8]) {
    let rust = ll::parse_individual_secrets(bytes)
        .ok()
        .map(|(_, secrets)| sorted_unique(secrets));
    let cpp = cpp_impl::decode_secrets(bytes).map(sorted_unique);
    if rust != cpp {
        panic!(
            "secrets decode divergence:\n  rust={:?}\n  cpp={:?}",
            rust, cpp
        );
    }
}

fn compare_encode_content(content: ContentChoice) {
    let content = EncodeContent::from(content);
    let rust = Vec::<u8>::try_from(content.content.clone()).ok();
    let c = c_impl::encode_content(&content);
    let cpp = cpp_impl::encode_content(&content);
    if rust != c || rust != cpp {
        panic!(
            "content encode divergence:\n  rust={:?}\n  c={:?}\n  cpp={:?}",
            rust, c, cpp,
        );
    }
}

fn compare_encode_paths(paths: Vec<Vec<u32>>) {
    // `bip138_paths_encode` caps the input at 255 paths before dedup (Rust and C++
    // cap the deduplicated set) and its depth is a u8, both documented in
    // bip138.h, so C only joins inputs inside that contract.
    let c = (paths.len() <= 255 && paths.iter().all(|p| p.len() <= 255))
        .then(|| c_impl::encode_paths(&paths));
    let cpp = cpp_impl::encode_paths(&paths);
    let rust =
        ll::encode_derivation_paths(paths.into_iter().map(DerivationPath::from).collect()).ok();
    if rust != cpp || c.as_ref().is_some_and(|c| *c != rust) {
        panic!(
            "paths encode divergence:\n  rust={:?}\n  c={:?}\n  cpp={:?}",
            rust, c, cpp,
        );
    }
}

fn compare_encode_secrets(secrets: &[[u8; 32]]) {
    // `bip138_secrets_encode` caps the input at 255 secrets before dedup (Rust and
    // C++ cap the deduplicated set), documented in bip138.h, so C only joins
    // inputs inside that contract.
    let c = (secrets.len() <= 255).then(|| c_impl::encode_secrets(secrets));
    let cpp = cpp_impl::encode_secrets(secrets);
    let rust = ll::encode_individual_secrets(secrets).ok();
    if rust != cpp || c.as_ref().is_some_and(|c| *c != rust) {
        panic!(
            "secrets encode divergence:\n  rust={:?}\n  c={:?}\n  cpp={:?}",
            rust, c, cpp,
        );
    }
}
