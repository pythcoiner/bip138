//! Cross-implementation differential fuzzing of BIP138.
//!
//! Each arm runs the crypto it ships in production: the Rust arm uses
//! `bip138`'s `RustBitcoin` (bitcoin_hashes + chacha20-poly1305), the C arm
//! the mbedTLS PSA backend Kern injects (see `c_impl`). Correct-but-independent
//! implementations of the same spec must agree; a divergence is a bug.

use std::collections::BTreeSet;

use arbitrary::Arbitrary;

pub mod c_impl;

use bip138::ll::{self, Content, DerivationPath, Padding, crypto::RustBitcoin};

/// x-only BIP341 NUMS point, dropped from the key set by both encoders. Feeding
/// it would make the arms diverge on how many real keys remain, so the encode
/// fuzzer filters it out of the input.
const NUMS_XONLY: [u8; 32] = [
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
];

/// Normalized decode result, compared field-by-field across arms.
#[derive(Debug, PartialEq, Eq)]
pub struct Decoded {
    pub paths: BTreeSet<Vec<u32>>,
    pub secrets: BTreeSet<[u8; 32]>,
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

/// One recovered content item, compared across arms after decryption.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Item {
    /// Content discriminant: 1 BIP, 2 proprietary, 3 string, 0 other.
    pub kind: u8,
    pub bip: u16,
    pub tag: Vec<u8>,
    pub data: Vec<u8>,
}

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

fn rust_decrypt_items(bytes: &[u8], key: &[u8; 32]) -> Option<Vec<Item>> {
    let (_paths, secrets, _enc, nonce, ciphertext) = ll::decode_v1(bytes).ok()?;
    let items = ll::decrypt_chacha20_poly1305_v1(&RustBitcoin, *key, &secrets, ciphertext, nonce)
        .ok()?;
    Some(items.into_iter().map(|(c, data)| content_to_item(&c, data)).collect())
}

fn content_to_item(content: &Content, data: Vec<u8>) -> Item {
    match content {
        Content::Bip138 => Item { kind: 1, bip: 138, tag: vec![], data },
        Content::Bip139 => Item { kind: 1, bip: 139, tag: vec![], data },
        Content::Bip380 => Item { kind: 1, bip: 380, tag: vec![], data },
        Content::Bip388 => Item { kind: 1, bip: 388, tag: vec![], data },
        Content::Bip329 => Item { kind: 1, bip: 329, tag: vec![], data },
        Content::BIP(n) => Item { kind: 1, bip: *n, tag: vec![], data },
        Content::Proprietary(tag) => Item { kind: 2, bip: 0, tag: tag.clone(), data },
        Content::String => Item { kind: 3, bip: 0, tag: vec![], data },
        Content::None | Content::Unknown => Item { kind: 0, bip: 0, tag: vec![], data },
    }
}

fn rust_encode(input: &Normalized) -> Option<Vec<u8>> {
    let paths: Vec<DerivationPath> = input
        .paths
        .iter()
        .map(|p| DerivationPath::from(p.clone()))
        .collect();
    let items = [(input.content.clone(), input.data.as_slice())];
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
enum ContentChoice {
    Bip(u16),
    Proprietary(Vec<u8>),
    Str(String),
}

/// Raw structured input the fuzzer mutates.
#[derive(Arbitrary, Debug)]
pub struct EncodeInput {
    keys: Vec<[u8; 32]>,
    paths: Vec<Vec<u32>>,
    content: ContentChoice,
    data: Vec<u8>,
    nonce: [u8; 12],
    geometric_pad: bool,
    decoy_seed: u64,
}

/// Input after canonicalization: distinct non-NUMS keys, non-common non-empty
/// paths, a non-zero nonce, non-empty data, and exactly the bucket's worth of
/// distinct non-zero decoys, so both encoders take the same path.
struct Normalized {
    keys: Vec<[u8; 32]>,
    paths: Vec<Vec<u32>>,
    content: Content,
    ctype: u8,
    bip: u16,
    tag: Vec<u8>,
    data: Vec<u8>,
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

    // Non-empty, non-common paths (dropping common paths is a separate concern;
    // keeping only non-common paths means neither encoder drops any).
    let paths: Vec<Vec<u32>> = input
        .paths
        .into_iter()
        .filter(|p| !p.is_empty() && p.len() <= 255)
        .filter(|p| !c_impl::path_is_common(p))
        .take(16)
        .collect();

    // Content and its C representation.
    let (content, ctype, bip, tag, data) = match input.content {
        ContentChoice::Bip(n) => (Content::BIP(n), 1u8, n, Vec::new(), cap(input.data)),
        ContentChoice::Proprietary(t) => {
            let tag = { let mut t = t; t.truncate(64); t };
            (Content::Proprietary(tag.clone()), 2u8, 0u16, tag, cap(input.data))
        }
        ContentChoice::Str(s) => {
            let bytes = { let mut b = s.into_bytes(); b.truncate(4096); b };
            (Content::String, 3u8, 0u16, Vec::new(), bytes)
        }
    };
    if data.is_empty() {
        return None;
    }

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
        content,
        ctype,
        bip,
        tag,
        data,
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

/// C's `bip138_parse` folds two AEAD-interpretation checks into parsing: the
/// ciphertext must be longer than the 16-byte Poly1305 tag, and its plaintext
/// must fit the RFC 8439 limit. Rust's `decode_v1` treats the ciphertext as
/// opaque length-delimited framing and defers both to decrypt. The framing is
/// valid either way, so this is a layering choice, not a divergence.
fn ciphertext_is_aead_shaped(len: usize) -> bool {
    const MAX_PLAINTEXT: usize = (1 << 38) - 64;
    len > 16 && len - 16 <= MAX_PLAINTEXT
}

/// Compare the two decoders (pure framing, no crypto) on raw bytes.
pub fn diff_decode(data: &[u8]) {
    let rust = rust_decode(data);
    let c = c_impl::decode(data);
    // Skip the inputs C rejects only because it validates AEAD ciphertext shape
    // at parse time while Rust validates it at decrypt.
    if let (Some(d), None) = (&rust, &c)
        && !ciphertext_is_aead_shaped(d.ciphertext.len())
    {
        return;
    }
    if rust != c {
        panic!(
            "decode divergence: rust_accepts={} c_accepts={}\n  rust={:?}\n  c={:?}",
            rust.is_some(),
            c.is_some(),
            rust,
            c,
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
        n.ctype,
        n.bip,
        &n.tag,
        &n.data,
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

/// Encode a valid container, then decrypt it in both arms and compare the
/// recovered items (cross-implementation encrypt/decrypt interop).
pub fn diff_decrypt(input: EncodeInput) {
    let Some(n) = normalize(input) else {
        return;
    };
    let Some(blob) = rust_encode(&n) else {
        return;
    };
    let key = n.keys[0];
    let rust = rust_decrypt_items(&blob, &key);
    let c = c_impl::decrypt_items(&blob, &key);
    if rust != c {
        panic!(
            "decrypt divergence: rust={:?}\n  c={:?}",
            rust, c,
        );
    }
}
