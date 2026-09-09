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

fn rust_decrypt_data(bytes: &[u8], key: &[u8; 32]) -> Option<Vec<Vec<u8>>> {
    let (_paths, secrets, _enc, nonce, ciphertext) = ll::decode_v1(bytes).ok()?;
    let items = ll::decrypt_chacha20_poly1305_v1(&RustBitcoin, *key, &secrets, ciphertext, nonce)
        .ok()?;
    Some(items.into_iter().map(|(_content, data)| data).collect())
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

/// Compare the three decoders (pure framing, no crypto) on raw bytes. All three
/// treat the ciphertext as opaque length-delimited framing and defer the AEAD
/// size check to decrypt, so no ciphertext-length normalization is needed.
pub fn diff_decode(data: &[u8]) {
    let rust = rust_decode(data);
    let c = c_impl::decode(data);
    let cpp = cpp_impl::decode(data);
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

/// Encode a valid container, then decrypt it in every arm and compare the
/// recovered item data (cross-implementation encrypt/decrypt interop).
pub fn diff_decrypt(input: EncodeInput) {
    let Some(n) = normalize(input) else {
        return;
    };
    let Some(blob) = rust_encode(&n) else {
        return;
    };
    let key = n.keys[0];
    let rust = rust_decrypt_data(&blob, &key);
    let c = c_impl::decrypt_data(&blob, &key);
    let cpp = cpp_impl::decrypt_data(&blob, &key);
    if rust != c || rust != cpp {
        panic!(
            "decrypt divergence:\n  rust={:?}\n  c={:?}\n  cpp={:?}",
            rust, c, cpp,
        );
    }
}
