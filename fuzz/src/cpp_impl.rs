//! The C++ arm: Sjors/bitcoin's `wallet/encrypted_backup` (built from the
//! `bitcoin` submodule) with Bitcoin Core's own crypto (CSHA256,
//! AEADChaCha20Poly1305). Bound through a `cxx` shim over its decode and
//! decrypt entry points and its component codecs.

use crate::{
    ContentType, Decoded, EncodeContent,
    c_impl::{BIP138_CONTENT_BIP, BIP138_CONTENT_PROPRIETARY, BIP138_CONTENT_STRING},
};

#[cxx::bridge(namespace = "bip138shim")]
mod ffi {
    /// One derivation path.
    struct CppPath {
        child: Vec<u32>,
    }

    /// Result of decoding a container.
    struct CppDecoded {
        ok: bool,
        paths: Vec<CppPath>,
        secrets: Vec<u8>, // flattened, 32 bytes per secret
        nonce: Vec<u8>,   // 12 bytes when ok
        ciphertext: Vec<u8>,
    }

    /// One recovered plaintext item.
    struct CppItem {
        data: Vec<u8>,
    }

    /// Result of decrypting a container with one key.
    struct CppItems {
        ok: bool,
        items: Vec<CppItem>,
    }

    /// Result of decoding a CONTENT_TYPE field. `known` is false for a type the
    /// C++ parser skips.
    struct CppContent {
        ok: bool,
        known: bool,
        type_: u8,
        bip: u16,
        payload: Vec<u8>,
        consumed: usize,
    }

    /// Result of decoding a DERIVATION_PATHS field.
    struct CppPaths {
        ok: bool,
        paths: Vec<CppPath>,
    }

    /// Result of an encoder, or of decoding INDIVIDUAL_SECRETS (flattened, 32
    /// bytes per secret).
    struct CppBytes {
        ok: bool,
        bytes: Vec<u8>,
    }

    unsafe extern "C++" {
        include!("shim.h");

        fn cpp_decode(data: &[u8]) -> CppDecoded;
        fn cpp_decrypt(data: &[u8], key: &[u8]) -> CppItems;
        fn cpp_decode_content(data: &[u8]) -> CppContent;
        fn cpp_decode_paths(data: &[u8]) -> CppPaths;
        fn cpp_decode_secrets(data: &[u8]) -> CppBytes;
        fn cpp_encode_content(type_: u8, bip: u16, payload: &[u8]) -> CppBytes;
        fn cpp_encode_paths(paths: &[CppPath]) -> CppBytes;
        fn cpp_encode_secrets(secrets: &[u8]) -> CppBytes;
        fn cpp_reencode(data: &[u8]) -> CppBytes;
    }
}

/// Decode a container. `None` on any rejection.
pub fn decode(bytes: &[u8]) -> Option<Decoded> {
    let d = ffi::cpp_decode(bytes);
    if !d.ok {
        return None;
    }
    let secrets = d
        .secrets
        .chunks_exact(32)
        .map(|c| {
            let mut s = [0u8; 32];
            s.copy_from_slice(c);
            s
        })
        .collect::<Vec<_>>();
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&d.nonce);
    let paths = d.paths.into_iter().map(|p| p.child).collect::<Vec<_>>();
    Some(Decoded {
        paths,
        secrets,
        nonce,
        ciphertext: d.ciphertext,
    })
}

/// Decrypt a container with one key, returning the recovered item data. `None`
/// when no key opens it.
pub fn decrypt_data(bytes: &[u8], key: &[u8; 32]) -> Option<Vec<Vec<u8>>> {
    let r = ffi::cpp_decrypt(bytes, key);
    if !r.ok {
        return None;
    }
    Some(r.items.into_iter().map(|i| i.data).collect())
}

/// Decode one CONTENT_TYPE field: bytes consumed and the content type.
pub fn parse_content(bytes: &[u8]) -> Option<(usize, ContentType)> {
    let c = ffi::cpp_decode_content(bytes);
    if !c.ok {
        return None;
    }
    let ctype = match (c.known, c.type_) {
        (false, _) => ContentType::Unknown,
        (true, BIP138_CONTENT_BIP) => ContentType::Bip(c.bip),
        (true, BIP138_CONTENT_PROPRIETARY) => ContentType::Proprietary(c.payload),
        (true, BIP138_CONTENT_STRING) => ContentType::String,
        (true, t) => unreachable!("DecodeContentType reported type {t} as known"),
    };
    Some((c.consumed, ctype))
}

/// Decode a DERIVATION_PATHS field (count prefix included).
pub fn decode_paths(bytes: &[u8]) -> Option<Vec<Vec<u32>>> {
    let p = ffi::cpp_decode_paths(bytes);
    if !p.ok {
        return None;
    }
    Some(p.paths.into_iter().map(|p| p.child).collect())
}

/// Decode an INDIVIDUAL_SECRETS field (count prefix included).
pub fn decode_secrets(bytes: &[u8]) -> Option<Vec<[u8; 32]>> {
    let s = ffi::cpp_decode_secrets(bytes);
    if !s.ok {
        return None;
    }
    Some(
        s.bytes
            .chunks_exact(32)
            .map(|c| {
                let mut s = [0u8; 32];
                s.copy_from_slice(c);
                s
            })
            .collect(),
    )
}

/// Encode a CONTENT_TYPE field.
pub(crate) fn encode_content(content: &EncodeContent) -> Option<Vec<u8>> {
    bytes(ffi::cpp_encode_content(
        content.ctype,
        content.bip,
        &content.tag,
    ))
}

/// Encode a DERIVATION_PATHS field (count prefix included).
pub fn encode_paths(paths: &[Vec<u32>]) -> Option<Vec<u8>> {
    let paths: Vec<ffi::CppPath> = paths
        .iter()
        .map(|p| ffi::CppPath { child: p.clone() })
        .collect();
    bytes(ffi::cpp_encode_paths(&paths))
}

/// Encode an INDIVIDUAL_SECRETS field (count prefix included).
pub fn encode_secrets(secrets: &[[u8; 32]]) -> Option<Vec<u8>> {
    let flat: Vec<u8> = secrets.iter().flatten().copied().collect();
    bytes(ffi::cpp_encode_secrets(&flat))
}

/// Decode a container and re-serialize the decoded struct with
/// `EncodeEncryptedBackup`. `None` when the decode rejects.
pub fn reencode(data: &[u8]) -> Option<Vec<u8>> {
    bytes(ffi::cpp_reencode(data))
}

fn bytes(b: ffi::CppBytes) -> Option<Vec<u8>> {
    b.ok.then_some(b.bytes)
}
