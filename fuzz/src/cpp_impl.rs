//! The C++ arm: Sjors/bitcoin's `wallet/encrypted_backup` (built from the
//! `bitcoin` submodule) with Bitcoin Core's own crypto (CSHA256,
//! AEADChaCha20Poly1305). Bound through a `cxx` shim over its decode and
//! decrypt entry points.

use std::collections::BTreeSet;

use crate::Decoded;

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

    unsafe extern "C++" {
        include!("shim.h");

        fn cpp_decode(data: &[u8]) -> CppDecoded;
        fn cpp_decrypt(data: &[u8], key: &[u8]) -> CppItems;
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
        .collect::<BTreeSet<_>>();
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&d.nonce);
    let paths = d.paths.into_iter().map(|p| p.child).collect::<BTreeSet<_>>();
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
