//! The crypto primitives the format needs, as traits the caller supplies. Keys
//! cross as raw 32-byte x-only public keys, so no elliptic-curve trait is
//! required. Bundled rust-bitcoin and OS-entropy implementations live behind
//! the `rust-bitcoin` and `os-rng` features for callers that do not bring
//! their own.

use alloc::vec::Vec;

/// Deterministic primitives: SHA-256 and the ChaCha20-Poly1305 AEAD.
pub trait Crypto {
    /// One-shot SHA-256.
    fn sha256(&self, data: &[u8]) -> [u8; 32];

    /// ChaCha20-Poly1305 encrypt. The ciphertext is 16 bytes longer than the
    /// plaintext (the Poly1305 tag). `None` on any cipher failure.
    fn aead_encrypt(&self, key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8]) -> Option<Vec<u8>>;

    /// ChaCha20-Poly1305 decrypt. `None` when the tag does not verify.
    fn aead_decrypt(&self, key: &[u8; 32], nonce: &[u8; 12], ciphertext: &[u8]) -> Option<Vec<u8>>;
}

/// A source of randomness for nonces and decoy secrets.
pub trait Rng {
    fn fill_bytes(&mut self, buf: &mut [u8]);
}

#[cfg(feature = "rust-bitcoin")]
mod rust_bitcoin {
    use super::Crypto;
    use alloc::vec::Vec;
    use bitcoin_hashes::{Hash, sha256};
    use chacha20_poly1305::{ChaCha20Poly1305, Key, Nonce};

    /// Poly1305 tag length.
    const TAG_LEN: usize = 16;

    /// Bundled SHA-256 and ChaCha20-Poly1305 from the rust-bitcoin crates.
    #[derive(Debug, Clone, Copy, Default)]
    pub struct RustBitcoin;

    impl Crypto for RustBitcoin {
        fn sha256(&self, data: &[u8]) -> [u8; 32] {
            sha256::Hash::hash(data).to_byte_array()
        }

        fn aead_encrypt(
            &self,
            key: &[u8; 32],
            nonce: &[u8; 12],
            plaintext: &[u8],
        ) -> Option<Vec<u8>> {
            let cipher = ChaCha20Poly1305::new(Key::new(*key), Nonce::new(*nonce));
            let mut out = plaintext.to_vec();
            let tag = cipher.encrypt(&mut out, None);
            out.extend_from_slice(&tag);
            Some(out)
        }

        fn aead_decrypt(
            &self,
            key: &[u8; 32],
            nonce: &[u8; 12],
            ciphertext: &[u8],
        ) -> Option<Vec<u8>> {
            let split = ciphertext.len().checked_sub(TAG_LEN)?;
            let (ciphertext, tag) = ciphertext.split_at(split);
            let cipher = ChaCha20Poly1305::new(Key::new(*key), Nonce::new(*nonce));
            let mut out = ciphertext.to_vec();
            cipher.decrypt(&mut out, tag.try_into().ok()?, None).ok()?;
            Some(out)
        }
    }
}

#[cfg(feature = "rust-bitcoin")]
pub use rust_bitcoin::RustBitcoin;

#[cfg(feature = "os-rng")]
mod os_rng {
    use super::Rng;
    use rand::{TryRngCore, rngs::OsRng};

    /// OS entropy source.
    #[derive(Debug, Clone, Copy, Default)]
    pub struct OsRandom;

    impl Rng for OsRandom {
        fn fill_bytes(&mut self, buf: &mut [u8]) {
            OsRng.try_fill_bytes(buf).expect("os rng must not fail");
        }
    }
}

#[cfg(feature = "os-rng")]
pub use os_rng::OsRandom;
