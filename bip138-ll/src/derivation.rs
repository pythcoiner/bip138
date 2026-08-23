//! Dependency-free derivation path. A path is the raw BIP32 child numbers with
//! the hardened bit kept in place, exactly as they cross the wire. Lexicographic
//! ordering over the raw `u32`s matches `bitcoin`'s `ChildNumber` ordering
//! (normal before hardened, then by index), so sort/dedup keep the same bytes.

use alloc::vec::Vec;

/// High bit marking a hardened BIP32 child.
pub const HARDENED_BIT: u32 = 1 << 31;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DerivationPath(Vec<u32>);

impl DerivationPath {
    /// The raw child numbers, hardened bit included.
    pub fn to_u32_vec(&self) -> &[u32] {
        &self.0
    }

    /// First child number with the hardened bit cleared, or `None` for an empty
    /// path.
    pub fn first_index(&self) -> Option<u32> {
        self.0.first().map(|index| index & !HARDENED_BIT)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl From<Vec<u32>> for DerivationPath {
    fn from(childs: Vec<u32>) -> Self {
        DerivationPath(childs)
    }
}

/// A hardened child number.
pub fn hardened(index: u32) -> u32 {
    index | HARDENED_BIT
}
