//! The bitcoin API the crate is written against. Each backend implements
//! [`Backend`] over one bitcoin/miniscript release, so the encryption rules,
//! the payload items and the backup documents never name a concrete type.

#[cfg(feature = "descriptor_backup")]
use alloc::string::String;
use alloc::vec::Vec;
use core::{
    fmt::{Debug, Display},
    str::FromStr,
};

#[cfg(feature = "descriptor_backup")]
use crate::Error;
use crate::ll;

#[cfg(not(feature = "miniscript_12"))]
compile_error!("A miniscript backend must be selected with a feature flag");

// The miniscript release the backend is built on, for callers that need its
// concrete types (xpubs, networks).
#[cfg(feature = "miniscript_12")]
pub use mscript_12 as miniscript;

pub mod rust_miniscript;

#[cfg(all(test, feature = "rand"))]
pub mod tests;

pub type Active = crate::backend::rust_miniscript::Miniscript;

pub type PublicKey = <Active as Backend>::PublicKey;
pub type DerivationPath = <Active as Backend>::DerivationPath;
pub type DescriptorKey = <Active as Backend>::DescriptorKey;
pub type Descriptor = <Active as Backend>::Descriptor;

/// Serde support the backup documents need on the types they store, only
/// required with the `descriptor_backup` feature.
#[cfg(feature = "descriptor_backup")]
pub trait MaybeSerde: serde::Serialize + serde::de::DeserializeOwned {}
#[cfg(feature = "descriptor_backup")]
impl<T: serde::Serialize + serde::de::DeserializeOwned> MaybeSerde for T {}
#[cfg(not(feature = "descriptor_backup"))]
pub trait MaybeSerde {}
#[cfg(not(feature = "descriptor_backup"))]
impl<T> MaybeSerde for T {}

pub trait Backend {
    type PublicKey: Copy + Ord + Debug;
    type DerivationPath: Clone + Ord + Debug;
    type DescriptorKey: Clone + Ord + Debug + FromStr + Display + MaybeSerde;
    type Descriptor: Clone + Eq + Debug + FromStr + Display + MaybeSerde;

    /// x-only serialization of a public key, the form the `ll` core keys on.
    fn xonly(key: &Self::PublicKey) -> [u8; 32];
    /// Convert a derivation path into the `ll` core's own path type.
    fn to_ll_path(path: &Self::DerivationPath) -> ll::DerivationPath;
    /// Convert an `ll` core derivation path back into the backend's one.
    fn from_ll_path(path: &ll::DerivationPath) -> Self::DerivationPath;
    /// Every key expression of the descriptor, in descriptor order.
    fn descriptor_keys(descriptor: &Self::Descriptor) -> Vec<Self::DescriptorKey>;
    fn classify(key: &Self::DescriptorKey) -> KeyExpr<Self>;
    /// True when a key expression of the descriptor has several derivation paths.
    #[cfg(feature = "descriptor_backup")]
    fn is_multipath(descriptor: &Self::Descriptor) -> bool;
    /// BIP388 template (with checksum) and key information vector of a descriptor.
    #[cfg(feature = "descriptor_backup")]
    fn to_wallet_policy(
        descriptor: &Self::Descriptor,
    ) -> Result<(String, Vec<Self::DescriptorKey>), Error>;
    /// Rebuild the descriptor from a BIP388 template and its key information vector.
    #[cfg(feature = "descriptor_backup")]
    fn from_wallet_policy(
        template: &str,
        keys: &[Self::DescriptorKey],
    ) -> Result<Self::Descriptor, Error>;
}

/// What the encryption rules need to know about one key expression.
pub enum KeyExpr<B: Backend + ?Sized> {
    /// A literal public key.
    Literal {
        xonly: [u8; 32],
        origin_path: Option<B::DerivationPath>,
    },
    /// An extended public key.
    XPub {
        root: B::PublicKey,
        origin_path: Option<B::DerivationPath>,
        /// A non-empty trailing derivation or a wildcard follows the xpub.
        derived: bool,
        /// The expression has several derivation paths.
        multipath: bool,
    },
}
