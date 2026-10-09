//! [`Backend`] over rust-miniscript, shared by every supported release.

#[cfg(feature = "descriptor_backup")]
pub mod wallet_policy;

#[cfg(feature = "descriptor_backup")]
use alloc::string::{String, ToString};
use alloc::vec::Vec;
#[cfg(feature = "descriptor_backup")]
use core::str::FromStr;

#[cfg(feature = "descriptor_backup")]
use crate::{
    Error,
    backend::rust_miniscript::wallet_policy::{Bip388Key, WalletPolicy},
};
use crate::{
    backend::{Backend, KeyExpr},
    ll,
    miniscript::{
        Descriptor, DescriptorPublicKey, ForEachKey,
        bitcoin::{
            bip32::{ChildNumber, DerivationPath},
            secp256k1,
        },
        descriptor::{SinglePubKey, Wildcard},
    },
};

pub enum Miniscript {}

/// A non-empty trailing derivation on every path, or a wildcard.
fn is_derived(paths: &[DerivationPath], wildcard: Wildcard) -> bool {
    let deriv = !paths.is_empty() && paths.iter().all(|p| !p.is_empty());
    deriv || wildcard != Wildcard::None
}

impl Backend for Miniscript {
    type PublicKey = secp256k1::PublicKey;
    type DerivationPath = DerivationPath;
    type DescriptorKey = DescriptorPublicKey;
    type Descriptor = Descriptor<DescriptorPublicKey>;

    fn xonly(key: &secp256k1::PublicKey) -> [u8; 32] {
        key.x_only_public_key().0.serialize()
    }

    fn to_ll_path(path: &DerivationPath) -> ll::DerivationPath {
        ll::DerivationPath::from(path.to_u32_vec())
    }

    fn from_ll_path(path: &ll::DerivationPath) -> DerivationPath {
        DerivationPath::from(
            path.to_u32_vec()
                .iter()
                .map(|child| ChildNumber::from(*child))
                .collect::<Vec<ChildNumber>>(),
        )
    }

    fn descriptor_keys(descriptor: &Descriptor<DescriptorPublicKey>) -> Vec<DescriptorPublicKey> {
        let mut keys = Vec::new();
        descriptor.for_each_key(|k| {
            keys.push(k.clone());
            true
        });
        keys
    }

    fn classify(key: &DescriptorPublicKey) -> KeyExpr<Self> {
        match key {
            DescriptorPublicKey::Single(k) => KeyExpr::Literal {
                xonly: match k.key {
                    SinglePubKey::FullKey(pk) => pk.inner.x_only_public_key().0.serialize(),
                    SinglePubKey::XOnly(xo) => xo.serialize(),
                },
                origin_path: k.origin.clone().map(|(_, p)| p),
            },
            DescriptorPublicKey::XPub(k) => KeyExpr::XPub {
                root: k.xkey.public_key,
                origin_path: k.origin.clone().map(|(_, p)| p),
                derived: is_derived(core::slice::from_ref(&k.derivation_path), k.wildcard),
                multipath: false,
            },
            DescriptorPublicKey::MultiXPub(k) => KeyExpr::XPub {
                root: k.xkey.public_key,
                origin_path: k.origin.clone().map(|(_, p)| p),
                derived: is_derived(k.derivation_paths.paths(), k.wildcard),
                multipath: true,
            },
        }
    }

    #[cfg(feature = "descriptor_backup")]
    fn is_multipath(descriptor: &Descriptor<DescriptorPublicKey>) -> bool {
        descriptor.is_multipath()
    }

    #[cfg(feature = "descriptor_backup")]
    fn to_wallet_policy(
        descriptor: &Descriptor<DescriptorPublicKey>,
    ) -> Result<(String, Vec<DescriptorPublicKey>), Error> {
        let wp = WalletPolicy::from_descriptor(descriptor)?;
        Ok((wp.template.to_string(), wp.key_info))
    }

    #[cfg(feature = "descriptor_backup")]
    fn from_wallet_policy(
        template: &str,
        keys: &[DescriptorPublicKey],
    ) -> Result<Descriptor<DescriptorPublicKey>, Error> {
        let template =
            Descriptor::<Bip388Key>::from_str(template).map_err(|_| Error::WalletPolicy)?;
        WalletPolicy {
            template,
            key_info: keys.to_vec(),
        }
        .into_descriptor()
    }
}
