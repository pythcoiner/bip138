//! Typed conversion between a `Descriptor<DescriptorPublicKey>` and a BIP388
//! wallet policy, behind the `descriptor_backup` feature.
//!
//! A wallet policy is a descriptor template with `@i` key placeholders plus a
//! key information vector of `[origin]xpub` entries. miniscript 12.3.5 has no
//! BIP388 parser, so this backports miniscript master's approach onto its
//! public API: a [`Bip388Key`] placeholder that implements [`MiniscriptKey`],
//! `FromStr` and `Display`, so `Descriptor<Bip388Key>` parses and serializes
//! the template through miniscript's own machinery. Conversion is then just
//! `Bip388Key <-> DescriptorPublicKey` driven by `Descriptor::translate_pk`.
//!
//! musig placeholders are out of scope: miniscript 12.x cannot parse them.

use alloc::{
    string::{String, ToString},
    vec,
    vec::Vec,
};
use core::{
    fmt::{self, Display},
    str::FromStr,
};

use crate::{
    Error,
    miniscript::{
        Descriptor, DescriptorPublicKey, ForEachKey, MiniscriptKey, TranslateErr, TranslatePk,
        Translator,
        bitcoin::{
            bip32::DerivationPath,
            hashes::{hash160, ripemd160, sha256},
        },
        descriptor::{DerivPaths, DescriptorMultiXKey, DescriptorXKey, Wildcard},
        hash256,
    },
};

/// A throwaway xpub used only to reuse miniscript's own suffix parser: the
/// constant root is parsed with a `/**` or `/<...>/*` suffix and only the
/// resulting derivation paths and wildcard are read back.
const PARSE_XPUB: &str = "xpub6Br37sWxruYfT8ASpCjVHKGwgdnYFEn98DwiN76i2oyY6fgH1LAPmmDcF46xjxJr22gw4jmVjTE2E3URMnRPEPYyo1zoPSUba563ESMXCeb";

/// Both `/**` halves of a BIP388 default multipath suffix.
const RECEIVE_INDEX: u32 = 0;
const CHANGE_INDEX: u32 = 1;

/// The `/**` shorthand expanded to the explicit form miniscript's key parser
/// understands.
const DEFAULT_MULTIPATH: &str = "/<0;1>/*";

/// A BIP388 `@i` key placeholder. Carries the placeholder index plus the
/// trailing derivation suffix shared with the key info entry it stands for.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Bip388Key {
    index: u32,
    derivation_paths: DerivPaths,
    wildcard: Wildcard,
}

impl MiniscriptKey for Bip388Key {
    type Sha256 = sha256::Hash;
    type Hash256 = hash256::Hash;
    type Ripemd160 = ripemd160::Hash;
    type Hash160 = hash160::Hash;

    fn num_der_paths(&self) -> usize {
        self.derivation_paths.paths().len()
    }
}

impl Display for Bip388Key {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "@{}", self.index)?;
        let paths = self.derivation_paths.paths();
        let star = match self.wildcard {
            Wildcard::None => return Err(fmt::Error),
            Wildcard::Unhardened => "*",
            Wildcard::Hardened => "*h",
        };
        if is_default_multipath(paths, self.wildcard) {
            return write!(f, "/**");
        }
        if paths.len() == 1 {
            return write!(f, "/{}/{}", paths[0], star);
        }
        write!(f, "/<")?;
        for (i, path) in paths.iter().enumerate() {
            if i != 0 {
                write!(f, ";")?;
            }
            write!(f, "{path}")?;
        }
        write!(f, ">/{star}")
    }
}

/// True for the `[0, 1]` unhardened suffix that renders as `/**`.
fn is_default_multipath(paths: &[DerivationPath], wildcard: Wildcard) -> bool {
    wildcard == Wildcard::Unhardened
        && paths.len() == 2
        && paths[0].to_string() == RECEIVE_INDEX.to_string()
        && paths[1].to_string() == CHANGE_INDEX.to_string()
}

impl FromStr for Bip388Key {
    type Err = Bip388KeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let rest = s.strip_prefix('@').ok_or(Bip388KeyError)?;
        let (digits, suffix) = match rest.find('/') {
            Some(pos) => (&rest[..pos], &rest[pos..]),
            None => return Err(Bip388KeyError),
        };
        let index: u32 = digits.parse().map_err(|_| Bip388KeyError)?;
        let (derivation_paths, wildcard) = parse_suffix(suffix)?;
        Ok(Bip388Key {
            index,
            derivation_paths,
            wildcard,
        })
    }
}

/// Parse a BIP388 derivation suffix (`/**`, `/<a;b;...>/*`, or `/<path>/*`) by
/// reusing miniscript's own key parser on a throwaway xpub. The `/**` shorthand
/// is expanded first, since the key parser only understands the explicit form.
/// Rejects a suffix that yields no wildcard.
fn parse_suffix(suffix: &str) -> Result<(DerivPaths, Wildcard), Bip388KeyError> {
    let suffix = if suffix == "/**" {
        DEFAULT_MULTIPATH
    } else {
        suffix
    };
    let mut buf = String::with_capacity(PARSE_XPUB.len() + suffix.len());
    buf.push_str(PARSE_XPUB);
    buf.push_str(suffix);
    let dpk = DescriptorPublicKey::from_str(&buf).map_err(|_| Bip388KeyError)?;
    let (paths, wildcard) = match dpk {
        DescriptorPublicKey::XPub(k) => (vec![k.derivation_path], k.wildcard),
        DescriptorPublicKey::MultiXPub(k) => (k.derivation_paths.into_paths(), k.wildcard),
        DescriptorPublicKey::Single(_) => return Err(Bip388KeyError),
    };
    if wildcard == Wildcard::None {
        return Err(Bip388KeyError);
    }
    let derivation_paths = DerivPaths::new(paths).ok_or(Bip388KeyError)?;
    Ok((derivation_paths, wildcard))
}

/// Failure to parse a [`Bip388Key`] from a string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bip388KeyError;

impl Display for Bip388KeyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("invalid BIP388 key placeholder")
    }
}

/// Root key of a key info entry: origin and xkey with no trailing derivation
/// and no wildcard. `Single` literal keys are not valid key info entries.
fn key_root(dpk: &DescriptorPublicKey) -> Result<DescriptorPublicKey, Error> {
    let (origin, xkey) = match dpk {
        DescriptorPublicKey::XPub(k) => (k.origin.clone(), k.xkey),
        DescriptorPublicKey::MultiXPub(k) => (k.origin.clone(), k.xkey),
        DescriptorPublicKey::Single(_) => return Err(Error::WalletPolicy),
    };
    Ok(DescriptorPublicKey::XPub(DescriptorXKey {
        origin,
        xkey,
        derivation_path: DerivationPath::master(),
        wildcard: Wildcard::None,
    }))
}

/// Trailing derivation paths and wildcard of a key expression, used to build a
/// [`Bip388Key`]. A key with no wildcard is not a valid placeholder.
fn key_suffix(dpk: &DescriptorPublicKey) -> Result<(DerivPaths, Wildcard), Error> {
    let (paths, wildcard) = match dpk {
        DescriptorPublicKey::XPub(k) => (vec![k.derivation_path.clone()], k.wildcard),
        DescriptorPublicKey::MultiXPub(k) => (k.derivation_paths.paths().clone(), k.wildcard),
        DescriptorPublicKey::Single(_) => return Err(Error::WalletPolicy),
    };
    if wildcard == Wildcard::None {
        return Err(Error::WalletPolicy);
    }
    let derivation_paths = DerivPaths::new(paths).ok_or(Error::WalletPolicy)?;
    Ok((derivation_paths, wildcard))
}

/// The key information vector, shared by both translation directions: it
/// collects the unique key roots when converting a descriptor, and resolves
/// each `@i` placeholder against them when rebuilding one.
struct KeySet {
    keys: Vec<DescriptorPublicKey>,
}

impl Translator<DescriptorPublicKey, Bip388Key, Error> for KeySet {
    fn pk(&mut self, dpk: &DescriptorPublicKey) -> Result<Bip388Key, Error> {
        let root = key_root(dpk)?;
        let index = match self.keys.iter().position(|k| *k == root) {
            Some(i) => i,
            None => {
                self.keys.push(root);
                self.keys.len() - 1
            }
        };
        let (derivation_paths, wildcard) = key_suffix(dpk)?;
        Ok(Bip388Key {
            index: index as u32,
            derivation_paths,
            wildcard,
        })
    }

    fn sha256(&mut self, h: &sha256::Hash) -> Result<sha256::Hash, Error> {
        Ok(*h)
    }
    fn hash256(&mut self, h: &hash256::Hash) -> Result<hash256::Hash, Error> {
        Ok(*h)
    }
    fn ripemd160(&mut self, h: &ripemd160::Hash) -> Result<ripemd160::Hash, Error> {
        Ok(*h)
    }
    fn hash160(&mut self, h: &hash160::Hash) -> Result<hash160::Hash, Error> {
        Ok(*h)
    }
}

impl Translator<Bip388Key, DescriptorPublicKey, Error> for KeySet {
    fn pk(&mut self, key: &Bip388Key) -> Result<DescriptorPublicKey, Error> {
        let root = self
            .keys
            .get(key.index as usize)
            .ok_or(Error::WalletPolicy)?;
        let (origin, xkey) = match root {
            DescriptorPublicKey::XPub(k) => (k.origin.clone(), k.xkey),
            DescriptorPublicKey::MultiXPub(k) => (k.origin.clone(), k.xkey),
            DescriptorPublicKey::Single(_) => return Err(Error::WalletPolicy),
        };
        let paths = key.derivation_paths.paths();
        let dpk = if paths.len() == 1 {
            DescriptorPublicKey::XPub(DescriptorXKey {
                origin,
                xkey,
                derivation_path: paths[0].clone(),
                wildcard: key.wildcard,
            })
        } else {
            DescriptorPublicKey::MultiXPub(DescriptorMultiXKey {
                origin,
                xkey,
                derivation_paths: key.derivation_paths.clone(),
                wildcard: key.wildcard,
            })
        };
        Ok(dpk)
    }

    fn sha256(&mut self, h: &sha256::Hash) -> Result<sha256::Hash, Error> {
        Ok(*h)
    }
    fn hash256(&mut self, h: &hash256::Hash) -> Result<hash256::Hash, Error> {
        Ok(*h)
    }
    fn ripemd160(&mut self, h: &ripemd160::Hash) -> Result<ripemd160::Hash, Error> {
        Ok(*h)
    }
    fn hash160(&mut self, h: &hash160::Hash) -> Result<hash160::Hash, Error> {
        Ok(*h)
    }
}

impl<E> From<TranslateErr<E>> for Error
where
    Error: From<E>,
{
    fn from(value: TranslateErr<E>) -> Self {
        match value {
            TranslateErr::TranslatorErr(e) => Error::from(e),
            TranslateErr::OuterError(_) => Error::WalletPolicy,
        }
    }
}

/// A BIP388 wallet policy: a descriptor template plus its key info vector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WalletPolicy {
    pub template: Descriptor<Bip388Key>,
    pub key_info: Vec<DescriptorPublicKey>,
}

/// BIP388 requires the placeholder indices to first appear in order `@0, @1,
/// ...` with no gaps; a later repeat of an already-introduced index is allowed.
fn check_key_order(template: &Descriptor<Bip388Key>) -> Result<(), Error> {
    let mut next = 0u32;
    let ordered = template.for_each_key(|k| {
        if k.index == next {
            next += 1;
            true
        } else {
            k.index < next
        }
    });
    if ordered {
        Ok(())
    } else {
        Err(Error::WalletPolicy)
    }
}

impl WalletPolicy {
    /// Build a wallet policy from a concrete descriptor.
    pub fn from_descriptor(d: &Descriptor<DescriptorPublicKey>) -> Result<Self, Error> {
        let mut translator = KeySet { keys: vec![] };
        let template = d.translate_pk(&mut translator)?;
        check_key_order(&template)?;
        Ok(WalletPolicy {
            template,
            key_info: translator.keys,
        })
    }

    /// Rebuild the concrete descriptor from this wallet policy.
    pub fn into_descriptor(self) -> Result<Descriptor<DescriptorPublicKey>, Error> {
        check_key_order(&self.template)?;
        let mut translator = KeySet {
            keys: self.key_info,
        };
        Ok(self.template.translate_pk(&mut translator)?)
    }
}

impl Display for WalletPolicy {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.template)
    }
}

impl FromStr for WalletPolicy {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let template = Descriptor::<Bip388Key>::from_str(s).map_err(|_| Error::WalletPolicy)?;
        check_key_order(&template)?;
        Ok(WalletPolicy {
            template,
            key_info: vec![],
        })
    }
}

#[cfg(all(test, feature = "descriptor_backup"))]
mod tests {
    use super::*;

    const KEY_WPKH: &str = "[6738736c/84'/0'/2']xpub6CRQzb8u9dmMcq5XAwwRn9gcoYCjndJkhKgD11WKzbVGd932UmrExWFxCAvRnDN3ez6ZujLmMvmLBaSWdfWVn75L83Qxu1qSX4fJNrJg2Gt";
    const KEY_M0: &str = "[6738736c/48'/0'/0'/2']xpub6FC1fXFP1GXLX5TKtcjHGT4q89SDRehkQLtbKJ2PzWcvbBHtyDsJPLtpLtkGqYNYZdVVAjRQ5kug9CsapegmmeRutpP7PW4u4wVF9JfkDhw";
    const KEY_M1: &str = "[b2b1f0cf/48'/0'/0'/2']xpub6EWhjpPa6FqrcaPBuGBZRJVjzGJ1ZsMygRF26RwN932Vfkn1gyCiTbECVitBjRCkexEvetLdiqzTcYimmzYxyR1BZ79KNevgt61PDcukmC7";

    fn dpk(s: &str) -> DescriptorPublicKey {
        DescriptorPublicKey::from_str(s).unwrap()
    }

    fn descr(s: &str) -> Descriptor<DescriptorPublicKey> {
        Descriptor::<DescriptorPublicKey>::from_str(s).unwrap()
    }

    /// Strip a trailing `#checksum` from a descriptor string.
    fn no_checksum(s: &str) -> String {
        match s.rsplit_once('#') {
            Some((body, _)) => body.to_string(),
            None => s.to_string(),
        }
    }

    /// Check one conversion vector: the template round-trips through the parser,
    /// the descriptor converts to that (template, key info), and rebuilds back.
    fn check_vector(desc: &str, template: &str, key_info: &[&str], descriptor: &str) {
        let parsed = Descriptor::<Bip388Key>::from_str(template).unwrap();
        assert_eq!(
            no_checksum(&parsed.to_string()),
            template,
            "{desc}: template parse"
        );

        let wp = WalletPolicy::from_descriptor(&descr(descriptor)).unwrap();
        assert_eq!(
            no_checksum(&wp.template.to_string()),
            template,
            "{desc}: template"
        );
        let expected: Vec<DescriptorPublicKey> = key_info.iter().map(|s| dpk(s)).collect();
        assert_eq!(wp.key_info, expected, "{desc}: key info");

        let rebuilt = wp.into_descriptor().unwrap();
        assert_eq!(
            no_checksum(&rebuilt.to_string()),
            no_checksum(descriptor),
            "{desc}: rebuilt descriptor"
        );
    }

    #[test]
    fn conversion_vectors() {
        #[derive(serde::Deserialize)]
        struct Vector {
            description: String,
            template: String,
            key_info: Vec<String>,
            descriptor: String,
        }
        const VECTORS: &str = include_str!("../test_vectors/bip388_wallet_policy.json");
        let vectors: Vec<Vector> = serde_json::from_str(VECTORS).unwrap();
        assert!(!vectors.is_empty());
        for v in vectors {
            let keys: Vec<&str> = v.key_info.iter().map(|s| s.as_str()).collect();
            check_vector(&v.description, &v.template, &keys, &v.descriptor);
        }
    }

    #[test]
    fn same_root_different_path() {
        // One key reused as @0/<0;1>/* and @0/<2;3>/* collapses to a single
        // key info entry, with the two distinct suffixes preserved.
        let xpub = "xpub6FC1fXFP1GXLX5TKtcjHGT4q89SDRehkQLtbKJ2PzWcvbBHtyDsJPLtpLtkGqYNYZdVVAjRQ5kug9CsapegmmeRutpP7PW4u4wVF9JfkDhw";
        let descriptor = alloc::format!(
            "wsh(multi(2,[6738736c/48'/0'/0'/2']{xpub}/<0;1>/*,[6738736c/48'/0'/0'/2']{xpub}/<2;3>/*))"
        );
        let full = descr(&descriptor);
        let wp = WalletPolicy::from_descriptor(&full).unwrap();
        assert_eq!(wp.key_info.len(), 1, "same root deduped");
        assert_eq!(
            no_checksum(&wp.template.to_string()),
            "wsh(multi(2,@0/**,@0/<2;3>/*))"
        );
        let rebuilt = wp.into_descriptor().unwrap();
        assert_eq!(no_checksum(&rebuilt.to_string()), descriptor);
    }

    #[test]
    fn single_literal_key_errors() {
        let descriptor =
            descr("pkh(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)");
        let err = WalletPolicy::from_descriptor(&descriptor).unwrap_err();
        assert_eq!(err, Error::WalletPolicy);
    }

    #[test]
    fn key_order_out_of_order_rejected() {
        // @1 introduced before @0.
        let err = WalletPolicy::from_str("wsh(multi(2,@1/**,@0/**))").unwrap_err();
        assert_eq!(err, Error::WalletPolicy);
    }

    #[test]
    fn key_order_gap_rejected() {
        // @1 with no @0.
        let err = WalletPolicy::from_str("wpkh(@1/**)").unwrap_err();
        assert_eq!(err, Error::WalletPolicy);
    }

    #[test]
    fn key_order_repeat_allowed() {
        // @0 reused at a later position (different path) is in order.
        WalletPolicy::from_str("wsh(multi(2,@0/**,@0/<2;3>/*))").unwrap();
    }

    #[test]
    fn into_descriptor_rejects_out_of_order() {
        // A struct literal bypasses from_str, so into_descriptor must also check.
        let template = Descriptor::<Bip388Key>::from_str("wsh(multi(2,@1/**,@0/**))").unwrap();
        let wp = WalletPolicy {
            template,
            key_info: vec![dpk(KEY_M0), dpk(KEY_M1)],
        };
        assert_eq!(wp.into_descriptor().unwrap_err(), Error::WalletPolicy);
    }

    #[test]
    fn placeholder_out_of_range_errors() {
        let wp = WalletPolicy {
            template: Descriptor::<Bip388Key>::from_str("wpkh(@1/**)").unwrap(),
            key_info: vec![dpk(KEY_WPKH)],
        };
        let err = wp.into_descriptor().unwrap_err();
        assert_eq!(err, Error::WalletPolicy);
    }

    #[test]
    fn bip388_key_display_variants() {
        // /** is the default multipath suffix.
        let k = Bip388Key::from_str("@0/**").unwrap();
        assert_eq!(k.to_string(), "@0/**");
        // A non-default 2-path multipath renders as /<a;b>/*.
        let k = Bip388Key::from_str("@2/<2;3>/*").unwrap();
        assert_eq!(k.to_string(), "@2/<2;3>/*");
        // A single fixed path renders as /<path>/*.
        let k = Bip388Key::from_str("@1/0/*").unwrap();
        assert_eq!(k.to_string(), "@1/0/*");
    }

    #[test]
    fn bip388_key_from_str_rejects() {
        // No leading @.
        assert!(Bip388Key::from_str("0/**").is_err());
        // No wildcard.
        assert!(Bip388Key::from_str("@0/0").is_err());
        // Empty.
        assert!(Bip388Key::from_str("").is_err());
        // No index digits.
        assert!(Bip388Key::from_str("@/**").is_err());
    }

    #[test]
    fn wallet_policy_from_str_empty_key_info() {
        let wp = WalletPolicy::from_str("wsh(sortedmulti(2,@0/**,@1/**))").unwrap();
        assert!(wp.key_info.is_empty());
        assert_eq!(
            no_checksum(&wp.to_string()),
            "wsh(sortedmulti(2,@0/**,@1/**))"
        );
    }

    #[test]
    fn arbitrary_multipath() {
        // A non-default multipath (not <0;1>) is the key's only path: it renders
        // explicitly as /<a;b>/* (never /**) and round-trips both ways.
        let xpub = "[6738736c/84'/0'/2']xpub6CRQzb8u9dmMcq5XAwwRn9gcoYCjndJkhKgD11WKzbVGd932UmrExWFxCAvRnDN3ez6ZujLmMvmLBaSWdfWVn75L83Qxu1qSX4fJNrJg2Gt";
        for paths in ["<1;2>", "<2;3>"] {
            let descriptor = alloc::format!("wpkh({xpub}/{paths}/*)");
            let wp = WalletPolicy::from_descriptor(&descr(&descriptor)).unwrap();
            assert_eq!(
                no_checksum(&wp.template.to_string()),
                alloc::format!("wpkh(@0/{paths}/*)")
            );
            assert_eq!(wp.key_info, vec![dpk(xpub)]);
            assert_eq!(
                no_checksum(&wp.into_descriptor().unwrap().to_string()),
                descriptor
            );
        }
    }
}
