//! BIP388 wallet policy backup documents (JSON only), behind the
//! `descriptor_backup` feature. A wallet policy is a descriptor template with
//! `@i` placeholders plus a key information vector of `[origin]xpub` entries.
//!
//! miniscript 12.3.5 has no BIP388 parser, so the template stays an opaque
//! string and is never compiled. The key vector is typed, which validates each
//! entry. The xpub roots are safe encryption keys here: the template's `/**`
//! guarantees the root never goes on-chain.

use alloc::{boxed::Box, collections::BTreeSet, string::String, vec::Vec};
use core::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::{
    descriptor::{bip341_nums, dpk_to_deriv_path},
    miniscript::{
        bitcoin::{bip32::DerivationPath, secp256k1},
        Descriptor, DescriptorPublicKey,
    },
    wallet_policy::WalletPolicy,
    Content, Decrypted, Error, ToPayload, Warning,
};

/// Document version defined by this specification.
const VERSION: u32 = 1;

// `DescriptorPublicKey` serializes as a string via miniscript's serde feature, so
// these typed structs are the wire format directly. The `keys` entries are
// validated (xpub-only, non-empty) in `validate()` after deserialization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyBackup {
    pub version: u32,
    pub policy_sets: Vec<PolicySet>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicySet {
    pub keys: Vec<DescriptorPublicKey>,
    pub policy: String,
    #[serde(default, skip_serializing_if = "core::ops::Not::not")]
    pub archived: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub range: Option<(u32, u32)>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub birth_time: Option<u64>,
}

impl PolicySet {
    /// A set with no metadata round-trips to the single `{keys, policy}` form.
    fn is_bare(&self) -> bool {
        !self.archived && self.range.is_none() && self.birth_time.is_none()
    }

    /// Build a policy set from a concrete descriptor: the template string and
    /// its key info vector, with no metadata. The template is stored without the
    /// descriptor checksum, matching the BIP388 wire form.
    pub fn from_descriptor(d: &Descriptor<DescriptorPublicKey>) -> Result<Self, Error> {
        let wp = WalletPolicy::from_descriptor(d)?;
        let mut policy = wp.template.to_string();
        if let Some(pos) = policy.rfind('#') {
            policy.truncate(pos);
        }
        Ok(PolicySet {
            keys: wp.key_info,
            policy,
            archived: false,
            range: None,
            birth_time: None,
        })
    }

    /// Rebuild the concrete descriptor from the policy template and keys.
    pub fn to_descriptor(&self) -> Result<Descriptor<DescriptorPublicKey>, Error> {
        let template = Descriptor::from_str(&self.policy).map_err(|_| Error::WalletPolicy)?;
        WalletPolicy {
            template,
            key_info: self.keys.clone(),
        }
        .into_descriptor()
    }
}

/// Parse a BIP388 wallet policy backup document. Always JSON: the single form
/// `{keys, policy}` or the multiple form `{version, policy_sets}`.
pub fn parse_policy_backup(bytes: &[u8]) -> Result<PolicyBackup, Error> {
    let text = core::str::from_utf8(bytes).map_err(|_| Error::Utf8)?;
    if !text.starts_with('{') {
        return Err(Error::DescriptorBackup);
    }
    let value: serde_json::Value =
        serde_json::from_str(text).map_err(|_| Error::DescriptorBackup)?;
    let object = value.as_object().ok_or(Error::DescriptorBackup)?;
    let backup = if object.contains_key("policy_sets") {
        serde_json::from_value(value).map_err(|_| Error::DescriptorBackup)?
    } else if object.contains_key("policy") {
        let set: PolicySet = serde_json::from_value(value).map_err(|_| Error::DescriptorBackup)?;
        PolicyBackup {
            version: VERSION,
            policy_sets: alloc::vec![set],
        }
    } else {
        return Err(Error::DescriptorBackup);
    };
    backup.validate()?;
    Ok(backup)
}

/// Root pubkey of a key info entry. Bare xpubs are valid here, so this reads
/// `xkey.public_key` directly instead of reusing `dpk_to_pk`.
fn key_root(key: &DescriptorPublicKey) -> Result<secp256k1::PublicKey, Error> {
    match key {
        DescriptorPublicKey::XPub(k) => Ok(k.xkey.public_key),
        DescriptorPublicKey::MultiXPub(k) => Ok(k.xkey.public_key),
        DescriptorPublicKey::Single(_) => Err(Error::DescriptorBackup),
    }
}

impl PolicyBackup {
    /// Reject documents the parser must not accept: wrong version, no sets, an
    /// empty key vector or policy, or a `Single` literal pubkey in the keys.
    fn validate(&self) -> Result<(), Error> {
        if self.version != VERSION || self.policy_sets.is_empty() {
            return Err(Error::DescriptorBackup);
        }
        for set in &self.policy_sets {
            if set.keys.is_empty() || set.policy.is_empty() {
                return Err(Error::DescriptorBackup);
            }
            if set
                .keys
                .iter()
                .any(|k| matches!(k, DescriptorPublicKey::Single(_)))
            {
                return Err(Error::DescriptorBackup);
            }
        }
        Ok(())
    }

    /// Encode as a JSON document. Always the multiple `{version, policy_sets}`
    /// form; [`ToPayload::to_payload`] chooses the wire shape.
    pub fn to_json(&self) -> Result<Vec<u8>, Error> {
        serde_json::to_vec(self).map_err(|_| Error::DescriptorBackup)
    }

    /// True when the single `{keys, policy}` form can represent the document
    /// without losing data: exactly one set with no metadata.
    fn is_single(&self) -> bool {
        self.version == VERSION && self.policy_sets.len() == 1 && self.policy_sets[0].is_bare()
    }

    fn to_single_json(&self) -> Result<Vec<u8>, Error> {
        serde_json::to_vec(&self.policy_sets[0]).map_err(|_| Error::DescriptorBackup)
    }

    fn all_keys(&self) -> impl Iterator<Item = &DescriptorPublicKey> {
        self.policy_sets.iter().flat_map(|set| set.keys.iter())
    }
}

impl ToPayload for PolicyBackup {
    fn to_payload(&self) -> Result<Vec<u8>, Error> {
        if self.is_single() {
            self.to_single_json()
        } else {
            self.to_json()
        }
    }

    fn content_type(&self) -> Content {
        Content::Bip388
    }

    fn derivation_paths(&self) -> Result<Vec<DerivationPath>, Error> {
        let mut paths = BTreeSet::new();
        for key in self.all_keys() {
            if let Some(path) = dpk_to_deriv_path(key) {
                paths.insert(path);
            }
        }
        Ok(paths.into_iter().collect())
    }

    fn keys(&self) -> Result<Vec<secp256k1::PublicKey>, Error> {
        let mut keys = BTreeSet::new();
        for key in self.all_keys() {
            keys.insert(key_root(key)?);
        }
        Ok(keys.into_iter().collect())
    }

    fn warnings(&self) -> Result<Vec<Warning>, Error> {
        let nums_xonly = bip341_nums().x_only_public_key().0;
        let mut warnings = Vec::new();
        for key in self.all_keys() {
            if key_root(key)?.x_only_public_key().0 == nums_xonly {
                let w = Warning::NumsKey(key.clone());
                if !warnings.contains(&w) {
                    warnings.push(w);
                }
            }
        }
        Ok(warnings)
    }
}

impl From<PolicyBackup> for Decrypted {
    fn from(value: PolicyBackup) -> Self {
        Decrypted::PolicyBackup(Box::new(value))
    }
}

#[cfg(all(test, feature = "descriptor_backup"))]
mod tests {
    use super::*;
    use alloc::{string::ToString, vec};
    use core::str::FromStr;

    const KEY0: &str = "[6738736c/48'/0'/0'/2']xpub6FC1fXFP1GXLX5TKtcjHGT4q89SDRehkQLtbKJ2PzWcvbBHtyDsJPLtpLtkGqYNYZdVVAjRQ5kug9CsapegmmeRutpP7PW4u4wVF9JfkDhw";
    const KEY1: &str = "[b2b1f0cf/48'/0'/0'/2']xpub6EWhjpPa6FqrcaPBuGBZRJVjzGJ1ZsMygRF26RwN932Vfkn1gyCiTbECVitBjRCkexEvetLdiqzTcYimmzYxyR1BZ79KNevgt61PDcukmC7";
    const KEY_PKH: &str = "[d34db33f/44'/0'/0']xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL";

    fn key(s: &str) -> DescriptorPublicKey {
        DescriptorPublicKey::from_str(s).unwrap()
    }

    fn single() -> PolicyBackup {
        PolicyBackup {
            version: 1,
            policy_sets: vec![PolicySet {
                keys: vec![key(KEY_PKH)],
                policy: "pkh(@0/**)".to_string(),
                archived: false,
                range: None,
                birth_time: None,
            }],
        }
    }

    fn multiple() -> PolicyBackup {
        PolicyBackup {
            version: 1,
            policy_sets: vec![
                PolicySet {
                    keys: vec![key(KEY0), key(KEY1)],
                    policy: "wsh(sortedmulti(2,@0/**,@1/**))".to_string(),
                    archived: true,
                    range: Some((0, 999)),
                    birth_time: Some(1710000000),
                },
                PolicySet {
                    keys: vec![key(KEY_PKH)],
                    policy: "pkh(@0/**)".to_string(),
                    archived: false,
                    range: None,
                    birth_time: None,
                },
            ],
        }
    }

    #[test]
    fn parse_single_form() {
        let doc = "{\"keys\":[\"".to_string() + KEY_PKH + "\"],\"policy\":\"pkh(@0/**)\"}";
        let backup = parse_policy_backup(doc.as_bytes()).unwrap();
        assert_eq!(backup, single());
        assert_eq!(backup.policy_sets.len(), 1);
    }

    #[test]
    fn parse_multiple_form() {
        let bytes = multiple().to_json().unwrap();
        assert_eq!(parse_policy_backup(&bytes).unwrap(), multiple());
    }

    #[test]
    fn non_json_errors() {
        let err = parse_policy_backup(b"pkh(@0/**)").unwrap_err();
        assert_eq!(err, Error::DescriptorBackup);
    }

    #[test]
    fn shapeless_object_errors() {
        let err = parse_policy_backup(b"{\"foo\":1}").unwrap_err();
        assert_eq!(err, Error::DescriptorBackup);
    }

    #[test]
    fn version_not_one_errors() {
        let backup = PolicyBackup {
            version: 2,
            policy_sets: single().policy_sets,
        };
        let bytes = serde_json::to_vec(&backup).unwrap();
        let err = parse_policy_backup(&bytes).unwrap_err();
        assert_eq!(err, Error::DescriptorBackup);
    }

    #[test]
    fn missing_policy_errors() {
        let doc = "{\"keys\":[\"".to_string() + KEY_PKH + "\"]}";
        let err = parse_policy_backup(doc.as_bytes()).unwrap_err();
        assert_eq!(err, Error::DescriptorBackup);
    }

    #[test]
    fn empty_policy_errors() {
        let doc = "{\"keys\":[\"".to_string() + KEY_PKH + "\"],\"policy\":\"\"}";
        let err = parse_policy_backup(doc.as_bytes()).unwrap_err();
        assert_eq!(err, Error::DescriptorBackup);
    }

    #[test]
    fn empty_keys_errors() {
        let doc = "{\"keys\":[],\"policy\":\"pkh(@0/**)\"}";
        let err = parse_policy_backup(doc.as_bytes()).unwrap_err();
        assert_eq!(err, Error::DescriptorBackup);
    }

    #[test]
    fn single_literal_key_errors() {
        let doc =
            "{\"keys\":[\"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798\"],\"policy\":\"pkh(@0/**)\"}";
        let err = parse_policy_backup(doc.as_bytes()).unwrap_err();
        assert_eq!(err, Error::DescriptorBackup);
    }

    #[test]
    fn to_payload_single_form() {
        let backup = single();
        let payload = backup.to_payload().unwrap();
        assert_eq!(payload, backup.to_single_json().unwrap());
        assert_eq!(parse_policy_backup(&payload).unwrap(), backup);
    }

    #[test]
    fn to_payload_multiple_form() {
        let backup = multiple();
        let payload = backup.to_payload().unwrap();
        assert_eq!(payload, backup.to_json().unwrap());
        assert_eq!(parse_policy_backup(&payload).unwrap(), backup);
    }

    #[test]
    fn keys_deduped_across_sets() {
        let backup = PolicyBackup {
            version: 1,
            policy_sets: vec![
                PolicySet {
                    keys: vec![key(KEY_PKH)],
                    policy: "pkh(@0/**)".to_string(),
                    archived: false,
                    range: None,
                    birth_time: None,
                },
                PolicySet {
                    keys: vec![key(KEY_PKH)],
                    policy: "wpkh(@0/**)".to_string(),
                    archived: false,
                    range: None,
                    birth_time: None,
                },
            ],
        };
        assert_eq!(backup.keys().unwrap().len(), 1);
    }

    #[test]
    fn json_test_vectors() {
        const VECTORS: &str = include_str!("../test_vectors/bip388.json");

        #[derive(Deserialize)]
        struct JsonVector {
            description: String,
            valid: bool,
            document: serde_json::Value,
        }

        let vectors: Vec<JsonVector> = serde_json::from_str(VECTORS).unwrap();
        assert!(!vectors.is_empty());
        for v in vectors {
            let bytes = serde_json::to_vec(&v.document).unwrap();
            let parsed = parse_policy_backup(&bytes);
            assert_eq!(parsed.is_ok(), v.valid, "{}", v.description);
            if let Ok(backup) = parsed {
                let payload = backup.to_payload().unwrap();
                assert_eq!(
                    parse_policy_backup(&payload).unwrap(),
                    backup,
                    "{}",
                    v.description
                );
            }
        }
    }

    #[test]
    fn policy_set_descriptor_roundtrip() {
        let descriptor = Descriptor::<DescriptorPublicKey>::from_str(
            "wsh(sortedmulti(2,[6738736c/48'/0'/0'/2']xpub6FC1fXFP1GXLX5TKtcjHGT4q89SDRehkQLtbKJ2PzWcvbBHtyDsJPLtpLtkGqYNYZdVVAjRQ5kug9CsapegmmeRutpP7PW4u4wVF9JfkDhw/<0;1>/*,[b2b1f0cf/48'/0'/0'/2']xpub6EWhjpPa6FqrcaPBuGBZRJVjzGJ1ZsMygRF26RwN932Vfkn1gyCiTbECVitBjRCkexEvetLdiqzTcYimmzYxyR1BZ79KNevgt61PDcukmC7/<0;1>/*))",
        )
        .unwrap();
        let set = PolicySet::from_descriptor(&descriptor).unwrap();
        assert_eq!(set.policy, "wsh(sortedmulti(2,@0/**,@1/**))");
        assert_eq!(set.keys, vec![key(KEY0), key(KEY1)]);
        assert!(set.is_bare());

        let rebuilt = set.to_descriptor().unwrap();
        let strip = |s: &str| s.rsplit_once('#').map(|(b, _)| b.to_string());
        assert_eq!(strip(&rebuilt.to_string()), strip(&descriptor.to_string()));
    }
}
