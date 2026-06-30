//! BIP380 descriptor backup documents, behind the `descriptor_backup` feature.
//! The plaintext of a BIP380 backup is a UTF-8 JSON document; a bare descriptor
//! string is rejected.
//!
//! Private key material needs no explicit check: `Descriptor<DescriptorPublicKey>`
//! cannot hold an xprv, so an xprv string is rejected at parse by the type.

use alloc::{boxed::Box, collections::BTreeSet, vec::Vec};

use serde::{Deserialize, Serialize};

use crate::{
    Content, Decrypted, Error, ToPayload, Warning,
    descriptor::{descr_to_dpks, descr_warnings, dpks_to_derivation_keys_paths},
    miniscript::{
        Descriptor, DescriptorPublicKey,
        bitcoin::{bip32::DerivationPath, secp256k1},
    },
};

/// Document version defined by this specification.
const VERSION: u32 = 1;

// `Descriptor`/`DescriptorPublicKey` serialize as strings via miniscript's serde
// feature, so the typed structs are the wire format directly. Cross-field rules
// are checked in `validate()` after deserialization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DescriptorBackup {
    pub version: u32,
    pub descriptor_sets: Vec<DescriptorSet>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DescriptorSet {
    pub descriptor: Descriptor<DescriptorPublicKey>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_descriptor: Option<Descriptor<DescriptorPublicKey>>,
    #[serde(default, skip_serializing_if = "core::ops::Not::not")]
    pub archived: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub range: Option<(u32, u32)>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub birth_time: Option<u64>,
}

/// Parse a BIP380 descriptor backup document. It is always JSON; a bare
/// descriptor string (no leading `{`) is rejected.
pub fn parse_descriptor_backup(bytes: &[u8]) -> Result<DescriptorBackup, Error> {
    let text = core::str::from_utf8(bytes).map_err(|_| Error::Utf8)?;
    if !text.starts_with('{') {
        return Err(Error::DescriptorBackup);
    }
    let backup: DescriptorBackup =
        serde_json::from_str(text).map_err(|_| Error::DescriptorBackup)?;
    backup.validate()?;
    Ok(backup)
}

impl DescriptorBackup {
    /// Reject documents the parser must not accept: wrong version, no sets, or a
    /// multipath descriptor paired with a separate change_descriptor.
    fn validate(&self) -> Result<(), Error> {
        if self.version != VERSION || self.descriptor_sets.is_empty() {
            return Err(Error::DescriptorBackup);
        }
        for set in &self.descriptor_sets {
            if set.descriptor.is_multipath() && set.change_descriptor.is_some() {
                return Err(Error::DescriptorBackup);
            }
        }
        Ok(())
    }

    /// Encode as a JSON document.
    pub fn to_json(&self) -> Result<Vec<u8>, Error> {
        serde_json::to_vec(self).map_err(|_| Error::DescriptorBackup)
    }

    /// Every descriptor and change_descriptor across all sets.
    fn descriptors(&self) -> impl Iterator<Item = &Descriptor<DescriptorPublicKey>> {
        self.descriptor_sets
            .iter()
            .flat_map(|set| core::iter::once(&set.descriptor).chain(set.change_descriptor.as_ref()))
    }
}

impl ToPayload for DescriptorBackup {
    fn to_payload(&self) -> Result<Vec<u8>, Error> {
        self.to_json()
    }

    fn content_type(&self) -> Content {
        Content::Bip380
    }

    fn derivation_paths(&self) -> Result<Vec<DerivationPath>, Error> {
        let mut paths = BTreeSet::new();
        for descriptor in self.descriptors() {
            let dpks = descr_to_dpks(descriptor)?;
            let (_, p) = dpks_to_derivation_keys_paths(&dpks);
            paths.extend(p);
        }
        Ok(paths.into_iter().collect())
    }

    fn keys(&self) -> Result<Vec<secp256k1::PublicKey>, Error> {
        let mut keys = BTreeSet::new();
        for descriptor in self.descriptors() {
            let dpks = descr_to_dpks(descriptor)?;
            let (k, _) = dpks_to_derivation_keys_paths(&dpks);
            keys.extend(k);
        }
        Ok(keys.into_iter().collect())
    }

    fn warnings(&self) -> Result<Vec<Warning>, Error> {
        let mut warnings = Vec::new();
        for descriptor in self.descriptors() {
            for w in descr_warnings(descriptor)? {
                if !warnings.contains(&w) {
                    warnings.push(w);
                }
            }
        }
        Ok(warnings)
    }
}

impl From<DescriptorBackup> for Decrypted {
    fn from(value: DescriptorBackup) -> Self {
        Decrypted::DescriptorBackup(Box::new(value))
    }
}

#[cfg(all(test, feature = "descriptor_backup"))]
mod tests {
    use super::*;
    use alloc::{string::String, vec};
    use core::str::FromStr;

    const MULTIPATH: &str = "wpkh([d34db33f/84h/1h/0h]tpubDC5FSnBiZDMmhiuCmWAYsLwgLYrrT9rAqvTySfuCCrgsWz8wxMXUS9Tb9iVMvcRbvFcAHGkMD5Kx8koh4GquNGNTfohfk7pgjhaPCdXpoba/<0;1>/*)";
    const RECEIVE: &str = "wpkh([d34db33f/84h/1h/0h]tpubDC5FSnBiZDMmhiuCmWAYsLwgLYrrT9rAqvTySfuCCrgsWz8wxMXUS9Tb9iVMvcRbvFcAHGkMD5Kx8koh4GquNGNTfohfk7pgjhaPCdXpoba/0/*)";
    const CHANGE: &str = "wpkh([d34db33f/84h/1h/0h]tpubDC5FSnBiZDMmhiuCmWAYsLwgLYrrT9rAqvTySfuCCrgsWz8wxMXUS9Tb9iVMvcRbvFcAHGkMD5Kx8koh4GquNGNTfohfk7pgjhaPCdXpoba/1/*)";

    fn descr(s: &str) -> Descriptor<DescriptorPublicKey> {
        Descriptor::<DescriptorPublicKey>::from_str(s).unwrap()
    }

    #[test]
    fn bare_descriptor_string_errors() {
        // Only JSON documents are valid; a bare descriptor (even multipath) fails.
        for s in [MULTIPATH, RECEIVE] {
            let err = parse_descriptor_backup(s.as_bytes()).unwrap_err();
            assert_eq!(err, Error::DescriptorBackup);
        }
    }

    #[test]
    fn json_detected_by_brace() {
        let doc = alloc::format!(
            "{{\"version\":1,\"descriptor_sets\":[{{\"descriptor\":\"{MULTIPATH}\"}}]}}"
        );
        let backup = parse_descriptor_backup(doc.as_bytes()).unwrap();
        assert_eq!(backup.version, 1);
        assert_eq!(backup.descriptor_sets.len(), 1);
        assert_eq!(backup.descriptor_sets[0].descriptor, descr(MULTIPATH));
    }

    #[test]
    fn json_multipath_set() {
        let doc = alloc::format!(
            "{{\"version\":1,\"descriptor_sets\":[{{\"descriptor\":\"{MULTIPATH}\",\"archived\":false}}]}}"
        );
        let backup = parse_descriptor_backup(doc.as_bytes()).unwrap();
        let set = &backup.descriptor_sets[0];
        assert_eq!(set.descriptor, descr(MULTIPATH));
        assert!(set.change_descriptor.is_none());
    }

    #[test]
    fn json_non_multipath_with_change() {
        let doc = alloc::format!(
            "{{\"version\":1,\"descriptor_sets\":[{{\"descriptor\":\"{RECEIVE}\",\"change_descriptor\":\"{CHANGE}\"}}]}}"
        );
        let backup = parse_descriptor_backup(doc.as_bytes()).unwrap();
        let set = &backup.descriptor_sets[0];
        assert_eq!(set.descriptor, descr(RECEIVE));
        assert_eq!(set.change_descriptor, Some(descr(CHANGE)));
    }

    #[test]
    fn json_metadata_fields() {
        let doc = alloc::format!(
            "{{\"version\":1,\"descriptor_sets\":[{{\"descriptor\":\"{MULTIPATH}\",\"archived\":true,\"range\":[0,999],\"birth_time\":1710000000}}]}}"
        );
        let backup = parse_descriptor_backup(doc.as_bytes()).unwrap();
        let set = &backup.descriptor_sets[0];
        assert!(set.archived);
        assert_eq!(set.range, Some((0, 999)));
        assert_eq!(set.birth_time, Some(1710000000));
    }

    #[test]
    fn json_version_not_one_errors() {
        let doc = alloc::format!(
            "{{\"version\":2,\"descriptor_sets\":[{{\"descriptor\":\"{MULTIPATH}\"}}]}}"
        );
        let err = parse_descriptor_backup(doc.as_bytes()).unwrap_err();
        assert_eq!(err, Error::DescriptorBackup);
    }

    #[test]
    fn json_multipath_with_change_errors() {
        let doc = alloc::format!(
            "{{\"version\":1,\"descriptor_sets\":[{{\"descriptor\":\"{MULTIPATH}\",\"change_descriptor\":\"{CHANGE}\"}}]}}"
        );
        let err = parse_descriptor_backup(doc.as_bytes()).unwrap_err();
        assert_eq!(err, Error::DescriptorBackup);
    }

    #[test]
    fn json_missing_descriptor_errors() {
        let doc = "{\"version\":1,\"descriptor_sets\":[{\"archived\":true}]}";
        let err = parse_descriptor_backup(doc.as_bytes()).unwrap_err();
        assert_eq!(err, Error::DescriptorBackup);
    }

    #[test]
    fn to_payload_is_json() {
        let backup = DescriptorBackup {
            version: 1,
            descriptor_sets: vec![DescriptorSet {
                descriptor: descr(RECEIVE),
                change_descriptor: Some(descr(CHANGE)),
                archived: true,
                range: Some((0, 999)),
                birth_time: Some(1710000000),
            }],
        };
        let payload = backup.to_payload().unwrap();
        assert_eq!(payload, backup.to_json().unwrap());
        assert_eq!(parse_descriptor_backup(&payload).unwrap(), backup);
    }

    #[test]
    fn json_test_vectors() {
        const JSON_VECTORS: &str = include_str!("../test_vectors/bip380_descriptor_backup.json");

        #[derive(Deserialize)]
        struct JsonVector {
            description: String,
            valid: bool,
            document: serde_json::Value,
        }

        let vectors: Vec<JsonVector> = serde_json::from_str(JSON_VECTORS).unwrap();
        assert!(!vectors.is_empty());
        for v in vectors {
            let bytes = serde_json::to_vec(&v.document).unwrap();
            let parsed = parse_descriptor_backup(&bytes);
            assert_eq!(parsed.is_ok(), v.valid, "{}", v.description);
            if let Ok(backup) = parsed {
                let payload = backup.to_payload().unwrap();
                assert_eq!(
                    parse_descriptor_backup(&payload).unwrap(),
                    backup,
                    "{}",
                    v.description
                );
            }
        }
    }
}
