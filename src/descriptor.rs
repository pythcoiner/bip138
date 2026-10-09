extern crate alloc;

use alloc::{collections::BTreeSet, vec::Vec};

use crate::{
    Error, Warning,
    backend::{Active, Backend, DerivationPath, Descriptor, DescriptorKey, KeyExpr, PublicKey},
};

/// Internal-only x-only normalization used by NUMS and exposed key detection.
/// Bypasses the allow/disallow check intentionally so a NUMS literal in tr()
/// is reported as Warning::NumsKey rather than DisallowedKeyExpression.
fn xonly_of(key: &DescriptorKey) -> [u8; 32] {
    match Active::classify(key) {
        KeyExpr::Literal { xonly, .. } => xonly,
        KeyExpr::XPub { root, .. } => Active::xonly(&root),
    }
}

/// Root public key of an xpub expression, ignoring any trailing derivation.
///
/// Unlike [`dpk_to_pk`], a bare xpub is accepted: the trailing derivation does not change
/// the root public key. That rule gates which keys may *encrypt* a backup, so it must not
/// reject a key offered to decrypt one.
pub fn dpk_to_root_pk(key: &DescriptorKey) -> Result<PublicKey, Error> {
    match Active::classify(key) {
        KeyExpr::XPub { root, .. } => Ok(root),
        KeyExpr::Literal { .. } => Err(Error::InvalidKeyExpression),
    }
}

pub fn dpk_to_pk(key: &DescriptorKey) -> Result<PublicKey, Error> {
    match Active::classify(key) {
        KeyExpr::XPub {
            root,
            derived: true,
            ..
        } => Ok(root),
        KeyExpr::XPub { derived: false, .. } | KeyExpr::Literal { .. } => {
            Err(Error::InvalidKeyExpression)
        }
    }
}

pub(crate) fn dpk_to_deriv_path(key: &DescriptorKey) -> Option<DerivationPath> {
    match Active::classify(key) {
        KeyExpr::Literal { origin_path, .. } | KeyExpr::XPub { origin_path, .. } => origin_path,
    }
}

// See
// https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki#constructing-and-spending-taproot-outputs:
// > One example of such a point is H =
// > lift_x(0x50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0) which is constructed
// > by taking the hash of the standard uncompressed encoding of the secp256k1 base point G as X
// > coordinate.
/// x-only BIP341 NUMS point H.
pub const BIP341_NUMS: [u8; 32] = [
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
];

/// Key expressions allowed to encrypt. May be empty: the encoder refuses only
/// when the key set pooled across the whole payload is empty.
pub fn descr_to_dpks(descriptor: &Descriptor) -> Vec<DescriptorKey> {
    let mut keys = BTreeSet::new();
    for k in Active::descriptor_keys(descriptor) {
        // invalid key expressions are sorted out
        if let Ok(pk) = dpk_to_pk(&k) {
            if Active::xonly(&pk) != BIP341_NUMS {
                keys.insert(k);
            }
        }
    }
    keys.into_iter().collect()
}

/// x-only keys a descriptor puts on chain as is: every literal key and every
/// bare xpub root (no derivation, no wildcard).
pub fn descr_exposed_keys(descriptor: &Descriptor) -> Vec<[u8; 32]> {
    let mut keys = BTreeSet::new();
    for k in Active::descriptor_keys(descriptor) {
        let exposed = match Active::classify(&k) {
            KeyExpr::Literal { xonly, .. } => Some(xonly),
            KeyExpr::XPub {
                root,
                derived: false,
                multipath: false,
                ..
            } => Some(Active::xonly(&root)),
            KeyExpr::XPub { .. } => None,
        };
        keys.extend(exposed);
    }
    keys.into_iter().collect()
}

/// Walk the descriptor and emit a warning for every key expression that
/// `descr_to_dpks` sorts out of the encryption-key set: disallowed
/// expressions (literal pubkey, bare xpub) and the BIP341 NUMS key.
/// NUMS detection wins over the disallow rule so a NUMS literal in tr()
/// is reported with the more specific reason.
pub fn descr_warnings(descriptor: &Descriptor) -> Result<Vec<Warning>, Error> {
    let mut warnings = Vec::new();
    for k in Active::descriptor_keys(descriptor) {
        if xonly_of(&k) == BIP341_NUMS {
            warnings.push(Warning::NumsKey(k));
        } else if dpk_to_pk(&k).is_err() {
            warnings.push(Warning::DisallowedKeyExpression(k));
        }
    }
    Ok(warnings)
}

/// Root of each key expression allowed to encrypt, paired with its origin
/// derivation path when it has one.
pub fn dpks_to_key_paths(dpks: &[DescriptorKey]) -> Vec<(PublicKey, DerivationPath)> {
    let mut key_paths = BTreeSet::new();
    for k in dpks {
        if let (Ok(key), Some(path)) = (dpk_to_pk(k), dpk_to_deriv_path(k)) {
            key_paths.insert((key, path));
        }
    }
    key_paths.into_iter().collect()
}

pub fn dpks_to_derivation_keys_paths(
    dpks: &Vec<DescriptorKey>,
) -> (Vec<PublicKey>, Vec<DerivationPath>) {
    let mut derivation_paths = BTreeSet::new();
    let mut keys = BTreeSet::new();
    for k in dpks {
        // invalid key expressions are sorted out
        if let Ok(key) = dpk_to_pk(k) {
            keys.insert(key);
            if let Some(path) = dpk_to_deriv_path(k) {
                derivation_paths.insert(path);
            }
        }
    }
    let deriv = derivation_paths.into_iter().collect();
    let keys = keys.into_iter().collect();
    (keys, deriv)
}

#[cfg(all(test, feature = "rand"))]
mod recipient_keys {
    use alloc::{collections::BTreeSet, string::String, vec::Vec};
    use core::str::FromStr;

    use crate::{
        EncryptedBackup, Error, ToPayload,
        backend::{Active, Backend, Descriptor},
    };

    const TEST_VECTORS_JSON: &str = include_str!("../test_vectors/recipient_keys.json");

    #[derive(serde::Deserialize)]
    struct TestVector {
        description: String,
        descriptors: Vec<String>,
        // None: the encoder must refuse
        expected_keys: Option<Vec<String>>,
    }

    #[test]
    fn test_vector_recipient_keys() {
        let vectors: Vec<TestVector> = serde_json::from_str(TEST_VECTORS_JSON).unwrap();

        for v in vectors {
            // This implementation does not support MuSig.
            if v.descriptors.iter().any(|d| d.contains("musig(")) {
                continue;
            }
            let descriptors = v
                .descriptors
                .iter()
                .map(|d| Descriptor::from_str(d).expect(&v.description))
                .collect::<Vec<_>>();
            let payloads = descriptors
                .iter()
                .map(|d| d as &dyn ToPayload)
                .collect::<Vec<_>>();
            let backup = EncryptedBackup::new()
                .set_payloads(&payloads)
                .expect(&v.description);
            match v.expected_keys {
                Some(expected) => {
                    let keys = backup
                        .get_keys()
                        .iter()
                        .map(|k| hex::encode(Active::xonly(k)))
                        .collect::<BTreeSet<_>>()
                        .into_iter()
                        .collect::<Vec<_>>();
                    assert_eq!(keys, expected, "{}", v.description);
                    backup.encrypt().expect(&v.description);
                }
                None => {
                    let err = backup.encrypt().unwrap_err();
                    assert_eq!(err, Error::DescriptorHasNoKeys, "{}", v.description);
                }
            }
        }
    }
}
