//! Key expression rules over concrete miniscript values, plus the shared
//! descriptor fixtures.

use alloc::{str::FromStr, vec};

use crate::{
    Error,
    descriptor::{
        BIP341_NUMS, descr_to_dpks, dpk_to_deriv_path, dpk_to_pk, dpk_to_root_pk,
        dpks_to_derivation_keys_paths,
    },
    miniscript::{
        Descriptor, DescriptorPublicKey, ForEachKey, ToPublicKey,
        bitcoin::{
            self,
            bip32::{self, ChainCode, ChildNumber, DerivationPath, Fingerprint},
            secp256k1,
        },
        descriptor::{
            self, DerivPaths, DescriptorMultiXKey, DescriptorXKey, SinglePub, SinglePubKey,
            Wildcard,
        },
    },
};

pub fn descr_1() -> Descriptor<DescriptorPublicKey> {
    let descr_str = "wsh(or_d(pk([58b7f8dc/48'/1'/0'/2']tpubDEPBvXvhta3pjVaKokqC3eeMQnszj9ehFaA2zD5nSdkaccwGAizu8jVB2NeSpvmP2P52MBoZvNCixqXRJnTyXx51FQzARR63tjxQSyP3Btw/<0;1>/*),and_v(v:pkh([58b7f8dc/48'/1'/0'/2']tpubDEPBvXvhta3pjVaKokqC3eeMQnszj9ehFaA2zD5nSdkaccwGAizu8jVB2NeSpvmP2P52MBoZvNCixqXRJnTyXx51FQzARR63tjxQSyP3Btw/<2;3>/*),older(52596))))#pggrcdd0";

    Descriptor::<DescriptorPublicKey>::from_str(descr_str).unwrap()
}

pub fn dpk_1() -> DescriptorPublicKey {
    let dpk_str = "[58b7f8dc/48'/1'/0'/2']tpubDEPBvXvhta3pjVaKokqC3eeMQnszj9ehFaA2zD5nSdkaccwGAizu8jVB2NeSpvmP2P52MBoZvNCixqXRJnTyXx51FQzARR63tjxQSyP3Btw/<0;1>/*";
    DescriptorPublicKey::from_str(dpk_str).unwrap()
}

fn dpk_2() -> DescriptorPublicKey {
    let dpk_str = "[58b7f8dc/48'/1'/0'/2']tpubDEPBvXvhta3pjVaKokqC3eeMQnszj9ehFaA2zD5nSdkaccwGAizu8jVB2NeSpvmP2P52MBoZvNCixqXRJnTyXx51FQzARR63tjxQSyP3Btw/<2;3>/*";
    DescriptorPublicKey::from_str(dpk_str).unwrap()
}

fn dpk_3() -> DescriptorPublicKey {
    let dpk_str = "tpubDEPBvXvhta3pjVaKokqC3eeMQnszj9ehFaA2zD5nSdkaccwGAizu8jVB2NeSpvmP2P52MBoZvNCixqXRJnTyXx51FQzARR63tjxQSyP3Btw/<2;3>/*";
    DescriptorPublicKey::from_str(dpk_str).unwrap()
}
pub fn pk() -> secp256k1::PublicKey {
    let raw = [
        3, 235, 210, 82, 202, 8, 119, 170, 224, 155, 157, 5, 130, 25, 104, 39, 117, 170, 60, 188,
        208, 73, 193, 47, 7, 131, 47, 44, 246, 163, 181, 23, 8,
    ];
    secp256k1::PublicKey::from_slice(&raw).unwrap()
}

#[test]
fn dpk_to_root_pk_accepts_bare_xpub() {
    let single_str = "02e6642fd69bd211f93f7f1f36ca51a26a5290eb2dd1b0d8279a87bb0d480c8443";
    let xpub = bip32::Xpub {
        network: bitcoin::NetworkKind::Test,
        depth: 1,
        parent_fingerprint: Fingerprint::from_str("00000000").unwrap(),
        child_number: ChildNumber::from_normal_idx(0).unwrap(),
        public_key: bitcoin::secp256k1::PublicKey::from_str(single_str).unwrap(),
        chain_code: ChainCode::from(&[1u8; 32]),
    };
    let bare = DescriptorPublicKey::XPub(DescriptorXKey {
        origin: None,
        xkey: xpub,
        derivation_path: DerivationPath::default(),
        wildcard: Wildcard::None,
    });
    let derived = DescriptorPublicKey::XPub(DescriptorXKey {
        origin: None,
        xkey: xpub,
        derivation_path: DerivationPath::from_str("0").unwrap(),
        wildcard: Wildcard::Unhardened,
    });

    // The encoding-side gate rejects the bare xpub, but both forms share a root
    // pubkey, so a bare xpub decrypts what the derived form encrypted.
    assert_eq!(dpk_to_pk(&bare), Err(Error::InvalidKeyExpression));
    let expected = bitcoin::secp256k1::PublicKey::from_str(single_str).unwrap();
    assert_eq!(dpk_to_root_pk(&bare).unwrap(), expected);
    assert_eq!(
        dpk_to_root_pk(&derived).unwrap(),
        dpk_to_pk(&derived).unwrap()
    );
}

#[test]
fn dpk_to_root_pk_rejects_literal_pubkey() {
    let single = DescriptorPublicKey::Single(SinglePub {
        origin: None,
        key: SinglePubKey::FullKey(
            bitcoin::PublicKey::from_str(
                "02e6642fd69bd211f93f7f1f36ca51a26a5290eb2dd1b0d8279a87bb0d480c8443",
            )
            .unwrap(),
        ),
    });

    assert_eq!(dpk_to_root_pk(&single), Err(Error::InvalidKeyExpression));
}

#[test]
fn test_dpk_to_pk() {
    // Valid key expressions (xpub with /<0;1>/*) extract the xpub root
    // pubkey and are accepted by dpk_to_pk.
    let expected = pk();
    let p = dpk_to_pk(&dpk_1()).unwrap();
    assert_eq!(p, expected);
    let p = dpk_to_pk(&dpk_2()).unwrap();
    assert_eq!(p, expected);

    // Single FullKey; disallowed by the spec's key-expression rule.
    let single_str = "0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";
    let dpk = DescriptorPublicKey::from_str(single_str).unwrap();
    assert_eq!(dpk_to_pk(&dpk), Err(Error::InvalidKeyExpression));

    // Single XOnly; disallowed.
    let xonly = bitcoin::PublicKey::from_str(single_str)
        .unwrap()
        .to_x_only_pubkey();
    let dpk = DescriptorPublicKey::Single(SinglePub {
        origin: None,
        key: descriptor::SinglePubKey::XOnly(xonly),
    });
    assert_eq!(dpk_to_pk(&dpk), Err(Error::InvalidKeyExpression));

    // Xpub with no derivation and no wildcard; disallowed.
    let xpub = bip32::Xpub {
        network: bitcoin::NetworkKind::Test,
        depth: 1,
        parent_fingerprint: Fingerprint::from_str("00000000").unwrap(),
        child_number: ChildNumber::from_normal_idx(0).unwrap(),
        public_key: bitcoin::secp256k1::PublicKey::from_str(single_str).unwrap(),
        chain_code: ChainCode::from(&[1u8; 32]),
    };
    let bare_xpub = DescriptorPublicKey::XPub(DescriptorXKey {
        origin: None,
        xkey: xpub,
        derivation_path: DerivationPath::default(),
        wildcard: Wildcard::None,
    });
    assert_eq!(dpk_to_pk(&bare_xpub), Err(Error::InvalidKeyExpression));

    // Xpub with non-empty derivation, no wildcard; allowed.
    let xpub_fixed = DescriptorPublicKey::XPub(DescriptorXKey {
        origin: None,
        xkey: xpub,
        derivation_path: DerivationPath::from_str("0/5").unwrap(),
        wildcard: Wildcard::None,
    });
    let expected_xpub_pk = bitcoin::secp256k1::PublicKey::from_str(single_str).unwrap();
    assert_eq!(dpk_to_pk(&xpub_fixed).unwrap(), expected_xpub_pk);

    // Xpub with empty derivation and wildcard; allowed.
    let xpub_wild = DescriptorPublicKey::XPub(DescriptorXKey {
        origin: None,
        xkey: xpub,
        derivation_path: DerivationPath::default(),
        wildcard: Wildcard::Unhardened,
    });
    assert_eq!(dpk_to_pk(&xpub_wild).unwrap(), expected_xpub_pk);

    // MultiXpub with non-empty path, no wildcard; allowed (deriv only).
    let multi_fixed = DescriptorPublicKey::MultiXPub(DescriptorMultiXKey {
        origin: None,
        xkey: xpub,
        derivation_paths: DerivPaths::new(vec![DerivationPath::from_str("0").unwrap()]).unwrap(),
        wildcard: Wildcard::None,
    });
    assert_eq!(dpk_to_pk(&multi_fixed).unwrap(), expected_xpub_pk);
}

#[test]
fn test_dpk_to_deriv() {
    let deriv_1 = dpk_to_deriv_path(&dpk_1()).unwrap();
    assert_eq!(deriv_1, DerivationPath::from_str("48'/1'/0'/2'").unwrap());
    let deriv_2 = dpk_to_deriv_path(&dpk_2()).unwrap();
    assert_eq!(deriv_2, DerivationPath::from_str("48'/1'/0'/2'").unwrap());
    let deriv_3 = dpk_to_deriv_path(&dpk_3());
    assert!(deriv_3.is_none());

    let dp = DerivationPath::from_str("0/0").unwrap();
    let origin = Some((Fingerprint::from_str("aabbccdd").unwrap(), dp.clone()));

    // Single
    let single_str = "0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";
    let dpk = DescriptorPublicKey::from_str(single_str).unwrap();
    let none = dpk_to_deriv_path(&dpk);
    assert!(none.is_none());
    let single_pk = SinglePubKey::FullKey(bitcoin::PublicKey::from_str(single_str).unwrap());
    let dpk = DescriptorPublicKey::Single(SinglePub {
        origin: origin.clone(),
        key: single_pk,
    });
    let deriv = dpk_to_deriv_path(&dpk).unwrap();
    assert_eq!(deriv, dp);

    // Xpub
    let xpub = bip32::Xpub {
        network: bitcoin::NetworkKind::Test,
        depth: 1,
        parent_fingerprint: Fingerprint::from_str("00000000").unwrap(),
        child_number: ChildNumber::from_normal_idx(0).unwrap(),
        public_key: bitcoin::secp256k1::PublicKey::from_str(single_str).unwrap(),
        chain_code: ChainCode::from(&[1u8; 32]),
    };
    let dpk = DescriptorPublicKey::XPub(DescriptorXKey {
        origin: None,
        xkey: xpub,
        derivation_path: DerivationPath::default(),
        wildcard: Wildcard::None,
    });
    let none = dpk_to_deriv_path(&dpk);
    assert!(none.is_none());
    let dpk = DescriptorPublicKey::XPub(DescriptorXKey {
        origin: origin.clone(),
        xkey: xpub,
        derivation_path: DerivationPath::default(),
        wildcard: Wildcard::None,
    });
    let deriv = dpk_to_deriv_path(&dpk).unwrap();
    assert_eq!(deriv, dp);

    // MultiXpub
    let dpk = DescriptorPublicKey::MultiXPub(DescriptorMultiXKey {
        origin: None,
        xkey: xpub,
        derivation_paths: DerivPaths::new(vec![DerivationPath::from_str("0").unwrap()]).unwrap(),
        wildcard: Wildcard::None,
    });
    let none = dpk_to_deriv_path(&dpk);
    assert!(none.is_none());
    let dpk = DescriptorPublicKey::MultiXPub(DescriptorMultiXKey {
        origin: origin.clone(),
        xkey: xpub,
        derivation_paths: DerivPaths::new(vec![DerivationPath::from_str("0").unwrap()]).unwrap(),
        wildcard: Wildcard::None,
    });
    let deriv = dpk_to_deriv_path(&dpk).unwrap();
    assert_eq!(deriv, dp);
}

#[test]
fn test_descript_to_dpk() {
    let dpks = descr_to_dpks(&descr_1());
    let expected = vec![dpk_1(), dpk_2()];
    assert_eq!(dpks, expected);
}

#[test]
fn test_descriptor_to_dpk_unspendable() {
    let descr_str = "tr(tpubD6NzVbkrYhZ4XWBqjZ7DTB4eFvi8eQZ79UvNbQFsxXiaMNaBn83jpMWTXLX2Gx6JgC5n9jWvx6vnijcAUgxXmRtFd4ntasRGNsYSCvQteSr/<0;1>/*,{and_v(v:and_v(v:pk([d4ab66f1/48'/1'/0'/2']tpubDEXYN145WM4rVKtcWpySBYiVQ229pmrnyAGJT14BBh2QJr7ABJswchDicZfFaauLyXhDad1nCoCZQEwAW87JPotP93ykC9WJvoASnBjYBxW/<2;3>/*),pk([79af2d8a/48'/1'/0'/2']tpubDEtHs6m9crfv1oeETj6EXteAtW7eoSSBVBaypEdWZt8VftbHF9R12xSZpzWGNuAofeGPL6cz48dLdCYbVioHL8ygA56yuPW76Xz5WZ3dt8o/<2;3>/*)),older(52596)),and_v(v:pk([d4ab66f1/48'/1'/0'/2']tpubDEXYN145WM4rVKtcWpySBYiVQ229pmrnyAGJT14BBh2QJr7ABJswchDicZfFaauLyXhDad1nCoCZQEwAW87JPotP93ykC9WJvoASnBjYBxW/<0;1>/*),pk([79af2d8a/48'/1'/0'/2']tpubDEtHs6m9crfv1oeETj6EXteAtW7eoSSBVBaypEdWZt8VftbHF9R12xSZpzWGNuAofeGPL6cz48dLdCYbVioHL8ygA56yuPW76Xz5WZ3dt8o/<0;1>/*))})#vudj49fm";
    let descriptor = Descriptor::<DescriptorPublicKey>::from_str(descr_str).unwrap();
    // unspendable keys must have been dropped
    let keys = descr_to_dpks(&descriptor);
    for key in keys {
        let pk = dpk_to_pk(&key).unwrap();
        assert_ne!(pk.x_only_public_key().0.serialize(), BIP341_NUMS);
    }
    // but the descriptor contains unspendable. The descriptor here uses
    // only xpub key expressions, so reading `xkey.public_key` directly
    // is sufficient and avoids exposing an unvalidated extractor.
    let contains_unspendable = descriptor.for_any_key(|k| {
        let xpub_key = match k {
            DescriptorPublicKey::XPub(x) => x.xkey.public_key,
            DescriptorPublicKey::MultiXPub(x) => x.xkey.public_key,
            DescriptorPublicKey::Single(_) => return false,
        };
        xpub_key.x_only_public_key().0.serialize() == BIP341_NUMS
    });
    assert!(contains_unspendable);
}

#[test]
fn test_dpks_to_deriv_paths() {
    let dpks = vec![dpk_1(), dpk_2()];
    let pks = vec![pk()];
    let deriv = vec![DerivationPath::from_str("48'/1'/0'/2'").unwrap()];
    let res = dpks_to_derivation_keys_paths(&dpks);
    assert_eq!(res, (pks, deriv));
}
