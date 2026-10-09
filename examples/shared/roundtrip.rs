//! A downstream crate encrypting a descriptor built with its own `miniscript`
//! dependency: it only compiles when bip138's backend is that same release.

use std::str::FromStr;

use bip138::{Decrypted, EncryptedBackup};
use miniscript::{Descriptor, DescriptorPublicKey};

const DESCRIPTOR: &str = "wsh(or_d(pk([58b7f8dc/48'/1'/0'/2']tpubDEPBvXvhta3pjVaKokqC3eeMQnszj9ehFaA2zD5nSdkaccwGAizu8jVB2NeSpvmP2P52MBoZvNCixqXRJnTyXx51FQzARR63tjxQSyP3Btw/<0;1>/*),and_v(v:pkh([58b7f8dc/48'/1'/0'/2']tpubDEPBvXvhta3pjVaKokqC3eeMQnszj9ehFaA2zD5nSdkaccwGAizu8jVB2NeSpvmP2P52MBoZvNCixqXRJnTyXx51FQzARR63tjxQSyP3Btw/<2;3>/*),older(52596))))#pggrcdd0";

fn main() {
    let descriptor =
        Descriptor::<DescriptorPublicKey>::from_str(DESCRIPTOR).expect("valid descriptor");
    let backup = EncryptedBackup::new()
        .set_payload(&descriptor)
        .expect("descriptor payload");
    let keys = backup.get_keys();
    let bytes = backup.encrypt().expect("encrypt").bytes;

    let restored = EncryptedBackup::new()
        .set_encrypted_payload(&bytes)
        .expect("parse backup")
        .set_keys(keys)
        .decrypt()
        .expect("decrypt");
    assert_eq!(restored, vec![Decrypted::Descriptor(Box::new(descriptor))]);
}
