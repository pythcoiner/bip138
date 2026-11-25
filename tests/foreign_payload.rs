use bip138::{
    Content, Decrypted, EncryptedBackup, Error, ToPayload,
    miniscript::bitcoin::{bip32::DerivationPath, secp256k1},
};

struct Note {
    text: String,
    key: secp256k1::PublicKey,
}

impl ToPayload for Note {
    fn to_payload(&self) -> Result<Vec<u8>, Error> {
        Ok(self.text.as_bytes().to_vec())
    }
    fn content_type(&self) -> Content {
        Content::String
    }
    fn key_derivation_paths(&self) -> Result<Vec<(secp256k1::PublicKey, DerivationPath)>, Error> {
        Ok(vec![])
    }
    fn keys(&self) -> Result<Vec<secp256k1::PublicKey>, Error> {
        Ok(vec![self.key])
    }
}

#[test]
fn a_type_of_another_crate_implements_to_payload() {
    let secp = secp256k1::Secp256k1::new();
    let key = secp256k1::PublicKey::from_secret_key(
        &secp,
        &secp256k1::SecretKey::from_slice(&[1; 32]).unwrap(),
    );
    let note = Note {
        text: "backup note".to_string(),
        key,
    };
    let bytes = EncryptedBackup::new()
        .set_payload(&note)
        .unwrap()
        .encrypt()
        .unwrap()
        .bytes;

    let restored = EncryptedBackup::new()
        .set_encrypted_payload(&bytes)
        .unwrap()
        .set_keys(vec![key])
        .decrypt()
        .unwrap();

    assert_eq!(restored, vec![Decrypted::String(note.text)]);
}
