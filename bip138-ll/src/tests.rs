use super::crypto::{OsRandom, RustBitcoin};
use super::*;
use rand::random;

// Compressed pubkey hex -> 32-byte x-only key (drop the 0x02/0x03 prefix byte).
fn xonly(compressed_hex: &str) -> [u8; 32] {
    let bytes = hex::decode(compressed_hex).unwrap();
    bytes[1..33].try_into().unwrap()
}

// Parse "m/84'/0'/0'" / "84h/0h/0h" / "0/1h/2/3h" / "m" into a DerivationPath.
fn parse_path(s: &str) -> DerivationPath {
    let mut childs = Vec::new();
    for part in s.split('/') {
        if part.is_empty() || part == "m" {
            continue;
        }
        let hardened = part.ends_with('\'') || part.ends_with('h') || part.ends_with('H');
        let num: u32 = part.trim_end_matches(['\'', 'h', 'H']).parse().unwrap();
        childs.push(if hardened { num | (1 << 31) } else { num });
    }
    DerivationPath::from(childs)
}

// Reconstructs the removed test-vector encoder: a raw-payload backup with an
// explicit nonce and the exact decoy individual secrets.
fn encode_v1_backup_for_test_vectors(
    paths: Vec<DerivationPath>,
    keys: Vec<[u8; 32]>,
    payload: Vec<u8>,
    nonce: [u8; 12],
    decoys: &[[u8; 32]],
) -> Result<Vec<u8>, Error> {
    encode_v1_backup(&RustBitcoin, paths, keys, payload, nonce, |secrets| {
        pad_individual_secrets_with_decoys(secrets, decoys)
    })
}

#[test]
fn caller_supplied_decoys_are_validated() {
    let keys = vec![pk1()];
    let payload = b"payload".to_vec();
    let nonce = [1u8; 12];
    // one key -> doubling bucket of 5 -> exactly 4 decoys are needed
    let decoys = [[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];
    let encode = |decoys: &[[u8; 32]]| {
        encode_v1_backup_for_test_vectors(vec![], keys.clone(), payload.clone(), nonce, decoys)
    };

    assert!(encode(&decoys).is_ok());
    // too few
    assert_eq!(encode(&decoys[..3]), Err(Error::IndividualSecretsLength));
    // a zeroed decoy
    let mut zeroed = decoys;
    zeroed[0] = [0u8; 32];
    assert_eq!(encode(&zeroed), Err(Error::IndividualSecretsLength));
    // a duplicate decoy
    let mut duplicate = decoys;
    duplicate[1] = duplicate[0];
    assert_eq!(encode(&duplicate), Err(Error::IndividualSecretsLength));
}

fn pk1() -> [u8; 32] {
    xonly("02e6642fd69bd211f93f7f1f36ca51a26a5290eb2dd1b0d8279a87bb0d480c8443")
}

fn pk2() -> [u8; 32] {
    xonly("0384526253c27c7aef56c7b71a5cd25bebb66dddda437826defc5b2568bde81f07")
}

fn pk3() -> [u8; 32] {
    xonly("0384526253c27c7aef56c7b71a5cd25bebb000000a437826defc5b2568bde81f07")
}

#[test]
fn test_fuzz_catch_1() {
    // NOTE: the bug was in check_offset_lookahead() where substract 1 to 0 panics
    let bytes = [
        66, 73, 80, 88, 88, 88, 88, 0, 0, 1, 0, 0, 0, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48,
        48, 48, 48, 48, 48, 207, 207, 207, 207, 207, 207, 48, 48, 48, 48, 48, 48, 48, 48, 48, 32,
        48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 0, 0, 0, 185, 185, 0, 88, 0, 0, 185, 185,
    ];
    let _ = decode_v1(&bytes);
}

#[test]
fn test_nonce() {
    let nonce_1 = draw_nonce(&mut OsRandom);
    let nonce_2 = draw_nonce(&mut OsRandom);
    assert_ne!(nonce_1, nonce_2);
}

#[test]
fn test_check_offset() {
    let res = check_offset(1, &[0x00]);
    assert!(res.is_err());
    check_offset(1, &[0x00, 0x00]).unwrap();
}

#[test]
fn test_check_offset_look_ahead() {
    let res = check_offset_lookahead(0, &[0x00; 2], 3);
    assert!(res.is_err());
    check_offset_lookahead(0, &[0x00; 2], 2).unwrap();
}

#[test]
fn test_init_offset() {
    let res = init_offset(&[0x00], 1);
    assert!(res.is_err());
    init_offset(&[0x00], 0).unwrap();
}

#[test]
fn test_increment_offset() {
    let res = increment_offset(&[0x00], 0, 1);
    assert!(res.is_err());
    increment_offset(&[0x00; 2], 0, 1).unwrap();
}

#[test]
fn test_parse_magic() {
    let magic = "BIP138".as_bytes();
    assert_eq!(MAGIC, "BIP138");
    let offset = parse_magic_byte(magic).unwrap();
    assert_eq!(offset, magic.len());
    let res = parse_magic_byte("BOBtst".as_bytes());
    assert_eq!(res, Err(Error::Magic));
    let _ = parse_magic_byte(MAGIC.as_bytes()).unwrap();
}

#[test]
fn test_parse_version() {
    // V0 (0x00) is not a valid on-the-wire version
    let res = parse_version(&[0x00]);
    assert_eq!(res, Err(Error::Version));
    let (_, v) = parse_version(&[0x01]).unwrap();
    assert_eq!(v, 0x01);
    let res = parse_version(&[]);
    assert_eq!(res, Err(Error::Version));
    let res = parse_version(&[0x02]);
    assert_eq!(res, Err(Error::Version));
}

#[test]
pub fn test_parse_encryption() {
    // 0x00 is reserved
    let failed = parse_encryption(&[0]).unwrap_err();
    assert_eq!(failed, Error::EncryptionReserved);
    let failed = parse_encryption(&[0, 2]).unwrap_err();
    assert_eq!(failed, Error::EncryptionReserved);
    // non-zero bytes are accepted (unknown algos are handled upstream)
    let (l, e) = parse_encryption(&[2, 0]).unwrap();
    assert_eq!(l, 1);
    assert_eq!(e, 2);
    let (l, e) = parse_encryption(&[1]).unwrap();
    assert_eq!(l, 1);
    assert_eq!(e, 1);
    let failed = parse_encryption(&[]).unwrap_err();
    assert_eq!(failed, Error::Encryption)
}

#[test]
pub fn test_parse_derivation_path() {
    // single deriv path
    let (_, p) = parse_derivation_paths(&[0x01, 0x01, 0x00, 0x00, 0x00, 0x01]).unwrap();
    assert_eq!(p.len(), 1);

    // child number must be encoded on 4 bytes
    let p = parse_derivation_paths(&[0x01, 0x01, 0x00]).unwrap_err();
    assert_eq!(p, Error::Corrupted);
    let p = parse_derivation_paths(&[0x01, 0x01, 0x00, 0x00]).unwrap_err();
    assert_eq!(p, Error::Corrupted);
    let p = parse_derivation_paths(&[0x01, 0x01, 0x00, 0x00, 0x00]).unwrap_err();
    assert_eq!(p, Error::Corrupted);

    // empty childs
    let p = parse_derivation_paths(&[0x01, 0x00]).unwrap_err();
    assert_eq!(p, Error::DerivPathEmpty);
}

#[test]
pub fn test_parse_individual_secrets() {
    // empty bytes
    let fail = parse_individual_secrets(&[]).unwrap_err();
    assert_eq!(fail, Error::EmptyBytes);

    // empty vector
    let fail = parse_individual_secrets(&[0x00]).unwrap_err();
    assert_eq!(fail, Error::IndividualSecretsEmpty);

    let is1 = [1u8; 32].to_vec();
    let is2 = [2u8; 32].to_vec();

    // single secret
    let mut bytes = vec![0x01];
    bytes.append(&mut is1.clone());
    let (_, is) = parse_individual_secrets(&bytes).unwrap();
    assert_eq!(is[0].to_vec(), is1);

    // multiple secrets
    let mut bytes = vec![0x02];
    bytes.append(&mut is1.clone());
    bytes.append(&mut is2.clone());
    let (_, is) = parse_individual_secrets(&bytes).unwrap();
    assert_eq!(is[0].to_vec(), is1);
    assert_eq!(is[1].to_vec(), is2);
}

#[test]
fn test_parse_content() {
    // empty bytes must fail
    assert!(parse_content(&[]).is_err());
    // TYPE 0x00 is reserved
    assert_eq!(parse_content(&[0]), Err(Error::ContentEnd));
    // BIP TYPE 0x01 requires 2 more bytes
    assert!(parse_content(&[1, 0]).is_err());
    // BIP380
    let (_, c) = parse_content(&[1, 0x01, 0x7c]).unwrap();
    assert_eq!(c, Content::Bip380);
    // BIP388
    let (_, c) = parse_content(&[1, 0x01, 0x84]).unwrap();
    assert_eq!(c, Content::Bip388);
    // BIP329
    let (_, c) = parse_content(&[1, 0x01, 0x49]).unwrap();
    assert_eq!(c, Content::Bip329);
    // BIP139
    let (_, c) = parse_content(&[1, 0x00, 0x8B]).unwrap();
    assert_eq!(c, Content::Bip139);
    // BIP138
    let (_, c) = parse_content(&[1, 0x00, 0x8A]).unwrap();
    assert_eq!(c, Content::Bip138);
    // Arbitrary BIPs
    let (_, c) = parse_content(&[1, 0xFF, 0xFF]).unwrap();
    assert_eq!(c, Content::BIP(u16::MAX));
    let (_, c) = parse_content(&[1, 0, 0]).unwrap();
    assert_eq!(c, Content::BIP(0));
    // Proprietary: TYPE=0x02, LENGTH=3, data=00 00 00
    let (_, c) = parse_content(&[2, 3, 0, 0, 0]).unwrap();
    assert_eq!(c, Content::Proprietary(vec![0, 0, 0]));
    let (_, c) = parse_content(&[3, 0]).unwrap();
    assert_eq!(c, Content::String);
}

#[test]
fn test_parse_content_metadata_insufficient_bytes() {
    // BIP TYPE=0x01 needs 2 more bytes, only 1 provided
    let result = parse_content(&[1, 0x01]);
    assert_eq!(result, Err(Error::ContentMetadata));

    // Proprietary TYPE=0x02 LENGTH=3 but only 2 bytes of data follow
    let result = parse_content(&[2, 3, 0xAA, 0xBB]);
    assert_eq!(result, Err(Error::Corrupted));

    // Proprietary LENGTH=5 with only 3 bytes of data
    let result = parse_content(&[2, 5, 0xAA, 0xBB, 0xCC]);
    assert_eq!(result, Err(Error::Corrupted));
}

#[test]
fn test_parse_content_metadata_exact_bytes() {
    // Proprietary TYPE=0x02 LENGTH=3 with exactly 3 bytes - should succeed
    let (offset, content) = parse_content(&[2, 3, 0xAA, 0xBB, 0xCC]).unwrap();
    assert_eq!(offset, 5); // 1 (TYPE) + 1 (LENGTH) + 3 (data)
    assert_eq!(content, Content::Proprietary(vec![0xAA, 0xBB, 0xCC]));

    // BIP TYPE=0x01 with exactly 2 bytes of BIP number - should succeed
    let (offset, content) = parse_content(&[1, 0x01, 0x7C]).unwrap();
    assert_eq!(offset, 3);
    assert_eq!(content, Content::Bip380);
}

#[test]
fn test_parse_content_metadata_upgrade_0x80() {
    // TYPE >= 0x80 signals an upgrade and parsers MUST stop
    let result = parse_content(&[0xFF]);
    assert_eq!(result, Err(Error::ContentMetadata));
    let result = parse_content(&[0xFF, 0xAA]);
    assert_eq!(result, Err(Error::ContentMetadata));
    let result = parse_content(&[0x80, 0x00]);
    assert_eq!(result, Err(Error::ContentMetadata));

    // Unknown TYPE < 0x80 must be skipped: consume LENGTH bytes of DATA
    let (offset, content) = parse_content(&[0x05, 0x02, 0xAA, 0xBB]).unwrap();
    assert_eq!(offset, 4); // 1 (TYPE) + 1 (LENGTH) + 2 (data)
    assert_eq!(content, Content::Unknown);
}

#[test]
fn test_serialize_content() {
    // Proprietary: TYPE=0x02, LENGTH=3, data
    let mut c = Content::Proprietary(vec![0, 0, 0]);
    let mut serialized: Vec<u8> = c.try_into().unwrap();
    assert_eq!(serialized, vec![0x02, 0x03, 0, 0, 0]);
    c = Content::String;
    serialized = c.try_into().unwrap();
    assert_eq!(serialized, vec![0x03, 0x00]);
    // BIP 380: TYPE=0x01, 2-byte BE BIP number (no LENGTH)
    c = Content::Bip380;
    serialized = c.try_into().unwrap();
    assert_eq!(serialized, vec![0x01, 0x01, 0x7C]);
    c = Content::BIP(380);
    serialized = c.try_into().unwrap();
    assert_eq!(serialized, vec![0x01, 0x01, 0x7C]);
    // BIP 388
    c = Content::Bip388;
    serialized = c.try_into().unwrap();
    assert_eq!(serialized, vec![0x01, 0x01, 0x84]);
    c = Content::BIP(388);
    serialized = c.try_into().unwrap();
    assert_eq!(serialized, vec![0x01, 0x01, 0x84]);
    // BIP 329
    c = Content::Bip329;
    serialized = c.try_into().unwrap();
    assert_eq!(serialized, vec![0x01, 0x01, 0x49]);
    c = Content::BIP(329);
    serialized = c.try_into().unwrap();
    assert_eq!(serialized, vec![0x01, 0x01, 0x49]);
    // BIP 139
    c = Content::Bip139;
    serialized = c.try_into().unwrap();
    assert_eq!(serialized, vec![0x01, 0x00, 0x8B]);
    c = Content::BIP(139);
    serialized = c.try_into().unwrap();
    assert_eq!(serialized, vec![0x01, 0x00, 0x8B]);
    // BIP 138
    c = Content::Bip138;
    serialized = c.try_into().unwrap();
    assert_eq!(serialized, vec![0x01, 0x00, 0x8A]);
    c = Content::BIP(138);
    serialized = c.try_into().unwrap();
    assert_eq!(serialized, vec![0x01, 0x00, 0x8A]);
}

#[test]
fn test_content_is_known() {
    let mut c = Content::None;
    assert!(!c.is_known());
    c = Content::Unknown;
    assert!(!c.is_known());
    c = Content::Proprietary(vec![0, 0, 0]);
    assert!(!c.is_known());
    c = Content::String;
    assert!(c.is_known());
    c = Content::Bip380;
    assert!(c.is_known());
    c = Content::Bip388;
    assert!(c.is_known());
    c = Content::Bip329;
    assert!(c.is_known());
    c = Content::Bip139;
    assert!(c.is_known());
    c = Content::Bip138;
    assert!(c.is_known());
    c = Content::BIP(0);
    assert!(c.is_known());
}

#[test]
fn test_padding_size_buckets() {
    let g = Padding::Geometric;
    assert_eq!(g.padded_size(1).unwrap(), PADDING_MIN_SIZE);
    assert_eq!(g.padded_size(PADDING_MIN_SIZE).unwrap(), PADDING_MIN_SIZE);
    assert_eq!(g.padded_size(PADDING_MIN_SIZE + 1).unwrap(), 12_800);
    assert_eq!(g.padded_size(12_801).unwrap(), 16_000);
    assert_eq!(g.padded_size(39_063).unwrap(), 48_828);
    // None never pads
    assert_eq!(Padding::None.padded_size(1).unwrap(), 1);
}

#[test]
fn test_individual_secrets_are_padded_to_bucket() {
    assert_eq!(doubling_bucket(1).unwrap(), 5);
    assert_eq!(doubling_bucket(5).unwrap(), 5);
    assert_eq!(doubling_bucket(6).unwrap(), 10);
    assert_eq!(doubling_bucket(11).unwrap(), 20);
    assert_eq!(doubling_bucket(21).unwrap(), 40);
    assert_eq!(doubling_bucket(160).unwrap(), 160);
    // past 160 the bucket saturates at the one-byte COUNT limit
    assert_eq!(doubling_bucket(161).unwrap(), 255);
    assert_eq!(doubling_bucket(255).unwrap(), 255);
    assert_eq!(doubling_bucket(256), Err(Error::IndividualSecretsLength));
}

#[test]
fn test_encrypt_161_keys_saturates_decoy_bucket() {
    // 161 keys overflow the 320 bucket: the count saturates at 255 and
    // encoding must still succeed.
    let mut keys = BTreeSet::new();
    while keys.len() < 161 {
        let key: [u8; 32] = random();
        keys.insert(key);
    }
    let keys = keys.into_iter().collect::<Vec<_>>();
    let data = "test".as_bytes().to_vec();
    let bytes = encrypt_chacha20_poly1305_v1(
        &RustBitcoin,
        &mut OsRandom,
        vec![],
        Content::Bip380,
        keys,
        &data,
        Padding::None,
    )
    .unwrap();
    let (_, individual_secrets, _, _, _) = decode_v1(&bytes).unwrap();
    assert_eq!(individual_secrets.len(), 255);
}

#[test]
fn test_common_derivation_paths() {
    let paths = common_derivation_paths(0);
    assert_eq!(paths.len(), 70);
    assert!(paths.contains(&parse_path("44h/0h/0h")));
    assert!(paths.contains(&parse_path("49h/0h/0h")));
    assert!(paths.contains(&parse_path("84h/0h/9h")));
    assert!(paths.contains(&parse_path("86h/0h/9h")));
    assert!(paths.contains(&parse_path("87h/0h/9h")));
    assert!(paths.contains(&parse_path("48h/0h/9h/1h")));
    assert!(paths.contains(&parse_path("48h/0h/9h/2h")));
    assert!(!paths.contains(&parse_path("49h/1h/0h")));
    assert!(!paths.contains(&parse_path("49h/0h/10h")));

    let paths = common_derivation_paths(1);
    assert_eq!(paths.len(), 70);
    assert!(paths.contains(&parse_path("44h/1h/0h")));
    assert!(paths.contains(&parse_path("86h/1h/9h")));
    assert!(paths.contains(&parse_path("87h/1h/9h")));
    assert!(paths.contains(&parse_path("48h/1h/9h/2h")));
    assert!(!paths.contains(&parse_path("49h/0h/0h")));
}

#[test]
fn test_encode_decode_plaintext_ignores_padding() {
    let content_metadata: Vec<u8> = Content::Bip380.try_into().unwrap();

    // padded: payload grows to the bucket, decode still recovers the data
    let padded = encode_plaintext(&[(&content_metadata, b"test")], Padding::Geometric).unwrap();
    assert_eq!(padded.len(), PADDING_MIN_SIZE);
    let items = decode_plaintext(&padded).unwrap();
    assert_eq!(items, vec![(Content::Bip380, b"test".to_vec())]);

    // unpadded: <CONTENT_METADATA(3)><LENGTH(1)><DATA(4)>, no trailing bytes
    let plain = encode_plaintext(&[(&content_metadata, b"test")], Padding::None).unwrap();
    assert_eq!(plain.len(), 3 + 1 + 4);
    let items = decode_plaintext(&plain).unwrap();
    assert_eq!(items, vec![(Content::Bip380, b"test".to_vec())]);
}

#[test]
fn test_encode_decode_plaintext_multi_content() {
    let meta_descr: Vec<u8> = Content::Bip380.try_into().unwrap();
    let meta_labels: Vec<u8> = Content::Bip329.try_into().unwrap();
    let items: &[(&[u8], &[u8])] = &[(&meta_descr, b"desc"), (&meta_labels, b"labels")];

    // unpadded: both items round-trip, in order
    let plain = encode_plaintext(items, Padding::None).unwrap();
    let decoded = decode_plaintext(&plain).unwrap();
    assert_eq!(
        decoded,
        vec![
            (Content::Bip380, b"desc".to_vec()),
            (Content::Bip329, b"labels".to_vec()),
        ]
    );

    // padded: the zero-fill terminator stops the sequence after the last item
    let padded = encode_plaintext(items, Padding::Geometric).unwrap();
    assert_eq!(padded.len(), PADDING_MIN_SIZE);
    let decoded = decode_plaintext(&padded).unwrap();
    assert_eq!(
        decoded,
        vec![
            (Content::Bip380, b"desc".to_vec()),
            (Content::Bip329, b"labels".to_vec()),
        ]
    );
}

#[test]
fn test_decode_plaintext_rejects_empty() {
    assert_eq!(decode_plaintext(&[]), Err(Error::EmptyBytes));
    // a payload that is only padding holds no content items
    assert_eq!(decode_plaintext(&[0u8; 8]), Err(Error::EmptyBytes));
}

#[test]
fn test_simple_encode_decode_encrypted_payload() {
    let bytes = encode_encrypted_payload([3; 12], &[1, 2, 3, 4]).unwrap();
    let mut expected = [3; 12].to_vec();
    expected.append(&mut [4, 1, 2, 3, 4].to_vec());
    assert_eq!(bytes, expected);
    let (nonce, cyphertext) = parse_encrypted_payload(&bytes).unwrap();
    assert_eq!([3u8; 12], nonce);
    assert_eq!([1, 2, 3, 4].to_vec(), cyphertext);
}

#[test]
fn test_encode_empty_encrypted_payload() {
    let res = encode_encrypted_payload([3; 12], &[]);
    assert_eq!(res, Err(Error::CypherTextEmpty));
}

#[test]
fn test_parse_zero_length_ciphertext() {
    // A valid nonce followed by a zero LENGTH must be rejected at framing.
    let mut bytes = [3u8; 12].to_vec();
    bytes.push(0x00);
    assert_eq!(parse_encrypted_payload(&bytes), Err(Error::CypherTextEmpty));
}

#[test]
fn test_parse_encrypted_payload_lengths_ignores_trailing() {
    let payload = encode_encrypted_payload([3; 12], &[1, 2, 3, 4]).unwrap();
    // trailing bytes that are not a payload are ignored
    let mut bytes = payload.clone();
    bytes.extend_from_slice(&[0xFF; 5]);
    assert_eq!(parse_encrypted_payload_lengths(&bytes).unwrap(), vec![4]);
    // a second full payload is still enumerated
    let mut bytes = payload.clone();
    bytes.extend_from_slice(&encode_encrypted_payload([4; 12], &[5; 11]).unwrap());
    assert_eq!(
        parse_encrypted_payload_lengths(&bytes).unwrap(),
        vec![4, 11]
    );
    // the first payload stays mandatory
    assert_eq!(
        parse_encrypted_payload_lengths(&[0xFF; 5]),
        Err(Error::Corrupted)
    );
}

#[test]
fn test_encode_decode_derivation_paths() {
    let bytes =
        encode_derivation_paths(vec![parse_path("0/1h/2/3h"), parse_path("84'/0'/0'/2'")]).unwrap();
    let expected = vec![
        2, 4, 0, 0, 0, 0, 128, 0, 0, 1, 0, 0, 0, 2, 128, 0, 0, 3, 4, 128, 0, 0, 84, 128, 0, 0, 0,
        128, 0, 0, 0, 128, 0, 0, 2,
    ];
    assert_eq!(expected, bytes);
    let (offset, paths) = parse_derivation_paths(&bytes).unwrap();
    assert_eq!(offset, 35);
    assert_eq!(
        paths,
        vec![parse_path("0/1h/2/3h"), parse_path("84'/0'/0'/2'")]
    );
}

#[test]
fn test_decode_deriv_path_sorted() {
    let bytes =
        encode_derivation_paths(vec![parse_path("84'/0'/0'/2'"), parse_path("0/1h/2/3h")]).unwrap();
    let (_, paths) = parse_derivation_paths(&bytes).unwrap();
    assert_eq!(
        paths,
        // NOTE: order of derivation paths is reverted here as during parsing they are stored
        // in an BTreeSet in order to avoid duplicates
        vec![parse_path("0/1h/2/3h"), parse_path("84'/0'/0'/2'")]
    );
}

#[test]
fn test_decode_deriv_path_no_duplicates() {
    let bytes = encode_derivation_paths(vec![
        parse_path("0/1h/2/3h"),
        parse_path("84'/0'/0'/2'"),
        parse_path("84'/0'/0'/2'"),
    ])
    .unwrap();
    let (_, paths) = parse_derivation_paths(&bytes).unwrap();
    assert_eq!(
        paths,
        vec![parse_path("0/1h/2/3h"), parse_path("84'/0'/0'/2'")]
    );
}

#[test]
fn test_decode_deriv_path_empty() {
    let bytes = encode_derivation_paths(vec![]).unwrap();
    assert_eq!(bytes, vec![0x00]);
    let (_, paths) = parse_derivation_paths(&bytes).unwrap();
    assert_eq!(paths, vec![]);
}

#[test]
fn test_encode_zero_child_deriv_path() {
    // A path with no children would encode CHILD_COUNT = 0, which the decoder
    // rejects; refuse it on encode instead of emitting an unparseable byte.
    let res = encode_derivation_paths(vec![parse_path("m")]);
    assert_eq!(res, Err(Error::DerivPathEmpty));
}

#[test]
fn test_encode_too_much_deriv_paths() {
    // Distinct paths: duplicates would be deduplicated away before the length check.
    let mut deriv_paths = vec![];
    for i in 0..256u32 {
        deriv_paths.push(DerivationPath::from(vec![i]));
    }
    assert_eq!(deriv_paths.len(), 256);
    let res = encode_derivation_paths(deriv_paths);
    assert_eq!(res, Err(Error::DerivPathLength));
}

#[test]
fn test_encode_too_long_deriv_paths() {
    let deriv_path = vec![0u32; 256];
    assert_eq!(deriv_path.len(), 256);
    let res = encode_derivation_paths(vec![DerivationPath::from(deriv_path)]);
    assert_eq!(res, Err(Error::DerivPathLength));
}

#[test]
fn test_encode_decode_encrypted_payload() {
    let payloads = [
        "test".as_bytes().to_vec(),
        [1; 0x1FFF].to_vec(),
        [2; 0x2FFFFFFF].to_vec(),
    ];
    for payload in payloads {
        let bytes = encode_encrypted_payload([3; 12], &payload).unwrap();
        let (nonce, cyphertext) = parse_encrypted_payload(&bytes).unwrap();
        assert_eq!([3u8; 12], nonce);
        assert_eq!(payload, cyphertext);
    }
}

#[test]
fn test_encode_empty_individual_secrets() {
    let res = encode_individual_secrets(&[]);
    assert_eq!(res, Err(Error::IndividualSecretsEmpty));
}

#[test]
fn test_too_much_individual_secrets() {
    let mut secrets = vec![];
    for _ in 0..256 {
        let secret: [u8; 32] = random();
        secrets.push(secret);
    }
    let res = encode_individual_secrets(&secrets);
    assert_eq!(res, Err(Error::IndividualSecretsLength));
}

#[test]
fn test_encode_decode_individual_secrets() {
    let secrets = vec![[2; 32], [1; 32]];
    let bytes = encode_individual_secrets(&secrets).unwrap();
    let expected = vec![
        2u8, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        2, 2, 2, 2, 2,
    ];
    assert_eq!(expected, bytes);
    let (_, decoded) = parse_individual_secrets(&bytes).unwrap();
    // BTreeSet sorts by value, so the encoded order is [1; 32], [2; 32].
    assert_eq!(vec![[1; 32], [2; 32]], decoded);
}

#[test]
fn test_encode_individual_secrets_no_duplicates() {
    let secrets = vec![[7; 32], [7; 32]];
    let bytes = encode_individual_secrets(&secrets).unwrap();
    let expected = vec![
        1u8, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
        7, 7, 7,
    ];
    assert_eq!(expected, bytes);
}

#[test]
fn test_decode_individual_secrets_no_duplicates() {
    let bytes = vec![
        2u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0,
    ];
    let (_, secrets) = parse_individual_secrets(&bytes).unwrap();
    assert_eq!(secrets.len(), 1);
}

#[test]
fn test_encode_decode_v1() {
    let bytes = encode_v1(
        0x01,
        encode_derivation_paths(vec![parse_path("8/9")]).unwrap(),
        [0x01; 33].to_vec(),
        0x01,
        encode_encrypted_payload([0x04u8; 12], &[0x00]).unwrap(),
    );
    // <MAGIC>
    let mut expected = MAGIC.as_bytes().to_vec();
    // <VERSION>
    expected.append(&mut vec![0x01]);
    // <DERIVATION_PATHS>
    expected.append(&mut vec![
        0x01, 0x02, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x09,
    ]);
    // <INDIVIDUAL_SECRETS>
    expected.append(&mut [0x01; 33].to_vec());
    // <ENCRYPTION>
    expected.append(&mut vec![0x01]);
    // <ENCRYPTED_PAYLOAD>
    expected.append(&mut encode_encrypted_payload([0x04u8; 12], &[0x00]).unwrap());
    assert_eq!(bytes, expected);
    let version = decode_version(&bytes).unwrap();
    assert_eq!(version, 0x01);
    let derivs = decode_derivation_paths(&bytes).unwrap();
    assert_eq!(derivs, vec![parse_path("8/9")]);
    let (derivs, secrets, encryption, nonce, cyphertext) = decode_v1(&bytes).unwrap();
    assert_eq!(derivs, vec![parse_path("8/9")]);
    assert_eq!(secrets, vec![[0x01; 32]]);
    assert_eq!(encryption, 0x01);
    assert_eq!(nonce, [0x04u8; 12]);
    assert_eq!(cyphertext, vec![0x00]);
}

#[test]
fn test_encrypt_sanitizing() {
    // Empty keyvector must fail
    let keys = vec![];
    let data = "test".as_bytes().to_vec();
    let res = encrypt_chacha20_poly1305_v1(
        &RustBitcoin,
        &mut OsRandom,
        vec![],
        Content::Bip380,
        keys,
        &data,
        Padding::None,
    );
    assert_eq!(res, Err(Error::KeyCount));

    // > 255 keys must fail
    let mut keys = BTreeSet::new();
    while keys.len() < 256 {
        let key: [u8; 32] = random();
        keys.insert(key);
    }
    let keys = keys.into_iter().collect::<Vec<_>>();
    let res = encrypt_chacha20_poly1305_v1(
        &RustBitcoin,
        &mut OsRandom,
        vec![],
        Content::Bip380,
        keys,
        &data,
        Padding::None,
    );
    assert_eq!(res, Err(Error::KeyCount));

    // Empty payload must fail
    let keys = [pk1()].to_vec();
    let res = encrypt_chacha20_poly1305_v1(
        &RustBitcoin,
        &mut OsRandom,
        vec![],
        Content::Bip380,
        keys,
        &[],
        Padding::None,
    );
    assert_eq!(res, Err(Error::DataLength));

    // > 255 deriv path must fail
    let keys = [pk1()].to_vec();
    let mut deriv_paths = BTreeSet::new();
    while deriv_paths.len() < 256 {
        let raw_deriv: [u32; 4] = random();
        deriv_paths.insert(DerivationPath::from(raw_deriv.to_vec()));
    }
    let deriv_paths = deriv_paths.into_iter().collect();
    let res = encrypt_chacha20_poly1305_v1(
        &RustBitcoin,
        &mut OsRandom,
        deriv_paths,
        Content::Bip380,
        keys,
        &data,
        Padding::None,
    );
    assert_eq!(res, Err(Error::DerivPathCount));
}

#[test]
fn test_keys_deduplicated_after_x_only_normalization() {
    // Two keys sharing an x coordinate normalize to the same x-only key and must
    // count once in the secret derivation.
    let key = pk1();
    assert_eq!(
        decryption_secret(&RustBitcoin, &[key]),
        decryption_secret(&RustBitcoin, &[key, key])
    );

    let payload = encode_plaintext(
        &[(&Vec::try_from(Content::Bip380).unwrap(), b"test")],
        Padding::None,
    )
    .unwrap();
    let nonce = [7u8; 12];
    let decoys = [[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];
    let single =
        encode_v1_backup_for_test_vectors(vec![], vec![pk1()], payload.clone(), nonce, &decoys)
            .unwrap();
    let both =
        encode_v1_backup_for_test_vectors(vec![], vec![pk1(), pk1()], payload, nonce, &decoys)
            .unwrap();
    assert_eq!(single, both);
}

#[test]
fn test_basic_encrypt_decrypt() {
    let keys = vec![pk2(), pk1()];
    let data = "test".as_bytes().to_vec();
    let bytes = encrypt_chacha20_poly1305_v1(
        &RustBitcoin,
        &mut OsRandom,
        vec![],
        Content::Bip380,
        keys,
        &data,
        Padding::None,
    )
    .unwrap();

    let version = decode_version(&bytes).unwrap();
    assert_eq!(version, 1);

    let deriv_paths = decode_derivation_paths(&bytes).unwrap();
    assert!(deriv_paths.is_empty());

    let (_, individual_secrets, encryption_type, nonce, cyphertext) = decode_v1(&bytes).unwrap();
    assert_eq!(encryption_type, 0x01);

    let decrypted_1 = decrypt_chacha20_poly1305_v1(
        &RustBitcoin,
        pk1(),
        &individual_secrets,
        cyphertext.clone(),
        nonce,
    )
    .unwrap();
    assert_eq!(decrypted_1, vec![(Content::Bip380, b"test".to_vec())]);
    let decrypted_2 = decrypt_chacha20_poly1305_v1(
        &RustBitcoin,
        pk2(),
        &individual_secrets,
        cyphertext.clone(),
        nonce,
    )
    .unwrap();
    assert_eq!(decrypted_2, vec![(Content::Bip380, b"test".to_vec())]);
    let decrypted_3 = decrypt_chacha20_poly1305_v1(
        &RustBitcoin,
        pk3(),
        &individual_secrets,
        cyphertext.clone(),
        nonce,
    );
    assert!(decrypted_3.is_err());
}

#[test]
fn test_encrypt_excludes_fallback_derivation_paths() {
    let keys = vec![pk1()];
    let data = "test".as_bytes().to_vec();
    let fallback_bitcoin = parse_path("84h/0h/0h");
    let fallback_testnet = parse_path("87h/1h/9h");
    let custom = parse_path("8/9");

    let bytes = encrypt_chacha20_poly1305_v1(
        &RustBitcoin,
        &mut OsRandom,
        vec![
            fallback_bitcoin.clone(),
            fallback_testnet.clone(),
            custom.clone(),
        ],
        Content::Bip380,
        keys,
        &data,
        Padding::None,
    )
    .unwrap();

    let deriv_paths = decode_derivation_paths(&bytes).unwrap();
    assert_eq!(deriv_paths, vec![custom]);
    assert!(!deriv_paths.contains(&fallback_bitcoin));
    assert!(!deriv_paths.contains(&fallback_testnet));
}

#[test]
fn test_padded_encrypt_decrypt() {
    let keys = vec![pk2(), pk1()];
    let data = "test".as_bytes().to_vec();
    let bytes = encrypt_chacha20_poly1305_v1(
        &RustBitcoin,
        &mut OsRandom,
        vec![],
        Content::Bip380,
        keys,
        &data,
        Padding::Geometric,
    )
    .unwrap();

    let (_, individual_secrets, encryption_type, nonce, cyphertext) = decode_v1(&bytes).unwrap();
    // padding lives in the plaintext, the encryption byte stays 0x01
    assert_eq!(encryption_type, 0x01);
    assert_eq!(cyphertext.len(), PADDING_MIN_SIZE + 16);

    let decrypted =
        decrypt_chacha20_poly1305_v1(&RustBitcoin, pk1(), &individual_secrets, cyphertext, nonce)
            .unwrap();
    assert_eq!(decrypted, vec![(Content::Bip380, b"test".to_vec())]);
}

#[test]
fn test_secret_padded_encrypt_decrypt() {
    let keys = vec![pk1()];
    let data = "test".as_bytes().to_vec();
    let bytes = encrypt_chacha20_poly1305_v1(
        &RustBitcoin,
        &mut OsRandom,
        vec![],
        Content::Bip380,
        keys,
        &data,
        Padding::None,
    )
    .unwrap();

    let (_, individual_secrets, _, nonce, cyphertext) = decode_v1(&bytes).unwrap();
    assert_eq!(individual_secrets.len(), 5);
    let decrypted =
        decrypt_chacha20_poly1305_v1(&RustBitcoin, pk1(), &individual_secrets, cyphertext, nonce)
            .unwrap();
    assert_eq!(decrypted, vec![(Content::Bip380, b"test".to_vec())]);
}

#[test]
fn test_decrypt_wrong_secret() {
    let secret = RustBitcoin.sha256("secret".as_bytes());
    let wrong_secret = RustBitcoin.sha256("wrong_secret".as_bytes());

    let payload = "payload".as_bytes().to_vec();
    let nonce = draw_nonce(&mut OsRandom);
    let (nonce, ciphertext) = encrypt_with_nonce(&RustBitcoin, secret, payload, nonce).unwrap();
    // decrypting with secret success
    let _ = try_decrypt_chacha20_poly1305(&RustBitcoin, &ciphertext, &secret, nonce).unwrap();
    // decrypting with wrong secret fails
    let fails = try_decrypt_chacha20_poly1305(&RustBitcoin, &ciphertext, &wrong_secret, nonce);
    assert!(fails.is_none());
}

#[test]
fn test_decrypt_wrong_nonce() {
    let secret = RustBitcoin.sha256("secret".as_bytes());

    let payload = "payload".as_bytes().to_vec();
    let nonce = draw_nonce(&mut OsRandom);
    let (nonce, ciphertext) = encrypt_with_nonce(&RustBitcoin, secret, payload, nonce).unwrap();
    // decrypting with correct nonce success
    let _ = try_decrypt_chacha20_poly1305(&RustBitcoin, &ciphertext, &secret, nonce).unwrap();
    // decrypting with wrong nonce fails
    let nonce = [0xF1; 12];
    let fails = try_decrypt_chacha20_poly1305(&RustBitcoin, &ciphertext, &secret, nonce);
    assert!(fails.is_none());
}

#[test]
fn test_decrypt_corrupted_ciphertext_fails() {
    let secret = RustBitcoin.sha256("secret".as_bytes());

    let payload = "payload".as_bytes().to_vec();
    let nonce = draw_nonce(&mut OsRandom);
    let (nonce, mut ciphertext) = encrypt_with_nonce(&RustBitcoin, secret, payload, nonce).unwrap();
    // decrypting with secret success
    let _ = try_decrypt_chacha20_poly1305(&RustBitcoin, &ciphertext, &secret, nonce).unwrap();

    // corrupting the ciphertext
    let offset = ciphertext.len() - 10;
    for i in offset..offset + 5 {
        *ciphertext.get_mut(i).unwrap() = 0;
    }

    // decryption must then fails
    let fails = try_decrypt_chacha20_poly1305(&RustBitcoin, &ciphertext, &secret, nonce);
    assert!(fails.is_none());
}

mod derivation_paths {
    use super::*;
    use alloc::{string::String, vec::Vec};

    const TEST_VECTORS_JSON: &str = include_str!("../../test_vectors/derivation_path.json");

    #[derive(serde::Deserialize)]
    struct TestVector {
        description: String,
        paths: Vec<String>,
        expected: Option<String>,
    }

    #[test]
    fn test_vector_derivation_path_ser_deser() {
        let vectors: Vec<TestVector> = serde_json::from_str(TEST_VECTORS_JSON).unwrap();

        let mut cases: Vec<(
            Vec<DerivationPath>,
            Option<Vec<u8>>,
            String, /* description */
        )> = vec![];
        for v in vectors {
            let p = v.paths.into_iter().map(|s| parse_path(&s)).collect();
            let ser: Option<Vec<u8>> = v
                .expected
                .map(|hex_str| hex::decode(hex_str).expect(&v.description));
            cases.push((p, ser, v.description));
        }

        for (paths, expected, description) in cases {
            // serialize
            let result = encode_derivation_paths(paths.clone()).ok();
            if result != expected {
                panic!("Derivation path serialization failed: {description}");
            }

            // deserialize; the encoder normalizes, so compare against the normalized input
            if let Some(serialized) = expected {
                let (_, paths2) = parse_derivation_paths(&serialized).expect(&description);
                let mut paths = paths;
                paths.sort();
                paths.dedup();
                if paths != paths2 {
                    panic!("Derivation path deserialization failed: {description}");
                }
            }
        }
    }
}

mod individual_secrets_vectors {
    use super::*;
    use alloc::{string::String, vec::Vec};

    const TEST_VECTORS_JSON: &str = include_str!("../../test_vectors/individual_secrets.json");

    #[derive(serde::Deserialize)]
    struct TestVector {
        description: String,
        secrets: Vec<String>,
        expected: Option<String>,
    }

    #[test]
    #[allow(clippy::type_complexity)]
    fn test_vector_individual_secrets_ser_deser() {
        let vectors: Vec<TestVector> = serde_json::from_str(TEST_VECTORS_JSON).unwrap();

        let mut cases: Vec<(
            Vec<[u8; 32]>,
            Option<Vec<u8>>,
            String, /* description */
        )> = vec![];

        for v in vectors {
            let secrets = v
                .secrets
                .into_iter()
                .map(|hex_str| {
                    let bytes = hex::decode(hex_str).expect(&v.description);
                    let arr: [u8; 32] = bytes.try_into().expect("secret must be 32 bytes");
                    arr
                })
                .collect();
            let ser: Option<Vec<u8>> = v
                .expected
                .map(|hex_str| hex::decode(hex_str).expect(&v.description));
            cases.push((secrets, ser, v.description));
        }

        for (mut secrets, expected, description) in cases {
            // serialize
            let result = encode_individual_secrets(&secrets).ok();
            if result != expected {
                panic!("Individual secrets serialization failed: {description}");
            }

            // deserialize
            if let Some(exp) = expected {
                let (_, mut parsed) = parse_individual_secrets(&exp).expect(&description);
                secrets.sort();
                secrets.dedup();
                parsed.sort();

                if secrets != parsed {
                    panic!("Individual secrets deserialization failed: {description}");
                }
            }
        }
    }
}

mod encryption_secret {
    use super::*;
    use alloc::{string::String, vec::Vec};

    const TEST_VECTORS_JSON: &str = include_str!("../../test_vectors/encryption_secret.json");

    #[derive(serde::Deserialize, serde::Serialize)]
    struct TestVector {
        description: String,
        keys: Vec<String>,
        decryption_secret: String,
        individual_secrets: Vec<String>,
    }

    #[test]
    #[ignore]
    fn regenerate_vectors() {
        let mut vectors: Vec<TestVector> = serde_json::from_str(TEST_VECTORS_JSON).unwrap();
        for v in vectors.iter_mut() {
            let mut raw_keys: Vec<[u8; 32]> = v.keys.iter().map(|s| xonly(s)).collect();
            raw_keys.sort();
            raw_keys.dedup();

            let s = decryption_secret(&RustBitcoin, &raw_keys);
            v.decryption_secret = hex::encode(s);
            v.individual_secrets = individual_secrets(&RustBitcoin, &s, &raw_keys)
                .iter()
                .map(hex::encode)
                .collect();
        }
        let out = serde_json::to_string_pretty(&vectors).unwrap();
        std::fs::write("../test_vectors/encryption_secret.json", out + "\n").unwrap();
    }

    #[test]
    fn test_vector_encryption_secret() {
        let vectors: Vec<TestVector> = serde_json::from_str(TEST_VECTORS_JSON).unwrap();

        for v in vectors {
            let description = &v.description;

            // Convert compressed pubkeys to x-only bytes and sort
            let mut raw_keys: Vec<[u8; XONLY_KEY_SIZE]> = v.keys.iter().map(|s| xonly(s)).collect();
            raw_keys.sort();
            raw_keys.dedup();

            // Parse expected decryption secret
            let expected_decryption_secret = hex::decode(&v.decryption_secret).expect(description);
            let expected_decryption_secret: [u8; 32] = expected_decryption_secret
                .try_into()
                .expect("decryption secret must be 32 bytes");

            // Parse expected individual secrets
            let expected_individual_secrets: Vec<[u8; 32]> = v
                .individual_secrets
                .iter()
                .map(|hex_str| {
                    let bytes = hex::decode(hex_str).expect(description);
                    let arr: [u8; 32] = bytes
                        .try_into()
                        .expect("individual secret must be 32 bytes");
                    arr
                })
                .collect();

            // Test decryption_secret generation
            let computed_decryption_secret = decryption_secret(&RustBitcoin, &raw_keys);
            assert_eq!(
                computed_decryption_secret, expected_decryption_secret,
                "Decryption secret mismatch: {description}"
            );

            // Test individual_secrets generation
            let computed_individual_secrets =
                individual_secrets(&RustBitcoin, &computed_decryption_secret, &raw_keys);
            assert_eq!(
                computed_individual_secrets.len(),
                expected_individual_secrets.len(),
                "Individual secrets count mismatch: {description}"
            );

            for (i, (computed, expected)) in computed_individual_secrets
                .iter()
                .zip(expected_individual_secrets.iter())
                .enumerate()
            {
                assert_eq!(
                    computed, expected,
                    "Individual secret {description} mismatch: {i}"
                );
            }

            // Test round-trip: recover decryption secret from individual secrets
            for (i, raw_key) in raw_keys.iter().enumerate() {
                let individual_sec = computed_individual_secrets[i];

                let si = tagged_hash(&RustBitcoin, INDIVIDUAL_SECRET.as_bytes(), raw_key);

                // Recover secret: S = Ci XOR Si
                let recovered_secret = xor(&individual_sec, &si);

                assert_eq!(
                    recovered_secret, expected_decryption_secret,
                    "Round-trip recovery failed for key {i}: {description}"
                );
            }
        }
    }
}

mod encryption_vectors {
    use super::*;
    use alloc::{string::String, vec::Vec};

    const TEST_VECTORS_JSON: &str =
        include_str!("../../test_vectors/chacha20poly1305_encryption.json");

    #[derive(serde::Deserialize, serde::Serialize)]
    struct TestVector {
        description: String,
        nonce: String,
        plaintext: String,
        secret: String,
        ciphertext: Option<String>,
    }

    #[test]
    #[ignore]
    fn regenerate_vectors() {
        let mut vectors: Vec<TestVector> = serde_json::from_str(TEST_VECTORS_JSON).unwrap();
        for v in vectors.iter_mut() {
            let nonce: [u8; 12] = hex::decode(&v.nonce).unwrap().try_into().unwrap();
            let secret: [u8; 32] = hex::decode(&v.secret).unwrap().try_into().unwrap();
            let plaintext = if v.plaintext.is_empty() {
                vec![]
            } else {
                hex::decode(&v.plaintext).unwrap()
            };
            v.ciphertext = encrypt_with_nonce(&RustBitcoin, secret, plaintext, nonce)
                .ok()
                .map(|(_, ct)| hex::encode(ct));
        }
        let out = serde_json::to_string_pretty(&vectors).unwrap();
        std::fs::write(
            "../test_vectors/chacha20poly1305_encryption.json",
            out + "\n",
        )
        .unwrap();
    }

    #[test]
    fn test_vector_chacha20poly1305_encryption() {
        let vectors: Vec<TestVector> = serde_json::from_str(TEST_VECTORS_JSON).unwrap();

        for v in vectors {
            let description = &v.description;

            // Parse inputs
            let nonce_bytes = hex::decode(&v.nonce).expect(description);
            let nonce: [u8; 12] = nonce_bytes.try_into().expect("nonce must be 12 bytes");

            let secret_bytes = hex::decode(&v.secret).expect(description);
            let secret: [u8; 32] = secret_bytes.try_into().expect("secret must be 32 bytes");

            let plaintext = if v.plaintext.is_empty() {
                vec![]
            } else {
                hex::decode(&v.plaintext).expect(description)
            };

            if let Some(expected_ciphertext_hex) = v.ciphertext {
                // Expected to succeed
                let expected_ciphertext = hex::decode(&expected_ciphertext_hex).expect(description);

                // Test encryption
                let (_, computed_ciphertext) =
                    encrypt_with_nonce(&RustBitcoin, secret, plaintext.clone(), nonce)
                        .expect(description);

                assert_eq!(
                    computed_ciphertext, expected_ciphertext,
                    "Ciphertext mismatch: {description}"
                );

                // Test decryption
                let decrypted = try_decrypt_chacha20_poly1305(
                    &RustBitcoin,
                    &computed_ciphertext,
                    &secret,
                    nonce,
                )
                .expect(description);

                assert_eq!(decrypted, plaintext, "Decryption failed: {description}");
            } else {
                // Expected to fail
                let result = encrypt_with_nonce(&RustBitcoin, secret, plaintext, nonce);
                assert!(
                    result.is_err(),
                    "Encryption should have failed: {description}"
                );
            }
        }
    }

    #[test]
    fn test_zeroed_nonce_rejected() {
        let secret = [0xab; 32];
        let data = vec![0x01, 0x02, 0x03];
        let zeroed_nonce = [0u8; 12];
        let result = encrypt_with_nonce(&RustBitcoin, secret, data, zeroed_nonce);
        assert_eq!(result, Err(Error::ZeroedNonce));
    }
}

mod encrypted_backup {
    use super::*;
    use alloc::{string::String, vec::Vec};

    const TEST_VECTORS_JSON: &str = include_str!("../../test_vectors/encrypted_backup.json");

    fn default_true() -> bool {
        true
    }
    fn is_true(b: &bool) -> bool {
        *b
    }

    // Nonzero nonce used only to build the all-zero-nonce rejection vector:
    // encrypt with it, then overwrite the serialized nonce field with zeros.
    const SENTINEL_NONCE: [u8; 12] = [
        0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18, 0x29, 0x3a, 0x4b, 0x5c,
    ];

    #[derive(serde::Deserialize, serde::Serialize)]
    struct ContentItem {
        content: String,
        plaintext: String,
    }

    #[derive(serde::Deserialize, serde::Serialize)]
    struct TestVector {
        description: String,
        version: u8,
        encryption: u8,
        content: String,
        keys: Vec<String>,
        decoy_individual_secrets: Vec<String>,
        derivation_paths: Vec<String>,
        plaintext: String,
        nonce: String,
        expected: String,
        /// `false` marks a backup that parsers MUST reject (e.g. an all-zero
        /// nonce). Defaults to `true`.
        #[serde(default = "default_true", skip_serializing_if = "is_true")]
        valid: bool,
        /// Additional content items packed into the same payload after the
        /// primary `content`/`plaintext`, for multi-content backups.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        extra: Vec<ContentItem>,
        /// Optional hex of arbitrary bytes appended to `expected` before
        /// parsing. Parsers MUST ignore trailing bytes past the end of
        /// the self-delimited backup.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        trailing: Option<String>,
    }

    /// The serialized `(content_metadata, plaintext)` items a vector encodes:
    /// the primary `content`/`plaintext` followed by any `extra` items.
    fn vector_items(v: &TestVector) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
        let mut metas = vec![hex::decode(&v.content).expect(&v.description)];
        let mut plaintexts = vec![v.plaintext.as_bytes().to_vec()];
        for e in &v.extra {
            metas.push(hex::decode(&e.content).expect(&v.description));
            plaintexts.push(e.plaintext.as_bytes().to_vec());
        }
        (metas, plaintexts)
    }

    fn encode_payload(metas: &[Vec<u8>], plaintexts: &[Vec<u8>]) -> Vec<u8> {
        let items: Vec<(&[u8], &[u8])> = metas
            .iter()
            .zip(plaintexts.iter())
            .map(|(m, p)| (m.as_slice(), p.as_slice()))
            .collect();
        encode_plaintext(&items, Padding::None).unwrap()
    }

    fn decoy_individual_secrets(v: &TestVector) -> Vec<[u8; 32]> {
        v.decoy_individual_secrets
            .iter()
            .map(|hex_str| {
                let bytes = hex::decode(hex_str).expect(&v.description);
                bytes.try_into().expect("decoy secret must be 32 bytes")
            })
            .collect()
    }

    fn envelope_derivation_paths(mut derivation_paths: Vec<DerivationPath>) -> Vec<DerivationPath> {
        let fallback_derivation_paths = fallback_derivation_path_set();
        derivation_paths.retain(|path| !fallback_derivation_paths.contains(path));
        derivation_paths.sort();
        derivation_paths.dedup();
        derivation_paths
    }

    #[test]
    #[ignore]
    fn regenerate_vectors() {
        let mut vectors: Vec<TestVector> = serde_json::from_str(TEST_VECTORS_JSON).unwrap();
        for v in vectors.iter_mut() {
            let keys: Vec<[u8; 32]> = v.keys.iter().map(|s| xonly(s)).collect();
            let derivation_paths: Vec<DerivationPath> =
                v.derivation_paths.iter().map(|s| parse_path(s)).collect();
            let nonce: [u8; 12] = hex::decode(&v.nonce).unwrap().try_into().unwrap();
            let decoys = decoy_individual_secrets(v);
            let (metas, plaintexts) = vector_items(v);
            let payload = encode_payload(&metas, &plaintexts);

            let encrypted = if v.valid {
                encode_v1_backup_for_test_vectors(derivation_paths, keys, payload, nonce, &decoys)
                    .unwrap()
            } else {
                // All-zero-nonce backup: encrypt with the sentinel nonce, then
                // overwrite the serialized nonce field with zeros.
                let mut enc = encode_v1_backup_for_test_vectors(
                    derivation_paths,
                    keys,
                    payload,
                    SENTINEL_NONCE,
                    &decoys,
                )
                .unwrap();
                let pos = enc
                    .windows(12)
                    .position(|w| w == SENTINEL_NONCE)
                    .expect("sentinel nonce present");
                for b in &mut enc[pos..pos + 12] {
                    *b = 0;
                }
                assert!(
                    matches!(decode_v1(&enc), Err(Error::ZeroedNonce)),
                    "zeroed-nonce backup must be rejected"
                );
                enc
            };
            v.expected = hex::encode(&encrypted);
        }
        let out = serde_json::to_string_pretty(&vectors).unwrap();
        std::fs::write("../test_vectors/encrypted_backup.json", out + "\n").unwrap();
    }

    #[test]
    fn test_vector_encrypted_backup() {
        let vectors: Vec<TestVector> = serde_json::from_str(TEST_VECTORS_JSON).unwrap();

        for v in vectors {
            let description = &v.description;

            let keys: Vec<[u8; 32]> = v.keys.iter().map(|s| xonly(s)).collect();

            let derivation_paths: Vec<DerivationPath> =
                v.derivation_paths.iter().map(|s| parse_path(s)).collect();
            let expected_derivation_paths = envelope_derivation_paths(derivation_paths.clone());

            let nonce_bytes = hex::decode(&v.nonce).expect(description);
            let nonce: [u8; 12] = nonce_bytes.try_into().expect("nonce must be 12 bytes");
            let decoys = decoy_individual_secrets(&v);

            let expected_bytes = hex::decode(&v.expected).expect(description);

            let (metas, plaintexts) = vector_items(&v);
            let expected_items: Vec<(Content, Vec<u8>)> = metas
                .iter()
                .zip(plaintexts.iter())
                .map(|(m, p)| (parse_content(m).expect(description).1, p.clone()))
                .collect();

            // Invalid vectors (all-zero nonce) MUST be rejected at parse time,
            // before any decryption is attempted.
            if !v.valid {
                assert!(
                    matches!(decode_v1(&expected_bytes), Err(Error::ZeroedNonce)),
                    "all-zero nonce must be rejected: {description}"
                );
                continue;
            }

            // Test encryption: re-encode through the multi-content payload path.
            let payload = encode_payload(&metas, &plaintexts);
            let encrypted = encode_v1_backup_for_test_vectors(
                derivation_paths.clone(),
                keys.clone(),
                payload,
                nonce,
                &decoys,
            )
            .expect(description);

            assert_eq!(
                encrypted, expected_bytes,
                "Encrypted payload mismatch: {description}"
            );

            // Test decryption
            let version = decode_version(&encrypted).expect(description);
            assert_eq!(version, v.version, "Version mismatch: {description}");

            let mut parsed_derivation_paths =
                decode_derivation_paths(&encrypted).expect(description);

            parsed_derivation_paths.sort();
            assert_eq!(
                parsed_derivation_paths, expected_derivation_paths,
                "Derivation paths mismatch: {description}"
            );

            let (_, individual_secrets, encryption_type, parsed_nonce, cyphertext) =
                decode_v1(&encrypted).expect(description);

            assert_eq!(
                encryption_type, v.encryption,
                "Encryption type mismatch: {description}"
            );
            assert_eq!(parsed_nonce, nonce, "Nonce mismatch: {description}");

            // Test decryption with each key
            for key in &keys {
                let decrypted = decrypt_chacha20_poly1305_v1(
                    &RustBitcoin,
                    *key,
                    &individual_secrets,
                    cyphertext.clone(),
                    parsed_nonce,
                )
                .expect(description);
                assert_eq!(
                    decrypted, expected_items,
                    "Decrypted items mismatch: {description}"
                );
            }

            // Trailing-bytes tolerance: when the vector provides a
            // `trailing` suffix, appending it to the valid backup MUST
            // NOT affect parsing or decryption. The framing is
            // self-delimited (VarInt <LENGTH> before the cyphertext),
            // so extra suffix bytes are ignored.
            let Some(trailing_hex) = v.trailing.as_deref() else {
                continue;
            };
            let trailing = hex::decode(trailing_hex).expect(description);
            let mut with_trailer = encrypted.clone();
            with_trailer.extend_from_slice(&trailing);

            let version_t = decode_version(&with_trailer).expect(description);
            assert_eq!(
                version_t, v.version,
                "Version mismatch with trailing bytes: {description}"
            );

            let mut parsed_paths_t = decode_derivation_paths(&with_trailer).expect(description);
            parsed_paths_t.sort();
            assert_eq!(
                parsed_paths_t, expected_derivation_paths,
                "Derivation paths mismatch with trailing bytes: {description}"
            );

            let (_, is_t, enc_t, nonce_t, cyphertext_t) =
                decode_v1(&with_trailer).expect(description);
            assert_eq!(
                enc_t, v.encryption,
                "Encryption type mismatch with trailing bytes: {description}"
            );
            assert_eq!(
                nonce_t, nonce,
                "Nonce mismatch with trailing bytes: {description}"
            );
            assert_eq!(
                cyphertext_t, cyphertext,
                "Cyphertext mismatch with trailing bytes: {description}"
            );

            let lengths = decode_v1_encrypted_payload_lengths(&encrypted).expect(description);
            let lengths_t = decode_v1_encrypted_payload_lengths(&with_trailer).expect(description);
            assert_eq!(
                lengths, lengths_t,
                "Payload lengths mismatch with trailing bytes: {description}"
            );

            for key in &keys {
                let decrypted = decrypt_chacha20_poly1305_v1(
                    &RustBitcoin,
                    *key,
                    &is_t,
                    cyphertext_t.clone(),
                    nonce_t,
                )
                .expect(description);
                assert_eq!(
                    decrypted, expected_items,
                    "Decrypted items mismatch with trailing bytes: {description}"
                );
            }
        }
    }
}

mod content_vectors {
    use super::*;
    use alloc::{
        string::{String, ToString},
        vec::Vec,
    };

    const TEST_VECTORS_JSON: &str = include_str!("../../test_vectors/content_type.json");

    #[derive(serde::Deserialize, serde::Serialize)]
    struct TestVector {
        description: String,
        valid: bool,
        content: String,
    }

    #[test]
    fn test_vector_content() {
        let vectors: Vec<TestVector> = serde_json::from_str(TEST_VECTORS_JSON).unwrap();

        let mut parsed = vec![];
        for v in vectors {
            let content = hex::decode(&v.content).expect(&v.description);
            match parse_content(&content) {
                Ok((_, content)) => {
                    assert!(v.valid);
                    parsed.push((content, v.description.to_string()));
                }
                Err(_) => assert!(!v.valid),
            }
        }

        let expected = vec![
            (Content::Bip138, "Bip 138".to_string()),
            (Content::Bip380, "Bip 380".to_string()),
            (Content::Bip388, "Bip 388".to_string()),
            (Content::Bip329, "Bip 329".to_string()),
            (Content::BIP(999), "Bip 999".to_string()),
            (Content::BIP(65535), "Bip max".to_string()),
            (Content::BIP(0), "Bip min".to_string()),
            (
                Content::Proprietary(vec![0x00, 0x01, 0x02, 0x03]),
                "Propietary 00010203".to_string(),
            ),
            (Content::String, "String".to_string()),
        ];

        assert_eq!(parsed, expected);
    }
}
