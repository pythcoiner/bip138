//! Dependency-free core of the BIP138 compact encryption scheme: the wire format
//! and the crypto orchestration. Every external primitive (SHA-256, the
//! ChaCha20-Poly1305 AEAD, randomness) is supplied by the caller through the
//! [`Crypto`] and [`Rng`] traits, and public keys cross as raw 32-byte x-only
//! keys, so the core pulls no elliptic-curve, hashing, cipher, or RNG dependency.
//! Bundled implementations and secp/descriptor handling live in the `bip138`
//! crate on top of this one.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

use alloc::{collections::BTreeSet, vec, vec::Vec};

pub mod crypto;
mod derivation;
#[cfg(feature = "ffi")]
pub mod ffi;
mod varint;

#[cfg(all(test, feature = "os-rng"))]
mod tests;

pub use crypto::{Crypto, Rng};
pub use derivation::DerivationPath;
use derivation::hardened;

const DECRYPTION_SECRET: &str = "BIP138_DECRYPTION_SECRET";
const INDIVIDUAL_SECRET: &str = "BIP138_INDIVIDUAL_SECRET";
pub const MAGIC: &str = "BIP138";

pub const PADDING_MIN_SIZE: usize = 10 * 1024;
const PADDING_GROWTH_NUMERATOR: usize = 5;
const PADDING_GROWTH_DENOMINATOR: usize = 4;
const COMMON_ACCOUNT_MAX: u32 = 9;

/// Size in bytes of a 32-byte x-only Schnorr/BIP340 public key.
pub const XONLY_KEY_SIZE: usize = 32;

/// x-only form of the BIP341 NUMS point. Keys equal to it are dropped from the
/// encryption set: nobody holds its private key, so encrypting to it is useless.
/// See bip-0341 "constructing and spending taproot outputs".
const NUMS_XONLY: [u8; XONLY_KEY_SIZE] = [
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    KeyCount,
    DerivPathCount,
    DerivPathLength,
    DerivPathEmpty,
    DataLength,
    Encrypt,
    Decrypt,
    Corrupted,
    Version,
    Magic,
    VarInt,
    WrongKey,
    IndividualSecretsEmpty,
    IndividualSecretsLength,
    CypherTextEmpty,
    CypherTextLength,
    ContentMetadata,
    Encryption,
    OffsetOverflow,
    EmptyBytes,
    Increment,
    ContentMetadataEmpty,
    ContentEnd,
    EncryptionReserved,
    ZeroedNonce,
    Padding,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Version {
    V0,
    V1,
    Unknown,
}

impl From<Version> for u8 {
    fn from(value: Version) -> Self {
        match value {
            Version::V0 => 0,
            Version::V1 => 1,
            Version::Unknown => 0xFF,
        }
    }
}

impl From<u8> for Version {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::V0,
            1 => Self::V1,
            _ => Self::Unknown,
        }
    }
}

impl Version {
    fn max() -> Self {
        Version::V1
    }
    pub fn is_valid(&self) -> bool {
        match self {
            Version::Unknown => false,
            Version::V0 | Version::V1 => true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encryption {
    Undefined,
    ChaCha20Poly1305,
    AesGcm256,
    Unknown,
}

impl From<u8> for Encryption {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::Undefined,
            1 => Self::ChaCha20Poly1305,
            _ => Self::Unknown,
        }
    }
}

impl From<Encryption> for u8 {
    fn from(value: Encryption) -> Self {
        match value {
            Encryption::Undefined => 0x00,
            Encryption::ChaCha20Poly1305 => 0x01,
            Encryption::AesGcm256 => 0x01,
            Encryption::Unknown => 0xFF,
        }
    }
}

impl Encryption {
    pub fn is_defined(&self) -> bool {
        match self {
            Encryption::Undefined | Encryption::Unknown => false,
            Encryption::AesGcm256 | Encryption::ChaCha20Poly1305 => true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Content {
    None,
    Bip138,
    Bip139,
    Bip380,
    Bip388,
    Bip329,
    BIP(u16),
    Proprietary(Vec<u8>),
    String,
    Unknown,
}

// `CONTENT` is a variable length field defining the type of the `PLAINTEXT` that
// follows it. It follows this format:
//
// `TYPE` (`LENGTH`) `DATA`
//
// A `PAYLOAD` carries one or more `CONTENT LENGTH PLAINTEXT` items, each `CONTENT`
// describing the `PLAINTEXT` immediately following it. The sequence ends at the
// first `TYPE` byte equal to `0x00` or at the end of the `PAYLOAD`; all remaining
// bytes are `PADDING` and are ignored.
//
// `TYPE`: 1-byte unsigned integer identifying how to interpret `DATA`.
//
// | Value  | Definition                             |
// |:-------|:---------------------------------------|
// | 0x00   | End of content items; padding follows  |
// | 0x01   | BIP Number (big-endian uint16)         |
// | 0x02   | Vendor-Specific Opaque Tag             |
// | 0x03   | String                                 |
//
// `LENGTH`: variable-length integer representing the length of `DATA` in bytes.
//
// For all `TYPE` values except `0x01`, `LENGTH` MUST be present.
//
// `DATA`: variable-length field whose encoding depends on `TYPE`.
//
// For `TYPE` values defined above:
// - 0x00: parsers MUST stop reading content items and treat the remaining bytes as padding.
// - 0x01: `LENGTH` MUST be omitted and `DATA` is a 2-byte big-endian unsigned integer representing the BIP number that defines it.
// - 0x02: `DATA` MUST be `LENGTH` bytes of opaque, vendor-specific data.
// - 0x03: `DATA` MUST be empty, and the following `PLAINTEXT` is the string itself, which MUST be valid UTF-8.
//
// For all `TYPE` values except `0x01`, parsers MUST reject `CONTENT` if `LENGTH` exceeds the remaining payload bytes.
//
// For an unknown `TYPE` less than `0x80`, parsers MUST consume its `LENGTH` bytes of `DATA`, treat the content type as unknown, consume the following payload `LENGTH` and `PLAINTEXT`, and continue with the next item.
//
// For an unknown `TYPE` greater than or equal to `0x80`, parsers MUST reject the payload.
const CONTENT_END: u8 = 0x00;
const CONTENT_BIP: u8 = 0x01;
const CONTENT_PROPRIETARY: u8 = 0x02;
const CONTENT_STRING: u8 = 0x03;
const CONTENT_UPGRADE: u8 = 0x80;

impl TryFrom<Content> for Vec<u8> {
    type Error = ();
    fn try_from(value: Content) -> Result<Self, ()> {
        let mut out = match &value {
            Content::Unknown | Content::None => return Err(()),
            Content::Bip139
            | Content::Bip138
            | Content::Bip380
            | Content::Bip388
            | Content::Bip329
            | Content::BIP(_) => {
                vec![CONTENT_BIP]
            }
            Content::Proprietary(_) => vec![CONTENT_PROPRIETARY],
            Content::String => vec![CONTENT_STRING],
        };
        let mut len = match &value {
            Content::Proprietary(d) => varint::encode(d.len() as u64),
            Content::String => varint::encode(0),
            _ => vec![],
        };
        out.append(&mut len);
        let mut data = match value {
            Content::None | Content::Unknown => vec![],
            Content::Bip138 => 138u16.to_be_bytes().to_vec(),
            Content::Bip139 => 139u16.to_be_bytes().to_vec(),
            Content::Bip380 => 380u16.to_be_bytes().to_vec(),
            Content::Bip388 => 388u16.to_be_bytes().to_vec(),
            Content::Bip329 => 329u16.to_be_bytes().to_vec(),
            Content::BIP(bip) => bip.to_be_bytes().to_vec(),
            Content::Proprietary(d) => d,
            Content::String => vec![],
        };
        out.append(&mut data);
        Ok(out)
    }
}

pub fn parse_content(bytes: &[u8]) -> Result<(usize, Content), Error> {
    let len = bytes.len();
    init_offset(bytes, 0)?;
    match bytes[0] {
        CONTENT_END => Err(Error::ContentEnd),
        CONTENT_BIP => {
            check_offset_lookahead(0, bytes, 3).map_err(|_| Error::ContentMetadata)?;
            let bip_bytes: [u8; 2] = bytes[1..3].try_into().expect("2 bytes");
            let bip = u16::from_be_bytes(bip_bytes);
            let content = match bip {
                138 => Content::Bip138,
                139 => Content::Bip139,
                380 => Content::Bip380,
                388 => Content::Bip388,
                329 => Content::Bip329,
                b => Content::BIP(b),
            };
            Ok((3, content))
        }
        t if t < CONTENT_UPGRADE => {
            let (data_len, offset) = varint::parse(&bytes[1..]).ok_or(Error::ContentMetadata)?;
            let data_len = usize::try_from(data_len).map_err(|_| Error::ContentMetadata)?;
            let start = 1 + offset;
            check_offset_lookahead(start, bytes, data_len)?;
            let end = start + data_len;
            if len < end {
                return Err(Error::ContentMetadata);
            }
            let data = bytes[offset + 1..end].to_vec();
            match t {
                CONTENT_PROPRIETARY => Ok((end, Content::Proprietary(data))),
                CONTENT_STRING => {
                    if !data.is_empty() {
                        return Err(Error::ContentMetadata);
                    }
                    Ok((end, Content::String))
                }
                // For an unknown `TYPE` less than `0x80`, parsers MUST consume its `LENGTH` bytes
                // of `DATA`, treat the content type as unknown, consume the following payload
                // `LENGTH` and `PLAINTEXT`, and continue with the next item.
                _ => Ok((end, Content::Unknown)),
            }
        }
        _ => {
            // For an unknown `TYPE` greater than or equal to `0x80`, parsers MUST reject the payload.
            Err(Error::ContentMetadata)
        }
    }
}

impl Content {
    pub fn is_known(&self) -> bool {
        match self {
            Content::None | Content::Unknown | Content::Proprietary(_) => false,
            Content::Bip138
            | Content::Bip139
            | Content::Bip380
            | Content::Bip388
            | Content::Bip329
            | Content::BIP(_)
            | Content::String => true,
        }
    }
}

pub fn tagged_hash<C: Crypto>(crypto: &C, tag: &[u8], bytes: &[u8]) -> [u8; 32] {
    // BIP340-style: prefix with SHA256(tag) || SHA256(tag)
    let tag_hash = crypto.sha256(tag);
    let mut buf = Vec::with_capacity(64 + bytes.len());
    buf.extend_from_slice(&tag_hash);
    buf.extend_from_slice(&tag_hash);
    buf.extend_from_slice(bytes);
    crypto.sha256(&buf)
}

pub fn xor(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0; 32];
    for i in 0..32 {
        out[i] = a[i] ^ b[i];
    }
    out
}

/// Draw a fresh 12-byte nonce. The spec requires a redraw when the source yields
/// an all-zero nonce; two zero draws in a row means the source is broken, and the
/// zero nonce then flows to `encrypt_with_nonce`, which rejects it.
pub fn draw_nonce<R: Rng>(rng: &mut R) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    for _ in 0..2 {
        rng.fill_bytes(&mut nonce);
        if nonce != [0u8; 12] {
            break;
        }
    }
    nonce
}

pub fn decryption_secret<C: Crypto>(crypto: &C, keys: &[[u8; XONLY_KEY_SIZE]]) -> [u8; 32] {
    // The secret is defined over the distinct keys in increasing lexicographic
    // order, so sort and deduplicate here rather than trust the caller. Two
    // keys sharing an x coordinate normalize to a single entry.
    let mut keys = keys.to_vec();
    keys.sort();
    keys.dedup();
    let mut bytes = Vec::with_capacity(keys.len() * XONLY_KEY_SIZE);
    for key in &keys {
        bytes.extend_from_slice(key);
    }
    tagged_hash(crypto, DECRYPTION_SECRET.as_bytes(), &bytes)
}

pub fn individual_secret<C: Crypto>(
    crypto: &C,
    secret: &[u8; 32],
    key: &[u8; XONLY_KEY_SIZE],
) -> [u8; 32] {
    let si = tagged_hash(crypto, INDIVIDUAL_SECRET.as_bytes(), key);
    let ci = xor(secret, &si);
    // Sanity harness: distinct domain-separation tags make c_i = 0
    // statistically impossible, so seeing it means secret derivation is
    // misconfigured (e.g. same tag for s and s_i).
    assert_ne!(
        ci, [0u8; 32],
        "c_i collapsed to zero, secret derivation is broken"
    );
    ci
}

pub fn individual_secrets<C: Crypto>(
    crypto: &C,
    secret: &[u8; 32],
    keys: &[[u8; XONLY_KEY_SIZE]],
) -> Vec<[u8; 32]> {
    keys.iter()
        .map(|k| individual_secret(crypto, secret, k))
        .collect::<Vec<_>>()
}

/// Common BIP32 derivation paths for a coin type (0 for mainnet, 1 for others).
/// A signer offers these when it has no explicit path to expose; the encoder
/// drops any of them from the stored set since a decoder assumes them.
pub fn common_derivation_paths(coin_type: u32) -> Vec<DerivationPath> {
    let mut paths = Vec::new();
    for account in 0..=COMMON_ACCOUNT_MAX {
        for script_type in [1, 2] {
            paths.push(DerivationPath::from(vec![
                hardened(48),
                hardened(coin_type),
                hardened(account),
                hardened(script_type),
            ]));
        }
    }
    for purpose in [44, 49, 84, 86, 87] {
        for account in 0..=COMMON_ACCOUNT_MAX {
            paths.push(DerivationPath::from(vec![
                hardened(purpose),
                hardened(coin_type),
                hardened(account),
            ]));
        }
    }
    paths
}

fn fallback_derivation_path_set() -> BTreeSet<DerivationPath> {
    let mut paths = BTreeSet::new();
    for coin_type in [0u32, 1u32] {
        paths.extend(common_derivation_paths(coin_type));
    }
    paths
}

pub fn encrypt_with_nonce<C: Crypto>(
    crypto: &C,
    secret: [u8; 32],
    data: Vec<u8>,
    nonce: [u8; 12],
) -> Result<([u8; 12], Vec<u8>), Error> {
    if nonce == [0u8; 12] {
        return Err(Error::ZeroedNonce);
    }
    if data.is_empty() {
        return Err(Error::EmptyBytes);
    }
    crypto
        .aead_encrypt(&secret, &nonce, &data)
        .map(|c| (nonce, c))
        .ok_or(Error::Encrypt)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Padding {
    None,
    Geometric,
}

fn doubling_bucket(len: usize) -> Result<usize, Error> {
    if len > u8::MAX as usize {
        return Err(Error::IndividualSecretsLength);
    }
    let mut bucket = 5usize;
    while bucket < len {
        bucket *= 2;
    }
    // the bucket saturates at the one-byte COUNT limit of the format
    Ok(bucket.min(u8::MAX as usize))
}

impl Padding {
    pub fn padded_size(&self, len: usize) -> Result<usize, Error> {
        match self {
            Padding::None => Ok(len),
            Padding::Geometric => geometric_bucket(len),
        }
    }
}

fn geometric_bucket(len: usize) -> Result<usize, Error> {
    if len <= PADDING_MIN_SIZE {
        return Ok(PADDING_MIN_SIZE);
    }
    let mut numerator = PADDING_MIN_SIZE as u128;
    let mut denominator = 1u128;
    let len = len as u128;
    let mut target = numerator / denominator;
    while target < len {
        numerator = numerator
            .checked_mul(PADDING_GROWTH_NUMERATOR as u128)
            .ok_or(Error::Padding)?;
        denominator = denominator
            .checked_mul(PADDING_GROWTH_DENOMINATOR as u128)
            .ok_or(Error::Padding)?;
        target = numerator / denominator;
    }
    usize::try_from(target).map_err(|_| Error::Padding)
}

/// Encode the decrypted payload as `(<CONTENT_METADATA><LENGTH><PLAINTEXT>)+ (<PADDING>)`.
/// Each item is a `(content_metadata, plaintext)` pair. Zero-fill padding after the
/// last item doubles as the `0x00` terminator that `decode_plaintext` stops at.
pub fn encode_plaintext(items: &[(&[u8], &[u8])], padding: Padding) -> Result<Vec<u8>, Error> {
    let mut payload = Vec::new();
    for (content_metadata, data) in items {
        payload.extend_from_slice(content_metadata);
        payload.append(&mut varint::encode(data.len() as u64));
        payload.extend_from_slice(data);
    }
    let target = padding.padded_size(payload.len())?;
    payload.resize(target, 0u8);
    Ok(payload)
}

/// Decode the content items from a decrypted payload. The sequence ends at the first
/// `0x00` `TYPE` byte (start of padding) or at the end of the payload.
pub fn decode_plaintext(bytes: &[u8]) -> Result<Vec<(Content, Vec<u8>)>, Error> {
    if bytes.is_empty() {
        return Err(Error::EmptyBytes);
    }
    let mut items = Vec::new();
    let mut offset = 0usize;
    while offset < bytes.len() {
        // A 0x00 TYPE byte marks the end of the content sequence; the rest is padding.
        if bytes[offset] == CONTENT_END {
            break;
        }
        // <CONTENT_METADATA>
        let (incr, content) = parse_content(&bytes[offset..])?;
        offset = offset.checked_add(incr).ok_or(Error::OffsetOverflow)?;
        // <LENGTH>
        let (data_len, incr) = varint::parse(&bytes[offset..]).ok_or(Error::DataLength)?;
        offset = offset.checked_add(incr).ok_or(Error::OffsetOverflow)?;
        let data_len = usize::try_from(data_len).map_err(|_| Error::DataLength)?;
        let end = offset.checked_add(data_len).ok_or(Error::OffsetOverflow)?;
        if end > bytes.len() {
            return Err(Error::Corrupted);
        }
        // <PLAINTEXT>
        items.push((content, bytes[offset..end].to_vec()));
        offset = end;
    }
    if items.is_empty() {
        return Err(Error::EmptyBytes);
    }
    Ok(items)
}

/// Encode following this format:
/// <LENGTH><DERIVATION_PATH_1><DERIVATION_PATH_2><..><DERIVATION_PATH_N>
///
/// The vector is sorted and deduplicated, so the encoding does not leak the caller's
/// ordering. This mirrors `encode_individual_secrets`.
pub fn encode_derivation_paths(derivation_paths: Vec<DerivationPath>) -> Result<Vec<u8>, Error> {
    let mut derivation_paths = derivation_paths;
    derivation_paths.sort();
    derivation_paths.dedup();
    if derivation_paths.len() > u8::MAX as usize {
        return Err(Error::DerivPathLength);
    }
    let mut encoded_paths = vec![derivation_paths.len() as u8];
    for path in derivation_paths {
        let childs = path.to_u32_vec();
        let len = childs.len();
        if len == 0 {
            return Err(Error::DerivPathEmpty);
        }
        if len > u8::MAX as usize {
            return Err(Error::DerivPathLength);
        }
        encoded_paths.push(len as u8);
        for c in childs {
            encoded_paths.extend_from_slice(&c.to_be_bytes());
        }
    }
    Ok(encoded_paths)
}

/// Encode following this format:
/// <LENGTH><INDIVIDUAL_SECRET_1><INDIVIDUAL_SECRET_2><..><INDIVIDUAL_SECRET_N>
pub fn encode_individual_secrets(individual_secrets: &[[u8; 32]]) -> Result<Vec<u8>, Error> {
    let mut individual_secrets = individual_secrets.to_vec();
    individual_secrets.sort();
    individual_secrets.dedup();
    if individual_secrets.len() > u8::MAX as usize {
        return Err(Error::IndividualSecretsLength);
    } else if individual_secrets.is_empty() {
        return Err(Error::IndividualSecretsEmpty);
    }
    let len = individual_secrets.len() as u8;
    let mut out = Vec::with_capacity(1 + (individual_secrets.len() * 32));
    out.push(len);
    for is in individual_secrets {
        out.extend_from_slice(&is);
    }
    Ok(out)
}

/// Encode following this format:
/// <NONCE><LENGTH><CYPHERTEXT>
pub fn encode_encrypted_payload(nonce: [u8; 12], cyphertext: &[u8]) -> Result<Vec<u8>, Error> {
    if cyphertext.is_empty() {
        return Err(Error::CypherTextEmpty);
    }
    let mut out = Vec::new();
    out.extend_from_slice(&nonce);
    out.append(&mut varint::encode(cyphertext.len() as u64));
    out.extend_from_slice(cyphertext);
    Ok(out)
}

/// Encode following this format
/// <MAGIC><VERSION><DERIVATION_PATHS><INDIVIDUAL_SECRETS><ENCRYPTION><ENCRYPTED_PAYLOAD>
/// NOTE: payload that will fail to decode can be encoded with this function, for instance with an
/// invalid version, the inputs args must be sanitized by the caller.
pub fn encode_v1(
    version: u8,
    mut derivation_paths: Vec<u8>,
    mut individual_secrets: Vec<u8>,
    encryption: u8,
    mut encrypted_payload: Vec<u8>,
) -> Vec<u8> {
    // <MAGIC>
    let mut out = MAGIC.as_bytes().to_vec();
    // <VERSION>
    out.push(version);
    // <DERIVATION_PATHS>
    out.append(&mut derivation_paths);
    // <INDIVIDUAL_SECRETS>
    out.append(&mut individual_secrets);
    // <ENCRYPTION>
    out.push(encryption);
    // <ENCRYPTED_PAYLOAD>
    out.append(&mut encrypted_payload);
    out
}

pub fn check_offset(offset: usize, bytes: &[u8]) -> Result<(), Error> {
    if bytes.len() <= offset {
        Err(Error::Corrupted)
    } else {
        Ok(())
    }
}

pub fn check_offset_lookahead(offset: usize, bytes: &[u8], lookahead: usize) -> Result<(), Error> {
    let target = offset
        .checked_add(lookahead)
        .ok_or(Error::Increment)?
        .checked_sub(1)
        .ok_or(Error::Increment)?;
    if bytes.len() <= target {
        Err(Error::Corrupted)
    } else {
        Ok(())
    }
}

pub fn init_offset(bytes: &[u8], value: usize) -> Result<usize, Error> {
    check_offset(value, bytes)?;
    Ok(value)
}

pub fn increment_offset(bytes: &[u8], offset: usize, incr: usize) -> Result<usize, Error> {
    check_offset(offset + incr, bytes)?;
    offset.checked_add(incr).ok_or(Error::OffsetOverflow)
}

/// Expects a payload following this format:
/// <MAGIC><VERSION><..>
pub fn decode_version(bytes: &[u8]) -> Result<u8, Error> {
    // <MAGIC>
    let offset = init_offset(bytes, parse_magic_byte(bytes)?)?;
    // <VERSION>
    let (_, version) = parse_version(&bytes[offset..])?;
    Ok(version)
}

/// Expects a payload following this format:
/// <MAGIC><VERSION><DERIVATION_PATHS><..>
pub fn decode_derivation_paths(bytes: &[u8]) -> Result<Vec<DerivationPath>, Error> {
    // <MAGIC>
    let mut offset = init_offset(bytes, parse_magic_byte(bytes)?)?;
    // <VERSION>
    let (incr, _) = parse_version(&bytes[offset..])?;
    offset = increment_offset(bytes, offset, incr)?;
    // <DERIVATION_PATHS>
    let (_, derivation_paths) = parse_derivation_paths(&bytes[offset..])?;
    Ok(derivation_paths)
}

/// Expects a payload following this format:
/// <MAGIC><VERSION><DERIVATION_PATHS><INDIVIDUAL_SECRETS><ENCRYPTION><ENCRYPTED_PAYLOAD><..>
#[allow(clippy::type_complexity)]
pub fn decode_v1(
    bytes: &[u8],
) -> Result<
    (
        Vec<DerivationPath>, /* derivation_paths */
        Vec<[u8; 32]>,       /* individual_secrets */
        u8,                  /* encryption_type */
        [u8; 12],            /* nonce */
        Vec<u8>,             /* cyphertext */
    ),
    Error,
> {
    let (offset, derivation_paths, individual_secrets, encryption_type) = parse_v1_header(bytes)?;
    // <ENCRYPTED_PAYLOAD>
    let (nonce, cyphertext) = parse_encrypted_payload(&bytes[offset..])?;

    Ok((
        derivation_paths,
        individual_secrets,
        encryption_type,
        nonce,
        cyphertext,
    ))
}

pub fn decode_v1_encrypted_payload_lengths(bytes: &[u8]) -> Result<Vec<usize>, Error> {
    let (offset, _, _, _) = parse_v1_header(bytes)?;
    parse_encrypted_payload_lengths(&bytes[offset..])
}

#[allow(clippy::type_complexity)]
fn parse_v1_header(bytes: &[u8]) -> Result<(usize, Vec<DerivationPath>, Vec<[u8; 32]>, u8), Error> {
    // <MAGIC>
    let mut offset = init_offset(bytes, parse_magic_byte(bytes)?)?;
    // <VERSION>
    let (incr, _) = parse_version(&bytes[offset..])?;
    offset = increment_offset(bytes, offset, incr)?;
    // <DERIVATION_PATHS>
    let (incr, derivation_paths) = parse_derivation_paths(&bytes[offset..])?;
    offset = increment_offset(bytes, offset, incr)?;
    // <INDIVIDUAL_SECRETS>
    let (incr, individual_secrets) = parse_individual_secrets(&bytes[offset..])?;
    offset = increment_offset(bytes, offset, incr)?;
    // <ENCRYPTION>
    let (incr, encryption_type) = parse_encryption(&bytes[offset..])?;
    offset = increment_offset(bytes, offset, incr)?;
    Ok((
        offset,
        derivation_paths,
        individual_secrets,
        encryption_type,
    ))
}

pub fn encrypt_chacha20_poly1305_v1<C: Crypto, R: Rng>(
    crypto: &C,
    rng: &mut R,
    derivation_paths: Vec<DerivationPath>,
    content_metadata: Content,
    keys: Vec<[u8; XONLY_KEY_SIZE]>,
    data: &[u8],
    padding: Padding,
) -> Result<Vec<u8>, Error> {
    encrypt_chacha20_poly1305_v1_items(
        crypto,
        rng,
        derivation_paths,
        &[(content_metadata, data)],
        keys,
        padding,
    )
}

pub fn encrypt_chacha20_poly1305_v1_items<C: Crypto, R: Rng>(
    crypto: &C,
    rng: &mut R,
    derivation_paths: Vec<DerivationPath>,
    items: &[(Content, &[u8])],
    keys: Vec<[u8; XONLY_KEY_SIZE]>,
    padding: Padding,
) -> Result<Vec<u8>, Error> {
    let nonce = draw_nonce(rng);
    let payload = build_v1_payload(items, padding)?;
    encode_v1_backup(crypto, derivation_paths, keys, payload, nonce, |secrets| {
        pad_individual_secrets(rng, secrets)
    })
}

/// Like [`encrypt_chacha20_poly1305_v1_items`] but with a caller-supplied `nonce`
/// and the exact decoy individual secrets, for platforms without a random source.
/// `decoy_individual_secrets` must hold exactly the padding target minus the real
/// secret count entries, each non-zero and distinct, or `IndividualSecretsLength`.
pub fn encrypt_chacha20_poly1305_v1_items_with_decoys<C: Crypto>(
    crypto: &C,
    derivation_paths: Vec<DerivationPath>,
    items: &[(Content, &[u8])],
    keys: Vec<[u8; XONLY_KEY_SIZE]>,
    padding: Padding,
    nonce: [u8; 12],
    decoy_individual_secrets: &[[u8; 32]],
) -> Result<Vec<u8>, Error> {
    let payload = build_v1_payload(items, padding)?;
    encode_v1_backup(crypto, derivation_paths, keys, payload, nonce, |secrets| {
        pad_individual_secrets_with_decoys(secrets, decoy_individual_secrets)
    })
}

/// Encode the content items into the padded plaintext payload.
fn build_v1_payload(items: &[(Content, &[u8])], padding: Padding) -> Result<Vec<u8>, Error> {
    let mut metadata = Vec::with_capacity(items.len());
    for (content, data) in items {
        // NOTE: RFC 8439 caps ChaCha20-Poly1305 plaintext at 2^38 - 64 bytes, but we
        // limit it to u32::MAX so the length never exceeds usize::MAX on 32-bit
        // architectures.
        // https://datatracker.ietf.org/doc/html/rfc8439#section-2.8
        if data.len() > u32::MAX as usize || data.is_empty() {
            return Err(Error::DataLength);
        }

        let content_metadata: Vec<u8> = content
            .clone()
            .try_into()
            .map_err(|_| Error::ContentMetadata)?;
        if content_metadata.is_empty() {
            return Err(Error::ContentMetadata);
        }
        metadata.push((content_metadata, *data));
    }
    let items = metadata
        .iter()
        .map(|(content, data)| (content.as_slice(), *data))
        .collect::<Vec<_>>();
    encode_plaintext(&items, padding)
}

/// Assemble a V1 backup from an already-encoded `payload` (see `encode_plaintext`),
/// the keys and the derivation paths, padding the individual-secret set with `pad`.
/// Content-agnostic: the payload may hold one or more content items.
fn encode_v1_backup<C: Crypto, F>(
    crypto: &C,
    derivation_paths: Vec<DerivationPath>,
    keys: Vec<[u8; XONLY_KEY_SIZE]>,
    payload: Vec<u8>,
    nonce: [u8; 12],
    pad: F,
) -> Result<Vec<u8>, Error>
where
    F: FnOnce(Vec<[u8; 32]>) -> Result<Vec<[u8; 32]>, Error>,
{
    // drop duplicate keys and sort out the BIP341 NUMS point; two keys sharing an
    // x coordinate normalize to a single entry
    let raw_keys = keys
        .into_iter()
        .filter(|k| *k != NUMS_XONLY)
        .collect::<BTreeSet<[u8; XONLY_KEY_SIZE]>>();

    // drop duplicate derivation paths and the ones a decoder already assumes
    let fallback_derivation_paths = fallback_derivation_path_set();
    let derivation_paths = derivation_paths
        .into_iter()
        .filter(|path| !fallback_derivation_paths.contains(path))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();

    if raw_keys.len() > u8::MAX as usize || raw_keys.is_empty() {
        return Err(Error::KeyCount);
    }
    if derivation_paths.len() > u8::MAX as usize {
        return Err(Error::DerivPathCount);
    }

    let raw_keys = raw_keys.into_iter().collect::<Vec<_>>();

    let secret = decryption_secret(crypto, &raw_keys);
    let individual_secrets = individual_secrets(crypto, &secret, raw_keys.as_slice());
    let individual_secrets = pad(individual_secrets)?;
    let individual_secrets = encode_individual_secrets(&individual_secrets)?;
    let derivation_paths = encode_derivation_paths(derivation_paths)?;

    let (nonce, cyphertext) = encrypt_with_nonce(crypto, secret, payload, nonce)?;
    let encrypted_payload = encode_encrypted_payload(nonce, cyphertext.as_slice())?;

    Ok(encode_v1(
        Version::V1.into(),
        derivation_paths,
        individual_secrets,
        Encryption::ChaCha20Poly1305.into(),
        encrypted_payload,
    ))
}

/// Pad the individual-secret set up to the doubling bucket with random decoys.
fn pad_individual_secrets<R: Rng>(
    rng: &mut R,
    mut secrets: Vec<[u8; 32]>,
) -> Result<Vec<[u8; 32]>, Error> {
    let target = doubling_bucket(secrets.len())?;
    while secrets.len() < target {
        let mut decoy = [0u8; 32];
        rng.fill_bytes(&mut decoy);
        if decoy != [0u8; 32] && !secrets.contains(&decoy) {
            secrets.push(decoy);
        }
    }
    Ok(secrets)
}

/// Pad the individual-secret set with caller-supplied decoys. The count must be
/// exactly the doubling bucket minus the real secrets, and each decoy non-zero and
/// distinct from the others, else `IndividualSecretsLength`.
fn pad_individual_secrets_with_decoys(
    mut secrets: Vec<[u8; 32]>,
    decoys: &[[u8; 32]],
) -> Result<Vec<[u8; 32]>, Error> {
    let target = doubling_bucket(secrets.len())?;
    if decoys.len() != target - secrets.len() {
        return Err(Error::IndividualSecretsLength);
    }
    for decoy in decoys {
        if *decoy == [0u8; 32] || secrets.contains(decoy) {
            return Err(Error::IndividualSecretsLength);
        }
        secrets.push(*decoy);
    }
    Ok(secrets)
}

pub fn try_decrypt_chacha20_poly1305<C: Crypto>(
    crypto: &C,
    cyphertext: &[u8],
    secret: &[u8; 32],
    nonce: [u8; 12],
) -> Option<Vec<u8>> {
    crypto.aead_decrypt(secret, &nonce, cyphertext)
}

pub fn decrypt_chacha20_poly1305_v1<C: Crypto>(
    crypto: &C,
    key: [u8; XONLY_KEY_SIZE],
    individual_secrets: &Vec<[u8; 32]>,
    cyphertext: Vec<u8>,
    nonce: [u8; 12],
) -> Result<Vec<(Content, Vec<u8>)>, Error> {
    let si = tagged_hash(crypto, INDIVIDUAL_SECRET.as_bytes(), &key);

    for ci in individual_secrets {
        let secret = xor(&si, ci);
        if let Some(out) = try_decrypt_chacha20_poly1305(crypto, &cyphertext, &secret, nonce) {
            return decode_plaintext(&out);
        }
    }

    Err(Error::WrongKey)
}

pub fn parse_magic_byte(bytes: &[u8]) -> Result<usize /* offset */, Error> {
    let magic = MAGIC.as_bytes();

    if bytes.len() < magic.len() || &bytes[..magic.len()] != magic {
        return Err(Error::Magic);
    }
    Ok(magic.len())
}

pub fn parse_version(bytes: &[u8]) -> Result<(usize, u8), Error> {
    if bytes.is_empty() {
        return Err(Error::Version);
    }
    let version = bytes[0];
    if version == u8::from(Version::V0) || version > Version::max().into() {
        return Err(Error::Version);
    }
    Ok((1, version))
}

pub fn parse_encryption(bytes: &[u8]) -> Result<(usize, u8), Error> {
    if bytes.is_empty() {
        return Err(Error::Encryption);
    }
    let encryption = bytes[0];
    if encryption == 0x00 {
        return Err(Error::EncryptionReserved);
    }
    Ok((1, encryption))
}

/// Expects to parse a payload of the form:
/// <COUNT>
/// <CHILD_COUNT><CHILD><..><CHILD>
/// <..>
/// <CHILD_COUNT><CHILD><..><CHILD>
/// <..>
pub fn parse_derivation_paths(
    bytes: &[u8],
) -> Result<(usize /* offset */, Vec<DerivationPath>), Error> {
    let mut offset = init_offset(bytes, 0).map_err(|_| Error::DerivPathEmpty)?;
    let mut derivation_paths = BTreeSet::new();

    // <COUNT>
    let count = bytes[0];

    if count != 0 {
        offset = increment_offset(bytes, offset, 1)?;
        for _ in 0..count {
            check_offset(offset, bytes)?;
            // <CHILD_COUNT>
            let child_count = bytes[offset];
            if child_count == 0 {
                return Err(Error::DerivPathEmpty);
            } else {
                let mut childs = vec![];
                offset += 1;
                for _ in 0..child_count {
                    check_offset_lookahead(offset, bytes, 4)?;
                    // <CHILD>
                    let raw_child: [u8; 4] =
                        bytes[offset..(offset + 4)].try_into().expect("verified");
                    let child = u32::from_be_bytes(raw_child);
                    childs.push(child);
                    offset += 4;
                }
                derivation_paths.insert(DerivationPath::from(childs));
            }
        }
    } else {
        offset += 1;
    }

    let derivation_paths = derivation_paths.into_iter().collect();

    Ok((offset, derivation_paths))
}

/// Expects to parse a payload of the form:
/// <COUNT>
/// <INDIVIDUAL_SECRET>
/// <..>
/// <INDIVIDUAL_SECRET>
/// <..>
pub fn parse_individual_secrets(
    bytes: &[u8],
) -> Result<(usize /* offset */, Vec<[u8; 32]>), Error> {
    if bytes.is_empty() {
        return Err(Error::EmptyBytes);
    }
    // <COUNT>
    let count = bytes[0];
    if count < 1 {
        return Err(Error::IndividualSecretsEmpty);
    }
    let mut offset = init_offset(bytes, 1)?;

    let mut individual_secrets = BTreeSet::new();
    for _ in 0..count {
        check_offset_lookahead(offset, bytes, 32)?;
        // <INDIVIDUAL_SECRET>
        let secret: [u8; 32] = bytes[offset..offset + 32]
            .try_into()
            .map_err(|_| Error::Corrupted)?;
        individual_secrets.insert(secret);
        offset += 32;
    }

    let individual_secrets = individual_secrets.into_iter().collect();
    Ok((offset, individual_secrets))
}

/// Expects to parse a payload of the form:
/// <NONCE><LENGTH><CYPHERTEXT>
/// <..>
pub fn parse_encrypted_payload(
    bytes: &[u8],
) -> Result<([u8; 12] /* nonce */, Vec<u8> /* cyphertext */), Error> {
    let mut offset = init_offset(bytes, 0)?;
    // <NONCE>
    check_offset_lookahead(offset, bytes, 12)?;
    let nonce: [u8; 12] = bytes[offset..offset + 12].try_into().expect("checked");
    if nonce == [0u8; 12] {
        return Err(Error::ZeroedNonce);
    }
    offset = increment_offset(bytes, offset, 12)?;
    // <LENGTH>
    let (data_len, incr) = varint::parse(&bytes[offset..]).ok_or(Error::VarInt)?;
    let data_len = usize::try_from(data_len).map_err(|_| Error::DataLength)?;
    if data_len == 0 {
        return Err(Error::CypherTextEmpty);
    }
    offset = increment_offset(bytes, offset, incr)?;
    // <CYPHERTEXT>
    check_offset_lookahead(offset, bytes, data_len)?;
    let cyphertext = bytes[offset..offset + data_len].to_vec();
    Ok((nonce, cyphertext))
}

pub fn parse_encrypted_payload_lengths(bytes: &[u8]) -> Result<Vec<usize>, Error> {
    if bytes.is_empty() {
        return Err(Error::EmptyBytes);
    }

    // The first payload is mandated by the spec, its errors bubble up. Vendors
    // may append more payloads after it; anything else there is trailing bytes
    // that parsers must ignore, so a parse failure ends the walk instead.
    let (data_len, mut offset) = parse_encrypted_payload_length(bytes, 0)?;
    let mut lengths = vec![data_len];
    while offset < bytes.len() {
        let Ok((data_len, end)) = parse_encrypted_payload_length(bytes, offset) else {
            break;
        };
        lengths.push(data_len);
        offset = end;
    }

    Ok(lengths)
}

/// Parse one `<NONCE><LENGTH><CYPHERTEXT>` payload at `offset`, returning the
/// cyphertext length and the offset of the byte after the payload.
fn parse_encrypted_payload_length(bytes: &[u8], offset: usize) -> Result<(usize, usize), Error> {
    check_offset_lookahead(offset, bytes, 12)?;
    let nonce: [u8; 12] = bytes[offset..offset + 12].try_into().expect("checked");
    if nonce == [0u8; 12] {
        return Err(Error::ZeroedNonce);
    }
    let offset = offset.checked_add(12).ok_or(Error::OffsetOverflow)?;

    let (data_len, incr) = varint::parse(&bytes[offset..]).ok_or(Error::VarInt)?;
    let data_len = usize::try_from(data_len).map_err(|_| Error::DataLength)?;
    if data_len == 0 {
        return Err(Error::CypherTextEmpty);
    }
    let offset = offset.checked_add(incr).ok_or(Error::OffsetOverflow)?;
    let end = offset.checked_add(data_len).ok_or(Error::OffsetOverflow)?;
    if end > bytes.len() {
        return Err(Error::Corrupted);
    }
    Ok((data_len, end))
}
