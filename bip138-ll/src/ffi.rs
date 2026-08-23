//! C binding: encrypt a payload to a set of x-only keys, and decrypt one back.
//!
//! The core does real cryptography, so the C consumer supplies the four
//! primitives (SHA-256, ChaCha20-Poly1305 encrypt/decrypt, randomness) through a
//! [`CryptoVtable`] of function pointers. The codec itself pulls no dependency.
//!
//! Ownership: Rust never frees C memory, and C never frees Rust memory except
//! through `bip138_buf_free` and `bip138_decrypt_free`. A vtable and its buffers
//! are borrowed for the duration of a call only.
//!
//! No entry point may panic. `no_std` has no unwinding, so a panic would reach
//! the consumer's handler instead of returning a code.

// Every entry point here is one `unsafe extern "C"` body operating on raw C
// pointers, so treat the whole body as the unsafe context rather than wrapping
// each pointer read.
#![allow(unsafe_op_in_unsafe_fn)]

use alloc::{boxed::Box, vec, vec::Vec};
use core::{ffi::c_char, ffi::c_void, ptr, slice};

use crate::{
    Content, Crypto, DerivationPath, Error, Padding, Rng, XONLY_KEY_SIZE,
    decrypt_chacha20_poly1305_v1, encrypt_chacha20_poly1305_v1,
};

pub const BIP138_OK: i32 = 0;

/// Content type discriminants shared with the C header.
pub const BIP138_CONTENT_NONE: u32 = 0;
pub const BIP138_CONTENT_BIP138: u32 = 1;
pub const BIP138_CONTENT_BIP139: u32 = 2;
pub const BIP138_CONTENT_BIP380: u32 = 3;
pub const BIP138_CONTENT_BIP388: u32 = 4;
pub const BIP138_CONTENT_BIP329: u32 = 5;
pub const BIP138_CONTENT_BIP: u32 = 6;
pub const BIP138_CONTENT_PROPRIETARY: u32 = 7;
pub const BIP138_CONTENT_STRING: u32 = 8;
pub const BIP138_CONTENT_UNKNOWN: u32 = 9;

/// Padding discriminants shared with the C header.
pub const BIP138_PADDING_NONE: u32 = 0;
pub const BIP138_PADDING_GEOMETRIC: u32 = 1;

/// The crypto primitives the C consumer supplies. Each callback takes the opaque
/// `ctx` back. A null callback makes an operation that needs it fail with
/// `BadVtable` rather than call through.
#[repr(C)]
pub struct CryptoVtable {
    pub ctx: *mut c_void,
    /// SHA-256 of `len` bytes at `data` into the 32-byte `out`.
    pub sha256:
        Option<unsafe extern "C" fn(ctx: *mut c_void, data: *const u8, len: usize, out: *mut u8)>,
    /// ChaCha20-Poly1305 encrypt. Writes at most `out_cap` bytes to `out` and the
    /// actual length to `out_len`. `out_cap` is `plaintext_len + 16`. Returns 0 on
    /// success, non-zero on failure.
    pub aead_encrypt: Option<
        unsafe extern "C" fn(
            ctx: *mut c_void,
            key: *const u8,
            nonce: *const u8,
            plaintext: *const u8,
            plaintext_len: usize,
            out: *mut u8,
            out_cap: usize,
            out_len: *mut usize,
        ) -> i32,
    >,
    /// ChaCha20-Poly1305 decrypt. Same buffer convention; `out_cap` is `ciphertext_len`.
    /// Returns 0 on success, non-zero when the tag does not verify.
    pub aead_decrypt: Option<
        unsafe extern "C" fn(
            ctx: *mut c_void,
            key: *const u8,
            nonce: *const u8,
            ciphertext: *const u8,
            ciphertext_len: usize,
            out: *mut u8,
            out_cap: usize,
            out_len: *mut usize,
        ) -> i32,
    >,
    /// Fill `len` bytes at `buf` with cryptographically secure randomness.
    pub fill_random: Option<unsafe extern "C" fn(ctx: *mut c_void, buf: *mut u8, len: usize)>,
}

/// One derivation path passed to encrypt: raw BIP32 child numbers, hardened bit
/// in the high bit. A null `ptr` with a non-zero `len` is rejected.
#[repr(C)]
pub struct U32List {
    pub ptr: *const u32,
    pub len: usize,
}

/// An owned byte buffer handed to C, released with `bip138_buf_free`.
#[repr(C)]
pub struct Buf {
    pub ptr: *mut u8,
    pub len: usize,
}

/// A byte run borrowed from a decrypt result, valid until `bip138_decrypt_free`.
#[repr(C)]
pub struct BorrowedBytes {
    pub ptr: *const u8,
    pub len: usize,
}

/// One decoded content item, borrowed from a decrypt result.
#[repr(C)]
pub struct DecryptItem {
    /// One of the `BIP138_CONTENT_*` discriminants.
    pub content_type: u32,
    /// BIP number when `content_type` is `BIP138_CONTENT_BIP`, else 0.
    pub bip: u16,
    /// Vendor tag when `content_type` is `BIP138_CONTENT_PROPRIETARY`, else empty.
    pub tag: BorrowedBytes,
    /// The recovered plaintext of this item.
    pub plaintext: BorrowedBytes,
}

/// Opaque owner of a decode's items. C sees only a pointer to it.
pub struct DecryptResult {
    items: Vec<(Content, Vec<u8>)>,
}

/// Failures the C boundary itself can raise, on top of the core's [`Error`].
enum FfiError {
    NullPointer,
    BadVtable,
    BadContentType,
    BadPadding,
    IndexOutOfBounds,
    Ll(Error),
}

impl FfiError {
    fn info(&self) -> (i32, &'static str) {
        match self {
            FfiError::NullPointer => (500, "null pointer\0"),
            FfiError::BadVtable => (501, "crypto vtable has a null callback\0"),
            FfiError::BadContentType => (502, "unknown content type discriminant\0"),
            FfiError::BadPadding => (503, "unknown padding discriminant\0"),
            FfiError::IndexOutOfBounds => (504, "item index out of bounds\0"),
            FfiError::Ll(error) => ll_error_info(*error),
        }
    }
}

fn ll_error_info(error: Error) -> (i32, &'static str) {
    match error {
        Error::KeyCount => (100, "key count out of range\0"),
        Error::DerivPathCount => (101, "too many derivation paths\0"),
        Error::DerivPathLength => (102, "derivation path too long\0"),
        Error::DerivPathEmpty => (103, "empty derivation path\0"),
        Error::DataLength => (104, "data length out of range\0"),
        Error::Encrypt => (105, "encryption failed\0"),
        Error::Decrypt => (106, "decryption failed\0"),
        Error::Corrupted => (107, "corrupted payload\0"),
        Error::Version => (108, "invalid version\0"),
        Error::Magic => (109, "bad magic\0"),
        Error::VarInt => (110, "invalid varint\0"),
        Error::WrongKey => (111, "no supplied key decrypts this backup\0"),
        Error::IndividualSecretsEmpty => (112, "individual secrets empty\0"),
        Error::IndividualSecretsLength => (113, "individual secrets length out of range\0"),
        Error::CypherTextEmpty => (114, "ciphertext empty\0"),
        Error::CypherTextLength => (115, "ciphertext length out of range\0"),
        Error::ContentMetadata => (116, "invalid content metadata\0"),
        Error::Encryption => (117, "invalid encryption field\0"),
        Error::OffsetOverflow => (118, "offset overflow\0"),
        Error::EmptyBytes => (119, "empty input\0"),
        Error::Increment => (120, "offset increment overflow\0"),
        Error::ContentMetadataEmpty => (121, "content metadata empty\0"),
        Error::ContentEnd => (122, "unexpected end of content\0"),
        Error::EncryptionReserved => (123, "reserved encryption value\0"),
        Error::ZeroedNonce => (124, "zeroed nonce\0"),
        Error::Padding => (125, "padding overflow\0"),
    }
}

/// Crypto provider backed by the C vtable.
struct VtableProvider<'a> {
    vtable: &'a CryptoVtable,
}

impl Crypto for VtableProvider<'_> {
    fn sha256(&self, data: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        // Presence of the callback is checked before any core call that hashes.
        if let Some(sha256) = self.vtable.sha256 {
            unsafe { sha256(self.vtable.ctx, data.as_ptr(), data.len(), out.as_mut_ptr()) };
        }
        out
    }

    fn aead_encrypt(&self, key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8]) -> Option<Vec<u8>> {
        let encrypt = self.vtable.aead_encrypt?;
        let cap = plaintext.len() + 16;
        let mut out = vec![0u8; cap];
        let mut out_len = 0usize;
        let rc = unsafe {
            encrypt(
                self.vtable.ctx,
                key.as_ptr(),
                nonce.as_ptr(),
                plaintext.as_ptr(),
                plaintext.len(),
                out.as_mut_ptr(),
                cap,
                &mut out_len,
            )
        };
        if rc != 0 || out_len > cap {
            return None;
        }
        out.truncate(out_len);
        Some(out)
    }

    fn aead_decrypt(&self, key: &[u8; 32], nonce: &[u8; 12], ciphertext: &[u8]) -> Option<Vec<u8>> {
        let decrypt = self.vtable.aead_decrypt?;
        // Plaintext is 16 bytes shorter than ciphertext, so ciphertext length is a
        // safe upper bound for the output buffer.
        let cap = ciphertext.len();
        let mut out = vec![0u8; cap];
        let mut out_len = 0usize;
        let rc = unsafe {
            decrypt(
                self.vtable.ctx,
                key.as_ptr(),
                nonce.as_ptr(),
                ciphertext.as_ptr(),
                ciphertext.len(),
                out.as_mut_ptr(),
                cap,
                &mut out_len,
            )
        };
        if rc != 0 || out_len > cap {
            return None;
        }
        out.truncate(out_len);
        Some(out)
    }
}

impl Rng for VtableProvider<'_> {
    fn fill_bytes(&mut self, buf: &mut [u8]) {
        if let Some(fill_random) = self.vtable.fill_random {
            unsafe { fill_random(self.vtable.ctx, buf.as_mut_ptr(), buf.len()) };
        }
    }
}

fn content_from_ffi(content_type: u32, bip: u16, tag: &[u8]) -> Result<Content, FfiError> {
    match content_type {
        BIP138_CONTENT_NONE => Ok(Content::None),
        BIP138_CONTENT_BIP138 => Ok(Content::Bip138),
        BIP138_CONTENT_BIP139 => Ok(Content::Bip139),
        BIP138_CONTENT_BIP380 => Ok(Content::Bip380),
        BIP138_CONTENT_BIP388 => Ok(Content::Bip388),
        BIP138_CONTENT_BIP329 => Ok(Content::Bip329),
        BIP138_CONTENT_BIP => Ok(Content::BIP(bip)),
        BIP138_CONTENT_PROPRIETARY => Ok(Content::Proprietary(tag.to_vec())),
        BIP138_CONTENT_STRING => Ok(Content::String),
        BIP138_CONTENT_UNKNOWN => Ok(Content::Unknown),
        _ => Err(FfiError::BadContentType),
    }
}

fn content_to_ffi(content: &Content) -> (u32, u16, BorrowedBytes) {
    let empty = BorrowedBytes {
        ptr: ptr::null(),
        len: 0,
    };
    match content {
        Content::None => (BIP138_CONTENT_NONE, 0, empty),
        Content::Bip138 => (BIP138_CONTENT_BIP138, 0, empty),
        Content::Bip139 => (BIP138_CONTENT_BIP139, 0, empty),
        Content::Bip380 => (BIP138_CONTENT_BIP380, 0, empty),
        Content::Bip388 => (BIP138_CONTENT_BIP388, 0, empty),
        Content::Bip329 => (BIP138_CONTENT_BIP329, 0, empty),
        Content::BIP(bip) => (BIP138_CONTENT_BIP, *bip, empty),
        Content::Proprietary(tag) => (
            BIP138_CONTENT_PROPRIETARY,
            0,
            BorrowedBytes {
                ptr: tag.as_ptr(),
                len: tag.len(),
            },
        ),
        Content::String => (BIP138_CONTENT_STRING, 0, empty),
        Content::Unknown => (BIP138_CONTENT_UNKNOWN, 0, empty),
    }
}

fn padding_from_ffi(padding: u32) -> Result<Padding, FfiError> {
    match padding {
        BIP138_PADDING_NONE => Ok(Padding::None),
        BIP138_PADDING_GEOMETRIC => Ok(Padding::Geometric),
        _ => Err(FfiError::BadPadding),
    }
}

/// Encrypt one content item to a set of x-only keys.
///
/// `keys` points at `n_keys` consecutive 32-byte x-only public keys. `paths`
/// points at `n_paths` derivation paths. `content_type`/`bip`/`tag` describe the
/// single content item; `payload` is its plaintext. On success `*out` owns the
/// encrypted bytes until `bip138_buf_free`.
///
/// # Safety
/// Every non-null pointer must be valid for its stated length, `out` must be
/// writable, and `vtable`'s callbacks must be sound. `err` may be null; when it
/// is not, a failure writes a static message to it.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bip138_encrypt(
    vtable: *const CryptoVtable,
    keys: *const u8,
    n_keys: usize,
    paths: *const U32List,
    n_paths: usize,
    content_type: u32,
    bip: u16,
    tag: *const u8,
    tag_len: usize,
    payload: *const u8,
    payload_len: usize,
    padding: u32,
    out: *mut Buf,
    err: *mut *const c_char,
) -> i32 {
    if vtable.is_null() || out.is_null() || keys.is_null() || payload.is_null() {
        return fail(FfiError::NullPointer, err);
    }
    let vtable = &*vtable;
    if vtable.sha256.is_none() || vtable.aead_encrypt.is_none() || vtable.fill_random.is_none() {
        return fail(FfiError::BadVtable, err);
    }

    let key_bytes = slice::from_raw_parts(keys, n_keys * XONLY_KEY_SIZE);
    let key_list = key_bytes
        .chunks_exact(XONLY_KEY_SIZE)
        .map(|chunk| {
            let mut key = [0u8; XONLY_KEY_SIZE];
            key.copy_from_slice(chunk);
            key
        })
        .collect::<Vec<_>>();

    let derivation_paths = match read_paths(paths, n_paths) {
        Ok(paths) => paths,
        Err(error) => return fail(error, err),
    };

    let tag = if tag.is_null() {
        &[]
    } else {
        slice::from_raw_parts(tag, tag_len)
    };
    let content = match content_from_ffi(content_type, bip, tag) {
        Ok(content) => content,
        Err(error) => return fail(error, err),
    };
    let padding = match padding_from_ffi(padding) {
        Ok(padding) => padding,
        Err(error) => return fail(error, err),
    };
    let data = slice::from_raw_parts(payload, payload_len);

    let mut provider = VtableProvider { vtable };
    let crypto = VtableProvider { vtable };
    match encrypt_chacha20_poly1305_v1(
        &crypto,
        &mut provider,
        derivation_paths,
        content,
        key_list,
        data,
        padding,
    ) {
        Ok(bytes) => {
            let bytes = Box::leak(bytes.into_boxed_slice());
            *out = Buf {
                ptr: bytes.as_mut_ptr(),
                len: bytes.len(),
            };
            BIP138_OK
        }
        Err(error) => fail(FfiError::Ll(error), err),
    }
}

/// Decrypt a backup with one x-only key. On success `*out` owns the decoded items
/// until `bip138_decrypt_free`.
///
/// # Safety
/// See `bip138_encrypt`. `key` must point at 32 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bip138_decrypt(
    vtable: *const CryptoVtable,
    key: *const u8,
    encrypted: *const u8,
    encrypted_len: usize,
    out: *mut *mut DecryptResult,
    err: *mut *const c_char,
) -> i32 {
    if vtable.is_null() || out.is_null() || key.is_null() || encrypted.is_null() {
        return fail(FfiError::NullPointer, err);
    }
    let vtable = &*vtable;
    if vtable.sha256.is_none() || vtable.aead_decrypt.is_none() {
        return fail(FfiError::BadVtable, err);
    }

    let bytes = slice::from_raw_parts(encrypted, encrypted_len);
    let (derivation_paths, individual_secrets, _encryption, nonce, cyphertext) =
        match crate::decode_v1(bytes) {
            Ok(decoded) => decoded,
            Err(error) => return fail(FfiError::Ll(error), err),
        };
    let _ = derivation_paths;

    let mut key_bytes = [0u8; XONLY_KEY_SIZE];
    key_bytes.copy_from_slice(slice::from_raw_parts(key, XONLY_KEY_SIZE));

    let crypto = VtableProvider { vtable };
    match decrypt_chacha20_poly1305_v1(&crypto, key_bytes, &individual_secrets, cyphertext, nonce) {
        Ok(items) => {
            let result = Box::new(DecryptResult { items });
            *out = Box::into_raw(result);
            BIP138_OK
        }
        Err(error) => fail(FfiError::Ll(error), err),
    }
}

/// Number of content items in a decrypt result. A null pointer is 0.
///
/// # Safety
/// `result` must come from `bip138_decrypt` and be live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bip138_decrypt_len(result: *const DecryptResult) -> usize {
    if result.is_null() {
        return 0;
    }
    (*result).items.len()
}

/// Read one decoded item into `out`. The item's `tag` and `plaintext` point into
/// the result and stay valid until `bip138_decrypt_free`.
///
/// # Safety
/// `result` must come from `bip138_decrypt` and be live; `out` must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bip138_decrypt_item(
    result: *const DecryptResult,
    index: usize,
    out: *mut DecryptItem,
    err: *mut *const c_char,
) -> i32 {
    if result.is_null() || out.is_null() {
        return fail(FfiError::NullPointer, err);
    }
    let items = &(*result).items;
    let Some((content, plaintext)) = items.get(index) else {
        return fail(FfiError::IndexOutOfBounds, err);
    };
    let (content_type, bip, tag) = content_to_ffi(content);
    *out = DecryptItem {
        content_type,
        bip,
        tag,
        plaintext: BorrowedBytes {
            ptr: plaintext.as_ptr(),
            len: plaintext.len(),
        },
    };
    BIP138_OK
}

/// Release a buffer returned by `bip138_encrypt`. A null pointer is a no-op.
///
/// # Safety
/// `buf` must come from this crate and must not be freed twice.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bip138_buf_free(buf: Buf) {
    if buf.ptr.is_null() {
        return;
    }
    drop(Box::from_raw(ptr::slice_from_raw_parts_mut(
        buf.ptr, buf.len,
    )));
}

/// Release a decrypt result. A null pointer is a no-op.
///
/// # Safety
/// `result` must come from `bip138_decrypt` and must not be freed twice.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bip138_decrypt_free(result: *mut DecryptResult) {
    if result.is_null() {
        return;
    }
    drop(Box::from_raw(result));
}

unsafe fn read_paths(
    paths: *const U32List,
    n_paths: usize,
) -> Result<Vec<DerivationPath>, FfiError> {
    if n_paths == 0 {
        return Ok(Vec::new());
    }
    if paths.is_null() {
        return Err(FfiError::NullPointer);
    }
    let lists = slice::from_raw_parts(paths, n_paths);
    let mut out = Vec::with_capacity(n_paths);
    for list in lists {
        let childs = if list.len == 0 {
            Vec::new()
        } else if list.ptr.is_null() {
            return Err(FfiError::NullPointer);
        } else {
            slice::from_raw_parts(list.ptr, list.len).to_vec()
        };
        out.push(DerivationPath::from(childs));
    }
    Ok(out)
}

unsafe fn fail(error: FfiError, err: *mut *const c_char) -> i32 {
    let (code, message) = error.info();
    if !err.is_null() {
        *err = message.as_ptr().cast();
    }
    code
}
