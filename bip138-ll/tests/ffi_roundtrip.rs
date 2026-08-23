//! Drives the C entry points end to end through a vtable backed by the bundled
//! RustBitcoin provider, so the whole FFI path (encrypt, decrypt, item read, free)
//! is exercised from Rust without a C toolchain. Randomness is a deterministic
//! counter here, which is all a round-trip needs.

#![cfg(all(feature = "ffi", feature = "rust-bitcoin"))]

use core::ffi::{c_char, c_void};
use core::ptr;
use core::sync::atomic::{AtomicU32, Ordering};

use bip138_ll::crypto::{Crypto, RustBitcoin};
use bip138_ll::ffi::{
    BIP138_CONTENT_STRING, BIP138_OK, BIP138_PADDING_NONE, Buf, CryptoVtable, DecryptItem,
    DecryptResult, bip138_buf_free, bip138_decrypt, bip138_decrypt_free, bip138_decrypt_item,
    bip138_decrypt_len, bip138_encrypt,
};

static COUNTER: AtomicU32 = AtomicU32::new(1);

extern "C" fn sha256_cb(_ctx: *mut c_void, data: *const u8, len: usize, out: *mut u8) {
    let data = unsafe { core::slice::from_raw_parts(data, len) };
    let hash = RustBitcoin.sha256(data);
    unsafe { ptr::copy_nonoverlapping(hash.as_ptr(), out, 32) };
}

extern "C" fn aead_encrypt_cb(
    _ctx: *mut c_void,
    key: *const u8,
    nonce: *const u8,
    plaintext: *const u8,
    plaintext_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    let key = unsafe { &*(key as *const [u8; 32]) };
    let nonce = unsafe { &*(nonce as *const [u8; 12]) };
    let plaintext = unsafe { core::slice::from_raw_parts(plaintext, plaintext_len) };
    match RustBitcoin.aead_encrypt(key, nonce, plaintext) {
        Some(bytes) if bytes.len() <= out_cap => {
            unsafe {
                ptr::copy_nonoverlapping(bytes.as_ptr(), out, bytes.len());
                *out_len = bytes.len();
            }
            0
        }
        _ => 1,
    }
}

extern "C" fn aead_decrypt_cb(
    _ctx: *mut c_void,
    key: *const u8,
    nonce: *const u8,
    ciphertext: *const u8,
    ciphertext_len: usize,
    out: *mut u8,
    out_cap: usize,
    out_len: *mut usize,
) -> i32 {
    let key = unsafe { &*(key as *const [u8; 32]) };
    let nonce = unsafe { &*(nonce as *const [u8; 12]) };
    let ciphertext = unsafe { core::slice::from_raw_parts(ciphertext, ciphertext_len) };
    match RustBitcoin.aead_decrypt(key, nonce, ciphertext) {
        Some(bytes) if bytes.len() <= out_cap => {
            unsafe {
                ptr::copy_nonoverlapping(bytes.as_ptr(), out, bytes.len());
                *out_len = bytes.len();
            }
            0
        }
        _ => 1,
    }
}

extern "C" fn fill_random_cb(_ctx: *mut c_void, buf: *mut u8, len: usize) {
    let buf = unsafe { core::slice::from_raw_parts_mut(buf, len) };
    for byte in buf {
        *byte = COUNTER.fetch_add(1, Ordering::Relaxed) as u8;
    }
}

fn vtable() -> CryptoVtable {
    CryptoVtable {
        ctx: ptr::null_mut(),
        sha256: Some(sha256_cb),
        aead_encrypt: Some(aead_encrypt_cb),
        aead_decrypt: Some(aead_decrypt_cb),
        fill_random: Some(fill_random_cb),
    }
}

#[test]
fn encrypt_then_decrypt_round_trips() {
    let vtable = vtable();
    let key = [7u8; 32];
    let payload = b"a string payload";

    let mut out = Buf {
        ptr: ptr::null_mut(),
        len: 0,
    };
    let mut err: *const c_char = ptr::null();
    let rc = unsafe {
        bip138_encrypt(
            &vtable,
            key.as_ptr(),
            1,
            ptr::null(),
            0,
            BIP138_CONTENT_STRING,
            0,
            ptr::null(),
            0,
            payload.as_ptr(),
            payload.len(),
            BIP138_PADDING_NONE,
            &mut out,
            &mut err,
        )
    };
    assert_eq!(rc, BIP138_OK);
    assert!(!out.ptr.is_null());

    let encrypted = unsafe { core::slice::from_raw_parts(out.ptr, out.len) };
    assert!(encrypted.starts_with(b"BIP138"));

    let mut result: *mut DecryptResult = ptr::null_mut();
    let rc = unsafe {
        bip138_decrypt(
            &vtable,
            key.as_ptr(),
            out.ptr,
            out.len,
            &mut result,
            &mut err,
        )
    };
    assert_eq!(rc, BIP138_OK);
    assert!(!result.is_null());
    assert_eq!(unsafe { bip138_decrypt_len(result) }, 1);

    let mut item = DecryptItem {
        content_type: 0,
        bip: 0,
        tag: bip138_ll::ffi::BorrowedBytes {
            ptr: ptr::null(),
            len: 0,
        },
        plaintext: bip138_ll::ffi::BorrowedBytes {
            ptr: ptr::null(),
            len: 0,
        },
    };
    let rc = unsafe { bip138_decrypt_item(result, 0, &mut item, &mut err) };
    assert_eq!(rc, BIP138_OK);
    assert_eq!(item.content_type, BIP138_CONTENT_STRING);
    let recovered = unsafe { core::slice::from_raw_parts(item.plaintext.ptr, item.plaintext.len) };
    assert_eq!(recovered, payload);

    unsafe {
        bip138_decrypt_free(result);
        bip138_buf_free(out);
    }
}

#[test]
fn wrong_key_reports_error() {
    let vtable = vtable();
    let key = [9u8; 32];
    let payload = b"secret";
    let mut out = Buf {
        ptr: ptr::null_mut(),
        len: 0,
    };
    let mut err: *const c_char = ptr::null();
    let rc = unsafe {
        bip138_encrypt(
            &vtable,
            key.as_ptr(),
            1,
            ptr::null(),
            0,
            BIP138_CONTENT_STRING,
            0,
            ptr::null(),
            0,
            payload.as_ptr(),
            payload.len(),
            BIP138_PADDING_NONE,
            &mut out,
            &mut err,
        )
    };
    assert_eq!(rc, BIP138_OK);

    let other_key = [1u8; 32];
    let mut result: *mut DecryptResult = ptr::null_mut();
    let rc = unsafe {
        bip138_decrypt(
            &vtable,
            other_key.as_ptr(),
            out.ptr,
            out.len,
            &mut result,
            &mut err,
        )
    };
    assert_ne!(rc, BIP138_OK);
    assert!(result.is_null());
    assert!(!err.is_null());

    unsafe { bip138_buf_free(out) };
}
