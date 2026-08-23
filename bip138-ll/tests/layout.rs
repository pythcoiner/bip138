//! Pins the size, alignment, and field offsets of every `#[repr(C)]` type the C
//! binding exposes, so a change on the Rust side fails here until
//! `include/bip138.h` is updated to match. The numbers are for a 64-bit target
//! (8-byte pointers and `size_t`), the same layout a C compiler produces over
//! the header.

#![cfg(feature = "ffi")]

use core::mem::{align_of, offset_of, size_of};

use bip138_ll::ffi::{BorrowedBytes, Buf, CryptoVtable, DecryptItem, U32List};

#[test]
fn crypto_vtable_layout() {
    assert_eq!(size_of::<CryptoVtable>(), 40);
    assert_eq!(align_of::<CryptoVtable>(), 8);
    assert_eq!(offset_of!(CryptoVtable, ctx), 0);
    assert_eq!(offset_of!(CryptoVtable, sha256), 8);
    assert_eq!(offset_of!(CryptoVtable, aead_encrypt), 16);
    assert_eq!(offset_of!(CryptoVtable, aead_decrypt), 24);
    assert_eq!(offset_of!(CryptoVtable, fill_random), 32);
}

#[test]
fn u32_list_layout() {
    assert_eq!(size_of::<U32List>(), 16);
    assert_eq!(align_of::<U32List>(), 8);
    assert_eq!(offset_of!(U32List, ptr), 0);
    assert_eq!(offset_of!(U32List, len), 8);
}

#[test]
fn buf_layout() {
    assert_eq!(size_of::<Buf>(), 16);
    assert_eq!(align_of::<Buf>(), 8);
    assert_eq!(offset_of!(Buf, ptr), 0);
    assert_eq!(offset_of!(Buf, len), 8);
}

#[test]
fn borrowed_bytes_layout() {
    assert_eq!(size_of::<BorrowedBytes>(), 16);
    assert_eq!(align_of::<BorrowedBytes>(), 8);
    assert_eq!(offset_of!(BorrowedBytes, ptr), 0);
    assert_eq!(offset_of!(BorrowedBytes, len), 8);
}

#[test]
fn decrypt_item_layout() {
    assert_eq!(size_of::<DecryptItem>(), 40);
    assert_eq!(align_of::<DecryptItem>(), 8);
    assert_eq!(offset_of!(DecryptItem, content_type), 0);
    assert_eq!(offset_of!(DecryptItem, bip), 4);
    assert_eq!(offset_of!(DecryptItem, tag), 8);
    assert_eq!(offset_of!(DecryptItem, plaintext), 24);
}
