//! The C arm: odudex/bip138 (built from the `bip138-c` submodule) with its
//! production crypto, mbedTLS via PSA (the reference callbacks in
//! `test/test_crypto.c`, identical to Kern's `bip138_crypto.c`).

use std::os::raw::c_int;
use std::ptr;
use std::slice;

use crate::{ContentType, Decoded, EncodeContent, EncodeItem, Item};

pub const BIP138_OK: c_int = 0;
pub const BIP138_MAGIC: &[u8] = b"BIP138";
pub const BIP138_VERSION: u8 = 0x01;
pub const BIP138_ENCRYPTION_CHACHA20_POLY1305: u8 = 0x01;
pub const BIP138_CONTENT_BIP: u8 = 0x01;
pub const BIP138_CONTENT_PROPRIETARY: u8 = 0x02;
pub const BIP138_CONTENT_STRING: u8 = 0x03;

#[repr(C)]
struct Crypto {
    _private: [u8; 0],
}

#[repr(C)]
struct Container {
    paths: *const u8,
    paths_len: usize,
    path_count: u8,
    secrets: *const u8,
    secret_count: u8,
    nonce: *const u8,
    ciphertext: *const u8,
    ciphertext_len: usize,
}

#[repr(C)]
struct Path {
    child: *const u32,
    depth: u8,
}

unsafe extern "C" {
    fn test_crypto() -> *const Crypto;

    fn bip138_parse(buf: *const u8, len: usize, out: *mut Container) -> c_int;

    fn bip138_path_at(
        c: *const Container,
        index: usize,
        child: *mut u32,
        child_cap: usize,
        depth: *mut usize,
    ) -> c_int;

    fn bip138_plaintext_max(c: *const Container) -> usize;

    fn bip138_decrypt(
        c: *const Crypto,
        cont: *const Container,
        keys: *const u8,
        n_keys: usize,
        plaintext: *mut u8,
        plaintext_cap: usize,
        plaintext_len: *mut usize,
        key_index: *mut usize,
    ) -> c_int;

    fn bip138_secret_bucket(n_real: usize) -> usize;

    fn bip138_item_iter_init(it: *mut ItemIter, plaintext: *const u8, len: usize);

    fn bip138_item_next(it: *mut ItemIter, item: *mut CItem) -> c_int;

    fn bip138_plaintext_encode(
        items: *const CItem,
        n_items: usize,
        geometric_pad: c_int,
        out: *mut u8,
        out_cap: usize,
        out_len: *mut usize,
    ) -> c_int;

    fn bip138_content_parse(
        buf: *const u8,
        len: usize,
        out: *mut CContent,
        consumed: *mut usize,
    ) -> c_int;

    fn bip138_content_encode(
        content: *const CContent,
        out: *mut u8,
        out_cap: usize,
        out_len: *mut usize,
    ) -> c_int;

    fn bip138_paths_encode(
        paths: *const Path,
        n_paths: usize,
        out: *mut u8,
        out_cap: usize,
        out_len: *mut usize,
    ) -> c_int;

    fn bip138_secrets_encode(
        secrets: *const u8,
        n_secrets: usize,
        out: *mut u8,
        out_cap: usize,
        out_len: *mut usize,
    ) -> c_int;

    // Internal (bip138_internal.h) but exported: the CompactSize writer the C
    // encoder uses for the ciphertext length.
    fn bip138_varint_write(out: *mut u8, out_cap: usize, value: u64, written: *mut usize) -> c_int;

    fn bip138_encrypt_ex(
        c: *const Crypto,
        keys: *const u8,
        n_keys: usize,
        paths: *const Path,
        n_paths: usize,
        nonce: *const u8,
        decoys: *const u8,
        n_decoys: usize,
        plaintext: *const u8,
        plaintext_len: usize,
        out: *mut u8,
        out_cap: usize,
        out_len: *mut usize,
    ) -> c_int;
}

#[repr(C)]
struct CContent {
    type_: u8,
    bip: u16,
    tag: *const u8,
    tag_len: usize,
}

#[repr(C)]
struct CItem {
    content: CContent,
    data: *const u8,
    data_len: usize,
}

#[repr(C)]
struct ItemIter {
    buf: *const u8,
    len: usize,
    pos: usize,
}

/// Parse a container (pure framing, no crypto). `None` on any rejection.
pub fn decode(bytes: &[u8]) -> Option<Decoded> {
    unsafe {
        let mut cont = Container {
            paths: ptr::null(),
            paths_len: 0,
            path_count: 0,
            secrets: ptr::null(),
            secret_count: 0,
            nonce: ptr::null(),
            ciphertext: ptr::null(),
            ciphertext_len: 0,
        };
        if bip138_parse(bytes.as_ptr(), bytes.len(), &mut cont) != BIP138_OK {
            return None;
        }

        let secret_count = cont.secret_count as usize;
        let secrets_bytes = slice::from_raw_parts(cont.secrets, secret_count * 32);
        let secrets = (0..secret_count)
            .map(|i| {
                let mut s = [0u8; 32];
                s.copy_from_slice(&secrets_bytes[i * 32..(i + 1) * 32]);
                s
            })
            .collect::<Vec<_>>();

        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(slice::from_raw_parts(cont.nonce, 12));

        let ciphertext = slice::from_raw_parts(cont.ciphertext, cont.ciphertext_len).to_vec();

        let mut paths = Vec::new();
        for i in 0..cont.path_count as usize {
            let mut child = [0u32; 256];
            let mut depth = 0usize;
            if bip138_path_at(&cont, i, child.as_mut_ptr(), child.len(), &mut depth) != BIP138_OK {
                return None;
            }
            paths.push(child[..depth].to_vec());
        }

        Some(Decoded {
            paths,
            secrets,
            nonce,
            ciphertext,
        })
    }
}

/// Decrypt a container with one x-only key. `Some(items)` on success.
pub fn decrypt(bytes: &[u8], key: &[u8; 32]) -> Option<Vec<u8>> {
    unsafe {
        let mut cont = Container {
            paths: ptr::null(),
            paths_len: 0,
            path_count: 0,
            secrets: ptr::null(),
            secret_count: 0,
            nonce: ptr::null(),
            ciphertext: ptr::null(),
            ciphertext_len: 0,
        };
        if bip138_parse(bytes.as_ptr(), bytes.len(), &mut cont) != BIP138_OK {
            return None;
        }
        let cap = bip138_plaintext_max(&cont);
        let mut plaintext = vec![0u8; cap.max(1)];
        let mut out_len = 0usize;
        let rc = bip138_decrypt(
            test_crypto(),
            &cont,
            key.as_ptr(),
            1,
            plaintext.as_mut_ptr(),
            plaintext.len(),
            &mut out_len,
            ptr::null_mut(),
        );
        if rc != BIP138_OK {
            return None;
        }
        plaintext.truncate(out_len);
        Some(plaintext)
    }
}

/// Deterministically encode content items to keys with an explicit nonce and
/// explicit decoys. `paths` is the raw child-number lists. `None` on any failure.
pub(crate) fn encode(
    keys: &[[u8; 32]],
    paths: &[Vec<u32>],
    items: &[EncodeItem],
    geometric_pad: bool,
    nonce: &[u8; 12],
    decoys: &[[u8; 32]],
) -> Option<Vec<u8>> {
    unsafe {
        let c_items: Vec<CItem> = items
            .iter()
            .map(|item| CItem {
                content: c_content(&item.content),
                data: item.data.as_ptr(),
                data_len: item.data.len(),
            })
            .collect();
        // Encode the plaintext payload (content metadata + items + padding).
        let mut payload = vec![0u8; 1 << 20];
        let mut payload_len = 0usize;
        if bip138_plaintext_encode(
            c_items.as_ptr(),
            c_items.len(),
            geometric_pad as c_int,
            payload.as_mut_ptr(),
            payload.len(),
            &mut payload_len,
        ) != BIP138_OK
        {
            return None;
        }
        payload.truncate(payload_len);

        let flat_keys: Vec<u8> = keys.iter().flatten().copied().collect();
        let flat_decoys: Vec<u8> = decoys.iter().flatten().copied().collect();
        let c_paths = c_paths(paths);

        let mut out = vec![0u8; payload.len() + (1 << 16)];
        let mut out_len = 0usize;
        let rc = bip138_encrypt_ex(
            test_crypto(),
            flat_keys.as_ptr(),
            keys.len(),
            if c_paths.is_empty() {
                ptr::null()
            } else {
                c_paths.as_ptr()
            },
            c_paths.len(),
            nonce.as_ptr(),
            if flat_decoys.is_empty() {
                ptr::null()
            } else {
                flat_decoys.as_ptr()
            },
            decoys.len(),
            payload.as_ptr(),
            payload.len(),
            out.as_mut_ptr(),
            out.len(),
            &mut out_len,
        );
        if rc != BIP138_OK {
            return None;
        }
        out.truncate(out_len);
        Some(out)
    }
}

fn c_content(content: &EncodeContent) -> CContent {
    CContent {
        type_: content.ctype,
        bip: content.bip,
        tag: if content.tag.is_empty() {
            ptr::null()
        } else {
            content.tag.as_ptr()
        },
        tag_len: content.tag.len(),
    }
}

/// Borrow the raw child-number lists as C paths. A depth above 255 does not fit
/// the C struct's u8, so callers keep paths within it.
fn c_paths(paths: &[Vec<u32>]) -> Vec<Path> {
    paths
        .iter()
        .map(|p| Path {
            child: p.as_ptr(),
            depth: p.len() as u8,
        })
        .collect()
}

/// Parse one CONTENT_TYPE field: bytes consumed and the content type.
pub fn parse_content(bytes: &[u8]) -> Option<(usize, ContentType)> {
    let mut content = CContent {
        type_: 0,
        bip: 0,
        tag: ptr::null(),
        tag_len: 0,
    };
    let mut consumed = 0usize;
    let rc =
        unsafe { bip138_content_parse(bytes.as_ptr(), bytes.len(), &mut content, &mut consumed) };
    if rc != BIP138_OK {
        return None;
    }
    Some((consumed, content_type(&content)))
}

/// Encode a CONTENT_TYPE field.
pub(crate) fn encode_content(content: &EncodeContent) -> Option<Vec<u8>> {
    let content = c_content(content);
    let mut out = vec![0u8; 1 + 9 + content.tag_len];
    let mut out_len = 0usize;
    let rc = unsafe { bip138_content_encode(&content, out.as_mut_ptr(), out.len(), &mut out_len) };
    if rc != BIP138_OK {
        return None;
    }
    out.truncate(out_len);
    Some(out)
}

/// Encode a DERIVATION_PATHS field (count prefix included). Paths must fit the
/// C struct, see `c_paths`.
pub fn encode_paths(paths: &[Vec<u32>]) -> Option<Vec<u8>> {
    let c_paths = c_paths(paths);
    let mut out = vec![0u8; 1 + paths.iter().map(|p| 1 + 4 * p.len()).sum::<usize>()];
    let mut out_len = 0usize;
    let rc = unsafe {
        bip138_paths_encode(
            c_paths.as_ptr(),
            c_paths.len(),
            out.as_mut_ptr(),
            out.len(),
            &mut out_len,
        )
    };
    if rc != BIP138_OK {
        return None;
    }
    out.truncate(out_len);
    Some(out)
}

/// Encode an INDIVIDUAL_SECRETS field (count prefix included).
pub fn encode_secrets(secrets: &[[u8; 32]]) -> Option<Vec<u8>> {
    let flat: Vec<u8> = secrets.iter().flatten().copied().collect();
    let mut out = vec![0u8; 1 + flat.len()];
    let mut out_len = 0usize;
    let rc = unsafe {
        bip138_secrets_encode(
            flat.as_ptr(),
            secrets.len(),
            out.as_mut_ptr(),
            out.len(),
            &mut out_len,
        )
    };
    if rc != BIP138_OK {
        return None;
    }
    out.truncate(out_len);
    Some(out)
}

/// Re-serialize a parsed container. C has no container serializer, so compose
/// its field encoders and CompactSize writer around the fixed header bytes.
pub fn reencode(d: &Decoded) -> Option<Vec<u8>> {
    let mut out = BIP138_MAGIC.to_vec();
    out.push(BIP138_VERSION);
    out.extend(encode_paths(&d.paths)?);
    out.extend(encode_secrets(&d.secrets)?);
    out.push(BIP138_ENCRYPTION_CHACHA20_POLY1305);
    out.extend_from_slice(&d.nonce);
    let mut len = [0u8; 9];
    let mut written = 0usize;
    let rc = unsafe {
        bip138_varint_write(
            len.as_mut_ptr(),
            len.len(),
            d.ciphertext.len() as u64,
            &mut written,
        )
    };
    if rc != BIP138_OK {
        return None;
    }
    out.extend_from_slice(&len[..written]);
    out.extend_from_slice(&d.ciphertext);
    Some(out)
}

/// Decoy bucket for `n_real` recipients (5, 10, 20, ... 255).
pub fn secret_bucket(n_real: usize) -> usize {
    unsafe { bip138_secret_bucket(n_real) }
}

fn content_type(content: &CContent) -> ContentType {
    match content.type_ {
        BIP138_CONTENT_BIP => ContentType::Bip(content.bip),
        BIP138_CONTENT_PROPRIETARY => ContentType::Proprietary(tag(content).to_vec()),
        BIP138_CONTENT_STRING => ContentType::String,
        _ => ContentType::Unknown,
    }
}

fn tag(content: &CContent) -> &[u8] {
    if content.tag_len == 0 {
        &[]
    } else {
        unsafe { slice::from_raw_parts(content.tag, content.tag_len) }
    }
}

/// Decrypt a container with one key and return the recovered items.
pub fn decrypt_items(bytes: &[u8], key: &[u8; 32]) -> Option<Vec<Item>> {
    let payload = decrypt(bytes, key)?;
    let mut items = Vec::new();
    unsafe {
        let mut it = ItemIter {
            buf: ptr::null(),
            len: 0,
            pos: 0,
        };
        bip138_item_iter_init(&mut it, payload.as_ptr(), payload.len());
        loop {
            let mut item = CItem {
                content: CContent {
                    type_: 0,
                    bip: 0,
                    tag: ptr::null(),
                    tag_len: 0,
                },
                data: ptr::null(),
                data_len: 0,
            };
            let rc = bip138_item_next(&mut it, &mut item);
            if rc < 0 {
                return None;
            }
            if rc == 0 {
                break;
            }
            items.push((
                content_type(&item.content),
                slice::from_raw_parts(item.data, item.data_len).to_vec(),
            ));
        }
    }
    Some(items)
}
