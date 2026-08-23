/*
 * C binding for bip138-ll: encrypt a payload to a set of x-only keys and decrypt
 * one back. The core does the cryptography through callbacks you supply, so this
 * header pulls in no crypto of its own.
 *
 * Kept in sync by hand with bip138-ll/src/ffi.rs. bip138-ll/tests/layout.rs pins
 * the size, alignment, and field offset of every struct below, so a change on
 * the Rust side fails that test until this header follows.
 *
 * Ownership: Rust never frees your memory, and you never free Rust memory except
 * through bip138_buf_free and bip138_decrypt_free. A vtable and the buffers you
 * pass in are borrowed for the duration of a call only. No entry point returns
 * through a panic; every failure is a return code.
 */
#ifndef BIP138_H
#define BIP138_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Success. Any other returned int32 is an error code; see the ranges below. */
#define BIP138_OK 0

/*
 * Content type discriminants. Used in bip138_encrypt input and bip138_decrypt_item
 * output. BIP carries its number in the `bip` field; PROPRIETARY carries its tag
 * in the `tag` field.
 */
#define BIP138_CONTENT_NONE 0
#define BIP138_CONTENT_BIP138 1
#define BIP138_CONTENT_BIP139 2
#define BIP138_CONTENT_BIP380 3
#define BIP138_CONTENT_BIP388 4
#define BIP138_CONTENT_BIP329 5
#define BIP138_CONTENT_BIP 6
#define BIP138_CONTENT_PROPRIETARY 7
#define BIP138_CONTENT_STRING 8
#define BIP138_CONTENT_UNKNOWN 9

/* Padding discriminants for bip138_encrypt. */
#define BIP138_PADDING_NONE 0
#define BIP138_PADDING_GEOMETRIC 1

/* Length of an x-only public key, and of a nonce, in bytes. */
#define BIP138_XONLY_KEY_LEN 32
#define BIP138_NONCE_LEN 12

/*
 * Error code ranges (all negative-free int32; 0 is success):
 *   100..199  core codec errors (bad magic, wrong key, corrupted, ...)
 *   500..599  C boundary errors (null pointer, null vtable callback, bad enum, ...)
 * The message written to the `err` out-parameter is a static, NUL-terminated
 * string owned by the library; never free it.
 */

/*
 * The crypto primitives you supply. `ctx` is passed back to every callback so you
 * can carry state. A callback needed by an operation must be non-null; a null one
 * makes that call fail with error 501.
 */
typedef struct bip138_crypto_vtable {
    void *ctx;
    /* SHA-256 of `len` bytes at `data` into the 32-byte `out`. */
    void (*sha256)(void *ctx, const uint8_t *data, size_t len, uint8_t *out);
    /*
     * ChaCha20-Poly1305 encrypt. `out_cap` is plaintext_len + 16. Write the
     * ciphertext to `out` and its length to `out_len`. Return 0 on success.
     */
    int32_t (*aead_encrypt)(void *ctx, const uint8_t *key, const uint8_t *nonce,
                            const uint8_t *plaintext, size_t plaintext_len,
                            uint8_t *out, size_t out_cap, size_t *out_len);
    /*
     * ChaCha20-Poly1305 decrypt. `out_cap` is ciphertext_len. Write the plaintext
     * to `out` and its length to `out_len`. Return 0 on success, non-zero when the
     * tag does not verify.
     */
    int32_t (*aead_decrypt)(void *ctx, const uint8_t *key, const uint8_t *nonce,
                            const uint8_t *ciphertext, size_t ciphertext_len,
                            uint8_t *out, size_t out_cap, size_t *out_len);
    /* Fill `len` bytes at `buf` with cryptographically secure randomness. */
    void (*fill_random)(void *ctx, uint8_t *buf, size_t len);
} bip138_crypto_vtable;

/*
 * One derivation path: raw BIP32 child numbers with the hardened bit in the high
 * bit. A null `ptr` with a non-zero `len` is rejected.
 */
typedef struct bip138_u32_list {
    const uint32_t *ptr;
    size_t len;
} bip138_u32_list;

/* An owned byte buffer returned by the library; release it with bip138_buf_free. */
typedef struct bip138_buf {
    uint8_t *ptr;
    size_t len;
} bip138_buf;

/* A byte run borrowed from a decrypt result; valid until bip138_decrypt_free. */
typedef struct bip138_bytes {
    const uint8_t *ptr;
    size_t len;
} bip138_bytes;

/* One decoded content item, borrowed from a decrypt result. */
typedef struct bip138_item {
    /* One of the BIP138_CONTENT_* values. */
    uint32_t content_type;
    /* BIP number when content_type is BIP138_CONTENT_BIP, else 0. */
    uint16_t bip;
    /* Vendor tag when content_type is BIP138_CONTENT_PROPRIETARY, else empty. */
    bip138_bytes tag;
    /* The recovered plaintext of this item. */
    bip138_bytes plaintext;
} bip138_item;

/* Opaque owner of a decode's items. */
typedef struct bip138_decrypt_result bip138_decrypt_result;

/*
 * Encrypt one content item to `n_keys` x-only keys (`keys` is n_keys * 32 bytes).
 * `paths` is `n_paths` derivation paths. `content_type`/`bip`/`tag` describe the
 * item; `payload` is its plaintext. On success writes the encrypted bytes to
 * `*out` (own it until bip138_buf_free). `err` may be NULL.
 */
int32_t bip138_encrypt(const bip138_crypto_vtable *vtable, const uint8_t *keys,
                       size_t n_keys, const bip138_u32_list *paths, size_t n_paths,
                       uint32_t content_type, uint16_t bip, const uint8_t *tag,
                       size_t tag_len, const uint8_t *payload, size_t payload_len,
                       uint32_t padding, bip138_buf *out, const char **err);

/*
 * Decrypt a backup with one 32-byte x-only key. On success writes an owning
 * handle to `*out` (release with bip138_decrypt_free). `err` may be NULL.
 */
int32_t bip138_decrypt(const bip138_crypto_vtable *vtable, const uint8_t *key,
                       const uint8_t *encrypted, size_t encrypted_len,
                       bip138_decrypt_result **out, const char **err);

/* Number of content items in a decrypt result. A NULL result is 0. */
size_t bip138_decrypt_len(const bip138_decrypt_result *result);

/*
 * Read the item at `index` into `*out`. Its tag and plaintext point into the
 * result and are valid until bip138_decrypt_free. `err` may be NULL.
 */
int32_t bip138_decrypt_item(const bip138_decrypt_result *result, size_t index,
                            bip138_item *out, const char **err);

/* Release an encrypt buffer. A NULL pointer is a no-op. */
void bip138_buf_free(bip138_buf buf);

/* Release a decrypt result. A NULL pointer is a no-op. */
void bip138_decrypt_free(bip138_decrypt_result *result);

#ifdef __cplusplus
}
#endif

#endif /* BIP138_H */
