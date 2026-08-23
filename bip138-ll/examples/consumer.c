/*
 * Example C consumer of bip138-ll: encrypt a payload to one x-only key, decrypt
 * it back, print the result, and free everything.
 *
 * The crypto vtable is backed by libsodium, whose IETF ChaCha20-Poly1305
 * (12-byte nonce, 32-byte key, 16-byte tag, no AAD), SHA-256, and randombytes
 * match what the core expects. Any other crypto library works the same way.
 *
 * Build (see bip138-ll/README.md for the staticlib shim `libbip138_shim.a`):
 *   cc -I ../include consumer.c path/to/libbip138_shim.a -lsodium -o consumer
 */
#include <stdio.h>
#include <string.h>

#include <sodium.h>

#include "bip138.h"

static void sha256_cb(void *ctx, const uint8_t *data, size_t len, uint8_t *out) {
    (void)ctx;
    crypto_hash_sha256(out, data, len);
}

static int32_t aead_encrypt_cb(void *ctx, const uint8_t *key, const uint8_t *nonce,
                               const uint8_t *plaintext, size_t plaintext_len,
                               uint8_t *out, size_t out_cap, size_t *out_len) {
    (void)ctx;
    unsigned long long clen = 0;
    if (out_cap < plaintext_len + crypto_aead_chacha20poly1305_ietf_ABYTES) {
        return 1;
    }
    if (crypto_aead_chacha20poly1305_ietf_encrypt(out, &clen, plaintext, plaintext_len,
                                                  NULL, 0, NULL, nonce, key) != 0) {
        return 1;
    }
    *out_len = (size_t)clen;
    return 0;
}

static int32_t aead_decrypt_cb(void *ctx, const uint8_t *key, const uint8_t *nonce,
                               const uint8_t *ciphertext, size_t ciphertext_len,
                               uint8_t *out, size_t out_cap, size_t *out_len) {
    (void)ctx;
    (void)out_cap;
    unsigned long long mlen = 0;
    if (crypto_aead_chacha20poly1305_ietf_decrypt(out, &mlen, NULL, ciphertext, ciphertext_len,
                                                  NULL, 0, nonce, key) != 0) {
        return 1;
    }
    *out_len = (size_t)mlen;
    return 0;
}

static void fill_random_cb(void *ctx, uint8_t *buf, size_t len) {
    (void)ctx;
    randombytes_buf(buf, len);
}

int main(void) {
    if (sodium_init() < 0) {
        fprintf(stderr, "libsodium init failed\n");
        return 1;
    }

    bip138_crypto_vtable vtable = {
        .ctx = NULL,
        .sha256 = sha256_cb,
        .aead_encrypt = aead_encrypt_cb,
        .aead_decrypt = aead_decrypt_cb,
        .fill_random = fill_random_cb,
    };

    /* A demo x-only key. In practice this is a real cosigner public key. */
    uint8_t key[BIP138_XONLY_KEY_LEN];
    memset(key, 0x07, sizeof(key));

    const char *payload = "a descriptor or any wallet blob";

    bip138_buf encrypted = {0};
    const char *err = NULL;
    int32_t rc = bip138_encrypt(&vtable, key, 1, NULL, 0, BIP138_CONTENT_STRING, 0, NULL, 0,
                                (const uint8_t *)payload, strlen(payload), BIP138_PADDING_NONE,
                                &encrypted, &err);
    if (rc != BIP138_OK) {
        fprintf(stderr, "encrypt failed (%d): %s\n", rc, err ? err : "");
        return 1;
    }
    printf("encrypted %zu bytes\n", encrypted.len);

    bip138_decrypt_result *result = NULL;
    rc = bip138_decrypt(&vtable, key, encrypted.ptr, encrypted.len, &result, &err);
    if (rc != BIP138_OK) {
        fprintf(stderr, "decrypt failed (%d): %s\n", rc, err ? err : "");
        bip138_buf_free(encrypted);
        return 1;
    }

    size_t count = bip138_decrypt_len(result);
    for (size_t i = 0; i < count; i++) {
        bip138_item item;
        if (bip138_decrypt_item(result, i, &item, &err) != BIP138_OK) {
            fprintf(stderr, "item %zu failed: %s\n", i, err ? err : "");
            continue;
        }
        printf("item %zu type %u: %.*s\n", i, item.content_type, (int)item.plaintext.len,
               item.plaintext.ptr);
    }

    bip138_decrypt_free(result);
    bip138_buf_free(encrypted);
    return 0;
}
