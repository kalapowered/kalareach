/*
 * SHA-256, HMAC-SHA-256 and base64url for the bridge's bootstrap proof.
 *
 * Copyright (c) Kala Powered.
 *
 * This file is added to GNU Bash's bundled Readline by the KalaReach reader patch set and is
 * distributed under the GNU General Public Licence, version 3 or later, that governs the rest of
 * the package; see shells/bash/LICENSE.
 */

#ifndef KR_BRIDGE_CRYPTO_H
#define KR_BRIDGE_CRYPTO_H

#include <stddef.h>

#define KR_SHA256_LEN 32
#define KR_SHA256_BLOCK 64

typedef unsigned int kr_u32;

typedef struct {
    kr_u32 h[8];
    unsigned long long length;
    unsigned char block[KR_SHA256_BLOCK];
    size_t buffered;
} kr_sha256;

void kr_sha256_init(kr_sha256 *state);
void kr_sha256_update(kr_sha256 *state, const void *data, size_t len);
void kr_sha256_final(kr_sha256 *state, unsigned char out[KR_SHA256_LEN]);

void kr_hmac_sha256(const unsigned char *key, size_t key_len, const unsigned char *message,
                    size_t message_len, unsigned char out[KR_SHA256_LEN]);

/* Decodes unpadded base64url. Returns non-zero on success. */
int kr_base64url_decode(const char *text, unsigned char *out, size_t capacity, size_t *written);

#endif /* KR_BRIDGE_CRYPTO_H */
