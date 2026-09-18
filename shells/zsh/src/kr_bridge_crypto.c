/*
 * SHA-256 and HMAC-SHA-256 for the bridge's bootstrap proof.
 *
 * Copyright (c) Kala Powered.
 *
 * This file is added to Zsh by the KalaReach reader patch set and is distributed under the Zsh
 * licence that governs the rest of the package; see shells/zsh/LICENSE.
 *
 * The proof is one HMAC over one transcript, taken once at startup. A shell package cannot take a
 * dependency on the host's cryptography library without linking the whole of it into every
 * interactive shell, so the two primitives it needs are here, from FIPS 180-4 and RFC 2104.
 */

#include "kr_bridge_crypto.h"

#include <string.h>

#define ROTR(value, bits) (((value) >> (bits)) | ((value) << (32 - (bits))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define BSIG0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define BSIG1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define SSIG0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ ((x) >> 3))
#define SSIG1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))

static const kr_u32 kr_sha256_k[64] = {
    0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL, 0x3956c25bUL, 0x59f111f1UL,
    0x923f82a4UL, 0xab1c5ed5UL, 0xd807aa98UL, 0x12835b01UL, 0x243185beUL, 0x550c7dc3UL,
    0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL, 0xc19bf174UL, 0xe49b69c1UL, 0xefbe4786UL,
    0x0fc19dc6UL, 0x240ca1ccUL, 0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL,
    0x983e5152UL, 0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL, 0xc6e00bf3UL, 0xd5a79147UL,
    0x06ca6351UL, 0x14292967UL, 0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL, 0x53380d13UL,
    0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL, 0xa2bfe8a1UL, 0xa81a664bUL,
    0xc24b8b70UL, 0xc76c51a3UL, 0xd192e819UL, 0xd6990624UL, 0xf40e3585UL, 0x106aa070UL,
    0x19a4c116UL, 0x1e376c08UL, 0x2748774cUL, 0x34b0bcb5UL, 0x391c0cb3UL, 0x4ed8aa4aUL,
    0x5b9cca4fUL, 0x682e6ff3UL, 0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL,
    0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL
};

static void
kr_sha256_block(kr_sha256 *state, const unsigned char *block)
{
    kr_u32 w[64];
    kr_u32 a, b, c, d, e, f, g, h, t1, t2;
    int i;

    for (i = 0; i < 16; i++) {
        w[i] = ((kr_u32)block[i * 4] << 24) | ((kr_u32)block[i * 4 + 1] << 16) |
               ((kr_u32)block[i * 4 + 2] << 8) | (kr_u32)block[i * 4 + 3];
    }
    for (i = 16; i < 64; i++) {
        w[i] = (SSIG1(w[i - 2]) + w[i - 7] + SSIG0(w[i - 15]) + w[i - 16]) & 0xffffffffUL;
    }

    a = state->h[0];
    b = state->h[1];
    c = state->h[2];
    d = state->h[3];
    e = state->h[4];
    f = state->h[5];
    g = state->h[6];
    h = state->h[7];

    for (i = 0; i < 64; i++) {
        t1 = (h + BSIG1(e) + CH(e, f, g) + kr_sha256_k[i] + w[i]) & 0xffffffffUL;
        t2 = (BSIG0(a) + MAJ(a, b, c)) & 0xffffffffUL;
        h = g;
        g = f;
        f = e;
        e = (d + t1) & 0xffffffffUL;
        d = c;
        c = b;
        b = a;
        a = (t1 + t2) & 0xffffffffUL;
    }

    state->h[0] = (state->h[0] + a) & 0xffffffffUL;
    state->h[1] = (state->h[1] + b) & 0xffffffffUL;
    state->h[2] = (state->h[2] + c) & 0xffffffffUL;
    state->h[3] = (state->h[3] + d) & 0xffffffffUL;
    state->h[4] = (state->h[4] + e) & 0xffffffffUL;
    state->h[5] = (state->h[5] + f) & 0xffffffffUL;
    state->h[6] = (state->h[6] + g) & 0xffffffffUL;
    state->h[7] = (state->h[7] + h) & 0xffffffffUL;

    memset(w, 0, sizeof(w));
}

void
kr_sha256_init(kr_sha256 *state)
{
    state->h[0] = 0x6a09e667UL;
    state->h[1] = 0xbb67ae85UL;
    state->h[2] = 0x3c6ef372UL;
    state->h[3] = 0xa54ff53aUL;
    state->h[4] = 0x510e527fUL;
    state->h[5] = 0x9b05688cUL;
    state->h[6] = 0x1f83d9abUL;
    state->h[7] = 0x5be0cd19UL;
    state->length = 0;
    state->buffered = 0;
}

void
kr_sha256_update(kr_sha256 *state, const void *data, size_t len)
{
    const unsigned char *bytes = (const unsigned char *)data;
    size_t taken;

    state->length += (unsigned long long)len * 8u;
    while (len > 0) {
        taken = KR_SHA256_BLOCK - state->buffered;
        if (taken > len) {
            taken = len;
        }
        memcpy(state->block + state->buffered, bytes, taken);
        state->buffered += taken;
        bytes += taken;
        len -= taken;
        if (state->buffered == KR_SHA256_BLOCK) {
            kr_sha256_block(state, state->block);
            state->buffered = 0;
        }
    }
}

void
kr_sha256_final(kr_sha256 *state, unsigned char out[KR_SHA256_LEN])
{
    unsigned long long bits = state->length;
    unsigned char tail[KR_SHA256_BLOCK * 2];
    size_t pad;
    int i;

    memset(tail, 0, sizeof(tail));
    tail[0] = 0x80;
    /* The length field is the last eight bytes of the final block. */
    pad = (state->buffered < 56) ? (56 - state->buffered) : (120 - state->buffered);
    for (i = 0; i < 8; i++) {
        tail[pad + i] = (unsigned char)((bits >> (56 - i * 8)) & 0xffu);
    }
    kr_sha256_update(state, tail, pad + 8);

    for (i = 0; i < 8; i++) {
        out[i * 4] = (unsigned char)((state->h[i] >> 24) & 0xffu);
        out[i * 4 + 1] = (unsigned char)((state->h[i] >> 16) & 0xffu);
        out[i * 4 + 2] = (unsigned char)((state->h[i] >> 8) & 0xffu);
        out[i * 4 + 3] = (unsigned char)(state->h[i] & 0xffu);
    }
    memset(state, 0, sizeof(*state));
}

void
kr_hmac_sha256(const unsigned char *key, size_t key_len, const unsigned char *message,
               size_t message_len, unsigned char out[KR_SHA256_LEN])
{
    unsigned char block[KR_SHA256_BLOCK];
    unsigned char inner[KR_SHA256_LEN];
    unsigned char shortened[KR_SHA256_LEN];
    kr_sha256 state;
    size_t i;

    if (key_len > KR_SHA256_BLOCK) {
        kr_sha256_init(&state);
        kr_sha256_update(&state, key, key_len);
        kr_sha256_final(&state, shortened);
        key = shortened;
        key_len = KR_SHA256_LEN;
    }

    memset(block, 0x36, sizeof(block));
    for (i = 0; i < key_len; i++) {
        block[i] = (unsigned char)(key[i] ^ 0x36u);
    }
    kr_sha256_init(&state);
    kr_sha256_update(&state, block, sizeof(block));
    kr_sha256_update(&state, message, message_len);
    kr_sha256_final(&state, inner);

    memset(block, 0x5c, sizeof(block));
    for (i = 0; i < key_len; i++) {
        block[i] = (unsigned char)(key[i] ^ 0x5cu);
    }
    kr_sha256_init(&state);
    kr_sha256_update(&state, block, sizeof(block));
    kr_sha256_update(&state, inner, sizeof(inner));
    kr_sha256_final(&state, out);

    memset(block, 0, sizeof(block));
    memset(inner, 0, sizeof(inner));
    memset(shortened, 0, sizeof(shortened));
}

int
kr_base64url_decode(const char *text, unsigned char *out, size_t capacity, size_t *written)
{
    static const char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    unsigned long accumulator = 0;
    int bits = 0;
    size_t produced = 0;
    const char *cursor;

    for (cursor = text; *cursor != '\0'; cursor++) {
        const char *found = strchr(alphabet, *cursor);
        if (found == NULL || *cursor == '\0') {
            return 0;
        }
        accumulator = (accumulator << 6) | (unsigned long)(found - alphabet);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (produced >= capacity) {
                return 0;
            }
            out[produced++] = (unsigned char)((accumulator >> bits) & 0xffu);
        }
    }
    /* Unpadded base64url leaves at most five bits, and they must all be zero. */
    if (bits >= 6 || (accumulator & ((1UL << bits) - 1UL)) != 0) {
        return 0;
    }
    *written = produced;
    return 1;
}
