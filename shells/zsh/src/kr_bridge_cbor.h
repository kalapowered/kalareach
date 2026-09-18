/*
 * The KR-CBOR-1 encoder and the bounded decoder the bridge frames use.
 *
 * Copyright (c) Kala Powered.
 *
 * This file is added to Zsh by the KalaReach reader patch set and is distributed under the Zsh
 * licence that governs the rest of the package; see shells/zsh/LICENSE.
 *
 * KR-CBOR-1 is RFC 8949 section 4.2.1 core deterministic encoding: shortest-form heads, definite
 * lengths, and map keys in the bytewise lexicographic order of their *complete encoded keys*. For
 * the text keys this bridge writes that is (length, bytes), so "z" sorts before "aa".
 * `kr_cbor_key` enforces it as the frame is written rather than trusting the call sites.
 */

#ifndef KR_BRIDGE_CBOR_H
#define KR_BRIDGE_CBOR_H

#include <stddef.h>

/* Every frame this bridge writes is far below the control stream's maximum. */
#define KR_CBOR_MAX_FRAME (1024u * 1024u)

/* The decoder's bounds. The arena grows with the frame and is released with it; a value needs at
 * least one byte on the wire, so a frame inside the stream's maximum cannot need more than this. */
#define KR_CBOR_MAX_VALUES 65536
#define KR_CBOR_MAX_DEPTH 16

typedef struct {
    unsigned char *bytes;
    size_t len;
    size_t capacity;
    int failed;
    /* The previous key of the map being written, so an out-of-order key is caught here. */
    const char *last_key[KR_CBOR_MAX_DEPTH];
    int depth;
} kr_cbor_writer;

void kr_cbor_writer_init(kr_cbor_writer *writer);
void kr_cbor_writer_free(kr_cbor_writer *writer);

void kr_cbor_uint(kr_cbor_writer *writer, unsigned long long value);
void kr_cbor_bstr(kr_cbor_writer *writer, const void *bytes, size_t len);
void kr_cbor_tstr(kr_cbor_writer *writer, const char *text);
void kr_cbor_tstr_len(kr_cbor_writer *writer, const char *text, size_t len);
void kr_cbor_bool(kr_cbor_writer *writer, int value);
void kr_cbor_null(kr_cbor_writer *writer);

/* Opens an array of exactly `count` items. */
void kr_cbor_array(kr_cbor_writer *writer, size_t count);
/* Opens a map of exactly `count` pairs; close it with kr_cbor_map_end. */
void kr_cbor_map(kr_cbor_writer *writer, size_t count);
void kr_cbor_map_end(kr_cbor_writer *writer);
/* Writes one map key, checking that it follows the previous one in canonical order. */
void kr_cbor_key(kr_cbor_writer *writer, const char *key);

/* An externally tagged enum variant that carries fields: a single-entry map. */
void kr_cbor_variant(kr_cbor_writer *writer, const char *name);
void kr_cbor_variant_end(kr_cbor_writer *writer);

/* ---- decoding ------------------------------------------------------------------------------ */

#define KR_CBOR_UINT 0
#define KR_CBOR_BSTR 2
#define KR_CBOR_TSTR 3
#define KR_CBOR_ARRAY 4
#define KR_CBOR_MAP 5
#define KR_CBOR_BOOL 7
#define KR_CBOR_NULL 8

typedef struct {
    int kind;
    unsigned long long number;      /* KR_CBOR_UINT, KR_CBOR_BOOL */
    const unsigned char *payload;   /* KR_CBOR_BSTR, KR_CBOR_TSTR */
    size_t payload_len;
    int first_child;                /* index into the arena, or -1 */
    size_t count;                   /* items, or pairs for a map */
    int next_sibling;               /* index into the arena, or -1 */
    const unsigned char *encoded;   /* this value's own bytes, for echoing one back verbatim */
    size_t encoded_len;
} kr_cbor_value;

typedef struct {
    kr_cbor_value *values;
    int capacity;
    int used;
    int failed;
} kr_cbor_doc;

/*
 * Parses one canonical object. Returns the root index, or -1.
 *
 * Strict: shortest-form heads, definite lengths, map keys that are text and strictly ascending in
 * the bytewise order of their complete encoded keys, and nothing outside the profile. Anything
 * else is a refusal rather than something to make sense of.
 */
int kr_cbor_parse(kr_cbor_doc *doc, const unsigned char *bytes, size_t len);

/* Releases what one parse allocated. */
void kr_cbor_doc_free(kr_cbor_doc *doc);

/* Returns the value of `key` in the map at `index`, or -1. */
int kr_cbor_get(const kr_cbor_doc *doc, int index, const char *key);

/* Returns the item at `position` of the array at `index`, or -1. */
int kr_cbor_at(const kr_cbor_doc *doc, int index, size_t position);

/* Walks a collection's items once: the first, then each next one, or -1. */
int kr_cbor_first(const kr_cbor_doc *doc, int index);
int kr_cbor_next(const kr_cbor_doc *doc, int index);

/* Returns the single entry of an externally tagged variant, and names it. */
int kr_cbor_variant_of(const kr_cbor_doc *doc, int index, const char **name, size_t *name_len);

/* Returns non-zero when the value at `index` is the text `text`. */
int kr_cbor_is_text(const kr_cbor_doc *doc, int index, const char *text);

/* Reads an unsigned integer, or `fallback` when the value is not one. */
unsigned long long kr_cbor_uint_or(const kr_cbor_doc *doc, int index, unsigned long long fallback);

/* Reads a boolean, or `fallback`. */
int kr_cbor_bool_or(const kr_cbor_doc *doc, int index, int fallback);

/* Copies a byte string of exactly `len` bytes. Returns non-zero on success. */
int kr_cbor_bytes_exact(const kr_cbor_doc *doc, int index, unsigned char *out, size_t len);

/* Writes a decoded value back out exactly as it arrived, which is how an answer echoes the command
 * the request carried rather than a re-encoding of it. */
void kr_cbor_embed(kr_cbor_writer *writer, const kr_cbor_doc *doc, int index);

#endif /* KR_BRIDGE_CBOR_H */
