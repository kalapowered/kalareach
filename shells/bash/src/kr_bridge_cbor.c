/*
 * The KR-CBOR-1 encoder and the bounded decoder the bridge frames use.
 *
 * Copyright (c) Kala Powered.
 *
 * This file is added to GNU Bash's bundled Readline by the KalaReach reader patch set and is
 * distributed under the GNU General Public Licence, version 3 or later, that governs the rest of
 * the package; see shells/bash/LICENSE.
 */

#include "kr_bridge_cbor.h"

#include <stdlib.h>
#include <string.h>

static void
kr_cbor_reserve(kr_cbor_writer *writer, size_t extra)
{
    size_t wanted;
    unsigned char *grown;

    if (writer->failed) {
        return;
    }
    if (writer->len + extra <= writer->capacity) {
        return;
    }
    wanted = writer->capacity ? writer->capacity : 256;
    while (wanted < writer->len + extra) {
        if (wanted > KR_CBOR_MAX_FRAME) {
            writer->failed = 1;
            return;
        }
        wanted *= 2;
    }
    grown = (unsigned char *)realloc(writer->bytes, wanted);
    if (grown == NULL) {
        writer->failed = 1;
        return;
    }
    writer->bytes = grown;
    writer->capacity = wanted;
}

static void
kr_cbor_raw(kr_cbor_writer *writer, const void *bytes, size_t len)
{
    kr_cbor_reserve(writer, len);
    if (writer->failed) {
        return;
    }
    memcpy(writer->bytes + writer->len, bytes, len);
    writer->len += len;
}

/* Writes the shortest head for `major` and `value`, which is what makes the encoding canonical. */
static void
kr_cbor_head(kr_cbor_writer *writer, unsigned int major, unsigned long long value)
{
    unsigned char head[9];
    size_t len;
    int i;

    if (value < 24u) {
        head[0] = (unsigned char)((major << 5) | (unsigned int)value);
        len = 1;
    } else if (value <= 0xffu) {
        head[0] = (unsigned char)((major << 5) | 24u);
        head[1] = (unsigned char)value;
        len = 2;
    } else if (value <= 0xffffu) {
        head[0] = (unsigned char)((major << 5) | 25u);
        head[1] = (unsigned char)(value >> 8);
        head[2] = (unsigned char)value;
        len = 3;
    } else if (value <= 0xffffffffULL) {
        head[0] = (unsigned char)((major << 5) | 26u);
        for (i = 0; i < 4; i++) {
            head[1 + i] = (unsigned char)(value >> (24 - i * 8));
        }
        len = 5;
    } else {
        head[0] = (unsigned char)((major << 5) | 27u);
        for (i = 0; i < 8; i++) {
            head[1 + i] = (unsigned char)(value >> (56 - i * 8));
        }
        len = 9;
    }
    kr_cbor_raw(writer, head, len);
}

void
kr_cbor_writer_init(kr_cbor_writer *writer)
{
    memset(writer, 0, sizeof(*writer));
}

void
kr_cbor_writer_free(kr_cbor_writer *writer)
{
    free(writer->bytes);
    memset(writer, 0, sizeof(*writer));
}

void
kr_cbor_uint(kr_cbor_writer *writer, unsigned long long value)
{
    kr_cbor_head(writer, 0, value);
}

void
kr_cbor_bstr(kr_cbor_writer *writer, const void *bytes, size_t len)
{
    kr_cbor_head(writer, 2, (unsigned long long)len);
    kr_cbor_raw(writer, bytes, len);
}

void
kr_cbor_tstr_len(kr_cbor_writer *writer, const char *text, size_t len)
{
    kr_cbor_head(writer, 3, (unsigned long long)len);
    kr_cbor_raw(writer, text, len);
}

void
kr_cbor_tstr(kr_cbor_writer *writer, const char *text)
{
    kr_cbor_tstr_len(writer, text, strlen(text));
}

void
kr_cbor_bool(kr_cbor_writer *writer, int value)
{
    unsigned char byte = (unsigned char)(value ? 0xf5u : 0xf4u);
    kr_cbor_raw(writer, &byte, 1);
}

void
kr_cbor_null(kr_cbor_writer *writer)
{
    unsigned char byte = 0xf6u;
    kr_cbor_raw(writer, &byte, 1);
}

void
kr_cbor_array(kr_cbor_writer *writer, size_t count)
{
    kr_cbor_head(writer, 4, (unsigned long long)count);
}

void
kr_cbor_map(kr_cbor_writer *writer, size_t count)
{
    kr_cbor_head(writer, 5, (unsigned long long)count);
    if (writer->depth >= KR_CBOR_MAX_DEPTH) {
        writer->failed = 1;
        return;
    }
    writer->last_key[writer->depth] = NULL;
    writer->depth++;
}

void
kr_cbor_map_end(kr_cbor_writer *writer)
{
    if (writer->depth <= 0) {
        writer->failed = 1;
        return;
    }
    writer->depth--;
}

void
kr_cbor_key(kr_cbor_writer *writer, const char *key)
{
    const char *previous;
    size_t left;
    size_t right;

    if (writer->depth <= 0) {
        writer->failed = 1;
        return;
    }
    previous = writer->last_key[writer->depth - 1];
    if (previous != NULL) {
        left = strlen(previous);
        right = strlen(key);
        /* The complete encoded key is head(len) || utf8, and the head rises with the length, so
         * comparing the encoded keys is comparing (length, bytes). */
        if (left > right || (left == right && strcmp(previous, key) >= 0)) {
            writer->failed = 1;
            return;
        }
    }
    writer->last_key[writer->depth - 1] = key;
    kr_cbor_tstr(writer, key);
}

void
kr_cbor_variant(kr_cbor_writer *writer, const char *name)
{
    kr_cbor_map(writer, 1);
    kr_cbor_key(writer, name);
}

void
kr_cbor_variant_end(kr_cbor_writer *writer)
{
    kr_cbor_map_end(writer);
}

/* ---- decoding ------------------------------------------------------------------------------ */

typedef struct {
    const unsigned char *bytes;
    size_t len;
    size_t at;
    kr_cbor_doc *doc;
    int depth;
} kr_cbor_parser;

static int kr_cbor_value_parse(kr_cbor_parser *parser);

static int
kr_cbor_take_head(kr_cbor_parser *parser, unsigned int *major, unsigned long long *value)
{
    unsigned char initial;
    unsigned int additional;
    unsigned long long number = 0;
    unsigned long long floor;
    size_t width;
    size_t i;

    if (parser->at >= parser->len) {
        return 0;
    }
    initial = parser->bytes[parser->at++];
    *major = (unsigned int)(initial >> 5);
    additional = (unsigned int)(initial & 0x1fu);
    if (additional < 24u) {
        *value = additional;
        return 1;
    }
    switch (additional) {
    case 24: width = 1; floor = 24ull; break;
    case 25: width = 2; floor = 0x100ull; break;
    case 26: width = 4; floor = 0x10000ull; break;
    case 27: width = 8; floor = 0x100000000ull; break;
    default: return 0; /* indefinite lengths and reserved values are outside the profile */
    }
    if (parser->len - parser->at < width) {
        return 0;
    }
    for (i = 0; i < width; i++) {
        number = (number << 8) | parser->bytes[parser->at + i];
    }
    /* Shortest form: a value that fits a narrower head was not encoded canonically. */
    if (number < floor) {
        return 0;
    }
    parser->at += width;
    *value = number;
    return 1;
}

static int
kr_cbor_take_value(kr_cbor_parser *parser)
{
    kr_cbor_doc *doc = parser->doc;
    int index;

    if (doc->used >= doc->capacity) {
        int wanted = doc->capacity ? doc->capacity * 2 : 64;
        kr_cbor_value *grown;
        if (wanted > KR_CBOR_MAX_VALUES) {
            wanted = KR_CBOR_MAX_VALUES;
        }
        if (doc->used >= wanted) {
            doc->failed = 1;
            return -1;
        }
        grown = (kr_cbor_value *)realloc(doc->values, (size_t)wanted * sizeof(kr_cbor_value));
        if (grown == NULL) {
            doc->failed = 1;
            return -1;
        }
        doc->values = grown;
        doc->capacity = wanted;
    }
    index = doc->used++;
    memset(&doc->values[index], 0, sizeof(kr_cbor_value));
    doc->values[index].first_child = -1;
    doc->values[index].next_sibling = -1;
    return index;
}

/* The complete encoded key's order, which for a text key is (length, bytes). */
static int
kr_cbor_key_precedes(const kr_cbor_value *left, const kr_cbor_value *right)
{
    size_t shortest;
    int order;

    if (left->payload_len != right->payload_len) {
        return left->payload_len < right->payload_len;
    }
    shortest = left->payload_len;
    order = shortest == 0 ? 0 : memcmp(left->payload, right->payload, shortest);
    return order < 0;
}

/* Map keys are text and strictly ascending, which is what makes the encoding canonical. */
static int
kr_cbor_keys_ordered(const kr_cbor_doc *doc, int parent)
{
    int key = doc->values[parent].first_child;
    int previous = -1;

    while (key >= 0) {
        int value = doc->values[key].next_sibling;
        if (doc->values[key].kind != KR_CBOR_TSTR) {
            return 0;
        }
        if (previous >= 0 && !kr_cbor_key_precedes(&doc->values[previous], &doc->values[key])) {
            return 0;
        }
        if (value < 0) {
            return 0;
        }
        previous = key;
        key = doc->values[value].next_sibling;
    }
    return 1;
}

static int
kr_cbor_children(kr_cbor_parser *parser, int parent, size_t items)
{
    int previous = -1;
    size_t i;

    for (i = 0; i < items; i++) {
        int child = kr_cbor_value_parse(parser);
        if (child < 0) {
            return 0;
        }
        if (previous < 0) {
            parser->doc->values[parent].first_child = child;
        } else {
            parser->doc->values[previous].next_sibling = child;
        }
        previous = child;
    }
    return 1;
}

static int
kr_cbor_value_parse(kr_cbor_parser *parser)
{
    unsigned int major;
    unsigned long long number;
    int index;
    size_t start = parser->at;

    if (parser->depth >= KR_CBOR_MAX_DEPTH) {
        parser->doc->failed = 1;
        return -1;
    }
    if (!kr_cbor_take_head(parser, &major, &number)) {
        parser->doc->failed = 1;
        return -1;
    }
    index = kr_cbor_take_value(parser);
    if (index < 0) {
        return -1;
    }
    parser->doc->values[index].encoded = parser->bytes + start;

    switch (major) {
    case 0:
        parser->doc->values[index].kind = KR_CBOR_UINT;
        parser->doc->values[index].number = number;
        break;
    case 2:
    case 3:
        if (number > (unsigned long long)(parser->len - parser->at)) {
            parser->doc->failed = 1;
            return -1;
        }
        parser->doc->values[index].kind = (major == 2) ? KR_CBOR_BSTR : KR_CBOR_TSTR;
        parser->doc->values[index].payload = parser->bytes + parser->at;
        parser->doc->values[index].payload_len = (size_t)number;
        parser->at += (size_t)number;
        break;
    case 4:
    case 5: {
        size_t items;
        /* Every item costs at least one byte, so a collection larger than what is left cannot be
         * there. The check also keeps the doubling below from wrapping. */
        if (number > (unsigned long long)(parser->len - parser->at)) {
            parser->doc->failed = 1;
            return -1;
        }
        items = (size_t)number * ((major == 5) ? 2u : 1u);
        parser->doc->values[index].kind = (major == 4) ? KR_CBOR_ARRAY : KR_CBOR_MAP;
        parser->doc->values[index].count = (size_t)number;
        parser->depth++;
        if (!kr_cbor_children(parser, index, items)) {
            parser->depth--;
            return -1;
        }
        parser->depth--;
        if (major == 5 && !kr_cbor_keys_ordered(parser->doc, index)) {
            parser->doc->failed = 1;
            return -1;
        }
        break;
    }
    case 7:
        if (number == 20 || number == 21) {
            parser->doc->values[index].kind = KR_CBOR_BOOL;
            parser->doc->values[index].number = (number == 21) ? 1u : 0u;
            break;
        }
        if (number == 22) {
            parser->doc->values[index].kind = KR_CBOR_NULL;
            break;
        }
        parser->doc->failed = 1;
        return -1;
    default:
        /* Negative integers, tags and floats do not appear in this contract's frames. */
        parser->doc->failed = 1;
        return -1;
    }
    parser->doc->values[index].encoded_len = parser->at - start;
    return index;
}

void
kr_cbor_doc_free(kr_cbor_doc *doc)
{
    free(doc->values);
    doc->values = NULL;
    doc->capacity = 0;
    doc->used = 0;
}

int
kr_cbor_parse(kr_cbor_doc *doc, const unsigned char *bytes, size_t len)
{
    kr_cbor_parser parser;
    int root;

    memset(doc, 0, sizeof(*doc));
    parser.bytes = bytes;
    parser.len = len;
    parser.at = 0;
    parser.doc = doc;
    parser.depth = 0;

    root = kr_cbor_value_parse(&parser);
    if (root < 0 || doc->failed || parser.at != len) {
        return -1;
    }
    return root;
}

int
kr_cbor_get(const kr_cbor_doc *doc, int index, const char *key)
{
    int child;
    size_t key_len;

    if (index < 0 || index >= doc->used || doc->values[index].kind != KR_CBOR_MAP) {
        return -1;
    }
    key_len = strlen(key);
    child = doc->values[index].first_child;
    while (child >= 0) {
        int value = doc->values[child].next_sibling;
        if (value < 0) {
            return -1;
        }
        if (doc->values[child].kind == KR_CBOR_TSTR &&
            doc->values[child].payload_len == key_len &&
            memcmp(doc->values[child].payload, key, key_len) == 0) {
            return value;
        }
        child = doc->values[value].next_sibling;
    }
    return -1;
}

int
kr_cbor_at(const kr_cbor_doc *doc, int index, size_t position)
{
    int child;
    size_t i;

    if (index < 0 || index >= doc->used || doc->values[index].kind != KR_CBOR_ARRAY) {
        return -1;
    }
    child = doc->values[index].first_child;
    for (i = 0; i < position && child >= 0; i++) {
        child = doc->values[child].next_sibling;
    }
    return child;
}

int
kr_cbor_variant_of(const kr_cbor_doc *doc, int index, const char **name, size_t *name_len)
{
    int key;

    if (index < 0 || index >= doc->used) {
        return -1;
    }
    if (doc->values[index].kind == KR_CBOR_TSTR) {
        /* A variant with no fields is its own name. */
        *name = (const char *)doc->values[index].payload;
        *name_len = doc->values[index].payload_len;
        return index;
    }
    if (doc->values[index].kind != KR_CBOR_MAP || doc->values[index].count != 1) {
        return -1;
    }
    key = doc->values[index].first_child;
    if (key < 0 || doc->values[key].kind != KR_CBOR_TSTR) {
        return -1;
    }
    *name = (const char *)doc->values[key].payload;
    *name_len = doc->values[key].payload_len;
    return doc->values[key].next_sibling;
}

int
kr_cbor_is_text(const kr_cbor_doc *doc, int index, const char *text)
{
    size_t len;

    if (index < 0 || index >= doc->used || doc->values[index].kind != KR_CBOR_TSTR) {
        return 0;
    }
    len = strlen(text);
    return doc->values[index].payload_len == len &&
           memcmp(doc->values[index].payload, text, len) == 0;
}

unsigned long long
kr_cbor_uint_or(const kr_cbor_doc *doc, int index, unsigned long long fallback)
{
    if (index < 0 || index >= doc->used || doc->values[index].kind != KR_CBOR_UINT) {
        return fallback;
    }
    return doc->values[index].number;
}

int
kr_cbor_bool_or(const kr_cbor_doc *doc, int index, int fallback)
{
    if (index < 0 || index >= doc->used || doc->values[index].kind != KR_CBOR_BOOL) {
        return fallback;
    }
    return doc->values[index].number ? 1 : 0;
}

int
kr_cbor_bytes_exact(const kr_cbor_doc *doc, int index, unsigned char *out, size_t len)
{
    if (index < 0 || index >= doc->used || doc->values[index].kind != KR_CBOR_BSTR ||
        doc->values[index].payload_len != len) {
        return 0;
    }
    memcpy(out, doc->values[index].payload, len);
    return 1;
}

void
kr_cbor_embed(kr_cbor_writer *writer, const kr_cbor_doc *doc, int index)
{
    if (index < 0 || index >= doc->used || doc->values[index].encoded_len == 0) {
        writer->failed = 1;
        return;
    }
    kr_cbor_raw(writer, doc->values[index].encoded, doc->values[index].encoded_len);
}
