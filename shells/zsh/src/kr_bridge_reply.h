/*
 * What a host writes into a terminal in answer to a question an application asked it.
 *
 * Copyright (c) Kala Powered.
 *
 * This file is added to Zsh by the KalaReach reader patch set and is distributed under the Zsh
 * licence that governs the rest of the package; see shells/zsh/LICENSE.
 */

#ifndef KR_BRIDGE_REPLY_H
#define KR_BRIDGE_REPLY_H

#include <stddef.h>

/* The longest answer the classifier follows. A longer string is never taken for one. */
#define KR_REPLY_MAX 480

/* What a run of bytes that starts with an Escape is. */
enum {
    /* Not an answer, and no more bytes will make it one. */
    KR_REPLY_NOT = 0,
    /* The start of an answer: more bytes are needed to say. */
    KR_REPLY_MORE = 1,
    /* An answer, complete with its last byte. */
    KR_REPLY_WHOLE = 2
};

/*
 * Classifies `length` bytes, the first of which is the Escape that begins a control sequence or
 * string, as an answer the host's query broker writes.
 *
 * The broker builds every answer itself, in 7-bit form, so the classifier knows only those: the
 * device-attributes, status, cursor-position, mode, window, version, keyboard-protocol, setting
 * and capability reports, the colour reports and the clipboard answer. Each is recognised by its
 * shape, never by its values. A key the person presses is never one: the one report whose shape a
 * function key shares, a cursor position on the first row with a column of 2 to 16, is left to
 * the person.
 *
 * It looks at the bytes it is given and nothing else, so the caller decides what to do about a
 * run that is only the start of an answer.
 */
int kr_reply_classify(const unsigned char *bytes, size_t length);

#endif /* KR_BRIDGE_REPLY_H */
