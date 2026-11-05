/*
 * What a host writes into a terminal in answer to a question an application asked it.
 *
 * Copyright (c) Kala Powered.
 *
 * This file is added to GNU Bash's bundled Readline by the KalaReach reader patch set and is
 * distributed under the GNU General Public Licence, version 3 or later, that governs the rest of
 * the package; see shells/bash/LICENSE.
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

/*
 * Follows the bytes a reader has taken after an Escape until it can say whether an answer is among
 * them.
 *
 * `held` holds `*length` bytes, the first an Escape, in a buffer of `capacity` bytes. `next`
 * returns the next byte the terminal has already delivered, or -1 when it holds none; it must not
 * wait. A run that stops being an answer at a later Escape is followed again from that Escape,
 * since the person's Escape and an answer can arrive in one delivery, so the first Escape is the
 * person's key and the answer begins at the second.
 *
 * Returns KR_REPLY_WHOLE when an answer is complete: it begins at `held[*start]` and ends with the
 * last byte held, and `held[0..*start)` is what came before it. Returns KR_REPLY_MORE when the run
 * is the start of an answer and `next` has no more, and KR_REPLY_NOT when no answer is in it. In
 * every case `*length` is the number of bytes held, the Escape the caller passed in among them.
 */
int kr_reply_follow(unsigned char *held, size_t *length, size_t capacity, int (*next)(void),
                    size_t *start);

#endif /* KR_BRIDGE_REPLY_H */
