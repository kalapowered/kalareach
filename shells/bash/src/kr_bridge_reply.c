/*
 * What a host writes into a terminal in answer to a question an application asked it.
 *
 * Copyright (c) Kala Powered.
 *
 * This file is added to GNU Bash's bundled Readline by the KalaReach reader patch set and is
 * distributed under the GNU General Public Licence, version 3 or later, that governs the rest of
 * the package; see shells/bash/LICENSE.
 *
 * A line editor reads the terminal's bytes as keys, and an answer the host wrote for an application
 * that has ended, or never read it, is bytes the editor finds at its prompt. No key the person
 * pressed starts as one of these does, so a reader that knows their shapes can leave them out of
 * the keys it decodes. The shapes are the ones the host's query broker builds, which writes every
 * answer itself and always in 7-bit form.
 */

#include <string.h>

#include "kr_bridge_reply.h"

#define KR_ESCAPE 0x1b
#define KR_BELL 0x07

/* The largest parameter value kept, which is far above anything the broker writes. */
#define KR_PARAMETER_LIMIT 100000UL

static int
kr_digit(unsigned char byte)
{
    return byte >= '0' && byte <= '9';
}

/*
 * A control sequence: Escape, a bracket, an optional private marker, numeric parameters, an
 * optional dollar sign and a final byte.
 */
static int
kr_classify_control_sequence(const unsigned char *bytes, size_t length)
{
    size_t at = 2;
    unsigned char marker = 0;
    unsigned char final;
    unsigned long value[3] = {0, 0, 0};
    size_t count = 0;
    int open = 0;
    int dollar = 0;

    if (at < length && bytes[at] >= '<' && bytes[at] <= '?') {
        marker = bytes[at++];
    }
    for (; at < length; at++) {
        if (kr_digit(bytes[at])) {
            if (!open) {
                open = 1;
                count++;
            }
            if (count <= 3 && value[count - 1] < KR_PARAMETER_LIMIT) {
                value[count - 1] = value[count - 1] * 10 + (unsigned long)(bytes[at] - '0');
            }
        } else if (bytes[at] == ';') {
            if (!open) {
                return KR_REPLY_NOT;
            }
            open = 0;
        } else {
            break;
        }
    }
    if (at == length) {
        return KR_REPLY_MORE;
    }
    if (bytes[at] == '$') {
        dollar = 1;
        if (++at == length) {
            return KR_REPLY_MORE;
        }
    }
    final = bytes[at];
    if (final < 0x40 || final > 0x7e || at + 1 != length) {
        return KR_REPLY_NOT;
    }
    if (count > 0 && !open) {
        return KR_REPLY_NOT;
    }

    if (dollar) {
        /* A mode report: the mode and its state, ANSI or DEC. */
        return final == 'y' && (marker == 0 || marker == '?') && count == 2 ? KR_REPLY_WHOLE
                                                                           : KR_REPLY_NOT;
    }
    switch (final) {
    case 'c':
        /* Device attributes, primary and secondary. */
        return (marker == '?' || marker == '>') && count >= 1 ? KR_REPLY_WHOLE : KR_REPLY_NOT;
    case 'n':
        /* The operating status, and the private status reports. */
        return (marker == 0 && count == 1) || (marker == '?' && count >= 1) ? KR_REPLY_WHOLE
                                                                           : KR_REPLY_NOT;
    case 'R':
        if (marker == 0 && count == 2) {
            /* A cursor position. On the first row, a column of 2 to 16 is also what a function
             * key with modifiers sends, and that is the person's. */
            return value[0] == 1 && value[1] >= 2 && value[1] <= 16 ? KR_REPLY_NOT
                                                                     : KR_REPLY_WHOLE;
        }
        /* The extended cursor position. */
        return marker == '?' && count == 3 ? KR_REPLY_WHOLE : KR_REPLY_NOT;
    case 't':
        /* The window and screen size reports. */
        return marker == 0 && count >= 1 ? KR_REPLY_WHOLE : KR_REPLY_NOT;
    case 'm':
        /* The key-modifier report. */
        return marker == '>' && count >= 1 ? KR_REPLY_WHOLE : KR_REPLY_NOT;
    case 'u':
        /* The keyboard-protocol report. */
        return marker == '?' && count >= 1 ? KR_REPLY_WHOLE : KR_REPLY_NOT;
    default:
        return KR_REPLY_NOT;
    }
}

/* How a device-control string that is an answer begins, after its Escape and its letter P. */
static const char *const kr_device_control_heads[] = {
    ">|",  /* the terminal's version */
    "!|",  /* tertiary device attributes */
    "1$r", /* a setting report */
    "0$r", /* a setting the profile does not report */
    "1+r", /* a capability report */
    "0+r", /* a capability the profile does not have */
};

/*
 * The length of the head of a device-control string that `bytes` begins with, 0 when they are
 * the start of one and more are needed, or -1 when no answer begins so.
 */
static int
kr_device_control_head(const unsigned char *bytes, size_t length)
{
    size_t index;
    int more = 0;

    for (index = 0; index < sizeof(kr_device_control_heads) / sizeof(kr_device_control_heads[0]);
         index++) {
        const char *head = kr_device_control_heads[index];
        size_t wanted = strlen(head);
        size_t shared = length < wanted ? length : wanted;

        if (memcmp(bytes, head, shared) != 0) {
            continue;
        }
        if (length >= wanted) {
            return (int)wanted;
        }
        more = 1;
    }
    return more ? 0 : -1;
}

/*
 * A string: a device-control string, which ends with the string terminator, or an operating-system
 * command, whose number is one or two digits and which ends with the string terminator or a bell.
 * Its body is printable text.
 */
static int
kr_classify_string(const unsigned char *bytes, size_t length, int command)
{
    size_t at = 2;

    if (command) {
        size_t digits = 0;

        while (at < length && kr_digit(bytes[at])) {
            if (++digits > 2) {
                return KR_REPLY_NOT;
            }
            at++;
        }
        if (at == length) {
            return KR_REPLY_MORE;
        }
        if (digits == 0 || bytes[at] != ';') {
            return KR_REPLY_NOT;
        }
        at++;
    } else {
        int head = kr_device_control_head(bytes + at, length - at);

        if (head < 0) {
            return KR_REPLY_NOT;
        }
        if (head == 0) {
            return KR_REPLY_MORE;
        }
        at += (size_t)head;
    }
    for (; at < length; at++) {
        if (bytes[at] == KR_ESCAPE) {
            if (at + 1 == length) {
                return KR_REPLY_MORE;
            }
            return bytes[at + 1] == '\\' && at + 2 == length ? KR_REPLY_WHOLE : KR_REPLY_NOT;
        }
        if (command && bytes[at] == KR_BELL) {
            return at + 1 == length ? KR_REPLY_WHOLE : KR_REPLY_NOT;
        }
        if (bytes[at] < 0x20 || bytes[at] > 0x7e) {
            return KR_REPLY_NOT;
        }
    }
    return KR_REPLY_MORE;
}

int
kr_reply_classify(const unsigned char *bytes, size_t length)
{
    if (length == 0 || bytes[0] != KR_ESCAPE || length > KR_REPLY_MAX) {
        return KR_REPLY_NOT;
    }
    if (length == 1) {
        return KR_REPLY_MORE;
    }
    switch (bytes[1]) {
    case '[':
        return kr_classify_control_sequence(bytes, length);
    case 'P':
        return kr_classify_string(bytes, length, 0);
    case ']':
        return kr_classify_string(bytes, length, 1);
    default:
        return KR_REPLY_NOT;
    }
}
