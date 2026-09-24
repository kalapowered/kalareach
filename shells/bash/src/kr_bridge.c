/*
 * The KalaReach root-editor bridge: the endpoint, the frames and every decision the contract puts
 * on the reader's side.
 *
 * Copyright (c) Kala Powered.
 *
 * This file is added to GNU Bash's bundled Readline by the KalaReach reader patch set and is
 * distributed under the GNU General Public Licence, version 3 or later, that governs the rest of
 * the package; see shells/bash/LICENSE.
 *
 * Nothing here blocks the reader. The endpoint is non-blocking and buffered in both directions;
 * `kr_bridge_service` reads what has arrived and answers it, and the patched reader calls it at a
 * key-sequence boundary and while it waits for a key. The one bounded wait is the handshake, which
 * happens once, before the first primary reader, where there is no reader to hold up.
 *
 * The decisions this file takes are the contract's, reproduced exactly:
 * `decide_launch` for the mailbox, `detach_eligibility` and `BridgeFenceView::decide` for the
 * end-of-file gesture, and `decide_activation` for whether a starting shell attempts anything at
 * all.
 */

#include "kr_bridge.h"
#include "kr_bridge_cbor.h"
#include "kr_bridge_crypto.h"
#include "kr_bridge_identity.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#ifdef __APPLE__
#include <libproc.h>
#include <sys/proc_info.h>
#endif

#define KR_ENDPOINT_VARIABLE "KR_SHELL_BRIDGE"
#define KR_SECRET_VARIABLE "KR_SHELL_BRIDGE_SECRET"
#define KR_SESSION_VARIABLE "KR_SESSION"
/* Where the integration writes what it did, when the session asked for that. */
#define KR_TRACE_VARIABLE "KR_SHELL_BRIDGE_TRACE"
/* Detaches submitted and not answered yet. A refusal belongs to a detach only if it answers one. */
#define KR_DETACH_IDS_MAX 8
/* The line capability is a UUID in its text form; anything longer is not one. */
#define KR_TOKEN_MAX 128

#define KR_UUID_LEN 16
#define KR_SECRET_MAX 64
#define KR_HINT_MAX 256
#define KR_HANDSHAKE_WAIT_MS 2000
#define KR_REVOKED_MAX 16
/* How many separate reads' arrival times are remembered for the bytes still buffered. */
#define KR_MARKS_MAX 256
/* What may wait to go out before the endpoint is treated as gone. */
#define KR_OUT_MAX (4u * 1024u * 1024u)
#define KR_FRAME_HEADER 4

#ifdef MSG_NOSIGNAL
#define KR_SEND_FLAGS MSG_NOSIGNAL
#else
#define KR_SEND_FLAGS 0
#endif

/* The bridge's whole state. One root shell, one endpoint, one reader. */
static struct {
    int fd;
    int registered;
    /*
     * True from the moment the handshake is accepted, and never cleared.
     *
     * Losing the transport does not turn a managed root shell back into an ordinary one: a
     * session that cannot prove whose gesture it was still consumes an eligible one with the
     * hint rather than turning it into a native empty-prompt end of file.
     */
    int managed;
    int lost;

    unsigned char session[KR_UUID_LEN];
    unsigned char secret[KR_SECRET_MAX];
    size_t secret_len;
    char endpoint[256];

    unsigned long long self_pid;
    unsigned long long self_start;

    unsigned char *in;
    size_t in_len;
    size_t in_capacity;
    unsigned char *out;
    size_t out_len;
    size_t out_capacity;
    unsigned char *frame;
    size_t frame_capacity;

    /* The fence the worker last published, held until the worker invalidates it. */
    int fence_live;
    unsigned char fence_id[KR_UUID_LEN];
    unsigned long fence_prompt;
    unsigned long fence_reader;
    unsigned char fence_attachment[KR_UUID_LEN];
    unsigned long long fence_epoch;

    /* The gesture in force, and one the line discipline has changed to. */
    int gesture_disabled;
    unsigned long gesture_byte;
    int pending_gesture;
    int pending_gesture_disabled;
    unsigned long pending_gesture_byte;
    unsigned long pending_gesture_at;

    int hinted;
    unsigned long hinted_prompt;
    char hint[KR_HINT_MAX];

    /* A launch this bridge installed and has not yet accepted. */
    int launch_pending;
    unsigned char launch_transaction[KR_UUID_LEN];

    /* Transactions the worker has revoked. A revocation the worker sent before the reader's own
     * step is one that step has to see, whichever read took it off the endpoint. */
    unsigned char revoked[KR_REVOKED_MAX][KR_UUID_LEN];
    size_t revoked_count;
    size_t revoked_next;

    /* Set while a cancellation this bridge asked for has not yet unwound the reader. Nothing else
     * is read or answered until it has, so a fence that follows sees what the reader has. */
    int cancel_in_flight;

    unsigned long long event_counter;
    /*
     * When each stretch of buffered input came off the endpoint, on this reader's own clock.
     *
     * A frame that waited in the buffer for its remaining bytes keeps its own arrival time, and a
     * request that arrived with those bytes is not charged for the wait.
     */
    struct {
        size_t ends_at;
        unsigned long long at_ms;
    } marks[KR_MARKS_MAX];
    size_t mark_count;
    unsigned long long frame_at_ms;

    /* The detaches this bridge submitted that the worker has not answered, oldest first. */
    unsigned long long detach_ids[KR_DETACH_IDS_MAX];
    size_t detach_count;

    /*
     * The event whose answer this bridge stopped waiting for, or 0.
     *
     * The worker answers events in the order they arrive, so an answer to this one or to any later
     * one says it has caught up. Until then nothing waits for it again.
     */
    unsigned long long owed;

    /* The acceptance last reported, and the line capability its answer carried. */
    unsigned long long accept_id;
    int accept_answered;
    int token_present;
    char token[KR_TOKEN_MAX];

    /* The resolve last asked, and the encoded answer once it has come. */
    unsigned long long resolve_id;
    int resolve_answered;
    unsigned char *resolve_answer;
    size_t resolve_answer_len;

    /* The command block of the line that is running. */
    int block_open;
    unsigned long block_prompt;
    unsigned long long block_started_ms;
    unsigned long long block_started_at;
    char *block_command;
    size_t block_command_len;
    char *block_cwd;
    size_t block_cwd_len;
    unsigned long block_cwd_revision;

    /* Where diagnostics go, when the session asked for them. */
    char trace[512];
} kr = {
    /* Not connected. Static storage starts at zero, which is a descriptor. */
    -1
};

/* ---- identifiers, clocks and process identity ----------------------------------------------- */

static unsigned long long
kr_now_ms(void)
{
    struct timespec now;
#ifdef CLOCK_MONOTONIC
    if (clock_gettime(CLOCK_MONOTONIC, &now) == 0) {
        return (unsigned long long)now.tv_sec * 1000ull + (unsigned long long)now.tv_nsec / 1000000ull;
    }
#endif
    return 0;
}

/* Milliseconds since the epoch, which is what a command block reports its start in. */
static unsigned long long
kr_wall_ms(void)
{
    struct timespec now;

    if (clock_gettime(CLOCK_REALTIME, &now) == 0) {
        return (unsigned long long)now.tv_sec * 1000ull + (unsigned long long)now.tv_nsec / 1000000ull;
    }
    return 0;
}

/*
 * One line of diagnostics, when the session asked for them.
 *
 * The integration says what it did and why when something asks it to, and nothing at all
 * otherwise: a managed root shell writes no file of its own unless it was told where to.
 */
static void
kr_trace(const char *format, ...)
{
    char line[1024];
    va_list arguments;
    struct stat file;
    int length;
    int fd;

    if (kr.trace[0] == '\0') {
        return;
    }
    va_start(arguments, format);
    length = vsnprintf(line, sizeof(line) - 1, format, arguments);
    va_end(arguments);
    if (length < 0) {
        return;
    }
    if ((size_t)length > sizeof(line) - 2) {
        length = (int)(sizeof(line) - 2);
    }
    line[length++] = '\n';
    /* A path that is not a plain file is written to never: opening a pipe nobody reads, or a
     * device, would hold the shell up, and diagnostics must never do that. */
    fd = open(kr.trace, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC | O_NONBLOCK, 0600);
    if (fd < 0) {
        return;
    }
    if (fstat(fd, &file) == 0 && S_ISREG(file.st_mode) && write(fd, line, (size_t)length) < 0) {
        /* Diagnostics that cannot be written are not a reason to do anything differently. */
    }
    close(fd);
}

/* Whether `len` bytes at `text` are well-formed UTF-8, which is all a text string on the wire may
 * hold. */
static int
kr_utf8_valid(const unsigned char *text, size_t len)
{
    size_t at = 0;

    while (at < len) {
        unsigned char lead = text[at];
        size_t follow;
        unsigned long value;
        size_t i;

        if (lead < 0x80) {
            at++;
            continue;
        }
        if (lead >= 0xc2 && lead <= 0xdf) {
            follow = 1;
            value = lead & 0x1fu;
        } else if (lead >= 0xe0 && lead <= 0xef) {
            follow = 2;
            value = lead & 0x0fu;
        } else if (lead >= 0xf0 && lead <= 0xf4) {
            follow = 3;
            value = lead & 0x07u;
        } else {
            return 0;
        }
        if (len - at <= follow) {
            return 0;
        }
        for (i = 1; i <= follow; i++) {
            if ((text[at + i] & 0xc0u) != 0x80u) {
                return 0;
            }
            value = (value << 6) | (text[at + i] & 0x3fu);
        }
        /* The shortest form only, no surrogates and nothing past the last code point. */
        if ((follow == 2 && value < 0x800) || (follow == 3 && value < 0x10000) ||
            (value >= 0xd800 && value <= 0xdfff) || value > 0x10ffff) {
            return 0;
        }
        at += follow + 1;
    }
    return 1;
}

/* Whether a descriptor of this process is one end of a pipe. */
static int
kr_is_pipe(int fd)
{
    struct stat file;

    return fstat(fd, &file) == 0 && S_ISFIFO(file.st_mode);
}

/* Whether a C string is well-formed UTF-8. */
static int
kr_utf8_text(const char *text)
{
    return text != NULL && kr_utf8_valid((const unsigned char *)text, strlen(text));
}

/*
 * A copy of `len` bytes as UTF-8 a reader can display, in memory the caller frees.
 *
 * A command line and a directory are the person's bytes, and the terminal's encoding need not be
 * UTF-8. What a block reports is for a person to read, so a byte that is not part of a well-formed
 * sequence is shown as U+FFFD rather than dropping the block.
 */
static char *
kr_utf8_lossy(const char *text, size_t len, size_t *out_len)
{
    /* Each byte becomes at most the three bytes of U+FFFD. */
    char *copy = (char *)malloc(len * 3 + 1);
    size_t at = 0;
    size_t used = 0;

    if (copy == NULL) {
        return NULL;
    }
    while (at < len) {
        size_t take = 1;
        unsigned char lead = (unsigned char)text[at];

        if (lead >= 0x80) {
            take = (lead >= 0xf0) ? 4 : (lead >= 0xe0) ? 3 : 2;
            if (take > len - at ||
                !kr_utf8_valid((const unsigned char *)text + at, take)) {
                copy[used++] = (char)0xef;
                copy[used++] = (char)0xbf;
                copy[used++] = (char)0xbd;
                at++;
                continue;
            }
        }
        memcpy(copy + used, text + at, take);
        used += take;
        at += take;
    }
    copy[used] = '\0';
    *out_len = used;
    return copy;
}

static int
kr_parse_uuid(const char *text, unsigned char out[KR_UUID_LEN])
{
    int written = 0;
    int high = -1;
    const char *cursor;

    for (cursor = text; *cursor != '\0'; cursor++) {
        int value;
        if (*cursor == '-') {
            continue;
        }
        if (*cursor >= '0' && *cursor <= '9') {
            value = *cursor - '0';
        } else if (*cursor >= 'a' && *cursor <= 'f') {
            value = *cursor - 'a' + 10;
        } else if (*cursor >= 'A' && *cursor <= 'F') {
            value = *cursor - 'A' + 10;
        } else {
            return 0;
        }
        if (high < 0) {
            high = value;
        } else {
            if (written >= KR_UUID_LEN) {
                return 0;
            }
            out[written++] = (unsigned char)((high << 4) | value);
            high = -1;
        }
    }
    return high < 0 && written == KR_UUID_LEN;
}

/*
 * The kernel's record of when this process started, in the source the host reads it from.
 *
 * The worker compares the connection's own process against the root shell it launched, so this has
 * to be the same number the host reads for the same process.
 */
static void
kr_process_identity(void)
{
    kr.self_pid = (unsigned long long)getpid();
    kr.self_start = 0;
#ifdef __APPLE__
    {
        struct proc_bsdinfo info;
        int size = proc_pidinfo((int)getpid(), PROC_PIDTBSDINFO, 0, &info, PROC_PIDTBSDINFO_SIZE);
        if (size == PROC_PIDTBSDINFO_SIZE) {
            kr.self_start = (unsigned long long)info.pbi_start_tvsec * 1000000ull +
                            (unsigned long long)info.pbi_start_tvusec;
        }
    }
#else
    {
        /* /proc/self/stat field 22, counted after the comm field, which may itself hold spaces. */
        char buffer[1024];
        FILE *stat = fopen("/proc/self/stat", "r");
        if (stat != NULL) {
            size_t read_bytes = fread(buffer, 1, sizeof(buffer) - 1, stat);
            char *cursor;
            buffer[read_bytes] = '\0';
            fclose(stat);
            cursor = strrchr(buffer, ')');
            if (cursor != NULL) {
                int field = 2;
                cursor++;
                while (*cursor != '\0') {
                    while (*cursor == ' ') {
                        cursor++;
                    }
                    if (*cursor == '\0') {
                        break;
                    }
                    field++;
                    if (field == 22) {
                        kr.self_start = strtoull(cursor, NULL, 10);
                        break;
                    }
                    while (*cursor != '\0' && *cursor != ' ') {
                        cursor++;
                    }
                }
            }
        }
    }
#endif
}

static const char *
kr_process_source(void)
{
#ifdef __APPLE__
    return "macos_proc_bsd_info";
#else
    return "linux_proc_stat";
#endif
}

/* ---- the endpoint ---------------------------------------------------------------------------- */

static void
kr_disconnect(int loss)
{
    if (kr.fd >= 0) {
        close(kr.fd);
        kr.fd = -1;
    }
    if (kr.registered && !kr.lost) {
        kr.lost = loss;
    }
    kr.registered = 0;
    kr.fence_live = 0;
    kr.launch_pending = 0;
    /* Nothing more will be answered, so nothing is owed and nothing is waited for. */
    kr.owed = 0;
    kr.detach_count = 0;
}

static int
kr_flush(void)
{
    while (kr.out_len > 0 && kr.fd >= 0) {
        /* A shell must not take a signal because the worker went away mid-write. Where the
         * platform has no send flag for it, the socket option set at connect covers it. */
        ssize_t written = send(kr.fd, kr.out, kr.out_len, KR_SEND_FLAGS);
        if (written > 0) {
            memmove(kr.out, kr.out + written, kr.out_len - (size_t)written);
            kr.out_len -= (size_t)written;
            continue;
        }
        if (written < 0 && (errno == EINTR)) {
            continue;
        }
        if (written < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            return 1;
        }
        kr_disconnect(KR_LOSS_BRIDGE_DISCONNECTED);
        return 0;
    }
    return 1;
}

/* Queues one complete frame: a four-byte big-endian length and the canonical object. */
static void
kr_send(kr_cbor_writer *writer)
{
    unsigned char header[KR_FRAME_HEADER];
    size_t needed;
    unsigned char *grown;

    if (writer->failed || kr.fd < 0) {
        kr_cbor_writer_free(writer);
        return;
    }
    header[0] = (unsigned char)((writer->len >> 24) & 0xffu);
    header[1] = (unsigned char)((writer->len >> 16) & 0xffu);
    header[2] = (unsigned char)((writer->len >> 8) & 0xffu);
    header[3] = (unsigned char)(writer->len & 0xffu);

    needed = kr.out_len + KR_FRAME_HEADER + writer->len;
    if (needed > KR_OUT_MAX) {
        /* A peer that asks and never reads cannot make this shell grow without limit. */
        kr_cbor_writer_free(writer);
        kr_disconnect(KR_LOSS_BRIDGE_DISCONNECTED);
        return;
    }
    if (needed > kr.out_capacity) {
        size_t wanted = kr.out_capacity ? kr.out_capacity : 4096;
        while (wanted < needed) {
            wanted *= 2;
        }
        grown = (unsigned char *)realloc(kr.out, wanted);
        if (grown == NULL) {
            kr_cbor_writer_free(writer);
            kr_disconnect(KR_LOSS_BRIDGE_DISCONNECTED);
            return;
        }
        kr.out = grown;
        kr.out_capacity = wanted;
    }
    memcpy(kr.out + kr.out_len, header, KR_FRAME_HEADER);
    memcpy(kr.out + kr.out_len + KR_FRAME_HEADER, writer->bytes, writer->len);
    kr.out_len = needed;
    kr_cbor_writer_free(writer);
    kr_flush();
}

/* Reads whatever has arrived. Returns 0 when the connection has gone. */
static int
kr_fill(void)
{
    for (;;) {
        ssize_t taken;
        if (kr.in_len + 4096 > kr.in_capacity) {
            size_t wanted = kr.in_capacity ? kr.in_capacity * 2 : 8192;
            unsigned char *grown;
            while (wanted < kr.in_len + 4096) {
                wanted *= 2;
            }
            if (wanted > KR_CBOR_MAX_FRAME * 2) {
                kr_disconnect(KR_LOSS_BRIDGE_DISCONNECTED);
                return 0;
            }
            grown = (unsigned char *)realloc(kr.in, wanted);
            if (grown == NULL) {
                kr_disconnect(KR_LOSS_BRIDGE_DISCONNECTED);
                return 0;
            }
            kr.in = grown;
            kr.in_capacity = wanted;
        }
        taken = read(kr.fd, kr.in + kr.in_len, kr.in_capacity - kr.in_len);
        if (taken > 0) {
            kr.in_len += (size_t)taken;
            /* Mark where this read reached, with the time it reached it. */
            if (kr.mark_count < KR_MARKS_MAX) {
                kr.marks[kr.mark_count].ends_at = kr.in_len;
                kr.marks[kr.mark_count].at_ms = kr_now_ms();
                kr.mark_count++;
            } else {
                /* With no room for another mark these bytes join the stretch before them, which
                 * came off the endpoint earlier. Every byte buffered still has an arrival time,
                 * and a frame among these is charged for more waiting than it did rather than
                 * less, so a budget can only run out sooner than it should. */
                kr.marks[kr.mark_count - 1].ends_at = kr.in_len;
            }
            continue;
        }
        if (taken == 0) {
            kr_disconnect(KR_LOSS_BRIDGE_DISCONNECTED);
            return 0;
        }
        if (errno == EINTR) {
            continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 1;
        }
        kr_disconnect(KR_LOSS_BRIDGE_DISCONNECTED);
        return 0;
    }
}

/* Takes one complete frame out of the input buffer. Returns its length, or 0. */
static size_t
kr_take_frame(const unsigned char **frame)
{
    unsigned long length;

    if (kr.in_len < KR_FRAME_HEADER) {
        return 0;
    }
    length = ((unsigned long)kr.in[0] << 24) | ((unsigned long)kr.in[1] << 16) |
             ((unsigned long)kr.in[2] << 8) | (unsigned long)kr.in[3];
    if (length == 0 || length > KR_CBOR_MAX_FRAME) {
        kr_disconnect(KR_LOSS_BRIDGE_DISCONNECTED);
        return 0;
    }
    if (kr.in_len < KR_FRAME_HEADER + length) {
        return 0;
    }
    *frame = kr.in + KR_FRAME_HEADER;
    return (size_t)length;
}

/* The time the read that completed a frame of `length` bytes happened. */
static unsigned long long
kr_frame_arrival(size_t length)
{
    size_t total = KR_FRAME_HEADER + length;
    size_t i;

    for (i = 0; i < kr.mark_count; i++) {
        if (kr.marks[i].ends_at >= total) {
            return kr.marks[i].at_ms;
        }
    }
    /* Bytes reach this buffer only by being read, so a complete frame always ends inside a mark.
     * If one ever does not, the oldest time anything here came off the endpoint is the answer that
     * cannot make a budget look longer than it is. */
    if (kr.mark_count > 0) {
        return kr.marks[0].at_ms;
    }
    return kr_now_ms();
}

/*
 * Takes the frame of `length` bytes that starts `at` bytes into the input buffer out of it.
 *
 * The frames around it keep their order and their arrival times: a mark past the frame moves down
 * with its bytes, and one that ended inside it now ends where the frame began, because the bytes
 * before that point arrived when it says they did.
 */
static void
kr_remove_frame_at(size_t at, size_t length)
{
    size_t total = KR_FRAME_HEADER + length;
    size_t kept = 0;
    size_t i;

    memmove(kr.in + at, kr.in + at + total, kr.in_len - at - total);
    kr.in_len -= total;
    for (i = 0; i < kr.mark_count; i++) {
        size_t ends = kr.marks[i].ends_at;

        if (ends > at + total) {
            ends -= total;
        } else if (ends > at) {
            ends = at;
        }
        if (ends == 0 || (kept > 0 && kr.marks[kept - 1].ends_at >= ends)) {
            continue;
        }
        kr.marks[kept].ends_at = ends;
        kr.marks[kept].at_ms = kr.marks[i].at_ms;
        kept++;
    }
    kr.mark_count = kept;
}

static void
kr_drop_frame(size_t length)
{
    kr_remove_frame_at(0, length);
}

/* ---- writing the contract's own shapes ------------------------------------------------------- */

static void
kr_write_process(kr_cbor_writer *writer, unsigned long long pid, unsigned long long start)
{
    kr_cbor_map(writer, 3);
    kr_cbor_key(writer, "pid");
    kr_cbor_uint(writer, pid);
    kr_cbor_key(writer, "source");
    kr_cbor_tstr(writer, kr_process_source());
    kr_cbor_key(writer, "start_value");
    kr_cbor_uint(writer, start);
    kr_cbor_map_end(writer);
}

static const char *
kr_context_name(int context)
{
    switch (context) {
    case KR_CONTEXT_CONTINUATION:
        return "continuation";
    case KR_CONTEXT_READ_BUILTIN:
        return "read_builtin";
    default:
        return "primary";
    }
}

static const char *
kr_keymap_name(int keymap)
{
    switch (keymap) {
    case KR_KEYMAP_VI_INSERT:
        return "vi_insert";
    case KR_KEYMAP_VI_COMMAND:
        return "vi_command";
    case KR_KEYMAP_CUSTOM:
        return "custom";
    default:
        return "emacs";
    }
}

static void
kr_write_editor(kr_cbor_writer *writer, const kr_reader_state *state)
{
    kr_cbor_map(writer, 4);
    kr_cbor_key(writer, "keymap");
    kr_cbor_tstr(writer, kr_keymap_name(state->keymap));
    kr_cbor_key(writer, "pending");
    kr_cbor_map(writer, 7);
    kr_cbor_key(writer, "paste");
    kr_cbor_bool(writer, state->pending_paste);
    kr_cbor_key(writer, "search");
    kr_cbor_bool(writer, state->pending_search);
    kr_cbor_key(writer, "vi_motion");
    kr_cbor_bool(writer, state->pending_vi_motion);
    kr_cbor_key(writer, "macro_input");
    kr_cbor_bool(writer, state->pending_macro_input);
    kr_cbor_key(writer, "numeric_argument");
    kr_cbor_bool(writer, state->pending_numeric_argument);
    kr_cbor_key(writer, "quoted_insertion");
    kr_cbor_bool(writer, state->pending_quoted_insertion);
    kr_cbor_key(writer, "multikey_sequence");
    kr_cbor_bool(writer, state->pending_multikey_sequence);
    kr_cbor_map_end(writer);
    kr_cbor_key(writer, "buffer_empty");
    kr_cbor_bool(writer, state->buffer_empty);
    kr_cbor_key(writer, "buffer_revision");
    kr_cbor_uint(writer, state->buffer_revision);
    kr_cbor_map_end(writer);
}

static void
kr_write_snapshot(kr_cbor_writer *writer, const kr_reader_state *state)
{
    kr_cbor_map(writer, 3);
    kr_cbor_key(writer, "keys");
    kr_cbor_bstr(writer, state->keys, state->keys_len);
    kr_cbor_key(writer, "queued_keys");
    kr_cbor_uint(writer, state->queued_keys);
    kr_cbor_key(writer, "pending_bytes");
    kr_cbor_uint(writer, state->pending_bytes);
    kr_cbor_map_end(writer);
}

static void
kr_write_queues(kr_cbor_writer *writer, const kr_reader_state *state)
{
    kr_cbor_map(writer, 3);
    kr_cbor_key(writer, "macro_input_drained");
    kr_cbor_bool(writer, state->macro_input_drained);
    kr_cbor_key(writer, "partial_key_drained");
    kr_cbor_bool(writer, state->partial_key_drained);
    kr_cbor_key(writer, "tty_typeahead_drained");
    kr_cbor_bool(writer, state->tty_typeahead_drained);
    kr_cbor_map_end(writer);
}

static void
kr_write_gesture(kr_cbor_writer *writer, int disabled, unsigned long byte)
{
    if (disabled) {
        kr_cbor_tstr(writer, "disabled");
        return;
    }
    kr_cbor_variant(writer, "terminal_eof");
    kr_cbor_map(writer, 1);
    kr_cbor_key(writer, "byte");
    kr_cbor_uint(writer, byte);
    kr_cbor_map_end(writer);
    kr_cbor_variant_end(writer);
}

/* Opens `{"event": {"id": <id>, "event": {"<name>": ` and leaves the payload to the caller.
 *
 * Each side allocates the identifiers it sends, so an answer belongs to its question rather than
 * to whatever is in flight. Returns the identifier, which is what the answer will carry. */
static unsigned long long
kr_open_event(kr_cbor_writer *writer, const char *name)
{
    kr_cbor_writer_init(writer);
    kr_cbor_variant(writer, "event");
    kr_cbor_map(writer, 2);
    kr_cbor_key(writer, "id");
    kr_cbor_uint(writer, ++kr.event_counter);
    kr_cbor_key(writer, "event");
    kr_cbor_variant(writer, name);
    return kr.event_counter;
}

static void
kr_close_event(kr_cbor_writer *writer)
{
    kr_cbor_variant_end(writer);
    kr_cbor_map_end(writer);
    kr_cbor_variant_end(writer);
    kr_send(writer);
}

static void
kr_open_answer(kr_cbor_writer *writer, unsigned long long id, const char *name)
{
    kr_cbor_writer_init(writer);
    kr_cbor_variant(writer, "answer");
    kr_cbor_map(writer, 2);
    kr_cbor_key(writer, "id");
    kr_cbor_uint(writer, id);
    kr_cbor_key(writer, "answer");
    kr_cbor_variant(writer, name);
}

/* ---- the handshake --------------------------------------------------------------------------- */

static void
kr_write_hello(kr_cbor_writer *writer, const unsigned char proof[KR_SHA256_LEN])
{
    size_t i;

    kr_cbor_writer_init(writer);
    kr_cbor_variant(writer, "hello");
    kr_cbor_map(writer, 6);

    kr_cbor_key(writer, "abi");
    kr_cbor_map(writer, 5);
    kr_cbor_key(writer, "mailbox");
    kr_cbor_tstr(writer, KR_MAILBOX_MECHANISM);
    kr_cbor_key(writer, "pre_eof");
    kr_cbor_tstr(writer, KR_PRE_EOF_MECHANISM);
    kr_cbor_key(writer, "fence_proof");
    kr_cbor_tstr(writer, "atomic_reader_state");
    kr_cbor_key(writer, "cancellation");
    kr_cbor_tstr(writer, "non_destructive_key_wait");
    kr_cbor_key(writer, "launch_delivery");
    kr_cbor_tstr(writer, "reader_mailbox");
    kr_cbor_map_end(writer);

    kr_cbor_key(writer, "proof");
    kr_cbor_bstr(writer, proof, KR_SHA256_LEN);

    kr_cbor_key(writer, "shell");
    kr_cbor_map(writer, 7);
    kr_cbor_key(writer, "kind");
    kr_cbor_tstr(writer, KR_SHELL_KIND);
    kr_cbor_key(writer, "modules");
    kr_cbor_array(writer, KR_MODULE_COUNT);
    for (i = 0; i < KR_MODULE_COUNT; i++) {
        kr_cbor_map(writer, 3);
        kr_cbor_key(writer, "name");
        kr_cbor_tstr(writer, kr_modules[i].name);
        kr_cbor_key(writer, "editor_abi");
        kr_cbor_tstr(writer, kr_modules[i].editor_abi);
        kr_cbor_key(writer, "search_path");
        kr_cbor_tstr(writer, kr_modules[i].search_path);
        kr_cbor_map_end(writer);
    }
    kr_cbor_key(writer, "patches");
    kr_cbor_array(writer, KR_PATCH_COUNT);
    for (i = 0; i < KR_PATCH_COUNT; i++) {
        kr_cbor_map(writer, 3);
        kr_cbor_key(writer, "name");
        kr_cbor_tstr(writer, kr_patches[i].name);
        kr_cbor_key(writer, "revision");
        kr_cbor_tstr(writer, kr_patches[i].revision);
        kr_cbor_key(writer, "upstream_revision");
        kr_cbor_tstr(writer, kr_patches[i].upstream_revision);
        kr_cbor_map_end(writer);
    }
    kr_cbor_key(writer, "editor_abi");
    kr_cbor_tstr(writer, KR_EDITOR_ABI);
    kr_cbor_key(writer, "executable");
    kr_cbor_tstr(writer, KR_SHELL_EXECUTABLE);
    kr_cbor_key(writer, "upstream_version");
    kr_cbor_tstr(writer, KR_UPSTREAM_VERSION);
    kr_cbor_key(writer, "integration_version");
    kr_cbor_tstr(writer, KR_INTEGRATION_VERSION);
    kr_cbor_map_end(writer);

    kr_cbor_key(writer, "protocol");
    kr_cbor_tstr(writer, KR_BRIDGE_PROTOCOL);
    kr_cbor_key(writer, "session_id");
    kr_cbor_bstr(writer, kr.session, KR_UUID_LEN);
    kr_cbor_key(writer, "shell_process");
    kr_write_process(writer, kr.self_pid, kr.self_start);

    kr_cbor_map_end(writer);
    kr_cbor_variant_end(writer);
}

/* CBOR(["kr-shell-bridge/1", session_id, endpoint, shell_process, integration_version]) */
static void
kr_write_transcript(kr_cbor_writer *writer)
{
    kr_cbor_writer_init(writer);
    kr_cbor_array(writer, 5);
    kr_cbor_tstr(writer, KR_BRIDGE_PROTOCOL);
    kr_cbor_bstr(writer, kr.session, KR_UUID_LEN);
    kr_cbor_tstr(writer, kr.endpoint);
    kr_write_process(writer, kr.self_pid, kr.self_start);
    kr_cbor_tstr(writer, KR_INTEGRATION_VERSION);
}

static void
kr_take_accept(const kr_cbor_doc *doc, int accepted)
{
    int gesture = kr_cbor_get(doc, accepted, "gesture");
    int hint = kr_cbor_get(doc, accepted, "hint");
    const char *name;
    size_t name_len;
    int payload;

    kr.gesture_disabled = 0;
    kr.gesture_byte = 4;
    payload = kr_cbor_variant_of(doc, gesture, &name, &name_len);
    if (payload >= 0) {
        if (name_len == 8 && memcmp(name, "disabled", 8) == 0) {
            kr.gesture_disabled = 1;
        } else if (name_len == 12 && memcmp(name, "terminal_eof", 12) == 0) {
            kr.gesture_byte =
                (unsigned long)kr_cbor_uint_or(doc, kr_cbor_get(doc, payload, "byte"), 4);
        }
    }
    if (hint >= 0 && doc->values[hint].kind == KR_CBOR_TSTR &&
        doc->values[hint].payload_len < KR_HINT_MAX) {
        memcpy(kr.hint, doc->values[hint].payload, doc->values[hint].payload_len);
        kr.hint[doc->values[hint].payload_len] = '\0';
    }
}

/* Waits for the one frame the shell cannot start without. */
static int
kr_await_handshake(void)
{
    unsigned long long deadline = kr_now_ms() + KR_HANDSHAKE_WAIT_MS;

    for (;;) {
        const unsigned char *frame;
        size_t length;
        struct pollfd waiting;
        long long remaining;

        length = kr_take_frame(&frame);
        if (length > 0) {
            kr_cbor_doc doc;
            int root = kr_cbor_parse(&doc, frame, length);
            const char *name;
            size_t name_len;
            int outcome = kr_cbor_variant_of(&doc, root, &name, &name_len);
            int accepted;
            int result = 0;

            if (outcome >= 0 && name_len == 9 && memcmp(name, "handshake", 9) == 0) {
                const char *verdict;
                size_t verdict_len;
                accepted = kr_cbor_variant_of(&doc, outcome, &verdict, &verdict_len);
                if (accepted >= 0 && verdict_len == 8 && memcmp(verdict, "accepted", 8) == 0) {
                    kr_take_accept(&doc, accepted);
                    result = 1;
                }
            }
            kr_cbor_doc_free(&doc);
            kr_drop_frame(length);
            return result;
        }
        if (kr.fd < 0) {
            return 0;
        }
        remaining = (long long)deadline - (long long)kr_now_ms();
        if (remaining <= 0) {
            return 0;
        }
        waiting.fd = kr.fd;
        waiting.events = (short)(POLLIN | (kr.out_len > 0 ? POLLOUT : 0));
        waiting.revents = 0;
        if (poll(&waiting, 1, (int)remaining) < 0) {
            if (errno == EINTR) {
                continue;
            }
            return 0;
        }
        if (kr.out_len > 0 && !kr_flush()) {
            return 0;
        }
        if (!kr_fill()) {
            return 0;
        }
    }
}

static int
kr_connect(const char *path)
{
    struct sockaddr_un address;
    int fd;
    int flags;

    if (strlen(path) >= sizeof(address.sun_path)) {
        return -1;
    }
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    strncpy(address.sun_path, path, sizeof(address.sun_path) - 1);
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        close(fd);
        return -1;
    }
    flags = fcntl(fd, F_GETFD, 0);
    if (flags >= 0) {
        fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
    }
#ifdef SO_NOSIGPIPE
    {
        int on = 1;
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(on));
    }
#endif
    flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) {
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }
    return fd;
}

void
kr_bridge_activate(void)
{
    const char *endpoint = getenv(KR_ENDPOINT_VARIABLE);
    const char *secret = getenv(KR_SECRET_VARIABLE);
    const char *session = getenv(KR_SESSION_VARIABLE);
    kr_cbor_writer transcript;
    kr_cbor_writer hello;
    unsigned char proof[KR_SHA256_LEN];

    if (kr.registered || kr.fd >= 0) {
        return;
    }
    /* `decide_activation`: without both bootstrap values there is nothing to attempt, which is
     * what keeps the guarded startup entry inert in every child shell. */
    if (endpoint == NULL || endpoint[0] == '\0' || secret == NULL || secret[0] == '\0') {
        return;
    }
    if (session == NULL || !kr_parse_uuid(session, kr.session)) {
        return;
    }
    if (strlen(endpoint) >= sizeof(kr.endpoint)) {
        return;
    }
    if (!kr_base64url_decode(secret, kr.secret, sizeof(kr.secret), &kr.secret_len)) {
        return;
    }
    strcpy(kr.endpoint, endpoint);
    strcpy(kr.hint, "Use kr detach --attachment <id> to detach.");
    kr.gesture_byte = 4;
    {
        /* Diagnostics go only to an absolute path the session named. */
        const char *trace = getenv(KR_TRACE_VARIABLE);
        if (trace != NULL && trace[0] == '/' && strlen(trace) < sizeof(kr.trace)) {
            strcpy(kr.trace, trace);
        }
    }

    kr_process_identity();

    kr.fd = kr_connect(kr.endpoint);
    if (kr.fd < 0) {
        memset(kr.secret, 0, sizeof(kr.secret));
        kr.secret_len = 0;
        return;
    }

    kr_write_transcript(&transcript);
    if (transcript.failed) {
        kr_cbor_writer_free(&transcript);
        kr_disconnect(0);
        return;
    }
    kr_hmac_sha256(kr.secret, kr.secret_len, transcript.bytes, transcript.len, proof);
    kr_cbor_writer_free(&transcript);

    kr_write_hello(&hello, proof);
    kr_send(&hello);

    if (!kr_await_handshake()) {
        memset(kr.secret, 0, sizeof(kr.secret));
        kr.secret_len = 0;
        kr_disconnect(0);
        return;
    }
    kr.registered = 1;

    /*
     * The secret leaves the exported environment and stays in this module's own memory, where a
     * child process and a user's startup file cannot reach it. The integration keeps it because a
     * reader re-established inside the same shell needs it again.
     */
    kr.managed = 1;

    kr_shell_unexport(KR_ENDPOINT_VARIABLE);
    kr_shell_unexport(KR_SECRET_VARIABLE);
    unsetenv(KR_ENDPOINT_VARIABLE);
    unsetenv(KR_SECRET_VARIABLE);
    kr_trace("registered: root shell %llu", kr.self_pid);
}

int
kr_bridge_registered(void)
{
    return kr.registered;
}

int
kr_bridge_managed(void)
{
    return kr.managed;
}

int
kr_bridge_root_process(void)
{
    /* A process forked from the root shell inherits this state and the endpoint's descriptor, and
     * is still not the process the worker registered. */
    return kr.registered && kr.fd >= 0 && (unsigned long long)getpid() == kr.self_pid;
}

int
kr_bridge_fd(void)
{
    return kr.registered ? kr.fd : -1;
}

int
kr_bridge_wants_write(void)
{
    return kr.registered && kr.out_len > 0;
}

void
kr_bridge_cancel_settled(void)
{
    kr.cancel_in_flight = 0;
}

int
kr_bridge_launch_pending(void)
{
    return kr.launch_pending;
}

/* ---- events ---------------------------------------------------------------------------------- */

void
kr_bridge_hooks_activated(unsigned long prompt_generation)
{
    kr_cbor_writer writer;

    if (!kr.registered) {
        return;
    }
    kr_open_event(&writer, "hooks_activated");
    kr_cbor_map(&writer, 2);
    kr_cbor_key(&writer, "session_id");
    kr_cbor_bstr(&writer, kr.session, KR_UUID_LEN);
    kr_cbor_key(&writer, "prompt_generation");
    kr_cbor_uint(&writer, prompt_generation);
    kr_cbor_map_end(&writer);
    kr_close_event(&writer);
}

/* A VEOF reassignment is a user change to the gesture, and it takes effect at the prompt that is
 * starting rather than in the middle of a read. */
static void
kr_observe_gesture(unsigned long prompt_generation)
{
    int veof = kr_shell_veof();
    int disabled = (veof < 0);
    unsigned long byte = disabled ? 0u : (unsigned long)veof;
    kr_cbor_writer writer;

    if (disabled == kr.gesture_disabled && (disabled || byte == kr.gesture_byte)) {
        return;
    }
    if (kr.pending_gesture && kr.pending_gesture_disabled == disabled &&
        (disabled || kr.pending_gesture_byte == byte)) {
        return;
    }
    kr.pending_gesture = 1;
    kr.pending_gesture_disabled = disabled;
    kr.pending_gesture_byte = byte;
    kr.pending_gesture_at = prompt_generation;

    kr_open_event(&writer, "gesture_changed");
    kr_cbor_map(&writer, 3);
    kr_cbor_key(&writer, "gesture");
    kr_write_gesture(&writer, disabled, byte);
    kr_cbor_key(&writer, "session_id");
    kr_cbor_bstr(&writer, kr.session, KR_UUID_LEN);
    kr_cbor_key(&writer, "effective_at");
    kr_cbor_uint(&writer, prompt_generation);
    kr_cbor_map_end(&writer);
    kr_close_event(&writer);
}

void
kr_bridge_editor_enter(void)
{
    kr_reader_state state;
    kr_cbor_writer writer;

    if (!kr.registered) {
        return;
    }
    kr_shell_reader_state(&state);
    kr_observe_gesture(state.prompt_generation);

    kr_open_event(&writer, "editor_enter");
    kr_cbor_map(&writer, 7);
    kr_cbor_key(&writer, "editor");
    kr_write_editor(&writer, &state);
    kr_cbor_key(&writer, "session_id");
    kr_cbor_bstr(&writer, kr.session, KR_UUID_LEN);
    kr_cbor_key(&writer, "cwd_revision");
    kr_cbor_uint(&writer, state.cwd_revision);
    kr_cbor_key(&writer, "root_process");
    kr_write_process(&writer, kr.self_pid, kr.self_start);
    kr_cbor_key(&writer, "reader_context");
    kr_cbor_tstr(&writer, kr_context_name(state.reader_context));
    kr_cbor_key(&writer, "reader_revision");
    kr_cbor_uint(&writer, state.reader_revision);
    kr_cbor_key(&writer, "prompt_generation");
    kr_cbor_uint(&writer, state.prompt_generation);
    kr_cbor_map_end(&writer);
    kr_close_event(&writer);
    kr_bridge_service();
}

void
kr_bridge_editor_leave(int reason)
{
    static const char *const reasons[] = {
        "command_accepted", "preexec", "reader_takeover", "cancellation", "root_exit"
    };
    kr_reader_state state;
    kr_cbor_writer writer;

    if (!kr.registered) {
        return;
    }
    if (reason < 0 || reason > KR_LEAVE_ROOT_EXIT) {
        reason = KR_LEAVE_CANCELLATION;
    }
    kr.launch_pending = 0;
    kr_shell_reader_state(&state);

    kr_open_event(&writer, "editor_leave");
    kr_cbor_map(&writer, 4);
    kr_cbor_key(&writer, "reason");
    kr_cbor_tstr(&writer, reasons[reason]);
    kr_cbor_key(&writer, "session_id");
    kr_cbor_bstr(&writer, kr.session, KR_UUID_LEN);
    kr_cbor_key(&writer, "reader_revision");
    kr_cbor_uint(&writer, state.reader_revision);
    kr_cbor_key(&writer, "prompt_generation");
    kr_cbor_uint(&writer, state.prompt_generation);
    kr_cbor_map_end(&writer);
    kr_close_event(&writer);
    kr_flush();
}

void
kr_bridge_reader_idle(void)
{
    kr_reader_state state;
    kr_cbor_writer writer;

    if (!kr.registered) {
        return;
    }
    kr_shell_reader_state(&state);

    kr_open_event(&writer, "reader_idle");
    kr_cbor_map(&writer, 7);
    kr_cbor_key(&writer, "editor");
    kr_write_editor(&writer, &state);
    kr_cbor_key(&writer, "snapshot");
    kr_write_snapshot(&writer, &state);
    kr_cbor_key(&writer, "session_id");
    kr_cbor_bstr(&writer, kr.session, KR_UUID_LEN);
    kr_cbor_key(&writer, "cwd_revision");
    kr_cbor_uint(&writer, state.cwd_revision);
    kr_cbor_key(&writer, "reader_context");
    kr_cbor_tstr(&writer, kr_context_name(state.reader_context));
    kr_cbor_key(&writer, "reader_revision");
    kr_cbor_uint(&writer, state.reader_revision);
    kr_cbor_key(&writer, "prompt_generation");
    kr_cbor_uint(&writer, state.prompt_generation);
    kr_cbor_map_end(&writer);
    kr_close_event(&writer);
}

void
kr_bridge_command_accepted(void)
{
    kr_reader_state state;
    kr_cbor_writer writer;
    int fenced;

    if (!kr.registered) {
        return;
    }
    kr_shell_reader_state(&state);
    fenced = kr.fence_live && kr.fence_prompt == state.prompt_generation &&
             kr.fence_reader == state.reader_revision;

    /* The answer carries the capability this line's own execution presents, so it is the one
     * answer a package waits for before the line runs. */
    kr.accept_id = kr_open_event(&writer, "command_accepted");
    kr.accept_answered = 0;
    kr.token_present = 0;
    kr_cbor_map(&writer, 4);
    kr_cbor_key(&writer, "origin");
    if (fenced) {
        kr_cbor_variant(&writer, "fenced");
        kr_cbor_map(&writer, 2);
        kr_cbor_key(&writer, "input_epoch");
        kr_cbor_uint(&writer, kr.fence_epoch);
        kr_cbor_key(&writer, "attachment_id");
        kr_cbor_bstr(&writer, kr.fence_attachment, KR_UUID_LEN);
        kr_cbor_map_end(&writer);
        kr_cbor_variant_end(&writer);
    } else {
        kr_cbor_tstr(&writer, "unverifiable");
    }
    kr_cbor_key(&writer, "fence_id");
    if (fenced) {
        kr_cbor_bstr(&writer, kr.fence_id, KR_UUID_LEN);
    } else {
        kr_cbor_null(&writer);
    }
    kr_cbor_key(&writer, "session_id");
    kr_cbor_bstr(&writer, kr.session, KR_UUID_LEN);
    kr_cbor_key(&writer, "prompt_generation");
    kr_cbor_uint(&writer, state.prompt_generation);
    kr_cbor_map_end(&writer);
    kr_close_event(&writer);
}

void
kr_bridge_lost(int loss, const char *detail)
{
    static const char *const losses[] = {
        "post_startup_failure", "semantic_hook_loss", "bridge_disconnected",
        "unqualified_root_replacement"
    };
    kr_cbor_writer writer;

    if (!kr.registered) {
        return;
    }
    if (loss < 0 || loss > KR_LOSS_UNQUALIFIED_ROOT_REPLACEMENT) {
        loss = KR_LOSS_SEMANTIC_HOOK_LOSS;
    }
    kr_open_event(&writer, "integration_lost");
    kr_cbor_map(&writer, 3);
    kr_cbor_key(&writer, "loss");
    kr_cbor_tstr(&writer, losses[loss]);
    kr_cbor_key(&writer, "detail");
    kr_cbor_tstr(&writer, detail != NULL ? detail : "");
    kr_cbor_key(&writer, "session_id");
    kr_cbor_bstr(&writer, kr.session, KR_UUID_LEN);
    kr_cbor_map_end(&writer);
    kr_close_event(&writer);
    kr_flush();
}

/* ---- the pre-EOF decision -------------------------------------------------------------------- */

/* `detach_eligibility`, in the contract's own order. Returns 1 when the gesture is eligible. */
static int
kr_detach_eligible(const kr_reader_state *state, int source)
{
    if (state->reader_context != KR_CONTEXT_PRIMARY) {
        return 0;
    }
    if (source == KR_SOURCE_MACRO || source == KR_SOURCE_PUSHED_BACK || source == KR_SOURCE_PASTE) {
        return 0;
    }
    if (!state->buffer_empty) {
        return 0;
    }
    return !(state->pending_quoted_insertion || state->pending_macro_input ||
             state->pending_search || state->pending_numeric_argument ||
             state->pending_multikey_sequence || state->pending_vi_motion || state->pending_paste);
}

static void
kr_send_consumed(unsigned long prompt_generation, const char *reason, int hint_printed)
{
    kr_cbor_writer writer;

    kr_open_event(&writer, "pre_eof_consumed");
    kr_cbor_map(&writer, 4);
    kr_cbor_key(&writer, "reason");
    kr_cbor_tstr(&writer, reason);
    kr_cbor_key(&writer, "session_id");
    kr_cbor_bstr(&writer, kr.session, KR_UUID_LEN);
    kr_cbor_key(&writer, "hint_printed");
    kr_cbor_bool(&writer, hint_printed);
    kr_cbor_key(&writer, "prompt_generation");
    kr_cbor_uint(&writer, prompt_generation);
    kr_cbor_map_end(&writer);
    kr_close_event(&writer);
}

/* Consumes the gesture, printing the hint at most once per prompt. */
static int
kr_consume(unsigned long prompt_generation, const char *reason)
{
    int printed = 0;

    if (!kr.hinted || kr.hinted_prompt != prompt_generation) {
        kr.hinted = 1;
        kr.hinted_prompt = prompt_generation;
        kr_shell_print_hint(kr.hint);
        printed = 1;
    }
    kr_send_consumed(prompt_generation, reason, printed);
    return KR_CONSUME;
}

static void
kr_promote_gesture(unsigned long prompt_generation)
{
    if (!kr.pending_gesture || prompt_generation < kr.pending_gesture_at) {
        return;
    }
    kr.gesture_disabled = kr.pending_gesture_disabled;
    kr.gesture_byte = kr.pending_gesture_byte;
    kr.pending_gesture = 0;
}

int
kr_bridge_pre_eof(int key, int source)
{
    kr_reader_state state;
    kr_cbor_writer writer;
    unsigned long long detach_id;

    if (!kr.managed) {
        return KR_NATIVE;
    }
    /* The mailbox has already been read through this package's own mechanism, so the fence this
     * decision is taken against is the one the worker last published. A shell whose bridge has
     * gone holds no fence, so an eligible gesture is consumed with the hint rather than becoming
     * a native end of file. */
    kr_shell_reader_state(&state);
    kr_promote_gesture(state.prompt_generation);

    if (kr.gesture_disabled) {
        return KR_NATIVE;
    }
    if ((unsigned long)(unsigned char)key != kr.gesture_byte) {
        return KR_NATIVE;
    }
    /* The gesture is the sequence that invoked this operation, not merely its last byte. A
     * character that arrived at the end of a longer sequence belongs to that sequence, and the
     * editor's own handling of it is the right answer. */
    if (state.keys_len > 1) {
        return KR_NATIVE;
    }
    if (!kr_detach_eligible(&state, source)) {
        return KR_NATIVE;
    }
    if (!kr.fence_live) {
        return kr_consume(state.prompt_generation, "fence_missing");
    }
    if (kr.fence_prompt != state.prompt_generation || kr.fence_reader != state.reader_revision) {
        return kr_consume(state.prompt_generation, "fence_stale");
    }

    detach_id = kr_open_event(&writer, "eof_detach");
    kr_cbor_map(&writer, 4);
    kr_cbor_key(&writer, "fence_id");
    kr_cbor_bstr(&writer, kr.fence_id, KR_UUID_LEN);
    kr_cbor_key(&writer, "session_id");
    kr_cbor_bstr(&writer, kr.session, KR_UUID_LEN);
    kr_cbor_key(&writer, "input_epoch");
    kr_cbor_uint(&writer, kr.fence_epoch);
    kr_cbor_key(&writer, "prompt_generation");
    kr_cbor_uint(&writer, kr.fence_prompt);
    kr_cbor_map_end(&writer);
    kr_close_event(&writer);
    /* A refusal is this detach's only when it answers it. The oldest goes when there is no room,
     * which a person pressing the gesture faster than the worker answers could only reach by
     * outrunning it several times over. */
    if (kr.detach_count == KR_DETACH_IDS_MAX) {
        memmove(kr.detach_ids, kr.detach_ids + 1, (KR_DETACH_IDS_MAX - 1) * sizeof(kr.detach_ids[0]));
        kr.detach_count--;
    }
    kr.detach_ids[kr.detach_count++] = detach_id;
    return KR_CONSUME;
}

/* The gesture has already left the reader, so a refused detach is consumed with the hint. */
static void
kr_detach_refused(void)
{
    kr_reader_state state;

    kr.fence_live = 0;
    kr_shell_reader_state(&state);
    kr_consume(state.prompt_generation, "fence_stale");
}

/* ---- answering the reader's mailbox ----------------------------------------------------------- */

static void
kr_answer_fence(unsigned long long id, const kr_cbor_doc *doc, int params)
{
    kr_reader_state state;
    kr_cbor_writer writer;
    unsigned char fence_id[KR_UUID_LEN];
    unsigned long prompt;
    unsigned long reader;

    if (!kr_cbor_bytes_exact(doc, kr_cbor_get(doc, params, "fence_id"), fence_id, KR_UUID_LEN)) {
        return;
    }
    prompt = (unsigned long)kr_cbor_uint_or(doc, kr_cbor_get(doc, params, "prompt_generation"), 0);
    reader = (unsigned long)kr_cbor_uint_or(doc, kr_cbor_get(doc, params, "reader_revision"), 0);
    kr_shell_reader_state(&state);

    if (prompt != state.prompt_generation || reader != state.reader_revision) {
        /* A report about a reader that is not running now says nothing about the one that is. */
        kr_open_answer(&writer, id, "fence");
        kr_cbor_variant(&writer, "refused");
        kr_cbor_map(&writer, 4);
        kr_cbor_key(&writer, "reason");
        kr_cbor_tstr(&writer, "reader_moved");
        kr_cbor_key(&writer, "fence_id");
        kr_cbor_bstr(&writer, fence_id, KR_UUID_LEN);
        kr_cbor_key(&writer, "snapshot");
        kr_write_snapshot(&writer, &state);
        kr_cbor_key(&writer, "reader_context");
        kr_cbor_tstr(&writer, kr_context_name(state.reader_context));
        kr_cbor_map_end(&writer);
        kr_cbor_variant_end(&writer);
        kr_cbor_variant_end(&writer);
        kr_cbor_map_end(&writer);
        kr_cbor_variant_end(&writer);
        kr_send(&writer);
        return;
    }

    /* Each queue is reported separately: a worker that learns which one still holds input can
     * retry, and one that learns only that the transition failed cannot. */
    kr_open_answer(&writer, id, "fence");
    kr_cbor_variant(&writer, "acknowledged");
    kr_cbor_map(&writer, 8);
    kr_cbor_key(&writer, "editor");
    kr_write_editor(&writer, &state);
    kr_cbor_key(&writer, "queues");
    kr_write_queues(&writer, &state);
    kr_cbor_key(&writer, "fence_id");
    kr_cbor_bstr(&writer, fence_id, KR_UUID_LEN);
    kr_cbor_key(&writer, "snapshot");
    kr_write_snapshot(&writer, &state);
    kr_cbor_key(&writer, "cwd_revision");
    kr_cbor_uint(&writer, state.cwd_revision);
    kr_cbor_key(&writer, "reader_context");
    kr_cbor_tstr(&writer, kr_context_name(state.reader_context));
    kr_cbor_key(&writer, "reader_revision");
    kr_cbor_uint(&writer, state.reader_revision);
    kr_cbor_key(&writer, "prompt_generation");
    kr_cbor_uint(&writer, state.prompt_generation);
    kr_cbor_map_end(&writer);
    kr_cbor_variant_end(&writer);
    kr_cbor_variant_end(&writer);
    kr_cbor_map_end(&writer);
    kr_cbor_variant_end(&writer);
    kr_send(&writer);
}

static void
kr_reject_launch(unsigned long long id, const unsigned char transaction[KR_UUID_LEN],
                 const unsigned char fence_id[KR_UUID_LEN], const char *reason,
                 const kr_reader_state *state)
{
    kr_cbor_writer writer;

    kr_open_answer(&writer, id, "launch");
    kr_cbor_variant(&writer, "rejected");
    kr_cbor_map(&writer, 5);
    kr_cbor_key(&writer, "reason");
    kr_cbor_tstr(&writer, reason);
    kr_cbor_key(&writer, "fence_id");
    kr_cbor_bstr(&writer, fence_id, KR_UUID_LEN);
    kr_cbor_key(&writer, "transaction");
    kr_cbor_bstr(&writer, transaction, KR_UUID_LEN);
    kr_cbor_key(&writer, "buffer_revision");
    kr_cbor_uint(&writer, state->buffer_revision);
    kr_cbor_key(&writer, "prompt_generation");
    kr_cbor_uint(&writer, state->prompt_generation);
    kr_cbor_map_end(&writer);
    kr_cbor_variant_end(&writer);
    kr_cbor_variant_end(&writer);
    kr_cbor_map_end(&writer);
    kr_cbor_variant_end(&writer);
    kr_send(&writer);
}

/* Builds the line the reader installs: an argument vector quoted for this shell, or a command the
 * caller already quoted. Nothing is assembled by interpolation. */
static char *
kr_launch_text(const kr_cbor_doc *doc, int command, size_t *length)
{
    const char *name;
    size_t name_len;
    int payload = kr_cbor_variant_of(doc, command, &name, &name_len);
    char *text = NULL;
    size_t used = 0;
    size_t capacity = 0;
    int item;

    if (payload < 0) {
        return NULL;
    }
    if (name_len == 14 && memcmp(name, "quoted_command", 14) == 0) {
        if (doc->values[payload].kind != KR_CBOR_TSTR) {
            return NULL;
        }
        text = (char *)malloc(doc->values[payload].payload_len + 1);
        if (text == NULL) {
            return NULL;
        }
        memcpy(text, doc->values[payload].payload, doc->values[payload].payload_len);
        text[doc->values[payload].payload_len] = '\0';
        *length = doc->values[payload].payload_len;
        return text;
    }
    if (!(name_len == 9 && memcmp(name, "arguments", 9) == 0) ||
        doc->values[payload].kind != KR_CBOR_ARRAY) {
        return NULL;
    }
    for (item = kr_cbor_first(doc, payload); item >= 0; item = kr_cbor_next(doc, item)) {
        char *raw;
        char *quoted;
        size_t quoted_len;
        char *grown;

        if (doc->values[item].kind != KR_CBOR_TSTR) {
            free(text);
            return NULL;
        }
        raw = (char *)malloc(doc->values[item].payload_len + 1);
        if (raw == NULL) {
            free(text);
            return NULL;
        }
        memcpy(raw, doc->values[item].payload, doc->values[item].payload_len);
        raw[doc->values[item].payload_len] = '\0';
        quoted = kr_shell_quote_argument(raw);
        free(raw);
        if (quoted == NULL) {
            free(text);
            return NULL;
        }
        quoted_len = strlen(quoted);
        if (used + quoted_len + 2 > capacity) {
            capacity = (capacity ? capacity * 2 : 128);
            while (capacity < used + quoted_len + 2) {
                capacity *= 2;
            }
            grown = (char *)realloc(text, capacity);
            if (grown == NULL) {
                free(quoted);
                free(text);
                return NULL;
            }
            text = grown;
        }
        if (used > 0) {
            text[used++] = ' ';
        }
        memcpy(text + used, quoted, quoted_len);
        used += quoted_len;
        free(quoted);
    }
    if (text == NULL) {
        text = (char *)malloc(1);
        if (text == NULL) {
            return NULL;
        }
    }
    text[used] = '\0';
    *length = used;
    return text;
}

/*
 * `decide_launch`, on the reader's own thread, in the order the reasons matter.
 *
 * The revocation check is in this same step: the endpoint delivers frames in order, so a
 * revocation the worker sent before this step is one this step has already read.
 */
static void
kr_answer_launch(unsigned long long id, const kr_cbor_doc *doc, int request, int revoked)
{
    kr_reader_state state;
    kr_cbor_writer writer;
    unsigned char transaction[KR_UUID_LEN];
    unsigned char fence_id[KR_UUID_LEN];
    unsigned long expected_prompt;
    unsigned long expected_buffer;
    unsigned long expected_cwd;
    unsigned long long deadline_ms;
    unsigned long long waited_ms;
    int command;
    char *text;
    size_t text_len = 0;

    if (!kr_cbor_bytes_exact(doc, kr_cbor_get(doc, request, "transaction"), transaction,
                             KR_UUID_LEN) ||
        !kr_cbor_bytes_exact(doc, kr_cbor_get(doc, request, "fence_id"), fence_id, KR_UUID_LEN)) {
        return;
    }
    expected_prompt =
        (unsigned long)kr_cbor_uint_or(doc, kr_cbor_get(doc, request, "expected_prompt_generation"), 0);
    expected_buffer =
        (unsigned long)kr_cbor_uint_or(doc, kr_cbor_get(doc, request, "expected_buffer_revision"), 0);
    expected_cwd =
        (unsigned long)kr_cbor_uint_or(doc, kr_cbor_get(doc, request, "expected_cwd_revision"), 0);
    deadline_ms = kr_cbor_uint_or(doc, kr_cbor_get(doc, request, "deadline_ms"), 0);
    command = kr_cbor_get(doc, request, "command");
    /* How long this request has been in the mailbox, measured on the reader's own clock from when
     * it came off the endpoint. */
    waited_ms = kr_now_ms() - kr.frame_at_ms;

    kr_shell_reader_state(&state);

    if (revoked) {
        kr_reject_launch(id, transaction, fence_id, "revoked", &state);
        return;
    }
    if (!kr.fence_live || memcmp(kr.fence_id, fence_id, KR_UUID_LEN) != 0) {
        kr_reject_launch(id, transaction, fence_id, "fence_invalid", &state);
        return;
    }
    if (state.reader_context != KR_CONTEXT_PRIMARY) {
        kr_reject_launch(id, transaction, fence_id, "not_primary_reader", &state);
        return;
    }
    if (waited_ms >= deadline_ms) {
        kr_reject_launch(id, transaction, fence_id, "timeout", &state);
        return;
    }
    if (!state.tty_typeahead_drained || !state.macro_input_drained || !state.partial_key_drained ||
        state.queued_keys > 0 || state.pending_bytes > 0 || state.pending_macro_input) {
        kr_reject_launch(id, transaction, fence_id, "queued_prior_input", &state);
        return;
    }
    if (state.prompt_generation != expected_prompt) {
        kr_reject_launch(id, transaction, fence_id, "prompt_generation_mismatch", &state);
        return;
    }
    if (state.cwd_revision != expected_cwd) {
        kr_reject_launch(id, transaction, fence_id, "cwd_revision_mismatch", &state);
        return;
    }
    if (!state.buffer_empty) {
        kr_reject_launch(id, transaction, fence_id, "buffer_not_empty", &state);
        return;
    }
    if (state.buffer_revision != expected_buffer) {
        kr_reject_launch(id, transaction, fence_id, "buffer_revision_mismatch", &state);
        return;
    }

    text = kr_launch_text(doc, command, &text_len);
    if (text == NULL) {
        kr_reject_launch(id, transaction, fence_id, "buffer_not_empty", &state);
        return;
    }
    /* Building the line took time of its own. Past the budget nothing is installed, which is what
     * makes "install no command" a fact rather than a hope. */
    if (kr_now_ms() - kr.frame_at_ms >= deadline_ms) {
        free(text);
        kr_reject_launch(id, transaction, fence_id, "timeout", &state);
        return;
    }
    if (!kr_shell_install_command(text, text_len)) {
        free(text);
        kr_reject_launch(id, transaction, fence_id, "buffer_not_empty", &state);
        return;
    }
    free(text);

    kr.launch_pending = 1;
    memcpy(kr.launch_transaction, transaction, KR_UUID_LEN);

    /* Installed, so the answer carries the caller's own command back and the buffer's new
     * revision. The line is then accepted, and only then is the transaction no longer one a
     * revocation could take back. */
    kr_open_answer(&writer, id, "launch");
    kr_cbor_variant(&writer, "accepted");
    kr_cbor_map(&writer, 6);
    kr_cbor_key(&writer, "fence_id");
    kr_cbor_bstr(&writer, fence_id, KR_UUID_LEN);
    kr_cbor_key(&writer, "installed");
    kr_cbor_embed(&writer, doc, command);
    kr_cbor_key(&writer, "transaction");
    kr_cbor_bstr(&writer, transaction, KR_UUID_LEN);
    kr_cbor_key(&writer, "buffer_revision");
    kr_cbor_uint(&writer, state.buffer_revision + 1);
    kr_cbor_key(&writer, "reader_revision");
    kr_cbor_uint(&writer, state.reader_revision);
    kr_cbor_key(&writer, "prompt_generation");
    kr_cbor_uint(&writer, state.prompt_generation);
    kr_cbor_map_end(&writer);
    kr_cbor_variant_end(&writer);
    kr_cbor_variant_end(&writer);
    kr_cbor_map_end(&writer);
    kr_cbor_variant_end(&writer);
    kr_send(&writer);

    /*
     * Installed and accepted. The transaction stays this bridge's own until the reader actually
     * leaves, because a revocation that arrives in that window still has text to take back out.
     */
    kr_shell_accept_line();
}

static void
kr_answer_cancel(unsigned long long id, const kr_cbor_doc *doc, int params)
{
    kr_reader_state state;
    kr_cancellation ended;
    kr_cbor_writer writer;
    unsigned long long sequence;
    unsigned long long epoch;
    unsigned long prompt;
    unsigned long reader;

    sequence = kr_cbor_uint_or(doc, kr_cbor_get(doc, params, "sequence"), 0);
    epoch = kr_cbor_uint_or(doc, kr_cbor_get(doc, params, "epoch"), 0);
    prompt = (unsigned long)kr_cbor_uint_or(doc, kr_cbor_get(doc, params, "prompt_generation"), 0);
    reader = (unsigned long)kr_cbor_uint_or(doc, kr_cbor_get(doc, params, "reader_revision"), 0);

    memset(&ended, 0, sizeof(ended));
    ended.buffer_preserved = 1;
    kr_shell_reader_state(&state);
    /*
     * A cancellation for a reader that is not the one running would end an operation the worker
     * never asked about. It is answered, so the worker can match and discard it, and nothing is
     * cancelled.
     */
    if (prompt != state.prompt_generation || reader != state.reader_revision) {
        /* A cancellation for a reader that is not the one running ends nothing, so nothing has to
         * unwind before the next request is answered. */
        ended.discarded_bytes = 0;
    } else {
        kr_shell_cancel_key_wait(&ended);
        kr_shell_reader_state(&state);
        /* Only an operation that was actually in progress has to unwind before the next request is
         * answered. A cancellation that ended nothing leaves the reader where it was. */
        kr.cancel_in_flight = ended.partial_escape || ended.quoted_insertion || ended.vi_motion ||
                              ended.multikey_sequence || ended.macro_input;
    }

    kr_open_answer(&writer, id, "cancel");
    kr_cbor_map(&writer, 7);
    kr_cbor_key(&writer, "epoch");
    kr_cbor_uint(&writer, epoch);
    kr_cbor_key(&writer, "sequence");
    kr_cbor_uint(&writer, sequence);
    kr_cbor_key(&writer, "cancelled");
    kr_cbor_map(&writer, 5);
    kr_cbor_key(&writer, "vi_motion");
    kr_cbor_bool(&writer, ended.vi_motion);
    kr_cbor_key(&writer, "macro_input");
    kr_cbor_bool(&writer, ended.macro_input);
    kr_cbor_key(&writer, "partial_escape");
    kr_cbor_bool(&writer, ended.partial_escape);
    kr_cbor_key(&writer, "quoted_insertion");
    kr_cbor_bool(&writer, ended.quoted_insertion);
    kr_cbor_key(&writer, "multikey_sequence");
    kr_cbor_bool(&writer, ended.multikey_sequence);
    kr_cbor_map_end(&writer);
    kr_cbor_key(&writer, "discarded_bytes");
    kr_cbor_uint(&writer, ended.discarded_bytes);
    kr_cbor_key(&writer, "reader_revision");
    kr_cbor_uint(&writer, reader != 0 ? reader : state.reader_revision);
    kr_cbor_key(&writer, "buffer_preserved");
    kr_cbor_bool(&writer, ended.buffer_preserved);
    kr_cbor_key(&writer, "prompt_generation");
    kr_cbor_uint(&writer, prompt != 0 ? prompt : state.prompt_generation);
    kr_cbor_map_end(&writer);
    kr_cbor_variant_end(&writer);
    kr_cbor_map_end(&writer);
    kr_cbor_variant_end(&writer);
    kr_send(&writer);
}

/* ---- reading the mailbox ---------------------------------------------------------------------- */

static void
kr_take_publication(const kr_cbor_doc *doc, int publication)
{
    const char *name;
    size_t name_len;
    int payload = kr_cbor_variant_of(doc, publication, &name, &name_len);

    if (payload < 0) {
        return;
    }
    if (name_len == 9 && memcmp(name, "published", 9) == 0) {
        unsigned char fence_id[KR_UUID_LEN];
        unsigned char attachment[KR_UUID_LEN];
        if (!kr_cbor_bytes_exact(doc, kr_cbor_get(doc, payload, "fence_id"), fence_id,
                                 KR_UUID_LEN) ||
            !kr_cbor_bytes_exact(doc, kr_cbor_get(doc, payload, "originating_attachment"),
                                 attachment, KR_UUID_LEN)) {
            return;
        }
        memcpy(kr.fence_id, fence_id, KR_UUID_LEN);
        memcpy(kr.fence_attachment, attachment, KR_UUID_LEN);
        kr.fence_prompt =
            (unsigned long)kr_cbor_uint_or(doc, kr_cbor_get(doc, payload, "prompt_generation"), 0);
        kr.fence_reader =
            (unsigned long)kr_cbor_uint_or(doc, kr_cbor_get(doc, payload, "reader_revision"), 0);
        kr.fence_epoch = kr_cbor_uint_or(doc, kr_cbor_get(doc, payload, "input_epoch"), 0);
        kr.fence_live = 1;
        return;
    }
    /* Withheld and invalidated both mean the bridge holds no fence. */
    kr.fence_live = 0;
}

/* Whether `id` is a detach this bridge submitted and has had no answer to, forgetting it if so. */
static int
kr_take_detach_id(unsigned long long id)
{
    size_t i;

    for (i = 0; i < kr.detach_count; i++) {
        if (kr.detach_ids[i] == id) {
            memmove(kr.detach_ids + i, kr.detach_ids + i + 1,
                    (kr.detach_count - i - 1) * sizeof(kr.detach_ids[0]));
            kr.detach_count--;
            return 1;
        }
    }
    return 0;
}

/*
 * Takes the worker's answer to one of this bridge's events.
 *
 * An answer belongs to the event its identifier names, never to whatever is in flight: a refusal
 * is a detach's only when it answers a detach, and the answers a package waits for before a
 * command runs are kept for the event that asked.
 */
static void
kr_take_event_result(const kr_cbor_doc *doc, unsigned long long id, int result)
{
    const char *name;
    size_t name_len;
    int payload;

    /* The worker answers in the order it was asked, so this answer, or a later one, is the owed
     * one having come. */
    if (kr.owed != 0 && id >= kr.owed) {
        kr.owed = 0;
    }
    payload = kr_cbor_variant_of(doc, result, &name, &name_len);
    if (payload < 0) {
        return;
    }
    if (kr_take_detach_id(id)) {
        if (name_len == 7 && memcmp(name, "refused", 7) == 0) {
            /* The one refusal every bridge must handle: the detach the gesture had already left
             * the reader for. */
            kr_detach_refused();
        } else if (name_len == 8 && memcmp(name, "detached", 8) == 0) {
            /* After a successful detach the bridge drops its fence, so a repeated gesture cannot
             * take on the next attachment's identity. */
            kr.fence_live = 0;
        }
        return;
    }
    if (id != 0 && id == kr.accept_id) {
        kr.accept_answered = 1;
        kr.token_present = 0;
        if (name_len == 16 && memcmp(name, "command_recorded", 16) == 0) {
            int token = kr_cbor_get(doc, payload, "detach_token");
            if (token >= 0 && doc->values[token].kind == KR_CBOR_TSTR &&
                doc->values[token].payload_len > 0 &&
                doc->values[token].payload_len < KR_TOKEN_MAX &&
                memchr(doc->values[token].payload, '\0', doc->values[token].payload_len) == NULL) {
                memcpy(kr.token, doc->values[token].payload, doc->values[token].payload_len);
                kr.token[doc->values[token].payload_len] = '\0';
                kr.token_present = 1;
            }
        }
        return;
    }
    if (id != 0 && id == kr.resolve_id) {
        kr.resolve_answered = 1;
        free(kr.resolve_answer);
        kr.resolve_answer = NULL;
        kr.resolve_answer_len = 0;
        /* Anything but a resolution, a refusal included, is no backend: the command runs as it
         * was typed. */
        if (name_len == 16 && memcmp(name, "command_resolved", 16) == 0 &&
            doc->values[payload].encoded_len > 0) {
            kr.resolve_answer = (unsigned char *)malloc(doc->values[payload].encoded_len);
            if (kr.resolve_answer != NULL) {
                memcpy(kr.resolve_answer, doc->values[payload].encoded,
                       doc->values[payload].encoded_len);
                kr.resolve_answer_len = doc->values[payload].encoded_len;
            }
        }
    }
}

/*
 * Takes the answer a package is waiting for out of what has already arrived.
 *
 * Only the answer to the acceptance or the resolve being waited for is taken, wherever it is among
 * the frames already read. Everything else stays where it is, in order, for the reader to take at
 * its next boundary: a request for the reader, a publication and a detach's answer all belong to a
 * reader, and none is running while a command starts.
 */
static void
kr_take_answers(void)
{
    size_t at = 0;

    while (kr.registered && kr.in_len - at >= KR_FRAME_HEADER) {
        unsigned long length = ((unsigned long)kr.in[at] << 24) |
                               ((unsigned long)kr.in[at + 1] << 16) |
                               ((unsigned long)kr.in[at + 2] << 8) | (unsigned long)kr.in[at + 3];
        kr_cbor_doc doc;
        const char *name;
        size_t name_len;
        int root;
        int payload;
        int taken = 0;

        if (length == 0 || length > KR_CBOR_MAX_FRAME) {
            kr_disconnect(KR_LOSS_BRIDGE_DISCONNECTED);
            return;
        }
        if (kr.in_len - at < KR_FRAME_HEADER + length) {
            return;
        }
        root = kr_cbor_parse(&doc, kr.in + at + KR_FRAME_HEADER, (size_t)length);
        payload = kr_cbor_variant_of(&doc, root, &name, &name_len);
        if (payload >= 0 && name_len == 12 && memcmp(name, "event_result", 12) == 0) {
            int id_value = kr_cbor_get(&doc, payload, "id");
            if (id_value >= 0 && doc.values[id_value].kind == KR_CBOR_UINT) {
                unsigned long long id = doc.values[id_value].number;
                if ((id == kr.accept_id && !kr.accept_answered) ||
                    (id == kr.resolve_id && !kr.resolve_answered)) {
                    kr_take_event_result(&doc, id, kr_cbor_get(&doc, payload, "result"));
                    taken = 1;
                } else if (kr.owed != 0 && id >= kr.owed) {
                    kr.owed = 0;
                }
            }
        }
        kr_cbor_doc_free(&doc);
        if (taken) {
            kr_remove_frame_at(at, (size_t)length);
        } else {
            at += KR_FRAME_HEADER + length;
        }
    }
}

/*
 * Waits until `*answered` is set, the deadline passes or the endpoint has gone.
 *
 * Nothing but the answer is taken off the endpoint's buffer here. A deadline that passes leaves the
 * answer owed, and while it is owed nothing waits again.
 */
static int
kr_await(unsigned long long id, const int *answered, unsigned long long deadline)
{
    for (;;) {
        struct pollfd waiting;
        long long remaining;
        int ready;

        kr_take_answers();
        if (*answered) {
            return 1;
        }
        if (!kr.registered || kr.fd < 0) {
            return 0;
        }
        remaining = (long long)deadline - (long long)kr_now_ms();
        if (remaining <= 0) {
            kr.owed = id;
            return 0;
        }
        waiting.fd = kr.fd;
        waiting.events = (short)(POLLIN | (kr.out_len > 0 ? POLLOUT : 0));
        waiting.revents = 0;
        ready = poll(&waiting, 1, (int)remaining);
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            kr.owed = id;
            return 0;
        }
        if (kr.out_len > 0 && !kr_flush()) {
            return 0;
        }
        if (ready > 0 && (waiting.revents & (POLLIN | POLLHUP | POLLERR)) != 0 && !kr_fill()) {
            return 0;
        }
    }
}

static int
kr_is_revoked(const unsigned char transaction[KR_UUID_LEN])
{
    size_t i;

    for (i = 0; i < kr.revoked_count; i++) {
        if (memcmp(kr.revoked[i], transaction, KR_UUID_LEN) == 0) {
            return 1;
        }
    }
    return 0;
}

/*
 * Remembers one revoked transaction, best effort.
 *
 * This is the out-of-order case only: a revocation the worker somehow sent before the launch it
 * names. The case the contract states, a revocation among the frames this step read, is answered
 * by looking at those frames rather than by remembering anything, so an entry falling out of this
 * ring cannot make a launch be accepted under a revocation the reader had already read.
 */
static void
kr_remember_revocation(const unsigned char transaction[KR_UUID_LEN])
{
    if (kr_is_revoked(transaction)) {
        return;
    }
    memcpy(kr.revoked[kr.revoked_next], transaction, KR_UUID_LEN);
    kr.revoked_next = (kr.revoked_next + 1) % KR_REVOKED_MAX;
    if (kr.revoked_count < KR_REVOKED_MAX) {
        kr.revoked_count++;
    }
}

/*
 * Whether a revocation for this transaction is among the frames already read.
 *
 * `ReaderLaunchState::revoked` is "a revocation for this transaction was in the frames this step
 * read", so the answer is in those frames: the ones still waiting in the input buffer behind the
 * request being decided. Reading them here rather than remembering them keeps the answer exact
 * whatever order the worker put them in, and leaves nothing to fill up or fall out.
 */
static int
kr_revoked_in_this_read(const unsigned char transaction[KR_UUID_LEN])
{
    size_t at = 0;

    if (kr_is_revoked(transaction)) {
        return 1;
    }
    while (kr.in_len - at >= KR_FRAME_HEADER) {
        unsigned long length = ((unsigned long)kr.in[at] << 24) |
                               ((unsigned long)kr.in[at + 1] << 16) |
                               ((unsigned long)kr.in[at + 2] << 8) | (unsigned long)kr.in[at + 3];
        const char *name;
        size_t name_len;
        kr_cbor_doc doc;
        int root;
        int payload;
        int found = 0;

        if (length == 0 || length > KR_CBOR_MAX_FRAME ||
            kr.in_len - at < KR_FRAME_HEADER + length) {
            return 0;
        }
        root = kr_cbor_parse(&doc, kr.in + at + KR_FRAME_HEADER, (size_t)length);
        payload = kr_cbor_variant_of(&doc, root, &name, &name_len);
        if (payload >= 0 && name_len == 14 && memcmp(name, "launch_revoked", 14) == 0) {
            unsigned char named[KR_UUID_LEN];
            found = kr_cbor_bytes_exact(&doc, kr_cbor_get(&doc, payload, "transaction"), named,
                                        KR_UUID_LEN) &&
                    memcmp(named, transaction, KR_UUID_LEN) == 0;
        }
        kr_cbor_doc_free(&doc);
        if (found) {
            return 1;
        }
        at += KR_FRAME_HEADER + length;
    }
    return 0;
}

static void
kr_take_revocation(const kr_cbor_doc *doc, int frame)
{
    unsigned char transaction[KR_UUID_LEN];

    if (!kr_cbor_bytes_exact(doc, kr_cbor_get(doc, frame, "transaction"), transaction,
                             KR_UUID_LEN)) {
        return;
    }
    kr_remember_revocation(transaction);
    if (kr.launch_pending && memcmp(kr.launch_transaction, transaction, KR_UUID_LEN) == 0) {
        /* Installed but not accepted: the text comes out, so a revoked launch leaves nothing
         * behind. */
        kr_shell_remove_installed();
        kr.launch_pending = 0;
    }
}

/* Handles one frame. */
static void
kr_handle_frame(const unsigned char *frame, size_t length)
{
    kr_cbor_doc doc;
    int root = kr_cbor_parse(&doc, frame, length);
    const char *name;
    size_t name_len;
    int payload;

    if (root < 0) {
        kr_cbor_doc_free(&doc);
        kr_disconnect(KR_LOSS_BRIDGE_DISCONNECTED);
        return;
    }
    payload = kr_cbor_variant_of(&doc, root, &name, &name_len);
    if (payload < 0) {
        kr_cbor_doc_free(&doc);
        kr_disconnect(KR_LOSS_BRIDGE_DISCONNECTED);
        return;
    }
    if (name_len == 15 && memcmp(name, "fence_published", 15) == 0) {
        kr_take_publication(&doc, payload);
        kr_cbor_doc_free(&doc);
        return;
    }
    if (name_len == 14 && memcmp(name, "launch_revoked", 14) == 0) {
        kr_take_revocation(&doc, payload);
        kr_cbor_doc_free(&doc);
        return;
    }
    if (name_len == 12 && memcmp(name, "event_result", 12) == 0) {
        int id_value = kr_cbor_get(&doc, payload, "id");
        if (id_value >= 0 && doc.values[id_value].kind == KR_CBOR_UINT) {
            kr_take_event_result(&doc, doc.values[id_value].number,
                                 kr_cbor_get(&doc, payload, "result"));
        }
        kr_cbor_doc_free(&doc);
        return;
    }
    if (name_len == 7 && memcmp(name, "request", 7) == 0) {
        unsigned long long id;
        const char *kind;
        size_t kind_len;
        int request;
        int id_value = kr_cbor_get(&doc, payload, "id");

        if (id_value < 0 || doc.values[id_value].kind != KR_CBOR_UINT) {
            kr_cbor_doc_free(&doc);
            return;
        }
        id = doc.values[id_value].number;
        request = kr_cbor_variant_of(&doc, kr_cbor_get(&doc, payload, "request"), &kind, &kind_len);
        if (request < 0) {
            kr_cbor_doc_free(&doc);
            return;
        }
        if (kind_len == 5 && memcmp(kind, "fence", 5) == 0) {
            kr_answer_fence(id, &doc, request);
        } else if (kind_len == 6 && memcmp(kind, "launch", 6) == 0) {
            unsigned char transaction[KR_UUID_LEN];
            int already =
                kr_cbor_bytes_exact(&doc, kr_cbor_get(&doc, request, "transaction"), transaction,
                                    KR_UUID_LEN)
                && kr_revoked_in_this_read(transaction);
            kr_answer_launch(id, &doc, request, already);
        } else if (kind_len == 6 && memcmp(kind, "cancel", 6) == 0) {
            kr_answer_cancel(id, &doc, request);
        }
        kr_cbor_doc_free(&doc);
        return;
    }
    /* A worker never sends a hello, an event or an answer. A frame that does not belong on this
     * endpoint ends the connection rather than being ignored. */
    kr_cbor_doc_free(&doc);
    kr_disconnect(KR_LOSS_BRIDGE_DISCONNECTED);
}

void
kr_bridge_service(void)
{
    if (!kr.registered || kr.fd < 0) {
        return;
    }
    kr_flush();
    if (kr.cancel_in_flight) {
        /* The reader has not come out of the operation the last cancellation ended. Whatever is
         * waiting stays on the endpoint until it has. */
        return;
    }
    if (!kr_fill()) {
        return;
    }
    for (;;) {
        const unsigned char *frame;
        size_t length = kr_take_frame(&frame);
        if (length == 0 || !kr.registered) {
            break;
        }
        /* Answering a request reads more of the endpoint, which moves the input buffer, so the
         * frame is copied out before its decoded values are used. */
        if (length > kr.frame_capacity) {
            unsigned char *grown = (unsigned char *)realloc(kr.frame, length);
            if (grown == NULL) {
                kr_disconnect(KR_LOSS_BRIDGE_DISCONNECTED);
                break;
            }
            kr.frame = grown;
            kr.frame_capacity = length;
        }
        memcpy(kr.frame, frame, length);
        kr.frame_at_ms = kr_frame_arrival(length);
        kr_drop_frame(length);
        kr_handle_frame(kr.frame, length);
        if (kr.cancel_in_flight) {
            break;
        }
    }
    kr_flush();
}

/* ---- the command a line runs ------------------------------------------------------------------ */

/* Frees a vector of strings that ends with a null pointer. */
static void
kr_free_vector(char **vector)
{
    size_t i;

    if (vector == NULL) {
        return;
    }
    for (i = 0; vector[i] != NULL; i++) {
        free(vector[i]);
    }
    free(vector);
}

/* A copy of a decoded text value as a C string, or NULL when it is not text or holds a NUL. */
static char *
kr_text_copy(const kr_cbor_doc *doc, int index)
{
    char *copy;

    if (index < 0 || doc->values[index].kind != KR_CBOR_TSTR ||
        memchr(doc->values[index].payload, '\0', doc->values[index].payload_len) != NULL) {
        return NULL;
    }
    copy = (char *)malloc(doc->values[index].payload_len + 1);
    if (copy == NULL) {
        return NULL;
    }
    memcpy(copy, doc->values[index].payload, doc->values[index].payload_len);
    copy[doc->values[index].payload_len] = '\0';
    return copy;
}

void
kr_bridge_resolution_free(kr_resolution *resolution)
{
    if (resolution == NULL) {
        return;
    }
    free(resolution->launcher);
    kr_free_vector(resolution->arguments);
    kr_free_vector(resolution->environment);
    memset(resolution, 0, sizeof(*resolution));
}

/*
 * Reads the answer to the resolve last asked into what the shell runs.
 *
 * A backend is the only answer that changes anything, and only when the launcher it names is an
 * absolute path to an executable file and the vector keeps the command name the person typed.
 * Anything else is run as typed: the launcher is never searched for.
 */
static int
kr_decide_launch(const char *command, const char *executable, kr_resolution *out)
{
    kr_cbor_doc doc;
    int root;
    int backend;
    int launcher;
    int arguments;
    int environment;
    int item;
    size_t count;
    size_t used;
    struct stat file;

    if (kr.resolve_answer == NULL) {
        kr_trace("resolve %llu: refused; runs as typed", kr.resolve_id);
        return 0;
    }
    root = kr_cbor_parse(&doc, kr.resolve_answer, kr.resolve_answer_len);
    backend = kr_cbor_get(&doc, root, "backend");
    if (backend < 0 || doc.values[backend].kind != KR_CBOR_MAP) {
        int bypass = kr_cbor_get(&doc, root, "bypass");
        if (bypass >= 0 && doc.values[bypass].kind == KR_CBOR_TSTR) {
            kr_trace("resolve %llu: bypass %.*s; runs as typed", kr.resolve_id,
                     (int)doc.values[bypass].payload_len, (const char *)doc.values[bypass].payload);
        } else {
            kr_trace("resolve %llu: no backend; runs as typed", kr.resolve_id);
        }
        kr_cbor_doc_free(&doc);
        return 0;
    }
    launcher = kr_cbor_get(&doc, backend, "launcher");
    arguments = kr_cbor_get(&doc, root, "arguments");
    environment = kr_cbor_get(&doc, backend, "environment");
    out->launcher = kr_text_copy(&doc, launcher);
    if (out->launcher == NULL || out->launcher[0] != '/' || stat(out->launcher, &file) != 0 ||
        !S_ISREG(file.st_mode) || access(out->launcher, X_OK) != 0) {
        kr_trace("resolve %llu: the launcher is not an absolute path to an executable file; "
                 "runs as typed", kr.resolve_id);
        kr_cbor_doc_free(&doc);
        kr_bridge_resolution_free(out);
        return 0;
    }
    if (arguments < 0 || doc.values[arguments].kind != KR_CBOR_ARRAY ||
        doc.values[arguments].count == 0 || environment < 0 ||
        doc.values[environment].kind != KR_CBOR_ARRAY) {
        kr_trace("resolve %llu: the answer names no vector; runs as typed", kr.resolve_id);
        kr_cbor_doc_free(&doc);
        kr_bridge_resolution_free(out);
        return 0;
    }

    /* The launcher's own vector: `launcher launch -- executable arguments...`. */
    count = doc.values[arguments].count;
    out->arguments = (char **)calloc(count + 5, sizeof(char *));
    if (out->arguments == NULL) {
        kr_cbor_doc_free(&doc);
        kr_bridge_resolution_free(out);
        return 0;
    }
    out->arguments[0] = strdup(out->launcher);
    out->arguments[1] = strdup("launch");
    out->arguments[2] = strdup("--");
    out->arguments[3] = strdup(executable);
    used = 4;
    for (item = kr_cbor_first(&doc, arguments); item >= 0; item = kr_cbor_next(&doc, item)) {
        out->arguments[used] = kr_text_copy(&doc, item);
        if (out->arguments[used] == NULL) {
            break;
        }
        used++;
    }
    if (used != count + 4 || out->arguments[0] == NULL || out->arguments[1] == NULL ||
        out->arguments[2] == NULL || out->arguments[3] == NULL ||
        strcmp(out->arguments[4], command) != 0) {
        /* The integration adds flags; it never renames the command the person typed. */
        kr_trace("resolve %llu: the answer does not keep the command name; runs as typed",
                 kr.resolve_id);
        kr_cbor_doc_free(&doc);
        kr_bridge_resolution_free(out);
        return 0;
    }

    /* The variables for this one child, as NAME=value. */
    count = doc.values[environment].count;
    out->environment = (char **)calloc(count + 1, sizeof(char *));
    if (out->environment == NULL) {
        kr_cbor_doc_free(&doc);
        kr_bridge_resolution_free(out);
        return 0;
    }
    used = 0;
    for (item = kr_cbor_first(&doc, environment); item >= 0; item = kr_cbor_next(&doc, item)) {
        char *name = kr_text_copy(&doc, kr_cbor_get(&doc, item, "name"));
        char *value = kr_text_copy(&doc, kr_cbor_get(&doc, item, "value"));
        char *pair = NULL;

        if (name != NULL && value != NULL && name[0] != '\0' && strchr(name, '=') == NULL) {
            size_t size = strlen(name) + strlen(value) + 2;
            pair = (char *)malloc(size);
            if (pair != NULL) {
                snprintf(pair, size, "%s=%s", name, value);
            }
        }
        free(name);
        free(value);
        if (pair == NULL) {
            break;
        }
        out->environment[used++] = pair;
    }
    kr_cbor_doc_free(&doc);
    if (used != count) {
        kr_trace("resolve %llu: the answer names a variable no environment can hold; runs as typed",
                 kr.resolve_id);
        kr_bridge_resolution_free(out);
        return 0;
    }
    out->launch = 1;
    kr_trace("resolve %llu: backend; runs through %s", kr.resolve_id, out->launcher);
    return 1;
}

int
kr_bridge_resolve(const char *const *argv, size_t argc, const char *executable, const char *cwd,
                  unsigned long cwd_revision, unsigned long prompt_generation, kr_resolution *out)
{
    kr_cbor_writer writer;
    size_t i;

    memset(out, 0, sizeof(*out));
    if (!kr_bridge_root_process() || argv == NULL || argc == 0 || executable == NULL ||
        cwd == NULL) {
        return 0;
    }
    /*
     * A command whose input or output is a pipe is part of a pipeline, even where the shell runs
     * that part itself rather than in a child it forks: the last part of a pipeline can run in
     * the root shell, with the pipe on its input.
     */
    if (kr_is_pipe(0) || kr_is_pipe(1)) {
        kr_trace("resolve: %s was not asked about: it is part of a pipeline", argv[0]);
        return 0;
    }
    /*
     * The request is text, and a backend is established for exactly the file and the directory it
     * names. An executable, a directory or an argument that is not UTF-8 cannot be named exactly,
     * so the command runs as typed without asking.
     */
    if (executable[0] != '/' || cwd[0] != '/' || !kr_utf8_text(executable) ||
        !kr_utf8_text(cwd)) {
        kr_trace("resolve: %s was not asked about: its path or directory cannot be named exactly",
                 argv[0] != NULL ? argv[0] : "");
        return 0;
    }
    for (i = 0; i < argc; i++) {
        if (argv[i] == NULL || !kr_utf8_text(argv[i])) {
            kr_trace("resolve: an argument is not UTF-8, so the command was not asked about");
            return 0;
        }
    }
    kr_take_answers();
    if (kr.owed != 0) {
        kr_trace("resolve: %s was not asked about: event %llu is still unanswered", argv[0],
                 kr.owed);
        return 0;
    }

    kr.resolve_id = kr_open_event(&writer, "command_resolve");
    kr.resolve_answered = 0;
    free(kr.resolve_answer);
    kr.resolve_answer = NULL;
    kr.resolve_answer_len = 0;
    kr_cbor_map(&writer, 7);
    kr_cbor_key(&writer, "cwd");
    kr_cbor_tstr(&writer, cwd);
    kr_cbor_key(&writer, "argv");
    kr_cbor_array(&writer, argc);
    for (i = 0; i < argc; i++) {
        kr_cbor_tstr(&writer, argv[i]);
    }
    kr_cbor_key(&writer, "executable");
    kr_cbor_tstr(&writer, executable);
    kr_cbor_key(&writer, "session_id");
    kr_cbor_bstr(&writer, kr.session, KR_UUID_LEN);
    kr_cbor_key(&writer, "interactive");
    kr_cbor_bool(&writer, 1);
    kr_cbor_key(&writer, "cwd_revision");
    kr_cbor_uint(&writer, cwd_revision);
    kr_cbor_key(&writer, "prompt_generation");
    kr_cbor_uint(&writer, prompt_generation);
    kr_cbor_map_end(&writer);
    kr_close_event(&writer);
    kr_trace("resolve %llu: asked about %s as %s in %s at revision %lu", kr.resolve_id, argv[0],
             executable, cwd, cwd_revision);

    if (!kr_await(kr.resolve_id, &kr.resolve_answered, kr_now_ms() + KR_ANSWER_WAIT_MS)) {
        kr_trace("resolve %llu: no answer; runs as typed", kr.resolve_id);
        return 0;
    }
    return kr_decide_launch(argv[0], executable, out);
}

const char *
kr_bridge_line_token(void)
{
    if (kr.accept_id == 0 || !kr_bridge_root_process()) {
        return NULL;
    }
    if (!kr.accept_answered) {
        kr_take_answers();
        if (!kr.accept_answered && kr.owed == 0) {
            kr_await(kr.accept_id, &kr.accept_answered, kr_now_ms() + KR_ANSWER_WAIT_MS);
        }
    }
    if (!kr.accept_answered) {
        kr_trace("line %llu: no answer, so no capability", kr.accept_id);
        return NULL;
    }
    kr_trace("line %llu: %s", kr.accept_id,
             kr.token_present ? "a capability for this line" : "no capability for this line");
    return kr.token_present ? kr.token : NULL;
}

/* Whether a line holds nothing but blanks, which runs no command. */
static int
kr_blank(const char *line, size_t len)
{
    size_t i;

    for (i = 0; i < len; i++) {
        if (line[i] != ' ' && line[i] != '\t' && line[i] != '\n' && line[i] != '\r') {
            return 0;
        }
    }
    return 1;
}

static void
kr_block_forget(void)
{
    free(kr.block_command);
    free(kr.block_cwd);
    kr.block_command = NULL;
    kr.block_cwd = NULL;
    kr.block_command_len = 0;
    kr.block_cwd_len = 0;
    kr.block_open = 0;
}

/* Sends the open block: running, or finished with `status` after `duration_ms`. */
static void
kr_send_block(int finished, int status, unsigned long long duration_ms)
{
    kr_cbor_writer writer;

    kr_open_event(&writer, "command_block");
    kr_cbor_map(&writer, 8);
    kr_cbor_key(&writer, "cwd");
    kr_cbor_tstr_len(&writer, kr.block_cwd, kr.block_cwd_len);
    kr_cbor_key(&writer, "command");
    kr_cbor_tstr_len(&writer, kr.block_command, kr.block_command_len);
    kr_cbor_key(&writer, "session_id");
    kr_cbor_bstr(&writer, kr.session, KR_UUID_LEN);
    kr_cbor_key(&writer, "duration_ms");
    if (finished) {
        kr_cbor_uint(&writer, duration_ms);
    } else {
        kr_cbor_null(&writer);
    }
    kr_cbor_key(&writer, "exit_status");
    if (finished) {
        kr_cbor_uint(&writer, (unsigned long long)(status < 0 ? 255 : status));
    } else {
        kr_cbor_null(&writer);
    }
    kr_cbor_key(&writer, "cwd_revision");
    kr_cbor_uint(&writer, kr.block_cwd_revision);
    kr_cbor_key(&writer, "started_at_ms");
    kr_cbor_uint(&writer, kr.block_started_ms);
    kr_cbor_key(&writer, "prompt_generation");
    kr_cbor_uint(&writer, kr.block_prompt);
    kr_cbor_map_end(&writer);
    kr_close_event(&writer);
}

void
kr_bridge_block_started(unsigned long prompt_generation, const char *line, size_t len,
                        const char *cwd, unsigned long cwd_revision)
{
    char *text;
    size_t text_len = 0;

    if (!kr_bridge_root_process() || line == NULL || cwd == NULL) {
        return;
    }
    text = kr_utf8_lossy(line, len, &text_len);
    if (text == NULL) {
        return;
    }
    if (kr.block_open && kr.block_prompt == prompt_generation) {
        /* A continuation line of the same prompt: the command is the lines together. */
        char *joined = (char *)realloc(kr.block_command, kr.block_command_len + text_len + 2);
        if (joined == NULL) {
            free(text);
            return;
        }
        joined[kr.block_command_len] = '\n';
        memcpy(joined + kr.block_command_len + 1, text, text_len + 1);
        kr.block_command = joined;
        kr.block_command_len += text_len + 1;
        free(text);
    } else {
        /* A block that never heard its line finish is not reported as finished by a later one. */
        kr_block_forget();
        if (kr_blank(line, len)) {
            free(text);
            return;
        }
        kr.block_cwd = kr_utf8_lossy(cwd, strlen(cwd), &kr.block_cwd_len);
        if (kr.block_cwd == NULL) {
            free(text);
            return;
        }
        kr.block_command = text;
        kr.block_command_len = text_len;
        kr.block_prompt = prompt_generation;
        kr.block_cwd_revision = cwd_revision;
        kr.block_started_ms = kr_wall_ms();
        kr.block_started_at = kr_now_ms();
        kr.block_open = 1;
    }
    kr_send_block(0, 0, 0);
    kr_trace("block %lu: started in %s at revision %lu", kr.block_prompt, kr.block_cwd,
             kr.block_cwd_revision);
}

void
kr_bridge_block_finished(int status)
{
    if (!kr.block_open) {
        return;
    }
    if (kr_bridge_root_process()) {
        kr_send_block(1, status, kr_now_ms() - kr.block_started_at);
        kr_trace("block %lu: finished with %d", kr.block_prompt, status);
    }
    kr_block_forget();
}
