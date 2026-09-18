/*
 * The KalaReach root-editor bridge: the endpoint, the frames and every decision the contract puts
 * on the reader's side.
 *
 * Copyright (c) Kala Powered.
 *
 * This file is added to Zsh by the KalaReach reader patch set and is distributed under the Zsh
 * licence that governs the rest of the package; see shells/zsh/LICENSE.
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
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

#define KR_UUID_LEN 16
#define KR_SECRET_MAX 64
#define KR_HINT_MAX 256
#define KR_HANDSHAKE_WAIT_MS 2000
#define KR_REVOKED_MAX 16
#define KR_FRAME_HEADER 4

/* The bridge's whole state. One root shell, one endpoint, one reader. */
static struct {
    int fd;
    int registered;
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

    unsigned long long event_counter;
    /* When the frame being handled came off the endpoint, on this reader's own clock. */
    unsigned long long frame_at_ms;
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
}

static int
kr_flush(void)
{
    while (kr.out_len > 0 && kr.fd >= 0) {
        ssize_t written = write(kr.fd, kr.out, kr.out_len);
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

static void
kr_drop_frame(size_t length)
{
    size_t total = KR_FRAME_HEADER + length;
    memmove(kr.in, kr.in + total, kr.in_len - total);
    kr.in_len -= total;
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
 * to whatever is in flight. */
static void
kr_open_event(kr_cbor_writer *writer, const char *name)
{
    kr_cbor_writer_init(writer);
    kr_cbor_variant(writer, "event");
    kr_cbor_map(writer, 2);
    kr_cbor_key(writer, "id");
    kr_cbor_uint(writer, ++kr.event_counter);
    kr_cbor_key(writer, "event");
    kr_cbor_variant(writer, name);
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
    kr_shell_unexport(KR_ENDPOINT_VARIABLE);
    kr_shell_unexport(KR_SECRET_VARIABLE);
    unsetenv(KR_ENDPOINT_VARIABLE);
    unsetenv(KR_SECRET_VARIABLE);
}

int
kr_bridge_registered(void)
{
    return kr.registered;
}

int
kr_bridge_fd(void)
{
    return kr.registered ? kr.fd : -1;
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

    kr_open_event(&writer, "command_accepted");
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

    if (!kr.registered) {
        return KR_NATIVE;
    }
    /* The mailbox has already been read through this package's own mechanism, so the fence this
     * decision is taken against is the one the worker last published. */
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

    kr_open_event(&writer, "eof_detach");
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
    size_t i;

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
    for (i = 0; i < doc->values[payload].count; i++) {
        int item = kr_cbor_at(doc, payload, i);
        char *raw;
        char *quoted;
        size_t quoted_len;
        char *grown;

        if (item < 0 || doc->values[item].kind != KR_CBOR_TSTR) {
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
    if (text == NULL || !kr_shell_install_command(text, text_len)) {
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

    kr_shell_accept_line();
    kr.launch_pending = 0;
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
    kr_shell_cancel_key_wait(&ended);
    kr_shell_reader_state(&state);

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

static void
kr_take_event_result(const kr_cbor_doc *doc, int result)
{
    const char *name;
    size_t name_len;

    if (kr_cbor_variant_of(doc, result, &name, &name_len) < 0) {
        return;
    }
    if (name_len == 7 && memcmp(name, "refused", 7) == 0) {
        /* The one refusal every bridge must handle: the detach the gesture had already left the
         * reader for. */
        kr_detach_refused();
        return;
    }
    if (name_len == 8 && memcmp(name, "detached", 8) == 0) {
        /* After a successful detach the bridge drops its fence, so a repeated gesture cannot take
         * on the next attachment's identity. */
        kr.fence_live = 0;
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

static void
kr_take_revocation(const kr_cbor_doc *doc, int frame)
{
    unsigned char transaction[KR_UUID_LEN];

    if (!kr_cbor_bytes_exact(doc, kr_cbor_get(doc, frame, "transaction"), transaction,
                             KR_UUID_LEN)) {
        return;
    }
    if (!kr_is_revoked(transaction)) {
        memcpy(kr.revoked[kr.revoked_next], transaction, KR_UUID_LEN);
        kr.revoked_next = (kr.revoked_next + 1) % KR_REVOKED_MAX;
        if (kr.revoked_count < KR_REVOKED_MAX) {
            kr.revoked_count++;
        }
    }
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
        kr_disconnect(KR_LOSS_BRIDGE_DISCONNECTED);
        return;
    }
    payload = kr_cbor_variant_of(&doc, root, &name, &name_len);
    if (payload < 0) {
        return;
    }
    if (name_len == 15 && memcmp(name, "fence_published", 15) == 0) {
        kr_take_publication(&doc, payload);
        return;
    }
    if (name_len == 14 && memcmp(name, "launch_revoked", 14) == 0) {
        kr_take_revocation(&doc, payload);
        return;
    }
    if (name_len == 12 && memcmp(name, "event_result", 12) == 0) {
        kr_take_event_result(&doc, kr_cbor_get(&doc, payload, "result"));
        return;
    }
    if (name_len == 7 && memcmp(name, "request", 7) == 0) {
        unsigned long long id;
        const char *kind;
        size_t kind_len;
        int request;
        int id_value = kr_cbor_get(&doc, payload, "id");

        if (id_value < 0 || doc.values[id_value].kind != KR_CBOR_UINT) {
            return;
        }
        id = doc.values[id_value].number;
        request = kr_cbor_variant_of(&doc, kr_cbor_get(&doc, payload, "request"), &kind, &kind_len);
        if (request < 0) {
            return;
        }
        if (kind_len == 5 && memcmp(kind, "fence", 5) == 0) {
            kr_answer_fence(id, &doc, request);
        } else if (kind_len == 6 && memcmp(kind, "launch", 6) == 0) {
            unsigned char transaction[KR_UUID_LEN];
            int already =
                kr_cbor_bytes_exact(&doc, kr_cbor_get(&doc, request, "transaction"), transaction,
                                    KR_UUID_LEN)
                && kr_is_revoked(transaction);
            kr_answer_launch(id, &doc, request, already);
        } else if (kind_len == 6 && memcmp(kind, "cancel", 6) == 0) {
            kr_answer_cancel(id, &doc, request);
        }
        return;
    }
    /* A worker never sends a hello, an event or an answer. A frame that does not belong on this
     * endpoint ends the connection rather than being ignored. */
    kr_disconnect(KR_LOSS_BRIDGE_DISCONNECTED);
}

void
kr_bridge_service(void)
{
    if (!kr.registered || kr.fd < 0) {
        return;
    }
    kr_flush();
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
        kr_drop_frame(length);
        kr.frame_at_ms = kr_now_ms();
        kr_handle_frame(kr.frame, length);
    }
    kr_flush();
}
