/*
 * The ZLE half of the KalaReach root-editor bridge.
 *
 * Copyright (c) Kala Powered.
 *
 * This file is added to Zsh by the KalaReach reader patch set and is distributed under the Zsh
 * licence that governs the rest of the package; see shells/zsh/LICENSE.
 *
 * Everything the contract asks a package to prove about its reader is read from ZLE's own state
 * here, in one operation, at the instant the reader is asked: the invoking key sequence, the bytes
 * the terminal still holds, the keys pushed back ahead of it, the edit buffer and which reader is
 * running. That is the native equivalent of $KEYS, $PENDING and $KEYS_QUEUED_COUNT, and taking the
 * three together is what a fence rests on.
 */

#include "zle.mdh"

#include "kr_bridge.h"
#include "kr_bridge_zle.h"

#include <stdio.h>
#include <string.h>
#include <termios.h>

/*
 * The reader's own revisions.
 *
 * A prompt generation counts primary readers; a reader revision counts every reader, so a plugin
 * that restarts the reader inside one prompt is a different reader and an old fence is stale. The
 * buffer revision changes when the buffer's contents change, which is what a launch's expectation
 * is checked against.
 */
static unsigned long kr_prompt_generation;
static unsigned long kr_reader_revision;
static unsigned long kr_buffer_revision;
static unsigned long kr_buffer_hash;
static unsigned long kr_cwd_revision;
static char *kr_cwd_seen;
static int kr_inside_reader;

/* What the reader is in the middle of, for the exclusions and the cancellation report. */
static int kr_pending_quoted;
static int kr_pending_numeric;
static int kr_pending_paste_open;
static int kr_source_is_pushed_back;

/* A takeover's cancellation: requested inside the wait, consumed at the next boundary. */
static int kr_cancel_requested;
static int kr_cancel_consumed;

/* True only while the reader is waiting for another key, which is what makes a key sequence
 * partial. At a boundary `keybuf` holds the sequence that invoked the current operation, which is
 * $KEYS rather than anything the reader is still waiting for. */
static int kr_in_key_wait;

/* True while a complete key sequence has been selected and its binding has not run. The person
 * typed it, so it is theirs and it goes before anything the worker asks for. */
static int kr_key_selected;

/* Whether this wait has already reported the reader idle. */
static int kr_idle_reported;

/* A launch this reader installed, so a revocation can take exactly that text back out. */
static int kr_installed_chars;

static unsigned long
kr_hash_line(void)
{
    unsigned long hash = 2166136261UL;
    int i;

    for (i = 0; i < zlell; i++) {
        unsigned long value = (unsigned long)zleline[i];
        hash ^= value & 0xffUL;
        hash *= 16777619UL;
        hash ^= (value >> 8) & 0xffUL;
        hash *= 16777619UL;
    }
    hash ^= (unsigned long)zlell;
    hash *= 16777619UL;
    return hash;
}

/* One revision per observed change of the buffer's contents, counted where it is read. */
static void
kr_track_buffer(void)
{
    unsigned long hash = kr_hash_line();

    if (hash != kr_buffer_hash) {
        kr_buffer_hash = hash;
        kr_buffer_revision++;
    }
}

static void
kr_track_cwd(void)
{
    if (pwd == NULL) {
        return;
    }
    if (kr_cwd_seen == NULL || strcmp(kr_cwd_seen, pwd) != 0) {
        zsfree(kr_cwd_seen);
        kr_cwd_seen = ztrdup(pwd);
        kr_cwd_revision++;
    }
}

static int
kr_reader_context(void)
{
    switch (zlecontext) {
    case ZLCON_LINE_CONT:
        return KR_CONTEXT_CONTINUATION;
    case ZLCON_VARED:
    case ZLCON_SELECT:
        return KR_CONTEXT_READ_BUILTIN;
    default:
        return KR_CONTEXT_PRIMARY;
    }
}

static int
kr_keymap(void)
{
    if (!invicmdmode()) {
        if (curkeymapname != NULL && strcmp(curkeymapname, "viins") == 0) {
            return KR_KEYMAP_VI_INSERT;
        }
        if (curkeymapname != NULL && strcmp(curkeymapname, "emacs") == 0) {
            return KR_KEYMAP_EMACS;
        }
        if (curkeymapname != NULL && strcmp(curkeymapname, "main") == 0) {
            return KR_KEYMAP_EMACS;
        }
        return KR_KEYMAP_CUSTOM;
    }
    return KR_KEYMAP_VI_COMMAND;
}

void
kr_shell_reader_state(kr_reader_state *out)
{
    size_t keys = (size_t)keybuflen;

    memset(out, 0, sizeof(*out));
    kr_track_buffer();
    /* A widget can change directory and return to the same prompt, so the revision is read where
     * it is reported rather than once at entry. */
    kr_track_cwd();

    out->prompt_generation = kr_prompt_generation;
    out->reader_revision = kr_reader_revision;
    out->reader_context = kr_reader_context();

    out->buffer_revision = kr_buffer_revision;
    out->buffer_empty = (zlell == 0);
    out->keymap = kr_keymap();

    out->pending_quoted_insertion = kr_pending_quoted;
    /* Keys pushed back by a widget or `zle -U` are the reader's own input, not the person's. */
    out->pending_macro_input = (kungetct > 0);
    /* ZLE keeps its own flag for an active incremental search. */
    out->pending_search = (isearch_active != 0);
    /* Being accumulated, or accumulated and waiting for the command it applies to. */
    out->pending_numeric_argument =
        kr_pending_numeric || prefixflag || (zmod.flags & (MOD_MULT | MOD_TMULT)) != 0;
    out->pending_multikey_sequence = (kr_in_key_wait && keybuflen > 0);
    out->pending_vi_motion = (virangeflag != 0);
    out->pending_paste = kr_pending_paste_open;

    if (keys > KR_KEYS_MAX) {
        keys = KR_KEYS_MAX;
    }
    memcpy(out->keys, keybuf, keys);
    out->keys_len = keys;
    out->pending_bytes = (unsigned long)noquery(0) + (kr_key_selected ? 1u : 0u);
    out->queued_keys = (unsigned long)kungetct;

    out->tty_typeahead_drained = (out->pending_bytes == 0);
    out->macro_input_drained = (kungetct == 0);
    out->partial_key_drained = !(kr_in_key_wait && keybuflen > 0);

    out->cwd_revision = kr_cwd_revision;
}

int
kr_shell_install_command(const char *text, size_t len)
{
    char *line;
    int metafied = 0;

    if (!zleactive || zlell != 0 || len == 0) {
        return 0;
    }
    if (zlemetaline != NULL) {
        unmetafy_line();
        metafied = 1;
    }
    /* The editor's own representation: `setline` unmetafies what it is given, so raw bytes above
     * 0x7f would change on the way in. */
    line = (char *)zalloc(len + 1);
    memcpy(line, text, len);
    line[len] = '\0';
    line = metafy(line, (int)len, META_REALLOC);
    setline(line, ZSL_TOEND);
    free(line);
    if (metafied) {
        metafy_line();
    }
    kr_installed_chars = zlell;
    kr_track_buffer();
    return zlell > 0;
}

int
kr_shell_remove_installed(void)
{
    int metafied = 0;

    if (kr_installed_chars <= 0) {
        return 0;
    }
    if (!zleactive) {
        kr_installed_chars = 0;
        return 0;
    }
    if (zlemetaline != NULL) {
        unmetafy_line();
        metafied = 1;
    }
    /* Only the text this launch installed comes out, and only while it is still all there. */
    if (zlell == kr_installed_chars) {
        zlecs = 0;
        foredel(zlell, CUT_RAW);
    }
    if (metafied) {
        metafy_line();
    }
    kr_installed_chars = 0;
    done = 0;
    kr_track_buffer();
    return 1;
}

void
kr_shell_accept_line(void)
{
    /* The read loop returns at its next boundary, which the patched zlecore takes immediately. */
    done = 1;
}

void
kr_shell_cancel_key_wait(kr_cancellation *out)
{
    out->partial_escape = (kr_in_key_wait && keybuflen > 0 && (unsigned char)keybuf[0] == 0x1b);
    out->multikey_sequence = (kr_in_key_wait && keybuflen > 0);
    out->quoted_insertion = kr_pending_quoted;
    out->vi_motion = (virangeflag != 0);
    out->macro_input = (kungetct > 0);
    out->buffer_preserved = 1;

    if (out->partial_escape || out->multikey_sequence || out->quoted_insertion || out->vi_motion ||
        out->macro_input) {
        out->discarded_bytes = (unsigned long)kungetct + (unsigned long)keybuflen;
        /* The old lease's undelivered input goes, the edit buffer stays. */
        kungetct = 0;
        /* The reader is inside something, so it is brought out of it: the wait ends and the
         * part-read sequence is dropped at the boundary that follows. */
        kr_cancel_requested = 1;
    } else {
        /*
         * Nothing was in progress, so there is nothing to unwind and nothing to throw away. The
         * reader stays in the wait it is in, and a sequence the person starts afterwards is not
         * taken for one this cancellation ended.
         */
        out->discarded_bytes = 0;
    }
}

char *
kr_shell_quote_argument(const char *argument)
{
    size_t len = strlen(argument);
    char *metafied;
    char *quoted;
    char *copy = NULL;
    int raw_len;

    metafied = (char *)zalloc(len + 1);
    memcpy(metafied, argument, len + 1);
    metafied = metafy(metafied, (int)len, META_REALLOC);

    pushheap();
    /*
     * Every argument is quoted, including the first. An argument vector is installed as literal
     * arguments, and a bare word at command position would be a reserved word, an assignment or
     * an alias rather than the name the caller asked to run.
     *
     * `quotestring` escapes for the inside of single quotes and leaves the quotes themselves to
     * its caller, so they are added here. Without them nothing would be quoted at all.
     */
    quoted = quotestring(metafied, QT_SINGLE);
    if (quoted != NULL) {
        size_t quoted_len = strlen(quoted);
        char *unmetafied = (char *)zalloc(quoted_len + 3);
        unmetafied[0] = '\'';
        memcpy(unmetafied + 1, quoted, quoted_len);
        unmetafied[quoted_len + 1] = '\'';
        unmetafied[quoted_len + 2] = '\0';
        raw_len = (int)quoted_len + 2;
        unmetafy(unmetafied, &raw_len);
        copy = (char *)malloc((size_t)raw_len + 1);
        if (copy != NULL) {
            memcpy(copy, unmetafied, (size_t)raw_len);
            copy[raw_len] = '\0';
        }
        zfree(unmetafied, quoted_len + 3);
    }
    popheap();
    free(metafied);
    return copy;
}

void
kr_shell_print_hint(const char *line)
{
    showmsg(line);
    /* The editor flushes its own output when it next refreshes the display. A hint printed while
     * the reader is waiting for a key has no next refresh to wait for, so it goes out now. */
    if (shout != NULL) {
        fflush(shout);
    }
}

int
kr_shell_veof(void)
{
#ifdef HAS_TIO
    struct ttyinfo info;

    if (SHTTY == -1) {
        return -1;
    }
    gettyinfo(&info);
# ifdef HAVE_TERMIOS_H
    if (info.tio.c_cc[VEOF] == VDISABLEVAL) {
        return -1;
    }
    return (int)(unsigned char)info.tio.c_cc[VEOF];
# else
    if (info.tio.c_cc[VEOF] == VDISABLEVAL) {
        return -1;
    }
    return (int)(unsigned char)info.tio.c_cc[VEOF];
# endif
#else
    return eofchar;
#endif
}

void
kr_shell_unexport(const char *name)
{
    /* The shell's own parameter goes with the environment entry, so a child inherits neither. */
    unsetparam((char *)name);
}

/* ---- the reader's boundaries ------------------------------------------------------------------ */

void
kr_zle_setup(void)
{
    kr_bridge_activate();
}

void
kr_zle_enter(void)
{
    if (!kr_bridge_registered()) {
        return;
    }
    if (kr_inside_reader) {
        /* A reader starting inside another is a takeover: the one that was running is over. */
        kr_bridge_editor_leave(KR_LEAVE_READER_TAKEOVER);
    }
    kr_reader_revision++;
    if (zlecontext == ZLCON_LINE_START) {
        kr_prompt_generation++;
    }
    kr_track_cwd();
    kr_buffer_hash = kr_hash_line();
    kr_buffer_revision++;
    kr_installed_chars = 0;
    kr_pending_quoted = kr_pending_numeric = kr_pending_paste_open = 0;
    kr_cancel_requested = kr_cancel_consumed = kr_in_key_wait = 0;
    kr_key_selected = kr_idle_reported = 0;
    /* A reader that is starting is not inside anything a cancellation has to unwind. */
    kr_bridge_cancel_settled();
    kr_inside_reader = 1;
    kr_bridge_editor_enter();
}

void
kr_zle_leave(int eof_sent)
{
    int reason;

    if (!kr_bridge_registered() || !kr_inside_reader) {
        kr_inside_reader = 0;
        return;
    }
    if (eof_sent || exit_pending) {
        reason = KR_LEAVE_ROOT_EXIT;
    } else if (errflag) {
        reason = KR_LEAVE_CANCELLATION;
    } else if (done) {
        reason = KR_LEAVE_COMMAND_ACCEPTED;
    } else {
        reason = KR_LEAVE_CANCELLATION;
    }
    kr_inside_reader = 0;
    kr_installed_chars = 0;
    kr_cancel_requested = kr_cancel_consumed = 0;
    kr_bridge_cancel_settled();
    if (reason == KR_LEAVE_COMMAND_ACCEPTED) {
        /* The accepted line is reported from the reader, inside the fence, before the leave: a
         * record sent after it could only ever say that nothing could be established. */
        kr_bridge_command_accepted();
    }
    kr_bridge_editor_leave(reason);
}

int
kr_zle_boundary(void)
{
    int source;
    int consumed;

    if (!kr_bridge_managed()) {
        return 0;
    }
    if (kr_cancel_consumed) {
        /* The takeover's cancellation ended the wait; the reader continues with its buffer. */
        kr_cancel_consumed = 0;
        keybuflen = 0;
        keybuf[0] = '\0';
        return 1;
    }
    /*
     * This is the key-sequence boundary: the reader has resolved one complete sequence and is
     * between operations, which is where its mailbox is read. The sequence it has resolved has
     * not run yet, so it is input of the person's that anything the mailbox holds waits behind.
     */
    kr_key_selected = 1;
    kr_bridge_service();
    kr_key_selected = 0;
    if (done) {
        return 1;		/* a launch was installed and accepted */
    }
    source = kr_source_is_pushed_back ? KR_SOURCE_PUSHED_BACK
                                      : (kr_pending_paste_open ? KR_SOURCE_PASTE
                                                               : KR_SOURCE_TERMINAL);
    consumed = kr_bridge_pre_eof(lastchar, source) == KR_CONSUME;
    /* The next wait is a fresh chance to be idle. */
    kr_idle_reported = 0;
    return consumed;
}

void
kr_zle_before_wait(void)
{
    if (!kr_bridge_registered() || kr_idle_reported) {
        return;
    }
    if (keybuflen != 0 || kungetct != 0) {
        return;
    }
    /* Nothing buffered and nothing part-read, and the reader is about to wait: one of the three
     * points the worker retries a withheld fence at. */
    kr_idle_reported = 1;
    kr_in_key_wait = 1;
    kr_bridge_reader_idle();
    kr_in_key_wait = 0;
}

int
kr_zle_wait(void)
{
    if (!kr_bridge_registered()) {
        return 0;
    }
    /* Everything answered from here is answered by a reader that is waiting for another key. */
    kr_in_key_wait = 1;
    kr_bridge_service();
    kr_in_key_wait = 0;
    if (kr_cancel_requested) {
        /* The wait is over, so the reader is out of whatever the cancellation ended and the
         * endpoint can be read again. */
        kr_cancel_requested = 0;
        kr_cancel_consumed = 1;
        kr_idle_reported = 0;
        kr_bridge_cancel_settled();
        return 1;
    }
    return done != 0;
}

int
kr_zle_fd(void)
{
    return kr_bridge_fd();
}

void
kr_zle_pass_end(void)
{
    /*
     * One pass of the read loop is over, so whatever a cancellation ended has ended: the reader is
     * back here, whether the wait returned or the binding ran. Anything that was waiting behind
     * the cancellation is read now, at this boundary, rather than at the next keystroke.
     */
    kr_cancel_requested = kr_cancel_consumed = 0;
    kr_bridge_cancel_settled();
    /* Whatever the pass did, the reader's queues may have changed, so the next wait reports
     * itself idle again and the worker gets its retry point. */
    kr_idle_reported = 0;
    kr_bridge_service();
    /* Reading the endpoint there can itself have ended something, and at a pass boundary that has
     * ended too, so whatever came behind it is read now rather than at the next keystroke. */
    kr_cancel_requested = kr_cancel_consumed = 0;
    kr_bridge_cancel_settled();
    kr_bridge_service();
}

void
kr_zle_source_pushed_back(void)
{
    kr_source_is_pushed_back = 1;
}

void
kr_zle_source_terminal(void)
{
    kr_source_is_pushed_back = 0;
}

void
kr_zle_pending_quoted_insertion(int active)
{
    kr_pending_quoted = active;
}

void
kr_zle_pending_numeric_argument(int active)
{
    kr_pending_numeric = active;
}

void
kr_zle_pending_paste(int active)
{
    kr_pending_paste_open = active;
}

/* ---- the guarded startup entry's one-shot activation -------------------------------------------- */

int
bin_kr_bridge(char *name, char **args, UNUSED(struct options *ops), UNUSED(int func))
{
    if (args[0] == NULL) {
        zwarnnam(name, "expected activated, lost or status");
        return 1;
    }
    if (strcmp(args[0], "status") == 0) {
        return kr_bridge_registered() ? 0 : 1;
    }
    if (strcmp(args[0], "activated") == 0) {
        if (!kr_bridge_registered()) {
            return 1;
        }
        kr_bridge_hooks_activated(kr_prompt_generation + 1);
        return 0;
    }
    if (strcmp(args[0], "lost") == 0) {
        int loss = KR_LOSS_SEMANTIC_HOOK_LOSS;

        const char *detail = "";
        if (args[1] != NULL) {
            if (strcmp(args[1], "post-startup-failure") == 0) {
                loss = KR_LOSS_POST_STARTUP_FAILURE;
            } else if (strcmp(args[1], "unqualified-root-replacement") == 0) {
                loss = KR_LOSS_UNQUALIFIED_ROOT_REPLACEMENT;
            }
            if (args[2] != NULL) {
                detail = args[2];
            }
        }
        kr_bridge_lost(loss, detail);
        return 0;
    }
    zwarnnam(name, "unknown request: %s", args[0]);
    return 1;
}
