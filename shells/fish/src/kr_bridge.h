/*
 * The KalaReach root-editor bridge: the interface between the patched reader and the bridge core.
 *
 * Copyright (c) Kala Powered.
 *
 * This file is added to fish by the KalaReach reader patch set and is
 * distributed under the GNU General Public Licence, version 2, that governs the rest of
 * the package; see shells/fish/LICENSE.
 *
 * The core below owns the endpoint, the frames and every decision the contract states. The reader
 * owns the state those decisions are taken against, and supplies it through the kr_shell_*
 * functions. Nothing here blocks the reader: the socket is non-blocking, and the mailbox is read
 * at key-sequence boundaries and while the reader waits for a key.
 */

#ifndef KR_BRIDGE_H
#define KR_BRIDGE_H

#include <stddef.h>

/* The protocol this bridge speaks, and the version of the integration itself. */
#define KR_BRIDGE_PROTOCOL "kr-shell-bridge/1"

/* Which reader is running. */
#define KR_CONTEXT_PRIMARY 0
#define KR_CONTEXT_CONTINUATION 1
#define KR_CONTEXT_READ_BUILTIN 2

/* The editor's keymap. */
#define KR_KEYMAP_EMACS 0
#define KR_KEYMAP_VI_INSERT 1
#define KR_KEYMAP_VI_COMMAND 2
#define KR_KEYMAP_CUSTOM 3

/* Where the reader took a character from. The pending flags say what is in progress; the source
 * says where this character came from, and the last character of a macro or a paste arrives with
 * the flags already clear. */
#define KR_SOURCE_TERMINAL 0
#define KR_SOURCE_TYPEAHEAD 1
#define KR_SOURCE_MACRO 2
#define KR_SOURCE_PUSHED_BACK 3
#define KR_SOURCE_PASTE 4

/* Why the reader left. */
#define KR_LEAVE_COMMAND_ACCEPTED 0
#define KR_LEAVE_PREEXEC 1
#define KR_LEAVE_READER_TAKEOVER 2
#define KR_LEAVE_CANCELLATION 3
#define KR_LEAVE_ROOT_EXIT 4

/* What the integration lost. */
#define KR_LOSS_POST_STARTUP_FAILURE 0
#define KR_LOSS_SEMANTIC_HOOK_LOSS 1
#define KR_LOSS_BRIDGE_DISCONNECTED 2
#define KR_LOSS_UNQUALIFIED_ROOT_REPLACEMENT 3

/* What the pre-EOF hook returns. `KR_NATIVE` gives the character back to the reader's own
 * end-of-file branch; `KR_CONSUME` continues the same reader call. */
#define KR_NATIVE 0
#define KR_CONSUME 1

/* The longest invoking key sequence the snapshot carries. */
#define KR_KEYS_MAX 64

/*
 * The reader's own state, read in one operation at one instant.
 *
 * This is the native equivalent of Zsh's $KEYS, $PENDING and $KEYS_QUEUED_COUNT together with the
 * buffer state: two reads taken a moment apart describe two different instants, which is the
 * ambiguity a fence exists to remove.
 */
typedef struct {
    unsigned long prompt_generation;
    unsigned long reader_revision;
    int reader_context;

    unsigned long buffer_revision;
    int buffer_empty;
    int keymap;

    int pending_quoted_insertion;
    int pending_macro_input;
    int pending_search;
    int pending_numeric_argument;
    int pending_multikey_sequence;
    int pending_vi_motion;
    int pending_paste;

    unsigned char keys[KR_KEYS_MAX];
    size_t keys_len;
    unsigned long pending_bytes;
    unsigned long queued_keys;

    int tty_typeahead_drained;
    int macro_input_drained;
    int partial_key_drained;

    unsigned long cwd_revision;
} kr_reader_state;

/* What a non-destructive cancellation ended. */
typedef struct {
    int partial_escape;
    int quoted_insertion;
    int vi_motion;
    int multikey_sequence;
    int macro_input;
    int buffer_preserved;
    unsigned long discarded_bytes;
} kr_cancellation;

/* ---- what the reader supplies -------------------------------------------------------------- */

/* Fills `out` from the reader's own state, atomically. */
void kr_shell_reader_state(kr_reader_state *out);

/* Installs `text` in the empty edit buffer. Returns non-zero when it went in. */
int kr_shell_install_command(const char *text, size_t len);

/* Removes text a launch installed that has not been accepted. Returns non-zero when it came out. */
int kr_shell_remove_installed(void);

/* Accepts the installed line, returning from the read loop at the next boundary. */
void kr_shell_accept_line(void);

/* Ends the pending key wait and keeps the edit buffer, reporting what it ended. */
void kr_shell_cancel_key_wait(kr_cancellation *out);

/* Returns `argument` quoted for this shell, in memory the caller frees, or NULL. */
char *kr_shell_quote_argument(const char *argument);

/* Prints one line above the prompt and redraws it. */
void kr_shell_print_hint(const char *line);

/* The terminal's VEOF, or -1 when the terminal has no end-of-file character. */
int kr_shell_veof(void);

/* Removes one variable from the shell's own exported environment. */
void kr_shell_unexport(const char *name);

/* ---- what the bridge supplies -------------------------------------------------------------- */

/* Non-zero once the handshake has been accepted. */
int kr_bridge_registered(void);

/*
 * Non-zero once this shell has ever been a managed root shell.
 *
 * It never returns to zero. A session that loses its bridge keeps the fail-safe answer to an
 * eligible end-of-file gesture, which is to consume it with the hint.
 */
int kr_bridge_managed(void);

/*
 * Attempts the handshake, unless the bootstrap variables say there is nothing to attempt.
 *
 * Called once, before the first primary reader. A shell that inherited nothing skips it, which is
 * what keeps the guarded startup entry inert in every child shell.
 */
void kr_bridge_activate(void);

/* Reports that the user's startup files have run and the user-facing hooks are live. */
void kr_bridge_hooks_activated(unsigned long prompt_generation);

/* The reader's own boundaries. */
void kr_bridge_editor_enter(void);
void kr_bridge_editor_leave(int reason);
void kr_bridge_reader_idle(void);
void kr_bridge_command_accepted(void);

/* Takes the end-of-file decision for a character the reader has selected. */
int kr_bridge_pre_eof(int key, int source);

/* Reads the mailbox and answers what is in it. Safe only at a key-sequence boundary or while the
 * reader waits for a key. */
void kr_bridge_service(void);

/* The endpoint's descriptor, for the reader's own select set, or -1. */
int kr_bridge_fd(void);

/* Non-zero while an answer is waiting to go out, so the reader's own wait can watch for room. */
int kr_bridge_wants_write(void);

/*
 * The reader has come out of the operation a cancellation ended.
 *
 * Until it does, the bridge reads and answers nothing, so a request that follows a cancellation is
 * answered against the reader's real state rather than the one it was leaving.
 */
void kr_bridge_cancel_settled(void);

/* Reports that the ground the integration stood on has gone. */
void kr_bridge_lost(int loss, const char *detail);

/* Non-zero while a launch this bridge installed is waiting to be accepted. */
int kr_bridge_launch_pending(void);

/* ---- the command a line runs ----------------------------------------------------------------- */

/*
 * The longest a shell waits for the worker to answer a resolve.
 *
 * A worker that is there answers in well under a millisecond. One that has stopped answering costs
 * this once: while an answer is owed nothing else waits, and every command runs as it was typed.
 */
#define KR_ANSWER_WAIT_MS 1000

/*
 * What an invocation runs as, once the worker has answered.
 *
 * `launch` is zero for everything but a backend the worker established: the command then runs
 * exactly as it was typed and nothing else here is set. Otherwise the shell executes `launcher`
 * with `arguments` (its own argument vector, the launcher first) and `environment` added to that
 * one child's environment. Both vectors end with a null pointer.
 */
typedef struct {
    int launch;
    char *launcher;
    char **arguments;
    char **environment;
} kr_resolution;

/* Non-zero in the root shell process that registered, and in no process forked from it. */
int kr_bridge_root_process(void);

/*
 * Asks the worker what one invocation resolves to, and waits at most KR_ANSWER_WAIT_MS.
 *
 * `argv` is what the shell is about to run and `executable` is the absolute path its own search
 * found, in `cwd` at `cwd_revision`. Returns `out->launch`. A bypass, a refusal, the deadline, a
 * lost endpoint and a launcher that is not an absolute path to an executable file all leave it
 * zero, and the shell runs the command as it was typed.
 */
int kr_bridge_resolve(const char *const *argv, size_t argc, const char *executable,
                      const char *cwd, unsigned long cwd_revision,
                      unsigned long prompt_generation, kr_resolution *out);

/* Releases what a resolution holds. */
void kr_bridge_resolution_free(kr_resolution *resolution);

#endif /* KR_BRIDGE_H */
