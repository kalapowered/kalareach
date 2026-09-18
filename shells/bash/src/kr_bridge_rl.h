/*
 * What the patched Readline reader calls, and what it exposes to the bridge core.
 *
 * Copyright (c) Kala Powered.
 *
 * This file is added to GNU Bash's bundled Readline by the KalaReach reader patch set and is
 * distributed under the GNU General Public Licence, version 3 or later, that governs the rest of
 * the package; see shells/bash/LICENSE.
 */

#ifndef KR_BRIDGE_RL_H
#define KR_BRIDGE_RL_H

/*
 * What a read returns when the reader has produced no character and the caller must go back to the
 * top of its loop: a takeover ended a pending key wait, or a launch was installed and accepted.
 *
 * It is negative and distinct from EOF and READERR, so every place in Readline that already treats
 * a negative key as an abort ends its own operation through its own path, with the edit buffer
 * untouched. That is the native cancellation this contract requires.
 */
#define KR_RL_CANCEL (-3)

/* Loads the bridge, before the user's startup files and before the first primary reader. */
void kr_rl_setup (void);

/* The reader has consumed everything it had buffered and is about to wait for the terminal. */
void kr_rl_idle (void);

/* Reads the mailbox while the reader waits. Returns non-zero when the wait must end. */
int kr_rl_wait (void);

/* The bridge's descriptor for the reader's own wait, or -1. */
int kr_rl_fd (void);

/* The end-of-file decision, immediately before Readline's own end-of-file branch. */
int kr_rl_pre_eof (int key);

/* The reader's own boundaries, called from readline's setup and teardown. */
void kr_rl_enter (void);
void kr_rl_leave (int accepted);

/* A cancellation the reader has now acted on. */
void kr_rl_cancel_observed (void);

/* Readline is filling its own buffer rather than waiting with nothing left to read. */
void kr_rl_gathering (int active);

/* The reader has taken a key, so the next wait is a fresh chance to report itself idle. */
void kr_rl_key_taken (void);

/*
 * Which reader is running: the shell's primary prompt, a continuation line of a command its
 * parser has not finished, or its `read` builtin reading through the editor. Only the shell
 * knows, so the shell supplies it.
 */
int kr_shell_prompt_context (void);

/* Where the character the reader has just taken came from. */
void kr_rl_source (int source);

/* The operations whose key wait a takeover has to be able to end. */
void kr_rl_pending_quoted_insertion (int active);
void kr_rl_pending_paste (int active);

/* The prompt the next primary reader will start at. */
unsigned long kr_rl_prompt_generation (void);

/* Counts Readline holds privately, for the fence proof. */
int _rl_kr_buffered (void);
int _rl_kr_macro_remaining (void);

#endif /* KR_BRIDGE_RL_H */
