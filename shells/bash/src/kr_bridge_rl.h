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

/*
 * Called with an Escape the reader has just taken from the terminal or its typeahead as a key.
 *
 * When the rest of a host's answer to a question an application asked has already been delivered,
 * the whole answer is taken here, so no part of it is a key, and the call returns non-zero. An
 * answer that begins at a later Escape, behind the person's own, is taken too: the call returns
 * zero, the Escape is the key, and the bytes between stay in the typeahead. Otherwise it returns
 * zero with every byte it looked at back in the reader's typeahead, in order, for the key lookup.
 * It never waits for a byte the terminal has not delivered. An Escape that is a byte of pasted
 * text Readline put back to read again is not offered to it at all.
 */
int kr_rl_host_reply_dropped (void);

/*
 * Called when a check for input says the terminal holds some and the typeahead is empty, before
 * the check reports it: a caller that asks first reads a key next and waits for it, so an answer
 * that is all the terminal holds must not be reported as one.
 *
 * Takes a whole answer at the front of the terminal's bytes and returns non-zero, with any keys
 * the person typed before it in the typeahead. Otherwise it returns zero with every byte it
 * looked at back in the typeahead, in order. It never waits for a byte the terminal has not
 * delivered.
 */
int kr_rl_drop_delivered_replies (void);

/* The operations whose key wait a takeover has to be able to end. */
void kr_rl_pending_quoted_insertion (int active);
void kr_rl_pending_paste (int active);

/* The prompt the next primary reader will start at. */
unsigned long kr_rl_prompt_generation (void);

/*
 * Non-zero from the moment a line of the shell is accepted until the next primary reader starts:
 * the commands that run in between are that line's, and nothing else is.
 */
int kr_rl_line_running (void);

/* The working directory now and the revision it is at, or NULL when it cannot be read. */
const char *kr_rl_cwd (unsigned long *revision);

/* The status the last command line finished with, as the shell itself keeps it. */
int kr_shell_last_status (void);

/* Puts one variable in the shell's own exported environment. */
void kr_shell_export (const char *name, const char *value);

/* The shell's own word list, which only the shell's half of the bridge reads. */
struct word_list;

/*
 * The executor's question, before it forks an external command it found on the search path with
 * no pipe and in the foreground. `command` is what the search found and `words` what will run.
 *
 * Returns non-zero when the command is to run through the integration's launcher, and then fills
 * the launcher's own vector and the variables to add. Both stay the bridge's until the next call.
 */
int kr_bash_resolve (struct word_list *words, const char *command, char ***launch,
		     char ***environment);

/*
 * In the forked child, in place of the command: starts the launcher with `environment` added to
 * `base`. Returns only when the launcher could not be started; the command then runs as typed.
 */
void kr_bash_launch (char **launch, char **environment, char **base);

/* Counts Readline holds privately, for the fence proof. */
int _rl_kr_buffered (void);

/* The next byte already delivered, from the typeahead and then the terminal's queue, or -1. It
   stops at a byte of pasted text that Readline put back to read again: no answer runs into one. */
int _rl_kr_delivered_byte (void);
int _rl_kr_macro_remaining (void);

/* Puts a byte of pasted text, which Readline collected and will read again as a key, at the front
   of the typeahead. The byte is marked, and the reader does not examine an Escape that is marked
   when Readline takes it, nor follow a run into it. Returns non-zero if the byte went in. */
int _rl_kr_unget_pasted_char (int key);

/* Puts a byte the reader took with `_rl_kr_delivered_byte' and found to be no part of an answer
   back at the front of the typeahead, as a key the person typed. What the reader takes and gives
   back is no key Readline took, so Readline's record of the marks of its own keys does not see it.
   Returns non-zero if the byte went in. */
int _rl_kr_unget_delivered_char (int key);

#endif /* KR_BRIDGE_RL_H */
