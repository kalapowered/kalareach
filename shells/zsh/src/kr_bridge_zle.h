/*
 * What the patched ZLE reader calls, and what it exposes to the bridge core.
 *
 * Copyright (c) Kala Powered.
 *
 * This file is added to Zsh by the KalaReach reader patch set and is distributed under the Zsh
 * licence that governs the rest of the package; see shells/zsh/LICENSE.
 */

#ifndef KR_BRIDGE_ZLE_H
#define KR_BRIDGE_ZLE_H

/* Loads the bridge when the editor module is set up, before the first primary reader. */
void kr_zle_setup(void);

/* The editor module is going: nothing may ask the bridge anything any more. */
void kr_zle_finish(void);

/* The reader's own boundaries, called from zleread. */
void kr_zle_enter(void);
void kr_zle_leave(int eof_sent);

/*
 * The key-sequence boundary: reads the mailbox and takes the end-of-file decision for the key the
 * reader has just resolved. Returns non-zero when the reader should continue without running the
 * binding, which is what "consume the character and continue the same reader" means.
 */
int kr_zle_boundary(void);

/* Called just before the reader waits, so a reader with nothing left to read says so. */
void kr_zle_before_wait(void);

/* Reads the mailbox while the reader waits for a key. Returns non-zero when the wait must end. */
int kr_zle_wait(void);

/*
 * The end of one pass of the read loop.
 *
 * A cancellation that ended a widget's own key wait has already done its work there, so it does
 * not survive into the next pass and take the person's next key with it.
 */
void kr_zle_pass_end(void);

/* The bridge's descriptor for the reader's own wait, or -1. */
int kr_zle_fd(void);

/* Records which of the reader's own input sources the last byte came from. */
void kr_zle_source_pushed_back(void);
void kr_zle_source_terminal(void);

/*
 * Called with an Escape the reader has just taken from the terminal as a byte of a key.
 *
 * When the terminal has already delivered the rest of a host's answer to a question an
 * application asked, the whole answer is taken here, so no part of it is a key, and the call
 * returns non-zero. An answer that begins at a later Escape, behind the person's own, is taken
 * too: the call returns zero, the Escape is the key, and the bytes between stay in the reader's
 * input. Otherwise it returns zero with every byte it looked at back in the reader's input, in
 * order, for the key lookup. It never waits for a byte the terminal has not delivered.
 */
int kr_zle_host_reply_dropped(void);

/*
 * The next byte of a key, which ZLE's own read of one byte gives, except that a host's answer
 * to a terminal query is taken out of the way and the read goes on. `timed` is what ZLE passes
 * its read: non-zero for a byte that must follow within KEYTIMEOUT. The limit runs from the
 * start of this call, so answers taken out of the way do not start it again.
 */
int kr_zle_key_byte(long timed);

/* The operations whose key wait a takeover has to be able to end. */
void kr_zle_pending_quoted_insertion(int active);
void kr_zle_pending_numeric_argument(int active);
void kr_zle_pending_paste(int active);

/* The `kr-bridge` builtin: the one-shot activation the guarded startup entry performs. */
int bin_kr_bridge(char *name, char **args, struct options *ops, int func);

#endif /* KR_BRIDGE_ZLE_H */
