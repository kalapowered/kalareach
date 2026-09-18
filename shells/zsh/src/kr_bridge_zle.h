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

/* The reader's own boundaries, called from zleread. */
void kr_zle_enter(void);
void kr_zle_leave(int eof_sent);

/*
 * The key-sequence boundary: reads the mailbox and takes the end-of-file decision for the key the
 * reader has just resolved. Returns non-zero when the reader should continue without running the
 * binding, which is what "consume the character and continue the same reader" means.
 */
int kr_zle_boundary(void);

/* Reads the mailbox while the reader waits for a key. Returns non-zero when the wait must end. */
int kr_zle_wait(void);

/* The bridge's descriptor for the reader's own wait, or -1. */
int kr_zle_fd(void);

/* Records which of the reader's own input sources the last byte came from. */
void kr_zle_source_pushed_back(void);
void kr_zle_source_terminal(void);

/* The operations whose key wait a takeover has to be able to end. */
void kr_zle_pending_quoted_insertion(int active);
void kr_zle_pending_numeric_argument(int active);
void kr_zle_pending_paste(int active);

/* The `kr-bridge` builtin: the one-shot activation the guarded startup entry performs. */
int bin_kr_bridge(char *name, char **args, struct options *ops, int func);

#endif /* KR_BRIDGE_ZLE_H */
