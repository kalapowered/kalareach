/*
 * The Readline half of the KalaReach root-editor bridge.
 *
 * Copyright (c) Kala Powered.
 *
 * This file is added to GNU Bash's bundled Readline by the KalaReach reader patch set and is
 * distributed under the GNU General Public Licence, version 3 or later, that governs the rest of
 * the package; see shells/bash/LICENSE.
 *
 * Readline's buffering is the reason this bridge exists in the reader rather than around it. The
 * reader returns pending and macro input without consulting the character callback at all, and
 * `rl_gather_tyi` can call that callback while it fills a buffer, before preceding characters have
 * changed `rl_end`. So the mailbox is read at the one point where the reader has taken everything
 * it had and is waiting for the terminal, and the end-of-file decision is taken immediately before
 * Readline's own end-of-file branch, after the next character has been selected.
 */

#define READLINE_LIBRARY

#if defined (HAVE_CONFIG_H)
#  include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#include "rldefs.h"
#include "readline.h"
#include "rlprivate.h"

#include "kr_bridge.h"
#include "kr_bridge_rl.h"

/*
 * The reader's own revisions.
 *
 * A prompt generation counts primary readers; a reader revision counts every reader. The buffer
 * revision changes when the line's contents change, which is what a launch's expectation is
 * checked against.
 */
static unsigned long kr_prompt_generation;
static unsigned long kr_reader_revision;
static unsigned long kr_buffer_revision;
static unsigned long kr_buffer_hash;
static unsigned long kr_cwd_revision;
static char kr_cwd_seen[4096];
static int kr_inside_reader;

static int kr_last_source = KR_SOURCE_TERMINAL;

/* True while Readline is filling its own buffer rather than waiting with nothing left to read.
 * `rl_gather_tyi` calls the character function too, and that is not the reader's idle point. */
static int kr_gathering;

/* Whether this wait has already reported the reader idle. */
static int kr_idle_reported;

/* What the reader is in the middle of, where Readline keeps no state of its own for it. */
static int kr_pending_quoted;
static int kr_pending_paste_open;

/* A takeover's cancellation: requested inside the wait, acted on by the next read. */
static int kr_cancel_requested;

/* A launch this reader installed, so a revocation can take exactly that text back out. */
static int kr_installed_chars;

static unsigned long
kr_hash_line (void)
{
  unsigned long hash = 2166136261UL;
  int i;

  for (i = 0; i < rl_end; i++)
    {
      hash ^= (unsigned long) (unsigned char) rl_line_buffer[i];
      hash *= 16777619UL;
    }
  hash ^= (unsigned long) rl_end;
  hash *= 16777619UL;
  return hash;
}

static void
kr_track_buffer (void)
{
  unsigned long hash = kr_hash_line ();

  if (hash != kr_buffer_hash)
    {
      kr_buffer_hash = hash;
      kr_buffer_revision++;
    }
}

static void
kr_track_cwd (void)
{
  char here[sizeof (kr_cwd_seen)];

  if (getcwd (here, sizeof (here)) == 0)
    return;
  if (strcmp (kr_cwd_seen, here) != 0)
    {
      strcpy (kr_cwd_seen, here);
      kr_cwd_revision++;
    }
}

static int
kr_context (void)
{
  return kr_shell_prompt_context ();
}

/* Whether the terminal has anything to give, without waiting for it.
 *
 * Readline's own `_rl_input_available` waits up to a tenth of a second, which is not something a
 * reader answering a fence can afford.
 */
static int
kr_terminal_ready (void)
{
#if defined (HAVE_SELECT)
  fd_set readfds;
  struct timeval nothing;
  int fd = rl_instream ? fileno (rl_instream) : 0;

  FD_ZERO (&readfds);
  FD_SET (fd, &readfds);
  nothing.tv_sec = 0;
  nothing.tv_usec = 0;
  return select (fd + 1, &readfds, (fd_set *)NULL, (fd_set *)NULL, &nothing) > 0;
#else
  return 0;
#endif
}

static int
kr_keymap (void)
{
  const char *name = rl_get_keymap_name (rl_get_keymap ());

  if (name == 0)
    return KR_KEYMAP_CUSTOM;
  if (strcmp (name, "emacs") == 0 || strcmp (name, "emacs-standard") == 0
      || strcmp (name, "emacs-meta") == 0 || strcmp (name, "emacs-ctlx") == 0)
    return KR_KEYMAP_EMACS;
  if (strcmp (name, "vi-insert") == 0)
    return KR_KEYMAP_VI_INSERT;
  if (strcmp (name, "vi") == 0 || strcmp (name, "vi-move") == 0
      || strcmp (name, "vi-command") == 0)
    return KR_KEYMAP_VI_COMMAND;
  return KR_KEYMAP_CUSTOM;
}

void
kr_shell_reader_state (kr_reader_state *out)
{
  size_t keys = (size_t) rl_key_sequence_length;
  int buffered = _rl_kr_buffered ();
  int macro_left = _rl_kr_macro_remaining ();

  memset (out, 0, sizeof (*out));
  kr_track_buffer ();
  /* A `bind -x` command can change directory and return to the same prompt, so the revision is
     read where it is reported rather than once at entry. */
  kr_track_cwd ();

  out->prompt_generation = kr_prompt_generation;
  out->reader_revision = kr_reader_revision;
  out->reader_context = kr_context ();

  out->buffer_revision = kr_buffer_revision;
  out->buffer_empty = (rl_end == 0);
  out->keymap = kr_keymap ();

  out->pending_quoted_insertion = kr_pending_quoted;
  out->pending_macro_input = (macro_left > 0) || RL_ISSTATE (RL_STATE_MACROINPUT);
  out->pending_search = RL_ISSTATE (RL_STATE_ISEARCH | RL_STATE_NSEARCH) ? 1 : 0;
  /* Being accumulated, or accumulated and waiting for the command it applies to. */
  out->pending_numeric_argument =
      (RL_ISSTATE (RL_STATE_NUMERICARG) || rl_explicit_arg) ? 1 : 0;
  out->pending_multikey_sequence =
      RL_ISSTATE (RL_STATE_MULTIKEY | RL_STATE_METANEXT) ? 1 : 0;
  out->pending_vi_motion = RL_ISSTATE (RL_STATE_VIMOTION | RL_STATE_CHARSEARCH) ? 1 : 0;
  out->pending_paste = kr_pending_paste_open;

  if (keys > KR_KEYS_MAX)
    keys = KR_KEYS_MAX;
  memcpy (out->keys, rl_executing_keyseq, keys);
  out->keys_len = keys;
  /* What the reader itself still holds, and what is queued ahead of the terminal. */
  out->pending_bytes = (unsigned long) (buffered > 0 ? buffered : 0);
  out->queued_keys = (unsigned long) ((macro_left > 0 ? macro_left : 0)
                                      + (rl_pending_input ? 1 : 0));

  out->tty_typeahead_drained = (buffered <= 0) && (kr_terminal_ready () == 0);
  out->macro_input_drained = (macro_left <= 0) && (rl_pending_input == 0);
  out->partial_key_drained = !RL_ISSTATE (RL_STATE_MULTIKEY | RL_STATE_METANEXT);

  out->cwd_revision = kr_cwd_revision;
}

int
kr_shell_install_command (const char *text, size_t len)
{
  char *line;

  if (rl_end != 0 || len == 0)
    return 0;
  line = (char *) malloc (len + 1);
  if (line == 0)
    return 0;
  memcpy (line, text, len);
  line[len] = '\0';
  rl_replace_line (line, 0);
  free (line);
  rl_point = rl_end;
  kr_installed_chars = rl_end;
  kr_track_buffer ();
  return rl_end > 0;
}

int
kr_shell_remove_installed (void)
{
  if (kr_installed_chars <= 0)
    return 0;
  /* Only the text this launch installed comes out, and only while it is still all there. */
  if (rl_end == kr_installed_chars)
    {
      rl_replace_line ("", 0);
      rl_point = rl_end = 0;
    }
  kr_installed_chars = 0;
  rl_done = 0;
  RL_UNSETSTATE (RL_STATE_DONE);
  kr_track_buffer ();
  return 1;
}

void
kr_shell_accept_line (void)
{
  /* The editor's own acceptance, so history, redisplay and the returned line are Readline's. */
  rl_newline (1, '\n');
}

void
kr_shell_cancel_key_wait (kr_cancellation *out)
{
  int macro_left = _rl_kr_macro_remaining ();
  int buffered = _rl_kr_buffered ();

  out->partial_escape = RL_ISSTATE (RL_STATE_METANEXT) ? 1 : 0;
  out->multikey_sequence = RL_ISSTATE (RL_STATE_MULTIKEY) ? 1 : 0;
  out->quoted_insertion = kr_pending_quoted;
  out->vi_motion = RL_ISSTATE (RL_STATE_VIMOTION | RL_STATE_CHARSEARCH) ? 1 : 0;
  out->macro_input = (macro_left > 0) || RL_ISSTATE (RL_STATE_MACROINPUT);
  out->buffer_preserved = 1;

  if (out->partial_escape || out->multikey_sequence || out->quoted_insertion || out->vi_motion
      || out->macro_input)
    {
      out->discarded_bytes = (unsigned long) ((macro_left > 0 ? macro_left : 0)
                                              + (buffered > 0 ? buffered : 0)
                                              + (rl_pending_input ? 1 : 0));
      /*
       * The reader is inside something, so the next read returns KR_RL_CANCEL. Readline's own
       * abort path then pops the executing macro, clears the pending input and resets the
       * argument, and the edit buffer is left as it was.
       */
      kr_cancel_requested = 1;
      kr_idle_reported = 0;
    }
  else
    {
      /*
       * Nothing was in progress, so there is nothing to unwind and nothing to throw away. The
       * reader stays in the read it is in, and a sequence the person starts afterwards is not
       * taken for one this cancellation ended.
       */
      out->discarded_bytes = 0;
    }
}

void
kr_rl_cancel_observed (void)
{
  /* The read that the cancellation ended has returned, so the reader is out of whatever it was in
     and the endpoint can be read again. */
  kr_cancel_requested = 0;
  kr_gathering = 0;
  kr_bridge_cancel_settled ();
  /* The reader's queues have changed, so the next wait reports itself idle again and the worker
     gets its retry point. */
  kr_idle_reported = 0;
}

/*
 * Single quotes, always.
 *
 * An argument vector is installed as literal arguments. A bare word at command position would be
 * a reserved word, an assignment or an alias rather than the name the caller asked to run, so
 * every argument is quoted including the first.
 */
char *
kr_shell_quote_argument (const char *argument)
{
  size_t len = strlen (argument);
  size_t i;
  char *quoted;
  size_t used = 0;

  /* Worst case: every byte is a quote, which becomes four bytes. */
  quoted = (char *) malloc (len * 4 + 3);
  if (quoted == 0)
    return 0;
  quoted[used++] = '\'';
  for (i = 0; i < len; i++)
    {
      if (argument[i] == '\'')
        {
          quoted[used++] = '\'';
          quoted[used++] = '\\';
          quoted[used++] = '\'';
          quoted[used++] = '\'';
        }
      else
        quoted[used++] = argument[i];
    }
  quoted[used++] = '\'';
  quoted[used] = '\0';
  return quoted;
}

void
kr_shell_print_hint (const char *line)
{
  fprintf (rl_outstream, "\n%s\n", line);
  fflush (rl_outstream);
  rl_on_new_line ();
  rl_redisplay ();
}

int
kr_shell_veof (void)
{
  struct termios settings;
  int fd = rl_instream ? fileno (rl_instream) : 0;

  if (tcgetattr (fd, &settings) < 0)
    return -1;
#ifdef _POSIX_VDISABLE
  if (settings.c_cc[VEOF] == _POSIX_VDISABLE)
    return -1;
#endif
  if (settings.c_cc[VEOF] == 0)
    return -1;
  return (int) (unsigned char) settings.c_cc[VEOF];
}

/* ---- the reader's boundaries ------------------------------------------------------------------ */

void
kr_rl_setup (void)
{
  kr_bridge_activate ();
}

void
kr_rl_key_taken (void)
{
  /* The reader has a key, so it is not filling its own buffer and the next wait is a fresh chance
     to be idle. Clearing the guard here is what keeps a gather that a signal cut short from
     leaving the mailbox unread. */
  kr_gathering = 0;
  kr_idle_reported = 0;
}

void
kr_rl_source (int source)
{
  kr_last_source = source;
}

void
kr_rl_pending_quoted_insertion (int active)
{
  kr_pending_quoted = active;
}

void
kr_rl_pending_paste (int active)
{
  kr_pending_paste_open = active;
}

void
kr_rl_enter (void)
{
  if (kr_bridge_registered () == 0)
    return;
  if (kr_inside_reader)
    kr_bridge_editor_leave (KR_LEAVE_READER_TAKEOVER);
  kr_reader_revision++;
  if (kr_context () == KR_CONTEXT_PRIMARY)
    kr_prompt_generation++;
  kr_track_cwd ();
  kr_buffer_hash = kr_hash_line ();
  kr_buffer_revision++;
  kr_installed_chars = 0;
  kr_cancel_requested = 0;
  kr_gathering = 0;
  kr_pending_quoted = kr_pending_paste_open = 0;
  kr_idle_reported = 0;
  /* A reader that is starting is not inside anything a cancellation has to unwind. */
  kr_bridge_cancel_settled ();
  kr_last_source = KR_SOURCE_TERMINAL;
  kr_inside_reader = 1;
  kr_bridge_editor_enter ();
}

void
kr_rl_leave (int accepted)
{
  if (kr_bridge_registered () == 0 || kr_inside_reader == 0)
    {
      kr_inside_reader = 0;
      return;
    }
  kr_inside_reader = 0;
  kr_installed_chars = 0;
  kr_cancel_requested = 0;
  kr_bridge_cancel_settled ();
  if (accepted)
    {
      /* The accepted line is reported from the reader, inside the fence, before the leave: a
	 record sent after it could only ever say that nothing could be established. */
      kr_bridge_command_accepted ();
      kr_bridge_editor_leave (KR_LEAVE_COMMAND_ACCEPTED);
    }
  else
    kr_bridge_editor_leave (KR_LEAVE_ROOT_EXIT);
}

void
kr_rl_idle (void)
{
  if (kr_bridge_registered () == 0 || kr_gathering)
    return;
  /* Everything Readline had buffered has been taken, so this is the reader's idle point. */
  if (kr_idle_reported == 0 && _rl_kr_buffered () <= 0 && _rl_kr_macro_remaining () <= 0)
    {
      /* One of the three points the worker retries a withheld fence at. */
      kr_idle_reported = 1;
      kr_bridge_reader_idle ();
    }
  kr_bridge_service ();
}

void
kr_rl_gathering (int active)
{
  kr_gathering = active;
}

int
kr_rl_wait (void)
{
  if (kr_bridge_registered () == 0 || kr_gathering)
    return 0;
  kr_bridge_service ();
  if (kr_cancel_requested)
    return 1;
  return rl_done != 0;
}

int
kr_rl_fd (void)
{
  return kr_bridge_fd ();
}

unsigned long
kr_rl_prompt_generation (void)
{
  return kr_prompt_generation;
}

int
kr_rl_pre_eof (int key)
{
  kr_rl_key_taken ();
  if (kr_bridge_managed () == 0)
    return KR_NATIVE;
  return kr_bridge_pre_eof (key, kr_last_source);
}
