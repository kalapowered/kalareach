/*
 * The shell half of the KalaReach root-editor bridge: the parts only Bash itself can do.
 *
 * Copyright (c) Kala Powered.
 *
 * This file is added to GNU Bash by the KalaReach reader patch set and is distributed under the
 * GNU General Public Licence, version 3 or later, that governs the rest of the package; see
 * shells/bash/LICENSE.
 *
 * The bridge lives in the bundled Readline, where the reader is. Removing a variable from the
 * shell's own exported environment is not something a line editor can do, so it is here.
 */

#include <config.h>

#include <stdio.h>

#include "bashtypes.h"
#include "shell.h"
#include "variables.h"

#include <readline/kr_bridge.h>
#include <readline/kr_bridge_rl.h>

/* Bash's own prompt state, which nothing outside the parser declares. */
extern char *ps2_prompt;
extern char *current_prompt_string;

int
kr_shell_prompt_context ()
{
  /*
   * The parser points the prompt at PS2 for every line of a command it has not finished, so a
   * reader started under that prompt is a continuation line rather than the root editor's own.
   */
  if (current_prompt_string != 0 && current_prompt_string == ps2_prompt)
    return KR_CONTEXT_CONTINUATION;
  return KR_CONTEXT_PRIMARY;
}

void
kr_shell_unexport (name)
     const char *name;
{
  /*
   * The bootstrap values leave the shell with the environment, so a child process started
   * afterwards inherits neither the endpoint nor the secret and the guarded startup entry is inert
   * in all of them. The bridge keeps the secret in its own memory, where a startup file cannot
   * reach it, because a reader re-established inside this shell needs it again.
   */
  unbind_variable ((char *) name);
}
