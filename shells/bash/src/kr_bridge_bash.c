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
#include "builtins.h"
#include "builtins/common.h"
#include "execute_cmd.h"

/* The `read' builtin's own entry point, as the generated builtin table declares it. Declared here
   rather than included, because that table is generated after this file is compiled. */
extern int read_builtin PARAMS((WORD_LIST *));

#include <readline/kr_bridge.h>
#include <readline/kr_bridge_rl.h>

int
kr_shell_prompt_context ()
{
  /*
   * The `read' builtin reading through the editor is not the root editor's prompt. Asking which
   * builtin is running answers that however the builtin is left, including through a signal or a
   * timeout: `executing_builtin' is restored by Bash's own unwind protection, and
   * `this_shell_builtin' only means anything while it is set.
   */
  if (executing_builtin && this_shell_builtin == read_builtin)
    return KR_CONTEXT_READ_BUILTIN;
  /*
   * The parser points the prompt at PS2 for every line of a command it has not finished, so a
   * reader started under that prompt is a continuation line rather than the root editor's own.
   */
  if (get_current_prompt_level () == 2)
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
