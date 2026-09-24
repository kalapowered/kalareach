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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "bashtypes.h"
#include "shell.h"
#include "variables.h"
#include "builtins.h"
#include "builtins/common.h"
#include "execute_cmd.h"
#include "trap.h"

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

int
kr_shell_last_status ()
{
  return last_command_exit_value;
}

void
kr_shell_export (name, value)
     const char *name;
     const char *value;
{
  SHELL_VAR *var;

  /*
   * The line's own commands inherit it, and nothing started after the line has ended does: the
   * reader takes it out of the environment again at the next prompt.
   */
  var = bind_variable ((char *) name, (char *) value, 0);
  if (var)
    set_auto_export (var);
}

/* What the command being started now runs as, held until the next command asks. */
static kr_resolution kr_resolution_now;

int
kr_bash_resolve (words, command, launch, environment)
     WORD_LIST *words;
     const char *command;
     char ***launch;
     char ***environment;
{
  const char *cwd;
  char *executable;
  char **argv;
  size_t size;
  unsigned long revision = 0;
  int argc, launching;

  *launch = *environment = (char **) NULL;
  kr_bridge_resolution_free (&kr_resolution_now);

  /*
   * A command of the line the person typed, started by the root shell itself: never one that a
   * function, a sourced file or a startup file, an eval, a trap or a prompt command runs, and
   * never one in a subshell.
   */
  if (kr_rl_line_running () == 0 || kr_bridge_root_process () == 0)
    return 0;
  if (interactive_shell == 0 || subshell_environment || sourcelevel || variable_context
      || parse_and_execute_level || running_trap)
    return 0;
  if (words == 0 || command == 0 || *command == '\0')
    return 0;
  cwd = kr_rl_cwd (&revision);
  if (cwd == 0)
    return 0;

  /* The file the search found, named absolutely: a relative directory on the path is the working
     directory's. */
  size = strlen (cwd) + strlen (command) + 2;
  executable = (char *) malloc (size);
  if (executable == 0)
    return 0;
  if (*command == '/')
    snprintf (executable, size, "%s", command);
  else
    snprintf (executable, size, "%s/%s", cwd, command);

  /* The words point into the command being run; only the vector itself is this call's. */
  argv = strvec_from_word_list (words, 0, 0, &argc);
  launching = kr_bridge_resolve ((const char *const *) argv, (size_t) argc, executable, cwd,
				 revision, kr_rl_prompt_generation (), &kr_resolution_now);
  free (argv);
  free (executable);
  if (launching)
    {
      *launch = kr_resolution_now.arguments;
      *environment = kr_resolution_now.environment;
    }
  return launching;
}

/* Whether two NAME=value entries name the same variable. */
static int
kr_same_name (a, b)
     const char *a;
     const char *b;
{
  while (*a && *a != '=' && *a == *b)
    {
      a++;
      b++;
    }
  return (*a == '=' || *a == '\0') && (*b == '=' || *b == '\0');
}

void
kr_bash_launch (launch, environment, base)
     char **launch;
     char **environment;
     char **base;
{
  char **merged;
  int count, added, used, i, j;

  for (count = 0; base && base[count]; count++)
    ;
  for (added = 0; environment && environment[added]; added++)
    ;
  merged = (char **) malloc ((count + added + 1) * sizeof (char *));
  if (merged == 0)
    return;
  used = 0;
  for (i = 0; i < count; i++)
    {
      /* A variable the backend names replaces the one the shell would have passed. */
      for (j = 0; j < added; j++)
	if (kr_same_name (base[i], environment[j]))
	  break;
      if (j == added)
	merged[used++] = base[i];
    }
  for (j = 0; j < added; j++)
    merged[used++] = environment[j];
  merged[used] = (char *) NULL;
  execve (launch[0], launch, merged);
  /* The launcher could not be started, so the command runs as it was typed: with the shell's own
     environment and nothing the backend named. */
  free (merged);
}
