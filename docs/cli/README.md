# The `kr` command line

`kr` is a local client. It reaches the control daemon for what the daemon owns, and it reaches a
worker directly for what a session owns.

## Commands

| Command | Short | What it does |
| --- | --- | --- |
| `kr new` | `kr n` | Create one worker, pseudo-terminal and root shell under an idempotent create token |
| `kr attach <id>` | `kr a` | Attach to an existing session. It never resumes or creates a replacement |
| `kr detach [--attachment <id>]` | `kr d` | Remove an attachment |
| `kr close [id]` | `kr c` | Close a session and terminate the processes it owns |
| `kr list` | `kr l` | List sessions with their display numbers, states and shells |
| `kr status [id]` | `kr s` | Show one session's state |
| `kr doctor` | — | Read-only diagnostics |

`--help`, `--version` and `--json` work everywhere. A literal `--` ends option parsing. Neither
shell commands nor paths are assembled by interpolating text.

A session is named by its display number or its identifier. Display numbers increase within an
environment and are never reused. A number that names sessions in more than one environment is
`AMBIGUOUS_SESSION`: the command says so and stops, and never picks the first match.

## `kr new`

The presentation flags are mutually exclusive:

| Flag | What happens |
| --- | --- |
| `--attach` | Create and attach in this terminal. The default when input and output are terminals |
| `--terminal` | Create a session and open an installed terminal application on it |
| `--invisible` | Create a session with no local terminal attachment |

Without a terminal and without a flag the command stops and asks for one, rather than choosing.

`--environment`, `--cwd`, `--shell` and `--shell-mode` select execution properties. For `--attach`
the creating terminal's size is registered before the shell starts, so the first prompt is drawn at
the real geometry. An invisible session starts at 120x40.

### Shell mode

This host implements the explicitly selected `native_compat` mode: the stock shell you name, run as
an interactive session root shell. It keeps create, attach, detach, close, transfer and terminal
presentation. It does **not** claim managed empty-prompt Ctrl-D, fenced `shell.launch` or
authoritative editor-buffer observation.

In `native_compat`, Ctrl-D at the prompt does whatever that shell does, which usually means the
shell exits and the session closes. `kr detach` always works and is the way to leave a session
without ending it. The mode is printed when a session is created and appears in `kr list`,
`kr status` and the `--json` output. Asking for `managed` returns
`SHELL_INTEGRATION_UNSUPPORTED` naming `native_compat` as the available choice; it is never silently
substituted.

## `kr attach`

Attaching reads the published descriptor and challenges the worker itself, so it works while the
control daemon is restarting.

Direct mode puts the outer terminal into raw mode and forwards its bytes in order, unchanged.
Nothing is decoded into text and re-encoded, nothing is normalised and no status bar is installed.
When an application turns mouse reporting on, the outer terminal produces those events and they are
forwarded; when it turns it off, the terminal's scrollback behaves normally again.

`--take-geometry` makes this terminal the size owner. Ordinary attach never moves size ownership,
and taking input never moves it either.

### The restoration guard

A broken connection must not leave a terminal in raw mode, and the restoration has to survive the
attach process being killed — which no in-process handler can do, because `SIGKILL` runs no handler.

So the saved state lives in another process. Before the terminal is touched, `kr attach` starts
`kr-attach-guard` and gives it one end of a pipe and its own handle on the terminal.

* A clean exit restores the terminal and sends the guard a byte, and the guard leaves without
  acting.
* Any other end — a crash, `SIGKILL`, the machine running out of memory — closes the pipe. The
  guard's read returns end of file and it restores the terminal itself.

The guard runs in its own process group, so signals aimed at the attach process do not reach it, and
it handles the background-write signal so that changing the terminal from the background is not a
reason to stop it.

Its limit is stated plainly: nothing recovers a terminal whose emulator has died, because there is
nothing left to restore.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | The command succeeded |
| 1 | Something else failed |
| 2 | The arguments are not a valid request |
| 3 | No host is running for this environment |
| 4 | The named session does not exist, or the command needed one and had none |
| 5 | A display number names sessions in more than one environment |
| 6 | The command needed a terminal, or the terminal could not be changed |
| 7 | No terminal application could be opened |
| 8 | The host refused the request |

A `--json` failure carries the same information:

```json
{ "ok": false, "code": "AMBIGUOUS_SESSION", "message": "...", "exit_code": 5 }
```

## `--json` shapes

`kr list --json` returns `{ "sessions": [ ... ] }`; `kr new --json` and `kr status --json` return one
session object:

```json
{
  "session_id": "d6d64b2b-f6f1-4617-a07a-bb89a08cd3fd",
  "display_number": 1,
  "environment_id": "70a528be-be60-4cfb-870e-e3d3ba30344d",
  "state": "live",
  "shell_mode": "native_compat",
  "shell": "/bin/zsh",
  "cwd": "/home/example",
  "dimensions": { "columns": 120, "rows": 40 },
  "attachments": 1,
  "worker_profile": "headless_user",
  "created_at_ms": 1789484611722,
  "closure": null
}
```

A closed session carries its record instead of a null:

```json
{
  "reason": "close_requested",
  "exit_code": null,
  "signal": null,
  "ownership_coverage": "incomplete",
  "durability": "durable",
  "closed_at_ms": 1789484611722
}
```

`kr doctor --json` returns `{ "host": { ... }, "doctor": { "healthy": true, "checks": [ ... ] } }`.
The command exits non-zero when a check did not pass.
