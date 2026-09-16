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

Direct mode puts the outer terminal into raw mode and writes what the host sends it, in order.
Nothing is decoded into text and re-encoded, nothing is normalised and no status bar is installed.
When an application turns mouse reporting on, the outer terminal produces those events and they are
forwarded; when it turns it off, the terminal's scrollback behaves normally again.

### What the command does to a keystroke

Nothing. It is worth saying as a list, because each item is something a terminal client is often
built to do and this one must not:

| What the person does | What the command sends |
| --- | --- |
| Presses a key, any key | the bytes their terminal produced, unchanged |
| Presses Return | the byte their terminal produced, whichever it is; no line ending is rewritten |
| Pastes text | the bytes the terminal sent, delimiters and all, so the application sees one paste |
| Types a character the command cannot decode | the bytes; nothing is replaced with a substitution character |
| Types a combining mark | two scalars, because that is what arrived; nothing is composed |
| Turns the wheel | the mouse report their terminal produced, never an arrow key |
| Clicks or drags | the mouse report, in whichever protocol the application enabled |
| Moves the window's focus | a focus event, and only while this attachment holds the input lease |

A terminal that may not type is told so once, on standard error, and goes on watching. That is what
happens under `--no-probe`: the host checks that a controller can supply the encoding the
application has negotiated, and a terminal nobody was allowed to ask about cannot be shown to. It is
also what happens when an application turns on a keyboard protocol this terminal does not implement
while the attachment is running; the next keystroke is refused and the command says which of the two
it got.

What the host sends is not always every byte the application wrote. The session's canonical grid
answers the application's queries itself and routes a bell, a clipboard write or a notification to
the one attachment holding the input lease, so two attached terminals can never both answer a
question and a secret can never land on every device that happens to be watching.

`--no-probe` withholds this terminal's own declaration of what it is. The host then serves this
attachment a rendering of the session's screen rather than the byte stream, because it has not been
told what those bytes would do here. It is the conservative choice, not a faster one.

Attaching shows the session's screen immediately, drawn from the host's canonical grid. It is never
the replayed history: replaying those bytes would replay whatever they contained.

`--take-geometry` makes this terminal the size owner. Ordinary attach never moves size ownership,
and taking input never moves it either.

### The restoration guard

A broken connection must not leave a terminal in raw mode, and the restoration has to survive the
attach process being killed — which no in-process handler can do, because `SIGKILL` runs no handler.

So the saved state lives in another process. `kr attach` starts `kr-attach-guard` before anything
touches the terminal and gives it one end of a pipe, its own handle on the terminal and the
terminal's complete mode state.

Only then does it ask the terminal anything. The capability handshake is bounded and synchronous: it
asks which keyboard protocols the terminal has negotiated (the Kitty protocol's flags and xterm's
`modifyOtherKeys` level, neither of which termios describes) and ends with the device-attributes
request every terminal answers. Reading the answers means putting the terminal into a mode where
they arrive, which is why the guard exists first. The answers then reach the guard over the same
pipe.

A terminal that does not finish the handshake within a second fails this attach with
`TERMINAL_PROBE_FAILED` and exit code 6; it does not begin forwarding input on a stream that may
still receive a late reply. What the person typed while the host was asking is kept apart from the
answers and is the first input the attachment forwards.

Both paths out put everything back: the mode words, the control characters, the sequences that undo
what an application may have left enabled, and then the keyboard protocols the terminal had chosen
for itself. A cleanup that runs before the attachment began forwarding, because the handshake failed
or the process was killed during it, leaves those protocols alone: nothing that had happened could
have changed them.

`--no-probe` asks the terminal nothing at all, which is what makes it the choice for a terminal that
does not answer. The session's own keyboard modes are still cleared when the attachment ends, since
the session could have set them, but nothing comes back afterwards: that is what never asking costs.

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
