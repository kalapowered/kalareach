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
| `kr question [list/show/answer/cancel]` | — | Read and answer the questions agents are waiting on |
| `kr skill [install/status/remove]` | — | Install the contact skill and its tool configuration for an agent |
| `kr agent-tools --stdio` | — | Run the contact tools for the agent that launched this process |
| `kr doctor` | — | Read-only diagnostics |
| `kr host power` | — | Show or change whether this host stays awake for work it has admitted |

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

Where the session runs is a separate choice, and these two are mutually exclusive as well:

| Flag | What happens |
| --- | --- |
| `--desktop` | Run in this host's current desktop. The session closes with `desktop_lost` when that desktop's login ends |
| `--headless` | Run in this host's headless user context, which is given none of the desktop's own handles. What that means for reaching a desktop differs by platform, and `kr doctor` says which |

Neither is the default. Without one, the session runs where the host says it creates sessions: a
desktop host uses its own desktop and an SSH-only or headless installation uses its configured
headless context. The command prints the execution context and where the choice came from before it
creates anything, and the receipt records the context the session actually got:

```text
execution context desktop_bound (this host's default)
created session 1 (d6d64b2b-f6f1-4617-a07a-bb89a08cd3fd)
execution context desktop_bound: desktop macos_security_session:uid=501:session=100019:generation=1788258227274902:boot=3239...
```

`--invisible` is about the terminal and nothing else. An invisible session in a desktop context
keeps that desktop's access, so a command inside it can open a browser on the screen in front of
you, and it closes with the desktop like any other desktop-bound session. It is not a headless
mode: what survives a logout is decided by the execution context, not by whether a terminal was
opened.

`--environment`, `--cwd`, `--shell` and `--shell-mode` select execution properties. For `--attach`
the creating terminal's size is registered before the shell starts, so the first prompt is drawn at
the real geometry. An invisible session starts at 120x40.

`--palette` chooses the colours the session starts with, and creation is the only moment it can be
chosen: afterwards the palette is the session's own, and an attachment joining from a differently
themed terminal is shown what the session has rather than what it has itself.

| Value | What the session records |
| --- | --- |
| `light` | The light preset |
| `dark` | The dark preset |
| `probe` | This terminal's own default foreground and background, as a client preference |
| absent | The profile default |

`probe` asks this terminal through the same bounded exchange an attach uses, for its default
foreground and its default background and nothing else: one second for the whole of it, a guard
holding this terminal's state throughout, and the replies never reaching an application. What the
person typed while the question was out is theirs, and with `--attach` it is the first input the
attachment forwards, in front of its own handshake's typing; with `--terminal` there is nothing
forwarding input here, so the command says how many bytes it could not deliver. A terminal that
does not report both colours has shared no palette, and the command says so rather than recording a
provenance nothing measured. `--invisible --palette probe` is refused for the same reason: there is
no terminal to ask.

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

Shift and Page Up, and Shift and Page Down, are the exception, and they are not input: they move
the window this terminal is looking through and never reach the session. The command reports the
new position through `attachment.viewport`, the host installs the pages that cover it, and the
input lease does not move: section 8 puts passive scrollback among the things that never seize it,
so a terminal that may not type can still read what is above the live page. A step is one window
less the line that joins the two pages, and a read of several of the key is that many pages. The
wheel does the same while the window is above the live page, where this terminal's own scrollback
holds nothing and the reports would otherwise address rows the application's grid does not have.

A read is one of those keys or it is the session's, whole and unchanged. That is the rule rather
than a reader that looks inside a batch, because looking inside is how a command starts altering
what somebody typed: it would have to hold back the beginning of a sequence a read boundary cut in
half and decide what a key means among bytes it did not recognise. What arrives among other bytes
is forwarded like every other byte, so a key that reaches the command that way scrolls nothing and
the person presses it again.

Bracketed paste is the one piece of context the command keeps, and it keeps it by watching the
bytes as they go past rather than by holding any of them: a start delimiter opens a paste and an
end delimiter closes it, wherever in a read each one falls and whether or not a read boundary cut
it in half, and while a paste is open nothing is a key or a pointer report. Pasted text therefore
reaches the session byte for byte. A paste a terminal sends without delimiters at all is text the
command cannot tell from typing.

The window this terminal is looking through is the session's answer to say. A scroll-back report
waits for the one before it, and what the person presses meanwhile is measured from where the
window actually landed. A report about this terminal's *size* goes out when the size changes,
whatever else is in flight, because a window drawn for a size the terminal no longer has is wrong
about every row; it carries what the newest report still waiting for an answer asked for, and
otherwise the window the screen says this terminal is drawing.

They are this terminal's keys only where this terminal has no history of its own. A terminal being
handed the session's bytes has them, so its own scrollback holds what scrolled past and the command
takes none of its keys; a terminal drawing a projection was never sent them, and the session's
window is the only way above its screen. They are also the application's while a full-screen
program is running, because its buffer keeps no history and it has its own use for those keys; the
window comes back to the live screen with the screen that program took.

While this terminal is showing rows above the live page no pointer report reaches the application. It would address
a cell of the live screen, and the rows the person is looking at are not on it; section 8 gives that
case its answer, that input outside the visible grid has no application effect. Every report is
taken, whether it arrives on its own, among other bytes, or in halves a read boundary cut it into,
and the wheel among them moves the window. Half of one waits a moment for the rest; if nothing
comes it was not a report and it goes to the application, which is the one way a report split by a
long pause reaches it. Inside a bracketed paste nothing is taken at all. Typing goes to the application wherever the window is,
and with `--follow-live` the first key brings the window back to the live screen, because what a
person types is answered there.

The command does not map pointer coordinates for a window that is panned across the columns; that
belongs with the rest of a window's pointer handling.

A window stays where the person put it while the session goes on writing underneath. `--follow-live`
brings it back to the live screen as soon as the session writes something, which the command reads
from the session's own output cursor moving rather than from why a screen arrived. It is this
command's own choice and nothing on the wire follows or does not follow.

A terminal that may not type at all is told so once, on standard error, and goes on watching. That
is what happens under `--no-probe`: the host checks that a controller can supply the encoding the
application has negotiated, and a terminal nobody was allowed to ask about cannot be shown to.

Losing the keys part way through is a different thing and ends the attachment. An application can
turn on a keyboard protocol the outer terminal does not implement, and the host then takes the keys
rather than let it send an encoding that means other keys; the next keystroke is refused with
`LEASE_LOST`, and the command exits with the refused-request code (8) after putting the terminal
back. Nothing reacquires them by itself: attaching again while that protocol is in force gives a
terminal that watches, and attaching once the application has left it gives one that can type.

What the host sends is not always every byte the application wrote. The session's canonical grid
answers the application's queries itself and routes a bell, a clipboard write or a notification to
the one attachment holding the input lease, so two attached terminals can never both answer a
question and a secret can never land on every device that happens to be watching.

`--no-probe` withholds this terminal's own declaration of what it is. The host then serves this
attachment the canonical grid rather than the byte stream, because it has not been told what those
bytes would do here. It is the conservative choice, not a faster one.

Attaching shows the session's screen immediately, from the host's canonical grid. It is never the
replayed history: replaying those bytes would replay whatever they contained.

### Projected mode

A terminal of any other size, or one the host will not hand the stream to, is projected: it receives
the canonical grid as state and draws it itself. What arrives is one snapshot, its rows in bounded
pages, and then one bounded update per batch of output, each naming the base it continues from. The
command draws each change at canonical cell positions, with autowrap off and an absolute cursor
address for every run, so a glyph this terminal measures differently cannot wrap or scroll anything.
A cluster the window's edge falls inside becomes a space rather than half a character.

A window narrower or shorter than the session shows the part it has room for. Nothing is reflowed:
what is outside the window is not drawn, and a line the application wrapped is drawn as two rows,
which is what a destination told about a row it has drawn itself can carry.

An update this terminal cannot apply — one continuing from a screen it does not hold, or from
another projection generation — is not drawn. The command asks the session for a fresh screen
instead, which is what the contract says to do and is cheaper than reasoning about what was missed.

Two things are drawn only when they exist: the outer terminal keeps whatever it was showing while a
snapshot's pages are still arriving, because a screen half installed is not the session's screen,
and a pending wrap is reported rather than reproduced, because every cursor placement clears one.

`--take-geometry` makes this terminal the size owner. Ordinary attach never moves size ownership,
and taking input never moves it either.

A frame also establishes the coordinate system its addresses are written in. Origin mode off, no
margins, the whole screen as the scroll region, replace rather than insert: a terminal that was
being forwarded the stream a moment ago can be in any of those, and each one changes where an
absolute address lands or what drawing a cell does to its neighbours. The session's own are
installed after the last row, so a projection that becomes a direct presentation hands the
application the terminal it is writing for. A window showing part of the grid cannot carry a margin,
which is a row of the grid, and says so through the projection's own report rather than installing
something close.

The palette travels as state: the session's foreground, background, cursor and selection colours,
every indexed colour an application overrode, and where the palette came from, recorded when the
session was created. What a projection does not do is impose the profile's own table on the rest. An
indexed colour nothing overrode is drawn in the destination's, exactly as it would be if this
terminal were being forwarded the stream. Two terminals with different themes therefore agree about
every colour the session set and keep their own for the ones it did not.

### The restoration guard

A broken connection must not leave a terminal in raw mode, and the restoration has to survive the
attach process being killed — which no in-process handler can do, because `SIGKILL` runs no handler.

So the saved state lives in another process. `kr attach` starts `kr-attach-guard` before anything
touches the terminal and gives it one end of a pipe, its own handle on the terminal and the
terminal's complete mode state.

* A clean exit restores the terminal and sends the guard a byte, and the guard leaves without
  acting.
* Any other end — a crash, `SIGKILL`, the machine running out of memory — closes the pipe. The
  guard's read returns end of file and it restores the terminal itself.

The guard runs in its own process group, so signals aimed at the attach process do not reach it, and
it handles the background-write signal so that changing the terminal from the background is not a
reason to stop it.

Its limit is stated plainly: nothing recovers a terminal whose emulator has died, because there is
nothing left to restore.

Only then does it ask the terminal anything. The capability handshake is bounded and synchronous,
and every question in it must be answered, so the questions follow the profile the terminal
declares. A terminal calling itself `xterm-kitty` or `ghostty` is asked which keyboard protocols it
has negotiated: the Kitty protocol's flags, and xterm's `modifyOtherKeys` level, neither of which
termios describes. Every terminal is asked for its device attributes, and that reply is the
terminator: the one thing that proves no earlier answer is still in flight.

Nothing else is asked. A question whose answer is optional is not a question this command may ask,
and nothing beyond the terminator can be required of a terminal calling itself `xterm-256color`:
Terminal.app answers neither colour query, and requiring one would fail every attach there. What
the command may do instead is not ask, which is the honest way to not know. A reply a terminal
volunteers is still recorded, because a terminal that says what it has negotiated has told the
truth about itself either way, and what it reported is what a cleanup puts back. Reading the answers
means putting the terminal into a mode where they arrive, which is why the guard exists first. The
answers then reach the guard over the same pipe.

An answer may arrive in pieces. A terminal is free to send half a reply, and the exchange keeps its
place between reads rather than treating the first half as something the person typed. The terminal
is put into a mode where a read waits for nothing at all, and the clock is checked between reads, so
the exchange ends within a millisecond of its one second rather than a tenth of a second past it.
What the person typed around the answers is theirs: before the terminator, after it, and the half of
a key they were part way through pressing when it arrived.

The record that makes a retry require a fresh terminal is written **before the first question**, and
removed only when the terminator arrives. A process killed in the middle of asking runs no cleanup
at all, and the terminal it was asking is exactly the one whose stream may still deliver a reply.

Nothing the terminal replies reaches the application. What the person typed during the exchange is
kept apart from the answers, in the order they typed it, and is the first input the attachment
forwards. Outside the handshake the command does not scan input for anything reply-shaped: after it,
every byte from the terminal is the person's.

A terminal that does not finish the handshake within a second fails this attach with
`TERMINAL_PROBE_FAILED` and exit code 6; it does not begin forwarding input on a stream that may
still receive a late reply. What the person typed while the host was asking is kept apart from the
answers and is the first input the attachment forwards.

Both paths out put everything back: the mode words, the control characters, the sequences that undo
what an application may have left enabled - the alternate screen, mouse reporting, bracketed paste,
the coordinate system a projection installed - and then the keyboard protocols the terminal had
chosen for itself. A cleanup that runs before the attachment began forwarding, because the handshake failed
or the process was killed during it, leaves those protocols alone: nothing that had happened could
have changed them.

Those sequences are the documented defaults, and for the modes the attachment itself changes they
are not the last word. The handshake asks a terminal declaring one of xterm's names what it has set
for the cursor's visibility, the three mouse tracking modes, the SGR mouse encoding and bracketed
paste, before anything changes any of them. What it reports is written back over the defaults, so a
person whose mouse reporting was already on gets it back rather than a terminal nobody had touched.
Those values travel to the restoration guard as well, so an attach process killed outright still
leaves the terminal as its owner had it.

A mode report is the one question whose silence is an answer. Every one of these modes has a
documented default, which is the state a restoration used before any of them were asked, so a
terminal that answers none of them is attached to, restored to those defaults, and told so: the
command ends by naming each mode it had to default rather than read.

`--no-probe` asks the terminal nothing at all, which is what makes it the choice for a terminal that
does not answer. The session's own keyboard modes are still cleared when the attachment ends, since
the session could have set them, but nothing comes back afterwards: that is what never asking costs.

A projection decides the two keyboard protocols separately, because they cannot be put back the
same way. The Kitty flags are installed only on a terminal that reported its own: that protocol has
no sequence returning a terminal to what it had, and its stack cannot be read, so flags installed on
a terminal nobody asked could not be taken off again. The `modifyOtherKeys` level is installed
whenever the person at this terminal can type, because that is the encoding the host advertises for
them and `CSI > 4 m` returns any terminal to the level it started with; a terminal the host will not
let type is left alone entirely, since installing a level there would change a terminal nobody asked
about for no one's benefit.

The choice is made before the first byte goes out, which is the only time it can be made honestly.
After a failed handshake the stream is not clean any more: a late reply could still arrive on it, so
a retry needs a fresh terminal and `--no-probe` on the same one is refused rather than treated as a
purge. Calling it afterwards would not unsend the questions.

### Nesting

`kr attach` inside a KalaReach session works, and the outer session treats the inner command as an
ordinary foreground application. Everything the person types while it is in the foreground goes to
the inner attachment, the end-of-file byte included: there is no outer interception in the way of
it, and the outer session's own shell never sees it. The inner command probes the terminal it is in,
which is the outer KalaReach terminal, and that worker answers as the sole responder for its own
session. `TERM_PROGRAM` is a hint about what the terminal is, never authentication and never proof
of compatibility.

A paste passes through a nesting once. Each session in the chain frames it for the application
reading it, so an application that turned bracketed paste on receives one pair of markers however
many sessions the keystrokes crossed, and one that did not receives the text.

### Over SSH, including to the same host

An attachment over SSH is an ordinary attachment. The terminal it asks is the pseudo-terminal
`sshd` gave it, the replies come back over the same connection, and every capability comes from that
exchange rather than from anything about the host: nothing is assumed because the far end happens to
be this machine. A loopback, `ssh localhost kr attach 1`, is therefore the same path as a remote one,
with two consequences worth stating. The handshake's one-second bound covers the round trip, so a
link slow enough to lose the terminator fails that attach rather than continuing on a stream that may
still deliver a late reply. And SSH's own escape character stays SSH's: `~.` closes the connection
before the attachment sees it, exactly as it does inside any other full-screen application.

## `kr detach`

`kr detach` removes one attachment and leaves the session running. Run inside a managed root shell
it takes no identifier: the session already knows which terminal the command's own line was typed
in, because the root integration records the originating attachment and input epoch through the
editor fence at the moment the line is accepted. That record is what the detach resolves against,
so the terminal that gets removed is the one the person is sitting at, never whichever client
happens to hold the input lease by the time the command runs.

When the recorded origin is a line whose input came from more than one attachment or epoch, or
there was no valid fence to establish it, the command returns `AMBIGUOUS_ATTACHMENT` and names no
attachment. Pass `--attachment <id>` to say which one. A session with no recorded origin at all —
a `native_compat` session, or a managed one before its first accepted line — resolves to its sole
terminal attachment and returns `AMBIGUOUS_ATTACHMENT` when it has more than one.

## `kr question`

The companion app is the primary place to answer an agent's question. These commands are the same
surface on the machine the session is on.

| Command | What it does |
| --- | --- |
| `kr question list [--session <id>] [--include-resolved]` | Lists what is waiting |
| `kr question show <question_id>` | One question in full |
| `kr question answer <question_id> (--text \| --choice <id> \| --yes \| --no \| --other <text>)` | Answers it |
| `kr question cancel <question_id>` | Withdraws it without answering |

Exactly one answer flag is required. `--other` is the free-text option every `select` and `confirm`
carries; it stays free text and is never read as a listed choice or as yes.

Listings lead with the application identity the host verified — the executable the kernel names and
its process identifier. The `agent_name` the caller supplied appears beside it as an unverified
label.

The revision the command read is the revision it submits. A question that was answered, cancelled
or expired between reading and answering is refused with `QUESTION_RESOLVED` or `QUESTION_EXPIRED`
rather than answered as though it had not moved.

Questions belong to the session, so these reach the session's worker directly, the way attaching
does; they keep working while the control daemon is restarting.

## `kr skill`

`kr skill install --agent <agent> --scope <user|project> [--project-dir <path>]` writes the
`kalareach-contact` package and registers `kr agent-tools --stdio` as a tool server for that agent.
The agents are `codex`, `claude-code`, `opencode`, `gemini-cli`, `kimi-code-cli` and `qoder-cli`. A
project scope with no `--project-dir` means this directory.

`kr skill status` reports what is installed and lists anything that has changed since, including an
installation that began and did not finish. `kr skill remove` undoes exactly what the installation
recorded, and leaves alone anything that changed after it was written. Both print the change
manifest: every directory created, every file written, and the configuration entry added.

What cannot be done safely is refused before anything changes: a file or a server entry this host
did not write, a configuration document whose access controls a replacement could not carry, and
every installation change on Windows, where this host has no way to make the change durable. After
an interrupted installation, `kr skill install` says so and lists under `unresolved` anything that
neither it nor a removal can account for.

## `kr agent-tools`

`kr agent-tools --stdio` speaks the Model Context Protocol on standard input and output. It is what
an installed agent runs; there is nothing to read in its output by hand, and it writes nothing else
to that stream.

It offers four tools — `ask_user`, `wait_for_answer`, `cancel_question` and `send_notification` —
bound to the session this process is running in. Outside a session every tool answers
`NOT_IN_KR_SESSION` with the instruction to start the agent inside one, and creates nothing.
[docs/contact/README.md](../contact/README.md) explains the binding, the states and the limits.

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

## `kr host power`

Automatic sleep is the machine's own policy, and `kr` changes it only when you ask:

```sh
kr host power                     # the setting, and what it is doing right now
kr host power --set mains_only    # stay awake for admitted work, on mains power
kr host power --set battery_too   # the same on battery, which is a separate choice
kr host power --set off           # the default
```

The setting is per-user host configuration. Writing it installs no service, obtains no privilege
and changes nothing else about the machine. With it on, the host holds the platform's own assertion
against automatic sleep while it has verified foreground work or a request it has accepted and not
answered, and releases it when that ends:

```text
sleep inhibited (mains_only): the host has requests it has not answered, held as a
power-management assertion against idle system sleep, held on behalf of process 82035 on mains power
```

Two kinds of work count. The host knows the first from its own bookkeeping: a request it has
accepted and not answered, which is a create it is still starting a worker for or a closure that is
still stopping processes and draining their output. The second is what a session's worker reports
about itself: an agent at work, or a decision waiting to be answered. A session whose worker reports
neither of those contributes neither, and an idle shell is not work however much output it has
produced.

That line appears in `kr status` and `kr doctor` too. The process it names is the one the operating
system's own listing shows, so `pmset -g assertions` on macOS can be compared with it directly.
`docs/host/platforms.md` has the facility each platform uses and what an assertion does not
promise.

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
  "desktop": { "desktop_session_id": null, "login_generation": null },
  "created_at_ms": 1789484611722,
  "closure": null
}
```

A session in a desktop context names the desktop it is bound to, and `kr status --json` adds what
the host's sleep setting is doing:

```json
{
  "worker_profile": "desktop_bound",
  "desktop": {
    "desktop_session_id": "macos_security_session:uid=501:session=100019:generation=1788258227274902:boot=3239...",
    "login_generation": 1788258227274902
  },
  "power": { "setting": "off", "active": false, "description": "sleep policy unchanged (off)" }
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

`kr doctor --json` returns
`{ "host": { ... }, "doctor": { ... }, "environment": { ... } }`, and exits non-zero when a check
did not pass. The host object carries `default_worker_profile` and the same `power` object. The
environment object is what `environment.capabilities` answers: the desktop and one record per
capability, the profile new sessions get, what a logout does to each profile on this platform, and
the power state. Each capability record carries the facility it is about and that facility's
identity, which is what to compare after installing a new version of a tool. In text form those become a line for the desktop, a line per profile and the same
inhibition line.

`kr host power --json` returns `{ "ok": true, "environment_id": "...", "power": { ... } }`. The
power object holds the setting, whether an assertion is held, its reason, the facility holding it,
the power source, the counts behind the decision, and either the holder or the reason nothing is
held.
