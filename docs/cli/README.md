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
| `kr doctor` | — | Read-only diagnostics, this host's effective configuration, and support bundles |
| `kr host power` | — | Show or change whether this host stays awake for work it has admitted |
| `kr host terminal` | — | Show the terminal applications this host has, and which one a new window opens in |
| `kr host startup` | — | Show or choose how `kr new` starts this environment's control daemon when none is running |
| `kr bridge --stdio` | — | Serve this environment to a local process bridge on standard input and output |
| `kr bridge [list/enrol/forget/refresh]` | — | The environments this host has enrolled, and what it last saw of them |
| `kr pair [invite/confirm/cancel/status]` | `kr p` | Pair a device: issue an invitation, approve the device that answers it, withdraw one, or read one |
| `kr project [list/init/clone/adopt]` | — | An environment's source repositories: list them, create one, clone one, or register a checkout that exists |
| `kr workspace [list/create/remove]` | — | The shared or isolated working copies of a repository. A live session is never moved |
| `kr changeset [capture/read/materialize]` | — | Capture an exact version of a workspace's work, read one, or write one out on its own |
| `kr diff [read/apply/revert]` | — | Read changes, or apply or revert a change-set version at a destination you name |
| `kr device [list/revoke]` | — | The devices paired with this host, and revoking one |
| `kr plugin [list/install/remove/pin/enable/disable]` | — | Plugin packages and what they may do |
| `kr plugin repo [list/add/sync/pin/remove]` | — | The repositories plugins come from, and the trust placed in them |

`--help`, `--version` and `--json` work everywhere. A literal `--` ends option parsing. Neither
shell commands nor paths are assembled by interpolating text.

The commands from `kr project` to `kr plugin repo` act in this installation's own environment, or in
the one `--environment <id>` names. Each is a client of one method the control daemon serves, and
the daemon decides every refusal. A command that removes or revokes something names it by its
identifier, never by a label or a number.

A session is named by its display number or its identifier. Display numbers increase within an
environment and are never reused. A number that names sessions in more than one environment is
`AMBIGUOUS_SESSION`: the command says so and stops, and never picks the first match.

## `kr new`

The presentation flags are mutually exclusive:

| Flag | What happens |
| --- | --- |
| `--attach` | Create and attach in this terminal. The default when input and output are terminals |
| `--terminal` | Create a session and ask the host to open an installed terminal application on it |
| `--invisible` | Create a session with no local terminal attachment |

Without a terminal and without a flag the command stops and asks for one, rather than choosing.

`--terminal` opens the window through the control daemon, which is the only party on the host that
can open one for a session created somewhere else: a paired device asking for a local tab takes the
same path. The daemon chooses in the order section 7 fixes: the application `--terminal-app` names,
then the environment's saved preference, then what it detects. Choosing a terminal and creating a
session are separate steps, so a host that cannot open a window still has the session. The command
then exits with `TERMINAL_UNAVAILABLE` and the reason, and the session is there to attach to;
running `kr new` again would make a second session rather than a second attempt at the window. A
create token asked twice is answered with what became of the first attempt, and never opens a
second window.

Two flags decide the session's launch profile, which is fixed when the session is created and read
back by `kr status`:

| Flag | What happens |
| --- | --- |
| `--terminal-app <id>` | Which terminal application `--terminal` opens in. The host detects what is installed when this is absent, and an application it does not have is `TERMINAL_UNAVAILABLE` rather than a different one |
| `--startup <host-default\|interactive\|login>` | Which startup files the root shell reads. The host default is login startup on macOS and the interactive startup alone elsewhere |
| `--no-fenced-launch` | Refuse `shell.launch` in this session. The fence, the empty-prompt Ctrl-D and the attributed acceptance all stay; what goes is installing a command the person did not type |

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

### When no control daemon is running

`kr new` asks the environment's control daemon for the session, and a host where none is running
has to have been set up for one to be started. One that was not is answered `HOST_NOT_CONFIGURED`
with what to do: start the daemon, `kr-controller`, or choose the standalone start with
`kr host startup --set standalone`. The command installs no service, enables no lingering and
obtains no privilege on the way.

With the standalone start chosen, `kr new` starts the daemon itself when nothing listens on the
environment's endpoint: the `kr-controller` installed beside `kr`, detached from the command. It runs
in a session and a process group of its own with no controlling terminal and none of the command's
standard streams, works in the environment's own state directory, and is told the environment's own
runtime and state roots. It inherits the command's environment, `PATH` included, exactly as a daemon
started by hand from the same shell does, so the tools it runs by name are the ones that shell
finds. It is otherwise an ordinary start: its keys go where an installed daemon keeps them, it serves
the usual owner-only endpoints, and it takes the environment's singleton lock and advances its
generation. That lock is what leaves one daemon when several commands start one at once; a daemon
that cannot take it ends, and the command that started it goes on with the one that did. The start
is for this installation's own environment only, and a command that names another environment is
told to start that environment's daemon.

The command waits up to 30 seconds for an answer, then creates the session exactly as it would with
a daemon that was already running. In text form it first says, on standard error, which daemon it
started. A daemon that has not answered in 30 seconds ends the command with
`ENVIRONMENT_UNAVAILABLE` and exit status 1, naming the process, whether it is still running and the
last line of its log. What the daemon writes goes to `controller.log` in the environment's state
directory, which has to be a file of this user's that nobody else can read or write; a log grown
past 1 MiB is emptied when the next start begins. The command does not end a daemon that is slow to
come up, such as one waiting for somebody to allow it into a credential store: it may still come up,
and the lock keeps a second one from serving beside it.

Something that is listening on the endpoint and does not answer within 10 seconds is reported the
same way, `ENVIRONMENT_UNAVAILABLE`, and nothing is started beside it.

Other commands never start a daemon. `kr list`, `kr status` and the rest answer `HOST_NOT_CONFIGURED`
with the same setup action when none is running.

### Shell mode

`native_compat` is the stock shell you name, run as an interactive session root shell. It keeps
create, attach, detach, close, transfer and terminal presentation. It does **not** claim managed
empty-prompt Ctrl-D, fenced `shell.launch` or authoritative editor-buffer observation.

`managed` launches a KalaReach-qualified shell package, and claims all three. A shell no installed
package qualifies returns `SHELL_INTEGRATION_UNSUPPORTED` naming that shell; `native_compat` is
never substituted for it.

In `native_compat`, Ctrl-D at the prompt does whatever that shell does, which usually means the
shell exits and the session closes. `kr detach` is the way to leave a session without ending it,
and outside the session's own context it takes `--attachment`, which a `native_compat` session
always is: it records no originating attachment. The mode is printed when a session is created and
appears in `kr list`, `kr status` and the `--json` output, beside the launch profile, which says
whether a fenced launch is admitted at all.

## `kr attach`

Attaching reads the published descriptor and challenges the worker itself, so it works while the
control daemon is restarting.

A session's descriptor goes when the session closes. With no descriptor to read, `kr attach` asks
the environment's control daemon, whose registry keeps each closure, and starts nothing either way.
A session that has closed is refused with `SESSION_CLOSED` and exit code 8, naming how it closed,
and `--json` carries its closure record as `closure` beside `session_id`. A session the registry
never held is `UNKNOWN_SESSION`. When no daemon is running for the environment, the command says
so and exits with 3: what cannot be asked is never reported as a closure.

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

The window this terminal is looking through is the session's to say. Each report about it waits
for the one before it to settle. Usually that is when the session has answered it and the screen
that answer names has arrived: every answer and every screen names a revision of the window, so a
screen the session drew before a report, a repaint of where the window was, is never taken for
the report's own. A refusal settles a report at once and changes nothing. So does an answer that
hands this terminal the session's own bytes, and so does a new subscription that begins with
them, because the session hands its bytes only to a window at the live screen's first line and
column. Nothing is reported while a new subscription is being asked for, so the first thing it
delivers can only answer what was sent before. What the person presses meanwhile waits too, and goes from where that screen
puts the window. Presses in one direction add up, and a reversal waits its turn, so a press the
window cannot make is spent without taking the next one with it. A report of this terminal's
*size* waits the same way. Only the newest size waits, carrying where the window is, so a report
refused meanwhile never takes a newer size with it. A resize this terminal makes as the size's
owner is not such a report and goes at once.

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

### When the session closes

An attachment ends when the person detaches, when another attachment takes the input lease, when the
session closes, or when the connection to its worker ends. The command prints one line saying which,
and exits with the status that line implies.

A session closes when its root shell exits, reads the end of its input or crashes, and when somebody
runs `kr close`. Its worker sends every attachment the session's closure record, after all the
output that attachment was owed, and only then exits. The attachment ends with the status the record
implies:

| Status | When |
| --- | --- |
| 0 | The shell exited with status 0, or somebody closed the session |
| 1 | Any other closure: the shell exited with another status, a signal ended it, it never became ready, its desktop login ended or its host shut down. A record the command could not read ends here too. The failure's code is `SESSION_CLOSED` |
| 3 | The connection ended before a whole closure record reached this attachment: the worker went without saying how the session ended, or exited before it could write the record to this attachment, or the connection was lost |

The worker waits five seconds at the most to write the record to an attachment that has stopped
reading. A record it could not finish writing in that time is lost with the connection when the
worker exits, and that attachment ends with 3 even when the session closed cleanly. A record written
in time stays on the attachment's connection, and the attachment reads it when it reads again.

The line comes from the record:

```text
the session closed: its shell exited with status 0
the session closed: its shell exited with status 7
the session closed: a signal ended its shell (<signal>)
the session closed: it was closed on request
the connection to the session ended
```

The command does not pass the shell's status through. Codes 2 to 8 already mean something here, so
a shell that exited with 3 would look like a missing host. The status is in the line and in the
`--json` record instead.

A closing session refuses input from the moment its closure begins. Once the host has refused
something typed at the attachment, the attachment sends nothing more. It goes on showing what the
session writes until the closure arrives, and its line ends with `; what was typed while it was
closing was not delivered`.

`kr new` ends the same way when it attaches this terminal to the session it created.

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

## `kr host terminal`

`kr host terminal` prints the terminal applications this host has, in the order it would choose
between them, and which one it prefers. `--set <id>` saves a preference for this environment, and
`--clear` removes it and lets the host choose again. A `--set` that names an application this host
does not have is `TERMINAL_UNAVAILABLE` and changes nothing.

The preference is the middle step of the order a `terminal` presentation uses: `kr new
--terminal-app` wins over it, and detection decides when neither says anything. A preference that
names something no longer installed is not an error, because nobody asked for it just now.

## `kr detach`

`kr detach` removes one attachment and leaves the session running. Run inside a managed root shell
it takes no identifier: the session already knows which terminal the command's own line was typed
in, because the root integration records the originating attachment and input epoch through the
editor fence at the moment the line is accepted. That record is what the detach resolves against,
so the terminal that gets removed is the one the person is sitting at, never whichever client
happens to hold the input lease by the time the command runs.

What connects the running command to that record is a capability, not anything about the process
the command runs in. The worker mints one secret for the line it has just recorded and gives it to
that line's own execution, through the integration, in `KR_DETACH_TOKEN`. `kr detach` with no
`--attachment` presents whatever that variable holds and the session answers from it alone: one
line, one capability, one attachment. Nothing about a caller's process is read, because nothing
about a process says which line it belongs to — it can be started by an earlier line, resumed from
the background with `fg`, left running after the line that started it finished, or share the
shell's own process group because job control is off. Each of those is a caller that looks exactly
like the line running now and is not it.

The capability lasts as long as its line runs. It ends when that line's command reports the status
it exited with, when the reader comes back at a later prompt, when the next line is accepted, and
when the integration is lost. A client taking the input lease part-way through does not end it,
because the line goes on running and goes on belonging to the terminal it was typed in.

Run anywhere else it takes an identifier, because a caller outside a line holds no capability.

Everything else returns `AMBIGUOUS_ATTACHMENT` and names no attachment: a caller presenting no
capability, one presenting a capability that is not this session's current line's, a line whose
input came from more than one attachment or epoch, a line accepted without a valid fence, an
origin whose terminal has already left, a session whose root editor has accepted nothing yet, and
a `native_compat` session, which records no origin at all. The refusal says `Use kr detach
--attachment <id> to detach`, and passing `--attachment <id>` is the answer to every one of them.
One remaining terminal is not proof that it is the one the command came from, so it is not treated
as one.

The packaged shells do not export the capability yet. It reaches them in the answer to
`root.command.accepted`, which they send; what they do not yet do is read that answer and put the
capability in the environment of the command they are about to run. Until they do, `kr detach`
inside a managed shell names its attachment with `--attachment <id>`, and a bare `kr detach` there
is answered with that instruction rather than with an attachment the host cannot stand behind.

## `kr question`

The companion app is the primary place to answer an agent's question. These commands are the same
surface on the machine the session is on.

| Command | What it does |
| --- | --- |
| `kr question list [--session <id>] [--include-resolved]` | Lists what is waiting |
| `kr question show <question_id>` | One question in full |
| `kr question answer <question_id> (--text \| --choice <id> \| --yes \| --no \| --other <text>)` | Answers it |
| `kr question cancel <question_id>` | Withdraws it without answering |
| `kr question drafts` | Lists the answers kept on this device, and says of each whether it can still be sent |
| `kr question send <question_id>` | Sends one kept answer |

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

An answer the worker could not take is kept rather than lost. When the connection to the worker
fails before the answer is sent, or ends while it is being sent so that nobody can say whether it
arrived, or the worker refuses it for the moment, `kr question answer` keeps the answer in this
user's state directory, readable only by its owner, with the question and the revision it answered.
It says so and exits with 3, and its `--json` document carries `"kept": true` beside the failure:
`OUTCOME_UNKNOWN` when whether it arrived is not known, and otherwise the code of what stopped it.
What the command says of the answer is what its attempt established, step by step: that it did not
send it, that the worker did not take it, or that whether the worker took it is not known, which it
never calls unsent. A reply that is not a message is the worker's own answer rather than a lost
connection, so it is shown as a refusal that says the answer's fate is not known, and nothing is
kept. An answer that can be neither taken nor kept is reported as both, with exit status 1. A worker
that replied that it took the answer took it: when that reply cannot be read, or the copy kept on
this device cannot be removed afterwards, the command says the worker took the answer and exits with
1, and the next `kr question drafts` retires any copy still kept. When the store on this device
cannot be read after an attempt, the command says so beside what the attempt established, never in
place of it, and exits with 1.

`kr question drafts` reads each kept answer's question again and finds the answer offered, unlisted
or retired. An answer whose question is still pending at the revision it answered is offered, and
stays kept. An answer whose question its session no longer lists, while the session's daemon does
not record the session ended, is unlisted: it stays kept and is not offered, and `kr question send`
neither sends nor retires it. Every other answer is retired: its question was answered, cancelled or
expired, or moved to another revision, or its session no longer lists it and the daemon records the
session ended. The command does not send a retired answer, and it is no longer kept. The command
sends nothing, however often it runs. `kr question send` is the one way a kept answer is sent: it reads the question once
more and sends the answer only while that question is still what the person answered. An answer
whose outcome was not known is retired by the next `kr question drafts` if it did arrive, so it is
never sent twice. When `kr question send` cannot send it, the failure keeps its own code and says
the answer is still kept. An answer `kr question answer` gives to a question that ended or moved
before the answer reached it is not sent, and the command says whether an answer kept for that
question earlier is still kept.

A kept answer is retired as gone only on the word of the daemon of the environment its session ran
in: a closure its registry keeps, or, for a session with no descriptor, no record of the session at
all. Nothing on disk, or missing from it, retires one, and neither does a session's worker that no
longer lists the question. An answer is retired as ended or moved on its session's own report of its
question. The descriptor is looked for only in the environment the session ran in, under the
session's own name. When the descriptor is missing and there is no daemon to ask, when the daemon
reports the session still live, when the descriptor or its directory cannot be read or is readable
by anyone but its owner, and when the environment cannot be identified, `kr question drafts` fails
and retires nothing. A worker that cannot be reached retires its answer only on a closure its daemon
keeps; the descriptor it left behind says nothing either way. Otherwise `kr question drafts` exits
with 3, names the worker it could not reach and what its daemon said of the session, and retires
nothing.

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
did not write, and a configuration document whose access controls a replacement could not carry. On
Windows that is a document with another owner, a protected, absent or empty list, encryption, a
control this host does not evaluate, or an entry set on the file itself where its list records which
entries it inherited. Three things the document alone cannot show are caught when the copy that
would replace a file is compared with it: an entry set on a file whose list was written the older
way and records no inheritance, a directory whose list changed after the document inherited from it,
and a document moved in from another directory. A copy that differs stops the change there, after
whatever was written before it. After an interrupted installation, `kr skill install` says so and
lists under `unresolved` anything that neither it nor a removal can account for.

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
| 3 | No host is running for this environment, or the connection to it ended |
| 4 | The named session does not exist, or the command needed one and had none |
| 5 | A display number names sessions in more than one environment |
| 6 | The command needed a terminal, or the terminal could not be changed |
| 7 | No terminal application could be opened |
| 8 | The host refused the request |

`kr attach`, and `kr new` when it attaches, exit 0 when the session closed cleanly, 1 when it closed
any other way, and 3 when the connection ended before a whole closure record arrived. [When the
session closes](#when-the-session-closes) says which closure is which.

A `--json` failure carries the same information:

```json
{ "ok": false, "code": "AMBIGUOUS_SESSION", "message": "...", "exit_code": 5 }
```

## `kr doctor`

Read-only. It asks the host what it is, what it is configured from and what is wrong with it, and
it repairs nothing.

```sh
kr doctor                          # each check's verdict, with evidence only where one did not pass
kr doctor --verbose                # every check's evidence, including the checks that passed
kr doctor --bundle support.tar     # write a redacted support bundle
kr doctor --bundle support.tar --include-content   # add the content-bearing diagnostic export
```

The output opens with the environment, the execution context, the desktop and its capabilities and
the sleep policy, then this host's effective configuration, then the checks and a summary:

```text
configuration /home/someone/.config/kalareach/environments/ab12cd34/config.json (schema version 1, revision 3): version 1
  runtime directory /run/user/1000/kalareach/ab12cd34
  state directory /home/someone/.local/state/kalareach/environments/ab12cd34
  document belongs at $XDG_CONFIG_HOME/kalareach/environments/<prefix>/config.json, or
    ~/.config/kalareach/environments/<prefix>/config.json where that variable is not set
  runtime_directory belongs at $XDG_RUNTIME_DIR/kalareach/<prefix>, or ~/.cache/kalareach/run/<prefix>
    where that variable is not set
  state_directory belongs at $XDG_STATE_HOME/kalareach/environments/<prefix>, or
    ~/.local/state/kalareach/environments/<prefix> where that variable is not set
  sleep_inhibition = mains_only from host_configuration, applies immediately
  worker_profile = headless_user from default, applies to new sessions only
  runtime_directory = /run/user/1000/kalareach/ab12cd34 from default, applies to new sessions only
  state_directory = /home/someone/.local/state/kalareach/environments/ab12cd34 from default, applies to new sessions only
  network.enabled = true from host_configuration, applies at the next start
  network.relay_urls = https://relay.example.com from host_configuration, applies at the next start
  network.dns_origin = none from default, applies at the next start
  …
  voice.broker_origin = none from default, applies at the next start
  session_limit ceiling 128
  enrolment ceiling 67108864 metadata bytes, 100000 entries, 5 generations retained, …;
    configured here: retained_generations
  grant_rights ceiling every right the grant and the host policy allow
ok             The runtime directory is owner-only
warning        Every published descriptor answered its challenge
               1 verified, 1 quarantined
               A quarantined descriptor is never used. Remove it once its session is known to be gone.
not_applicable Catalogue metadata and its capability evidence
               no catalogue is synchronised on this host
14 checks: 12 passed, 1 with something worth knowing, 0 failed, 1 not applicable
```

Each engineering default the product makes configurable is printed with the value in force and the
rung it came from, so what this host is doing and why are one reading rather than two. The
locations are printed twice over: the paths this host resolved, which is where your files are, and
the rule this platform follows, which is where the next one would go. A location an allowlisted
variable chose says so in place of the rule. This is your own host answering you about your own
machine; a support bundle is written for somebody else to read and carries those paths as their
class and their length instead. A paired device that asks this host for its diagnostics, its
environments, its capabilities or its metadata is answered the way a bundle is written: it is told
which environment this is and what it runs on, and never your account name, a path on your disk or
what the platform said. The value in
force is the one the host is enforcing, not the one the document asks for: where an effect could
not be applied, the `configuration-in-force` check fails and says what stopped it, and the ceiling
lines show both what was asked for and what is in force. `--json` carries the same two facts as
`configuration.not_in_force` and `configuration.fence_outstanding`.

The document's `network` and `voice` sections are printed the same way, one line for each of their
eleven fields, and each says `applies at the next start`: the daemon reads them when it starts, and
no environment variable reaches them. The `configuration-network` check reports what the running
network and voice services are doing, and warns when the document now selects a different network
or voice broker, which takes a restart to put into force.

The `configuration-overrides` check names the two variables that take part in the precedence, and
the variables this build reads outside it that are set here, each with what it selects: the
platform's locations and login, and the proxy variables and `SystemRoot` that the endpoint's
network library reads itself. It also says that `SSL_CERT_FILE` and `SSL_CERT_DIR` are not read,
and which of them is set: an authority given only through one of them is not trusted by the
managed-service, rendezvous, delivery, plugin repository and mail clients until it is installed in
the system store. The network endpoint's relays and discovery servers are verified against the
public anchors and `network.relay_trust_anchors` instead.

Asking for the diagnostics is what puts this host's configuration into force, so a ceiling somebody
edited by hand takes effect during the run. One that changes what a caller may do withdraws the
authority this command's own connection was admitted under; the command opens a new one and asks
again, so the report is the one this host is acting on rather than the one it was acting on a
moment ago.

The exit status is 0 when no check failed and 1 when one did. `--json` returns one document with
`ok`, `host`, `doctor`, `configuration` and `environment`, and `bundle` when one was written.

### Support bundles

`--bundle <path>` writes an uncompressed `tar` archive holding `manifest.json`, which carries the
software versions, the capability evidence, the diagnostics, the effective configuration and this
host's errors, and `report.txt`, the same diagnostics as readable lines. Both are written from the
bundle's own exported copy rather than from what the terminal showed: the report on your screen
names your paths because you are at this machine, and the file you send somebody carries each of
them as its class and its length.

Every field in it is redacted by what it is rather than by what it looks like. Each exported field
is listed once, with what its value is made of, and a field whose value came from outside this
build leaves as its class and its length: `[message withheld, 47 bytes]` in place of a library's
error, `[path withheld, 62 bytes]` in place of a directory, `[name withheld, 5 bytes]` in place of
a name an account, a platform or a person supplied. What leaves as itself is what this build wrote:
its own sentences, the words of its own closed sets, its numbers, and the identifiers it generated.

"What this build wrote" is decided by the value rather than by the field it sits in. Each of those
sentences is held in a type that knows whether this process composed it, so a diagnostic `kr doctor`
read back from the daemon and a capability record a worker reported are measured on their way into
the bundle rather than repeated.

The daemon's own build identity is the one thing a bundle names although it arrived in a reply,
because which build is running is the first thing somebody reading one needs. Nothing of the text
survives the parse: what is kept is the program's name, out of the closed list of the programs this
product builds, and the three numbers of its version. What is printed is composed from those.
`kr-controller/0.1.0` is named in full; a component this product does not build and a version that
is not three numbers are not a build identity, and carry their length like any other name. The
parse settles the shape and not the build: the reply still chooses the three numbers, so a bundle
names the build the daemon reported rather than proving which one is installed.

That is why a credential cannot reach a bundle by being spelled in an unexpected way. Nothing reads
a value to decide about it, so a lower-case scheme word, an unfamiliar token alphabet and a
credential in the middle of an ordinary sentence are all gone for the same reason: the field they
arrived in is one this host does not publish the text of.

Nothing content-bearing is in it. `--include-content` adds a `content/` entry, and the command
prints what that entry will hold, on the error stream, before it writes anything:

```text
--include-content adds the content-bearing diagnostic export:
  content/sessions.json: every live and closed session (4 of them) with its shell command line,
  working directory and title
support bundle written to support.tar (4 software versions, 2 capability records, 13 checks,
1 content-bearing entries)
```

Giving the flag is the selection. Without it there is no content-bearing export and the manifest
says so.

## `kr bridge`

`kr bridge --stdio` is the destination half of a local process bridge. It is what a Windows host
starts inside a WSL distribution, and what a container host starts inside an enrolled container:

```text
wsl.exe --distribution Ubuntu-24.04 --user kala --exec /usr/local/bin/kr bridge --stdio
podman exec --interactive --user kala -- 8f3c1d2e4a5b /usr/local/bin/kr bridge --stdio
```

It reads protocol frames from standard input, carries them to this environment's own control
daemon or session worker over local IPC, and writes the answers back to standard output. Standard
error stays diagnostic. Nothing is printed on standard output but frames, so the stream cannot be
corrupted by a message meant for a person.

The bridge serves locally authenticated invocations only. A handshake that says the request
arrived from the network is refused with `PERMISSION_DENIED` before anything is connected, and so
is one that says the request has already crossed a bridge. A frame larger than the protocol's
control-frame maximum is refused rather than truncated.

The other four operations act on the environments this host has enrolled:

```text
kr bridge list [--access wsl|container|ssh|paired]
kr bridge enrol --access wsl --label ubuntu --target Ubuntu-24.04 \
  --user kala --helper /usr/local/bin/kr \
  (--environment-id <uuid> | --probe) [--clipboard <destination>]
kr bridge forget <label>
kr bridge refresh <label> [--start]
```

`--target` is the identity the platform issued: the distribution name WSL registered, the
identifier the container runtime issued, or the SSH destination. `--label` is what a person types
to select the record; it is never compared as an identity, so a container recreated under the same
name does not inherit the old one. `--helper` is absolute, in the target environment's own terms.

An enrolment names the environment's own identity. Pass it with `--environment-id`, or pass
`--probe` to ask the destination for it. A probe runs the helper inside that environment, so the
environment has to be running already: enrolment starts nothing, and a probe of a stopped
environment is refused rather than starting it. A container's `--target` is resolved through the container runtime
first, and the identifier it answers with is what the record keeps; a name, or a short prefix of an
identifier, is not one.

`list` reads this host's cache. It contacts nothing and starts nothing, and every row says so:
each carries the environment identity, when it was last observed, an explicit `running`,
`environment_stopped` or `stale` status, and whether that came from the cache or from an
observation. `refresh` is the only one that asks the platform, and it starts the environment it
selected only with `--start`.

A refresh of a running environment also opens a bridge to it and reports what answered: the
environment identity, the user the helper runs as inside it, the protocol version and the frame
bound. That line is the connection diagnostic, and it says what stopped the bridge when one could
not be opened — the program that would not start, the environment that answered with another
identity, or the destination's own refusal.

## `kr pair`

`kr pair` pairs a device with this host over the host's network endpoint. It is the owner's side of
section 10's pairing; the new device runs its own side, in the companion application.

| Command | What it does |
| --- | --- |
| `kr pair invite --owner` | Issue an invitation for an owner device: every right over this host, until it is revoked |
| `kr pair invite --view [MINUTES]` | Issue an invitation for a device that may view sessions, for the minutes given (60 by default) |
| `kr pair confirm <invitation>` | Approve the device that answered, once it shows its verification value |
| `kr pair cancel <invitation> [--deny]` | Withdraw the invitation, or deny the device that answered it |
| `kr pair status <invitation>` | Show where the invitation has reached, and the device that answered it |

An invitation is a ten-character code shown as `XXXX-XXX-XXX` beside the rendezvous origin it is
reserved at, with a QR code that carries both; `--origin` names another rendezvous origin than
this host's default. `--direct` offers a QR code instead, which carries everything the new device
needs to reach this host on the same network and contacts no rendezvous service. Either lasts five
minutes. A code may be guessed at five times before the invitation closes, and `kr pair status`
says how many guesses are left. The QR code is drawn black on white whatever the terminal's own
colours are.

Issuing an invitation and approving a device each need a fresh owner confirmation naming exactly
that action, and `kr` asks the host for one first. On a host that has an owner, an owner device
confirms it in its own ceremony: `kr` says so on standard error and waits, asking the host again
every second, until the confirmation arrives or the challenge runs out after two minutes.

### A host's first owner

A host starts with no owner, and its first owner is paired at the terminal of the person who owns
it: `kr pair invite --owner` asks them to type `pair` to issue the invitation, and `kr pair
confirm` asks them to type the verification value the new device shows. Both are read from the
controlling terminal itself, not from standard input. `kr` then confirms on the host's
`local_bootstrap_terminal` channel with a key it makes for that one confirmation. The host accepts
that channel only while it has no owner and only for this pairing, so the pairing that commits
closes it for good; a host with no owner refuses to issue anything else first.

The first owner is confirmed only at an interactive terminal outside every KalaReach session.
Standard input and output must be terminals, the controlling terminal must open, neither
`KR_SESSION` nor `KR_ATTACHMENT` may be set, and every live session's worker must establish that
the command is not one of its own processes. Where a worker cannot establish it, because a reading
of the process tree it needed failed or changed while it read it, `kr` refuses as well, as it does
where a worker does not answer or a session descriptor cannot be read: what cannot be established
is not taken as outside. The refusals are exit code 6 for a missing terminal and 8 for a session.

On macOS the kernel does not describe another user's processes, and Terminal and iTerm2 start
each shell through the system's `login` by default, which runs as root. A worker establishes that
such a terminal is outside its session when the terminal's shell started before the session did,
and cannot establish it otherwise. So in a window opened after a session started, `kr pair invite
--owner` refuses while that session runs: use a window opened earlier, or end the session first.

This guard exists so that an agent running in a session cannot start the ceremony by accident. It
is not isolation from other code running under the same account, which can do anything `kr` does.

## `kr project`

`kr project` works with an environment's source repositories. Plugin repositories are a separate
thing, managed with `kr plugin repo`.

| Command | What it does |
| --- | --- |
| `kr project list` | Lists the repositories, each with its state, its origin and how many workspaces it has |
| `kr project init <path> [--label <label>] [--initial-branch <name>]` | Creates an empty repository in a new directory |
| `kr project clone <source> <path> [--label <label>] [--remote-name <name>] [--credential-broker <name>]` | Clones into a new directory |
| `kr project adopt <path> [--label <label>]` | Registers a Git checkout that already exists, and changes nothing inside it |

`<path>` is a directory whose parent exists, and a relative one is taken from the directory `kr`
runs in. The daemon opens the parent with this host's own authority and creates the one name inside
it, so nothing lands anywhere else. Without `--label` a repository is labelled with its directory's
name, and from then on it is named by the identifier the daemon gave it.

A clone's source is an `https://` URL, an ssh remote (`ssh://host/path` or `user@host:path`), the
absolute path of a repository on this machine, or the identifier of a repository this environment
has registered. Anything else, a `git://` or `file://` URL included, is refused before anything is
sent. The credential broker `--credential-broker` names authenticates a network remote; it is
`os-secret-store` unless you say otherwise, and a URL that carries a credential is refused.

## `kr workspace`

| Command | What it does |
| --- | --- |
| `kr workspace list [--project <id>]` | Lists workspaces. Listing one never removes anything |
| `kr workspace create <project> --kind shared` | Uses the repository's own tree, where it is |
| `kr workspace create <project> --kind isolated --isolation <git-worktree\|independent-clone> --path <path> [--include <class>]... [--base <revision>] [--base-change-set <id>] [--preview]` | Makes a separate tree from a base |
| `kr workspace remove <workspace> [--remove-retained]` | Removes a workspace once no live session or run is bound to it |

There is no default kind. A shared workspace is the person's own tree, and all of their uncommitted
work stays in it, so `--include` is refused there. An isolated one starts with the classes of
uncommitted work `--include` names: `dirty-files`, `untracked-files`, `submodules`, `binary-files`,
`generated-artefacts`, or `all`. A class it does not name is left out of the new tree and stays
where it is in the original. A Git worktree shares the repository's objects and references under
the same account, so it is not a sandbox, and an independent clone has objects of its own.

`--preview` sends the same request with nothing written and prints what the workspace would hold:
each class with how many of its paths would come across, the base revision, and what the host says
the preview cannot promise.

A removal keeps what the workspace still holds, which is its uncommitted work, the change sets
pinned against it and review evidence. It lists them and leaves the workspace waiting, and
`--remove-retained` removes them too. The tree of a shared workspace is never removed.

## `kr changeset` and `kr diff`

| Command | What it does |
| --- | --- |
| `kr changeset capture <workspace> (--label <label> \| --change-set <id>) [--include <class>]... [--include-path <path>]... [--exclude-path <path>]... [--quiesced] [--require <per-file\|quiesced\|atomic>] [--pin] [--note <text>]` | Records one immutable version of a workspace's work |
| `kr changeset read <change-set> [--version <n>]` | Reads one exact version, the latest by default, with every version beside it |
| `kr changeset materialize <change-set> <version> --purpose <test\|review\|inspection> [--label <label>]` | Writes one exact version into a directory of the host's own |
| `kr diff read (--workspace <id> \| --change-set <id> --version <n>)` | Reads the changes of a live tree or of one captured version, each path with its content digest |
| `kr diff apply <change-set> <version> --to <proposal\|reference\|working-tree> ...` | Applies that version at the destination named |
| `kr diff revert <change-set> <version> --to <proposal\|reference\|working-tree> ...` | Reverts it there |

A capture takes the classes of uncommitted work `--include` names and nothing else, the way an
isolated workspace does. `--include-path` and `--exclude-path` narrow what it reads, and the host's
own secret rules always apply. The version records the consistency the host could establish about
its source: `per_file_capture`, `quiesced_capture` or `atomic_snapshot`. `--quiesced` records what
you say about the tree and decides nothing, and `--require` refuses a capture that cannot reach the
class it names.

An apply names its destination every time. `proposal` records a new version and writes to no tree.
`reference` moves the Git reference `--reference` names, and only while it holds the value
`--reference-at` gives, or `absent` for one that does not exist yet. `working-tree` writes the
workspace's own files in place. Every destination but a bare proposal names `--workspace`.

Each path the change writes is named with `--expect PATH=DIGEST`, the digest being the one
`kr diff read` shows, or with `--expect PATH=absent`, and the host checks every one before it
writes. A destination that is not as expected is `DRAFT_CONFLICT`, and nothing is written. `--path`
limits the apply to some of the version's paths and `--preflight` checks without writing. A write
to a working tree is refused until you pass back each limitation the host states for it, with
`--acknowledge`.

`kr diff read` shows `absent` only for a path the change deletes. A path it has no digest for
otherwise, such as a link or a file the host could not read, shows `unavailable`, which `--expect`
does not take.

An apply or a revert that began and did not finish exits with 1: `DRAFT_CONFLICT` when the
destination stopped being what the request expected part way, `OUTCOME_UNKNOWN` when the host
stopped before it finished or cannot say what the destination holds. The text names each path
that changed or could not be established and the versions to recover from, and the `--json`
document is the host's whole result with the failure's code and status beside it.

## `kr device`

`kr device list [--include-revoked]` lists the devices paired with this host: each one's
identifier, its name, whether it is an owner device, and the last authority revision it
acknowledged. A device that is offline cannot apply a revocation it has not received, and the
acknowledgement is how you see which devices have.

`kr device revoke <device>` revokes a device and every grant it holds. An identifier this host never
paired is refused with `RESOURCE_UNAVAILABLE` and nothing is sent; a device already revoked answers
with its revocation as it stands.

A revocation is complete when every affected session's worker has fenced it, so the command says
how far they have got. Until then it is pending, not a success: the command names each worker it
waits for with the reason the host gives, and exits with 1 and `RESOURCE_UNAVAILABLE`; its `--json`
document is the host's whole result with the failure beside it. Running it again reports how far
the revocation has got. A worker that has fenced it but whose evidence has not all arrived is named
too, and so is any action a worker could not show did not run before the revocation reached it.

## `kr plugin`

| Command | What it does |
| --- | --- |
| `kr plugin list` | Lists the plugins installed in the environment |
| `kr plugin install <repository> <plugin> <version> --digest <hash> [--grant <capability>]...` | Installs a package from an enrolled repository, at exactly the hash named |
| `kr plugin remove <plugin>` | Removes an installed plugin and closes its live bindings |
| `kr plugin pin <plugin> [--digest <hash>]` | Holds it at one exact hash, or releases the pin when no hash is given |
| `kr plugin enable <plugin>` and `kr plugin disable <plugin>` | Enables it, or disables it without removing it |
| `kr plugin repo list` | Lists the enrolled repositories with their roots, generations and budgets |
| `kr plugin repo add <repository> --root <file> --metadata-url <url> --targets-url <url>` | Refused at a terminal, as below |
| `kr plugin repo sync <repository>` | Fetches its newest generation inside the trust it already has |
| `kr plugin repo pin <repository> [--generation <n>]` | Holds it at one generation, or releases it |
| `kr plugin repo remove <repository>` | Stops trusting its root; what was installed from it stays installed |

Two decisions are the owner's, and section 10 says this account's own identity is not the owner's
confirmation. The first is adopting a repository's trust root. A request to add a repository
carries an owner device's signed confirmation of exactly that root, so `kr plugin repo add` refuses
with `OWNER_CONFIRMATION_REQUIRED` and sends nothing: add the repository from an owner device.

The second is an installation that may do more than the one it replaces or, with none to replace,
more than its repository permits by itself, and every release that installs a native bridge or
declares a command integration.
`kr plugin install` asks without a confirmation, which is all an installation inside what is
already permitted needs. When the host answers that this one needs the owner, `kr` exits with
`OWNER_CONFIRMATION_REQUIRED` and says to confirm and install it from an owner device. It leaves no
confirmation waiting.

## `kr host startup`

```sh
kr host startup                        # what is chosen, where it was chosen, and the definition
kr host startup --set service          # your own service manager starts the control daemon
kr host startup --set standalone       # kr new starts the control daemon itself when none runs
kr host startup --clear                # choose nothing; kr new says what to set up instead
```

The choice is the `startup.controller` selection of the versioned per-user host configuration
document, and `--set` and `--clear` each apply one validated revision of it, making the
environment's own directories first on a host where no daemon has run yet. No daemon is asked,
started or ended: `kr new` reads the choice the next time it finds no daemon running, which is why
`kr doctor` reports it as applying at the next start. Neither choice enables lingering or obtains a
privilege.

`service` is for a host whose own per-user service manager should start the daemon. `--set service`
writes that manager a definition of the daemon, records exactly what it wrote in the environment's
state directory, and has the manager load it. From then on, `kr new` asks the manager to start the
daemon when none answers, and the manager is the daemon's parent. It starts one process however
many commands ask at once. `kr new` itself installs nothing: a definition that has gone, that kr did
not write, or that was changed after kr wrote it stops the command with `HOST_NOT_CONFIGURED`, names
the file, and says to run `kr host startup --set service`. The command never writes it again. The
same goes for a definition in the domain the environment's default execution profile no longer
implies, which the setup, run again, rewrites; and for a manager that would run anything but that
definition. On macOS that is a job launchd holds under the definition's label from another file or
in an earlier form. On Linux it is a unit the user manager loads from another file or has not
reloaded since it changed; a drop-in for the unit, wherever it is, with a line that sets a key
starting with `Exec` or the key `Type`; or a command the manager prints other than the
definition's. So the daemon's command comes from kr's file alone. A drop-in that sets the daemon's
environment, limits or timeouts is the host's or yours, and the manager applies it; `--set
service` names each drop-in the manager reads for the unit. kr leaves what a manager holds to the
person: it names the remedy, `launchctl bootout <domain>/<label>` or the drop-ins to look in, and
the setup takes the definition once it has been applied. kr ends no daemon, so it never runs
`launchctl bootout` itself.

Such a failure says what differs in kr's own words and the manager's fixed names for load states,
start types and settings. It never repeats what the manager printed, a file the manager names, a
drop-in's name or what the drop-in holds, or a path read back from kr's record. Instead it names
the commands that show them: `launchctl print <domain>/<label>` for a job, and for a unit `systemctl
--user cat kr-controller-<environment>.service`, which shows the files the manager reads for it,
and `systemctl --user show kr-controller-<environment>.service`, which shows what it holds.

| Platform | The definition | Where it is loaded |
| --- | --- | --- |
| macOS | a launchd job, `~/Library/LaunchAgents/kr-controller-<environment>.plist` | your graphical domain when the environment's sessions are desktop-bound by default, your background domain when they are headless |
| Linux | a systemd user unit, `kr-controller-<environment>.service` in `$XDG_CONFIG_HOME/systemd/user`, `~/.config/systemd/user` by default | the user manager, with no `[Install]` section, so nothing enables it |

On Linux, kr asks the user manager everything through `systemctl --user`, from the same
environment with the runtime directory set, so every question and every request makes the same
choice of manager and, while the managers stay as they are, reaches the same one. A host whose user
manager does not answer has no service start.

kr's definition runs the `kr-controller` installed beside `kr`, told this installation's runtime
and state roots, working in the environment's state directory and writing to its `controller.log`,
and has the manager start it only when a command asks: never at login, and not again after it ends.
Those are the definition's settings. On Linux a drop-in you or the host add can change the working
directory, where output goes and whether the daemon is restarted; kr checks the command and how it
is started, not those. The daemon runs in the manager's environment rather than the command's, as
every service the manager starts does.
A launchd domain is a login context, so the daemon of a desktop host runs in the graphical login,
keychain and all, and ends with it; a headless host's daemon runs outside that login and outlives
it. `--set service` refuses a definition already under that label that kr did not write, or one
changed since kr wrote it, and leaves it exactly as it is.

`--clear` and `--set standalone` remove exactly what `--set service` wrote, the definition and its
record, and end nothing. Setup, removal and `kr new` take turns: each holds the environment's
`controller-service.lock` while it looks at or changes the definition or the manager's job, and
`kr host startup` holds it until the configuration document is written too. A daemon the manager is
running keeps serving. launchd keeps the job until its domain ends: the graphical domain ends at
logout, and the background domain can outlive it. kr asks it to start nothing more, though a start requested just before
may still complete. The user manager forgets the unit once the daemon stops. A definition changed
after kr wrote it is no longer kr's to remove, so it stays where it is and the command says so. `kr doctor` reports whether the definition matches
what kr wrote.

`standalone` is for a host with no service manager set up to start the daemon: `kr new` runs the
`kr-controller` installed beside it, detached from the command, as
[When no control daemon is running](#when-no-control-daemon-is-running) describes. On Windows both
are refused, and the daemon is started by hand: the standalone start runs the daemon in a session of
its own, which Windows does not have, and this build writes service definitions for launchd and
systemd only.

## `kr host power`

Automatic sleep is the machine's own policy, and `kr` changes it only when you ask:

```sh
kr host power                     # the setting, and what it is doing right now
kr host power --set mains_only    # stay awake for admitted work, on mains power
kr host power --set battery_too   # the same on battery, which is a separate choice
kr host power --set off           # the default
```

The setting is one section of the versioned per-user host configuration document, and `--set`
applies one validated revision of it. Writing it installs no service, obtains no privilege and
changes nothing else about the machine. `docs/host/README.md` has the document's schema, where it
lives and what decides a value when a request, a profile and the document disagree. With it on, the host holds the platform's own assertion
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

`kr status --json` also carries `terminal_attachments`: each terminal attachment of the session as
its worker reports it, with how it is presented and why. `presentation` is `direct` or `viewport`,
and `presentation_reason` is null for a direct attachment, which needs no reason, and for a
viewport whose worker was built before reasons existed. It is null as a whole for a session read
from the control daemon, which has no live worker to ask; when the worker answered the session read
and not the question about its attachments, within 10 seconds of being asked,
`terminal_attachments_unread` says why.

```json
{
  "terminal_attachments": [
    {
      "attachment_id": "0f8e2a64-9b1d-4c3e-8a57-2b6d9e1f4c70",
      "presentation": "viewport",
      "presentation_reason": "size_mismatch",
      "dimensions": { "columns": 100, "rows": 30 },
      "terminal_profile_id": "xterm-256color"
    }
  ]
}
```

The text form prints one line per terminal attachment, and a viewport's line names its reason and
what it means:

```text
attachment 0f8e2a64-9b1d-4c3e-8a57-2b6d9e1f4c70: viewport (size_mismatch): its size is not the session's
```

The reason is the first of these that holds, in this order:

| Reason | What keeps the attachment off the live stream |
| --- | --- |
| `no_terminal_profile` | its client declared no terminal profile, as `--no-probe` does |
| `unqualified_terminal_profile` | the profile its client declared is not one this build has qualified |
| `size_mismatch` | its size is not the session's |
| `history_window` | its window is above the live screen |
| `stream_not_carryable` | the session's output is no longer something a terminal can be handed as it is |
| `restoration_incomplete` | the screen it was last given could not carry everything the application addresses, such as a pending wrap |
| `awaiting_parser_boundary` | forwarding waits for the session's output to reach the end of a sequence |

The first three last as long as the attachment stays as it is, the window until the person
returns to the live screen, and the others pass by themselves.

A closed session carries its record instead of a null: whose it is, how it closed, the owned
processes the closure terminated and anything that survived it.

```json
{
  "session_id": "d6d64b2b-f6f1-4617-a07a-bb89a08cd3fd",
  "session_epoch": "1",
  "terminated": [
    {
      "pid": 48213,
      "start": { "pid": "48213", "source": "macos_proc_bsd_info", "start_value": "1789484600112233" },
      "name": "zsh",
      "forced": false
    }
  ],
  "surviving": [],
  "reason": "close_requested",
  "exit_code": null,
  "signal": null,
  "ownership_coverage": "incomplete",
  "durability": "durable",
  "closed_at_ms": 1789484611722
}
```

`kr new --json` adds four members to the session object. `presentation` is `attach`, `terminal` or
`invisible`. `presentation_error` says why the session could not be shown that way, and is null
when it was. `execution_context_chosen` says whether `--desktop` or `--headless` was given. `outcome`
is the line the attachment of this terminal ended with, and null when there was no attachment. When
that attachment ended with the session's closure, `state` is `closed` and `closure` is the record,
so the document describes the session as the command leaves it.

`kr attach --json` returns how the attachment ended, with the record when the session closed:

```json
{
  "ok": true,
  "session_id": "d6d64b2b-f6f1-4617-a07a-bb89a08cd3fd",
  "outcome": "the session closed: its shell exited with status 0",
  "closure": {
    "reason": "root_exit",
    "exit_code": 0,
    "signal": null,
    "ownership_coverage": "incomplete",
    "durability": "durable",
    "closed_at_ms": 1789484611722
  }
}
```

`ok` is false whenever the exit status is not 0. `closure` is null unless the attachment ended with
a record it could read.

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

`kr host startup --json` returns what is chosen and where it was chosen. `controller` is
`standalone` or null, `source` is `host_configuration` or `default`, `document_state` is the
document's condition as `kr doctor` names it, and `revision` is the document's revision as text:

```json
{
  "ok": true,
  "environment_id": "70a528be-be60-4cfb-870e-e3d3ba30344d",
  "startup": {
    "controller": "standalone",
    "source": "host_configuration",
    "document": "/home/example/.config/kalareach/environments/70a528be/config.json",
    "document_state": "loaded",
    "revision": "4"
  }
}
```

`kr pair invite --json` returns the invitation:

```json
{
  "ok": true,
  "invitation_id": "0b8a1c3e-4d5f-4a6b-8c7d-9e0f1a2b3c4d",
  "expires_at_ms": 1789484911722,
  "mode": "code",
  "code": "4XkP-Qm7-Zr2",
  "rendezvous_origin": "https://reach.kala.to",
  "qr_text": "..."
}
```

A direct invitation has `"mode": "direct"` and no `code` or `rendezvous_origin`. `kr pair status
--json` and `kr pair cancel --json` return the host's status of the invitation, with `ok` and
`invitation_id` beside it; the issuing owner also gets `owner`, what it may approve:

```json
{
  "ok": true,
  "invitation_id": "0b8a1c3e-4d5f-4a6b-8c7d-9e0f1a2b3c4d",
  "status": { "open": { "remaining_confirmations": 5, "expires_at_ms": 1789484911722 } },
  "owner": { "mode": "code", "grant_kind": "personal_owner", "remaining_confirmations": 5, "...": "..." }
}
```

`kr pair confirm --json` returns `ok`, `invitation_id`, `device_id`, `grant_id`, `device_name` and
`platform`.

`kr project`, `kr workspace`, `kr changeset`, `kr diff`, `kr device` and `kr plugin` print the
host's answer exactly as it sent it, with `ok` beside it. `kr project list --json` is
`{ "ok": true, "projects": [ ... ] }`, and `kr workspace create --json` carries `workspace`, which
is null for a preview, beside `preview` and `unapplied`. Identifiers are strings, and so are 64-bit
counts, which the host writes as decimal text.
