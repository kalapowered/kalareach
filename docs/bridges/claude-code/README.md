# The Claude Code bridge

Claude Code has no protocol the worker's gateway can sit in front of. A channel is an MCP server
that Claude Code starts as its own child and talks to over that child's standard streams, and a
hook is a command it runs for an event. So the only place KalaReach can stand is where those
processes stand. The Claude Code connector package installs a small registration that makes Claude
Code start `kr-hook`, the core forwarder, in both places. `kr-hook` carries what Claude Code says to
the endpoint of the launch it belongs to, and the worker's gateway for that launch decides
everything about it.

What follows is the contract between the two: what the forwarder sends, and what the gateway checks
and does when it serves a launch's endpoint. The gateway serves a launch it made; the section
"Finding the worker" says what that launch publishes, and "Launching from the shell" says how a
`claude` typed at a managed prompt becomes one.

The forwarder runs under Claude Code's own permissions, outside the KalaReach plugin sandbox and
outside Wasmtime. The package's installation grant says so before anything is installed.

## What the package installs

Three files under the user's own Claude Code directory, and one settings key:

| File | What it registers |
| --- | --- |
| `skills/kalareach-channels/.claude-plugin/plugin.json` | The plugin `kalareach-channels`, off by default, whose channel is the server `kalareach` |
| `skills/kalareach-channels/.mcp.json` | The server `kalareach`: `kr-hook claude-code channel` over standard input and output |
| `skills/kalareach-channels/hooks/hooks.json` | `kr-hook claude-code hook` for `SessionStart`, `SessionEnd`, `PostToolUse`, `PostToolUseFailure` and `Notification`, with a one-second timeout for `SessionEnd` and five seconds for the rest |

Every hook is registered in exec form, a `command` with its `args`, and runs in the foreground, so
Claude Code starts `kr-hook` itself, with no shell between them, and waits for it. The settings key
`enabledPlugins."kalareach-channels@skills-dir"` turns the plugin on, and removing it turns the
plugin off. The core repository keeps a copy of the three files in
`fixtures/bridges/claude-code/`, pinned by the SHA-256 digests the package's recipe records, and
`crates/kr-hook/tests/fixtures.rs` checks that every invocation they name is one the forwarder
accepts, and that every hook is in that form. A package change moves the copies and the digests
together.

The host applies the recipe in `.claude` in the account's home, the directory Claude Code reads when
`CLAUDE_CONFIG_DIR` is not set, once the owner's confirmed installation of the release has
committed, and removes it when the package is removed; `docs/plugins/catalogue.md` says what it
checks before writing anything and what a removal leaves. One of those checks is Claude Code's
version, which only a signed record naming its executable by digest establishes; no release carries
one yet, so the recipe is refused and nothing is written. The settings key is spliced into the
person's own `settings.json`, so every other byte of it stays as it was. The registration names the
forwarder as `kr-hook`, a bare command Claude Code finds on its own search path. The installation
expects the `kr-hook` beside the daemon, and a connection running another copy is refused at
admission, so the launched Claude Code has to find that one first.

The five hook events are the ones whose exit codes refuse nothing: the action has already happened,
or the code is ignored. A hook here observes because the forwarder never answers anything but `{}`,
and on these five events even a wrong exit code could not block anything.

## The command line

`kr-hook` accepts exactly the invocations the registration names, the relay a launched agent uses,
and the launcher the shell runs for an integrated command:

```
kr-hook claude-code channel
kr-hook claude-code hook
kr-hook relay
kr-hook launch -- <executable> <command name> <arguments...>
```

Anything else is refused on standard error before anything is read or connected, with exit code 64.
That code is deliberate. Claude Code reads a hook's exit code 2 as a request to block the action it
observed, and on `PostToolUse` it hands the hook's standard error to the model. A forwarder invoked
wrongly can do neither.

The launcher fails the way a shell does when it cannot run the program: 126 when the file cannot be
executed and 127 when it is not there. It also exits 126, running nothing, when its registration
variable names no launch it could have been given.

## Finding the worker

The worker writes two files for every launch it makes, both inside its owner-only runtime
directory:

- The registration file: one `name=value` line each for the endpoint, the launch profile, the
  application instance, the process it launched and its start value, the credential file, and the
  framing. Nothing in it is secret.
- The credential file: the launch's private exchange, 64 hexadecimal characters, written owner-only
  beside the registration.

The launched application's environment names one of them: `KR_REGISTRATION` is the registration's
path and nothing more, and the registration names the credential file. One variable is what
survives Claude Code's `CLAUDE_CODE_SUBPROCESS_ENV_SCRUB` setting, which removes anything named
like a credential from the environment of the hooks and servers it starts and keeps
`KR_REGISTRATION`. A hook inherits Claude Code's environment, as the hooks reference documents; the
channel server relies on Claude Code passing the same variable to the MCP servers it starts. A
`KR_SESSION` in the environment goes into the hello as a diagnostic and decides nothing: a process
whose environment names no registration is outside any launch, whatever else it carries.

The forwarder reads the endpoint as a socket path or a loopback address, and refuses anything
else. It reads the credential only from a file in the registration's own directory, and refuses a
credential file that another user could read, because the exchange in it would already belong to
somebody else too.

## Launching from the shell

When the Claude Code connector's command integration is on, a `claude` typed at a managed Zsh or
Bash prompt starts under a launch the worker made for it. The shell asks the worker about the
command before it forks, as the shell integration's contract describes, and for an integrated
command the worker establishes a backend: an endpoint in a fresh owner-only directory, a credential,
and a launch record, `launch`, that names the two. Nothing is reserved and no registration exists
yet. The answer adds the integration's flags to the vector and gives the forked child
`KR_REGISTRATION` and the absolute path of the installation's `kr-hook`, which the child runs as
`kr-hook launch -- <executable> claude <arguments...>`.

The launcher presents itself on the endpoint with the credential, its process and start, the
executable and the vector. The worker admits it only when the kernel names the connecting process
as the root shell's own child, started after the establish; the credential is the backend's; the
executable is the file the worker identified for the backend and the vector is the one it answered;
and no other launch holds the backend. It then records the launch profile, registers the instance,
writes the registration naming the launcher's own process, and answers `admitted`. The launcher
answers `going`, the worker commits the launch and answers `committed`, and only then does the
launcher exec Claude Code in place. The process keeps its identifier and its start, so the
registration names Claude Code before Claude Code runs. A hook that connects while the commit is
still under way waits for it, within its hello deadline, rather than being refused for arriving
first.

Anything short of that runs what was typed. On a refusal, on no answer within two seconds (counted
from the launcher's start for the admission, and from `going` for the commit), or when it cannot
reach the endpoint or read the launch record, the launcher takes `KR_REGISTRATION` out of its
environment and execs the vector the person typed, without the integration's flags. It needs
nothing from the backend for that, because the registration's file name, `registration.<at>.<n>`,
says that `<n>` added flags start at index `<at>`. A Claude Code started with the flags and nothing
behind them would be worse off than one started without them. With no `KR_REGISTRATION` at all, the
launcher execs its vector as given.

One invocation binds a backend. A retry of that same invocation (the same vector, file, directory
and directory revision) gets the same backend, and a second integrated command in the line, such as
the `claude b` of `claude a; claude b`, runs as typed. A backend no launch took is retired when its
line's command block finishes, when a later prompt asks about a command, or when the session closes;
a committed one ends when Claude Code exits or the session closes. Retiring a backend removes its
endpoint, credential, launch record and registration.

The worker also checks what Claude Code's process runs. When it establishes the backend it opens
the executable the shell found, once, reads its identity, hashes it with SHA-256, and takes the
version a signed qualification record names for that digest. It reads no version from anything
beside the executable, such as a `package.json`, which can change before or after the binary does.
A script is refused, because its running image is its interpreter. Then, for every bridge that
authenticates, it checks that the process runs what was hashed. On Linux that is the file
`/proc/<pid>/exe` names, compared by its whole identity or, when the identity moved, by its content,
so an upgrade installed over the running file passes and a rewrite of its code does not. On macOS it
is the code-directory hash the kernel reports for the process's main executable, which must be one
of the hashed file's own. A mismatch refuses that bridge and every later bridge of the launch, so a
Claude Code that execs another program in its own process loses its bridges from then on.

The Claude Code package asks for no file access, so its launch is granted no directory to read.

No package can turn a command integration on yet, and the worker does not yet receive the installed
connectors it launches from, so today a `claude` typed at a prompt runs as typed.

## A Claude Code the integration did not launch

Claude Code started any other way is adopted rather than launched: by absolute path, with its
integration off, after a refused or retired launch, in a pipeline or another form the shell does not
ask about, or from a shell that does not ask. Four times a second, while a command has the terminal,
the worker looks at the terminal's foreground process group. It adopts a process there that the
root shell started itself, that no launch holds, and whose executable the connector recognises, and
records it as a native terminal instance. The record holds the executable and argument vector the
kernel reports, the executable's digest, and the reason the shell's question about it was answered
with a bypass, where the line running it asked one.

An adopted Claude Code gets no registration, endpoint or credential. Its environment names no
registration either, since a bypassed invocation is given no variable, so its hooks answer `{}` with
nothing to report to and its channel declares nothing. None of its bridges is admitted. The instance
ends when its process exits. Adoption recognises Claude Code by the installed connector, which the
worker does not yet receive, so today nothing is adopted.

Every instance, launched or adopted, is announced to the session's attached views when it starts,
when its bridges are refused and when it ends, with its mode, its plugin and profile, and the reason
its bridges are refused where they are. An adopted instance's announcement says that none of its
bridges is admitted. When the session closes, its instances end with it and the views are told
before they detach.

## Admission

The forwarder connects to the endpoint and writes one line before anything else:

```
{"kr_hello":{"credential":"<hex>","pid":4242,"start":381742,"session":null,"headers":{},
 "bridge":{"application":"claude-code","surface":"hook"}}}
```

The worker reads that line under a five-second deadline and nothing past it until it has decided.
It refuses the connection, without a word, unless every one of these holds:

1. The connection comes from the user who owns the session, and on a private socket the kernel
   names the connecting process.
2. The process the hello presents is the one the operating system reports for that identifier, and
   on a private socket it is the process the kernel named.
3. The launched application started it. The worker walks the kernel's parent chain from the
   connecting process to the process it launched, and checks every link by its start identity, so
   an identifier recycled since the application started does not complete the chain. Each parent is
   read between two readings of its child that both name it: a child's recorded parent changes when
   that parent exits and never changes back, so the process read was still its parent. No wall-clock
   start is compared, so setting the clock back cannot break a real chain. A bridge whose start the
   platform records on a clock that only moves forward is refused when that record cannot be read.
4. It is the installation. The worker recorded, for the launch, which package's bridge is installed,
   the application name its registration invokes the forwarder for, the surfaces it registered and
   the forwarder executable it points Claude Code at. The hello's declaration must name that
   application and one of those surfaces, and the process must be running that executable.
5. The credential is the launch's own, compared in constant time where the launch's record keeps it.
6. For a launch from the shell, the launched process still runs the file the worker hashed for it.
   Only a bridge that passed the five checks above asks, so only the application's own bridges
   decide it.

An admitted connection gets one line back, `{"kr_bridge":{"admitted":"hook"}}` or `"channel"`, and
then carries JSON lines of at most 1,048,576 bytes each, the bound the connector package declares.
A line past the bound ends the connection. So does a line the connection cuts short.

## Hooks

Whatever happens, a hook writes exactly `{}` to standard output and exits 0. It waits for the worker
for at most 500 milliseconds from its start and then answers anyway, and it never waits for a
person. A diagnostic goes to standard error only after the answer, and is waited for until those 500
milliseconds are up, or for 100 milliseconds after an answer that came at them: a standard error
nobody reads cannot hold the hook longer, and a line not written by then may be lost when the hook
ends. Claude Code writes standard error to its debug log for an exit-0 hook and shows it to nobody.
A report counts only if the worker admits its hook while the hook is still running: the worker
checks the hook's process as it admits it, so a report whose hook has already answered and gone is
lost, and nothing tells the worker it was sent.

Inside a launch, the forwarder turns Claude Code's payload into one observation and sends it
straight behind the hello. It reads only what it reports and skips the rest, including a tool's
whole response. Then it waits for the worker to admit it, apply the observation and close the
connection. When that exchange completes, the worker has the report before the hook answers Claude
Code, which holds a session's first response until its `SessionStart` hooks finish. The worker does
not have it first when the hook reaches its deadline, or when Claude Code moves on without waiting,
as it may when `/clear` or a switch of conversation comes while background `SessionStart` hooks
still run; the report is then applied late, or, if the hook has already gone, not at all.

| Event | Observation | What the worker does with it |
| --- | --- | --- |
| `SessionStart` | `thread_started`, with `source` as its detail; `thread_continued` after a compaction | Selects the thread and advances the binding revision, even for the thread already selected; a compaction changes nothing |
| `SessionEnd` | `thread_ended`, with `reason` | Leaves no thread selected |
| `PostToolUse` | `tool_finished`, with the tool's name | Records it; for the contact skill's `ask_user`, also records which thread ran the request |
| `PostToolUseFailure` | `tool_failed`, with the tool's name | Records it |
| `Notification` | `notification`, with its kind and text | Records it |

The thread is Claude Code's `session_id`. `/clear` and an interactive `/resume` end one session and
start another; compaction starts the same one again, which changes nothing.

Only a hook the launched Claude Code process started itself reports its selection. The worker reads
which process started each hook from the kernel's parent link, checked by start identity, and a
report from a hook some other process started (another Claude Code the session runs, or a wrapper
between Claude Code and `kr-hook`) is recorded and moves nothing.

Every hook is its own process on its own connection, so reports can arrive in any order. The worker
places each by when the kernel recorded Claude Code starting its hook, on a clock that only moves
forward: on Linux the start time in clock ticks since boot, and on macOS the host's absolute time
at the fork rather than the wall-clock start, which a change of the clock can move back. Two hooks
from one tick of that clock are not placed against each other, because nothing the worker can
verify says which came first. To keep that rare, a hook that reports a session starting or ending
answers no sooner than 20 milliseconds, two Linux ticks, after it started. A hook Claude Code
starts only once that one has answered, as it does after a session ends, then falls in a later
tick.

The newest report decides the thread. A `SessionStart` for a resume, a clear or a fork is a new
selection even of the thread already selected, so the binding advances; one for a compaction
continues the thread and changes nothing. An older report still matters when its hook started after,
or in the same tick as, the report that began the binding's current revision: a thread starting or
ending there, or another thread going on, is a switch the worker learned of late, and a question
bound to that revision may have been asked across it. So the binding advances to a new revision of
what the newest report says, and the thread stays as it is. A report whose hook started before the
current revision began changes nothing.

A report that cannot be placed against the newest, because the two hooks fall in one tick, changes
nothing if it leaves the binding as it is whichever came first: an end when no thread is selected,
or the selected thread going on. Any other, a start included, leaves no thread vouched for, leaves
the thread the binding had so nothing bound to it survives, and suspends rich mutations until a
report whose hook started in a later tick settles it.

### Which thread asked a question

A contact question is asked through the contact skill's own server, which one Claude Code process
shares between all of its threads. When a question is asked, the worker records the thread the
bridge vouches is selected, and its revision. That is not the question's binding yet, because the
request may have come from a thread whose report had not arrived. When the `ask_user` call finishes,
its `PostToolUse` hook says which thread ran it, naming the call by its request identifier. Claude
Code runs `PostToolUse` only for a call that succeeded; a refused call is a `PostToolUseFailure`,
which names no request. So while the identifier names this one question, its reports are the
reports of the call that asked it. If they name the thread recorded when the question was asked,
the question is bound to the revision recorded then, and a later switch of thread invalidates it for
every client. If the reports name another thread, or disagree with each other, the question stays
bound to the application alone and claims no thread-switch detection. Once the identifier is used
again, by an exact retry that returns the question or by another question the same launch asked
under it, no one call asked under it, so no later report binds either question. A question already
bound by then was bound by its own call's report, before any other call used the identifier, and
stays bound.

## Channels

Before it answers Claude Code's handshake, the channel finds its registration, connects and waits
to be admitted, so what it declares is what holds. Admitted, it declares the Channels pair and no
tools:

```
"capabilities": {"experimental": {"claude/channel": {}, "claude/channel/permission": {}}}
```

It negotiates MCP revision 2025-11-25 at the newest, because Claude Code does not register a channel
server that negotiates 2026-07-28 on its v2 client runtime. Outside a launch it completes the
handshake and declares nothing. Inside a launch, if the worker refuses it, it exits 1 without
answering, so Claude Code shows the server as failed rather than as a channel nothing stands
behind.

Only three notifications cross, in the connector's own shapes, correlated at `params.request_id`:

| Notification | Direction | Checked |
| --- | --- | --- |
| `notifications/claude/channel` | worker to Claude Code | `content` is text; `meta` holds only text under keys of letters, digits and underscores; nothing else |
| `notifications/claude/channel/permission_request` | Claude Code to worker | `request_id`, five lowercase letters without `l`; `tool_name`, `description` and `input_preview` are text; only those four go on |
| `notifications/claude/channel/permission` | worker to Claude Code | `behavior` is `allow` or `deny`; `request_id` is one this channel relayed and has not answered |

A frame that fails its check is dropped with a line on standard error. Nothing becomes a different
frame: a malformed verdict, or one naming a request this channel did not relay, never reaches the
session as a message. A verdict is checked in full before the request it answers is taken, so a
malformed one leaves the request answerable by a correct one. An approval too large for the exchange
is not relayed, and the terminal's own dialog answers it.

The worker serves the channel of the launch's own Claude Code and no other. The channel's starter,
read from the kernel's parent link and checked by start identity, must be the process the launch
registered, and a launch has one channel open at a time. The channel is served only when a signed
qualification record names a version for the digest of the executable the launch hashed, and the
connector's table is qualified for that version. Any other channel is closed, and Claude Code's own
dialog answers.

Each relayed `permission_request` becomes a pending approval, recorded with its frame, and every
attached view is told of it. The first one is the evidence that the channel is registered, and it
makes the launch's `agent.approval` capability available until the channel closes. Claude Code
acknowledges no message into the session and no sender stands behind one, so the channel carries
none: `agent.prompt` has no evidence, and a steer, a cancellation and any other action of the
package are refused with their reasons. A frame the table does not route towards the worker closes
the channel, since the forwarder relays nothing else.

The worker interprets an approval when the session holds a binding of the connector's exact package
(its identifier, publisher and installed hash) whose installation was granted `approval.decode`. The
decisions it offers are the ones the table's decision destination maps, labelled with the choices of
the package's answer action. A client can answer it when the installation was also granted
`approval.respond`, through `agent.approval.respond` or through the package's action with
`plugin.action.invoke`. Either way the answer is written once on the channel as the verdict the
table maps, for Allow:

```
{"method":"notifications/claude/channel/permission","params":{"request_id":"abcde","behavior":"allow"}}
```

Without such a binding the approval stays visible and unanswerable, and the terminal's dialog
answers it. Nothing binds the package yet, so today that is every approval.

Claude Code tells the channel nothing back. An approval answered in the terminal stays pending here
until the channel closes, and a written verdict is never acknowledged: whichever answer Claude Code
takes first wins. When the channel closes, however it closes, the worker settles what it relayed. An
approval never answered is cancelled; one that was answered is uncertain, because nothing says
whether its verdict reached Claude Code. The channel's checks are the last ones before the bytes
leave KalaReach. When the worker closes the channel, the channel ends its session with Claude Code
and exits 1. When Claude Code closes its end, the channel exits 0.

## Platforms

Where the platform has a private socket, the endpoint is one inside the worker's owner-only
runtime directory, and the kernel names every connecting process. Elsewhere the endpoint is
loopback, and the credential is the whole authentication. On a platform where the host cannot prove
that a file is closed to other accounts, it writes neither the credential file nor the registration
that names it, so no bridge is admitted there, and a command the shell asks about gets no backend
and runs as typed. A forwarder whose environment names a registration it cannot read answers its
hooks with `{}` and ends its channel with a failure before the handshake, which Claude Code shows as
a failed server.

## What admission does not prove

Admission proves that a connection belongs to this launch and this installation. It does not make
the forwarder's reports true. Code running as the same user, a tool command Claude runs included,
can read the credential file and start the forwarder itself. Section 11 places arbitrary code under
the account inside the operating system's trust boundary, and this bridge claims nothing beyond it.

The image check proves what the process ran when it was read. A process that execs other code after
the check and before its bridge is answered has that bridge admitted, and its next bridge refused.
Holding a bridge to its program for as long as it is open would need the operating system to report
the exec and revoke the bridge.
