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
"Finding the worker" says what that launch publishes.

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

The five hook events are the ones whose exit codes refuse nothing: the action has already happened,
or the code is ignored. A hook here observes because the forwarder never answers anything but `{}`,
and on these five events even a wrong exit code could not block anything.

## The command line

`kr-hook` accepts exactly the invocations the registration names, plus the relay a launched agent
uses:

```
kr-hook claude-code channel
kr-hook claude-code hook
kr-hook relay
```

Anything else is refused on standard error before anything is read or connected, with exit code 64.
That code is deliberate. Claude Code reads a hook's exit code 2 as a request to block the action it
observed, and on `PostToolUse` it hands the hook's standard error to the model. A forwarder invoked
wrongly can do neither.

## Finding the worker

The worker writes two files for every launch it makes, both inside its owner-only runtime
directory:

- The registration file: one `name=value` line each for the endpoint, the launch profile, the
  application instance, the process it launched and its start value, and the framing. Nothing in it
  is secret.
- The credential file: the launch's private exchange, 64 hexadecimal characters, written owner-only.

The launched application's environment names them. `KR_REGISTRATION` and `KR_CREDENTIAL` are paths
and nothing more. A hook inherits Claude Code's environment, as the hooks reference documents; the
channel server relies on Claude Code passing the same two variables to the MCP servers it starts. A
`KR_SESSION` in the environment goes into the hello as a diagnostic and decides nothing: a process
whose environment names no registration is outside any launch, whatever else it carries.

The forwarder reads the endpoint as a socket path or a loopback address, and refuses anything
else. It refuses a credential file that another user could read, because the exchange in it would
already belong to somebody else too.

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
   an identifier recycled since the application started does not complete the chain.
4. It is the installation. The worker recorded, for the launch, which package's bridge is installed,
   the application name its registration invokes the forwarder for, the surfaces it registered and
   the forwarder executable it points Claude Code at. The hello's declaration must name that
   application and one of those surfaces, and the process must be running that executable.
5. The credential is the launch's own, compared in constant time where the launch's record keeps it.

An admitted connection gets one line back, `{"kr_bridge":{"admitted":"hook"}}` or `"channel"`, and
then carries JSON lines of at most 1,048,576 bytes each, the bound the connector package declares.
A line past the bound ends the connection. So does a line the connection cuts short.

## Hooks

Whatever happens, a hook writes exactly `{}` to standard output and exits 0 within 500
milliseconds. Diagnostics go to standard error, which Claude Code writes to its debug log for an
exit-0 hook and shows to nobody. If the worker does not answer in time, the hook answers anyway. It
never waits for a person.

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
orders them by what the kernel recorded when Claude Code started each hook process: the start value
first, and within one tick of the kernel's clock the process identifier, which Linux and macOS
allocate in sequence. Claude Code starts its hooks one after another, so the hook for a later event
has the later record. A report whose hook started after the one in force decides the thread, and one
whose hook started before changes nothing, whichever arrived first. A `SessionStart` for a resume, a
clear or a fork is a new selection even of the thread already selected, so the binding advances;
one for a compaction continues the thread and changes nothing. When two reports cannot be ordered
and one of them would change the binding in either order, the worker does not guess: no thread is
vouched for, the thread the binding had is left so nothing bound to it survives, and rich mutations
are suspended until a report whose hook started later settles it.

### Which thread asked a question

A contact question is asked through the contact skill's own server, which one Claude Code process
shares between all of its threads. When a question is asked, the worker records the thread the
bridge vouches is selected, and its revision. That is not the question's binding yet, because the
request may have come from a thread whose report had not arrived. When the `ask_user` call finishes,
its `PostToolUse` hook says which thread ran it. If that is the thread recorded when the question
was asked, the question is bound to the revision recorded then, and a later switch of thread
invalidates it for every client. If the reports name another thread, or disagree with each other,
the question stays bound to the application alone and claims no thread-switch detection. So does a
question the agent asked again with the same request identifier: no one call asked it, so no report
of a call can say which thread did.

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

The gateway hands the admitted channel's connection to its caller, which serves the application's
Channels traffic on it. Which answer goes is the worker's arbitration; the channel's checks are the
last ones before the bytes leave KalaReach. When the worker closes the channel, the channel ends its
session with Claude Code and exits 1. When Claude Code closes its end, the channel exits 0.

## Platforms

Where the platform has a private socket, the endpoint is one inside the worker's owner-only
runtime directory, and the kernel names every connecting process. Elsewhere the endpoint is
loopback, and the credential is the whole authentication. On a platform where the host cannot prove
that a file is closed to other accounts, it does not publish the credential, and the gateway makes
no launch there for a bridge to belong to. A forwarder whose environment names a registration it
cannot read answers its hooks with `{}` and ends its channel with a failure before the handshake,
which Claude Code shows as a failed server.

## What admission does not prove

Admission proves that a connection belongs to this launch and this installation. It does not make
the forwarder's reports true. Code running as the same user, a tool command Claude runs included,
can read the credential file and start the forwarder itself. Section 11 places arbitrary code under
the account inside the operating system's trust boundary, and this bridge claims nothing beyond it.
