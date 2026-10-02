# kalareach/gemini-cli

Recognises Gemini CLI, observes its sessions through hooks, reads its agent protocol through a
declarative table, and stops the turn it is running, with the stock terminal untouched.

## What it does

KalaReach matches the `gemini` executable, labels the session, and runs Gemini CLI through its
ordinary terminal path. That terminal is the default and it stays exactly as Gemini CLI draws it. It
carries everything the upstream has no typed path for. This package adds hooks that report the
session's start, end and tool permission notifications, a reading of the agent protocol the same
build speaks, and one control over the turn.

`connector.json` is the declarative native-proxy table for the agent protocol Gemini CLI speaks over
its standard streams: one JSON document per line, identifiers at `id`, methods at `method`,
responses matched by repeating the `id`. Core code reads that table directly, so nothing of this
package's sits on the forwarding path.

## The agent protocol is a mode you choose

Starting Gemini CLI in agent-protocol mode creates its own execution. It is not a second engine
attached to the conversation already running in a terminal, and nothing here replaces the terminal
route with it. The published documentation names two flags for that mode; the build this table is
qualified against accepts `--acp` and also accepts `--experimental-acp`, which it marks as
deprecated. The table is pinned to Gemini CLI 0.60.0 and qualified against that version alone.

## What it classifies

Seventeen methods, each with the evidence it was classified against.

Eight travel from the host to the agent. `initialize` negotiates what the connection may afterwards
be asked to do, `session/new` creates an execution, `session/load` loads a stored conversation,
`session/prompt` submits a turn, and `session/set_mode` and `session/set_model` change how the
session will behave: all mutations. `authenticate` is a credential method, because it starts the
vendor's own credential flow and the broker never passes a credential to a component.
`session/cancel` ends the turn in flight; the protocol defines it as a notification, which carries
no identifier and gets no reply, and this qualification did not send one.

Nine travel the other way, because the agent asks the host for things. `session/update` carries the
turn's own stream and is an observation. `session/request_permission` is a reverse request naming a
tool call the agent is waiting on, and answering it runs or refuses that call, so it is a mutation
rather than a report. The filesystem and terminal requests are the rest: reading a file and reading
a terminal's output observe, while writing a file, starting a process, ending one and releasing a
terminal change something. Every one of them runs in the host environment the session selected,
under that environment's own identity and with resources the broker scopes, rather than wherever a
client happens to be attached.

A method this table does not list is treated as a mutation. That is the safe answer to a name a
publisher forgot, and nothing in the file changes it.

## What it does not carry

No component, and so no approval decoder. A pending tool approval stays with the gateway and the
terminal that asked for it; this package offers no button that would answer one.

No prompt action. A control supplies parameters, and the declarative binding has no way to say "the
broker fills the bound session here", so an action that sent `session/prompt` would have to let a
control name the session. A control that can name a session can name the wrong one.

No attachment contribution. The default route is the terminal, where the composer's own syntax is
what inserts a file, and this package qualifies no composer syntax and claims no automatic
insertion.

No hook for a tool. The hooks below report nothing about tool calls or their results, and this
package claims no tool observation.

## The hooks it registers

The native bridge installs an extension, `kalareach`, into your own Gemini CLI directory: its
manifest at `extensions/kalareach/gemini-extension.json`, its hooks at
`extensions/kalareach/hooks/hooks.json`, and at `extensions/kalareach/.gemini-extension-install.json`
the record Gemini CLI keeps of where an extension came from. Gemini CLI loads an extension's hooks
for every project and every later session, beside any hooks of your own, and runs them whether or
not you trust the folder. Nothing in your `settings.json` changes.

The record names `/dev/null/kalareach` as a local source, a path nothing can exist under. Gemini CLI
reads a local extension's updates from its recorded source, and it resolves a relative source,
`~/...` included, from the session's working directory, where a project could put a newer manifest
and have Gemini CLI offer it as an update. Nothing can be read from this one, so Gemini CLI never
offers an update for the extension; KalaReach replaces its files itself.

The record matters most where your settings list allowed extensions in `security.allowedExtensions`.
There Gemini CLI refuses to start at all while any directory under `extensions/` has no record, and
it loads an extension only when a pattern in the list matches the source its record names, so
`^/dev/null/kalareach$` allows this one. Without such a pattern, Gemini CLI skips the extension with
a warning and the session runs without these hooks.

Removing the bridge deletes those three files, each only while it still holds the bytes that were
installed, and the record last, only once nothing else is left beside it. Where something else has
to stay in `extensions/kalareach/`, a file of yours or one that changed since it was installed, the
record stays with it, so Gemini CLI does not refuse to start. What it does instead depends on what
stayed: with no manifest left it skips the directory with a warning, but a manifest that changed
and stayed still loads, with the hooks of a hooks file that changed and stayed beside it, so a
changed extension can remain active, under an allow list wherever a pattern allows the record's
source. Whatever removes the bridge also removes the directories the installation created once they
are empty, because an empty `extensions/kalareach/` is a directory with no record too.

The hooks start `kr-hook gemini-cli hook`, the KalaReach forwarder, for three events:
`SessionStart` and `Notification` with a five-second timeout, and `SessionEnd` with one second.
Gemini CLI runs a hook's command through `bash -c`, and bash runs a command of plain words like
this one in its own process, so the forwarder is Gemini CLI's own child. It runs under Gemini CLI's
permissions, outside the KalaReach plugin sandbox and outside Wasmtime. It reports the event to the
KalaReach worker that launched the session, stops waiting for the worker half a second after it
started, then answers `{}` with exit 0, and it never waits for a person. Outside a KalaReach launch
it answers the same way and reports nothing.

Those three are events whose refusals Gemini CLI ignores, and that is why there are no others.
Gemini CLI reads a hook's standard error as its answer when standard output is empty, and turns
plain text with an exit code other than 0 and 1 into a refusal. On a finished tool, a refusal
replaces the result the model reads. A forwarder that is missing, or too old to know this
invocation, prints exactly that kind of text, so a hook on tool events could change what the model
reads; on these three, the most it can do is a warning.

Gemini CLI starts a copy of itself as a child process and runs the session there, unless
`GEMINI_CLI_NO_RELAUNCH` is set. Without the command integration below, the hooks are that child's,
not the process KalaReach launched, so the worker records what they report and none of them selects
the session's thread.

## The command integration

The package declares a command integration that sets `GEMINI_CLI_NO_RELAUNCH=true`, the value Gemini
CLI gives the child it starts, and adds no arguments. When a person runs `gemini` in a KalaReach
session with the integration on, the process KalaReach launched runs the session itself and starts
the hooks, so they can select the session's thread.

That gives up what the child is for. The first process raises the child's memory limit to half of
the machine's memory where that is more than Node's default, unless the person's settings turn
automatic memory configuration off; without the child the session keeps Node's default, and a very
large session runs out of memory sooner. When the child exits to restart, after an update or for a
restart Gemini CLI asks for, the first process starts the session again; without it the session ends
and the person runs `gemini` again. The first process also keeps the administrator settings a child
reports and passes them to the next child it starts, which a session with no child never needs.

Applying the integration is a grant of its own, `command_integration.launch`, which the owner
confirms for every release that declares it. The grant says what the person gives up, beside the
variable exactly as the host sets it.

## Fixtures

`fixtures/conformance.json` states what a person sees in nine situations, and the build evaluates
this package's own predicates against each one. They are display conformance and only that: the
runner reads no agent frame. One case is an installed version this table is not qualified against,
where both controls disappear and the terminal path is what remains.

`fixtures/frames.json` is the other half: eight frames, each marked with where it came from. Two
are the exact requests that were sent to the pinned build over its standard streams and answered,
two are captures with one detail replaced, the working directory in the request that creates an
execution and the command list in the update that build sent back, and four are written from names
present in that build. Each carries the method the table should find, the route and class it
should reach, the identifier the table's path should extract with its JSON type, and the members its
own situation is about. The test `every_pinned_frame_is_read_the_way_the_table_says` under
`cargo test` reads every one of them through this package's own table.

Each is a frame, not a sequence. What a host does across a pending permission, a reconnection or a
competing answer is the gateway's and is not settled here.
