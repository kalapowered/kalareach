# kalareach/qoder-cli

Recognises Qoder CLI, reads its agent protocol through a declarative table, and stops the turn it is
running, with the terminal as the default route.

## What it does

KalaReach matches Qoder CLI's own entry points, labels the session, and runs it through the ordinary
terminal path. That terminal is the default and it stays exactly as Qoder CLI draws it, and it
carries everything the upstream has no typed path for. What this package adds is a reading of the
agent protocol the same build speaks, and one control over the turn.

`connector.json` is the declarative native-proxy table for the agent protocol the same build speaks
over its standard streams: one JSON document per line, identifiers at `id`, methods at `method`,
responses matched by repeating the `id`. Core code reads that table directly, so nothing of this
package's sits on the forwarding path.

## The agent protocol is a mode you choose

Selecting agent-protocol mode starts a subprocess with its own execution. The published
documentation establishes no way to attach to a terminal that is already running, so this package
does not offer one, and selecting the mode never replaces the terminal route.

The table is pinned to Qoder CLI 1.1.59 and qualified against that version alone. Qoder CLI installs
itself under `~/.qoder` and keeps its executable under a name that carries the version, selecting it
through a stable dispatcher and a stable command name. The rules here recognise both: the two stable
names wherever they are installed, and the versioned file of the release this package is qualified
against, under the directory the vendor installs it into. A match rule compares a whole file name,
so the versioned rule names one release and covers the one this table was qualified for; another
release is recognised by the stable names until a package qualified against it names its file too.
Every rule here reports itself as a guess rather than as proof, because no registry publishes this
application.

## What it classifies

Twenty-two methods, each with the evidence it was classified against.

Thirteen travel from the host to the agent. `initialize` negotiates what the connection may
afterwards be asked to do; `session/new`, `session/load`, `session/prompt`, `session/resume`,
`session/close`, `session/delete` and `session/fork` change what exists or what the agent is doing;
`session/set_mode` alters what the agent runs without asking, and `session/set_model` changes the
model. `session/list` reads the stored sessions without loading one, which makes it an observation.
`authenticate` is a credential method, because it starts the vendor's own credential flow and the
broker never passes a credential to a component. `session/cancel` ends the turn in flight.

Nine travel the other way, because the agent asks the host for things. `session/update` carries the
turn's own stream and is an observation. `session/request_permission` is a reverse request naming a
tool call the agent is waiting on, and answering it runs or refuses that call, so it is a mutation
rather than a report. The filesystem and terminal requests are the rest: reading a file and reading
a terminal's output observe, while writing a file, starting a process, ending one and releasing a
terminal change something. Every one of them runs in the host environment the session selected,
under that environment's own identity and with resources the broker scopes.

A method this table does not list is treated as a mutation. That is the safe answer to a name a
publisher forgot, and nothing in the file changes it.

## What it does not carry

No component, and so no approval decoder. A pending tool approval stays with the gateway and the
terminal that asked for it; this package offers no button that would answer one.

No prompt action. A control supplies parameters, and the declarative binding has no way to say "the
broker fills the bound session here", so an action that sent `session/prompt` would have to let a
control name the session.

Nothing that uses the vendor's remote-control feature. That feature runs through Qoder's own
application and account, which is not a protocol this package may reuse, so no capability here
depends on it.

No attachment contribution, and no hook registration. The default route is the terminal, where the
composer's own syntax is what inserts a file; this package qualifies no composer syntax, writes
nothing into Qoder CLI's settings, and claims no automatic insertion.

## Fixtures

`fixtures/conformance.json` states what a person sees in eight situations, and the build evaluates
this package's own predicates against each one. They are display conformance and only that: the
runner reads no agent frame. One case is an installed version this table is not qualified against,
where both controls disappear and the terminal path is what remains.

`fixtures/frames.json` is the other half: eight frames, each marked with where it came from. Two
are the exact requests that were sent to the pinned build over its standard streams and answered,
one is that request with its working directory replaced, and five are written from names present in
that build's executable. Each carries the method the
table should find, the route and class it should reach, the identifier the table's path should
extract with its JSON type, and the members its own situation is about. The test
`every_pinned_frame_is_read_the_way_the_table_says` under `cargo test` reads every one of them
through this package's own table.

Each is a frame, not a sequence. What a host does across a pending permission, a reconnection or a
competing answer is the gateway's and is not settled here.
