# kalareach/kimi-code-cli

Recognises the kimi.com Kimi Code CLI distribution, reads its agent protocol through a declarative
table, and stops the turn it is running.

## What it does

KalaReach matches the `kimi` executable, labels the session, and runs Kimi Code CLI through its
ordinary terminal path. That terminal is the default and it stays exactly as Kimi Code CLI draws it.
What this package adds is a reading of the agent protocol the same build speaks, and one control
over the turn.

`connector.json` is the declarative native-proxy table for that protocol: one JSON document per line
over the bound process's standard streams, identifiers at `id`, methods at `method`, responses
matched by repeating the `id`. Core code reads that table directly, so nothing of this package's
sits on the forwarding path.

## Which distribution, and why that matters

Two distributions share the name Kimi. This package is the profile for the kimi.com one, which
installs under `~/.kimi-code` and reports itself as Kimi Code CLI. The other is MoonshotAI's
`kimi-cli`, which installs under `~/.kimi` and has its own flags and its own server contract; it is
a separate profile with its own record, match rules and version line.

The distribution and the execution owner are read before any protocol is chosen. The rule that
names the installation directory is what identifies this one; a rule that recognises an executable
called `kimi` by name alone is a guess, and it is reported as a guess. An executable with that name
establishes nothing about which server contract is available, and a directory of saved sessions
establishes nothing about which process owns the live one. When the installed evidence does not
match the distribution this package pins, the capability is incompatible, every control this package
draws disappears, and the terminal is what is left.

The table is pinned to Kimi Code CLI 2.0.2 and qualified against that version alone.

## The agent protocol is a mode you choose

Starting the agent-protocol mode creates its own execution over standard streams. It is not a second
engine attached to the conversation already running in a terminal, and nothing here replaces the
terminal route with it. Attaching a terminal to a server this package selected would need source or
executable verification that this qualification does not have, so the package neither claims it nor
offers it.

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

No attachment contribution, and nothing that depends on the vendor's own web server or its remote
service. The default route is the terminal, where the composer's own syntax is what inserts a file,
and this package qualifies no composer syntax.

## Fixtures

`fixtures/conformance.json` states what a person sees in eight situations, and the build evaluates
this package's own predicates against each one. They are display conformance and only that: the
runner reads no agent frame. One case is an installation of the other distribution, where both
controls disappear and the terminal path is what remains.

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
