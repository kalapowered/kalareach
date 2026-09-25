# kalareach/gemini-cli

Recognises Gemini CLI, reads its agent protocol through a declarative table, and stops the turn it
is running, with the stock terminal untouched.

## What it does

KalaReach matches the `gemini` executable, labels the session, and runs Gemini CLI through its
ordinary terminal path. That terminal is the default and it stays exactly as Gemini CLI draws it. It
carries everything the upstream has no typed path for, and this package adds a reading of the agent
protocol the same build speaks, plus one control over the turn.

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

No hook registration. Nothing here writes into Gemini CLI's settings, so the observations a hook
would add are not among the ones this package claims, and neither this document nor the session view
it draws suggests otherwise.

## Fixtures

`fixtures/conformance.json` states what a person sees in eight situations, and the build evaluates
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
