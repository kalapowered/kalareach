# kalareach/opencode-attach

Recognises OpenCode, reads the event stream of the server that `opencode serve` starts and
`opencode attach` connects a terminal to, through a declarative table, and stops the turn it is
running.

## What it does

KalaReach matches the `opencode` executable, labels the session, and runs OpenCode through its
ordinary terminal path. That terminal stays exactly as OpenCode draws it, attached to the server it
was started against, and the session reads the same server. What this package adds is a reading of
what that server is doing, and one control over it.

`connector.json` is the declarative native-proxy table. It states the framing, where a message
carries its identifier, where it names its method, how a response is matched to its request, which
methods travel which way, and what each one does. Core code reads that table directly, so nothing of
this package's sits on the forwarding path.

## Which API family, and why that matters

OpenCode's server answers two distinct API families from the same build, and they are not
interchangeable. This package is the profile for the earlier one: the unprefixed routes that a
server started with `opencode serve` offers to a terminal started with `opencode attach <url>`. Its
event stream at `GET /event` carries each event as an envelope with `id`, `type` and `properties`.
The shared per-user family serves `/api/...` instead, and its stream at `GET /api/event` publishes
the same event names with the payload under `data`. That family is a separate profile with its own
package, `kalareach/opencode`.

This package covers the earlier family alone. It is pinned to OpenCode 1.18.31 and qualified against
the OpenAPI document that build serves, so which family a connection belongs to is settled from the
installed version and the served schema before the connection is opened, never from the name of an
executable.

An event name will not settle it on its own. This family publishes eighty-nine names and the
shared-server family publishes eighty-eight of them. The one it lacks, `server.instance.disposed`,
belongs to this family alone, so seeing it is evidence of the family this table was qualified
against, and the table reads it as the observation it is. No name belongs to the shared-server
family alone, so there is none this table could refuse by name: a frame from that family routes by
its shared name, and its payload sits under a member this table never reads, so the table extracts
nothing from it. `fixtures/frames.json` pins one envelope of each kind.

When the installed evidence does not match the version and the schema this package pins, the
capability is incompatible, every control this package draws disappears, and the terminal is what is
left. Reading that evidence is the host's; what this package settles is what it draws once the host
has read it.

## What it classifies

Eighty-nine event names, each with the evidence it was classified against: every name in this
family's event union, with nothing added and nothing left out. An event that reports what the session
did is an observation: turn steps, text and reasoning chunks, tool calls and their results, changed
files, the sessions that are idle, and the permissions and questions the session is waiting on,
under their earlier names and under the newer ones this build also publishes on this stream. None of
them carries a credential.

Four are not observations. `tui.session.select` moves the attached terminal to another conversation,
which changes the execution a binding is observing, and `tui.toast.show` writes on that terminal's
screen; both are mutations. `tui.prompt.append` writes into the native composer and
`tui.command.execute` runs a named terminal command, including `prompt.submit`. This package
qualifies no composer insertion and no terminal control surface, so the table declares both
unsupported rather than proxying them.

An event this table does not list is treated as a mutation. That is the safe answer to a name a
publisher forgot, and nothing in the file changes it.

## What the table covers, and what it does not

It covers the event stream: the leg on which the server tells every attached client what happened.
That leg has a framing, a method name at `type` and an identifier at `id`, which is the durable
identifier the stream orders by. Nothing travels the other way on it, so there is no request here
for a response to answer; the correlation the table declares repeats the same identifier, and that
is all it means on this leg.

It does not cover the request leg. Asking that server to do something is an HTTP request, whose
method is a verb and a path rather than a member of a document, and a connector table names methods
by a path into a decoded message. `docs/qualification-notes.md` in this repository records that gap
alongside the rest of the qualification.

Interrupting a turn therefore goes through the broker's own cancellation against the bound
execution, not through a method this table routes. The message size the table declares is the bound
this host enforces while reading frames, not a limit OpenCode states.

## What it does not carry

No component, and so no approval decoder. A pending OpenCode permission stays with the gateway and
the terminal that asked for it; this package offers no button that would answer one.

No prompt action, and no attachment contribution. The ordinary route is the terminal, where the
composer's own syntax is what inserts a file, and this package qualifies no composer syntax and
claims no automatic insertion.

Reading a stored session is not evidence that this process owns the live execution, and nothing here
treats it as though it were. Nothing in this package adopts a server holding somebody else's
sessions: the binding is to the execution the launch produced.

## Fixtures

`fixtures/conformance.json` states what a person sees in eight situations, and the build evaluates
this package's own predicates against each one. They are display conformance and only that: the
runner reads no OpenCode frame. One case is an installation of the shared-server family, where both
controls disappear and the terminal path is what remains.

`fixtures/frames.json` is the other half: nine event frames written from the event schemas in the
OpenAPI document the installed build serves, each checked against the schema of the family it
belongs to. Each carries the method the table should find, the route and class it should reach, the
identifier the table's path should extract with its JSON type, and the members its own situation is
about. The test `every_pinned_frame_is_read_the_way_the_table_says` under `cargo test` reads every
one of them through this package's own table.
`a_frame_from_the_other_api_family_is_unsupported_or_carries_no_payload` checks the envelope from the
shared-server family, and
`a_name_only_one_api_family_publishes_is_read_by_its_own_table_and_refused_by_the_other` checks
`server.instance.disposed` against this table and against the shared-server package's. The frames
also pin the evidence they were written against, by digest.

Each is a frame, not a sequence. What a host does across two pending permissions, or across a
reconnection to the server, is the gateway's and is not settled here.
