# kalareach/codex

Recognises Codex CLI, reads its App Server through a declarative table, and stops the turn it is
running.

## What it does

KalaReach matches the `codex` executable, labels the session, and runs Codex through its ordinary
terminal path. That terminal stays exactly as Codex draws it. What this package adds on top is a
reading of what Codex is doing, and one control over it.

`connector.json` is the declarative native-proxy table. It states the framing (one JSON document per
line), where a request carries its identifier, where a message names its method, how a response is
matched to its request, which methods travel which way, and what each method does. Core code reads
that table directly, so no component of this package's sits between Codex and the host on the
forwarding path.

The table is pinned to the App Server protocol of Codex CLI 0.155.1 and qualified against that
version alone. A protocol revision is exactly the kind of change that moves a method between
classes, so the table carries forward to nothing.

## What it classifies

Forty-nine methods, each with the evidence it was classified against. Reads are observations.
Starting, steering, interrupting and compacting a thread are mutations, and so is every reverse
request whose answer changes what the agent does. The account methods are credential methods: the
broker keeps their answers and never passes them to a component.

Nine methods are declared unsupported rather than proxied. `thread/shellCommand` and `process/spawn`
run outside Codex's sandbox; `command/exec` runs a command with no thread or turn to bind it to; the
`config/*` writers rewrite the user's `config.toml`; the `fs/*` methods reach absolute paths through
Codex instead of through KalaReach's own file grant; and `account/logout` discards the credentials
somebody signed in with.

A method this table does not list is treated as a mutation. That is the safe answer to a method a
publisher forgot, and nothing in the file changes it.

## What the table covers, and what it does not

It covers the connection between KalaReach and the App Server: JSON-RPC 2.0 over the bound process's
standard streams, one document per line, identifiers at `id`, methods at `method`, responses matched
by repeating the `id`. On that connection the App Server meets the declarative proxy contract, which
is why this package installs no native bridge and edits none of Codex's settings.

It does not cover the native `--remote` connection. That client speaks WebSocket, over TCP or over a
Unix socket with an HTTP upgrade, which the table's framing vocabulary cannot describe. The leg
between the native terminal and the gateway is the gateway's own listener, and this package makes no
claim about it. `docs/qualification-notes.md` in this repository records that gap alongside the rest
of the qualification.

The message size the table declares is the bound this host enforces while reading frames, not a
limit Codex states. A response larger than it fails the connection rather than being read in part.

## What it does not carry

No component, and therefore no approval decoder. A pending Codex approval stays with the gateway and
the terminal Codex drew it in; this package offers no button that would answer it.

No prompt or steer action either. A control supplies parameters, and the declarative binding has no
way to say "the broker fills the bound thread here", so an action that sent `turn/start` or
`turn/steer` would have to let a control name the thread. A control that can name a thread can name
the wrong one.

Resuming a saved thread reads stored history. It does not establish that this process owns the live
execution, and nothing in this package treats it as though it did.

## Fixtures

`fixtures/conformance.json` states what a person sees in eight situations, and the build evaluates
this package's own predicates against each one. The cases are named for what they assert, which is
which controls a person sees and which of those they can use. They are display conformance, and only
that: the fixture runner evaluates control predicates and never reads a Codex frame, so nothing here
exercises framing, identifiers, transitions or dispatch.

The Codex integration has to be exercised against six protocol situations, and each of them belongs
to the gateway that drives the connection rather than to a catalogue package:

| Situation | What this package contributes |
| --- | --- |
| Thread subscriptions | The table routes and classifies the subscription methods and the events they produce |
| `turn/steer` and its `expectedTurnId` | The table classifies `turn/steer` as a mutation and states that its `expectedTurnId` must be the active turn |
| An uncertain `turn/start` result | Nothing. The binding state a control depends on is the host's, and this package declares no turn-starting action |
| Competing approvals | The table classifies each reverse approval request as a mutation, and this package draws no control that would answer one |
| `serverRequest/resolved` | The table routes it as an observation, which is how the host learns a pending request was answered or cleared |
| Reconnect | Nothing. Reconciling identifiers across a reconnected connection is the gateway's, and this table declares no tested volatile forwarding either, so the terminal is the supported path while receipts cannot be stored |

A predicate edit that changes what any of the eight cases says a person sees fails the build.

`fixtures/frames.json` is the other half: fifteen App Server frames, written from the published
documentation's own examples and completed against the required members of the generated schema.
Each carries the method the table should find, the route and class it should reach, the identifier
the table's path should extract with its JSON type, and the members its own situation is about. The
test `every_pinned_frame_is_read_the_way_the_table_says` under `cargo test` reads every frame through
this package's own table. A route, a classification or a path edited so that one of these frames is
read differently fails there. The frames also pin the evidence they were written against, by digest.

The frames are drawn from the situations the integration has to handle: starting and unsubscribing a
thread, steering with an expected turn, a turn start and the notification that would confirm it, two
approval requests, a resolved server request, a connection opening again and a turn being
interrupted, one method the table refuses outright, one it treats as carrying a credential, and one
it does not list at all, which is read as a mutation because that is what an unlisted method is.
Each is a frame, not a sequence: what a host does across two pending requests, or across a
reconnection, is the gateway's and is not settled here.
