# kalareach/codex

Recognises Codex CLI, serves it behind a gateway, reads its App Server through a declarative table,
answers its command and file-change approvals, and stops the turn it is running.

## What it does

KalaReach matches the `codex` executable and labels the session. When you type `codex` in a managed
shell, the integration starts Codex's App Server as the session's backend, opens a gateway socket,
and starts the terminal with `--remote` and that socket's address. The terminal stays exactly as
Codex draws it. This package adds a reading of what Codex is doing, and the controls over it.

`connector.json` is the declarative table. It states the framing (one JSON document per line), where
a request carries its identifier, where a message names its method and which members hold its
parameters, result and error, how a response is matched to its request, which methods travel which
way, and what each method does. Core code reads that table directly, so no component of this
package's sits between Codex and the host on the forwarding path. The table also says three things
that only an application server of this shape needs said:

- **Observation.** Which messages name the conversation the terminal is in: `thread/start`,
  `thread/resume` and `thread/fork` replies name the thread it selected; `thread/unsubscribe`,
  `thread/closed`, `thread/archived` and `thread/deleted` end it; `turn/started` and
  `turn/completed` name the running turn; `serverRequest/resolved` names the request that was
  answered or cleared. The host reads those places itself. Without them it would know nothing of
  the thread, and every rich operation would stay refused.
- **Decision response.** Codex reads the answer to an approval as the response to the request it
  asked, `{"id": <the request's id>, "result": {"decision": <value>}}`. The table maps the four
  decisions to the values Codex reads (`accept`, `acceptForSession`, `decline`, `cancel`) for
  `item/commandExecution/requestApproval` and `item/fileChange/requestApproval`. The host writes the
  answer from the table, so neither a caller nor a component chooses the identifier or the value.
- **Operations.** How Codex spells the host's own requests: a prompt is `turn/start`, a steer is
  `turn/steer` with the turn it expects, and a cancellation is `turn/interrupt`. Each has a template
  with a hole where the thread, the turn and the text go, and the reply to a prompt or a steer names
  the turn at the place the table says. A prompt that is queued behind a turn is not declared, so
  the host does not offer one.

The table is pinned to the App Server protocol of Codex CLI 0.155.1 and qualified against that
version alone. A protocol revision is exactly the kind of change that moves a method between
classes, so the table carries forward to nothing.

## What the integration serves

The integration is for the native `codex` executable. A launch is served when it types no option, or
when its first word is `resume` or `fork`; any other launch (a prompt, an option, a subcommand that
is not a terminal) runs as typed. An `npm` script that starts Codex is not served either, because
what runs is the script and not the executable the build qualified. Windows runs the command as
typed: no gateway runs there.

## What it classifies

Every stable method name of the pinned schema, 195 of them, plus `process/spawn`, which no request
union lists and which is kept classified. Each has the evidence it was classified against. Reads are
observations. Starting, steering, interrupting and compacting a thread are mutations, and so is every
reverse request whose answer changes what the agent does. The account, configuration and
authentication methods are credential methods: the broker keeps their answers and never passes them
to a component.

Thirty-eight methods are declared unsupported rather than proxied. They run outside Codex's sandbox
(`thread/shellCommand`, `process/spawn`, `command/exec` and its write, terminate and resize);
rewrite the user's configuration or install code (the `config/*` writers, the `plugin/*`
installers and sharing methods, the marketplace methods, the skill configuration writers, the
external agent import); reach absolute paths through Codex instead of through KalaReach's own file
grant (every `fs/*` method); approve what Codex's guardian denied
(`thread/approveGuardianDeniedAction`); or discard or spend what the account holds
(`account/logout`, `account/rateLimitResetCredit/consume`, `account/sendAddCreditsNudgeEmail`,
`feedback/upload`).

A method this table does not list is treated as a mutation, and it holds rich operations back until
the terminal selects a thread again. That is the safe answer to a method a release adds, and nothing
in the file changes it.

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

## What it carries

- **Cancel.** `turn.cancel` is the action the host carries out itself, with nothing a component
  could change: it writes `turn/interrupt` naming the thread and the running turn.
- **Answer an approval.** `approval.answer` is a decision the host writes as the response to the
  request, for a binding that holds `approval.decode` and `approval.respond`. The terminal can answer
  the same request, and the host forwards one answer to Codex: the first to reach it. When a person
  answers in the terminal after a device has, the terminal's answer is not forwarded and the
  connection goes on.
- **Prompt and steer.** The host's typed prompt and steer are written from the operations above. They
  are not package actions: no control of this package can name a thread or write text of its own.

No component, and therefore no decoder or encoder a package ships: the table is all the host reads.

Resuming a saved thread reads stored history. It does not establish that this process owns the live
execution, and nothing in this package treats it as though it did. After a resume into a thread that
is already running, a steer or a cancel is refused until Codex says a turn started, because a reply
to a resume does not name the turn. A prompt is not refused then: the host knows of no running turn,
and it learns of one only from `turn/started`.

## What is not measured

The host's cases for this package run against a stand-in for Codex's App Server in the core
repository, not against a live Codex. Five things about a real 0.155.1 session are assumed and left
for a run that has one:

1. The terminal closes its approval prompt when Codex sends `serverRequest/resolved` for a request
   a device answered.
2. The terminal shows a turn the host started.
3. `thread/start`, `thread/resume` and `thread/fork` are the only ways the terminal selects a
   thread, and the thread a reply names is the one the terminal shows. A thread the terminal starts
   for its own purposes on the same connection, an ephemeral one for instance, would be taken as the
   conversation it is in.
4. The 195 stable method names are every method a 0.155.1 session sends. A method outside the list
   is read as a mutation.
5. A prompt sent over a running turn is not a queue, which is why the host refuses one while it
   knows a turn is running.

Queueing a prompt is declared off for the same reason, and the matrix's case for queued prompts is
open.

## Fixtures

`fixtures/conformance.json` states what a person sees in thirteen situations, and the build evaluates
this package's own predicates against each one. The cases are named for what they assert, which is
which controls a person sees and which of those they can use. They are display conformance, and only
that: the fixture runner evaluates control predicates and never reads a Codex frame, so nothing here
exercises framing, identifiers, transitions or dispatch.

`fixtures/frames.json` is the other half: twenty-one App Server frames, written from the published
documentation's own examples and completed against the required members of the generated schema.
Each carries the method the table should find, the route and class it should reach, the identifier
the table's path should extract with its JSON type, and the members its own situation is about. The
test `every_pinned_frame_is_read_the_way_the_table_says` under `cargo test` reads every frame through
this package's own table. A route, a classification or a path edited so that one of these frames is
read differently fails there. The frames also pin the evidence they were written against, by digest.

The frames are drawn from the situations the integration has to handle: starting, resuming, forking
and unsubscribing a thread, the notifications that end one, steering with an expected turn, a turn
start and the notifications that report it, two approval requests, a resolved server request, a
connection opening again and a turn being interrupted, two methods the table refuses outright or
treats as carrying a credential, and one it does not list at all, which is read as a mutation
because that is what an unlisted method is. Each is a frame, not a sequence: what a host does across
two pending requests, or across a reconnection, is the gateway's and is not settled here.
