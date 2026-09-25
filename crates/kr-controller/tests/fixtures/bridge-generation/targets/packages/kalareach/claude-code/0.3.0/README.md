# kalareach/claude-code

Recognises Claude Code, observes it through lifecycle and tool hooks, carries a message into the
session and declares how the tool approvals it relays are answered.

## What it does

KalaReach matches the `claude` executable, labels the session, and keeps Claude Code in the terminal
KalaReach already owns. Nothing here replaces that terminal or starts a second Claude Code beside
it.

Two surfaces reach the session, and they stay apart on purpose.

The hooks watch. The installed registration points Claude Code's lifecycle and tool events at the
core forwarder, which carries them to the worker that owns the terminal. The forwarder answers every
hook with `{}`, an object that sets nothing, and exits 0, so no hook changes what Claude Code
permits.

Channels carry messages in and the answer to a tool approval back. Claude Code spawns a channel as
an MCP server of its own and talks to it over that process's standard streams, so the gateway has
nowhere to sit between them. This package installs the registration that makes the core forwarder
that channel, and `connector.json` states how the frames on the private exchange are read and how an
approval is answered.

## How an approval is answered

Claude Code relays a pending tool approval as `notifications/claude/channel/permission_request`,
with a five-letter `request_id`, the tool's name, a description of the call and a preview of its
arguments. The answer is `notifications/claude/channel/permission`, carrying that same `request_id`
and `allow` or `deny`.

`connector.json` routes both methods, classifies them and puts the correlation at
`params.request_id`. Its decision destination says which message is a pending approval, the relayed
request, and how one is answered: `channel.permission`, repeating the request's own
`params.request_id`, with `params.behavior` set to `allow` or `deny`. Those are the only decisions
it maps, and a decision it does not map is refused rather than sent.

The package registers one answering action, `approval.answer`. A call names the pending request it
answers, and the host checks that request before it marks anything. The identifier in the answer is
the one the request carried, never a value a caller supplies.

The document draws Allow and Deny for a person who holds the approval right while an approval is
pending. The document is written before any request exists, so the controls test that an approval is
pending rather than naming one; a client that draws them beside a request binds the press to that
request. They are enabled only while the host reports that it can answer approvals on this channel,
and never during volatile-native operation. Where the host cannot carry an answer, the controls stay
disabled and the approval is answered in the terminal, where Claude Code also asks.

Only a relayed request is an approval. Text that reads like a permission prompt, on the terminal or
in a `Notification` hook's report, makes no pending approval and never enables Allow or Deny.

What is checked here: the declarations validate against the package contract, the fixtures say who
sees the controls and who can use them, and the tests write the pinned answer from the table. What
is not: an answer given to a live Claude Code, or carried by a running host.

The message path is separate, and it is an action with its own effect class. It carries the text a
person wrote into the session. It is not an approval path, and nothing in this package lets text
reach one.

Delivering a message is not steering and not an acknowledgement that anything was processed. Claude
Code queues messages that arrive while a turn is running and delivers them together on the next
turn,
and the write to the transport is the only receipt there is. Claude Code applies whichever answer
reaches it first, the terminal's or another channel's, and drops the other, without telling the
channel which happened.

## What stays in the terminal

Project trust and MCP server consent. Claude Code asks for both in its own terminal and relays
neither, so this package offers no control for them, whatever rights the person holds.

## Runtime gates

The registration is what makes the channel available; it is not what turns it on. Claude Code
registers a channel only when every one of these holds where it runs:

- The session names the server or its plugin at launch. A registration Claude Code can see is not a
  registration it uses.
- The plugin is on the effective allowlist, which is the vendor's own unless an organisation
replaces
  it, or the session was started with the development flag instead.
- The organisation's channel setting permits channels at all.
- The session authenticates in a way that supports channels, which rules out the third-party model
  providers.
- The server declares the channel capability, and the permission capability as well before any
  approval is relayed to it.
- The negotiated protocol revision is one this version of Claude Code registers a channel over.
- The feature itself reaches this installation. It is a research preview, rolling out gradually, and
  a session it has not reached refuses the registration whatever the settings say.

- The skills directory is scanned at all. Managed marketplace policy can suppress that scan, which
  leaves the registration on disk and unloaded.

Each of those is decided where Claude Code runs, not here. Until they all hold, the approval is
answered in the terminal.

## The registration it installs

Claude Code reads its channels and its hooks from files in its own directory, so the bridge is three
declarative files and one settings key. Nothing here is a program, and nothing here carries protocol
logic: each file names the core forwarder and the surface it should carry.

| Installed | What it is |
| --- | --- |
| `skills/kalareach-channels/.claude-plugin/plugin.json` | The plugin manifest, declaring one channel bound to the server below |
| `skills/kalareach-channels/.mcp.json` | The channel server: the core forwarder, started over standard streams |
| `skills/kalareach-channels/hooks/hooks.json` | Five hook registrations, each bounded by its own timeout |

The settings key is `enabledPlugins."kalareach-channels@skills-dir"`, set to `true`. The recipe adds
that one key and leaves every other setting where it was.

The hooks are registered on `SessionStart`, `SessionEnd`, `PostToolUse`, `PostToolUseFailure` and
`Notification`. Those five were chosen because none of them refuses what Claude Code was about to do
when a handler exits with a failure code. That narrows the ways a hook can interfere; it does not
remove them, because a handler can answer with a stop decision on most events instead. The core
forwarder answers every hook with `{}` and exits 0 within half a second. Each registration is in
exec form, a command and its arguments with no shell between Claude Code and the forwarder, and
carries its own timeout, one second for `SessionEnd` and five for the rest, so a forwarder that
cannot reach the worker costs seconds rather than the ten minutes a command hook may otherwise take.

The registration installs disabled. Claude Code loads a plugin from a skills directory as soon as it
is there, so the manifest sets its default to off and the settings key is what turns it on. Removal
takes that key out first and then deletes the three files in the reverse of the order it wrote them.
Each file is checked against the digest it was installed with, and one that somebody has since
edited
is reported and left alone rather than deleted, which leaves a registration on disk that the key no
longer enables. A session that is already running keeps what it loaded: Claude Code picks up a
registration change when it reloads its plugins or starts again.

The forwarder runs under Claude Code's own permissions, outside the KalaReach plugin sandbox and
outside Wasmtime, because Claude Code is the process that starts it. The installation grant says
exactly that, and it says what the forwarder can see. None of the three files carries a session
identifier or a secret: the worker admits a forwarder only for the launch KalaReach made, through
that launch's private exchange, and the forwarder and the worker are the host's, not this package's.

## What it asks for

Seven capabilities. Matching, declarative presentation and broker semantic events are the reading
half. The upstream action capability carries a message you wrote. The two approval capabilities let
the table say which relayed requests are approvals and answer one with Allow or Deny. Interpreting a
request and answering it are separate grants, and neither is within a repository's default ceiling,
so an installation asks its owner for both. The bridge installation capability is declared with the
recipe it installs and the grant that says what accepting it means.

## Fixtures

`fixtures/conformance.json` states what a person sees in twelve situations, and the build evaluates
this package's own predicates against each one: a bound session, an actor who may only view,
volatile-native operation, a session with no qualified evidence for acting upstream, an upload in
progress, a binding disabled by repeated faults, a pending approval and an actor who may answer it,
the same approval and an actor who may not, no approval waiting, volatile-native operation and
missing evidence each leaving the answer unusable, and a session waiting on a prompt that only reads
like a permission request.

`fixtures/frames.json` is the other half: five pinned Channels frames, taken from the published
reference's own examples and the field names in the installed executable, each with the method the
table should find, the route and class it should reach, and the identifier the table's path should
extract. The test `every_pinned_frame_is_read_the_way_the_table_says` under `cargo test` reads every
frame through this package's own table, including an answer naming a request nobody issued, whose
identifier has to come back verbatim so the host can refuse it, and an ordinary MCP tool call, which
this table does not list and which is therefore a mutation. Two more tests hold the answer to the
frames: `a_relayed_claude_code_approval_is_answered_with_its_own_identifier_and_nothing_else_is`
writes the answer for the pinned request from the table and compares it with the pinned answer, and
`an_answer_to_a_claude_code_approval_names_the_pending_request_it_answers` checks that a call names
the request it answers.

Some of what this package promises is structural rather than conditional, and a fixture cannot state
it. There is no action for project trust or MCP consent, so no right produces a control for either.
There is no action that steers a running turn, so a message delivered to a busy session cannot be
presented as steering.

`docs/qualification-notes.md` in this repository records what every claim above was checked against,
and which claims were not checked against a live install.
