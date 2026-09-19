# Client reference

What the shared native client library decides, and what it leaves to whoever is using it. The code
is `crates/kr-client`. It is the same library in the command line, the desktop and mobile
applications and anything else that talks to a host, which is why the decisions below are made once
here rather than five times in five clients.

It holds no authority. It carries requests to a host and answers back, and it knows which of its own
actions are unresolved. What it does hold is the screen a projected client draws and the cursors a
stream has reached, which are its copies of what the host told it, and the drafts on this device,
which are the person's own and were never the host's. Everything a request means belongs to the
host.

## Two ways in, one contract above them

| Path | What it is | Where it lives |
| --- | --- | --- |
| Local | A Unix socket or a Windows named pipe, with local peer authentication instead of a device proof | `kr-ipc`, wrapped by `ipc::IpcTransport` |
| Remote | An iroh connection with the `hello` and `kr-connect/1` proofs | `transport::NetworkTransport` |

`transport::ControlTransport` is the seam and it is narrow: send a control frame, read the next
control frame, end the connection. `session::Session` is written against that trait and nothing
else, so request correlation, action identifiers, receipts, cursors and the action window behave
identically whichever way a client connected. The command line is a local client; a paired device on
the far side of a relay runs the same code above the transport.

## What a failure means

`retry` is one table over every error code section 23 requires. Each code has a step, which is what
happens to the request, and an action, which is the direct thing a user interface offers instead of
showing the code. The match is exhaustive, so a code added to the protocol has to be decided here rather
than reaching a client unclassified.

An automatic retry needs two things at once, and neither alone is enough:

- the **code** permits one, which means its retry category is `Transient`;
- the **request** is one of the three classes section 23 names: an idempotent read as the method
  registry marks it, a transfer chunk, or a request whose receipt proves it was never dispatched.

Everything else is `retry::RequestClass::Dispatchable`, including every mutation until its receipt
says otherwise. `Session::read` applies this itself for a read the registry marks idempotent, under
a bounded attempt count and jittered backoff, and the caller sees the last answer rather than each
attempt. `Session::mutate` never retries: the library cannot know whether the host dispatched a
mutation, so the decision goes back to the caller with `ClientError::decision`.

The attempt count and the backoff are bounded so that retrying is not what makes a reconnect slow.
Section 27 gives a reconnect two seconds to a usable screen, and a restoration is idempotent reads,
which is exactly what this library retries. The most the delays can add to *one* read is 700
milliseconds, which `a_retry_cannot_spend_a_reconnects_budget` holds them to; each read has its own
budget, so a restoration that made several would have several. What the client's own half of a
restoration costs is measured rather than argued:
`a_reconnect_reaches_a_screen_a_terminal_can_draw_inside_the_budget` goes from an available
transport through the subscription to a painted 120x40 screen, once against a host that answers at
once and once against one that refuses the read first, and holds both inside the two seconds. It is
a necessary condition for the row and not the row's own measurement: it leaves out the attach that
precedes a subscription, and everything a real host spends answering.

| Code | Step | What a person is offered |
| --- | --- | --- |
| `OUTCOME_UNKNOWN` | Ask the host what became of the action | Check whether it went through |
| `RESYNC_REQUIRED` | Take a new snapshot and resume from its cursor | Refresh |
| `RATE_LIMITED`, `SERVICE_CAPACITY`, `QUOTA_EXCEEDED` | Wait the delay the host asked for, or the bounded backoff | Wait |
| Transient conditions | An eligible request is sent again | Wait |
| Authentication, pairing and schema failures | Stop | Pair again, sign in, or change a setting |
| Everything else | Stop | The host's own message |

`OUTCOME_UNKNOWN` never yields a retry, whatever class asks for one. Section 9 forbids dispatching
the identifier again, and inventing a new one would submit the same intent twice.

Two refusers know more than a code can carry. A managed service answers `PERMISSION_DENIED` both for
a caller that is not signed in and for an account that may not do this, so it classifies its own
refusal and `ClientError::Refused` carries the action. This device's draft store has its own answers
too: a draft that will not fit is not a reason to update the application.

## Drafts

A draft is durable and belongs to this device. An attachment is only what is presenting it.

`drafts::DraftStore` holds drafts in a directory the caller chooses, owner-only where the platform
expresses that. `drafts::Associations` holds which attachment is presenting which draft, in memory,
and nothing else. They are separate because their lifetimes are: a draft outlives every connection a
client makes, and an association cannot outlive the connection that produced the attachment.

- A draft is one file, written to a temporary name, flushed, and renamed over its own. Every change
  takes an exclusive lock on the store and reading a draft takes a shared one, so reading a draft,
  comparing its revision and replacing it is one step against every other window and every other
  process. A second editor that lost the comparison is told so and overwrites nothing. Reading the
  note beside a draft takes the exclusive lock instead, because a note this build cannot read is
  removed rather than returned. The contents are flushed before the rename on every platform; on
  Unix the directory entry is flushed too: every level the store creates has its own name flushed
  into the level above it, and a replacement or a removal flushes the directory it happened in. On
  Windows this build flushes none and claims no durability for the names themselves.
- `Associations::connection_lost` clears every association and touches no draft. A `Session` does
  not own the associations and does not clear them: whoever holds both calls it when a connection
  ends, which is the same caller that binds a draft to a new attachment on reconnect.
- A changed application or binding revision marks the draft conflicted; a target that is gone marks
  it orphaned. Either way the text is kept and `Draft::submission` refuses until a caller retargets
  it explicitly. Rebinding is not retargeting: only a person decides whether text written for one
  agent still means what they wanted for the next.
- Nothing here submits. `Draft::submission` answers a question; `Associations::bind`,
  `Associations::connection_lost` and `Draft::rebind` answer with a state or an attachment. Sending
  a draft is the caller's own separate step.

`drafts::DraftSync` is the optional half. It publishes through `services::SyncBackupService` under
compare and swap on the generation this device last saw, which is kept beside the draft and is *not*
the draft's own revision: a draft edited three times offline is at revision four and has still only
been published once. What goes to the service is the record the store holds, read together with that
note under one hold of the lock, so a caller cannot publish text this device does not have and
cannot send an older revision against a generation another publisher has just advanced. A note that
already names a later generation stands, so an answer that arrives late does not undo what a fetch
has already learnt. A refused comparison is an answer rather than a failure: what the service holds
comes down **beside** the local draft under a fresh identity, never over it, and the person chooses.
Reconnecting never replaces their text.

Sealing is the caller's: `drafts::DraftSealer` is the seam, and nothing in the library sees a key.

## Controls

The document node union, the control model and the visibility grammar are the package contract's, in
`kr-plugin-sdk`. `controls` is the client's half of the same contract.

- `controls::read_document` turns what arrived into things this build can draw. A node kind it does
  not know becomes an unsupported-content block that names the kind and carries nothing else: no
  source, no stylesheet, no module, no address and no markup. It offers no control, so a newer
  package cannot reach an action through a node an older client cannot read.
- `controls::evaluate` decides visibility from a state a caller supplies. Absent is not false: a
  client that has not been told whether the person holds the input lease does not know, and a
  control whose visibility turns on that is hidden and says which fact was missing. Guessing false
  would, under a `not`, show a control the package meant to hide. A predicate outside the grammar's
  depth and width bounds is hidden and reported.
- `controls::invoke` produces the invocation, carrying the control's revision so the host can
  recheck the condition against the control the person actually saw. A hidden or disabled control
  produces none.

Hiding is a courtesy either way, and it is a client-side one: what `invoke` produces is a value
carrying the control's revision, which is what section 11 requires a host to recheck the condition
against when the invocation reaches it. Rechecking is the host's, so a control this client shows
that it should not have is a control the host then refuses.

## Managed services

`services` holds one trait per managed service section 17 names (account login, relay leases, push,
encrypted sync and backup, managed inference), and `ServiceClients` holds one optional
implementation of each. `services::relay` is the one managed implementation this crate carries,
because a lease is the one managed resource a client cannot do without and still use a relay at all.

A field left `None` is a service this client does not use, and nothing degrades. Direct connections,
local sessions, drafts, plugins, local descriptions and user-operated alternatives need none of
them. `ServiceClients::availability` reports every service in one shape. A service with no
implementation is named along with what to do instead; a service with one is reported as configured,
which is the only thing a client can know without asking, because `NullService` is configured and
answers nothing and whether a call succeeds is what the call says. It explains and nothing more: no
code path consults it before doing local work, and a client that deleted every field would lose the
managed resources and keep the product.

`services::NullService` implements every trait by saying so. It exists so a caller can hold a
service client unconditionally and get an honest answer rather than a silent default.

## Requirement rows

| Row | What closes it |
| --- | --- |
| KR-REQ-04.23 | `crates/kr-cli/tests/client_paths.rs`, and `the_local_path_is_a_socket_and_the_remote_path_is_iroh_behind_one_seam` in `crates/kr-client/tests/session.rs` |
| KR-REQ-11.46 | `crates/kr-client/src/controls.rs` tests |
| KR-PERF-006 | `a_reconnect_reaches_a_screen_a_terminal_can_draw_inside_the_budget` in `crates/kr-client/tests/session.rs` for the client's half, and `scripts/performance.sh` for the whole of it |
| KR-REQ-17.14 | `a_session_a_draft_and_a_control_need_no_managed_service_and_do_not_change_with_one` in `crates/kr-client/tests/session.rs` |
| KR-REQ-23.57 | `crates/kr-client/src/retry.rs` tests, and the retry tests in `crates/kr-client/tests/session.rs` |
| KR-REQ-24.13 | `crates/kr-client/src/drafts.rs` tests, and `a_draft_outlives_its_attachment_its_connection_and_another_devices_write` in `crates/kr-client/tests/session.rs` |
