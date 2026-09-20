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

## Settings sync

`sync` is the other half of what a synchronisation service carries. Drafts travel through
`drafts::DraftSync`; settings and a client's own position travel through `sync::SyncClient`, under
the same compare-and-swap discipline and the same sealing seam.

- A publication sends the object the store holds against the generation the note beside it names,
  which is never the object's own revision. A revision is a fresh 128-bit value for every write
  rather than a counter, so an object removed and written again never passes through a revision it
  has already had. The fence check, the object, its note and the sealing happen under one hold of
  the store's lock, so the generation the work is admitted under is the one that was in force when
  its ciphertext was made.
- A refused comparison is an answer. What the service holds comes down as a `ConflictCopy` **beside**
  this device's own object, which is untouched, and the person chooses. Nothing here resolves a
  conflict, and nothing compares timestamps to do it: an object carries when it was written because
  a person choosing wants to know, not because it decides anything. Copies are bounded at section
  20's limit and the oldest goes first, so a device that never resolves them cannot spend somebody's
  storage without bound and the newest refusal is always the one that is kept.
- `SyncClient::fetch` applies nothing. It brings the other device's object back, keeps it as a copy
  when this device holds another revision, and writes the note. Putting a chosen object in place is
  the caller's own step through `SyncStore::put_object`.
- Host grants and revocation state have one host authority, and this client cannot reach it.
  `SyncBody` has a variant for settings and one for a client's position and no others, a setting is
  text or a number or a switch, and the client holds no handle to any authority store. Text is text,
  so the narrow value type is not a claim that nothing authority-shaped can be written into a
  setting; what holds is that nothing here reads a setting as authority and there is no code path
  from this module to one. A draft is refused before the service is asked and named for the draft
  store, so there is one way to write a draft on this device and nothing on either path submits
  one.
- A note naming a generation a reset or replaced service no longer holds does not resolve itself.
  `SyncStore::forget_checkpoint` is the explicit recovery, and nothing does it automatically,
  because a note that looks stale and is not is a note whose object another device has just written.
  A service that answers at a generation *below* the one the note names has provably gone back
  behind it, and the refusal says so; one this device could not reach at all is reported as it came,
  because absence and unreachability are not the same answer.
- An answer this device cannot make sense of leaves the work outstanding. Only an accepted write
  and a refused comparison say what became of a publication; anything else, including an abandoned
  call and a restart, leaves a durable record saying it was sent. This contract offers no way to
  ask what became of one request: a service takes a comparison and answers with a generation, and
  what it holds afterwards is a fact about the object rather than about any one write of it. So a
  later definite answer about that object retires the earlier dispatch, and what it may have sent
  is listed by `exported` as content sent without an answer rather than resolved.

`sync::StorageFeature` names the three parts of what section 18 offers: encrypted settings sync,
which is this module; history backups; and recovery material, which is what a restore without
another device needs. The last two are optional, which is what sections 18 and 20 call them, and
each part carries what a person does without it.

### Privacy mode

The host records a privacy generation and drives every subsystem through the same four steps. This
client is one of those subsystems, in plain methods that take the generation as a number, because a
client never depends on a host crate:

| Method | What it does |
| --- | --- |
| `fence` | Stops production at the generation. A publication after it is refused. |
| `cancel_undispatched` | Discards the staged ciphertext that was admitted and never sent, and counts what had already been dispatched, which cannot be taken back. |
| `remove_retained` | Removes the conflict copies, the checkpoints and the staged work that never left, and reports the bytes and records it actually deleted. Work already dispatched keeps its record, because that record is what says it may be out there, and work admitted under a later generation is another cleanup's. |
| `outstanding` | How many dispatched publications have no settled outcome, read from the durable records rather than from what is running. An abandoned call, a failed connection and a restart all leave one counted, and a record this build cannot read counts too. Cleanup is complete when it is nought, and a later definite answer about the same object is what gets it there. |
| `kept` | What stays, and why: the device's own settings, the labels the person pinned, and the record of what has already been published. |
| `exported` | What has already left, shown rather than claimed to be erased, including a write the service accepted after the fence: suppressing a result does not undo an upload. None of it is deletable from here, because a compare-and-exchange store takes a replacement and not a deletion. |
| `accepts_result` | A result is published only under the generation in force. An answer to work admitted earlier is discarded and moves nothing. |
| `resume` | Turns production back on under a generation of its own. It reconstructs nothing that was omitted. |

A pinned label is kept until the person clears it. `SyncClient::settings_to_publish` is the filter a
caller applies when it builds the object it is about to store: it leaves the pinned labels out while
privacy mode is on, and the device's own copy keeps them, so turning privacy mode off has nothing to
reconstruct. `publish` does not filter anything on the way out, because what goes to the service is
the record on disk; while privacy mode is on it refuses the whole publication instead.

A publication that has left cannot be taken back. It is recorded as dispatched before the call
leaves, so a cancellation counts it rather than discarding it and a restart does not take it back as
though it had never gone; its answer is then refused by the generation rule instead of published.

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
| KR-PERF-006 | Nothing here. `a_reconnect_reaches_a_screen_a_terminal_can_draw_inside_the_budget` in `crates/kr-client/tests/session.rs` measures the client's half against a host that answers at once, which is a necessary condition and not the row's own measurement: it leaves out the attach a subscription follows and everything a real host spends |
| KR-REQ-17.14 | `a_session_a_draft_and_a_control_need_no_managed_service_and_do_not_change_with_one` in `crates/kr-client/tests/session.rs` |
| KR-REQ-23.57 | `crates/kr-client/src/retry.rs` tests, and the retry tests in `crates/kr-client/tests/session.rs` |
| KR-REQ-24.13 | `crates/kr-client/src/drafts.rs` tests, and `a_draft_outlives_its_attachment_its_connection_and_another_devices_write` in `crates/kr-client/tests/session.rs` |
| KR-REQ-20.13 | `crates/kr-client/tests/sync.rs`, for this row's client half: per-object revisions and compare-and-swap writes, a lost comparison kept beside rather than resolved by a clock, the closed kind set that no restore can reach host authority through, and drafts that stay drafts. The service half is closed by the storage service's own suite |
| §24 privacy | `crates/kr-client/tests/sync.rs` drives the fence, the cancellation, the removal, the pinned-label rule, a publication in flight when privacy mode is enabled, and reconciliation of work whose caller walked away. Turning the generation on is the host's, and this client is one subsystem of it |
| KR-REQ-18.05 | `the_service_holds_ciphertext_in_a_declared_bucket_and_never_a_setting` and `the_feature_names_its_three_parts_and_which_of_them_is_optional` in `crates/kr-client/tests/sync.rs`, for the encrypted settings sync part only. The history backup and recovery material parts are the recovery module's, and nothing here performs either |
