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

A connection that a relay stood in the way of is not reported as a host that did not answer.
`NetworkTransport::connect` returns `ClientError::Transport` holding
`TransportError::RelayRefused` when the attempt timed out without a connection while the relay
status showed a relay on the route turning this device away, or when the device had nothing but
refusing relays to try: it names the relay, carries what the relay said, and lists the kinds of path
that may still work. Its code comes from the kind token the relay's reason starts with: a spent
allowance is `QUOTA_EXCEEDED`, a relay that is stopping is `SERVICE_CAPACITY`, and a reason with no
known token is `RESOURCE_UNAVAILABLE`, like any other connection that could not be made. A device
whose only path is the relay learns this as soon as the relay refuses it; one that can take a direct
path learns it when its attempt ends without one, if the status still shows the refusal then. A
refusal counts only while the status shows it, because a relay that is being dialled again may have
admitted the device since. The transport reference has the rule, the token grammar and the
alternatives.

Two refusers know more than a code can carry. A managed service answers `PERMISSION_DENIED` both for
a caller that is not signed in and for an account that may not do this, so it classifies its own
refusal and `ClientError::Refused` carries the action. This device's draft store has its own answers
too: a draft that will not fit is not a reason to update the application.

## What a diagnostic may show

A failure, a line on standard error and a panic, from this library and from the command line, say
only a `shown::Shown`. A `Shown` is built from this program's own words (a `&'static str` written
in its source), from values with nothing in them to hide (`Plain`: numbers, identifiers that are
UUIDs or counters, and codes and states from a fixed vocabulary), and from what a reducer or a door
decided may be said. There is no way to make one from a `String`, so text that arrived from a
person, a file, a host or a service reaches a diagnostic only through one of those.

A reducer keeps what somebody diagnosing a fault needs and drops the rest. Where it says text that
arrived, the text is one of a closed list this build holds, or has a shape that cannot carry chosen
words: a UUID, eight or more hexadecimal digits, or decimal digits. A test of the characters alone is
not enough, because anything can be written in a shape made of letters. Three say more, each by a
contract of its own: `address` says a host's name, because which service or relay failed is what a
person acts on; `root` and `within` say a directory the program was configured with or derived,
which the caller vouches for; and the command line's `named` says a path the person typed, back to
them.

| Reducer | What it says |
| --- | --- |
| `address` | The scheme, the host and the port. An address with a user name or a password in it is not printed at all, and no path, query or fragment ever is |
| `cbor` | The KR-CBOR-1 rule the bytes broke and the offset where they broke it, never a key, a value or a decoder's message |
| `json` | The kind of fault, with its line and column |
| `io` | The kind of failure and the operating system's error number; a message a caller attached is dropped |
| `frame`, `ipc`, `transport`, `crypto` | Their own fixed words, with CBOR and input or output failures said as above |
| `pairing` | A pairing failure's own fixed words and numbers; what a rendezvous service, a store or a peer wrote is named by its kind, and a refusal by its code |
| `qr_payload` | The rule an invitation's QR payload broke, a member that failed by its name, and its size or version, never a mode it named or why a member failed |
| `task` | Whether a task panicked or was cancelled, never what a panic said |
| `route` | Each segment of a request path that is a word of the service adapters' own paths or an identifier, and a placeholder for any other |
| `collection` | A sync collection's kind, one of the protocol's, and its object's identifier |
| `terminfo` | A terminal type that is one of the terminfo names this build lists |
| `root`, `within` | A directory this program was configured with or derived, and a fixed name under one |
| `stored` | A file in a store, whose name is said only when it is one of the store's fixed names or an identifier with the store's own extensions |
| `host_path` | A path in this installation's tree: the configured runtime or state root whole, and below it only identifiers and the names the tree writes; outside it, a drive's letter but never a server's, a share's or a device's name |

A door passes text whole, because the value it takes was written to be shown to a person: a host's
refusal message (section 23 makes that plain text for a person, with no credentials in it), a
managed service's refusal, and a package's words about its controls. A host sentence goes through a
door too, and one that arrived from a document rather than being composed here is said by its class
and its length. The signal a closure record names is said when it is one of the names platforms
give signals, with the number a platform puts after one.

So an error holds text only as a `Shown`, and an input or output failure as an `IoFault`, which is
not itself an error and is never a `source()`. A `thiserror` message is one literal whose holes
name the variant's own fields, `Debug` is the same text as `Display`, and a hand-written `Error`
names no source, so walking a failure's chain finds nothing its rendering left out. `ClientError`
and `CliError` still carry the values other crates build and match (a host's `ProtocolError`, a
`TransportError`, an `IpcError`) and render each through its door or reducer.
`kr_client::error::refusal` is the one place a `ProtocolError` is made from text, and it takes a
`Shown`.

The command line reports every failure through one reporter, which writes the line on standard
error and the `--json` failure document. A usage mistake is said by its kind and by what the
command declares: the argument, the values it takes, a suggestion and the usage line, which names
the command `kr` however it was invoked. What was typed is never repeated, because an argument in
the wrong place can be a secret pasted into it.
`kr account token show` and `kr account token import` say a stored origin as an address, and the
stored scopes as the names this build knows, with the others counted. While an owner device
confirms a pairing, the command says the verification value the new device should show, grouped in
fours as both devices show it and only when it is eight hexadecimal digits, and names the device by
its platform: the name a device gave itself is not repeated. When `kr new` starts a daemon that does
not answer, the failure names the process and the daemon's log, and repeats the log's last line only
when it is the daemon's own refusal of an environment another daemon holds.

A pairing attempt's failure says its kind and a detail that is a `Shown`, so it carries nothing a
host, a room or a store wrote and nothing an invitation carried. A room that could not be opened is
said by its stage, its origin as an address, the status it answered with, and a reason when the
reason is one this library gives; a failed link to a host is said by the host's own refusal, or by
its kind.

Two tests hold this. `crates/kr-client/tests/shown_rule.rs` reads both crates' sources as the
compiler does, with each literal's escapes decoded, each type named by its full path through the
file's imports, and only code that cannot compile without `test` left out. It names the file and
line of anything that could put other text in a rendering: a hand-written `Display`, a `Plain`
claim outside the two `shown.rs` files, an error field a rendering reaches that is none of the
types above, a formatted panic, an `unwrap` or `expect` in either call form, an assertion that
prints what it compares, a log line, standard error written outside the reporter, and source it
cannot follow: a renamed import, a macro, a derive it does not know, an attribute under `cfg_attr`
that it reads, a `#[path]` or an `include!`. The marker tests plant
one marker where input goes (each text leaf, map key and other leaf of a stored file, malformed
bytes, typed arguments, origins) and look for it in every rendering that comes back, as text, as
decimal and hexadecimal bytes, and in base64; beside each, the same planting of another value is
held to naming the fault's class and its place. A service's answer that cannot be read is said
through `json` or `cbor`, whose renderings carry none of the answer by their types.

Standard output, the `--json` answers other than a failure document and the account token's, and
the derived `Debug` of a type that is not a failure are outside this rule.

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
  removed rather than returned. The contents are flushed before the rename, and the directory entry
  afterwards, on every platform: every level the store creates has its own name flushed into the
  level above it, and a replacement or a removal flushes the directory it happened in. On Windows
  the entry is flushed through a handle on the directory that may add a file to it, which is what
  the operating system asks of a flush there.
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
compare and swap on the position this device last saw, which is kept beside the draft and is *not*
the draft's own revision: a draft edited three times offline is at revision four and has still only
been published once. What goes to the service is the record the store holds, read together with that
note under one hold of the lock, so a caller cannot publish text this device does not have and
cannot send an older revision against a position another publisher has just advanced. A note that
already names a later write stands, so an answer that arrives late does not undo what a fetch
has already learnt, and so does a note naming the same place in the service's order under another
name, which is a second history rather than a later write. Both compare places within one history
of the collection; a collection put back from an archive is followed instead (see
[A collection put back](#a-collection-put-back)). A refused comparison is an answer rather
than a failure: what the service holds comes down **beside** the local draft under a fresh identity,
never over it, and the person chooses. Reconnecting never replaces their text.

`DraftSync` takes the device's `sync::SyncStore`, the one the settings client keeps its records in,
and a draft publication is accounted for and settled there by the same rules as a setting.

- Each publication keeps one request record, written before the call leaves and replaced whole at
  every step, so a device that stops anywhere comes back to one account of it. Admitting it and
  making the first attempt are one step, under the hold the privacy fence is decided in, so no
  draft sits between the two for a cancellation to find. `SyncClient::outstanding` counts a draft
  that left without an answer, and `SyncClient::exported` names it.
- A publication has one request identity, chosen when it is admitted. Publishing the same revision
  again while the answer is unknown presents that identity with the same bytes and the same
  comparison, and the service answers from its receipt if an earlier attempt ran. The record keeps
  the earliest and the latest instant any attempt was signed at, which is what a fence carries. A
  later attempt is a replay only while the service is sure to hold that receipt still, so an
  identity is presented again only while every attempt under it is signed within one freshness
  window of every other. Section 9 keeps a receipt for thirty days from the reading that admitted
  its attempt, and a replay inside that span could then run twice only if the service's clock went
  back by nearly all of those thirty days, which is what the service's cutoff below closes. Past
  the span, the first publication keeps its own account and publishing again is new work under a
  new identity. So it is once the collection has been put back since the first attempt, and once
  the service has refused an attempt as signed before its cutoff: the identity is never presented
  again. Nothing makes an attempt by itself, and an attempt under an identity whose call is still
  out is refused rather than sent beside it.
- `DraftSync::reconcile_unsettled` settles a publication whose answer was lost the way the settings
  client settles its own. It asks about the request's identity: an applied receipt moves the note
  beside the draft unless the note already names a later write, and a refused one brings the other
  content down beside the draft. While the generation that admitted it is in force, a publication
  the service holds no receipt for stays counted. Once privacy mode has moved past that generation,
  the settings client's cleanup fences it with the two recorded instants and settles it too,
  leaving no account where the service says nothing ran and keeping the account where it cannot
  say so. The note is written in the draft store before the record that ends the request, so a stop
  between the two leaves the request counted and the next pass writes the same note again.
- A refusal names the copy the service kept of this device's write on the copy that comes down
  beside the draft, as `Draft::retained`. `DraftSync::resolve` records the person's choice about that
  copy: it takes the copy out of the draft store and drops the one copy on the service that answers
  it. The choice is recorded before the service is asked, so a service that cannot be told hears of
  it from `SyncClient::finish_resolutions` later. A refusal whose other content never came down is
  listed in `exported` as deletable, and `SyncClient::drop_kept_copy` drops it.
- While privacy mode is on, no draft is published and none is fetched. An answer that comes back
  for work from an earlier generation is `drafts::Published::Discarded`, or a late result for a
  fetch. The account of what left stays, no note moves and no copy comes down.

Sealing goes through `drafts::DraftSealer`. `sync::CollectionSealer` is the implementation this
crate carries; a client that seals differently supplies its own.

## Uploads

`uploads::Upload` is one upload's plan: the content, the layout the host chose and the chunks the
host has acknowledged. `uploads::send` drives it. The reservation, the status reads and the
publication go on the session, and every chunk goes on the transfer's attachment-chunk lane, a
`chunks::ChunkLane` that `chunks::ChunkRoute` opens once the transfer is reserved.

No chunk travels on a control connection, whatever its size. A control frame holds at most 1 MiB and
a full chunk is 1 MiB of data plus its metadata, so section 23 gives chunks a stream kind of their
own, with room for 1 MiB of data and 4 KiB of metadata, and says a control stream cannot select that
bound. On this machine the lane is a second connection to the environment's controller, at the
address `kr-ipc` names beside the control endpoint (`EnvironmentPaths::attachment_chunk_endpoint`).
It says hello like any local client and keeps the action window the host gives that connection,
adopting each renewal. A lane carries one transfer and refuses a chunk of another before it sends
anything.

- A lane that drops or will not open, and a chunk the host refuses with a transient code, are retried
  as `RequestClass::TransferChunk`. The budget is three retries, and progress the host confirms
  restores it. Before it sends again the driver reads `upload.status` and gives the plan the host's
  bitmap, so a chunk the host stored after its answer was lost is not sent twice, and the upload
  keeps its identifier.
- The plan stays with the caller. Calling `send` again with a plan that already holds a transfer
  starts from `upload.status`, which is how a lost `upload.finish` reply or a dropped session is
  settled without a second file.
- The plan records a reservation as asked for before `upload.begin` leaves, and only a definite
  answer clears that: the host's result, its refusal, or a receipt saying the reservation never
  took effect. A lost reply, an answer saying the outcome is unknown, any other receipt with no
  result and a call abandoned part way all leave the plan refusing to reserve again. Nobody knows
  whether the host holds a transfer for it, so uploading the same file a second time is the
  person's decision.
- A lane has a reader of its own for as long as it lives, as a session does. It applies each window
  the host renews the moment it arrives, ends the lane at an answer to a call the lane never made,
  and when it stops, a write the host is no longer reading stops with it. The host renews a window
  when half its validity has passed, so a call carries the newest window while the lane received it
  less than half its validity ago, and otherwise waits for the renewal; a lane whose window runs
  out with no renewal has lost its connection, and the upload opens another. The lane cannot see
  the host's clock, though: a pause before it read a window, or a suspension its clock does not
  count, can leave it holding a window the host has let expire. The host refuses a chunk under
  such a window with `PERMISSION_DENIED`, so the upload sends a chunk refused that way once more on
  a new lane, whose window the host has just issued, and stops at a second refusal in a row.
- `ChunkLane::read_chunk` hands back a downloaded chunk only when it is exactly the chunk
  `download.begin` described: its index, its length and its digest. Checking the whole file and
  writing it to a destination belong to whoever publishes the download.

## Settings sync

`sync` is the other half of what a synchronisation service carries. Drafts travel through
`drafts::DraftSync`; settings and a client's own position travel through `sync::SyncClient`, under
the same compare-and-swap discipline and the same sealing seam, and both keep their request records
in one `sync::SyncStore`.

- A publication sends the object the store holds against the position the note beside it names,
  which is never the object's own revision. A revision is a fresh 128-bit value for every write
  rather than a counter, so an object removed and written again never passes through a revision it
  has already had. The fence check, the object, its note and the sealing happen under one hold of
  the store's lock, so the generation the work is admitted under is the one that was in force when
  its ciphertext was made.
- A position is where an object stands on the service: the name the service gave one write, and
  where that write falls in the collection's order. The order is the service's to state, and this
  client compares two answers by it and by nothing else. A device that numbered answers as they
  arrived would put a reply delayed behind another device's write after the write that superseded
  it, and would then compare against a place the object had already left. An object nothing has
  written yet has no position at all, so a first publication compares against nothing rather than
  against a place that stands for emptiness.
- Removing an object takes a place in that order too, and leaves no write for a name to belong to,
  so the removal's position carries the place and no revision. An object that is not there is
  therefore distinguishable from one that has never been there: the note keeps where the removal
  fell, the comparison after it names no object, and the write that follows carries on from the
  removal rather than starting the order again. An answer behind that place is still a service that
  has gone back, and a write claiming the removal's own place is still two histories.
- A refused comparison is an answer. What the service holds comes down as a `ConflictCopy` **beside**
  this device's own object, which is untouched, and the person chooses. Nothing here resolves a
  conflict, and nothing compares timestamps to do it: an object carries when it was written because
  a person choosing wants to know, not because it decides anything. Copies are bounded at section
  20's limit and the oldest goes first, so a device that never resolves them cannot spend somebody's
  storage without bound and the newest refusal is always the one that is kept.
- The service keeps a copy of the refused write as well, for the same reason, and once one object
  holds as many unresolved copies as the service keeps, a write of it that loses its comparison is
  refused outright rather than kept. So the person's choice goes to both places. A copy kept after a
  refusal names the copy the service kept of that refused write, and `SyncClient::resolve` takes the
  copy out of this device's store and drops that one copy from the service. Another refused write of
  the same object is another version the person has not decided about, and it stays where it is.
  The choice is recorded before the service is asked, so a service that cannot be asked leaves it
  recorded, a restart keeps it, and `SyncClient::finish_resolutions` asks again. A copy the service
  kept with nothing on this device to choose about, because the other content could not be brought
  down or the copy here was pruned, is named in `exported` as deletable, and
  `SyncClient::drop_kept_copy` drops it when the person asks for exactly that. None of this sends
  content, so privacy mode does not stop it.
- `SyncClient::fetch` applies nothing. It brings the other device's object back, keeps it as a copy
  when this device holds another revision, and writes the note. Putting a chosen object in place is
  the caller's own step through `SyncStore::put_object`. Whether there is a choice to keep is
  decided against what this device holds when the answer is applied, inside the hold that writes
  the copy, because a window that stored its own content while the call was out has given the
  person two versions to choose between.
- Host grants and revocation state have one host authority, and this client cannot reach it.
  `SyncBody` has a variant for settings and one for a client's position and no others, a setting is
  text or a number or a switch, and the client holds no handle to any authority store. Text is text,
  so the narrow value type is not a claim that nothing authority-shaped can be written into a
  setting; what holds is that nothing here reads a setting as authority and there is no code path
  from this module to one. A draft is refused before the service is asked and named for the draft
  store, so there is one way to write a draft on this device and nothing on either path submits
  one.
- A note naming a write a reset or replaced service no longer holds does not resolve itself.
  `SyncStore::forget_checkpoint` is the explicit recovery, and nothing does it automatically,
  because a note that looks stale and is not is a note whose object another device has just written.
  Within one history of the collection, two answers are provably wrong rather than merely
  surprising, and the refusal says which: a service answering with a write sequence *below* the one
  the note names has gone back behind what this device already saw, and one answering with another
  name for the same place in the order holds a history that forked. A collection put back from an
  archive is neither: its answers name another history, and this client follows it (see
  [A collection put back](#a-collection-put-back)). One this device could not reach at all is
  reported as it came, because absence and unreachability are not the same answer.
- Everything this device knows about one publication is in one record, named by the request's own
  identity, and every step of that request replaces the whole of it: admitted, sent, and then what
  the service answered. A device that stops part way through a settlement comes back to one record
  saying where the request had got to, so an account of what left this device can never name one
  request twice, whatever the timing. What a settled request still owes the store, the object's
  publication record, is written from that record afterwards, and a device that stops between the
  two finishes the step the next time anything reads.
- An answer this device cannot make sense of leaves the work outstanding. Only an accepted write
  and a refused comparison say what became of a publication; anything else, including an abandoned
  call and a restart, leaves a durable record saying it was sent. What the object holds afterwards
  does not settle it: that is a fact about the object rather than about any one write of it. What
  does settle it is the request's own identity. Every exchange carries the request's own
  identifier, the service records the reply it gave that identity, and
  `SyncClient::reconcile_unsettled` asks for it back: an applied write settles as an accepted one
  and moves the checkpoint, and a refused one settles as a write that did not replace the object
  and brings the other device's content down beside this device's own. A refusal is not a claim
  that the service kept nothing. A service that stores the rejected write as a copy of its own
  names that copy, and `exported` reports it, because the ciphertext is on the service whatever
  the comparison decided.
- A service that holds no receipt for a request says so, and that settles nothing. A request still
  on its way, one that never arrived and a receipt past its thirty-day retention look the same from
  here, and none of them says the write did not land, so nothing is retried: section 23 allows an
  automatic retry only where a receipt proves no dispatch. While the generation that admitted the
  work is the one in force, the work stays counted and the next reconciliation asks again. Once
  privacy mode has moved past that generation no answer to it could ever be published, and waiting
  for a receipt that may never exist would leave a barrier nothing could lift, so this client asks
  the service to **fence** the request instead. A fence ends it: either the service had already
  decided the request, and that answer settles it, or it records that the request will never run and
  refuses anything that arrives under that identity afterwards. Only applied, refused and fenced
  release the barrier. A service that cannot be asked, for either call, leaves the work counted, so
  a cleanup reports what is still outstanding rather than assuming it is finished.
- Two answers can claim one place in one history of the service's order, which is a service whose
  history forked rather than a later state of this one. The object's own publication record can
  name only one of them, so the request that lost keeps its own record as the account of the
  ciphertext that left under it, and `exported` names both. Which of the two it is is decided in
  the same replacement that ends the request, and never again: deciding it later would leave a
  stop between the two, and a publication that moved the object's record on in between would make
  the account look like ordinary older news and drop it. A publication or a fetch that meets the
  same disagreement in its note is told, because the note is compared inside the hold that writes
  it and the next comparison may never meet it: the service can reach a later write, which follows
  from either history. A reconciliation counts them instead of refusing, because it is ending a
  barrier rather than answering one caller. `SyncStore::forget_checkpoint` is the recovery, and
  nothing does it automatically.
- A write takes the next place in the order after the one it replaced, so an accepted answer at that
  place or behind it, in the same history, is not a later state of the history the request was
  made against. The settlement records such a write as one that went into another history, never
  as applied: the request's own record keeps the account of what left, no note moves and no
  publication record claims it, and the caller is told which it was, a service that went back (a
  smaller write sequence) or two histories claiming one place (the same one). Only a write's own
  answer is held to this; a read may name the very place this device already holds, which is the
  same write said again.
- An answer this device cannot read is declined rather than guessed at. A place in the order counts
  from one, and a write that produced content is named by a revision, so a position with neither is
  the removal of the object and not somewhere a write of it landed. This client publishes writes and
  never removals: an accepted answer at a removal's place, a fetch that carries content at one, and
  anything at nought are all refused, and the work stays counted rather than being settled from an
  answer that cannot be about it.
- A fence always ends the request, because nothing executes under a fenced identity, so the barrier
  releases either way. Whether anything ever *ran* under the identity is a second question, and the
  **service** answers it rather than this device working it out. The fence carries the two instants
  the request's own record holds: when this device first signed the content away, and when it last
  did. The service admits a request only within its freshness window of the instant it carries, so
  a receipt of anything that ran under this identity would bear an instant no earlier than the
  first of those two less one window; the service keeps a mark of how far back it has swept its own
  receipts, and it answers that nothing ran exactly when it holds no receipt for the identity and
  has swept nothing that old. The newest instant keeps the fence itself alive: the service holds the
  fence until nothing this device signed can still become fresh, so no attempt can outlive the fence
  that ended it, however wrong this device's clock was when it signed.
- Where the service says nothing ran, nothing of the request is anywhere and its record goes. Where
  it cannot say so, the ciphertext may be on the service, and the record stays as the account of
  what left with no content in it. `exported` names it, and deleting it because nobody could tell
  which had happened would hide an upload rather than undo one. This device compares no instants to
  reach that: every fact in the answer is the service's, and a device putting its own clock against
  the service's could be wrong in the direction that deletes the account of an upload that happened.
- A dispatch has one owner, and the store is what records it. Sending takes an exclusive lock on the
  request itself, and anything that wants to decide what became of that request claims the same lock
  first, so two windows of the application over one store cannot each conclude about the other's
  live call. A service writes its receipt when it commits the write, so a request still on the wire
  looks exactly like one that never arrived, and the device making the call is the only thing that
  can tell the two apart. A claim that succeeds because the owner is gone permits **asking** the
  service and never concluding: what settles a request is the answer, not the absence of an owner.
- An identity another request has already worn answers for that request, and the service refuses
  the exchange rather than running it. That ends this request too: the payload did not execute and
  never will under that identity, so the work goes and nothing asks about the identity again.
  Settling this payload from somebody else's receipt would move the note to a revision this content
  never produced, and one sealing per piece of work is what makes the refusal safe to read that
  way: every attempt sends the same bytes, so an identity refused for carrying different content is
  refused for content this device never sent under it.
- A service keeps a receipt for thirty days and no longer, so it keeps a cutoff too: it refuses,
  running nothing and recording nothing, an attempt signed so long ago that the receipt of an
  earlier run of the same request could be gone, which a service clock gone back would otherwise
  admit as a first run. An exchange reads that refusal as an answer about the attempt
  (`SyncExchanged::SignedBeforeCutoff`), and the caller is told `SyncError::SignedBeforeCutoff`.
  Nothing is attempted under the identity again, signed now or otherwise, and the record stays as
  the account of what left, since an earlier attempt may have run. The cutoff only rises, so where
  every attempt the record names was signed no later than the refused one, none of them can ever
  run and the request ends at once. Where one was signed later, which only a clock corrected
  backwards between two attempts produces, it could still be on its way, so the request stays
  counted and the next reconciliation fences it at once, whatever the generation; the account
  stays whatever that fence says. Publishing again is new work under an identity of its own.
  Every other request, a comparison and so a fetch, a resolution, a status query, a fence, a read
  of key records and the offer of one, is signed when it is sent, or, for an offer, at an instant
  its caller recorded and sends only while it is fresh. The service checks freshness first, so the
  refusal of one of these says that the collection's cutoff runs ahead of the clocks, which
  nothing on this device can correct. The caller is told `CLOCK_UNTRUSTED` with the action to
  wait, and a message that nothing ran and nothing was recorded. Nothing sends or signs the
  request again by itself, and asking again can succeed only once the cutoff falls behind the
  clocks. Its status and its fence settle an offer refused this way, as they settle any offer
  whose answer never came.

`sync::StorageFeature` names the three parts of what section 18 offers: encrypted settings sync,
which is this module; history backups; and recovery material, which is what a restore without
another device needs. The last two are optional, which is what sections 18 and 20 call them, and
each part carries what a person does without it.

### A collection put back

A service restored from an archive puts every collection back as the archive held it, under a
recovery identity of its own (`services::SyncRecoveryId`). Every answer names that identity: beside
each place in a collection's order it states, and on an answer that states none, a refusal about an
object the collection never held, a status query that finds no receipt, a fence. A deployment never
put back names none. An answer without the member is declined as unreadable. Places compare only
within one history, so a place under another identity is a collection put back, never a service
that went back or forked.

- Every stored position keeps its history: a note, a request's comparison, a publication record, a
  conflict copy, and the recovery bundle's write record. A record stored before histories were
  recorded names none, which is how this client read the collection then, and a record in a
  history never put back is written without the member, so either reads as it always did.
- The store keeps, for each object, the history it reads the object's collection in and every
  history it has seen that collection put back from, and each request records the history its
  attempts were made in. Every call carries the history that was current when it left, and every
  answer is read against it, under the store's lock. An answer in the current history is read as
  above. An answer in a new history, to a call that left in the current one, is the collection put
  back: the new history becomes current and the old one never is again, and the note moves to the
  place the answer names, or goes where the answer says the restored collection holds nothing of
  the object. The object itself is never replaced. An answer from a history the collection was put
  back from, or from a new one to a call that left before the history this device reads now, moves
  nothing: an applied write is recorded as one that went into another history, its record the
  account of what left, and the caller is told `SyncError::UnfollowedHistory`.
- Nothing this device wrote is written again automatically. A write the restore lost keeps its
  account, and the next fetch or publication brings what the restored collection holds down
  beside this device's own content where the two differ, for the person to choose; both versions
  stay readable.
- A request attempted in a history the collection has since been put back from is never attempted
  again. Where the current history holds no receipt of it, a reconciliation fences it at once,
  whatever the privacy generation, and the account stays, since a restored collection's fence
  cannot say for thirty days that anything signed before the restore never ran. A draft
  publication is attempted again only in the history its attempts were made in. A draft whose
  collection was put back stays the person's own: what the restored collection holds comes down
  beside it, and nothing is submitted.
- A read of several pages, a comparison, an inventory or the key records, holds every page to one
  history, and a read that meets a restore between its pages is declined and asked again.
- A fetch that finds the collection holding no object is an answer too, and it names the history
  that holds none (`services::SyncFetched::Absent`). The store reads it under its lock as it reads
  a refusal that names no place. In a new history, to a call that left in the current one, the
  collection was put back without the object: the new history becomes current and the note goes,
  so the next publication compares against nothing, and a draft publication attempted in the
  replaced history is never attempted again. In the current history the history stays where it
  is, and only a note still naming a place in a history the collection was put back from goes.
  Either way the caller is told the object is not held (`UNKNOWN_SESSION`). From a history the collection was put
  back from, or from a new one answering a call that left before this device moved on, nothing
  moves and the caller is told `SyncError::UnfollowedHistory`. An answer that arrives after
  privacy mode moved past its generation writes nothing, the history included. The recovery bundle
  store refuses a locator that holds no bundle in another history than the one it read the bundle
  in, as it refuses a bundle put back (`RecoveryError::BundlePutBackEmpty`), before anything is
  compared.

### The key a collection is sealed under

The service holds ciphertext and no keys, so the key is the device's. It is not one of the device's
own four keypairs: those identify the device, and this one is shared by every device permitted to
read the collection. `sync::CollectionKeys` is where a sealer gets it, named by the collection and
by the key epoch, because section 20 requires a mutable shared collection to be re-keyed when the
set of devices that may read it changes, and a device keeps the key of an epoch it still has
objects from beside the key it writes under.

A key that is not held is an error. Nothing in that interface makes one: a key drawn in place of a
missing one would seal content the other devices cannot read, and from the device that drew it
would look exactly like success.

| Implementation | Where the key is |
| --- | --- |
| `sync::StoredCollectionKeys` | The device's own secret store, through `kr_crypto::store::StoreSelection`: the operating system's credential store, or the owner-only directory section 10 offers in its place, whose directory is 0700 and whose files are 0600 |
| `sync::MemoryCollectionKeys` | This process, for a demonstration or a bench. Keys are put in deliberately and reach no store |

`sync::CollectionSealer` is the sealing itself: `kr-sync-object/1` authenticated encryption, padded
to section 20's declared size buckets, producing the sealed object the service stores. It asks for
the key on every call, so a key that has been withdrawn stops working at the next call rather than
at the next restart.

### Who holds a collection's key

A settings collection two or more devices share lives in the namespace of the device that started
it, its home. Its members are the devices its signed key record names, each with the epoch's key
wrapped to its stored-envelope key (`kr_protocol::collection_keys`). `sync::membership` is one
member's side of that record: `SyncMembership` checks the records the service keeps, stores the
key it is given, and issues the next record when the owner adds or removes a device or a host
reports one revoked.

A device gets a collection key only by opening its own wrap in a record it accepted; a restore never
brings one back (see [Settings after a restore](#settings-after-a-restore)). It accepts a
record when its own entry names both of its keys; the record follows the one it holds, link by
link, each signed by an issuer the record before it named; one of its hosts reports the issuer
paired and able to manage it, with the same stored-envelope key, and nothing it recorded from a
host or a verified authority feed reports the issuer revoked (the issuer of the record that opened
the epoch passes the same test); the signature verifies; and the key it opens is the one it
already holds for that epoch, or, for a new epoch, one that differs from every key it holds and
every key it opened from an earlier record since it joined. It never accepts a record carrying a
key it withdrew: the key of a record it sent since it joined that never applied.

Adding a device and joining a collection each widen who reads a person's settings, so each is a
plan (`Plan`) the owner confirms: "share settings with *name*" on a member, with the recipient's
keys taken from its hosts' reports and nowhere else, and "join settings shared by *name*" on the
device that joins. A plan is consumed once; one swapped, cancelled, reused or expired is refused.
Removing a device needs no new confirmation, and neither does removing a device a host reports
revoked. A member never removes itself.

Removing a device gives the members that stay a freshly drawn key at the next epoch; the removed
device has no wrap of it. What it held already stays with it: a rotation takes nothing back, and
no retroactive secrecy is claimed. A record that leaves this device out ends its membership, even
when a later record lists it again: it forgets the collection's keys and reads the collection
again only after the owner confirms a join on it. So does a service that answers the collection
as absent, or with a chain this device cannot follow; that answer is recorded at once.

A collection put back from an archive names its history on every key-record answer, and the
membership file records the history its records were read in: the one its first record applied
in, for a collection this device starts; the one of the chain a join verified; and none for a
collection never put back. An answer from another history changes nothing until this device reads
the collection again there, in the same step: the record at its head and the records after it,
both in that history. Its own head found there, with the same bytes, proves that the records up to
it are the ones it holds, since each names the digest of the one before it, and the device follows
the collection there. Missing, or another record in its place, the head is one the archive did not
keep, and a record the restore lost may have removed a device, so this device is out at once, as for
a chain it cannot follow, and reads the collection again only after the owner confirms a join; a
candidate it dispatched is settled first, as always. Two reads answered from two histories record
nothing (`MembershipError::PutBackWhileRead`), and the step is asked again. A membership listing
entry is news to this device when it names another history, whatever its revision, or a later
revision in the same one (`MembershipListing::names_news`): a reason to refresh, and nothing more.

Every record this device issues takes the next epoch and a freshly drawn key, an addition
included. It wraps the key in use only for the devices its installed record lists, so a record
that is sent and never applies, whose wraps a service could still hand out, carries no key anybody
writes with. A new member reads the settings once a member seals them again under the new epoch.
Records another member issues at an unchanged epoch, which only add members, are accepted as
before. A service can still hand out the wraps of such a record, and another member could carry
its key into a record of its own, so when a record this device sent settles without applying, the
write that settles it withdraws its key: no record carrying that key is accepted, whoever issued
it, and the device rotates away from one as from any record it refuses. The withdrawn keys last as
long as the membership; a new join starts with none.

The membership file keeps ten facts: the join record, the installed record, the head, the host
answers, the pending removals, at most one pending addition, at most one candidate record with its
request identity and dispatch mark, the keys withdrawn since the join, whether a join awaits the
owner, and the outcomes not yet shown; and beside them the history its records were read in.
`SyncMembership::step` runs one row of the reconciler at a time and makes at most one durable
write, so a restart resumes where the file says; the module documentation has the rows.
Publication into the collection is open only while no removal is pending, no candidate stands, no
join awaits the owner and the newest record this device has is the one it installed
(`SyncMembership::publishes`). A candidate is sent once, after its dispatch mark is written; an
answer that is lost is settled by the request's status and then its fence, and where the service
no longer holds the receipt, by the record after the candidate's base. A dispatched candidate
leaves the file only through that settlement. A device that is out still settles it first, by
status and fence, sending nothing and moving no head, and only then forgets the collection's keys;
a join or a new collection waits for both, so nothing it sent can still run in the membership that
follows. A change is reported done only at a head fetched after the change was recorded.

The file is replaced whole: written to a temporary name, flushed, renamed over the old one, and the
directory entry flushed too, so a write the reconciler has returned from survives a power loss. On
Windows the entry is flushed through a handle on the directory that may add a file to it, which is
what the operating system asks of a flush there. A crash of the process alone loses nothing on
either platform.

Two limits are stated rather than closed:

* A device revoked at a host but not yet removed by a record this device accepted is still a
  member. A device that has not received a revocation cannot act on it, and a hostile service can
  hold a removal back; it can deny service, but it cannot keep a key an honest member rotated away
  from it.
* A member that passes the host check and reuses key bytes where this device cannot see them, in an
  epoch it was not a member of or one from before its current join. Such a member could as well
  hand the key, or the settings themselves, to a removed device.

The reconciler's exhaustive test runs a bounded model of its world over the reconciler itself: every
reachable combination of the file's facts under the owner's changes, other members' records (a
faulty one among them, which may carry the key of any record this device sent), host and feed
revocations, lost requests and answers, expired receipts, a service that answers as if the
collection were gone, and crashes, with every state checked against the invariants and every state
settling once events stop. Its nine configurations run with
`cargo test --release -p kr-client --lib membership::exhaustive -- --ignored`; the two smallest,
and one run for each rule the test can weaken, run with the rest of the suite. Its service is never
put back; what a device does with a collection put back is tested over the same reconciler by the
scripted tests under "A collection put back" in `crates/kr-client/tests/membership.rs`.

### Privacy mode

The host records a privacy generation and drives every subsystem through the same four steps. This
client is one of those subsystems, in plain methods that take the generation as a number, because a
client never depends on a host crate:

| Method | What it does |
| --- | --- |
| `fence` | Stops production at the generation. A publication after it is refused. |
| `cancel_undispatched` | Discards the ciphertext of every request that was admitted and never sent, reconciles what had already been dispatched and counts whatever the service could not account for. It reports what that reconciliation established as well as the total. |
| `remove_retained` | Removes the conflict copies, the checkpoints and the work that never left, and reports the bytes and records it actually deleted. It reconciles afterwards, so the ciphertext of a request nothing can account for goes as well. Work admitted under a later generation is another cleanup's. A draft's note and the copies kept beside a draft are the draft store's, and this leaves them where they are. |
| `reconcile_unsettled` | Asks the service what became of every dispatch this device has no answer for, under the identity each request carried, and settles it. A service that cannot be asked leaves the work counted rather than failing the step. A draft publication is settled here once privacy mode has moved past the generation that admitted it; before that it is the draft half's, through `DraftSync::reconcile_unsettled`, and this counts it as unresolved. |
| `outstanding` | How many dispatched publications, settings and drafts alike, have no settled outcome, read from the durable records rather than from what is running. An abandoned call, a failed connection and a restart all leave one counted, and a record this build cannot read counts too. Cleanup is complete when it is nought, and it reaches nought after a lost answer because the two cleanup steps reconcile before they measure. |
| `kept` | What stays, and why: the device's own settings, the labels the person pinned, and the record of what has already been published. |
| `exported` | What has already left, shown rather than claimed to be erased: a write the service accepted after the fence, a refused write the service kept a copy of, a dispatch nothing has established the outcome of, and a request ended too late for a receipt to say whether it ran. Suppressing a result does not undo an upload. A copy the service kept of a refused write is the one entry marked deletable, because the service drops such a copy when asked and `drop_kept_copy` is the asking; nothing else is, because this client publishes writes and offers no operation that removes a published object. |
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
What ends such a request is an answer about the request itself, and a cleanup is complete only when
every one of them has one.

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

## Pairing

`pairing` is the side of pairing that runs on the device being added, and on an owner device when it
answers its hosts. kr-pairing holds the state machines and the proofs and no transport; this module
runs the candidate's half over the transport a host serves. A front end builds one `Pairing` from
its parts (the device's keys, its attempt budget and clock, how it opens a room, how it reaches a
host, and its records of paired hosts) and calls `pair_by_code`, `pair_directly` or `resume`.
Progress arrives on a `watch` channel as `AttemptState`, and an attempt that fails ends as a
`PairingFailure`. The ending also says how the attempt was made and, for a code, which service it
went through, so a front end names that service and asks for a direct invitation to be pasted again
rather than for a code. Neither carries a secret, a key, a transcript, a challenge or a proof, so a
front end can hand them to a screen as they are.

A code goes through one room socket. The device sends the four locator characters, and nothing else,
to the rendezvous service it is set to use, at `/api/pair/room/<locator>/candidate`, directly and
over TLS checked against the platform's trust (see `services::http` below). A host opens its end of
the room the same way, through the proxy its configuration selects when it selects one: the socket is
then an HTTP `CONNECT` tunnel with the room's TLS inside it, so the proxy sees where the socket goes
and nothing that travels on it. kr-pairing charges the attempt budget before that lookup, so a service
that cannot be reached still costs a try. The exchange then moves to iroh, to the endpoint the
host's authenticated bundle pinned, and `pair.finish` is sent only once the device has checked that
the live peer is that endpoint. A direct invitation goes to `pair.redeem` under the same check, and
no proof leaves the device for any other peer.

Each host is reached through the relay and discovery services its own configuration names, with one
dialling endpoint for each set of services. A key holds one endpoint on a relay at a time, so two
configurations that share a relay are never open together, and binding one closes the other. An
attempt holds its host's endpoint from its first dial to its end, and an owner's review holds its
host's while it runs. Nothing else the device does closes a held endpoint, and a connection that
would have to is refused until the hold ends.

The verification value is computed here, from the transcript, and grouped `f3c1 46fd` by the
function the host and the command line use. The device shows it only once the host's answer to
`pair.finish` names the same value; an answer naming another ends the attempt as `host_mismatch`,
and nothing is shown.

`invitation` reads the one invitation text there is: unpadded base64url over the canonical KR-CBOR-1
payload, the text a QR code carries. The older JSON forms are not invitations. A code payload that
names a service other than the one the device is set to use says so, and a front end asks the person
before it opens any connection there.

Every wait has an end. A code attempt may recover an answer it lost until the invitation's five
minutes and one more have passed; a direct one until the invitation's own expiry and one more
minute. Each wait for the host inside that is bounded as well, so a host that stops answering ends
the attempt instead of holding it open: as `timed_out` during the exchange, and as
`approval_unknown` once the host may already have added the device, because then nothing the device
can see says whether it did. A refusal is read from what the host sent, never from what the
transport concluded about the connection. An attempt still waiting for its owner is kept in
`paired`, and `resume` takes it up after a restart; a device the host committed while it was away
finds its record and confirms that instead.

While it waits for the owner, the device asks `pair.status` every three seconds. A host answers an
unpaired connection four times in any ten seconds and sixteen times in all, and ends it a minute
after it answered the connection's handshake. So the device counts its questions the way the host
does, counts that minute from before its offer went, which is never later than the host, waits when
the window is full, and asks nothing on a connection after its last call, ten seconds before the
host ends it. From four questions before the end, by count or by time, it opens a fresh connection
before each question, asks there, and changes to it once it has answered. A host that commits the
device serves it nothing on a new unpaired connection, so the old connection is then the only place
to learn what the device became. The device keeps its last question there while fresh connections
fail, and asks it at the last call. A question that would leave the host's window no room at the
call is kept for the call instead, so the window always has room for the last question when the call
comes. The device waits at most ten seconds for an answer, so from ten seconds before the call it
asks nothing there but the kept question. Every other step it takes before the call ends by then,
its pause after an answer included, and the kept question does not wait for that pause: the device
is free when the call comes. A look for a fresh connection takes time, so after one that fails the
device plans its next step again from when the look ended. A device that is late for the call all
the same, by more than a second, lets the connection go instead of asking a question the host may no
longer be there to answer. Ten seconds before the attempt's own deadline every answer is final, and
from then on the device asks the connection it holds at its usual pace and looks for no other. A
commit made after the last question on the last connection opened before it, while no new connection
opens, is one the device cannot learn of by itself, and the attempt ends as `approval_unknown`. A
change of connection is not a lost connection, and the device does not show it as one. A host that
turns a question away as too soon keeps the connection. It counts the questions it refuses as well,
so the device waits twice as long after each refusal in a row, however long that grows, up to the
attempt's own deadline and the connection's last call.

`owner` is the owner device's half. It reads `owner.confirmation.pending` over the device's
authorised session, checks each challenge against what it would authorise, and describes it in one
line: what, on which host, and for how long. A challenge whose display does not match its digest is
marked as one this device cannot check, and nothing is signed for it. The platform's ceremony is a
trait the application implements; it is asked with that line and the challenge's remaining
lifetime, and only a confirmation inside that lifetime is signed, on `owner_device_presence`, and
completed. Only the host's own refusal makes a review "not confirmed". A host that says nothing for
ten seconds, one that replies that it does not know what came of the answer, or a connection that
ends after the answer went, may still have taken it: the device asks what the host lists, and the
review is "confirmed" when the challenge is listed as answered and "unknown" otherwise.

## Managed services

`services` holds one trait per managed service section 17 names (account login, relay leases, push,
encrypted sync and backup, managed inference), and `ServiceClients` holds one optional
implementation of each. `services::account` is the account sign-in: the authorisation request a
system browser is handed (S256 PKCE, a fresh state and nonce, the registered redirect byte for
byte), the checks on what comes back (the redirect, one of each parameter, the state, the issuer,
then a code used once), the exchange with its ID token checks, and `SignedInAccount`, which keeps
the grant in a secure store under one lock across refreshes, sign-outs and restarts, revokes on
sign-out, and is the `AccountTokenSource` every managed resource asks for a token with the scope it
needs. `services::relay` is the relay-lease client, because a lease is the one
managed resource a client cannot do without and still use a relay at all, and `services::voice` is
the voice broker. `services::authority` carries the durable authority feed, where a remote owner
publishes a signed revocation request and the host that owns the feed acknowledges what it applied,
`services::mailbox` carries the encrypted mailbox, `services::sync` carries settings sync,
`services::storage` carries managed storage and `services::backup` the backup manifest. All five sign
through `services::signed`, which is the one credential every method of the section 23 `Services`
group is proven by: the gateway origin, the method, a fresh nonce, the time and the digest of the
canonical request body.

A request for something an account owns, rather than the key that asks, carries a second
authorisation beside that credential. `signed::AccountAuthorisation` names a token source and the
scope the resource reads; the token the source holds at that moment is taken before the request is
signed and travels as its `authorization` header, and the signature covers none of it. The same
call says whether a request that went unanswered ever left this device: `Unanswered::NotSent` for
everything refused before the transport is given the request (a body it cannot write, a token its
source will not give, a credential it cannot make or that falls outside the service's clock window,
a request larger than the method admits), and `Unanswered::Sent` for everything after, an answer it
cannot read included. An authorisation made for one purpose asks for that purpose alone:
`AuthorisationRequest::asking` asks the identity and refresh scopes and the resources its caller
names, so a device restoring from a recovery kit asks for `backup.restore` and nothing else, while
`AuthorisationRequest::new` is the application's own sign-in and asks for what it always has. That
sign-in never asks for `backup.write`. `AuthorisationRequest::with_recovery_backup` does, with every
scope the application's sign-in asks for before it, because the grant it leads to replaces the one
the device holds: it is the second authorisation the person makes when they turn recovery-enabled
backup on, and the sign-in the application makes again while backup stays on.

A gateway in front of a managed service answers 502 or 504 when the service's answer did not reach
it, and it can do that after passing the request on. Such an answer, with no envelope of the
service's (for the account service, no OAuth error of its own), says nothing about what the service
did, so every client reads it by whether its request may have run. Where it may have, the answer is
`OUTCOME_UNKNOWN`, or for a voice start the unknown creation it already has a state for, and nothing
sends the request again by itself. Where sending it again is safe, the answer stays
`UPSTREAM_UNAVAILABLE`, which an idempotent read may retry. The account service's code exchange and
refresh may have run: a code is spent once, and a refresh token rotates on every use and revokes its
family when a rotated token is presented again. A refresh whose answer was lost after the service
rotated the token therefore ends the sign-in: the device still holds the spent token, its next
refresh presents it, the service revokes the family, and the person signs in again. Nothing short of
that recovers, because the new token was only in the lost answer. A voice start may have started a
call, and a relay lease request may have issued and installed a lease. Of what `services::signed`
carries, a storage deletion and every authority feed request may have run and are not safe to send
again: the service keeps a deletion's first target only for the signature that asked for it, and a
delegation has nothing to tell a repeat from a later change. Everything else it carries is safe to
send again, because its method is an idempotent read or the service answers a repeat of each of its
operations without a second effect: a delivery by its envelope identifier, a settings-sync request
by its identity, a manifest by its generation, an upload part by its number. So are a revocation,
the identity and usage reads, the voice terms and closing a voice call.

A caller of `services::relay` finds out what became of a lease request whose answer went missing, a
success it cannot read included, before it asks for anything else, by sending the same request
again, with the same signer, payer, pair, direction and cumulative ceiling: a pair that already
holds a lease on a live reservation is answered with that lease and no more bytes held, a first
request that issued nothing is answered with a new lease, and either can be refused. The caller then
uses the lease it is given or ends it. A revocation whose answer went missing is asked again as it
was.

A mailbox is addressed by the identifier of the recipient's stored-envelope public key, and every
paired peer of that recipient knows that key, because it is what they seal to. So possession of the
private half is what distinguishes the recipient: the first read of an unclaimed mailbox is
answered with an ephemeral X25519 challenge, and `MailboxClient::read_as` answers it from the
recipient's own key pair and reads once more. What leaves the device is one value bound to that
challenge, that mailbox and nothing else; the private key stays where it was. The claim settles on
the key that answered, so a mailbox is read and acknowledged by one device and a peer that knows
the public key is refused rather than served.

The client seals nothing and opens nothing here: `kr_crypto::envelope` produces and opens
envelopes, and `services::mailbox` carries them. Everything outside the box stays untrusted on the
way back. The routing record selects a sender's key out of the paired set rather than supplying
one, the fields outside the box are held to the fields inside it, an identifier already accepted is
refused by the reader's own replay ledger, and the bytes a mailbox counts are the declared size
bucket rather than the length of the plaintext padded into it.

`services::http` is the exchange underneath them: `HttpService` addresses one gateway origin, which
it compares as a parsed scheme, host and port before it makes contact, and refuses an address that
carries credentials or that uses plain HTTP anywhere but loopback. Certificate and hostname
verification stay on. Connect, read and total deadlines are finite and the total one covers reading
the answer, so a call either has an answer or a failure. An answer is read under the bound its
operation states, measured as the bytes arrive rather than from the length the sender claimed, and
an answer past it is refused rather than truncated. It follows no redirect, keeps no cookie and asks
for no compression. It goes through the proxy its caller names, or directly, and never through one
the environment names: a host passes the `network.proxy_url` its configuration document selected
when the daemon started, and a device, which has no such document, passes none. `client_builder`
starts the other HTTP clients the product builds, such as the host's fetches from plugin
repositories, on the same two rules, and leaves their deadlines to them.

The certificates these clients trust are the platform's (`platform_tls`), and the room socket and the
host's mail submission verify with the same configuration. On macOS, Windows, iOS and Android it is
the operating system's own verifier, whose trust settings a person manages there. On Linux it is the
distribution's certificate store, read from the places distributions keep it: the first bundle that
exists among `/etc/ssl/certs/ca-certificates.crt`, `/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem`
and the others the platform verifier's own probe looks for, and every file in `/etc/ssl/certs`,
`/etc/pki/tls/certs` and `/etc/security/certificates`. `SSL_CERT_FILE` and `SSL_CERT_DIR` are not
read. While either is set, the platform verifier would trust only what it names, and an inherited
variable would then decide who can answer for a service. So an authority given only through one of
them is not trusted until it is installed in the system store, with `update-ca-certificates` or
`update-ca-trust` for example, and `kr doctor` says the same. The network endpoint is not one of
these clients: it verifies its relays and Pkarr servers against the public anchors and any relay
trust anchors its configuration names (see the transport guide).

The service sees one request at most for one dispatch, which is what keeps a request identity and
its receipt simple. The transport never sends again a request that may have reached the service:
`retry` decides whether to ask again, with the failure's class in view. Connections are pooled, so
several service clients over one gateway are one set of connections rather than one each, and a
pooled connection can be taken away between one request and the next; the HTTP library may open a
new connection for a request of which it has written no byte, which is not the request arriving
twice, because it never arrived.

A failure the connector itself reported — an address that could not be resolved, a connection
refused, a handshake that failed, an establishment that ran past its deadline — says the request
was not carried out, because none of it had been written. Every other failure says the outcome is
unknown, and that includes this client's own total deadline running out while the connection was
still being established: saying "unknown" about something that never left is the safe direction,
and saying "no effect" about something that may have arrived is not.

Beside the class, every failure of an exchange names the phase it happened in: the connection being
established, the request on its way to the service, the answer arriving. That is what makes a
deadline legible, because "it did not finish in time" leaves a caller guessing which deadline ran
out and how much the service had already seen. The phase is also what a client shows a person while
a call is in flight: `ExchangeProgress` is told when an exchange starts and when the answer's head
has arrived, it carries the phase and nothing else, and a transport nobody asked reports nothing.

Nothing that travelled is written down. The transport emits no diagnostics of its own, and in
`services` the bytes of a request or an answer, a credential, a signature and a header value are
held only in types that write their own `Debug`: what a rendering carries is the operation, the
class and the length.

`services::json` is the one reader of what a service answers. Every service client here reads an
answer through it, and so does the host where it reads the gateway's answers itself. It refuses an
answer in which any object names one member twice, at any depth and whatever the member, before
anything reads a member of it, and it compares names as the strings they decode to, so `"a"` and
`"\u0061"` are one name. Such an answer says two things at once: one reader would keep the first
value and another the last, and neither is an answer the service gave. The envelope that
`services::signed` reads is closed too: `ok` with `data`, or `ok` with `error`, and no other member
beside them. A refused answer is treated as any answer its client cannot read. Where the status
decides that, as it does for the signed calls and relay leases, a refused success is an unknown
outcome that nothing retries by itself. The failure names the rule the answer broke and where,
never what the answer held.

`services::SyncBackupService` is the sync and backup trait: a compare-and-exchange over opaque
bytes where every exchange names the request as well as the object. An exchange is answered with
`Applied`, carrying the position the service put the write at, or with `Refused`, because a refusal
is an answer and not a failure, and `Refused` names what the service kept of the rejected write.
`request_status` answers about that request afterwards, from the receipt and never from what the
collection holds now, adding `Unknown` for a request the service holds no receipt for and `Fenced`
for one it will never execute. `fence_request` is how a caller reaches that last answer: it never
says it does not know, so a request can always be ended. It carries the earliest and the latest
instant an attempt was signed at, and it answers whether anything ever ran under the identity.
The service is what states that, from records only it holds, and the caller does no arithmetic of
its own. Every exchange is signed with the instant its caller states rather than one the
implementation reads, because those are the instants the fence presents afterwards. `resolve` drops
the copy the service kept of one refused write once the person has chosen, and answers a copy that
is already gone the same way, so asking again is safe. `compare_exchange_dispatched` is the exchange
for a caller that records a write before it sends it: it answers `SyncDispatch::NotSent` for a
request refused before anything left, which can never run, and an implementation that cannot tell
counts every failure as possibly sent.

The trait states what an implementation owes. The order is the service's: every applied write takes
the next place in its collection's order, from a counter the service keeps, because numbers assigned
as answers arrive describe the order they arrived in. A receipt is history, so an applied receipt
names the position that write produced however far the object has moved since. A position is absent
only when nothing has ever been there, and a position with no revision is a removal. A fence ends a
request, which is what lets a cleanup finish. And a fence says nothing ran only where the service
can establish that no receipt of a run has ever been removed, keeping the fence itself until
nothing the caller signed can become fresh again.

`services::sync` is settings sync's client, `ManagedSyncService`, the implementation of that trait
this crate carries. It speaks the eight members of `sync.compare_exchange` over `services::signed`:
an exchange, a comparison, a resolution, the status of a request identity, a fence of one, a read
of a collection's key records, the offer of the record that follows its newest, and the list of
shared collections that name this installation.

- It keeps nothing. Every position, receipt and statement about whether a request ran is passed
  through as the service stated it, including a removal's place and a place of nought, which the
  caller declines. An answer that leaves out what the contract requires, such as a status or fence
  answer without `never_ran`, a fence answered `unknown`, or an answer about another request
  identity, is an unknown outcome rather than a guess.
- An exchange is signed at the instant its caller recorded for the attempt, never at a reading of
  its own, and an attempt outside the service's freshness window by this device's clock is refused
  before it is sent. The body is a function of what the caller passed, so the same attempt made twice
  is one document: the service answers a retry from its receipt only when nothing its digest covers
  has changed.
- This crate names a collection for one object's kind and identity, with `sync::sync_collection`
  or `drafts::draft_collection`, and the service's collection is named by the object's own
  identity, scoped by the service to the installation key that signs. A name neither function makes
  is refused before anything is sent, and so is a sealed object the service would refuse for its
  structure, a fence whose instants are out of order, and a counter past the largest the service
  compares exactly.
- `REQUEST_FENCED` is reported as the refusal of that identity with nothing for a person to do,
  `ID_CONFLICT` as a reused identity and `INVALID_ARGUMENT` as a value this client should not have
  sent. Where a shared collection's two refusals reach a caller as errors, `COLLECTION_ABSENT` is
  an unknown object and `KEY_EPOCH_RETIRED` a view to bring up to date. A fetch reads the object
  through a comparison for its kind, and a collection holding none is reported as such.
- The owner's recovery bundle is the fourth kind, `recovery_bundle`, named by
  `recovery::bundle_collection` for its kind and the kit's locator. Its four requests, an exchange,
  a read, the status of a request identity and a fence, name the locator instead of a collection
  and a home, because the service keeps one collection at each locator for the whole origin. Each
  carries the account token `ManagedSyncService::presenting` names beside the signature:
  `backup.write` for a device that writes the bundle, `backup.restore` for one restoring from the
  kit. A client that presents no account sends none of them. The bundle travels as a
  `SealedRecoveryBundle`, its stream and nothing else, of at most 128 KiB, which fits the request
  every member shares. A longer one, a locator that is not a canonical identifier and a resolution
  (a bundle keeps no copies) are refused before anything is sent, and a bundle named among a
  collection's objects or copies is an answer about something else.
- An answer may carry members this client does not read, because the service and this client are
  deployed on their own schedules; every member it does read is required and typed. A sealed object
  and a key record are the exceptions and stay closed schemas. One path carries every member, and a
  comparison page holds sixty-four objects and sixty-four copies, so
  `services::managed_response_limits` gives that path a bound of its own.

A collection two or more devices share is named by a `sync::membership::CollectionRef`: the
installation that started it, its home, and the collection. The `_shared` calls address one:
`exchange_shared`, `status_shared`, `fence_shared`, `compare_shared` and `resolve_shared`. Every one
names the home, every write names the key epoch its object is sealed under, and the per-object
name this crate gives an object names it inside the collection. A write, its status query and its
fence answer with `services::Keyed`, which adds the two answers a shared collection gives beside
the usual ones:

- `Retired`, for a write sealed under an epoch the collection has retired. Nothing was stored or
  held, the refusal names the collection's epoch and revision, and it is the request's receipt, so
  a status query and a fence answer the same. It ends the attempt that met it and says nothing of an
  earlier one.
- `Absent`, for a collection that does not exist or whose newest key record does not list this
  installation; the service answers both the same way. A member removed after it sent a request
  is still answered about that request.

A comparison and a resolution answer nothing for such a collection, and otherwise the comparison
and the resolution the unshared calls give.

An answer names where the collection's key records stood, `services::KeyHead`, when the service
named it: a write and a comparison in a collection a key record has claimed, and a status query or
fence about a receipt that recorded it. A status query about an identity nothing was recorded for,
a fence that has just been made and a resolution name none. A device holding an older record than a named head knows to fetch the ones
after it. The epoch is part of what a write asks, so a retry names the epoch the first attempt named
and is answered from the receipt, whatever the collection's epoch has become; a write under a new
identity and the retired epoch meets the refusal. For a collection only its home writes, neither
answer can be the service's, and both stay errors.

The service answers a comparison sixty-four objects at a time and names every object the
collection holds. `compare_shared` takes what the reader holds, each object at the revision it
holds it at, which the service leaves out, and follows the pages until nothing the collection names
is missing. It reads each page whole and folds them into one answer: the objects the reader lacks,
and the objects it named that the collection no longer holds, each with the place its removal
took. What a later page says of an object replaces what an earlier page said, so an object removed
between two pages comes back removed, and one written again after that comes back as the object.
Each request names every object the reader holds once, and after the first page only those the
collection lists, which keeps it within what the service reads. It stops at a page that brings
nothing while something is missing, at an object a page brought that the collection stops listing
without any page saying it went, and after `MAX_COMPARISON_PAGES` pages of a collection that keeps
moving.

`ManagedSyncService` is also the membership's `KeyRecordService`. A read of key records names the
home and follows every page to the newest, handing the records over as the service answered them,
because whether they form a chain is for the reader to establish; it stops following a page that
does not move on, and at `MAX_KEY_RECORDS_READ` records. The offer of a record carries its request
identity, its home and the record exactly as it was signed. A record the service would refuse for
its collection, its home, its structure or a revision or epoch past what the service compares
exactly never leaves the device. Its status and fence read the receipt of the offer, and one that
names a write is an answer about another request. `memberships` lists the shared collections whose
newest record names this installation, page by page, from an index that can be behind and admits
nobody.

`inventory` reads what a shared collection holds, each with the epoch it is sealed under: every
object, and its copies of refused writes, page by page. A collection keeps copies until a person
chooses about them, including copies of objects it no longer holds, so their number has no bound
this client can state, and each page carries the copies' content. A read therefore stops at the
number of pages its caller gives it, at least one, and names the cursor it stopped at; the caller
continues from there, handing back what it has, until the read reaches the end. That is what a member reads before
it forgets an old epoch's key, and only a read that reached the end can show that nothing is sealed
under one.

`services::storage` is managed storage's client, `ManagedStorageService`, the `StorageService` this
crate carries, and `services::backup` is the backup manifest's, `ManagedBackupManifestService`, its
`BackupManifestService`. Backup storage belongs to an account, and an installation's own entitlement
holds none, so every storage request and every publication carries the account token for
`backup.write` beside its signature, and names the installation the signing key derives, which binds
the two proofs to one caller. A client given no account sends none of them, and neither does one whose
sign-in was not granted `backup.write`: its token source refuses, and nothing leaves the device. An
enrolment and a fetch spend nothing and carry no token.

- Backup storage is off until `set_retention` turns it on, decided against the revision a status read
  names, and turning it off deletes nothing.
- An upload is created before any content leaves, and it is answered with its part table: every part
  8 MiB but the last, one table for one total, which this client holds to its own arithmetic. A part's
  body is its ciphertext, and its signed request travels in the `kr-service-request` header beside
  it, naming its length and SHA-256; a read is answered with the ciphertext itself. `upload_parts`
  sends the parts after the last one acknowledged, in order, and tells its caller of each
  acknowledgement before the next part leaves, so a transfer that stopped goes on at the next part and
  sends no acknowledged part again. A part sent again after its answer was lost is answered as the part
  it is, and a completion asked for again is answered with the result it already gave.
- A refusal is an answer about the work, `ArchiveAnswer`, only where its code means that in every use
  the service makes of it: `CollectionDeleted`, a collection its owner deleted from the account
  console, which takes no upload and no publication again, so backing up again means enrolling a new
  collection; and `UploadGone`, an upload the service holds none of. `FORBIDDEN` about an upload also
  answers a pair of proofs the service could not bind that time, and `INVALID_REQUEST` a body cut short
  on its way, and the upload takes the next part after either, so both stay the errors the service
  named; an upload is ended by asking the service to abandon it, whose answer says it is over. Where
  `COLLECTION_DELETED` reaches a caller as an error it is a change of configuration, with a message
  that says to enrol a new collection, and never an update. A service with no room for a part now,
  `SERVICE_UNAVAILABLE`, is capacity to wait for, with the delay it names. An upload that would spend
  an account's storage without the account's proof is answered `QUOTA_EXHAUSTED`, with a message that
  says where backup storage comes from; the ledger's own `PAYMENT_REQUIRED` never reaches a client.
- A publication is signed by the writer the collection's owner enrolled and carried by that writer's
  own key, and an enrolment is carried by the owner's. The same publication sent again is answered as a
  duplicate, and other content for a generation already published is refused. A fetch answers with the
  publication exactly as it was published, or with nothing when the service holds no such generation,
  or none as new as the checkpoint presented.
- A read answers with up to 8 MiB of ciphertext, and a fetch with a whole publication, which for a
  descriptor at its bound is past the bound an ordinary answer is read under, so
  `services::managed_response_limits` gives each path a bound of its own.

Two things call these clients: the host's outbox uploader, `kr_controller::backup::uploader`, and the
device's settings archive, `recovery::SettingsArchive`, below.

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

### What a deployment answers

Every other suite here checks this client against something this repository wrote: a mock, a
loopback server, a service half running inside the test. `tests/integration/sync` checks it against
a deployment. It seals a real envelope, signs a real credential, sends it to the origin it is given,
and holds the answer to the rules sections 9, 10, 20 and 24 state. Three groups of legs run there:
the mailbox, where an envelope is delivered, claimed, read, opened and acknowledged, and a routing
record, an unpaired sender, a replayed identifier, a repeated acknowledgement, a declared size
bucket and a credential for another gateway each get the answer the rules require; the durable
authority feed, where a published revocation is retained until every enrolled host has finished with
it, a revision follows the one already accepted, an acknowledgement names a revision that applied
the request, a synchronisation stays owed until one happens, and an unreachable feed is stale rather
than empty; and settings sync, where the client, its store and its sealing are the product's own and
only the collection key is made for the run.

In the settings-sync legs a lost comparison keeps both versions, readable through a comparison with
its copies, until the person's choice leaves no copy on either side, and no clock decides anything;
a write against a stale revision is refused and kept as a copy; a draft is stored as a draft and
nothing submits it; a client fenced by privacy mode sends nothing and keeps its pinned labels out of
what it would publish; a sealed object the service refuses for its structure is refused here first;
an answer lost on its way back settles from the receipt, and the write is applied once; a fence of an
identity that never arrived says nothing ran and refuses what comes after; and a setting is stored in
a declared bucket and never in the clear. The service derives a collection from the installation key
that signs, so the two devices of a leg are two client stores under one run key: the legs prove the
conflict and resolution rules, and they say nothing about two installations sharing a collection.

Two variables decide what those legs do. `KR_DEPLOYED_ORIGIN` names the origin; without it every leg
prints why it did nothing and returns, so an ordinary `cargo test --workspace` stays offline and
passes. `KR_REQUIRE_DEPLOYED_ORIGIN=1` turns that absence into a failure, which is how a run that
was promised a deployment finds out that it did not get one.

`scripts/e2e-deployment.sh https://example.invalid` is the command to run once a deployment is live.
It refuses anything but an HTTPS origin and refuses one carrying credentials, prints the commit, the
host, the time and the origin, runs each leg in a process of its own, and prints one line per leg
saying what that leg proved. It exits non-zero when any leg failed or did not run, because a report
that named a deployment and then ran nothing against it has proved nothing. One log per leg is left
under the directory `KR_TEST_ARTIFACTS_DIR` names, so a leg that failed keeps its whole output and
not the line the report had room for.

What such a run sends, and what it leaves. Every principal is made when a leg starts and discarded
when it ends: a fresh authorisation key signs, and the identifiers the legs publish are drawn for
that run alone, so a leg touches nothing that was not made for it. No account is created and nothing
is bought. Each leg gives back what it took before it reports - a host removes itself from the feed
it enrolled in, a mailbox is emptied and acknowledged, and a collection has every request identity
the leg presented fenced, every copy resolved and every object removed under comparison - whether
the leg passed or failed. A leg that could not is named in the report's closing lines, and what it
left is the deployment's to end. A durable authority record is retained until it is acknowledged,
refused or removed, so that one does not lapse on its own and a run that reports it is reporting
something that needs a hand. Settings sync keeps some things by its own rules, which no client may
remove: each request identity's receipt for thirty days, a record of each removed object's place in
the order with no content in it, spent nonces, and the ledger's record of the installation a run's
key made.

## Recovery

`recovery` holds the owner's half of section 20's recovery material: the kit that carries the seed,
the bundle at its stable locator, and what a fresh restore may put back.

### The kit

One document, printed for a person to type and carried in a QR code's byte mode for a camera to
read. They are the same bytes, so what a scanner reads is what a person could have typed. It names
the format and cryptographic profile version, the seed and its checksum, every configured service
origin and the stable opaque bundle locator, because a seed with no way to find the encrypted
bundle is not a complete kit.

The seed is grouped Crockford base32: no `I`, `L`, `O` or `U`, so the letters a hand-written kit is
misread as are not in the alphabet, and reading maps `I` and `L` to `1` and `O` to `0` because that
is what somebody who wrote them down meant. The checksum catches what the alphabet does not, and it
is checked before anything is derived, so a mistyped kit fails as a mistyped kit rather than as an
authentication failure that looks like a hostile service. The rendered document is built into a
buffer reserved at its exact final size inside `Zeroizing`, so no reallocation leaves a copy of the
seed behind.

### The bundle

`BundleStore` reads and writes the bundle through `services::SyncBackupService`, which is a
compare-and-swap over opaque bytes at the locator; `bundle_collection` names the collection for the
bundle's kind and the locator, and a managed service is reached through `services::sync` with the
account's token beside every request. A new kit's locator is drawn with `fresh_locator`, a random
identifier in its one spelling. Three things follow.

**A writer is declared recovery-enabled only after its bundle has landed.** `enable_writer` commits
the updated bundle and then returns `WriterEnabled`, whose fields are private and which this crate
builds nowhere else: a caller that holds one holds evidence the commit happened, at the origin and
locator the evidence names. A rotation adds the replacement key and **keeps** the rotated-out one,
because the bundle is the only place a restore takes a writer key from and dropping it would leave
every archive it had already signed unverifiable. `retire_writer` is the separate, deliberate step
that drops a key once no retained archive needs it.

**The bundle also names the producers.** A key wrap is a `crypto_box` between the producer's
stored-envelope key and the recipient's, and opening one needs the producer's public key; the
descriptor carries only an identifier, which is a hash. `enable_producer` puts it in the bundle, and
a restore takes it from there, because taking it from the archive would be taking key material from
something untrusted.

**A verified generation only moves forward.** `record_checkpoint` refuses a lower generation, and
the same generation with a different manifest hash. A verification of generation four arriving after
one of generation nine is a late answer rather than a newer fact, and writing it would hand a
service five generations it could replay unnoticed.

**A lost comparison is a conflict, not a failure.** Another device that wrote first leaves this one
with `BundleConflict`, its bundle's revision put back where it was, and the obvious next step:
read again and apply the change to what is actually there. The conflict names the copy the service
kept of the refused write, where it kept one, because what a service holds is ciphertext this
device sent and an owner is shown a retained artefact rather than told it does not exist.

**The locator names one collection for the whole origin, owned by the account whose first write
applied there.** A device holding only the kit reaches it with the locator and its account, and
another account is answered as if nothing were there. The locator's secrecy covers its first claim
only: once one service has seen it, a claim at a second service, or at one put back from an archive
that held no bundle, can be taken by another account that writes there first. That denies the owner
the bundle at that service. It cannot forge one, because only the seed derives the key.

**The bundle is key material, and it settles itself by reading.** Section 20 says what it holds:
collection locators, trusted backup-writer signing public keys and generation checkpoints. None of
that is session content, so it is not one of the content-bearing outboxes privacy mode fences, and a
write of it is not cancelled or deleted when privacy mode is enabled: a deleted bundle is a restore
that cannot verify an archive the owner still holds. The settings-sync outbox keeps a full account
of every request it dispatches, content included, because its work is session content under a
privacy generation; the bundle needs none of that. It writes directly and reads to find out what
happened. What the store keeps is one record of the last write it sent, and the record holds only
what settling and recognising that write take: where the bundle is, the place the write compared
against, the identity and instant it went out under, the digest of the encrypted bundle it sent, and
what is known of what became of it. It never holds the bundle, its ciphertext or a key.

Each write carries an identity of its own and the instant of the call, which is what the service
signs with and measures freshness against. Nothing is ever resent on its own, so each attempt is
its own request. When an answer does not come back, `commit` says exactly that -
`BundleOutcomeUnknown` - and the store writes nothing further until that write is over. A second
write made in the meantime would compare against a place the first one may be about to leave, and
its refusal would be reported as another device's conflict when what it had met was this device's
own write.

The one exception is a write that never left this device. A bundle sealed past the 128 KiB a
service keeps is refused before anything is recorded (`BundleTooLarge`). For the rest the service
client says whether a refused request left (`SyncDispatch::NotSent`): one refused for want of an
account token, for a signing instant outside the service's window or for a locator the service
cannot address can never run, so `commit` puts back the record the call found, reports
`BundleNotSent`, and the next write goes out. A migration whose destination write is refused that
way leaves both locations and both stores as they were. A record the disk will not take back
reads, after a restart, as a write outstanding, and `end_lost_write` ends it once the service can
be asked: a fence, and a read after it where the fence cannot say the write never ran. Everything
after the request left stays unknown, a fault with no envelope included.

Two things end it. A read that finds the very bytes this device sent, which the record's digest
establishes, settles the write as applied: it landed, and it cannot land twice, because a service
answers a repeated identity from the receipt it already holds. The bytes and not the bundle inside
them, because every encryption starts from a fresh random header: another device writing an equal
bundle at the same instant still writes other bytes. A read that finds another bundle
settles nothing, and says so: it has established what is at the locator, not that a request still
in flight cannot land after it. For that the request has to be ended, and only the service can end
it, so `end_lost_write` asks the service to fence the identity. Nothing executes under it from that
moment, and the fence answers with whatever the service had already decided, which is how a write
whose answer was lost but which did apply is recognised without writing again. The receipt names
the place it landed, and a store that has not already read that place or a later one reads the
bundle back and holds it to the record's digest. Other bytes at the receipt's place mean two
histories, so the store refuses them instead of adopting them.
Fencing here is not a privacy operation and ends nothing else: it is how a caller makes one request
over when no answer to it ever came back. `writer_enabled` is the matching half for the
declaration: the evidence that a writer's bundle has landed comes from the authenticated bundle at
the locator, so a lost answer costs a read rather than another write.

**A lost write outlives the process that sent it.** `BundleStore::open` takes the directory where
the device keeps its recovery state, and each record lives there under a name derived from its
bundle's location, so one directory serves every bundle the device writes. The record is written and
flushed before the write leaves, and the write does not leave if that fails. It stays until the next
write replaces it, and what is learned about the write, an answer or a settlement, is written into
it as well. A store opened over it after a restart takes the write up. One whose answer never came
back and which nothing settled starts unsettled, as if the answer had just been lost, and the store
writes nothing until a read finds the write's bytes or `end_lost_write` fences its identity. Its
reads are held to the place the write compared against, because the bundle had reached that place
before the write went out, and the write's own bytes count only at a place past it, whatever the
store knows of the write. The record also outlives an answer, because `complete_migration` needs it:
a migration whose destination answered is not complete until the bundle has been read back there,
and a destination store opened after a restart finishes it from the record. A record this build
cannot read is refused rather than set aside, since it may be the only account of a write that can
still land. An open store holds a lock beside its record, so a second store for the same bundle on
the device, in this process or another, gets `BundleStoreInUse` instead of writing a record over the
first one's. A restore opens no store at all, because it only reads.

**An answer this device cannot read is declined rather than guessed at.** A place in the order
counts from one and a write that produced content is named by a revision, so a removal's place and
nought are not where a write of the bundle can be. A place behind one this device has already read
is a service that has gone back, and one place under two names is a history that forked. So is one
place read twice with different content: a place names one content, so the store refuses the second
reading and keeps the bundle it authenticated there. A place in another history than the one the
store holds is refused before any place in it is compared (`RecoveryError::BundlePutBack`): after a
restore, a place further on need not hold what this device wrote before it. An applied
write is held to one thing more: it has to move the bundle on, because every applied write takes
the next place in the order, so an answer that stands still is a service saying it wrote and did
not write. A read of that same place is ordinary, which is why the two are checked apart. Each is
its own refusal, and none of them becomes the position the next write compares against. The way out
is the plain one: read the bundle from a store with no history of its own, and judge what comes
back.

**Where the bundle is stored is part of its key.** The encryption key mixes the seed with the
origin and the locator, so a bundle served from somewhere else does not authenticate. A migration
is therefore a deliberate re-encryption rather than a copy: `migrate` is given the destination's own
service client, writes the bundle there, reads it back from *that* service, checks that what came
back is what went in, and only then produces the updated kit and the record. The updated kit names
the destination and nothing else, because a kit's origins share one locator and an origin left
behind would point at a bundle this migration did not move. An owner with several services migrates
each one and keeps the kit each migration produced.

The copy at the old location stays there, because this seam publishes and fetches and does not
delete, and because removing a bundle before its owner has the new kit in hand would be a migration
that lost what it was moving. `MigrationRecord::describe` says exactly that: keep the updated kit
and destroy the old one, which still opens the superseded copy.

**Everything that can be checked is checked before anything is written.** The kit has to be the one
this bundle belongs to - this origin, this locator, this recovery seed - and the bundle at the old
location is read again and has to be the one the caller is holding, so a write another device made
in between is a conflict rather than a migration that quietly moves an older writer set. A kit that
names another seed is refused outright, because the updated kit is built from the seed and handing
back a kit the owner's existing archives were never wrapped for would be losing them. The kit the
migration would hand back is rendered before the write as well: a destination whose locator cannot
be printed, or whose kit is larger than a scannable code, is a bundle moved somewhere its owner
could keep no kit for.

Reading the old location again is a freshness check, not only an authentication one. Authentication
says who could have written the ciphertext and never how long ago, so a service that serves a
revision this device has already seen superseded is serving a replay. The revision this store knew
is held against what comes back, and a source that has gone backwards is a conflict rather than a
migration that drops the writers enrolled in between.

What cannot be checked first is the write itself, so a migration is **not** atomic and does not
claim to be: a destination that takes the bundle and then fails to serve it back leaves the new
location populated while this store stays where it was. The caller's bundle is untouched in that
case, which is what makes reading the old location again and trying once more a valid retry rather
than a revision it can never commit. The destination object has to be cleared before that retry can
succeed, and there is no operation here that clears it.

A migration checks the destination store before it reads the old location. When both would refuse,
because the destination store has read a bundle there and the old location has moved on, the caller
gets `DestinationHoldsABundle`: no retry gets past that refusal, while reading the old location
again clears the conflict.

The other failure is a destination whose answer never came back, and `complete_migration` finishes
that one. The migration reported `BundleOutcomeUnknown` and its write may have landed, but migrating
again cannot finish it: the destination store will not write while that write is outstanding, and it
refuses once it has read the bundle there. Completion writes nothing. It asks the service about the
identity the destination's write went out under, which also ends that write, and it treats the
bundle at the destination as the migration's own only when two answers agree. The service must not
say the write was refused or never ran, and the bytes read back must be the ones the write sent, at
the place the service's receipt names. The place alone never decides it, because another writer's
bundle can sit at the very place this write would have taken, and an equal bundle does not either:
once the service no longer holds a receipt, the bytes are all that still name the write. Then it
checks what a migration checks, including that the old location still holds the bundle that was
moved, and hands back the record and the updated kit. Ask again and it answers the same way. A write
that never landed gives `MigrationDidNotLand` when nothing can be read at the destination, and the
move can then be made again, since nothing will land under that write's identity later.

### A fresh restore

A restore obtains service access through the configured retrieval policy - a managed account or a
service the owner runs - and then authenticates the bundle with the kit. They are two different
things, and the cryptography is what makes them different: the ciphertext that access reaches opens
only under the owner's own seed, so signing in gets a restore to the bytes and no further.
`ServiceAccess` is what the policy gave the device: the reader it reaches one origin through. Under
a managed account that is a `ManagedSyncService` presenting a token from an authorisation made for
the restore alone (`backup.restore`, with the identity and refresh scopes); under a service the
owner runs it presents the credential the owner's own deployment issued. `FreshRestore::open_bundle`
reads only through it and refuses before the policy has given access, and the service decides what
the reader reaches: a reader it does not admit reads nothing, so holding a `ServiceAccess` proves
nothing by itself.

Substituting the origin or the locator fails authentication. A kit will not even build a context
for an origin it does not name, and a bundle written at one origin does not open under the key
another derives. It does not fall back to anything, and in particular it does not fall back to a
writer key an archive supplied: `TrustedMaterial` carries the writers the bundle named, and nothing
in a restore reads a writer key out of an archive at all.

What a restore puts back is decided by `kr_crypto::backup`'s table, so a device and a host give the
same answer: session data, device configuration and generation checkpoints come back, and reusable
endpoint and control-signing private keys, the notification extension's preview key, the recovery
seed, a settings collection's key, this host's grant and revocation authority and any grant that
had been revoked do not, each with its reason rather than as a silent omission.

The table classifies material a caller names. It is the decision, not the gate: the archive layer
below it carries opaque bytes, so a caller that wrote a private key into a member object and never
asked the table about it would get that object back. The gate is each export and import path
asking the table for every kind it carries; the settings path below is one. A restored device
still has no host access either way: it requires fresh owner-authorised pairing, and it never
creates remote-control authority.

### Settings after a restore

`recovery::export_settings` and `recovery::import_settings` are how a device's settings go into a
recovery-enabled archive and come back out of one. The export reads the settings object from the
device's sync store, to be carried under `recovery::SETTINGS_FILENAME`. It is refused while privacy
mode is on, because privacy mode stops backups as it stops sync, and it names the privacy generation
it was read under, so the archive is published only while that generation holds. The import asks the
table about whatever the archive says a member is, takes device configuration and nothing else, and
reads the bytes as a settings object.

A restore gives back the settings, with their values and pinned labels, as the restored device's
own. It never gives back:

* a settings collection's key, at any epoch. The recovery seed opens the archive, so a key inside
  it would be a way into the collection for anybody holding the seed;
* the collection's key records, or the old device's membership of the collection. Who may read the
  collection is authority, and restored settings cannot overwrite authority;
* a note of where the settings stood on the sync service. The restored device is a new
  installation, so the note would describe a place its copy never reached; its first publication
  compares against nothing and learns from the service where the settings stand.

An import never writes over settings the device already holds, or beside a note of where they stood:
choosing between two versions of the settings is the person's, not the last writer's.

So a restored device syncs nothing until it is a member again, exactly as a new device would be.
The owner pairs it with a host again under a grant that manages the host, a member shares the
collection with it, and the owner confirms the join on the restored device. Its keys are new, since
no reusable key is backed up, so the records that listed the device it replaces give it nothing. The
lost device is revoked at the host and a member rotates it out. With no member left, the owner starts
a new collection on the restored device, with the restored settings.

The seed comes from the kit or from a device's secure store. Those are the two, and a service is
not one of them, so an account password reset returns an account and nothing else.

### The settings archive

`recovery::SettingsArchive` takes a device's settings to a service as a recovery-enabled archive.
Each generation is one member, the export carried under `SETTINGS_FILENAME`, sealed by
`kr_crypto::backup` with the manifest key wrapped for the recovery recipient, so the kit alone opens
it. The device uploads the member and the encrypted manifest through a storage client and then
publishes the descriptor through a manifest client, both built for the generation from the
`ArchiveServices` it is given and both signed by the writer. They present the account token for
`backup.write`, and the sign-in that turns recovery-enabled backup on is the only one that asks for
it.

`SettingsArchive::enable` puts the bundle first. One bundle write names the archive's collection,
the producer whose wraps a restore opens and the writer a restore verifies against, and the writer
is enrolled at the manifest service only after that write has landed; a write that does not land
enrols nothing. A `SettingsArchive` holds the `WriterEnabled` evidence, so no generation is published
by a writer a restore with only the kit could not verify. A device that enabled its writer before
takes the archive up again with `SettingsArchive::resume`, which reads the bundle from the service,
authenticates it and holds the archive to the collection, the producer and the writer that bundle
names, since a restore finds and opens nothing else. A bundle the device changed and could not
commit counts for nothing.

The export refuses while privacy mode is on, before anything is sent. After that, every request of
the generation leaves through one transport that reads the device's privacy state at the moment it
is handed the request, which is once the request's account token is in hand and it is signed. A
fence, or a privacy generation that has moved on, that lands at any moment before then keeps that
request on the device, and every request after it; an upload it stops is abandoned at the service.

Before an object leaves, its identity is written down in the directory the device keeps its
recovery state in, and a generation whose publication is answered is struck off. What stays listed
across a restart, `SettingsArchive::unsettled`, is every generation whose objects may be at the
service without a publication the device saw answered, so they can be shown and removed; one whose
publication was sent without an answer is among them, so the manifest is asked before anything it
names is removed. A collection deleted from the account console refuses the upload or the
publication with a message that says to enrol a new collection. A generation that fails part-way is
made again as the next generation, under new keys.

## Requirement rows

| Row | What this library does for it |
| --- | --- |
| KR-REQ-04.23 | The local path is a socket and the remote path is iroh, behind one seam, so a caller chooses a host rather than a transport |
| KR-REQ-04.19 | The JSON representation as this library reads it: every managed-service answer goes through `services::json`, which refuses one that names a member twice at any depth, two spellings of one name included (`a_text_that_names_a_member_twice_is_refused_at_any_depth`), and a walk of the service modules fails when one of them decodes answer text any other way (`nothing_but_this_reader_decodes_the_text_of_an_answer`, both in `crates/kr-client/src/services/json.rs`). Each client is held to it: `a_success_that_names_its_recovery_twice_is_not_one_this_client_reads`, `a_lease_answer_that_names_a_member_twice_is_an_unknown_outcome`, `a_session_answer_that_names_a_member_twice_is_not_a_call_this_client_reads`, `a_refusal_that_names_its_reason_twice_is_not_one_this_client_reads`, `a_token_answer_that_names_its_access_token_twice_is_refused` and `an_id_token_that_names_its_subject_twice_is_refused_and_hands_back_its_refresh_token`. The envelope `services::signed` reads carries nothing beside `ok` and its `data` or `error` (`an_envelope_that_carries_any_other_member_is_not_one_this_client_reads`) |
| KR-REQ-10.23 | A code pairs through the product client and a room, with the budget on disk, and the committed device reads its own `pair.status` over its authorised connection (`a_device_pairs_by_code_through_the_product_client` in `crates/kr-controller/tests/pairing_client.rs`, and through a room behind TLS in `a_device_pairs_through_a_room_behind_tls`). A host's confirmation tag with one bit flipped ends the attempt ambiguous before anything is trusted (`a_host_tag_that_does_not_verify_ends_the_attempt_before_anything_is_trusted`) |
| KR-REQ-10.27 | The candidate's room socket, its TLS verification and its frames (`crates/kr-client/tests/pairing_room.rs`), what each way a room can fail is called (`crates/kr-client/tests/pairing_failures.rs`), and `pair.finish` bound to the peer the connection authenticated (`the_finish_is_bound_to_the_endpoint_the_client_authenticated`) |
| KR-REQ-10.36 | `a_device_pairs_directly_through_the_product_client`: a direct invitation redeemed over iroh and committed. In `a_direct_redemption_proves_nothing_to_the_wrong_host_and_shows_no_wrong_value`, a secret with one bit flipped is refused and locks nothing, and no proof goes to a host the invitation did not pin. `a_device_waits_inside_the_hosts_request_budget_for_an_owner_who_takes_their_time` waits nearly a minute for the owner inside the budget a host serves an unpaired connection by |
| KR-REQ-10.37 | The value both devices show is computed on the device and shown grouped only when the host's answer agrees (`a_finish_answered_with_another_value_shows_no_value`, `a_direct_redemption_proves_nothing_to_the_wrong_host_and_shows_no_wrong_value`) |
| KR-REQ-10.38 | One invitation format: what `pair.invite` issues reads back in this reader in both modes (`the_hosts_invitation_reads_back_in_the_companion_reader`), and `crates/kr-client/tests/pairing_invitation.rs` reads the payloads `fixtures/pairing/codes.json` publishes and refuses everything else |
| KR-REQ-10.46 | `services::authority` carries the durable authority feed, and the seven legs in `tests/integration/sync/tests/authority.rs` hold a live deployment and this client's feed record to the retention, validation, revision, acknowledgement and staleness rules together |
| KR-REQ-10.47 | `sync::StoredCollectionKeys` keeps a collection key in the operating system's credential store, or in the owner-only directory section 10 offers in its place. The `crates/kr-client/src/sync/keys.rs` tests check that directory on Unix, directory and files both, which is where those modes mean something; the credential store itself is `a_key_kept_in_the_platform_store_is_read_back_from_it_and_taken_away_again`, which writes one item named for the run and takes it away again. An ordinary run leaves it out as ignored, and a run that includes it with `--ignored` also sets `KR_TEST_PLATFORM_SECRET_STORE=1`, without which it fails before it writes, because on a person's own machine that store is their login keyring |
| KR-REQ-11.46 | The controls a client offers, and what each one does to a session |
| KR-PERF-006 | The client's own share of a reconnect: it holds no work of its own between a host's answer and a screen a terminal can draw. What the attach and the host spend is theirs |
| KR-REQ-17.14 | A session, a draft and a control need no managed service, and none of them changes when one is configured |
| KR-REQ-17.40 | The report of an exhausted relay: a new connection that a relay on its route turned this device away from fails as that refusal, with the relay's kind of refusal, its words and what may still work, while established and direct connections carry on (`an_exhausted_relay_is_the_reported_reason_a_new_connection_fails` in `crates/kr-controller/tests/network.rs`; each kind, the route and the direct paths in `crates/kr-transport/tests/relay_refusal.rs`) |
| KR-REQ-23.57 | The retry rules: which classes of request may be retried automatically, and what a person is offered for the rest. A gateway's 502 or 504 on a request that may have run is an unknown outcome and is never sent again: `kr_req_23_57_a_gateway_that_lost_an_exchange_or_a_refresh_leaves_its_outcome_unknown` for the account service's code exchange and refresh, `kr_req_23_57_a_gateway_that_lost_a_starts_answer_leaves_the_creation_unknown` for a voice start, and `kr_req_23_57_a_gateway_that_lost_a_deletion_or_an_authority_request_leaves_its_outcome_unknown` for the signed calls that are not safe to send again, each with the service's own refusal on a 502 and the calls that are safe to send again as its controls |
| KR-REQ-23.21 | A chunk never shares the control connection: it travels on its transfer's attachment-chunk lane at the attachment bound, under that connection's own window (`a_full_chunk_travels_on_the_lane_under_the_window_the_host_renewed` and `a_lane_refuses_another_transfers_chunk_before_sending_it` in `crates/kr-client/tests/chunks.rs`) |
| KR-REQ-14.12 | An upload whose lane drops resumes from `upload.status` under its identifier and sends only what the host is missing (`the_driver_resumes_from_the_status_bitmap_after_its_lane_drops`); a plan that holds a transfer starts from status and publishes nothing twice (`a_plan_that_holds_a_transfer_starts_from_status`); a reservation without a definite answer is never made again, whether its reply was lost, the host could not report it, a receipt alone settled it or the call was abandoned (`an_uncertain_reservation_is_never_reserved_again` and the tests beside it), all in `crates/kr-client/tests/chunks.rs`. Against the controller itself: `an_upload_resumes_from_status_after_its_chunk_connection_drops` in `apps/companion/src-tauri/tests/transfers.rs` |
| KR-REQ-14.16 | The client's check of each downloaded chunk: bytes that do not match their descriptor, and a descriptor other than the one `download.begin` gave, are refused (`a_downloaded_chunk_that_is_not_the_one_described_is_refused` in `crates/kr-client/tests/chunks.rs`) |
| KR-REQ-12.31 | The companion's drop goes through this library's upload: four full chunks and a remainder reach a verified handle whose bytes read back chunk by chunk and whole, against the controller on the same machine (`a_dropped_file_of_several_full_chunks_reaches_a_verified_handle` in `apps/companion/src-tauri/tests/transfers.rs`) |
| KR-REQ-26.14 | No inherited variable chooses what this library's clients trust or which proxy they go through. The service client and the room socket refuse a server that only a store named by `SSL_CERT_FILE`, `SSL_CERT_DIR` or both vouches for, as they do with neither set (`no_certificate_variable_chooses_what_a_client_trusts` in `crates/kr-client/tests/trust_store.rs`); a client from `client_builder` reaches its server directly while the proxy variables name another (`no_proxy_variable_moves_a_client_this_product_builds`), and the service client goes through the proxy its caller names and not around it (`crates/kr-client/tests/proxy_selection.rs`); a host's room socket opens through its proxy as a tunnel, and a proxy that refuses or cannot be reached ends the attempt (`crates/kr-client/tests/pairing_room.rs`) |
| KR-REQ-24.13 | A draft outlives its attachment, its connection and another device's write, and is never replaced by remote content. A draft settled after its answer was lost is still never submitted, and neither is a draft whose collection was put back, which is kept beside the restored one (`a_draft_outlives_its_attachment_its_connection_and_another_devices_write` and `a_draft_whose_collection_was_put_back_is_kept_beside_and_never_submitted` in `crates/kr-client/tests/session.rs`). A draft publication whose collection was put back from an archive that held no draft is never attempted again under its identity (`a_draft_whose_collection_was_put_back_empty_is_never_attempted_again_under_its_identity`), while a collection that holds nothing in the history this device reads moves nothing (`an_empty_collection_in_the_history_this_device_reads_moves_nothing`), both in `crates/kr-client/tests/sync.rs` |
| KR-REQ-20.13 | Per-object revisions and compare-and-swap writes, a lost comparison kept beside rather than resolved by a clock, the person's choice leaving no copy on the device or the service, the settlement of a write whose answer was lost through the request's own identity, for a draft as for a setting, the closed kind set that no restore can reach host authority through, and drafts that stay drafts. Across a restore: a note in one history meets its collection put back in another and follows it, while a service that went back within one history is still refused (`a_note_in_one_history_meets_its_collection_put_back_in_another_and_follows_it`, `a_service_that_went_back_in_its_own_history_is_still_refused`); a fetch from a collection put back keeps both versions and writes nothing away (`a_fetch_from_a_collection_put_back_keeps_both_versions_and_writes_nothing_away`); an answer from a history the collection was put back from moves nothing (`an_answer_from_a_history_the_collection_was_put_back_from_moves_nothing`), all in `crates/kr-client/tests/sync.rs`; and every answer's recovery identity is read and required, once (`every_answer_names_the_history_its_places_are_in` and `a_success_that_names_its_recovery_twice_is_not_one_this_client_reads` in `crates/kr-client/src/services/sync/tests.rs`). A fetch that finds its collection put back empty follows it into the history the restore began and frees the next publication (`a_fetch_that_finds_its_collection_put_back_empty_follows_it_and_frees_the_next_publication`), and an empty collection moves nothing in a history already put back from or for a fetch made before the device moved on, and takes a note left in the history it replaced (`an_empty_collection_in_a_history_already_put_back_from_moves_nothing`, `an_empty_collection_answering_a_fetch_made_before_the_device_moved_on_moves_nothing` and `an_empty_collection_in_the_history_this_device_reads_takes_a_note_left_in_the_one_it_replaced`), all in `crates/kr-client/tests/sync.rs`; a locator put back without its bundle is refused as a bundle put back (`a_locator_put_back_without_its_bundle_is_refused_as_a_bundle_put_back` in `crates/kr-client/tests/recovery.rs`). The legs in `tests/integration/sync/tests/sync.rs` hold a live deployment to the same rules through `services::sync`, with two client stores under one installation, and hold a deployment never put back to naming no history, a fetch of an object never published included (`kr_req_20_13_a_fetch_of_an_object_never_published_answers_its_absence_under_no_history`) |
| §24 privacy | The fence, the cancellation, the removal, the pinned-label rule, a publication in flight when privacy mode is enabled, a draft's as well as a setting's, work whose caller walked away staying outstanding, and the settlement of a dispatch whose answer was lost: applied, refused, and a request the service holds no receipt for, which stays counted under the generation in force and is ended at the service once privacy mode has moved past it, keeping the account of what left wherever the service cannot establish that nothing ran. Across a restore, a request attempted before its collection was put back is ended at once with its account kept (`a_request_attempted_before_its_collection_was_put_back_is_ended_at_once_and_keeps_its_account`), and a refusal before the service's cutoff ends the attempt with its account kept and holds the barrier while an attempt signed later could still run (`a_refusal_before_the_cutoff_holds_the_barrier_while_an_attempt_signed_later_is_on_its_way`). A client fenced by privacy mode sends a live deployment nothing (`kr_req_24_28_a_client_fenced_by_privacy_mode_publishes_nothing_and_keeps_its_pinned_labels`). Turning the generation on is the host's, and this client is one subsystem of it |
| KR-REQ-24.28 | The settings-sync client's part. An empty collection whose answer arrives after privacy mode fenced the generation it was asked under writes nothing, not even the history it names: a setting's fetch and a draft's are told the result is late, and a publication whose refusal was settled before the fence is told its result was discarded (`an_empty_collection_read_after_privacy_mode_moved_on_writes_nothing` in `crates/kr-client/tests/sync.rs`). A draft publication in a collection put back empty is ended with its account kept (`a_draft_whose_collection_was_put_back_empty_is_never_attempted_again_under_its_identity`), and a client fenced by privacy mode sends a live deployment nothing (`kr_req_24_28_a_client_fenced_by_privacy_mode_publishes_nothing_and_keeps_its_pinned_labels`). The rest of the row, the work in flight and what privacy mode reports, is the host's and its workers' |
| KR-REQ-18.05 | The encrypted settings sync part only: the service holds ciphertext in a declared size bucket and never a setting, against a live deployment as well as the suite's own service (`kr_req_18_05_a_setting_is_stored_sealed_in_a_declared_bucket`), and the feature names its three parts and which of them are optional. A device receives a collection key only through its own wrap in a record it accepted, and only after its hosts committed its pairing and the owner confirmed the addition and the join (`a_production_device_receives_its_key_through_its_own_wrap_and_keeps_it_in_its_store`, `nothing_is_sealed_to_a_device_its_host_has_not_committed` in `crates/kr-client/tests/membership.rs`, against the suite's own service and hosts). Across a restore, a device follows a collection put back only from the head it holds and is otherwise out until the owner confirms a join (`a_collection_put_back_without_the_head_this_device_holds_leaves_it_out_until_a_join`, with its control `an_older_revision_in_the_same_history_leaves_the_head_standing`, in the same file). The backup part, for a device's settings: they go to the service as a recovery-enabled archive only while privacy mode is off, and a generation read under one privacy generation is not published under another (`privacy_mode_on_refuses_the_settings_archive_before_anything_is_sent`, `privacy_mode_turned_on_while_a_token_is_fetched_keeps_that_request_on_the_device` and `a_privacy_generation_that_moved_refuses_the_publication_and_what_was_stored_stays_listed` in `crates/kr-client/tests/settings_archive.rs`). Backing up session history is the host's |
| KR-REQ-20.11 | The sync-collection half: removing a device gives the members that stay a fresh key at the next epoch that the removed device has no wrap of, and publication stays fenced until that record is installed (`removing_a_device_gives_the_rest_a_key_it_cannot_open`, `every_new_epoch_has_a_freshly_drawn_key`, `publication_stays_fenced_from_a_recorded_removal_until_its_record_is_installed` in `crates/kr-client/tests/membership.rs`, and the reconciler's exhaustive test in `crates/kr-client/src/sync/membership/exhaustive.rs`) |
| KR-REQ-20.14 | `a_kit_round_trips_through_its_printable_and_scanned_forms`, `the_printed_kit_is_the_document_the_fixture_publishes`, `a_mistyped_kit_fails_on_its_checksum_before_anything_is_derived`, `a_kit_read_by_hand_forgives_the_letters_the_alphabet_leaves_out` and `a_kit_value_whose_spacing_would_change_when_read_is_refused` in `crates/kr-client/tests/recovery.rs`, with `fixtures/crypto/kdf.json` and `fixtures/crypto/recovery-kit.json` |
| KR-REQ-20.15 | `a_writer_is_declared_recovery_enabled_only_after_its_bundle_has_landed`, `a_writer_whose_bundle_did_not_commit_is_not_declared`, `rotating_a_writers_key_replaces_it_in_one_commit` and `a_verified_generation_never_moves_backwards` in `crates/kr-client/tests/recovery.rs`. They establish the ordering and what the bundle holds. The declaration to a *service* is the collection's enrolment record, and the device's settings writer is enrolled only after the bundle naming it has landed, while a bundle that does not land enrols nothing (`the_settings_writer_is_enrolled_only_after_the_bundle_naming_it_has_landed` in `crates/kr-client/tests/settings_archive.rs`). Through the managed client, against a service kept to the managed service's contract, a writer is declared only once its bundle has landed at the locator (`a_bundle_is_written_and_read_at_its_locator_with_the_account_token_beside_every_request` in `crates/kr-client/src/services/sync/tests/bundle.rs`) |
| KR-REQ-20.16 | `a_restore_with_only_the_kit_reaches_the_archive_and_trusts_only_the_bundles_writers` in `crates/kr-client/tests/recovery.rs`, which drops every producer value before the restore and takes the producer key out of the authenticated bundle; through the managed client, a bundle served under another locator or read as another origin's, or under another seed's kit, trusts no writer (`a_bundle_served_under_another_locator_or_origin_fails_authentication` in `crates/kr-client/src/services/sync/tests/bundle.rs`) |
| KR-REQ-20.17 | The table's answers: `the_material_table_refuses_a_reusable_key_and_a_revoked_grant` and `the_admitted_set_is_data_and_configuration_and_the_limits_still_require_owner_pairing` in `crates/kr-client/tests/recovery.rs`. The settings part, through the export and import paths that ask the table: `a_collection_key_is_neither_backed_up_nor_restored`, `a_restore_returns_settings_without_a_key_a_membership_or_a_sync_checkpoint` and `a_restored_device_joins_only_after_a_fresh_authorisation` in `crates/kr-client/tests/membership.rs`, which carry the settings through an archive only the recovery recipient opens. The device's archive producer carries them the whole way: `recovery::SettingsArchive` seals the export as one member for the recovery recipient, uploads it and publishes it, and a new device holding only the kit and the account brings the settings back as its own through `import_settings` (`the_settings_go_out_as_an_archive_and_come_back_with_only_the_kit` in `crates/kr-client/tests/settings_archive.rs`, against a service kept to the managed service's contract) |
| KR-REQ-20.18 | `a_migration_produces_an_updated_kit_and_a_verified_record` and `one_kit_serves_several_services` in `crates/kr-client/tests/recovery.rs`. The offline-export half is `the_encrypted_bundle_and_selected_archives_export_offline` in the same file, over the library's own `OfflineExport`: the encrypted bundle and the selected archives' ciphertext in one canonical document, which restores without a service. The bundle's path to a managed service: its locator and the claim a first write makes, the race between two writers and a lost write ended under a new token (`two_writers_of_one_account_race_and_one_is_told_the_bundle_moved_on`, `competing_first_claims_leave_one_owner_and_every_other_account_meets_an_absent_bundle`, `a_first_write_that_did_not_apply_claims_nothing`, `a_fence_made_before_the_claim_survives_it`, `a_lost_write_is_ended_under_a_new_token_and_after_a_restart`), and a write that never left (`a_write_refused_before_it_was_sent_leaves_the_store_as_it_was_and_the_next_write_goes_out`, `a_migration_refused_before_it_was_sent_leaves_both_locations_as_they_were`, `a_bundle_over_its_bound_is_refused_before_anything_is_recorded_or_sent`), all in `crates/kr-client/src/services/sync/tests/bundle.rs`, with `a_write_refused_before_it_was_sent_is_reported_so_and_leaves_the_store_as_it_was` and `a_record_the_disk_would_not_take_back_leaves_an_unsent_write_a_restart_ends` in `crates/kr-client/tests/recovery.rs` |
| KR-REQ-20.19 | `service_access_alone_does_not_decrypt_the_bundle` and `substituting_the_origin_or_the_locator_fails_authentication` in `crates/kr-client/tests/recovery.rs`. Through the managed client: a device with only the kit reads the bundle through the access its policy gave it and reaches nothing without it (`a_device_with_only_the_kit_reads_the_bundle_through_the_access_its_policy_gives_it`), and a service put back without the bundle is refused as a bundle put back (`a_service_put_back_without_the_bundle_is_refused_as_a_bundle_put_back`), in `crates/kr-client/src/services/sync/tests/bundle.rs`; the restore's own authorisation holds a token for `backup.restore` and for no other resource (`a_restore_authorisation_holds_a_token_for_its_scope_and_for_no_other` in `crates/kr-client/src/services/account.rs`) |
| KR-REQ-20.12 | The client's half of a generation's publication: the writer's signature over the descriptor, carried by the writer's own key with the account token beside it; the same publication sent again answered as a duplicate and other content for a generation already published refused; a fetch that answers with the publication exactly as it was published, and with nothing for a generation the service does not hold (`the_backup_manifest_enrols_publishes_and_fetches_as_the_service_answers` and `a_publication_sent_again_is_a_duplicate_and_other_content_for_it_is_refused` in `crates/kr-client/tests/storage.rs`). A settings generation a device published is fetched by a new device and opened against the writer the bundle names (`the_settings_go_out_as_an_archive_and_come_back_with_only_the_kit` in `crates/kr-client/tests/settings_archive.rs`) |
| KR-REQ-20.22 | The client's part: backup storage is off until it is turned on, against the revision a status read names; a status read reports what is stored, what is deleted and not yet removed, what open uploads hold and the retention the service applies; and a deletion is a tombstone the service still charges until it removes the ciphertext (`each_storage_method_is_answered_as_the_service_answers_it` and `each_storage_method_meets_a_refusal_the_service_sends` in `crates/kr-client/tests/storage.rs`). The snapshots kept, the removal after seven days and the provider's bound are the service's |
