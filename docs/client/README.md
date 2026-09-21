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
compare and swap on the position this device last saw, which is kept beside the draft and is *not*
the draft's own revision: a draft edited three times offline is at revision four and has still only
been published once. What goes to the service is the record the store holds, read together with that
note under one hold of the lock, so a caller cannot publish text this device does not have and
cannot send an older revision against a position another publisher has just advanced. A note that
already names a later write stands, so an answer that arrives late does not undo what a fetch
has already learnt. A refused comparison is an answer rather than a failure: what the service holds
comes down **beside** the local draft under a fresh identity, never over it, and the person chooses.
Reconnecting never replaces their text.

Every exchange carries an identity for the request itself, which is what a service answers about
afterwards. This half sends a fresh identity per attempt. It keeps no record of a publication it
has sent, so it has nothing to present a second time and every call is a first attempt, and an
answer it loses is one nothing later establishes: the settlement below is the settings half's.

Sealing goes through `drafts::DraftSealer`. `sync::CollectionSealer` is the implementation this
crate carries; a client that seals differently supplies its own.

## Settings sync

`sync` is the other half of what a synchronisation service carries. Drafts travel through
`drafts::DraftSync`; settings and a client's own position travel through `sync::SyncClient`, under
the same compare-and-swap discipline and the same sealing seam.

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
- A note naming a write a reset or replaced service no longer holds does not resolve itself.
  `SyncStore::forget_checkpoint` is the explicit recovery, and nothing does it automatically,
  because a note that looks stale and is not is a note whose object another device has just written.
  Two answers are provably wrong rather than merely surprising, and the refusal says which: a
  service answering with a write sequence *below* the one the note names has gone back behind what
  this device already saw, and one answering with another name for the same place in the order
  holds a history that forked. One this device could not reach at all is reported as it came,
  because absence and unreachability are not the same answer.
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
- A fence is about the future, and about the past only while a receipt would still have been there
  to find. It always ends the request, because nothing executes under a fenced identity, so the
  barrier releases either way. What it says is that the service holds no outcome for the identity,
  and a receipt swept after its thirty days says exactly what a request that never arrived says. So
  this device measures the interval itself, between the instant its own record says the content
  left and its own clock now. Inside the retention, less a day for the sweep, the request provably
  never ran: nothing of it is anywhere and its record goes. Past that, or on a clock that has gone
  backwards, the ciphertext may be on the service, and the record stays as the account of what left
  with no content in it. `exported` names it, and deleting it because this device could not tell
  which had happened would hide an upload rather than undo one.
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

`sync::StorageFeature` names the three parts of what section 18 offers: encrypted settings sync,
which is this module; history backups; and recovery material, which is what a restore without
another device needs. The last two are optional, which is what sections 18 and 20 call them, and
each part carries what a person does without it.

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

### Privacy mode

The host records a privacy generation and drives every subsystem through the same four steps. This
client is one of those subsystems, in plain methods that take the generation as a number, because a
client never depends on a host crate:

| Method | What it does |
| --- | --- |
| `fence` | Stops production at the generation. A publication after it is refused. |
| `cancel_undispatched` | Discards the ciphertext of every request that was admitted and never sent, reconciles what had already been dispatched and counts whatever the service could not account for. It reports what that reconciliation established as well as the total. |
| `remove_retained` | Removes the conflict copies, the checkpoints and the work that never left, and reports the bytes and records it actually deleted. It reconciles afterwards, so the ciphertext of a request nothing can account for goes as well. Work admitted under a later generation is another cleanup's. |
| `reconcile_unsettled` | Asks the service what became of every dispatch this device has no answer for, under the identity each request carried, and settles it. A service that cannot be asked leaves the work counted rather than failing the step. |
| `outstanding` | How many dispatched publications have no settled outcome, read from the durable records rather than from what is running. An abandoned call, a failed connection and a restart all leave one counted, and a record this build cannot read counts too. Cleanup is complete when it is nought, and it reaches nought after a lost answer because the two cleanup steps reconcile before they measure. |
| `kept` | What stays, and why: the device's own settings, the labels the person pinned, and the record of what has already been published. |
| `exported` | What has already left, shown rather than claimed to be erased: a write the service accepted after the fence, a refused write the service kept a copy of, a dispatch nothing has established the outcome of, and a request ended too late for a receipt to say whether it ran. Suppressing a result does not undo an upload. None of it is deletable from here, because a compare-and-exchange store takes a replacement and not a deletion. |
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

## Managed services

`services` holds one trait per managed service section 17 names (account login, relay leases, push,
encrypted sync and backup, managed inference), and `ServiceClients` holds one optional
implementation of each. `services::relay` is the relay-lease client, because a lease is the one
managed resource a client cannot do without and still use a relay at all, and `services::voice` is
the voice broker. `services::authority` carries the durable authority feed, where a remote owner
publishes a signed revocation request and the host that owns the feed acknowledges what it applied,
and `services::mailbox` carries the encrypted mailbox. Both sign through `services::signed`, which
is the one credential every method of the section 23 `Services` group is proven by: the gateway
origin, the method, a fresh nonce, the time and the digest of the canonical request body.

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
an answer past it is refused rather than truncated. It follows no redirect, keeps no cookie, asks
for no compression and finds no proxy of its own.

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

`services::SyncBackupService` is the sync and backup trait: a compare-and-exchange over opaque
bytes where every exchange names the request as well as the object. An exchange is answered with
`Applied`, carrying the position the service put the write at, or with `Refused`, because a refusal
is an answer and not a failure, and `Refused` names what the service kept of the rejected write.
`request_status` answers about that request afterwards, from the receipt and never from what the
collection holds now, adding `Unknown` for a request the service holds no receipt for and `Fenced`
for one it will never execute. `fence_request` is how a caller reaches that last answer: it never
says it does not know, so a request can always be ended. What a fence establishes about the past is
bounded by how long the service keeps a receipt, so the trait states that retention as
`SYNC_RECEIPT_RETENTION_MS` and `fence_proves_it_never_ran` is the question a caller asks of its own
clock; an implementation over a service that keeps receipts for a different time owes its caller a
check that the two agree.

The trait states what an implementation owes. The order is the service's: every applied write takes
the next place in its collection's order, from a counter the service keeps, because numbers assigned
as answers arrive describe the order they arrived in. A receipt is history, so an applied receipt
names the position that write produced however far the object has moved since. A position is absent
only when nothing is there. And a fence ends a request, which is what lets a cleanup finish.

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
compare-and-swap over opaque bytes at the locator. Three things follow.

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
read again and apply the change to what is actually there.

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

### A fresh restore

A restore obtains service access through the configured retrieval policy - a managed account or a
service the owner runs - and then authenticates the bundle with the kit. They are two different
things, and the cryptography is what makes them different: the ciphertext that access reaches opens
only under the owner's own seed, so signing in gets a restore to the bytes and no further.
`FreshRestore::open_bundle` also refuses before the policy has been satisfied, which orders the two
steps; `ServiceAccess` is the caller's own statement that its policy was met, so that ordering is a
guard against a caller skipping a step rather than a proof that the service authenticated anybody.

Substituting the origin or the locator fails authentication. A kit will not even build a context
for an origin it does not name, and a bundle written at one origin does not open under the key
another derives. It does not fall back to anything, and in particular it does not fall back to a
writer key an archive supplied: `TrustedMaterial` carries the writers the bundle named, and nothing
in a restore reads a writer key out of an archive at all.

What a restore puts back is decided by `kr_crypto::backup`'s table, so a device and a host give the
same answer: session data, device configuration and generation checkpoints come back, and reusable
endpoint and control-signing private keys, the notification extension's preview key, the recovery
seed, this host's grant and revocation authority and any grant that had been revoked do not, each
with its reason rather than as a silent omission.

The table classifies material a caller names. It is the decision, not the gate: the archive layer
below it carries opaque bytes, so a caller that wrote a private key into a member object and never
asked the table about it would get that object back. The gate is the caller's own export and import
paths asking the table for every kind they carry, and this library supplies the answer rather than
the paths. A restored device still has no host access either way: it requires fresh
owner-authorised pairing, and it never creates remote-control authority.

The seed comes from the kit or from a device's secure store. Those are the two, and a service is
not one of them, so an account password reset returns an account and nothing else.

## Requirement rows

| Row | What this library does for it |
| --- | --- |
| KR-REQ-04.23 | The local path is a socket and the remote path is iroh, behind one seam, so a caller chooses a host rather than a transport |
| KR-REQ-11.46 | The controls a client offers, and what each one does to a session |
| KR-PERF-006 | The client's own share of a reconnect: it holds no work of its own between a host's answer and a screen a terminal can draw. What the attach and the host spend is theirs |
| KR-REQ-17.14 | A session, a draft and a control need no managed service, and none of them changes when one is configured |
| KR-REQ-23.57 | The retry rules: which classes of request may be retried automatically, and what a person is offered for the rest |
| KR-REQ-24.13 | A draft outlives its attachment, its connection and another device's write, and is never replaced by remote content |
| KR-REQ-20.13 | Per-object revisions and compare-and-swap writes, a lost comparison kept beside rather than resolved by a clock, the settlement of a write whose answer was lost through the request's own identity, the closed kind set that no restore can reach host authority through, and drafts that stay drafts |
| §24 privacy | The fence, the cancellation, the removal, the pinned-label rule, a publication in flight when privacy mode is enabled, work whose caller walked away staying outstanding, and the settlement of a dispatch whose answer was lost: applied, refused, and a request the service holds no receipt for, which stays counted under the generation in force and is ended at the service once privacy mode has moved past it, keeping the account of what left when the fence came too late to say whether it ran. Turning the generation on is the host's, and this client is one subsystem of it |
| KR-REQ-18.05 | The encrypted settings sync part only: the service holds ciphertext in a declared size bucket and never a setting, and the feature names its three parts and which of them are optional. Nothing here performs a history backup or produces recovery material |
| KR-REQ-20.14 | `a_kit_round_trips_through_its_printable_and_scanned_forms`, `the_printed_kit_is_the_document_the_fixture_publishes`, `a_mistyped_kit_fails_on_its_checksum_before_anything_is_derived`, `a_kit_read_by_hand_forgives_the_letters_the_alphabet_leaves_out` and `a_kit_value_whose_spacing_would_change_when_read_is_refused` in `crates/kr-client/tests/recovery.rs`, with `fixtures/crypto/kdf.json` and `fixtures/crypto/recovery-kit.json` |
| KR-REQ-20.15 | `a_writer_is_declared_recovery_enabled_only_after_its_bundle_has_landed`, `a_writer_whose_bundle_did_not_commit_is_not_declared`, `rotating_a_writers_key_replaces_it_in_one_commit` and `a_verified_generation_never_moves_backwards` in `crates/kr-client/tests/recovery.rs`. They establish the ordering and what the bundle holds; nothing here declares a writer to a *service*, because that declaration belongs to the collection's enrolment record |
| KR-REQ-20.16 | `a_restore_with_only_the_kit_reaches_the_archive_and_trusts_only_the_bundles_writers` in `crates/kr-client/tests/recovery.rs`, which drops every producer value before the restore and takes the producer key out of the authenticated bundle |
| KR-REQ-20.17 | `a_backup_never_carries_a_reusable_key_and_a_restore_never_gives_back_a_revoked_grant` and `a_restore_puts_back_data_and_configuration_and_still_needs_fresh_owner_pairing` in `crates/kr-client/tests/recovery.rs`. They establish the decision the table gives, not an export path that consults it: no such path exists in this library yet |
| KR-REQ-20.18 | `a_migration_produces_an_updated_kit_and_a_verified_record` and `one_kit_serves_several_services` in `crates/kr-client/tests/recovery.rs`. The offline-export half is `the_encrypted_bundle_and_selected_archives_export_offline` in the same file, over the library's own `OfflineExport`: the encrypted bundle and the selected archives' ciphertext in one canonical document, which restores without a service |
| KR-REQ-20.19 | `service_access_alone_does_not_decrypt_the_bundle` and `substituting_the_origin_or_the_locator_fails_authentication` in `crates/kr-client/tests/recovery.rs` |
