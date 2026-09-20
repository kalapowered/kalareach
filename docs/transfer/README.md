# Transfer reference

How bytes get into and out of an execution environment, what a completed attachment is, and what an
adapter or a client can build on top. The code is `crates/kr-transfer`, hosted by the control daemon
in `crates/kr-controller/src/transfer.rs`; the wire types are `kr_protocol::transfer`.

One service does this for everybody. The command line, the desktop and mobile applications, an
adapter that needs a staged image, and anything else that speaks the protocol are all callers. There
is no graphical half.

```text
upload.begin ─▶ upload.chunk ─▶ upload.finish ─▶ attachment handle
       │             │               │                  │
       │             │               │                  ├─▶ agent.draft.add_attachment
       │             │               │                  │     then agent.prompt.submit
       │             │               │                  └─▶ download.begin ─▶ download.chunk
       └─────────────┴── upload.status ─── resume, or resolve a lost reply
```

There are four stages and four records. Transfer moves bytes. Storage publishes them as an
attachment. Insertion offers that attachment to an agent through its adapter. Submission is a
further action again. A failed insertion loses none of the three stages before it.

## The seven methods

| Method | Effect | What it does |
| --- | --- | --- |
| `upload.begin` | write | Reserves the declared size and returns the upload identity, the chunk layout, an empty received-chunk bitmap and an expiry |
| `upload.status` | read | Reports verified chunk status, and the published handle once there is one |
| `upload.chunk` | write | Accepts one chunk with its index, exact length and digest |
| `upload.finish` | write | Verifies the whole-file digest and size, then publishes the handle |
| `upload.cancel` | write | Cancels an unfinished upload and releases its reservation |
| `download.begin` | read | Opens an immutable source or stages a bounded immutable snapshot, and describes its chunks |
| `download.chunk` | read | Reads one chunk of that same snapshot, rechecking read authority first |

`draft.create`, `draft.update` and `agent.draft.add_attachment` are in the same method group and the
same service. `agent.prompt.submit` is not: submission goes to the worker that owns the session.

Every one of these returns an opaque identifier. None of them returns a client-supplied absolute
host path, and none accepts one.

## Limits

These are configurable resource limits, not subscription restrictions. A self-hosted owner changes
them; nothing in the protocol depends on the defaults.

| Limit | Default | Where it lives |
| --- | --- | --- |
| chunk size | 1 MiB | `kr_protocol::limits::UPLOAD_CHUNK_LEN`, fixed by the wire contract |
| one file | 2 GiB | `max_file_len`, per environment |
| staged bytes | 8 GiB | `max_staged_len`, per environment |
| concurrent transfers | 2 | `max_concurrent_transfers`, per authenticated principal |
| unfinished upload | 24 hours | `UNFINISHED_UPLOAD_LIFETIME` |
| unused attachment | 7 days | `UNUSED_ATTACHMENT_LIFETIME` |
| download snapshot | 24 hours | `DOWNLOAD_SNAPSHOT_LIFETIME` |
| one reply | 768 KiB encoded | `MAX_TRANSFER_RESULT_BYTES`, checked on `draft.create`, `draft.update`, `agent.draft.add_attachment`, the insertion outcome and the draft read, before each commits |
| one insertion detail | 4096 characters | `MAX_INSERTION_DETAIL_LEN`, on the evidence or the reason an adapter reports |

A submitted attachment follows its session's retention instead of the seven-day window, which is why
submission is recorded rather than inferred from age. The host tells the service which sessions its
retention still covers; the service never guesses. An attachment uploaded without a session takes
the draft's session when it is submitted to one, so the retention that applies is the session's
rather than the seven-day window that applied while nothing held it.

What the host currently answers with is the session registry: a session is covered while it has a
launch reservation in any phase, which includes failed and closed ones. That preserves files rather
than losing them, and it is deliberately the conservative direction, but it is not yet the session
retention policy the archive owns. Until the archive's retained-session state is the thing the
sweep asks, a submitted attachment can be preserved longer than that policy would keep it. The
service asks one question through one interface, so making the archive the authority is a change to
the answer and not to the sweep.

The environment's staged total counts three things together: receiving uploads at their declared
size, published attachments still on disk, and open download snapshots. A snapshot is storage this
environment spent, so it is charged like everything else. Reading a published attachment in place
charges nothing, because those bytes are already counted against the attachment that holds them.

A byte quota is `QUOTA_EXCEEDED`, which nothing retries into. The concurrency ceiling is
`RESOURCE_UNAVAILABLE`, because it clears when one of the caller's own transfers finishes.

The ceiling counts per authenticated principal, which is what identifies a device to this host: a
paired device's actor is that device, and a local caller's actor is the operating-system user. The
`device_id` a request carries is recorded as metadata and confers nothing, because a caller that
could change it per request would give itself another allowance.

Bytes stay charged until the payload they name is actually gone. Closing an upload's row marks it
for cleanup and keeps its reservation; removing the file releases it. A removal that fails, or a
daemon that dies between the two, leaves the row marked and the bytes charged, and the next
recovery pass retries it. That is why a staged total can include a cancelled upload for a moment,
and why it can never omit a file that still exists.

## Which stream a chunk travels on

A 1 MiB chunk does not fit a control frame. Section 23 gives it its own stream kind with its own
bound, 1 MiB of chunk data plus at most 4 KiB of metadata and framing, and says outright that the
larger bound cannot be selected on a control stream. So chunks have their own stream on both
transports.

On the network transport it is a data stream whose header declares `attachment_chunks` and names the
transfer, validated against the established control connection. On a local endpoint there are no
streams to multiplex, so the daemon listens on a second endpoint beside its control endpoint and
frames that connection at the attachment bound. The handshake, the peer-credential
authentication and the action windows are the control connection's, unchanged. The frame bound is
the only difference, and it is why the endpoint exists at all.

| Endpoint | Unix | Windows | Carries |
| --- | --- | --- | --- |
| clients | `<runtime>/<prefix>/c.sock` | `kalareach-<uid>-<prefix>-c` | every method whose frames fit 1 MiB |
| attachment chunks | `<runtime>/<prefix>/t.sock` | `kalareach-<uid>-<prefix>-t` | `upload.chunk` and `download.chunk` |

What travels is the same `ControlFrame` union both transports carry, so a chunk is an ordinary
mutation with an ordinary action window and an ordinary response. That is what keeps `upload.chunk`
inside the host's admission path rather than beside it. `kr_transfer::chunks::ChunkChannel` is the
client half; it replaces the window whenever the host renews one, so a long chunk sequence never has
to think about freshness.

The two endpoints carry disjoint sets of methods, and a caller that uses the wrong one is refused.
Without that the larger bound would also admit an oversized ordinary request that the control
endpoint would have refused, which would make the second endpoint a second admission rather than the
same admission at a second frame size.

Whoever runs the daemon binds both endpoints and owns the tasks that serve them. A listener has to
be released before the next daemon binds the same address, and only the owner of the task holding it
can release it at a known moment: an in-process restart releases both and binds them again, which
is what the restart test does.

## Storage layout

```text
<state>/environments/<prefix>/transfers/
  transfers.sqlite
  <32 random hexadecimal characters>/
    incomplete/   uploads still receiving chunks
    complete/     verified, published attachments
    snapshots/    immutable download snapshots
```

The staging directory is 0700 on Unix. On Windows it is created with a protected access-control list
holding one entry for the object's owner and one inherit-only entry that becomes an owner entry on
everything created beneath it, so inheritance from the user profile cannot widen it.

Incomplete files live in a different directory from completed ones. Nothing can read a partially
written payload as though it were an attachment, because a published handle names a file in the
completed area.

Payload files are created exclusively, without following links, mode 0600, and never with an
executable bit. The storage name comes from the transfer identifier in hexadecimal, plus at most a
validated extension taken from the original filename.

The extension rule is an allowlist, not a denylist. Section 14 permits a validated extension to be
retained for an agent that requires one, and the allowed set is the media, document, audio, video
and archive types an attachment is; the list is `PERMITTED_EXTENSIONS` in `staging.rs`. Anything
outside it keeps the bare identifier with no extension at all, which executes nothing on any
platform. Asking instead which extensions Windows can execute would be a list nobody can close.

Everything else about the client's name is metadata. Separators, traversal segments, reserved
device names and stream separators never reach the storage path.

The random directory name is not a secret and nothing depends on it staying unknown. It is there so
two installations, or an installation and a restored backup, never collide on a payload name, and so
a path guessed from a transfer identifier alone names nothing. What makes a staging area *this*
environment's is the object rather than the name: its stable filesystem identity is recorded the
first time it is opened, and a directory replaced at the same name afterwards is refused.

## The journal, and what makes a transfer resumable

`transfers.sqlite` runs in write-ahead-logging mode with full synchronisation and forward-only
migrations. Every state change commits together with the outbox row that announces it.

| Table | What it holds |
| --- | --- |
| `uploads` | one row per upload: the declaration, the reservation, the state, the verified digest, the payload's filesystem identity, whether a payload still has to be removed, and the preview |
| `chunks` | the per-chunk journal: index, exact length, digest and when it was written |
| `snapshots`, `snapshot_chunks` | download snapshots, their chunk layout and the source facts they were taken against |
| `scopes` | registered read scopes, with the stable filesystem identity each one was recorded for |
| `drafts`, `draft_attachments` | drafts, the attachments bound to them and what became of each offer |
| `grants` | narrow read grants over one attachment each |
| `actions` | retained mutation outcomes, keyed by actor and action identifier |
| `events`, `cursors` | the outbox and its consumers' positions |

The order the rows are written in is what makes a resume possible.

An upload row exists before a single byte is accepted, with its declared size already charged against
the environment's budget. A chunk row is written after its bytes are on disk and flushed, because a
row with no bytes behind it would let a later verification trust a hole; bytes with no row are simply
sent again, which costs one chunk.

Publication is two commits with a recoverable state between them, and the identity of the verified
object is what ties them together. The row moves to `publishing` carrying the device and inode (or
volume serial and file index) of the file the verification was made against, then the file is
renamed, then the row moves to `published`.

A daemon that dies in the middle finds the `publishing` row and resolves it by asking which name
holds *that exact object*: the published name means the rename landed and only the row was behind,
and the incomplete name means it did not and the verified bytes are still there to move.

Identity is the first question and not the last one. It is cheap, and it settles which of the two
names to look at, but it says only that the filesystem did not give this object a new identifier.
A payload rewritten where it lies keeps its identity, and a filesystem that hands a new file the
identifier a removal has just freed gives a replacement the same one. So the object is read back
and its digest compared with the one the verification recorded, and *that* is what decides. Bytes
that are not the verified bytes invalidate the upload: `invalidated`, the reason recorded on the
row, both payload names removed and the reservation released. The identifier is spent and a new
upload is required.

A row whose object is in neither place is invalidated the same way, because a handle whose file is
gone is not a handle. Both of those leave the row terminal, so one payload nothing can vouch for
does not stop the pass: the publications behind it are resolved in the same pass rather than
waiting for a start that would find the same payload again. What is reported instead of being read
as an answer about the payload is a failure that is not one: the journal, the storage, or the
staging directory no longer being the directory the service opened. Those stop the pass, because
none of them says what the staging area holds.

The directory that names a payload is flushed before the record that depends on it commits: after a
`create`, after the rename that publishes, and after each directory of the staging tree is created.
Without that a power loss could leave SQLite saying `published` while the rename was still only in
the page cache. The flush opens a descriptor of its own for the directory, because the handle this
service holds may be a reference to the directory rather than a file description, which is what
Linux gives for an ordinary directory open and refuses to flush.

On Windows there is no directory flush to make: the platform refuses one on a directory handle, and
a rename inside one volume is its own ordered metadata operation. So the ordering above is a Unix
guarantee, and what it leaves open on Windows is what the Windows qualification pass records. A retried `upload.finish` resolves a
`publishing` row the same way, so a caller does not have to wait for the next start to learn what
happened.

Cleanup is owned by the row, not by the caller that happened to close it. Closing an upload or a
snapshot marks it as still holding a payload, and the reservation is released only when the file is
actually gone. A removal that fails leaves the mark and the charge in place, and the next pass tries
again: a removal failure never turns into forgotten bytes.

Recovery at startup does three jobs, all idempotent. It resolves every interrupted publication as
above. It retries every payload whose row says the bytes are still there. And it reconciles the
three staging areas against the journal: every payload name is derived from a transfer identifier,
so a name no live row accounts for is a file an interrupted `upload.begin` created before its row
existed, and it is removed. The hourly sweep runs the same retry, so a removal that failed once does
not wait for the next start.

That is what makes the ownership contract true rather than merely stated. A worker's death
invalidates an insertion; it does not change the identity of a file this service already verified.

Every state change commits an outbox row with it, including the submission that moves an attachment
onto its session's retention. Consumers keep their own cursor in `cursors`.

## Integrity

Every chunk carries its index, its exact length and the SHA-256 digest of exactly those bytes.
Three rules follow.

Bytes that do not match their own descriptor are refused, and the upload survives. A transmission
fault is the caller's to retry.

A duplicate that matches what was recorded is acknowledged, and nothing is rewritten.

A duplicate that conflicts invalidates the upload. Two different byte sequences claimed the same
position, and nothing can choose between them without guessing, so the identifier is spent and a
new one is required.

`upload.finish` then reads the whole staged file back through its own handle and compares the digest
and the size against what `upload.begin` recorded. A mismatch invalidates the upload with
`ATTACHMENT_INTEGRITY`. This is also the check that catches another process under the same account
writing to the staged file, which the authority model does not exclude.

A `upload.finish` whose declared size or digest differs from the one `upload.begin` recorded is
`SOURCE_CHANGED`. A changed source needs a new upload identifier: the reservation, the layout and
every chunk already accepted belong to the first declaration.

A lost reply to `upload.finish` is resolved two ways, both of which return the same handle and
neither of which produces a second file. `upload.status` reports the published handle. Repeating the
same action identifier returns the retained outcome, and the retained record is consulted before the
freshness window is, because a retry carries the window it was first admitted under and the
connection now holds a newer one. The same identifier with a different payload is `ID_CONFLICT`.

## Filesystem authority

Section 14 paragraph 5 asks for opened directory and object handles rather than validated path
strings, and that is what `AuthorisedDirectory` is: an open directory descriptor, with every
descendant opened relative to it, one component at a time.

The no-escape policy, qualified:

- A name is relative in this crate's accepted form. No root, no drive prefix, no `..`, no `.`, no
  empty component, no NUL or other control byte, no separator other than `/`, none of the
  characters Windows refuses in a filename (`< > " | ? *`), no trailing dot or space on a
  component, no alternate-data-stream colon, and no Windows reserved device name. The device-name
  comparison drops everything from the first dot, trims surrounding space and folds the superscript
  digits Windows folds, so `NUL .txt` and `COM¹` are refused too. The same rules apply on every
  platform, so a name one host accepts is a name every host accepts.
- **Every** open is made against the authorised directory's own handle with the accumulated path,
  never against the previous component's handle. That is what keeps the boundary the platform
  enforces the authorised directory rather than whatever the walk last reached: a directory moved
  out of the tree between two components makes the next open fail, because the accumulated path no
  longer resolves beneath the root.
- Each prefix is opened with the no-follow open before the object itself is. A component that is a
  symbolic link or a reparse point at the moment it is resolved fails the lookup instead of
  redirecting it, whether it points inside the tree or out of it.
- After the open, the object's stable filesystem identity, device and inode on Unix or volume serial
  and file index on Windows, is read back through the handle and checked against the policy the
  caller asked for. A payload file this host created must have exactly one name; a file the host only
  reads may have more, because a hard link is a name inside the directory rather than a path that
  leaves it.
- A directory handle's identity is recorded when it is opened. A scope reopened after a restart is
  refused unless it finds the same object, so a rename, a case alias or a replacement directory at
  the same path does not extend the grant to an unrelated tree. The handle is the authority; the
  recorded path is for diagnostics and for reopening.
- An environment identity travels with every handle. A handle from one environment is never accepted
  by another, which is how a Windows path and a WSL path stay separate rather than aliasing.

`cap-std` 4.0.3 owns the three platform implementations: `openat2` with `RESOLVE_BENEATH` on Linux,
which resolves a whole accumulated path in one syscall, component-wise `openat` with `O_NOFOLLOW`
beneath the same start directory on other Unix systems, and relative `NtCreateFile` opens on
Windows. This crate is the policy, not the syscalls.

One thing the delegation does not cover. `cap-std`'s Windows no-follow test recognises
name-surrogate reparse tags, which covers junctions and symbolic links and not every reparse point,
so this crate reads `FILE_ATTRIBUTE_REPARSE_POINT` from each opened handle itself and refuses any
tag.

An open is non-blocking on Unix, so a name replaced with a named pipe cannot hold the service open
waiting for a writer. The handle's own metadata then decides whether it is a regular file.

The service's own directories are owner-only, and that is checked on every open rather than assumed
from the create. On Unix the check is the owner and the mode read from the opened handle. Windows
has no mode bits, so the equivalent is the access-control list: the staging directory is created
with a protected list naming its owner, and every open reads the list back and refuses one that
names any account except the directory's owner, the local system and the administrators group, or
that carries an entry this host cannot evaluate. The staging directory is additionally required to
hold a *protected* list, which is what stops the user profile above it from propagating an entry
into it; the directories beneath it inherit their owner entry from it by design, so their lists are
checked for the accounts they name.

`fixtures/transfer/no-escape.json` is the policy in one document: the names the validator accepts and
refuses, the tree a lookup runs against, and what each lookup must do. The Unix cases run in
`crates/kr-transfer/tests/authority.rs`. The Windows cases are in the same fixture and are built
when the running platform can build them; where it cannot, the case is reported as not exercised
rather than counted as passed, and the run prints the names it skipped so a Windows qualification
pass knows which ones it owns. The Windows access-list checks have their own tests beside the code
that performs them, and they run on Windows.

### Two limits the host states rather than hides

A download published into a client's destination with the user's explicit overwrite action cannot be
rolled back (Residual 5): the temporary name is checked against the verified object immediately before the
rename, and a rename replaces atomically with nothing to restore afterwards. Once an overwrite publish
succeeds, previous content cannot be recovered from the transfer subsystem itself; this is by design and
callers must retain their own copies if rollback is needed. The no-replace publish
has no such window, because a link that finds the name taken fails. The window that remains is
inside the service's own owner-only private directory, where anything able to swap the temporary
name could already have tampered with the bytes before they were verified.

A byte copy of a source this service does not own is not an atomic snapshot (Residual 6). Two
uncoordinated reads without coordinated locking do not constitute an atomic snapshot, whether for
a single file being rewritten concurrently or across multiple files. It refuses every change the
host can observe: the source's identity, its size, its modification time, and the digest of a second
bounded read compared with the copy. A writer that reproduces the same interleaving in both reads is
not excluded. Where the filesystem offers a clone, `cloned_snapshot` has the property outright, and
a caller that needs it on a filesystem without one coordinates with the writer or copies the file
itself.

### What this does not promise

Three residuals, stated rather than implied.

Handle-based resolution removes path-resolution races. It does not make an authorised file private
from another process running as the same operating-system user: such a process can open and write a
file this host has authorised, before or after it is published, and nothing in this crate prevents
it. What the host does instead is detect: `upload.finish` reads the whole staged file back and
refuses to publish bytes that do not match the declaration, a published payload's recorded identity
is compared before it is served, and every chunk's digest is compared against the bytes that come
off the disk. A tampered attachment is refused rather than delivered. For a source this service
never verified, detection is not enough and it stages its own copy.

Handle-based resolution removes the race between checking a path and using it, because there is no
path to re-resolve: the boundary is a descriptor. What it does not remove is what happens *inside*
one resolution of a multi-component name. Something that moves a component while a read is
resolving it can make that read reach an object the caller did not name.

Containment is `cap-std`'s to enforce, by `RESOLVE_BENEATH` where the platform has it and by its own
component-wise resolution otherwise, and its documentation is the authority on what each of those
leaves open. What this crate adds on top is the identity check, which refuses a handle that is not
the object recorded earlier, and the single-component rule on everything that changes what a
directory holds. A multi-component read is not atomic with respect to the tree it walks, and no
read here claims to be.

Every operation that *changes* what a directory holds takes a single component, so nothing above it
is resolved at all: a create, a write, a removal, a rename and a link each name one entry in the
directory whose handle is held. That is deliberate, and it is the reason the case above is about
reads. A creation is the operation a later refusal cannot undo, so it never depends on a prefix
that could have moved between being checked and being resolved.

Where `openat2` with `RESOLVE_BENEATH` is available, Linux resolves an accumulated path in one
syscall and there is no window inside it. `cap-std` falls back to its own component-wise resolution
where that syscall is unavailable or returns `EAGAIN`, which is the same shape as the other Unix
platforms. `cap-std`'s own documentation is the authority on what that leaves open.

Residual 4 (native Windows qualification): the Windows cross-compilation and check gates pass under
`x86_64-pc-windows-gnu`. Native Windows runtime qualification is assigned to worker T-025, respecting
lead ruling D-114.8 (T-024b holds the Windows host during current qualification passes).

D-114.10: The `kr-ipc` shared check is owned by worker T-024b and is not modified in this follow-up.

D-081 residual 8: The create-and-open primitive for materialisations is intentionally not built
(documented system limitation); materialisation directories are created and subsequently opened
through descriptors, bounded by the emptiness check.

Under KR-REQ-14.29, `AuthorisedFile` exposes descriptor-bound access-control list inspection
(`access_control`), restoration (`set_access_control`), and clearing (`clear_access_control`), used
by `kr-changeset` to preserve destination access-control lists across atomic apply replacements
without path reopening. On macOS, this operates through descriptor libc ACL calls (`acl_get_fd`,
`acl_set_fd`) using native binary representation (`acl_copy_ext_native`, `acl_copy_int_native`). On
Linux, this operates through descriptor extended attribute calls (`fgetxattr`, `fsetxattr`,
`fremovexattr`) on `system.posix_acl_access`. On unsupported Unix platforms, operations are refused
before rename rather than risking unverified publication.

## Verified downloads

One distinction decides everything else. A published attachment is written once by this service,
verified, and never written by it again, so it is read where it lies. Any other source is a file
something else owns, and an open handle does not make it otherwise, so the host stages its own
bounded copy and serves that. `download.begin` says which of the three cases it took, so nothing
has to infer it: `immutable_source` for an attachment read in place, `cloned_snapshot` for a
copy-on-write clone, `staged_snapshot` for a byte copy.

The first of those is worth stating exactly, because it is easy to read as more than it is. This
service writes an attachment once and no client can reach it: the staging area is the
environment's own, owner-only, and the bytes are named only by an opaque handle. What it is *not*
is protection from another process running as the same operating-system user. Such a process can
open and write the file, and nothing in this crate prevents it.

What the service does instead is refuse to serve bytes it cannot vouch for. The publication records
the payload's filesystem identity, every chunk's digest is recorded when it is verified, and both
are checked when bytes are served. The digest is the one that decides, because a replacement does
not always fail the identity check: a payload rewritten where it lies keeps its identity, and a
filesystem that hands a new file the identifier a removal has just freed gives a replacement the
same one. Changed bytes fail their chunk digest either way, so a download of a tampered attachment
is refused rather than delivered.

Staging a second copy of an attachment would not add a guarantee here. The same process could write
the copy, which the same digests would catch, and every download would charge the environment twice
for bytes it already holds. So the answer for an attachment is detection plus accounting rather than
duplication; the answer for a source this service does not own is a snapshot, because there the
bytes are not ones it ever verified.

A snapshot is taken one of two ways, and the result says which.

Where the platform and the filesystem offer a copy-on-write clone, the host clones the source:
`clonefile` on Apple platforms, the `FICLONE` ioctl on Linux. A clone is atomic with respect to the
source, so the snapshot is one revision of it whatever a writer does next, and the result is
`cloned_snapshot`.

Everywhere else the host copies the bytes, which is not atomic, and the result is `staged_snapshot`.
There the source's stable identity, its size and its modification time are recorded before the copy
and compared after it. If any of them moved, or the source grew past the size the snapshot reserved
for it, the snapshot fails with `SOURCE_CHANGED` and keeps a failed record. Metadata equality is
evidence, not proof: a writer that rewrote the same number of bytes and restored the modification
time would pass it. What the comparison rules out is every change that leaves a trace, and what the
chunk digests then rule out is a snapshot changed after it was taken.

That is why the metadata comparison is not the end of it. The copy's digest is compared with a
second, bounded read of the source, and a difference is `SOURCE_CHANGED`. Equal digests exclude
every change that left the source different from the copy at the verification read, which is what
makes an ordinary concurrent rewrite fail rather than serve.

What two uncoordinated reads cannot exclude is a writer that reproduces the same interleaving in
both of them: the first half of one revision and the second half of another, twice. A copy is not an
atomic snapshot and this document does not claim it is. Where the platform offers a clone, the
`cloned_snapshot` path has the property outright; where it does not, a caller that needs it has to
coordinate with the writer or copy the file itself. The one thing the host never does is serve bytes
it has not checked.

Either way the staged file is read back through its own handle and its digests computed from what is
actually on disk, so a snapshot never serves bytes nothing checked, and the chunks it serves come
from one revision of the file or the transfer is refused.

Resuming names the transfer. The same snapshot answers with the same identity, size, digest, chunk
layout and expiry. A snapshot that has expired, failed or been released is refused rather than
silently replaced, and a new transfer is required.

Read authority is rechecked on every chunk, not once at the start. A revoked read scope stops
further bytes at once; so does an attachment whose retention has ended. Every chunk's bytes are
rehashed and compared against the digest recorded for them, so a snapshot file tampered with after
staging fails integrity.

### The client's half

The host never writes to a client destination. `DownloadWriter` is the contract the client performs,
and it is in this crate so both halves run the same code.

It verifies every chunk against its own digest before writing it, refuses a conflicting duplicate
rather than replacing what was accepted, writes through a temporary file in the destination itself,
and checks the total size and the whole-file digest before the destination is named. An existing
destination is refused unless the placement carries the user's explicit overwrite action for that
exact destination, which is checked again at the publish because a destination can appear while a
download runs. A writer that is dropped without publishing takes its temporary file with it.

## Attachments, drafts and insertion

`upload.finish` returns an `AttachmentHandle`: an opaque, environment-bound identity with the
verified size and digest of the bytes behind it, the media type the client declared, the original
filename as metadata, a bounded preview where one could be made, and an expiry. It carries no host
path.

`presented_as_image` is true only when the bytes decoded as one of the four supported formats. An
adapter reads that rather than guessing from a declared media type or a filename, which is how
unsupported media transfers as a file without being offered as a model image.

A draft is durable and device-owned, with its own revision. Every update and every binding names the
revision it expects, and a mismatch is `DRAFT_CONFLICT` that changes nothing. Losing a connection
removes an attachment's association, not the draft.

A draft's reply carries the draft: its text, every attachment bound to it and every preview. That
reply has to fit the frame that carries it, so its encoded size is checked *before* the mutation
commits and the refusal is `QUOTA_EXCEEDED` with what to remove. Checking afterwards would leave a
caller with a committed effect and no receipt, which is the one outcome an action identifier exists
to avoid.

`agent.draft.add_attachment` binds a completed handle to a draft and records that the adapter was
asked. The binding starts at `recorded`, which says exactly that and no more. It reaches
`accepted_by_agent` only when an adapter reports the upstream part or native draft binding, and
nothing else sets it. A failure records `failed` with its reason and keeps both the draft and the
published attachment, so a retry has something to retry with.

The attachment and the draft must belong to the same principal, and to the same session where both
name one. An attachment bound to one session would otherwise be retained against that session while
a draft for another held it.

A contribution declares what one operation accepts before anything is offered: the media types, the
selected model's size limit, how many attachments a draft may carry, the insertion method and any
external destination. The host checks the handle against that declaration. An operation that claims
a model media capability cannot bind bytes that did not decode as an image.

A declared external destination is a disclosure, and the host's job is to keep it. It is recorded
with the binding and returned by the draft, so a client can show where the bytes go before the
prompt is submitted and can still say so afterwards. A destination declared without being named, or
longer than a person reads, is refused: an unnamed destination discloses nothing. The host does not
resolve the destination, reach it, or check it against anything; it refuses to lose it.

Section 12 allows three insertion methods and no others:

| Method | Needs a readable path | What it is |
| --- | --- | --- |
| `typed_submission` | no | A typed submission against the exact upstream binding |
| `verified_composer_insertion` | yes | Insertion into a native composer behind a qualified atomic editor boundary |
| `manual_terminal_workflow` | yes | The user performs the native operation after an environment-local transfer, with the host showing the tested syntax |

The two that need a readable path get an `AttachmentReadGrant`: one file, read only, one purpose,
fifteen minutes. The staged file is inside the environment's state directory and outside every
repository, which is what keeps an upload from becoming a file in a working tree. No sandbox is
widened and no file is placed in a repository. A typed submission needs no path and is given none.

## Previews

Section 14 fixes four numbers and a format list: 40 megapixels of input, 256 MiB of decode memory, a
16 MiB decoded-thumbnail budget, and PNG, JPEG, WebP and the first frame of a GIF. The `image` crate
is pinned at 0.25.10 with only the decoders named below compiled in.

WebP is on that list and is withheld. The pinned lossless decoder takes its Huffman group count from
a sixteen-bit metadata field and allocates a table set per group, so a file of a few kilobytes can
ask for hundreds of megabytes that no bound on pixels can catch. The decoder is therefore not
compiled in at all; a WebP is recognised from its twelve-byte container signature and publishes with
no preview and the reason `no preview for this format`. The transfer itself succeeds, because an
attachment without a preview is still an attachment. WebP previews return when the pin bounds that
allocation.

Two of those numbers need this crate's own enforcement rather than the library's. `image` documents
its allocation limit as advisory, and its decoders hold more than the output while they work, so the
limit is set on the decoder *and* the decode is refused in advance on a charge this crate makes: the
declared pixels at sixteen bytes each. Sixteen is the worst case among the decoders compiled in
here, a PNG decoded to sixteen-bit RGBA and a compositing decoder holding its output, its frame and
its canvas at once. The charge belongs to the pins in the manifest and is re-derived when they
move.

It bounds the *pixel* buffers, which is what image dimensions decide. It does not bound every
structure a codec can allocate from its own metadata, and where a pinned decoder does that the
answer here is not to run it: that is why WebP is withheld above. Among the decoders that are
compiled in, the pixel charge is the bound, and a decoder whose metadata could allocate past it is
one this host does not link.

An image whose charge is above the budget publishes as a file. What that establishes is a bound on
the *pixel* buffers of an accepted image, not a proof that an accepted image cannot make a decoder
allocate more: the paragraph above says where it does not reach. In practice the budget is the
binding limit, at sixteen megapixels rather than forty.

The dimensions that are charged are the ones that get allocated, which is not always the ones a
header reports. A GIF's logical screen can be one pixel while its first frame is eight thousand by
six thousand, and the decoder crops the frame into the screen, so the frame's own extent is read
from the image descriptor and charged instead.

The encoded input is bounded too, at 48 MiB, because both reader passes are taken over the same
handle and a small image with a large trailing payload would otherwise spend the budget in the pass
that was supposed to read a header.

The third is a bound the specification does not state and a result cannot do without: a reply travels
in one frame, and a draft's reply carries one preview per bound attachment. So an encoded thumbnail
is at most 48 KiB, and an image whose thumbnail does not fit is re-encoded at 320, 192 and then 96
pixels until it does. A ninety-six-pixel thumbnail of ordinary content is a few kilobytes, so the
ladder ends there in practice; an image whose thumbnail still does not fit publishes with no preview,
which is the same answer as any other refusal and is what the `ThumbnailTooLarge` refusal is for.
The dimensions are also re-checked on the decoded image rather than trusted from the header, because
a GIF's logical screen is not always its first frame's size.

The format comes from the bytes. A declared media type is a claim and an extension is metadata, so
the crate's own sniffing decides which decoder runs. The dimensions are read from the header before
anything is decoded, which means an image above the pixel limit costs a header read rather than an
allocation. A GIF decoded as one image yields its first frame and reads no further; the animation
interface is a separate call this crate never makes.

HTML and SVG stay files. Rendering either needs a reviewed renderer, and this is not one, so both are
refused by declared media type and again by the bytes.

When a decode fails, or the image is too large, or the format is one this decoder does not
handle, the attachment publishes with no preview, the reply says why, and the original file is
untouched. Nothing invents a placeholder image to stand in for it.

## Errors

| Code | When |
| --- | --- |
| `ATTACHMENT_INTEGRITY` | a chunk, a size or a whole-file digest did not verify |
| `SOURCE_CHANGED` | a declaration changed, a source moved under a snapshot, or a snapshot is gone |
| `QUOTA_EXCEEDED` | a per-file or per-environment byte limit |
| `RESOURCE_UNAVAILABLE` | the device's concurrency ceiling, or a transfer in a state that admits no more |
| `DRAFT_CONFLICT` | the draft's revision is not the one the caller expected |
| `PERMISSION_DENIED` | a name that leaves an authorised directory, or a revoked scope or grant |
| `ENVIRONMENT_UNAVAILABLE` | the request names an environment this service does not own |
| `ID_CONFLICT` | one action identifier used for two different payloads |
| `INVALID_ARGUMENT` | a malformed request, or an identifier that names nothing this caller owns |
| `STORAGE_UNAVAILABLE` | the journal or the staging area could not be used, including a name the storage would not answer about |

An identifier that names nothing is `INVALID_ARGUMENT` rather than a code of its own, and an
identifier that names another principal's transfer or draft gets the same refusal with the same
message. A caller therefore never learns from the error whether something with that identifier
exists.

A name refused by the authority and a name the storage would not answer about are different
answers. A traversal segment, a link, the wrong kind of object, a changed identity and a name that
is absent are all `PERMISSION_DENIED`. A full disk or a read failure is `STORAGE_UNAVAILABLE`,
because the caller should wait rather than change its request.

## What a caller builds on

The Rust API is `kr_transfer`. A host opens `TransferService::open(&environment_paths)`, calls
`recover()` before serving anything, and drives the methods above; the control daemon does exactly
that in `crates/kr-controller/src/transfer.rs`. A client that wants a file on disk uses
`DownloadWriter`, which never holds more than one chunk in memory. A caller that needs a readable
source registers it with `register_scope` and addresses files beneath it by relative name.

`AuthorisedDirectory` is the type the project and change-set services reuse. The policy is the
same whether it authorises a staging area, a repository working tree or a client's chosen
destination.

The daemon side is `crates/kr-controller/src/transfer.rs`: it binds the attachment-chunk endpoint
with `bind_chunk_endpoint`, serves it with `serve_chunks`, answers the service's one question about
session retention, and sweeps hourly. Everything else a transfer method needs, from the action
window to the receipt, is the daemon's ordinary path.
