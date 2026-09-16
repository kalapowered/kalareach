# The KalaReach host

A KalaReach host runs one control daemon per operating-system user and environment, and one worker
per terminal session. The split is the point: a worker owns a shell, and nothing the control daemon
does — restarting, being upgraded, crashing — may end it.

```text
kr  ──────────────┐
                  ├─▶ kr-controller ──spawn──▶ service manager ──▶ kr-worker ──▶ PTY ──▶ shell
kr attach ────────┴─────────────────────────────────────────────▶ kr-worker
```

`kr attach` does not go through the control daemon. It reads a published descriptor, challenges the
worker named in it, and attaches. That is what keeps attaching possible while the daemon is
restarting.

## Directories

Two roots, both owner-only, both checked rather than assumed on every open.

| Root | macOS | Linux | Override | Holds |
| --- | --- | --- | --- | --- |
| runtime | `$TMPDIR/kalareach` | `$XDG_RUNTIME_DIR/kalareach` | `KR_RUNTIME_DIR` | the control socket, the rendezvous socket, worker endpoints, published descriptors |
| state | `~/Library/Application Support/KalaReach` | `$XDG_STATE_HOME/kalareach` | `KR_STATE_DIR` | the registry, worker journals, output spools, generated job definitions, the secret-store fallback, the transfer store and its staging area |

Everything above a root is created with the platform's ordinary permissions; `/tmp` is
world-writable by design and `~/.cache` is usually group-readable, and neither is KalaReach's to
change. The root and everything below it is created with mode 0700 and verified on every open. A
directory that is a symbolic link, or that belongs to another user, is refused rather than repaired.

Per environment the directories are `<runtime>/<prefix>` and `<state>/environments/<prefix>`, where
the prefix is the first four bytes of the environment identifier in hexadecimal. The prefix is
short because a Unix socket address is 104 bytes on macOS and the runtime directory already spends
much of that; it is not unique, so each directory also carries an `environment` file holding the
complete identifier. A second environment whose identifier shares the prefix is refused, never
silently given another environment's registry.

Endpoints are `c.sock` (clients), `r.sock` (the owner-only rendezvous), `t.sock` (attachment
chunks) and `w<display>.sock` (one worker). On Windows they are named pipes scoped by user and
environment, carrying an owner-only access-control list, because the pipe namespace has no directory
permissions to inherit.

## Descriptors

The control daemon publishes one descriptor per live session, atomically — written to a temporary
file in the same directory, then renamed, then the directory entry flushed. A descriptor carries
the session identifier and epoch, the environment, the display number, the boot identity, the
worker's process-start identity, the protocol version, the endpoint, the worker's public key and
its profile. It carries no secret.

A reader checks the file before it reads it: a symbolic link, another user's file, a file others
can read or write, or one larger than any descriptor this host writes is refused. A descriptor
whose contents name a different session from its filename, or a different environment from its
directory, is refused too.

Nothing in a descriptor is acted on until the worker behind the endpoint has answered a challenge.

## Identity and verification

Four proofs, each with a job.

| Proof | Who signs | What it settles |
| --- | --- | --- |
| rendezvous | the worker, once at startup | this process is the worker the daemon reserved |
| verification | the worker, on every challenge | the process answering this endpoint is that worker, now |
| generation | the control daemon | this connection speaks for the current daemon generation |
| peer credentials | the kernel | the caller on this socket is this user |

The worker generates an Ed25519 keypair from the operating system's random generator at startup and
keeps the private half in memory for its whole life. It is never written to disk, placed in an
argument vector or put in an environment variable.

Boot and process-start identities come from the kernel:

| Platform | Boot identity | Process start identity |
| --- | --- | --- |
| Linux | `/proc/sys/kernel/random/boot_id` | `/proc/<pid>/stat` field 22 |
| macOS | `kern.bootsessionuuid` | `proc_pidinfo(PROC_PIDTBSDINFO)` |
| Windows | the recorded boot time | the process creation time in whole seconds |

A process identifier alone is never enough. Every ownership check compares the start value as well,
so a recycled identifier reads as a different process. A query the operating system refuses is
reported as unknown, never as death: a recovery path that treated a failed query as a death would
release a session identity while its worker was still running.

## Supervision

A worker's lifetime belongs to the platform, not to the control daemon.

| Platform | How a worker starts | Where its identity comes from |
| --- | --- | --- |
| macOS | a per-session launchd job, bootstrapped into `gui/<uid>` and started once with `launchctl kickstart -p` | the kickstart output's process identifier, then `proc_pidinfo` |
| Linux with systemd | a transient user *service*, `systemd-run --user --unit=... -p Type=exec -p Restart=no` | `systemctl --user show -p MainPID`, then `/proc/<pid>/stat` |
| other Unix | a child in its own process group, reparented to init when the daemon exits | the spawned child |
| Windows | the spawned child, outside the daemon's kill-on-close Job | the child's identifier and creation time |

`kickstart -p`, never `-k`: the second restarts a job that is already running, which for a session
worker means killing a live shell to start another one.

The service manager reports a process identifier as soon as it has spawned the process, which can
be before the kernel will describe it. The daemon retries briefly rather than refusing a worker
that started perfectly well.

### Privacy permissions

A worker started by the service manager is not a child of the terminal that asked for it. On macOS
that makes it its own process as far as the operating system's privacy controls are concerned, so
the first time a worker reads a protected location — an external volume, the desktop, the documents
folder — the person is asked to allow it, once per installed binary. That is the operating system
working as intended; nothing here asks for blanket access on the user's behalf.

Two consequences are worth knowing. A session whose working directory is on a protected volume will
prompt when its shell starts, not when the person later opens a file. And a host whose binaries are
replaced — a new build, an upgrade — is a new binary to those controls, so the question is asked
again.

A launchd job's standard error goes to `<state>/environments/<prefix>/jobs/<label>.diagnostics`. A
worker that fails before its rendezvous has no terminal, no connection and no journal yet, so that
file is the only place its diagnosis can go.

## Creating a session

1. The daemon records the reservation durably: the actor, the create token, the immutable payload
   digest, the allocated session identifier and display number, and the launch phase. Display
   numbers increase and are never reused.
2. The reservation moves to `spawned` **before** anything starts, because a worker can reach the
   rendezvous socket the instant the service manager starts it.
3. The service manager starts the worker. Its job definition carries only non-secret facts: the
   reservation, the session, the environment, the display number, the rendezvous address and the
   two directory roots.
4. The worker connects to the rendezvous socket and presents its signed claim. The daemon checks
   the signature, matches the reservation, and compares the connecting process — both its
   identifier and the kernel's record of its start — with what the launcher reported. Exactly one
   rendezvous per reservation succeeds; a second is refused, recorded, and fences the reservation.
5. The daemon sends the launch specification over that private channel: the create request, its own
   public key and its generation.
6. The worker creates the pseudo-terminal, launches the root shell, binds its endpoint and reports
   itself ready. The daemon records the worker's public key inside the same transaction that marks
   the session live, then publishes the descriptor.

The create token is the request's action identifier. A retry with the same payload resolves to the
same reservation; the same token with a different payload is refused rather than becoming a second
session. A lost reply never causes a second launch.

## The terminal

The host is the terminal, not whatever is attached to it. Every byte the shell writes passes
through the worker's canonical grid (`kr-term`) before any attachment sees it, and the retained
history keeps the raw stream underneath.

| What arrives | What an attached terminal gets |
| --- | --- |
| Ordinary output | the same bytes, forwarded unchanged, in direct mode |
| A query | nothing; the host answers it once, into the application's own input |
| A bell, clipboard write, notification or progress report | delivered to the one attachment holding the input lease, and to nobody else |
| A sequence the profile does not name | nothing; it is consumed with a rate-limited diagnostic |

Two presentations, and the choice is the host's:

| Presentation | What it receives | When it applies |
| --- | --- | --- |
| `direct` | the spans of the raw stream the engine cleared | the terminal is exactly the canonical size, has declared the terminal it probed, and the stream is still carryable |
| `viewport` | a rendering of the canonical grid, clipped to the terminal's own size | every other case |

`kr attach --no-probe` withholds the declaration, so that attachment is projected: a host that has
not been told which terminal it is talking to does not hand it a byte stream and hope.

An attachment never receives replayed history. What it is given when it joins, and again whenever
it resynchronises, is the screen as it is now, rendered from a closed set of operations with no
member that can ring, copy, notify, download, launch or ask anything. A terminal that was not there
when the history happened does not have the history happen to it.

Rendering a screen back into bytes cannot carry everything a client that holds its own grid could
apply. What it leaves out is counted rather than assumed away — the saved cursor and keyboard
negotiation of the buffer that is not showing, the virtual title stack, soft-wrap markers, the
right-hand side of a row wider than the window, and a pending wrap on a row outside that window —
and `Session::restoration_losses` is the count.

A sequence the profile does not name is consumed rather than forwarded, and the engine counts it;
`Session::terminal_diagnostics` reports those totals. A side effect that arrives while nothing holds
the input lease has no destination, so it becomes a durable host event in the worker's own journal
rather than being shown to whoever happens to be watching.

## Who may type

A session has one input lease with an epoch. `input.acquire` takes it immediately: the epoch
advances, the previous holder's undelivered bytes are dropped, and nothing waits for that holder to
agree. What has already reached the application cannot be recalled, so the count of discarded bytes
is the honest limit of what a takeover undoes. A write at any other epoch, or from any other
attachment, is `LEASE_LOST`, and it never takes the lease as a side effect: acquiring is something a
controller asks for.

Whether it may hold the lease is a comparison rather than a label. The canonical grid knows which
keyboard encoding the application has negotiated — the ordinary one, `modifyOtherKeys` at a level,
or the Kitty protocol with a set of flags — and the host compares that against what the controller
can produce. A controller that cannot produce it is refused with `INPUT_INCOMPATIBLE` and keeps
everything else it had: it goes on watching, and its typed actions are unaffected.

| Controller | What it offers |
| --- | --- |
| A semantic attachment | whichever protocol is in force, because it builds each key from the logical key and its modifiers through the shared encoder |
| A terminal that declared what it is | what that terminal is known to implement, from `kr_worker::input::KEYBOARD_PROTOCOLS` |
| A terminal outside that table, but declared | the ordinary encoding, which every terminal sends |
| A terminal that declared nothing, which is what `--no-probe` chooses | nothing, in either direction: a terminal nobody was allowed to ask about is as likely to have been left in an enhanced protocol by whatever ran before it |

The table rests on the same fact `QUALIFIED_TERMINALS` rests on, and carries the same limit: each
row is what that terminal's own documentation says it implements, and a `TERM` name is the client's
claim about which terminal it is rather than a measurement of it. So the rows are conservative. A
protocol a terminal implements only under a setting is not claimed, because the name does not say
whether the setting is on: WezTerm's Kitty support is behind a configuration option that starts off,
so `wezterm` claims `modifyOtherKeys` and nothing more. Nor is a protocol claimed for something that
is not a terminal: what `tmux` forwards depends on its own extended-keys setting and on whatever is
outside it, so it claims only the ordinary encoding. A controller that advertised a protocol and
then sent another is exactly what section 8 refuses to allow.

A controller that builds its own keys is declared for the flags this build's encoder actually
produces, which is not all of them: alternate-key reporting asks for the shifted and base forms of a
key beside the one that was pressed, and the encoder reports the key it was given. An application
that asks for that flag is served by no controller here, and says so, rather than being sent an
encoding one of them only advertises.

One limit of that encoder is worth stating rather than implying. The Kitty keyboard protocol
identifies a key by the code point of its unshifted form, so a client that reports a shifted
character has to say which key produced it; one that does not is refused that form rather than
served a guess at its layout. What the encoder cannot detect is a character a *lock* transformed -
a capital produced by Caps Lock reports no modifier at all - so a client that has a layout supplies
the base key whether or not it thinks a modifier was held.

The comparison is made again whenever the application changes the negotiation, which it can do at
any moment and without telling anybody. Parsing the output is what tells the host, so an application
that turns an enhanced protocol on takes the keys from a terminal that cannot send it, and one that
turns it off leaves the ordinary encoding, which any declared terminal can send, so that terminal
is eligible again and can ask for the keys. Nothing gives them back by itself. The release is the
ordinary one — the epoch advances, the fence goes out, a paste the lease had open is closed — and
the holder learns on its next write, which is `LEASE_LOST`.

Such a release has no answer of its own to report in, and neither does a detach, so what it
interrupted is carried instead: the bytes that were accepted and never arrived, and whether a paste
the application was inside had to be closed. The next `input.acquire` reports them with its own, once.
A paste is never completed under another actor's lease, and closing the framing does not undo the
part of it the application already has.

Three things that look like input are not: a focus event, a passive scrollback read and an attached
window that is doing nothing all leave the lease exactly where it was. So does the host's own reply
to a question the application asked, which travels on the same path to the terminal and is not a
lease event.

What reaches the terminal is not a record of what was typed. `input.write` is an ordered stream
rather than an admitted action, so no receipt, intent or result is written for a keystroke and
nothing replays one. Nor is delivery proof of effect: bytes written into a pseudo-terminal whose
application is not reading have reached the terminal and done nothing at all.

## Who owns the size

Size ownership is separate from input ownership, and both are separate from observing the session.
The first eligible geometry claim owns rows and columns; eligibility needs a terminal attachment, a
registered claim and the geometry right together, so reporting a viewport confers none of it and a
conversation view — which is semantic, and cannot claim — never competes for it.

| What happens | What it does to the size |
| --- | --- |
| A second terminal attaches | nothing: an existing owner keeps it |
| An attachment reports its viewport | nothing; it decides only how that attachment is shown the session |
| The owner resizes at the current epoch | moves the pseudo-terminal and the canonical grid together |
| The owner detaches or withdraws its claim | the oldest remaining eligible claim succeeds and supplies its own dimensions |
| No eligible claim remains | the last geometry is retained, and the next eligible claimant takes it |
| `terminal.geometry.transfer` at the expected epoch | moves it deliberately, and every attachment learns at once |
| An input takeover | nothing |

Every ownership change advances the geometry epoch, and a change that did not happen does not: a
resize the kernel or the session's budget refused leaves the epoch where it was, so a refusal cannot
invalidate every client's next request. A succession is the exception that proves the rule — the
owner did give up its claim, whatever the kernel then said about the successor's size, so the size
goes back unowned rather than to an attachment that has left or has withdrawn.

Dimensions are validated before anything is allocated, against all three of section 8's constraints
at once: 1 to 2,048 columns, 1 to 1,024 rows and at most 262,144 cells, with checked multiplication
so a product that would overflow is a refusal rather than a wrap. The independent maxima are not
valid together. A refusal names the limit it violated and changes nothing about the grid the session
is running at, its epoch included. A session created without a terminal starts at 120x40. A history
page carries at most 1,000 rows and 1 MiB.

Semantic snapshots have their bounds and nothing yet to spend them: `kr_protocol::semantic` holds
section 8's three limits (16 MiB across the parts, sixteen levels of depth, twenty thousand nodes),
the budget a producer spends as it walks a tree, and the continuation a refused node produces, so a
part that stops short says which limit stopped it and where a reader asks for the rest. The producer
that walks the tree is the semantic-snapshot task's, and until it exists these bounds are what that
task has to spend rather than a bound anything is under.

## Action windows and the dispatch lease

Both are the transport's own components (`kr_transport::window`, `kr_transport::lease`), used
directly rather than reimplemented for the local path, and both are measured on the transport's
suspend-aware continuous clock (`kr_transport::clock`).

* The daemon and each worker issue one action window per authenticated connection, bound to that
  connection and to the host's boot. A window is replaced on the live connection at half its
  validity, without being asked for, and arrives as `ControlEvent::ActionWindowRenewed`. A window
  from another connection, or from before a restart, first-admits nothing.
* The accepted deadline of a mutation is the earliest of the window's expiry, receipt time plus the
  requested lifetime, and any applicable authority deadline. What one host process forwards to
  another is what *remains* of it, as a duration: two processes measure on their own continuous
  clocks and neither clock's origin means anything to the other.
* Remote dispatch additionally needs a live lease from the current generation and revision. The
  daemon takes it at the moment it forwards, not when the request arrived, and the lease's own
  remaining time bounds the deadline the worker is given.

## What the host owes the transport

Two contracts `docs/transport/README.md` names, and where they are kept:

* **Admission and revocation.** The daemon validates the caller's record and registers the
  connection in one critical section, in one lock order that a revocation also takes, so nothing
  can be admitted against authority that has already been replaced. Withdrawing a registration
  fences that connection's reads. At a worker, binding a newer controller generation withdraws the
  previous connection's registration, which stops the subscription it had already started; the
  connection stays open so its next request can say why it was refused.
* **Work that must complete.** A mutation's effect runs on a task that outlives the connection, so
  a durable commit is never left half done because the caller went away. The worker's own dispatch
  path holds no await between the marker and the outcome, so it cannot be cancelled part way.

## Journals and the receipt contract

Each worker has its own SQLite journal in write-ahead-logging mode with full synchronisation.

| Table | What it holds |
| --- | --- |
| `receipts` | one row per `(verified_actor_id, action_id)`: method, revision, state, rejection reason, payload digest, accepted deadline, error, timestamps |
| `results` | the result a duplicate request must receive back |
| `closure` | the session's final record |

The order is the contract. The intent is committed before the caller is told it was accepted. The
dispatch marker is committed before the effect. A marker with no authoritative outcome becomes
`unknown` on restart and is never dispatched again, because nothing can establish from here whether
the effect happened. De-duplication records are kept for 30 days.

Raw input is not in this table. Section 9 makes it a separate ordered stream keyed by connection,
lease epoch and sequence, with nothing replayed on reconnection.

## What an idle session wakes for

A session with nothing happening in it should cost nothing, and twenty of them are measured
together. KR-PERF-003 puts the whole host under one per cent of one processor core, averaged over
five minutes: twenty idle sessions, thirty-two attached views, the allocated grids with their
caches, and the daemon. A host that asked the kernel ten times a second, for every session, whether
anything had happened yet would spend most of that allowance on the questions alone.

So every wait in a worker is on something that happens rather than on a clock.

| What is watched | What wakes the host | What is left on a clock |
| --- | --- | --- |
| the application's output | the terminal's own descriptor, which reports output and a hangup alike | a one-minute safety net, for a platform that reports neither |
| room for the application's input | the same descriptor | nothing; a write with no room waits on it |
| the root shell's exit | the child signal the kernel sends the worker | a thirty-second sweep, in case a signal is lost. Windows reports a process ending on its handle rather than by a signal, so there a hundred-millisecond check is the whole answer |
| the processes the session owns | input the session accepted and output it produced, which is where a new process usually comes from | the same sweep, for everything that comes from neither |
| the login a desktop-bound session is tied to | nothing this host can subscribe to | the same sweep |
| a held paste prefix | its own deadline, which exists only while a prefix is held | nothing |
| an attached view | the frames its connection carries | one keepalive per connection every ten seconds, which section 23 requires of a local connection |

The sweep is a window rather than a guarantee, and it is worth saying exactly what that costs. A
process that starts and ends between two observations of the ownership boundary is not in the
closure record's list of what was stopped. The record never claims every application was discovered,
and the coverage flag says which boundary produced it.

The session's own traffic keeps that window narrow when the session is visibly doing something, and
it is a hint rather than a proof. An application that is already running can start and collect
children on its own timer, on a filesystem event or on something that arrived over a network, and
print nothing while it does; and input is marked as it is queued for the terminal, so a process the
application starts after reading it, and finishes before anything else is marked, is in no reading
at all. Silence here is therefore not evidence of idleness: idle means a verified idle shell with no
pending request and no active owned work, which is a different question asked elsewhere. What a
closure rests on instead is the boundary observed again as the processes are asked to stop, as
whatever is left is forced, and as the record is written.

## The transfer service

The daemon hosts the environment's transfer service, which owns `transfers.sqlite` and a private
staging directory under the state directory. The daemon owns three things about it: admission, the
endpoints and the retention.

Admission is the ordinary path. A transfer read is checked against current authority before and
after it runs. A transfer mutation carries an action window, is checked against the method registry,
and runs on a task a dropped connection cannot cancel part way. A retry after a lost reply is
answered from the retained record before the freshness window is considered, because the retry
carries the window it was first admitted under.

A 1 MiB attachment chunk does not fit a control frame, so chunk traffic has its own endpoint,
`t.sock`, framed at the attachment bound. Everything else about that connection is the control
connection's: the same handshake, the same peer credentials and the same action windows.

The service cannot know which sessions this host still retains, so the daemon answers for them: a
session the registry has a reservation for keeps what was submitted to it. An hourly sweep expires
unfinished uploads after twenty-four hours, unused attachments after seven days, and download
snapshots at their own expiry. At startup the service resolves any publication an earlier daemon
left between its two commits, so a handle never names a file this host has not found.

`docs/transfer/` has the protocol, the limits, the storage layout and the authority model.

## Closure

`session.close` is a state, not a request to exit.

1. The session moves to `closing` atomically. Input is rejected from that moment.
2. The acceptance is written to the requester **before** anything is signalled, because the
   requester is often a command running inside the process group about to be stopped.
3. The owned process group is asked to stop, and has five seconds.
4. Whatever remains is forced.
5. Output drains for two more seconds.
6. The record is written: the reason, the root shell's exit status or the signal that ended it, the
   process identities that were terminated, and an ownership-coverage flag. The record never claims
   every application was discovered.

If the journal is unavailable the closure still happens — storage failure must not prevent an
authorised stop — and the reply says `durability=volatile` rather than claiming otherwise.

The control daemon watches a closing worker and writes the tombstone and removes the descriptor
once the kernel agrees the worker has gone. A worker that disappears without a close request is
reconciled the same way and recorded as an abnormal closure. A daemon that merely cannot reach a
worker records nothing: not reaching a process is not evidence that it died.

## Recovery

A replacement daemon takes the environment's singleton lock, advances its persistent generation,
and rebuilds its directory from the registry rows and the published descriptors — never from a list
of process names. Each worker is verified by a fresh challenge. A descriptor that fails is
quarantined and never spawned from. No worker is killed because the daemon restarted.

A worker accepts its current generation again only after a fresh challenge, which fences that
generation's previous connection; it refuses a lower generation and requires a strictly higher one
from a replacement. The daemon's identity key is created once and loaded thereafter: a missing key
on a later start is a recovery condition, not an invitation to make a new one, because every live
worker holds the public half and rotation is a procedure that closes them all.
