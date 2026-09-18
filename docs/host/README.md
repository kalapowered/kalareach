# The KalaReach host

A KalaReach host runs one control daemon per operating-system user and environment, and one worker
per terminal session. The split is the point: a worker owns a shell, and nothing the control daemon
does — restarting, being upgraded, crashing — may end it.

```text
kr  ──────────────┐
                  ├─▶ kr-controller ──spawn──▶ service manager ──▶ kr-worker ──▶ PTY ──▶ shell
kr attach ────────┴─────────────────────────────────────────────▶ kr-worker

paired device ──iroh──▶ kr-controller ──proxy──▶ kr-worker
```

`kr attach` does not go through the control daemon. It reads a published descriptor, challenges the
worker named in it, and attaches. That is what keeps attaching possible while the daemon is
restarting.

A paired device does go through it, because a worker has no network endpoint and the daemon is what
authenticates a device. The network path is below.

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

### Where the daemon keeps its keys

`kr-controller --secret-store` chooses where the controller identity and this host's network
device keys go. One selection covers both:

| Value | Store | Who uses it |
| --- | --- | --- |
| `platform` (the default) | the operating system's credential store, with the owner-only directory where section 10 offers it | an installed host |
| `file` | this environment's own `secrets` directory | a test, a bench or a demonstration run |

The two key sets are opened separately, because the identity is opened at startup, behind the
singleton lock, and the network keys only when the environment selects a network. Under `platform`
each takes the store it always took: the identity follows the `.store-kind` record this host made,
and the network keys take the platform's credential store where there is one and the owner-only
directory where there is not. On a Linux host whose secret service appeared after it recorded the
directory, that is two different stores, which is what an installed host has today.

Under `file` both go in the environment's own `secrets` directory. `file` names where the keys go
and nothing else: it allocates no directory and deletes nothing afterwards, so a run that wants its
keys to disappear gives the daemon a state directory it owns and throws away. That is what the
harnesses do, and it is why nothing a test or a measurement does reaches the person's own
credential store; the in-process suites call `kr_crypto::store::open_store_in` for the same reason.
The daemon names the store it opened in its first line of output, so a run's log says where its
keys went.

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

### The plugin runtime

A worker is not the only thing whose lifetime belongs to the platform. Components run in
`kr-plugin-host`, one process per environment, started through the same supervisor as its own job
outside the daemon's kill tree, and started only when a binding first needs one: an environment
whose shells never use a component has no plugin process at all.

It reports itself on a rendezvous endpoint of its own, signed with a keypair it generated at startup
and keeps in memory, and the daemon publishes an owner-only descriptor at `plugin-host.json` beside
the worker descriptors. Workers read it, challenge the process behind the endpoint, register their
bindings and keep their own ledgers. Nothing durable lives in that process, so its death invalidates
rich bindings, kills no worker and loses no request; a worker notices, re-registers, and carries on.

`docs/plugins/runtime.md` has the execution model, the per-instance limits, the compiled-code cache
and the protocol.

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

## The network path

The daemon joins the network once, at the end of its startup, when its environment selects one.
`KR_NETWORK` turns it on and the variables in `crates/kr-controller/src/net/config.rs` select the
relay map, the Pkarr publisher, the Pkarr resolver and the DNS origin, each on its own and none
inherited. `KR_NETWORK_RELAY_ONLY` removes the direct paths altogether, for a deployment where one
is not available or not wanted. `KR_NETWORK_OWNER_KEY` names the enrolled owner signer; without one the host accepts no
pairing, because there is nobody who could authorise a confirmation. A daemon that selects no
network serves its local endpoint alone, which is a supported deployment rather than a degraded
one.

Its own network device keys are a separate key set from the environment's controller identity. The
controller identity signs generation tokens to this host's workers; these are the keys a *device*
authenticates, and conflating them would make a worker's view of its daemon and a device's view of
its host the same secret. They live in the platform credential store, with the documented
owner-only directory as the fallback, and are created once: a host that lost them is a host every
paired device would refuse, because its endpoint identity is what an invitation pinned.

What a device reaches, in order:

1. **Unpaired**, it reaches the bounded `pair.*` surface and nothing else. The daemon drives
   `kr-pairing`'s own state machines behind it; the owner ceremony that authorises an invitation and
   approves a candidate is the platform's, and the daemon holds the challenge and the ledger that
   makes it single use.
2. **Paired**, it gets an authorised connection whose actor the daemon constructs: `paired_device`
   ingress, the device, the grant and the revision it was validated at, the controller generation
   that admitted the connection, and the connection's own identity.
3. **Reads the daemon owns** — the host, the environment, the session list and one session's
   metadata — are answered by the daemon.
4. **Everything a session owns** is forwarded to the worker over a link the daemon opened for that
   connection, under the verified envelope and the deadline the daemon accepted, through the same
   serial barrier a local caller's mutation passes through. That link declares itself a proxy before
   it presents a generation token, so a device's attachment, subscription and input lane belong to a
   connection of their own without displacing the daemon's authority connection.

What the grant decides, for every request:

* **Expiry.** A grant that has run out is refused, and once it has been found expired it stays
  expired, so a wall clock stepped backwards revives nothing. What remains of its lifetime is also
  an authority deadline: an action admitted a moment before the expiry cannot dispatch after it.
* **Selectors.** The environment and the session the request names have to be ones the grant
  admits. A listing names no session, so the *answer* is narrowed instead: a device is told about
  the sessions its grant admits and no others.
* **Rights.** Every right the method requires unconditionally, and every conditional one whose
  condition this request meets — a `session.attach` that claims geometry needs `terminal.geometry`,
  whether or not the worker would have given it the capability. A condition the daemon cannot
  decide is treated as holding, so the right is asked for rather than skipped.
* **History.** Retained history is not served to a device at all: its scope is the grant's lower
  bound, that bound is a moment in time and a history page is a byte range, and a host that cannot
  narrow content to a grant refuses it rather than serving more than the grant allows. The
  session's live screen and the stream that follows it are served when the grant includes them,
  and "the live screen" means the screen that is showing: a device's attachment is drawn the active
  buffer alone, and the rows of the buffer that is not showing are counted among what its
  restoration did not carry. The exception section 10 names is the visible screen, and never the
  inactive buffer, the scrollback or the backing transcript.

What the subject decides stays the subject's, and the conditional requirements the daemon cannot
evaluate are exactly those: whose subject it is. A device detaches the attachment its own
connection created and nothing else, and it cancels or reads its own action and nothing else,
because the worker enforces both inside its own dispatch barrier — the attachment list is the
connection's, and the receipt journal is keyed by the verified actor and the action together. A
local caller keeps its cross-window detach, because every local caller is the same authenticated
operating-system user. An `action.read` names an action rather than a session, so it goes to the
session the device's connection is already serving, which is where its actions on this host were
performed.

Remote dispatch needs a live lease, and a lease is renewed only after the worker has acknowledged
the authority revision in force. A worker starts having acknowledged nothing, so the daemon asks
*that* worker for its acknowledgement when it opens a proxy link to it and again if a dispatch
finds no lease; asking every worker would make one paused session everybody's wait. The envelope
carries the revision the grant was checked at, and the worker refuses inside its barrier an action
validated under a revision it has since installed past. Local input and stopping owned execution
depend on none of this: neither is remote dispatch.

An action whose fate the daemon cannot establish is reported as unknown rather than as refused. A
frame that reached a worker before the link failed may have been dispatched, so a proxy link that
was interrupted part way through a frame, or that did not answer in time, answers
`OUTCOME_UNKNOWN`: nothing retries it, and the client keeps it on the list of actions whose outcome
it must ask about.

A device that falls behind is told rather than waited for. What the daemon holds for one device is
bounded in bytes, not in messages, at section 9's send queue per peer; a device that reaches that
bound loses its link, which takes its subscription and its attachment with it, and section 8 has it
reconnect and resume from the cursor it holds. Holding the worker's own delivery task instead would
make one slow device everybody's problem.

## What the host owes the transport

Two contracts `docs/transport/README.md` names, and where they are kept:

* **Admission and revocation.** The daemon validates the caller's record and registers the
  connection in one critical section, in one lock order that a revocation also takes, so nothing
  can be admitted against authority that has already been replaced. One authority store holds both
  ingresses, so a revocation fences a paired device and a local caller through one table.
  Withdrawing a registration fences that connection's reads, its dispatches and its subscription.
  Every frame a network connection sends is decided and written behind one turn, and a withdrawal
  sets that turn's latch before it closes the connection, so no write begins after the authority
  behind it went; the withdrawal itself never waits for a peer. Revoking a device withdraws its
  registrations and releases what its connections owned at their workers *before* it writes
  anything, because the fence is the step that cannot fail; the record's revocation and the
  authority revision then move in one critical section, so no connection can be admitted between
  the two. What it fences is that device's connections, because nobody else's authority was
  withdrawn. At a worker, binding a newer controller generation withdraws the
  previous connection's registration, which stops the subscription it had already started; the
  connection stays open so its next request can say why it was refused.
* **Work that must complete.** A mutation's effect runs on a task that outlives the connection, so
  a durable commit is never left half done because the caller went away. So does the release of
  what a remote connection owned at its worker, because the handler is dropped the moment the
  control stream ends. The worker's own dispatch path holds no await between the marker and the
  outcome, so it cannot be cancelled part way.

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
and runs on a task a dropped connection cannot cancel part way. The admission is checked once more
immediately before the write, because everything in between can wait for a lock or a thread: an
action whose accepted deadline passed while it queued does not go on to write. A request whose
envelope names a different session from the object its parameters name is refused, because the
receipt would otherwise name a session the effect never touched. A retry after a lost reply is
answered from the retained record before the freshness window is considered, because the retry
carries the window it was first admitted under.

A 1 MiB attachment chunk does not fit a control frame, so chunk traffic has its own endpoint,
`t.sock`, framed at the attachment bound. Everything else about that connection is the control
connection's: the same handshake, the same peer credentials and the same action windows. The two
endpoints carry disjoint sets of methods, so the larger bound is not a second admission: a chunk on
the control endpoint and an ordinary request on the chunk endpoint are both refused. The daemon
process binds both and owns the tasks that serve them, so a restart releases the addresses before it
binds them again.

The service cannot know which sessions this host still retains, so the daemon answers for them: a
session the registry has a reservation for, in any launch phase, keeps what was submitted to it.
That preserves files rather than losing them, and it is not yet the archive's retention policy; when
the archive owns that state, the answer to this one question changes and the sweep does not. An hourly sweep expires
unfinished uploads after twenty-four hours, unused attachments after seven days, and download
snapshots at their own expiry. At startup the service resolves any publication an earlier daemon
left between its two commits, so a handle never names a file this host has not found.

`docs/transfer/` has the protocol, the limits, the storage layout and the authority model.

## The project service

The daemon also hosts the environment's project service, which owns `projects.sqlite`, the
repositories the user works in, the working copies selected on them, and every Git invocation this
host makes. The daemon owns two things about it: admission, and the sessions a workspace is bound to.

Admission is the ordinary path. A project read is checked against current authority before and after
it runs. A project mutation carries an action window, is checked against the method registry, and
runs on a task a dropped connection cannot cancel part way. The admission is checked once more
immediately before the write, for the same reason it is for a transfer: everything in between can
wait for a blocking thread or for the journal's lock, and an action whose accepted deadline passed
while it queued does not go on to write. A project acts on neither a session nor a foreground
application, so an envelope that names one is refused before anything runs.

Some of these calls are long. A clone reaches the network and a materialisation copies files, so
they run on blocking tasks and the journal's lock is never held across a subprocess. A cancellation
therefore cannot reach inside a running clone: it sets the operation's flag, and the invocation that
holds the child ends everything *it* started, by the identity this process recorded. On Unix that is
the process group the child leads, which holds every helper the clone spawned; on Windows it is the
job object the child was created inside, which holds them for the same reason and which a process
cannot leave.

### The boundary around a Git invocation

Every Git this host runs is enclosed by the operating system for the length of that one invocation,
and the enclosure is built from the directories this host opened rather than from the paths it was
given. Three things it holds, whatever the repository's configuration says and whoever writes to the
repository while Git is running.

* **Only Git executes.** Git's own program and the helpers under Git's own directory, the approved
  broker's ssh program for a remote that needs one, and the system shell for an invocation that
  reaches a repository over Git's own transport, because Git builds its connection and its call to a
  credential helper as command strings for it. A driver, filter, hook, credential helper, pager or
  filesystem monitor planted anywhere else cannot be executed, whether it was planted before this
  host read the configuration, between that reading and the moment Git started, or while Git was
  running.
* **Only this operation's network.** A local operation reaches no address at all and nothing may
  listen. An operation that reaches a remote may open outbound connections on the ports its
  transport uses and resolve the remote's name, and nothing may listen there either. Which part of
  that each platform enforces, and what it leaves, is in `crates/kr-project/README.md`: the ports
  are enforced on two of the three platforms, and on Linux they are a guarantee about the protocol
  the transports use rather than about every packet a name resolution sends.
* **Only this operation's directories are written.** The repository's working tree and its Git
  directory, the destination the operation reserved, and one temporary directory that exists for the
  length of the invocation and is taken away with it. Everything else is read-only.

The enclosure is what makes the checks around it sufficient rather than advisory. This host reads a
repository's configuration before it runs Git and reads it again afterwards, and it always could; a
writer racing the two readings is what those checks could notice and not prevent. Now the child
starts inside the directory this host opened rather than at a name, so a tree put at that name
afterwards is not the tree Git works in; and every directory the enclosure was built around is
required to still be that object before anything the child produced is used, so a substitution made
while Git ran is this host's declared refusal rather than a result nobody can account for.

What it does not confine, on the two platforms whose mechanism separates the two, is reading. Git
reads the system's shared libraries, its locale data and its certificate store, and a read
confinement that missed one of those would fail an operation for a reason that has nothing to do
with safety. What a repository can reach by reading is what the account this host runs as can reach,
exactly as before.

Where a guarantee cannot be enforced from outside Git, the operation that needs it is refused rather
than run under checks that notice afterwards. A kernel too old to mediate the filesystem rights this
rests on runs no Git; one too old to say which addresses a process may reach runs no remote
operation; and **Windows runs no repository operation at all**, because an application container cannot keep a
repository from being executed from and cannot bound which ports a remote operation reaches. The
platform task that qualifies this host on Windows is what changes that.
`crates/kr-project/README.md` says exactly what each platform enforces and what it leaves.

`docs/project/` and `crates/kr-project/README.md` say which mechanism holds which guarantee on each
platform, and what a platform refuses rather than pretends.

This daemon's project mutations check the accepted deadline and the connection's authority
immediately before the write, as its transfer mutations do. That is the boundary the host contract
has today: a mutation still waits for a blocking thread and for the journal's lock after the check,
and closing that gap means carrying the admission into the service's own transaction for every
service rather than re-deriving it here.

At startup the service resolves whatever an earlier daemon left unfinished, before anything is
served. A publication that landed is completed; one that did not is either finished or cleaned up;
one this host cannot decide is recorded as unresolved with its staging path named rather than
removed. The question it asks is never whether a name exists but which name holds the object that
was staged, because the operation row carries that object's filesystem identity and the row's key is
the caller's own action identifier.

The service cannot know which sessions and automation runs are bound to a workspace, so whoever
owns those lifetimes records the binding here and the service enforces it: a workspace a live
session or run still holds refuses removal whatever retention policy the request carries, and
nothing new may hold one whose removal has begun.

`docs/project/` has the ten methods, the identity model, the staged publication, the credential rule
and the restricted Git execution profile.

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

Every process in that record is named by its identifier *and* the kernel's record of when it
started, because an identifier alone can belong to something else within milliseconds. One case
cannot have both: a shell that leaves before the host has read it. A session whose shell exits
immediately, because a startup file says so or because the program it named is not there, is a
session that ran, and the host records it as one; macOS stops describing a process the moment it
exits, so there is no start value left to read, and the identity carries a reserved value that says
the reading never happened. Such an identity always reads as ended, which is what it is, and it
never matches a live process that inherits the identifier.

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
