# Running a plugin component

`docs/plugins/README.md` says what a package is and what its component may do. This is the other
side of the same contract: where a component actually runs, what bounds it, and what happens when it
misbehaves.

A component runs in `kr-plugin-host`, one process per environment, started when a binding first
needs one. A worker never links the engine. It registers a binding with that process and keeps its
own ledger, so a component that traps costs its binding and nothing else.

```text
kr-controller ──start job──▶ service manager ──▶ kr-plugin-host ──▶ component instance
      │                                               ▲
      └──rendezvous, descriptor─────────────────────── │
                                                       │
kr-worker ──register, deliver, call, unbind ───────────┘
```

## Why a separate process

A worker owns a shell, a pseudo-terminal, an approval ledger and a person's session. A component is
vendor code compiled from a catalogue. Putting the second inside the first would make a trap in
somebody's arithmetic a risk to somebody's work.

With the split:

- a plugin-host crash invalidates rich bindings and kills no worker;
- no request is lost, because requests live in the worker's broker and were never in the other
  process;
- a control-daemon restart does not interrupt a binding, because the host is its own job;
- an environment whose shells never use a component has no plugin process at all.

The last one is worth stating plainly: nothing here starts until an application that uses a component
has been matched. An idle shell costs no engine, no instance, no compiled cache and no threads.

## The engine

Wasmtime 48.0.2, pinned to that exact release. The pin is part of the compiled-code cache key rather
than a convenience: an artefact one engine produced is not one another engine can load.

`wasmtime-wasi` is not linked. The linker holds four interfaces, all from the SDK's WIT package:

| Interface | What it offers |
| --- | --- |
| `source-events` | the immutable bytes behind a handle this call was given, and their provenance |
| `upstream` | facts about the bound execution, and no function that sends |
| `attachments` | completed attachment handles, never bytes, never an upload |
| `document` | nodes from the closed union, bounded per call |

There is no filesystem, network, process, environment, clock or random import to grant, because
there is nothing to grant it from.

## The import check

Before a component is instantiated, its own type is inspected and every import is compared with that
list. An import outside it is refused with the import named, so a publisher sees which one:

```text
the component imports wasi:filesystem/types@0.2.9, which is not one of the four plugin host
interfaces; a component has no filesystem, network, process, environment, clock or random access
```

The check runs on the compiled component, not on the manifest. A manifest says what a publisher
declared; the component type says what the code asks for.

### Building a component that passes it

This matters more than it looks, because the default way to build a Rust component does not pass.
`cargo build --target wasm32-wasip2` against the standard library produces a component that imports
`wasi:cli/environment`, `wasi:cli/exit`, `wasi:io/streams`, `wasi:clocks/monotonic-clock` and
several more, whether or not a line of the source calls them: they come from the standard library's
own start-up and panic paths.

A component that imports only the contract is `no_std` with `alloc`, and supplies four things of its
own: a global allocator, a panic handler, `cabi_realloc` and `memcmp`. The test components under
`fixtures/plugins/components/` are built that way, and `fixtures/plugins/components/support/` is the
twenty lines that supply them.

## What each call may spend

Two bounds per call, measuring different things.

| Export | Elapsed deadline | Instruction allowance |
| --- | --- | --- |
| `bind` | none of its own; runs under the compilation budget | the setup allowance |
| `observe` | 10 ms | 10 × the fuel rate |
| `prepare-action` | 10 ms | 10 × the fuel rate |
| `decode-request` | 50 ms | 50 × the fuel rate |
| `encode-response` | 50 ms | 50 × the fuel rate |
| `snapshot` | 100 ms | 100 × the fuel rate |
| `checkpoint` | 100 ms | 100 × the fuel rate |
| `restore` | 100 ms | 100 × the fuel rate |

The deadline is enforced with Wasmtime's epoch interruption. A thread advances the engine's epoch
once a millisecond while a call is in flight, and sleeps when none is, so a host serving idle shells
has no thread waking a thousand times a second on its behalf. The counter tracks **elapsed time**
rather than the number of times that thread woke up: each pass advances the epoch to where the
monotonic clock says it should be, so a thread the scheduler kept waiting makes a deadline fire late
by the length of its own delay and never by more.

The instruction allowance is enforced with fuel. **Fuel is a work bound, not a measurement of
processor time.** The two are not competitors: the deadline is what stops an ordinary call that is
taking too long, and fuel is the ceiling on how much work one call can ever do, which holds even
when a loaded machine delivers the epoch late. The figure is 100 million units per millisecond of
deadline, measured rather than guessed: at 2 million per millisecond fuel was stopping calls that
were inside their deadline, at 20 million the two bounds were close enough that which one fired
depended on how busy the machine was, and at 100 million the deadline is reliably first while the
ceiling is still about an order of magnitude away rather than unreachable.

The failure says which bound ran out, and a fuel exhaustion is never described as a duration. A host
that could not start the epoch thread at all refuses to run a deadlined call rather than running one
it cannot bound, and reports that as its own failure rather than the component's.

### Per instance

| Bound | Value |
| --- | --- |
| Linear memory, across every memory the instance has | 64 MiB |
| Output per call, across the document and the returned value | 1 MiB |
| Largest single document node | 1 MiB less 8 KiB |
| Cost of one node before its contents | 64 bytes |
| Document nodes per call | 4096 |
| Linear memories | 8 |
| Tables | 32, of at most 100 000 elements each and 400 000 between them |
| Core instances | 64 |

Two of those are worth spelling out, because a looser reading of each would leave the bound doing
nothing.

**Per instance, not per memory.** A component may create several linear memories. A limiter that
checked each one against 64 MiB would let eight of them reach half a gigabyte between them, so the
limiter tracks the total across the store and refuses the growth that would take the total past the
bound. Table elements are counted the same way.

**One output budget, not one per kind.** A call's output is its document nodes *and* the value it
returned. A checkpoint, an encoded response and a decoded projection are all bytes the host holds
and the protocol carries; a budget that covered only the document would bound the smaller half. A
node also costs a fixed 64 bytes before its strings are counted, because a component that emitted
millions of empty nodes would otherwise emit them for nothing.

A node is bounded below the call budget because a control frame is 1 MiB including its envelope, so
a node that fitted the budget exactly would be a node the protocol could not carry. A component with
more to say emits more nodes, which is what the node union is for, and a document of many nodes is
sent as however many frames it takes rather than as one frame that would be refused. The value a
call returns is bounded the same way: a checkpoint the runtime admitted is a checkpoint one frame
can deliver.

A refused allocation is recorded rather than only returned, so the failure can name the resource. A
component that asked for a gigabyte and one that divided by zero both arrive as traps, and without
the record they would produce the same disabled reason. A refusal is recorded only when this host's
bound was the reason: a module whose own declared maximum is smaller is refused by that maximum, and
saying "over its bound of 67108864" about it would be untrue.

## The observation queue

One bounded queue per binding, 4 MiB. Offering an event to it never waits and never runs a
component: the producer hands over the bytes and carries on, whatever the component is doing. That
is the structural form of section 11's rule that PTY draining, terminal-query responses and the
presentation queues never wait for an observation callback.

Overflow is explicit. The oldest observations are evicted, a gap naming how many events and bytes
went is reported, and the component is asked for a fresh snapshot before anything it emits is
trusted again.

An authoritative native request is never evicted to make room for anything. If one cannot be
admitted even after every ordinary observation has gone, the admission is refused instead: the
broker still holds the request and its proven native path, and what is unavailable is the rich
interpretation of it rather than the request. A dropped request would be a decision nobody made.

## What happens to a document nobody is reading

Three bounded queues stand between a component and a worker that has stopped reading, and none of
them grows: the binding's own event channel, the connection's notice queue in the host, and the
client's notice queue in the worker. Each drops presentation and keeps the rest.

A component must not be blocked because a socket is slow, and a reader that has stopped reading must
not be able to make either process grow without bound. So a full queue means the oldest documents go,
the loss is reported as a gap with no events named, and the component is asked to rebuild its view,
which is the same answer a lost observation gets.

A fault and a disabled notice are never dropped: those two are the ones a reader cannot infer from
anything else. What keeps that from being a hole in the bound is that their text is clipped where it
is built and a connection holds a bounded number of bindings, each of which faults a bounded number
of times before it is disabled. The binding's thread does wait for room to report one, and it waits
for two seconds and no longer; after that it disables the binding itself, which is what the notice it
could not deliver would have asked for.

The binding's own channel is bounded in places: 256 of them, of which the last eight are the
must-arrive events' and presentation may not take them. The two the service keeps -- one in the host
per connection, one in the worker's client -- are bounded in bytes, and that bound covers the record
of what has already been dropped as well as what is waiting. In those two, losses coalesce into one
record per binding, so a reader that stopped reading cannot be given a backlog of gaps either, and a
document is dropped whole: every piece of it that is waiting goes together, and the pieces of it that
have not arrived yet are dropped as they arrive, whether they were dropped to make room or refused
for want of it. Half a document would tell a reader it had a whole one. The queue remembers which
documents went until their last piece has been accounted for or until their binding goes. That
record is counted rather than measured: past 256 unfinished ones the connection ends, because
forgetting one would mean delivering the end of a document without its beginning. A fault and a disabling are never dropped; if even those will not fit once every document has
gone, the connection is over, because a connection whose reliable news cannot be delivered is not one
worth keeping open.

A document the host's queue dropped is one the component is asked to draw again, and the ask goes to
the binding the lost document belonged to -- not always the binding whose document made room for
another. A document the *worker's* queue dropped is reported to the worker as a gap; asking for a
fresh one is then the worker's, because only the worker knows whether it still wants that binding's
presentation.

A binding also holds a bounded number of unanswered calls. A caller whose deadline ran out has
stopped waiting, but its request is still on the binding's thread until that thread reaches it, and
the thread skips the ones whose callers have gone rather than spending a call's budget on an answer
nobody will read.

## Faults

Three faults within one minute disable the binding, with the reason a person reads.

A fault is a trap, an exhausted bound, a refused allocation, an attempt to emit past the output
budget, or a handle the call was not given. A component that returns `refused`, `unreadable`,
`not-permitted` or `exhausted` has *answered*: it read the input and declined, and that is never a
fault. Nor is a slow compilation, and nor is a caller's own deadline.

The window is measured on the machine's continuous clock, which counts a suspend. A laptop that
faults twice, sleeps for an hour and faults once more has faulted three times in an hour.

A trap is terminal for a component instance: the component model admits no further entry into one.
So a faulted instance is replaced from the component that is already compiled, `bind` runs again,
and the binding asks for a snapshot, because the replacement has no presentation state. That is what
makes the first two faults survivable rather than merely counted.

The replacement is told what the host holds *now*: the current binding revision, the current rights
and the attachments the draft holds, not the ones the binding was created with. It is bound to the
current revision too, because binding a replacement to a revision that has moved on would have it
presenting one execution's state against another's. And the snapshot comes before anything else is
delivered: the rest of an observation batch stops at the fault and resumes after the snapshot, so
nothing is interpreted against a document that no longer exists.

The snapshot obligation is a number rather than a flag. A snapshot that was already running when a
new gap appeared discharges the obligation it was asked for and not the new one, because it cannot
have seen what the new gap lost.

## Compilation

Lazily, at binding preparation, on a background pool, under its own budget:

| Bound | Value |
| --- | --- |
| Largest component compiled | 16 MiB |
| Compilation budget | 30 s |
| Concurrent compilations | 2 |
| Queued compilations | 8 |

A component past the size bound is refused before any work starts. A compile that finishes outside
its budget has its result discarded and reports the figure. A pool whose queue is full refuses the
next request rather than starting a hundred compiles.

No call deadline contains a compile. The two steps are separate in the API for that reason: a
component is compiled, and only then is an instance created and a call budget started. Instantiation
and `bind` run on the binding's own thread rather than a caller's, and the caller's own deadline
covers the whole preparation: the compile, the instantiation and `bind` together.

The time half of the budget is a threshold on accepting a result rather than a cap on the work.
Cranelift cannot be interrupted part way, so an over-budget compile has its result discarded and
reports the figure; what bounds the resources already spent is the size bound and the pool's fixed
threads and bounded queue.

Each pool thread lowers its own scheduling priority when it starts, through the platform's own
thread scheduling. What that means is the platform's answer, and a platform that declines is not a
failure, because the compile still runs off the hot path, which is the property that matters.

## The compiled-code cache

Compiled machine code is filed under three things, all three necessary:

| Part | Why |
| --- | --- |
| the Wasm digest | different code compiles to different machine code |
| the engine's compatibility identity | a different engine expects a different artefact |
| the target | machine code for one instruction set is not machine code for another |

A component this process compiled or loaded once is kept in memory, up to thirty-two of them, so a
second binding of the same package neither compiles nor reads a file. For those, no question of
provenance arises at all.

For the rest, a serialised component is machine code. Reading one back is equivalent to loading a
shared library, and it is worth being exact about which question the manifest beside it answers.

**Which artefact is this?** The manifest answers that, and every answer is checked:

- the digest of the Wasm the caller is asking for, so an artefact filed under one component cannot
  be served for another;
- the engine's compatibility identity and the target, so an artefact another engine or another
  instruction set produced is refused rather than loaded and trusted;
- the artefact's own digest and length, checked against the bytes the host then hands to the
  engine: the same bytes, read once, not the file reopened afterwards;
- a marker saying a local compilation produced it, so an artefact that arrived any other way is a
  miss rather than a load.

**Could somebody put machine code here on purpose?** The manifest does not answer that, and no
manifest could: every field in it is one a writer of the directory could produce. What answers it is
the directory, which is the owner's own and nobody else's. A process that can write there runs as
this user and can replace the plugin host's own executable, so the cache is not where that boundary
is drawn and this host does not pretend otherwise.

What the checks do buy, on top of the directory, is that a *downloaded* artefact cannot become a
cache entry by accident or by being dropped in: a payload fetched from a catalogue has no manifest,
and one filed under a digest the caller did not verify is refused by name. Section 11's rule is that
a downloaded native-code cache is never deserialised as validated Wasm, and that is the rule these
checks keep.

An entry that fails any check is removed and the component is compiled again, because a refused
entry is a reason to recompile rather than a reason to refuse the binding.

## The service

One process per environment, `kr-plugin-host`, started by the control daemon through the same
supervisor trait a worker is started through: a launchd job, a systemd transient user service, or a
detached process, in each case its own job outside the daemon's kill tree.

### What proves which process is answering

Four things, none of which substitutes for another:

| Proof | Who provides it | What it settles |
| --- | --- | --- |
| the owner-only runtime directory | the filesystem | another user cannot reach the socket |
| peer credentials | the kernel | the caller on the socket is this user |
| the rendezvous | the host, once at startup | this process is the one the launcher started |
| a verification challenge | the host, on demand | the process answering this endpoint is that one, now |

The host generates an Ed25519 keypair at startup and keeps the private half in memory for its whole
life. It is never written to disk, placed in an argument vector or put in an environment variable, so
nothing that is not that process can answer for it even with full access to the runtime directory.

The launcher records the process identity the service manager reported *before* the host connects,
and compares it with the connecting peer as the kernel names it, with what the claim says, and with
the boot this launcher is running in. A peer the kernel will not name is refused rather than taken on
the strength of a signature. Each launch also has a rendezvous address of its own, named after its
reservation, so a claim can never arrive on an address two launches meant.

The deadline covers receiving and checking the claim, publishing the descriptor and acknowledging
it -- not merely accepting a connection. Publication is the one step a timer cannot interrupt: a
write, a flush and a rename finish whether or not anybody is still waiting. So it is fenced as well
as bounded. Each launch takes its environment's publication turn, holds it from the check to the
rename, and writes nothing if a later launch has taken it; a publication this launcher gave up on
therefore cannot replace the descriptor its successor published. A peer that connects and then says nothing does not hold a
startup open, and a refused claim does not end the wait: the launcher keeps listening until its
deadline and reports the last refusal if nothing better arrives.

One reservation is one host, and the launcher keeps it that way by holding the reservation's own
endpoint for as long as the host it started is running. A second claim reaches that and nothing
else: it is accepted, dropped without a word, and counted, so two processes claiming one reservation
is something a host can see rather than infer. Giving the fence up is what a launcher does when the
host is gone, and the address becomes available again for the next launch.

The host binds the endpoint workers will use *before* it reports itself and holds that listener until
it serves. A bind, a release and a second bind would let another launch win the endpoint between
them, and the descriptor the daemon published would then name the process that lost. The host also
waits to be told its claim was accepted before it serves anybody: a host answering workers before the
daemon had accepted it would be serving as a process the daemon might still refuse.

On success the launcher publishes an owner-only descriptor at `plugin-host.json` in the environment's
runtime directory. A worker reads it, challenges the process behind the endpoint, and talks to that
process directly. Nothing in the descriptor is acted on before the challenge: a filename and a
process identifier are hints.

### What a worker sends

KR-CBOR-1 objects in the host's own length-delimited frames, one closed union in each direction.
Every request carries a number the response echoes, because the host also sends document nodes,
gaps, faults and disabled notices as they happen: a frame with a `reply_to` is somebody's answer, and
a frame without one is news.

| Request | What it does |
| --- | --- |
| `hello` | opens the connection and names the protocol |
| `verify` | asks the host to sign a fresh challenge |
| `register_binding` | compile the component, instantiate it, call `bind` |
| `event` | offer one scoped source event to the binding's queue |
| `snapshot` | ask the component for a fresh document |
| `checkpoint` | take the component's own resumable state |
| `restore` | restore it |
| `unbind` | remove the binding and its instance |
| `health` | ask what the host is doing: live bindings, this connection's own and its bound, the compiled components the cache holds and what they cost, the notice bytes waiting and the documents dropped |

A binding belongs to the connection that registered it. Another connection that has the identifier
finds no binding, which is the same answer it would get for one nobody ever registered, and a
connection that ends takes its own bindings and nobody else's, once whatever it had running has
finished.

A document travels as its own frames, chunked so each fits one, and every piece names the document it
belongs to; only the last is marked as the last. That is how a reader knows which notices go together
and when it has all of them, and a document that cannot be delivered whole is dropped whole rather
than leaving a reader with pieces it cannot tell are incomplete. A response carries no nodes: it
names the document number the call drew instead, or nothing at all when the call drew nothing.

An observation is answered on the task that read it, because it enters no component: it is a queue
push. Everything that can enter a component runs in a task of its own, so reading the next request
never waits for the last one to finish. A connection holds up to sixteen such calls at once and up
to sixty-four bindings; past either, the next request is refused rather than queued.

The rich calls a broker makes in process -- `prepare-action`, `decode-request`, `encode-response`,
and revising a binding's facts and attachments -- are not in this protocol yet. They are in the
runtime crate's own API, which is where the broker task will find them; what travels between a worker
and the host today is the set above.

A component's bytes travel as a location rather than as a payload: a control frame is bounded at
1 MiB and a component may be sixteen times that. The worker sends the payload's path and the digest
it verified against the catalogue, and the host checks the file against that digest before compiling
anything. The path has to be inside the packages directory the host was started with; one outside it
is refused by name.

## Where the broker fits

Nothing here decides whether an effect happens.

`prepare-action` returns a plan. `decode-request` returns a projection. `encode-response` returns
bytes. In each case the broker then checks the actor, the grant, the binding revision and the
declared effect class, and claims and dispatches. Pending and dispatch state lives in the worker's
broker ledger, never in a component and never in the plugin host, which is why a plugin-host crash
cannot destroy an approval ledger.

The broker lives in `crates/kr-worker/src/broker`, and it builds on the API in
`crates/kr-plugin-runtime`: prepare a binding, offer events to its queue, invoke a control, ask for
an interpretation, take a checkpoint, unbind. `docs/host/README.md` has its whole contract; what
matters from this side is the order:

1. The broker records the opaque native request **before** it forwards it, and forwards it whether
   or not any component is healthy.
2. A component's `decode-request` returns a projection. The broker checks the binding's
   approval-interpreter grant, the decoding-trust record that names *this* package at *this*
   digest, the method that record covers, the projection's schema version and decision count, the
   source frame's generation, and that this source event has not already produced an
   interpretation. Only then does the request become something a person can answer.
3. A component's `encode-response` returns bytes. The broker rechecks the resource's own state and
   deadline, the instance, the source generation and the decoder's right to answer, checks the
   decision against the ones the request actually offered, commits the dispatch marker, and only
   then may the answer go.

What is not joined up yet is the hand-over in either direction: the plugin host invokes the
component's exports, and passing the broker's action token into that invocation and its projection
back out is the work that joins the two crates. Until it lands, the broker's own suites drive the
checks and the plugin host's drive the calls.

A component that is faulted, disabled or slow changes none of step 1. That is the whole of the
separation: rich meaning is a thing the broker asks for, and the native path does not wait for the
answer.

Offering an event never waits at all. Every call carries the caller's own deadline and returns when
it runs out, so nothing on the terminal path can end up behind a component. `unbind` is the one that
blocks: it waits for the binding's thread so that a caller knows the instance has stopped before it
drops what the instance was using, and the wait is bounded because the call the thread is finishing
is bounded. The plugin host runs it off its executor for that reason.

Dropping the *last* handle signals the thread rather than waiting for it, which is what makes a
handle safe to drop anywhere. Dropping one a caller holds stops nothing on its own: the runtime
holds a handle of its own until the binding is unbound or its owner goes, and only the last one to
go signals the thread.

## The package that ships with the host

A fresh installation has no repository. It still has to recognise an application, present it and
activate a package, so one package travels with the host: `bundled-plugins/fixture`, which is
`kalareach/example-declarative` 0.1.0, and `bundled-plugins.lock`, which names it.

The lock is the evidence beside the bytes. It carries the package identifier, the version, the SDK
and WIT ranges the manifest declares, the digest and exact length of the manifest and of every
payload, the total the package adds up to, the trust root the chain was verified against, and the
repository, commit, generation and tree address the copy was made from.

The two checks happen at different times, on purpose.

| When | What is checked | By what |
| --- | --- | --- |
| Making the copy | The whole TUF chain: root, timestamp, snapshot, targets, every target's digest and length, expiry enforced | `scripts/sync-bundled-plugins.sh`, through the catalogue tool the plugin repository publishes |
| Using the copy | Every byte against the digest and length the lock names | `kr_plugin_sdk::bundle`, on every activation |

A host reading a bundled package has no repository to re-run a chain against: the metadata, the
mirror and the delegations are all behind the network it has not got. What it can do is recompute
the digest of every byte it is about to use, and refuse anything that is not what the lock names. That is what `BundleLock::activate` does: it opens
the package directory relative to a `cap_std::fs::Dir` handle the caller supplies, reads and
verifies every file, and only then parses anything. A package whose files do not all verify does
not activate at all, so nothing half-read reaches a caller, and a payload the lock does not name
answers `PACKAGE_UNAVAILABLE_OFFLINE` rather than a capability nobody could perform.

Absence and tampering are answered apart. A file that is simply not there is
`PACKAGE_UNAVAILABLE_OFFLINE`, because there is nowhere to fetch it from. A file that is there and
is not what the lock names, including a link in place of one, is `REPOSITORY_UNTRUSTED`: a host that
reported that as "try again when you are online" would retry for ever.

### What the bundle does not promise

It is one package of one generation, frozen at the commit it was copied from. It is not a
catalogue: nothing about it searches, fetches, updates or decides that a newer generation exists,
and the generation it names does not become the host's enrolled repository. Its trust root is the
development root the plugin repository publishes for exactly this purpose: a signature under that
root says the bytes are the ones that root's keys signed, and says nothing about who may run them.
The package's capability requests, its grants and its repository ceiling are applied to it exactly
as they are to anything installed.

Reading it needs no current metadata and no trusted clock, which is the point: a pinned package
stays usable offline under the grants it already has, whatever has expired elsewhere. A new
generation is a different matter and needs metadata that has not expired, which is the catalogue's
concern rather than the bundle's.

### Changing what is bundled

`scripts/sync-bundled-plugins.sh` makes the copy. It takes the plugin repository checkout and the
commit to pin (the lock's own commit by default), exports that commit into a private directory of
its own, verifies the chain there, resolves each payload by the digest the verified metadata pins,
and stages the package beside the published entry. It refuses a checkout that is not at the pin, a
link anywhere in the exported generation, an unsafe path, two names that are one file, a payload
that is not the exact length the metadata pinned, and an entry already published that the lock on
disk does not describe. It executes nothing out of the package, and it holds a directory lock so two
runs cannot publish at once.

Publishing is three renames: the published entry moves aside, the staged package takes its name, and
the new lock replaces the old one. Each is a rename, so the published name holds a whole package
before and after every step and never a mixture of two. It is not a single atomic replacement: POSIX
has no directory swap, so between the first two renames the name is absent.

What an interruption leaves depends on what kind it was. A failure, a `SIGINT` or a `SIGTERM` runs
the script's own cleanup. If nothing was published, it puts the previous package back and drops the
new lock. If the package was published and the lock was not, it leaves the new package, the previous
one and the new lock all on disk and prints where each is, because guessing which a person wanted
would be worse than telling them. Once the lock is installed the previous package is no longer
anything, and cleanup removes it.

A `SIGKILL` or a power cut runs nothing, and cleanup can itself fail on a full disk. What is on disk
then is whichever renames had happened, under names that say what they are: a `.retiring.` directory
is the package that was published before, and a dotted pending lock beside `bundled-plugins.lock` is
the one that was about to replace it. `--verify` says whether the package and the lock agree, which
is the question worth answering; it does not replay what the run was doing.

`scripts/sync-bundled-plugins.sh --verify` is the offline half: it recomputes every digest under
`bundled-plugins/` against the lock and reports any drift, including a file, a directory or a whole
package that is there and is not in the lock. It reaches no network, builds nothing and needs no
plugin repository, which is why it runs in continuous integration.

## Capability ceiling and installation grants

Section 11 establishes the repository ceiling to bound what packages can do without explicit
permission. When evaluating what a requested capability requires, the SDK's stricter rule governs:
the capabilities `terminal.input`, `filesystem.read`, `network.outbound`, `approval.decode`, and
`approval.respond` require an explicit installation grant even where an explicit repository grant
exists.

| Capability | Requirement |
| --- | --- |
| `metadata.match`, `presentation.declarative`, `broker.semantic_events` | Within default ceiling (enrolment already permits) |
| `terminal.stream`, `terminal.transcript_tail`, `process.observe`, `upstream.action` | Explicit repository or installation grant |
| `terminal.input`, `filesystem.read`, `network.outbound`, `approval.decode`, `approval.respond` | Explicit installation grant required (repository ceiling cannot satisfy) |
| `native_bridge.install` | Confirmed installation grant (owner confirmation required) |

The specification's "package or repository grant" names the ceiling's source, and the stricter check
never grants more than either. An increase over what the previous installation held also requires an
installation grant.
