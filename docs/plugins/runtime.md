# Running a plugin component

`docs/plugins/README.md` says what a package is and what its component may do. This is the other
side of the same contract: where a component actually runs, what bounds it, and what happens when it
misbehaves.

A component runs in `kr-plugin-host`, one process for each plugin host protocol and environment,
started when a binding first needs one. A worker never links the engine. It asks the control
daemon for the process, registers a binding with it and keeps its own ledger, so a component that
traps costs its binding and nothing else.

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

The split has these consequences:

- a plugin-host crash invalidates rich bindings and kills no worker;
- no request is lost, because requests live in the worker's broker and were never in the other
  process;
- a control-daemon restart does not interrupt a binding, because the host is its own job;
- an environment whose shells never use a component has no plugin process at all.

The last one is worth stating plainly: nothing here starts until an application that uses a component
has been matched. An idle shell costs no engine, no instance, no compiled cache and no threads.

## The engine

The engine is Wasmtime 48.0.7, pinned to that exact release. The pin is part of the compiled-code
cache key rather than a convenience: an artefact is filed under the release that compiled it, and a
release reads only its own.

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

This is not a formality, because the default way to build a Rust component does not pass.
`cargo build --target wasm32-wasip2` against the standard library produces a component that imports
`wasi:cli/environment`, `wasi:cli/exit`, `wasi:io/streams`, `wasi:clocks/monotonic-clock` and
several more, whether or not a line of the source calls them: they come from the standard library's
own start-up and panic paths.

A component that imports only the contract is `no_std` with `alloc`, and supplies four things of its
own: a global allocator, a panic handler, `cabi_realloc` and `memcmp`. The test components under
`fixtures/plugins/components/` are built that way, and `fixtures/plugins/components/support/` is the
twenty lines that supply them.

## What each call may spend

Each call has two bounds, measuring different things.

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

Each binding has one bounded queue, 4 MiB. Offering an event to it never waits and never runs a
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

The worker has a lane of its own in front of this queue, with the same bound and the same rules, so
that the terminal's read loop and the gateway's reader never wait for the connection to the host
either. `What a worker observes`, below, describes it.

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
must-arrive events' and presentation may not take them. The two the service keeps (one in the host
per connection, one in the worker's client) are bounded in bytes, and that bound covers the record
of what has already been dropped as well as what is waiting. In those two, losses coalesce into one
record per binding, so a reader that stopped reading cannot be given a backlog of gaps either, and a
document is dropped whole: every piece of it that is waiting goes together, and the pieces of it
that have not arrived yet are dropped as they arrive, whether they were dropped to make room or
refused for want of it. Half a document would tell a reader it had a whole one. The queue remembers
which documents went until their last piece has been accounted for or until their binding goes. That
record is counted rather than measured: past 256 unfinished ones the connection ends, because
forgetting one would mean delivering the end of a document without its beginning. A fault and a
disabling are never dropped; if even those will not fit once every document has gone, the connection
is over, because a connection whose reliable news cannot be delivered is not one worth keeping open.

A document the host's queue dropped is one the component is asked to draw again, and the ask goes to
the binding the lost document belonged to, not always the binding whose document made room for
another. A document the *worker's* queue dropped is reported to the worker as a gap; asking for a
fresh one is then the worker's, because only the worker knows whether it still wants that binding's
presentation.

A document the host withholds because privacy mode stands is not one a queue dropped for want of room,
and no gap is owed for it while it is withheld (see "Privacy mode at the host").

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

Compilation runs lazily, at binding preparation, on a background pool, under its own budget:

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
failure, because the compile still runs off the hot path, which is the property the design is after.

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

One process for each protocol and environment, `kr-plugin-host`, started by the control daemon
through the same supervisor trait a worker is started through: a launchd job, a systemd transient
user service, or a detached process (which on Windows is created outside the daemon's
kill-on-close job), in each case its own job outside the daemon's kill tree.

The daemon starts it when a worker asks and not before. The request travels on the daemon's
rendezvous endpoint, after the hello a worker sends there, as a `PluginRuntimeWanted` frame naming
the session, and the answer is a `PluginRuntimeState`: running, or unavailable with a reason and how
long to leave before asking again. The daemon answers only the process it recorded for that
session, as the kernel names it now. A worker that sends the request before the daemon has recorded
it is told to ask again.

The daemon's holder for the runtime is idle, starting, running or failed. A request in idle first
looks at the descriptor a previous daemon published: a runtime that answers a challenge is kept,
one whose process has ended is retired, and one whose process is running and does not answer is
answered as unreachable for ten seconds. A descriptor whose content this build refuses (another
protocol, another environment, not a descriptor) is retired; one that cannot be read at all, a link
or a file another account could write, is left in place and answered as unreachable. Otherwise
the daemon starts one, every request that arrives meanwhile waits for that one attempt, and an
attempt that fails is answered from memory for ten seconds. At most five runtimes are started in
ten minutes. A runtime in running is judged by the kernel's account of its process, not by whether
a descriptor exists, and one the daemon did not start is adopted without a fence. Nothing here ends
a process: a runtime that has stopped answering stays until it ends.

### What proves which process is answering

There are four proofs, none of which substitutes for another:

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
it, not merely accepting a connection. Publication is the one step a timer cannot interrupt: a
write, a flush and a rename finish whether or not anybody is still waiting. So it is fenced as well
as bounded. Each launch takes its environment's publication turn, holds it from the check to the
rename, and writes nothing if a later launch has taken it; a publication this launcher gave up on
therefore cannot replace the descriptor its successor published. A peer that connects and then says
nothing does not hold a startup open, and a refused claim does not end the wait: the launcher keeps
listening until its deadline and reports the last refusal if nothing better arrives.

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

On success the launcher publishes an owner-only descriptor in the environment's runtime directory,
in the file the host's protocol names: `plugin-host-3.json` for `kr-plugin-host/3`, and
`plugin-host.json` for `kr-plugin-host/2`, the protocol the release before speaks. A worker reads
the descriptor of its own protocol, challenges the process behind the endpoint, and talks to that
process directly. Nothing in the descriptor is acted on before the challenge: a filename and a
process identifier are hints.

### What a worker sends

The wire carries KR-CBOR-1 objects in the host's own length-delimited frames, one closed union in
each direction. Every request carries a number the response echoes, because the host also sends
document nodes, gaps, faults and disabled notices as they happen: a frame with a `reply_to` is
somebody's answer, and a frame without one is news.

| Request | What it does |
| --- | --- |
| `hello` | opens the connection, names the protocol and says which later requests the host answers |
| `verify` | asks the host to sign a fresh challenge |
| `register_binding` | compile the component, instantiate it, call `bind` |
| `event` | offer one scoped source event to the binding's queue |
| `snapshot` | ask the component for a fresh document |
| `prepare_action` | ask the component to turn an invoked control into a proposed effect |
| `checkpoint` | take the component's own resumable state |
| `restore` | restore it |
| `unbind` | remove the binding and its instance |
| `health` | ask what the host is doing: live bindings, this connection's own and its bound, the compiled components the cache holds and what they cost, the notice bytes waiting and the documents dropped |
| `decode` | ask the component to interpret one native request the broker retained |
| `encode` | ask the component to encode a decision the broker validated as the bytes of a response |
| `revise_facts` | replace the facts the component reads about its binding's bound execution |
| `revise_attachments` | replace the attachments the component reads the current draft as holding |
| `privacy` | tell the host whether privacy mode stands for the worker this connection serves |

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

`prepare-action`, `decode` and `encode` are the rich calls this protocol carries. Each is answered by
what the component returned, as plain data, or by the fault it declared. A worker sends
`prepare-action` the invocation's token (the actor, the grant record, which is empty for the local
owner, the binding revision, the action and the hash of the parameters a person saw) and the arguments
in the order the action declares them, and is given back the plan the component proposed. It sends
`decode` the native request as the broker retained it, with the provenance it recorded and the
identifier the upstream gave, and is given back the identifier the component says the request has, its
class for the method, a one-line summary, the decisions it says are offered and the nodes that
present the request. It sends `encode` the broker's own record of a pending request, the decision it
validated and, where it still holds it, the request's source event, and is given back the bytes of a
response with the identifier of the request the component says it answers. A component sends nothing
in any of the three: the answer is a value, and the host has no way to put it anywhere but in the
reply.

`revise_facts` and `revise_attachments` do not enter a component. They are answered when the host has
accepted them, on the task that read them, and a revision is what the binding's next call reads: one
no call has yet seen is replaced by a later one, and a call already inside the component does not see
it. The facts are the ones registration carries, and the plugin they name is the one the binding
serves. A worker is not required to send either; the facts a binding is registered with are the ones
its component reads until a revision replaces them.

`privacy` is answered on the reading task as well, once the host holds what it was told (see "Privacy
mode at the host").

A worker and a host speak one protocol, which the host names in its `hello` answer and in its
descriptor (`kr-plugin-host/3`; the request that prepares an action came with the second protocol,
and the third has the requests the second has and the five that decode, encode, revise a binding's
facts and attachments and tell the host about privacy mode). A host of another protocol is refused at
the handshake, by name, because a host ends the connection, and every binding on it, over a request
it does not know.

### What is fixed with a protocol

Every frame of `kr-plugin-host/3` is closed before its first release, because nothing records the
frames of a released host protocol other than its name, and a request, a response or a notice
variant, or a member added to a record of one, would meet a worker or a host of the release before
that adopted it: it ends the connection, and every binding on it, over a frame it cannot read. A
change to a frame, or to one of the rules a host reads a request under, takes a new protocol. The
rules are these.

- The reading task answers `hello`, `verify`, `event`, `health`, `revise_facts`, `revise_attachments`
  and `privacy` without entering a component. The other requests that name a binding run in a task of
  their own and take a place from the connection's sixteen. A connection holds sixty-four bindings,
  and a request past either bound is refused and not queued.
- A call's own deadline is from 1 to 30,000 ms. A `decode` or an `encode` event is at most the
  largest document node a frame carries, has the provenance `native_protocol` and carries the
  identifier the upstream gave: an event that is a scrape or names no request is refused before any
  component runs. An `encode` names a decision among the request's offered decisions (at most 16, of
  at most 256 bytes), and its event, where it has one, is the source of the request being answered,
  with the same handle and identifier. A request, a method, an identifier or a decision is at most
  256 bytes.
- Facts have strings of at most 1 KiB, at most 64 held rights and the plugin identifier the binding
  was registered with, and the facts of a registration are held to the same bounds. A draft's
  attachments are at most 64, with an identifier and a media type of at most 256 bytes and a name of
  at most 1 KiB.
- An answer to `encode` that names another request than the one it was asked about is refused by the
  host. The identifier a `decode` names is not: the host holds no record of requests, and the worker
  checks it against the request it holds.
- A refusal is `Refused` and disables no binding. An event offered to a binding the runtime has
  disabled is refused as a disabled binding's, and the worker stops offering it anything.
- A frame, an answer and a document node each fit one frame of a mebibyte, the envelope included.

### One host for each protocol

A host process speaks one protocol, fixed by the program that runs. Each protocol has an endpoint
and a descriptor of its own: `kr-plugin-host/2` keeps `p.sock` and `plugin-host.json`, and
`kr-plugin-host/3` uses `p3.sock` and `plugin-host-3.json`. A later protocol `/N` uses `p<N>.sock`
and `plugin-host-<N>.json`. Hosts of two protocols run side by side, and a client reads only the
descriptor of its own protocol, so it never opens a connection to the other's host.

The control daemon holds one plugin runtime for each protocol it serves: the protocol of its own
release, and each protocol a retained level recorded. A worker asks the daemon for the runtime, and
the daemon answers with the runtime of the protocol the worker's level speaks.

- A worker of the daemon's own release is served by a host of this release's protocol, started
  from the program beside the daemon.
- A worker of a retained level is served by a host of the protocol that level recorded. The daemon
  adopts such a host when one runs: a host that a daemon of that release started outlives an update
  and a rollback, because a host ends only with the login session, a restart of the machine or a
  crash. When none runs, which is the case after the host's crash and when a worker of that level
  first needs a runtime after the update, the daemon starts the `kr-plugin-host` of the release
  that worker runs, from the release store, as a job of its own beside the host of the daemon's own
  protocol. A host takes no hold on its release: after the store retires a release, a host that was
  started from it runs on from its open program. A new launch takes the program of the release the
  asking worker runs, so that worker is served by a host of its own release. A host that was
  adopted, or that the daemon started for an earlier worker, may be of another release of the same
  level, and it serves every worker of that level, since they speak one surface; the pinning of a
  worker to the release it was started with holds for the launch and not for a host that is shared.
- A host keeps no release store on Windows, and neither does a tree that is not installed in one.
  Where there is none, and no host of the retained protocol runs, the daemon starts none and answers
  that the runtime cannot be reached, with the reason, and answers the same each time it is asked.
  The terminal and every other binding of that worker carry on, and the worker's rich
  bindings are unavailable until its session ends, as they are after a crash of the runtime. This is
  the case of a worker of the release before that first needs a runtime after an update, or whose
  host has been lost; a host that runs is adopted wherever it is.
- A host that a daemon or a rollback leaves behind stays until it ends, and costs memory only. A
  rollback to the release before leaves the host of this release's protocol running, in a file the
  release before does not read, and the release before's daemon starts or adopts a host of its own
  protocol for its workers. An update again adopts the host that is still there.

The protocol a retained level recorded is one this build has a route for
(`RETAINED_PLUGIN_HOST_PROTOCOLS` in `kr-protocol`), and `kr-protocol-gen --check` fails when a
level recorded another, or when a route is listed for a protocol no retained level records. The
release that stops retaining a level removes the route of the protocol that level alone recorded.

The frames this release reads from or writes to a host of a retained protocol are the claim it
presents to its launcher, the acknowledgement, the descriptor file, and the `hello` and `verify`
requests and their answers. They are recorded from the real program, under
`crates/kr-protocol/retained/<level>/plugin-host-frames.json`, and the protocol keeps no other
reader of an earlier version. A change to a released protocol takes a new name: a request, a
response or notice variant, or a member added to any record of it after a release exists would meet
a host or a worker of that release, which the level records by the protocol's name alone.

A component's bytes travel as a location rather than as a payload: a control frame is bounded at
1 MiB and a component may be sixteen times that. The worker sends the payload's path and the digest
it verified against the catalogue, and the host checks the file against that digest before compiling
anything. The path has to be inside the packages directory the host was started with; one outside it
is refused by name.

### What a worker observes

A worker offers a component the part of its session that the installation lets it see. Three things
have to hold: the binding's package ships a component, the binding holds the observation grant, and
the installation granted the stream. `broker.semantic_events` grants the connector's own upstream
frames and `terminal.stream` grants the terminal's output. The worker reads the grants for each
entry, so a stream the owner withdraws stops with the next entry. A component is offered nothing
before the worker has registered it and made it ready, and nothing once its rich capabilities are
disabled.

| Stream | Provenance | What the component is offered |
| --- | --- | --- |
| the connector's upstream frames | `native_protocol` | the bytes of a frame whose method the connector's table lists and does not class as credential or configuration access, to the bindings of the package whose table read the connection; a request the upstream is waiting on carries the identifier the upstream gave it |
| the terminal's output | `terminal_scrape` | each span as the owner's terminal receives it, in pieces of at most 256 KiB |

A frame whose method the table does not list is not offered, because nothing says it carries no
credential. The frames and replies of the native client, the broker's own record of what it read,
and process observation are not offered either.

The producers never call the runtime. The terminal's read loop and the gateway's reader push what
they have onto the worker's observation lane and carry on. The lane holds at most 4 MiB, counting the
entry being sent. An entry that does not fit pushes out the oldest ordinary entries until it does,
and the lane counts what it lost. A request the upstream is waiting on is never pushed out. If only
such requests remain, the new entry is refused and counted, and the broker still holds the request
in its ledger with its source frame.

One task of the link, the pump, takes entries in the order they were pushed. An upstream frame goes
as an `event` the pump waits to have answered, so the answer says whether the binding's queue took
it, and the wait is bounded by the client's five seconds. Terminal output goes as an `event` the pump
does not wait for: the client queues at most 256 of them and 4 MiB, a task of the client writes them,
and a full hand-off refuses the span at once. A runtime that does not answer is passed over for ten
seconds, then for twice as long after each failure up to two minutes, and each entry passed over is
counted. The two sources have no order between them, and each keeps the order it was pushed in.

Whatever a ready component does not get is a numbered loss: an entry the lane pushed out or refused,
one the pump passed over, one the host's queue refused. What was pushed before a binding became
ready, or while the worker had no connection to the runtime, predates the binding's view and is not
a loss. The pump offers a binding nothing while it owes the binding a snapshot, so a component is
asked for a fresh snapshot before anything later is handed to it. The snapshot waits, for up to a
second, until the client has written every event it was handed, an event being counted until its
write is over; if it has not, the binding is passed over and asked again after a wait that grows.
The snapshot request is then written after those events, and the runtime reads them in that order.
Whether the component has observed them when it answers is not claimed: the runtime queues an event
when it reads it, takes the queue in batches of sixteen and may answer a snapshot request between
two batches, so the snapshot is the view of what the component held when it ran, and each
observation after it draws the view again. The lane gives the pump what it lost together with the
entry it hands over, and what it lost is older than that entry, so the pump applies the loss, takes
the snapshot and then offers the entry. The lane loses ordinary entries before it loses a request
the upstream is waiting on, and refuses an entry larger than itself whatever waits, so something
lost after a request was pushed is newer than the request: each loss goes with the first entry newer
than it, or waits for one, and the request is offered before that loss is applied. A loss that
arrives while a snapshot runs has a number of its own and asks for another. A snapshot the component
answers or declines discharges its number. One that does not reach the component is asked for again
after a wait that doubles from one second to thirty.

The link keeps three more things. When a component has been offered something since its state was
last asked for and has then been left alone for two seconds, or its last request is a minute old or
there has been none, the link asks it for a checkpoint. The worker keeps checkpoints in memory only,
at most 8 MiB in all, under the package's digest and the source generation the component was
registered in, so state taken in one generation of the instance's source is never restored into
another. When a binding is registered again, after the runtime was replaced for example, the link
restores the checkpoint it holds and makes the binding ready, owing a snapshot that the pump takes
before it offers the binding anything. The observations between the checkpoint and the new
registration are not replayed, and the component's report says so. A restore the component does not
answer is reported the same way, and the snapshot rebuilds its view from whatever it holds. A
component registered with no checkpoint to restore starts from the live point.

Every thirty seconds the link asks the runtime what it is doing. Two answers in a row that do not
come count as losing the runtime: the bindings are reported unavailable with the reason, and the link
asks the daemon for the runtime again. An event the client cannot write to the runtime within ten
seconds means the runtime has stopped reading, and the client's writer ends the connection, which
the link treats the same way.

A component's report carries how it was registered (compiled, with the time it took, or loaded from
the compiled-code cache), what it last missed, and its last fault, in the words the runtime gave.

Privacy mode does not stop observation for live use. While it is on, the worker asks for no
component state, and it holds none that was asked for before privacy mode was turned on or off.
Turning it on drops the state held. A component that was handed anything the worker had while
privacy mode was on, including something that waited in the lane and was handed over after it ended,
or whose hand-over was not answered, is marked before the hand-over and is not asked for its state
again until it starts again, since what it holds may be what it was handed.

The runtime's words in a fault, and in the reason a component is disabled for, are withheld from the
report once privacy mode has been on at any time since the worker made the connection to the runtime
that carries them, and until it makes another. The connection decides it, not the notice: any
component on it may have been handed something while privacy mode stood, by an observation, a
restore or an action, and its words can be made of what it was handed. So every notice about every
component on the connection is withheld, however many wait and however late each is read. A
connection made while privacy mode is on is withheld from its start, and so is one that a component
is handed something made in privacy mode on. The documents a component draws are read and dropped
by the worker, in privacy mode as at any other time, and the host does not send them in privacy mode
(see "Privacy mode at the host").

### Privacy mode at the host

The worker tells the host whether privacy mode stands, with a `privacy` request, and tells it again
each time that changes. It tells a new connection once, before it publishes the connection and before
it registers anything on it, so that the first document `bind` draws is judged by privacy mode as it
stands; after that one task of the link sends the changes, in the order they were made.

While the host holds that privacy mode stands on a connection, it writes no document notice on it,
and it sends the nodes that present a decoded request empty. A document is a component's drawing of
what it was handed, and in privacy mode nothing that was made of the session's content crosses the
boundary of the host's process or waits in its queue for a reader that may not come. The host
answers a `privacy` request holding the connection's writer: it sets the flag, drops the documents
its queue holds and writes the answer, and its notice writer checks the flag holding the same writer
before it writes a document. So every document frame of a connection is before the answer in the
stream or is never written, whichever of the two tasks reached the writer first.

A document the host withholds is not one it lost for want of room, so nothing is owed for it while it
is withheld. A withheld piece of a document that is not its last is remembered as a dropped one is, so
that the rest of that document is dropped when it arrives after privacy mode has ended and a reader
is never given the end of a document it did not receive the start of. When privacy mode ends, one
loss of documents for each binding that had one withheld is reported as a gap, which tells a reader
that holds the start of a document that it lost the rest, and makes the host ask the component to
draw again. The component's drawing is then fresh and not a continuation.

What the host withholds is documents and presentation. A fault's detail, a disabling's reason, a
decoded request's summary and decisions, a declared fault's text and a checkpoint's state still cross,
and the worker keeps none of them beyond what it uses: a summary is what a person is shown beside an
approval and is kept in the approvals ledger; the rest it withholds by the rules above, because it
has to for whatever was said before the host was told. The worker's state and the host's agree
eventually and not at one instant: a document drawn before the host has answered is as it was, read
and dropped by the worker, which keeps nothing.

## Where the broker fits

Nothing here decides whether an effect happens.

`prepare-action` returns a plan, `decode-request` returns a projection, and `encode-response`
returns bytes. In each case the broker then checks the actor, the grant, the binding revision and
the declared effect class, and claims and dispatches. Pending and dispatch state lives in the
worker's broker ledger, never in a component and never in the plugin host, which is why a
plugin-host crash cannot destroy an approval ledger.

A binding is the broker's, and it is made only from the plugin admissions the control daemon hands
the worker (`docs/plugins/catalogue.md`). What a binding may do is derived from the installation's
effective capabilities, never from what a caller describes: observation from
`broker.semantic_events`, `terminal.stream`, `terminal.transcript_tail` or `process.observe`;
upstream action from `upstream.action`; and the approval interpreter from `approval.decode`, with
the right to answer only where `approval.respond` is granted beside it. The decoding trust comes
from the admitted package's connector table, and the actions from its verified manifest's
declarations. A package with a component binds for its declarative parts, and the worker also
registers the component with the plugin runtime, as the component link of
`crates/kr-worker/src/plugin_runtime.rs` describes. The broker pins the component the admissions
named when the binding was made, so a binding that stays on a release after an upgrade registers
that release's component. The link reads which bindings want a component from the broker each time
round, registers those not yet registered, unbinds those that ended, were forgotten or lost their
rich capabilities, and reports where each component stands in the worker's report on its bindings:
pending, with the step it is at (asking the control daemon, connecting, registering), registered,
unavailable with the reason, or disabled. A binding the runtime refuses is offered again after half
a minute, and after twice that each time it is refused again, up to ten minutes. The link does not
reach the runtime before a wait the daemon asked for or a backoff has passed, however often the
broker's set changes meanwhile, except that a link nothing wants the runtime of any more forgets
the wait, and the next binding that wants a component asks at once; the daemon's bound on starts
is what holds a runtime that keeps ending. The worker's report on its admissions says that this
host never calls the component's encode-response export, because the connector's table writes every
answer; it says so of every package that ships a component, whether or not the package decodes.

### An action a component prepares

An action whose implementation is `component` runs in two passes, so that the call to another
process never happens inside the boundary that revalidates an action and writes its dispatch marker.

1. The first pass is the admission. The request goes through everything any mutation goes through
   up to the receipt's `accepted` state: the envelope, the action window, the limits, the rights of
   the action's class, and the arguments read against the parameters the action declares. It also
   needs the binding's component to be registered with the runtime. The receipt then stays
   `accepted` while the component is asked. A repeat of the
   request is answered with that receipt, a cancellation rejects it, a revocation fences it, and the
   worker's outstanding-action limit counts it.
2. The component is asked outside every lock of the worker, on a task of its own, bounded by the
   action's accepted deadline and a few seconds. The connection goes on serving the same client
   meanwhile. A component that declines with a fault rejects the action with `INVALID_ARGUMENT`.
   A component that is still being registered, a runtime that is gone, a component that traps and a
   component that does not answer in time reject it with `RESOURCE_UNAVAILABLE`: a new request, with
   a new action identifier, can succeed (a component that keeps trapping is disabled by the runtime,
   and then the code is `UNSUPPORTED_CAPABILITY`). A repeat with the same identifier is answered
   with the rejected receipt.
3. The second pass is the ordinary pipeline with the plan in hand. It takes the dispatch barrier and
   the session, checks the authority the connection holds, and then reads the receipt: an action
   that was cancelled or fenced is answered with the receipt it has. Then it checks the authority
   revision the daemon validated the action under and the action's deadline. Only then are the
   binding, the declaration and the grant checked again, the invocation admitted, a token issued and
   spent, and the plan validated against it. A package that registered the action again while it
   was prepared has declared a different action, and the plan prepared for the first is carried by
   no route of the second. A plan the broker refuses rejects the receipt: nothing was dispatched,
   so it is `rejected` and not `refused` or `unknown`. A plan it accepts is the permit the dispatch
   marker precedes, and the receipt then follows the upstream's answer as any operation's does.

The component is asked after the request is accepted, so an action it prepares can reach the
upstream after a request the same client sent later. A client that needs the order waits for the
action's answer before it sends the next request. The arguments of every action that a component
prepares or that answers a pending request are read against its declared parameters; the arguments
of an action the host carries out itself by redrawing the package's document are read by no one.

What the component proposes is a proposal. The worker builds the effect it validates from the
invocation and the declaration, never from the component's words: the plan must be for the action
invoked, of the class the declaration implies, with the arguments the component was given, and its
operation must be the one the action declared. A plan that fills in fields of a routed method, or
names a method other than the one the action goes out as, is refused by name, because what leaves
is the invocation's own validated arguments. A component is therefore a veto, and a chooser of the
one operation its action declared.

The broker lives in `crates/kr-worker/src/broker`. Its way to a component is the plugin host,
through the client in `crates/kr-plugin-service`: register a binding, offer events to its queue,
make a call, take a checkpoint, unbind. `docs/host/README.md` has its whole contract; from this side
the order is what counts:

1. The broker records the opaque native request **before** it forwards it, and forwards it whether
   or not any component is healthy.
2. A component's `decode-request` returns a proposal. Which decoder reads a request is decided once it
   is recorded and forwarded, and never before: the connector's table interprets it at once when no
   binding of the package whose table the connection reads, trusted to decode the method, ships a
   component; when one does, the component decodes it and the table does not. A package that ships a
   component and relies on its table for approvals therefore has opaque approvals unless its
   component decodes, so a component that only draws must still return the request's identifier, the
   table's decisions and no summary. The choice reads no component's state. The request is queued, at
   most thirty-two for all bindings and eight for one, and a task of the link asks the components, at
   most four at once and one for a binding. A request whose component is being registered waits for
   it, which a session's first approval does when the component has to be compiled; one whose
   component is unavailable, disabled or gone, and one the queue could not take, stays recorded and
   opaque for the terminal to answer, and is not decoded later if the component registers later. The
   terminal's own answer waits for none of this.
   What comes back is believed no further than the broker can check. The identifier must be the
   request's own, every decision must be one the connector's table maps for it and none twice, the
   decisions carry the table's labels and never the component's, and the summary is carried whole or
   the proposal is refused, since a shortened sentence can say something the component did not. The
   component's class for the method and the nodes it presents the request with are carried and
   unused: the table classifies a method, and a person answers an approval and not a component's
   drawing of one. The broker then checks the binding's approval-interpreter grant, the
   decoding-trust record that names *this* package at *this* digest, the method that record covers,
   the projection's schema version and decision count, that the request is still pending (a native
   answer given while the component decoded wins), the source frame's generation, and that this
   source event has not already produced an interpretation. Only then does the request become
   something a person can answer, with the decoder's package and the request's bytes in the ledger and
   the component's summary, which an invitation to share the approval shows as what it asks, in place
   of the request.
   A component that faults, runs out its deadline, declines or answers what it was not asked leaves
   the request as it was, and the binding's report counts it by kind and never in the component's
   words.
3. A component's `encode-response` returns bytes. The broker rechecks the resource's own state and
   deadline, the instance, the source generation and the decoder's right to answer, checks the
   decision against the ones the request actually offered, commits the dispatch marker, and only
   then may the answer go.

What is not joined up yet is the encode step: no answer a person gives is encoded by a component. The
connector's table writes every answer, inside the admission that claims the resource, and the plugin
host's `encode` request returns what a component would write without anything calling it for an
answer. Calling it there means asking the component outside the broker's lock and rechecking, claiming
and dispatching after it returns, a native answer given meanwhile winning, as the preparation of an
action does.

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

### An action that offers an attachment

An action that offers an attachment from a draft is a component action that also names a draft. The
action's package must declare that it offers attachments by uploading them to the upstream. That's
the only way a worker can offer an attachment. The action must declare exactly one parameter of kind
`attachment_handle`, which will be the identifier of the transfer. Since the worker needs to read
the draft from the control daemon, there are two more possible refusals before it asks the component
to handle the action. The worker must have a daemon to ask, and a place must be free for the report
of the offer, because it keeps at most 256 reports waiting for the daemon.

The preparation runs in a fixed order: read, ask, compare, claim.

1. The worker reads what the draft holds and checks it against the package's declaration. The draft
   is for this application instance, the attachment is bound to it, and its size, media type (exact,
   or by a `type/*` family) and destination are what the package declares. What the control daemon
   owns it decides when it claims the binding: that the draft is open, that the binding is
   `recorded` and is a typed submission, and that the draft holds no more attachments than the
   package accepts.
2. The component is asked for its plan.
3. The plan is compared with the invocation: it must offer the attachment that the invocation names,
   and no other.
4. The worker reads the action's receipt again. An action that was cancelled or fenced in the
   meantime claims nothing.
5. The worker claims the binding, at the attempt step 1 read, so that a binding bound again since
   is refused. This is the last thing it does, so that it doesn't claim the binding until it has
   done everything else that might refuse the action.

One bound covers all of it, from the read of the draft to the claim: five seconds, or the action's
accepted deadline if that is sooner.

From the point that it claims the binding, the worker is responsible for reporting the result of the
action to the daemon, regardless of how the action ends. If the upstream acknowledges the request,
the worker reports `accepted_by_agent`, with the upstream request and turn as evidence. If the
upstream refuses the request, or the action is rejected after the claim, it reports `failed`. If the
action reaches the dispatch marker without ever being answered, it reports `unknown`, and a later
offer of the same attachment names the earlier action it supersedes, as any action on a subject with
an uncertain outcome does. A claim that the daemon was asked for and did not answer is settled by a
report that the offer failed, made once the claim's deadline has passed, because until then the
daemon may still commit it. The worker keeps these reports in memory until it can deliver them, and
uses a task to keep asking the daemon until it either records the report or refuses it. A worker
that ends first is a closed session, and the closure fails every offer in flight, so nothing needs
to survive the worker.

An attachment to an upstream is referenced by a worker both via its identifiers and the grant which
gives access to the attachment file. It is never referenced by its name. The grant's path ends in
the transfer's identifier in hexadecimal and, at most, one extension from a closed list that the
storage keeps. For instance, an uploaded file `shot.PNG` is staged with the extension `.png`, a file
`page.html` is staged with the extension `.html`, but a file `tool.exe`, a file `shot.png.exe` or a
file without an extension keeps none. As a consequence, a name with spaces, quotes or non-ASCII
letters, one that looks like a relative path, a WSL path or a Windows drive path, reaches the
upstream as none of those. Also note that there is no check whatsoever that the extension matches
the media type declared by the uploader, which means that if the receiving party needs to ensure
that the media type is correct, it needs to read the file.

The request names the attachment in these members of its parameters:

| Member | Holds |
| --- | --- |
| `attachment.transfer_id` | the transfer's identifier |
| `attachment.media_type` | the media type the upload declared |
| `attachment.byte_len` | the exact size of the file, in bytes, as a JSON number |
| `attachment.content_digest` | the SHA-256 digest of the file's bytes, as unpadded base64url |
| `attachment.read_grant.path` | the path on the environment's host that the grant lets the receiver read |
| `attachment.read_grant.expires_at_ms` | when the grant expires, as a JSON number of UTC milliseconds since the Unix epoch |
| `attachment.read_grant.environment_id` | the environment the grant is valid in |

A receiver of such a request is expected to open the path, confirm that the file there has the
stated size and digest, and only then acknowledge the request. There is no way for the host to know
if the receiver does this. A receiver that finds the file is not what the request says refuses with
the invalid-parameters error (-32602), and the offer then fails with the draft and the upload kept
for a retry. The same holds for the other reserved errors that say a request was not acted on: parse
error (-32700), invalid request (-32600) and method not found (-32601). The worker records any other
error from the upstream as an unknown outcome, because such an error does not prove that nothing
happened, so the next offer of the attachment names the action it supersedes.

`accepted_by_agent` therefore records that the receiver of this typed request acknowledged it after
the file named by the grant was available to it. It does not record that the agent used or
understood the file. How the path becomes something a particular vendor's agent understands is the
connector's contract with its bridge, and this host does not define it.

## The generation that ships with the host

A fresh installation has no repository and may have no network. It still has to recognise an
application, present it and activate a package. So the host carries a signed catalogue generation:
its metadata, its index and the packages the script lists at its top, nine of them. They live in
`bundled-plugins/`, and `bundled-plugins.lock` names every file in it.

The lock is the evidence beside the bytes. It carries the digest and exact length of every metadata
file, of the index and of every manifest and payload, the SDK and WIT ranges each manifest declares,
the highest trust root the generation ships, and the repository, commit, generation and tree address
the copy was made from. The bundle holds every root from version 1 to the highest, and
`metadata/root.json` is the same bytes as the highest, so a host that adopted an earlier root can
follow the chain. Targets keep their plain names, because the root says the generation does not name
them by digest.

The host compiles the bundle in. `crates/kr-plugin-catalogue/src/bundled_files.rs` lists each file
with `include_bytes!`, and `seed_trust.rs` holds the root key identifiers a build trusts and the
official repository's addresses. The script writes both, and `--verify` fails when either differs
from what it would write.

The two checks happen at different times, on purpose. Making the copy checks the whole TUF chain,
with expiry enforced, through the catalogue tool the plugin repository publishes: root, timestamp,
snapshot, targets, and every target's digest and length. Using the copy checks every byte against
the digest and length the lock names, in `SeedBundle`, when the host reads the bundle in. A host
with no repository cannot re-run a chain against a network it has not got, so what it can do is
recompute the digest of every byte it is about to use and refuse anything that is not what the lock
names. A bundle whose files do not match its lock is not a bundle: a byte changed after the lock, a
file the lock does not name, a root missing from the chain and a manifest that disagrees with its
lock are each refused, and nothing is seeded from it.

### Seeding

The daemon seeds the catalogue from the bundle at every start, right after it starts and before it
binds the local endpoints a client reaches. A request that arrives sooner on the network endpoint
waits for the catalogue until the seed ends. A seed that fails, or does nothing, does not stop the
daemon. The doctor's catalogue check says what it skipped and why, and where the generation in use
came from; a pin, a removed repository or a repository of the owner's that holds the same root are
the owner's choices and raise no warning.

A build decides whether it trusts the bundle's highest root from that root's key identifiers alone,
and never from anything the root says about itself. A shipped build trusts only the production root
keys it commits. None exist yet, so a shipped build refuses the bundle, writes nothing for it and
says so at every start. A build with debug assertions also trusts the development lineage's root
keys, which anybody can derive; the daemon built that way seeds only when it is started with
`--seed`, so a test that starts it and expects an empty catalogue is not changed by it.

Where the build trusts the root, the seed enrols the official repository against it, at
`https://plugins.reach.kala.to/metadata/` and `https://plugins.reach.kala.to/targets/`, with the
budgets the configuration allows and no capability beyond the default ceiling, and with no full
offline mirror. It leaves alone an enrolment of the owner's own: where a repository already trusts a
root of the bundled lineage, or one named `official` is enrolled with other keys, the seed enrols
nothing and records that it declined. It then activates the generation through the ordinary update
client over a transport made of the bundle's own bytes, so no network is asked. Expiry is waived for
that one generation, which the host reports as expired when it is; a later sync enforces expiry as
it does for any repository, and the client's own trust checkpoint still refuses a clock that went
back. Every root the client reaches along a chain of rotations is one the build trusts before it is
kept.

Last, the seed installs each bundled package once: enabled, with an empty grant, under an authority
of its own, from the bundle's own bytes. A later start finishes the packages an earlier one did not
reach, installs the packages a newer bundle adds, and activates a newer bundled generation after the
host is updated; a release that generation revokes loses the native bridge it had applied, as it
would after any synchronisation. It grants nothing, so nothing was confirmed by an owner and
no prompt was shown. Every capability past the repository's default ceiling stays
permission-required, and no native bridge is applied for a package whose grant lacks
`native_bridge.install`.

What the seed leaves alone is as much of its work. It never replaces an installation that is already
there, whatever repository it came from and in whatever state, and it records that it left it. An
owner's uninstall or disable is never undone: once the seed has made its enrolment, an uninstall
settles that plugin in its own commit, so a seed that stopped part way cannot bring back what the
owner took out. Removing the repository the seed made keeps the record that it made it, so the seed
never enrols again. A pin on the repository stops the sync and not the installs. A store a network
sync has moved past the bundle gets any package it lacks from the active index and the bundle's
bytes; where that index no longer lists the package at the bundle's digest, or lists it revoked, the
package is skipped, reported and tried again at the next start.

A payload the bundle carries is served from the bundle's bytes whenever a repository's accepted
generation pins it by digest, and the bytes are checked against the digest and length that
generation signed. Reclamation therefore cannot strand an offline install of a bundled package. Where the host decides
that a payload cannot be had, it says so before it makes room for it: a seeded installation is
refused for a payload the bundle does not carry, and a host with no transport for its repository's
address is refused for one that is neither cached nor in the bundle, so nothing is evicted for a
package that cannot arrive. A cached file counts only when its bytes are the ones its name says.

### Granting a seeded bridge

The first grant of a capability to a package that asks for a native bridge goes through
`plugin.install` of the installed release, with the owner's confirmation. That is where the owner is
shown the publisher's own statement of what the bridge does and the host's notice that it runs
outside the plugin sandbox. `plugin.grant` does not widen an installation whose release asks for
`native_bridge.install`: it refuses, names `plugin.install`, and spends no confirmation. Narrowing
stays allowed.

A release that asks for `command_integration.launch` is granted that capability the same way.
`plugin.grant` does not add it to an installed release: it refuses, names `plugin.install`, and
spends no confirmation, because the install is where the owner is shown the host's exact reading of
what the integration does. Narrowing stays allowed, and so does adding another capability, unless
the release asks for a native bridge, which refuses every addition.

This has a cost, and it is stated here. An installation of a package that asks for capabilities past
the repository's ceiling has to be granted all of them at once, so a seeded bridge package gets
every capability it asks for beyond the ceiling in one confirmed install. A partial grant comes only
from narrowing afterwards, and adding one capability back takes all of them again through
`plugin.install`.

### What the bundle does not promise

It is one generation, frozen at the commit it was copied from. It is not a catalogue: nothing about
it searches, fetches, updates or decides that a newer generation exists, and the repository it
enrols is fetched from its own address when an owner or a client asks it to synchronise. A signature under the development
lineage's root says the bytes are the ones that root's keys signed, and says nothing about who may
run them: that is why only a build with debug assertions trusts it, and why a release trusts a root
only once the production root exists. The package's capability requests, its grants and its
repository ceiling are applied to it exactly as they are to anything installed.

### Changing what is bundled

`scripts/sync-bundled-plugins.sh` makes the copy. It takes the plugin repository checkout and the
commit to pin (the lock's own commit by default), exports that commit into a private directory of
its own, verifies the chain there, resolves each payload by the digest the verified metadata pins,
and stages the whole bundle beside the published one. The packages it bundles are listed at the top
of the script. It refuses a checkout that is not at the pin, a link anywhere in the exported
generation, an unsafe path, two names that are one file, a payload that is not the exact length the
metadata pinned, roots that do not run from version 1 without a gap, and a bundle already published
that the lock on disk does not describe. It executes nothing out of a package, and it holds a
directory lock so two runs cannot publish at once. The trust a build commits (the production root
key identifiers, which stay empty until the production root exists, and the development lineage's)
is written at the top of the script too.

Publishing is three renames: the published bundle moves aside, the staged bundle takes its name, and
the new lock replaces the old one. Each is a rename, so the published name holds a whole bundle
before and after every step and never a mixture of two. It is not a single atomic replacement: POSIX
has no directory swap, so between the first two renames the name is absent. The two generated Rust
files follow, each written by a rename of a file beside it.

What an interruption leaves depends on what kind it was. A failure, a `SIGINT` or a `SIGTERM` runs
the script's own cleanup. If nothing was published, it puts the previous bundle back and drops the
new lock. If the bundle was published and the lock was not, it leaves the new bundle, the previous
one and the new lock all on disk and prints where each is, because guessing which a person wanted
would be worse than telling them. Once the lock is installed the previous bundle is no longer
anything, and cleanup removes it.

A `SIGKILL` or a power cut runs nothing, and cleanup can itself fail on a full disk. What is on disk
then is whichever renames had happened, under names that say what they are: a
`.bundled-plugins.retiring.` directory beside the bundle is the bundle that was published before,
and a dotted pending lock beside `bundled-plugins.lock` is the one that was about to replace it.
`--verify` says whether the bundle and the lock agree, which is the question worth answering; it
does not replay what the run was doing.

`scripts/sync-bundled-plugins.sh --verify` is the offline half. It recomputes every digest under
`bundled-plugins/` against the lock and reports any drift, including a file, a directory or a whole
package that is there and is not in the lock. It checks that the roots run from version 1, that the
highest is the one `root.json` holds and the lock names, that the keys of every shipped root are all
development keys or all production keys this build commits, that the index is within the default
metadata budget, and that the generation and production time the lock names are the index's. It
runs the release scan's own checks over every bundled file, so a private key, a key seed or a
credential is refused whatever the file is called. It regenerates the two Rust files and reports any
difference. `--verify --release` also requires a root a release trusts, which none is yet, so it
fails for the committed bundle until the production root exists; no workflow runs it yet.
`--generate` writes the two Rust files from the bundle on disk. None of them reaches a network,
builds anything or needs the plugin repository, which is why `--verify` runs in continuous
integration.

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
