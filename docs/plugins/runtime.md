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
the strength of a signature. Exactly one rendezvous per reservation succeeds: the second claim for a
reservation is refused by a record the launcher keeps and is counted, so two processes claiming one
reservation is something a host can see rather than infer. Each launch also has a rendezvous address
of its own, named after its reservation, so a claim can never arrive on an address two launches meant.

The deadline covers receiving and checking the claim, not merely accepting a connection. A peer that
connects and then says nothing does not hold a startup open, and a refused claim does not end the
wait: the launcher keeps listening until its deadline and reports the last refusal if nothing better
arrives.

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
| `health` | ask what the host is doing |

A binding belongs to the connection that registered it. Another connection that has the identifier
finds no binding, which is the same answer it would get for one nobody ever registered, and a
connection that ends takes its own bindings and nobody else's.

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

The broker itself, the gateway, the native proxy and action tokens are a separate piece of work. What
it builds on is the API in `crates/kr-plugin-runtime`: prepare a binding, offer events to its queue,
invoke a control, ask for an interpretation, take a checkpoint, unbind.

Offering an event never waits at all. Every call carries the caller's own deadline and returns when
it runs out, so nothing on the terminal path can end up behind a component. `unbind` is the one that
blocks: it waits for the binding's thread so that a caller knows the instance has stopped before it
drops what the instance was using, and the wait is bounded because the call the thread is finishing
is bounded. A caller that must not block drops its handle instead, which signals the thread without
waiting for it.
