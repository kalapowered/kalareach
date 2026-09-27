# Local session names and descriptions

Every KalaReach session has a name and a status. Most of the time that name comes from facts the
host already has: the repository you are in, the branch you are on, the directory, the application.
That part works on every host, with no model, no network and no account.

On top of that floor, a host can run a small language model locally to say what a session is
*doing* — `KalaReach pairing`, `Checks the code-entry flow and host approval screen` — instead of
just where it is. This document is about how that works, what it costs and what it deliberately
cannot do.

## The floor: deterministic titles

A session's title is a pure function of metadata the host holds:

| What the host knows | The title |
| --- | --- |
| A repository and a branch | `kalareach (main)` |
| A repository | `kalareach` |
| A directory | `crates` |
| A foreground application | `nvim` |
| Nothing | `Session 4` |

The status beside it — starting, running, unreachable, awaiting approval, awaiting input,
completed, failed, closed — comes from the host's own lifecycle record. It is not text and it is
never produced by a model. A description cannot claim a test passed, invent an approval or mark a
session complete, because there is no function anywhere that turns generated text into a status.

## The model

One shared inference process and one mapped model per execution environment. Never one per session.

- **The default profile** is `openbmb/MiniCPM5-2B`, quantised to Q4\_K\_M, about 1.5 GiB on disk and
  about 2 GiB resident.
- **`HuggingFaceTB/SmolLM3-3B`** ships as a *candidate*, behind platform, resource and quality
  gates - all three, and a candidate profile that declared fewer is refused. It is not a fallback:
  memory pressure, a timeout and bad output never cause a switch to a larger model. The fallback is
  always deterministic metadata. The gates are checked again where a profile is mapped, so a
  candidate obtained some other way still cannot run without them.
- **WSL** reaches a native-host broker only after somebody explicitly chooses to let local data
  cross. Without that choice a distribution runs no model, and shows deterministic titles.
- **Mobile** never runs a model to label a host session.
- Grouping machines together so you can see them in one list grants nothing: two environments in
  one group have their own mapping, their own context and their own transcripts.

### The profile

A model profile is not configuration. It is the statement a qualification was made against, and it
records the source model's repository and commit, the repository and commit the converted asset was
published at, the runtime, the verified size and SHA-256 of every asset, the tokenizer and
chat-template digests, the sampler values, that reasoning is off, that there is no tools or vision
component, zero GPU layers and the targets it declares as compatible.

Three things the profile is careful not to claim. The `converter_revision` is empty for both shipped
profiles, because neither publisher states which tool produced their GGUF; what binds the asset is
its digest, not a converter this product cannot see. The tokenizer and chat-template digests are the
*source* files' - the tokenizer inference uses is the one embedded in the asset, which the asset
digest pins. And the chat template is recorded rather than applied: this build sends the instruction
and the data section as a plain prompt, so the template digest is provenance for a profile's
identity rather than a description of what the runtime does with it.

There is one way to get a profile: a document plus a detached signature from a key the host
accepts. The profiles shipped here are compiled in beside their signatures and the public half of
the key that made them, and they are verified before use like any other. Against a document from
outside the binary that is worth what a signature is normally worth. Against the built-in documents
it is worth less, and it is honest to say so: the anchor ships beside them, so replacing one means
rebuilding, and a rebuild can carry a new anchor. What it buys is one code path instead of two.

The profile-signing key is per build: it is generated, used, and not kept. Changing a shipped
profile means generating a key, signing both documents again and committing the anchor with them,
in one change.

Assets are downloaded once, for the selected profile only, under a policy that states the exact byte
count before anything is fetched. A fetch is *admitted*; only a fetch whose files have been verified
against the recorded size and digest is *held*, so a download that was cancelled or produced the
wrong bytes leaves nothing behind and the next request fetches again. Replacing a mapped model
unloads the old one first, and a result that comes back from the old profile revision is refused
rather than shown.

## The budgets

Section 22's defaults, which are what a qualification is measured against:

| Budget | Value |
| --- | --- |
| CPU threads | 4 |
| Requests in flight | 1 |
| Context | 4,096 tokens |
| Output | 128 tokens |
| Context debounce | 2 s |
| Minimum per-session cooldown | 30 s |
| Process memory ceiling | 4 GiB |
| Execution deadline, after dequeue | 30 s |

The deadline starts at dequeue. A model loads before any job leaves the queue, under a five-minute
deadline of its own, so a slow load costs the queue's wait and never a job's thirty seconds. The
cold start is reported on its own.

The memory a resident model costs is accounted for item by item — weights, mapping overhead, the
key-value cache, other caches, batch buffers and the runtime's own allocations — because a 1.5 GiB
file is not a 1.5 GiB process. An owner may tighten the ceiling or the reserve, and never loosen
either.

## When inference runs, and when it does not

Before loading, the host checks that the model's cost plus a reserve of **at least the larger of
1 GiB or 20% of physical RAM** still fits in the memory it can actually see. A model that is already
resident is not free either: the key-value cache, the other caches and the batch buffers are built
again for every job, and that peak has to fit beside the reserve before the next job starts. If it does not, the
state is `resource_paused`, the reason is named, and the deterministic titles are unaffected.

- **Battery** pauses inference by default. A host that cannot read its own power source is treated
  as being on battery, because it has not been told otherwise.
- **Thermal or memory pressure** pauses it even on mains.
- When pressure clears, the host resumes on the next evaluation. Nothing is restarted: the queue
  keeps its positions, the sessions keep their titles, and no worker is touched.
- A host that cannot read a memory signal refuses to load rather than assuming the reserve holds.
- Turning descriptions off is one setting, and it stops admission and dispatch as well as unloading
  what is mapped.

The 4 GiB ceiling is the description process's, and it is checked against that process rather than
the profile's estimate. The daemon reads the process's resident set every second while it loads or
runs a job and ends it past the ceiling, and the process ends a job itself when it passes the
ceiling between tokens. A description whose job took the process past the ceiling stays published.
The process is ended after it, and inference pauses with `memory_pressure` until the next load may
happen.

CPU-only is two settings rather than one. Zero GPU layers keeps every layer's weights on the
processor; turning the library's *operation* offload off keeps the arithmetic there too, because the
scheduler would otherwise send a large enough matrix multiply to a registered backend even when its
weights are in host memory. Both are needed on Apple silicon, where the pinned binding compiles the
Metal backend in whether or not it is wanted: its manifest enables that feature for the target
rather than behind an option, so what makes this build CPU-only is the two settings rather than the
absence of the backend from the binary.

The description process's model thread runs at the background scheduling class each platform
offers (`SCHED_BATCH` on Linux, the lowest ordinary thread priority elsewhere), and the process says
which mechanism it applied when it starts. No
IO class is applied in this build, and the qualification matrix records that rather than claiming
it.

## The queue

At most one queued job per session. When a session changes again, the job's *content* is replaced
and its *position* is kept, so a session that changes every two seconds neither floods the queue
nor overtakes one that has been waiting longer.

Foreground and attention work goes first, but after at most three priority jobs the oldest waiting
ordinary job is served. That is the whole fairness bound, and it means a quiet session drains at one
in four however busy the host is.

The cadence is the measured service time multiplied by the number of eligible sessions, floored at
the thirty-second cooldown, and it is also when an ordinary session is described again: not before
the cadence has passed since its last job. So the cadence a client is shown is the one the queue
runs at. Foreground and attention work waits for the cooldown alone.

Thirty seconds is a *minimum*, not a promise: when demand exceeds
capacity, a client is shown how long its job has been queued, when it last succeeded, and whether
the description it is looking at is current, delayed or stale. There is no state that means
"probably current".

Queue-wait and execution latency are published separately at 1, 5, 20 and 50 sessions. They answer
different questions — one is what fairness costs, the other is what the host costs — and a single
figure would hide the difference.

Every attempt is measured once, however it ended: published, refused, past its deadline, cancelled,
or cut short when its process ended. Each one occupied the process, so each counts toward the
service time the cadence is worked out from and toward both latency figures. A host that measured
only its successes would report a cadence it cannot keep.

## What goes into a description

The context revision advances on meaningful changes only: the working directory, the foreground
application, the selected thread, the task intent and completion. Not tokens, not spinners, not
keystrokes. Changes inside the debounce window collapse into one revision, and the window starts at
the *first* pending change, so a long active turn still reaches a new revision every couple of
seconds instead of waiting for a quiet moment that never arrives.

A change that settles while the session's job is running moves the revision on, so that job's
result, which describes the session as it was, is refused as a changed context. The job is cancelled
at once rather than left to finish, and the new revision is described once the session's cooldown
has passed. A change still inside its debounce when the answer arrives refuses nothing: the answer
is judged at the revision in force, and the change settles after it.

A session is superseded at most once in a row. While the job after a superseded one runs, the
session's changes wait for it, and they settle as one revision the moment it ends. In a long active
turn that never stops changing, then, at least every other job runs to its end rather than being
refused for a change; what it publishes, when its output is valid and nothing else stops it, is at
most one job behind the session, and the revision catches up as soon as it lands. Without that, a
host whose jobs take longer than the debounce would refuse every job the turn produced. A job whose
session closes, or opens again, before it ends leaves no such mark on the session that is there
then.

The input is bounded directory and repository metadata plus recent authorised semantic events.
Raw keystrokes, hidden input, environment values, file bodies and whole histories are excluded, and
there is no setting that admits them.

Project text — a repository name, a branch, an intent somebody typed — is carried as data. It goes
inside a delimited section of the prompt that is labelled as data, and the output is constrained by
a grammar, so an instruction inside a branch name cannot change the shape of the answer or the
status shown beside it. It can still mislead a model about what a session is doing, and nothing here
claims otherwise.

## What comes out

Grammar-constrained JSON with four fields: a `title` of at most 64 Unicode codepoints, an
`activity_text` of at most 160, the source cursor interval it covers and the context revision it was
produced at.

Every result is validated again before it is published, because a grammar is a constraint on
generation rather than a guarantee about a process. It is judged against what is in force when it
arrives, not when its job was sent. A result is refused when it is malformed, when it carries a
field this build does not know, when a control character reaches a field, when either bound is
exceeded, when the session has closed or its epoch is wrong, when the context or the binding has
changed since the job was admitted, when the model has since been remapped, when privacy mode's
generation has moved, or when a person has pinned the name. A result that arrives after descriptions
were turned off is not published either; its job keeps its place in the queue. Nothing is tidied
into acceptability.

A refusal costs nothing: the session keeps the title it had.

## Pins

A pinned name is the one a person chose, and generated text never replaces one. Pins live in a small
store of their own beside the session journal, so they survive the session closing, the worker
exiting and the host restarting. Clearing a pin is an explicit action and the only thing that
removes one.

A pin is written through a connection of its own while descriptions are published through another,
so the store checks for a pin and writes a description in one statement. A pin that commits first
stops the write, and one that commits after it finds the description there and still wins, because
a pin is always shown first. A description stopped by a pin is not counted as a success.

The same store holds each generated description's provenance: which profile produced it, at which
revision, at which context revision, over which cursor interval and when.

## Privacy mode

Privacy mode is a session's state, not the host's: one private session sits beside one that is not,
and everything below reaches the first only.

Enabling it records a generation, then, in order: fences that session's description processing at
once and cancels its job if one is running, takes back its queued job, and removes its generated
description and the context this host had captured for it, while keeping its pin.

From the instant the fence goes up, that session's title comes from its pin or from deterministic
metadata — there is no window in which a generated title is still shown — and nothing more is
captured for it, so a change made while it was private cannot reach a job after privacy ends. A job
that was already running is counted as in flight, and the cleanup does not report complete until it
has finished or until a removal this host could not make has been made. Its answer, when it arrives,
is refused: publication happens under the same lock that raises the fence, re-checking the fence,
the cancellation token and the whole-job deadline inside it, so a fence raised from another thread or a
token that fired between generation and publication publishes nothing. The write itself goes through
the job's token, so a cancellation that arrives while the description is being written waits for it
and is told it was too late, rather than deleting the description an earlier, uncancelled job left
for that session. The job counts as running, and as in flight, until its outcome is complete, the
write included, so nobody is told a job is past cancelling before its description is in the store.

Descriptions are produced, stored and shown on this host. None of them is uploaded, so there is no
copy elsewhere for privacy mode to offer a separate deletion of.

## The description process

The model runs in a process of its own, `kr-describe-inference`, one per execution environment. The
control daemon starts it as its own child the first time work is due, in the directory the daemon
names and with no environment beyond what the daemon gives it. Nothing in it outlives the daemon:
the two talk over the child's standard input and output, and when the daemon goes, the child's input
ends, and it cancels its job and exits.

They speak section 23's frame, a four-byte length and one KR-CBOR-1 object, through the protocol's
own codec. The daemon says hello, and the process answers with its build, its target, its start
identity and the background class it runs under; the daemon speaks only to a process of its own
release. After that the daemon sends a load, then jobs one at a time, and cancellations, and every
answer names the work it answers. An answer for work nobody is waiting for is dropped and counted.

The daemon holds the process to its bounds, and ends it outright when it breaks one:

| Bound | Limit |
| --- | --- |
| Answering hello | 10 s |
| A load | its own deadline of five minutes, and 2 s more |
| A job | its thirty seconds from dequeue, and 2 s more |
| Answering a cancellation | 2 s |
| The resident set, read every second during a load or a job | 4 GiB |

The process holds itself to them as well, so no end depends on the daemon alone. Its watchdog ends
it when its control thread has spent two seconds on one request, which is a daemon that stopped
reading its answers, and when a load or a job runs two seconds past its deadline. The daemon passes
its own start identity when it starts the process, and once a second the watchdog asks whether that
daemon is still running: a control thread stuck inside a read never sees its input end, and the
process still goes when its daemon does. The daemon reads its identity afresh for every start, and a
daemon that cannot read it starts no process at all; the load ends as failed and the next start
tries again after the restart delay. Before its first
load it takes the environment's lock, `describe-inference.lock` in the runtime directory, and keeps
it until it exits, so a process a replacement daemon starts loads nothing until the old one has
gone.

A process loads one model in its life. Unloading a model ends the process, whatever the reason: an
idle host, a pause, descriptions turned off, or a failure. The next load starts a new one.

The daemon starts the two threads that carry a process's frames before it starts the process, so a
thread the system will not create leaves no process behind; the load ends as failed, and the next
start waits out the restart delay. Once the process is running, anything that fails on the way to
the handshake kills it and collects it.

## Lifecycle and failure

The model stays loaded while there is work and sessions to justify it, and a host with no sessions
at all unloads after fifteen minutes.

A load is cancelled when its reason goes: descriptions turned off, a pause, or no work left for it.
A job is cancelled when privacy mode fences its session, when its session closes, when a change to
the session settles, when a pause arrives, or when a caller cancels it, and a job stopped for a
pause keeps its place in the queue. A cancellation and a passed deadline publish nothing.

A process that exits, breaks the wire or is ended for breaking a bound takes the model with it and
nothing else. The store, the pins, the provenance, every session and every deterministic title
survive. The job it was running is queued again once, with its aging position, and if the next
process fails it as well it is not retried. A job a caller or privacy mode cancelled is never queued
again, even when its process ends before the cancellation is answered, and even when a pause had
already stopped it: a retry would run it under a new token that nobody had cancelled. The service's
handle on the running job is the one way to cancel it from outside, and the job's token never leaves
the service. The moment the service decides what a job that did not finish comes to is the moment a
cancellation stops counting, so a cancellation that comes first is honoured, and one that comes
after finds nothing running and says so. The next load waits a second after the first failure, twice
as long after each failure that follows, up to five minutes, and a published description resets the
wait.

The runtime is a crate of its own, `kr-describe-model`, built on the description service in
`kr-describe`, which holds no model: a process that links the service alone, as the control daemon
does, has no inference library anywhere in its dependency graph.

## Measuring it

`scripts/bench-descriptions.sh` runs the real model against real weights. It downloads the selected
profile's assets once into a cache on local storage, and `kr-describe-bench` verifies every size and
digest before it loads anything. The run is pinned to four processors, states the hardware beside
every figure, and reports:

- cold-start load time;
- the declared itemised resident cost beside the measured resident set, whole process and model;
- queue-wait and execution latency at 1, 5, 20 and 50 sessions, separately;
- how many descriptions were produced, how many passed the deadline and how many were refused;
- the resource-paused case, driven on the same host that has just been publishing.

That last point matters: section 22 forbids passing the active-contention case by keeping inference
switched off, so the pause is measured beside real production rather than instead of it.

Every figure is of one process, which holds the runtime, the harness and the terminal workload the
contention case needs, and each line says so. What that process grew by over a baseline is reported
as an estimate of the model and its runtime rather than as a measurement of them: the baselines are
real (the process before the model was loaded, and the terminal workload running with no job
admitted), but subtracting one peak from another does not separate threads that share a process.
Whole-product RSS and CPU are not measured here at all, because the controller, the workers and the
shared services are not running beside this one process; the release matrix measures them.

A budget the run misses is named as a qualification target that was not met and the run exits
non-zero, after it has measured everything else it can still measure: a benchmark that stopped at
the first breach would answer one question by withholding the rest.

`cargo test -p kr-describe` never downloads weights. It starts a stub description process, the same
serving code over a model that answers from the prompt, and drives it over real pipes, so the rules
(fairness, rejection, unloading, privacy) and the process's bounds are tested in seconds. `cargo
test -p kr-describe-model` runs the real process with the real weights where the benchmark's cache
holds them, including a job it is told to cancel, which the model has to stop itself, and says so
where it does not. Neither can answer whether the text is any good, and
that is what the benchmark is for.

## The qualification matrix

The matrix covers useful titles, unsupported claims, stability, grammar, multilingual names,
malicious project text, long active turns, rapid directory changes, cold start, memory, CPU
contention, cancellation, queue fairness and stale-result rejection, across the required host
architectures.

Each case names what stands behind it: a named test, on the targets the suite has been run on, or
nothing yet with the owner that will run it. Each also names what its evidence does **not** cover,
because a test against a deterministic runtime proves a rule and not the model, the library or the
machine. A case is never recorded as evidence on a target
nothing has run on, and the cases that need real weights stay outstanding until a benchmark run is
recorded against a commit and a target. `Matrix::gaps` is that list, and it is a method rather than
a comment so a report that prints the matrix prints the gaps with it.

The smoke results reported on 13 September are preserved as reported. They have not been
reproduced, the scripts and raw outputs behind them were not supplied, and they qualify no profile
and no reference host.
