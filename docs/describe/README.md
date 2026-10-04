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

## The model's files

The files of the selected profile are kept in `<state>/models/<profile>/<revision>/`, where the description process looks for them. A file named `held.json` in that directory says this host holds them: it names the profile, its revision, and each file with the size and digest it was checked against. At start the daemon takes the files as held when `held.json` is the selected profile's own and each file is there at the size the profile records. Without them nothing is loaded and nothing new is generated: a session shows the title it has from metadata, a pin or an earlier description, and describe reports `not_downloaded`. A new revision of a profile has a different directory, so the files of an older revision are never considered held for it. Once the new files are kept, and again at each daemon start that finds them held, the daemon removes the directories of the profile's other revisions.

Files are not fetched until the owner asks, and a fetch needs no account. The daemon fetches files from the addresses the profile names, using the proxy the daemon was started with. It follows at most 5 redirects. It times out after 30 seconds if it cannot connect to a server, or after 60 seconds if the server does not answer or does not send a chunk of the body. It refuses a file if its declared length exceeds the size the profile records or if it receives more bytes in the body than that size, and it refuses to begin when the disk has less room than the files need plus 256 MiB. Each file is written as `<file>.partial` and checked by the description process, which compares it with the size and digest in its own signed catalogue. The daemon never tells it what to accept. Once a file passes, it is renamed to `<file>`, and the marker is written once every file is in place. Description processes launched solely for a check do not load the model and exit after checking the file.

If a fetch is cancelled or fails, the partial and every file of the profile it had already put in place are removed, so nothing of a profile is kept unless all of it is. Only one fetch can run at a time, and turning off descriptions cancels an in-progress fetch.

The process checks each file again at every load. A file it finds changed ends the load as `assets`. That is no failure of inference: it starts no restart delay and counts toward no pause. The host marks the files as not held and removes the marker, and setup shows nothing fetched, so fetching again recovers it. Once the files are held, they are not fetched again.

## The processor

On x86-64, the description process needs a processor with the x86-64-v3 instruction sets that compiled code uses: SSE4.2, POPCNT, AVX, AVX2, BMI1, BMI2, FMA, F16C, LZCNT and MOVBE. llama.cpp compiles its CPU code for them when the process is built, and a processor without one stops the process with an illegal instruction the first time it loads a model. Intel Core processors since the Haswell generation (2013) and AMD processors since Zen (2017) have all ten. Older processors, some Intel Pentium and Celeron models, and virtual machines whose hypervisor does not pass the instructions through do not. Other targets, such as ARM64, do not have this limitation.

The build fixes the set and never reads it from the machine that compiles. `.cargo/config.toml` forces the llama.cpp options for the six sets that have one on and the wider ones off. The compilers add the other four themselves, so the host checks them too. `kr-describe-model` refuses to build when a `target-cpu` flag, or a target feature wider than the set, would replace it. `kr-describe` refuses to build when the build itself enables one of the ten, because the standard library then answers every question about it with yes. `kr_describe::processor` lists the ten, and a test holds the pins and the list equal.

The daemon asks the processor which of them it has before it selects a profile. On a processor that lacks one, no profile is selected and the description process is never started. A session shows the title it has from metadata, a pin or an earlier description. `description.setup` answers `offered: false` and names the missing instruction sets in `unavailable`, for example "this processor lacks AVX2 and BMI2, which the description process needs". `description.download` refuses and gives the same reason, and `kr doctor` reports descriptions as not applicable, names the missing sets and suggests giving a virtual machine a CPU type that passes them through. No setting changes this.

## Setup

`description.setup` answers what descriptions offer on this host before anything is fetched. It says whether the host can run a model at all, whether the owner has enabled descriptions, the profile, its exact size in bytes, the addresses a fetch would reach, how a fetch is going, whether it can be cancelled, and what state inference is in and why it is paused. It never says a hosted account is needed, because none is. It is a read, served on the local socket and to a paired device whose grant carries host management.

There are two writes that change the host, `description.configure` and `description.download`, and neither is served to a paired device: description settings are changed on the host itself, and a paired device reads them as the host reports them. `description.configure` turns descriptions on or off and allows or forbids inference on battery. The settings are stored in the host's configuration document, and they apply at once. Turning descriptions off cancels any work in flight, including a fetch of the model's files. It also ends the description process. `description.download` starts a fetch of the selected profile's files or cancels the one that runs. Each answers with what setup shows afterwards, so a client sees the fetch running, or the failure that ended it, without asking again.

`kr host descriptions` is the command line for all three. `kr doctor` says whether this host generates descriptions and, when it does not, what it is waiting for.

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

The prompt has a bound of its own, counted in the model's tokens. A job's prompt may be what the window leaves beside the answer's bound, 3,968 tokens, or what the deadline leaves for reading it, whichever is less. The deadline is the smaller. Take 1 s of fixed cost and 12.8 s for a full answer of 128 tokens out of 30 s and 16.2 s are left, and at 55 tokens a second a prompt may be 891 tokens. The figures come from the selected profile on a 32-core x86-64 server at four threads under a load average of 20 to 40, where prompts were read at 61 to 69 tokens a second and each answer token took 70 to 85 ms, so the budget assumes a slower machine on both counts.

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
host whose jobs take longer than the debounce would refuse every job the turn produced.

A job whose session closes, or opens again, before it ends describes a session that has gone. It is
stopped, what it produced is refused, it is never queued again, and it leaves no mark on the session
there now, whatever that session's epoch, binding and revision happen to be. A session opened again
also drops the job it had waiting in the queue, which was built from the context it had, the
semantic events it had recorded, and the retry an earlier failure had used.

The input is bounded directory and repository metadata plus recent authorised semantic events.
Raw keystrokes, hidden input, environment values, file bodies and whole histories are excluded, and
there is no setting that admits them.

Project text — a repository name, a branch, an intent somebody typed — is carried as data. It goes
inside a delimited section of the prompt that is labelled as data, and the output is constrained by
a grammar, so an instruction inside a branch name cannot change the shape of the answer or the
status shown beside it. Project text that spells one of the model's control tokens, such as `<|im_end|>`
or `/no_think`, reaches the model as the characters it is made of, never as the token. Project text
can still mislead a model about what a session is doing, and nothing here claims otherwise.

## What fits in the prompt

The daemon sends the process the parts of the prompt: the revision and cursor interval the answer repeats, the session's facts and its recent events. The process adds the fixed instruction, counts tokens with the model's own tokenizer and makes the prompt fit its bound. It always keeps the instruction and the two provenance lines. After those it keeps parts in this order: the task intent, the directory and the repository, then the newest event, then the branch, the thread and the application, then the other events, newest first. Each is kept whole while the prompt fits. The first one that does not fit is cut to a run of its codepoints that does, and nothing after it is kept. The oldest events go first, and the same context under the same bound gives the same prompt every time.

A prompt is trimmed only when its session is large. The benchmark's ordinary sessions are 180 to 250 tokens and are never trimmed. Its largest context, with every field and every event at its bound, is 708 tokens in Latin text and fits whole. The same context in Arabic text is 1,768 tokens, in Hebrew 2,152 and in emoji 5,164, and each is trimmed to 891 tokens or just under. Some scripts cost more tokens than others, so a session with long Arabic events can be trimmed where a Latin one is not.

No job can be too large for a profile. Verifying a profile refuses a context window that cannot hold the instruction byte for byte, two framing tokens and the output bound, because in a byte-level vocabulary a prompt is never more tokens than it is bytes.

## What comes out

Grammar-constrained JSON with four fields: a `title` of at most 64 Unicode codepoints, an
`activity_text` of at most 160, the source cursor interval it covers and the context revision it was
produced at.

The grammar admits every character that validation accepts except the quote and the backslash, which a string cannot hold bare, and no character that validation refuses. Its character class lists the characters it admits and does not name the ones it leaves out. llama.cpp refuses a token that ends inside a letter when no character that letter could finish is listed, and a class that named the bidirectional controls would refuse every token ending in the first byte of an Arabic or a Persian letter, so the model could not copy text in those scripts.

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

A model can run out of output tokens before it closes the object. If that happens inside the activity text, or inside the fields that repeat the revision and cursor interval after it, the process ends the answer so that the whole of it, counted in tokens, is within the output bound. It keeps the title as written, cuts the activity text back to the last boundary between characters a person sees, never inside a combining sequence or an emoji sequence and never ending in white space, closes the string, and writes the revision and the cursor interval from the prompt. The activity line may then be shorter than the model meant it to be, and the answer is validated like any other. If the model runs out inside the title, or the title leaves no room for any activity text, or the model had begun to repeat a number that is not the prompt's, nothing is changed: the answer is refused, and the session keeps the title it had.

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

## The host in the daemon

The description service is owned by one of the threads in the control daemon. That thread also owns the process it drives and a store connection of its own. The rest of the daemon reaches that thread through a handle: the links to the workers hand it facts, the controller tells it when a session opens or closes, the owner's settings arrive as messages, and `session.describe` reads a snapshot the thread publishes after each turn. Nothing runs on a keystroke's path. A keystroke, a resize and a terminal query reach no fact, and facts reach the thread only as pages a worker chose to send.

Each session has a link. The control daemon opens a connection to the session's worker for descriptions, checks the worker, and keeps one request held there. The request asks for the facts past the revision the daemon has read, and the worker holds it for up to five minutes until something changes. The request includes the latest privacy generation number that the worker reported, so a worker whose privacy mode moved answers at once and the daemon never waits on a generation it has not been told. A link that fails is made again after a delay. The delay is doubled each time, starting from half a second and increasing up to five minutes. A worker from an older build refuses the role and is asked again, quietly, until it is replaced.

A page of facts is applied under privacy mode's admission at the generation it was captured under, and dropped when none admits it. A job is registered as in flight under the same admission. Either the job is sent before privacy mode is published, in which case the change finds it and cancels it, or the job is never sent. A result is published under the admission too. When privacy mode is enabled, the thread that enabled it raises the fence of each session and deletes the rows in the store at once. The memory the service holds, which is its queue, its contexts and the pages waiting for the host, is cleared by a purge the host answers within two seconds. A purge that takes longer is reported as unavailable, and privacy mode's change is not complete until it has finished. A host that does not run owes privacy mode nothing.

The host reads the memory, power and thermal conditions of the machine every ten seconds, on a thread of its own, because reading the state of the platform can start a program. A reading more than a minute old says nothing: every signal is then unqualified, and the policy pauses rather than trusting the last answer.

The description process is a child of the control daemon. It is located next to the executable of the worker. It is started when work is first due.

## What a worker records

A description is built from facts the session itself produced, and each session's worker keeps them in one small record. The record holds:

- the last component of the directory the newest command ran in;
- the repository that directory is inside, and its branch;
- the program the newest command ran, and whether it succeeded or failed once it ended;
- the last prompt an agent in the session was given;
- the thread the agent selected;
- the eight most recent events, newest first.

Each field with text is truncated to 120 characters and stripped of control characters. Each time the record changes, its revision moves. The record also carries the privacy generation it was captured under.

Keystrokes, application outputs and query answers are never recorded. The record is captured only in the places where the worker already decides that something happened: a command block the shell integration reported, a prompt the worker admitted, an observation an admitted bridge sent. Those hooks are not called from the input, resize or query paths. The command line, and consequently its arguments, is never recorded. The program's name comes from the shell's own resolution of the command: the Zsh and Bash packages ask the worker before each command a line starts, and when the shell's search found a file, the name is the last part of the command as it was typed. A word the shell did not resolve to a file, such as a token pasted at the prompt, names no program, and neither does a shell that does not ask. The first command of a line that the shell resolved names the program for the whole line.

The repository is read from the nearest `.git` in the command's directory or above it. This is done on a thread of its own, so the hook that reported the command never waits for it. The walk stops after 64 directories, reads at most 4 KiB of `HEAD`, and opens only regular files, so a pipe named `.git` opens nothing. When a command ends, the worker reads the directory the shell is in from the operating system, which means a `cd` is described at the next prompt with nothing more typed.

While privacy mode is on, nothing is captured. Enabling it clears the record in the same step as every other subsystem's fence, and turning it off starts an empty record under the new generation.

## Lifecycle and failure

The model stays loaded while there is work and sessions to justify it, and a host with no sessions
at all unloads after fifteen minutes.

A load is cancelled when its reason goes: descriptions turned off, a pause, or no work left for it.
A job is cancelled when privacy mode fences its session, when its session closes or opens again,
when a change to the session settles, when a pause arrives, or when a caller cancels it, and a job
stopped for a pause keeps its place in the queue. A cancellation and a passed deadline publish
nothing.

A process that exits, breaks the wire or is ended for breaking a bound takes the model with it and
nothing else. The store, the pins, the provenance, every session and every deterministic title
survive. The job it was running is queued again once, with its aging position, and if the next
process fails it as well it is not retried, however many pauses come between. A job a caller or
privacy mode cancelled is never queued again, even when its process ends before the cancellation is
answered, and even when a pause had already stopped it: a retry would run it under a new token that
nobody had cancelled. The service's handle on the running job is the one way to cancel it from
outside, and the job's token never leaves the service. The moment the service decides what a job
that did not finish comes to is the moment a cancellation stops counting, so a cancellation that
comes first is honoured, and one that comes after finds nothing running and says so. The next load
waits a second after the first failure, twice as long after each failure that follows, up to five
minutes, and a published description resets the wait.

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
