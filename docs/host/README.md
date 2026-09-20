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

A session's output spool is created the same way rather than inheriting the process umask, because
it holds the terminal's own output: mode 0700 on Unix, and on Windows the owner-only access list of
the state directory above it.

**Keys are OS-protected where the operating system offers protection, and the limit is
documented.** On macOS the device keys live in the login keychain, and on Windows in the
credential manager. On Linux the Secret Service is available only where a session keyring is, which
a headless host usually has not got: there the keys fall back to a file under the owner-only state
root, protected by the directory's own permissions and by nothing else. That is the documented
headless Linux limitation, and it is a limitation rather than a defect of this host: a key file an
account can read is a key its own account can read, and no file permission makes it otherwise.
A host that must do better needs a hardware-backed store, which is a separate decision from this
one.


## The bundled package

One plugin package travels with the host, so that recognising an application and presenting it does
not depend on a repository being reachable. The bytes are in `bundled-plugins/`, one directory per
package, and `bundled-plugins.lock` beside them says what those bytes are: the package, its version,
the digest and exact length of every file, the trust root the copy was verified against, and the
repository, commit and generation it came from.

The lock is checked on every activation, not once at installation. Activating a bundled package
opens the bundle directory, reads every file relative to that handle with links refused, and
compares each one's length and SHA-256 digest with the lock before anything is parsed. A package
whose files do not all match does not activate at all: there is no half-activated package, and no
unverified byte reaches a parser.

Absence and tampering are answered apart, because a caller does different things about them. A file
that is not there is `PACKAGE_UNAVAILABLE_OFFLINE`: nothing is reachable to fetch it from, and the
honest answer is that the package is unavailable rather than a capability that would fail the moment
somebody used it. A file that is there and is not what the lock names, a link in place of one
included, is `REPOSITORY_UNTRUSTED`. A read the machine could not make for want of a descriptor or
memory is neither, and is `RESOURCE_UNAVAILABLE`: sending a person to look for tampering that never
happened is its own kind of wrong answer.

The bundle holds one directory per package, directly under `bundled-plugins/`. Activating a package
reads the files the lock names and no others, so a file, a directory or a whole package that is
there and is not in the lock is found by the check over the whole bundle,
`scripts/sync-bundled-plugins.sh --verify`, rather than by activation.

What the bundle is not: a catalogue, an enrolled repository, or a grant. It carries one generation,
frozen at the commit it was copied from, and the package's capability requests, grants and
repository ceiling are applied to it exactly as they are to anything installed. The plugin runtime
reference describes how the copy is made and what the synchronisation script refuses.

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

The profile decides which login context a worker is started in, not only which variables it is
given. On macOS a desktop-bound worker's job goes into the user's graphical domain and a headless
one's into the background domain, because a headless worker inside the graphical login would have
that login's access however little of its environment it was given. On Windows a worker is a child
of this daemon and runs in the logon session this daemon runs in, so a headless session there is one
with no desktop handles and no promise about the desktop rather than one that cannot reach it.

Linux places a job in no login session at all: a user service manager started at boot has no
display, no compositor socket and no session message bus, because those belong to a graphical login
that happened later. So a desktop-bound worker's transient unit is given the selected session's own
handles explicitly, read from that session's leader, and every other login-session handle is removed
from what the unit would otherwise inherit. Both halves matter on a host where one user is logged in
twice: the manager holds one environment for the whole user, so what it offers is used only when it
says which session it describes and says the selected one, and a handle that was not collected is
cleared rather than left to arrive from the other login. A headless worker is given none of them.

The fallback supervisor, which a host with no service manager uses, has no domains to choose
between: a worker it starts is in whatever login context this daemon is in, and a headless worker
there has the desktop's variables stripped rather than a login context of its own.

What a logout does to a worker of either profile is the platform's answer, and
`docs/host/platforms.md` records it per platform along with the explicit setting that changes it on
Linux. Nothing here enables that setting: creating a session never turns on a persistence option,
and neither does installing the host.

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

### Which shell, and what the session claims

A create request names a shell mode, and the two modes are different promises rather than degrees of
the same one.

**Managed** launches a KalaReach-qualified package: the exact binary its reader patch was built
into, with the flags that package declares. The daemon resolves the package before it records a
reservation, so a shell no package qualifies is `SHELL_INTEGRATION_UNSUPPORTED` by name rather than a
session that closes itself a moment later, and a command line rather than an executable is refused
the same way. Step 6 changes for a managed session: the worker binds the root-editor endpoint
*before* the shell starts, because the address and a one-time secret travel to it in its own
environment, and it reports itself ready only after the integration has qualified, which is after the
user's startup files have run. An integration that fails before that closes the session that was
being created and records why; an explicit compatibility retry is a new create request.

**`native_compat`** launches the selected stock shell. It keeps create, attach, detach, close,
transfer and terminal presentation, and it claims none of the managed editor: Ctrl-D follows that
shell's own behaviour and can close the session, a launch installs no command, and `kr detach`
remains available. It is an explicit choice and never an automatic substitution for a managed
request that could not be served.

[docs/shell-integration/host.md](../shell-integration/host.md) describes the endpoint, the handshake,
the phases, the launch transaction and the guarded startup entries `kr shell` writes.
## The desktop a session runs on

Where a session is shown and where its processes run are different questions. `kr new --invisible`
answers the first. The execution profile answers the second, and it decides which display, which
message bus and which operating-system permissions a command inside the session actually has.

| Profile | What it is bound to | What ends it |
| --- | --- | --- |
| `desktop_bound` | the boot, the operating-system user, the platform's login-session identifier and the login-session generation | the graphical login ending, which closes the session with `desktop_lost`. Losing every attachment does not, and neither does this daemon restarting |
| `headless_user` | the boot and the operating-system user | the platform's own answer, which this host reports rather than assumes |

A desktop host creates sessions in its own desktop's context and an SSH-only or headless
installation creates them in its configured headless context. `kr new` prints which one it is about
to use before it creates anything, and the create receipt records the one it used. `--invisible`
changes neither: an invisible session in a desktop context keeps that desktop's access, which is
what lets an agent with no terminal window drive a browser on the screen in front of you.

The identity is the whole of it, and nothing is ever rebound to a new login: a session whose
desktop ended is closed and you create another. How well a reused login-session number is told
apart from the login before it depends on the platform, because the generation is the start value
of the process that owns the login and each platform owns its login differently.
`docs/host/platforms.md` says what each one establishes, including where the answer is weaker.
`docs/host/platforms.md` has the per-platform detail, including what each platform does at logout
and what it will not tell this host.

A desktop is not a permission. Screen capture and input injection each need an operating-system
permission that selecting a desktop does not carry, and `environment.capabilities` answers each of
them separately, in the shared capability-evidence shape, saying what produced the answer and what
makes it stale. Nothing there performs the operation a capability is: a platform query can refuse
either of them and cannot establish one, so an answer nothing has run says exactly that. There is no
general desktop-control interface here either: desktop automation means the user's own tools
running in the selected context under the permissions they were actually granted.

## First-start permissions

Selecting a desktop is not a permission, and neither is holding one permission evidence for
another. On macOS, Accessibility, Screen & System Audio Recording, Full Disk Access and the
Automation grants are four separate things granted to one signed application, and Full Disk Access
does not stand in for the rest: an application holding it still cannot take a screen image or send
a keystroke. The microphone and Remote Desktop belong to the features that use them and nothing
asks for them until you do.

None of these can be enabled by KalaReach. Some of them can only be set in System Settings at all,
so setup takes you to the right pane and you set the switch.

### What a check can establish, and what it cannot

A permission cannot be verified without performing the operation it guards. Asking the platform
what a permission is set to is not the same question, and on macOS it is not a question a program
can put about itself. So the checks perform the operations:

| Check | What it does | What it touches |
| --- | --- | --- |
| Read a file you authorised | opens the file you nominated and reads its first few thousand bytes | that file, and nothing else on the filesystem |
| Take a screen image | takes one image of the desktop and measures it | writes the image into the check's own directory and removes it before answering |
| Find an element | asks the accessibility tree for the name of one element | reads the tree; selects nothing, moves nothing, clicks nothing |
| Open an application | starts one new hidden instance of the platform's own calculator, and ends the instance it started | nothing you already have open: the application it starts has no documents to reopen |
| Send a keystroke | delivers one keystroke | this one changes something, so it runs only inside a test context that owns the application the keystroke lands in, and this build has none |

Each of them runs in the same execution context an agent's own tools run in, each declares what it
does before it runs, each is bounded, and none sends input to an application you did not ask about
or changes anything you own. The last one is the exception that proves the rule. Delivering a
keystroke safely means owning the application it lands in, and the platform's own input facility
delivers to whatever is in front instead, so it is not performed here at all: its record says
nothing was established either way rather than claiming an answer.

Every result is a capability record in the shared shape: the state, `disclosed_probe` as what
produced it, the exact facility it was established about, and what makes it stale. That last part
is what decides when a check runs again: the facility or the host agent being replaced, an
operating-system permission changing, a new login, or a different execution profile. Time is not on
the list. Nothing about a permission changes because an hour passed, and a check that re-ran on a
clock would take an image of your screen for no reason.

### What each answer means

`ready` is an operation that was performed and worked. `permission_required` is one the operating
system refused, and the record names which grant. `desktop_unavailable` is a desktop that is not
there to act on, and a check that ran on a desktop that is there and did not get far enough says
that instead. A capability nothing has performed the operation for says so, and that is an answer
rather than a failure: it means nothing is known either way, which is different from knowing it
cannot be done.

One more answer belongs to the person rather than to the host. macOS gives a new grant to a process
when that process starts, so an application that was already running when you granted something is
still running without it. When a permission has been granted and the capability still reports that
the permission is required, the answer is to open KalaReach again.

A tool-specific permission stays its own record throughout. An accessibility grant this context
holds says nothing about a screen image, and no part of this ever reports one as evidence for the
other.

### Where a grant is recorded

An operating system files a permission under a signed application, which is why setup shows that
identity before it guides you anywhere: the bundle identifier, the file it is running from, and the
signature on that file as the platform's own signing tool reports it.

What matters is not whether there is a signature but whether it is one the operating system will
recognise again. An ad-hoc signature is one the machine made for that file; the next build carries
a different one, and every grant given to the old one stays with it. The same goes for a bundle
inside a build directory, which the next build overwrites. Install a signed build first.

### Running the demonstration

`scripts/e2e-permissions.sh` runs the whole of it on the machine it is run on: a real control
daemon, a real worker in your own graphical login, what the host publishes through
`kr doctor --json`, the four checks performed from that session's own shell and the records they
produce, and the tools an agent reaches for on that desktop. It ends every process it started, it writes its artefacts under
`KR_TEST_ARTIFACTS_DIR`, and it asks for no account of any kind.

## Sleep

This host does not change the machine's sleep policy unless the owner asks it to. The setting is
off until then, `kr host power` shows and changes it, and the two choices are separate: mains power
only, or battery as well.

With it on, the host holds the platform's own assertion against automatic sleep while it has
verified foreground work or a request it has accepted and not answered: a session whose worker
reports an agent at work, a session waiting for a decision to be answered, or a closure that is
still stopping processes and draining their output. Work begins and ends without this daemon being
told, so while the setting is on it looks at the question every fifteen seconds as well as whenever
a session is created or closed and whenever it is asked; while the setting is off nothing looks at
anything. A close that arrived over the network reaches the same review at the same point, when
the worker has accepted it, so a closure a device asked for is looked at under the owner's setting
rather than releasing an assertion the host never took. The review runs on its own task and the
device's answer does not wait for it, so what this establishes is that the setting is looked at
rather than that an assertion is held for every instant of every closure. Each session gets half a second to answer and the whole round two seconds, so the answer
does not get slower as sessions are added. Host status, `kr status` and `kr doctor` each print what
is held and why.

The assertion is held by running the platform's facility as a child with a pipe on its input, so
releasing it is closing the pipe and a daemon that dies releases everything it held. A facility
that has already exited holds nothing, so one that does is reported as an assertion this host does
not have rather than as one it does.

An assertion asks the operating system not to sleep on its own. It does not stop a closed lid, a
forced sleep or a platform policy that overrides the request, and none of those need to be stopped:
every deadline this host decides is measured on a clock that counts suspended time, so waking up
never brings an expired action window, lease or grant back.

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

## Windows

The terminal on Windows is a pseudo-console. It is the same session, the same lease and the same
retained history; what differs is the three things this platform does its own way.

**The console, and where byte preservation begins.** ConPTY renders an application's console-API
output into VT sequences before the host sees any of it. So the promise this host makes starts at
ConPTY's output pipe: every byte that arrives there is carried through unchanged, and what an
application did through the console API rather than by writing bytes is whatever ConPTY made of it.
A session never claims to have preserved writes it was never handed.

**The job object.** The worker holds the sole owning handle for one job object per session, with
kill-on-close, and every process it starts joins that job *before* it runs: the shell is created
suspended, assigned, confirmed to be held, and only then resumed. Both limits are read back from
the kernel rather than taken from what was asked for. Default breakaway stays disabled, so a child
cannot leave by asking. A vendor sandbox that creates a job of its own nests inside this one;
nesting and breakaway are separate questions, and disabling the second says nothing about the
first. Where the job cannot be created, cannot hold what it must, or does not hold the shell, the
**launch fails by name**: no session is quietly given a weaker boundary instead. Section 7's other
permitted outcome, an explicitly selected reduced-ownership execution profile, is not something
this build offers, because nothing selects one. A GUI resource that has to outlive the session is
created outside the job and is never ended by closing one.

A closure says what it could not establish. A job that stops answering, a process the operating
system will not describe, and a termination the kernel refused are each carried into the closure
receipt as a surviving resource, and any one of them keeps the ownership coverage incomplete: a
record that ended says nothing about a boundary that was never read.

**The interrupt, and asking a shell to stop.** There is no foreground process group here and no
signal to send one. The interrupt is the byte the console turns into a control event for whatever
is attached to it, written through the console's own input rather than through the session's, so
it is not queued behind input this host has not yet delivered. What it cannot get ahead of is what
is already in the pipe, which the console reads in order; a console with no room takes none of it
and says so rather than reporting an interrupt that did not happen.

The same byte is how a closure *asks*. The five-second grace period needs a request the shell can
answer, and this platform has no other; force is the step after it, and it is the job object that
carries force to the descendants.

**win32 input mode.** A ConPTY asks for console key records with `CSI ?9001h` and disables them
with `CSI ?9001l`. Both stop here: neither is forwarded to a client, and neither appears in a
snapshot or in a restoration, which are the other two ways bytes reach one. The worker records what
its own backend asked for.

The encoding is `CSI Vk;Sc;Uc;Kd;Cs;Rc_` - a final underscore, not an APC string - carrying the
virtual key, the scan code the console reported, one UTF-16 code unit, the key-down flag, the
control-key state and the repeat count, with all six fields written every time. A reader fills in
`0,0,0,0,0,1` for any that were omitted. Nothing decodes a record and encodes it again with a scan
code this host chose. A client that sends no records sends legacy VT input, which is accepted
without any claim about scan-code fidelity.

What a console inside the session does - `wsl.exe`, an `ssh` client, a nested ConPTY - happens on
the boundary between that console and the one this worker owns, below this host: what arrives here
is whatever the owned console chose to send, and what this host records is that. Restoring the
*client's* console to the modes it had before an attachment is the attach client's own saved mode
words, and that is what a detach writes back.

**What is not here yet.** The console reader and the encoder exist and are tested, and the worker
selects the ConPTY backend so that a mode request from its own console is recorded rather than
ignored. What does not exist is the transport between them: the session protocol carries input as
bytes, so a local attach client on Windows still sends bytes rather than typed key records, and the
worker does not yet choose the encoding per client. A session therefore runs on the legacy VT path
today. Nothing reports that at runtime: the engine tracks which fidelity the backend asked for and
the reader knows which one it is reading, but no receipt, diagnostic or client message carries
either answer yet, so this page is where the limit is stated.

### Running the Windows tests

Two machines run them and they run different things.

**The GitHub-hosted runner** (`windows-2025`, the `windows` job in `.github/workflows/core-ci.yml`)
compiles the whole workspace and its tests with `-D warnings` and then runs what has been qualified
on this platform, one command per step:

```
cargo test --locked -p kr-term -p kr-project -p kr-cli
cargo test --locked -p kr-worker --lib
cargo test --locked -p kr-worker --test windows
```

followed by the repository boundary again on its own, so a result names the system it happened on,
and the `aarch64-pc-windows-msvc` compile. The pseudo-console tests open a console of their own and
drive it, which the runner can do.

The worker's other integration suites are compiled here and not run. They drive a session the way a
Unix pseudo-terminal behaves, and on Windows a number of them fail on that difference rather than
on the code they are checking; running them and calling the result a Windows failure would say
something nobody has established. Two tests in the worker's library and one in its service are
skipped here for their own stated reasons, which `cargo test` prints.

What the runner cannot do is the release matrix. It has no interactive logon, no window manager, no
IME and no physical keyboard, so nothing about Windows Terminal, a real desktop session, IME
composition at the keyboard or a GUI logout is established there. Those need a machine.

**The Windows test machine.** Prerequisites, all of which the CI runner also has:

| What | Why |
| --- | --- |
| Windows 11 or Windows Server 2025, x86-64 or ARM64 | the release baseline |
| Visual Studio 2022 Build Tools, the C++ tools for the target, Windows 11 SDK 22621 | the MSVC toolchain the product is built with |
| LLVM, with `clang` on `PATH` | `ring` compiles its ARM64 Windows sources with clang rather than `cl.exe`, so the ARM64 build needs it |
| rustup with `x86_64-pc-windows-msvc` and `aarch64-pc-windows-msvc` | the two targets the product ships on |
| PowerShell 7 | the shell the product launches, and the one `crates/kr-worker/tests/windows.rs` qualifies |
| Git for Windows | its `usr\bin\sh.exe` is the POSIX shell the test scripts run in; `kr_worker::testing` finds it |

The test list, in the order it is worth running:

```
cargo clippy --workspace --all-targets -- -D warnings
cargo test -p kr-term -p kr-project -p kr-cli
cargo test -p kr-worker --lib
cargo test -p kr-worker --test windows -- --nocapture
cargo test -p kr-project --test boundary -- --nocapture
cargo check -p kr-ipc -p kr-worker -p kr-controller -p kr-cli -p kr-term -p kr-project \
  --target aarch64-pc-windows-msvc
```

`cargo test -p kr-worker` on its own, with every suite, does not pass here yet; what each suite hits
is recorded where this branch's work was handed over. Set
`RUSTFLAGS=-Clink-arg=/IGNORE:4099` first: the vendored C library ships no debug database and the
linker says so once per object file, which is thousands of lines and drowns everything else.

`cargo test -p kr-worker --test windows` is the platform suite: it opens a pseudo-console, starts
PowerShell 7 inside it, resizes it and reads the new geometry back from the application, drains
what the application wrote after it has gone, delivers the interrupt, checks that the job holds the
shell and the processes it started and that terminating it ends the tree, checks that closing the
last handle to the job ends what it holds, and checks that a process started outside the job
survives the session's closure.

What no automated suite here establishes, and a person at this machine has to: a vendor sandbox
that creates a job of its own running inside the session's job; a child that asks to break away
being refused; an IME composing at a real keyboard; and Windows Terminal, WSL interop and a nested
ConPTY across the release matrix.

The two build commands both need the developer environment for the target loaded first, which
`vcvarsall.bat x64` or `vcvarsall.bat x64_arm64` does.

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

### The admission a mutation carries

A deadline checked before a service takes its store lock proves the deadline stood before the
wait, which is not the question. So the daemon builds one **admission** when it accepts a mutation:
the accepted deadline, the authority revision it was admitted under, and the connection it arrived
on. The mutation carries it into its own transaction.

Every service in this host follows one rule, in this order:

1. Take the service's own store lock.
2. Take the daemon's registry lock. Admission and revocation both take these two in this order, so
   none of the three can interleave.
3. Check the admission. It is refused when the accepted deadline has passed, when the authority
   revision has advanced past the one the mutation was admitted under, or when the connection's
   registration has been withdrawn.
4. Write, with nothing awaited between the check and the write.

`Controller::enter_admitted` is steps 2 to 4 as one operation: a service in another crate holds its
own store lock, calls it, and writes inside the closure, so the registry lock is held across the
check and the write and a revocation cannot land between them. `kr_controller::authority::AdmittedMutation`
is what the mutation carries from the moment the daemon accepted it.

`session.create` checks it inside the same critical section as the transition to `spawned`, after
the durable write rather than before it, so a create that queued past its deadline fails its
reservation instead of starting a shell. `session.close` checks it once it holds the worker's
client, which is where the waiting happens.

The authority changes take the two locks the other way round, because the admission is a question
about the registry: they hold the registry guard and take the grant store's lock inside it, and
nothing takes those two in the other order. The check itself is the same, and it happens inside the
grant store's transaction. `grant.create` checks once the parent is resolved and before the grant
and its invitation are written. `grant.revoke` checks once the subtree it is about to withdraw has
been read, which walks every grant this host holds. `device.revoke` withdraws the grants in that
transaction and then marks the device's own record, which is a separate store. When the transaction
withdrew nothing — the paired device whose grant lives in its pairing record — that record is
the whole withdrawal, so the check is repeated before each wait between the two, and a refusal
after the fence has been written down is answered once that fence has run rather than instead of
it. When
the transaction did withdraw something, the rest follows whatever the clock has done since: a
revocation takes authority away rather than granting any, and grants withdrawn beside a device
record still live is the state worth avoiding.

An admission can carry **no deadline at all**, and that is not the same as one whose deadline has
passed. A retry of an action this host may already hold has no freshness: section 9 keeps a receipt
readable after the window that admitted it is gone, so the daemon forwards such a mutation with a
spent deadline and lets the process that owns the record answer it. The authority half still
applies, because disclosing a retained result under withdrawn authority is exactly what the
registration check exists to stop.

Such an admission may be *answered* and may not **write**: `Controller::enter_admitted` refuses it
outright, because what the freshness admitted was the action and nothing can admit a new one
without it. A mutation this daemon performs itself has its retained record here, so a window that
admits nothing has already been past its own answer.

### The revocation barrier

A revocation is complete for a worker when that worker has acknowledged installing the revision
**and** fencing the undispatched actions it affects, or when its execution is confirmed ended.
Nothing else completes it, and nothing ends a process to make it complete: a worker that will not
answer stays `pending`, and the daemon says so.

The acknowledgement carries two lists, because the fence produces two answers:

* the undispatched intents it rejected, which are now `rejected(revoked)`;
* the actions whose dispatch transition had already won the serial race, which are **named** rather
  than counted. The set is defined by the race rather than by the outcome, so an action that
  settled while the revocation queued behind it is named too, and each one's receipt state says how
  much is known about what it did.

Both lists are retained. An acknowledgement lost on the way back is the ordinary case, so the
worker replays what its fence found for a repeat of the same revision, and the daemon accumulates
across passes rather than replacing: a fence that ran in two goes has to have all of it named.

The evidence is bounded, because the acknowledgement that carries it is one control frame. A fence
names at most `kr_protocol::action::MAX_NAMED_FENCED_ACTIONS` actions of each kind and reports how
many more it holds; every one of them keeps its own receipt in the worker's journal, which is where
the complete record lives either way. A revocation whose evidence would not encode is worse than
one whose evidence is partly counted.

The names live in the worker's journal, in a `fence_evidence` row per named action, and not in its
memory, and the position the last completed fence reached is a row of its own in `fence_state`.
That is what lets a revocation's result survive what memory does not: a fence that failed part way,
an acknowledgement lost on the way back, a page whose exchange failed, collection taking the
receipt the name refers to, and the worker's own restart.

A revision advancing is not what finishes a revocation's names. They are kept until the daemon has
taken them, however many revisions have been installed since, because the actions a fence could not
take back are named in the *result*. What the daemon holds is a fact the worker has: an
announcement asks for the page after the names it already has, and that is what the worker writes
down, against the controller generation that said it. A replacement controller holds none of what
its predecessor collected, so a later generation's count replaces the figure rather than being
compared with it, and only a count the generation asking now made is what finishes a revocation's
names.

Keeping them for a daemon that stopped asking would grow the journal a revocation at a time, so at
most `kr_worker::journal::MAX_HELD_REVOCATIONS` revocations have names in it at once, counting the
one a fence is about to name. Past that the oldest go, and the count of what went takes their place
in `FenceEvidence.omitted`, so a page that carries nothing because nothing is left says how much is
missing rather than reading as a fence that named nothing. Those counts are bounded in the same
way, and a revocation older than the oldest count is answered with no evidence at all rather than
with an empty page: absent evidence and empty evidence are different statements, and the daemon
reads the difference. The boundary is written down before the count it replaces goes, so a failure
between the two leaves the conservative answer rather than none.

The daemon keeps its reports the same way, one per revocation rather than one per worker. An older
revocation's result names what that revocation's fence named, and a newer one's lists are a
different question's answer. It also asks again for the pages an older revocation still owes: the
revision in force comes first, and the unfinished ones after it, out of one page budget per
announcement.

A rejection and its name are one transaction. A rejection committed without its name would be an
action the result owes and cannot produce, and the next pass would not find it: a pass selects
intents that are still accepted, and that one is not.

The evidence is delivered a page at a time. One acknowledgement carries at most
`kr_protocol::action::MAX_NAMED_FENCED_ACTIONS` names and says how many remain; the daemon asks
again from where the page ended, through `AuthorityRevisionNotice.evidence_from`, until nothing
remains or it has collected as many pages as one announcement collects, and each of those
exchanges is bounded like the first. The barrier holds on the first
page, because that page *is* the acknowledgement; what the later ones complete is the naming, and
`WorkerBarrier.names_pending` says how much of it has not arrived rather than letting a partial
report read as a complete one.

An announcement that arrives while the worker is inside a dispatch transition is answered with a
refusal that says to come back, and the daemon reports that worker `pending`. The fence takes the
same serial boundary a dispatch does, which is what makes its two answers two answers: it reads an
action either before its dispatch marker, and rejects it, or after it, and names it, never between
the acceptance and the marker. The refused revision is recorded, and the worker's own maintenance
runs the fence inside that boundary, so the fence does not wait on the daemon asking again.

A worker that reports **no** evidence is a third case, and it is not a barrier that holds. Such a
worker has installed the revision and said nothing about its fence, which is half of what section 9
asks for, so the revocation stays `pending` for it with a report that says which half is missing.
Absent evidence and empty evidence are different values on the wire for this reason.

Membership is the registry's durable worker rows, not the verified directory. A worker whose
challenge failed, or that a replacement daemon has never reached, is still recorded and still
pending: a revocation is not complete for a worker nobody can account for. Each announcement is
bounded, because waiting is the opposite of completion, and a worker that runs out is reported
`pending` while the announcement carries on to the next one.

`kr_controller::authority::AuthorityBarrier` holds both halves, the lease issuer and the fence
reports, because a lease running out is not a barrier holding and the two are read together.

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
3. **Reads the daemon owns** — the host, the environment list, the environment's capability
   records, the diagnostics, the session list, one session's metadata, and the repository and
   workspace metadata — are answered by the daemon, out of the same call a local caller reaches.
4. **Effects the daemon owns** — creating a session, and the repository and workspace mutations —
   are performed by the daemon, on a task that outlives the connection that asked. They name no
   session, so no worker owns them.
5. **Everything a session owns** is forwarded to the worker over a link the daemon opened for that
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
  condition this request meets — a `session.attach` whose `claim_geometry` registers a claim needs
  `terminal.geometry`. A condition the daemon cannot decide is treated as holding, so the right is
  asked for rather than skipped. *Asking for* a capability is not one of these conditions: it is a
  request the host intersects, described below.
* **Capabilities.** What an attachment is granted is what it asked for intersected with the rights
  the grant carries, made where the attachment is admitted. See "What an attachment may do".
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

### What an attachment may do

Section 8 separates three things: observing a session, owning its size and holding its input. What
an attachment is granted is what it asked for intersected with the rights of the grant the request
was checked against, capability by capability:

| Capability | The right that carries it |
| --- | --- |
| `observe_terminal` | `session.view` |
| `observe_semantic` | `session.view` |
| `input` | `terminal.input` |
| `geometry` | `terminal.geometry` |

The table is `kr_protocol::rights::attachment_capability_right`, beside the action vocabulary, so a
right added to the vocabulary has to be decided for the capabilities rather than defaulting into
one. The intersection is made in the worker, where the attachment is admitted, because that is
where the attachment's own record is written, and the summary the caller is given then says what it
actually holds.

Every later operation on that attachment — resizing, transferring the size, acquiring the lease,
writing input — passes two checks, not one. The daemon checks the grant's current rights for the
method, as it does for every request. The worker then checks the capability the attachment was
granted. The second is what the intersection buys: a device whose grant carries `terminal.input`
but whose attachment was admitted without the input capability is refused by the worker, and a
device whose grant has since lost the right is refused by the daemon.

Asking for a capability the grant does not carry is not a refusal. A client that asks for
everything it can use gets an attachment without the parts its grant does not reach, which is what
an intersection is for; registering a geometry claim is the separate thing, and that does need the
right before anything is admitted.

Exactly one caller is not narrowed: a local caller on the worker's own socket holding no grant. Its
peer credentials already proved it is this user and the worker's own authority covers its session.
Everything else is narrowed, so a caller that reached the host some other way and named no grant
receives nothing rather than everything.

### Repositories and working copies over the network

The registry admits a paired device to all ten project and workspace methods, and the daemon serves
them through the same call a local caller reaches, so a device's `project.list` and the owner's are
one answer. The mutations take the daemon's own path: the envelope is checked first — a project
acts on a repository or a working copy, so a target naming a session or an application is refused —
then the action's route is recorded with this host named as the owner of what it produces, and the
effect runs on a task a dropped connection cannot cancel part way. `Controller::project_mutation`
is the one place either door reaches the service from, and it asks about the admission the ingress
recorded immediately before the write.

What a device is additionally held to is its grant: `project.create` for initialising, cloning and
adopting, `workspace.manage` for creating and removing a working copy. The four reads require no
right of their own, so a grant that covers the environment reads the whole repository and workspace
surface.

**Five of the mutations are not served to a device at all yet.** `project.init`, `project.clone`,
`project.adopt`, `workspace.create` and `workspace.remove` each name a destination or a source that
this host cannot check a device's authority over. A creation carries the absolute parent directory
it wants and this host resolves it once with its own filesystem authority; a working copy's source
is bounded by nothing but the environment. For a caller on the machine's own socket that is the
user's own authority over the user's own filesystem, and those five run as they always have. For a
device the grant's action right would be the whole of the restriction — `project.create` would
reach any directory this host can open, `workspace.manage` every repository the environment holds —
and section 14 asks for an authorised destination handle while section 23 asks for a destination
policy and for source and destination grants. So a device is refused them by name, with a refusal
that says which subject it cannot authorise. It keeps the four reads, and `project.operation.cancel`
for work it started itself. The refusal is lifted when the project service bounds a destination and
a source by the grant that asked.

What the resolution does establish, for the caller that is served, is that the directory it opened
is the one the effect writes into, by the identity it recorded, so nothing is substituted
underneath it.

One further limit, stated rather than implied.

* **`action.read` does not answer for an action this host owns.** A receipt lives in the journal of
  the session an action was performed on, and a create or a repository mutation belongs to no
  session. What such an action leaves is kept by the service, which is not a receipt in the shape
  that method answers with, so the request is refused and the refusal says how the outcome is
  obtained: submit the action again under the same identifier. That is the recovery section 9 puts
  first, and it works — the service answers the repeat from its own record without performing
  anything twice.

The admission a project mutation carries is asked about twice. Once where the daemon accepts it,
under the registry lock, and once inside the service's own blocking work, immediately after it has
failed to find a retained record and immediately before it acts. The second reads the registration
and the clock from memory, so it costs nothing and covers the waiting that the first cannot: a
blocking task to be scheduled and a retained record to be looked for. A retry never reaches it,
because the retained record answered first.

What neither covers is the service's own preparation. Resolving a destination and taking the
store's lock happen after the second answer, and a clone or a materialisation runs behind them, so
a revocation or an expiry that completes in there reaches an action that then begins. Section 9
asks for authority and expiry to be revalidated immediately before the effect and says that durable
acceptance does not preserve expired authority, so this is a gap rather than something the section
allows. Closing it means asking inside the service's own transaction, which the service would have
to offer.

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
| `receipts` | one row per `(verified_actor_id, action_id)`: method, revision, state, rejection reason, payload digest, subject digest, accepted deadline, the boot and continuous instant it was created at, error, timestamps |
| `fence_evidence` | one row per action a revocation's fence named, in delivery order: the revision, the position, whether it was rejected or is possibly executed, the actor, the action, and for a possibly executed one its method and receipt state |
| `fence_state` | one row: the journal event position the last completed fence reached, which is where the next one starts looking |
| `fence_delivery` | one row per revocation whose names are still accounted for: how many its fence produced, how many the daemon has taken, and the controller generation that took them |
| `fence_forgotten` | one row: the revision up to which this journal can no longer say what a fence named |
| `host_time` | one row: what the host time contract has to survive a restart - the last qualified checkpoint, the trust the clock stands at now, the furthest reading it could prove, and the expiration tombstones |
| `results` | the result a duplicate request must receive back |
| `observations` | additive evidence about an action: its provenance, the subject and version it saw, the source cursor and what it claims |
| `closure` | the session's final record |
| `session` | the session's own summary, so a reader with no worker can still say what the session was |
| `host_events` | an application notice that had no attachment to go to, and where in the output stream it happened |
| `outbox` | the event each state transition committed with: its immutable identifier, the stream, the subsystem, the actor and action, the subject revision and the content class |
| `outbox_cursors` | one row per consumer: how far it has taken the outbox and how much it has taken |
| `journal_gaps` | one row per interval durable writing was unavailable, so no reader reads continuity across it |

The order is the contract. The intent is committed before the caller is told it was accepted. The
dispatch marker is committed before the effect.

**Everything the host can decide is decided before the marker.** There is no
`dispatching -> rejected` edge, because past the marker nothing may imply that an uncertain side
effect did not happen. So a refusal the host is able to reach on its own, a stale geometry epoch, a
lease somebody else holds, a cancellation of an action that has already been dispatched, happens in
the revalidation rather than inside the effect, and the receipt it leaves says `rejected`.

**Recovery is two rules.** A marker with no authoritative outcome becomes `unknown` and is never
dispatched again, because nothing can establish from here whether the effect happened. An accepted
intent with no marker is *rejected*: section 9 lets it proceed only if the revalidation still
passes, and the freshness it was admitted under cannot be revalidated after a restart, because the
deadline was decided on a continuous clock this process no longer has and the connection and the
window that admitted it went with the process that issued them. Rejecting it also releases the
outstanding-mutation capacity it was holding.

**De-duplication records are kept for 30 days**, pruned while the worker runs rather than only when
it starts. Retention is a wall-clock period and the wall clock is the thing that can move, so a
record this boot wrote is kept while a window that could admit its exact original request may still
be live: a window lasts at most five minutes on the continuous clock, and no step of the wall clock
shortens that. A record from an earlier boot needs no such guard, because the windows a host issues
live in its memory and a host that has restarted can admit nothing through them.

An observation is evidence, not an execution state. Only an authoritative answer about an uncertain
outcome moves a receipt, and an inferred screen never does: a screen is what the host parsed, not
what the interface that owns the subject said. "Observed" in a user interface means evidence was
observed.

A new action identifier cannot quietly take an uncertain outcome's place. The journal stores a
**subject digest** beside the payload digest: the method and version, the complete target and the
parameters, and nothing that differs between a first attempt and the later request that supersedes
it. So a fresh identifier for a subject that already carries an uncertain outcome is refused
unless its preconditions name that action and the receipt revision the caller read it at. A service
that wanted to hide the uncertainty would have to name the receipt it was hiding.

One actor holds at most eight admitted, unsettled mutations at once, lowered by whatever the
connection negotiated. That is section 9's figure, and what it bounds is durable admissions this
host still owes a decision on. A connection that offers to hold none is refused at the handshake
rather than read as one, and a connection that offers more than eight does not get more. Eight is
this build's ceiling: there is no host configuration that raises or lowers it, and when one arrives
it replaces the constant rather than being compared against it.

The concurrent-attachment limit is kept per session in this build, while section 23 states it per
host. One session is the whole of what a worker serves, so the two are the same figure for a
single-session host and the per-host bound is the stricter of the two once a host serves several.

Raw input is not in these tables. Section 9 makes it a separate ordered stream keyed by connection,
lease epoch and sequence, with nothing replayed on reconnection.

### What each store promises

`kr_worker::persistence::stores::STORES` is that table as data. Each entry says how much of a
crash its store survives, what it keeps and for how long, what class of content it holds, what
protects it where it lies, who removes what it no longer needs, how it is brought back into
agreement after a restart, whether a history byte cap may evict it and whether the archive serves
it afterwards. It is data rather than prose because the rules that matter are checkable: a test
walks the journal's own tables and refuses one with no declaration, and another refuses a
declaration that would let a byte cap reach authority or dispatch data.

The rule that does the most work is that last one. **Authority, dispatch and causal-budget data
cannot be evicted under a history byte cap.** A host under output pressure that dropped a dispatch
marker to make room would forget that an action had been sent, and the next retry would send it
again. Only the retained output and the host events an attachment never saw are evictable that way.

### What waits for a flush, and what never does

Section 24 names three commit points that must be durable before something else happens: the
intent before the acknowledgement, the dispatch marker before the effect, and the outcome with its
receipt revision, its event and its outbox record. It permits safe grouped commits to share a
flush; it does not forbid grouping these with each other. **This build commits each of them on its
own**, which is its own policy rather than something the section requires.

They are not the only writes a caller waits for, either. Turning privacy mode on waits for the
generation to be recorded, and a closure waits for its own record, because in both cases the
answer would otherwise claim something the store had not yet taken.
Section 24 forbids a per-keystroke, per-output-byte or ordinary prompt and command telemetry
event from waiting for an fsync, and this host goes further with the first two: a keystroke and an
output byte write no durable row at all. The live parser is in worker memory and the retained
output is a bounded indexed spool.

Grouping is the transaction. A receipt transition writes three rows - the receipt, its event and
its outbox record - in one transaction, so three rows share one flush and either all three are
durable or none of them is. That is what section 24 permits by "safe grouped commits may share a
flush", and the invariant that makes it safe is that a commit point is never grouped with work
nobody is waiting on.

### The outbox, and what reads it

Every state transition commits a small event record in the same transaction. Consumers read the
outbox from a cursor of their own, and delivery is at-least-once: a consumer that takes a page and
dies before recording its cursor takes the same page again. The event carries an immutable
identifier so the consumer can apply it once.

The cursor orders this journal's own events and nothing else. There is no global cross-database
order here and nothing invents one: an event from the transfer journal and an event from this one
are not comparable.

Collection is by delivery rather than by whose receipt an event belongs to. An event goes when it
is past the retention period *and* below every registered consumer's cursor, so a receipt written
thirty days ago whose outcome event was written this minute does not take that event with it. A
consumer that has never registered a cursor has no claim; one that intends to rely on this
registers before it starts.

### When the journal stops answering

A worker whose journal stops answering is not a worker that stops. The condition it publishes is
`kr_worker::persistence::fault::JournalHealth`, and what reads it decides:

| Condition | What proceeds |
| --- | --- |
| healthy | everything |
| faulted | an authorised stop, raw terminal input and interruption under the live lease, and every read |

Everything else is refused before dispatch, which keeps the refusal a rejection rather than an
uncertain outcome: nothing was sent, so the caller is told no rather than told nothing. The two
exceptions are section 7's, which keeps an authorised stop available with `durability=volatile`,
and section 11's, which keeps the native terminal usable. Neither authorises a hidden rich retry.

A fault is classified from the store's own result code rather than from its message: a full store,
a store whose pages are corrupt, a store that is absent, and a write that failed for some other
reason. A full store is told apart from a broken one because a person can act on it.

**Recovery writes the gap down before it clears the condition.** The interval durability was
unavailable becomes a `journal_gaps` row, and only then does the journal call itself healthy; a
recovery whose gap could not be written is not a recovery, because the record would read as
continuous over an interval this host knows it did not write. A store whose *content* could not be
read stays faulted until the store itself says its pages are sound.

### Migrations

Migrations are forward-only, transactional and keyed by a schema version.
`kr_worker::persistence::migration::LADDER` is the list of steps, each one transaction, each
moving one version. A store a newer build wrote is refused rather than read, because reading it
would mean guessing what a column this build does not know about means. A store older than the
ladder starts from is refused too, and named: it needs an explicit versioned import rather than
being restored in part. Code reads one current schema after migration, and there is no branch
anywhere that reads two.

## Retained output, and what eviction leaves behind

Section 20 gives retained session output three bounds, and all three hold at once: seven days, a
1 GiB host-wide cap and a 128 MiB per-session cap. They are simultaneous upper bounds rather than
reserved capacity, so a session well inside its own 128 MiB is still evicted when the host is over
1 GiB. "The first applicable limit" names which bound is doing the work, which is what a person
looking at a gap is told; it does not mean checking one instead of the others.

The session cap is the spool's own capacity, so the append path keeps it close: the eviction runs
after the write rather than before it, so one large append is over the bound until that eviction,
and a segment this host could not unlink stays. The host bound is applied on the worker's
maintenance tick, from a reading of the environment's whole spool directory, so two sessions
writing at once can take the host past it until the next tick. Neither bound is a reservation and
neither is enforced ahead of the write.

Eviction is not quiet. A retention pass records the cursor range it took and the bound that took
it, and a reader asking for a cursor inside that range is told both: `history.page` returns the
range as a gap with a cause. The spool's own capacity is the exception: when an append rotates past
the session cap the oldest segment goes with it, and that drop carries no recorded cause, so the
range reads as a gap without one until a retention pass records the bound it was over. A spool that
has evicted everything writes down where its output got to before it deletes what supports that, so
a session reopened over an empty directory continues its cursor and reports the range that went
rather than starting again at nought.

What a page cannot yet report is a hole *inside* the retained range. The reader asks which segment
covers the cursor it was given; a middle segment that has gone leaves that cursor covered by
nothing, and the page comes back empty rather than as a gap. Segment continuity is not checked,
and the archive's own completeness check reads the oldest cursor and the boundary rather than what
is between them. This task's handoff carries it as residual 21.

Removing output because it is old is expiry-based collection, so section 9's rule applies: a host
that cannot prove its wall clock does not do it. The caps still apply, because they are about
bytes rather than about time. The seven-day line is approached from the safe side: a spool segment
goes only when its newest byte is past the deadline, and the resident window advances only to an
interval whose newest byte is past it. Both a segment and a resident interval are bounded in how
long they go on for - an hour and a minute - so what is kept past the deadline is bounded by that
rather than removed early.

An eviction publishes the boundary before it deletes what supports it, and a boundary this host
could not write stops the eviction rather than losing the record of where the output reached. A
boundary that is written and cannot be read back is a host that does not know what it is missing,
and every page it serves says so.

Receipts are not part of any of this. Section 20 gives them a separately budgeted store and 30
days, so history pressure cannot delete a live dispatch barrier or a de-duplication record.

## The archive service

A closed or crashed session's history, final receipts and retained resource references belong to
the environment archive service, which is a controller module and not a surviving worker.

**Ownership is taken, and only after the worker is gone.** The archive asks the kernel whether the
recorded process is the process that was recorded - both the identifier and the start value,
because the kernel reuses identifiers - and only a confirmed ending is death. Then it removes the
worker's published endpoint and descriptor, and only then is anything opened. The order is that
way round because the answer can be *no*: a daemon that fenced before it asked would delete a
working session's socket on the way to finding out that it was working. A query the platform
declines is not death either, and the archive leaves the session alone.

The removal is best effort, and the answer is one value: whether either half went. It does not
say which. What makes the stores safe to open is the death this host confirmed, not the socket
file: a worker the kernel says has ended cannot answer a socket whether or not the file is still
on disk.

A read of a closed session asks the same question first. A session this daemon has verified is
refused with the endpoint to ask; so is one whose registry record names a process the kernel still
describes, because a worker this daemon failed to verify at startup is absent from its directory
and not absent from the machine. What ownership does not yet have is a token the read methods
require or a lock that spans one recovery, so it is a rule this daemon keeps rather than one the
store enforces, and two reconciliations of one session inside one daemon are not kept apart.
Removing the endpoint is also best effort: a descriptor or a socket this host could not unlink
leaves the fence reported as taken with one of its two halves undone.

**A reader cannot create a worker.** Every read the archive serves is a read of what is already on
disk. A history request never starts an execution, and a retried create is answered from the
reservation the first one made.

**A lost or corrupt journal produces an explicit incomplete archive.** Not an error and not an
empty success: the archive names what it could not account for - a missing journal, one it could
not read, a closure or summary that did not survive, a range of output that is gone, an interval
durable writing was lost - so a reader is told the record has holes rather than reading continuity
into it. "This session kept nothing" and "this host cannot say what this session kept" are
different answers and a reader is owed the second one.

**A worker crash closes the session.** The controller takes recovery ownership, runs section 9's
two recovery rules over the journal the worker left - a dispatch marker with no authoritative
outcome becomes `unknown` and is never dispatched again, and an accepted intent with no marker is
rejected - then asks what is still owned, and only then records the closure. The closure record
carries the terminated process identities, whatever the fence reached, the resources known to
survive, and an ownership-coverage flag that never claims every application was discovered.
Nothing is rebuilt from terminal history.

**What the fence reaches today is nothing, and it says so.** A worker's descendants join the
process group it led, and once the worker has gone the kernel is free to give its number to an
unrelated process whose group would answer to it; the root shell also starts a session of its own,
so its jobs need not be in the worker's group even while the worker lives. Stopping what such a
group held would be stopping somebody else's processes on the strength of a coincidence. The
boundary that would work is the one the platform keeps - the transient unit or Job the supervisor
started the worker in, named from the reservation and unable to name anything else - and this host
does not stop one yet. So the coverage is incomplete and the record says which part of it this
host could not account for.

The transfer service's one retention question is answered here. Section 14 gives a submitted
attachment its session's retention rather than the seven-day unused window, and the archive is
what holds a closed session's record: a session it has a record of keeps what was submitted to it,
one whose journal it cannot read keeps it too, because declining to delete is the answer that
cannot lose a file, and one neither the registry nor the archive knows about keeps nothing.

## Privacy mode

Enabling privacy mode records a **privacy generation** and asks the same four things of every
subsystem it reaches. They are one contract rather than four hooks, because a subsystem that did
three of them would leave the fourth undone somewhere a person could not see.

1. **Fence** what is content-bearing, immediately. Not "stop producing more": stop the queue that
   already holds content from reaching anything outside this host.
2. **Cancel** the work that was admitted and never dispatched. It has not left, so it can be taken
   back rather than followed.
3. **Reject a late result.** Work that had already left is still out there and its answer will
   come back. An answer produced under the generation before this one is refused.
4. **Reconcile** before completion is reported. In-flight cleanup is finished when every subsystem
   says it has nothing outstanding, not when it was asked for.

The generation is written down **before** any subsystem is touched. A generation that was applied
and not recorded would be a boundary a restart could not see, and a late result from before it
would then be published; a host that cannot record it does not enter privacy mode at all.

Content-history retention, description inference, sync production and backup production are
disabled prospectively, together. What this host holds itself is removed with them: the retained
output goes, the spool with it, and the content a settled receipt carries - the intent envelope
the caller sent and the result the action produced - is taken out of the journal while the
receipt's own metadata stays. A receipt that has *not* settled keeps its envelope, because
recovery reads it and a retry of an action this host may already have performed is answered from
it; when it settles later, the host's own maintenance takes its content then.

Two stores privacy mode does not reach yet. The canonical grid keeps its own scrollback, which a
client can still page through, and there is no semantic-history cache or generated-title store in
the worker at all. Both are named in this task's handoff with the task that owns them rather than
described here as though they were done.

A cleanup that could not finish is not a cleanup that finished. A redaction the store refused and
a spool file this host could not unlink are both content privacy mode was asked to remove and has
not, and they are kept apart: each is retried on the host's own maintenance tick and cleared only
by its own success, so a redaction that works does not settle a spool that did not empty. A
session reopened under privacy mode, or one whose privacy state this host could not read, owes
both, because an enabling that was interrupted leaves content behind and nothing on disk says
whether it did.

What stays is named rather than quietly retained: the receipt journal's operation metadata, the
minimal local authority this host holds, the envelope of an action that has not settled, live
pending questions and approvals, which keep working under the grants they already have without
their bodies being exported as historical content, and user-pinned labels, which are kept locally
unless explicitly cleared and excluded from later sync while privacy mode is on. A host that
claimed a functioning durable control system wrote no state at all would be claiming something
untrue.

What has already left the host is shown rather than erased. An uploaded archive or notification is
listed with a separately authorised deletion action for the copies this host holds a reference to;
it does not silently delete unrelated backup collections and does not claim a copy somebody else
holds can be recalled. Local deletion is logical cleanup of this host's own records rather than a
claim of physical secure erase: the files are unlinked and the rows are cleared, and nothing here
says the bytes are unrecoverable from the device they were on.

Turning privacy mode off starts retention again from that moment, under a generation of its own.
It reconstructs nothing, and the new generation is what keeps the private interval's own results
refused afterwards: leaving the generation where it was would make every answer admitted during
privacy mode acceptable the moment privacy mode ended.

A session reopened with privacy mode on does not start retaining again, and one whose privacy
state this host could not read does not either: not knowing whether privacy mode is on is not a
reason to keep output.

### What privacy mode does not reach yet

Stated here rather than left to be discovered, because the gap between what a mode is called and
what it removes is exactly the thing a person cannot check for themselves.

* **Nothing in this build turns it on.** The generation, the contract and the two adapters over
  the spool and the journal are here and tested; no method or command reaches them, and the
  transfer preview, description inference, sync and backup subsystems are recorded stubs rather
  than services. Until a caller exists, privacy mode is a contract this host can keep, not a
  setting a person has.
* **The canonical grid keeps its scrollback.** Retention stops at the spool and the resident
  window; the projection's own history is not reached, because removing rows from it while keeping
  the live screen needs an interface the task that owns the projection has to provide.
* **Application notices keep their content.** A notification's title and body are written to the
  host-event store, and privacy cleanup removes neither the rows already there nor later ones.
* **Content that settles is taken in a second step.** An action admitted under privacy mode has
  its receipt content removed where it settles, which is after the transaction that wrote the
  outcome; a crash between the two leaves it, and two settlement paths do not reach that step at
  all.
* **The archive does not enforce any of this.** A session read after its worker has gone is served
  from the store as it stands: the archive neither finishes an unfinished cleanup nor holds a read
  while one is owed.

Each of these is carried as a numbered residual in this task's handoff, with the next step and who
owns it.

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
| the login a desktop-bound session is tied to | nothing this host can subscribe to, so it is asked on every wake: one kernel query about the process that owns the login session, at most once a second | the same sweep |
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
  are enforced on two of the three platforms, and on Linux a socket is made only of what this host
  can account for, so the ports are a guarantee about the protocol the transports use rather than
  about every packet a name resolution sends. A host whose name service cannot fall back from the
  caches it reaches over a local socket to the resolver itself cannot turn a name that needs the
  resolver into an address inside the boundary, and says so; an address written out in full, and a
  name the files answer, are reached either way. A credential broker that would ask another program
  on this machine over a local socket cannot do that inside the boundary, and the operation fails
  rather than the credential being found some other way.
* **Only this operation's directories are written.** The repository's working tree and its Git
  directory, the destination the operation reserved, and one temporary directory that exists for
  the length of the invocation. Everything else is read-only. That temporary directory is taken
  away by the record this host wrote before it made it, and never by descending into it:
  `crates/kr-project/README.md` says what is left behind instead, and why.

The enclosure is what makes the checks around it sufficient rather than advisory. This host reads a
repository's configuration before it runs Git and reads it again afterwards, and it always could; a
writer racing the two readings is what those checks could notice and not prevent. Now the child
starts inside the directory this host opened rather than at a name, so a tree put at that name
afterwards is not the tree Git works in. What the kernels enforce is that opens for writing succeed
only inside the granted root objects' subtrees as they stand at open time, that execution stays
confined, and that the granted roots are re-confirmed by identity before the spawn and after the
run. Neither kernel asks again on each write through a file already open, so a file opened inside a
granted subtree that a same-account writer then moves out of it is still written through that
descriptor, which is an accepted limit: that writer already holds write access to the file. The
re-confirmation after the run is detection: it says a root changed, it does not keep one from
changing. Inside a granted subtree the kernels draw no further line, so a directory put at an
unrecorded name in a tree the operation owns is written to as the tree is; the only writer who could
put it there is a writer under this same account, who could write those files directly.

What it does not confine, on the two platforms whose mechanism separates the two, is reading. Git
reads the system's shared libraries, its locale data and its certificate store, and a read
confinement that missed one of those would fail an operation for a reason that has nothing to do
with safety. What a repository can reach by reading is what the account this host runs as can reach,
exactly as before.

Where a guarantee cannot be enforced from outside Git at all, the operation that needs it is refused
rather than run under checks that notice afterwards. Two cases are the exception, and
`crates/kr-project/README.md` names them: a directory Git is given by name is answered by the
declared honest result after the fact rather than prevented, and a directory put at an unrecorded
name inside a tree the operation owns is outside the guarantee, because no filesystem confinement
that grants a tree can refuse part of it. A kernel too old to mediate the filesystem rights this
rests on runs no Git; one too old to say which addresses a process may reach runs no remote
operation; and **Windows runs no repository operation at all**, because an application container
cannot keep a repository from being executed from and cannot bound which ports a remote operation
reaches. The platform task that qualifies this host on Windows is what changes that.
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

## The host time contract

`kr_worker::action::time` holds this host's time contract. It rests on three anchors and concludes
only what each one supports.

What asks it today is retention: section 9 stops expiry-based collection while the wall clock
cannot be proved, and the session's journal prunes only when the contract says collection may run.
The deadlines that exist besides that, the action window, the dispatch lease and the accepted
deadline of a mutation, are decided on the transport's suspend-aware continuous clock, which is the
same anchor reached by a different route. The consumer the contract has and nothing yet uses is the
cross-reboot signed object: no store holds one, and `ExpiringObject::signed_across_reboot` is the
shape the grant and archive tasks hand it.

| Anchor | What it proves |
| --- | --- |
| the recorded boot identity | which boot a continuous reading belongs to; a reading from another boot proves nothing, because the clock restarts |
| a suspend-aware continuous anchor (`kr_ipc::clock`) | how much time has passed, including time the machine spent asleep; a timer that excludes sleep cannot extend authority |
| a trusted UTC deadline | the only thing that can outlive a reboot, and usable only while this host can prove what its wall clock reads |

A wake, a reboot or any other discontinuity owes a revalidation before an expiry-dependent read or
mutation is served. The detector is two clocks rather than a notification: one counts a suspension
and the other does not, so the difference between two deltas of theirs *is* the suspension, with
nothing to subscribe to. On Apple and Linux the second clock is `std::time::Instant`; on Windows
`Instant` is the performance counter, which keeps running through a suspension, so the detector
there is `QueryUnbiasedInterruptTime` beside the biased counter `kr_ipc::clock` reads. A suspension
shorter than the tolerance is not noticed, which is a bound rather than a guarantee.

A wall-clock rollback beyond five seconds marks wall-clock trust unresolved. That stops
expiry-based collection and refuses objects whose expiry cannot otherwise be proved. It does **not**
disable a non-expiring personal owner grant, or a fresh online action bounded by this boot's
continuous clock: neither depends on the wall clock. A forward step expires conservatively, and a
rollback never enlarges a lifetime. A previously expired object never revives, because its
expiration tombstone answers whatever the clock later reads.

The rollback is measured against the furthest point this host could ever *prove* the clock had
reached, projected forward by the continuous time since. Measuring against the previous reading
alone would forgive a little slippage, then forgive the next against the moved mark, and enough of
those would give a deadline back indefinitely. The same proven reading is what a UTC deadline is
compared against, with the platform's own uncertainty bound added to it, so an object expires when
it cannot still be valid rather than when a forgiving clock says so.

The checkpoint, the trust it stood at and the expiration tombstones are what a host writes down.
Without them a restarted host would start trusting a clock it had marked unresolved, and an object
it had already expired could revive; `TimeContract::durable_state` and `TimeContract::restore` are
the two halves. A host with nothing recorded starts trusted only when its own time service says so,
because with no earlier mark that answer is the whole of what it knows.

Returning to trusted needs qualified evidence from the configured host time authority and a new
checkpoint, with the old tombstones retained; without that, the owner performs an explicit
authenticated retrust. An ordinary paired peer's clock is never a time authority.

### The platform time adapter

The adapter records the synchronisation source, its status and a bounded uncertainty, using the
interface the platform actually supports. Nothing here opens a socket, contacts a time server or
signs anything.

| Platform | What is read |
| --- | --- |
| macOS | `ntp_adjtime(2)` with no modes set: the kernel discipline the system time service maintains, its status word, its maximum and estimated error, and the time state as the return value |
| Linux | `ntp_adjtime(2)`, the adjtimex status, maintained by `systemd-timesyncd`, `chronyd` or `ntpd` |
| Windows | `w32tm /query /status`: the W32Time service's own source, leap indicator, stratum and root dispersion |

The reading half is behind `cfg` because the call is; the classifier is not. `fixtures/time/adapter.json`
records real platform values for all three platforms and the classification each must produce, so
one machine checks every platform's classification while only its own reading comes from the
kernel. A reading the host could not take reports `unavailable` rather than a synchronised clock
with no stated error, because not knowing is its own state.
## Attention, review and what changed since a visit

The attention engine runs on the host, from typed events. It holds an inbox, a quiet-hours window,
each actor's acknowledgements and the cursors it has consumed, and it reads no clock of its own:
every decision that depends on time takes a reading of the host time contract from its caller.

### Where its events come from

The host's own maintenance reads the retained sources and gives the engine what it has not seen,
keyed by each source's own cursor. Two sources reach it: the question ledger, whose events carry
the moment a request became pending, and the journal's host events, which are the terminal side
effects that had no attachment to go to. A record that no rule covers moves the cursor and raises
nothing, so a later record is not read as a range retention took. A pass reads bounded pages until
it has caught up, and only then decides any timer: deciding against a half-read history would raise
a reminder for a request whose answer is in the next page. A page announces nothing by itself for
the same reason - a question raised and answered inside a backlog is not a notification to send
now - and the timer pass that follows a completed catch-up is what decides what is still owed.

A pass that cannot finish decides nothing. A source it could not read, a page it could not write
down and a backlog longer than one pass reads all leave the timers where they were, and maintenance
comes back for the rest a couple of seconds later rather than treating the still-due deadline as an
instruction to try again immediately.

Maintenance otherwise wakes at the earlier of its own cadence and the moment the engine says a
timer is due, so a five-minute reminder is five minutes rather than five minutes rounded up to the
next time the host happened to look. What it counts from is where the host read the record, not
where the request started waiting, because the sources this build reads record when something
happened and not where that moment sat on the clock intervals are measured on. The reminder is late
by however long a record waited to be read; the next paragraph is why that is the direction to err
in.

One clock measures every interval, and it is not the wall clock. A wall clock can be set, and a
host that trusts one still trusts it after somebody moves it forward an hour, so two readings it
vouches for are not two readings on one scale. Intervals are measured on the machine's continuous
clock instead: it only goes forward, nobody can set it, and it counts the time the machine spent
asleep. It means nothing outside its own boot, so every interval the host writes down is kept as the
continuous reading it starts from *and* the boot that reading was taken in, and one whose boot has
ended starts again rather than being worked out across the gap - once, because opening the store is
what restarts it and opening the store writes the new start down, so the next open finds an
interval this boot can measure. An event brings an anchor
of its own when its producer read that clock, separately for each moment it carries, because a
request can become pending long before the record of it is written. Every one of those answers is
nought or less than the true wait, never more: a reminder that comes late is still a reminder, and
one raised seconds after a request because somebody corrected a clock is an interruption nobody
earned. The wall clock keeps the two jobs it can do - deciding quiet hours, and saying when
something happened for a person reading the record.

### The rule set

Eight rules, each with a stable identifier that outlives any change to the wording it produces.

| Rule | What raises it | Starts at | While it stands |
| --- | --- | --- | --- |
| `attention.pending_approval` | An agent is waiting for an approval decision | urgent | announced again every five minutes |
| `attention.pending_input` | A verified source is waiting for an answer | notable | announced once |
| `attention.input_idle_reminder` | A verified request has waited five minutes | urgent | announced again every five minutes |
| `attention.command_failed` | A command exited nonzero | notable | announced once |
| `attention.review_ready` | A turn finished and is waiting to be reviewed | notable | announced once |
| `attention.adapter_failed` | An adapter failed | notable | urgent after five minutes, then every five |
| `attention.host_contact_lost` | Contact with the host was lost | notable | urgent after a minute, then every five |
| `attention.application_notice` | An `OSC 9`, `OSC 99` or `OSC 777` sequence | informational | announced once |

The idle reminder counts from the moment the request became pending, not from the last output: a
session printing continuously while a question waits still owes the reminder, and a silent session
with nothing pending does not. A repeat of the same condition inside sixty seconds is counted on
the item rather than announced again.

An application notice is the one untrusted rule. Any process writing to the terminal can emit one,
so the item says so and the rule cannot raise any other kind of item; nothing a notice says makes
it a pending approval. A notice the host recorded as a side effect is one that had no attachment to
go to: section 8 sends a notification to the attachment holding the input lease, and a record
exists because nobody held it. With no lease holder there is nobody to send it to, so it goes
through the owner's configured notification policy, and it is retained in Attention.

### Quiet hours

A quiet-hours window defers an announcement and releases it when the window ends. It never drops
one, and it never takes an item out of the inbox: an urgent pending approval is in the inbox
throughout, with its audible delivery held. The one thing that does take a held announcement away
is the condition it was about ending, which is a cancellation rather than a loss: nothing is
waiting on the person any more.

Setting or clearing the window records it and announces nothing by itself. What the change lets
through is released by the next timer pass, and the change wakes maintenance rather than waiting
for its next tick, so the release follows the setting rather than the minute. That is what keeps a
release a decision about the present: announcing inside the setter would decide against whatever
history the host had read at the moment somebody happened to change a setting.

The window is minutes of the UTC day, so the host needs no time-zone database to decide whether it
is inside one. A client converts its own local window before it sets one and may record the zone it
converted from, which the host stores and gives back and never interprets. A host that cannot prove
what its wall clock reads is never inside a window: quiet hours are a time of day, and a
suppression decided on an unprovable clock would withhold a notification at an hour nobody chose.

Setting the window is host management rather than session view authority, because one window
suppresses the owner's delivery rather than one actor's.

### Review, and what it does not do

A version only goes forward, and each version an event names is weighed on its own. A turn at a
version the host has already reached is a record arriving late rather than new review work: it
moves the source's cursor, so what follows it is not read as a range retention took, and it raises
nothing, reopens no completed review and is not a change since anybody's visit. A change set named
beside that turn is weighed separately, so one arriving at a version the host has not seen is
recorded, is review work again, and is a change since a visit, whatever the turn beside it said.

A review acknowledgement records that one actor read one version of one subject: a completed turn,
or a captured change set. It approves no command, applies no patch and changes no Git state.
Section 14 makes promotion a separate authorised action, and the engine has no operation that
performs one, so that holds by construction rather than by policy.

An acknowledgement binds the version it was made against. When a later version arrives the subject
is outstanding again, because a new change is new review work and an acknowledgement of an earlier
version does not cover it. Acknowledging a subject the host holds no version of is refused, and so
is a version beyond the one it holds.

An acknowledgement affects only the actor that made it. It does not stop the host reminding
anybody: the ladder and the repeats belong to the condition, and they end when the condition does.

A refusal the host can decide is decided before anything is dispatched. A subject this session
never held, a version nobody produced, a counter the store could not write down as it was given, a
quiet-hours bound that is not a minute of the day, a log view past its own bounds and one more
actor than the store admits are all rejections, not outcomes nobody can establish.

### Changed since a visit

A visit records how far one actor has read, and never moves backwards. The view compares that
cursor with the semantic events the host retains and answers with three separate things: the
authoritative changes, the ranges that are missing, and a model summary when one covers the
interval. The three never merge. A summary names the interval it was written from and cannot stand
in for an event; a gap is not an absence of changes but a statement that the host cannot say what
was there.

A log view's source offset and its filter travel with the visit. They come back after a reconnect,
each view keeps its own position when a client switches between two, and a view whose range
retention has taken is served from the oldest byte that still exists with the range between stated
as an explicit history gap.

### The feature store, and what a gap means

The state lives beside the receipts, in the session's own private journal, under its own table
names and its own schema version. What it decided is a projection of the journal's events, so that
half can be rebuilt from them: replaying a record the engine has already consumed changes nothing,
which is what makes a rebuild safe to run twice. What people and clients put there is not, and no
replay restores it: the acknowledgements, the per-actor revisions, the visits and their log views,
the quiet-hours window and the identities already given to announcements are records in their own
right, and the store is where they live.

One session's worker is the one owner of its own attention store, for as long as it is running.
Every write replaces the whole state and is made from the copy its owner is holding, so two owners
would each replace the other's work with a picture of the world that predates it. The claim is a
row inside the store: opening it reads that row first of all, and writes its own under the same
transaction, so whatever name reached the database reaches the one claim, and an opener that may
not have it is told who holds it before a row of the state has been read. Every write reads the
claim again, inside the transaction it writes in, so an owner whose store was taken while it was
away replaces nothing: it is told the store is no longer its to write, and whoever opens the store
next reads it fresh.

Letting the store go removes that one claim and nothing else - not the state, and not a claim
somebody else now holds - so the next opener does not have to work out that nobody is holding it.
That removal is the best this worker can do rather than a promise: a file that has gone, or another
holder of it that keeps the write waiting, leaves the claim where it is. An owner that ends without
letting go, one that was killed or a machine that stopped, leaves its claim behind too, and the
next opener is what clears it. A claim from a boot that has ended is not standing, because that boot's processes
are gone with it. A claim from this boot is weighed on the process it names: the worker records the
pair the kernel describes, its number and the start value that tells it apart from whoever holds
that number next, so a claim whose process has gone is taken the moment the next worker asks. Where
the platform will not answer, the claim's own lease decides instead, and it stands for ten minutes
unrefreshed against an owner that refreshes it on every write and a maintenance loop that writes at
least once a minute. A process the kernel says is running keeps its store however long it has been
idle.

A database is journalled under the name it was opened by, so one file that two names reach can be
journalled twice over by two processes that never see each other's work. The store refuses such a
file outright and says how many names reach it. The count is of the file the store has open rather
than of whatever a name reaches now: on Windows it comes from the store's own handle on the file,
and on the Unix family, where nothing safe describes an open file, the name is described without
opening it - a second descriptor there would drop every lock this process holds on the file,
including the receipt journal's - and the store then asks its own database whether the file it has
open is still the one that name reaches. Those are two answers rather than one, so a name swapped
between them is not ruled out; what is ruled out is every ordinary second name. A host that cannot
answer at all is refused rather than admitted.

Every mutating call writes the new state before it publishes the decision. A write that fails
leaves the engine where it was, so the same event can be offered again and produces the same
answer. The exception is the store being taken: that value holds a state that is no longer the
store's, so it answers nothing more and the session's worker opens the store again rather than
retrying against it.

A decided announcement stays written down until a delivery consumer says it has taken durable
responsibility for it. Taking one is two steps for that reason: the host offers what is outstanding
without forgetting it, and forgets it only once the consumer has settled it by its own identity,
which is the item and the announcement's number. That number comes from a counter of the store's
own that only goes forward, so it outlives the item it was given for: a condition that ends and
returns is a new item, and an identity a consumer already recorded can never settle a decision made
after the condition came back. A host that died at any point before the settlement offers the
announcement again. What becomes of it afterwards - the destinations, the attempts, the receipts -
belongs to the delivery journal.

An item holds one outstanding decision at a time. A later announcement about the same condition
replaces the identity waiting to be taken, and the condition ending takes it away, because an
announcement about something that is no longer true is not one anybody wants. So a consumer takes
what is waiting rather than a queue of everything that was ever decided.

A jump in a source's sequence means the records between were evicted. The engine records the range,
marks every unresolved item from that same source uncertain, and leaves it in the inbox. A gap is
never an approval and never a completion: an approval whose answer may have been in the missing
range stays pending and says the host cannot tell. A host that starts the engine partway through a
session's life says where it is starting rather than leaving the first record to look like an
eviction.

A rebuild announces nothing. An event from an hour ago is history rather than a notification to
send now, so the replay restores each item with the age it had, where the anchor that age is
measured from belongs to this boot, and starts the age here where it does not. Either way the first
timer pass after the rebuild decides what still needs saying.

The inbox is a working set rather than a record: the receipts, the question ledger and the retained
output are where the history lives. Past five hundred items the host lets go of its least urgent
and oldest *record* of a condition, and the read says how many it has let go of. An item that has
only just arrived is not one of those: nothing has been decided about it yet, so it is kept until
its decision has gone out, been recorded by a consumer, and outlived the minute in which the same
condition would be folded into it rather than announced again. Weighing what is left by level and
age is what stops a fresh notice displacing an urgent approval.

What the bound never lets go of is a condition somebody or something is still waiting on - an
unanswered approval, an unanswered request, an adapter still down, a host still out of contact - or
a decision about one that is still in flight: one no consumer has settled, one quiet hours are
holding, one nobody has made yet, and one whose sixty-second window is still running, because the
item is the whole of what the host remembers that window by and letting go of it would announce the
same condition twice inside it. When the whole inbox is those, it goes over its bound rather than answering that nothing
is waiting or losing an announcement nothing will offer again, and it comes back inside its bound
on the next timer pass, against what that pass decided and what a consumer settled meanwhile. A
host whose notifications nobody is taking therefore keeps them rather than quietly dropping them.

Review state has no retention at all. A subject nobody has acknowledged is outstanding review work,
and deleting it would answer that there is none; a subject somebody has acknowledged is that
actor's own record of what they read, and nothing can rebuild it from the events, because the
cursor that consumed them has already moved. What is bounded is the answer: a review read returns
at most two hundred subjects and continues after the last one it gave, in the order the host first
heard of each subject, so a new version of one already served does not move it under a page that is
continuing. A subject the session does not hold is refused as a continuation rather than silently
restarting the list.

A feature store admits two hundred and fifty-six actors; past that a new actor's acknowledgement is
refused, before anything is dispatched, rather than an existing actor's being deleted.

### What a caller is served

An item's text and a change's text come from retained content: a question's wording, a command
line, what an application printed. Section 10 narrows retained content to the grant that asked for
it, and this host cannot narrow a moment in time to an item's text, which is why it refuses a
retained history page to a paired device outright. An attention item is not a history page, so it
is narrowed rather than refused: a caller that did not arrive over the local socket is served the
host's own record of a condition - which rule, at what level, how often, when - with the text left
out and said to be left out, and no model summary either.

An item's key carries none of that text either. A key has to be derived rather than allocated, so
that rebuilding the inbox from the retained events lands on the items it had before, and it travels
to every caller that may read the inbox at all. So it carries a digest of the subject rather than
the subject: a command line or a notification body cannot reach a caller inside the key of the item
whose text was withheld.

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

## Grants, sharing and revocation

A grant is the authority a request is decided against. It names its issuer and its recipient, the
authority revision it was issued under, the environments and sessions it covers, the actions it
permits, how far back it may see, when it stops and which organisation membership it requires.

Two stores hold grants. A pairing writes its grant into the device record, and a paired device's
session request is decided at the network boundary against that grant, the session and environment
it covers, and the rights the method registry requires. `crates/kr-controller/src/grants/` holds the
grants this daemon issues through the sharing method group, and `grants::decide` is the intersection
those are decided by. Both read the registry's required-rights column, so neither invents a right
the other does not ask for.

`grants::decide` takes the intersection in this order:

1. The method has to be in the registry and reachable from the caller's ingress class. An unlisted
   name is denied whatever the caller holds.
2. The grant has to be live: not revoked, no revoked ancestor, redeemed, not expired, and claiming
   no revision this host has never issued.
3. The host's own policy has to permit it: the organisation lease it requires, and the bounded
   offline-validity policy when the owner chose one.
4. The selectors have to admit the environment and the session the request names.
5. The intersected rights have to carry every right the method requires under the conditions this
   request meets.

The rights come from `kr_protocol::method::REGISTRY`, which is section 23's table with one entry
per method. Nothing here restates that table: a second copy drifts, and the copy that drifts is
always the one an authorisation check happens to read.

**Expiry does not downgrade.** A grant whose deadline has passed refuses the request. It does not
quietly keep serving reads, because continued reads still need valid authority and a narrower grant
is something the person chooses.

**A grant's issuing revision is provenance, not a deadline.** Somebody else's revocation advancing
the host's revision does not invalidate an untouched grant; what stops a grant is revocation or
expiry. A grant claiming a revision this host has never issued is refused, because nothing here
could have issued it.

**Expiry is decided from a clock that does not go backwards.** The host keeps the highest reading it
has decided from and uses the later of that and the current clock, so winding the clock back past a
deadline does not revive a grant the host has already refused.

**Delegation narrows.** A child grant can never reach further than its parent in rights, resources,
history or lifetime, and it can never drop an organisation requirement its parent carries. The rule
is checked where a grant is composed and again where it is written, so it does not depend on a
caller remembering to ask.

**Revoking a parent revokes its descendants.** The parent link is a column in the store, so the
cascade is a property of the store rather than a loop somebody has to remember to write. A grant
already revoked keeps the moment and the ancestor it was first revoked under.

**Roles are not authority.** Viewer, reviewer, controller and owner compile to explicit actions when
a grant is written, and the grant carries no role afterwards. Only controller and owner include
`question.respond`; a viewer or reviewer receives it through an explicit invitation option that
carries the notice explaining that an answer, including free text, is input the agent may act on
under its own permissions.

**An issuer is shown what it is sharing.** The preview is computed by the same code that writes the
grant, and an invitation that names a question, an approval or the live screen is refused unless
text for that thing arrives with it and the two name the same things. The request is refused when
the notices the issuer states it accepted are not the ones the grant carries. A shared live screen
can hold text printed long before the invitation, so the preview carries the text rather than a
description of it. A new recipient receives no historical attachment keys.

**Invitations are single use and they expire.** The default is `session.view` for one hour, from the
moment the invitation is issued: the recipient sees the selected live screen and what happens next,
and earlier history is a separate choice. The issuer may choose less than an hour or extend it to at
most 30 days. A lifetime past the bound is refused rather than clamped, because a silently shortened
invitation is one whose issuer believes something untrue about it. Persistent co-owner access is
explicit owner pairing, not a longer invitation.

**A grant is a proposal until its invitation is redeemed.** `grant.create` writes the grant and its
invitation together and the grant authorises nothing; redemption activates it, for exactly the
device the invitation names, once. A second redemption by anybody finds the work done. Withdrawing
an invitation withdraws the proposal with it, so cancelling is a complete answer rather than a note
beside live authority.

**Transfer of control is not a delegation.** The transferring device does not keep what it hands
over: the recipient receives an active grant over the session named in the plan, and the
transferring device's grant is revoked with its descendants, both in one commit. It changes who
holds authority, so it takes the owner's confirmation every time.

The confirmation is accepted against an expectation built from what the caller states this host is:
its device identity, its endpoint, the recipient's public keys, the rights the plan hands over and a
digest covering the whole plan. A challenge that supplied its own answers to those does not satisfy
it. The signer and the outstanding-challenge ledger are the caller's too, so the acceptance is only
as strong as the caller's own enrolment record. What comes out of that acceptance is evidence bound
to the host it was accepted for, to the boot it was accepted in, and to the ceremony's own monotonic
deadline, and the transfer checks all three before it does anything. A confirmation accepted for
another host, in an earlier boot, or past its lifetime authorises nothing.

The transfer hands over no more than the transferring grant carries, and it advances the revision
and fences like any other revocation.

**Nothing is lent through an intermediary.** The rule for a plugin action, an attachment action or a
workflow is the *intersection* of what the actor holds and what the intermediary declares: an
intermediary bounds a call and never funds one. `sharing::roles::effective_rights` and
`check_indirect` are where the host states that rule, for an execution path to apply where it
resolves the actor and the intermediary together.

**Delegating needs the parent and the right to pass it on.** An issuer has to hold the grant it
delegates from — naming one is not holding one — and that grant has to carry `session.share`.
Only this host's own device issues a grant that delegates from nothing.

### Revocation

`Controller::revoke_grant` and `Controller::revoke_device_authority` run in the order a revocation
cannot be correct without:

1. The grants go first, because a grant still in the store is a grant the next request would be
   decided against.
2. The revision advances, which invalidates every outstanding dispatch lease at once and
   deregisters the connections admitted under the authority just withdrawn.
3. The connections holding those registrations are fenced, so a subscription already open is closed
   rather than left reading.
4. The revision is announced to every worker, and what comes back is the per-worker completion
   status.

A revocation is complete for a worker once that worker has acknowledged the revision and fenced the
undispatched actions it affects, or once it is confirmed ended. Anything else is `pending`, and the
answer says which worker and why. Already dispatched effects and content already copied cannot be
undone.

A revocation that withdrew nothing advances no revision. Retrying one is answered from the result
the host recorded for that action rather than performed again, so a retry cannot fence the host a
second time for one withdrawal, and an action identifier reused with different parameters is a
conflict rather than a second revocation.

The fence this daemon takes is host-wide: every registration is withdrawn and the connections that
kept their authority are re-admitted at the revision now in force. Withdrawing one device's
registration on its own belongs to the network half, which owns those registrations.

### The remote authority feed

A remote owner publishes a signed revocation **request**, which carries no revision. Only the target
host numbers it, from the same sequence its own revocations use, because a device that could number
its own request would be assigning itself a place in the host's order. A record at or below the
revision this host has accepted is refused, so replaying an old feed entry cannot put authority
back, and a different request wearing an identity this host has already applied is refused rather
than answered with somebody else's revision.

Revocation records are retained until every enrolled host has acknowledged them or that host is
explicitly removed; they do not share mailbox expiry or notification coalescing. A settled record is
kept rather than deleted, because its revision is what a device list reports as that host's last
acknowledgement and its identity is what stops the request being applied again. `device.list` shows
each host's last acknowledgement beside the feed's own staleness, because an offline host cannot
apply a revocation it has not received and a list that looked current because nothing had
contradicted it would be worse than no list. The feed records that a synchronisation is owed from
the moment a connection is established until one has happened on it, and an unreachable feed is
reported stale rather than current.

### What the host policy holds

`grants::policy` holds what is true of this host rather than of one grant.

* **Organisation leases.** A signed membership lease lasts at most 15 minutes and is held per
  member account. When `grants::decide` decides a grant that requires membership, the lease is
  checked against the clock rather than against whether a socket is open, so an expired membership
  blocks organisation-mediated reads and mutations while the transport stays connected, and one
  member's lease never answers for another. A paired device's session request is decided at the
  network boundary against the grant its pairing recorded, which is the other of the two stores
  described above.
  A lease longer than 15 minutes, signed under an unpinned key revision, or wider than its role's
  ceiling is not stored at all. Personal local owner access continues through an organisation
  outage unless the host is exclusively organisation-managed.
* **The bounded offline-validity policy.** Optional, and off by default: the non-expiring owner
  grant stays account-free and usable without an authority-feed dependency. An owner who chooses a
  bound gets that bound, measured from the last successful synchronisation, with the stale status
  and the last sync visible beside it.
* **Revalidation after wake and reboot.** The policy, its restrictions, its enrolments and both
  floors are read back from the environment's authority store when the daemon starts, so a restart
  does not return an unrestricted host. Membership leases are not: a lease lasts at most fifteen
  minutes, and a restarted host holds none until the service gives it one. A policy document naming
  a revision at or below the floor is refused, and the floor only rises. A signature proves who
  wrote a policy, not that the policy is the current one.

  The floors live in the same store as the grants they protect, so restoring that store wholesale
  takes them back with it. That is a recovery event rather than a policy document, and the remedy is
  the remote feed, whose revisions this host accepts but never issues on another host's behalf.

### The shared history filter

`crates/kr-worker/src/history_filter/` is where a grant's history lower bound is enforced. It is one
filter with nine named surfaces — event pages, terminal and semantic snapshots, loaded
conversations, attachment references, exports, summaries, changed-since-last-visit and voice context
— and one decision behind all of them, so a surface cannot be served by a rule of its own. The
surface list is closed: content that is not one of them is not filtered here, it is not filtered
anywhere, and adding a surface means adding it to that list.

The worker asks the filter how much of the screen a forwarded caller may be drawn, and installs the
projection it answers with.

Content is admitted by **when it was produced**, never by when it was read, re-read or summarised,
so a summary generated now from an hour-old conversation is an hour-old conversation. Derived data
carries the interval and the resources it was built from; the filter answers with the interval to
rebuild from when that interval crosses the viewer's scope, and with nothing when the whole of it
does. Whether a viewer may read a particular *resource* is a separate question the caller answers:
the filter decides when, and a file's or an attachment's own grant decides what.

A live-only invitation reaches the currently visible screen and nothing else. Snapshot installation
goes through the filtered projection rather than the worker's unrestricted state, so the buffer that
is not showing is neither drawn nor described: not its rows, not its saved cursor, not its keyboard
negotiation. Attachment bytes are a second question from the attachment reference, and need their
own `files.read`. An invitation may name current questions or approval requests explicitly, which
permits those exact decisions and not the conversation they came from.
