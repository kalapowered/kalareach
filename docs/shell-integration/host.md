# The host side of the root-editor contract

`docs/shell-integration/README.md` is the contract as a shell-package author reads it: the frames,
the reader-thread rules, the state machine and the scenarios. This is the other half. It describes
what the worker does with those rules — where the endpoint is, how a bridge is admitted, what drives
the machine, and what a launch actually goes through — and it is the document to read before
changing any of it.

## The endpoint

One session, one endpoint, bound before the root shell starts.

On Unix it is a socket file in the environment's runtime directory, which is owner-only (`0700`) and
is checked rather than repaired: one that is group-readable, owned by somebody else or reached
through a symbolic link is refused, because the host cannot tell whether it was widened by accident
or by someone else. The socket itself is `0600` and is removed when the session ends, and only if it
is still the same socket this session bound.

Its name is `b` and six characters of the session identifier, so the host adds one separator and
seven characters to whatever runtime root it is installed under. That is not brevity for its own
sake: a Unix socket address is copied into a fixed array of 104 bytes on the tightest platform, and a
runtime root inside a temporary directory already spends most of it. Six characters are a name rather
than an identity, so a second live session whose identifier begins the same way is given another name
of the same length; the whole identity is in the descriptor either way.

On Windows it is a named pipe, `\\.\pipe\kalareach-<uid>-<session>-shell-bridge`. The pipe namespace
has no directory permissions to inherit, so the pipe carries an owner-only access-control list
instead.

The shell is told where it is through two reserved variables, and only those two:

| Variable | What it carries |
| --- | --- |
| `KR_SHELL_BRIDGE` | The endpoint, exactly as the worker bound it |
| `KR_SHELL_BRIDGE_SECRET` | 32 random bytes, unpadded base64url, generated for this session alone |

Both come from the worker. A creator's environment snapshot cannot preload either: every name
beginning `KR_` is dropped from the snapshot before the shell's environment is built. Both leave the
exported environment as soon as the handshake succeeds, so a child process started afterwards
inherits neither.

## Being admitted

Three things happen when a bridge connects, and only the last of them decides anything.

1. **The kernel is asked who is calling.** The listener has already refused another user; the host
   then reads the connecting process and its start identity from the operating system. Nothing in
   the hello contributes to that answer.
2. **The proof is verified.** It is HMAC-SHA-256 over
   `CBOR(["kr-shell-bridge/1", session_id, endpoint, shell_process, integration_version])` under the
   bootstrap secret. The host rebuilds that transcript from what *it* knows — its session, its
   endpoint and the root process it launched — so only the integration version comes from the hello.
   The comparison is constant time, and a tag that is not exactly 32 bytes fails without one.
3. **The contract decides.** `contract::transport::decide_handshake` compares the observed process
   with the launched root shell and with the hello's own claim, then reads the verdict above, then
   the declaration. Its order is what names the refusal: a child that inherited the bootstrap values
   is refused as a different process rather than as a bad proof, whichever identity it claims.

A refused bridge is told which named reason it was refused for and the connection ends. It is not a
loss: nothing was registered, so the session has nothing to lose.

## The phase a session is in

Section 7 separates authentication from qualification, and the difference decides real behaviour.

| Phase | Input | Fence | Launch | Attribution | Eligible Ctrl-D | Ready |
| --- | --- | --- | --- | --- | --- | --- |
| `unauthenticated` | no | no | no | no | consumed with the hint | no |
| `authenticated` | yes | no | no | no | consumed with the hint | no |
| `qualified` | yes | yes | yes | yes | detach | yes |
| `degraded` | yes | no | no | no | consumed with the hint | no |
| `terminal_only` | yes | no | no | no | the shell's own | no |

A session is `authenticated` from the moment its bridge registers and `qualified` from the moment
the integration reports its hooks live, which is after the user's startup files have run. The input
column is enforced where input is accepted: an `unauthenticated` managed session refuses a client's
bytes outright, and from `authenticated` onwards they reach the terminal the moment they arrive,
because no fence is held below `qualified`. That is what keeps a startup profile that asks a question
from waiting for anything.

Before qualification every loss closes the session that was being created and records why: a create
that cannot deliver the managed contract fails rather than succeeding with less. After it, a lost
bridge or lost hooks leave the session `degraded`, and an `exec` to an unqualified replacement leaves
it visibly `terminal_only`. An explicit compatibility retry is a new create request.

## What drives the machine

`contract::fence::FenceMachine` is the single source of fence and detach truth. The worker's driver
adds three things to it and nothing else.

* **The clock and the timer.** The machine takes a reading; the driver supplies it from the
  suspend-aware continuous clock and arms one timer at the machine's own `deadline()`.
* **The phase gate.** Below a qualified session the reader's boundaries are answered and recorded
  and no exchange begins; a launch is refused before the machine sees it; an accepted line is
  recorded as unverifiable rather than attributed.
* **The bytes.** The machine names batches of input; the driver holds the actual bytes and hands
  them to the terminal's writer in the order the machine releases them.

Every consequence is one of the machine's own actions, carried out in the order the outcome lists
them. There is no second state machine and no heuristic fence: nothing in the worker concludes
anything about the reader from a prompt, a timestamp or a byte count.

A loss that leaves the session below `qualified` is followed by an `editor_left` stimulus naming the
reader the bridge last reported, so the machine deregisters it. Without that the machine would keep
a registered editor and start another exchange at the next lease change, and a session the phase says
is degraded would publish a fence and hand out a detach proof it cannot stand behind.

The stimulus and everything that came of it happen under one session lock, and the actions are
carried out as one list, front to back, including the frames for the bridge. Releasing the lock
between the two would let another writer put a batch in front of one the machine had just released;
grouping the actions by kind would tell the bridge a detach had happened before the attachment was
gone, or interrupt an application before the launch that interrupt revoked had been called off.

| Action | What the worker does |
| --- | --- |
| `ask_fence`, `send_launch`, `cancel_native_operations` | One request on the bridge, which the reader thread answers |
| `hold`, `forward`, `release`, `discard` | The batch waits, is written, is written in arrival order, or is dropped and counted |
| `publish_fence`, `withhold_fence`, `invalidate_fence` | The bridge is told, because it cannot infer any of the three |
| `emit_editor_busy` | An `editor_busy` attachment event to the client whose keystrokes waited |
| `acknowledge_lease_change`, `close_takeover_receipt` | The takeover receipt: what the worker discarded, and what the reader did |
| `remove_attachment`, `acknowledge_detach`, `reject_detach` | The empty-prompt gesture's outcome |
| `install_launch`, `reject_launch`, `revoke_launch`, `late_installation` | The launch transaction's outcome, and what is recorded beside it |
| `interrupt`, `refuse_interrupt` | The configured native interrupt, which bypasses the hold |
| `record_acceptance` | The origin a detach with no attachment identifier resolves against |

## The takeover receipt

A takeover reports two counts, because they are two different things.

* What the **worker** accepted from a client and never delivered: its own queue, the batches the
  machine was holding, and an incomplete paste delimiter. This is the `discarded_bytes` of the
  `input.acquire` answer.
* What the **reader** discarded from its own queues when its incomplete operation was cancelled.
  That answer arrives later, so the session's own receipt records `pending` while the reader has
  been asked, `known` with the count when it answered inside the hold, and `unknown` when the hold
  ended first or a departure superseded the cancellation. It is never a zero nobody measured, and it
  is the session's record rather than a field of the `input.acquire` answer.

## `shell.launch`

The caller's answer is the reader's word. The sequence is:

1. The mutation is admitted on the ordinary receipt path: the terminal-input right, the current
   input lease held by this connection's own attachment, a session whose mode claims the managed
   editor, and a qualified phase.
2. Inside the session boundary the machine reserves the current fence, holds later input, and the
   request goes into the reader's mailbox with the worker's own recorded working-directory revision
   and what is left of the 250 ms.
3. The boundary ends there. The caller waits outside it, so a transaction does not hold every other
   mutation on the worker behind it.
4. At the deadline the worker revokes the transaction, releases the held input in its original order
   and emits `editor_busy`. It does not answer the caller: only the reader knows whether it installed
   anything.
5. The answer is what the reader said. The installed result when it installed one; `DRAFT_CONFLICT`
   when the reader's own buffer, prompt or working directory had moved under it; `EDITOR_BUSY` when
   the transaction could not be held; and `OUTCOME_UNKNOWN` when the reader can no longer answer at
   all.

The wait happens on a task of its own rather than on the connection's read loop, so the same client
goes on typing, interrupting and detaching while its launch is with the reader.

Because the outcome is not known when the boundary ends, the receipt is settled when the reader
answers. A reader that proved it installed nothing settles the receipt as `refused`; only an answer
nothing can give any more settles it as `unknown`. The dispatch marker was committed before the
request reached the reader, so a crash in between also leaves it `unknown`, which is exactly what a
command that may be in the editor is. A caller that repeats an `OUTCOME_UNKNOWN` action under the
same identifier is given the retained receipt rather than a second attempt.

Nothing is ever written into the pseudo-terminal for a launch. There is no wake marker, no launch
string and no private key injection; a bridge that offers key injection is refused registration.

### Quoting

An argument vector is preserved literally and quoted for the target shell. `eval` is never used, and
neither is `Invoke-Expression`: the text that reaches the editor is the command itself, so what the
person sees on the line is what runs.

| Shell | An embedded `'` |
| --- | --- |
| Zsh, Bash | `'it'\''s'` |
| Fish | `'it\'s'` |
| PowerShell | `'it''s'` |

A command the caller has already quoted for its target shell is installed exactly as given.

## Launching the root shell

Managed mode launches a KalaReach-qualified package: the exact binary its reader patch was built
into and the module tree it will load. Nothing is substituted. A shell no package qualifies is
refused with `SHELL_INTEGRATION_UNSUPPORTED`, by name, before a reservation is recorded and before
anything is spawned. A command line rather than an executable is refused the same way: a
non-interactive script request never becomes an interactive shell.

A package is what `scripts/build-shells.sh` installed, and this host reads that installation rather
than a description of its own:

```
<root>/<shell>/current                            the identity this installation uses
<root>/<shell>/<identity>/kr-shell-identity.json  what the package declares in its handshake
```

`<root>` is the installation's own shell directory, or whatever `KR_SHELL_PACKAGES` names, which is
how a test runs against a package that was just built. `docs/shell-integration/packages.md` is where
the record's own shape is stated; these are the parts a session depends on.

| Field | What it is |
| --- | --- |
| `shell.kind` | `zsh`, `bash`, `fish` or `powershell` |
| `shell.executable` | The shell binary, as the build installed it |
| `shell.upstream_version` | The upstream release it was built from |
| `shell.editor_abi` | The editor ABI revision the reader patch was built against |
| `shell.integration_version` | The package's own integration version |
| `shell.patches` | Every published reader patch, with the upstream revision each applies to |
| `shell.modules` | The module tree, with each module's search path and ABI |
| `startup_entry.file` | The file the guarded startup entry sources |

A hello is checked against the package's editor ABI and integration version, and the rest of the
identity it carries — the executable, the upstream revision, the patches and the module tree — is
recorded whole with the session, which is what its diagnostics report.

The arguments that make one of these an interactive login shell are the host's rather than the
package's: a record says what a package was built from, not how a session starts it, and the
arguments belong to the shell family. A package whose recorded executable is no longer where the
build put it is still read from its own directory, so a package that was copied somewhere else is
the package that is there.

## Setup

`kr shell status` reports the resolved executable, flags, version, editor ABI, integration version
and mode, and where each guarded entry goes and whether it is there. It writes nothing.

`kr shell install` adds one marked entry per shell to the file that shell actually reads:

| Shell | Where |
| --- | --- |
| Zsh | `.zshrc` inside the configured `ZDOTDIR` when there is one |
| Bash | `.bashrc`, plus the first login file this user has when it does not already source `.bashrc` |
| Fish | a guarded `conf.d` entry; it loads before `config.fish` and its own activation is deferred until after it |
| PowerShell | the user's own profile, added to rather than replaced |

The entry is delimited by `# >>> KalaReach shell integration >>>` and `# <<< KalaReach shell
integration <<<`, and its body is one line that sources the package's own file. Nothing of the
integration's logic is copied into the user's configuration, so upgrading the package changes what
runs without rewriting anything they own. Nothing replaces `.bashrc`, points a shell at another
`ZDOTDIR`, substitutes an `--rcfile` or disables a profile.

`kr shell install --nsh-bypass` adds the documented session-local bypass for a known auto-wrapper:
`NSH_NO_WRAP=1`, set only where the worker exported the bridge, which is a KalaReach-created shell.
It changes no other setting of that tool and affects no ordinary terminal.

`kr shell remove` deletes exactly the marked entry. Everything the user wrote stays as they left it.

Either one writes the file beside itself and renames it over, so a full disk or a crash leaves the
configuration as it was rather than half of it. The file beside it is created exclusively, under a
name of that call's own and owner-only from its first byte. A startup file that is a symbolic link
into a checkout is written through: the link stays a link, and the entry lands in the file it names,
whether the entry is being added or removed.

A file that changed between being read and being written is left alone and the change is reported,
because a replacement built on what was read would throw away whatever was saved in between. The
contents are checked immediately before the rename, after the write and the flush, and on Unix so is
the file's own identity, so a file that was replaced rather than edited is caught too. What is left
is the interval between that check and the rename: a comparison and a rename are two steps on every
platform this runs on, and an editor that saves inside that interval has its save replaced. Two of
these commands in one process are serialised against each other; two `kr` processes are not.

## The command hooks

Two of the integration's hooks ask the session rather than the fence machine, and the session
answers each on the step that carried it, after everything the same stimulus released.

`root.command.resolve` runs in front of an interactive invocation, before the command starts. The
session answers with the argument vector to run: the command name and the vector the person typed,
plus the flags an enabled integration for that command adds. Four things bypass it, and each keeps
the invocation exactly as typed and is given no backend at all: a command invoked by absolute path,
an integration the user has not enabled, a line of a script rather than an interactive invocation,
and a shell whose integration is not a managed KalaReach root shell yet. An integrated invocation
is answered with the worker-owned backend the session established *before* it answered, so the
gateway exists before the program does. There is no other route to one: a program already running
never acquires a backend afterwards, because this hook is the only place one is made.

`root.command.block` reports one command block: the command line the editor accepted, when it
started, how long it ran, what it exited with and the directory it ran in, with the
working-directory revision a launch is checked against. Each block arrives twice, once with no
status when the command starts and once when it ends, and the second replaces the first, so a
reader sees one entry per command. The session keeps the most recent sixty-four and `session.read`
carries the newest. Nothing here is parsed out of terminal output; all of it comes from the
reader's own boundaries.

## Section 23's private group

`root.editor.enter`, `root.editor.leave`, `root.editor.fence`, `root.eof.detach`,
`root.command.accepted`, `root.command.resolve` and `root.command.block` are reachable from a
validated root registration over private IPC and
nowhere else. That is true of the transport rather than only of an authority table: they travel on
the bridge endpoint as its own frames, and there is no frame on the worker's client endpoint that
carries one — a request naming one of them is refused by the dispatch, because no handler serves it.
Another process of the same user can open the endpoint; what it cannot do is authenticate as the
root shell the worker launched. The group itself is read from the protocol registry rather than
written out again here, so a method that joins it is covered without anything being kept in step by
hand.

`shell.launch` is not in that group. It is a host-authorised operation a client asks for, bound to
the same fence.
