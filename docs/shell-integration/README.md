# The KalaReach shell integration

A managed root shell has to answer one question the rest of the host cannot answer for it: whose
keystrokes reached the line editor. Ctrl-D at an empty root prompt detaches the client that typed
it, a launch installs a command in the root editor and nowhere else, and neither may happen while an
application is reading the terminal. A prompt hook, a process-group check or an empty kernel queue
cannot tell you any of that, so this contract is built on what the shell's own reader can prove.

This reference is the contract as a shell-package author reads it. Four packages implement it,
against their own readers:

| Package | Mailbox mechanism | Pre-EOF mechanism |
| --- | --- | --- |
| Zsh 5.9+ | `key_sequence_boundary_mailbox`: the published ZLE patch checks a mailbox at key-sequence boundaries, with immediate line acceptance and non-destructive cancellation | `native_hook`, in the same patch, immediately before ZLE's empty-EOF branch |
| Bash 5.2+ | `idle_reader_mailbox`: the published patch to the bundled Readline runs a callback after buffered input is consumed | `native_hook`, immediately before Readline's own EOF decision, after the next character has been selected |
| Fish 4.x | `reader_event_bridge` against the Rust reader | `named_reader_binding`: a named binding that receives the actual reader context |
| PowerShell 7.4+ | `reader_thread_queue`: the qualified PSReadLine module's request queue and signal | `reader_state_handler` over PSReadLine's buffer and invocation state, under the configured gesture |

The mechanisms are per package, and the handshake checks them that way: a declaration naming another
shell's mailbox or pre-EOF mechanism describes a reader this package does not have.

The Rust half is `crates/kr-shell-integration`. Its wire types live in `kr_protocol::root`, the
scenarios live in `fixtures/shell-bridge/`, and the state machine is a pure library: it takes clock
readings as arguments and returns actions, so the worker drives it with real sockets and the
scenarios drive it with numbers.

## The bridge endpoint

The worker listens on one endpoint per session inside its own owner-only runtime directory. On Unix
that is a socket with mode 0600 in a directory with mode 0700; on Windows it is a named pipe whose
security descriptor admits the owning user alone. Peer credentials are checked before a frame is
read, so the endpoint serves the session owner or nobody.

Peer credentials are not the whole check. The worker also asks the platform which process is on the
other end and compares that, not what the first frame says, against the root shell it launched. A
child that inherited the bootstrap values can name its parent's identifier and compute the matching
proof; it cannot be its parent.

Two reserved variables carry it into the shell:

| Variable | Carries |
| --- | --- |
| `KR_SHELL_BRIDGE` | The endpoint path, or the pipe name on Windows |
| `KR_SHELL_BRIDGE_SECRET` | A one-time 32-byte bootstrap secret, as unpadded base64url |

An endpoint path is absolute and at most 103 bytes. That bound is the tightest platform's, because a
Unix socket address is copied into a fixed array of 104 bytes on macOS and 108 on Linux; a path that
validates against the tighter one binds everywhere rather than only on the machine it was written
on.

Frames are the host's usual ones: a four-byte unsigned big-endian length followed by one KR-CBOR-1
object, bounded by the control stream's maximum frame of 1 MiB. `kr_shell_integration::contract::transport::frame_codec`
returns the codec both sides use, so a package encodes the bytes the worker's own codec reads.

The frame union is closed and each side refuses what its role does not send:

| Frame | Direction | Fields | What it is |
| --- | --- | --- | --- |
| `hello` | bridge to worker | `protocol`, `session_id`, `shell_process`, `shell`, `abi`, `proof` | The opening frame |
| `handshake` | worker to bridge | `accepted` with the acceptance below, or `refused` with `reason` and `error` | Registered, or refused with a named reason |
| `event` | bridge to worker | `id`, `event` | Something the reader did |
| `event_result` | worker to bridge | `id`, `result` | The answer to that event |
| `request` | worker to bridge | `id`, `request` | Something the reader thread must decide |
| `answer` | bridge to worker | `id`, `answer` | The reader thread's answer |
| `fence_published` | worker to bridge | `published` with the fence, `withheld` with `reason` and `state`, or `invalidated` with `fence_id`, `reason` and `state` | Whether a fence became live, why not, or that one which was live has gone |
| `launch_revoked` | worker to bridge | `transaction`, `reason` | A launch transaction is over and nothing may be installed for it |

The nested objects of the handshake:

| Object | Fields |
| --- | --- |
| `shell_process`, `root_process` | `pid`, `source` (`linux_proc_stat`, `macos_proc_bsd_info`, `windows_process_start_seconds`), `start_value` |
| `shell` | `kind`, `executable`, `upstream_version`, `editor_abi`, `integration_version`, `patches`, `modules` |
| `patches[]` | `name`, `upstream_revision`, `revision` |
| `modules[]` | `name`, `search_path`, `editor_abi` |
| `abi` | `mailbox`, `pre_eof`, `fence_proof`, `cancellation`, `launch_delivery` |
| `accepted` | `protocol`, `session_id`, `editor_abi`, `hold_ms`, `gesture`, `hint`, `secret_location`, `unexport` |
| `refused.error` | `code`, `message`, `retry`, `diagnostic_id` |
| `backend` | `session_id`, `prompt_generation`, `environment`, `launcher` (the absolute path of the installation's `kr-hook`), or null where the host establishes none |
| `event_result` | `editor_entered`, `editor_left`, `detached`, `command_recorded`, `command_resolved`, `command_block_recorded`, `received`, or `refused` with an error |

A bridge holds a fence only between a `published` and the `invalidated` that ends it: every reason
the worker drops one, from a reader entry to a detach to a lost integration, reaches the bridge that
way.

Each side allocates the identifiers it sends, so an answer belongs to its question rather than to
whatever is in flight. Events are answered too: `event_result` carries `editor_entered`,
`editor_left`, `detached`, `command_recorded`, `command_resolved`, `command_block_recorded`,
`received` for an event that needs no answer, or `refused` with the session's error. A refused detach is the one every bridge must handle, because
the gesture has already left the reader.

An enum on the wire is externally tagged: a variant with fields is a single-entry map whose key names
the variant, and a variant without fields is that name as a text string. Identifiers are 16-byte
strings, counters are unsigned integers and durations are milliseconds.

A frame that does not belong on this endpoint ends the connection. A bridge that has the direction of
this contract wrong cannot be trusted with the fence.

## The handshake

The bridge opens with `kr-shell-bridge/1` and says what it is:

| Field | What it carries |
| --- | --- |
| `protocol` | `kr-shell-bridge/1` |
| `session_id` | The session the shell believes it belongs to. A claim the worker checks against the endpoint, so a stale inherited environment is refused rather than registered against the wrong session |
| `shell_process` | This process's identifier and the kernel's record of when it started |
| `shell` | The executable, the upstream version, the editor ABI, the integration version, every published patch and the module tree with each module's ABI |
| `abi` | The five mechanisms the bridge implements (see "What qualifies a bridge") |
| `proof` | HMAC-SHA-256 over the bootstrap transcript, keyed by the bootstrap secret |

The transcript is `CBOR(["kr-shell-bridge/1", session_id, endpoint, shell_process,
integration_version])`. Binding the endpoint and the shell's own process identity is what stops a
proof taken in one session being replayed in another, or by another process of the same user.

The worker checks identity before capability, so a process that is not this session's root shell is
refused before its declaration is read at all:

| Reason | Error code | When |
| --- | --- | --- |
| `protocol_mismatch` | `UNSUPPORTED_SCHEMA` | The bridge offered a protocol this worker does not speak |
| `session_mismatch` | `PERMISSION_DENIED` | The hello named another session |
| `process_mismatch` | `PERMISSION_DENIED` | The process on the other end is not the root shell the worker started |
| `peer_unidentified` | `PERMISSION_DENIED` | The platform could not say which process is calling |
| `proof_mismatch` | `PERMISSION_DENIED` | The proof does not verify |
| `already_registered` | `PERMISSION_DENIED` | This session already has a root integration |
| `unqualified_mailbox` | `SHELL_INTEGRATION_UNSUPPORTED` | The mailbox cannot carry a fenced request |
| `mailbox_not_for_shell` | `SHELL_INTEGRATION_UNSUPPORTED` | The mailbox named belongs to another shell's reader |
| `key_binding_pre_eof` | `SHELL_INTEGRATION_UNSUPPORTED` | The end-of-file decision would come from a key-binding wrapper |
| `pre_eof_not_for_shell` | `SHELL_INTEGRATION_UNSUPPORTED` | The pre-EOF mechanism named belongs to another shell's reader |
| `unprovable_fence` | `SHELL_INTEGRATION_UNSUPPORTED` | The offered fence evidence proves nothing |
| `no_cancellation_path` | `SHELL_INTEGRATION_UNSUPPORTED` | A takeover could not end a pending key wait without losing the buffer |
| `key_injection_forbidden` | `SHELL_INTEGRATION_UNSUPPORTED` | The declaration named pseudo-terminal key injection as its launch path |
| `editor_abi_unsupported` | `SHELL_INTEGRATION_UNSUPPORTED` | The editor ABI is not one this build was qualified against |
| `integration_version_unsupported` | `SHELL_INTEGRATION_UNSUPPORTED` | The integration version is not supported |
| `module_tree_unsupported` | `SHELL_INTEGRATION_UNSUPPORTED` | A module in the tree was built against a different editor ABI |
| `package_mismatch` | `PERMISSION_DENIED` | The declaration describes a different build from the package this session launched |

An installation is read shell by shell. A record this host cannot read refuses that shell by name
and says what is wrong with it: one that names paths outside its own package, one whose pointer
names an identity that is not there, one missing a field. The shells beside it are unaffected: a
machine whose PowerShell package is broken still has a Zsh package that is exactly what it says it
is, and a managed create naming Zsh still starts.

A refusal is a named qualification error, never a false ready state and never a quietly reduced
contract. Loading ordinary startup files is not evidence that a native module matches the packaged
reader, which is why the module tree carries each module's ABI.

A worker that launched a package compares the whole declaration against that package's own record:
the executable, the upstream version, the editor ABI, the integration version, the published reader
patches and the module tree. Two builds of one shell agree on the editor ABI and the integration
version and are still two different readers, so those two alone do not establish that the process
on the endpoint is the package this session started. That comparison comes last, after every
identity check and every capability check, and its answer is `package_mismatch`.

An accept carries the editor ABI the worker took (`editor_abi`), the hold (`hold_ms`, 250), the
configured end-of-file gesture (`gesture`), the hint text (`hint`), where the secret now lives
(`secret_location`) and the variables the bridge removes from the exported environment before it
returns (`unexport`).

### The phases a session passes through

The handshake is not the whole lifecycle. A session is authenticated and ABI-checked before external
input is accepted, and qualified only after the user's startup files have run; a live session can
lose ground afterwards.

| Phase | External input | Ready or create success | Launch and attribution | Holds a fence | Eligible gesture |
| --- | --- | --- | --- | --- | --- |
| `unauthenticated` | no | no | no | no | consumed with the hint |
| `authenticated` | yes, in the reader's own non-primary context while profiles run | no | no | no | consumed with the hint |
| `qualified` | yes | yes | yes | yes | detached under a fence |
| `degraded` | yes | already reported | no | no | consumed with the hint |
| `terminal_only` | yes | no | no | no | the shell's own behaviour |

The phases advance on what the bridge reports, never on a guess. The handshake authenticates it.
`hooks_activated` says its user-facing hooks are live after the startup files, which is what makes a
session qualified. `integration_lost` says the ground has gone, and the worker infers the same when
the bridge's connection ends.

A loss before qualification closes the creating session, whatever it was: a create that cannot
deliver the managed contract fails rather than succeeding with less, and an explicit compatibility
retry is a new create request. In a live session, losing the semantic hooks or the bridge degrades
it, and an unqualified root replacement makes it terminal-only. Leaving `qualified` invalidates the
fence and cancels a launch transaction, because both rest on a reader the session can no longer
speak for. A degraded session keeps the fail-safe answer: an eligible gesture is consumed with the
hint rather than turned into a native empty-prompt end of file.

### The bootstrap secret, and what a child shell inherits

The secret is in the exported environment only until the handshake succeeds. The integration then
removes both bootstrap variables from the exported environment and keeps the secret in private
integration state: a shell-local variable it never exports, or the module's own memory for a
compiled bridge. It keeps it because a reader re-established inside the same shell needs it again.

A child shell therefore inherits neither an active root token nor automatic activation, and two
independent rules keep it that way:

1. A starting shell attempts the handshake only when both bootstrap values are in its exported
   environment (`decide_activation`). After the root handshake there is nothing to inherit, so the
   guarded startup entry is inert in every child.
2. Even with the values in hand, the handshake binds to the root process the worker started. A child
   has its own process identity, so its hello is refused with `process_mismatch`.

## What each package publishes

Every package records, and the worker keeps with the session:

- the executable actually launched, and the upstream shell version
- the editor ABI revision the bridge was built against
- the integration version
- every published reader patch, with the upstream revision it was rebased onto and its own revision
- the loadable module tree, with each module's search path and the ABI it was built against

## The reader events

Everything below comes from the reader itself, at the moment the reader does the thing. This is the
contract a bridge speaks and the host answers; which of these a given package sends is that
package's own declaration. The Zsh and Bash packages send every event in this table. The fish and
PSReadLine packages send neither `command_resolve` nor `command_block`, so a command in one of those
shells runs as it was typed and reports no block.

| Event | When | Fields |
| --- | --- | --- |
| `editor_enter` | The actual primary reader starts, not when a prompt is printed | `session_id`, `root_process` (`pid`, `source`, `start_value`), `prompt_generation`, `reader_revision`, `reader_context`, `editor`, `cwd_revision` |
| `editor_leave` | Before command acceptance returns, before preexec, when another reader takes over, on cancellation and on root exit | `session_id`, `prompt_generation`, `reader_revision`, `reason` (`command_accepted`, `preexec`, `reader_takeover`, `cancellation`, `root_exit`) |
| `reader_idle` | The reader has nothing left to read | `session_id`, `prompt_generation`, `reader_revision`, `reader_context`, `snapshot`, `editor`, `cwd_revision` |
| `eof_detach` | An eligible gesture at an empty primary prompt, under a fence | `session_id`, `fence_id`, `prompt_generation`, `input_epoch` |
| `command_accepted` | At acceptance, inside the fenced context, before the reader leaves | `session_id`, `fence_id`, `prompt_generation`, `origin` |
| `command_resolve` | In front of an interactive invocation, before the command starts | `session_id`, `prompt_generation`, `argv`, `executable` (the absolute path the shell's own search resolved the name to), `interactive`, `cwd`, `cwd_revision` |
| `command_block` | When a command starts and again when it ends | `session_id`, `prompt_generation`, `command`, `started_at_ms`, `duration_ms`, `exit_status`, `cwd`, `cwd_revision` |
| `gesture_changed` | The line discipline's `VEOF` changed, or the configured PSReadLine gesture did | `session_id`, `gesture`, `effective_at` |
| `pre_eof_consumed` | An eligible gesture was consumed because it could not be attributed | `session_id`, `prompt_generation`, `reason`, `hint_printed` |
| `hooks_activated` | Once, after the user's startup files have run and before the first primary reader | `session_id`, `prompt_generation` |
| `integration_lost` | The hooks, the reader or the root shell have gone | `session_id`, `loss` (`post_startup_failure`, `semantic_hook_loss`, `bridge_disconnected`, `unqualified_root_replacement`), `detail` |

The nested objects those fields carry:

| Object | Fields |
| --- | --- |
| `editor` | `buffer_revision`, `buffer_empty`, `keymap` (`emacs`, `vi_insert`, `vi_command`, `custom`), `pending` |
| `pending` | `quoted_insertion`, `macro_input`, `search`, `numeric_argument`, `multikey_sequence`, `vi_motion`, `paste`, all booleans |
| `snapshot` | `keys` (the sequence that invoked the current operation), `pending_bytes`, `queued_keys` |
| `queues` | `tty_typeahead_drained`, `macro_input_drained`, `partial_key_drained` |
| `gesture` | `terminal_eof` with `byte`, `disabled`, or `chord` with `keys` |
| `origin` | `fenced` with `attachment_id` and `input_epoch`, `mixed`, or `unverifiable` |
| `reader_context` | `primary`, `continuation` or `read_builtin` |
| `fence_acknowledgement` | `fence_id`, `reader_context`, `prompt_generation`, `reader_revision`, `queues`, `snapshot`, `editor`, `cwd_revision` |
| `fence_refusal` | `fence_id`, `reason` (`reader_busy`, `queues_not_drained`, `reader_moved`, `cancellation_unavailable`), `reader_context`, `snapshot` |
| `launch_accepted` | `transaction`, `installed`, `fence_id`, `prompt_generation`, `buffer_revision`, `reader_revision` |
| `launch_rejected` | `transaction`, `fence_id`, `reason`, `prompt_generation`, `buffer_revision` |
| `cancellation_report` | `sequence`, `epoch`, `prompt_generation`, `reader_revision`, `cancelled`, `buffer_preserved`, `discarded_bytes` |
| `event_result.editor_entered` | `state`, `fence_exchange` |
| `event_result.editor_left` | `state` |
| `event_result.detached` | `detached_attachment`, `state`, `discarded_input_bytes` |
| `event_result.command_recorded` | `origin`, `detach_token`, `state` |
| `event_result.command_resolved` | `arguments`, `added`, `bypass` (`not_integrated`, `disabled`, `absolute_path`, `unmanaged_shell`, `not_interactive`, `backend_unavailable`, `session_closing`, or null), `backend` |
| `event_result.command_block_recorded` | `prompt_generation`, `retained` |

Three ordering rules matter. Leaving invalidates the fence, so `command_accepted` is sent first, from
the reader, inside the fence; a record sent after the leave could only ever say `unverifiable`. A
`VEOF` reassignment takes effect at the prompt it names rather than mid-reader, because the character
the reader is holding was typed under the gesture that was in force when it was typed. And a leave
from a reader that has already been replaced is ignored: the worker compares the prompt generation
and reader revision before it deregisters anything.

### The line capability

`command_recorded` answers `command_accepted` with `detach_token`, and that field is how `kr detach`
inside a session knows which attachment it belongs to. The worker mints one secret per accepted
line and puts it nowhere else: this answer, to this bridge, for this line. A line the worker could
not attribute — a mixed origin, an unverifiable one — carries a null token, because there is
nothing for it to name.

A package that implements it exports the token in the environment of the command it is about to
run, as `KR_DETACH_TOKEN`, and for that command alone. `kr detach` with no `--attachment` presents
whatever that variable holds; the worker resolves the attachment from the token and refuses
everything else with `Use kr detach --attachment <id> to detach`. Nothing about the calling process
is read, and a package must not substitute anything for the token: a process identifier, a process
group, the terminal's foreground job and the parent chain each name the line running now just as
well as they name a caller an earlier line left behind.

The token is valid while its line runs and the worker ends it on its own: at the next accepted
line, at a `command_block` that reports an exit status, at a reader entry or idle at a later prompt
generation, and at `integration_lost`. A package needs no expiry logic of its own; it needs only to
stop exporting a token once the command it exported it for has ended.

One acceptance is not a line: the input a running command reads through the editor. A shell reports
it with `command_accepted` like any other, because to the editor it is one, and the worker tells
them apart by the context the reader entered and acknowledged in. An acceptance from a
`read_builtin` reader records no origin and mints no capability; the answer carries the origin that
stays in force and a null `detach_token`, and the line that started the command goes on holding
both. A `continuation` acceptance is not this case: it is part of the line being typed, at the same
prompt, and that line is the one that runs.

The Zsh and Bash packages export it for a primary or continuation line, after waiting at most one
second for the answer that carries it, and take it out of the environment again when the next
primary reader starts, whether or not the bridge is still connected by then. The fish and PSReadLine
packages do not export it, so a bare `kr detach` inside one of those is answered with the
instruction to name the attachment, which is the refusal this contract asks for rather than an
attachment the host cannot stand behind.

### The command a line runs

The Zsh and Bash packages ask before each command of an accepted line that the root shell starts
itself: an external command found on the search path, at the top level of the line, in the
foreground and with no pipe. The question is `command_resolve`, asked from the shell's executor
after its own search has found the file and before it forks, so it names the vector the shell is
about to run, the absolute path it found and the directory it runs in. A command in a subshell, a
command substitution or the background runs in a process the shell forks; a command in any part of a
pipeline is part of that pipeline, including the part a shell runs itself (zsh runs a group at the
end of one, and Bash its last part under `lastpipe`); and one that a function, a sourced or startup
file, an `eval`, a trap or a prompt hook runs is not a command of the line. None of these asks, and
each runs as it was typed. A script is a process of its own, so only the interpreter it is started
with is asked about. Zsh expands a filename pattern and applies the assignments in front of a
command only in the child it forks, so a command with either is not asked about either: `PATH` or
`ARGV0` there would change the file or the vector that runs.

The shell waits at most one second for the answer. A bypass, a refusal, the deadline and a lost
endpoint all run the command exactly as the shell would have run it without asking: the same file,
the same vector and the same environment. While an answer is owed nothing waits for another one, so
a worker that has stopped answering costs one wait rather than one per command. When the answer
carries a backend, the forked child starts the launcher the backend names, as `<launcher> launch --
<executable> <arguments>`, with the backend's variables added to that one child's environment. The
launcher is only ever the absolute path the answer gives and is never searched for; one that is not
an absolute path to an executable file is refused, and the command runs as it was typed.

None of this changes what the person sees: no key binding, function, alias or hook is added or
replaced, the history holds the line as it was typed, and `type` and `which` report the command as
they did before.

Each line also reports its command block from the reader's own boundaries. When a primary line is
accepted, its block starts with the line as the editor accepted it, the directory and that
directory's revision, and a continuation line joins it. When the next primary reader starts, the
block ends with the status the shell itself holds for the line and how long the line ran. An empty
line runs nothing and reports no block, and the input a running command reads through the editor
belongs to that command.

A session that names an absolute path in `KR_SHELL_BRIDGE_TRACE` gets one line of diagnostics in
that file for each question, answer and block, as long as the path is a plain file: a pipe or a
device is never opened for writing in a way that could hold the shell up. Otherwise the integration
writes no file of its own.

## The reader-thread rules

Three requests, each answered on the reader's own thread:

| Request | Fields | The reader must | Answer |
| --- | --- | --- | --- |
| `fence` | `session_id`, `fence_id`, `prompt_generation`, `reader_revision`, `deadline_ms`, `cause` (`editor_entry`, `lease_change`, `retry`) | Read its key queues atomically under its own lock, and say which of the tty/typeahead, macro and partial-key queues are clear | `acknowledged` with `fence_id`, `reader_context`, `prompt_generation`, `reader_revision`, `queues`, `snapshot`, `editor`, `cwd_revision`; or `refused` with `reader_busy`, `queues_not_drained`, `reader_moved` or `cancellation_unavailable` |
| `launch` | `session_id`, `transaction`, `fence_id`, `command`, `expected_prompt_generation`, `expected_buffer_revision`, `expected_cwd_revision`, `deadline_ms` | Check its actual state against every expectation and its own deadline, then install and submit or refuse, atomically | `accepted` with `transaction`, `fence_id`, `prompt_generation`, `buffer_revision`, `reader_revision`; or `rejected` with `transaction`, `fence_id`, `reason`, `prompt_generation`, `buffer_revision` |
| `cancel` | `session_id`, `epoch`, `prompt_generation`, `reader_revision` | End the pending key wait and keep the edit buffer | `cancelled` (which operations ended), `buffer_preserved`, `discarded_bytes`, echoing `epoch`, `prompt_generation` and `reader_revision` |

A report or an answer that names a reader the worker did not ask, or a cancellation it is not
waiting on, is ignored rather than acted on. Two takeovers can happen at one prompt in one reader,
which is why the cancellation carries the epoch it belongs to: the reader's identity alone cannot
tell one from the next.

The takeover receipt waits on that report, and only for the hold. The lease change is acknowledged
the moment it happens, because it stands whatever the reader says, and its acknowledgement says
whether the reader's own discards are still outstanding. They arrive once, with the count when the
reader reported it inside the hold and with nothing when it did not, which the receipt states rather
than a zero nobody measured.

The snapshot is the native equivalent of Zsh's `$KEYS`, `$PENDING` and `$KEYS_QUEUED_COUNT`: the
sequence that invoked the current operation, the bytes still unread in the reader's own queue, and
the keys still queued ahead of the terminal. Two reads taken a moment apart describe two different
instants, which is the ambiguity a fence exists to remove, so a qualified package takes them
together.

A launch is never written into the pseudo-terminal. There is no wake marker and no launch string,
because the process reading the terminal may not be the shell. A rejection installs nothing.

The transaction has its own identity, because a fence does not: the same fence is still valid after a
transaction has timed out, so a second launch would reserve it and a late answer to the first would
look like an answer to the second.

Two clocks, so the decision between installing and cancelling belongs to one of them. It belongs to
the reader, in the step where it reads its mailbox:

- The worker holds input for 250 ms from the moment it reserves the fence. The reader's own budget is
  200 ms from the moment it receives the request, and the request carries what is left of that
  budget rather than the whole of it, so a worker that has already spent part of its hold shortens
  the reader's window and never extends it.
- When the hold expires the worker releases the held input, because that is what the hold was for,
  and sends `launch_revoked`. The frames on this endpoint are ordered, so a revocation the worker
  sent before the reader's atomic step is one that step sees, and the reader then installs nothing
  and answers `revoked`.
- The caller's answer waits for the reader's word, not for the worker's timer. A rejection carries
  its own reason's code, which is `EDITOR_BUSY` for `revoked` and for every transition failure, and
  `DRAFT_CONFLICT` where the editor's own state had moved. It is then a fact rather than a guess.
  An acceptance means the reader had already installed before it saw the revocation: the command is
  in the editor, so the caller is told what happened and the session records the late installation.
- Every cancellation works the same way, not just the timeout. A reader leave, a lease change, a
  detach or a lost integration all revoke a dispatched transaction and wait for the reader's word,
  because a refusal that claimed nothing was installed would be claiming something the worker cannot
  see.
- More than one transaction can be unresolved at once, and each keeps its own answer.
- If the reader can no longer answer, because the bridge ended or the root shell was replaced or the
  session is closing, the answer is `OUTCOME_UNKNOWN`. The command may or may not be in the editor
  and nothing left can say which, which is the one launch outcome a caller never retries under the
  same action identifier.

This is a deliberate reading of section 7's "on timeout, reject the launch with `EDITOR_BUSY`,
release the held user input in order and install no command". The host installs no command by any
other means, and the ordinary answer is still `EDITOR_BUSY`; it is sent when the worker knows it is
true rather than while a command might be going into the editor. What the reader cannot give is a
cutoff both sides can verify: the two clocks are independent, the delivery delay is unmeasurable
from either end, and a reader that answered a synchronous question would be a blocking reader, which
is what the mailbox exists to avoid. So an uncertain outcome is reported as uncertain rather than
reported as a refusal.

The order at a successful launch is the reader's: it installs and submits the command, answers the
mailbox, reports `command_accepted` for the line, and then leaves. The worker resolves that line's
origin to the client that asked for the launch, which the reader cannot know.

The reader's own check, in the order the reasons matter, is `decide_launch`: this reader and this
fence, inside the deadline, with no input of the person's waiting ahead of it, then the prompt
generation, the working-directory revision and an empty buffer at the revision the caller named. The
reason decides what the caller is told:

| Rejection | Error code |
| --- | --- |
| `editor_left`, `queued_prior_input`, `lease_changed`, `fence_invalid`, `not_primary_reader`, `timeout`, `revoked` | `EDITOR_BUSY` |
| `buffer_not_empty`, `buffer_revision_mismatch`, `prompt_generation_mismatch`, `cwd_revision_mismatch` | `DRAFT_CONFLICT` |
| `confirmation_lost` | `OUTCOME_UNKNOWN` |
| `session_closing` | `SESSION_CLOSED` |

Section 23 lists the preconditions of `shell.launch` as `terminal.input`, the current input lease, a
qualified root editor, an empty prompt and fence, the working-directory revision and the launch
profile. The caller supplies the three that are its own, which section 7 names: the argument vector
or quoted command, the expected prompt generation and the expected empty-buffer revision. The rest
are the worker's, checked under its own dispatch barrier: the lease and the rights behind
`terminal.input`, the fence and the prompt, the working-directory revision it recorded at the last
reader boundary, and the session's launch profile.

Each cancellation carries its own sequence number, because neither the reader's identity nor the
epoch tells every one from the next: a takeover and a departure can both cancel at one prompt in one
reader, and a departure can happen at the epoch a takeover just produced. A report is matched on that
sequence. Only a takeover opens a receipt; a departure ends the reader's wait and has no receipt to
fill.

A cancellation that reports `buffer_preserved: false` ended the key wait by losing what the person
had typed. That is not the path this contract requires, so the worker withholds the fence rather
than publishing one over a reader state it cannot attribute input through, and the package is
unqualified.

## The pre-EOF decision

Readline and ZLE recognise an empty-line end of file before an ordinary binding runs, so the decision
belongs to a native hook immediately before that branch, after the next character has been selected
from the reader's input sources. An ordinary key-binding wrapper is downstream of the decision it
claims to make. Readline's buffering makes the point twice over: it returns pending and macro input
without consulting the character callback, and `rl_gather_tyi` can call the callback while it fills a
buffer, before preceding characters have changed `rl_end`.

The hook is handed the character (`key`: a `byte` or a `chord`) and the detach condition
(`managed_root_editor`, `reader_context`, `source`, `editor`), at the prompt generation and reader
revision it was selected at. It answers `native` or `consume`, without replacing the user's saved
binding, and `consume` continues the same reader call. `BridgeFenceView::decide` is that answer:

| The reader's situation | Decision | The hook returns |
| --- | --- | --- |
| The character is not the configured gesture | `native`, reason `not_the_gesture` | `native` |
| `VEOF` is disabled | `native`, reason `gesture_disabled` | `native` |
| The detach condition does not hold | `native`, with the named exclusion | `native` |
| A fence is published for this exact reader | `eof_detach(fence_id, prompt_generation, input_epoch)` | `consume` |
| No fence, or one from an earlier prompt or another reader revision | Consume, with at most one hint per prompt | `consume` |
| The worker refused the detach | Consume, with at most one hint per prompt | already consumed |

The hint is exactly `Use kr detach --attachment <id> to detach.` The `<id>` stays literal: the hint is
printed only when no fence can name an attachment, and an identifier guessed from the current lease
would be the uncertain attribution the gesture was consumed to avoid. The person names one. After a
successful detach the bridge drops its fence, so a repeated gesture is consumed rather than adopting
the next attachment's identity.

KR does not force `IGNORE_EOF` globally, and it preserves an existing user setting for native cases
outside the detach condition. Explicit `exit`, a real read error and a genuine end of stream keep
their normal closure behaviour.

### The detach condition

It requires the managed root editor, the primary prompt and an empty buffer. Ten states exclude it,
evaluated in this order:

| Exclusion | Holds when |
| --- | --- |
| `continuation_input` | The reader is on a continuation line |
| `read_builtin` | The `read` builtin is reading through the editor |
| `buffer_not_empty` | The buffer holds something |
| `quoted_insertion` | A quoted insertion waits for its character |
| `macro_input` | The reader is consuming a macro, or this character's source is `macro` or `pushed_back` |
| `search` | A search is active |
| `numeric_argument` | A numeric argument is being accumulated |
| `multikey_sequence` | A multikey sequence waits for its remaining keys |
| `vi_motion` | A vi motion waits for its target |
| `paste` | A bracketed paste is open, or this character's source is `paste` |

The pending flags and the source answer different questions. A flag says the reader is in the middle
of something; the source says where this character came from. The last character of a macro or a
paste arrives with the flags already clear, and it is still not a gesture a person just made, which
is why the source is part of the condition rather than a field nobody reads.

`not_managed_root_editor` is separate: it is the requirement that the contract applies to this reader
at all, not a state of a managed one. Outside the condition the original editor or application
handles the key normally.

### The gesture

The default is Ctrl-D, read from the line discipline rather than assumed. A `VEOF` reassignment is a
user change to the gesture: the bridge records it with the prompt it takes effect at, and the
character typed at the current prompt is still judged by the gesture that was in force when it was
typed. Disabled `VEOF` leaves the terminal with no gesture, so no character is one. Windows uses the
configured PSReadLine gesture, which is a chord rather than a byte, and the worker supplies it in the
accept.

## The fence and detach state machine

A fence is the ownership proof for the input delivered during one editor epoch: the root process, the
prompt generation, the reader revision, the input-lease epoch and exactly one originating attachment.
It is not a guess from the most recent input timestamp.

| State | What it means |
| --- | --- |
| `outside` | No root editor is registered. Input forwards immediately and a lease change waits for nothing |
| `unfenced` | A root editor is registered and nothing proves who owns its input |
| `fenced` | A root editor is registered and its fence is valid |
| `launch_reserved` | A launch transaction holds that fence while the reader's mailbox decides |
| `closing` | The session is closing |

The transitions, as the machine implements them:

Every entry point sweeps the deadlines against the clock reading it is given before it looks at the
stimulus, so a deadline is a fact about the clock rather than about which message arrives next. A
stimulus that discards the held input itself, an attachment removal, a detach or a closure, keeps it
through the sweep: releasing it there and discarding it here would deliver a client's keystrokes on
the way to throwing them away.

The hold belongs to the input, not to the reader. A reader that replaces another inside the same
hold does not restart it: the exchange carries the original deadline, and the bridge is told what is
left of it. Otherwise a succession of restarts could keep somebody's keystrokes waiting
indefinitely.

| Stimulus | State | What the worker does |
| --- | --- | --- |
| Editor entry | `unfenced` | Invalidate the previous fence, withhold an exchange the previous reader was to answer, ask for a fence, hold new input. The hold survives: a retry waits for the mixed queues rather than discarding them |
| Lease change, root editor registered | `unfenced` | Invalidate the fence, cancel the reader's incomplete operations when there was a previous holder, discard the old lease's undelivered input, acknowledge the change, ask for a fence, hold new input |
| Lease change, no root editor | `outside` | Acknowledge the change. Input forwards immediately; an application does not have a reader bridge |
| Acknowledged drain | `fenced` | Publish the fence, then release the held input in its original order |
| Acknowledgement with a queue still holding input | `unfenced` | Withhold the fence, release the held input in order, emit `EDITOR_BUSY`, wait for the queues to drain before publishing anything |
| Acknowledgement from a reader that has moved | `unfenced` | The same, with reason `reader_moved` |
| Refusal | `unfenced` | The same, with reason `refused` |
| A cancellation that did not preserve the buffer | `unfenced` | Withhold the fence, release the held input in order, emit `EDITOR_BUSY` |
| A cancellation that preserved it | unchanged | Add the reader's own discarded bytes to the takeover receipt for that epoch |
| Hold expiry at 250 ms | `unfenced` | The lease change still stands. Withhold, release in order, emit `EDITOR_BUSY` |
| A fence acknowledgement that arrives after its deadline | as the expiry left it | The hold is swept first, so it publishes nothing. A launch answer is different: it is the reader's word on a command that may be in the editor, and it answers the caller |
| Reader entry or idle callback after a withheld fence | `unfenced` | Ask again, respecting the outside-state bypass |
| Idle callback from a reader that has moved | `unfenced` | Invalidate the fence first: it proved something about a reader that is not running now |
| Editor leave | `outside` | Invalidate the fence, cancel a launch in flight, release any held input in order whatever the hold began for. No `EDITOR_BUSY` is owed: nothing is busy once the reader is gone |
| A leave or an idle report from a reader already replaced | unchanged | Ignore it rather than deregistering the reader running now |
| Input from an attachment that is no longer the holder | unchanged | Discard it. A removed or detached attachment's keystrokes go nowhere, even before the epoch advances |
| Eligible gesture with no fence | unchanged | The bridge consumes it with the hint until a fence exists |
| Valid detach | `unfenced` | Invalidate the fence *before* acknowledging, cancel a launch holding it, discard the removed attachment's undelivered input, end the reader's pending wait, remove the attachment, acknowledge |
| Detach naming a stale or missing fence | unchanged | Refuse it. The bridge consumes the gesture and prints the hint |
| Attachment removed | `unfenced` when it owned the fence | Discard its undelivered input, retire an exchange that was to name it, drop its lease, end the reader's pending wait |
| Launch request at a fenced primary prompt | `launch_reserved` | Reserve the fence under a transaction identity, send the mailbox request with the recorded working-directory revision, hold further input for at most 250 ms |
| Launch request in any other state | unchanged | Refuse with `EDITOR_BUSY` or, for a prompt that has moved, `DRAFT_CONFLICT`. Install nothing |
| Launch answered | `fenced` | Answer the caller, release the held input in order. An acceptance records the requesting attachment as the origin of the line it installs |
| Launch hold expiry | `fenced` | Revoke the transaction and release the held input in order. The caller's answer waits for the reader's confirmation |
| The reader's confirmation after a revocation | unchanged | `revoked` is `EDITOR_BUSY`; an acceptance means the command is in the editor, so the caller is told that and the late installation is recorded |
| The bridge ends with a confirmation outstanding | `unfenced` or `outside` | Answer `OUTCOME_UNKNOWN`: nothing left can say whether the command reached the editor |
| An acceptance for a transaction nobody is waiting for | unchanged | Record the installation and the breach: the package installed a command after its own budget |
| Interrupt under the current epoch | unchanged | Interrupt. It bypasses the hold and accepts only the configured native action |
| Command accepted | unchanged | Record the origin through the fenced context, which for an installed launch is the client that asked for it |
| The integration lost its hooks or its bridge | `unfenced` | Invalidate the fence, cancel a launch, release the hold: nothing left can answer for the reader |
| The root shell was replaced by something unqualified | `outside` | The same, and nothing is registered any more: input forwards like any application's |
| Session closing | `closing` | Invalidate the fence, discard what was held, refuse input, detaches, interrupts and launches |

Four rules are worth stating on their own, because they are the ones a heuristic implementation gets
wrong:

- **A new fence publishes only after an acknowledged drain.** A prompt event or a kernel byte count
  is not a substitute, and a retried fence waits for the mixed queues rather than discarding them.
- **The 250 ms release is not a failed `input.acquire`.** The lease change stands, the epoch in the
  `EDITOR_BUSY` event is the one that now holds input, and the released bytes went to the terminal in
  the order they arrived.
- **A failed fence never restarts the shell**, and it never flushes unrelated accepted text.
  Explicit attachment selection stays available throughout.
- **A detach outranks a launch.** The attachment the fence names is going away, so a transaction
  holding that fence loses it: the caller is told, the reader is told to install nothing, and the
  detach is validated and acknowledged.

At command acceptance the worker records the accepted line's origin through the same fenced context:
the attachment and epoch when the fence and the reader agree, the requesting client when a launch
installed the line, `mixed` when the fence and the reader disagree, and `unverifiable` when there was
no valid fence. `kr detach` without an attachment identifier targets that recorded origin, and
returns `AMBIGUOUS_ATTACHMENT` when it is mixed or unverifiable. A lease change afterwards does not
move it: it never targets whichever client holds the lease when the child command later starts.

## What qualifies a bridge

Five declared mechanisms, of which one value each is qualified:

| Mechanism | Qualified | Not qualified |
| --- | --- | --- |
| Mailbox | The declaring shell's own: `key_sequence_boundary_mailbox` (Zsh), `idle_reader_mailbox` (Bash), `reader_event_bridge` (Fish), `reader_thread_queue` (PSReadLine) | `file_descriptor_watcher`: stock `zle -F`, including `-w`, whose callback can run inside a multikey wait and can guarantee neither immediate acceptance nor cancellation. Another shell's mailbox is refused too |
| Pre-EOF | The declaring shell's own: `native_hook` (Zsh, Bash), `named_reader_binding` (Fish), `reader_state_handler` (PSReadLine) | `key_binding_wrapper`, and any of the other three declared by a shell it does not belong to |
| Fence proof | `atomic_reader_state` | `prompt_hook`, `foreground_process_group`, `screen_coordinates`, `empty_kernel_queue` |
| Cancellation | `non_destructive_key_wait` | `unavailable` |
| Launch delivery | `reader_mailbox` | `pseudo_terminal_key_injection` |

The four rejected fence proofs each describe something adjacent to the reader, and none of them says
that the reader has no input of its own, no plugin-mutated buffer and no imminent transition:

| Offered as proof | What it cannot establish |
| --- | --- |
| A prompt hook firing | It runs before the reader exists and says nothing about its queues |
| The foreground process group | It names a process, not the state of a reader inside it |
| Screen coordinates | They describe what was drawn, not what is waiting to be read |
| An empty kernel queue | It says nothing about input the reader has already taken, a plugin-mutated buffer or an imminent reader transition |

A bridge that cannot prove its delivery fence is unqualified, and it must not fall back to injecting a
private key into the pseudo-terminal. That fallback is not a value a qualified declaration can hold:
`qualify` refuses it outright.

### How a package proves its fence

1. Declare `atomic_reader_state` and implement the fence answer inside the reader, under whatever
   lock the reader already holds at a key-sequence boundary.
2. Read the three queue states and the buffer state in one operation, at one instant.
3. Report each queue separately. A worker that learns which queue still holds input can retry; one
   that learns only that the transition failed cannot.
4. Never report a queue clear on the strength of a prompt hook, the process group, the screen or the
   kernel's own byte count.
5. Answer within the 250 ms hold, or expect the worker to release the held input and ask again at the
   next entry, leave or idle callback.

## What each reader can prove, and what it cannot

The four packages answer one contract, and the mechanism table at the top of this document says
which mechanism each of them answers it with. Two of those mechanisms are not a patched reader, so
what they can and cannot establish is written out here rather than left to be discovered.

### fish

fish 4.x is a Rust shell, so the reader's own half of the bridge is Rust beside the reader and the
shell-independent core is the same C every other package compiles. The published patch set does
four things:

- The bridge's endpoint joins the reader's own `select` set, so a fence, a cancellation or a launch
  that arrives while the reader is blocked is answered then rather than at the person's next key.
- The mailbox is read at every key-sequence boundary: after one complete sequence has been resolved
  and before its binding runs, which is where the reader is between operations. Every wait the
  reader can be in watches the endpoint alongside the terminal: the wait for a key, the wait for
  the rest of a character and the wait for the rest of an escape sequence. It watches for room to
  write while an answer is still going out, and the two waits inside the reader's own decoding
  give up what they are waiting for when a takeover ends them.
- The end-of-file decision is a **named binding**, `kr-eof-decide`, in the reader's own command
  table. The guarded entry under `conf.d` puts it on the configured gesture once the person's own
  configuration has run, in every bind mode the shipped bindings use, keeps whatever was bound
  there in each of them, and runs that outside the detach condition. The decision carries the key
  the reader decoded rather than the byte the terminal sent, so a gesture that arrived as a whole
  escape sequence is still one key. A person who binds the gesture key afterwards takes it back,
  which is theirs to do.
- A cancellation ends a pending key wait through the reader's own interruption path, which returns
  the part-read sequence, handles the interruption and leaves the edit buffer exactly as it was. It
  settles at the boundary the reader comes out at rather than the one it was asked in, and reports
  the bytes it dropped.

The states the detach condition excludes are read from where this reader actually keeps them. Its
vi bindings hold a count and a pending operator in the shell's own variables and in the `operator`
bind mode, and both are reported and both hold the partial-key queue. So do the first bytes of a
character the decoder has not finished and characters the reader has taken from the terminal and
not yet put in the buffer. One thing this reader does not have, and the package says so rather than
claiming it: a quoted insertion of its own. `get-key` waits for a literal key in the same way and
the bridge reports that state, so a package that binds it is covered; nothing binds it by default.

The buffer's revision is the reader's own edit generation, so a binding that changes the line and
puts it back has changed it twice; a directory change counts wherever `PWD` is set, for the same
reason.

The gesture follows the terminal's own end-of-file character, read from the modes the shell hands
to the programs it runs. The reader holds the terminal in the shell's own modes while it reads, and
those keep their own control characters, so a `stty eof` of the person's own lands there and takes
effect at the next prompt.

### PSReadLine

This package rebuilds no shell. PSReadLine is the editor the person already has, and the module
binds into it: it wraps the host's own read-line entry point for the reader's boundaries, wraps the
editor's own operations so the reader has a boundary to answer at and the states they wait in are
observable, and puts its end-of-file decision on the configured gesture in front of whatever was
bound there. A handler the person wrote themselves is left exactly as it is, identified by what the
editor holds rather than by the name a handler carries, and what the module installed is put back
when it is removed, except where the person has since bound that key themselves.

What it pins is a range rather than a release: PowerShell 7.4 or later with PSReadLine 2.3.4 up to
3.0. The module declares the versions it found in its handshake and the worker refuses an editor
ABI it was not qualified for. A build that does not keep the reader's own key queue where this
package was qualified to find it is refused with a named error rather than registered.

Section 7 says this package does not claim that the stock public API has an asynchronous editing
method, and that is exactly what it cannot do:

- **The reader is reached when it steps.** The module's queue is serviced on the reader's own
  thread, after each of the editor's own operations has run: every chord the editor has a binding
  for goes through the module, which runs the editor's operation and then reads the queue. The
  read-line entry reports the reader and reads nothing, because the editor clears its buffer when
  its read starts. A key the person bound to a script of their own is theirs and carries no
  boundary, and an ordinary character goes straight to the editor's own insertion, so a request
  that arrives at a parked reader is answered at its next bound key rather than immediately. Until
  then the reader's last idle report is what the worker has to go on.
- **A launch is installed where it is decided and accepted at the next step.** The decision, the
  state check and the installation all happen on the reader's thread, inside the fence, at a point
  where the reader is between operations: a key of the person's that has been read and not yet run
  is never one the launch goes in front of. The editor's own accept is what ends the read, and it
  ends it when the operation the module answered from returns. Nothing is decided before the read
  starts, because the editor clears its buffer there and a line installed then is one nobody would
  run.
- **A cancellation ends nothing here, and says so.** Every operation that waits for another key
  runs this editor's own read loop, and nothing of the module's runs on the reader's thread while
  one is running, so a cancellation arrives after the operation it was meant for has finished or
  not at all. The report names nothing ended, discards nothing and leaves the line alone; the
  worker then withholds the fence until the reader's own queues drain, which is the fail-safe
  answer.
- **The queues are the editor's own.** The reader's key queue is read directly, under the version
  range this package was qualified against. Asking the console whether a key is available instead
  would take the lock the editor's own read is holding, and the reader would wait for itself.
- **What the reader cannot prove, it does not claim.** The editor decodes the terminal's bytes
  inside its own key read, where nothing of the module's runs. What the module reports is the
  editor's own key queue and the operations it is inside; a sequence the editor has begun to
  decode and not finished is in neither, so the queue proof here is as good as that queue and no
  better. A fence asked while the reader is blocked on a key is answered at its next step,
  against the state it has then.
- **The buffer belongs to the read that is in progress.** Between one line being accepted and the
  next read starting, the editor still holds the line that has gone; the module reports the buffer
  it is about to have, which is empty, and counts no change the person did not make.

Running the module on Windows, where the endpoint is a named pipe and the gesture is the configured
chord rather than the line discipline's own character, is qualified separately.

## The scenarios

`fixtures/shell-bridge/` holds 40 scenarios, one JSON file each. Every file names what it
demonstrates, the requirement rows it covers, the shell packages that must reproduce it, and the
exact outcome of every step, including the error codes and the hint text as literals. Four script
kinds drive the four decision points: `handshake` drives the handshake and the activation decision,
`fence` drives the state machine one stimulus at a time at a stated clock reading, `pre_eof` drives
the decision inside the bridge, and `launch` drives the reader thread's own check.

```bash
# Replay every scenario against the contract.
cargo test -p kr-shell-integration --test harness

# Rewrite the scenarios after a contract change, and check the committed ones.
cargo run -p kr-shell-integration --bin kr-shell-fixtures
cargo run -p kr-shell-integration --bin kr-shell-fixtures -- --check
```

| Scenario | What it shows |
| --- | --- |
| `handshake-accept` | Each package's qualified declaration registers, and the accept tells it to unexport the bootstrap values |
| `handshake-reject` | Every named qualification error, and the two reasons a starting shell does not attempt the handshake |
| `enter-fence-acknowledge-detach` | The whole path from reader entry to an attributable detach |
| `detach-condition-exclusions` | The eligible case and each of the ten exclusions |
| `takeover-partial-escape`, `takeover-quoted-insertion`, `takeover-vi-motion`, `takeover-incomplete-chord`, `takeover-macro` | A takeover during each kind of incomplete operation: the cancellation and what it ended, the reader's own discarded bytes, a withheld fence while a queue still holds input, a retry at the idle callback, and the edit buffer intact |
| `takeover-destructive-cancellation` | A cancellation that lost the buffer, the fence the worker therefore withholds, and a report from a reader it did not ask |
| `takeover-receipt-superseded` | A departure that supersedes a takeover's cancellation, and the receipt that closes as unknown rather than taking the departure's count |
| `two-outstanding-confirmations` | Two unresolved transactions, each keeping its own answer |
| `attachment-removed-during-exchange` | An attachment that goes away mid-exchange, taking the exchange and its lease with it |
| `deadline-meets-departure` | A hold that expires at the same moment as a removal or a closure, and input from an attachment that is no longer the holder |
| `detach-at-the-launch-deadline` | A gesture that arrives as the launch hold expires, with the detaching attachment's held input discarded rather than released |
| `integration-lost` | A session that loses its hooks, and one whose root shell was replaced |
| `timeout-editor-entry`, `timeout-takeover`, `timeout-launch` | The 250 ms release in each of the three places it applies, including an answer that arrives late with no timer stimulus first |
| `launch-installed` | A launch the reader installs, and the accepted line attributed to the client that asked for it |
| `launch-reader-decisions` | The reader thread's own decision table: one case per rejection reason, and a successful install of an argument vector no interpolation could survive |
| `launch-confirmation-lost` | A revoked transaction whose confirmation never comes, and the unknown outcome the caller is told |
| `launch-cancelled-by-leave`, `launch-cancelled-by-prior-input`, `launch-cancelled-by-lease-change`, `launch-cancelled-by-buffer-revision` | The four ways a launch is cancelled, which error each one is, and the held input released when the reader leaves |
| `detach-during-launch` | A valid gesture while a transaction holds the fence: the launch loses it and the detach goes through |
| `eof-stale-fence`, `eof-missing-fence` | A detach the worker refuses, and a gesture the bridge consumes with one hint per prompt |
| `eof-repeated-after-detach` | A repeated gesture that cannot adopt the next attachment's identity, and the hint a refused detach prints |
| `eof-after-detach-succession` | No new fence until the old queues drain, and the next attachment's own fence when they do |
| `veof-change`, `veof-disabled`, `psreadline-chord-gesture` | A reassigned gesture taking effect at the next prompt, a terminal with no gesture, and the configured Windows chord |
| `acceptance-mixed-context` | A recorded origin, a mixed one and an unverifiable one, what `kr detach` resolves to in each case, and a lease change that does not move it |
| `editor-leave-boundaries` | The five reader boundaries a leave is reported at, and a stale leave that is ignored |
| `retry-at-entry-and-leave` | A retry at the reader's next entry, and a leave that releases what was held |
| `interrupt-bypasses-the-hold` | An interrupt that is not held, and the two ways it is refused |
| `outside-state-bypass` | A lease change and input outside a registered root editor, waiting for nothing |
| `closing-rejects-input` | Closing, and what it refuses |

A package's own tests read these files rather than restating their expectations, so a package and the
worker are checked against one corpus instead of against each other.
