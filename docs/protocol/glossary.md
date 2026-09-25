# Glossary

The terms the protocol relies on, in alphabetical order. An identifier in parentheses is the wire
name of the object the term names; `crates/kr-protocol/src/ids.rs` defines each one.
[README.md](README.md) is the protocol reference and [methods.md](methods.md) the method index.

**Action** (`action_id`). One submitted intent and its receipt. The action identifier is the
durable identity of a mutation: an exact retry over a new connection carries the same one, while
`request_id` only correlates a response on one connection. See [Digests and signing
input](README.md#digests-and-signing-input).

**Action window** (`action_window_id`). The freshness context a mutation is admitted under. The
mutation digest covers it, so a request sent under a replacement for an expired window is a new
first admission rather than a retry.

**Actor** (`actor_id`). The identity the host builds for a request: a stable principal the host
issued, the ingress the request arrived through and, where they apply, the paired device and the
grant it is checked against. A mutation is de-duplicated by its actor and its action identifier.

**Application instance** (`application_instance_id`). One foreground application inside a
terminal session.

**Attachment** (`attachment_id`). One CLI or app view of a session, identified independently of
the device it runs on. An attachment is granted a set of capabilities (observing the terminal,
observing semantic state, input, geometry): what it asked for, narrowed by the rights of the grant
it arrived under when it arrived under one. See [Rights and capabilities are not the same
thing](README.md#rights-and-capabilities-are-not-the-same-thing).

**Attachment ordinal** (`attachment_ordinal`). The order in which attachments joined a session,
which decides who owns the terminal's size next when its owner leaves.

**Capability** (`capability_id`, `capability_revision`). What a binding can currently do, with the
evidence for it. Capability evidence never creates authority: a right is what a grant permits.

**Change set** (`change_set_id`, `change_set_version`). Captured work that does not change once
captured. A version names the exact content that was tested or reviewed. See
[docs/project/README.md](../project/README.md).

**Control daemon.** `kr-controller`, one per operating-system user and environment. It keeps the
session registry, starts and supervises workers, authenticates paired devices and serves the
host's own methods. Restarting, upgrading or losing it ends no session. See
[docs/host/README.md](../host/README.md).

**Controller generation** (`controller_generation`). The control daemon's persistent generation,
advanced every time a daemon starts. A worker refuses a lower generation than the one it has
accepted, so a daemon that has been replaced cannot act on a worker that accepted its
replacement.

**Device** (`device_id`). A computer or phone paired with a host. It holds keys separated by
purpose, and the host issues it grants.

**Dispatch marker.** The durable record written before an action crosses the boundary to the
application or service that performs it. Once it exists, the action's receipt can end as
`applied`, `refused` or `unknown`, never as `rejected`. See [Receipt
states](README.md#receipt-states).

**Domain.** The first element of a signing input, `CBOR([domain, element, ...])`, such as
`kr-connect/1` or `kr-mutation/1`. It is what stops a signature over one kind of statement being
read as a signature over another.

**Editor fence.** The proof that a session's root editor belongs to one exchange: the root process
with the kernel's record of when it started, the prompt generation, the reader revision, the input
epoch and exactly one originating attachment. See [The root
integration](README.md#the-root-integration).

**Effect.** Whether a method reads state or changes it: `read` or `write`. A write sent to a host
arrives as a mutation and carries an action, raw input excepted. A method of the `Services` group is
sent to a service as a signed service request instead; see [The service
credential](README.md#the-service-credential).

**Endpoint** (`endpoint_id`). An iroh peer, named by its public key. A host and each paired device
have one.

**Environment** (`environment_id`). One installed operating system, distribution or container,
and one operating-system user in it. Sessions run in environments, and each environment has its own
control daemon, registry and directories.

**Envelope.** The outer shape of a message: a request, a mutation, a response or a notification.
See [Envelopes](README.md#envelopes).

**Geometry owner.** The attachment that decides the pseudo-terminal's size. By default it is the
first authorised attachment that claims it; ownership passes by explicit transfer or, when the
owner leaves, in attachment order.

**Grant** (`grant_id`). A host-issued authority object: which rights, over which resources, for how
long, and how much history. A delegated grant is never wider than the grant it came from. See
[Grants](../pairing/README.md#grants).

**Host.** A computer running KalaReach: a control daemon for each operating-system user and
environment, and a worker for each session.

**Ingress.** Where a request entered the host: `local_ipc` (an authenticated operating-system
caller on a local socket or named pipe), `paired_device` (an authorised iroh connection),
`unpaired_peer` (a connection that has not passed device authorisation), `workflow` (an automation
run under its workflow grant), `plugin` (a plugin component in the plugin runtime) or
`service_client` (a credential presented at a managed or self-hosted service). Each method lists
the ingress it accepts, and ingress is checked before rights.

**Input lease.** A session's single right to write to its terminal, held by at most one
attachment. A remote attachment acquires it explicitly. A takeover is immediate and advances the
lease's epoch, which invalidates the previous holder's epoch and any of its input not yet
delivered. Raw input is an ordered stream under the current epoch.

**KR-CBOR-1.** The canonical encoding every signature, digest and frame uses: RFC 8949 core
deterministic encoding narrowed by a profile. See [KR-CBOR-1](README.md#kr-cbor-1).

**Machine** (`machine_id`). A random, owner-approved logical grouping of environments. It is not a
hardware identity.

**Method.** A named, versioned operation in the method registry. Every method has one authority
entry, and anything not in the registry is denied. See [the method index](methods.md).

**Mutation.** A request that changes state. Besides the method and parameters it carries the
action identifier, the grant reference, the target, the preconditions, the action window and the
requested time to live.

**Owner confirmation.** A fresh confirmation by the host's owner, bound to the exact digest of one
sensitive action, used once and short-lived. See [Owner
confirmation](../pairing/README.md#owner-confirmation).

**Pairing.** How a device becomes trusted by a host: a short code or a direct QR invitation, a
proof of what both sides saw, and the owner's confirmation. See
[docs/pairing/README.md](../pairing/README.md).

**Prompt generation.** Which prompt the root editor is at. It advances at every primary prompt, so
a decision taken at one prompt cannot be replayed at the next.

**Receipt.** The durable record of an action's state as it moves from `received` towards
`applied`, `refused` or `rejected`, with a revision that only increases. See [Receipt
states](README.md#receipt-states).

**Right.** One permission a grant can carry, from the action-right vocabulary in
`crates/kr-protocol/src/rights.rs`. A request needs every right its method requires, except one
whose condition does not apply to it: `session.attach` needs `terminal.geometry` only for a
geometry claim.

**Root editor.** The line editor of a session's root shell, which a managed shell package connects
to the worker so that Ctrl-D at an empty prompt detaches and a launch installs a command through
the editor rather than through the terminal.

**Root shell, session root shell.** A session's initial interactive shell, started by its worker
on the session's pseudo-terminal. When it exits or is ended by a signal, the session closes. *Root*
names its place at the top of the session, not a privilege: a root shell is not a superuser shell.
It runs as the environment's operating-system user, and the host raises no privilege for it or for
anything it starts; only a person inside the session who runs a privilege-elevation tool changes
that, for the program they run.

**Session** (`session_id`). A KalaReach terminal session: one root shell on one pseudo-terminal,
owned by one worker. A new execution always has a new session identifier.

**Session epoch** (`session_epoch`). Fixed at 1 in this version of the protocol.

**Shell mode.** How a session's root shell is launched. `managed` runs a KalaReach-qualified shell
package and claims the root editor; `native_compat` runs the stock shell named and claims none of
it.

**Stream cursor** (`stream_cursor`). A position in one event stream. A client resumes from its
cursor; one that fell behind its stream is answered `RESYNC_REQUIRED`, takes a new snapshot and
resumes from the snapshot's cursor.

**Worker.** `kr-worker`, one process per session. It owns the pseudo-terminal, the root shell, the
terminal state, the attachments, the input lease and the session's receipt journal. Nothing the
control daemon does, restarting, being upgraded or crashing, ends it, which is what lets a session
outlive the daemon.

**Workflow** (`workflow_id`, `workflow_run_id`, `causal_root_id`). An automation definition, one
run of it, and the causal chain a run belongs to. See
[docs/automation/README.md](../automation/README.md).

**Workspace** (`workspace_id`). A working copy of a project repository that sessions are bound to:
the user's own tree, shared, or an isolated copy. See [Workspaces](../project/README.md#workspaces).
