# Automation reference

Workflows are versioned directed acyclic graphs of typed execution nodes executed on the host.
They react to verified event triggers, run under causal budgets, and observe per-workflow, per-host,
and per-grant admission limits.

## The five methods

| Method | What it does | Right |
| --- | --- | --- |
| `workflow.install` | Validates and stores a versioned workflow definition document | `automation.manage` |
| `workflow.enable` | Activates an installed workflow definition revision | `automation.manage` |
| `workflow.pause` | Pauses an enabled workflow definition revision | `automation.manage` |
| `workflow.run` | Explicitly triggers an execution run of an enabled workflow | `automation.manage` |
| `workflow.read` | Reads definitions and whether each revision is paused, runs, node receipts, a chain's remaining budget, and the alerts no attention state has taken | `automation.manage` |

The control daemon serves all five, to the owner on the local socket and to a paired device over
the network, and those are the only ingresses the method registry lists for them. They arrive
through the daemon's ordinary path on either door: a read is checked against current authority,
and a mutation carries an action window, is checked against the method registry and its rights,
and runs on a task a dropped connection cannot cancel part way through. A workflow belongs to the
environment rather than to a session, so a request that targets a session or a foreground
application is refused before anything is written.

A paired device acts under the grant it holds and no other. It may install a workflow only under
that grant, and only as a new workflow or a new revision of one that already acts under it; it may
enable, pause, run and read only the workflows that act under it. Whether it may reach a revision
is decided before anything else is said about it, and a revision it cannot reach is answered
exactly as a revision that is not installed, so it learns neither that the revision exists nor
which grant it acts under. A revision number the journal cannot hold names no revision at all.

A causal chain belongs to the grant its root run acts under. The owner may install a workflow that
crosses grants: one under a device's grant, say, triggered by the owner's own events, which brings
runs under the device's grant into the owner's chain. What a device installs does not follow such a
crossing. A revision a paired device installed is triggered only by a run whose whole chain, from
its root to that run, acts under the device's grant, so a device cannot subscribe to another
grant's events, spend another grant's chain or read another grant's runs back as its descendants'
parents, however the chain came to include a run under its grant. A device reads a chain's
remaining budget and its alerts only for a chain that is its grant's. A run of its own that a
crossing brought into another grant's chain is shown to it with nothing of the run it descends
from: no parent run or node, no causal parent in its node receipts, and a trigger identifier that
is the derived-trigger prefix `node:` alone. It keeps the chain's root identifier and its own
depth, which name no run. A workflow therefore never gives a device a right its own grant does not
carry.

A paired device's grant is read from its pairing record, so revoking the device stops every
workflow under that grant, and a grant whose expiry the host has recorded does not come back.

Every method has an exhaustive authority entry in `kr_protocol::method::REGISTRY` naming its
effect class, the ingress an actor may reach it through, the rights it requires, its resource
selectors, its freshness and its idempotency. Each method names the exact definition revision it
acts on, and a request whose revision does not match the document it carries is refused.

## Every mutation is an action

`workflow.install`, `workflow.enable`, `workflow.pause` and `workflow.run` are actions. Each
carries the caller's action identifier, and the workflow journal records what it came to in the
same transaction as its effect.

* **One transaction.** The journal first looks for the record an earlier submission of the same
  action left. If there is one, it is the answer and nothing is written. Otherwise the journal asks
  the daemon whether the admission the mutation was accepted under still stands (no fence the
  host owes stops dispatch, and the connection's registration, the authority revision it was
  admitted under and its accepted deadline stand),
  immediately before the action's first write; then it writes the effect and the record together.
  No effect exists without its record, and there is no record of an action still under way.
* **A repeat is answered, not performed.** A retry after a lost reply is the original mutation,
  freshness window and all. It is answered from the record before its window is considered, so a
  caller whose window has since been replaced still gets its own result. A repeated enable returns
  the first answer and cannot undo a pause decided after it. A repeated run is told where the run
  it started stands now, and starts nothing.
* **A refusal is an answer too.** A refusal the host decided about the action is recorded together
  with whatever deciding it wrote, such as the pause a breached limit owes, and a repeat is refused
  the same way. A journal that could not be written, a grant store that could not be read and an
  admission that lapsed say nothing about the action: they leave no record and write nothing, so a
  later submission is decided afresh.
* **A reused identifier is refused.** The same identifier carrying a different method or payload
  is refused with `ID_CONFLICT`.
* **A duplicate costs nothing.** A trigger already recorded for the revision is found inside the
  transaction that would admit it, before any allowance is spent, so two copies of one event that
  arrive together cannot both reach admission.

## The grant a workflow acts under

A definition names a grant identifier and nothing more. The host reads that grant from its own
grant store and decides it under its own policy, and does so again immediately before every node
it dispatches and once more where the node's effect begins.

* **Read, never supplied.** Nothing a caller passes in decides what a run may do. A grant this
  host never issued names no workflow it will install.
* **Decided as a device's request is.** The daemon decides the grant with the model it decides a
  paired device's request with. The rights ceiling the host's configuration puts in force narrows
  the grant before anything else, so a right the configuration removed is not one a workflow may
  use. The grant is then intersected with the host's policy as it stands: a revoked ancestor, the
  clock floor, redemption, expiry, an authority revision the host never issued, the organisation
  lease a grant requires and the bounded offline validity for a grant held by a paired device.
  That bound is held on the continuous clock it was anchored on as well as in UTC, so a wall clock
  wound back after the bound ran out does not bring it back. The rights left are the rights the
  node is checked against. A grant that requires an organisation membership is refused here,
  because nothing on this host yet records which member account a grant's recipient is.
* **Nothing is decided on a floor a restart would not know.** Each decision raises the clock
  floor, so a clock wound back between two dispatches of an unattended workflow does not revive an
  expiry the host already refused. A refusal the clock decided is answered only once the floor it
  stood on is written down, and while any such floor is still owed its record nothing is decided at
  all: the write is made first, and while it cannot be, authority is unavailable and nothing is
  dispatched. Every wait is therefore over before the decision, which is taken at the reading the
  caller took advanced by the time those waits took, so a deadline that passed while the decision
  waited for storage is decided as passed, and nothing waits between a permission and its use.
* **Withdrawn is withdrawn.** A grant that has expired, has been revoked, has a revoked ancestor,
  or has never had its invitation redeemed admits no run. A withdrawal that lands between two
  nodes of a run stops the run where it stands: the node that has not been dispatched is paused,
  and nothing is claimed about the node that already ran.
* **Held while the effect commits.** The host's own action runner reads the grant once more
  inside the task that performs the effect, before a capture reads a working tree. The change-set
  service then asks for the node's grant around every transaction that commits the effect: the
  clone identity a capture fixes, the change set and its version, the row a materialisation is
  written under. Each time, the host takes its registry, which a revocation takes to complete,
  refuses while a fence is owed, reads the grant as it stands and checks the node against it, and
  only then lets the transaction commit. A withdrawal that lands while the write waits for the
  store is seen there and nothing is written; one that begins while the write commits finishes
  after it. A refusal at any of these points pauses the node and its run exactly as a refusal a
  moment earlier would have, because the effect did not happen.
* **Each node needs every right its effect needs.** A `shell_command` node opens a session, types
  into a shell account, and closes the session when it settles. It therefore requires the
  `terminal.input`, `session.create`, and `session.close` rights. Similarly, `run_tests`
  additionally needs `workspace.manage` because it writes out the version it tests.
  `create_session`, `request_review`, `capture_changeset`, `materialize_changeset`, and `apply_diff`
  also need `session.create`, `agent.prompt` and `session.view`, `changeset.create`,
  `workspace.manage`, and `files.apply_diff` respectively (because those are the rights that the
  methods which perform those same effects require). The requirement that a composite effect require
  the rights for all of the methods that perform the same effect prevents a workflow being used to
  call a method that a given person would not be able to call any other way. For example, a
  view-only invitation cannot obtain terminal input through a workflow. A `create_session` node that
  names the shell its session runs also needs `terminal.input`. A definition whose grant lacks a
  right one of its nodes needs is refused at install, and the refusal names the right. A definition
  installed earlier under fewer rights is refused when a run is admitted, and a run already under
  way pauses its node and itself when dispatch reaches a node its grant does not authorise, with the
  refusal naming the right its grant lacks. The grant will never be augmented.
* **A broad shell grant selects every session.** If a node causes a command to run, it must create a
  session and run the command in that session, in the selected environment. If the grant does not
  select every session in that environment, the definition is refused at install and the node at
  each dispatch; a grant that selects one named session, or none, does not. A definition installed
  under such a grant earlier is refused when a run is admitted, and a run already under way pauses
  its node and itself when dispatch reaches a node its grant does not authorise, with that refusal.
  A `create_session` node that names the shell its session runs is held to the same grant, because a
  named shell runs a program the definition chose.
* **A device's workflow gets what its grant carries.** Because the grant is held inside the
  change-set service's own transactions, a workflow under a paired device's grant runs the
  change-set nodes that grant's rights allow, under the same hold, and nothing more.
* **Scope is checked too.** Every node's effect happens in the environment this host serves, so
  the grant has to cover that environment whether or not the definition names one, and a
  definition scoped to another environment runs nothing here. A definition scoped to a session is
  refused unless the grant covers it, a shell node's declared execution environment has to be one
  the grant admits, and a session node creates its session in this host's environment and nowhere
  else. A capture node, and an apply node that names a workspace, has to name the workspace the
  definition is scoped to, and a materialisation is refused where it would begin unless the
  version it names can be read and was captured from the definition's workspace, when it names
  one, and from this environment.

## What a node actually does

Launching a node (command or session creating) will follow the daemon's own create path, the same
path a connection's `session.create` takes, going through the registry's reservation, checking the
environment's session limit and the update handover gate, and creating a session under a supervisor.
A node is not a connection, so it stands on its grant, and the session will use a stable principal
scoped to the grant of the definition that the node is in, not to the run. The token for the session
create will be the ID of the journalled action that represents the node, ensuring that if the daemon
restarts and the session create is retried, the retry finds the session its first attempt made and
never makes a second one. The digest that token stands for covers only the things that don't change
about the node. At the launch transition, under the registry guard, where the session comes into
being, the grant (with the rights above) and the moment the engine stops waiting for the node are
checked. They are checked again when the worker claims its launch, which is when the program is
released to start. A grant withdrawn or a wait that ended in between starts nothing, and so does a
run cancelled once the engine has asked the node to stop (while the engine waits for the node, it
reads the run's status after each timer wait, with the timer set for at most a quarter of a second).
The claim also decides the moment after which the session's process may not be created, each end
read as the moment it ends on the machine's continuous clock. The worker checks this moment where it
creates the process, after everything it prepares. For commands, this will be the earlier of the
time at which the node is no longer being waited on, and the time at which the grant ends (its
expiry, an organisation lease, a bounded offline validity). For `create_session` nodes, the session
outlives the node's wait, so only the time at which the grant ends bounds it, and that holds for the
shell it names as it does for a command. The chain's session allowance is spent for each node that
creates a session, a command's included.

A `create_session` node creates a session using the parameters of `session.create`. Once the session
is created, it will continue to run, and the session will be the output of this node. The session
belongs to whoever uses it afterwards. The create runs on a task of the daemon's own, so a node
whose wait ends in the middle of it leaves no half-made reservation. If the node is asked to stop
before its admission at the launch transition begins, the node stops and no session is made. Once
the session has been admitted at the launch transition, the node can no longer be stopped: a node
whose wait or run deadline passes is left unknown, and a node whose run is cancelled is recorded as
cancelled. A request to stop that comes before the worker's claim is still held against the claim,
which is refused, so no program will start and no session will be made. A session whose claim came
before the request stays.

A `shell_command` node will run the specified command as the root of a new session. The worker runs
the command line through `/bin/sh -c`. No login or interactive startup is performed, and the
environment variable `SHELL` is set to the path of that interpreter. The command will be run in the
workspace specified by the scope of the definition, if it is named (a shared checkout only because
the definition named it); otherwise, a private directory will be created for the command node. The
workspace is opened the same way as for captures; if the tree has been moved, removed or replaced
since it was recorded in the project service, the tree is refused and the node pauses. Also, the
worker refuses a directory that is not there instead of running the command somewhere else. (The
directory is verified when the command is accepted; one swapped in the moments after that is not
detected.) Standard input for the command will be the terminal of the session, so that a command
that reads it waits for a person or for the node's wait. The result of the command node will depend
on how the root process of the session exited, as this host recorded it. If it exited with status
zero, the command will succeed; if it exited with a non-zero exit status or was terminated by a
signal, the command will fail and record the exit status or signal that terminated it. If the worker
could not launch the command, the node fails; a start refused because the grant was withdrawn or has
ended pauses the node and its run, as any refusal does. If the session is closed for any other
reason (by a request, a crash, the loss of the desktop or the host's shutdown), it says nothing
reliable about the command, and the node is left unknown; so is a node whose command exited with no
exit status recorded. Like any other session, the session running the command can be listed and
attached to; additionally, its summary will note that it is running a command as its root. The
session's journal keeps that word in a row of its own and its summary in the form the release before
reads, so that a host rolled back to that release reads a command's session as it reads any other.
An update that closes sessions closes a running command too. Commands are offered only on hosts that
have a POSIX shell: a definition that holds one is refused at install on Windows.

When a node reaches its wait or run deadline or its run is cancelled, the command's session is
closed and the node settles cancelled, which says the host stopped asking and nothing about what the
command did. Everything a command node owns outside the journal (its session, its directory, the
run's hold on its workspace) is written down in a ledger of its own before any of it is made, and
released once the session's closure accounts for its worker. A node's private directory is made for
it alone, and its identity is recorded before the command can start. The directory is removed only
while it is still the object that was recorded, by the removal the project uses for a directory it
recorded: its inode and the filesystem it is on must be the ones the handle that made it reported,
and its device number may differ from the recorded one only where it is on the filesystem of the
directory it is in. The removal opens the scratch root without following a link, and opens the
directory beneath it through that handle. The directory is made private again if the command
loosened its mode (unpacking an archive does), and it has to be one only this account can change.
What is in it goes through handles the removal holds, staying on the directory's own mount and
holding no more than 128 levels. A tree the removal does not take (a mount inside it, one nested
deeper than that, a directory in it that its owner cannot write, one whose owner read bit the
command removed, one with an access-control list on macOS, entries still being written, a failure of
the storage) stays where it is after that attempt: the row is released and the daemon's log names
the directory (the removal is tried again only if the row stays open for another reason). On a
filesystem that reports no identity of its own (some Linux ones report only the device number; a
macOS volume may have no UUID) the filesystem part of the identity is zeros, and the check rests on
the inode with the exact device number, or on the inode alone where the directory is on the
filesystem of the directory it is in. There is one further limit: between the last check of the
directory's name and its removal, another process running as the same account could create an empty
directory with the same name, and that directory would be substituted for the one being removed. If
the directory was created but its identity was never recorded, it will only be removed if it is
empty. A dispatch always owns its row while it is running. If the daemon restarts while a dispatch
is running, or a dispatch exits without releasing its row, the sweep will close the session, remove
the node directory, end the hold, and release the row, without waiting for the run to end. A run
only holds a workspace once, even if multiple nodes are run in the same workspace. The hold ends
with the last of them. If a run pauses between nodes, it does not hold the workspace while paused.
If the session's closure does not account for the worker, the row is kept until the kernel says that
the worker's process has ended or the boot it ran in has (the row records the boot it began in). The
row also records the process the launcher started, which the daemon registry retains even after the
session has closed. The sweep looks again less and less often while a row stays owed. What the
worker could not account for stays outside the release: a process the command started that left the
session's boundary can outlive it, and where the platform gives incomplete coverage of owned
processes (always on macOS) the closure says so. The ledger is a store of its own beside the
journal, so a release that does not know it reads the journal as before.

The host carries out the change-set nodes against the environment's own change-set service. A
`capture_changeset` node's parameters are the `changeset.capture` method's own typed parameters,
and a `materialize_changeset` node's are `changeset.materialize`'s, so a node asks for exactly
what the method asks for and nothing is interpreted along the way. The version a capture produces
records the run that asked for it, whatever the document said, so evidence a later node reads is
bound to the execution that made it. The node's receipt carries the captured version, or the
version and the materialisation that holds it.

`request_review`, `attention_notice` and `apply_diff`, and the command kinds on a platform without a
POSIX shell, are refused by name. A refusal is not an uncertain outcome: nothing was dispatched and
nothing was made on the way to refusing it. Since no work is done, the node is failed, and any node
depending on it will see a failure rather than a result nobody produced.

A node that succeeds records its kind's typed output, and a runner that reports an output of
another kind has not reported this node's success: what its action did is not established, so the
node settles unknown, its receipt holds no output, and its dependants pause for review.

## Definitions and graph validation

A workflow definition is a versioned JSON document with an event trigger, resource scope,
typed action nodes, success and failure transition edges, run and action deadlines, and a grant reference.

Install-time validation enforces:
* **Graph acyclicity.** The node graph must be an acyclic directed graph (DAG).
* **Registered action kinds.** Every node names one of eight action kinds, and a document naming
  any other is refused when it is read.
* **Typed parameters.** Each node carries exactly its kind's own typed parameters: every field the
  type has, no field it does not, identifiers that are identifiers, and every name non-empty and
  within its bound. A kind whose parameters are a method's own is also held to every check that
  method makes on the request alone: a session geometry the terminal cannot open at, an apply
  with no workspace, a versioned reference with no expected value or a malformed name, a direct
  apply to a shared working tree that has not acknowledged each of that destination's
  limitations, or an atomic snapshot of a policy that includes uncommitted work is refused when
  it is installed. What the method checks against the host's live state, such as whether a
  version exists or a path is in it, is checked when the node runs. A `create_session` node
  carries no environment variables: its session takes this host's environment, and a stored
  definition would keep them. A journal an earlier build wrote comes forward without any it held.
* **Typed outputs.** Each kind produces one output type, named by the kind, and a receipt holds
  that output and nothing else: identifiers and states the host observed, never text a node, a
  terminal or a model produced.

| Kind | Parameters | Output |
| --- | --- | --- |
| `shell_command` | `command`, 1 to 16 KiB, run in this host's own environment, which the node declares | the session it ran in |
| `run_tests` | `suite`, 1 to 256 bytes, and the immutable `version` the result binds to | the suite and the version it passed against |
| `request_review` | the reviewer agent (`reviewer_id`), the immutable `version`, the `workspace` kind of the separate reviewer session, and the `instructions` | the version, the reviewer session and the turn that carried the result |
| `create_session` | `session.create`'s own parameters, naming this host's environment | the session |
| `attention_notice` | `summary`, 1 to 1024 bytes | none beyond its kind |
| `materialize_changeset` | `changeset.materialize`'s own parameters | the version and the materialisation that holds it |
| `apply_diff` | `diff.apply`'s own parameters | the version applied, its destination, the class it came to and any proposal version |
| `capture_changeset` | `changeset.capture`'s own parameters | the version captured |
* **No template evaluation.** Parameter values are inspected after JSON decoding, so a marker such
  as `{{ ... }}`, `${ ... }` or `$( ... )` is rejected however it was written. Nothing in a
  definition is evaluated.
* **Broad shell confinement.** A `shell_command` node is admitted only when it declares an
  execution environment and the definition's own grant is a broad shell grant, carrying terminal
  input, whose environment selector admits that environment. A definition that merely names a
  grant identifier is refused; the grant itself is checked.
* **Revision immutability.** The request and the document must name the same workflow, revision and
  grant. A revision number only moves forward, and an installed revision can never be replaced.

## Causal roots and budgets

Every session, action, and derived trigger created by a workflow keeps its causal identity: the
root, the depth and the parent. The host derives all three from its own journal, and a run is
the unit it derives them for. Nothing a caller sends names any of them.

* **A method trigger is an external root.** `workflow.run` carries no parent. Every run it starts
  is an external trigger with a causal root the host mints, so a caller can neither place a run
  inside a chain nor lift one out of it.
* **A derived trigger comes from the journal.** A node that succeeds commits, with its outcome, an
  event whose type its action kind fixes: `capture_changeset` produces `changeset.captured`,
  `materialize_changeset` produces `changeset.materialized`, `run_tests` produces `tests.passed`,
  `request_review` produces `review.completed`, `create_session` produces `session.created`,
  `shell_command` produces `command.completed` and `apply_diff` produces `diff.applied`. The host's
  trigger dispatcher starts a run of every enabled, unpaused workflow whose trigger names that
  type; a trigger matches on the event type and nothing else. The run's root, depth, budget
  generation and parent come from the journal's record of the run whose node produced the event,
  and the trigger's identifier is `node:` followed by that node's action identifier. A definition
  can mint neither an event type nor an event identifier, a replayed event is the same trigger and
  runs once, and an external trigger may not use an identifier beginning with `node:`, so a caller
  cannot take a derived trigger's place.
* **Descendant isolation.** A workflow cannot retrigger on its own descendants. Only a definition
  installed with explicit recurrence may, and even then the root stays the parent's: recurrence
  buys another turn in the chain, never a fresh budget.
* **Causal budget defaults.** Per causal root:
  * Maximum depth: 16
  * Maximum runs: 64
  * Maximum actions: 100
  * Maximum created sessions: 10
  * Maximum lifetime: one hour
* **Inherited ceilings.** A chain inherits from its host, when its root run is admitted, the most
  sessions the host admits, so its created-session ceiling is the lower of that and ten, and the
  managed allowance it may spend, which is none: this host gives a workflow no managed allowance
  and no action kind spends one. Its descendants are held to the root's record, so a ceiling the
  host raises later widens no chain already running, and a re-arm keeps the ceilings.
* **Reservation before dispatch.** Each run, action and created session is reserved against the
  chain's durable budget in one transaction with the refusal it may produce, so two concurrent
  dispatches cannot both take the last of an allowance.
* **Budget exhaustion.** Breaching any ceiling pauses the chain with error code `CAUSAL_LIMIT`,
  refuses every further descendant, and commits exactly one attention record in the same
  transaction as the pause. The record outlives a restart and is settled only once the host's
  attention state has written its own, so a chain that ran out owes one item however many
  refusals follow and whatever restarts intervene.
* **Re-arming.** Only an authorised re-arm establishes a new budget: one made under a grant this
  host holds as live, for this environment, with the right to manage automation, which no event
  carries. It advances the chain's generation and resets its counters without anybody raising a
  ceiling, and it continues the chain in the same transaction: every descendant the exhausted
  budget refused, which the journal kept with the refusal, is admitted once as a run of the same
  chain in the new generation, under its own workflow's grant and limits, and the record of it is
  spent whatever that admission decides. A descendant of a run from the previous generation that
  arrives afterwards carries that earlier generation and is refused as late, and a replay of a
  continued trigger is a duplicate.
* **External triggers.** A trigger with no verifiable causal parent, an unauthenticated callback
  among them, is a new external trigger: the host mints its root and host-wide admission bounds
  it. It can never adopt a causal root of its choosing. The host does not claim to recover
  causality another service lost: a workflow that reaches this host again through an outside
  service arrives as a new external trigger.

## Limits, deadlines and admission

Section 17's per-workflow limits and section 25's per-host and per-grant rates are decided from
the workflow journal, inside the transaction that records the run they admit, so a restart finds
each of them as it stood and two admissions that arrive together cannot both take the last place.

* **Four running, a hundred waiting.** A workflow runs at most four runs at once. A run admitted
  while four are running waits as pending, and the answer to `workflow.run` says so; the host's
  dispatcher starts the oldest pending run when a slot frees, and a paused or disabled revision
  starts none. A hundred-and-first pending run is a limit exceeded.
* **Rates.** At most 600 runs a minute are admitted host-wide and 120 a minute under one grant.
  The admissions they count are the journal's, so neither a restart nor a reopened service is a
  way past them, and an unauthenticated callback, which is a new external trigger, counts like
  any other.
* **Run deadline and action wait.** A definition may shorten section 17's 30-minute run deadline
  and ten-minute action wait, and may neither lengthen them nor set one to nothing. A run's
  deadline starts when the run starts running. The host waits for an action no longer than its
  wait or its run's deadline, whichever passes first, reading its clock at least every quarter
  second while it waits, and then asks the action to stop. A report it reads only once its clock
  has passed the wait is not taken, however the host got there. A kind that can be stopped
  settles cancelled, which says the host stopped asking and not that the world is as it was; a
  kind that cannot settles unknown. Neither change-set kind can be stopped once it has begun.
* **A limit stops the run.** When a run's deadline or an action's wait passes, the run dispatches
  nothing further. In one transaction, the action it outlived settles as above, every node still
  waiting that depends on an outcome that is not known pauses for review, every other node still
  waiting is cancelled, the run is cancelled, and the revision pauses with its attention item. A
  run the host finds unfinished, with an outcome not known or a node waiting for review, after its
  deadline has passed is stopped the same way, which is what a restart finds when a run was
  interrupted and its deadline went by; a run whose every node settled finished its work.
* **The host's clock.** Deadlines, waits and a chain's lifetime are measured on automation's
  reading of UTC. It starts from the daemon's own reading, the later of the wall clock and its
  clock floor, and then follows the wall clock while that keeps pace with the suspend-aware
  continuous clock, ordinary drift and suspensions included. A wall clock set back is not followed
  down: the reading runs on at all but a thousandth of continuous time, closing on the wall clock
  by a millisecond a second. It never moves backwards, and a clock set back holds a deadline back
  by at most a thousandth of the time it runs. It does not read the clock floor after it starts,
  so the grant decisions its readings feed into the floor are not read back as time passing.

A limit exceeded, whether a full queue, a rate, a run deadline or an action's wait, pauses the
workflow revision and records one attention item, in one transaction, so the workflow stops
rather than being refused one request at a time. Enabling the revision again is what clears the
pause. A revision is installed disabled: `workflow.enable` is what makes it runnable, and
`workflow.pause` stops it.

## Durability, execution, and restart

The workflow journal is an environment SQLite store in the environment's state directory, beside
the daemon's registry, because a causal budget has to survive a reboot as well as a restart.
* **Transactional commitment.** A trigger, its run, its deduplication key, its node receipts and
  the chain's budget reservation commit in one transaction before any node dispatches. A
  refusal commits its own consequences the same way: the chain's pause and the one attention
  record it owes land together, as do a workflow's pause and its record.
* **Deduplication.** Triggers are deduplicated by `(workflow_id, definition_revision, event_id)`.
* **Authoritative outcomes.** A dependency runs only when the predecessor outcome is authoritative.
* **Unknown outcomes pause.** A node whose outcome the host cannot establish, including one whose
  action was dispatched and never reported back, is recorded as unknown, and its dependants pause
  for review. No edge fires from it, not even a failure edge: the host does not know there was a
  failure. A process exit code does not prove downstream success.
* **Restart safety.** A node's recorded status is what decides whether it runs, so a node that
  already settled is never dispatched a second time. When the daemon starts, it recovers the
  journal before it serves anything: a node that was running when the host stopped may have been
  dispatched, so it is settled as unknown and its dependants pause for review, and the runs the
  journal holds as running are marked to resume; a run that was waiting for a slot waits on.
  Nothing executes yet. The resumed
  runs and the pending triggers run only once the daemon's start has passed every gate it has,
  the configuration it puts into force among them, whose withdrawal of authority may owe a fence
  that has to be up first; a start that fails executes nothing. Only nodes that were never
  dispatched go on, each after its grant is read again. Causal budgets, run records, node
  receipts, pending triggers and the dispatcher's own position are all the journal's and come
  back as they were left. Every dispatcher pass after that does the same for a run whose
  execution in this daemon ended without settling it, a journal write that failed part way among
  them, so no run holds one of its workflow's places while nothing executes it. A run under way is
  held by its execution from inside the transaction that made it running, so it is never taken
  up twice.
* **Cancellation.** Cancelling a run stops undispatched nodes: the journal, not a snapshot taken
  when the run started, decides whether a node still has anything owed to it, so a cancellation
  that arrives while an earlier node is running still stops the next one. Cancellation is
  terminal: an action that reports back after its node was cancelled does not settle the node,
  and a run that was cancelled is never recorded as completed. An active action is asked to stop
  when it outlives its wait or its run's deadline. Nothing is claimed about an external side
  effect an already dispatched action may have had.

## The event stream and its consumers

The journal commits a small event with every transition a consumer outside it has to know about, in
the same transaction as the transition: an accepted trigger and the run it started, a node's settled
outcome, a run's stop (completed, failed, paused or cancelled), an exhausted chain, and a workflow
paused by one of its own limits or enabled again. Every event carries an envelope: the subsystem it
comes from (`automation`), the verified actor whose action caused it or `host` for the host's own
transitions, and its content class (`identifiers`). Inside, it carries the identifiers a consumer
needs, the run's causal root, generation, depth and parent, and nothing a node produced: no output,
no terminal text.

The contract with every consumer:

* **What a consumer reads.** Events of the types it registered for, in the order of their
  position in the stream. An event is never rewritten, and its position never changes. Positions
  only increase and are not dense: every type shares one stream, so the events other consumers
  read sit between the ones a consumer registered for. A consumer keeps the last position it read
  and never takes the next event's position to be one more.
* **How it records where it is.** A consumer acts on an event and then records its position. A
  consumer whose effects are in the same journal, the trigger dispatcher among them, commits its
  effect and its new position in one transaction; a pass that stops at one event keeps the runs it
  committed for the events before it, and the event it stopped at is read again. A consumer with a store of its own keeps its own
  cursor there, keyed by the event's position, so a redelivery changes nothing, and acknowledges to
  the journal once its own state is written.
* **When an event may be removed.** Only once every consumer registered for its type has
  acknowledged a position at or past it. An event of a type no consumer is registered for is never
  removed.

The attention records wait in the stream under that rule. The environment's attention state is the
consumer they are for; until it registers, nothing removes them. The attention state treats a jump
in a source's sequence as records that retention removed, so before each record the attention
consumer tells it that the source stands just before that record: the positions between are the
events it read past, not missing history. An attention state that is behind even the last
position the consumer read has lost records delivered to it, and records that gap itself. `workflow.read` shows each
revision's pause and lists the alerts no attention state has taken, for the workflows and chains the
read covers, newest 256 at most.

## Test runs and the evidence they leave

A test result is what this host observed, and nothing a caller reports.

* **A suite is the owner's command.** A `run_tests` node names a suite and the immutable version it
  runs against. Note that the actual command to run the suite is not in the node; it is always the
  one the host's configuration (`automation.test_suites`) gives the suite. This configuration is
  read once, when the node dispatches, from the document as the daemon last accepted it. If the
  suite is not named in the configuration, or the configuration is one the host cannot use, the node
  fails before anything is made.
* **A private copy of exactly that version.** The host writes the version into a directory of its
  own, under an identifier its ledger row already names, so a stop at any point leaves something the
  sweep finds from the row. The command runs in that copy as the root of a session, as a
  `shell_command` node's does. An edit a person makes in the main workspace after the capture
  changes nothing the suite reads; it is a later version, and the evidence stays against the earlier
  one.
* **What is recorded.** When the session has closed after a suite ran to an end of its own (it
  exited with a status, or a signal ended it), the host will read the copy back and record the
  result against the version. The exit status will be recorded; a signal is a suite something
  stopped, with no status, and its detail and the line of evidence name the signal. The times the
  suite began and ended, the session, workflow run and node it observed, and the digest of the
  command the suite's configuration gave (never the command) will also be recorded. One line of
  evidence says how the suite ended and whether the copy still held the version. A suite that never
  started, or that a stop of its node or of its session ended, has no result to record, and the
  node's answer says how its session closed. The node succeeds only when the suite exited with
  status zero and the copy still holds exactly the version. If the suite exited with a non-zero exit
  status or was stopped by a signal, the node will fail. If the suite exited with status zero
  against a copy that was changed, or that cannot be read back, it attests no version, so the node
  is left unknown. When the copy was changed, what it held is stored as a version of its own, which
  is a reading and not an attestation, up to the bounds of a capture. When the copy cannot be read
  back, or something wrote into it after the session closed, no version is stored (the files a
  reading did store stay in the content store). The host will read the copy when creating the copy
  and when recording the result of the suite, but will not monitor the copy while the suite is
  running.
* **Declared outputs.** A suite may declare paths it intends to write, other than its source, such
  as a build directory. These paths are not compared, and are recorded in one reference each. A
  directory is recorded as the digest of its sorted listing (the path, length and instant written of
  every entry, links listed and not followed), with the sum of the lengths it lists. The listing
  holds up to 50,000 entries, 64 levels and 16 MiB of path text; beyond this it is a truncated
  listing. A file is recorded as the digest of its first 64 MiB and its whole length. A symbolic
  link or other non-file, non-directory object is recorded as such. If a directory in an output is a
  link, a mount, or has a name this host does not carry, it is an entry of the listing and is not
  entered. Nothing in an output enters the content store. A result that attests the version names
  the output paths it left out of the comparison. A path the suite adds beside an output still
  changes the source, so a tool that writes beside each source directory (a compiled-code cache is
  the usual one) makes each run of that suite unknown and stores what it wrote as a version of its
  own. An output path must be exactly specified; it is not possible to use a pattern. An ancestor of
  an output is entered only to reach it. Declarations that repeat, lie inside one another or
  contradict a path the version holds are refused before the suite runs. So is a declaration with a
  name this host does not carry as input (a colon, one of `< > " | ? *`, a trailing dot or space, a
  name a Windows device has with or without an extension, a name over 255 bytes), which the
  configuration accepts and every dispatch of that suite then refuses.
* **The copy's release.** A copy is taken away when its node settles, and by the sweep for a node
  that did not release it. The owner's right to change each of the copy's directories is given back
  first, so a tree a run left read-only does not hold the version, and each level is removed through
  its own handle, without following a link and without leaving the mount the copy is on. Only this
  host's own directories change, and only those on the copy's own mount. A copy that holds something
  the removal cannot take away is not removed and goes on holding its version: a mount (of another
  filesystem, or a bind mount of the same one), a volume on another device that is no mount (a btrfs
  subvolume), a tree deeper than 128 levels, a directory below the root that its owner cannot read,
  a directory that another account owns and this account cannot empty (a container that ran as root
  leaves these), on Linux a root its owner cannot search where `/proc` is not mounted, or on macOS
  an entry with the immutable or append-only flag set or one that an access-control entry forbids
  this account to delete. The sweep keeps trying, its log names why, and a person removes what the
  suite left.
* **Reviews.** A reviewer session and the attention items for review results are refused by name
  (`request_review`, `attention_notice`); no caller can register a test or review result.

## Captures of a working tree

When a run captures a change-set, the version of that change-set is bound to the run by the host,
not by what a caller said: the provenance a capture records names the run that asked for it. A
capture of the working tree a workflow runs asks the host to hold its workspace still, and the host
refuses, naming why: a shared existing checkout is written by the user's own tools, a workspace live
sessions hold is written by their shells, and this host's own writers do not yet ask for a
reservation before they write. The capture records the per-file consistency it performs and never
claims a quiesced tree. If the workflow includes a capture node that requires a quiesced capture,
the node fails with the reason. An atomic snapshot, which reads the base commit's own Git objects
rather than the working tree, is a point-in-time capture and needs no reservation.
