# Automation reference

Workflows are versioned directed acyclic graphs of typed execution nodes executed on the host.
They react to verified event triggers, run under causal budgets, and observe per-workflow, per-host,
and per-grant admission limits.

## The six methods

| Method | What it does | Right |
| --- | --- | --- |
| `workflow.install` | Validates and stores a versioned workflow definition document | `automation.manage` |
| `workflow.enable` | Activates an installed workflow definition revision | `automation.manage` |
| `workflow.pause` | Pauses an enabled workflow definition revision | `automation.manage` |
| `workflow.run` | Explicitly triggers an execution run of an enabled workflow | `automation.manage` |
| `workflow.rearm` | Gives a causal chain whose budget ran out a new budget and continues it | `automation.manage` |
| `workflow.read` | Reads definitions and whether each revision is paused, runs, node receipts, a chain's remaining budget, and the alerts no attention state has taken | `automation.manage` |

The control daemon serves all six, to the owner on the local socket and to a paired device over
the network, and those are the only ingresses the method registry lists for them. They arrive
through the daemon's ordinary path on either door: a read is checked against current authority,
and a mutation carries an action window, is checked against the method registry and its rights,
and runs on a task a dropped connection cannot cancel part way through. A workflow belongs to the
environment rather than to a session, so a request that targets a session or a foreground
application is refused before anything is written.

A paired device acts under the grant it holds and no other. It may install a workflow only under
that grant, and only as a new workflow or a new revision of one that already acts under it; it may
enable, pause, run and read only the workflows that act under it, and re-arm only a chain whose
root run acts under it. Whether it may reach a revision
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
same transaction as its effect. `workflow.rearm` is the one mutation that keeps no such record: the
generation it names is its own key, and the chain's state is what answers a repeat of it (see
"Re-arming" below).

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
before its admission at the launch transition has passed, the node stops and no session is made.
Once it has passed, the node can no longer be stopped: a node whose wait or run deadline passes is
left unknown, and a node whose run is cancelled is recorded as cancelled. A request to stop that
comes before the worker's claim is still held against the claim, which is refused, so no program
will start and no session will be made. A session whose claim came before the request stays.

A `shell_command` node runs its command as the root of a new session. The worker runs the command
line with `/bin/sh -c` (without any login or other interactive startup), setting the `SHELL`
environment variable to the path of that interpreter. The command will be run in the workspace
specified by the scope of the definition, if it is named (a shared checkout only because the
definition named it); otherwise, a private directory will be created for the command node. The
workspace is opened the same way as for captures; if the tree has been moved, removed or replaced
since it was recorded in the project service, the tree is refused and the node pauses. Also, the
worker refuses a directory that is not there instead of running the command somewhere else. (The
directory is verified when the command is accepted; one swapped in the moments after that is not
detected.) The standard input of the command is the terminal of the session, so if the command reads
from it it will wait for a person or for the node's wait. The result of a command node depends on
how the process that was the root of its session exited as recorded by this host. If it exited with
status 0 the command is considered to have succeeded, but if it exited with any other status or was
terminated by a signal the command failed, and the failure records the exit status, or the signal
when the closure names one. If the worker is unable to launch the command at all the node will fail,
but if it's because the grant was withdrawn or has ended then the node (and its run) will be paused
instead (as it would if the grant was refused at any other point; a node of a kind that's refused by
name fails instead, as described below). A launch that may still have completed leaves the node
unknown. If the session is closed for any other reason (by a request, a crash, the loss of the
desktop or the host's shutdown) it says nothing reliable about the command, and the node is left
unknown; so is a node whose command exited with no exit status recorded. The session used to run the
command can be listed and attached to like any other; its summary will note that it's running a
command as its root, and its journal will record that word in a row of its own as well as recording
the summary in a form that can be read by the previous release so that if a host is rolled back to
that release it can read such sessions like any other. An update that closes sessions closes a
running command too. Commands are only offered on hosts that have a POSIX shell; attempting to
install a definition that contains one on a Windows host will result in the definition being
refused.

When a node reaches its wait or run deadline or its run is cancelled, the command's session is
closed and the node is settled as cancelled. This indicates that the host stopped asking and says
nothing about what the command did. A node whose dispatch had already ended when its wait or
deadline was found to have lapsed is left unknown instead, because there is nothing for the host to
ask to stop; a node whose run is cancelled is settled as cancelled in either case. A command node
owns some resources outside the journal (its session, its directory, the run's hold on its
workspace). These are recorded in its own ledger before any of them is made, and are released when
the node's session is closed and the session's closure accounts for its worker. A node's private
directory is made for it alone, and its identity is recorded in the node's ledger before the command
can start. The directory is removed only while it is still the object that was recorded, by the
removal the project uses for a directory it recorded. This checks that the directory's inode and the
filesystem it is on are the ones the handle that made it reported. The directory's device number may
differ from the recorded one only where it is on the filesystem of the directory it is in. The
removal opens the scratch root without following a link, and opens the directory beneath it through
that handle. The directory is made private again if the command loosened its mode (unpacking an
archive does), and it has to be one only this account can change. What is in it goes through handles
the removal holds, so that it stays on the directory's own mount and holds no more than 128 levels.
A tree the removal does not take (a mount inside it, one nested deeper than that, a directory in it
that its owner cannot write, one whose owner read bit the command removed, one with an
access-control list on macOS, entries still being written, a failure of the storage) stays where it
is after that attempt: the row is released and the daemon's log names the directory (the removal is
tried again only if the row stays open for another reason). On a filesystem that reports no identity
of its own (some Linux ones report only the device number; a macOS volume may have no UUID) the
filesystem part of the identity is zeros. In this case the check rests on the directory's inode
number with the exact device number, or on the inode number alone where the directory is on the
filesystem of the directory it is in. There is one further limit: between the point at which the
directory's name is last checked and the point at which the directory is removed, another process
running as the same account can create an empty directory with the same name, and that directory
will be removed instead. If the directory is created but its identity is not recorded for some
reason, it will only be removed if it is empty. A dispatch always owns its row while it is running.
If the daemon is restarted while a dispatch is running, or if a dispatch exits without releasing its
row, the daemon's sweeping procedure will close the dispatch's session, remove its node directory,
release the workspace hold, and release the row, without waiting for the run to end. A run only
holds a workspace once, even if multiple nodes are run in the same workspace. The hold ends with the
last of them. If a run pauses between nodes, it does not hold the workspace while it is paused,
unless the row of one of its command nodes in that workspace is still owed. When a session is
closed, if it does not account for the command node's worker, the node's row will be kept open until
the kernel indicates that the worker's process has ended or that the boot it ran in has ended. The
node's row records the boot it began in. The node's row also records the process the launcher
started, which the daemon's registry keeps after the session has closed. The daemon's sweeping
procedure will look again less and less often while a row stays owed. What the worker could not
account for stays outside the release: a process the command started that left the session's
boundary can outlive it, and where the platform gives incomplete coverage of owned processes (always
on macOS) the closure says so. The ledger is a store of its own beside the journal, so a release
that does not know it reads the journal as before.

The host carries out the change-set nodes against the environment's own change-set service. A
`capture_changeset` node's parameters are the `changeset.capture` method's own typed parameters,
and a `materialize_changeset` node's are `changeset.materialize`'s, so a node asks for exactly
what the method asks for and nothing is interpreted along the way. The version a capture produces
records the run that asked for it, whatever the document said, so evidence a later node reads is
bound to the execution that made it. The node's receipt carries the captured version, or the
version and the materialisation that holds it.

`request_review`, `attention_notice` and `apply_diff` are refused by name when a node of that kind
is dispatched. A refusal is not an uncertain outcome: nothing was dispatched and nothing was made on
the way to refusing it. Since no work is done, the node is failed, and any node depending on it will
see a failure rather than a result nobody produced. On a platform without a POSIX shell, a
definition with a node of a command kind (`shell_command` or `run_tests`) is refused when it is
installed, so none of its nodes runs.

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
* **Re-arming.** Only an authorised re-arm establishes a new budget, and `workflow.rearm` is that
  request. It names the chain by its causal root, the grant it is made under, and the budget
  generation it leaves, which `workflow.read` shows beside the chain's budget. The grant has to be
  one this host holds as live, for this environment, with the right to manage automation; no event
  carries one. A paired device names the grant it holds and reaches only a chain whose root run
  acts under that grant. Any other chain is answered as a root this host holds no budget for.
  A chain whose budget has not run out is refused, since nothing about it is stopped. The re-arm
  advances the chain's generation and resets its counters without anybody raising a ceiling, and
  it continues the chain in the same transaction: every descendant the exhausted budget refused,
  which the journal kept with the refusal, is admitted once as a run of the same chain in the new
  generation, under its own workflow's grant and limits, and the record of it is spent whatever
  that admission decides. The runs that start execute once the re-arm has committed. A daemon
  that stops between the two finds them running in the journal and takes them up when it starts.
  A descendant of a run from the previous generation that arrives afterwards carries that earlier
  generation and is refused as late, and a replay of a continued trigger is a duplicate.
* **A repeat of a re-arm.** The generation the request names is what tells a repeat from a second
  re-arm. The request that moves a chain from generation 0 to generation 1 is answered with
  generation 1. Sent again, because its reply was lost, it finds the chain on generation 1, is
  answered with that, and changes nothing, even if the chain has run out again in the meantime. A
  request that names any other generation is refused as a conflict. Nothing is stored for the
  request, so the journal's stored form is the one it had before the method existed.
* **What a re-arm does not do.** It continues the descendants the budget refused when the chain
  tried to admit them, which is how a chain that reached its depth or run ceiling goes on. A run
  stopped at a node, because the chain's action, session or spend allowance ran out when the node
  was to be dispatched, stays paused. Nothing resumes a paused run, so the re-arm gives that
  chain a new budget and does not restart the run; the chain goes on from a new external trigger.
  The attention item the exhausted chain raised also stays open after a re-arm until it is
  acknowledged, because ending it takes a journal event that the journal's stored form has no
  place for.
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
* **Run deadline and action wait.** A definition may shorten the 30-minute run deadline and
  10-minute action wait specified in Section 17, but may not lengthen them or set one to nothing. A
  run's deadline begins when the run starts running. While waiting for an action, the host waits
  until the earlier of the action's wait and the run's deadline has passed, reading its clock after
  each timer wait, with the timer set for at most a quarter of a second, and then asks the action to
  stop. If the host reads a report from the action only after its clock has passed the action's
  wait, for any reason, it does not take that report. An action the host can still stop settles
  cancelled, which says the host stopped asking and not that the world is as it was; one it cannot
  stop settles unknown. A change-set node cannot be stopped after it has begun. A `create_session`
  node cannot be stopped once its admission at the launch transition has passed, or, for a node
  that runs again after a restart, once the session its first attempt made has been handed back to
  it. A command, test or `create_session` node whose dispatch has ended cannot be stopped either.
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
  changes neither the version nor the copy of it; it is a later version, and the evidence stays
  against the earlier one.
* **What is recorded.** When the session has closed after a suite ran to an end of its own (it
  exited with a status, or a signal ended it), the host will read the copy back and record the
  result against the version, and then one line of evidence beside it. A result is recorded only by
  the dispatch that waits for the session: after a restart the sweep closes the session and releases
  the copy, and records none. If the result or its line of evidence cannot be recorded, the node is
  left unknown, whatever the suite's status; a result can be recorded without its line of evidence.
  The exit status will be recorded; a signal is a suite something stopped, with no status, and its
  detail and the line of evidence say that a signal ended it and name the signal when the closure
  does. The times the session was created and closed, the session, workflow run and node it
  observed, and the digest of the command the suite's configuration gave (never the command) will
  also be recorded. One line of evidence says how the suite ended and whether the copy still held
  the version. A suite that never started, or that a stop of its node or of its session ended, has
  no result to record. When the wait for its action or the run's deadline expires, the node settles
  as cancelled and its answer says that its action was asked to stop (a node whose dispatch had
  already ended when the wait was found to have lapsed is left unknown instead); when its run is
  cancelled, the node settles as cancelled with the reason "run cancelled by request"; when its
  session closes in any way but the suite's own end before the node is settled, the node's answer
  says how the session closed. A node settled as cancelled stays cancelled, whatever the suite does
  afterwards. The node succeeds only when the suite exited with status zero, the copy still holds
  exactly the version, and nothing outside the suite's declared outputs was written in the copy
  while the suite ran. If the suite exited with a non-zero exit status or was stopped by a signal,
  the node will fail, once the host has recorded what it observed. If the suite exited with status
  zero against a copy that was changed, that cannot be read back, that had something written in it
  and put back, or that this host could not bind to the run, it attests no version, so the node is
  left unknown. When the copy was changed and what it held can be read completely, within
  the bounds of a capture and the rules for what a version may hold, that is stored as a version of
  its own, which is a reading and not an attestation. When the copy cannot be read back, or a file
  outside the declared outputs that the reading found has a modification time in a later millisecond
  than the closure of the session, no version is stored (the files a reading did store stay in the
  content store); a change after the closure that leaves no such time, such as a deletion, cannot be
  told from a change the suite made.
* **The result is bound to its run.** Reading the copy when it is made and again when the suite has
  ended is not enough. A suite that changes a file, tests the change and puts the file back, bytes
  and modification time included, leaves a copy that reads as the version. So the host also
  records, after the copy is made and before the suite starts, what the platform says about the
  copy's own directory and about every file and directory beneath it: the kind of object, its
  device and inode, its length, the time it was last modified and the time its inode last changed.
  The change time is the one a run cannot put back. A write, a truncation, a rename, a change of
  mode and a change of time each move it to the moment they happen, and no call a process can make
  sets it to an earlier one. When the session has closed, the host records the same again. An
  entry that is added, gone or different means something was written while the suite ran, and then
  the result attests no version although the copy reads as the version. A file made and removed
  again counts, because it moves the change time of the directory it was in. Two checks make equal
  records mean what they say. The filesystem has to be one whose change times this host knows to be
  kept (ext2 to ext4, XFS, Btrfs, tmpfs, overlayfs, F2FS and ZFS on Linux; APFS and HFS+ on
  macOS), and on any other the result is indeterminate. And before the suite starts the host waits,
  for up to three seconds, until the filesystem's own clock has passed the newest change time it
  recorded, so that a change made in the same tick as the record still shows. The record is kept in
  the daemon's memory by the dispatch that waits for the session, so a daemon that stops while the
  suite runs records no result at all. A platform that keeps no such record has none, and a result
  there is indeterminate.
  The record shows that nothing in the copy was written while the suite ran. It does not show what
  the suite read, which can be anything on the machine. Nor does it show a write through a shared
  mapping that the platform has not yet recorded when the result is recorded, a write by a process
  that outlives the session, or a system clock set back by an account allowed to set it.
* **Declared outputs.** A suite may declare paths it intends to write, other than its source, such
  as a build directory. These paths are not compared, and each one the reading reaches is recorded
  in one reference; a reading that stops at a problem in the source records only the outputs before
  it, and a copy that cannot be opened records none. A directory is recorded as the digest of its
  sorted listing (the path, length and instant written of every entry, links listed and not
  followed), with the sum of the lengths it lists. The listing holds up to 50,000 entries, 64 levels
  and 16 MiB of path text; beyond this it is a truncated listing. A file is recorded as the digest
  of its first 64 MiB and its whole length. A symbolic link or other non-file, non-directory object
  is recorded as such, and an output that cannot be opened, or a file that cannot be read, is
  recorded as an unreadable output with the digest of no bytes; a directory that opens but cannot be
  listed, or an entry of a listing that cannot be read, is listed as an unreadable entry. If a
  directory in an output is a link, a mount, or has a name this host does not carry, it is an entry
  of the listing and is not entered. Nothing in an output enters the content store. A result that
  attests the version names the output paths it left out of the comparison. Before the suite
  starts, the host makes the directories above each declared output that the copy does not have,
  empty, so that writing the output changes no entry above the directory it is in. That directory,
  the output's parent, is the one place whose own record the host does not compare, because
  creating the output changes it, and a record cannot tell the output from a name written beside
  it. The host watches the parent by name instead, from before the suite starts to after it has
  ended. A name created, removed, renamed, written or changed there, other than a declared output,
  makes the result indeterminate however briefly it existed: a scratch file the suite made and
  removed again at the copy's root, beside an output called `target`, is such a name. On Linux the
  watcher is the kernel's inotify. On macOS it is FSEvents, which reports on its own schedule, so
  the host writes a file of its own beside the copy and waits, for up to ten seconds, until the
  watcher reports it, which means every report up to then has arrived. A watcher that cannot
  start, that lost reports or that does not answer in that time makes the result indeterminate,
  and so does a platform with no watcher whenever a suite declares an output. A suite that removes
  a directory above its declared output is writing outside the output. A file the suite adds
  beside an output is not left out of the comparison and changes the source (an added empty
  directory does not, unless the reading cannot open or list it, reaches a bound, or the change
  set's rules keep its path out, which makes the source indeterminate), so a tool that writes beside
  each source directory (a compiled-code cache is the usual one) makes a run of that suite that
  exits with status zero unknown and, where what the copy held can be read completely, stores what
  it wrote as a version of its own under the conditions given above. An output path must be exactly
  specified; it is not possible to use a pattern. An ancestor of an output is entered to reach it,
  and its other entries follow the normal rules for the source. Declarations that repeat, lie inside
  one another, or are or contain a path the version holds are refused before the suite runs. So is a
  declaration with a name this host does not carry as input (a colon, one of `< > " | ? *`, a
  trailing dot or space, a name a Windows device has with or without an extension, a name over 255
  bytes), which the configuration accepts and every dispatch of that suite then refuses. A
  declaration beneath a file of the version is accepted, but the directory above its output cannot
  be made, so the result of a suite that declares one is always indeterminate.
* **The copy's release.** A copy is taken away by the dispatch at once when no suite ran (the copy
  could not be written whole, or its session could not be made), and otherwise once the session has
  closed and its worker is accounted for; the sweep takes away any other copy. A node that settles
  first, such as one whose action wait expired, does not release its copy by settling. The owner's
  right to change each of the copy's directories is given back first, so a tree a run left read-only
  does not hold the version, and each level is removed through its own handle, without following a
  link and without leaving the mount the copy is on. Only this host's own directories change, and
  only those on the copy's own mount. A copy that holds something the removal cannot take away is
  not removed and goes on holding its version: a mount (of another filesystem, or a bind mount of
  the same one), a volume on another device that is no mount (a btrfs subvolume), a tree deeper than
  128 levels, a directory below the root that its owner cannot read, a directory that another
  account owns and this account cannot empty (a container that ran as root leaves these), on Linux a
  root its owner cannot search where `/proc` is not mounted, or on macOS an entry with the immutable
  or append-only flag set or one that an access-control entry forbids this account to delete. The
  sweep keeps trying, its log names why, and a person removes what the suite left.
* **Reviews.** A reviewer session and the attention items for review results are refused by name
  (`request_review`, `attention_notice`); no caller can register a test or review result.

## Captures of a working tree

When a run captures a change-set, the version of that change-set is bound to the run by the host,
not by what a caller said: the provenance a capture records names the run that asked for it. A
capture of the working tree a workflow runs asks the host to hold its workspace still. The host
grants that for an isolated workspace it made, when none of its own writers is at work in the
repository and no live session it started is in a tree it records for it, and then the version is
recorded as a quiesced capture, with a sentence that says which writers were kept off and that an
editor or program outside them was not. Everything else is captured file by file and recorded as
the per-file class, whose detail says that the workspace could not be reserved. If the workflow
includes a capture node that requires a quiesced capture, the node fails when the host cannot hold
the workspace, and its reason names which applies: a shared existing checkout is written by the
user's own tools, a live session is written by its shell, and a writer of this host that is at
work cannot be waited for. While the capture reads, a session, `diff.apply`, a workspace
operation or an agent-tool installation or removal that would write the repository is turned
away with `RESOURCE_UNAVAILABLE` and is not retried by the host; `docs/project/README.md` lists
them and what a reservation does not see. A node that meets that refusal while it starts a
session fails like any node whose session cannot start. An atomic snapshot, which reads the base
commit's own Git objects rather than the working tree, is a point-in-time capture and needs no
reservation.
