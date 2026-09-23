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
that grant, and it may enable, pause, run and read only the workflows that act under it; the
owner's workflows and another device's are neither its to change nor its to see. A workflow
therefore never gives a device a right its own grant does not carry. A paired device's grant is
read from its pairing record, so revoking the device stops every workflow under that grant, and a
grant whose expiry the host has recorded does not come back.

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
  the daemon whether the admission the mutation was accepted under still stands (the connection's
  registration, the authority revision it was admitted under and its accepted deadline),
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
* **Decided under the host's policy.** The grant is intersected with the host's policy as it
  stands: a revoked ancestor, the clock floor, redemption, expiry, an authority revision the host
  never issued, the organisation lease a grant requires and the bounded offline validity for a
  grant held by a paired device. The rights the policy leaves are the rights the node is checked
  against. Each of these decisions raises the clock floor and writes it down, as the host's other
  decisions do, so a clock wound back between two dispatches of an unattended workflow does not
  revive an expiry the host already refused. A grant that requires an organisation membership is
  refused here, because this path resolves no member account for its recipient.
* **Withdrawn is withdrawn.** A grant that has expired, has been revoked, has a revoked ancestor,
  or has never had its invitation redeemed admits no run. A withdrawal that lands between two
  nodes of a run stops the run where it stands: the node that has not been dispatched is paused,
  and nothing is claimed about the node that already ran.
* **Asked again where the effect begins.** The host's own action runner reads the grant once more
  inside the task that performs the effect, after the wait for that task. A refusal there pauses
  the node and its run exactly as a refusal a moment earlier would have, because no action was
  performed. The change-set service's own lock and preparation come after that last check, and
  that service takes no admission into its own transaction.
* **Each node needs the right its effect needs.** A `shell_command` or `run_tests` node needs
  `terminal.input`, `create_session` needs `session.create`, `request_review` needs
  `agent.prompt` and `session.view`, `capture_changeset` needs `changeset.create`,
  `materialize_changeset` needs `workspace.manage`, and `apply_diff` needs `files.apply_diff`.
  These are the rights the methods that perform the same effects require, so a workflow is not a
  way around the method a person would otherwise have called, and a view-only invitation cannot
  obtain terminal input through one.
* **Scope is checked too.** Every node's effect happens in the environment this host serves, so
  the grant has to cover that environment whether or not the definition names one, and a
  definition scoped to another environment runs nothing here. A definition scoped to a session is
  refused unless the grant covers it, and a shell node's declared execution environment has to be
  one the grant admits. A capture node has to name the workspace the definition is scoped to, and
  a materialisation is refused where it would begin unless the version it names can be read and
  was captured from the definition's workspace, when it names one, and from this environment.

## What a node actually does

The host carries out the change-set nodes against the environment's own change-set service. A
`capture_changeset` node's parameters are the `changeset.capture` method's own typed parameters,
and a `materialize_changeset` node's are `changeset.materialize`'s, so a node asks for exactly
what the method asks for and nothing is interpreted along the way. The version a capture produces
records the run that asked for it, whatever the document said, so evidence a later node reads is
bound to the execution that made it.

Every other registered action kind is refused by name. A refusal is not an uncertain outcome:
nothing was dispatched, so the node failed and its dependants see a failure rather than a result
nobody produced.

## Definitions and graph validation

A workflow definition is a versioned JSON document with an event trigger, resource scope,
typed action nodes, success and failure transition edges, run and action deadlines, and a grant reference.

Install-time validation enforces:
* **Graph acyclicity.** The node graph must be an acyclic directed graph (DAG).
* **Registered action kinds.** Action nodes must reference registered action types: `shell_command`,
  `run_tests`, `request_review`, `create_session`, `attention_notice`, `materialize_changeset`,
  `apply_diff` and `capture_changeset`.
* **Typed parameters.** Each node's parameters must parse as JSON and carry the fields its action
  kind declares.
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
* **Reservation before dispatch.** Each run, action and created session is reserved against the
  chain's durable budget in one transaction with the refusal it may produce, so two concurrent
  dispatches cannot both take the last of an allowance.
* **Budget exhaustion.** Breaching any ceiling pauses the chain with error code `CAUSAL_LIMIT`,
  refuses every further descendant, and commits exactly one attention record in the same
  transaction as the pause. The record outlives a restart and is settled only once the host's
  attention state has written its own, so a chain that ran out owes one item however many
  refusals follow and whatever restarts intervene.
* **Re-arming.** Only an authorised re-arm establishes a new budget. It advances the chain's
  generation and resets its counters without anybody raising a ceiling, and a descendant of a run
  from the previous generation carries that earlier generation and is refused as late.
* **External triggers.** A trigger with no verifiable causal parent, an unauthenticated callback
  among them, is a new external trigger: the host mints its root and host-wide admission bounds
  it. It can never adopt a causal root of its choosing. The host does not claim to recover
  causality another service lost: a workflow that reaches this host again through an outside
  service arrives as a new external trigger.

## Admission and concurrency

Admission limits govern runs before execution begins:
* **Per-workflow concurrency.** Defaults to 4 concurrent runs and 100 pending runs per definition.
* **Per-host rate limiting.** A sliding-window rate limit enforces maximum workflow invocations host-wide.
* **Per-grant rate limiting.** Individual grants enforce separate sliding-window invocation quotas.

A breached limit pauses the workflow revision and records one attention item, in one
transaction, so the workflow stops rather than being refused one request at a time. Enabling
the revision again is what clears the pause. A revision is installed disabled: `workflow.enable`
is what makes it runnable, and `workflow.pause` stops it.

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
  already settled is never dispatched a second time. When the daemon starts, it resumes the runs
  the journal holds as waiting or running. A node that was running when the host stopped may have
  been dispatched, so it is settled as unknown and its dependants pause for review; only nodes
  that were never dispatched go on, each after its grant is read again. Causal budgets, run
  records, node receipts, pending triggers and the dispatcher's own position are all the
  journal's and come back as they were left.
* **Cancellation.** Cancelling a run stops undispatched nodes: the journal, not a snapshot taken
  when the run started, decides whether a node still has anything owed to it, so a cancellation
  that arrives while an earlier node is running still stops the next one. Cancellation is
  terminal: an action that reports back after its node was cancelled does not settle the node,
  and a run that was cancelled is never recorded as completed. Nothing is claimed about an
  external side effect an already dispatched action may have had.

## The event stream and its consumers

The journal commits a small event with every transition that matters outside it, in the same
transaction as the transition: an accepted trigger and the run it started, a node's settled
outcome, a run's stop (completed, failed, paused or cancelled), an exhausted chain, and a workflow
paused by one of its own limits or enabled again. Every event carries an envelope: the subsystem
it comes from (`automation`), the verified actor whose action caused it or `host` for the host's
own transitions, and its content class (`identifiers`). Inside, it carries the identifiers a
consumer needs, the run's causal root, generation, depth and parent, and nothing a node produced:
no output, no terminal text.

The contract with every consumer:

* **What a consumer reads.** Events of the types it registered for, in the order of their
  position in the stream. An event is never rewritten, and its position never changes.
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
consumer they are for; until it registers, nothing removes them. `workflow.read` shows each
revision's pause and lists the alerts no attention state has taken, for the workflows and chains the
read covers, newest 256 at most.

## Source workflow and evidence binding

The source workflow registers what a run reported against the exact version it was given:
* **Immutable change-set binding.** A test result and a review result are recorded against one
  immutable change-set version (`kr_changeset`). A later edit in the workspace produces a later
  version; it never changes evidence already recorded against an earlier one.
* **Quiescence reservations.** A workspace can be reserved for the length of a capture, and a
  second reservation on the same workspace is refused until the first is released or expires.
* **Separate identities.** The agent, the test run and the reviewer each carry their own session
  and agent identity, and a review is recorded against the reviewer who gave it.

A change-set version a run captured is bound to that run by the host, not by what the caller
said: the provenance a capture records names the run that asked for it. A test result and a
review result registered through the coordinator are still the caller's account of what happened,
and binding those to the execution that produced them is the remaining half of this.
