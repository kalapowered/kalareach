# Automation reference

Workflows are versioned directed acyclic graphs of typed execution nodes executed on the host.
They react to verified event triggers, run under causal budgets, and observe per-workflow, per-host,
and per-grant admission limits.

## The five methods

| Method | What it does | Authority |
| --- | --- | --- |
| `workflow.install` | Validates and stores a versioned workflow definition document | `workflow.manage` |
| `workflow.enable` | Activates an installed workflow definition revision | `workflow.manage` |
| `workflow.pause` | Pauses an enabled workflow definition revision | `workflow.manage` |
| `workflow.run` | Explicitly triggers an execution run of an enabled workflow | `workflow.manage` |
| `workflow.read` | Reads workflow definitions, revision states, runs, and budgets | `workflow.read` |

All mutation methods require an explicit workflow-management grant and the exact definition revision.
Every method has an exhaustive authority entry in `kr_protocol::method::REGISTRY`.

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

Every session, action, and derived trigger created by a workflow keeps its host-verified causal
identity: the root, the depth and the parent.

* **The host derives the ancestry.** A request names a parent run and a parent node, and nothing
  else. The host reads the root, the depth and the budget generation from its own journal, so
  event content cannot mint a root, claim a depth or place a trigger in a chain it did not earn.
  A parent run this host never recorded, a parent node with no receipt, and a claimed root that
  is not the parent's are each refused.
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
  refuses every further descendant, and commits exactly one attention record. The record is
  delivered to the attention engine (`kr_attention`) and settled there, so a chain that ran out
  raises one item however many refusals follow and whatever restarts intervene.
* **Re-arming.** Only an authorised re-arm establishes a new budget. It advances the chain's
  generation and resets its counters, so the same ceilings become usable again without anybody
  raising them, and a descendant of a run from the previous generation is refused as late.
* **External triggers.** A trigger with no verifiable causal parent, an unauthenticated callback
  among them, is a new external trigger: the host mints its root and host-wide admission bounds
  it. It can never adopt a causal root of its choosing.

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

The workflow journal is an environment SQLite store located under the runtime directory.
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
  already settled is never dispatched a second time. Causal budgets, run records, node receipts
  and undelivered attention records are all the journal's and come back as they were left.
* **Cancellation.** Cancelling a run stops undispatched nodes: the journal, not a snapshot taken
  when the run started, decides whether a node still has anything owed to it, so a cancellation
  that arrives while an earlier node is running still stops the next one. Nothing is claimed about
  an external side effect an already dispatched action may have had.
* **Attention delivery.** Attention records are committed with the pause that caused them and
  settled only after the host's attention state has written its own. Each record is delivered
  under its own journal row number, so a redelivery after an interrupted settle replays a
  sequence the attention state has already consumed and changes nothing.

## Source workflow and evidence binding

The source workflow registers what a run reported against the exact version it was given:
* **Immutable change-set binding.** A test result and a review result are recorded against one
  immutable change-set version (`kr_changeset`). A later edit in the workspace produces a later
  version; it never changes evidence already recorded against an earlier one.
* **Quiescence reservations.** A workspace can be reserved for the length of a capture, and a
  second reservation on the same workspace is refused until the first is released or expires.
* **Separate identities.** The agent, the test run and the reviewer each carry their own session
  and agent identity, and a review is recorded against the reviewer who gave it.

The version, the session and the outcome come from the caller. Tying them to the execution that
produced them, so that a result cannot be registered against a version the run never read, needs
the host execution path and is not yet in place.
