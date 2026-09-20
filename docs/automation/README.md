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
* **Registered action kinds.** Action nodes must reference registered action types (`shell_command`,
  `run_tests`, `request_review`, `notify`).
* **No template evaluation.** Arbitrary template code or dynamic parameter interpolation syntax
  such as `{{ ... }}` or `${ ... }` is rejected.
* **Broad shell confinement.** A `shell_command` action node is admitted only when the definition
  explicitly references a broad shell grant and a declared execution environment.

## Causal roots and budgets

Every session, action, and derived trigger created by a workflow preserves its host-verified causal
identity: `root_id`, `depth`, and `causal_parent`.

* **Descendant isolation.** A workflow cannot retrigger on its own descendants by default.
* **Recurrence preservation.** Explicit recurrence cannot reset the root budget by altering
  workflow identifiers or minting fresh event identifiers.
* **Causal budget defaults.** Per causal root:
  * Maximum depth: 16
  * Maximum runs: 64
  * Maximum actions: 100
  * Maximum created sessions: 10
  * Maximum lifetime: 1 hour (3600 seconds)
* **Budget exhaustion.** Breaching any limit pauses the causal chain atomically with error
  code `CAUSAL_LIMIT`, rejects further descendant dispatches, and emits exactly one attention item
  via the attention engine (`kr_attention`).
* **Re-arming.** Only an authorized re-arm command creates a new budget. Replayed or late events
  cannot revive an exhausted budget.
* **External triggers.** Unauthenticated callbacks are treated as new external triggers under host-wide
  limits and can never adopt an arbitrary causal root.

## Admission and concurrency

Admission limits govern runs before execution begins:
* **Per-workflow concurrency.** Defaults to 4 concurrent runs and 100 pending runs per definition.
* **Per-host rate limiting.** A sliding-window rate limit enforces maximum workflow invocations host-wide.
* **Per-grant rate limiting.** Individual grants enforce separate sliding-window invocation quotas.

Breached limits pause the workflow and emit an attention notification.

## Durability, execution, and restart

The workflow journal is an environment SQLite store located under the runtime directory.
* **Transactional commitment.** Triggers, runs, and budget reservations are committed together
  with an outbox record in a single transaction before any node dispatches.
* **Deduplication.** Triggers are deduplicated by `(workflow_id, definition_revision, event_id)`.
* **Authoritative outcomes.** A dependency runs only when the predecessor outcome is authoritative.
* **Unknown outcomes pause.** If a node outcome is unknown, dependent nodes are paused for review
  rather than assumed successful. A process exit code does not prove downstream success.
* **Restart safety.** On restart, completed nodes are not re-executed; only undispatched, still-authorized
  nodes resume. Budgets and reservations survive daemon restarts and reboots.
* **Cancellation.** Cancelling a run stops undispatched nodes and signals active actions without
  assuming external side effects are undone.

## Source workflow and evidence binding

The source workflow coordinates agent completion, test execution, reviewer assignment, and attention items:
* **Immutable change-set binding.** Test and review runs bind to an immutable change-set version
  hash (`kr_changeset`). Subsequent working tree changes produce distinct versions and never alter
  existing evidence.
* **Quiescence reservations.** The workflow service coordinates enforceable quiescence reservations
  to prevent concurrent modifications while tests or reviews execute.
* **Separate identities.** Agent, test runner, and reviewer sessions use separate, explicit identities.
