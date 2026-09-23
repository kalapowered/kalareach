//! Automation definitions, workflow runs, node receipts, and causal budget wire types.
//!
//! Section 25 defines automation workflows as versioned JSON documents with an event trigger,
//! resource scope, typed action nodes, success/failure edges, deadlines, and an explicit grant
//! reference.
//!
//! Five principles shape every type here:
//!
//! * **Definitions are versioned, acyclic, and grant-bound.** Every workflow references an
//!   explicit grant and revision. Cycles are rejected at install time. Nodes reference registered
//!   action kinds and typed outputs; no arbitrary template code is permitted.
//! * **Causal chains are bounded and tracked.** Every workflow-created session, action, and derived
//!   trigger retains the host-verified causal root, depth, and parent. Causal budgets enforce
//!   hard limits (depth 16, 64 runs, 100 actions, 10 sessions, 1h lifetime) across all participating
//!   workflows, surviving controller restarts.
//! * **Triggers are deduplicated.** Runs are persisted before first node dispatch, and deduplicated
//!   by `(workflow_id, definition_revision, event_id)`.
//! * **Dependencies require authoritative outcomes.** A node executes only after predecessor
//!   outcomes are authoritative. An unknown outcome pauses dependent nodes for review.
//! * **Authority and method dispatch are explicit.** Methods in the `Automation` group require
//!   the `automation.manage` grant and the exact definition revision.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ids::{
    ActionId, CausalRootId, EnvironmentId, GrantId, SessionId, WorkflowId, WorkflowRunId,
    WorkspaceId,
};
use crate::scalars::{Nullable, TimestampMs, U64};

/// Default maximum causal chain depth.
pub const DEFAULT_CAUSAL_DEPTH_LIMIT: u64 = 16;
/// Default maximum total runs per causal root.
pub const DEFAULT_CAUSAL_RUNS_LIMIT: u64 = 64;
/// Default maximum total actions per causal root.
pub const DEFAULT_CAUSAL_ACTIONS_LIMIT: u64 = 100;
/// Default maximum sessions created per causal root.
pub const DEFAULT_CAUSAL_SESSIONS_LIMIT: u64 = 10;
/// Default maximum elapsed lifetime per causal root (1 hour in milliseconds).
pub const DEFAULT_CAUSAL_LIFETIME_MS: u64 = 3_600_000;

/// Default maximum concurrent runs per workflow.
pub const DEFAULT_WORKFLOW_CONCURRENT_RUNS: u64 = 4;
/// Default maximum pending runs per workflow.
pub const DEFAULT_WORKFLOW_PENDING_RUNS: u64 = 100;
/// Default run deadline per workflow (30 minutes in milliseconds).
pub const DEFAULT_WORKFLOW_RUN_DEADLINE_MS: u64 = 1_800_000;
/// Default maximum wait time per action node (10 minutes in milliseconds).
pub const DEFAULT_WORKFLOW_ACTION_WAIT_MS: u64 = 600_000;

macro_rules! wire_enum {
    ($(#[doc = $doc:literal])* $name:ident { $($variant:ident => $wire:literal, $variant_doc:literal;)+ }) => {
        $(#[doc = $doc])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
        pub enum $name {
            $(
                #[doc = $variant_doc]
                #[serde(rename = $wire)]
                $variant,
            )+
        }

        impl $name {
            /// All variants in declaration order.
            pub const ALL: &'static [Self] = &[$(Self::$variant,)+];

            /// Returns the wire representation.
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $wire,)+
                }
            }

            /// Parses from wire representation.
            #[must_use]
            pub fn from_wire(value: &str) -> Option<Self> {
                match value {
                    $($wire => Some(Self::$variant),)+
                    _ => None,
                }
            }
        }

        impl core::fmt::Display for $name {
            fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                formatter.write_str(self.as_str())
            }
        }
    };
}

wire_enum! {
    /// Condition required on an edge for traversal.
    EdgeCondition {
        Success => "success", "Traverse when the source node succeeded.";
        Failure => "failure", "Traverse when the source node failed.";
        Always => "always", "Traverse regardless of source node outcome.";
    }
}

wire_enum! {
    /// Status of a workflow run.
    WorkflowRunStatus {
        Pending => "pending", "Queued and waiting for execution.";
        Running => "running", "Currently executing action nodes.";
        Completed => "completed", "All reachable nodes finished successfully.";
        Failed => "failed", "One or more nodes failed without recovery.";
        Paused => "paused", "Paused by user or limit breach.";
        Cancelled => "cancelled", "Cancelled by user request.";
    }
}

wire_enum! {
    /// Execution status of a single workflow action node.
    NodeStatus {
        Pending => "pending", "Waiting for dependencies to complete.";
        Running => "running", "Currently executing.";
        Success => "success", "Completed successfully with authoritative outcome.";
        Failed => "failed", "Completed with failure.";
        Unknown => "unknown", "Outcome could not be established; paused for review.";
        Paused => "paused", "Paused for review or budget exhaustion.";
        Cancelled => "cancelled", "Cancelled before execution or during execution.";
    }
}

/// An event trigger definition for a workflow.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkflowTrigger {
    /// The event type that triggers the workflow (e.g., "turn_completed", "changeset_captured").
    pub event_type: String,
    /// Optional criteria or filter for the triggering event.
    pub criteria: Nullable<String>,
}

/// Resource scope binding for a workflow.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkflowResourceScope {
    /// Environment scope, if constrained.
    pub environment_id: Nullable<EnvironmentId>,
    /// Workspace scope, if constrained.
    pub workspace_id: Nullable<WorkspaceId>,
    /// Session scope, if constrained.
    pub session_id: Nullable<SessionId>,
}

impl Default for WorkflowResourceScope {
    fn default() -> Self {
        Self {
            environment_id: Nullable::null(),
            workspace_id: Nullable::null(),
            session_id: Nullable::null(),
        }
    }
}

/// A single action node in a workflow graph.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkflowNode {
    /// Unique identifier for this node within the workflow definition.
    pub node_id: String,
    /// Registered action kind (e.g., "shell_command", "run_tests", "request_review").
    pub action_kind: String,
    /// Typed action parameters JSON string without template code.
    pub action_params: String,
    /// Declared execution environment required for shell commands.
    pub declared_environment: Nullable<EnvironmentId>,
}

/// A directed edge connecting two action nodes in a workflow graph.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkflowEdge {
    /// Source node identifier.
    pub from_node: String,
    /// Destination node identifier.
    pub to_node: String,
    /// Condition required to follow this edge.
    pub condition: EdgeCondition,
}

/// Operational deadlines configured for a workflow.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkflowDeadlines {
    /// Maximum run lifetime in milliseconds before timeout.
    pub run_deadline_ms: U64,
    /// Maximum time in milliseconds to wait for a single action outcome.
    pub action_wait_ms: U64,
}

impl Default for WorkflowDeadlines {
    fn default() -> Self {
        Self {
            run_deadline_ms: U64::new(DEFAULT_WORKFLOW_RUN_DEADLINE_MS),
            action_wait_ms: U64::new(DEFAULT_WORKFLOW_ACTION_WAIT_MS),
        }
    }
}

/// Complete versioned workflow definition document.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkflowDefinition {
    /// Unique workflow identifier.
    pub workflow_id: WorkflowId,
    /// Revision counter of this definition.
    pub revision: U64,
    /// Human-readable name.
    pub name: String,
    /// Optional description.
    pub description: Nullable<String>,
    /// Trigger configuration.
    pub trigger: WorkflowTrigger,
    /// Resource scope.
    pub resource_scope: WorkflowResourceScope,
    /// Graph nodes.
    pub nodes: Vec<WorkflowNode>,
    /// Graph edges.
    pub edges: Vec<WorkflowEdge>,
    /// Deadlines.
    pub deadlines: WorkflowDeadlines,
    /// Explicit grant reference required to run this workflow.
    pub grant_reference: GrantId,
    /// Whether this workflow is enabled to process triggers.
    pub enabled: bool,
    /// Whether explicit recurrence is allowed under the reviewed definition (default: false).
    #[serde(default)]
    pub explicit_recurrence: bool,
}

/// Summary of a causal budget and its consumption.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CausalBudgetSummary {
    /// Causal root identifier.
    pub causal_root_id: CausalRootId,
    /// Current depth reached.
    pub depth: U64,
    /// Maximum allowed depth.
    pub max_depth: U64,
    /// Total runs executed under this root.
    pub total_runs: U64,
    /// Maximum allowed runs.
    pub max_runs: U64,
    /// Total action nodes executed.
    pub total_actions: U64,
    /// Maximum allowed action nodes.
    pub max_actions: U64,
    /// Total sessions created.
    pub created_sessions: U64,
    /// Maximum allowed sessions created.
    pub max_sessions: U64,
    /// Elapsed lifetime in milliseconds.
    pub elapsed_lifetime_ms: U64,
    /// Maximum allowed lifetime in milliseconds.
    pub max_lifetime_ms: U64,
    /// Whether the chain is paused due to limit exhaustion.
    pub paused: bool,
    /// Whether any limit was exhausted.
    pub exhausted: bool,
}

/// Summary of an installed workflow definition.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkflowDefinitionSummary {
    /// Workflow identifier.
    pub workflow_id: WorkflowId,
    /// Revision of the definition.
    pub revision: U64,
    /// Human-readable name.
    pub name: String,
    /// Optional description.
    pub description: Nullable<String>,
    /// Grant reference.
    pub grant_reference: GrantId,
    /// Whether enabled.
    pub enabled: bool,
    /// When installed.
    pub installed_at_ms: TimestampMs,
}

/// Summary of a workflow run.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkflowRunSummary {
    /// Run identifier.
    pub run_id: WorkflowRunId,
    /// Workflow identifier.
    pub workflow_id: WorkflowId,
    /// Definition revision executed.
    pub revision: U64,
    /// Causal root identifier.
    pub causal_root_id: CausalRootId,
    /// Depth in causal chain.
    pub depth: U64,
    /// Current status.
    pub status: WorkflowRunStatus,
    /// The run whose node triggered this one, as this host recorded it, when this run descends
    /// from another. Absent for a run an external trigger started.
    pub parent_run_id: Nullable<WorkflowRunId>,
    /// The node of that run whose outcome triggered this one.
    pub parent_node_id: Nullable<String>,
    /// Trigger event identifier.
    pub trigger_event_id: String,
    /// When execution began.
    pub started_at_ms: TimestampMs,
    /// When execution finished, if terminated.
    pub ended_at_ms: Nullable<TimestampMs>,
}

/// Summary receipt of an executed action node.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NodeReceiptSummary {
    /// Workflow run identifier.
    pub run_id: WorkflowRunId,
    /// Node identifier within the workflow.
    pub node_id: String,
    /// Action identifier assigned to this execution.
    pub action_id: ActionId,
    /// Causal parent description.
    pub causal_parent: Nullable<String>,
    /// Node execution status.
    pub status: NodeStatus,
    /// Output result string, if available.
    pub output: Nullable<String>,
    /// When execution started.
    pub started_at_ms: TimestampMs,
    /// When execution finished.
    pub ended_at_ms: Nullable<TimestampMs>,
}

// -------------------------------------------------------------------------------------------------
// Method Parameters and Results
// -------------------------------------------------------------------------------------------------

/// Parameters for `workflow.install`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkflowInstallParams {
    /// Workflow identifier to install or update.
    pub workflow_id: WorkflowId,
    /// Expected new revision.
    pub revision: U64,
    /// Full definition document.
    pub definition: WorkflowDefinition,
    /// Explicit grant reference.
    pub grant_reference: GrantId,
}

/// Result of `workflow.install`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkflowInstallResult {
    /// Installed workflow identifier.
    pub workflow_id: WorkflowId,
    /// Installed revision.
    pub revision: U64,
    /// Timestamp when installed.
    pub installed_at_ms: TimestampMs,
}

/// Parameters for `workflow.enable`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkflowEnableParams {
    /// Workflow identifier.
    pub workflow_id: WorkflowId,
    /// Revision to enable.
    pub revision: U64,
}

/// Result of `workflow.enable`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkflowEnableResult {
    /// Workflow identifier.
    pub workflow_id: WorkflowId,
    /// Revision enabled.
    pub revision: U64,
    /// True when enabled.
    pub enabled: bool,
}

/// Parameters for `workflow.pause`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkflowPauseParams {
    /// Workflow identifier.
    pub workflow_id: WorkflowId,
    /// Revision to pause.
    pub revision: U64,
    /// Optional reason for pausing.
    pub reason: Nullable<String>,
}

/// Result of `workflow.pause`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkflowPauseResult {
    /// Workflow identifier.
    pub workflow_id: WorkflowId,
    /// Revision paused.
    pub revision: U64,
    /// True when paused.
    pub paused: bool,
}

/// Parameters for `workflow.run`.
///
/// A run started through this method is an external trigger, and the host mints its causal root.
/// Nothing here can name a parent: a trigger that descends from a workflow's own node is started
/// by the host itself, which records the node it came from, so a caller can neither place a run
/// inside a chain nor lift one out of it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkflowRunParams {
    /// Workflow identifier to run.
    pub workflow_id: WorkflowId,
    /// Exact definition revision to run.
    pub revision: U64,
    /// Trigger event identifier.
    pub event_id: String,
    /// Trigger event type.
    pub event_type: String,
    /// Optional event payload string.
    pub event_payload: Nullable<String>,
}

/// Result of `workflow.run`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkflowRunResult {
    /// Allocated run identifier.
    pub run_id: WorkflowRunId,
    /// Workflow identifier.
    pub workflow_id: WorkflowId,
    /// Revision executed.
    pub revision: U64,
    /// Host-verified causal root identifier.
    pub causal_root_id: CausalRootId,
    /// Causal tree depth.
    pub depth: U64,
    /// Current run status.
    pub status: WorkflowRunStatus,
}

/// Parameters for `workflow.read`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkflowReadParams {
    /// Filter by workflow identifier.
    pub workflow_id: Nullable<WorkflowId>,
    /// Filter by definition revision.
    pub revision: Nullable<U64>,
    /// Filter by run identifier.
    pub run_id: Nullable<WorkflowRunId>,
    /// Filter by causal root identifier.
    pub causal_root_id: Nullable<CausalRootId>,
}

impl Default for WorkflowReadParams {
    fn default() -> Self {
        Self {
            workflow_id: Nullable::null(),
            revision: Nullable::null(),
            run_id: Nullable::null(),
            causal_root_id: Nullable::null(),
        }
    }
}

/// Result of `workflow.read`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkflowReadResult {
    /// Matching workflow definitions.
    pub definitions: Vec<WorkflowDefinitionSummary>,
    /// Matching workflow runs.
    pub runs: Vec<WorkflowRunSummary>,
    /// Matching node execution receipts.
    pub node_receipts: Vec<NodeReceiptSummary>,
    /// Remaining causal budget for requested causal root, if queried.
    pub remaining_causal_budget: Nullable<CausalBudgetSummary>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_deadlines_match_specification() {
        let deadlines = WorkflowDeadlines::default();
        assert_eq!(deadlines.run_deadline_ms.get(), 1_800_000);
        assert_eq!(deadlines.action_wait_ms.get(), 600_000);
    }

    #[test]
    fn edge_condition_round_trips() {
        for condition in EdgeCondition::ALL {
            assert_eq!(
                EdgeCondition::from_wire(condition.as_str()),
                Some(*condition)
            );
        }
    }

    #[test]
    fn workflow_run_status_round_trips() {
        for status in WorkflowRunStatus::ALL {
            assert_eq!(WorkflowRunStatus::from_wire(status.as_str()), Some(*status));
        }
    }

    #[test]
    fn node_status_round_trips() {
        for status in NodeStatus::ALL {
            assert_eq!(NodeStatus::from_wire(status.as_str()), Some(*status));
        }
    }
}
