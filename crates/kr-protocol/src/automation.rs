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

use crate::agent::PromptText;
use crate::changeset::{ApplyOutcomeClass, DestinationClass, VersionRef};
use crate::ids::{
    ActionId, AgentTurnId, CausalRootId, EnvironmentId, GrantId, MaterialisationId, PluginId,
    SessionId, WorkflowId, WorkflowRunId, WorkspaceId,
};
use crate::project::WorkspaceKind;
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

/// The longest command line a `shell_command` node carries, in bytes.
pub const MAX_SHELL_COMMAND_BYTES: usize = 16 * 1024;
/// The longest test suite name a `run_tests` node carries, in bytes.
pub const MAX_TEST_SUITE_BYTES: usize = 256;
/// The longest summary an `attention_notice` node carries, in bytes.
pub const MAX_NOTICE_SUMMARY_BYTES: usize = 1024;

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
    /// What a workflow alert is about.
    WorkflowAlertKind {
        CausalLimit => "causal_limit", "A causal chain ran out of budget and was paused.";
        WorkflowPaused => "workflow_paused", "A workflow revision was paused by one of its own limits.";
        WorkflowResumed => "workflow_resumed", "The pause a limit caused was cleared by enabling the revision.";
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

wire_enum! {
    /// The action kinds a workflow node can name.
    ///
    /// Each kind takes one parameter type, needs the rights the method that performs the same
    /// effect needs, and produces one output type ([`NodeOutput`]). A node naming anything else is
    /// refused when the definition is read.
    WorkflowActionKind {
        ShellCommand => "shell_command", "Runs a command line in a shell in the node's declared execution environment.";
        RunTests => "run_tests", "Runs a named test suite against one immutable change-set version.";
        RequestReview => "request_review", "Asks an agent in a separate reviewer session to review one immutable change-set version.";
        CreateSession => "create_session", "Creates a session, taking `session.create`'s own parameters.";
        AttentionNotice => "attention_notice", "Raises an attention notice.";
        MaterializeChangeset => "materialize_changeset", "Writes one immutable change-set version into a private directory, taking `changeset.materialize`'s own parameters.";
        ApplyDiff => "apply_diff", "Applies one immutable change-set version to a destination, taking `diff.apply`'s own parameters.";
        CaptureChangeset => "capture_changeset", "Captures one workspace into an immutable change-set version, taking `changeset.capture`'s own parameters.";
    }
}

/// Parameters of a `shell_command` node.
///
/// The command runs in the node's declared execution environment, and only under a broad shell
/// grant that admits that environment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ShellCommandParams {
    /// The command line the shell runs: 1 to [`MAX_SHELL_COMMAND_BYTES`] bytes.
    pub command: String,
}

/// Parameters of a `run_tests` node.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RunTestsParams {
    /// The test suite to run, by the name the environment's test configuration gives it: 1 to
    /// [`MAX_TEST_SUITE_BYTES`] bytes.
    pub suite: String,
    /// The immutable change-set version the tests run against, which their result binds to.
    pub version: VersionRef,
}

/// Parameters of a `request_review` node.
///
/// Everything the review stands on is explicit: the agent that reviews, the immutable version it
/// reads, and the workspace policy its separate session runs under.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RequestReviewParams {
    /// The agent that reviews, by the identifier of the connector that runs it.
    pub reviewer_id: PluginId,
    /// The immutable change-set version the review reads, which its result binds to.
    pub version: VersionRef,
    /// The kind of workspace the separate reviewer session works in.
    pub workspace: WorkspaceKind,
    /// What the reviewer is asked.
    pub instructions: PromptText,
}

/// Parameters of an `attention_notice` node.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AttentionNoticeParams {
    /// What the notice says: 1 to [`MAX_NOTICE_SUMMARY_BYTES`] bytes.
    pub summary: String,
}

/// What a node's action produced, as this host observed it.
///
/// One shape per action kind, named by the kind itself, so a receipt says what it is a receipt
/// of. An output holds identifiers and states, never text a node, a terminal or a model produced:
/// a reader that needs more reads the session or the change set it names, under its own authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum NodeOutput {
    /// A `shell_command` node's command ran to completion.
    ShellCommand {
        /// The session the command ran in.
        session_id: SessionId,
    },
    /// A `run_tests` node's suite passed against the version.
    RunTests {
        /// The suite that ran.
        suite: String,
        /// The version it ran against.
        version: VersionRef,
    },
    /// A `request_review` node's reviewer finished its review.
    RequestReview {
        /// The version reviewed.
        version: VersionRef,
        /// The separate reviewer session.
        session_id: SessionId,
        /// The reviewer turn whose completion carried the result.
        turn_id: AgentTurnId,
    },
    /// A `create_session` node created a session.
    CreateSession {
        /// The session.
        session_id: SessionId,
    },
    /// An `attention_notice` node raised its notice.
    AttentionNotice,
    /// A `materialize_changeset` node wrote the version into a private directory.
    MaterializeChangeset {
        /// The version written.
        version: VersionRef,
        /// The materialisation that holds it.
        materialisation_id: MaterialisationId,
    },
    /// An `apply_diff` node applied the version.
    ApplyDiff {
        /// The version applied.
        applied_version: VersionRef,
        /// Where it was applied.
        destination: DestinationClass,
        /// Which class the apply came to, absent for a preflight that found nothing to do.
        outcome: Nullable<ApplyOutcomeClass>,
        /// The immutable proposal a proposal apply produced.
        proposal_version: Nullable<VersionRef>,
    },
    /// A `capture_changeset` node captured the workspace.
    CaptureChangeset {
        /// The version captured.
        version: VersionRef,
    },
}

impl NodeOutput {
    /// The action kind whose output this is.
    #[must_use]
    pub const fn action_kind(&self) -> WorkflowActionKind {
        match self {
            Self::ShellCommand { .. } => WorkflowActionKind::ShellCommand,
            Self::RunTests { .. } => WorkflowActionKind::RunTests,
            Self::RequestReview { .. } => WorkflowActionKind::RequestReview,
            Self::CreateSession { .. } => WorkflowActionKind::CreateSession,
            Self::AttentionNotice => WorkflowActionKind::AttentionNotice,
            Self::MaterializeChangeset { .. } => WorkflowActionKind::MaterializeChangeset,
            Self::ApplyDiff { .. } => WorkflowActionKind::ApplyDiff,
            Self::CaptureChangeset { .. } => WorkflowActionKind::CaptureChangeset,
        }
    }
}

/// An event trigger definition for a workflow.
///
/// A trigger matches an event by its type and by nothing else. The events a workflow's own nodes
/// produce have types their action kinds fix, such as `changeset.captured` or `tests.passed`, and a
/// run started through `workflow.run` is an external trigger whatever type it names.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkflowTrigger {
    /// The event type that triggers the workflow, such as `changeset.captured`.
    pub event_type: String,
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
    /// The action kind this node performs.
    pub action_kind: WorkflowActionKind,
    /// The kind's own typed parameters, as a JSON document: exactly the fields the kind's
    /// parameter type has, with no template code in any value.
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
    /// Managed allowance the chain's actions have spent.
    pub managed_spend: U64,
    /// The managed allowance the chain inherited from its host when its root was admitted.
    pub max_managed_spend: U64,
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
    /// Whether paused, by `workflow.pause` or because one of its own limits was breached.
    pub paused: bool,
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
    /// from another. Absent for a run an external trigger started, and, to a paired device, for a
    /// run that another grant's run triggered.
    pub parent_run_id: Nullable<WorkflowRunId>,
    /// The node of that run whose outcome triggered this one, absent whenever the parent run is.
    pub parent_node_id: Nullable<String>,
    /// Trigger event identifier. A trigger a node produced is `node:` followed by that node's
    /// action identifier; a paired device is shown `node:` alone for one another grant's run
    /// produced.
    pub trigger_event_id: String,
    /// When execution began.
    pub started_at_ms: TimestampMs,
    /// When execution finished, if terminated.
    pub ended_at_ms: Nullable<TimestampMs>,
}

/// One attention record the automation journal holds and no attention state has acknowledged.
///
/// It is the record an exhausted chain or a breached workflow limit owes, and the one that ends a
/// pause. It stays in the journal, and in `workflow.read`, until the environment's attention state
/// has taken it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkflowAlert {
    /// The record's position in the automation journal's event stream.
    pub sequence: U64,
    /// What it is about.
    pub kind: WorkflowAlertKind,
    /// The workflow, for an alert about a workflow revision.
    pub workflow_id: Nullable<WorkflowId>,
    /// The revision, for an alert about a workflow revision.
    pub revision: Nullable<U64>,
    /// The chain, for an alert about a causal budget.
    pub causal_root_id: Nullable<CausalRootId>,
    /// Which limit was reached, or what ended the condition.
    pub reason: String,
    /// When the record was committed.
    pub raised_at_ms: TimestampMs,
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
    /// The node of the parent run whose outcome triggered this run, when the run descends from
    /// another and the reader may see that run.
    pub causal_parent: Nullable<String>,
    /// Node execution status.
    pub status: NodeStatus,
    /// What the action produced, typed by the node's kind, for a node that succeeded.
    pub output: Nullable<NodeOutput>,
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
    /// The alerts about the workflows and chains this read covers that no attention state has
    /// taken yet, oldest first.
    pub alerts: Vec<WorkflowAlert>,
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
    fn a_trigger_carries_its_event_type_and_nothing_else() {
        let filtered = serde_json::json!({
            "event_type": "changeset.captured",
            "criteria": "only on main",
        });
        assert!(
            serde_json::from_value::<WorkflowTrigger>(filtered).is_err(),
            "a filter nothing applies is refused rather than ignored"
        );
        let plain = serde_json::json!({ "event_type": "changeset.captured" });
        assert_eq!(
            serde_json::from_value::<WorkflowTrigger>(plain)
                .expect("a trigger")
                .event_type,
            "changeset.captured"
        );
    }

    #[test]
    fn a_node_names_a_registered_action_kind_or_is_refused() {
        let node = |kind: &str| {
            serde_json::json!({
                "node_id": "only",
                "action_kind": kind,
                "action_params": "{}",
                "declared_environment": null,
            })
        };
        for kind in WorkflowActionKind::ALL {
            let decoded: WorkflowNode =
                serde_json::from_value(node(kind.as_str())).expect("a registered kind");
            assert_eq!(decoded.action_kind, *kind);
            assert_eq!(WorkflowActionKind::from_wire(kind.as_str()), Some(*kind));
        }
        assert!(
            serde_json::from_value::<WorkflowNode>(node("delete_everything")).is_err(),
            "a kind nothing registered is refused when the node is read"
        );
    }

    #[test]
    fn an_output_names_the_kind_that_produced_it_and_carries_nothing_else() {
        let version = VersionRef {
            change_set_id: crate::ids::ChangeSetId::new(crate::scalars::Uuid::from_bytes([7; 16])),
            version: crate::ids::ChangeSetVersion::new(3),
        };
        let captured = NodeOutput::CaptureChangeset { version };
        let value = serde_json::to_value(&captured).expect("encodes");
        assert_eq!(value["kind"], captured.action_kind().as_str());
        assert_eq!(
            serde_json::from_value::<NodeOutput>(value.clone()).expect("decodes"),
            captured
        );
        let mut padded = value;
        padded["exit_code"] = serde_json::json!(0);
        assert!(
            serde_json::from_value::<NodeOutput>(padded).is_err(),
            "a field the kind does not produce is refused"
        );
        let notice = serde_json::to_value(NodeOutput::AttentionNotice).expect("encodes");
        assert_eq!(notice, serde_json::json!({ "kind": "attention_notice" }));
    }

    #[test]
    fn node_status_round_trips() {
        for status in NodeStatus::ALL {
            assert_eq!(NodeStatus::from_wire(status.as_str()), Some(*status));
        }
    }
}
