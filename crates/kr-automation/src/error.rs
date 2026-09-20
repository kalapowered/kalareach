//! Error types and conversions for the automation engine.

use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{CausalRootId, WorkflowId, WorkflowRunId};

/// Result alias for automation operations.
pub type Result<T> = std::result::Result<T, AutomationError>;

/// Errors originating in the automation engine.
#[derive(Debug, thiserror::Error)]
pub enum AutomationError {
    /// A provided argument was invalid.
    #[error("invalid argument: {0}")]
    InvalidArgument(String),

    /// The workflow graph contains a cycle.
    #[error("workflow graph is cyclic: {detail}")]
    CyclicGraph {
        /// Explanation of the detected cycle.
        detail: String,
    },

    /// Arbitrary template evaluation was detected in a node.
    #[error("arbitrary template code is forbidden in node {node_id}")]
    TemplateCodeRejected {
        /// The node containing template syntax.
        node_id: String,
    },

    /// A shell command node was specified without the required broad shell grant.
    #[error(
        "shell command node requires an explicit broad shell grant and declared environment: {detail}"
    )]
    ShellGrantRequired {
        /// Explanation of missing grant or environment.
        detail: String,
    },

    /// The caller lacks the necessary authority.
    #[error("permission denied: {0}")]
    PermissionDenied(String),

    /// This host could not read the grant a definition names, so it cannot say what it admits.
    ///
    /// This is not a refusal. A refusal says the grant does not authorise the work; this says the
    /// host does not know, which is a different thing to tell a caller.
    #[error("the grant store could not be read: {0}")]
    AuthorityUnavailable(String),

    /// One action identifier was reused for a different action.
    #[error("action {action_id} was submitted before, carrying something else")]
    ActionIdentifierReused {
        /// The identifier the request carried.
        action_id: String,
    },

    /// This host carries out no action of that kind.
    ///
    /// Nothing was dispatched, so nothing happened: a node refused this way is a definite failure
    /// of the run rather than an outcome nobody can establish.
    #[error("this host carries out no action of kind '{action_kind}'")]
    ActionUnavailable {
        /// The action kind the node named.
        action_kind: String,
    },

    /// The named workflow was not found.
    #[error("workflow {0} not found")]
    WorkflowNotFound(WorkflowId),

    /// The definition revision does not match the expected revision.
    #[error("revision mismatch for workflow {workflow_id}: expected {expected}, found {found}")]
    RevisionMismatch {
        /// The workflow ID.
        workflow_id: WorkflowId,
        /// The expected revision.
        expected: u64,
        /// The found revision.
        found: u64,
    },

    /// The workflow is currently disabled.
    #[error("workflow {0} is disabled")]
    WorkflowDisabled(WorkflowId),

    /// The workflow is currently paused.
    #[error("workflow {0} is paused")]
    WorkflowPaused(WorkflowId),

    /// The causal budget for the causal root has been exhausted.
    #[error("causal limit exhausted for root {root}: {reason}")]
    CausalLimitExhausted {
        /// The causal root ID.
        root: CausalRootId,
        /// Reason for exhaustion (e.g. depth, total runs, actions, sessions, lifetime).
        reason: String,
    },

    /// A workflow attempted to retrigger on its own descendants by default.
    #[error(
        "workflow {workflow_id} attempted to retrigger on its own causal descendant under root {root}"
    )]
    SelfRetriggerRejected {
        /// The workflow ID.
        workflow_id: WorkflowId,
        /// The causal root ID.
        root: CausalRootId,
    },

    /// Trigger event was already processed (deduplicated).
    #[error("duplicate trigger for workflow {workflow_id} rev {revision} event {event_id}")]
    DuplicateTrigger {
        /// The workflow ID.
        workflow_id: WorkflowId,
        /// The definition revision.
        revision: u64,
        /// The event ID.
        event_id: String,
    },

    /// Per-workflow concurrency limit was breached.
    #[error("concurrency limit {limit} exceeded for workflow {workflow_id}")]
    ConcurrencyLimitExceeded {
        /// The workflow ID.
        workflow_id: WorkflowId,
        /// The concurrency limit.
        limit: u64,
    },

    /// Admission rate limit was breached.
    #[error("admission rate limit exceeded: {reason}")]
    RateLimitExceeded {
        /// Explanation of rate limit.
        reason: String,
    },

    /// A predecessor node produced an unknown outcome.
    #[error("predecessor node {node_id} produced unknown outcome: {detail}")]
    OutcomeUnknown {
        /// Node ID.
        node_id: String,
        /// Explanation.
        detail: String,
    },

    /// Node execution timed out.
    #[error("action wait deadline exceeded for node {node_id}")]
    ActionTimeout {
        /// Node ID.
        node_id: String,
    },

    /// Run timed out.
    #[error("run deadline exceeded for run {run_id}")]
    RunTimeout {
        /// Run ID.
        run_id: WorkflowRunId,
    },

    /// Stale causal generation attempted to consume a rearmed budget.
    #[error(
        "stale causal generation {found_generation} rejected against budget generation {expected_generation} for root {root}"
    )]
    StaleCausalGeneration {
        /// The causal root ID.
        root: CausalRootId,
        /// The current budget generation.
        expected_generation: u64,
        /// The found generation on the descendant.
        found_generation: u64,
    },

    /// The parent run was not found in host storage.
    #[error("parent run {0} not found in durable host store")]
    ParentRunNotFound(WorkflowRunId),

    /// The parent node was not found in the parent run.
    #[error("parent node {node_id} not found in run {run_id}")]
    ParentNodeNotFound {
        /// Run ID.
        run_id: WorkflowRunId,
        /// Node ID.
        node_id: String,
    },

    /// The request named a causal root that the parent run does not belong to.
    #[error("claimed causal root {claimed} is not the parent run's root {actual}")]
    CausalRootMismatch {
        /// The root the request named.
        claimed: CausalRootId,
        /// The root the host has on record for the parent run.
        actual: CausalRootId,
    },

    /// A workflow definition revision is already installed and immutable.
    #[error("workflow {workflow_id} revision {revision} is already installed and immutable")]
    AlreadyInstalled {
        /// Workflow ID.
        workflow_id: WorkflowId,
        /// Revision.
        revision: u64,
    },

    /// SQLite storage error.
    #[error("storage error: {0}")]
    DatabaseError(#[from] rusqlite::Error),

    /// JSON serialization or deserialization error.
    #[error("json error: {0}")]
    JsonError(#[from] serde_json::Error),

    /// Attention engine error.
    #[error("attention error: {0}")]
    AttentionError(#[from] kr_attention::Error),

    /// Change-set service error.
    #[error("changeset error: {0}")]
    ChangesetError(#[from] kr_changeset::ChangeSetError),
}

impl From<AutomationError> for ProtocolError {
    fn from(error: AutomationError) -> Self {
        match error {
            AutomationError::InvalidArgument(message) => {
                Self::new(ErrorCode::InvalidArgument, message)
            }
            AutomationError::CyclicGraph { detail } => Self::new(
                ErrorCode::InvalidArgument,
                format!("workflow definition graph is cyclic: {detail}"),
            ),
            AutomationError::TemplateCodeRejected { node_id } => Self::new(
                ErrorCode::InvalidArgument,
                format!("arbitrary template code is forbidden in node {node_id}"),
            ),
            AutomationError::ShellGrantRequired { detail } => Self::new(
                ErrorCode::PermissionDenied,
                format!("shell command node requires explicit broad shell grant: {detail}"),
            ),
            AutomationError::PermissionDenied(message) => {
                Self::new(ErrorCode::PermissionDenied, message)
            }
            AutomationError::AuthorityUnavailable(message) => Self::new(
                ErrorCode::StorageUnavailable,
                format!("this host could not read the grant this workflow names: {message}"),
            ),
            AutomationError::ActionIdentifierReused { action_id } => Self::new(
                ErrorCode::IdConflict,
                format!("action {action_id} was submitted before, carrying something else"),
            ),
            AutomationError::ActionUnavailable { action_kind } => Self::new(
                ErrorCode::ResourceUnavailable,
                format!("this host carries out no action of kind '{action_kind}'"),
            ),
            AutomationError::WorkflowNotFound(id) => Self::new(
                ErrorCode::InvalidArgument,
                format!("workflow {id} not found"),
            ),
            AutomationError::RevisionMismatch {
                workflow_id,
                expected,
                found,
            } => Self::new(
                ErrorCode::DraftConflict,
                format!(
                    "revision mismatch for workflow {workflow_id}: expected {expected}, found {found}"
                ),
            ),
            AutomationError::WorkflowDisabled(id) => Self::new(
                ErrorCode::PluginDisabled,
                format!("workflow {id} is disabled"),
            ),
            AutomationError::WorkflowPaused(id) => Self::new(
                ErrorCode::PluginDisabled,
                format!("workflow {id} is paused"),
            ),
            AutomationError::CausalLimitExhausted { root, reason } => Self::new(
                ErrorCode::CausalLimit,
                format!("causal budget exhausted for root {root}: {reason}"),
            ),
            AutomationError::SelfRetriggerRejected { workflow_id, root } => Self::new(
                ErrorCode::CausalLimit,
                format!(
                    "workflow {workflow_id} cannot retrigger on own descendant under root {root}"
                ),
            ),
            AutomationError::DuplicateTrigger {
                workflow_id,
                revision,
                event_id,
            } => Self::new(
                ErrorCode::IdConflict,
                format!(
                    "duplicate trigger for workflow {workflow_id} rev {revision} event {event_id}"
                ),
            ),
            AutomationError::ConcurrencyLimitExceeded { workflow_id, limit } => Self::new(
                ErrorCode::RateLimited,
                format!("concurrency limit {limit} exceeded for workflow {workflow_id}"),
            ),
            AutomationError::RateLimitExceeded { reason } => Self::new(
                ErrorCode::RateLimited,
                format!("rate limit exceeded: {reason}"),
            ),
            AutomationError::OutcomeUnknown { node_id, detail } => Self::new(
                ErrorCode::OutcomeUnknown,
                format!("node {node_id} outcome unknown: {detail}"),
            ),
            AutomationError::ActionTimeout { node_id } => Self::new(
                ErrorCode::ResourceUnavailable,
                format!("action wait deadline exceeded for node {node_id}"),
            ),
            AutomationError::RunTimeout { run_id } => Self::new(
                ErrorCode::ResourceUnavailable,
                format!("run deadline exceeded for run {run_id}"),
            ),
            AutomationError::StaleCausalGeneration { root, .. } => Self::new(
                ErrorCode::CausalLimit,
                format!("stale causal generation rejected for root {root}"),
            ),
            AutomationError::ParentRunNotFound(id) => Self::new(
                ErrorCode::InvalidArgument,
                format!("parent run {id} not found in host storage"),
            ),
            AutomationError::ParentNodeNotFound { run_id, node_id } => Self::new(
                ErrorCode::InvalidArgument,
                format!("parent node {node_id} not found in run {run_id}"),
            ),
            AutomationError::CausalRootMismatch { claimed, actual } => Self::new(
                ErrorCode::InvalidArgument,
                format!("claimed causal root {claimed} is not the parent run's root {actual}"),
            ),
            AutomationError::AlreadyInstalled {
                workflow_id,
                revision,
            } => Self::new(
                ErrorCode::DraftConflict,
                format!(
                    "workflow {workflow_id} revision {revision} is already installed and immutable"
                ),
            ),
            AutomationError::DatabaseError(err) => Self::new(
                ErrorCode::StorageUnavailable,
                format!("workflow database storage error: {err}"),
            ),
            AutomationError::JsonError(err) => Self::new(
                ErrorCode::InvalidArgument,
                format!("invalid json structure: {err}"),
            ),
            AutomationError::AttentionError(err) => Self::new(
                ErrorCode::StorageUnavailable,
                format!("attention engine error: {err}"),
            ),
            AutomationError::ChangesetError(err) => Self::new(
                ErrorCode::StorageUnavailable,
                format!("changeset service error: {err}"),
            ),
        }
    }
}
