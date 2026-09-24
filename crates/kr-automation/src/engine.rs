//! Workflow execution engine: node sequencing, dependency resolution, and outcome handling.
//!
//! Section 25 and Section 17 ¶8 specify:
//! - Persist a run before dispatching its first node.
//! - Record each node's action identifier and causal parent.
//! - Dependencies run only after the required predecessor outcome is authoritative.
//! - An unknown outcome pauses dependants for review rather than being read as success.
//! - A process exit is never treated as proof that a later review or deployment succeeded.
//! - Cancellation stops undispatched nodes and requests cancellation for supported active
//!   actions while claiming nothing about external side effects.
//! - Enforce deadlines: 30-minute run deadline and 10-minute action wait deadline.

use std::collections::HashMap;
use std::sync::Arc;

use kr_protocol::automation::{
    EdgeCondition, NodeOutput, NodeStatus, WorkflowActionKind, WorkflowDefinition, WorkflowNode,
    WorkflowRunStatus,
};
use kr_protocol::changeset::{DestinationClass, VersionRef};
use kr_protocol::ids::{
    ActionId, AgentTurnId, ChangeSetId, ChangeSetVersion, EnvironmentId, MaterialisationId,
    SessionId, WorkflowRunId,
};
use kr_protocol::scalars::{Nullable, Uuid};

use crate::authority::{self, AuthoritySource};
use crate::causal::CausalContext;
use crate::error::Result;
use crate::store::{NodeSettlement, WorkflowStore};
use crate::{Host, HostClock};

/// Node execution outcome from an action executor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ActionOutcome {
    /// Action completed with authoritative success.
    Success {
        /// What it produced, typed by the node's action kind.
        output: NodeOutput,
    },
    /// Action completed with failure.
    Failed {
        /// Error description.
        error: String,
    },
    /// Action outcome could not be determined. Dependants must pause for review.
    Unknown {
        /// Detail about why outcome is unknown.
        detail: String,
    },
}

/// Everything the host knows about the node it is about to dispatch.
///
/// A workflow's effects are the host's own actions, and section 25 requires the causal root, the
/// depth and the parent to travel with every session, action and derived trigger a workflow
/// creates. So a runner is handed the chain this node belongs to rather than only the node's own
/// parameters: what it starts is recorded as this run's work, and the chain it charges is the one
/// the host verified.
#[derive(Clone, Copy, Debug)]
pub struct Dispatch<'a> {
    /// The run this node belongs to.
    pub run_id: WorkflowRunId,
    /// The definition being run.
    pub definition: &'a WorkflowDefinition,
    /// The node itself.
    pub node: &'a WorkflowNode,
    /// The action identifier the journal recorded for this node.
    pub action_id: ActionId,
    /// The verified causal chain this dispatch belongs to.
    pub causal: &'a CausalContext,
    /// The host's clock as it stood when the node was claimed.
    pub now_ms: u64,
}

/// What asking an action to stop came to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cancellation {
    /// The action was asked to stop. Nothing is claimed about what it did before it stopped.
    Requested,
    /// An action of this kind cannot be stopped once it has begun.
    Unsupported,
}

/// Trait implemented by action node runners (e.g., shell commands, test runners, reviews).
///
/// A runner that asks the grant again before its effect, as the host's own does, answers
/// [`crate::AutomationError::PermissionDenied`] or [`crate::AutomationError::AuthorityUnavailable`]
/// only when it refused the effect before starting it. The engine treats that exactly as it treats
/// a refusal it decided itself: the node and its run pause, and nothing is claimed about an effect
/// that never began.
pub trait ActionRunner: Send + Sync {
    /// Executes one action node.
    fn execute(
        &self,
        dispatch: &Dispatch<'_>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<ActionOutcome>> + Send>>;

    /// Asks the action `dispatch` began to stop.
    ///
    /// The engine asks this when the action has outlived its wait or its run's deadline, and then
    /// stops waiting for it. A kind that can be stopped settles cancelled, which says the host
    /// stopped asking and not that the world is as it was; a kind that cannot settles unknown, and
    /// its dependants pause for review.
    fn cancel(&self, dispatch: &Dispatch<'_>) -> Cancellation;
}

/// How often the engine reads the host's clock while it waits for an action, so a deadline that
/// passes during the wait is found within this long of passing.
const DEADLINE_POLL_MS: u64 = 250;

/// An output of `kind` whose identifiers name nothing, for a runner that stands in for the host.
///
/// It has the shape a real action of that kind produces and refers to no real session, version or
/// materialisation.
#[must_use]
pub fn stand_in_output(kind: WorkflowActionKind) -> NodeOutput {
    let nothing = Uuid::from_bytes([0; 16]);
    let version = VersionRef {
        change_set_id: ChangeSetId::new(nothing),
        version: ChangeSetVersion::new(1),
    };
    match kind {
        WorkflowActionKind::ShellCommand => NodeOutput::ShellCommand {
            session_id: SessionId::new(nothing),
        },
        WorkflowActionKind::RunTests => NodeOutput::RunTests {
            suite: "stand-in".to_owned(),
            version,
        },
        WorkflowActionKind::RequestReview => NodeOutput::RequestReview {
            version,
            session_id: SessionId::new(nothing),
            turn_id: AgentTurnId::new("stand-in".to_owned()).expect("a static turn identifier"),
        },
        WorkflowActionKind::CreateSession => NodeOutput::CreateSession {
            session_id: SessionId::new(nothing),
        },
        WorkflowActionKind::AttentionNotice => NodeOutput::AttentionNotice,
        WorkflowActionKind::MaterializeChangeset => NodeOutput::MaterializeChangeset {
            version,
            materialisation_id: MaterialisationId::new(nothing),
        },
        WorkflowActionKind::ApplyDiff => NodeOutput::ApplyDiff {
            applied_version: version,
            destination: DestinationClass::Proposal,
            outcome: Nullable::null(),
            proposal_version: Nullable::null(),
        },
        WorkflowActionKind::CaptureChangeset => NodeOutput::CaptureChangeset { version },
    }
}

/// A default test/mock action runner.
#[derive(Default)]
pub struct MockActionRunner {
    outcomes: std::sync::Mutex<HashMap<String, ActionOutcome>>,
    stoppable: std::sync::Mutex<std::collections::HashSet<String>>,
}

impl MockActionRunner {
    /// Creates a new mock action runner.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Configures the outcome for a specific node_id.
    pub fn set_outcome(&self, node_id: &str, outcome: ActionOutcome) {
        self.outcomes
            .lock()
            .unwrap()
            .insert(node_id.to_owned(), outcome);
    }

    /// Lets the action of `node_id` be stopped once it has begun.
    pub fn set_stoppable(&self, node_id: &str) {
        self.stoppable.lock().unwrap().insert(node_id.to_owned());
    }
}

impl ActionRunner for MockActionRunner {
    fn execute(
        &self,
        dispatch: &Dispatch<'_>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<ActionOutcome>> + Send>> {
        let node_id = dispatch.node.node_id.clone();
        let outcome = self
            .outcomes
            .lock()
            .unwrap()
            .get(&node_id)
            .cloned()
            .unwrap_or_else(|| ActionOutcome::Success {
                output: stand_in_output(dispatch.node.action_kind),
            });
        Box::pin(async move { Ok(outcome) })
    }

    fn cancel(&self, dispatch: &Dispatch<'_>) -> Cancellation {
        if self
            .stoppable
            .lock()
            .unwrap()
            .contains(&dispatch.node.node_id)
        {
            Cancellation::Requested
        } else {
            Cancellation::Unsupported
        }
    }
}

/// Coordinates execution of a workflow run.
pub struct WorkflowEngine {
    store: Arc<WorkflowStore>,
    runner: Arc<dyn ActionRunner>,
    authority: Arc<dyn AuthoritySource>,
    clock: Arc<dyn HostClock>,
    environment_id: EnvironmentId,
}

impl WorkflowEngine {
    /// Creates a workflow execution engine over `store`, for the host `host` describes.
    #[must_use]
    pub fn new(store: Arc<WorkflowStore>, host: Host) -> Self {
        Self {
            store,
            runner: host.runner,
            authority: host.authority,
            clock: host.clock,
            environment_id: host.environment_id,
        }
    }

    /// Executes all reachable nodes of a workflow run according to graph dependencies.
    ///
    /// The engine reads the host clock again before every reservation and every receipt, so a
    /// run that takes an hour is charged against the time it actually spent rather than against
    /// the moment it was admitted.
    pub async fn execute_run(
        &self,
        run_id: WorkflowRunId,
        definition: &WorkflowDefinition,
        causal_ctx: &CausalContext,
    ) -> Result<WorkflowRunStatus> {
        let now_ms = self.clock.now_ms();
        let receipts = self.store.list_node_receipts(run_id)?;
        let mut node_statuses: HashMap<String, NodeStatus> = receipts
            .iter()
            .map(|r| (r.node_id.clone(), r.status))
            .collect();
        let node_actions: HashMap<String, ActionId> = receipts
            .iter()
            .map(|r| (r.node_id.clone(), r.action_id))
            .collect();

        // In-edges: to_node -> Vec<(from_node, condition)>
        let mut in_edges: HashMap<&str, Vec<(&str, EdgeCondition)>> = HashMap::new();
        for edge in &definition.edges {
            in_edges
                .entry(edge.to_node.as_str())
                .or_default()
                .push((edge.from_node.as_str(), edge.condition));
        }

        // The run's deadline, set when it began running: it measures the run's execution. It is
        // decided on the host's clock before every node and while every action runs, and each
        // action is waited for no longer than the definition's action wait either.
        let deadline_ms = self.store.run_deadline(run_id)?.unwrap_or(u64::MAX);
        let action_wait_ms = definition.deadlines.action_wait_ms.get();

        let mut progress = true;
        let mut run_status = WorkflowRunStatus::Completed;

        while progress {
            progress = false;

            for node in &definition.nodes {
                let current_status = node_statuses.get(&node.node_id).copied().unwrap();
                if current_status != NodeStatus::Pending {
                    continue;
                }

                // Check dependencies
                let incoming = in_edges
                    .get(node.node_id.as_str())
                    .cloned()
                    .unwrap_or_default();
                let mut can_run = true;
                let mut must_pause_for_review = false;

                if !incoming.is_empty() {
                    for (parent_id, condition) in incoming {
                        let parent_status = node_statuses
                            .get(parent_id)
                            .copied()
                            .unwrap_or(NodeStatus::Pending);
                        match parent_status {
                            NodeStatus::Pending | NodeStatus::Running => {
                                // Dependency not yet settled
                                can_run = false;
                                break;
                            }
                            NodeStatus::Unknown => {
                                // Unknown outcome pauses dependants for review! (Section 25 ¶5)
                                must_pause_for_review = true;
                                can_run = false;
                                break;
                            }
                            NodeStatus::Success => {
                                if condition == EdgeCondition::Failure {
                                    can_run = false;
                                }
                            }
                            NodeStatus::Failed => {
                                if condition == EdgeCondition::Success {
                                    can_run = false;
                                }
                            }
                            NodeStatus::Paused | NodeStatus::Cancelled => {
                                can_run = false;
                                break;
                            }
                        }
                    }
                }

                if must_pause_for_review {
                    let paused = self.store.pause_waiting_node(
                        run_id,
                        &node.node_id,
                        "paused for review due to unknown predecessor outcome",
                        now_ms,
                    )?;
                    let recorded = if paused {
                        NodeStatus::Paused
                    } else {
                        self.recorded_status(run_id, &node.node_id)?
                    };
                    node_statuses.insert(node.node_id.clone(), recorded);
                    run_status = WorkflowRunStatus::Paused;
                    progress = true;
                    continue;
                }

                if can_run {
                    // A run past its deadline dispatches nothing further. Section 17 makes the
                    // deadline one of the workflow's own limits: the run stops where it stands,
                    // the revision pauses, and the pause owes one attention item.
                    let checked_ms = self.clock.now_ms();
                    if checked_ms >= deadline_ms {
                        return self.stop_on_breach(
                            run_id,
                            definition,
                            &crate::error::AutomationError::RunTimeout { run_id }.to_string(),
                            checked_ms,
                        );
                    }

                    // The grant is read again here, immediately before this node is dispatched,
                    // rather than once when the run was admitted. A run takes minutes and a
                    // revocation, an expiry or a narrowing can land between two of its nodes; a
                    // grant that no longer admits this node's effect stops the run where it
                    // stands, with nothing claimed and nothing reserved.
                    let authority_time_ms = self.clock.now_ms();
                    match self
                        .authority
                        .grant(definition.grant_reference, authority_time_ms)
                        .and_then(|grant| {
                            authority::check_node(&grant, definition, node, self.environment_id)
                        }) {
                        Ok(()) => {}
                        Err(error) => {
                            return self.pause_on_refusal(
                                run_id,
                                &node.node_id,
                                error,
                                authority_time_ms,
                            );
                        }
                    }

                    // The journal, not the snapshot this loop started from, decides whether the
                    // node still has a dispatch owed to it, and the claim comes first so that a
                    // node nobody owes anything to spends none of the chain's allowance.
                    // Reading its status and moving it to running is one statement, so a
                    // cancellation that arrives while an earlier node was running either gets
                    // there first and this node is never dispatched, or finds it already
                    // running and leaves it alone.
                    if !self.store.claim_node_for_dispatch(run_id, &node.node_id)? {
                        let recorded = self.store.node_status(run_id, &node.node_id)?;
                        node_statuses.insert(
                            node.node_id.clone(),
                            recorded.unwrap_or(NodeStatus::Cancelled),
                        );
                        progress = true;
                        continue;
                    }
                    node_statuses.insert(node.node_id.clone(), NodeStatus::Running);

                    // A workflow paused since this run started dispatches nothing further. The
                    // run itself stays where it is, for whoever enables the workflow again.
                    if self
                        .store
                        .is_paused(definition.workflow_id, definition.revision.get())?
                    {
                        return self.pause_on_refusal(
                            run_id,
                            &node.node_id,
                            crate::error::AutomationError::WorkflowPaused(definition.workflow_id),
                            self.clock.now_ms(),
                        );
                    }

                    // Every reservation is checked against the clock as it stands now, not
                    // against the time the run was admitted, so a chain cannot keep spending
                    // after its lifetime has run out.
                    let dispatch_time_ms = self.clock.now_ms();

                    // A node that creates a session spends the chain's session allowance as
                    // well as its action allowance, and both are reserved before dispatch.
                    if node.action_kind == WorkflowActionKind::CreateSession
                        && let Err(err) = self.store.reserve_budget_session(
                            causal_ctx.root_id,
                            causal_ctx.generation,
                            dispatch_time_ms,
                        )
                    {
                        return self.pause_on_refusal(run_id, &node.node_id, err, dispatch_time_ms);
                    }

                    if let Err(err) = self.store.reserve_budget_action(
                        causal_ctx.root_id,
                        causal_ctx.generation,
                        crate::definition::managed_spend(node.action_kind),
                        dispatch_time_ms,
                    ) {
                        return self.pause_on_refusal(run_id, &node.node_id, err, dispatch_time_ms);
                    }

                    // The claim, the pause check and the reservations each waited on the journal,
                    // and a revocation can land in any of those waits. The grant is therefore
                    // read once more here, with nothing left between this and the dispatch but
                    // the call itself.
                    let final_check_ms = self.clock.now_ms();
                    if let Err(error) = self
                        .authority
                        .grant(definition.grant_reference, final_check_ms)
                        .and_then(|grant| {
                            authority::check_node(&grant, definition, node, self.environment_id)
                        })
                    {
                        return self.pause_on_refusal(run_id, &node.node_id, error, final_check_ms);
                    }

                    let dispatch = Dispatch {
                        run_id,
                        definition,
                        node,
                        action_id: node_actions[&node.node_id],
                        causal: causal_ctx,
                        now_ms: dispatch_time_ms,
                    };
                    // The action is waited for until its own wait or the run's deadline passes,
                    // whichever comes first, and no longer.
                    let wait_until = dispatch_time_ms
                        .saturating_add(action_wait_ms)
                        .min(deadline_ms);
                    let Some(outcome_res) = self
                        .wait_for(self.runner.execute(&dispatch), wait_until)
                        .await
                    else {
                        let outlived_ms = self.clock.now_ms();
                        let past_deadline = outlived_ms >= deadline_ms;
                        let limit = if past_deadline {
                            crate::error::AutomationError::RunTimeout { run_id }
                        } else {
                            crate::error::AutomationError::ActionTimeout {
                                node_id: node.node_id.clone(),
                            }
                        }
                        .to_string();
                        // The host stops waiting and asks the action to stop. What it did is
                        // claimed either way only as far as the host knows it.
                        let (status, detail) = match self.runner.cancel(&dispatch) {
                            Cancellation::Requested => (
                                NodeStatus::Cancelled,
                                format!(
                                    "{limit}: the action was asked to stop, and nothing is claimed \
                                     about what it did before it stopped"
                                ),
                            ),
                            Cancellation::Unsupported => (
                                NodeStatus::Unknown,
                                format!(
                                    "{limit}: an action of this kind cannot be stopped once it \
                                     has begun, so what it did is not established"
                                ),
                            ),
                        };
                        self.store.settle_node(&NodeSettlement {
                            run_id,
                            node_id: &node.node_id,
                            status,
                            output: None,
                            error: Some(&detail),
                            produced: None,
                            at_ms: outlived_ms,
                        })?;
                        if past_deadline {
                            return self.stop_on_breach(run_id, definition, &limit, outlived_ms);
                        }
                        // The action's wait is one of the workflow's own limits too.
                        self.store.pause_workflow_on_breach(
                            definition.workflow_id,
                            definition.revision.get(),
                            &limit,
                            outlived_ms,
                        )?;
                        let recorded = self.recorded_status(run_id, &node.node_id)?;
                        node_statuses.insert(node.node_id.clone(), recorded);
                        if recorded == NodeStatus::Unknown {
                            run_status = WorkflowRunStatus::Paused;
                        }
                        progress = true;
                        continue;
                    };

                    // A runner that asked the grant once more and was refused never began the
                    // effect, so this is a refusal and not an outcome: the node pauses as it would
                    // have if the engine's own check had refused it a moment earlier.
                    if let Err(
                        refusal @ (crate::error::AutomationError::PermissionDenied(_)
                        | crate::error::AutomationError::AuthorityUnavailable(_)),
                    ) = outcome_res
                    {
                        return self.pause_on_refusal(
                            run_id,
                            &node.node_id,
                            refusal,
                            self.clock.now_ms(),
                        );
                    }

                    // What the action came to, and what the run owes because of it. The action
                    // was dispatched, so whether it did anything is not this host's to say
                    // unless the runner said so: an uncertain answer stays uncertain and its
                    // dependants pause, and only a definite report of failure is a failure.
                    let (status, output, detail) = match outcome_res {
                        Ok(ActionOutcome::Success { output })
                            if output.action_kind() == node.action_kind =>
                        {
                            (NodeStatus::Success, Some(output), None)
                        }
                        // An output of another kind is not the result of this node's action, so
                        // what the action did is not established, and its dependants pause.
                        Ok(ActionOutcome::Success { output }) => (
                            NodeStatus::Unknown,
                            None,
                            Some(format!(
                                "the action reported a {} output for a {} node, so what it did \
                                 is not established",
                                output.action_kind(),
                                node.action_kind
                            )),
                        ),
                        Ok(ActionOutcome::Failed { error }) => {
                            (NodeStatus::Failed, None, Some(error))
                        }
                        Ok(ActionOutcome::Unknown { detail }) => {
                            (NodeStatus::Unknown, None, Some(detail))
                        }
                        Err(error) => {
                            let uncertain = matches!(
                                error,
                                crate::error::AutomationError::OutcomeUnknown { .. }
                            );
                            let status = if uncertain {
                                NodeStatus::Unknown
                            } else {
                                NodeStatus::Failed
                            };
                            (status, None, Some(error.to_string()))
                        }
                    };
                    // Only a node that is still this dispatch's is settled. A node cancelled while
                    // its action ran keeps its cancellation, and so does its run: an answer that
                    // arrived after the host stopped asking does not make the run a completed one.
                    // The outcome and the event that says so commit together. A success
                    // produces the event its action kind fixes, which is what a derived trigger
                    // names; the event's identifier is this node's action identifier, so a replay
                    // of it cannot become a second trigger.
                    let produced = (status == NodeStatus::Success)
                        .then(|| crate::definition::produced_event(node.action_kind))
                        .flatten();
                    let settled = self.store.settle_node(&NodeSettlement {
                        run_id,
                        node_id: &node.node_id,
                        status,
                        output: output.as_ref(),
                        error: detail.as_deref(),
                        produced,
                        at_ms: self.clock.now_ms(),
                    })?;
                    let recorded = if settled {
                        status
                    } else {
                        self.recorded_status(run_id, &node.node_id)?
                    };
                    node_statuses.insert(node.node_id.clone(), recorded);
                    match recorded {
                        NodeStatus::Failed => run_status = WorkflowRunStatus::Failed,
                        NodeStatus::Unknown => run_status = WorkflowRunStatus::Paused,
                        _ => {}
                    }

                    progress = true;
                }
            }
        }

        // The run is only as settled as its least settled node, and what the nodes are is read
        // back from the journal rather than from this loop's snapshot: a cancellation that
        // landed while the loop was running is in the journal and not in the snapshot.
        let settled = self.store.list_node_receipts(run_id)?;
        if settled.iter().any(|r| r.status == NodeStatus::Cancelled) {
            run_status = WorkflowRunStatus::Cancelled;
        } else if settled
            .iter()
            .any(|r| r.status == NodeStatus::Paused || r.status == NodeStatus::Unknown)
        {
            run_status = WorkflowRunStatus::Paused;
        } else if settled.iter().any(|r| r.status == NodeStatus::Failed) {
            run_status = WorkflowRunStatus::Failed;
        }

        if run_status == WorkflowRunStatus::Cancelled {
            // A cancelled node's dependants can never run, so the nodes still waiting are
            // cancelled with the run rather than left looking as though they might.
            self.store.cancel_run(
                run_id,
                "a node of this run was cancelled, so the nodes after it do not run",
                self.clock.now_ms(),
            )?;
        } else {
            self.store
                .finish_run(run_id, run_status, self.clock.now_ms())?;
        }
        Ok(run_status)
    }

    /// Waits for `action` until the host's clock reaches `until`, and answers `None` when it
    /// outlived that moment.
    ///
    /// The clock is read at least every [`DEADLINE_POLL_MS`], so a deadline that passes while the
    /// host sleeps or while nothing else happens is found soon after it passes rather than when
    /// the action ends.
    async fn wait_for<T>(
        &self,
        action: impl std::future::Future<Output = T>,
        until: u64,
    ) -> Option<T> {
        let mut action = std::pin::pin!(action);
        loop {
            let now = self.clock.now_ms();
            if now >= until {
                return None;
            }
            let left = std::time::Duration::from_millis((until - now).min(DEADLINE_POLL_MS));
            tokio::select! {
                biased;
                outcome = &mut action => return Some(outcome),
                () = tokio::time::sleep(left) => {}
            }
        }
    }

    /// Stops a run that exceeded one of its workflow's limits: every node still waiting is
    /// cancelled, the run is cancelled, and the revision pauses with the attention item it owes,
    /// all in one transaction.
    fn stop_on_breach(
        &self,
        run_id: WorkflowRunId,
        definition: &WorkflowDefinition,
        reason: &str,
        now_ms: u64,
    ) -> Result<WorkflowRunStatus> {
        self.store.stop_run_on_breach(
            run_id,
            definition.workflow_id,
            definition.revision.get(),
            reason,
            now_ms,
        )?;
        Ok(WorkflowRunStatus::Cancelled)
    }

    /// Reads a node's status from the journal, for a node this loop no longer owns.
    fn recorded_status(&self, run_id: WorkflowRunId, node_id: &str) -> Result<NodeStatus> {
        Ok(self
            .store
            .node_status(run_id, node_id)?
            .unwrap_or(NodeStatus::Cancelled))
    }

    /// Records a refused dispatch and pauses the run, keeping the refusal for the caller.
    ///
    /// The node is paused rather than failed: nothing was dispatched, so there is no failure to
    /// report about the action itself. Returning the error preserves `CAUSAL_LIMIT` all the way
    /// out to the caller instead of turning an exhausted chain into an ordinary paused run.
    ///
    /// A node or a run that has already been cancelled keeps its cancellation: the journal's own
    /// transaction decides that, so a refusal racing a cancellation cannot overwrite it.
    fn pause_on_refusal(
        &self,
        run_id: WorkflowRunId,
        node_id: &str,
        error: crate::error::AutomationError,
        now_ms: u64,
    ) -> Result<WorkflowRunStatus> {
        self.store
            .pause_on_refusal(run_id, node_id, &error.to_string(), now_ms)?;
        Err(error)
    }

    /// Cancels a workflow run: stops undispatched nodes and marks run cancelled.
    ///
    /// Nothing here claims anything about an external side effect an already dispatched action
    /// may have had. A cancelled node says the host stopped asking, not that the world is clean.
    ///
    /// # Errors
    ///
    /// Returns a storage error when the journal cannot be written.
    pub fn cancel_run(&self, run_id: WorkflowRunId, now_ms: u64) -> Result<()> {
        self.store
            .cancel_run(run_id, "run cancelled by request", now_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::definition::create_workflow_definition;
    use kr_protocol::automation::WorkflowEdge;
    use kr_protocol::ids::{GrantId, WorkflowId};
    use kr_protocol::scalars::Uuid;

    fn test_wf_id(v: u8) -> WorkflowId {
        WorkflowId::new(Uuid::from_bytes([v; 16]))
    }

    fn test_grant_id(v: u8) -> GrantId {
        GrantId::new(Uuid::from_bytes([v; 16]))
    }

    #[tokio::test]
    async fn dependency_executes_only_after_predecessor_success() {
        let store = Arc::new(WorkflowStore::in_memory().unwrap());
        let runner = Arc::new(MockActionRunner::new());
        let engine = WorkflowEngine::new(
            Arc::clone(&store),
            crate::test_host(
                runner,
                crate::authority::every_right(test_grant_id(1)),
                Arc::new(crate::ManualClock::new(1000)),
            ),
        );

        let wf_id = test_wf_id(1);
        let grant_id = test_grant_id(1);

        let n1 = crate::fixtures::node("step1", WorkflowActionKind::RunTests);
        let n2 = crate::fixtures::node("step2", WorkflowActionKind::RequestReview);
        let e1 = WorkflowEdge {
            from_node: "step1".to_owned(),
            to_node: "step2".to_owned(),
            condition: EdgeCondition::Success,
        };

        let def = create_workflow_definition(wf_id, 1, "test-wf", grant_id, vec![n1, n2], vec![e1]);
        store.save_definition(&def, 1000).unwrap();

        let run_id = WorkflowRunId::new(Uuid::from_bytes([20; 16]));
        let causal = CausalContext::new_root();

        store
            .commit_trigger_and_run(run_id, &def, "evt-1", &causal, 1000)
            .unwrap();

        let status = engine.execute_run(run_id, &def, &causal).await.unwrap();
        assert_eq!(status, WorkflowRunStatus::Completed);

        let receipts = store.list_node_receipts(run_id).unwrap();
        assert_eq!(receipts.len(), 2);
        assert_eq!(receipts[0].status, NodeStatus::Success);
        assert_eq!(receipts[1].status, NodeStatus::Success);
    }

    #[tokio::test]
    async fn unknown_outcome_pauses_dependants_for_review() {
        let store = Arc::new(WorkflowStore::in_memory().unwrap());
        let runner = Arc::new(MockActionRunner::new());
        runner.set_outcome(
            "step1",
            ActionOutcome::Unknown {
                detail: "process exited without conclusive receipt".to_owned(),
            },
        );

        let engine = WorkflowEngine::new(
            Arc::clone(&store),
            crate::test_host(
                runner,
                crate::authority::every_right(test_grant_id(2)),
                Arc::new(crate::ManualClock::new(1000)),
            ),
        );

        let wf_id = test_wf_id(2);
        let grant_id = test_grant_id(2);

        let n1 = crate::fixtures::node("step1", WorkflowActionKind::RunTests);
        let n2 = crate::fixtures::node("step2", WorkflowActionKind::RequestReview);
        let e1 = WorkflowEdge {
            from_node: "step1".to_owned(),
            to_node: "step2".to_owned(),
            condition: EdgeCondition::Success,
        };

        let def = create_workflow_definition(wf_id, 1, "test-wf", grant_id, vec![n1, n2], vec![e1]);
        store.save_definition(&def, 1000).unwrap();

        let run_id = WorkflowRunId::new(Uuid::from_bytes([21; 16]));
        let causal = CausalContext::new_root();

        store
            .commit_trigger_and_run(run_id, &def, "evt-1", &causal, 1000)
            .unwrap();

        let status = engine.execute_run(run_id, &def, &causal).await.unwrap();
        assert_eq!(status, WorkflowRunStatus::Paused);

        let receipts = store.list_node_receipts(run_id).unwrap();
        let step1 = receipts.iter().find(|r| r.node_id == "step1").unwrap();
        let step2 = receipts.iter().find(|r| r.node_id == "step2").unwrap();

        assert_eq!(step1.status, NodeStatus::Unknown);
        assert_eq!(step2.status, NodeStatus::Paused); // Paused for review!
    }
}
