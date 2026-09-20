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
    EdgeCondition, NodeStatus, WorkflowDefinition, WorkflowNode, WorkflowRunStatus,
};
use kr_protocol::ids::{ActionId, WorkflowRunId};

use crate::causal::CausalContext;
use crate::error::Result;
use crate::store::WorkflowStore;
use crate::{HostClock, SystemClock};

/// Node execution outcome from an action executor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ActionOutcome {
    /// Action completed with authoritative success.
    Success {
        /// Result output data.
        output: String,
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

/// Trait implemented by action node runners (e.g., shell commands, test runners, reviews).
pub trait ActionRunner: Send + Sync {
    /// Executes one action node.
    fn execute(
        &self,
        node: &WorkflowNode,
        action_id: ActionId,
        now_ms: u64,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<ActionOutcome>> + Send>>;
}

/// A default test/mock action runner.
#[derive(Default)]
pub struct MockActionRunner {
    outcomes: std::sync::Mutex<HashMap<String, ActionOutcome>>,
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
}

impl ActionRunner for MockActionRunner {
    fn execute(
        &self,
        node: &WorkflowNode,
        _action_id: ActionId,
        _now_ms: u64,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<ActionOutcome>> + Send>> {
        let outcome = self
            .outcomes
            .lock()
            .unwrap()
            .get(&node.node_id)
            .cloned()
            .unwrap_or_else(|| ActionOutcome::Success {
                output: format!("mock-success for {}", node.node_id),
            });
        Box::pin(async move { Ok(outcome) })
    }
}

/// Coordinates execution of a workflow run.
pub struct WorkflowEngine {
    store: Arc<WorkflowStore>,
    runner: Arc<dyn ActionRunner>,
    clock: Arc<dyn HostClock>,
}

impl WorkflowEngine {
    /// Creates a workflow execution engine reading the host's wall clock.
    #[must_use]
    pub fn new(store: Arc<WorkflowStore>, runner: Arc<dyn ActionRunner>) -> Self {
        Self::with_clock(store, runner, Arc::new(SystemClock))
    }

    /// Creates a workflow execution engine reading the clock it is given.
    #[must_use]
    pub fn with_clock(
        store: Arc<WorkflowStore>,
        runner: Arc<dyn ActionRunner>,
        clock: Arc<dyn HostClock>,
    ) -> Self {
        Self {
            store,
            runner,
            clock,
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

        // Update run status to Running
        self.store
            .update_run_status(run_id, WorkflowRunStatus::Running, None)?;

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
                    node_statuses.insert(node.node_id.clone(), NodeStatus::Paused);
                    self.store.update_node_receipt(
                        run_id,
                        &node.node_id,
                        NodeStatus::Paused,
                        None,
                        Some("paused for review due to unknown predecessor outcome"),
                        Some(now_ms),
                    )?;
                    run_status = WorkflowRunStatus::Paused;
                    progress = true;
                    continue;
                }

                if can_run {
                    // Every reservation is checked against the clock as it stands now, not
                    // against the time the run was admitted, so a chain cannot keep spending
                    // after its lifetime has run out.
                    let dispatch_time_ms = self.clock.now_ms();

                    // A node that creates a session spends the chain's session allowance as
                    // well as its action allowance, and both are reserved before dispatch.
                    if node.action_kind == "create_session"
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
                        dispatch_time_ms,
                    ) {
                        return self.pause_on_refusal(run_id, &node.node_id, err, dispatch_time_ms);
                    }

                    // Mark running
                    node_statuses.insert(node.node_id.clone(), NodeStatus::Running);
                    self.store.update_node_receipt(
                        run_id,
                        &node.node_id,
                        NodeStatus::Running,
                        None,
                        None,
                        None,
                    )?;

                    let action_id = node_actions[&node.node_id];
                    let outcome_res = self.runner.execute(node, action_id, dispatch_time_ms).await;

                    match outcome_res {
                        Ok(ActionOutcome::Success { output }) => {
                            node_statuses.insert(node.node_id.clone(), NodeStatus::Success);
                            self.store.update_node_receipt(
                                run_id,
                                &node.node_id,
                                NodeStatus::Success,
                                Some(&output),
                                None,
                                Some(self.clock.now_ms()),
                            )?;
                        }
                        Ok(ActionOutcome::Failed { error }) => {
                            node_statuses.insert(node.node_id.clone(), NodeStatus::Failed);
                            self.store.update_node_receipt(
                                run_id,
                                &node.node_id,
                                NodeStatus::Failed,
                                None,
                                Some(&error),
                                Some(self.clock.now_ms()),
                            )?;
                            run_status = WorkflowRunStatus::Failed;
                        }
                        Ok(ActionOutcome::Unknown { detail }) => {
                            // Node marked Unknown -> dependants will pause
                            node_statuses.insert(node.node_id.clone(), NodeStatus::Unknown);
                            self.store.update_node_receipt(
                                run_id,
                                &node.node_id,
                                NodeStatus::Unknown,
                                None,
                                Some(&detail),
                                Some(self.clock.now_ms()),
                            )?;
                            run_status = WorkflowRunStatus::Paused;
                        }
                        Err(err) => {
                            node_statuses.insert(node.node_id.clone(), NodeStatus::Failed);
                            self.store.update_node_receipt(
                                run_id,
                                &node.node_id,
                                NodeStatus::Failed,
                                None,
                                Some(&err.to_string()),
                                Some(self.clock.now_ms()),
                            )?;
                            run_status = WorkflowRunStatus::Failed;
                        }
                    }

                    progress = true;
                }
            }
        }

        // Check if any node is paused or unknown
        if node_statuses
            .values()
            .any(|&s| s == NodeStatus::Paused || s == NodeStatus::Unknown)
        {
            run_status = WorkflowRunStatus::Paused;
        } else if node_statuses.values().any(|&s| s == NodeStatus::Failed) {
            run_status = WorkflowRunStatus::Failed;
        }

        self.store
            .update_run_status(run_id, run_status, Some(self.clock.now_ms()))?;
        Ok(run_status)
    }

    /// Records a refused reservation and pauses the run, keeping the refusal for the caller.
    ///
    /// The node is paused rather than failed: nothing was dispatched, so there is no failure to
    /// report about the action itself. Returning the error preserves `CAUSAL_LIMIT` all the way
    /// out to the caller instead of turning an exhausted chain into an ordinary paused run.
    fn pause_on_refusal(
        &self,
        run_id: WorkflowRunId,
        node_id: &str,
        error: crate::error::AutomationError,
        now_ms: u64,
    ) -> Result<WorkflowRunStatus> {
        self.store.update_node_receipt(
            run_id,
            node_id,
            NodeStatus::Paused,
            None,
            Some(&error.to_string()),
            Some(now_ms),
        )?;
        self.store
            .update_run_status(run_id, WorkflowRunStatus::Paused, Some(now_ms))?;
        Err(error)
    }

    /// Cancels a workflow run: stops undispatched nodes and marks run cancelled.
    ///
    /// Nothing here claims anything about an external side effect an already dispatched action
    /// may have had. A cancelled node says the host stopped asking, not that the world is clean.
    pub fn cancel_run(&self, run_id: WorkflowRunId, now_ms: u64) -> Result<()> {
        let receipts = self.store.list_node_receipts(run_id)?;
        for receipt in receipts {
            if receipt.status == NodeStatus::Pending || receipt.status == NodeStatus::Running {
                self.store.update_node_receipt(
                    run_id,
                    &receipt.node_id,
                    NodeStatus::Cancelled,
                    None,
                    Some("run cancelled by request"),
                    Some(now_ms),
                )?;
            }
        }
        self.store
            .update_run_status(run_id, WorkflowRunStatus::Cancelled, Some(now_ms))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::definition::create_workflow_definition;
    use kr_protocol::automation::WorkflowEdge;
    use kr_protocol::ids::{GrantId, WorkflowId};
    use kr_protocol::scalars::{Nullable, Uuid};

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
        let engine = WorkflowEngine::with_clock(
            Arc::clone(&store),
            runner,
            Arc::new(crate::ManualClock::new(1000)),
        );

        let wf_id = test_wf_id(1);
        let grant_id = test_grant_id(1);

        let n1 = WorkflowNode {
            node_id: "step1".to_owned(),
            action_kind: "run_tests".to_owned(),
            action_params: r#"{"suite": "unit"}"#.to_owned(),
            declared_environment: Nullable::null(),
        };
        let n2 = WorkflowNode {
            node_id: "step2".to_owned(),
            action_kind: "request_review".to_owned(),
            action_params: r#"{"reviewer_id": "bob"}"#.to_owned(),
            declared_environment: Nullable::null(),
        };
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

        let engine = WorkflowEngine::with_clock(
            Arc::clone(&store),
            runner,
            Arc::new(crate::ManualClock::new(1000)),
        );

        let wf_id = test_wf_id(2);
        let grant_id = test_grant_id(2);

        let n1 = WorkflowNode {
            node_id: "step1".to_owned(),
            action_kind: "run_tests".to_owned(),
            action_params: r#"{"suite": "unit"}"#.to_owned(),
            declared_environment: Nullable::null(),
        };
        let n2 = WorkflowNode {
            node_id: "step2".to_owned(),
            action_kind: "request_review".to_owned(),
            action_params: r#"{"reviewer_id": "bob"}"#.to_owned(),
            declared_environment: Nullable::null(),
        };
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
