//! Causal context, root identities, and causal parent tracking.
//!
//! Section 25 requires that every workflow-created session, action, and derived trigger
//! retains the original host-verified causal root, depth, and parent.
//!
//! A definition cannot retrigger on its own descendants by default, and explicit recurrence
//! cannot reset the root by changing workflow IDs or minting fresh event IDs.

use kr_protocol::automation::CausalParentRef;
use kr_protocol::ids::{CausalRootId, WorkflowId, WorkflowRunId};
use kr_protocol::scalars::U64;

/// Host-verified causal context tracking a run's position in a causal execution graph.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CausalContext {
    /// Host-verified causal root identifier.
    pub root_id: CausalRootId,
    /// Current depth from the causal root (starts at 1 for root run).
    pub depth: u64,
    /// Direct causal parent, if this run was triggered by another workflow node.
    pub parent: Option<CausalParentRef>,
    /// List of ancestor workflow IDs in the chain, preventing self-retrigger loops.
    pub ancestors: Vec<WorkflowId>,
}

impl CausalContext {
    /// Creates a new root causal context for an independent or external trigger.
    #[must_use]
    pub fn new_root(workflow_id: WorkflowId) -> Self {
        Self {
            root_id: CausalRootId::new(crate::new_uuid()),
            depth: 1,
            parent: None,
            ancestors: vec![workflow_id],
        }
    }

    /// Creates a causal context with an existing root ID (e.g. from durable store).
    #[must_use]
    pub fn from_existing_root(root_id: CausalRootId, workflow_id: WorkflowId) -> Self {
        Self {
            root_id,
            depth: 1,
            parent: None,
            ancestors: vec![workflow_id],
        }
    }

    /// Derives a child causal context for a descendant triggered by a parent run.
    #[must_use]
    pub fn derive_child(
        &self,
        parent_run_id: WorkflowRunId,
        parent_node_id: &str,
        child_workflow_id: WorkflowId,
    ) -> Self {
        let mut ancestors = self.ancestors.clone();
        if !ancestors.contains(&child_workflow_id) {
            ancestors.push(child_workflow_id);
        }
        Self {
            root_id: self.root_id,
            depth: self.depth.saturating_add(1),
            parent: Some(CausalParentRef {
                causal_root_id: self.root_id,
                parent_run_id,
                parent_node_id: parent_node_id.to_owned(),
                depth: U64::new(self.depth),
            }),
            ancestors,
        }
    }

    /// Checks if the given workflow ID is an ancestor in this causal chain.
    #[must_use]
    pub fn contains_ancestor(&self, workflow_id: &WorkflowId) -> bool {
        self.ancestors.contains(workflow_id)
    }
}
