//! Causal context, root identities, and causal parent tracking.
//!
//! Section 25 requires that every workflow-created session, action, and derived trigger
//! retains the original host-verified causal root, depth, and parent.
//!
//! Everything in this module is derived by the host from its own journal. A caller never names a
//! parent, a root, a depth or a budget generation: a run started through `workflow.run` is an
//! external trigger and gets a root the host mints, and a run that descends from a workflow's own
//! node is started by the host from the journal's record of that node. That is what stops a
//! definition from resetting its root by changing workflow identifiers or minting fresh event
//! identifiers, and what makes an unauthenticated external callback a new external trigger rather
//! than a member of a chain it did not earn.

use kr_protocol::ids::{CausalRootId, WorkflowRunId};

use crate::store::StoredRunRecord;

/// The node a descendant run was triggered by, as the host recorded it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CausalParent {
    /// The run the node belongs to.
    pub run_id: WorkflowRunId,
    /// The node whose outcome triggered the descendant.
    pub node_id: String,
}

/// Host-verified causal context tracking a run's position in a causal execution graph.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CausalContext {
    /// Host-verified causal root identifier.
    pub root_id: CausalRootId,
    /// The causal budget generation this run belongs to.
    ///
    /// An authorised rearm advances the budget's generation. A descendant of a run from an
    /// earlier generation carries that earlier number and is refused, which is how a replayed
    /// or late event is kept from spending a budget it did not earn.
    pub generation: u64,
    /// Depth from the causal root. A root run sits at depth 1.
    pub depth: u64,
    /// Direct causal parent, as the host recorded it, when this run descends from another.
    pub parent: Option<CausalParent>,
}

impl CausalContext {
    /// Creates the context of a new independent root.
    ///
    /// The host mints the identifier. Nothing a caller supplies reaches it.
    #[must_use]
    pub fn new_root() -> Self {
        Self {
            root_id: CausalRootId::new(crate::new_uuid()),
            generation: 0,
            depth: 1,
            parent: None,
        }
    }

    /// Derives the context of a descendant from the parent run the host has on record.
    ///
    /// The root, the depth and the generation all come from `parent`, which is the journal's own
    /// record of the run whose node produced the trigger. A descendant of a pre-rearm run stays in
    /// the pre-rearm generation, where the budget refuses it.
    #[must_use]
    pub fn descendant_of(parent: &StoredRunRecord, node_id: &str) -> Self {
        Self {
            root_id: parent.causal_root_id,
            generation: parent.generation,
            depth: parent.depth.saturating_add(1),
            parent: Some(CausalParent {
                run_id: parent.run_id,
                node_id: node_id.to_owned(),
            }),
        }
    }

    /// The same position in the chain, in the budget generation an authorised rearm established.
    ///
    /// Only the rearm that continues a chain from a descendant its exhausted budget refused asks
    /// for this; every other descendant keeps its parent's generation.
    #[must_use]
    pub(crate) fn in_generation(self, generation: u64) -> Self {
        Self { generation, ..self }
    }

    /// Rebuilds the context a run was admitted under, from the run's own record.
    #[must_use]
    pub fn of_run(run: &StoredRunRecord) -> Self {
        Self {
            root_id: run.causal_root_id,
            generation: run.generation,
            depth: run.depth,
            parent: run
                .parent_run_id
                .zip(run.parent_node_id.clone())
                .map(|(run_id, node_id)| CausalParent { run_id, node_id }),
        }
    }
}
