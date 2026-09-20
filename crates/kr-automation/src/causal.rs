//! Causal context, root identities, and causal parent tracking.
//!
//! Section 25 requires that every workflow-created session, action, and derived trigger
//! retains the original host-verified causal root, depth, and parent.
//!
//! Everything in this module is derived by the host from its own journal. A caller names a
//! parent run and a parent node; it never names the root, the depth or the budget generation.
//! That is what stops a definition from resetting its root by changing workflow identifiers or
//! minting fresh event identifiers, and what makes an unauthenticated external callback a new
//! external trigger rather than a member of a chain it did not earn.

use kr_protocol::automation::CausalParentRef;
use kr_protocol::ids::CausalRootId;
use kr_protocol::scalars::U64;

use crate::store::StoredRunRecord;

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
    pub parent: Option<CausalParentRef>,
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
    /// The root and the depth come from `parent`, never from the request that asked for the
    /// run. `generation` is the parent run's own generation, so a descendant of a pre-rearm
    /// run stays in the pre-rearm generation.
    #[must_use]
    pub fn descendant_of(parent: &StoredRunRecord, parent_node_id: &str) -> Self {
        Self {
            root_id: parent.causal_root_id,
            generation: parent.generation,
            depth: parent.depth.saturating_add(1),
            parent: Some(CausalParentRef {
                causal_root_id: parent.causal_root_id,
                parent_run_id: parent.run_id,
                parent_node_id: parent_node_id.to_owned(),
                depth: U64::new(parent.depth),
            }),
        }
    }
}
