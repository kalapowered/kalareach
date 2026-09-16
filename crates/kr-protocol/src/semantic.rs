//! Bounds on a semantic snapshot, and the continuation that stands where they stop.
//!
//! Section 8 fixes three limits on a semantic snapshot at once: 16 MiB of encoded content across
//! every part, a tree no deeper than sixteen levels, and no more than twenty thousand nodes.
//! Exceeding any one of them yields a paged or truncated representation with an explicit
//! continuation, never an unbounded tree.
//!
//! The producer of the tree is not here. What is here is the budget a producer spends and the
//! continuation it emits when the budget runs out, because that is the part a reader has to be
//! able to trust whatever built the tree: a snapshot that stopped short says so, says which limit
//! stopped it, and says where a reader asks for the rest. A truncation that looked like a complete
//! tree would be worse than a refusal, because nothing downstream could tell the difference.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::scalars::{Nullable, U64};

/// Maximum encoded bytes one semantic snapshot may carry, across every part.
pub const MAX_SEMANTIC_SNAPSHOT_BYTES: u64 = 16 * 1024 * 1024;

/// Maximum depth of a semantic tree. The root is depth one.
pub const MAX_SEMANTIC_TREE_DEPTH: u64 = 16;

/// Maximum nodes in a semantic tree.
pub const MAX_SEMANTIC_TREE_NODES: u64 = 20_000;

/// Which limit stopped a semantic snapshot.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum SemanticLimit {
    /// The total encoded size.
    Bytes,
    /// The tree depth.
    Depth,
    /// The node count.
    Nodes,
}

impl SemanticLimit {
    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bytes => "bytes",
            Self::Depth => "depth",
            Self::Nodes => "nodes",
        }
    }

    /// Returns the value of this limit.
    #[must_use]
    pub const fn value(self) -> u64 {
        match self {
            Self::Bytes => MAX_SEMANTIC_SNAPSHOT_BYTES,
            Self::Depth => MAX_SEMANTIC_TREE_DEPTH,
            Self::Nodes => MAX_SEMANTIC_TREE_NODES,
        }
    }
}

/// Where a reader continues a semantic snapshot that stopped short.
///
/// It is present exactly when something was left out. A snapshot with no continuation is the whole
/// tree; one with a continuation is a part, and the fields say what to ask for next.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SemanticContinuation {
    /// Which limit stopped this part.
    pub limit: SemanticLimit,
    /// The value of that limit, so a reader does not have to hold this build's constants.
    pub limit_value: U64,
    /// The node the next part starts at, counted over the producer's own walk order.
    pub from_node: U64,
    /// How many nodes this part carried.
    pub nodes: U64,
    /// How many encoded bytes this part carried.
    pub bytes: U64,
}

/// A semantic snapshot's three limits, spent as a producer walks its tree.
///
/// Every limit is checked before a node is admitted, so nothing is allocated for a node the
/// snapshot cannot carry. The budget is deliberately not a validator that runs afterwards: a tree
/// that has already been built is a tree that has already been paid for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SemanticBudget {
    max_bytes: u64,
    max_depth: u64,
    max_nodes: u64,
    nodes: u64,
    bytes: u64,
}

impl Default for SemanticBudget {
    fn default() -> Self {
        Self::new()
    }
}

impl SemanticBudget {
    /// Builds a budget at section 8's limits.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            max_bytes: MAX_SEMANTIC_SNAPSHOT_BYTES,
            max_depth: MAX_SEMANTIC_TREE_DEPTH,
            max_nodes: MAX_SEMANTIC_TREE_NODES,
            nodes: 0,
            bytes: 0,
        }
    }

    /// Builds a budget whose byte allowance is the smaller of a caller's request and the limit.
    ///
    /// A caller can ask for less. It cannot ask for more: the limit is the contract, not a default.
    #[must_use]
    pub const fn with_max_bytes(requested: u64) -> Self {
        let mut budget = Self::new();
        if requested < budget.max_bytes {
            budget.max_bytes = requested;
        }
        budget
    }

    /// Returns how many nodes have been admitted.
    #[must_use]
    pub const fn nodes(&self) -> u64 {
        self.nodes
    }

    /// Returns how many encoded bytes have been admitted.
    #[must_use]
    pub const fn bytes(&self) -> u64 {
        self.bytes
    }

    /// Admits one node at `depth`, carrying `bytes` of encoded content.
    ///
    /// `depth` counts the root as one. Returns `Ok(())` when the node is part of this snapshot,
    /// and the limit that stopped it otherwise. A refused node is not counted, so a producer that
    /// walks its siblings after a refusal spends nothing on them either.
    ///
    /// # Errors
    ///
    /// Returns the [`SemanticLimit`] a node would have exceeded.
    pub const fn admit(&mut self, depth: u64, bytes: u64) -> Result<(), SemanticLimit> {
        if depth == 0 || depth > self.max_depth {
            return Err(SemanticLimit::Depth);
        }
        if self.nodes >= self.max_nodes {
            return Err(SemanticLimit::Nodes);
        }
        let Some(total) = self.bytes.checked_add(bytes) else {
            return Err(SemanticLimit::Bytes);
        };
        if total > self.max_bytes {
            return Err(SemanticLimit::Bytes);
        }
        self.nodes += 1;
        self.bytes = total;
        Ok(())
    }

    /// Builds the continuation a refused node produces.
    ///
    /// `from_node` is where the next part begins in the producer's own walk order, which is the
    /// node that was refused.
    #[must_use]
    pub const fn continuation(&self, limit: SemanticLimit, from_node: u64) -> SemanticContinuation {
        // The limit this budget is actually spending, which is the specification's except where a
        // caller asked for less. Reporting the constant would tell a reader it had 16 MiB left when
        // its own request was what stopped it.
        let limit_value = match limit {
            SemanticLimit::Bytes => self.max_bytes,
            SemanticLimit::Depth => self.max_depth,
            SemanticLimit::Nodes => self.max_nodes,
        };
        SemanticContinuation {
            limit,
            limit_value: U64::new(limit_value),
            from_node: U64::new(from_node),
            nodes: U64::new(self.nodes),
            bytes: U64::new(self.bytes),
        }
    }

    /// Returns the continuation field of a part that carried the whole tree.
    #[must_use]
    pub const fn complete() -> Nullable<SemanticContinuation> {
        Nullable::null()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_three_bounds_are_the_ones_section_eight_states() {
        assert_eq!(MAX_SEMANTIC_SNAPSHOT_BYTES, 16 * 1024 * 1024);
        assert_eq!(MAX_SEMANTIC_TREE_DEPTH, 16);
        assert_eq!(MAX_SEMANTIC_TREE_NODES, 20_000);
    }

    #[test]
    fn a_node_below_every_bound_is_admitted() {
        let mut budget = SemanticBudget::new();
        budget.admit(1, 128).expect("the root");
        budget.admit(16, 128).expect("the deepest level");
        assert_eq!(budget.nodes(), 2);
        assert_eq!(budget.bytes(), 256);
    }

    #[test]
    fn a_seventeenth_level_is_refused_as_a_depth_rather_than_truncated_silently() {
        let mut budget = SemanticBudget::new();
        assert_eq!(budget.admit(17, 1), Err(SemanticLimit::Depth));
        assert_eq!(budget.nodes(), 0, "a refused node costs nothing");
        let continuation = budget.continuation(SemanticLimit::Depth, 40);
        assert_eq!(continuation.limit, SemanticLimit::Depth);
        assert_eq!(continuation.limit_value.get(), 16);
        assert_eq!(continuation.from_node.get(), 40);
    }

    #[test]
    fn the_node_count_stops_the_walk_and_names_where_to_continue() {
        let mut budget = SemanticBudget::new();
        for _ in 0..MAX_SEMANTIC_TREE_NODES {
            budget.admit(2, 1).expect("within the node bound");
        }
        assert_eq!(budget.admit(2, 1), Err(SemanticLimit::Nodes));
        let continuation = budget.continuation(SemanticLimit::Nodes, MAX_SEMANTIC_TREE_NODES);
        assert_eq!(continuation.nodes.get(), MAX_SEMANTIC_TREE_NODES);
        assert_eq!(continuation.from_node.get(), MAX_SEMANTIC_TREE_NODES);
    }

    #[test]
    fn the_total_size_is_checked_before_anything_is_carried() {
        let mut budget = SemanticBudget::new();
        assert_eq!(
            budget.admit(1, MAX_SEMANTIC_SNAPSHOT_BYTES + 1),
            Err(SemanticLimit::Bytes)
        );
        budget
            .admit(1, MAX_SEMANTIC_SNAPSHOT_BYTES)
            .expect("exactly the limit fits");
        assert_eq!(budget.admit(1, 1), Err(SemanticLimit::Bytes));
    }

    #[test]
    fn an_addition_that_would_overflow_is_a_size_refusal_rather_than_a_wrap() {
        let mut budget = SemanticBudget::new();
        budget.admit(1, 1).expect("one byte");
        assert_eq!(budget.admit(1, u64::MAX), Err(SemanticLimit::Bytes));
    }

    #[test]
    fn a_caller_can_ask_for_less_than_the_limit_but_never_for_more() {
        let mut budget = SemanticBudget::with_max_bytes(512);
        assert_eq!(budget.admit(1, 513), Err(SemanticLimit::Bytes));
        assert_eq!(
            budget
                .continuation(SemanticLimit::Bytes, 0)
                .limit_value
                .get(),
            512,
            "the continuation reports the budget that stopped it, not the one it could have had"
        );
        let mut generous = SemanticBudget::with_max_bytes(u64::MAX);
        assert_eq!(
            generous.admit(1, MAX_SEMANTIC_SNAPSHOT_BYTES + 1),
            Err(SemanticLimit::Bytes),
            "the limit is the contract, not a default"
        );
    }

    #[test]
    fn a_complete_part_carries_no_continuation() {
        assert!(!SemanticBudget::complete().is_present());
    }
}
