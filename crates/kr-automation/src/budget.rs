//! Causal budgets: resource ceilings spanning cross-run and cross-workflow causal chains.
//!
//! Section 25 specifies:
//! - Chain resources reserved durably before each descendant dispatch.
//! - Defaults per causal root:
//!   - depth 16
//!   - 64 total runs
//!   - 100 actions
//!   - 10 created sessions
//!   - 1 hour elapsed lifetime
//!   - plus inherited managed-spend and resource ceilings.
//! - Limits span all participating workflows and survive restart.
//! - Exhaustion atomically pauses the chain with `CAUSAL_LIMIT`, rejects further descendants
//!   and emits exactly one attention item.
//! - Only an authorised rearm establishes a new budget; replayed or late events cannot rearm.

use kr_protocol::automation::{
    CausalBudgetSummary, DEFAULT_CAUSAL_ACTIONS_LIMIT, DEFAULT_CAUSAL_DEPTH_LIMIT,
    DEFAULT_CAUSAL_LIFETIME_MS, DEFAULT_CAUSAL_RUNS_LIMIT, DEFAULT_CAUSAL_SESSIONS_LIMIT,
};
use kr_protocol::ids::CausalRootId;
use kr_protocol::scalars::U64;

use crate::error::{AutomationError, Result};

/// A persistent causal budget governing one causal root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CausalBudget {
    /// Causal root identifier.
    pub causal_root_id: CausalRootId,
    /// Maximum depth reached.
    pub depth: u64,
    /// Maximum depth ceiling.
    pub max_depth: u64,
    /// Total workflow runs executed.
    pub total_runs: u64,
    /// Maximum allowed runs.
    pub max_runs: u64,
    /// Causal budget generation, incremented on rearm to reject late descendants.
    pub generation: u64,
    /// Total action nodes executed.
    pub total_actions: u64,
    /// Maximum allowed actions.
    pub max_actions: u64,
    /// Total sessions created.
    pub created_sessions: u64,
    /// Maximum allowed sessions.
    pub max_sessions: u64,
    /// Timestamp when causal root was created (UTC ms).
    pub started_at_ms: u64,
    /// Maximum elapsed lifetime in milliseconds.
    pub max_lifetime_ms: u64,
    /// Whether the chain is paused due to limit exhaustion.
    pub paused: bool,
    /// Whether any limit was breached.
    pub exhausted: bool,
    /// Whether the exceedance attention item has already been emitted.
    pub attention_emitted: bool,
    /// Timestamp of most recent rearm, if rearmed.
    pub rearmed_at_ms: Option<u64>,
}

impl CausalBudget {
    /// Creates a new causal budget with standard default limits.
    #[must_use]
    pub fn new(causal_root_id: CausalRootId, started_at_ms: u64) -> Self {
        Self {
            causal_root_id,
            generation: 0,
            depth: 0,
            max_depth: DEFAULT_CAUSAL_DEPTH_LIMIT,
            total_runs: 0,
            max_runs: DEFAULT_CAUSAL_RUNS_LIMIT,
            total_actions: 0,
            max_actions: DEFAULT_CAUSAL_ACTIONS_LIMIT,
            created_sessions: 0,
            max_sessions: DEFAULT_CAUSAL_SESSIONS_LIMIT,
            started_at_ms,
            max_lifetime_ms: DEFAULT_CAUSAL_LIFETIME_MS,
            paused: false,
            exhausted: false,
            attention_emitted: false,
            rearmed_at_ms: None,
        }
    }

    /// Checks that the caller's generation is current and not from a pre-rearm generation.
    pub fn check_generation(&self, descendant_generation: u64) -> Result<()> {
        if descendant_generation < self.generation {
            return Err(AutomationError::StaleCausalGeneration {
                root: self.causal_root_id,
                expected_generation: self.generation,
                found_generation: descendant_generation,
            });
        }
        Ok(())
    }

    /// Checks whether another run at `requested_depth` can be admitted, and reserves it.
    ///
    /// A breach pauses the chain, marks it exhausted and returns `CAUSAL_LIMIT`. The caller
    /// commits the changed budget, so the pause and the refusal land in one transaction.
    pub fn reserve_run(&mut self, requested_depth: u64, now_ms: u64) -> Result<()> {
        self.check_open()?;
        self.check_lifetime(now_ms)?;

        if requested_depth > self.max_depth {
            return Err(self.exceeded(format!(
                "depth {} exceeds limit {}",
                requested_depth, self.max_depth
            )));
        }

        if self.total_runs.saturating_add(1) > self.max_runs {
            return Err(self.exceeded(format!(
                "runs {} exceeds limit {}",
                self.total_runs + 1,
                self.max_runs
            )));
        }

        self.total_runs = self.total_runs.saturating_add(1);
        self.depth = self.depth.max(requested_depth);
        Ok(())
    }

    /// Checks whether another action can be admitted, and reserves it.
    pub fn reserve_action(&mut self, now_ms: u64) -> Result<()> {
        self.check_open()?;
        self.check_lifetime(now_ms)?;

        if self.total_actions.saturating_add(1) > self.max_actions {
            return Err(self.exceeded(format!(
                "actions {} exceeds limit {}",
                self.total_actions + 1,
                self.max_actions
            )));
        }

        self.total_actions = self.total_actions.saturating_add(1);
        Ok(())
    }

    /// Checks whether another session can be created, and reserves it.
    pub fn reserve_session(&mut self, now_ms: u64) -> Result<()> {
        self.check_open()?;
        self.check_lifetime(now_ms)?;

        if self.created_sessions.saturating_add(1) > self.max_sessions {
            return Err(self.exceeded(format!(
                "created sessions {} exceeds limit {}",
                self.created_sessions + 1,
                self.max_sessions
            )));
        }

        self.created_sessions = self.created_sessions.saturating_add(1);
        Ok(())
    }

    /// Refuses anything further once the chain is paused or exhausted.
    fn check_open(&self) -> Result<()> {
        if self.paused || self.exhausted {
            return Err(AutomationError::CausalLimitExhausted {
                root: self.causal_root_id,
                reason: "causal chain is already paused or exhausted".to_owned(),
            });
        }
        Ok(())
    }

    /// The elapsed lifetime is read before every reservation, not only at the first run.
    fn check_lifetime(&mut self, now_ms: u64) -> Result<()> {
        let elapsed = now_ms.saturating_sub(self.started_at_ms);
        if elapsed > self.max_lifetime_ms {
            return Err(self.exceeded(format!(
                "elapsed lifetime {}ms exceeds limit {}ms",
                elapsed, self.max_lifetime_ms
            )));
        }
        Ok(())
    }

    /// Pauses the chain, marks it exhausted and builds the `CAUSAL_LIMIT` refusal.
    fn exceeded(&mut self, reason: String) -> AutomationError {
        self.exhaust();
        AutomationError::CausalLimitExhausted {
            root: self.causal_root_id,
            reason,
        }
    }

    /// Pauses and exhausts the chain.
    ///
    /// Returns whether this call is the transition that owes an attention item. Every later
    /// refusal returns `false`, which is how one exhausted chain produces exactly one item.
    pub fn exhaust(&mut self) -> bool {
        self.paused = true;
        self.exhausted = true;
        if self.attention_emitted {
            false
        } else {
            self.attention_emitted = true;
            true
        }
    }

    /// Rearms the budget under an authorised administrative request.
    ///
    /// The chain gets a fresh generation and fresh counters, so the same ceilings are usable
    /// again without anybody raising them. Runs from the previous generation keep their old
    /// number, and [`Self::check_generation`] refuses them: a replayed or late event cannot
    /// spend the new budget, and it cannot rearm one of its own.
    pub fn rearm(&mut self, now_ms: u64) {
        self.generation = self.generation.saturating_add(1);
        self.total_runs = 0;
        self.total_actions = 0;
        self.created_sessions = 0;
        self.depth = 0;
        self.paused = false;
        self.exhausted = false;
        self.attention_emitted = false;
        self.started_at_ms = now_ms;
        self.rearmed_at_ms = Some(now_ms);
    }

    /// Converts this budget into the protocol summary wire shape.
    #[must_use]
    pub fn to_summary(&self, now_ms: u64) -> CausalBudgetSummary {
        let elapsed = now_ms.saturating_sub(self.started_at_ms);
        CausalBudgetSummary {
            causal_root_id: self.causal_root_id,
            depth: U64::new(self.depth),
            max_depth: U64::new(self.max_depth),
            total_runs: U64::new(self.total_runs),
            max_runs: U64::new(self.max_runs),
            total_actions: U64::new(self.total_actions),
            max_actions: U64::new(self.max_actions),
            created_sessions: U64::new(self.created_sessions),
            max_sessions: U64::new(self.max_sessions),
            elapsed_lifetime_ms: U64::new(elapsed),
            max_lifetime_ms: U64::new(self.max_lifetime_ms),
            paused: self.paused,
            exhausted: self.exhausted,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::scalars::Uuid;

    fn test_root_id() -> CausalRootId {
        CausalRootId::new(Uuid::from_bytes([42; 16]))
    }

    #[test]
    fn budget_tracks_runs_and_exhausts_at_limit() {
        let root = test_root_id();
        let mut budget = CausalBudget::new(root, 1000);
        budget.max_runs = 3;

        budget.reserve_run(1, 1000).unwrap();
        assert_eq!(budget.total_runs, 1);
        budget.reserve_run(2, 1000).unwrap();
        assert_eq!(budget.total_runs, 2);
        budget.reserve_run(3, 1000).unwrap();
        assert_eq!(budget.total_runs, 3);

        // 4th run breaches limit
        let err = budget.reserve_run(4, 1000).unwrap_err();
        assert!(matches!(err, AutomationError::CausalLimitExhausted { .. }));
        assert!(budget.paused);
        assert!(budget.exhausted);
        assert!(budget.attention_emitted);

        // Subsequent run is rejected without owing a second attention item
        let err2 = budget.reserve_run(5, 1000).unwrap_err();
        assert!(matches!(err2, AutomationError::CausalLimitExhausted { .. }));
        assert!(!budget.exhaust());
    }

    #[test]
    fn budget_enforces_depth_limit() {
        let root = test_root_id();
        let mut budget = CausalBudget::new(root, 1000);
        budget.max_depth = 5;

        assert!(budget.reserve_run(4, 1000).is_ok());
        assert!(budget.reserve_run(5, 1000).is_ok());
        let err = budget.reserve_run(6, 1000).unwrap_err();
        assert!(matches!(err, AutomationError::CausalLimitExhausted { .. }));
    }

    #[test]
    fn budget_enforces_lifetime_limit() {
        let root = test_root_id();
        let mut budget = CausalBudget::new(root, 1_000);
        budget.max_lifetime_ms = 5_000;

        assert!(budget.reserve_run(1, 2_000).is_ok());
        assert!(budget.reserve_run(1, 5_000).is_ok());
        let err = budget.reserve_run(1, 7_000).unwrap_err(); // elapsed = 6000 > 5000
        assert!(matches!(err, AutomationError::CausalLimitExhausted { .. }));
    }

    #[test]
    fn rearm_establishes_a_fresh_usable_generation() {
        let root = test_root_id();
        let mut budget = CausalBudget::new(root, 1000);
        budget.max_runs = 1;
        budget.reserve_run(1, 1000).unwrap();
        assert!(budget.reserve_run(1, 1000).is_err());
        assert!(budget.paused);

        budget.rearm(2000);
        assert!(!budget.paused);
        assert!(!budget.exhausted);
        assert!(!budget.attention_emitted);
        assert_eq!(budget.started_at_ms, 2000);
        assert_eq!(budget.generation, 1);

        // The same ceiling is usable again, because the counters were reset with it.
        assert_eq!(budget.total_runs, 0);
        budget.reserve_run(1, 2000).unwrap();

        // A descendant of a run from the generation before the rearm is refused.
        let err = budget.check_generation(0).unwrap_err();
        assert!(matches!(
            err,
            AutomationError::StaleCausalGeneration {
                expected_generation: 1,
                found_generation: 0,
                ..
            }
        ));
    }
}
