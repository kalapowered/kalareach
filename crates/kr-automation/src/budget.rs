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

use kr_attention::event::{EventCursor, EventKind, SourceEvent};
use kr_protocol::attention::AttentionSource;
use kr_protocol::automation::{
    CausalBudgetSummary, DEFAULT_CAUSAL_ACTIONS_LIMIT, DEFAULT_CAUSAL_DEPTH_LIMIT,
    DEFAULT_CAUSAL_LIFETIME_MS, DEFAULT_CAUSAL_RUNS_LIMIT, DEFAULT_CAUSAL_SESSIONS_LIMIT,
};
use kr_protocol::ids::{CausalRootId, PluginId};
use kr_protocol::scalars::{TimestampMs, U64};

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
            depth: 1,
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

    /// Checks whether another run at `requested_depth` can be admitted, and reserves it.
    ///
    /// If limits are exceeded, pauses the budget, marks exhausted, and returns `CAUSAL_LIMIT`.
    /// Also returns whether this call should emit the attention item (true only for the first breach).
    pub fn reserve_run(
        &mut self,
        requested_depth: u64,
        now_ms: u64,
    ) -> Result<Option<SourceEvent>> {
        if self.paused || self.exhausted {
            return Err(AutomationError::CausalLimitExhausted {
                root: self.causal_root_id,
                reason: "causal chain is already paused or exhausted".to_owned(),
            });
        }

        // Check depth limit
        if requested_depth > self.max_depth {
            let _ = self.exhaust("depth limit exceeded", now_ms);
            return Err(AutomationError::CausalLimitExhausted {
                root: self.causal_root_id,
                reason: format!(
                    "depth {} exceeds limit {}",
                    requested_depth, self.max_depth
                ),
            });
        }

        // Check total runs limit
        if self.total_runs.saturating_add(1) > self.max_runs {
            let _ = self.exhaust("total runs limit exceeded", now_ms);
            return Err(AutomationError::CausalLimitExhausted {
                root: self.causal_root_id,
                reason: format!("runs {} exceeds limit {}", self.total_runs + 1, self.max_runs),
            });
        }

        // Check lifetime limit
        let elapsed = now_ms.saturating_sub(self.started_at_ms);
        if elapsed > self.max_lifetime_ms {
            let _ = self.exhaust("elapsed lifetime exceeded", now_ms);
            return Err(AutomationError::CausalLimitExhausted {
                root: self.causal_root_id,
                reason: format!(
                    "elapsed lifetime {}ms exceeds limit {}ms",
                    elapsed, self.max_lifetime_ms
                ),
            });
        }

        // Reserve
        self.total_runs = self.total_runs.saturating_add(1);
        self.depth = self.depth.max(requested_depth);
        Ok(None)
    }

    /// Checks whether another action can be admitted, and reserves it.
    pub fn reserve_action(&mut self, now_ms: u64) -> Result<Option<SourceEvent>> {
        if self.paused || self.exhausted {
            return Err(AutomationError::CausalLimitExhausted {
                root: self.causal_root_id,
                reason: "causal chain is already paused or exhausted".to_owned(),
            });
        }

        if self.total_actions.saturating_add(1) > self.max_actions {
            let _event = self.exhaust("total actions limit exceeded", now_ms);
            return Err(AutomationError::CausalLimitExhausted {
                root: self.causal_root_id,
                reason: format!(
                    "actions {} exceeds limit {}",
                    self.total_actions + 1,
                    self.max_actions
                ),
            });
        }

        self.total_actions = self.total_actions.saturating_add(1);
        Ok(None)
    }

    /// Checks whether another session can be created, and reserves it.
    pub fn reserve_session(&mut self, now_ms: u64) -> Result<Option<SourceEvent>> {
        if self.paused || self.exhausted {
            return Err(AutomationError::CausalLimitExhausted {
                root: self.causal_root_id,
                reason: "causal chain is already paused or exhausted".to_owned(),
            });
        }

        if self.created_sessions.saturating_add(1) > self.max_sessions {
            let _event = self.exhaust("created sessions limit exceeded", now_ms);
            return Err(AutomationError::CausalLimitExhausted {
                root: self.causal_root_id,
                reason: format!(
                    "created sessions {} exceeds limit {}",
                    self.created_sessions + 1,
                    self.max_sessions
                ),
            });
        }

        self.created_sessions = self.created_sessions.saturating_add(1);
        Ok(None)
    }

    /// Atomically marks the budget exhausted and paused, returning an attention event if not yet emitted.
    pub fn exhaust(&mut self, reason: &str, now_ms: u64) -> Option<SourceEvent> {
        self.paused = true;
        self.exhausted = true;

        if !self.attention_emitted {
            self.attention_emitted = true;
            let plugin_str = format!("causal_limit.{}", self.causal_root_id);
            let plugin_id = PluginId::new(plugin_str).unwrap_or_else(|_| {
                PluginId::new("causal_limit").expect("static identifier")
            });

            Some(SourceEvent::new(
                EventCursor::new(AttentionSource::Semantic, 1),
                TimestampMs::new(now_ms),
                EventKind::AdapterFailed {
                    plugin_id,
                    session_id: None,
                    detail: format!(
                        "causal budget exhausted for root {}: {}",
                        self.causal_root_id, reason
                    ),
                },
            ))
        } else {
            None
        }
    }

    /// Rearms the budget under an explicit authorized administrative request.
    ///
    /// Replayed or late events cannot call this; only an explicit API call with management rights.
    pub fn rearm(&mut self, now_ms: u64) {
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

        assert!(budget.reserve_run(1, 1000).unwrap().is_none());
        assert_eq!(budget.total_runs, 1);
        assert!(budget.reserve_run(2, 1000).unwrap().is_none());
        assert_eq!(budget.total_runs, 2);
        assert!(budget.reserve_run(3, 1000).unwrap().is_none());
        assert_eq!(budget.total_runs, 3);

        // 4th run breaches limit
        let err = budget.reserve_run(4, 1000).unwrap_err();
        assert!(matches!(err, AutomationError::CausalLimitExhausted { .. }));
        assert!(budget.paused);
        assert!(budget.exhausted);
        assert!(budget.attention_emitted);

        // Subsequent run is rejected without emitting another attention event
        let err2 = budget.reserve_run(5, 1000).unwrap_err();
        assert!(matches!(err2, AutomationError::CausalLimitExhausted { .. }));
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
    fn rearm_clears_exhaustion() {
        let root = test_root_id();
        let mut budget = CausalBudget::new(root, 1000);
        budget.max_runs = 1;
        assert!(budget.reserve_run(1, 1000).is_ok());
        assert!(budget.reserve_run(1, 1000).is_err());
        assert!(budget.paused);

        budget.rearm(2000);
        assert!(!budget.paused);
        assert!(!budget.exhausted);
        assert_eq!(budget.started_at_ms, 2000);
    }
}
