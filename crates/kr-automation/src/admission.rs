//! Host and per-grant admission rates and per-workflow concurrency control.
//!
//! Section 17 ¶8 and Section 25 specify:
//! - Per-workflow defaults: 4 concurrent runs, 100 pending runs, 30-minute run deadline,
//!   10-minute maximum action wait.
//! - A breached limit pauses the workflow and emits an attention event.
//! - Per-host and per-grant admission rates apply beyond per-workflow concurrency.
//! - Unauthenticated external callbacks are treated as new external triggers under host-wide limits.

use std::collections::HashMap;

use kr_protocol::automation::{DEFAULT_WORKFLOW_CONCURRENT_RUNS, DEFAULT_WORKFLOW_PENDING_RUNS};
use kr_protocol::ids::{GrantId, WorkflowId};

use crate::error::{AutomationError, Result};

/// Default host-wide maximum dispatches per minute.
pub const DEFAULT_HOST_MAX_DISPATCHES_PER_MINUTE: u64 = 600;
/// Default per-grant maximum dispatches per minute.
pub const DEFAULT_GRANT_MAX_DISPATCHES_PER_MINUTE: u64 = 120;

/// Manages admission rates and concurrency limits.
#[derive(Debug)]
pub struct AdmissionController {
    /// Active runs currently executing per workflow.
    pub active_runs: HashMap<WorkflowId, u64>,
    /// Pending runs currently queued per workflow.
    pub pending_runs: HashMap<WorkflowId, u64>,
    /// Timestamps of recent host-wide dispatches for sliding window rate limiting.
    pub host_dispatches: Vec<u64>,
    /// Timestamps of recent dispatches per grant.
    pub grant_dispatches: HashMap<GrantId, Vec<u64>>,
    /// Configured host-wide maximum dispatches per minute.
    pub host_rate_limit: u64,
    /// Configured per-grant maximum dispatches per minute.
    pub grant_rate_limit: u64,
}

impl Default for AdmissionController {
    fn default() -> Self {
        Self {
            active_runs: HashMap::new(),
            pending_runs: HashMap::new(),
            host_dispatches: Vec::new(),
            grant_dispatches: HashMap::new(),
            host_rate_limit: DEFAULT_HOST_MAX_DISPATCHES_PER_MINUTE,
            grant_rate_limit: DEFAULT_GRANT_MAX_DISPATCHES_PER_MINUTE,
        }
    }
}

impl AdmissionController {
    /// Creates a new admission controller.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Checks host-wide and per-grant admission rates and per-workflow concurrency.
    ///
    /// If concurrency is breached, returns an error and indicates that the workflow must be paused.
    pub fn admit_run(
        &mut self,
        workflow_id: WorkflowId,
        grant_id: GrantId,
        now_ms: u64,
        max_concurrent: Option<u64>,
        max_pending: Option<u64>,
    ) -> Result<()> {
        let max_conc = max_concurrent.unwrap_or(DEFAULT_WORKFLOW_CONCURRENT_RUNS);
        let max_pend = max_pending.unwrap_or(DEFAULT_WORKFLOW_PENDING_RUNS);

        // Check per-workflow concurrency
        let current_active = self.active_runs.get(&workflow_id).copied().unwrap_or(0);
        if current_active >= max_conc {
            return Err(AutomationError::ConcurrencyLimitExceeded {
                workflow_id,
                limit: max_conc,
            });
        }

        let current_pending = self.pending_runs.get(&workflow_id).copied().unwrap_or(0);
        if current_pending >= max_pend {
            return Err(AutomationError::ConcurrencyLimitExceeded {
                workflow_id,
                limit: max_pend,
            });
        }

        // Check host-wide rate limit (1 minute window)
        let one_minute_ago = now_ms.saturating_sub(60_000);
        self.host_dispatches.retain(|&ts| ts >= one_minute_ago);
        if self.host_dispatches.len() as u64 >= self.host_rate_limit {
            return Err(AutomationError::RateLimitExceeded {
                reason: format!(
                    "host-wide rate limit of {}/min exceeded",
                    self.host_rate_limit
                ),
            });
        }

        // Check per-grant rate limit (1 minute window)
        let grant_history = self.grant_dispatches.entry(grant_id).or_default();
        grant_history.retain(|&ts| ts >= one_minute_ago);
        if grant_history.len() as u64 >= self.grant_rate_limit {
            return Err(AutomationError::RateLimitExceeded {
                reason: format!(
                    "grant {} rate limit of {}/min exceeded",
                    grant_id, self.grant_rate_limit
                ),
            });
        }

        // Record admission
        self.host_dispatches.push(now_ms);
        self.grant_dispatches.entry(grant_id).or_default().push(now_ms);
        *self.active_runs.entry(workflow_id).or_default() += 1;

        Ok(())
    }

    /// Signals that a run has finished, releasing concurrency permits.
    pub fn release_run(&mut self, workflow_id: WorkflowId) {
        if let Some(active) = self.active_runs.get_mut(&workflow_id) {
            *active = active.saturating_sub(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::scalars::Uuid;

    fn test_workflow_id(v: u8) -> WorkflowId {
        WorkflowId::new(Uuid::from_bytes([v; 16]))
    }

    fn test_grant_id(v: u8) -> GrantId {
        GrantId::new(Uuid::from_bytes([v; 16]))
    }

    #[test]
    fn enforces_concurrency_limit() {
        let mut admission = AdmissionController::new();
        let wf = test_workflow_id(1);
        let grant = test_grant_id(1);

        // Admit 4 runs (default max)
        for _ in 0..4 {
            assert!(admission.admit_run(wf, grant, 1000, None, None).is_ok());
        }

        // 5th run is rejected
        let err = admission.admit_run(wf, grant, 1000, None, None).unwrap_err();
        assert!(matches!(
            err,
            AutomationError::ConcurrencyLimitExceeded { limit: 4, .. }
        ));

        // Release one
        admission.release_run(wf);
        assert!(admission.admit_run(wf, grant, 1000, None, None).is_ok());
    }
}
