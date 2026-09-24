//! Per-workflow concurrency and pending limits, and host-wide and per-grant admission rates.
//!
//! Section 17 ¶8 and section 25 specify:
//! - Per-workflow defaults: 4 concurrent runs, 100 pending runs, a 30-minute run deadline and a
//!   10-minute maximum action wait. Exceeding a limit pauses the workflow and emits an attention
//!   event.
//! - Per-host and per-grant admission rates apply in addition to per-workflow concurrency.
//! - Unauthenticated external callbacks are new external triggers under host-wide limits.
//! - Limits survive restart.
//!
//! Every count here is the workflow journal's, read inside the transaction that records the run it
//! decides. A restart therefore finds the rates as they stood and the queue as it was left, and two
//! admissions that arrive at once are serialised by that transaction rather than both reading the
//! last free place.

use kr_protocol::automation::{
    DEFAULT_WORKFLOW_CONCURRENT_RUNS, DEFAULT_WORKFLOW_PENDING_RUNS, WorkflowRunStatus,
};
use kr_protocol::ids::{GrantId, WorkflowId};

use crate::error::{AutomationError, Result};
use crate::store::Journal;

/// The most runs this host admits in one window, whatever their grant.
pub const DEFAULT_HOST_MAX_ADMISSIONS_PER_MINUTE: u64 = 600;
/// The most runs this host admits under one grant in one window.
pub const DEFAULT_GRANT_MAX_ADMISSIONS_PER_MINUTE: u64 = 120;
/// The window both rates are counted over, in milliseconds.
pub const ADMISSION_WINDOW_MS: u64 = 60_000;

/// Where an admitted run goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Placement {
    /// A slot is free: the run is recorded running and executes now.
    Start,
    /// Every slot is taken: the run is recorded pending and starts when one frees.
    Queue,
}

/// Decides one run's admission against the journal, inside the transaction that will record it.
///
/// The host-wide rate first, then the grant's, then the workflow's own limits: a run starts when
/// fewer than four of its workflow's runs are running, waits as pending when fewer than a hundred
/// are waiting, and is refused otherwise. A refusal here is a limit exceeded; the caller pauses
/// the workflow and records the attention item that pause owes.
///
/// # Errors
///
/// Returns [`AutomationError::RateLimitExceeded`] for a rate the window is full of,
/// [`AutomationError::PendingLimitExceeded`] for a full queue, and a storage error when the
/// journal cannot be read.
pub fn place(
    journal: &Journal<'_>,
    workflow_id: WorkflowId,
    grant: GrantId,
    now_ms: u64,
) -> Result<Placement> {
    let since = now_ms.saturating_sub(ADMISSION_WINDOW_MS);
    if journal.admissions_since(since, None)? >= DEFAULT_HOST_MAX_ADMISSIONS_PER_MINUTE {
        return Err(AutomationError::RateLimitExceeded {
            reason: format!(
                "host-wide rate limit of {DEFAULT_HOST_MAX_ADMISSIONS_PER_MINUTE}/min exceeded"
            ),
        });
    }
    if journal.admissions_since(since, Some(grant))? >= DEFAULT_GRANT_MAX_ADMISSIONS_PER_MINUTE {
        return Err(AutomationError::RateLimitExceeded {
            reason: format!(
                "grant {grant} rate limit of {DEFAULT_GRANT_MAX_ADMISSIONS_PER_MINUTE}/min exceeded"
            ),
        });
    }
    if journal.runs_in(workflow_id, WorkflowRunStatus::Running)? < DEFAULT_WORKFLOW_CONCURRENT_RUNS
    {
        return Ok(Placement::Start);
    }
    if journal.runs_in(workflow_id, WorkflowRunStatus::Pending)? < DEFAULT_WORKFLOW_PENDING_RUNS {
        return Ok(Placement::Queue);
    }
    Err(AutomationError::PendingLimitExceeded {
        workflow_id,
        limit: DEFAULT_WORKFLOW_PENDING_RUNS,
    })
}
