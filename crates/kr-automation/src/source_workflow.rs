//! The completion-to-tests-to-reviewer source workflow and immutable evidence binding.
//!
//! Section 25 ¶6 and KR-REQ-25.20 specify:
//! - Agent completion triggers tests.
//! - Passing tests trigger a separate reviewer session.
//! - Review results create attention items.
//! - The agent identities, selected workspace policy, immutable change-set input version,
//!   and separate session creation are explicit.
//! - Tests and reviewer results bind that immutable version. Subsequent main-workspace edits
//!   produce later versions rather than changing earlier evidence.
//! - This workflow never silently resumes another live agent conversation or shares a dirty
//!   worktree without the selected workspace policy.
//!
//! Two things this module does not do yet, and says so rather than implying them:
//! - A quiescence reservation excludes a second reservation on the same workspace. No workspace
//!   writer consults it, so it does not yet stop a write during a capture.
//! - A test or review result registered here is bound to the immutable version it names, and is
//!   still the caller's account of what happened: this host did not observe the execution that
//!   produced it. So are the reviewer turn a review names and that turn's position in its
//!   session's events. A version a workflow node captured is different, because the host records
//!   the run that captured it.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use kr_attention::event::{EventCursor, EventKind, SourceEvent};
use kr_changeset::ChangeSetService;
use kr_protocol::attention::AttentionSource;
use kr_protocol::changeset::{EvidenceKind, VersionRef};
use kr_protocol::ids::{AgentTurnId, SessionId, WorkspaceId};
use kr_protocol::scalars::{TimestampMs, Uuid};

use crate::error::{AutomationError, Result};

/// An enforceable quiescence reservation on a workspace.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuiescenceReservation {
    /// Unique reservation token.
    pub reservation_id: Uuid,
    /// Reserved workspace.
    pub workspace_id: WorkspaceId,
    /// When granted.
    pub granted_at_ms: u64,
    /// Expiry deadline in milliseconds.
    pub expires_at_ms: u64,
    /// Active state.
    pub active: bool,
}

/// Manages exclusive quiescence reservations on workspaces.
#[derive(Debug, Default)]
pub struct QuiescenceManager {
    reservations: Mutex<HashMap<WorkspaceId, QuiescenceReservation>>,
}

impl QuiescenceManager {
    /// Creates a new quiescence manager.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Obtains an enforceable quiescence reservation on a workspace.
    pub fn reserve(
        &self,
        workspace_id: WorkspaceId,
        timeout_ms: u64,
        now_ms: u64,
    ) -> Result<QuiescenceReservation> {
        let mut lock = self.reservations.lock().unwrap();
        if let Some(existing) = lock.get_mut(&workspace_id)
            && existing.active
            && now_ms < existing.expires_at_ms
        {
            return Err(AutomationError::PermissionDenied(format!(
                "workspace {workspace_id} is already reserved for quiescence until {}",
                existing.expires_at_ms
            )));
        }

        let reservation = QuiescenceReservation {
            reservation_id: crate::new_uuid(),
            workspace_id,
            granted_at_ms: now_ms,
            expires_at_ms: now_ms.saturating_add(timeout_ms),
            active: true,
        };

        lock.insert(workspace_id, reservation.clone());
        Ok(reservation)
    }

    /// Releases a quiescence reservation.
    pub fn release(&self, workspace_id: WorkspaceId, reservation_id: Uuid) -> bool {
        let mut lock = self.reservations.lock().unwrap();
        if let Some(existing) = lock.get_mut(&workspace_id)
            && existing.reservation_id == reservation_id
        {
            existing.active = false;
            return true;
        }
        false
    }

    /// Checks whether a workspace is currently quiesced.
    #[must_use]
    pub fn is_quiesced(&self, workspace_id: WorkspaceId, now_ms: u64) -> bool {
        let lock = self.reservations.lock().unwrap();
        lock.get(&workspace_id)
            .is_some_and(|r| r.active && now_ms < r.expires_at_ms)
    }
}

/// The reviewer's turn a review result came from, as that session's own events record it.
///
/// The host that watched the reviewer's session knows which turn finished, which version of that
/// turn's result this is, and where its completion sits in the session's semantic events. The
/// attention item a review raises is keyed to that turn and positioned at that record, so a result
/// reported twice is one item, and a later review is not taken for a replay of an earlier one. A
/// turn that runs again produces a later result version, which is review work of its own even
/// when the change-set version it reviewed has not moved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReviewerTurn {
    /// The reviewer's session.
    pub session_id: SessionId,
    /// The turn whose completion carried the result.
    pub turn_id: AgentTurnId,
    /// The version of that turn's result.
    pub result_version: u64,
    /// Where that completion sits in the session's semantic events.
    pub cursor: EventCursor,
}

/// The completion -> tests -> reviewer coordinator.
pub struct SourceWorkflowCoordinator {
    quiescence: Arc<QuiescenceManager>,
}

impl SourceWorkflowCoordinator {
    /// Creates a new source workflow coordinator.
    #[must_use]
    pub fn new(quiescence: Arc<QuiescenceManager>) -> Self {
        Self { quiescence }
    }

    /// Returns the quiescence manager.
    #[must_use]
    pub fn quiescence(&self) -> &Arc<QuiescenceManager> {
        &self.quiescence
    }

    /// Records a test result against one immutable change-set version.
    ///
    /// The host records this evidence against the exact change-set version.
    /// Subsequent workspace edits produce later versions without altering this evidence.
    pub fn bind_test_evidence(
        &self,
        changeset_service: &ChangeSetService,
        version: VersionRef,
        passed: bool,
        test_suite_label: &str,
        session_id: SessionId,
        _now_ms: u64,
    ) -> Result<()> {
        let detail = format!(
            "tests '{}' in session {} passed: {}",
            test_suite_label, session_id, passed
        );

        changeset_service
            .record_evidence(
                version.change_set_id,
                version.version,
                EvidenceKind::TestResult,
                &detail,
            )
            .map_err(AutomationError::ChangesetError)?;

        Ok(())
    }

    /// Records a review result against the exact immutable version it reviewed, and returns the
    /// event that makes it review-ready work in the attention state.
    ///
    /// The event is the reviewer turn's own completion: it names that turn and sits where the
    /// session's semantic events hold it. Nothing here mints either, because an identity made up
    /// at this moment would make a result reported twice into two items, and a position made up
    /// here would be one the attention state has already consumed.
    ///
    /// # Errors
    ///
    /// Returns [`AutomationError::InvalidArgument`] for a turn whose position is not a record of
    /// the session's semantic events, and the change-set service's refusal for a version it does
    /// not hold.
    pub fn bind_reviewer_evidence(
        &self,
        changeset_service: &ChangeSetService,
        version: VersionRef,
        reviewer_agent_id: &str,
        review_outcome: &str,
        turn: &ReviewerTurn,
        now_ms: u64,
    ) -> Result<SourceEvent> {
        if turn.cursor.source != AttentionSource::Semantic || turn.cursor.sequence == 0 {
            return Err(AutomationError::InvalidArgument(format!(
                "a reviewer turn's completion is a record of its session's semantic events, not \
                 {:?} sequence {}",
                turn.cursor.source, turn.cursor.sequence
            )));
        }
        let detail = format!(
            "review by {} in session {} turn {}: {}",
            reviewer_agent_id, turn.session_id, turn.turn_id, review_outcome
        );

        changeset_service
            .record_evidence(
                version.change_set_id,
                version.version,
                EvidenceKind::ReviewAcknowledgement,
                &detail,
            )
            .map_err(AutomationError::ChangesetError)?;

        let event = SourceEvent::new(
            turn.cursor,
            TimestampMs::new(now_ms),
            EventKind::TurnCompleted {
                session_id: turn.session_id,
                turn_id: turn.turn_id.clone(),
                version: turn.result_version,
                change_set: Some((version.change_set_id, version.version.get())),
                summary: format!(
                    "review completed for change-set version {}: {}",
                    version.version.get(),
                    review_outcome
                ),
            },
        );

        Ok(event)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::scalars::Uuid;

    fn test_workspace_id(v: u8) -> WorkspaceId {
        WorkspaceId::new(Uuid::from_bytes([v; 16]))
    }

    #[test]
    fn quiescence_reservation_enforces_exclusive_hold() {
        let mgr = QuiescenceManager::new();
        let ws = test_workspace_id(1);

        let res = mgr.reserve(ws, 10_000, 1_000).unwrap();
        assert!(res.active);
        assert!(mgr.is_quiesced(ws, 2_000));

        // Concurrent reservation is refused
        let err = mgr.reserve(ws, 5_000, 2_000).unwrap_err();
        assert!(matches!(err, AutomationError::PermissionDenied(_)));

        // Release works
        assert!(mgr.release(ws, res.reservation_id));
        assert!(!mgr.is_quiesced(ws, 2_000));

        // Can reserve again after release
        assert!(mgr.reserve(ws, 5_000, 3_000).is_ok());
    }

    #[test]
    fn quiescence_reservation_expires_automatically() {
        let mgr = QuiescenceManager::new();
        let ws = test_workspace_id(2);

        let _res = mgr.reserve(ws, 5_000, 1_000).unwrap(); // expires at 6_000
        assert!(mgr.is_quiesced(ws, 3_000));
        assert!(!mgr.is_quiesced(ws, 7_000)); // expired
    }
}
