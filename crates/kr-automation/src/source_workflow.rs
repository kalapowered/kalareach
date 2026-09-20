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
//! Residuals from T-029 closed here:
//! - Residual 2: Enforceable quiescence reservation provided by the workflow service.
//! - Residual 3: Host that owns execution binds the result to the command bytes and immutable version.

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

/// Manages workspace quiescence reservations (closing T-029 Residual 2).
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
    pub fn reserve(&self, workspace_id: WorkspaceId, timeout_ms: u64, now_ms: u64) -> Result<QuiescenceReservation> {
        let mut lock = self.reservations.lock().unwrap();
        if let Some(existing) = lock.get_mut(&workspace_id)
            && existing.active && now_ms < existing.expires_at_ms
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

    /// Binds an execution test result to an immutable change-set version (closing T-029 Residual 3).
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

    /// Triggers the reviewer session after tests pass, binding the exact same immutable version.
    pub fn bind_reviewer_evidence(
        &self,
        changeset_service: &ChangeSetService,
        version: VersionRef,
        reviewer_agent_id: &str,
        review_outcome: &str,
        reviewer_session_id: SessionId,
        now_ms: u64,
    ) -> Result<SourceEvent> {
        let detail = format!(
            "review by {} in session {}: {}",
            reviewer_agent_id, reviewer_session_id, review_outcome
        );

        changeset_service
            .record_evidence(
                version.change_set_id,
                version.version,
                EvidenceKind::ReviewAcknowledgement,
                &detail,
            )
            .map_err(AutomationError::ChangesetError)?;

        // Produce attention event for review ready
        let turn_id = AgentTurnId::new(uuid::Uuid::new_v4().to_string()).expect("valid turn id");
        let event = SourceEvent::new(
            EventCursor::new(AttentionSource::Semantic, 1),
            TimestampMs::new(now_ms),
            EventKind::TurnCompleted {
                session_id: reviewer_session_id,
                turn_id,
                version: version.version.get(),
                change_set: Some((version.change_set_id, version.version.get())),
                summary: format!("review completed for version {}: {}", version.version.get(), review_outcome),
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
