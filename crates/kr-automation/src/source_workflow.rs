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
//! - Nothing here holds a workspace still. A capture a workflow runs asks the host for a
//!   reservation, and the host refuses every one until its writers ask for reservations before
//!   they write, so a capture records the per-file consistency it performs and is never a
//!   quiesced one.
//! - A test or review result registered here is bound to the immutable version it names, and is
//!   still the caller's account of what happened: this host did not observe the execution that
//!   produced it. So are the reviewer turn a review names and that turn's position in its
//!   session's events. A version a workflow node captured is different, because the host records
//!   the run that captured it.

use kr_attention::event::{EventCursor, EventKind, SourceEvent};
use kr_changeset::ChangeSetService;
use kr_protocol::attention::AttentionSource;
use kr_protocol::changeset::{EvidenceKind, VersionRef};
use kr_protocol::ids::{AgentTurnId, SessionId};
use kr_protocol::scalars::TimestampMs;

use crate::error::{AutomationError, Result};

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
#[derive(Debug, Default)]
pub struct SourceWorkflowCoordinator;

impl SourceWorkflowCoordinator {
    /// Creates a new source workflow coordinator.
    #[must_use]
    pub const fn new() -> Self {
        Self
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
