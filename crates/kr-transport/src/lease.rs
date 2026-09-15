//! The remote dispatch lease the controller issues and the worker holds.
//!
//! Section 9: remote dispatch additionally requires a live worker-held authority lease from the
//! current controller generation and revision. Its maximum validity is five seconds on the host's
//! suspend-aware continuous clock, and every dispatch checks that deadline in the serial path.
//! Renewal can occur only after the worker has acknowledged the relevant authority revision.
//! Losing the generation binding stops renewal, and a replacement controller cannot adopt old
//! queued actor envelopes without revalidation.
//!
//! Two halves, both here because they are one contract:
//!
//! * [`LeaseIssuer`] is the controller's half. It records which revision each worker has
//!   acknowledged, and refuses to renew past a revision the worker has not installed.
//! * [`DispatchLease`] is the worker's half. It answers one question — may this dispatch proceed
//!   right now — and answers it from the clock, not from a timer that fired earlier.
//!
//! The lease is a bounded stop on stale remote work. It is not the revocation barrier: section 9
//! is explicit that waiting for a lease timer is not completion, because a paused worker could
//! already be inside a dispatch transition. [`LeaseIssuer::revoke`] therefore reports which
//! workers are still pending rather than declaring success.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use kr_protocol::ids::{AuthorityRevision, ControllerGeneration, RemoteDispatchLeaseId, SessionId};
use kr_protocol::limits::MAX_REMOTE_DISPATCH_LEASE;

use crate::clock::{ContinuousClock, ContinuousInstant};
use crate::error::Result;
use crate::random::fresh_lease_id;

/// The longest a remote dispatch lease can be valid.
///
/// Section 9: five seconds on the suspend-aware continuous clock.
pub const MAX_LEASE: Duration = Duration::from_millis(MAX_REMOTE_DISPATCH_LEASE.get());

/// A lease as the worker holds it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DispatchLease {
    /// The lease identity.
    pub lease_id: RemoteDispatchLeaseId,
    /// The controller generation that issued it. A replacement controller advances this.
    pub generation: ControllerGeneration,
    /// The authority revision the lease is bound to.
    pub authority_revision: AuthorityRevision,
    /// The deadline on the continuous clock.
    pub deadline: ContinuousInstant,
}

impl DispatchLease {
    /// Returns whether a dispatch may proceed under this lease.
    ///
    /// The check is against the clock, at the moment of the dispatch, in the worker's serial path.
    /// A lease that was valid when the action was queued proves nothing.
    #[must_use]
    pub fn permits(
        &self,
        now: ContinuousInstant,
        generation: ControllerGeneration,
        authority_revision: AuthorityRevision,
    ) -> bool {
        now < self.deadline
            && self.generation == generation
            && self.authority_revision == authority_revision
    }

    /// Returns how long the lease has left, or zero once it has expired.
    #[must_use]
    pub fn remaining(&self, now: ContinuousInstant) -> Duration {
        self.deadline.saturating_duration_since(now)
    }
}

/// Why a lease was not issued or renewed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum LeaseRefusal {
    /// The presented generation is not the current one, so renewal has stopped.
    #[error("the controller generation has been replaced")]
    GenerationReplaced,
    /// The worker has not acknowledged the authority revision this lease would carry.
    #[error("the worker has not acknowledged the authority revision")]
    RevisionNotAcknowledged,
    /// The worker has no lease to renew.
    #[error("the worker holds no lease")]
    NoLease,
}

/// What a revocation is still waiting for.
///
/// Until every affected worker has acknowledged the revision, or has been confirmed ended, the
/// result is `pending` with per-worker status. It is never reported as success.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevocationStatus {
    /// The revision being installed.
    pub authority_revision: AuthorityRevision,
    /// Workers that have acknowledged the revision and fenced their undispatched actions.
    pub acknowledged: Vec<SessionId>,
    /// Workers that have not acknowledged yet and have not been confirmed ended.
    pub pending: Vec<SessionId>,
}

impl RevocationStatus {
    /// Returns true when every affected worker has acknowledged or ended.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.pending.is_empty()
    }
}

#[derive(Debug, Default)]
struct WorkerState {
    acknowledged_revision: Option<AuthorityRevision>,
    lease: Option<DispatchLease>,
    ended: bool,
}

/// The controller's half of the lease contract.
#[derive(Debug)]
pub struct LeaseIssuer {
    generation: ControllerGeneration,
    authority_revision: Mutex<AuthorityRevision>,
    validity: Duration,
    workers: Mutex<HashMap<SessionId, WorkerState>>,
}

impl LeaseIssuer {
    /// Creates an issuer for one controller generation at one authority revision.
    ///
    /// The validity is capped at five seconds; a caller that asks for longer gets five.
    #[must_use]
    pub fn new(
        generation: ControllerGeneration,
        authority_revision: AuthorityRevision,
        validity: Duration,
    ) -> Self {
        Self {
            generation,
            authority_revision: Mutex::new(authority_revision),
            validity: validity.min(MAX_LEASE),
            workers: Mutex::new(HashMap::new()),
        }
    }

    /// Creates an issuer whose leases last the full five seconds.
    #[must_use]
    pub fn with_maximum_validity(
        generation: ControllerGeneration,
        authority_revision: AuthorityRevision,
    ) -> Self {
        Self::new(generation, authority_revision, MAX_LEASE)
    }

    /// Returns this issuer's controller generation.
    #[must_use]
    pub const fn generation(&self) -> ControllerGeneration {
        self.generation
    }

    /// Returns the current authority revision.
    #[must_use]
    pub fn authority_revision(&self) -> AuthorityRevision {
        *self.revision()
    }

    /// Records that a worker acknowledged an authority revision.
    ///
    /// Acknowledgement means the worker has installed the revision and fenced or rejected the
    /// undispatched actions it affects. Only then can the worker's lease carry that revision.
    pub fn acknowledge(&self, session_id: SessionId, revision: AuthorityRevision) {
        let mut workers = self.workers();
        let state = workers.entry(session_id).or_default();
        if state
            .acknowledged_revision
            .is_none_or(|current| revision > current)
        {
            state.acknowledged_revision = Some(revision);
        }
    }

    /// Records that a worker's execution has ended.
    ///
    /// A worker that can no longer dispatch satisfies the barrier as surely as one that
    /// acknowledged, which is the other half of the section 9 rule.
    pub fn worker_ended(&self, session_id: SessionId) {
        let mut workers = self.workers();
        let state = workers.entry(session_id).or_default();
        state.ended = true;
        state.lease = None;
    }

    /// Issues or renews a worker's lease.
    ///
    /// # Errors
    ///
    /// Returns [`LeaseRefusal::GenerationReplaced`] when the caller presents a generation this
    /// issuer no longer holds, and [`LeaseRefusal::RevisionNotAcknowledged`] when the worker has
    /// not acknowledged the current revision.
    pub fn renew(
        &self,
        session_id: SessionId,
        generation: ControllerGeneration,
        clock: &dyn ContinuousClock,
    ) -> Result<std::result::Result<DispatchLease, LeaseRefusal>> {
        if generation != self.generation {
            return Ok(Err(LeaseRefusal::GenerationReplaced));
        }
        let revision = *self.revision();
        let mut workers = self.workers();
        let state = workers.entry(session_id).or_default();
        if state.ended || state.acknowledged_revision != Some(revision) {
            return Ok(Err(LeaseRefusal::RevisionNotAcknowledged));
        }
        let deadline = clock.now().checked_add(self.validity).ok_or(
            crate::error::TransportError::LimitExceeded {
                what: "the dispatch lease deadline",
                limit: 0,
            },
        )?;
        let lease = DispatchLease {
            lease_id: fresh_lease_id()?,
            generation,
            authority_revision: revision,
            deadline,
        };
        state.lease = Some(lease);
        Ok(Ok(lease))
    }

    /// Advances the authority revision and reports the barrier's status.
    ///
    /// Advancing invalidates every outstanding lease at once, because a lease carries the revision
    /// it was issued at. Workers that have not acknowledged the new revision are named as pending;
    /// none of them can renew until they do.
    pub fn revoke(&self, revision: AuthorityRevision) -> RevocationStatus {
        {
            let mut current = self.revision();
            if revision > *current {
                *current = revision;
            }
        }
        self.status(revision)
    }

    /// Reports which workers have acknowledged a revision and which are still pending.
    #[must_use]
    pub fn status(&self, revision: AuthorityRevision) -> RevocationStatus {
        let workers = self.workers();
        let mut acknowledged = Vec::new();
        let mut pending = Vec::new();
        for (session_id, state) in workers.iter() {
            if state.ended || state.acknowledged_revision == Some(revision) {
                acknowledged.push(*session_id);
            } else {
                pending.push(*session_id);
            }
        }
        acknowledged.sort_unstable();
        pending.sort_unstable();
        RevocationStatus {
            authority_revision: revision,
            acknowledged,
            pending,
        }
    }

    /// Stops renewal for one worker, which is what losing the control stream does.
    ///
    /// The worker keeps whatever remains of its current lease and then stops dispatching. Nothing
    /// here kills a healthy shell.
    pub fn stop_renewal(&self, session_id: SessionId) {
        let mut workers = self.workers();
        if let Some(state) = workers.get_mut(&session_id) {
            state.lease = None;
        }
    }

    fn revision(&self) -> std::sync::MutexGuard<'_, AuthorityRevision> {
        self.authority_revision
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn workers(&self) -> std::sync::MutexGuard<'_, HashMap<SessionId, WorkerState>> {
        self.workers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::ManualClock;
    use kr_protocol::scalars::Uuid;

    fn session(byte: u8) -> SessionId {
        SessionId::new(Uuid::from_bytes([byte; 16]))
    }

    fn issuer() -> LeaseIssuer {
        LeaseIssuer::with_maximum_validity(ControllerGeneration::new(7), AuthorityRevision::new(3))
    }

    #[test]
    fn a_lease_lasts_at_most_five_seconds() {
        let clock = ManualClock::new();
        let issuer = LeaseIssuer::new(
            ControllerGeneration::new(1),
            AuthorityRevision::new(1),
            Duration::from_secs(60),
        );
        issuer.acknowledge(session(1), AuthorityRevision::new(1));
        let lease = issuer
            .renew(session(1), ControllerGeneration::new(1), &clock)
            .expect("a lease")
            .expect("an issued lease");
        assert_eq!(lease.remaining(clock.now()), MAX_LEASE);
    }

    #[test]
    fn renewal_waits_for_the_workers_acknowledgement() {
        let clock = ManualClock::new();
        let issuer = issuer();
        assert_eq!(
            issuer
                .renew(session(1), ControllerGeneration::new(7), &clock)
                .expect("a decision"),
            Err(LeaseRefusal::RevisionNotAcknowledged)
        );
        issuer.acknowledge(session(1), AuthorityRevision::new(3));
        assert!(
            issuer
                .renew(session(1), ControllerGeneration::new(7), &clock)
                .expect("a decision")
                .is_ok()
        );
    }

    #[test]
    fn a_replaced_generation_stops_renewal() {
        let clock = ManualClock::new();
        let issuer = issuer();
        issuer.acknowledge(session(1), AuthorityRevision::new(3));
        assert_eq!(
            issuer
                .renew(session(1), ControllerGeneration::new(6), &clock)
                .expect("a decision"),
            Err(LeaseRefusal::GenerationReplaced)
        );
    }

    #[test]
    fn a_dispatch_checks_the_deadline_at_the_moment_it_runs() {
        let clock = ManualClock::new();
        let issuer = issuer();
        issuer.acknowledge(session(1), AuthorityRevision::new(3));
        let lease = issuer
            .renew(session(1), ControllerGeneration::new(7), &clock)
            .expect("a lease")
            .expect("an issued lease");
        assert!(lease.permits(
            clock.now(),
            ControllerGeneration::new(7),
            AuthorityRevision::new(3)
        ));
        clock.advance(Duration::from_secs(6));
        assert!(!lease.permits(
            clock.now(),
            ControllerGeneration::new(7),
            AuthorityRevision::new(3)
        ));
        assert_eq!(lease.remaining(clock.now()), Duration::ZERO);
    }

    #[test]
    fn a_lease_never_carries_another_generation_or_revision() {
        let clock = ManualClock::new();
        let issuer = issuer();
        issuer.acknowledge(session(1), AuthorityRevision::new(3));
        let lease = issuer
            .renew(session(1), ControllerGeneration::new(7), &clock)
            .expect("a lease")
            .expect("an issued lease");
        assert!(!lease.permits(
            clock.now(),
            ControllerGeneration::new(8),
            AuthorityRevision::new(3)
        ));
        assert!(!lease.permits(
            clock.now(),
            ControllerGeneration::new(7),
            AuthorityRevision::new(4)
        ));
    }

    #[test]
    fn a_revocation_reports_pending_until_every_worker_acknowledges_or_ends() {
        let clock = ManualClock::new();
        let issuer = issuer();
        for worker in [1u8, 2, 3] {
            issuer.acknowledge(session(worker), AuthorityRevision::new(3));
            issuer
                .renew(session(worker), ControllerGeneration::new(7), &clock)
                .expect("a lease")
                .expect("an issued lease");
        }

        let status = issuer.revoke(AuthorityRevision::new(4));
        assert!(!status.is_complete());
        assert_eq!(status.pending.len(), 3);

        issuer.acknowledge(session(1), AuthorityRevision::new(4));
        issuer.worker_ended(session(2));
        let status = issuer.status(AuthorityRevision::new(4));
        assert_eq!(status.pending, vec![session(3)]);

        issuer.acknowledge(session(3), AuthorityRevision::new(4));
        assert!(issuer.status(AuthorityRevision::new(4)).is_complete());
    }

    #[test]
    fn an_outstanding_lease_cannot_dispatch_after_the_revision_advances() {
        let clock = ManualClock::new();
        let issuer = issuer();
        issuer.acknowledge(session(1), AuthorityRevision::new(3));
        let lease = issuer
            .renew(session(1), ControllerGeneration::new(7), &clock)
            .expect("a lease")
            .expect("an issued lease");
        issuer.revoke(AuthorityRevision::new(4));
        assert!(!lease.permits(
            clock.now(),
            ControllerGeneration::new(7),
            issuer.authority_revision()
        ));
        assert_eq!(
            issuer
                .renew(session(1), ControllerGeneration::new(7), &clock)
                .expect("a decision"),
            Err(LeaseRefusal::RevisionNotAcknowledged)
        );
    }
}
