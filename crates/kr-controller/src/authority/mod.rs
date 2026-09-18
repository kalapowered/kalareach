//! The revocation barrier, the dispatch lease and the generation they are both bound to.
//!
//! Section 9 says two things about a revocation that are easy to conflate and must not be.
//!
//! * **The bounded lease stops stale remote work.** A worker may dispatch remotely only under a
//!   live lease from the current generation and revision, valid at most five seconds on the
//!   suspend-aware continuous clock. [`kr_transport::lease::LeaseIssuer`] owns that contract,
//!   because the same lease governs a network device and a local one.
//! * **The lease is not the barrier.** "Cutting a network path or merely waiting for a lease timer
//!   is not completion: a paused worker could already be inside a dispatch transition." So a
//!   revocation is complete for a worker only when that worker has acknowledged installing the
//!   revision and fencing the undispatched actions it affects, or when its execution is confirmed
//!   ended. Anything else is `pending`.
//!
//! [`AuthorityBarrier`] is the daemon's half of both, in one type, because they are read and
//! written together on every path. It adds to the lease issuer exactly what the barrier needs and
//! the lease cannot carry: which actions each worker's fence rejected, and which ones had already
//! won the serial race and may therefore have executed. Those are *named* in the report rather
//! than counted, because a count says how many things may have happened and a name says which.
//!
//! Nothing here ends a process. A pending worker stays pending, and the daemon says so, because
//! section 9 forbids killing a healthy shell to force a revocation to complete. The remedy for a
//! worker that will not answer is the worker ending of its own accord or being confirmed gone,
//! and both arrive through [`AuthorityBarrier::worker_ended`].

use std::collections::HashMap;
use std::sync::Mutex;

use kr_protocol::action::{BarrierState, PossiblyExecutedAction, RevocationBarrier, WorkerBarrier};
use kr_protocol::ids::{AuthorityRevision, ConnectionId, ControllerGeneration, SessionId};
use kr_protocol::scalars::Nullable;
use kr_transport::clock::{ContinuousClock, ContinuousInstant};
use kr_transport::lease::{DispatchLease, LeaseIssuer, LeaseRefusal, WorkerBinding};

/// One mutation's admission, carried from the moment this daemon accepted it to the moment its
/// effect is committed.
///
/// Checking a deadline and a registration *before* a service takes its store lock proves they
/// stood before the wait, which is not the question. A service that waits on its own lock can be
/// admitted at one moment and reach its transaction at another, and what section 9 requires is
/// that the mutation is refused at the second moment rather than the first. So the admission
/// travels with the mutation and is checked again inside the transaction, under the store's own
/// lock, immediately before anything durable is written.
///
/// The rule for every service in this host, in order:
///
/// 1. Take the service's own store lock.
/// 2. Take this daemon's registry lock, which is the order admission and revocation both take.
/// 3. Check the admission.
/// 4. Write, with nothing awaited between the check and the write.
///
/// `docs/host/README.md` states it for the services that are not in this crate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdmittedMutation {
    /// The connection the mutation arrived on.
    pub connection_id: ConnectionId,
    /// The authority revision it was admitted under.
    pub admitted_revision: AuthorityRevision,
    /// The accepted deadline, on this daemon's continuous clock.
    ///
    /// Absent means this mutation carries no freshness at all, which is what a retry of an action
    /// whose window is gone carries. Section 9 keeps a receipt readable after the freshness that
    /// admitted it has expired, so such a mutation may be answered from what this host already
    /// holds and may not be admitted as a new one. The authority half of the admission still
    /// applies: a retained result is disclosed only under authority that has not been withdrawn.
    pub deadline: Option<ContinuousInstant>,
}

/// What this daemon's authority store says at the moment a transaction asks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdmissionContext {
    /// The continuous clock, read inside the transaction.
    pub now: ContinuousInstant,
    /// The authority revision in force, read under the registry lock.
    pub authority_revision: AuthorityRevision,
    /// Whether the connection is still registered at that revision.
    pub registered: bool,
}

/// Why an admission no longer stands.
///
/// The order [`AdmittedMutation::check`] reports these in is part of the contract. A caller may act
/// on one and not another: the close path goes on when the freshness is gone, because the worker
/// that owns the session is the only thing that knows whether it already holds the action's
/// receipt, and it may never go on when the authority is gone. So the two authority answers come
/// first and `Expired` comes last, and a caller that reads past the last one cannot read past
/// either of the others by accident.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AdmissionLapse {
    /// The accepted deadline passed before the transaction reached its write.
    #[error("the deadline this action was admitted under passed before its effect was committed")]
    Expired,
    /// The authority revision advanced past the one the mutation was admitted under.
    #[error(
        "the authority this action was admitted under was withdrawn before its effect was \
            committed"
    )]
    Revoked,
    /// The connection's registration was withdrawn.
    #[error("the registration this action was admitted under has been withdrawn")]
    Deregistered,
}

impl AdmittedMutation {
    /// Refuses a mutation whose admission no longer stands.
    ///
    /// # Errors
    ///
    /// Returns the first way the admission has lapsed.
    pub fn check(&self, context: AdmissionContext) -> Result<(), AdmissionLapse> {
        // Authority first, and freshness after it. The order is what a caller can safely act on:
        // section 9 lets a *retry* go on when its freshness is gone, because a receipt outlives
        // the window that admitted it, and a caller that reads past `Expired` for that reason must
        // not read past a revocation with it. Reporting the weaker lapse first would hide the
        // stronger one behind it.
        if context.authority_revision > self.admitted_revision {
            return Err(AdmissionLapse::Revoked);
        }
        if !context.registered {
            return Err(AdmissionLapse::Deregistered);
        }
        if self
            .deadline
            .is_some_and(|deadline| context.now >= deadline)
        {
            return Err(AdmissionLapse::Expired);
        }
        Ok(())
    }
}

/// How many revocations one worker's reports are kept for.
///
/// A revocation's result is what section 9 asks to be named, and a revision advancing does not
/// finish the one before it: a page of an older revocation's names may still be owed, and reading
/// a newer revocation's lists as the older one's answer would name the wrong actions. So the
/// reports are kept by revision. A worker that produced more revocations than this without their
/// evidence ever being completed loses the oldest, which is the same bound its own journal keeps.
const MAX_HELD_FENCE_REPORTS: usize = 8;

/// What one worker's fence reported when it installed one revision.
#[derive(Clone, Debug, PartialEq, Eq)]
struct FenceReport {
    /// The revision this report is the answer for.
    ///
    /// Every report belongs to one revocation. A later revocation's fence is a different question
    /// with a different answer, and answering the first with the second would name actions the
    /// first revocation did not cover.
    revision: AuthorityRevision,
    /// How many names the worker said it still held when it last answered.
    ///
    /// The evidence travels a page at a time, because one acknowledgement is one control frame.
    /// This is what the daemon asks for next, and nought is what says the evidence is complete.
    remaining: u64,
    /// Whether the worker reported fence evidence at all.
    ///
    /// A worker that does not report it has still installed the revision, and that is all this
    /// daemon knows. Section 9 makes the acknowledgement two statements, so one of them arriving
    /// is not the barrier: the revocation stays pending for that worker, and the report says why
    /// rather than letting an absence read as a clean fence.
    reported: bool,
    rejected: Vec<kr_protocol::action::FencedAction>,
    possibly_executed: Vec<PossiblyExecutedAction>,
    omitted: u64,
}

impl FenceReport {
    /// Starts the report of one revocation, before anything has been said about it.
    fn opened(revision: AuthorityRevision) -> Self {
        Self {
            revision,
            remaining: 0,
            reported: false,
            rejected: Vec::new(),
            possibly_executed: Vec::new(),
            omitted: 0,
        }
    }

    /// Takes one acknowledgement's evidence into this report.
    ///
    /// The lists accumulate. A fence that ran in two passes, because the first failed part way or
    /// its acknowledgement was lost, has rejected what each pass rejected, and the result has to
    /// name all of it.
    fn absorb(&mut self, evidence: kr_protocol::action::FenceEvidence) {
        self.reported = true;
        for action in evidence.rejected_actions {
            if !self.rejected.contains(&action) {
                self.rejected.push(action);
            }
        }
        self.remaining = evidence.remaining.get();
        for action in evidence.possibly_executed {
            // The complete key, because two actors may each have used one identifier and merging
            // on the identifier alone would drop one of their actions.
            if !self
                .possibly_executed
                .iter()
                .any(|held| held.action_id == action.action_id && held.actor_id == action.actor_id)
            {
                self.possibly_executed.push(action);
            }
        }
        self.omitted = self.omitted.max(evidence.omitted.get());
    }

    /// Returns how many names this report holds, which is where the next page starts.
    fn named(&self) -> u64 {
        let held = self
            .rejected
            .len()
            .saturating_add(self.possibly_executed.len());
        u64::try_from(held).unwrap_or(u64::MAX)
    }
}

/// What one worker has said about each revocation it has answered, oldest first.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct WorkerFences {
    reports: Vec<FenceReport>,
}

impl WorkerFences {
    /// Takes one acknowledgement into the report of the revocation it answers.
    ///
    /// A revision this worker had not answered before opens a report of its own rather than
    /// replacing the one before it: the earlier revocation's names are what that revocation's
    /// result owes, and a page of them may still be on its way.
    fn record(
        &mut self,
        revision: AuthorityRevision,
        evidence: Option<kr_protocol::action::FenceEvidence>,
    ) {
        let position = match self
            .reports
            .iter()
            .position(|report| report.revision == revision)
        {
            Some(position) => position,
            None => {
                let position = self
                    .reports
                    .partition_point(|report| report.revision < revision);
                self.reports.insert(position, FenceReport::opened(revision));
                position
            }
        };
        if let Some(evidence) = evidence {
            self.reports[position].absorb(evidence);
        }
        // The oldest goes first, because the newest revocation is the one a person is waiting on.
        while self.reports.len() > MAX_HELD_FENCE_REPORTS {
            self.reports.remove(0);
        }
    }

    /// Returns the highest revision this worker has said it installed.
    fn installed(&self) -> Option<AuthorityRevision> {
        self.reports.last().map(|report| report.revision)
    }

    /// Returns what this worker said about one revocation, and nothing about any other.
    fn at(&self, revision: AuthorityRevision) -> Option<&FenceReport> {
        self.reports
            .iter()
            .find(|report| report.revision == revision)
    }

    /// Returns whether this worker has said what a fence at or after this revision did.
    ///
    /// Installing a later revision fences everything an earlier one would have, so a report of a
    /// later revocation answers the earlier revocation's second question. What it does not do is
    /// name the earlier revocation's actions, which is why the names are read from [`Self::at`].
    fn reported_from(&self, revision: AuthorityRevision) -> bool {
        self.reports
            .iter()
            .any(|report| report.revision >= revision && report.reported)
    }
}

/// The daemon's half of the dispatch lease and the revocation barrier.
///
/// Every operation that changes more than one thing takes `order` first. The lease issuer has its
/// own lock and the fence reports have theirs, so without it an acknowledgement could check the
/// binding, have the path replaced underneath it, and then write its report against the
/// replacement: two locks make two moments, and this is what makes them one.
#[derive(Debug)]
pub struct AuthorityBarrier {
    leases: LeaseIssuer,
    order: Mutex<()>,
    fences: Mutex<HashMap<SessionId, WorkerFences>>,
    /// The workers whose execution this daemon has established has ended.
    ///
    /// Kept here rather than read back out of the lease issuer, because the issuer counts an ended
    /// worker and an acknowledging one as the same thing - both satisfy a lease - and the barrier
    /// has to tell them apart. A worker that installed a revision without reporting what its fence
    /// did is pending; the same worker, once it is gone, can no longer dispatch anything, and that
    /// answers the question a different way.
    ended: Mutex<Vec<SessionId>>,
}

impl AuthorityBarrier {
    /// Creates a barrier for one controller generation at one authority revision.
    ///
    /// The leases it issues last the full five seconds section 9 permits.
    #[must_use]
    pub fn new(generation: ControllerGeneration, authority_revision: AuthorityRevision) -> Self {
        Self {
            leases: LeaseIssuer::with_maximum_validity(generation, authority_revision),
            order: Mutex::new(()),
            fences: Mutex::new(HashMap::new()),
            ended: Mutex::new(Vec::new()),
        }
    }

    /// Returns the generation this barrier speaks for.
    #[must_use]
    pub const fn generation(&self) -> ControllerGeneration {
        self.leases.generation()
    }

    /// Returns the authority revision in force.
    #[must_use]
    pub fn authority_revision(&self) -> AuthorityRevision {
        self.leases.authority_revision()
    }

    /// Records that a worker's control path was established, returning its binding.
    pub fn bind(&self, session_id: SessionId) -> WorkerBinding {
        let _order = self.ordered();
        // A new control path owes a fresh acknowledgement. What the previous path reported about
        // its *fence* is kept, because the fence ran: section 9 requires the actions it could not
        // take back to be named in the result, and an acknowledgement lost on the way back must
        // not lose them. What is cleared is the acknowledgement itself, which is the lease
        // issuer's to clear.
        self.leases.bind(session_id)
    }

    /// Returns the binding in force for a worker.
    #[must_use]
    pub fn binding(&self, session_id: SessionId) -> WorkerBinding {
        self.leases.binding(session_id)
    }

    /// Records a worker's acknowledgement, with what its fence rejected and could not take back.
    ///
    /// The two lists are the acknowledgement rather than an addition to it: section 9 makes the
    /// acknowledgement a statement that the revision is installed **and** that the undispatched
    /// actions it affects have been rejected or fenced.
    /// Returns whether the acknowledgement was accepted.
    ///
    /// A caller that records the acknowledgement anywhere else waits for this answer: the binding
    /// check is here, and a store updated before it had been made would hold an acknowledgement
    /// this barrier refused.
    pub fn acknowledge(
        &self,
        session_id: SessionId,
        binding: WorkerBinding,
        revision: AuthorityRevision,
        evidence: Option<kr_protocol::action::FenceEvidence>,
    ) -> bool {
        let _order = self.ordered();
        if binding != self.leases.binding(session_id) {
            // The acknowledgement was made over a control path this daemon has given up on. The
            // lease issuer refuses it for the same reason, and its fence lists are no more
            // evidence about the path in force than the acknowledgement itself is.
            return false;
        }
        {
            // Into the report of the revocation this acknowledgement answers, and no other. What
            // the fence reported is kept and added to: a fence that ran in two passes, because the
            // first failed part way or its acknowledgement was lost, has to have all of it named,
            // and a repeat that carries nothing must not erase what the first pass said. A late
            // acknowledgement of an older revision is news about that revocation and nothing else:
            // it neither unsays a newer revision this worker has installed nor lends its names to
            // one.
            let mut fences = self.lock();
            fences
                .entry(session_id)
                .or_default()
                .record(revision, evidence);
        }
        self.leases.acknowledge(session_id, binding, revision);
        true
    }

    /// Returns where the next page of a worker's fence evidence starts, when one is owed.
    ///
    /// `None` means the evidence this worker holds is complete here. Anything else is the number
    /// of names already held, which is what the next announcement asks from.
    #[must_use]
    pub fn evidence_owed(&self, session_id: SessionId, revision: AuthorityRevision) -> Option<u64> {
        let _order = self.ordered();
        let fences = self.lock();
        // This revocation's own report. A newer revision arriving does not finish the one before
        // it: the page that is owed belongs to the list it was issued against.
        let report = fences.get(&session_id)?.at(revision)?;
        if report.remaining == 0 {
            return None;
        }
        Some(report.named())
    }

    /// Returns the older revocations this worker still owes names for, oldest first.
    ///
    /// A page whose exchange failed before a newer revision arrived is still owed: section 9 asks
    /// for the actions a fence could not take back to be named in *that* revocation's result, and
    /// a revision advancing does not answer the question the older one asked. What is returned is
    /// bounded by how many reports this daemon keeps per worker.
    #[must_use]
    pub fn evidence_outstanding(
        &self,
        session_id: SessionId,
        before: AuthorityRevision,
    ) -> Vec<AuthorityRevision> {
        let _order = self.ordered();
        let fences = self.lock();
        fences.get(&session_id).map_or_else(Vec::new, |held| {
            held.reports
                .iter()
                .filter(|report| report.revision < before && report.remaining > 0)
                .map(|report| report.revision)
                .collect()
        })
    }

    /// Records that a worker's execution has ended.
    ///
    /// A worker that can no longer dispatch satisfies the barrier as surely as one that
    /// acknowledged. This is how a worker that will not answer is resolved, and it is the only
    /// way: nothing in this module ends a process to make a revocation complete.
    pub fn worker_ended(&self, session_id: SessionId) {
        let _order = self.ordered();
        let mut ended = self
            .ended
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !ended.contains(&session_id) {
            ended.push(session_id);
        }
        drop(ended);
        self.leases.worker_ended(session_id);
    }

    /// Stops renewal for one worker, which is what losing the control path does.
    pub fn stop_renewal(&self, session_id: SessionId, binding: WorkerBinding) {
        let _order = self.ordered();
        self.leases.stop_renewal(session_id, binding);
    }

    /// Returns true when renewal for this worker is fenced.
    #[must_use]
    pub fn is_fenced(&self, session_id: SessionId) -> bool {
        self.leases.is_fenced(session_id)
    }

    /// Issues or renews a worker's dispatch lease.
    ///
    /// # Errors
    ///
    /// Returns a transport failure when the generator is unavailable; the inner result carries the
    /// refusal when the generation has been replaced or the worker has not acknowledged the
    /// revision in force.
    pub fn renew(
        &self,
        session_id: SessionId,
        generation: ControllerGeneration,
        clock: &dyn ContinuousClock,
    ) -> kr_transport::error::Result<Result<DispatchLease, LeaseRefusal>> {
        self.leases.renew(session_id, generation, clock)
    }

    /// Returns the lease a worker currently holds, if any.
    #[must_use]
    pub fn current_lease(&self, session_id: SessionId) -> Option<DispatchLease> {
        self.leases.current_lease(session_id)
    }

    /// Advances the authority revision.
    ///
    /// Every outstanding lease becomes invalid at once, because a lease carries the revision it was
    /// issued at. Nothing is complete yet: the barrier is what completes a revocation, and this is
    /// only the moment the revision changed.
    pub fn revoke(&self, revision: AuthorityRevision) {
        let _order = self.ordered();
        self.leases.revoke(revision);
    }

    /// Reports the barrier across the workers this daemon knows about.
    ///
    /// A worker that has never answered is `pending` rather than absent, because a revocation is
    /// not complete for a worker this daemon cannot account for. Each pending entry says what is
    /// missing, so a person reading `pending` learns which worker and why.
    pub fn report(
        &self,
        revision: AuthorityRevision,
        workers: impl IntoIterator<Item = SessionId>,
    ) -> RevocationBarrier {
        let _order = self.ordered();
        let status = self.leases.status(revision);
        let ended = self
            .ended
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let fences = self.lock();
        let mut reported: Vec<WorkerBarrier> = Vec::new();
        let mut seen = Vec::new();
        for session_id in workers {
            if seen.contains(&session_id) {
                continue;
            }
            seen.push(session_id);
            reported.push(Self::describe(
                &status, &ended, &fences, session_id, revision,
            ));
        }
        // A worker the directory no longer lists but the lease issuer still holds a record of is
        // still part of the barrier: it is exactly the case where a worker was lost rather than
        // confirmed ended, and dropping it would report a revocation as complete because nobody
        // could see the worker any more.
        for session_id in status.acknowledged.iter().chain(status.pending.iter()) {
            if seen.contains(session_id) {
                continue;
            }
            seen.push(*session_id);
            reported.push(Self::describe(
                &status,
                &ended,
                &fences,
                *session_id,
                revision,
            ));
        }
        reported.sort_by_key(|worker| worker.session_id);
        RevocationBarrier {
            authority_revision: revision,
            workers: reported,
        }
    }

    fn describe(
        status: &kr_transport::lease::RevocationStatus,
        ended: &[SessionId],
        fences: &HashMap<SessionId, WorkerFences>,
        session_id: SessionId,
        revision: AuthorityRevision,
    ) -> WorkerBarrier {
        let held = fences.get(&session_id);
        // The names are this revocation's own. Whether the barrier holds is a question a later
        // revocation also answers, because installing it fences everything this one would have.
        let fence = held.and_then(|held| held.at(revision));
        let acknowledged = held
            .and_then(WorkerFences::installed)
            .filter(|held| *held >= revision);
        let reported = held.is_some_and(|held| held.reported_from(revision));
        // An ending is checked before an acknowledgement, because it is the stronger answer: a
        // worker that has ended can no longer dispatch anything, whatever it did or did not say
        // about its fence while it was running.
        let state = if ended.contains(&session_id) {
            BarrierState::Ended
        } else if acknowledged.is_some() && reported {
            BarrierState::Acknowledged
        } else if status.acknowledged.contains(&session_id) && acknowledged.is_none() {
            // The lease issuer counts a worker whose execution has ended as satisfying the
            // barrier. It has no fence report, because it never ran one, and that is the point.
            BarrierState::Ended
        } else {
            BarrierState::Pending
        };
        let pending_names = fence.map_or(0, |report| report.remaining);
        let omitted_names = fence.map_or(0, |report| report.omitted);
        // This revocation answered by a later one: the worker went straight past it, or it
        // installed it without saying what its fence did, or this daemon no longer holds its
        // report. The barrier holds and the names are another revocation's, so this says so rather
        // than letting empty lists read as a fence that named nothing.
        let answered_later = held.is_some_and(|held| {
            !held.at(revision).is_some_and(|report| report.reported)
                && held
                    .installed()
                    .is_some_and(|installed| installed > revision)
        });
        let detail = match state {
            // A barrier that holds can still owe evidence: the names are in the worker's journal
            // and travel a page at a time, so a page exchange that has not happened yet leaves
            // this to say rather than nothing.
            BarrierState::Acknowledged | BarrierState::Ended if pending_names > 0 => format!(
                "this worker's barrier holds, and {pending_names} of the actions its fence named \
                 have not reached this daemon yet; they are in its journal and the next \
                 announcement continues from where the last page ended"
            ),
            // Names that went before they arrived. The worker says how many it no longer holds,
            // and a result missing that many actions is not the complete one section 9 asks for.
            BarrierState::Acknowledged | BarrierState::Ended if omitted_names > 0 => format!(
                "this worker's barrier holds, and {omitted_names} of the actions its fence named \
                 are no longer held by the worker that named them, so this names what reached \
                 this daemon rather than everything the fence found"
            ),
            // The barrier for this revocation held because a later one was installed, and a later
            // revocation's fence is a different question's answer. Only an acknowledgement is
            // explained this way: a worker whose execution ended holds because it can no longer
            // dispatch anything, whatever it had said about any revision.
            BarrierState::Acknowledged if answered_later => format!(
                "this worker's barrier holds because it installed a later revision, which fences \
                 everything revision {revision} would have; this daemon holds no names under \
                 revision {revision} itself"
            ),
            BarrierState::Ended if answered_later => format!(
                "this worker's execution is confirmed ended, so it can no longer dispatch \
                 anything; this daemon holds no names under revision {revision} itself"
            ),
            BarrierState::Acknowledged | BarrierState::Ended => String::new(),
            // Two different ways to be pending, and a person reading `pending` is owed the
            // difference. A worker that installed the revision without reporting what its fence
            // did has answered half the question section 9 asks, and half an answer is not one.
            BarrierState::Pending if acknowledged.is_some() => format!(
                "this worker has installed revision {revision} but reports nothing about the \
                 actions its fence rejected or could not take back, so the revocation is not \
                 complete for it"
            ),
            BarrierState::Pending => format!(
                "this worker has not acknowledged revision {revision} and has not been confirmed \
                 ended, so the revocation is not complete for it"
            ),
        };
        WorkerBarrier {
            session_id,
            state,
            acknowledged_revision: Nullable(acknowledged),
            // Whatever this worker reported, whether or not its barrier ended up held by an
            // acknowledgement or by its own ending. An ending proves that no further dispatch can
            // happen; it says nothing about what already did, and dropping the names would lose
            // exactly the actions section 9 requires to be named.
            rejected_actions: fence
                .map(|report| report.rejected.clone())
                .unwrap_or_default(),
            possibly_executed: fence
                .map(|report| report.possibly_executed.clone())
                .unwrap_or_default(),
            omitted_actions: kr_protocol::scalars::U64::new(omitted_names),
            names_pending: kr_protocol::scalars::U64::new(pending_names),
            detail,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<SessionId, WorkerFences>> {
        self.fences
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Serialises the operations that change more than one of this type's two stores.
    fn ordered(&self) -> std::sync::MutexGuard<'_, ()> {
        self.order
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::ids::ActionId;
    use kr_protocol::method::Method;
    use kr_protocol::receipt::ReceiptState;
    use kr_protocol::scalars::Uuid;
    use kr_transport::clock::ManualClock;
    use std::time::Duration;

    fn session(byte: u8) -> SessionId {
        SessionId::new(Uuid::from_bytes([byte; 16]))
    }

    fn action(byte: u8) -> ActionId {
        ActionId::new(Uuid::from_bytes([byte; 16]))
    }

    fn barrier() -> AuthorityBarrier {
        AuthorityBarrier::new(ControllerGeneration::new(7), AuthorityRevision::new(3))
    }

    #[test]
    fn a_worker_that_installs_a_revision_without_saying_what_its_fence_did_is_pending() {
        // Section 9 makes the acknowledgement two statements: the revision is installed, and the
        // actions it affects have been rejected or named. A worker that makes only the first is a
        // worker whose fence this daemon knows nothing about, and calling that a complete barrier
        // would report a revocation as complete on the strength of something nobody said.
        let barrier = barrier();
        let binding = barrier.bind(session(1));
        assert!(barrier.acknowledge(session(1), binding, AuthorityRevision::new(4), None));
        let report = barrier.report(AuthorityRevision::new(4), [session(1)]);
        assert!(!report.holds());
        assert_eq!(report.workers[0].state, BarrierState::Pending);
        assert_eq!(
            report.workers[0].acknowledged_revision,
            Nullable::some(AuthorityRevision::new(4)),
            "the revision is installed, and the report says so"
        );
        assert!(
            report.workers[0].detail.contains("reports nothing"),
            "{:?}",
            report.workers[0].detail
        );

        // The same worker reporting its fence completes the barrier. Nothing else changed.
        assert!(barrier.acknowledge(
            session(1),
            binding,
            AuthorityRevision::new(4),
            evidence(Vec::new(), Vec::new()),
        ));
        let complete = barrier.report(AuthorityRevision::new(4), [session(1)]);
        assert!(complete.holds(), "{complete:?}");
        assert_eq!(complete.workers[0].state, BarrierState::Acknowledged);
    }

    #[test]
    fn a_worker_confirmed_ended_satisfies_the_barrier_whatever_it_said_about_its_fence() {
        // A worker that installed the revision and reported nothing about its fence is pending.
        // The same worker, once its execution is confirmed ended, can no longer dispatch anything
        // at all, which answers the question section 9 asks rather than leaving it open for ever.
        let barrier = barrier();
        let binding = barrier.bind(session(1));
        assert!(barrier.acknowledge(session(1), binding, AuthorityRevision::new(4), None));
        assert!(
            !barrier
                .report(AuthorityRevision::new(4), [session(1)])
                .holds()
        );
        barrier.worker_ended(session(1));
        let report = barrier.report(AuthorityRevision::new(4), [session(1)]);
        assert!(report.holds(), "{report:?}");
        assert_eq!(report.workers[0].state, BarrierState::Ended);
        assert!(report.workers[0].detail.is_empty());
    }

    #[test]
    fn evidence_is_owed_until_the_worker_says_nothing_remains() {
        let barrier = barrier();
        let binding = barrier.bind(session(1));
        assert!(barrier.acknowledge(
            session(1),
            binding,
            AuthorityRevision::new(4),
            Some(kr_protocol::action::FenceEvidence {
                rejected_actions: vec![fenced(10), fenced(11)],
                possibly_executed: Vec::new(),
                remaining: kr_protocol::scalars::U64::new(3),
                omitted: kr_protocol::scalars::U64::new(0),
            }),
        ));
        assert_eq!(
            barrier.evidence_owed(session(1), AuthorityRevision::new(4)),
            Some(2),
            "the next page starts after the names this daemon holds"
        );
        assert!(barrier.acknowledge(
            session(1),
            binding,
            AuthorityRevision::new(4),
            Some(kr_protocol::action::FenceEvidence {
                rejected_actions: vec![fenced(12), fenced(13), fenced(14)],
                possibly_executed: Vec::new(),
                remaining: kr_protocol::scalars::U64::new(0),
                omitted: kr_protocol::scalars::U64::new(0),
            }),
        ));
        assert_eq!(
            barrier.evidence_owed(session(1), AuthorityRevision::new(4)),
            None,
            "nothing remains, so nothing is owed"
        );
        let report = barrier.report(AuthorityRevision::new(4), [session(1)]);
        assert_eq!(
            report.workers[0].rejected_actions.len(),
            5,
            "the pages together are what the report names"
        );
        // A revision nobody reported evidence for owes none of it.
        assert_eq!(
            barrier.evidence_owed(session(1), AuthorityRevision::new(5)),
            None
        );
    }

    #[test]
    fn a_barrier_that_holds_says_how_many_names_have_not_reached_this_daemon() {
        let barrier = barrier();
        let binding = barrier.bind(session(1));
        assert!(barrier.acknowledge(
            session(1),
            binding,
            AuthorityRevision::new(4),
            Some(kr_protocol::action::FenceEvidence {
                rejected_actions: vec![fenced(10)],
                possibly_executed: Vec::new(),
                remaining: kr_protocol::scalars::U64::new(44),
                omitted: kr_protocol::scalars::U64::new(0),
            }),
        ));
        let report = barrier.report(AuthorityRevision::new(4), [session(1)]);
        assert!(
            report.holds(),
            "the revision is installed and the fence ran"
        );
        assert_eq!(
            report.workers[0].names_pending.get(),
            44,
            "and the report says what has not arrived rather than reading complete"
        );
        assert!(report.workers[0].detail.contains("have not reached"));

        // The continuation arrives. Nothing is outstanding, and the report says so.
        assert!(barrier.acknowledge(
            session(1),
            binding,
            AuthorityRevision::new(4),
            Some(kr_protocol::action::FenceEvidence {
                rejected_actions: vec![fenced(11)],
                possibly_executed: Vec::new(),
                remaining: kr_protocol::scalars::U64::new(0),
                omitted: kr_protocol::scalars::U64::new(0),
            }),
        ));
        let complete = barrier.report(AuthorityRevision::new(4), [session(1)]);
        assert_eq!(complete.workers[0].names_pending.get(), 0);
        assert!(complete.workers[0].detail.is_empty());
        assert_eq!(complete.workers[0].rejected_actions.len(), 2);
    }

    #[test]
    fn an_ending_keeps_the_names_the_worker_had_already_reported() {
        // A worker that named an action past its dispatch marker and then ended. The ending proves
        // that no further dispatch can happen; it says nothing about what already did, and the
        // action section 9 requires to be named is exactly the one that did.
        let barrier = barrier();
        let binding = barrier.bind(session(1));
        assert!(barrier.acknowledge(
            session(1),
            binding,
            AuthorityRevision::new(4),
            evidence(vec![action(10)], vec![possibly_executed(11)]),
        ));
        barrier.worker_ended(session(1));
        let report = barrier.report(AuthorityRevision::new(4), [session(1)]);
        assert!(report.holds());
        assert_eq!(report.workers[0].state, BarrierState::Ended);
        assert_eq!(report.workers[0].rejected_actions, vec![fenced(10)]);
        assert_eq!(
            report.possibly_executed().len(),
            1,
            "an ending does not erase what already happened"
        );
    }

    #[test]
    fn a_report_the_worker_could_not_fit_in_one_frame_carries_the_count_of_what_it_left_out() {
        let barrier = barrier();
        let binding = barrier.bind(session(1));
        assert!(barrier.acknowledge(
            session(1),
            binding,
            AuthorityRevision::new(4),
            Some(kr_protocol::action::FenceEvidence {
                rejected_actions: vec![fenced(10)],
                possibly_executed: vec![possibly_executed(11)],
                remaining: kr_protocol::scalars::U64::new(0),
                omitted: kr_protocol::scalars::U64::new(9_000),
            }),
        ));
        let report = barrier.report(AuthorityRevision::new(4), [session(1)]);
        assert!(report.holds());
        assert_eq!(report.workers[0].omitted_actions.get(), 9_000);
        // A repeat of the same revision does not add the same count twice: what the worker holds
        // is a total, not an increment.
        assert!(barrier.acknowledge(
            session(1),
            binding,
            AuthorityRevision::new(4),
            Some(kr_protocol::action::FenceEvidence {
                rejected_actions: Vec::new(),
                possibly_executed: Vec::new(),
                remaining: kr_protocol::scalars::U64::new(0),
                omitted: kr_protocol::scalars::U64::new(9_000),
            }),
        ));
        assert_eq!(
            barrier
                .report(AuthorityRevision::new(4), [session(1)])
                .workers[0]
                .omitted_actions
                .get(),
            9_000
        );
    }

    #[test]
    fn a_newer_revocation_neither_finishes_the_one_before_it_nor_lends_it_names() {
        // Revision 4 names three hundred actions and two hundred and fifty-six of them arrive.
        // Revision 5 then arrives with names of its own. What revision 4 still owes is revision
        // 4's, and answering it with revision 5's list would name actions revision 4 never
        // covered.
        let barrier = barrier();
        let binding = barrier.bind(session(1));
        assert!(barrier.acknowledge(
            session(1),
            binding,
            AuthorityRevision::new(4),
            Some(kr_protocol::action::FenceEvidence {
                rejected_actions: vec![fenced(10)],
                possibly_executed: Vec::new(),
                remaining: kr_protocol::scalars::U64::new(44),
                omitted: kr_protocol::scalars::U64::new(0),
            }),
        ));
        assert!(barrier.acknowledge(
            session(1),
            binding,
            AuthorityRevision::new(5),
            evidence(vec![action(20)], Vec::new()),
        ));

        assert_eq!(
            barrier.evidence_owed(session(1), AuthorityRevision::new(4)),
            Some(1),
            "the page revision 4 owes is still owed, and continues where its own list ended"
        );
        assert_eq!(
            barrier.evidence_owed(session(1), AuthorityRevision::new(5)),
            None,
            "revision 5's own evidence is complete"
        );

        let fourth = barrier.report(AuthorityRevision::new(4), [session(1)]);
        assert!(fourth.holds(), "{fourth:?}");
        assert_eq!(
            fourth.workers[0].rejected_actions,
            vec![fenced(10)],
            "revision 4's result names what revision 4's fence named"
        );
        assert_eq!(
            fourth.workers[0].names_pending.get(),
            44,
            "and says what has not arrived rather than reading complete"
        );
        assert_eq!(
            fourth.workers[0].acknowledged_revision,
            Nullable::some(AuthorityRevision::new(5)),
            "the worker has installed a later revision, which the report says"
        );

        let fifth = barrier.report(AuthorityRevision::new(5), [session(1)]);
        assert_eq!(fifth.workers[0].rejected_actions, vec![fenced(20)]);
        assert_eq!(fifth.workers[0].names_pending.get(), 0);

        // The continuation of revision 4 arrives after revision 5 was installed, and belongs to
        // revision 4.
        assert!(barrier.acknowledge(
            session(1),
            binding,
            AuthorityRevision::new(4),
            Some(kr_protocol::action::FenceEvidence {
                rejected_actions: vec![fenced(11)],
                possibly_executed: Vec::new(),
                remaining: kr_protocol::scalars::U64::new(0),
                omitted: kr_protocol::scalars::U64::new(0),
            }),
        ));
        let complete = barrier.report(AuthorityRevision::new(4), [session(1)]);
        assert_eq!(
            complete.workers[0].rejected_actions,
            vec![fenced(10), fenced(11)]
        );
        assert_eq!(complete.workers[0].names_pending.get(), 0);
        assert_eq!(
            barrier
                .report(AuthorityRevision::new(5), [session(1)])
                .workers[0]
                .rejected_actions,
            vec![fenced(20)],
            "and revision 5's result is untouched by it"
        );
    }

    #[test]
    fn a_revocation_this_daemon_no_longer_holds_the_names_of_says_so() {
        // The reports are kept by revision and bounded, because a worker that keeps producing
        // revocations nobody collects the evidence of would otherwise grow this daemon one
        // revocation at a time. What the bound may not do is let the oldest read as a fence that
        // named nothing.
        let barrier = barrier();
        let binding = barrier.bind(session(1));
        let oldest = AuthorityRevision::new(1);
        assert!(barrier.acknowledge(
            session(1),
            binding,
            oldest,
            evidence(vec![action(10)], Vec::new()),
        ));
        for revision in 2..=u64::try_from(MAX_HELD_FENCE_REPORTS + 1).expect("a small bound") {
            assert!(barrier.acknowledge(
                session(1),
                binding,
                AuthorityRevision::new(revision),
                evidence(Vec::new(), Vec::new()),
            ));
        }
        let report = barrier.report(oldest, [session(1)]);
        assert!(
            report.holds(),
            "a later revision was installed, which fences everything this one would have"
        );
        assert!(
            report.workers[0].rejected_actions.is_empty(),
            "the names this daemon no longer holds are not replaced by another revocation's"
        );
        assert!(
            report.workers[0]
                .detail
                .contains("holds no names under revision 1"),
            "{:?}",
            report.workers[0].detail
        );
    }

    #[test]
    fn a_revocation_whose_own_fence_said_nothing_is_not_reported_as_one_that_named_nothing() {
        // The worker installs revision 4 and says nothing about its fence, then installs revision
        // 5 and reports that one. Installing 5 fences everything 4 would have, so 4's barrier
        // holds; what it does not do is answer 4's second question, and a result with empty lists
        // and no explanation would read as a fence that found nothing to take back.
        let barrier = barrier();
        let binding = barrier.bind(session(1));
        assert!(barrier.acknowledge(session(1), binding, AuthorityRevision::new(4), None));
        assert!(barrier.acknowledge(
            session(1),
            binding,
            AuthorityRevision::new(5),
            evidence(vec![action(20)], Vec::new()),
        ));
        let report = barrier.report(AuthorityRevision::new(4), [session(1)]);
        assert!(report.holds(), "{report:?}");
        assert!(
            report.workers[0].rejected_actions.is_empty(),
            "revision 5's names are not revision 4's"
        );
        assert!(
            report.workers[0]
                .detail
                .contains("holds no names under revision 4"),
            "{:?}",
            report.workers[0].detail
        );
    }

    #[test]
    fn an_older_revocation_that_still_owes_names_is_one_the_daemon_asks_again_for() {
        let barrier = barrier();
        let binding = barrier.bind(session(1));
        assert!(barrier.acknowledge(
            session(1),
            binding,
            AuthorityRevision::new(4),
            Some(kr_protocol::action::FenceEvidence {
                rejected_actions: vec![fenced(10)],
                possibly_executed: Vec::new(),
                remaining: kr_protocol::scalars::U64::new(44),
                omitted: kr_protocol::scalars::U64::new(0),
            }),
        ));
        assert!(barrier.acknowledge(
            session(1),
            binding,
            AuthorityRevision::new(5),
            evidence(vec![action(20)], Vec::new()),
        ));
        assert_eq!(
            barrier.evidence_outstanding(session(1), AuthorityRevision::new(5)),
            vec![AuthorityRevision::new(4)],
            "the older revocation's page is still owed and still asked for"
        );
        // Once it arrives, nothing is outstanding.
        assert!(barrier.acknowledge(
            session(1),
            binding,
            AuthorityRevision::new(4),
            Some(kr_protocol::action::FenceEvidence {
                rejected_actions: vec![fenced(11)],
                possibly_executed: Vec::new(),
                remaining: kr_protocol::scalars::U64::new(0),
                omitted: kr_protocol::scalars::U64::new(0),
            }),
        ));
        assert!(
            barrier
                .evidence_outstanding(session(1), AuthorityRevision::new(5))
                .is_empty()
        );
    }

    #[test]
    fn an_ended_worker_holds_because_it_ended_rather_than_because_of_a_later_revision() {
        // The same absence of evidence, on a worker that then ended. What holds the barrier is the
        // ending, and the ending is the stronger answer: it says no further dispatch can happen
        // whatever the worker said about any revision.
        let barrier = barrier();
        let binding = barrier.bind(session(1));
        assert!(barrier.acknowledge(session(1), binding, AuthorityRevision::new(4), None));
        assert!(barrier.acknowledge(session(1), binding, AuthorityRevision::new(5), None));
        barrier.worker_ended(session(1));
        let report = barrier.report(AuthorityRevision::new(4), [session(1)]);
        assert!(report.holds(), "{report:?}");
        assert_eq!(report.workers[0].state, BarrierState::Ended);
        assert!(
            report.workers[0].detail.contains("confirmed ended"),
            "{:?}",
            report.workers[0].detail
        );
        assert!(
            !report.workers[0]
                .detail
                .contains("installed a later revision"),
            "{:?}",
            report.workers[0].detail
        );
    }

    /// The evidence one fence pass reported, complete in one page.
    fn evidence(
        rejected: Vec<ActionId>,
        possibly_executed: Vec<PossiblyExecutedAction>,
    ) -> Option<kr_protocol::action::FenceEvidence> {
        Some(kr_protocol::action::FenceEvidence {
            rejected_actions: rejected
                .into_iter()
                .map(|action_id| kr_protocol::action::FencedAction {
                    actor_id: kr_protocol::ids::ActorId::new("device:phone").expect("a principal"),
                    action_id,
                })
                .collect(),
            possibly_executed,
            remaining: kr_protocol::scalars::U64::new(0),
            omitted: kr_protocol::scalars::U64::new(0),
        })
    }

    /// The name of one rejected action, as a report holds it.
    fn fenced(byte: u8) -> kr_protocol::action::FencedAction {
        kr_protocol::action::FencedAction {
            actor_id: kr_protocol::ids::ActorId::new("device:phone").expect("a principal"),
            action_id: action(byte),
        }
    }

    fn possibly_executed(byte: u8) -> PossiblyExecutedAction {
        PossiblyExecutedAction {
            action_id: action(byte),
            actor_id: kr_protocol::ids::ActorId::new("device:phone").expect("a principal"),
            method: Method::AgentApprovalRespond.into(),
            state: ReceiptState::Unknown,
        }
    }

    fn connection(byte: u8) -> ConnectionId {
        ConnectionId::new(Uuid::from_bytes([byte; 16]))
    }

    fn admission(clock: &ManualClock, lifetime: Duration) -> AdmittedMutation {
        AdmittedMutation {
            connection_id: connection(1),
            admitted_revision: AuthorityRevision::new(3),
            deadline: clock.now().checked_add(lifetime),
        }
    }

    fn context(clock: &ManualClock, revision: u64, registered: bool) -> AdmissionContext {
        AdmissionContext {
            now: clock.now(),
            authority_revision: AuthorityRevision::new(revision),
            registered,
        }
    }

    #[test]
    fn an_admission_that_still_stands_permits_the_write() {
        let clock = ManualClock::new();
        let admission = admission(&clock, Duration::from_secs(120));
        clock.advance(Duration::from_secs(119));
        assert_eq!(admission.check(context(&clock, 3, true)), Ok(()));
    }

    #[test]
    fn an_admission_whose_deadline_passed_during_the_wait_is_refused() {
        let clock = ManualClock::new();
        let admission = admission(&clock, Duration::from_secs(120));
        // The mutation waited on a store lock for longer than it had left.
        clock.advance(Duration::from_secs(121));
        assert_eq!(
            admission.check(context(&clock, 3, true)),
            Err(AdmissionLapse::Expired)
        );
    }

    #[test]
    fn a_zero_lifetime_admission_is_refused_at_the_transaction_rather_than_written() {
        let clock = ManualClock::new();
        let admission = admission(&clock, Duration::ZERO);
        assert_eq!(
            admission.check(context(&clock, 3, true)),
            Err(AdmissionLapse::Expired),
            "a lifetime of zero means what it says"
        );
    }

    #[test]
    fn an_admission_whose_authority_was_revoked_during_the_wait_is_refused() {
        let clock = ManualClock::new();
        let admission = admission(&clock, Duration::from_secs(120));
        assert_eq!(
            admission.check(context(&clock, 4, true)),
            Err(AdmissionLapse::Revoked)
        );
    }

    #[test]
    fn an_admission_whose_registration_was_withdrawn_is_refused() {
        let clock = ManualClock::new();
        let admission = admission(&clock, Duration::from_secs(120));
        assert_eq!(
            admission.check(context(&clock, 3, false)),
            Err(AdmissionLapse::Deregistered)
        );
    }

    #[test]
    fn a_revocation_is_reported_before_a_spent_deadline_because_it_is_the_stronger_answer() {
        // A retry may go on when its freshness is gone, because a receipt outlives the window that
        // admitted it. It may never go on when its authority is gone. So the weaker lapse is
        // reported last: a caller that reads past it for the first reason cannot read past a
        // revocation with it.
        let clock = ManualClock::new();
        let admission = admission(&clock, Duration::from_secs(1));
        clock.advance(Duration::from_secs(2));
        assert_eq!(
            admission.check(context(&clock, 9, false)),
            Err(AdmissionLapse::Revoked)
        );
        assert_eq!(
            admission.check(context(&clock, 3, false)),
            Err(AdmissionLapse::Deregistered)
        );
        assert_eq!(
            admission.check(context(&clock, 3, true)),
            Err(AdmissionLapse::Expired)
        );
    }

    #[test]
    fn a_worker_that_has_not_answered_is_pending_rather_than_absent() {
        let barrier = barrier();
        let report = barrier.report(AuthorityRevision::new(4), [session(1)]);
        assert!(!report.holds());
        assert_eq!(report.pending(), vec![session(1)]);
        assert_eq!(report.workers[0].state, BarrierState::Pending);
        assert!(
            report.workers[0].detail.contains("not complete"),
            "{:?}",
            report.workers[0].detail
        );
    }

    #[test]
    fn an_acknowledgement_completes_one_workers_barrier_and_carries_its_lists() {
        let barrier = barrier();
        let binding = barrier.bind(session(1));
        barrier.revoke(AuthorityRevision::new(4));
        barrier.acknowledge(
            session(1),
            binding,
            AuthorityRevision::new(4),
            evidence(vec![action(10)], vec![possibly_executed(11)]),
        );
        let report = barrier.report(AuthorityRevision::new(4), [session(1)]);
        assert!(report.holds());
        assert_eq!(report.workers[0].state, BarrierState::Acknowledged);
        assert_eq!(report.workers[0].rejected_actions, vec![fenced(10)]);
        assert_eq!(
            report.possibly_executed().len(),
            1,
            "the action that won the serial race is named rather than counted"
        );
        assert_eq!(report.possibly_executed()[0].action_id, action(11));
    }

    #[test]
    fn the_barrier_is_pending_until_every_worker_holds() {
        let barrier = barrier();
        let first = barrier.bind(session(1));
        barrier.bind(session(2));
        barrier.revoke(AuthorityRevision::new(4));
        barrier.acknowledge(
            session(1),
            first,
            AuthorityRevision::new(4),
            evidence(Vec::new(), Vec::new()),
        );
        let report = barrier.report(AuthorityRevision::new(4), [session(1), session(2)]);
        assert!(!report.holds());
        assert_eq!(report.pending(), vec![session(2)]);

        // The second worker's execution ends, which answers the same question a different way.
        barrier.worker_ended(session(2));
        let report = barrier.report(AuthorityRevision::new(4), [session(1), session(2)]);
        assert!(report.holds());
        assert_eq!(report.workers[1].state, BarrierState::Ended);
        assert!(
            report.workers[1].rejected_actions.is_empty(),
            "a worker that ended never ran a fence, so it reports no lists"
        );
    }

    #[test]
    fn a_lease_timer_running_out_is_not_completion() {
        let clock = ManualClock::new();
        let barrier = barrier();
        let binding = barrier.bind(session(1));
        barrier.acknowledge(
            session(1),
            binding,
            AuthorityRevision::new(3),
            evidence(Vec::new(), Vec::new()),
        );
        let lease = barrier
            .renew(session(1), ControllerGeneration::new(7), &clock)
            .expect("the generator is available")
            .expect("a lease");
        assert!(lease.permits(
            clock.now(),
            ControllerGeneration::new(7),
            AuthorityRevision::new(3)
        ));

        barrier.revoke(AuthorityRevision::new(4));
        // Far beyond the lease's five seconds. The lease cannot authorise a dispatch any more, and
        // the barrier is still not complete, because nothing has established what the worker was
        // doing when the revision changed.
        clock.advance(Duration::from_secs(3_600));
        assert!(!lease.permits(
            clock.now(),
            ControllerGeneration::new(7),
            AuthorityRevision::new(4)
        ));
        let report = barrier.report(AuthorityRevision::new(4), [session(1)]);
        assert!(
            !report.holds(),
            "waiting for a lease timer is not an acknowledgement"
        );
    }

    #[test]
    fn a_replaced_control_path_keeps_the_fence_and_re_earns_the_lease() {
        let clock = ManualClock::new();
        let barrier = barrier();
        let first = barrier.bind(session(1));
        barrier.revoke(AuthorityRevision::new(4));
        barrier.acknowledge(
            session(1),
            first,
            AuthorityRevision::new(4),
            evidence(vec![action(10)], vec![possibly_executed(11)]),
        );
        assert!(
            barrier
                .report(AuthorityRevision::new(4), [session(1)])
                .holds()
        );

        // The path is lost and replaced. The fence ran, so the revocation stays complete for this
        // worker: losing a socket does not un-install a revision, and the actions the fence could
        // not take back are still what the result has to name.
        barrier.stop_renewal(session(1), first);
        let second = barrier.bind(session(1));
        let report = barrier.report(AuthorityRevision::new(4), [session(1)]);
        assert!(report.holds(), "the fence ran, and it stays run");
        assert_eq!(report.workers[0].rejected_actions, vec![fenced(10)]);
        assert_eq!(report.possibly_executed().len(), 1);

        // What the replacement has to earn again is the lease: renewal stopped with the path, and
        // it resumes only on an acknowledgement of the revision in force over the path in force.
        assert_eq!(
            barrier
                .renew(session(1), ControllerGeneration::new(7), &clock)
                .expect("the generator is available"),
            Err(LeaseRefusal::RevisionNotAcknowledged)
        );
        barrier.acknowledge(
            session(1),
            second,
            AuthorityRevision::new(4),
            evidence(Vec::new(), Vec::new()),
        );
        assert!(
            barrier
                .renew(session(1), ControllerGeneration::new(7), &clock)
                .expect("the generator is available")
                .is_ok()
        );
    }

    #[test]
    fn an_acknowledgement_lost_on_the_way_back_does_not_lose_what_the_fence_named() {
        // The worker fences once and names what it could not take back. Its answer is lost, the
        // path is replaced, and it is asked again: the second answer carries no lists, because the
        // fence already ran. The result still names the action.
        let barrier = barrier();
        let first = barrier.bind(session(1));
        barrier.revoke(AuthorityRevision::new(4));
        barrier.acknowledge(
            session(1),
            first,
            AuthorityRevision::new(4),
            evidence(vec![action(10)], vec![possibly_executed(11)]),
        );
        let second = barrier.bind(session(1));
        barrier.acknowledge(
            session(1),
            second,
            AuthorityRevision::new(4),
            evidence(Vec::new(), Vec::new()),
        );
        let report = barrier.report(AuthorityRevision::new(4), [session(1)]);
        assert_eq!(report.workers[0].rejected_actions, vec![fenced(10)]);
        assert_eq!(report.possibly_executed().len(), 1);
    }

    #[test]
    fn a_late_acknowledgement_of_an_older_revision_does_not_undo_a_newer_one() {
        let barrier = barrier();
        let binding = barrier.bind(session(1));
        barrier.revoke(AuthorityRevision::new(4));
        barrier.acknowledge(
            session(1),
            binding,
            AuthorityRevision::new(4),
            evidence(vec![action(10)], Vec::new()),
        );
        // An answer to the previous announcement, arriving after the current one. It is not news.
        barrier.acknowledge(
            session(1),
            binding,
            AuthorityRevision::new(3),
            evidence(vec![action(20)], Vec::new()),
        );
        let report = barrier.report(AuthorityRevision::new(4), [session(1)]);
        assert!(report.holds(), "the newer acknowledgement stands");
        assert_eq!(report.workers[0].rejected_actions, vec![fenced(10)]);
    }

    #[test]
    fn a_barrier_with_no_participants_is_not_one_that_holds_over_a_worker_it_cannot_see() {
        // A daemon that has just replaced another starts with nothing in its lease table. What it
        // does have is the registry's worker rows, and passing them in is what makes an isolated
        // worker a pending participant rather than one nobody can see.
        let barrier = barrier();
        barrier.revoke(AuthorityRevision::new(4));
        let blind = barrier.report(AuthorityRevision::new(4), []);
        assert!(
            blind.workers.is_empty(),
            "a report over nothing describes nothing"
        );
        let informed = barrier.report(AuthorityRevision::new(4), [session(1), session(2)]);
        assert!(!informed.holds());
        assert_eq!(informed.pending(), vec![session(1), session(2)]);
    }

    #[test]
    fn an_acknowledgement_over_a_lost_path_changes_nothing() {
        let barrier = barrier();
        let lost = barrier.bind(session(1));
        barrier.revoke(AuthorityRevision::new(4));
        barrier.stop_renewal(session(1), lost);
        // The acknowledgement was already travelling when the path was given up on.
        barrier.acknowledge(
            session(1),
            lost,
            AuthorityRevision::new(4),
            evidence(vec![action(10)], Vec::new()),
        );
        let report = barrier.report(AuthorityRevision::new(4), [session(1)]);
        assert!(!report.holds());
        assert!(report.workers[0].rejected_actions.is_empty());
    }

    #[test]
    fn an_older_acknowledgement_does_not_complete_a_newer_revocation() {
        let barrier = barrier();
        let binding = barrier.bind(session(1));
        barrier.acknowledge(
            session(1),
            binding,
            AuthorityRevision::new(3),
            evidence(Vec::new(), Vec::new()),
        );
        barrier.revoke(AuthorityRevision::new(4));
        let report = barrier.report(AuthorityRevision::new(4), [session(1)]);
        assert!(!report.holds());
        assert_eq!(report.workers[0].state, BarrierState::Pending);
    }

    #[test]
    fn a_repeat_acknowledgement_keeps_the_lists_the_fence_produced() {
        let barrier = barrier();
        let binding = barrier.bind(session(1));
        barrier.revoke(AuthorityRevision::new(4));
        barrier.acknowledge(
            session(1),
            binding,
            AuthorityRevision::new(4),
            evidence(vec![action(10)], vec![possibly_executed(11)]),
        );
        // The worker is asked again and answers with the revision it already holds, which carries
        // no lists because its fence ran once.
        barrier.acknowledge(
            session(1),
            binding,
            AuthorityRevision::new(4),
            evidence(Vec::new(), Vec::new()),
        );
        let report = barrier.report(AuthorityRevision::new(4), [session(1)]);
        assert_eq!(report.workers[0].rejected_actions, vec![fenced(10)]);
        assert_eq!(report.workers[0].possibly_executed.len(), 1);
    }

    #[test]
    fn a_worker_the_directory_no_longer_lists_is_still_part_of_the_barrier() {
        let barrier = barrier();
        let binding = barrier.bind(session(1));
        barrier.revoke(AuthorityRevision::new(4));
        barrier.stop_renewal(session(1), binding);
        // Nothing is passed in: the directory has lost the worker. Losing sight of a worker is not
        // evidence that it stopped.
        let report = barrier.report(AuthorityRevision::new(4), []);
        assert_eq!(report.workers.len(), 1);
        assert!(!report.holds());
    }

    #[test]
    fn a_replacement_generation_cannot_renew_a_lease_it_did_not_issue() {
        let clock = ManualClock::new();
        let barrier = barrier();
        let binding = barrier.bind(session(1));
        barrier.acknowledge(
            session(1),
            binding,
            AuthorityRevision::new(3),
            evidence(Vec::new(), Vec::new()),
        );
        let refused = barrier
            .renew(session(1), ControllerGeneration::new(8), &clock)
            .expect("the generator is available");
        assert_eq!(refused, Err(LeaseRefusal::GenerationReplaced));
    }

    #[test]
    fn renewal_waits_for_the_acknowledgement_of_the_revision_in_force() {
        let clock = ManualClock::new();
        let barrier = barrier();
        let binding = barrier.bind(session(1));
        // Nothing acknowledged yet.
        assert_eq!(
            barrier
                .renew(session(1), ControllerGeneration::new(7), &clock)
                .expect("the generator is available"),
            Err(LeaseRefusal::RevisionNotAcknowledged)
        );
        barrier.acknowledge(
            session(1),
            binding,
            AuthorityRevision::new(3),
            evidence(Vec::new(), Vec::new()),
        );
        assert!(
            barrier
                .renew(session(1), ControllerGeneration::new(7), &clock)
                .expect("the generator is available")
                .is_ok()
        );
        // The revision advances. Renewal stops until the worker acknowledges the new one, so a
        // replacement cannot adopt an envelope queued under the old one.
        barrier.revoke(AuthorityRevision::new(4));
        assert_eq!(
            barrier
                .renew(session(1), ControllerGeneration::new(7), &clock)
                .expect("the generator is available"),
            Err(LeaseRefusal::RevisionNotAcknowledged)
        );
        assert!(barrier.current_lease(session(1)).is_none_or(|lease| {
            !lease.permits(
                clock.now(),
                ControllerGeneration::new(7),
                AuthorityRevision::new(4),
            )
        }));
    }

    #[test]
    fn losing_the_generation_binding_stops_renewal() {
        let clock = ManualClock::new();
        let barrier = barrier();
        let binding = barrier.bind(session(1));
        barrier.acknowledge(
            session(1),
            binding,
            AuthorityRevision::new(3),
            evidence(Vec::new(), Vec::new()),
        );
        assert!(
            barrier
                .renew(session(1), ControllerGeneration::new(7), &clock)
                .expect("the generator is available")
                .is_ok()
        );
        barrier.stop_renewal(session(1), binding);
        assert!(barrier.is_fenced(session(1)));
        assert_eq!(
            barrier
                .renew(session(1), ControllerGeneration::new(7), &clock)
                .expect("the generator is available"),
            Err(LeaseRefusal::RevisionNotAcknowledged)
        );
        assert!(barrier.current_lease(session(1)).is_none());
    }
}
