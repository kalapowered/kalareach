//! Privacy mode's four calls, over this crate's own stores, one session at a time.
//!
//! Section 24 names generated descriptions twice: *enabling privacy mode immediately fences
//! content-bearing outboxes/captures, cancels undispatched backup/sync/description work, removes
//! retained local output/semantic-history caches and generated descriptions, and uses metadata-only
//! titles*, and *user-pinned labels are retained locally unless explicitly cleared*.
//!
//! [`kr_worker::privacy::PrivacySubsystem`] is that contract, and this module implements it over
//! the three things this crate holds for a session: its place in the queue, its retained context,
//! and its row in the description store.
//!
//! # Why every one of these is per session
//!
//! Privacy mode's generation is the environment's, and every session applies it, but a session
//! applies it at its own moment: `Session::enable_privacy` records it in that session's journal
//! when the session is told. The model is shared and the queue is shared, but what privacy mode
//! reaches is each session's, so every type here is keyed by [`SessionId`] and
//! [`crate::service::DescriptionService::privacy`] hands out a hook for one session. A hook that
//! emptied the whole queue would be cancelling work for sessions not yet told.
//!
//! | Call | What it does here |
//! | --- | --- |
//! | `fence` | Raises the fence for this session and cancels its job if one is running |
//! | `cancel_undispatched` | Drops this session's queued job, and counts a running one as in flight |
//! | `remove_retained` | Deletes this session's generated description and forgets its context and events |
//! | `outstanding` | Its running job; a removal that did not finish is unavailable, with its reason |
//! | `kept` | Pins, named, with why they stay |
//! | `exported` | Nothing. A description is never sent anywhere |
//!
//! # The late-result rule is not restated here
//!
//! [`kr_worker::privacy::PrivacyMode::accepts_result`] is the whole rule and it lives on the mode.
//! What this crate does is carry the generation on the job, from admission to publication, and
//! check the fence again *after* the runtime answers, so a fence raised while a job was running
//! refuses its result rather than publishing it.
//!
//! # Metadata-only titles
//!
//! While a session's fence is up, [`crate::service::DescriptionService::label`] does not read its
//! generated record at all, so the answer is a pin or a deterministic title from the instant the
//! fence goes up rather than from the moment the removal finishes.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use kr_protocol::ids::SessionId;
use kr_worker::privacy::{
    Cancelled, Exported, Fenced, KeptExplicitly, PrivacyGeneration, PrivacySubsystem, Removed,
    Unavailable,
};

use crate::context::{ContextTracker, SemanticEvent};
use crate::priority::Cancellation;
use crate::queue::Scheduler;
use crate::store::DescriptionStore;

/// Which sessions have description processing stopped, and at which generation.
///
/// It is shared rather than owned because the thing that raises it - privacy mode - and the things
/// that obey it - admission, dispatch, publication and the label path - are held by different
/// owners. Raising it is one store, and it is seen by everything at once, which is what
/// *immediately* has to mean.
#[derive(Clone, Debug, Default)]
pub struct DescriptionFence {
    fenced: Arc<Mutex<BTreeMap<SessionId, PrivacyGeneration>>>,
}

/// What happened when attempting to publish under the fence lock.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublishGate {
    /// Publication succeeded.
    Allowed,
    /// The session's fence was raised.
    Fenced,
    /// A fence was raised at a newer generation.
    LateGeneration {
        /// What the fence recorded.
        expected: PrivacyGeneration,
        /// What the job was produced under.
        found: PrivacyGeneration,
    },
    /// The job's cancellation token fired.
    Cancelled,
    /// The whole-job deadline was exceeded.
    DeadlineExceeded,
    /// The session's name is pinned, so the store recorded nothing.
    NamePinned,
}

/// Why a write through a job's token recorded nothing.
enum NotWritten {
    /// The session has a pin.
    NamePinned,
    /// The store refused the write.
    Store(crate::DescribeError),
}

impl DescriptionFence {
    /// Builds a fence that is down for every session.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns whether a session's description processing is stopped.
    #[must_use]
    pub fn is_fenced(&self, session_id: &SessionId) -> bool {
        self.generation(session_id).is_some()
    }

    /// Returns the generation a session's fence was raised at, when it is up.
    #[must_use]
    pub fn generation(&self, session_id: &SessionId) -> Option<PrivacyGeneration> {
        self.fenced
            .lock()
            .ok()
            .and_then(|held| held.get(session_id).copied())
    }

    /// Raises a session's fence at a generation.
    pub fn raise(&self, session_id: SessionId, generation: PrivacyGeneration) {
        if let Ok(mut held) = self.fenced.lock() {
            held.insert(session_id, generation);
        }
    }

    /// Lowers a session's fence, which is what disabling privacy mode does.
    ///
    /// Section 24: disabling *starts new retention from that point and cannot reconstruct omitted
    /// history*. Lowering the fence lets new descriptions be produced. It restores nothing, and
    /// the context this session had while it was private has already been forgotten.
    pub fn lower(&self, session_id: &SessionId) {
        if let Ok(mut held) = self.fenced.lock() {
            held.remove(session_id);
        }
    }

    /// Returns how many sessions are fenced.
    #[must_use]
    pub fn fenced_sessions(&self) -> usize {
        self.fenced.lock().map_or(0, |held| held.len())
    }

    /// Publishes a description under the fence's lock if the session is not fenced, not cancelled,
    /// and has not exceeded its whole-job deadline.
    ///
    /// `elapsed_ms` is how long the job has run since it was dequeued, which the caller measures on
    /// the clock every other interval here is measured on.
    #[allow(clippy::too_many_arguments)]
    pub fn publish_under_lock(
        &self,
        store: &DescriptionStore,
        session_id: &SessionId,
        description: &crate::output::GeneratedDescription,
        wall_ms: u64,
        produced_generation: PrivacyGeneration,
        fallback_generation: PrivacyGeneration,
        cancellation: &Cancellation,
        elapsed_ms: u64,
        deadline_ms: u64,
    ) -> crate::error::Result<PublishGate> {
        self.publish_with(
            session_id,
            produced_generation,
            fallback_generation,
            cancellation,
            elapsed_ms,
            deadline_ms,
            || match store.publish(session_id, description, wall_ms) {
                Ok(crate::store::Published::Recorded) => Ok(()),
                Ok(crate::store::Published::NamePinned) => Err(NotWritten::NamePinned),
                Err(error) => Err(NotWritten::Store(error)),
            },
        )
    }

    /// Publishes a summary under the fence's lock if the session is not fenced, not cancelled,
    /// and has not exceeded its whole-job deadline: [`Self::publish_under_lock`] for the other
    /// kind of result, produced under the generation the record carries.
    ///
    /// # Errors
    ///
    /// Returns the store's error when the write fails.
    pub fn publish_summary_under_lock(
        &self,
        store: &DescriptionStore,
        record: &crate::summary::SummaryRecord,
        fallback_generation: PrivacyGeneration,
        cancellation: &Cancellation,
        elapsed_ms: u64,
        deadline_ms: u64,
    ) -> crate::error::Result<PublishGate> {
        self.publish_with(
            &record.session_id,
            record.generation,
            fallback_generation,
            cancellation,
            elapsed_ms,
            deadline_ms,
            || store.publish_summary(record).map_err(NotWritten::Store),
        )
    }

    /// The rules of publishing under the fence, for a write that is one kind of result's own.
    #[allow(clippy::too_many_arguments)]
    fn publish_with(
        &self,
        session_id: &SessionId,
        produced_generation: PrivacyGeneration,
        fallback_generation: PrivacyGeneration,
        cancellation: &Cancellation,
        elapsed_ms: u64,
        deadline_ms: u64,
        write: impl FnOnce() -> Result<(), NotWritten>,
    ) -> crate::error::Result<PublishGate> {
        let held = self
            .fenced
            .lock()
            .map_err(|_| crate::DescribeError::Runtime {
                detail: "fence mutex poisoned".to_owned(),
            })?;
        if let Some(&fence_gen) = held.get(session_id) {
            if fence_gen != produced_generation {
                return Ok(PublishGate::LateGeneration {
                    expected: fence_gen,
                    found: produced_generation,
                });
            }
            return Ok(PublishGate::Fenced);
        }
        if fallback_generation != produced_generation {
            return Ok(PublishGate::LateGeneration {
                expected: fallback_generation,
                found: produced_generation,
            });
        }
        if cancellation.is_cancelled() {
            return Ok(PublishGate::Cancelled);
        }
        if elapsed_ms > deadline_ms {
            return Ok(PublishGate::DeadlineExceeded);
        }
        // The fence is held for the write, so a fence raised on another thread waits for it and
        // then applies to the next job. Cancellation is not a lock, so the write goes through the
        // token itself: a cancellation that arrives while the row is being written waits for it and
        // is told it was too late, rather than returning to its caller over a description it did
        // not stop. Nothing is removed here, because the row a removal would take is the session's
        // only generated description and an earlier job published it. A pin that stops the write
        // is a write that recorded nothing, so the token goes back to cancellable, as it does for a
        // write the store refused.
        let written = cancellation.publish_unless_cancelled(write);
        match written {
            None => Ok(PublishGate::Cancelled),
            Some(Ok(())) => Ok(PublishGate::Allowed),
            Some(Err(NotWritten::NamePinned)) => Ok(PublishGate::NamePinned),
            Some(Err(NotWritten::Store(error))) => Err(error),
        }
    }
}

/// How many description jobs have been dispatched and not yet reconciled, per session.
///
/// A dispatched job is out of the queue and inside the runtime. Cancelling cannot take it back, so
/// privacy mode counts it as in flight and reconciliation is this number reaching nought.
#[derive(Clone, Debug, Default)]
pub struct InFlight {
    total: Arc<AtomicU64>,
    by_session: Arc<Mutex<BTreeMap<SessionId, u64>>>,
}

impl InFlight {
    /// Builds a counter at nought.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records that a session's job has been dispatched.
    pub fn dispatched(&self, session_id: SessionId) {
        self.total.fetch_add(1, Ordering::AcqRel);
        if let Ok(mut held) = self.by_session.lock() {
            *held.entry(session_id).or_insert(0) += 1;
        }
    }

    /// Records that a session's job has finished, however it finished.
    pub fn reconciled(&self, session_id: &SessionId) {
        // Saturating rather than wrapping: a count that went below nought would report
        // reconciliation complete for work nobody had accounted for.
        let _ = self
            .total
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |held| {
                Some(held.saturating_sub(1))
            });
        if let Ok(mut held) = self.by_session.lock()
            && let Some(count) = held.get_mut(session_id)
        {
            *count = count.saturating_sub(1);
            if *count == 0 {
                held.remove(session_id);
            }
        }
    }

    /// Returns how many jobs are in flight for one session.
    #[must_use]
    pub fn get(&self, session_id: &SessionId) -> u64 {
        self.by_session
            .lock()
            .map_or(0, |held| held.get(session_id).copied().unwrap_or(0))
    }

    /// Returns how many jobs are in flight across every session.
    #[must_use]
    pub fn total(&self) -> u64 {
        self.total.load(Ordering::Acquire)
    }

    /// Returns how many jobs are in flight for one session, or why that cannot be read.
    ///
    /// A count left locked by a call that failed is not a count of nought, and privacy mode's
    /// reconciliation reads it through this.
    ///
    /// # Errors
    ///
    /// Returns [`Unavailable`] when the count was left locked by a call that failed.
    pub fn read(&self, session_id: &SessionId) -> Result<u64, Unavailable> {
        self.by_session
            .lock()
            .map(|held| held.get(session_id).copied().unwrap_or(0))
            .map_err(|_| {
                Unavailable::new(
                    "the count of description jobs in flight was left locked by a call that failed",
                )
            })
    }
}

/// The job the runtime is executing right now, and the token that cancels it.
///
/// A job runs inside one call, so the only way to stop it from outside is a token somebody else
/// holds. This is that handle: raising a session's fence cancels its running job through it, and
/// the runtime checks the token between tokens of output.
///
/// A cancellation made through this handle is a caller's, and it outlasts anything the service
/// decides for reasons of its own: a job a caller cancelled is never queued again, not even one a
/// pause had already stopped. The service closes the handle at the moment it decides what a job
/// that did not finish comes to, so a cancellation either arrives first and is honoured, or
/// arrives after and finds nothing running. Only the service starts, finishes and closes a job
/// here, and the job's token never leaves it: this handle is the one way to cancel from outside.
#[derive(Clone, Debug, Default)]
pub struct RunningJob {
    held: Arc<Mutex<Option<Running>>>,
}

/// The job a [`RunningJob`] holds.
#[derive(Debug)]
struct Running {
    session_id: SessionId,
    cancellation: Cancellation,
    /// Whether a caller cancelled it through the handle.
    by_caller: bool,
}

impl RunningJob {
    /// Builds a handle with nothing running.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records that a session's job has started, and returns its cancellation token.
    #[must_use]
    pub(crate) fn started(&self, session_id: SessionId) -> Cancellation {
        let cancellation = Cancellation::new();
        if let Ok(mut held) = self.held.lock() {
            *held = Some(Running {
                session_id,
                cancellation: cancellation.clone(),
                by_caller: false,
            });
        }
        cancellation
    }

    /// Records that the running job has finished.
    pub(crate) fn finished(&self) {
        if let Ok(mut held) = self.held.lock() {
            *held = None;
        }
    }

    /// Returns whether this session's job is the one running.
    #[must_use]
    pub fn is_running(&self, session_id: &SessionId) -> bool {
        self.held.lock().is_ok_and(|held| {
            held.as_ref()
                .is_some_and(|running| running.session_id == *session_id)
        })
    }

    /// Cancels the running job when it is this session's, and says whether it stopped one.
    ///
    /// It is false when no job of this session's is running and false when the job's description
    /// had already reached the store, because in both cases this call took nothing back.
    pub fn cancel(&self, session_id: &SessionId) -> bool {
        let Ok(mut held) = self.held.lock() else {
            return false;
        };
        match held.as_mut() {
            Some(running) if running.session_id == *session_id => {
                let stopped = running.cancellation.cancel();
                running.by_caller |= stopped;
                stopped
            }
            _ => false,
        }
    }

    /// Closes this session's running job, and says whether a caller cancelled it first.
    ///
    /// The service calls this when it decides what a job that did not finish comes to. From then on
    /// a cancellation finds nothing running and says so, so no caller is told it stopped a job that
    /// is then queued again.
    pub(crate) fn close(&self, session_id: &SessionId) -> bool {
        let mut held = self
            .held
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        held.take_if(|running| running.session_id == *session_id)
            .is_some_and(|running| running.by_caller)
    }
}

/// Cleanup this host was asked to do and could not finish.
///
/// It belongs to the service rather than to the hook, because a hook is built for one call and
/// dropped. A debt that lived on the hook would disappear the moment privacy mode asked again, and
/// the next reconciliation would report complete over content that is still there. A failed
/// removal is the only thing that sets it, and a removal that succeeds is the only thing that
/// clears it.
#[derive(Clone, Debug, Default)]
pub struct CleanupDebt {
    owed: Arc<Mutex<BTreeMap<SessionId, String>>>,
}

impl CleanupDebt {
    /// Builds a debt of nothing.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records that a session's cleanup could not finish.
    pub fn owe(&self, session_id: SessionId, why: String) {
        if let Ok(mut held) = self.owed.lock() {
            held.insert(session_id, why);
        }
    }

    /// Records that a session's cleanup finished, which is the only thing that clears a debt.
    pub fn settle(&self, session_id: &SessionId) {
        if let Ok(mut held) = self.owed.lock() {
            held.remove(session_id);
        }
    }

    /// Returns why a session's cleanup is outstanding, when it is.
    #[must_use]
    pub fn owed(&self, session_id: &SessionId) -> Option<String> {
        self.owed
            .lock()
            .ok()
            .and_then(|held| held.get(session_id).cloned())
    }

    /// Returns why a session's cleanup is outstanding, when it is, or why that cannot be read.
    ///
    /// A record left locked by a call that failed is not a record of nothing owed.
    ///
    /// # Errors
    ///
    /// Returns [`Unavailable`] when the record was left locked by a call that failed.
    pub fn read(&self, session_id: &SessionId) -> Result<Option<String>, Unavailable> {
        self.owed
            .lock()
            .map(|held| held.get(session_id).cloned())
            .map_err(|_| {
                Unavailable::new(
                    "the record of description cleanup owed was left locked by a call that failed",
                )
            })
    }

    /// Returns how many sessions have cleanup outstanding.
    #[must_use]
    pub fn len(&self) -> usize {
        self.owed.lock().map_or(0, |held| held.len())
    }

    /// Returns whether every session's cleanup has finished.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Privacy mode's hook over one session's queue position, context and store row.
#[derive(Debug)]
pub struct DescriptionPrivacy<'a> {
    session_id: SessionId,
    fence: &'a DescriptionFence,
    scheduler: &'a mut Scheduler,
    tracker: Option<&'a mut ContextTracker>,
    events: Option<&'a mut Vec<SemanticEvent>>,
    store: &'a DescriptionStore,
    in_flight: &'a InFlight,
    running: &'a RunningJob,
    debt: &'a CleanupDebt,
}

impl<'a> DescriptionPrivacy<'a> {
    /// Builds the hook for one session.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn over(
        session_id: SessionId,
        fence: &'a DescriptionFence,
        scheduler: &'a mut Scheduler,
        tracker: Option<&'a mut ContextTracker>,
        events: Option<&'a mut Vec<SemanticEvent>>,
        store: &'a DescriptionStore,
        in_flight: &'a InFlight,
        running: &'a RunningJob,
        debt: &'a CleanupDebt,
    ) -> Self {
        Self {
            session_id,
            fence,
            scheduler,
            tracker,
            events,
            store,
            in_flight,
            running,
            debt,
        }
    }

    /// Returns why this session's removal could not finish, when it could not.
    ///
    /// It is the service's record rather than this hook's, so it outlives the hook that saw the
    /// failure.
    #[must_use]
    pub fn failure(&self) -> Option<String> {
        self.debt.owed(&self.session_id)
    }
}

impl PrivacySubsystem for DescriptionPrivacy<'_> {
    fn name(&self) -> &'static str {
        "descriptions"
    }

    fn fence(&mut self, generation: PrivacyGeneration) -> Result<Fenced, Unavailable> {
        // The fence goes up before anything is counted, so nothing is admitted between the count
        // and the stop. The running job is then cancelled through the token its dispatcher left
        // behind, which is the only way to reach work that is already inside the runtime.
        self.fence.raise(self.session_id, generation);
        let cancelled_running = self.running.cancel(&self.session_id);
        Ok(Fenced {
            queues: 1,
            items: u64::from(self.scheduler.has_queued(&self.session_id))
                + u64::from(cancelled_running),
        })
    }

    fn cancel_undispatched(
        &mut self,
        _generation: PrivacyGeneration,
    ) -> Result<Cancelled, Unavailable> {
        Ok(Cancelled {
            undispatched: u64::from(self.scheduler.cancel(&self.session_id)),
            in_flight: self.in_flight.read(&self.session_id)?,
        })
    }

    fn remove_retained(&mut self, _generation: PrivacyGeneration) -> Result<Removed, Unavailable> {
        // The retained context goes first. It is not in a store, it is in this host's memory, and
        // leaving it would let a change captured while private reach a job after privacy ended.
        if let Some(tracker) = self.tracker.as_deref_mut() {
            tracker.forget();
        }
        // The retained semantic events go with it. They are the other half of what this host had
        // captured for the session, and one left behind would reach the next job after the fence
        // came down.
        if let Some(events) = self.events.as_deref_mut() {
            events.clear();
        }
        match self.store.remove_generated_for(&self.session_id) {
            Ok(removed) => {
                self.debt.settle(&self.session_id);
                Ok(Removed {
                    bytes: removed.bytes,
                    records: removed.records,
                })
            }
            Err(error) => {
                // Nothing is claimed. A removal this host could not make is a removal it does not
                // report, and the debt keeps the cleanup unavailable however many times privacy
                // mode asks again.
                let reason = error.to_string();
                self.debt.owe(self.session_id, reason.clone());
                Err(Unavailable::new(reason))
            }
        }
    }

    fn outstanding(&self) -> Result<u64, Unavailable> {
        if let Some(owed) = self.debt.read(&self.session_id)? {
            return Err(Unavailable::new(owed));
        }
        self.in_flight.read(&self.session_id)
    }

    fn kept(&self) -> Vec<KeptExplicitly> {
        vec![KeptExplicitly {
            what: "a session name a person pinned",
            why: "a name somebody chose is theirs, and section 24 keeps it until they clear it; it \
                  is excluded from sync while privacy mode is on",
        }]
    }

    fn exported(&self) -> Result<Vec<Exported>, Unavailable> {
        // A description is produced on this host, stored on this host and shown on this host. It is
        // never uploaded, so there is no copy elsewhere to offer a separate deletion of.
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{ContextBinding, ContextRevision, CursorInterval};
    use crate::metadata::{ActivityText, Title};
    use crate::output::{GeneratedDescription, ProducedUnder};
    use crate::profile::ProfileRevision;
    use kr_protocol::ids::{SessionEpoch, SessionId};
    use kr_protocol::scalars::Uuid;

    fn sample_session(seed: u8) -> SessionId {
        SessionId::new(Uuid::from_bytes([seed; 16]))
    }

    fn sample_description(generation: PrivacyGeneration) -> GeneratedDescription {
        GeneratedDescription {
            title: Title::new("sample title").expect("title"),
            activity: ActivityText::new("sample activity").expect("activity"),
            cursor: CursorInterval { from: 0, to: 10 },
            revision: ContextRevision::new(1),
            produced_under: ProducedUnder {
                session_epoch: SessionEpoch::new(1),
                binding: ContextBinding::new("desktop-1/terminal/epoch-1"),
                context_revision: ContextRevision::new(1),
                cursor: CursorInterval { from: 0, to: 10 },
                profile_id: "test-profile".to_owned(),
                profile_revision: ProfileRevision::new(1),
                generation,
            },
        }
    }

    #[test]
    fn publish_under_lock_allows_and_publishes_when_unfenced_and_within_deadline() {
        let store = DescriptionStore::in_memory().expect("store");
        let fence = DescriptionFence::new();
        let session = sample_session(1);
        let desc = sample_description(PrivacyGeneration::INITIAL);
        let cancellation = Cancellation::new();
        let elapsed_ms = 0;

        let gate = fence
            .publish_under_lock(
                &store,
                &session,
                &desc,
                1000,
                PrivacyGeneration::INITIAL,
                PrivacyGeneration::INITIAL,
                &cancellation,
                elapsed_ms,
                5000,
            )
            .expect("gate");

        assert_eq!(gate, PublishGate::Allowed);
        let record = store.generated(&session).expect("record").expect("some");
        assert_eq!(record.title.as_str(), "sample title");
        assert_eq!(record.activity.as_str(), "sample activity");
    }

    #[test]
    fn publish_under_lock_reports_a_pinned_name_and_leaves_the_job_cancellable() {
        let store = DescriptionStore::in_memory().expect("store");
        let fence = DescriptionFence::new();
        let session = sample_session(1);
        store
            .pin(
                &session,
                &Title::new("Release prep").expect("title"),
                "local:501",
                900,
            )
            .expect("pin");
        let desc = sample_description(PrivacyGeneration::INITIAL);
        let cancellation = Cancellation::new();
        let elapsed_ms = 0;

        let gate = fence
            .publish_under_lock(
                &store,
                &session,
                &desc,
                1000,
                PrivacyGeneration::INITIAL,
                PrivacyGeneration::INITIAL,
                &cancellation,
                elapsed_ms,
                5000,
            )
            .expect("gate");

        assert_eq!(gate, PublishGate::NamePinned);
        assert!(store.generated(&session).expect("record").is_none());
        assert!(
            cancellation.cancel(),
            "nothing was published, so the job can still be cancelled"
        );
    }

    #[test]
    fn publish_under_lock_refuses_when_cancelled() {
        let store = DescriptionStore::in_memory().expect("store");
        let fence = DescriptionFence::new();
        let session = sample_session(1);
        let desc = sample_description(PrivacyGeneration::INITIAL);
        let cancellation = Cancellation::new();
        cancellation.cancel();
        let elapsed_ms = 0;

        let gate = fence
            .publish_under_lock(
                &store,
                &session,
                &desc,
                1000,
                PrivacyGeneration::INITIAL,
                PrivacyGeneration::INITIAL,
                &cancellation,
                elapsed_ms,
                5000,
            )
            .expect("gate");

        assert_eq!(gate, PublishGate::Cancelled);
        assert!(store.generated(&session).expect("record").is_none());
    }

    #[test]
    fn publish_under_lock_refuses_when_deadline_exceeded() {
        let store = DescriptionStore::in_memory().expect("store");
        let fence = DescriptionFence::new();
        let session = sample_session(1);
        let desc = sample_description(PrivacyGeneration::INITIAL);
        let cancellation = Cancellation::new();
        let elapsed_ms = 5001;

        let gate = fence
            .publish_under_lock(
                &store,
                &session,
                &desc,
                1000,
                PrivacyGeneration::INITIAL,
                PrivacyGeneration::INITIAL,
                &cancellation,
                elapsed_ms,
                5000,
            )
            .expect("gate");

        assert_eq!(gate, PublishGate::DeadlineExceeded);
        assert!(store.generated(&session).expect("record").is_none());
    }

    #[test]
    fn publish_under_lock_refuses_when_fenced_at_newer_generation() {
        let store = DescriptionStore::in_memory().expect("store");
        let fence = DescriptionFence::new();
        let session = sample_session(1);
        let desc = sample_description(PrivacyGeneration::INITIAL);
        let cancellation = Cancellation::new();
        let elapsed_ms = 0;
        fence.raise(session, PrivacyGeneration::new(2));

        let gate = fence
            .publish_under_lock(
                &store,
                &session,
                &desc,
                1000,
                PrivacyGeneration::INITIAL,
                PrivacyGeneration::INITIAL,
                &cancellation,
                elapsed_ms,
                5000,
            )
            .expect("gate");

        assert_eq!(
            gate,
            PublishGate::LateGeneration {
                expected: PrivacyGeneration::new(2),
                found: PrivacyGeneration::INITIAL,
            }
        );
        assert!(store.generated(&session).expect("record").is_none());
    }

    #[test]
    fn publish_under_lock_refuses_when_fallback_generation_mismatches() {
        let store = DescriptionStore::in_memory().expect("store");
        let fence = DescriptionFence::new();
        let session = sample_session(1);
        let desc = sample_description(PrivacyGeneration::INITIAL);
        let cancellation = Cancellation::new();
        let elapsed_ms = 0;

        let gate = fence
            .publish_under_lock(
                &store,
                &session,
                &desc,
                1000,
                PrivacyGeneration::INITIAL,
                PrivacyGeneration::new(3),
                &cancellation,
                elapsed_ms,
                5000,
            )
            .expect("gate");

        assert_eq!(
            gate,
            PublishGate::LateGeneration {
                expected: PrivacyGeneration::new(3),
                found: PrivacyGeneration::INITIAL,
            }
        );
        assert!(store.generated(&session).expect("record").is_none());
    }

    #[test]
    fn publish_under_lock_refuses_when_fenced_at_same_generation() {
        let store = DescriptionStore::in_memory().expect("store");
        let fence = DescriptionFence::new();
        let session = sample_session(1);
        let desc = sample_description(PrivacyGeneration::INITIAL);
        let cancellation = Cancellation::new();
        let elapsed_ms = 0;
        fence.raise(session, PrivacyGeneration::INITIAL);

        let gate = fence
            .publish_under_lock(
                &store,
                &session,
                &desc,
                1000,
                PrivacyGeneration::INITIAL,
                PrivacyGeneration::INITIAL,
                &cancellation,
                elapsed_ms,
                5000,
            )
            .expect("gate");

        assert_eq!(gate, PublishGate::Fenced);
        assert!(store.generated(&session).expect("record").is_none());
    }

    #[test]
    fn publish_under_lock_guarantees_atomicity_under_concurrent_fence_contention() {
        let store = Arc::new(Mutex::new(DescriptionStore::in_memory().expect("store")));
        let fence = DescriptionFence::new();
        let session = sample_session(42);
        let desc = sample_description(PrivacyGeneration::INITIAL);

        for iteration in 0..50 {
            let store_clone = store.clone();
            let fence_clone = fence.clone();
            let session_clone = session;
            let desc_clone = desc.clone();
            let cancellation = Cancellation::new();
            let elapsed_ms = 0;

            let t_publish = std::thread::spawn(move || {
                let store_guard = store_clone.lock().unwrap();
                fence_clone.publish_under_lock(
                    &store_guard,
                    &session_clone,
                    &desc_clone,
                    1000 + iteration,
                    PrivacyGeneration::INITIAL,
                    PrivacyGeneration::INITIAL,
                    &cancellation,
                    elapsed_ms,
                    5000,
                )
            });

            let fence_clone2 = fence.clone();
            let t_fence = std::thread::spawn(move || {
                fence_clone2.raise(session, PrivacyGeneration::new(2));
            });

            let gate = t_publish.join().expect("publish thread").expect("gate");
            t_fence.join().expect("fence thread");

            // Both orders are accounted for rather than only the losing one: raising the fence and
            // publishing take the same lock, so the gate's answer says which went first and the
            // store must agree with it.
            let store_guard = store.lock().unwrap();
            let record = store_guard.generated(&session).expect("read");
            match gate {
                PublishGate::Allowed => assert!(
                    record.is_some(),
                    "publication that won the lock must leave its description in the store"
                ),
                PublishGate::Fenced | PublishGate::LateGeneration { .. } => assert!(
                    record.is_none(),
                    "a fence that won the lock must leave nothing in the store"
                ),
                other => panic!("neither thread can produce {other:?}"),
            }

            let _ = store_guard.remove_generated_for(&session);
            drop(store_guard);
            fence.lower(&session);
        }
    }

    #[test]
    fn publish_under_lock_guarantees_atomicity_under_concurrent_cancellation_contention() {
        let store = Arc::new(Mutex::new(DescriptionStore::in_memory().expect("store")));
        let fence = DescriptionFence::new();
        let session = sample_session(99);
        let mut earlier = sample_description(PrivacyGeneration::INITIAL);
        earlier.title = Title::new("an earlier title").expect("title");
        let desc = sample_description(PrivacyGeneration::INITIAL);

        for iteration in 0..50 {
            // Every iteration starts with a description an earlier, uncancelled job published, so a
            // cancelled publication is measured by what it leaves behind as well as by what it
            // refuses to write.
            store
                .lock()
                .unwrap()
                .publish(&session, &earlier, 500)
                .expect("the earlier description");

            let store_clone = store.clone();
            let fence_clone = fence.clone();
            let desc_clone = desc.clone();
            let cancellation = Cancellation::new();
            let cancellation_clone = cancellation.clone();
            let elapsed_ms = 0;

            let t_publish = std::thread::spawn(move || {
                let store_guard = store_clone.lock().unwrap();
                fence_clone.publish_under_lock(
                    &store_guard,
                    &session,
                    &desc_clone,
                    2000 + iteration,
                    PrivacyGeneration::INITIAL,
                    PrivacyGeneration::INITIAL,
                    &cancellation,
                    elapsed_ms,
                    5000,
                )
            });

            let t_cancel = std::thread::spawn(move || cancellation_clone.cancel());

            let gate = t_publish.join().expect("publish thread").expect("gate");
            let stopped_the_job = t_cancel.join().expect("cancel thread");

            // The two threads take the same token, so one of them is first and the outcome says
            // which. There is no order in which a cancellation both stops the job and finds the
            // description published, and none in which a cancelled job leaves anything behind.
            let store_guard = store.lock().unwrap();
            let record = store_guard.generated(&session).expect("read").expect("row");
            if stopped_the_job {
                assert_eq!(
                    gate,
                    PublishGate::Cancelled,
                    "a cancellation that stopped the job must refuse the publication"
                );
                assert_eq!(
                    record.title.as_str(),
                    "an earlier title",
                    "a cancelled job must leave the description an earlier job published"
                );
            } else {
                assert_eq!(
                    gate,
                    PublishGate::Allowed,
                    "a cancellation that was too late must leave the publication alone"
                );
                assert_eq!(
                    record.title.as_str(),
                    "sample title",
                    "a published description is not taken away by a late cancellation"
                );
                assert_eq!(record.produced_at_ms, 2000 + iteration);
            }

            let _ = store_guard.remove_generated_for(&session);
        }
    }

    #[test]
    fn a_cancelled_job_leaves_the_description_an_earlier_job_published() {
        let store = DescriptionStore::in_memory().expect("store");
        let fence = DescriptionFence::new();
        let session = sample_session(77);
        let mut earlier = sample_description(PrivacyGeneration::INITIAL);
        earlier.title = Title::new("an earlier title").expect("title");
        store
            .publish(&session, &earlier, 500)
            .expect("the earlier description");

        let desc = sample_description(PrivacyGeneration::INITIAL);
        let cancellation = Cancellation::new();
        assert!(cancellation.cancel());
        let elapsed_ms = 0;

        let gate = fence
            .publish_under_lock(
                &store,
                &session,
                &desc,
                3000,
                PrivacyGeneration::INITIAL,
                PrivacyGeneration::INITIAL,
                &cancellation,
                elapsed_ms,
                5000,
            )
            .expect("gate");

        assert_eq!(gate, PublishGate::Cancelled);
        let record = store.generated(&session).expect("read").expect("row");
        assert_eq!(record.title.as_str(), "an earlier title");
        assert_eq!(record.produced_at_ms, 500);
    }
}
