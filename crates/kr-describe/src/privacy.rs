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
//! Privacy mode is a session's state in this product: `Session::enable_privacy` records a
//! generation for one session, and one private session sits beside another that is not. The model
//! is shared and the queue is shared, but what privacy mode reaches is not, so every type here is
//! keyed by [`SessionId`] and [`crate::service::DescriptionService::privacy`] hands out a hook for
//! one session. A hook that emptied the whole queue would be cancelling work for sessions nobody
//! asked about.
//!
//! | Call | What it does here |
//! | --- | --- |
//! | `fence` | Raises the fence for this session and cancels its job if one is running |
//! | `cancel_undispatched` | Drops this session's queued job, and counts a running one as in flight |
//! | `remove_retained` | Deletes this session's generated description and forgets its context and events |
//! | `outstanding` | Its running job, plus a removal that did not finish |
//! | `kept` | Its pin, named, with why it stays |
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
        job_clock: &crate::time::JobClock,
        dequeued_ms: u64,
        deadline_ms: u64,
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
        let elapsed = job_clock.now_ms().saturating_sub(dequeued_ms);
        if elapsed > deadline_ms {
            return Ok(PublishGate::DeadlineExceeded);
        }
        store.publish(session_id, description, wall_ms)?;
        Ok(PublishGate::Allowed)
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
}

/// The job the runtime is executing right now, and the token that cancels it.
///
/// A job runs inside one call, so the only way to stop it from outside is a token somebody else
/// holds. This is that handle: raising a session's fence cancels its running job through it, and
/// the runtime checks the token between tokens of output.
#[derive(Clone, Debug, Default)]
pub struct RunningJob {
    held: Arc<Mutex<Option<(SessionId, Cancellation)>>>,
}

impl RunningJob {
    /// Builds a handle with nothing running.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records that a session's job has started, and returns its cancellation token.
    #[must_use]
    pub fn started(&self, session_id: SessionId) -> Cancellation {
        let cancellation = Cancellation::new();
        if let Ok(mut held) = self.held.lock() {
            *held = Some((session_id, cancellation.clone()));
        }
        cancellation
    }

    /// Records that the running job has finished.
    pub fn finished(&self) {
        if let Ok(mut held) = self.held.lock() {
            *held = None;
        }
    }

    /// Returns whether this session's job is the one running.
    #[must_use]
    pub fn is_running(&self, session_id: &SessionId) -> bool {
        self.held.lock().is_ok_and(|held| {
            held.as_ref()
                .is_some_and(|(running, _)| running == session_id)
        })
    }

    /// Returns the cancellation token for the running job when it is this session's.
    #[must_use]
    pub fn cancellation(&self, session_id: &SessionId) -> Option<Cancellation> {
        let Ok(held) = self.held.lock() else {
            return None;
        };
        match held.as_ref() {
            Some((running, cancellation)) if running == session_id => Some(cancellation.clone()),
            _ => None,
        }
    }

    /// Cancels the running job when it is this session's, and says whether it did.
    pub fn cancel(&self, session_id: &SessionId) -> bool {
        let Ok(held) = self.held.lock() else {
            return false;
        };
        match held.as_ref() {
            Some((running, cancellation)) if running == session_id => {
                cancellation.cancel();
                true
            }
            _ => false,
        }
    }
}

/// Cleanup this host was asked to do and could not finish.
///
/// It belongs to the service rather than to the hook, because a hook is built for one call and
/// dropped. A debt that lived on the hook would disappear the moment privacy mode asked again, and
/// the next reconciliation would report complete over content that is still there.
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
    pins_kept: u64,
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
            pins_kept: 0,
        }
    }

    /// Returns why the removal could not finish, when it could not.
    #[must_use]
    pub fn failure(&self) -> Option<String> {
        self.debt.owed(&self.session_id)
    }

    /// Returns how many pins were kept, as the last removal counted them.
    #[must_use]
    pub const fn pins_kept(&self) -> u64 {
        self.pins_kept
    }
}

impl PrivacySubsystem for DescriptionPrivacy<'_> {
    fn name(&self) -> &'static str {
        "descriptions"
    }

    fn fence(&mut self, generation: PrivacyGeneration) -> Fenced {
        // The fence goes up before anything is counted, so nothing is admitted between the count
        // and the stop. The running job is then cancelled through the token its dispatcher left
        // behind, which is the only way to reach work that is already inside the runtime.
        self.fence.raise(self.session_id, generation);
        let cancelled_running = self.running.cancel(&self.session_id);
        Fenced {
            queues: 1,
            items: u64::from(self.scheduler.has_queued(&self.session_id))
                + u64::from(cancelled_running),
        }
    }

    fn cancel_undispatched(&mut self, _generation: PrivacyGeneration) -> Cancelled {
        Cancelled {
            undispatched: u64::from(self.scheduler.cancel(&self.session_id)),
            in_flight: self.in_flight.get(&self.session_id),
        }
    }

    fn remove_retained(&mut self, _generation: PrivacyGeneration) -> Removed {
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
        // Pins are counted before the removal so the figure reported as kept is of rows that are
        // still there afterwards rather than of rows that were there before.
        match self.store.pin_count_for(&self.session_id) {
            Ok(pins) => self.pins_kept = pins,
            Err(error) => self.debt.owe(self.session_id, error.to_string()),
        }
        match self.store.remove_generated_for(&self.session_id) {
            Ok(removed) => {
                self.debt.settle(&self.session_id);
                Removed {
                    bytes: removed.bytes,
                    records: removed.records,
                }
            }
            Err(error) => {
                // Nothing is claimed. A removal this host could not make is a removal it does not
                // report, and the debt keeps the cleanup from reporting complete however many
                // times privacy mode asks again.
                self.debt.owe(self.session_id, error.to_string());
                Removed::default()
            }
        }
    }

    fn outstanding(&self) -> u64 {
        self.in_flight
            .get(&self.session_id)
            .saturating_add(u64::from(self.debt.owed(&self.session_id).is_some()))
    }

    fn kept(&self) -> Vec<KeptExplicitly> {
        if self.pins_kept == 0 {
            return Vec::new();
        }
        vec![KeptExplicitly {
            what: "a session name a person pinned",
            why: "a name somebody chose is theirs, and section 24 keeps it until they clear it; it \
                  is excluded from sync while privacy mode is on",
        }]
    }

    fn exported(&self) -> Vec<Exported> {
        // A description is produced on this host, stored on this host and shown on this host. It is
        // never uploaded, so there is no copy elsewhere to offer a separate deletion of.
        Vec::new()
    }
}
