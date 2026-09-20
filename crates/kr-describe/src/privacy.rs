//! Privacy mode's four calls, over this crate's own stores.
//!
//! Section 24 names generated descriptions twice: *enabling privacy mode immediately fences
//! content-bearing outboxes/captures, cancels undispatched backup/sync/description work, removes
//! retained local output/semantic-history caches and generated descriptions, and uses metadata-only
//! titles*, and *user-pinned labels are retained locally unless explicitly cleared*.
//!
//! [`kr_worker::privacy::PrivacySubsystem`] is that contract, and this module implements it over
//! the two things this crate holds: the queue and the description store. Each call does the thing
//! rather than reporting it.
//!
//! | Call | What it does here |
//! | --- | --- |
//! | `fence` | Raises [`DescriptionFence`], which stops admission and dispatch at once |
//! | `cancel_undispatched` | Empties the queue, and counts what is already running as in flight |
//! | `remove_retained` | Deletes every generated description and keeps every pin |
//! | `outstanding` | The jobs still running, plus a removal that did not finish |
//! | `kept` | The pins, named, with why they stay |
//! | `exported` | Nothing. A description is never sent anywhere |
//!
//! # The late-result rule is not restated here
//!
//! [`kr_worker::privacy::PrivacyMode::accepts_result`] is the whole rule and it lives on the mode.
//! What this crate does is carry the generation on the job, from admission to publication, so there
//! is something exact to compare. [`crate::output::validate`] makes the comparison, and a job
//! admitted before the enabling is refused rather than shown.
//!
//! # Metadata-only titles
//!
//! While the fence is up, [`crate::service::DescriptionService::label`] does not read the generated
//! record at all, so the answer is a pin or a deterministic title even in the moment between the
//! fence and the removal. There is no window in which a generated title is shown under privacy
//! mode.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use kr_worker::privacy::{
    Cancelled, Exported, Fenced, KeptExplicitly, PrivacyGeneration, PrivacySubsystem, Removed,
};

use crate::queue::Scheduler;
use crate::store::DescriptionStore;

/// Whether description processing is stopped, and at which generation.
///
/// It is shared rather than owned because the thing that raises it - privacy mode - and the things
/// that obey it - admission, dispatch and the label path - are held by different owners. Raising it
/// is one store, and it is seen by everything at once, which is what *immediately* has to mean.
#[derive(Clone, Debug, Default)]
pub struct DescriptionFence {
    fenced: Arc<AtomicBool>,
    generation: Arc<AtomicU64>,
}

impl DescriptionFence {
    /// Builds a fence that is down.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns whether description processing is stopped.
    #[must_use]
    pub fn is_fenced(&self) -> bool {
        self.fenced.load(Ordering::Acquire)
    }

    /// Returns the generation the fence was raised at.
    #[must_use]
    pub fn generation(&self) -> PrivacyGeneration {
        PrivacyGeneration::new(self.generation.load(Ordering::Acquire))
    }

    /// Raises the fence at a generation.
    pub fn raise(&self, generation: PrivacyGeneration) {
        self.generation.store(generation.get(), Ordering::Release);
        self.fenced.store(true, Ordering::Release);
    }

    /// Lowers the fence, which is what disabling privacy mode does.
    ///
    /// Section 24: disabling *starts new retention from that point and cannot reconstruct omitted
    /// history*. Lowering the fence lets new descriptions be produced. It restores nothing.
    pub fn lower(&self) {
        self.fenced.store(false, Ordering::Release);
    }
}

/// How many description jobs have been dispatched and not yet reconciled.
///
/// A dispatched job is out of the queue and inside the runtime. Cancelling cannot take it back, so
/// privacy mode counts it as in flight and reconciliation is this number reaching nought.
#[derive(Clone, Debug, Default)]
pub struct InFlight(Arc<AtomicU64>);

impl InFlight {
    /// Builds a counter at nought.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records that a job has been dispatched.
    pub fn dispatched(&self) {
        self.0.fetch_add(1, Ordering::AcqRel);
    }

    /// Records that a job has finished, however it finished.
    pub fn reconciled(&self) {
        // Saturating rather than wrapping: a count that went below nought would report
        // reconciliation complete for work nobody had accounted for.
        let _ = self
            .0
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |held| {
                Some(held.saturating_sub(1))
            });
    }

    /// Returns how many jobs are in flight.
    #[must_use]
    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Acquire)
    }
}

/// Privacy mode's hook over this crate's queue and store.
#[derive(Debug)]
pub struct DescriptionPrivacy<'a> {
    fence: &'a DescriptionFence,
    scheduler: &'a mut Scheduler,
    store: &'a DescriptionStore,
    in_flight: &'a InFlight,
    pins_kept: u64,
    failure: Option<String>,
}

impl<'a> DescriptionPrivacy<'a> {
    /// Builds the hook.
    #[must_use]
    pub fn over(
        fence: &'a DescriptionFence,
        scheduler: &'a mut Scheduler,
        store: &'a DescriptionStore,
        in_flight: &'a InFlight,
    ) -> Self {
        Self {
            fence,
            scheduler,
            store,
            in_flight,
            pins_kept: 0,
            failure: None,
        }
    }

    /// Returns why the removal could not finish, when it could not.
    #[must_use]
    pub fn failure(&self) -> Option<&str> {
        self.failure.as_deref()
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
        // and the stop.
        self.fence.raise(generation);
        Fenced {
            queues: 1,
            items: self.scheduler.queued() as u64,
        }
    }

    fn cancel_undispatched(&mut self, _generation: PrivacyGeneration) -> Cancelled {
        Cancelled {
            undispatched: self.scheduler.cancel_all(),
            in_flight: self.in_flight.get(),
        }
    }

    fn remove_retained(&mut self, _generation: PrivacyGeneration) -> Removed {
        // Pins are counted before the removal so the figure reported as kept is of rows that are
        // still there afterwards rather than of rows that were there before.
        match self.store.pin_count() {
            Ok(pins) => self.pins_kept = pins,
            Err(error) => self.failure = Some(error.to_string()),
        }
        match self.store.remove_generated() {
            Ok(removed) => Removed {
                bytes: removed.bytes,
                records: removed.records,
            },
            Err(error) => {
                // Nothing is claimed. A removal this host could not make is a removal it does not
                // report, and it keeps the cleanup from reporting complete.
                self.failure = Some(error.to_string());
                Removed::default()
            }
        }
    }

    fn outstanding(&self) -> u64 {
        self.in_flight
            .get()
            .saturating_add(u64::from(self.failure.is_some()))
    }

    fn kept(&self) -> Vec<KeptExplicitly> {
        if self.pins_kept == 0 {
            return Vec::new();
        }
        vec![KeptExplicitly {
            what: "session names a person pinned",
            why: "a name somebody chose is theirs, and section 24 keeps it until they clear it; it \
                  is excluded from sync while privacy mode is on",
        }]
    }

    fn exported(&self) -> Vec<Exported> {
        // A description is produced on this host, stored on this host and shown on this host. It is
        // never uploaded, so there is no copy elsewhere to offer a separate deletion of, and saying
        // so is more useful than an empty list with no explanation.
        Vec::new()
    }
}
