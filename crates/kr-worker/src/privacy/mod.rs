//! Privacy mode, and the generation every subsystem answers to.
//!
//! Section 24 asks for one thing from every part of the host at once, and the parts are not alike:
//! retained output is a spool, a description is a model call in flight, a backup is an outbox
//! entry, a preview is a decoded image. What they share is the shape of what privacy mode asks of
//! them, and that shape is [`PrivacySubsystem`]:
//!
//! 1. **Fence** what is content-bearing, immediately. Not "stop producing more": stop the queue
//!    that already holds content from reaching anything outside this host.
//! 2. **Cancel** the work that has been admitted and not dispatched. It has not left, so it can
//!    be taken back rather than followed.
//! 3. **Reject a late result.** Work that *had* left is still out there, and its answer will come
//!    back. An answer produced under the generation before this one is refused, because
//!    publishing it would be publishing content privacy mode had already disabled.
//! 4. **Reconcile** before completion is reported. In-flight cleanup is not finished because it
//!    was asked for; it is finished when every subsystem says it has nothing outstanding.
//!
//! The generation is what ties the four together. It is recorded when privacy mode is enabled, it
//! travels with every piece of work, and it is what makes "late" decidable: a result carries the
//! generation it was produced under, and this host compares rather than guesses.
//!
//! What privacy mode does **not** do is equally fixed. It does not erase what has already left
//! the host, and it does not pretend to: [`Exported`] is what a person is shown instead, with the
//! separately authorised deletion that is the only honest offer. It does not stop the durable
//! control system writing, because a host that wrote nothing could not stop a session or refuse a
//! replay; [`KeptExplicitly`] names what stays and why. And local deletion is logical cleanup
//! rather than a claim of physical erasure.

use kr_protocol::scalars::TimestampMs;

/// The generation privacy mode records.
///
/// Nought is a host that has never enabled privacy mode, and each enabling advances it. Disabling
/// does not: what a generation identifies is the boundary work was admitted on either side of,
/// and reusing a number would make a late result from before the boundary indistinguishable from
/// one produced after it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PrivacyGeneration(u64);

impl PrivacyGeneration {
    /// The generation of a host that has never enabled privacy mode.
    pub const INITIAL: Self = Self(0);

    /// Builds a generation from a recorded value.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the recorded value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Returns the generation after this one.
    #[must_use]
    pub const fn next(self) -> Self {
        Self(self.0.saturating_add(1))
    }
}

/// What privacy mode disables prospectively.
///
/// Prospectively is the whole of it: what was retained before the generation is removed by the
/// cleanup, and what these four would have produced after it is never produced.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Disabled {
    /// Session content-history retention.
    ContentHistoryRetention,
    /// Description inference.
    DescriptionInference,
    /// Sync production.
    Sync,
    /// Backup production.
    Backup,
}

impl Disabled {
    /// Every capability privacy mode disables, in the order section 24 states them.
    pub const ALL: &'static [Self] = &[
        Self::ContentHistoryRetention,
        Self::DescriptionInference,
        Self::Sync,
        Self::Backup,
    ];

    /// Returns the stable name this is reported under.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ContentHistoryRetention => "content_history_retention",
            Self::DescriptionInference => "description_inference",
            Self::Sync => "sync",
            Self::Backup => "backup",
        }
    }
}

/// Something privacy mode keeps, and says it keeps.
///
/// Section 24: *minimal local authority and receipt metadata and live pending resources remain
/// explicitly identified; do not falsely promise that a functioning durable control system writes
/// no state at all.* Each of these is named rather than quietly retained.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeptExplicitly {
    /// What is kept.
    pub what: &'static str,
    /// Why a host that stopped keeping it could not do its job.
    pub why: &'static str,
}

/// Something that had already left this host before privacy mode was enabled.
///
/// It is not erased and this host does not claim it could be. What it offers instead is the truth
/// and a separate action: the copy is shown, and deleting it is authorised on its own.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Exported {
    /// What kind of copy it is.
    pub kind: String,
    /// The opaque reference a person is shown, never a client path.
    pub reference: String,
    /// When it left.
    pub left_at_ms: TimestampMs,
    /// Whether deleting it is an action this host can offer.
    pub deletable: bool,
}

/// What one subsystem's fence did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Fenced {
    /// How many content-bearing queues or captures were stopped.
    pub queues: u64,
    /// How many items those queues were holding.
    pub items: u64,
}

/// What one subsystem's cancellation did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Cancelled {
    /// How many admitted, undispatched pieces of work were taken back.
    pub undispatched: u64,
    /// How many pieces of work had already been dispatched and cannot be taken back.
    ///
    /// These are what the late-result rule exists for. They are counted rather than hidden,
    /// because reconciliation is not complete while any of them is outstanding.
    pub in_flight: u64,
}

/// What one subsystem's local cleanup removed.
///
/// Local deletion is logical cleanup. This host removes its own records and does not claim the
/// bytes are unrecoverable from the device they were on.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Removed {
    /// Bytes of retained content this host stopped holding.
    pub bytes: u64,
    /// Records this host stopped holding.
    pub records: u64,
}

/// What every subsystem privacy mode reaches has to implement.
///
/// One trait rather than four hooks, because the four steps are one contract: a subsystem that
/// fenced and did not reconcile would let privacy mode report complete while its own work was
/// still in flight, and one that cancelled without rejecting a late result would publish the
/// answer to work it had cancelled.
pub trait PrivacySubsystem: std::fmt::Debug + Send {
    /// The subsystem's stable name, which is what a report names.
    fn name(&self) -> &'static str;

    /// Stops every content-bearing queue and capture, at once.
    fn fence(&mut self, generation: PrivacyGeneration) -> Fenced;

    /// Takes back the work that was admitted and never dispatched.
    fn cancel_undispatched(&mut self, generation: PrivacyGeneration) -> Cancelled;

    /// Removes the retained local content this subsystem holds.
    fn remove_retained(&mut self, generation: PrivacyGeneration) -> Removed;

    /// Returns how much of this subsystem's in-flight work is still being cleaned up.
    ///
    /// Reconciliation is this answer reaching nought. A subsystem that returned nought while work
    /// was outstanding would make privacy mode report complete before it was.
    fn outstanding(&self) -> u64;

    /// Returns what this subsystem keeps, explicitly, whatever privacy mode is doing.
    fn kept(&self) -> Vec<KeptExplicitly> {
        Vec::new()
    }

    /// Returns what has already left this host, which privacy mode does not erase.
    fn exported(&self) -> Vec<Exported> {
        Vec::new()
    }

    /// Returns whether a result produced under `produced_under` may still be published.
    ///
    /// The default is the rule itself, and a subsystem should not need to override it: a result
    /// from before the current generation is refused. It is on the trait rather than beside it so
    /// that every subsystem answers the same question the same way.
    fn accepts_result(
        &self,
        produced_under: PrivacyGeneration,
        current: PrivacyGeneration,
    ) -> bool {
        produced_under >= current
    }
}

/// What enabling privacy mode did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Enabling {
    /// The generation this enabling recorded.
    pub generation: PrivacyGeneration,
    /// When it was recorded.
    pub at_ms: TimestampMs,
    /// What was disabled prospectively.
    pub disabled: Vec<Disabled>,
    /// What each subsystem's fence did, by name.
    pub fenced: Vec<(&'static str, Fenced)>,
    /// What each subsystem's cancellation did, by name.
    pub cancelled: Vec<(&'static str, Cancelled)>,
    /// What each subsystem's local cleanup removed, by name.
    pub removed: Vec<(&'static str, Removed)>,
    /// What is kept, explicitly.
    pub kept: Vec<KeptExplicitly>,
    /// What had already left this host, which is shown rather than erased.
    pub exported: Vec<Exported>,
}

impl Enabling {
    /// Returns how much work was in flight when privacy mode was enabled.
    #[must_use]
    pub fn in_flight(&self) -> u64 {
        self.cancelled
            .iter()
            .map(|(_, cancelled)| cancelled.in_flight)
            .sum()
    }
}

/// Whether privacy mode's cleanup has finished.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Completion {
    /// Every subsystem has reconciled. This is the only state privacy mode reports as complete.
    Complete,
    /// Cleanup is still reconciling, and these subsystems are why.
    Reconciling {
        /// Each subsystem with work outstanding, and how much.
        outstanding: Vec<(&'static str, u64)>,
    },
}

impl Completion {
    /// Returns true when cleanup has finished.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        matches!(self, Self::Complete)
    }
}

/// Privacy mode for one session.
#[derive(Debug)]
pub struct PrivacyMode {
    generation: PrivacyGeneration,
    enabled: bool,
    enabled_at_ms: Option<TimestampMs>,
    subsystems: Vec<Box<dyn PrivacySubsystem>>,
}

impl PrivacyMode {
    /// Builds privacy mode over the subsystems it reaches.
    #[must_use]
    pub fn new(subsystems: Vec<Box<dyn PrivacySubsystem>>) -> Self {
        Self {
            generation: PrivacyGeneration::INITIAL,
            enabled: false,
            enabled_at_ms: None,
            subsystems,
        }
    }

    /// Builds privacy mode from a generation a restart read back.
    #[must_use]
    pub fn restored(
        generation: PrivacyGeneration,
        enabled: bool,
        subsystems: Vec<Box<dyn PrivacySubsystem>>,
    ) -> Self {
        Self {
            generation,
            enabled,
            enabled_at_ms: None,
            subsystems,
        }
    }

    /// Returns the generation now in force.
    #[must_use]
    pub const fn generation(&self) -> PrivacyGeneration {
        self.generation
    }

    /// Returns whether privacy mode is on.
    #[must_use]
    pub const fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Returns whether a capability is disabled right now.
    #[must_use]
    pub const fn disables(&self, _capability: Disabled) -> bool {
        // All four, together: section 24 names them as one set, and a host that disabled three of
        // them would be a host whose privacy mode meant something different from what it said.
        self.enabled
    }

    /// Enables privacy mode.
    ///
    /// The order is the contract and it is the order section 24 states: record the generation,
    /// fence what is content-bearing *immediately*, cancel what has not been dispatched, then
    /// remove the retained local content. Fencing first is what stops the queue emptying itself
    /// while the cancellation walks it.
    ///
    /// It does not report completion. In-flight work is reconciled by [`Self::reconcile`], and
    /// until that says so this is an enabling rather than a finished cleanup.
    pub fn enable(&mut self, now_ms: TimestampMs) -> Enabling {
        self.generation = self.generation.next();
        self.enabled = true;
        self.enabled_at_ms = Some(now_ms);
        let generation = self.generation;

        let mut fenced = Vec::new();
        for subsystem in &mut self.subsystems {
            fenced.push((subsystem.name(), subsystem.fence(generation)));
        }
        let mut cancelled = Vec::new();
        for subsystem in &mut self.subsystems {
            cancelled.push((subsystem.name(), subsystem.cancel_undispatched(generation)));
        }
        let mut removed = Vec::new();
        for subsystem in &mut self.subsystems {
            removed.push((subsystem.name(), subsystem.remove_retained(generation)));
        }
        let kept = self
            .subsystems
            .iter()
            .flat_map(|subsystem| subsystem.kept())
            .collect();
        let exported = self
            .subsystems
            .iter()
            .flat_map(|subsystem| subsystem.exported())
            .collect();
        Enabling {
            generation,
            at_ms: now_ms,
            disabled: Disabled::ALL.to_vec(),
            fenced,
            cancelled,
            removed,
            kept,
            exported,
        }
    }

    /// Asks every subsystem whether its in-flight cleanup has finished.
    #[must_use]
    pub fn reconcile(&self) -> Completion {
        let outstanding: Vec<(&'static str, u64)> = self
            .subsystems
            .iter()
            .map(|subsystem| (subsystem.name(), subsystem.outstanding()))
            .filter(|(_, outstanding)| *outstanding > 0)
            .collect();
        if outstanding.is_empty() {
            Completion::Complete
        } else {
            Completion::Reconciling { outstanding }
        }
    }

    /// Returns whether a result produced under an earlier generation may be published.
    ///
    /// Asked of the subsystem that produced it, so a subsystem with a reason of its own is the
    /// one that answers. None has such a reason today, and the trait's own rule is what they all
    /// use.
    #[must_use]
    pub fn accepts_result(&self, subsystem: &str, produced_under: PrivacyGeneration) -> bool {
        self.subsystems
            .iter()
            .find(|candidate| candidate.name() == subsystem)
            .is_none_or(|candidate| candidate.accepts_result(produced_under, self.generation))
    }

    /// Returns what this host keeps while privacy mode is on, explicitly.
    #[must_use]
    pub fn kept(&self) -> Vec<KeptExplicitly> {
        self.subsystems
            .iter()
            .flat_map(|subsystem| subsystem.kept())
            .collect()
    }

    /// Returns what had already left this host, which privacy mode does not erase.
    #[must_use]
    pub fn exported(&self) -> Vec<Exported> {
        self.subsystems
            .iter()
            .flat_map(|subsystem| subsystem.exported())
            .collect()
    }

    /// Turns privacy mode off.
    ///
    /// Retention starts again from this moment. It does not reconstruct what was omitted while
    /// privacy mode was on, and nothing here pretends it could: the generation stays where it is,
    /// so a late result from the private interval is still refused.
    pub fn disable(&mut self, now_ms: TimestampMs) -> Resumed {
        self.enabled = false;
        Resumed {
            generation: self.generation,
            retention_resumes_at_ms: now_ms,
        }
    }
}

/// What turning privacy mode off did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Resumed {
    /// The generation still in force, which a late result is still refused against.
    pub generation: PrivacyGeneration,
    /// The instant retention starts again from. Nothing before it is reconstructed.
    pub retention_resumes_at_ms: TimestampMs,
}

pub mod subsystems;

pub use crate::privacy::subsystems::{
    BackupOutbox, DescriptionInference, ReceiptMetadata, RetainedHistory, SyncOutbox,
    TransferPreviews,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy::subsystems::Recording;

    fn mode() -> PrivacyMode {
        PrivacyMode::new(vec![
            Box::new(Recording::new("first")),
            Box::new(Recording::new("second")),
        ])
    }

    #[test]
    fn enabling_records_a_generation_and_advances_it_each_time() {
        let mut mode = mode();
        assert_eq!(mode.generation(), PrivacyGeneration::INITIAL);
        let first = mode.enable(TimestampMs::new(1_000));
        assert_eq!(first.generation, PrivacyGeneration::new(1));
        let second = mode.enable(TimestampMs::new(2_000));
        assert_eq!(second.generation, PrivacyGeneration::new(2));
        assert!(mode.is_enabled());
    }

    #[test]
    fn every_subsystem_is_fenced_before_any_is_cancelled() {
        let mut mode = mode();
        let enabling = mode.enable(TimestampMs::new(1_000));
        // Both fences ran, and both ran before either cancellation: the recording subsystem
        // refuses to cancel anything it has not fenced first, so a cancellation that had run
        // early would have been counted as such.
        assert_eq!(enabling.fenced.len(), 2);
        assert!(enabling.fenced.iter().all(|(_, fenced)| fenced.queues > 0));
        assert!(
            enabling
                .cancelled
                .iter()
                .all(|(_, cancelled)| cancelled.undispatched > 0)
        );
    }

    #[test]
    fn all_four_capabilities_are_disabled_together() {
        let mut mode = mode();
        for capability in Disabled::ALL {
            assert!(!mode.disables(*capability));
        }
        let enabling = mode.enable(TimestampMs::new(1_000));
        assert_eq!(enabling.disabled, Disabled::ALL.to_vec());
        for capability in Disabled::ALL {
            assert!(mode.disables(*capability));
        }
    }

    #[test]
    fn completion_is_not_reported_while_any_subsystem_is_still_reconciling() {
        let mut mode = PrivacyMode::new(vec![
            Box::new(Recording::new("quiet")),
            Box::new(Recording::with_in_flight("busy", 3)),
        ]);
        mode.enable(TimestampMs::new(1_000));
        match mode.reconcile() {
            Completion::Reconciling { outstanding } => {
                assert_eq!(outstanding, vec![("busy", 3)]);
            }
            Completion::Complete => panic!("cleanup had not finished"),
        }
    }

    #[test]
    fn a_result_from_before_the_generation_is_refused_and_one_from_after_it_is_not() {
        let mut mode = mode();
        mode.enable(TimestampMs::new(1_000));
        assert!(!mode.accepts_result("first", PrivacyGeneration::INITIAL));
        assert!(mode.accepts_result("first", PrivacyGeneration::new(1)));
        // A second enabling refuses what the first admitted.
        mode.enable(TimestampMs::new(2_000));
        assert!(!mode.accepts_result("first", PrivacyGeneration::new(1)));
    }

    #[test]
    fn disabling_starts_retention_again_and_reconstructs_nothing() {
        let mut mode = mode();
        mode.enable(TimestampMs::new(1_000));
        let resumed = mode.disable(TimestampMs::new(5_000));
        assert!(!mode.is_enabled());
        assert_eq!(resumed.retention_resumes_at_ms.get(), 5_000);
        assert_eq!(resumed.generation, PrivacyGeneration::new(1));
        // The generation does not go back, so a late result from the private interval is still
        // refused after privacy mode is turned off.
        assert!(!mode.accepts_result("first", PrivacyGeneration::INITIAL));
    }
}
