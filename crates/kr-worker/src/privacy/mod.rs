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
//! generation it was produced under, and this host compares rather than guesses. One generation is
//! in force for a whole environment: the environment's record advances it, and each session applies
//! the one it is given, so every part of the host draws its boundary in the same place.
//!
//! Every step answers whether it was taken. A store that refused a step, or cannot say what is
//! still outstanding, answers [`Unavailable`] with its own reason, and reconciliation reports that
//! as [`Completion::Unavailable`]: not complete, and not merely waiting either. "This host cannot
//! say what it owes" is never read as "this host owes nothing".
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
/// Nought is a host that has never enabled privacy mode, and each change of state advances it,
/// turning it off as much as turning it on: what a generation identifies is the boundary work was
/// admitted on either side of, and reusing a number would make a late result from before the
/// boundary indistinguishable from one produced after it.
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
    /// Whether this host holds a reference it can ask for the copy's removal through.
    ///
    /// It says this host has a way to ask, not that asking will succeed and not that no other
    /// copy exists. A copy somebody else holds is not recallable and is not claimed to be.
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

/// Why a subsystem could not take a step, or could not say where its cleanup stands.
///
/// It carries the reason the subsystem's own store gave, because a person told that privacy mode's
/// cleanup is unfinished needs to know what is in the way. A subsystem that cannot answer is not a
/// subsystem with nothing outstanding, and privacy mode never reads the first as the second.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{reason}")]
pub struct Unavailable {
    reason: String,
}

impl Unavailable {
    /// Builds one from the reason a store gave.
    #[must_use]
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }

    /// Returns the reason.
    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

/// One of the three steps privacy mode takes on every subsystem, in the order it takes them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Step {
    /// [`PrivacySubsystem::fence`].
    Fence,
    /// [`PrivacySubsystem::cancel_undispatched`].
    Cancel,
    /// [`PrivacySubsystem::remove_retained`].
    Remove,
}

impl Step {
    /// Returns the stable name this step is reported under.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fence => "fence",
            Self::Cancel => "cancel",
            Self::Remove => "remove",
        }
    }
}

/// A subsystem privacy mode could not take through all three steps.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Unfinished {
    /// The subsystem's name.
    pub subsystem: &'static str,
    /// The step it could not take. The steps after it were not taken either.
    pub step: Step,
    /// Why, as the subsystem's store said.
    pub unavailable: Unavailable,
}

/// What every subsystem privacy mode reaches has to implement.
///
/// One trait rather than four hooks, because the four steps are one contract: a subsystem that
/// fenced and did not reconcile would let privacy mode report complete while its own work was
/// still in flight, and one that cancelled without rejecting a late result would publish the
/// answer to work it had cancelled.
///
/// Every step is idempotent at one generation. Taken again after it succeeded it changes nothing;
/// taken again after it failed it is taken as though for the first time. That is what lets a
/// caller that could not finish retry by taking the subsystem through all three steps again, and
/// it is why a subsystem keeps no memory of its own failures: the caller that saw one keeps it,
/// and clears it only when that step succeeds.
pub trait PrivacySubsystem: std::fmt::Debug {
    /// The subsystem's stable name, which is what a report names.
    fn name(&self) -> &'static str;

    /// Stops every content-bearing queue and capture, at once.
    ///
    /// # Errors
    ///
    /// Returns [`Unavailable`], with the store's reason, when the fence could not be raised.
    fn fence(&mut self, generation: PrivacyGeneration) -> Result<Fenced, Unavailable>;

    /// Takes back the work that was admitted and never dispatched.
    ///
    /// # Errors
    ///
    /// Returns [`Unavailable`], with the store's reason, when the work could not be taken back.
    fn cancel_undispatched(
        &mut self,
        generation: PrivacyGeneration,
    ) -> Result<Cancelled, Unavailable>;

    /// Removes the retained local content this subsystem holds.
    ///
    /// # Errors
    ///
    /// Returns [`Unavailable`], with the store's reason, when any of that content is still there.
    fn remove_retained(&mut self, generation: PrivacyGeneration) -> Result<Removed, Unavailable>;

    /// Returns how much of this subsystem's in-flight work is still being cleaned up.
    ///
    /// Reconciliation is this answer reaching nought. A subsystem that returned nought while work
    /// was outstanding would make privacy mode report complete before it was.
    ///
    /// # Errors
    ///
    /// Returns [`Unavailable`], with the store's reason, when the subsystem cannot say.
    fn outstanding(&self) -> Result<u64, Unavailable>;

    /// Returns what this subsystem keeps, explicitly, whatever privacy mode is doing.
    fn kept(&self) -> Vec<KeptExplicitly> {
        Vec::new()
    }

    /// Returns what has already left this host, which privacy mode does not erase.
    ///
    /// # Errors
    ///
    /// Returns [`Unavailable`], with the store's reason, when the subsystem cannot list it. An
    /// empty list is a statement that nothing has left, so a store that cannot be read never
    /// answers with one.
    fn exported(&self) -> Result<Vec<Exported>, Unavailable> {
        Ok(Vec::new())
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
    /// Each subsystem that could not be taken through all three steps, and the step it stopped at.
    pub unfinished: Vec<Unfinished>,
    /// What is kept, explicitly.
    pub kept: Vec<KeptExplicitly>,
    /// What had already left this host, which is shown rather than erased.
    pub exported: Vec<Exported>,
    /// Each subsystem that could not list what had already left, and why.
    pub unlisted: Vec<(&'static str, Unavailable)>,
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

    /// Returns true when every subsystem was taken through all three steps.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.unfinished.is_empty()
    }

    /// Returns why one subsystem could not be taken through all three steps, when it could not.
    #[must_use]
    pub fn unfinished(&self, subsystem: &str) -> Option<&Unfinished> {
        self.unfinished
            .iter()
            .find(|unfinished| unfinished.subsystem == subsystem)
    }
}

/// Each subsystem with work outstanding, and how much.
pub type Outstanding = Vec<(&'static str, u64)>;

/// Each subsystem that could not answer, with its store's reason.
pub type Unanswered = Vec<(&'static str, Unavailable)>;

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
    /// Something is in the way: a subsystem could not take a step, or cannot say where its cleanup
    /// stands. Cleanup is not complete, and it is not merely waiting for work to settle.
    Unavailable {
        /// Each subsystem that could not answer, with its store's reason.
        unavailable: Vec<(&'static str, Unavailable)>,
        /// Each subsystem with work outstanding, and how much.
        outstanding: Vec<(&'static str, u64)>,
    },
}

impl Completion {
    /// Builds the answer from what is outstanding and what could not answer.
    #[must_use]
    pub fn from_parts(outstanding: Outstanding, unavailable: Unanswered) -> Self {
        if !unavailable.is_empty() {
            Self::Unavailable {
                unavailable,
                outstanding,
            }
        } else if !outstanding.is_empty() {
            Self::Reconciling { outstanding }
        } else {
            Self::Complete
        }
    }

    /// Returns what is outstanding and what could not answer, which is everything this says.
    #[must_use]
    pub fn into_parts(self) -> (Outstanding, Unanswered) {
        match self {
            Self::Complete => (Vec::new(), Vec::new()),
            Self::Reconciling { outstanding } => (outstanding, Vec::new()),
            Self::Unavailable {
                unavailable,
                outstanding,
            } => (outstanding, unavailable),
        }
    }

    /// Returns true when cleanup has finished.
    #[must_use]
    pub const fn is_complete(&self) -> bool {
        matches!(self, Self::Complete)
    }
}

/// What privacy mode stops, as it travels.
impl From<Disabled> for kr_protocol::privacy::PrivacyDisabled {
    fn from(disabled: Disabled) -> Self {
        match disabled {
            Disabled::ContentHistoryRetention => Self::ContentHistoryRetention,
            Disabled::DescriptionInference => Self::DescriptionInference,
            Disabled::Sync => Self::Sync,
            Disabled::Backup => Self::Backup,
        }
    }
}

/// What is kept, as it travels.
impl From<&KeptExplicitly> for kr_protocol::privacy::PrivacyKept {
    fn from(kept: &KeptExplicitly) -> Self {
        Self {
            what: kept.what.to_owned(),
            why: kept.why.to_owned(),
        }
    }
}

/// A copy that had already left, as it travels.
impl From<&Exported> for kr_protocol::privacy::PrivacyExported {
    fn from(exported: &Exported) -> Self {
        Self {
            kind: exported.kind.clone(),
            reference: exported.reference.clone(),
            left_at_ms: exported.left_at_ms,
            deletable: exported.deletable,
        }
    }
}

/// The completion as it travels: each subsystem by its stable name, each reason as its store gave
/// it.
impl From<&Completion> for kr_protocol::privacy::PrivacyCompletion {
    fn from(completion: &Completion) -> Self {
        let outstanding = |outstanding: &Outstanding| {
            outstanding
                .iter()
                .map(
                    |(subsystem, count)| kr_protocol::privacy::PrivacyOutstanding {
                        subsystem: (*subsystem).to_owned(),
                        count: kr_protocol::scalars::U64::new(*count),
                    },
                )
                .collect()
        };
        match completion {
            Completion::Complete => Self::Complete,
            Completion::Reconciling { outstanding: owed } => Self::Reconciling {
                outstanding: outstanding(owed),
            },
            Completion::Unavailable {
                unavailable,
                outstanding: owed,
            } => Self::Unavailable {
                unavailable: unavailable
                    .iter()
                    .map(
                        |(subsystem, unavailable)| kr_protocol::privacy::PrivacyUnavailable {
                            subsystem: (*subsystem).to_owned(),
                            reason: unavailable.reason().to_owned(),
                        },
                    )
                    .collect(),
                outstanding: outstanding(owed),
            },
        }
    }
}

/// Where a change another owner recorded stands against the generation in force.
///
/// The environment's record is what advances the generation, and a session applies the one it is
/// given. So a session asks this first: a newer generation is a change to make, the one in force
/// in the state already in force is the same change again, and anything else would move the
/// boundary backwards or give one generation two meanings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Standing {
    /// A newer generation: the change it names is made.
    Newer,
    /// The generation in force, in the state in force: nothing changes, and cleanup is retried.
    Current,
    /// An older generation, or the one in force in the other state: refused.
    Refused,
}

/// Privacy mode's durable state: the generation, and whether privacy mode is on.
///
/// The environment's record advances it with [`Self::open_generation`] and [`Self::disable`]; a
/// session applies the generation it is given with [`Self::enter`] and [`Self::leave`]. It does not
/// own the subsystems, and that is deliberate. A subsystem worth having is an adapter over a live
/// store - the session's retained output, its journal - which its owner already holds, and one
/// that reports its own cleanup has to stay reachable after the enabling that started it. So the
/// caller passes them in, drives them here, and keeps them.
#[derive(Clone, Copy, Debug, Default)]
pub struct PrivacyMode {
    generation: PrivacyGeneration,
    enabled: bool,
    enabled_at_ms: Option<TimestampMs>,
}

impl PrivacyMode {
    /// Builds privacy mode for a host that has never enabled it.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            generation: PrivacyGeneration::INITIAL,
            enabled: false,
            enabled_at_ms: None,
        }
    }

    /// Builds privacy mode from a generation a restart read back.
    #[must_use]
    pub const fn restored(generation: PrivacyGeneration, enabled: bool) -> Self {
        Self {
            generation,
            enabled,
            enabled_at_ms: None,
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

    /// Returns when privacy mode was enabled in this process, when it was.
    #[must_use]
    pub const fn enabled_at_ms(&self) -> Option<TimestampMs> {
        self.enabled_at_ms
    }

    /// Returns whether a capability is disabled right now.
    #[must_use]
    pub const fn disables(&self, _capability: Disabled) -> bool {
        // All four, together: section 24 names them as one set, and a host that disabled three of
        // them would be a host whose privacy mode meant something different from what it said.
        self.enabled
    }

    /// Advances the generation and records that privacy mode is on.
    ///
    /// The caller writes this down durably *before* it drives any subsystem. A generation that
    /// was applied and not recorded would be a boundary a restart could not see, and a late
    /// result from before it would then be published.
    pub const fn open_generation(&mut self, now_ms: TimestampMs) -> PrivacyGeneration {
        self.generation = self.generation.next();
        self.enabled = true;
        self.enabled_at_ms = Some(now_ms);
        self.generation
    }

    /// Returns where a generation another owner recorded stands against the one in force.
    #[must_use]
    pub const fn standing(&self, generation: PrivacyGeneration, enabled: bool) -> Standing {
        if generation.get() > self.generation.get() {
            Standing::Newer
        } else if generation.get() == self.generation.get() && enabled == self.enabled {
            Standing::Current
        } else {
            Standing::Refused
        }
    }

    /// Turns privacy mode on at a generation another owner recorded, when that is newer.
    ///
    /// It returns where the generation stood and changes nothing unless it was newer. As with
    /// [`Self::open_generation`], the caller writes the change down before it drives anything.
    pub const fn enter(&mut self, generation: PrivacyGeneration, now_ms: TimestampMs) -> Standing {
        let standing = self.standing(generation, true);
        if matches!(standing, Standing::Newer) {
            self.generation = generation;
            self.enabled = true;
            self.enabled_at_ms = Some(now_ms);
        }
        standing
    }

    /// Turns privacy mode off from a generation another owner recorded, when that is newer.
    ///
    /// It returns where the generation stood, and what resumed when it was newer. Like
    /// [`Self::disable`], it reconstructs nothing that was omitted while privacy mode was on.
    pub const fn leave(
        &mut self,
        generation: PrivacyGeneration,
        now_ms: TimestampMs,
    ) -> (Standing, Option<Resumed>) {
        let standing = self.standing(generation, false);
        if !matches!(standing, Standing::Newer) {
            return (standing, None);
        }
        self.generation = generation;
        self.enabled = false;
        self.enabled_at_ms = None;
        (
            standing,
            Some(Resumed {
                generation,
                retention_resumes_at_ms: now_ms,
            }),
        )
    }

    /// Drives every subsystem through the four things privacy mode asks of them.
    ///
    /// The order is the contract and it is the order section 24 states: fence what is
    /// content-bearing *immediately*, cancel what has not been dispatched, then remove the
    /// retained local content. Fencing first is what stops a queue emptying itself while the
    /// cancellation walks it.
    ///
    /// A subsystem whose step fails takes no further step: a cancellation or a removal behind a
    /// fence that did not go up would be cleanup reported over a queue that is still filling. It
    /// is listed among the enabling's unfinished subsystems with the step and its store's reason,
    /// and the other subsystems are taken through every step. A caller retries it by applying it
    /// again.
    ///
    /// It does not report completion. In-flight work is reconciled by [`Self::reconcile`], and
    /// until that says so this is an enabling rather than a finished cleanup.
    pub fn apply(
        &self,
        subsystems: &mut [&mut dyn PrivacySubsystem],
        now_ms: TimestampMs,
    ) -> Enabling {
        let generation = self.generation;
        let mut stopped = vec![false; subsystems.len()];
        let mut unfinished = Vec::new();
        let mut fenced = Vec::new();
        for (index, subsystem) in subsystems.iter_mut().enumerate() {
            match subsystem.fence(generation) {
                Ok(done) => fenced.push((subsystem.name(), done)),
                Err(unavailable) => {
                    stopped[index] = true;
                    unfinished.push(Unfinished {
                        subsystem: subsystem.name(),
                        step: Step::Fence,
                        unavailable,
                    });
                }
            }
        }
        let mut cancelled = Vec::new();
        for (index, subsystem) in subsystems.iter_mut().enumerate() {
            if stopped[index] {
                continue;
            }
            match subsystem.cancel_undispatched(generation) {
                Ok(done) => cancelled.push((subsystem.name(), done)),
                Err(unavailable) => {
                    stopped[index] = true;
                    unfinished.push(Unfinished {
                        subsystem: subsystem.name(),
                        step: Step::Cancel,
                        unavailable,
                    });
                }
            }
        }
        let mut removed = Vec::new();
        for (index, subsystem) in subsystems.iter_mut().enumerate() {
            if stopped[index] {
                continue;
            }
            match subsystem.remove_retained(generation) {
                Ok(done) => removed.push((subsystem.name(), done)),
                Err(unavailable) => unfinished.push(Unfinished {
                    subsystem: subsystem.name(),
                    step: Step::Remove,
                    unavailable,
                }),
            }
        }
        let kept = subsystems
            .iter()
            .flat_map(|subsystem| subsystem.kept())
            .collect();
        let mut exported = Vec::new();
        let mut unlisted = Vec::new();
        for subsystem in subsystems.iter() {
            match subsystem.exported() {
                Ok(copies) => exported.extend(copies),
                Err(unavailable) => unlisted.push((subsystem.name(), unavailable)),
            }
        }
        Enabling {
            generation,
            at_ms: now_ms,
            disabled: Disabled::ALL.to_vec(),
            fenced,
            cancelled,
            removed,
            unfinished,
            kept,
            exported,
            unlisted,
        }
    }

    /// Asks every subsystem whether its in-flight cleanup has finished.
    ///
    /// A subsystem that cannot say makes the answer [`Completion::Unavailable`], whatever the
    /// others say, and one with work outstanding makes it at least [`Completion::Reconciling`].
    #[must_use]
    pub fn reconcile(subsystems: &[&dyn PrivacySubsystem]) -> Completion {
        let mut outstanding = Vec::new();
        let mut unavailable = Vec::new();
        for subsystem in subsystems {
            match subsystem.outstanding() {
                Ok(0) => {}
                Ok(count) => outstanding.push((subsystem.name(), count)),
                Err(reason) => unavailable.push((subsystem.name(), reason)),
            }
        }
        Completion::from_parts(outstanding, unavailable)
    }

    /// Returns whether a result produced under an earlier generation may be published.
    ///
    /// It is the whole rule and it is here rather than beside each publication, because a rule
    /// each caller restated would be a rule one of them could restate differently. A result is
    /// published only when the generation it was produced under is *exactly* the one in force: an
    /// older one belongs to work privacy mode cancelled, and a newer one belongs to no generation
    /// this host has opened.
    #[must_use]
    pub const fn accepts_result(&self, produced_under: PrivacyGeneration) -> bool {
        produced_under.get() == self.generation.get()
    }

    /// Turns privacy mode off.
    ///
    /// Retention starts again from this moment, and it starts under a generation of its own.
    /// Leaving the generation where it was would leave every result admitted during the private
    /// interval acceptable the moment privacy mode was turned off, which is the one thing the
    /// generation exists to prevent: the boundary is what work was admitted on either side of,
    /// and turning privacy mode off is a boundary as much as turning it on is.
    ///
    /// It reconstructs nothing that was omitted while privacy mode was on.
    pub const fn disable(&mut self, now_ms: TimestampMs) -> Resumed {
        self.enabled = false;
        self.generation = self.generation.next();
        self.enabled_at_ms = None;
        Resumed {
            generation: self.generation,
            retention_resumes_at_ms: now_ms,
        }
    }
}

/// What turning privacy mode off did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Resumed {
    /// The generation retention resumes under.
    ///
    /// It is a new one, so a result admitted during the private interval is refused after privacy
    /// mode is turned off exactly as it was during it.
    pub generation: PrivacyGeneration,
    /// The instant retention starts again from. Nothing before it is reconstructed.
    pub retention_resumes_at_ms: TimestampMs,
}

pub mod subsystems;

pub use crate::privacy::subsystems::{
    BackupOutbox, DescriptionInference, ReceiptMetadata, RetainedHistory, SyncOutbox,
    TransferPreviews, exported,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::privacy::subsystems::Recording;

    fn drive(mode: &PrivacyMode, first: &mut Recording, second: &mut Recording) -> Enabling {
        let mut subsystems: Vec<&mut dyn PrivacySubsystem> = vec![first, second];
        mode.apply(&mut subsystems, TimestampMs::new(1_000))
    }

    #[test]
    fn opening_a_generation_advances_it_each_time() {
        let mut mode = PrivacyMode::new();
        assert_eq!(mode.generation(), PrivacyGeneration::INITIAL);
        assert_eq!(
            mode.open_generation(TimestampMs::new(1_000)),
            PrivacyGeneration::new(1)
        );
        assert_eq!(
            mode.open_generation(TimestampMs::new(2_000)),
            PrivacyGeneration::new(2)
        );
        assert!(mode.is_enabled());
    }

    #[test]
    fn every_subsystem_is_fenced_before_any_is_cancelled() {
        let mut mode = PrivacyMode::new();
        mode.open_generation(TimestampMs::new(1_000));
        let mut first = Recording::new("first");
        let mut second = Recording::new("second");
        let enabling = drive(&mode, &mut first, &mut second);
        // The recording subsystem refuses to cancel anything it has not fenced first, so a
        // cancellation that had run early would be counted as taking nothing back.
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
        let mut mode = PrivacyMode::new();
        for capability in Disabled::ALL {
            assert!(!mode.disables(*capability));
        }
        mode.open_generation(TimestampMs::new(1_000));
        let mut first = Recording::new("first");
        let mut second = Recording::new("second");
        assert_eq!(
            drive(&mode, &mut first, &mut second).disabled,
            Disabled::ALL.to_vec()
        );
        for capability in Disabled::ALL {
            assert!(mode.disables(*capability));
        }
    }

    #[test]
    fn completion_is_not_reported_while_any_subsystem_is_still_reconciling() {
        let mut mode = PrivacyMode::new();
        mode.open_generation(TimestampMs::new(1_000));
        let mut quiet = Recording::new("quiet");
        let mut busy = Recording::with_in_flight("busy", 2);
        drive(&mode, &mut quiet, &mut busy);
        match PrivacyMode::reconcile(&[&quiet, &busy]) {
            Completion::Reconciling { outstanding } => assert_eq!(outstanding, vec![("busy", 2)]),
            other => panic!("cleanup had not finished, and nothing was in the way: {other:?}"),
        }
        // The subsystem the caller still holds is the one that reports its own cleanup, which is
        // what makes completion reachable rather than a state nothing can leave.
        busy.note_reconciled();
        busy.note_reconciled();
        assert!(PrivacyMode::reconcile(&[&quiet, &busy]).is_complete());
    }

    /// A store that cannot say what is outstanding makes the whole answer unavailable, with its
    /// reason, and never complete, whatever the other subsystems say; it does not hide their work.
    #[test]
    fn a_subsystem_that_cannot_answer_makes_completion_unavailable_and_never_complete() {
        let mut mode = PrivacyMode::new();
        mode.open_generation(TimestampMs::new(1_000));
        let mut busy = Recording::with_in_flight("busy", 1);
        let mut stuck = Recording::unanswerable("stuck");
        drive(&mode, &mut busy, &mut stuck);
        let Completion::Unavailable {
            unavailable,
            outstanding,
        } = PrivacyMode::reconcile(&[&busy, &stuck])
        else {
            panic!("a subsystem that cannot answer is not reconciling and not complete");
        };
        assert_eq!(unavailable.len(), 1);
        assert_eq!(unavailable[0].0, "stuck");
        assert!(unavailable[0].1.reason().contains("cannot say"));
        assert_eq!(outstanding, vec![("busy", 1)]);

        // Its work settling elsewhere does not make it complete while it still cannot answer.
        busy.note_reconciled();
        assert!(!PrivacyMode::reconcile(&[&busy, &stuck]).is_complete());
        stuck.recover();
        assert!(PrivacyMode::reconcile(&[&busy, &stuck]).is_complete());
    }

    /// A refused step stops that subsystem, with its reason, and takes nothing behind it; the
    /// others go through every step. Applying it again once the store answers finishes it.
    #[test]
    fn a_refused_step_stops_its_subsystem_and_the_others_go_on() {
        let mut mode = PrivacyMode::new();
        mode.open_generation(TimestampMs::new(1_000));
        let mut refusing = Recording::refusing("refusing", Step::Fence);
        let mut willing = Recording::new("willing");
        let enabling = drive(&mode, &mut refusing, &mut willing);
        assert!(!enabling.is_finished());
        let unfinished = enabling.unfinished("refusing").expect("it stopped");
        assert_eq!(unfinished.step, Step::Fence);
        assert!(
            unfinished
                .unavailable
                .reason()
                .contains("refused the fence step")
        );
        assert!(!refusing.was_fenced() && !refusing.was_cancelled());
        assert!(willing.was_fenced() && willing.was_cancelled());
        assert_eq!(enabling.fenced.len(), 1);
        assert_eq!(enabling.cancelled.len(), 1);
        assert_eq!(enabling.removed.len(), 1);

        refusing.recover();
        let enabling = drive(&mode, &mut refusing, &mut willing);
        assert!(enabling.is_finished());
        assert!(refusing.was_fenced() && refusing.was_cancelled());
    }

    /// A generation another owner recorded is taken only when it is newer; the one in force in
    /// the same state changes nothing, and anything else is refused.
    #[test]
    fn a_named_generation_is_taken_only_when_it_is_newer() {
        let mut mode = PrivacyMode::new();
        assert_eq!(
            mode.enter(PrivacyGeneration::new(3), TimestampMs::new(1_000)),
            Standing::Newer
        );
        assert!(mode.is_enabled());
        assert_eq!(mode.generation(), PrivacyGeneration::new(3));
        assert_eq!(
            mode.enter(PrivacyGeneration::new(3), TimestampMs::new(2_000)),
            Standing::Current
        );
        assert_eq!(mode.enabled_at_ms(), Some(TimestampMs::new(1_000)));
        assert_eq!(
            mode.enter(PrivacyGeneration::new(2), TimestampMs::new(2_000)),
            Standing::Refused
        );
        let (standing, resumed) = mode.leave(PrivacyGeneration::new(3), TimestampMs::new(3_000));
        assert_eq!((standing, resumed), (Standing::Refused, None));
        assert!(
            mode.is_enabled(),
            "one generation does not mean both on and off"
        );
        let (standing, resumed) = mode.leave(PrivacyGeneration::new(4), TimestampMs::new(3_000));
        assert_eq!(standing, Standing::Newer);
        assert_eq!(
            resumed.map(|resumed| resumed.generation),
            Some(PrivacyGeneration::new(4))
        );
        assert!(!mode.is_enabled());
        assert!(!mode.accepts_result(PrivacyGeneration::new(3)));
        assert_eq!(
            mode.leave(PrivacyGeneration::new(4), TimestampMs::new(4_000)),
            (Standing::Current, None)
        );
    }

    #[test]
    fn a_result_is_published_only_under_the_generation_in_force() {
        let mut mode = PrivacyMode::new();
        mode.open_generation(TimestampMs::new(1_000));
        assert!(!mode.accepts_result(PrivacyGeneration::INITIAL));
        assert!(mode.accepts_result(PrivacyGeneration::new(1)));
        // A generation this host has never opened is not a licence either.
        assert!(!mode.accepts_result(PrivacyGeneration::new(2)));
        mode.open_generation(TimestampMs::new(2_000));
        assert!(!mode.accepts_result(PrivacyGeneration::new(1)));
    }

    #[test]
    fn disabling_opens_a_boundary_of_its_own_and_reconstructs_nothing() {
        let mut mode = PrivacyMode::new();
        mode.open_generation(TimestampMs::new(1_000));
        let resumed = mode.disable(TimestampMs::new(5_000));
        assert!(!mode.is_enabled());
        assert_eq!(resumed.retention_resumes_at_ms.get(), 5_000);
        assert_eq!(resumed.generation, PrivacyGeneration::new(2));
        assert!(!mode.accepts_result(PrivacyGeneration::new(1)));
        assert!(!mode.accepts_result(PrivacyGeneration::INITIAL));
        assert!(mode.accepts_result(resumed.generation));
    }
}
