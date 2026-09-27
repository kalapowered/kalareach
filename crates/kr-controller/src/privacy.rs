//! Privacy mode for one environment: its record, and the composition root that drives the
//! daemon's subsystems through the privacy contract.
//!
//! Section 24 asks for one privacy generation, recorded, and every part of the host drawing its
//! boundary there. This module is where that generation lives and where it is driven from.
//!
//! * **The record comes first.** `privacy.sqlite3` in the daemon's state directory holds the
//!   generation, whether privacy mode is on, and one obligation per session whose own cleanup has
//!   not been evidenced. An enabling or a disabling commits its row before any subsystem is
//!   touched, so a boundary a restart could not see is never drawn, and a store that cannot take
//!   the row refuses the change with nothing touched.
//! * **The state is published as the row commits.** [`PrivacyState`] is what every reader asks:
//!   descriptions stop answering generated text, and delivery sends no content, from the moment
//!   the row is written rather than from the moment each subsystem's own fence goes up. A fence a
//!   store refused therefore leaves nothing able to leave this host while the fence is retried.
//! * **Every daemon subsystem goes through the contract.** The backup service and the delivery
//!   outbox are each fenced, then have their undispatched work taken back, then have their
//!   retained content removed, in that order across all of them. A step a store refuses is owed,
//!   with the store's reason, and retried on a schedule until it succeeds; the backup service is
//!   reconciled again after its retry succeeds, because a generation it accepted while it could not
//!   take a step is finished only by reconciliation.
//! * **Nothing is settled here.** Work that left this host before the fence is in flight until the
//!   evidence about that attempt arrives through the subsystem that holds it. A restart and an
//!   object acknowledgement are not evidence, and reconciliation reports the work until it is.
//! * **Sessions apply the generation themselves.** Each live session's worker is told the
//!   generation and answers with its own completion; a session's obligation ends only when its
//!   worker says its cleanup is complete. A session whose worker has ended keeps its obligation,
//!   reported as unavailable, because what it retained is the archive's and nothing here removes
//!   it.
//! * **Disabling is two phases.** It is refused while a daemon step or a live session still owes
//!   cleanup. Otherwise the new generation is recorded first and then each fence is released; a
//!   release that is still pending, or that a store refused, is owed and retried, and the report
//!   says privacy mode is still being turned off until every release has landed.
//!
//! # The startup order
//!
//! [`EnvironmentPrivacy::open`] reads the record before anything else runs, and publishes the state
//! it holds. [`EnvironmentPrivacy::resume`] then takes every daemon subsystem through the steps the
//! record asks for again. A daemon calls it after opening the backup service, which opens unready,
//! and before reconciling that service, starting delivery or serving any request, so work an
//! earlier process left behind is fenced before anything can resume it.

use std::collections::BTreeMap;
use std::path::Path;
use std::str::FromStr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, RwLock};

use kr_delivery::privacy::DeliveryOutbox;
use kr_protocol::ids::SessionId;
use kr_protocol::scalars::TimestampMs;
use kr_worker::privacy::{
    Completion, Disabled, Enabling, Exported, KeptExplicitly, PrivacyGeneration, PrivacyMode,
    PrivacySubsystem, Unavailable,
};
use rusqlite::{Connection, OptionalExtension, params};

use crate::backup::BackupService;
use crate::backup::store::FenceRelease;
use crate::error::{ControllerError, Result};
use crate::push::DeliveryModule;

/// The file the environment's privacy record lives in.
pub const PRIVACY_RECORD: &str = "privacy.sqlite3";

/// The schema version this build reads and writes.
const SCHEMA_VERSION: i64 = 1;

/// The first wait before a refused step is tried again.
const FIRST_RETRY_MS: u64 = 1_000;

/// The longest wait between two tries of a refused step.
const LONGEST_RETRY_MS: u64 = 60_000;

/// What the environment's privacy state is, as every reader sees it.
///
/// It is published as the record commits, before any subsystem is driven, and at open, before
/// anything runs. It is cheap to clone and to read, because a delivery asks it before every send.
#[derive(Clone, Debug, Default)]
pub struct PrivacyState {
    published: Arc<RwLock<Published>>,
}

/// One reading of [`PrivacyState`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Published {
    /// The generation in force.
    pub generation: PrivacyGeneration,
    /// Whether privacy mode is on.
    pub private: bool,
}

impl PrivacyState {
    /// Returns the state as it stands now.
    #[must_use]
    pub fn now(&self) -> Published {
        *self
            .published
            .read()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Returns true while privacy mode is on.
    #[must_use]
    pub fn is_private(&self) -> bool {
        self.now().private
    }

    /// Returns whether content may leave this host through a delivery now.
    ///
    /// Never while privacy mode is on, whatever any subsystem's own fence says: the state is
    /// published before any fence is raised, and a fence a store refused is still being retried.
    #[must_use]
    pub fn may_send_content(&self) -> bool {
        !self.is_private()
    }

    /// Returns whether a result produced under `produced_under` may be published.
    ///
    /// Only the generation in force is accepted: an older one belongs to work privacy mode drew a
    /// line under, and a newer one to no generation this environment has recorded.
    #[must_use]
    pub fn accepts_result(&self, produced_under: PrivacyGeneration) -> bool {
        self.now().generation == produced_under
    }

    fn publish(&self, published: Published) {
        *self
            .published
            .write()
            .unwrap_or_else(PoisonError::into_inner) = published;
    }
}

/// The daemon subsystems this module drives.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Subsystem {
    Backup,
    Delivery,
}

impl Subsystem {
    const ALL: [Self; 2] = [Self::Backup, Self::Delivery];

    const fn name(self) -> &'static str {
        match self {
            Self::Backup => crate::backup::SUBSYSTEM_NAME,
            Self::Delivery => "delivery",
        }
    }
}

/// When a refused step is next tried, and how many times it has been.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Backoff {
    attempts: u32,
    next_at_ms: u64,
}

impl Backoff {
    /// Returns the schedule after one more try that did not succeed.
    fn after_failure(self, now_ms: TimestampMs) -> Self {
        let wait = FIRST_RETRY_MS
            .saturating_mul(1_u64 << self.attempts.min(16))
            .min(LONGEST_RETRY_MS);
        Self {
            attempts: self.attempts.saturating_add(1),
            next_at_ms: now_ms.get().saturating_add(wait),
        }
    }

    const fn due(self, now_ms: TimestampMs) -> bool {
        now_ms.get() >= self.next_at_ms
    }
}

/// What one daemon subsystem still owes, and why.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Owed {
    work: Work,
    owing: Owing,
    retry: Backoff,
}

/// Which piece of work is owed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Work {
    /// The enabling's steps, from the fence on.
    Steps,
    /// Reconciling the backup service after its steps succeeded.
    Reconcile,
    /// Releasing the fence when privacy mode is turned off.
    Release,
}

/// Why it is owed.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Owing {
    /// A store refused the work, with its reason.
    Refused(Unavailable),
    /// The work is waiting for cleanup to finish: this much is outstanding.
    Pending(u64),
}

/// How far one session has come, as its worker last said.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct SessionProgress {
    reach: Reach,
    answer: Option<Answer>,
    notices: Backoff,
}

/// Whether a session's worker can be told anything.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Reach {
    /// Nothing has said yet, which is the state of every session after a daemon restart.
    #[default]
    Unknown,
    /// Its worker is running.
    Live,
    /// Its worker has ended; what it retained is the archive's.
    Ended,
}

/// A worker's last answer to a notice.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Answer {
    generation: PrivacyGeneration,
    enabled: bool,
    completion: Completion,
}

/// A notice one session's worker is owed: the generation in force and whether privacy mode is on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Notice {
    /// The session.
    pub session_id: SessionId,
    /// The generation in force.
    pub generation: PrivacyGeneration,
    /// Whether privacy mode is on at it.
    pub enabled: bool,
}

/// One session's cleanup that privacy mode is still owed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Obligation {
    /// The session.
    pub session_id: SessionId,
    /// The generation whose cleanup it owes.
    pub generation: PrivacyGeneration,
    /// Where it stands.
    pub standing: Standing,
}

/// Where one session's obligation stands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Standing {
    /// Its worker has not said yet.
    AwaitingWorker,
    /// Its worker says its cleanup is still reconciling, with this much outstanding.
    Reconciling {
        /// How much is outstanding.
        outstanding: u64,
    },
    /// Its worker says something is in the way.
    Unavailable {
        /// What its worker said.
        reason: String,
    },
    /// Its worker ended before it said its cleanup was complete. What it retained is the
    /// archive's, and the obligation stays until something gives evidence that it is gone.
    WorkerEnded,
}

/// Where privacy mode stands for the environment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    /// The generation in force.
    pub generation: PrivacyGeneration,
    /// Whether privacy mode is on.
    pub enabled: bool,
    /// When it last changed.
    pub changed_at_ms: TimestampMs,
    /// Whether the last change has finished taking effect: the enabling's cleanup reconciled, or
    /// the disabling's releases landed. Every session obligation counts in either state.
    pub completion: Completion,
    /// Each session's cleanup still owed.
    pub obligations: Vec<Obligation>,
    /// What is disabled while privacy mode is on.
    pub disabled: Vec<Disabled>,
    /// What the daemon's subsystems keep, explicitly.
    pub kept: Vec<KeptExplicitly>,
    /// What had already left this host, which is shown rather than erased.
    pub exported: Vec<Exported>,
    /// Each subsystem that could not list what had left, and why.
    pub unlisted: Vec<(&'static str, Unavailable)>,
}

/// The environment's privacy record, and its composition root.
#[derive(Debug)]
pub struct EnvironmentPrivacy {
    inner: Mutex<Inner>,
    state: PrivacyState,
    backup: Arc<BackupService>,
    delivery: Arc<DeliveryModule>,
}

#[derive(Debug)]
struct Inner {
    record: Record,
    mode: PrivacyMode,
    changed_at_ms: TimestampMs,
    owed: BTreeMap<Subsystem, Owed>,
    cleanup: Backoff,
    obligations: BTreeMap<SessionId, PrivacyGeneration>,
    sessions: BTreeMap<SessionId, SessionProgress>,
}

impl EnvironmentPrivacy {
    /// Opens the environment's privacy record in `state_dir` and publishes the state it holds.
    ///
    /// Nothing is driven here: [`Self::resume`] is what takes the subsystems through the steps the
    /// record asks for.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the record cannot be opened or read.
    /// A daemon that cannot read whether privacy mode is on does not start as though it knew.
    pub fn open(
        state_dir: &Path,
        backup: Arc<BackupService>,
        delivery: Arc<DeliveryModule>,
    ) -> Result<Self> {
        let record = Record::open(state_dir)?;
        let stored = record.read()?;
        let obligations = record.obligations()?;
        let state = PrivacyState::default();
        state.publish(Published {
            generation: stored.generation,
            private: stored.enabled,
        });
        Ok(Self {
            inner: Mutex::new(Inner {
                record,
                mode: PrivacyMode::restored(stored.generation, stored.enabled),
                changed_at_ms: stored.changed_at_ms,
                owed: BTreeMap::new(),
                cleanup: Backoff::default(),
                obligations,
                sessions: BTreeMap::new(),
            }),
            state,
            backup,
            delivery,
        })
    }

    /// Returns the published state every reader asks.
    #[must_use]
    pub fn state(&self) -> PrivacyState {
        self.state.clone()
    }

    fn inner(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Takes every daemon subsystem through what the record asks for, as a daemon starts.
    ///
    /// With privacy mode on, each subsystem is fenced, has its undispatched work taken back and
    /// has its retained content removed again; each step is idempotent at one generation, so what
    /// an earlier process finished stays finished and what it did not is finished here. With it
    /// off, every fence is released again. A step a store refuses is owed and retried by
    /// [`Self::tick`].
    pub fn resume(&self, now_ms: TimestampMs) -> Report {
        let mut inner = self.inner();
        if inner.mode.is_enabled() {
            self.apply(&mut inner, &Subsystem::ALL, now_ms);
        } else if inner.mode.generation() > PrivacyGeneration::INITIAL {
            self.release(&mut inner, now_ms);
        }
        self.report(&inner, now_ms)
    }

    /// Turns privacy mode on.
    ///
    /// The generation is advanced and recorded, with an obligation for every session in
    /// `sessions` (each one this environment holds content for), in one transaction before
    /// anything else happens; the state is published as it commits; then every daemon subsystem
    /// is taken through its steps. Privacy mode already on is answered with where it stands.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the record cannot be written. Nothing
    /// has been fenced or removed then: a privacy mode this environment cannot write down is one
    /// it must not claim to be in.
    pub fn enable(&self, sessions: &[SessionId], now_ms: TimestampMs) -> Result<Report> {
        let mut inner = self.inner();
        if inner.mode.is_enabled() {
            return Ok(self.report(&inner, now_ms));
        }
        let mut mode = inner.mode;
        let generation = mode.open_generation(now_ms);
        inner.record.enable(generation, sessions, now_ms)?;
        inner.mode = mode;
        inner.changed_at_ms = now_ms;
        self.state.publish(Published {
            generation,
            private: true,
        });
        // An enabling supersedes whatever an earlier disabling still owed: the fences it would
        // have released are raised again at the new generation, and the next disabling releases
        // every fence that stands.
        inner.owed.clear();
        inner.cleanup = Backoff::default();
        for session_id in sessions {
            inner.obligations.insert(*session_id, generation);
        }
        for progress in inner.sessions.values_mut() {
            progress.notices = Backoff::default();
        }
        self.apply(&mut inner, &Subsystem::ALL, now_ms);
        Ok(self.report(&inner, now_ms))
    }

    /// Turns privacy mode off.
    ///
    /// Refused while a daemon subsystem or a live session still owes cleanup: resuming retention
    /// beside an unfinished purge would mix new content into what is still being removed. A
    /// session whose worker has ended does not hold it back, because nothing resumes in its store;
    /// its obligation stays recorded and reported. Otherwise the next generation is recorded first
    /// and every fence is then released. Privacy mode already off is answered with where it stands.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::Refused`], with
    /// [`kr_protocol::error::ErrorCode::ResourceUnavailable`], while cleanup is owed, naming what
    /// is owed, and [`ControllerError::RegistryUnavailable`] when the record cannot be written.
    pub fn disable(&self, now_ms: TimestampMs) -> Result<Report> {
        let mut inner = self.inner();
        if !inner.mode.is_enabled() {
            return Ok(self.report(&inner, now_ms));
        }
        let owed = self.owed_before_disabling(&inner, now_ms);
        if !owed.is_empty() {
            return Err(ControllerError::Refused {
                code: kr_protocol::error::ErrorCode::ResourceUnavailable,
                detail: format!(
                    "privacy mode is not turned off while its cleanup is unfinished: {}",
                    owed.join("; ")
                ),
            });
        }
        let mut mode = inner.mode;
        let resumed = mode.disable(now_ms);
        inner.record.disable(resumed.generation, now_ms)?;
        inner.mode = mode;
        inner.changed_at_ms = now_ms;
        self.state.publish(Published {
            generation: resumed.generation,
            private: false,
        });
        for progress in inner.sessions.values_mut() {
            progress.notices = Backoff::default();
        }
        self.release(&mut inner, now_ms);
        Ok(self.report(&inner, now_ms))
    }

    /// Retries what is owed and whose retry is due, and says where privacy mode stands.
    ///
    /// With privacy mode on, each daemon subsystem that owes a step is taken through its steps
    /// again, and the backup service is reconciled once its retry succeeds; while the backup
    /// service still holds cleanup obligations, its cleanup is run again on the same schedule, so
    /// a target that was briefly unavailable is removed and a generation whose attempt has ended
    /// is finished. With it off, each release still owed is attempted again.
    pub fn tick(&self, now_ms: TimestampMs) -> Report {
        let mut inner = self.inner();
        if inner.mode.is_enabled() {
            let due: Vec<Subsystem> = inner
                .owed
                .iter()
                .filter(|(_, owed)| owed.work != Work::Release && owed.retry.due(now_ms))
                .map(|(subsystem, _)| *subsystem)
                .collect();
            if !due.is_empty() {
                self.apply(&mut inner, &due, now_ms);
            }
            self.clean_backup(&mut inner, now_ms);
        } else if inner
            .owed
            .values()
            .any(|owed| owed.work == Work::Release && owed.retry.due(now_ms))
        {
            self.release(&mut inner, now_ms);
        }
        self.report(&inner, now_ms)
    }

    /// Says where privacy mode stands, without retrying anything.
    #[must_use]
    pub fn report_now(&self, now_ms: TimestampMs) -> Report {
        let inner = self.inner();
        self.report(&inner, now_ms)
    }

    /// Records that a session's worker is running, so it is told the generation in force.
    pub fn note_session_live(&self, session_id: SessionId) {
        let mut inner = self.inner();
        let progress = inner.sessions.entry(session_id).or_default();
        progress.reach = Reach::Live;
    }

    /// Records that a session's worker has ended.
    ///
    /// Its obligation, when it has one, stays: an ended worker is not evidence that what it
    /// retained is gone.
    pub fn note_session_ended(&self, session_id: SessionId) {
        let mut inner = self.inner();
        if inner.obligations.contains_key(&session_id) {
            let progress = inner.sessions.entry(session_id).or_default();
            progress.reach = Reach::Ended;
        } else {
            inner.sessions.remove(&session_id);
        }
    }

    /// Returns the notices owed to live sessions whose turn has come, and schedules the next.
    ///
    /// A session is owed one until its worker answers that it holds the generation in force, in
    /// the state in force, with its cleanup complete. Repeating a notice is how a worker's
    /// completion is asked about again.
    pub fn notices_due(&self, now_ms: TimestampMs) -> Vec<Notice> {
        let mut inner = self.inner();
        let generation = inner.mode.generation();
        let enabled = inner.mode.is_enabled();
        let mut due = Vec::new();
        for (session_id, progress) in &mut inner.sessions {
            if progress.reach != Reach::Live || !progress.notices.due(now_ms) {
                continue;
            }
            let settled = progress.answer.as_ref().is_some_and(|answer| {
                answer.generation == generation
                    && answer.enabled == enabled
                    && answer.completion.is_complete()
            });
            if settled {
                continue;
            }
            progress.notices = progress.notices.after_failure(now_ms);
            due.push(Notice {
                session_id: *session_id,
                generation,
                enabled,
            });
        }
        due
    }

    /// Records a worker's answer to a notice.
    ///
    /// An answer that its session holds the generation in force, in the state in force, with its
    /// cleanup complete ends that session's obligation, durably. Anything else is kept as where
    /// the session stands.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the obligation's end cannot be
    /// written. The obligation then stays, and the next answer ends it.
    pub fn note_answer(
        &self,
        session_id: SessionId,
        generation: PrivacyGeneration,
        enabled: bool,
        completion: Completion,
    ) -> Result<()> {
        let mut inner = self.inner();
        let current = generation == inner.mode.generation() && enabled == inner.mode.is_enabled();
        if current && completion.is_complete() && inner.obligations.contains_key(&session_id) {
            inner.record.discharge(session_id, generation)?;
            inner.obligations.remove(&session_id);
        }
        let progress = inner.sessions.entry(session_id).or_default();
        if progress.reach == Reach::Unknown {
            progress.reach = Reach::Live;
        }
        progress.answer = Some(Answer {
            generation,
            enabled,
            completion,
        });
        Ok(())
    }

    /// Takes the named daemon subsystems through the enabling's steps, and records what they owe.
    fn apply(&self, inner: &mut Inner, which: &[Subsystem], now_ms: TimestampMs) {
        let mode = inner.mode;
        let backup_was_owed = inner.owed.contains_key(&Subsystem::Backup);
        let enabling = self.drive(mode, which, now_ms);
        for subsystem in which {
            let unfinished = enabling
                .as_ref()
                .map_err(Clone::clone)
                .and_then(|enabling| {
                    enabling
                        .unfinished(subsystem.name())
                        .map_or(Ok(()), |unfinished| Err(unfinished.unavailable.clone()))
                });
            match unfinished {
                Ok(()) => {
                    inner.owed.remove(subsystem);
                }
                Err(unavailable) => owe(
                    inner,
                    *subsystem,
                    Work::Steps,
                    Owing::Refused(unavailable),
                    now_ms,
                ),
            }
        }
        // A generation the backup service accepted while it could not take a step is finished
        // only by reconciliation, so a retry that succeeds is followed by one.
        if backup_was_owed
            && which.contains(&Subsystem::Backup)
            && !inner.owed.contains_key(&Subsystem::Backup)
            && let Err(error) = self.backup.reconcile(now_ms)
        {
            owe(
                inner,
                Subsystem::Backup,
                Work::Reconcile,
                Owing::Refused(Unavailable::new(format!(
                    "the backup service could not be reconciled after its privacy steps: {error}"
                ))),
                now_ms,
            );
        }
    }

    /// Runs the privacy contract over the named subsystems, every fence before any cancellation.
    ///
    /// The delivery journal is held for the whole of it, so no delivery pass runs between two
    /// steps. A delivery module that cannot be held is itself the reason delivery could not be
    /// taken through its steps; the others still are.
    fn drive(
        &self,
        mode: PrivacyMode,
        which: &[Subsystem],
        now_ms: TimestampMs,
    ) -> std::result::Result<Enabling, Unavailable> {
        let mut backup = self.backup.privacy(now_ms);
        if !which.contains(&Subsystem::Delivery) {
            return Ok(mode.apply(&mut [&mut backup], now_ms));
        }
        let with_delivery = self.delivery.with(|producer| {
            let mut delivery = DeliveryOutbox::over(producer.journal_mut(), now_ms.get());
            let mut hooks: Vec<&mut dyn PrivacySubsystem> = Vec::new();
            if which.contains(&Subsystem::Backup) {
                hooks.push(&mut backup);
            }
            hooks.push(&mut delivery);
            Ok(mode.apply(&mut hooks, now_ms))
        });
        match with_delivery {
            Ok(enabling) => Ok(enabling),
            Err(error) => {
                let unavailable =
                    Unavailable::new(format!("the delivery outbox could not be reached: {error}"));
                if !which.contains(&Subsystem::Backup) {
                    return Err(unavailable);
                }
                let mut enabling = mode.apply(&mut [&mut self.backup.privacy(now_ms)], now_ms);
                enabling.unfinished.push(kr_worker::privacy::Unfinished {
                    subsystem: Subsystem::Delivery.name(),
                    step: kr_worker::privacy::Step::Fence,
                    unavailable,
                });
                Ok(enabling)
            }
        }
    }

    /// Runs the backup service's cleanup again while it holds obligations and its turn has come.
    fn clean_backup(&self, inner: &mut Inner, now_ms: TimestampMs) {
        if inner.owed.contains_key(&Subsystem::Backup) || !inner.cleanup.due(now_ms) {
            return;
        }
        let before = match self.backup.outstanding_work() {
            Ok(work) => work.obligations.len(),
            // The report asks the store again and says it cannot answer; a pass is not tried
            // over a store that cannot be read.
            Err(_) => {
                inner.cleanup = inner.cleanup.after_failure(now_ms);
                return;
            }
        };
        if before == 0 {
            inner.cleanup = Backoff::default();
            return;
        }
        match self.backup.run_cleanup(inner.mode.generation(), now_ms) {
            Ok(_) => {
                let after = self
                    .backup
                    .outstanding_work()
                    .map_or(before, |work| work.obligations.len());
                // Progress starts the schedule again; a pass that removed nothing waits longer.
                inner.cleanup = if after < before {
                    Backoff::default()
                } else {
                    inner.cleanup.after_failure(now_ms)
                };
            }
            Err(error) => owe(
                inner,
                Subsystem::Backup,
                Work::Steps,
                Owing::Refused(Unavailable::new(format!(
                    "staged backup ciphertext could not be removed: {error}"
                ))),
                now_ms,
            ),
        }
    }

    /// Releases every fence, now that the record says privacy mode is off.
    ///
    /// Each backup fence that stands below the new generation is released under it; one whose
    /// cleanup is still outstanding stays, pending, and is owed. The delivery outbox's fence is
    /// lifted at the new generation. Each is idempotent, so a release that already landed stays
    /// landed.
    fn release(&self, inner: &mut Inner, now_ms: TimestampMs) {
        let resumed = inner.mode.generation();
        match self.release_backup(resumed, now_ms) {
            Ok(None) => {
                inner.owed.remove(&Subsystem::Backup);
            }
            Ok(Some(pending)) => owe(
                inner,
                Subsystem::Backup,
                Work::Release,
                Owing::Pending(pending),
                now_ms,
            ),
            Err(unavailable) => owe(
                inner,
                Subsystem::Backup,
                Work::Release,
                Owing::Refused(unavailable),
                now_ms,
            ),
        }
        let lifted = self.delivery.with(|producer| {
            producer
                .journal_mut()
                .lift_fence(resumed.get())
                .map_err(|error| ControllerError::Storage {
                    operation: "lift the delivery outbox's privacy fence",
                    detail: error.to_string(),
                })
        });
        match lifted {
            Ok(()) => {
                inner.owed.remove(&Subsystem::Delivery);
            }
            Err(error) => owe(
                inner,
                Subsystem::Delivery,
                Work::Release,
                Owing::Refused(Unavailable::new(error.to_string())),
                now_ms,
            ),
        }
    }

    /// Releases the backup service's fences below `resumed`, and returns how much cleanup is
    /// still outstanding under one that could not be released yet.
    fn release_backup(
        &self,
        resumed: PrivacyGeneration,
        now_ms: TimestampMs,
    ) -> std::result::Result<Option<u64>, Unavailable> {
        let refused = |error: ControllerError| {
            Unavailable::new(format!(
                "the backup privacy fence could not be released: {error}"
            ))
        };
        loop {
            let status = self.backup.privacy_status().map_err(refused)?;
            let Some(fence) = status.unreleased_fence else {
                return Ok(None);
            };
            if fence >= resumed.get() {
                return Ok(None);
            }
            match self
                .backup
                .release_fence(PrivacyGeneration::new(fence), resumed, now_ms)
                .map_err(refused)?
            {
                FenceRelease::Released => {}
                FenceRelease::Pending { obligations } => return Ok(Some(obligations)),
                FenceRelease::NotHeld => return Ok(None),
            }
        }
    }

    /// Returns what keeps privacy mode from being turned off: every daemon step owed or still
    /// reconciling, and every session obligation whose worker has not ended.
    fn owed_before_disabling(&self, inner: &Inner, now_ms: TimestampMs) -> Vec<String> {
        let mut owed = Vec::new();
        let (outstanding, unavailable) = self.daemon_completion(inner, now_ms).into_parts();
        for (name, count) in outstanding {
            owed.push(format!("{name} has {count} outstanding"));
        }
        for (name, reason) in unavailable {
            owed.push(format!("{name}: {reason}"));
        }
        for (session_id, generation) in &inner.obligations {
            let reach = inner
                .sessions
                .get(session_id)
                .map_or(Reach::Unknown, |progress| progress.reach);
            if reach != Reach::Ended {
                owed.push(format!(
                    "session {session_id} has not said its cleanup for privacy generation {} is \
                     complete",
                    generation.get()
                ));
            }
        }
        owed
    }

    /// Returns where the daemon's own subsystems stand: what they owe, and while privacy mode is
    /// on, what their stores say is outstanding.
    fn daemon_completion(&self, inner: &Inner, now_ms: TimestampMs) -> Completion {
        let mut outstanding = Vec::new();
        let mut unavailable = Vec::new();
        for (subsystem, owed) in &inner.owed {
            match &owed.owing {
                Owing::Refused(reason) => unavailable.push((subsystem.name(), reason.clone())),
                Owing::Pending(count) => outstanding.push((subsystem.name(), *count)),
            }
        }
        if inner.mode.is_enabled() {
            let asked: Vec<Subsystem> = Subsystem::ALL
                .into_iter()
                .filter(|subsystem| !inner.owed.contains_key(subsystem))
                .collect();
            let (more_outstanding, more_unavailable) =
                self.reconcile_hooks(&asked, now_ms).into_parts();
            outstanding.extend(more_outstanding);
            unavailable.extend(more_unavailable);
        }
        Completion::from_parts(outstanding, unavailable)
    }

    /// Asks the named subsystems' hooks whether their in-flight cleanup has finished.
    fn reconcile_hooks(&self, which: &[Subsystem], now_ms: TimestampMs) -> Completion {
        let backup = self.backup.privacy(now_ms);
        if !which.contains(&Subsystem::Delivery) {
            if which.contains(&Subsystem::Backup) {
                return PrivacyMode::reconcile(&[&backup]);
            }
            return Completion::Complete;
        }
        let answered = self.delivery.with(|producer| {
            let delivery = DeliveryOutbox::over(producer.journal_mut(), now_ms.get());
            let mut hooks: Vec<&dyn PrivacySubsystem> = Vec::new();
            if which.contains(&Subsystem::Backup) {
                hooks.push(&backup);
            }
            hooks.push(&delivery);
            Ok(PrivacyMode::reconcile(&hooks))
        });
        answered.unwrap_or_else(|error| {
            let (outstanding, mut unavailable) = if which.contains(&Subsystem::Backup) {
                PrivacyMode::reconcile(&[&backup]).into_parts()
            } else {
                (Vec::new(), Vec::new())
            };
            unavailable.push((
                Subsystem::Delivery.name(),
                Unavailable::new(format!("the delivery outbox could not be reached: {error}")),
            ));
            Completion::from_parts(outstanding, unavailable)
        })
    }

    /// Builds the report.
    fn report(&self, inner: &Inner, now_ms: TimestampMs) -> Report {
        let (mut outstanding, mut unavailable) = self.daemon_completion(inner, now_ms).into_parts();
        let obligations = obligations(inner);
        for obligation in &obligations {
            match &obligation.standing {
                Standing::AwaitingWorker => outstanding.push(("sessions", 1)),
                Standing::Reconciling { outstanding: count } => {
                    outstanding.push(("sessions", (*count).max(1)));
                }
                Standing::Unavailable { reason } => unavailable.push((
                    "sessions",
                    Unavailable::new(format!("session {}: {reason}", obligation.session_id)),
                )),
                Standing::WorkerEnded => unavailable.push((
                    "sessions",
                    Unavailable::new(format!(
                        "session {} ended before it applied privacy generation {}; the archive \
                         holds what it retained, and nothing has given evidence that it is gone",
                        obligation.session_id,
                        obligation.generation.get()
                    )),
                )),
            }
        }
        if !inner.mode.is_enabled() {
            // Turning privacy mode off finishes once every live session holds the new generation.
            let generation = inner.mode.generation();
            for (session_id, progress) in &inner.sessions {
                if progress.reach != Reach::Live || inner.obligations.contains_key(session_id) {
                    continue;
                }
                let holds = progress
                    .answer
                    .as_ref()
                    .is_some_and(|answer| answer.generation == generation && !answer.enabled);
                if !holds {
                    outstanding.push(("sessions", 1));
                }
            }
        }
        let (kept, exported, unlisted) = self.retained(now_ms);
        Report {
            generation: inner.mode.generation(),
            enabled: inner.mode.is_enabled(),
            changed_at_ms: inner.changed_at_ms,
            completion: Completion::from_parts(outstanding, unavailable),
            obligations,
            disabled: if inner.mode.is_enabled() {
                Disabled::ALL.to_vec()
            } else {
                Vec::new()
            },
            kept,
            exported,
            unlisted,
        }
    }

    /// Returns what the daemon's subsystems keep, what has left this host, and what could not
    /// be listed.
    fn retained(
        &self,
        now_ms: TimestampMs,
    ) -> (
        Vec<KeptExplicitly>,
        Vec<Exported>,
        Vec<(&'static str, Unavailable)>,
    ) {
        let backup = self.backup.privacy(now_ms);
        let mut kept = backup.kept();
        let mut exported = Vec::new();
        let mut unlisted = Vec::new();
        match backup.exported() {
            Ok(copies) => exported.extend(copies),
            Err(reason) => unlisted.push((Subsystem::Backup.name(), reason)),
        }
        let delivery = self.delivery.with(|producer| {
            let outbox = DeliveryOutbox::over(producer.journal_mut(), now_ms.get());
            Ok((outbox.kept(), outbox.exported()))
        });
        match delivery {
            Ok((delivery_kept, delivery_exported)) => {
                kept.extend(delivery_kept);
                match delivery_exported {
                    Ok(copies) => exported.extend(copies),
                    Err(reason) => unlisted.push((Subsystem::Delivery.name(), reason)),
                }
            }
            Err(error) => unlisted.push((
                Subsystem::Delivery.name(),
                Unavailable::new(format!("the delivery outbox could not be reached: {error}")),
            )),
        }
        (kept, exported, unlisted)
    }
}

/// Records that `subsystem` owes `work`, keeping its schedule when it already owed the same work.
fn owe(inner: &mut Inner, subsystem: Subsystem, work: Work, owing: Owing, now_ms: TimestampMs) {
    let retry = inner
        .owed
        .get(&subsystem)
        .filter(|owed| owed.work == work)
        .map_or_else(Backoff::default, |owed| owed.retry)
        .after_failure(now_ms);
    inner.owed.insert(subsystem, Owed { work, owing, retry });
}

/// Returns every session obligation, with where it stands.
fn obligations(inner: &Inner) -> Vec<Obligation> {
    let generation = inner.mode.generation();
    let enabled = inner.mode.is_enabled();
    inner
        .obligations
        .iter()
        .map(|(session_id, owed_at)| {
            let progress = inner.sessions.get(session_id);
            let standing = match progress {
                Some(progress) if progress.reach == Reach::Ended => Standing::WorkerEnded,
                Some(SessionProgress {
                    answer: Some(answer),
                    ..
                }) if answer.generation == generation && answer.enabled == enabled => {
                    match &answer.completion {
                        Completion::Complete => Standing::AwaitingWorker,
                        Completion::Reconciling { outstanding } => Standing::Reconciling {
                            outstanding: outstanding.iter().map(|(_, count)| count).sum(),
                        },
                        Completion::Unavailable { unavailable, .. } => Standing::Unavailable {
                            reason: unavailable
                                .iter()
                                .map(|(name, reason)| format!("{name}: {reason}"))
                                .collect::<Vec<_>>()
                                .join("; "),
                        },
                    }
                }
                _ => Standing::AwaitingWorker,
            };
            Obligation {
                session_id: *session_id,
                generation: *owed_at,
                standing,
            }
        })
        .collect()
}

/// The record as it is stored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Stored {
    generation: PrivacyGeneration,
    enabled: bool,
    changed_at_ms: TimestampMs,
}

/// `privacy.sqlite3`: the environment's privacy record and its session obligations.
#[derive(Debug)]
struct Record {
    connection: Connection,
}

impl Record {
    fn open(state_dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(state_dir).map_err(ControllerError::registry)?;
        let connection =
            Connection::open(state_dir.join(PRIVACY_RECORD)).map_err(ControllerError::registry)?;
        // Every change is one transaction, and it is on the disk before the change is reported:
        // a boundary lost to a power failure would be one no restart could see.
        connection
            .execute_batch(
                "PRAGMA journal_mode = WAL;
                 PRAGMA synchronous = FULL;
                 CREATE TABLE IF NOT EXISTS privacy_schema (version INTEGER NOT NULL);
                 CREATE TABLE IF NOT EXISTS privacy_record (
                     id            INTEGER PRIMARY KEY CHECK (id = 0),
                     generation    INTEGER NOT NULL CHECK (generation >= 0),
                     enabled       INTEGER NOT NULL CHECK (enabled IN (0, 1)),
                     changed_at_ms INTEGER NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS privacy_obligations (
                     session_id     TEXT PRIMARY KEY,
                     generation     INTEGER NOT NULL CHECK (generation > 0),
                     recorded_at_ms INTEGER NOT NULL
                 );
                 CREATE TRIGGER IF NOT EXISTS privacy_generation_moves_forward
                 BEFORE UPDATE OF generation ON privacy_record
                 WHEN NEW.generation < OLD.generation
                 BEGIN SELECT RAISE(ABORT, 'a privacy generation never moves backwards'); END;
                 INSERT OR IGNORE INTO privacy_record (id, generation, enabled, changed_at_ms)
                 VALUES (0, 0, 0, 0);",
            )
            .map_err(ControllerError::registry)?;
        let version: Option<i64> = connection
            .query_row("SELECT version FROM privacy_schema", [], |row| row.get(0))
            .optional()
            .map_err(ControllerError::registry)?;
        match version {
            None => {
                connection
                    .execute(
                        "INSERT INTO privacy_schema (version) VALUES (?1)",
                        params![SCHEMA_VERSION],
                    )
                    .map_err(ControllerError::registry)?;
            }
            Some(SCHEMA_VERSION) => {}
            Some(found) => {
                return Err(ControllerError::registry(format!(
                    "the privacy record is at schema {found} and this build reads \
                     {SCHEMA_VERSION}"
                )));
            }
        }
        Ok(Self { connection })
    }

    fn read(&self) -> Result<Stored> {
        let (generation, enabled, changed_at_ms): (i64, i64, i64) = self
            .connection
            .query_row(
                "SELECT generation, enabled, changed_at_ms FROM privacy_record WHERE id = 0",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(ControllerError::registry)?;
        Ok(Stored {
            generation: PrivacyGeneration::new(u64::try_from(generation).unwrap_or(0)),
            enabled: enabled != 0,
            changed_at_ms: TimestampMs::new(u64::try_from(changed_at_ms).unwrap_or(0)),
        })
    }

    fn obligations(&self) -> Result<BTreeMap<SessionId, PrivacyGeneration>> {
        let mut statement = self
            .connection
            .prepare("SELECT session_id, generation FROM privacy_obligations")
            .map_err(ControllerError::registry)?;
        let rows = statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
            })
            .map_err(ControllerError::registry)?;
        let mut obligations = BTreeMap::new();
        for row in rows {
            let (session, generation) = row.map_err(ControllerError::registry)?;
            let session_id = SessionId::from_str(&session).map_err(|_| {
                ControllerError::registry(
                    "a privacy obligation names a session this build cannot read",
                )
            })?;
            obligations.insert(
                session_id,
                PrivacyGeneration::new(u64::try_from(generation).unwrap_or(0)),
            );
        }
        Ok(obligations)
    }

    /// Records that privacy mode is on at `generation`, with an obligation for each session, in
    /// one transaction.
    fn enable(
        &mut self,
        generation: PrivacyGeneration,
        sessions: &[SessionId],
        now_ms: TimestampMs,
    ) -> Result<()> {
        let transaction = self
            .connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(ControllerError::registry)?;
        transaction
            .execute(
                "UPDATE privacy_record SET generation = ?1, enabled = 1, changed_at_ms = ?2
                  WHERE id = 0",
                params![as_i64(generation.get()), as_i64(now_ms.get())],
            )
            .map_err(ControllerError::registry)?;
        for session_id in sessions {
            transaction
                .execute(
                    "INSERT INTO privacy_obligations (session_id, generation, recorded_at_ms)
                     VALUES (?1, ?2, ?3)
                     ON CONFLICT (session_id) DO UPDATE SET
                         generation = excluded.generation,
                         recorded_at_ms = excluded.recorded_at_ms",
                    params![
                        session_id.to_string(),
                        as_i64(generation.get()),
                        as_i64(now_ms.get())
                    ],
                )
                .map_err(ControllerError::registry)?;
        }
        transaction.commit().map_err(ControllerError::registry)
    }

    /// Records that privacy mode is off from `generation`.
    fn disable(&mut self, generation: PrivacyGeneration, now_ms: TimestampMs) -> Result<()> {
        self.connection
            .execute(
                "UPDATE privacy_record SET generation = ?1, enabled = 0, changed_at_ms = ?2
                  WHERE id = 0",
                params![as_i64(generation.get()), as_i64(now_ms.get())],
            )
            .map_err(ControllerError::registry)?;
        Ok(())
    }

    /// Ends a session's obligation for `generation` and any before it.
    fn discharge(&mut self, session_id: SessionId, generation: PrivacyGeneration) -> Result<()> {
        self.connection
            .execute(
                "DELETE FROM privacy_obligations WHERE session_id = ?1 AND generation <= ?2",
                params![session_id.to_string(), as_i64(generation.get())],
            )
            .map_err(ControllerError::registry)?;
        Ok(())
    }
}

fn as_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backup::Admitted;
    use crate::backup::store::{AttemptStatus, Publication, Step};
    use kr_crypto::backup::{
        ArchivePlan, ArchiveRecipients, CollectionKind, KeyRotation, ObjectSource, seal_archive,
        stage_object,
    };
    use kr_crypto::keys::{
        AuthorisationKeyPair, NotificationPreviewKeyPair, StoredEnvelopeKeyPair,
    };
    use kr_delivery::destination::{
        DeliveryRule, Destination, DestinationId, DestinationKind, DestinationRecord,
        ExternalDestination, Idempotency,
    };
    use kr_delivery::journal::{
        Claim, DeliveryRecord, DeliveryState, EventKey, EventSource, TakenEvent, Transition,
    };
    use kr_protocol::ids::{
        ArchiveId, BackupGeneration, BackupObjectId, DeviceId, EnvironmentId, NotificationId,
    };
    use kr_protocol::scalars::Uuid;

    /// Who these tests hand a dispatch attempt to.
    const EXECUTOR: &str = "the test transport";

    /// A fixed instant the tests' clock starts from.
    const NOW: u64 = 1_700_000_000_000;

    fn at(offset_ms: u64) -> TimestampMs {
        TimestampMs::new(NOW + offset_ms)
    }

    fn archive_id() -> ArchiveId {
        ArchiveId::new(Uuid::from_bytes([0x11; 16]))
    }

    fn session(byte: u8) -> SessionId {
        SessionId::new(Uuid::from_bytes([byte; 16]))
    }

    fn consumer() -> String {
        EventSource::WorkerOutbox.consumer("session-1")
    }

    /// The one external destination these tests deliver to.
    fn hook() -> DestinationRecord {
        DestinationRecord {
            id: DestinationId::new("hook").expect("an identifier"),
            destination: Destination::External(ExternalDestination {
                kind: DestinationKind::Webhook,
                endpoint: "https://example.invalid/hook".to_owned(),
                idempotency: Idempotency::Unsupported,
                credential: None,
            }),
            rule: Some(DeliveryRule {
                name: "on failure".to_owned(),
                grant_id: None,
            }),
            enabled: true,
            configured_at_ms: TimestampMs::new(1),
        }
    }

    /// The backup service and the delivery module of one environment, over `state`.
    fn services(state: &Path) -> (Arc<BackupService>, Arc<DeliveryModule>) {
        let backup = Arc::new(BackupService::open(state).expect("a backup service"));
        let delivery = Arc::new(
            DeliveryModule::open_at(
                &state.join("delivery.sqlite3"),
                NotificationPreviewKeyPair::generate().expect("a keypair"),
                StoredEnvelopeKeyPair::generate().expect("a keypair"),
                crate::push::secrets::DestinationSecrets::new(
                    Arc::new(kr_crypto::store::MemoryStore::new()),
                    EnvironmentId::new(Uuid::from_bytes([0xee; 16])),
                ),
            )
            .expect("a delivery module"),
        );
        (backup, delivery)
    }

    /// One environment's daemon subsystems and its privacy record, all on the internal disk.
    struct Host {
        root: tempfile::TempDir,
        writer: AuthorisationKeyPair,
        sender: StoredEnvelopeKeyPair,
        device: StoredEnvelopeKeyPair,
        backup: Arc<BackupService>,
        delivery: Arc<DeliveryModule>,
        privacy: EnvironmentPrivacy,
    }

    impl Host {
        /// A host whose backup service has reconciled, as a started daemon's has.
        fn open() -> Self {
            let host = Self::unreconciled();
            host.backup
                .reconcile(at(0))
                .expect("the startup reconciliation");
            host
        }

        /// A host whose backup service has opened and not yet reconciled.
        fn unreconciled() -> Self {
            let root = tempfile::tempdir().expect("a directory on the internal disk");
            let (backup, delivery) = services(root.path());
            let writer = AuthorisationKeyPair::generate().expect("a writer key");
            backup
                .enrol_writer(writer.key_id(), archive_id(), at(0))
                .expect("the writer is enrolled");
            delivery
                .with(|producer| {
                    let journal = producer.journal_mut();
                    journal
                        .register_consumer(&consumer(), 1)
                        .expect("a consumer");
                    journal
                        .configure_destination(&hook())
                        .expect("a destination");
                    Ok(())
                })
                .expect("the delivery journal");
            let privacy =
                EnvironmentPrivacy::open(root.path(), Arc::clone(&backup), Arc::clone(&delivery))
                    .expect("the privacy record");
            Self {
                root,
                writer,
                sender: StoredEnvelopeKeyPair::generate().expect("a producer key"),
                device: StoredEnvelopeKeyPair::generate().expect("a device key"),
                backup,
                delivery,
                privacy,
            }
        }

        /// The same host after a restart: every store opened again, the backup service unready,
        /// and nothing driven yet.
        fn restarted(self) -> Self {
            let Self {
                root,
                writer,
                sender,
                device,
                backup,
                delivery,
                privacy,
            } = self;
            drop(privacy);
            drop(backup);
            drop(delivery);
            let (backup, delivery) = services(root.path());
            let privacy =
                EnvironmentPrivacy::open(root.path(), Arc::clone(&backup), Arc::clone(&delivery))
                    .expect("the privacy record");
            Self {
                root,
                writer,
                sender,
                device,
                backup,
                delivery,
                privacy,
            }
        }

        /// Seals and admits one backup generation with one member object.
        fn admit(&self, generation: u8) -> crate::error::Result<Admitted> {
            let objects = [stage_object(
                &ObjectSource {
                    object_id: BackupObjectId::new(Uuid::from_bytes([generation; 16])),
                    filename: "history.cbor",
                    plaintext: b"what a session said",
                },
                KeyRotation::INITIAL,
            )
            .expect("a staged object")];
            let mut recipients = ArchiveRecipients::new(CollectionKind::Owned);
            assert!(recipients.add(*self.device.public()));
            let sealed = seal_archive(
                &self.writer,
                &self.sender,
                &recipients,
                &ArchivePlan {
                    archive_id: archive_id(),
                    backup_generation: BackupGeneration::new(u64::from(generation)),
                    owner_device_id: DeviceId::new(Uuid::from_bytes([0x33; 16])),
                    manifest_object_id: BackupObjectId::new(Uuid::from_bytes(
                        [0x80 + generation; 16],
                    )),
                    created_at_ms: at(0),
                },
                &objects,
            )
            .expect("a sealed archive");
            self.backup
                .admit(&sealed, &objects, self.writer.key_id(), at(0))
        }

        /// The staged ciphertext of one generation.
        fn staged(&self, generation: u8) -> Vec<std::path::PathBuf> {
            self.backup
                .objects(archive_id(), BackupGeneration::new(u64::from(generation)))
                .expect("a read")
                .into_iter()
                .map(|row| row.staged_path)
                .collect()
        }

        /// Admits one delivery to the webhook and claims it, so it is on the wire.
        fn delivery_on_the_wire(&self, byte: u8) -> NotificationId {
            let event = Uuid::from_bytes([byte; 16]);
            let notification_id = NotificationId::new(Uuid::from_bytes([byte + 100; 16]));
            self.delivery
                .with(|producer| {
                    let journal = producer.journal_mut();
                    journal
                        .take_events(
                            &consumer(),
                            &[TakenEvent {
                                key: EventKey::outbox(&event),
                                source_cursor: u64::from(byte),
                                session_id: None,
                                recorded_at_ms: at(0),
                                notice: Vec::new(),
                            }],
                            u64::from(byte),
                        )
                        .expect("a page");
                    journal
                        .admit(&DeliveryRecord {
                            notification_id,
                            event: EventKey::outbox(&event),
                            destination_id: DestinationId::new("hook").expect("an identifier"),
                            state: DeliveryState::Admitted,
                            privacy_generation: 0,
                            destination_digest: hook().binding_digest(),
                            authority_digest: String::new(),
                            content: Some(vec![b'x'; 100]),
                            payload_bytes: 100,
                            expires_at_ms: at(3_600_000),
                            admitted_at_ms: at(0),
                            attempts: 0,
                            suppression: None,
                            detail: None,
                            dispatched: false,
                        })
                        .expect("admitted");
                    assert!(matches!(
                        journal.claim(notification_id, NOW).expect("a claim"),
                        Claim::Taken(_)
                    ));
                    Ok(())
                })
                .expect("the delivery journal");
            notification_id
        }

        /// The answer to a delivery that was on the wire arrives.
        fn delivery_answered(&self, notification_id: NotificationId) {
            self.delivery
                .with(|producer| {
                    producer
                        .journal_mut()
                        .record_attempt(&Transition {
                            notification_id,
                            attempt: 1,
                            state: DeliveryState::Accepted,
                            started_at_ms: at(0),
                            settled_at_ms: Some(at(50)),
                            next_attempt_at_ms: None,
                            next: kr_delivery::push::NextAction::None,
                            detail: Some("the destination took it".to_owned()),
                            suppression: None,
                            left_this_host: false,
                            reported_by_destination: false,
                        })
                        .expect("a transition");
                    Ok(())
                })
                .expect("the delivery journal");
        }

        fn delivery_is_fenced(&self) -> bool {
            self.delivery
                .with(|producer| Ok(producer.journal().is_fenced().expect("a read")))
                .expect("the delivery journal")
        }
    }

    /// How much one subsystem has outstanding, as a report says.
    fn outstanding(report: &Report, name: &str) -> u64 {
        match &report.completion {
            Completion::Complete => 0,
            Completion::Reconciling { outstanding }
            | Completion::Unavailable { outstanding, .. } => outstanding
                .iter()
                .filter(|(subsystem, _)| *subsystem == name)
                .map(|(_, count)| count)
                .sum(),
        }
    }

    /// Why one subsystem cannot answer, as a report says.
    fn unavailable(report: &Report, name: &str) -> Vec<String> {
        match &report.completion {
            Completion::Unavailable { unavailable, .. } => unavailable
                .iter()
                .filter(|(subsystem, _)| *subsystem == name)
                .map(|(_, reason)| reason.reason().to_owned())
                .collect(),
            _ => Vec::new(),
        }
    }

    /// KR-REQ-24.27: the record comes first, and a record this environment cannot write is a
    /// privacy mode it does not claim to be in: nothing is fenced, cancelled or removed.
    #[test]
    fn the_record_is_written_first_and_one_that_cannot_be_written_touches_nothing() {
        let host = Host::open();
        let admitted = host.admit(1).expect("admitted");
        let refuse = Connection::open(host.root.path().join(PRIVACY_RECORD)).expect("the record");
        refuse
            .execute_batch(
                "CREATE TRIGGER refuse_the_record BEFORE UPDATE ON privacy_record
                 BEGIN SELECT RAISE(ABORT, 'this store refused the record'); END;",
            )
            .expect("the record will be refused");

        let refused = host
            .privacy
            .enable(&[session(1)], at(10))
            .expect_err("a privacy mode this environment cannot write down");
        assert!(
            refused.to_string().contains("refused the record"),
            "{refused}"
        );
        assert!(!host.privacy.state().is_private());
        assert_eq!(host.backup.fenced_at().expect("a read"), None);
        assert!(!host.delivery_is_fenced());
        assert!(
            host.backup
                .outbox()
                .expect("a read")
                .iter()
                .any(|attempt| attempt.sequence == admitted.sequence
                    && attempt.status == AttemptStatus::Queued),
            "the queued work was not taken back for a privacy mode that was never recorded"
        );
        assert!(host.privacy.report_now(at(10)).obligations.is_empty());

        refuse
            .execute_batch("DROP TRIGGER refuse_the_record")
            .expect("the record is accepted again");
        let report = host
            .privacy
            .enable(&[session(1)], at(20))
            .expect("privacy mode is enabled");
        assert!(report.enabled);
        assert_eq!(report.generation, PrivacyGeneration::new(1));
        assert!(host.privacy.state().is_private());
        assert!(!host.privacy.state().may_send_content());
        let (generation, enabled): (i64, i64) = refuse
            .query_row(
                "SELECT generation, enabled FROM privacy_record WHERE id = 0",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("the record");
        assert_eq!((generation, enabled), (1, 1));
        assert_eq!(host.backup.fenced_at().expect("a read"), Some(1));
        assert!(host.delivery_is_fenced());
    }

    /// KR-REQ-24.28: privacy mode enabled while a backup upload and a delivery are both on their
    /// way reports reconciling, and never complete, until the evidence about each arrives.
    #[test]
    fn enabled_with_a_backup_upload_and_a_delivery_in_flight_it_reconciles_until_each_settles() {
        let host = Host::open();
        let admitted = host.admit(1).expect("admitted");
        host.backup
            .note_dispatched(admitted.sequence, EXECUTOR, at(1))
            .expect("the upload is on its way");
        let delivery = host.delivery_on_the_wire(7);
        let staged = host.staged(1);

        let report = host
            .privacy
            .enable(&[], at(10))
            .expect("privacy mode is enabled");
        assert!(!report.completion.is_complete());
        assert!(
            outstanding(&report, "backup") > 0,
            "{:?}",
            report.completion
        );
        assert_eq!(outstanding(&report, "delivery"), 1);
        for path in &staged {
            assert!(!path.exists(), "the staged ciphertext is removed at once");
        }

        // The delivery's answer arrives. The upload is still out there.
        host.delivery_answered(delivery);
        let report = host.privacy.tick(at(20));
        assert_eq!(outstanding(&report, "delivery"), 0);
        assert!(!report.completion.is_complete(), "{:?}", report.completion);

        // The transport that held the upload says it stopped without an answer. That attempt is
        // over, and what it carried is a copy that may be at a service, which is shown.
        host.backup
            .note_attempt_stopped(admitted.sequence, at(30))
            .expect("the attempt stopped");
        let report = host.privacy.tick(at(40));
        assert!(report.completion.is_complete(), "{:?}", report.completion);
        assert!(
            report
                .exported
                .iter()
                .any(|copy| copy.kind.starts_with("backup archive") && !copy.deletable),
            "{:?}",
            report.exported
        );
        assert!(
            report
                .exported
                .iter()
                .any(|copy| copy.kind.contains("webhook") && !copy.deletable),
            "{:?}",
            report.exported
        );
    }

    /// KR-REQ-24.27: a restart between the record and the removal finishes the removal. The
    /// record is read before anything is driven, and `resume` fences and removes before the
    /// backup service reconciles, so nothing an earlier process left is resumed.
    #[test]
    fn a_restart_between_the_record_and_the_removal_finishes_the_removal() {
        let host = Host::open();
        host.admit(1).expect("admitted");
        let staged = host.staged(1);
        host.backup
            .set_query_only(true)
            .expect("the store refuses writes");
        let report = host
            .privacy
            .enable(&[], at(10))
            .expect("the record is written");
        let reasons = unavailable(&report, "backup");
        assert!(
            reasons
                .iter()
                .any(|reason| reason.contains("could not be raised")),
            "{reasons:?}"
        );
        assert!(host.privacy.state().is_private());
        for path in &staged {
            assert!(
                path.exists(),
                "nothing was removed behind a fence that did not go up"
            );
        }

        let host = host.restarted();
        assert!(
            host.privacy.state().is_private(),
            "the record is read before anything runs"
        );
        assert_eq!(host.backup.fenced_at().expect("a read"), None);
        let report = host.privacy.resume(at(100));
        assert_eq!(host.backup.fenced_at().expect("a read"), Some(1));
        for path in &staged {
            assert!(
                !path.exists(),
                "the removal the restart interrupted is finished"
            );
        }
        host.backup
            .reconcile(at(110))
            .expect("the startup reconciliation");
        assert!(
            host.backup
                .outbox()
                .expect("a read")
                .iter()
                .all(|attempt| attempt.status != AttemptStatus::Queued),
            "nothing is resumed under the fence"
        );
        assert!(report.completion.is_complete(), "{:?}", report.completion);
        assert!(
            host.admit(2).is_err(),
            "nothing is admitted while the fence holds"
        );
    }

    /// KR-REQ-24.28: a result that comes back for work admitted before the boundary is recorded as
    /// what it is and never becomes this host's; one that claims the new generation is refused.
    #[test]
    fn a_late_result_of_the_old_generation_is_refused() {
        let host = Host::open();
        let admitted = host.admit(1).expect("admitted");
        host.backup
            .note_dispatched(admitted.sequence, EXECUTOR, at(1))
            .expect("the upload is on its way");
        for row in host
            .backup
            .objects(archive_id(), BackupGeneration::new(1))
            .expect("a read")
        {
            host.backup
                .note_object_uploaded(
                    admitted.sequence,
                    archive_id(),
                    BackupGeneration::new(1),
                    row.object_id,
                    at(2),
                )
                .expect("the object arrived");
        }
        host.backup
            .note_attempt_accepted(admitted.sequence, at(3))
            .expect("the upload finished");
        let publication = host
            .backup
            .outbox()
            .expect("a read")
            .into_iter()
            .find(|attempt| attempt.step == Step::Publish)
            .expect("a publication attempt")
            .sequence;
        host.backup
            .note_dispatched(publication, EXECUTOR, at(4))
            .expect("the publication is on its way");

        let report = host
            .privacy
            .enable(&[], at(10))
            .expect("privacy mode is enabled");
        assert!(!report.completion.is_complete());
        let state = host.privacy.state();
        assert!(!state.accepts_result(PrivacyGeneration::INITIAL));
        assert!(state.accepts_result(PrivacyGeneration::new(1)));

        // A caller that relabels the answer with the generation in force is refused: the
        // generation the work was admitted under is the store's.
        assert!(
            host.backup
                .note_published(publication, PrivacyGeneration::new(1), at(20))
                .is_err()
        );
        assert_eq!(
            host.backup
                .note_published(publication, PrivacyGeneration::INITIAL, at(20))
                .expect("the late answer is recorded"),
            Publication::RetainedArtifact {
                privacy_generation: 0
            }
        );
        let report = host.privacy.tick(at(30));
        assert!(report.completion.is_complete(), "{:?}", report.completion);
        assert!(
            report
                .exported
                .iter()
                .any(|copy| copy.kind == "backup archive" && !copy.deletable),
            "the archive the service holds is shown: {:?}",
            report.exported
        );
    }

    /// Settlement comes only from evidence about the named attempt. A restart is not evidence,
    /// and neither is an object's acknowledgement: only the transport saying that attempt ended.
    #[test]
    fn a_restart_or_an_object_acknowledgement_is_not_evidence_about_an_attempt() {
        let host = Host::open();
        let admitted = host.admit(1).expect("admitted");
        host.backup
            .note_dispatched(admitted.sequence, EXECUTOR, at(1))
            .expect("the upload is on its way");
        let report = host
            .privacy
            .enable(&[], at(10))
            .expect("privacy mode is enabled");
        assert!(outstanding(&report, "backup") > 0);

        let host = host.restarted();
        host.privacy.resume(at(100));
        host.backup
            .reconcile(at(110))
            .expect("the startup reconciliation");
        let report = host.privacy.tick(at(120));
        assert!(
            outstanding(&report, "backup") > 0,
            "a restart says nothing about the upload"
        );

        for row in host
            .backup
            .objects(archive_id(), BackupGeneration::new(1))
            .expect("a read")
        {
            host.backup
                .note_object_uploaded(
                    admitted.sequence,
                    archive_id(),
                    BackupGeneration::new(1),
                    row.object_id,
                    at(130),
                )
                .expect("the object arrived");
        }
        let report = host.privacy.tick(at(2_000));
        assert!(
            outstanding(&report, "backup") > 0,
            "an object arriving does not end the attempt that carried it"
        );

        host.backup
            .note_attempt_accepted(admitted.sequence, at(2_100))
            .expect("the transport says the upload finished");
        let report = host.privacy.tick(at(4_000));
        assert!(report.completion.is_complete(), "{:?}", report.completion);
    }

    /// A step a store refused is owed, with its reason, and tried again on its schedule, not
    /// before. Once it succeeds the backup service is reconciled again: here that is what makes a
    /// service that opened unready ready.
    #[test]
    fn a_refused_step_is_retried_on_its_schedule_and_the_backup_is_reconciled_after_it() {
        let host = Host::unreconciled();
        host.backup
            .set_query_only(true)
            .expect("the store refuses writes");
        let report = host
            .privacy
            .enable(&[], at(0))
            .expect("the record is written");
        assert!(!unavailable(&report, "backup").is_empty());
        assert!(host.backup.unready().is_some());

        host.backup
            .set_query_only(false)
            .expect("the store accepts writes");
        let report = host.privacy.tick(at(500));
        assert!(
            !unavailable(&report, "backup").is_empty(),
            "the retry waits for its turn"
        );
        let report = host.privacy.tick(at(1_000));
        assert!(report.completion.is_complete(), "{:?}", report.completion);
        assert_eq!(host.backup.fenced_at().expect("a read"), Some(1));
        assert_eq!(
            host.backup.unready(),
            None,
            "the service was reconciled once its step succeeded"
        );
    }

    /// Disabling is refused while the backup service still owes cleanup, a target it could not
    /// remove is retried on its schedule, and once nothing is owed every fence is released.
    #[cfg(unix)]
    #[test]
    fn disabling_is_refused_while_cleanup_is_owed_and_a_briefly_unavailable_target_is_retried() {
        use std::os::unix::fs::PermissionsExt as _;
        let set_writable = |directory: &Path, writable: bool| {
            let mode = if writable { 0o755 } else { 0o555 };
            std::fs::set_permissions(directory, std::fs::Permissions::from_mode(mode))
                .expect("permissions");
        };
        let host = Host::open();
        host.admit(1).expect("admitted");
        let staged = host.staged(1);
        let directory = staged[0].parent().expect("a directory").to_path_buf();
        set_writable(&directory, false);

        let report = host
            .privacy
            .enable(&[], at(0))
            .expect("privacy mode is enabled");
        assert!(
            outstanding(&report, "backup") > 0,
            "{:?}",
            report.completion
        );
        let refused = host.privacy.disable(at(10)).expect_err("cleanup is owed");
        assert!(refused.to_string().contains("unfinished"), "{refused}");
        assert!(host.privacy.state().is_private());

        // The first pass finds the target still unavailable, and the next waits its turn.
        let report = host.privacy.tick(at(20));
        assert!(outstanding(&report, "backup") > 0);
        set_writable(&directory, true);
        let report = host.privacy.tick(at(500));
        assert!(outstanding(&report, "backup") > 0, "not before its turn");
        let report = host.privacy.tick(at(1_020));
        assert!(report.completion.is_complete(), "{:?}", report.completion);
        for path in &staged {
            assert!(!path.exists());
        }

        let report = host
            .privacy
            .disable(at(2_000))
            .expect("nothing is owed now");
        assert!(!report.enabled);
        assert_eq!(report.generation, PrivacyGeneration::new(2));
        assert!(report.completion.is_complete(), "{:?}", report.completion);
        assert!(host.privacy.state().may_send_content());
        assert_eq!(host.backup.fenced_at().expect("a read"), None);
        assert!(!host.delivery_is_fenced());
        let admitted = host.admit(2).expect("backup production starts again");
        assert_eq!(admitted.privacy_generation, 2);
    }

    /// A release the store refused is owed and retried: privacy mode is off, but it is still
    /// being turned off, and backup production stays fenced until the release lands.
    #[test]
    fn a_release_the_store_refused_is_owed_and_production_stays_fenced_until_it_lands() {
        let host = Host::open();
        let report = host
            .privacy
            .enable(&[], at(0))
            .expect("privacy mode is enabled");
        assert!(report.completion.is_complete(), "{:?}", report.completion);
        host.backup
            .set_query_only(true)
            .expect("the store refuses writes");
        let report = host.privacy.disable(at(10)).expect("the record is written");
        assert!(!report.enabled);
        assert!(
            unavailable(&report, "backup")
                .iter()
                .any(|reason| reason.contains("could not be released")),
            "{:?}",
            report.completion
        );
        assert_eq!(host.backup.fenced_at().expect("a read"), Some(1));

        host.backup
            .set_query_only(false)
            .expect("the store accepts writes");
        let report = host.privacy.tick(at(500));
        assert!(!report.completion.is_complete(), "not before its turn");
        let report = host.privacy.tick(at(1_010));
        assert!(report.completion.is_complete(), "{:?}", report.completion);
        assert_eq!(host.backup.fenced_at().expect("a read"), None);
    }

    /// Each live session is told the generation until its worker says its cleanup is complete,
    /// which is what ends its obligation, durably. Disabling waits for a live session and not for
    /// one whose worker has ended; that obligation stays through the disabling, a restart and a
    /// later enabling, and keeps the report from saying complete.
    #[test]
    fn sessions_are_told_until_complete_and_an_ended_one_keeps_its_obligation() {
        let host = Host::open();
        let report = host
            .privacy
            .enable(&[session(1), session(2)], at(0))
            .expect("privacy mode is enabled");
        assert_eq!(report.obligations.len(), 2);
        assert_eq!(outstanding(&report, "sessions"), 2);
        host.privacy.note_session_live(session(1));
        host.privacy.note_session_live(session(2));
        let notices = host.privacy.notices_due(at(10));
        assert_eq!(notices.len(), 2);
        assert!(
            notices
                .iter()
                .all(|notice| notice.generation == PrivacyGeneration::new(1) && notice.enabled)
        );
        assert!(
            host.privacy.notices_due(at(20)).is_empty(),
            "a notice is repeated on its schedule"
        );

        // One worker says its cleanup is still going, then that it is complete.
        host.privacy
            .note_answer(
                session(1),
                PrivacyGeneration::new(1),
                true,
                Completion::Reconciling {
                    outstanding: vec![("attention", 1)],
                },
            )
            .expect("an answer");
        assert_eq!(host.privacy.notices_due(at(1_010)).len(), 2);
        host.privacy
            .note_answer(
                session(1),
                PrivacyGeneration::new(1),
                true,
                Completion::Complete,
            )
            .expect("an answer");
        let report = host.privacy.report_now(at(1_020));
        assert_eq!(report.obligations.len(), 1);
        assert_eq!(report.obligations[0].session_id, session(2));

        // The other session's worker is live and has not said: privacy mode stays on.
        let refused = host
            .privacy
            .disable(at(1_030))
            .expect_err("a live session still owes");
        assert!(refused.to_string().contains("has not said"), "{refused}");

        // Its worker ends. Nothing resumes in its store, so disabling goes ahead, and its
        // obligation stays and keeps the report from saying complete.
        host.privacy.note_session_ended(session(2));
        let report = host
            .privacy
            .disable(at(1_040))
            .expect("an ended session does not hold privacy mode on");
        assert!(!report.enabled);
        assert_eq!(report.obligations.len(), 1);
        assert_eq!(report.obligations[0].standing, Standing::WorkerEnded);
        assert!(!unavailable(&report, "sessions").is_empty());
        assert_eq!(
            host.backup.fenced_at().expect("a read"),
            None,
            "the releases landed"
        );
        assert_eq!(
            outstanding(&report, "sessions"),
            1,
            "the live session has not said it holds the new generation"
        );
        let notices = host.privacy.notices_due(at(2_000));
        assert_eq!(
            notices,
            vec![Notice {
                session_id: session(1),
                generation: PrivacyGeneration::new(2),
                enabled: false,
            }]
        );
        host.privacy
            .note_answer(
                session(1),
                PrivacyGeneration::new(2),
                false,
                Completion::Complete,
            )
            .expect("an answer");
        let report = host.privacy.report_now(at(2_010));
        assert_eq!(outstanding(&report, "sessions"), 0);
        assert!(!report.completion.is_complete());

        // A restart and a later enabling keep it.
        let host = host.restarted();
        host.privacy.resume(at(3_000));
        let report = host
            .privacy
            .enable(&[], at(3_010))
            .expect("privacy mode is enabled again");
        assert_eq!(report.generation, PrivacyGeneration::new(3));
        assert_eq!(report.obligations.len(), 1);
        assert_eq!(report.obligations[0].session_id, session(2));
        assert_eq!(report.obligations[0].generation, PrivacyGeneration::new(1));
        assert!(!report.completion.is_complete());
    }
}
