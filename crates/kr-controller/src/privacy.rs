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
//! * **Production closes as the row commits.** The backup service's fence is raised at once,
//!   before anything can wait, and then [`PrivacyState`] is published: descriptions stop answering
//!   generated text, and no delivery content leaves, from that moment rather than from the moment
//!   each subsystem's own fence goes up. A send holds an admission from its check to the end of its
//!   exchange, and publishing waits for every admitted send, so none starts after the state says
//!   private. A fence a store refused therefore leaves nothing able to leave this host while the
//!   fence is retried.
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
//! * **A launch is recorded before its worker runs.** A session created while privacy mode is on
//!   owes its cleanup from the moment its worker is asked for ([`EnvironmentPrivacy::note_session_launching`]),
//!   and its worker is told the state in its launch specification and applies it before its shell
//!   starts. A launch that never produced a worker, as the registry and the daemon's own creates
//!   show, has its obligation discharged ([`EnvironmentPrivacy::discharge_unstarted`]): nothing
//!   ran, so nothing was kept.
//! * **Disabling is two phases.** It is refused while a daemon step, or a session whose worker is
//!   running or may still start, owes cleanup. Otherwise the new generation is recorded first and
//!   then each fence is released; a release that is still pending, or that a store refused, is
//!   owed and retried, and the report says privacy mode is still being turned off until every
//!   release has landed.
//!
//! # The startup order
//!
//! [`EnvironmentPrivacy::open`] reads the record before anything else runs, and publishes the state
//! it holds. [`EnvironmentPrivacy::resume`] then takes every daemon subsystem through the steps the
//! record asks for again. A daemon calls it after opening the backup service, which opens unready,
//! and before reconciling that service, starting delivery or serving any request, so work an
//! earlier process left behind is fenced before anything can resume it.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::str::FromStr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, RwLock};

use kr_delivery::privacy::DeliveryOutbox;
use kr_protocol::ids::SessionId;
use kr_protocol::privacy::{
    PrivacyCompletion, PrivacyGenerationAck, PrivacyOutstanding, PrivacyReport, PrivacySession,
    PrivacySessionStanding, PrivacyUnavailable,
};
use kr_protocol::scalars::{TimestampMs, U64};
use kr_worker::privacy::{
    Completion, Disabled, Enabling, Exported, KeptExplicitly, PrivacyGeneration, PrivacyMode,
    PrivacySubsystem, Unavailable,
};
use rusqlite::{Connection, OptionalExtension, params};

use crate::backup::BackupService;
use crate::backup::store::FenceRelease;
use crate::describe::DescribeModule;
use crate::error::{ControllerError, Result};
use crate::push::DeliveryModule;

/// The file the environment's privacy record lives in.
pub const PRIVACY_RECORD: &str = "privacy.sqlite3";

/// The schema version this build reads and writes.
const SCHEMA_VERSION: i64 = 1;

/// The first wait before a refused step is tried again.
const FIRST_RETRY_MS: u64 = 1_000;

/// Runs one durable write under the admission of the action that asked for it.
///
/// It is called once every wait the write has is behind it, with the write itself: it checks the
/// admission, a deadline and the authority it was given, and holds that authority standing until
/// the write has committed, so a withdrawal is ordered wholly before the check or wholly after
/// the commit. A refusal is returned without running the write. The daemon passes
/// [`crate::service::Controller::under_registration`] over the admission a mutation carried.
pub type Admitted<'a> = &'a dyn Fn(&mut dyn FnMut() -> Result<()>) -> Result<()>;

/// The longest wait between two tries of a refused step.
const LONGEST_RETRY_MS: u64 = 60_000;

/// What the environment's privacy state is, as every reader sees it.
///
/// It is published with the record, before the delivery outbox and the descriptions are driven,
/// and at open, before anything runs. It is cheap to clone and to read.
///
/// It is also the admission every delivery exchange takes: [`Self::admit_send`] is held from the
/// check to the end of the exchange, and a change of state holds the write side from before its
/// record is written until it is published, so taking it waits until every admission taken before
/// it has ended and none is taken in between. An exchange either finished before privacy mode was
/// turned on, and is in flight at that moment, or it is checked against the published boundary.
#[derive(Clone, Debug, Default)]
pub struct PrivacyState {
    published: Arc<RwLock<Published>>,
}

/// An admission to send one delivery or ask one question about a delivery, while privacy mode is
/// off. Holding it keeps privacy mode from being turned on until the exchange has ended, so it is
/// dropped as soon as the exchange ends and never held while waiting for anything else.
#[derive(Debug)]
pub struct SendAdmission<'a> {
    _held: std::sync::RwLockReadGuard<'a, Published>,
}

/// One reading of [`PrivacyState`], held: a change of state waits until it is dropped.
///
/// What is decided under it is decided wholly before a change of privacy mode is published, or
/// wholly after, so it is held from the reading until the decision is made and never while waiting
/// for anything else.
#[derive(Debug)]
pub struct Reading<'a> {
    held: std::sync::RwLockReadGuard<'a, Published>,
}

impl Reading<'_> {
    /// The state this reading holds.
    #[must_use]
    pub fn published(&self) -> Published {
        *self.held
    }
}

/// One reading of [`PrivacyState`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Published {
    /// The generation in force.
    pub generation: PrivacyGeneration,
    /// Whether privacy mode is on.
    pub private: bool,
}

impl Published {
    /// Returns this state as a worker is told it in its launch specification.
    #[must_use]
    pub const fn to_launch(self) -> kr_protocol::worker::PrivacyLaunch {
        kr_protocol::worker::PrivacyLaunch {
            generation: U64::new(self.generation.get()),
            enabled: self.private,
        }
    }
}

impl PrivacyState {
    /// A state that holds `published`, for this crate's own tests of its readers.
    #[cfg(test)]
    pub(crate) fn at(published: Published) -> Self {
        let state = Self::default();
        state.publish(published);
        state
    }

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

    /// Reads the state and holds it, so a change of state waits until the reading is dropped.
    ///
    /// A reader that decides something from the state, such as whether generated text may be
    /// shown, decides it under this rather than from a copy taken earlier: a copy read before a
    /// wait would still say what the state was before a change published during the wait.
    #[must_use]
    pub fn reading(&self) -> Reading<'_> {
        Reading {
            held: self
                .published
                .read()
                .unwrap_or_else(PoisonError::into_inner),
        }
    }

    /// Admits one delivery exchange, a send or a question about one, whose work was admitted under
    /// `admitted_under`: only while privacy mode is off and that generation is the one in force.
    ///
    /// Never while privacy mode is on, whatever any subsystem's own fence says: the state is
    /// published before the delivery outbox is driven, and a fence a store refused is still being
    /// retried. Never for work of an earlier generation either, even once privacy mode is off
    /// again: a notice privacy mode drew a line under is not sent, and nothing is asked about it.
    /// Both are read under the one guard the admission then holds until the exchange ends.
    #[must_use]
    pub fn admit_send(&self, admitted_under: PrivacyGeneration) -> Option<SendAdmission<'_>> {
        let held = self
            .published
            .read()
            .unwrap_or_else(PoisonError::into_inner);
        (!held.private && held.generation == admitted_under)
            .then_some(SendAdmission { _held: held })
    }

    /// Returns whether a result produced under `produced_under` may be published.
    ///
    /// Only the generation in force is accepted: an older one belongs to work privacy mode drew a
    /// line under, and a newer one to no generation this environment has recorded.
    #[must_use]
    pub fn accepts_result(&self, produced_under: PrivacyGeneration) -> bool {
        self.now().generation == produced_under
    }

    /// Takes the write side for a change of state: it waits for every admission taken before it
    /// to end, and while the change is held nothing is admitted and nothing is read.
    ///
    /// It is taken only by a thread that holds the record's own mutex ([`EnvironmentPrivacy`]'s
    /// `inner`), once [`EnvironmentPrivacy::open`] has published the state it starts with, and
    /// nothing that holds a reader's guard takes that mutex. That is what keeps the queue of a
    /// read-write lock, in which a waiting writer stops new readers, from turning a reader that
    /// waits for something a writer holds into a stall; a new taker of this side goes under the
    /// same rule.
    fn change(&self) -> Change<'_> {
        Change {
            held: self
                .published
                .write()
                .unwrap_or_else(PoisonError::into_inner),
        }
    }

    fn publish(&self, published: Published) {
        self.change().publish(published);
    }
}

/// A change of [`PrivacyState`] in progress: the write side, held until the change is published
/// or given up.
struct Change<'a> {
    held: std::sync::RwLockWriteGuard<'a, Published>,
}

impl Change<'_> {
    /// Publishes the new state, which ends the change.
    fn publish(mut self, published: Published) {
        *self.held = published;
    }
}

/// The daemon subsystems this module drives.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Subsystem {
    Backup,
    Delivery,
    Descriptions,
}

impl Subsystem {
    const ALL: [Self; 3] = [Self::Backup, Self::Delivery, Self::Descriptions];

    const fn name(self) -> &'static str {
        match self {
            Self::Backup => crate::backup::SUBSYSTEM_NAME,
            Self::Delivery => "delivery",
            Self::Descriptions => "descriptions",
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
    /// The enabling's steps, taken again from the fence on; this is the step that stopped them.
    Steps(kr_worker::privacy::Step),
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
    /// A worker has been asked for and has not yet been found running: its launch is under way,
    /// and what it owes is recorded, but there is nobody to tell yet.
    Launching,
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
    completion: PrivacyCompletion,
}

impl Answer {
    /// Whether its worker said its cleanup is complete.
    const fn is_complete(&self) -> bool {
        matches!(self.completion, PrivacyCompletion::Complete)
    }
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

impl Report {
    /// The report as `privacy.set` and `privacy.status` answer it.
    #[must_use]
    pub fn to_wire(&self) -> PrivacyReport {
        PrivacyReport {
            generation: U64::new(self.generation.get()),
            enabled: self.enabled,
            changed_at_ms: self.changed_at_ms,
            completion: (&self.completion).into(),
            sessions: self
                .obligations
                .iter()
                .map(|obligation| PrivacySession {
                    session_id: obligation.session_id,
                    generation: U64::new(obligation.generation.get()),
                    standing: match &obligation.standing {
                        Standing::AwaitingWorker => PrivacySessionStanding::AwaitingWorker,
                        Standing::Reconciling { outstanding } => {
                            PrivacySessionStanding::Reconciling {
                                outstanding: U64::new(*outstanding),
                            }
                        }
                        Standing::Unavailable { reason } => PrivacySessionStanding::Unavailable {
                            reason: reason.clone(),
                        },
                        Standing::WorkerEnded => PrivacySessionStanding::WorkerEnded,
                    },
                })
                .collect(),
            disabled: self
                .disabled
                .iter()
                .map(|disabled| (*disabled).into())
                .collect(),
            kept: self.kept.iter().map(Into::into).collect(),
            exported: self.exported.iter().map(Into::into).collect(),
            unlisted: self
                .unlisted
                .iter()
                .map(|(subsystem, unavailable)| PrivacyUnavailable {
                    subsystem: (*subsystem).to_owned(),
                    reason: unavailable.reason().to_owned(),
                })
                .collect(),
        }
    }
}

/// The environment's privacy record, and its composition root.
#[derive(Debug)]
pub struct EnvironmentPrivacy {
    inner: Mutex<Inner>,
    state: PrivacyState,
    backup: Arc<BackupService>,
    delivery: Arc<DeliveryModule>,
    descriptions: Arc<DescribeModule>,
    /// Where this module's own tests stop an enabling: its record written, inside the backup
    /// store's hold, before the backup fence goes up.
    #[cfg(test)]
    after_record: crate::attention::Pause,
    /// Where this crate's own tests stop an enabling: holding the record's own mutex, about to
    /// take the state's write side, so every wait it has after that is still ahead of it.
    #[cfg(test)]
    pub(crate) before_change: crate::attention::Pause,
}

#[derive(Debug)]
struct Inner {
    record: Record,
    mode: PrivacyMode,
    changed_at_ms: TimestampMs,
    owed: BTreeMap<Subsystem, Owed>,
    cleanup: Backoff,
    obligations: BTreeMap<SessionId, PrivacyGeneration>,
    /// Obligations held here whose durable write failed, with the store's reason, until a retry
    /// writes them.
    unrecorded: BTreeMap<SessionId, Unavailable>,
    sessions: BTreeMap<SessionId, SessionProgress>,
}

impl EnvironmentPrivacy {
    /// Opens the environment's privacy record in `state_dir` and publishes the state it holds.
    ///
    /// The state is published into the delivery module's own ([`DeliveryModule::privacy_state`]),
    /// which every exchange with a destination is admitted under, so the send gate is this record
    /// from the moment it is open. Nothing is driven here: [`Self::resume`] is what takes the
    /// subsystems through the steps the record asks for.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the record cannot be opened or read.
    /// A daemon that cannot read whether privacy mode is on does not start as though it knew.
    pub fn open(
        state_dir: &Path,
        backup: Arc<BackupService>,
        delivery: Arc<DeliveryModule>,
        descriptions: Arc<DescribeModule>,
    ) -> Result<Self> {
        let record = Record::open(state_dir)?;
        let stored = record.read()?;
        let obligations = record.obligations()?;
        let state = delivery.privacy_state().clone();
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
                unrecorded: BTreeMap::new(),
                sessions: BTreeMap::new(),
            }),
            state,
            backup,
            delivery,
            descriptions,
            #[cfg(test)]
            after_record: crate::attention::Pause::default(),
            #[cfg(test)]
            before_change: crate::attention::Pause::default(),
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
    /// `admitted` runs the record's write under the admission the change was asked under: it is
    /// called once the record's own transaction is held, after every wait, checks the admission and
    /// holds it standing until the write has committed. An admission that has lapsed by then, its
    /// deadline passed or its authority withdrawn, changes nothing, and one withdrawn afterwards is
    /// ordered after the commit.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the record cannot be written, and
    /// what `admitted` returns when it refuses. Nothing has been fenced or removed then: a privacy
    /// mode this environment cannot write down is one it must not claim to be in.
    pub fn enable(
        &self,
        sessions: &[SessionId],
        now_ms: TimestampMs,
        admitted: Admitted<'_>,
    ) -> Result<Report> {
        let mut inner = self.inner();
        if inner.mode.is_enabled() {
            return Ok(self.report(&inner, now_ms));
        }
        let mut mode = inner.mode;
        let generation = mode.open_generation(now_ms);
        // Every session this environment holds content for owes its cleanup, and so does every
        // session whose worker is running now or is on its way, whether or not the caller named
        // it: a launch that has been asked for has no journal yet for the caller to find.
        let mut owing: Vec<SessionId> = sessions.to_vec();
        owing.extend(
            inner
                .sessions
                .iter()
                .filter(|(_, progress)| matches!(progress.reach, Reach::Live | Reach::Launching))
                .map(|(session_id, _)| *session_id),
        );
        owing.sort_unstable();
        owing.dedup();
        #[cfg(test)]
        self.before_change.wait();
        // The state's write side is taken before the record is written and held until the new
        // state is published. Taking it waits for every delivery exchange already admitted, and
        // holding it admits none, so a send checked under the generation before the boundary has
        // either ended before the record or is checked against the published boundary: none passes
        // between the two. A record that fails gives the change up with nothing published.
        let change = self.state.change();
        // The record and the backup fence are one step for backup production: both happen inside
        // one hold of the backup store, which every backup production decision takes, so none is
        // decided after the boundary is recorded and before the backup service stops at it. A
        // record that fails changes nothing there; a fence that fails leaves the readiness guard
        // withholding production, and the steps below try it again.
        let record = &mut inner.record;
        let _raised = self.backup.raise_fence_recorded(generation, now_ms, || {
            let recorded = record.enable(generation, &owing, now_ms, admitted);
            #[cfg(test)]
            if recorded.is_ok() {
                self.after_record.wait();
            }
            recorded
        })?;
        inner.mode = mode;
        inner.changed_at_ms = now_ms;
        change.publish(Published {
            generation,
            private: true,
        });
        // An enabling supersedes whatever an earlier disabling still owed: the fences it would
        // have released are raised again at the new generation, and the next disabling releases
        // every fence that stands.
        inner.owed.clear();
        inner.cleanup = Backoff::default();
        for session_id in owing {
            inner.obligations.insert(session_id, generation);
        }
        for progress in inner.sessions.values_mut() {
            progress.notices = Backoff::default();
        }
        self.apply(&mut inner, &Subsystem::ALL, now_ms);
        Ok(self.report(&inner, now_ms))
    }

    /// Turns privacy mode off.
    ///
    /// Refused while a daemon subsystem, or a session whose worker is running or may still start,
    /// owes cleanup: resuming retention beside an unfinished purge would mix new content into what
    /// is still being removed. A session whose worker has ended, which is one the registry shows
    /// its launch to be over for ([`Self::sessions_seen`]), does not hold it back, because nothing
    /// resumes in its store; its obligation stays recorded and reported. Otherwise the next
    /// generation is recorded first and every fence is then released. Privacy mode already off is
    /// answered with where it stands.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::Refused`], with
    /// [`kr_protocol::error::ErrorCode::ResourceUnavailable`], while cleanup is owed, naming what
    /// is owed, [`ControllerError::RegistryUnavailable`] when the record cannot be written, and
    /// what `admitted` returns when it refuses; it runs the record's write as [`Self::enable`]'s
    /// does.
    pub fn disable(&self, now_ms: TimestampMs, admitted: Admitted<'_>) -> Result<Report> {
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
        inner.record.disable(resumed.generation, now_ms, admitted)?;
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
        // An obligation held here whose write failed is written again, whatever else is owed. One
        // that fails again stays owed with the store's new reason, which the report carries.
        let unrecorded: Vec<SessionId> = inner.unrecorded.keys().copied().collect();
        for session_id in unrecorded {
            let Some(generation) = inner.obligations.get(&session_id).copied() else {
                inner.unrecorded.remove(&session_id);
                continue;
            };
            let _kept_owed = write_obligation(&mut inner, session_id, generation, now_ms);
        }
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

    /// Answers `privacy.set`: turns privacy mode on or off and says where the change stands.
    ///
    /// `sessions` are the sessions the environment holds content for, each of which owes its own
    /// cleanup when privacy mode is turned on ([`Self::enable`]); turning it off is refused while
    /// cleanup is owed ([`Self::disable`]). `admitted` runs the change's write, as it does for
    /// each of them. Asking for the state already in force changes nothing.
    ///
    /// # Errors
    ///
    /// As [`Self::enable`] and [`Self::disable`].
    pub fn set(
        &self,
        enabled: bool,
        sessions: &[SessionId],
        now_ms: TimestampMs,
        admitted: Admitted<'_>,
    ) -> Result<PrivacyReport> {
        let report = if enabled {
            self.enable(sessions, now_ms, admitted)?
        } else {
            self.disable(now_ms, admitted)?
        };
        Ok(report.to_wire())
    }

    /// Answers `privacy.status`: where privacy mode stands, without retrying anything.
    #[must_use]
    pub fn status(&self, now_ms: TimestampMs) -> PrivacyReport {
        self.report_now(now_ms).to_wire()
    }

    /// Says where privacy mode stands, without retrying anything.
    #[must_use]
    pub fn report_now(&self, now_ms: TimestampMs) -> Report {
        let inner = self.inner();
        self.report(&inner, now_ms)
    }

    /// Records that a session's worker is running, so it is told the generation in force.
    ///
    /// While privacy mode is on, a session that joins owes its cleanup like every other, durably,
    /// until its worker says the generation in force is applied and its cleanup complete: nothing
    /// is known about what it retained before it was told. A session created while privacy mode is
    /// on already has its obligation by now ([`Self::note_session_launching`]); this finds it there,
    /// and is what writes it for a worker this daemon meets without having launched it.
    ///
    /// Success says the session owes nothing or its obligation is on the disk.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when its obligation cannot be written, by
    /// this call or by an earlier one whose write failed and which this call tries again. It is
    /// still told the generation, and privacy mode is not turned off while it has not answered.
    pub fn note_session_live(&self, session_id: SessionId, now_ms: TimestampMs) -> Result<()> {
        let mut inner = self.inner();
        let generation = inner.mode.generation();
        let enabled = inner.mode.is_enabled();
        let progress = inner.sessions.entry(session_id).or_default();
        progress.reach = Reach::Live;
        let settled = progress.answer.as_ref().is_some_and(|answer| {
            answer.generation == generation && answer.enabled && answer.is_complete()
        });
        if enabled && !settled && !inner.obligations.contains_key(&session_id) {
            // Held here first, so a write that fails still keeps the session owed: it counts
            // against completion and disabling, with the store's reason, until a write lands.
            inner.obligations.insert(session_id, generation);
            return write_obligation(&mut inner, session_id, generation, now_ms);
        }
        // One held here from an earlier call whose write failed is written now: this call does not
        // say the session is recorded while it is not.
        if inner.unrecorded.contains_key(&session_id)
            && let Some(owed) = inner.obligations.get(&session_id).copied()
        {
            return write_obligation(&mut inner, session_id, owed, now_ms);
        }
        Ok(())
    }

    /// Records that a session's worker has been asked for, before it is launched.
    ///
    /// While privacy mode is on, the session owes its cleanup from this moment, durably, because
    /// its worker is told the privacy state when it is launched and applies it before its shell
    /// runs, and turning privacy mode off must wait for it from then. Privacy mode being off, the
    /// session owes nothing yet, and a change that turns it on while the launch is under way finds
    /// the session here and obliges it ([`Self::enable`]). Nothing is told to a worker that does not
    /// exist: the session is told the generation once it is running ([`Self::note_session_live`]).
    ///
    /// The launch waits here for everything that holds the record, a change of privacy mode among
    /// it, and records the state that change left. Success says the session owes nothing or its
    /// obligation is on the disk, and a session created while privacy mode is on is launched only
    /// once it has succeeded. A write that fails leaves nothing held: no worker will come of a
    /// launch that is refused, so nothing is owed for it.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when its obligation cannot be written.
    pub fn note_session_launching(&self, session_id: SessionId, now_ms: TimestampMs) -> Result<()> {
        let mut inner = self.inner();
        if inner.mode.is_enabled() && !inner.obligations.contains_key(&session_id) {
            let generation = inner.mode.generation();
            inner.record.oblige(session_id, generation, now_ms)?;
            inner.obligations.insert(session_id, generation);
        }
        let progress = inner.sessions.entry(session_id).or_default();
        // A session that is already running, or whose worker has ended, is not taken back.
        if progress.reach == Reach::Unknown {
            progress.reach = Reach::Launching;
        }
        Ok(())
    }

    /// Forgets the sessions whose launches the daemon shows never produced a worker, with their
    /// obligations.
    ///
    /// A launch that failed or was fenced before its worker claimed its reservation, whose launcher
    /// has ended, or whose create returned without recording one, was never given a launch
    /// specification, so no shell ran and nothing was retained: what its obligation recorded is not
    /// owed, and an obligation kept for it would be reported for good as the archive's. Each
    /// obligation is deleted from the record first, and the session forgotten only once that has
    /// landed; a delete the store refuses leaves the session owed, and the next pass tries it
    /// again.
    ///
    /// # Errors
    ///
    /// Returns the first delete the record refused; every session is still tried.
    pub fn discharge_unstarted(&self, sessions: &[SessionId]) -> Result<()> {
        let mut inner = self.inner();
        let generation = inner.mode.generation();
        let mut refused = None;
        for session_id in sessions {
            if inner.obligations.contains_key(session_id) {
                if let Err(error) = inner.record.discharge(*session_id, generation) {
                    refused.get_or_insert(error);
                    continue;
                }
                inner.obligations.remove(session_id);
            }
            inner.unrecorded.remove(session_id);
            inner.sessions.remove(session_id);
        }
        refused.map_or(Ok(()), Err)
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

    /// Returns the sessions this record follows or holds an obligation for whose worker it has no
    /// news of: neither running nor recorded, and not yet taken for ended.
    ///
    /// The daemon asks its registry about each one ([`Self::sessions_seen`]), because a worker that
    /// is not recorded may not have reported yet: a session whose launch is still in progress has no
    /// worker the registry lists, and is one this host has not reached, not one that has ended.
    #[must_use]
    pub fn unreached(&self, live: &[SessionId], recorded: &[SessionId]) -> Vec<SessionId> {
        let inner = self.inner();
        inner
            .sessions
            .keys()
            .chain(inner.obligations.keys())
            .filter(|session_id| !recorded.contains(session_id) && !live.contains(session_id))
            .filter(|session_id| {
                inner
                    .sessions
                    .get(session_id)
                    .is_none_or(|progress| progress.reach != Reach::Ended)
            })
            .copied()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    /// Brings what this record knows of the sessions' workers into line with the daemon's: each
    /// session in `live` has a worker running, and each session in `over` has ended.
    ///
    /// `over` is what the daemon's registry shows to be over: a session that is neither running nor
    /// recorded ([`Self::unreached`]) and whose launch it has no record of, or recorded as closed or
    /// as failed after a worker claimed it, so no worker is coming for it that could answer. That
    /// covers a session that closed before privacy mode was turned on and whose output is still on
    /// the disk, and every obligation a restart read back for a session whose worker had run. A
    /// launch that never produced a worker is not here: it is forgotten
    /// ([`Self::discharge_unstarted`]). A session that is not in `over` keeps what was known of it,
    /// and a session `recorded` lists and `live` does not is never taken for ended: a worker this
    /// daemon has not reached yet, or whose launch has not finished, is not one that has ended, and
    /// turning privacy mode off waits for it.
    ///
    /// # Errors
    ///
    /// Returns the first obligation that could not be written ([`Self::note_session_live`]); every
    /// session is still noted, and each such obligation is held and written again by the tick.
    pub fn sessions_seen(
        &self,
        live: &[SessionId],
        recorded: &[SessionId],
        over: &[SessionId],
        now_ms: TimestampMs,
    ) -> Result<()> {
        for session_id in over {
            if !recorded.contains(session_id) && !live.contains(session_id) {
                self.note_session_ended(*session_id);
            }
        }
        let mut refused = None;
        for session_id in live {
            if let Err(error) = self.note_session_live(*session_id, now_ms) {
                refused.get_or_insert(error);
            }
        }
        refused.map_or(Ok(()), Err)
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
        // Every worker starts at the initial generation with privacy mode off, and none is told
        // another until the environment records one, so while that is what is in force nothing
        // is owed.
        if generation == PrivacyGeneration::INITIAL && !enabled {
            return Vec::new();
        }
        let mut due = Vec::new();
        for (session_id, progress) in &mut inner.sessions {
            if progress.reach != Reach::Live || !progress.notices.due(now_ms) {
                continue;
            }
            let settled = progress.answer.as_ref().is_some_and(|answer| {
                answer.generation == generation && answer.enabled == enabled && answer.is_complete()
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
    pub fn note_answer(&self, ack: &PrivacyGenerationAck) -> Result<()> {
        let session_id = ack.session_id;
        let generation = PrivacyGeneration::new(ack.generation.get());
        let answer = Answer {
            generation,
            enabled: ack.enabled,
            completion: ack.completion.clone(),
        };
        let mut inner = self.inner();
        let current =
            generation == inner.mode.generation() && ack.enabled == inner.mode.is_enabled();
        if current && answer.is_complete() && inner.obligations.contains_key(&session_id) {
            inner.record.discharge(session_id, generation)?;
            inner.obligations.remove(&session_id);
            inner.unrecorded.remove(&session_id);
        }
        let progress = inner.sessions.entry(session_id).or_default();
        // An answer says the worker is running, whatever this record had heard of it before.
        if matches!(progress.reach, Reach::Unknown | Reach::Launching) {
            progress.reach = Reach::Live;
        }
        progress.answer = Some(answer);
        Ok(())
    }

    /// Takes the named daemon subsystems through the enabling's steps, and records what they owe.
    ///
    /// What a subsystem owes is cleared only when the work it owed succeeds: its steps, and for the
    /// backup service the reconciliation that follows a retry of them. Until then its entry, and
    /// the schedule it is retried on, stay.
    fn apply(&self, inner: &mut Inner, which: &[Subsystem], now_ms: TimestampMs) {
        let mode = inner.mode;
        let enabling = self.drive(mode, which, now_ms);
        for subsystem in which {
            let unfinished = enabling
                .as_ref()
                .map_err(|unavailable| (kr_worker::privacy::Step::Fence, unavailable.clone()))
                .and_then(|enabling| {
                    enabling
                        .unfinished(subsystem.name())
                        .map_or(Ok(()), |unfinished| {
                            Err((unfinished.step, unfinished.unavailable.clone()))
                        })
                });
            match unfinished {
                Err((step, unavailable)) => owe(
                    inner,
                    *subsystem,
                    Work::Steps(step),
                    Owing::Refused(unavailable),
                    now_ms,
                ),
                // A generation the backup service accepted while it could not take a step is
                // finished only by reconciliation, so a retry that succeeds is followed by one.
                Ok(())
                    if *subsystem == Subsystem::Backup
                        && inner.owed.contains_key(&Subsystem::Backup) =>
                {
                    match self.backup.reconcile(now_ms) {
                        Ok(_) => {
                            inner.owed.remove(subsystem);
                        }
                        Err(error) => owe(
                            inner,
                            Subsystem::Backup,
                            Work::Reconcile,
                            Owing::Refused(Unavailable::new(format!(
                                "the backup service could not be reconciled after its privacy \
                                 steps: {error}"
                            ))),
                            now_ms,
                        ),
                    }
                }
                Ok(()) => {
                    inner.owed.remove(subsystem);
                }
            }
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
        let wants = |subsystem: Subsystem| which.contains(&subsystem);
        let mut backup = self.backup.privacy(now_ms);
        let mut descriptions = self.descriptions.privacy();
        if !wants(Subsystem::Delivery) {
            let mut hooks: Vec<&mut dyn PrivacySubsystem> = Vec::new();
            if wants(Subsystem::Backup) {
                hooks.push(&mut backup);
            }
            if wants(Subsystem::Descriptions) {
                hooks.push(&mut descriptions);
            }
            return Ok(mode.apply(&mut hooks, now_ms));
        }
        let mut driven = None;
        let reached = self.delivery.with(|producer| {
            let mut delivery = DeliveryOutbox::over(producer.journal_mut(), now_ms.get());
            let mut hooks: Vec<&mut dyn PrivacySubsystem> = Vec::new();
            if wants(Subsystem::Backup) {
                hooks.push(&mut backup);
            }
            hooks.push(&mut delivery);
            if wants(Subsystem::Descriptions) {
                hooks.push(&mut descriptions);
            }
            driven = Some(mode.apply(&mut hooks, now_ms));
            Ok(())
        });
        if let Some(enabling) = driven {
            return Ok(enabling);
        }
        let unavailable = Unavailable::new(format!(
            "the delivery outbox could not be reached: {}",
            reached
                .err()
                .map_or_else(String::new, |error| error.to_string())
        ));
        let mut hooks: Vec<&mut dyn PrivacySubsystem> = Vec::new();
        if wants(Subsystem::Backup) {
            hooks.push(&mut backup);
        }
        if wants(Subsystem::Descriptions) {
            hooks.push(&mut descriptions);
        }
        if hooks.is_empty() {
            return Err(unavailable);
        }
        let mut enabling = mode.apply(&mut hooks, now_ms);
        enabling.unfinished.push(kr_worker::privacy::Unfinished {
            subsystem: Subsystem::Delivery.name(),
            step: kr_worker::privacy::Step::Fence,
            unavailable,
        });
        Ok(enabling)
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
                Work::Steps(kr_worker::privacy::Step::Remove),
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
    ///
    /// A fence with cleanup still owed under it is not released over that cleanup: the cleanup is
    /// run first, each time this is tried, so a target that becomes available again lets the
    /// release land rather than leaving it pending for ever.
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
            if status.obligations > 0 {
                self.backup
                    .run_cleanup(PrivacyGeneration::new(fence), now_ms)
                    .map_err(|error| {
                        Unavailable::new(format!(
                            "the cleanup under the backup privacy fence could not run: {error}"
                        ))
                    })?;
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
        for (session_id, reason) in &inner.unrecorded {
            owed.push(format!("session {session_id}: {reason}"));
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
        let wants = |subsystem: Subsystem| which.contains(&subsystem);
        let backup = self.backup.privacy(now_ms);
        let descriptions = self.descriptions.privacy();
        let others = || {
            let mut hooks: Vec<&dyn PrivacySubsystem> = Vec::new();
            if wants(Subsystem::Backup) {
                hooks.push(&backup);
            }
            if wants(Subsystem::Descriptions) {
                hooks.push(&descriptions);
            }
            hooks
        };
        if !wants(Subsystem::Delivery) {
            return PrivacyMode::reconcile(&others());
        }
        let answered = self.delivery.with(|producer| {
            let delivery = DeliveryOutbox::over(producer.journal_mut(), now_ms.get());
            let mut hooks = others();
            hooks.push(&delivery);
            Ok(PrivacyMode::reconcile(&hooks))
        });
        answered.unwrap_or_else(|error| {
            let (outstanding, mut unavailable) = PrivacyMode::reconcile(&others()).into_parts();
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
        for (session_id, reason) in &inner.unrecorded {
            unavailable.push((
                "sessions",
                Unavailable::new(format!("session {session_id}: {reason}")),
            ));
        }
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
        // An environment that never turned privacy mode on owes its workers nothing: none is told
        // anything at the initial generation, so none has an answer to wait for.
        if !inner.mode.is_enabled() && inner.mode.generation() > PrivacyGeneration::INITIAL {
            // Turning privacy mode off finishes once every live session holds the new generation
            // with nothing of its own still owed; until then its worker's own account is carried.
            let generation = inner.mode.generation();
            for (session_id, progress) in &inner.sessions {
                if progress.reach != Reach::Live || inner.obligations.contains_key(session_id) {
                    continue;
                }
                let answer = progress
                    .answer
                    .as_ref()
                    .filter(|answer| answer.generation == generation && !answer.enabled);
                match answer.map(|answer| &answer.completion) {
                    Some(PrivacyCompletion::Complete) => {}
                    Some(PrivacyCompletion::Reconciling { outstanding: owed }) => {
                        outstanding.push(("sessions", owed_count(owed).max(1)));
                    }
                    Some(PrivacyCompletion::Unavailable {
                        unavailable: owed, ..
                    }) => unavailable.push((
                        "sessions",
                        Unavailable::new(format!("session {session_id}: {}", reasons(owed))),
                    )),
                    None => outstanding.push(("sessions", 1)),
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
        let descriptions = self.descriptions.privacy();
        let mut kept = backup.kept();
        kept.extend(descriptions.kept());
        let mut exported = Vec::new();
        let mut unlisted = Vec::new();
        for (name, listed) in [
            (Subsystem::Backup.name(), backup.exported()),
            (Subsystem::Descriptions.name(), descriptions.exported()),
        ] {
            match listed {
                Ok(copies) => exported.extend(copies),
                Err(reason) => unlisted.push((name, reason)),
            }
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

/// Writes the obligation `session_id` holds here at `generation`.
///
/// A write that lands ends its place among the unrecorded; one that fails keeps it there with the
/// store's reason, and the store's error is returned.
fn write_obligation(
    inner: &mut Inner,
    session_id: SessionId,
    generation: PrivacyGeneration,
    now_ms: TimestampMs,
) -> Result<()> {
    match inner.record.oblige(session_id, generation, now_ms) {
        Ok(()) => {
            inner.unrecorded.remove(&session_id);
            Ok(())
        }
        Err(error) => {
            inner.unrecorded.insert(
                session_id,
                Unavailable::new(format!("its obligation could not be recorded: {error}")),
            );
            Err(error)
        }
    }
}

impl crate::service::Controller {
    /// Performs `privacy.set` under the admission it carries, and answers the report.
    ///
    /// The sessions the environment holds content for are every worker the registry records, every
    /// launch whose worker may be starting or running (a reservation that is spawned, claimed or
    /// fenced after a claim) and every session whose journal or spool is still on disk, and each
    /// owes its own cleanup when privacy mode is turned on. The admission is asked again immediately before the change is
    /// written, after every wait ([`EnvironmentPrivacy::set`]).
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::WindowExpired`] for an action that carries no freshness, and
    /// otherwise what [`EnvironmentPrivacy::set`] refuses with.
    pub(crate) async fn privacy_set(
        self: &Arc<Self>,
        mutation: &kr_protocol::envelope::MutationRequest,
        carried: crate::authority::AdmittedMutation,
    ) -> Result<kr_protocol::envelope::ParamsValue> {
        if carried.deadline.is_none() {
            return Err(ControllerError::WindowExpired {
                detail: "this action carries no freshness, so it may be answered from what this \
                         host holds and may not change privacy mode"
                    .to_owned(),
            });
        }
        let params: kr_protocol::privacy::PrivacySetParams = mutation
            .params
            .to_typed()
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?;
        let mut sessions: Vec<SessionId> = {
            let registry = self.registry_handle().lock().await;
            let mut sessions: Vec<SessionId> = registry
                .workers()?
                .into_iter()
                .map(|worker| worker.session_id)
                .collect();
            // A launch that handed its worker a specification, or may be about to, owes its
            // cleanup too, whether or not its worker has opened a journal or reported yet: after a
            // restart this daemon's own record of launches is gone, and the registry is the only
            // place that says a worker may be running there.
            // A reservation fenced before any worker claimed it handed nobody a specification.
            for phase in [
                crate::registry::LaunchPhase::Spawned,
                crate::registry::LaunchPhase::Claimed,
                crate::registry::LaunchPhase::Fenced,
            ] {
                sessions.extend(
                    registry
                        .reservations_in(phase)?
                        .into_iter()
                        .filter(|reservation| {
                            phase != crate::registry::LaunchPhase::Fenced
                                || reservation.claimed_key.is_some()
                        })
                        .map(|reservation| reservation.session_id),
                );
            }
            sessions
        };
        sessions.extend(self.archive().sessions_on_disk()?);
        sessions.sort_unstable();
        sessions.dedup();
        let controller = Arc::clone(self);
        let now_ms = kr_ipc::now_ms();
        let report = tokio::task::spawn_blocking(move || {
            controller
                .privacy
                .set(params.enabled, &sessions, now_ms, &|write| {
                    controller.under_registration(&carried, write)?
                })
        })
        .await
        .map_err(|_| ControllerError::RegistryUnavailable {
            detail: "the privacy change stopped before it could say what it did".to_owned(),
        })??;
        kr_protocol::envelope::ParamsValue::from_typed(&report)
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))
    }

    /// Answers `privacy.status`.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the report could not be made.
    pub(crate) async fn privacy_status(&self) -> Result<kr_protocol::envelope::ParamsValue> {
        let privacy = Arc::clone(&self.privacy);
        let now_ms = kr_ipc::now_ms();
        let report = tokio::task::spawn_blocking(move || privacy.status(now_ms))
            .await
            .map_err(|_| ControllerError::RegistryUnavailable {
                detail: "privacy mode's report could not be made".to_owned(),
            })?;
        kr_protocol::envelope::ParamsValue::from_typed(&report)
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))
    }
}

/// Records that `subsystem` owes `work`.
///
/// The same work failing again waits longer each time. Progress starts the schedule again: work
/// of another kind, or the enabling's steps stopping at a later step than before.
fn owe(inner: &mut Inner, subsystem: Subsystem, work: Work, owing: Owing, now_ms: TimestampMs) {
    let previous = inner
        .owed
        .get(&subsystem)
        .map(|owed| (owed.work, owed.retry));
    let retry = match (previous, work) {
        (Some((Work::Steps(before), retry)), Work::Steps(after)) if after <= before => retry,
        (Some((before, retry)), _) if before == work => retry,
        _ => Backoff::default(),
    }
    .after_failure(now_ms);
    inner.owed.insert(subsystem, Owed { work, owing, retry });
}

/// Returns how much a worker says is outstanding, over all its subsystems.
fn owed_count(outstanding: &[PrivacyOutstanding]) -> u64 {
    outstanding
        .iter()
        .map(|owed| owed.count.get())
        .fold(0, u64::saturating_add)
}

/// Returns what a worker says is in the way, one subsystem after another.
fn reasons(unavailable: &[PrivacyUnavailable]) -> String {
    unavailable
        .iter()
        .map(|owed| format!("{}: {}", owed.subsystem, owed.reason))
        .collect::<Vec<_>>()
        .join("; ")
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
                }) if answer.generation == generation && answer.enabled == enabled => match &answer
                    .completion
                {
                    PrivacyCompletion::Complete => Standing::AwaitingWorker,
                    PrivacyCompletion::Reconciling { outstanding } => Standing::Reconciling {
                        outstanding: owed_count(outstanding),
                    },
                    PrivacyCompletion::Unavailable { unavailable, .. } => Standing::Unavailable {
                        reason: reasons(unavailable),
                    },
                },
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
        // A write that finds the record held by another connection waits for it, up to five
        // seconds, rather than refusing the change at once.
        connection
            .busy_timeout(std::time::Duration::from_secs(5))
            .map_err(ControllerError::registry)?;
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
    /// one transaction, written under `admitted` once the transaction is held.
    fn enable(
        &mut self,
        generation: PrivacyGeneration,
        sessions: &[SessionId],
        now_ms: TimestampMs,
        admitted: Admitted<'_>,
    ) -> Result<()> {
        // Taking the transaction is the record's one wait: another writer holds it for up to the
        // busy timeout. The admission is asked once it is held, and the transaction is rolled
        // back unwritten when it refuses.
        let mut transaction = Some(
            self.connection
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .map_err(ControllerError::registry)?,
        );
        admitted(&mut || {
            let transaction = transaction.take().ok_or_else(|| {
                ControllerError::registry("the privacy record's transaction was already written")
            })?;
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
        })
    }

    /// Records that privacy mode is off from `generation`, written under `admitted` once the
    /// record's transaction is held.
    fn disable(
        &mut self,
        generation: PrivacyGeneration,
        now_ms: TimestampMs,
        admitted: Admitted<'_>,
    ) -> Result<()> {
        let mut transaction = Some(
            self.connection
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .map_err(ControllerError::registry)?,
        );
        admitted(&mut || {
            let transaction = transaction.take().ok_or_else(|| {
                ControllerError::registry("the privacy record's transaction was already written")
            })?;
            transaction
                .execute(
                    "UPDATE privacy_record SET generation = ?1, enabled = 0, changed_at_ms = ?2
                      WHERE id = 0",
                    params![as_i64(generation.get()), as_i64(now_ms.get())],
                )
                .map_err(ControllerError::registry)?;
            transaction.commit().map_err(ControllerError::registry)
        })
    }

    /// Records that one session owes its cleanup at `generation`.
    fn oblige(
        &mut self,
        session_id: SessionId,
        generation: PrivacyGeneration,
        now_ms: TimestampMs,
    ) -> Result<()> {
        self.connection
            .execute(
                "INSERT INTO privacy_obligations (session_id, generation, recorded_at_ms)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT (session_id) DO UPDATE SET
                     generation = MAX(generation, excluded.generation),
                     recorded_at_ms = excluded.recorded_at_ms",
                params![
                    session_id.to_string(),
                    as_i64(generation.get()),
                    as_i64(now_ms.get())
                ],
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

    /// The backup service, the delivery module and the session-metadata store of one environment,
    /// over `state`.
    fn services(state: &Path) -> (Arc<BackupService>, Arc<DeliveryModule>, Arc<DescribeModule>) {
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
        let descriptions = Arc::new(DescribeModule::open(state).expect("a session-metadata store"));
        (backup, delivery, descriptions)
    }

    /// One environment's daemon subsystems and its privacy record, all on the internal disk.
    struct Host {
        root: tempfile::TempDir,
        writer: AuthorisationKeyPair,
        sender: StoredEnvelopeKeyPair,
        device: StoredEnvelopeKeyPair,
        backup: Arc<BackupService>,
        delivery: Arc<DeliveryModule>,
        descriptions: Arc<DescribeModule>,
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
            let (backup, delivery, descriptions) = services(root.path());
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
            let privacy = EnvironmentPrivacy::open(
                root.path(),
                Arc::clone(&backup),
                Arc::clone(&delivery),
                Arc::clone(&descriptions),
            )
            .expect("the privacy record");
            Self {
                root,
                writer,
                sender: StoredEnvelopeKeyPair::generate().expect("a producer key"),
                device: StoredEnvelopeKeyPair::generate().expect("a device key"),
                backup,
                delivery,
                descriptions,
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
                descriptions,
                privacy,
            } = self;
            drop(privacy);
            drop(backup);
            drop(delivery);
            drop(descriptions);
            let (backup, delivery, descriptions) = services(root.path());
            let privacy = EnvironmentPrivacy::open(
                root.path(),
                Arc::clone(&backup),
                Arc::clone(&delivery),
                Arc::clone(&descriptions),
            )
            .expect("the privacy record");
            Self {
                root,
                writer,
                sender,
                device,
                backup,
                delivery,
                descriptions,
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

        /// Carries one admitted generation to a publication attempt that has left this host, and
        /// returns that attempt.
        fn publication_on_the_wire(&self, generation: u8) -> u64 {
            let admitted = self.admit(generation).expect("admitted");
            let backup_generation = BackupGeneration::new(u64::from(generation));
            self.backup
                .note_dispatched(admitted.sequence, EXECUTOR, at(1))
                .expect("the upload is on its way");
            for row in self
                .backup
                .objects(archive_id(), backup_generation)
                .expect("a read")
            {
                self.backup
                    .note_object_uploaded(
                        admitted.sequence,
                        archive_id(),
                        backup_generation,
                        row.object_id,
                        at(2),
                    )
                    .expect("the object arrived");
            }
            self.backup
                .note_attempt_accepted(admitted.sequence, at(3))
                .expect("the upload finished");
            let publication = self
                .backup
                .outbox()
                .expect("a read")
                .into_iter()
                .find(|attempt| attempt.step == Step::Publish)
                .expect("a publication attempt")
                .sequence;
            self.backup
                .note_dispatched(publication, EXECUTOR, at(4))
                .expect("the publication is on its way");
            publication
        }

        /// Opens the privacy record again over the same subsystems, as a daemon's next start does.
        #[cfg(unix)]
        fn reopen_privacy(&mut self) {
            self.privacy = EnvironmentPrivacy::open(
                self.root.path(),
                Arc::clone(&self.backup),
                Arc::clone(&self.delivery),
                Arc::clone(&self.descriptions),
            )
            .expect("the privacy record");
        }

        /// What one daemon subsystem owes now, and when it is next tried, as an offset from the
        /// tests' clock.
        fn owed(&self, subsystem: Subsystem) -> Option<(Work, u64)> {
            self.privacy
                .inner()
                .owed
                .get(&subsystem)
                .map(|owed| (owed.work, owed.retry.next_at_ms - NOW))
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

    /// An admission that stands, as the owner's own path does: the write runs.
    fn standing(write: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        write()
    }

    /// A worker's answer to a notice, as it arrives.
    fn ack(
        session_id: SessionId,
        generation: u64,
        enabled: bool,
        completion: PrivacyCompletion,
    ) -> PrivacyGenerationAck {
        PrivacyGenerationAck {
            session_id,
            generation: U64::new(generation),
            enabled,
            completion,
        }
    }

    /// A worker's account of cleanup still settling in one of its subsystems.
    fn reconciling(subsystem: &str, count: u64) -> PrivacyCompletion {
        PrivacyCompletion::Reconciling {
            outstanding: vec![PrivacyOutstanding {
                subsystem: subsystem.to_owned(),
                count: U64::new(count),
            }],
        }
    }

    /// A worker's account of one of its subsystems that could not finish.
    fn refused(subsystem: &str, reason: &str) -> PrivacyCompletion {
        PrivacyCompletion::Unavailable {
            unavailable: vec![PrivacyUnavailable {
                subsystem: subsystem.to_owned(),
                reason: reason.to_owned(),
            }],
            outstanding: Vec::new(),
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
            .enable(&[session(1)], at(10), &standing)
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
            .enable(&[session(1)], at(20), &standing)
            .expect("privacy mode is enabled");
        assert!(report.enabled);
        assert_eq!(report.generation, PrivacyGeneration::new(1));
        assert!(host.privacy.state().is_private());
        assert!(
            host.privacy
                .state()
                .admit_send(PrivacyGeneration::new(1))
                .is_none()
        );
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
            .enable(&[], at(10), &standing)
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
            .enable(&[], at(10), &standing)
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
        let publication = host.publication_on_the_wire(1);

        let report = host
            .privacy
            .enable(&[], at(10), &standing)
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
            .enable(&[], at(10), &standing)
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
            .enable(&[], at(0), &standing)
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
            .enable(&[], at(0), &standing)
            .expect("privacy mode is enabled");
        assert!(
            outstanding(&report, "backup") > 0,
            "{:?}",
            report.completion
        );
        let refused = host
            .privacy
            .disable(at(10), &standing)
            .expect_err("cleanup is owed");
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
            .disable(at(2_000), &standing)
            .expect("nothing is owed now");
        assert!(!report.enabled);
        assert_eq!(report.generation, PrivacyGeneration::new(2));
        assert!(report.completion.is_complete(), "{:?}", report.completion);
        assert!(
            host.privacy
                .state()
                .admit_send(PrivacyGeneration::new(2))
                .is_some()
        );
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
            .enable(&[], at(0), &standing)
            .expect("privacy mode is enabled");
        assert!(report.completion.is_complete(), "{:?}", report.completion);
        host.backup
            .set_query_only(true)
            .expect("the store refuses writes");
        let report = host
            .privacy
            .disable(at(10), &standing)
            .expect("the record is written");
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
            .enable(&[session(1), session(2)], at(0), &standing)
            .expect("privacy mode is enabled");
        assert_eq!(report.obligations.len(), 2);
        assert_eq!(outstanding(&report, "sessions"), 2);
        host.privacy
            .note_session_live(session(1), at(5))
            .expect("a live session");
        host.privacy
            .note_session_live(session(2), at(5))
            .expect("a live session");
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
            .note_answer(&ack(session(1), 1, true, reconciling("attention", 1)))
            .expect("an answer");
        assert_eq!(host.privacy.notices_due(at(1_010)).len(), 2);
        host.privacy
            .note_answer(&ack(session(1), 1, true, PrivacyCompletion::Complete))
            .expect("an answer");
        let report = host.privacy.report_now(at(1_020));
        assert_eq!(report.obligations.len(), 1);
        assert_eq!(report.obligations[0].session_id, session(2));

        // The other session's worker is live and has not said: privacy mode stays on.
        let refused = host
            .privacy
            .disable(at(1_030), &standing)
            .expect_err("a live session still owes");
        assert!(refused.to_string().contains("has not said"), "{refused}");

        // Its worker ends. Nothing resumes in its store, so disabling goes ahead, and its
        // obligation stays and keeps the report from saying complete.
        host.privacy.note_session_ended(session(2));
        let report = host
            .privacy
            .disable(at(1_040), &standing)
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
            .note_answer(&ack(session(1), 2, false, PrivacyCompletion::Complete))
            .expect("an answer");
        let report = host.privacy.report_now(at(2_010));
        assert_eq!(outstanding(&report, "sessions"), 0);
        assert!(!report.completion.is_complete());

        // A restart and a later enabling keep it.
        let host = host.restarted();
        host.privacy.resume(at(3_000));
        let report = host
            .privacy
            .enable(&[], at(3_010), &standing)
            .expect("privacy mode is enabled again");
        assert_eq!(report.generation, PrivacyGeneration::new(3));
        assert_eq!(report.obligations.len(), 1);
        assert_eq!(report.obligations[0].session_id, session(2));
        assert_eq!(report.obligations[0].generation, PrivacyGeneration::new(1));
        assert!(!report.completion.is_complete());
    }

    /// Backup production closes before the enabling waits for anything. With the delivery outbox
    /// held elsewhere, an enabling that has published the private state has already raised the
    /// backup fence, so an answer about work from before the boundary is never made current.
    #[test]
    fn backup_production_is_closed_before_the_enabling_waits_for_the_delivery_outbox() {
        let host = Host::open();
        let publication = host.publication_on_the_wire(1);
        let (held_tx, held_rx) = std::sync::mpsc::channel();
        let (go_tx, go_rx) = std::sync::mpsc::channel::<()>();
        std::thread::scope(|scope| {
            // Held here, so an assertion that fails below drops it and lets the holder go rather
            // than leaving every thread of the scope waiting for the others.
            let go_tx = go_tx;
            let delivery = &host.delivery;
            scope.spawn(move || {
                delivery
                    .with(|_| {
                        held_tx.send(()).expect("the holder says so");
                        let _ = go_rx.recv();
                        Ok(())
                    })
                    .expect("the delivery outbox");
            });
            held_rx.recv().expect("the delivery outbox is held");
            let enabling = scope.spawn(|| host.privacy.enable(&[], at(10), &standing));
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
            while !host.privacy.state().is_private() {
                assert!(
                    std::time::Instant::now() < deadline,
                    "the record never committed"
                );
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            assert_eq!(
                host.backup.fenced_at().expect("a read"),
                Some(1),
                "the backup fence is up before anything waits"
            );
            assert_eq!(
                host.backup
                    .note_published(publication, PrivacyGeneration::INITIAL, at(20))
                    .expect("the answer is recorded"),
                Publication::RetainedArtifact {
                    privacy_generation: 0
                },
                "an answer from before the boundary does not become current"
            );
            go_tx.send(()).expect("the holder lets go");
            let report = enabling
                .join()
                .expect("the enabling finishes")
                .expect("privacy mode is enabled");
            assert!(report.enabled);
            assert!(host.delivery_is_fenced());
        });
    }

    /// A delivery exchange admitted while privacy mode is off ends before privacy mode is turned
    /// on, and none is admitted after.
    #[test]
    fn a_send_admitted_before_privacy_mode_finishes_first_and_none_is_admitted_after() {
        let state = PrivacyState::default();
        let admission = state
            .admit_send(PrivacyGeneration::INITIAL)
            .expect("admitted while privacy mode is off");
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        std::thread::scope(|scope| {
            scope.spawn(|| {
                state.publish(Published {
                    generation: PrivacyGeneration::new(1),
                    private: true,
                });
                done_tx.send(()).expect("the turn says so");
            });
            assert!(
                done_rx
                    .recv_timeout(std::time::Duration::from_millis(200))
                    .is_err(),
                "turning privacy mode on waits for the admitted exchange"
            );
            drop(admission);
            done_rx
                .recv_timeout(std::time::Duration::from_secs(30))
                .expect("and goes ahead once it has ended");
        });
        assert!(
            state.admit_send(PrivacyGeneration::new(1)).is_none(),
            "nothing is admitted after"
        );
        assert!(!state.accepts_result(PrivacyGeneration::INITIAL));
    }

    /// A session whose worker joins while privacy mode is on owes its cleanup like any other,
    /// durably, until its worker answers: disabling waits for it, and an ended worker and a
    /// restart before that answer keep it.
    #[test]
    fn a_session_that_joins_while_private_owes_its_cleanup_until_its_worker_answers() {
        let host = Host::open();
        host.privacy
            .enable(&[], at(0), &standing)
            .expect("privacy mode is enabled");
        host.privacy
            .note_session_live(session(5), at(10))
            .expect("a live session");
        let report = host.privacy.report_now(at(20));
        assert_eq!(report.obligations.len(), 1);
        assert!(!report.completion.is_complete());
        assert!(
            host.privacy.disable(at(30), &standing).is_err(),
            "a live session has not answered"
        );

        // Its worker ends before it answers: the obligation stays, and survives a restart.
        host.privacy.note_session_ended(session(5));
        let host = host.restarted();
        host.privacy.resume(at(40));
        let report = host.privacy.report_now(at(50));
        assert_eq!(report.obligations.len(), 1);
        assert_eq!(report.obligations[0].session_id, session(5));
        assert!(!report.completion.is_complete());

        // A session that joins and answers complete ends its own obligation.
        host.privacy
            .note_session_live(session(6), at(60))
            .expect("a live session");
        host.privacy
            .note_answer(&ack(session(6), 1, true, PrivacyCompletion::Complete))
            .expect("an answer");
        assert_eq!(host.privacy.report_now(at(70)).obligations.len(), 1);
    }

    /// Turning privacy mode off finishes only once each live worker says it holds the new
    /// generation with its cleanup complete; a worker still reconciling, or one that cannot say,
    /// is carried in the report.
    #[test]
    fn turning_privacy_off_waits_for_each_live_worker_to_say_it_is_complete() {
        let host = Host::open();
        host.privacy
            .note_session_live(session(1), at(0))
            .expect("a live session");
        host.privacy
            .enable(&[], at(10), &standing)
            .expect("privacy mode is enabled");
        host.privacy
            .note_answer(&ack(session(1), 1, true, PrivacyCompletion::Complete))
            .expect("an answer");
        let report = host
            .privacy
            .disable(at(20), &standing)
            .expect("nothing is owed");
        assert_eq!(outstanding(&report, "sessions"), 1, "not yet answered");

        host.privacy
            .note_answer(&ack(session(1), 2, false, reconciling("history", 2)))
            .expect("an answer");
        let report = host.privacy.report_now(at(30));
        assert_eq!(outstanding(&report, "sessions"), 2);
        assert!(!report.completion.is_complete());

        host.privacy
            .note_answer(&ack(
                session(1),
                2,
                false,
                refused("receipts", "the journal refused the redaction"),
            ))
            .expect("an answer");
        let report = host.privacy.report_now(at(40));
        assert!(
            unavailable(&report, "sessions")
                .iter()
                .any(|reason| reason.contains("refused the redaction")),
            "{:?}",
            report.completion
        );

        host.privacy
            .note_answer(&ack(session(1), 2, false, PrivacyCompletion::Complete))
            .expect("an answer");
        assert!(host.privacy.report_now(at(50)).completion.is_complete());
    }

    /// A release pending under cleanup that is still owed runs that cleanup again on each try, and
    /// lands once the target is back. Here the record says privacy mode is off while the backup
    /// service still holds its fence, as after a backup store put back from an earlier copy.
    #[cfg(unix)]
    #[test]
    fn a_pending_release_runs_the_cleanup_it_waits_for_and_lands_once_the_target_returns() {
        use std::os::unix::fs::PermissionsExt as _;
        let set_writable = |directory: &Path, writable: bool| {
            let mode = if writable { 0o755 } else { 0o555 };
            std::fs::set_permissions(directory, std::fs::Permissions::from_mode(mode))
                .expect("permissions");
        };
        let mut host = Host::open();
        host.admit(1).expect("admitted");
        let staged = host.staged(1);
        let directory = staged[0].parent().expect("a directory").to_path_buf();
        set_writable(&directory, false);
        host.privacy
            .enable(&[], at(0), &standing)
            .expect("privacy mode is enabled");
        Connection::open(host.root.path().join(PRIVACY_RECORD))
            .expect("the record")
            .execute_batch("UPDATE privacy_record SET generation = 2, enabled = 0 WHERE id = 0")
            .expect("the record says privacy mode is off");
        host.reopen_privacy();

        let report = host.privacy.resume(at(10));
        assert!(!report.enabled);
        assert!(
            outstanding(&report, "backup") > 0,
            "{:?}",
            report.completion
        );
        assert!(matches!(
            host.owed(Subsystem::Backup),
            Some((Work::Release, 1_010))
        ));
        assert_eq!(host.backup.fenced_at().expect("a read"), Some(1));

        set_writable(&directory, true);
        let report = host.privacy.tick(at(500));
        assert!(!report.completion.is_complete(), "not before its turn");
        let report = host.privacy.tick(at(1_010));
        assert!(report.completion.is_complete(), "{:?}", report.completion);
        assert_eq!(host.backup.fenced_at().expect("a read"), None);
        for path in &staged {
            assert!(!path.exists());
        }
    }

    /// The same work failing again waits longer each time, and reconciliation that keeps failing
    /// after the steps succeed keeps its schedule rather than starting again.
    #[test]
    fn a_reconciliation_that_keeps_failing_waits_longer_each_time() {
        let host = Host::unreconciled();
        host.backup
            .set_query_only(true)
            .expect("the store refuses writes");
        host.privacy
            .enable(&[], at(0), &standing)
            .expect("the record is written");
        assert!(matches!(
            host.owed(Subsystem::Backup),
            Some((Work::Steps(kr_worker::privacy::Step::Fence), 1_000))
        ));
        host.backup
            .set_query_only(false)
            .expect("the store accepts writes");
        let hide = Connection::open(host.root.path().join("backup.sqlite")).expect("the store");
        hide.execute_batch("ALTER TABLE writers RENAME TO writers_hidden")
            .expect("reconciliation cannot read its writers");

        // The steps succeed and the reconciliation after them does not: that is progress, so its
        // schedule starts again, and each further failure waits longer.
        host.privacy.tick(at(1_000));
        assert_eq!(host.owed(Subsystem::Backup), Some((Work::Reconcile, 2_000)));
        host.privacy.tick(at(2_000));
        assert_eq!(host.owed(Subsystem::Backup), Some((Work::Reconcile, 4_000)));
        host.privacy.tick(at(3_000));
        assert_eq!(
            host.owed(Subsystem::Backup),
            Some((Work::Reconcile, 4_000)),
            "not before its turn"
        );

        hide.execute_batch("ALTER TABLE writers_hidden RENAME TO writers")
            .expect("reconciliation can read its writers again");
        let report = host.privacy.tick(at(4_000));
        assert_eq!(host.owed(Subsystem::Backup), None);
        assert!(report.completion.is_complete(), "{:?}", report.completion);
        assert_eq!(host.backup.unready(), None);
    }

    /// Steps stopping at a later step than before is progress, and starts the schedule again;
    /// the same step failing again waits longer. A cancellation the store refuses is owed with
    /// its reason and nothing behind it runs.
    #[test]
    fn a_refused_cancellation_is_progress_from_a_refused_fence_and_is_retried() {
        let host = Host::open();
        host.admit(1).expect("admitted");
        let staged = host.staged(1);
        host.backup
            .set_query_only(true)
            .expect("the store refuses writes");
        host.privacy
            .enable(&[], at(0), &standing)
            .expect("the record is written");
        host.privacy.tick(at(1_000));
        assert!(matches!(
            host.owed(Subsystem::Backup),
            Some((Work::Steps(kr_worker::privacy::Step::Fence), 3_000))
        ));

        host.backup
            .set_query_only(false)
            .expect("the store accepts writes");
        let store = Connection::open(host.root.path().join("backup.sqlite")).expect("the store");
        store
            .execute_batch(
                "CREATE TRIGGER refuse_the_cancellation BEFORE UPDATE ON outbox
                 BEGIN SELECT RAISE(ABORT, 'this store refused the cancellation'); END;",
            )
            .expect("the store will refuse the cancellation");
        let report = host.privacy.tick(at(3_000));
        assert!(matches!(
            host.owed(Subsystem::Backup),
            Some((Work::Steps(kr_worker::privacy::Step::Cancel), 4_000))
        ));
        assert!(
            unavailable(&report, "backup")
                .iter()
                .any(|reason| reason.contains("refused the cancellation")),
            "{:?}",
            report.completion
        );
        for path in &staged {
            assert!(
                path.exists(),
                "nothing is removed behind a cancellation that failed"
            );
        }

        store
            .execute_batch("DROP TRIGGER refuse_the_cancellation")
            .expect("the store accepts the cancellation");
        let report = host.privacy.tick(at(4_000));
        assert!(report.completion.is_complete(), "{:?}", report.completion);
        for path in &staged {
            assert!(!path.exists());
        }
    }

    /// A removal the store refuses is owed with its reason, and retried on its schedule.
    #[test]
    fn a_refused_removal_is_owed_and_retried() {
        let host = Host::open();
        host.admit(1).expect("admitted");
        let store = Connection::open(host.root.path().join("backup.sqlite")).expect("the store");
        store
            .execute_batch(
                "CREATE TRIGGER refuse_the_removal BEFORE UPDATE OF local_state ON objects
                 BEGIN SELECT RAISE(ABORT, 'this store refused the removal'); END;",
            )
            .expect("the store will refuse the removal");
        let report = host
            .privacy
            .enable(&[], at(0), &standing)
            .expect("privacy mode is enabled");
        assert!(matches!(
            host.owed(Subsystem::Backup),
            Some((Work::Steps(kr_worker::privacy::Step::Remove), 1_000))
        ));
        assert!(
            unavailable(&report, "backup")
                .iter()
                .any(|reason| reason.contains("refused the removal")),
            "{:?}",
            report.completion
        );
        store
            .execute_batch("DROP TRIGGER refuse_the_removal")
            .expect("the store accepts the removal");
        let report = host.privacy.tick(at(1_000));
        assert!(report.completion.is_complete(), "{:?}", report.completion);
    }

    /// A delivery fence the journal refuses is owed with its reason, nothing behind it runs, and
    /// its retry finishes it; the other subsystems are taken through their steps meanwhile.
    #[test]
    fn a_refused_delivery_fence_is_owed_and_retried_while_the_backup_goes_on() {
        let host = Host::open();
        let delivery = host.delivery_on_the_wire(7);
        let journal =
            Connection::open(host.root.path().join("delivery.sqlite3")).expect("the journal");
        journal
            .execute_batch(
                "CREATE TRIGGER refuse_the_fence BEFORE UPDATE ON delivery_privacy
                 BEGIN SELECT RAISE(ABORT, 'this journal refused the fence'); END;",
            )
            .expect("the journal will refuse the fence");
        let report = host
            .privacy
            .enable(&[], at(0), &standing)
            .expect("privacy mode is enabled");
        assert!(
            unavailable(&report, "delivery")
                .iter()
                .any(|reason| reason.contains("refused the fence")),
            "{:?}",
            report.completion
        );
        assert!(!host.delivery_is_fenced());
        assert_eq!(host.backup.fenced_at().expect("a read"), Some(1));
        assert!(
            host.privacy
                .state()
                .admit_send(PrivacyGeneration::new(1))
                .is_none(),
            "no delivery exchange is admitted while the fence is retried"
        );

        journal
            .execute_batch("DROP TRIGGER refuse_the_fence")
            .expect("the journal accepts the fence");
        host.delivery_answered(delivery);
        let report = host.privacy.tick(at(1_000));
        assert!(host.delivery_is_fenced());
        assert!(report.completion.is_complete(), "{:?}", report.completion);
    }

    /// KR-REQ-22.17 and 24.27: enabling removes every generated description and keeps every pin,
    /// and from the moment privacy mode is recorded a read answers no generated text.
    #[test]
    fn enabling_removes_generated_descriptions_keeps_pins_and_reads_answer_metadata_titles() {
        let host = Host::open();
        let other =
            kr_describe::store::DescriptionStore::open(host.root.path()).expect("the same store");
        for byte in 1..=2 {
            other
                .publish(
                    &session(byte),
                    &crate::describe::tests::generated("Pairing check", PrivacyGeneration::INITIAL),
                    900,
                )
                .expect("a description");
        }
        let facts = kr_describe::metadata::SessionFacts {
            directory: Some("kalareach".to_owned()),
            ..kr_describe::metadata::SessionFacts::default()
        };
        let whole = crate::describe::HistoryReach::WholeSession;
        host.descriptions
            .rename(
                session(2),
                Some("Release prep"),
                "local:501",
                &facts,
                at(0),
                &standing,
            )
            .expect("a name is pinned");
        assert_eq!(
            host.descriptions
                .describe(session(1), &facts, whole, &host.privacy.state())
                .expect("a read")
                .source,
            kr_protocol::describe::LabelSource::Generated
        );

        let report = host
            .privacy
            .enable(&[], at(10), &standing)
            .expect("privacy mode is enabled");
        assert!(report.completion.is_complete(), "{:?}", report.completion);
        assert_eq!(other.generated_count().expect("a count"), 0);
        assert_eq!(other.pin_count().expect("a count"), 1);
        assert!(
            report
                .kept
                .iter()
                .any(|kept| kept.what == "session names people pinned")
        );
        let described = host
            .descriptions
            .describe(session(1), &facts, whole, &host.privacy.state())
            .expect("a read");
        assert_eq!(
            described.source,
            kr_protocol::describe::LabelSource::Metadata
        );
        assert_eq!(described.title, "kalareach");
        assert!(described.activity_text.0.is_none());
        let pinned = host
            .descriptions
            .describe(session(2), &facts, whole, &host.privacy.state())
            .expect("a read");
        assert_eq!(pinned.title, "Release prep");
    }

    /// An exchange for work of an earlier generation is not admitted once privacy mode has come
    /// and gone: a question paused before its admission, across an enabling and a disabling, finds
    /// the generation it was admitted under is no longer the one in force.
    #[test]
    fn an_exchange_for_work_of_an_earlier_generation_is_not_admitted_after_privacy_came_and_went() {
        let state = PrivacyState::default();
        let admitted_under = state.now().generation;
        state.publish(Published {
            generation: PrivacyGeneration::new(1),
            private: true,
        });
        state.publish(Published {
            generation: PrivacyGeneration::new(2),
            private: false,
        });
        assert!(
            state.admit_send(admitted_under).is_none(),
            "work privacy mode drew a line under is not sent or asked about"
        );
        assert!(state.admit_send(PrivacyGeneration::new(2)).is_some());
        assert!(
            state.admit_send(PrivacyGeneration::new(3)).is_none(),
            "nor is work of a generation not yet recorded"
        );
    }

    /// An obligation whose write the store refuses is still owed: it keeps the report from saying
    /// complete and privacy mode from being turned off, with the store's reason, through the
    /// worker's end, until a retry writes it.
    #[test]
    fn an_obligation_the_store_refused_is_still_owed_and_written_on_a_retry() {
        let host = Host::open();
        host.privacy
            .enable(&[], at(0), &standing)
            .expect("privacy mode is enabled");
        let record = Connection::open(host.root.path().join(PRIVACY_RECORD)).expect("the record");
        record
            .execute_batch(
                "CREATE TRIGGER refuse_the_obligation BEFORE INSERT ON privacy_obligations
                 BEGIN SELECT RAISE(ABORT, 'this store refused the obligation'); END;",
            )
            .expect("the store will refuse the obligation");
        let refused = host
            .privacy
            .note_session_live(session(5), at(10))
            .expect_err("the obligation could not be written");
        assert!(
            refused.to_string().contains("refused the obligation"),
            "{refused}"
        );
        let report = host.privacy.report_now(at(20));
        assert!(
            unavailable(&report, "sessions")
                .iter()
                .any(|reason| reason.contains("refused the obligation")),
            "{:?}",
            report.completion
        );
        assert!(
            host.privacy.disable(at(30), &standing).is_err(),
            "the session still owes"
        );

        // Its worker ends before anything is written; the obligation is still owed.
        host.privacy.note_session_ended(session(5));
        assert!(!host.privacy.report_now(at(40)).completion.is_complete());

        record
            .execute_batch("DROP TRIGGER refuse_the_obligation")
            .expect("the store accepts the obligation");
        let report = host.privacy.tick(at(50));
        assert!(
            unavailable(&report, "sessions")
                .iter()
                .all(|reason| !reason.contains("refused the obligation"))
        );
        assert_eq!(report.obligations.len(), 1);
        assert_eq!(report.obligations[0].standing, Standing::WorkerEnded);
        let written: i64 = record
            .query_row("SELECT COUNT(*) FROM privacy_obligations", [], |row| {
                row.get(0)
            })
            .expect("a count");
        assert_eq!(written, 1, "the retry wrote it down");
    }

    /// A session noted live again after its obligation's write failed is not said to be recorded
    /// until the write lands, whether or not its worker ended in between. Once a note has said so,
    /// the obligation outlasts the worker and a restart.
    #[test]
    fn a_repeated_live_note_says_the_obligation_is_recorded_only_once_it_is() {
        let host = Host::open();
        host.privacy
            .enable(&[], at(0), &standing)
            .expect("privacy mode is enabled");
        let record = Connection::open(host.root.path().join(PRIVACY_RECORD)).expect("the record");
        record
            .execute_batch(
                "CREATE TRIGGER refuse_the_obligation BEFORE INSERT ON privacy_obligations
                 BEGIN SELECT RAISE(ABORT, 'this store refused the obligation'); END;",
            )
            .expect("the store will refuse the obligation");
        host.privacy
            .note_session_live(session(5), at(10))
            .expect_err("the obligation could not be written");
        let again = host
            .privacy
            .note_session_live(session(5), at(20))
            .expect_err("a repeat does not say it is recorded");
        assert!(
            again.to_string().contains("refused the obligation"),
            "{again}"
        );
        host.privacy.note_session_ended(session(5));
        host.privacy
            .note_session_live(session(5), at(30))
            .expect_err("nor does one after its worker ended");

        record
            .execute_batch("DROP TRIGGER refuse_the_obligation")
            .expect("the store accepts the obligation");
        host.privacy
            .note_session_live(session(5), at(40))
            .expect("the repeat writes it, and says so");
        let report = host.privacy.report_now(at(50));
        assert!(
            unavailable(&report, "sessions")
                .iter()
                .all(|reason| !reason.contains("refused the obligation")),
            "{:?}",
            report.completion
        );
        drop(record);

        // Its worker ends and the daemon restarts before the worker has answered.
        host.privacy.note_session_ended(session(5));
        let host = host.restarted();
        host.privacy.resume(at(60));
        let report = host.privacy.report_now(at(70));
        assert_eq!(report.obligations.len(), 1);
        assert_eq!(report.obligations[0].session_id, session(5));
        assert!(!report.completion.is_complete());
    }

    /// A send checked at the generation before the boundary, once the boundary is recorded and
    /// before it is published, is refused: the check waits for the publication rather than
    /// passing between the two. A send checked after it at the new generation is refused while
    /// privacy mode is on, and one at the generation after is admitted once it is off, as before.
    #[test]
    fn a_send_checked_between_the_record_and_its_publication_is_refused() {
        let host = Host::open();
        let (arrived, release) = host.privacy.after_record.arm();
        std::thread::scope(|scope| {
            // Owned here, so a failed assertion lets the stopped enabling go on rather than wait.
            let release = release;
            let enabling = scope.spawn(|| host.privacy.enable(&[], at(10), &standing));
            arrived
                .recv_timeout(std::time::Duration::from_secs(30))
                .expect("the record is written");
            let state = host.privacy.state();
            let (checked_tx, checked_rx) = std::sync::mpsc::channel();
            scope.spawn(move || {
                // The admission is dropped at once, so nothing here holds the publication back.
                let admitted = state.admit_send(PrivacyGeneration::INITIAL).is_some();
                let _ = checked_tx.send(admitted);
            });
            let before = checked_rx.recv_timeout(std::time::Duration::from_millis(300));
            release.send(()).expect("the enabling goes on");
            enabling
                .join()
                .expect("the enabling finishes")
                .expect("privacy mode is enabled");
            let admitted = before.unwrap_or_else(|_| {
                checked_rx
                    .recv_timeout(std::time::Duration::from_secs(30))
                    .expect("the check is answered")
            });
            assert!(
                !admitted,
                "a send checked between the record and its publication is refused"
            );
        });

        let state = host.privacy.state();
        assert!(
            state.admit_send(PrivacyGeneration::new(1)).is_none(),
            "refused while privacy mode is on"
        );
        host.privacy
            .disable(at(20), &standing)
            .expect("privacy mode is turned off");
        assert!(
            state.admit_send(PrivacyGeneration::new(2)).is_some(),
            "admitted at the generation after"
        );
    }

    /// The record and the backup fence are one step for backup production. An enabling stopped
    /// once its record is written, before the fence, still holds the backup store: a backup
    /// production decision made then waits, and finds the fence up.
    #[test]
    fn a_backup_decision_made_once_the_record_is_written_waits_and_finds_the_fence_up() {
        let host = Host::open();
        let publication = host.publication_on_the_wire(1);
        let (arrived, release) = host.privacy.after_record.arm();
        std::thread::scope(|scope| {
            // Owned here, so a failed assertion lets the stopped enabling go on rather than wait.
            let release = release;
            let enabling = scope.spawn(|| host.privacy.enable(&[], at(10), &standing));
            arrived
                .recv_timeout(std::time::Duration::from_secs(30))
                .expect("the record is written");
            let (answered_tx, answered_rx) = std::sync::mpsc::channel();
            let backup = &host.backup;
            scope.spawn(move || {
                let answered =
                    backup.note_published(publication, PrivacyGeneration::INITIAL, at(20));
                let _ = answered_tx.send(answered);
            });
            assert!(
                answered_rx
                    .recv_timeout(std::time::Duration::from_millis(300))
                    .is_err(),
                "no backup decision falls between the record and the fence"
            );
            release.send(()).expect("the enabling goes on");
            let report = enabling
                .join()
                .expect("the enabling finishes")
                .expect("privacy mode is enabled");
            assert!(report.enabled);
            let answered = answered_rx
                .recv_timeout(std::time::Duration::from_secs(30))
                .expect("the decision is made")
                .expect("the answer is recorded");
            assert_eq!(
                answered,
                Publication::RetainedArtifact {
                    privacy_generation: 0
                },
                "it was decided after the backup service stopped at the boundary"
            );
        });
    }

    /// A session that closed before privacy mode was turned on, whose output is still on the
    /// disk, owes its cleanup like every other; but no worker is recorded for it that could
    /// answer, and once the daemon's registry shows its launch is over the session is taken as
    /// ended: its obligation stays, reported with the archive named as what holds its output, and
    /// it does not hold turning privacy mode off back. The same holds after a restart, which reads
    /// the obligation back before any worker has been seen.
    #[test]
    fn a_session_with_no_worker_recorded_is_ended_and_does_not_hold_disabling_back() {
        let host = Host::open();
        host.privacy
            .enable(&[session(9)], at(0), &standing)
            .expect("privacy mode is enabled");
        let host = host.restarted();
        host.privacy.resume(at(10));
        host.privacy
            .sessions_seen(&[], &[], &host.privacy.unreached(&[], &[]), at(20))
            .expect("the workers are seen");
        let report = host.privacy.report_now(at(30));
        assert_eq!(report.obligations.len(), 1);
        assert_eq!(report.obligations[0].standing, Standing::WorkerEnded);
        let reasons = unavailable(&report, "sessions");
        assert!(
            reasons.iter().any(|reason| reason.contains("archive")),
            "{reasons:?}"
        );
        let report = host
            .privacy
            .disable(at(40), &standing)
            .expect("an ended session does not hold privacy mode on");
        assert!(!report.enabled);
        assert_eq!(
            report.obligations.len(),
            1,
            "its obligation stays until something shows its output is gone"
        );
    }

    /// A session whose launch is still in progress is not one that has ended. Its journal is on
    /// the disk, so turning privacy mode on obliges it, but its worker has not reported: the
    /// daemon finds it neither running nor recorded, and the registry shows no evidence that the
    /// launch is over. Its obligation holds turning privacy mode off back, and so does the worker
    /// once it is running, until it has been told the generation and answered that its cleanup is
    /// complete; otherwise it would come up under the generation after and never remove what it
    /// kept while privacy mode was on.
    #[test]
    fn a_session_still_launching_is_not_ended_and_holds_disabling_back() {
        let host = Host::open();
        host.privacy
            .enable(&[session(9)], at(0), &standing)
            .expect("privacy mode is enabled");
        // The daemon looks and finds no worker; the registry gives no evidence that it is over,
        // so the session is not taken as ended, whatever the tick sees next.
        assert_eq!(host.privacy.unreached(&[], &[]), vec![session(9)]);
        host.privacy
            .sessions_seen(&[], &[], &[], at(10))
            .expect("the workers are seen");
        assert_eq!(host.privacy.unreached(&[], &[]), vec![session(9)]);
        let refused = host
            .privacy
            .disable(at(20), &standing)
            .expect_err("a session that may still start holds privacy mode on");
        assert!(
            matches!(refused, ControllerError::Refused { .. }),
            "{refused:?}"
        );
        assert!(
            refused.to_string().contains(&session(9).to_string()),
            "the refusal names the session: {refused}"
        );

        // Its worker reports, is told the generation in force and answers that it is complete.
        host.privacy
            .sessions_seen(&[session(9)], &[session(9)], &[], at(30))
            .expect("the worker is seen");
        let notices = host.privacy.notices_due(at(40));
        assert_eq!(notices.len(), 1);
        assert_eq!(notices[0].session_id, session(9));
        assert!(notices[0].enabled);
        host.privacy
            .note_answer(&ack(session(9), 1, true, PrivacyCompletion::Complete))
            .expect("the answer is recorded");
        let report = host
            .privacy
            .disable(at(50), &standing)
            .expect("nothing is owed now");
        assert!(!report.enabled);
        assert!(report.obligations.is_empty());
    }

    /// How many obligations the record holds on the disk, read through a connection of its own.
    fn recorded_obligations(host: &Host) -> i64 {
        Connection::open(host.root.path().join(PRIVACY_RECORD))
            .expect("a second connection to the record")
            .query_row("SELECT COUNT(*) FROM privacy_obligations", [], |row| {
                row.get(0)
            })
            .expect("a count")
    }

    /// KR-REQ-24.27: a session launched while privacy mode is on owes its cleanup, durably, before
    /// any worker is running, so turning privacy mode off waits for it from that moment. Its worker
    /// does not exist yet, so nothing is told it: it is told, at once and not after a wait that
    /// grew while there was nobody to tell, when the daemon first finds it running.
    #[test]
    fn a_session_launched_while_privacy_mode_is_on_owes_cleanup_before_its_worker_runs() {
        let host = Host::open();
        host.privacy
            .enable(&[], at(0), &standing)
            .expect("privacy mode is enabled");
        host.privacy
            .note_session_launching(session(7), at(10))
            .expect("the launch is recorded");
        assert_eq!(recorded_obligations(&host), 1, "it is on the disk");
        let report = host.privacy.report_now(at(20));
        assert_eq!(report.obligations.len(), 1);
        assert_eq!(report.obligations[0].session_id, session(7));
        assert_eq!(report.obligations[0].generation, PrivacyGeneration::new(1));
        assert_eq!(report.obligations[0].standing, Standing::AwaitingWorker);
        assert!(!report.completion.is_complete());
        let refused = host
            .privacy
            .disable(at(30), &standing)
            .expect_err("a launch that will produce a worker holds privacy mode on");
        assert!(
            refused.to_string().contains(&session(7).to_string()),
            "{refused}"
        );
        assert_eq!(
            host.privacy.unreached(&[], &[]),
            vec![session(7)],
            "it is neither running nor over"
        );

        // Nobody is told anything while there is no worker, and no wait is spent on trying.
        for offset in [2_000, 4_000, 8_000, 16_000] {
            assert!(host.privacy.notices_due(at(offset)).is_empty());
        }
        host.privacy
            .note_session_live(session(7), at(20_000))
            .expect("the worker is running");
        let notices = host.privacy.notices_due(at(20_010));
        assert_eq!(notices.len(), 1, "told as soon as it is running");
        assert_eq!(notices[0].session_id, session(7));
        assert!(notices[0].enabled);
        assert_eq!(recorded_obligations(&host), 1, "and still one obligation");

        // Noting a launch again, as a repeated create would, does not take a running session back.
        host.privacy
            .note_session_launching(session(7), at(20_020))
            .expect("noted again");
        assert_eq!(host.privacy.notices_due(at(40_000)).len(), 1);
    }

    /// KR-REQ-24.27: a session launched while privacy mode is off owes nothing, and one that is
    /// launched and has no worker yet when privacy mode is turned on owes its cleanup like every
    /// session the environment holds, though no list names it and no journal of it exists.
    #[test]
    fn a_launch_under_way_when_privacy_mode_is_turned_on_owes_its_cleanup() {
        let host = Host::open();
        host.privacy
            .note_session_launching(session(8), at(0))
            .expect("the launch is recorded");
        let report = host.privacy.report_now(at(5));
        assert!(report.obligations.is_empty());
        assert!(report.completion.is_complete(), "{:?}", report.completion);
        assert_eq!(recorded_obligations(&host), 0);

        let report = host
            .privacy
            .enable(&[session(9)], at(10), &standing)
            .expect("privacy mode is enabled");
        let owing: Vec<SessionId> = report
            .obligations
            .iter()
            .map(|obligation| obligation.session_id)
            .collect();
        assert_eq!(owing, vec![session(8), session(9)], "both owe it");
        assert_eq!(recorded_obligations(&host), 2);
        assert!(host.privacy.disable(at(20), &standing).is_err());
    }

    /// KR-REQ-24.27: a launch whose obligation cannot be written is refused, and nothing is owed
    /// for it: no worker will come of it, so the report does not say one is awaited and privacy
    /// mode can be turned off. The same launch is recorded once the store takes it.
    #[test]
    fn a_launch_whose_obligation_cannot_be_written_owes_nothing() {
        let host = Host::open();
        host.privacy
            .enable(&[], at(0), &standing)
            .expect("privacy mode is enabled");
        let record = Connection::open(host.root.path().join(PRIVACY_RECORD)).expect("the record");
        record
            .execute_batch(
                "CREATE TRIGGER refuse_the_obligation BEFORE INSERT ON privacy_obligations
                 BEGIN SELECT RAISE(ABORT, 'this store refused the obligation'); END;",
            )
            .expect("the store will refuse the obligation");
        let refused = host
            .privacy
            .note_session_launching(session(5), at(10))
            .expect_err("the obligation could not be written");
        assert!(
            refused.to_string().contains("refused the obligation"),
            "{refused}"
        );
        let report = host.privacy.report_now(at(20));
        assert!(report.obligations.is_empty(), "{:?}", report.obligations);
        assert!(
            unavailable(&report, "sessions").is_empty(),
            "{:?}",
            report.completion
        );
        assert!(host.privacy.unreached(&[], &[]).is_empty());
        host.privacy
            .disable(at(30), &standing)
            .expect("nothing is owed for a launch that was refused");
        host.privacy
            .enable(&[], at(40), &standing)
            .expect("privacy mode is turned on again");
        record
            .execute_batch("DROP TRIGGER refuse_the_obligation")
            .expect("the store accepts the obligation");
        host.privacy
            .note_session_launching(session(5), at(50))
            .expect("the same launch is recorded once the store takes it");
        assert_eq!(recorded_obligations(&host), 1);
    }

    /// KR-REQ-24.27: a launch is recorded after a change that holds the record has finished, not
    /// before it and not around it: it waits, and what it records is the state the change left.
    #[test]
    fn a_launch_waits_for_a_change_that_holds_the_record() {
        let host = Host::open();
        let (arrived, release) = host.privacy.before_change.arm();
        std::thread::scope(|scope| {
            let enabling = scope.spawn(|| host.privacy.enable(&[], at(10), &standing));
            arrived
                .recv_timeout(std::time::Duration::from_secs(30))
                .expect("the enabling holds the record");
            let launching = scope.spawn(|| host.privacy.note_session_launching(session(3), at(20)));
            std::thread::sleep(std::time::Duration::from_millis(300));
            assert!(
                !launching.is_finished(),
                "the launch waits for the change that holds the record"
            );
            release.send(()).expect("the enabling goes on");
            enabling
                .join()
                .expect("the enabling finishes")
                .expect("privacy mode is enabled");
            launching
                .join()
                .expect("the launch finishes")
                .expect("the launch is recorded");
        });
        let report = host.privacy.report_now(at(30));
        assert_eq!(report.obligations.len(), 1);
        assert_eq!(report.obligations[0].session_id, session(3));
        assert_eq!(
            report.obligations[0].generation,
            PrivacyGeneration::new(1),
            "at the generation the change left"
        );
        assert_eq!(recorded_obligations(&host), 1);
    }

    /// KR-REQ-24.28: a launch the registry shows never produced a worker is forgotten with its
    /// obligation, durably, and does not keep privacy mode on or the report from saying complete.
    /// A refused delete keeps it owed, with nothing forgotten, until a later pass lands it.
    #[test]
    fn a_launch_that_never_started_is_discharged_once_the_store_takes_the_delete() {
        let host = Host::open();
        host.privacy
            .enable(&[], at(0), &standing)
            .expect("privacy mode is enabled");
        host.privacy
            .note_session_launching(session(5), at(10))
            .expect("the launch is recorded");
        host.privacy
            .note_session_launching(session(6), at(10))
            .expect("the launch is recorded");
        let record = Connection::open(host.root.path().join(PRIVACY_RECORD)).expect("the record");
        record
            .execute_batch(
                "CREATE TRIGGER refuse_the_delete BEFORE DELETE ON privacy_obligations
                 BEGIN SELECT RAISE(ABORT, 'this store refused the delete'); END;",
            )
            .expect("the store will refuse the delete");
        let refused = host
            .privacy
            .discharge_unstarted(&[session(5)])
            .expect_err("the delete was refused");
        assert!(
            refused.to_string().contains("refused the delete"),
            "{refused}"
        );
        assert_eq!(recorded_obligations(&host), 2, "nothing was forgotten");
        assert_eq!(host.privacy.report_now(at(20)).obligations.len(), 2);
        assert!(host.privacy.disable(at(30), &standing).is_err());

        record
            .execute_batch("DROP TRIGGER refuse_the_delete")
            .expect("the store takes the delete");
        host.privacy
            .discharge_unstarted(&[session(5)])
            .expect("the delete lands");
        assert_eq!(recorded_obligations(&host), 1);
        let report = host.privacy.report_now(at(40));
        assert_eq!(report.obligations.len(), 1);
        assert_eq!(report.obligations[0].session_id, session(6));
        assert_eq!(host.privacy.unreached(&[], &[]), vec![session(6)]);

        // The other launch ends the way a worker that ran does: its obligation stays.
        host.privacy.note_session_ended(session(6));
        let report = host
            .privacy
            .disable(at(50), &standing)
            .expect("an ended session does not hold privacy mode on");
        assert_eq!(report.obligations.len(), 1);
        assert_eq!(report.obligations[0].standing, Standing::WorkerEnded);
    }

    /// An environment that never turned privacy mode on owes its workers nothing: none is told
    /// anything at the initial generation, so the report is complete with workers running, and
    /// asking to turn it off, once or again after a pass of the tick, answers that it is off and
    /// complete.
    #[test]
    fn an_environment_that_never_turned_privacy_mode_on_owes_its_workers_nothing() {
        let host = Host::open();
        host.privacy
            .sessions_seen(
                &[session(1), session(2)],
                &[session(1), session(2)],
                &[],
                at(0),
            )
            .expect("the workers are seen");
        assert!(host.privacy.notices_due(at(10)).is_empty());
        let report = host.privacy.report_now(at(20));
        assert!(report.completion.is_complete(), "{:?}", report.completion);
        let report = host
            .privacy
            .disable(at(30), &standing)
            .expect("privacy mode is already off");
        assert!(!report.enabled);
        assert!(report.completion.is_complete(), "{:?}", report.completion);
        // A pass of the tick and a repeat of the request change nothing about that.
        let report = host.privacy.tick(at(40));
        assert!(report.completion.is_complete(), "{:?}", report.completion);
        let report = host
            .privacy
            .disable(at(50), &standing)
            .expect("privacy mode is still off");
        assert!(!report.enabled);
        assert!(report.completion.is_complete(), "{:?}", report.completion);
    }

    /// The admission is asked once the record's own transaction is held, after its wait: an action
    /// whose admission lapses while another writer holds the record changes nothing, neither the
    /// record nor the published state nor the backup fence.
    #[test]
    fn an_admission_that_lapses_while_the_record_waits_changes_nothing() {
        let host = Host::open();
        let holder = rusqlite::Connection::open(host.root.path().join(PRIVACY_RECORD))
            .expect("a second connection to the record");
        let lapsed = std::sync::atomic::AtomicBool::new(false);
        let admitted = |write: &mut dyn FnMut() -> Result<()>| {
            if lapsed.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(ControllerError::WindowExpired {
                    detail: "the action's deadline passed".to_owned(),
                });
            }
            write()
        };
        let (arrived, release) = host.privacy.before_change.arm();
        std::thread::scope(|scope| {
            let enabling = scope.spawn(|| host.privacy.enable(&[], at(10), &admitted));
            // The enabling is running, and every wait it has is still ahead of it. Another writer
            // takes the record's write lock, and the enabling goes on to wait for it.
            arrived
                .recv_timeout(std::time::Duration::from_secs(30))
                .expect("the enabling arrives");
            holder
                .execute_batch("BEGIN IMMEDIATE;")
                .expect("the record's write lock is held");
            release.send(()).expect("the enabling goes on");
            std::thread::sleep(std::time::Duration::from_millis(300));
            assert!(!enabling.is_finished(), "the record's transaction waits");
            lapsed.store(true, std::sync::atomic::Ordering::SeqCst);
            holder
                .execute_batch("ROLLBACK;")
                .expect("the write lock is let go");
            let refused = enabling.join().expect("the enabling finishes");
            assert!(
                matches!(refused, Err(ControllerError::WindowExpired { .. })),
                "{refused:?}"
            );
        });
        let stored = host
            .privacy
            .inner()
            .record
            .read()
            .expect("the record reads");
        assert_eq!(stored.generation, PrivacyGeneration::INITIAL);
        assert!(!stored.enabled);
        assert!(!host.privacy.state().is_private());
        assert_eq!(host.backup.fenced_at().expect("a read"), None);
    }

    /// KR-REQ-22.17: a description read that is deciding when privacy mode is turned on finishes
    /// before the change is published. The change waits for it, so the generated text it answers
    /// was decided before the boundary, and a read after the change answers the metadata title.
    #[test]
    fn a_description_read_in_progress_is_decided_before_privacy_mode_is_published() {
        let host = Host::open();
        let other =
            kr_describe::store::DescriptionStore::open(host.root.path()).expect("the same store");
        other
            .publish(
                &session(1),
                &crate::describe::tests::generated("Pairing check", PrivacyGeneration::INITIAL),
                900,
            )
            .expect("a description");
        let facts = kr_describe::metadata::SessionFacts {
            directory: Some("kalareach".to_owned()),
            ..kr_describe::metadata::SessionFacts::default()
        };
        let whole = crate::describe::HistoryReach::WholeSession;
        let state = host.privacy.state();
        let (arrived, release) = host.descriptions.pauses.before_decision.arm();
        std::thread::scope(|scope| {
            let release = release;
            let reading = scope.spawn(|| {
                host.descriptions
                    .describe(session(1), &facts, whole, &state)
            });
            arrived
                .recv_timeout(std::time::Duration::from_secs(30))
                .expect("the read is deciding");
            // The change is running and about to take the state's write side, which the read
            // holds a read guard of; it goes on and waits for that.
            let (enabling_arrived, enabling_release) = host.privacy.before_change.arm();
            let enabling = scope.spawn(|| host.privacy.enable(&[], at(10), &standing));
            enabling_arrived
                .recv_timeout(std::time::Duration::from_secs(30))
                .expect("the change arrives");
            enabling_release.send(()).expect("the change goes on");
            std::thread::sleep(std::time::Duration::from_millis(300));
            assert!(
                !enabling.is_finished(),
                "the change waits for the read that is deciding"
            );
            // Read from the file rather than from the state: a reader of the state would queue
            // behind the change that is waiting, as every new reader does.
            let recorded: i64 = rusqlite::Connection::open(host.root.path().join(PRIVACY_RECORD))
                .expect("a second connection to the record")
                .query_row(
                    "SELECT generation FROM privacy_record WHERE id = 0",
                    [],
                    |row| row.get(0),
                )
                .expect("the record reads");
            assert_eq!(recorded, 0, "and nothing is recorded meanwhile");
            release.send(()).expect("the read goes on");
            let answered = reading.join().expect("the read ends").expect("an answer");
            assert_eq!(
                answered.source,
                kr_protocol::describe::LabelSource::Generated,
                "decided before the boundary"
            );
            enabling
                .join()
                .expect("the change ends")
                .expect("privacy mode is enabled");
        });
        let after = host
            .descriptions
            .describe(session(1), &facts, whole, &state)
            .expect("a read");
        assert_eq!(after.source, kr_protocol::describe::LabelSource::Metadata);
        assert!(after.activity_text.0.is_none());
    }

    /// KR-REQ-22.17: a description read that waited for the store while privacy mode was turned on
    /// decides under the state as it stands once the store is its own, not under the state it
    /// found before it waited. The generated description is still in the store, its removal
    /// waiting behind the read for the store, and the read answers the metadata title.
    #[test]
    fn a_description_read_that_waited_across_the_change_answers_the_metadata_title() {
        let host = Host::open();
        let other =
            kr_describe::store::DescriptionStore::open(host.root.path()).expect("the same store");
        other
            .publish(
                &session(1),
                &crate::describe::tests::generated("Pairing check", PrivacyGeneration::INITIAL),
                900,
            )
            .expect("a description");
        let facts = kr_describe::metadata::SessionFacts {
            directory: Some("kalareach".to_owned()),
            ..kr_describe::metadata::SessionFacts::default()
        };
        let whole = crate::describe::HistoryReach::WholeSession;
        let state = host.privacy.state();
        // The read holds the store and has not looked at the state yet.
        let (arrived, release) = host.descriptions.pauses.before_reading.arm();
        std::thread::scope(|scope| {
            let release = release;
            let reading = scope.spawn(|| {
                host.descriptions
                    .describe(session(1), &facts, whole, &state)
            });
            arrived
                .recv_timeout(std::time::Duration::from_secs(30))
                .expect("the read holds the store");
            // Privacy mode is turned on and published while the read waits. The removal of the
            // generated description that follows needs the store, so it waits behind the read.
            let enabling = scope.spawn(|| host.privacy.enable(&[], at(10), &standing));
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
            while !state.is_private() {
                assert!(
                    std::time::Instant::now() < deadline,
                    "privacy mode was not published"
                );
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            assert!(!enabling.is_finished(), "the removal waits for the store");
            assert_eq!(
                other.generated_count().expect("a read"),
                1,
                "the generated description is still in the store"
            );
            release.send(()).expect("the read goes on");
            let answered = reading.join().expect("the read ends").expect("an answer");
            assert_eq!(
                answered.source,
                kr_protocol::describe::LabelSource::Metadata,
                "decided under the state after the wait"
            );
            assert!(answered.activity_text.0.is_none());
            enabling
                .join()
                .expect("the change ends")
                .expect("privacy mode is enabled");
        });
        assert_eq!(
            other.generated_count().expect("a read"),
            0,
            "the removal ran once the read was done"
        );
    }
}
