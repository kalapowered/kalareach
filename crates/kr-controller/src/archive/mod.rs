//! The environment archive service: what a session leaves behind, served with no worker.
//!
//! Section 24 gives closed history, final receipts and retained resource references an owner of
//! their own, and says what that owner is: *the environment archive service over fenced worker
//! journals and spools and an archive index. It can be a controller module; it is not a surviving
//! execution worker.* Four rules follow, and this module is each of them.
//!
//! * **Ownership is taken, and only after the worker is gone.** [`ArchiveService::take_ownership`]
//!   validates death through the kernel's own answer, then fences the worker's endpoint, and only
//!   then is anything opened. A process the operating system declines to describe is not dead; it
//!   is unanswered, and the archive leaves the session alone rather than taking a journal a live
//!   worker is writing, or deleting the endpoint of one that is still serving.
//! * **A reader cannot create a worker.** Every read here is a read of what is already on disk.
//!   There is no path from a history request to a launch, and a retried create is answered from
//!   the reservation the first one made rather than by starting a second execution.
//! * **A lost or corrupt journal produces an explicit incomplete archive.** Not an error, and not
//!   an empty success: [`Archive::incompleteness`] names what is missing, so a reader is told the
//!   record has holes rather than reading continuity into it. It names a missing or unreadable
//!   store, a missing closure or summary, a lost range of output - before the oldest cursor, or
//!   inside the retained range where a segment has gone - an interval durable writing was lost,
//!   and a recovery pass that did not run. A reader paging across a hole is told the range and
//!   given what follows it.
//! * **Privacy mode is the worker's, not the archive's.** A store recovered here is not checked
//!   for an unfinished privacy cleanup, and a content read is not held while one is owed, so a
//!   host that crashed between recording privacy mode and removing what it was asked to remove
//!   serves that content from here, and so does one whose last redaction failed. Recovery would
//!   have to read the privacy generation under ownership and run both obligations, and a content
//!   read would have to be refused while either is owed; neither is built.
//! * **A worker crash closes the session, and what it still owned is stopped first.** The closure
//!   is recorded and nothing is rebuilt from terminal history. Taking ownership removes the
//!   worker's published endpoint and descriptor; [`ArchiveService::fence_owned`] then stops what
//!   the worker recorded that the session still owned, and what a service manager's control group
//!   still holds, and reports what it ended, what it forced and what it could not end. A process
//!   that outlasts the attempt has no endpoint, no descriptor and no terminal of the session to act
//!   through, is named in the closure with where it was, and is never claimed gone.
//!
//! Retention reaches a closed session as well. A session with no worker has no maintenance tick,
//! so [`ArchiveService::collect`] applies the bounds that belong to it under recovery ownership:
//! output past seven days and receipts past thirty, each on its own budget, only on a clock the
//! caller can prove, after section 9's recovery rules have settled what the worker left
//! unfinished.
//!
//! The transfer service's one retention question is answered here too. Section 14 gives a
//! submitted attachment its session's retention rather than the seven-day unused window, and the
//! archive is what knows a closed session's retention: it holds the closure record and the
//! retained references, so it can say whether what was submitted to a session is still kept.

use kr_protocol::identity::ProcessStartIdentity;
use kr_protocol::ids::{ActorId, SessionId};
use kr_protocol::receipt::{ActionReadResult, Receipt};
use kr_protocol::recovery::{HistoryGap, HistoryGapCause, HistoryPageResult};
use kr_protocol::scalars::{Bytes, Nullable, TimestampMs, U64};
use kr_protocol::session::{ClosureRecord, SessionSummary};
use kr_worker::journal::Journal;
use kr_worker::persistence::fault::RecoveryGap;

use crate::error::{ControllerError, Result};

mod fence;
mod import;

pub use fence::{Ended, Fenced};
pub use import::{ImportOutcome, JournalImport, RefusalCause, UNACCOUNTED_WORKER};

/// The most bytes one archive history page carries.
///
/// A control frame carries [`kr_protocol::limits::MAX_CONTROL_FRAME_LEN`] in all, and a page is a
/// response with a header, cursors and a gap beside its bytes. Three quarters of the frame leaves
/// room for every one of those whatever the caller asked for.
pub const MAX_ARCHIVE_PAGE_BYTES: u64 = (kr_protocol::limits::MAX_CONTROL_FRAME_LEN as u64) * 3 / 4;

/// How long an archive waits for a process the operating system will not describe.
///
/// A query that is denied or fails is not death. Section 24 makes recovery ownership conditional
/// on validated death, so an unanswered query leaves the session alone and the archive asks
/// again; this is how long one attempt spends before it says so.
pub const DEATH_VALIDATION_ATTEMPTS: u32 = 3;

/// What an archive could not account for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Incompleteness {
    /// No journal was found where this session's journal belongs.
    JournalMissing,
    /// The journal is there and cannot be read.
    JournalUnreadable {
        /// What the store said.
        detail: String,
    },
    /// The session ended and no closure record survived it.
    ClosureMissing,
    /// No session summary survived, so the archive cannot say what the session was.
    SummaryMissing,
    /// Retained output was evicted, its spool is gone, or a range inside it is not held.
    HistoryLost {
        /// The first cursor that is missing.
        from_cursor: u64,
        /// The first cursor that is present again.
        to_cursor: u64,
    },
    /// Actions are still in a state recovery would have resolved.
    ///
    /// The archive runs section 9's recovery rules under ownership. A store that still holds an
    /// accepted intent with no marker, or a marker with no outcome, is one those rules never ran
    /// over: either ownership could not be taken, or the pass itself failed. A reader is told,
    /// because a session whose last actions have no ending is not a complete record of it.
    RecoveryUnfinished {
        /// How many actions are still in one of those states.
        unresolved: u64,
    },
    /// Durable writing was unavailable for an interval, so the record has a hole in it.
    DurabilityLost {
        /// When the fault was observed.
        from_ms: u64,
        /// When durable writing worked again.
        to_ms: u64,
    },
}

impl Incompleteness {
    /// Returns a sentence for a person, naming what is missing rather than why it matters.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::JournalMissing => "this session's journal is not on this host".to_owned(),
            Self::JournalUnreadable { detail } => {
                format!("this session's journal could not be read: {detail}")
            }
            Self::ClosureMissing => {
                "this session ended without a closure record surviving it".to_owned()
            }
            Self::SummaryMissing => "this session's own summary did not survive it".to_owned(),
            Self::HistoryLost {
                from_cursor,
                to_cursor,
            } => format!("retained output from {from_cursor} to {to_cursor} is no longer held"),
            Self::RecoveryUnfinished { unresolved } => format!(
                "{unresolved} of this session's actions have no ending, because the recovery pass \
                 that settles them did not run over this store"
            ),
            Self::DurabilityLost { from_ms, to_ms } => {
                format!("durable writing was unavailable from {from_ms} to {to_ms}")
            }
        }
    }
}

/// One resource a closed session still refers to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetainedResource {
    /// What kind of resource it is.
    pub kind: String,
    /// The opaque reference, never a client path.
    pub reference: String,
}

/// What a closed or crashed session left behind.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Archive {
    /// The session.
    pub session_id: SessionId,
    /// Its summary, when one survived.
    pub summary: Option<SessionSummary>,
    /// Its closure record, when one survived.
    pub closure: Option<ClosureRecord>,
    /// How many receipts it still holds, counted from the receipts table. It is nothing when that
    /// table cannot be read, which [`Incompleteness::JournalUnreadable`] then says.
    pub receipts: u64,
    /// The oldest cursor of retained output that can still be served.
    pub oldest_retained_cursor: u64,
    /// The cursor after the last byte of retained output.
    pub next_cursor: u64,
    /// How many bytes of output the archive holds, which is not the distance between the cursors:
    /// output that aged out is a gap and holds nothing.
    pub output_bytes: u64,
    /// Resources this session still refers to.
    pub retained: Vec<RetainedResource>,
    /// What this archive could not account for. Empty means complete.
    pub incompleteness: Vec<Incompleteness>,
}

impl Archive {
    /// Returns true when nothing is missing.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.incompleteness.is_empty()
    }

    /// Returns true when this session's own retention still covers what was submitted to it.
    ///
    /// Section 14 gives a submitted attachment its session's retention rather than the seven-day
    /// unused-attachment window. A session's retention is what the archive still holds of it: its
    /// receipts for thirty days and its output for seven. So the answer is *yes* while any of these
    /// holds:
    ///
    /// * a receipt or a byte of output is held;
    /// * something could not be read, because declining to delete is the answer that cannot lose a
    ///   file and an unreadable record is not evidence that retention has ended;
    /// * the session has a summary and no closure, which is a session still starting or one whose
    ///   end was never recorded;
    /// * the session closed less than thirty days ago, or the clock cannot say it did not.
    ///
    /// `proven_now` is the host's reading of the wall clock when it can prove it, and none when it
    /// cannot. The age of a closure is a decision the wall clock makes, and an unproved clock is
    /// how a rollback deletes what had not expired, so without a proved reading the answer is yes.
    ///
    /// The age is counted from the closure's recorded time, which is the wall clock's reading when
    /// the closure was written, with no record of whether the clock could be proved then. Once
    /// nothing else keeps the file, a clock that was behind at that moment and has been corrected
    /// since shortens the thirty days by the error.
    ///
    /// A lost range does not keep a file: age and the caps leave one behind by design, and a
    /// session whose every byte and receipt aged out would otherwise keep its files for ever. Only
    /// an archive that found nothing at all, and could read everything it looked at, answers no
    /// without a closure. The one thing that must never happen here is a *false* answer produced by
    /// not looking, because the sweep reads no as expiry and removes the payload.
    #[must_use]
    pub fn retains_submissions(&self, proven_now: Option<TimestampMs>) -> bool {
        if self.receipts > 0
            || self.output_bytes > 0
            || self
                .incompleteness
                .iter()
                .any(|reason| matches!(reason, Incompleteness::JournalUnreadable { .. }))
        {
            return true;
        }
        match &self.closure {
            Some(closure) => proven_now.is_none_or(|now| {
                now.get()
                    < closure
                        .closed_at_ms
                        .get()
                        .saturating_add(RECEIPT_RETENTION_MS)
            }),
            None => self.summary.is_some(),
        }
    }
}

/// How long a closed session's receipts are kept, which is how long a file submitted to it is.
pub const RECEIPT_RETENTION_MS: u64 = 30 * 24 * 60 * 60 * 1000;

/// What recovering a crashed session's journal resolved.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Recovered {
    /// Dispatch markers with no authoritative outcome, left `unknown` and never dispatched again.
    pub left_unknown: u64,
    /// Accepted intents with no marker, rejected because their freshness cannot be revalidated.
    pub rejected: u64,
}

/// What collecting a closed session removed, and what it could not.
///
/// The two stores are reported apart, because section 20 budgets them apart and either can fail
/// on its own: output past seven days, and receipts past thirty days.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Collected {
    /// Whether this pass collected by age at all.
    ///
    /// It is the caller's clock answer: removing what is old is expiry-based collection, which
    /// section 9 stops while the wall clock cannot be proved. It governs the two periods, seven
    /// days of output and thirty of receipts; the session's own byte cap applies either way.
    pub age_permitted: bool,
    /// Bytes of retained output that went.
    pub output_bytes: u64,
    /// Bytes of retained output still held after the pass, or none where this host could not say.
    pub output_retained: Option<u64>,
    /// Why output past its retention is still there, when some is.
    pub output_left_behind: Option<String>,
    /// Why the rows of the time index for output that went are still there, when they are. The
    /// index describes output and is not output: this does not hold the output's own collection.
    pub times_left_behind: Option<String>,
    /// What the recovery rules settled before any receipt was collected.
    pub recovered: Recovered,
    /// Receipts past their retention that went.
    pub receipts: u64,
    /// Receipts still held after the pass, or none where this host could not say.
    pub receipts_retained: Option<u64>,
    /// Why receipts past their retention are still there, when some are.
    pub receipts_left_behind: Option<String>,
}

/// Exclusive recovery ownership of one session's stores.
///
/// It exists only after the session's recovery lock is held, the endpoint is fenced and the
/// worker's death is validated, which is the order section 24 fixes: a journal taken over while its
/// worker was still writing would be two writers on one store. The lock is a file in the runtime
/// directory held for as long as this value is, so two recoveries, collections or migrations of one
/// session are kept apart, in one process and between processes, and the operating system gives it
/// back with the process that held it.
///
/// There is exactly one at a time for a session, so it is not [`Clone`]. Every operation that
/// writes a session's stores while no worker owns them takes it.
#[derive(Debug)]
pub struct RecoveryOwnership {
    /// The session whose stores this owns.
    session_id: SessionId,
    /// The identity the kernel confirmed had ended, where ownership rests on a death validated
    /// here, and none where it rests on a closure that was recorded for a worker that is gone.
    ended: Option<ProcessStartIdentity>,
    /// Whether the worker's published endpoint was removed.
    endpoint_fenced: bool,
    /// When ownership was taken.
    taken_at_ms: TimestampMs,
    _lock: RecoveryLock,
}

impl RecoveryOwnership {
    /// The session whose stores this owns, and the only one it opens.
    #[must_use]
    pub fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// The identity the kernel confirmed had ended, where ownership rests on a death validated
    /// here.
    #[must_use]
    pub fn ended(&self) -> Option<&ProcessStartIdentity> {
        self.ended.as_ref()
    }

    /// Whether the worker's published endpoint was removed.
    #[must_use]
    pub fn endpoint_fenced(&self) -> bool {
        self.endpoint_fenced
    }

    /// When ownership was taken.
    #[must_use]
    pub fn taken_at_ms(&self) -> TimestampMs {
        self.taken_at_ms
    }
}

/// The lock of one session's recovery, held until it is dropped.
#[derive(Debug)]
struct RecoveryLock {
    file: std::fs::File,
}

impl Drop for RecoveryLock {
    fn drop(&mut self) {
        // A descriptor copied into a child process keeps the lock alive after this one closes, so
        // it is let go of here and not left to the close.
        let _ = kr_flush::lock::release(&self.file);
    }
}

impl RecoveryLock {
    /// Takes the lock of `session_id`'s recovery if no one holds it, and does not wait.
    fn take(
        paths: &kr_ipc::paths::EnvironmentPaths,
        session_id: SessionId,
    ) -> std::result::Result<Self, OwnershipRefusal> {
        let unavailable = |detail: String| OwnershipRefusal::LockUnavailable {
            session: session_id.to_string(),
            detail,
        };
        kr_ipc::paths::create_private_tree(paths.runtime_root(), &paths.recoveries_dir())
            .map_err(|error| unavailable(error.to_string()))?;
        let file = kr_ipc::paths::open_lock_file(&paths.recovery_lock(session_id))
            .map_err(|error| unavailable(error.to_string()))?;
        match kr_flush::lock::try_exclusive(&file) {
            Ok(()) => Ok(Self { file }),
            Err(std::fs::TryLockError::WouldBlock) => Err(OwnershipRefusal::Held {
                session: session_id.to_string(),
            }),
            Err(std::fs::TryLockError::Error(error)) => Err(unavailable(error.to_string())),
        }
    }
}

/// Why recovery ownership could not be taken.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum OwnershipRefusal {
    /// The worker is still running.
    #[error(
        "the worker of session {session} is still running, so its stores are not the archive's"
    )]
    WorkerAlive {
        /// The session.
        session: String,
    },
    /// The operating system did not say whether the worker had ended.
    #[error(
        "the operating system did not say whether the worker of session {session} had ended: \
         {detail}"
    )]
    DeathUnvalidated {
        /// The session.
        session: String,
        /// What the platform said.
        detail: String,
    },
    /// Another recovery, collection or migration of the session holds its stores.
    #[error("session {session} is being recovered by another, so its stores are not this one's")]
    Held {
        /// The session.
        session: String,
    },
    /// The worker is gone and its published endpoint is not: it could not be removed.
    #[error(
        "the endpoint a worker of session {session} published could not be removed, so its \
         stores are not taken: {detail}"
    )]
    Unfenced {
        /// The session.
        session: String,
        /// What the file system said.
        detail: String,
    },
    /// The lock that keeps recoveries apart could not be made or taken.
    #[error("the recovery lock of session {session} could not be taken: {detail}")]
    LockUnavailable {
        /// The session.
        session: String,
        /// What the file system said.
        detail: String,
    },
    /// Something says a worker may still own the session's stores.
    #[error(
        "session {session} has a worker this host has not seen end, so a worker may still own \
         its stores and nothing of them is collected"
    )]
    WorkerMayRemain {
        /// The session.
        session: String,
    },
}

/// Why the stores of a closed session could not be owned for a collection.
#[derive(Debug, thiserror::Error)]
pub enum ClosedRefusal {
    /// The session is held, or a worker may remain.
    #[error("{0}")]
    Ownership(#[from] OwnershipRefusal),
    /// The evidence that no worker remains could not be read.
    #[error("{0}")]
    Evidence(#[from] ControllerError),
}

impl From<OwnershipRefusal> for ControllerError {
    fn from(refusal: OwnershipRefusal) -> Self {
        Self::InvalidArgument(refusal.to_string())
    }
}

/// What a daemon tells its archive about the workers of its sessions: whether one may still own a
/// session's stores, by everything the daemon holds (the registry's worker row, closure and
/// reservation, and the published descriptor).
#[derive(Clone)]
struct WorkerEvidence(std::sync::Arc<dyn Fn(SessionId) -> bool + Send + Sync>);

impl std::fmt::Debug for WorkerEvidence {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("WorkerEvidence")
    }
}

/// The environment's archive service.
#[derive(Clone, Debug)]
pub struct ArchiveService {
    paths: kr_ipc::paths::EnvironmentPaths,
    /// The daemon's answer to whether a worker may remain, where the archive is a daemon's. It is
    /// asked only when a migration is due, and a migration it answers yes to is not made.
    evidence: Option<WorkerEvidence>,
}

impl ArchiveService {
    /// Builds an archive over one environment's stores.
    #[must_use]
    pub const fn new(paths: kr_ipc::paths::EnvironmentPaths) -> Self {
        Self {
            paths,
            evidence: None,
        }
    }

    /// Makes the archive ask `a_worker_may_remain` before it migrates a store it does not own.
    ///
    /// The archive alone can tell only what the published descriptor says. A daemon knows more: a
    /// worker hands its closure over before it exits, and the closure erases the registry's row of
    /// it and retires its descriptor, so the process the launch ran is the only evidence left that
    /// the worker is still there.
    #[must_use]
    pub fn asking(
        mut self,
        a_worker_may_remain: impl Fn(SessionId) -> bool + Send + Sync + 'static,
    ) -> Self {
        self.evidence = Some(WorkerEvidence(std::sync::Arc::new(a_worker_may_remain)));
        self
    }

    /// Returns the environment this archive serves.
    #[must_use]
    pub const fn paths(&self) -> &kr_ipc::paths::EnvironmentPaths {
        &self.paths
    }

    /// Takes exclusive recovery ownership of one session's stores.
    ///
    /// The session's recovery lock comes first, so that what follows is decided by the one party
    /// that holds it. Death is validated next, and the endpoint is fenced only once it has been.
    /// Section 24 puts the fence before the journal is opened, which is what this keeps: nothing
    /// reaches the stores until the endpoint is gone. What it must not do is fence first and ask
    /// afterwards, because the answer can be *no*: a worker that is alive would then have had its
    /// published endpoint deleted by the daemon that was only enquiring, and every client of a
    /// working session would find nothing where its socket had been.
    ///
    /// Validation is the kernel's own answer, and both halves of it: the identifier and the start
    /// value, because the kernel reuses identifiers and an unrelated program can hold the number
    /// within milliseconds. Only a confirmed ending is death. A query the platform declines is
    /// not death, and leaves the session alone.
    ///
    /// The fence is part of the ownership and not a courtesy: an endpoint or a descriptor that is
    /// there and cannot be removed refuses it, because a stale socket left beside a recovered
    /// journal is the state this exists to rule out. One that is already gone is fenced.
    ///
    /// It never creates a worker, and there is no argument by which it could: what it takes is a
    /// directory and a database that already exist.
    ///
    /// # Errors
    ///
    /// Returns the [`OwnershipRefusal`]: another holds the session, the worker is alive or its
    /// death could not be validated, or the fence could not be made. Nothing has been fenced when
    /// the worker is alive or its death is unvalidated.
    pub fn take_ownership(
        &self,
        session_id: SessionId,
        display_number: kr_protocol::session::DisplayNumber,
        identity: &ProcessStartIdentity,
    ) -> std::result::Result<RecoveryOwnership, OwnershipRefusal> {
        let lock = RecoveryLock::take(&self.paths, session_id)?;
        let mut last = String::new();
        for _ in 0..DEATH_VALIDATION_ATTEMPTS {
            match kr_ipc::identity::process_state(identity) {
                kr_ipc::identity::ProcessState::Ended => {
                    let fenced =
                        self.fence_endpoint(session_id, display_number)
                            .map_err(|detail| OwnershipRefusal::Unfenced {
                                session: session_id.to_string(),
                                detail,
                            })?;
                    return Ok(RecoveryOwnership {
                        session_id,
                        ended: Some(identity.clone()),
                        endpoint_fenced: fenced,
                        taken_at_ms: kr_ipc::now_ms(),
                        _lock: lock,
                    });
                }
                kr_ipc::identity::ProcessState::Running => {
                    return Err(OwnershipRefusal::WorkerAlive {
                        session: session_id.to_string(),
                    });
                }
                kr_ipc::identity::ProcessState::Unknown { detail } => last = detail,
            }
        }
        Err(OwnershipRefusal::DeathUnvalidated {
            session: session_id.to_string(),
            detail: last,
        })
    }

    /// Takes exclusive ownership of the stores of a session that has already closed, for the
    /// collection of what it retains.
    ///
    /// There is no process to validate here: the caller's `a_worker_may_remain` is every piece of
    /// evidence the host holds that one is gone, asked **with the lock held**, so that no other
    /// recovery can change the answer between the question and the use. A closure the registry
    /// recorded, a worker row, the closure's own list of a worker it never saw end and the
    /// published descriptor are the evidence, and the caller reads all of them.
    ///
    /// # Errors
    ///
    /// Returns [`OwnershipRefusal::Held`] when another holds the session,
    /// [`OwnershipRefusal::WorkerMayRemain`] when `a_worker_may_remain` says a worker may, and
    /// whatever it fails with otherwise.
    pub fn own_closed(
        &self,
        session_id: SessionId,
        a_worker_may_remain: impl FnOnce() -> Result<bool>,
    ) -> std::result::Result<RecoveryOwnership, ClosedRefusal> {
        let lock = RecoveryLock::take(&self.paths, session_id)?;
        if a_worker_may_remain()? {
            return Err(OwnershipRefusal::WorkerMayRemain {
                session: session_id.to_string(),
            }
            .into());
        }
        Ok(RecoveryOwnership {
            session_id,
            ended: None,
            endpoint_fenced: false,
            taken_at_ms: kr_ipc::now_ms(),
            _lock: lock,
        })
    }

    /// Returns whether a worker this host has not seen end may still own this session.
    ///
    /// The published descriptor names the process, and it outlives the worker that wrote it. A
    /// kernel answer of `Ended` is the only one that clears this: `Running` is a worker, and a
    /// query the platform declines establishes nothing, which is not the same as establishing
    /// that there is nothing there.
    ///
    /// This is one of three things that can say so, and it is the one a live session has: a
    /// worker publishes a descriptor when it starts. It does not outlast a closure - writing one
    /// retires the descriptor along with the registry's worker row - so a session closed without a
    /// confirmed death is answered for by the closure's own surviving list instead. The daemon's
    /// `a_worker_may_still_own` asks all three; this half is here because a migration is a write
    /// and must be able to refuse on its own.
    #[must_use]
    pub fn a_worker_may_still_own(&self, session_id: SessionId) -> bool {
        match kr_ipc::descriptor::read(&self.paths, session_id) {
            // A descriptor names the process. Only `Ended` clears this: `Running` is a worker, and
            // a query the platform declines establishes nothing, which is not the same as
            // establishing that there is nothing there.
            Ok(Some(descriptor)) => !matches!(
                kr_ipc::identity::process_state(&descriptor.process_start_identity),
                kr_ipc::identity::ProcessState::Ended
            ),
            // No descriptor is a session this host fenced or one that never published, and either
            // way there is nothing here to ask about. Absence is not a death, which is why this
            // only ever gates a *write*: a read of a store nobody published a descriptor for is
            // the ordinary archive case, and the caller's own liveness check covers it.
            Ok(None) => false,
            // A directory this host could not read answers nothing at all, and a migration is a
            // write. It is refused rather than guessed at.
            Err(_) => true,
        }
    }

    /// Brings a store an earlier build wrote forward, so this build's one reader can read it.
    ///
    /// Section 24 asks for forward-only migrations and one current schema read by code. A worker
    /// migrates its own store when it opens it. A session that closed before this build shipped
    /// has no worker to do that, and its store would otherwise be refused for ever by the
    /// read-only opener, taking with it the shell, the directory, the geometry and the creation
    /// time a person is shown for a closed session.
    ///
    /// So the archive does it once, here, and only here: the store is opened writable, migrated,
    /// and closed again before anything reads it. It runs on a session with no live worker, which
    /// is what every caller of this establishes first, because migrating a store a worker still
    /// owns would be a second writer.
    ///
    /// A store already at the current version is not opened at all. A store older than the ladder
    /// is left alone and reported by the reader, because restoring one in part is worse than
    /// saying it cannot be read.
    ///
    /// An archive that belongs to a daemon ([`Self::asking`]) also asks the daemon, once a
    /// migration is due, whether a worker of the session may remain, and leaves the store where it
    /// is when one may.
    pub fn bring_forward(&self, session_id: SessionId) {
        self.bring_forward_with(session_id, None);
    }

    /// Brings a store forward as [`Self::bring_forward`] does, for the recovery that owns it.
    ///
    /// A migration is a write, so it is made under the session's recovery lock. The recovery that
    /// holds that lock is the one that calls this, and it needs no second hold on it.
    pub fn bring_forward_owned(&self, ownership: &RecoveryOwnership) {
        self.bring_forward_with(ownership.session_id, Some(ownership));
    }

    fn bring_forward_with(&self, session_id: SessionId, owned: Option<&RecoveryOwnership>) {
        // A migration is a write, so it asks the question recovery ownership asks, and asks it
        // here rather than trusting a caller: a session whose published descriptor names a process
        // the kernel has not said ended may still own this store, and a closure written over an
        // unvalidated death does not change that. The store is then left where it is and the
        // reader reports it, which is the safe direction.
        if self.a_worker_may_still_own(session_id) {
            return;
        }
        let path = self.paths.journal_database(session_id);
        if !path.exists() {
            return;
        }
        let Ok(recorded) = Journal::recorded_schema_version(&path) else {
            return;
        };
        if recorded == kr_worker::persistence::migration::CURRENT
            || kr_worker::persistence::migration::plan(recorded).is_err()
        {
            return;
        }
        // The daemon's evidence is asked only now that there is something to write, and not for the
        // recovery that owns the store: its death was validated by the kernel.
        if owned.is_none()
            && self
                .evidence
                .as_ref()
                .is_some_and(|ask| (ask.0)(session_id))
        {
            return;
        }
        // The lock is taken only when there is something to write, and not waited for: a store
        // another recovery holds is left to it, and the reader reports it until it is done.
        let _held = if owned.is_some() {
            None
        } else {
            match RecoveryLock::take(&self.paths, session_id) {
                Ok(lock) => Some(lock),
                Err(_) => return,
            }
        };
        #[cfg(test)]
        while_migrating::run(session_id);
        // `Journal::open` migrates and then holds the current schema. Dropping it immediately is
        // what keeps this a migration rather than a second reader.
        drop(Journal::open(&path));
    }

    /// Removes the worker's published endpoint and descriptor, and returns whether anything went.
    ///
    /// Fencing is not a message to the worker. A worker that has crashed cannot be told anything;
    /// what this does is stop a client finding a socket that no longer has a process behind it,
    /// and stop a restarted daemon rebuilding its directory from a descriptor for a session that
    /// has ended. It runs only after death is validated, because the endpoint it removes belongs
    /// to a session that may still be serving.
    ///
    /// A file that is not there is fenced. A file that is there and cannot be removed is not, and
    /// is returned as the reason.
    fn fence_endpoint(
        &self,
        session_id: SessionId,
        display_number: kr_protocol::session::DisplayNumber,
    ) -> std::result::Result<bool, String> {
        let remove = |path: &std::path::Path| -> std::result::Result<bool, String> {
            match std::fs::remove_file(path) {
                Ok(()) => Ok(true),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
                Err(error) => Err(format!("{}: {error}", path.display())),
            }
        };
        let mut fenced = remove(&self.paths.descriptor_file(session_id))?;
        if let Ok(endpoint) = self.paths.worker_endpoint(display_number) {
            // On Windows the endpoint is the name of a pipe, which has no file to remove and goes
            // with the process that made it.
            #[cfg(unix)]
            {
                fenced |= remove(endpoint.as_path())?;
            }
            #[cfg(not(unix))]
            {
                fenced |= std::fs::remove_file(endpoint.as_path()).is_ok();
            }
        }
        Ok(fenced)
    }

    /// Recovers a crashed session's journal, under ownership, without creating one.
    ///
    /// Section 9's two recovery rules are the worker's, and a worker that crashed never ran them.
    /// The archive runs them once instead: a dispatch marker with no authoritative outcome
    /// becomes `unknown` and is never dispatched again, and an accepted intent with no marker is
    /// rejected, because the freshness it was admitted under cannot be revalidated after the
    /// process that issued it has gone. Without this a crashed session would serve `dispatching`
    /// for ever, which says an effect may be about to happen on a host where nothing is running.
    ///
    /// It opens the journal that is there and creates none: a session with no journal has nothing
    /// to recover, and inventing an empty one would replace an incomplete archive with a
    /// confident empty one.
    ///
    /// # Errors
    ///
    /// Returns the store's refusal when the journal is there and cannot be recovered.
    pub fn recover_journal(&self, ownership: &RecoveryOwnership) -> Result<Recovered> {
        let path = self.paths.journal_database(ownership.session_id);
        if !path.exists() {
            return Ok(Recovered::default());
        }
        // The opener that creates nothing. A journal that went between the look and the open, or
        // a file that is not one this build wrote, is reported rather than replaced with an empty
        // store that would read as a session which kept nothing.
        let mut journal = Journal::open_existing(&path)
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?;
        recover_open(&mut journal)
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))
    }

    /// Applies section 20's retention to a session with no worker, under recovery ownership.
    ///
    /// A closed session has no maintenance tick of its own, so without this its output would stay
    /// past section 20's seven days and its receipts past their thirty for as long as this host
    /// kept the files. The archive runs the collections the worker runs, on the same budgets and
    /// apart: output past seven days, and receipts past thirty. Section 9's recovery rules run over
    /// the journal first, so no receipt goes while its action has no ending.
    ///
    /// `age_permitted` is the caller's clock answer, as it is for the worker: removing what is old
    /// on a clock this host cannot prove is how a rollback deletes what had not expired, so
    /// neither store is collected by age without it. The recovery rules run either way, and the
    /// session's own byte cap is applied either way. The host-wide cap is not applied here: it is
    /// decided across the whole environment rather than one session at a time.
    ///
    /// Each store's failure is reported in its own field rather than failing the other, and a
    /// segment that could not be removed is still counted and still served until a later pass
    /// removes it.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::InvalidArgument`] when a worker may still own the session, and
    /// nothing is collected then.
    pub fn collect(
        &self,
        ownership: &RecoveryOwnership,
        now_ms: TimestampMs,
        age_permitted: bool,
    ) -> Result<Collected> {
        let session_id = ownership.session_id;
        // A collection is a write. The ownership taken says the worker it names has ended; the
        // published descriptor is asked as well, because a worker that is still serving is the
        // one thing that must never have its stores collected under it.
        if self.a_worker_may_still_own(session_id) {
            return Err(OwnershipRefusal::WorkerMayRemain {
                session: session_id.to_string(),
            }
            .into());
        }
        let mut collected = Collected {
            age_permitted,
            ..Collected::default()
        };
        self.collect_receipts(session_id, now_ms, &mut collected);
        self.collect_output(session_id, now_ms, &mut collected);
        Ok(collected)
    }

    /// Settles the journal's unfinished actions, then removes the receipts past their period.
    fn collect_receipts(&self, session_id: SessionId, now_ms: TimestampMs, into: &mut Collected) {
        let path = self.paths.journal_database(session_id);
        match path.try_exists() {
            Ok(true) => {}
            Ok(false) => {
                into.receipts_retained = Some(0);
                return;
            }
            // A store this host cannot even look for is not one it may report as empty.
            Err(error) => {
                into.receipts_left_behind = Some(format!(
                    "this session's journal could not be looked for: {error}"
                ));
                return;
            }
        }
        let mut journal = match Journal::open_existing(&path) {
            Ok(journal) => journal,
            Err(error) => {
                into.receipts_left_behind = Some(error.to_string());
                return;
            }
        };
        match recover_open(&mut journal) {
            Ok(recovered) => into.recovered = recovered,
            Err(error) => {
                // A receipt whose action has no ending is not one to collect, so a pass whose
                // recovery failed collects none.
                into.receipts_left_behind = Some(error.to_string());
                return;
            }
        }
        if into.age_permitted {
            match journal.prune(now_ms) {
                Ok(removed) => into.receipts = removed as u64,
                Err(error) => into.receipts_left_behind = Some(error.to_string()),
            }
        }
        // What is left is told only when the table says so: a table that cannot be read leaves
        // the figure unknown.
        into.receipts_retained = journal.len_checked().ok();
    }

    /// Applies the output bounds that belong to the session: its age, on a clock the caller can
    /// prove, and its own cap, on any clock.
    fn collect_output(&self, session_id: SessionId, now_ms: TimestampMs, into: &mut Collected) {
        // A worker killed while it made the session's time index left the file it was building,
        // which nothing else names, and the session has no worker to make it again.
        into.times_left_behind = kr_worker::output_times::remove_unfinished(
            &self.paths.session_output_times(session_id),
        )
        .err();
        let directory = self.paths.session_spool(session_id);
        match directory.try_exists() {
            Ok(true) => {}
            Ok(false) => {
                into.output_retained = Some(0);
                return;
            }
            Err(error) => {
                into.output_left_behind = Some(format!(
                    "this session's spool could not be looked for: {error}"
                ));
                return;
            }
        }
        // The opener that creates and repairs nothing: collection removes what is past its
        // bounds, and a directory that is not there is not one to make.
        let mut history = match kr_worker::history::OutputHistory::read_spool(
            &directory,
            kr_worker::history::SpoolLayout::DEFAULT,
        ) {
            Ok(history) => history.with_time_index(self.paths.session_output_times(session_id)),
            Err(error) => {
                into.output_left_behind = Some(error.to_string());
                return;
            }
        };
        // The session's own figure stands for the host's, so the host cap is not what this pass
        // applies.
        let held = history.retained_bytes();
        let taken = history.apply_retention(
            kr_worker::persistence::retention::OutputRetention::DEFAULT,
            held,
            now_ms,
            into.age_permitted,
        );
        into.output_bytes = taken.iter().map(|eviction| eviction.bytes).sum();
        into.output_retained = Some(history.retained_bytes());
        into.output_left_behind = history.left_behind().map(str::to_owned);
        into.times_left_behind = history
            .flush_times()
            .err()
            .or_else(|| into.times_left_behind.take());
    }

    /// Gives up output of a closed session so that the host-wide cap holds, and returns how many
    /// bytes went.
    ///
    /// `excess` is how far over the cap the host is. The session gives up what it can of it, oldest
    /// output first, and no more than it holds; the caller goes on to the next session with what is
    /// left. Only the caps are applied: age is [`Self::collect`]'s, and it needs a clock the host
    /// can prove, which a cap does not.
    ///
    /// # Errors
    ///
    /// Returns an error when a worker may still own the session, and nothing is taken then.
    pub fn collect_over_host_cap(
        &self,
        ownership: &RecoveryOwnership,
        retention: kr_worker::persistence::retention::OutputRetention,
        excess: u64,
        now_ms: TimestampMs,
    ) -> Result<u64> {
        let session_id = ownership.session_id;
        if self.a_worker_may_still_own(session_id) {
            return Err(OwnershipRefusal::WorkerMayRemain {
                session: session_id.to_string(),
            }
            .into());
        }
        let directory = self.paths.session_spool(session_id);
        if !directory.try_exists().unwrap_or(false) {
            return Ok(0);
        }
        let mut history = kr_worker::history::OutputHistory::read_spool(
            &directory,
            kr_worker::history::SpoolLayout::DEFAULT,
        )
        .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?
        .with_time_index(self.paths.session_output_times(session_id));
        // The host figure this session reports is the cap and the excess, so the most it gives up
        // is the excess, bounded by what it holds.
        let taken = history.apply_retention(
            retention,
            retention.host_cap_bytes.saturating_add(excess),
            now_ms,
            false,
        );
        let _ = history.flush_times();
        Ok(taken.iter().map(|eviction| eviction.bytes).sum())
    }

    /// Reads when a closed session's output was produced, between two cursors.
    ///
    /// The index is read from the file the session's worker left. A session whose worker has not
    /// gone is the caller's to refuse, as it is for a page of its output.
    ///
    /// # Errors
    ///
    /// Returns why the index could not be read, which a caller states and does not hide: output
    /// with no recorded time is declared as that.
    pub fn history_times(
        &self,
        session_id: SessionId,
        from_cursor: u64,
        to_cursor: u64,
        limit: usize,
    ) -> std::result::Result<kr_worker::output_times::Times, kr_worker::output_times::Unavailable>
    {
        kr_worker::output_times::read(
            &self.paths.session_output_times(session_id),
            from_cursor,
            to_cursor,
            limit,
        )
    }

    /// Reads what one session left behind.
    ///
    /// A journal that is missing, or that is there and cannot be read, produces an archive that
    /// says so rather than an error or an empty success. That is section 24's explicit incomplete
    /// archive, and it is the difference between "this session kept nothing" and "this host
    /// cannot say what this session kept".
    ///
    /// # Errors
    ///
    /// Returns an error only when a path this host owns cannot be built. Everything about the
    /// stores themselves is reported as incompleteness.
    pub fn archive(&self, session_id: SessionId) -> Result<Archive> {
        self.archive_beside(session_id, None)
    }

    /// Reads what one session left behind, beside a closure the caller already holds.
    ///
    /// A crashed worker never wrote its own closure, and the record the controller writes for it
    /// lives in the registry. Passing it in is what stops the archive reporting a closure as
    /// missing when this host has one: the journal is the authority when it has one, and the
    /// caller's record is what answers when it has not.
    ///
    /// # Errors
    ///
    /// Returns an error only when a path this host owns cannot be built.
    pub fn archive_beside(
        &self,
        session_id: SessionId,
        recorded: Option<ClosureRecord>,
    ) -> Result<Archive> {
        self.bring_forward(session_id);
        let path = self.paths.journal_database(session_id);
        let mut incompleteness = Vec::new();
        let mut archive = Archive {
            session_id,
            summary: None,
            closure: None,
            receipts: 0,
            oldest_retained_cursor: 0,
            next_cursor: 0,
            output_bytes: 0,
            retained: Vec::new(),
            incompleteness: Vec::new(),
        };
        archive.closure = recorded;
        if !path.exists() {
            archive.incompleteness.push(Incompleteness::JournalMissing);
            if archive.closure.is_none() {
                archive.incompleteness.push(Incompleteness::ClosureMissing);
            }
            self.read_history_into(session_id, &mut archive);
            return Ok(archive);
        }
        // Read-only, and it never creates. A journal this host cannot open is a journal it
        // reports rather than one it replaces with an empty new database.
        match Journal::open_read_only(&path) {
            Ok(journal) => {
                match journal.read_session(session_id) {
                    Ok(Some(summary)) => archive.summary = Some(summary),
                    Ok(None) => incompleteness.push(Incompleteness::SummaryMissing),
                    Err(error) => incompleteness.push(Incompleteness::JournalUnreadable {
                        detail: error.to_string(),
                    }),
                }
                match journal.read_closure(session_id) {
                    // The worker's own record is the authority: it knows the root's result, what
                    // it stopped and how much of that it could account for, and a record written
                    // from outside knows none of those.
                    Ok(Some(closure)) => archive.closure = Some(closure),
                    Ok(None) if archive.closure.is_none() => {
                        incompleteness.push(Incompleteness::ClosureMissing);
                    }
                    Ok(None) => {}
                    Err(error) => incompleteness.push(Incompleteness::JournalUnreadable {
                        detail: error.to_string(),
                    }),
                }
                match journal.unresolved_work() {
                    Ok(0) => {}
                    Ok(unresolved) => {
                        incompleteness.push(Incompleteness::RecoveryUnfinished { unresolved });
                    }
                    Err(error) => incompleteness.push(Incompleteness::JournalUnreadable {
                        detail: error.to_string(),
                    }),
                }
                // Checked and counted from the table itself: the cheaper count comes from an
                // index, which reads whole in a store whose receipts table does not, and a count
                // the table has not stood behind is not one to report. A table that cannot be
                // read leaves the count at nothing claimed and the archive incomplete.
                match journal.len_checked() {
                    Ok(count) => archive.receipts = count,
                    Err(error) => incompleteness.push(Incompleteness::JournalUnreadable {
                        detail: error.to_string(),
                    }),
                }
                match journal.recovery_gaps() {
                    Ok(gaps) => incompleteness.extend(gaps.iter().map(durability_lost)),
                    // A record of lost durability that cannot itself be read is a store this host
                    // cannot account for, not a store with no gaps in it.
                    Err(error) => incompleteness.push(Incompleteness::JournalUnreadable {
                        detail: error.to_string(),
                    }),
                }
            }
            Err(error) => incompleteness.push(Incompleteness::JournalUnreadable {
                detail: error.to_string(),
            }),
        }
        archive.incompleteness = incompleteness;
        self.read_history_into(session_id, &mut archive);
        Ok(archive)
    }

    /// Reads one page of a closed session's retained output.
    ///
    /// It opens the spool directory and nothing else. A cursor inside a range that is gone is
    /// answered with the gap, exactly as a live worker answers it, so a reader that pages a
    /// closed session and a reader that pages a live one are told the same kind of thing.
    ///
    /// # Errors
    ///
    /// Returns an error when a spool segment is there and cannot be read.
    pub fn history_page(
        &self,
        session_id: SessionId,
        from_cursor: u64,
        max_bytes: u64,
    ) -> Result<HistoryPageResult> {
        let directory = self.paths.session_spool(session_id);
        if !directory.exists() {
            // Nothing was retained, or what was retained is gone. Either way the answer is an
            // explicit gap rather than an empty page that reads as "nothing ever happened".
            return Ok(HistoryPageResult {
                from_cursor: U64::new(from_cursor),
                next_cursor: U64::new(from_cursor),
                bytes: Bytes::new(Vec::new()),
                oldest_retained_cursor: U64::new(from_cursor),
                gap: Nullable::some(HistoryGap {
                    from_cursor: U64::new(0),
                    to_cursor: U64::new(from_cursor),
                    cause: Some(HistoryGapCause::ArchiveIncomplete),
                }),
            });
        }
        let history = kr_worker::history::OutputHistory::read_spool(
            &directory,
            kr_worker::history::SpoolLayout::DEFAULT,
        )
        .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?;
        // The page is bounded by what one control frame carries, because the archive answers over
        // the same endpoint a live worker's page does and a page that could not be encoded would
        // be a page nobody receives.
        history
            .page(from_cursor, max_bytes.min(MAX_ARCHIVE_PAGE_BYTES))
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))
    }

    /// Reads one retained receipt of a closed session, as its reader is shown it.
    ///
    /// `owner` says whether the reader is the owner at this machine on its own socket. The owner
    /// is shown the receipt and its result whole. Any other reader is shown the state of the
    /// action and none of what it carries: the error's text and a question's content are withheld,
    /// and a close's description of the session with them, because a closed session's history is
    /// not the reader's to be shown by a later read ([`kr_worker::history_filter::retained`]).
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::UnknownSession`] when this host holds no journal for the
    /// session, an invalid-argument failure when no receipt answers, and a refusal when the
    /// result is one a reader who is not the owner is not shown at all.
    pub fn receipt(
        &self,
        session_id: SessionId,
        actor_id: &ActorId,
        action_id: kr_protocol::ids::ActionId,
        owner: bool,
    ) -> Result<ActionReadResult> {
        use kr_worker::history_filter::retained::{
            Disclosure, Occasion, shown_receipt, shown_result, withheld_entirely,
        };

        self.bring_forward(session_id);
        let path = self.paths.journal_database(session_id);
        if !path.exists() {
            return Err(ControllerError::UnknownSession {
                session: session_id.to_string(),
            });
        }
        let journal = Journal::open_read_only(&path)
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?;
        let receipt: Receipt = journal
            .read(actor_id.clone(), action_id)
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?
            .ok_or_else(|| {
                ControllerError::InvalidArgument(format!("no receipt for action {action_id}"))
            })?;
        let retained = journal
            .read_result(actor_id, action_id)
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?;
        let disclosure = if owner {
            Disclosure::Whole
        } else {
            Disclosure::StateOnly
        };
        let refused = |error: kr_worker::error::WorkerError| {
            ControllerError::refused(&error.to_protocol_error())
        };
        let result = retained
            .map(|bytes| {
                let value = kr_cbor::decode(&bytes, &kr_cbor::Limits::DEFAULT)
                    .map(kr_protocol::envelope::ParamsValue::new)
                    .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?;
                // A result is shown by the method that kept it, which the receipt names. A method
                // this build does not know is the owner's to read as it is, and nobody else's.
                match receipt.method.method() {
                    Some(method) => {
                        shown_result(&disclosure, method, value, Occasion::Replay).map_err(refused)
                    }
                    None if owner => Ok(value),
                    None => Err(refused(withheld_entirely())),
                }
            })
            .transpose()?;
        Ok(ActionReadResult {
            receipt: shown_receipt(&disclosure, receipt),
            result: Nullable(result),
        })
    }

    /// Returns whether a session's retention still covers what was submitted to it.
    ///
    /// This is the transfer sweep's one question, answered by the store that owns the answer.
    ///
    /// # Errors
    ///
    /// Returns an error only when a path this host owns cannot be built.
    pub fn retains_submissions(
        &self,
        session_id: SessionId,
        recorded: Option<ClosureRecord>,
        proven_now: Option<TimestampMs>,
    ) -> Result<bool> {
        Ok(self
            .archive_beside(session_id, recorded)?
            .retains_submissions(proven_now))
    }

    /// Returns every session this host still holds a journal or a spool for.
    ///
    /// The sweep needs the union of what the registry knows and what is on disk, because a
    /// session the registry has finished with still keeps what was submitted to it while its
    /// archive is there.
    ///
    /// A scan this host could not complete is an error rather than a shorter list. The sweep
    /// reads a session's absence as expiry and removes its payload, so a directory that could not
    /// be read must stop the sweep rather than quietly shrink its answer.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::InvalidArgument`] when a directory this host owns cannot be
    /// read. A directory that is simply not there is not an error: a host with no journals yet
    /// has no sessions on disk.
    pub fn sessions_on_disk(&self) -> Result<Vec<SessionId>> {
        let mut found = std::collections::BTreeSet::new();
        for (directory, prefix, suffix) in [
            (self.paths.journals_dir(), "session-", ".sqlite"),
            (self.paths.spool_dir(), "", ".log"),
        ] {
            let entries = match std::fs::read_dir(&directory) {
                Ok(entries) => entries,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => {
                    return Err(ControllerError::InvalidArgument(format!(
                        "{} could not be read, so this host cannot say which sessions it holds: \
                         {error}",
                        directory.display()
                    )));
                }
            };
            for entry in entries {
                let entry = entry.map_err(|error| {
                    ControllerError::InvalidArgument(format!(
                        "{} could not be read to the end: {error}",
                        directory.display()
                    ))
                })?;
                let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                    continue;
                };
                let Some(rest) = name.strip_prefix(prefix) else {
                    continue;
                };
                let Some(identifier) = rest.strip_suffix(suffix) else {
                    continue;
                };
                if let Ok(uuid) = identifier.parse::<kr_protocol::scalars::Uuid>() {
                    found.insert(SessionId::new(uuid));
                }
            }
        }
        Ok(found.into_iter().collect())
    }

    fn read_history_into(&self, session_id: SessionId, archive: &mut Archive) {
        let directory = self.paths.session_spool(session_id);
        if !directory.exists() {
            // A session this host has some other record of once retained output, and its spool is
            // not there: this host cannot tell an empty spool from a lost one, so it says the
            // range is missing rather than reporting an archive with nothing missing. A session
            // it has no record of at all is a different thing - there is nothing it has lost,
            // because there was never anything of it here.
            if archive.summary.is_some() || archive.closure.is_some() || archive.receipts > 0 {
                archive.incompleteness.push(Incompleteness::HistoryLost {
                    from_cursor: 0,
                    to_cursor: 0,
                });
            }
            return;
        }
        let Ok(history) = kr_worker::history::OutputHistory::read_spool(
            &directory,
            kr_worker::history::SpoolLayout::DEFAULT,
        ) else {
            // A spool that is there and cannot be read is a range this host cannot account for.
            archive
                .incompleteness
                .push(Incompleteness::JournalUnreadable {
                    detail: "this session's output spool could not be read".to_owned(),
                });
            return;
        };
        archive.oldest_retained_cursor = history.oldest_retained_cursor();
        archive.next_cursor = history.next_cursor();
        archive.output_bytes = history.retained_bytes();
        if history.boundary_unreadable() {
            // This session recorded where its output got to and this host cannot read it back, so
            // the range it is missing is not a range this host can name.
            archive
                .incompleteness
                .push(Incompleteness::JournalUnreadable {
                    detail: "this session's spool recorded where its output got to and it cannot \
                             be read back"
                        .to_owned(),
                });
        }
        if archive.oldest_retained_cursor > 0 {
            archive.incompleteness.push(Incompleteness::HistoryLost {
                from_cursor: 0,
                to_cursor: archive.oldest_retained_cursor,
            });
        }
        // What lies between the oldest cursor and the boundary is continuous only when the
        // segments meet. A range no segment covers is output this host cannot account for,
        // whatever took it, and it is reported beside the range before the oldest cursor.
        for (from_cursor, to_cursor) in history.holes() {
            archive.incompleteness.push(Incompleteness::HistoryLost {
                from_cursor,
                to_cursor,
            });
        }
        archive.retained.push(RetainedResource {
            kind: "output_spool".to_owned(),
            reference: format!("{session_id}"),
        });
    }
}

/// Runs section 9's two recovery rules over a journal the archive has open under ownership.
///
/// A dispatch marker with no authoritative outcome becomes `unknown` and is never dispatched
/// again; an accepted intent with no marker is rejected, because the freshness it was admitted
/// under cannot be revalidated after the process that issued it has gone.
fn recover_open(journal: &mut Journal) -> std::result::Result<Recovered, kr_worker::WorkerError> {
    let now = kr_ipc::now_ms();
    let unknown = journal.resolve_unfinished_dispatches(now)?;
    let rejected = journal.reject_unrevalidated_intents(now)?;
    Ok(Recovered {
        left_unknown: unknown as u64,
        rejected: rejected as u64,
    })
}

fn durability_lost(gap: &RecoveryGap) -> Incompleteness {
    Incompleteness::DurabilityLost {
        from_ms: gap.faulted_at_ms.get(),
        to_ms: gap.recovered_at_ms.get(),
    }
}

/// A step of a test that runs inside a migration, with the session's recovery lock held.
#[cfg(test)]
pub(crate) mod while_migrating {
    use std::sync::Mutex;

    use kr_protocol::ids::SessionId;

    type Step = Box<dyn FnOnce() + Send>;

    static NEXT: Mutex<Option<(SessionId, Step)>> = Mutex::new(None);

    /// Makes the next migration of `session_id` run `step` once it holds the session's lock and
    /// before it opens the store.
    pub(crate) fn run_once(session_id: SessionId, step: impl FnOnce() + Send + 'static) {
        *NEXT
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            Some((session_id, Box::new(step)));
    }

    pub(super) fn run(session_id: SessionId) {
        let step = {
            let mut next = NEXT
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match next.take() {
                Some((session, step)) if session == session_id => Some(step),
                other => {
                    *next = other;
                    None
                }
            }
        };
        if let Some(step) = step {
            step();
        }
    }
}

impl crate::service::Controller {
    /// Returns this environment's archive, asking this daemon's evidence before it migrates a store.
    #[must_use]
    pub fn archive(&self) -> ArchiveService {
        ArchiveService::new(self.paths().clone()).asking(self.asker_of_a_worker_that_may_remain())
    }

    /// Returns the sessions whose archives still keep what was submitted to them.
    ///
    /// Section 14 gives a submitted attachment its session's retention, and this is where that
    /// question is answered now. Two authorities know about sessions and the answer is the union
    /// of them, because the sweep reads a missing session as expiry and removes its payload: the
    /// registry, which lists every reservation in any launch phase and every worker row, and the
    /// archive, which holds the journal and the spool of a session the registry has finished
    /// with. A session either of them knows about keeps what was submitted to it.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the registry cannot be read.
    pub fn archive_retention(&self) -> Result<ArchiveRetention> {
        let archive = self.archive();
        let mut candidates = std::collections::BTreeSet::new();
        {
            let registry = self.registry_handle().blocking_lock();
            for phase in EVERY_LAUNCH_PHASE {
                for reservation in registry.reservations_in(*phase)? {
                    candidates.insert(reservation.session_id);
                }
            }
            for worker in registry.workers()? {
                candidates.insert(worker.session_id);
            }
        }
        let mut retention = ArchiveRetention::default();
        // Every session the registry lists keeps what was submitted to it, whatever its journal
        // says: the registry is a record of the session, and a record is what retention is about.
        for session_id in &candidates {
            retention.insert(*session_id);
        }
        // Then the sessions only the archive knows about, which are the ones the registry has
        // finished with. Asking the archive about each is what makes this the union rather than
        // the registry's answer with a different name on it.
        for session_id in archive.sessions_on_disk()? {
            if candidates.contains(&session_id) {
                continue;
            }
            if archive.retains_submissions(session_id, None, None)? {
                retention.insert(session_id);
            }
        }
        Ok(retention)
    }
}

/// Every launch phase a session's reservation can be in.
///
/// A session with a reservation in any of them is one this host still knows about, including a
/// failed or closed one: what was submitted to a session is kept by that session's retention
/// rather than by whether it is still running.
const EVERY_LAUNCH_PHASE: &[crate::registry::LaunchPhase] = &[
    crate::registry::LaunchPhase::Reserved,
    crate::registry::LaunchPhase::Spawned,
    crate::registry::LaunchPhase::Claimed,
    crate::registry::LaunchPhase::Live,
    crate::registry::LaunchPhase::Fenced,
    crate::registry::LaunchPhase::Failed,
    crate::registry::LaunchPhase::Closed,
];

/// The sessions an environment's archive still keeps what was submitted to.
///
/// This is the answer the transfer sweep asks for, behind the archive's interface rather than the
/// registry's. The difference matters: the registry knows which sessions it has a reservation
/// for, and the archive knows which sessions still have a record. A session whose reservation was
/// cleaned up but whose archive survives keeps its attachments; one with neither keeps nothing.
#[derive(Clone, Debug, Default)]
pub struct ArchiveRetention {
    sessions: std::collections::BTreeSet<SessionId>,
}

impl ArchiveRetention {
    /// Records one session as retained.
    pub fn insert(&mut self, session_id: SessionId) {
        self.sessions.insert(session_id);
    }

    /// Returns true when this session keeps what was submitted to it.
    #[must_use]
    pub fn retains(&self, session_id: SessionId) -> bool {
        self.sessions.contains(&session_id)
    }

    /// Returns every retained session.
    #[must_use]
    pub fn sessions(&self) -> std::collections::BTreeSet<SessionId> {
        self.sessions.clone()
    }

    /// Returns how many sessions are retained.
    #[must_use]
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    /// Returns true when no session is retained.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_archive_with_nothing_missing_is_complete() {
        let archive = Archive {
            session_id: SessionId::new(kr_ipc::new_uuid()),
            summary: None,
            closure: None,
            receipts: 0,
            oldest_retained_cursor: 0,
            next_cursor: 0,
            output_bytes: 0,
            retained: Vec::new(),
            incompleteness: Vec::new(),
        };
        assert!(archive.is_complete());
        assert!(!archive.retains_submissions(None));
    }

    #[test]
    fn a_journal_this_host_cannot_read_keeps_what_was_submitted_to_its_session() {
        let archive = Archive {
            session_id: SessionId::new(kr_ipc::new_uuid()),
            summary: None,
            closure: None,
            receipts: 0,
            oldest_retained_cursor: 0,
            next_cursor: 0,
            output_bytes: 0,
            retained: Vec::new(),
            incompleteness: vec![Incompleteness::JournalUnreadable {
                detail: "the store said so".to_owned(),
            }],
        };
        assert!(!archive.is_complete());
        assert!(
            archive.retains_submissions(None),
            "declining to delete is the answer that cannot lose a file"
        );
    }

    #[test]
    fn every_kind_of_incompleteness_says_what_is_missing() {
        for reason in [
            Incompleteness::JournalMissing,
            Incompleteness::JournalUnreadable {
                detail: "a reason".to_owned(),
            },
            Incompleteness::ClosureMissing,
            Incompleteness::SummaryMissing,
            Incompleteness::HistoryLost {
                from_cursor: 0,
                to_cursor: 8,
            },
            Incompleteness::DurabilityLost {
                from_ms: 1,
                to_ms: 2,
            },
        ] {
            assert!(!reason.describe().is_empty());
        }
    }
}
