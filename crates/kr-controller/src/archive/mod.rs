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
//!   store, a missing closure or summary, a lost range of output, an interval durable writing was
//!   lost, and a recovery pass that did not run. It does not name a *hole* inside the retained
//!   range: a middle spool segment that has gone reads as an empty page, which is the handoff's
//!   residual 21.
//! * **Privacy mode is the worker's, not the archive's.** A store recovered here is not checked
//!   for an unfinished privacy cleanup, and a content read is not held while one is owed, so a
//!   host that crashed between recording privacy mode and removing what it was asked to remove
//!   serves that content from here. That is the handoff's residual 18.
//! * **A worker crash closes the session.** The closure is recorded and nothing is rebuilt from
//!   terminal history. What this module does *not* do is stop what the session still owned:
//!   [`ArchiveService::fence_owned`] removes the worker's published endpoint and descriptor and
//!   stops no process, because this build records no boundary a later daemon could act on. The
//!   closure's coverage says so, and section 7's cleaning half is open - the handoff's residual
//!   12 carries it.
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
    /// Retained output was evicted or its spool is gone.
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
    /// How many receipts it still holds.
    pub receipts: u64,
    /// The oldest cursor of retained output that can still be served.
    pub oldest_retained_cursor: u64,
    /// The cursor after the last byte of retained output.
    pub next_cursor: u64,
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
    /// unused-attachment window, so the question is whether this host still holds a record of the
    /// session at all. Three answers are *yes* and they are all the same kind of answer:
    ///
    /// * a summary or a closure survived, which is a session this host remembers;
    /// * a receipt survived, which is the same thing said by a different store;
    /// * retained output survived, which is a session whose history is still being kept;
    /// * this host could not read something, including a spool it cannot tell an empty one from;
    /// * something could not be read, because declining to delete is the answer that cannot lose
    ///   a file and an unreadable record is not evidence that retention has ended.
    ///
    /// Only an archive that found nothing at all and could read everything it looked at answers
    /// no. The one thing that must never happen here is a *false* answer produced by not looking,
    /// because the sweep reads no as expiry and removes the payload.
    #[must_use]
    pub fn retains_submissions(&self) -> bool {
        self.summary.is_some()
            || self.closure.is_some()
            || self.receipts > 0
            || self.next_cursor > 0
            || self.incompleteness.iter().any(|reason| {
                matches!(
                    reason,
                    Incompleteness::JournalUnreadable { .. } | Incompleteness::HistoryLost { .. }
                )
            })
    }
}

/// The boundary a crashed session's remaining processes are cleaned by.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CleanupBoundary {
    /// The transient unit or Job the supervisor started this worker in.
    ///
    /// This is the boundary section 7 names, and it is the only one that cannot name something
    /// else: it is derived from the reservation rather than from a process identifier the kernel
    /// may since have reused. No supervisor in this build stops one yet.
    SupervisedUnit(String),
    /// No boundary this host can work from.
    None,
}

/// What recovering a crashed session's journal resolved.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Recovered {
    /// Dispatch markers with no authoritative outcome, left `unknown` and never dispatched again.
    pub left_unknown: u64,
    /// Accepted intents with no marker, rejected because their freshness cannot be revalidated.
    pub rejected: u64,
}

/// What fencing a crashed session's owned processes did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fenced {
    /// The session.
    pub session_id: SessionId,
    /// The boundary this pass was able to enumerate.
    pub boundary: CleanupBoundary,
    /// The processes this pass terminated.
    ///
    /// Empty until this host records a boundary it can stop: nothing is terminated on the
    /// strength of an identifier the kernel may have reused.
    pub stopped: Vec<ProcessStartIdentity>,
    /// How many recorded processes had already ended.
    pub already_gone: u64,
    /// How many recorded processes this host could not account for.
    pub unaccounted: u64,
    /// Resources known to survive, which are the user's rather than this host's.
    pub surviving: Vec<kr_protocol::session::SurvivingResource>,
    /// Whether every owned process was accounted for.
    pub coverage: kr_protocol::session::OwnershipCoverage,
}

/// Exclusive recovery ownership of one session's stores.
///
/// It exists only after the endpoint is fenced and the worker's death is validated, which is the
/// order section 24 fixes: a journal taken over while its worker was still writing would be two
/// writers on one store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryOwnership {
    /// The session whose stores this owns.
    pub session_id: SessionId,
    /// The identity the kernel confirmed had ended.
    pub ended: ProcessStartIdentity,
    /// Whether the worker's published endpoint was removed.
    pub endpoint_fenced: bool,
    /// When ownership was taken.
    pub taken_at_ms: TimestampMs,
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
}

/// The environment's archive service.
#[derive(Clone, Debug)]
pub struct ArchiveService {
    paths: kr_ipc::paths::EnvironmentPaths,
}

impl ArchiveService {
    /// Builds an archive over one environment's stores.
    #[must_use]
    pub const fn new(paths: kr_ipc::paths::EnvironmentPaths) -> Self {
        Self { paths }
    }

    /// Returns the environment this archive serves.
    #[must_use]
    pub const fn paths(&self) -> &kr_ipc::paths::EnvironmentPaths {
        &self.paths
    }

    /// Takes exclusive recovery ownership of one session's stores.
    ///
    /// Death is validated first, and the endpoint is fenced only once it has been. Section 24
    /// puts the fence before the journal is opened, which is what this keeps: nothing reaches the
    /// stores until the endpoint is gone. What it must not do is fence first and ask afterwards,
    /// because the answer can be *no*: a worker that is alive would then have had its published
    /// endpoint deleted by the daemon that was only enquiring, and every client of a working
    /// session would find nothing where its socket had been.
    ///
    /// Validation is the kernel's own answer, and both halves of it: the identifier and the start
    /// value, because the kernel reuses identifiers and an unrelated program can hold the number
    /// within milliseconds. Only a confirmed ending is death. A query the platform declines is
    /// not death, and leaves the session alone.
    ///
    /// It never creates a worker, and there is no argument by which it could: what it takes is a
    /// directory and a database that already exist.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::InvalidArgument`] carrying an [`OwnershipRefusal`] when the
    /// worker is alive or its death could not be validated. Nothing has been fenced in either
    /// case.
    pub fn take_ownership(
        &self,
        session_id: SessionId,
        display_number: kr_protocol::session::DisplayNumber,
        identity: &ProcessStartIdentity,
    ) -> Result<RecoveryOwnership> {
        let mut last = String::new();
        for _ in 0..DEATH_VALIDATION_ATTEMPTS {
            match kr_ipc::identity::process_state(identity) {
                kr_ipc::identity::ProcessState::Ended => {
                    let fenced = self.fence_endpoint(session_id, display_number);
                    return Ok(RecoveryOwnership {
                        session_id,
                        ended: identity.clone(),
                        endpoint_fenced: fenced,
                        taken_at_ms: kr_ipc::now_ms(),
                    });
                }
                kr_ipc::identity::ProcessState::Running => {
                    return Err(ControllerError::InvalidArgument(
                        OwnershipRefusal::WorkerAlive {
                            session: session_id.to_string(),
                        }
                        .to_string(),
                    ));
                }
                kr_ipc::identity::ProcessState::Unknown { detail } => last = detail,
            }
        }
        Err(ControllerError::InvalidArgument(
            OwnershipRefusal::DeathUnvalidated {
                session: session_id.to_string(),
                detail: last,
            }
            .to_string(),
        ))
    }

    /// Returns whether a worker this host has not seen end may still own this session.
    ///
    /// The published descriptor names the process, and it outlives the worker that wrote it. A
    /// kernel answer of `Ended` is the only one that clears this: `Running` is a worker, and a
    /// query the platform declines establishes nothing, which is not the same as establishing
    /// that there is nothing there.
    ///
    /// This is asked of the descriptor rather than of the registry because a closure deletes the
    /// registry's worker row, and a closure can be recorded for a session whose death this host
    /// inferred rather than confirmed - a boot that is not this one ends every process in it, and
    /// the platform may still decline to say so about any one of them. The descriptor is not
    /// deleted by a closure; it goes when the session is fenced.
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
    pub fn bring_forward(&self, session_id: SessionId) {
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
    fn fence_endpoint(
        &self,
        session_id: SessionId,
        display_number: kr_protocol::session::DisplayNumber,
    ) -> bool {
        let mut fenced = std::fs::remove_file(self.paths.descriptor_file(session_id)).is_ok();
        if let Ok(endpoint) = self.paths.worker_endpoint(display_number)
            && std::fs::remove_file(endpoint.as_path()).is_ok()
        {
            fenced = true;
        }
        fenced
    }

    /// Reports what a crashed session still owns, and what this host can do about it.
    ///
    /// Section 7: after a worker crash the controller fences its endpoints, uses the cgroup or
    /// Job or the recorded identities for cleanup, and records any incomplete coverage. The
    /// endpoint is fenced by [`Self::take_ownership`]. This is the second half, and what it
    /// reports today is that the second half has no boundary to work from.
    ///
    /// **Nothing is inferred from a dead identifier.** A worker's descendants join the group it
    /// led, and after the worker has gone the kernel is free to give its number to an unrelated
    /// process, whose group would then answer to that number. Enumerating it and stopping what it
    /// held would be stopping somebody else's processes on the strength of a coincidence. The
    /// root shell also starts a session of its own, so its jobs need not be in the worker's group
    /// even while the worker lives.
    ///
    /// What would work is the boundary the platform itself keeps: the transient unit or Job the
    /// supervisor started this worker in, which is named from the reservation and cannot name
    /// anything else. This host does not record or stop one yet, so the coverage this returns is
    /// incomplete and says why. The next step is in this task's handoff.
    #[must_use]
    pub fn fence_owned(&self, ownership: &RecoveryOwnership, closure: &ClosureRecord) -> Fenced {
        Fenced {
            session_id: ownership.session_id,
            boundary: CleanupBoundary::None,
            stopped: Vec::new(),
            // What the session recorded as already stopped, confirmed against the kernel rather
            // than taken on trust: the identifier may since have been reused.
            already_gone: closure
                .terminated
                .iter()
                .filter(|terminated| {
                    matches!(
                        kr_ipc::identity::process_state(&terminated.identity),
                        kr_ipc::identity::ProcessState::Ended
                    )
                })
                .count() as u64,
            // The boundary itself: this host has none to work from, and that is one thing it
            // cannot account for.
            unaccounted: 1,
            surviving: closure.surviving.clone(),
            // Section 7 forbids claiming that every application a worker may have started was
            // discovered, and a host with no boundary to clean by is further from that than most.
            coverage: kr_protocol::session::OwnershipCoverage::Incomplete,
        }
    }

    /// Returns what a closure records when this host had no chance to fence anything.
    ///
    /// A reconciliation that finds a worker already gone without taking ownership still writes a
    /// closure, and this is what it carries: nothing stopped, nothing accounted for, coverage
    /// incomplete.
    #[must_use]
    pub const fn nothing_fenced(session_id: SessionId) -> Fenced {
        Fenced {
            session_id,
            boundary: CleanupBoundary::None,
            stopped: Vec::new(),
            already_gone: 0,
            unaccounted: 1,
            surviving: Vec::new(),
            coverage: kr_protocol::session::OwnershipCoverage::Incomplete,
        }
    }

    /// Recovers a crashed session's journal, under ownership, without creating one.    /// Recovers a crashed session's journal, under ownership, without creating one.
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
        let now = kr_ipc::now_ms();
        let unknown = journal
            .resolve_unfinished_dispatches(now)
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?;
        let rejected = journal
            .reject_unrevalidated_intents(now)
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?;
        Ok(Recovered {
            left_unknown: unknown as u64,
            rejected: rejected as u64,
        })
    }

    /// Reads what one session left behind.    /// Reads what one session left behind.
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
                match journal.len() {
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

    /// Reads one retained receipt of a closed session.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::UnknownSession`] when this host holds no journal for the
    /// session, and an invalid-argument failure when no receipt answers.
    pub fn receipt(
        &self,
        session_id: SessionId,
        actor_id: &ActorId,
        action_id: kr_protocol::ids::ActionId,
    ) -> Result<ActionReadResult> {
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
        let result = retained
            .map(|bytes| {
                kr_cbor::decode(&bytes, &kr_cbor::Limits::DEFAULT)
                    .map(kr_protocol::envelope::ParamsValue::new)
                    .map_err(|error| ControllerError::InvalidArgument(error.to_string()))
            })
            .transpose()?;
        Ok(ActionReadResult {
            receipt,
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
    pub fn retains_submissions(&self, session_id: SessionId) -> Result<bool> {
        Ok(self.archive(session_id)?.retains_submissions())
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
        archive.retained.push(RetainedResource {
            kind: "output_spool".to_owned(),
            reference: format!("{session_id}"),
        });
    }
}

fn durability_lost(gap: &RecoveryGap) -> Incompleteness {
    Incompleteness::DurabilityLost {
        from_ms: gap.faulted_at_ms.get(),
        to_ms: gap.recovered_at_ms.get(),
    }
}

impl crate::service::Controller {
    /// Returns this environment's archive.
    #[must_use]
    pub fn archive(&self) -> ArchiveService {
        ArchiveService::new(self.paths().clone())
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
            if archive.retains_submissions(session_id)? {
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

impl kr_transfer::service::SessionRetention for ArchiveRetention {
    fn retains(&self, session_id: SessionId) -> bool {
        self.sessions.contains(&session_id)
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
            retained: Vec::new(),
            incompleteness: Vec::new(),
        };
        assert!(archive.is_complete());
        assert!(!archive.retains_submissions());
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
            retained: Vec::new(),
            incompleteness: vec![Incompleteness::JournalUnreadable {
                detail: "the store said so".to_owned(),
            }],
        };
        assert!(!archive.is_complete());
        assert!(
            archive.retains_submissions(),
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
