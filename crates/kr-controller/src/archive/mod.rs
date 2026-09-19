//! The environment archive service: what a session leaves behind, served with no worker.
//!
//! Section 24 gives closed history, final receipts and retained resource references an owner of
//! their own, and says what that owner is: *the environment archive service over fenced worker
//! journals and spools and an archive index. It can be a controller module; it is not a surviving
//! execution worker.* Four rules follow, and this module is each of them.
//!
//! * **Ownership is taken, and only after the worker is gone.** [`ArchiveService::take_ownership`]
//!   fences the worker's endpoint and validates its death through the kernel's own answer before
//!   it opens anything. A process the operating system declines to describe is not dead; it is
//!   unanswered, and the archive waits rather than taking a journal a live worker is writing.
//! * **A reader cannot create a worker.** Every read here is a read of what is already on disk.
//!   There is no path from a history request to a launch, and a retried create is answered from
//!   the reservation the first one made rather than by starting a second execution.
//! * **A lost or corrupt journal produces an explicit incomplete archive.** Not an error, and not
//!   an empty success: [`Archive::incompleteness`] names what is missing, so a reader is told the
//!   record has holes rather than reading continuity into it.
//! * **A worker crash closes the session.** The closure is recorded, the owned processes are
//!   fenced by the boundary the worker established, and nothing is rebuilt from terminal history.
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
    /// Section 14 gives a submitted attachment its session's retention. A session the archive
    /// holds a record of keeps what was submitted to it; one this host has no record of at all
    /// keeps nothing. An archive that could not read its journal answers *yes*, because declining
    /// to delete is the answer that cannot lose a file.
    #[must_use]
    pub fn retains_submissions(&self) -> bool {
        self.summary.is_some()
            || self.closure.is_some()
            || self
                .incompleteness
                .iter()
                .any(|reason| matches!(reason, Incompleteness::JournalUnreadable { .. }))
    }
}

/// What fencing a crashed session's owned processes did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fenced {
    /// The session.
    pub session_id: SessionId,
    /// The processes this pass terminated. The signal reached each of them.
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

/// Terminates one recorded process, and says whether the signal reached it.
///
/// What this reports is delivery rather than death. A process terminated a moment ago is still
/// described by the kernel until whoever started it collects its status, so asking again
/// immediately would read a process that has certainly been ended as one that has not. Section 7
/// gives closure a grace period and then forces what is left; this is the forcing, and the next
/// pass is what observes the result.
#[cfg(unix)]
fn stop(identity: &ProcessStartIdentity) -> bool {
    let Ok(pid) = i32::try_from(identity.pid.get()) else {
        return false;
    };
    // The identity has already been matched against the kernel's own answer, so this is the
    // process that was recorded rather than whatever holds its number now.
    let Some(pid) = rustix::process::Pid::from_raw(pid) else {
        return false;
    };
    rustix::process::kill_process(pid, rustix::process::Signal::KILL).is_ok()
}

/// Terminates one recorded process, and says whether the signal reached it.
#[cfg(not(unix))]
fn stop(_identity: &ProcessStartIdentity) -> bool {
    // A crashed worker's Job Object is closed with the handle it held, which terminates what it
    // contained. What the archive would have to stop by identity is what left that Job, and a
    // process outside it is not one this host owns.
    false
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
    /// The order is the contract, and both steps are here rather than in the caller so neither
    /// can be skipped: the endpoint is fenced first, so nothing new reaches a worker that may be
    /// part way through ending, and the kernel is then asked whether the recorded process is the
    /// process that was recorded. Only a confirmed ending is death. A query the platform declines
    /// leaves the session alone.
    ///
    /// It never creates a worker, and there is no argument by which it could: what it takes is a
    /// directory and a database that already exist.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::InvalidArgument`] carrying an [`OwnershipRefusal`] when the
    /// worker is alive or its death could not be validated.
    pub fn take_ownership(
        &self,
        session_id: SessionId,
        display_number: kr_protocol::session::DisplayNumber,
        identity: &ProcessStartIdentity,
    ) -> Result<RecoveryOwnership> {
        let fenced = self.fence_endpoint(session_id, display_number);
        let mut last = String::new();
        for _ in 0..DEATH_VALIDATION_ATTEMPTS {
            match kr_ipc::identity::process_state(identity) {
                kr_ipc::identity::ProcessState::Ended => {
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

    /// Removes the worker's published endpoint and descriptor, and returns whether anything went.
    ///
    /// Fencing is not a message to the worker. A worker that has crashed cannot be told anything;
    /// what this does is stop a client finding a socket that no longer has a process behind it,
    /// and stop a restarted daemon rebuilding its directory from a descriptor for a session that
    /// has ended.
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

    /// Fences whatever a crashed session still owns, by the identities it recorded.
    ///
    /// Section 7: after a worker crash the controller fences its endpoints, uses the cgroup or
    /// Job or the recorded identities for cleanup, and records any incomplete coverage. The
    /// endpoint is fenced by [`Self::take_ownership`]; this is the second half.
    ///
    /// Only identities this session recorded are touched, and each is checked before it is
    /// stopped: a process identifier on its own proves nothing, because the kernel reuses them,
    /// so the recorded start value has to match as well. A process that has already ended is
    /// counted as gone rather than as stopped, and one the platform declines to describe is
    /// counted as neither, which is what makes the coverage incomplete.
    #[must_use]
    pub fn fence_owned(&self, ownership: &RecoveryOwnership, closure: &ClosureRecord) -> Fenced {
        let mut fenced = Fenced {
            session_id: ownership.session_id,
            stopped: Vec::new(),
            already_gone: 0,
            unaccounted: 0,
            surviving: Vec::new(),
            coverage: kr_protocol::session::OwnershipCoverage::Incomplete,
        };
        for terminated in &closure.terminated {
            match kr_ipc::identity::process_state(&terminated.identity) {
                kr_ipc::identity::ProcessState::Ended => fenced.already_gone += 1,
                kr_ipc::identity::ProcessState::Running => {
                    if stop(&terminated.identity) {
                        fenced.stopped.push(terminated.identity.clone());
                    } else {
                        fenced.unaccounted += 1;
                    }
                }
                kr_ipc::identity::ProcessState::Unknown { .. } => fenced.unaccounted += 1,
            }
        }
        // Section 7 forbids claiming that every application a worker may have started was
        // discovered. What survives outside the recorded boundary is the user's.
        fenced.surviving = closure.surviving.clone();
        fenced.coverage = if fenced.unaccounted == 0 && !closure.surviving.is_empty() {
            kr_protocol::session::OwnershipCoverage::Incomplete
        } else if fenced.unaccounted == 0 {
            closure.ownership_coverage
        } else {
            kr_protocol::session::OwnershipCoverage::Incomplete
        };
        fenced
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
        if !path.exists() {
            archive.incompleteness.push(Incompleteness::JournalMissing);
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
                    Ok(Some(closure)) => archive.closure = Some(closure),
                    Ok(None) => incompleteness.push(Incompleteness::ClosureMissing),
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
                for gap in journal.recovery_gaps().unwrap_or_default() {
                    incompleteness.push(durability_lost(&gap));
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
        let history = kr_worker::history::OutputHistory::with_spool(
            0,
            &directory,
            kr_worker::history::SpoolLayout::DEFAULT,
        )
        .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?;
        history
            .page(from_cursor, max_bytes)
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

    fn read_history_into(&self, session_id: SessionId, archive: &mut Archive) {
        let directory = self.paths.session_spool(session_id);
        if !directory.exists() {
            return;
        }
        let Ok(history) = kr_worker::history::OutputHistory::with_spool(
            0,
            &directory,
            kr_worker::history::SpoolLayout::DEFAULT,
        ) else {
            return;
        };
        archive.oldest_retained_cursor = history.oldest_retained_cursor();
        archive.next_cursor = history.next_cursor();
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
    /// question is answered now: the archive holds a closed session's record, so it can say what
    /// a session keeps after the registry has stopped holding a reservation for it.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::RegistryUnavailable`] when the registry cannot be read.
    pub fn archive_retention(&self) -> Result<ArchiveRetention> {
        let archive = self.archive();
        let sessions = {
            let registry = self.registry_handle().blocking_lock();
            let mut sessions: Vec<SessionId> = Vec::new();
            for phase in EVERY_LAUNCH_PHASE {
                for reservation in registry.reservations_in(*phase)? {
                    sessions.push(reservation.session_id);
                }
            }
            for worker in registry.workers()? {
                sessions.push(worker.session_id);
            }
            sessions
        };
        let mut retention = ArchiveRetention::default();
        for session_id in sessions {
            // A session the registry still lists keeps what was submitted to it. One it no longer
            // lists is asked of the archive, which is what holds a closed session's record, and a
            // session neither of them knows about keeps nothing.
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
