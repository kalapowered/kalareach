//! The attention engine's host adapter.
//!
//! The engine itself is in `kr-attention`: a state machine that reads no clock, opens no file and
//! sends no notification. This is the part of it that belongs to a worker - where its feature store
//! lives, which reading of the host time contract it is given, and how the six methods of section
//! 23's review and attention group reach it.
//!
//! # Where the state lives
//!
//! Beside the receipts, in the session's own private journal file, under its own table names and
//! its own schema version. That is section 24's environment feature store for this worker: a
//! projection of the journal's events rather than a second copy of them, reconstructed from the
//! retained events whenever it has to be. A session with no retained journal keeps it for the life
//! of the process, which is what that session already does with its receipts.
//!
//! # Which clock
//!
//! The engine takes every reading from here, and here takes it from the host time contract. The
//! continuous clock measures intervals and needs nobody's trust; the wall clock decides quiet
//! hours, which are a time of day, and the contract is what says whether this host can prove what
//! it reads. A host that cannot prove it does not suppress: a withheld notification at an hour
//! nobody chose is the failure that matters.
//!
//! # What a review method may not do
//!
//! Anything to the code. Section 14 makes promotion a separate authorised action and section 23
//! gives this group "no code mutation", and the shape of this module is how that holds: the engine
//! has no operation that writes a file, applies a patch, moves a branch or approves a command, so
//! neither has anything reachable from here.

use std::path::Path;
use std::sync::Mutex;

use kr_attention::event::SourceEvent;
use kr_attention::{Attention as Engine, HostReading, Outcome};
use kr_protocol::action::WallClockTrust;
use kr_protocol::attention::{
    AttentionAcknowledgeParams, AttentionAcknowledgeResult, AttentionQuietHoursParams,
    AttentionQuietHoursResult, AttentionReadParams, AttentionReadResult, ReviewAcknowledgeParams,
    ReviewAcknowledgeResult, ReviewReadParams, ReviewReadResult, VisitAcknowledgeParams,
    VisitAcknowledgeResult, VisitChangedParams, VisitChangedResult,
};
use kr_protocol::ids::ActorId;

use crate::action::time::TimeContract;
use crate::error::{Result, WorkerError};

/// The attention engine as this worker holds it.
#[derive(Debug)]
pub struct Attention {
    engine: Mutex<Engine>,
}

/// Returns the host time contract's answer, in the form the engine takes.
///
/// The continuous reading is the machine's boot-scoped clock, which is the one the contract itself
/// measures intervals on and which counts time the machine spent asleep. The wall reading is the
/// clock the contract watches, and whether it can be proved is the contract's own answer rather
/// than this module's opinion.
#[must_use]
pub fn reading(time: &TimeContract) -> HostReading {
    HostReading::new(
        kr_ipc::clock::boot_elapsed_ms(),
        kr_ipc::now_ms().get(),
        time.trust() == WallClockTrust::Trusted,
    )
}

fn translate(error: kr_attention::Error) -> WorkerError {
    match error {
        kr_attention::Error::UnknownReviewSubject { subject } => {
            WorkerError::InvalidArgument(format!("this session holds no review subject {subject}"))
        }
        kr_attention::Error::UnknownReviewVersion {
            subject,
            version,
            current,
        } => WorkerError::PreconditionFailed {
            detail: format!("{subject} is at version {current}, not {version}"),
        },
        kr_attention::Error::StoreUnavailable { kind, detail } => WorkerError::JournalUnavailable {
            detail: format!("the attention store is {kind}: {detail}"),
        },
        kr_attention::Error::StoreUnreadable { field } => WorkerError::JournalUnavailable {
            detail: format!("the attention store holds a {field} this build cannot read"),
        },
    }
}

impl Attention {
    /// Opens the feature store beside the session's journal, or in memory when there is none.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::JournalUnavailable`] when the store cannot be opened or read back.
    pub fn open(journal_path: Option<&Path>, time: &TimeContract) -> Result<Self> {
        let engine = Engine::beside(journal_path, reading(time)).map_err(translate)?;
        Ok(Self {
            engine: Mutex::new(engine),
        })
    }

    /// Applies one typed event the worker observed.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::JournalUnavailable`] when the decision cannot be written down, in
    /// which case nothing about it happened and the same event can be offered again.
    pub fn observe(&self, event: &SourceEvent, time: &TimeContract) -> Result<Vec<Outcome>> {
        self.locked()?
            .apply(event, reading(time))
            .map_err(translate)
    }

    /// Advances every timer, which is what raises an idle reminder and releases a held
    /// announcement.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::JournalUnavailable`] when the decision cannot be written down.
    pub fn tick(&self, time: &TimeContract) -> Result<Vec<Outcome>> {
        self.locked()?.tick(reading(time)).map_err(translate)
    }

    /// Returns the continuous reading the next timer is due at.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::JournalUnavailable`] when the engine cannot be reached.
    pub fn next_deadline(&self, time: &TimeContract) -> Result<Option<u64>> {
        Ok(self.locked()?.engine().next_deadline(reading(time)))
    }

    /// Serves `attention.read`.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::JournalUnavailable`] when the engine cannot be reached.
    pub fn read(
        &self,
        actor: &ActorId,
        params: &AttentionReadParams,
        time: &TimeContract,
    ) -> Result<AttentionReadResult> {
        Ok(self.locked()?.read(actor, params, reading(time)))
    }

    /// Serves `attention.acknowledge`.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::JournalUnavailable`] when the acknowledgement cannot be written.
    pub fn acknowledge(
        &self,
        actor: &ActorId,
        params: &AttentionAcknowledgeParams,
        time: &TimeContract,
    ) -> Result<AttentionAcknowledgeResult> {
        self.locked()?
            .acknowledge(actor, &params.keys, reading(time))
            .map_err(translate)
    }

    /// Serves `attention.quiet_hours`.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::InvalidArgument`] for a window outside the day and
    /// [`WorkerError::JournalUnavailable`] when it cannot be written.
    pub fn set_quiet_hours(
        &self,
        params: &AttentionQuietHoursParams,
        time: &TimeContract,
    ) -> Result<AttentionQuietHoursResult> {
        if let Some(quiet) = params.quiet_hours.as_ref() {
            let day = kr_protocol::attention::MINUTES_IN_DAY;
            if quiet.start_minute.get() >= day || quiet.end_minute.get() >= day {
                return Err(WorkerError::InvalidArgument(format!(
                    "a quiet-hours bound is a minute of the UTC day, below {day}"
                )));
            }
        }
        let now = reading(time);
        let mut engine = self.locked()?;
        engine
            .set_quiet_hours(params.quiet_hours.0.clone(), now)
            .map_err(translate)?;
        Ok(AttentionQuietHoursResult {
            quiet_hours: kr_protocol::scalars::Nullable(engine.engine().quiet_hours().cloned()),
            quiet_now: engine.engine().quiet_now(now),
            quiet_hours_provable: now.wall_proven,
        })
    }

    /// Serves `review.read`.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::JournalUnavailable`] when the engine cannot be reached.
    pub fn review_read(
        &self,
        actor: &ActorId,
        params: &ReviewReadParams,
    ) -> Result<ReviewReadResult> {
        let engine = self.locked()?;
        let reviews = match params.subject.as_ref() {
            Some(subject) => engine.reviews().state(actor, subject).into_iter().collect(),
            None => engine.review_states(actor, params.session_id),
        };
        Ok(ReviewReadResult {
            actor_id: actor.clone(),
            reviews,
        })
    }

    /// Serves `review.acknowledge`.
    ///
    /// It records that this actor read one version. No command is approved, no patch is applied
    /// and no Git state changes.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::InvalidArgument`] when the subject is not one this session holds,
    /// [`WorkerError::PreconditionFailed`] when the version is not one it holds, and
    /// [`WorkerError::JournalUnavailable`] when the acknowledgement cannot be written.
    pub fn acknowledge_review(
        &self,
        actor: &ActorId,
        params: &ReviewAcknowledgeParams,
        time: &TimeContract,
    ) -> Result<ReviewAcknowledgeResult> {
        self.locked()?
            .acknowledge_review(actor, &params.subject, params.version.get(), reading(time))
            .map_err(translate)
    }

    /// Serves `visit.acknowledge`.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::JournalUnavailable`] when the visit cannot be written.
    pub fn acknowledge_visit(
        &self,
        actor: &ActorId,
        params: &VisitAcknowledgeParams,
    ) -> Result<VisitAcknowledgeResult> {
        self.locked()?
            .acknowledge_visit(
                actor,
                params.acknowledged_cursor.get(),
                params.views.clone(),
            )
            .map_err(translate)
    }

    /// Serves `visit.changed`.
    ///
    /// `oldest_output_cursor` is the oldest output the session can still replay, which is what
    /// decides whether a retained log view can be served from where it was left.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::JournalUnavailable`] when the engine cannot be reached.
    pub fn changed(
        &self,
        actor: &ActorId,
        params: &VisitChangedParams,
        oldest_output_cursor: u64,
    ) -> Result<VisitChangedResult> {
        Ok(self
            .locked()?
            .changed_result(actor, params.max_changes.get(), oldest_output_cursor))
    }

    fn locked(&self) -> Result<std::sync::MutexGuard<'_, Engine>> {
        self.engine
            .lock()
            .map_err(|_| WorkerError::JournalUnavailable {
                detail: "the attention engine's lock is poisoned".to_owned(),
            })
    }
}
