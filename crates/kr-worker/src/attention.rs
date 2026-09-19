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

use kr_attention::event::{ApplicationNotice, EventCursor, EventKind, SourceEvent};
use kr_attention::{Attention as Engine, HostReading, Outcome};
use kr_protocol::action::WallClockTrust;
use kr_protocol::attention::{
    AttentionAcknowledgeParams, AttentionAcknowledgeResult, AttentionQuietHoursParams,
    AttentionQuietHoursResult, AttentionReadParams, AttentionReadResult, AttentionSource,
    MAX_LOG_VIEW_FILTER_LEN, MAX_LOG_VIEW_ID_LEN, MAX_RETAINED_LOG_VIEWS, ReviewAcknowledgeParams,
    ReviewAcknowledgeResult, ReviewReadParams, ReviewReadResult, ReviewSubject,
    VisitAcknowledgeParams, VisitAcknowledgeResult, VisitChangedParams, VisitChangedResult,
};
use kr_protocol::ids::ActorId;

/// Largest time-zone name a quiet-hours window records.
pub const MAX_ZONE_LEN: usize = 64;

/// How many retained records one maintenance pass takes from each source.
///
/// A pass is bounded so a session that has been running for a week does not read its whole history
/// on the tick after a restart. What is left is taken on the next pass, and the cursor is what says
/// where that is.
pub const PAGE: usize = 512;

/// Returns the one line a refusal names a review subject by.
#[must_use]
pub fn describe(subject: &ReviewSubject) -> String {
    match subject {
        ReviewSubject::CompletedTurn { turn_id, .. } => format!("turn {turn_id}"),
        ReviewSubject::ChangeSet { change_set_id, .. } => format!("change set {change_set_id}"),
    }
}

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
        kr_attention::Error::UnknownContinuation { key } => WorkerError::PreconditionFailed {
            detail: format!("this inbox no longer holds {key}, so a page cannot continue after it"),
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
        self.locked()?
            .read(actor, params, reading(time))
            .map_err(translate)
    }

    /// Returns how far the engine has read one retained source.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::JournalUnavailable`] when the engine cannot be reached.
    pub fn consumed(&self, source: AttentionSource) -> Result<Option<u64>> {
        Ok(self.locked()?.engine().consumed(source))
    }

    /// Takes the announcements the host has decided and not yet handed over.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::JournalUnavailable`] when the state cannot be written.
    pub fn take_announcements(&self) -> Result<Vec<kr_attention::engine::Announcement>> {
        self.locked()?.take_announcements().map_err(translate)
    }

    /// Refuses, before anything is dispatched, a review acknowledgement this host can decide about.
    ///
    /// Section 9 makes a refusal the host can decide a rejection rather than an outcome nobody can
    /// establish, so a subject this session never held and a version nobody produced are answered
    /// here rather than inside the effect.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::InvalidArgument`] when the subject is not one this session holds and
    /// [`WorkerError::PreconditionFailed`] when the version is not one it holds.
    pub fn check_review(&self, params: &ReviewAcknowledgeParams) -> Result<()> {
        let engine = self.locked()?;
        let state = engine
            .reviews()
            .state(
                &ActorId::new("local:precheck").expect("a constant principal"),
                &params.subject,
            )
            .ok_or_else(|| {
                WorkerError::InvalidArgument(format!(
                    "this session holds no review subject {}",
                    describe(&params.subject)
                ))
            })?;
        if params.version.get() > state.current_version.get() {
            return Err(WorkerError::PreconditionFailed {
                detail: format!(
                    "{} is at version {}, not {}",
                    describe(&params.subject),
                    state.current_version.get(),
                    params.version.get()
                ),
            });
        }
        Ok(())
    }

    /// Refuses a quiet-hours window that is not minutes of a day.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::InvalidArgument`] for a bound outside the day.
    pub fn check_quiet_hours(params: &AttentionQuietHoursParams) -> Result<()> {
        let Some(quiet) = params.quiet_hours.as_ref() else {
            return Ok(());
        };
        let day = kr_protocol::attention::MINUTES_IN_DAY;
        if quiet.start_minute.get() >= day || quiet.end_minute.get() >= day {
            return Err(WorkerError::InvalidArgument(format!(
                "a quiet-hours bound is a minute of the UTC day, below {day}"
            )));
        }
        if quiet
            .zone
            .as_ref()
            .is_some_and(|zone| zone.len() > MAX_ZONE_LEN)
        {
            return Err(WorkerError::InvalidArgument(format!(
                "a time-zone name is at most {MAX_ZONE_LEN} bytes"
            )));
        }
        Ok(())
    }

    /// Refuses a visit whose views carry more than the host will write down.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::InvalidArgument`] for a view identifier or a filter past its bound,
    /// or for more views than one actor may retain.
    pub fn check_visit(params: &VisitAcknowledgeParams) -> Result<()> {
        if params.views.len() > usize::try_from(MAX_RETAINED_LOG_VIEWS).unwrap_or(usize::MAX) {
            return Err(WorkerError::InvalidArgument(format!(
                "an actor retains at most {MAX_RETAINED_LOG_VIEWS} log views"
            )));
        }
        for view in &params.views {
            if view.view_id.is_empty() || view.view_id.len() > MAX_LOG_VIEW_ID_LEN {
                return Err(WorkerError::InvalidArgument(format!(
                    "a log view identifier is 1 to {MAX_LOG_VIEW_ID_LEN} bytes"
                )));
            }
            if view.filter.len() > MAX_LOG_VIEW_FILTER_LEN {
                return Err(WorkerError::InvalidArgument(format!(
                    "a log view filter is at most {MAX_LOG_VIEW_FILTER_LEN} bytes"
                )));
            }
        }
        Ok(())
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
        Self::check_quiet_hours(params)?;
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

    /// Reads the retained sources this worker holds and gives the engine what it has not seen.
    ///
    /// Returns the events it fed in, for a caller that wants to know a pass did something.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::JournalUnavailable`] when a decision cannot be written down. What
    /// was already fed in stays fed in: the cursor moves with each event, so the pass resumes
    /// where it stopped.
    pub fn feed(&self, events: &[SourceEvent], time: &TimeContract) -> Result<Vec<Outcome>> {
        let mut produced = Vec::new();
        for event in events {
            produced.extend(self.observe(event, time)?);
        }
        Ok(produced)
    }

    fn locked(&self) -> Result<std::sync::MutexGuard<'_, Engine>> {
        self.engine
            .lock()
            .map_err(|_| WorkerError::JournalUnavailable {
                detail: "the attention engine's lock is poisoned".to_owned(),
            })
    }
}

/// Turns one question transition into the typed event the engine reads.
///
/// `verified` is whether the worker admitted the source that created the question, which is what
/// section 25 means by a verified pending request. The label a caller gave itself is not part of
/// it, and neither is anything the question's text says.
#[must_use]
pub fn question_event(sequence: u64, event: &kr_protocol::question::QuestionEvent) -> SourceEvent {
    let kind = match event.kind {
        kr_protocol::question::QuestionEventKind::Created => EventKind::QuestionPending {
            question_id: event.question.question_id,
            session_id: event.question.session_id,
            verified: event.question.source.session_member,
            pending_since_ms: event.pending_since_ms,
            summary: event.question.question.clone(),
        },
        kr_protocol::question::QuestionEventKind::Answered => EventKind::QuestionResolved {
            question_id: event.question.question_id,
            answered: true,
        },
        kr_protocol::question::QuestionEventKind::Cancelled
        | kr_protocol::question::QuestionEventKind::Expired => EventKind::QuestionResolved {
            question_id: event.question.question_id,
            answered: false,
        },
    };
    SourceEvent::new(
        EventCursor::new(AttentionSource::Questions, sequence),
        event.recorded_at_ms,
        kind,
    )
}

/// Turns one recorded terminal side effect into the typed event the engine reads.
///
/// Only a notification is a rule's condition. Everything else - a bell, a progress report, a
/// clipboard operation - moves the cursor and nothing else, so a later notification is not read as
/// a range retention took.
///
/// A recorded side effect is by definition one that had no attachment to go to: section 8 sends it
/// to the lease holder, and this record exists because there was none. That is why the notice says
/// no lease was held, and why section 25 routes it through the owner's notification policy.
#[must_use]
pub fn host_event(
    sequence: u64,
    session_id: kr_protocol::ids::SessionId,
    event: &crate::journal::HostEvent,
) -> SourceEvent {
    let kind = if event.kind == "notification" {
        EventKind::ApplicationNotice {
            session_id,
            notice: ApplicationNotice {
                id: None,
                title: None,
                body: event.detail.clone(),
                lease_held: false,
            },
        }
    } else {
        EventKind::Observed
    };
    SourceEvent::new(
        EventCursor::new(AttentionSource::HostEvents, sequence),
        event.recorded_at_ms,
        kind,
    )
}
