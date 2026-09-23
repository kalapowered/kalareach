//! The attention engine's host adapter.
//!
//! The engine itself is in `kr-attention`: a state machine that reads no clock, opens no file and
//! sends no notification. This is the part of it that belongs to a worker - where its feature store
//! lives, which reading of the host time contract it is given, and how the seven methods of the
//! review and attention group reach it.
//!
//! # Where the state lives
//!
//! Beside the receipts, in the session's own private journal file, under its own table names and
//! its own schema version. That is section 24's environment feature store for this worker. What it
//! decided is a projection of the journal's events, reconstructed from the retained events
//! whenever it has to be; what people and clients put there - the acknowledgements, the revisions,
//! the visits and their views, the quiet-hours window - is a record in its own right that no
//! replay restores. A session with no retained journal keeps all of it for the life of the
//! process, which is what that session already does with its receipts.
//!
//! # Which clock
//!
//! The engine takes every reading from here, and here takes it from the host time contract. The
//! continuous clock measures intervals and needs nobody's trust; the wall clock decides quiet
//! hours, which are a time of day, and the contract is what says whether this host can prove what
//! it reads. A host that cannot prove it does not suppress: a withheld notification at an hour
//! nobody chose is the failure that matters.
//!
//! # What a caller is served
//!
//! An item's text and a change's text come from retained content: a question's wording, a command
//! line, what an application printed. Section 10 narrows retained content to the grant that asked
//! for it, and this host cannot narrow a moment in time to a byte range, which is why it refuses a
//! retained history page to a paired device outright. An attention item is not a history page, so
//! it is narrowed rather than refused: a caller that did not arrive over the local socket is served
//! the host's own record of a condition - which rule, at what level, how often, when - without the
//! session's text, and [`Content`] is what says which.
//!
//! # What a review method may not do
//!
//! Anything to the code. Section 14 makes promotion a separate authorised action and section 23
//! gives this group "no code mutation", and the shape of this module is how that holds: the engine
//! has no operation that writes a file, applies a patch, moves a branch or approves a command, so
//! neither has anything reachable from here.

use std::path::Path;
use std::sync::Mutex;

use kr_attention::event::{ApplicationNotice, EventCursor, EventKind, Fingerprint, SourceEvent};
use kr_attention::time::BootMark;
use kr_attention::{
    Attention as Engine, ChangedPage, Claimant, Content, HostReading, InboxPage, Liveness, Origin,
    Outcome, Viewer,
};
use kr_protocol::action::WallClockTrust;
use kr_protocol::attention::{
    AttentionAcknowledgeParams, AttentionAcknowledgeResult, AttentionQuietHoursParams,
    AttentionQuietHoursResult, AttentionReadParams, AttentionSource, MAX_LOG_VIEW_FILTER_LEN,
    MAX_LOG_VIEW_ID_LEN, MAX_RETAINED_LOG_VIEWS, ReviewAcknowledgeParams, ReviewAcknowledgeResult,
    ReviewReadParams, ReviewReadResult, ReviewSubject, VisitAcknowledgeParams,
    VisitAcknowledgeResult, VisitChangedParams,
};
use kr_protocol::ids::ActorId;

/// Largest time-zone name a quiet-hours window records.
pub const MAX_ZONE_LEN: usize = 64;

/// The largest counter the feature store writes down.
///
/// Its rows are signed integers, and a value it could not read back as the one it was given would
/// be worse than a refusal. Anything a caller names past this is refused before the action is
/// dispatched rather than failing to store afterwards.
pub const MAX_STORED_COUNTER: u64 = i64::MAX as u64;

/// How many retained records one page takes from each source.
///
/// A page is bounded so a session that has been running for a week does not read its whole history
/// in one read. A pass takes as many pages as it needs, up to [`crate::service::ATTENTION_CATCH_UP_PAGES`];
/// what is left after that is taken on the next pass, and the cursor is what says where that is.
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
    /// The secret this worker fingerprints what a record says under.
    ///
    /// A notice without an identifier is one condition with every other notice that says the same
    /// thing, and the store knows what it says by this fingerprint rather than by its text.
    subjects: kr_attention::key::KeySecret,
}

/// Returns the host time contract's answer, in the form the engine takes.
///
/// Three things travel, and each answers only its own question. The **boot** is the contract's own
/// boot identity, reduced to a fixed-width mark: it is what says whether a continuous reading
/// written down earlier is on the same clock as this one. The **continuous** reading is the
/// machine's boot-scoped clock, which the contract measures every interval on and which counts
/// time the machine spent asleep. The **wall** reading is the clock the contract watches, and
/// whether it can be proved is the contract's own answer rather than this module's opinion; it
/// decides quiet hours and says when something happened, and it measures nothing, because a clock
/// a host trusts is still a clock somebody can set forward.
#[must_use]
pub fn reading(time: &TimeContract) -> HostReading {
    HostReading::new(
        boot_mark(time),
        kr_ipc::clock::boot_elapsed_ms(),
        kr_ipc::now_ms().get(),
        time.trust() == WallClockTrust::Trusted,
    )
}

/// Returns the mark for the boot this host's time contract belongs to.
///
/// The identity is opaque and compared for equality, so the mark is taken over its source and its
/// value together: two boots that differ in either are two boots.
fn boot_mark(time: &TimeContract) -> BootMark {
    let identity = time.boot_identity();
    let mut bytes = format!("{:?}", identity.source).into_bytes();
    bytes.push(b'|');
    bytes.extend_from_slice(identity.value.as_slice());
    BootMark::of(&bytes)
}

/// Refuses a value the feature store could not write down as the one it was given.
fn storable(value: u64, what: &str) -> Result<()> {
    if value > MAX_STORED_COUNTER {
        return Err(WorkerError::InvalidArgument(format!(
            "{what} is at most {MAX_STORED_COUNTER}"
        )));
    }
    Ok(())
}

/// Names this worker and how it asks about a claim it finds on the store.
///
/// The process identity is the pair the kernel describes: the number and the start value that says
/// this is the same process holding it. A worker that crashed left its claim behind, and the next
/// one clears it the moment the kernel says that process has gone; where the kernel will not
/// answer, the claim's own lease decides, and a claim whose process is still running is never
/// taken.
fn claim_check() -> Result<kr_protocol::identity::ProcessStartIdentity> {
    kr_ipc::identity::current_process_start_identity().map_err(|error| {
        WorkerError::JournalUnavailable {
            detail: format!("this worker's process cannot be identified: {error}"),
        }
    })
}

/// Returns what the kernel says about the process a claim names.
fn liveness(held: &kr_protocol::identity::ProcessStartIdentity) -> Liveness {
    match kr_ipc::identity::process_state(held) {
        kr_ipc::identity::ProcessState::Running => Liveness::Running,
        kr_ipc::identity::ProcessState::Ended => Liveness::Ended,
        kr_ipc::identity::ProcessState::Unknown { .. } => Liveness::Unknown,
    }
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
            detail: format!(
                "this session no longer holds {key}, so a page cannot continue after it"
            ),
        },
        kr_attention::Error::StoreHeld { process } => WorkerError::JournalUnavailable {
            detail: format!("process {process} holds this session's attention store"),
        },
        kr_attention::Error::StoreTaken => WorkerError::JournalUnavailable {
            detail: "this session's attention store is no longer this worker's to write".to_owned(),
        },
        kr_attention::Error::StoreAliased { names } => WorkerError::JournalUnavailable {
            detail: format!(
                "{names} names reach this session's journal file, and one is the most it can have"
            ),
        },
        kr_attention::Error::TooManyActors { bound } => WorkerError::QuotaExceeded {
            detail: format!(
                "this session's attention store holds {bound} actors, which is its bound"
            ),
        },
        kr_attention::Error::RevisionAhead {
            key,
            revision,
            current,
        } => WorkerError::PreconditionFailed {
            detail: format!("{key} is at revision {current}, not {revision}"),
        },
        kr_attention::Error::ActionConflict { action } => WorkerError::IdConflict { action },
    }
}

impl Attention {
    /// Opens the feature store beside the session's journal, or in memory when there is none.
    ///
    /// Opening writes. What it reads back may have to be re-anchored - every interval whose boot
    /// has ended starts again - and the new starts are written down as part of the same
    /// transaction, so a session that opens and changes nothing still leaves the store where the
    /// next one can pick the intervals up.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::JournalUnavailable`] when the store cannot be opened, read back or
    /// written; when another live owner already holds it, because one session's worker is the one
    /// owner of its own store and every write replaces the whole of it; and when more than one
    /// name reaches the journal file, which is a file two processes could journal separately.
    pub fn open(journal_path: Option<&Path>, time: &TimeContract) -> Result<Self> {
        let claimant = Claimant::new(claim_check()?, &liveness);
        let engine = Engine::beside(journal_path, reading(time), &claimant).map_err(translate)?;
        Ok(Self {
            engine: Mutex::new(engine),
            subjects: kr_attention::key::KeySecret::fresh(),
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
    /// The worker asks only after a pass that read its sources to the end, so everything its
    /// session committed before now has been read.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::JournalUnavailable`] when the decision cannot be written down.
    pub fn tick(&self, time: &TimeContract) -> Result<Vec<Outcome>> {
        let now = reading(time);
        let read_to_now = |_: &Origin| Some(now.continuous_ms);
        self.locked()?.tick(now, &read_to_now).map_err(translate)
    }

    /// Returns this worker's fingerprint of what one record says.
    #[must_use]
    pub fn fingerprint(&self, subject: &str) -> Fingerprint {
        self.subjects.fingerprint(subject)
    }

    /// Returns the continuous reading the next timer is due at.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::JournalUnavailable`] when the engine cannot be reached.
    pub fn next_deadline(&self, time: &TimeContract) -> Result<Option<u64>> {
        Ok(self
            .locked()?
            .engine()
            .map_err(translate)?
            .next_deadline(reading(time)))
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
        content: Content,
    ) -> Result<InboxPage> {
        self.locked()?
            .read(actor, &Viewer::Owner, params, reading(time), content)
            .map_err(translate)
    }

    /// Returns the key one rule and one subject land on in this session's store.
    ///
    /// The derivation is under a secret of that store's, so a producer names an item by asking
    /// rather than by deriving one of its own.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::JournalUnavailable`] when the engine cannot be reached.
    pub fn key_for(
        &self,
        rule: kr_protocol::attention::AttentionRule,
        subject: &kr_attention::Subject,
    ) -> Result<kr_protocol::attention::AttentionKey> {
        self.locked()?.key_for(rule, subject).map_err(translate)
    }

    /// Returns how far the engine has read one retained source.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::JournalUnavailable`] when the engine cannot be reached.
    pub fn consumed(&self, origin: Origin, source: AttentionSource) -> Result<Option<u64>> {
        Ok(self
            .locked()?
            .engine()
            .map_err(translate)?
            .consumed(origin, source))
    }

    /// Returns the announcements the host has decided and no consumer has settled.
    ///
    /// Asking forgets nothing. A consumer records what it is given and then calls
    /// [`Attention::settle_announcements`]; anything it does not settle is offered again.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::JournalUnavailable`] when the engine cannot be reached.
    pub fn take_announcements(&self) -> Result<Vec<kr_attention::engine::Announcement>> {
        self.locked()?
            .take_announcements(&|_| true)
            .map_err(translate)
    }

    /// Forgets the announcements a consumer has taken durable responsibility for.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::JournalUnavailable`] when the state cannot be written, in which case
    /// nothing is forgotten.
    pub fn settle_announcements(
        &self,
        settled: &[(kr_protocol::attention::AttentionKey, u64)],
    ) -> Result<()> {
        self.locked()?
            .settle_announcements(settled)
            .map_err(translate)
    }

    /// Answers whether this worker still holds its session's store, without changing anything.
    ///
    /// A store it no longer holds records nothing whatever it is asked to record, so asking here
    /// makes that a rejection of the action rather than a failure inside the effect, which settles
    /// as an outcome nobody can establish.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::JournalUnavailable`] when the engine cannot be reached, and when the
    /// store is no longer this worker's.
    pub fn check_store(&self) -> Result<()> {
        self.locked()?.check_store().map_err(translate)
    }

    /// Refuses, before anything is dispatched, an actor this session's store cannot admit.
    ///
    /// The store bounds how many actors it holds on admission rather than on eviction, so nothing
    /// anybody has acknowledged is deleted to make room. Asking here makes one more actor than the
    /// bound a rejection of the action rather than a storage failure after the marker, which
    /// settles as an outcome nobody can establish.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::QuotaExceeded`] when the actor is new and the bound is reached.
    pub fn check_actor(&self, actor: &ActorId) -> Result<()> {
        self.locked()?.check_actor(actor).map_err(translate)
    }

    /// Refuses, before anything is dispatched, an acknowledgement naming a revision past an item's
    /// own.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::PreconditionFailed`] for such a revision.
    pub fn check_acknowledgement(&self, params: &AttentionAcknowledgeParams) -> Result<()> {
        for item in &params.items {
            storable(item.revision.get(), "an item revision")?;
        }
        self.locked()?
            .check_revisions(&Viewer::Owner, &params.items)
            .map_err(translate)
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
        storable(params.version.get(), "a review version")?;
        let engine = self.locked()?;
        let state = engine
            .reviews()
            .map_err(translate)?
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
        storable(params.acknowledged_cursor.get(), "an acknowledged cursor")?;
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
            storable(view.source_offset.get(), "a log view offset")?;
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
            .acknowledge(actor, &Viewer::Owner, &params.items, reading(time))
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
            .set_quiet_hours(params.quiet_hours.0.clone())
            .map_err(translate)?;
        let state = engine.engine().map_err(translate)?;
        Ok(AttentionQuietHoursResult {
            quiet_hours: kr_protocol::scalars::Nullable(state.quiet_hours().cloned()),
            quiet_now: state.quiet_now(now),
            quiet_hours_provable: now.wall_proven,
        })
    }

    /// Serves `review.read`.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::JournalUnavailable`] when the engine cannot be reached, and
    /// [`WorkerError::PreconditionFailed`] when the page continues after a subject this session no
    /// longer holds.
    pub fn review_read(
        &self,
        actor: &ActorId,
        params: &ReviewReadParams,
    ) -> Result<ReviewReadResult> {
        let engine = self.locked()?;
        let (reviews, more) = match params.subject.as_ref() {
            // A subject of another session than the one the page is narrowed to is not on it.
            Some(subject) => (
                engine
                    .review_state(actor, &Viewer::Owner, subject)
                    .map_err(translate)?
                    .filter(|_| {
                        params.session_id.0.is_none_or(|session_id| {
                            session_id == kr_attention::review::subject_session(subject)
                        })
                    })
                    .into_iter()
                    .collect(),
                false,
            ),
            None => engine
                .review_states(
                    actor,
                    &Viewer::Owner,
                    params.session_id.0,
                    params.after.as_ref(),
                    params.max_reviews.get(),
                )
                .map_err(translate)?,
        };
        Ok(ReviewReadResult {
            actor_id: actor.clone(),
            reviews,
            more,
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
            .acknowledge_review(
                actor,
                &Viewer::Owner,
                &params.subject,
                params.version.get(),
                reading(time),
            )
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
                params.session_id,
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
        content: Content,
    ) -> Result<ChangedPage> {
        self.locked()?
            .changed(
                actor,
                params.session_id,
                params.max_changes.get(),
                oldest_output_cursor,
                content,
            )
            .map_err(translate)
    }

    /// Gives the engine a page of retained records it has not seen, announcing none of them.
    ///
    /// This is the catch-up path rather than the live one. A page of retained records is history
    /// as far as the engine is concerned: a question raised and answered inside it is not a
    /// notification to send now, and a request still open at the end of it is. So the page rebuilds
    /// state without deciding anything, and the [`Attention::tick`] that follows a completed
    /// catch-up decides what is owed against the present. A producer with a live event calls
    /// [`Attention::observe`] instead.
    ///
    /// The whole page is one transaction, so a page that could not be written leaves the cursor
    /// where it was and the same page is read again.
    ///
    /// # Errors
    ///
    /// Returns [`WorkerError::JournalUnavailable`] when the page cannot be written down.
    pub fn feed(&self, events: &[SourceEvent], time: &TimeContract) -> Result<Vec<Outcome>> {
        self.locked()?
            .rebuild(events, reading(time))
            .map_err(translate)
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
///
/// The event carries no anchor, because the ledger records a moment on the wall clock and not
/// where that moment sat on this machine's continuous clock. Every interval the engine measures
/// therefore starts where the host read the record, which makes a reminder late rather than
/// immediate. A ledger that comes to record a continuous reading builds the event with
/// `SourceEvent::anchored` and passes `pending_since_anchor`.
#[must_use]
pub fn question_event(sequence: u64, event: &kr_protocol::question::QuestionEvent) -> SourceEvent {
    let kind = match event.kind {
        kr_protocol::question::QuestionEventKind::Created => EventKind::QuestionPending {
            question_id: event.question.question_id,
            session_id: event.question.session_id,
            verified: event.question.source.session_member,
            pending_since_ms: event.pending_since_ms,
            // The ledger records when a request became pending, and not where that moment sat on
            // this machine's continuous clock. So the five-minute reminder counts from where this
            // host read the record, which is late by however long the record waited to be read. A
            // ledger that comes to record a continuous reading beside its moment passes it here.
            pending_since_anchor: None,
            summary: event.question.question.clone(),
        },
        kr_protocol::question::QuestionEventKind::Answered => EventKind::QuestionResolved {
            question_id: event.question.question_id,
            session_id: event.question.session_id,
            answered: true,
        },
        kr_protocol::question::QuestionEventKind::Cancelled
        | kr_protocol::question::QuestionEventKind::Expired => EventKind::QuestionResolved {
            question_id: event.question.question_id,
            session_id: event.question.session_id,
            answered: false,
        },
    };
    SourceEvent::new(
        EventCursor::in_session(
            event.question.session_id,
            AttentionSource::Questions,
            sequence,
        ),
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
///
/// As with a question, the record carries a wall-clock moment and no reading of the continuous
/// clock beside it, so the event carries no anchor and the notice's age starts where the host read
/// the record.
///
/// `fingerprint` is this worker's digest of what the notice says, which is what makes two notices
/// that say the same thing one condition without the store keeping either one's text.
#[must_use]
pub fn host_event(
    sequence: u64,
    session_id: kr_protocol::ids::SessionId,
    event: &crate::journal::HostEvent,
    fingerprint: Fingerprint,
) -> SourceEvent {
    let kind = if event.kind == "notification" {
        EventKind::ApplicationNotice {
            session_id,
            notice: ApplicationNotice {
                id: None,
                title: None,
                body: event.detail.clone(),
                lease_held: false,
                fingerprint: Some(fingerprint),
            },
        }
    } else {
        EventKind::Observed
    };
    SourceEvent::new(
        EventCursor::in_session(session_id, AttentionSource::HostEvents, sequence),
        event.recorded_at_ms,
        kind,
    )
}
