//! The engine, the review state, the visits and the store, put together.
//!
//! [`Attention`] is what a host holds. It applies a typed event to the engine, records whatever
//! review work and semantic change the event created, and writes the result to the feature store
//! before it answers. A read never writes.
//!
//! # Reconstruction
//!
//! [`Attention::open`] reads the store and re-anchors every interval at the reading it opened at.
//! [`Attention::rebuild`] goes further: it starts from nothing and replays the retained events,
//! which is section 24's idempotent reconstruction. Both land in the same place, because an event
//! the engine has already consumed changes nothing, so a replay that overlaps what the store
//! already held is not a second inbox.
//!
//! A replay that starts past where the store had got says so. The jump between the consumed cursor
//! and the first replayed event is a range retention took, and it is recorded as a gap with every
//! item it could have resolved marked uncertain. Nothing in this crate reads a gap as an approval
//! or a completion.

use std::path::Path;

use kr_protocol::attention::{
    AttentionGap, AttentionItem, AttentionKey, AttentionReadResult, AttentionSource, ChangeSummary,
    LogViewState, QuietHours, ReviewState, ReviewSubject, SemanticChangeKind, VisitChangedResult,
};
use kr_protocol::ids::{ActorId, SessionId};
use kr_protocol::scalars::{Nullable, TimestampMs, U64};

use crate::engine::{Engine, Outcome};
use crate::error::Result;
use crate::event::{EventKind, SourceEvent};
use crate::review::Reviews;
use crate::store::{Store, StoredState};
use crate::time::HostReading;
use crate::visit::{Changed, Visit, Visits};

/// The attention engine with its durable state.
#[derive(Debug)]
pub struct Attention {
    engine: Engine,
    reviews: Reviews,
    visits: Visits,
    store: Store,
}

impl Attention {
    /// Opens the feature store at `path` and restores everything it holds.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::StoreUnavailable`] when the store cannot be opened or read, and
    /// [`crate::Error::StoreUnreadable`] when it holds a value this build cannot read back.
    pub fn open(path: impl AsRef<Path>, reading: HostReading) -> Result<Self> {
        Self::from_store(Store::open(path)?, reading)
    }

    /// Opens a store that lives only as long as this value.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::StoreUnavailable`] when the schema cannot be created.
    pub fn in_memory(reading: HostReading) -> Result<Self> {
        Self::from_store(Store::in_memory()?, reading)
    }

    fn from_store(store: Store, reading: HostReading) -> Result<Self> {
        let state = store.load()?;
        let mut engine = Engine::new();
        engine.install(
            state.items,
            state.item_acks,
            state.consumed,
            state.gaps,
            state.pending_inputs,
            state.quiet,
        );
        engine.reanchor(reading);
        let mut reviews = Reviews::new();
        reviews.install(state.subjects, state.review_acks);
        let mut visits = Visits::new();
        visits.install(
            state.changes,
            state.next_cursor,
            state.omitted,
            state.summaries,
            state.visits,
        );
        Ok(Self {
            engine,
            reviews,
            visits,
            store,
        })
    }

    /// Returns the engine.
    #[must_use]
    pub const fn engine(&self) -> &Engine {
        &self.engine
    }

    /// Returns the review state.
    #[must_use]
    pub const fn reviews(&self) -> &Reviews {
        &self.reviews
    }

    /// Returns the visits and the semantic change log.
    #[must_use]
    pub const fn visits(&self) -> &Visits {
        &self.visits
    }

    /// Applies one typed event and records what it produced.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::StoreUnavailable`] when the state cannot be written. The decision
    /// is not published when it cannot be recorded: a host that announced something it could not
    /// remember would announce it again at its next start.
    pub fn apply(&mut self, event: &SourceEvent, reading: HostReading) -> Result<Vec<Outcome>> {
        let fresh = self
            .engine
            .consumed(event.cursor.source)
            .is_none_or(|consumed| event.cursor.sequence > consumed);
        // Read before the engine applies the event: a resolution names the question rather than
        // the session, and the engine forgets a request the moment it resolves one.
        let resolved_session = self.session_of_question(event);
        let outcomes = self.engine.apply(event, reading);
        if fresh {
            self.record_semantics(event, resolved_session);
        }
        self.persist()?;
        Ok(outcomes)
    }

    /// Advances every timer to this reading.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::StoreUnavailable`] when the state cannot be written.
    pub fn tick(&mut self, reading: HostReading) -> Result<Vec<Outcome>> {
        let outcomes = self.engine.tick(reading);
        if !outcomes.is_empty() {
            self.persist()?;
        }
        Ok(outcomes)
    }

    /// Records a range of retained events the host can no longer read.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::StoreUnavailable`] when the state cannot be written.
    pub fn note_gap(
        &mut self,
        source: AttentionSource,
        from: u64,
        to: u64,
    ) -> Result<Vec<Outcome>> {
        let outcomes = self.engine.note_gap(source, from, to);
        if !outcomes.is_empty() {
            self.persist()?;
        }
        Ok(outcomes)
    }

    /// Returns the inbox one actor sees.
    #[must_use]
    pub fn inbox(&self, actor: &ActorId, include_acknowledged: bool) -> Vec<AttentionItem> {
        self.engine.inbox(actor, include_acknowledged)
    }

    /// Returns the inbox read one actor gets, with the quiet-hours state beside it.
    #[must_use]
    pub fn read(
        &self,
        actor: &ActorId,
        include_acknowledged: bool,
        reading: HostReading,
    ) -> AttentionReadResult {
        AttentionReadResult {
            items: self.engine.inbox(actor, include_acknowledged),
            gaps: self.engine.gaps().to_vec(),
            quiet_hours: Nullable(self.engine.quiet_hours().cloned()),
            quiet_now: self.engine.quiet_now(reading),
            quiet_hours_provable: reading.wall_proven,
        }
    }

    /// Records one actor's acknowledgement of each item it holds.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::StoreUnavailable`] when the state cannot be written.
    pub fn acknowledge(
        &mut self,
        actor: &ActorId,
        keys: &[AttentionKey],
        reading: HostReading,
    ) -> Result<Vec<AttentionKey>> {
        let acknowledged = self.engine.acknowledge(actor, keys, reading);
        self.persist()?;
        Ok(acknowledged)
    }

    /// Sets or clears the quiet-hours window.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::StoreUnavailable`] when the state cannot be written.
    pub fn set_quiet_hours(
        &mut self,
        quiet: Option<QuietHours>,
        reading: HostReading,
    ) -> Result<Vec<Outcome>> {
        let outcomes = self.engine.set_quiet_hours(quiet, reading);
        self.persist()?;
        Ok(outcomes)
    }

    /// Records one actor's review acknowledgement.
    ///
    /// It moves a row and nothing else. No command is approved, no patch is applied and no Git
    /// state changes: section 14 makes promotion a separate authorised action, and this type has
    /// no operation that performs one.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::UnknownReviewSubject`] or [`crate::Error::UnknownReviewVersion`]
    /// when the acknowledgement names something the host does not hold, and
    /// [`crate::Error::StoreUnavailable`] when the state cannot be written.
    pub fn acknowledge_review(
        &mut self,
        actor: &ActorId,
        subject: &ReviewSubject,
        version: u64,
        reading: HostReading,
    ) -> Result<ReviewState> {
        let state = self
            .reviews
            .acknowledge(actor, subject, version, reading.wall_ms)?;
        self.persist()?;
        Ok(state)
    }

    /// Records one actor's visit and the log views it had open.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::StoreUnavailable`] when the state cannot be written.
    pub fn acknowledge_visit(
        &mut self,
        actor: &ActorId,
        cursor: u64,
        views: Vec<LogViewState>,
    ) -> Result<Visit> {
        let visit = self.visits.acknowledge(actor, cursor, views);
        self.persist()?;
        Ok(visit)
    }

    /// Records a model summary of one interval.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::StoreUnavailable`] when the state cannot be written.
    pub fn summarise(&mut self, summary: ChangeSummary) -> Result<()> {
        self.visits.summarise(summary);
        self.persist()
    }

    /// Answers what changed since one actor's last visit.
    #[must_use]
    pub fn changed_since(
        &self,
        actor: &ActorId,
        max_changes: u64,
        oldest_output_cursor: u64,
    ) -> Changed {
        self.visits
            .changed_since(actor, max_changes, oldest_output_cursor)
    }

    /// Answers what changed since one actor's last visit, as the wire type.
    #[must_use]
    pub fn changed_result(
        &self,
        actor: &ActorId,
        max_changes: u64,
        oldest_output_cursor: u64,
    ) -> VisitChangedResult {
        let changed = self.changed_since(actor, max_changes, oldest_output_cursor);
        VisitChangedResult {
            actor_id: actor.clone(),
            from_cursor: U64::new(changed.from_cursor),
            to_cursor: U64::new(changed.to_cursor),
            changes: changed.changes,
            omitted: changed.omitted,
            more: changed.more,
            summary: Nullable(changed.summary),
            views: changed.views,
        }
    }

    /// Returns one actor's review state for every subject in one session.
    #[must_use]
    pub fn review_states(&self, actor: &ActorId, session_id: SessionId) -> Vec<ReviewState> {
        self.reviews.states(actor, session_id)
    }

    /// Rebuilds the whole state by replaying the retained events over what the store holds.
    ///
    /// This is section 24's idempotent reconstruction. Replaying events the engine has already
    /// consumed changes nothing, so running it after a restart, after a repair or twice by mistake
    /// gives the same answer. A replay that starts past the consumed cursor records the range
    /// between as a gap.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::StoreUnavailable`] when the state cannot be written.
    pub fn rebuild(
        &mut self,
        events: &[SourceEvent],
        reading: HostReading,
    ) -> Result<Vec<Outcome>> {
        let mut outcomes = Vec::new();
        for event in events {
            let fresh = self
                .engine
                .consumed(event.cursor.source)
                .is_none_or(|consumed| event.cursor.sequence > consumed);
            let resolved_session = self.session_of_question(event);
            outcomes.extend(self.engine.apply(event, reading));
            if fresh {
                self.record_semantics(event, resolved_session);
            }
        }
        self.persist()?;
        Ok(outcomes)
    }

    /// Returns the ranges of retained events the host can no longer read.
    #[must_use]
    pub fn gaps(&self) -> Vec<AttentionGap> {
        self.engine.gaps().to_vec()
    }

    fn record_semantics(&mut self, event: &SourceEvent, resolved_session: Option<SessionId>) {
        match &event.kind {
            EventKind::TurnCompleted {
                session_id,
                turn_id,
                version,
                change_set,
                summary,
            } => {
                self.reviews.record_version(
                    ReviewSubject::CompletedTurn {
                        session_id: *session_id,
                        turn_id: turn_id.clone(),
                    },
                    *version,
                    event.at_ms,
                );
                if let Some(change_set_id) = change_set {
                    self.reviews.record_version(
                        ReviewSubject::ChangeSet {
                            session_id: *session_id,
                            change_set_id: *change_set_id,
                        },
                        *version,
                        event.at_ms,
                    );
                    self.visits.record(
                        SemanticChangeKind::ChangeSetCaptured,
                        *session_id,
                        summary.clone(),
                        event.at_ms,
                    );
                }
                self.visits.record(
                    SemanticChangeKind::TurnCompleted,
                    *session_id,
                    summary.clone(),
                    event.at_ms,
                );
            }
            EventKind::CommandCompleted {
                session_id,
                command,
                exit_code,
            } => {
                self.visits.record(
                    SemanticChangeKind::CommandCompleted,
                    *session_id,
                    format!("{command} exited {exit_code}"),
                    event.at_ms,
                );
            }
            EventKind::QuestionResolved { answered: true, .. } => {
                if let Some(session_id) = resolved_session {
                    self.visits.record(
                        SemanticChangeKind::QuestionAnswered,
                        session_id,
                        "a question was answered".to_owned(),
                        event.at_ms,
                    );
                }
            }
            EventKind::AdapterFailed {
                session_id: Some(session_id),
                plugin_id,
                detail,
            } => {
                self.visits.record(
                    SemanticChangeKind::AdapterState,
                    *session_id,
                    format!("{plugin_id} failed: {detail}"),
                    event.at_ms,
                );
            }
            _ => {}
        }
    }

    /// Returns the session a resolved question belonged to, while the engine still holds it.
    ///
    /// A question the engine never held produces no semantic change, which is right: nothing was
    /// waiting on it here.
    fn session_of_question(&self, event: &SourceEvent) -> Option<SessionId> {
        let EventKind::QuestionResolved { question_id, .. } = &event.kind else {
            return None;
        };
        self.engine
            .pending_inputs()
            .get(question_id)
            .map(|pending| pending.session_id)
    }

    fn persist(&mut self) -> Result<()> {
        let state = StoredState {
            items: self.engine.items().cloned().collect(),
            item_acks: self.engine.all_acknowledgements().clone(),
            consumed: self.engine.all_consumed().clone(),
            gaps: self.engine.gaps().to_vec(),
            pending_inputs: self.engine.pending_inputs().clone(),
            quiet: self.engine.quiet_hours().cloned(),
            subjects: self
                .reviews
                .subjects()
                .map(|subject| {
                    (
                        crate::review::subject_key(&subject.subject),
                        subject.clone(),
                    )
                })
                .collect(),
            review_acks: self.reviews.all_acknowledgements().clone(),
            changes: self.visits.changes().cloned().collect(),
            next_cursor: self.visits.head(),
            omitted: self.visits.omitted().to_vec(),
            summaries: self.visits.summaries().to_vec(),
            visits: self.visits.visits().clone(),
        };
        self.store.save(&state)
    }
}

/// Builds the summary a host records for one interval, naming where it came from.
///
/// It exists here so a summary cannot be recorded without its interval: section 25 requires a
/// model summary to name its source interval and stay separate from the authoritative events, and
/// a constructor that takes both is how that stops being a convention.
#[must_use]
pub fn summary_of(
    text: impl Into<String>,
    model: impl Into<String>,
    from_cursor: u64,
    to_cursor: u64,
    from_ms: TimestampMs,
    to_ms: TimestampMs,
) -> ChangeSummary {
    ChangeSummary {
        text: text.into(),
        from_cursor: U64::new(from_cursor),
        to_cursor: U64::new(to_cursor),
        from_ms,
        to_ms,
        model: model.into(),
    }
}
