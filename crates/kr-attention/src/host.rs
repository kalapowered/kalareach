//! The engine, the review state, the visits and the store, put together.
//!
//! [`Attention`] is what a host holds. It applies a typed event to the engine, records whatever
//! review work and semantic change the event created, and writes the result to the feature store
//! before it answers. A read never writes.
//!
//! # A decision is not published until it is written down
//!
//! Every mutating call works on a copy, writes the copy to the store, and only then installs it.
//! A write that fails leaves the engine exactly where it was, so the caller can try the same event
//! again and get the same answer. The alternative - change first, write after - advances the
//! consumed cursor in memory, and a retry then skips the event it never recorded and announces
//! nothing at all.
//!
//! What this does not cover is the step after: a host that is handed an announcement and then dies
//! before sending it. Closing that needs a delivery outbox with its own receipts, which section 24
//! gives to the delivery journal rather than to the feature store.
//!
//! # Reconstruction
//!
//! [`Attention::open`] reads the store and re-anchors every interval at the reading it opened at.
//! [`Attention::rebuild`] replays the retained events, which is section 24's idempotent
//! reconstruction: an event the engine has already consumed changes nothing, so a replay that
//! overlaps what the store already held is not a second inbox. A replay announces nothing, because
//! an event from an hour ago is not a notification to send now; the first [`Attention::tick`]
//! after it decides every announcement against the present.
//!
//! A replay that starts past where the store had got says so. The jump between the consumed cursor
//! and the first replayed event is a range retention took, and it is recorded as a gap with every
//! item from that source marked uncertain. Nothing here reads a gap as an approval or a
//! completion.

use std::collections::BTreeMap;
use std::path::Path;

use kr_protocol::attention::{
    AttentionAcknowledgeResult, AttentionGap, AttentionItem, AttentionKey, AttentionReadParams,
    AttentionReadResult, AttentionRule, AttentionSource, ChangeSummary, LogViewState,
    MAX_ATTENTION_ITEMS, MAX_RETAINED_ACTORS, QuietHours, ReviewAcknowledgeResult, ReviewState,
    ReviewSubject, SemanticChangeKind, VisitAcknowledgeResult, VisitChangedResult,
};
use kr_protocol::ids::{ActorId, SessionId};
use kr_protocol::scalars::{Nullable, TimestampMs, U64};

use crate::engine::{Announcement, Content, Engine, Outcome, Restored};
use crate::error::Result;
use crate::event::{EventKind, SourceEvent};
use crate::review::Reviews;
use crate::store::{Owner, Store, StoredState};
use crate::time::HostReading;
use crate::visit::{Changed, Visit, Visits};

/// Everything the feature store holds, in memory.
#[derive(Clone, Debug, Default)]
struct State {
    engine: Engine,
    reviews: Reviews,
    visits: Visits,
    revisions: BTreeMap<ActorId, u64>,
}

/// The attention engine with its durable state.
#[derive(Debug)]
pub struct Attention {
    state: State,
    store: Store,
    /// This process's claim on the store, refreshed by every write it makes.
    ///
    /// Every write replaces the whole state and is made from the copy this value holds, so two
    /// owners would each replace the other's work with a picture of the world that predates it.
    /// The claim is a row in the store, taken as it is opened, and a second opener that finds a
    /// live one is told so rather than handed a state it may not write back.
    owner: Owner,
    /// The last reading this value was given, which is what refreshes the claim.
    ///
    /// A call that carries no reading of its own refreshes the claim at the last one there was,
    /// which is never later than now: a claim that looks older than it is may be taken by somebody
    /// else, and one that looked newer would keep a store nobody owns.
    latest: HostReading,
}

impl Attention {
    /// Opens the feature store at `path` and restores everything it holds.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::StoreHeld`] when another live owner already holds the store,
    /// [`crate::Error::StoreUnavailable`] when it cannot be opened, read or written back, and
    /// [`crate::Error::StoreUnreadable`] when it holds a value this build cannot read. Opening
    /// writes, because what it read back may have had to be re-anchored.
    pub fn open(path: impl AsRef<Path>, reading: HostReading) -> Result<Self> {
        Self::from_store(Store::open(path)?, reading)
    }

    /// Opens the store inside the worker's private journal, or in memory when there is none.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::StoreHeld`] when another live owner already holds the store,
    /// [`crate::Error::StoreUnavailable`] when it cannot be opened, read or written back, and
    /// [`crate::Error::StoreUnreadable`] when it holds a value this build cannot read. Opening
    /// writes, because what it read back may have had to be re-anchored.
    pub fn beside(path: Option<&Path>, reading: HostReading) -> Result<Self> {
        Self::from_store(Store::beside(path)?, reading)
    }

    /// Opens a store that lives only as long as this value.
    ///
    /// Nothing it holds outlives the drop, so its opening write is a write to memory and the
    /// intervals it re-anchors are re-anchored for this value alone.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::StoreUnavailable`] when the schema cannot be created or the state
    /// this open re-anchored cannot be written back.
    pub fn in_memory(reading: HostReading) -> Result<Self> {
        Self::from_store(Store::in_memory()?, reading)
    }

    fn from_store(mut store: Store, reading: HostReading) -> Result<Self> {
        // The read, the re-anchoring and the write that records it are one transaction, and its
        // write lock is taken before the read. A whole-state write replaces everything, so another
        // connection that committed between the two would have its work replaced by the older
        // state this one had read.
        let claim = Owner::fresh_claim();
        let owner = Owner::here(claim, reading);
        let state = store.recover(|stored| {
            // The claim is read and written under the transaction that reads the state, so no
            // opener can come between the two. A claim from a boot that has ended, or one this
            // boot has not refreshed within its lease, is taken; a live one is told about.
            if let Some(held) = stored.owner
                && held.stands_against(claim, reading)
            {
                return Err(crate::Error::StoreHeld {
                    process: held.process,
                });
            }
            let state = Self::restore(stored, reading);
            let written = snapshot(&state, Some(owner));
            Ok((written, state))
        })?;
        Ok(Self {
            state,
            store,
            owner,
            latest: reading,
        })
    }

    /// Builds the state one stored snapshot and one reading describe.
    fn restore(stored: crate::store::StoredState, reading: HostReading) -> State {
        let mut engine = Engine::new();
        engine.install(Restored {
            items: stored.items,
            acks: stored.item_acks,
            consumed: stored.consumed,
            gaps: stored.gaps,
            pending: stored.pending_inputs,
            quiet: stored.quiet,
            dropped: stored.dropped,
            next_announcement: stored.next_announcement,
            keys: stored.keys,
        });
        engine.reanchor(reading);
        let mut reviews = Reviews::new();
        reviews.install(stored.subjects, stored.review_acks);
        let mut visits = Visits::new();
        visits.install(
            stored.changes,
            stored.next_cursor,
            stored.omitted,
            stored.summaries,
            stored.visits,
        );
        State {
            engine,
            reviews,
            visits,
            revisions: stored.revisions,
        }
    }

    /// Returns the engine.
    #[must_use]
    pub const fn engine(&self) -> &Engine {
        &self.state.engine
    }

    /// Returns the review state.
    #[must_use]
    pub const fn reviews(&self) -> &Reviews {
        &self.state.reviews
    }

    /// Returns the visits and the semantic change log.
    #[must_use]
    pub const fn visits(&self) -> &Visits {
        &self.state.visits
    }

    /// Returns one actor's acknowledgement revision.
    #[must_use]
    pub fn revision(&self, actor: &ActorId) -> u64 {
        self.state.revisions.get(actor).copied().unwrap_or_default()
    }

    /// Applies one typed event and records what it produced.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::StoreUnavailable`] when the state cannot be written. Nothing the
    /// event would have changed is kept, and nothing is announced: a decision this host could not
    /// record is one it would make again at its next start.
    pub fn apply(&mut self, event: &SourceEvent, reading: HostReading) -> Result<Vec<Outcome>> {
        self.latest = reading;

        self.commit(|state| {
            let mut outcomes = Vec::new();
            consume(state, event, reading, false, &mut outcomes);
            outcomes
        })
    }

    /// Lets the store go, so the next owner does not wait out a lease nobody is holding.
    ///
    /// An owner that ends without this - killed, or its process gone - leaves its claim behind,
    /// and the lease is what releases that one. This is the ordinary way, and it is immediate.
    fn release(&mut self) {
        // Best effort: a store that cannot be written now is one whose claim the lease releases
        // instead, and there is nobody left to tell.
        let released = snapshot(&self.state, None);
        let _ = self.store.save(&released);
    }

    /// Returns the key one rule and one subject land on in this session's store.
    ///
    /// A producer that wants to name an item it raised asks here rather than deriving one of its
    /// own: the derivation is under a secret of this store's, which is what stops a reader served
    /// the record without the session's text working the key out from a guess at the text.
    #[must_use]
    pub fn key_for(
        &self,
        rule: kr_protocol::attention::AttentionRule,
        subject: &str,
    ) -> AttentionKey {
        self.state.engine.key_for(rule, subject)
    }

    /// Returns the continuous reading the next timer is due at.
    ///
    /// A host wakes at it rather than polling, and `None` means nothing is waiting on time. While
    /// anything is deferred and the window that deferred it has ended, it is now.
    #[must_use]
    pub fn next_deadline(&self, reading: HostReading) -> Option<u64> {
        self.state.engine.next_deadline(reading)
    }

    /// Advances every timer to this reading.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::StoreUnavailable`] when the state cannot be written.
    pub fn tick(&mut self, reading: HostReading) -> Result<Vec<Outcome>> {
        self.latest = reading;

        self.commit(|state| {
            let outcomes = state.engine.tick(reading);
            carry_gaps(state, &outcomes);
            outcomes
        })
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
        self.commit(|state| {
            let outcomes = state.engine.note_gap(source, from, to);
            carry_gaps(state, &outcomes);
            outcomes
        })
    }

    /// Records where a source stands without claiming anything about what came before.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::StoreUnavailable`] when the state cannot be written.
    pub fn start_from(&mut self, source: AttentionSource, sequence: u64) -> Result<()> {
        self.commit(|state| {
            state.engine.start_from(source, sequence);
        })
    }

    /// Returns the inbox one actor sees.
    #[must_use]
    pub fn inbox(
        &self,
        actor: &ActorId,
        include_acknowledged: bool,
        content: Content,
    ) -> Vec<AttentionItem> {
        self.state
            .engine
            .inbox(actor, include_acknowledged, content)
    }

    /// Returns one page of the inbox one actor sees, with the quiet-hours state beside it.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::UnknownContinuation`] when the key a page continues after is no
    /// longer in this actor's inbox. Starting again at the beginning would repeat items the
    /// client has already been given, and it could not tell that from a valid continuation.
    pub fn read(
        &self,
        actor: &ActorId,
        params: &AttentionReadParams,
        reading: HostReading,
        content: Content,
    ) -> Result<AttentionReadResult> {
        let all = self
            .state
            .engine
            .inbox(actor, params.include_acknowledged, content);
        let start = match params.after.as_ref() {
            Some(after) => all
                .iter()
                .position(|item| &item.key == after)
                .map(|index| index + 1)
                .ok_or_else(|| crate::Error::UnknownContinuation {
                    key: after.as_str().to_owned(),
                })?,
            None => 0,
        };
        let limit =
            usize::try_from(params.max_items.get().clamp(1, MAX_ATTENTION_ITEMS)).unwrap_or(1);
        let page: Vec<_> = all.iter().skip(start).take(limit).cloned().collect();
        let more = all.len() > start.saturating_add(page.len());
        Ok(AttentionReadResult {
            items: page,
            more,
            dropped: U64::new(self.state.engine.dropped()),
            gaps: self.state.engine.gaps().to_vec(),
            quiet_hours: Nullable(self.state.engine.quiet_hours().cloned()),
            quiet_now: self.state.engine.quiet_now(reading),
            quiet_hours_provable: reading.wall_proven,
        })
    }

    /// Returns the announcements the host has decided and no consumer has settled.
    ///
    /// Nothing is forgotten by asking. A consumer records what it is given and then calls
    /// [`Attention::settle_announcements`]; anything it does not settle is offered again.
    #[must_use]
    pub fn take_announcements(&self) -> Vec<Announcement> {
        self.state.engine.take_announcements()
    }

    /// Forgets the announcements a consumer has taken durable responsibility for.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::StoreUnavailable`] when the state cannot be written, in which case
    /// nothing is forgotten and the same announcements are offered again.
    pub fn settle_announcements(&mut self, settled: &[(AttentionKey, u64)]) -> Result<()> {
        self.commit(|state| state.engine.settle_announcements(settled))
    }

    /// Returns how many decided announcements are waiting to be taken.
    #[must_use]
    pub fn awaiting_delivery(&self) -> usize {
        self.state.engine.awaiting_delivery()
    }

    /// Answers whether this store would admit one actor, without changing anything.
    ///
    /// The bound is on admission rather than on eviction: nothing anybody has acknowledged is
    /// deleted to make room for somebody new. A host asks here before it dispatches, so an actor
    /// past the bound is a refusal of the action rather than an outcome nobody can establish.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::TooManyActors`] when this actor is new and the bound is reached.
    pub fn check_actor(&self, actor: &ActorId) -> Result<()> {
        admit(&self.state, actor)
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
    ) -> Result<AttentionAcknowledgeResult> {
        self.latest = reading;
        self.try_commit(|state| {
            admit(state, actor)?;
            let acknowledged = state.engine.acknowledge(actor, keys, reading);
            let revision = bump(state, actor);
            Ok(AttentionAcknowledgeResult {
                actor_id: actor.clone(),
                acknowledged,
                revision: U64::new(revision),
            })
        })
    }

    /// Sets or clears the quiet-hours window.
    ///
    /// It announces nothing. What the change lets through is released by the next
    /// [`Attention::tick`], which [`Attention::next_deadline`] brings forward to now while
    /// anything is deferred, so a release is decided against a history the host has finished
    /// reading rather than against whatever it had reached when somebody changed a setting.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::StoreUnavailable`] when the state cannot be written.
    pub fn set_quiet_hours(&mut self, quiet: Option<QuietHours>) -> Result<()> {
        self.commit(|state| state.engine.set_quiet_hours(quiet))
    }

    /// Records one actor's review acknowledgement.
    ///
    /// It moves a row and nothing else. No command is approved, no patch is applied and no Git
    /// state changes: section 14 makes promotion a separate authorised action, and this type has
    /// no operation that performs one. The inbox item that said the turn was waiting to be
    /// reviewed is acknowledged for the same actor at the same time, so review state and the inbox
    /// say one thing rather than two.
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
    ) -> Result<ReviewAcknowledgeResult> {
        self.latest = reading;
        self.try_commit(|state| {
            admit(state, actor)?;
            let review = state
                .reviews
                .acknowledge(actor, subject, version, reading.wall_ms)?;
            if !review.outstanding
                && let ReviewSubject::CompletedTurn {
                    session_id,
                    turn_id,
                } = subject
            {
                let key = state.engine.key_for(
                    AttentionRule::ReviewReady,
                    &format!("{session_id}|{turn_id}"),
                );
                state.engine.acknowledge(actor, &[key], reading);
            }
            let revision = bump(state, actor);
            Ok(ReviewAcknowledgeResult {
                actor_id: actor.clone(),
                review,
                revision: U64::new(revision),
            })
        })
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
    ) -> Result<VisitAcknowledgeResult> {
        self.try_commit(|state| {
            admit(state, actor)?;
            let revision = bump(state, actor);
            let visit = state.visits.acknowledge(actor, cursor, views, revision);
            Ok(VisitAcknowledgeResult {
                actor_id: actor.clone(),
                acknowledged_cursor: U64::new(visit.cursor),
                views: visit.views,
                revision: U64::new(revision),
            })
        })
    }

    /// Returns one actor's visit.
    #[must_use]
    pub fn visit(&self, actor: &ActorId) -> Option<&Visit> {
        self.state.visits.visit(actor)
    }

    /// Records a model summary of one interval.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::StoreUnavailable`] when the state cannot be written.
    pub fn summarise(&mut self, summary: ChangeSummary) -> Result<()> {
        self.commit(|state| state.visits.summarise(summary))
    }

    /// Answers what changed since one actor's last visit.
    #[must_use]
    pub fn changed_since(
        &self,
        actor: &ActorId,
        max_changes: u64,
        oldest_output_cursor: u64,
        content: Content,
    ) -> Changed {
        self.state
            .visits
            .changed_since(actor, max_changes, oldest_output_cursor, content)
    }

    /// Answers what changed since one actor's last visit, as the wire type.
    #[must_use]
    pub fn changed_result(
        &self,
        actor: &ActorId,
        max_changes: u64,
        oldest_output_cursor: u64,
        content: Content,
    ) -> VisitChangedResult {
        let changed = self.changed_since(actor, max_changes, oldest_output_cursor, content);
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

    /// Returns one page of one actor's review state for one session, oldest first.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::UnknownContinuation`] when `after` names a subject this session no
    /// longer holds.
    pub fn review_states(
        &self,
        actor: &ActorId,
        session_id: SessionId,
        after: Option<&ReviewSubject>,
        max: u64,
    ) -> Result<(Vec<ReviewState>, bool)> {
        self.state
            .reviews
            .states_page(actor, session_id, after, max)
    }

    /// Rebuilds the whole state by replaying the retained events over what the store holds.
    ///
    /// This is section 24's idempotent reconstruction. Replaying events the engine has already
    /// consumed changes nothing, so running it after a restart, after a repair or twice by mistake
    /// gives the same answer. Nothing is announced: the events are history, and the first
    /// [`Attention::tick`] after the replay decides what still needs saying.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::StoreUnavailable`] when the state cannot be written.
    pub fn rebuild(
        &mut self,
        events: &[SourceEvent],
        reading: HostReading,
    ) -> Result<Vec<Outcome>> {
        self.latest = reading;
        self.commit(|state| {
            let mut outcomes = Vec::new();
            for event in events {
                consume(state, event, reading, true, &mut outcomes);
            }
            outcomes
        })
    }

    /// Returns the ranges of retained events the host can no longer read.
    #[must_use]
    pub fn gaps(&self) -> Vec<AttentionGap> {
        self.state.engine.gaps().to_vec()
    }

    /// Runs one change against a copy of the state and installs it once it is written down.
    fn commit<T>(&mut self, change: impl FnOnce(&mut State) -> T) -> Result<T> {
        self.try_commit(|state| Ok(change(state)))
    }

    /// The same, for a change that can refuse before anything is written.
    fn try_commit<T>(&mut self, change: impl FnOnce(&mut State) -> Result<T>) -> Result<T> {
        let mut candidate = self.state.clone();
        let answer = change(&mut candidate)?;
        // Every write refreshes the claim, which is what tells a later opener this owner is still
        // here.
        self.owner = Owner::here(self.owner.claim, self.latest);
        self.store.save(&snapshot(&candidate, Some(self.owner)))?;
        self.state = candidate;
        Ok(answer)
    }
}

/// Returns the next revision for one actor, which every acknowledgement of theirs advances.
fn bump(state: &mut State, actor: &ActorId) -> u64 {
    let revision = state.revisions.entry(actor.clone()).or_default();
    *revision = revision.saturating_add(1);
    *revision
}

/// Admits one actor to the feature store, or refuses a new one past the bound.
///
/// An acknowledgement is that actor's own record, and this store never deletes one to make room:
/// the bound is on admission instead. An actor already here is always admitted, so nothing anybody
/// has already acknowledged stops working when the bound is reached.
fn admit(state: &State, actor: &ActorId) -> Result<()> {
    if state.revisions.contains_key(actor) || state.revisions.len() < MAX_RETAINED_ACTORS {
        return Ok(());
    }
    Err(crate::Error::TooManyActors {
        bound: MAX_RETAINED_ACTORS,
    })
}

/// Applies one event to a candidate state, live or as a replay.
fn consume(
    state: &mut State,
    event: &SourceEvent,
    reading: HostReading,
    replay: bool,
    outcomes: &mut Vec<Outcome>,
) {
    let fresh = state
        .engine
        .consumed(event.cursor.source)
        .is_none_or(|consumed| event.cursor.sequence > consumed);
    // A turn the host already holds at this version or later is a record it has, not review work
    // it has been given. The *engine* is told the record was consumed and nothing more, so a late
    // event cannot reopen an inbox item whose review is complete. What the event says about every
    // other version it names still goes to the review state: a turn arriving late beside a change
    // set the host has not seen is still that change set's capture, and each version is weighed on
    // its own there.
    let consumed_only;
    let for_engine = if reopens_nothing(state, event) {
        consumed_only = SourceEvent::new(event.cursor, event.at_ms, EventKind::Observed);
        &consumed_only
    } else {
        event
    };
    let produced = if replay {
        state.engine.replay(for_engine, reading)
    } else {
        state.engine.apply(for_engine, reading)
    };
    carry_gaps(state, &produced);
    outcomes.extend(produced);
    if fresh {
        record_semantics(state, event);
    }
}

/// Whether this event names a completed turn at a version the host already holds.
///
/// The versions only go forward, so an event naming one the host has reached is a record arriving
/// late rather than new review work. Raising its item again would reopen a review an actor has
/// already completed, and announce it a second time once the rule's window had passed.
fn reopens_nothing(state: &State, event: &SourceEvent) -> bool {
    let EventKind::TurnCompleted {
        session_id,
        turn_id,
        version,
        ..
    } = &event.kind
    else {
        return false;
    };
    state
        .reviews
        .version_of(&ReviewSubject::CompletedTurn {
            session_id: *session_id,
            turn_id: turn_id.clone(),
        })
        .is_some_and(|held| held >= *version)
}

/// Puts every gap the engine recorded where a visit can see it.
fn carry_gaps(state: &mut State, outcomes: &[Outcome]) {
    for outcome in outcomes {
        if let Outcome::GapRecorded { gap } = outcome {
            state.visits.note_source_gap(*gap);
        }
    }
}

/// Records the review work and the semantic change one event produced.
fn record_semantics(state: &mut State, event: &SourceEvent) {
    match &event.kind {
        EventKind::TurnCompleted {
            session_id,
            turn_id,
            version,
            change_set,
            summary,
        } => {
            let turn_moved = state.reviews.record_version(
                ReviewSubject::CompletedTurn {
                    session_id: *session_id,
                    turn_id: turn_id.clone(),
                },
                *version,
                event.at_ms,
            );
            // Each version is weighed on its own: a turn arriving late beside a change set the
            // host has not seen records the change set and nothing else.
            if let Some((change_set_id, change_set_version)) = change_set
                && state.reviews.record_version(
                    ReviewSubject::ChangeSet {
                        session_id: *session_id,
                        change_set_id: *change_set_id,
                    },
                    *change_set_version,
                    event.at_ms,
                )
            {
                state.visits.record(
                    SemanticChangeKind::ChangeSetCaptured,
                    *session_id,
                    summary.clone(),
                    event.at_ms,
                );
            }
            if turn_moved {
                state.visits.record(
                    SemanticChangeKind::TurnCompleted,
                    *session_id,
                    summary.clone(),
                    event.at_ms,
                );
            }
        }
        EventKind::ChangeSetCaptured {
            session_id,
            change_set_id,
            version,
            summary,
        } => {
            if state.reviews.record_version(
                ReviewSubject::ChangeSet {
                    session_id: *session_id,
                    change_set_id: *change_set_id,
                },
                *version,
                event.at_ms,
            ) {
                state.visits.record(
                    SemanticChangeKind::ChangeSetCaptured,
                    *session_id,
                    summary.clone(),
                    event.at_ms,
                );
            }
        }
        EventKind::CommandCompleted {
            session_id,
            command,
            exit_code,
        } => {
            state.visits.record(
                SemanticChangeKind::CommandCompleted,
                *session_id,
                format!("{command} exited {exit_code}"),
                event.at_ms,
            );
        }
        EventKind::QuestionResolved {
            session_id,
            answered: true,
            ..
        } => {
            state.visits.record(
                SemanticChangeKind::QuestionAnswered,
                *session_id,
                "a question was answered".to_owned(),
                event.at_ms,
            );
        }
        EventKind::AdapterFailed {
            session_id: Some(session_id),
            plugin_id,
            detail,
        } => {
            state.visits.record(
                SemanticChangeKind::AdapterState,
                *session_id,
                format!("{plugin_id} failed: {detail}"),
                event.at_ms,
            );
        }
        _ => {}
    }
}

impl Drop for Attention {
    fn drop(&mut self) {
        self.release();
    }
}

/// Returns everything the feature store writes down.
fn snapshot(state: &State, owner: Option<Owner>) -> StoredState {
    StoredState {
        items: state.engine.items().cloned().collect(),
        item_acks: state.engine.all_acknowledgements().clone(),
        revisions: state.revisions.clone(),
        consumed: state.engine.all_consumed().clone(),
        gaps: state.engine.gaps().to_vec(),
        dropped: state.engine.dropped(),
        owner,
        next_announcement: state.engine.next_announcement(),
        keys: state.engine.key_secret(),
        pending_inputs: state.engine.pending_inputs().clone(),
        quiet: state.engine.quiet_hours().cloned(),
        subjects: state
            .reviews
            .subjects()
            .map(|subject| {
                (
                    crate::review::subject_key(&subject.subject),
                    subject.clone(),
                )
            })
            .collect(),
        review_acks: state.reviews.all_acknowledgements().clone(),
        changes: state.visits.changes().cloned().collect(),
        next_cursor: state.visits.head(),
        omitted: state.visits.omitted().to_vec(),
        summaries: state.visits.summaries().to_vec(),
        visits: state.visits.visits().clone(),
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
