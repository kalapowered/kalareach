//! The engine, the review state, the visits and the store, put together.
//!
//! [`Attention`] is what a host holds: one per environment. It applies a typed event to the
//! engine, records whatever review work and semantic change the event created, and writes the
//! result to the feature store before it answers. A read never writes.
//!
//! # A decision is not published until it is written down
//!
//! Every mutating call works on a copy, writes what the copy changed to the store, and only then
//! installs it. A write that fails leaves the engine exactly where it was, so the caller can try
//! the same event again and get the same answer. The alternative - change first, write after -
//! advances the consumed cursor in memory, and a retry then skips the event it never recorded and
//! announces nothing at all.
//!
//! One failure is not like that. [`crate::Error::StoreTaken`] says the store is no longer this
//! value's, so what it holds is the state as it was before somebody else took it: retrying against
//! it would decide against a state it no longer has. It answers nothing after that, and the store
//! is opened again instead.
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
//! item from that origin and source marked uncertain. Nothing here reads a gap as an approval or a
//! completion.
//!
//! # Actions
//!
//! [`Attention::perform`] is how a host that owns the review and attention group's mutations
//! performs one: the action's record is written in the same transaction as its effect, an exact
//! repeat is answered from that record, and a different request under the same identity is
//! refused. The caller's admission is asked inside the transaction, after the claim and before
//! anything the request names is weighed or written, so an action whose authority lapsed while it
//! waited is refused as that and does not begin.

use std::collections::BTreeMap;
use std::path::Path;

use kr_protocol::attention::{
    AttentionAcknowledgeResult, AttentionGap, AttentionItem, AttentionItemRevision, AttentionKey,
    AttentionReadParams, AttentionReadResult, AttentionRule, AttentionSource, LogViewState,
    MAX_ATTENTION_ITEMS, MAX_RETAINED_ACTORS, QuietHours, ReviewAcknowledgeResult, ReviewState,
    ReviewSubject, SemanticChangeKind, VisitAcknowledgeResult, VisitChangedResult,
};
use kr_protocol::ids::{ActorId, SessionId};
use kr_protocol::scalars::{Nullable, U64};

use crate::engine::{Announcement, Content, Engine, Item, Outcome, Restored, Text, clip_summary};
use crate::error::Result;
use crate::event::{EventCursor, EventKind, Origin, SourceEvent};
use crate::review::Reviews;
use crate::scope::Viewer;
use crate::store::{ActionRecord, Claimant, Owner, Store, StoredState};
use crate::time::HostReading;
use crate::visit::{Visit, Visits};

/// Everything the feature store holds, in memory.
#[derive(Clone, Debug, Default)]
struct State {
    engine: Engine,
    reviews: Reviews,
    visits: Visits,
    revisions: BTreeMap<ActorId, u64>,
}

/// One page of the inbox, with the records its session text is read from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InboxPage {
    /// The page, with the host's own words filled in and a session's text left null.
    pub result: AttentionReadResult,
    /// For each item whose text is a session's, its index in the page and the record to read it
    /// from. Empty when the caller is served no session text.
    pub texts: Vec<(usize, EventCursor)>,
}

/// One changed-since-last-visit answer, with the records its session text is read from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChangedPage {
    /// The answer, with the host's own words filled in and a session's text left null.
    pub result: VisitChangedResult,
    /// For each change whose text is a session's, its index in the answer and the record to read
    /// it from. Empty when the caller is served no session text.
    pub texts: Vec<(usize, EventCursor)>,
}

/// One action a caller asked for, as the store records it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActionKey {
    /// The verified actor whose action it is.
    pub actor: ActorId,
    /// The identity the actor gave it.
    pub action_id: String,
    /// The method it performs.
    pub method: String,
    /// A digest of the request, which tells an exact repeat from a reuse of the identity.
    pub digest: Vec<u8>,
}

/// One of the review and attention group's mutations.
#[derive(Debug)]
pub enum Mutation<'a> {
    /// `attention.acknowledge`.
    Acknowledge {
        /// Who is asking, which bounds what may be acknowledged.
        viewer: &'a Viewer<'a>,
        /// The items, each at the revision the caller saw.
        items: &'a [AttentionItemRevision],
    },
    /// `attention.quiet_hours`.
    QuietHours(Option<QuietHours>),
    /// `review.acknowledge`.
    Review {
        /// Who is asking, which bounds which subjects may be acknowledged.
        viewer: &'a Viewer<'a>,
        /// The subject.
        subject: &'a ReviewSubject,
        /// The version the caller read.
        version: u64,
    },
    /// `visit.acknowledge`.
    Visit {
        /// The session visited.
        session_id: SessionId,
        /// The semantic cursor the caller has seen up to.
        cursor: u64,
        /// The log views it had open.
        views: Vec<LogViewState>,
    },
}

/// What a mutation answered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Answer {
    /// `attention.acknowledge`.
    Acknowledged(AttentionAcknowledgeResult),
    /// `attention.quiet_hours`: the window now in force.
    QuietHours(Option<QuietHours>),
    /// `review.acknowledge`.
    Reviewed(ReviewAcknowledgeResult),
    /// `visit.acknowledge`.
    Visited(VisitAcknowledgeResult),
}

/// What [`Attention::perform`] did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Performed {
    /// The action was performed now, and this is its answer.
    Done(Answer),
    /// The action had been performed before, and this is its record.
    Retained(ActionRecord),
}

/// The attention engine with its durable state.
#[derive(Debug)]
pub struct Attention {
    state: State,
    /// What this owner last wrote, which is what the next write is worked out against.
    written: StoredState,
    store: Store,
    /// This process's claim on the store, refreshed by every write it makes.
    ///
    /// Every write is worked out from the copy this value holds, so two owners would each replace
    /// the other's work with a picture of the world that predates it. The claim is a row in the
    /// store, taken as it is opened, and an opener that finds a standing one is told so rather than
    /// handed a state it may not write back. It is read again inside every write, so this value
    /// changes nothing after the store has been taken from it.
    owner: Owner,
    /// The last reading this value was given, which is what refreshes the claim.
    ///
    /// A call that carries no reading of its own refreshes the claim at the last one there was,
    /// which is never later than now: a claim that looks older than it is may be taken by somebody
    /// else, and one that looked newer would keep a store nobody owns.
    latest: HostReading,
    /// Whether the store has been taken from this value.
    ///
    /// What it holds is the state as it was before that happened, which is not the state any more:
    /// an item somebody else has acknowledged still looks outstanding here, and a decision they
    /// resolved is still waiting to be announced. So it answers nothing once this is set. The
    /// store is read again by whoever opens it next.
    taken: bool,
}

impl Attention {
    /// Opens the feature store at `path` and restores everything it holds.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::StoreHeld`] when another live owner already holds the store,
    /// [`crate::Error::StoreAliased`] when the platform says more than one name reaches its file,
    /// [`crate::Error::StoreUnavailable`] when it cannot be opened, read or written back, and
    /// [`crate::Error::StoreUnreadable`] when it holds a value this build cannot read. Opening
    /// writes, because what it read back may have had to be re-anchored.
    pub fn open(
        path: impl AsRef<Path>,
        reading: HostReading,
        claimant: &Claimant<'_>,
    ) -> Result<Self> {
        Self::from_store(Store::open(path)?, reading, claimant)
    }

    /// Opens the store at `path`, or in memory when there is none.
    ///
    /// # Errors
    ///
    /// As [`Attention::open`].
    pub fn beside(
        path: Option<&Path>,
        reading: HostReading,
        claimant: &Claimant<'_>,
    ) -> Result<Self> {
        Self::from_store(Store::beside(path)?, reading, claimant)
    }

    /// Opens a store that lives only as long as this value.
    ///
    /// Nothing it holds outlives the drop, so its opening write is a write to memory and the
    /// intervals it re-anchors are re-anchored for this value alone. It takes the claim its own
    /// writes are made under like any other store, because nothing about the state depends on
    /// where the state is kept; there is simply nobody else who could be holding it.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::StoreUnavailable`] when the schema cannot be created or the state
    /// this open re-anchored cannot be written back.
    pub fn in_memory(reading: HostReading, claimant: &Claimant<'_>) -> Result<Self> {
        Self::from_store(Store::in_memory()?, reading, claimant)
    }

    fn from_store(mut store: Store, reading: HostReading, claimant: &Claimant<'_>) -> Result<Self> {
        // The claim, the read, the re-anchoring and the write that records it are one transaction,
        // and its write lock is taken before any of them. The write replaces every row, so another
        // connection that committed between the read and the write would have its work replaced
        // by the older state this one had read.
        let claim = Owner::fresh_claim();
        let owner = Owner::here(claim, claimant.process().clone(), reading);
        let taken = owner.clone();
        let (state, written) = store.recover(
            // The claim on the store is read first and answered before a row of the state is read,
            // so an opener that may not have it is refused rather than handed a state it would not
            // be allowed to write back.
            |held| match held {
                Some(held)
                    if held.stands_against(claim, reading, |process| {
                        claimant.liveness_of(process)
                    }) =>
                {
                    Err(crate::Error::StoreHeld {
                        process: held.process.pid.get(),
                    })
                }
                _ => Ok(taken),
            },
            |stored| {
                let state = Self::restore(stored, reading);
                let written = snapshot(&state);
                Ok((written.clone(), (state, written)))
            },
        )?;
        Ok(Self {
            state,
            written,
            store,
            owner,
            latest: reading,
            taken: false,
        })
    }

    /// Builds the state one stored snapshot and one reading describe.
    fn restore(stored: StoredState, reading: HostReading) -> State {
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
            next_revision: stored.next_revision,
            finalised: stored.finalised,
            keys: stored.keys,
        });
        engine.reanchor(reading);
        let mut reviews = Reviews::new();
        reviews.install(stored.subjects, stored.review_acks);
        let mut visits = Visits::new();
        visits.install(stored.sessions);
        State {
            engine,
            reviews,
            visits,
            revisions: stored.revisions,
        }
    }

    /// Returns the engine.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::StoreTaken`] when the store is no longer this owner's, because what
    /// this value holds is then the state as it was before somebody else took it.
    pub fn engine(&self) -> Result<&Engine> {
        self.live()?;
        Ok(&self.state.engine)
    }

    /// Returns the review state.
    ///
    /// # Errors
    ///
    /// As [`Attention::engine`].
    pub fn reviews(&self) -> Result<&Reviews> {
        self.live()?;
        Ok(&self.state.reviews)
    }

    /// Returns the visits and the semantic change logs.
    ///
    /// # Errors
    ///
    /// As [`Attention::engine`].
    pub fn visits(&self) -> Result<&Visits> {
        self.live()?;
        Ok(&self.state.visits)
    }

    /// Returns one actor's acknowledgement revision.
    ///
    /// # Errors
    ///
    /// As [`Attention::engine`].
    pub fn revision(&self, actor: &ActorId) -> Result<u64> {
        self.live()?;
        Ok(self.state.revisions.get(actor).copied().unwrap_or_default())
    }

    /// Applies one typed event and records what it produced.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::StoreUnavailable`] when the state cannot be written, and
    /// [`crate::Error::StoreTaken`] when the store is no longer this owner's to write. Nothing the
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

    /// Rebuilds the state by replaying retained events over what the store holds.
    ///
    /// This is section 24's idempotent reconstruction. Replaying events the engine has already
    /// consumed changes nothing, so running it after a restart, after a repair or twice by mistake
    /// gives the same answer. Nothing is announced: the events are history, and the first
    /// [`Attention::tick`] after the replay decides what still needs saying.
    ///
    /// # Errors
    ///
    /// As [`Attention::apply`].
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

    /// Recovers one source whose consumer position ran ahead of this store, in one write.
    ///
    /// A source that keeps its own record of how far this store has read can be ahead of the store
    /// when the store lost what it had written. The records up to that position that the source
    /// still holds are replayed, and the whole range the store has no record of reading is then
    /// recorded as a gap, because some of it may be gone; every unresolved item of that origin and
    /// source is uncertain afterwards, including one the replay raised, since the record that
    /// would have resolved it may be the one that is gone. All of it is one write, so a failure
    /// leaves the store where it was and the recovery is repeated rather than half done.
    ///
    /// # Errors
    ///
    /// As [`Attention::apply`].
    pub fn recover_source(
        &mut self,
        origin: Origin,
        source: AttentionSource,
        retained: &[SourceEvent],
        through: u64,
        reading: HostReading,
    ) -> Result<Vec<Outcome>> {
        self.latest = reading;
        self.commit(|state| {
            let from = state
                .engine
                .consumed(origin, source)
                .unwrap_or_default()
                .saturating_add(1);
            let mut outcomes = Vec::new();
            for event in retained {
                if event.cursor.origin == origin
                    && event.cursor.source == source
                    && event.cursor.sequence <= through
                {
                    consume(state, event, reading, true, &mut outcomes);
                }
            }
            let recorded =
                state
                    .engine
                    .note_gap(origin, source, from, Some(through.saturating_add(1)));
            carry_gaps(state, &recorded);
            outcomes.extend(recorded);
            state.engine.start_from(origin, source, through);
            outcomes
        })
    }

    /// Returns the key one rule and one subject land on in this store.
    ///
    /// A producer that wants to name an item it raised asks here rather than deriving one of its
    /// own: the derivation is under a secret of this store's, which is what stops a reader served
    /// the record without the session's text working the key out from a guess at the text.
    ///
    /// # Errors
    ///
    /// As [`Attention::engine`].
    pub fn key_for(&self, rule: AttentionRule, subject: &str) -> Result<AttentionKey> {
        self.live()?;
        Ok(self.state.engine.key_for(rule, subject))
    }

    /// Returns the continuous reading the next timer is due at.
    ///
    /// # Errors
    ///
    /// As [`Attention::engine`].
    pub fn next_deadline(&self, reading: HostReading) -> Result<Option<u64>> {
        self.live()?;
        Ok(self.state.engine.next_deadline(reading))
    }

    /// Returns the continuous reading the next timer of one origin is due at.
    ///
    /// # Errors
    ///
    /// As [`Attention::engine`].
    pub fn next_deadline_of(&self, origin: &Origin, reading: HostReading) -> Result<Option<u64>> {
        self.live()?;
        Ok(self.state.engine.next_deadline_of(origin, reading))
    }

    /// Advances every timer to this reading, for the origins `certified` vouches for.
    ///
    /// # Errors
    ///
    /// As [`Attention::apply`].
    pub fn tick(
        &mut self,
        reading: HostReading,
        certified: &dyn Fn(&Origin) -> Option<u64>,
    ) -> Result<Vec<Outcome>> {
        self.latest = reading;
        self.commit(|state| {
            let outcomes = state.engine.tick(reading, certified);
            carry_gaps(state, &outcomes);
            outcomes
        })
    }

    /// Records a range of one origin's retained events the host can no longer read.
    ///
    /// # Errors
    ///
    /// As [`Attention::apply`].
    pub fn note_gap(
        &mut self,
        origin: Origin,
        source: AttentionSource,
        from: u64,
        to: Option<u64>,
    ) -> Result<Vec<Outcome>> {
        self.commit(|state| {
            let outcomes = state.engine.note_gap(origin, source, from, to);
            carry_gaps(state, &outcomes);
            outcomes
        })
    }

    /// Records where one origin's source stands without claiming anything about what came before.
    ///
    /// # Errors
    ///
    /// As [`Attention::apply`].
    pub fn start_from(
        &mut self,
        origin: Origin,
        source: AttentionSource,
        sequence: u64,
    ) -> Result<()> {
        self.commit(|state| {
            state.engine.start_from(origin, source, sequence);
        })
    }

    /// Ends the live conditions of a session that has closed, and takes nothing more from it.
    ///
    /// # Errors
    ///
    /// As [`Attention::apply`].
    pub fn finalise(
        &mut self,
        session_id: SessionId,
        reading: HostReading,
    ) -> Result<Vec<Outcome>> {
        self.latest = reading;
        self.commit(|state| state.engine.finalise(session_id))
    }

    /// Returns every item one caller sees, oldest first, without the session's text.
    ///
    /// # Errors
    ///
    /// As [`Attention::engine`].
    pub fn inbox(
        &self,
        actor: &ActorId,
        viewer: &Viewer<'_>,
        include_acknowledged: bool,
    ) -> Result<Vec<AttentionItem>> {
        self.live()?;
        Ok(self
            .state
            .engine
            .inbox(actor, viewer, include_acknowledged, None)
            .into_iter()
            .map(|(item, _)| item)
            .collect())
    }

    /// Returns one page of the inbox one caller sees, with the quiet-hours state beside it.
    ///
    /// The host's own words are in the page. A session's text is not: when `content` lets the
    /// caller be served it, [`InboxPage::texts`] names the record each such item's text is read
    /// from, and the caller reads it from that record's owner at the moment it serves the page.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::UnknownContinuation`] when the key a page continues after is not
    /// one this caller's inbox holds. Starting again at the beginning would repeat items the
    /// client has already been given, and it could not tell that from a valid continuation. And
    /// [`crate::Error::StoreTaken`] as [`Attention::engine`].
    pub fn read(
        &self,
        actor: &ActorId,
        viewer: &Viewer<'_>,
        params: &AttentionReadParams,
        reading: HostReading,
        content: Content,
    ) -> Result<InboxPage> {
        self.live()?;
        let session = params.session_id.0;
        let all = self
            .state
            .engine
            .inbox(actor, viewer, params.include_acknowledged, session);
        let start = match params.after.as_ref() {
            Some(after) => all
                .iter()
                .position(|(item, _)| &item.key == after)
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
        let texts = if content == Content::Whole {
            page.iter()
                .enumerate()
                .filter_map(|(index, (_, record))| record.map(|record| (index, record)))
                .collect()
        } else {
            Vec::new()
        };
        let gaps: Vec<AttentionGap> = self
            .state
            .engine
            .gaps()
            .iter()
            .filter(|gap| viewer.sees_gap(gap))
            .filter(|gap| session.is_none_or(|session_id| gap.session_id.0 == Some(session_id)))
            .copied()
            .collect();
        Ok(InboxPage {
            result: AttentionReadResult {
                items: page.into_iter().map(|(item, _)| item).collect(),
                more,
                dropped: U64::new(self.state.engine.dropped()),
                gaps,
                quiet_hours: Nullable(self.state.engine.quiet_hours().cloned()),
                quiet_now: self.state.engine.quiet_now(reading),
                quiet_hours_provable: reading.wall_proven,
            },
            texts,
        })
    }

    /// Returns the announcements the host has decided and no consumer has settled, among the
    /// items `offer` admits.
    ///
    /// Nothing is forgotten by asking. A consumer records what it is given and then calls
    /// [`Attention::settle_announcements`]; anything it does not settle is offered again.
    ///
    /// # Errors
    ///
    /// As [`Attention::engine`].
    pub fn take_announcements(&self, offer: &dyn Fn(&Item) -> bool) -> Result<Vec<Announcement>> {
        self.live()?;
        Ok(self.state.engine.take_announcements(offer))
    }

    /// Forgets the announcements a consumer has taken durable responsibility for.
    ///
    /// # Errors
    ///
    /// As [`Attention::apply`]. In either case nothing is forgotten and the same announcements
    /// are offered again.
    pub fn settle_announcements(&mut self, settled: &[(AttentionKey, u64)]) -> Result<()> {
        self.commit(|state| state.engine.settle_announcements(settled))
    }

    /// Returns how many decided announcements are waiting to be taken.
    ///
    /// # Errors
    ///
    /// As [`Attention::engine`].
    pub fn awaiting_delivery(&self) -> Result<usize> {
        self.live()?;
        Ok(self.state.engine.awaiting_delivery())
    }

    /// Answers whether this value still holds its store, without changing anything.
    ///
    /// A host asks before it dispatches an action, so a store it no longer holds is a refusal of
    /// the action rather than an outcome nobody can establish.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::StoreTaken`] when somebody else has taken the store.
    pub fn check_store(&self) -> Result<()> {
        self.live()
    }

    /// Answers whether this store would admit one actor, without changing anything.
    ///
    /// The bound is on admission rather than on eviction: nothing anybody has acknowledged is
    /// deleted to make room for somebody new.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::TooManyActors`] when this actor is new and the bound is reached, and
    /// [`crate::Error::StoreTaken`] as [`Attention::engine`].
    pub fn check_actor(&self, actor: &ActorId) -> Result<()> {
        self.live()?;
        admit(&self.state, actor)
    }

    /// Answers whether an acknowledgement would be refused for naming a revision past an item's
    /// own, without changing anything.
    ///
    /// A host asks before it dispatches, so a request the store will refuse is a rejection of the
    /// action rather than an outcome nobody can establish.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::RevisionAhead`] as [`Attention::acknowledge`] would, and
    /// [`crate::Error::StoreTaken`] as [`Attention::engine`].
    pub fn check_revisions(
        &self,
        viewer: &Viewer<'_>,
        items: &[AttentionItemRevision],
    ) -> Result<()> {
        self.live()?;
        for requested in items {
            if let Some(item) = self.state.engine.item(&requested.key)
                && viewer.sees(item)
                && requested.revision.get() > item.revision
            {
                return Err(crate::Error::RevisionAhead {
                    key: requested.key.as_str().to_owned(),
                    revision: requested.revision.get(),
                    current: item.revision,
                });
            }
        }
        Ok(())
    }

    /// Records one actor's acknowledgement of each item, at the revision the actor saw it.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::RevisionAhead`] when a visible item is named at a revision past its
    /// own, [`crate::Error::TooManyActors`] for one actor past the bound, and the store's errors as
    /// [`Attention::apply`]. Nothing is recorded in any of those cases.
    pub fn acknowledge(
        &mut self,
        actor: &ActorId,
        viewer: &Viewer<'_>,
        items: &[AttentionItemRevision],
        reading: HostReading,
    ) -> Result<AttentionAcknowledgeResult> {
        self.latest = reading;
        self.try_commit(|state| acknowledge_in(state, actor, viewer, items, reading))
    }

    /// Sets or clears the environment's quiet-hours window.
    ///
    /// It announces nothing. What the change lets through is released by the next
    /// [`Attention::tick`], which [`Attention::next_deadline`] brings forward to now while
    /// anything is deferred, so a release is decided against a history the host has finished
    /// reading rather than against whatever it had reached when somebody changed a setting.
    ///
    /// # Errors
    ///
    /// As [`Attention::apply`].
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
    /// when the acknowledgement names something the host does not hold or this caller may not
    /// see, and the store's errors as [`Attention::apply`].
    pub fn acknowledge_review(
        &mut self,
        actor: &ActorId,
        viewer: &Viewer<'_>,
        subject: &ReviewSubject,
        version: u64,
        reading: HostReading,
    ) -> Result<ReviewAcknowledgeResult> {
        self.latest = reading;
        self.try_commit(|state| review_in(state, actor, viewer, subject, version, reading))
    }

    /// Records one actor's visit to one session and the log views it had open.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::TooManyActors`] for one actor past the bound, and the store's errors
    /// as [`Attention::apply`].
    pub fn acknowledge_visit(
        &mut self,
        actor: &ActorId,
        session_id: SessionId,
        cursor: u64,
        views: Vec<LogViewState>,
    ) -> Result<VisitAcknowledgeResult> {
        self.try_commit(|state| visit_in(state, actor, session_id, cursor, views))
    }

    /// Performs one of the group's mutations as an action, answering an exact repeat from its
    /// record.
    ///
    /// The record is written in the transaction that performs the effect, so there is never an
    /// effect without a record. `admit` is asked inside that transaction, after the claim and
    /// before the mutation is weighed: an action whose admission lapsed while it waited is refused
    /// as that, whatever else is wrong with it, and does not begin. `encode` turns the answer into
    /// what the record keeps, which is what a repeat is answered with.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::ActionConflict`] when the identity was used with a different
    /// request, whatever `admit` returns, the mutation's own refusals, and the store's errors as
    /// [`Attention::apply`]. Nothing is recorded when the action is refused.
    pub fn perform(
        &mut self,
        action: &ActionKey,
        mutation: Mutation<'_>,
        reading: HostReading,
        admit: impl FnOnce() -> Result<()>,
        encode: impl FnOnce(&Answer) -> Vec<u8>,
    ) -> Result<Performed> {
        self.live()?;
        if let Some(record) = self.store.action(&action.actor, &action.action_id)? {
            if record.method == action.method && record.digest == action.digest {
                return Ok(Performed::Retained(record));
            }
            return Err(crate::Error::ActionConflict {
                action: action.action_id.clone(),
            });
        }
        self.latest = reading;
        let actor = action.actor.clone();
        let answer = self.write_candidate(
            |state| match mutation {
                Mutation::Acknowledge { viewer, items } => {
                    acknowledge_in(state, &actor, viewer, items, reading).map(Answer::Acknowledged)
                }
                Mutation::QuietHours(quiet) => {
                    state.engine.set_quiet_hours(quiet);
                    Ok(Answer::QuietHours(state.engine.quiet_hours().cloned()))
                }
                Mutation::Review {
                    viewer,
                    subject,
                    version,
                } => review_in(state, &actor, viewer, subject, version, reading)
                    .map(Answer::Reviewed),
                Mutation::Visit {
                    session_id,
                    cursor,
                    views,
                } => visit_in(state, &actor, session_id, cursor, views).map(Answer::Visited),
            },
            admit,
            |answer| {
                Some(ActionRecord {
                    actor: action.actor.clone(),
                    action_id: action.action_id.clone(),
                    method: action.method.clone(),
                    digest: action.digest.clone(),
                    answer: encode(answer),
                    recorded_at_ms: reading.wall_ms.get(),
                })
            },
        )?;
        Ok(Performed::Done(answer))
    }

    /// Returns the record of one actor's action, when this store performed it.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::StoreUnavailable`] when the record cannot be read, and
    /// [`crate::Error::StoreTaken`] as [`Attention::engine`].
    pub fn answered(&self, actor: &ActorId, action_id: &str) -> Result<Option<ActionRecord>> {
        self.live()?;
        self.store.action(actor, action_id)
    }

    /// Forgets the action records written before `before_ms`.
    ///
    /// Section 20 keeps a receipt for thirty days; a repeat after that is a new request.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::StoreTaken`] when the store is no longer this owner's and
    /// [`crate::Error::StoreUnavailable`] when the records cannot be removed.
    pub fn forget_actions_before(&mut self, before_ms: u64) -> Result<usize> {
        self.live()?;
        let refreshed = Owner::here(self.owner.claim, self.owner.process.clone(), self.latest);
        match self.store.forget_actions(&refreshed, before_ms) {
            Ok(removed) => {
                self.owner = refreshed;
                Ok(removed)
            }
            Err(error) => {
                self.taken = matches!(error, crate::Error::StoreTaken);
                Err(error)
            }
        }
    }

    /// Returns one actor's visit to one session.
    ///
    /// # Errors
    ///
    /// As [`Attention::engine`].
    pub fn visit(&self, actor: &ActorId, session_id: SessionId) -> Result<Option<&Visit>> {
        self.live()?;
        Ok(self.state.visits.visit(actor, session_id))
    }

    /// Answers what changed in one session since one actor's last visit to it.
    ///
    /// The host's own words are in the answer. A session's text is not: when `content` lets the
    /// caller be served it, [`ChangedPage::texts`] names the record each such change's text is
    /// read from.
    ///
    /// # Errors
    ///
    /// As [`Attention::engine`].
    pub fn changed(
        &self,
        actor: &ActorId,
        session_id: SessionId,
        max_changes: u64,
        oldest_output_cursor: u64,
        content: Content,
    ) -> Result<ChangedPage> {
        self.live()?;
        let changed =
            self.state
                .visits
                .changed_since(actor, session_id, max_changes, oldest_output_cursor);
        let texts = if content == Content::Whole {
            changed
                .changes
                .iter()
                .enumerate()
                .filter_map(|(index, (_, record))| record.map(|record| (index, record)))
                .collect()
        } else {
            Vec::new()
        };
        Ok(ChangedPage {
            result: VisitChangedResult {
                actor_id: actor.clone(),
                from_cursor: U64::new(changed.from_cursor),
                to_cursor: U64::new(changed.to_cursor),
                changes: changed
                    .changes
                    .into_iter()
                    .map(|(change, _)| change)
                    .collect(),
                omitted: changed.omitted,
                more: changed.more,
                // A model summary is its producer's to keep, and this store holds none.
                summary: Nullable::null(),
                views: changed.views,
            },
            texts,
        })
    }

    /// Returns one actor's review state of one subject, when this caller may see it.
    ///
    /// A subject outside the caller's scope is answered exactly as one the host does not hold.
    ///
    /// # Errors
    ///
    /// As [`Attention::engine`].
    pub fn review_state(
        &self,
        actor: &ActorId,
        viewer: &Viewer<'_>,
        subject: &ReviewSubject,
    ) -> Result<Option<ReviewState>> {
        self.live()?;
        if !viewer.sees_session(crate::review::subject_session(subject)) {
            return Ok(None);
        }
        Ok(self.state.reviews.state(actor, subject))
    }

    /// Returns one page of one actor's review state, oldest first, over what this caller may see.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::UnknownContinuation`] when `after` names a subject this caller
    /// cannot be shown, and [`crate::Error::StoreTaken`] as [`Attention::engine`].
    pub fn review_states(
        &self,
        actor: &ActorId,
        viewer: &Viewer<'_>,
        session: Option<SessionId>,
        after: Option<&ReviewSubject>,
        max: u64,
    ) -> Result<(Vec<ReviewState>, bool)> {
        self.live()?;
        self.state
            .reviews
            .states_page(actor, viewer, session, after, max)
    }

    /// Returns the ranges of retained events the host can no longer read.
    ///
    /// # Errors
    ///
    /// As [`Attention::engine`].
    pub fn gaps(&self) -> Result<Vec<AttentionGap>> {
        self.live()?;
        Ok(self.state.engine.gaps().to_vec())
    }

    /// Lets the store go, so the next owner does not wait for a claim nobody is holding.
    ///
    /// It removes this owner's claim and nothing else: not the state, which belongs to the store
    /// rather than to whoever was last writing it, and not another owner's claim, which is not
    /// this one's to give up.
    fn release(&mut self) {
        if self.taken {
            // The claim on the store is somebody else's, and theirs is not this one's to remove.
            return;
        }
        // Best effort: a store whose claim cannot be removed now is one the next opener clears
        // instead, and there is nobody left to tell.
        let _ = self.store.release(self.owner.claim);
    }

    /// Runs one change against a copy of the state and installs it once it is written down.
    fn commit<T>(&mut self, change: impl FnOnce(&mut State) -> T) -> Result<T> {
        self.try_commit(|state| Ok(change(state)))
    }

    /// The same, for a change that can refuse before anything is written.
    fn try_commit<T>(&mut self, change: impl FnOnce(&mut State) -> Result<T>) -> Result<T> {
        self.write_candidate(change, || Ok(()), |_| None)
    }

    /// Runs one change against a copy of the state inside the write's transaction, after `admit`,
    /// writes what it changed with `record`, and installs the copy once the write has committed.
    ///
    /// The change is decided after the admission, not before it: a request whose authority lapsed
    /// is refused as that, and nothing it asked about is weighed under authority it no longer has.
    fn write_candidate<T>(
        &mut self,
        change: impl FnOnce(&mut State) -> Result<T>,
        admit: impl FnOnce() -> Result<()>,
        record: impl FnOnce(&T) -> Option<ActionRecord>,
    ) -> Result<T> {
        self.live()?;
        let mut candidate = self.state.clone();
        // Every write refreshes the claim, which is what tells a later opener this owner is still
        // here, and every write is refused unless the claim on the store is still this one's.
        let refreshed = Owner::here(self.owner.claim, self.owner.process.clone(), self.latest);
        let written = self.store.write(&refreshed, &self.written, admit, || {
            let answer = change(&mut candidate)?;
            let action = record(&answer);
            Ok((snapshot(&candidate), action, answer))
        });
        let (after, answer) = match written {
            Ok(written) => written,
            Err(error) => {
                // A store this owner no longer holds is one whose state this value no longer
                // knows. It keeps neither the change nor the answer, and it answers nothing else
                // either.
                self.taken = matches!(error, crate::Error::StoreTaken);
                return Err(error);
            }
        };
        self.owner = refreshed;
        self.state = candidate;
        self.written = after;
        Ok(answer)
    }

    /// Refuses every further answer once the store has been taken from this value.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::StoreTaken`], which is what the caller was told when the store went.
    fn live(&self) -> Result<()> {
        if self.taken {
            return Err(crate::Error::StoreTaken);
        }
        Ok(())
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

/// Acknowledges items for one actor on a candidate state.
fn acknowledge_in(
    state: &mut State,
    actor: &ActorId,
    viewer: &Viewer<'_>,
    items: &[AttentionItemRevision],
    reading: HostReading,
) -> Result<AttentionAcknowledgeResult> {
    admit(state, actor)?;
    let requested: Vec<(AttentionKey, u64)> = items
        .iter()
        .map(|item| (item.key.clone(), item.revision.get()))
        .collect();
    let (acknowledged, stale) = state
        .engine
        .acknowledge(actor, &requested, viewer, reading)?;
    // An actor's revision counts what it has recorded. A request that recorded nothing - every
    // key stale - leaves it where it was.
    let revision = if acknowledged.is_empty() {
        state.revisions.get(actor).copied().unwrap_or_default()
    } else {
        bump(state, actor)
    };
    Ok(AttentionAcknowledgeResult {
        actor_id: actor.clone(),
        acknowledged,
        stale,
        revision: U64::new(revision),
    })
}

/// Records one actor's review acknowledgement on a candidate state.
fn review_in(
    state: &mut State,
    actor: &ActorId,
    viewer: &Viewer<'_>,
    subject: &ReviewSubject,
    version: u64,
    reading: HostReading,
) -> Result<ReviewAcknowledgeResult> {
    admit(state, actor)?;
    // A subject outside the caller's scope is answered exactly as one the store never held, so
    // an acknowledgement cannot be used to find out what exists beyond it.
    if !viewer.sees_session(crate::review::subject_session(subject)) {
        return Err(crate::Error::UnknownReviewSubject {
            subject: crate::review::subject_key(subject),
        });
    }
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
        state.engine.acknowledge_current(actor, &key, reading);
    }
    let revision = bump(state, actor);
    Ok(ReviewAcknowledgeResult {
        actor_id: actor.clone(),
        review,
        revision: U64::new(revision),
    })
}

/// Records one actor's visit on a candidate state.
fn visit_in(
    state: &mut State,
    actor: &ActorId,
    session_id: SessionId,
    cursor: u64,
    views: Vec<LogViewState>,
) -> Result<VisitAcknowledgeResult> {
    admit(state, actor)?;
    let revision = bump(state, actor);
    let visit = state
        .visits
        .acknowledge(actor, session_id, cursor, views, revision);
    Ok(VisitAcknowledgeResult {
        actor_id: actor.clone(),
        acknowledged_cursor: U64::new(visit.cursor),
        views: visit.views,
        revision: U64::new(revision),
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
    let origin = event.cursor.origin;
    let fresh = !state.engine.is_finalised(&origin)
        && state
            .engine
            .consumed(origin, event.cursor.source)
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

/// Puts every gap the engine recorded where a visit to its session can see it.
fn carry_gaps(state: &mut State, outcomes: &[Outcome]) {
    for outcome in outcomes {
        if let Outcome::GapRecorded { gap } = outcome {
            state.visits.note_source_gap(*gap);
        }
    }
}

/// Where a change's text comes from: the record, for a session's, and the host's own words for
/// the environment's.
fn change_text(event: &SourceEvent, host_words: impl FnOnce() -> String) -> Text {
    match event.cursor.origin {
        Origin::Session(_) => Text::Record(event.cursor),
        Origin::Environment => Text::Host(clip_summary(&host_words())),
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
                    change_text(event, || summary.clone()),
                    event.at_ms,
                );
            }
            if turn_moved {
                state.visits.record(
                    SemanticChangeKind::TurnCompleted,
                    *session_id,
                    change_text(event, || summary.clone()),
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
                    change_text(event, || summary.clone()),
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
                change_text(event, || format!("{command} exited {exit_code}")),
                event.at_ms,
            );
        }
        EventKind::QuestionResolved {
            session_id,
            answered: true,
            ..
        } => {
            // The host's own words: that a question was answered is its record, and the answer
            // itself is the session's and stays with the question.
            state.visits.record(
                SemanticChangeKind::QuestionAnswered,
                *session_id,
                Text::Host("a question was answered".to_owned()),
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
                change_text(event, || format!("{plugin_id} failed: {detail}")),
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
fn snapshot(state: &State) -> StoredState {
    StoredState {
        items: state.engine.items().cloned().collect(),
        item_acks: state.engine.all_acknowledgements().clone(),
        revisions: state.revisions.clone(),
        consumed: state.engine.all_consumed().clone(),
        gaps: state.engine.gaps().to_vec(),
        dropped: state.engine.dropped(),
        next_announcement: state.engine.next_announcement(),
        next_revision: state.engine.next_revision(),
        finalised: state.engine.finalised().clone(),
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
        sessions: state.visits.sessions().clone(),
    }
}
