//! The attention engine: a state machine over typed events.
//!
//! The engine holds the inbox, the quiet-hours window, the per-actor acknowledgements and the
//! cursors it has consumed. It reads no clock, opens no file and sends no notification. Everything
//! it decides comes out as an [`Outcome`], and the host is what acts on one.
//!
//! One engine holds the whole environment: every session's conditions and the environment's own.
//! Each condition keeps the [`Origin`] of the record that raised it, which is whose sources a gap
//! is weighed against and whose reading a timer waits for.
//!
//! # The shape of a decision
//!
//! An event names a condition. The condition maps to one rule and one subject, and the two
//! together are the item's key, derived rather than allocated so a replay lands on the same item.
//! From there:
//!
//! 1. A condition the engine has already consumed changes nothing.
//! 2. A repeat inside the rule's sixty-second window is counted on the item rather than announced.
//! 3. An announcement inside quiet hours is deferred and released when they end, never dropped.
//! 4. An item climbs its rule's ladder while the condition stands, and is announced again at the
//!    rule's interval. An acknowledgement does not stop it: section 23 makes an acknowledgement
//!    affect only the actor that made it, and one actor cannot silence the host's own reminder to
//!    another.
//! 5. A condition that ends resolves its item, which leaves the inbox and takes any announcement
//!    still held for it with it.
//!
//! # Live and replay
//!
//! [`Engine::apply`] is the live path: it decides and announces. [`Engine::replay`] rebuilds the
//! same state from the retained events without announcing any of it, because an event from an hour
//! ago is not a notification to send now. A replay leaves every item's announcement undecided, and
//! the first [`Engine::tick`] after it decides them against the present.
//!
//! # A timer waits for its origin
//!
//! A timer is a decision about the present: a reminder says a request is still unanswered, a repeat
//! says a condition still stands. The engine decides one only against an origin's records the host
//! has certified it has read up to a moment, and only for a timer that fell due by then. A session
//! whose records the host has not finished reading keeps its timers, so an answer on a page the host
//! has not read yet never becomes a reminder. Late, never early.
//!
//! # Text that is not the host's
//!
//! What a session wrote - a question's wording, what an application printed - is not kept here.
//! An item keeps a [`Text::Record`] naming the retained record its text comes from, and whoever
//! serves the item reads the text from that record's owner at the moment it is served, under that
//! session's privacy state then. Only the host's own words, about its own journal, are kept as
//! [`Text::Host`].
//!
//! # What the engine will not do
//!
//! It will not treat a gap as an ending. A range of retained events that retention has taken is
//! recorded as a gap, and every unresolved item from that same origin and source is marked
//! uncertain and left in the inbox. Section 24 is explicit: a history gap is not an inferred
//! approval or completion, and the only honest answer for a host that cannot tell is to say so.

use std::collections::{BTreeMap, BTreeSet};

use kr_protocol::attention::{
    AttentionAutomationSubject, AttentionGap, AttentionItem, AttentionKey, AttentionLevel,
    AttentionRouting, AttentionRule, AttentionSource, IDLE_REMINDER_MS, MAX_ATTENTION_SUMMARY_LEN,
    MAX_RETAINED_ATTENTION_ITEMS, MAX_RETAINED_PENDING_INPUTS, NotificationState, QuietHours,
};
use kr_protocol::ids::{ActorId, GrantId, QuestionId, SessionId};
use kr_protocol::scalars::{Nullable, TimestampMs, U64};

use crate::event::{EventCursor, EventKind, Origin, SourceEvent, numbers_every_record};
use crate::rule::rule;
use crate::scope::Viewer;
use crate::time::{Anchor, Elapsed, HostReading, MS_IN_MINUTE};

/// Largest number of gaps the engine keeps. The oldest is dropped past it.
pub const MAX_GAPS: usize = 64;

/// Whether a decision is being made now or rebuilt from what was retained.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// The condition is happening now, so a decision is announced.
    Live,
    /// The condition is being read back from the retained events. State is rebuilt and nothing is
    /// announced, because an announcement is about the present.
    Replay,
}

/// Where an item's or a change's text comes from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Text {
    /// The host's own words, about its own journal, kept here and served whole.
    Host(String),
    /// A session's retained record, which the text is read from when it is served.
    Record(EventCursor),
}

impl Text {
    /// Returns the record the text is read from, when it is one.
    #[must_use]
    pub const fn record(&self) -> Option<EventCursor> {
        match self {
            Self::Host(_) => None,
            Self::Record(cursor) => Some(*cursor),
        }
    }
}

/// One item of attention, as the engine holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Item {
    /// The rule and subject this item stands for.
    pub key: AttentionKey,
    /// The rule that raised it.
    pub rule: AttentionRule,
    /// The retained source the condition was observed in.
    pub source: AttentionSource,
    /// Whose source that is.
    pub origin: Origin,
    /// The session it belongs to, when it belongs to one.
    pub session_id: Option<SessionId>,
    /// Where its one line of text comes from.
    pub text: Text,
    /// The grant an automation item's workflow or chain acts under, when the journal named one.
    pub grant: Option<GrantId>,
    /// The workflow revision or causal chain an automation item is about.
    pub automation: Option<AttentionAutomationSubject>,
    /// The item's revision: set when it is raised and at each new occurrence, from a counter of
    /// the store's own that only goes forward.
    pub revision: u64,
    /// Where its notification went.
    pub routing: AttentionRouting,
    /// What it currently asks for.
    pub level: AttentionLevel,
    /// How many steps of its rule's ladder have been taken.
    pub steps_taken: usize,
    /// How many times the condition occurred, including suppressed repeats.
    pub occurrences: u64,
    /// When the condition was first observed.
    pub first_seen_ms: TimestampMs,
    /// When it was last observed.
    pub last_seen_ms: TimestampMs,
    /// What became of the notification.
    pub notification: NotificationState,
    /// When the last announcement was decided, when there has been one.
    pub last_notified_ms: Option<TimestampMs>,
    /// Where this item's age is measured from, on the clock that can measure one.
    ///
    /// [`Item::first_seen_ms`] says when the condition was first seen, for a person reading the
    /// record; this says where that moment sits on a continuous clock, and in which boot. An
    /// anchor from another boot measures nothing, so the age starts again from the reading that
    /// found it, and this is moved to that reading. It is always set for an item this engine
    /// raised, whether or not its producer had a reading of its own: what a producer supplies is
    /// where the age *starts*, and what is kept here is where it starts on a clock this host can
    /// measure. `None` is only a row from a store that carried none.
    pub anchor: Option<Anchor>,
    /// Where the interval since the last announcement is measured from.
    ///
    /// [`Item::last_notified_ms`] says when the decision was made, for a person reading the
    /// record; this says where that moment sits on a continuous clock, and in which boot. Both are
    /// set when the decision is made, which is before quiet hours are asked whether it goes out
    /// now, so a deferred announcement has them too: the interval they measure is the one the
    /// de-duplication window and the repeat both run on, and that runs from the decision. `None`
    /// is an item nothing has been decided about yet. An announcement made in a boot that has ended
    /// measures nothing across the gap, so the interval starts again at the reading that found it,
    /// and this is moved to that reading: the same condition is then folded into the item for one
    /// more window rather than announced twice inside one, and a second restart does not start it
    /// again.
    pub announced_anchor: Option<Anchor>,
    /// The level the last announcement went out at.
    ///
    /// An item that has climbed past it is owed another announcement; one that has not is not.
    /// Keeping it durable is what stops a restart announcing everything at the level it already
    /// announced.
    pub announced_level: Option<AttentionLevel>,
    /// How many announcements this item has produced.
    ///
    /// It is the count a client shows: one condition is announced many times over its life. It is
    /// not the identity of any of them, because an item that resolves and is raised again starts
    /// counting from nought.
    pub announcements: u64,
    /// The announcement, by its own number, that no delivery consumer has settled yet.
    ///
    /// A decision is written down before the caller is handed it and stays written down until a
    /// consumer says it has taken durable responsibility for it. Taking one is therefore two
    /// steps: [`Engine::take_announcements`] offers what is outstanding without forgetting it, and
    /// [`Engine::settle_announcements`] forgets it once the consumer has recorded it. A host that
    /// decided an announcement and died at any point before that offers it again.
    ///
    /// The number comes from a counter that only goes forward and outlives the item, so an
    /// identity a consumer recorded never names a later decision about the same condition.
    pub pending_handoff: Option<u64>,
    /// Whether a gap in the retained events could have resolved it.
    pub uncertain: bool,
    /// How long the item has stood.
    pub age: Elapsed,
    /// How long since the last announcement, when there has been one.
    pub since_notified: Option<Elapsed>,
    /// Whether quiet hours are holding an announcement for it.
    pub deferred: bool,
}

/// How much of the retained content a caller is served.
///
/// A caller whose grant the host cannot narrow retained content to is served the host's own record
/// of a condition without the session's text. That is the same direction section 10 takes for a
/// history page a host cannot narrow: serve less than the grant allows rather than more.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Content {
    /// Everything, including the text the condition came from.
    Whole,
    /// The host's own record, without the session's text.
    Narrowed,
}

impl Item {
    /// Returns the session this item is about: the one it names, or else the one whose records
    /// raised it.
    ///
    /// A page's session filter and a session's ending both go by it.
    #[must_use]
    pub fn session(&self) -> Option<SessionId> {
        self.session_id.or_else(|| self.origin.session())
    }

    /// Returns this item as the wire type, for one actor.
    ///
    /// The host's own words travel with it. A session's text does not: the wire item's summary is
    /// null here, and whoever serves the item reads the text from [`Text::Record`] when the caller
    /// may be served it.
    #[must_use]
    pub fn to_wire(&self, acknowledged: bool) -> AttentionItem {
        AttentionItem {
            key: self.key.clone(),
            rule: self.rule,
            source: self.source,
            level: self.level,
            session_id: Nullable(self.session()),
            summary: Nullable(match &self.text {
                Text::Host(text) => Some(text.clone()),
                Text::Record(_) => None,
            }),
            trusted: rule(self.rule).trusted,
            routing: self.routing,
            occurrences: U64::new(self.occurrences),
            first_seen_ms: self.first_seen_ms,
            last_seen_ms: self.last_seen_ms,
            notification: self.notification,
            awaiting_delivery: self.pending_handoff.is_some(),
            acknowledged,
            uncertain: self.uncertain,
            revision: U64::new(self.revision),
            automation: Nullable(self.automation.clone()),
        }
    }
}

/// What the engine decided, for the host to act on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// A condition entered the inbox.
    Raised {
        /// The item.
        key: AttentionKey,
        /// Its rule.
        rule: AttentionRule,
        /// What it asks for.
        level: AttentionLevel,
    },
    /// The same condition recurred. Whether it was announced again is said by what follows it.
    Repeated {
        /// The item.
        key: AttentionKey,
        /// How many times the condition has now occurred.
        occurrences: u64,
    },
    /// An announcement to send now.
    Notified {
        /// The item.
        key: AttentionKey,
        /// What it asks for.
        level: AttentionLevel,
        /// Where it goes.
        routing: AttentionRouting,
    },
    /// An announcement quiet hours are holding.
    Deferred {
        /// The item.
        key: AttentionKey,
        /// What it asks for.
        level: AttentionLevel,
    },
    /// A held announcement, released because quiet hours ended.
    Released {
        /// The item.
        key: AttentionKey,
        /// What it asks for.
        level: AttentionLevel,
        /// Where it goes.
        routing: AttentionRouting,
    },
    /// An item that climbed a step of its ladder.
    Escalated {
        /// The item.
        key: AttentionKey,
        /// What it asked for before.
        from: AttentionLevel,
        /// What it asks for now.
        to: AttentionLevel,
    },
    /// A condition that ended. The item has left the inbox.
    Resolved {
        /// The item.
        key: AttentionKey,
    },
    /// A request that ended with its session, which closed before it was answered.
    ///
    /// It is not an answer, an approval or a completion. The session's closure is a fact the
    /// host holds, and a closed session's request cannot be answered any more, so the item leaves
    /// the inbox; nothing about what the request would have been answered with is inferred.
    Ended {
        /// The item.
        key: AttentionKey,
    },
    /// An item the host let go of to stay inside its own bound.
    Dropped {
        /// The item.
        key: AttentionKey,
    },
    /// A range of retained events the host can no longer read.
    GapRecorded {
        /// The range.
        gap: AttentionGap,
    },
}

/// One announcement the host decided and has not yet handed to a delivery consumer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Announcement {
    /// The item.
    pub key: AttentionKey,
    /// This decision's own number in the store that made it.
    ///
    /// It comes from a counter that only goes forward and outlives the item it was given for, so
    /// the pair of the key and this number is an identity the store never hands out twice: a newer
    /// decision about the same condition is a different announcement, even when the condition ended
    /// and returned in between, and an older identity settles none of it.
    pub number: u64,
    /// Its rule.
    pub rule: AttentionRule,
    /// What it asks for.
    pub level: AttentionLevel,
    /// Where it goes.
    pub routing: AttentionRouting,
    /// The session it belongs to, when it belongs to one.
    pub session_id: Option<SessionId>,
    /// Where its one line of text comes from. A consumer reads a session's text when it sends.
    pub text: Text,
}

/// One actor's acknowledgement of one item.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ItemAck {
    /// The item revision the acknowledgement was made at.
    ///
    /// A later occurrence, or the condition ending and returning, gives the item a later revision,
    /// and the acknowledgement does not cover it.
    pub revision: u64,
    /// When the actor acknowledged it.
    pub at_ms: TimestampMs,
}

/// A question that is waiting for an answer, and how long it has waited.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingInput {
    /// The session it belongs to.
    pub session_id: SessionId,
    /// The record that made it pending, which is where the reminder's text is read from.
    pub record: EventCursor,
    /// What the wall clock read when the request became pending.
    pub pending_since_ms: TimestampMs,
    /// How long it has been pending.
    pub waited: Elapsed,
    /// Whether the reminder has already been raised for this request.
    pub reminded: bool,
    /// Where the wait is measured from, on the clock that can measure one.
    ///
    /// `None`, or an anchor from another boot, starts the wait where the engine read the record,
    /// which raises the reminder late rather than at once.
    pub anchor: Option<Anchor>,
}

/// The attention engine.
#[derive(Clone, Debug, Default)]
pub struct Engine {
    items: BTreeMap<AttentionKey, Item>,
    acks: BTreeMap<ActorId, BTreeMap<AttentionKey, ItemAck>>,
    consumed: BTreeMap<(Origin, AttentionSource), u64>,
    gaps: Vec<AttentionGap>,
    pending_inputs: BTreeMap<QuestionId, PendingInput>,
    quiet: Option<QuietHours>,
    dropped: u64,
    next_announcement: u64,
    next_revision: u64,
    finalised: BTreeSet<SessionId>,
    keys: crate::key::KeySecret,
}

/// Returns `text` clipped to the bound one summary carries, on a character boundary.
#[must_use]
pub fn clip_summary(text: &str) -> String {
    if text.len() <= MAX_ATTENTION_SUMMARY_LEN {
        return text.to_owned();
    }
    let mut end = MAX_ATTENTION_SUMMARY_LEN;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}

/// Everything one raised condition names.
struct Raise {
    id: AttentionRule,
    subject: String,
    source: AttentionSource,
    origin: Origin,
    session_id: Option<SessionId>,
    text: Text,
    grant: Option<GrantId>,
    automation: Option<AttentionAutomationSubject>,
    routing: AttentionRouting,
    at_ms: TimestampMs,
    at_anchor: Option<Anchor>,
}

/// Where a condition's text comes from: the record, for a session's, and the host's own words for
/// the environment's.
fn text_of(event: &SourceEvent, host_words: impl FnOnce() -> String) -> Text {
    match event.cursor.origin {
        Origin::Session(_) => Text::Record(event.cursor),
        Origin::Environment => Text::Host(clip_summary(&host_words())),
    }
}

/// The subject an automation item is keyed on, and the one line the host says about it.
fn automation_subject(subject: &AttentionAutomationSubject) -> (String, String) {
    match subject {
        AttentionAutomationSubject::Workflow {
            workflow_id,
            revision,
        } => (
            format!("workflow|{workflow_id}|{}", revision.get()),
            format!("workflow {workflow_id} revision {}", revision.get()),
        ),
        AttentionAutomationSubject::CausalChain { causal_root_id } => (
            format!("chain|{causal_root_id}"),
            format!("causal chain {causal_root_id}"),
        ),
    }
}

/// The subject a pending approval is keyed on.
///
/// An upstream request identifier is the connector's own and is not unique across sessions, so the
/// session is part of it.
fn approval_subject(session_id: SessionId, request_id: &impl core::fmt::Display) -> String {
    format!("{session_id}|{request_id}")
}

/// The subject an adapter failure is keyed on: the adapter, within the origin that reported it.
///
/// One adapter can fail for two sessions at once, and each session's failure is its own: a device
/// that sees one session is shown that session's, and its recovery ends that one. The
/// environment's own reports keep the adapter alone as their subject.
fn adapter_subject(origin: Origin, plugin_id: &impl core::fmt::Display) -> String {
    match origin {
        Origin::Environment => plugin_id.to_string(),
        Origin::Session(session_id) => format!("{session_id}|{plugin_id}"),
    }
}

impl Engine {
    /// Builds an engine with nothing consumed and nothing in the inbox.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the configured quiet hours.
    #[must_use]
    pub const fn quiet_hours(&self) -> Option<&QuietHours> {
        self.quiet.as_ref()
    }

    /// Returns whether the host is inside its quiet hours at this reading.
    ///
    /// A host that cannot prove its wall clock is never inside them. Quiet hours are a time of
    /// day, and a host that cannot say what the time is cannot say it is a quiet one.
    #[must_use]
    pub fn quiet_now(&self, reading: HostReading) -> bool {
        reading.wall_proven
            && self
                .quiet
                .as_ref()
                .is_some_and(|quiet| quiet.covers(reading.minute_of_day()))
    }

    /// Sets or clears the quiet-hours window.
    ///
    /// It records the window and announces nothing. What the change lets through is released by
    /// the next [`Engine::tick`], which is what [`Engine::next_deadline`] brings forward to now
    /// while anything is deferred. Announcing here instead would decide against whatever history
    /// the host had read by the moment somebody happened to change a setting.
    pub fn set_quiet_hours(&mut self, quiet: Option<QuietHours>) {
        self.quiet = quiet;
    }

    /// Returns the ranges of retained events the host can no longer read.
    #[must_use]
    pub fn gaps(&self) -> &[AttentionGap] {
        &self.gaps
    }

    /// Returns how many items the host has let go of to stay inside its bound.
    #[must_use]
    pub const fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Returns the key one rule and one subject land on in this store.
    ///
    /// It is derived under the store's own secret, so a caller cannot work one out and a host that
    /// holds an item can always name it again.
    #[must_use]
    pub fn key_for(&self, rule: AttentionRule, subject: &str) -> AttentionKey {
        self.keys.attention_key(rule, subject)
    }

    /// Returns the secret this store derives its keys under, for the store to write down.
    #[must_use]
    pub const fn key_secret(&self) -> crate::key::KeySecret {
        self.keys
    }

    /// Returns the highest announcement identity this store has handed out.
    #[must_use]
    pub const fn next_announcement(&self) -> u64 {
        self.next_announcement
    }

    /// Returns the highest item revision this store has handed out.
    #[must_use]
    pub const fn next_revision(&self) -> u64 {
        self.next_revision
    }

    /// Returns the highest sequence consumed from one origin's source.
    #[must_use]
    pub fn consumed(&self, origin: Origin, source: AttentionSource) -> Option<u64> {
        self.consumed.get(&(origin, source)).copied()
    }

    /// Records where a source stands without claiming anything about what came before.
    ///
    /// A host that starts the engine partway through a source's life calls this rather than
    /// letting the first event look like a jump. Without it, a first event at sequence nine says
    /// eight records were evicted, which is a gap the host has no reason to believe in.
    pub fn start_from(&mut self, origin: Origin, source: AttentionSource, sequence: u64) {
        let consumed = self.consumed.entry((origin, source)).or_insert(sequence);
        *consumed = (*consumed).max(sequence);
    }

    /// Returns every item, by key.
    pub fn items(&self) -> impl Iterator<Item = &Item> {
        self.items.values()
    }

    /// Returns one item.
    #[must_use]
    pub fn item(&self, key: &AttentionKey) -> Option<&Item> {
        self.items.get(key)
    }

    /// Returns one actor's acknowledgements.
    #[must_use]
    pub fn acknowledgements(&self, actor: &ActorId) -> Option<&BTreeMap<AttentionKey, ItemAck>> {
        self.acks.get(actor)
    }

    /// Returns every actor's acknowledgements.
    #[must_use]
    pub const fn all_acknowledgements(
        &self,
    ) -> &BTreeMap<ActorId, BTreeMap<AttentionKey, ItemAck>> {
        &self.acks
    }

    /// Returns the highest sequence consumed from each origin's sources.
    #[must_use]
    pub const fn all_consumed(&self) -> &BTreeMap<(Origin, AttentionSource), u64> {
        &self.consumed
    }

    /// Returns the questions waiting for an answer.
    #[must_use]
    pub const fn pending_inputs(&self) -> &BTreeMap<QuestionId, PendingInput> {
        &self.pending_inputs
    }

    /// Returns the sessions whose live conditions ended with their closure.
    #[must_use]
    pub const fn finalised(&self) -> &BTreeSet<SessionId> {
        &self.finalised
    }

    /// Returns whether one origin has been finalised.
    #[must_use]
    pub fn is_finalised(&self, origin: &Origin) -> bool {
        origin
            .session()
            .is_some_and(|session_id| self.finalised.contains(&session_id))
    }

    /// Returns the items one caller sees, oldest first, each with the record its text is read
    /// from when that text is the session's.
    ///
    /// `session` narrows the answer to one session; it never widens what `viewer` may see.
    #[must_use]
    pub fn inbox(
        &self,
        actor: &ActorId,
        viewer: &Viewer<'_>,
        include_acknowledged: bool,
        session: Option<SessionId>,
    ) -> Vec<(AttentionItem, Option<EventCursor>)> {
        let mut items: Vec<_> = self
            .items
            .values()
            .filter(|item| viewer.sees(item))
            .filter(|item| session.is_none_or(|session_id| item.session() == Some(session_id)))
            .filter_map(|item| {
                let acknowledged = self.is_acknowledged(actor, item);
                (include_acknowledged || !acknowledged)
                    .then(|| (item.to_wire(acknowledged), item.text.record()))
            })
            .collect();
        items.sort_by(|left, right| {
            left.0
                .first_seen_ms
                .get()
                .cmp(&right.0.first_seen_ms.get())
                .then_with(|| left.0.key.as_str().cmp(right.0.key.as_str()))
        });
        items
    }

    /// Records one actor's acknowledgement of each item, at the revision the actor saw it.
    ///
    /// The whole request is decided before anything is recorded. A revision past an item's own is
    /// one the host never handed out, and the request is refused whole. Otherwise each item is
    /// acknowledged when it is still at the revision named and this caller may see it; an item
    /// that has moved on, has gone, or is outside the caller's scope is returned as stale and
    /// nothing is recorded for it, so an acknowledgement never covers work the caller did not see
    /// and never tells a caller anything about an item it may not see.
    ///
    /// Nothing about the host's own reminders changes. Section 23 makes an acknowledgement affect
    /// only the actor that made it, so one device marking an approval seen does not stop the host
    /// reminding the person about an agent that is still waiting.
    ///
    /// # Errors
    ///
    /// Returns [`crate::Error::RevisionAhead`] when a visible item is named at a revision past its
    /// own, and then nothing is recorded.
    pub fn acknowledge(
        &mut self,
        actor: &ActorId,
        requested: &[(AttentionKey, u64)],
        viewer: &Viewer<'_>,
        reading: HostReading,
    ) -> crate::Result<(Vec<AttentionKey>, Vec<AttentionKey>)> {
        for (key, revision) in requested {
            if let Some(item) = self.items.get(key)
                && viewer.sees(item)
                && *revision > item.revision
            {
                return Err(crate::Error::RevisionAhead {
                    key: key.as_str().to_owned(),
                    revision: *revision,
                    current: item.revision,
                });
            }
        }
        let mut acknowledged = Vec::new();
        let mut stale = Vec::new();
        for (key, revision) in requested {
            let current = self
                .items
                .get(key)
                .filter(|item| viewer.sees(item) && item.revision == *revision)
                .map(|item| item.revision);
            match current {
                Some(revision) => {
                    self.acks.entry(actor.clone()).or_default().insert(
                        key.clone(),
                        ItemAck {
                            revision,
                            at_ms: reading.wall_ms,
                        },
                    );
                    acknowledged.push(key.clone());
                }
                None => stale.push(key.clone()),
            }
        }
        Ok((acknowledged, stale))
    }

    /// Records one actor's acknowledgement of an item at the revision it stands at now.
    ///
    /// This is the host's own path, for an acknowledgement another one implies: completing a review
    /// acknowledges the inbox item that said the review was waiting, for the same actor.
    pub fn acknowledge_current(
        &mut self,
        actor: &ActorId,
        key: &AttentionKey,
        reading: HostReading,
    ) {
        if let Some(item) = self.items.get(key) {
            let revision = item.revision;
            self.acks.entry(actor.clone()).or_default().insert(
                key.clone(),
                ItemAck {
                    revision,
                    at_ms: reading.wall_ms,
                },
            );
        }
    }

    /// Returns whether this actor has acknowledged the current revision of an item.
    #[must_use]
    pub fn is_acknowledged(&self, actor: &ActorId, item: &Item) -> bool {
        self.acks
            .get(actor)
            .and_then(|acks| acks.get(&item.key))
            .is_some_and(|ack| ack.revision >= item.revision)
    }

    /// Records a range of one origin's retained events the host can no longer read.
    ///
    /// Every unresolved item from the same origin and source becomes uncertain. It stays in the
    /// inbox: a gap is never an inferred approval or completion. `to` is the first sequence present
    /// again, or `None` when nothing after the range can be read.
    pub fn note_gap(
        &mut self,
        origin: Origin,
        source: AttentionSource,
        from: u64,
        to: Option<u64>,
    ) -> Vec<Outcome> {
        if to.is_some_and(|to| to <= from) {
            return Vec::new();
        }
        let gap = AttentionGap {
            source,
            session_id: Nullable(origin.session()),
            from_sequence: U64::new(from),
            to_sequence: Nullable(to.map(U64::new)),
        };
        if self.gaps.contains(&gap) {
            return Vec::new();
        }
        self.gaps.push(gap);
        if self.gaps.len() > MAX_GAPS {
            self.gaps.remove(0);
        }
        for item in self.items.values_mut() {
            if item.origin == origin && item.source == source {
                item.uncertain = true;
            }
        }
        // The consumed cursor moves past the range, because the records inside it will never
        // arrive. Leaving it where it was would make the next event look like a second gap. A range
        // with no end moves nothing: nothing after it can be read.
        if let Some(to) = to {
            let consumed = self.consumed.entry((origin, source)).or_insert(0);
            *consumed = (*consumed).max(to.saturating_sub(1));
        }
        vec![Outcome::GapRecorded { gap }]
    }

    /// Ends the live conditions of a session that has closed.
    ///
    /// A pending approval, a pending question and its reminder leave the inbox as
    /// [`Outcome::Ended`]: a closed session's request can no longer be answered, and the closure is
    /// a fact the host holds rather than something read from a gap. Nothing about how the request
    /// would have been answered is inferred. A request ends when the session it names has ended, and
    /// when the session whose records it came from has, because no answer can arrive from either.
    /// Review work, failed commands, notices and gaps stay: completed work awaiting review outlives
    /// the session that produced it. Records of the session that arrive afterwards change nothing.
    /// Ending a session twice changes nothing the second time.
    pub fn finalise(&mut self, session_id: SessionId) -> Vec<Outcome> {
        self.finalised.insert(session_id);
        let ending: Vec<AttentionKey> = self
            .items
            .values()
            .filter(|item| {
                (item.origin == Origin::Session(session_id) || item.session_id == Some(session_id))
                    && matches!(
                        item.rule,
                        AttentionRule::PendingApproval
                            | AttentionRule::PendingInput
                            | AttentionRule::InputIdleReminder
                    )
            })
            .map(|item| item.key.clone())
            .collect();
        let mut outcomes = Vec::new();
        for key in ending {
            self.items.remove(&key);
            for acks in self.acks.values_mut() {
                acks.remove(&key);
            }
            outcomes.push(Outcome::Ended { key });
        }
        self.pending_inputs.retain(|_, pending| {
            pending.session_id != session_id && pending.record.origin != Origin::Session(session_id)
        });
        outcomes
    }

    /// Applies one typed event, announcing what it decides.
    ///
    /// An event at or below the cursor already consumed from its origin's source changes nothing,
    /// which is what lets the retained events be replayed as often as a host needs to. An event
    /// beyond the next sequence of a source that numbers every record means the records between
    /// were evicted, and the range is recorded as a gap before the event itself is applied.
    pub fn apply(&mut self, event: &SourceEvent, reading: HostReading) -> Vec<Outcome> {
        self.consume(event, reading, Mode::Live)
    }

    /// Rebuilds state from one retained event without announcing anything.
    ///
    /// This is the reconstruction path. An item's age is taken from the anchor its event carried,
    /// when that anchor is on this boot's clock, so an approval that has been outstanding for an
    /// hour inside this boot comes back an hour old; an event with no anchor, or one from a boot
    /// that has ended, starts its age here instead. Either way nothing is announced for something
    /// that happened before this host was running. The first [`Engine::tick`] after a replay
    /// decides every announcement against the present.
    pub fn replay(&mut self, event: &SourceEvent, reading: HostReading) -> Vec<Outcome> {
        self.consume(event, reading, Mode::Replay)
    }

    /// Advances every timer to this reading, for the origins the host has finished reading.
    ///
    /// `certified` answers, for one origin, the continuous reading up to which the host has read
    /// every record that origin committed, or `None` when it cannot say. A timer of that origin is
    /// decided only when it fell due by then, and an item nothing has been decided about is decided
    /// only when the origin has any certificate at all: an answer on a page the host has not read
    /// must never become a reminder. A session that has ended is certified for ever, because
    /// nothing more of it will arrive.
    ///
    /// The order is deliberate. Levels are settled first, then at most one announcement is decided
    /// per item, so an item that climbed a step and was also due a repeat is announced once, at the
    /// level it now stands at, rather than twice at two levels. The inbox bound is applied last,
    /// against what those decisions left.
    pub fn tick(
        &mut self,
        reading: HostReading,
        certified: &dyn Fn(&Origin) -> Option<u64>,
    ) -> Vec<Outcome> {
        let finalised = self.finalised.clone();
        let at = |origin: &Origin| -> Option<HostReading> {
            if origin
                .session()
                .is_some_and(|session_id| finalised.contains(&session_id))
            {
                return Some(reading);
            }
            certified(origin).map(|certificate| reading.at_or_before(certificate))
        };
        let mut outcomes = self.fire_idle_reminders(reading, &at);
        outcomes.extend(self.climb(&at));
        outcomes.extend(self.announce_due(reading, &at));
        // Last, because what the bound may let go of is decided by what has just been announced
        // and by what a consumer has settled since the last pass. An inbox that went over its
        // bound while everything in it was work in flight comes back inside it here.
        outcomes.extend(self.enforce_bound(reading));
        outcomes
    }

    /// Returns the announcements the host has decided and no consumer has settled, among the items
    /// `offer` admits.
    ///
    /// Nothing is forgotten here. A consumer takes these, records them durably, and then calls
    /// [`Engine::settle_announcements`] with what it recorded; anything it did not settle is
    /// offered again, at this start or the next one. Forgetting one at the moment it was handed
    /// over would lose it to a crash between the handing and the recording. `offer` is how a host
    /// holds back what it may not hand over yet, such as a closing session's.
    #[must_use]
    pub fn take_announcements(&self, offer: &dyn Fn(&Item) -> bool) -> Vec<Announcement> {
        self.items
            .values()
            .filter(|item| offer(item))
            .filter_map(|item| {
                item.pending_handoff.map(|number| Announcement {
                    key: item.key.clone(),
                    number,
                    rule: item.rule,
                    level: item.level,
                    routing: item.routing,
                    session_id: item.session(),
                    text: item.text.clone(),
                })
            })
            .collect()
    }

    /// Forgets the announcements a consumer has taken durable responsibility for.
    ///
    /// An identity that names an announcement the item has since replaced settles nothing: the
    /// newer decision is a different announcement, and it is still outstanding. A number is never
    /// reused, so an identity recorded before a condition ended cannot settle a decision made
    /// after the same condition returned.
    pub fn settle_announcements(&mut self, settled: &[(AttentionKey, u64)]) {
        for (key, number) in settled {
            if let Some(item) = self.items.get_mut(key)
                && item.pending_handoff == Some(*number)
            {
                item.pending_handoff = None;
            }
        }
    }

    /// Returns the announcements waiting to be taken, without taking them.
    #[must_use]
    pub fn awaiting_delivery(&self) -> usize {
        self.items
            .values()
            .filter(|item| item.pending_handoff.is_some())
            .count()
    }

    /// Returns the continuous reading the next timer is due at.
    ///
    /// A host wakes at it rather than polling. `None` means nothing is waiting on time.
    #[must_use]
    pub fn next_deadline(&self, reading: HostReading) -> Option<u64> {
        self.deadline_among(reading, &|_| true)
    }

    /// Returns the continuous reading the next timer of one origin is due at.
    ///
    /// A host that reads an origin's records by holding a request open bounds the wait by this,
    /// so a timer that falls due is decided against records read after it did.
    #[must_use]
    pub fn next_deadline_of(&self, origin: &Origin, reading: HostReading) -> Option<u64> {
        self.deadline_among(reading, &|candidate| candidate == origin)
    }

    fn deadline_among(
        &self,
        reading: HostReading,
        include: &dyn Fn(&Origin) -> bool,
    ) -> Option<u64> {
        let mut earliest: Option<u64> = None;
        let mut consider = |deadline: u64| {
            earliest = Some(earliest.map_or(deadline, |current: u64| current.min(deadline)));
        };
        let quiet = self.quiet_now(reading);
        if self
            .items
            .values()
            .any(|item| item.deferred && include(&item.origin))
        {
            // Either the window is still standing, and the release is when it ends, or it is not,
            // and the release is now.
            consider(self.quiet_release(reading).unwrap_or(reading.continuous_ms));
        }
        for pending in self.pending_inputs.values() {
            if !pending.reminded && include(&pending.record.origin) {
                consider(pending.waited.due_at(IDLE_REMINDER_MS));
            }
        }
        for item in self.items.values().filter(|item| include(&item.origin)) {
            let policy = rule(item.rule);
            if let Some(next) = policy.next_step_after(item.steps_taken) {
                consider(item.age.due_at(next));
            }
            // A deferred announcement is waiting on the window rather than on its own interval, so
            // nothing about it is a deadline of its own until it has been released.
            if item.deferred && quiet {
                continue;
            }
            let Some(since) = item.since_notified else {
                // Nothing has been decided about it at all: a replay rebuilt it, or the store
                // refused the write that would have recorded the decision. It is due now.
                consider(reading.continuous_ms);
                continue;
            };
            if item.announced_level != Some(item.level) {
                // It has climbed past what was announced, so another announcement is owed. It
                // waits out the rule's window first, which is what stops an escalation announcing
                // a second time within a minute of the first.
                consider(since.due_at(policy.dedup_window_ms));
            }
            if let Some(repeat) = policy.repeat_ms {
                consider(since.due_at(repeat));
            }
        }
        earliest
    }

    /// Installs restored state.
    pub(crate) fn install(&mut self, restored: Restored) {
        self.items = restored
            .items
            .into_iter()
            .map(|item| (item.key.clone(), item))
            .collect();
        self.acks = restored.acks;
        self.consumed = restored.consumed;
        self.gaps = restored.gaps;
        self.pending_inputs = restored.pending;
        self.quiet = restored.quiet;
        self.dropped = restored.dropped;
        // Never behind an identity the restored items already carry: a counter that came back
        // short would hand a second decision a number a consumer has already recorded.
        self.next_announcement = self
            .items
            .values()
            .filter_map(|item| item.pending_handoff)
            .fold(restored.next_announcement, u64::max);
        // The same for the revisions: one handed out again would let an acknowledgement recorded
        // at it cover a later occurrence nobody has seen.
        self.next_revision = self
            .items
            .values()
            .map(|item| item.revision)
            .fold(restored.next_revision, u64::max);
        self.finalised = restored.finalised;
        self.keys = restored.keys;
    }

    /// Re-anchors every interval at `reading`, from the anchors the store kept.
    ///
    /// The continuous clock restarts with the machine, so each interval is kept as the anchor it
    /// was measured from: a continuous reading and the boot it was taken in. An anchor from this
    /// boot measures the interval exactly, including one already overdue, because nothing can set
    /// that clock. An anchor from a boot that has ended measures nothing, and the interval starts
    /// again. Starting again makes a reminder late; working it out across two wall-clock readings
    /// would make it immediate the moment somebody corrected a clock, which is the failure that
    /// matters.
    ///
    /// Every anchor is then written back on *this* boot's clock, at the moment its interval now
    /// starts from. That is what makes the restart happen once: without it the store would keep
    /// the anchor of a boot that has ended, and the next restart would find the same dead anchor
    /// and start the same interval again, however long this boot had been running.
    pub(crate) fn reanchor(&mut self, reading: HostReading) {
        for item in self.items.values_mut() {
            let age = Self::waited(item.anchor, reading);
            item.age = Elapsed::already(age, reading);
            item.anchor = Some(Self::anchor_of(age, reading));
            item.since_notified = item.last_notified_ms.map(|_| {
                let since = Self::waited(item.announced_anchor, reading);
                item.announced_anchor = Some(Self::anchor_of(since, reading));
                Elapsed::already(since, reading)
            });
        }
        for pending in self.pending_inputs.values_mut() {
            let waited = Self::waited(pending.anchor, reading);
            pending.waited = Elapsed::already(waited, reading);
            pending.anchor = Some(Self::anchor_of(waited, reading));
        }
    }

    /// Returns the anchor, on this reading's own clock, an interval that has run for `elapsed_ms`
    /// started from.
    ///
    /// An interval whose anchor is already this boot's comes back with the same one, so nothing
    /// drifts; one that had none, or one from a boot that has ended, gets an anchor here.
    fn anchor_of(elapsed_ms: u64, reading: HostReading) -> Anchor {
        Anchor::new(
            reading.boot,
            reading.continuous_ms.saturating_sub(elapsed_ms),
        )
    }

    fn consume(&mut self, event: &SourceEvent, reading: HostReading, mode: Mode) -> Vec<Outcome> {
        let origin = event.cursor.origin;
        let source = event.cursor.source;
        let sequence = event.cursor.sequence;
        let mut outcomes = Vec::new();
        // A session whose live conditions ended with its closure takes nothing more: its records
        // were read before it was ended, and anything that arrives now would raise a request that
        // can no longer be answered.
        if self.is_finalised(&origin) {
            return outcomes;
        }
        let dense = numbers_every_record(source);
        match self.consumed.get(&(origin, source)).copied() {
            Some(consumed) => {
                if sequence <= consumed {
                    return outcomes;
                }
                if dense && sequence > consumed + 1 {
                    outcomes.extend(self.note_gap(origin, source, consumed + 1, Some(sequence)));
                }
            }
            // Nothing consumed from this source yet. Sequences start at one, so an engine whose
            // first record is a later one has missed the ones before it. A host that knows better
            // says so with `start_from` rather than leaving the engine to guess.
            None if dense && sequence > 1 => {
                outcomes.extend(self.note_gap(origin, source, 1, Some(sequence)));
            }
            None => {}
        }
        self.consumed.insert((origin, source), sequence);
        outcomes.extend(self.decide(event, reading, mode));
        outcomes
    }

    #[expect(
        clippy::too_many_lines,
        reason = "one arm per typed event, each naming the rule and subject it raises or ends"
    )]
    fn decide(&mut self, event: &SourceEvent, reading: HostReading, mode: Mode) -> Vec<Outcome> {
        let source = event.cursor.source;
        let origin = event.cursor.origin;
        let raise = |id: AttentionRule,
                     subject: String,
                     session_id: Option<SessionId>,
                     text: Text,
                     routing: AttentionRouting| Raise {
            id,
            subject,
            source,
            origin,
            session_id,
            text,
            grant: None,
            automation: None,
            routing,
            at_ms: event.at_ms,
            at_anchor: event.at_anchor,
        };
        match &event.kind {
            // A record the host consumed that no rule covers. It moves the cursor and nothing
            // else, which is what keeps a jump in the sequence meaning an eviction rather than a
            // record this engine had no rule for.
            EventKind::Observed => Vec::new(),
            EventKind::ApprovalRequested {
                request_id,
                session_id,
                summary,
            } => self.raise(
                raise(
                    AttentionRule::PendingApproval,
                    approval_subject(*session_id, request_id),
                    Some(*session_id),
                    text_of(event, || summary.clone()),
                    AttentionRouting::OwnerPolicy,
                ),
                reading,
                mode,
            ),
            EventKind::ApprovalResolved {
                request_id,
                session_id,
            } => self.resolve(
                AttentionRule::PendingApproval,
                &approval_subject(*session_id, request_id),
            ),
            EventKind::QuestionPending {
                question_id,
                session_id,
                verified,
                pending_since_ms,
                pending_since_anchor,
                summary,
            } => {
                if !*verified {
                    // An unverified source never becomes attention work. Section 25 counts the
                    // idle reminder from a verified pending request, and a request the worker did
                    // not admit is a claim rather than a request.
                    return Vec::new();
                }
                let waited = Self::waited(*pending_since_anchor, reading);
                // Whether the producer anchored the moment or not, the wait now runs from a point
                // on this boot's clock, and that point is what is written down.
                let anchor = Self::anchor_of(waited, reading);
                self.bound_pending_inputs(*question_id);
                self.pending_inputs.insert(
                    *question_id,
                    PendingInput {
                        session_id: *session_id,
                        record: event.cursor,
                        pending_since_ms: *pending_since_ms,
                        waited: Elapsed::already(waited, reading),
                        reminded: false,
                        anchor: Some(anchor),
                    },
                );
                self.raise(
                    raise(
                        AttentionRule::PendingInput,
                        question_id.to_string(),
                        Some(*session_id),
                        text_of(event, || summary.clone()),
                        AttentionRouting::OwnerPolicy,
                    ),
                    reading,
                    mode,
                )
            }
            EventKind::QuestionResolved { question_id, .. } => {
                self.pending_inputs.remove(question_id);
                let mut outcomes =
                    self.resolve(AttentionRule::PendingInput, &question_id.to_string());
                outcomes.extend(
                    self.resolve(AttentionRule::InputIdleReminder, &question_id.to_string()),
                );
                outcomes
            }
            EventKind::CommandCompleted {
                session_id,
                command,
                exit_code,
            } => {
                if *exit_code == 0 {
                    return Vec::new();
                }
                self.raise(
                    raise(
                        AttentionRule::CommandFailed,
                        format!("{session_id}|{command}"),
                        Some(*session_id),
                        text_of(event, || format!("{command} exited {exit_code}")),
                        AttentionRouting::OwnerPolicy,
                    ),
                    reading,
                    mode,
                )
            }
            EventKind::TurnCompleted {
                session_id,
                turn_id,
                summary,
                ..
            } => self.raise(
                raise(
                    AttentionRule::ReviewReady,
                    format!("{session_id}|{turn_id}"),
                    Some(*session_id),
                    text_of(event, || summary.clone()),
                    AttentionRouting::OwnerPolicy,
                ),
                reading,
                mode,
            ),
            // A change set captured outside a turn is review work with no inbox item of its own.
            // Nothing is waiting on the person for it: it is a version they will find when they
            // look, and the review state is where that belongs.
            EventKind::ChangeSetCaptured { .. } => Vec::new(),
            EventKind::AdapterFailed {
                plugin_id,
                session_id,
                detail,
            } => self.raise(
                raise(
                    AttentionRule::AdapterFailed,
                    adapter_subject(origin, plugin_id),
                    *session_id,
                    text_of(event, || format!("{plugin_id}: {detail}")),
                    AttentionRouting::OwnerPolicy,
                ),
                reading,
                mode,
            ),
            EventKind::AdapterRecovered { plugin_id } => self.resolve(
                AttentionRule::AdapterFailed,
                &adapter_subject(origin, plugin_id),
            ),
            EventKind::HostContactLost { detail } => self.raise(
                raise(
                    AttentionRule::HostContactLost,
                    "host".to_owned(),
                    None,
                    text_of(event, || detail.clone()),
                    AttentionRouting::OwnerPolicy,
                ),
                reading,
                mode,
            ),
            EventKind::HostContactRestored => self.resolve(AttentionRule::HostContactLost, "host"),
            EventKind::ApplicationNotice { session_id, notice } => {
                // An identifier is the application's own grouping, and the notice is keyed on it.
                // Without one, two notices that say the same thing are one condition, and what
                // they say is known by the fingerprint the record's owner made, which travels
                // whether or not the text does. A notice with neither is its own record.
                let subject = match (&notice.id, &notice.fingerprint) {
                    (Some(id), _) => format!("{session_id}|id|{id}"),
                    (None, Some(fingerprint)) => {
                        format!("{session_id}|fingerprint|{}", fingerprint.to_hex())
                    }
                    (None, None) => format!(
                        "{session_id}|record|{}|{}|{}",
                        event.cursor.origin, event.cursor.source, event.cursor.sequence
                    ),
                };
                let routing = if notice.lease_held {
                    AttentionRouting::LeaseHolder
                } else {
                    AttentionRouting::OwnerPolicy
                };
                self.raise(
                    raise(
                        AttentionRule::ApplicationNotice,
                        subject,
                        Some(*session_id),
                        text_of(event, || match &notice.title {
                            Some(title) => format!("{title}: {}", notice.body),
                            None => notice.body.clone(),
                        }),
                        routing,
                    ),
                    reading,
                    mode,
                )
            }
            EventKind::AutomationPaused {
                subject,
                reason,
                grant_id,
            } => {
                let (keyed, named) = automation_subject(subject);
                let mut paused = raise(
                    AttentionRule::AutomationPaused,
                    keyed,
                    None,
                    // The workflow journal's own record: identifiers and the name of a limit,
                    // never anything a node, a terminal or a model produced.
                    Text::Host(clip_summary(&format!("{named} paused: {reason}"))),
                    AttentionRouting::OwnerPolicy,
                );
                paused.grant = *grant_id;
                paused.automation = Some(subject.clone());
                self.raise(paused, reading, mode)
            }
            EventKind::AutomationResumed { subject } => {
                let (keyed, _) = automation_subject(subject);
                self.resolve(AttentionRule::AutomationPaused, &keyed)
            }
        }
    }

    /// Keeps the pending requests inside [`MAX_RETAINED_PENDING_INPUTS`].
    ///
    /// The question ledger is where a request lives; this is only what the reminder is measured
    /// from. What goes is the request that has been pending longest *and* has already had its
    /// reminder raised, so the bound never takes away a reminder that is still owed. When every
    /// request is still owed one, the set goes over its bound rather than losing one.
    fn bound_pending_inputs(&mut self, keep: QuestionId) {
        while self.pending_inputs.len() >= MAX_RETAINED_PENDING_INPUTS {
            let Some(oldest) = self
                .pending_inputs
                .iter()
                .filter(|(question_id, pending)| **question_id != keep && pending.reminded)
                .min_by(|left, right| {
                    left.1
                        .pending_since_ms
                        .get()
                        .cmp(&right.1.pending_since_ms.get())
                        .then_with(|| left.0.cmp(right.0))
                })
                .map(|(question_id, _)| *question_id)
            else {
                break;
            };
            self.pending_inputs.remove(&oldest);
        }
    }

    /// Returns how much of an interval had already run at this reading.
    ///
    /// Only one clock answers that: the boot-scoped continuous one, which nobody can set. An
    /// anchor on it, taken in this boot, gives the exact figure; anything else - no anchor at all,
    /// or one from a boot that has ended - gives nought, and the interval starts here. Nought is
    /// less than the true wait, never more, which makes a reminder late; the alternative is
    /// arithmetic on a wall clock somebody may have moved, which makes one fire at once.
    fn waited(anchor: Option<Anchor>, reading: HostReading) -> u64 {
        anchor
            .and_then(|anchor| anchor.elapsed_at(reading))
            .unwrap_or_default()
    }

    /// Returns the next item revision, which only goes forward.
    fn fresh_revision(&mut self) -> u64 {
        self.next_revision = self.next_revision.saturating_add(1);
        self.next_revision
    }

    fn raise(&mut self, raise: Raise, reading: HostReading, mode: Mode) -> Vec<Outcome> {
        let key = self.keys.attention_key(raise.id, &raise.subject);
        let policy = rule(raise.id);
        let mut outcomes = Vec::new();
        if self.items.contains_key(&key) {
            // A new occurrence is new work for everybody who acknowledged the last one, so the
            // item takes a revision nobody's acknowledgement names.
            let revision = self.fresh_revision();
            let item = self
                .items
                .get_mut(&key)
                .expect("the item was found a moment ago");
            item.occurrences = item.occurrences.saturating_add(1);
            item.revision = revision;
            item.last_seen_ms = raise.at_ms;
            item.text = raise.text;
            item.routing = raise.routing;
            item.source = raise.source;
            item.origin = raise.origin;
            let occurrences = item.occurrences;
            let inside = item
                .since_notified
                .is_some_and(|since| since.ms(reading) < policy.dedup_window_ms);
            outcomes.push(Outcome::Repeated {
                key: key.clone(),
                occurrences,
            });
            if mode == Mode::Replay {
                // A replayed occurrence outside the window is one nobody has decided about. The
                // replay itself announces nothing, so the item is left undecided and the first
                // tick after the rebuild decides it; leaving the previous announcement's interval
                // in place would hide the new occurrence behind an announcement of the old one.
                if !inside && let Some(item) = self.items.get_mut(&key) {
                    item.since_notified = None;
                    item.last_notified_ms = None;
                    item.announced_level = None;
                    item.notification = NotificationState::Pending;
                }
                return outcomes;
            }
            if inside {
                if let Some(item) = self.items.get_mut(&key) {
                    item.notification = NotificationState::Suppressed;
                }
                return outcomes;
            }
            outcomes.extend(self.announce(&key, reading, false));
            return outcomes;
        }
        // Whether the producer anchored the condition's moment or not, the age now runs from a
        // point on this boot's clock, and that point is what is written down.
        let waited = Self::waited(raise.at_anchor, reading);
        let age = Elapsed::already(waited, reading);
        let anchor = Some(Self::anchor_of(waited, reading));
        // A fresh item is fresh work. An acknowledgement of an earlier occurrence covered that
        // occurrence, not this one, so it is cleared rather than carried across.
        for acks in self.acks.values_mut() {
            acks.remove(&key);
        }
        let revision = self.fresh_revision();
        let item = Item {
            key: key.clone(),
            rule: raise.id,
            source: raise.source,
            origin: raise.origin,
            session_id: raise.session_id,
            text: raise.text,
            grant: raise.grant,
            automation: raise.automation,
            revision,
            routing: raise.routing,
            level: policy.initial,
            steps_taken: 0,
            occurrences: 1,
            first_seen_ms: raise.at_ms,
            last_seen_ms: raise.at_ms,
            notification: NotificationState::Pending,
            anchor,
            last_notified_ms: None,
            announced_anchor: None,
            announced_level: None,
            announcements: 0,
            pending_handoff: None,
            uncertain: false,
            age,
            since_notified: None,
            deferred: false,
        };
        let level = item.level;
        self.items.insert(key.clone(), item);
        outcomes.push(Outcome::Raised {
            key: key.clone(),
            rule: raise.id,
            level,
        });
        outcomes.extend(self.enforce_bound(reading));
        if mode == Mode::Live && self.items.contains_key(&key) {
            outcomes.extend(self.announce(&key, reading, false));
        }
        outcomes
    }

    /// Keeps the inbox inside [`MAX_RETAINED_ATTENTION_ITEMS`].
    ///
    /// The inbox is a working set. The receipts, the question ledger and the retained output are
    /// where the record lives, so what is let go of here is the least urgent and oldest *record of
    /// a condition*, and the count of what has gone is reported rather than hidden. An item that
    /// has only just arrived is not one of those and cannot be chosen; among those that are, level
    /// and then age decide, so an informational notice goes before an urgent approval.
    ///
    /// Four things are never let go of: a condition somebody or something is still waiting on, a
    /// decision no delivery consumer has settled, a decision quiet hours are holding, and a
    /// decision whose de-duplication window is still running - which includes a condition nobody
    /// has decided about at all, because that window has not started.
    fn enforce_bound(&mut self, reading: HostReading) -> Vec<Outcome> {
        let bound = usize::try_from(MAX_RETAINED_ATTENTION_ITEMS).unwrap_or(usize::MAX);
        let mut outcomes = Vec::new();
        while self.items.len() > bound {
            let Some(victim) = self
                .items
                .values()
                .filter(|item| {
                    let policy = rule(item.rule);
                    // Four of these are not a record of a condition but work in flight, and
                    // letting go of one loses something nothing will offer again: a decision
                    // nobody has taken responsibility for, a decision quiet hours are holding, a
                    // condition nobody has decided about at all - which is what a fresh item is
                    // until it is announced, and what every replayed item is until the first tick
                    // after a rebuild - and a decision whose de-duplication window is still
                    // running, because the item is the whole of what the engine remembers that
                    // window by and the same condition would be announced twice inside it.
                    policy.droppable
                        && item.pending_handoff.is_none()
                        && !item.deferred
                        && item
                            .since_notified
                            .is_some_and(|since| since.ms(reading) >= policy.dedup_window_ms)
                })
                .min_by(|left, right| {
                    left.level
                        .cmp(&right.level)
                        .then_with(|| left.first_seen_ms.get().cmp(&right.first_seen_ms.get()))
                        .then_with(|| left.key.as_str().cmp(right.key.as_str()))
                })
                .map(|item| item.key.clone())
            else {
                // Everything in the inbox is a condition somebody or something is still waiting
                // on, or a decision about one that has not gone out, been taken or been made. The
                // inbox goes over its bound rather than forgetting one of those: section 25 keeps
                // an outstanding approval in the inbox, and a host that dropped one would be
                // answering that nothing is waiting when something is.
                break;
            };
            self.items.remove(&victim);
            for acks in self.acks.values_mut() {
                acks.remove(&victim);
            }
            self.dropped = self.dropped.saturating_add(1);
            outcomes.push(Outcome::Dropped { key: victim });
        }
        outcomes
    }

    fn announce(
        &mut self,
        key: &AttentionKey,
        reading: HostReading,
        released: bool,
    ) -> Vec<Outcome> {
        let quiet = self.quiet_now(reading);
        let Some(item) = self.items.get_mut(key) else {
            return Vec::new();
        };
        let (level, routing) = (item.level, item.routing);
        // The interval starts whether the announcement goes out or is held, so a repeat that falls
        // inside quiet hours is deferred once rather than re-decided on every tick.
        item.since_notified = Some(Elapsed::starting(reading));
        item.last_notified_ms = Some(reading.wall_ms);
        item.announced_anchor = Some(reading.anchor());
        if quiet {
            item.deferred = true;
            item.notification = NotificationState::Deferred;
            return vec![Outcome::Deferred {
                key: key.clone(),
                level,
            }];
        }
        item.deferred = false;
        item.notification = NotificationState::Delivered;
        item.announced_level = Some(level);
        item.announcements = item.announcements.saturating_add(1);
        // The identity comes from a counter of this store's own, not from the item's count. An
        // item that resolves and is raised again starts its count at one, and a consumer that had
        // recorded the earlier decision would settle the new one by the number they shared.
        let number = self.next_announcement.saturating_add(1);
        self.next_announcement = number;
        let item = self
            .items
            .get_mut(key)
            .expect("the item was read a moment ago");
        item.pending_handoff = Some(number);
        vec![if released {
            Outcome::Released {
                key: key.clone(),
                level,
                routing,
            }
        } else {
            Outcome::Notified {
                key: key.clone(),
                level,
                routing,
            }
        }]
    }

    /// Ends one item, taking any announcement still held for it with it.
    ///
    /// A held announcement about a condition that has ended is not a notification anybody wants:
    /// quiet hours defer an announcement about something outstanding, and nothing here is
    /// outstanding any more.
    fn resolve(&mut self, id: AttentionRule, subject: &str) -> Vec<Outcome> {
        let key = self.keys.attention_key(id, subject);
        if self.items.remove(&key).is_none() {
            return Vec::new();
        }
        for acks in self.acks.values_mut() {
            acks.remove(&key);
        }
        vec![Outcome::Resolved { key }]
    }

    /// Settles every item's level against its origin's certified reading, without announcing
    /// anything.
    fn climb(&mut self, at: &dyn Fn(&Origin) -> Option<HostReading>) -> Vec<Outcome> {
        let mut outcomes = Vec::new();
        for item in self.items.values_mut() {
            let Some(reading) = at(&item.origin) else {
                continue;
            };
            let policy = rule(item.rule);
            let (level, taken) = policy.level_after(item.age.ms(reading));
            if taken > item.steps_taken {
                let from = item.level;
                item.level = level;
                item.steps_taken = taken;
                outcomes.push(Outcome::Escalated {
                    key: item.key.clone(),
                    from,
                    to: level,
                });
            }
        }
        outcomes
    }

    /// Makes at most one announcement decision per item whose origin the host has certified.
    ///
    /// An announcement is owed when nothing has been decided about the item, when it has climbed
    /// past the level its last announcement went out at, or when its rule's repeat interval has
    /// run. Whichever it is, the rule's de-duplication window applies: an escalation a few seconds
    /// after an announcement waits out the window, and [`Engine::next_deadline`] is where the host
    /// learns when to come back for it. Whether the announcement goes out or is held is decided
    /// against the present, because quiet hours are about now.
    fn announce_due(
        &mut self,
        reading: HostReading,
        at: &dyn Fn(&Origin) -> Option<HostReading>,
    ) -> Vec<Outcome> {
        let quiet = self.quiet_now(reading);
        let due: Vec<_> = self
            .items
            .values()
            .filter_map(|item| {
                let certified = at(&item.origin)?;
                if item.deferred {
                    // Still held, or released now that the window has ended.
                    return (!quiet).then(|| (item.key.clone(), true));
                }
                let policy = rule(item.rule);
                let Some(since) = item.since_notified else {
                    return Some((item.key.clone(), false));
                };
                let owed = item.announced_level != Some(item.level)
                    || policy
                        .repeat_ms
                        .is_some_and(|repeat| since.ms(certified) >= repeat);
                (owed && since.ms(certified) >= policy.dedup_window_ms)
                    .then(|| (item.key.clone(), false))
            })
            .collect();
        due.into_iter()
            .flat_map(|(key, released)| self.announce(&key, reading, released))
            .collect()
    }

    fn fire_idle_reminders(
        &mut self,
        reading: HostReading,
        at: &dyn Fn(&Origin) -> Option<HostReading>,
    ) -> Vec<Outcome> {
        // A request is its record's: the record's origin is whose reading decides the reminder and
        // whose text the reminder carries, and the session the request names stays the one it is
        // about.
        let due: Vec<_> = self
            .pending_inputs
            .iter()
            .filter(|(_, pending)| {
                !pending.reminded
                    && at(&pending.record.origin)
                        .is_some_and(|certified| pending.waited.ms(certified) >= IDLE_REMINDER_MS)
            })
            .map(|(question_id, pending)| (*question_id, pending.session_id, pending.record))
            .collect();
        let mut outcomes = Vec::new();
        for (question_id, session_id, record) in due {
            if let Some(pending) = self.pending_inputs.get_mut(&question_id) {
                pending.reminded = true;
            }
            outcomes.extend(self.raise(
                Raise {
                    id: AttentionRule::InputIdleReminder,
                    subject: question_id.to_string(),
                    source: record.source,
                    origin: record.origin,
                    session_id: Some(session_id),
                    text: Text::Record(record),
                    grant: None,
                    automation: None,
                    routing: AttentionRouting::OwnerPolicy,
                    at_ms: reading.wall_ms,
                    // The reminder is raised now, on the reading this host is holding, so its
                    // anchor is that reading.
                    at_anchor: Some(reading.anchor()),
                },
                reading,
                Mode::Live,
            ));
        }
        outcomes
    }

    /// Returns the continuous reading quiet hours end at, when the host is inside them.
    fn quiet_release(&self, reading: HostReading) -> Option<u64> {
        if !reading.wall_proven {
            return None;
        }
        let quiet = self.quiet.as_ref()?;
        let minute = reading.minute_of_day();
        if !quiet.covers(minute) {
            return None;
        }
        let remaining = quiet
            .minutes_until_end(minute)
            .saturating_mul(MS_IN_MINUTE)
            .saturating_sub(reading.ms_of_day() % MS_IN_MINUTE);
        Some(reading.continuous_ms.saturating_add(remaining))
    }
}

/// The engine's half of what the feature store read back.
pub(crate) struct Restored {
    pub(crate) items: Vec<Item>,
    pub(crate) acks: BTreeMap<ActorId, BTreeMap<AttentionKey, ItemAck>>,
    pub(crate) consumed: BTreeMap<(Origin, AttentionSource), u64>,
    pub(crate) gaps: Vec<AttentionGap>,
    pub(crate) pending: BTreeMap<QuestionId, PendingInput>,
    pub(crate) quiet: Option<QuietHours>,
    pub(crate) dropped: u64,
    pub(crate) next_announcement: u64,
    pub(crate) next_revision: u64,
    pub(crate) finalised: BTreeSet<SessionId>,
    pub(crate) keys: crate::key::KeySecret,
}
