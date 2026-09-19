//! The attention engine: a state machine over typed events.
//!
//! The engine holds the inbox, the quiet-hours window, the per-actor acknowledgements and the
//! cursors it has consumed. It reads no clock, opens no file and sends no notification. Everything
//! it decides comes out as an [`Outcome`], and the host is what acts on one.
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
//! # What the engine will not do
//!
//! It will not treat a gap as an ending. A range of retained events that retention has taken is
//! recorded as a gap, and every unresolved item from that same source is marked uncertain and left
//! in the inbox. Section 24 is explicit: a history gap is not an inferred approval or completion,
//! and the only honest answer for a host that cannot tell is to say so.

use std::collections::BTreeMap;

use kr_protocol::attention::{
    AttentionGap, AttentionItem, AttentionKey, AttentionLevel, AttentionRouting, AttentionRule,
    AttentionSource, IDLE_REMINDER_MS, MAX_ATTENTION_SUMMARY_LEN, MAX_RETAINED_ATTENTION_ITEMS,
    MAX_RETAINED_PENDING_INPUTS, NotificationState, QuietHours,
};
use kr_protocol::ids::{ActorId, QuestionId, SessionId};
use kr_protocol::scalars::{Nullable, TimestampMs, U64};

use crate::event::{EventKind, SourceEvent};
use crate::rule::rule;
use crate::time::{Elapsed, HostReading, MS_IN_MINUTE};

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

/// One item of attention, as the engine holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Item {
    /// The rule and subject this item stands for.
    pub key: AttentionKey,
    /// The rule that raised it.
    pub rule: AttentionRule,
    /// The retained source the condition was observed in.
    pub source: AttentionSource,
    /// The session it belongs to, when it belongs to one.
    pub session_id: Option<SessionId>,
    /// One line naming the subject, clipped to [`MAX_ATTENTION_SUMMARY_LEN`].
    pub summary: String,
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
    /// Whether the clock was proved when this item's own moments were stamped.
    ///
    /// [`Item::first_seen_ms`] is what an interval measured against the present starts from, and a
    /// host that could not prove its clock when it consumed the event cannot say what that moment
    /// means on a clock it can prove later. So the two are kept together: an age is measured only
    /// when both ends were taken on a clock somebody could vouch for, and starts again otherwise.
    pub anchor_wall_proven: bool,
    /// Whether the clock that stamped [`Item::last_notified_ms`] could be proved at the time.
    ///
    /// A host that cannot prove its wall clock still stamps the moment it read, because the
    /// alternative is no anchor at all. What it must not do is measure against that stamp later,
    /// once the clock is proved: the two readings are not on the same scale, and subtracting one
    /// from the other can make a two-second-old announcement look an hour old, which would announce
    /// the same condition again inside its own window.
    pub announced_wall_proven: bool,
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
    /// Returns this item as the wire type, for one actor.
    #[must_use]
    pub fn to_wire(&self, acknowledged: bool, content: Content) -> AttentionItem {
        AttentionItem {
            key: self.key.clone(),
            rule: self.rule,
            source: self.source,
            level: self.level,
            session_id: Nullable(self.session_id),
            summary: Nullable((content == Content::Whole).then(|| self.summary.clone())),
            trusted: rule(self.rule).trusted,
            routing: self.routing,
            occurrences: U64::new(self.occurrences),
            first_seen_ms: self.first_seen_ms,
            last_seen_ms: self.last_seen_ms,
            notification: self.notification,
            awaiting_delivery: self.pending_handoff.is_some(),
            acknowledged,
            uncertain: self.uncertain,
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
    /// and returned in between, and an older identity settles none of it. The number is unique
    /// inside one session's store; a consumer that combines several keys by the session too.
    pub number: u64,
    /// Its rule.
    pub rule: AttentionRule,
    /// What it asks for.
    pub level: AttentionLevel,
    /// Where it goes.
    pub routing: AttentionRouting,
    /// The session it belongs to, when it belongs to one.
    pub session_id: Option<SessionId>,
    /// One line naming the subject.
    pub summary: String,
}

/// One actor's acknowledgement of one item.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ItemAck {
    /// The occurrence count the item stood at when it was acknowledged.
    ///
    /// A later occurrence is new work, and the acknowledgement does not cover it.
    pub occurrences: u64,
    /// When the actor acknowledged it.
    pub at_ms: TimestampMs,
}

/// A question that is waiting for an answer, and how long it has waited.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingInput {
    /// The session it belongs to.
    pub session_id: SessionId,
    /// One line naming what is being asked.
    pub summary: String,
    /// What the wall clock read when the request became pending.
    pub pending_since_ms: TimestampMs,
    /// How long it has been pending.
    pub waited: Elapsed,
    /// Whether the reminder has already been raised for this request.
    pub reminded: bool,
    /// Whether the clock was proved when [`PendingInput::pending_since_ms`] was taken.
    ///
    /// The five-minute reminder is measured from that moment, so a host that could not prove its
    /// clock then cannot measure against it once it can. The wait starts again instead, which
    /// raises the reminder late rather than at once.
    pub anchor_wall_proven: bool,
}

/// The attention engine.
#[derive(Clone, Debug, Default)]
pub struct Engine {
    items: BTreeMap<AttentionKey, Item>,
    acks: BTreeMap<ActorId, BTreeMap<AttentionKey, ItemAck>>,
    consumed: BTreeMap<AttentionSource, u64>,
    gaps: Vec<AttentionGap>,
    pending_inputs: BTreeMap<QuestionId, PendingInput>,
    quiet: Option<QuietHours>,
    dropped: u64,
    next_announcement: u64,
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
    session_id: Option<SessionId>,
    summary: String,
    routing: AttentionRouting,
    at_ms: TimestampMs,
    at_proven: bool,
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

    /// Returns the highest sequence consumed from one source.
    #[must_use]
    pub fn consumed(&self, source: AttentionSource) -> Option<u64> {
        self.consumed.get(&source).copied()
    }

    /// Records where a source stands without claiming anything about what came before.
    ///
    /// A host that starts the engine partway through a session's life calls this rather than
    /// letting the first event look like a jump. Without it, a first event at sequence nine says
    /// eight records were evicted, which is a gap the host has no reason to believe in.
    pub fn start_from(&mut self, source: AttentionSource, sequence: u64) {
        let consumed = self.consumed.entry(source).or_insert(sequence);
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

    /// Returns the highest sequence consumed from each source.
    #[must_use]
    pub const fn all_consumed(&self) -> &BTreeMap<AttentionSource, u64> {
        &self.consumed
    }

    /// Returns the questions waiting for an answer.
    #[must_use]
    pub const fn pending_inputs(&self) -> &BTreeMap<QuestionId, PendingInput> {
        &self.pending_inputs
    }

    /// Returns the inbox one actor sees, oldest first.
    #[must_use]
    pub fn inbox(
        &self,
        actor: &ActorId,
        include_acknowledged: bool,
        content: Content,
    ) -> Vec<AttentionItem> {
        let mut items: Vec<_> = self
            .items
            .values()
            .filter_map(|item| {
                let acknowledged = self.is_acknowledged(actor, item);
                (include_acknowledged || !acknowledged).then(|| item.to_wire(acknowledged, content))
            })
            .collect();
        items.sort_by(|left, right| {
            left.first_seen_ms
                .get()
                .cmp(&right.first_seen_ms.get())
                .then_with(|| left.key.as_str().cmp(right.key.as_str()))
        });
        items
    }

    /// Records one actor's acknowledgement of each key it holds an item for.
    ///
    /// Returns the keys that were acknowledged. A key with no item is not acknowledged: there is
    /// nothing to have seen, and recording it would hide the item if the condition recurred.
    ///
    /// Nothing about the host's own reminders changes. Section 23 makes an acknowledgement affect
    /// only the actor that made it, so one device marking an approval seen does not stop the host
    /// reminding the person about an agent that is still waiting.
    pub fn acknowledge(
        &mut self,
        actor: &ActorId,
        keys: &[AttentionKey],
        reading: HostReading,
    ) -> Vec<AttentionKey> {
        let mut acknowledged = Vec::new();
        for key in keys {
            let Some(item) = self.items.get(key) else {
                continue;
            };
            let occurrences = item.occurrences;
            self.acks.entry(actor.clone()).or_default().insert(
                key.clone(),
                ItemAck {
                    occurrences,
                    at_ms: reading.wall_ms,
                },
            );
            acknowledged.push(key.clone());
        }
        acknowledged
    }

    /// Returns whether this actor has acknowledged the current occurrence of an item.
    #[must_use]
    pub fn is_acknowledged(&self, actor: &ActorId, item: &Item) -> bool {
        self.acks
            .get(actor)
            .and_then(|acks| acks.get(&item.key))
            .is_some_and(|ack| ack.occurrences >= item.occurrences)
    }

    /// Records a range of retained events the host can no longer read.
    ///
    /// Every unresolved item from the same source becomes uncertain. It stays in the inbox: a gap
    /// is never an inferred approval or completion.
    pub fn note_gap(&mut self, source: AttentionSource, from: u64, to: u64) -> Vec<Outcome> {
        if to <= from {
            return Vec::new();
        }
        let gap = AttentionGap {
            source,
            from_sequence: U64::new(from),
            to_sequence: U64::new(to),
        };
        if self.gaps.contains(&gap) {
            return Vec::new();
        }
        self.gaps.push(gap);
        if self.gaps.len() > MAX_GAPS {
            self.gaps.remove(0);
        }
        for item in self.items.values_mut() {
            if item.source == source {
                item.uncertain = true;
            }
        }
        // The consumed cursor moves past the range, because the records inside it will never
        // arrive. Leaving it where it was would make the next event look like a second gap.
        let consumed = self.consumed.entry(source).or_insert(0);
        *consumed = (*consumed).max(to.saturating_sub(1));
        vec![Outcome::GapRecorded { gap }]
    }

    /// Applies one typed event, announcing what it decides.
    ///
    /// An event at or below the cursor already consumed from its source changes nothing, which is
    /// what lets the retained events be replayed as often as a host needs to. An event beyond the
    /// next sequence means the records between were evicted, and the range is recorded as a gap
    /// before the event itself is applied.
    pub fn apply(&mut self, event: &SourceEvent, reading: HostReading) -> Vec<Outcome> {
        self.consume(event, reading, Mode::Live)
    }

    /// Rebuilds state from one retained event without announcing anything.
    ///
    /// This is the reconstruction path. An item's age is taken from the event's own recorded time,
    /// so an approval that has been outstanding for an hour comes back an hour old, and nothing is
    /// announced for something that happened before this host was running. The first
    /// [`Engine::tick`] after a replay decides every announcement against the present.
    pub fn replay(&mut self, event: &SourceEvent, reading: HostReading) -> Vec<Outcome> {
        self.consume(event, reading, Mode::Replay)
    }

    /// Advances every timer to this reading.
    ///
    /// The order is deliberate. Levels are settled first, then at most one announcement is decided
    /// per item, so an item that climbed a step and was also due a repeat is announced once, at the
    /// level it now stands at, rather than twice at two levels. The inbox bound is applied last,
    /// against what those decisions left.
    pub fn tick(&mut self, reading: HostReading) -> Vec<Outcome> {
        let mut outcomes = self.fire_idle_reminders(reading);
        outcomes.extend(self.climb(reading));
        outcomes.extend(self.announce_due(reading));
        // Last, because what the bound may let go of is decided by what has just been announced
        // and by what a consumer has settled since the last pass. An inbox that went over its
        // bound while everything in it was work in flight comes back inside it here.
        outcomes.extend(self.enforce_bound(reading));
        outcomes
    }

    /// Returns the announcements the host has decided and no consumer has settled.
    ///
    /// Nothing is forgotten here. A consumer takes these, records them durably, and then calls
    /// [`Engine::settle_announcements`] with what it recorded; anything it did not settle is
    /// offered again, at this start or the next one. Forgetting one at the moment it was handed
    /// over would lose it to a crash between the handing and the recording.
    #[must_use]
    pub fn take_announcements(&self) -> Vec<Announcement> {
        self.items
            .values()
            .filter_map(|item| {
                item.pending_handoff.map(|number| Announcement {
                    key: item.key.clone(),
                    number,
                    rule: item.rule,
                    level: item.level,
                    routing: item.routing,
                    session_id: item.session_id,
                    summary: item.summary.clone(),
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
        let mut earliest: Option<u64> = None;
        let mut consider = |deadline: u64| {
            earliest = Some(earliest.map_or(deadline, |current: u64| current.min(deadline)));
        };
        let quiet = self.quiet_now(reading);
        if self.items.values().any(|item| item.deferred) {
            // Either the window is still standing, and the release is when it ends, or it is not,
            // and the release is now.
            consider(self.quiet_release(reading).unwrap_or(reading.continuous_ms));
        }
        for pending in self.pending_inputs.values() {
            if !pending.reminded {
                consider(pending.waited.due_at(IDLE_REMINDER_MS));
            }
        }
        for item in self.items.values() {
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
        self.keys = restored.keys;
    }

    /// Re-anchors every interval at `reading`, from the wall-clock moments the store kept.
    ///
    /// The continuous clock restarts with the machine, so the durable half of an interval is the
    /// moment it started. An interval is measured again only when both ends were taken on a clock
    /// somebody could prove: this reading, and the reading that stamped the anchor. That keeps an
    /// interval exactly where it was, including one already overdue, whenever it can be trusted,
    /// and starts every other one again rather than subtracting two readings that are not on the
    /// same scale. Starting again makes a reminder late; the arithmetic would make it immediate,
    /// which is the failure that matters.
    pub(crate) fn reanchor(&mut self, reading: HostReading) {
        let since = |recorded: TimestampMs| {
            if reading.wall_proven {
                reading.wall_ms.get().saturating_sub(recorded.get())
            } else {
                0
            }
        };
        for item in self.items.values_mut() {
            let anchored = item.anchor_wall_proven;
            item.age = Elapsed::already(
                if anchored {
                    since(item.first_seen_ms)
                } else {
                    0
                },
                reading,
            );
            // Both ends of the interval have to be on a clock somebody can vouch for. An anchor
            // stamped while this host could not prove its clock is not one, whatever the clock
            // says now, so that interval starts again rather than being measured against it.
            let announced = item.announced_wall_proven;
            item.since_notified = item
                .last_notified_ms
                .map(|at| Elapsed::already(if announced { since(at) } else { 0 }, reading));
        }
        for pending in self.pending_inputs.values_mut() {
            let anchored = pending.anchor_wall_proven;
            pending.waited = Elapsed::already(
                if anchored {
                    since(pending.pending_since_ms)
                } else {
                    0
                },
                reading,
            );
        }
    }

    fn consume(&mut self, event: &SourceEvent, reading: HostReading, mode: Mode) -> Vec<Outcome> {
        let source = event.cursor.source;
        let sequence = event.cursor.sequence;
        let mut outcomes = Vec::new();
        match self.consumed.get(&source).copied() {
            Some(consumed) => {
                if sequence <= consumed {
                    return outcomes;
                }
                if sequence > consumed + 1 {
                    outcomes.extend(self.note_gap(source, consumed + 1, sequence));
                }
            }
            // Nothing consumed from this source yet. Sequences start at one, so an engine whose
            // first record is a later one has missed the ones before it. A host that knows better
            // says so with `start_from` rather than leaving the engine to guess.
            None if sequence > 1 => {
                outcomes.extend(self.note_gap(source, 1, sequence));
            }
            None => {}
        }
        self.consumed.insert(source, sequence);
        outcomes.extend(self.decide(event, reading, mode));
        outcomes
    }

    fn decide(&mut self, event: &SourceEvent, reading: HostReading, mode: Mode) -> Vec<Outcome> {
        let source = event.cursor.source;
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
                Raise {
                    id: AttentionRule::PendingApproval,
                    subject: request_id.to_string(),
                    source,
                    session_id: Some(*session_id),
                    summary: summary.clone(),
                    routing: AttentionRouting::OwnerPolicy,
                    at_ms: event.at_ms,
                    at_proven: event.at_proven,
                },
                reading,
                mode,
            ),
            EventKind::ApprovalResolved { request_id } => {
                self.resolve(AttentionRule::PendingApproval, &request_id.to_string())
            }
            EventKind::QuestionPending {
                question_id,
                session_id,
                verified,
                pending_since_ms,
                summary,
            } => {
                if !*verified {
                    // An unverified source never becomes attention work. Section 25 counts the
                    // idle reminder from a verified pending request, and a request the worker did
                    // not admit is a claim rather than a request.
                    return Vec::new();
                }
                let waited = Self::waited(*pending_since_ms, event.at_ms, event.at_proven, reading);
                self.bound_pending_inputs(*question_id);
                self.pending_inputs.insert(
                    *question_id,
                    PendingInput {
                        session_id: *session_id,
                        summary: clip_summary(summary),
                        pending_since_ms: *pending_since_ms,
                        waited: Elapsed::already(waited, reading),
                        reminded: false,
                        anchor_wall_proven: event.at_proven,
                    },
                );
                self.raise(
                    Raise {
                        id: AttentionRule::PendingInput,
                        subject: question_id.to_string(),
                        source,
                        session_id: Some(*session_id),
                        summary: summary.clone(),
                        routing: AttentionRouting::OwnerPolicy,
                        at_ms: event.at_ms,
                        at_proven: event.at_proven,
                    },
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
                    Raise {
                        id: AttentionRule::CommandFailed,
                        subject: format!("{session_id}|{command}"),
                        source,
                        session_id: Some(*session_id),
                        summary: format!("{command} exited {exit_code}"),
                        routing: AttentionRouting::OwnerPolicy,
                        at_ms: event.at_ms,
                        at_proven: event.at_proven,
                    },
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
                Raise {
                    id: AttentionRule::ReviewReady,
                    subject: format!("{session_id}|{turn_id}"),
                    source,
                    session_id: Some(*session_id),
                    summary: summary.clone(),
                    routing: AttentionRouting::OwnerPolicy,
                    at_ms: event.at_ms,
                    at_proven: event.at_proven,
                },
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
                Raise {
                    id: AttentionRule::AdapterFailed,
                    subject: plugin_id.to_string(),
                    source,
                    session_id: *session_id,
                    summary: format!("{plugin_id}: {detail}"),
                    routing: AttentionRouting::OwnerPolicy,
                    at_ms: event.at_ms,
                    at_proven: event.at_proven,
                },
                reading,
                mode,
            ),
            EventKind::AdapterRecovered { plugin_id } => {
                self.resolve(AttentionRule::AdapterFailed, &plugin_id.to_string())
            }
            EventKind::HostContactLost { detail } => self.raise(
                Raise {
                    id: AttentionRule::HostContactLost,
                    subject: "host".to_owned(),
                    source,
                    session_id: None,
                    summary: detail.clone(),
                    routing: AttentionRouting::OwnerPolicy,
                    at_ms: event.at_ms,
                    at_proven: event.at_proven,
                },
                reading,
                mode,
            ),
            EventKind::HostContactRestored => self.resolve(AttentionRule::HostContactLost, "host"),
            EventKind::ApplicationNotice { session_id, notice } => {
                let subject = notice.id.clone().unwrap_or_else(|| notice.body.clone());
                let summary = match &notice.title {
                    Some(title) => format!("{title}: {}", notice.body),
                    None => notice.body.clone(),
                };
                let routing = if notice.lease_held {
                    AttentionRouting::LeaseHolder
                } else {
                    AttentionRouting::OwnerPolicy
                };
                self.raise(
                    Raise {
                        id: AttentionRule::ApplicationNotice,
                        subject: format!("{session_id}|{subject}"),
                        source,
                        session_id: Some(*session_id),
                        summary,
                        routing,
                        at_ms: event.at_ms,
                        at_proven: event.at_proven,
                    },
                    reading,
                    mode,
                )
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

    /// Returns how long a request has been pending at this reading.
    ///
    /// Measuring against the clock this host reads now counts the delay between the producer
    /// recording the event and the engine consuming it, which is part of the wait. It is only
    /// arithmetic anybody can trust when both ends were taken on a clock somebody could vouch for:
    /// this reading, and the moment the event names. Where either cannot be vouched for, the wait
    /// is measured inside the event's own moments, which are one producer's readings of one clock
    /// whatever anyone could prove about it. That understates the wait rather than inventing one.
    fn waited(
        since: TimestampMs,
        at_ms: TimestampMs,
        at_proven: bool,
        reading: HostReading,
    ) -> u64 {
        if reading.wall_proven && at_proven {
            reading.wall_ms.get().saturating_sub(since.get())
        } else {
            at_ms.get().saturating_sub(since.get())
        }
    }

    fn raise(&mut self, raise: Raise, reading: HostReading, mode: Mode) -> Vec<Outcome> {
        let key = self.keys.attention_key(raise.id, &raise.subject);
        let policy = rule(raise.id);
        let summary = clip_summary(&raise.summary);
        let mut outcomes = Vec::new();
        if let Some(item) = self.items.get_mut(&key) {
            item.occurrences = item.occurrences.saturating_add(1);
            item.last_seen_ms = raise.at_ms;
            item.summary = summary;
            item.routing = raise.routing;
            item.source = raise.source;
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
        // A fresh item is fresh work. An acknowledgement of an earlier occurrence covered that
        // occurrence, not this one, so it is cleared rather than carried across.
        for acks in self.acks.values_mut() {
            acks.remove(&key);
        }
        let item = Item {
            key: key.clone(),
            rule: raise.id,
            source: raise.source,
            session_id: raise.session_id,
            summary,
            routing: raise.routing,
            level: policy.initial,
            steps_taken: 0,
            occurrences: 1,
            first_seen_ms: raise.at_ms,
            last_seen_ms: raise.at_ms,
            notification: NotificationState::Pending,
            anchor_wall_proven: raise.at_proven,
            last_notified_ms: None,
            announced_wall_proven: false,
            announced_level: None,
            announcements: 0,
            pending_handoff: None,
            uncertain: false,
            age: Elapsed::already(
                Self::waited(raise.at_ms, raise.at_ms, raise.at_proven, reading),
                reading,
            ),
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
        item.announced_wall_proven = reading.wall_proven;
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

    /// Settles every item's level against this reading, without announcing anything.
    fn climb(&mut self, reading: HostReading) -> Vec<Outcome> {
        let mut outcomes = Vec::new();
        for item in self.items.values_mut() {
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

    /// Makes at most one announcement decision per item.
    ///
    /// An announcement is owed when nothing has been decided about the item, when it has climbed
    /// past the level its last announcement went out at, or when its rule's repeat interval has
    /// run. Whichever it is, the rule's de-duplication window applies: an escalation a few seconds
    /// after an announcement waits out the window, and [`Engine::next_deadline`] is where the host
    /// learns when to come back for it.
    fn announce_due(&mut self, reading: HostReading) -> Vec<Outcome> {
        let quiet = self.quiet_now(reading);
        let due: Vec<_> = self
            .items
            .values()
            .filter_map(|item| {
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
                        .is_some_and(|repeat| since.ms(reading) >= repeat);
                (owed && since.ms(reading) >= policy.dedup_window_ms)
                    .then(|| (item.key.clone(), false))
            })
            .collect();
        due.into_iter()
            .flat_map(|(key, released)| self.announce(&key, reading, released))
            .collect()
    }

    fn fire_idle_reminders(&mut self, reading: HostReading) -> Vec<Outcome> {
        let due: Vec<_> = self
            .pending_inputs
            .iter()
            .filter(|(_, pending)| {
                !pending.reminded && pending.waited.ms(reading) >= IDLE_REMINDER_MS
            })
            .map(|(question_id, pending)| {
                (*question_id, pending.session_id, pending.summary.clone())
            })
            .collect();
        let mut outcomes = Vec::new();
        for (question_id, session_id, summary) in due {
            if let Some(pending) = self.pending_inputs.get_mut(&question_id) {
                pending.reminded = true;
            }
            outcomes.extend(self.raise(
                Raise {
                    id: AttentionRule::InputIdleReminder,
                    subject: question_id.to_string(),
                    source: AttentionSource::Questions,
                    session_id: Some(session_id),
                    summary,
                    routing: AttentionRouting::OwnerPolicy,
                    at_ms: reading.wall_ms,
                    // The reminder is raised now, on the reading this host is holding, so its
                    // anchor is exactly as vouched for as that reading is.
                    at_proven: reading.wall_proven,
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
    pub(crate) consumed: BTreeMap<AttentionSource, u64>,
    pub(crate) gaps: Vec<AttentionGap>,
    pub(crate) pending: BTreeMap<QuestionId, PendingInput>,
    pub(crate) quiet: Option<QuietHours>,
    pub(crate) dropped: u64,
    pub(crate) next_announcement: u64,
    pub(crate) keys: crate::key::KeySecret,
}
