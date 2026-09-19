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
//! 4. An item nobody has attended to climbs its rule's ladder and is announced again at the rule's
//!    interval.
//! 5. A condition that ends resolves its item, which leaves the inbox.
//!
//! # What the engine will not do
//!
//! It will not treat a gap as an ending. A range of retained events that retention has taken is
//! recorded as a gap, and every unresolved item the missing range could have resolved is marked
//! uncertain and left in the inbox. Section 24 is explicit: a history gap is not an inferred
//! approval or completion, and the only honest answer for a host that cannot tell is to say so.

use std::collections::{BTreeMap, BTreeSet};

use kr_protocol::attention::{
    AttentionGap, AttentionItem, AttentionKey, AttentionLevel, AttentionRouting, AttentionRule,
    AttentionSource, IDLE_REMINDER_MS, NotificationState, QuietHours,
};
use kr_protocol::ids::{ActorId, QuestionId, SessionId};
use kr_protocol::scalars::{Nullable, TimestampMs, U64};

use crate::event::{EventKind, SourceEvent};
use crate::rule::{Rule, rule};
use crate::time::{HostReading, MS_IN_MINUTE};

/// Largest number of gaps the engine keeps. The oldest is dropped past it.
pub const MAX_GAPS: usize = 64;

/// One item of attention, as the engine holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Item {
    /// The rule and subject this item stands for.
    pub key: AttentionKey,
    /// The rule that raised it.
    pub rule: AttentionRule,
    /// The session it belongs to, when it belongs to one.
    pub session_id: Option<SessionId>,
    /// One line naming the subject.
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
    /// Whether a gap in the retained events could have resolved it.
    pub uncertain: bool,
    /// Whether any actor has acknowledged this occurrence.
    ///
    /// The ladder and the repeats stop when somebody has seen the item; each actor's own view of
    /// it is unchanged, because an acknowledgement is per actor and affects only that actor.
    pub attended: bool,
    /// The continuous reading the item was raised at.
    ///
    /// The continuous clock is boot-scoped, so a restored item is re-anchored at the reading it
    /// was restored at. A ladder therefore restarts after a restart rather than being walked to
    /// the top by a clock that began again at nought.
    pub raised_at: u64,
    /// The continuous reading of the last announcement, when there has been one.
    pub last_notified_at: Option<u64>,
    /// The continuous reading an announcement was deferred at, when one is being held.
    pub deferred_at: Option<u64>,
}

impl Item {
    /// Returns this item as the wire type, for one actor.
    #[must_use]
    pub fn to_wire(&self, acknowledged: bool) -> AttentionItem {
        AttentionItem {
            key: self.key.clone(),
            rule: self.rule,
            level: self.level,
            session_id: Nullable(self.session_id),
            summary: self.summary.clone(),
            trusted: rule(self.rule).trusted,
            routing: self.routing,
            occurrences: U64::new(self.occurrences),
            first_seen_ms: self.first_seen_ms,
            last_seen_ms: self.last_seen_ms,
            notification: self.notification,
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
    /// A range of retained events the host can no longer read.
    GapRecorded {
        /// The range.
        gap: AttentionGap,
    },
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

/// A question that is waiting for an answer, and when its idle interval started.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingInput {
    /// The session it belongs to.
    pub session_id: SessionId,
    /// One line naming what is being asked.
    pub summary: String,
    /// What the wall clock read when the request became pending.
    ///
    /// This is the durable half. The continuous reading beside it is boot-scoped and means
    /// nothing after a restart, so the interval is re-anchored from this one.
    pub pending_since_ms: TimestampMs,
    /// The continuous reading the request became pending at.
    pub pending_since: u64,
    /// Whether the reminder has already been raised for this request.
    pub reminded: bool,
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
}

/// Which rules one retained source carries the conditions of.
///
/// A gap can only cast doubt on what its own source was carrying. A range of terminal side effects
/// that retention took says nothing about whether an approval was answered, and marking every item
/// uncertain over it would make the flag mean nothing.
const fn rules_of(source: AttentionSource) -> &'static [AttentionRule] {
    match source {
        AttentionSource::Receipts => {
            &[AttentionRule::PendingApproval, AttentionRule::CommandFailed]
        }
        AttentionSource::Questions => &[
            AttentionRule::PendingInput,
            AttentionRule::InputIdleReminder,
        ],
        AttentionSource::HostEvents => &[AttentionRule::ApplicationNotice],
        AttentionSource::Semantic => &[
            AttentionRule::ReviewReady,
            AttentionRule::AdapterFailed,
            AttentionRule::HostContactLost,
        ],
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

    /// Sets or clears the quiet-hours window, releasing anything the change lets through.
    pub fn set_quiet_hours(
        &mut self,
        quiet: Option<QuietHours>,
        reading: HostReading,
    ) -> Vec<Outcome> {
        self.quiet = quiet;
        self.release_deferred(reading)
    }

    /// Returns the ranges of retained events the host can no longer read.
    #[must_use]
    pub fn gaps(&self) -> &[AttentionGap] {
        &self.gaps
    }

    /// Returns the highest sequence consumed from one source.
    #[must_use]
    pub fn consumed(&self, source: AttentionSource) -> Option<u64> {
        self.consumed.get(&source).copied()
    }

    /// Returns every item, oldest first.
    pub fn items(&self) -> impl Iterator<Item = &Item> {
        self.items.values()
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

    /// Returns the questions waiting for an answer, with the reading each started at.
    #[must_use]
    pub const fn pending_inputs(&self) -> &BTreeMap<QuestionId, PendingInput> {
        &self.pending_inputs
    }

    /// Returns the inbox one actor sees, oldest first.
    #[must_use]
    pub fn inbox(&self, actor: &ActorId, include_acknowledged: bool) -> Vec<AttentionItem> {
        let mut items: Vec<_> = self
            .items
            .values()
            .filter_map(|item| {
                let acknowledged = self.is_acknowledged(actor, item);
                (include_acknowledged || !acknowledged).then(|| item.to_wire(acknowledged))
            })
            .collect();
        items.sort_by_key(|item| (item.first_seen_ms.get(), item.key.as_str().to_owned()));
        items
    }

    /// Records one actor's acknowledgement of each key it holds an item for.
    ///
    /// Returns the keys that were acknowledged. A key with no item is not acknowledged: there is
    /// nothing to have seen, and recording it would hide the item if the condition recurred.
    pub fn acknowledge(
        &mut self,
        actor: &ActorId,
        keys: &[AttentionKey],
        reading: HostReading,
    ) -> Vec<AttentionKey> {
        let mut acknowledged = Vec::new();
        for key in keys {
            let Some(item) = self.items.get_mut(key) else {
                continue;
            };
            item.attended = true;
            self.acks.entry(actor.clone()).or_default().insert(
                key.clone(),
                ItemAck {
                    occurrences: item.occurrences,
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
    /// Every unresolved item the missing range could have resolved becomes uncertain. It stays in
    /// the inbox: a gap is never an inferred approval or completion.
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
        let doubted: BTreeSet<_> = rules_of(source).iter().copied().collect();
        for item in self.items.values_mut() {
            if doubted.contains(&item.rule) {
                item.uncertain = true;
            }
        }
        // The consumed cursor moves past the range, because the records inside it will never
        // arrive. Leaving it where it was would make the next event look like a second gap.
        let consumed = self.consumed.entry(source).or_insert(0);
        *consumed = (*consumed).max(to.saturating_sub(1));
        vec![Outcome::GapRecorded { gap }]
    }

    /// Applies one typed event.
    ///
    /// An event at or below the cursor already consumed from its source changes nothing, which is
    /// what lets the retained events be replayed as often as a host needs to. An event beyond the
    /// next sequence means the records between were evicted, and the range is recorded as a gap
    /// before the event itself is applied.
    pub fn apply(&mut self, event: &SourceEvent, reading: HostReading) -> Vec<Outcome> {
        let source = event.cursor.source;
        let sequence = event.cursor.sequence;
        let mut outcomes = Vec::new();
        if let Some(consumed) = self.consumed.get(&source).copied() {
            if sequence <= consumed {
                return outcomes;
            }
            if sequence > consumed + 1 {
                outcomes.extend(self.note_gap(source, consumed + 1, sequence));
            }
        }
        self.consumed.insert(source, sequence);
        outcomes.extend(self.decide(event, reading));
        outcomes
    }

    /// Advances every timer to this reading.
    ///
    /// Three things happen here and nowhere else: a held announcement is released when quiet hours
    /// end, an idle reminder is raised when a verified request has waited its interval, and an
    /// unattended item climbs its ladder or is announced again.
    pub fn tick(&mut self, reading: HostReading) -> Vec<Outcome> {
        let mut outcomes = self.release_deferred(reading);
        outcomes.extend(self.fire_idle_reminders(reading));
        outcomes.extend(self.escalate(reading));
        outcomes
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
        if self.items.values().any(|item| item.deferred_at.is_some())
            && let Some(release) = self.quiet_release(reading)
        {
            consider(release);
        }
        for pending in self.pending_inputs.values() {
            if !pending.reminded {
                consider(pending.pending_since.saturating_add(IDLE_REMINDER_MS));
            }
        }
        for item in self.items.values() {
            if item.attended {
                continue;
            }
            let policy = rule(item.rule);
            if let Some(next) = policy.next_step_after(item.steps_taken) {
                consider(item.raised_at.saturating_add(next));
            } else if let (Some(repeat), Some(last)) = (policy.repeat_ms, item.last_notified_at) {
                consider(last.saturating_add(repeat));
            }
        }
        earliest
    }

    /// Restores an engine's state, re-anchoring every interval at this reading.
    pub(crate) fn install(
        &mut self,
        items: Vec<Item>,
        acks: BTreeMap<ActorId, BTreeMap<AttentionKey, ItemAck>>,
        consumed: BTreeMap<AttentionSource, u64>,
        gaps: Vec<AttentionGap>,
        pending: BTreeMap<QuestionId, PendingInput>,
        quiet: Option<QuietHours>,
    ) {
        self.items = items
            .into_iter()
            .map(|item| (item.key.clone(), item))
            .collect();
        self.acks = acks;
        self.consumed = consumed;
        self.gaps = gaps;
        self.pending_inputs = pending;
        self.quiet = quiet;
    }

    /// Re-anchors every continuous reading at `reading`.
    ///
    /// The continuous clock restarts with the machine, so a reading written down in one boot means
    /// nothing in the next. Anchoring a restored item at the reading it was restored at is the one
    /// honest choice: the alternative is a ladder climbed to the top by arithmetic on a clock that
    /// began again at nought.
    pub(crate) fn reanchor(&mut self, reading: HostReading) {
        let since = |recorded: TimestampMs| {
            if reading.wall_proven {
                reading
                    .continuous_ms
                    .saturating_sub(reading.wall_ms.get().saturating_sub(recorded.get()))
            } else {
                reading.continuous_ms
            }
        };
        for item in self.items.values_mut() {
            // How long an item has stood is a fact about the world, so a host that can prove its
            // wall clock keeps the ladder where it was. One that cannot starts the interval again
            // rather than climbing a ladder by arithmetic on a reading nobody can vouch for.
            item.raised_at = since(item.first_seen_ms);
            // The repeat interval starts again either way. A restart is not a reason to announce
            // everything that was outstanding at once.
            item.last_notified_at = item.last_notified_at.map(|_| reading.continuous_ms);
            item.deferred_at = item.deferred_at.map(|_| reading.continuous_ms);
        }
        for pending in self.pending_inputs.values_mut() {
            pending.pending_since = since(pending.pending_since_ms);
        }
    }

    fn decide(&mut self, event: &SourceEvent, reading: HostReading) -> Vec<Outcome> {
        match &event.kind {
            EventKind::ApprovalRequested {
                request_id,
                session_id,
                summary,
            } => self.raise(
                AttentionRule::PendingApproval,
                &request_id.to_string(),
                Some(*session_id),
                summary.clone(),
                AttentionRouting::OwnerPolicy,
                event.at_ms,
                reading,
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
                // How long it had already waited when the host recorded the event, so a request
                // that was pending before the engine saw it is not given a fresh five minutes.
                // The subtraction saturates at this boot's own reading: a machine that was off
                // for part of the wait did not observe it, and counting time it was not running
                // for would fire the reminder before anybody could have answered.
                let waited = event.at_ms.get().saturating_sub(pending_since_ms.get());
                self.pending_inputs.insert(
                    *question_id,
                    PendingInput {
                        session_id: *session_id,
                        summary: summary.clone(),
                        pending_since_ms: *pending_since_ms,
                        pending_since: reading.continuous_ms.saturating_sub(waited),
                        reminded: false,
                    },
                );
                self.raise(
                    AttentionRule::PendingInput,
                    &question_id.to_string(),
                    Some(*session_id),
                    summary.clone(),
                    AttentionRouting::OwnerPolicy,
                    event.at_ms,
                    reading,
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
                    AttentionRule::CommandFailed,
                    &format!("{session_id}|{command}"),
                    Some(*session_id),
                    format!("{command} exited {exit_code}"),
                    AttentionRouting::OwnerPolicy,
                    event.at_ms,
                    reading,
                )
            }
            EventKind::TurnCompleted {
                session_id,
                turn_id,
                summary,
                ..
            } => self.raise(
                AttentionRule::ReviewReady,
                &format!("{session_id}|{turn_id}"),
                Some(*session_id),
                summary.clone(),
                AttentionRouting::OwnerPolicy,
                event.at_ms,
                reading,
            ),
            EventKind::AdapterFailed {
                plugin_id,
                session_id,
                detail,
            } => self.raise(
                AttentionRule::AdapterFailed,
                &plugin_id.to_string(),
                *session_id,
                format!("{plugin_id}: {detail}"),
                AttentionRouting::OwnerPolicy,
                event.at_ms,
                reading,
            ),
            EventKind::AdapterRecovered { plugin_id } => {
                self.resolve(AttentionRule::AdapterFailed, &plugin_id.to_string())
            }
            EventKind::HostContactLost { detail } => self.raise(
                AttentionRule::HostContactLost,
                "host",
                None,
                detail.clone(),
                AttentionRouting::OwnerPolicy,
                event.at_ms,
                reading,
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
                    AttentionRule::ApplicationNotice,
                    &format!("{session_id}|{subject}"),
                    Some(*session_id),
                    summary,
                    routing,
                    event.at_ms,
                    reading,
                )
            }
        }
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "one call site per rule, each naming exactly what that rule keys and shows"
    )]
    fn raise(
        &mut self,
        id: AttentionRule,
        subject: &str,
        session_id: Option<SessionId>,
        summary: String,
        routing: AttentionRouting,
        at_ms: TimestampMs,
        reading: HostReading,
    ) -> Vec<Outcome> {
        let Ok(key) = AttentionKey::of(id, subject) else {
            // A subject this host cannot key on is a subject it cannot de-duplicate or
            // acknowledge, and an item nobody can acknowledge would sit in the inbox for ever.
            return Vec::new();
        };
        let policy = rule(id);
        let mut outcomes = Vec::new();
        if let Some(item) = self.items.get_mut(&key) {
            item.occurrences = item.occurrences.saturating_add(1);
            item.last_seen_ms = at_ms;
            item.summary = summary;
            item.routing = routing;
            let inside = item.last_notified_at.is_some_and(|last| {
                reading.continuous_ms.saturating_sub(last) < policy.dedup_window_ms
            });
            if inside {
                item.notification = NotificationState::Suppressed;
                outcomes.push(Outcome::Repeated {
                    key,
                    occurrences: item.occurrences,
                });
                return outcomes;
            }
            let (level, routing) = (item.level, item.routing);
            let key_for_notice = key.clone();
            outcomes.push(Outcome::Repeated {
                key,
                occurrences: item.occurrences,
            });
            outcomes.extend(self.announce(&key_for_notice, level, routing, reading));
            return outcomes;
        }
        // A fresh item is fresh work. An acknowledgement of an earlier occurrence covered that
        // occurrence, not this one, so it is cleared rather than carried across.
        for acks in self.acks.values_mut() {
            acks.remove(&key);
        }
        let item = Item {
            key: key.clone(),
            rule: id,
            session_id,
            summary,
            routing,
            level: policy.initial,
            steps_taken: 0,
            occurrences: 1,
            first_seen_ms: at_ms,
            last_seen_ms: at_ms,
            notification: NotificationState::Pending,
            uncertain: false,
            attended: false,
            raised_at: reading.continuous_ms,
            last_notified_at: None,
            deferred_at: None,
        };
        let level = item.level;
        self.items.insert(key.clone(), item);
        outcomes.push(Outcome::Raised {
            key: key.clone(),
            rule: id,
            level,
        });
        outcomes.extend(self.announce(&key, level, routing, reading));
        outcomes
    }

    fn announce(
        &mut self,
        key: &AttentionKey,
        level: AttentionLevel,
        routing: AttentionRouting,
        reading: HostReading,
    ) -> Vec<Outcome> {
        let quiet = self.quiet_now(reading);
        let Some(item) = self.items.get_mut(key) else {
            return Vec::new();
        };
        if quiet {
            item.notification = NotificationState::Deferred;
            item.deferred_at = Some(reading.continuous_ms);
            return vec![Outcome::Deferred {
                key: key.clone(),
                level,
            }];
        }
        item.notification = NotificationState::Delivered;
        item.last_notified_at = Some(reading.continuous_ms);
        item.deferred_at = None;
        vec![Outcome::Notified {
            key: key.clone(),
            level,
            routing,
        }]
    }

    fn resolve(&mut self, id: AttentionRule, subject: &str) -> Vec<Outcome> {
        let Ok(key) = AttentionKey::of(id, subject) else {
            return Vec::new();
        };
        if self.items.remove(&key).is_none() {
            return Vec::new();
        }
        for acks in self.acks.values_mut() {
            acks.remove(&key);
        }
        vec![Outcome::Resolved { key }]
    }

    fn release_deferred(&mut self, reading: HostReading) -> Vec<Outcome> {
        if self.quiet_now(reading) {
            return Vec::new();
        }
        let held: Vec<_> = self
            .items
            .values()
            .filter(|item| item.deferred_at.is_some())
            .map(|item| (item.key.clone(), item.level, item.routing))
            .collect();
        held.into_iter()
            .map(|(key, level, routing)| {
                if let Some(item) = self.items.get_mut(&key) {
                    item.notification = NotificationState::Delivered;
                    item.last_notified_at = Some(reading.continuous_ms);
                    item.deferred_at = None;
                }
                Outcome::Released {
                    key,
                    level,
                    routing,
                }
            })
            .collect()
    }

    fn fire_idle_reminders(&mut self, reading: HostReading) -> Vec<Outcome> {
        let due: Vec<_> = self
            .pending_inputs
            .iter()
            .filter(|(_, pending)| {
                !pending.reminded
                    && reading.continuous_ms.saturating_sub(pending.pending_since)
                        >= IDLE_REMINDER_MS
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
                AttentionRule::InputIdleReminder,
                &question_id.to_string(),
                Some(session_id),
                summary,
                AttentionRouting::OwnerPolicy,
                reading.wall_ms,
                reading,
            ));
        }
        outcomes
    }

    fn escalate(&mut self, reading: HostReading) -> Vec<Outcome> {
        let mut outcomes = Vec::new();
        let keys: Vec<_> = self.items.keys().cloned().collect();
        for key in keys {
            let Some(item) = self.items.get_mut(&key) else {
                continue;
            };
            if item.attended {
                continue;
            }
            let policy: &Rule = rule(item.rule);
            let elapsed = reading.continuous_ms.saturating_sub(item.raised_at);
            let (level, taken) = policy.level_after(elapsed);
            let climbed = taken > item.steps_taken;
            if climbed {
                let from = item.level;
                item.level = level;
                item.steps_taken = taken;
                outcomes.push(Outcome::Escalated {
                    key: key.clone(),
                    from,
                    to: level,
                });
            }
            let due = policy.repeat_ms.is_some_and(|repeat| {
                item.last_notified_at
                    .is_some_and(|last| reading.continuous_ms.saturating_sub(last) >= repeat)
            });
            if climbed || due {
                let (level, routing) = (item.level, item.routing);
                outcomes.extend(self.announce(&key, level, routing, reading));
            }
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
