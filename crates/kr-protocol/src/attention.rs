//! Section 25's attention inbox, review acknowledgements and the changed-since-last-visit view.
//!
//! Three separate things travel through this module, and keeping them apart is most of the
//! contract:
//!
//! * **Attention** is what the host decided about typed events it observed. An item names the rule
//!   that raised it, the level it currently stands at and how many times the same condition
//!   recurred. It is a statement about the host's own events, never an authority to act.
//! * **Review** is a person's acknowledgement, bound to the exact version they looked at.
//!   Section 14 makes promotion a separate authorised action: acknowledging a review approves no
//!   command, applies no patch and changes no Git state, and nothing in this module can express
//!   any of those.
//! * **A visit** is where one actor's attention had got to. The changed-since-last-visit view
//!   compares that cursor with the semantic events the host still retains, and states an omitted
//!   range as a gap rather than closing over it.
//!
//! # An application notice is not an approval
//!
//! An `OSC 9`, `OSC 99` or `OSC 777` sequence is an application asking for a notification. Any
//! process writing to the terminal can emit one, so [`AttentionItem::trusted`] is false for every
//! item the [`AttentionRule::ApplicationNotice`] rule raised, and the rule cannot raise any other
//! kind of item. Nothing a notice says makes it a pending approval.
//!
//! # Quiet hours are a UTC window
//!
//! [`QuietHours`] is expressed in minutes of the UTC day so the host needs no time-zone database to
//! decide whether it is inside one. A client converts its own local window before it sets them and
//! may record the zone it converted from in [`QuietHours::zone`], which the host stores and returns
//! unchanged and never interprets. Quiet hours suppress audible delivery; they never drop an item
//! and never remove one from the inbox.

use core::fmt;
use core::str::FromStr;

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Deserializer, Serialize};

use crate::ids::{ActorId, AgentTurnId, ChangeSetId, SessionId};
use crate::recovery::HistoryGap;
use crate::scalars::{Nullable, TimestampMs, U64};

/// How long one rule suppresses a repeat of the same condition, in milliseconds.
///
/// Section 25 fixes it at sixty seconds. A repeat inside the window is counted on the item it
/// belongs to rather than raised again, so nothing is lost and nothing is announced twice.
pub const DEDUPLICATION_WINDOW_MS: u64 = 60_000;

/// How long a verified pending input request waits before the idle reminder fires.
///
/// Section 25 is explicit that the five minutes count from the request becoming pending, not from
/// the last output. A session that prints continuously while a question waits still gets the
/// reminder, and a silent session with nothing pending does not.
pub const IDLE_REMINDER_MS: u64 = 300_000;

/// Minutes in a day, the modulus quiet hours are expressed in.
pub const MINUTES_IN_DAY: u64 = 1_440;

/// Largest number of items one attention read returns.
pub const MAX_ATTENTION_ITEMS: u64 = 200;

/// Largest number of items the host keeps in one session's inbox.
///
/// The inbox is a working set rather than a record: the receipts, the question ledger and the
/// retained output are where the history lives. Past this bound the host drops the least urgent
/// and oldest item and counts it in [`AttentionReadResult::dropped`], because an inbox that grows
/// without limit is one the host cannot write down or serve.
pub const MAX_RETAINED_ATTENTION_ITEMS: u64 = 500;

/// Largest summary one item or change carries, in bytes.
///
/// A summary is display text taken from a command line or an application's own notification, and
/// neither is bounded at its source. It is clipped on a character boundary rather than refused:
/// the item matters more than the whole of its text.
pub const MAX_ATTENTION_SUMMARY_LEN: usize = 512;

/// Largest number of model summaries the host keeps for one session.
pub const MAX_RETAINED_SUMMARIES: usize = 32;

/// Largest number of review subjects one review read returns.
///
/// The host keeps every subject it is told about: one nobody has read is outstanding review work,
/// and one somebody has read is that actor's own record of reading it, so neither is a working set
/// a retention bound may take. This bounds the answer instead, and a caller continues after the
/// last subject it was given.
pub const MAX_REVIEW_SUBJECTS: u64 = 200;

/// Largest number of semantic changes one changed-since-last-visit read returns.
pub const MAX_VISIT_CHANGES: u64 = 500;

/// Largest number of log views one actor may retain for a session.
pub const MAX_RETAINED_LOG_VIEWS: u64 = 32;

/// Largest log-view identifier, in bytes.
pub const MAX_LOG_VIEW_ID_LEN: usize = 128;

/// Largest filter one log view carries, in bytes.
///
/// A filter is the client's own form and the host never reads it, but it does write it down and
/// give it back, so its size is the host's business. A filter past this is refused rather than
/// clipped: a clipped filter means something else.
pub const MAX_LOG_VIEW_FILTER_LEN: usize = 4_096;

/// Largest model name one summary names, in bytes.
pub const MAX_SUMMARY_MODEL_LEN: usize = 128;

/// Largest number of actors one session's feature store keeps.
pub const MAX_RETAINED_ACTORS: usize = 256;

/// Largest number of pending input requests one session's feature store keeps.
pub const MAX_RETAINED_PENDING_INPUTS: usize = 500;

macro_rules! wire_enum {
    (
        $(#[$meta:meta])*
        $name:ident { $($variant:ident => $wire:literal, $doc:literal;)+ }
    ) => {
        $(#[$meta])*
        #[derive(
            Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
            JsonSchema,
        )]
        pub enum $name {
            $(
                #[doc = $doc]
                #[serde(rename = $wire)]
                $variant,
            )+
        }

        impl $name {
            /// Every value, in declaration order.
            pub const ALL: &'static [Self] = &[$(Self::$variant,)+];

            /// Returns the stable wire string.
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $wire,)+
                }
            }

            /// Returns the value for a wire string.
            #[must_use]
            pub fn from_wire(value: &str) -> Option<Self> {
                match value {
                    $($wire => Some(Self::$variant),)+
                    _ => None,
                }
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.as_str())
            }
        }
    };
}

wire_enum! {
    /// One rule of section 25's attention rule set.
    ///
    /// The identifiers are stable: they are what an acknowledgement, a stored item and a client
    /// preference name, so they outlive any wording change in the text a rule produces.
    AttentionRule {
        PendingApproval => "attention.pending_approval",
            "An upstream agent is waiting for an approval decision.";
        PendingInput => "attention.pending_input",
            "A verified source is waiting for the person to answer a question.";
        InputIdleReminder => "attention.input_idle_reminder",
            "A verified pending input request has waited the idle interval.";
        CommandFailed => "attention.command_failed",
            "A command completed with a nonzero status.";
        ReviewReady => "attention.review_ready",
            "An agent turn completed and is waiting to be reviewed.";
        AdapterFailed => "attention.adapter_failed",
            "An adapter failed and the capability it provided is unavailable.";
        HostContactLost => "attention.host_contact_lost",
            "Contact with the host was lost.";
        ApplicationNotice => "attention.application_notice",
            "An application asked for a notification. Untrusted, and never an approval.";
    }
}

wire_enum! {
    /// How much attention an item is asking for.
    AttentionLevel {
        Informational => "informational", "Worth seeing when the person looks.";
        Notable => "notable", "Worth telling the person about.";
        Urgent => "urgent", "Worth interrupting for, subject to quiet hours.";
    }
}

wire_enum! {
    /// Where the host sent an item's notification.
    ///
    /// Section 8 gives a terminal side effect one destination, the attachment holding the input
    /// lease. With no lease holder there is nobody to send it to, so section 25 routes it through
    /// the owner's configured notification policy and keeps it in Attention either way.
    AttentionRouting {
        LeaseHolder => "lease_holder", "The attachment that held the input lease.";
        OwnerPolicy => "owner_policy", "The owner's configured notification policy.";
    }
}

wire_enum! {
    /// What became of an item's notification.
    NotificationState {
        Pending => "pending", "Not yet decided.";
        Delivered => "delivered", "Sent to the destination.";
        Deferred => "deferred", "Held by quiet hours, to be released when they end.";
        Suppressed => "suppressed", "Inside the rule's de-duplication window.";
    }
}

wire_enum! {
    /// Which retained source one consumed cursor or one gap belongs to.
    AttentionSource {
        Receipts => "receipts", "The worker's receipt journal.";
        Questions => "questions", "The question ledger.";
        HostEvents => "host_events", "Terminal side effects with no attachment to go to.";
        Semantic => "semantic", "The session's own semantic events.";
    }
}

wire_enum! {
    /// What one semantic change was.
    SemanticChangeKind {
        TurnCompleted => "turn_completed", "An agent turn finished.";
        CommandCompleted => "command_completed", "A command finished.";
        QuestionAnswered => "question_answered", "A question was answered.";
        ChangeSetCaptured => "change_set_captured", "A change set was captured.";
        AdapterState => "adapter_state", "An adapter failed or recovered.";
    }
}

/// An attention item's stable key: an attention rule and the subject it was raised about.
///
/// The key is derived rather than allocated, so rebuilding the inbox from the retained events
/// produces the same keys it had before. An identifier minted at the moment an item is raised
/// would give a replay new keys and turn idempotent reconstruction into a second inbox.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct AttentionKey(String);

/// Largest attention key, in bytes.
pub const MAX_ATTENTION_KEY_LEN: usize = 256;

/// A key that is empty, too long or carries a character a key may not carry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttentionKeyError;

impl fmt::Display for AttentionKeyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an attention key is 1 to 256 bytes with no control character")
    }
}

impl std::error::Error for AttentionKeyError {}

impl AttentionKey {
    /// Builds the key for one rule and one subject.
    ///
    /// # Errors
    ///
    /// Returns [`AttentionKeyError`] when the subject is empty, contains a control character or
    /// takes the key past [`MAX_ATTENTION_KEY_LEN`] bytes.
    pub fn of(rule: AttentionRule, subject: &str) -> Result<Self, AttentionKeyError> {
        Self::new(format!("{}|{subject}", rule.as_str()))
    }

    /// Wraps existing key text.
    ///
    /// # Errors
    ///
    /// Returns [`AttentionKeyError`] when the text is empty, longer than
    /// [`MAX_ATTENTION_KEY_LEN`] bytes or contains a control character.
    pub fn new(value: impl Into<String>) -> Result<Self, AttentionKeyError> {
        let value = value.into();
        if value.is_empty() || value.len() > MAX_ATTENTION_KEY_LEN {
            return Err(AttentionKeyError);
        }
        if value.chars().any(char::is_control) {
            return Err(AttentionKeyError);
        }
        Ok(Self(value))
    }

    /// Returns the key text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AttentionKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for AttentionKey {
    type Err = AttentionKeyError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl<'de> Deserialize<'de> for AttentionKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::new(text).map_err(serde::de::Error::custom)
    }
}

impl JsonSchema for AttentionKey {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "AttentionKey".into()
    }

    fn schema_id() -> std::borrow::Cow<'static, str> {
        "kalareach::AttentionKey".into()
    }

    fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "string",
            "minLength": 1,
            "maxLength": MAX_ATTENTION_KEY_LEN,
            "description": "One attention rule and the subject it was raised about."
        })
    }
}

/// One item in the attention inbox.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AttentionItem {
    /// The rule and subject this item stands for.
    pub key: AttentionKey,
    /// The rule that raised it.
    pub rule: AttentionRule,
    /// The retained source the condition was observed in.
    ///
    /// It is what a gap is weighed against: a range that retention took from this source is a
    /// range that could have resolved this item, and a range taken from another source is not.
    pub source: AttentionSource,
    /// What it is asking for now, after any escalation.
    pub level: AttentionLevel,
    /// The session it belongs to, when it belongs to one.
    pub session_id: Nullable<SessionId>,
    /// One line naming the subject, when this caller may be served it.
    ///
    /// Null means the host withheld it. An item's text comes from retained content - a question's
    /// wording, a command line, what an application printed - and a caller whose grant the host
    /// cannot narrow that content to is served the item without it rather than more than its grant
    /// allows. What is left says which rule, at what level, how often and when, which is the
    /// host's own record rather than the session's.
    pub summary: Nullable<String>,
    /// Whether the host itself observed the condition.
    ///
    /// False for an application notice, which any process writing to the terminal can emit. A
    /// client must not present an untrusted item as a host decision, and nothing untrusted is ever
    /// a pending approval.
    pub trusted: bool,
    /// Where the notification went.
    pub routing: AttentionRouting,
    /// How many times the condition occurred, including the occurrences de-duplication suppressed.
    pub occurrences: U64,
    /// When the condition was first observed.
    pub first_seen_ms: TimestampMs,
    /// When it was last observed.
    pub last_seen_ms: TimestampMs,
    /// What became of the notification.
    pub notification: NotificationState,
    /// Whether a decided announcement is still waiting to be taken by a delivery consumer.
    ///
    /// The host writes a decision down before it hands it over, and keeps it written down until
    /// somebody takes it, so a host that decided an announcement and then died re-offers it rather
    /// than losing it. What becomes of the announcement afterwards belongs to the delivery
    /// journal, not to the feature store.
    pub awaiting_delivery: bool,
    /// Whether this actor has acknowledged it.
    pub acknowledged: bool,
    /// Whether a gap in the retained events covers this item's subject.
    ///
    /// A gap is not a resolution. An item whose resolving event may have been evicted stays in the
    /// inbox and says that the host cannot tell, which is section 24's rule that a history gap is
    /// never an inferred approval or completion.
    pub uncertain: bool,
}

/// A range of retained source events the host can no longer read.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AttentionGap {
    /// Which source the range belongs to.
    pub source: AttentionSource,
    /// The first sequence that is missing.
    pub from_sequence: U64,
    /// The first sequence that is present again.
    pub to_sequence: U64,
}

/// The window in which audible delivery is held back.
///
/// Both bounds are minutes of the UTC day, and a window whose end is at or before its start wraps
/// midnight. A window whose bounds are equal is a whole day of quiet hours, which is a thing a
/// person can choose; a client that means "never" clears the configuration instead.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QuietHours {
    /// The first minute of the UTC day the window covers.
    pub start_minute: U64,
    /// The first minute of the UTC day after the window.
    pub end_minute: U64,
    /// The time zone the client converted from, recorded for the client's own use.
    ///
    /// The host stores it and gives it back. It never interprets it, which is why the window
    /// itself is in UTC: deciding a local window would need a zone database the host does not
    /// carry, and guessing one would suppress a notification at the wrong hour.
    pub zone: Nullable<String>,
}

impl QuietHours {
    /// Returns true when `minute_of_day` is inside the window.
    ///
    /// # Panics
    ///
    /// Never. Every value is reduced modulo [`MINUTES_IN_DAY`] first, so a window a client built
    /// from a time zone offset cannot address a minute outside the day.
    #[must_use]
    pub fn covers(&self, minute_of_day: u64) -> bool {
        let start = self.start_minute.get() % MINUTES_IN_DAY;
        let end = self.end_minute.get() % MINUTES_IN_DAY;
        let minute = minute_of_day % MINUTES_IN_DAY;
        if start == end {
            return true;
        }
        if start < end {
            minute >= start && minute < end
        } else {
            minute >= start || minute < end
        }
    }

    /// Returns how many minutes remain until the window ends, from `minute_of_day` inside it.
    ///
    /// A window that covers the whole day never ends, and the answer is [`MINUTES_IN_DAY`]: the
    /// caller wakes a day later and finds the window still standing, which is the honest answer
    /// for a configuration that says every hour is quiet.
    #[must_use]
    pub fn minutes_until_end(&self, minute_of_day: u64) -> u64 {
        let end = self.end_minute.get() % MINUTES_IN_DAY;
        let minute = minute_of_day % MINUTES_IN_DAY;
        if self.start_minute.get() % MINUTES_IN_DAY == end {
            return MINUTES_IN_DAY;
        }
        if end > minute {
            end - minute
        } else {
            MINUTES_IN_DAY - minute + end
        }
    }
}

/// What a review acknowledgement is attached to.
///
/// A subject names what is being reviewed and nothing about which version of it. The version
/// travels beside the subject, in [`ReviewState::current_version`] and
/// [`ReviewAcknowledgeParams::version`], because a subject keeps one identity while its versions
/// move: that is what lets a new change reopen review work an older version had closed.
///
/// The two are told apart by which variant is present rather than by a tag beside them. An
/// internally tagged union buffers what it decodes before it knows the variant, and buffering is
/// where a format's own representation of an identifier is lost: the canonical wire form encodes
/// one as sixteen bytes, and a buffered decode would ask for a string and refuse it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ReviewSubject {
    /// One completed agent turn.
    CompletedTurn {
        /// The session the turn belongs to.
        session_id: SessionId,
        /// The turn.
        turn_id: AgentTurnId,
    },
    /// One captured change set.
    ChangeSet {
        /// The session the change set was captured in.
        session_id: SessionId,
        /// The change set.
        change_set_id: ChangeSetId,
    },
}

/// The review state of one subject, for one actor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReviewState {
    /// What is being reviewed, at the version the host currently holds.
    pub subject: ReviewSubject,
    /// The current version of that subject.
    pub current_version: U64,
    /// The version this actor acknowledged, when it has acknowledged one.
    pub acknowledged_version: Nullable<U64>,
    /// When this actor acknowledged it.
    pub acknowledged_at_ms: Nullable<TimestampMs>,
    /// Whether review work is outstanding for this actor.
    ///
    /// True when nothing has been acknowledged, and true again after a new version appears: a new
    /// change is new review work, and an acknowledgement of an earlier version does not cover it.
    pub outstanding: bool,
}

/// One log view's retained position and filter.
///
/// Section 25 keeps a log view's source offsets and filtering state across a reconnect, a switch
/// to another view and a retention eviction. The offset is the source's own cursor, so it survives
/// a client that discards everything it was holding.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LogViewState {
    /// The view, as the client names it.
    pub view_id: String,
    /// The source offset the view was reading at.
    pub source_offset: U64,
    /// The filter the view had applied, in the client's own form.
    pub filter: String,
}

/// One retained log view, with the gap retention left in it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RetainedLogView {
    /// The view, at the offset it can be served from now.
    pub view: LogViewState,
    /// The offset the view was left at, when retention has moved past it.
    ///
    /// Present exactly when [`RetainedLogView::gap`] is: the view keeps saying where it was even
    /// though it can no longer be served from there.
    pub requested_offset: Nullable<U64>,
    /// The range retention evicted, when the retained offset is no longer readable.
    pub gap: Nullable<HistoryGap>,
}

/// One semantic change in the changed-since-last-visit view.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SemanticChange {
    /// The cursor this change sits at.
    pub cursor: U64,
    /// What it was.
    pub kind: SemanticChangeKind,
    /// The session it belongs to.
    pub session_id: SessionId,
    /// One line naming it, when this caller may be served it.
    ///
    /// Null means the host withheld it, for the same reason an attention item's text is withheld.
    pub summary: Nullable<String>,
    /// When the host recorded it.
    pub at_ms: TimestampMs,
}

/// A model's summary of an interval, carried beside the authoritative events.
///
/// Section 25 requires a summary to name its source interval and stay separate from the events. It
/// is never merged into [`VisitChangedResult::changes`] and never stands in for one: a client that
/// ignores it loses nothing authoritative.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChangeSummary {
    /// The summary text.
    pub text: String,
    /// The first cursor the summary was written from.
    pub from_cursor: U64,
    /// The first cursor after the interval the summary was written from.
    pub to_cursor: U64,
    /// When the interval started.
    pub from_ms: TimestampMs,
    /// When it ended.
    pub to_ms: TimestampMs,
    /// The model that produced it, as the host recorded it.
    pub model: String,
}

/// Parameters of `attention.read`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AttentionReadParams {
    /// The session whose inbox is read.
    pub session_id: SessionId,
    /// Whether items this actor has already acknowledged are included.
    pub include_acknowledged: bool,
    /// The largest page the caller will accept, bounded by [`MAX_ATTENTION_ITEMS`].
    pub max_items: U64,
    /// The key to continue after, or null to start at the oldest item.
    pub after: Nullable<AttentionKey>,
}

/// The result of `attention.read`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AttentionReadResult {
    /// The items, oldest first.
    pub items: Vec<AttentionItem>,
    /// Whether more items remain after the last one in this page.
    pub more: bool,
    /// How many items the host has dropped to stay inside its own bound.
    ///
    /// Nought is the ordinary answer. Anything else says the inbox reached
    /// [`MAX_RETAINED_ATTENTION_ITEMS`] and the host let go of its least urgent and oldest items,
    /// which a client shows rather than hides.
    pub dropped: U64,
    /// The ranges of retained events the host can no longer read.
    pub gaps: Vec<AttentionGap>,
    /// The configured quiet hours, when there are any.
    pub quiet_hours: Nullable<QuietHours>,
    /// Whether the host is inside its quiet hours now.
    pub quiet_now: bool,
    /// Whether this host can prove what its wall clock reads.
    ///
    /// Quiet hours are a wall-clock window, so a host that cannot prove its clock cannot prove it
    /// is inside one. It delivers rather than suppresses, and says so here, because a suppression
    /// decided on an unprovable clock withholds a notification nobody asked to withhold.
    pub quiet_hours_provable: bool,
}

/// Parameters of `attention.acknowledge`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AttentionAcknowledgeParams {
    /// The session whose items are acknowledged.
    pub session_id: SessionId,
    /// The items, by key.
    pub keys: Vec<AttentionKey>,
}

/// The result of `attention.acknowledge`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AttentionAcknowledgeResult {
    /// The actor the acknowledgement belongs to.
    pub actor_id: ActorId,
    /// The keys that were acknowledged, in the order they were given.
    pub acknowledged: Vec<AttentionKey>,
    /// This actor's acknowledgement revision after the change.
    pub revision: U64,
}

/// Parameters of `attention.quiet_hours`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AttentionQuietHoursParams {
    /// The session whose quiet hours are set.
    pub session_id: SessionId,
    /// The window, or null to clear it.
    pub quiet_hours: Nullable<QuietHours>,
}

/// The result of `attention.quiet_hours`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AttentionQuietHoursResult {
    /// The window now in force, or null when there is none.
    pub quiet_hours: Nullable<QuietHours>,
    /// Whether the host is inside it now.
    pub quiet_now: bool,
    /// Whether this host can prove what its wall clock reads.
    pub quiet_hours_provable: bool,
}

/// Parameters of `review.read`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReviewReadParams {
    /// The session the review state belongs to.
    pub session_id: SessionId,
    /// One subject, or null for a page of every subject this session knows about.
    pub subject: Nullable<ReviewSubject>,
    /// The largest page the caller will accept, bounded by [`MAX_REVIEW_SUBJECTS`].
    ///
    /// It is ignored when `subject` names one subject, because that answer is one row.
    pub max_reviews: U64,
    /// The subject to continue after, or null to start at the oldest.
    ///
    /// A subject this session no longer holds is refused rather than restarting the page, because
    /// a page that silently began again would read as the end of the list.
    pub after: Nullable<ReviewSubject>,
}

/// The result of `review.read`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReviewReadResult {
    /// The actor this state belongs to.
    pub actor_id: ActorId,
    /// The review state of each subject, oldest first.
    pub reviews: Vec<ReviewState>,
    /// Whether more subjects remain after the last one in this page.
    pub more: bool,
}

/// Parameters of `review.acknowledge`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReviewAcknowledgeParams {
    /// The session the subject belongs to.
    pub session_id: SessionId,
    /// What is being acknowledged.
    pub subject: ReviewSubject,
    /// The exact version that was read.
    ///
    /// A version the host does not hold is refused. Acknowledging a version nobody produced would
    /// close review work that was never presented.
    pub version: U64,
}

/// The result of `review.acknowledge`.
///
/// It reports review state and nothing else. Acknowledging approves no command, applies no patch
/// and changes no Git state; section 14 makes promotion a separate authorised action, and this
/// group has no method that performs one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReviewAcknowledgeResult {
    /// The actor the acknowledgement belongs to.
    pub actor_id: ActorId,
    /// The state of the subject after the acknowledgement.
    pub review: ReviewState,
    /// This actor's acknowledgement revision after the change.
    pub revision: U64,
}

/// Parameters of `visit.acknowledge`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VisitAcknowledgeParams {
    /// The session being visited.
    pub session_id: SessionId,
    /// The semantic cursor this actor has seen up to.
    pub acknowledged_cursor: U64,
    /// The log views this actor had open, with their offsets and filters.
    pub views: Vec<LogViewState>,
}

/// The result of `visit.acknowledge`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VisitAcknowledgeResult {
    /// The actor the visit belongs to.
    pub actor_id: ActorId,
    /// The cursor now recorded for it.
    ///
    /// It never goes backwards. A client that acknowledges an older cursor than the one the host
    /// holds keeps the host's, because a visit records how far somebody has got.
    pub acknowledged_cursor: U64,
    /// The views the host retained, after the per-session bound.
    pub views: Vec<LogViewState>,
    /// This actor's acknowledgement revision after the change.
    pub revision: U64,
}

/// Parameters of `visit.changed`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VisitChangedParams {
    /// The session to compare.
    pub session_id: SessionId,
    /// The largest number of changes the caller will accept, bounded by [`MAX_VISIT_CHANGES`].
    pub max_changes: U64,
}

/// The result of `visit.changed`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct VisitChangedResult {
    /// The actor this view belongs to.
    pub actor_id: ActorId,
    /// The cursor this actor last acknowledged.
    pub from_cursor: U64,
    /// The cursor to acknowledge once this view has been read.
    pub to_cursor: U64,
    /// The semantic changes after the acknowledged cursor, oldest first.
    pub changes: Vec<SemanticChange>,
    /// The ranges retention evicted before this view could show them.
    ///
    /// An omitted range is stated. The view never presents a shorter list as if it were the whole
    /// of what happened.
    pub omitted: Vec<AttentionGap>,
    /// Whether more changes remain past [`VisitChangedResult::to_cursor`].
    pub more: bool,
    /// The summary of this interval, when one was requested and produced.
    pub summary: Nullable<ChangeSummary>,
    /// The log views this actor retained, with any gap retention left in them.
    pub views: Vec<RetainedLogView>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_rule_has_a_stable_identifier_that_round_trips() {
        for rule in AttentionRule::ALL {
            assert_eq!(AttentionRule::from_wire(rule.as_str()), Some(*rule));
            assert!(rule.as_str().starts_with("attention."));
        }
        assert_eq!(AttentionRule::ALL.len(), 8);
    }

    #[test]
    fn a_key_is_built_from_the_rule_and_its_subject() {
        let key = AttentionKey::of(AttentionRule::PendingApproval, "request-7")
            .expect("a well-formed key");
        assert_eq!(key.as_str(), "attention.pending_approval|request-7");
        assert_eq!(
            AttentionKey::of(AttentionRule::PendingApproval, "request-7"),
            Ok(key)
        );
    }

    #[test]
    fn a_key_refuses_a_control_character_and_an_over_long_subject() {
        assert_eq!(
            AttentionKey::of(AttentionRule::CommandFailed, "one\nline"),
            Err(AttentionKeyError)
        );
        let long = "s".repeat(MAX_ATTENTION_KEY_LEN);
        assert_eq!(
            AttentionKey::of(AttentionRule::CommandFailed, &long),
            Err(AttentionKeyError)
        );
    }

    fn window(start: u64, end: u64) -> QuietHours {
        QuietHours {
            start_minute: U64::new(start),
            end_minute: U64::new(end),
            zone: Nullable::null(),
        }
    }

    #[test]
    fn a_window_inside_one_day_covers_its_own_minutes_only() {
        let quiet = window(60, 120);
        assert!(!quiet.covers(59));
        assert!(quiet.covers(60));
        assert!(quiet.covers(119));
        assert!(!quiet.covers(120));
        assert_eq!(quiet.minutes_until_end(60), 60);
    }

    #[test]
    fn a_window_that_wraps_midnight_covers_both_sides_of_it() {
        let quiet = window(1_380, 420);
        assert!(quiet.covers(1_380));
        assert!(quiet.covers(0));
        assert!(quiet.covers(419));
        assert!(!quiet.covers(420));
        assert!(!quiet.covers(1_379));
        assert_eq!(quiet.minutes_until_end(1_380), 480);
        assert_eq!(quiet.minutes_until_end(400), 20);
    }

    #[test]
    fn a_window_whose_bounds_are_equal_is_the_whole_day() {
        let quiet = window(300, 300);
        assert!(quiet.covers(0));
        assert!(quiet.covers(299));
        assert!(quiet.covers(1_439));
        assert_eq!(quiet.minutes_until_end(299), MINUTES_IN_DAY);
    }

    #[test]
    fn the_review_subject_round_trips_through_its_json_form() {
        let subject = ReviewSubject::ChangeSet {
            session_id: SessionId::new(crate::scalars::Uuid::from_bytes([2; 16])),
            change_set_id: ChangeSetId::new(crate::scalars::Uuid::from_bytes([7; 16])),
        };
        let json = serde_json::to_string(&subject).expect("a review subject encodes");
        assert!(json.contains("\"change_set\""));
        let back: ReviewSubject = serde_json::from_str(&json).expect("a review subject decodes");
        assert_eq!(back, subject);
    }

    #[test]
    fn an_unknown_field_is_refused_rather_than_ignored() {
        let json = r#"{"view_id":"log","source_offset":"4","filter":"","extra":1}"#;
        assert!(serde_json::from_str::<LogViewState>(json).is_err());
    }
}
