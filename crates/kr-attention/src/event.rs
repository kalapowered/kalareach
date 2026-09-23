//! The typed events the attention engine runs from.
//!
//! Section 25 says the engine runs locally from typed events. These are those events: one enum,
//! one variant per thing a host observes, each carrying the identity the rule it feeds keys on.
//! Nothing here is a wire type, because nothing outside the host produces one. A client cannot
//! post an attention event, and a terminal cannot print one.
//!
//! # Cursors, and what a gap in them means
//!
//! Every event arrives with the cursor of the retained record it came from. Two things rest on
//! that. The first is idempotence: replaying a record the engine has already consumed changes
//! nothing, which is what makes reconstruction from the retained events safe to run twice. The
//! second is honesty about what is missing. A jump in the sequence means the records between the
//! two were evicted, and section 24 is explicit that a gap is not an inferred approval or
//! completion: the engine records the gap, marks what the missing range could have resolved as
//! uncertain, and leaves it in the inbox.
//!
//! # Whose source
//!
//! The store is the environment's, and every session keeps retained sources of its own with its
//! own numbering: sequence nine of one session's question ledger says nothing about the same
//! number in another's. So a cursor names its [`Origin`] - a session, or the environment itself -
//! beside the source and the sequence, and everything consumed, and every gap, is kept per origin.
//!
//! # A source whose numbering has holes by design
//!
//! Most sources number every record, so a jump is a range retention took. The workflow journal's
//! outbox does not: it interleaves the attention records with the run events other consumers read,
//! and the attention store reads only its own types. A jump there is the other records, and the
//! only gap such a source has is the one its consumer reports.

use kr_protocol::attention::{AttentionAutomationSubject, AttentionSource};
use kr_protocol::ids::{
    AgentTurnId, ApprovalRequestId, ChangeSetId, GrantId, PluginId, QuestionId, SessionId,
};
use kr_protocol::scalars::TimestampMs;

use crate::time::Anchor;

/// Whose retained source a record came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Origin {
    /// The environment itself: its workflow journal and anything else no session owns.
    Environment,
    /// One session's own retained sources.
    Session(SessionId),
}

impl Origin {
    /// Returns the session this origin is, when it is one.
    #[must_use]
    pub const fn session(&self) -> Option<SessionId> {
        match self {
            Self::Environment => None,
            Self::Session(session_id) => Some(*session_id),
        }
    }

    /// Returns the origin a session, or its absence, names.
    #[must_use]
    pub const fn of(session_id: Option<SessionId>) -> Self {
        match session_id {
            Some(session_id) => Self::Session(session_id),
            None => Self::Environment,
        }
    }
}

/// Whether a jump in a source's sequence is a range retention took.
///
/// It is, for every source that numbers each of its records. It is not for the workflow journal's
/// outbox, which numbers every event it holds and hands the attention store only its own types.
#[must_use]
pub const fn numbers_every_record(source: AttentionSource) -> bool {
    !matches!(source, AttentionSource::Automation)
}

/// Where one event sat in its retained source.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EventCursor {
    /// Whose source it is.
    pub origin: Origin,
    /// The retained source.
    pub source: AttentionSource,
    /// The sequence within it. Sequences start at one; nought is never a record.
    pub sequence: u64,
}

impl EventCursor {
    /// Builds a cursor into one of the environment's own sources.
    #[must_use]
    pub const fn new(source: AttentionSource, sequence: u64) -> Self {
        Self {
            origin: Origin::Environment,
            source,
            sequence,
        }
    }

    /// Builds a cursor into one session's own source.
    #[must_use]
    pub const fn in_session(session_id: SessionId, source: AttentionSource, sequence: u64) -> Self {
        Self {
            origin: Origin::Session(session_id),
            source,
            sequence,
        }
    }
}

/// The number of bytes in a [`Fingerprint`].
pub const FINGERPRINT_BYTES: usize = 32;

/// A keyed digest of a record's subject, made by the record's owner.
///
/// Some rules key on content: two notices without an identifier are the same condition when they
/// say the same thing. The text itself cannot be what the key is derived from, because a record's
/// text is not always served - privacy mode withholds it - and an item's identity must not change
/// with whether it was. So the session that holds the record digests its subject under a secret of
/// its own and hands over the digest whether or not the text comes with it. The store derives the
/// item's key from the digest under its own secret, so neither step lets a reader try guesses.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Fingerprint([u8; FINGERPRINT_BYTES]);

impl Fingerprint {
    /// Builds a fingerprint from its bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; FINGERPRINT_BYTES]) -> Self {
        Self(bytes)
    }

    /// Returns its bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; FINGERPRINT_BYTES] {
        &self.0
    }

    /// Returns it as lowercase hexadecimal.
    #[must_use]
    pub fn to_hex(&self) -> String {
        use core::fmt::Write as _;
        let mut text = String::with_capacity(FINGERPRINT_BYTES * 2);
        for byte in &self.0 {
            write!(text, "{byte:02x}").expect("writing to a string cannot fail");
        }
        text
    }

    /// Reads a fingerprint back from [`Fingerprint::to_hex`]'s form.
    #[must_use]
    pub fn from_hex(text: &str) -> Option<Self> {
        if text.len() != FINGERPRINT_BYTES * 2 {
            return None;
        }
        let mut bytes = [0u8; FINGERPRINT_BYTES];
        for (index, byte) in bytes.iter_mut().enumerate() {
            let at = index * 2;
            *byte = u8::from_str_radix(text.get(at..at + 2)?, 16).ok()?;
        }
        Some(Self(bytes))
    }
}

impl core::fmt::Debug for Fingerprint {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("Fingerprint(..)")
    }
}

/// What an application asked for with an `OSC 9`, `OSC 99` or `OSC 777` sequence.
///
/// It is a notice, not a fact. Any process writing to the terminal can emit one, including one the
/// person did not start, so nothing here is evidence of anything and none of it can become an
/// approval resource.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApplicationNotice {
    /// The application's own identifier for the notification, when it gave one.
    ///
    /// It groups the parts of one notification, so it is what the engine keys on when present. A
    /// notice with no identifier is keyed on its own text instead.
    pub id: Option<String>,
    /// The title, when the sequence carried one.
    pub title: Option<String>,
    /// The body.
    pub body: String,
    /// Whether an attachment held the input lease when the sequence arrived.
    ///
    /// Section 8 sends a side effect to the lease holder. With no lease holder there is nobody to
    /// send it to, and section 25 routes it through the owner's configured notification policy and
    /// retains it in Attention.
    pub lease_held: bool,
    /// The record owner's keyed digest of what the notice says, when it has the record's content.
    ///
    /// A notice with an identifier is keyed on that. One without is keyed on this, so two notices
    /// that say the same thing are one condition whether or not their text was served. A notice
    /// with neither is keyed on the record it came from.
    pub fingerprint: Option<Fingerprint>,
}

/// What one typed event says happened.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EventKind {
    /// A retained record the host consumed that no rule covers.
    ///
    /// The retained sources carry more than the attention engine has rules for. Without a way to
    /// say "I read this and it was nothing", the cursor would stay behind and the next record the
    /// engine does have a rule for would look like a gap. This is that way.
    Observed,
    /// An upstream agent asked for an approval decision.
    ApprovalRequested {
        /// The request.
        request_id: ApprovalRequestId,
        /// The session it belongs to.
        session_id: SessionId,
        /// One line naming what is being approved.
        summary: String,
    },
    /// An approval request was answered, withdrawn or expired.
    ApprovalResolved {
        /// The request.
        request_id: ApprovalRequestId,
        /// The session it belonged to.
        ///
        /// An upstream request identifier is the connector's own and is not unique across
        /// sessions, so the request is named by both.
        session_id: SessionId,
    },
    /// A question became pending.
    QuestionPending {
        /// The question.
        question_id: QuestionId,
        /// The session it belongs to.
        session_id: SessionId,
        /// Whether the worker admitted the source that created it.
        ///
        /// Section 25's idle reminder counts from a *verified* pending request. An unverified
        /// source never becomes attention work at all: it is a claim, and a claim that waits five
        /// minutes is still a claim.
        verified: bool,
        /// When it became pending, which is where the idle interval counts from.
        pending_since_ms: TimestampMs,
        /// Where [`EventKind::QuestionPending::pending_since_ms`] sits on the continuous clock.
        ///
        /// It is asked about separately from [`SourceEvent::at_anchor`] because it is a different
        /// moment: a request can become pending long before the record of it is written. Without
        /// it the five-minute reminder counts from where the engine read the record, which is
        /// late; with one from the boot the engine is reading in, from where the request actually
        /// started waiting. An anchor from any other boot measures nothing, like any other.
        pending_since_anchor: Option<Anchor>,
        /// One line naming what is being asked.
        summary: String,
    },
    /// A question reached a terminal state.
    QuestionResolved {
        /// The question.
        question_id: QuestionId,
        /// The session it belonged to.
        ///
        /// It travels with the resolution rather than being looked up, because the reminder
        /// record the engine keeps for a request is a working set with a bound of its own. A
        /// question answered after its record left it is still a change since somebody's last
        /// visit, and only the event still knows whose session it was.
        session_id: SessionId,
        /// Whether a person answered it, as against it being cancelled or expiring.
        answered: bool,
    },
    /// A command finished.
    CommandCompleted {
        /// The session it ran in.
        session_id: SessionId,
        /// The command, as the shell adapter reported it.
        command: String,
        /// Its exit status. Nought raises nothing.
        exit_code: i32,
    },
    /// An agent turn finished and is waiting to be reviewed.
    TurnCompleted {
        /// The session.
        session_id: SessionId,
        /// The turn.
        turn_id: AgentTurnId,
        /// The version of the turn's result that is waiting to be reviewed.
        ///
        /// A turn that runs again produces a later version, and section 14 binds an
        /// acknowledgement to the version it was made against, so a later version is new review
        /// work rather than work an earlier acknowledgement covered.
        version: u64,
        /// The change set the turn captured, and that change set's own version.
        ///
        /// A change set has a version of its own: capturing the same workspace twice in one turn
        /// produces two versions, and a change set captured outside a turn has no turn version to
        /// borrow. Carrying both is what lets a review acknowledgement bind the version it was
        /// actually made against.
        change_set: Option<(ChangeSetId, u64)>,
        /// One line naming what the turn did.
        summary: String,
    },
    /// A change set was captured outside a turn.
    ChangeSetCaptured {
        /// The session it was captured in.
        session_id: SessionId,
        /// The change set.
        change_set_id: ChangeSetId,
        /// Its version.
        version: u64,
        /// One line naming what it holds.
        summary: String,
    },
    /// An adapter failed.
    AdapterFailed {
        /// The adapter.
        plugin_id: PluginId,
        /// The session it was serving, when it was serving one.
        session_id: Option<SessionId>,
        /// What failed.
        detail: String,
    },
    /// An adapter that had failed is serving again.
    AdapterRecovered {
        /// The adapter.
        plugin_id: PluginId,
    },
    /// Contact with the host was lost.
    HostContactLost {
        /// What was lost, as the transport named it.
        detail: String,
    },
    /// Contact with the host was restored.
    HostContactRestored,
    /// An application asked for a notification.
    ApplicationNotice {
        /// The session it was printed in.
        session_id: SessionId,
        /// The notice.
        notice: ApplicationNotice,
    },
    /// A workflow revision or a causal chain was paused by one of its own limits.
    AutomationPaused {
        /// What was paused.
        subject: AttentionAutomationSubject,
        /// Which limit was reached, as the workflow journal names it.
        reason: String,
        /// The grant the workflow revision or the chain acts under, when the journal can name one.
        ///
        /// It decides which paired devices may see the item: one whose own grant it is.
        grant_id: Option<GrantId>,
    },
    /// A paused workflow revision runs again.
    AutomationResumed {
        /// What runs again.
        subject: AttentionAutomationSubject,
    },
}

/// One typed event, with where it came from and when the host recorded it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceEvent {
    /// Where the event sat in its retained source.
    pub cursor: EventCursor,
    /// When the host recorded it.
    pub at_ms: TimestampMs,
    /// Where [`SourceEvent::at_ms`] sits on the only clock an interval can be measured on.
    ///
    /// The engine measures an interval from a moment an event names - how long a condition has
    /// stood - against the clock it reads now, and the only clock that answers that is the
    /// boot-scoped continuous one. A producer that read it when it recorded the event says so
    /// here; one that did not, or one from another boot, gives the engine nothing to measure
    /// across, and the interval starts where the engine reads the record. That makes a reminder
    /// late rather than making it fire the moment somebody corrects a wall clock.
    pub at_anchor: Option<Anchor>,
    /// What it says.
    pub kind: EventKind,
}

impl SourceEvent {
    /// Builds an event whose recorded moment has no place on this engine's clock.
    #[must_use]
    pub const fn new(cursor: EventCursor, at_ms: TimestampMs, kind: EventKind) -> Self {
        Self {
            cursor,
            at_ms,
            at_anchor: None,
            kind,
        }
    }

    /// Builds an event whose producer read the continuous clock when it recorded the moment.
    #[must_use]
    pub const fn anchored(
        cursor: EventCursor,
        at_ms: TimestampMs,
        anchor: Anchor,
        kind: EventKind,
    ) -> Self {
        Self {
            cursor,
            at_ms,
            at_anchor: Some(anchor),
            kind,
        }
    }
}
