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

use kr_protocol::attention::AttentionSource;
use kr_protocol::ids::{
    AgentTurnId, ApprovalRequestId, ChangeSetId, PluginId, QuestionId, SessionId,
};
use kr_protocol::scalars::TimestampMs;

/// Where one event sat in its retained source.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EventCursor {
    /// The retained source.
    pub source: AttentionSource,
    /// The sequence within it. Sequences start at one; nought is never a record.
    pub sequence: u64,
}

impl EventCursor {
    /// Builds a cursor.
    #[must_use]
    pub const fn new(source: AttentionSource, sequence: u64) -> Self {
        Self { source, sequence }
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
}

/// One typed event, with where it came from and when the host recorded it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceEvent {
    /// Where the event sat in its retained source.
    pub cursor: EventCursor,
    /// When the host recorded it.
    pub at_ms: TimestampMs,
    /// What it says.
    pub kind: EventKind,
}

impl SourceEvent {
    /// Builds an event.
    #[must_use]
    pub const fn new(cursor: EventCursor, at_ms: TimestampMs, kind: EventKind) -> Self {
        Self {
            cursor,
            at_ms,
            kind,
        }
    }
}
