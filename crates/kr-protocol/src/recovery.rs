//! State recovery: subscriptions, snapshots and history pages.
//!
//! A client subscribes from a cursor *before* it installs a snapshot, so the worker can return the
//! state at cursor N and queue everything after N. When the bounded replay window no longer covers
//! the requested cursor, the answer is an explicit gap and a fresh snapshot, never a silently
//! shortened history.
//!
//! The canonical grid snapshot belongs to the terminal engine. This module carries the byte-level
//! contract the worker owns: the monotonically increasing output cursor, the retained byte
//! history, the explicit gap marker and the resynchronisation requirement a slow client receives
//! instead of holding the pseudo-terminal read loop.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::attachment::{AttachmentSummary, GeometryState};
use crate::ids::{AttachmentId, SessionId, StreamId};
use crate::input::InputLeaseState;
use crate::scalars::{Bytes, CanonicalSet, Nullable, TimestampMs, U64};
use crate::session::SessionSummary;

/// The event streams a session publishes.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum EventStream {
    /// Lifecycle and application-state changes.
    SessionState,
    /// Raw terminal output bytes with their cursors.
    Output,
    /// Attachment joins, departures, geometry ownership and viewport reports.
    Attachments,
    /// Input lease changes.
    InputLease,
    /// Action receipts.
    Receipts,
}

impl EventStream {
    /// Every stream, in declaration order.
    pub const ALL: &'static [Self] = &[
        Self::SessionState,
        Self::Output,
        Self::Attachments,
        Self::InputLease,
        Self::Receipts,
    ];

    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SessionState => "session_state",
            Self::Output => "output",
            Self::Attachments => "attachments",
            Self::InputLease => "input_lease",
            Self::Receipts => "receipts",
        }
    }
}

/// Parameters of `events.subscribe`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EventsSubscribeParams {
    /// The session to subscribe to.
    pub session_id: SessionId,
    /// The attachment the subscription belongs to.
    pub attachment_id: AttachmentId,
    /// The streams to receive.
    pub streams: CanonicalSet<EventStream>,
    /// The output cursor to resume from. Null starts from the current position.
    pub from_cursor: Nullable<U64>,
}

/// The result of `events.subscribe`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EventsSubscribeResult {
    /// The stream identifier notifications will carry.
    pub stream_id: StreamId,
    /// The cursor the subscription starts from.
    pub from_cursor: U64,
    /// The oldest cursor the worker can still replay. A requested cursor below this returns a gap.
    pub oldest_retained_cursor: U64,
    /// Present when the requested cursor was already evicted, so the client must discard its
    /// partial state and install a new snapshot.
    pub gap: Nullable<HistoryGap>,
}

/// A range of output the worker can no longer replay.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HistoryGap {
    /// The first cursor that is missing.
    pub from_cursor: U64,
    /// The first cursor that is present again.
    pub to_cursor: U64,
    /// Why the range is missing, when the host recorded a reason for it.
    ///
    /// Section 20 asks eviction to leave *explicit* history-gap cursors. The cursors say what is
    /// gone; this says which bound took it, so a person looking at a gap can tell their own
    /// session's size from a busy host.
    ///
    /// It is absent from the wire when the host has no reason recorded, so a gap this host
    /// reports is byte for byte what a client built before causes existed expects.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cause: Option<HistoryGapCause>,
}

/// Why a range of output is no longer retained.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum HistoryGapCause {
    /// Output older than the retention period.
    Retention,
    /// The host-wide cap on retained session output.
    HostCapacity,
    /// This session's own cap on retained output.
    SessionCapacity,
    /// The spool could not be written, so only the resident window is retained.
    SpoolUnavailable,
    /// The archive holds no record of this range.
    ///
    /// A session whose journal or spool was lost produces an explicit incomplete archive rather
    /// than an empty success, and this is what a reader of its history is told: the range is not
    /// accounted for, which is a different answer from "nothing happened".
    ArchiveIncomplete,
}

impl HistoryGapCause {
    /// Returns the stable wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Retention => "retention",
            Self::HostCapacity => "host_capacity",
            Self::SessionCapacity => "session_capacity",
            Self::SpoolUnavailable => "spool_unavailable",
            Self::ArchiveIncomplete => "archive_incomplete",
        }
    }
}

/// Parameters of `events.snapshot`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EventsSnapshotParams {
    /// The session to snapshot.
    pub session_id: SessionId,
}

/// The result of `events.snapshot`.
///
/// Every field is present state, not a replay: installing a snapshot emits no bell, no clipboard
/// write, no notification and no query.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EventsSnapshotResult {
    /// The cursor this snapshot was taken at. Subsequent updates resume from here.
    pub cursor: U64,
    /// The session.
    pub session: SessionSummary,
    /// Who owns the size.
    pub geometry: GeometryState,
    /// Who holds input.
    pub lease: InputLeaseState,
    /// Every current attachment, in join order.
    pub attachments: Vec<AttachmentSummary>,
    /// The oldest output cursor still retained.
    pub oldest_retained_cursor: U64,
    /// When the snapshot was taken.
    pub taken_at_ms: TimestampMs,
}

/// Maximum bytes one history page may carry.
pub const MAX_HISTORY_PAGE_BYTES: u64 = 1024 * 1024;

/// Parameters of `history.page`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HistoryPageParams {
    /// The session to read.
    pub session_id: SessionId,
    /// The cursor to read from.
    pub from_cursor: U64,
    /// The largest page the caller will accept, bounded by [`MAX_HISTORY_PAGE_BYTES`].
    pub max_bytes: U64,
}

/// The result of `history.page`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HistoryPageResult {
    /// The cursor this page starts at, after any gap.
    pub from_cursor: U64,
    /// The cursor to request next.
    pub next_cursor: U64,
    /// The retained bytes. Raw output is a byte string and need not be valid UTF-8.
    pub bytes: Bytes,
    /// The oldest cursor still retained when the page was built.
    pub oldest_retained_cursor: U64,
    /// Present when the requested range had been evicted. The page states its gap rather than
    /// returning a shorter range as if it were complete.
    pub gap: Nullable<HistoryGap>,
}

/// Why a subscriber must resynchronise.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ResyncReason {
    /// The subscriber's queue reached its bound. The pseudo-terminal read loop is never held for
    /// a slow client.
    SendQueueFull,
    /// The subscriber's cursor fell out of the retained window.
    HistoryEvicted,
    /// The canonical grid was replaced, for instance by a buffer switch.
    ProjectionReset,
}

impl ResyncReason {
    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SendQueueFull => "send_queue_full",
            Self::HistoryEvicted => "history_evicted",
            Self::ProjectionReset => "projection_reset",
        }
    }
}

/// The event that tells one subscriber to discard its partial state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResyncRequired {
    /// Why.
    pub reason: ResyncReason,
    /// The cursor the worker is currently at.
    pub cursor: U64,
    /// The oldest cursor still retained.
    pub oldest_retained_cursor: U64,
}

/// One batch of output bytes on the output stream.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OutputEvent {
    /// The cursor these bytes start at.
    pub cursor: U64,
    /// The bytes.
    pub bytes: Bytes,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_history_page_is_bounded() {
        assert_eq!(MAX_HISTORY_PAGE_BYTES, 1024 * 1024);
    }

    #[test]
    fn every_stream_has_a_distinct_wire_string() {
        let mut names: Vec<&str> = EventStream::ALL.iter().map(|s| s.as_str()).collect();
        names.sort_unstable();
        let count = names.len();
        names.dedup();
        assert_eq!(names.len(), count);
    }
}
