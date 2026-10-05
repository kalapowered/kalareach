//! Summaries of what changed in a session since a person last looked.
//!
//! Section 18 gives the product changes since a person's previous visit, *derived from host events
//! and requested summaries*. The changes are the host's own record, and a summary is a model's
//! reading of them: it is asked for, it is generated under a grammar of its own and held to the
//! rules a description is held to, and it is kept apart from the changes it was written from. A
//! client that never asks loses nothing authoritative.
//!
//! # One job slot for a session
//!
//! A summary is a job like a description, run by the same process under the same admission, and a
//! session has one place in the queue for both. A request of one kind that arrives while the other
//! kind waits is held as the session's next request and takes the place when that job is sent. At
//! most one of each kind is held, so a later request replaces a waiting one of its kind in place,
//! keeping its age. Summaries are priority work, so an ordinary description waits behind at most
//! three of them.
//!
//! # The interval is frozen when it is asked for
//!
//! A request names the first cursor the person has not acknowledged and the cursor the session's
//! changes had reached, and the job is built from the changes between them as they stood. A
//! session that goes on changing neither lengthens the job nor invalidates its result: the result
//! is of that interval, and says so, and the next request is for a longer one that starts at the
//! same first cursor. Retention and acknowledgement move the first cursor of the next request and
//! nothing about the interval a result was written for.
//!
//! # What a result is held under
//!
//! A result is kept by its session, its interval, the profile that wrote it and the privacy
//! generation it was written under, at most [`MAX_SUMMARIES_PER_SESSION`] for a session, and the
//! oldest go first. It is read only under all of them: another profile's, another generation's and
//! one written while privacy mode was on are not answered.

use kr_protocol::ids::SessionId;
use kr_protocol::scalars::U64;
use kr_worker::privacy::PrivacyGeneration;

use crate::context::{CursorInterval, ProjectText};
use crate::metadata::SummaryText;
use crate::profile::ProfileRevision;
use crate::prompt::{Datum, Prompt, PromptKind};
use crate::queue::Enqueued;

/// The most results the store keeps for one session. The oldest go first.
pub const MAX_SUMMARIES_PER_SESSION: usize = 8;

/// The most changes one summary job is built from: the newest ones in its interval. The interval
/// is still the whole of what was asked for, and the prompt is made to fit its token bound by
/// letting the oldest of these go first.
pub const MAX_SUMMARY_CHANGES: usize = 64;

/// One change in a session, as a summary job reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SummaryChange {
    /// The cursor the change sits at in the session's changes.
    pub cursor: u64,
    /// What kind of change it was, by its stable name.
    pub kind: &'static str,
    /// When the host recorded it, on the wall clock.
    pub at_ms: u64,
    /// The text of the change, when it has one that may be read: carried as data.
    pub text: Option<ProjectText>,
}

/// A request for a summary of one session's changes in one interval.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SummaryAsk {
    /// The session.
    pub session_id: SessionId,
    /// The interval of the session's changes: the first cursor, and the first cursor after it.
    pub interval: CursorInterval,
    /// When the earliest change in the interval happened.
    pub from_ms: u64,
    /// When the latest change in the interval happened.
    pub to_ms: u64,
    /// The privacy generation the text of the changes was read under, when any was read from the
    /// session: a request whose text was read under another generation than the one in force is
    /// refused.
    pub generation: Option<PrivacyGeneration>,
    /// The newest changes in the interval, oldest first.
    pub changes: Vec<SummaryChange>,
}

impl SummaryAsk {
    /// Builds a request, keeping the newest [`MAX_SUMMARY_CHANGES`] of `changes`.
    ///
    /// A request with no change in it has nothing to summarise and gives [`None`].
    #[must_use]
    pub fn new(
        session_id: SessionId,
        interval: CursorInterval,
        from_ms: u64,
        to_ms: u64,
        generation: Option<PrivacyGeneration>,
        mut changes: Vec<SummaryChange>,
    ) -> Option<Self> {
        changes.sort_by_key(|change| change.cursor);
        let over = changes.len().saturating_sub(MAX_SUMMARY_CHANGES);
        changes.drain(..over);
        if changes.is_empty() {
            return None;
        }
        Some(Self {
            session_id,
            interval,
            from_ms,
            to_ms,
            generation,
            changes,
        })
    }

    /// Returns the prompt this request is asked about in.
    ///
    /// Every piece of a session's text is in it as a labelled datum, as a description's is, and
    /// nothing in it outside the instruction came from anywhere else.
    #[must_use]
    pub fn prompt(&self) -> Prompt {
        Prompt {
            kind: PromptKind::Summary,
            revision: U64::new(0),
            cursor_from: U64::new(self.interval.from),
            cursor_to: U64::new(self.interval.to),
            facts: Vec::new(),
            events: self
                .changes
                .iter()
                .map(|change| Datum {
                    label: format!("change {}", change.kind),
                    text: change
                        .text
                        .as_ref()
                        .map(|text| text.as_str().to_owned())
                        .unwrap_or_default(),
                })
                .collect(),
        }
    }
}

/// A summary that was written, with the provenance that says what it was written from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SummaryRecord {
    /// The session.
    pub session_id: SessionId,
    /// The interval of the session's changes it covers: the first cursor, and the first cursor
    /// after it.
    pub cursor: CursorInterval,
    /// When the earliest change in the interval happened.
    pub from_ms: u64,
    /// When the latest change in the interval happened.
    pub to_ms: u64,
    /// The summary.
    pub text: SummaryText,
    /// The profile that wrote it.
    pub profile_id: String,
    /// That profile's revision.
    pub profile_revision: ProfileRevision,
    /// The privacy generation in force when it was written.
    pub generation: PrivacyGeneration,
    /// When it was written, on the wall clock.
    pub produced_at_ms: u64,
}

impl SummaryRecord {
    /// Returns whether this result answers a request for the changes from `first` to `head`: it
    /// starts where the request does and ends at or before the head.
    #[must_use]
    pub const fn answers(&self, first: u64, head: u64) -> bool {
        self.cursor.from == first && self.cursor.to <= head
    }
}

/// Returns whether a request for the changes from the first cursor of `newest` to `head` is worth
/// a job, given the newest result held for that first cursor.
///
/// Nothing held is worth one. A result that reaches the head has nothing newer to say. A result
/// that stops short of it is refreshed once it is older than the cadence, from the same first
/// cursor to the head and never for the tail alone, since a person who has not acknowledged still
/// reads from that first cursor.
#[must_use]
pub fn is_wanted(
    newest: Option<&SummaryRecord>,
    head: u64,
    now_wall_ms: u64,
    cadence_ms: u64,
) -> bool {
    match newest {
        None => true,
        Some(held) if held.cursor.to >= head => false,
        Some(held) => now_wall_ms.saturating_sub(held.produced_at_ms) >= cadence_ms,
    }
}

/// What asking for a summary came to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SummaryAsked {
    /// The request was queued, or held beside the session's other kind of job, or replaced one
    /// that was waiting.
    Queued(Enqueued),
    /// A result already held, or a job already running, covers what was asked for, or is too
    /// recent to be refreshed: nothing was queued.
    Covered,
    /// The request was refused, and why.
    Refused(SummaryRefusal),
}

/// Why a request for a summary was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SummaryRefusal {
    /// This host selected no model, so nothing it queued would run.
    NoModel,
    /// The service is not tracking the session: it is closed, or has not been opened.
    NotTracked,
    /// Privacy mode has stopped description processing for the session.
    Fenced,
    /// The text of the changes was read under another privacy generation than the one in force.
    Generation,
}

impl SummaryRefusal {
    /// Returns the stable name this refusal is reported under.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoModel => "no_model",
            Self::NotTracked => "not_tracked",
            Self::Fenced => "fenced",
            Self::Generation => "generation",
        }
    }
}
