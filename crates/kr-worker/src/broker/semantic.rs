//! The semantic entries an adapter observes, the cursor it checkpoints, and the gap an eviction
//! leaves.
//!
//! Section 24: "Adapters checkpoint their last consumed semantic cursor. On restart, replay
//! retained events through that cursor. If the range was evicted, rebuild from verified native
//! state and show a history gap for anything unavailable. A grid image or transcript file cannot
//! reconstruct an unobserved pending approval."
//!
//! Two rules make the last sentence true rather than aspirational.
//!
//! * **A gap is reported, never filled.** [`Replay::history_gap`] is set when the reader asked for
//!   a cursor this log no longer holds. Nothing here reconstructs the missing entries from
//!   anything, because there is nothing to reconstruct them from that would be honest.
//! * **A filtered answer says how much it withheld.** The shared host-side history filter decides
//!   what one actor may see. What this returns is the entries it admitted and the count it did
//!   not, so a reader can tell a short answer from a complete one without being shown what it may
//!   not see.

use std::collections::VecDeque;

use kr_protocol::agent::AgentSnapshotEntry;
use kr_protocol::ids::StreamCursor;
use kr_protocol::scalars::{TimestampMs, U64};
use kr_protocol::semantic::{SemanticBudget, SemanticContinuation};

/// How many semantic entries one instance's log retains.
///
/// Past this the oldest go, and a reader that asked for one of them is told there is a gap rather
/// than given a shorter answer that looks complete.
pub const MAX_RETAINED_ENTRIES: usize = 4096;

/// What one actor may see of an instance's history.
///
/// Section 23 gives every agent read a `GrantLowerBound` history filter, and section 10 has one
/// shared host-side implementation serve every subsystem. This is the seam it plugs into: the
/// shared filter ([`crate::history_filter::HistoryFilter`]) decides each entry by when it was
/// observed, on the semantic-snapshot surface.
pub trait HistoryFilter {
    /// Returns true when this actor may see the entry at this cursor.
    fn admits(&self, cursor: StreamCursor, entry: &AgentSnapshotEntry) -> bool;
}

/// The shared host-side filter, deciding an entry by the moment it was observed.
///
/// A replay asks it before an entry spends any of the page's budget, so what it withholds is
/// counted rather than paid for, and an entry is placed at its own time rather than at the time
/// of the read.
impl HistoryFilter for crate::history_filter::HistoryFilter {
    fn admits(&self, _cursor: StreamCursor, entry: &AgentSnapshotEntry) -> bool {
        self.admit_at(
            crate::history_filter::Surface::SemanticSnapshot,
            entry.observed_at.get(),
        )
        .is_ok()
    }
}

/// A filter that admits everything from one cursor onwards.
///
/// It decides by position in the log rather than by time, so it is not how a grant's scope is
/// applied: that is the shared filter's, by the moment each entry was observed. It serves a reader
/// that wants a range of the log by position.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GrantLowerBound {
    /// The earliest cursor this actor's grant reaches.
    pub from: StreamCursor,
}

impl HistoryFilter for GrantLowerBound {
    fn admits(&self, cursor: StreamCursor, _entry: &AgentSnapshotEntry) -> bool {
        cursor.get() >= self.from.get()
    }
}

/// What a replay produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Replay {
    /// The entries this part carries, in order.
    pub entries: Vec<AgentSnapshotEntry>,
    /// Where a reader continues, when a limit stopped this part.
    pub continuation: Option<SemanticContinuation>,
    /// True when the range the reader asked for had been evicted.
    pub history_gap: bool,
    /// How many entries the history filter withheld.
    pub withheld: u64,
    /// The cursor a reader that consumed this part checkpoints.
    ///
    /// It stops at the last entry this reader actually received. An entry the filter withheld
    /// does not advance it: another consumer with wider visibility checkpoints the same instance,
    /// and skipping over what this one could not see would lose it for that one too.
    pub consumed: StreamCursor,
    /// The cursor the next part starts *at*, when a limit stopped this one.
    ///
    /// It is inclusive, because the node it names is the first one that was left out. A reader
    /// that passed it back as a consumed cursor would skip it.
    pub resume_at: Option<StreamCursor>,
}

/// One instance's retained semantic entries.
#[derive(Debug)]
pub struct SemanticLog {
    entries: VecDeque<(StreamCursor, AgentSnapshotEntry)>,
    first_retained: StreamCursor,
    next: u64,
}

impl Default for SemanticLog {
    fn default() -> Self {
        Self::new()
    }
}

impl SemanticLog {
    /// An empty log.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: VecDeque::new(),
            first_retained: StreamCursor::new(1),
            next: 1,
        }
    }

    /// Appends one observed entry and returns its cursor.
    pub fn append(
        &mut self,
        kind: impl Into<String>,
        text: impl Into<String>,
        at: TimestampMs,
    ) -> StreamCursor {
        let cursor = StreamCursor::new(self.next);
        self.next = self.next.saturating_add(1);
        self.entries.push_back((
            cursor,
            AgentSnapshotEntry {
                node: U64::new(cursor.get()),
                kind: kind.into(),
                text: text.into(),
                observed_at: at,
            },
        ));
        while self.entries.len() > MAX_RETAINED_ENTRIES {
            if let Some((evicted, _)) = self.entries.pop_front() {
                self.first_retained = StreamCursor::new(evicted.get().saturating_add(1));
            }
        }
        cursor
    }

    /// Returns the earliest cursor this log still holds.
    #[must_use]
    pub const fn first_retained(&self) -> StreamCursor {
        self.first_retained
    }

    /// Returns the cursor the next entry will take.
    #[must_use]
    pub const fn next_cursor(&self) -> StreamCursor {
        StreamCursor::new(self.next)
    }

    /// Replays everything after the cursor an adapter consumed.
    ///
    /// `from` is the last cursor the adapter checkpointed; the replay starts after it. A `from`
    /// this log no longer holds is a gap: the answer starts at what is retained and says so,
    /// because the alternative is a shorter answer that reads as a complete one.
    pub fn replay(&self, from: Option<StreamCursor>, filter: &dyn HistoryFilter) -> Replay {
        let requested = from.map_or(1, |cursor| cursor.get().saturating_add(1));
        let history_gap = requested < self.first_retained.get();
        let start = requested.max(self.first_retained.get());

        let mut budget = SemanticBudget::new();
        let mut entries = Vec::new();
        let mut withheld = 0;
        let mut consumed = from.unwrap_or_else(|| StreamCursor::new(0));
        let mut continuation = None;
        let mut resume_at = None;
        for (cursor, entry) in &self.entries {
            if cursor.get() < start {
                continue;
            }
            if !filter.admits(*cursor, entry) {
                withheld += 1;
                continue;
            }
            match budget.admit(1, u64::try_from(entry.text.len()).unwrap_or(u64::MAX)) {
                Ok(()) => {
                    entries.push(entry.clone());
                    consumed = *cursor;
                }
                Err(limit) => {
                    continuation = Some(budget.continuation(limit, cursor.get()));
                    resume_at = Some(*cursor);
                    break;
                }
            }
        }
        Replay {
            entries,
            continuation,
            history_gap,
            withheld,
            consumed,
            resume_at,
        }
    }

    /// Resumes a log at the cursor an adapter had already consumed.
    ///
    /// A restart does not keep the entries: they are the live parser's, and section 24 says a
    /// rebuilt range shows a history gap for anything unavailable. What it does keep is the
    /// numbering, so a new entry never takes a cursor an adapter has already checkpointed past,
    /// and everything before the resume point is a gap rather than a silently empty answer.
    pub const fn resume_after(&mut self, consumed: StreamCursor) {
        let next = consumed.get().saturating_add(1);
        if next > self.next {
            self.next = next;
            self.first_retained = StreamCursor::new(next);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn log(count: u64) -> SemanticLog {
        let mut log = SemanticLog::new();
        for index in 1..=count {
            log.append("message", format!("entry {index}"), TimestampMs::new(index));
        }
        log
    }

    struct EverythingAdmitted;

    impl HistoryFilter for EverythingAdmitted {
        fn admits(&self, _cursor: StreamCursor, _entry: &AgentSnapshotEntry) -> bool {
            true
        }
    }

    #[test]
    fn a_replay_starts_after_the_cursor_the_adapter_consumed() {
        let log = log(5);
        let replay = log.replay(Some(StreamCursor::new(2)), &EverythingAdmitted);
        assert_eq!(replay.entries.len(), 3);
        assert_eq!(replay.entries[0].text, "entry 3");
        assert!(!replay.history_gap);
        assert_eq!(replay.consumed, StreamCursor::new(5));

        let from_nothing = log.replay(None, &EverythingAdmitted);
        assert_eq!(from_nothing.entries.len(), 5);
        assert!(!from_nothing.history_gap);
    }

    #[test]
    fn an_evicted_range_rebuilds_with_a_visible_history_gap() {
        let mut log = SemanticLog::new();
        for index in 1..=(MAX_RETAINED_ENTRIES as u64 + 10) {
            log.append("message", format!("entry {index}"), TimestampMs::new(index));
        }
        assert!(log.first_retained().get() > 1);

        // The adapter checkpointed before the eviction.
        let replay = log.replay(Some(StreamCursor::new(1)), &EverythingAdmitted);
        assert!(
            replay.history_gap,
            "a range this log no longer holds is a gap, not a shorter answer"
        );
        assert_eq!(replay.entries.len(), MAX_RETAINED_ENTRIES);
        assert_eq!(
            replay.entries[0].node.get(),
            log.first_retained().get(),
            "the rebuild starts at what is verifiably retained"
        );

        // An adapter that is up to date sees no gap.
        let current = log.replay(Some(log.first_retained()), &EverythingAdmitted);
        assert!(!current.history_gap);
    }

    /// The shared filter decides each entry by the moment it was observed, before the entry spends
    /// any of the page's budget: what it withholds before, between and after what it keeps is
    /// counted on the page that examined it and never paid for, a withheld entry does not advance
    /// the checkpoint, a continuation names the first kept entry that did not fit, and a page the
    /// filter withholds wholly is an empty answer that says how much it withheld.
    #[test]
    fn the_shared_filter_decides_by_when_an_entry_was_observed_before_the_page_budget() {
        use kr_protocol::grant::HistoryScope;
        use kr_protocol::scalars::{CanonicalSet, Nullable};

        use crate::history_filter::{HistoryFilter as Shared, ViewerScope};

        let reaching_back_to = |bound: u64| {
            Shared::new(ViewerScope::from_history(
                &HistoryScope {
                    lower_bound_ms: Nullable::some(TimestampMs::new(bound)),
                    include_live_screen: true,
                    named_questions: CanonicalSet::new(),
                    named_approvals: CanonicalSet::new(),
                },
                true,
            ))
        };
        let nodes = |replay: &Replay| {
            replay
                .entries
                .iter()
                .map(|entry| entry.node.get())
                .collect::<Vec<_>>()
        };
        // Two kept entries too large to share a page, with withheld entries of the same size
        // before and between them and a small one after, out of time order the way a clock
        // stepped backwards leaves them.
        let large = "x".repeat(9 * 1024 * 1024);
        let mut log = SemanticLog::new();
        log.append("message", large.clone(), TimestampMs::new(1_000));
        log.append("message", large.clone(), TimestampMs::new(2_500));
        log.append("message", large.clone(), TimestampMs::new(1_500));
        log.append("message", large, TimestampMs::new(3_000));
        log.append("message", "said before, last", TimestampMs::new(1_200));
        let filter = reaching_back_to(2_000);

        let first = log.replay(None, &filter);
        assert_eq!(nodes(&first), [2]);
        assert_eq!(first.withheld, 2, "the withheld entries this page examined");
        assert_eq!(
            first.consumed,
            StreamCursor::new(2),
            "a withheld entry does not advance the checkpoint"
        );
        assert!(first.continuation.is_some());
        assert_eq!(first.resume_at, Some(StreamCursor::new(4)));

        let next = log.replay(Some(StreamCursor::new(3)), &filter);
        assert_eq!(nodes(&next), [4]);
        assert_eq!(next.withheld, 1);
        assert!(next.continuation.is_none());

        let nothing = log.replay(None, &reaching_back_to(10_000));
        assert!(nothing.entries.is_empty());
        assert_eq!(nothing.withheld, 5);
        assert_eq!(nothing.consumed, StreamCursor::new(0));
        assert!(nothing.continuation.is_none());
    }

    #[test]
    fn a_filtered_answer_says_how_much_it_withheld() {
        let log = log(5);
        let filter = GrantLowerBound {
            from: StreamCursor::new(4),
        };
        let replay = log.replay(None, &filter);
        assert_eq!(replay.entries.len(), 2);
        assert_eq!(
            replay.withheld, 3,
            "a reader can tell a short answer from a complete one"
        );
        assert!(!replay.history_gap, "a filter is not an eviction");
    }
}
