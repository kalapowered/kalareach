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
//!
//! A part of a replay is also bounded by what carries it. Each entry is paid for at what it
//! encodes to, against the allowance the caller gives, which is at most section 8's 16 MiB: a
//! part read over a connection is given what is left of that connection's control frame once the
//! rest of the answer is in it.

use std::collections::VecDeque;

use kr_protocol::agent::AgentSnapshotEntry;
use kr_protocol::ids::StreamCursor;
use kr_protocol::scalars::{TimestampMs, U64};
use kr_protocol::semantic::{
    MAX_SEMANTIC_SNAPSHOT_BYTES, SemanticBudget, SemanticContinuation, SemanticLimit,
};

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

/// An entry that a part cannot carry even on its own and without its text.
///
/// Beside its text an entry carries a few numbers and the name of its kind, and a part's allowance
/// is what is left of the reader's frame once the rest of the answer is in it, so a small frame
/// beside a large binding, or an entry whose kind has a long name, can leave too little room for
/// it. Answering it with an empty part that continues at the same entry would have the reader ask
/// for that part for ever, so it is a refusal instead.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Uncarried {
    /// The entry's position in the log.
    pub node: u64,
    /// What the entry encodes to with no text.
    pub bytes: u64,
    /// What the part it would have started could carry.
    pub allowance: u64,
}

impl std::fmt::Display for Uncarried {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "entry {} of this history takes {} bytes without its text, and a part of this answer \
             carries {}",
            self.node, self.bytes, self.allowance
        )
    }
}

/// What `value` encodes to on the wire, in bytes.
///
/// A value the codec cannot represent is reported at the largest size there is, so nothing is
/// ever admitted to a part on the strength of a measurement that failed.
pub(crate) fn encoded_bytes<T: serde::Serialize + ?Sized>(value: &T) -> u64 {
    crate::snapshot::wire::measure(value)
        .and_then(|cost| u64::try_from(cost.bytes).ok())
        .unwrap_or(u64::MAX)
}

/// How much a text's encoding can grow past the empty text's beyond the text's own bytes: its
/// length is written ahead of it in one byte when it is empty and in at most nine.
const TEXT_LENGTH_GROWTH: u64 = 8;

/// Returns `entry` with its text cut to a start, ending at a character boundary, with which the
/// entry encodes to at most `allowance` bytes, and saying how many bytes it left out.
///
/// The start kept fits whatever length the text's own header takes, so it is short of the longest
/// that fits exactly by at most [`TEXT_LENGTH_GROWTH`] bytes and the part of the character the cut
/// would have split.
///
/// # Errors
///
/// Returns [`Uncarried`] when the entry does not fit even with no text at all.
fn cut(entry: &AgentSnapshotEntry, allowance: u64) -> Result<AgentSnapshotEntry, Uncarried> {
    let whole = entry.text.len();
    // Measured with everything left out, and a count of what was left out encodes no longer when
    // it is smaller, so what the entry costs beside its text is no less than this.
    let bare = AgentSnapshotEntry {
        text: String::new(),
        omitted_text_bytes: U64::new(u64::try_from(whole).unwrap_or(u64::MAX)),
        ..entry.clone()
    };
    let bytes = encoded_bytes(&bare);
    let uncarried = Uncarried {
        node: entry.node.get(),
        bytes,
        allowance,
    };
    let room = allowance
        .checked_sub(bytes)
        .ok_or(uncarried)?
        .saturating_sub(TEXT_LENGTH_GROWTH);
    let kept = entry
        .text
        .floor_char_boundary(usize::try_from(room).unwrap_or(usize::MAX).min(whole));
    Ok(AgentSnapshotEntry {
        text: entry.text[..kept].to_owned(),
        omitted_text_bytes: U64::new(u64::try_from(whole - kept).unwrap_or(u64::MAX)),
        ..entry.clone()
    })
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
                omitted_text_bytes: U64::ZERO,
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

    /// Replays everything after the cursor an adapter consumed, in a part whose entries encode to
    /// at most `max_bytes`.
    ///
    /// `from` is the last cursor the adapter checkpointed; the replay starts after it. A `from`
    /// this log no longer holds is a gap: the answer starts at what is retained and says so,
    /// because the alternative is a shorter answer that reads as a complete one.
    ///
    /// Each entry the filter admits is paid for at what it encodes to, and section 8's limit
    /// bounds the allowance: a caller can ask for less than 16 MiB and never for more. An entry
    /// that does not fit what is left ends the part, and the continuation names it, so the next
    /// part starts with it. An entry that does not fit even as the first of its part is carried
    /// with its text cut at a character boundary, saying how many bytes it left out, so that no
    /// entry ends every part at itself.
    ///
    /// # Errors
    ///
    /// Returns [`Uncarried`] when an entry does not fit a part of its own even with no text.
    pub fn replay(
        &self,
        from: Option<StreamCursor>,
        filter: &dyn HistoryFilter,
        max_bytes: u64,
    ) -> Result<Replay, Uncarried> {
        let requested = from.map_or(1, |cursor| cursor.get().saturating_add(1));
        let history_gap = requested < self.first_retained.get();
        let start = requested.max(self.first_retained.get());

        let allowance = max_bytes.min(MAX_SEMANTIC_SNAPSHOT_BYTES);
        let mut budget = SemanticBudget::with_max_bytes(allowance);
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
            let carried = match budget.admit(1, encoded_bytes(entry)) {
                Ok(()) => entry.clone(),
                // The first entry of its part, so nothing has been spent: the whole allowance is
                // there for it, and it is carried cut rather than left to start the next part too.
                Err(SemanticLimit::Bytes) if entries.is_empty() => {
                    let cut = cut(entry, allowance)?;
                    let bytes = encoded_bytes(&cut);
                    budget.admit(1, bytes).map_err(|_| Uncarried {
                        node: entry.node.get(),
                        bytes,
                        allowance,
                    })?;
                    cut
                }
                Err(limit) => {
                    continuation = Some(budget.continuation(limit, cursor.get()));
                    resume_at = Some(*cursor);
                    break;
                }
            };
            entries.push(carried);
            consumed = *cursor;
        }
        Ok(Replay {
            entries,
            continuation,
            history_gap,
            withheld,
            consumed,
            resume_at,
        })
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

    /// Replays with section 8's whole allowance, which every entry these tests write fits.
    fn whole(log: &SemanticLog, from: Option<StreamCursor>, filter: &dyn HistoryFilter) -> Replay {
        log.replay(from, filter, MAX_SEMANTIC_SNAPSHOT_BYTES)
            .expect("every entry fits a part of its own")
    }

    /// An entry is paid for at what it encodes to, not at the length of its text: a part with room
    /// for the first entry and for the length of the other two texts carries the first entry and
    /// no more, and its continuation reports the allowance it was given.
    #[test]
    fn an_entry_is_paid_for_at_what_it_encodes_to() {
        let log = log(3);
        let first = log.entries[0].1.clone();
        let allowance = encoded_bytes(&first) + ("entry 2".len() + "entry 3".len()) as u64;
        let part = log
            .replay(None, &EverythingAdmitted, allowance)
            .expect("the first entry fits");
        assert_eq!(part.entries, [first], "the first entry and no more");
        let continuation = part.continuation.expect("the part says where it stopped");
        assert_eq!(continuation.limit, SemanticLimit::Bytes);
        assert_eq!(continuation.limit_value.get(), allowance);
        assert_eq!(continuation.from_node.get(), 2);
    }

    /// An entry that does not fit even as the first of its part is carried in a part of its own
    /// with its text cut at a character boundary, inside the allowance and saying how many bytes
    /// it left out; the entries on either side of it are carried whole, in the parts before and
    /// after it, and a reader that follows the continuations reads each once.
    #[test]
    fn an_entry_larger_than_its_part_is_carried_cut_at_a_character_boundary() {
        const ALLOWANCE: u64 = 1_000;
        let large = "€".repeat(2_000);
        let mut log = SemanticLog::new();
        log.append("message", "said before", TimestampMs::new(1));
        log.append("message", large.clone(), TimestampMs::new(2));
        log.append("message", "said after", TimestampMs::new(3));

        let before = log
            .replay(None, &EverythingAdmitted, ALLOWANCE)
            .expect("a part");
        assert_eq!(before.entries.len(), 1);
        assert_eq!(before.entries[0].text, "said before");
        assert_eq!(before.entries[0].omitted_text_bytes, U64::ZERO);
        assert_eq!(before.resume_at, Some(StreamCursor::new(2)));

        let cut = log
            .replay(Some(StreamCursor::new(1)), &EverythingAdmitted, ALLOWANCE)
            .expect("a part");
        assert_eq!(cut.entries.len(), 1, "the large entry is a part of its own");
        let entry = &cut.entries[0];
        assert!(
            large.starts_with(entry.text.as_str()),
            "the start of its text"
        );
        assert!(!entry.text.is_empty(), "as much of it as fits");
        assert_eq!(
            entry.omitted_text_bytes.get(),
            (large.len() - entry.text.len()) as u64,
            "it says how many bytes it left out"
        );
        assert!(
            encoded_bytes(entry) <= ALLOWANCE,
            "the cut entry is inside the allowance: {}",
            encoded_bytes(entry)
        );
        assert_eq!(cut.consumed, StreamCursor::new(2), "the reader has had it");
        assert_eq!(cut.resume_at, Some(StreamCursor::new(3)));

        let after = log
            .replay(Some(cut.consumed), &EverythingAdmitted, ALLOWANCE)
            .expect("a part");
        assert_eq!(after.entries.len(), 1);
        assert_eq!(after.entries[0].text, "said after");
        assert!(after.continuation.is_none());
    }

    /// An entry that a part cannot carry even with no text is refused, naming the entry, rather
    /// than answered with an empty part that continues at the same entry for ever.
    #[test]
    fn an_entry_that_does_not_fit_without_its_text_is_refused() {
        let log = log(1);
        let refused = log
            .replay(None, &EverythingAdmitted, 8)
            .expect_err("no entry fits eight bytes");
        assert_eq!(refused.node, 1);
        assert_eq!(refused.allowance, 8);
        assert!(refused.bytes > 8, "{refused}");
    }

    #[test]
    fn a_replay_starts_after_the_cursor_the_adapter_consumed() {
        let log = log(5);
        let replay = whole(&log, Some(StreamCursor::new(2)), &EverythingAdmitted);
        assert_eq!(replay.entries.len(), 3);
        assert_eq!(replay.entries[0].text, "entry 3");
        assert!(!replay.history_gap);
        assert_eq!(replay.consumed, StreamCursor::new(5));

        let from_nothing = whole(&log, None, &EverythingAdmitted);
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
        let replay = whole(&log, Some(StreamCursor::new(1)), &EverythingAdmitted);
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
        let current = whole(&log, Some(log.first_retained()), &EverythingAdmitted);
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

        let first = whole(&log, None, &filter);
        assert_eq!(nodes(&first), [2]);
        assert_eq!(first.withheld, 2, "the withheld entries this page examined");
        assert_eq!(
            first.consumed,
            StreamCursor::new(2),
            "a withheld entry does not advance the checkpoint"
        );
        assert!(first.continuation.is_some());
        assert_eq!(first.resume_at, Some(StreamCursor::new(4)));

        let next = whole(&log, Some(StreamCursor::new(3)), &filter);
        assert_eq!(nodes(&next), [4]);
        assert_eq!(next.withheld, 1);
        assert!(next.continuation.is_none());

        let nothing = whole(&log, None, &reaching_back_to(10_000));
        assert!(nothing.entries.is_empty());
        assert_eq!(nothing.withheld, 5);
        assert_eq!(nothing.consumed, StreamCursor::new(0));
        assert!(nothing.continuation.is_none());
    }

    /// An entry number is never given twice, at the end of the numbering as anywhere else.
    #[test]
    fn an_entry_number_is_never_given_twice_at_the_end_of_the_numbering() {
        let mut log = SemanticLog::new();
        log.resume_after(StreamCursor::new(u64::MAX - 2));
        let numbers: Vec<u64> = (0..3_u64)
            .map(|index| {
                log.append("message", format!("entry {index}"), TimestampMs::new(index))
                    .get()
            })
            .collect();
        let distinct: std::collections::BTreeSet<&u64> = numbers.iter().collect();
        assert_eq!(distinct.len(), numbers.len(), "numbers given: {numbers:?}");
    }

    #[test]
    fn a_filtered_answer_says_how_much_it_withheld() {
        let log = log(5);
        let filter = GrantLowerBound {
            from: StreamCursor::new(4),
        };
        let replay = whole(&log, None, &filter);
        assert_eq!(replay.entries.len(), 2);
        assert_eq!(
            replay.withheld, 3,
            "a reader can tell a short answer from a complete one"
        );
        assert!(!replay.history_gap, "a filter is not an eviction");
    }
}
