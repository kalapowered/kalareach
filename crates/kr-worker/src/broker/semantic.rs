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
//!
//! One snapshot is bounded across its parts too. Section 8's 16 MiB and twenty thousand nodes are
//! spent by every part of it together, so a part is paid for out of what the parts before it left
//! ([`SnapshotCarried`]). The part that would pass the total ends the snapshot with a continuation
//! that names the total, and what a reader asks for from there is a snapshot of its own.
//!
//! An entry's number is its identity to every reader, so no number is given twice: a log that has
//! given the last one refuses the next entry ([`Exhausted`]).

use std::collections::VecDeque;

use kr_protocol::agent::AgentSnapshotEntry;
use kr_protocol::ids::StreamCursor;
use kr_protocol::scalars::{TimestampMs, U64};
use kr_protocol::semantic::{
    MAX_SEMANTIC_SNAPSHOT_BYTES, MAX_SEMANTIC_TREE_NODES, SemanticBudget, SemanticContinuation,
    SemanticLimit,
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
    /// What this snapshot's parts have carried, this one included, when a later part continues it.
    ///
    /// `None` when this part is the snapshot's last: nothing was left out, or the parts together
    /// reached section 8's total, and what is asked for from the continuation is a snapshot of its
    /// own.
    pub carried: Option<SnapshotCarried>,
}

/// What the parts of one snapshot have carried so far.
///
/// Section 8 bounds a semantic snapshot at 16 MiB of encoded content and twenty thousand nodes
/// across every part of it, so each part is paid for out of what the parts before it left, not out
/// of a fresh allowance of its own.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SnapshotCarried {
    /// How many entries the parts carried.
    pub nodes: u64,
    /// What those entries encode to, in bytes.
    pub bytes: u64,
}

impl SnapshotCarried {
    /// What a snapshot has carried before its first part.
    pub const NOTHING: Self = Self { nodes: 0, bytes: 0 };

    /// Returns the limit of section 8's that one more entry of `bytes` would pass, after what this
    /// snapshot's earlier parts and `part` have carried.
    fn refuses(self, part: &SemanticBudget, bytes: u64) -> Option<SemanticLimit> {
        if self.nodes.saturating_add(part.nodes()) >= MAX_SEMANTIC_TREE_NODES {
            return Some(SemanticLimit::Nodes);
        }
        match self.bytes.saturating_add(part.bytes()).checked_add(bytes) {
            Some(total) if total <= MAX_SEMANTIC_SNAPSHOT_BYTES => None,
            _ => Some(SemanticLimit::Bytes),
        }
    }

    /// Returns what the snapshot has carried once `part` is added to it.
    fn with(self, part: &SemanticBudget) -> Self {
        Self {
            nodes: self.nodes.saturating_add(part.nodes()),
            bytes: self.bytes.saturating_add(part.bytes()),
        }
    }
}

/// A log that has given every entry number it has.
///
/// A reader knows an entry by its number, and a continuation names the next entry by it, so a log
/// at the end of its numbering refuses the next entry rather than give a number twice. The last
/// number it gives is one below the largest there is, because the number after an entry is where
/// the next one would start.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Exhausted;

impl std::fmt::Display for Exhausted {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(
            "this history has given every entry number it has, and it gives none of them twice",
        )
    }
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
    ///
    /// # Errors
    ///
    /// Returns [`Exhausted`] when this log has given its last entry number, and records nothing.
    pub fn append(
        &mut self,
        kind: impl Into<String>,
        text: impl Into<String>,
        at: TimestampMs,
    ) -> Result<StreamCursor, Exhausted> {
        let following = self.next.checked_add(1).ok_or(Exhausted)?;
        let cursor = StreamCursor::new(self.next);
        self.next = following;
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
        Ok(cursor)
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

    /// Returns true when this log has given every entry number it has ([`Exhausted`]).
    #[must_use]
    pub const fn is_exhausted(&self) -> bool {
        self.next.checked_add(1).is_none()
    }

    /// Replays everything after the cursor an adapter consumed, in a part whose entries encode to
    /// at most `max_bytes`, of a snapshot whose earlier parts carried `carried`.
    ///
    /// `from` is the last cursor the adapter checkpointed; the replay starts after it. A `from`
    /// this log no longer holds is a gap: the answer starts at what is retained and says so,
    /// because the alternative is a shorter answer that reads as a complete one.
    ///
    /// Each entry the filter admits is paid for at what it encodes to, twice over. The part pays
    /// out of its allowance, which section 8's limit bounds: a caller can ask for less than 16 MiB
    /// and never for more. An entry that does not fit what is left of it ends the part, and the
    /// continuation names it, so the next part starts with it; one that does not fit even as the
    /// first of its part is carried with its text cut at a character boundary, saying how many
    /// bytes it left out, so that no entry ends every part at itself. The snapshot pays out of
    /// section 8's total, less what its earlier parts carried. An entry that would pass the total
    /// ends the snapshot, and the continuation names the total and the entry, which the next
    /// snapshot starts with; the snapshot's own first entry has the whole total to itself, which
    /// is more than any part carries, so the part's rule decides it.
    ///
    /// # Errors
    ///
    /// Returns [`Uncarried`] when an entry does not fit a part of its own even with no text.
    pub fn replay(
        &self,
        from: Option<StreamCursor>,
        filter: &dyn HistoryFilter,
        max_bytes: u64,
        carried: SnapshotCarried,
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
        let mut ended = false;
        for (cursor, entry) in &self.entries {
            if cursor.get() < start {
                continue;
            }
            if !filter.admits(*cursor, entry) {
                withheld += 1;
                continue;
            }
            let bytes = encoded_bytes(entry);
            let first_of_snapshot = carried == SnapshotCarried::NOTHING && entries.is_empty();
            if !first_of_snapshot && let Some(limit) = carried.refuses(&budget, bytes) {
                continuation = Some(SemanticContinuation {
                    limit,
                    limit_value: U64::new(limit.value()),
                    from_node: U64::new(cursor.get()),
                    nodes: U64::new(budget.nodes()),
                    bytes: U64::new(budget.bytes()),
                });
                resume_at = Some(*cursor);
                ended = true;
                break;
            }
            let admitted = match budget.admit(1, bytes) {
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
            entries.push(admitted);
            consumed = *cursor;
        }
        let carried = (continuation.is_some() && !ended).then(|| carried.with(&budget));
        Ok(Replay {
            entries,
            continuation,
            history_gap,
            withheld,
            consumed,
            resume_at,
            carried,
        })
    }

    /// Resumes a log at the cursor an adapter had already consumed.
    ///
    /// A restart does not keep the entries: they are the live parser's, and section 24 says a
    /// rebuilt range shows a history gap for anything unavailable. What it does keep is the
    /// numbering, so a new entry never takes a cursor an adapter has already checkpointed past,
    /// and everything before the resume point is a gap rather than a silently empty answer. A
    /// checkpoint at the last number there is leaves the log with none to give ([`Exhausted`]).
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
            said(&mut log, format!("entry {index}"), index);
        }
        log
    }

    /// Appends one message at `at`, which every log these tests write has numbers left for.
    fn said(log: &mut SemanticLog, text: impl Into<String>, at: u64) -> StreamCursor {
        log.append("message", text, TimestampMs::new(at))
            .expect("the log has numbers left")
    }

    struct EverythingAdmitted;

    impl HistoryFilter for EverythingAdmitted {
        fn admits(&self, _cursor: StreamCursor, _entry: &AgentSnapshotEntry) -> bool {
            true
        }
    }

    /// Replays with section 8's whole allowance, which every entry these tests write fits.
    fn whole(log: &SemanticLog, from: Option<StreamCursor>, filter: &dyn HistoryFilter) -> Replay {
        log.replay(
            from,
            filter,
            MAX_SEMANTIC_SNAPSHOT_BYTES,
            SnapshotCarried::NOTHING,
        )
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
            .replay(
                None,
                &EverythingAdmitted,
                allowance,
                SnapshotCarried::NOTHING,
            )
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
        said(&mut log, "said before", 1);
        said(&mut log, large.clone(), 2);
        said(&mut log, "said after", 3);

        let before = log
            .replay(
                None,
                &EverythingAdmitted,
                ALLOWANCE,
                SnapshotCarried::NOTHING,
            )
            .expect("a part");
        assert_eq!(before.entries.len(), 1);
        assert_eq!(before.entries[0].text, "said before");
        assert_eq!(before.entries[0].omitted_text_bytes, U64::ZERO);
        assert_eq!(before.resume_at, Some(StreamCursor::new(2)));

        let cut = log
            .replay(
                Some(StreamCursor::new(1)),
                &EverythingAdmitted,
                ALLOWANCE,
                SnapshotCarried::NOTHING,
            )
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
            .replay(
                Some(cut.consumed),
                &EverythingAdmitted,
                ALLOWANCE,
                SnapshotCarried::NOTHING,
            )
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
            .replay(None, &EverythingAdmitted, 8, SnapshotCarried::NOTHING)
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
            said(&mut log, format!("entry {index}"), index);
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
        said(&mut log, large.clone(), 1_000);
        said(&mut log, large.clone(), 2_500);
        said(&mut log, large.clone(), 1_500);
        said(&mut log, large, 3_000);
        said(&mut log, "said before, last", 1_200);
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

    /// An entry number is never given twice, at the end of the numbering as anywhere else: the
    /// log gives the last number it has and refuses the entries after it, recording nothing, and
    /// a reader that consumed the last entry is given nothing again.
    #[test]
    fn an_entry_number_is_never_given_twice_at_the_end_of_the_numbering() {
        let mut log = SemanticLog::new();
        log.resume_after(StreamCursor::new(u64::MAX - 2));
        let given: Vec<Result<StreamCursor, Exhausted>> = (0..3_u64)
            .map(|index| log.append("message", format!("entry {index}"), TimestampMs::new(index)))
            .collect();
        assert_eq!(
            given,
            [
                Ok(StreamCursor::new(u64::MAX - 1)),
                Err(Exhausted),
                Err(Exhausted)
            ],
            "the last number, then refusals"
        );
        let replayed = whole(
            &log,
            Some(StreamCursor::new(u64::MAX - 2)),
            &EverythingAdmitted,
        );
        assert_eq!(replayed.entries.len(), 1, "a refused entry is not recorded");
        let after = whole(
            &log,
            Some(StreamCursor::new(u64::MAX - 1)),
            &EverythingAdmitted,
        );
        assert!(
            after.entries.is_empty(),
            "and the last one is not given again"
        );

        let mut spent = SemanticLog::new();
        spent.resume_after(StreamCursor::new(u64::MAX));
        assert_eq!(
            spent.append("message", "more", TimestampMs::new(1)),
            Err(Exhausted),
            "a checkpoint at the last number leaves none to give"
        );
    }

    /// The control: ordinary numbering is what it was, one after another from one, and from one
    /// past a resumed checkpoint.
    #[test]
    fn entries_are_numbered_one_after_another() {
        let mut log = SemanticLog::new();
        let numbers: Vec<u64> = (1..=3)
            .map(|at| said(&mut log, "entry", at).get())
            .collect();
        assert_eq!(numbers, [1, 2, 3]);
        let mut resumed = SemanticLog::new();
        resumed.resume_after(StreamCursor::new(40));
        assert_eq!(said(&mut resumed, "entry", 1).get(), 41);
        assert_eq!(resumed.next_cursor(), StreamCursor::new(42));
    }

    /// A part is paid for out of what the snapshot's earlier parts left of section 8's total, not
    /// out of a fresh total of its own: an entry that would pass it ends the snapshot with a
    /// continuation that names the total and the entry, even with the part's own allowance to
    /// spare, and the part says the snapshot has ended.
    #[test]
    fn a_part_is_paid_for_out_of_what_the_earlier_parts_left() {
        let log = log(3);
        let entry = encoded_bytes(&log.entries[0].1);
        let nearly_spent = SnapshotCarried {
            nodes: 7,
            bytes: MAX_SEMANTIC_SNAPSHOT_BYTES - entry + 1,
        };
        let part = log
            .replay(
                None,
                &EverythingAdmitted,
                MAX_SEMANTIC_SNAPSHOT_BYTES,
                nearly_spent,
            )
            .expect("a part");
        assert!(part.entries.is_empty(), "the first entry passes the total");
        let continuation = part.continuation.expect("the part says where it stopped");
        assert_eq!(continuation.limit, SemanticLimit::Bytes);
        assert_eq!(continuation.limit_value.get(), MAX_SEMANTIC_SNAPSHOT_BYTES);
        assert_eq!(continuation.from_node.get(), 1);
        assert_eq!(part.resume_at, Some(StreamCursor::new(1)));
        assert_eq!(part.carried, None, "the snapshot has ended");

        let room_for_one = SnapshotCarried {
            nodes: 7,
            bytes: MAX_SEMANTIC_SNAPSHOT_BYTES - entry,
        };
        let part = log
            .replay(
                None,
                &EverythingAdmitted,
                MAX_SEMANTIC_SNAPSHOT_BYTES,
                room_for_one,
            )
            .expect("a part");
        assert_eq!(part.entries.len(), 1, "exactly the total fits");
        assert_eq!(
            part.continuation
                .expect("the next passes it")
                .limit_value
                .get(),
            MAX_SEMANTIC_SNAPSHOT_BYTES
        );
        assert_eq!(part.carried, None);
    }

    /// A part cut by its own allowance says what the snapshot has carried with it, so the next
    /// part is paid for out of what is left; a part that carries the rest says the snapshot ended.
    #[test]
    fn a_part_cut_by_its_allowance_says_what_the_snapshot_has_carried() {
        let log = log(3);
        let first = encoded_bytes(&log.entries[0].1);
        let earlier = SnapshotCarried {
            nodes: 2,
            bytes: 100,
        };
        let part = log
            .replay(None, &EverythingAdmitted, first, earlier)
            .expect("a part");
        assert_eq!(part.entries.len(), 1);
        assert_eq!(
            part.carried,
            Some(SnapshotCarried {
                nodes: 3,
                bytes: 100 + first
            })
        );
        let rest = log
            .replay(
                Some(part.consumed),
                &EverythingAdmitted,
                MAX_SEMANTIC_SNAPSHOT_BYTES,
                part.carried.expect("the snapshot continues"),
            )
            .expect("a part");
        assert_eq!(rest.entries.len(), 2);
        assert!(rest.continuation.is_none());
        assert_eq!(rest.carried, None, "the snapshot is whole");
    }

    /// The snapshot's own first entry has the whole total to itself, so one larger than the total
    /// is carried cut in its part, as it always was, rather than ending every snapshot at itself.
    #[test]
    fn a_snapshots_first_entry_is_decided_by_its_part() {
        let mut log = SemanticLog::new();
        let large = "x".repeat(usize::try_from(MAX_SEMANTIC_SNAPSHOT_BYTES).expect("fits") + 10);
        said(&mut log, large, 1);
        let part = log
            .replay(None, &EverythingAdmitted, 1_000, SnapshotCarried::NOTHING)
            .expect("a part");
        assert_eq!(part.entries.len(), 1, "carried, cut");
        assert!(part.entries[0].omitted_text_bytes.get() > 0);
        assert!(part.continuation.is_none());
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
