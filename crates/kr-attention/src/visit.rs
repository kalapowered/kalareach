//! Visits, the changed-since-last-visit view and the log views an actor keeps.
//!
//! A visit is one actor's cursor into the session's semantic events. The view compares that cursor
//! with what the host still retains and answers with three separate things:
//!
//! * the authoritative changes after the cursor,
//! * the ranges retention took before the view could show them, stated as gaps,
//! * a model summary, when one exists, naming the interval it was written from.
//!
//! The three never merge. A summary is not an event and cannot stand in for one; a gap is not an
//! absence of changes but a statement that the host cannot say what was there.
//!
//! # Log views
//!
//! Section 25 keeps a log view's source offset and filtering state across a reconnect, a switch to
//! another view and a retention eviction. The host holds them per actor, keyed by the view's own
//! identifier, so switching between two views loses neither one's position. When retention has
//! moved past a retained offset the view is served from the oldest offset that still exists, and
//! the range between the two is stated as a history gap rather than quietly skipped.

use std::collections::{BTreeMap, VecDeque};

use kr_protocol::attention::{
    AttentionGap, AttentionSource, ChangeSummary, LogViewState, MAX_LOG_VIEW_FILTER_LEN,
    MAX_LOG_VIEW_ID_LEN, MAX_RETAINED_ACTORS, MAX_RETAINED_LOG_VIEWS, MAX_RETAINED_SUMMARIES,
    MAX_SUMMARY_MODEL_LEN, MAX_VISIT_CHANGES, RetainedLogView, SemanticChange, SemanticChangeKind,
};
use kr_protocol::ids::{ActorId, SessionId};
use kr_protocol::recovery::HistoryGap;
use kr_protocol::scalars::{Nullable, TimestampMs, U64};

/// Largest number of semantic changes the host retains for one session.
pub const MAX_RETAINED_CHANGES: usize = 1_000;

/// Largest number of omitted ranges the host keeps. The oldest is dropped past it.
pub const MAX_OMITTED_RANGES: usize = 64;

/// Returns `text` clipped to `bound` bytes, on a character boundary.
fn clip(text: &str, bound: usize) -> String {
    if text.len() <= bound {
        return text.to_owned();
    }
    let mut end = bound;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}

/// One range that is missing from what a visit can be shown, and where it is missing from.
///
/// Two different things are missing for two different reasons, and a reader has to be able to tell
/// them apart. Retention takes a range of this host's own change log, which is a range of local
/// cursors. An eviction in a retained *source* takes a range of that source's own sequences, and
/// the engine records it when it notices the jump; it is placed at the local cursor the host had
/// reached when it noticed, so a visit from before that point is told about it and one from after
/// is not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Omitted {
    /// The range, in the numbering of whatever it belongs to.
    pub gap: AttentionGap,
    /// The local cursor the host had reached when the range went missing.
    pub at_cursor: u64,
}

/// One actor's visit.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Visit {
    /// The semantic cursor the actor has seen up to.
    pub cursor: u64,
    /// The log views it had open.
    pub views: Vec<LogViewState>,
    /// This actor's acknowledgement revision when the visit was recorded.
    pub revision: u64,
}

/// What one changed-since-last-visit read answered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Changed {
    /// The cursor this actor had acknowledged.
    pub from_cursor: u64,
    /// The cursor to acknowledge once this view has been read.
    pub to_cursor: u64,
    /// The authoritative changes, oldest first.
    pub changes: Vec<SemanticChange>,
    /// The ranges retention took before the view could show them.
    pub omitted: Vec<AttentionGap>,
    /// Whether more changes remain past `to_cursor`.
    pub more: bool,
    /// The summary of the interval, when one covers it.
    pub summary: Option<ChangeSummary>,
    /// The log views this actor retained.
    pub views: Vec<RetainedLogView>,
}

/// The semantic change log, the visits into it and the log views beside them.
#[derive(Clone, Debug, Default)]
pub struct Visits {
    log: VecDeque<SemanticChange>,
    next_cursor: u64,
    oldest_cursor: u64,
    omitted: Vec<Omitted>,
    summaries: Vec<ChangeSummary>,
    visits: BTreeMap<ActorId, Visit>,
}

impl Visits {
    /// Builds an empty log.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the cursor the next change will be recorded at.
    #[must_use]
    pub const fn head(&self) -> u64 {
        self.next_cursor
    }

    /// Returns the oldest cursor the host can still serve.
    #[must_use]
    pub const fn oldest(&self) -> u64 {
        self.oldest_cursor
    }

    /// Returns every retained change, oldest first.
    pub fn changes(&self) -> impl Iterator<Item = &SemanticChange> {
        self.log.iter()
    }

    /// Returns every summary the host holds.
    #[must_use]
    pub fn summaries(&self) -> &[ChangeSummary] {
        &self.summaries
    }

    /// Returns every range that is missing, with where it went missing.
    #[must_use]
    pub fn omitted(&self) -> &[Omitted] {
        &self.omitted
    }

    /// Records a range a retained source lost, at the position the host had reached.
    ///
    /// The engine notices the jump; this is where it becomes visible to somebody reading what
    /// changed since their last visit. Section 25 requires the omitted range to be shown rather
    /// than closed over, and a source gap is exactly a range of events nobody can be shown.
    pub fn note_source_gap(&mut self, gap: AttentionGap) {
        if self
            .omitted
            .iter()
            .any(|held| held.gap == gap && held.at_cursor == self.next_cursor)
        {
            return;
        }
        self.push_omitted(Omitted {
            gap,
            at_cursor: self.next_cursor,
        });
    }

    /// Returns one actor's visit.
    #[must_use]
    pub fn visit(&self, actor: &ActorId) -> Option<&Visit> {
        self.visits.get(actor)
    }

    /// Returns every visit.
    #[must_use]
    pub const fn visits(&self) -> &BTreeMap<ActorId, Visit> {
        &self.visits
    }

    /// Records one semantic change and returns the cursor it was recorded at.
    ///
    /// Retention evicts the oldest change past the bound, and the range it took is recorded as an
    /// omitted range, because a client whose cursor is inside it has to be told rather than served
    /// a shorter list.
    pub fn record(
        &mut self,
        kind: SemanticChangeKind,
        session_id: SessionId,
        summary: String,
        at_ms: TimestampMs,
    ) -> u64 {
        let cursor = self.next_cursor;
        self.log.push_back(SemanticChange {
            cursor: U64::new(cursor),
            kind,
            session_id,
            summary: Nullable::some(crate::engine::clip_summary(&summary)),
            at_ms,
        });
        self.next_cursor = cursor.saturating_add(1);
        while self.log.len() > MAX_RETAINED_CHANGES {
            let evicted = self.log.pop_front().expect("the log is not empty");
            self.note_evicted(evicted.cursor.get(), evicted.cursor.get().saturating_add(1));
        }
        self.oldest_cursor = self
            .log
            .front()
            .map_or(self.next_cursor, |change| change.cursor.get());
        cursor
    }

    /// Records a model summary of one interval.
    ///
    /// It is held beside the changes, never merged into them. A summary names the interval it was
    /// written from so a reader can see what it did and did not cover.
    pub fn summarise(&mut self, mut summary: ChangeSummary) {
        summary.text = crate::engine::clip_summary(&summary.text);
        summary.model = clip(&summary.model, MAX_SUMMARY_MODEL_LEN);
        self.summaries
            .retain(|held| held.from_cursor != summary.from_cursor);
        self.summaries.push(summary);
        self.summaries
            .sort_by_key(|summary| summary.from_cursor.get());
        // A summary is a convenience beside the events, so the oldest goes first once the host
        // holds more than it is prepared to write down.
        while self.summaries.len() > MAX_RETAINED_SUMMARIES {
            self.summaries.remove(0);
        }
    }

    /// Records one actor's visit and the views it had open.
    ///
    /// The cursor never goes backwards: a visit records how far somebody has got, and a client
    /// that reports an older position has not unseen what it saw. Returns the visit as stored.
    pub fn acknowledge(
        &mut self,
        actor: &ActorId,
        cursor: u64,
        views: Vec<LogViewState>,
        revision: u64,
    ) -> Visit {
        let visit = self.visits.entry(actor.clone()).or_default();
        visit.cursor = visit.cursor.max(cursor.min(self.next_cursor));
        visit.revision = revision;
        for view in views {
            // A view identifier and a filter are the client's own text, and the host writes both
            // down and gives them back. A filter past its bound is refused where the request is
            // read; anything that reaches here is clipped so a stored view cannot grow past what
            // the store and the answer can carry.
            let view = LogViewState {
                view_id: clip(&view.view_id, MAX_LOG_VIEW_ID_LEN),
                filter: clip(&view.filter, MAX_LOG_VIEW_FILTER_LEN),
                ..view
            };
            // A view that is updated moves to the newest position. Leaving it where it was would
            // make the bound below evict the view a client had just used.
            visit.views.retain(|held| held.view_id != view.view_id);
            visit.views.push(view);
        }
        // The bound drops the view that was updated longest ago, which is the one a client is
        // least likely to return to. A client with more open views than the bound keeps the ones
        // it touched last.
        let over = visit
            .views
            .len()
            .saturating_sub(usize::try_from(MAX_RETAINED_LOG_VIEWS).unwrap_or(usize::MAX));
        if over > 0 {
            visit.views.drain(0..over);
        }
        let answer = visit.clone();
        self.enforce_actor_bound(actor);
        answer
    }

    /// Keeps the visits inside [`MAX_RETAINED_ACTORS`], never letting go of the one just recorded.
    ///
    /// What goes is the actor whose revision is lowest, which is the one that has acknowledged
    /// least recently. An actor whose visit has gone is an actor with no visit, which is where
    /// every actor starts.
    fn enforce_actor_bound(&mut self, keep: &ActorId) {
        while self.visits.len() > MAX_RETAINED_ACTORS {
            let Some(oldest) = self
                .visits
                .iter()
                .filter(|(actor, _)| *actor != keep)
                .min_by(|left, right| {
                    left.1
                        .revision
                        .cmp(&right.1.revision)
                        .then_with(|| left.0.cmp(right.0))
                })
                .map(|(actor, _)| actor.clone())
            else {
                break;
            };
            self.visits.remove(&oldest);
        }
    }

    /// Answers what changed since one actor's last visit.
    ///
    /// `oldest_output_cursor` is the oldest output the host can still replay, which is what decides
    /// whether a retained log view can still be served from where it was left.
    #[must_use]
    pub fn changed_since(
        &self,
        actor: &ActorId,
        max_changes: u64,
        oldest_output_cursor: u64,
        content: crate::engine::Content,
    ) -> Changed {
        let visit = self.visits.get(actor);
        let from = visit.map_or(0, |visit| visit.cursor);
        let limit = usize::try_from(max_changes.clamp(1, MAX_VISIT_CHANGES)).unwrap_or(1);
        let mut omitted: Vec<AttentionGap> = self
            .omitted
            .iter()
            .filter(|held| held.at_cursor >= from)
            .map(|held| held.gap)
            .collect();
        if from < self.oldest_cursor {
            omitted.push(AttentionGap {
                source: AttentionSource::Semantic,
                from_sequence: U64::new(from),
                to_sequence: U64::new(self.oldest_cursor),
            });
        }
        omitted.dedup();
        let start = from.max(self.oldest_cursor);
        let changes: Vec<_> = self
            .log
            .iter()
            .filter(|change| change.cursor.get() >= start)
            .take(limit)
            .map(|change| SemanticChange {
                summary: Nullable(
                    (content == crate::engine::Content::Whole)
                        .then(|| change.summary.as_ref().cloned())
                        .flatten(),
                ),
                ..change.clone()
            })
            .collect();
        let to_cursor = changes
            .last()
            .map_or(self.next_cursor.max(start), |change| {
                change.cursor.get().saturating_add(1)
            });
        // A model summary is written from the session's own content, so it goes where the text
        // goes: a caller served the host's record without the text is not served a paraphrase of
        // it either.
        let summary = (content == crate::engine::Content::Whole)
            .then(|| {
                self.summaries
                    .iter()
                    .rfind(|summary| {
                        summary.to_cursor.get() <= to_cursor && summary.to_cursor.get() > from
                    })
                    .cloned()
            })
            .flatten();
        Changed {
            from_cursor: from,
            to_cursor,
            changes,
            omitted,
            more: self.next_cursor > to_cursor,
            summary,
            views: self.retained_views(visit, oldest_output_cursor),
        }
    }

    /// Installs restored state.
    pub(crate) fn install(
        &mut self,
        log: VecDeque<SemanticChange>,
        next_cursor: u64,
        omitted: Vec<Omitted>,
        summaries: Vec<ChangeSummary>,
        visits: BTreeMap<ActorId, Visit>,
    ) {
        self.oldest_cursor = log
            .front()
            .map_or(next_cursor, |change| change.cursor.get());
        self.log = log;
        self.next_cursor = next_cursor;
        self.omitted = omitted;
        self.summaries = summaries;
        self.visits = visits;
    }

    /// Records a range of this host's own change log that retention took.
    fn note_evicted(&mut self, from: u64, to: u64) {
        if let Some(last) = self.omitted.last_mut()
            && last.gap.source == AttentionSource::Semantic
            && last.at_cursor == last.gap.from_sequence.get()
            && last.gap.to_sequence.get() == from
        {
            last.gap.to_sequence = U64::new(to);
            return;
        }
        self.push_omitted(Omitted {
            gap: AttentionGap {
                source: AttentionSource::Semantic,
                from_sequence: U64::new(from),
                to_sequence: U64::new(to),
            },
            at_cursor: from,
        });
    }

    fn push_omitted(&mut self, omitted: Omitted) {
        self.omitted.push(omitted);
        if self.omitted.len() > MAX_OMITTED_RANGES {
            self.omitted.remove(0);
        }
    }

    fn retained_views(
        &self,
        visit: Option<&Visit>,
        oldest_output_cursor: u64,
    ) -> Vec<RetainedLogView> {
        visit
            .map(|visit| visit.views.clone())
            .unwrap_or_default()
            .into_iter()
            .map(|view| {
                if view.source_offset.get() >= oldest_output_cursor {
                    return RetainedLogView {
                        view,
                        requested_offset: Nullable::null(),
                        gap: Nullable::null(),
                    };
                }
                // Retention moved past where this view was reading. The filter is kept, the offset
                // is moved to the oldest byte that still exists, and the range between the two is
                // stated so the client does not read the next byte as the one after its last.
                let requested = view.source_offset;
                RetainedLogView {
                    view: LogViewState {
                        source_offset: U64::new(oldest_output_cursor),
                        ..view
                    },
                    requested_offset: Nullable::some(requested),
                    gap: Nullable::some(HistoryGap {
                        from_cursor: requested,
                        to_cursor: U64::new(oldest_output_cursor),
                    }),
                }
            })
            .collect()
    }
}
