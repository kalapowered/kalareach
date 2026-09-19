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
    AttentionGap, AttentionSource, ChangeSummary, LogViewState, MAX_RETAINED_LOG_VIEWS,
    MAX_VISIT_CHANGES, RetainedLogView, SemanticChange, SemanticChangeKind,
};
use kr_protocol::ids::{ActorId, SessionId};
use kr_protocol::recovery::HistoryGap;
use kr_protocol::scalars::{Nullable, TimestampMs, U64};

/// Largest number of semantic changes the host retains for one session.
pub const MAX_RETAINED_CHANGES: usize = 1_000;

/// One actor's visit.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Visit {
    /// The semantic cursor the actor has seen up to.
    pub cursor: u64,
    /// The log views it had open.
    pub views: Vec<LogViewState>,
    /// This actor's acknowledgement revision.
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
    omitted: Vec<AttentionGap>,
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

    /// Returns the ranges retention has taken.
    #[must_use]
    pub fn omitted(&self) -> &[AttentionGap] {
        &self.omitted
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
            summary,
            at_ms,
        });
        self.next_cursor = cursor.saturating_add(1);
        while self.log.len() > MAX_RETAINED_CHANGES {
            let evicted = self.log.pop_front().expect("the log is not empty");
            self.note_omitted(evicted.cursor.get(), evicted.cursor.get().saturating_add(1));
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
    pub fn summarise(&mut self, summary: ChangeSummary) {
        self.summaries
            .retain(|held| held.from_cursor != summary.from_cursor);
        self.summaries.push(summary);
        self.summaries
            .sort_by_key(|summary| summary.from_cursor.get());
    }

    /// Records one actor's visit and the views it had open.
    ///
    /// The cursor never goes backwards: a visit records how far somebody has got, and a client
    /// that reports an older position has not unseen what it saw. Returns the visit as stored.
    pub fn acknowledge(&mut self, actor: &ActorId, cursor: u64, views: Vec<LogViewState>) -> Visit {
        let visit = self.visits.entry(actor.clone()).or_default();
        visit.cursor = visit.cursor.max(cursor.min(self.next_cursor));
        visit.revision = visit.revision.saturating_add(1);
        for view in views {
            match visit
                .views
                .iter_mut()
                .find(|held| held.view_id == view.view_id)
            {
                Some(held) => *held = view,
                None => visit.views.push(view),
            }
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
        visit.clone()
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
    ) -> Changed {
        let visit = self.visits.get(actor);
        let from = visit.map_or(0, |visit| visit.cursor);
        let limit = usize::try_from(max_changes.clamp(1, MAX_VISIT_CHANGES)).unwrap_or(1);
        let mut omitted = Vec::new();
        if from < self.oldest_cursor {
            omitted.push(AttentionGap {
                source: AttentionSource::Semantic,
                from_sequence: U64::new(from),
                to_sequence: U64::new(self.oldest_cursor),
            });
        }
        let start = from.max(self.oldest_cursor);
        let changes: Vec<_> = self
            .log
            .iter()
            .filter(|change| change.cursor.get() >= start)
            .take(limit)
            .cloned()
            .collect();
        let to_cursor = changes
            .last()
            .map_or(self.next_cursor.max(start), |change| {
                change.cursor.get().saturating_add(1)
            });
        let summary = self
            .summaries
            .iter()
            .rfind(|summary| summary.to_cursor.get() <= to_cursor && summary.to_cursor.get() > from)
            .cloned();
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
        omitted: Vec<AttentionGap>,
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

    fn note_omitted(&mut self, from: u64, to: u64) {
        if let Some(last) = self.omitted.last_mut()
            && last.to_sequence.get() == from
        {
            last.to_sequence = U64::new(to);
            return;
        }
        self.omitted.push(AttentionGap {
            source: AttentionSource::Semantic,
            from_sequence: U64::new(from),
            to_sequence: U64::new(to),
        });
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
