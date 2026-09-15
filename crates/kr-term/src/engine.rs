//! The terminal engine: one parse, one policy decision, one canonical state, one responder.
//!
//! [`Engine::feed`] is the whole output path. Bytes go in; what comes out is a list of spans that
//! may be forwarded unchanged, the side effects that need routing, the diagnostics that need
//! publishing, and a canonical grid that has been updated exactly once. Replies go to the trusted
//! lane, where the session loop picks them up on its own schedule.
//!
//! Nothing in here is optional at runtime. There is no path that skips the policy decision, no
//! path that hands the grid a sequence policy refused, and no path that sends a query onwards.
//!
//! One rule is worth stating on its own. When the canonical grid does not understand a sequence
//! the class table approved, the engine consumes it: the grid does not apply it and the bytes are
//! not forwarded. Half-understanding a sequence is worse than refusing it, because the canonical
//! screen and the physical terminal would then disagree about what happened.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crate::broker::{BrokerState, CanonicalReport, ColourOperation, INDEXED_BASE, QueryBroker};
use crate::budget::{GridSize, SessionBudget};
use crate::class::SequenceClass;
use crate::classify::{CsiView, MODE_WIN32_INPUT};
use crate::diag::{Diagnostic, DiagnosticKind, DiagnosticSink};
use crate::error::{Result, TermError};
use crate::event::{DirectDisposition, Event, EventKind};
use crate::grid::{CanonicalGrid, GridConfig, GridRow};
use crate::lane::{LaneDegradation, LaneLimits, ResponseLane};
use crate::lexer::{LexLimits, Lexer};
use crate::modes::{ModeKind, ModeState};
use crate::palette::{DynamicColour, Palette, PaletteSource};
use crate::policy::{Backend, Policy};
use crate::profile::Profile;
use crate::sideeffect::{LeaseHolder, SideEffect, SideEffectRefusal};
use crate::snapshot::{
    ActiveBuffer, Charsets, CursorState, Delta, HistoryPage, HyperlinkRange, KeyboardSnapshot,
    Margins, ModeEntry, PaletteSnapshot, Snapshot, Viewport,
};
use crate::span::ByteSpan;
use crate::span::SeqBytes;
use crate::title::{TitleState, TitleTarget};

/// Where an untrusted observation came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObservationSource {
    /// OSC 7, the working directory.
    WorkingDirectory,
    /// OSC 133, the FinalTerm prompt and command boundaries.
    PromptBoundary,
    /// OSC 633, the VS Code shell integration.
    ShellIntegration,
    /// OSC 1337, the iTerm2 metadata keys.
    TerminalMetadata,
}

/// Something an application said about itself.
///
/// Section 8 is explicit that these are observations and nothing more. A working directory an
/// application printed cannot establish a filesystem grant, and a prompt marker cannot stand in for
/// an authenticated editor event. They are carried because a projection and a person find them
/// useful, and they are labelled so nothing downstream mistakes them for authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    /// Which convention produced it.
    pub source: ObservationSource,
    /// The subcommand or key.
    pub key: String,
    /// The value, bounded.
    pub value: String,
    /// Output-stream offset of the sequence that carried it.
    pub at: u64,
}

/// The longest observation value the engine keeps.
const MAX_OBSERVATION_BYTES: usize = 512;

/// How one session is configured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EngineConfig {
    /// Starting dimensions.
    pub size: GridSize,
    /// The profile.
    pub profile: Profile,
    /// The policy.
    pub policy: Policy,
    /// The lexer bounds.
    pub lex: LexLimits,
    /// The grid configuration.
    pub grid: GridConfig,
    /// The response-lane bounds.
    pub lane: LaneLimits,
    /// Where the session's initial palette comes from.
    pub palette_source: PaletteSource,
}

impl EngineConfig {
    /// The defaults: an invisible session's 120 by 40 grid under the kr-vt/1 profile.
    pub const DEFAULT: Self = Self {
        size: crate::budget::DEFAULT_SIZE,
        profile: Profile::KR_VT_1,
        policy: Policy::DEFAULT,
        lex: LexLimits::DEFAULT,
        grid: GridConfig::DEFAULT,
        lane: LaneLimits::DEFAULT,
        palette_source: PaletteSource::ProfileDefault,
    };
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// What one call to [`Engine::feed`] produced.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct FeedOutcome {
    /// How many events the lexer produced.
    pub events: usize,
    /// Spans whose original bytes a direct-mode attachment may forward unchanged.
    pub forward: Vec<ByteSpan>,
    /// Where the attachment must move to projected mode, when something arrived that direct mode
    /// cannot carry.
    pub projection_required_at: Option<u64>,
    /// Side effects to route.
    pub side_effects: Vec<SideEffect>,
    /// Side effects policy refused.
    pub refusals: Vec<SideEffectRefusal>,
    /// Diagnostics to publish out of band.
    pub diagnostics: Vec<Diagnostic>,
    /// Untrusted observations the output carried.
    pub observations: Vec<Observation>,
    /// Replies accepted by the response lane.
    pub responses: usize,
    /// The most recent parser-ground boundary, when the parser reached one.
    pub ground_boundary: Option<u64>,
    /// How the lane is shedding load.
    pub degradation: LaneDegradation,
    /// Whether the projection generation advanced, which resets a client's projection.
    pub projection_reset: bool,
    /// Whether resident state is over one of its bounds.
    pub resident_pressure: ResidentPressure,
}

/// Which resident-state bounds are currently exceeded.
///
/// Both are degradations rather than failures. The session keeps running while the grid evicts
/// historical rows back under the cache bound; a caller that watches these reports pressure and,
/// for a session that stays over, can detach rather than grow without limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ResidentPressure {
    /// The historical row cache is over its own bound.
    pub row_cache: bool,
    /// Committed usage is over the whole session budget.
    pub session: bool,
}

impl ResidentPressure {
    /// Whether any bound is exceeded.
    #[must_use]
    pub const fn any(self) -> bool {
        self.row_cache || self.session
    }
}

/// The revisions a delta compares against.
///
/// A revision is a counter rather than a flag, so two clients reading deltas from two different
/// bases never clear each other's changes. Nothing has to be acknowledged, and nothing is lost if
/// one client is slower than the other.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Revisions {
    any: u64,
    title: u64,
    palette: u64,
    dimensions: u64,
    keyboard: u64,
    presentation: u64,
}

/// One point a delta may be built against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Checkpoint {
    cursor: u64,
    seqno: usize,
    generation: u64,
    revisions: Revisions,
}

/// How many checkpoints the replay window keeps.
///
/// A client that has fallen further behind than this is told to take a fresh snapshot, which is
/// cheaper than reasoning about what it might have missed.
const REPLAY_WINDOW: usize = 64;

/// How often the retained-row measurement runs, in calls to [`Engine::feed`].
///
/// Measuring means walking the scrollback, so doing it on every read would cost more than the bound
/// it enforces. Every 64 reads is often enough that the cache overshoots by a fraction of itself.
const ROW_CACHE_INTERVAL: u32 = 64;

/// How many rows the scrollback may gain or lose before it is measured again, whatever the read
/// count says.
const ROW_CACHE_ROW_STEP: usize = 32;

/// How many times eviction re-measures before leaving the rest to the next read.
const EVICTION_PASSES: u32 = 4;

/// How many rows a history page builds at a time before checking its byte bound.
const PAGE_BATCH_ROWS: usize = 32;

/// The terminal engine for one session.
#[derive(Debug)]
pub struct Engine {
    lexer: Lexer,
    policy: Policy,
    profile: Profile,
    grid: CanonicalGrid,
    broker: QueryBroker,
    lane: ResponseLane,
    modes: ModeState,
    titles: TitleState,
    palette: Palette,
    diagnostics: DiagnosticSink,
    budget: SessionBudget,
    lease: LeaseHolder,
    projection_generation: u64,
    cursor_style: u32,
    links: BTreeSet<String>,
    checkpoints: VecDeque<Checkpoint>,
    revision: u64,
    mode_revisions: BTreeMap<(ModeKind, u16), u64>,
    title_revision: u64,
    palette_revision: u64,
    dimensions_revision: u64,
    presentation_revision: u64,
    measured_rows: usize,
    measure_now: bool,
    dropped_marks: u64,
    keyboard_revision: u64,
    feeds: u32,
    scratch: Vec<Event>,
}

impl Engine {
    /// Builds an engine.
    ///
    /// # Errors
    ///
    /// Returns [`TermError::Geometry`] for dimensions outside the three simultaneous constraints,
    /// and [`TermError::Budget`] when the screens would not fit.
    pub fn new(config: EngineConfig) -> Result<Self> {
        let mut budget = SessionBudget::new();
        let grid = CanonicalGrid::new(config.size, config.grid, &mut budget)?;
        let mut engine = Self {
            lexer: Lexer::with_limits(config.lex),
            policy: config.policy,
            profile: config.profile,
            grid,
            broker: QueryBroker::new(),
            lane: ResponseLane::with_limits(config.lane),
            modes: ModeState::new(),
            titles: TitleState::new(),
            palette: Palette::new(config.palette_source),
            diagnostics: DiagnosticSink::new(),
            budget,
            lease: LeaseHolder::none(),
            projection_generation: 1,
            cursor_style: 1,
            links: BTreeSet::new(),
            checkpoints: VecDeque::new(),
            revision: 0,
            mode_revisions: BTreeMap::new(),
            title_revision: 0,
            palette_revision: 0,
            dimensions_revision: 0,
            presentation_revision: 0,
            measured_rows: 0,
            measure_now: false,
            dropped_marks: 0,
            keyboard_revision: 0,
            feeds: 0,
            scratch: Vec::new(),
        };
        engine.record_checkpoint();
        Ok(engine)
    }

    /// Adopts a palette the client shared during the bounded probe.
    pub fn adopt_palette(&mut self, palette: Palette) {
        self.palette = palette;
        self.palette_revision = self.next_revision();
    }

    /// Advances the change counter and returns its new value.
    fn next_revision(&mut self) -> u64 {
        self.revision = self.revision.saturating_add(1);
        self.revision
    }

    /// Records that one mode changed.
    fn mark_mode(&mut self, kind: ModeKind, mode: u16) {
        let revision = self.next_revision();
        self.mode_revisions.insert((kind, mode), revision);
    }

    /// Records who holds the input lease, which is the default destination for a side effect.
    pub const fn set_lease_holder(&mut self, lease: LeaseHolder) {
        self.lease = lease;
    }

    /// The profile in force.
    #[must_use]
    pub const fn profile(&self) -> Profile {
        self.profile
    }

    /// The tracked modes.
    #[must_use]
    pub const fn modes(&self) -> &ModeState {
        &self.modes
    }

    /// The canonical palette.
    #[must_use]
    pub const fn palette(&self) -> &Palette {
        &self.palette
    }

    /// The titles and the virtual stack.
    #[must_use]
    pub const fn titles(&self) -> &TitleState {
        &self.titles
    }

    /// The canonical grid.
    #[must_use]
    pub const fn grid(&self) -> &CanonicalGrid {
        &self.grid
    }

    /// The response lane.
    #[must_use]
    pub const fn lane(&self) -> &ResponseLane {
        &self.lane
    }

    /// The response lane, for draining.
    pub const fn lane_mut(&mut self) -> &mut ResponseLane {
        &mut self.lane
    }

    /// The resource budget.
    #[must_use]
    pub const fn budget(&self) -> &SessionBudget {
        &self.budget
    }

    /// The monotonic output cursor: the point every delivered event has reached.
    ///
    /// This is the cursor a snapshot, a delta base and a live-forwarding handoff all refer to. It
    /// lags [`Engine::read_offset`] by whatever the parser is still collecting, so a client never
    /// holds a cursor for output it has not been given.
    #[must_use]
    pub fn output_cursor(&self) -> u64 {
        self.lexer.committed_offset()
    }

    /// How many bytes of the session's output have been read.
    #[must_use]
    pub const fn read_offset(&self) -> u64 {
        self.lexer.offset()
    }

    /// The current projection generation.
    #[must_use]
    pub const fn projection_generation(&self) -> u64 {
        self.projection_generation
    }

    /// Whether the parser is standing on ground right now.
    #[must_use]
    pub fn at_ground(&self) -> bool {
        self.lexer.at_ground()
    }

    /// The output cursor of a parser-ground boundary, when the parser is on one.
    ///
    /// The boundary is the committed cursor, not the read offset: forwarding may only resume where
    /// every byte before it has already been delivered.
    #[must_use]
    pub fn ground_boundary(&self) -> Option<u64> {
        if self.lexer.at_ground() {
            Some(self.lexer.committed_offset())
        } else {
            None
        }
    }

    /// Feeds application output through the engine.
    pub fn feed(&mut self, bytes: &[u8], now_ms: u64) -> FeedOutcome {
        let mut events = core::mem::take(&mut self.scratch);
        events.clear();
        self.lexer.feed(bytes, &mut events);
        self.feeds = self.feeds.wrapping_add(1);
        let outcome = self.consume(&events, now_ms);
        self.scratch = events;
        outcome
    }

    /// Settles the screen when the stream has gone quiet.
    ///
    /// The lexer holds back the last scalar of a text run so that a combining mark in the next read
    /// still joins it. This releases that scalar. The session loop calls it when a read returns
    /// nothing, and a snapshot calls it itself, so a quiet stream never leaves a character held.
    pub fn quiesce(&mut self, now_ms: u64) -> FeedOutcome {
        let mut events = core::mem::take(&mut self.scratch);
        events.clear();
        self.lexer.flush_tail(&mut events);
        let outcome = self.consume(&events, now_ms);
        self.scratch = events;
        outcome
    }

    /// Closes the stream, flushing any incomplete scalar or control string.
    pub fn close(&mut self, now_ms: u64) -> FeedOutcome {
        let mut events = core::mem::take(&mut self.scratch);
        events.clear();
        self.lexer.close(&mut events);
        let outcome = self.consume(&events, now_ms);
        self.scratch = events;
        outcome
    }

    fn consume(&mut self, events: &[Event], now_ms: u64) -> FeedOutcome {
        let mut outcome = FeedOutcome {
            events: events.len(),
            ..FeedOutcome::default()
        };
        let generation_before = self.projection_generation;
        for event in events {
            // A control inside a sequence is performed where it appeared, before the sequence it
            // was found in, which is the order a terminal performs them in. The bytes stop here
            // whatever the sequence around them turns out to be, so the attachment has to project:
            // a direct terminal never saw the controls, and its cursor is now somewhere else.
            if !event.embedded.is_empty() {
                self.apply_embedded(event, &mut outcome, now_ms);
                outcome
                    .projection_required_at
                    .get_or_insert(event.span.start());
            }
            let decision = self.policy.decide(event);
            let mut disposition = decision.disposition;
            if decision.apply_to_grid {
                // The primary buffer's rows are not reachable while the alternate buffer is
                // showing, so they are measured before the switch rather than after it.
                if !self.grid.alternate_active() && enters_alternate(&event.kind) {
                    self.measure_now = true;
                    self.enforce_resident_state(now_ms);
                }
                if self.link_budget_exceeded(event) {
                    self.diagnostics.record(
                        DiagnosticKind::ResidentStateTruncated,
                        event.span.start(),
                        now_ms,
                        "the session hyperlink table is full; the link is not recorded",
                    );
                    disposition = DirectDisposition::Withhold;
                } else {
                    let adapted = self.grid.apply(event);
                    if adapted.clamped {
                        // The grid did what it could rather than what the sequence said, so the
                        // original bytes would take a physical terminal somewhere else.
                        disposition = DirectDisposition::RequireProjection;
                        self.diagnostics.record(
                            DiagnosticKind::UnclassifiedSequence,
                            event.span.start(),
                            now_ms,
                            "a parameter was reduced to what the grid can act on",
                        );
                    }
                    // Anything but printed text can move a margin, change the pen, a tab stop or a
                    // character set, and a delta has to carry those for a client to repaint from.
                    if !matches!(
                        event.kind,
                        EventKind::Text { .. } | EventKind::Replacement { .. }
                    ) {
                        self.presentation_revision = self.next_revision();
                    }
                    self.report_truncation(event, &mut outcome, now_ms);
                    if adapted.unrecognised {
                        // The class table approved it and the canonical grid does not know it.
                        // Consuming it keeps the two screens in step.
                        self.diagnostics.record(
                            DiagnosticKind::UnclassifiedSequence,
                            event.span.start(),
                            now_ms,
                            "the canonical grid does not implement this sequence",
                        );
                        disposition = DirectDisposition::Withhold;
                    } else if decision.track {
                        self.track(event, &mut outcome);
                    }
                }
            } else if decision.track {
                self.track(event, &mut outcome);
            }
            if decision.apply_to_grid {
                if restores_cursor(&event.kind) {
                    self.follow_cursor_restore(&mut outcome, event.span.start());
                }
                self.sync_grid_modes();
            }
            if decision.answer {
                outcome.responses += self.answer_query(event, now_ms);
            }
            // Colour requests are applied here whether they ask anything or not, because a request
            // may interleave mutations and questions and every question is about the palette as it
            // stands at that point in the request.
            if decision.answer || decision.track {
                outcome.responses += self.apply_colours(event, now_ms);
            }
            if let Some(selection) = decision.clipboard_answer {
                let response = self.broker.clipboard_answer(selection, event.span.start());
                if self.lane.offer(response, now_ms) {
                    outcome.responses += 1;
                }
            }
            if let Some(kind) = decision.side_effect {
                outcome.side_effects.push(SideEffect {
                    kind,
                    destination: self.lease.destination(),
                    at: event.span.start(),
                });
                if self.lease.attachment.is_none() {
                    self.diagnostics.record(
                        DiagnosticKind::SideEffectWithoutDestination,
                        event.span.start(),
                        now_ms,
                        "no input lease; recorded as a host event",
                    );
                }
            }
            if let Some(refusal) = decision.refusal {
                outcome.refusals.push(refusal);
            }
            if let Some((kind, detail)) = decision.diagnostic {
                self.diagnostics
                    .record(kind, event.span.start(), now_ms, detail);
            }
            match disposition {
                DirectDisposition::Forward => push_span(&mut outcome.forward, event.span),
                DirectDisposition::RequireProjection => {
                    outcome
                        .projection_required_at
                        .get_or_insert(event.span.start());
                }
                DirectDisposition::Withhold => {}
            }
        }
        let degradation = self.lane.degradation();
        if degradation.is_degraded() {
            self.diagnostics.record(
                DiagnosticKind::ResponseLaneDegraded,
                self.lexer.offset(),
                now_ms,
                format!(
                    "coalesced {}, dropped {}, over budget {}, oversized {}, expired {}",
                    degradation.coalesced,
                    degradation.dropped,
                    degradation.over_budget,
                    degradation.oversized,
                    degradation.expired
                ),
            );
        }
        self.enforce_resident_state(now_ms);
        self.record_checkpoint();
        outcome.degradation = degradation;
        outcome.resident_pressure = self.resident_pressure();
        outcome.diagnostics = self.diagnostics.drain();
        outcome.ground_boundary = self.ground_boundary();
        outcome.projection_reset = self.projection_generation != generation_before;
        outcome
    }

    /// Performs the controls that arrived inside a sequence.
    ///
    /// Each one is decided on its own, so a bell inside a cursor movement still reaches the lease
    /// holder and a line feed still moves the screen. The bytes of the sequence they were found in
    /// are not forwarded, so nothing performs them a second time.
    fn apply_embedded(&mut self, event: &Event, outcome: &mut FeedOutcome, now_ms: u64) {
        for byte in event.embedded.clone() {
            let inner = Event {
                span: event.span,
                bytes: SeqBytes::new(&[byte]),
                kind: EventKind::Control { byte },
                class: crate::classify::classify(&EventKind::Control { byte }),
                disposition: DirectDisposition::Withhold,
                ground_after: false,
                passthrough_depth: event.passthrough_depth,
                eight_bit_introducer: false,
                embedded: Vec::new(),
            };
            let decision = self.policy.decide(&inner);
            if decision.apply_to_grid {
                self.grid.apply(&inner);
                self.revision = self.next_revision();
            }
            if let Some(kind) = decision.side_effect {
                outcome.side_effects.push(SideEffect {
                    kind,
                    destination: self.lease.destination(),
                    at: inner.span.start(),
                });
            }
            if let Some((kind, detail)) = decision.diagnostic {
                self.diagnostics
                    .record(kind, inner.span.start(), now_ms, detail);
            }
        }
    }

    /// Copies back the modes the canonical grid changes on its own.
    ///
    /// A cursor restore, a soft reset and a buffer switch all change these inside the reducer
    /// without a set or reset sequence of their own, so a tracker that only watched sequences would
    /// report state the grid is not using, and the cursor report would name the wrong row. The grid
    /// is the one that draws, so the grid is the answer.
    ///
    /// This runs after the event has been tracked, because the tracker would otherwise write the
    /// sequence's own parameter over what the reducer just did.
    fn sync_grid_modes(&mut self) {
        for (kind, mode, value) in [
            (ModeKind::Dec, 6, self.grid.origin_mode()),
            (ModeKind::Dec, 7, self.grid.auto_wrap()),
            (ModeKind::Dec, 69, self.grid.margin_mode()),
            (ModeKind::Ansi, 4, self.grid.insert_mode()),
        ] {
            if self.modes.is_set(kind, mode) != value {
                self.modes.set(kind, mode, value);
                self.mark_mode(kind, mode);
            }
        }
    }

    /// Follows the reducer's cursor restore for the state it changes without exposing.
    ///
    /// The pinned revision clears newline mode and the shift-out selection when it restores a
    /// cursor, which xterm does not, and it does not expose newline mode for reading back. The
    /// profile applies the same rule so that there is one answer, and asks for projection when that
    /// changes something, because a physical terminal following the same bytes would not have done
    /// it. The narrow patch is recorded in `crate::unicode::LIBRARY`.
    fn follow_cursor_restore(&mut self, outcome: &mut FeedOutcome, at: u64) {
        if self.modes.is_set(ModeKind::Ansi, 20) {
            self.modes.set(ModeKind::Ansi, 20, false);
            self.mark_mode(ModeKind::Ansi, 20);
            outcome.projection_required_at.get_or_insert(at);
        }
    }

    /// Whether recording this event's hyperlink would pass the session's bound.
    ///
    /// What is counted is the whole link, parameters included. The identifier parameter is retained
    /// alongside the target and is the part an application controls most freely, so counting only
    /// the target would let a program hold megabytes of identifiers inside a budget that says it is
    /// using nothing.
    fn link_budget_exceeded(&mut self, event: &Event) -> bool {
        let EventKind::Osc {
            selector: Some(8),
            parts,
        } = &event.kind
        else {
            return false;
        };
        if parts.len() < 3 {
            return false;
        }
        // A URI may contain the separator, so everything after the parameter field is the target.
        let uri = parts[2..].join(&b';');
        if uri.is_empty() {
            return false;
        }
        let parameters = String::from_utf8_lossy(&parts[1]).into_owned();
        let uri = format!("{parameters};{}", String::from_utf8_lossy(&uri));
        // One link has a length bound of its own, separate from how many distinct links a session
        // keeps. Every cell inside a link holds a reference to it, so an application that opens a
        // link with a megabyte of identifier in it once a row would hold a megabyte a row, and the
        // table of distinct targets would count that as one link.
        if uri.len() > self.budget.limits().link_bytes {
            self.budget.record_truncation();
            return true;
        }
        if self.links.contains(&uri) {
            return false;
        }
        let cost = uri.len() as u64;
        if self.links.len() >= self.budget.limits().unique_links || !self.budget.metadata_fits(cost)
        {
            self.budget.record_truncation();
            return true;
        }
        let metadata = self.budget.usage().metadata + cost;
        self.budget.set_metadata(metadata);
        self.links.insert(uri);
        false
    }

    /// Reports content the grid could not keep whole.
    ///
    /// A cell has a content bound, and combining marks past it are dropped rather than allowed to
    /// grow one cell without limit. That is a degradation and not a silent one: the caller is told,
    /// and the attachment projects, because a physical terminal reading the same bytes would have
    /// kept them and the two screens would otherwise disagree.
    fn report_truncation(&mut self, event: &Event, outcome: &mut FeedOutcome, now_ms: u64) {
        let dropped = self.grid.dropped_marks();
        if dropped == self.dropped_marks {
            return;
        }
        self.dropped_marks = dropped;
        self.budget.record_truncation();
        self.diagnostics.record(
            DiagnosticKind::ResidentStateTruncated,
            event.span.start(),
            now_ms,
            "a cell reached its content bound; the marks past it were dropped",
        );
        outcome
            .projection_required_at
            .get_or_insert(event.span.start());
    }

    /// Measures and enforces the resident-state bounds.
    ///
    /// Measuring the retained rows means walking the scrollback, so it is not done on every read.
    /// Counting them is cheap, though, so a read that added rows is measured however few reads have
    /// happened: one read can carry a megabyte, and waiting for the next sixty-three would let the
    /// cache grow far past its bound before anyone looked.
    ///
    /// While the alternate buffer is active the primary buffer's history is not reachable and is
    /// not changing either, so the last measurement of it stands rather than being replaced by the
    /// alternate buffer's nothing.
    fn enforce_resident_state(&mut self, now_ms: u64) {
        let rows = self.grid.scrollback_rows();
        let grew = rows.abs_diff(self.measured_rows) >= ROW_CACHE_ROW_STEP;
        if !grew && !self.measure_now && !self.feeds.is_multiple_of(ROW_CACHE_INTERVAL) {
            return;
        }
        self.measure_now = false;
        self.measured_rows = rows;
        if self.grid.alternate_active() {
            return;
        }
        let mut bytes = self.grid.history_bytes();
        let limit = self.budget.limits().row_cache_bytes;
        let mut evicted = false;
        // The row count to keep is worked out from the average cost of a row, and the rows are not
        // all the same size, so one pass can land just over the bound. A few passes converge; the
        // count is bounded so a pathological row cannot make this loop.
        for _ in 0..EVICTION_PASSES {
            if !self.grid.enforce_row_cache(bytes, limit) {
                break;
            }
            evicted = true;
            bytes = self.grid.history_bytes();
        }
        if evicted {
            self.measured_rows = self.grid.scrollback_rows();
            self.diagnostics.record(
                DiagnosticKind::ResidentStateTruncated,
                self.lexer.offset(),
                now_ms,
                format!("historical rows passed the {limit}-byte cache bound; older rows evicted"),
            );
        }
        self.budget.set_row_cache(bytes);
    }

    /// Whether resident state is over one of its bounds right now.
    ///
    /// This is a degradation, not an error: the session keeps working while the grid evicts rows
    /// back under the bound. It is reported on every feed, where a rate-limited diagnostic would
    /// be suppressed and the caller would see nothing.
    fn resident_pressure(&self) -> ResidentPressure {
        ResidentPressure {
            row_cache: self.budget.row_cache_over_budget(),
            session: self.budget.session_over_budget(),
        }
    }

    fn record_checkpoint(&mut self) {
        let checkpoint = Checkpoint {
            cursor: self.lexer.committed_offset(),
            seqno: self.grid.sequence_number(),
            generation: self.projection_generation,
            revisions: self.revisions(),
        };
        // A cursor can repeat while the screen moves on: a held cell keeps the committed cursor
        // still, and state can change with no bytes at all. The earliest state seen at a cursor is
        // the one kept, because a delta built against a later one would leave out everything that
        // happened in between, and a client that already has some of what a delta carries loses
        // nothing by being told again.
        if self.checkpoints.back().map(|last| last.cursor) == Some(checkpoint.cursor) {
            return;
        }
        if self.checkpoints.len() == REPLAY_WINDOW {
            self.checkpoints.pop_front();
        }
        self.checkpoints.push_back(checkpoint);
    }

    const fn revisions(&self) -> Revisions {
        Revisions {
            any: self.revision,
            title: self.title_revision,
            palette: self.palette_revision,
            dimensions: self.dimensions_revision,
            keyboard: self.keyboard_revision,
            presentation: self.presentation_revision,
        }
    }

    fn canonical_report(&self) -> CanonicalReport {
        let (col, row) = self.grid.cursor();
        let (top, bottom) = self.grid.margins_vertical();
        let (left, right) = self.grid.margins_horizontal();
        let size = self.grid.size();
        CanonicalReport {
            cursor_row: row + 1,
            cursor_col: col + 1,
            rows: size.rows,
            cols: size.cols,
            margin_top: top + 1,
            margin_bottom: bottom + 1,
            margin_left: left + 1,
            margin_right: right + 1,
            origin_mode: self.grid.origin_mode(),
            cursor_style: self.cursor_style,
        }
    }

    /// Answers a query event and queues the replies.
    fn answer_query(&mut self, event: &Event, now_ms: u64) -> usize {
        let sgr = self.grid.sgr_parameters();
        let responses = {
            let state = BrokerState {
                modes: &self.modes,
                palette: &self.palette,
                report: self.canonical_report(),
                sgr: &sgr,
            };
            self.broker.answer(event, &state)
        };
        let mut accepted = 0;
        for response in responses {
            if self.lane.offer(response, now_ms) {
                accepted += 1;
            }
        }
        accepted
    }

    /// Tracks the state changes an approved event makes, and the observations it carries.
    ///
    /// The canonical grid tracks its own copy of much of this. The engine keeps its own because the
    /// query broker answers from session state, snapshots restore from session state, and neither
    /// should have to reach into the grid library for something the profile owns.
    fn track(&mut self, event: &Event, outcome: &mut FeedOutcome) {
        match &event.kind {
            EventKind::Esc {
                intermediate: None,
                final_byte,
                ..
            } => match final_byte {
                b'c' => {
                    self.modes.full_reset();
                    self.titles = TitleState::new();
                    self.palette = Palette::new(self.palette.source());
                    self.cursor_style = 1;
                    self.title_revision = self.next_revision();
                    self.palette_revision = self.next_revision();
                    self.advance_projection();
                }
                b'=' => {
                    self.modes.set_keypad_application(true);
                    self.mark_mode(ModeKind::Dec, 66);
                }
                b'>' => {
                    self.modes.set_keypad_application(false);
                    self.mark_mode(ModeKind::Dec, 66);
                }
                _ => {}
            },
            EventKind::Csi {
                params,
                truncated,
                final_byte,
            } => {
                let csi = CsiView::with_truncation(params, *final_byte, *truncated);
                self.track_csi(&csi);
            }
            EventKind::Osc { selector, parts } => {
                self.track_osc(*selector, parts);
                observe_osc(*selector, parts, event.span.start(), outcome);
            }
            _ => {}
        }
    }

    fn track_csi(&mut self, csi: &CsiView) {
        match (csi.private, csi.intermediates.as_slice(), csi.final_byte) {
            (None, [], b'h' | b'l') => {
                let enabled = csi.final_byte == b'h';
                for slot in &csi.numbers {
                    if let Some(mode) = slot.and_then(|value| u16::try_from(value).ok()) {
                        self.modes.set(ModeKind::Ansi, mode, enabled);
                        self.mark_mode(ModeKind::Ansi, mode);
                    }
                }
            }
            (Some(b'?'), [], b'h' | b'l') => {
                let enabled = csi.final_byte == b'h';
                for slot in &csi.numbers {
                    let Some(mode) = slot.and_then(|value| u16::try_from(value).ok()) else {
                        continue;
                    };
                    // The win32 input mode belongs to the backend that owns the pseudo-terminal.
                    // On a Unix backend nobody asked for it and nothing implements it.
                    if mode == MODE_WIN32_INPUT && self.policy.backend != Backend::ConPty {
                        continue;
                    }
                    self.modes.set(ModeKind::Dec, mode, enabled);
                    self.mark_mode(ModeKind::Dec, mode);
                    if matches!(mode, 47 | 1047 | 1049) {
                        self.advance_projection();
                    }
                }
            }
            (None, [b'!'], b'p') => {
                // DECSTR returns the primary screen, which resets the projection with it.
                self.modes.soft_reset();
                self.cursor_style = 1;
                self.advance_projection();
            }
            (None, [b' '], b'q') => {
                self.cursor_style = u32::try_from(csi.first_or(1).max(0)).unwrap_or(1);
            }
            (None, [], b't') => {
                let target = title_target(csi.number(1));
                match csi.first_or(0) {
                    22 => {
                        self.titles.push(target);
                        self.title_revision = self.next_revision();
                    }
                    // The stack is the session's own. An underflow stops here rather than reaching
                    // into whatever the attach client saved, so the result is not acted on.
                    23 => {
                        let _ = self.titles.pop(target);
                        self.title_revision = self.next_revision();
                    }
                    _ => {}
                }
            }
            // Keyboard negotiation, with the defaults each form carries. `CSI > m` resets every
            // resource, `CSI = u` clears the flags, and a pop count of zero pops nothing.
            (Some(b'>'), [], b'm') => {
                let resource = csi
                    .number(0)
                    .map(|value| u8::try_from(value.clamp(0, 255)).unwrap_or(0));
                let value = csi
                    .number(1)
                    .map(|value| u8::try_from(value.clamp(0, 255)).unwrap_or(0));
                self.modes.set_modify_other_keys(resource, value);
                self.keyboard_revision = self.next_revision();
            }
            (Some(b'>'), [], b'u') => {
                let flags = u8::try_from(csi.first_or(0).clamp(0, 255)).unwrap_or(0);
                self.modes.push_kitty(flags);
                self.keyboard_revision = self.next_revision();
            }
            (Some(b'<'), [], b'u') => {
                let count = usize::try_from(csi.first_or(1).max(0)).unwrap_or(0);
                self.modes.pop_kitty(count);
                self.keyboard_revision = self.next_revision();
            }
            (Some(b'='), [], b'u') => {
                let flags = u8::try_from(csi.first_or(0).clamp(0, 255)).unwrap_or(0);
                let mode = u8::try_from(csi.number(1).unwrap_or(1).clamp(0, 255)).unwrap_or(1);
                self.modes.set_kitty(flags, mode);
                self.keyboard_revision = self.next_revision();
            }
            _ => {}
        }
    }

    fn track_osc(&mut self, selector: Option<u32>, parts: &[Vec<u8>]) {
        let Some(selector) = selector else {
            return;
        };
        match selector {
            0..=2 => {
                let Some(target) = TitleTarget::from_selector(selector) else {
                    return;
                };
                // A title may contain semicolons, so everything after the selector is the title.
                // Everything after the selector is the title, and it is sanitised once so that the
                // session title and the grid's title are the same string.
                let title = parts[1..]
                    .iter()
                    .map(|part| sanitise_text(part))
                    .collect::<Vec<_>>()
                    .join(";");
                self.titles.set(target, &title);
                self.title_revision = self.next_revision();
            }
            104 => {
                if parts.len() <= 1 || parts[1].is_empty() {
                    self.palette.reset_all_indexed();
                } else {
                    for part in &parts[1..] {
                        if let Some(slot) = core::str::from_utf8(part)
                            .ok()
                            .and_then(|text| text.parse::<u8>().ok())
                        {
                            self.palette.reset_indexed(slot);
                        }
                    }
                }
                self.palette_revision = self.next_revision();
            }
            110..=119 => {
                if let Some(which) = DynamicColour::from_selector(selector - 100) {
                    self.palette.reset_dynamic(which);
                    self.palette_revision = self.next_revision();
                }
            }
            _ => {}
        }
    }

    /// Applies an OSC colour string in order, queueing an answer at each question.
    ///
    /// A request may interleave mutations and questions, and each question is about the palette as
    /// it stands at that point. Applying every mutation first and answering afterwards would give
    /// the wrong answer to a question that came before a change.
    fn apply_colours(&mut self, event: &Event, now_ms: u64) -> usize {
        let EventKind::Osc { selector, parts } = &event.kind else {
            return 0;
        };
        let Some(selector) = *selector else {
            return 0;
        };
        if !matches!(selector, 4 | 10..=19) {
            return 0;
        }
        let terminator = QueryBroker::reply_terminator(event);
        let at = event.span.start();
        let operations = crate::broker::colour_operations(selector, parts);
        let mut accepted = 0;
        for operation in operations {
            match operation {
                ColourOperation::Set {
                    selector: key,
                    colour,
                } => {
                    if key >= INDEXED_BASE {
                        if let Ok(index) = u8::try_from(key - INDEXED_BASE) {
                            self.palette.set_indexed(index, colour);
                            self.palette_revision = self.next_revision();
                        }
                    } else if let Some(which) = DynamicColour::from_selector(key) {
                        self.palette.set_dynamic(which, colour);
                        self.palette_revision = self.next_revision();
                    }
                }
                ColourOperation::Query { selector: key } => {
                    let colour = if key >= INDEXED_BASE {
                        u8::try_from(key - INDEXED_BASE)
                            .ok()
                            .map(|index| self.palette.indexed(index))
                    } else {
                        DynamicColour::from_selector(key).map(|which| self.palette.dynamic(which))
                    };
                    let Some(colour) = colour else {
                        continue;
                    };
                    if let Some(response) = self.broker.colour_answer(key, colour, terminator, at)
                        && self.lane.offer(response, now_ms)
                    {
                        accepted += 1;
                    }
                }
            }
        }
        accepted
    }

    /// Resets the projection, so that no client continues from a base taken before it.
    ///
    /// The bases are dropped rather than left to be refused one at a time. A base is a byte cursor,
    /// and a reset can happen without any byte arriving, so a new base at the same cursor would
    /// otherwise look like the old one and a client would be told nothing had changed.
    fn advance_projection(&mut self) {
        self.projection_generation = self.projection_generation.wrapping_add(1);
        self.checkpoints.clear();
    }

    /// Changes the canonical geometry.
    ///
    /// A geometry change resets the projection. Every row a client holds was laid out for the old
    /// width and the rows reflow, so a client cannot continue from a base it took before the
    /// change; it asks for a fresh snapshot instead. It also settles the question of what a base
    /// cursor names, because output does not have to arrive for the screen to change here.
    ///
    /// # Errors
    ///
    /// Returns [`TermError::Geometry`] for dimensions outside the three simultaneous constraints
    /// and [`TermError::Budget`] when the new screens would not fit. The grid is unchanged in both
    /// cases, and so is the projection.
    pub fn resize(&mut self, size: GridSize) -> Result<()> {
        self.grid.resize(size, &mut self.budget)?;
        self.dimensions_revision = self.next_revision();
        self.advance_projection();
        Ok(())
    }

    /// Takes a snapshot for `viewport`.
    ///
    /// Any held text tail is released first, so the snapshot describes a settled screen.
    pub fn snapshot(&mut self, viewport: Viewport, now_ms: u64) -> (Snapshot, FeedOutcome) {
        let settled = self.quiesce(now_ms);
        let rows = self.grid.visible_rows();
        let (oldest, _) = self.grid.stable_range();
        let (col, row) = self.grid.cursor();
        let (top, bottom) = self.grid.margins_vertical();
        let (left, right) = self.grid.margins_horizontal();
        let (g0, g1) = self.grid.charsets();
        let snapshot = Snapshot {
            projection_generation: self.projection_generation,
            output_cursor: self.lexer.committed_offset(),
            active_buffer: self.active_buffer(),
            dimensions: self.grid.size(),
            viewport,
            cursor: CursorState {
                col,
                row,
                visible: self.modes.is_set(ModeKind::Dec, 25),
                style: self.cursor_style,
                // Not observable from the pinned grid library; see `crate::unicode::LIBRARY`.
                pending_wrap: None,
            },
            // Not observable from the pinned grid library; see `crate::unicode::LIBRARY`.
            saved_cursors: [None, None],
            margins: Margins {
                top,
                bottom,
                left,
                right,
            },
            rendition: self.grid.pen(),
            tab_stops: self.grid.tab_stops(),
            charsets: Charsets {
                g0,
                g1,
                shift_out: self.grid.shift_out(),
            },
            modes: self.mode_entries(),
            keypad_application: self.modes.keypad_application(),
            keyboard: self.keyboard_snapshot(),
            title: crate::title::TitleEntry {
                icon: self.titles.icon().to_owned(),
                window: self.titles.window().to_owned(),
            },
            title_stack: self.titles.entries().to_vec(),
            hyperlinks: hyperlinks_of(&rows),
            hyperlink: self.grid.pen_hyperlink(),
            palette: self.palette_snapshot(),
            rows,
            // Not reachable on the pinned grid library; see `crate::unicode::LIBRARY`.
            inactive_rows: None,
            oldest_retained_row: oldest,
            evicted: oldest > 0,
        };
        (snapshot, settled)
    }

    fn active_buffer(&self) -> ActiveBuffer {
        if self.grid.alternate_active() {
            ActiveBuffer::Alternate
        } else {
            ActiveBuffer::Primary
        }
    }

    fn keyboard_snapshot(&self) -> KeyboardSnapshot {
        let (primary_flags, primary_stack) = self.modes.kitty_buffer(false);
        let (alternate_flags, alternate_stack) = self.modes.kitty_buffer(true);
        KeyboardSnapshot {
            modify_other_keys: self.modes.modify_other_keys(),
            primary: crate::snapshot::KittyKeyboard {
                flags: primary_flags,
                stack: primary_stack,
            },
            alternate: crate::snapshot::KittyKeyboard {
                flags: alternate_flags,
                stack: alternate_stack,
            },
        }
    }

    fn mode_entries(&self) -> Vec<ModeEntry> {
        self.modes
            .tracked()
            .into_iter()
            .map(|(kind, mode, enabled)| ModeEntry {
                kind,
                mode,
                enabled,
            })
            .collect()
    }

    fn palette_snapshot(&self) -> PaletteSnapshot {
        let defaults = Palette::new(self.palette.source());
        let mut overrides = Vec::new();
        for index in 0..=u8::MAX {
            let colour = self.palette.indexed(index);
            if colour != defaults.indexed(index) {
                overrides.push((index, colour));
            }
        }
        PaletteSnapshot {
            source: self.palette.source(),
            foreground: self.palette.dynamic(DynamicColour::Foreground),
            background: self.palette.dynamic(DynamicColour::Background),
            cursor: self.palette.dynamic(DynamicColour::Cursor),
            pointer_foreground: self.palette.dynamic(DynamicColour::PointerForeground),
            pointer_background: self.palette.dynamic(DynamicColour::PointerBackground),
            selection_background: self.palette.dynamic(DynamicColour::SelectionBackground),
            selection_foreground: self.palette.dynamic(DynamicColour::SelectionForeground),
            overrides,
        }
    }

    /// Builds a delta against `base_cursor`.
    ///
    /// The delta carries the rows that changed since the client's base, the modes and title that
    /// changed with them, and the palette or dimensions when either moved.
    ///
    /// # Errors
    ///
    /// Returns [`TermError::CursorGap`] when the base is outside the replay window, or when the
    /// projection was reset since then. A client answers both by taking a fresh snapshot.
    pub fn delta(&self, base_cursor: u64, base_generation: u64) -> Result<Delta> {
        // The generation is part of the base, not a second check on it. A projection reset can
        // happen without a byte arriving, so the same cursor can name two different screens; a
        // client that names the generation it holds is told to start again rather than handed a
        // delta against a screen it never saw.
        if base_generation != self.projection_generation {
            return Err(TermError::CursorGap {
                requested: base_cursor,
                available: self.lexer.committed_offset(),
            });
        }
        let Some(base) = self
            .checkpoints
            .iter()
            .find(|checkpoint| checkpoint.cursor == base_cursor)
        else {
            return Err(TermError::CursorGap {
                requested: base_cursor,
                available: self
                    .checkpoints
                    .front()
                    .map_or(self.lexer.offset(), |checkpoint| checkpoint.cursor),
            });
        };
        if base.generation != self.projection_generation {
            return Err(TermError::CursorGap {
                requested: base_cursor,
                available: self.lexer.offset(),
            });
        }
        let base = *base;
        let changed: BTreeSet<i64> = self
            .grid
            .changed_rows_since(base.seqno)
            .into_iter()
            .collect();
        let rows: Vec<GridRow> = self
            .grid
            .visible_rows()
            .into_iter()
            .filter(|row| changed.contains(&row.stable_id))
            .collect();
        let (col, row) = self.grid.cursor();
        let (top, bottom) = self.grid.margins_vertical();
        let (left, right) = self.grid.margins_horizontal();
        let hyperlinks = hyperlinks_of(&rows);
        Ok(Delta {
            base_cursor,
            next_cursor: self.lexer.committed_offset(),
            projection_generation: self.projection_generation,
            rows,
            cursor: CursorState {
                col,
                row,
                visible: self.modes.is_set(ModeKind::Dec, 25),
                style: self.cursor_style,
                pending_wrap: None,
            },
            modes: self.changed_modes(base.revisions.any),
            margins: (self.presentation_revision > base.revisions.presentation).then_some(
                Margins {
                    top,
                    bottom,
                    left,
                    right,
                },
            ),
            rendition: (self.presentation_revision > base.revisions.presentation)
                .then(|| self.grid.pen()),
            tab_stops: (self.presentation_revision > base.revisions.presentation)
                .then(|| self.grid.tab_stops()),
            charsets: (self.presentation_revision > base.revisions.presentation).then(|| {
                let (g0, g1) = self.grid.charsets();
                Charsets {
                    g0,
                    g1,
                    shift_out: self.grid.shift_out(),
                }
            }),
            hyperlinks,
            title: (self.title_revision > base.revisions.title).then(|| crate::title::TitleEntry {
                icon: self.titles.icon().to_owned(),
                window: self.titles.window().to_owned(),
            }),
            keyboard: (self.keyboard_revision > base.revisions.keyboard)
                .then(|| self.keyboard_snapshot()),
            palette: (self.palette_revision > base.revisions.palette)
                .then(|| self.palette_snapshot()),
            dimensions: (self.dimensions_revision > base.revisions.dimensions)
                .then(|| self.grid.size()),
            title_stack: (self.title_revision > base.revisions.title)
                .then(|| self.titles.entries().to_vec()),
            hyperlink: (self.presentation_revision > base.revisions.presentation)
                .then(|| self.grid.pen_hyperlink()),
        })
    }

    fn changed_modes(&self, since: u64) -> Vec<ModeEntry> {
        self.mode_revisions
            .iter()
            .filter(|(_, revision)| **revision > since)
            .map(|((kind, mode), _)| ModeEntry {
                kind: *kind,
                mode: *mode,
                enabled: self.modes.is_set(*kind, *mode),
            })
            .collect()
    }

    /// Reads a page of history rows.
    ///
    /// The page is bounded by both of the section 8 limits at once: at most 1,000 rows and at most
    /// 1 MiB of encoded content, whichever binds first. The size counts everything the page
    /// carries, not only its text.
    #[must_use]
    pub fn history_page(&self, from: i64) -> HistoryPage {
        let limits = self.budget.limits();
        let mut rows = Vec::new();
        let mut bytes = 0usize;
        let mut truncated = false;
        let mut next = from;
        // Rows are taken a batch at a time rather than all at once. A page is bounded in bytes as
        // well as in rows, and the rows that do not fit are rows nobody asked to have built: rows
        // carrying long hyperlink targets can cost many times the page bound before the first byte
        // of the page is counted.
        'page: while rows.len() < limits.history_page_rows {
            let want = PAGE_BATCH_ROWS.min(limits.history_page_rows - rows.len());
            let batch = self.grid.history_rows(next, want);
            if batch.is_empty() {
                break;
            }
            // The grid clamps a request below its oldest retained row, so the next batch starts
            // after the last row it actually returned rather than after where it was asked to look.
            let Some(last) = batch.last().map(|row| row.stable_id) else {
                break;
            };
            next = last.saturating_add(1);
            for mut row in batch {
                let mut row_bytes = encoded_row_bytes(&row);
                if row_bytes > limits.history_page_bytes {
                    // One row larger than a whole page still has to be representable, or a reader
                    // could never get past it. It is degraded explicitly rather than dropped.
                    if !rows.is_empty() {
                        truncated = true;
                        break 'page;
                    }
                    truncate_row(&mut row, limits.history_page_bytes);
                    row_bytes = encoded_row_bytes(&row);
                }
                if bytes + row_bytes > limits.history_page_bytes {
                    truncated = true;
                    break 'page;
                }
                bytes += row_bytes;
                rows.push(row);
            }
        }
        let (oldest, newest) = self.grid.stable_range();
        let last = from.saturating_add(i64::try_from(rows.len()).unwrap_or(0));
        HistoryPage {
            rows,
            oldest_retained_row: oldest,
            evicted: oldest > 0,
            more: truncated || last < newest,
        }
    }

    /// Answers a `Q` event that a caller already has in hand.
    ///
    /// [`Engine::feed`] already answers every query it sees. This is for a caller holding a query
    /// event that wants the answer without re-feeding the bytes.
    pub fn answer(&mut self, event: &Event, now_ms: u64) -> usize {
        if event.class != SequenceClass::Query {
            return 0;
        }
        self.answer_query(event, now_ms)
    }

    /// Diagnostics recorded so far, by kind.
    #[must_use]
    pub fn diagnostic_totals(&self) -> Vec<(DiagnosticKind, u64)> {
        self.diagnostics.totals()
    }
}

/// Whether a sequence switches to the alternate buffer.
fn enters_alternate(kind: &EventKind) -> bool {
    let EventKind::Csi {
        params,
        final_byte: b'h',
        ..
    } = kind
    else {
        return false;
    };
    let csi = crate::classify::CsiView::new(params, b'h');
    csi.private == Some(b'?')
        && csi
            .numbers
            .iter()
            .any(|slot| matches!(slot, Some(47 | 1047 | 1049)))
}

/// Whether a sequence restores a saved cursor, directly or as part of leaving a buffer.
fn restores_cursor(kind: &EventKind) -> bool {
    match kind {
        EventKind::Esc {
            intermediate: None,
            final_byte: b'8',
            ..
        } => true,
        EventKind::Csi {
            params, final_byte, ..
        } => {
            let csi = crate::classify::CsiView::new(params, *final_byte);
            match csi.final_byte {
                b'u' if csi.private.is_none() => true,
                b'l' if csi.private == Some(b'?') => csi
                    .numbers
                    .iter()
                    .any(|slot| matches!(slot, Some(1048 | 1049))),
                _ => false,
            }
        }
        _ => false,
    }
}

/// Records the untrusted observations an approved shell-integration sequence carried.
fn observe_osc(selector: Option<u32>, parts: &[Vec<u8>], at: u64, outcome: &mut FeedOutcome) {
    let Some(selector) = selector else {
        return;
    };
    let (source, key, value) = match selector {
        7 => (
            ObservationSource::WorkingDirectory,
            "Cwd".to_owned(),
            text_of(parts.get(1)),
        ),
        133 => (
            ObservationSource::PromptBoundary,
            text_of(parts.get(1)),
            text_of(parts.get(2)),
        ),
        633 => (
            ObservationSource::ShellIntegration,
            text_of(parts.get(1)),
            text_of(parts.get(2)),
        ),
        1337 => (
            ObservationSource::TerminalMetadata,
            text_of(parts.get(1)),
            String::new(),
        ),
        _ => return,
    };
    outcome.observations.push(Observation {
        source,
        key: bounded(key),
        value: bounded(value),
        at,
    });
}

/// The encoded size of one row, counting everything a page carries for it.
///
/// Counting only the text would let a page of short, heavily linked rows pass the bound several
/// times over, because a hyperlink target can be far longer than the text it covers.
fn encoded_row_bytes(row: &GridRow) -> usize {
    const ROW_OVERHEAD: usize = 16;
    ROW_OVERHEAD
        + row
            .runs
            .iter()
            .map(|run| {
                crate::grid::RUN_OVERHEAD_BYTES
                    + run.text.len()
                    + run.hyperlink.as_ref().map_or(0, std::string::String::len)
            })
            .sum::<usize>()
}

/// Drops runs from the end of a row until its record fits `limit`, and says that it happened.
fn truncate_row(row: &mut GridRow, limit: usize) {
    while encoded_row_bytes(row) > limit && !row.runs.is_empty() {
        row.runs.pop();
    }
    row.truncated = true;
}

/// Makes a control-string payload safe to show, the same way the grid sees it.
fn sanitise_text(part: &[u8]) -> String {
    String::from_utf8_lossy(part)
        .chars()
        .filter(|scalar| !scalar.is_control() && !('\u{80}'..='\u{9f}').contains(scalar))
        .collect()
}

fn text_of(part: Option<&Vec<u8>>) -> String {
    part.map(|bytes| String::from_utf8_lossy(bytes).into_owned())
        .unwrap_or_default()
}

fn bounded(mut text: String) -> String {
    if text.len() > MAX_OBSERVATION_BYTES {
        let mut end = MAX_OBSERVATION_BYTES;
        while end > 0 && !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
    }
    text
}

fn title_target(second: Option<i64>) -> TitleTarget {
    // `CSI 22 ; Ps t` selects which title: 0 both, 1 icon, 2 window.
    match second {
        Some(1) => TitleTarget::Icon,
        Some(2) => TitleTarget::Window,
        _ => TitleTarget::Both,
    }
}

fn push_span(spans: &mut Vec<ByteSpan>, span: ByteSpan) {
    match spans.last_mut() {
        Some(last) if last.adjoins(span) => *last = last.join(span),
        _ => spans.push(span),
    }
}

fn hyperlinks_of(rows: &[GridRow]) -> Vec<HyperlinkRange> {
    let mut out = Vec::new();
    for row in rows {
        for run in &row.runs {
            if let Some(uri) = &run.hyperlink {
                out.push(HyperlinkRange {
                    row: row.stable_id,
                    start_col: run.column,
                    end_col: run.column + run.cells,
                    uri: uri.clone(),
                });
            }
        }
    }
    out
}
