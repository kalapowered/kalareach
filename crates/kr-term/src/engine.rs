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

use std::collections::{BTreeSet, VecDeque};

use crate::broker::{BrokerState, CanonicalReport, ColourOperation, INDEXED_BASE, QueryBroker};
use crate::budget::{GridSize, SessionBudget};
use crate::class::SequenceClass;
use crate::classify::{CsiView, MODE_WIN32_INPUT};
use crate::diag::{Diagnostic, DiagnosticKind, DiagnosticSink};
use crate::error::{Result, TermError};
use crate::event::{DirectDisposition, Event, EventKind};
use crate::grid::{CanonicalGrid, GridConfig, GridRow};
use crate::lane::{LaneDegradation, LaneLimits, Response, ResponseKind, ResponseLane};
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
}

/// One point a delta may be built against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Checkpoint {
    cursor: u64,
    seqno: usize,
    generation: u64,
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
    dirty_modes: BTreeSet<(ModeKind, u16)>,
    dirty_title: bool,
    dirty_palette: bool,
    dirty_dimensions: bool,
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
            dirty_modes: BTreeSet::new(),
            dirty_title: false,
            dirty_palette: false,
            dirty_dimensions: false,
            feeds: 0,
            scratch: Vec::new(),
        };
        engine.record_checkpoint();
        Ok(engine)
    }

    /// Adopts a palette the client shared during the bounded probe.
    pub fn adopt_palette(&mut self, palette: Palette) {
        self.palette = palette;
        self.dirty_palette = true;
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

    /// The monotonic output cursor: how many bytes of the session's output have been lexed.
    #[must_use]
    pub const fn output_cursor(&self) -> u64 {
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
    #[must_use]
    pub fn ground_boundary(&self) -> Option<u64> {
        if self.lexer.at_ground() {
            Some(self.lexer.offset())
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
            let decision = self.policy.decide(event);
            let mut disposition = decision.disposition;
            if decision.apply_to_grid {
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
            if decision.answer {
                outcome.responses += self.answer_query(event, now_ms);
            }
            if let Some(bytes) = decision.immediate_reply {
                let response = Response::new(ResponseKind::Clipboard, event.span.start(), bytes);
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
        outcome.diagnostics = self.diagnostics.drain();
        outcome.ground_boundary = self.ground_boundary();
        outcome.projection_reset = self.projection_generation != generation_before;
        outcome
    }

    /// Whether recording this event's hyperlink would pass the session's bound.
    fn link_budget_exceeded(&mut self, event: &Event) -> bool {
        let EventKind::Osc {
            selector: Some(8),
            parts,
        } = &event.kind
        else {
            return false;
        };
        let Some(uri) = parts.get(2) else {
            return false;
        };
        if uri.is_empty() {
            return false;
        }
        let uri = String::from_utf8_lossy(uri).into_owned();
        if self.links.contains(&uri) {
            return false;
        }
        if self.links.len() >= self.budget.limits().unique_links {
            self.budget.record_truncation();
            return true;
        }
        let metadata = self.budget.usage().metadata + uri.len() as u64;
        self.budget.set_metadata(metadata);
        self.links.insert(uri);
        false
    }

    /// Measures and enforces the resident-state bounds.
    ///
    /// Measuring the retained rows means walking the scrollback, so it happens periodically rather
    /// than on every read. The bound it enforces is a cache size, so overshooting it briefly costs
    /// memory in proportion to how often this runs and nothing else.
    fn enforce_resident_state(&mut self, now_ms: u64) {
        if !self.feeds.is_multiple_of(ROW_CACHE_INTERVAL) {
            return;
        }
        let bytes = self.grid.history_bytes();
        let limit = self.budget.limits().row_cache_bytes;
        if self.grid.enforce_row_cache(bytes, limit) {
            self.diagnostics.record(
                DiagnosticKind::ResidentStateTruncated,
                self.lexer.offset(),
                now_ms,
                format!("historical rows passed the {limit}-byte cache bound; older rows evicted"),
            );
        }
        self.budget.set_row_cache(bytes);
    }

    fn record_checkpoint(&mut self) {
        let checkpoint = Checkpoint {
            cursor: self.lexer.offset(),
            seqno: self.grid.sequence_number(),
            generation: self.projection_generation,
        };
        if self.checkpoints.back() == Some(&checkpoint) {
            return;
        }
        if self.checkpoints.len() == REPLAY_WINDOW {
            self.checkpoints.pop_front();
        }
        self.checkpoints.push_back(checkpoint);
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
                    self.dirty_title = true;
                    self.dirty_palette = true;
                    self.advance_projection();
                }
                b'=' => self.modes.set_keypad_application(true),
                b'>' => self.modes.set_keypad_application(false),
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
                        self.dirty_modes.insert((ModeKind::Ansi, mode));
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
                    self.dirty_modes.insert((ModeKind::Dec, mode));
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
                        self.dirty_title = true;
                    }
                    // The stack is the session's own. An underflow stops here rather than reaching
                    // into whatever the attach client saved, so the result is not acted on.
                    23 => {
                        let _ = self.titles.pop(target);
                        self.dirty_title = true;
                    }
                    _ => {}
                }
            }
            (Some(b'>'), [], b'm') => {
                let resource = u8::try_from(csi.first_or(4).clamp(0, 255)).unwrap_or(4);
                let value = u8::try_from(csi.number(1).unwrap_or(0).clamp(0, 255)).unwrap_or(0);
                self.modes.set_modify_other_keys(resource, value);
            }
            (Some(b'>'), [], b'u') => {
                let flags = u8::try_from(csi.first_or(0).clamp(0, 255)).unwrap_or(0);
                self.modes.push_kitty(flags);
            }
            (Some(b'<'), [], b'u') => {
                let count = usize::try_from(csi.first_or(1).max(1)).unwrap_or(1);
                self.modes.pop_kitty(count);
            }
            (Some(b'='), [], b'u') => {
                let flags = u8::try_from(csi.first_or(0).clamp(0, 255)).unwrap_or(0);
                let mode = u8::try_from(csi.number(1).unwrap_or(1).clamp(0, 255)).unwrap_or(1);
                self.modes.set_kitty(flags, mode);
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
                let title = parts[1..]
                    .iter()
                    .map(|part| String::from_utf8_lossy(part).into_owned())
                    .collect::<Vec<_>>()
                    .join(";");
                self.titles.set(target, &title);
                self.dirty_title = true;
            }
            4 | 10..=19 => {
                for operation in crate::broker::colour_operations(selector, parts) {
                    let ColourOperation::Set {
                        selector: key,
                        colour,
                    } = operation
                    else {
                        continue;
                    };
                    if key >= INDEXED_BASE {
                        if let Ok(index) = u8::try_from(key - INDEXED_BASE) {
                            self.palette.set_indexed(index, colour);
                            self.dirty_palette = true;
                        }
                    } else if let Some(which) = DynamicColour::from_selector(key) {
                        self.palette.set_dynamic(which, colour);
                        self.dirty_palette = true;
                    }
                }
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
                self.dirty_palette = true;
            }
            110..=119 => {
                if let Some(which) = DynamicColour::from_selector(selector - 100) {
                    self.palette.reset_dynamic(which);
                    self.dirty_palette = true;
                }
            }
            _ => {}
        }
    }

    const fn advance_projection(&mut self) {
        self.projection_generation = self.projection_generation.wrapping_add(1);
    }

    /// Resizes the canonical grid.
    ///
    /// # Errors
    ///
    /// Returns [`TermError::Geometry`] or [`TermError::Budget`]. The current grid is unchanged in
    /// either case.
    pub fn resize(&mut self, size: GridSize) -> Result<()> {
        self.grid.resize(size, &mut self.budget)?;
        self.dirty_dimensions = true;
        Ok(())
    }

    /// Takes a snapshot for `viewport`.
    ///
    /// Any held text tail is released first, so the snapshot describes a settled screen.
    pub fn snapshot(&mut self, viewport: Viewport, now_ms: u64) -> Snapshot {
        self.quiesce(now_ms);
        let rows = self.grid.visible_rows();
        let (oldest, _) = self.grid.stable_range();
        let (col, row) = self.grid.cursor();
        let (top, bottom) = self.grid.margins_vertical();
        let (left, right) = self.grid.margins_horizontal();
        let (g0, g1) = self.grid.charsets();
        let snapshot = Snapshot {
            projection_generation: self.projection_generation,
            output_cursor: self.lexer.offset(),
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
            saved_cursor: None,
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
            palette: self.palette_snapshot(),
            rows,
            oldest_retained_row: oldest,
            evicted: oldest > 0,
        };
        self.dirty_modes.clear();
        self.dirty_title = false;
        self.dirty_palette = false;
        self.dirty_dimensions = false;
        snapshot
    }

    fn active_buffer(&self) -> ActiveBuffer {
        if self.grid.alternate_active() {
            ActiveBuffer::Alternate
        } else {
            ActiveBuffer::Primary
        }
    }

    fn keyboard_snapshot(&self) -> KeyboardSnapshot {
        KeyboardSnapshot {
            modify_other_keys: self.modes.modify_other_keys(),
            kitty_flags: self.modes.kitty_flags(),
            kitty_stack: self.modes.kitty_stack().to_vec(),
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
    pub fn delta(&self, base_cursor: u64) -> Result<Delta> {
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
        Ok(Delta {
            base_cursor,
            next_cursor: self.lexer.offset(),
            projection_generation: self.projection_generation,
            rows,
            cursor: CursorState {
                col,
                row,
                visible: self.modes.is_set(ModeKind::Dec, 25),
                style: self.cursor_style,
                pending_wrap: None,
            },
            modes: self.changed_modes(),
            title: self.dirty_title.then(|| crate::title::TitleEntry {
                icon: self.titles.icon().to_owned(),
                window: self.titles.window().to_owned(),
            }),
            palette: self.dirty_palette.then(|| self.palette_snapshot()),
            dimensions: self.dirty_dimensions.then(|| self.grid.size()),
        })
    }

    fn changed_modes(&self) -> Vec<ModeEntry> {
        self.dirty_modes
            .iter()
            .map(|(kind, mode)| ModeEntry {
                kind: *kind,
                mode: *mode,
                enabled: self.modes.is_set(*kind, *mode),
            })
            .collect()
    }

    /// Acknowledges that a client now holds everything up to `cursor`.
    ///
    /// The next delta starts from there, so a change is carried once rather than in every delta
    /// until the next snapshot.
    pub fn acknowledge(&mut self, cursor: u64) {
        if cursor >= self.lexer.offset() {
            self.dirty_modes.clear();
            self.dirty_title = false;
            self.dirty_palette = false;
            self.dirty_dimensions = false;
        }
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
        for row in self.grid.history_rows(from, limits.history_page_rows) {
            let row_bytes = encoded_row_bytes(&row);
            if bytes + row_bytes > limits.history_page_bytes {
                truncated = true;
                break;
            }
            bytes += row_bytes;
            rows.push(row);
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
    const RUN_OVERHEAD: usize = 24;
    const ROW_OVERHEAD: usize = 16;
    ROW_OVERHEAD
        + row
            .runs
            .iter()
            .map(|run| {
                RUN_OVERHEAD
                    + run.text.len()
                    + run.hyperlink.as_ref().map_or(0, std::string::String::len)
            })
            .sum::<usize>()
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
