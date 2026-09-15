//! The terminal engine: one parse, one policy decision, one canonical state, one responder.
//!
//! [`Engine::feed`] is the whole output path. Bytes go in; what comes out is a list of spans that
//! may be forwarded unchanged, the side effects that need routing, the diagnostics that need
//! publishing, and a canonical grid that has been updated exactly once. Replies go to the trusted
//! lane, where the session loop picks them up on its own schedule.
//!
//! Nothing in here is optional at runtime. There is no path that skips the policy decision, no
//! path that hands the grid a sequence policy refused, and no path that sends a query onwards.

use crate::broker::{BrokerState, CanonicalReport, QueryBroker};
use crate::budget::{GridSize, SessionBudget};
use crate::class::SequenceClass;
use crate::classify::CsiView;
use crate::diag::{Diagnostic, DiagnosticKind, DiagnosticSink};
use crate::error::Result;
use crate::event::{CsiParam, DirectDisposition, Event, EventKind};
use crate::grid::{CanonicalGrid, GridConfig, GridRow, Rendition};
use crate::lane::{LaneDegradation, Response, ResponseKind, ResponseLane};
use crate::lexer::{LexLimits, Lexer};
use crate::modes::{ModeKind, ModeState};
use crate::palette::{DynamicColour, Palette, PaletteSource};
use crate::policy::Policy;
use crate::profile::Profile;
use crate::sideeffect::{LeaseHolder, SideEffect, SideEffectRefusal};
use crate::snapshot::{
    ActiveBuffer, Charsets, CursorState, Delta, HistoryPage, HyperlinkRange, Margins, ModeEntry,
    PaletteSnapshot, SavedCursor, Snapshot, Viewport,
};
use crate::span::ByteSpan;
use crate::title::{TitleState, TitleTarget};

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
    /// Replies accepted by the response lane.
    pub responses: usize,
    /// The most recent parser-ground boundary, when the parser reached one.
    pub ground_boundary: Option<u64>,
    /// How the lane is shedding load.
    pub degradation: LaneDegradation,
    /// Whether the projection generation advanced, which resets a client's projection.
    pub projection_reset: bool,
}

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
    protection: u32,
    scratch: Vec<Event>,
}

impl Engine {
    /// Builds an engine.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::TermError::Geometry`] for dimensions outside the three simultaneous
    /// constraints, and [`crate::error::TermError::Budget`] when the screens would not fit.
    pub fn new(config: EngineConfig) -> Result<Self> {
        let mut budget = SessionBudget::new();
        let grid = CanonicalGrid::new(config.size, config.grid, &mut budget)?;
        Ok(Self {
            lexer: Lexer::with_limits(config.lex),
            policy: config.policy,
            profile: config.profile,
            grid,
            broker: QueryBroker::new(),
            lane: ResponseLane::new(),
            modes: ModeState::new(),
            titles: TitleState::new(),
            palette: Palette::new(config.palette_source),
            diagnostics: DiagnosticSink::new(),
            budget,
            lease: LeaseHolder::none(),
            projection_generation: 1,
            cursor_style: 1,
            protection: 0,
            scratch: Vec::new(),
        })
    }

    /// Adopts a palette the client shared during the bounded probe.
    pub fn adopt_palette(&mut self, palette: Palette) {
        self.palette = palette;
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
            if decision.track {
                self.track(event);
            }
            if decision.apply_to_grid {
                self.grid.apply(event);
            }
            if decision.answer {
                outcome.responses += self.answer_with_rendition(event, now_ms);
            }
            if let Some(bytes) = decision.immediate_reply {
                let response = Response {
                    bytes,
                    kind: ResponseKind::Clipboard,
                    query_at: event.span.start(),
                };
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
            match decision.disposition {
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
                    "coalesced {}, dropped {}, over budget {}, oversized {}",
                    degradation.coalesced,
                    degradation.dropped,
                    degradation.over_budget,
                    degradation.oversized
                ),
            );
        }
        self.budget.set_row_cache(self.grid.history_bytes());
        outcome.degradation = degradation;
        outcome.diagnostics = self.diagnostics.drain();
        outcome.ground_boundary = self.ground_boundary();
        outcome.projection_reset = self.projection_generation != generation_before;
        outcome
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
            cursor_style: self.cursor_style,
            protection: self.protection,
        }
    }

    /// Answers a query event, with the current graphic rendition included.
    ///
    /// The engine takes this path for DECRQSS, which needs the pen rendered as SGR parameters.
    fn answer_with_rendition(&mut self, event: &Event, now_ms: u64) -> usize {
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

    /// Tracks the state changes an approved `D` or `M` event makes.
    ///
    /// The canonical grid tracks its own copy of much of this. The engine keeps its own because the
    /// query broker answers from session state, snapshots restore from session state, and neither
    /// should have to reach into the grid library for something the profile owns.
    fn track(&mut self, event: &Event) {
        match &event.kind {
            EventKind::Esc {
                intermediate: None,
                final_byte,
            } => match final_byte {
                b'c' => {
                    self.modes.full_reset();
                    self.titles = TitleState::new();
                    self.palette = Palette::new(self.palette.source());
                    self.cursor_style = 1;
                    self.protection = 0;
                    self.advance_projection();
                }
                b'=' => self.modes.set_keypad_application(true),
                b'>' => self.modes.set_keypad_application(false),
                _ => {}
            },
            EventKind::Csi {
                params, final_byte, ..
            } => self.track_csi(&CsiView::new(params, *final_byte), params),
            EventKind::Osc { selector, parts } => self.track_osc(*selector, parts),
            _ => {}
        }
    }

    fn track_csi(&mut self, csi: &CsiView, params: &[CsiParam]) {
        match (csi.private, csi.intermediates.as_slice(), csi.final_byte) {
            (None, [], b'h' | b'l') => {
                let enabled = csi.final_byte == b'h';
                for slot in &csi.numbers {
                    if let Some(mode) = slot.and_then(|value| u16::try_from(value).ok()) {
                        self.modes.set(ModeKind::Ansi, mode, enabled);
                    }
                }
            }
            (Some(b'?'), [], b'h' | b'l') => {
                let enabled = csi.final_byte == b'h';
                for slot in &csi.numbers {
                    let Some(mode) = slot.and_then(|value| u16::try_from(value).ok()) else {
                        continue;
                    };
                    self.modes.set(ModeKind::Dec, mode, enabled);
                    if matches!(mode, 47 | 1047 | 1049) {
                        self.advance_projection();
                    }
                }
            }
            (None, [b'!'], b'p') => {
                self.modes.soft_reset();
                self.cursor_style = 1;
                self.protection = 0;
            }
            (None, [b' '], b'q') => {
                self.cursor_style = u32::try_from(csi.first_or(1).max(0)).unwrap_or(1);
            }
            (None, [b'"'], b'q') => {
                self.protection = u32::try_from(csi.first_or(0).max(0)).unwrap_or(0);
            }
            (None, [], b't') => {
                let target = title_target(csi.number(1));
                match csi.first_or(0) {
                    22 => self.titles.push(target),
                    // The stack is the session's own. An underflow stops here rather than
                    // reaching into whatever the attach client saved, so the result is discarded.
                    23 => drop(self.titles.pop(target)),
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
            _ => {
                let _ = params;
            }
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
                let title = parts
                    .get(1)
                    .map(|part| String::from_utf8_lossy(part).into_owned())
                    .unwrap_or_default();
                self.titles.set(target, &title);
            }
            4 => {
                let mut index = 1;
                while index + 1 < parts.len() {
                    if let (Some(slot), Ok(spec)) = (
                        core::str::from_utf8(&parts[index])
                            .ok()
                            .and_then(|text| text.parse::<u8>().ok()),
                        core::str::from_utf8(&parts[index + 1]),
                    ) && let Some(colour) = crate::palette::Rgb::parse(spec)
                    {
                        self.palette.set_indexed(slot, colour);
                    }
                    index += 2;
                }
            }
            10..=19 => {
                let Some(which) = DynamicColour::from_selector(selector) else {
                    return;
                };
                if let Some(spec) = parts.get(1)
                    && let Ok(text) = core::str::from_utf8(spec)
                    && let Some(colour) = crate::palette::Rgb::parse(text)
                {
                    self.palette.set_dynamic(which, colour);
                }
            }
            104 => {
                if parts.len() <= 1 {
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
            }
            110..=119 => {
                if let Some(which) = DynamicColour::from_selector(selector - 100) {
                    self.palette.reset_dynamic(which);
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
    /// Returns [`crate::error::TermError::Geometry`] or [`crate::error::TermError::Budget`]. The
    /// current grid is unchanged in either case.
    pub fn resize(&mut self, size: GridSize) -> Result<()> {
        self.grid.resize(size, &mut self.budget)
    }

    /// Takes a snapshot for `viewport`.
    #[must_use]
    pub fn snapshot(&self, viewport: Viewport) -> Snapshot {
        let rows = self.grid.visible_rows();
        let (oldest, _) = self.grid.stable_range();
        let (col, row) = self.grid.cursor();
        let (top, bottom) = self.grid.margins_vertical();
        let (left, right) = self.grid.margins_horizontal();
        let (g0, g1) = self.grid.charsets();
        Snapshot {
            projection_generation: self.projection_generation,
            output_cursor: self.lexer.offset(),
            active_buffer: if self.grid.alternate_active() {
                ActiveBuffer::Alternate
            } else {
                ActiveBuffer::Primary
            },
            dimensions: self.grid.size(),
            viewport,
            cursor: CursorState {
                col,
                row,
                visible: self.modes.is_set(ModeKind::Dec, 25),
                style: self.cursor_style,
                pending_wrap: false,
            },
            saved_cursors: self.saved_cursors(),
            margins: Margins {
                top,
                bottom,
                left,
                right,
            },
            rendition: Rendition::default(),
            tab_stops: self.grid.tab_stops(),
            charsets: Charsets {
                g0,
                g1,
                shift_out: self.grid.shift_out(),
            },
            modes: self.mode_entries(),
            keypad_application: self.modes.keypad_application(),
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
        }
    }

    fn saved_cursors(&self) -> Vec<SavedCursor> {
        // The grid library keeps the saved cursor privately per buffer. What a restoration needs is
        // that a saved cursor exists and where it is, which the snapshot carries for the active
        // buffer; the inactive buffer's is restored with its own snapshot on the next switch.
        let (col, row) = self.grid.cursor();
        vec![SavedCursor {
            buffer: if self.grid.alternate_active() {
                ActiveBuffer::Alternate
            } else {
                ActiveBuffer::Primary
            },
            col,
            row,
        }]
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
            overrides,
        }
    }

    /// Builds a delta against `base_cursor`.
    #[must_use]
    pub fn delta(&self, base_cursor: u64) -> Delta {
        let (col, row) = self.grid.cursor();
        Delta {
            base_cursor,
            next_cursor: self.lexer.offset(),
            projection_generation: self.projection_generation,
            rows: self.grid.visible_rows(),
            cursor: CursorState {
                col,
                row,
                visible: self.modes.is_set(ModeKind::Dec, 25),
                style: self.cursor_style,
                pending_wrap: false,
            },
            modes: Vec::new(),
            title: None,
        }
    }

    /// Reads a page of history rows.
    ///
    /// The page is bounded by both of the section 8 limits at once: at most 1,000 rows and at most
    /// 1 MiB of encoded content, whichever binds first.
    #[must_use]
    pub fn history_page(&self, from: i64) -> HistoryPage {
        let limits = self.budget.limits();
        let mut rows = self.grid.history_rows(from, limits.history_page_rows);
        let mut bytes = 0usize;
        let mut kept = 0usize;
        for row in &rows {
            let row_bytes: usize = row.runs.iter().map(|run| run.text.len()).sum();
            if kept > 0 && bytes + row_bytes > limits.history_page_bytes {
                break;
            }
            bytes += row_bytes;
            kept += 1;
        }
        let truncated = kept < rows.len();
        rows.truncate(kept);
        let (oldest, newest) = self.grid.stable_range();
        let last = from.saturating_add(i64::try_from(rows.len()).unwrap_or(0));
        HistoryPage {
            rows,
            oldest_retained_row: oldest,
            evicted: oldest > 0,
            more: truncated || last < newest,
        }
    }

    /// Answers a `Q` event that needs the current rendition, such as DECRQSS.
    ///
    /// [`Engine::feed`] already answers every query it sees. This is for a caller that has a query
    /// event in hand and wants the rendition-aware answer without re-feeding bytes.
    pub fn answer(&mut self, event: &Event, now_ms: u64) -> usize {
        if event.class != SequenceClass::Query {
            return 0;
        }
        self.answer_with_rendition(event, now_ms)
    }

    /// Diagnostics recorded so far, by kind.
    #[must_use]
    pub fn diagnostic_totals(&self) -> Vec<(DiagnosticKind, u64)> {
        self.diagnostics.totals()
    }
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
