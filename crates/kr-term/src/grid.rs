//! The canonical grid.
//!
//! This is the session's authoritative screen state, built on the pinned terminal state library.
//! The library is used for what it is good at — the cell model, wrapping, scroll regions, the
//! alternate buffer — and it is used through a narrow door: it receives already-decoded actions
//! that the policy layer approved, and it can write nothing anywhere.
//!
//! Three deliberate constraints:
//!
//! * The writer it is constructed with accepts bytes but delivers them nowhere, and counts them.
//!   The query broker is the only thing allowed to answer a query, so a non-zero count is a
//!   qualification failure rather than a stray reply.
//! * Raster graphics are configured off. Nothing would reach them anyway, since no image sequence
//!   is ever classified as display, but a profile that promises no raster graphics should not rely
//!   on one mechanism alone.
//! * The Unicode model is pinned rather than defaulted, so the width of a cell is a property of
//!   the profile and not of whatever the library's default happened to be that month.

use std::sync::{Arc, Mutex};

use wezterm_term::color::ColorPalette;
use wezterm_term::{
    Alert, AlertHandler, CellAttributes, Intensity, Terminal, TerminalConfiguration, TerminalSize,
    Underline, UnicodeVersion,
};

use crate::adapter::{Adapted, adapt};
use crate::budget::{GridSize, SessionBudget};
use crate::error::Result;
use crate::event::Event;
use crate::palette::Rgb;
use crate::unicode::UnicodeModel;

/// A writer that accepts bytes and delivers none, counting what it was given.
#[derive(Debug, Default)]
struct SilentWriter {
    log: Arc<Mutex<WriterLog>>,
}

/// What the grid library tried to write.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WriterLog {
    /// Total bytes offered.
    pub bytes: usize,
    /// The first bytes offered, so a failure says what was written and not only how much.
    pub first: Vec<u8>,
}

impl std::io::Write for SilentWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if let Ok(mut log) = self.log.lock() {
            log.bytes += buf.len();
            if log.first.len() < 64 {
                let room = 64 - log.first.len();
                log.first.extend_from_slice(&buf[..buf.len().min(room)]);
            }
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// An alert the grid library raised while applying an action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GridAlert {
    /// The window title changed.
    WindowTitle(String),
    /// The icon title changed.
    IconTitle(Option<String>),
    /// The working directory observation changed.
    WorkingDirectory,
    /// The palette changed.
    Palette,
    /// A user variable was set by a shell integration sequence.
    UserVar {
        /// The name.
        name: String,
        /// The value.
        value: String,
    },
    /// Something the profile routes itself reached the library. Recorded so it is visible.
    Unexpected(String),
}

#[derive(Debug, Default)]
struct AlertCollector {
    alerts: Arc<Mutex<Vec<GridAlert>>>,
}

impl AlertHandler for AlertCollector {
    fn alert(&mut self, alert: Alert) {
        let record = match alert {
            Alert::WindowTitleChanged(title) => GridAlert::WindowTitle(title),
            Alert::IconTitleChanged(title) => GridAlert::IconTitle(title),
            Alert::CurrentWorkingDirectoryChanged => GridAlert::WorkingDirectory,
            Alert::PaletteChanged => GridAlert::Palette,
            Alert::SetUserVar { name, value } => GridAlert::UserVar { name, value },
            Alert::OutputSinceFocusLost => return,
            other => GridAlert::Unexpected(format!("{other:?}")),
        };
        if let Ok(mut alerts) = self.alerts.lock() {
            alerts.push(record);
        }
    }
}

/// The configuration the grid library runs under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GridConfig {
    /// Rows of scrollback kept in the library's own buffer.
    pub scrollback_rows: usize,
    /// The pinned Unicode model.
    pub unicode: UnicodeModel,
}

impl GridConfig {
    /// The kr-vt/1 defaults.
    pub const DEFAULT: Self = Self {
        scrollback_rows: 3_500,
        unicode: UnicodeModel::KR_VT_1,
    };
}

impl Default for GridConfig {
    fn default() -> Self {
        Self::DEFAULT
    }
}

#[derive(Debug)]
struct KrVtConfiguration {
    config: GridConfig,
}

impl TerminalConfiguration for KrVtConfiguration {
    fn color_palette(&self) -> ColorPalette {
        // The canonical palette lives in the engine, because a query must be answered from session
        // state rather than from the grid's rendering defaults.
        ColorPalette::default()
    }

    fn scrollback_size(&self) -> usize {
        self.config.scrollback_rows
    }

    fn unicode_version(&self) -> UnicodeVersion {
        self.config.unicode.to_library()
    }

    fn enable_kitty_graphics(&self) -> bool {
        false
    }

    fn enable_kitty_keyboard(&self) -> bool {
        true
    }

    fn enable_title_reporting(&self) -> bool {
        false
    }

    fn enq_answerback(&self) -> String {
        String::new()
    }

    fn normalize_output_to_unicode_nfc(&self) -> bool {
        // Section 8 forbids normalising the application's output.
        false
    }
}

/// A colour in the projection format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Colour {
    /// The session default.
    Default,
    /// A palette index.
    Indexed(u8),
    /// A direct colour.
    Direct(Rgb),
}

/// How a cell run is underlined.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnderlineStyle {
    /// Not underlined.
    None,
    /// One line.
    Single,
    /// Two lines.
    Double,
    /// A curly line.
    Curly,
    /// A dotted line.
    Dotted,
    /// A dashed line.
    Dashed,
}

/// The rendition of a run of cells.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rendition {
    /// Foreground colour.
    pub foreground: Colour,
    /// Background colour.
    pub background: Colour,
    /// Bold.
    pub bold: bool,
    /// Faint.
    pub faint: bool,
    /// Italic.
    pub italic: bool,
    /// Underline style.
    pub underline: UnderlineStyle,
    /// Blinking.
    pub blink: bool,
    /// Reverse video.
    pub reverse: bool,
    /// Invisible.
    pub invisible: bool,
    /// Struck through.
    pub strikethrough: bool,
}

impl Default for Rendition {
    fn default() -> Self {
        Self {
            foreground: Colour::Default,
            background: Colour::Default,
            bold: false,
            faint: false,
            italic: false,
            underline: UnderlineStyle::None,
            blink: false,
            reverse: false,
            invisible: false,
            strikethrough: false,
        }
    }
}

/// A run of cells sharing one rendition and one hyperlink.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Run {
    /// The text.
    pub text: String,
    /// Column of the first cell, zero-based.
    pub column: u32,
    /// Cells the run occupies, counting the width model's wide cells as two.
    pub cells: u32,
    /// The rendition.
    pub rendition: Rendition,
    /// The hyperlink target, when the run is inside one.
    pub hyperlink: Option<String>,
}

/// One canonical row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GridRow {
    /// The stable identifier of the row, which survives scrollback eviction.
    pub stable_id: i64,
    /// Whether the row ends in a soft wrap rather than a hard line break.
    pub soft_wrapped: bool,
    /// The runs, left to right.
    pub runs: Vec<Run>,
}

/// The canonical grid.
pub struct CanonicalGrid {
    terminal: Terminal,
    writer_log: Arc<Mutex<WriterLog>>,
    alerts: Arc<Mutex<Vec<GridAlert>>>,
    size: GridSize,
    config: GridConfig,
    unrecognised: u64,
}

impl core::fmt::Debug for CanonicalGrid {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CanonicalGrid")
            .field("size", &self.size)
            .field("config", &self.config)
            .field("unrecognised", &self.unrecognised)
            .finish_non_exhaustive()
    }
}

impl CanonicalGrid {
    /// Builds a grid of `size`.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::TermError::Geometry`] for dimensions outside the three simultaneous
    /// constraints, and [`crate::error::TermError::Budget`] when the screens would not fit.
    pub fn new(size: GridSize, config: GridConfig, budget: &mut SessionBudget) -> Result<Self> {
        let size = size.validate()?;
        let cost = budget.check_geometry(size)?;
        let writer_log = Arc::new(Mutex::new(WriterLog::default()));
        let alerts = Arc::new(Mutex::new(Vec::new()));
        let mut terminal = Terminal::new(
            to_library_size(size),
            Arc::new(KrVtConfiguration { config }),
            crate::profile::PROFILE_NAME,
            &crate::profile::PROFILE_REVISION.to_string(),
            Box::new(SilentWriter {
                log: Arc::clone(&writer_log),
            }),
        );
        terminal.set_notification_handler(Box::new(AlertCollector {
            alerts: Arc::clone(&alerts),
        }));
        budget.commit_geometry(cost);
        Ok(Self {
            terminal,
            writer_log,
            alerts,
            size,
            config,
            unrecognised: 0,
        })
    }

    /// Applies one approved event.
    ///
    /// An event of any class other than `D` or `M` produces no actions, so the reducer cannot apply
    /// a sequence the policy layer rejected even if it is handed one.
    pub fn apply(&mut self, event: &Event) -> Adapted {
        let adapted = adapt(event);
        if adapted.unrecognised {
            self.unrecognised = self.unrecognised.saturating_add(1);
        }
        if !adapted.actions.is_empty() {
            self.terminal.perform_actions(adapted.actions.clone());
        }
        adapted
    }

    /// How many approved sequences the grid library did not recognise.
    ///
    /// Anything above zero means the class table and the grid disagree about a sequence, which the
    /// conformance fixtures treat as a failure.
    #[must_use]
    pub const fn unrecognised(&self) -> u64 {
        self.unrecognised
    }

    /// What the grid library tried to write. It must stay empty.
    #[must_use]
    pub fn writer_log(&self) -> WriterLog {
        self.writer_log
            .lock()
            .map(|log| log.clone())
            .unwrap_or_default()
    }

    /// Takes the alerts the grid library raised.
    pub fn take_alerts(&mut self) -> Vec<GridAlert> {
        self.alerts
            .lock()
            .map(|mut alerts| core::mem::take(&mut *alerts))
            .unwrap_or_default()
    }

    /// The current size.
    #[must_use]
    pub const fn size(&self) -> GridSize {
        self.size
    }

    /// Resizes the grid.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::TermError::Geometry`] for invalid dimensions and
    /// [`crate::error::TermError::Budget`] when the new screens would not fit. The current grid is
    /// unchanged in both cases.
    pub fn resize(&mut self, size: GridSize, budget: &mut SessionBudget) -> Result<()> {
        let size = size.validate()?;
        let cost = budget.check_geometry(size)?;
        self.terminal.resize(to_library_size(size));
        budget.commit_geometry(cost);
        self.size = size;
        Ok(())
    }

    /// Whether the alternate buffer is active.
    #[must_use]
    pub fn alternate_active(&self) -> bool {
        self.terminal.is_alt_screen_active()
    }

    /// The cursor position, zero-based.
    #[must_use]
    pub fn cursor(&self) -> (u32, u32) {
        let pos = self.terminal.cursor_pos();
        #[expect(
            clippy::cast_sign_loss,
            clippy::cast_possible_truncation,
            reason = "a visible row index is bounded by the validated row count"
        )]
        let row = pos.y.max(0) as u32;
        #[expect(
            clippy::cast_possible_truncation,
            reason = "a column index is bounded by the validated column count"
        )]
        let col = pos.x as u32;
        (col, row)
    }

    /// The top and bottom margins, zero-based and inclusive.
    #[must_use]
    pub fn margins_vertical(&self) -> (u32, u32) {
        let range = self.terminal.get_top_and_bottom_margins();
        #[expect(
            clippy::cast_sign_loss,
            clippy::cast_possible_truncation,
            reason = "margins are bounded by the validated row count"
        )]
        let top = range.start.max(0) as u32;
        #[expect(
            clippy::cast_sign_loss,
            clippy::cast_possible_truncation,
            reason = "margins are bounded by the validated row count"
        )]
        let bottom = (range.end - 1).max(0) as u32;
        (top, bottom)
    }

    /// The left and right margins, zero-based and inclusive.
    #[must_use]
    pub fn margins_horizontal(&self) -> (u32, u32) {
        let range = self.terminal.get_left_and_right_margins();
        #[expect(
            clippy::cast_possible_truncation,
            reason = "margins are bounded by the validated column count"
        )]
        let left = range.start as u32;
        #[expect(
            clippy::cast_possible_truncation,
            reason = "margins are bounded by the validated column count"
        )]
        let right = range.end.saturating_sub(1) as u32;
        (left, right)
    }

    /// The columns that carry a tab stop.
    #[must_use]
    pub fn tab_stops(&self) -> Vec<u32> {
        self.terminal
            .tab_stops_by_column()
            .into_iter()
            .enumerate()
            .filter_map(
                |(index, set)| {
                    if set { u32::try_from(index).ok() } else { None }
                },
            )
            .collect()
    }

    /// The designated character sets for G0 and G1.
    #[must_use]
    pub fn charsets(&self) -> (String, String) {
        (
            format!("{:?}", self.terminal.g0_charset()),
            format!("{:?}", self.terminal.g1_charset()),
        )
    }

    /// Whether the shift-out character set is active.
    #[must_use]
    pub fn shift_out(&self) -> bool {
        self.terminal.shift_out_enabled()
    }

    /// The current graphic rendition, as the parameter list of an SGR sequence.
    #[must_use]
    pub fn sgr_parameters(&self) -> String {
        sgr_parameters(&self.terminal.pen())
    }

    /// The stable identifier range currently held, as a half-open range.
    #[must_use]
    pub fn stable_range(&self) -> (i64, i64) {
        let screen = self.terminal.screen();
        let rows = i64::try_from(screen.scrollback_rows()).unwrap_or(0);
        let oldest = i64::try_from(screen.phys_to_stable_row_index(0)).unwrap_or(0);
        (oldest, oldest.saturating_add(rows))
    }

    /// The visible rows of the active buffer.
    #[must_use]
    pub fn visible_rows(&self) -> Vec<GridRow> {
        let screen = self.terminal.screen();
        let rows = i64::from(self.size.rows);
        let lines = screen.lines_in_phys_range(screen.phys_range(&(0..rows)));
        lines
            .iter()
            .enumerate()
            .map(|(index, line)| {
                let visible = i64::try_from(index).unwrap_or(0);
                let stable = screen.visible_row_to_stable_row(visible);
                GridRow {
                    stable_id: i64::try_from(stable).unwrap_or(0),
                    soft_wrapped: line.last_cell_was_wrapped(),
                    runs: runs_of(line),
                }
            })
            .collect()
    }

    /// Rows from the scrollback, by stable identifier, bounded to `max_rows`.
    #[must_use]
    pub fn history_rows(&self, from: i64, max_rows: usize) -> Vec<GridRow> {
        let screen = self.terminal.screen();
        let (oldest, newest) = self.stable_range();
        let start = from.max(oldest);
        let end = (start.saturating_add(i64::try_from(max_rows).unwrap_or(0))).min(newest);
        if start >= end {
            return Vec::new();
        }
        let range = isize::try_from(start).unwrap_or(0)..isize::try_from(end).unwrap_or(0);
        let phys = screen.stable_range(&range);
        screen
            .lines_in_phys_range(phys)
            .iter()
            .enumerate()
            .map(|(index, line)| GridRow {
                stable_id: start.saturating_add(i64::try_from(index).unwrap_or(0)),
                soft_wrapped: line.last_cell_was_wrapped(),
                runs: runs_of(line),
            })
            .collect()
    }

    /// Bytes the historical rows are currently using, for the budget.
    #[must_use]
    pub fn history_bytes(&self) -> u64 {
        let screen = self.terminal.screen();
        let mut bytes = 0u64;
        screen.for_each_phys_line(|_, line| {
            bytes = bytes.saturating_add(line.as_str().len() as u64);
        });
        bytes
    }
}

fn to_library_size(size: GridSize) -> TerminalSize {
    TerminalSize {
        rows: size.rows as usize,
        cols: size.cols as usize,
        pixel_width: 0,
        pixel_height: 0,
        dpi: 0,
    }
}

fn colour_of(attribute: wezterm_term::color::ColorAttribute) -> Colour {
    use wezterm_term::color::ColorAttribute;
    match attribute {
        ColorAttribute::Default => Colour::Default,
        ColorAttribute::PaletteIndex(index)
        | ColorAttribute::TrueColorWithPaletteFallback(_, index) => Colour::Indexed(index),
        ColorAttribute::TrueColorWithDefaultFallback(tuple) => {
            let (r, g, b, _) = tuple.to_srgb_u8();
            Colour::Direct(Rgb::new(r, g, b))
        }
    }
}

fn rendition_of(attrs: &CellAttributes) -> Rendition {
    Rendition {
        foreground: colour_of(attrs.foreground()),
        background: colour_of(attrs.background()),
        bold: attrs.intensity() == Intensity::Bold,
        faint: attrs.intensity() == Intensity::Half,
        italic: attrs.italic(),
        underline: match attrs.underline() {
            Underline::None => UnderlineStyle::None,
            Underline::Single => UnderlineStyle::Single,
            Underline::Double => UnderlineStyle::Double,
            Underline::Curly => UnderlineStyle::Curly,
            Underline::Dotted => UnderlineStyle::Dotted,
            Underline::Dashed => UnderlineStyle::Dashed,
        },
        blink: attrs.blink() != wezterm_term::Blink::None,
        reverse: attrs.reverse(),
        invisible: attrs.invisible(),
        strikethrough: attrs.strikethrough(),
    }
}

fn runs_of(line: &wezterm_term::Line) -> Vec<Run> {
    let mut runs: Vec<Run> = Vec::new();
    for cell in line.visible_cells() {
        let rendition = rendition_of(cell.attrs());
        let hyperlink = cell.attrs().hyperlink().map(|link| link.uri().to_owned());
        let column = u32::try_from(cell.cell_index()).unwrap_or(0);
        let width = u32::try_from(cell.width()).unwrap_or(1);
        match runs.last_mut() {
            Some(last)
                if last.rendition == rendition
                    && last.hyperlink == hyperlink
                    && last.column + last.cells == column =>
            {
                last.text.push_str(cell.str());
                last.cells += width;
            }
            _ => runs.push(Run {
                text: cell.str().to_owned(),
                column,
                cells: width,
                rendition,
                hyperlink,
            }),
        }
    }
    runs
}

/// Renders a cell rendition as SGR parameters, without the introducer or the final byte.
///
/// DECRQSS asks for exactly this. The list always starts at `0` so the answer is complete rather
/// than relative to whatever came before.
#[must_use]
pub fn sgr_parameters(attrs: &CellAttributes) -> String {
    let mut parts = vec!["0".to_owned()];
    match attrs.intensity() {
        Intensity::Bold => parts.push("1".to_owned()),
        Intensity::Half => parts.push("2".to_owned()),
        Intensity::Normal => {}
    }
    if attrs.italic() {
        parts.push("3".to_owned());
    }
    match attrs.underline() {
        Underline::None => {}
        Underline::Single => parts.push("4".to_owned()),
        Underline::Double => parts.push("21".to_owned()),
        Underline::Curly => parts.push("4:3".to_owned()),
        Underline::Dotted => parts.push("4:4".to_owned()),
        Underline::Dashed => parts.push("4:5".to_owned()),
    }
    if attrs.blink() != wezterm_term::Blink::None {
        parts.push("5".to_owned());
    }
    if attrs.reverse() {
        parts.push("7".to_owned());
    }
    if attrs.invisible() {
        parts.push("8".to_owned());
    }
    if attrs.strikethrough() {
        parts.push("9".to_owned());
    }
    push_colour(&mut parts, colour_of(attrs.foreground()), 30, 38, 90);
    push_colour(&mut parts, colour_of(attrs.background()), 40, 48, 100);
    parts.join(";")
}

fn push_colour(parts: &mut Vec<String>, colour: Colour, base: u16, extended: u16, bright: u16) {
    match colour {
        Colour::Default => {}
        Colour::Indexed(index) if index < 8 => parts.push((base + u16::from(index)).to_string()),
        Colour::Indexed(index) if index < 16 => {
            parts.push((bright + u16::from(index - 8)).to_string());
        }
        Colour::Indexed(index) => parts.push(format!("{extended}:5:{index}")),
        Colour::Direct(rgb) => parts.push(format!("{extended}:2::{}:{}:{}", rgb.r, rgb.g, rgb.b)),
    }
}
