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

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use wezterm_escape_parser::csi::{CSI, Mode, TerminalMode, TerminalModeCode};
use wezterm_escape_parser::osc::OperatingSystemCommand;
use wezterm_escape_parser::{Action, ControlCode};

use wezterm_escape_parser::hyperlink::Hyperlink;
use wezterm_surface::CursorShape;
use wezterm_term::color::ColorPalette;
use wezterm_term::{
    Alert, AlertHandler, CellAttributes, Intensity, Terminal, TerminalConfiguration, TerminalSize,
    Underline, UnicodeVersion, VerticalAlign,
};

use crate::adapter::{AdaptContext, Adapted, adapt};
use crate::budget::{CELL_OVERHEAD_BYTES, GridSize, SessionBudget};
use crate::error::Result;
use crate::event::{Event, EventKind};
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

/// How many alerts are held before the oldest is dropped.
///
/// Alerts are a diagnostic channel. A program that changes its title in a loop must not be able to
/// grow this list, so the newest ones win and the drops are counted.
const MAX_ALERTS: usize = 256;

#[derive(Debug, Default)]
struct AlertCollector {
    alerts: Arc<Mutex<Vec<GridAlert>>>,
    dropped: Arc<AtomicUsize>,
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
            if alerts.len() >= MAX_ALERTS {
                alerts.remove(0);
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
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
    /// Bytes of encoded content one cell may hold.
    pub cell_bytes: usize,
    /// Bytes one row may carry when it is read, which bounds what building a page can allocate.
    pub row_bytes: usize,
}

impl GridConfig {
    /// The kr-vt/1 defaults.
    pub const DEFAULT: Self = Self {
        scrollback_rows: 3_500,
        unicode: UnicodeModel::KR_VT_1,
        cell_bytes: 64,
        row_bytes: 1024 * 1024,
    };
}

impl Default for GridConfig {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// The configuration the grid library reads, with the parts that change at runtime.
///
/// The scrollback size is one of those. Section 8 bounds the historical row cache in bytes, and the
/// library bounds it in rows, so the engine converts: when the retained rows pass the byte bound it
/// lowers the row count here and bumps the generation, and the library evicts on its next append.
#[derive(Debug)]
struct KrVtConfiguration {
    config: GridConfig,
    scrollback_rows: AtomicUsize,
    generation: AtomicUsize,
}

impl TerminalConfiguration for KrVtConfiguration {
    fn generation(&self) -> usize {
        self.generation.load(Ordering::Relaxed)
    }

    fn color_palette(&self) -> ColorPalette {
        // The canonical palette lives in the engine, because a query must be answered from session
        // state rather than from the grid's rendering defaults.
        ColorPalette::default()
    }

    fn scrollback_size(&self) -> usize {
        self.scrollback_rows.load(Ordering::Relaxed)
    }

    fn unicode_version(&self) -> UnicodeVersion {
        self.config.unicode.to_library()
    }

    fn enable_kitty_graphics(&self) -> bool {
        false
    }

    fn enable_kitty_keyboard(&self) -> bool {
        // Keyboard negotiation has one owner in this profile, and it is not the grid. Nothing
        // reaches this path, and leaving it off means nothing ever can.
        false
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
    pub blink: Blink,
    /// Reverse video.
    pub reverse: bool,
    /// Invisible.
    pub invisible: bool,
    /// Struck through.
    pub strikethrough: bool,
    /// Overlined.
    pub overline: bool,
    /// The underline colour, when it differs from the text.
    pub underline_colour: Colour,
    /// Superscript or subscript.
    pub vertical_align: VerticalPosition,
}

/// Where a run sits relative to the baseline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerticalPosition {
    /// On the baseline.
    Baseline,
    /// Raised.
    Superscript,
    /// Lowered.
    Subscript,
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
            blink: Blink::None,
            reverse: false,
            invisible: false,
            strikethrough: false,
            overline: false,
            underline_colour: Colour::Default,
            vertical_align: VerticalPosition::Baseline,
        }
    }
}

/// How a cell blinks.
///
/// The two rates are different sequences and different renderings, so they are different here as
/// well: a projection that reduced them to one would draw a rapid blink as a slow one.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Blink {
    /// Not blinking.
    #[default]
    None,
    /// SGR 5.
    Slow,
    /// SGR 6.
    Rapid,
}

/// Where the cursor was, and what the screen looked like, before one cell was printed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PrintOrigin {
    col: usize,
    row: i64,
    stable_top: i64,
    cursor_seqno: usize,
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
    /// Whether runs were dropped to keep the row inside a page's byte bound.
    pub truncated: bool,
    /// The runs, left to right.
    pub runs: Vec<Run>,
}

/// The canonical grid.
pub struct CanonicalGrid {
    terminal: Terminal,
    writer_log: Arc<Mutex<WriterLog>>,
    alerts: Arc<Mutex<Vec<GridAlert>>>,
    alerts_dropped: Arc<AtomicUsize>,
    configuration: Arc<KrVtConfiguration>,
    size: GridSize,
    config: GridConfig,
    unrecognised: u64,
    tail: Option<TailCell>,
    dropped_marks: u64,
}

/// The cell a text run ended on, so a later combining mark can still join it.
///
/// The grid library drops a zero-width grapheme that arrives with nothing before it in the same
/// call, so a mark that arrives after the screen has settled would be lost. Keeping the cell means
/// the mark is applied by drawing the cell again with the mark on it, which is what the same bytes
/// would have produced had they arrived together.
#[derive(Debug, Clone)]
struct TailCell {
    /// Whether the cell has already reached its content bound.
    ///
    /// Once it has, every later mark is dropped too. Keeping some of a group and none of the next
    /// would make the answer depend on how many marks arrived in each read.
    full: bool,
    /// The scalars that were printed into the cell.
    text: String,
    /// What the cell holds, which a designated character set can make different from the scalars.
    stored: String,
    /// Cells it occupies.
    width: usize,
    /// Column of its first cell.
    col: usize,
    /// Row it is on, relative to the top of the visible screen.
    row: i64,
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
        let alerts_dropped = Arc::new(AtomicUsize::new(0));
        let configuration = Arc::new(KrVtConfiguration {
            config,
            scrollback_rows: AtomicUsize::new(config.scrollback_rows),
            generation: AtomicUsize::new(1),
        });
        let mut terminal = Terminal::new(
            to_library_size(size),
            Arc::clone(&configuration) as Arc<dyn TerminalConfiguration + Send + Sync>,
            crate::profile::PROFILE_NAME,
            &crate::profile::PROFILE_REVISION.to_string(),
            Box::new(SilentWriter {
                log: Arc::clone(&writer_log),
            }),
        );
        terminal.set_notification_handler(Box::new(AlertCollector {
            alerts: Arc::clone(&alerts),
            dropped: Arc::clone(&alerts_dropped),
        }));
        budget.commit_geometry(cost);
        Ok(Self {
            terminal,
            writer_log,
            alerts,
            alerts_dropped,
            configuration,
            size,
            config,
            unrecognised: 0,
            tail: None,
            dropped_marks: 0,
        })
    }

    /// Applies one approved event.
    ///
    /// An event of any class other than `D` or `M` produces no actions, so the reducer cannot apply
    /// a sequence the policy layer rejected even if it is handed one.
    ///
    /// An event the library does not recognise is not applied either. A half-understood sequence is
    /// worse than a consumed one: the canonical grid would do something the physical terminal on
    /// the other side would not, or the other way round.
    pub fn apply(&mut self, event: &Event) -> Adapted {
        let adapted = adapt(
            event,
            AdaptContext {
                rows: self.size.rows,
                cols: self.size.cols,
            },
        );
        if adapted.unrecognised {
            self.unrecognised = self.unrecognised.saturating_add(1);
            return adapted;
        }
        if let EventKind::Text { .. } = &event.kind
            && let Ok(text) = core::str::from_utf8(event.raw())
        {
            self.print(text);
            return adapted;
        }
        // Anything that is not printed text ends the cell, exactly as it would have done inside one
        // read: the library flushes its own print buffer for the same reason.
        self.tail = None;
        if !adapted.actions.is_empty() {
            self.terminal.perform_actions(adapted.actions.clone());
        }
        adapted
    }

    /// Draws a text run as the profile's width model says it should look.
    ///
    /// Two things separate this from handing the whole run to the library. A run that is not plain
    /// ASCII is cut at every cell boundary, so the library's own cluster reducer never sees two
    /// scalars that this model gives a cell each. And the final cell is drawn on its own, so that
    /// its position is known and a combining mark in a later read can still reach it.
    fn print(&mut self, text: &str) {
        let mut rest = text;
        let leading = crate::unicode::leading_zero_width(rest);
        if leading > 0 {
            let (marks, tail) = rest.split_at(leading);
            self.rejoin(marks);
            rest = tail;
        }
        if rest.is_empty() {
            return;
        }
        if crate::unicode::may_join(rest) {
            self.print_cells(rest);
            return;
        }
        // Plain ASCII: one call for the run, and one more for its final cell so that the cell's
        // position is known and a mark in a later read can still reach it.
        let split = crate::unicode::last_cell_start(rest);
        let (head, last) = rest.split_at(split);
        if !head.is_empty() {
            self.terminal
                .perform_actions(vec![Action::PrintString(head.to_owned())]);
        }
        let before = self.print_origin();
        self.terminal
            .perform_actions(vec![Action::PrintString(last.to_owned())]);
        self.tail = self.locate(last, before);
    }

    /// Draws text that starts a cell, cutting it at every cell boundary where that can matter.
    ///
    /// Plain ASCII needs no cutting: the library's clustering and this model agree on every scalar
    /// in it. Anything else is cut at every cell, which is both simpler and safer than listing the
    /// joins the library performs: a list can be incomplete, and the library's list is longer than
    /// emoji.
    fn print_cells(&mut self, text: &str) {
        let starts: Vec<usize> = text
            .char_indices()
            .filter(|(_, scalar)| !crate::unicode::is_zero_width(*scalar))
            .map(|(index, _)| index)
            .collect();
        let Some(first) = starts.first().copied() else {
            // Nothing here has a width of its own, so all of it belongs to the cell before.
            self.rejoin(text);
            return;
        };
        if first > 0 {
            self.rejoin(&text[..first]);
        }
        for (position, start) in starts.iter().copied().enumerate() {
            let end = starts.get(position + 1).copied().unwrap_or(text.len());
            let base = start + text[start..end].chars().next().map_or(0, char::len_utf8);
            self.print_cell(&text[start..base], &text[base..end]);
        }
    }

    /// Draws one cell: the scalar that has a width, then the marks that belong to it.
    ///
    /// The marks are written into the cell rather than printed, for two reasons. The library
    /// clusters what it is given by its own rules, which would split some of them off and drop
    /// them; and printing them separately is exactly what happens when they arrive in a later read,
    /// so doing it the same way here is what makes the two answers identical.
    ///
    /// The row is read first because the library has two row representations, and the compact one
    /// stores a row as one string and works out where its cells are by clustering that string
    /// again. Reading a cell converts the row to the representation that remembers.
    fn print_cell(&mut self, base: &str, marks: &str) {
        let (_, row) = self.cursor_cell();
        let _ = self.terminal.screen_mut().get_cell(0, row);
        let before = self.print_origin();
        self.terminal
            .perform_actions(vec![Action::PrintString(base.to_owned())]);
        self.tail = self.locate(base, before);
        if !marks.is_empty() {
            self.rejoin(marks);
        }
    }

    /// The cursor as a cell coordinate, before or after a print.
    fn cursor_cell(&self) -> (usize, i64) {
        let pos = self.terminal.cursor_pos();
        (pos.x, pos.y)
    }

    /// The cursor and the screen's position, which together say where a print put its cell.
    fn print_origin(&self) -> PrintOrigin {
        let (col, row) = self.cursor_cell();
        PrintOrigin {
            col,
            row,
            stable_top: self.stable_top(),
            cursor_seqno: self.terminal.cursor_pos().seqno,
        }
    }

    /// The stable identifier of the top visible row, which moves exactly when the screen scrolls.
    fn stable_top(&self) -> i64 {
        let screen = self.terminal.screen();
        i64::try_from(screen.visible_row_to_stable_row(0)).unwrap_or(0)
    }

    /// Finds where a just-printed cell landed, so a later combining mark can reach it.
    ///
    /// The column the cursor started at is the cell's column, whether or not the cursor then
    /// advanced: a cell that fills the row to its margin leaves the cursor on top of itself. What
    /// the cursor cannot say is whether the print wrapped before placing anything, and whether that
    /// wrap scrolled the screen. The stable identifier of the top visible row answers the second,
    /// and the row the cursor is on answers the first.
    ///
    /// Comparing what is in the cell would be the obvious alternative and is wrong twice over: two
    /// cells can hold the same text, and a designated character set means a cell may not hold the
    /// scalars that were printed into it.
    fn locate(&mut self, cell: &str, before: PrintOrigin) -> Option<TailCell> {
        let width = crate::unicode::cells_for(cell);
        let (after_col, row) = self.cursor_cell();
        let left = self.terminal.get_left_and_right_margins().start;
        // Four things say the print wrapped before it placed anything: the cursor is on another
        // row, the screen scrolled, the cursor column moved left, or the cursor was placed rather
        // than advanced. The last one is what a scroll inside a region looks like, where the row,
        // the column and the screen's own position can all come back the same.
        let placed = self.terminal.cursor_pos().seqno != before.cursor_seqno;
        let wrapped = self.stable_top() != before.stable_top
            || row != before.row
            || after_col < before.col
            || placed;
        let (col, row) = if wrapped {
            (left, row)
        } else {
            (before.col, before.row)
        };
        let stored = self.cell_text(col, row)?;
        Some(TailCell {
            full: false,
            text: cell.to_owned(),
            stored,
            width,
            col,
            row,
        })
    }

    /// The text of one cell of the active buffer.
    fn cell_text(&mut self, col: usize, row: i64) -> Option<String> {
        self.terminal
            .screen_mut()
            .get_cell(col, row)
            .map(|cell| cell.str().to_owned())
    }

    /// Adds combining marks to the cell the previous text run ended on.
    ///
    /// The cell is written where it already is. Nothing moves the cursor, nothing is printed, and
    /// insert mode plays no part, so the marks cannot shift the cells beside it or wrap the row.
    /// The width cannot change either, because a zero-width scalar adds none.
    ///
    /// The marks are dropped when there is no cell to join, which is the same answer the library
    /// gives for a leading zero-width grapheme, and when the cell has reached its content bound.
    fn rejoin(&mut self, marks: &str) {
        let Some(tail) = self.tail.take() else {
            self.dropped_marks = self.dropped_marks.saturating_add(1);
            return;
        };
        // A cell has a content bound, and the marks that fit inside it are kept whether they
        // arrived together or one at a time: cutting the whole group because the last one does not
        // fit would make the answer depend on how the reads fell.
        if tail.full {
            self.dropped_marks = self.dropped_marks.saturating_add(1);
            self.tail = Some(tail);
            return;
        }
        let room = self.config.cell_bytes.saturating_sub(tail.stored.len());
        let keep = marks
            .char_indices()
            .take_while(|(index, scalar)| index + scalar.len_utf8() <= room)
            .map(|(index, scalar)| index + scalar.len_utf8())
            .last()
            .unwrap_or(0);
        let full = keep < marks.len();
        if full {
            self.dropped_marks = self.dropped_marks.saturating_add(1);
        }
        if keep == 0 {
            self.tail = Some(TailCell { full, ..tail });
            return;
        }
        let marks = &marks[..keep];
        let Some((attributes, found)) = self
            .terminal
            .screen_mut()
            .get_cell(tail.col, tail.row)
            .map(|cell| (cell.attrs().clone(), cell.str().to_owned()))
        else {
            self.dropped_marks = self.dropped_marks.saturating_add(1);
            return;
        };
        // The cell has to still be the one that was drawn. A resize reflows the rows and eviction
        // moves them, so the remembered position can now hold someone else's text, and writing into
        // it would overwrite that instead of adding a mark to this.
        if found != tail.stored {
            self.dropped_marks = self.dropped_marks.saturating_add(1);
            return;
        }
        // The marks go on what the cell holds, not on the scalars that were printed into it. A
        // designated character set makes those different, and rebuilding the cell from the printed
        // scalars would undo the mapping the reducer applied.
        let mut text = tail.stored;
        text.push_str(marks);
        // The write is a change like any other, so it takes a sequence number of its own. Without
        // one the row does not count as changed, and the mark never reaches a client reading
        // deltas.
        self.terminal.increment_seqno();
        let seqno = self.terminal.current_seqno();
        self.terminal
            .screen_mut()
            .set_cell_grapheme(tail.col, tail.row, &text, tail.width, attributes, seqno);
        let stored = self
            .cell_text(tail.col, tail.row)
            .unwrap_or_else(|| text.clone());
        self.tail = Some(TailCell {
            full,
            text: tail.text,
            stored,
            width: tail.width,
            col: tail.col,
            row: tail.row,
        });
    }

    /// How many combining marks arrived with no cell to join.
    #[must_use]
    pub const fn dropped_marks(&self) -> u64 {
        self.dropped_marks
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

    /// How many alerts were dropped because the bounded list was full.
    #[must_use]
    pub fn alerts_dropped(&self) -> usize {
        self.alerts_dropped.load(Ordering::Relaxed)
    }

    /// The library's change counter, which a delta uses as its base.
    #[must_use]
    pub fn sequence_number(&self) -> usize {
        self.terminal.current_seqno()
    }

    /// The stable identifiers of visible rows that changed since `seqno`.
    #[must_use]
    pub fn changed_rows_since(&self, seqno: usize) -> Vec<i64> {
        let (oldest, newest) = self.stable_range();
        let top = newest.saturating_sub(i64::from(self.size.rows)).max(oldest);
        let range = isize::try_from(top).unwrap_or(0)..isize::try_from(newest).unwrap_or(0);
        self.terminal
            .screen()
            .get_changed_stable_rows(range, seqno)
            .into_iter()
            .map(|row| i64::try_from(row).unwrap_or(0))
            .collect()
    }

    /// Debug dump.
    pub fn dump_row0(&self) {
        let screen = self.terminal.screen();
        let lines = screen.lines_in_phys_range(screen.phys_range(&(0..1)));
        for cell in lines[0].visible_cells() {
            println!(
                "   idx={} width={} str={:?}",
                cell.cell_index(),
                cell.width(),
                cell.str()
            );
        }
    }

    /// The current graphic rendition.
    #[must_use]
    pub fn pen(&self) -> Rendition {
        rendition_of(&self.terminal.pen())
    }

    /// The hyperlink the next character printed would belong to.
    #[must_use]
    pub fn pen_hyperlink(&self) -> Option<String> {
        self.terminal
            .pen()
            .hyperlink()
            .map(|link| link.uri().to_owned())
    }

    /// Lowers the scrollback row count so the retained rows fit the byte bound.
    ///
    /// Returns whether the cache was over its bound. The library evicts as it appends, so the
    /// retained rows converge back under the bound over the following rows rather than being
    /// dropped all at once. The lowered row count is proportional to the overshoot, so the
    /// sequence converges rather than oscillating.
    pub fn enforce_row_cache(&mut self, bytes: u64, limit: u64) -> bool {
        if bytes <= limit {
            return false;
        }
        let rows = self.scrollback_rows().max(1);
        #[expect(
            clippy::cast_possible_truncation,
            reason = "the quotient of two byte counts times a row count stays inside usize here"
        )]
        // Aim a little under the bound rather than exactly at it. The row count is worked out from
        // the average cost of a row, the rows are not all the same size, and the visible rows are
        // measured but are not part of the scrollback the count bounds, so aiming exactly at the
        // bound lands just above it.
        let target =
            ((rows as u64).saturating_mul(limit) * 9 / (bytes.max(1).saturating_mul(10))) as usize;
        let current = self.configuration.scrollback_rows.load(Ordering::Relaxed);
        // There is no floor: the retained rows are a cache, and at a wide geometry even a screen's
        // worth of them can pass the bound on its own. Keeping none of them is the right answer
        // then, and the spool still has everything.
        let next = target.min(current);
        if next < current {
            self.configuration
                .scrollback_rows
                .store(next, Ordering::Relaxed);
            self.configuration
                .generation
                .fetch_add(1, Ordering::Relaxed);
        }
        self.trim_scrollback();
        true
    }

    /// Drops the rows that are now past the scrollback bound, without waiting for more output.
    ///
    /// The library evicts while it scrolls, so a session that has stopped printing would otherwise
    /// hold everything it had until it printed again. Scrolling by nothing does the eviction and
    /// leaves the screen alone: no row moves, none is compressed, and none is added.
    fn trim_scrollback(&mut self) {
        let rows = i64::from(self.size.rows);
        let seqno = self.terminal.current_seqno();
        let bidi = self.configuration.bidi_mode();
        self.terminal
            .screen_mut()
            .scroll_up(&(0..rows), 0, seqno, CellAttributes::blank(), bidi);
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
        // The rows reflow, so the cell a mark would have joined is no longer where it was.
        self.tail = None;
        self.terminal.resize(to_library_size(size));
        budget.commit_geometry(cost);
        self.size = size;
        Ok(())
    }

    /// Ends the hyperlink the pen is inside, if it is inside one.
    pub fn close_hyperlink(&mut self) {
        if self.pen_hyperlink().is_none() {
            return;
        }
        self.terminal
            .perform_actions(vec![Action::OperatingSystemCommand(Box::new(
                OperatingSystemCommand::SetHyperlink(None),
            ))]);
    }

    /// Turns newline mode back on, after something in the reducer cleared it.
    pub fn set_newline_mode(&mut self) {
        self.terminal
            .perform_actions(vec![Action::CSI(CSI::Mode(Mode::SetMode(
                TerminalMode::Code(TerminalModeCode::AutomaticNewline),
            )))]);
    }

    /// Selects the shift-out character set again, after something in the reducer cleared it.
    pub fn set_shift_out(&mut self) {
        self.terminal
            .perform_actions(vec![Action::Control(ControlCode::ShiftOut)]);
    }

    /// The DECSCUSR style the reducer is using.
    ///
    /// A cursor restore puts back the shape that was saved with it, without a sequence of its own,
    /// so the reducer is the answer rather than a tracker watching sequences.
    #[must_use]
    pub fn cursor_style(&self) -> u32 {
        match self.terminal.cursor_pos().shape {
            CursorShape::BlinkingBlock => 1,
            CursorShape::SteadyBlock => 2,
            CursorShape::BlinkingUnderline => 3,
            CursorShape::SteadyUnderline => 4,
            CursorShape::BlinkingBar => 5,
            CursorShape::SteadyBar => 6,
            CursorShape::Default => 0,
        }
    }

    /// Whether autowrap is on.
    #[must_use]
    pub fn auto_wrap(&self) -> bool {
        self.terminal.dec_auto_wrap_enabled()
    }

    /// Whether insert mode is on.
    #[must_use]
    pub fn insert_mode(&self) -> bool {
        self.terminal.insert_mode_enabled()
    }

    /// Whether left and right margin mode is on.
    #[must_use]
    pub fn margin_mode(&self) -> bool {
        self.terminal.left_and_right_margin_mode_enabled()
    }

    /// Whether the alternate buffer is active.
    #[must_use]
    pub fn alternate_active(&self) -> bool {
        self.terminal.is_alt_screen_active()
    }

    /// Whether origin mode is on, which makes a cursor report relative to the margins.
    #[must_use]
    pub fn origin_mode(&self) -> bool {
        self.terminal.dec_origin_mode_enabled()
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
                let (runs, truncated) = runs_of(line, self.config.row_bytes);
                GridRow {
                    stable_id: i64::try_from(stable).unwrap_or(0),
                    soft_wrapped: line.last_cell_was_wrapped(),
                    truncated,
                    runs,
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
            .map(|(index, line)| {
                let (runs, truncated) = runs_of(line, self.config.row_bytes);
                GridRow {
                    stable_id: start.saturating_add(i64::try_from(index).unwrap_or(0)),
                    soft_wrapped: line.last_cell_was_wrapped(),
                    truncated,
                    runs,
                }
            })
            .collect()
    }

    /// How many rows the active buffer is retaining above the screen.
    ///
    /// Cheap, unlike measuring them, so it is what decides when a measurement is worth taking.
    #[must_use]
    pub fn scrollback_rows(&self) -> usize {
        self.terminal
            .screen()
            .scrollback_rows()
            .saturating_sub(self.size.rows as usize)
    }

    /// Bytes the retained rows are currently using.
    ///
    /// This counts the encoded text plus the per-cell bookkeeping the grid keeps for it, because
    /// the bound in section 8 is on resident state rather than on characters.
    #[must_use]
    pub fn screen_content_bytes(&self) -> u64 {
        let screen = self.terminal.screen();
        let history = screen
            .scrollback_rows()
            .saturating_sub(self.size.rows as usize);
        let mut bytes = 0u64;
        let mut index = 0usize;
        screen.for_each_phys_line(|_, line| {
            let counted = index >= history;
            index += 1;
            if counted {
                bytes = bytes.saturating_add(line.as_str().len() as u64);
            }
        });
        bytes
    }

    /// Bytes the hyperlinks of the rows that are showing cost.
    #[must_use]
    pub fn screen_link_bytes(&self) -> u64 {
        let screen = self.terminal.screen();
        let history = screen
            .scrollback_rows()
            .saturating_sub(self.size.rows as usize);
        let mut bytes = 0u64;
        let mut index = 0usize;
        screen.for_each_phys_line(|_, line| {
            let counted = index >= history;
            index += 1;
            if counted {
                bytes = bytes.saturating_add(link_bytes(line));
            }
        });
        bytes
    }

    /// Bytes the retained rows are currently using.
    ///
    /// This counts the encoded text plus the per-cell bookkeeping the grid keeps for it, because
    /// the bound in section 8 is on resident state rather than on characters.
    #[must_use]
    pub fn history_bytes(&self) -> u64 {
        let screen = self.terminal.screen();
        // Only the rows above the screen. The screens have a cost of their own in the session
        // budget, and charging them twice would make a wide grid look like it had passed a bound it
        // has nothing to do with.
        let history = screen
            .scrollback_rows()
            .saturating_sub(self.size.rows as usize);
        let mut bytes = 0u64;
        let mut index = 0usize;
        screen.for_each_phys_line(|_, line| {
            let counted = index < history;
            index += 1;
            if !counted {
                return;
            }
            let text = line.as_str().len() as u64;
            let cells = line.len() as u64;
            bytes = bytes.saturating_add(text + cells * CELL_OVERHEAD_BYTES);
            bytes = bytes.saturating_add(link_bytes(line));
        });
        bytes
    }
}

/// What the hyperlinks of one row cost.
///
/// A cell inside a hyperlink holds a reference to the whole link, and a row of them costs far more
/// than its text. Each distinct link object is counted once: the cells of one link share it, and two
/// links that happen to have the same target do not share anything.
fn link_bytes(line: &wezterm_term::Line) -> u64 {
    if !line.has_hyperlink() {
        return 0;
    }
    let mut bytes = 0u64;
    // Every distinct object on the row, not every run of them: one link can be opened once and used
    // in cells that are not next to each other, and charging it again each time would report a row
    // as costing a thousand times what it does.
    let mut seen: BTreeSet<*const Hyperlink> = BTreeSet::new();
    for cell in line.visible_cells() {
        let Some(link) = cell.attrs().hyperlink() else {
            continue;
        };
        if !seen.insert(Arc::as_ptr(link)) {
            continue;
        }
        bytes = bytes.saturating_add(link_object_bytes(link));
    }
    bytes
}

/// What a link of this length will cost once the grid holds it.
///
/// `text` is the parameters and the target, as one string. The bound a caller checks before it
/// applies a link has to be the cost of the object the grid will build, not the length of what
/// arrived.
#[must_use]
pub fn link_cost(text: &str, parameters: usize) -> u64 {
    LINK_OBJECT_BYTES + text.len() as u64 + parameters as u64 * PARAMETER_OVERHEAD_BYTES
}

/// What one link object costs, as the pinned library holds it.
///
/// The strings are the visible part. The object also carries an allocation of its own, a map of its
/// parameters and the bookkeeping around them, which together cost far more than a short target:
/// counting only the characters would report a screen of links as almost free.
fn link_object_bytes(link: &Hyperlink) -> u64 {
    let params: u64 = link
        .params()
        .iter()
        .map(|(key, value)| (key.len() + value.len()) as u64 + PARAMETER_OVERHEAD_BYTES)
        .sum();
    LINK_OBJECT_BYTES + link.uri().len() as u64 + params
}

/// What one link object costs beyond its strings.
const LINK_OBJECT_BYTES: u64 = 512;

/// What one link parameter costs beyond its key and value.
const PARAMETER_OVERHEAD_BYTES: u64 = 128;

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
        blink: match attrs.blink() {
            wezterm_term::Blink::None => Blink::None,
            wezterm_term::Blink::Slow => Blink::Slow,
            wezterm_term::Blink::Rapid => Blink::Rapid,
        },
        reverse: attrs.reverse(),
        invisible: attrs.invisible(),
        strikethrough: attrs.strikethrough(),
        overline: attrs.overline(),
        underline_colour: colour_of(attrs.underline_color()),
        vertical_align: match attrs.vertical_align() {
            VerticalAlign::BaseLine => VerticalPosition::Baseline,
            VerticalAlign::SuperScript => VerticalPosition::Superscript,
            VerticalAlign::SubScript => VerticalPosition::Subscript,
        },
    }
}

fn runs_of(line: &wezterm_term::Line, budget: usize) -> (Vec<Run>, bool) {
    let mut runs: Vec<Run> = Vec::new();
    let mut bytes = 0usize;
    let mut truncated = false;
    // A wide cell covers the column after it. Depending on how the library is storing the row at
    // the moment, that covered column may or may not come back as a cell of its own, so it is
    // skipped by position instead. Without this the same screen reads differently.
    let mut next_column = 0u32;
    for cell in line.visible_cells() {
        let rendition = rendition_of(cell.attrs());
        let hyperlink = cell.attrs().hyperlink().map(|link| link.uri().to_owned());
        let column = u32::try_from(cell.cell_index()).unwrap_or(0);
        let width = u32::try_from(cell.width()).unwrap_or(1);
        if column < next_column {
            continue;
        }
        next_column = column + width.max(1);
        // A row is bounded while it is built, not after. What a row costs is what its runs cost, so
        // a cell that joins the run before it costs its own text and nothing more: charging the
        // target and the run overhead for every cell would cut a row that fits comfortably.
        let joins_previous = runs.last().is_some_and(|last: &Run| {
            last.rendition == rendition
                && last.hyperlink == hyperlink
                && last.column + last.cells == column
        });
        bytes += cell.str().len()
            + if joins_previous {
                0
            } else {
                hyperlink.as_ref().map_or(0, String::len) + RUN_OVERHEAD_BYTES
            };
        if bytes > budget {
            truncated = true;
            break;
        }
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
    (runs, truncated)
}

/// What one run costs beyond its text and its hyperlink target.
pub(crate) const RUN_OVERHEAD_BYTES: usize = 24;

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
    match attrs.blink() {
        wezterm_term::Blink::None => {}
        wezterm_term::Blink::Slow => parts.push("5".to_owned()),
        wezterm_term::Blink::Rapid => parts.push("6".to_owned()),
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
    if attrs.overline() {
        parts.push("53".to_owned());
    }
    match attrs.vertical_align() {
        VerticalAlign::BaseLine => {}
        VerticalAlign::SuperScript => parts.push("73".to_owned()),
        VerticalAlign::SubScript => parts.push("74".to_owned()),
    }
    push_colour(&mut parts, colour_of(attrs.foreground()), 30, 38, 90);
    push_colour(&mut parts, colour_of(attrs.background()), 40, 48, 100);
    // The underline colour has no short form, so it is always the sublist spelling.
    match colour_of(attrs.underline_color()) {
        Colour::Default => {}
        Colour::Indexed(index) => parts.push(format!("58:5:{index}")),
        Colour::Direct(rgb) => parts.push(format!("58:2::{}:{}:{}", rgb.r, rgb.g, rgb.b)),
    }
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
