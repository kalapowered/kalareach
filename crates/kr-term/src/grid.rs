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

use std::collections::{BTreeSet, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use wezterm_escape_parser::csi::{CSI, Mode, TerminalMode, TerminalModeCode};
use wezterm_escape_parser::osc::OperatingSystemCommand;
use wezterm_escape_parser::{Action, ControlCode};

use wezterm_escape_parser::hyperlink::Hyperlink;
use wezterm_surface::CursorShape;
use wezterm_term::color::{ColorAttribute, ColorPalette};
use wezterm_term::{
    Alert, AlertHandler, CellAttributes, Intensity, Terminal, TerminalConfiguration, TerminalSize,
    Underline, UnicodeVersion, VerticalAlign,
};

use crate::adapter::{AdaptContext, Adapted, adapt};
use crate::budget::{CELL_OVERHEAD_BYTES, GridSize, SessionBudget};
use crate::error::Result;
use crate::event::{Event, EventKind};
use crate::layout::{
    ALERT_RECORD_BYTES, CELL_ATTRIBUTES_BYTES, CELL_BYTES, COLOR_ATTRIBUTE_BYTES, HANDLE_BYTES,
    HYPERLINK_BYTES, ROW_RECORD_BYTES, TABLE_PAIR_BYTES, WORD_BYTES,
};
use crate::palette::Rgb;
use crate::snapshot::{ActiveBuffer, Designations, SavedCursor};
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

/// How much of one alert's text is held.
///
/// An alert carries what an application said, and an application can say a great deal: without a
/// bound here a program that sets a long title in a loop would hold megabytes in a list nothing
/// measures. What is kept is enough to see what happened.
const MAX_ALERT_BYTES: usize = 1_024;

/// Keeps the first `MAX_ALERT_BYTES` of `text`, cut at a scalar boundary.
///
/// What is kept is a copy rather than the original cut short, because cutting a string short keeps
/// the room it was holding: the point of the bound is the allocation, not the length.
fn bounded_alert_text(text: String) -> String {
    if text.len() <= MAX_ALERT_BYTES {
        return text;
    }
    let mut end = MAX_ALERT_BYTES;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}

#[derive(Debug, Default)]
struct AlertCollector {
    alerts: Arc<Mutex<Vec<GridAlert>>>,
    dropped: Arc<AtomicUsize>,
}

impl AlertHandler for AlertCollector {
    fn alert(&mut self, alert: Alert) {
        let record = match alert {
            Alert::WindowTitleChanged(title) => GridAlert::WindowTitle(bounded_alert_text(title)),
            Alert::IconTitleChanged(title) => GridAlert::IconTitle(title.map(bounded_alert_text)),
            Alert::CurrentWorkingDirectoryChanged => GridAlert::WorkingDirectory,
            Alert::PaletteChanged => GridAlert::Palette,
            Alert::SetUserVar { name, value } => GridAlert::UserVar {
                name: bounded_alert_text(name),
                value: bounded_alert_text(value),
            },
            Alert::OutputSinceFocusLost => return,
            other => GridAlert::Unexpected(bounded_alert_text(format!("{other:?}"))),
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

/// The most the alert list can be holding.
///
/// Every alert is bounded and the list is bounded, so this is a constant rather than a
/// measurement: it is what the session is charged for the channel, whether or not anything is on
/// it at the moment.
pub const ALERT_LIST_BYTES: u64 =
    // Twice, because the list grows by appending and can be holding twice the alerts it has. Each
    // alert carries at most two strings, each cut to the bound.
    2 * MAX_ALERTS as u64 * (ALERT_RECORD_BYTES + 2 * MAX_ALERT_BYTES as u64);

/// What the rows of both screens come to, gathered as they are walked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct RowsBytes {
    cell_slots: u64,
    records: u64,
}

/// What the retained rows cost, kept as they move rather than worked out by walking them.
///
/// The bound in section 8 is on bytes, and a row can carry a hundred times what the row beside it
/// carries, so the cache cannot be enforced by counting rows. Walking the whole history for every
/// row that joins it is what the bound used to cost, and it grows with the history: a session
/// printing steadily paid a scan of everything it had retained on every read.
///
/// So the figure is carried instead. A row is charged once, where it leaves the screen, and its
/// charge is given back once, where the row is dropped.
///
/// Nothing on this path reads a row that has already been charged, and nothing needs to. What a
/// row costs is its cells, the text they hold and the allocations they keep, and once the library
/// has compressed a row for the scrollback none of those three changes. The library does still
/// touch a retained row — a palette change and a buffer switch stamp a sequence number on one —
/// and a sequence number is not in the charge. What does change a charge is a rewrite, and a
/// resize is the one that does it: the reflow joins and splits the retained rows, and normalising
/// a row to a narrower geometry rewrites it. Both say so through `stale`, and the account is built
/// again from the rows themselves. An erasure needs no rebuild, because it changes no row: it
/// drops the oldest, and their charges come off the front like any other row the library drops.
///
/// Other things do read a retained row. The periodic measurement of what the session's screens and
/// hyperlinks hold walks every row of both buffers wherever it sits, and it runs inside a read; so
/// does a snapshot of the history, when one is asked for. Neither is proportional to the reads: the
/// measurement runs every sixty-fourth read, or when the rows have grown by a page, or when
/// something asked for it. What this account removes is the walk a *single row leaving the screen*
/// used to cost, which is the one that grew with the history and happened thousands of times a
/// read.
///
/// [`CanonicalGrid::measure_history_bytes`] is the same figure worked out the long way, and the
/// two agree after every operation.
#[derive(Debug, Default)]
struct HistoryAccount {
    /// What each retained row costs, oldest first.
    ///
    /// One entry a row, so the rows dropped to bring the cache back under its bound are chosen by
    /// what they cost rather than by an average of what the rows cost.
    charges: VecDeque<u64>,
    /// The sum of `charges`.
    total: u64,
    /// The stable identifier of the oldest retained row.
    start: i64,
    /// The stable identifier one past the newest retained row.
    end: i64,
    /// Whether something rewrote or discarded the rows this account is holding.
    stale: bool,
}

/// The fewest charges the reservation for the account is written against.
///
/// The array is asked for one charge a row, and an allocator gives at least what it is asked for
/// rather than exactly it, so a request for a charge or two can come back with more. This is the
/// smallest non-empty allocation the standard library takes for an eight-byte element, which is as
/// much as such a request can be rounded up to.
const HISTORY_ACCOUNT_MINIMUM_CHARGES: usize = 4;

impl HistoryAccount {
    /// Keeps the array's room at one charge for every row the scrollback may hold.
    ///
    /// Which is what the geometry reserved for it. The array is brought to that room and stays
    /// there, so a row arriving never allocates and a row leaving never gives back room the next
    /// row would ask for again. Sizing the room to the charges on it instead would put a pair of
    /// reallocations, each copying the whole history, on the arrival of a single row whenever the
    /// rows arriving cost a little more than the rows they replace.
    ///
    /// Eviction lowers how many rows the library keeps, not how many the session was admitted for,
    /// so the room stays where it is through one.
    ///
    /// There is one way past that room: a reflow can leave the buffer that is not showing holding
    /// more rows than its geometry reserved for. Those rows are excess and so are their charges,
    /// and the room goes back to the reserved figure here as soon as the rows do.
    fn hold_room_for(&mut self, rows: usize) {
        if self.charges.len() > rows {
            return;
        }
        if self.charges.capacity() < rows {
            self.charges.reserve_exact(rows - self.charges.len());
        } else if self.charges.capacity() > rows {
            self.charges.shrink_to(rows);
        }
    }
}

/// What the rows of both buffers hold, apart from the hyperlink objects on them.
///
/// Read from the rows that are showing and from how many rows there are, so what it costs to read
/// is a property of the geometry rather than of how long the session has been printing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ScreenBytes {
    /// What each buffer's rows that are showing hold beyond their cell slots, primary first.
    pub content: [u64; 2],
    /// What the cells of those rows cost in the slots they take.
    pub cell_slots: u64,
    /// What every row record of both buffers costs in the array it sits in, retained rows
    /// included, and the room the retained rows' account keeps for its charges.
    pub row_records: u64,
}

/// What the grid is holding, measured in one pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BufferBytes {
    /// What each buffer's rows that are showing hold beyond their cell slots, primary first.
    pub content: [u64; 2],
    /// What the cells of those rows cost in the slots they take.
    ///
    /// Every row of the alternate buffer is counted, including any the library is still holding
    /// from a taller geometry; the primary buffer's retained rows are counted against the
    /// historical cache instead, where the rest of what they hold is counted.
    pub cell_slots: u64,
    /// What every row record of both buffers costs in the array it sits in, retained rows
    /// included, and the room the retained rows' account keeps for its charges.
    pub row_records: u64,
    /// What every hyperlink object the grid holds costs: the objects on the rows of both buffers,
    /// the objects on the retained rows, the link the pen is inside and the links the saved
    /// cursors carry.
    ///
    /// One figure, because a row moving between a screen and the retained rows moves no object: a
    /// link counted in one place and not the other would look like an allocation where nothing was
    /// allocated.
    pub links: u64,
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
    /// Whether a resize left each buffer holding more than its geometry can, primary first.
    stale: [bool; 2],
    /// What the retained rows cost, carried rather than measured.
    history: HistoryAccount,
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
    /// constraints, and [`crate::error::TermError::Admission`] when what both buffers can hold at
    /// that size does not fit the session budget.
    pub fn new(size: GridSize, config: GridConfig, budget: &mut SessionBudget) -> Result<Self> {
        let size = size.validate()?;
        let footprint =
            budget.check_geometry(size, config.scrollback_rows, config.cell_bytes as u64)?;
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
        budget.commit_geometry(footprint);
        let mut grid = Self {
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
            stale: [false, false],
            history: HistoryAccount::default(),
        };
        grid.sync_history();
        Ok(grid)
    }

    /// Applies one approved event.
    ///
    /// An event of any class other than `D` or `M` produces no actions, so the reducer cannot apply
    /// a sequence the policy layer rejected even if it is handed one.
    ///
    /// An event the library does not recognise is not applied either. A half-understood sequence is
    /// worse than a consumed one: the canonical grid would do something the physical terminal on
    /// the other side would not, or the other way round.
    ///
    /// The actions this applied are handed to the library rather than copied to it, so the record
    /// it returns says what the adaptation decided and carries no actions. Copying them would put
    /// a second list of every event's actions on the path every byte of output takes.
    pub fn apply(&mut self, event: &Event) -> Adapted {
        let mut adapted = adapt(
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
            self.sync_history();
            return adapted;
        }
        // Anything that is not printed text ends the cell, exactly as it would have done inside one
        // read: the library flushes its own print buffer for the same reason.
        self.tail = None;
        if !adapted.actions.is_empty() {
            self.terminal
                .perform_actions(core::mem::take(&mut adapted.actions));
        }
        self.sync_history();
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
        self.print_text(last);
        self.tail = self.locate(last, before);
    }

    /// Draws text that starts a cell, cutting it at every cell boundary where that can matter.
    ///
    /// Plain ASCII needs no cutting: the library's clustering and this model agree on every scalar
    /// in it. Anything else is cut at every cell, which is both simpler and safer than listing the
    /// joins the library performs: a list can be incomplete, and the library's list is longer than
    /// emoji.
    fn print_cells(&mut self, text: &str) {
        // One pass, carrying the cell that has been opened and not yet drawn. A cell is a scalar
        // with a width of its own and the zero-width scalars after it, so a cell is complete
        // exactly where the next scalar with a width of its own begins.
        let mut cell: Option<(usize, usize)> = None;
        for (index, scalar) in text.char_indices() {
            if crate::unicode::is_zero_width(scalar) {
                continue;
            }
            if let Some((start, base)) = cell {
                self.print_cell(&text[start..base], &text[base..index]);
            } else if index > 0 {
                // Whatever came before the first cell of this run has no width of its own, so it
                // belongs to the cell the run before it ended on.
                self.rejoin(&text[..index]);
            }
            cell = Some((index, index + scalar.len_utf8()));
        }
        match cell {
            Some((start, base)) => self.print_cell(&text[start..base], &text[base..]),
            // Nothing here has a width of its own, so all of it belongs to the cell before.
            None => self.rejoin(text),
        }
    }

    /// Draws one run of text, as one scalar where it is one scalar.
    ///
    /// A single scalar goes as itself rather than as a string, which the library reads the same way
    /// and which costs no allocation. Every cell a session prints comes through here, so that is
    /// one allocation a cell.
    fn print_text(&mut self, text: &str) {
        let mut scalars = text.chars();
        let action = match (scalars.next(), scalars.next()) {
            (Some(scalar), None) => Action::Print(scalar),
            _ => Action::PrintString(text.to_owned()),
        };
        self.terminal.perform_actions(vec![action]);
    }

    /// Draws one cell: the scalar that has a width, then the marks that belong to it.
    ///
    /// The marks are written into the cell rather than printed, for two reasons. The library
    /// clusters what it is given by its own rules, which would split some of them off and drop
    /// them; and printing them separately is exactly what happens when they arrive in a later read,
    /// so doing it the same way here is what makes the two answers identical.
    fn print_cell(&mut self, base: &str, marks: &str) {
        let before = self.print_origin();
        self.print_text(base);
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
    /// Returns whether the rows were over it. The caller applies it while the primary buffer is
    /// showing: the library drops the rows it is told to drop as it appends, and nothing appends
    /// to a buffer that is not showing.
    ///
    /// One pass is enough, and it lands under the bound rather than converging towards it. The row
    /// count kept is read off what the rows cost: the oldest are given up one at a time until what
    /// is left costs no more than the bound, and that count becomes the library's scrollback size.
    /// Working it out from the average cost of a row would leave the answer wrong whenever the
    /// rows are not all the same size, which is the usual case. Nothing is walked and no cell is
    /// read: every one of those figures was taken where its row left the screen.
    pub fn enforce_row_cache(&mut self, limit: u64) -> bool {
        if self.history.total <= limit {
            return false;
        }
        let mut remaining = self.history.total;
        let mut given_up = 0usize;
        for charge in &self.history.charges {
            if remaining <= limit {
                break;
            }
            remaining = remaining.saturating_sub(*charge);
            given_up += 1;
        }
        let keep = self.history.charges.len().saturating_sub(given_up);
        let current = self.configuration.scrollback_rows.load(Ordering::Relaxed);
        // There is no floor: the retained rows are a cache, and at a wide geometry even a screen's
        // worth of them can pass the bound on its own. Keeping none of them is the right answer
        // then, and the spool still has everything.
        if keep < current {
            self.configuration
                .scrollback_rows
                .store(keep, Ordering::Relaxed);
            self.configuration
                .generation
                .fetch_add(1, Ordering::Relaxed);
        }
        self.trim_scrollback();
        self.sync_history();
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

    /// The title the grid is holding.
    ///
    /// The grid keeps its own copy of what an OSC title set, and it is cut to the length a session
    /// holds before it arrives, so the two owners hold the same string.
    #[must_use]
    pub fn title(&self) -> &str {
        self.terminal.get_title()
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
    /// [`crate::error::TermError::Admission`] when what both buffers can hold at the new size does
    /// not fit the session budget. The current grid is unchanged in both cases.
    pub fn resize(&mut self, size: GridSize, budget: &mut SessionBudget) -> Result<()> {
        let size = size.validate()?;
        let footprint = budget.check_geometry(
            size,
            self.config.scrollback_rows,
            self.config.cell_bytes as u64,
        )?;
        // The rows reflow, so the cell a mark would have joined is no longer where it was.
        self.tail = None;
        self.terminal.resize(to_library_size(size));
        self.size = size;
        self.stale = [true, true];
        // The reflow rewrote every retained row and joined and split some of them, so what the
        // account is carrying describes rows that no longer exist.
        self.history.stale = true;
        self.normalise_storage();
        budget.commit_geometry(footprint);
        Ok(())
    }

    /// Brings the buffer that is showing back to what its geometry can hold, if a resize left it
    /// holding more.
    ///
    /// Returns whether there was anything to do. A resize can only settle the buffer that is
    /// showing, so the other one is settled when it comes back.
    pub fn settle_active_buffer(&mut self) -> bool {
        if !self.stale[usize::from(self.alternate_active())] {
            return false;
        }
        self.normalise_storage();
        true
    }

    /// Brings the screen that is showing back to what its geometry can hold.
    ///
    /// Reflowing a narrower screen builds as many rows as the text needs, which can be many times
    /// the rows the geometry keeps, and it hands back a row of blanks whole rather than cutting it
    /// to the new width. Neither is undone until something scrolls. So the row count is brought
    /// back to the screen and its scrollback, and a row still holding more columns than the screen
    /// has is cut to the columns it has. A row that survived reflow at its old width is blank, so
    /// cutting it loses nothing: the columns beyond the screen were never going to be shown.
    ///
    /// Only the screen that is showing. Reaching into the other one is not something the library
    /// offers, so it is done again when that one comes back.
    fn normalise_storage(&mut self) {
        let alternate = self.alternate_active();
        self.stale[usize::from(alternate)] = false;
        // Every row of the screen that is showing is cut to the columns the geometry has, retained
        // rows included, so the charges taken when those rows left the screen no longer describe
        // them.
        self.history.stale = true;
        let cols = self.size.cols as usize;
        let rows = self.size.rows as usize;
        let seqno = self.terminal.current_seqno();
        let screen = self.terminal.screen_mut();
        screen.for_each_phys_line_mut(|_, line| {
            if line.len() <= cols {
                return;
            }
            if line.is_whitespace() {
                // Rebuilt rather than cut. Shortening a row leaves the room it was holding, and
                // this is the row a reflow handed back whole: it is as wide as the screen used to
                // be. Every cell on it is a blank of one column, so the cells that fit are copied
                // as they are and the rest are the columns the screen no longer has.
                let wrapped = line.last_cell_was_wrapped();
                let mut cells: Vec<wezterm_term::Cell> = Vec::with_capacity(cols);
                cells.extend(line.visible_cells().take(cols).map(|cell| cell.as_cell()));
                cells.resize(cols, wezterm_term::Cell::blank());
                *line = wezterm_term::Line::from_cells(cells, seqno);
                if wrapped {
                    line.set_last_cell_was_wrapped(true, seqno);
                }
            } else {
                line.resize(cols, seqno);
            }
        });
        if alternate {
            // The alternate buffer keeps no history, so a shorter geometry leaves it holding rows
            // nothing can reach. Scrolling does not drop them: with no scrollback the library
            // removes exactly as many rows as it adds. This is the one operation that does.
            if screen.scrollback_rows() > rows {
                screen.erase_scrollback();
            }
            self.sync_history();
            return;
        }
        self.trim_scrollback();
        self.sync_history();
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
        self.sync_history();
    }

    /// Turns newline mode back on, after something in the reducer cleared it.
    pub fn set_newline_mode(&mut self) {
        self.terminal
            .perform_actions(vec![Action::CSI(CSI::Mode(Mode::SetMode(
                TerminalMode::Code(TerminalModeCode::AutomaticNewline),
            )))]);
        self.sync_history();
    }

    /// Selects the shift-out character set again, after something in the reducer cleared it.
    pub fn set_shift_out(&mut self) {
        self.terminal
            .perform_actions(vec![Action::Control(ControlCode::ShiftOut)]);
        self.sync_history();
    }

    /// The DECSCUSR style the reducer is using.
    ///
    /// A cursor restore puts back the shape that was saved with it, without a sequence of its own,
    /// so the reducer is the answer rather than a tracker watching sequences.
    #[must_use]
    pub fn cursor_style(&self) -> u32 {
        style_of(self.terminal.cursor_pos().shape)
    }

    /// Whether the next printable character wraps before it is placed.
    ///
    /// A cursor in the last column of a full row and a cursor in the last column of a row that
    /// still has space are the same coordinates, and the next character goes to a different place
    /// in each, so a snapshot that left this out would put it in the wrong cell.
    #[must_use]
    pub fn pending_wrap(&self) -> bool {
        self.terminal.pending_wrap()
    }

    /// The cursor one buffer has saved, if it has saved one.
    ///
    /// Each buffer keeps its own, and a save carries the rendition, the character sets, origin
    /// mode and the cursor shape with it. A restore that put back only a position would leave an
    /// application drawing in the wrong colours from the wrong origin.
    #[must_use]
    pub fn saved_cursor(&self, alternate: bool) -> Option<SavedCursor> {
        let saved = self.terminal.saved_cursor(alternate)?;
        #[expect(
            clippy::cast_sign_loss,
            clippy::cast_possible_truncation,
            reason = "a saved row index is bounded by the validated row count"
        )]
        let row = saved.position.y.max(0) as u32;
        #[expect(
            clippy::cast_possible_truncation,
            reason = "a saved column index is bounded by the validated column count"
        )]
        let col = saved.position.x as u32;
        Some(SavedCursor {
            buffer: if alternate {
                ActiveBuffer::Alternate
            } else {
                ActiveBuffer::Primary
            },
            col,
            row,
            pending_wrap: saved.wrap_next,
            rendition: rendition_of(&saved.pen),
            charsets: Designations {
                g0: format!("{:?}", saved.g0_charset),
                g1: format!("{:?}", saved.g1_charset),
            },
            origin_mode: saved.dec_origin_mode,
            style: style_of(saved.position.shape),
            hyperlink: saved.pen.hyperlink().map(|link| link.uri().to_owned()),
        })
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
        self.rows_of(self.terminal.screen())
    }

    /// The visible rows of the buffer that is not active.
    ///
    /// Section 8 asks a restoration to reproduce both buffers. A client that reconnects while a
    /// full-screen application is running gets the application's screen from [`Self::visible_rows`]
    /// and what the shell left behind from here, so leaving the application puts the session back
    /// where it was instead of on a blank screen.
    #[must_use]
    pub fn inactive_rows(&self) -> Vec<GridRow> {
        self.rows_of(self.terminal.inactive_screen())
    }

    fn rows_of(&self, screen: &wezterm_term::screen::Screen) -> Vec<GridRow> {
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
        self.primary_screen()
            .scrollback_rows()
            .saturating_sub(self.size.rows as usize)
    }

    /// What the grid is holding.
    ///
    /// Both buffers, because the one that is not showing still holds its own: a session can fill
    /// the primary buffer, switch, and fill the alternate one as well.
    #[must_use]
    pub fn buffer_bytes(&self) -> BufferBytes {
        let screens = self.screen_bytes();
        BufferBytes {
            content: screens.content,
            cell_slots: screens.cell_slots,
            row_records: screens.row_records,
            links: self.link_bytes(),
        }
    }

    /// What the rows of both buffers hold, apart from the hyperlink objects on them.
    ///
    /// The rows that are showing are read; the retained rows are counted. A retained row's content
    /// is the historical cache's to carry, and it is carried, charged where the row leaves the
    /// screen. What is left of a retained row is the slot it takes in the array its screen keeps,
    /// and how many slots a screen has taken is a number the library already has. So this costs
    /// what a screen costs however much history sits behind it, and a session printing steadily
    /// can afford it on every read.
    #[must_use]
    pub fn screen_bytes(&self) -> ScreenBytes {
        let alternate = self.alternate_active();
        let mut rows = RowsBytes::default();
        let active = self.showing_content_of(self.terminal.screen(), !alternate, &mut rows);
        let inactive =
            self.showing_content_of(self.terminal.inactive_screen(), alternate, &mut rows);
        let content = if alternate {
            [inactive, active]
        } else {
            [active, inactive]
        };
        ScreenBytes {
            content,
            cell_slots: rows.cell_slots,
            // The retained rows' account is an array of row slots like the screens' own, and it
            // holds its room whether or not the charges are on it, so what is measured is the room
            // rather than the charges.
            row_records: rows.records.saturating_add(
                (self.history.charges.capacity() as u64).saturating_mul(HISTORY_CHARGE_SLOT_BYTES),
            ),
        }
    }

    /// What every hyperlink object the grid holds costs.
    ///
    /// The one walk of every row there is, and the reason it is a walk: a link object is shared.
    /// The cells of one link hold the same object, one link can be on rows that are not next to
    /// each other and in either buffer, and the pen keeps the one it is inside, so an object has to
    /// be found wherever it sits and counted once. A row moving between a screen and the retained
    /// rows moves no object, and this reads the two the same way, so nothing appears or disappears
    /// when a row scrolls off.
    #[must_use]
    pub fn link_bytes(&self) -> u64 {
        let mut seen = BTreeSet::new();
        let mut links = 0u64;
        // The pen's link and the saved cursors' links come first, because they are on no row: a
        // link that is opened and then saved, or opened over an empty screen, is held by the pen
        // alone, and a measurement that only walked rows would report it as free.
        if let Some(link) = self.terminal.pen().hyperlink() {
            add_link_object(link, &mut seen, &mut links);
        }
        for alternate in [false, true] {
            if let Some(saved) = self.terminal.saved_cursor(alternate)
                && let Some(link) = saved.pen.hyperlink()
            {
                add_link_object(link, &mut seen, &mut links);
            }
        }
        for screen in [self.terminal.screen(), self.terminal.inactive_screen()] {
            screen.for_each_phys_line(|_, line| count_row_links(line, &mut seen, &mut links));
        }
        links
    }

    /// The screen the history belongs to, wherever it is.
    ///
    /// The alternate buffer keeps no history, so the retained rows are always the primary one's.
    /// While the alternate buffer is showing they are still there and a resize can still move rows
    /// into them, so what they cost is read from the primary screen rather than from whichever
    /// screen happens to be active.
    fn primary_screen(&self) -> &wezterm_term::screen::Screen {
        if self.alternate_active() {
            self.terminal.inactive_screen()
        } else {
            self.terminal.screen()
        }
    }

    /// What one screen's rows that are showing hold, adding its row records to a running total.
    ///
    /// `keeps_history` says whether the rows above the screen belong to the historical cache,
    /// which has a bound of its own. Only the primary buffer keeps one. The alternate buffer's
    /// rows are all its own, including any the library is still holding from a taller geometry, so
    /// treating the oldest of them as somebody else's would leave them in no account at all.
    fn showing_content_of(
        &self,
        screen: &wezterm_term::screen::Screen,
        keeps_history: bool,
        rows: &mut RowsBytes,
    ) -> u64 {
        let held = screen.scrollback_rows();
        let retained = if keeps_history {
            held.saturating_sub(self.size.rows as usize)
        } else {
            0
        };
        // Every row record, showing or retained: the record is a slot in the array its screen
        // keeps, and a screen holding more rows than its geometry has is holding more slots. How
        // many it holds is all this needs, so no row is read to count it.
        rows.records = rows
            .records
            .saturating_add((held as u64).saturating_mul(ROW_SLOT_BYTES));
        let mut content = 0u64;
        let mut index = 0usize;
        screen.for_each_phys_line(|_, line| {
            let showing = index >= retained;
            index += 1;
            if showing {
                content = content.saturating_add(row_content_bytes(line));
                rows.cell_slots = rows
                    .cell_slots
                    .saturating_add((line.len() as u64).saturating_mul(CELL_OVERHEAD_BYTES));
            }
        });
        content
    }

    /// Brings the account of the retained rows up to date with the screen.
    ///
    /// Every operation that can move a row leaves this called, so what the account holds is what
    /// the screen holds whenever anything reads it. The work is proportional to the rows that
    /// moved: an operation that moved none costs two reads and a comparison.
    ///
    /// The retained rows are the stable identifiers `[start, end)`, and both ends only ever move
    /// forwards while rows are being added and dropped. A row that leaves the screen advances the
    /// end; a row the library drops to make room advances the start. So the two ends say exactly
    /// which rows joined and which were given up, without reading a row to find out.
    ///
    /// An end that went backwards, or a rewrite that said so, means the rows themselves changed
    /// rather than moved, and the account is built again from them. Only a resize and an erasure
    /// do that, and neither is on the path a printing application takes.
    fn sync_history(&mut self) {
        let screen = self.primary_screen();
        let history = screen
            .scrollback_rows()
            .saturating_sub(self.size.rows as usize);
        let start = i64::try_from(screen.phys_to_stable_row_index(0)).unwrap_or(0);
        let end = start.saturating_add(i64::try_from(history).unwrap_or(0));
        if self.history.stale || start < self.history.start || end < self.history.end {
            self.rebuild_history(start, end);
            return;
        }
        // The rows the library dropped to make room. They are the oldest, so their charges are at
        // the front of the account. A drop count past what the account holds means a row joined
        // and was given up between two of these calls, and a row that was never charged gives
        // nothing back.
        let dropped = usize::try_from(start.saturating_sub(self.history.start)).unwrap_or(0);
        for _ in 0..dropped.min(self.history.charges.len()) {
            let charge = self.history.charges.pop_front().unwrap_or(0);
            self.history.total = self.history.total.saturating_sub(charge);
        }
        self.history.hold_room_for(self.config.scrollback_rows);
        // What is left is what the rows that have just arrived cost, and they are the newest rows
        // of the history. Each is read once, here, and never again, and each is reached by its own
        // index rather than by walking to it, so a read that scrolled one row reads one row.
        let arrived = history.saturating_sub(self.history.charges.len());
        if arrived > 0 {
            if self.alternate_active() {
                // Nothing prints into the primary buffer while the alternate one is showing, so a
                // row can only have reached its history through a resize, and a resize says so
                // rather than arriving here. Charging one would mean reaching into the screen that
                // is not showing, which the library does not offer, so the account is built again.
                self.rebuild_history(start, end);
                return;
            }
            let first = history - arrived;
            let mut charges = core::mem::take(&mut self.history.charges);
            let mut total = self.history.total;
            let screen = self.terminal.screen_mut();
            for index in first..history {
                let charge = history_row_bytes(screen.line_mut(index));
                total = total.saturating_add(charge);
                charges.push_back(charge);
            }
            self.history.charges = charges;
            self.history.total = total;
        }
        self.history.start = start;
        self.history.end = end;
    }

    /// Builds the account again from the rows themselves.
    ///
    /// The one walk of the retained rows there is. It happens where the rows changed rather than
    /// moved: a resize reflows them, and an erasure discards them.
    fn rebuild_history(&mut self, start: i64, end: i64) {
        let rows = usize::try_from(end.saturating_sub(start)).unwrap_or_default();
        // The room the geometry reserved, or the rows there are if a reflow left more of them.
        let mut charges = VecDeque::with_capacity(rows.max(self.config.scrollback_rows));
        let mut total = 0u64;
        self.walk_history(|charge| {
            total = total.saturating_add(charge);
            charges.push_back(charge);
        });
        self.history = HistoryAccount {
            charges,
            total,
            start,
            end,
            stale: false,
        };
    }

    /// Hands `charge` what each retained row costs, oldest first.
    fn walk_history<F: FnMut(u64)>(&self, mut charge: F) {
        let screen = self.primary_screen();
        let history = screen
            .scrollback_rows()
            .saturating_sub(self.size.rows as usize);
        let mut index = 0usize;
        screen.for_each_phys_line(|_, line| {
            if index < history {
                charge(history_row_bytes(line));
            }
            index += 1;
        });
    }

    /// Bytes the retained rows are currently using.
    ///
    /// Carried rather than measured: a row is charged where it leaves the screen and gives its
    /// charge back where it is dropped, so this is a read of one figure however long the history
    /// is. [`Self::measure_history_bytes`] is the same answer worked out by walking the rows, and
    /// the two agree after every operation.
    ///
    /// This counts the encoded text plus the per-cell bookkeeping the grid keeps for it, because
    /// the bound in section 8 is on resident state rather than on characters.
    #[must_use]
    pub const fn history_bytes(&self) -> u64 {
        self.history.total
    }

    /// What a walk of the retained rows says they cost.
    ///
    /// The long way round, and the proof that the carried figure is the right one. Nothing on the
    /// path a printing application takes calls it.
    #[must_use]
    pub fn measure_history_bytes(&self) -> u64 {
        let mut total = 0u64;
        self.walk_history(|charge| total = total.saturating_add(charge));
        total
    }
}

/// What one retained row costs the historical cache.
///
/// Its cells and the text and attribute allocations they hold. Two things are deliberately not
/// here. The slot the row takes in its screen's array is reserved whole when the geometry is
/// admitted, scrollback slots included, so charging it again would count it twice. And the
/// hyperlink objects on it are charged to the session's one hyperlink envelope wherever they are,
/// so that a row scrolling off the screen moves no charge from one account to another.
///
/// What is left depends on the row and on nothing else, which is what lets the charge be taken
/// once, where the row leaves the screen, and carried until the row is dropped.
fn history_row_bytes(line: &wezterm_term::Line) -> u64 {
    let cells = line.len() as u64;
    row_content_bytes(line).saturating_add(cells.saturating_mul(CELL_OVERHEAD_BYTES))
}

/// Adds one link object, if it has not been counted already.
///
/// A cell inside a hyperlink holds a reference to the whole link, and a row of them costs far more
/// than its text. Each distinct object is counted once and no more: the cells of one link share
/// it, one link can be used in cells that are not next to each other and on rows that are not next
/// to each other, and two links that happen to have the same target share nothing.
fn add_link_object(link: &Arc<Hyperlink>, seen: &mut BTreeSet<*const Hyperlink>, bytes: &mut u64) {
    if seen.insert(Arc::as_ptr(link)) {
        *bytes = bytes.saturating_add(link_object_bytes(link));
    }
}

/// What a link of this length will cost once the grid holds it.
///
/// `text` is the parameters and the target, as one string. The bound a caller checks before it
/// applies a link has to be the cost of the object the grid will build, not the length of what
/// arrived. The object does not exist yet, so its strings are charged at twice what they hold,
/// which is the most a doubling allocator keeps for them; the next measurement replaces this with
/// what the object actually holds.
#[must_use]
pub fn link_cost(text: &str, parameters: usize) -> u64 {
    LINK_OBJECT_BYTES + 2 * text.len() as u64 + table_bytes(parameters)
}

/// What one link object costs, as the pinned library holds it.
///
/// The strings are the visible part. The object also carries an allocation of its own, a map of its
/// parameters and the bookkeeping around them, which together cost far more than a short target:
/// counting only the characters would report a screen of links as almost free.
fn link_object_bytes(link: &Hyperlink) -> u64 {
    let params = link.params();
    // The table as it is allocated rather than as many entries as it holds: a table keeps room it
    // is not using, and a session that filled one would be under-charged for every link in it.
    let mut bytes = LINK_OBJECT_BYTES
        .saturating_add(link.uri().len() as u64)
        // The room the table is holding rather than the entries in it: a table grows before it
        // looks for the key it is given, so a parameter field that repeats a key leaves a table
        // larger than its entries.
        .saturating_add(table_bytes(params.capacity()));
    for (key, value) in params {
        bytes = bytes.saturating_add((key.capacity() + value.capacity()) as u64);
    }
    bytes
}

/// What the table of distinct hyperlink targets costs for one entry, beyond the bytes of the
/// target it holds.
///
/// The table keeps its entries in nodes that hold several of them and are allocated whole, so an
/// entry is charged for the slot it takes, for the room beside it the node is holding empty, and
/// for the pointer the node above keeps to it.
pub const LINK_TABLE_ENTRY_BYTES: u64 = 2 * HANDLE_BYTES + 2 * WORD_BYTES;

/// What the first node of the table of distinct hyperlink targets costs.
///
/// A node holds several entries and is allocated whole, so the first target to arrive pays for a
/// node that is almost all empty.
pub const LINK_TABLE_NODE_BYTES: u64 = 11 * HANDLE_BYTES + 4 * WORD_BYTES;

/// What the table of distinct hyperlink targets costs for `target`.
///
/// The string as it is held rather than as it reads: it is built by appending, so it can be
/// holding twice the bytes of the target.
pub fn link_table_entry_bytes(target: &String) -> u64 {
    STRING_HANDLE_BYTES + target.capacity() as u64 + LINK_TABLE_ENTRY_BYTES
}

/// What one charge takes in the array the retained rows' account keeps.
pub const HISTORY_CHARGE_SLOT_BYTES: u64 = size_of::<u64>() as u64;

/// What one retained row is reserved at in the account of what the retained rows cost.
///
/// One charge a row, at twice what a charge takes. A retained row is a slot here as well as a slot
/// in its screen's own array, the account holds that room for every row the scrollback may keep
/// whether or not the rows are there, and an array allocates at least the room it is asked for
/// rather than exactly it, so the reservation carries the same doubling every other array in this
/// model carries.
pub const HISTORY_CHARGE_BYTES: u64 = 2 * HISTORY_CHARGE_SLOT_BYTES;

/// The least the account of what the retained rows cost is reserved at.
///
/// A session whose scrollback is a row or two asks for a charge or two and can be given the
/// smallest allocation there is, so the reservation carries that floor, at twice it like
/// everything else here. Without it the reservation would be under the truth at the smallest
/// geometries.
pub const HISTORY_ACCOUNT_MINIMUM_BYTES: u64 =
    (2 * HISTORY_ACCOUNT_MINIMUM_CHARGES * size_of::<u64>()) as u64;

/// What one row costs in the array its screen keeps, whether or not anything is on it.
///
/// A screen holds its rows in one array of row records, and the array is grown by doubling, so it
/// can be holding room for twice the rows it has. An empty row is a record like any other: it
/// occupies its slot, and a screen of them is not free.
///
/// A row record is the one part of this model whose size is not the same on every supported host,
/// so the figure is the largest of them and [`crate::layout`] says why.
pub const ROW_SLOT_BYTES: u64 = 2 * ROW_RECORD_BYTES;

/// What one row allocates for itself before anything is on it.
///
/// The compact form a row is usually held in starts with room for eighty bytes of text, and it
/// keeps two further allocations beside that text: the offsets of its cells, where the text is not
/// its own record of where they are, and a bit for each cell that is two columns wide. Both are
/// reached through a pointer, so each costs a header of its own whatever it holds. An empty row is
/// not free, which is the whole reason to count it.
pub const ROW_STORAGE_BYTES: u64 =
    CLUSTERED_TEXT_CAPACITY + HANDLE_BYTES + FIXED_BITSET_HEADER_BYTES;

/// The room the compact form of a row asks for when it is built.
const CLUSTERED_TEXT_CAPACITY: u64 = 80;

/// What the bit-per-cell record of the wide cells costs before its bits.
///
/// A vector of blocks and the length beside it, which is what the set is.
const FIXED_BITSET_HEADER_BYTES: u64 = HANDLE_BYTES + WORD_BYTES;

/// What the grid keeps for the titles it is told about.
///
/// The grid holds its own copy of the window title and the icon title. Both are cut to the length
/// a session holds before they reach it, so this is a figure rather than a measurement: room for
/// two titles, each at twice what one may hold.
pub const GRID_TITLE_BYTES: u64 =
    2 * (STRING_HANDLE_BYTES + 2 * crate::title::MAX_TITLE_BYTES as u64);

/// What a cell's text costs beyond its bytes once it no longer fits inside the cell.
///
/// A cell holds its text in the cell itself while that text is shorter than a machine word and
/// covers at most two columns. Past either of those the grid puts the text on the heap behind a
/// header that holds the byte vector and the width the text was measured at.
pub const CELL_TEXT_HEAP_BYTES: u64 = HANDLE_BYTES + WORD_BYTES;

/// Whether a cell's text is too big to live inside the cell.
fn cell_text_is_on_the_heap(text: &str, width: usize) -> bool {
    text.len() >= size_of::<u64>() || width > 2
}

/// What a string costs beyond the bytes it holds: the pointer, the length and the capacity.
pub const STRING_HANDLE_BYTES: u64 = HANDLE_BYTES;

/// What one link object costs before the bytes its strings hold.
///
/// The counted handle every cell shares it through, and the object's own fields: the target's
/// string handle, the parameter table's own handle and the flag beside them.
const LINK_OBJECT_BYTES: u64 = HYPERLINK_BYTES + 2 * WORD_BYTES;

/// What one slot of a parameter table costs: the key and value handles it holds and the control
/// byte the table keeps beside them.
const TABLE_SLOT_BYTES: u64 = TABLE_PAIR_BYTES + 1;

/// What a parameter table keeps beyond its slots: the group of control bytes it reads past the
/// end of them.
const TABLE_GROUP_BYTES: u64 = 16;

/// What a cell's independently allocated attributes cost when it has them.
///
/// A cell keeps its true colours, its underline colour, its link handle and its image list in one
/// allocation of its own, reached through a pointer, and the grid makes that allocation as soon as
/// any of them is more than the packed form on the cell can hold. Its fields are the three colour
/// attributes, the link handle and the image list.
pub const CELL_ATTRIBUTE_BYTES: u64 = {
    let fields = 3 * COLOR_ATTRIBUTE_BYTES + 4 * WORD_BYTES;
    // The allocation is aligned to a pointer, so what it occupies rounds up to a multiple of one.
    fields.next_multiple_of(WORD_BYTES)
};

// A row is held either as a vector of cells or as a string with a run of attributes beside it,
// and it changes from one to the other while it is being written, so both can be alive at once.
// Each is built by appending, so each can be holding twice the slots it is using. Beside the
// compact form a row keeps one offset per cell, where its text is not its own record of where the
// cells are, and one bit per cell for the cells that are two columns wide. The per-cell figure the
// budget charges covers all of that together.
/// What one cell of a row costs in the storage the library keeps for it.
///
/// The vector of cells and the run of attributes beside the text, each at twice the cells it
/// holds; the offset the compact form records for the cell, at twice the offsets it holds; and the
/// bit that says whether the cell is two columns wide, charged as a byte.
const CELL_STORAGE_BYTES: u64 = 2 * CELL_BYTES
    + 2 * (CELL_ATTRIBUTES_BYTES + size_of::<u16>() as u64).next_multiple_of(WORD_BYTES)
    + 2 * WORD_BYTES
    + 1;
const _: () = assert!(CELL_OVERHEAD_BYTES >= CELL_STORAGE_BYTES);

/// What a hash table with room for `room` entries costs.
///
/// The table keeps a power of two of slots, never fewer than four, and leaves an eighth of them
/// free, so the room it reports and the entries it was built for round to the same number of
/// slots. Both sides go through here: the reservation made before a link is applied passes the
/// separators the parameter field carries, which is never fewer than the entries the table is
/// built for, and the measurement passes the room the table ended up with.
fn table_bytes(room: usize) -> u64 {
    let slots: u64 = match room {
        0 => return 0,
        1..=3 => 4,
        4..=7 => 8,
        _ => (room.saturating_mul(8) / 7).next_power_of_two() as u64,
    };
    slots.saturating_mul(TABLE_SLOT_BYTES) + TABLE_GROUP_BYTES
}

/// Whether a cell with these attributes has an allocation of its own.
fn attributes_are_allocated(attrs: &CellAttributes) -> bool {
    attrs.hyperlink().is_some()
        || attrs.underline_color() != ColorAttribute::Default
        || attrs.foreground() != ColorAttribute::Default
        || attrs.background() != ColorAttribute::Default
}

/// What one row holds beyond the cells the screens are already charged for.
///
/// The text as it is encoded, the allocation each cell that needs one keeps for its attributes,
/// and the header a cell keeps once its text is too big to live inside the cell. Counting the text
/// alone would report a screen of coloured cells as costing what a screen of plain ones costs.
fn row_content_bytes(line: &wezterm_term::Line) -> u64 {
    // What the row allocates for itself before anything is on it, and then the text as the row is
    // holding it rather than as it reads: a row grows its string by appending, so it can be
    // holding twice what it shows. Nothing here asks a row for the semantic zones it can cache, so
    // the vector it would cache them in stays empty.
    let mut bytes = ROW_STORAGE_BYTES + 2 * line.as_str().len() as u64;
    for cell in line.visible_cells() {
        let width = cell.width().max(1);
        if attributes_are_allocated(cell.attrs()) {
            // The columns a wide cell covers carry its attributes, and while the row is held as a
            // vector of cells each of those columns is a cell with an allocation of its own.
            bytes = bytes.saturating_add(CELL_ATTRIBUTE_BYTES.saturating_mul(width as u64));
        }
        if cell_text_is_on_the_heap(cell.str(), width) {
            bytes = bytes.saturating_add(CELL_TEXT_HEAP_BYTES);
        }
    }
    bytes
}

/// Adds the link objects one row's cells hold to the session's running total.
///
/// Separate from what the row costs, because the two are counted against different things and at
/// different moments. What a row costs is its own and is charged once, where the row moves. A link
/// object is shared: the cells of one link hold the same object, one link can appear on rows that
/// are not next to each other, and one envelope covers both screens and the retained rows
/// together, so a row moving between them moves no charge. So the objects are gathered by the walk
/// that measures the session's links, wherever the rows sit.
///
/// A row carries a flag saying whether any of its cells is inside a link, and it is the row's flag
/// rather than the cells', so a row built from cells that hold links does not have it set. Reading
/// the cells is the answer that cannot be wrong.
fn count_row_links(
    line: &wezterm_term::Line,
    seen: &mut BTreeSet<*const Hyperlink>,
    links: &mut u64,
) {
    for cell in line.visible_cells() {
        if let Some(link) = cell.attrs().hyperlink() {
            add_link_object(link, seen, links);
        }
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

fn colour_of(attribute: ColorAttribute) -> Colour {
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

/// The DECSCUSR style number for a cursor shape.
fn style_of(shape: CursorShape) -> u32 {
    match shape {
        CursorShape::BlinkingBlock => 1,
        CursorShape::SteadyBlock => 2,
        CursorShape::BlinkingUnderline => 3,
        CursorShape::SteadyUnderline => 4,
        CursorShape::BlinkingBar => 5,
        CursorShape::SteadyBar => 6,
        CursorShape::Default => 0,
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
