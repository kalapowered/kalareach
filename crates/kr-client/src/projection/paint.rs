//! Drawing a held screen into a destination terminal.
//!
//! This is the projected renderer. It is shared: the CLI draws an outer terminal with it and the
//! companion app draws its own surface with it, so there is one answer to where a canonical cell
//! goes rather than one per client.
//!
//! # The rule that shapes every byte
//!
//! Section 8: a projected renderer uses canonical cell positions and explicit cursor placement,
//! and it must *prevent* a mismatched glyph from causing an unintended wrap or scroll before the
//! next cursor placement. Repositioning after the damage is not enough, because a scroll has
//! already moved every row on the screen by the time anything could be repositioned.
//!
//! Three things together make that true:
//!
//! 1. **Autowrap is off while anything is drawn.** The painter clears DEC mode 7 before its first
//!    cell and puts the session's own value back after its last, so no glyph this renderer writes
//!    can wrap whatever the destination thinks that glyph is worth.
//! 2. **Every run is placed absolutely.** A run begins with a cursor address, so a glyph the
//!    destination measured differently moves nothing after it.
//! 3. **A span the destination cannot reproduce is replaced rather than drawn.** The width of a
//!    run's text is measured against the profile's pinned model and compared with the cell span
//!    the session says it occupies. A disagreement means the text cannot be placed at canonical
//!    positions, so the span is filled with spaces and counted. That is the encoding rejection,
//!    and it is made per run rather than once per screen.
//!
//! A cluster that would be cut in half by the window's edge is never half drawn: it is replaced by
//! a space for each cell of it that is inside, which keeps every later cell on its own column.

use kr_protocol::projection::{
    CellBlink, CellColour, CellRendition, CellRendition as Pen, CellRun, CellUnderline,
    CellVerticalAlign, ProjectedBuffer, ProjectedRow,
};
use kr_term::unicode;

use super::Screen;

/// The part of the canonical grid a destination is showing, in canonical coordinates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Window {
    /// The stable identifier of the row drawn on the destination's first line.
    pub top_row: u64,
    /// The canonical column drawn in the destination's first column.
    pub left_column: u64,
    /// How many lines the destination has for the grid.
    pub rows: u32,
    /// How many columns the destination has for the grid.
    pub columns: u32,
}

impl Window {
    /// The window a screen's own viewport describes.
    #[must_use]
    pub fn of(screen: &Screen) -> Self {
        Self {
            top_row: screen.viewport.top_row.get(),
            left_column: screen.viewport.left_column.get(),
            rows: u32::try_from(screen.viewport.rows.get()).unwrap_or(u32::MAX),
            columns: u32::try_from(screen.viewport.columns.get()).unwrap_or(u32::MAX),
        }
    }

    /// The destination line one stable row identifier is drawn on, when it is shown at all.
    #[must_use]
    pub fn line_of(&self, row: u64) -> Option<u32> {
        let offset = row.checked_sub(self.top_row)?;
        let offset = u32::try_from(offset).ok()?;
        (offset < self.rows).then_some(offset)
    }
}

/// What a paint could not carry, measured rather than assumed.
///
/// Every field is a fact about this screen and this destination, so a caller can report a
/// projection that is degraded instead of presenting an approximation as the session.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Comparison {
    /// Runs whose text could not be placed at canonical positions and were replaced with spaces.
    pub runs_replaced: usize,
    /// Cells that lie outside the window and were not drawn.
    pub cells_clipped: u64,
    /// Rows that had cells outside the window.
    pub rows_clipped: usize,
    /// Clusters replaced because the window's edge fell inside them.
    pub clusters_replaced: usize,
    /// Whether the canonical pending wrap could not be reproduced.
    ///
    /// Only printing into the last column sets one and every cursor movement clears one, so a
    /// renderer that places the cursor explicitly cannot leave a destination in it. The cost is
    /// one character: the next one the application prints lands beside the last column instead of
    /// wrapping.
    pub pending_wrap: bool,
    /// Whether the canonical cursor is outside the window, so it was hidden rather than misplaced.
    pub cursor_outside: bool,
    /// Soft-wrap markers, which a destination cannot be told about for a row drawn into it.
    pub soft_wraps: usize,
    /// Rows the session had already truncated to stay inside a page bound.
    pub truncated_rows: usize,
    /// Rows of the visible page that lie outside the window, on a destination too short for it.
    pub rows_outside: usize,
    /// Cells in those rows, which are cells of the session nobody is looking at.
    pub cells_outside: u64,
    /// Whether the session's keyboard negotiation was withheld from a destination nobody asked.
    pub keyboard_withheld: bool,
    /// Keyboard-stack entries the session holds, which a projection installs as a state, not a
    /// stack.
    pub keyboard_stack: usize,
    /// Control bytes dropped from a title or a link target so that it could not end its own string.
    pub controls_dropped: usize,
    /// Whether the session's scroll region, margins or origin mode could not be installed.
    ///
    /// They are rows and columns of the canonical grid, so a destination showing only part of the
    /// grid has nowhere to put them. It is drawn in the plain coordinate system instead, which is
    /// right for every cell this renderer writes and wrong for an application that later writes to
    /// this terminal itself.
    pub geometry_withheld: bool,
}

impl Comparison {
    /// Whether the destination is showing the whole of what the session holds.
    ///
    /// Two fields are counts of another field's loss rather than losses of their own, and are not
    /// read here: a row is only clipped when cells of it were clipped, and a cell is only outside
    /// the window when the row holding it is. Each travels with the field that reports it, so
    /// reading them here would make a frame incomplete for a reason nothing could put into words.
    #[must_use]
    pub const fn complete(&self) -> bool {
        self.runs_replaced == 0
            && self.cells_clipped == 0
            && self.clusters_replaced == 0
            && !self.pending_wrap
            && !self.cursor_outside
            && self.soft_wraps == 0
            && self.truncated_rows == 0
            && self.rows_outside == 0
            && !self.keyboard_withheld
            && self.keyboard_stack == 0
            && self.controls_dropped == 0
            && !self.geometry_withheld
    }

    /// Takes everything another frame's comparison found into this one.
    ///
    /// A caller that paints several frames before it reports reports the whole of what they could
    /// not carry, rather than only the last one's share of it.
    pub fn absorb(&mut self, other: Self) {
        self.runs_replaced += other.runs_replaced;
        self.cells_clipped = self.cells_clipped.saturating_add(other.cells_clipped);
        self.rows_clipped += other.rows_clipped;
        self.clusters_replaced += other.clusters_replaced;
        self.pending_wrap |= other.pending_wrap;
        self.cursor_outside |= other.cursor_outside;
        self.soft_wraps += other.soft_wraps;
        self.truncated_rows += other.truncated_rows;
        self.rows_outside += other.rows_outside;
        self.cells_outside = self.cells_outside.saturating_add(other.cells_outside);
        self.keyboard_withheld |= other.keyboard_withheld;
        self.keyboard_stack += other.keyboard_stack;
        self.controls_dropped += other.controls_dropped;
        self.geometry_withheld |= other.geometry_withheld;
    }
}

/// One painted frame.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Painted {
    /// The bytes to write to the destination.
    pub bytes: Vec<u8>,
    /// What the frame could not carry.
    pub comparison: Comparison,
}

/// Whether this destination's keyboard protocols may be changed at all.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Keyboard {
    /// The session's negotiation is installed, because this destination said what it had before
    /// anything touched it and can therefore be put back exactly.
    #[default]
    Install,
    /// Nothing about the keyboard is changed, because nobody was allowed to ask this destination
    /// what it had and nothing else can put back what an install would take away.
    ///
    /// This is what an attachment that asked its terminal nothing is served: the conservative
    /// profile is one that does not touch what it cannot restore.
    Withhold,
}

/// Draws the whole screen.
///
/// This is what an installed snapshot produces: the state the destination has to be in, the
/// screen cleared, every visible row, and the cursor placed last so the destination is never left
/// mid-repaint with a live cursor on it.
#[must_use]
pub fn install(screen: &Screen, window: Window, keyboard: Keyboard) -> Painted {
    let mut writer = Writer::new(screen, window, keyboard);
    writer.begin();
    writer.state();
    writer.clear();
    let rows = screen.visible_rows();
    writer.rows(&rows);
    writer.finish();
    writer.done()
}

/// Draws only the rows an update changed, and the state when the update moved any of it.
///
/// A row that is not on the destination is skipped rather than clamped: the window says which
/// canonical rows this destination shows, and a row outside it belongs to a part of the grid
/// nobody is looking at. Those cells are still counted, because a person looking at a window too
/// short for the session is not seeing the session.
///
/// `state` says whether the update carried anything but rows. A palette an application changed, a
/// title it set, a mode it turned on: a destination that was sent only the rows would show the
/// previous one until the next whole screen arrived.
#[must_use]
pub fn update(
    screen: &Screen,
    window: Window,
    rows: &[u64],
    state: bool,
    keyboard: Keyboard,
) -> Painted {
    let mut writer = Writer::new(screen, window, keyboard);
    writer.begin();
    if state {
        writer.state();
    }
    writer.rows(rows);
    writer.finish();
    writer.done()
}

/// The escape introducer.
const ESC: u8 = 0x1B;

/// The string terminator every profile in the repertoire accepts.
const ST: &[u8] = b"\x1b\\";

/// DEC private mode 7, autowrap.
const AUTOWRAP: u16 = 7;

/// DEC private mode 25, cursor visibility.
const CURSOR_VISIBLE: u16 = 25;

/// DEC private mode 6, origin mode, which changes what every absolute address means.
const ORIGIN_MODE: u16 = 6;

/// DEC private mode 1048, a cursor save and restore rather than a state to be left in.
const CURSOR_SAVE_MODE: u16 = 1048;

/// DEC private mode 66, the application keypad.
const KEYPAD_MODE: u16 = 66;

/// DEC private mode 69, the left and right margins, which change what a column address means.
const LEFT_RIGHT_MARGINS: u16 = 69;

/// ANSI mode 4, insert mode, which would push the cells beside a drawn one along the row.
const INSERT_MODE: u16 = 4;

/// The modes that are the buffer selection under another spelling.
///
/// Setting one of them here would clear the buffer this frame is about to paint. Which buffer is
/// showing is installed on its own.
const ALTERNATE_BUFFER_MODES: &[u16] = &[47, 1047, 1049];

/// The scroll region a frame left the destination in, in the destination's own coordinates.
///
/// It is what the last cursor placement has to be written against: once origin mode is on, an
/// absolute address is measured from the region's own corner.
#[derive(Clone, Copy, Debug)]
struct Region {
    top: u32,
    bottom: u32,
    left: u32,
    right: u32,
    /// Whether origin mode is on, which makes every address afterwards relative to this region.
    origin: bool,
    /// Whether left and right margins are in force, which is what makes the columns relative too.
    horizontal: bool,
}

struct Writer<'a> {
    screen: &'a Screen,
    window: Window,
    keyboard: Keyboard,
    out: Vec<u8>,
    /// The rendition the destination is in, once this writer has put it in one.
    ///
    /// `None` until something sets it, because a writer that assumed the destination started plain
    /// would skip the first rendition when it happens to be the default one and leave a row drawn
    /// in whatever the destination already had.
    pen: Option<Pen>,
    /// The hyperlink currently open, so a run does not reopen the one it is already inside.
    link: Option<String>,
    comparison: Comparison,
}

impl<'a> Writer<'a> {
    fn new(screen: &'a Screen, window: Window, keyboard: Keyboard) -> Self {
        Self {
            screen,
            window,
            keyboard,
            out: Vec::new(),
            pen: None,
            link: None,
            comparison: Comparison::default(),
        }
    }

    /// Puts the destination into the coordinate system this frame's addresses are written in.
    ///
    /// Autowrap off is the rule that keeps a mismatched glyph from wrapping, and four more modes
    /// decide what an absolute address means at all. A destination that was forwarding directly a
    /// moment ago can be in origin mode, inside a scroll region, inside left and right margins, or
    /// in insert mode. In origin mode `CSI 5;1H` is the fifth row *of the region*; inside left and
    /// right margins a column address is measured from the left margin; in insert mode drawing a
    /// cell pushes its neighbours along the row. None of that is corrected by repositioning
    /// afterwards, so all of it is cleared before the first cell and the session's own is put back
    /// after the last.
    fn begin(&mut self) {
        self.mode(ORIGIN_MODE, false);
        self.mode(LEFT_RIGHT_MARGINS, false);
        // The whole screen is the scroll region while this frame draws.
        self.csi(b"r");
        self.mode_of(super::ProjectedModeSpelling::Ansi, INSERT_MODE, false);
        self.mode(AUTOWRAP, false);
    }

    /// Puts the session's own autowrap and geometry back and places the cursor.
    fn finish(&mut self) {
        if self.link.is_some() {
            self.close_link();
        }
        // The rendition the next character would be drawn with belongs to the session, so it is
        // installed after the rows and before the cursor: a row drawn afterwards would otherwise
        // be drawn through the pen of whichever run happened to be last.
        self.rendition(self.screen.rendition);
        self.mode(AUTOWRAP, self.screen.autowrap());
        let region = self.geometry();
        self.cursor(region);
    }

    /// Installs the session's scroll region, margins, insert mode and origin mode.
    ///
    /// Why install them at all, when this renderer addresses every cell absolutely and needs none
    /// of them? Because a projected presentation can become a direct one: the session hands the
    /// attachment the stream and the application writes to this terminal itself, expecting the
    /// region it set and the origin mode it turned on to be in force. A destination left in the
    /// plain coordinate system would scroll the wrong rows for it.
    ///
    /// A margin is a row and a column of the canonical grid, so this is only possible for a
    /// destination that shows the whole grid. A window showing part of it says so through the
    /// comparison instead of installing something approximate, and a projection that cannot carry
    /// the geometry is also one that will not be handed the stream.
    fn geometry(&mut self) -> Option<Region> {
        let margins = self.screen.margins;
        let rows = self.screen.dimensions.rows.get();
        let columns = self.screen.dimensions.columns.get();
        let origin = self
            .screen
            .mode(super::ProjectedModeSpelling::Dec, u64::from(ORIGIN_MODE));
        let insert = self
            .screen
            .mode(super::ProjectedModeSpelling::Ansi, u64::from(INSERT_MODE));
        let vertical = margins.top.get() == 0 && margins.bottom.get().saturating_add(1) == rows;
        let horizontal =
            margins.left.get() == 0 && margins.right.get().saturating_add(1) == columns;
        if vertical && horizontal && !origin && !insert {
            // Nothing of the session's to install: this is the plain coordinate system the frame
            // already left the destination in.
            return None;
        }
        if !self.shows_whole_grid() {
            self.comparison.geometry_withheld = true;
            return None;
        }
        let (top, bottom) = (margins.top.get(), margins.bottom.get());
        if !vertical {
            let mut body = top.saturating_add(1).to_string().into_bytes();
            body.push(b';');
            body.extend_from_slice(bottom.saturating_add(1).to_string().as_bytes());
            body.push(b'r');
            self.csi(&body);
        }
        let (left, right) = (margins.left.get(), margins.right.get());
        if !horizontal {
            self.mode(LEFT_RIGHT_MARGINS, true);
            let mut body = left.saturating_add(1).to_string().into_bytes();
            body.push(b';');
            body.extend_from_slice(right.saturating_add(1).to_string().as_bytes());
            body.push(b's');
            self.csi(&body);
        }
        if insert {
            self.mode_of(super::ProjectedModeSpelling::Ansi, INSERT_MODE, true);
        }
        if origin {
            self.mode(ORIGIN_MODE, true);
        }
        Some(Region {
            top: u32::try_from(top).unwrap_or(0),
            bottom: u32::try_from(bottom).unwrap_or(u32::MAX),
            left: u32::try_from(left).unwrap_or(0),
            right: u32::try_from(right).unwrap_or(u32::MAX),
            origin,
            horizontal: !horizontal,
        })
    }

    /// Whether this destination shows the whole canonical grid, cell for cell.
    fn shows_whole_grid(&self) -> bool {
        self.window.left_column == 0
            && self.window.top_row == self.screen.viewport.top_row.get()
            && u64::from(self.window.columns) == self.screen.dimensions.columns.get()
            && u64::from(self.window.rows) == self.screen.dimensions.rows.get()
    }

    fn done(self) -> Painted {
        Painted {
            bytes: self.out,
            comparison: self.comparison,
        }
    }

    fn clear(&mut self) {
        self.csi(b"2J");
        self.csi(b"H");
    }

    /// Installs the state a destination has to be in for this screen to mean what it says.
    ///
    /// Two halves, and both matter. The display half is what the cells are drawn through: the
    /// palette, the title, the character sets, the scroll region. The *input* half is what the
    /// person's keyboard and mouse then produce: mouse reporting, bracketed paste, application
    /// cursor keys, the keypad and the keyboard negotiation. A destination that was drawn the cells
    /// and not put into the input modes sends the application nothing when the mouse moves and an
    /// unframed paste when text is pasted, which is a session that looks right and does not work.
    ///
    /// Four modes are deliberately not installed:
    ///
    /// * the alternate-buffer spellings, because they are the buffer selection under another name
    ///   and setting one would clear the buffer this frame is about to paint;
    /// * 1048, because it is a cursor save or restore rather than a state to be left in;
    /// * the coordinate system (origin mode, left and right margins, insert mode), because it
    ///   changes what every absolute address afterwards means and what drawing a cell does to its
    ///   neighbours; it is installed with the scroll region after the last row;
    /// * autowrap, which this frame owns: it is off while anything is drawn and put back at the end.
    fn state(&mut self) {
        self.palette();
        self.title();
        // The character sets the cells were written under. A destination left in a graphics set
        // would draw line-drawing characters where the session holds ASCII.
        let charsets = self.screen.charsets.clone();
        let designation = |name: &str| -> &'static [u8] {
            match name {
                "DecLineDrawing" => b"0",
                "UkIso646" => b"A",
                _ => b"B",
            }
        };
        self.out.push(ESC);
        self.out.push(b'(');
        self.out
            .extend_from_slice(designation(charsets.g0.as_str()));
        self.out.push(ESC);
        self.out.push(b')');
        self.out
            .extend_from_slice(designation(charsets.g1.as_str()));
        self.out.push(if charsets.shift_out { 0x0E } else { 0x0F });

        for ((spelling, mode), enabled) in self.screen.modes.clone() {
            let Ok(number) = u16::try_from(mode) else {
                continue;
            };
            let geometry = matches!(spelling, super::ProjectedModeSpelling::Dec)
                && (number == ORIGIN_MODE || number == LEFT_RIGHT_MARGINS)
                || matches!(spelling, super::ProjectedModeSpelling::Ansi) && number == INSERT_MODE;
            if geometry {
                // The coordinate system, which this frame owns: cleared before its first cell and
                // installed with the margins after its last row.
                continue;
            }
            if spelling == super::ProjectedModeSpelling::Dec
                && (ALTERNATE_BUFFER_MODES.contains(&number)
                    || number == CURSOR_SAVE_MODE
                    || number == AUTOWRAP
                    // The keypad is installed below, in the spelling a terminal takes.
                    || number == KEYPAD_MODE)
            {
                continue;
            }
            self.mode_of(spelling, number, enabled);
        }
        // The keypad's own mode is carried twice by a screen; this is the spelling a terminal
        // takes, and it is written whichever way the modes above spelled it.
        if self.screen.keypad_application {
            self.out.extend_from_slice(b"\x1b=");
        } else {
            self.out.extend_from_slice(b"\x1b>");
        }
        self.keyboard();
        // The tab stops, which a person's Tab key and an application's HT both land on.
        self.csi(b"3g");
        for stop in self.screen.tab_stops.clone() {
            let Ok(column) = u32::try_from(stop) else {
                continue;
            };
            let Some(destination) = self.window_column(u64::from(column)) else {
                continue;
            };
            self.place(0, destination);
            self.out.push(ESC);
            self.out.push(b'H');
        }
    }

    /// Installs the keyboard negotiation, when this destination's protocols are ours to change.
    fn keyboard(&mut self) {
        if self.keyboard == Keyboard::Withhold {
            // Nobody was allowed to ask this destination what it had negotiated, so nothing here
            // changes it: a level or a flag installed now could not be put back, and a person left
            // in an encoding their shell does not expect is the failure they cannot work around.
            let negotiated = &self.screen.keyboard;
            let flags = match self.screen.active_buffer {
                ProjectedBuffer::Primary => &negotiated.primary,
                ProjectedBuffer::Alternate => &negotiated.alternate,
            };
            if negotiated.modify_other_keys.get() != 0 || flags.flags.0.is_some() {
                self.comparison.keyboard_withheld = true;
            }
            return;
        }
        let negotiated = self.screen.keyboard.clone();
        let level = negotiated.modify_other_keys.get();
        self.csi(format!(">4;{level}m").as_bytes());
        let buffer = match self.screen.active_buffer {
            ProjectedBuffer::Primary => &negotiated.primary,
            ProjectedBuffer::Alternate => &negotiated.alternate,
        };
        // An absolute state rather than a push, because a stack entry written here could be taken
        // off by an application inside the session and the pop would then land on somebody else's.
        let flags = buffer.flags.0.map_or(0, |flags| flags.get());
        self.csi(format!("={flags};1u").as_bytes());
        self.comparison.keyboard_stack += buffer.stack.len();
    }

    /// Writes one tracked mode.
    fn mode_of(&mut self, spelling: super::ProjectedModeSpelling, mode: u16, enabled: bool) {
        let mut body = Vec::new();
        if spelling == super::ProjectedModeSpelling::Dec {
            body.push(b'?');
        }
        body.extend_from_slice(mode.to_string().as_bytes());
        body.push(if enabled { b'h' } else { b'l' });
        self.csi(&body);
    }

    /// The destination column one canonical column is drawn in, when it is shown at all.
    fn window_column(&self, canonical: u64) -> Option<u32> {
        let left = self.window.left_column;
        let right = left.saturating_add(u64::from(self.window.columns));
        if canonical < left || canonical >= right {
            return None;
        }
        u32::try_from(canonical - left).ok()
    }

    fn palette(&mut self) {
        let palette = &self.screen.palette;
        // Every indexed colour goes back to the destination's own default first. Applying only the
        // session's overrides would leave an index this destination had been given earlier and the
        // session has since put back.
        self.osc_bare(b"104");
        for entry in &palette.overrides {
            let mut body = entry.index.to_string().into_bytes();
            body.push(b';');
            body.extend_from_slice(&specification(entry.colour));
            self.osc(b"4", &body);
        }
        for (selector, colour) in [
            (&b"10"[..], palette.foreground),
            (b"11", palette.background),
            (b"12", palette.cursor),
            (b"13", palette.pointer_foreground),
            (b"14", palette.pointer_background),
            (b"17", palette.selection_background),
            (b"19", palette.selection_foreground),
        ] {
            self.osc(selector, &specification(colour));
        }
    }

    fn title(&mut self) {
        // The stack stays virtual. Pushing it onto the destination's own would grow that stack by
        // its whole depth on every repaint, and could evict a title the person's own terminal had
        // saved for itself.
        self.osc(b"1", self.screen.title.icon.clone().as_bytes());
        self.osc(b"2", self.screen.title.window.clone().as_bytes());
    }

    fn rows(&mut self, rows: &[u64]) {
        for row in rows {
            let Some(line) = self.window.line_of(*row) else {
                // A row of the visible page this destination has no line for. It is counted, not
                // skipped quietly: a window shorter than the session is a window that is not
                // showing the session, and a person who is not told cannot make it taller.
                if self.screen.visible_rows().contains(row) {
                    self.comparison.rows_outside += 1;
                    let cells = self
                        .screen
                        .rows
                        .get(&(self.screen.active_buffer, *row))
                        .map_or(0, |held| {
                            held.runs
                                .iter()
                                .fold(0_u64, |total, run| total.saturating_add(run.cells.get()))
                        });
                    self.comparison.cells_outside =
                        self.comparison.cells_outside.saturating_add(cells);
                }
                continue;
            };
            self.row(*row, line);
        }
    }

    fn row(&mut self, row: u64, line: u32) {
        // The whole line is cleared before anything is drawn on it. A row's runs cover only the
        // cells that hold something, so a row whose first cell is blank has no run at column zero
        // and a row shorter than the one before it has none at its end: clearing only after the
        // runs would leave both of those showing whatever was there before. The pen goes back to
        // the default first, because an erase paints the background colour in force.
        self.rendition(CellRendition::PLAIN);
        self.place(line, 0);
        self.csi(b"K");
        let Some(content) = self.screen.rows.get(&(self.screen.active_buffer, row)) else {
            // A row the window shows and the session does not hold is blank, not stale, and the
            // line has just been cleared. That is what makes a destination taller than the grid
            // leave its unused area empty.
            return;
        };
        if content.soft_wrapped {
            // A row this writer draws itself is a hard row as far as the destination is concerned,
            // so a line the application wrapped is two lines there. The marker is what a selection
            // needs to copy one logical line, and it is reported rather than approximated.
            self.comparison.soft_wraps += 1;
        }
        if content.truncated {
            self.comparison.truncated_rows += 1;
        }
        let mut clipped = false;
        for run in &content.runs {
            clipped |= self.run(run, line);
        }
        if clipped {
            self.comparison.rows_clipped += 1;
        }
    }

    /// Draws one run, returning whether any of it lay outside the window.
    fn run(&mut self, run: &CellRun, line: u32) -> bool {
        let start = run.column.get();
        let cells = run.cells.get();
        let end = start.saturating_add(cells);
        let left = self.window.left_column;
        let right = left.saturating_add(u64::from(self.window.columns));
        if end <= left || start >= right {
            self.comparison.cells_clipped = self.comparison.cells_clipped.saturating_add(cells);
            return true;
        }
        let clipped = start < left || end > right;
        if clipped {
            let outside = left.saturating_sub(start) + end.saturating_sub(right);
            self.comparison.cells_clipped = self.comparison.cells_clipped.saturating_add(outside);
        }

        // The width the profile's pinned model gives this text, against the cell span the session
        // says it occupies. A disagreement means the text cannot be placed at canonical positions,
        // and drawing it anyway is what would move everything after it.
        let measured = unicode::cells_for(&run.text) as u64;
        let mut painted: Vec<(String, u64, u64)> = Vec::new();
        if measured == cells {
            let mut column = start;
            for cluster in clusters(&run.text) {
                let cluster_end = column.saturating_add(cluster.cells);
                if cluster.cells == 0 {
                    // A cluster of no cells belongs to a cell that is already on the screen, and a
                    // projection has no way to say "add this to what is there". It is counted
                    // rather than written where a destination would attach it to a neighbour.
                    self.comparison.clusters_replaced += 1;
                    continue;
                }
                if cluster_end <= left || column >= right {
                    column = cluster_end;
                    continue;
                }
                if column < left || cluster_end > right {
                    // The window's edge falls inside this cluster. Half a wide character is not a
                    // narrower character: the destination would place it somewhere of its own
                    // choosing. A space for each cell of it that is inside keeps every later cell
                    // on its own column.
                    let inside = cluster_end.min(right).saturating_sub(column.max(left));
                    self.comparison.clusters_replaced += 1;
                    painted.push((
                        " ".repeat(usize::try_from(inside).unwrap_or(0)),
                        column.max(left),
                        inside,
                    ));
                } else {
                    painted.push((cluster.text.to_owned(), column, cluster.cells));
                }
                column = cluster_end;
            }
        } else {
            // Replaced, not dropped: the cells still belong to this run, and leaving them empty
            // would let the next run's absolute address be the only thing holding the row together.
            self.comparison.runs_replaced += 1;
            let inside = end.min(right).saturating_sub(start.max(left));
            painted.push((
                " ".repeat(usize::try_from(inside).unwrap_or(0)),
                start.max(left),
                inside,
            ));
        }
        if painted.is_empty() {
            return clipped;
        }

        self.rendition(run.rendition);
        match run.hyperlink.as_ref() {
            Some(uri) => self.open_link(uri),
            None => {
                if self.link.is_some() {
                    self.close_link();
                }
            }
        }
        // Each piece is placed at the canonical column it occupies, and the placement is repeated
        // whenever the destination's own cursor cannot be relied on to be there. A destination that
        // joins a sequence this profile measures as two cells advances by two where the profile
        // says four, and everything after it in the run would land two columns early: the rule is
        // that a mismatched glyph must not move anything *before the next cursor placement*, so the
        // next placement is made rather than assumed. Plain single-cell ASCII is the one advance
        // every terminal agrees about, so a span of it costs one placement and not one per cell.
        let mut believed: Option<u64> = None;
        for (text, column, cells) in painted {
            if believed != Some(column) {
                let Some(destination) = self.window_column(column) else {
                    continue;
                };
                self.place(line, destination);
            }
            // Filtered by scalar, never by byte: a continuation byte of a multi-byte scalar
            // shares its numeric range with the C1 controls, and a byte filter would take the
            // second half of every non-ASCII character.
            for scalar in text.chars().filter(|scalar| !scalar.is_control()) {
                let mut buffer = [0_u8; 4];
                self.out
                    .extend_from_slice(scalar.encode_utf8(&mut buffer).as_bytes());
            }
            believed = predictable(&text).then(|| column.saturating_add(cells));
        }
        clipped
    }

    fn cursor(&mut self, region: Option<Region>) {
        let cursor = self.screen.cursor;
        if cursor.pending_wrap {
            self.comparison.pending_wrap = true;
        }
        let column = cursor.column.get();
        let left = self.window.left_column;
        let right = left.saturating_add(u64::from(self.window.columns));
        let line = u32::try_from(cursor.row.get()).unwrap_or(u32::MAX);
        if column < left || column >= right || line >= self.window.rows {
            // A cursor drawn in the wrong cell is worse than no cursor: a person would type where
            // it appears to be. It is hidden and the fact is reported.
            self.comparison.cursor_outside = true;
            self.mode(CURSOR_VISIBLE, false);
            return;
        }
        let destination = u32::try_from(column.saturating_sub(left)).unwrap_or(u32::MAX);
        match region.filter(|region| region.origin) {
            // Origin mode is on, so the address this places is measured from the region's own
            // corner. A cursor outside the region cannot be addressed at all while it is on,
            // because a relative address is clamped into the region: that is a misplaced cursor,
            // which is the one thing this never leaves behind.
            Some(region) => {
                let outside = line < region.top
                    || line > region.bottom
                    || (region.horizontal
                        && (destination < region.left || destination > region.right));
                if outside {
                    self.comparison.cursor_outside = true;
                    self.mode(CURSOR_VISIBLE, false);
                    return;
                }
                let relative = if region.horizontal {
                    destination - region.left
                } else {
                    destination
                };
                self.place(line - region.top, relative);
            }
            None => self.place(line, destination),
        }
        self.mode(CURSOR_VISIBLE, cursor.visible);
        let style = cursor.style.get();
        let mut body = style.to_string().into_bytes();
        body.extend_from_slice(b" q");
        self.csi(&body);
    }

    /// Addresses the destination's cursor absolutely.
    fn place(&mut self, line: u32, column: u32) {
        let mut body = (line + 1).to_string().into_bytes();
        body.push(b';');
        body.extend_from_slice((column + 1).to_string().as_bytes());
        body.push(b'H');
        self.csi(&body);
    }

    fn mode(&mut self, mode: u16, enabled: bool) {
        let mut body = b"?".to_vec();
        body.extend_from_slice(mode.to_string().as_bytes());
        body.push(if enabled { b'h' } else { b'l' });
        self.csi(&body);
    }

    fn rendition(&mut self, rendition: CellRendition) {
        if self.pen == Some(rendition) {
            return;
        }
        // One reset and then the whole rendition, rather than the difference. A difference would be
        // shorter and would also depend on the destination agreeing about what the previous
        // rendition left set, which is exactly the assumption a projection exists to avoid.
        let mut parameters: Vec<String> = vec!["0".to_owned()];
        if rendition.bold {
            parameters.push("1".to_owned());
        }
        if rendition.faint {
            parameters.push("2".to_owned());
        }
        if rendition.italic {
            parameters.push("3".to_owned());
        }
        match rendition.underline {
            CellUnderline::None => {}
            CellUnderline::Single => parameters.push("4".to_owned()),
            CellUnderline::Double => parameters.push("21".to_owned()),
            CellUnderline::Curly => parameters.push("4:3".to_owned()),
            CellUnderline::Dotted => parameters.push("4:4".to_owned()),
            CellUnderline::Dashed => parameters.push("4:5".to_owned()),
        }
        match rendition.blink {
            CellBlink::None => {}
            CellBlink::Slow => parameters.push("5".to_owned()),
            CellBlink::Rapid => parameters.push("6".to_owned()),
        }
        if rendition.reverse {
            parameters.push("7".to_owned());
        }
        if rendition.invisible {
            parameters.push("8".to_owned());
        }
        if rendition.strikethrough {
            parameters.push("9".to_owned());
        }
        if rendition.overline {
            parameters.push("53".to_owned());
        }
        match rendition.vertical_align {
            CellVerticalAlign::Baseline => {}
            CellVerticalAlign::Superscript => parameters.push("73".to_owned()),
            CellVerticalAlign::Subscript => parameters.push("74".to_owned()),
        }
        if let Some(parameter) = colour_parameter(rendition.foreground, 30, 90, 38) {
            parameters.push(parameter);
        }
        if let Some(parameter) = colour_parameter(rendition.background, 40, 100, 48) {
            parameters.push(parameter);
        }
        match rendition.underline_colour {
            CellColour::Direct(rgb) => {
                parameters.push(format!("58:2::{}:{}:{}", rgb.red, rgb.green, rgb.blue));
            }
            CellColour::Indexed(index) => parameters.push(format!("58:5:{index}")),
            CellColour::Default => {}
        }
        let mut body = parameters.join(";").into_bytes();
        body.push(b'm');
        self.csi(&body);
        self.pen = Some(rendition);
    }

    fn open_link(&mut self, uri: &str) {
        if self.link.as_deref() == Some(uri) {
            return;
        }
        let mut body = b";".to_vec();
        body.extend_from_slice(uri.as_bytes());
        self.osc(b"8", &body);
        self.link = Some(uri.to_owned());
    }

    fn close_link(&mut self) {
        self.osc(b"8", b";");
        self.link = None;
    }

    fn csi(&mut self, body: &[u8]) {
        self.out.push(ESC);
        self.out.push(b'[');
        self.out.extend_from_slice(body);
    }

    /// Writes one control string, with nothing in its payload that could end it early.
    ///
    /// A title and a link target come from the application. A payload carrying a string terminator
    /// would close this command and leave whatever followed to be read as a fresh one, which is how
    /// a restoration that emits only rendering operations could be made to emit a clipboard write.
    /// Every C0 and C1 byte is therefore dropped from the payload: a title cannot contain one and
    /// mean anything, and dropping them is what makes the closed set of operations actually closed.
    fn osc(&mut self, selector: &[u8], body: &[u8]) {
        self.out.push(ESC);
        self.out.push(b']');
        self.out.extend_from_slice(selector);
        self.out.push(b';');
        let before = self.out.len();
        // By scalar, for the reason a run's text is filtered by scalar: a byte filter would take
        // the continuation bytes of every character outside ASCII.
        let text = String::from_utf8_lossy(body);
        for scalar in text.chars().filter(|scalar| !scalar.is_control()) {
            let mut buffer = [0_u8; 4];
            self.out
                .extend_from_slice(scalar.encode_utf8(&mut buffer).as_bytes());
        }
        if self.out.len() != before + body.len() {
            self.comparison.controls_dropped += 1;
        }
        self.out.extend_from_slice(ST);
    }

    fn osc_bare(&mut self, selector: &[u8]) {
        self.out.push(ESC);
        self.out.push(b']');
        self.out.extend_from_slice(selector);
        self.out.extend_from_slice(ST);
    }
}

/// Whether every terminal will advance by exactly this text's own cell count.
///
/// Plain ASCII of one cell each: no terminal disagrees about those. Anything else may be clustered
/// or measured differently by the destination, so the next piece of the row is placed explicitly
/// rather than written where this one is believed to have left the cursor.
fn predictable(text: &str) -> bool {
    text.len() == 1 && text.as_bytes()[0].is_ascii_graphic()
        || text.len() == 1 && text.as_bytes()[0] == b' '
}

/// One cell of text: a scalar with a width of its own, plus the zero-width scalars that join it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Cluster<'a> {
    text: &'a str,
    cells: u64,
}

/// Splits text into the clusters the pinned width model measures.
///
/// The model is per scalar: a combining mark, a joiner and a variation selector all belong to
/// whatever came before them. Splitting anywhere else would let a cluster be cut in half.
fn clusters(text: &str) -> Vec<Cluster<'_>> {
    let mut out: Vec<Cluster<'_>> = Vec::new();
    let mut start = 0_usize;
    let mut index = 0_usize;
    // Whether the bytes collected so far already hold a scalar with a width of its own. Until they
    // do, everything collected is zero-width and belongs to the cell that follows it: a run opening
    // with a combining mark has nothing behind it to join, so the mark travels with the first cell
    // rather than becoming a cluster of no cells that the clipping would drop without saying so.
    let mut has_cell = false;
    for scalar in text.chars() {
        let width = scalar.len_utf8();
        if unicode::is_zero_width(scalar) {
            index += width;
            continue;
        }
        if has_cell {
            let piece = &text[start..index];
            out.push(Cluster {
                text: piece,
                cells: unicode::cells_for(piece) as u64,
            });
            start = index;
        }
        has_cell = true;
        index += width;
    }
    if index > start {
        let piece = &text[start..index];
        out.push(Cluster {
            text: piece,
            cells: unicode::cells_for(piece) as u64,
        });
    }
    out
}

/// The SGR parameter one colour needs, or `None` for the session default.
fn colour_parameter(colour: CellColour, base: u8, bright: u8, extended: u8) -> Option<String> {
    match colour {
        CellColour::Default => None,
        CellColour::Indexed(index) if index < 8 => {
            Some((u16::from(base) + u16::from(index)).to_string())
        }
        CellColour::Indexed(index) if index < 16 => {
            Some((u16::from(bright) + u16::from(index - 8)).to_string())
        }
        CellColour::Indexed(index) => Some(format!("{extended}:5:{index}")),
        CellColour::Direct(rgb) => Some(format!(
            "{extended}:2::{}:{}:{}",
            rgb.red, rgb.green, rgb.blue
        )),
    }
}

/// The `rgb:` specification an OSC colour command carries.
fn specification(colour: kr_protocol::projection::Rgb) -> Vec<u8> {
    format!(
        "rgb:{:02x}/{:02x}/{:02x}",
        colour.red, colour.green, colour.blue
    )
    .into_bytes()
}

/// Whether a row's runs agree with the pinned width model about every one of their cell spans.
///
/// A caller that wants the comparison without drawing anything asks this. It is the same check the
/// painter makes per run, which is what keeps the two answers from drifting apart.
#[must_use]
pub fn row_encodes_exactly(row: &ProjectedRow) -> bool {
    row.runs
        .iter()
        .all(|run| unicode::cells_for(&run.text) as u64 == run.cells.get())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cluster_keeps_its_combining_marks() {
        let pieces = clusters("a\u{301}b");
        assert_eq!(pieces.len(), 2);
        assert_eq!(pieces[0].text, "a\u{301}");
        assert_eq!(pieces[0].cells, 1);
        assert_eq!(pieces[1].text, "b");
    }

    #[test]
    fn a_wide_cluster_is_two_cells() {
        let pieces = clusters("\u{1f600}x");
        assert_eq!(pieces.len(), 2);
        assert_eq!(pieces[0].cells, 2);
        assert_eq!(pieces[1].cells, 1);
    }

    #[test]
    fn a_joined_sequence_is_measured_per_scalar() {
        // A multi-codepoint emoji: two wide scalars glued by a zero-width joiner. The pinned model
        // measures per scalar, so it is two cells and two cells, and the joiner belongs to the
        // scalar before it. Any other split would let a cluster be cut in half at a margin.
        let text = "\u{1f468}\u{200d}\u{1f4bb}";
        let pieces = clusters(text);
        assert_eq!(pieces.len(), 2);
        assert_eq!(pieces[0].text, "\u{1f468}\u{200d}");
        assert_eq!(pieces[0].cells, 2);
        assert_eq!(pieces[1].cells, 2);
        let total: u64 = pieces.iter().map(|piece| piece.cells).sum();
        assert_eq!(total, unicode::cells_for(text) as u64);
    }

    #[test]
    fn the_colour_parameters_are_the_ones_the_profile_writes() {
        assert_eq!(
            colour_parameter(CellColour::Indexed(1), 30, 90, 38).as_deref(),
            Some("31")
        );
        assert_eq!(
            colour_parameter(CellColour::Indexed(9), 30, 90, 38).as_deref(),
            Some("91")
        );
        assert_eq!(
            colour_parameter(CellColour::Indexed(200), 30, 90, 38).as_deref(),
            Some("38:5:200")
        );
        assert_eq!(colour_parameter(CellColour::Default, 30, 90, 38), None);
    }
}

/// How a destination measures what it is asked to draw.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Width {
    /// The profile's pinned model, which is the one the session measures with.
    Pinned,
    /// A destination that joins across a zero-width joiner and draws the whole sequence as one
    /// double-width glyph.
    ///
    /// Real terminals do this and the pinned model does not: the session says a joined emoji
    /// occupies four cells and this destination advances two. That disagreement is the whole
    /// reason the renderer places every cluster at an absolute address, so the corpus is checked
    /// against a destination that actually disagrees rather than against the renderer's own
    /// measurement of its own output.
    Joining,
}

/// A model of the terminal a frame is drawn into.
///
/// It is deliberately not a model of a *correct* terminal. It measures glyphs its own way, it can
/// start in origin mode inside a scroll region with left and right margins and insert mode set,
/// and it records anything that would have moved a cell the renderer did not address: an overflow
/// past the last column, a scroll, a wrap left pending. Comparing its grid with the canonical rows
/// is the continuous cursor and wrap comparison the projection owes, made against the bytes a
/// frame actually writes rather than against what it meant by them.
#[cfg(test)]
#[derive(Debug)]
struct Destination {
    cells: Vec<Vec<String>>,
    columns: usize,
    line: usize,
    column: usize,
    autowrap: bool,
    cursor_visible: bool,
    overflowed: bool,
    scrolled: bool,
    /// This destination's own width behaviour.
    width: Width,
    /// Whether an address is measured from the region's corner.
    origin: bool,
    /// The scroll region, as inclusive line numbers.
    region: (usize, usize),
    /// The left and right margins, once mode 69 has allowed them.
    horizontal: Option<(usize, usize)>,
    /// Whether mode 69 is on, without which a margin cannot be set.
    margins_allowed: bool,
    /// Whether drawing a cell pushes its neighbours along the row.
    insert: bool,
    /// Whether a wrap is pending: the last column holds a cell and the next one would wrap.
    pending: bool,
}

#[cfg(test)]
impl Destination {
    fn new(rows: usize, columns: usize) -> Self {
        Self {
            cells: vec![vec![" ".to_owned(); columns]; rows],
            columns,
            line: 0,
            column: 0,
            autowrap: true,
            cursor_visible: true,
            overflowed: false,
            scrolled: false,
            width: Width::Pinned,
            origin: false,
            region: (0, rows.saturating_sub(1)),
            horizontal: None,
            margins_allowed: false,
            insert: false,
            pending: false,
        }
    }

    /// A destination in every state a previous direct presentation could have left it in.
    ///
    /// Origin mode inside a scroll region, left and right margins in force, insert mode on, and a
    /// width model of its own. A frame that draws the canonical cells into this one draws them
    /// into any terminal.
    fn hostile(rows: usize, columns: usize) -> Self {
        let mut destination = Self::new(rows, columns);
        destination.width = Width::Joining;
        destination.margins_allowed = true;
        destination.region = (1, rows.saturating_sub(1).max(1));
        destination.horizontal = Some((1, columns.saturating_sub(1).max(1)));
        destination.origin = true;
        destination.insert = true;
        destination
    }

    fn feed(&mut self, bytes: &[u8]) {
        let text = String::from_utf8_lossy(bytes).into_owned();
        let mut chars = text.chars().peekable();
        let mut pending = String::new();
        while let Some(scalar) = chars.next() {
            match scalar {
                '\u{1b}' => {
                    self.print(&core::mem::take(&mut pending));
                    match chars.next() {
                        Some('[') => {
                            let mut body = String::new();
                            for next in chars.by_ref() {
                                body.push(next);
                                if next.is_ascii_alphabetic() || next == '@' || next == '`' {
                                    break;
                                }
                            }
                            self.csi(&body);
                        }
                        Some(']') => {
                            // A string, consumed to its terminator. Nothing a colour or a title
                            // command does can move a cell.
                            let mut previous = '\0';
                            for next in chars.by_ref() {
                                if next == '\u{7}' || (previous == '\u{1b}' && next == '\\') {
                                    break;
                                }
                                previous = next;
                            }
                        }
                        Some('D') | Some('E') | Some('M') => self.scrolled = true,
                        _ => {}
                    }
                }
                '\n' | '\u{b}' | '\u{c}' => {
                    self.print(&core::mem::take(&mut pending));
                    self.scrolled = true;
                }
                '\r' => {
                    self.print(&core::mem::take(&mut pending));
                    self.column = 0;
                    self.pending = false;
                }
                other => pending.push(other),
            }
        }
        self.print(&pending);
    }

    fn csi(&mut self, body: &str) {
        let Some(final_byte) = body.chars().last() else {
            return;
        };
        let parameters = &body[..body.len() - final_byte.len_utf8()];
        let field = |index: usize| -> Option<usize> {
            parameters
                .split(';')
                .nth(index)
                .and_then(|field| field.parse::<usize>().ok())
        };
        match final_byte {
            'H' => {
                let line = field(0).unwrap_or(1).saturating_sub(1);
                let column = field(1).unwrap_or(1).saturating_sub(1);
                self.address(line, column);
            }
            'J' => {
                for row in &mut self.cells {
                    for cell in row.iter_mut() {
                        *cell = " ".to_owned();
                    }
                }
                self.pending = false;
            }
            'K' => {
                if let Some(row) = self.cells.get_mut(self.line) {
                    for cell in row.iter_mut().skip(self.column) {
                        *cell = " ".to_owned();
                    }
                }
                self.pending = false;
            }
            'r' => {
                // The scroll region, which also homes the cursor.
                let rows = self.cells.len();
                let top = field(0).unwrap_or(1).saturating_sub(1);
                let bottom = field(1).unwrap_or(rows).saturating_sub(1);
                self.region = (top, bottom.min(rows.saturating_sub(1)));
                self.address(0, 0);
            }
            's' if self.margins_allowed => {
                let left = field(0).unwrap_or(1).saturating_sub(1);
                let right = field(1).unwrap_or(self.columns).saturating_sub(1);
                self.horizontal = Some((left, right.min(self.columns.saturating_sub(1))));
            }
            'h' | 'l' => {
                let enabled = final_byte == 'h';
                match parameters.strip_prefix('?') {
                    Some(mode) => match mode {
                        "6" => {
                            self.origin = enabled;
                            // Changing origin mode homes the cursor, which is why a frame that
                            // installs it does so before it places the cursor and not after.
                            self.address(0, 0);
                        }
                        "7" => self.autowrap = enabled,
                        "25" => self.cursor_visible = enabled,
                        "69" => {
                            self.margins_allowed = enabled;
                            if !enabled {
                                self.horizontal = None;
                            }
                        }
                        _ => {}
                    },
                    None => {
                        if parameters == "4" {
                            self.insert = enabled;
                        }
                    }
                }
            }
            'S' | 'T' | 'L' | 'M' => self.scrolled = true,
            _ => {}
        }
    }

    /// Where an address lands, which depends on the coordinate system this destination is in.
    fn address(&mut self, line: usize, column: usize) {
        let (left, right) = self
            .horizontal
            .unwrap_or((0, self.columns.saturating_sub(1)));
        if self.origin {
            self.line = (self.region.0 + line).min(self.region.1);
            self.column = (left + column).min(right);
        } else {
            self.line = line.min(self.cells.len().saturating_sub(1));
            self.column = column.min(self.columns.saturating_sub(1));
        }
        self.pending = false;
    }

    /// This destination's own segmentation of a string, and its own width for each piece.
    fn segment(&self, text: &str) -> Vec<(String, usize)> {
        let mut out: Vec<(String, usize)> = Vec::new();
        for cluster in clusters(text) {
            let width = usize::try_from(cluster.cells).unwrap_or(0);
            if self.width == Width::Joining
                && let Some(last) = out.last_mut()
                && last.0.ends_with('\u{200d}')
            {
                // Joined to what came before it, and drawn in the cells that piece already has.
                // This is where this destination and the session disagree.
                last.0.push_str(cluster.text);
                continue;
            }
            out.push((cluster.text.to_owned(), width));
        }
        out
    }

    fn print(&mut self, text: &str) {
        if text.is_empty() {
            return;
        }
        for (cluster, width) in self.segment(text) {
            if self.pending {
                // A cell was already written into the last column and this one wraps.
                self.overflowed = true;
                if self.autowrap {
                    self.scrolled = true;
                }
                return;
            }
            if self.column + width > self.columns {
                // Autowrap would move this to the next line and could scroll the screen. With it
                // off the destination discards the cell, which is still a cell the renderer had no
                // business writing here.
                self.overflowed = true;
                if self.autowrap {
                    self.scrolled = true;
                }
                return;
            }
            let columns = self.columns;
            let insert = self.insert;
            if let Some(row) = self.cells.get_mut(self.line) {
                if insert {
                    // Insert mode: the cells beside this one are pushed along the row, which is
                    // the damage a frame that did not clear it would do to every row it drew.
                    for _ in 0..width {
                        row.insert(self.column, String::new());
                    }
                    row.truncate(columns);
                }
                if let Some(cell) = row.get_mut(self.column) {
                    *cell = cluster;
                }
                for offset in 1..width {
                    if let Some(cell) = row.get_mut(self.column + offset) {
                        *cell = String::new();
                    }
                }
            }
            self.column += width;
            if self.column >= self.columns && self.autowrap {
                self.column = self.columns.saturating_sub(1);
                self.pending = true;
            }
        }
    }
}

#[cfg(test)]
mod fixtures {
    use super::*;
    use kr_protocol::projection::{
        CellRendition, CellRun, CharsetState, MarginState, PaletteProvenance, PaletteState,
        ProjectedBuffer, ProjectedCursor, ProjectedKeyboard, ProjectedRow, ProjectedTitle,
        ProjectedViewport, Rgb,
    };
    use kr_protocol::scalars::{Nullable, U64};
    use std::collections::BTreeMap;

    fn plain_palette() -> PaletteState {
        let grey = Rgb {
            red: 0x80,
            green: 0x80,
            blue: 0x80,
        };
        PaletteState {
            source: PaletteProvenance::ProfileDefault,
            foreground: grey,
            background: grey,
            cursor: grey,
            pointer_foreground: grey,
            pointer_background: grey,
            selection_background: grey,
            selection_foreground: grey,
            overrides: Vec::new(),
        }
    }

    fn screen_of(case: &serde_json::Value) -> (Screen, Window) {
        let window = &case["window"];
        let viewport = ProjectedViewport {
            top_row: U64::new(window["top_row"].as_u64().expect("a top row")),
            rows: U64::new(window["rows"].as_u64().expect("rows")),
            left_column: U64::new(window["left_column"].as_u64().expect("a left column")),
            columns: U64::new(window["columns"].as_u64().expect("columns")),
        };
        let cursor = &case["cursor"];
        let mut rows = BTreeMap::new();
        for row in case["rows"].as_array().expect("rows") {
            let id = row["row"].as_u64().expect("a row identifier");
            let runs: Vec<CellRun> = row["runs"]
                .as_array()
                .expect("runs")
                .iter()
                .map(|run| CellRun {
                    column: U64::new(run["column"].as_u64().expect("a column")),
                    cells: U64::new(run["cells"].as_u64().expect("cells")),
                    text: run["text"].as_str().expect("text").to_owned(),
                    rendition: CellRendition::PLAIN,
                    hyperlink: Nullable::null(),
                })
                .collect();
            rows.insert(
                (ProjectedBuffer::Primary, id),
                ProjectedRow {
                    row: U64::new(id),
                    soft_wrapped: row["soft_wrapped"].as_bool().unwrap_or_default(),
                    truncated: false,
                    runs,
                },
            );
        }
        let screen = Screen {
            generation: 1,
            cursor_at: 0,
            active_buffer: ProjectedBuffer::Primary,
            dimensions: kr_protocol::session::Dimensions::new(
                window["columns"].as_u64().expect("columns"),
                window["rows"].as_u64().expect("rows"),
            ),
            viewport,
            cursor: ProjectedCursor {
                column: U64::new(cursor["column"].as_u64().expect("a column")),
                row: U64::new(cursor["row"].as_u64().expect("a row")),
                visible: cursor["visible"].as_bool().unwrap_or(true),
                style: U64::new(cursor["style"].as_u64().unwrap_or(1)),
                pending_wrap: cursor["pending_wrap"].as_bool().unwrap_or_default(),
            },
            saved_cursors: Vec::new(),
            margins: MarginState {
                top: U64::ZERO,
                bottom: U64::new(window["rows"].as_u64().expect("rows").saturating_sub(1)),
                left: U64::ZERO,
                right: U64::new(
                    window["columns"]
                        .as_u64()
                        .expect("columns")
                        .saturating_sub(1),
                ),
            },
            rendition: CellRendition::PLAIN,
            tab_stops: Vec::new(),
            charsets: CharsetState {
                g0: "Ascii".to_owned(),
                g1: "Ascii".to_owned(),
                shift_out: false,
            },
            modes: BTreeMap::new(),
            keypad_application: false,
            keyboard: ProjectedKeyboard {
                modify_other_keys: U64::ZERO,
                primary: kr_protocol::projection::KittyKeyboardState {
                    flags: Nullable::null(),
                    stack: Vec::new(),
                },
                alternate: kr_protocol::projection::KittyKeyboardState {
                    flags: Nullable::null(),
                    stack: Vec::new(),
                },
            },
            title: ProjectedTitle::default(),
            title_stack: Vec::new(),
            hyperlink: None,
            palette: plain_palette(),
            rows,
            hyperlinks: BTreeMap::new(),
            oldest_retained_row: 0,
            evicted: false,
            degraded: false,
        };
        let window = Window::of(&screen);
        (screen, window)
    }

    /// Puts on the destination whatever a case says was there before the frame.
    fn preload(destination: &mut Destination, case: &serde_json::Value) {
        if let Some(preload) = case.get("preload").and_then(serde_json::Value::as_array) {
            for (index, line) in preload.iter().enumerate() {
                destination.line = index;
                destination.column = 0;
                destination.print(line.as_str().expect("a preloaded line"));
            }
            destination.line = 0;
            destination.column = 0;
            // Whatever the preload did is not what this frame is being judged on.
            destination.overflowed = false;
            destination.scrolled = false;
            destination.pending = false;
        }
    }

    /// KR-REQ-08.40 and KR-ACC-023: the renderer's corpus, checked against a destination.
    ///
    /// Every case is drawn twice. Once as an installed snapshot into a terminal that measures
    /// glyphs the way the session does, and once as a *delta* into a terminal that disagrees about
    /// width and starts in origin mode, inside a scroll region, inside left and right margins and
    /// in insert mode. The second pass is where the promises are worth something: an update clears
    /// no screen, so every blank cell has to come from the row erasure, and every cell has to land
    /// on its canonical column although the destination advances its own cursor differently.
    #[test]
    fn the_projected_renderer_matches_its_fixtures() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("fixtures")
            .join("terminal")
            .join("projection.json");
        let text = std::fs::read_to_string(&path).expect("the projection fixtures");
        let document: serde_json::Value = serde_json::from_str(&text).expect("the fixtures parse");
        let cases = document["cases"].as_array().expect("cases");
        assert!(!cases.is_empty(), "the corpus is not empty");
        for case in cases {
            let id = case["id"].as_str().expect("an identifier");
            let (screen, window) = screen_of(case);
            let lines = usize::try_from(window.rows).expect("rows");
            let columns = usize::try_from(window.columns).expect("columns");
            let visible = screen.visible_rows();
            let passes = [
                (
                    "installed",
                    install(&screen, window, Keyboard::Install),
                    Destination::new(lines, columns),
                ),
                (
                    "updated on a terminal that disagrees",
                    update(&screen, window, &visible, true, Keyboard::Install),
                    Destination::hostile(lines, columns),
                ),
            ];
            for (pass, painted, mut destination) in passes {
                preload(&mut destination, case);
                destination.feed(&painted.bytes);

                assert!(
                    !destination.overflowed,
                    "{id} ({pass}): no cell was written past the last column"
                );
                assert!(
                    !destination.scrolled,
                    "{id} ({pass}): nothing the renderer wrote could scroll the destination"
                );
                assert!(
                    destination.autowrap,
                    "{id} ({pass}): the session's own autowrap was put back"
                );
                assert!(
                    !destination.pending,
                    "{id} ({pass}): and no wrap was left pending on it"
                );

                let expected = case["lines"].as_array().expect("lines");
                for (index, line) in expected.iter().enumerate() {
                    let wanted: Vec<String> = line
                        .as_array()
                        .expect("cells")
                        .iter()
                        .map(|cell| cell.as_str().expect("a cell").to_owned())
                        .collect();
                    assert_eq!(
                        destination.cells[index], wanted,
                        "{id} ({pass}): line {index} holds the canonical cells the window shows"
                    );
                }

                if let Some(cell) = case.get("cursor_cell") {
                    let wanted = cell.as_array().expect("a cursor cell");
                    assert_eq!(
                        (destination.line, destination.column),
                        (
                            usize::try_from(wanted[0].as_u64().expect("a line")).expect("a line"),
                            usize::try_from(wanted[1].as_u64().expect("a column"))
                                .expect("a column")
                        ),
                        "{id} ({pass}): the cursor was placed explicitly"
                    );
                    assert!(
                        destination.cursor_visible,
                        "{id} ({pass}): the cursor is shown"
                    );
                }
                if case
                    .get("cursor_hidden")
                    .and_then(serde_json::Value::as_bool)
                    == Some(true)
                {
                    assert!(
                        !destination.cursor_visible,
                        "{id} ({pass}): a cursor outside the window is hidden rather than misplaced"
                    );
                }

                let expect = &case["expect"];
                let comparison = painted.comparison;
                assert_eq!(
                    comparison.runs_replaced as u64,
                    expect["runs_replaced"].as_u64().expect("runs_replaced"),
                    "{id} ({pass}): runs replaced"
                );
                assert_eq!(
                    comparison.clusters_replaced as u64,
                    expect["clusters_replaced"]
                        .as_u64()
                        .expect("clusters_replaced"),
                    "{id} ({pass}): clusters replaced"
                );
                assert_eq!(
                    comparison.cells_clipped,
                    expect["cells_clipped"].as_u64().expect("cells_clipped"),
                    "{id} ({pass}): cells clipped"
                );
                assert_eq!(
                    comparison.soft_wraps as u64,
                    expect["soft_wraps"].as_u64().expect("soft_wraps"),
                    "{id} ({pass}): soft wraps reported"
                );
                assert_eq!(
                    comparison.pending_wrap,
                    expect["pending_wrap"].as_bool().expect("pending_wrap"),
                    "{id} ({pass}): the pending wrap"
                );
                assert_eq!(
                    comparison.cursor_outside,
                    expect["cursor_outside"].as_bool().expect("cursor_outside"),
                    "{id} ({pass}): the cursor's window"
                );
            }
        }
    }

    /// A screen with a scroll region of its own, and origin mode on.
    fn screen_with_a_region() -> (Screen, Window) {
        let case = serde_json::json!({
            "window": {"top_row": 0, "left_column": 0, "rows": 4, "columns": 8},
            "rows": [
                {"row": 0, "soft_wrapped": false, "runs": [
                    {"column": 0, "cells": 5, "text": "first"}]},
                {"row": 2, "soft_wrapped": false, "runs": [
                    {"column": 0, "cells": 5, "text": "third"}]}
            ],
            "cursor": {"column": 3, "row": 2, "visible": true, "style": 1,
                       "pending_wrap": false}
        });
        let (mut screen, window) = screen_of(&case);
        screen.margins = MarginState {
            top: U64::new(1),
            bottom: U64::new(2),
            left: U64::ZERO,
            right: U64::new(7),
        };
        screen
            .modes
            .insert((super::super::ProjectedModeSpelling::Dec, 6), true);
        (screen, window)
    }

    /// KR-REQ-08.40 and KR-REQ-08.84: the session's own coordinate system is put back after the
    /// last row, so a presentation that becomes a direct one hands the application the terminal it
    /// is writing for.
    #[test]
    fn a_frame_installs_the_sessions_own_region_after_its_last_row() {
        let (screen, window) = screen_with_a_region();
        let painted = install(&screen, window, Keyboard::Install);
        assert!(
            !painted.comparison.geometry_withheld,
            "a destination showing the whole grid can carry the geometry"
        );
        let bytes = String::from_utf8_lossy(&painted.bytes).into_owned();
        let region = bytes
            .find("\u{1b}[2;3r")
            .expect("the session's scroll region");
        let origin = bytes.find("\u{1b}[?6h").expect("the session's origin mode");
        let content = bytes.rfind("third").expect("the last row's text");
        assert!(
            region > content && origin > region,
            "the region and origin mode come after the last row, because every row before them \
             was addressed absolutely: {}",
            bytes.escape_debug()
        );

        let mut destination = Destination::new(4, 8);
        destination.feed(&painted.bytes);
        assert!(destination.origin, "the destination is left in origin mode");
        assert_eq!(
            destination.region,
            (1, 2),
            "inside the session's own scroll region"
        );
        assert_eq!(
            (destination.line, destination.column),
            (2, 3),
            "and the cursor is on the canonical cell, addressed in the coordinates that now apply"
        );
        assert_eq!(
            destination.cells[2][..5],
            ["t", "h", "i", "r", "d"],
            "while the rows were drawn where the canonical grid holds them"
        );
    }

    /// KR-REQ-08.40: a window that shows part of the grid has nowhere to put a margin, so it says
    /// so rather than installing one that means something else.
    #[test]
    fn a_window_that_cannot_carry_the_sessions_region_says_so() {
        let (mut screen, window) = screen_with_a_region();
        // The grid is wider than the window: this destination is showing a part of it.
        screen.dimensions = kr_protocol::session::Dimensions::new(12, 4);
        let painted = install(&screen, window, Keyboard::Install);
        assert!(
            painted.comparison.geometry_withheld,
            "the projection reports what it could not carry"
        );
        assert!(
            !painted.comparison.complete(),
            "and a frame that could not carry it is not a complete one"
        );
        let bytes = String::from_utf8_lossy(&painted.bytes).into_owned();
        assert!(
            !bytes.contains("\u{1b}[?6h"),
            "nothing left this destination in origin mode: {}",
            bytes.escape_debug()
        );
        assert!(
            !bytes.contains("\u{1b}[2;3r"),
            "and nothing set a region on it: {}",
            bytes.escape_debug()
        );
        let mut destination = Destination::hostile(4, 8);
        destination.feed(&painted.bytes);
        assert!(
            !destination.origin,
            "a destination that was in origin mode is taken out of it and left out of it"
        );
        assert_eq!(
            destination.region,
            (0, 3),
            "with the whole screen as its region"
        );
        assert!(!destination.insert, "and in replace mode");
    }

    /// KR-REQ-08.40: a frame establishes the coordinate system it addresses in, and turns autowrap
    /// off, before its first cell, whatever else it does.
    #[test]
    fn every_frame_disables_autowrap_before_it_draws_anything() {
        let case = serde_json::json!({
            "window": {"top_row": 0, "left_column": 0, "rows": 1, "columns": 4},
            "rows": [{"row": 0, "soft_wrapped": false, "runs": [
                {"column": 0, "cells": 4, "text": "full"}
            ]}],
            "cursor": {"column": 0, "row": 0, "visible": true, "style": 1, "pending_wrap": false}
        });
        let (screen, window) = screen_of(&case);
        for painted in [
            install(&screen, window, Keyboard::Install),
            update(&screen, window, &[0], false, Keyboard::Install),
        ] {
            assert!(
                painted
                    .bytes
                    .starts_with(b"\x1b[?6l\x1b[?69l\x1b[r\x1b[4l\x1b[?7l"),
                "a frame opens with origin mode off, no margins, the whole screen as the scroll \
                 region, replace mode and autowrap off, before anything is drawn: {}",
                String::from_utf8_lossy(&painted.bytes).escape_debug()
            );
            assert!(
                painted.bytes.windows(5).any(|window| window == b"\x1b[?7h"),
                "and the session's own value is put back"
            );
        }
    }
}

#[cfg(test)]
mod safety {
    use super::*;
    use kr_protocol::projection::{
        CellRendition, CellRun, CharsetState, MarginState, PaletteProvenance, PaletteState,
        ProjectedCursor, ProjectedKeyboard, ProjectedRow, ProjectedTitle, ProjectedViewport, Rgb,
    };
    use kr_protocol::scalars::{Nullable, U64};
    use std::collections::BTreeMap;

    fn screen(title: &str, text: &str, link: Option<&str>) -> Screen {
        let colour = Rgb {
            red: 1,
            green: 2,
            blue: 3,
        };
        Screen {
            generation: 1,
            cursor_at: 0,
            active_buffer: ProjectedBuffer::Primary,
            dimensions: kr_protocol::session::Dimensions::new(20, 1),
            viewport: ProjectedViewport {
                top_row: U64::ZERO,
                rows: U64::new(1),
                left_column: U64::ZERO,
                columns: U64::new(20),
            },
            cursor: ProjectedCursor {
                column: U64::ZERO,
                row: U64::ZERO,
                visible: true,
                style: U64::new(1),
                pending_wrap: false,
            },
            saved_cursors: Vec::new(),
            margins: MarginState {
                top: U64::ZERO,
                bottom: U64::ZERO,
                left: U64::ZERO,
                right: U64::new(19),
            },
            rendition: CellRendition::PLAIN,
            tab_stops: Vec::new(),
            charsets: CharsetState {
                g0: "Ascii".to_owned(),
                g1: "Ascii".to_owned(),
                shift_out: false,
            },
            modes: BTreeMap::new(),
            keypad_application: false,
            keyboard: ProjectedKeyboard {
                modify_other_keys: U64::ZERO,
                primary: kr_protocol::projection::KittyKeyboardState {
                    flags: Nullable::null(),
                    stack: Vec::new(),
                },
                alternate: kr_protocol::projection::KittyKeyboardState {
                    flags: Nullable::null(),
                    stack: Vec::new(),
                },
            },
            title: ProjectedTitle {
                icon: String::new(),
                window: title.to_owned(),
            },
            title_stack: Vec::new(),
            hyperlink: None,
            palette: PaletteState {
                source: PaletteProvenance::ProfileDefault,
                foreground: colour,
                background: colour,
                cursor: colour,
                pointer_foreground: colour,
                pointer_background: colour,
                selection_background: colour,
                selection_foreground: colour,
                overrides: Vec::new(),
            },
            rows: BTreeMap::from([(
                (ProjectedBuffer::Primary, 0),
                ProjectedRow {
                    row: U64::ZERO,
                    soft_wrapped: false,
                    truncated: false,
                    runs: vec![CellRun {
                        column: U64::ZERO,
                        cells: U64::new(
                            u64::try_from(unicode::cells_for(text)).unwrap_or_default(),
                        ),
                        text: text.to_owned(),
                        rendition: CellRendition::PLAIN,
                        hyperlink: Nullable(link.map(str::to_owned)),
                    }],
                },
            )]),
            hyperlinks: BTreeMap::new(),
            oldest_retained_row: 0,
            evicted: false,
            degraded: false,
        }
    }

    /// KR-REQ-08.82: nothing a frame writes can end its own control string and start another.
    #[test]
    fn a_title_cannot_carry_a_clipboard_write_out_of_a_rendering() {
        // A title an application set, carrying a string terminator and an OSC 52 behind it. Written
        // through, it would close the title command and leave a clipboard write to be read as a
        // fresh one: a restoration that emits only rendering operations, emitting one that copies.
        let hostile = "ordinary\u{1b}\\\u{1b}]52;c;c2VjcmV0\u{7}";
        let screen = screen(hostile, "text", None);
        let painted = install(&screen, Window::of(&screen), Keyboard::Install);
        let bytes = painted.bytes;
        assert!(
            !contains(&bytes, b"\x1b]52"),
            "no clipboard command reached the destination: {:?}",
            String::from_utf8_lossy(&bytes)
        );
        // Every control string this frame wrote is one this frame opened. The count of terminators
        // equals the count of introducers, which is what a payload ending its own string breaks.
        let introducers = bytes.windows(2).filter(|pair| *pair == b"\x1b]").count();
        let terminators = bytes.windows(2).filter(|pair| *pair == b"\x1b\\").count();
        assert_eq!(
            introducers,
            terminators,
            "no payload ended its own string: {:?}",
            String::from_utf8_lossy(&bytes)
        );
        assert!(
            contains(&bytes, b"ordinary"),
            "what the title actually said is still drawn"
        );
        assert_eq!(
            painted.comparison.controls_dropped, 1,
            "and the frame says it dropped something rather than passing it through quietly"
        );
    }

    /// KR-REQ-08.82: the same rule for a link target and for the text of a row.
    #[test]
    fn a_link_target_and_a_cell_cannot_carry_a_control_either() {
        let screen = screen(
            "plain",
            "before\u{7}after",
            Some("https://example.invalid/\u{1b}\\\u{1b}]52;c;c2VjcmV0\u{7}"),
        );
        let painted = install(&screen, Window::of(&screen), Keyboard::Install);
        let bytes = painted.bytes;
        assert!(
            !contains(&bytes, b"\x1b]52"),
            "no clipboard command reached the destination: {:?}",
            String::from_utf8_lossy(&bytes)
        );
        // Every control string this frame wrote is one this frame opened. The count of terminators
        // equals the count of introducers, which is what a payload ending its own string breaks.
        let introducers = bytes.windows(2).filter(|pair| *pair == b"\x1b]").count();
        let terminators = bytes.windows(2).filter(|pair| *pair == b"\x1b\\").count();
        assert_eq!(
            introducers,
            terminators,
            "no payload ended its own string: {:?}",
            String::from_utf8_lossy(&bytes)
        );
        assert!(
            !bytes.contains(&0x07),
            "and no bell rang: {:?}",
            String::from_utf8_lossy(&bytes)
        );
        assert!(
            contains(&bytes, b"beforeafter"),
            "the cells are still drawn"
        );
    }

    /// KR-REQ-08.40: the destination is put into the modes the session's input depends on.
    #[test]
    fn a_frame_installs_the_modes_the_session_needs_for_input() {
        let mut screen = screen("plain", "text", None);
        screen
            .modes
            .insert((super::super::ProjectedModeSpelling::Dec, 1006), true);
        screen
            .modes
            .insert((super::super::ProjectedModeSpelling::Dec, 1000), true);
        screen
            .modes
            .insert((super::super::ProjectedModeSpelling::Dec, 2004), true);
        screen
            .modes
            .insert((super::super::ProjectedModeSpelling::Dec, 1049), true);
        screen.keypad_application = true;
        let painted = install(&screen, Window::of(&screen), Keyboard::Install);
        let bytes = painted.bytes;
        for mode in [&b"\x1b[?1006h"[..], b"\x1b[?1000h", b"\x1b[?2004h"] {
            assert!(
                contains(&bytes, mode),
                "the destination was put into {:?}: without it a person's mouse and paste produce \
                 nothing the application reads",
                String::from_utf8_lossy(mode)
            );
        }
        assert!(
            contains(&bytes, b"\x1b="),
            "and into the application keypad"
        );
        assert!(
            !contains(&bytes, b"\x1b[?1049h"),
            "and not into the alternate buffer, which is the buffer selection under another name \
             and would clear the screen this frame is painting"
        );
        assert!(
            contains(&bytes, b"\x1b[>4;0m") && contains(&bytes, b"\x1b[=0;1u"),
            "the keyboard negotiation is installed as a state: {:?}",
            String::from_utf8_lossy(&bytes)
        );

        // And withheld from a terminal nobody was allowed to ask about.
        let withheld = install(&screen, Window::of(&screen), Keyboard::Withhold);
        assert!(
            !contains(&withheld.bytes, b"\x1b[>4;"),
            "nothing of the keyboard is changed on a terminal that was never asked"
        );
        assert!(!contains(&withheld.bytes, b"\x1b[="));
        assert!(
            contains(&withheld.bytes, b"\x1b[?1006h"),
            "but the mouse modes still are, because those are not the keyboard's"
        );
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }
}
