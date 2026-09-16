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
    CellVerticalAlign, ProjectedRow,
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
}

impl Comparison {
    /// Whether the destination is showing the whole of what the session holds.
    #[must_use]
    pub const fn complete(&self) -> bool {
        self.runs_replaced == 0
            && self.cells_clipped == 0
            && self.clusters_replaced == 0
            && !self.pending_wrap
            && !self.cursor_outside
            && self.soft_wraps == 0
            && self.truncated_rows == 0
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

/// Draws the whole screen.
///
/// This is what an installed snapshot produces: the palette, the title, the screen cleared, every
/// visible row, and the cursor placed last so the destination is never left mid-repaint with a
/// live cursor on it.
#[must_use]
pub fn install(screen: &Screen, window: Window) -> Painted {
    let mut writer = Writer::new(screen, window);
    writer.begin();
    writer.palette();
    writer.title();
    writer.clear();
    let rows = screen.visible_rows();
    writer.rows(&rows);
    writer.finish();
    writer.done()
}

/// Draws only the rows an update changed.
///
/// A row that is not on the destination is skipped rather than clamped: the window says which
/// canonical rows this destination shows, and a row outside it belongs to a part of the grid
/// nobody is looking at.
#[must_use]
pub fn update(screen: &Screen, window: Window, rows: &[u64]) -> Painted {
    let mut writer = Writer::new(screen, window);
    writer.begin();
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

struct Writer<'a> {
    screen: &'a Screen,
    window: Window,
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
    fn new(screen: &'a Screen, window: Window) -> Self {
        Self {
            screen,
            window,
            out: Vec::new(),
            pen: None,
            link: None,
            comparison: Comparison::default(),
        }
    }

    /// Turns autowrap off, before a single cell is written.
    fn begin(&mut self) {
        self.mode(AUTOWRAP, false);
    }

    /// Puts the session's own autowrap back and places the cursor.
    fn finish(&mut self) {
        if self.link.is_some() {
            self.close_link();
        }
        // The rendition the next character would be drawn with belongs to the session, so it is
        // installed after the rows and before the cursor: a row drawn afterwards would otherwise
        // be drawn through the pen of whichever run happened to be last.
        self.rendition(self.screen.rendition);
        self.mode(AUTOWRAP, self.screen.autowrap());
        self.cursor();
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
                continue;
            };
            self.row(*row, line);
        }
    }

    fn row(&mut self, row: u64, line: u32) {
        self.place(line, 0);
        let Some(content) = self.screen.rows.get(&(self.screen.active_buffer, row)) else {
            // A row the window shows and the session does not hold is blank, not stale. Erasing it
            // is what makes a destination taller than the grid leave its unused area empty.
            self.csi(b"K");
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
        // Whatever the runs did not cover is cleared, so a shorter row does not leave the tail of
        // a longer one behind it.
        self.csi(b"K");
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
        let mut painted: Vec<(String, u64)> = Vec::new();
        if measured == cells {
            let mut column = start;
            for cluster in clusters(&run.text) {
                let cluster_end = column.saturating_add(cluster.cells);
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
                    painted.push((" ".repeat(usize::try_from(inside).unwrap_or(0)), inside));
                } else {
                    painted.push((cluster.text.to_owned(), cluster.cells));
                }
                column = cluster_end;
            }
        } else {
            // Replaced, not dropped: the cells still belong to this run, and leaving them empty
            // would let the next run's absolute address be the only thing holding the row together.
            self.comparison.runs_replaced += 1;
            let inside = end.min(right).saturating_sub(start.max(left));
            painted.push((" ".repeat(usize::try_from(inside).unwrap_or(0)), inside));
        }
        if painted.is_empty() {
            return clipped;
        }

        let destination = start.max(left).saturating_sub(left);
        let destination = u32::try_from(destination).unwrap_or(u32::MAX);
        self.place(line, destination);
        self.rendition(run.rendition);
        match run.hyperlink.as_ref() {
            Some(uri) => self.open_link(uri),
            None => {
                if self.link.is_some() {
                    self.close_link();
                }
            }
        }
        for (text, _) in painted {
            self.out.extend_from_slice(text.as_bytes());
        }
        clipped
    }

    fn cursor(&mut self) {
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
        self.place(line, destination);
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

    fn osc(&mut self, selector: &[u8], body: &[u8]) {
        self.out.push(ESC);
        self.out.push(b']');
        self.out.extend_from_slice(selector);
        self.out.push(b';');
        self.out.extend_from_slice(body);
        self.out.extend_from_slice(ST);
    }

    fn osc_bare(&mut self, selector: &[u8]) {
        self.out.push(ESC);
        self.out.push(b']');
        self.out.extend_from_slice(selector);
        self.out.extend_from_slice(ST);
    }
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
    for scalar in text.chars() {
        let width = scalar.len_utf8();
        if unicode::is_zero_width(scalar) {
            // It joins whatever is already being collected. A run that opens with one has nothing
            // to join here, so it becomes the start of the first cluster and is measured with it.
            index += width;
            continue;
        }
        if index > start {
            let piece = &text[start..index];
            out.push(Cluster {
                text: piece,
                cells: unicode::cells_for(piece) as u64,
            });
            start = index;
        }
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

/// A destination terminal, as much of one as the renderer's own promises can be checked against.
///
/// It is deliberately literal. It applies exactly the operations the painter emits, and it records
/// the two things section 8 forbids: a cell written past the last column, and anything that would
/// scroll the destination. Comparing its grid with the canonical rows is the continuous cursor and
/// wrap comparison the projection owes, made against bytes rather than against intentions.
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
        }
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
                            while let Some(next) = chars.next() {
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
                            while let Some(next) = chars.next() {
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
        match final_byte {
            'H' => {
                let mut fields = parameters.split(';');
                let line = fields
                    .next()
                    .and_then(|field| field.parse::<usize>().ok())
                    .unwrap_or(1);
                let column = fields
                    .next()
                    .and_then(|field| field.parse::<usize>().ok())
                    .unwrap_or(1);
                self.line = line.saturating_sub(1);
                self.column = column.saturating_sub(1);
            }
            'J' => {
                for row in &mut self.cells {
                    for cell in row.iter_mut() {
                        *cell = " ".to_owned();
                    }
                }
            }
            'K' => {
                if let Some(row) = self.cells.get_mut(self.line) {
                    for cell in row.iter_mut().skip(self.column) {
                        *cell = " ".to_owned();
                    }
                }
            }
            'h' | 'l' => {
                let enabled = final_byte == 'h';
                if let Some(mode) = parameters.strip_prefix('?') {
                    match mode {
                        "7" => self.autowrap = enabled,
                        "25" => self.cursor_visible = enabled,
                        _ => {}
                    }
                }
            }
            'S' | 'T' | 'L' | 'M' => self.scrolled = true,
            _ => {}
        }
    }

    fn print(&mut self, text: &str) {
        if text.is_empty() {
            return;
        }
        for cluster in clusters(text) {
            let width = usize::try_from(cluster.cells).unwrap_or(0);
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
            if let Some(row) = self.cells.get_mut(self.line) {
                if let Some(cell) = row.get_mut(self.column) {
                    *cell = cluster.text.to_owned();
                }
                for offset in 1..width {
                    if let Some(cell) = row.get_mut(self.column + offset) {
                        *cell = String::new();
                    }
                }
            }
            self.column += width;
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
        };
        let window = Window::of(&screen);
        (screen, window)
    }

    /// KR-REQ-08.40 and KR-ACC-023: the renderer's corpus, checked against a destination.
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
            let painted = install(&screen, window);

            let mut destination = Destination::new(
                usize::try_from(window.rows).expect("rows"),
                usize::try_from(window.columns).expect("columns"),
            );
            destination.feed(&painted.bytes);

            assert!(
                !destination.overflowed,
                "{id}: no cell was written past the last column"
            );
            assert!(
                !destination.scrolled,
                "{id}: nothing the renderer wrote could scroll the destination"
            );
            assert!(
                destination.autowrap,
                "{id}: the session's own autowrap was put back"
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
                    "{id}: line {index} holds the canonical cells the window shows"
                );
            }

            if let Some(cell) = case.get("cursor_cell") {
                let wanted = cell.as_array().expect("a cursor cell");
                assert_eq!(
                    (destination.line, destination.column),
                    (
                        usize::try_from(wanted[0].as_u64().expect("a line")).expect("a line"),
                        usize::try_from(wanted[1].as_u64().expect("a column")).expect("a column")
                    ),
                    "{id}: the cursor was placed explicitly"
                );
                assert!(destination.cursor_visible, "{id}: the cursor is shown");
            }
            if case
                .get("cursor_hidden")
                .and_then(serde_json::Value::as_bool)
                == Some(true)
            {
                assert!(
                    !destination.cursor_visible,
                    "{id}: a cursor outside the window is hidden rather than misplaced"
                );
            }

            let expect = &case["expect"];
            let comparison = painted.comparison;
            assert_eq!(
                comparison.runs_replaced as u64,
                expect["runs_replaced"].as_u64().expect("runs_replaced"),
                "{id}: runs replaced"
            );
            assert_eq!(
                comparison.clusters_replaced as u64,
                expect["clusters_replaced"]
                    .as_u64()
                    .expect("clusters_replaced"),
                "{id}: clusters replaced"
            );
            assert_eq!(
                comparison.cells_clipped,
                expect["cells_clipped"].as_u64().expect("cells_clipped"),
                "{id}: cells clipped"
            );
            assert_eq!(
                comparison.soft_wraps as u64,
                expect["soft_wraps"].as_u64().expect("soft_wraps"),
                "{id}: soft wraps reported"
            );
            assert_eq!(
                comparison.pending_wrap,
                expect["pending_wrap"].as_bool().expect("pending_wrap"),
                "{id}: the pending wrap"
            );
            assert_eq!(
                comparison.cursor_outside,
                expect["cursor_outside"].as_bool().expect("cursor_outside"),
                "{id}: the cursor's window"
            );
        }
    }

    /// KR-REQ-08.40: a frame turns autowrap off before its first cell, whatever else it does.
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
        for painted in [install(&screen, window), update(&screen, window, &[0])] {
            assert!(
                painted.bytes.starts_with(b"\x1b[?7l"),
                "the first bytes of a frame clear autowrap"
            );
            assert!(
                painted.bytes.windows(5).any(|window| window == b"\x1b[?7h"),
                "and the session's own value is put back"
            );
        }
    }
}
