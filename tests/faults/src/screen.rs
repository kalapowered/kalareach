//! A screen read by position.
//!
//! Two screens built by different paths name their rows differently: a client's terminal numbers
//! the rows it was drawn, the session numbers the rows its application wrote. What a person sees
//! is the same when the same text, in the same renditions, is on the same lines with the cursor in
//! the same cell and the terminal in the same modes. [`View`] is that, and nothing else: every row
//! identifier is dropped and every row is placed by its line.
//!
//! A view is built from a client's projected screen ([`View::of`]) or from a terminal engine's
//! own state ([`View::of_engine`]), which is converted through the same installation the session
//! sends its clients, so both sides of a comparison are read the same way.

use std::collections::BTreeMap;

use kr_client::projection::{ProjectedModeSpelling, Projection, Screen};
use kr_protocol::projection::{
    CellRendition, CharsetState, MarginState, PaletteOverride, ProjectedBuffer, ProjectedCursor,
    ProjectedHyperlink, ProjectedKeyboard, ProjectedTitle, ProjectionResetReason, Rgb,
    SavedCursorState, SavedTitleEntry,
};
use kr_protocol::scalars::{Nullable, U64};
use kr_term::engine::Engine;
use kr_term::snapshot::Viewport;

/// DEC private mode 1048, which saves the cursor when it is set and restores it when it is reset.
///
/// The session records it as a mode; it is an action that leaves nothing a terminal does
/// differently afterwards, and a restoration puts the saved cursor back rather than leaving a
/// terminal in it. So whether it reads as set is not compared: the saved cursor it made is.
pub const CURSOR_SAVE_MODE: u64 = 1048;

/// One run of cells on a line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Run {
    /// The first cell's column.
    pub column: u64,
    /// How many cells it covers.
    pub cells: u64,
    /// Its text.
    pub text: String,
    /// Its rendition.
    pub rendition: CellRendition,
    /// The link it is inside, if any.
    pub hyperlink: Option<ProjectedHyperlink>,
}

/// One line of a buffer.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Line {
    /// Whether it ends in a soft wrap.
    pub soft_wrapped: bool,
    /// Its runs, left to right, as [`normalised`] leaves them: a blank cell in the plain rendition
    /// outside a link is no cell at all, whether the application erased it or never wrote it,
    /// because a person cannot tell the two apart.
    pub runs: Vec<Run>,
}

impl Line {
    /// Its text as a person reads it: each run at its column, trailing blanks dropped.
    #[must_use]
    pub fn text(&self) -> String {
        let mut text = String::new();
        let mut width = 0_u64;
        for run in &self.runs {
            while width < run.column {
                text.push(' ');
                width += 1;
            }
            text.push_str(&run.text);
            width = run.column.saturating_add(run.cells);
        }
        text.trim_end().to_owned()
    }
}

/// The colours a palette sets, without where they came from.
///
/// Where a palette came from is the session's record, not something a terminal shows: a terminal
/// that was drawn the profile's colours explicitly shows exactly what one that started with them
/// shows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Colours {
    /// The foreground, background, cursor, pointer and selection colours, in that order.
    pub named: [Rgb; 7],
    /// The indexed colours that differ from the profile's.
    pub overrides: Vec<PaletteOverride>,
}

/// A screen, by position.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct View {
    /// Which buffer is showing.
    pub active: ProjectedBuffer,
    /// Columns and rows.
    pub dimensions: (u64, u64),
    /// The showing buffer's lines, top to bottom.
    pub lines: Vec<Line>,
    /// The other buffer's lines, top to bottom.
    pub other: Vec<Line>,
    /// The cursor, on a line of the showing buffer.
    pub cursor: ProjectedCursor,
    /// The saved cursors.
    pub saved: Vec<SavedCursorState>,
    /// The scroll region.
    pub margins: MarginState,
    /// The pen.
    pub rendition: CellRendition,
    /// The tab stops.
    pub tab_stops: Vec<u64>,
    /// The character sets.
    pub charsets: CharsetState,
    /// Every tracked mode.
    pub modes: BTreeMap<(ProjectedModeSpelling, u64), bool>,
    /// Whether the keypad is in application mode.
    pub keypad_application: bool,
    /// The keyboard protocol, with Kitty flags nobody set read as the flags `0` a terminal starts
    /// with: a terminal that was told `0` encodes every key exactly as one never told anything.
    pub keyboard: ProjectedKeyboard,
    /// The titles.
    pub title: ProjectedTitle,
    /// The title stack.
    pub title_stack: Vec<SavedTitleEntry>,
    /// The link the next character would be inside.
    pub hyperlink: Option<ProjectedHyperlink>,
    /// The palette's colours.
    pub colours: Colours,
}

/// Which parts of two views a comparison reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Parts {
    /// Everything a view holds: what a projection holds.
    Whole,
    /// Everything but the marks that say a row was wrapped rather than ended: what a terminal holds
    /// that was handed a restoration and then the stream. No sequence marks a row a terminal draws
    /// as wrapped, so a restoration draws a wrapped row as a row of its own and says so, and the
    /// session then keeps that terminal on a projection.
    Terminal,
    /// Which buffer is showing and the rows of both: what any restoration puts into a terminal,
    /// whether or not the session hands it the stream afterwards.
    Buffers,
    /// The showing buffer's lines and the cursor: what a terminal painted from a projection holds.
    /// A painter draws the rows a window shows and places the cursor, and says what it could not
    /// carry, which is read apart.
    Painted,
}

impl View {
    /// The view of a screen a client holds.
    #[must_use]
    pub fn of(screen: &Screen) -> Self {
        let showing = screen.active_buffer;
        let other_buffer = match showing {
            ProjectedBuffer::Primary => ProjectedBuffer::Alternate,
            ProjectedBuffer::Alternate => ProjectedBuffer::Primary,
        };
        let line = |buffer: ProjectedBuffer, row: u64| -> Line {
            screen
                .rows
                .get(&(buffer, row))
                .map_or_else(Line::default, |row| Line {
                    soft_wrapped: row.soft_wrapped,
                    runs: normalised(row.runs.iter().map(|run| Run {
                        column: run.column.get(),
                        cells: run.cells.get(),
                        text: run.text.clone(),
                        rendition: run.rendition,
                        hyperlink: run.hyperlink.as_ref().cloned(),
                    })),
                })
        };
        let lines = screen
            .visible_rows()
            .into_iter()
            .map(|row| line(showing, row))
            .collect();
        // The other buffer keeps no scrollback that anybody is shown, so what it holds is its last
        // page: the rows it would show when it is switched to.
        let height = usize::try_from(screen.dimensions.rows.get()).unwrap_or(usize::MAX);
        let mut held: Vec<u64> = screen
            .rows
            .keys()
            .filter(|(buffer, _)| *buffer == other_buffer)
            .map(|(_, row)| *row)
            .collect();
        held.sort_unstable();
        let first = held.len().saturating_sub(height);
        let other = padded(
            held[first..]
                .iter()
                .map(|row| line(other_buffer, *row))
                .collect(),
            screen.dimensions.rows.get(),
        );
        let palette = &screen.palette;
        Self {
            active: showing,
            dimensions: (
                screen.dimensions.columns.get(),
                screen.dimensions.rows.get(),
            ),
            lines,
            other,
            cursor: screen.cursor,
            saved: screen.saved_cursors.clone(),
            margins: screen.margins,
            rendition: screen.rendition,
            tab_stops: screen.tab_stops.clone(),
            charsets: screen.charsets.clone(),
            modes: screen.modes.clone(),
            keypad_application: screen.keypad_application,
            keyboard: {
                let mut keyboard = screen.keyboard.clone();
                for state in [&mut keyboard.primary, &mut keyboard.alternate] {
                    if !state.flags.is_present() {
                        state.flags = Nullable::some(U64::new(0));
                    }
                }
                keyboard
            },
            title: screen.title.clone(),
            title_stack: screen.title_stack.clone(),
            hyperlink: screen.hyperlink.clone(),
            colours: Colours {
                named: [
                    palette.foreground,
                    palette.background,
                    palette.cursor,
                    palette.pointer_foreground,
                    palette.pointer_background,
                    palette.selection_background,
                    palette.selection_foreground,
                ],
                overrides: palette.overrides.clone(),
            },
        }
    }

    /// The view of what a terminal engine holds on its live screen.
    ///
    /// The engine's state is converted through the installation a session sends a client that
    /// joins it, and read back as that client reads it, so the view says exactly what a client
    /// installed from this engine would hold.
    ///
    /// # Errors
    ///
    /// Returns what the conversion or the installation refused.
    pub fn of_engine(engine: &mut Engine, now_ms: u64) -> Result<Self, String> {
        let size = engine.grid().size();
        let top = engine.grid().visible_top_row();
        let viewport = Viewport {
            top_row: top,
            rows: size.rows,
            left_col: 0,
            cols: size.cols,
        };
        let (snapshot, _) = engine.snapshot_without_rows(viewport, now_ms);
        let update = kr_worker::snapshot::install(
            &snapshot,
            viewport,
            top,
            ProjectionResetReason::Attached,
            0,
            false,
            usize::MAX,
            kr_worker::render::Scope::WholeScreen,
            engine,
        )
        .map_err(|error| format!("the engine's state could not be installed: {error}"))?;
        let mut projection = Projection::new();
        for outgoing in update.events {
            let _ = projection.apply(outgoing.event);
        }
        projection
            .screen()
            .map(Self::of)
            .ok_or_else(|| "the installation did not complete a screen".to_owned())
    }

    /// The same view with the other buffer's lines replaced, padded to the screen's height.
    #[must_use]
    pub fn with_other(mut self, other: Vec<Line>) -> Self {
        self.other = padded(other, self.dimensions.1);
        self
    }

    /// Where `self` differs from `expected` in the parts named, one line each; empty when they
    /// agree.
    #[must_use]
    pub fn differences(&self, expected: &Self, parts: Parts) -> Vec<String> {
        let mut found = Vec::new();
        let marks = parts == Parts::Whole;
        compare_lines("line", &self.lines, &expected.lines, marks, &mut found);
        if parts != Parts::Buffers
            && (self.cursor.row != expected.cursor.row
                || self.cursor.column != expected.cursor.column)
        {
            found.push(format!(
                "cursor at line {} column {}, expected line {} column {}",
                self.cursor.row.get(),
                self.cursor.column.get(),
                expected.cursor.row.get(),
                expected.cursor.column.get()
            ));
        }
        if parts == Parts::Painted {
            return found;
        }
        if self.active != expected.active {
            found.push(format!(
                "showing the {} buffer, expected the {}",
                self.active.as_str(),
                expected.active.as_str()
            ));
        }
        compare_lines(
            "other buffer's line",
            &self.other,
            &expected.other,
            marks,
            &mut found,
        );
        if parts == Parts::Buffers {
            return found;
        }
        if self.dimensions != expected.dimensions {
            found.push(format!(
                "{:?} cells, expected {:?}",
                self.dimensions, expected.dimensions
            ));
        }
        field(
            &mut found,
            "the cursor's visibility",
            &self.cursor.visible,
            &expected.cursor.visible,
        );
        field(
            &mut found,
            "the cursor's style",
            &self.cursor.style,
            &expected.cursor.style,
        );
        field(
            &mut found,
            "the pending wrap",
            &self.cursor.pending_wrap,
            &expected.cursor.pending_wrap,
        );
        field(
            &mut found,
            "the saved cursors",
            &self.saved,
            &expected.saved,
        );
        field(
            &mut found,
            "the scroll region",
            &self.margins,
            &expected.margins,
        );
        field(
            &mut found,
            "the pen",
            &Pen(self.rendition),
            &Pen(expected.rendition),
        );
        field(
            &mut found,
            "the tab stops",
            &self.tab_stops,
            &expected.tab_stops,
        );
        field(
            &mut found,
            "the character sets",
            &self.charsets,
            &expected.charsets,
        );
        field(
            &mut found,
            "the keypad",
            &self.keypad_application,
            &expected.keypad_application,
        );
        field(
            &mut found,
            "the keyboard protocol",
            &self.keyboard,
            &expected.keyboard,
        );
        field(&mut found, "the titles", &self.title, &expected.title);
        field(
            &mut found,
            "the title stack",
            &self.title_stack,
            &expected.title_stack,
        );
        field(
            &mut found,
            "the open link",
            &self.hyperlink,
            &expected.hyperlink,
        );
        field(&mut found, "the palette", &self.colours, &expected.colours);
        for (key, enabled) in &self.modes {
            if key.1 == CURSOR_SAVE_MODE {
                continue;
            }
            if expected.modes.get(key) != Some(enabled) {
                found.push(format!("mode {key:?} is {enabled}, expected otherwise"));
            }
        }
        for key in expected.modes.keys() {
            if key.1 != CURSOR_SAVE_MODE && !self.modes.contains_key(key) {
                found.push(format!("mode {key:?} is not tracked"));
            }
        }
        found
    }
}

/// `lines` with empty lines added at the end until there are `height` of them. A buffer that holds
/// fewer rows than the screen is tall shows the rest as empty.
fn padded(mut lines: Vec<Line>, height: u64) -> Vec<Line> {
    let height = usize::try_from(height).unwrap_or(usize::MAX);
    while lines.len() < height {
        lines.push(Line::default());
    }
    lines
}

/// One cell: a scalar with a width of its own and the zero-width scalars after it.
struct Cell {
    column: u64,
    width: u64,
    text: String,
    rendition: CellRendition,
    hyperlink: Option<ProjectedHyperlink>,
}

/// The cell of `line` that covers `column`: the column it starts at (the one before, for the right
/// half of a wide character), its text with any zero-width scalars after it, its rendition and its
/// link. Nothing for a blank cell in the plain rendition outside a link.
#[must_use]
pub fn cell_at(
    line: &Line,
    column: u64,
) -> Option<(u64, String, CellRendition, Option<ProjectedHyperlink>)> {
    let mut found: Option<Cell> = None;
    for run in &line.runs {
        let mut at = run.column;
        for scalar in run.text.chars() {
            let mut buffer = [0_u8; 4];
            let encoded: &str = scalar.encode_utf8(&mut buffer);
            if kr_term::unicode::is_zero_width(scalar) {
                if let Some(cell) = found.as_mut() {
                    cell.text.push(scalar);
                }
                continue;
            }
            if found.is_some() {
                break;
            }
            let width = u64::try_from(kr_term::unicode::cells_for(encoded)).unwrap_or(1);
            if at <= column && column < at.saturating_add(width) {
                found = Some(Cell {
                    column: at,
                    width,
                    text: scalar.to_string(),
                    rendition: run.rendition,
                    hyperlink: run.hyperlink.clone(),
                });
            }
            at = at.saturating_add(width);
        }
        if found.is_some() {
            break;
        }
    }
    found.map(|cell| (cell.column, cell.text, cell.rendition, cell.hyperlink))
}

/// Runs of cells, rewritten so that two lines a person reads the same way hold the same runs.
///
/// Each run is split into its cells by the profile's own width model; a blank cell in the plain
/// rendition outside a link is dropped, because an erased cell and one never written look the same;
/// and what is left is joined into the longest runs of one rendition and one link.
#[must_use]
pub fn normalised(runs: impl IntoIterator<Item = Run>) -> Vec<Run> {
    let mut cells: Vec<Cell> = Vec::new();
    for run in runs {
        let mut column = run.column;
        for scalar in run.text.chars() {
            let mut buffer = [0_u8; 4];
            let encoded: &str = scalar.encode_utf8(&mut buffer);
            if kr_term::unicode::is_zero_width(scalar) {
                if let Some(last) = cells.last_mut() {
                    last.text.push(scalar);
                }
                continue;
            }
            let width = u64::try_from(kr_term::unicode::cells_for(encoded)).unwrap_or(1);
            cells.push(Cell {
                column,
                width,
                text: scalar.to_string(),
                rendition: run.rendition,
                hyperlink: run.hyperlink.clone(),
            });
            column = column.saturating_add(width);
        }
    }
    let mut joined: Vec<Run> = Vec::new();
    for cell in cells {
        if cell.text == " " && cell.rendition == CellRendition::PLAIN && cell.hyperlink.is_none() {
            continue;
        }
        if let Some(last) = joined.last_mut()
            && last.column.saturating_add(last.cells) == cell.column
            && last.rendition == cell.rendition
            && last.hyperlink == cell.hyperlink
        {
            last.cells = last.cells.saturating_add(cell.width);
            last.text.push_str(&cell.text);
            continue;
        }
        joined.push(Run {
            column: cell.column,
            cells: cell.width,
            text: cell.text,
            rendition: cell.rendition,
            hyperlink: cell.hyperlink,
        });
    }
    joined
}

/// Names one field that differs, with both values.
fn field<T: PartialEq + std::fmt::Debug>(
    found: &mut Vec<String>,
    name: &str,
    got: &T,
    expected: &T,
) {
    if got != expected {
        found.push(format!("{name} is {got:?}, expected {expected:?}"));
    }
}

/// A rendition written as the attributes it sets, and nothing for the plain one.
#[derive(PartialEq)]
struct Pen(CellRendition);

impl std::fmt::Debug for Pen {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let pen = &self.0;
        if *pen == CellRendition::PLAIN {
            return formatter.write_str("plain");
        }
        let plain = CellRendition::PLAIN;
        let mut parts: Vec<String> = Vec::new();
        if pen.foreground != plain.foreground {
            parts.push(format!("fg {:?}", pen.foreground));
        }
        if pen.background != plain.background {
            parts.push(format!("bg {:?}", pen.background));
        }
        if pen.underline_colour != plain.underline_colour {
            parts.push(format!("underline colour {:?}", pen.underline_colour));
        }
        if pen.underline != plain.underline {
            parts.push(format!("{:?}", pen.underline));
        }
        if pen.blink != plain.blink {
            parts.push(format!("{:?}", pen.blink));
        }
        if pen.vertical_align != plain.vertical_align {
            parts.push(format!("{:?}", pen.vertical_align));
        }
        for (set, name) in [
            (pen.bold, "bold"),
            (pen.faint, "faint"),
            (pen.italic, "italic"),
            (pen.reverse, "reverse"),
            (pen.invisible, "invisible"),
            (pen.strikethrough, "struck"),
            (pen.overline, "overline"),
        ] {
            if set {
                parts.push(name.to_owned());
            }
        }
        formatter.write_str(&parts.join(" "))
    }
}

/// A line's runs written compactly: where each starts, what it says and how it is drawn.
fn runs_of(line: &Line) -> String {
    let runs: Vec<String> = line
        .runs
        .iter()
        .map(|run| {
            let link = run
                .hyperlink
                .as_ref()
                .map_or_else(String::new, |link| format!(" link {link:?}"));
            format!(
                "@{} {:?} [{:?}]{link}",
                run.column,
                run.text,
                Pen(run.rendition)
            )
        })
        .collect();
    let wrap = if line.soft_wrapped {
        " (soft wrapped)"
    } else {
        ""
    };
    format!("{}{wrap}", runs.join(", "))
}

fn compare_lines(
    name: &str,
    got: &[Line],
    expected: &[Line],
    marks: bool,
    found: &mut Vec<String>,
) {
    if got.len() != expected.len() {
        found.push(format!(
            "{} {name}s, expected {}",
            got.len(),
            expected.len()
        ));
    }
    for (index, (got, expected)) in got.iter().zip(expected).enumerate() {
        if got.runs == expected.runs && (!marks || got.soft_wrapped == expected.soft_wrapped) {
            continue;
        }
        let (got_text, expected_text) = (got.text(), expected.text());
        if got_text == expected_text {
            found.push(format!(
                "{name} {index} {got_text:?} is drawn {}, expected {}",
                runs_of(got),
                runs_of(expected)
            ));
        } else {
            found.push(format!(
                "{name} {index} is {got_text:?}, expected {expected_text:?}"
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_term::budget::GridSize;
    use kr_term::engine::EngineConfig;

    fn engine(bytes: &[u8]) -> Engine {
        let mut engine = Engine::new(EngineConfig {
            size: GridSize { cols: 12, rows: 3 },
            ..EngineConfig::DEFAULT
        })
        .expect("an engine");
        let _ = engine.feed(bytes, 0);
        engine
    }

    #[test]
    fn two_engines_that_were_sent_the_same_screen_by_different_paths_read_the_same() {
        // One wrote the lines in order; the other drew the same lines by addressing each cell,
        // after a screen of other text it then cleared, so its rows were numbered differently.
        let mut written = engine(b"one\r\n\x1b[1mtwo\x1b[m\r\nthree");
        let mut drawn = engine(
            b"a\r\nb\r\nc\r\nd\r\ne\x1b[2J\x1b[3;1Hthree\x1b[1;1Hone\x1b[2;1H\x1b[1mtwo\x1b[m\x1b[3;6H",
        );
        let written = View::of_engine(&mut written, 0).expect("a view");
        let drawn = View::of_engine(&mut drawn, 0).expect("a view");
        assert_eq!(
            written.differences(&drawn, Parts::Whole),
            Vec::<String>::new()
        );
        assert_eq!(written.lines[1].text(), "two");
    }

    #[test]
    fn a_line_in_another_rendition_or_a_moved_cursor_is_named() {
        let mut plain = engine(b"one\r\ntwo");
        let mut bold = engine(b"one\r\n\x1b[1mtwo\x1b[m\r\n");
        let plain = View::of_engine(&mut plain, 0).expect("a view");
        let bold = View::of_engine(&mut bold, 0).expect("a view");
        let found = bold.differences(&plain, Parts::Painted);
        assert!(
            found
                .iter()
                .any(|line| line.contains("line 1 \"two\" is drawn @0 \"two\" [bold]")),
            "{found:?}"
        );
        assert!(
            found
                .iter()
                .any(|line| line.starts_with("cursor at line 2")),
            "{found:?}"
        );
    }
}
