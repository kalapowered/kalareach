//! The shape the page draws a raw terminal view from.
//!
//! The page is sent cells, never bytes: each line of the view's window as pieces of text, each at
//! the column it is drawn in, with its rendition. Where a piece goes is the client library's
//! renderer's own rule on a desktop, so a canonical cell lands where the CLI's terminal has it; a
//! phone builds the library without the pinned width model the renderer measures with, and places
//! only what needs no measuring. What could not be placed is counted, never guessed at.

use kr_client::projection::{ProjectedModeSpelling, Screen};
use kr_protocol::attachment::AttachmentSummary;
use kr_protocol::projection::{CellRendition, CellRun, PaletteState};
use kr_protocol::scalars::U64;
use kr_protocol::session::Dimensions;
use serde::Serialize;

/// DEC private mode 5, reverse video: the whole screen drawn with foreground and background
/// swapped.
const REVERSE_VIDEO: u64 = 5;

/// What one raw terminal view is, as its page is told.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum TerminalViewState {
    /// Attached, with no complete screen to draw: before the first, or between the host's reset or
    /// resynchronisation and the next.
    Waiting {
        /// The attachment, as the host summarised it when the view attached.
        attachment: AttachmentSummary,
        /// The newest of the page's moves it may take as settled.
        settled: u64,
        /// Whether the view controls the program.
        control: TerminalControl,
    },
    /// Attached, with a complete screen.
    Showing {
        /// The attachment, as the host summarised it when the view attached.
        attachment: AttachmentSummary,
        /// The part of the screen the view shows.
        screen: TerminalScreen,
        /// The newest of the page's moves it may take as settled.
        settled: u64,
        /// Whether the view controls the program.
        control: TerminalControl,
    },
    /// The view has ended, and why, in the host's words or the link's.
    Ended {
        /// Why.
        reason: String,
    },
}

impl TerminalViewState {
    /// The same state, saying `control` of the program. An ended view has no control to say.
    #[must_use]
    pub fn with_control(self, control: TerminalControl) -> Self {
        match self {
            Self::Waiting {
                attachment,
                settled,
                ..
            } => Self::Waiting {
                attachment,
                settled,
                control,
            },
            Self::Showing {
                attachment,
                screen,
                settled,
                ..
            } => Self::Showing {
                attachment,
                screen,
                settled,
                control,
            },
            ended @ Self::Ended { .. } => ended,
        }
    }
}

/// Whether a view controls the program, as the page is told.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TerminalControl {
    /// The page's newest control request the view took, or 0 before the first.
    pub number: u64,
    /// Whether the view watches, is taking control, or controls the program.
    pub state: ControlState,
    /// Why control last ended or was refused, until a newer request.
    pub ended: Option<String>,
}

/// Whether a view watches, is taking control, or controls the program.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlState {
    /// Nothing of the person's reaches the program.
    Watching,
    /// The view asked the session for control and waits for the answer.
    Taking,
    /// The view holds the session's input: the program gets its wheel and its keys.
    Controlling,
}

/// Whether a wheel turn over the screen reaches its program, and why not.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Wheel {
    /// The program reports the mouse in an encoding the view writes.
    Reaches,
    /// The program does not report the mouse.
    Unreported,
    /// The program reports the mouse in an encoding the view does not write.
    Unwritable,
}

/// The part of a session's screen one view shows.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TerminalScreen {
    /// The session's own size.
    pub dimensions: Dimensions,
    /// The window the host drew for this view: its size, and where it starts.
    pub window: Window,
    /// How far the window can still move each way.
    pub room: Room,
    /// Exactly the window's rows, top to bottom.
    pub lines: Vec<TerminalLine>,
    /// The cursor, or nothing when it is outside the window.
    pub cursor: Option<TerminalCursor>,
    /// The session's palette, with where it came from.
    pub palette: PaletteState,
    /// Whether the session had to shorten content to stay inside a bound.
    pub degraded: bool,
    /// How many runs and clusters could not be placed, and are blank or left out.
    pub replaced: u64,
    /// Whether a wheel turn over the screen reaches the program.
    pub wheel: Wheel,
}

/// The window the host drew for a view: its size in cells, and where it starts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Window {
    /// How many rows it shows.
    pub rows: u32,
    /// How many columns it shows.
    pub columns: u32,
    /// The first canonical column it shows.
    pub column: u64,
    /// The line of the live screen it starts at; 0 in the history.
    pub line: u64,
    /// How many rows above the live screen's first line it starts; 0 on the live screen.
    pub above: u64,
}

/// How many cells a window can still move each way before it reaches a limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Room {
    /// Rows up, back into the history.
    pub up: u64,
    /// Rows down, as far as the live screen's last line that still fills the window.
    pub down: u64,
    /// Columns to the left.
    pub left: u64,
    /// Columns to the right, as far as the last that still fills the window.
    pub right: u64,
}

/// One line of the window.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TerminalLine {
    /// The row's stable identifier in the session.
    pub row: U64,
    /// Whether the row ends in a soft wrap.
    pub soft_wrapped: bool,
    /// Whether the session left runs out of the row to keep it inside a page's bound.
    pub truncated: bool,
    /// What is drawn on it, left to right. A cell no piece covers is blank.
    pub pieces: Vec<TerminalPiece>,
}

/// Text drawn at one column of a line.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TerminalPiece {
    /// The column, in the window, of the piece's first cell.
    pub column: u32,
    /// How many cells it covers. The text never draws past them.
    pub cells: u32,
    /// The text, with no control character in it.
    pub text: String,
    /// How it is drawn, with the screen's reverse video already applied.
    pub rendition: CellRendition,
    /// The link it is inside, as inert metadata.
    pub hyperlink: Option<String>,
}

/// The cursor, in the window's coordinates.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct TerminalCursor {
    /// Its column in the window.
    pub column: u32,
    /// Its line in the window.
    pub line: u32,
    /// Whether it is shown.
    pub visible: bool,
    /// The cursor-style number the session set.
    pub style: u32,
}

/// One piece of a run, at the canonical column it is drawn in.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Piece {
    text: String,
    column: u64,
    cells: u64,
}

/// Where one run's pieces go, and how many of its runs and clusters could not go anywhere.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Placement {
    pieces: Vec<Piece>,
    replaced: u64,
}

/// The part of `screen` its window shows, as the page draws it.
#[must_use]
pub fn of(screen: &Screen) -> TerminalScreen {
    let top = screen.viewport.top_row.get();
    let rows = u32::try_from(screen.viewport.rows.get()).unwrap_or(u32::MAX);
    let left = screen.viewport.left_column.get();
    let columns = u32::try_from(screen.viewport.columns.get()).unwrap_or(u32::MAX);
    let reverse_video = screen.mode(ProjectedModeSpelling::Dec, REVERSE_VIDEO);
    let mut replaced = 0_u64;
    let lines = (0..rows)
        .map(|offset| {
            let id = top.saturating_add(u64::from(offset));
            let mut line = TerminalLine {
                row: U64::new(id),
                soft_wrapped: false,
                truncated: false,
                pieces: Vec::new(),
            };
            if let Some(row) = screen.row(id) {
                line.soft_wrapped = row.soft_wrapped;
                line.truncated = row.truncated;
                for run in &row.runs {
                    let placement = place(run, left, columns);
                    replaced = replaced.saturating_add(placement.replaced);
                    let mut rendition = run.rendition;
                    rendition.reverse ^= reverse_video;
                    for piece in placement.pieces {
                        line.pieces.push(TerminalPiece {
                            column: u32::try_from(piece.column.saturating_sub(left))
                                .unwrap_or(u32::MAX),
                            cells: u32::try_from(piece.cells).unwrap_or(u32::MAX),
                            text: piece.text,
                            rendition,
                            hyperlink: run.hyperlink.0.clone(),
                        });
                    }
                }
            }
            line.pieces = joined(std::mem::take(&mut line.pieces));
            if reverse_video {
                line.pieces = reversed_blanks(std::mem::take(&mut line.pieces), columns);
            }
            line
        })
        .collect();
    let (window, room) = placed(screen, top, rows, left, columns);
    TerminalScreen {
        dimensions: screen.dimensions,
        window,
        room,
        lines,
        cursor: cursor(screen, top, rows, left, columns),
        palette: screen.palette.clone(),
        degraded: screen.degraded,
        replaced,
        wheel: super::input::wheel_of(screen),
    }
}

/// Where a window of `rows` by `columns` starting at row `top` and column `left` is on `screen`, and
/// how far it can still move: up to the oldest row the session keeps, down to the live screen's
/// last line that still fills the window, and across to the last column that still fills it.
fn placed(screen: &Screen, top: u64, rows: u32, left: u64, columns: u32) -> (Window, Room) {
    let live_top = screen.viewport.screen_top_row.get();
    let (line, above) = if top >= live_top {
        (top - live_top, 0)
    } else {
        (0, live_top - top)
    };
    let canonical_rows = screen.dimensions.rows.get();
    let canonical_columns = screen.dimensions.columns.get();
    let last_top =
        live_top.saturating_add(canonical_rows.saturating_sub(u64::from(rows).min(canonical_rows)));
    let last_column = canonical_columns.saturating_sub(u64::from(columns).min(canonical_columns));
    (
        Window {
            rows,
            columns,
            column: left,
            line,
            above,
        },
        Room {
            up: top.saturating_sub(screen.oldest_retained_row),
            down: last_top.saturating_sub(top),
            left,
            right: last_column.saturating_sub(left),
        },
    )
}

/// Places one run: the client library's renderer's own rule, and its control filter.
///
/// It is the same code on every platform, a phone's included, because the width model it measures
/// with builds for all of them.
fn place(run: &CellRun, left: u64, columns: u32) -> Placement {
    use kr_client::projection::paint;

    let placed = paint::place(
        run,
        paint::Window {
            top_row: 0,
            left_column: left,
            rows: 1,
            columns,
        },
    );
    Placement {
        replaced: u64::from(placed.run_replaced)
            .saturating_add(u64::try_from(placed.clusters_replaced).unwrap_or(u64::MAX)),
        pieces: placed
            .pieces
            .into_iter()
            .map(|piece| Piece {
                text: paint::drawable(&piece.text).collect(),
                column: piece.column,
                cells: piece.cells,
            })
            .collect(),
    }
}

/// Whether a piece is one cell of plain ASCII, which a renderer advances over exactly.
fn single_ascii(piece: &TerminalPiece) -> bool {
    piece.cells == 1 && piece.text.len() == 1 && piece.text.is_ascii()
}

/// Joins neighbouring pieces of plain ASCII that are drawn alike into one, so a line of ordinary
/// text is one piece rather than one per cell. Only pieces that were each one cell of plain ASCII
/// are joined: every other piece keeps the column it was placed at, whole.
fn joined(pieces: Vec<TerminalPiece>) -> Vec<TerminalPiece> {
    let mut out: Vec<(TerminalPiece, bool)> = Vec::with_capacity(pieces.len());
    for piece in pieces {
        let joinable = single_ascii(&piece);
        if joinable
            && let Some((last, true)) = out.last_mut()
            && last.column.saturating_add(last.cells) == piece.column
            && last.rendition == piece.rendition
            && last.hyperlink == piece.hyperlink
        {
            last.text.push_str(&piece.text);
            last.cells = last.cells.saturating_add(1);
            continue;
        }
        out.push((piece, joinable));
    }
    out.into_iter().map(|(piece, _)| piece).collect()
}

/// Under reverse video the whole screen is drawn reversed, the cells no run covers included, as
/// the pinned terminal library's renderer draws them: each such span becomes a blank reversed
/// piece.
fn reversed_blanks(pieces: Vec<TerminalPiece>, columns: u32) -> Vec<TerminalPiece> {
    let blank = |column: u32, cells: u32| TerminalPiece {
        column,
        cells,
        text: " ".repeat(usize::try_from(cells).unwrap_or(0)),
        rendition: CellRendition {
            reverse: true,
            ..CellRendition::PLAIN
        },
        hyperlink: None,
    };
    let mut covered: Vec<(u32, u32)> = pieces
        .iter()
        .map(|piece| (piece.column, piece.column.saturating_add(piece.cells)))
        .collect();
    covered.sort_unstable();
    let mut out = pieces;
    let mut at = 0_u32;
    for (from, to) in covered {
        if from > at {
            out.push(blank(at, from - at));
        }
        at = at.max(to);
    }
    if at < columns {
        out.push(blank(at, columns - at));
    }
    out.sort_by_key(|piece| piece.column);
    out
}

/// The cursor in the window's coordinates, or nothing when the window does not show its cell.
///
/// The cursor's row is a line of the live screen, whose first row the viewport carries apart from
/// the window's own first row, as the renderer reads it.
fn cursor(screen: &Screen, top: u64, rows: u32, left: u64, columns: u32) -> Option<TerminalCursor> {
    let stable = screen
        .viewport
        .screen_top_row
        .get()
        .saturating_add(screen.cursor.row.get());
    let line = stable
        .checked_sub(top)
        .filter(|line| *line < u64::from(rows))?;
    let column = screen
        .cursor
        .column
        .get()
        .checked_sub(left)
        .filter(|column| *column < u64::from(columns))?;
    Some(TerminalCursor {
        column: u32::try_from(column).ok()?,
        line: u32::try_from(line).ok()?,
        visible: screen.cursor.visible,
        style: u32::try_from(screen.cursor.style.get()).unwrap_or(0),
    })
}

/// The state a view is in while it holds `screen`, or waits for one, with the newest of the page's
/// moves it may take as settled and whether it controls the program.
pub(crate) fn state_of(
    attachment: &AttachmentSummary,
    screen: Option<&Screen>,
    settled: u64,
    control: TerminalControl,
) -> TerminalViewState {
    match screen {
        Some(screen) => TerminalViewState::Showing {
            attachment: attachment.clone(),
            screen: of(screen),
            settled,
            control,
        },
        None => TerminalViewState::Waiting {
            attachment: attachment.clone(),
            settled,
            control,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::scalars::Nullable;

    fn run(column: u64, cells: u64, text: &str) -> CellRun {
        CellRun {
            column: U64::new(column),
            cells: U64::new(cells),
            text: text.to_owned(),
            rendition: CellRendition::PLAIN,
            hyperlink: Nullable::null(),
        }
    }

    fn piece(column: u32, cells: u32, text: &str) -> TerminalPiece {
        TerminalPiece {
            column,
            cells,
            text: text.to_owned(),
            rendition: CellRendition::PLAIN,
            hyperlink: None,
        }
    }

    fn texts(placement: &Placement) -> Vec<(&str, u64, u64)> {
        placement
            .pieces
            .iter()
            .map(|piece| (piece.text.as_str(), piece.column, piece.cells))
            .collect()
    }

    /// KR-REQ-13.08: a run of mixed widths is placed at each cluster's own column, on every
    /// platform: the width model this measures with is the one the terminal engine measures with,
    /// so a phone's placement is a desktop's cell for cell.
    #[test]
    fn a_run_of_mixed_widths_places_each_cluster_at_its_own_column() {
        // ASCII, a wide pair, a combining mark, a wide emoji, then ASCII: 1 + 4 + 1 + 2 + 1 cells.
        let mixed = run(3, 9, "a\u{4e2d}\u{6587}e\u{301}\u{1f600}b");
        let placed = place(&mixed, 0, 40);
        assert_eq!(placed.replaced, 0);
        assert_eq!(
            texts(&placed),
            vec![
                ("a", 3, 1),
                ("\u{4e2d}", 4, 2),
                ("\u{6587}", 6, 2),
                ("e\u{301}", 8, 1),
                ("\u{1f600}", 9, 2),
                ("b", 11, 1),
            ]
        );
        // The window's edge cuts a wide cluster whole rather than half drawing it.
        let clipped = place(&mixed, 5, 4);
        assert!(
            clipped
                .pieces
                .iter()
                .all(|piece| piece.column >= 5 && piece.column + piece.cells <= 9),
            "{clipped:?}"
        );
    }

    /// Control: a run of printable ASCII is placed one cell to a piece, as a desktop always did,
    /// and clipped to the window.
    #[test]
    fn a_run_of_plain_ascii_is_placed_and_clipped() {
        let placed = place(&run(2, 5, "hello"), 0, 20);
        assert_eq!(
            texts(&placed),
            vec![
                ("h", 2, 1),
                ("e", 3, 1),
                ("l", 4, 1),
                ("l", 5, 1),
                ("o", 6, 1)
            ]
        );
        assert_eq!(placed.replaced, 0);
        let clipped = place(&run(2, 5, "hello"), 3, 3);
        assert_eq!(texts(&clipped), vec![("e", 3, 1), ("l", 4, 1), ("l", 5, 1)]);
        assert_eq!(
            place(&run(30, 2, "ab"), 0, 20),
            Placement::default(),
            "outside"
        );
    }

    /// Neighbouring single cells of plain ASCII drawn alike become one piece; a blank run keeps
    /// its own piece, and so does anything drawn differently.
    #[test]
    fn neighbouring_ascii_cells_join_and_nothing_else_does() {
        let mut bold = piece(4, 1, "d");
        bold.rendition.bold = true;
        let joined = joined(vec![
            piece(0, 1, "a"),
            piece(1, 1, "b"),
            piece(2, 1, "c"),
            piece(3, 2, "\u{4e2d}"),
            bold,
            piece(5, 3, "   "),
            piece(8, 1, "e"),
        ]);
        let shown: Vec<(u32, u32, &str)> = joined
            .iter()
            .map(|piece| (piece.column, piece.cells, piece.text.as_str()))
            .collect();
        assert_eq!(
            shown,
            vec![
                (0, 3, "abc"),
                (3, 2, "\u{4e2d}"),
                (4, 1, "d"),
                (5, 3, "   "),
                (8, 1, "e"),
            ]
        );
    }

    /// Under reverse video every cell no piece covers is a blank reversed piece.
    #[test]
    fn reverse_video_draws_the_uncovered_cells_reversed() {
        let pieces = reversed_blanks(vec![piece(2, 3, "abc"), piece(7, 1, "d")], 10);
        let shown: Vec<(u32, u32, &str, bool)> = pieces
            .iter()
            .map(|piece| {
                (
                    piece.column,
                    piece.cells,
                    piece.text.as_str(),
                    piece.rendition.reverse,
                )
            })
            .collect();
        assert_eq!(
            shown,
            vec![
                (0, 2, "  ", true),
                (2, 3, "abc", false),
                (5, 2, "  ", true),
                (7, 1, "d", false),
                (8, 2, "  ", true),
            ]
        );
    }
}
