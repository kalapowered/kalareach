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
    },
    /// Attached, with a complete screen.
    Showing {
        /// The attachment, as the host summarised it when the view attached.
        attachment: AttachmentSummary,
        /// The part of the screen the view shows.
        screen: TerminalScreen,
    },
    /// The view has ended, and why, in the host's words or the link's.
    Ended {
        /// Why.
        reason: String,
    },
}

/// The part of a session's screen one view shows.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TerminalScreen {
    /// The session's own size.
    pub dimensions: Dimensions,
    /// The size of the window the host drew for this view, from the live screen's top left.
    pub window: WindowSize,
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
}

/// A window's size, in cells.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct WindowSize {
    /// How many rows it shows.
    pub rows: u32,
    /// How many columns it shows.
    pub columns: u32,
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
    TerminalScreen {
        dimensions: screen.dimensions,
        window: WindowSize { rows, columns },
        lines,
        cursor: cursor(screen, top, rows, left, columns),
        palette: screen.palette.clone(),
        degraded: screen.degraded,
        replaced,
    }
}

/// Places one run on a desktop: the client library's renderer's own rule, and its control filter.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
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

/// Places one run on a phone, which has no pinned width model to measure text with.
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn place(run: &CellRun, left: u64, columns: u32) -> Placement {
    plain(run, left, columns)
}

/// Places a run with no width model at all.
///
/// Printable ASCII is the one text whose width every destination agrees about: a scalar each, a
/// cell each. A run that is only that, and whose cells are its scalars, is placed; any other run is
/// blank across its cells, and counted, rather than drawn at a width nobody measured.
#[cfg_attr(
    any(target_os = "linux", target_os = "macos", target_os = "windows"),
    allow(
        dead_code,
        reason = "the desktop's placement measures; this rule is the phones'"
    )
)]
fn plain(run: &CellRun, left: u64, columns: u32) -> Placement {
    let start = run.column.get();
    let cells = run.cells.get();
    let end = start.saturating_add(cells);
    let right = left.saturating_add(u64::from(columns));
    if end <= left || start >= right {
        return Placement::default();
    }
    let from = start.max(left);
    let to = end.min(right);
    let inside = to.saturating_sub(from);
    let ascii = run
        .text
        .bytes()
        .all(|byte| byte.is_ascii_graphic() || byte == b' ')
        && u64::try_from(run.text.len()).is_ok_and(|length| length == cells);
    if ascii {
        let skip = usize::try_from(from.saturating_sub(start)).unwrap_or(usize::MAX);
        let take = usize::try_from(inside).unwrap_or(usize::MAX);
        return Placement {
            pieces: vec![Piece {
                text: run.text.chars().skip(skip).take(take).collect(),
                column: from,
                cells: inside,
            }],
            replaced: 0,
        };
    }
    Placement {
        pieces: vec![Piece {
            text: " ".repeat(usize::try_from(inside).unwrap_or(0)),
            column: from,
            cells: inside,
        }],
        replaced: 1,
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

/// The state a view is in while it holds `screen`, or waits for one.
pub(crate) fn state_of(
    attachment: &AttachmentSummary,
    screen: Option<&Screen>,
) -> TerminalViewState {
    match screen {
        Some(screen) => TerminalViewState::Showing {
            attachment: attachment.clone(),
            screen: of(screen),
        },
        None => TerminalViewState::Waiting {
            attachment: attachment.clone(),
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

    /// KR-REQ-13.08: a phone, which has no width model to measure with, places a run of printable
    /// ASCII whose cells are its scalars, clipped to the window.
    #[test]
    fn a_phone_places_a_run_of_plain_ascii() {
        let placed = plain(&run(2, 5, "hello"), 0, 20);
        assert_eq!(texts(&placed), vec![("hello", 2, 5)]);
        assert_eq!(placed.replaced, 0);
        let clipped = plain(&run(2, 5, "hello"), 3, 3);
        assert_eq!(texts(&clipped), vec![("ell", 3, 3)]);
    }

    /// Any other run is blank across its cells on a phone, and counted, rather than drawn at a
    /// width nobody measured.
    #[test]
    fn a_phone_leaves_any_other_run_blank_and_counts_it() {
        for text in ["h\u{e9}llo", "\u{4e2d}\u{6587}x", "a\u{7}bcd", "ab"] {
            let placed = plain(&run(1, 5, text), 0, 20);
            assert_eq!(texts(&placed), vec![("     ", 1, 5)], "{text:?}");
            assert_eq!(placed.replaced, 1, "{text:?}");
        }
        assert_eq!(
            plain(&run(30, 2, "ab"), 0, 20),
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
