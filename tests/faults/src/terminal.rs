//! A model of a person's physical terminal: what one of the xterm family shows after it is sent
//! some bytes, and every side effect it performs.
//!
//! It is one terminal: one engine of the profile, whose two buffers share one cursor, one pen, one
//! set of modes, one title and one palette, as a terminal of the xterm family keeps them. The
//! profile does not include DEC mode 47 (section 8 lists the modes it does, and the engine consumes
//! a request for one it does not), and a restoration is written for the profile, so it never asks for
//! it. A terminal of the xterm family does switch with it, so the model reads the two mode-47
//! switches itself and hands the engine what the pinned terminal library does for each, which draws a
//! restoration that did ask for one as such a terminal would; the restoration checks name it:
//!
//! | Sequence | What the library does | What the engine is handed |
//! | --- | --- | --- |
//! | `CSI ? 47 h` | shows the alternate buffer with the plain pen; clears nothing; the cursor stays | `CSI ? 1047 h`, which the library handles with the same code |
//! | `CSI ? 47 l` | shows the primary buffer with the plain pen; clears nothing; the cursor stays | `CSI ? 1049 l`, which shows the primary buffer and clears nothing either, and then what the cursor restore that comes with it changed, put back |
//!
//! `CSI ? 1049 l` restores the primary buffer's saved cursor: its position, its pending wrap, its
//! pen, origin mode, character sets and shape, and it turns shift-out and new-line mode off. The
//! model reads each of those before the switch and sets it again after: the plain pen, the shape,
//! new-line mode, origin mode, the position, a pending wrap (by writing the cell under the cursor
//! again, which leaves the cell as it was), the character sets and shift-out. The saved cursors
//! are left alone, as a mode-47 switch leaves them. Everything else, modes 1047 and 1049 and a full
//! reset included, goes to the engine as it came.

use kr_protocol::projection::CellVerticalAlign;
use kr_protocol::projection::{CellBlink, CellColour, CellRendition, CellUnderline};
use kr_term::budget::GridSize;
use kr_term::engine::{Engine, EngineConfig};
use kr_term::modes::ModeKind;
use kr_term::sideeffect::SideEffectKind;

use crate::screen::{View, cell_at};

/// The switch to the alternate buffer that clears nothing.
const SHOW_ALTERNATE: &[u8] = b"\x1b[?47h";
/// The switch back to the primary buffer that clears nothing.
const SHOW_PRIMARY: &[u8] = b"\x1b[?47l";

/// What one feed made the terminal do.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Performed {
    /// The side effects, in order.
    pub effects: Vec<SideEffectKind>,
    /// Side effects it refused, as a person would name them, and anything the model could not do.
    pub refused: Vec<String>,
    /// How many questions it answered.
    pub replies: usize,
}

/// A terminal of the xterm family, modelled on the profile's engine.
pub struct Terminal {
    engine: Engine,
    /// The start of a mode-47 switch the last feed ended inside, held until the rest arrives.
    held: Vec<u8>,
}

impl std::fmt::Debug for Terminal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Terminal")
            .field("alternate", &self.engine.grid().alternate_active())
            .finish_non_exhaustive()
    }
}

/// What a `CSI ? 1049 l` restores of the cursor, read before the switch so it can be put back.
struct Cursor {
    column: u32,
    row: u32,
    pending_wrap: bool,
    origin: bool,
    charsets: (String, String),
    shift_out: bool,
    style: u64,
    new_line: bool,
    insert: bool,
}

impl Terminal {
    /// A terminal of `columns` by `rows` that has been sent nothing.
    ///
    /// # Errors
    ///
    /// Returns what the engine refused about the size.
    pub fn new(columns: u16, rows: u16) -> Result<Self, String> {
        let engine = Engine::new(EngineConfig {
            size: GridSize {
                cols: u32::from(columns),
                rows: u32::from(rows),
            },
            ..EngineConfig::DEFAULT
        })
        .map_err(|error| format!("a terminal of {columns}x{rows}: {error}"))?;
        Ok(Self {
            engine,
            held: Vec::new(),
        })
    }

    /// Sends the terminal `bytes`, and says what it did.
    pub fn feed(&mut self, bytes: &[u8]) -> Performed {
        let mut input = std::mem::take(&mut self.held);
        input.extend_from_slice(bytes);
        let mut performed = Performed::default();
        let mut start = 0;
        let mut at = 0;
        while at < input.len() {
            if input[at] != 0x1b {
                at += 1;
                continue;
            }
            let rest = &input[at..];
            if rest.starts_with(SHOW_ALTERNATE) || rest.starts_with(SHOW_PRIMARY) {
                self.send(&input[start..at], &mut performed);
                if rest.starts_with(SHOW_ALTERNATE) {
                    self.send(b"\x1b[?1047h", &mut performed);
                } else {
                    self.show_primary(&mut performed);
                }
                at += SHOW_ALTERNATE.len();
                start = at;
                continue;
            }
            if SHOW_ALTERNATE.starts_with(rest) || SHOW_PRIMARY.starts_with(rest) {
                // The feed ends part way into what may be a switch: the rest decides.
                self.send(&input[start..at], &mut performed);
                self.held = rest.to_vec();
                return performed;
            }
            at += 1;
        }
        self.send(&input[start..], &mut performed);
        performed
    }

    fn send(&mut self, bytes: &[u8], performed: &mut Performed) {
        if bytes.is_empty() {
            return;
        }
        let outcome = self.engine.feed(bytes, 0);
        let settled = self.engine.quiesce(0);
        for outcome in [outcome, settled] {
            performed
                .effects
                .extend(outcome.side_effects.into_iter().map(|effect| effect.kind));
            performed.refused.extend(
                outcome
                    .refusals
                    .iter()
                    .map(|refusal| format!("a refused side effect ({refusal:?})")),
            );
            performed.replies += outcome.responses;
        }
    }

    /// `CSI ? 47 l`: the primary buffer shown, nothing cleared, the cursor where it was.
    fn show_primary(&mut self, performed: &mut Performed) {
        if !self.engine.grid().alternate_active() {
            return;
        }
        let before = match self.cursor() {
            Ok(before) => before,
            Err(error) => {
                performed.refused.push(error);
                return;
            }
        };
        self.send(b"\x1b[?1049l", performed);
        match self.put_back(&before) {
            Ok(repair) => self.send(&repair, performed),
            Err(error) => performed.refused.push(error),
        }
    }

    fn cursor(&mut self) -> Result<Cursor, String> {
        let style = View::of_engine(&mut self.engine, 0)?.cursor.style.get();
        let grid = self.engine.grid();
        let (column, row) = grid.cursor();
        Ok(Cursor {
            column,
            row,
            pending_wrap: grid.pending_wrap(),
            origin: grid.origin_mode(),
            charsets: grid.charsets(),
            shift_out: grid.shift_out(),
            style,
            new_line: self.engine.modes().is_set(ModeKind::Ansi, 20),
            insert: grid.insert_mode(),
        })
    }

    /// The bytes that put back what `CSI ? 1049 l` restored of the cursor, leaving the plain pen as
    /// a mode-47 switch does.
    fn put_back(&mut self, before: &Cursor) -> Result<Vec<u8>, String> {
        let mut repair = b"\x1b[0m".to_vec();
        if self.engine.grid().pen_hyperlink().is_some() {
            repair.extend_from_slice(b"\x1b]8;;\x1b\\");
        }
        repair.extend_from_slice(format!("\x1b[{} q", before.style).as_bytes());
        if before.new_line {
            repair.extend_from_slice(b"\x1b[20h");
        }
        if self.engine.grid().origin_mode() != before.origin {
            repair.extend_from_slice(if before.origin {
                b"\x1b[?6h"
            } else {
                b"\x1b[?6l"
            });
        }
        let grid = self.engine.grid();
        let (top, _) = grid.margins_vertical();
        let (left, _) = grid.margins_horizontal();
        let margins = grid.margin_mode();
        let place = |column: u32| -> Vec<u8> {
            let (row, column) = if before.origin {
                (
                    before.row.saturating_sub(top),
                    if margins {
                        column.saturating_sub(left)
                    } else {
                        column
                    },
                )
            } else {
                (before.row, column)
            };
            format!("\x1b[{};{}H", row + 1, column + 1).into_bytes()
        };
        if before.pending_wrap {
            // Only a character written in the last cell leaves a wrap pending. The cell under the
            // cursor is written again as it is, in the primary buffer that now shows, so the cell
            // stays what it was and the wrap is pending again.
            let view = View::of_engine(&mut self.engine, 0)?;
            let line = view
                .lines
                .get(before.row as usize)
                .ok_or_else(|| format!("the terminal model has no row {}", before.row))?;
            let (column, text, rendition, link) = cell_at(line, u64::from(before.column))
                .unwrap_or_else(|| {
                    (
                        u64::from(before.column),
                        " ".to_owned(),
                        CellRendition::PLAIN,
                        None,
                    )
                });
            if before.insert {
                repair.extend_from_slice(b"\x1b[4l");
            }
            // Written through the ASCII set, so the text is what lands.
            repair.extend_from_slice(b"\x1b(B\x0f");
            repair.extend_from_slice(&place(u32::try_from(column).unwrap_or(before.column)));
            repair.extend_from_slice(&sgr(rendition));
            if let Some(link) = link.as_ref() {
                repair.extend_from_slice(
                    format!("\x1b]8;{};{}\x1b\\", link.params, link.uri).as_bytes(),
                );
            }
            repair.extend_from_slice(text.as_bytes());
            repair.extend_from_slice(b"\x1b[0m");
            if link.is_some() {
                repair.extend_from_slice(b"\x1b]8;;\x1b\\");
            }
            if before.insert {
                repair.extend_from_slice(b"\x1b[4h");
            }
        } else {
            repair.extend_from_slice(&place(before.column));
        }
        repair.extend_from_slice(&designation(b'(', &before.charsets.0)?);
        repair.extend_from_slice(&designation(b')', &before.charsets.1)?);
        repair.push(if before.shift_out { 0x0e } else { 0x0f });
        Ok(repair)
    }

    /// What the terminal shows, and holds in the buffer that is not showing.
    ///
    /// # Errors
    ///
    /// Returns what reading the engine refused.
    pub fn view(&mut self) -> Result<View, String> {
        View::of_engine(&mut self.engine, 0)
    }
}

/// The sequence that designates the character set the library names `name` into G0 (`(`) or G1
/// (`)`).
fn designation(set: u8, name: &str) -> Result<Vec<u8>, String> {
    let last = match name {
        "Ascii" => b'B',
        "Uk" => b'A',
        "DecLineDrawing" => b'0',
        other => return Err(format!("the terminal model knows no character set {other}")),
    };
    Ok(vec![0x1b, set, last])
}

/// The SGR sequence that sets `rendition` from the plain one.
fn sgr(rendition: CellRendition) -> Vec<u8> {
    let mut parameters: Vec<String> = vec!["0".to_owned()];
    for (set, parameter) in [
        (rendition.bold, "1"),
        (rendition.faint, "2"),
        (rendition.italic, "3"),
    ] {
        if set {
            parameters.push(parameter.to_owned());
        }
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
    for (set, parameter) in [
        (rendition.reverse, "7"),
        (rendition.invisible, "8"),
        (rendition.strikethrough, "9"),
        (rendition.overline, "53"),
    ] {
        if set {
            parameters.push(parameter.to_owned());
        }
    }
    match rendition.vertical_align {
        CellVerticalAlign::Baseline => {}
        CellVerticalAlign::Superscript => parameters.push("73".to_owned()),
        CellVerticalAlign::Subscript => parameters.push("74".to_owned()),
    }
    parameters.extend(colour(rendition.foreground, 30, 90, 38));
    parameters.extend(colour(rendition.background, 40, 100, 48));
    match rendition.underline_colour {
        CellColour::Default => {}
        CellColour::Indexed(index) => parameters.push(format!("58:5:{index}")),
        CellColour::Direct(rgb) => {
            parameters.push(format!("58:2::{}:{}:{}", rgb.red, rgb.green, rgb.blue));
        }
    }
    format!("\x1b[{}m", parameters.join(";")).into_bytes()
}

fn colour(colour: CellColour, base: u16, bright: u16, extended: u16) -> Option<String> {
    match colour {
        CellColour::Default => None,
        CellColour::Indexed(index) if index < 8 => Some((base + u16::from(index)).to_string()),
        CellColour::Indexed(index) if index < 16 => {
            Some((bright + u16::from(index - 8)).to_string())
        }
        CellColour::Indexed(index) => Some(format!("{extended}:5:{index}")),
        CellColour::Direct(rgb) => Some(format!(
            "{extended}:2::{}:{}:{}",
            rgb.red, rgb.green, rgb.blue
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_client::projection::ProjectedModeSpelling;
    use kr_protocol::projection::ProjectedBuffer;

    fn text(lines: &[crate::screen::Line]) -> Vec<String> {
        lines.iter().map(crate::screen::Line::text).collect()
    }

    fn fed(columns: u16, rows: u16, bytes: &[u8]) -> (Terminal, View) {
        let mut terminal = Terminal::new(columns, rows).expect("a terminal");
        let performed = terminal.feed(bytes);
        assert!(performed.refused.is_empty(), "{:?}", performed.refused);
        let view = terminal.view().expect("a view");
        (terminal, view)
    }

    #[test]
    fn mode_47_switches_without_clearing_and_1049_clears_the_alternate_buffer_on_entry() {
        let (mut terminal, view) = fed(12, 3, b"primary\x1b[?47h\x1b[Halternate\x1b[?47l");
        assert_eq!(view.active, ProjectedBuffer::Primary);
        assert_eq!(text(&view.lines)[0], "primary");
        assert_eq!(text(&view.other)[0], "alternate");
        let _ = terminal.feed(b"\x1b[?1049h");
        let view = terminal.view().expect("a view");
        assert_eq!(view.active, ProjectedBuffer::Alternate);
        assert_eq!(
            text(&view.lines)[0],
            "",
            "entering 1049 clears the alternate buffer"
        );
        assert_eq!(text(&view.other)[0], "primary");
    }

    #[test]
    fn a_switch_split_across_two_feeds_is_read_whole() {
        let mut terminal = Terminal::new(12, 3).expect("a terminal");
        let _ = terminal.feed(b"shell\x1b[?4");
        let _ = terminal.feed(b"7h\x1b[Happ");
        let view = terminal.view().expect("a view");
        assert_eq!(view.active, ProjectedBuffer::Alternate);
        assert_eq!(text(&view.lines)[0], "app");
        assert_eq!(text(&view.other)[0], "shell");
    }

    #[test]
    fn the_cursor_stays_where_it_was_through_both_mode_47_switches() {
        let (mut terminal, view) = fed(12, 3, b"ab\x1b[?47hX");
        assert_eq!(text(&view.lines)[0], "  X", "X lands where the cursor was");
        assert_eq!(view.cursor.column.get(), 3);
        let _ = terminal.feed(b"\x1b[?47lY");
        let view = terminal.view().expect("a view");
        assert_eq!(text(&view.lines)[0], "ab Y");
        assert_eq!(view.cursor.column.get(), 4);
    }

    #[test]
    fn titles_modes_and_the_palette_are_the_one_terminals_on_both_buffers() {
        let (mut terminal, before) = fed(
            12,
            3,
            b"\x1b]2;one\x1b\\\x1b[?7l\x1b]4;1;rgb:12/34/56\x1b\\\x1b[?2004h\x1b[?47h",
        );
        assert_eq!(before.active, ProjectedBuffer::Alternate);
        let autowrap = (ProjectedModeSpelling::Dec, 7);
        assert_eq!(before.modes.get(&autowrap), Some(&false));
        let _ = terminal.feed(b"\x1b]2;two\x1b\\\x1b[?47l");
        let after = terminal.view().expect("a view");
        assert_eq!(after.active, ProjectedBuffer::Primary);
        assert_eq!(after.title, {
            let mut title = before.title.clone();
            title.window = "two".to_owned();
            title.icon = after.title.icon.clone();
            title
        });
        assert_eq!(after.modes.get(&autowrap), Some(&false));
        assert_eq!(
            after.modes.get(&(ProjectedModeSpelling::Dec, 2004)),
            Some(&true)
        );
        assert_eq!(after.colours, before.colours);
    }

    #[test]
    fn a_full_reset_on_the_alternate_buffer_resets_the_whole_terminal() {
        let (_, view) = fed(
            12,
            3,
            b"\x1b]2;shell\x1b\\shell\x1b[?1049h\x1b[Happ\x1b[?7l\x1bc",
        );
        assert_eq!(view.active, ProjectedBuffer::Primary);
        assert!(text(&view.lines).iter().all(String::is_empty), "{view:?}");
        assert!(text(&view.other).iter().all(String::is_empty), "{view:?}");
        assert_eq!(
            view.modes.get(&(ProjectedModeSpelling::Dec, 7)),
            Some(&true)
        );
        let (_, fresh) = fed(12, 3, b"");
        assert_eq!(view.title, fresh.title);
    }

    #[test]
    fn leaving_by_mode_47_restores_nothing_the_primary_buffer_saved() {
        let (mut terminal, view) = fed(
            12,
            6,
            b"\x1b[5;5H\x1b7\x1b[1;1H\x1b[?47h\x1b[2;3H\x1b(0\x1b[1m\x1b[?47l",
        );
        assert_eq!(view.active, ProjectedBuffer::Primary);
        assert_eq!(
            (view.cursor.row.get(), view.cursor.column.get()),
            (1, 2),
            "the cursor stays where it was, not where the primary buffer saved it"
        );
        let _ = terminal.feed(b"q");
        let view = terminal.view().expect("a view");
        assert_eq!(
            text(&view.lines)[1],
            "  \u{2500}",
            "the line-drawing set stays"
        );
        assert_eq!(
            view.lines[1].runs[0].rendition,
            CellRendition::PLAIN,
            "the pen is the plain one after the switch"
        );
        let _ = terminal.feed(b"\x1b8");
        let view = terminal.view().expect("a view");
        assert_eq!(
            (view.cursor.row.get(), view.cursor.column.get()),
            (4, 4),
            "what the primary buffer saved is still there"
        );
    }

    #[test]
    fn a_pending_wrap_survives_a_mode_47_switch() {
        let (mut terminal, view) = fed(12, 3, b"abc\x1b[?47h\x1b[1;1Habcdefghijkl\x1b[?47l");
        assert_eq!(view.active, ProjectedBuffer::Primary);
        assert!(view.cursor.pending_wrap, "{:?}", view.cursor);
        assert_eq!(view.cursor.column.get(), 11);
        assert_eq!(text(&view.lines)[0], "abc", "the primary row is as it was");
        let _ = terminal.feed(b"Z");
        let view = terminal.view().expect("a view");
        assert_eq!(text(&view.lines)[0], "abc");
        assert_eq!(text(&view.lines)[1], "Z", "the next character wraps");
    }
}
