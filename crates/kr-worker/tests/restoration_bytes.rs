//! What a restoration writes to a physical terminal, read back from the screens a real engine holds.
//!
//! The bytes are the product's own output for a screen a real stream produced, and what is checked
//! is what a terminal does with them, so a small reader follows the sequences as a terminal would.
//! No xterm runs here. The rules the reader applies are the ones xterm's source and a measured
//! xterm give: a soft reset saves a fresh cursor only in the buffer that is showing, `?1049h` saves
//! the cursor in the buffer that is showing and then shows the alternate one, and a soft reset
//! makes the cursor show.

use kr_protocol::scalars::U64;
use kr_protocol::session::Dimensions;
use kr_term::lane::LaneGate;
use kr_worker::projection::TerminalEngine;
use kr_worker::render::{Keyboard, Scope};

/// One thing in a run of terminal output.
#[derive(Debug, PartialEq, Eq)]
enum Item {
    /// A control sequence introduced by `CSI`: its parameters, intermediates and final byte.
    Csi(String),
    /// A command introduced by `OSC`, up to its terminator.
    Osc(String),
    /// Any other sequence that starts with an escape.
    Esc(String),
    /// A character drawn on the screen.
    Text(char),
    /// A control character.
    Control(u8),
}

fn items(bytes: &[u8]) -> Vec<Item> {
    let mut found = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        match bytes[at] {
            0x1b if bytes.get(at + 1) == Some(&b'[') => {
                let end = bytes[at + 2..]
                    .iter()
                    .position(|byte| (0x40..=0x7e).contains(byte))
                    .map(|offset| at + 2 + offset)
                    .expect("every sequence is finished");
                found.push(Item::Csi(
                    String::from_utf8_lossy(&bytes[at + 2..=end]).into_owned(),
                ));
                at = end + 1;
            }
            0x1b if bytes.get(at + 1) == Some(&b']') => {
                let mut end = at + 2;
                while !(bytes[end] == 0x07 || bytes[end..].starts_with(b"\x1b\\")) {
                    end += 1;
                }
                found.push(Item::Osc(
                    String::from_utf8_lossy(&bytes[at + 2..end]).into_owned(),
                ));
                at = end + if bytes[end] == 0x07 { 1 } else { 2 };
            }
            0x1b => {
                // A character-set designation has one more byte than the other two-byte escapes.
                let length = if matches!(bytes.get(at + 1), Some(b'(' | b')')) {
                    3
                } else {
                    2
                };
                found.push(Item::Esc(
                    String::from_utf8_lossy(&bytes[at + 1..at + length]).into_owned(),
                ));
                at += length;
            }
            byte if byte < 0x20 || byte == 0x7f => {
                found.push(Item::Control(byte));
                at += 1;
            }
            _ => {
                let text = std::str::from_utf8(&bytes[at..]).unwrap_or_else(|error| {
                    std::str::from_utf8(&bytes[at..at + error.valid_up_to()]).expect("valid")
                });
                let character = text.chars().next().expect("a character");
                found.push(Item::Text(character));
                at += character.len_utf8();
            }
        }
    }
    found
}

fn dimensions() -> Dimensions {
    Dimensions {
        columns: U64::new(20),
        rows: U64::new(6),
    }
}

/// The restoration a terminal of the session's size is drawn after `stream` has been written.
fn restoration_after(stream: &[u8]) -> Vec<u8> {
    let mut engine = TerminalEngine::new(
        dimensions(),
        std::sync::Arc::new(kr_ipc::clock::SystemSharedClock),
    )
    .expect("a canonical grid");
    engine.feed(0, stream, LaneGate::default());
    let (_, restoration, _) = engine.restoration(
        dimensions(),
        LaneGate::default(),
        Keyboard::Install,
        Scope::WholeScreen,
    );
    restoration.bytes
}

/// The screens the tests draw: each buffer showing, and the other one holding something. The
/// alternate buffer is entered through mode 1047, which saves no cursor, so the session holds no
/// saved cursor in either buffer.
const PRIMARY_SHOWING: &[u8] = b"shell one\r\nshell two\r\n\x1b[?1047h\x1b[Halt text\x1b[?1047l";
const ALTERNATE_SHOWING: &[u8] = b"shell one\r\nshell two\r\n\x1b[?1047h\x1b[Halt text";

/// What a terminal that follows xterm's rules holds in its two saved-cursor slots after the bytes.
///
/// A slot is fresh when the last thing that touched it was a soft reset run while its buffer was
/// showing, and not otherwise: a save leaves whatever the cursor was, and a slot nothing has
/// touched holds what an earlier application left in it.
fn fresh_slots(items: &[Item], starts_on_alternate: bool) -> (bool, bool) {
    let (mut primary, mut alternate) = (false, false);
    let mut on_alternate = starts_on_alternate;
    for item in items {
        let slot = if on_alternate {
            &mut alternate
        } else {
            &mut primary
        };
        match item {
            Item::Csi(sequence) if sequence == "!p" => *slot = true,
            Item::Csi(sequence) if sequence == "?1049h" => {
                *slot = false;
                on_alternate = true;
            }
            Item::Csi(sequence) if sequence == "?1049l" => on_alternate = false,
            Item::Esc(sequence) if sequence == "7" => *slot = false,
            _ => {}
        }
    }
    (primary, alternate)
}

/// A restoration leaves the session's saved cursors on the terminal, and where the session holds
/// none the terminal holds none. xterm keeps one saved cursor per buffer, a soft reset forgets only
/// the one of the buffer that is showing, and an earlier application can have saved one in the
/// other buffer, so a restore that comes before any save of the application's would go to where
/// that cursor was. It cannot be left to the buffer the terminal happens to show when the
/// restoration begins.
#[test]
fn a_restoration_leaves_no_saved_cursor_the_session_does_not_hold() {
    for (name, stream, primary_showing) in [
        ("primary", PRIMARY_SHOWING, true),
        ("alternate", ALTERNATE_SHOWING, false),
    ] {
        let written = items(&restoration_after(stream));
        for starts_on_alternate in [false, true] {
            let (primary, alternate) = fresh_slots(&written, starts_on_alternate);
            let began = if starts_on_alternate {
                "alternate"
            } else {
                "primary"
            };
            assert!(
                alternate,
                "{name} showing, terminal began on the {began} buffer: the alternate buffer's \
                 saved cursor is not fresh"
            );
            // With the alternate buffer showing, the way back into it saves a plain cursor in the
            // primary buffer, which is what a fresh one holds.
            assert!(
                primary || !primary_showing,
                "{name} showing, terminal began on the {began} buffer: the primary buffer's \
                 saved cursor is not fresh"
            );
        }
    }
}

/// A soft reset does not close a hyperlink, so one the stream left open when the restoration begins
/// would be on every cell drawn before the restoration's own first link. The link is closed before
/// the first cell is drawn.
#[test]
fn a_link_the_stream_left_open_is_closed_before_the_first_cell_is_drawn() {
    // The screen's first row has no link, and the link the session had open is closed.
    let written = items(&restoration_after(
        b"plain \x1b]8;;http://example.invalid/\x1b\\linked\x1b]8;;\x1b\\ after",
    ));
    let first_text = written
        .iter()
        .position(|item| matches!(item, Item::Text(_)))
        .expect("a cell is drawn");
    let closed = written[..first_text]
        .iter()
        .any(|item| matches!(item, Item::Osc(command) if command == "8;;"));
    assert!(
        closed,
        "no hyperlink is closed before the first cell: {:?}",
        &written[..first_text]
    );
}

/// A soft reset makes the cursor show, and so does the mode the session tracks for it. A cursor
/// that shows while rows are drawn travels across the screen as each is placed, so the cursor is
/// hidden from the first reset and shows again only at the end, where the session's own cursor says
/// whether it does.
#[test]
fn a_restoration_is_drawn_while_the_cursor_is_hidden() {
    for (name, stream, shows) in [
        ("a cursor that shows", &b"one\r\ntwo"[..], true),
        (
            "a cursor the application hid",
            b"one\r\ntwo\x1b[?25l",
            false,
        ),
    ] {
        let written = items(&restoration_after(stream));
        let mut visible = false;
        let mut drawn_while_visible = false;
        for item in &written {
            match item {
                Item::Csi(sequence) if sequence == "!p" || sequence == "?25h" => visible = true,
                Item::Csi(sequence) if sequence == "?25l" => visible = false,
                Item::Text(_) => drawn_while_visible |= visible,
                _ => {}
            }
        }
        assert!(
            !drawn_while_visible,
            "{name}: a cell is drawn with the cursor showing"
        );
        assert_eq!(
            visible, shows,
            "{name}: the restoration ends with the session's own cursor"
        );
    }
}
