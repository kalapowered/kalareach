//! What a restoration writes to a physical terminal, read back from screens a real engine holds.
//!
//! The bytes are the product's own output for a screen a real stream produced, and what is checked
//! is what a terminal does with them, so a small reader follows the sequences as a terminal would.
//! No terminal runs here. The rules the reader applies are the ones the terminals' sources and
//! measurements give: `DECSC` saves the cursor in the buffer that is showing, `?1049h` saves it in
//! the buffer that is showing and then shows the alternate one, and `?1049l` takes the cursor
//! back from the primary buffer's save.

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
fn restoration_after(stream: &[u8], scope: Scope) -> Vec<u8> {
    restoration_with(stream, Keyboard::Install, scope)
}

/// The same, for a terminal whose keyboard the restoration may or may not change.
fn restoration_with(stream: &[u8], keyboard: Keyboard, scope: Scope) -> Vec<u8> {
    let mut engine = TerminalEngine::new(
        dimensions(),
        std::sync::Arc::new(kr_ipc::clock::SystemSharedClock),
    )
    .expect("a canonical grid");
    engine.feed(0, stream, LaneGate::default());
    let (_, restoration, _) =
        engine.restoration(dimensions(), LaneGate::default(), keyboard, scope);
    restoration.bytes
}

/// Both scopes a restoration is drawn in: the whole screen, and the live screen alone.
const SCOPES: [Scope; 2] = [Scope::WholeScreen, Scope::LiveScreen];

/// The screens the tests draw: each buffer showing, and the other one holding something. The
/// alternate buffer is entered through mode 1047, which saves no cursor, so the session holds no
/// saved cursor in either buffer.
const PRIMARY_SHOWING: &[u8] = b"shell one\r\nshell two\r\n\x1b[?1047h\x1b[Halt text\x1b[?1047l";
const ALTERNATE_SHOWING: &[u8] = b"shell one\r\nshell two\r\n\x1b[?1047h\x1b[Halt text";

/// Where the cursor and the rendition stand, as far as the bytes written so far say.
#[derive(Clone, Copy, Debug, Default)]
struct Stand {
    /// The cursor is at home.
    home: bool,
    /// The rendition is the plain one.
    plain: bool,
}

impl Stand {
    /// Follows one item: what moves the cursor or changes the rendition, and what leaves both
    /// alone, such as saving the cursor or designating a character set.
    fn follow(&mut self, item: &Item) {
        match item {
            Item::Csi(sequence) => {
                let last = sequence.chars().last().expect("a final byte");
                if sequence == "H" || sequence == "1;1H" {
                    self.home = true;
                } else if "ABCDEFGHdefa`".contains(last) {
                    self.home = false;
                }
                if last == 'm' {
                    self.plain = sequence == "0m";
                }
            }
            Item::Esc(sequence) if sequence == "7" || sequence.starts_with(['(', ')']) => {}
            Item::Text(_) | Item::Esc(_) => self.home = false,
            Item::Control(byte) if *byte != b'\r' && *byte != 0x0f => self.home = false,
            _ => {}
        }
    }

    /// Whether what a save would store is the plain state.
    const fn is_plain(self) -> bool {
        self.home && self.plain
    }
}

/// What a terminal that follows xterm's rules holds in its two saved-cursor slots after the bytes.
///
/// A slot is plain when the last thing that touched it saved the cursor at home in the plain
/// rendition, and not otherwise: a slot nothing has touched holds what an earlier application left
/// in it. `DECSC` and `?1049h` save in the buffer that is showing, and `?1049l` takes the cursor
/// from the primary buffer's slot, so what comes after it is what that slot held.
fn plain_slots(items: &[Item], starts_on_alternate: bool) -> (bool, bool) {
    let (mut primary, mut alternate) = (false, false);
    let mut on_alternate = starts_on_alternate;
    let mut stand = Stand::default();
    for item in items {
        let slot = if on_alternate {
            &mut alternate
        } else {
            &mut primary
        };
        match item {
            Item::Esc(sequence) if sequence == "7" => *slot = stand.is_plain(),
            Item::Csi(sequence) if sequence == "?1049h" => {
                *slot = stand.is_plain();
                on_alternate = true;
                stand = Stand::default();
            }
            Item::Csi(sequence) if sequence == "?1049l" => {
                on_alternate = false;
                stand = Stand {
                    home: primary,
                    plain: primary,
                };
            }
            _ => stand.follow(item),
        }
    }
    (primary, alternate)
}

/// A restoration leaves the session's saved cursors on the terminal, and where the session holds
/// none the terminal holds the plain one. xterm keeps one saved cursor per buffer, and an earlier
/// application can have saved one in the buffer that is not showing, so a restore that comes before
/// any save of the application's would go to where that cursor was. It cannot be left to the buffer
/// the terminal happens to show when the restoration begins.
#[test]
fn a_restoration_leaves_no_saved_cursor_the_session_does_not_hold() {
    for (name, stream) in [
        ("primary", PRIMARY_SHOWING),
        ("alternate", ALTERNATE_SHOWING),
    ] {
        for scope in SCOPES {
            let written = items(&restoration_after(stream, scope));
            for starts_on_alternate in [false, true] {
                let (primary, alternate) = plain_slots(&written, starts_on_alternate);
                let began = if starts_on_alternate {
                    "alternate"
                } else {
                    "primary"
                };
                assert!(
                    alternate,
                    "{name} showing in {scope:?}, terminal began on the {began} buffer: the \
                     alternate buffer's saved cursor is not plain"
                );
                assert!(
                    primary,
                    "{name} showing in {scope:?}, terminal began on the {began} buffer: the \
                     primary buffer's saved cursor is not plain"
                );
            }
        }
    }
}

/// What a terminal saves when the alternate buffer is entered: the position and the rendition it
/// finds. Every entry a restoration makes must find the plain state (the cursor at home, the
/// default rendition), because the application's own restore, in either buffer, goes to what was
/// saved.
fn entries_that_save_something_else(items: &[Item]) -> Vec<usize> {
    let mut stand = Stand::default();
    let mut found = Vec::new();
    for (at, item) in items.iter().enumerate() {
        match item {
            Item::Csi(sequence) if sequence == "?1049h" => {
                if !stand.is_plain() {
                    found.push(at);
                }
                // A switch restores or replaces the cursor: nothing is known after it.
                stand = Stand::default();
            }
            Item::Csi(sequence) if sequence == "?1049l" => stand = Stand::default(),
            _ => stand.follow(item),
        }
    }
    found
}

/// A terminal saves, on every entry into the alternate buffer, the position and rendition it is in.
/// A restoration that begins on the alternate buffer, with the cursor wherever the application left
/// it, must not be saved there.
#[test]
fn a_restoration_saves_the_plain_state_whenever_it_enters_the_alternate_buffer() {
    for (name, stream) in [
        ("primary", PRIMARY_SHOWING),
        ("alternate", ALTERNATE_SHOWING),
    ] {
        for scope in SCOPES {
            let written = items(&restoration_after(stream, scope));
            let entered = entries_that_save_something_else(&written);
            assert!(
                entered.is_empty(),
                "{name} showing in {scope:?}: entries at items {entered:?} do not find the cursor \
                 at home in the default rendition: {written:?}"
            );
        }
    }
}

/// A terminal can have a hyperlink open when the restoration begins, and one that stays open would
/// be on every cell drawn before the restoration's own first link. The link is closed before the
/// first cell is drawn.
#[test]
fn a_link_the_stream_left_open_is_closed_before_the_first_cell_is_drawn() {
    for scope in SCOPES {
        // The screen's first row has no link, and the link the session had open is closed.
        let written = items(&restoration_after(
            b"plain \x1b]8;;http://example.invalid/\x1b\\linked\x1b]8;;\x1b\\ after",
            scope,
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
            "{scope:?}: no hyperlink is closed before the first cell: {:?}",
            &written[..first_text]
        );
    }
}

/// Whether text is drawn under the link the stream left open, on a terminal that saves the open
/// hyperlink with the cursor: entering the alternate buffer saves the link in force (unless that
/// buffer already shows), and leaving it gives back the saved one, wherever the terminal shows.
fn draws_under_the_streams_link(items: &[Item], starts_on_alternate: bool) -> bool {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Link {
        None,
        Streams,
        Own,
    }
    // An application saved a cursor while its link was open, and the link is still open.
    let (mut link, mut saved) = (Link::Streams, Link::Streams);
    let mut on_alternate = starts_on_alternate;
    for item in items {
        match item {
            Item::Osc(command) => {
                let mut parts = command.splitn(3, ';');
                if parts.next() == Some("8") {
                    link = if parts.nth(1).is_some_and(str::is_empty) {
                        Link::None
                    } else {
                        Link::Own
                    };
                }
            }
            Item::Csi(sequence) if sequence == "?1049h" => {
                if !on_alternate {
                    saved = link;
                }
                on_alternate = true;
            }
            Item::Csi(sequence) if sequence == "?1049l" => {
                link = saved;
                on_alternate = false;
            }
            Item::Text(_) if link == Link::Streams => return true,
            _ => {}
        }
    }
    false
}

/// A switch of buffer can give back a hyperlink that the cursor it restores had saved, in a
/// buffer the restoration did not close it in, so the link is closed again after every switch,
/// whichever buffer the terminal began on and whichever scope is drawn.
#[test]
fn a_switch_of_buffer_does_not_bring_the_streams_link_back() {
    for (name, stream) in [
        ("primary", PRIMARY_SHOWING),
        ("alternate", ALTERNATE_SHOWING),
    ] {
        for scope in SCOPES {
            let written = items(&restoration_after(stream, scope));
            for starts_on_alternate in [false, true] {
                assert!(
                    !draws_under_the_streams_link(&written, starts_on_alternate),
                    "{name} showing in {scope:?}, alternate first: {starts_on_alternate}: text \
                     is drawn under the link the stream left open: {written:?}"
                );
            }
        }
    }
}

/// A terminal shows its cursor when a restoration begins, and so does the mode the session tracks
/// for it. A cursor that shows while rows are drawn travels across the screen as each is placed, so
/// the cursor is hidden at the start and shows again only at the end, where the session's own
/// cursor says whether it does.
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
        for scope in SCOPES {
            let written = items(&restoration_after(stream, scope));
            let mut visible = true;
            let mut drawn_while_visible = false;
            for item in &written {
                match item {
                    Item::Csi(sequence) if sequence == "?25h" => visible = true,
                    Item::Csi(sequence) if sequence == "?25l" => visible = false,
                    Item::Text(_) => drawn_while_visible |= visible,
                    _ => {}
                }
            }
            assert!(
                !drawn_while_visible,
                "{name} in {scope:?}: a cell is drawn with the cursor showing"
            );
            assert_eq!(
                visible, shows,
                "{name} in {scope:?}: the restoration ends with the session's own cursor"
            );
        }
    }
}

/// What a restoration writes to put a terminal in the plain state is written before the first cell
/// is drawn, in the buffer the terminal shows, in the other one and in the primary buffer again,
/// and not asked of a soft reset. Terminals disagree about what that does: some ignore it, so
/// origin mode, a scroll region or a character set an earlier application left would stay in force
/// while the rows are drawn, and some empty the keyboard stack or leave their saved cursors alone.
#[test]
fn a_restoration_writes_the_plain_state_in_every_buffer_it_visits() {
    let plain = ["?25l", "0m", "?6l", "?69l", "r", "0 q", "H"];
    for (name, stream) in [
        ("primary", PRIMARY_SHOWING),
        ("alternate", ALTERNATE_SHOWING),
    ] {
        for scope in SCOPES {
            let written = items(&restoration_after(stream, scope));
            let first_cell = written
                .iter()
                .position(|item| matches!(item, Item::Text(_)))
                .expect("a cell is drawn");
            let switches: Vec<usize> = written[..first_cell]
                .iter()
                .enumerate()
                .filter(|(_, item)| matches!(item, Item::Csi(sequence) if sequence.starts_with("?1049")))
                .map(|(at, _)| at)
                .collect();
            assert!(switches.len() >= 2, "{name} in {scope:?}: {written:?}");
            let visits = [
                &written[..switches[0]],
                &written[switches[0]..switches[1]],
                &written[switches[1]..first_cell],
            ];
            for (visit, items) in visits.iter().enumerate() {
                for sequence in plain {
                    assert!(
                        items.contains(&Item::Csi(sequence.to_owned())),
                        "{name} in {scope:?}, visit {visit}: no {sequence:?} in {items:?}"
                    );
                }
                for escape in ["(B", ")B", "7"] {
                    assert!(
                        items.contains(&Item::Esc(escape.to_owned())),
                        "{name} in {scope:?}, visit {visit}: no ESC {escape} in {items:?}"
                    );
                }
                assert!(
                    items.contains(&Item::Control(0x0f)),
                    "{name} in {scope:?}, visit {visit}: no shift-in in {items:?}"
                );
                assert!(
                    items.contains(&Item::Osc("8;;".to_owned())),
                    "{name} in {scope:?}, visit {visit}: no link is closed in {items:?}"
                );
            }
        }
    }
}

/// A restoration changes no keyboard state of a terminal beyond what its brief names, and no title
/// stack: a soft reset is how kitty and foot would empty a keyboard stack, foot would empty its
/// title stack and WezTerm would reset `modifyOtherKeys`, and the stacks are the person's own.
/// A terminal nobody asked about its keyboard has no sequence about it written at all; one that
/// was asked has the flags in force and the `modifyOtherKeys` level installed, and never a push
/// or a pop.
#[test]
fn a_restoration_leaves_the_keyboard_and_title_stacks_the_terminal_holds_alone() {
    let stream = b"shell\r\n\x1b[>4;2m\x1b[>1u\x1b[>5u\x1b]2;title\x07\x1b[22;0t";
    for scope in SCOPES {
        for keyboard in [Keyboard::Withhold, Keyboard::Install] {
            let written = items(&restoration_with(stream, keyboard, scope));
            for item in &written {
                let Item::Csi(sequence) = item else {
                    continue;
                };
                assert!(
                    sequence != "!p",
                    "{keyboard:?} in {scope:?}: a soft reset is written"
                );
                assert!(
                    !sequence.ends_with('t'),
                    "{keyboard:?} in {scope:?}: a window operation, which includes the title \
                     stack, is written: {sequence:?}"
                );
                if sequence.ends_with('u') {
                    assert!(
                        keyboard == Keyboard::Install && sequence.starts_with('='),
                        "{keyboard:?} in {scope:?}: {sequence:?} changes the keyboard stack"
                    );
                }
                if sequence.starts_with('>') {
                    assert!(
                        keyboard == Keyboard::Install && sequence.starts_with(">4;"),
                        "{keyboard:?} in {scope:?}: {sequence:?} is written to a terminal that \
                         was not asked about its keyboard"
                    );
                }
            }
        }
    }
}
