//! Where the cursor is when an address or a character reaches the right edge.
//!
//! A terminal stops an address that names a column past the last one on the last column, and it
//! leaves the cursor on the last column when a character ends there, wide or not. The expected
//! answers here are the ones two physical terminals gave to the same bytes (the records under
//! `fixtures/terminal/physical`), and the controls keep every move that stays inside the grid where
//! it was.

use std::path::{Path, PathBuf};

use kr_term::budget::GridSize;
use kr_term::lane::LaneGate;
use kr_term::snapshot::Viewport;
use kr_term::{Engine, EngineConfig};
use serde_json::Value;

fn engine(cols: u32, rows: u32) -> Engine {
    Engine::new(EngineConfig {
        size: GridSize::new(cols, rows),
        ..EngineConfig::DEFAULT
    })
    .expect("an engine")
}

/// Feeds `bytes` and asks where the cursor is: the row and the column, each counted from one, as
/// the engine answers an application that sends a cursor position report.
fn cursor_after(cols: u32, rows: u32, bytes: &[u8]) -> (u32, u32) {
    let mut engine = engine(cols, rows);
    engine.feed(bytes, 0);
    engine.quiesce(0);
    reported(&mut engine)
}

fn reported(engine: &mut Engine) -> (u32, u32) {
    engine.feed(b"\x1b[6n", 0);
    let reply: Vec<u8> = engine
        .lane_mut()
        .drain(LaneGate::default(), 4096, 0)
        .iter()
        .flat_map(|reply| reply.bytes().to_vec())
        .collect();
    let text = String::from_utf8(reply).expect("a text reply");
    let body = text
        .strip_prefix("\x1b[")
        .and_then(|rest| rest.strip_suffix('R'))
        .unwrap_or_else(|| panic!("not a cursor position report: {text:?}"));
    let (row, col) = body.split_once(';').expect("a row and a column");
    (row.parse().expect("a row"), col.parse().expect("a column"))
}

fn pending_wrap(engine: &Engine) -> bool {
    let size = engine.grid().size();
    engine
        .screen_state(Viewport {
            top_row: 0,
            rows: size.rows,
            left_col: 0,
            cols: size.cols,
        })
        .cursor
        .pending_wrap
}

fn records() -> Vec<(String, Value)> {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("fixtures")
        .join("terminal")
        .join("physical");
    let mut found: Vec<(String, Value)> = std::fs::read_dir(&directory)
        .unwrap_or_else(|error| panic!("{}: {error}", directory.display()))
        .map(|entry| entry.expect("an entry").path())
        .filter(|path: &PathBuf| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .map(|path| {
            let text = std::fs::read_to_string(&path).expect("a record");
            let value = serde_json::from_str(&text)
                .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
            (path.display().to_string(), value)
        })
        .collect();
    found.sort_by(|left, right| left.0.cmp(&right.0));
    found
}

fn hex(text: &str) -> Vec<u8> {
    (0..text.len() / 2)
        .map(|at| u8::from_str_radix(&text[at * 2..at * 2 + 2], 16).expect("hexadecimal"))
        .collect()
}

/// Every recorded step named `id`, with the window it was measured in and what the terminal said.
fn recorded(id: &str) -> Vec<(String, u32, u32, Vec<u8>, (u32, u32))> {
    let mut found = Vec::new();
    for (name, record) in records() {
        let window = record["window"].as_array().expect("a window");
        let cols = u32::try_from(window[0].as_u64().expect("columns")).expect("columns fit");
        let rows = u32::try_from(window[1].as_u64().expect("rows")).expect("rows fit");
        let step = record["steps"]
            .as_array()
            .expect("steps")
            .iter()
            .find(|step| step["id"] == id)
            .unwrap_or_else(|| panic!("{name} has no step {id}"));
        let answer = &step["terminal"];
        found.push((
            name,
            cols,
            rows,
            hex(step["bytes"].as_str().expect("bytes")),
            (
                u32::try_from(answer["row"].as_u64().expect("a row")).expect("row fits"),
                u32::try_from(answer["col"].as_u64().expect("a column")).expect("column fits"),
            ),
        ));
    }
    assert!(found.len() >= 2, "records of at least two terminals");
    found
}

#[test]
fn an_address_past_the_corner_is_answered_as_both_recorded_terminals_answered_it() {
    for (name, cols, rows, bytes, terminal) in recorded("addressing.clamps-to-the-corner") {
        assert_eq!(terminal, (rows, cols), "{name} stops on the corner");
        assert_eq!(cursor_after(cols, rows, &bytes), terminal, "{name}");
    }
}

#[test]
fn a_wide_character_that_ends_in_the_last_column_is_answered_as_both_recorded_terminals_did() {
    for (name, cols, rows, bytes, terminal) in
        recorded("wide.wide-character-two-cells-from-the-edge")
    {
        assert_eq!(
            terminal,
            (1, cols),
            "{name} leaves the cursor on the last column"
        );
        assert_eq!(cursor_after(cols, rows, &bytes), terminal, "{name}");
    }
}

#[test]
fn every_absolute_column_past_the_last_stops_on_the_last() {
    // One grid wider than it is tall and one taller than it is wide: the library's own bound on a
    // column parameter is the larger of the two, so both shapes are needed.
    for (cols, rows) in [(10, 5), (10, 30)] {
        for (name, bytes) in [
            ("cursor position, far past", "\x1b[2;99H"),
            ("cursor position, one past", "\x1b[2;11H"),
            ("horizontal and vertical position, far past", "\x1b[2;99f"),
            ("column absolute, far past", "\x1b[2;4H\x1b[99G"),
            ("column absolute, one past", "\x1b[2;4H\x1b[11G"),
            (
                "horizontal position absolute, far past",
                "\x1b[2;4H\x1b[99`",
            ),
            (
                "column absolute, inside a taller grid's own bound",
                "\x1b[2;4H\x1b[25G",
            ),
        ] {
            assert_eq!(
                cursor_after(cols, rows, bytes.as_bytes()),
                (2, cols),
                "{name} in {cols} by {rows}"
            );
        }
    }
}

#[test]
fn a_character_after_an_address_past_the_edge_lands_on_the_last_column() {
    let mut engine = engine(10, 5);
    engine.feed(b"\x1b[1;99Hx", 0);
    engine.quiesce(0);
    assert_eq!(reported(&mut engine), (1, 10));
    assert!(
        pending_wrap(&engine),
        "the character filled the last column"
    );
    engine.feed(b"y", 0);
    engine.quiesce(0);
    assert_eq!(reported(&mut engine), (2, 2), "the next character wraps");
    let text = |row: usize| -> String {
        engine.grid().visible_rows()[row]
            .runs
            .iter()
            .map(|run| run.text.as_str())
            .collect()
    };
    assert_eq!(text(0).trim_end(), "         x");
    assert_eq!(text(1).trim_end(), "y");
}

#[test]
fn an_address_inside_the_grid_is_left_where_it_says() {
    for (cols, rows) in [(10, 5), (10, 30)] {
        for (name, bytes, expected) in [
            ("cursor position", "\x1b[3;7H", (3, 7)),
            ("the last column", "\x1b[3;10H", (3, 10)),
            ("the first column", "\x1b[3;1H", (3, 1)),
            ("no column", "\x1b[3H", (3, 1)),
            ("a zero column", "\x1b[3;0H", (3, 1)),
            ("horizontal and vertical position", "\x1b[2;9f", (2, 9)),
            ("column absolute", "\x1b[2;4H\x1b[6G", (2, 6)),
            (
                "column absolute, the last column",
                "\x1b[2;4H\x1b[10G",
                (2, 10),
            ),
            ("column absolute, no parameter", "\x1b[2;4H\x1b[G", (2, 1)),
            ("horizontal position absolute", "\x1b[2;4H\x1b[7`", (2, 7)),
        ] {
            assert_eq!(
                cursor_after(cols, rows, bytes.as_bytes()),
                expected,
                "{name} in {cols} by {rows}"
            );
        }
    }
}

#[test]
fn a_wide_character_ends_the_row_on_its_last_column_and_a_narrow_one_does_too() {
    // Eight columns and a two-cell character fill ten; nine and a one-cell character do too.
    let wide = "aaaaaaaa\u{3042}";
    let narrow = "aaaaaaaaab";
    for text in [wide, narrow] {
        let mut engine = engine(10, 5);
        engine.feed(text.as_bytes(), 0);
        engine.quiesce(0);
        assert_eq!(reported(&mut engine), (1, 10), "{text:?}");
        assert!(pending_wrap(&engine), "{text:?}");
        let size = engine.grid().size();
        let snapshot = engine
            .screen_state(Viewport {
                top_row: 0,
                rows: size.rows,
                left_col: 0,
                cols: size.cols,
            })
            .cursor;
        assert_eq!(
            snapshot.col, 9,
            "a snapshot names the same column: {text:?}"
        );
        engine.feed(b"z", 0);
        engine.quiesce(0);
        assert_eq!(
            reported(&mut engine),
            (2, 2),
            "{text:?} wraps the next character"
        );
    }
}

#[test]
fn a_wide_character_that_leaves_room_leaves_the_cursor_after_it() {
    for (text, expected) in [
        ("aaaaaaa\u{3042}", (1, 10)),
        ("aaaaaa\u{3042}", (1, 9)),
        ("\u{3042}", (1, 3)),
        ("a\u{3042}b", (1, 5)),
    ] {
        assert_eq!(cursor_after(10, 5, text.as_bytes()), expected, "{text:?}");
    }
    assert!(!{
        let mut engine = engine(10, 5);
        engine.feed("aaaaaaa\u{3042}".as_bytes(), 0);
        engine.quiesce(0);
        pending_wrap(&engine)
    });
}

#[test]
fn a_wide_character_that_ends_at_a_right_margin_leaves_the_cursor_on_the_margin() {
    // Columns 3 to 8 are the margins. Four cells and a two-cell character end on column 8, and so
    // do five cells and a one-cell character: the two must agree, as they do at the screen's edge.
    for text in ["aaaa\u{3042}", "aaaaab"] {
        let bytes = format!("\x1b[?69h\x1b[3;8s\x1b[1;3H{text}");
        assert_eq!(cursor_after(20, 5, bytes.as_bytes()), (1, 8), "{text:?}");
    }
}
