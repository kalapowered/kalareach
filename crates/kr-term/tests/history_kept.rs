//! The rows above the live screen, and what it takes to keep none of them.
//!
//! An engine whose history is not kept gives up every row held above the live screen when that is
//! asked for and holds none between two calls afterwards. The live screen is the same before and
//! after, and turning the history back on starts it empty.

use kr_term::budget::GridSize;
use kr_term::diag::DiagnosticKind;
use kr_term::engine::{Engine, EngineConfig};
use kr_term::grid::GridRow;

const ENTER_ALTERNATE: &str = "\x1b[?1049h";
const LEAVE_ALTERNATE: &str = "\x1b[?1049l";

fn engine(cols: u32, rows: u32) -> Engine {
    Engine::new(EngineConfig {
        size: GridSize::new(cols, rows),
        ..EngineConfig::DEFAULT
    })
    .expect("engine")
}

fn printed(word: &str, from: usize, to: usize) -> String {
    (from..to)
        .map(|index| format!("{word} {index}\r\n"))
        .collect()
}

fn text_of(rows: &[GridRow]) -> Vec<String> {
    rows.iter()
        .map(|row| row.runs.iter().map(|run| run.text.as_str()).collect())
        .collect()
}

/// The text of every row the engine holds above the live screen, oldest first.
fn retained(engine: &Engine) -> Vec<String> {
    let grid = engine.grid();
    let (oldest, _) = grid.stable_range();
    let count = usize::try_from(grid.visible_top_row() - oldest).expect("rows above the screen");
    text_of(&grid.history_rows(oldest, count))
}

fn truncations(engine: &Engine) -> u64 {
    engine
        .diagnostic_totals()
        .into_iter()
        .filter(|(kind, _)| *kind == DiagnosticKind::ResidentStateTruncated)
        .map(|(_, count)| count)
        .sum()
}

/// What a person reading the live screen sees, and where the cursor stands.
fn screen_of(engine: &mut Engine) -> (Vec<GridRow>, Vec<GridRow>, String) {
    let view = kr_term::snapshot::Viewport {
        top_row: engine.grid().visible_top_row(),
        rows: engine.grid().size().rows,
        left_col: 0,
        cols: engine.grid().size().cols,
    };
    let (snapshot, _) = engine.snapshot(view, 0);
    (
        snapshot.rows,
        snapshot.inactive_rows,
        format!("{:?}", snapshot.cursor),
    )
}

#[test]
fn the_rows_above_the_screen_are_given_up_and_the_screen_is_not_changed() {
    let mut engine = engine(20, 4);
    engine.feed(printed("before", 0, 40).as_bytes(), 0);
    assert!(
        retained(&engine).iter().any(|row| row.contains("before 0")),
        "the rows are held before the call"
    );
    let screen = screen_of(&mut engine);

    engine.set_history_kept(false);

    assert!(
        retained(&engine).is_empty(),
        "no row is held above the screen"
    );
    assert_eq!(engine.grid().history_bytes(), 0);
    assert_eq!(
        screen_of(&mut engine),
        screen,
        "the rows, their identifiers and the cursor are the same"
    );
}

#[test]
fn a_wrapped_line_and_a_wide_character_at_the_boundary_are_not_changed() {
    // Twenty columns of wide characters on a screen of eight: the line wraps over three rows, and
    // the next line pushes the first of them above a screen of three rows.
    let mut engine = engine(8, 3);
    engine.feed(format!("{}\r\nx", "\u{5168}".repeat(10)).as_bytes(), 0);
    assert!(!retained(&engine).is_empty(), "the first row is held");
    let screen = screen_of(&mut engine);
    let first = screen.0.first().expect("the first row of the screen");
    assert!(
        first.soft_wrapped,
        "the screen starts inside the wrapped line"
    );

    engine.set_history_kept(false);

    assert!(retained(&engine).is_empty());
    assert_eq!(screen_of(&mut engine), screen);
}

#[test]
fn nothing_is_held_between_two_calls_and_nothing_is_recorded_as_cut() {
    let mut engine = engine(20, 4);
    engine.feed(printed("before", 0, 10).as_bytes(), 0);
    engine.set_history_kept(false);

    // A read of many screens, and then a row at a time.
    engine.feed(printed("while", 0, 5_000).as_bytes(), 0);
    assert!(retained(&engine).is_empty());
    assert_eq!(engine.grid().scrollback_rows(), 0);
    for index in 5_000..5_010 {
        engine.feed(printed("while", index, index + 1).as_bytes(), 0);
        assert!(retained(&engine).is_empty());
        assert_eq!(engine.grid().history_bytes(), 0);
    }
    assert_eq!(
        truncations(&engine),
        0,
        "giving rows up is not cutting content to fit a bound"
    );
    let shown = text_of(&engine.grid().visible_rows());
    assert!(
        shown.iter().any(|row| row.contains("while 5009")),
        "the screen shows the newest rows"
    );
}

#[test]
fn the_history_is_kept_again_from_the_first_row_that_comes_onto_the_screen() {
    let mut engine = engine(20, 4);
    engine.feed(printed("before", 0, 20).as_bytes(), 0);
    engine.set_history_kept(false);
    engine.feed(printed("while", 0, 20).as_bytes(), 0);
    assert!(retained(&engine).is_empty());

    engine.set_history_kept(true);
    assert!(
        retained(&engine).is_empty(),
        "turning it on starts with no rows"
    );
    engine.feed(printed("after", 0, 20).as_bytes(), 0);

    let rows = retained(&engine);
    assert!(rows.iter().any(|row| row.contains("after")));
    assert!(
        rows.iter().all(|row| row.contains("after")),
        "nothing that was on the screen when it was turned on is kept: {rows:?}"
    );
    assert!(
        !rows.iter().any(|row| row.contains("after 0")),
        "the row the cursor was on is given up with the rest: {rows:?}"
    );
}

#[test]
fn a_resize_does_not_let_the_rows_on_the_screen_be_kept() {
    // Rows of eighteen columns on a screen of twenty. Narrowed to ten, each splits in two, so the
    // library's numbers of rows move and the mark has to move with them.
    let mut engine = engine(20, 4);
    engine.feed(printed("before 0123456", 0, 20).as_bytes(), 0);
    engine.set_history_kept(false);
    engine.feed(printed("while 0123456", 0, 6).as_bytes(), 0);
    engine.set_history_kept(true);

    engine.resize(GridSize::new(10, 4), 0).expect("narrower");
    engine.feed(printed("after", 0, 20).as_bytes(), 0);

    let rows = retained(&engine);
    assert!(rows.iter().any(|row| row.contains("after")));
    assert!(
        rows.iter().all(|row| row.contains("after")),
        "no half of a row that was on the screen is kept: {rows:?}"
    );
}

#[test]
fn rows_owed_while_the_alternate_buffer_shows_go_in_the_call_that_leaves_it() {
    let mut engine = engine(20, 4);
    engine.feed(printed("before", 0, 20).as_bytes(), 0);
    let shell = screen_of(&mut engine);
    engine.feed(ENTER_ALTERNATE.as_bytes(), 0);
    engine.feed(b"\x1b[2J\x1b[Happ", 0);
    assert!(engine.grid().alternate_active());
    let app = screen_of(&mut engine);

    engine.set_history_kept(false);

    assert!(
        engine.grid().scrollback_rows() > 0,
        "the primary buffer's rows cannot be reached while the alternate buffer shows"
    );
    assert_eq!(
        screen_of(&mut engine),
        app,
        "neither buffer's screen is changed"
    );

    // The program leaves, and writes more in the same read.
    engine.feed(
        format!("{LEAVE_ALTERNATE}{}", printed("while", 0, 3)).as_bytes(),
        0,
    );
    assert!(!engine.grid().alternate_active());
    assert!(
        retained(&engine).is_empty(),
        "nothing from before is held once the primary buffer shows again: {:?}",
        retained(&engine)
    );
    assert_eq!(engine.grid().history_bytes(), 0);
    assert_ne!(
        screen_of(&mut engine),
        shell,
        "the later rows are on the screen"
    );
}

#[test]
fn rows_owed_are_still_owed_when_the_history_is_turned_on_before_the_program_leaves() {
    let mut engine = engine(20, 4);
    engine.feed(printed("before", 0, 20).as_bytes(), 0);
    engine.feed(ENTER_ALTERNATE.as_bytes(), 0);
    engine.set_history_kept(false);
    engine.set_history_kept(true);
    assert!(
        engine.grid().scrollback_rows() > 0,
        "the rows are still held while the alternate buffer shows"
    );

    engine.feed(
        format!("{LEAVE_ALTERNATE}{}", printed("after", 0, 20)).as_bytes(),
        0,
    );

    let rows = retained(&engine);
    assert!(
        rows.iter().any(|row| row.contains("after")),
        "rows printed afterwards are kept"
    );
    assert!(
        rows.iter().all(|row| row.contains("after")),
        "no row from before comes back, those on the screen included: {rows:?}"
    );
}
