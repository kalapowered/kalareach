//! The rows above the live screen, and what it takes to keep none of them.
//!
//! An engine whose history is not kept gives up every row held above the live screen when that is
//! asked for and holds none between two calls afterwards, whichever buffer shows. The live screen
//! is the same before and after. A row that is on the screen when the history is kept again was
//! printed before that point, so it is given up when it leaves the screen, wherever the library
//! has moved it to by then. Rows are kept again after that.

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

fn feed(engine: &mut Engine, text: &str) {
    engine.feed(text.as_bytes(), 0);
}

fn printed(word: &str, from: usize, to: usize) -> String {
    (from..to)
        .map(|index| format!("{word} {index}\r\n"))
        .collect()
}

fn numbered(word: &str, from: usize, to: usize) -> Vec<String> {
    (from..to).map(|index| format!("{word} {index}")).collect()
}

fn text_of(rows: &[GridRow]) -> Vec<String> {
    rows.iter()
        .map(|row| {
            row.runs
                .iter()
                .map(|run| run.text.as_str())
                .collect::<String>()
                .trim_end()
                .to_string()
        })
        .collect()
}

/// The text of every row the engine holds above the live screen, oldest first. The primary buffer
/// is showing.
fn retained(engine: &Engine) -> Vec<String> {
    let grid = engine.grid();
    assert!(!grid.alternate_active(), "the primary buffer shows");
    let (oldest, _) = grid.stable_range();
    let count = usize::try_from(grid.visible_top_row() - oldest).expect("rows above the screen");
    text_of(&grid.history_rows(oldest, count))
}

/// Every row of text that the engine holds or shows on the primary screen, oldest first, without the
/// empty rows: what a person scrolling back from the bottom would read.
fn text_rows(engine: &Engine) -> Vec<String> {
    retained(engine)
        .into_iter()
        .chain(text_of(&engine.grid().visible_rows()))
        .filter(|row| !row.is_empty())
        .collect()
}

/// How many rows the primary buffer holds above its screen, whichever buffer shows.
fn held_above_primary(engine: &Engine) -> usize {
    let grid = engine.grid();
    let (start, end) = if grid.alternate_active() {
        grid.inactive_stable_range()
    } else {
        grid.stable_range()
    };
    usize::try_from(end - start)
        .expect("rows held")
        .saturating_sub(grid.size().rows as usize)
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

/// The whole state of both screens: the cells, the cursor, both saved cursors, the margins, the
/// deferred wrap and the pen.
fn state_of(engine: &Engine) -> String {
    let grid = engine.grid();
    format!(
        "{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}",
        grid.visible_rows(),
        grid.inactive_rows(),
        grid.cursor(),
        grid.saved_cursor(false),
        grid.saved_cursor(true),
        grid.margins_vertical(),
        grid.margins_horizontal(),
        grid.pending_wrap(),
        grid.pen(),
    )
}

/// An engine of twenty columns and four rows that had twenty rows printed while the history was
/// not being kept, and keeps it again. The screen holds `while 17` to `while 19` and the empty row
/// the cursor is on.
fn after_a_private_interval() -> Engine {
    let mut engine = engine(20, 4);
    engine.set_history_kept(false);
    feed(&mut engine, &printed("while", 0, 20));
    engine.set_history_kept(true);
    engine
}

fn assert_none_of(rows: &[String], words: &[&str]) {
    for row in rows {
        for word in words {
            assert!(
                !row.contains(word),
                "{word:?} is in a row that is kept: {rows:?}"
            );
        }
    }
}

#[test]
fn the_rows_above_the_screen_are_given_up_and_the_screen_is_not_changed() {
    let mut engine = engine(20, 4);
    feed(&mut engine, &printed("before", 0, 40));
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
fn the_whole_state_of_the_screen_is_the_same_at_the_enabling_and_at_the_disabling() {
    let mut engine = engine(20, 6);
    feed(&mut engine, &printed("before", 0, 30));
    // A saved cursor, margins on both axes, a pending wrap and a rendition on the pen.
    feed(
        &mut engine,
        "\x1b[2;4H\x1b7\x1b[?69h\x1b[3;12s\x1b[2;5r\x1b[1;31mred",
    );
    feed(&mut engine, "\x1b[5;20Hz");
    let sequence = engine.grid().sequence_number();
    let state = state_of(&engine);

    engine.set_history_kept(false);
    assert_eq!(state_of(&engine), state, "at the enabling");
    assert!(
        engine.grid().changed_rows_since(sequence).is_empty(),
        "no row reads as changed at the enabling"
    );

    engine.set_history_kept(true);
    assert_eq!(state_of(&engine), state, "at the disabling");
    assert!(
        engine.grid().changed_rows_since(sequence).is_empty(),
        "no row reads as changed at the disabling"
    );
}

#[test]
fn a_wrapped_line_and_a_wide_character_at_the_boundary_are_not_changed() {
    // Twenty columns of wide characters on a screen of eight: the line wraps over three rows, and
    // the next line pushes the first of them above a screen of three rows.
    let mut engine = engine(8, 3);
    feed(&mut engine, &format!("{}\r\nx", "\u{5168}".repeat(10)));
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
    feed(&mut engine, &printed("before", 0, 10));
    engine.set_history_kept(false);

    // A read of many screens, and then a row at a time.
    feed(&mut engine, &printed("while", 0, 5_000));
    assert!(retained(&engine).is_empty());
    assert_eq!(engine.grid().scrollback_rows(), 0);
    for index in 5_000..5_010 {
        feed(&mut engine, &printed("while", index, index + 1));
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
fn exactly_the_rows_printed_after_the_screen_has_gone_are_kept() {
    let mut engine = after_a_private_interval();
    assert!(retained(&engine).is_empty(), "turning it on starts empty");

    feed(&mut engine, &printed("after", 0, 20));

    // `after 0` was printed onto the row the cursor was on at the disabling, which is a row that
    // was on the screen then, so it is given up with the rows of the interval. Nothing after it is.
    assert_eq!(retained(&engine), numbered("after", 1, 17));
    assert_eq!(
        text_of(&engine.grid().visible_rows()),
        vec!["after 17", "after 18", "after 19", ""]
    );
}

#[test]
fn a_clear_scrollback_and_a_buffer_switch_without_a_clear_change_nothing_about_that() {
    // The program's own clear of the rows above the screen.
    let mut engine = after_a_private_interval();
    feed(&mut engine, "\x1b[3J");
    feed(&mut engine, &printed("after", 0, 20));
    assert_eq!(retained(&engine), numbered("after", 1, 17), "after CSI 3 J");

    // A switch to the alternate buffer that does not clear it, and back.
    let mut engine = after_a_private_interval();
    feed(&mut engine, "\x1b[?1047h");
    assert!(engine.grid().alternate_active());
    feed(&mut engine, "\x1b[?1047l");
    assert!(!engine.grid().alternate_active());
    feed(&mut engine, &printed("after", 0, 20));
    assert_eq!(
        retained(&engine),
        numbered("after", 1, 17),
        "after a switch"
    );
}

#[test]
fn a_full_reset_gives_up_the_next_screen_of_rows_and_keeps_the_rows_after_it() {
    let mut engine = after_a_private_interval();
    feed(&mut engine, "\x1bc");
    assert!(retained(&engine).is_empty());

    feed(&mut engine, &printed("after", 0, 20));

    // The reset blanks the lines on the screen in place. They still stand for the interval, so
    // the first screen of rows goes: this is what the rule gives up that it could keep.
    assert_eq!(retained(&engine), numbered("after", 4, 17));
}

#[test]
fn a_screen_clear_gives_up_the_next_screen_of_rows_like_a_full_reset() {
    let mut engine = after_a_private_interval();
    feed(&mut engine, "\x1b[2J\x1b[H");
    feed(&mut engine, &printed("after", 0, 20));

    assert_eq!(retained(&engine), numbered("after", 4, 17));
}

/// A line of ten columns whose first part was printed while rows were not kept and whose rest was
/// printed on a new line after that, then the rows that push both above a screen of four rows.
fn a_wrapped_line_that_began_in_the_interval(resize_first: bool) -> Vec<String> {
    let mut engine = engine(10, 4);
    engine.set_history_kept(false);
    feed(&mut engine, "a\r\nb\r\nc\r\nABCDEFGHIJ");
    engine.set_history_kept(true);
    // The rest wraps onto a new line, which was not on the screen at the disabling.
    feed(&mut engine, "klmno");
    if resize_first {
        // Wider, so the library joins the two parts into one line again.
        engine.resize(GridSize::new(20, 4), 0).expect("wider");
    }
    feed(&mut engine, &format!("\r\n{}", printed("z", 0, 12)));
    retained(&engine)
}

#[test]
fn a_resize_gives_up_the_rest_of_a_wrapped_line_whose_first_part_is_given_up_and_nothing_else() {
    let kept = a_wrapped_line_that_began_in_the_interval(false);
    let rejoined = a_wrapped_line_that_began_in_the_interval(true);

    assert_eq!(
        kept,
        [vec!["klmno".to_string()], numbered("z", 0, 9)].concat(),
        "without a resize the rest is its own row, and it is kept"
    );
    assert_eq!(
        rejoined,
        numbered("z", 0, 9),
        "the resize joined it to the first part, and the whole line is given up"
    );
}

#[test]
fn rows_are_kept_through_a_height_only_resize_that_gives_up_nothing_of_its_own() {
    let mut engine = after_a_private_interval();
    feed(&mut engine, &printed("after", 0, 3));
    engine.resize(GridSize::new(20, 5), 0).expect("taller");
    feed(&mut engine, &printed("later", 0, 10));

    assert_eq!(
        retained(&engine),
        [numbered("after", 1, 3), numbered("later", 0, 6)].concat()
    );
}

#[test]
fn rows_are_kept_through_a_resize_to_the_same_size_and_a_width_only_resize() {
    // While an old row of the interval and fresh rows share the screen: the screen of six rows holds
    // `while 18` and `while 19`, `after 0` (printed onto a row that was on the screen at the
    // disabling) and the fresh rows `after 1` and `after 2`. A resize that gave up what is above the
    // screen, or marked the rows on it, would lose `after 1` and `after 2` here.
    for (note, columns) in [
        ("without a resize", None),
        ("a resize to the size it has", Some(20)),
        ("a wider screen", Some(21)),
        ("a narrower screen that splits no row", Some(12)),
    ] {
        let mut engine = engine(20, 6);
        engine.set_history_kept(false);
        feed(&mut engine, &printed("while", 0, 20));
        engine.set_history_kept(true);
        feed(&mut engine, &printed("after", 0, 3));
        assert_eq!(
            text_of(&engine.grid().visible_rows()),
            vec!["while 18", "while 19", "after 0", "after 1", "after 2", ""]
        );
        if let Some(columns) = columns {
            engine
                .resize(GridSize::new(columns, 6), 0)
                .expect("resizes");
        }
        feed(&mut engine, &format!("\r\n{}", printed("later", 0, 12)));

        assert_eq!(
            text_rows(&engine),
            [numbered("after", 1, 3), numbered("later", 0, 12)].concat(),
            "{note}: the complete list of rows kept"
        );
    }

    // After every row of the interval has left the screen.
    let mut engine = after_a_private_interval();
    feed(&mut engine, &printed("after", 0, 12));
    // The screen holds `after 9` to `after 11` and the row the cursor is on; `after 0` was
    // printed onto a row that was on the screen at the disabling.
    let kept = numbered("after", 1, 9);
    assert_eq!(retained(&engine), kept);

    engine
        .resize(GridSize::new(20, 4), 0)
        .expect("the same size");
    assert_eq!(retained(&engine), kept, "after a resize to the size it has");

    engine.resize(GridSize::new(21, 4), 0).expect("wider");
    assert_eq!(retained(&engine), kept, "after a wider screen");

    // A narrower screen that splits no row. The library moves the row above the screen onto it when
    // the empty row under the cursor goes, so the rows held and the rows shown are read together.
    engine.resize(GridSize::new(12, 4), 0).expect("narrower");
    assert_eq!(
        text_rows(&engine),
        numbered("after", 1, 12),
        "after a narrower screen: none of the rows is joined, cut or given up"
    );
    feed(&mut engine, &format!("\r\n{}", printed("later", 0, 4)));
    assert_eq!(
        text_rows(&engine),
        [numbered("after", 1, 12), numbered("later", 0, 4)].concat(),
        "and the rows that come after are kept"
    );
}

#[test]
fn a_resize_that_joins_the_parts_of_a_wrapped_line_gives_up_the_first_part_when_the_rest_is_given_up()
 {
    // The rest of the line is marked and the first part is a fresh row. Without a resize the first
    // part is kept; a resize that joins them gives up the whole line, and the fresh rows that leave
    // while it stays on the screen below them.
    let kept = |resize: bool| -> Vec<String> {
        let mut engine = engine(20, 4);
        engine.set_history_kept(false);
        feed(&mut engine, "a\r\nb\r\nc\r\nd");
        engine.set_history_kept(true);
        // A fresh row at the top, and twenty-five characters from its start: twenty fill it and five
        // wrap onto the row of the interval that stands under it.
        feed(&mut engine, "\x1b[H\x1bM0123456789ABCDEFGHIJKLMNO");
        if resize {
            engine.resize(GridSize::new(30, 4), 0).expect("wider");
        }
        // Three fresh rows at the top push the rows of the interval off the bottom, then three rows
        // are printed on them and scrolled away.
        feed(&mut engine, "\x1b[H\x1bM\x1bM\x1bM");
        feed(&mut engine, "g3\r\ng2\r\ng1");
        feed(&mut engine, "\x1b[4;1H\n\n\n\n\n\n");
        retained(&engine)
    };

    assert_eq!(
        kept(false),
        ["g3", "g2", "g1", "0123456789ABCDEFGHIJ", "", ""],
        "without a resize the first part and the rows after it are kept"
    );
    assert_eq!(
        kept(true),
        ["", ""],
        "after the join the whole line is a row of the interval, and none of them is kept"
    );
}

#[test]
fn a_scroll_inside_margins_carries_the_rule_to_the_line_that_receives_the_cells() {
    // A clear at the disabling, four rows printed onto the cleared lines, and a run of rows after
    // them from the bottom of the screen.
    let kept = |scroll_in_margins: bool| -> Vec<String> {
        let mut engine = after_a_private_interval();
        feed(&mut engine, "\x1b[2J\x1b[H");
        feed(&mut engine, &printed("after", 0, 4));
        if scroll_in_margins {
            // One reverse index inside columns 1 to 10: the fresh row at the bottom receives the cells
            // of the marked row above it.
            feed(
                &mut engine,
                "\x1b[?69h\x1b[1;10s\x1b[H\x1bM\x1b[1;20s\x1b[?69l",
            );
        }
        feed(&mut engine, "\x1b[4;1H");
        feed(&mut engine, &printed("later", 0, 12));
        retained(&engine)
    };

    assert_eq!(
        kept(false),
        numbered("later", 0, 9),
        "four rows are given up: `after 0` to `after 3`"
    );
    assert_eq!(
        kept(true),
        numbered("later", 1, 9),
        "five are: the fresh row that received the cells took the rule with them"
    );
}

#[test]
fn a_resize_does_not_let_the_rows_on_the_screen_be_kept() {
    // Rows of seventeen columns on a screen of twenty. Narrowed to ten, each splits in two, so the
    // library's numbers of rows move.
    let mut engine = engine(20, 4);
    feed(&mut engine, &printed("before 0123456", 0, 20));
    engine.set_history_kept(false);
    feed(&mut engine, &printed("while 0123456", 0, 6));
    engine.set_history_kept(true);

    engine.resize(GridSize::new(10, 4), 0).expect("narrower");
    assert!(
        retained(&engine).is_empty(),
        "the rows a narrower screen moved above it are given up in the call"
    );
    feed(&mut engine, &printed("after", 0, 20));

    let rows = retained(&engine);
    assert!(rows.iter().any(|row| row.contains("after")));
    assert!(
        rows.iter().all(|row| row.contains("after")),
        "no half of a row that was on the screen is kept: {rows:?}"
    );
}

#[test]
fn a_shorter_resize_while_rows_are_not_kept_holds_nothing_when_it_returns() {
    let mut engine = engine(20, 4);
    engine.set_history_kept(false);
    feed(&mut engine, &printed("while", 0, 20));

    engine.resize(GridSize::new(20, 2), 0).expect("shorter");

    assert!(retained(&engine).is_empty(), "read at once, before output");
    assert_eq!(engine.grid().history_bytes(), 0);
    assert_eq!(text_of(&engine.grid().visible_rows()), vec!["while 19", ""]);
}

#[test]
fn a_width_only_resize_after_a_clear_brings_no_earlier_row_onto_the_screen() {
    let mut engine = engine(20, 4);
    feed(&mut engine, &printed("before", 0, 20));
    engine.set_history_kept(false);
    // Ctrl-L: the shell clears the screen and draws its prompt at the top.
    feed(&mut engine, "\x1b[H\x1b[2Jprompt");

    engine.resize(GridSize::new(21, 4), 0).expect("wider");

    assert_none_of(&text_of(&engine.grid().visible_rows()), &["before"]);
    assert!(retained(&engine).is_empty());
}

#[test]
fn a_reverse_index_does_not_carry_an_earlier_row_into_the_kept_rows() {
    let mut engine = after_a_private_interval();
    feed(&mut engine, "after 0\r\n\x1b[H\x1bM\x1bM");
    feed(&mut engine, "\x1b[4;1H\n\n\n\n");

    assert_none_of(&retained(&engine), &["while"]);
    assert!(retained(&engine).is_empty(), "{:?}", retained(&engine));
}

#[test]
fn an_insert_line_does_not_carry_an_earlier_row_into_the_kept_rows() {
    let mut engine = after_a_private_interval();
    feed(&mut engine, "after 0\r\n\x1b[H\x1b[2L");
    feed(&mut engine, "\x1b[4;1H\n\n\n\n");

    assert_none_of(&retained(&engine), &["while"]);
    assert!(retained(&engine).is_empty(), "{:?}", retained(&engine));
}

#[test]
fn a_scroll_down_does_not_carry_an_earlier_row_into_the_kept_rows() {
    // The sequence of the second section's order: the row of the interval is the cursor's row.
    let mut engine = engine(20, 4);
    engine.set_history_kept(false);
    feed(&mut engine, "A\r\nB\r\nC\r\nSECRET\r");
    engine.set_history_kept(true);

    feed(&mut engine, "\n\x1b[1T\x1b[4;1H\n\n\n\n");

    assert_none_of(&retained(&engine), &["SECRET", "A", "B", "C"]);
}

#[test]
fn a_region_at_the_top_keeps_no_row_while_a_row_of_the_interval_stays_below_it() {
    let mut engine = engine(20, 4);
    engine.set_history_kept(false);
    feed(&mut engine, &printed("while", 0, 6));
    feed(&mut engine, "\x1b[4;1HSTATUS");
    engine.set_history_kept(true);

    // Three rows at the top scroll, and STATUS stays on the screen below them.
    feed(&mut engine, "\x1b[1;3r\x1b[3;1H");
    feed(&mut engine, &printed("in", 0, 10));
    assert!(
        retained(&engine).is_empty(),
        "no row leaves the region while STATUS stays below it: {:?}",
        retained(&engine)
    );

    // The region ends, STATUS leaves, and the rows after it are kept.
    feed(&mut engine, "\x1b[r\x1b[4;1H");
    feed(&mut engine, &printed("later", 0, 12));
    let rows = retained(&engine);
    assert_none_of(&rows, &["STATUS", "while", "in "]);
    assert!(rows.iter().any(|row| row.contains("later")), "{rows:?}");
}

#[test]
fn a_downward_copy_inside_margins_carries_the_row_of_the_interval_with_it() {
    let mut engine = after_a_private_interval();
    // One scroll gives the screen a fresh last row, then two copies of cells downward inside the
    // columns 1 to 10 put `while 19` into it. The margins are put back before the rows scroll off.
    feed(&mut engine, "\n");
    feed(&mut engine, "\x1b[?69h\x1b[1;10s\x1bM\x1bM");
    assert_eq!(
        text_of(&engine.grid().visible_rows())[3],
        "while 19",
        "the cells were copied into the fresh row"
    );
    feed(&mut engine, "\x1b[1;20s\x1b[?69l\x1b[4;1H\n\n\n\n");

    assert_none_of(&retained(&engine), &["while"]);
}

#[test]
fn an_upward_copy_inside_margins_carries_the_row_of_the_interval_with_it() {
    let mut engine = after_a_private_interval();
    // Two line feeds and three reverse indexes put three fresh rows above `while 19`, which is the
    // last row. A copy of cells upward inside the columns 1 to 10 puts `while 19` into the third
    // fresh row and blanks it where it was, and one more reverse index removes that row.
    feed(&mut engine, "\n\n\x1b[H\x1bM\x1bM\x1bM");
    assert_eq!(text_of(&engine.grid().visible_rows())[3], "while 19");
    feed(&mut engine, "\x1b[?69h\x1b[1;10s\x1b[S");
    assert_eq!(
        text_of(&engine.grid().visible_rows()),
        vec!["", "", "while 19", ""],
        "the cells were copied into a fresh row"
    );
    feed(&mut engine, "\x1b[1;20s\x1b[?69l\x1b[H\x1bM");
    feed(&mut engine, "\x1b[4;1H\n\n\n\n\n");

    assert_none_of(&retained(&engine), &["while"]);
}

#[test]
fn the_newest_marked_row_split_by_a_narrower_screen_is_given_up_whole() {
    let mut engine = engine(20, 4);
    engine.set_history_kept(false);
    feed(&mut engine, &printed("while", 0, 20));
    feed(&mut engine, "while 20 xxxxxxxxx");
    engine.set_history_kept(true);

    feed(&mut engine, "\n");
    engine.resize(GridSize::new(10, 10), 0).expect("narrower");
    feed(&mut engine, &printed("after", 0, 30));

    assert_none_of(&retained(&engine), &["while", "xxxx"]);
}

#[test]
fn the_newest_marked_row_joined_to_a_row_of_the_interval_is_given_up_whole() {
    let mut engine = engine(20, 4);
    engine.set_history_kept(false);
    feed(&mut engine, &printed("while", 0, 20));
    feed(&mut engine, "while 20");
    engine.set_history_kept(true);

    // The row moves to the second line of the screen, a fresh row goes above it, and letters that
    // wrap from the fresh row onto it make the two one logical line.
    feed(&mut engine, "\n\n\n\x1b[H\x1bMABCDEFGHIJKLMNOPQRSTUVW");
    engine.resize(GridSize::new(30, 4), 0).expect("wider");
    // The cursor goes to the bottom row, off the joined line, so that nothing printed afterwards
    // overwrites the cells that the list below is read for.
    feed(&mut engine, "\x1b[4;1H");
    feed(&mut engine, &printed("after", 0, 30));

    assert_eq!(
        retained(&engine),
        [vec![String::new(); 2], numbered("after", 0, 27)].concat(),
        "the joined line is not kept, whole or in part, and nothing else is lost"
    );
}

#[test]
fn a_blank_row_that_holds_a_link_is_given_up_when_a_narrower_screen_rebuilds_it() {
    let mut engine = engine(20, 4);
    engine.set_history_kept(false);
    feed(&mut engine, &printed("while", 0, 20));
    // The link covers twelve columns, more than the ten of the narrower screen, so the row is wider
    // than the screen it is handed back to and the grid rebuilds it.
    feed(
        &mut engine,
        "\x1b]8;;https://link.example/\x1b\\            \x1b]8;;\x1b\\\r\n",
    );
    engine.set_history_kept(true);

    engine.resize(GridSize::new(10, 4), 0).expect("narrower");
    feed(&mut engine, &printed("after", 0, 30));

    assert!(
        engine.grid().link_census().links.is_empty(),
        "no row that is kept holds the link: {:?}",
        engine.grid().link_census().links
    );
}

#[test]
fn a_full_reset_while_rows_are_not_kept_keeps_none_and_changes_no_other_rule() {
    let mut engine = engine(20, 4);
    engine.set_history_kept(false);
    feed(&mut engine, &printed("while", 0, 10));
    feed(&mut engine, "\x1bc");
    feed(&mut engine, &printed("while", 10, 30));
    assert!(retained(&engine).is_empty());
    engine.set_history_kept(true);
    feed(&mut engine, &printed("after", 0, 20));
    assert_eq!(retained(&engine), numbered("after", 1, 17));
}

// The alternate buffer. The primary buffer's rows are given up in the call that asks, and a resize
// that the library does on both buffers brings none of them back.

fn print_then_enter_the_alternate_buffer() -> Engine {
    let mut engine = engine(20, 4);
    feed(&mut engine, &printed("before", 0, 20));
    feed(&mut engine, ENTER_ALTERNATE);
    feed(&mut engine, "\x1b[2J\x1b[Happ");
    assert!(engine.grid().alternate_active());
    engine
}

#[test]
fn the_rows_are_given_up_at_the_enabling_while_the_alternate_buffer_shows() {
    let mut engine = print_then_enter_the_alternate_buffer();
    assert!(held_above_primary(&engine) > 0, "held before the call");
    let app = screen_of(&mut engine);

    engine.set_history_kept(false);

    assert_eq!(held_above_primary(&engine), 0, "nothing is owed");
    assert_eq!(
        screen_of(&mut engine),
        app,
        "neither buffer's screen is changed"
    );
    assert_eq!(
        text_of(&engine.grid().inactive_rows()),
        vec!["before 17", "before 18", "before 19", ""],
        "the primary buffer's own screen is as it was"
    );
}

#[test]
fn a_taller_resize_under_the_alternate_buffer_brings_no_earlier_row_back() {
    let mut engine = print_then_enter_the_alternate_buffer();
    engine.set_history_kept(false);

    engine.resize(GridSize::new(20, 8), 0).expect("taller");

    assert_eq!(held_above_primary(&engine), 0);
    assert_eq!(
        text_of(&engine.grid().inactive_rows()),
        vec!["before 17", "before 18", "before 19", "", "", "", "", ""],
        "the page the host reads at once"
    );
    feed(&mut engine, LEAVE_ALTERNATE);
    assert_eq!(
        text_of(&engine.grid().visible_rows()),
        vec!["before 17", "before 18", "before 19", "", "", "", "", ""],
        "the screen when the program leaves"
    );
    assert!(retained(&engine).is_empty());
}

#[test]
fn a_taller_resize_then_the_disabling_before_the_program_leaves_brings_no_earlier_row_back() {
    let mut engine = print_then_enter_the_alternate_buffer();
    engine.set_history_kept(false);
    engine.resize(GridSize::new(20, 8), 0).expect("taller");
    engine.set_history_kept(true);

    feed(&mut engine, LEAVE_ALTERNATE);

    assert_eq!(
        text_of(&engine.grid().visible_rows()),
        vec!["before 17", "before 18", "before 19", "", "", "", "", ""]
    );
    assert!(retained(&engine).is_empty());
}

#[test]
fn a_width_only_resize_after_a_clear_under_the_alternate_buffer_brings_no_earlier_row_back() {
    let mut engine = engine(20, 4);
    feed(&mut engine, &printed("before", 0, 20));
    // Ctrl-L before the program starts, then the program.
    feed(&mut engine, "\x1b[H\x1b[2Jprompt");
    feed(&mut engine, ENTER_ALTERNATE);
    engine.set_history_kept(false);

    engine.resize(GridSize::new(21, 4), 0).expect("wider");
    assert_none_of(&text_of(&engine.grid().inactive_rows()), &["before"]);
    feed(&mut engine, LEAVE_ALTERNATE);

    assert_none_of(&text_of(&engine.grid().visible_rows()), &["before"]);
    assert!(
        text_of(&engine.grid().visible_rows())
            .iter()
            .any(|row| row == "prompt")
    );
}

#[test]
fn growth_and_shrink_then_growth_under_the_alternate_buffer_bring_no_earlier_row_back() {
    let mut engine = print_then_enter_the_alternate_buffer();
    engine.set_history_kept(false);

    engine.resize(GridSize::new(20, 2), 0).expect("shorter");
    assert_eq!(held_above_primary(&engine), 0, "read at once after it");
    engine.resize(GridSize::new(20, 8), 0).expect("taller");
    assert_eq!(held_above_primary(&engine), 0);
    assert_none_of(
        &text_of(&engine.grid().inactive_rows()),
        &["before 17", "before 18", "before 16"],
    );
    feed(&mut engine, LEAVE_ALTERNATE);

    assert_none_of(
        &text_of(&engine.grid().visible_rows()),
        &["before 17", "before 18", "before 16"],
    );
    assert!(retained(&engine).is_empty());
}

#[test]
fn rows_printed_after_the_program_leaves_are_kept_once_the_screen_has_gone() {
    let mut engine = print_then_enter_the_alternate_buffer();
    engine.set_history_kept(false);
    engine.set_history_kept(true);

    feed(
        &mut engine,
        &format!("{LEAVE_ALTERNATE}{}", printed("after", 0, 20)),
    );

    // The primary screen holds `before 17` to `before 19` and the row the cursor was on, all
    // printed before the disabling, and the rows after them are kept.
    assert_eq!(retained(&engine), numbered("after", 1, 17));
}
