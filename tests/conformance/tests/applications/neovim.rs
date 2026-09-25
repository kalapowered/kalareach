//! Neovim: the alternate screen, a paste of every script, a click, the keyboard protocol it
//! negotiates, and a character split between two writes.

use std::path::{Path, PathBuf};

use kr_protocol::projection::ProjectedBuffer;

use crate::harness::{Launch, Screen, Session, application};
use crate::queries;

/// Neovim with no configuration, no swap file and no shared data. Arabic is drawn as the letters
/// were written rather than in the presentation forms Neovim substitutes by default, so the grid
/// can be compared with the text itself.
fn launch(nvim: &Path, file: &Path) -> Launch {
    Launch::new(nvim)
        .arguments(["--clean", "-n", "-i", "NONE", "--cmd", "set noarabicshape"])
        .arguments([file.to_string_lossy().into_owned()])
}

/// Writes `text` to a file in `directory`.
fn file(directory: &Path, name: &str, text: &str) -> PathBuf {
    let path = directory.join(name);
    std::fs::write(&path, text).expect("writes the file");
    path
}

/// The cursor Neovim reports in its ruler: the line and the screen column, from 1.
fn ruler(screen: &Screen) -> Option<(u64, u64)> {
    (0..screen.rows.len()).rev().find_map(|row| {
        screen.line(row).split_whitespace().find_map(|word| {
            let (line, column) = word.split_once(',')?;
            let line = line.parse::<u64>().ok()?;
            // `16-11` is the byte column and then the screen column; one number is both.
            let column = column.rsplit('-').next()?.parse::<u64>().ok()?;
            Some((line, column))
        })
    })
}

/// Shows that the program asked its terminal questions and that none of them reached the typing
/// terminal.
fn no_query_reached_the_terminal(session: &Session) {
    let asked = queries::find(&session.written());
    assert!(
        !asked.is_empty(),
        "Neovim asked its terminal nothing, so this case shows nothing about queries"
    );
    let reached = queries::find(&session.received());
    assert!(
        reached.is_empty(),
        "the queries Neovim asked reached the attached terminal: {}",
        reached
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    );
}

/// KR-ACC-004, KR-REQ-27.04: Neovim draws the file on the alternate screen, and leaving it puts
/// back the shell's screen as it was, with nothing of the file on it; every query it asked was
/// answered by the host and reached no attached terminal.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "runs the pinned applications; scripts/run-conformance.sh --group applications runs it"]
async fn the_alternate_screen_holds_the_file_and_leaves_the_shells_screen_as_it_was() {
    let nvim = application("neovim");
    let directory = tempfile::tempdir().expect("a directory");
    let path = file(
        directory.path(),
        "sample.txt",
        "plain ascii line\nsecond line\nthird line\n",
    );
    let mut session = Session::start(
        launch(&nvim.executable, &path).after("printf 'kr-after-nvim\\n'; read -r _"),
    )
    .await;
    let screen = session
        .wait_for("Neovim to draw the file", |screen| {
            screen.shows("third line")
        })
        .await;
    assert_eq!(screen.buffer, ProjectedBuffer::Alternate, "{screen}");
    assert_eq!(
        [screen.line(0), screen.line(1), screen.line(2)],
        ["plain ascii line", "second line", "third line"],
        "{screen}"
    );
    session.type_bytes(b":qa!\r");
    let screen = session
        .wait_for("the shell's line after Neovim", |screen| {
            screen.shows("kr-after-nvim")
        })
        .await;
    assert_eq!(screen.buffer, ProjectedBuffer::Primary, "{screen}");
    assert!(
        !screen.shows("plain ascii line"),
        "the file stayed on the primary screen:\n{screen}"
    );
    no_query_reached_the_terminal(&session);
}

/// Lines of text in a script, each followed by an ASCII marker whose column says how wide
/// everything before it was drawn. Neovim and section 8's model agree on every one of these.
const SCRIPTS: &[(&str, &str)] = &[
    ("CJK", "中文テキスト"),
    ("combining marks", "e\u{301}galite\u{301} n\u{303}"),
    ("Hebrew", "שלום עולם"),
    ("Arabic", "مرحبا بالعالم"),
    ("an emoji", "\u{1f600}"),
    ("a flag", "\u{1f1ff}\u{1f1e6}"),
];

/// Emoji sequences Neovim draws as one cluster two cells wide, and the width section 8's
/// per-codepoint model gives each: a wide emoji is two cells, a skin-tone modifier is a wide emoji
/// of its own, and the joiner is none.
const SEQUENCES: &[(&str, &str, u64)] = &[
    ("a skin tone", "\u{1f44b}\u{1f3fd}", 4),
    ("a joined sequence", "\u{1f469}\u{200d}\u{1f4bb}", 4),
];

/// Where one pasted sample landed: Neovim's column for its marker, the grid's, the grid's cursor
/// and the grid's row.
struct Landing {
    neovim_column: u64,
    grid_column: Option<u64>,
    cursor: (u64, u64),
    row: String,
}

/// Pastes each sample, followed by its marker, into Neovim, writes the file, checks that Neovim
/// received the paste byte for byte, and then puts Neovim's cursor on each marker in turn.
async fn paste_and_land(session: &mut Session, path: &Path, samples: &[&str]) -> Vec<Landing> {
    session
        .wait_for("Neovim to draw the empty file", |screen| {
            screen.shows("pasted.txt")
        })
        .await;
    let text: String = samples
        .iter()
        .map(|sample| format!("{sample}|end\n"))
        .collect();
    session.type_bytes(b"i");
    session.paste(&text);
    // Typed after the paste has landed, as a person would: Neovim takes a paste in pieces.
    session
        .wait_for("the paste to land", |screen| {
            (0..samples.len()).all(|row| screen.line(row).ends_with("|end"))
        })
        .await;
    // The Kitty keyboard protocol's escape, which is what Neovim asked its terminal to send.
    session.type_bytes(b"\x1b[27u");
    session.type_bytes(b":w\r");
    let expected = format!("{text}\n");
    let started = tokio::time::Instant::now();
    while std::fs::read_to_string(path).unwrap_or_default() != expected {
        assert!(
            started.elapsed() < crate::harness::LIVENESS,
            "Neovim wrote {:?} rather than the paste",
            std::fs::read_to_string(path).unwrap_or_default()
        );
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    let mut landings = Vec::new();
    for index in 0..samples.len() {
        let line = index as u64 + 1;
        // The cursor on the marker's `|`: the line, then the start of it, then the marker.
        session.type_bytes(format!("{line}G0f|").as_bytes());
        let screen = session
            .wait_for("the cursor on the marker", |screen| {
                ruler(screen).is_some_and(|(at, _)| at == line)
            })
            .await;
        let (_, column) = ruler(&screen).expect("a ruler");
        landings.push(Landing {
            neovim_column: column - 1,
            grid_column: crate::harness::ascii_suffix_column(&screen, index, "|end"),
            cursor: screen.cursor,
            row: screen.line(index),
        });
    }
    landings
}

/// KR-ACC-004, KR-REQ-27.04: a bracketed paste of CJK, combining marks, bidirectional text, an
/// emoji and a flag reaches Neovim byte for byte, and each line lands on the grid where Neovim puts
/// it: the row is the sample, and its marker and the grid's cursor are where Neovim's own cursor
/// says they are.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "runs the pinned applications; scripts/run-conformance.sh --group applications runs it"]
async fn a_pasted_line_of_every_script_lands_where_neovim_puts_it() {
    let nvim = application("neovim");
    let directory = tempfile::tempdir().expect("a directory");
    let path = file(directory.path(), "pasted.txt", "");
    let mut session = Session::start(launch(&nvim.executable, &path)).await;
    let samples: Vec<&str> = SCRIPTS.iter().map(|(_, sample)| *sample).collect();
    let landings = paste_and_land(&mut session, &path, &samples).await;
    let mut disagreements = Vec::new();
    for (row, ((script, sample), landing)) in SCRIPTS.iter().zip(&landings).enumerate() {
        if !landing.row.starts_with(sample) {
            disagreements.push(format!(
                "{script} ({}): the grid's row is {:?}",
                sample.escape_unicode(),
                landing.row
            ));
        }
        if landing.grid_column != Some(landing.neovim_column)
            || landing.cursor != (landing.neovim_column, row as u64)
        {
            disagreements.push(format!(
                "{script} ({}): Neovim puts the marker at column {}, the grid has it at {:?} and its cursor at {:?}",
                sample.escape_unicode(),
                landing.neovim_column,
                landing.grid_column,
                landing.cursor
            ));
        }
    }
    assert!(disagreements.is_empty(), "{}", disagreements.join("\n"));
    no_query_reached_the_terminal(&session);
}

/// KR-ACC-004, KR-REQ-27.04: an emoji sequence Neovim clusters is a known difference between
/// Neovim and the profile, and what the profile defines holds. Neovim draws a skin-tone sequence
/// and a joined sequence as one cluster two cells wide and puts the marker after it there; section
/// 8 pins widths per codepoint, so the grid gives each sequence four cells, and Neovim's marker
/// lands on the cells the sequence's second half took. The same file written straight to the
/// terminal puts each marker four cells in. The case records both readings as a known difference.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "runs the pinned applications; scripts/run-conformance.sh --group applications runs it"]
async fn an_emoji_sequence_neovim_clusters_is_drawn_per_codepoint_as_the_profile_defines() {
    const TEST: &str =
        "neovim::an_emoji_sequence_neovim_clusters_is_drawn_per_codepoint_as_the_profile_defines";
    let nvim = application("neovim");
    let directory = tempfile::tempdir().expect("a directory");
    let path = file(directory.path(), "pasted.txt", "");
    let mut session = Session::start(launch(&nvim.executable, &path).after(&format!(
        "cat '{}'; printf 'kr-written-out\\n'; read -r _",
        path.display()
    )))
    .await;
    let samples: Vec<&str> = SEQUENCES.iter().map(|(_, sample, _)| *sample).collect();
    let landings = paste_and_land(&mut session, &path, &samples).await;
    for ((script, _, _), landing) in SEQUENCES.iter().zip(&landings) {
        assert_eq!(
            landing.neovim_column, 2,
            "{script}: Neovim draws the sequence as one cluster of two cells"
        );
        assert_eq!(
            landing.grid_column,
            Some(2),
            "{script}: the grid holds the marker where Neovim put it"
        );
    }
    session.type_bytes(b":qa\r");
    let screen = session
        .wait_for("the file written out", |screen| {
            screen.shows("kr-written-out")
        })
        .await;
    for ((script, sample, cells), landing) in SEQUENCES.iter().zip(&landings) {
        let row = (0..screen.rows.len())
            .find(|row| screen.line(*row) == format!("{sample}|end"))
            .unwrap_or_else(|| panic!("{script}: the written-out line:\n{screen}"));
        assert_eq!(
            crate::harness::ascii_suffix_column(&screen, row, "|end"),
            Some(*cells),
            "{script}: the grid gives the sequence its per-codepoint width:\n{screen}"
        );
        crate::harness::known_difference(
            TEST,
            &format!("{script} ({})", sample.escape_unicode()),
            &format!(
                "Neovim draws it as one cluster of {} cells",
                landing.neovim_column
            ),
            &format!("section 8's per-codepoint widths give it {cells} cells"),
            &format!(
                "in Neovim the grid's row reads {:?}, the marker written over the sequence's second half; written straight to the terminal the row reads {:?}",
                landing.row,
                screen.line(row)
            ),
        );
    }
    no_query_reached_the_terminal(&session);
}

/// KR-ACC-004, KR-REQ-27.04: Neovim turns on button-event tracking in SGR form, and a click on a
/// wide character moves its cursor to that character, which the grid shows where Neovim does.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "runs the pinned applications; scripts/run-conformance.sh --group applications runs it"]
async fn a_click_in_sgr_form_moves_the_cursor_to_the_wide_character_it_was_on() {
    let nvim = application("neovim");
    let directory = tempfile::tempdir().expect("a directory");
    let path = file(
        directory.path(),
        "clicked.txt",
        "first line\n中文テキスト\n",
    );
    let mut session = Session::start(launch(&nvim.executable, &path)).await;
    let screen = session
        .wait_for("Neovim to draw the file", |screen| screen.shows("テキスト"))
        .await;
    assert!(screen.mode(1002), "button-event tracking: {}", screen.modes);
    assert!(screen.mode(1006), "the SGR form: {}", screen.modes);
    // Press and release the first button on the ninth cell of the second row: the character that
    // starts there is the fifth, `ス`, because each before it takes two cells.
    session.type_bytes(b"\x1b[<0;9;2M\x1b[<0;9;2m");
    let screen = session
        .wait_for("the cursor on the clicked character", |screen| {
            ruler(screen) == Some((2, 9))
        })
        .await;
    assert_eq!(screen.cursor, (8, 1), "{screen}");
    no_query_reached_the_terminal(&session);
}

/// KR-ACC-004, KR-REQ-27.04: Neovim asks for the Kitty keyboard protocol on its screen, the
/// session's snapshot records it, and keys typed in that protocol do what they mean: an escape
/// leaves insert mode and control-A increments the number under the cursor.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "runs the pinned applications; scripts/run-conformance.sh --group applications runs it"]
async fn keys_in_the_kitty_protocol_neovim_asks_for_do_what_they_mean() {
    let nvim = application("neovim");
    let directory = tempfile::tempdir().expect("a directory");
    let path = file(directory.path(), "keys.txt", "41\n");
    let mut session = Session::start(launch(&nvim.executable, &path)).await;
    let screen = session
        .wait_for("Neovim to draw the file", |screen| screen.shows("41"))
        .await;
    assert!(
        screen
            .keyboard
            .contains("alternate: KittyKeyboardState { flags: Nullable(Some(U64("),
        "Neovim's screen carries Kitty flags: {}",
        screen.keyboard
    );
    session.type_bytes(b"A");
    session
        .wait_for("insert mode", |screen| screen.shows("-- INSERT --"))
        .await;
    session.type_bytes(b"\x1b[27u");
    session
        .wait_for("normal mode", |screen| !screen.shows("-- INSERT --"))
        .await;
    // Control-A in the Kitty protocol: the `a` key with the control modifier.
    session.type_bytes(b"\x1b[97;5u");
    let screen = session
        .wait_for("the incremented number", |screen| screen.line(0) == "42")
        .await;
    assert_eq!(screen.line(0), "42", "{screen}");
    no_query_reached_the_terminal(&session);
}

/// KR-ACC-004, KR-REQ-27.04: a character whose UTF-8 bytes arrive in two writes reaches Neovim as
/// one character, and the grid draws it once, two cells wide.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "runs the pinned applications; scripts/run-conformance.sh --group applications runs it"]
async fn a_character_split_between_two_writes_arrives_whole() {
    let nvim = application("neovim");
    let directory = tempfile::tempdir().expect("a directory");
    let path = file(directory.path(), "split.txt", "");
    let mut session = Session::start(launch(&nvim.executable, &path)).await;
    session
        .wait_for("Neovim to draw the empty file", |screen| {
            screen.shows("split.txt")
        })
        .await;
    session.type_bytes(b"i");
    let bytes = "中".as_bytes();
    session.type_bytes(&bytes[..1]);
    session.type_bytes(&bytes[1..]);
    session.type_bytes(b"|end\x1b[27u:w\r");
    let started = tokio::time::Instant::now();
    while std::fs::read_to_string(&path).unwrap_or_default() != "中|end\n" {
        assert!(
            started.elapsed() < crate::harness::LIVENESS,
            "Neovim wrote {:?}",
            std::fs::read_to_string(&path).unwrap_or_default()
        );
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    let screen = session
        .wait_for("the character on the grid", |screen| {
            screen.line(0) == "中|end"
        })
        .await;
    assert_eq!(
        crate::harness::ascii_suffix_column(&screen, 0, "|end"),
        Some(2),
        "{screen}"
    );
    no_query_reached_the_terminal(&session);
}
