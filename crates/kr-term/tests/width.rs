//! The width model a phone measures with is the terminal library's own.
//!
//! `kr-width` measures text for every client, including those on platforms the terminal state
//! library does not build for. That is only sound if it comes out the same as the library's own
//! function for every input the profile can meet, so this holds the two together: every scalar,
//! the rows of the committed width fixture, and a generated corpus of sequences.

use kr_term::unicode::{self, UnicodeModel};
use kr_width as width;
use wezterm_term::grapheme_column_width;

fn library(text: &str) -> usize {
    grapheme_column_width(text, Some(&UnicodeModel::KR_VT_1.to_library()))
}

/// The scalars below U+0300 with no cells in the table that `is_zero_width` still calls cells: the
/// C0 and C1 controls, which never reach it, and the soft hyphen, which does.
fn below_the_shortcut(scalar: char) -> bool {
    let value = scalar as u32;
    value < 0x20 || (0x7f..0xa0).contains(&value) || value == 0xad
}

#[test]
fn every_scalar_measures_as_the_library_measures_it() {
    let mut checked = 0_u32;
    for value in 0..=0x0010_ffff_u32 {
        let Some(scalar) = char::from_u32(value) else {
            continue;
        };
        let mut buffer = [0_u8; 4];
        let text: &str = scalar.encode_utf8(&mut buffer);
        assert_eq!(width::cells_for(text), library(text), "U+{value:04X}");
        assert_eq!(unicode::cells_for(text), width::cells_for(text));
        // The shortcut below U+0300 is the one place the zero-width test does not ask the table.
        let asks_the_table = value >= 0x0300;
        let zero = library(text) == 0;
        if !asks_the_table && !below_the_shortcut(scalar) {
            assert!(
                !zero,
                "U+{value:04X} has no cells and is not one the shortcut skips"
            );
        }
        if asks_the_table || !below_the_shortcut(scalar) {
            assert_eq!(
                width::is_zero_width(scalar),
                asks_the_table && zero,
                "U+{value:04X}"
            );
        } else {
            assert!(!width::is_zero_width(scalar), "U+{value:04X}");
            assert!(
                zero,
                "U+{value:04X} is one of the scalars the shortcut skips"
            );
        }
        checked += 1;
    }
    assert!(checked > 1_100_000, "every scalar was checked ({checked})");
}

/// A run measures as the sum of its scalars, not as one call to the library's cluster function,
/// which caps at two cells and folds joined sequences.
#[test]
fn a_run_measures_as_the_sum_of_its_scalars() {
    for text in [
        "",
        "abc",
        "\u{4e2d}\u{6587}",
        "e\u{301}",
        "\u{1f468}\u{200d}\u{1f469}\u{200d}\u{1f467}",
        "\u{1f1fa}\u{1f1f8}",
        "1\u{fe0f}\u{20e3}",
        "\u{1100}\u{1161}\u{11a8}",
    ] {
        let expected: usize = text
            .chars()
            .map(|scalar| {
                let mut buffer = [0_u8; 4];
                library(scalar.encode_utf8(&mut buffer))
            })
            .sum();
        assert_eq!(width::cells_for(text), expected, "{text:?}");
    }
    assert!(
        width::cells_for("\u{1f468}\u{200d}\u{1f469}\u{200d}\u{1f467}") > 2,
        "the library's cluster function would say two"
    );
}

/// A pseudo-random corpus of scalars taken from every block the tables distinguish, joined into
/// runs, measured both ways.
#[test]
fn a_generated_corpus_measures_alike() {
    let mut state = 0x9e37_79b9_7f4a_7c15_u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for _ in 0..20_000 {
        let length = usize::try_from(next() % 12).unwrap_or(0) + 1;
        let text: String = (0..length)
            .filter_map(|_| {
                let pool = match next() % 6 {
                    0 => 0x20..0x7f,
                    1 => 0x0300..0x0370,
                    2 => 0x1100..0x1200,
                    3 => 0x2e80..0xa000,
                    4 => 0x1f300..0x1fb00,
                    _ => 0..0x0011_0000,
                };
                let span = u64::from(pool.end - pool.start);
                char::from_u32(pool.start + u32::try_from(next() % span).unwrap_or(0))
            })
            .collect();
        let expected: usize = text
            .chars()
            .map(|scalar| {
                let mut buffer = [0_u8; 4];
                library(scalar.encode_utf8(&mut buffer))
            })
            .sum();
        assert_eq!(width::cells_for(&text), expected, "{text:?}");
        assert_eq!(
            width::last_cell_start(if text.is_empty() { "a" } else { &text }),
            unicode::last_cell_start(if text.is_empty() { "a" } else { &text })
        );
    }
}

/// The rows of the committed width fixture measure as the library's cells say.
#[test]
fn the_width_fixture_rows_measure_as_the_grid_placed_them() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("fixtures")
        .join("terminal")
        .join("width.json");
    let fixture: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(path).expect("the fixture")).expect("json");
    let mut rows = 0;
    for case in fixture["cases"].as_array().expect("cases") {
        for row in case["screen"].as_array().expect("a screen") {
            let text = row["text"].as_str().expect("text");
            let cells = row["cells"].as_u64().expect("cells");
            if text.is_empty() {
                continue;
            }
            rows += 1;
            assert_eq!(
                width::cells_for(text) as u64,
                cells,
                "{} row {text:?}",
                case["id"]
            );
        }
    }
    assert!(rows >= 8, "the fixture has rows with text ({rows})");
}
