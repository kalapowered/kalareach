//! The steps a terminal is measured with.
//!
//! Each step is the bytes written after a full reset, and the answer is where the cursor is
//! afterwards. The steps are grouped by the rule they exercise. Several depend on the window's
//! size, because the interesting place for a wrapping rule is the last column, so the corpus is
//! built for the size the terminal reports.

/// One step of the corpus.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    /// A stable name, unique in the corpus.
    pub id: String,
    /// The rule the step exercises.
    pub group: &'static str,
    /// What the step writes after the reset.
    pub bytes: Vec<u8>,
}

fn step(group: &'static str, id: &str, text: impl AsRef<[u8]>) -> Step {
    Step {
        id: format!("{group}.{id}"),
        group,
        bytes: text.as_ref().to_vec(),
    }
}

/// `text` repeated `count` times.
fn run(text: &str, count: u32) -> String {
    text.repeat(usize::try_from(count).unwrap_or(0))
}

/// Every step, for a window of `cols` columns and `rows` rows.
///
/// # Panics
///
/// Panics when the window is smaller than the corpus needs to place its margins and stops, which no
/// real terminal window is: 40 columns by 12 rows is the least.
#[must_use]
pub fn steps(cols: u32, rows: u32) -> Vec<Step> {
    assert!(
        cols >= 40 && rows >= 12,
        "the corpus needs 40 by 12 at least"
    );
    let last = cols;
    let mut all = Vec::new();
    all.extend(addressing(cols, rows));
    all.extend(autowrap(cols, rows));
    all.extend(margins(rows));
    all.extend(tabs(cols));
    all.extend(widths(last));
    all.extend(alternate_screen(rows));
    all.extend(controls(rows));
    all
}

fn addressing(cols: u32, rows: u32) -> Vec<Step> {
    let g = "addressing";
    vec![
        step(g, "absolute", "\x1b[5;10H"),
        step(g, "clamps-to-the-corner", "\x1b[9999;9999H"),
        step(g, "default-is-home", "\x1b[7;9H\x1b[H"),
        step(g, "up-stops-at-the-top", "\x1b[3;4H\x1b[99A"),
        step(g, "down-stops-at-the-bottom", "\x1b[3;4H\x1b[999B"),
        step(g, "right-stops-at-the-edge", "\x1b[3;4H\x1b[999C"),
        step(g, "left-stops-at-the-edge", "\x1b[3;4H\x1b[999D"),
        step(g, "column-absolute", "\x1b[3;4H\x1b[30G"),
        step(g, "row-absolute", "\x1b[3;4H\x1b[12d"),
        step(g, "next-line", "\x1b[3;4H\x1b[2E"),
        step(g, "previous-line", "\x1b[6;4H\x1b[2F"),
        step(g, "save-and-restore", "\x1b[5;6H\x1b7\x1b[1;1H\x1b8"),
        step(g, "save-and-restore-csi", "\x1b[5;6H\x1b[s\x1b[1;1H\x1b[u"),
        step(
            g,
            "column-past-the-edge",
            format!("\x1b[3;4H\x1b[{}G", cols + 50),
        ),
        step(
            g,
            "row-past-the-edge",
            format!("\x1b[3;4H\x1b[{}d", rows + 50),
        ),
    ]
}

fn autowrap(cols: u32, rows: u32) -> Vec<Step> {
    let g = "autowrap";
    let fill = run("a", cols);
    vec![
        step(g, "fill-a-row-leaves-the-wrap-pending", &fill),
        step(g, "one-more-wraps", run("a", cols + 1)),
        step(g, "two-rows-and-three", run("a", 2 * cols + 3)),
        step(
            g,
            "off-holds-at-the-edge",
            format!("\x1b[?7l{}", run("a", cols + 5)),
        ),
        step(g, "pending-then-return", format!("{fill}\r")),
        step(g, "pending-then-line-feed", format!("{fill}\n")),
        step(g, "pending-then-left", format!("{fill}\x1b[D")),
        step(g, "pending-then-right", format!("{fill}\x1b[C")),
        step(g, "pending-then-backspace", format!("{fill}\x08")),
        step(
            g,
            "pending-cleared-by-addressing",
            format!("{fill}\x1b[1;{cols}Hb"),
        ),
        step(g, "pending-survives-erase-line", format!("{fill}\x1b[Kb")),
        step(
            g,
            "pending-survives-save-and-restore",
            format!("{fill}\x1b7\x1b[H\x1b8x"),
        ),
        step(
            g,
            "last-row-scrolls",
            format!("\x1b[{rows};1H{}", run("a", cols + 1)),
        ),
        step(
            g,
            "pending-on-the-last-row-then-line-feed",
            format!("\x1b[{rows};1H{fill}\n"),
        ),
        step(
            g,
            "insert-mode-at-the-edge",
            format!("\x1b[4h\x1b[1;{cols}Hxy"),
        ),
    ]
}

fn margins(rows: u32) -> Vec<Step> {
    let g = "margins";
    let below = rows.min(11) + 1;
    vec![
        step(g, "region-homes-the-cursor", "\x1b[3;4H\x1b[5;10r"),
        step(
            g,
            "line-feed-at-the-bottom-margin",
            "\x1b[5;10r\x1b[10;3H\n",
        ),
        step(g, "line-feed-below-the-region", "\x1b[5;10r\x1b[11;3H\n"),
        step(g, "index-at-the-bottom-margin", "\x1b[5;10r\x1b[10;3H\x1bD"),
        step(
            g,
            "reverse-index-at-the-top-margin",
            "\x1b[5;10r\x1b[5;3H\x1bM",
        ),
        step(
            g,
            "reverse-index-above-the-region",
            "\x1b[5;10r\x1b[4;3H\x1bM",
        ),
        step(
            g,
            "reverse-index-at-the-top-of-the-screen",
            "\x1b[5;10r\x1b[1;3H\x1bM",
        ),
        step(
            g,
            "next-line-at-the-bottom-margin",
            "\x1b[5;10r\x1b[10;3H\x1bE",
        ),
        step(
            g,
            "scroll-up-keeps-the-cursor",
            "\x1b[5;10r\x1b[7;3H\x1b[3S",
        ),
        step(
            g,
            "scroll-down-keeps-the-cursor",
            "\x1b[5;10r\x1b[7;3H\x1b[3T",
        ),
        step(
            g,
            "down-stops-at-the-bottom-margin",
            "\x1b[5;10r\x1b[6;3H\x1b[99B",
        ),
        step(
            g,
            "up-stops-at-the-top-margin",
            "\x1b[5;10r\x1b[8;3H\x1b[99A",
        ),
        step(
            g,
            "down-passes-a-margin-from-outside",
            "\x1b[5;10r\x1b[11;3H\x1b[99B",
        ),
        step(
            g,
            "addressing-leaves-the-region",
            format!("\x1b[5;10r\x1b[{below};1H"),
        ),
        step(g, "origin-mode-is-relative", "\x1b[5;10r\x1b[?6h\x1b[2;3H"),
        step(
            g,
            "origin-mode-clamps-to-the-region",
            "\x1b[5;10r\x1b[?6h\x1b[99;3H",
        ),
        step(
            g,
            "insert-line-moves-to-the-first-column",
            "\x1b[3;9H\x1b[2L",
        ),
        step(
            g,
            "delete-line-moves-to-the-first-column",
            "\x1b[3;9H\x1b[2M",
        ),
        step(
            g,
            "left-and-right-margins-wrap",
            "\x1b[?69h\x1b[5;20s\x1b[1;5H01234567890123456789x",
        ),
        step(
            g,
            "left-and-right-margins-clamp",
            "\x1b[?69h\x1b[5;20s\x1b[1;7H\x1b[99C",
        ),
        step(
            g,
            "return-goes-to-the-left-margin",
            "\x1b[?69h\x1b[5;20s\x1b[1;9H\r",
        ),
        step(g, "region-off-again", "\x1b[5;10r\x1b[r\x1b[10;1H\n"),
    ]
}

fn tabs(cols: u32) -> Vec<Step> {
    let g = "tabs";
    let near = cols - 2;
    vec![
        step(g, "default-stop", "\t"),
        step(g, "three-default-stops", "\t\t\t"),
        step(g, "past-the-last-stop", format!("\x1b[1;{near}H\t\t")),
        step(g, "none-set-goes-to-the-edge", "\x1b[3g\t"),
        step(g, "a-stop-set-by-hand", "\x1b[3g\x1b[1;20H\x1bH\x1b[1;1H\t"),
        step(g, "one-stop-cleared", "\x1b[1;9H\x1b[0g\x1b[1;1H\t"),
        step(g, "backward", "\x1b[1;30H\x1b[Z"),
        step(g, "backward-twice-to-the-start", "\x1b[1;12H\x1b[5Z"),
        step(g, "forward-by-parameter", "\x1b[2I"),
        step(g, "backspace-at-the-left-edge", "\x08"),
        step(g, "backspace-after-text", "ab\x08"),
        step(
            g,
            "tab-from-a-pending-wrap",
            format!("{}\t", run("a", cols)),
        ),
        step(g, "reset-restores-the-stops", "\x1b[3g\x1bc\t"),
    ]
}

fn widths(last: u32) -> Vec<Step> {
    let mut all = Vec::new();
    let g = "wide";
    all.extend([
        step(g, "two-cjk-characters", "\u{3042}\u{3044}"),
        step(g, "mixed-with-ascii", "a\u{3042}b"),
        step(
            g,
            "wide-character-one-cell-from-the-edge",
            format!("{}\u{3042}", run("a", last - 1)),
        ),
        step(
            g,
            "wide-character-two-cells-from-the-edge",
            format!("{}\u{3042}", run("a", last - 2)),
        ),
        step(g, "overwrite-the-right-half", "\u{3042}\x1b[1;2Hx"),
        step(g, "overwrite-the-left-half", "\u{3042}\x1b[1;1Hx"),
        step(g, "fullwidth-latin", "\u{ff21}\u{ff22}"),
        step(g, "halfwidth-katakana", "\u{ff71}\u{ff72}"),
        step(g, "backspace-over-a-wide-character", "\u{3042}\x08"),
        step(
            g,
            "wide-character-in-insert-mode",
            "ab\x1b[4h\x1b[1;1H\u{3042}",
        ),
    ]);
    let g = "combining";
    all.extend([
        step(g, "acute-accent", "e\u{301}"),
        step(g, "three-marks", "e\u{301}\u{302}\u{303}"),
        step(g, "at-the-start-of-a-line", "\u{301}"),
        step(g, "on-a-pending-wrap", format!("{}\u{301}", run("a", last))),
        step(g, "after-a-wide-character", "\u{3042}\u{301}"),
        step(g, "hangul-jamo-syllable", "\u{1100}\u{1161}\u{11a8}"),
        step(g, "devanagari-conjunct", "\u{0915}\u{094d}\u{0937}\u{093f}"),
        step(g, "variation-selector-on-ascii", "a\u{fe0f}"),
        step(g, "zero-width-space", "a\u{200b}b"),
        step(g, "zero-width-joiner-between-latin", "a\u{200d}b"),
        step(g, "soft-hyphen", "a\u{ad}b"),
        step(g, "non-breaking-space", "a\u{a0}b"),
        step(g, "replacement-for-an-invalid-byte", b"a\xffb".as_slice()),
        step(
            g,
            "replacement-for-a-truncated-sequence",
            b"a\xe3\x81b".as_slice(),
        ),
    ]);
    let g = "emoji";
    all.extend([
        step(g, "one-emoji", "\u{1f600}"),
        step(g, "text-default-symbol", "\u{2764}"),
        step(g, "text-default-with-emoji-selector", "\u{2764}\u{fe0f}"),
        step(g, "emoji-with-text-selector", "\u{1f600}\u{fe0e}"),
        step(g, "keycap-sequence", "1\u{fe0f}\u{20e3}"),
        step(g, "regional-indicator-pair", "\u{1f1fa}\u{1f1f8}"),
        step(
            g,
            "two-flags-back-to-back",
            "\u{1f1fa}\u{1f1f8}\u{1f1ec}\u{1f1e7}",
        ),
        step(g, "skin-tone-modifier", "\u{1f44d}\u{1f3fd}"),
        step(
            g,
            "joined-family",
            "\u{1f468}\u{200d}\u{1f469}\u{200d}\u{1f467}",
        ),
        step(
            g,
            "joined-family-then-ascii",
            "\u{1f468}\u{200d}\u{1f469}\u{200d}\u{1f467}a",
        ),
        step(
            g,
            "emoji-one-cell-from-the-edge",
            format!("{}\u{1f600}", run("a", last - 1)),
        ),
        step(g, "emoji-then-a-return", "\u{1f600}\r"),
        step(g, "two-emoji", "\u{1f600}\u{1f600}"),
    ]);
    let g = "ambiguous";
    all.extend([
        step(g, "inverted-exclamation", "\u{a1}"),
        step(g, "greek-letter", "\u{3b1}"),
        step(g, "geometric-shape", "\u{25b2}"),
        step(g, "copyright-sign", "\u{a9}"),
        step(g, "box-drawing", "\u{2500}\u{2502}"),
        step(g, "block-elements", "\u{2588}\u{2591}"),
        step(g, "four-together", "\u{a1}\u{3b1}\u{25b2}\u{a9}"),
    ]);
    all
}

fn alternate_screen(rows: u32) -> Vec<Step> {
    let g = "alternate-screen";
    vec![
        step(
            g,
            "enter-and-leave-restores-the-cursor",
            "\x1b[5;6H\x1b[?1049h\x1b[2;2Hx\x1b[?1049l",
        ),
        step(
            g,
            "enter-keeps-the-cursor-where-it-was",
            "\x1b[5;6H\x1b[?1049h",
        ),
        step(
            g,
            "enter-without-saving-keeps-the-cursor",
            "\x1b[5;6H\x1b[?1047h\x1b[2;2H\x1b[?1047l",
        ),
        step(
            g,
            "save-and-restore-by-mode",
            "\x1b[5;6H\x1b[?1048h\x1b[1;1H\x1b[?1048l",
        ),
        step(
            g,
            "reverse-index-on-the-alternate-screen",
            "\x1b[?1049h\x1b[1;1H\x1bM",
        ),
        step(
            g,
            "scrolling-on-the-alternate-screen",
            format!("\x1b[?1049h\x1b[{rows};1H\n"),
        ),
        step(
            g,
            "the-saved-cursor-is-per-screen",
            "\x1b[3;3H\x1b7\x1b[?1049h\x1b[6;6H\x1b7\x1b[?1049l\x1b8",
        ),
    ]
}

fn controls(rows: u32) -> Vec<Step> {
    let g = "controls";
    vec![
        step(g, "return-and-line-feed", "abc\r\n"),
        step(g, "line-feed-alone-keeps-the-column", "abc\n"),
        step(g, "next-line", "abc\x1bE"),
        step(g, "vertical-tab", "abc\x0b"),
        step(g, "form-feed", "abc\x0c"),
        step(g, "line-feed-mode-adds-a-return", "\x1b[20habc\n"),
        step(g, "bell-does-not-move", "abc\x07"),
        step(g, "null-is-ignored", "a\0b"),
        step(g, "erase-does-not-move", "abc\x1b[2J\x1b[K"),
        step(g, "insert-character-does-not-move", "abc\x1b[1;2H\x1b[3@"),
        step(g, "delete-character-does-not-move", "abc\x1b[1;2H\x1b[2P"),
        step(g, "erase-character-does-not-move", "abc\x1b[1;2H\x1b[2X"),
        step(g, "repeat-the-last-character", "a\x1b[5b"),
        step(g, "index-at-the-last-row", format!("\x1b[{rows};4H\x1bD")),
        step(g, "reverse-index-at-the-first-row", "\x1b[1;4H\x1bM"),
        step(g, "line-feeds-past-the-bottom", run("\n", rows + 3)),
        step(g, "soft-reset-keeps-the-cursor", "\x1b[3;4H\x1b[!p"),
        step(g, "escape-in-a-sequence-restarts-it", "\x1b[3\x1b[5;6H"),
        step(g, "control-inside-a-sequence-runs", "\x1b[3;\n4H"),
        step(g, "carriage-return-inside-a-sequence", "abc\x1b[\r2C"),
    ]
}
