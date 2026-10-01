//! The committed records of physical terminals, held to the corpus, to the grid as it is now and to
//! the terminal reference that reports them.
//!
//! A record says what a terminal answered and what the canonical grid answered at the time. If the
//! corpus changes, a record that still passes would be a claim about steps that no longer exist,
//! so these tests fail until the terminal is measured again. If only the grid changes, what the
//! terminal answered still holds: the grid's half of each record (`canonical`,
//! `canonical_pending_wrap`, `canonical_library`, `agrees` and the summary) is computed again from
//! the same bytes, as `run::canonical` does, and the tests fail until it is.

use std::path::{Path, PathBuf};

use kr_term_probe::corpus;
use kr_term_probe::run;
use serde_json::Value;

fn records() -> Vec<(PathBuf, Value)> {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("fixtures")
        .join("terminal")
        .join("physical");
    let mut found: Vec<_> = std::fs::read_dir(&directory)
        .unwrap_or_else(|error| panic!("{}: {error}", directory.display()))
        .map(|entry| entry.expect("an entry").path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .map(|path| {
            let text = std::fs::read_to_string(&path).expect("a record");
            let value = serde_json::from_str(&text)
                .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
            (path, value)
        })
        .collect();
    found.sort_by(|left, right| left.0.cmp(&right.0));
    found
}

fn window(record: &Value) -> (u32, u32) {
    let size = record["window"].as_array().expect("a window");
    (
        u32::try_from(size[0].as_u64().expect("columns")).expect("columns fit"),
        u32::try_from(size[1].as_u64().expect("rows")).expect("rows fit"),
    )
}

fn hex(text: &str) -> Vec<u8> {
    (0..text.len() / 2)
        .map(|at| u8::from_str_radix(&text[at * 2..at * 2 + 2], 16).expect("hexadecimal"))
        .collect()
}

#[test]
fn every_record_measures_the_current_corpus() {
    let records = records();
    assert!(records.len() >= 2, "records of at least two terminals");
    for (path, record) in &records {
        let (cols, rows) = window(record);
        let expected = corpus::steps(cols, rows);
        let steps = record["steps"].as_array().expect("steps");
        assert_eq!(steps.len(), expected.len(), "{}", path.display());
        for (step, expected) in steps.iter().zip(&expected) {
            assert_eq!(step["id"], expected.id.as_str(), "{}", path.display());
            assert_eq!(hex(step["bytes"].as_str().expect("bytes")), expected.bytes);
        }
    }
}

#[test]
fn every_record_holds_the_grids_answer_as_it_is_now() {
    for (path, record) in records() {
        let (cols, rows) = window(&record);
        for step in record["steps"].as_array().expect("steps") {
            let (position, pending) =
                run::canonical(cols, rows, &hex(step["bytes"].as_str().expect("bytes")));
            assert_eq!(
                step["canonical"],
                serde_json::json!({ "row": position.row, "col": position.col }),
                "{}: {} has a new canonical position; compute the grid's half of the record again",
                path.display(),
                step["id"]
            );
            assert_eq!(step["canonical_pending_wrap"], pending, "{}", step["id"]);
        }
    }
}

#[test]
fn every_summary_counts_its_steps_and_every_answer_is_one_terminal_reported() {
    for (path, record) in records() {
        let steps = record["steps"].as_array().expect("steps");
        let agree = steps.iter().filter(|step| step["agrees"] == true).count();
        let silent = steps
            .iter()
            .filter(|step| step["terminal"].is_null())
            .count();
        let summary = &record["summary"];
        assert_eq!(summary["steps"], steps.len(), "{}", path.display());
        assert_eq!(summary["agree"], agree, "{}", path.display());
        assert_eq!(summary["unanswered"], silent, "{}", path.display());
        assert_eq!(
            summary["differ"],
            steps.len() - agree - silent,
            "{}",
            path.display()
        );
        for step in steps {
            assert_eq!(
                step["agrees"] == true,
                step["terminal"] == step["canonical"],
                "{}: {}",
                path.display(),
                step["id"]
            );
        }
        assert_eq!(
            record["canonical_library"],
            kr_term::unicode::LIBRARY.revision,
            "{} holds a grid half computed against another revision of the library; compute it again",
            path.display()
        );
        assert!(
            record["launcher"]["application"].is_string()
                && record["launcher"]["version"].is_string(),
            "{} names the application and its version",
            path.display()
        );
        assert_eq!(
            record["launcher"]["wrapped_in_a_multiplexer"],
            false,
            "{} was measured inside a multiplexer",
            path.display()
        );
    }
}

fn reference() -> String {
    std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("docs")
            .join("terminal")
            .join("README.md"),
    )
    .expect("the terminal reference")
}

/// The cells of one table row.
fn cells(line: &str) -> Vec<String> {
    let line = line.trim();
    let line = line.strip_prefix('|').unwrap_or(line);
    let line = line.strip_suffix('|').unwrap_or(line);
    line.split('|').map(|cell| cell.trim().to_owned()).collect()
}

/// Whether `cell` is a separator cell: a run of hyphens, with a colon at either end for alignment.
fn is_separator_cell(cell: &str) -> bool {
    let cell = cell.strip_prefix(':').unwrap_or(cell);
    let cell = cell.strip_suffix(':').unwrap_or(cell);
    !cell.is_empty() && cell.chars().all(|character| character == '-')
}

/// The header cells and the rows of the table whose header line begins with `header`. The line
/// under the header has to be a separator of as many cells, and every row as many cells as the
/// header.
fn table(reference: &str, header: &str) -> Result<(Vec<String>, Vec<Vec<String>>), String> {
    let mut lines = reference
        .lines()
        .skip_while(|line| !line.starts_with(header));
    let head = cells(
        lines
            .next()
            .ok_or_else(|| format!("the reference has no table headed {header:?}"))?,
    );
    let separator = cells(lines.next().unwrap_or_default());
    if separator.len() != head.len() || !separator.iter().all(|cell| is_separator_cell(cell)) {
        return Err(format!(
            "the table headed {header:?} has {separator:?} for a separator under {} header cells",
            head.len()
        ));
    }
    let mut rows = Vec::new();
    for line in lines.take_while(|line| line.starts_with('|')) {
        let row = cells(line);
        if row.len() != head.len() {
            return Err(format!(
                "the row {line:?} has {} cells where the header has {}",
                row.len(),
                head.len()
            ));
        }
        rows.push(row);
    }
    Ok((head, rows))
}

/// The most bytes one cell of the reference may ask for in a run of the letter `a`.
const MOST_REPEATED: usize = 4096;

/// The bytes a step's cell in the reference writes, for a window of `cols` by `rows`: `\e`, `\n`,
/// `\r` and `\u{...}` for a character, `a×columns` and `a×(columns-1)` for the letter `a` once for
/// each of that many columns, and `<columns>` and `<rows>` for the window's size. The cell is
/// wrapped in one pair of backticks.
fn written_bytes(notation: &str, cols: u32, rows: u32) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    let mut rest = notation
        .strip_prefix('`')
        .and_then(|text| text.strip_suffix('`'))
        .ok_or_else(|| format!("{notation:?}: a notation not wrapped in backticks"))?;
    while !rest.is_empty() {
        if let Some(tail) = rest.strip_prefix("\\e") {
            bytes.push(0x1b);
            rest = tail;
        } else if let Some(tail) = rest.strip_prefix("\\n") {
            bytes.push(b'\n');
            rest = tail;
        } else if let Some(tail) = rest.strip_prefix("\\r") {
            bytes.push(b'\r');
            rest = tail;
        } else if let Some(tail) = rest.strip_prefix("\\u{") {
            let (digits, tail) = tail
                .split_once('}')
                .ok_or_else(|| format!("{notation:?}: a \\u{{ with no closing brace"))?;
            let character = u32::from_str_radix(digits, 16)
                .ok()
                .and_then(char::from_u32)
                .ok_or_else(|| format!("{notation:?}: \\u{{{digits}}} is not a character"))?;
            bytes.extend_from_slice(character.encode_utf8(&mut [0; 4]).as_bytes());
            rest = tail;
        } else if let Some(tail) = rest.strip_prefix("a×") {
            let (count, tail) = if let Some(tail) = tail.strip_prefix("columns") {
                (i64::from(cols), tail)
            } else if let Some(tail) = tail.strip_prefix("(columns") {
                let (offset, tail) = tail
                    .split_once(')')
                    .ok_or_else(|| format!("{notation:?}: a count with no closing bracket"))?;
                let offset: i64 = offset
                    .parse()
                    .map_err(|_| format!("{notation:?}: {offset:?} is not an offset"))?;
                let count = i64::from(cols)
                    .checked_add(offset)
                    .ok_or_else(|| format!("{notation:?}: the count overflows"))?;
                (count, tail)
            } else {
                return Err(format!("{notation:?}: a× is not followed by a count"));
            };
            let count = usize::try_from(count)
                .ok()
                .filter(|count| *count <= MOST_REPEATED)
                .ok_or_else(|| {
                    format!("{notation:?}: a count of {count} for {cols} columns is out of range")
                })?;
            bytes.resize(bytes.len() + count, b'a');
            rest = tail;
        } else if let Some(tail) = rest.strip_prefix("<columns>") {
            bytes.extend_from_slice(cols.to_string().as_bytes());
            rest = tail;
        } else if let Some(tail) = rest.strip_prefix("<rows>") {
            bytes.extend_from_slice(rows.to_string().as_bytes());
            rest = tail;
        } else if rest.starts_with('\\') {
            return Err(format!(
                "{notation:?}: an escape the reference does not use"
            ));
        } else {
            let character = rest.chars().next().expect("a character");
            bytes.extend_from_slice(character.encode_utf8(&mut [0; 4]).as_bytes());
            rest = &rest[character.len_utf8()..];
        }
    }
    Ok(bytes)
}

fn position(value: &Value) -> String {
    format!("{};{}", value["row"], value["col"])
}

/// How the reference names the application a record measured.
fn shown_name(record: &Value) -> Result<&str, String> {
    match record["launcher"]["application"].as_str() {
        Some("Terminal") => Ok("Terminal.app"),
        Some(other) => Ok(other),
        None => Err("a record names no application".to_owned()),
    }
}

/// The steps a terminal answered and differs on, in either record. A terminal that gave no
/// position for such a step has `silent` in its cell, and is counted in the summary's last column.
/// A step that no terminal answered and differs on has no row.
fn differing_steps(records: &[(PathBuf, Value)]) -> Vec<&str> {
    records[0].1["steps"]
        .as_array()
        .expect("steps")
        .iter()
        .map(|step| step["id"].as_str().expect("an id"))
        .filter(|id| {
            records.iter().any(|(_, record)| {
                record["steps"]
                    .as_array()
                    .expect("steps")
                    .iter()
                    .any(|step| {
                        step["id"] == *id && step["agrees"] == false && !step["terminal"].is_null()
                    })
            })
        })
        .collect()
}

/// The cell a step has in the step table for one terminal.
fn expected_cell(step: &Value) -> String {
    if step["agrees"] == true {
        "agrees".to_owned()
    } else if step["terminal"].is_null() {
        "silent".to_owned()
    } else {
        format!(
            "{} / **{}**",
            position(&step["canonical"]),
            position(&step["terminal"])
        )
    }
}

/// A terminal that agrees has `agrees`, one that differs has the grid's cell and its own in bold,
/// and one that gave no answer to a step the other differs on has `silent`.
#[test]
fn a_cell_says_agrees_where_the_cursor_is_or_silent() {
    let step = |canonical: Option<(u32, u32)>, terminal: Option<(u32, u32)>, agrees: bool| {
        let cell = |at: Option<(u32, u32)>| {
            at.map_or(
                Value::Null,
                |(row, col)| serde_json::json!({ "row": row, "col": col }),
            )
        };
        serde_json::json!({
            "canonical": cell(canonical),
            "terminal": cell(terminal),
            "agrees": agrees,
        })
    };
    assert_eq!(
        expected_cell(&step(Some((1, 3)), Some((1, 3)), true)),
        "agrees"
    );
    assert_eq!(
        expected_cell(&step(Some((1, 79)), Some((1, 80)), false)),
        "1;79 / **1;80**"
    );
    assert_eq!(expected_cell(&step(Some((1, 79)), None, false)), "silent");
}

/// What the reference holds for the records: a row of the first table for each terminal, with its
/// name, version, window and counts under the header the table is given, and a row of the second
/// for every step either terminal differs on, in the corpus's order, with the bytes written for
/// each window and each terminal's cell under a header that names that terminal, its version and
/// its window.
fn check_reference(reference: &str, records: &[(PathBuf, Value)]) -> Result<(), String> {
    const SUMMARY_HEADER: [&str; 7] = [
        "Terminal", "Version", "Window", "Steps", "Agree", "Differ", "Silent",
    ];
    let (head, summary) = table(reference, "| Terminal | Version | Window |")?;
    if head != SUMMARY_HEADER {
        return Err(format!(
            "the summary header is {head:?}, not {SUMMARY_HEADER:?}"
        ));
    }
    if summary.len() != records.len() {
        return Err(format!(
            "the summary has {} rows for {} records",
            summary.len(),
            records.len()
        ));
    }
    for (_, record) in records {
        let name = shown_name(record)?;
        let (cols, rows) = window(record);
        let version = record["launcher"]["version"].as_str().ok_or("a version")?;
        let build = record["launcher"]["build"].as_str().ok_or("a build")?;
        let shown = if build == version {
            version.to_owned()
        } else {
            format!("{version} ({build})")
        };
        let found: Vec<&Vec<String>> = summary.iter().filter(|row| row[0] == name).collect();
        let [row] = found.as_slice() else {
            return Err(format!(
                "the summary has {} rows for {name}, not one",
                found.len()
            ));
        };
        let counts = &record["summary"];
        for (cell, expected) in [
            (&row[1], shown),
            (&row[2], format!("{cols} by {rows}")),
            (&row[3], counts["steps"].to_string()),
            (&row[4], counts["agree"].to_string()),
            (&row[5], counts["differ"].to_string()),
            (&row[6], counts["unanswered"].to_string()),
        ] {
            if *cell != expected {
                return Err(format!(
                    "the summary row for {name} says {cell:?} where the record has {expected:?}"
                ));
            }
        }
    }

    let (head, rows_written) = table(reference, "| Step | Bytes after a reset |")?;
    if head.len() != 2 + records.len() || head[0] != "Step" || head[1] != "Bytes after a reset" {
        return Err(format!(
            "the step table's header is {head:?}, for a step, its bytes and {} terminals",
            records.len()
        ));
    }
    let columns: Vec<usize> = records
        .iter()
        .map(|(_, record)| {
            let (cols, rows) = window(record);
            let version = record["launcher"]["version"].as_str().expect("a version");
            let wanted = format!("{} {version}, {cols} by {rows}", shown_name(record)?);
            let found: Vec<usize> = (2..head.len()).filter(|&at| head[at] == wanted).collect();
            match found.as_slice() {
                [at] => Ok(*at),
                _ => Err(format!(
                    "the step table's header {head:?} has no single column {wanted:?}"
                )),
            }
        })
        .collect::<Result<_, String>>()?;

    let differing = differing_steps(records);
    let written: Vec<&str> = rows_written
        .iter()
        .map(|row| {
            row[0]
                .strip_prefix('`')
                .and_then(|id| id.strip_suffix('`'))
                .unwrap_or(&row[0])
        })
        .collect();
    if written != differing {
        return Err(format!(
            "the step table lists {written:?}, and the steps either terminal differs on are \
             {differing:?}"
        ));
    }

    for (row, id) in rows_written.iter().zip(&written) {
        for ((_, record), &column) in records.iter().zip(&columns) {
            let (cols, rows) = window(record);
            let step = record["steps"]
                .as_array()
                .expect("steps")
                .iter()
                .find(|step| step["id"] == *id)
                .ok_or_else(|| format!("{id} is in a record no more"))?;
            let bytes = written_bytes(&row[1], cols, rows)?;
            if bytes != hex(step["bytes"].as_str().expect("bytes")) {
                return Err(format!(
                    "{id}: the bytes written do not make the step's bytes"
                ));
            }
            let expected = expected_cell(step);
            if row[column] != expected {
                return Err(format!(
                    "{id}: the table says {:?} for {} and the record has {expected:?}",
                    row[column], head[column]
                ));
            }
        }
    }
    Ok(())
}

/// Every table the terminal reference holds about the records says what the records say, row by
/// row: the versions, windows and counts, and for each step either terminal differs on, its bytes
/// and where the grid and each terminal put the cursor.
#[test]
fn the_reference_says_what_the_records_say() {
    if let Err(difference) = check_reference(&reference(), &records()) {
        panic!("{difference}");
    }
}

/// `reference` with the first `from` written as `to`; `from` has to be there.
fn replaced(reference: &str, from: &str, to: &str) -> String {
    assert!(
        reference.contains(from),
        "the reference no longer holds {from:?}"
    );
    reference.replacen(from, to, 1)
}

/// Copies of the reference with one thing wrong each, and the words the refusal has to hold, so a
/// copy refused for another reason is a failure too.
fn damaged_copies(reference: &str) -> Vec<(&'static str, String, &'static str)> {
    let swapped_names = replaced(
        &replaced(
            &replaced(reference, "| Terminal.app | 2.15", "| @@ | 2.15"),
            "| iTerm2 | 3.7.1 |",
            "| Terminal.app | 3.7.1 |",
        ),
        "| @@ |",
        "| iTerm2 |",
    );
    let feed =
        "| `controls.line-feed-mode-adds-a-return` | `\\e[20habc\\n` | agrees | 2;1 / **2;4** |";
    let a_row_added = replaced(reference, feed, &format!("{feed}\n{feed}"));
    let a_row_missing: String = reference
        .lines()
        .filter(|line| !line.starts_with("| `emoji.joined-family-then-ascii` |"))
        .map(|line| format!("{line}\n"))
        .collect();
    assert_ne!(a_row_missing, reference, "the row is there");
    vec![
        (
            "a cell moved",
            replaced(reference, "| 5;6 / **1;1** |", "| 5;6 / **1;2** |"),
            "the table says",
        ),
        (
            "a byte changed",
            replaced(
                reference,
                r"`\e[5;6H\e[s\e[1;1H\e[u`",
                r"`\e[5;6H\e[s\e[1;1H\e[v`",
            ),
            "the bytes written",
        ),
        (
            "a count changed",
            replaced(
                reference,
                "| 136 | 115 | 21 | 0 |",
                "| 136 | 116 | 20 | 0 |",
            ),
            "the summary row for",
        ),
        (
            "a window changed",
            replaced(reference, "| 80 by 24 | 136 |", "| 80 by 25 | 136 |"),
            "the summary row for",
        ),
        (
            "the two terminals' names swapped in the summary",
            swapped_names,
            "the summary row for",
        ),
        (
            "two of the summary's labels swapped",
            replaced(reference, "| Agree | Differ |", "| Differ | Agree |"),
            "summary header",
        ),
        (
            "one terminal's name written for both in the step table's header",
            replaced(
                reference,
                "| Terminal.app 2.15, 80 by 24 |",
                "| iTerm2 2.15, 80 by 24 |",
            ),
            "step table's header",
        ),
        (
            "the two terminals' names swapped in the step table's header",
            replaced(
                reference,
                "| Terminal.app 2.15, 80 by 24 | iTerm2 3.7.1, 179 by 37 |",
                "| iTerm2 2.15, 80 by 24 | Terminal.app 3.7.1, 179 by 37 |",
            ),
            "step table's header",
        ),
        (
            "a digit added to a version in the step table's header",
            replaced(
                reference,
                "| iTerm2 3.7.1, 179 by 37 |",
                "| iTerm2 13.7.1, 179 by 37 |",
            ),
            "step table's header",
        ),
        (
            "a step that differs renamed in the table",
            replaced(
                reference,
                "| `controls.line-feed-mode-adds-a-return` |",
                "| `controls.line-feed-mode-adds-a-return-too` |",
            ),
            "the step table lists",
        ),
        (
            "a step that agrees put in the table",
            replaced(
                reference,
                "| `addressing.save-and-restore-csi` |",
                "| `addressing.absolute` |",
            ),
            "the step table lists",
        ),
        ("a row added", a_row_added, "the step table lists"),
        ("a row missing", a_row_missing, "the step table lists"),
        (
            "a cell added to a row",
            replaced(reference, feed, &format!("{} extra |", feed)),
            "cells where the header has",
        ),
        (
            "a cell missing from a row",
            replaced(reference, "| agrees | 2;1 / **2;4** |", "| agrees |"),
            "cells where the header has",
        ),
        (
            "a closing backtick missing",
            replaced(
                reference,
                r"`\e[5;6H\e[s\e[1;1H\e[u`",
                r"`\e[5;6H\e[s\e[1;1H\e[u",
            ),
            "backticks",
        ),
        (
            "an extreme repeat count",
            replaced(
                reference,
                r"`a×columns\e[D`",
                r"`a×(columns+9223372036854775807)\e[D`",
            ),
            "count",
        ),
        (
            "a separator of the wrong width",
            replaced(
                reference,
                "| --- | --- | --- | --- | --- | --- | --- |",
                "| --- | --- |",
            ),
            "separator",
        ),
        (
            "a separator cell that is not a run of hyphens",
            replaced(
                reference,
                "| --- | --- | --- | --- | --- | --- | --- |",
                "| --- | --- | --- | --- | --- | --- | ---:--- |",
            ),
            "separator",
        ),
        (
            "a separator cell of colons",
            replaced(
                reference,
                "| --- | --- | --- | --- |",
                "| --- | --- | ::: | --- |",
            ),
            "separator",
        ),
        (
            "an extra empty cell in front of a row",
            replaced(reference, feed, &format!("|{feed}")),
            "cells where the header has",
        ),
    ]
}

/// The check above is not vacuous: each copy of the reference with one thing wrong is refused,
/// and for its own reason, and the reference as it is is accepted.
#[test]
fn a_damaged_reference_is_refused() {
    let reference = reference();
    let records = records();
    let mut wrong = Vec::new();
    for (what, damaged, refusal) in damaged_copies(&reference) {
        match check_reference(&damaged, &records) {
            Ok(()) => wrong.push(format!("{what}: accepted")),
            Err(message) if !message.contains(refusal) => {
                wrong.push(format!(
                    "{what}: refused as {message:?}, not for {refusal:?}"
                ));
            }
            Err(_) => {}
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    assert_eq!(
        check_reference(&reference, &records),
        Ok(()),
        "the reference itself is accepted"
    );
}

/// Whether `text` holds a `~` that begins a word and has a name straight after it: `~anne`, which
/// is what replacing a home directory by its text wherever it occurs leaves of `/Users/anne` when
/// the home directory is `/Users/ann`. A tilde after a letter or a digit (`a~b`) is part of a name,
/// and a bare `~` or `~/` is the home directory written as the probe writes it.
fn begins_a_path_with_a_tilde_and_a_name(text: &str) -> bool {
    text.char_indices().any(|(at, character)| {
        character == '~'
            && !text[..at]
                .chars()
                .next_back()
                .is_some_and(char::is_alphanumeric)
            && text[at + 1..]
                .chars()
                .next()
                .is_some_and(|next| next.is_alphanumeric() || matches!(next, '_' | '.' | '-'))
    })
}

/// The check on the records that a home directory written as a tilde leaves no name behind it:
/// where it holds and where it does not.
#[test]
fn a_tilde_with_a_name_after_it_is_found_and_the_home_directory_written_whole_is_not() {
    for text in [
        "~anne",
        "~anne/.terminfo",
        "/opt:~jo/bin",
        "~jo x",
        "x ~jo",
        "/a:~/b:~jo",
        "HOME=~anne",
        "\"~anne\"",
    ] {
        assert!(
            begins_a_path_with_a_tilde_and_a_name(text),
            "{text:?} holds a tilde and a name"
        );
    }
    for text in [
        "~",
        "~/",
        "~/.terminfo",
        "~:/usr/bin",
        "~ x",
        "/opt:~/bin:~",
        "a~b",
        "/Applications/a~b.app",
        "HOME=~/x",
        "",
    ] {
        assert!(
            !begins_a_path_with_a_tilde_and_a_name(text),
            "{text:?} holds no tilde with a name"
        );
    }
}

/// A record is kept in a repository: it names programs and application bundles, never a home
/// directory, a session or the directory of a program outside an application.
#[test]
fn no_record_names_a_home_directory_a_session_or_a_program_directory() {
    fn strings<'a>(value: &'a Value, found: &mut Vec<&'a str>) {
        match value {
            Value::String(text) => found.push(text),
            Value::Array(items) => items.iter().for_each(|item| strings(item, found)),
            Value::Object(fields) => fields.values().for_each(|field| strings(field, found)),
            _ => {}
        }
    }
    for (path, record) in records() {
        let mut found = Vec::new();
        strings(&record["launcher"], &mut found);
        for text in found {
            for private in ["/Users/", "/home/", "C:\\Users"] {
                assert!(
                    !text.contains(private),
                    "{} writes {text:?}, which holds {private:?}",
                    path.display()
                );
            }
            assert!(
                !begins_a_path_with_a_tilde_and_a_name(text),
                "{} writes {text:?}, which holds what is left of an account name after a tilde",
                path.display()
            );
        }
        for ancestor in record["launcher"]["ancestors"]
            .as_array()
            .expect("ancestors")
        {
            let name = ancestor.as_str().expect("a program name");
            assert!(
                !name.contains('/') && !name.contains('\\'),
                "{}: {name:?} is a path, and a record keeps the program's name",
                path.display()
            );
        }
        for variable in ["STY", "TMUX", "TMUX_PANE"] {
            let value = &record["launcher"]["environment"][variable];
            assert!(
                value.is_null() || value == "set",
                "{}: {variable} is {value}, and a record keeps only whether it was set",
                path.display()
            );
        }
    }
}
