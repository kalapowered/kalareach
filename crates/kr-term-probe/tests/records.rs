//! The committed records of physical terminals, held to the corpus, to the grid as it is now and to
//! the terminal reference that reports them.
//!
//! A record says what a terminal answered and what the canonical grid answered at the time. If the
//! corpus changes, a record that still passes would be a claim about steps that no longer exist,
//! so these tests fail until the terminal is measured again. If only the grid changes, what the
//! terminal answered still holds: the grid's half of each record (`canonical`,
//! `canonical_pending_wrap`, `agrees` and the summary) is computed again from the same bytes, as
//! `run::canonical` does, and the tests fail until it is.

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
            "{} was measured against another revision of the grid's library",
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
    line.trim()
        .trim_matches('|')
        .split('|')
        .map(|cell| cell.trim().to_owned())
        .collect()
}

/// The header cells and the rows of the table whose header line begins with `header`.
fn table(reference: &str, header: &str) -> Result<(Vec<String>, Vec<Vec<String>>), String> {
    let mut lines = reference
        .lines()
        .skip_while(|line| !line.starts_with(header));
    let head = lines
        .next()
        .ok_or_else(|| format!("the reference has no table headed {header:?}"))?;
    let rows = lines
        .skip(1)
        .take_while(|line| line.starts_with('|'))
        .map(cells)
        .collect();
    Ok((cells(head), rows))
}

/// The bytes a step's cell in the reference writes, for a window of `cols` by `rows`: `\e`, `\n`,
/// `\r` and `\u{...}` for a character, `a×columns` and `a×(columns-1)` for the letter `a` once for
/// each of that many columns, and `<columns>` and `<rows>` for the window's size.
fn written_bytes(notation: &str, cols: u32, rows: u32) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    let mut rest = notation.trim_matches('`');
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
                (i64::from(cols) + offset, tail)
            } else {
                return Err(format!("{notation:?}: a× is not followed by a count"));
            };
            let count = usize::try_from(count)
                .map_err(|_| format!("{notation:?}: a count below zero for {cols} columns"))?;
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

fn position(value: &Value) -> Result<String, String> {
    if value.is_null() {
        return Err("a step the terminal did not answer has no cell in the reference".to_owned());
    }
    Ok(format!("{};{}", value["row"], value["col"]))
}

/// What the reference holds for the records: a row of the first table for each terminal, with its
/// version, window and counts, and a row of the second for every step either terminal differs on,
/// in the corpus's order, with the bytes written for each window and each terminal's cell.
fn check_reference(reference: &str, records: &[(PathBuf, Value)]) -> Result<(), String> {
    let (_, summary) = table(reference, "| Terminal | Version | Window |")?;
    for (_, record) in records {
        let (cols, rows) = window(record);
        let version = record["launcher"]["version"].as_str().ok_or("a version")?;
        let build = record["launcher"]["build"].as_str().ok_or("a build")?;
        let shown = if build == version {
            version.to_owned()
        } else {
            format!("{version} ({build})")
        };
        let found: Vec<&Vec<String>> = summary
            .iter()
            .filter(|row| row[2] == format!("{cols} by {rows}") && row[1].starts_with(version))
            .collect();
        let [row] = found.as_slice() else {
            return Err(format!(
                "the summary has {} rows for version {version} in a window of {cols} by {rows}",
                found.len()
            ));
        };
        let counts = &record["summary"];
        for (cell, expected) in [
            (&row[1], shown),
            (&row[3], counts["steps"].to_string()),
            (&row[4], counts["agree"].to_string()),
            (&row[5], counts["differ"].to_string()),
            (&row[6], counts["unanswered"].to_string()),
        ] {
            if *cell != expected {
                return Err(format!(
                    "the summary row for {version} says {cell:?} where the record has {expected:?}"
                ));
            }
        }
    }
    if summary.len() != records.len() {
        return Err(format!(
            "the summary has {} rows for {} records",
            summary.len(),
            records.len()
        ));
    }

    let (head, rows_written) = table(reference, "| Step | Bytes after a reset |")?;
    if head.len() != 2 + records.len() {
        return Err(format!(
            "the step table has {} columns for {} records",
            head.len(),
            records.len()
        ));
    }
    let columns: Vec<usize> = records
        .iter()
        .map(|(_, record)| {
            let (cols, rows) = window(record);
            let version = record["launcher"]["version"].as_str().expect("a version");
            let wanted = format!("{version}, {cols} by {rows}");
            let found: Vec<usize> = (2..head.len())
                .filter(|&at| head[at].ends_with(&wanted))
                .collect();
            match found.as_slice() {
                [at] => Ok(*at),
                _ => Err(format!(
                    "the step table has no single column for {wanted:?}"
                )),
            }
        })
        .collect::<Result<_, _>>()?;

    let corpus = records[0].1["steps"].as_array().expect("steps");
    let differing: Vec<&str> = corpus
        .iter()
        .map(|step| step["id"].as_str().expect("an id"))
        .filter(|id| {
            records.iter().any(|(_, record)| {
                record["steps"]
                    .as_array()
                    .expect("steps")
                    .iter()
                    .any(|step| step["id"] == *id && step["agrees"] == false)
            })
        })
        .collect();
    let written: Vec<&str> = rows_written
        .iter()
        .map(|row| row[0].trim_matches('`'))
        .collect();
    if written != differing {
        return Err(format!(
            "the step table lists {written:?}, and the steps either terminal differs on are \
             {differing:?}"
        ));
    }

    for row in &rows_written {
        let id = row[0].trim_matches('`');
        for ((_, record), &column) in records.iter().zip(&columns) {
            let (cols, rows) = window(record);
            let step = record["steps"]
                .as_array()
                .expect("steps")
                .iter()
                .find(|step| step["id"] == id)
                .ok_or_else(|| format!("{id} is in a record no more"))?;
            let bytes = written_bytes(&row[1], cols, rows)?;
            if bytes != hex(step["bytes"].as_str().expect("bytes")) {
                return Err(format!(
                    "{id}: the bytes written do not make the step's bytes"
                ));
            }
            let expected = if step["agrees"] == true {
                "agrees".to_owned()
            } else {
                format!(
                    "{} / **{}**",
                    position(&step["canonical"])?,
                    position(&step["terminal"])?
                )
            };
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

/// The check above is not vacuous: a table with one fact changed, a row missing or a row added is
/// refused, each in a copy of the reference.
#[test]
fn a_damaged_reference_is_refused() {
    let reference = reference();
    let records = records();
    let damages: [(&str, &str, &str); 6] = [
        ("a cell moved", "| 5;6 / **1;1** |", "| 5;6 / **1;2** |"),
        (
            "a byte changed",
            r"`\e[5;6H\e[s\e[1;1H\e[u`",
            r"`\e[5;6H\e[s\e[1;1H\e[v`",
        ),
        (
            "a count changed",
            "| 136 | 115 | 21 | 0 |",
            "| 136 | 116 | 20 | 0 |",
        ),
        (
            "a window changed",
            "| 80 by 24 | 136 |",
            "| 80 by 25 | 136 |",
        ),
        (
            "a step that differs is no longer in the table",
            "| `controls.line-feed-mode-adds-a-return` |",
            "| `controls.line-feed-mode-adds-a-return-too` |",
        ),
        (
            "a step that agrees is in the table",
            "| `addressing.save-and-restore-csi` |",
            "| `addressing.absolute` |",
        ),
    ];
    for (what, from, to) in damages {
        assert!(
            reference.contains(from),
            "{what}: the reference no longer holds {from:?}"
        );
        let damaged = reference.replacen(from, to, 1);
        assert!(
            check_reference(&damaged, &records).is_err(),
            "{what}: a damaged reference was accepted"
        );
    }
    let without_a_row: String = reference
        .lines()
        .filter(|line| !line.starts_with("| `emoji.joined-family-then-ascii` |"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(without_a_row.len() < reference.len(), "the row is there");
    assert!(
        check_reference(&without_a_row, &records).is_err(),
        "a reference with a row missing was accepted"
    );
    assert!(
        check_reference(&reference, &records).is_ok(),
        "the reference itself is accepted"
    );
}

/// Whether a path in `text` begins with `~` and a name: `~anne`, which is what replacing a home
/// directory by its text wherever it occurs leaves of `/Users/anne` when the home directory is
/// `/Users/ann`. A bare `~` or `~/` is the home directory written as the probe writes it.
fn begins_a_path_with_a_tilde_and_a_name(text: &str) -> bool {
    text.char_indices().any(|(at, character)| {
        character == '~'
            && (at == 0 || matches!(text.as_bytes()[at - 1], b':' | b' '))
            && text[at + 1..]
                .chars()
                .next()
                .is_some_and(|next| !matches!(next, '/' | ':' | ' '))
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
