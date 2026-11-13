//! A check of the crate's source against the table of its sentences (`tests/sentences.txt`).
//!
//! Every place in `src/` that makes a text for a person is found by its form, and each one either
//! carries an identifier, as the comment `// text: <identifier>` on the line before it, or is counted
//! in the table's list of the places that carry none. The forms are the calls `Error::Refused(`,
//! `Error::Failed(`, `Begin::Refuse(` (a refusal that a result carries), `say(`, `println!(`,
//! `print!(`, `eprintln!(` and `eprint!(`; the reasons handed to `parent_refusal`, `program_refusal`,
//! `child_refusal` and `anchor_refusal`; the contexts of `io_error(`, `last(`, `error(` and
//! `Handle::new(`; every `#[error(...)]` message; and each `pub fn` that returns words (a `String`
//! or a `&str`) and each `pub const` of words.
//!
//! The table has a row for each sentence that a place makes: `<identifier> | <fixed words> |
//! <sentence> | <read>`. The fixed words are a fragment of the place's own source text, and the case
//! fails where the place's text does not hold the words of its row, so a row of another place fails.
//! A place with no identifier is counted in a line `listed | <form> | <file> | <count> | <reason>`,
//! and the case fails where the count of the places of that form in that file that carry no
//! identifier is not the listed count, so a new text of any form cannot come in without a row.
//!
//! What it cannot check: that a row's read is really behind its sentence (the reviewer's read), and
//! a text that no listed form makes. A new form of place is added to `CALLS` and to the cases below.
//! They run on every platform.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

/// The comment that carries the identifiers of a place, on the line before it.
const MARKER: &str = "// text: ";

/// The calls that make a text, by their opening text. A call that another name continues, a method
/// of the same name, a definition and a pattern are not places.
const CALLS: &[&str] = &[
    "Error::Refused(",
    "Error::Failed(",
    "Begin::Refuse(",
    "say(",
    "println!(",
    "print!(",
    "eprintln!(",
    "eprint!(",
    "parent_refusal(",
    "program_refusal(",
    "child_refusal(",
    "anchor_refusal(",
    "io_error(",
    "last(",
    "error(",
    "ffi::last(",
    "ffi::error(",
    "Handle::new(",
];

/// The form of an attribute that makes a text.
const ATTRIBUTE: &str = "#[error(";

/// The words of a function that is public and returns words, and of a public constant of words.
const FUNCTION: &str = "pub fn";
const CONSTANT: &str = "pub const";

/// A place that makes texts: the line (from 0), the form of each text that it makes, and the source
/// text of the place, from its line to the end of the call, attribute, function or constant.
#[derive(Debug)]
struct Place {
    line: usize,
    forms: Vec<&'static str>,
    text: String,
}

fn is_identifier_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Whether the call `needle` at byte `at` of `line` is a place: it does not continue a longer name,
/// is not a method or a path of another name (for the bare names), is not a definition and is not
/// a pattern.
fn is_call_place(line: &str, at: usize, needle: &str) -> bool {
    let before = line[..at].chars().next_back();
    let after = &line[at + needle.len()..];
    let bare = !needle.contains("::");
    let continues =
        before.is_some_and(|c| is_identifier_char(c) || (bare && (c == '.' || c == ':')));
    let definition = line[..at].trim_end().ends_with("fn") && line[..at].ends_with(' ');
    let pattern = (needle.starts_with("Error::") && after.starts_with("_)"))
        || (needle == "Begin::Refuse("
            && after.split_once(')').is_some_and(|(binding, rest)| {
                is_identifier(binding) && rest.trim_start().starts_with("=>")
            }));
    !continues && !definition && !pattern
}

/// The forms of the texts that a line makes, in the order of the line, and the byte of the last
/// call's opening parenthesis (or bracket).
fn call_forms(line: &str) -> (Vec<&'static str>, Option<usize>) {
    let mut found: Vec<(usize, &'static str, usize)> = Vec::new();
    for needle in CALLS.iter().copied() {
        for (at, _) in line.match_indices(needle) {
            if is_call_place(line, at, needle) {
                found.push((at, needle, at + needle.len() - 1));
            }
        }
    }
    found.sort_unstable();
    let last = found.last().map(|(_, _, open)| *open);
    (
        found.into_iter().map(|(_, needle, _)| needle).collect(),
        last,
    )
}

/// The byte just past a literal or a comment that starts at `at`, or `None` where none starts.
fn skip_literal(text: &str, at: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    match bytes[at] {
        b'"' => {
            let mut i = at + 1;
            while i < bytes.len() {
                match bytes[i] {
                    b'\\' => i += 2,
                    b'"' => return Some(i + 1),
                    _ => i += 1,
                }
            }
            Some(bytes.len())
        }
        b'r' if at == 0 || !is_identifier_char(char::from(bytes[at - 1])) => {
            let hashes = bytes[at + 1..]
                .iter()
                .take_while(|byte| **byte == b'#')
                .count();
            if bytes.get(at + 1 + hashes) != Some(&b'"') {
                return None;
            }
            let close: Vec<u8> = std::iter::once(b'"')
                .chain(std::iter::repeat_n(b'#', hashes))
                .collect();
            let from = at + 2 + hashes;
            Some(
                text[from..]
                    .find(std::str::from_utf8(&close).unwrap())
                    .map_or(bytes.len(), |end| from + end + close.len()),
            )
        }
        b'\'' => {
            // A character literal, or a lifetime or a label, which has no closing quote.
            let rest = &text[at + 1..];
            let mut chars = rest.chars();
            match chars.next() {
                Some('\\') => rest.find('\'').map(|end| at + 1 + end + 1),
                Some(c) if rest[c.len_utf8()..].starts_with('\'') => {
                    Some(at + 1 + c.len_utf8() + 1)
                }
                _ => None,
            }
        }
        b'/' if bytes.get(at + 1) == Some(&b'/') => {
            Some(text[at..].find('\n').map_or(bytes.len(), |end| at + end))
        }
        b'/' if bytes.get(at + 1) == Some(&b'*') => Some(
            text[at + 2..]
                .find("*/")
                .map_or(bytes.len(), |end| at + 2 + end + 2),
        ),
        _ => None,
    }
}

/// The byte just past the group that opens at `open` (a `(`, a `{` or a `[`), skipping literals and
/// comments, or the end of the text where it never closes.
fn group_end(text: &str, open: usize) -> usize {
    let bytes = text.as_bytes();
    let (opening, closing) = match bytes[open] {
        b'(' => (b'(', b')'),
        b'{' => (b'{', b'}'),
        _ => (b'[', b']'),
    };
    let mut depth = 0_usize;
    let mut i = open;
    while i < bytes.len() {
        if let Some(next) = skip_literal(text, i) {
            i = next;
            continue;
        }
        if bytes[i] == opening {
            depth += 1;
        } else if bytes[i] == closing {
            depth -= 1;
            if depth == 0 {
                return i + 1;
            }
        }
        i += 1;
    }
    bytes.len()
}

/// The byte of the first `{` or `;` at or after `from` that is outside every literal, comment and
/// parenthesis.
fn body_start(text: &str, from: usize) -> usize {
    let bytes = text.as_bytes();
    let mut depth = 0_usize;
    let mut i = from;
    while i < bytes.len() {
        if let Some(next) = skip_literal(text, i) {
            i = next;
            continue;
        }
        match bytes[i] {
            b'(' | b'[' => depth += 1,
            b')' | b']' => depth = depth.saturating_sub(1),
            b'{' | b';' if depth == 0 => return i,
            _ => {}
        }
        i += 1;
    }
    bytes.len()
}

/// The text of a place from the start of its line to its end.
fn place_text(text: &str, line_start: usize, end: usize) -> String {
    text[line_start..end.min(text.len())].to_owned()
}

/// Whether the `pub fn` that starts at `lines[at]` returns words.
fn returns_words(lines: &[&str], at: usize) -> bool {
    let mut signature = String::new();
    for line in lines.iter().skip(at).take(14) {
        signature.push(' ');
        signature.push_str(line.trim());
        if line.contains('{') || line.trim_end().ends_with(';') {
            break;
        }
    }
    let Some((_, returned)) = signature.split_once("->") else {
        return false;
    };
    let returned = returned.split('{').next().unwrap_or("");
    let returned = returned.split(" where ").next().unwrap_or("");
    returned.contains("String") || returned.contains("&str") || returned.contains("&'static str")
}

/// The places of a source file.
fn places(text: &str) -> Vec<Place> {
    let lines: Vec<&str> = text.lines().collect();
    let mut starts = Vec::with_capacity(lines.len());
    let mut offset = 0;
    for line in &lines {
        starts.push(offset);
        offset += line.len() + 1;
    }
    let mut found = Vec::new();
    for (at, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("//") {
            continue;
        }
        let start = starts[at];
        if trimmed.starts_with(ATTRIBUTE) {
            let open = start + line.find('[').unwrap_or(0);
            found.push(Place {
                line: at,
                forms: vec!["#[error]"],
                text: place_text(text, start, group_end(text, open)),
            });
            continue;
        }
        if trimmed.starts_with("pub fn ") {
            if returns_words(&lines, at) {
                let open = body_start(text, start);
                let end = if text.as_bytes().get(open) == Some(&b'{') {
                    group_end(text, open)
                } else {
                    open + 1
                };
                found.push(Place {
                    line: at,
                    forms: vec![FUNCTION],
                    text: place_text(text, start, end),
                });
            }
            continue;
        }
        if trimmed.starts_with("pub const ") && trimmed.contains(": &") {
            let end = body_start(text, start) + 1;
            found.push(Place {
                line: at,
                forms: vec![CONSTANT],
                text: place_text(text, start, end),
            });
            continue;
        }
        let (forms, open) = call_forms(line);
        if let Some(open) = open {
            let end = group_end(text, start + open);
            found.push(Place {
                line: at,
                forms,
                text: place_text(text, start, end),
            });
        }
    }
    found
}

fn is_identifier(text: &str) -> bool {
    !text.is_empty()
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// One row of the table: its line (from 1), its identifier and its fixed words.
struct Row {
    line: usize,
    id: String,
    fixed: String,
}

/// What is wrong between the sources (file name, text) and the table, as sentences. An empty list
/// is a source whose every place has a row that its own words hold, or is counted as listed, and a
/// table whose every row has a place and every listed count is the source's.
fn check(sources: &[(&str, &str)], table: &str) -> Vec<String> {
    let mut faults = Vec::new();
    // The rows and the listed counts.
    let mut rows: Vec<Row> = Vec::new();
    let mut listed: BTreeMap<(String, String), (usize, usize)> = BTreeMap::new();
    for (number, line) in table.lines().enumerate() {
        let number = number + 1;
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split(" | ").map(str::trim).collect();
        if fields[0] == "listed" {
            let count = fields.get(3).and_then(|count| count.parse::<usize>().ok());
            match (fields.len(), count) {
                (5, Some(count)) if fields.iter().all(|field| !field.is_empty()) => {
                    listed.insert(
                        (fields[1].to_owned(), fields[2].to_owned()),
                        (count, number),
                    );
                }
                _ => faults.push(format!(
                    "table line {number}: not `listed | <form> | <file> | <count> | <reason>`"
                )),
            }
            continue;
        }
        if fields.len() != 4
            || fields.iter().any(|field| field.is_empty())
            || !is_identifier(fields[0])
        {
            faults.push(format!(
                "table line {number}: not `<identifier> | <fixed words> | <sentence> | <read>`"
            ));
            continue;
        }
        rows.push(Row {
            line: number,
            id: fields[0].to_owned(),
            fixed: fields[1].to_owned(),
        });
    }

    // The places: each carries its identifiers, or is counted for the list.
    let mut carried: BTreeMap<String, Vec<(String, usize, String)>> = BTreeMap::new();
    let mut unmarked: BTreeMap<(String, String), usize> = BTreeMap::new();
    for (file, text) in sources {
        let lines: Vec<&str> = text.lines().collect();
        for place in places(text) {
            let ids: Vec<&str> = place
                .line
                .checked_sub(1)
                .and_then(|before| lines[before].trim_start().strip_prefix(MARKER))
                .map(|ids| ids.split_whitespace().collect())
                .unwrap_or_default();
            if ids.is_empty() {
                for form in &place.forms {
                    *unmarked
                        .entry(((*form).to_owned(), (*file).to_owned()))
                        .or_default() += 1;
                }
                continue;
            }
            if ids.len() != place.forms.len() || !ids.iter().all(|id| is_identifier(id)) {
                faults.push(format!(
                    "{file}:{}: a place that makes {} text(s) has the wrong number of identifiers",
                    place.line + 1,
                    place.forms.len()
                ));
                continue;
            }
            for id in ids {
                carried.entry(id.to_owned()).or_default().push((
                    (*file).to_owned(),
                    place.line + 1,
                    place.text.clone(),
                ));
            }
        }
    }

    // The counts of the places that carry no identifier, against the list.
    let keys: Vec<(String, String)> = unmarked
        .keys()
        .chain(listed.keys())
        .cloned()
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    for (form, file) in keys {
        let have = unmarked
            .get(&(form.clone(), file.clone()))
            .copied()
            .unwrap_or(0);
        let said = listed
            .get(&(form.clone(), file.clone()))
            .map(|(count, _)| *count);
        if said.unwrap_or(0) != have {
            faults.push(format!(
                "{file}: {have} place(s) of the form `{form}` carry no `{MARKER}<identifier>` line, and the table lists {}",
                said.map_or("none".to_owned(), |count| count.to_string())
            ));
        }
    }

    // Each identifier has a row, each row a place, and each row's words are in its place's text.
    for (id, where_) in &carried {
        if where_.len() > 1 {
            faults.push(format!(
                "identifier {id} is carried by {} places: {}",
                where_.len(),
                where_
                    .iter()
                    .map(|(file, line, _)| format!("{file}:{line}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        if !rows.iter().any(|row| &row.id == id) {
            faults.push(format!(
                "identifier {id} ({}:{}) has no row in the table",
                where_[0].0, where_[0].1
            ));
        }
    }
    for row in &rows {
        match carried.get(&row.id) {
            None => faults.push(format!(
                "the table has a row for {}, and no place carries it",
                row.id
            )),
            Some(places) => {
                if !places.iter().any(|(_, _, text)| text.contains(&row.fixed)) {
                    faults.push(format!(
                        "table line {}: the words `{}` of the row {} are not in the text of its place ({}:{})",
                        row.line, row.fixed, row.id, places[0].0, places[0].1
                    ));
                }
            }
        }
    }
    faults
}

fn source_files(dir: &Path, root: &Path, out: &mut Vec<(String, String)>) {
    let mut entries: Vec<_> = fs::read_dir(dir)
        .expect("the source directory is read")
        .map(|entry| entry.expect("an entry").path())
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            source_files(&path, root, out);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            let name = path
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            out.push((
                name,
                fs::read_to_string(&path).expect("a source file is read"),
            ));
        }
    }
}

/// Every place of the crate's source that makes a text has an identifier whose row its own words
/// hold, or is counted in the table's list, and every row and every listed count is the source's.
#[test]
fn every_place_that_makes_a_text_has_a_row_that_its_own_words_hold() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let src = manifest.join("src");
    let mut sources = Vec::new();
    source_files(&src, &src, &mut sources);
    let table =
        fs::read_to_string(manifest.join("tests/sentences.txt")).expect("the table is read");
    let borrowed: Vec<(&str, &str)> = sources
        .iter()
        .map(|(file, text)| (file.as_str(), text.as_str()))
        .collect();
    let faults = check(&borrowed, &table);
    assert!(faults.is_empty(), "{}", faults.join("\n"));
}

/// The check itself: it fails for a place without an identifier, for an identifier without a row,
/// for a row without a place, for an identifier used twice and for a row whose words are not in its
/// place; it finds each form that item lists; and it takes patterns, longer names, methods,
/// definitions and functions that return no words for no place.
#[test]
fn the_check_fails_for_a_place_without_a_row_a_row_without_a_place_and_a_row_of_another_place() {
    let good =
        "fn f() {\n    // text: f-1\n    return Err(Error::Refused(\"the disk is full\"));\n}\n";
    let table = "f-1 | the disk is full | the disk is full | read: a call\n";
    assert_eq!(check(&[("install.rs", good)], table), Vec::<String>::new());

    // A row whose words are those of another place fails, also when the identifiers are swapped.
    let two = "// text: a-1\nsay(\"the first words\");\n// text: a-2\nsay(\"the second words\");\n";
    let right = "a-1 | the first words | s | r\na-2 | the second words | s | r\n";
    assert!(check(&[("x.rs", two)], right).is_empty());
    let swapped = "a-1 | the second words | s | r\na-2 | the first words | s | r\n";
    let faults = check(&[("x.rs", two)], swapped);
    assert_eq!(faults.len(), 2, "{faults:?}");
    assert!(
        faults
            .iter()
            .all(|fault| fault.contains("not in the text of its place"))
    );
    // Words that the place's own source holds, however long its text runs over lines.
    let long = "// text: a-1\nError::Failed(format!(\n    \"one {}\",\n    (\")\", 1).0,\n))\nthe_next(x);\n";
    assert!(check(&[("x.rs", long)], "a-1 | one {} | s | r\n").is_empty());
    let beyond = check(&[("x.rs", long)], "a-1 | the_next | s | r\n");
    assert_eq!(
        beyond.len(),
        1,
        "a word after the call is not in the place: {beyond:?}"
    );

    // A place without an identifier is counted, and the list must say how many.
    let bare = "fn f() {\n    return Err(Error::Failed(x));\n}\n";
    let faults = check(&[("install.rs", bare)], "");
    assert_eq!(faults.len(), 1, "{faults:?}");
    assert!(
        faults[0].contains("1 place(s) of the form `Error::Failed(`"),
        "{faults:?}"
    );
    assert!(
        check(
            &[("install.rs", bare)],
            "listed | Error::Failed( | install.rs | 1 | a reason\n"
        )
        .is_empty()
    );
    let faults = check(
        &[("install.rs", bare)],
        "listed | Error::Failed( | install.rs | 2 | a reason\n",
    );
    assert_eq!(faults.len(), 1, "{faults:?}");
    let faults = check(
        &[("install.rs", "fn f() {}\n")],
        "listed | Error::Failed( | install.rs | 1 | a reason\n",
    );
    assert_eq!(faults.len(), 1, "a listed count with no place: {faults:?}");
    // A marker that is not on the line before the place leaves it uncounted as marked.
    let far = "// text: f-1\nlet x = 1;\nsay(\"x\");\n";
    assert_eq!(check(&[("install.rs", far)], "f-1 | x | s | r\n").len(), 2);
    // A place that makes two texts on one line needs two identifiers.
    let two_on_a_line = "// text: f-1\nlet _ = (Error::Failed(a), say(b));\n";
    // (the wrong number of identifiers, and the row of the identifier that no place then carries)
    assert_eq!(
        check(&[("install.rs", two_on_a_line)], "f-1 | a | s | r\n").len(),
        2
    );
    let two_ok = "// text: f-1 f-2\nlet _ = (Error::Failed(a), say(b));\n";
    assert!(
        check(
            &[("install.rs", two_ok)],
            "f-1 | Error::Failed(a) | s | r\nf-2 | say(b) | s | r\n"
        )
        .is_empty()
    );

    // An identifier with no row, and a row with no place.
    let faults = check(
        &[("install.rs", good)],
        "g-1 | a | a sentence | read: a call\n",
    );
    assert_eq!(faults.len(), 2, "{faults:?}");
    assert!(
        faults
            .iter()
            .any(|fault| fault.contains("f-1") && fault.contains("no row"))
    );
    assert!(
        faults
            .iter()
            .any(|fault| fault.contains("g-1") && fault.contains("no place"))
    );

    // An identifier that two places carry, in one file and in two.
    let twice = "// text: f-1\nsay(a);\n// text: f-1\nsay(a);\n";
    let faults = check(&[("install.rs", twice)], "f-1 | a | s | r\n");
    assert_eq!(faults.len(), 1, "{faults:?}");
    assert!(faults[0].contains("carried by 2 places"), "{faults:?}");
    let once = "// text: f-1\nsay(a);\n";
    let faults = check(
        &[("install.rs", once), ("other.rs", once)],
        "f-1 | a | s | r\n",
    );
    assert_eq!(faults.len(), 1, "{faults:?}");

    // A row with a missing field, an empty field or a bad identifier.
    for bad in [
        "f-1 | only a sentence\n",
        "f-1 |  | s | r\n",
        "f 1 | a | b | c\n",
        "f-1 | a | b\n",
    ] {
        assert!(!check(&[("install.rs", once)], bad).is_empty(), "{bad}");
    }

    // Not places: a pattern, a longer name, a method, a path, a definition, a comment and a word-free function.
    let not_places = "fn say(line: &str) {}\nErr(Error::Refused(_)) => 1,\nRootError::Refused(x);\nthing.say(x);\nm::say(x);\n// Error::Failed(x) in a comment\n/// say(x) in a doc comment\npub fn last(a: u8) -> u8 {\n    a\n}\nlet n = items.last();\nfn io_error(x: &str) {}\nlet y = x.error(1);\nm::error(1);\nOwnedHandle::new(1);\n";
    assert!(check(&[("install.rs", not_places)], "").is_empty());
    let no_words = "pub fn is_ok(a: &str) -> bool {\n    true\n}\n";
    assert!(check(&[("remedy.rs", no_words)], "").is_empty());

    // The forms that the check finds, each as a place that needs an identifier.
    for (form, source) in [
        ("println!(", "println!(\"x\");\n"),
        ("print!(", "print!(\"x\");\n"),
        ("eprintln!(", "eprintln!(\"x\");\n"),
        (
            "parent_refusal(",
            "return Err(parent_refusal(paths, \"x\", y));\n",
        ),
        ("program_refusal(", "program_refusal(paths, a, b, \"x\");\n"),
        ("child_refusal(", "child_refusal(paths, \"x\");\n"),
        ("anchor_refusal(", "anchor_refusal(paths, &r, false);\n"),
        (
            "io_error(",
            "fs::read().map_err(io_error(\"reading the answer\"))?;\n",
        ),
        ("last(", "return Err(last(\"opening the service\"));\n"),
        ("last(", "return Err(ffi::last(\"opening the service\"));\n"),
        ("error(", "return Err(ffi::error(1, \"a call\"));\n"),
        ("Handle::new(", "ffi::Handle::new(raw, \"opening x\")?;\n"),
        (
            "Begin::Refuse(",
            "Look::There => Begin::Refuse(format!(\"x\")),\n",
        ),
    ] {
        let faults = check(&[("a.rs", source)], "");
        assert_eq!(faults.len(), 1, "{form}: {faults:?}");
        assert!(
            faults[0].contains(&format!("`{form}`"))
                || faults[0].contains(form.trim_end_matches('(')),
            "{form}: {faults:?}"
        );
    }
    // A pattern that passes a refusal on is no place.
    let passed_on = "records::Begin::Refuse(text) => return Ok(text),\n";
    assert!(check(&[("install.rs", passed_on)], "").is_empty());
    // A message of the error attribute, however long, is a place; its words are held by its text.
    let attribute = "#[derive(Error)]\nenum E {\n    // text: e-1\n    #[error(\n        \"it could not be read: {0}\"\n    )]\n    Read(String),\n}\n";
    assert!(check(&[("m.rs", attribute)], "e-1 | could not be read | s | r\n").is_empty());
    assert_eq!(
        check(&[("m.rs", attribute)], "e-1 | not in it | s | r\n").len(),
        1
    );
    assert_eq!(check(&[("m.rs", "#[error(\"x\")]\nRead,\n")], "").len(), 1);

    // A public function that returns words, in any file; and a constant of words.
    for returned in ["String", "Option<String>", "&'static str", "Vec<String>"] {
        let words = format!("pub fn words(a: &str) -> {returned} {{\n    todo!()\n}}\n");
        for file in ["remedy.rs", "records.rs", "setup_args.rs"] {
            assert_eq!(
                check(&[(file, &words)], "").len(),
                1,
                "{returned} in {file}"
            );
        }
    }
    let words = "pub fn words(\n    a: &str,\n) -> String {\n    todo!()\n}\n";
    assert_eq!(check(&[("remedy.rs", words)], "").len(), 1);
    let carried =
        "// text: words\npub fn words(\n    a: &str,\n) -> String {\n    format!(\"why not\")\n}\n";
    assert!(check(&[("remedy.rs", carried)], "words | why not | s | r\n").is_empty());
    let constant = "pub const WHY: &str = \"x; y\";\n";
    assert_eq!(check(&[("remedy.rs", constant)], "").len(), 1);
    assert!(
        check(
            &[(
                "remedy.rs",
                "// text: WHY\npub const WHY: &str = \"x; y\";\n"
            )],
            "WHY | x; y | s | r\n"
        )
        .is_empty()
    );
}
