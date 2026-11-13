//! A check of the crate's source against the table of its sentences (`tests/sentences.txt`).
//!
//! Every place in `src/` that makes a text for a person carries an identifier, as the comment
//! `// text: <identifier>` on the line before it: each `Error::Refused(`, `Error::Failed(`, `Begin::Refuse(` and `say(`
//! (a place that makes two texts on one line lists two identifiers), and, in `remedy.rs` and
//! `records.rs`, each `pub fn` that returns words (a `String` or a `&str`) and each `pub const` of
//! words. The table names, for each identifier, the sentences that state a fact about the machine
//! and the read behind each. The case fails for a place without an identifier, for an identifier
//! with no row, for a row that no place carries, and for an identifier that two places carry.
//!
//! What it cannot check: that a row's read is really behind its sentence, that a row's sentence
//! is what the place says, and that a text which no listed form makes (a thiserror message, a
//! `println!`, a text that a function builds and a place then passes on) has a place. A
//! reviewer reads those. A new form of place is added to `places` and to the cases below.
//! They run on every platform.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

/// The comment that carries the identifiers of a place, on the line before it.
const MARKER: &str = "// text: ";

/// How many texts a line makes: the occurrences of `needle` that are not a pattern and do not
/// continue a longer name.
fn occurrences(line: &str, needle: &str) -> usize {
    line.match_indices(needle)
        .filter(|(at, _)| {
            let before = line[..*at].chars().next_back();
            let after = &line[*at + needle.len()..];
            let continues = before.is_some_and(|c| {
                c.is_alphanumeric() || c == '_' || (needle == "say(" && (c == '.' || c == ':'))
            });
            let pattern = (needle.starts_with("Error::") && after.starts_with("_)"))
                || (needle == "Begin::Refuse("
                    && after.split_once(')').is_some_and(|(binding, rest)| {
                        is_identifier(binding) && rest.trim_start().starts_with("=>")
                    }));
            !continues && !pattern
        })
        .count()
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

/// The places of a source file: the index of the line and how many identifiers it needs.
fn places(file: &str, lines: &[&str]) -> Vec<(usize, usize)> {
    let words_file = file == "remedy.rs" || file == "records.rs";
    let mut found = Vec::new();
    for (at, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("//") {
            continue;
        }
        if words_file && trimmed.starts_with("pub fn ") {
            if returns_words(lines, at) {
                found.push((at, 1));
            }
            continue;
        }
        if words_file && trimmed.starts_with("pub const ") && trimmed.contains(": &") {
            found.push((at, 1));
            continue;
        }
        if line.contains("fn say(") {
            continue;
        }
        let needed = [
            "Error::Refused(",
            "Error::Failed(",
            "Begin::Refuse(",
            "say(",
        ]
        .iter()
        .map(|needle| occurrences(line, needle))
        .sum();
        if needed > 0 {
            found.push((at, needed));
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

/// What is wrong between the sources (file name, text) and the table, as sentences. An empty list
/// is a source whose every place has a row and a table whose every row has a place.
fn check(sources: &[(&str, &str)], table: &str) -> Vec<String> {
    let mut faults = Vec::new();
    let mut carried: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (file, text) in sources {
        let lines: Vec<&str> = text.lines().collect();
        for (at, needed) in places(file, &lines) {
            let ids: Vec<&str> = at
                .checked_sub(1)
                .and_then(|before| lines[before].trim_start().strip_prefix(MARKER))
                .map(|ids| ids.split_whitespace().collect())
                .unwrap_or_default();
            if ids.len() != needed || !ids.iter().all(|id| is_identifier(id)) {
                faults.push(format!(
                    "{file}:{}: a place that makes {needed} text(s) has no `{MARKER}<identifier>` line before it, or the wrong number of identifiers",
                    at + 1
                ));
                continue;
            }
            for id in ids {
                carried
                    .entry(id.to_owned())
                    .or_default()
                    .push(format!("{file}:{}", at + 1));
            }
        }
    }
    let mut rows: BTreeMap<String, usize> = BTreeMap::new();
    for (number, line) in table.lines().enumerate() {
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split(" | ").map(str::trim).collect();
        if fields.len() != 3
            || fields.iter().any(|field| field.is_empty())
            || !is_identifier(fields[0])
        {
            faults.push(format!(
                "table line {}: not `<identifier> | <sentence> | <read>`",
                number + 1
            ));
            continue;
        }
        *rows.entry(fields[0].to_owned()).or_default() += 1;
    }
    for (id, where_) in &carried {
        if where_.len() > 1 {
            faults.push(format!(
                "identifier {id} is carried by {} places: {}",
                where_.len(),
                where_.join(", ")
            ));
        }
        if !rows.contains_key(id) {
            faults.push(format!(
                "identifier {id} ({}) has no row in the table",
                where_.join(", ")
            ));
        }
    }
    for id in rows.keys() {
        if !carried.contains_key(id) {
            faults.push(format!(
                "the table has a row for {id}, and no place carries it"
            ));
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

/// Every place of the crate's source that makes a text has an identifier and a row, and every row
/// has a place that carries it.
#[test]
fn every_place_that_makes_a_text_has_a_row_and_every_row_a_place() {
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
/// for a row without a place and for an identifier used twice, and it takes patterns, longer names,
/// methods and functions that return no words for no place.
#[test]
fn the_check_fails_for_a_place_without_a_row_a_row_without_a_place_and_a_name_used_twice() {
    let good = "fn f() {\n    // text: f-1\n    return Err(Error::Refused(x));\n}\n";
    let table = "f-1 | a sentence | read: a call\n";
    assert_eq!(check(&[("install.rs", good)], table), Vec::<String>::new());

    // A place without an identifier.
    let bare = "fn f() {\n    return Err(Error::Failed(x));\n}\n";
    let faults = check(&[("install.rs", bare)], "");
    assert_eq!(faults.len(), 1, "{faults:?}");
    assert!(faults[0].starts_with("install.rs:2:"), "{faults:?}");
    // A marker that is not on the line before the place.
    let far = "// text: f-1\nlet x = 1;\nsay(\"x\");\n";
    assert_eq!(check(&[("install.rs", far)], table).len(), 2);
    // A place that makes two texts on one line needs two identifiers.
    let two = "// text: f-1\nlet _ = (Error::Failed(a), say(b));\n";
    assert_eq!(check(&[("install.rs", two)], table).len(), 2);
    let two_ok = "// text: f-1 f-2\nlet _ = (Error::Failed(a), say(b));\n";
    let two_table = "f-1 | a | read: x\nf-2 | b | read: y\n";
    assert!(check(&[("install.rs", two_ok)], two_table).is_empty());

    // An identifier with no row, and a row with no place.
    let faults = check(&[("install.rs", good)], "g-1 | a sentence | read: a call\n");
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
    let twice = "// text: f-1\nsay(a);\n// text: f-1\nsay(b);\n";
    let faults = check(&[("install.rs", twice)], table);
    assert_eq!(faults.len(), 1, "{faults:?}");
    assert!(faults[0].contains("carried by 2 places"), "{faults:?}");
    let faults = check(&[("install.rs", good), ("other.rs", good)], table);
    assert_eq!(faults.len(), 1, "{faults:?}");

    // A row with a missing field, an empty field or a bad identifier.
    for bad in [
        "f-1 | only a sentence\n",
        "f-1 |  | read\n",
        "f 1 | a | b\n",
    ] {
        assert!(!check(&[("install.rs", good)], bad).is_empty(), "{bad}");
    }

    // Not places: a pattern, a longer name, a method, a definition, a comment and a word-free function.
    let not_places = "fn say(line: &str) {}\nErr(Error::Refused(_)) => 1,\nRootError::Refused(x);\nthing.say(x);\nm::say(x);\n// Error::Failed(x) in a comment\n/// say(x) in a doc comment\n";
    assert!(check(&[("install.rs", not_places)], "").is_empty());
    let no_words = "pub fn is_ok(a: &str) -> bool {\n    true\n}\n";
    assert!(check(&[("remedy.rs", no_words)], "").is_empty());
    // A public function that returns words, in the two files that hold them and in no other.
    for returned in ["String", "Option<String>", "&'static str", "Vec<String>"] {
        let words = format!("pub fn words(a: &str) -> {returned} {{\n    todo!()\n}}\n");
        assert_eq!(check(&[("remedy.rs", &words)], "").len(), 1, "{returned}");
        assert_eq!(check(&[("records.rs", &words)], "").len(), 1, "{returned}");
        assert!(
            check(&[("setup_args.rs", &words)], "").is_empty(),
            "{returned}"
        );
    }
    let words = "pub fn words(\n    a: &str,\n) -> String {\n    todo!()\n}\n";
    assert_eq!(check(&[("remedy.rs", words)], "").len(), 1);
    let carried = "// text: words\npub fn words(\n    a: &str,\n) -> String {\n    todo!()\n}\n";
    assert!(check(&[("remedy.rs", carried)], "words | s | read: r\n").is_empty());
    // A constant of words.
    let constant = "pub const WHY: &str = \"x\";\n";
    assert_eq!(check(&[("remedy.rs", constant)], "").len(), 1);
    // A refusal that a result carries is a place; a pattern that passes it on is not.
    let returned = "Look::There => Begin::Refuse(format!(\"x\")),\n";
    assert_eq!(check(&[("records.rs", returned)], "").len(), 1);
    let passed_on = "records::Begin::Refuse(text) => return Err(Error::Refused(text)),\n";
    assert_eq!(check(&[("install.rs", passed_on)], "").len(), 1);
    let only_passed_on = "records::Begin::Refuse(text) => return Ok(text),\n";
    assert!(check(&[("install.rs", only_passed_on)], "").is_empty());
}
