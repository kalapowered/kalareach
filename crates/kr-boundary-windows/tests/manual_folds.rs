//! A scan of the crate's product sources (`src/`, not `tests/`, not the build script) for the forms
//! that can fold a failed read into a value without a method that the linter's list can name, each
//! of which stands in `tests/manual_folds.txt` with its reason.
//!
//! The forms: a `match` arm on an error that does not use what it caught (`Err(_) =>`, `Err(..) =>`,
//! or a name that the arm's text never mentions, an underscore name included: `Err(_error) =>`), a
//! wildcard arm (`_ =>`, `_ if .. =>`) of a `match` whose earlier arms at the same indentation match
//! an `Ok(` or an `Err(`, an `if let Ok(` or `while let Ok(`, a `let Ok(` with an `else`, a `.err()`,
//! a result that is discarded (`let _ =` or a binding that starts with an underscore), and a
//! `matches!(` over an `Ok(`, an `Err(` or a lookup's answer. A place is found by its file, its form
//! and the statement's own text (the first line, trimmed), never by a line number, so a place moves
//! with its code and a new one cannot come in without a row.
//!
//! What it cannot see:
//! - a form over several lines: a pattern or an arrow on a later line than the first of the
//!   statement, a wildcard arm whose earlier arms are not at its indentation, and a `match` whose
//!   result arms all stand after the wildcard;
//! - a pattern in a tuple (`(Ok(a), Err(_)) =>`), which is read only as far as the first `Err(` on
//!   its line, and a `match` whose arms name no `Ok(` or `Err(` (a wildcard on a value that was
//!   made from a result is then not a place);
//! - a fold that is written another way: a closure that swallows an error, `Result::into_iter` and
//!   `for` over a result, an `Option` made from a `Result` by a method outside the linter's list,
//!   and an error that an arm uses only to build a value that hides it;
//! - what lies after a `#[cfg(test)]` line.
//!
//! A call whose result is discarded as a statement (`read_machine();`) is not looked for here: the
//! compiler refuses it. Every `Result` is `#[must_use]`, and the `unused_must_use` lint of rustc
//! (a warning that the checks' `-D warnings` turns into an error) refuses a statement that drops one;
//! this crate sets no `allow` for it. The reviewer's read is what holds a row's reason true. They
//! run on every platform.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

/// One place of a form in a source, with how many times the same statement stands in the file.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Place {
    file: String,
    form: &'static str,
    text: String,
}

fn sources(dir: &Path, found: &mut Vec<PathBuf>) {
    let mut entries: Vec<PathBuf> = fs::read_dir(dir)
        .expect("a source directory is read")
        .map(|entry| entry.expect("an entry is read").path())
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            sources(&path, found);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            found.push(path);
        }
    }
}

fn indentation(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

/// The words of an identifier that stand in a pattern as names: lower-case words that are not a
/// path's part, not the head of a call and not a wildcard.
fn bindings(pattern: &str) -> Vec<String> {
    let characters: Vec<char> = pattern.chars().collect();
    let mut names = Vec::new();
    let mut start = None;
    for index in 0..=characters.len() {
        let is_word = characters
            .get(index)
            .is_some_and(|c| c.is_alphanumeric() || *c == '_');
        match (start, is_word) {
            (None, true) => start = Some(index),
            (Some(from), false) => {
                let word: String = characters[from..index].iter().collect();
                let next = characters.get(index).copied();
                let after_path = from >= 2 && characters[from - 2..from] == [':', ':'];
                // An underscore name (`_error`) is a name that the arm may leave unused; the
                // wildcard alone is the pattern `_`, which the caller reads.
                let lower = word
                    .chars()
                    .next()
                    .is_some_and(|first| first.is_lowercase() || (first == '_' && word.len() > 1));
                if lower
                    && word != "ref"
                    && word != "mut"
                    && next != Some('(')
                    && next != Some(':')
                    && !after_path
                {
                    names.push(word);
                }
                start = None;
            }
            _ => {}
        }
    }
    names
}

/// Whether the text mentions the name as a word.
fn mentions(text: &str, name: &str) -> bool {
    let mut from = 0;
    while let Some(at) = text[from..].find(name) {
        let start = from + at;
        let end = start + name.len();
        let before = text[..start].chars().next_back();
        let after = text[end..].chars().next();
        let word = |c: Option<char>| c.is_some_and(|c| c.is_alphanumeric() || c == '_');
        if !word(before) && !word(after) {
            return true;
        }
        from = end;
    }
    false
}

/// Whether an arm at this indentation belongs to a `match` that has an earlier arm, at the same
/// indentation, with a pattern of `Ok(` or `Err(`: the lines before the arm are read backwards until
/// the line that is less indented (the `match` itself).
fn arms_before_match_a_result(before: &[&str], indent: usize) -> bool {
    for line in before.iter().rev() {
        if line.trim().is_empty() {
            continue;
        }
        let here = indentation(line);
        if here < indent {
            return false;
        }
        if here == indent {
            let pattern = line.trim_start().split("=>").next().unwrap_or("");
            if pattern.contains("Ok(") || pattern.contains("Err(") {
                return true;
            }
        }
    }
    false
}

/// The places of the forms in one source's text.
fn scan(file: &str, text: &str) -> Vec<Place> {
    let lines: Vec<&str> = text.lines().collect();
    let mut places = Vec::new();
    for (index, raw) in lines.iter().enumerate() {
        let line = raw.trim();
        if line == "#[cfg(test)]" {
            break;
        }
        if line.starts_with("//") || line.starts_with("#[") {
            continue;
        }
        let mut place = |form: &'static str| {
            places.push(Place {
                file: file.to_owned(),
                form,
                text: line.to_owned(),
            });
        };
        // An arm's pattern may follow another one (`Ok(None) | Err(_) =>`), so the error pattern is
        // looked for anywhere on the line, at the start of a word.
        let at = line.find("Err(").filter(|at| {
            line[..*at]
                .chars()
                .next_back()
                .is_none_or(|before| !(before.is_alphanumeric() || before == '_'))
        });
        if let Some(at) = at
            && let rest = &line[at + 4..]
            && let Some(arrow) = rest.find("=>")
            && !line[..at].contains("=>")
        {
            let head = &rest[..arrow];
            let pattern = head.split(" if ").next().unwrap_or(head).trim_end();
            let pattern = pattern.strip_suffix(')').unwrap_or(pattern);
            // What the arm uses includes its guard: an arm that examines the error in its guard (its
            // kind or its number) handles that case by name and does not fold the others.
            let mut arm = String::from(
                &line[line
                    .find(" if ")
                    .unwrap_or_else(|| line.find("=>").unwrap_or(0))..],
            );
            for next in &lines[index + 1..] {
                if next.trim().is_empty() || indentation(next) > indentation(raw) {
                    arm.push('\n');
                    arm.push_str(next);
                } else {
                    break;
                }
            }
            let names = bindings(pattern);
            let folds = pattern == "_"
                || pattern == ".."
                || (!names.is_empty() && names.iter().all(|name| !mentions(&arm, name)));
            if folds {
                place("an error arm that does not use the error");
            }
        }
        // A wildcard arm catches an error without naming it, where the arms before it match a result.
        if (line.starts_with("_ =>") || line.starts_with("_ if "))
            && arms_before_match_a_result(&lines[..index], indentation(raw))
        {
            place("a wildcard arm of a match on a result");
        }
        if line.starts_with("let Ok(") {
            place("let Ok else");
        } else if line.contains("let Ok(") {
            place("if let Ok");
        }
        if line.contains(".try_exists()") {
            place(".try_exists()");
        }
        if line.contains(".err()") {
            place(".err()");
        }
        if line.starts_with("let _ =")
            || line.starts_with("let _ :")
            || line.starts_with("let _")
                && line[5..].starts_with(|c: char| c.is_alphanumeric() || c == '_')
                && line.contains('=')
        {
            place("a result that is discarded");
        }
        if line.contains("matches!(")
            && (line.contains("Ok(")
                || line.contains("Err(")
                || line.contains("Look::")
                || line.contains("Waited::"))
        {
            place("matches over a read");
        }
    }
    places
}

/// The rows of the list: file, form, statement, count and reason, separated by tabs.
fn rows(list: &str) -> BTreeMap<(String, String, String), (usize, String)> {
    let mut rows = BTreeMap::new();
    for line in list.lines() {
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.split('\t').collect();
        let [file, form, text, count, reason] = parts.as_slice() else {
            panic!("a row of the list has five parts separated by tabs: {line:?}");
        };
        assert!(!reason.trim().is_empty(), "a row has no reason: {line:?}");
        let count: usize = count.parse().expect("the count of a row is a number");
        let key = ((*file).to_owned(), (*form).to_owned(), (*text).to_owned());
        assert!(
            rows.insert(key, (count, (*reason).to_owned())).is_none(),
            "a place is listed twice: {line:?}"
        );
    }
    rows
}

/// What is wrong between the places and the list, as sentences. An empty list means the two agree.
fn problems(places: &[Place], list: &str) -> Vec<String> {
    let rows = rows(list);
    let mut found: BTreeMap<(String, String, String), usize> = BTreeMap::new();
    for place in places {
        *found
            .entry((
                place.file.clone(),
                place.form.to_owned(),
                place.text.clone(),
            ))
            .or_insert(0) += 1;
    }
    let mut wrong = Vec::new();
    for (key, count) in &found {
        match rows.get(key) {
            None => wrong.push(format!(
                "{} holds {} of `{}` ({} time(s)) with no row",
                key.0, key.1, key.2, count
            )),
            Some((listed, _)) if listed != count => wrong.push(format!(
                "{}: `{}` ({}) stands {} time(s), and its row says {}",
                key.0, key.2, key.1, count, listed
            )),
            Some(_) => {}
        }
    }
    for key in rows.keys() {
        if !found.contains_key(key) {
            wrong.push(format!(
                "the list has a row for `{}` ({}) in {}, and no place holds it",
                key.2, key.1, key.0
            ));
        }
    }
    wrong
}

#[test]
fn every_place_that_can_fold_a_failed_read_stands_in_the_list_with_its_reason() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    sources(&manifest.join("src"), &mut files);
    let mut places = Vec::new();
    for path in &files {
        let relative = path
            .strip_prefix(manifest.join("src"))
            .expect("a source is under src")
            .to_string_lossy()
            .replace('\\', "/");
        let text = fs::read_to_string(path).expect("a source is read");
        places.extend(scan(&relative, &text));
    }
    let list =
        fs::read_to_string(manifest.join("tests/manual_folds.txt")).expect("the list is read");
    let wrong = problems(&places, &list);
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

/// The scan finds each form in a sample, finds nothing in an error arm that carries its error or in
/// a comment, and its comparison with the list names a place without a row, a row without a place
/// and a wrong count.
#[test]
fn the_scan_finds_each_form_and_the_check_names_what_the_list_lacks() {
    let sample = r#"fn read() {
    match step() {
        Ok(value) => value,
        Err(_) => 0,
    }
    match step() {
        Ok(value) => value,
        Err(error) => failures.push(format!("{error}")),
    }
    match step() {
        Ok(value) => value,
        Err(unused) => {
            let nothing = 0;
            nothing
        }
    }
    match step() {
        Ok(value) => value,
        Err(error) => {
            report(&error);
            0
        }
    }
    if let Ok(entries) = std::fs::read_dir(path) {}
    let Ok(file) = open() else { return };
    let seen = step().err();
    let _ = std::fs::remove_dir(path);
    let _kept = step();
    let there = matches!(look(path), Look::NotThere);
    match step() {
        Ok(value) => value,
        Err(_error) => 0,
    }
    match step() {
        Ok(value) => value,
        Err(..) => 0,
    }
    match step() {
        Ok(value) => value,
        _ => 0,
    }
    match count {
        1 => one(),
        _ => other(),
    }
    // Err(_) => 1,
}
#[cfg(test)]
mod tests {
    fn another() { let _ = 1; }
}
"#;
    let places = scan("sample.rs", sample);
    let forms: Vec<&str> = places.iter().map(|place| place.form).collect();
    assert_eq!(
        forms,
        [
            "an error arm that does not use the error",
            "an error arm that does not use the error",
            "if let Ok",
            "let Ok else",
            ".err()",
            "a result that is discarded",
            "a result that is discarded",
            "matches over a read",
            "an error arm that does not use the error",
            "an error arm that does not use the error",
            "a wildcard arm of a match on a result",
        ],
        "{places:#?}"
    );
    let list = "sample.rs\tif let Ok\tif let Ok(entries) = std::fs::read_dir(path) {}\t1\tbecause\nsample.rs\t.err()\tnothing here\t1\tbecause\nsample.rs\tlet Ok else\tlet Ok(file) = open() else { return };\t2\tbecause\n";
    let wrong = problems(&places, list);
    assert!(
        wrong
            .iter()
            .any(|line| line.contains("Err(_) => 0,") && line.contains("no row")),
        "{wrong:?}"
    );
    assert!(
        wrong
            .iter()
            .any(|line| line.contains("nothing here") && line.contains("no place holds it")),
        "{wrong:?}"
    );
    assert!(
        wrong
            .iter()
            .any(|line| line.contains("open()") && line.contains("its row says 2")),
        "{wrong:?}"
    );
    assert!(
        !wrong.iter().any(|line| line.contains("read_dir")),
        "{wrong:?}"
    );
}
