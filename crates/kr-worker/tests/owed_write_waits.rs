//! The spool's owed write has one appender, no waiter that holds the session, and no reader that is
//! told of retained output while a discard of it is owed.
//!
//! `owed_write_waits.txt` lists, against the source of this crate, every call of the four ways to
//! append output (`append_deferred`, `OutputHistory::append`, `ingest_output_deferring_the_spool`
//! and `ingest_output`) and of every wait for the write that is in flight, by file, function and
//! callee, with how many there are; and every method of the history that reads it, with how it
//! answers while a discard is owed. A call with no row, a row with no call, a different number of
//! calls and a reader that does not answer through the history's one helper each fail the case.
//!
//! What this holds and what it does not. It reads source text with the comments, the string
//! literals and the test modules taken out, and finds a call by the name that follows a `.` or a
//! `::`. It does not follow a call into another function or tell the receiver's type: `append` is
//! also a method of other types, and each of those has a row of its own, so that an `append` on an
//! output history in a new place fails like any other new one. It does not see that a lock is not
//! held across a wait: the two waits that may exist are listed, and a person's read decides what
//! each holds.
//!
//! The cases after the first run the scan over small trees of source text, so that each way it
//! could miss a caller is shown by a caller it must find.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// The names whose calls are listed.
const CALLEES: &[&str] = &[
    "append",
    "append_deferred",
    "ingest_output",
    "ingest_output_deferring_the_spool",
    "wait_for_owed_write",
    "wait_idle",
    "wait_idle_for",
    "wait_for_the_spool_write",
];

/// The file the history lives in, and the type whose readers are listed.
const HISTORY: &str = "crates/kr-worker/src/history.rs";
const HISTORY_TYPE: &str = "OutputHistory";

/// Source text with its comments, string and character literals blanked, newlines kept.
fn blank(source: &str) -> String {
    let bytes: Vec<char> = source.chars().collect();
    let mut out = String::with_capacity(source.len());
    let mut at = 0;
    let keep = |c: char| if c == '\n' { '\n' } else { ' ' };
    while at < bytes.len() {
        let c = bytes[at];
        let next = bytes.get(at + 1).copied();
        if c == '/' && next == Some('/') {
            while at < bytes.len() && bytes[at] != '\n' {
                out.push(' ');
                at += 1;
            }
        } else if c == '/' && next == Some('*') {
            let mut depth = 0;
            while at < bytes.len() {
                if bytes[at] == '/' && bytes.get(at + 1) == Some(&'*') {
                    depth += 1;
                    out.push_str("  ");
                    at += 2;
                } else if bytes[at] == '*' && bytes.get(at + 1) == Some(&'/') {
                    depth -= 1;
                    out.push_str("  ");
                    at += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    out.push(keep(bytes[at]));
                    at += 1;
                }
            }
        } else if c == 'r' && matches!(next, Some('"' | '#')) && is_raw_string(&bytes, at) {
            let mut hashes = 0;
            let mut cursor = at + 1;
            while bytes.get(cursor) == Some(&'#') {
                hashes += 1;
                cursor += 1;
            }
            cursor += 1; // the opening quote
            loop {
                if cursor >= bytes.len() {
                    break;
                }
                if bytes[cursor] == '"'
                    && (0..hashes).all(|k| bytes.get(cursor + 1 + k) == Some(&'#'))
                {
                    cursor += 1 + hashes;
                    break;
                }
                cursor += 1;
            }
            while at < cursor {
                out.push(keep(bytes[at]));
                at += 1;
            }
        } else if c == '"' {
            out.push(' ');
            at += 1;
            while at < bytes.len() && bytes[at] != '"' {
                if bytes[at] == '\\' {
                    out.push(' ');
                    at += 1;
                }
                if at < bytes.len() {
                    out.push(keep(bytes[at]));
                    at += 1;
                }
            }
            out.push(' ');
            at += 1;
        } else if c == '\'' && is_char_literal(&bytes, at) {
            let mut cursor = at + 1;
            if bytes[cursor] == '\\' {
                cursor += 1;
            }
            cursor += 1;
            while cursor < bytes.len() && bytes[cursor] != '\'' {
                cursor += 1;
            }
            while at <= cursor && at < bytes.len() {
                out.push(' ');
                at += 1;
            }
        } else {
            out.push(c);
            at += 1;
        }
    }
    out
}

/// Whether the `r` at `at` opens a raw string: `r"` or `r#..#"`, and not the end of a word.
fn is_raw_string(bytes: &[char], at: usize) -> bool {
    if at > 0 && (bytes[at - 1].is_alphanumeric() || bytes[at - 1] == '_') {
        return false;
    }
    let mut cursor = at + 1;
    while bytes.get(cursor) == Some(&'#') {
        cursor += 1;
    }
    bytes.get(cursor) == Some(&'"')
}

/// Whether the quote at `at` opens a character literal and not a lifetime.
fn is_char_literal(bytes: &[char], at: usize) -> bool {
    matches!(
        (bytes.get(at + 1), bytes.get(at + 2)),
        (Some('\\'), _) | (Some(_), Some('\''))
    )
}

/// Blanks every `#[cfg(test)]` module, so that a call a test makes is not a shipped one.
fn without_test_modules(blanked: &str) -> String {
    let mut text: Vec<char> = blanked.chars().collect();
    let mut from = 0;
    let needle: Vec<char> = "#[cfg(test)]".chars().collect();
    while let Some(found) = find(&text, &needle, from) {
        let mut cursor = found + needle.len();
        // Another attribute may stand between, and then the item: only a module is a test module.
        let rest: String = text[cursor..].iter().take(200).collect();
        let trimmed = rest.trim_start();
        if !trimmed.starts_with("mod ") && !trimmed.starts_with("pub mod ") {
            from = cursor;
            continue;
        }
        while cursor < text.len() && text[cursor] != '{' && text[cursor] != ';' {
            cursor += 1;
        }
        if cursor >= text.len() || text[cursor] == ';' {
            from = cursor;
            continue;
        }
        let mut depth = 0;
        let mut end = cursor;
        while end < text.len() {
            match text[end] {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                _ => {}
            }
            end += 1;
        }
        let last = end.min(text.len() - 1);
        for c in &mut text[found..=last] {
            if *c != '\n' {
                *c = ' ';
            }
        }
        from = end;
    }
    text.into_iter().collect()
}

fn find(text: &[char], needle: &[char], from: usize) -> Option<usize> {
    (from..text.len().saturating_sub(needle.len()) + 1).find(|&at| text[at..].starts_with(needle))
}

fn is_ident(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// One call of a listed name: where it stands and what it calls.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Site {
    file: String,
    function: String,
    callee: String,
}

/// The identifiers of a text with their offsets.
fn idents(text: &[char]) -> Vec<(usize, String)> {
    let mut found = Vec::new();
    let mut at = 0;
    while at < text.len() {
        if is_ident(text[at]) && !text[at].is_ascii_digit() {
            let start = at;
            while at < text.len() && is_ident(text[at]) {
                at += 1;
            }
            found.push((start, text[start..at].iter().collect()));
        } else {
            at += 1;
        }
    }
    found
}

/// The function each offset of a text is in: its name, or none at the top of a file.
fn function_at(text: &[char]) -> Vec<Option<String>> {
    let mut inside = vec![None; text.len()];
    let words = idents(text);
    let mut stack: Vec<(String, usize)> = Vec::new();
    let mut depth = 0_usize;
    let mut pending: Option<String> = None;
    let mut word = 0;
    for (at, &c) in text.iter().enumerate() {
        while word < words.len() && words[word].0 < at {
            word += 1;
        }
        if word < words.len() && words[word].0 == at && words[word].1 == "fn" {
            pending = words.get(word + 1).map(|(_, name)| name.clone());
        }
        match c {
            '{' => {
                depth += 1;
                if let Some(name) = pending.take() {
                    stack.push((name, depth));
                }
            }
            '}' => {
                if stack.last().is_some_and(|(_, opened)| *opened == depth) {
                    stack.pop();
                }
                depth = depth.saturating_sub(1);
            }
            ';' if depth == stack.last().map_or(0, |(_, opened)| *opened) => pending = None,
            _ => {}
        }
        inside[at] = stack.last().map(|(name, _)| name.clone());
    }
    inside
}

/// Every call of a listed name in one file's shipped source.
fn sites(file: &str, source: &str) -> Vec<Site> {
    let text: Vec<char> = without_test_modules(&blank(source)).chars().collect();
    let inside = function_at(&text);
    let mut found = Vec::new();
    for (at, name) in idents(&text) {
        if !CALLEES.contains(&name.as_str()) {
            continue;
        }
        let after = at + name.len();
        let opens = text[after..]
            .iter()
            .find(|c| !c.is_whitespace())
            .is_some_and(|c| *c == '(');
        let before: Vec<&char> = text[..at]
            .iter()
            .rev()
            .filter(|c| !c.is_whitespace())
            .take(2)
            .collect();
        let reached = matches!(before.as_slice(), ['.', ..] | [':', ':']);
        if opens && reached {
            found.push(Site {
                file: file.to_owned(),
                function: inside[at].clone().unwrap_or_else(|| "(top)".to_owned()),
                callee: name,
            });
        }
    }
    found
}

/// The body of function `name` in `text`, and the offset it starts at, from its first `{`.
fn body_of(text: &[char], name: &str, from: usize, to: usize) -> Option<(usize, usize)> {
    for (at, word) in idents(&text[from..to]) {
        let at = at + from;
        let preceded_by_fn = idents(&text[..at])
            .last()
            .is_some_and(|(_, last)| last == "fn");
        if word == name && preceded_by_fn {
            let mut cursor = at;
            while cursor < to && text[cursor] != '{' && text[cursor] != ';' {
                cursor += 1;
            }
            if cursor >= to || text[cursor] == ';' {
                return None;
            }
            let mut depth = 0;
            let mut end = cursor;
            while end < to {
                match text[end] {
                    '{' => depth += 1,
                    '}' => {
                        depth -= 1;
                        if depth == 0 {
                            return Some((cursor, end));
                        }
                    }
                    _ => {}
                }
                end += 1;
            }
        }
    }
    None
}

/// The range of the `impl <HISTORY_TYPE> {` block of a file.
fn impl_range(text: &[char], ty: &str) -> Option<(usize, usize)> {
    let needle: Vec<char> = format!("impl {ty} {{").chars().collect();
    let start = find(text, &needle, 0)?;
    let open = start + needle.len() - 1;
    let mut depth = 0;
    for (offset, c) in text[open..].iter().enumerate() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some((open, open + offset));
                }
            }
            _ => {}
        }
    }
    None
}

/// The methods of the history type that take `&self`, public or not, with the text of their bodies.
fn history_methods(source: &str) -> Vec<(String, String)> {
    let text: Vec<char> = without_test_modules(&blank(source)).chars().collect();
    let Some((from, to)) = impl_range(&text, HISTORY_TYPE) else {
        return Vec::new();
    };
    let mut methods = Vec::new();
    let words = idents(&text[from..to]);
    for (index, (at, word)) in words.iter().enumerate() {
        if word != "fn" {
            continue;
        }
        let at = at + from;
        let Some((_, name)) = words.get(index + 1) else {
            continue;
        };
        let header: String = text[at..(at + 400).min(to)].iter().collect();
        let header = header.split(['{', ';']).next().unwrap_or("").to_owned();
        let before: String = text[..at].iter().collect();
        let before = before.trim_end();
        let public = before.ends_with("pub") || before.ends_with("pub const");
        if !header.contains("&self") || !public {
            continue;
        }
        if let Some((open, close)) = body_of(&text, name, from, to) {
            methods.push((name.clone(), text[open..=close].iter().collect()));
        }
    }
    methods
}

/// What the roster says.
#[derive(Debug, Default)]
struct Roster {
    sites: BTreeMap<Site, usize>,
    readers: BTreeMap<String, String>,
    exempt: BTreeMap<String, String>,
}

fn parse(roster: &str) -> Roster {
    let mut parsed = Roster::default();
    for line in roster.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        let words: Vec<&str> = line.split_whitespace().collect();
        match words.as_slice() {
            [] => {}
            ["site", file, function, callee, count] => {
                parsed.sites.insert(
                    Site {
                        file: (*file).to_owned(),
                        function: (*function).to_owned(),
                        callee: (*callee).to_owned(),
                    },
                    count.parse().expect("a count"),
                );
            }
            ["reader", name, "via", via] => {
                parsed.readers.insert((*name).to_owned(), (*via).to_owned());
            }
            ["exempt", name, reason @ ..] if !reason.is_empty() => {
                parsed.exempt.insert((*name).to_owned(), reason.join(" "));
            }
            other => panic!("a roster line this scan cannot read: {other:?}"),
        }
    }
    parsed
}

/// Every way the tree and the roster disagree, one line each.
fn violations(files: &[(String, String)], roster: &Roster) -> Vec<String> {
    let mut found: BTreeMap<Site, usize> = BTreeMap::new();
    for (name, source) in files {
        for site in sites(name, source) {
            *found.entry(site).or_default() += 1;
        }
    }
    let mut out = Vec::new();
    for (site, count) in &found {
        match roster.sites.get(site) {
            None => out.push(format!(
                "a call with no row: {} in {} calls {} ({count} times)",
                site.function, site.file, site.callee
            )),
            Some(listed) if listed != count => out.push(format!(
                "{} in {} calls {} {count} times and the roster says {listed}",
                site.function, site.file, site.callee
            )),
            Some(_) => {}
        }
    }
    for site in roster.sites.keys() {
        if !found.contains_key(site) {
            out.push(format!(
                "a row with no call: {} in {} calls {}",
                site.function, site.file, site.callee
            ));
        }
    }

    // The readers of the history.
    let history = files.iter().find(|(name, _)| name == HISTORY);
    let methods = history
        .map(|(_, source)| history_methods(source))
        .unwrap_or_default();
    let known: Vec<&str> = methods.iter().map(|(name, _)| name.as_str()).collect();
    for (name, body) in &methods {
        let through = if let Some(via) = roster.readers.get(name) {
            let needle = if via == "standing" {
                ".standing()".to_owned()
            } else {
                format!("self.{via}(")
            };
            if body.contains(&needle) {
                continue;
            }
            Some(format!(
                "the reader {name} does not answer through {via}: it never calls {needle}"
            ))
        } else if roster.exempt.contains_key(name) {
            continue;
        } else {
            Some(format!("a method of the history with no row: {name}"))
        };
        out.extend(through);
    }
    for name in roster.readers.keys().chain(roster.exempt.keys()) {
        if history.is_some() && !known.contains(&name.as_str()) {
            out.push(format!("a row for a method that is not there: {name}"));
        }
    }

    // What the discard and the appender must do, which the rows above do not say.
    if let Some((_, source)) = history {
        let text: Vec<char> = without_test_modules(&blank(source)).chars().collect();
        if let Some((open, close)) = body_of(&text, "discard_window_and_spool", 0, text.len()) {
            let body: String = text[open..=close].iter().collect();
            if !body.contains("defer_discard_if_in_flight") {
                out.push(
                    "discard_window_and_spool does not look at the write in flight".to_owned(),
                );
            }
            for wait in ["wait_idle", "wait_for_owed_write", "wait_idle_for"] {
                if body.contains(wait) {
                    out.push(format!("discard_window_and_spool waits: it calls {wait}"));
                }
            }
        }
    }
    out
}

fn source_files(root: &Path, directory: &Path, found: &mut Vec<(String, String)>) {
    let mut entries: Vec<PathBuf> = std::fs::read_dir(directory)
        .expect("a source directory")
        .flatten()
        .map(|entry| entry.path())
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            source_files(root, &path, found);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            let name = path
                .strip_prefix(root)
                .expect("under the root")
                .to_string_lossy()
                .replace('\\', "/");
            found.push((name, std::fs::read_to_string(&path).expect("a source file")));
        }
    }
}

fn tree() -> Vec<(String, String)> {
    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut found = Vec::new();
    source_files(crate_root, &crate_root.join("src"), &mut found);
    for (name, _) in &mut found {
        *name = format!("crates/kr-worker/{name}");
    }
    found
}

fn roster() -> Roster {
    parse(include_str!("owed_write_waits.txt"))
}

#[test]
fn the_spool_has_one_appender_and_no_waiter_that_holds_the_session() {
    let found = violations(&tree(), &roster());
    assert!(found.is_empty(), "{}", found.join("\n"));
}

// ---------------------------------------------------------------------------------------------
// The scan over small trees
// ---------------------------------------------------------------------------------------------

const HISTORY_TREE: &str = r#"
pub struct OutputHistory {}
impl OutputHistory {
    pub fn append_deferred(&mut self) { self.wait_for_owed_write(); }
    fn wait_for_owed_write(&self) { spool.owed.wait_idle(); }
    fn discard_window_and_spool(&mut self) {
        if spool.owed.defer_discard_if_in_flight() { return; }
    }
    pub fn page(&self) -> u8 { self.standing().oldest }
    pub fn page_within(&self) -> u8 { self.page() }
    pub fn next_cursor(&self) -> u64 { 0 }
}
"#;

const CLEAN_ROSTER: &str = "
site crates/kr-worker/src/history.rs append_deferred wait_for_owed_write 1
site crates/kr-worker/src/history.rs wait_for_owed_write wait_idle 1
reader page via standing
reader page_within via page
exempt next_cursor it is the session's own position and a discard leaves it
";

fn small(extra: &[(&str, &str)], roster: &str) -> Vec<String> {
    let mut files = vec![(HISTORY.to_owned(), HISTORY_TREE.to_owned())];
    files.extend(
        extra
            .iter()
            .map(|(n, s)| ((*n).to_owned(), (*s).to_owned())),
    );
    violations(&files, &parse(roster))
}

#[test]
fn a_tree_the_roster_describes_has_no_violation() {
    assert_eq!(small(&[], CLEAN_ROSTER), Vec::<String>::new());
}

#[test]
fn a_second_caller_of_the_pumps_entry_point_is_found() {
    let roster = format!(
        "{CLEAN_ROSTER}site crates/kr-worker/src/runtime.rs start ingest_output_deferring_the_spool 1\n"
    );
    let pump = "fn start() { session.ingest_output_deferring_the_spool(&b); }";
    let two = "fn start() { session.ingest_output_deferring_the_spool(&b); }\nfn other() { s.ingest_output_deferring_the_spool(&b); }";
    assert_eq!(
        small(&[("crates/kr-worker/src/runtime.rs", pump)], &roster),
        Vec::<String>::new()
    );
    let found = small(&[("crates/kr-worker/src/runtime.rs", two)], &roster);
    assert!(
        found
            .iter()
            .any(|line| line.contains("other") && line.contains("no row")),
        "{found:?}"
    );
}

#[test]
fn a_second_call_in_the_same_function_is_found() {
    let roster = format!(
        "{CLEAN_ROSTER}site crates/kr-worker/src/runtime.rs start ingest_output_deferring_the_spool 1\n"
    );
    let two = "fn start() { a.ingest_output_deferring_the_spool(&b); a.ingest_output_deferring_the_spool(&c); }";
    let found = small(&[("crates/kr-worker/src/runtime.rs", two)], &roster);
    assert!(
        found.iter().any(|line| line.contains("2 times")),
        "{found:?}"
    );
}

#[test]
fn an_append_on_an_output_history_in_a_new_place_is_found() {
    let rogue = "fn rogue(h: &mut OutputHistory) { h.append(b\"\"); }";
    let found = small(&[("crates/kr-worker/src/session.rs", rogue)], CLEAN_ROSTER);
    assert!(
        found
            .iter()
            .any(|line| line.contains("rogue") && line.contains("append")),
        "{found:?}"
    );
}

#[test]
fn a_shipped_caller_of_ingest_output_is_found() {
    let rogue = "fn rogue(s: &mut Session) { s.ingest_output(b\"\"); }";
    let found = small(&[("crates/kr-worker/src/service.rs", rogue)], CLEAN_ROSTER);
    assert!(
        found.iter().any(|line| line.contains("ingest_output")),
        "{found:?}"
    );
}

#[test]
fn the_wait_put_back_into_the_discard_is_found() {
    let waiting = HISTORY_TREE.replace(
        "if spool.owed.defer_discard_if_in_flight() { return; }",
        "self.wait_for_owed_write(); if spool.owed.defer_discard_if_in_flight() { return; }",
    );
    let roster = format!(
        "{CLEAN_ROSTER}site crates/kr-worker/src/history.rs discard_window_and_spool wait_for_owed_write 1\n"
    );
    let found = violations(&[(HISTORY.to_owned(), waiting)], &parse(&roster));
    assert!(
        found
            .iter()
            .any(|line| line.contains("discard_window_and_spool waits")),
        "{found:?}"
    );
}

#[test]
fn a_reader_that_does_not_answer_through_the_helper_is_found() {
    let bare = HISTORY_TREE.replace("self.standing().oldest", "0");
    let found = violations(&[(HISTORY.to_owned(), bare)], &parse(CLEAN_ROSTER));
    assert!(
        found
            .iter()
            .any(|line| line.contains("reader page does not answer")),
        "{found:?}"
    );
}

#[test]
fn a_new_method_of_the_history_with_no_row_is_found() {
    let more = HISTORY_TREE.replace(
        "pub fn next_cursor",
        "pub fn how_much(&self) -> u64 { 0 }\n    pub fn next_cursor",
    );
    let found = violations(&[(HISTORY.to_owned(), more)], &parse(CLEAN_ROSTER));
    assert!(
        found.iter().any(|line| line.contains("how_much")),
        "{found:?}"
    );
}

#[test]
fn a_row_with_no_call_is_found() {
    let roster =
        format!("{CLEAN_ROSTER}site crates/kr-worker/src/runtime.rs start append_deferred 1\n");
    let found = small(&[], &roster);
    assert!(
        found.iter().any(|line| line.contains("a row with no call")),
        "{found:?}"
    );
}

#[test]
fn comments_strings_and_test_modules_hold_no_call() {
    let quiet = r##"
// s.ingest_output(b"")
/* s.ingest_output(b"") */
fn quiet() { let _ = "s.ingest_output(b\"\")"; let _ = r#"s.ingest_output(x)"#; }
#[cfg(test)]
mod tests { fn t() { s.ingest_output(b""); } }
"##;
    assert_eq!(
        small(&[("crates/kr-worker/src/session.rs", quiet)], CLEAN_ROSTER),
        Vec::<String>::new()
    );
}
