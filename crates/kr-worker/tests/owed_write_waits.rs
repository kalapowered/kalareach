//! The spool's owed write has one appender, no waiter that holds the session, and no reader that is
//! told of retained output while a discard of it is owed or of a settled receipt's content while its
//! removal is owed.
//!
//! `owed_write_waits.txt` lists, against the source of this crate, every call of the four ways to
//! append output (`append_deferred`, `OutputHistory::append`, `ingest_output_deferring_the_spool`
//! and `ingest_output`) and of every wait for the write that is in flight, by file, function and
//! callee, with how many there are; every method of every inherent block of the history's type
//! that takes `&self` or `&mut self`, whatever its visibility, with how it answers while a discard
//! is owed; and every function that selects a receipt's intent or result, with the journal's
//! decision that it asks. A call with no row, a row with no call, a different number of calls, a
//! reader whose body never calls its helper and a content reader whose body never calls the
//! journal's decision each fail the case, and so does a deferral whose look at the write in flight
//! and whose mark do not stand under one lock.
//!
//! What this holds and what it does not. It reads source text with the comments, the string
//! literals and the test modules taken out (the strings are read only to find the SQL that selects
//! a receipt's content), and finds a call by the name that follows a `.` or a `::`. It does not
//! follow a call into another function or tell the receiver's type: `append` is also a method of
//! other types, and each of those has a row of its own, so that an `append` on an output history
//! in a new place fails like any other new one. The check on a reader is a check that a call is
//! present in its body: it does not see that the answer is built from what the call returned. It
//! does not see that a lock is not held across a wait: the two waits that may exist are listed, and
//! a person's read decides what each holds. A statement that selects a receipt's content from a
//! constant is not found, and a method of the history that takes `self` by value is not read.
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
    blank_with(source, false)
}

/// Source text with its comments and character literals blanked and, unless `strings` says to keep
/// them, its string literals too. The text is as long as the source, character for character, so
/// an offset in one is the same place in the other.
fn blank_with(source: &str, strings: bool) -> String {
    let bytes: Vec<char> = source.chars().collect();
    let mut out = String::with_capacity(source.len());
    let mut at = 0;
    let keep = |c: char| if c == '\n' { '\n' } else { ' ' };
    let shown = |c: char| if strings { c } else { keep(c) };
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
                out.push(shown(bytes[at]));
                at += 1;
            }
        } else if c == '"' {
            out.push(shown('"'));
            at += 1;
            while at < bytes.len() && bytes[at] != '"' {
                if bytes[at] == '\\' {
                    out.push(shown('\\'));
                    at += 1;
                }
                if at < bytes.len() {
                    out.push(shown(bytes[at]));
                    at += 1;
                }
            }
            out.push(shown('"'));
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

/// The range of every `impl <ty> {` block of a file, each from its opening brace to its closing one.
fn impl_ranges(text: &[char], ty: &str) -> Vec<(usize, usize)> {
    let needle: Vec<char> = format!("impl {ty} {{").chars().collect();
    let mut ranges = Vec::new();
    let mut cursor = 0;
    while let Some(start) = find(text, &needle, cursor) {
        let open = start + needle.len() - 1;
        let mut depth = 0;
        let mut close = text.len() - 1;
        for (offset, c) in text[open..].iter().enumerate() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        close = open + offset;
                        break;
                    }
                }
                _ => {}
            }
        }
        ranges.push((open, close));
        cursor = close;
    }
    ranges
}

/// The methods of every inherent block of `ty` in a file that take `&self` or `&mut self`, with
/// whatever visibility, and the text of their bodies.
fn methods_of(source: &str, ty: &str) -> Vec<(String, String)> {
    let text: Vec<char> = without_test_modules(&blank(source)).chars().collect();
    let mut methods = Vec::new();
    for (from, to) in impl_ranges(&text, ty) {
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
            let header = header.split(['{', ';']).next().unwrap_or("");
            if !header.contains("&self") && !header.contains("&mut self") {
                continue;
            }
            if let Some((open, close)) = body_of(&text, name, from, to) {
                methods.push((name.clone(), text[open..=close].iter().collect()));
            }
        }
    }
    methods
}

/// Every function of a file, by name, whose body holds a string literal that selects a column
/// named `intent` or `result`: the SQL that reads what a receipt carries as its caller's content.
/// A statement held in a constant is not found; the function that formats the constant into its
/// own query is. Functions of one name in one file are read together.
fn content_readers(file: &str, source: &str) -> Vec<(String, String, String)> {
    let text: Vec<char> = without_test_modules(&blank(source)).chars().collect();
    let kept: Vec<char> = without_test_modules(&blank_with(source, true))
        .chars()
        .collect();
    // Each function's text twice: with its strings, to read the SQL, and without, to find calls.
    let mut bodies: BTreeMap<String, (String, String)> = BTreeMap::new();
    for ((name, with_strings), without_strings) in
        function_at(&text).into_iter().zip(&kept).zip(&text)
    {
        if let Some(name) = name {
            let entry = bodies.entry(name).or_default();
            entry.0.push(*with_strings);
            entry.1.push(*without_strings);
        }
    }
    bodies
        .into_iter()
        .filter(|(_, (with_strings, _))| {
            with_strings.split('"').skip(1).step_by(2).any(|literal| {
                let words: Vec<String> = idents(&literal.chars().collect::<Vec<_>>())
                    .into_iter()
                    .map(|(_, word)| word)
                    .collect();
                words.iter().any(|word| word == "SELECT")
                    && words
                        .iter()
                        .any(|word| word == "intent" || word == "result")
            })
        })
        .map(|(name, (_, without_strings))| (file.to_owned(), name, without_strings))
        .collect()
}

/// What the roster says.
#[derive(Debug, Default)]
struct Roster {
    sites: BTreeMap<Site, usize>,
    readers: BTreeMap<String, String>,
    exempt: BTreeMap<String, String>,
    /// The functions that read a receipt's content, by file and name, and what they ask.
    content_readers: BTreeMap<(String, String), String>,
    content_exempt: BTreeMap<(String, String), String>,
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
            ["content_reader", file, name, "via", via] => {
                parsed
                    .content_readers
                    .insert(((*file).to_owned(), (*name).to_owned()), (*via).to_owned());
            }
            ["content_exempt", file, name, reason @ ..] if !reason.is_empty() => {
                parsed
                    .content_exempt
                    .insert(((*file).to_owned(), (*name).to_owned()), reason.join(" "));
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

    // The readers of the history: every method of every inherent block of its type, in every file,
    // with whatever visibility and a shared or an exclusive receiver.
    let history = files.iter().find(|(name, _)| name == HISTORY);
    let methods: Vec<(String, String)> = files
        .iter()
        .flat_map(|(_, source)| methods_of(source, HISTORY_TYPE))
        .collect();
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
                "the reader {name} never calls {via}: {needle} is not in its body"
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

    // The functions that read what a receipt carries as its caller's content, and what each asks.
    let mut content = BTreeMap::new();
    for (name, source) in files {
        for (file, function, body) in content_readers(name, source) {
            content.insert((file, function), body);
        }
    }
    for ((file, function), body) in &content {
        let key = (file.clone(), function.clone());
        if let Some(via) = roster.content_readers.get(&key) {
            let needle = format!("self.{via}()");
            if !body.contains(&needle) {
                out.push(format!(
                    "the content reader {function} in {file} never calls {via}: {needle} is not \
                     in its body"
                ));
            }
        } else if !roster.content_exempt.contains_key(&key) {
            out.push(format!(
                "a function that reads a receipt's content has no row: {function} in {file}"
            ));
        }
    }
    for (file, function) in roster
        .content_readers
        .keys()
        .chain(roster.content_exempt.keys())
    {
        if !content.contains_key(&(file.clone(), function.clone())) {
            out.push(format!(
                "a row for a content reader that is not there: {function} in {file}"
            ));
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
        // The look at the write in flight and the mark that a discard is owed are one step under
        // one lock, so that a write either is in flight and marked, or has ended and the caller
        // may discard.
        if let Some((open, close)) = body_of(&text, "defer_discard_if_in_flight", 0, text.len()) {
            let body: String = text[open..=close].iter().collect();
            let locks = body.matches(".lock()").count();
            if locks != 1 || !body.contains(".discard_deferred = true") {
                out.push(format!(
                    "the look and the mark of defer_discard_if_in_flight do not stand under one \
                     lock: it takes {locks} and sets the mark {}",
                    if body.contains(".discard_deferred = true") {
                        "in its body"
                    } else {
                        "nowhere"
                    }
                ));
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
impl OwedWrite {
    fn defer_discard_if_in_flight(&self) -> bool {
        let mut state = self.lock();
        if state.in_flight.is_some() { state.discard_deferred = true; true } else { false }
    }
}
"#;

const CLEAN_ROSTER: &str = "
site crates/kr-worker/src/history.rs append_deferred wait_for_owed_write 1
site crates/kr-worker/src/history.rs wait_for_owed_write wait_idle 1
reader page via standing
reader page_within via page
exempt next_cursor it is the session's own position and a discard leaves it
exempt append_deferred it is the appender
exempt wait_for_owed_write it is a wait
exempt discard_window_and_spool it is the discard itself
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
fn a_reader_with_no_call_of_the_helper_is_found() {
    let bare = HISTORY_TREE.replace("self.standing().oldest", "0");
    let found = violations(&[(HISTORY.to_owned(), bare)], &parse(CLEAN_ROSTER));
    assert!(
        found
            .iter()
            .any(|line| line.contains("reader page never calls")),
        "{found:?}"
    );
}

/// A method that reads the history, written in the forms the scan once passed: a narrower
/// visibility, none, a mutable receiver, a second block of the type, and a block in another file.
fn a_reader_in(form: &str) -> Vec<String> {
    let tree = match form {
        "crate" => HISTORY_TREE.replace(
            "pub fn next_cursor",
            "pub(crate) fn raw(&self) -> u64 { 0 }\n    pub fn next_cursor",
        ),
        "super" => HISTORY_TREE.replace(
            "pub fn next_cursor",
            "pub(super) fn raw(&self) -> u64 { 0 }\n    pub fn next_cursor",
        ),
        "private" => HISTORY_TREE.replace(
            "pub fn next_cursor",
            "fn raw(&self) -> u64 { 0 }\n    pub fn next_cursor",
        ),
        "mutable" => HISTORY_TREE.replace(
            "pub fn next_cursor",
            "pub fn raw(&mut self) -> u64 { 0 }\n    pub fn next_cursor",
        ),
        "second block" => {
            format!("{HISTORY_TREE}\nimpl OutputHistory {{ pub fn raw(&self) -> u64 {{ 0 }} }}\n")
        }
        _ => HISTORY_TREE.to_owned(),
    };
    let elsewhere = (form == "another file").then(|| {
        (
            "crates/kr-worker/src/history/more.rs",
            "impl OutputHistory { pub fn raw(&self) -> u64 { 0 } }",
        )
    });
    let mut files = vec![(HISTORY.to_owned(), tree)];
    files.extend(
        elsewhere
            .into_iter()
            .map(|(name, source)| (name.to_owned(), source.to_owned())),
    );
    violations(&files, &parse(CLEAN_ROSTER))
}

#[test]
fn a_reader_in_a_form_the_scan_once_passed_is_found() {
    for form in [
        "crate",
        "super",
        "private",
        "mutable",
        "second block",
        "another file",
    ] {
        let found = a_reader_in(form);
        assert!(
            found
                .iter()
                .any(|line| line.contains("a method of the history with no row: raw")),
            "{form}: {found:?}"
        );
    }
    assert_eq!(a_reader_in("none"), Vec::<String>::new());
}

#[test]
fn a_deferral_whose_look_and_mark_take_two_locks_is_found() {
    let two = HISTORY_TREE.replace(
        "let mut state = self.lock();\n        if state.in_flight.is_some() { state.discard_deferred = true; true } else { false }",
        "let in_flight = self.lock().in_flight.is_some();\n        if in_flight { self.lock().discard_deferred = true; }\n        in_flight",
    );
    let found = violations(&[(HISTORY.to_owned(), two)], &parse(CLEAN_ROSTER));
    assert!(
        found
            .iter()
            .any(|line| line.contains("do not stand under one lock")),
        "{found:?}"
    );
}

const JOURNAL: &str = "crates/kr-worker/src/journal.rs";

const JOURNAL_TREE: &str = r#"
impl Journal {
    pub fn read_result(&self) -> u8 {
        self.connection.query_row(&format!("SELECT result FROM results WHERE {}", state_list(self.withheld_now())), []);
        0
    }
}
"#;

const CONTENT_ROSTER: &str =
    "content_reader crates/kr-worker/src/journal.rs read_result via withheld_now\n";

#[test]
fn a_content_reader_the_roster_describes_has_no_violation() {
    let roster = format!("{CLEAN_ROSTER}{CONTENT_ROSTER}");
    assert_eq!(
        small(&[(JOURNAL, JOURNAL_TREE)], &roster),
        Vec::<String>::new()
    );
}

#[test]
fn a_content_reader_with_no_row_is_found() {
    let found = small(&[(JOURNAL, JOURNAL_TREE)], CLEAN_ROSTER);
    assert!(
        found
            .iter()
            .any(|line| line.contains("has no row: read_result")),
        "{found:?}"
    );
    // Another form of the same reader: the envelope, in a function of another file, with the
    // statement spread over lines.
    let envelope = "fn peek(c: &C) { c.query(\"SELECT actor_id,\n intent FROM receipts\"); }";
    let found = small(
        &[("crates/kr-worker/src/service.rs", envelope)],
        CLEAN_ROSTER,
    );
    assert!(
        found.iter().any(|line| line.contains("has no row: peek")),
        "{found:?}"
    );
}

#[test]
fn a_content_reader_that_never_asks_the_decision_is_found() {
    let roster = format!("{CLEAN_ROSTER}{CONTENT_ROSTER}");
    let unfenced = JOURNAL_TREE.replace("state_list(self.withheld_now())", "state_list(&[])");
    let found = small(&[(JOURNAL, unfenced.as_str())], &roster);
    assert!(
        found
            .iter()
            .any(|line| line.contains("content reader read_result") && line.contains("never calls")),
        "{found:?}"
    );
}

#[test]
fn a_row_for_a_content_reader_that_is_not_there_is_found() {
    let roster = format!("{CLEAN_ROSTER}{CONTENT_ROSTER}");
    let found = small(&[], &roster);
    assert!(
        found
            .iter()
            .any(|line| line.contains("a row for a content reader that is not there")),
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
