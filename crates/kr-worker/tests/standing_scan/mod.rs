//! The reader of source text that the two scans of the standing function share.
//!
//! A scan lists, against the source of this crate, the calls of a set of names inside the
//! functions of a scope, by file, function and callee, with how many there are, and holds the list
//! in both directions: a call with no row, a row with no call, a different number of calls, a scope
//! row with no function and a row outside the scope each fail.
//!
//! What it reads and what it does not. It reads source text with the comments, the string literals
//! and the test modules taken out, and finds a call by the name that follows a `.` or a `::` and is
//! followed by an opening parenthesis. It does not follow a call into another function, so a
//! function that a scoped function calls is read only when it is in the scope itself, and it does
//! not tell the receiver's type: a name that two types share is listed for each place it is called.
//! A call through a function pointer or a closure that is passed in is not found.
//!
//! The roster has three kinds of row, one to a line, with `#` for a comment:
//!
//! * `scope <file> <function>`: a function whose body is read.
//! * `site <file> <function> <callee> <how many calls>`: the calls found in it.
//! * `outside <file> <function>`: a function the scoped ones call that is not read, which has to
//!   exist, so that a rename does not leave a stale statement.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// Source text with its comments, string and character literals blanked, newlines kept.
pub fn blank(source: &str) -> String {
    blank_with(source, false)
}

/// Source text with its comments and character literals blanked and, unless `strings` says to keep
/// them, its string literals too. The text is as long as the source, character for character, so
/// an offset in one is the same place in the other.
pub fn blank_with(source: &str, strings: bool) -> String {
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
pub fn is_raw_string(bytes: &[char], at: usize) -> bool {
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
pub fn is_char_literal(bytes: &[char], at: usize) -> bool {
    matches!(
        (bytes.get(at + 1), bytes.get(at + 2)),
        (Some('\\'), _) | (Some(_), Some('\''))
    )
}

/// Blanks every `#[cfg(test)]` module, so that a call a test makes is not a shipped one.
pub fn without_test_modules(blanked: &str) -> String {
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

pub fn find(text: &[char], needle: &[char], from: usize) -> Option<usize> {
    (from..text.len().saturating_sub(needle.len()) + 1).find(|&at| text[at..].starts_with(needle))
}

pub fn is_ident(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// The identifiers of a text with their offsets.
pub fn idents(text: &[char]) -> Vec<(usize, String)> {
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
pub fn function_at(text: &[char]) -> Vec<Option<String>> {
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

pub fn source_files(root: &Path, directory: &Path, found: &mut Vec<(String, String)>) {
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

/// One call of a listed name: where it stands and what it calls.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Site {
    pub file: String,
    pub function: String,
    pub callee: String,
}

/// The rows of a roster.
#[derive(Default)]
pub struct Roster {
    pub scope: BTreeSet<(String, String)>,
    pub sites: BTreeMap<(String, String, String), usize>,
    pub outside: BTreeSet<(String, String)>,
}

/// Reads a roster.
///
/// # Panics
///
/// Panics on a row that is not one of the three kinds, which is a fault of the roster.
pub fn parse(roster: &str) -> Roster {
    let mut rows = Roster::default();
    for line in roster.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let words: Vec<&str> = line.split_whitespace().collect();
        match words.as_slice() {
            ["scope", file, function] => {
                rows.scope
                    .insert(((*file).to_owned(), (*function).to_owned()));
            }
            ["site", file, function, callee, count] => {
                rows.sites.insert(
                    (
                        (*file).to_owned(),
                        (*function).to_owned(),
                        (*callee).to_owned(),
                    ),
                    count.parse().expect("a count"),
                );
            }
            ["outside", file, function] => {
                rows.outside
                    .insert(((*file).to_owned(), (*function).to_owned()));
            }
            other => panic!("a roster row that is none of the three kinds: {other:?}"),
        }
    }
    rows
}

/// Every call of a name in `callees` in `source`, with the function it stands in.
pub fn sites(file: &str, source: &str, callees: &[&str]) -> Vec<Site> {
    let text: Vec<char> = without_test_modules(&blank(source)).chars().collect();
    let inside = function_at(&text);
    let mut found = Vec::new();
    for (at, name) in idents(&text) {
        if !callees.contains(&name.as_str()) {
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

/// What is wrong between the roster and the source files, one line each.
pub fn violations(files: &[(String, String)], roster: &Roster, callees: &[&str]) -> Vec<String> {
    let mut problems = Vec::new();
    // The functions each file defines, read once: a name that follows `fn`.
    let defined: BTreeMap<&str, BTreeSet<String>> = files
        .iter()
        .map(|(name, source)| {
            let text: Vec<char> = without_test_modules(&blank(source)).chars().collect();
            let words = idents(&text);
            let names = words
                .windows(2)
                .filter(|pair| pair[0].1 == "fn")
                .map(|pair| pair[1].1.clone())
                .collect();
            (name.as_str(), names)
        })
        .collect();
    let exists = |file: &str, function: &str| {
        defined
            .get(file)
            .is_some_and(|names| names.contains(function))
    };
    for (file, function) in &roster.scope {
        if !exists(file, function) {
            problems.push(format!(
                "scope {file} {function}: there is no such function"
            ));
        }
    }
    for (file, function) in &roster.outside {
        if !exists(file, function) {
            problems.push(format!(
                "outside {file} {function}: there is no such function"
            ));
        }
    }
    let mut found: BTreeMap<(String, String, String), usize> = BTreeMap::new();
    for (file, source) in files {
        for site in sites(file, source, callees) {
            if roster
                .scope
                .contains(&(site.file.clone(), site.function.clone()))
            {
                *found
                    .entry((site.file, site.function, site.callee))
                    .or_default() += 1;
            }
        }
    }
    for ((file, function, callee), count) in &found {
        match roster
            .sites
            .get(&(file.clone(), function.clone(), callee.clone()))
        {
            None => problems.push(format!(
                "{file} {function} calls {callee} {count} time(s) and no row lists it: \
                 site {file} {function} {callee} {count}"
            )),
            Some(listed) if listed != count => problems.push(format!(
                "{file} {function} calls {callee} {count} time(s) and its row says {listed}"
            )),
            Some(_) => {}
        }
    }
    for (file, function, callee) in roster.sites.keys() {
        if !roster.scope.contains(&(file.clone(), function.clone())) {
            problems.push(format!(
                "site {file} {function} {callee}: the function is not in the scope"
            ));
        } else if !found.contains_key(&(file.clone(), function.clone(), callee.clone())) {
            problems.push(format!(
                "site {file} {function} {callee}: the call is not there"
            ));
        }
    }
    problems
}

/// The source files of this crate, as the roster names them.
pub fn tree() -> Vec<(String, String)> {
    let crate_root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut found = Vec::new();
    source_files(crate_root, &crate_root.join("src"), &mut found);
    for (name, _) in &mut found {
        *name = format!("crates/kr-worker/{name}");
    }
    found
}
