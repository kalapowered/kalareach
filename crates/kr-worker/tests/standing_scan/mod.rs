//! The reader of source text that the two scans of the standing function share.
//!
//! A scan lists, against the source of this crate, the calls of a set of names inside the
//! functions of a scope, by file, function and callee, with how many there are, and holds the list
//! in both directions: a call with no row, a row with no call, a different number of calls, a scope
//! row with no function and a row outside the scope each fail.
//!
//! What it reads. Source text with the comments, the string literals and the test modules taken
//! out. A call is a name that an opening parenthesis follows; a counted call is one that follows a
//! `.` or a `::`.
//!
//! What it does not see. It does not follow a call into another function: a function that a scoped
//! body calls is read only when it is in the scope itself, and a helper that is declared outside
//! the scope or allowed is not read, so what it calls is not seen. It reads names and not types,
//! so a name that two types share is judged for each place it is called, and a row for one of the
//! two covers the other. It does not see a call through a function pointer or a closure that is
//! passed in, a macro's expansion, a call to a name that no function of this crate declares (the
//! standard library and other crates), or what a guard is, beyond the two names it knows (a `let`
//! that calls `session` or locks the service's `dispatch`, and a parameter of the session's type).
//!
//! The roster has these kinds of row, one to a line, with `#` for a comment:
//!
//! * `scope <file> <function>`: a function whose body is read.
//! * `site <file> <function> <callee> <how many calls>`: the counted calls found in it.
//! * `outside <file> <function>`: a function the scoped ones call that is not read, which has to
//!   exist, so that a rename does not leave a stale statement.
//! * `allow <name> ...`: functions of this crate that a scoped body calls and the scan does not
//!   read. A name that no scoped body calls fails, so the list cannot go stale.
//! * `caller <callee> <file> <function> <count>`: a call of `callee` from `function`; in each file
//!   that a row of `callee` names, no other function calls it and the count is exact. A counted
//!   call inside a scoped function is judged by its site row.
//! * `only <callee> <file> <function> <count>`: as `caller`, in every file of the crate.
//! * `held <file> <function> <callee> <guards>`: the guards that `function` holds where it calls
//!   `callee`, as a comma list of `BAR` (the dispatch barrier), `SES` (the session) or `none`.
//!
//! The boundary. A call from a scoped body to a function that this crate declares fails unless the
//! name is one the scan counts, a scoped function, an `outside` function, an `allow` name or the
//! callee of a `caller` or `only` row. A new helper in a listed body therefore has to be declared,
//! with its row, before the case passes.

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
    /// Functions of this crate that a scoped body may call and that the scan does not read.
    pub allowed: BTreeSet<String>,
    /// The functions that call a watched function, by the watched function, the file and the
    /// caller, with how many calls each makes.
    pub callers: BTreeMap<(String, String, String), usize>,
    /// The watched functions whose callers are read in every file of the crate, not only in the
    /// files that their rows name.
    pub everywhere: BTreeSet<String>,
    /// The domains of the guards that a function holds where it makes a call, by file, function
    /// and callee.
    pub held: BTreeMap<(String, String, String), BTreeSet<String>>,
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
            ["allow", names @ ..] if !names.is_empty() => {
                rows.allowed
                    .extend(names.iter().map(|name| (*name).to_owned()));
            }
            ["caller", callee, file, function, count] => {
                rows.callers.insert(
                    (
                        (*callee).to_owned(),
                        (*file).to_owned(),
                        (*function).to_owned(),
                    ),
                    count.parse().expect("a count"),
                );
            }
            ["only", callee, file, function, count] => {
                rows.everywhere.insert((*callee).to_owned());
                rows.callers.insert(
                    (
                        (*callee).to_owned(),
                        (*file).to_owned(),
                        (*function).to_owned(),
                    ),
                    count.parse().expect("a count"),
                );
            }
            ["held", file, function, callee, domains] => {
                let domains = domains
                    .split(',')
                    .filter(|domain| *domain != "none")
                    .map(str::to_owned)
                    .collect();
                rows.held.insert(
                    (
                        (*file).to_owned(),
                        (*function).to_owned(),
                        (*callee).to_owned(),
                    ),
                    domains,
                );
            }
            other => panic!("a roster row that is none of the seven kinds: {other:?}"),
        }
    }
    rows
}

/// Whether `name` is one of the `listed` names: equal to one, or, for a listed name that ends in
/// `*`, beginning with what comes before the star.
pub fn listed(names: &[&str], name: &str) -> bool {
    names.iter().any(|listed| match listed.strip_suffix('*') {
        Some(prefix) => name.starts_with(prefix),
        None => *listed == name,
    })
}

/// Every call of a name in `callees` in `source`, with the function it stands in.
pub fn sites(file: &str, source: &str, callees: &[&str]) -> Vec<Site> {
    let text: Vec<char> = without_test_modules(&blank(source)).chars().collect();
    let inside = function_at(&text);
    let mut found = Vec::new();
    for (at, name) in idents(&text) {
        if !listed(callees, &name) {
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
    if callees.contains(&MUT_PARAMETER) {
        for (file, source) in files {
            let text: Vec<char> = without_test_modules(&blank(source)).chars().collect();
            for span in spans(&text) {
                let count = mut_parameters(&text[span.at..span.open]);
                if count > 0 && roster.scope.contains(&(file.clone(), span.name.clone())) {
                    *found
                        .entry((file.clone(), span.name, MUT_PARAMETER.to_owned()))
                        .or_default() += count;
                }
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
    problems.extend(boundary(files, roster, callees));
    problems.extend(callers(files, roster, callees));
    problems.extend(held(files, roster));
    problems
}

/// The name that stands for a `&mut` parameter in a list of counted names: a function that takes
/// one can write through it.
pub const MUT_PARAMETER: &str = "&mut";

/// How many parameters of a function are a `&mut` (a receiver, a reference or one inside an
/// `Option`), from its signature.
fn mut_parameters(signature: &[char]) -> usize {
    parameters(signature)
        .iter()
        .map(|parameter| {
            let text: Vec<char> = parameter.chars().collect();
            let words = idents(&text);
            words
                .iter()
                .filter(|(at, word)| {
                    word == "mut"
                        && text[..*at]
                            .iter()
                            .rev()
                            .find(|c| !c.is_whitespace() && !is_ident(**c) && **c != '\'')
                            == Some(&'&')
                })
                .count()
        })
        .sum()
}

/// Every call in a text, with its offset: an identifier that an opening parenthesis follows and
/// that is not the name a `fn` declares.
pub fn calls(text: &[char]) -> Vec<(usize, String)> {
    let words = idents(text);
    let mut found = Vec::new();
    for (index, (at, name)) in words.iter().enumerate() {
        let opens = text[at + name.len()..]
            .iter()
            .find(|c| !c.is_whitespace())
            .is_some_and(|c| *c == '(');
        let declared = index > 0 && words[index - 1].1 == "fn";
        if opens && !declared {
            found.push((*at, name.clone()));
        }
    }
    found
}

/// The names that a `fn` declares in `source`, outside its test modules.
pub fn defined_functions(source: &str) -> BTreeSet<String> {
    let text: Vec<char> = without_test_modules(&blank(source)).chars().collect();
    idents(&text)
        .windows(2)
        .filter(|pair| pair[0].1 == "fn")
        .map(|pair| pair[1].1.clone())
        .collect()
}

/// The declared helper boundary. A call from a scoped body to a function of this crate that is
/// none of the names the scan counts, a function in the scope, a function declared outside it and
/// a function allowed, fails: a helper that is not read cannot hide a call that the scan forbids.
/// A call to a name that no function of this crate declares is a call into the standard library
/// or another crate, which this boundary does not judge.
fn boundary(files: &[(String, String)], roster: &Roster, callees: &[&str]) -> Vec<String> {
    let defined: BTreeSet<String> = files
        .iter()
        .flat_map(|(_, source)| defined_functions(source))
        .collect();
    let mut known: BTreeSet<&str> = roster.allowed.iter().map(String::as_str).collect();
    known.extend(roster.scope.iter().map(|(_, function)| function.as_str()));
    known.extend(roster.outside.iter().map(|(_, function)| function.as_str()));
    known.extend(roster.callers.keys().map(|(callee, _, _)| callee.as_str()));
    let mut problems = BTreeSet::new();
    let mut used: BTreeSet<&str> = BTreeSet::new();
    for (file, source) in files {
        let text: Vec<char> = without_test_modules(&blank(source)).chars().collect();
        let inside = function_at(&text);
        for (at, name) in calls(&text) {
            let Some(function) = inside[at].clone() else {
                continue;
            };
            if !roster.scope.contains(&(file.clone(), function.clone())) {
                continue;
            }
            if let Some(allowed) = roster.allowed.get(&name) {
                used.insert(allowed.as_str());
            }
            if defined.contains(&name) && !listed(callees, &name) && !known.contains(name.as_str())
            {
                problems.insert(format!(
                    "{file} {function} calls {name}, which is neither counted, in the scope, \
                     outside it nor allowed: add a scope, outside or allow row for {name}"
                ));
            }
        }
    }
    for name in &roster.allowed {
        if !used.contains(name.as_str()) {
            problems.insert(format!("allow {name}: no scoped function calls it"));
        }
    }
    problems.into_iter().collect()
}

/// The call sites of the watched functions: every function that calls one, with how many calls,
/// and no other.
fn callers(files: &[(String, String)], roster: &Roster, callees: &[&str]) -> Vec<String> {
    let watched: BTreeSet<&str> = roster
        .callers
        .keys()
        .map(|(callee, _, _)| callee.as_str())
        .collect();
    let mut found: BTreeMap<(String, String, String), usize> = BTreeMap::new();
    for (file, source) in files {
        let text: Vec<char> = without_test_modules(&blank(source)).chars().collect();
        let inside = function_at(&text);
        for (at, name) in calls(&text) {
            let read = watched.contains(name.as_str())
                && (roster.everywhere.contains(&name)
                    || roster
                        .callers
                        .keys()
                        .any(|(callee, row_file, _)| *callee == name && row_file == file));
            // A counted call in a scoped function is judged by its site row.
            let counted = listed(callees, &name)
                && inside[at].as_ref().is_some_and(|function| {
                    roster.scope.contains(&(file.clone(), function.clone()))
                });
            if read && !counted {
                let function = inside[at].clone().unwrap_or_else(|| "(top)".to_owned());
                *found.entry((name, file.clone(), function)).or_default() += 1;
            }
        }
    }
    let mut problems = Vec::new();
    for ((callee, file, function), count) in &found {
        match roster
            .callers
            .get(&(callee.clone(), file.clone(), function.clone()))
        {
            None => problems.push(format!(
                "{file} {function} calls {callee} {count} time(s) and no row lists the caller: \
                 caller {callee} {file} {function} {count}"
            )),
            Some(listed) if listed != count => problems.push(format!(
                "{file} {function} calls {callee} {count} time(s) and its caller row says {listed}"
            )),
            Some(_) => {}
        }
    }
    for (callee, file, function) in roster.callers.keys() {
        if !found.contains_key(&(callee.clone(), file.clone(), function.clone())) {
            problems.push(format!(
                "caller {callee} {file} {function}: the call is not there"
            ));
        }
    }
    problems
}

/// A function of a text: its name, where its `fn` stands and where its body opens and closes.
struct Span {
    name: String,
    at: usize,
    open: usize,
    close: usize,
}

/// The functions of a text that have a body.
fn spans(text: &[char]) -> Vec<Span> {
    let mut found = Vec::new();
    for pair in idents(text).windows(2) {
        if pair[0].1 != "fn" {
            continue;
        }
        let mut brackets = 0_i32;
        let mut open = None;
        for (at, &c) in text.iter().enumerate().skip(pair[1].0) {
            match c {
                '(' | '[' => brackets += 1,
                ')' | ']' => brackets -= 1,
                '{' if brackets == 0 => {
                    open = Some(at);
                    break;
                }
                ';' if brackets == 0 => break,
                _ => {}
            }
        }
        let Some(open) = open else { continue };
        let mut depth = 0_i32;
        let mut close = text.len() - 1;
        for (at, &c) in text.iter().enumerate().skip(open) {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        close = at;
                        break;
                    }
                }
                _ => {}
            }
        }
        found.push(Span {
            name: pair[1].1.clone(),
            at: pair[0].0,
            open,
            close,
        });
    }
    found
}

/// The braces open before each character of a text.
fn depths(text: &[char]) -> Vec<i32> {
    let mut open = 0_i32;
    text.iter()
        .map(|&c| {
            let before = open;
            match c {
                '{' => open += 1,
                '}' => open -= 1,
                _ => {}
            }
            before
        })
        .collect()
}

/// The domain a guard belongs to, from the text that makes it: a function's parameter of the
/// session's type, or a `let` whose initialiser calls `session`, holds the session (SES); a `let`
/// whose initialiser locks the service's `dispatch` holds the dispatch barrier (BAR).
fn domain_of(made: &[char], parameter: bool) -> Option<&'static str> {
    let words = idents(made);
    let names: Vec<&str> = words.iter().map(|(_, name)| name.as_str()).collect();
    if parameter {
        return names.contains(&"Session").then_some("SES");
    }
    if calls(made).iter().any(|(_, name)| name == "session") {
        Some("SES")
    } else if names.contains(&"dispatch") && names.contains(&"lock") {
        Some("BAR")
    } else {
        None
    }
}

/// Whether `drop(name)` stands in `text[from..to]`.
fn dropped(text: &[char], from: usize, to: usize, name: &str) -> bool {
    calls(&text[from..to]).iter().any(|(at, called)| {
        called == "drop" && {
            let after = from + at + "drop".len();
            idents(&text[after..to])
                .first()
                .is_some_and(|(next, word)| {
                    word == name && text[after..after + next].contains(&'(')
                })
        }
    })
}

/// The text with everything inside braces blanked, so that what a block does in an arm is not
/// taken for what the statement binds.
fn outside_braces(text: &[char]) -> Vec<char> {
    let mut depth = 0_i32;
    text.iter()
        .map(|&c| match c {
            '{' => {
                depth += 1;
                ' '
            }
            '}' => {
                depth -= 1;
                ' '
            }
            _ if depth > 0 => ' ',
            _ => c,
        })
        .collect()
}

/// The parameters of a function, as the text of each, from its signature.
fn parameters(signature: &[char]) -> Vec<String> {
    let Some(first) = signature.iter().position(|c| *c == '(') else {
        return Vec::new();
    };
    let mut level = 0_i32;
    let mut part = String::new();
    let mut parts = Vec::new();
    for (at, &c) in signature.iter().enumerate().skip(first + 1) {
        match c {
            '(' | '[' | '<' => level += 1,
            ')' if level == 0 => break,
            '>' if signature[at - 1] == '-' => {}
            ')' | ']' | '>' => level -= 1,
            _ => {}
        }
        if c == ',' && level == 0 {
            parts.push(std::mem::take(&mut part));
        } else {
            part.push(c);
        }
    }
    parts.push(part);
    parts
}

/// The domains of the guards that are live where `at` stands in the function `span`: the
/// parameters of the session's type and the `let` bindings before `at` whose block is still open
/// and that no `drop` ended.
fn live_guards(text: &[char], open_braces: &[i32], span: &Span, at: usize) -> BTreeSet<String> {
    let mut live = BTreeSet::new();
    for parameter in parameters(&text[span.at..span.open]) {
        if let Some((name, kind)) = parameter.split_once(':') {
            let kind: Vec<char> = kind.chars().collect();
            let name = name.split_whitespace().last().unwrap_or("");
            if let Some(domain) = domain_of(&kind, true)
                && !dropped(text, span.open, at, name)
            {
                live.insert(domain.to_owned());
            }
        }
    }
    let words = idents(&text[span.open..at]);
    for (index, (word_at, word)) in words.iter().enumerate() {
        if word != "let" {
            continue;
        }
        let start = span.open + word_at;
        let named = match words.get(index + 1) {
            Some((_, name)) if name == "mut" => words.get(index + 2),
            other => other,
        };
        let Some((name_at, name)) = named else {
            continue;
        };
        let name_end = span.open + name_at + name.len();
        let mut nesting = 0_i32;
        let mut end = None;
        for (offset, &c) in text.iter().enumerate().take(at).skip(name_end) {
            match c {
                '(' | '[' | '{' => nesting += 1,
                ')' | ']' | '}' => nesting -= 1,
                ';' if nesting == 0 => {
                    end = Some(offset);
                    break;
                }
                _ => {}
            }
        }
        let Some(end) = end else { continue };
        let still_open = open_braces[start + 1..=at]
            .iter()
            .all(|depth| *depth >= open_braces[start]);
        if still_open
            && let Some(domain) = domain_of(&outside_braces(&text[name_end..end]), false)
            && !dropped(text, end, at, name)
        {
            live.insert(domain.to_owned());
        }
    }
    live
}

/// The guards held at a call: for each held row, the domains of the guards that the function holds
/// where it calls the callee are exactly the row's.
fn held(files: &[(String, String)], roster: &Roster) -> Vec<String> {
    let mut problems = Vec::new();
    let mut seen: BTreeSet<(String, String, String)> = BTreeSet::new();
    for (file, source) in files {
        if !roster.held.keys().any(|(row_file, _, _)| row_file == file) {
            continue;
        }
        let text: Vec<char> = without_test_modules(&blank(source)).chars().collect();
        let inside = function_at(&text);
        let open_braces = depths(&text);
        let functions = spans(&text);
        for (at, callee) in calls(&text) {
            let Some(function) = inside[at].clone() else {
                continue;
            };
            let key = (file.clone(), function.clone(), callee.clone());
            let Some(row) = roster.held.get(&key) else {
                continue;
            };
            seen.insert(key);
            let span = functions
                .iter()
                .filter(|span| span.name == function && span.open < at && at < span.close)
                .max_by_key(|span| span.open)
                .expect("the function that the call stands in");
            let live = live_guards(&text, &open_braces, span, at);
            if live != *row {
                problems.push(format!(
                    "{file} {function} calls {callee} holding {live:?} and its held row says {row:?}"
                ));
            }
        }
    }
    for (file, function, callee) in roster.held.keys() {
        if !seen.contains(&(file.clone(), function.clone(), callee.clone())) {
            problems.push(format!(
                "held {file} {function} {callee}: the call is not there"
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
