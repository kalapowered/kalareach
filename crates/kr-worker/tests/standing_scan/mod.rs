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
//! What it does not see. It reads names and not types: where a name is declared by several
//! functions, a `calls` row or an `allow` row says which definition a body calls, and the row is
//! the author's reading of the receiver's type, not a proof. It does not see:
//!
//! * a call through a function pointer or a closure that is passed in, a macro's expansion, or a
//!   call to a name that no function of this crate declares (the standard library and other
//!   crates);
//! * the dispatch barrier's guard, which this reader does not read: the compiler holds that nine
//!   functions (`receipted`, `continue_prepared`, `admit_and_dispatch`, `dispatch_accepted`,
//!   `standing_pass`, and four of the bodies that the other takers of the barrier run:
//!   `revalidate_time`, `accept_generation`, `fence` and `fence_what_is_owed`) are called with a
//!   borrow of a guard, that the pass keeps its borrow, and that a boundary can be taken only in
//!   its own module (a service takes its one boundary through two methods written there). Scope
//!   alone holds the rest of the work that runs under the boundary (the expiry task's release, the
//!   maintenance pass's session work, the storage recovery, the answers). The compiler does not
//!   hold that the guard is the service's own: the two entries `receipted` and `continue_prepared`
//!   check that before any work, and a test shows the check. A second take under the held barrier
//!   is held by the `taker` and `mention` rows below, which count names and read no guard;
//! * what a guard is, beyond the names it knows: a `let` that calls `session` (SES) and a
//!   parameter whose type names `Session` (SES, held or not: a `supplies` row tells two calls
//!   apart). `let Some(x) =` and `let Ok(x) =` bind `x`, with the initialiser after the pattern,
//!   and a binding `_` holds nothing. A `let` that `if`, `while` or `&&` precedes binds for its
//!   condition's block and is not read. A row that says `none` or `SES` holds only against the
//!   guards that are known: a guard that any other function returns, a pattern of another shape
//!   (`Some((x, y))`, a struct) and a `match` arm's binding are not known;
//! * where a call runs: a call is read where it is written, so a body written as a closure under
//!   a guard and run after the guard's drop (`let body = || { .. call .. }; drop(guard);
//!   run(body)`) reads as held; a call through a function value (`let f = Self::callee;
//!   f(self)`) is not a call of the name. A `caller` row reads only the file that it names and an
//!   `only` row every file of the crate; `session` is known by name and its body is not read;
//! * the body of an `allow`ed name;
//! * the body of a callee that a counted name reaches. A counted call is counted and not followed,
//!   so a second take or write inside `Broker::state`, `Questions::locked`, `lock_session` or
//!   `Session::state` is not seen by the roster that counts that name; the `site` row of the
//!   counted call is the only record of what the callee does;
//! * a `Drop` impl, which no call names: a take or a write in `InputGuard::drop` passes;
//! * a write that is not a call of a listed name: an assignment, a compound assignment, or a store
//!   through `borrow_mut`;
//! * the body that follows a `fn(` type, which is taken for a function (see "What it can merge").
//!
//! A `calls` row reads every function of that name in the file it names, so a type that shares a
//! name with another in that file is read together with it.
//!
//! What it can merge. Four steps of the reader take two things for one, with no failure:
//!
//! * a function is known by its file and name, so two functions of one name in one file are one
//!   body: the read set, the `site` counts and a `calls` row cover both (`attested_thread` is
//!   declared on `BridgeThreads` and on `Broker` in `broker/bridge.rs`, and the takes roster has
//!   one `site ... attested_thread state 1` row for the two);
//! * a `calls` key holds a set of files, so a wrong file beside the right one is never reported as
//!   stale: it only adds that file's functions of the name to the read set;
//! * an `outside` row matches its name in every file, so a second function of that name in another
//!   file would be left unread as well (today `decidable` has one definition);
//! * the word after any `fn` token is taken as a function's name, so a `fn(` type in a signature
//!   (`f: fn(u8) -> u8`) renames the body that follows to `u8`, and a take in that body is
//!   attributed to no function that is read.
//!
//! What it follows. A call from a function that the scan reads to a name that this crate declares
//! once is followed: the callee's body is read, and so are the bodies that it calls in turn, and a
//! counted call found in any of them needs its own `site` row. A call to a name that several
//! functions declare is followed into the file that a `calls` row names. The scan therefore reads
//! every helper that a listed body reaches by such a name, whether a row declares it or not; a
//! callee that a counted name reaches is not followed (see "What it does not see"). A name that
//! this crate declares once and that is really a method of the standard library or of another
//! crate needs an `allow` row, or the scan reads the crate's function of that name.
//!
//! The roster has these kinds of row, one to a line, with `#` for a comment. A kind that holds one
//! value for a key (`site`, `caller` and `only`, `held`, `supplies`, `mention`) refuses a second row for the
//! same key, so that a later row never replaces an earlier one:
//!
//! * `scope <file> <function>`: a function that has to exist and whose body is read. The row seeds
//!   the read set and judges no call: a call is judged by the boundary and the `site` rows in
//!   every body that is read, scoped or followed, and a scoped body has no exemption.
//! * `site <file> <function> <callee> <how many calls>`: the counted calls found in a function
//!   that the scan reads, scoped or followed.
//! * `outside <file> <function>`: a function that is declared and not read, and not followed,
//!   which has to exist, so that a rename does not leave a stale statement.
//! * `allow <file> <function> <name> ...`: names that this function calls where the receiver is a
//!   type of the standard library or of another crate, and the scan does not follow. The row
//!   counts for that function alone. A name that the function does not call fails, so the list
//!   cannot go stale, and a name that the function also has a `calls` row for fails too.
//! * `calls <file> <function> <name> <file of the definition>`: the definition that this function
//!   calls where several functions of the crate declare `name` and the receiver is a type of this
//!   crate. The scan reads it. A body that calls two definitions has one row for each file.
//! * `caller <callee> <file> <function> <count>`: a call of `callee` from `function`; in each file
//!   that a row of `callee` names, no other function calls it and the count is exact. A counted
//!   call inside a function that the scan reads is judged by its site row.
//! * `only <callee> <file> <function> <count>`: as `caller`, in every file of the crate.
//! * `held <file> <function> <callee> <guards>`: the guards that `function` holds where it calls
//!   `callee`, as a comma list of `SES` (the session) or `none`.
//! * `taker <name>`: a function that takes the dispatch boundary, or one of the two methods that
//!   take it, in a list that a person keeps (the functions of the nine take sites and the two
//!   methods). For each `taker` the reader counts, in every file of the crate, the times that the
//!   name stands in code: a declaration, a call, an argument, a function value. Comments, string
//!   literals and test modules are taken out.
//! * `mention <name> <file> <count>`: how many times the `taker` `name` stands in the code of
//!   `file`; a file with no row has none. A different number in any file fails the main case,
//!   wherever the new mention stands (an argument, a helper, a statement after a call): a take
//!   under the held barrier waits on itself, so a person reads the new text and then sets the
//!   number, adding a `taker` row first for a new function that takes the boundary. One limit,
//!   which the crate does not hold: a take that is reached with none of these names in the text
//!   (a name that a macro makes, or a function that a macro writes).
//! * `supplies <file> <function> <callee> <position> <text>`: the argument at `position` (from
//!   zero) of every call of `callee` from `function`, with its white space taken out, is `text`. A
//!   row for each argument of one call stands beside the others. It reads what a call hands on
//!   where `held` reads what is live there.
//!
//! The boundary. A call from any body that the scan reads, scoped or followed, to a name that
//! several functions of this crate declare fails unless the name is one the scan counts, an
//! `outside` function, a name allowed for that body or one that a `calls` row for that body
//! declares. A counted name called without a path is a free function: it is followed like any
//! helper when it is declared once. A stale `allow` row or `calls` row fails, and so does a `calls`
//! row whose file declares no function of that name.

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

/// Whether the `r` at `at` opens a raw string: `r"` or `r#..#"`, with a `b` or `c` before the `r`
/// for a raw byte or C string, and not the end of a word.
pub fn is_raw_string(bytes: &[char], at: usize) -> bool {
    let start = if at > 0 && matches!(bytes[at - 1], 'b' | 'c') {
        at - 1
    } else {
        at
    };
    if start > 0 && (bytes[start - 1].is_alphanumeric() || bytes[start - 1] == '_') {
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
    /// The names a function that the scan reads may call without the scan following them, by file
    /// and function: an allowed name counts for the body that lists it and for no other.
    pub allowed: BTreeSet<(String, String, String)>,
    /// The files whose definition of a shared name a function calls, by file, function and name:
    /// the declared target of a call to a name that several functions of the crate declare.
    pub calls: BTreeMap<(String, String, String), BTreeSet<String>>,
    /// The argument that a call hands on, by file, function, callee and the argument's position:
    /// its text with the white space taken out. The position is part of the key, so a row for one
    /// argument of a call never replaces the row for another.
    pub supplies: BTreeMap<(String, String, String, usize), String>,
    /// The functions that call a watched function, by the watched function, the file and the
    /// caller, with how many calls each makes.
    pub callers: BTreeMap<(String, String, String), usize>,
    /// The watched functions whose callers are read in every file of the crate, not only in the
    /// files that their rows name.
    pub everywhere: BTreeSet<String>,
    /// The domains of the guards that a function holds where it makes a call, by file, function
    /// and callee.
    pub held: BTreeMap<(String, String, String), BTreeSet<String>>,
    /// The functions that take the dispatch boundary and the two methods that take it, by name: a
    /// list that a person keeps.
    pub takers: BTreeSet<String>,
    /// How many times each such name stands in the code of a file, by name and file.
    pub mentions: BTreeMap<(String, String), usize>,
}

/// Reads a roster.
///
/// # Panics
///
/// Panics on a row that is not one of the eleven kinds, and on a row of a kind that holds one value
/// per key (`site`, `supplies`, `caller` and `only`, `held`, `mention`) whose key an earlier row already
/// holds: a later row never replaces an earlier one unseen. A `scope`, `outside` or `allow` row
/// that repeats is a set's member again, and a `calls` row adds a file to the body's set of
/// targets, so neither can replace anything.
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
                insert_once(
                    &mut rows.sites,
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
            ["allow", file, function, names @ ..] if !names.is_empty() => {
                rows.allowed.extend(names.iter().map(|name| {
                    (
                        (*file).to_owned(),
                        (*function).to_owned(),
                        (*name).to_owned(),
                    )
                }));
            }
            ["calls", file, function, name, definition] => {
                rows.calls
                    .entry((
                        (*file).to_owned(),
                        (*function).to_owned(),
                        (*name).to_owned(),
                    ))
                    .or_default()
                    .insert((*definition).to_owned());
            }
            ["supplies", file, function, callee, position, text @ ..] if !text.is_empty() => {
                insert_once(
                    &mut rows.supplies,
                    (
                        (*file).to_owned(),
                        (*function).to_owned(),
                        (*callee).to_owned(),
                        position.parse().expect("a position"),
                    ),
                    text.concat(),
                );
            }
            ["caller", callee, file, function, count] => {
                insert_once(
                    &mut rows.callers,
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
                insert_once(
                    &mut rows.callers,
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
                insert_once(
                    &mut rows.held,
                    (
                        (*file).to_owned(),
                        (*function).to_owned(),
                        (*callee).to_owned(),
                    ),
                    domains,
                );
            }
            ["taker", name] => {
                rows.takers.insert((*name).to_owned());
            }
            ["mention", name, file, count] => {
                insert_once(
                    &mut rows.mentions,
                    ((*name).to_owned(), (*file).to_owned()),
                    count.parse().expect("a count"),
                );
            }
            other => panic!("a roster row that is none of the eleven kinds: {other:?}"),
        }
    }
    rows
}

/// Puts a row's value in `rows` under its key and refuses a key that an earlier row holds.
fn insert_once<K: Ord + std::fmt::Debug, V>(rows: &mut BTreeMap<K, V>, key: K, value: V) {
    let shown = format!("{key:?}");
    assert!(
        rows.insert(key, value).is_none(),
        "a roster row repeats the key {shown} of an earlier row"
    );
}

/// Whether `name` is one of the `listed` names: equal to one, or, for a listed name that ends in
/// `*`, beginning with what comes before the star.
pub fn listed(names: &[&str], name: &str) -> bool {
    names.iter().any(|listed| match listed.strip_suffix('*') {
        Some(prefix) => name.starts_with(prefix),
        None => *listed == name,
    })
}

/// Whether the call that stands at `at` follows a `.` or a `::`.
fn reached(text: &[char], at: usize) -> bool {
    let before: Vec<&char> = text[..at]
        .iter()
        .rev()
        .filter(|c| !c.is_whitespace())
        .take(2)
        .collect();
    matches!(before.as_slice(), ['.', ..] | [':', ':'])
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
        let reached = reached(&text, at);
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
    let read = reads(files, roster, callees);
    let mut found: BTreeMap<(String, String, String), usize> = BTreeMap::new();
    for (file, source) in files {
        for site in sites(file, source, callees) {
            if read.contains(&(site.file.clone(), site.function.clone())) {
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
                if count > 0 && read.contains(&(file.clone(), span.name.clone())) {
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
        if !read.contains(&(file.clone(), function.clone())) {
            problems.push(format!(
                "site {file} {function} {callee}: the function is not read"
            ));
        } else if !found.contains_key(&(file.clone(), function.clone(), callee.clone())) {
            problems.push(format!(
                "site {file} {function} {callee}: the call is not there"
            ));
        }
    }
    problems.extend(boundary(files, roster, callees, &read));
    problems.extend(callers(files, roster, callees, &read));
    problems.extend(held(files, roster));
    problems.extend(supplied(files, roster));
    problems.extend(mentioned(files, roster));
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

/// Where each function of this crate is declared: its name, with the file of each declaration.
fn definitions(files: &[(String, String)]) -> BTreeMap<String, Vec<String>> {
    let mut found: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (file, source) in files {
        for name in defined_functions(source) {
            found.entry(name).or_default().push(file.clone());
        }
    }
    found
}

/// The names that a `fn` declares in `source`, outside its test modules, once for each `fn`.
fn defined_functions(source: &str) -> Vec<String> {
    let text: Vec<char> = without_test_modules(&blank(source)).chars().collect();
    idents(&text)
        .windows(2)
        .filter(|pair| pair[0].1 == "fn")
        .map(|pair| pair[1].1.clone())
        .collect()
}

/// What a read body calls that the scan follows into: the crate functions that are declared once,
/// by name, in the whole crate, and the definitions that a `calls` row names for a name that
/// several functions declare. A call to a counted name (reached by a `.` or a `::`), to a name
/// allowed for this body, to a name declared outside, or to a name that no function of the crate
/// declares is not followed. A counted name called without a path is followed like any other.
fn followed_from(
    file: &str,
    function: &str,
    text: &[char],
    inside: &[Option<String>],
    roster: &Roster,
    callees: &[&str],
    declared: &BTreeMap<String, Vec<String>>,
) -> Vec<(String, String)> {
    let mut found = Vec::new();
    for (at, name) in calls(text) {
        let row = (file.to_owned(), function.to_owned(), name.clone());
        if inside[at].as_deref() != Some(function)
            || (listed(callees, &name) && reached(text, at))
            || roster.allowed.contains(&row)
            || roster.outside.iter().any(|(_, outside)| *outside == name)
        {
            continue;
        }
        let Some(files) = declared.get(&name) else {
            continue;
        };
        if let [only] = files.as_slice() {
            found.push((only.clone(), name));
        } else if let Some(targets) = roster.calls.get(&row) {
            for target in targets.iter().filter(|target| files.contains(*target)) {
                found.push((target.clone(), name.clone()));
            }
        }
    }
    found
}

/// The functions whose bodies a scan reads: the scoped ones, and every function that a read body
/// calls by a name that this crate declares once, and the ones those call in turn. A helper that
/// nothing declares is read all the same, so a new helper cannot hide a call that the scan counts.
fn reads(
    files: &[(String, String)],
    roster: &Roster,
    callees: &[&str],
) -> BTreeSet<(String, String)> {
    let declared = definitions(files);
    let texts: BTreeMap<&str, (Vec<char>, Vec<Option<String>>)> = files
        .iter()
        .map(|(file, source)| {
            let text: Vec<char> = without_test_modules(&blank(source)).chars().collect();
            let inside = function_at(&text);
            (file.as_str(), (text, inside))
        })
        .collect();
    let mut read: BTreeSet<(String, String)> = roster.scope.clone();
    let mut queue: Vec<(String, String)> = read.iter().cloned().collect();
    while let Some((file, function)) = queue.pop() {
        let Some((text, inside)) = texts.get(file.as_str()) else {
            continue;
        };
        for next in followed_from(&file, &function, text, inside, roster, callees, &declared) {
            if read.insert(next.clone()) {
                queue.push(next);
            }
        }
    }
    read
}

/// The declared helper boundary, held in every function that the scan reads. A call to a name
/// that several functions of this crate declare fails unless the name is counted, declared
/// outside, allowed for that function (the standard library's method, or another crate's) or
/// declared by a `calls` row for that function, which names the file of the definition that is
/// called and which the scan reads. A name that this crate declares once is read instead, as above.
/// A call to a name that no function of this crate declares is a call into the standard library or
/// another crate, which this boundary does not judge. An `allow` or `calls` row that its function
/// does not use, and a `calls` row whose file declares no such function, fail, so the lists cannot
/// go stale. A name that a body has both an `allow` row and a `calls` row for fails too: the follow
/// skips an allowed name, so the `calls` row would read nothing.
fn boundary(
    files: &[(String, String)],
    roster: &Roster,
    callees: &[&str],
    read: &BTreeSet<(String, String)>,
) -> Vec<String> {
    let declared = definitions(files);
    let mut problems = BTreeSet::new();
    let mut allowed_used: BTreeSet<(String, String, String)> = BTreeSet::new();
    let mut calls_used: BTreeSet<(String, String, String)> = BTreeSet::new();
    for (file, source) in files {
        let text: Vec<char> = without_test_modules(&blank(source)).chars().collect();
        let inside = function_at(&text);
        for (at, name) in calls(&text) {
            let Some(function) = inside[at].clone() else {
                continue;
            };
            if !read.contains(&(file.clone(), function.clone())) {
                continue;
            }
            let row = (file.clone(), function.clone(), name.clone());
            let allowed = roster.allowed.contains(&row);
            if allowed {
                allowed_used.insert(row.clone());
            }
            let declared_target = roster.calls.contains_key(&row);
            if declared_target {
                calls_used.insert(row.clone());
            }
            let several = declared.get(&name).is_some_and(|files| files.len() > 1);
            let counted = listed(callees, &name) && reached(&text, at);
            let outside = roster.outside.iter().any(|(_, outside)| *outside == name);
            if several && !counted && !outside && !allowed && !declared_target {
                problems.insert(format!(
                    "{file} {function} calls {name}, which several functions of the crate declare \
                     and which is neither counted, outside, allowed nor declared for this \
                     function: add `allow {file} {function} {name}` for the standard library's \
                     or `calls {file} {function} {name} <the file of the definition>` (declared \
                     in {:?})",
                    declared.get(&name).cloned().unwrap_or_default()
                ));
            }
        }
    }
    for row in &roster.allowed {
        if roster.calls.contains_key(row) {
            let (file, function, name) = row;
            problems.insert(format!(
                "allow {file} {function} {name} and calls {file} {function} {name}: a name that \
                 the body allows is not followed, so its `calls` row reads nothing"
            ));
        }
    }
    for (file, function, name) in &roster.allowed {
        if !allowed_used.contains(&(file.clone(), function.clone(), name.clone())) {
            problems.insert(format!(
                "allow {file} {function} {name}: no function that the scan reads makes the call"
            ));
        }
    }
    for ((file, function, name), targets) in &roster.calls {
        if !calls_used.contains(&(file.clone(), function.clone(), name.clone())) {
            problems.insert(format!(
                "calls {file} {function} {name}: no function that the scan reads makes the call"
            ));
        }
        for target in targets {
            if !declared
                .get(name)
                .is_some_and(|files| files.contains(target))
            {
                problems.insert(format!(
                    "calls {file} {function} {name} {target}: that file declares no such function"
                ));
            }
        }
    }
    problems.into_iter().collect()
}

/// The arguments of the calls of `callee` that stand in `function`, each with its white space taken
/// out, one list for each call. An argument ends at a comma outside every bracket.
fn arguments_of(
    text: &[char],
    inside: &[Option<String>],
    function: &str,
    callee: &str,
) -> Vec<Vec<String>> {
    let mut found = Vec::new();
    for (at, name) in calls(text) {
        if name != callee || inside[at].as_deref() != Some(function) {
            continue;
        }
        let open = text[at + name.len()..]
            .iter()
            .position(|c| *c == '(')
            .map(|offset| at + name.len() + offset)
            .expect("a call has an opening parenthesis");
        let mut depth = 0_i32;
        let mut argument = String::new();
        let mut list = Vec::new();
        for &c in &text[open..] {
            match c {
                '(' | '[' | '{' => {
                    depth += 1;
                    if depth == 1 {
                        continue;
                    }
                }
                ')' | ']' | '}' => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                _ => {}
            }
            if c == ',' && depth == 1 {
                list.push(std::mem::take(&mut argument));
            } else if !c.is_whitespace() {
                argument.push(c);
            }
        }
        if !argument.is_empty() {
            list.push(argument);
        }
        found.push(list);
    }
    found
}

/// What a call hands on: for each `supplies` row, every call of the callee from the function hands
/// the row's text as the argument at the row's position, so that a piece which is given the
/// session, or none, is handed what the row says and not what the guard that is live there would
/// have the caller believe.
fn supplied(files: &[(String, String)], roster: &Roster) -> Vec<String> {
    let mut problems = Vec::new();
    for ((file, function, callee, position), expected) in &roster.supplies {
        let Some((_, source)) = files.iter().find(|(name, _)| name == file) else {
            problems.push(format!(
                "supplies {file} {function} {callee}: there is no such file"
            ));
            continue;
        };
        let text: Vec<char> = without_test_modules(&blank(source)).chars().collect();
        let inside = function_at(&text);
        let calls = arguments_of(&text, &inside, function, callee);
        if calls.is_empty() {
            problems.push(format!(
                "supplies {file} {function} {callee}: the call is not there"
            ));
        }
        for arguments in calls {
            match arguments.get(*position) {
                Some(actual) if actual == expected => {}
                Some(actual) => problems.push(format!(
                    "{file} {function} calls {callee} handing {actual} as argument {position} \
                     and its supplies row says {expected}"
                )),
                None => problems.push(format!(
                    "{file} {function} calls {callee} with no argument {position}"
                )),
            }
        }
    }
    problems
}

/// The call sites of the watched functions: every function that calls one, with how many calls,
/// and no other.
fn callers(
    files: &[(String, String)],
    roster: &Roster,
    callees: &[&str],
    scanned: &BTreeSet<(String, String)>,
) -> Vec<String> {
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
                && reached(&text, at)
                && inside[at]
                    .as_ref()
                    .is_some_and(|function| scanned.contains(&(file.clone(), function.clone())));
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
/// session's type, or a `let` whose initialiser calls `session`, holds the session (SES). The
/// dispatch barrier's guard is not read here.
fn domain_of(made: &[char], parameter: bool) -> Option<&'static str> {
    if parameter {
        return idents(made)
            .iter()
            .any(|(_, name)| name == "Session")
            .then_some("SES");
    }
    calls(made)
        .iter()
        .any(|(_, name)| name == "session")
        .then_some("SES")
}

/// Whether the `let` at `start` follows `if`, `while` or `&&`: it binds for the block of its
/// condition, and the reader does not follow that block, so the `let` is not read.
fn in_a_condition(
    text: &[char],
    words: &[(usize, String)],
    index: usize,
    start: usize,
    base: usize,
) -> bool {
    let mut before = start;
    while before > 0 && text[before - 1].is_whitespace() {
        before -= 1;
    }
    if before >= 2 && text[before - 1] == '&' && text[before - 2] == '&' {
        return true;
    }
    index > 0 && {
        let (word_at, word) = &words[index - 1];
        matches!(word.as_str(), "if" | "while") && base + word_at + word.len() == before
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

/// The offset of the parenthesis that closes the one at `open`, before `limit`.
fn closing(text: &[char], open: usize, limit: usize) -> Option<usize> {
    let mut level = 0_i32;
    for (offset, &c) in text.iter().enumerate().take(limit).skip(open) {
        match c {
            '(' => level += 1,
            ')' => {
                level -= 1;
                if level == 0 {
                    return Some(offset);
                }
            }
            _ => {}
        }
    }
    None
}

/// The domains of the guards that are live where `at` stands in the function `span`: the
/// parameters of the session's type and the `let` bindings before `at` whose block is still open
/// and that no `drop` ended. `let Some(x) =` and `let Ok(x) =` bind `x`, and the initialiser is
/// the text after the pattern; a binding `_` holds nothing. A `let` that `if`, `while` or `&&`
/// precedes is not read.
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
        if in_a_condition(text, &words, index, start, span.open) {
            continue;
        }
        let mut next = index + 1;
        if words.get(next).is_some_and(|(_, word)| word == "mut") {
            next += 1;
        }
        let Some((name_at, name)) = words.get(next) else {
            continue;
        };
        let mut name = name.as_str();
        // Where the initialiser starts: after the name, or after the pattern of `Some(name)` and
        // `Ok(name)`, which bind the name inside the parentheses.
        let mut initialiser = span.open + name_at + name.len();
        if matches!(name, "Some" | "Ok")
            && let Some(open) = text[initialiser..at]
                .iter()
                .position(|c| !c.is_whitespace())
            && text[initialiser + open] == '('
        {
            let open = initialiser + open;
            let Some(close) = closing(text, open, at) else {
                continue;
            };
            let mut inner = next + 1;
            while words
                .get(inner)
                .is_some_and(|(_, word)| word == "mut" || word == "ref")
            {
                inner += 1;
            }
            let Some((inner_at, inner_name)) = words.get(inner) else {
                continue;
            };
            if span.open + inner_at > close {
                continue;
            }
            name = inner_name.as_str();
            initialiser = close + 1;
        }
        // A binding `_` drops its value at once.
        if name == "_" {
            continue;
        }
        let mut nesting = 0_i32;
        let mut end = None;
        for (offset, &c) in text.iter().enumerate().take(at).skip(initialiser) {
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
        if !still_open {
            continue;
        }
        if let Some(domain) = domain_of(&outside_braces(&text[initialiser..end]), false)
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

/// The mentions of the names that take the dispatch boundary: for every `taker` name and every file
/// of the crate, the times that the name stands in the file's code are the `mention` row's number,
/// or none where there is no row. A name counts wherever it stands (a call, an argument, a
/// statement after a call, a function value), so a second take of the boundary under a held one
/// changes a number, whatever its shape. It is a count of names and reads no guard.
fn mentioned(files: &[(String, String)], roster: &Roster) -> Vec<String> {
    let mut problems = Vec::new();
    for (name, file) in roster.mentions.keys() {
        if !roster.takers.contains(name) {
            problems.push(format!("mention {name} {file}: the name has no taker row"));
        }
        if !files.iter().any(|(known, _)| known == file) {
            problems.push(format!(
                "mention {name} {file}: the file is not in the crate"
            ));
        }
    }
    let mut stands: BTreeMap<&str, usize> = BTreeMap::new();
    for (file, source) in files {
        let text: Vec<char> = without_test_modules(&blank(source)).chars().collect();
        let words = idents(&text);
        for name in &roster.takers {
            let count = words.iter().filter(|(_, word)| word == name).count();
            *stands.entry(name.as_str()).or_default() += count;
            let listed = roster
                .mentions
                .get(&(name.clone(), file.clone()))
                .copied()
                .unwrap_or(0);
            if count != listed {
                problems.push(format!(
                    "{file} mentions {name} {count} time(s) and its mention row says {listed}: a name \
                     that takes the dispatch boundary stands where it did not, or does not where it \
                     did. Read the new text (a take under the held boundary waits on itself; the \
                     lock audit's table of takers is the record), then set `mention {name} {file} \
                     {count}`, and add `taker <name>` first for a new function that takes the boundary"
                ));
            }
        }
    }
    for name in &roster.takers {
        if stands.get(name.as_str()).copied().unwrap_or(0) == 0 {
            problems.push(format!("taker {name}: no file of the crate mentions it"));
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
