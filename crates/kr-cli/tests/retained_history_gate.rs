//! The gate of the historical reader, in a target of its own.
//!
//! The reader (the `retained_surface` target's `history_gate` case) reads every release tag and writes
//! a report: for each tag the sightings it found, the lines of the items that gave them, and whether
//! the scan failed. This target declares none of the reader's modules: it holds the report to what it
//! finds itself, so that a fault of a helper the reader uses cannot move the report and the check
//! together.
//!
//! * The tags, their commits and dates come from `git for-each-ref`, parsed and ordered here.
//! * The files of a tag come from `git archive`, the workspace members from the root manifest, and
//!   the client crates are the members that are neither the protocol, the worker nor the controller.
//! * The oracle lexes each product file itself and finds the sender names the plan lists (the six
//!   variant names, the six wire names, `MutationRequest {` and `ActionTarget {`), in the files that a
//!   module walk with rustc's two file rules and `#[path]` strings reaches, outside the places whose
//!   `cfg` is false with `test` false and every other atom unknown. Each hit must lie inside the lines
//!   of a reported sighting.
//! * The sightings of every tag are kept in `retained_history_record.txt` beside this file: a change
//!   to the result at an old tag fails until the record changes with it.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const VARIANTS: [&str; 6] = [
    "AgentPromptSubmit",
    "AgentPromptQueue",
    "AgentTurnSteer",
    "AgentTurnCancel",
    "AgentApprovalRespond",
    "PluginActionInvoke",
];
const WIRE_NAMES: [&str; 6] = [
    "agent.prompt.submit",
    "agent.prompt.queue",
    "agent.turn.steer",
    "agent.turn.cancel",
    "agent.approval.respond",
    "plugin.action.invoke",
];
/// The crates that receive a mutation and the daemon that relays one: the gate's own copy of the
/// rule that makes every other member a client.
const NOT_CLIENTS: [&str; 3] = ["kr_protocol", "kr_worker", "kr_controller"];

// ---------------------------------------------------------------------------------------------
// The tags
// ---------------------------------------------------------------------------------------------

/// A release tag as git lists it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Release {
    tag: String,
    commit: String,
    version: (u32, u32, u32),
    date: i64,
}

impl Release {
    /// The order of releases: version, then the commit's date, then the tag.
    fn key(&self) -> ((u32, u32, u32), i64, &str) {
        (self.version, self.date, &self.tag)
    }
}

/// The lines of `git for-each-ref --format=%(refname:strip=2)<TAB>%(objectname)<TAB>%(*objectname)<TAB>
/// %(committerdate:unix)<TAB>%(*committerdate:unix)`, each peeled to its commit where the tag is
/// annotated, in the order of releases.
fn parse_listing(text: &str) -> Result<Vec<Release>, String> {
    let mut listed = Vec::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.split('\t').collect();
        let [tag, object, peeled, date, peeled_date] = fields.as_slice() else {
            return Err(format!("a line of {} fields: {line}", fields.len()));
        };
        let (commit, date) = if peeled.is_empty() {
            (object, date)
        } else {
            (peeled, peeled_date)
        };
        let version = version_of(tag).ok_or_else(|| format!("{tag} is no release tag"))?;
        listed.push(Release {
            tag: (*tag).to_owned(),
            commit: (*commit).to_owned(),
            version,
            date: date
                .parse()
                .map_err(|error| format!("the date of {tag}: {error}"))?,
        });
    }
    listed.sort_by(|left, right| left.key().cmp(&right.key()));
    Ok(listed)
}

/// `packages/v<major>.<minor>.<patch>+<twelve characters>`.
fn version_of(tag: &str) -> Option<(u32, u32, u32)> {
    let (version, short) = tag.strip_prefix("packages/v")?.split_once('+')?;
    if short.len() != 12 {
        return None;
    }
    let numbers: Vec<u32> = version
        .split('.')
        .map(|part| part.parse().ok())
        .collect::<Option<_>>()?;
    match numbers.as_slice() {
        [major, minor, patch] => Some((*major, *minor, *patch)),
        _ => None,
    }
}

fn git(repository: &Path, args: &[&str]) -> Result<String, String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(repository)
        .output()
        .map_err(|error| format!("git {}: {error}", args.join(" ")))?;
    if !output.status.success() {
        return Err(format!(
            "git {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn listed_releases(repository: &Path) -> Result<Vec<Release>, String> {
    let text = git(
        repository,
        &[
            "for-each-ref",
            "--format=%(refname:strip=2)%09%(objectname)%09%(*objectname)%09%(committerdate:unix)%09%(*committerdate:unix)",
            "refs/tags/packages/v*",
        ],
    )?;
    parse_listing(&text)
}

// ---------------------------------------------------------------------------------------------
// The report
// ---------------------------------------------------------------------------------------------

/// What the reader reports for one tag.
#[derive(Debug, Default, PartialEq, Eq)]
struct Tag {
    commit: String,
    /// `Some(Ok(n))` for a scan that found `n` sightings, `Some(Err(text))` for one that failed.
    scan: Option<Result<usize, String>>,
    scans: usize,
    /// For each sighting `(crate, name)`: its kinds.
    sightings: BTreeMap<(String, String), String>,
    /// The lines the items of each sighting cover.
    extents: BTreeMap<(String, String), BTreeSet<(String, usize, usize)>>,
}

/// The tags of a report in the order it lists them.
#[derive(Debug, Default, PartialEq, Eq)]
struct Report {
    order: Vec<String>,
    tags: BTreeMap<String, Tag>,
}

/// The report's lines, tab separated:
/// `release <tag> <commit>`, `scan <tag> ok <count>`, `scan <tag> failed <text>`,
/// `sighting <tag> <crate> <name> <kinds>` and `extent <tag> <crate> <name> <file> <first> <last>`.
fn parse_report(text: &str) -> Result<Report, String> {
    let mut report = Report::default();
    for line in text.lines() {
        let fields: Vec<&str> = line.split('\t').collect();
        let tag_of = |report: &mut Report, tag: &str| -> Result<(), String> {
            if report.tags.contains_key(tag) {
                Ok(())
            } else {
                Err(format!(
                    "a line for {tag}, which no release line precedes: {line}"
                ))
            }
        };
        match fields.as_slice() {
            ["release", tag, commit] => {
                if report.tags.contains_key(*tag) {
                    return Err(format!("{tag} is listed twice"));
                }
                report.order.push((*tag).to_owned());
                report.tags.insert(
                    (*tag).to_owned(),
                    Tag {
                        commit: (*commit).to_owned(),
                        ..Tag::default()
                    },
                );
            }
            ["scan", tag, "ok", count] => {
                tag_of(&mut report, tag)?;
                let entry = report.tags.get_mut(*tag).expect("listed");
                entry.scans += 1;
                entry.scan = Some(Ok(count
                    .parse()
                    .map_err(|error| format!("{line}: {error}"))?));
            }
            ["scan", tag, "failed", text] => {
                tag_of(&mut report, tag)?;
                let entry = report.tags.get_mut(*tag).expect("listed");
                entry.scans += 1;
                entry.scan = Some(Err((*text).to_owned()));
            }
            ["sighting", tag, krate, name, kinds] => {
                tag_of(&mut report, tag)?;
                report.tags.get_mut(*tag).expect("listed").sightings.insert(
                    ((*krate).to_owned(), (*name).to_owned()),
                    (*kinds).to_owned(),
                );
            }
            ["extent", tag, krate, name, file, first, last] => {
                tag_of(&mut report, tag)?;
                let number = |text: &str| -> Result<usize, String> {
                    text.parse().map_err(|error| format!("{line}: {error}"))
                };
                report
                    .tags
                    .get_mut(*tag)
                    .expect("listed")
                    .extents
                    .entry(((*krate).to_owned(), (*name).to_owned()))
                    .or_default()
                    .insert(((*file).to_owned(), number(first)?, number(last)?));
            }
            _ => return Err(format!("a line the report does not hold: {line}")),
        }
    }
    Ok(report)
}

/// The sightings of the report as the record keeps them: a line for each, in the order of the
/// report's tags, then crate and name.
fn record_of(report: &Report) -> String {
    let mut out = String::new();
    for tag in &report.order {
        for ((krate, name), kinds) in &report.tags[tag].sightings {
            out.push_str(&format!("{tag}\t{krate}\t{name}\t{kinds}\n"));
        }
    }
    out
}

// ---------------------------------------------------------------------------------------------
// The lexer
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
enum Tok {
    Ident(String),
    Str(String),
    Open(char),
    Close(char),
    Punct(char),
    Other,
}

#[derive(Clone, Debug)]
struct Token {
    tok: Tok,
    line: usize,
}

/// The value of the escapes of a string literal body, and the number of lines it spans.
fn decode(chars: &[char], mut at: usize) -> Result<(String, usize, usize), String> {
    let mut out = String::new();
    let mut lines = 0;
    while at < chars.len() {
        match chars[at] {
            '"' => return Ok((out, at + 1, lines)),
            '\\' => {
                at += 1;
                match chars.get(at) {
                    Some('n') => out.push('\n'),
                    Some('r') => out.push('\r'),
                    Some('t') => out.push('\t'),
                    Some('0') => out.push('\0'),
                    Some('x') => {
                        let hex: String = chars.get(at + 1..at + 3).unwrap_or(&[]).iter().collect();
                        out.push(
                            u32::from_str_radix(&hex, 16)
                                .ok()
                                .and_then(char::from_u32)
                                .ok_or("a bad \\x escape")?,
                        );
                        at += 2;
                    }
                    Some('u') => {
                        let close = chars[at..]
                            .iter()
                            .position(|c| *c == '}')
                            .ok_or("a bad \\u escape")?;
                        let hex: String = chars[at + 2..at + close].iter().collect();
                        out.push(
                            u32::from_str_radix(&hex.replace('_', ""), 16)
                                .ok()
                                .and_then(char::from_u32)
                                .ok_or("a bad \\u escape")?,
                        );
                        at += close;
                    }
                    Some('\n') => {
                        lines += 1;
                        while chars.get(at + 1).is_some_and(|c| c.is_whitespace()) {
                            if chars[at + 1] == '\n' {
                                lines += 1;
                            }
                            at += 1;
                        }
                    }
                    Some(other) => out.push(*other),
                    None => return Err("a string that does not end".to_owned()),
                }
                at += 1;
            }
            other => {
                if other == '\n' {
                    lines += 1;
                }
                out.push(other);
                at += 1;
            }
        }
    }
    Err("a string that does not end".to_owned())
}

/// The body of a raw string with `hashes` marks, from `at` (after the opening quote).
fn raw(chars: &[char], at: usize, hashes: usize) -> Result<(String, usize, usize), String> {
    let mut end = at;
    while end < chars.len() {
        if chars[end] == '"' && (1..=hashes).all(|n| chars.get(end + n) == Some(&'#')) {
            let body: String = chars[at..end].iter().collect();
            let lines = body.matches('\n').count();
            return Ok((body, end + 1 + hashes, lines));
        }
        end += 1;
    }
    Err("a raw string that does not end".to_owned())
}

fn lex(text: &str) -> Result<Vec<Token>, String> {
    let chars: Vec<char> = text.chars().collect();
    let mut out = Vec::new();
    let (mut at, mut line) = (0usize, 1usize);
    let push = |out: &mut Vec<Token>, tok: Tok, line: usize| out.push(Token { tok, line });
    while at < chars.len() {
        let c = chars[at];
        if c == '\n' {
            line += 1;
            at += 1;
        } else if c.is_whitespace() {
            at += 1;
        } else if c == '/' && chars.get(at + 1) == Some(&'/') {
            while at < chars.len() && chars[at] != '\n' {
                at += 1;
            }
        } else if c == '/' && chars.get(at + 1) == Some(&'*') {
            let mut depth = 0;
            while at < chars.len() {
                if chars[at] == '/' && chars.get(at + 1) == Some(&'*') {
                    depth += 1;
                    at += 2;
                } else if chars[at] == '*' && chars.get(at + 1) == Some(&'/') {
                    depth -= 1;
                    at += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    if chars[at] == '\n' {
                        line += 1;
                    }
                    at += 1;
                }
            }
        } else if c == '"' {
            let (body, next, lines) =
                decode(&chars, at + 1).map_err(|e| format!("line {line}: {e}"))?;
            push(&mut out, Tok::Str(body), line);
            line += lines;
            at = next;
        } else if c == '\'' {
            if chars.get(at + 1) == Some(&'\\') {
                let mut end = at + 3;
                while end < chars.len() && chars[end] != '\'' {
                    end += 1;
                }
                at = end + 1;
            } else if chars.get(at + 2) == Some(&'\'') {
                at += 3;
            } else {
                at += 1;
                while at < chars.len() && (chars[at].is_alphanumeric() || chars[at] == '_') {
                    at += 1;
                }
            }
            push(&mut out, Tok::Other, line);
        } else if c.is_alphabetic() || c == '_' {
            let start = at;
            while at < chars.len() && (chars[at].is_alphanumeric() || chars[at] == '_') {
                at += 1;
            }
            let word: String = chars[start..at].iter().collect();
            let next = chars.get(at).copied();
            if matches!(word.as_str(), "b" | "c") && next == Some('"') {
                let (body, after, lines) =
                    decode(&chars, at + 1).map_err(|e| format!("line {line}: {e}"))?;
                push(&mut out, Tok::Str(body), line);
                line += lines;
                at = after;
            } else if matches!(word.as_str(), "r" | "br" | "cr") && matches!(next, Some('"' | '#'))
            {
                let mut hashes = 0;
                while chars.get(at + hashes) == Some(&'#') {
                    hashes += 1;
                }
                if chars.get(at + hashes) == Some(&'"') {
                    let (body, after, lines) = raw(&chars, at + hashes + 1, hashes)
                        .map_err(|e| format!("line {line}: {e}"))?;
                    push(&mut out, Tok::Str(body), line);
                    line += lines;
                    at = after;
                } else if word == "r" && hashes == 1 {
                    let start = at + 1;
                    at = start;
                    while at < chars.len() && (chars[at].is_alphanumeric() || chars[at] == '_') {
                        at += 1;
                    }
                    push(
                        &mut out,
                        Tok::Ident(chars[start..at].iter().collect()),
                        line,
                    );
                } else {
                    push(&mut out, Tok::Ident(word), line);
                }
            } else {
                push(&mut out, Tok::Ident(word), line);
            }
        } else if c.is_ascii_digit() {
            while at < chars.len() && (chars[at].is_alphanumeric() || chars[at] == '_') {
                at += 1;
            }
            push(&mut out, Tok::Other, line);
        } else {
            let tok = match c {
                '(' | '[' | '{' => Tok::Open(c),
                ')' | ']' | '}' => Tok::Close(c),
                _ => Tok::Punct(c),
            };
            push(&mut out, tok, line);
            at += 1;
        }
    }
    Ok(out)
}

/// The index of the token that closes the group opened at `open`.
fn closing(tokens: &[Token], open: usize) -> Result<usize, String> {
    let mut depth = 0usize;
    for (at, token) in tokens.iter().enumerate().skip(open) {
        match token.tok {
            Tok::Open(_) => depth += 1,
            Tok::Close(_) => {
                depth -= 1;
                if depth == 0 {
                    return Ok(at);
                }
            }
            _ => {}
        }
    }
    Err(format!(
        "line {}: a group that does not close",
        tokens[open].line
    ))
}

// ---------------------------------------------------------------------------------------------
// The condition rule (Kleene's three values: `test` is false, the rest unknown)
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Value {
    True,
    False,
    Unknown,
}

fn not(value: Value) -> Value {
    match value {
        Value::True => Value::False,
        Value::False => Value::True,
        Value::Unknown => Value::Unknown,
    }
}

/// The value of the predicate in `tokens`, from `at`: the value and the index after it.
fn predicate(tokens: &[Token], at: usize) -> Result<(Value, usize), String> {
    let Some(Tok::Ident(word)) = tokens.get(at).map(|token| &token.tok) else {
        return Err("a predicate that is not a word".to_owned());
    };
    let next = at + 1;
    if matches!(word.as_str(), "not" | "all" | "any") {
        if !matches!(tokens.get(next).map(|t| &t.tok), Some(Tok::Open('('))) {
            return Err(format!("{word} without its list"));
        }
        let close = closing(tokens, next)?;
        let mut values = Vec::new();
        let mut index = next + 1;
        while index < close {
            let (value, after) = predicate(tokens, index)?;
            values.push(value);
            index = after;
            if matches!(tokens.get(index).map(|t| &t.tok), Some(Tok::Punct(','))) {
                index += 1;
            }
        }
        let value = match word.as_str() {
            "not" => match values.as_slice() {
                [one] => not(*one),
                _ => return Err("not of other than one predicate".to_owned()),
            },
            "all" => {
                if values.contains(&Value::False) {
                    Value::False
                } else if values.iter().all(|v| *v == Value::True) {
                    Value::True
                } else {
                    Value::Unknown
                }
            }
            _ => {
                if values.contains(&Value::True) {
                    Value::True
                } else if values.iter().all(|v| *v == Value::False) {
                    Value::False
                } else {
                    Value::Unknown
                }
            }
        };
        return Ok((value, close + 1));
    }
    let value = match word.as_str() {
        "test" => Value::False,
        "true" => Value::True,
        "false" => Value::False,
        _ => Value::Unknown,
    };
    // `key = "value"` is one atom.
    if matches!(tokens.get(next).map(|t| &t.tok), Some(Tok::Punct('='))) {
        return Ok((Value::Unknown, next + 2));
    }
    Ok((value, next))
}

/// What an attribute says that the walk needs.
#[derive(Debug, PartialEq)]
enum Attr {
    /// `cfg(..)` with its value.
    Cfg(Value),
    /// `path = "..."`.
    Path(String),
    Other,
}

fn attribute(tokens: &[Token]) -> Attr {
    match tokens.first().map(|t| &t.tok) {
        Some(Tok::Ident(word)) if word == "cfg" => {
            match predicate(tokens, 2).map(|(value, _)| value) {
                Ok(value) if matches!(tokens.get(1).map(|t| &t.tok), Some(Tok::Open('('))) => {
                    Attr::Cfg(value)
                }
                // A predicate this reads wrongly is no reason to leave a place out.
                _ => Attr::Cfg(Value::Unknown),
            }
        }
        Some(Tok::Ident(word)) if word == "path" => match tokens.get(2).map(|t| &t.tok) {
            Some(Tok::Str(text)) => Attr::Path(text.clone()),
            _ => Attr::Other,
        },
        _ => Attr::Other,
    }
}

// ---------------------------------------------------------------------------------------------
// The oracle: the module walk and the line search
// ---------------------------------------------------------------------------------------------

/// A place where a sender name stands.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Hit {
    file: String,
    line: usize,
    what: String,
}

/// One body-less module declaration: the files it may be at, and whether a `#[path]` names it.
#[derive(Debug)]
struct Declared {
    name: String,
    candidates: Vec<String>,
    explicit: bool,
}

#[derive(Debug, Default)]
struct FileRead {
    hits: Vec<Hit>,
    declared: Vec<Declared>,
}

fn dir_of(file: &str) -> String {
    file.rsplit_once('/')
        .map_or(String::new(), |(dir, _)| dir.to_owned())
}

fn join(base: &str, rest: &str) -> String {
    if base.is_empty() {
        rest.to_owned()
    } else {
        format!("{base}/{rest}")
    }
}

/// `path` with its `.` steps left out and each `..` taken with the step before it; a path that
/// leaves its start is an error.
fn normal(path: &str) -> Result<String, String> {
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts
                    .pop()
                    .ok_or_else(|| format!("{path} leaves the tree"))?;
            }
            other => parts.push(other),
        }
    }
    Ok(parts.join("/"))
}

/// The end of the item that begins at `start`: after its `;`, after the first `{..}` group at its own
/// level, or before the group that holds it closes.
fn skip_item(tokens: &[Token], start: usize) -> usize {
    let mut depth = 0usize;
    let mut at = start;
    while at < tokens.len() {
        match tokens[at].tok {
            Tok::Open(_) => depth += 1,
            Tok::Close(close) => {
                if depth == 0 {
                    return at;
                }
                depth -= 1;
                if depth == 0 && close == '}' {
                    return at + 1;
                }
            }
            Tok::Punct(';') if depth == 0 => return at + 1,
            _ => {}
        }
        at += 1;
    }
    tokens.len()
}

/// Reads one file: the hits outside the places a false `cfg` leaves out, and the module
/// declarations the file makes outside them. `beside` says whether the file's modules sit beside it
/// (a root, a `mod.rs`, or a file a `#[path]` names) or in a folder of its name. `None` where an inner
/// `cfg` of the file is false.
fn read_file(file: &str, text: &str, beside: bool) -> Result<Option<FileRead>, String> {
    let tokens = lex(text).map_err(|error| format!("{file}: {error}"))?;
    let stem = file
        .rsplit('/')
        .next()
        .and_then(|name| name.strip_suffix(".rs"))
        .unwrap_or_default();
    let base = if beside {
        dir_of(file)
    } else {
        join(&dir_of(file), stem)
    };
    let mut read = FileRead::default();
    let mut inline: Vec<(usize, String)> = Vec::new();
    let mut depth = 0usize;
    let mut pending: Vec<Attr> = Vec::new();
    let mut at = 0;
    while at < tokens.len() {
        let token = &tokens[at];
        match &token.tok {
            Tok::Punct('#') => {
                let inner = matches!(tokens.get(at + 1).map(|t| &t.tok), Some(Tok::Punct('!')));
                let open = at + 1 + usize::from(inner);
                if matches!(tokens.get(open).map(|t| &t.tok), Some(Tok::Open('['))) {
                    let close = closing(&tokens, open).map_err(|e| format!("{file}: {e}"))?;
                    let attr = attribute(&tokens[open + 1..close]);
                    at = close + 1;
                    if inner {
                        if attr == Attr::Cfg(Value::False) && depth == 0 {
                            return Ok(None);
                        }
                        continue;
                    }
                    pending.push(attr);
                    // The attributes that follow are the item's too.
                    while matches!(tokens.get(at).map(|t| &t.tok), Some(Tok::Punct('#')))
                        && matches!(tokens.get(at + 1).map(|t| &t.tok), Some(Tok::Open('[')))
                    {
                        let close = closing(&tokens, at + 1).map_err(|e| format!("{file}: {e}"))?;
                        pending.push(attribute(&tokens[at + 2..close]));
                        at = close + 1;
                    }
                    if pending.contains(&Attr::Cfg(Value::False)) {
                        at = skip_item(&tokens, at);
                        pending.clear();
                    }
                    continue;
                }
            }
            Tok::Ident(word) if word == "mod" => {
                if let (Some(Tok::Ident(name)), Some(after)) = (
                    tokens.get(at + 1).map(|t| &t.tok),
                    tokens.get(at + 2).map(|t| &t.tok),
                ) {
                    let path = pending.iter().find_map(|attr| match attr {
                        Attr::Path(text) => Some(text.clone()),
                        _ => None,
                    });
                    let comps: Vec<&str> = inline.iter().map(|(_, c)| c.as_str()).collect();
                    let folder = if comps.is_empty() {
                        base.clone()
                    } else {
                        join(&base, &comps.join("/"))
                    };
                    match after {
                        Tok::Punct(';') => {
                            let (candidates, explicit) = match path {
                                Some(path) => {
                                    // A path is relative to the file's folder, and inside an inline
                                    // module to the folder of that module.
                                    let from = if comps.is_empty() {
                                        dir_of(file)
                                    } else {
                                        folder
                                    };
                                    (vec![normal(&join(&from, &path))?], true)
                                }
                                None => (
                                    vec![
                                        join(&folder, &format!("{name}.rs")),
                                        join(&folder, &format!("{name}/mod.rs")),
                                    ],
                                    false,
                                ),
                            };
                            read.declared.push(Declared {
                                name: name.clone(),
                                candidates,
                                explicit,
                            });
                            pending.clear();
                            at += 3;
                            continue;
                        }
                        Tok::Open('{') => {
                            inline.push((depth + 1, path.unwrap_or_else(|| name.clone())));
                            pending.clear();
                            at += 2;
                            continue;
                        }
                        _ => {}
                    }
                }
            }
            Tok::Open(_) => {
                depth += 1;
                pending.clear();
            }
            Tok::Close(_) => {
                if inline.last().is_some_and(|(open, _)| *open == depth) {
                    inline.pop();
                }
                depth = depth.saturating_sub(1);
                pending.clear();
            }
            Tok::Punct(';') => pending.clear(),
            Tok::Ident(word) => {
                if VARIANTS.contains(&word.as_str()) && !after_action_right(&tokens, at) {
                    read.hits.push(hit(file, token.line, word));
                }
                if matches!(word.as_str(), "MutationRequest" | "ActionTarget")
                    && matches!(tokens.get(at + 1).map(|t| &t.tok), Some(Tok::Open('{')))
                {
                    read.hits.push(hit(file, token.line, &format!("{word} {{")));
                }
                if matches!(
                    word.as_str(),
                    "fn" | "struct"
                        | "enum"
                        | "union"
                        | "trait"
                        | "impl"
                        | "use"
                        | "static"
                        | "type"
                        | "const"
                ) {
                    pending.clear();
                }
            }
            Tok::Str(text) => {
                if let Some(name) = WIRE_NAMES.iter().find(|name| text.contains(*name)) {
                    read.hits.push(hit(file, token.line, name));
                }
            }
            _ => {}
        }
        at += 1;
    }
    Ok(Some(read))
}

fn hit(file: &str, line: usize, what: &str) -> Hit {
    Hit {
        file: file.to_owned(),
        line,
        what: what.to_owned(),
    }
}

/// Whether the name at `at` follows `ActionRight ::`, a right that holds the same names.
fn after_action_right(tokens: &[Token], at: usize) -> bool {
    at >= 3
        && tokens[at - 1].tok == Tok::Punct(':')
        && tokens[at - 2].tok == Tok::Punct(':')
        && tokens[at - 3].tok == Tok::Ident("ActionRight".to_owned())
}

/// The hits of the files that a walk from `roots` reaches under `folder`, outside the places a false
/// `cfg` leaves out. A module at no file, or at two, is an error.
fn walk(folder: &Path, roots: &[String]) -> Result<Vec<Hit>, String> {
    let mut todo: Vec<(String, bool)> = roots.iter().map(|root| (root.clone(), true)).collect();
    let mut seen = BTreeSet::new();
    let mut hits = Vec::new();
    while let Some((file, beside)) = todo.pop() {
        if !seen.insert(file.clone()) {
            continue;
        }
        let text =
            std::fs::read_to_string(folder.join(&file)).map_err(|e| format!("{file}: {e}"))?;
        let Some(read) = read_file(&file, &text, beside)? else {
            continue;
        };
        hits.extend(read.hits);
        for declared in read.declared {
            let found: Vec<&String> = declared
                .candidates
                .iter()
                .filter(|candidate| folder.join(candidate).is_file())
                .collect();
            match found.as_slice() {
                [one] => {
                    let beside = declared.explicit || one.ends_with("/mod.rs") || *one == "mod.rs";
                    todo.push(((*one).clone(), beside));
                }
                [] => {
                    return Err(format!(
                        "{file}: mod {} is at no file (tried {})",
                        declared.name,
                        declared.candidates.join(", ")
                    ));
                }
                _ => {
                    return Err(format!("{file}: mod {} is at two files", declared.name));
                }
            }
        }
    }
    hits.sort();
    Ok(hits)
}

/// The names the members of a workspace manifest list: the quoted strings between `members = [` and
/// its `]`.
fn members_of(manifest: &str) -> Vec<String> {
    let Some(start) = manifest.find("members") else {
        return Vec::new();
    };
    let rest = &manifest[start..];
    let Some(open) = rest.find('[') else {
        return Vec::new();
    };
    let Some(close) = rest[open..].find(']') else {
        return Vec::new();
    };
    rest[open + 1..open + close]
        .split('"')
        .skip(1)
        .step_by(2)
        .map(str::to_owned)
        .collect()
}

/// The package name a member's manifest gives, with `-` as `_`.
fn crate_name(manifest: &str) -> Option<String> {
    manifest.lines().find_map(|line| {
        let line = line.trim();
        let rest = line.strip_prefix("name")?.trim_start().strip_prefix('=')?;
        Some(rest.trim().trim_matches('"').replace('-', "_"))
    })
}

/// The roots Cargo finds in a member's `src`: `lib.rs`, `main.rs`, `bin/*.rs` and `bin/*/main.rs`.
fn roots_of(folder: &Path, member: &str) -> Vec<String> {
    let mut roots = Vec::new();
    for root in ["lib.rs", "main.rs"] {
        let path = format!("{member}/src/{root}");
        if folder.join(&path).is_file() {
            roots.push(path);
        }
    }
    if let Ok(entries) = std::fs::read_dir(folder.join(member).join("src/bin")) {
        let mut names: Vec<String> = entries
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        for name in names {
            let path = format!("{member}/src/bin/{name}");
            if name.ends_with(".rs") {
                roots.push(path);
            } else if folder.join(&path).join("main.rs").is_file() {
                roots.push(format!("{path}/main.rs"));
            }
        }
    }
    roots
}

/// The hits of the client crates of the workspace under `folder`.
fn oracle(folder: &Path) -> Result<Vec<Hit>, String> {
    let manifest = std::fs::read_to_string(folder.join("Cargo.toml"))
        .map_err(|error| format!("the root manifest: {error}"))?;
    let mut hits = Vec::new();
    for member in members_of(&manifest) {
        if member.starts_with("tests") {
            continue;
        }
        let text = std::fs::read_to_string(folder.join(&member).join("Cargo.toml"))
            .map_err(|error| format!("{member}: {error}"))?;
        let name = crate_name(&text).ok_or_else(|| format!("{member}: no package name"))?;
        if NOT_CLIENTS.contains(&name.as_str()) {
            continue;
        }
        let roots = roots_of(folder, &member);
        if roots.is_empty() {
            return Err(format!(
                "{member}: no library or binary target the gate finds"
            ));
        }
        hits.extend(walk(folder, &roots)?);
    }
    hits.sort();
    Ok(hits)
}

// ---------------------------------------------------------------------------------------------
// The gate
// ---------------------------------------------------------------------------------------------

/// The hits that no extent of the file covers.
fn uncovered<'a>(hits: &'a [Hit], extents: &BTreeSet<(String, usize, usize)>) -> Vec<&'a Hit> {
    hits.iter()
        .filter(|hit| {
            !extents.iter().any(|(file, first, last)| {
                *file == hit.file && (*first..=*last).contains(&hit.line)
            })
        })
        .collect()
}

/// The problems of one tag: a scan that is missing, repeated or failed, a count that is not the
/// sightings listed, a sighting with no lines, and each hit of the oracle that no sighting covers.
fn tag_problems(tag: &str, reported: &Tag, hits: &[Hit]) -> Vec<String> {
    let mut problems = Vec::new();
    match (&reported.scan, reported.scans) {
        (Some(Ok(count)), 1) => {
            if *count != reported.sightings.len() {
                problems.push(format!(
                    "{tag}: the scan says {count} sightings and the report lists {}",
                    reported.sightings.len()
                ));
            }
        }
        (Some(Err(text)), _) => problems.push(format!("{tag}: the scan failed: {text}")),
        (_, scans) => problems.push(format!("{tag}: {scans} scan lines, not one")),
    }
    for ((krate, name), kinds) in &reported.sightings {
        let lines = reported.extents.get(&(krate.clone(), name.clone()));
        if kinds != "Expands" && lines.is_none_or(BTreeSet::is_empty) {
            problems.push(format!("{tag}: {krate}::{name} ({kinds}) covers no line"));
        }
    }
    for ((krate, name), extents) in &reported.extents {
        for (file, first, last) in extents {
            if *first == 0 || first > last {
                problems.push(format!(
                    "{tag}: {krate}::{name} covers lines {first} to {last} of {file}"
                ));
            }
        }
    }
    let all: BTreeSet<(String, usize, usize)> =
        reported.extents.values().flatten().cloned().collect();
    for hit in uncovered(hits, &all) {
        problems.push(format!(
            "{tag}: {} line {} ({}) is no part of a sighting",
            hit.file, hit.line, hit.what
        ));
    }
    problems
}

/// Where the report's releases are not the tags and commits git lists, in the same order.
fn release_problems(listed: &[Release], report: &Report) -> Vec<String> {
    let mut problems = Vec::new();
    let read: Vec<(&str, &str)> = report
        .order
        .iter()
        .map(|tag| (tag.as_str(), report.tags[tag].commit.as_str()))
        .collect();
    let wanted: Vec<(&str, &str)> = listed
        .iter()
        .map(|release| (release.tag.as_str(), release.commit.as_str()))
        .collect();
    if read.len() != wanted.len() {
        problems.push(format!(
            "{} releases reported for {} tags",
            read.len(),
            wanted.len()
        ));
    }
    for (at, (found, expected)) in read.iter().zip(&wanted).enumerate() {
        if found != expected {
            problems.push(format!(
                "release {at} is {} at {}, the tags give {} at {}",
                found.0, found.1, expected.0, expected.1
            ));
        }
    }
    problems
}

/// The lines in which `record` and `now` differ: each as `+` (in the report only) or `-` (in the
/// record only), the first `limit` of them.
fn record_problems(record: &str, now: &str, limit: usize) -> Vec<String> {
    let kept: BTreeSet<&str> = record.lines().collect();
    let found: BTreeSet<&str> = now.lines().collect();
    let mut problems: Vec<String> = Vec::new();
    for line in found.difference(&kept) {
        problems.push(format!("the record lacks: {line}"));
    }
    for line in kept.difference(&found) {
        problems.push(format!("the report lacks: {line}"));
    }
    let total = problems.len();
    problems.truncate(limit);
    if total > limit {
        problems.push(format!(
            "and {} more differences from the record",
            total - limit
        ));
    }
    problems
}

// ---------------------------------------------------------------------------------------------
// The history
// ---------------------------------------------------------------------------------------------

fn repository() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the repository")
}

/// The `crates` and `apps` folders of a commit, extracted into `folder`.
fn extract(repository: &Path, commit: &str, folder: &Path) -> Result<(), String> {
    let top = git(repository, &["ls-tree", "--name-only", commit])?;
    let mut args = vec!["archive", "--format=tar", commit];
    for name in ["Cargo.toml", "crates", "apps"] {
        if top.lines().any(|line| line == name) {
            args.push(name);
        }
    }
    let mut archive = Command::new("git")
        .args(&args)
        .current_dir(repository)
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|error| format!("git archive: {error}"))?;
    let unpacked = Command::new("tar")
        .args(["-x", "-C"])
        .arg(folder)
        .stdin(archive.stdout.take().expect("a pipe"))
        .status()
        .map_err(|error| format!("tar: {error}"))?;
    let made = archive
        .wait()
        .map_err(|error| format!("git archive: {error}"))?;
    if !made.success() || !unpacked.success() {
        return Err(format!("the files of {commit} could not be extracted"));
    }
    Ok(())
}

#[test]
#[ignore = "reads every release tag; run by hand with --show-output after the reader has written its report"]
fn the_report_of_the_reader_holds_to_what_the_gate_finds_in_every_release() {
    let path = std::env::var_os("KR_HISTORY_REPORT")
        .expect("KR_HISTORY_REPORT names the report the reader wrote");
    let report =
        parse_report(&std::fs::read_to_string(path).expect("the report")).expect("a report");
    let repository = repository();
    let listed = listed_releases(&repository).expect("the release tags");
    let mut problems = release_problems(&listed, &report);
    for release in &listed {
        let Some(reported) = report.tags.get(&release.tag) else {
            continue;
        };
        let folder = tempfile::tempdir().expect("a folder");
        extract(&repository, &release.commit, folder.path())
            .unwrap_or_else(|error| panic!("{}: {error}", release.tag));
        match oracle(folder.path()) {
            Ok(hits) => {
                println!("{}: {} hits", release.tag, hits.len());
                problems.extend(tag_problems(&release.tag, reported, &hits));
            }
            Err(error) => problems.push(format!(
                "{}: the oracle cannot read the tree: {error}",
                release.tag
            )),
        }
    }
    let record_path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/retained_history_record.txt");
    let record = std::fs::read_to_string(&record_path).unwrap_or_default();
    problems.extend(record_problems(&record, &record_of(&report), 40));
    println!(
        "gate read {} releases of {} tags",
        report.order.len(),
        listed.len()
    );
    assert!(problems.is_empty(), "{}", problems.join("\n"));
}

// ---------------------------------------------------------------------------------------------
// Cases
// ---------------------------------------------------------------------------------------------

#[cfg(test)]
mod cases {
    use super::*;

    fn write(folder: &Path, path: &str, text: &str) {
        let at = folder.join(path);
        std::fs::create_dir_all(at.parent().expect("a parent")).expect("a folder");
        std::fs::write(at, text).expect("a file");
    }

    fn tree(files: &[(&str, &str)]) -> tempfile::TempDir {
        let folder = tempfile::tempdir().expect("a folder");
        write(
            folder.path(),
            "Cargo.toml",
            "[workspace]\nmembers = [\n    \"crates/kr-a\",\n    \"crates/kr-worker\",\n]\n",
        );
        write(
            folder.path(),
            "crates/kr-a/Cargo.toml",
            "[package]\nname = \"kr-a\"\n",
        );
        write(
            folder.path(),
            "crates/kr-worker/Cargo.toml",
            "[package]\nname = \"kr-worker\"\n",
        );
        write(
            folder.path(),
            "crates/kr-worker/src/lib.rs",
            "fn w() { Method::AgentTurnCancel; }\n",
        );
        for (path, text) in files {
            write(folder.path(), path, text);
        }
        folder
    }

    fn lines(hits: &[Hit]) -> Vec<(String, usize)> {
        hits.iter()
            .map(|hit| (hit.file.clone(), hit.line))
            .collect()
    }

    #[test]
    fn the_gate_lists_and_orders_the_tags_itself() {
        let text = "packages/v0.10.0+aaaaaaaaaaaa\tobj1\t\t200\t\n\
                    packages/v0.9.0+bbbbbbbbbbbb\tobj2\tcommit2\t300\t100\n\
                    packages/v0.9.0+cccccccccccc\tobj3\t\t50\t\n";
        let listed = parse_listing(text).expect("a listing");
        let tags: Vec<(&str, &str)> = listed
            .iter()
            .map(|r| (r.tag.as_str(), r.commit.as_str()))
            .collect();
        // Version first, so 0.9 comes before 0.10; within a version, the commit's date, an annotated
        // tag taking the date and the commit it peels to.
        assert_eq!(
            tags,
            [
                ("packages/v0.9.0+cccccccccccc", "obj3"),
                ("packages/v0.9.0+bbbbbbbbbbbb", "commit2"),
                ("packages/v0.10.0+aaaaaaaaaaaa", "obj1"),
            ]
        );
        for bad in [
            "packages/v0.9.0+bbbbbbbbbbbb\tobj2\n",
            "packages/v0.9+bbbbbbbbbbbb\tobj\t\t1\t\n",
            "packages/v0.9.0+short\tobj\t\t1\t\n",
            "packages/v0.9.0+bbbbbbbbbbbb\tobj\t\tx\t\n",
        ] {
            assert!(parse_listing(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_report_is_read_back_line_by_line_and_a_line_it_does_not_hold_is_an_error() {
        let text = "release\tt1\tc1\nscan\tt1\tok\t1\nsighting\tt1\tkr_a\tf\tNames\nextent\tt1\tkr_a\tf\tcrates/kr-a/src/lib.rs\t3\t9\nrelease\tt2\tc2\nscan\tt2\tfailed\ta text\n";
        let report = parse_report(text).expect("a report");
        assert_eq!(report.order, ["t1", "t2"]);
        assert_eq!(report.tags["t1"].scan, Some(Ok(1)));
        assert_eq!(report.tags["t2"].scan, Some(Err("a text".to_owned())));
        assert_eq!(record_of(&report), "t1\tkr_a\tf\tNames\n");
        for bad in [
            "scan\tt1\tok\t1\n",
            "release\tt1\tc1\nrelease\tt1\tc1\n",
            "release\tt1\tc1\nextent\tt1\tkr_a\tf\tfile\tx\t9\n",
            "release\tt1\n",
        ] {
            assert!(parse_report(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn the_oracle_finds_a_name_in_each_form_a_string_or_an_identifier_takes() {
        let lib = "fn a() { Method::AgentTurnCancel; }\n\
                   fn b() { \"agent.turn.cancel\"; }\n\
                   fn c() { r#\"agent.turn.steer\"#; }\n\
                   fn d() { \"agent\\x2eturn.\\u{63}ancel\"; }\n\
                   fn e() { \"agent.prompt.\\\n        submit\"; }\n\
                   fn f() { b\"agent.prompt.queue\"; }\n\
                   fn g() { r#AgentTurnSteer; }\n\
                   fn h() { MutationRequest { x: 1 }; ActionTarget{ y: 2 }; }\n\
                   fn i() { ActionRight::AgentTurnCancel; AgentTurnCancelled; MutationRequest::new(); }\n\
                   // Method::AgentTurnCancel in a comment\n\
                   /* \"agent.turn.cancel\" /* nested */ AgentTurnSteer */\n\
                   fn j() { let _ = 'a'; let _: &'static str = \"plain\"; }\n";
        let folder = tree(&[("crates/kr-a/src/lib.rs", lib)]);
        let hits = oracle(folder.path()).expect("hits");
        let at = "crates/kr-a/src/lib.rs";
        assert_eq!(
            lines(&hits),
            [1, 2, 3, 4, 5, 7, 8, 9, 9]
                .iter()
                .map(|line| (at.to_owned(), *line))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn the_oracle_leaves_out_a_place_only_a_false_cfg_builds() {
        let lib = "#[cfg(test)]\nmod tests { fn t() { Method::AgentTurnCancel; } }\n\
                   #[cfg(test)]\nfn only_in_test() { Method::AgentTurnSteer; }\n\
                   #[cfg(all(unix, test))]\nfn also_not() { Method::AgentTurnSteer; }\n\
                   #[cfg(not(test))]\nfn kept_a() { Method::AgentTurnCancel; }\n\
                   #[cfg(unix)]\nfn kept_b() { Method::AgentTurnCancel; }\n\
                   #[cfg(any(test, unix))]\nfn kept_c() { Method::AgentTurnCancel; }\n\
                   #[cfg(feature = \"x\")]\n#[inline]\nfn kept_d() { Method::AgentTurnCancel; }\n\
                   #[cfg(test)]\n#[inline]\nstruct S;\nfn kept_e() { Method::AgentTurnCancel; }\n\
                   fn nested() {\n    #[cfg(test)]\n    let _ = Method::AgentTurnSteer;\n    let _ = Method::AgentTurnCancel;\n}\n";
        let folder = tree(&[("crates/kr-a/src/lib.rs", lib)]);
        let hits = oracle(folder.path()).expect("hits");
        let found: Vec<usize> = hits.iter().map(|hit| hit.line).collect();
        assert_eq!(found, [8, 10, 12, 15, 19, 23], "{hits:?}");
        // A file whose own inner attribute is false is not read, nor is anything it declares.
        let folder = tree(&[
            ("crates/kr-a/src/lib.rs", "mod inner;\n"),
            (
                "crates/kr-a/src/inner.rs",
                "#![cfg(test)]\nmod deeper;\nfn t() { Method::AgentTurnCancel; }\n",
            ),
        ]);
        assert_eq!(oracle(folder.path()), Ok(Vec::new()));
    }

    #[test]
    fn the_module_walk_follows_the_two_file_rules_and_path_strings() {
        let at = |path: &str| path.to_owned();
        let folder = tree(&[
            (
                "crates/kr-a/src/lib.rs",
                "mod a;\nmod b;\nmod c { mod d; }\n#[path = \"x/y.rs\"]\nmod e;\n#[cfg(test)]\nmod gone;\n",
            ),
            (
                "crates/kr-a/src/a.rs",
                "mod inner;\nfn a() { Method::AgentTurnCancel; }\n",
            ),
            (
                "crates/kr-a/src/a/inner.rs",
                "fn i() { Method::AgentTurnSteer; }\n",
            ),
            ("crates/kr-a/src/b/mod.rs", "mod sub;\n"),
            (
                "crates/kr-a/src/b/sub.rs",
                "fn s() { Method::AgentPromptSubmit; }\n",
            ),
            (
                "crates/kr-a/src/c/d.rs",
                "fn d() { Method::AgentPromptQueue; }\n",
            ),
            (
                "crates/kr-a/src/x/y.rs",
                "mod z;\nfn y() { Method::AgentApprovalRespond; }\n",
            ),
            (
                "crates/kr-a/src/x/z.rs",
                "fn z() { Method::PluginActionInvoke; }\n",
            ),
            // A file no declaration reaches is not read.
            (
                "crates/kr-a/src/unreached.rs",
                "fn u() { Method::AgentTurnCancel; }\n",
            ),
        ]);
        let hits = oracle(folder.path()).expect("hits");
        let files: BTreeSet<String> = hits.iter().map(|hit| hit.file.clone()).collect();
        assert_eq!(
            files,
            BTreeSet::from(
                [
                    "crates/kr-a/src/a.rs",
                    "crates/kr-a/src/a/inner.rs",
                    "crates/kr-a/src/b/sub.rs",
                    "crates/kr-a/src/c/d.rs",
                    "crates/kr-a/src/x/y.rs",
                    "crates/kr-a/src/x/z.rs",
                ]
                .map(at)
            )
        );
        let missing = tree(&[("crates/kr-a/src/lib.rs", "mod nowhere;\n")]);
        assert!(oracle(missing.path()).is_err_and(|e| e.contains("at no file")));
        let both = tree(&[
            ("crates/kr-a/src/lib.rs", "mod both;\n"),
            ("crates/kr-a/src/both.rs", "\n"),
            ("crates/kr-a/src/both/mod.rs", "\n"),
        ]);
        assert!(oracle(both.path()).is_err_and(|e| e.contains("at two files")));
        // A crate with no root the gate finds is an error, never an empty result.
        let none = tree(&[]);
        std::fs::remove_file(none.path().join("crates/kr-worker/src/lib.rs")).expect("a file");
        write(none.path(), "crates/kr-a/src/other.rs", "\n");
        assert!(oracle(none.path()).is_err_and(|e| e.contains("no library or binary target")));
        // The worker is no client: its names are not looked for.
        let only_worker = tree(&[("crates/kr-a/src/lib.rs", "fn quiet() {}\n")]);
        assert_eq!(oracle(only_worker.path()), Ok(Vec::new()));
    }

    #[test]
    fn a_hit_that_no_reported_line_covers_is_a_problem_whatever_the_report_says_else() {
        let extents = BTreeSet::from([("crates/kr-a/src/lib.rs".to_owned(), 3, 9)]);
        let hits = [
            hit("crates/kr-a/src/lib.rs", 3, "inside"),
            hit("crates/kr-a/src/lib.rs", 9, "inside"),
            hit("crates/kr-a/src/lib.rs", 10, "after"),
            hit("crates/kr-a/src/lib.rs", 2, "before"),
            hit("crates/kr-a/src/other.rs", 5, "another file"),
        ];
        let found: Vec<&str> = uncovered(&hits, &extents)
            .iter()
            .map(|hit| hit.what.as_str())
            .collect();
        assert_eq!(found, ["after", "before", "another file"]);
        assert_eq!(uncovered(&hits, &BTreeSet::new()).len(), 5);
    }

    fn reported(scan: Option<Result<usize, String>>, scans: usize) -> Tag {
        let mut tag = Tag {
            commit: "c".to_owned(),
            scan,
            scans,
            ..Tag::default()
        };
        tag.sightings
            .insert(("kr_a".to_owned(), "f".to_owned()), "Names".to_owned());
        tag.extents.insert(
            ("kr_a".to_owned(), "f".to_owned()),
            BTreeSet::from([("crates/kr-a/src/lib.rs".to_owned(), 1, 4)]),
        );
        tag
    }

    #[test]
    fn a_scan_that_is_missing_failed_or_wrong_is_a_problem_and_never_an_empty_result() {
        let covered = [hit("crates/kr-a/src/lib.rs", 2, "x")];
        assert_eq!(
            tag_problems("t", &reported(Some(Ok(1)), 1), &covered),
            Vec::<String>::new()
        );
        // A refused file ends the scan `Failed`.
        let failed = tag_problems("t", &reported(Some(Err("a file".to_owned())), 1), &covered);
        assert_eq!(failed, ["t: the scan failed: a file"]);
        // No scan line, or two.
        assert_eq!(
            tag_problems("t", &reported(None, 0), &covered),
            ["t: 0 scan lines, not one"]
        );
        assert_eq!(
            tag_problems("t", &reported(Some(Ok(1)), 2), &covered),
            ["t: 2 scan lines, not one"]
        );
        // A count that is not the list.
        assert_eq!(
            tag_problems("t", &reported(Some(Ok(0)), 1), &covered),
            ["t: the scan says 0 sightings and the report lists 1"]
        );
        // A scan that found nothing where the oracle finds a name.
        let mut empty = Tag {
            commit: "c".to_owned(),
            scan: Some(Ok(0)),
            scans: 1,
            ..Tag::default()
        };
        assert_eq!(
            tag_problems("t", &empty, &covered),
            ["t: crates/kr-a/src/lib.rs line 2 (x) is no part of a sighting"]
        );
        // A sighting with no lines, or with lines that make no range.
        empty.scan = Some(Ok(1));
        empty
            .sightings
            .insert(("kr_a".to_owned(), "g".to_owned()), "Names".to_owned());
        assert!(
            tag_problems("t", &empty, &[])
                .contains(&"t: kr_a::g (Names) covers no line".to_owned())
        );
        let mut odd = reported(Some(Ok(1)), 1);
        odd.extents
            .get_mut(&("kr_a".to_owned(), "f".to_owned()))
            .expect("extents")
            .insert(("crates/kr-a/src/lib.rs".to_owned(), 0, 4));
        assert_eq!(
            tag_problems("t", &odd, &covered),
            ["t: kr_a::f covers lines 0 to 4 of crates/kr-a/src/lib.rs"]
        );
        // A sighting that only a mark gives covers no line, and needs none.
        let mut marked = Tag {
            commit: "c".to_owned(),
            scan: Some(Ok(1)),
            scans: 1,
            ..Tag::default()
        };
        marked.sightings.insert(
            ("kr_a".to_owned(), "macro:m".to_owned()),
            "Expands".to_owned(),
        );
        assert!(tag_problems("t", &marked, &[]).is_empty());
    }

    #[test]
    fn releases_that_are_not_the_tags_and_a_record_that_differs_are_problems() {
        let listed = parse_listing(
            "packages/v0.1.0+aaaaaaaaaaaa\tc1\t\t1\t\npackages/v0.2.0+bbbbbbbbbbbb\tc2\t\t2\t\n",
        )
        .expect("a listing");
        let good = parse_report(
            "release\tpackages/v0.1.0+aaaaaaaaaaaa\tc1\nrelease\tpackages/v0.2.0+bbbbbbbbbbbb\tc2\n",
        )
        .expect("a report");
        assert!(release_problems(&listed, &good).is_empty());
        let short = parse_report("release\tpackages/v0.1.0+aaaaaaaaaaaa\tc1\n").expect("a report");
        assert_eq!(
            release_problems(&listed, &short),
            ["1 releases reported for 2 tags"]
        );
        let moved = parse_report(
            "release\tpackages/v0.1.0+aaaaaaaaaaaa\tc1\nrelease\tpackages/v0.2.0+bbbbbbbbbbbb\tcx\n",
        )
        .expect("a report");
        assert_eq!(
            release_problems(&listed, &moved),
            [
                "release 1 is packages/v0.2.0+bbbbbbbbbbbb at cx, the tags give packages/v0.2.0+bbbbbbbbbbbb at c2"
            ]
        );
        assert!(record_problems("a\nb\n", "a\nb\n", 10).is_empty());
        assert_eq!(
            record_problems("a\nb\n", "a\nc\n", 10),
            ["the record lacks: c", "the report lacks: b"]
        );
        assert_eq!(record_problems("", "a\nb\nc\n", 1).len(), 2);
    }

    #[test]
    fn the_members_names_and_roots_come_from_the_manifests_and_the_folders() {
        assert_eq!(
            members_of(
                "[workspace]\nresolver = \"3\"\nmembers = [\n  \"crates/kr-a\",\n  \"apps/x/src-tauri\",\n]\n[dependencies]\n"
            ),
            ["crates/kr-a", "apps/x/src-tauri"]
        );
        assert_eq!(
            crate_name("[package]\nname = \"kr-a-b\"\nversion = \"1\"\n"),
            Some("kr_a_b".to_owned())
        );
        let folder = tree(&[
            ("crates/kr-a/src/lib.rs", "\n"),
            ("crates/kr-a/src/main.rs", "\n"),
            ("crates/kr-a/src/bin/one.rs", "\n"),
            ("crates/kr-a/src/bin/two/main.rs", "\n"),
            ("crates/kr-a/src/bin/three/other.rs", "\n"),
        ]);
        assert_eq!(
            roots_of(folder.path(), "crates/kr-a"),
            [
                "crates/kr-a/src/lib.rs",
                "crates/kr-a/src/main.rs",
                "crates/kr-a/src/bin/one.rs",
                "crates/kr-a/src/bin/two/main.rs",
            ]
        );
    }

    #[test]
    fn the_oracle_counts_the_lines_of_each_literal_and_comment_and_reads_a_raw_string_by_its_own_rule()
     {
        // Each form that spans lines is followed by a name on the line after it, and a raw string
        // holds a quote and a backslash that a plain string would end or escape at.
        let lib = concat!(
            "fn a() { r#\"say \"agent.turn.cancel\" \\\"#; }\n",
            "fn b() { ActionRight::r#AgentTurnCancel; }\n",
            "fn c() { \"the method agent.turn.steer is gone\"; }\n",
            "fn d() { r#\"one\n",
            "two\"#; Method::AgentTurnSteer; }\n",
            "fn e() { \"one\n",
            "two\"; Method::AgentTurnSteer; }\n",
            "fn f() { b\"one\n",
            "two\"; Method::AgentTurnSteer; }\n",
            "/* one\n",
            "two */ fn g() { Method::AgentTurnSteer; }\n",
            "fn h() { let _ = '\"'; Method::AgentTurnSteer; }\n",
        );
        let folder = tree(&[("crates/kr-a/src/lib.rs", lib)]);
        let hits = oracle(folder.path()).expect("hits");
        let at = "crates/kr-a/src/lib.rs";
        assert_eq!(
            lines(&hits),
            [1, 3, 5, 7, 9, 11, 12]
                .iter()
                .map(|line| (at.to_owned(), *line))
                .collect::<Vec<_>>()
        );
    }
}
