//! The rule a rendering follows, held over the sources of the two crates that render diagnostics.
//!
//! In this library and in the command line, a failure, a line on standard error and a panic say
//! only a `Shown`: this program's own words, values with nothing in them to hide (`Plain`), and
//! what a reducer or a door decided may be said. The types make that so where they can, and this
//! test reads both crates' sources for the places where a type alone cannot, failing with the
//! file, the line and the item wherever one of these holds:
//!
//! * an error type derives `Debug`, has a `Debug` that is not its `Display`, names a source by
//!   hand, or renders a field (through an `#[error]` hole, `transparent`, or as its source) whose
//!   type is not a `Shown`, an `IoFault`, a type claimed `Plain`, another of these crates' errors,
//!   or one of the six values other crates build and match. Types are compared by their full path,
//!   read through each file's imports, so a type of the same name elsewhere is not the claimed one;
//! * an `#[error]` attribute is anything but `transparent` or one literal, its escapes decoded,
//!   whose holes name the variant's own fields, with no argument after it and no `?` in a hole;
//! * a `Display` is written by hand outside the two files that define what may be shown;
//! * `Plain` is claimed outside those two files;
//! * a `ProtocolError` is built anywhere but the one constructor that takes a `Shown`;
//! * production code logs, writes standard error outside the command line's reporter, formats a
//!   panic, asserts on values, or calls `unwrap` or `expect`, whose panic renders what failed;
//! * the source is one this reading cannot follow: an `Error` derive not spelled
//!   `thiserror::Error`, an import of `thiserror`, a renamed import of a trait or a type the rule
//!   names, a macro that defines a type or writes an `impl`, a module whose file a `#[path]` names,
//!   an `include!`, a `cfg` inside a block, or a field type it cannot place.
//!
//! Test code is not held to the rule: an item whose `cfg` cannot hold without `test`, and every
//! file such an item declares, is passed over. An item that may compile without `test`, such as
//! one under `cfg(any(test, unix))`, is read like any other.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};

/* -------------------------------------------------------------------------------------------- */
/* Reading a source                                                                              */
/* -------------------------------------------------------------------------------------------- */

/// One token of a source, as far as this reading needs to tell them apart.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Token {
    /// An identifier or a keyword, without any `r#`.
    Ident(String),
    /// One punctuation character.
    Punct(char),
    /// A string literal's contents, its escapes decoded.
    Str(String),
    /// A character or byte literal.
    Char,
    /// A number.
    Number,
    /// A lifetime or a label, with its quote.
    Lifetime(String),
}

/// A token and the line it starts on.
#[derive(Clone, Debug)]
struct Located {
    token: Token,
    line: usize,
}

/// Whether `c` can continue an identifier.
fn identifier_character(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Splits a source into tokens, dropping comments and whitespace.
fn lex(text: &str) -> Result<Vec<Located>, String> {
    let chars: Vec<char> = text.chars().collect();
    let mut tokens = Vec::new();
    let mut at = 0;
    let mut line = 1;
    let count_lines = |from: usize, to: usize, chars: &[char]| {
        chars[from..to].iter().filter(|&&c| c == '\n').count()
    };
    while at < chars.len() {
        let c = chars[at];
        if c == '\n' {
            line += 1;
            at += 1;
            continue;
        }
        if c.is_whitespace() {
            at += 1;
            continue;
        }
        if c == '/' && chars.get(at + 1) == Some(&'/') {
            while at < chars.len() && chars[at] != '\n' {
                at += 1;
            }
            continue;
        }
        if c == '/' && chars.get(at + 1) == Some(&'*') {
            let start = at;
            let mut depth = 0;
            loop {
                if at + 1 >= chars.len() {
                    return Err(format!("line {line}: a block comment does not end"));
                }
                if chars[at] == '/' && chars[at + 1] == '*' {
                    depth += 1;
                    at += 2;
                } else if chars[at] == '*' && chars[at + 1] == '/' {
                    depth -= 1;
                    at += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    at += 1;
                }
            }
            line += count_lines(start, at, &chars);
            continue;
        }
        if c.is_alphabetic() || c == '_' {
            let start = at;
            while at < chars.len() && identifier_character(chars[at]) {
                at += 1;
            }
            let word: String = chars[start..at].iter().collect();
            let next = chars.get(at).copied();
            // A raw identifier.
            if word == "r"
                && next == Some('#')
                && chars
                    .get(at + 1)
                    .is_some_and(|c| c.is_alphabetic() || *c == '_')
            {
                at += 1;
                let start = at;
                while at < chars.len() && identifier_character(chars[at]) {
                    at += 1;
                }
                tokens.push(Located {
                    token: Token::Ident(chars[start..at].iter().collect()),
                    line,
                });
                continue;
            }
            // A prefixed literal: a raw, byte or C string, or a byte character.
            let raw = matches!(word.as_str(), "r" | "br" | "cr");
            if matches!(word.as_str(), "b" | "c") && next == Some('"')
                || raw && matches!(next, Some('"' | '#'))
            {
                let (contents, end) = if raw {
                    raw_string(&chars, at)
                        .ok_or_else(|| format!("line {line}: a raw string does not end"))?
                } else {
                    string(&chars, at)
                        .ok_or_else(|| format!("line {line}: a string does not end"))?
                };
                let start_line = line;
                line += count_lines(at, end, &chars);
                at = end;
                tokens.push(Located {
                    token: Token::Str(contents),
                    line: start_line,
                });
                continue;
            }
            if word == "b" && next == Some('\'') {
                at = character(&chars, at)
                    .ok_or_else(|| format!("line {line}: a byte literal does not end"))?;
                tokens.push(Located {
                    token: Token::Char,
                    line,
                });
                continue;
            }
            tokens.push(Located {
                token: Token::Ident(word),
                line,
            });
            continue;
        }
        if c.is_ascii_digit() {
            while at < chars.len() && identifier_character(chars[at]) {
                at += 1;
            }
            // A fraction, but not a range.
            if chars.get(at) == Some(&'.') && chars.get(at + 1).is_some_and(char::is_ascii_digit) {
                at += 1;
                while at < chars.len() && identifier_character(chars[at]) {
                    at += 1;
                }
            }
            tokens.push(Located {
                token: Token::Number,
                line,
            });
            continue;
        }
        if c == '"' {
            let (contents, end) =
                string(&chars, at).ok_or_else(|| format!("line {line}: a string does not end"))?;
            let start_line = line;
            line += count_lines(at, end, &chars);
            at = end;
            tokens.push(Located {
                token: Token::Str(contents),
                line: start_line,
            });
            continue;
        }
        if c == '\'' {
            // A character literal is a quote, one character or an escape, and a quote; anything
            // else starting with a quote is a lifetime or a label.
            let escaped = chars.get(at + 1) == Some(&'\\');
            let closed = chars.get(at + 2) == Some(&'\'');
            if escaped || closed {
                at = character(&chars, at)
                    .ok_or_else(|| format!("line {line}: a character literal does not end"))?;
                tokens.push(Located {
                    token: Token::Char,
                    line,
                });
            } else {
                let start = at;
                at += 1;
                while at < chars.len() && identifier_character(chars[at]) {
                    at += 1;
                }
                tokens.push(Located {
                    token: Token::Lifetime(chars[start..at].iter().collect()),
                    line,
                });
            }
            continue;
        }
        tokens.push(Located {
            token: Token::Punct(c),
            line,
        });
        at += 1;
    }
    Ok(tokens)
}

/// Reads a string that opens at `at`, returning its contents with the escapes decoded and the index
/// after it.
fn string(chars: &[char], at: usize) -> Option<(String, usize)> {
    let mut index = at + 1;
    let mut contents = String::new();
    while index < chars.len() {
        match chars[index] {
            '\\' => {
                let escaped = *chars.get(index + 1)?;
                index += 2;
                match escaped {
                    'n' => contents.push('\n'),
                    'r' => contents.push('\r'),
                    't' => contents.push('\t'),
                    '0' => contents.push('\0'),
                    '\\' | '"' | '\'' => contents.push(escaped),
                    'x' => {
                        let digits: String = chars.get(index..index + 2)?.iter().collect();
                        contents.push(char::from(u8::from_str_radix(&digits, 16).ok()?));
                        index += 2;
                    }
                    'u' => {
                        if chars.get(index) != Some(&'{') {
                            return None;
                        }
                        let close = (index..chars.len()).find(|&at| chars[at] == '}')?;
                        let digits: String = chars[index + 1..close]
                            .iter()
                            .filter(|c| **c != '_')
                            .collect();
                        contents.push(char::from_u32(u32::from_str_radix(&digits, 16).ok()?)?);
                        index = close + 1;
                    }
                    // A line continuation: the line break and the whitespace after it are not in
                    // the string.
                    '\n' | '\r' => {
                        while chars.get(index).is_some_and(|c| c.is_whitespace()) {
                            index += 1;
                        }
                    }
                    _ => return None,
                }
            }
            '"' => return Some((contents, index + 1)),
            other => {
                contents.push(other);
                index += 1;
            }
        }
    }
    None
}

/// Reads a raw string whose hashes start at `at`.
fn raw_string(chars: &[char], at: usize) -> Option<(String, usize)> {
    let mut index = at;
    let mut hashes = 0;
    while chars.get(index) == Some(&'#') {
        hashes += 1;
        index += 1;
    }
    if chars.get(index) != Some(&'"') {
        return None;
    }
    index += 1;
    let start = index;
    while index < chars.len() {
        if chars[index] == '"' && (1..=hashes).all(|offset| chars.get(index + offset) == Some(&'#'))
        {
            return Some((chars[start..index].iter().collect(), index + 1 + hashes));
        }
        index += 1;
    }
    None
}

/// Reads a character literal that opens at `at`, returning the index after it.
fn character(chars: &[char], at: usize) -> Option<usize> {
    let mut index = at + 1;
    while index < chars.len() {
        match chars[index] {
            '\\' => index += 2,
            '\'' => return Some(index + 1),
            '\n' => return None,
            _ => index += 1,
        }
    }
    None
}

fn ident(located: Option<&Located>) -> Option<&str> {
    match located.map(|located| &located.token) {
        Some(Token::Ident(word)) => Some(word),
        _ => None,
    }
}

fn punct(located: Option<&Located>, wanted: char) -> bool {
    matches!(located.map(|located| &located.token), Some(Token::Punct(c)) if *c == wanted)
}

/// Returns the index of the token that closes the group opening at `open`.
fn closing(tokens: &[Located], open: usize) -> Option<usize> {
    let mut depth = 0_i64;
    for (index, located) in tokens.iter().enumerate().skip(open) {
        match located.token {
            Token::Punct('{' | '(' | '[') => depth += 1,
            Token::Punct('}' | ')' | ']') => {
                depth -= 1;
                if depth == 0 {
                    return Some(index);
                }
            }
            _ => {}
        }
    }
    None
}

/// Splits the tokens between `open` and its closing token at the commas outside any group or
/// angle brackets.
fn arguments(tokens: &[Located], open: usize) -> Option<Vec<Vec<Located>>> {
    let close = closing(tokens, open)?;
    Some(split_commas(&tokens[open + 1..close]))
}

/// Splits `tokens` at the commas outside any group or angle brackets.
fn split_commas(tokens: &[Located]) -> Vec<Vec<Located>> {
    let mut parts = vec![Vec::new()];
    let mut depth = 0_i64;
    let mut angle = 0_i64;
    for located in tokens {
        match located.token {
            Token::Punct('{' | '(' | '[') => depth += 1,
            Token::Punct('}' | ')' | ']') => depth -= 1,
            Token::Punct('<') => angle += 1,
            Token::Punct('>') => angle = (angle - 1).max(0),
            Token::Punct(',') if depth == 0 && angle == 0 => {
                parts.push(Vec::new());
                continue;
            }
            _ => {}
        }
        if let Some(last) = parts.last_mut() {
            last.push(located.clone());
        }
    }
    if parts.last().is_some_and(Vec::is_empty) {
        parts.pop();
    }
    parts
}

/* -------------------------------------------------------------------------------------------- */
/* What compiles without `test`                                                                  */
/* -------------------------------------------------------------------------------------------- */

/// A `cfg` predicate's value when the code is compiled without `test`, with every other condition
/// unknown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Truth {
    True,
    False,
    Unknown,
}

/// Evaluates the predicate that starts at `at`, moving `at` past it.
fn without_test(tokens: &[Located], at: &mut usize) -> Truth {
    let Some(name) = ident(tokens.get(*at)).map(ToOwned::to_owned) else {
        *at += 1;
        return Truth::Unknown;
    };
    *at += 1;
    if punct(tokens.get(*at), '(') && matches!(name.as_str(), "all" | "any" | "not") {
        let close = closing(tokens, *at).unwrap_or(tokens.len());
        let mut values = Vec::new();
        let mut inner = *at + 1;
        while inner < close {
            values.push(without_test(tokens, &mut inner));
            if punct(tokens.get(inner), ',') {
                inner += 1;
            }
        }
        *at = close + 1;
        return match name.as_str() {
            "all" if values.contains(&Truth::False) => Truth::False,
            "all" if values.iter().all(|value| *value == Truth::True) => Truth::True,
            "any" if values.contains(&Truth::True) => Truth::True,
            "any" if values.iter().all(|value| *value == Truth::False) => Truth::False,
            "not" => match values.as_slice() {
                [Truth::True] => Truth::False,
                [Truth::False] => Truth::True,
                _ => Truth::Unknown,
            },
            _ => Truth::Unknown,
        };
    }
    if punct(tokens.get(*at), '=') {
        *at += 2;
        return Truth::Unknown;
    }
    if name == "test" {
        Truth::False
    } else {
        Truth::Unknown
    }
}

/// The attribute whose `[` is at `open`, read as `cfg`: `None` when it is not a `cfg`, and whether
/// the item it is on can compile without `test` otherwise.
fn cfg_compiles_without_test(tokens: &[Located], open: usize) -> Option<bool> {
    if ident(tokens.get(open + 1)) != Some("cfg") || !punct(tokens.get(open + 2), '(') {
        return None;
    }
    let mut at = open + 3;
    Some(without_test(tokens, &mut at) != Truth::False)
}

/// Returns the index just past the attribute that opens at `start` (`#` or `#!`).
fn attribute_end(tokens: &[Located], start: usize) -> Option<usize> {
    let mut index = start + 1;
    if punct(tokens.get(index), '!') {
        index += 1;
    }
    if !punct(tokens.get(index), '[') {
        return None;
    }
    closing(tokens, index).map(|close| close + 1)
}

/// Returns the index just past the item, statement, field or variant that starts at `start`.
fn item_end(tokens: &[Located], start: usize) -> usize {
    let keyword = matches!(
        ident(tokens.get(start)),
        Some(
            "fn" | "mod"
                | "impl"
                | "struct"
                | "enum"
                | "use"
                | "const"
                | "static"
                | "type"
                | "trait"
                | "pub"
                | "unsafe"
                | "async"
                | "extern"
                | "macro_rules"
                | "let"
        )
    );
    let mut depth = 0_i64;
    let mut index = start;
    while index < tokens.len() {
        match tokens[index].token {
            Token::Punct('{' | '(' | '[') => depth += 1,
            Token::Punct('}' | ')' | ']') => {
                depth -= 1;
                if depth == 0 && punct(tokens.get(index), '}') {
                    // A block closes the item unless an expression goes on after it, which a
                    // statement ends with a semicolon.
                    let next = tokens.get(index + 1);
                    let goes_on = punct(next, ';')
                        || punct(next, '.')
                        || punct(next, '?')
                        || ident(next) == Some("else");
                    if !goes_on {
                        return index + 1;
                    }
                }
                if depth < 0 {
                    return index;
                }
            }
            Token::Punct(';') if depth == 0 => return index + 1,
            Token::Punct(',') if depth == 0 && !keyword => return index + 1,
            _ => {}
        }
        index += 1;
    }
    tokens.len()
}

/// The module that the item starting at `at` declares in a file of its own, if it is one.
fn declared_module(tokens: &[Located], at: usize) -> Option<String> {
    let mut index = skip_visibility(tokens, at);
    if ident(tokens.get(index)) != Some("mod") {
        return None;
    }
    index += 1;
    if !punct(tokens.get(index + 1), ';') {
        return None;
    }
    ident(tokens.get(index)).map(ToOwned::to_owned)
}

/// The index past a `pub` or `pub(...)` at `at`, or `at`.
fn skip_visibility(tokens: &[Located], at: usize) -> usize {
    if ident(tokens.get(at)) != Some("pub") {
        return at;
    }
    if punct(tokens.get(at + 1), '(') {
        return closing(tokens, at + 1).map_or(at + 1, |close| close + 1);
    }
    at + 1
}

/* -------------------------------------------------------------------------------------------- */
/* Production code and its names                                                                 */
/* -------------------------------------------------------------------------------------------- */

/// A place the rule is not held, with what is wrong there.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Finding {
    file: String,
    line: usize,
    item: String,
    what: String,
}

impl fmt::Display for Finding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}:{}: {}: {}",
            self.file, self.line, self.item, self.what
        )
    }
}

/// One name a file imports.
#[derive(Clone, Debug)]
struct Import {
    /// The name it is known by in the file.
    local: String,
    /// The full path it names.
    path: Vec<String>,
}

/// One source file, as the rule reads it.
struct Source {
    /// The path from the workspace root, which is how a finding names it.
    name: String,
    /// The crate it belongs to, as code names that crate.
    crate_name: String,
    /// Its module's full path, starting with the crate.
    module: Vec<String>,
    /// Its production tokens: everything that can compile without `test`.
    tokens: Vec<Located>,
    /// The modules it declares in files of their own, and whether each is test code.
    children: Vec<(String, bool)>,
    /// The modules it declares inline.
    inline_modules: BTreeSet<String>,
    /// The names it imports.
    imports: Vec<Import>,
    /// Whether it imports everything from somewhere, which leaves a bare name unplaceable.
    globs: bool,
    /// The types, traits and aliases it defines.
    definitions: BTreeSet<String>,
    /// What this reading cannot follow in it.
    problems: Vec<Finding>,
}

/// The primitive types, which every file names without importing them.
const PRIMITIVES: [&str; 17] = [
    "u8", "u16", "u32", "u64", "u128", "usize", "i8", "i16", "i32", "i64", "i128", "isize", "bool",
    "char", "str", "f32", "f64",
];

/// Names a renamed import would hide from this reading.
const RENAME_GUARDED: [&str; 11] = [
    "Display",
    "Debug",
    "Error",
    "Plain",
    "Said",
    "Shown",
    "IoFault",
    "fmt",
    "error",
    "thiserror",
    "Write",
];

impl Source {
    fn problem(&mut self, line: usize, item: &str, what: &str) {
        self.problems.push(Finding {
            file: self.name.clone(),
            line,
            item: item.to_owned(),
            what: what.to_owned(),
        });
    }

    /// The full path of `segments` as a path written in this file, first segment resolved through
    /// its imports, its modules and its definitions; `None` when this reading cannot place it.
    fn resolve(&self, segments: &[String], aliases: &BTreeMap<String, String>) -> Option<String> {
        let (first, rest) = segments.split_first()?;
        let path: Vec<String> = match first.as_str() {
            "crate" => std::iter::once(self.crate_name.clone())
                .chain(rest.iter().cloned())
                .collect(),
            "self" => self.module.iter().chain(rest).cloned().collect(),
            "super" => {
                let supers = segments
                    .iter()
                    .take_while(|segment| *segment == "super")
                    .count();
                let keep = self.module.len().checked_sub(supers)?;
                if keep == 0 {
                    return None;
                }
                self.module[..keep]
                    .iter()
                    .chain(&segments[supers..])
                    .cloned()
                    .collect()
            }
            "Self" => return None,
            _ if rest.is_empty() && PRIMITIVES.contains(&first.as_str()) => {
                vec!["prim".to_owned(), first.clone()]
            }
            _ => {
                let imported: BTreeSet<&Vec<String>> = self
                    .imports
                    .iter()
                    .filter(|import| import.local == *first)
                    .map(|import| &import.path)
                    .collect();
                if imported.len() > 1 {
                    return None;
                }
                if let Some(path) = imported.into_iter().next() {
                    path.iter().chain(rest).cloned().collect()
                } else if self.children.iter().any(|(child, _)| child == first)
                    || self.inline_modules.contains(first)
                    || rest.is_empty() && self.definitions.contains(first)
                {
                    self.module.iter().chain(segments).cloned().collect()
                } else if rest.is_empty() {
                    // A bare name neither imported nor defined here: a glob's or the prelude's,
                    // which this reading does not place.
                    return None;
                } else {
                    segments.to_vec()
                }
            }
        };
        let joined = path.join("::");
        Some(aliases.get(&joined).cloned().unwrap_or(joined))
    }

    /// The full path an import names, read from where the import is written.
    fn import_path(&self, segments: &[String]) -> Vec<String> {
        match segments.first().map(String::as_str) {
            Some("crate") => std::iter::once(self.crate_name.clone())
                .chain(segments[1..].iter().cloned())
                .collect(),
            Some("self") => self.module.iter().chain(&segments[1..]).cloned().collect(),
            Some("super") => {
                let supers = segments
                    .iter()
                    .take_while(|segment| *segment == "super")
                    .count();
                let keep = self.module.len().saturating_sub(supers).max(1);
                self.module[..keep]
                    .iter()
                    .chain(&segments[supers..])
                    .cloned()
                    .collect()
            }
            Some(first)
                if self.children.iter().any(|(child, _)| child == first)
                    || self.inline_modules.contains(first) =>
            {
                self.module.iter().chain(segments).cloned().collect()
            }
            _ => segments.to_vec(),
        }
    }
}

/// Reads the import tree in `tokens` under `prefix`.
fn use_tree(
    tokens: &[Located],
    prefix: &[String],
    line: usize,
    source: &mut Source,
    found: &mut Vec<(Vec<String>, Option<String>)>,
) {
    let mut segments = prefix.to_vec();
    let mut index = 0;
    if punct(tokens.first(), ':') {
        index += 2;
    }
    loop {
        match tokens.get(index).map(|located| &located.token) {
            Some(Token::Ident(word)) if word != "as" => {
                segments.push(word.clone());
                index += 1;
                if punct(tokens.get(index), ':') && punct(tokens.get(index + 1), ':') {
                    index += 2;
                    continue;
                }
                break;
            }
            Some(Token::Punct('{')) => {
                let close = closing(tokens, index).unwrap_or(tokens.len());
                for part in split_commas(&tokens[index + 1..close.min(tokens.len())]) {
                    use_tree(&part, &segments, line, source, found);
                }
                return;
            }
            Some(Token::Punct('*')) => {
                source.globs = true;
                return;
            }
            _ => break,
        }
    }
    let renamed = if ident(tokens.get(index)) == Some("as") {
        ident(tokens.get(index + 1)).map(ToOwned::to_owned)
    } else {
        None
    };
    if let Some(renamed) = &renamed
        && renamed != "_"
        && segments
            .last()
            .is_some_and(|last| RENAME_GUARDED.contains(&last.as_str()))
    {
        source.problem(
            line,
            &format!("use {} as {renamed}", segments.join("::")),
            "a renamed import this reading cannot follow",
        );
    }
    found.push((segments, renamed));
}

/// Reads one file into its production tokens, its imports, its definitions and the modules it
/// declares.
fn read_source(
    root: &Path,
    path: &Path,
    test: bool,
    crate_name: &str,
    module: Vec<String>,
) -> Result<Source, String> {
    let name = path
        .strip_prefix(root)
        .unwrap_or(path)
        .display()
        .to_string();
    let text = std::fs::read_to_string(path).map_err(|error| format!("{name}: {error}"))?;
    let all = lex(&text).map_err(|error| format!("{name}: {error}"))?;
    let mut source = Source {
        name,
        crate_name: crate_name.to_owned(),
        module,
        tokens: Vec::new(),
        children: Vec::new(),
        inline_modules: BTreeSet::new(),
        imports: Vec::new(),
        globs: false,
        definitions: BTreeSet::new(),
        problems: Vec::new(),
    };
    let mut file_test = test;
    // The attributes of the item about to start, and whether one of them makes it test code.
    let mut attributes: Vec<Located> = Vec::new();
    let mut attributes_test = false;
    let mut depth = 0_i64;
    let mut index = 0;
    while index < all.len() {
        if punct(all.get(index), '#')
            && let Some(end) = attribute_end(&all, index)
        {
            let inner = punct(all.get(index + 1), '!');
            let open = index + 1 + usize::from(inner);
            let compiles = cfg_compiles_without_test(&all, open);
            if ident(all.get(open + 1)) == Some("path") {
                source.problem(
                    all[index].line,
                    "#[path]",
                    "a module file this reading cannot follow",
                );
            }
            if inner {
                if depth > 0 && compiles.is_some() {
                    source.problem(
                        all[index].line,
                        "#![cfg]",
                        "an inner cfg inside a block, which this reading cannot follow",
                    );
                }
                if depth == 0 {
                    file_test |= compiles == Some(false);
                }
                if !file_test {
                    source.tokens.extend_from_slice(&all[index..end]);
                }
            } else {
                attributes_test |= compiles == Some(false);
                attributes.extend_from_slice(&all[index..end]);
            }
            index = end;
            continue;
        }
        let skipped = attributes_test && !file_test;
        let module = if skipped || ident(all.get(index)) == Some("mod") {
            declared_module(&all, index)
        } else {
            None
        };
        if let Some(module) = module {
            source.children.push((module, attributes_test || file_test));
        }
        if skipped {
            attributes.clear();
            attributes_test = false;
            index = item_end(&all, index);
            continue;
        }
        match all[index].token {
            Token::Punct('{') => depth += 1,
            Token::Punct('}') => depth -= 1,
            _ => {}
        }
        if !file_test {
            source.tokens.append(&mut attributes);
            source.tokens.push(all[index].clone());
        }
        attributes.clear();
        attributes_test = false;
        index += 1;
    }
    if !file_test {
        source.tokens.append(&mut attributes);
    }
    // What the production tokens define and import.
    let tokens = std::mem::take(&mut source.tokens);
    let mut found = Vec::new();
    for (at, located) in tokens.iter().enumerate() {
        match ident(Some(located)) {
            Some("struct" | "enum" | "union" | "trait" | "type") => {
                if let Some(defined) = ident(tokens.get(at + 1)) {
                    source.definitions.insert(defined.to_owned());
                }
            }
            Some("mod") if punct(tokens.get(at + 2), '{') => {
                if let Some(inline) = ident(tokens.get(at + 1)) {
                    source.inline_modules.insert(inline.to_owned());
                }
            }
            Some("use") => {
                let end = (at..tokens.len())
                    .find(|&end| punct(tokens.get(end), ';'))
                    .unwrap_or(tokens.len());
                use_tree(
                    &tokens[at + 1..end],
                    &[],
                    located.line,
                    &mut source,
                    &mut found,
                );
            }
            _ => {}
        }
    }
    source.tokens = tokens;
    for (segments, renamed) in found {
        let path = source.import_path(&segments);
        let local = match renamed {
            Some(renamed) => renamed,
            None if segments.last().is_some_and(|last| last == "self") => {
                segments.iter().rev().nth(1).cloned().unwrap_or_default()
            }
            None => segments.last().cloned().unwrap_or_default(),
        };
        let path = if path.last().is_some_and(|last| last == "self") {
            path[..path.len() - 1].to_vec()
        } else {
            path
        };
        if local != "_" {
            source.imports.push(Import { local, path });
        }
    }
    Ok(source)
}

/// Every production file of the crate named `crate_name` whose root is `crate_root`, following its
/// module tree.
fn crate_sources(
    workspace: &Path,
    crate_root: &Path,
    crate_name: &str,
) -> Result<Vec<Source>, String> {
    let mut sources = Vec::new();
    let mut pending = vec![(
        crate_root.to_path_buf(),
        false,
        true,
        vec![crate_name.to_owned()],
    )];
    while let Some((path, test, root_like, module)) = pending.pop() {
        let source = read_source(workspace, &path, test, crate_name, module.clone())?;
        let directory = if root_like {
            path.parent().map(Path::to_path_buf).unwrap_or_default()
        } else {
            path.with_extension("")
        };
        for (child, child_test) in &source.children {
            let flat = directory.join(format!("{child}.rs"));
            let nested = directory.join(child).join("mod.rs");
            let found = if flat.exists() {
                (flat, false)
            } else if nested.exists() {
                (nested, true)
            } else {
                return Err(format!("{}: module {child} has no file", source.name));
            };
            let mut child_module = module.clone();
            child_module.push(child.clone());
            pending.push((found.0, *child_test || test, found.1, child_module));
        }
        if !test {
            sources.push(source);
        }
    }
    Ok(sources)
}

/* -------------------------------------------------------------------------------------------- */
/* The rule                                                                                      */
/* -------------------------------------------------------------------------------------------- */

/// The two files that define what may be shown.
const SHOWN_FILES: [&str; 2] = [
    "crates/kr-client/src/shown.rs",
    "crates/kr-cli/src/shown.rs",
];

/// The one constructor of a protocol error from text.
const REFUSAL_FILE: &str = "crates/kr-client/src/error.rs";

/// The command line's reporter, the one writer of standard error.
const REPORTER_FILE: &str = "crates/kr-cli/src/report.rs";

/// What every rendering may hold, by full path.
const SHOWN: &str = "kr_client::shown::Shown";
const IO_FAULT: &str = "kr_client::shown::IoFault";

/// The values other crates build and match, which an error holds whole and renders through a door
/// or a reducer: the error type, its variant and the field type's name.
const RAW: [(&str, &str, &str); 6] = [
    ("kr_client::error::ClientError", "Host", "ProtocolError"),
    ("kr_client::error::ClientError", "Refused", "ProtocolError"),
    (
        "kr_client::error::ClientError",
        "Transport",
        "TransportError",
    ),
    ("kr_client::error::ClientError", "Ipc", "IpcError"),
    ("kr_cli::error::CliError", "Refused", "ProtocolError"),
    ("kr_cli::error::CliError", "Ipc", "IpcError"),
];

/// Wrappers a field type may have around the value it holds.
const WRAPPERS: [&str; 4] = ["Box", "Option", "Vec", "Arc"];

/// The holes of a format string, each as the text between its braces.
fn holes(literal: &str) -> Vec<String> {
    let mut found = Vec::new();
    let chars: Vec<char> = literal.chars().collect();
    let mut index = 0;
    while index < chars.len() {
        match chars[index] {
            '{' if chars.get(index + 1) == Some(&'{') => index += 2,
            '}' if chars.get(index + 1) == Some(&'}') => index += 2,
            '{' => {
                let start = index + 1;
                while index < chars.len() && chars[index] != '}' {
                    index += 1;
                }
                found.push(chars[start..index.min(chars.len())].iter().collect());
                index += 1;
            }
            _ => index += 1,
        }
    }
    found
}

/// Whether one argument is a single string literal with no holes.
fn plain_literal(argument: &[Located]) -> bool {
    matches!(argument, [Located { token: Token::Str(text), .. }] if holes(text).is_empty())
}

/// The last path segment of the type that starts at `start`, skipping `&`, `dyn`, `mut` and
/// lifetimes, with generic arguments dropped.
fn named_type(tokens: &[Located], mut start: usize) -> Option<(String, usize)> {
    while punct(tokens.get(start), '&')
        || matches!(
            tokens.get(start).map(|located| &located.token),
            Some(Token::Lifetime(_))
        )
        || matches!(ident(tokens.get(start)), Some("dyn" | "mut"))
    {
        start += 1;
    }
    let mut last = None;
    let mut index = start;
    while let Some(located) = tokens.get(index) {
        match &located.token {
            Token::Ident(word) => {
                last = Some(word.clone());
                index += 1;
            }
            Token::Punct(':') if punct(tokens.get(index + 1), ':') => index += 2,
            _ => break,
        }
    }
    Some((last?, index))
}

/// The path written at the start of `tokens`, and the index after it.
fn written_path(tokens: &[Located]) -> (Vec<String>, usize) {
    let mut segments = Vec::new();
    let mut index = 0;
    if punct(tokens.first(), ':') && punct(tokens.get(1), ':') {
        index = 2;
    }
    while let Some(word) = ident(tokens.get(index)) {
        segments.push(word.to_owned());
        index += 1;
        if punct(tokens.get(index), ':') && punct(tokens.get(index + 1), ':') {
            index += 2;
        } else {
            break;
        }
    }
    (segments, index)
}

/// The types a type written in `source` holds, each by its full path: the type itself, or what a
/// `Box`, an `Option`, a `Vec` or an `Arc` holds. A reference keeps its lifetime. `None` stands for
/// a type this reading cannot place.
fn held(
    source: &Source,
    tokens: &[Located],
    aliases: &BTreeMap<String, String>,
) -> Vec<Option<String>> {
    if punct(tokens.first(), '&') {
        let mut index = 1;
        let lifetime = match tokens.get(index).map(|located| &located.token) {
            Some(Token::Lifetime(lifetime)) => {
                index += 1;
                lifetime.clone()
            }
            _ => String::new(),
        };
        if ident(tokens.get(index)) == Some("mut") {
            index += 1;
        }
        return held(source, &tokens[index..], aliases)
            .into_iter()
            .map(|inner| inner.map(|inner| format!("&{lifetime} {inner}")))
            .collect();
    }
    let (segments, after) = written_path(tokens);
    if segments.is_empty() {
        return vec![None];
    }
    if after == tokens.len() {
        return vec![source.resolve(&segments, aliases)];
    }
    if !punct(tokens.get(after), '<') || !punct(tokens.last(), '>') {
        return vec![None];
    }
    let generics = split_commas(&tokens[after + 1..tokens.len() - 1]);
    let wrapper = segments
        .last()
        .is_some_and(|last| WRAPPERS.contains(&last.as_str()));
    if wrapper {
        return generics
            .iter()
            .flat_map(|argument| held(source, argument, aliases))
            .collect();
    }
    vec![
        source
            .resolve(&segments, aliases)
            .map(|path| format!("{path}<..>")),
    ]
}

/// What the rule knows before it reads an item: which types are `Plain`, which are errors, how each
/// error renders. Every type is named by its full path.
#[derive(Default)]
struct Known {
    plain: BTreeSet<String>,
    /// Each error type, with the file it is declared in.
    errors: BTreeMap<String, String>,
    /// The error types `thiserror` renders.
    thiserror: BTreeSet<String>,
    debug_as_display: BTreeSet<String>,
}

/// The re-exports of each crate's root, as full paths to what they name.
fn aliases(sources: &[Source]) -> BTreeMap<String, String> {
    let mut aliases = BTreeMap::new();
    for source in sources.iter().filter(|source| source.module.len() == 1) {
        for import in &source.imports {
            aliases.insert(
                format!("{}::{}", source.crate_name, import.local),
                import.path.join("::"),
            );
        }
    }
    aliases
}

fn collect_known(sources: &[Source], aliases: &BTreeMap<String, String>) -> Known {
    let mut known = Known::default();
    for source in sources {
        let tokens = &source.tokens;
        let shown_file = SHOWN_FILES.contains(&source.name.as_str());
        for (index, located) in tokens.iter().enumerate() {
            let Token::Ident(word) = &located.token else {
                continue;
            };
            match word.as_str() {
                // `impl Plain for T`, claimed only in the two files that define what may be shown.
                "Plain" if shown_file && ident(tokens.get(index + 1)) == Some("for") => {
                    let end = (index + 2..tokens.len())
                        .find(|&end| punct(tokens.get(end), '{'))
                        .unwrap_or(tokens.len());
                    known.plain.extend(
                        held(source, &tokens[index + 2..end], aliases)
                            .into_iter()
                            .flatten(),
                    );
                }
                "plain" | "debug_as_display"
                    if punct(tokens.get(index + 1), '!') && punct(tokens.get(index + 2), '(') =>
                {
                    if word == "plain" && !shown_file {
                        continue;
                    }
                    for argument in arguments(tokens, index + 2).unwrap_or_default() {
                        let paths = held(source, &argument, aliases).into_iter().flatten();
                        if word == "plain" {
                            known.plain.extend(paths);
                        } else {
                            known.debug_as_display.extend(paths);
                        }
                    }
                }
                // `impl std::error::Error for T` and `#[derive(thiserror::Error)] enum T`.
                "Error"
                    if ident(tokens.get(index + 1)) == Some("for") && impl_of(tokens, index) =>
                {
                    let end = (index + 2..tokens.len())
                        .find(|&end| punct(tokens.get(end), '{') || punct(tokens.get(end), ';'))
                        .unwrap_or(tokens.len());
                    for path in held(source, &tokens[index + 2..end], aliases)
                        .into_iter()
                        .flatten()
                    {
                        known
                            .errors
                            .entry(path)
                            .or_insert_with(|| source.name.clone());
                    }
                }
                "derive" if punct(tokens.get(index + 1), '(') => {
                    let derives = derive_names(tokens, index + 1);
                    if derives.iter().any(|name| name == "thiserror::Error")
                        && let Some(name) = defined_after(tokens, index)
                    {
                        let path = format!("{}::{name}", source.module.join("::"));
                        known.errors.insert(path.clone(), source.name.clone());
                        known.thiserror.insert(path);
                    }
                }
                _ => {}
            }
        }
    }
    known
}

/// Whether the trait path ending at `at` follows an `impl`, with any generics between.
fn impl_of(tokens: &[Located], at: usize) -> bool {
    let mut index = at;
    // Back over the path.
    while index >= 2 && punct(tokens.get(index - 1), ':') && punct(tokens.get(index - 2), ':') {
        index = index.saturating_sub(3);
    }
    let mut back = index;
    // Back over `impl<...>`.
    if back > 0 && punct(tokens.get(back - 1), '>') {
        let mut depth = 0;
        while back > 0 {
            back -= 1;
            match tokens[back].token {
                Token::Punct('>') => depth += 1,
                Token::Punct('<') => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                _ => {}
            }
        }
    }
    back > 0 && ident(tokens.get(back - 1)) == Some("impl")
}

/// The paths a `derive(...)` whose parenthesis opens at `open` names, each spelled as written.
fn derive_names(tokens: &[Located], open: usize) -> Vec<String> {
    arguments(tokens, open)
        .unwrap_or_default()
        .iter()
        .map(|argument| {
            argument
                .iter()
                .map(|located| match &located.token {
                    Token::Ident(word) => word.clone(),
                    Token::Punct(c) => c.to_string(),
                    _ => "?".to_owned(),
                })
                .collect::<String>()
        })
        .collect()
}

/// The name of the struct or enum the attributes around `at` belong to.
fn defined_after(tokens: &[Located], at: usize) -> Option<String> {
    let mut index = at;
    while index < tokens.len() {
        match ident(tokens.get(index)) {
            Some("struct" | "enum" | "union") => {
                return ident(tokens.get(index + 1)).map(ToOwned::to_owned);
            }
            Some("fn" | "impl" | "mod" | "trait" | "type" | "use" | "const" | "static") => {
                return None;
            }
            _ => index += 1,
        }
    }
    None
}

/// Reads the rule over every production file.
fn check(sources: &[Source]) -> Vec<Finding> {
    let aliases = aliases(sources);
    let known = collect_known(sources, &aliases);
    let mut findings = BTreeSet::new();
    for source in sources {
        findings.extend(source.problems.iter().cloned());
        check_source(source, &known, &aliases, &mut findings);
    }
    for (error, file) in &known.errors {
        // The two files that define what may be shown write their own types' renderings.
        if !known.debug_as_display.contains(error) && !SHOWN_FILES.contains(&file.as_str()) {
            findings.insert(Finding {
                file: file.clone(),
                line: 0,
                item: error.clone(),
                what: "an error type whose Debug is not its Display (debug_as_display!)".to_owned(),
            });
        }
    }
    findings.into_iter().collect()
}

fn check_source(
    source: &Source,
    known: &Known,
    aliases: &BTreeMap<String, String>,
    findings: &mut BTreeSet<Finding>,
) {
    let tokens = &source.tokens;
    let shown_file = SHOWN_FILES.contains(&source.name.as_str());
    let mut find = |line: usize, item: &str, what: &str| {
        findings.insert(Finding {
            file: source.name.clone(),
            line,
            item: item.to_owned(),
            what: what.to_owned(),
        });
    };
    for (index, located) in tokens.iter().enumerate() {
        let line = located.line;
        let Token::Ident(word) = &located.token else {
            continue;
        };
        let next_is_bang = punct(tokens.get(index + 1), '!');
        let after_dot = index > 0 && punct(tokens.get(index - 1), '.');
        match word.as_str() {
            "Plain" if ident(tokens.get(index + 1)) == Some("for") && !shown_file => {
                find(
                    line,
                    "impl Plain",
                    "Plain is claimed outside the two files that define it",
                );
            }
            "plain" if next_is_bang && !shown_file => {
                find(
                    line,
                    "plain!",
                    "Plain is claimed outside the two files that define it",
                );
            }
            "Display"
                if ident(tokens.get(index + 1)) == Some("for")
                    && impl_of(tokens, index)
                    && !shown_file =>
            {
                let item =
                    named_type(tokens, index + 2).map_or_else(|| "?".to_owned(), |(name, _)| name);
                find(line, &item, "a Display written by hand");
            }
            "Debug"
                if ident(tokens.get(index + 1)) == Some("for")
                    && impl_of(tokens, index)
                    && !shown_file =>
            {
                let end = (index + 2..tokens.len())
                    .find(|&end| punct(tokens.get(end), '{'))
                    .unwrap_or(tokens.len());
                for path in held(source, &tokens[index + 2..end], aliases)
                    .into_iter()
                    .flatten()
                {
                    if known.errors.contains_key(&path) {
                        find(line, &path, "an error type with a Debug written by hand");
                    }
                }
            }
            "Error" if ident(tokens.get(index + 1)) == Some("for") && impl_of(tokens, index) => {
                // A hand-written `Error` names no source: what a failure says is in its own
                // rendering, never in a value a caller walks to.
                let mut open = index + 2;
                while open < tokens.len()
                    && !punct(tokens.get(open), '{')
                    && !punct(tokens.get(open), ';')
                {
                    open += 1;
                }
                if punct(tokens.get(open), '{') {
                    let close = closing(tokens, open).unwrap_or(open);
                    let body = &tokens[open..close];
                    for (at, located) in body.iter().enumerate() {
                        if ident(Some(located)) == Some("fn")
                            && matches!(
                                ident(body.get(at + 1)),
                                Some("source" | "cause" | "description")
                            )
                        {
                            let item = named_type(tokens, index + 2)
                                .map_or_else(|| "?".to_owned(), |(name, _)| name);
                            find(
                                located.line,
                                &item,
                                "an Error with a source written by hand",
                            );
                        }
                    }
                }
            }
            "ProtocolError"
                if punct(tokens.get(index + 1), ':')
                    && ident(tokens.get(index + 3)) == Some("new")
                    && source.name != REFUSAL_FILE =>
            {
                find(
                    line,
                    "ProtocolError::new",
                    "a protocol error built from text outside kr_client::error::refusal",
                );
            }
            "eprint" | "eprintln" if next_is_bang && source.name != REPORTER_FILE => {
                find(line, word, "standard error written outside the reporter");
            }
            // A call of `stderr()`, not a method of that name such as a command's.
            "stderr"
                if punct(tokens.get(index + 1), '(')
                    && !after_dot
                    && source.name != REPORTER_FILE =>
            {
                find(
                    line,
                    "stderr()",
                    "standard error written outside the reporter",
                );
            }
            "info" | "warn" | "error" | "debug" | "trace" | "event" | "span" if next_is_bang => {
                find(line, word, "a log line");
            }
            "assert_eq" | "assert_ne" | "debug_assert_eq" | "debug_assert_ne"
                if next_is_bang && !shown_file =>
            {
                find(
                    line,
                    word,
                    "an assertion that renders the values it compares",
                );
            }
            "panic" | "unreachable" | "todo" | "unimplemented" if next_is_bang => {
                let parts = arguments(tokens, index + 2).unwrap_or_default();
                if !(parts.is_empty() || parts.len() == 1 && plain_literal(&parts[0])) {
                    find(line, word, "a panic that formats a value");
                }
            }
            "assert" | "debug_assert" if next_is_bang => {
                let parts = arguments(tokens, index + 2).unwrap_or_default();
                if parts.len() > 2 || parts.len() == 2 && !plain_literal(&parts[1]) {
                    find(line, word, "an assertion that formats a value");
                }
            }
            "unwrap" | "expect" | "unwrap_err" | "expect_err"
                if after_dot && punct(tokens.get(index + 1), '(') =>
            {
                find(
                    line,
                    word,
                    "an unwrap or expect, whose panic renders what failed",
                );
            }
            "include" if next_is_bang => {
                find(
                    line,
                    "include!",
                    "included source this reading cannot follow",
                );
            }
            "thiserror" if index > 0 && ident(tokens.get(index - 1)) == Some("use") => {
                find(
                    line,
                    "use thiserror",
                    "an import this reading cannot follow; spell thiserror::Error",
                );
            }
            "derive" if punct(tokens.get(index + 1), '(') => {
                let derives = derive_names(tokens, index + 1);
                let defined = defined_after(tokens, index).unwrap_or_else(|| "?".to_owned());
                for derive in &derives {
                    if derive.ends_with("Error") && derive != "thiserror::Error" {
                        find(
                            line,
                            &defined,
                            "an Error derive not spelled thiserror::Error",
                        );
                    }
                }
                let path = format!("{}::{defined}", source.module.join("::"));
                if known.errors.contains_key(&path)
                    && derives.iter().any(|derive| derive == "Debug")
                {
                    find(line, &defined, "an error type that derives Debug");
                }
            }
            "macro_rules" if next_is_bang && !shown_file => {
                let open = index + 3;
                let body_close = closing(tokens, open).unwrap_or(open);
                let writes = tokens[open.min(tokens.len())..body_close.min(tokens.len())]
                    .iter()
                    .any(|located| {
                        matches!(
                            ident(Some(located)),
                            Some("struct" | "enum" | "union" | "trait" | "impl")
                        )
                    });
                if writes {
                    let item = ident(tokens.get(index + 2)).unwrap_or("?").to_owned();
                    find(
                        line,
                        &item,
                        "a macro that defines a type or writes an impl this reading cannot see",
                    );
                }
            }
            "struct" | "enum" if !shown_file => {
                if let Some(name) = ident(tokens.get(index + 1)) {
                    let path = format!("{}::{name}", source.module.join("::"));
                    if known.errors.contains_key(&path) {
                        check_error_type(source, index, &path, known, aliases, &mut find);
                    }
                }
            }
            _ => {}
        }
    }
}

/// One field of an error type or of one of its variants.
struct Field {
    /// Its name, or its position in a tuple.
    name: String,
    /// The line it is on.
    line: usize,
    /// Whether it is the error's source: `#[source]`, `#[from]`, or named `source`.
    source: bool,
    /// Its type's tokens.
    type_tokens: Vec<Located>,
}

/// The fields in the group that opens at `open`.
fn fields(tokens: &[Located], open: usize) -> Vec<Field> {
    let named = punct(tokens.get(open), '{');
    arguments(tokens, open)
        .unwrap_or_default()
        .into_iter()
        .enumerate()
        .map(|(position, part)| {
            let mut index = 0;
            let mut source = false;
            while index < part.len() {
                if punct(part.get(index), '#') {
                    source |= matches!(ident(part.get(index + 2)), Some("source" | "from"));
                    index = attribute_end(&part, index).unwrap_or(part.len());
                    continue;
                }
                let past = skip_visibility(&part, index);
                if past != index {
                    index = past;
                    continue;
                }
                break;
            }
            let line = part.get(index).map_or(0, |located| located.line);
            let name = if named {
                let name = ident(part.get(index)).unwrap_or("?").to_owned();
                index += 2;
                name
            } else {
                position.to_string()
            };
            source |= name == "source";
            Field {
                name,
                line,
                source,
                type_tokens: part[index.min(part.len())..].to_vec(),
            }
        })
        .collect()
}

/// Holds one error type to the rule: its `#[error]` attributes, and the type of every field a
/// rendering of it reaches.
///
/// A `thiserror` type renders the fields its `#[error]` literal names and, through `source()`, its
/// source; its `Debug` is its `Display`. Those fields are held to the allowed types, and a field
/// neither names is never rendered. A type that says itself through `Said` renders only what its
/// `said` composes, which its types already hold to a `Shown`.
fn check_error_type(
    source: &Source,
    at: usize,
    path: &str,
    known: &Known,
    aliases: &BTreeMap<String, String>,
    find: &mut impl FnMut(usize, &str, &str),
) {
    let tokens = &source.tokens;
    let is_enum = ident(tokens.get(at)) == Some("enum");
    let mut index = at + 2;
    while index < tokens.len()
        && !punct(tokens.get(index), '{')
        && !punct(tokens.get(index), '(')
        && !punct(tokens.get(index), ';')
    {
        index += 1;
    }
    if punct(tokens.get(index), ';') {
        return;
    }
    let Some(close) = closing(tokens, index) else {
        find(
            tokens[at].line,
            path,
            "an error type whose body this reading cannot follow",
        );
        return;
    };
    let derived = known.thiserror.contains(path);
    if !is_enum {
        let fields = fields(tokens, index);
        let rendered = error_attributes(tokens, before_item(tokens, at), at, path, &fields, find);
        if derived {
            check_rendered_fields(source, &fields, &rendered, path, None, known, aliases, find);
        }
        return;
    }
    let mut cursor = index + 1;
    while cursor < close {
        let attributes_start = cursor;
        while punct(tokens.get(cursor), '#') {
            cursor = attribute_end(tokens, cursor).unwrap_or(close);
        }
        let Some(variant) = ident(tokens.get(cursor)).map(ToOwned::to_owned) else {
            cursor += 1;
            continue;
        };
        let attributes_end = cursor;
        cursor += 1;
        let mut variant_fields = Vec::new();
        if punct(tokens.get(cursor), '{') || punct(tokens.get(cursor), '(') {
            let group_close = closing(tokens, cursor).unwrap_or(close);
            variant_fields = fields(tokens, cursor);
            cursor = group_close + 1;
        }
        let item = format!("{path}::{variant}");
        let rendered = error_attributes(
            tokens,
            attributes_start,
            attributes_end,
            &item,
            &variant_fields,
            find,
        );
        if derived {
            check_rendered_fields(
                source,
                &variant_fields,
                &rendered,
                path,
                Some(&variant),
                known,
                aliases,
                find,
            );
        }
        while cursor < close && !punct(tokens.get(cursor), ',') {
            cursor += 1;
        }
        cursor += 1;
    }
}

/// Where the attributes in front of the item at `at` begin.
fn before_item(tokens: &[Located], at: usize) -> usize {
    let mut start = at;
    // Back over visibility, `pub` or `pub(...)`.
    if start > 0 && punct(tokens.get(start - 1), ')') {
        let mut back = start - 1;
        while back > 0 && !punct(tokens.get(back), '(') {
            back -= 1;
        }
        if back > 0 && ident(tokens.get(back - 1)) == Some("pub") {
            start = back - 1;
        }
    } else if start > 0 && ident(tokens.get(start - 1)) == Some("pub") {
        start -= 1;
    }
    loop {
        if start == 0 || !punct(tokens.get(start - 1), ']') {
            return start;
        }
        let mut depth = 0;
        let mut back = start - 1;
        loop {
            match tokens[back].token {
                Token::Punct(']') => depth += 1,
                Token::Punct('[') => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                _ => {}
            }
            if back == 0 {
                return start;
            }
            back -= 1;
        }
        if back == 0 || !punct(tokens.get(back - 1), '#') {
            return start;
        }
        start = back - 1;
    }
}

/// What the `#[error]` attributes between `start` and `end` render.
enum Rendered {
    /// No `#[error]`: the type or variant is said some other way.
    Nothing,
    /// `#[error(transparent)]`: its one field, whole.
    Transparent,
    /// One literal, naming these fields.
    Fields(BTreeSet<String>),
}

/// Holds the `#[error]` attributes between `start` and `end` to one literal whose holes name the
/// fields, and returns what they render.
fn error_attributes(
    tokens: &[Located],
    start: usize,
    end: usize,
    item: &str,
    fields: &[Field],
    find: &mut impl FnMut(usize, &str, &str),
) -> Rendered {
    let mut rendered = Rendered::Nothing;
    let mut index = start;
    while index < end {
        if !punct(tokens.get(index), '#') {
            index += 1;
            continue;
        }
        let Some(attribute_close) = attribute_end(tokens, index) else {
            break;
        };
        if ident(tokens.get(index + 2)) == Some("error") && punct(tokens.get(index + 3), '(') {
            let line = tokens[index].line;
            let parts = arguments(tokens, index + 3).unwrap_or_default();
            match parts.as_slice() {
                [part] => match part.as_slice() {
                    [
                        Located {
                            token: Token::Ident(word),
                            ..
                        },
                    ] if word == "transparent" => {
                        rendered = Rendered::Transparent;
                    }
                    [
                        Located {
                            token: Token::Str(text),
                            ..
                        },
                    ] => {
                        let mut named = BTreeSet::new();
                        for hole in holes(text) {
                            let (argument, spec) =
                                hole.split_once(':').unwrap_or((hole.as_str(), ""));
                            let argument = argument.trim().to_owned();
                            if !fields.iter().any(|field| field.name == argument) {
                                find(
                                    line,
                                    item,
                                    "an #[error] hole that is not one of the variant's own fields",
                                );
                            }
                            if spec.contains('?') {
                                find(line, item, "an #[error] hole formatted with Debug");
                            }
                            named.insert(argument);
                        }
                        rendered = Rendered::Fields(named);
                    }
                    _ => find(
                        line,
                        item,
                        "an #[error] that is not one literal naming its fields",
                    ),
                },
                _ => find(
                    line,
                    item,
                    "an #[error] that is not one literal naming its fields",
                ),
            }
        }
        index = attribute_close;
    }
    rendered
}

/// Holds each field a rendering reaches to the allowed types.
#[expect(
    clippy::too_many_arguments,
    reason = "the field, where it is, and what the rule knows"
)]
fn check_rendered_fields(
    source: &Source,
    fields: &[Field],
    rendered: &Rendered,
    path: &str,
    variant: Option<&str>,
    known: &Known,
    aliases: &BTreeMap<String, String>,
    find: &mut impl FnMut(usize, &str, &str),
) {
    let item = variant.map_or_else(|| path.to_owned(), |variant| format!("{path}::{variant}"));
    for field in fields {
        let reached = field.source
            || match rendered {
                Rendered::Nothing => false,
                Rendered::Transparent => true,
                Rendered::Fields(named) => named.contains(&field.name),
            };
        if !reached {
            continue;
        }
        for field_type in held(source, &field.type_tokens, aliases) {
            let Some(field_type) = field_type else {
                find(
                    field.line,
                    &item,
                    "a rendered error field whose type this reading cannot place",
                );
                continue;
            };
            let allowed = field_type == SHOWN
                || field_type == IO_FAULT
                || known.plain.contains(&field_type)
                || known.errors.contains_key(&field_type)
                || variant.is_some_and(|variant| {
                    RAW.iter().any(|(error, raw_variant, raw)| {
                        *error == path
                            && *raw_variant == variant
                            && field_type.rsplit("::").next() == Some(*raw)
                    })
                });
            if !allowed {
                find(
                    field.line,
                    &item,
                    &format!(
                        "a rendered error field of type {field_type}, which is not Shown, \
                         IoFault, Plain or an error of these crates"
                    ),
                );
            }
        }
    }
}

/* -------------------------------------------------------------------------------------------- */
/* The two crates                                                                                */
/* -------------------------------------------------------------------------------------------- */

fn workspace() -> PathBuf {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let Some(workspace) = manifest.ancestors().nth(2) else {
        panic!("the crate is two levels below the workspace");
    };
    workspace.to_path_buf()
}

fn both_crates() -> Vec<Source> {
    let workspace = workspace();
    let mut roots = vec![
        (
            workspace.join("crates/kr-client/src/lib.rs"),
            "kr_client".to_owned(),
        ),
        (
            workspace.join("crates/kr-cli/src/lib.rs"),
            "kr_cli".to_owned(),
        ),
    ];
    let binaries = workspace.join("crates/kr-cli/src/bin");
    let mut entries: Vec<PathBuf> = std::fs::read_dir(&binaries)
        .expect("the command line's binaries")
        .map(|entry| entry.expect("an entry").path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "rs"))
        .collect();
    entries.sort();
    for entry in entries {
        let name = entry
            .file_stem()
            .and_then(|stem| stem.to_str())
            .map(|stem| stem.replace('-', "_"))
            .expect("a binary's name");
        roots.push((entry, name));
    }
    let mut sources = Vec::new();
    for (root, crate_name) in roots {
        match crate_sources(&workspace, &root, &crate_name) {
            Ok(found) => sources.extend(found),
            Err(unreadable) => panic!("a source this reading cannot follow: {unreadable}"),
        }
    }
    sources
}

#[test]
fn both_crates_render_only_what_the_rule_allows() {
    let sources = both_crates();
    assert!(
        sources.len() > 60,
        "the walk reaches every module of both crates: {}",
        sources.len()
    );
    let findings = check(&sources);
    let listed = findings
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        findings.is_empty(),
        "{} places do not hold the rule:\n{listed}",
        findings.len()
    );
}

/* -------------------------------------------------------------------------------------------- */
/* The reading's own controls                                                                    */
/* -------------------------------------------------------------------------------------------- */

/// A crate written to a directory of its own for one control, removed when the control ends.
struct Scratch {
    workspace: PathBuf,
}

impl Scratch {
    /// Writes `files`, each a path under `crates/kr-cli/src` and its text.
    fn new(label: &str, files: &[(&str, &str)]) -> Self {
        let workspace =
            std::env::temp_dir().join(format!("kr-shown-rule-{label}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&workspace);
        for (path, text) in files {
            let path = workspace.join("crates/kr-cli/src").join(path);
            std::fs::create_dir_all(path.parent().expect("a directory")).expect("a directory");
            std::fs::write(&path, text).expect("a control file");
        }
        Self { workspace }
    }

    /// The crate's production files, read from its root.
    fn sources(&self) -> Result<Vec<Source>, String> {
        crate_sources(
            &self.workspace,
            &self.workspace.join("crates/kr-cli/src/lib.rs"),
            "kr_cli",
        )
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.workspace);
    }
}

/// The claims and the errors every control can use, in the files the rule names.
const SHOWN_CONTROL: &str =
    "pub struct Named;\nimpl Plain for Named {}\nplain!(u64, &'static str);\n";
const ERRORS_CONTROL: &str = "#[derive(thiserror::Error)]\npub enum CliError {\n    \
                              #[error(\"refused\")]\n    Refused,\n}\n\
                              kr_client::debug_as_display!(CliError);\n";

/// What the rule finds in one control file, beside the claims and the errors.
fn findings_in(label: &str, text: &str) -> Vec<Finding> {
    let scratch = Scratch::new(
        label,
        &[
            ("lib.rs", "mod control;\nmod error;\nmod shown;\n"),
            ("shown.rs", SHOWN_CONTROL),
            ("error.rs", ERRORS_CONTROL),
            ("control.rs", text),
        ],
    );
    let sources = scratch.sources().expect("the control is readable");
    check(&sources)
        .into_iter()
        .filter(|finding| finding.file.ends_with("control.rs"))
        .collect()
}

/// Each class of break the rule names is found, at its line, in a source that has nothing else.
#[test]
fn each_break_of_the_rule_is_named_with_its_class_and_place() {
    let cases: &[(&str, &str, usize, &str)] = &[
        (
            "a source written by hand",
            "pub struct Failure(std::io::Error);\nimpl std::error::Error for Failure {\n    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(&self.0) }\n}\nkr_client::display_as_said!(Failure);\nkr_client::debug_as_display!(Failure);\n",
            3,
            "an Error with a source written by hand",
        ),
        (
            "a hand-written Display",
            "struct View;\nimpl std::fmt::Display for View {\n    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str(\"x\") }\n}\n",
            2,
            "a Display written by hand",
        ),
        (
            "a Plain claim",
            "struct Secret(String);\nimpl kr_client::Plain for Secret {}\n",
            2,
            "Plain is claimed outside",
        ),
        (
            "a protocol error from text",
            "fn f(text: String) {\n    let _ = ProtocolError::new(ErrorCode::Internal, text);\n}\n",
            2,
            "a protocol error built from text",
        ),
        (
            "standard error",
            "fn f(text: &str) {\n    eprintln!(\"{text}\");\n}\n",
            2,
            "standard error written outside",
        ),
        (
            "a log line",
            "fn f(text: &str) {\n    tracing::warn!(%text, \"failed\");\n}\n",
            2,
            "a log line",
        ),
        (
            "an assertion on values",
            "fn f(a: &str, b: &str) {\n    assert_eq!(a, b);\n}\n",
            2,
            "renders the values",
        ),
        (
            "a formatted panic",
            "fn f(text: &str) {\n    panic!(\"failed: {text}\");\n}\n",
            2,
            "a panic that formats",
        ),
        (
            "a formatted assertion",
            "fn f(ok: bool, text: &str) {\n    assert!(ok, \"failed: {}\", text);\n}\n",
            2,
            "an assertion that formats",
        ),
        (
            "an expect with a literal message over a failure that carries text",
            "fn f(input: String) {\n    Err::<(), _>(std::io::Error::other(input)).expect(\"read\");\n}\n",
            2,
            "an unwrap or expect",
        ),
        (
            "an unwrap",
            "fn f(r: Result<(), E>) {\n    r.unwrap();\n}\n",
            2,
            "an unwrap or expect",
        ),
        (
            "an error that derives Debug",
            "#[derive(Debug, thiserror::Error)]\npub enum Failure {\n    #[error(\"failed\")]\n    Failed,\n}\nkr_client::debug_as_display!(Failure);\n",
            1,
            "an error type that derives Debug",
        ),
        (
            "an error holding raw text",
            "#[derive(thiserror::Error)]\npub enum Failure {\n    #[error(\"failed: {0}\")]\n    Failed(String),\n}\nkr_client::debug_as_display!(Failure);\n",
            4,
            "whose type this reading cannot place",
        ),
        (
            "a hole spelled with escapes",
            "#[derive(thiserror::Error)]\npub enum Failure {\n    #[error(\"\\x7b0\\x7d\")]\n    Failed(std::string::String),\n}\nkr_client::debug_as_display!(Failure);\n",
            4,
            "error field of type std::string::String",
        ),
        (
            "a borrowed string that is not static",
            "#[derive(thiserror::Error)]\npub enum Failure<'a> {\n    #[error(\"failed: {0}\")]\n    Failed(&'a str),\n}\nkr_client::debug_as_display!(Failure);\n",
            4,
            "error field of type &'a prim::str",
        ),
        (
            "a type named like a claimed one",
            "pub struct Named(String);\n#[derive(thiserror::Error)]\npub enum Failure {\n    #[error(\"failed: {0}\")]\n    Failed(Named),\n}\nkr_client::debug_as_display!(Failure);\n",
            5,
            "error field of type kr_cli::control::Named",
        ),
        (
            "an #[error] with an argument",
            "#[derive(thiserror::Error)]\npub enum Failure {\n    #[error(\"failed: {}\", .0.len())]\n    Failed(kr_client::shown::Shown),\n}\nkr_client::debug_as_display!(Failure);\n",
            3,
            "not one literal naming its fields",
        ),
        (
            "an #[error] with Debug",
            "#[derive(thiserror::Error)]\npub enum Failure {\n    #[error(\"failed: {0:?}\")]\n    Failed(kr_client::shown::Shown),\n}\nkr_client::debug_as_display!(Failure);\n",
            3,
            "formatted with Debug",
        ),
        (
            "an Error derive this reading cannot follow",
            "use thiserror::Error as Failing;\n#[derive(Failing)]\npub enum Failure {}\n",
            1,
            "an import this reading cannot follow",
        ),
        (
            "a renamed trait",
            "use std::fmt::Display as Shows;\nstruct View;\nimpl Shows for View {\n    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str(\"x\") }\n}\n",
            1,
            "a renamed import this reading cannot follow",
        ),
        (
            "a type a macro defines",
            "macro_rules! failure {\n    ($name:ident) => { pub struct $name(String); };\n}\n",
            1,
            "a macro that defines a type or writes an impl",
        ),
        (
            "an impl a macro writes",
            "macro_rules! shows {\n    ($trait:path, $name:ident) => { impl $trait for $name { fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str(\"x\") } } };\n}\n",
            1,
            "a macro that defines a type or writes an impl",
        ),
        (
            "an item that compiles on some platform without test",
            "#[cfg(any(test, unix))]\nfn f(a: &str, b: &str) {\n    assert_eq!(a, b);\n}\n",
            3,
            "renders the values",
        ),
        (
            "an inner cfg inside a block",
            "mod inline {\n    #![cfg(test)]\n    fn f(a: &str, b: &str) { assert_eq!(a, b); }\n}\n",
            2,
            "an inner cfg inside a block",
        ),
        (
            "a module in a file a path attribute names",
            "#[path = \"elsewhere.rs\"]\nmod moved;\n",
            1,
            "a module file this reading cannot follow",
        ),
        (
            "an included source",
            "include!(\"generated.rs\");\n",
            1,
            "included source this reading cannot follow",
        ),
        (
            "an error whose Debug is not its Display",
            "#[derive(thiserror::Error)]\npub enum Failure {\n    #[error(\"failed\")]\n    Failed,\n}\n",
            0,
            "whose Debug is not its Display",
        ),
    ];
    for (position, (class, text, line, what)) in cases.iter().enumerate() {
        let findings = if text.contains("mod moved;") {
            // A module whose file is named elsewhere has no conventional file, and the reading
            // says so before anything else.
            let scratch = Scratch::new(
                &format!("case-{position}"),
                &[
                    ("lib.rs", "mod control;\n"),
                    ("control.rs", text),
                    ("control/moved.rs", ""),
                ],
            );
            let sources = scratch.sources().expect("the control is readable");
            check(&sources)
        } else {
            findings_in(&format!("case-{position}"), text)
        };
        assert!(
            findings
                .iter()
                .any(|finding| finding.line == *line && finding.what.contains(what)),
            "{class}: expected a finding at line {line} saying {what:?}, found {findings:?}"
        );
    }
}

/// What the rule allows is not found: the same shapes, written the way the rule asks.
#[test]
fn what_the_rule_allows_is_not_named() {
    let text = "use kr_client::shown::{IoFault, Shown};\n\
                use crate::error::CliError;\n\
                #[derive(thiserror::Error)]\n\
                pub enum Failure {\n    \
                    #[error(\"the store at {path} failed: {fault}\")]\n    \
                    Store { path: Shown, fault: IoFault },\n    \
                    #[error(transparent)]\n    \
                    Command(CliError),\n    \
                    #[error(\"failed at {0}\")]\n    \
                    At(u64),\n    \
                    #[error(\"named {0}\")]\n    \
                    Named(&'static str),\n    \
                    #[error(\"a write is unsettled\")]\n    \
                    Unsettled { sent: [u8; 32], text: String },\n\
                }\n\
                kr_client::debug_as_display!(Failure);\n\
                fn f(ok: bool) {\n    \
                    assert!(ok, \"it holds\");\n    \
                    let Some(one) = Some(1) else { unreachable!(\"there is one\") };\n    \
                    let _ = one;\n\
                }\n\
                #[cfg(test)]\n\
                mod tests {\n    \
                    fn g(a: &str) { assert_eq!(a, \"x\"); eprintln!(\"{a}\"); Some(1).unwrap(); }\n\
                }\n";
    let findings = findings_in("allowed", text);
    assert!(findings.is_empty(), "{findings:?}");
}

/// A module under `#[cfg(test)]` is test code however it is declared, and so is every file it
/// declares.
#[test]
fn test_code_is_passed_over_wherever_it_is_declared() {
    let scratch = Scratch::new(
        "tests",
        &[
            ("lib.rs", "#[cfg(test)]\nmod helper;\nmod shipped;\n"),
            (
                "helper.rs",
                "mod deeper;\nfn f(a: u8) { assert_eq!(a, 1); }\n",
            ),
            ("helper/deeper.rs", "fn g(a: u8) { assert_eq!(a, 1); }\n"),
            (
                "shipped.rs",
                "fn h(a: u8) -> u8 { a }\n#[cfg(all(test, unix))]\nfn i(a: u8) { assert_eq!(a, 1); }\n#[cfg(not(test))]\nfn j(a: u8) { assert_eq!(a, 2); }\n",
            ),
        ],
    );
    let sources = scratch.sources().expect("readable");
    let findings = check(&sources);
    let names: BTreeSet<&str> = sources.iter().map(|source| source.name.as_str()).collect();
    assert!(
        !names.iter().any(|name| name.contains("helper")),
        "{names:?}"
    );
    assert_eq!(
        findings.len(),
        1,
        "only the item compiled outside tests is held: {findings:?}"
    );
    assert_eq!(findings[0].line, 5, "{findings:?}");
}

/// A literal's escapes are decoded, so a hole spelled with them is a hole.
#[test]
fn a_literal_is_read_as_the_compiler_reads_it() {
    let tokens =
        lex("\"\\x7b0\\x7d \\u{7b}name\\u{7D} a\\\n    b\" r#\"{raw}\"#").expect("readable");
    let texts: Vec<&str> = tokens
        .iter()
        .filter_map(|located| match &located.token {
            Token::Str(text) => Some(text.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(texts, ["{0} {name} ab", "{raw}"]);
    assert_eq!(holes(texts[0]), ["0", "name"]);
}
