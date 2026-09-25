//! The rule a rendering follows, held over the sources of the two crates that render diagnostics.
//!
//! In this library and in the command line, a failure, a line on standard error and a panic say
//! only a `Shown`: this program's own words, values with nothing in them to hide (`Plain`), and
//! what a reducer or a door decided may be said. The types make that so where they can, and this
//! test reads both crates' sources for the places where a type alone cannot, failing with the
//! file, the line and the item wherever one of these holds:
//!
//! * an error type derives `Debug`, has a `Debug` that is not its `Display`, or holds a field that
//!   is not a `Shown`, an `IoFault`, a `Plain` value, another of these crates' errors, or one of
//!   the six values other crates build and match (a host's `ProtocolError`, a `TransportError`, an
//!   `IpcError`);
//! * an `#[error]` attribute is anything but `transparent` or one literal whose holes name the
//!   variant's own fields, with no argument after it and no `?` in a hole;
//! * a `Display` is written by hand outside the two files that define what may be shown;
//! * `Plain` is claimed outside those two files;
//! * a `ProtocolError` is built anywhere but the one constructor that takes a `Shown`;
//! * production code logs, writes standard error outside the command line's reporter, formats a
//!   panic, asserts on values, or passes `expect` anything but a literal;
//! * the syntax is one this reading cannot follow: an `Error` derive not spelled
//!   `thiserror::Error`, an import of `thiserror`, a macro that defines a type, or a field type it
//!   cannot read.
//!
//! Test code is not held to the rule: an item under `#[cfg(test)]`, and every file such an item
//! declares, is passed over.

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
    /// A string literal's contents as written, escapes included.
    Str(String),
    /// A character or byte literal.
    Char,
    /// A number.
    Number,
    /// A lifetime or a label.
    Lifetime,
}

/// A token and the line it starts on.
#[derive(Clone, Debug)]
struct Located {
    token: Token,
    line: usize,
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
            while at < chars.len() && (chars[at].is_alphanumeric() || chars[at] == '_') {
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
                while at < chars.len() && (chars[at].is_alphanumeric() || chars[at] == '_') {
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
            while at < chars.len() && (chars[at].is_alphanumeric() || chars[at] == '_') {
                at += 1;
            }
            // A fraction, but not a range.
            if chars.get(at) == Some(&'.') && chars.get(at + 1).is_some_and(char::is_ascii_digit) {
                at += 1;
                while at < chars.len() && (chars[at].is_alphanumeric() || chars[at] == '_') {
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
                at += 1;
                while at < chars.len() && (chars[at].is_alphanumeric() || chars[at] == '_') {
                    at += 1;
                }
                tokens.push(Located {
                    token: Token::Lifetime,
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

/// Reads a string that opens at `at`, returning its contents and the index after it.
fn string(chars: &[char], at: usize) -> Option<(String, usize)> {
    let mut index = at + 1;
    let mut contents = String::new();
    while index < chars.len() {
        match chars[index] {
            '\\' => {
                contents.push('\\');
                contents.push(*chars.get(index + 1)?);
                index += 2;
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

/* -------------------------------------------------------------------------------------------- */
/* Production code                                                                               */
/* -------------------------------------------------------------------------------------------- */

/// One source file, as the rule reads it.
struct Source {
    /// The path from the workspace root, which is how a finding names it.
    name: String,
    /// Its production tokens: everything not under `#[cfg(test)]`.
    tokens: Vec<Located>,
    /// The modules it declares in files of their own, and whether each is test code.
    children: Vec<(String, bool)>,
}

/// Whether the attribute that ends just before `end` and opens at `start` makes an item test code.
fn is_test_attribute(tokens: &[Located], start: usize, end: usize) -> bool {
    let inner = &tokens[start..end];
    let Some(Token::Ident(first)) = inner.get(2).map(|located| &located.token) else {
        return false;
    };
    if first != "cfg" {
        return false;
    }
    // `test` anywhere in the condition, unless it is under a `not`.
    let mut negated_depth: Option<usize> = None;
    let mut depth = 0_usize;
    for (index, located) in inner.iter().enumerate() {
        match &located.token {
            Token::Punct('(') => depth += 1,
            Token::Punct(')') => {
                if negated_depth == Some(depth) {
                    negated_depth = None;
                }
                depth = depth.saturating_sub(1);
            }
            Token::Ident(word) if word == "not" => {
                if matches!(
                    inner.get(index + 1).map(|next| &next.token),
                    Some(Token::Punct('('))
                ) {
                    negated_depth.get_or_insert(depth + 1);
                }
            }
            Token::Ident(word) if word == "test" && negated_depth.is_none() => return true,
            _ => {}
        }
    }
    false
}

/// Returns the index just past the attribute that opens at `start` (`#` or `#!`).
fn attribute_end(tokens: &[Located], start: usize) -> Option<usize> {
    let mut index = start + 1;
    if matches!(
        tokens.get(index).map(|located| &located.token),
        Some(Token::Punct('!'))
    ) {
        index += 1;
    }
    if !matches!(
        tokens.get(index).map(|located| &located.token),
        Some(Token::Punct('['))
    ) {
        return None;
    }
    let mut depth = 0_i64;
    while index < tokens.len() {
        match tokens[index].token {
            Token::Punct('[') => depth += 1,
            Token::Punct(']') => {
                depth -= 1;
                if depth == 0 {
                    return Some(index + 1);
                }
            }
            _ => {}
        }
        index += 1;
    }
    None
}

/// Returns the index just past the item, statement, field or variant that starts at `start`.
fn item_end(tokens: &[Located], start: usize) -> usize {
    let keyword = matches!(
        tokens.get(start).map(|located| &located.token),
        Some(Token::Ident(word)) if matches!(word.as_str(),
            "fn" | "mod" | "impl" | "struct" | "enum" | "use" | "const" | "static" | "type"
            | "trait" | "pub" | "unsafe" | "async" | "extern" | "macro_rules" | "let")
    );
    let mut depth = 0_i64;
    let mut index = start;
    while index < tokens.len() {
        match tokens[index].token {
            Token::Punct('{' | '(' | '[') => depth += 1,
            Token::Punct('}' | ')' | ']') => {
                depth -= 1;
                if depth == 0 && matches!(tokens[index].token, Token::Punct('}')) {
                    // A block closes the item unless an expression goes on after it, which a
                    // statement ends with a semicolon.
                    let next = tokens.get(index + 1).map(|located| &located.token);
                    let goes_on = matches!(next, Some(Token::Punct(';' | '.' | '?')))
                        || matches!(next, Some(Token::Ident(word)) if word == "else");
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
    let mut index = at;
    if ident(tokens.get(index)) == Some("pub") {
        index += 1;
        if punct(tokens.get(index), '(') {
            index = closing(tokens, index)? + 1;
        }
    }
    if ident(tokens.get(index)) != Some("mod") || !punct(tokens.get(index + 2), ';') {
        return None;
    }
    ident(tokens.get(index + 1)).map(ToOwned::to_owned)
}

/// Reads one file into its production tokens and the modules it declares.
fn read_source(root: &Path, path: &Path, test: bool) -> Result<Source, String> {
    let name = path
        .strip_prefix(root)
        .unwrap_or(path)
        .display()
        .to_string();
    let text = std::fs::read_to_string(path).map_err(|error| format!("{name}: {error}"))?;
    let all = lex(&text).map_err(|error| format!("{name}: {error}"))?;
    let mut tokens = Vec::new();
    let mut children = Vec::new();
    let mut file_test = test;
    // The attributes of the item about to start, and whether one of them makes it test code.
    let mut attributes: Vec<Located> = Vec::new();
    let mut attributes_test = false;
    let mut index = 0;
    while index < all.len() {
        if punct(all.get(index), '#')
            && let Some(end) = attribute_end(&all, index)
        {
            let inner = punct(all.get(index + 1), '!');
            let is_test = is_test_attribute(&all, index + usize::from(inner), end);
            if inner {
                file_test |= is_test;
                if !file_test {
                    tokens.extend_from_slice(&all[index..end]);
                }
            } else {
                attributes_test |= is_test;
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
            children.push((module, attributes_test || file_test));
        }
        if skipped {
            attributes.clear();
            attributes_test = false;
            index = item_end(&all, index);
            continue;
        }
        if !file_test {
            tokens.append(&mut attributes);
            tokens.push(all[index].clone());
        }
        attributes.clear();
        attributes_test = false;
        index += 1;
    }
    if !file_test {
        tokens.append(&mut attributes);
    }
    Ok(Source {
        name,
        tokens,
        children,
    })
}

/// Every production file of the crate whose root is `crate_root`, following its module tree.
fn crate_sources(workspace: &Path, crate_root: &Path) -> Result<Vec<Source>, String> {
    let mut sources = Vec::new();
    let mut pending = vec![(crate_root.to_path_buf(), false, true)];
    while let Some((path, test, root_like)) = pending.pop() {
        let source = read_source(workspace, &path, test)?;
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
            pending.push((found.0, *child_test || test, found.1));
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

/// The two files that define what may be shown.
const SHOWN_FILES: [&str; 2] = [
    "crates/kr-client/src/shown.rs",
    "crates/kr-cli/src/shown.rs",
];

/// The one constructor of a protocol error from text.
const REFUSAL_FILE: &str = "crates/kr-client/src/error.rs";

/// The command line's reporter, the one writer of standard error.
const REPORTER_FILE: &str = "crates/kr-cli/src/report.rs";

/// The values other crates build and match, which an error holds whole and renders through a door
/// or a reducer: the error type, its variant and the field's type.
const RAW: [(&str, &str, &str); 6] = [
    ("ClientError", "Host", "ProtocolError"),
    ("ClientError", "Refused", "ProtocolError"),
    ("ClientError", "Transport", "TransportError"),
    ("ClientError", "Ipc", "IpcError"),
    ("CliError", "Refused", "ProtocolError"),
    ("CliError", "Ipc", "IpcError"),
];

/// Wrappers a field type may have around the value it holds.
const WRAPPERS: [&str; 4] = ["Box", "Option", "Vec", "Arc"];

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
    let mut parts = vec![Vec::new()];
    let mut depth = 0_i64;
    let mut angle = 0_i64;
    for located in &tokens[open + 1..close] {
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
        parts.last_mut()?.push(located.clone());
    }
    if parts.last().is_some_and(Vec::is_empty) {
        parts.pop();
    }
    Some(parts)
}

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

/// What the rule knows before it reads an item: which types are `Plain`, which are errors, how each
/// error renders.
#[derive(Default)]
struct Known {
    plain: BTreeSet<String>,
    /// Each error type, with the file it is declared in.
    errors: BTreeMap<String, String>,
    /// The error types `thiserror` renders.
    thiserror: BTreeSet<String>,
    debug_as_display: BTreeSet<String>,
    display_as_said: BTreeSet<String>,
}

/// The last path segment of the type that starts at `start`, skipping `&`, `dyn`, `mut` and
/// lifetimes, with generic arguments dropped.
fn named_type(tokens: &[Located], mut start: usize) -> Option<(String, usize)> {
    while matches!(
        tokens.get(start).map(|located| &located.token),
        Some(Token::Punct('&') | Token::Lifetime)
    ) || matches!(ident(tokens.get(start)), Some("dyn" | "mut"))
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

fn collect_known(sources: &[Source]) -> Known {
    let mut known = Known::default();
    for source in sources {
        let tokens = &source.tokens;
        for (index, located) in tokens.iter().enumerate() {
            let Token::Ident(word) = &located.token else {
                continue;
            };
            match word.as_str() {
                // `impl Plain for T`, and `plain!(T, U, ...)`.
                "Plain" if ident(tokens.get(index + 1)) == Some("for") => {
                    if let Some((name, _)) = named_type(tokens, index + 2) {
                        known.plain.insert(name);
                    }
                }
                "plain" | "debug_as_display" | "display_as_said"
                    if punct(tokens.get(index + 1), '!') && punct(tokens.get(index + 2), '(') =>
                {
                    for argument in arguments(tokens, index + 2).unwrap_or_default() {
                        let Some((name, _)) = named_type(&argument, 0) else {
                            continue;
                        };
                        let into = match word.as_str() {
                            "plain" => &mut known.plain,
                            "debug_as_display" => &mut known.debug_as_display,
                            _ => &mut known.display_as_said,
                        };
                        into.insert(name);
                    }
                }
                // `impl std::error::Error for T` and `#[derive(thiserror::Error)] enum T`.
                "Error"
                    if ident(tokens.get(index + 1)) == Some("for") && impl_of(tokens, index) =>
                {
                    if let Some((name, _)) = named_type(tokens, index + 2) {
                        known
                            .errors
                            .entry(name)
                            .or_insert_with(|| source.name.clone());
                    }
                }
                "derive" if punct(tokens.get(index + 1), '(') => {
                    let derives = derive_names(tokens, index + 1);
                    if derives.iter().any(|name| name == "thiserror::Error")
                        && let Some(name) = defined_after(tokens, index)
                    {
                        known.errors.insert(name.clone(), source.name.clone());
                        known.thiserror.insert(name);
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
    let known = collect_known(sources);
    let mut findings = BTreeSet::new();
    for source in sources {
        check_source(source, &known, &mut findings);
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

fn check_source(source: &Source, known: &Known, findings: &mut BTreeSet<Finding>) {
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
                if let Some((name, _)) = named_type(tokens, index + 2)
                    && known.errors.contains_key(&name)
                {
                    find(line, &name, "an error type with a Debug written by hand");
                }
            }
            "Error" if ident(tokens.get(index + 1)) == Some("for") && impl_of(tokens, index) => {
                // A hand-written `Error` names no source: what a failure says is in its own
                // rendering, never in a value a caller walks to.
                let mut open = index + 2;
                while open < tokens.len() && !matches!(tokens[open].token, Token::Punct('{' | ';'))
                {
                    open += 1;
                }
                if punct(tokens.get(open), '{') {
                    let close = closing(tokens, open).unwrap_or(open);
                    let body = &tokens[open..close];
                    for (at, located) in body.iter().enumerate() {
                        if matches!(&located.token, Token::Ident(word) if word == "fn")
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
                    && !(index > 0 && punct(tokens.get(index - 1), '.'))
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
            "expect"
                if index > 0
                    && punct(tokens.get(index - 1), '.')
                    && punct(tokens.get(index + 1), '(') =>
            {
                let parts = arguments(tokens, index + 1).unwrap_or_default();
                if !(parts.len() == 1 && plain_literal(&parts[0])) {
                    find(line, "expect", "an expect whose message is not one literal");
                }
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
                if known.errors.contains_key(&defined)
                    && derives.iter().any(|derive| derive == "Debug")
                {
                    find(line, &defined, "an error type that derives Debug");
                }
            }
            "macro_rules" if next_is_bang => {
                let open = index + 3;
                let body_close = closing(tokens, open).unwrap_or(open);
                let defines = tokens[open.min(tokens.len())..body_close.min(tokens.len())]
                    .iter()
                    .any(|located| matches!(&located.token, Token::Ident(word) if word == "struct" || word == "enum"));
                if defines {
                    let item = ident(tokens.get(index + 2)).unwrap_or("?").to_owned();
                    find(
                        line,
                        &item,
                        "a macro that defines a type this reading cannot see",
                    );
                }
            }
            "struct" | "enum" => {
                if let Some(name) = ident(tokens.get(index + 1))
                    && known.errors.contains_key(name)
                    && !shown_file
                {
                    check_error_type(tokens, index, name, known, &mut find);
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
                if ident(part.get(index)) == Some("pub") {
                    index += 1;
                    if punct(part.get(index), '(') {
                        index = closing(&part, index).map_or(part.len(), |close| close + 1);
                    }
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
    tokens: &[Located],
    at: usize,
    name: &str,
    known: &Known,
    find: &mut impl FnMut(usize, &str, &str),
) {
    let is_enum = ident(tokens.get(at)) == Some("enum");
    let mut index = at + 2;
    while index < tokens.len() && !matches!(tokens[index].token, Token::Punct('{' | '(' | ';')) {
        index += 1;
    }
    if punct(tokens.get(index), ';') {
        return;
    }
    let Some(close) = closing(tokens, index) else {
        find(
            tokens[at].line,
            name,
            "an error type whose body this reading cannot follow",
        );
        return;
    };
    let derived = known.thiserror.contains(name);
    if !is_enum {
        let fields = fields(tokens, index);
        let rendered = error_attributes(tokens, before_item(tokens, at), at, name, &fields, find);
        if derived {
            check_rendered_fields(&fields, &rendered, name, None, known, find);
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
        if matches!(
            tokens.get(cursor).map(|located| &located.token),
            Some(Token::Punct('{' | '('))
        ) {
            let group_close = closing(tokens, cursor).unwrap_or(close);
            variant_fields = fields(tokens, cursor);
            cursor = group_close + 1;
        }
        let item = format!("{name}::{variant}");
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
                &variant_fields,
                &rendered,
                name,
                Some(&variant),
                known,
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
fn check_rendered_fields(
    fields: &[Field],
    rendered: &Rendered,
    name: &str,
    variant: Option<&str>,
    known: &Known,
    find: &mut impl FnMut(usize, &str, &str),
) {
    let item = variant.map_or_else(|| name.to_owned(), |variant| format!("{name}::{variant}"));
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
        for field_type in held_types(&field.type_tokens) {
            let allowed = field_type == "Shown"
                || field_type == "IoFault"
                || known.plain.contains(&field_type)
                || known.errors.contains_key(&field_type)
                || variant.is_some_and(|variant| {
                    RAW.iter().any(|(error, raw_variant, raw)| {
                        *error == name && *raw_variant == variant && *raw == field_type
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

/// The types a field type holds: the type itself, or what a `Box`, `Option`, `Vec` or `Arc` holds.
fn held_types(field: &[Located]) -> Vec<String> {
    let Some((outer, after)) = named_type(field, 0) else {
        return vec!["(a type this reading cannot follow)".to_owned()];
    };
    if WRAPPERS.contains(&outer.as_str()) && punct(field.get(after), '<') {
        let inner_end = field.len().saturating_sub(1);
        if punct(field.get(inner_end), '>') {
            return held_types(&field[after + 1..inner_end]);
        }
    }
    if after < field.len() && !punct(field.get(after), '<') {
        return vec!["(a type this reading cannot follow)".to_owned()];
    }
    vec![outer]
}

/* -------------------------------------------------------------------------------------------- */
/* The two crates                                                                                */
/* -------------------------------------------------------------------------------------------- */

fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("the crate is two levels below the workspace")
        .to_path_buf()
}

fn both_crates() -> Vec<Source> {
    let workspace = workspace();
    let mut roots = vec![
        workspace.join("crates/kr-client/src/lib.rs"),
        workspace.join("crates/kr-cli/src/lib.rs"),
    ];
    let binaries = workspace.join("crates/kr-cli/src/bin");
    let mut entries: Vec<PathBuf> = std::fs::read_dir(&binaries)
        .expect("the command line's binaries")
        .map(|entry| entry.expect("an entry").path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "rs"))
        .collect();
    entries.sort();
    roots.extend(entries);
    let mut sources = Vec::new();
    for root in roots {
        match crate_sources(&workspace, &root) {
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

/// Reads one source written here, as if it were a file of a crate.
fn findings_in(name: &str, text: &str) -> Vec<Finding> {
    let tokens = lex(text).expect("the control is readable");
    let source = Source {
        name: name.to_owned(),
        tokens,
        children: Vec::new(),
    };
    check(&[source])
}

/// Each class of break the rule names is found, at its line, in a source that has nothing else.
#[test]
fn each_break_of_the_rule_is_named_with_its_class_and_place() {
    let cases: [(&str, &str, usize, &str); 17] = [
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
            "an expect with a built message",
            "fn f(r: Result<(), E>, m: String) {\n    r.expect(&m);\n}\n",
            2,
            "an expect whose message",
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
            "error field of type String",
        ),
        (
            "an #[error] with an argument",
            "#[derive(thiserror::Error)]\npub enum Failure {\n    #[error(\"failed: {}\", .0.len())]\n    Failed(Shown),\n}\nkr_client::debug_as_display!(Failure);\n",
            3,
            "not one literal naming its fields",
        ),
        (
            "an #[error] with Debug",
            "#[derive(thiserror::Error)]\npub enum Failure {\n    #[error(\"failed: {0:?}\")]\n    Failed(Shown),\n}\nkr_client::debug_as_display!(Failure);\n",
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
            "a type a macro defines",
            "macro_rules! failure {\n    ($name:ident) => { pub struct $name(String); };\n}\n",
            1,
            "a macro that defines a type",
        ),
        (
            "an error whose Debug is not its Display",
            "#[derive(thiserror::Error)]\npub enum Failure {\n    #[error(\"failed\")]\n    Failed,\n}\n",
            0,
            "whose Debug is not its Display",
        ),
    ];
    for (class, text, line, what) in cases {
        let findings = findings_in("crates/kr-cli/src/control.rs", text);
        assert!(
            findings
                .iter()
                .any(|finding| finding.line == line && finding.what.contains(what)),
            "{class}: expected a finding at line {line} saying {what:?}, found {findings:?}"
        );
    }
}

/// What the rule allows is not found: the same shapes, written the way the rule asks.
#[test]
fn what_the_rule_allows_is_not_named() {
    let text = "#[derive(thiserror::Error)]\n\
                pub enum Failure {\n    \
                    #[error(\"the store at {path} failed: {fault}\")]\n    \
                    Store { path: Shown, fault: IoFault },\n    \
                    #[error(transparent)]\n    \
                    Client(ClientError),\n    \
                    #[error(\"failed at {0}\")]\n    \
                    At(u64),\n    \
                    #[error(\"a write is unsettled\")]\n    \
                    Unsettled { sent: [u8; 32], text: String },\n\
                }\n\
                kr_client::debug_as_display!(Failure);\n\
                fn f(ok: bool) {\n    \
                    assert!(ok, \"it holds\");\n    \
                    let _: Option<u8> = None.or(Some(1));\n    \
                    Some(1).expect(\"there is one\");\n    \
                    unreachable!(\"no other state\");\n\
                }\n\
                #[cfg(test)]\n\
                mod tests {\n    \
                    fn g(a: &str) { assert_eq!(a, \"x\"); eprintln!(\"{a}\"); }\n\
                }\n";
    let workspace = std::env::temp_dir().join(format!("kr-shown-rule-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&workspace);
    let source = workspace.join("crates/kr-client/src");
    std::fs::create_dir_all(&source).expect("a directory for the control");
    std::fs::write(
        source.join("lib.rs"),
        "mod control;\nmod shown;\n#[derive(thiserror::Error)]\npub enum ClientError {}\n\
         kr_client::debug_as_display!(ClientError);\n",
    )
    .expect("the root");
    std::fs::write(source.join("shown.rs"), "plain!(u64);\n").expect("the claims");
    std::fs::write(source.join("control.rs"), text).expect("the control");
    let sources = crate_sources(&workspace, &source.join("lib.rs")).expect("readable");
    let findings = check(&sources);
    let _ = std::fs::remove_dir_all(&workspace);
    assert!(findings.is_empty(), "{findings:?}");
}

/// A module under `#[cfg(test)]` is test code however it is declared, and so is every file it
/// declares.
#[test]
fn test_code_is_passed_over_wherever_it_is_declared() {
    let workspace =
        std::env::temp_dir().join(format!("kr-shown-rule-tests-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&workspace);
    std::fs::create_dir_all(workspace.join("src/helper")).expect("a directory for the control");
    std::fs::write(
        workspace.join("src/lib.rs"),
        "#[cfg(test)]\nmod helper;\nmod shipped;\n",
    )
    .expect("the root");
    std::fs::write(
        workspace.join("src/helper.rs"),
        "mod deeper;\nfn f(a: u8) { assert_eq!(a, 1); }\n",
    )
    .expect("a test file");
    std::fs::write(
        workspace.join("src/helper/deeper.rs"),
        "fn g(a: u8) { assert_eq!(a, 1); }\n",
    )
    .expect("a deeper test file");
    std::fs::write(
        workspace.join("src/shipped.rs"),
        "fn h(a: u8) -> u8 { a }\n#[cfg(all(test, unix))]\nfn i(a: u8) { assert_eq!(a, 1); }\n#[cfg(not(test))]\nfn j(a: u8) { assert_eq!(a, 2); }\n",
    )
    .expect("a shipped file");
    let sources = crate_sources(&workspace, &workspace.join("src/lib.rs")).expect("readable");
    let findings = check(&sources);
    let _ = std::fs::remove_dir_all(&workspace);
    let names: BTreeMap<&str, usize> = sources
        .iter()
        .map(|source| (source.name.as_str(), source.tokens.len()))
        .collect();
    assert!(
        !names.keys().any(|name| name.contains("helper")),
        "{names:?}"
    );
    assert_eq!(
        findings.len(),
        1,
        "only the item compiled outside tests is held: {findings:?}"
    );
    assert_eq!(findings[0].line, 5, "{findings:?}");
}
