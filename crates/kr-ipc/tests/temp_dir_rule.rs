//! A fixture's temporary directory is dropped after everything that holds a file in it.
//!
//! Rust drops a struct's fields in the order they are declared. A fixture that declares its
//! [`kr_ipc::testing::TempHost`] or [`kr_ipc::testing::PrivateTempDir`] before the service, the
//! runtime or the plugin host that works in it has the directory removed while those still hold
//! files open, and on Windows an open file refuses the removal. The removal is then tried again for
//! 45 seconds, and the fields after it cannot let go until it returns, so the case waits the whole
//! time for a directory that cannot go yet. This test reads the Rust sources under `crates`,
//! `apps` and `tests` and fails, naming the file and the line, for a struct that declares a field
//! of one of those two types before a field of another type: the fields that own a directory are
//! the last ones of the struct, in whatever order among themselves.
//!
//! The reading is by tokens: comments and string and character literals are not code, so a
//! sentence that mentions a type is not a field of it. A field owns a directory when the type it
//! names contains `TempHost` or `PrivateTempDir` anywhere, in an `Option`, an `Arc`, a `Vec`, a
//! tuple or a path.
//!
//! What it cannot see:
//!
//! - a type alias, or an import that renames one of the two types, since it matches the names;
//! - a field that owns a directory through another type of the workspace, as a `Host` that holds a
//!   `TempHost` does for the struct that holds the `Host`: the order of the fields of that struct
//!   is the author's to keep, and the first struct is checked alone;
//! - a tuple or an enum variant that holds the directory before another value, and the order of
//!   local variables, which drop in the reverse order of their declaration;
//! - a struct made by a macro.
//!
//! Neither does it see what a field holds. A fixture whose later field is a task that is only
//! detached when its handle drops keeps its files open all the same, so its `Drop` or its `close`
//! ends the task.

use std::path::{Path, PathBuf};

/// The directories the reading covers, under the workspace's root.
const ROOTS: [&str; 3] = ["crates", "apps", "tests"];

/// The types that own a directory a test made.
const OWNING: [&str; 2] = ["TempHost", "PrivateTempDir"];

/// The structs that must keep a field that owns a directory before another field, as the file
/// they are in, their name and the reason. The fixtures of the workspace keep none.
const KEPT: &[(&str, &str, &str)] = &[];

#[derive(Clone, Debug, PartialEq)]
enum Kind {
    Word(String),
    Punct(char),
    Literal,
}

struct Token {
    kind: Kind,
    line: usize,
}

/// Splits a source into tokens, dropping comments and whitespace and the contents of literals.
fn lex(text: &str) -> Vec<Token> {
    let chars: Vec<char> = text.chars().collect();
    let mut tokens = Vec::new();
    let mut at = 0;
    let mut line = 1;
    while at < chars.len() {
        let c = chars[at];
        let next = chars.get(at + 1).copied();
        if c == '\n' {
            line += 1;
            at += 1;
        } else if c.is_whitespace() {
            at += 1;
        } else if c == '/' && next == Some('/') {
            while at < chars.len() && chars[at] != '\n' {
                at += 1;
            }
        } else if c == '/' && next == Some('*') {
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
            tokens.push(Token {
                kind: Kind::Literal,
                line,
            });
            at = past_string(&chars, at + 1, &mut line);
        } else if c == '\'' {
            if next == Some('\\') {
                at += 2;
                while at < chars.len() && chars[at] != '\'' {
                    at += 1;
                }
                at += 1;
                tokens.push(Token {
                    kind: Kind::Literal,
                    line,
                });
            } else if chars.get(at + 2) == Some(&'\'') {
                at += 3;
                tokens.push(Token {
                    kind: Kind::Literal,
                    line,
                });
            } else {
                tokens.push(Token {
                    kind: Kind::Punct('\''),
                    line,
                });
                at += 1;
            }
        } else if c.is_alphabetic() || c == '_' {
            let begun = at;
            while at < chars.len() && (chars[at].is_alphanumeric() || chars[at] == '_') {
                at += 1;
            }
            let word: String = chars[begun..at].iter().collect();
            let hashes = chars[at..].iter().take_while(|&&c| c == '#').count();
            if (word == "r" || word == "br") && chars.get(at + hashes) == Some(&'"') {
                at = past_raw_string(&chars, at + hashes + 1, hashes, &mut line);
                tokens.push(Token {
                    kind: Kind::Literal,
                    line,
                });
            } else {
                tokens.push(Token {
                    kind: Kind::Word(word),
                    line,
                });
            }
        } else {
            tokens.push(Token {
                kind: Kind::Punct(c),
                line,
            });
            at += 1;
        }
    }
    tokens
}

/// Where a string literal whose contents begin at `at` ends.
fn past_string(chars: &[char], mut at: usize, line: &mut usize) -> usize {
    while at < chars.len() {
        match chars[at] {
            '\\' => {
                if chars.get(at + 1) == Some(&'\n') {
                    *line += 1;
                }
                at += 2;
            }
            '"' => return at + 1,
            c => {
                if c == '\n' {
                    *line += 1;
                }
                at += 1;
            }
        }
    }
    at
}

/// Where a raw string literal with `hashes` marks whose contents begin at `at` ends.
fn past_raw_string(chars: &[char], mut at: usize, hashes: usize, line: &mut usize) -> usize {
    while at < chars.len() {
        if chars[at] == '"' && chars[at + 1..].iter().take_while(|&&c| c == '#').count() >= hashes {
            return at + 1 + hashes;
        }
        if chars[at] == '\n' {
            *line += 1;
        }
        at += 1;
    }
    at
}

fn word(tokens: &[Token], at: usize) -> Option<&str> {
    match tokens.get(at) {
        Some(Token {
            kind: Kind::Word(word),
            ..
        }) => Some(word),
        _ => None,
    }
}

fn punct(tokens: &[Token], at: usize) -> Option<char> {
    match tokens.get(at) {
        Some(Token {
            kind: Kind::Punct(c),
            ..
        }) => Some(*c),
        _ => None,
    }
}

/// The index of the token that closes the group opened at `open`, whichever of `(`, `[`, `{` and
/// `<` it is. A `>` that follows a `-` is an arrow, not a closing angle.
fn closing(tokens: &[Token], open: usize) -> usize {
    let mut depth = 0_usize;
    let mut at = open;
    while at < tokens.len() {
        match punct(tokens, at) {
            Some('(' | '[' | '{') => depth += 1,
            Some('<') => depth += 1,
            Some(')' | ']' | '}') => depth = depth.saturating_sub(1),
            Some('>') if at > 0 && punct(tokens, at - 1) != Some('-') => {
                depth = depth.saturating_sub(1);
            }
            _ => {}
        }
        if depth == 0 {
            return at;
        }
        at += 1;
    }
    tokens.len()
}

struct Field {
    name: String,
    line: usize,
    owns: bool,
}

struct Declared {
    name: String,
    fields: Vec<Field>,
}

/// The fields of the body that opens at `open`, in the order they are declared.
fn fields(tokens: &[Token], open: usize, close: usize, braced: bool) -> Vec<Field> {
    let mut found = Vec::new();
    let mut at = open + 1;
    while at < close {
        let mut end = at;
        let mut depth = 0_usize;
        while end < close {
            match punct(tokens, end) {
                Some('(' | '[' | '{' | '<') => depth += 1,
                Some(')' | ']' | '}') => depth = depth.saturating_sub(1),
                Some('>') if end > 0 && punct(tokens, end - 1) != Some('-') => {
                    depth = depth.saturating_sub(1);
                }
                Some(',') if depth == 0 => break,
                _ => {}
            }
            end += 1;
        }
        let mut start = at;
        while punct(tokens, start) == Some('#') && punct(tokens, start + 1) == Some('[') {
            start = closing(tokens, start + 1) + 1;
        }
        if word(tokens, start) == Some("pub") {
            start += 1;
            if punct(tokens, start) == Some('(') {
                start = closing(tokens, start) + 1;
            }
        }
        if start < end {
            let (name, line, typed) = if braced {
                (
                    word(tokens, start).unwrap_or("?").to_string(),
                    tokens[start].line,
                    start + 2,
                )
            } else {
                (found.len().to_string(), tokens[start].line, start)
            };
            let owns = tokens[typed.min(end)..end]
                .iter()
                .any(|t| matches!(&t.kind, Kind::Word(w) if OWNING.contains(&w.as_str())));
            found.push(Field { name, line, owns });
        }
        at = end + 1;
    }
    found
}

/// Every struct a source declares, with its fields.
fn structs(text: &str) -> Vec<Declared> {
    let tokens = lex(text);
    let mut found = Vec::new();
    let mut at = 0;
    while at < tokens.len() {
        if word(&tokens, at) != Some("struct") {
            at += 1;
            continue;
        }
        let Some(name) = word(&tokens, at + 1).map(str::to_string) else {
            at += 1;
            continue;
        };
        let mut body = at + 2;
        if punct(&tokens, body) == Some('<') {
            body = closing(&tokens, body) + 1;
        }
        if word(&tokens, body) == Some("where") {
            while body < tokens.len() && !matches!(punct(&tokens, body), Some('{' | ';')) {
                body += 1;
            }
        }
        let braced = match punct(&tokens, body) {
            Some('{') => true,
            Some('(') => false,
            _ => {
                at += 1;
                continue;
            }
        };
        let close = closing(&tokens, body);
        found.push(Declared {
            name,
            fields: fields(&tokens, body, close, braced),
        });
        at = close;
    }
    found
}

/// The structs of a source whose fields that own a directory are not all the last ones: the
/// struct, the first field that owns one and the line of it, and the first field after it that
/// does not.
fn offences(text: &str) -> Vec<(String, String, usize, String)> {
    structs(text)
        .into_iter()
        .filter_map(|declared| {
            let first = declared.fields.iter().position(|field| field.owns)?;
            let after = declared.fields[first..].iter().find(|field| !field.owns)?;
            Some((
                declared.name.clone(),
                declared.fields[first].name.clone(),
                declared.fields[first].line,
                after.name.clone(),
            ))
        })
        .collect()
}

fn sources(directory: &Path, found: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return;
    };
    let mut entries: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .collect();
    entries.sort();
    for entry in entries {
        let name = entry
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("");
        if entry.is_dir() {
            if !matches!(name, "target" | "node_modules" | ".git") {
                sources(&entry, found);
            }
        } else if entry.extension().is_some_and(|extension| extension == "rs") {
            found.push(entry);
        }
    }
}

/// The workspace's root.
fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the workspace")
}

/// Every offence under the workspace's roots, as `file:line: ...`, with the file and the name of
/// the struct that made it.
fn found_in_the_workspace() -> Vec<(String, String, String)> {
    let workspace = workspace();
    let mut files = Vec::new();
    for root in ROOTS {
        sources(&workspace.join(root), &mut files);
    }
    assert!(
        files.len() > 100,
        "the reading finds the workspace's sources"
    );
    let mut found = Vec::new();
    for file in files {
        let Ok(text) = std::fs::read_to_string(&file) else {
            continue;
        };
        let relative = file
            .strip_prefix(&workspace)
            .expect("under the workspace")
            .to_string_lossy()
            .replace('\\', "/");
        for (name, owning, line, after) in offences(&text) {
            found.push((
                relative.clone(),
                name.clone(),
                format!("{relative}:{line}: `{name}` declares `{owning}` before `{after}`"),
            ));
        }
    }
    found
}

#[test]
fn a_temporary_directory_is_declared_after_every_field_that_holds_a_file_in_it() {
    let found = found_in_the_workspace();
    let unkept: Vec<&str> = found
        .iter()
        .filter(|(file, name, _)| {
            !KEPT
                .iter()
                .any(|(kept_file, kept_name, _)| kept_file == file && kept_name == name)
        })
        .map(|(_, _, message)| message.as_str())
        .collect();
    assert!(
        unkept.is_empty(),
        "a struct drops its fields in the order they are declared, so a directory declared before \
         a field that holds a file in it is removed while the file is open, and on Windows the \
         removal waits for the file for 45 seconds. Declare the field of type TempHost or \
         PrivateTempDir after the others:\n{}",
        unkept.join("\n")
    );
    let stale: Vec<String> = KEPT
        .iter()
        .filter(|(kept_file, kept_name, _)| {
            !found
                .iter()
                .any(|(file, name, _)| file == kept_file && name == kept_name)
        })
        .map(|(file, name, reason)| format!("{file}: `{name}` ({reason})"))
        .collect();
    assert!(
        stale.is_empty(),
        "a struct listed as one that keeps its order no longer needs to:\n{}",
        stale.join("\n")
    );
}

#[test]
fn the_reading_finds_a_directory_declared_before_another_field_however_it_is_written() {
    let wrong = "\
struct Wired {
    _temp: kr_ipc::testing::TempHost,
    service: std::sync::Arc<Service>,
}
";
    assert_eq!(
        offences(wrong),
        [("Wired".into(), "_temp".into(), 2, "service".into())]
    );

    let dressed = "\
pub struct Host<'a, T: Fn(u8) -> u8> where T: Send {
    /// What the host keeps.
    #[allow(dead_code)]
    pub(crate) tree: Option<(u8, PrivateTempDir)>,
    pub task: &'a char,
}
";
    assert_eq!(
        offences(dressed),
        [("Host".into(), "tree".into(), 4, "task".into())]
    );

    assert_eq!(
        offences("struct Pair(TempHost, u8);"),
        [("Pair".into(), "0".into(), 1, "1".into())]
    );
}

#[test]
fn the_reading_passes_a_directory_declared_last_and_words_that_are_not_fields() {
    let right = "\
struct Wired {
    service: Service,
    temp: TempHost,
    work: PrivateTempDir,
}
struct Pair(u8, TempHost);
struct Plain { service: Service }
struct Alone { temp: TempHost }
struct Words { a: u8, /* TempHost */ b: &'static str }
const A: &str = \"struct Bad { temp: TempHost, a: u8 }\";
const B: &str = r#\"struct Bad { temp: TempHost, a: u8 }\"#;
// struct Bad { temp: TempHost, a: u8 }
";
    assert_eq!(offences(right), []);

    let after_a_quote = "\
const QUOTE: char = '\"';
struct Bad { temp: TempHost, a: u8 }
";
    assert_eq!(
        offences(after_a_quote),
        [("Bad".into(), "temp".into(), 2, "a".into())]
    );
}
