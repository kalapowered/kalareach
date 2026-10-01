//! The words the product's sources write: a message wrapped over two lines keeps one space where
//! the line broke.
//!
//! A string literal ends a line with a backslash to wrap, and the compiler drops the line break and
//! the indentation after it. A literal joined onto one line instead carries the indentation into
//! the message as a run of spaces, which a person reads in a refusal, a log line or the generated
//! schema. Nothing but a reading of the sources sees it, so this one reads them.

use std::path::{Path, PathBuf};

/// The shortest run of spaces between two words of prose that is read as a lost line break. A
/// column of a report keeps its figures apart with fewer, and nothing the sources print keeps
/// words apart with more.
const LOST_BREAK: usize = 12;

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..")
}

/// Every Rust source under `directory`, skipping what a build or an install leaves.
fn sources(directory: &Path, found: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if path.is_dir() {
            if !matches!(
                name.as_ref(),
                "target" | "node_modules" | ".git" | ".targets" | "shells"
            ) && !name.starts_with("target-")
            {
                sources(&path, found);
            }
        } else if name.ends_with(".rs") {
            found.push(path);
        }
    }
}

/// The string literals that open and close on one line of `source`, with their line numbers.
///
/// The source is read as Rust is: a comment of either kind, a raw string, a character and a
/// string that runs over several lines are passed over, wherever their lines begin. A literal that
/// runs over several lines is not read, since a line break inside it is the writer's, and the lines
/// of an embedded program or a query keep their own indentation; a literal that holds an escaped
/// line break is not read for the same reason.
fn literals(source: &str) -> Vec<(usize, &str)> {
    let bytes = source.as_bytes();
    let mut found = Vec::new();
    let mut line = 1;
    let mut at = 0;
    while at < bytes.len() {
        match bytes[at] {
            b'\n' => {
                line += 1;
                at += 1;
            }
            // A comment of the line.
            b'/' if bytes.get(at + 1) == Some(&b'/') => {
                while at < bytes.len() && bytes[at] != b'\n' {
                    at += 1;
                }
            }
            // A block comment, which nests.
            b'/' if bytes.get(at + 1) == Some(&b'*') => {
                let mut depth = 0_usize;
                while at < bytes.len() {
                    if bytes[at] == b'/' && bytes.get(at + 1) == Some(&b'*') {
                        depth += 1;
                        at += 2;
                    } else if bytes[at] == b'*' && bytes.get(at + 1) == Some(&b'/') {
                        depth -= 1;
                        at += 2;
                        if depth == 0 {
                            break;
                        }
                    } else {
                        if bytes[at] == b'\n' {
                            line += 1;
                        }
                        at += 1;
                    }
                }
            }
            // A raw string, which ends at a quote and as many hashes as it opened with: `r`, `br`
            // and `cr`, when the letters do not end a longer name.
            b'r' | b'b' | b'c'
                if (at == 0
                    || !(bytes[at - 1].is_ascii_alphanumeric() || bytes[at - 1] == b'_'))
                    && (bytes[at] == b'r' || bytes.get(at + 1) == Some(&b'r')) =>
            {
                let opened = at + if bytes[at] == b'r' { 1 } else { 2 };
                let mut hashes = 0;
                while bytes.get(opened + hashes) == Some(&b'#') {
                    hashes += 1;
                }
                if bytes.get(opened + hashes) == Some(&b'"') {
                    at = opened + hashes + 1;
                    let mut closing = vec![b'"'];
                    closing.extend(std::iter::repeat_n(b'#', hashes));
                    while at < bytes.len() && !bytes[at..].starts_with(&closing) {
                        if bytes[at] == b'\n' {
                            line += 1;
                        }
                        at += 1;
                    }
                    at += closing.len();
                } else {
                    at += 1;
                }
            }
            // A character literal, which may be a quote; a lifetime has no closing quote.
            b'\'' => {
                let rest = &source[at + 1..];
                let mut characters = rest.chars();
                let width = match characters.next() {
                    // The escaped character, and then what runs to the closing quote: `\'`, `\n`, `\x41`.
                    Some('\\') => rest[2..].find('\'').map(|found| found + 3),
                    Some(first) if characters.next() == Some('\'') => Some(first.len_utf8() + 1),
                    _ => None,
                };
                at += 1 + width.unwrap_or(0);
            }
            b'"' => {
                let start = at + 1;
                let begun = line;
                let mut end = start;
                let mut over_lines = false;
                while end < bytes.len() && bytes[end] != b'"' {
                    if bytes[end] == b'\n' {
                        over_lines = true;
                        line += 1;
                    }
                    if bytes[end] == b'\\' {
                        // The escaped character is not read: `\"` is not the end, and a `\` before a
                        // line break wraps the literal.
                        if bytes.get(end + 1) == Some(&b'\n') {
                            over_lines = true;
                            line += 1;
                        }
                        end += 1;
                    }
                    end += 1;
                }
                if !over_lines {
                    found.push((begun, &source[start..end.min(bytes.len())]));
                }
                at = end + 1;
            }
            _ => at += 1,
        }
    }
    found
}

/// The lines of `source` that carry a string literal with a run of `LOST_BREAK` spaces or more
/// between two words of prose, and the literal.
///
/// Prose is lower-case words: a literal that begins with a space is a row of a report, and a run
/// between a name and an upper-case type is a column of a query.
fn lost_breaks(source: &str) -> Vec<(usize, String)> {
    literals(source)
        .into_iter()
        .filter(|(_, text)| !text.starts_with(' ') && !text.contains("\\n"))
        .filter(|(_, text)| {
            let bytes = text.as_bytes();
            let mut at = 0;
            while at < bytes.len() {
                if bytes[at] != b' ' {
                    at += 1;
                    continue;
                }
                let run = bytes[at..].iter().take_while(|byte| **byte == b' ').count();
                let before = at.checked_sub(1).map(|before| bytes[before]);
                let after = bytes.get(at + run).copied();
                if run >= LOST_BREAK
                    && before
                        .is_some_and(|byte| byte.is_ascii_lowercase() || b",;:.)}".contains(&byte))
                    && after.is_some_and(|byte| byte.is_ascii_lowercase() || byte == b'{')
                {
                    return true;
                }
                at += run;
            }
            false
        })
        .map(|(line, text)| (line, text.to_owned()))
        .collect()
}

/// No message in the repository's Rust carries the indentation of a wrapped line: each is written
/// with the backslash that wraps it, which leaves its words one space apart.
#[test]
fn no_message_keeps_the_indentation_of_a_line_it_was_wrapped_over() {
    let root = repository();
    let mut files = Vec::new();
    sources(&root, &mut files);
    assert!(
        files.len() > 500,
        "the reading reaches the repository's sources: {} files",
        files.len()
    );
    let mut lost = Vec::new();
    for file in files {
        let Ok(source) = std::fs::read_to_string(&file) else {
            continue;
        };
        for (line, text) in lost_breaks(&source) {
            let shown = file.strip_prefix(&root).unwrap_or(&file).display();
            lost.push(format!("{shown}:{line}: {text}"));
        }
    }
    assert!(
        lost.is_empty(),
        "a message carries a run of spaces where its line was wrapped:\n{}",
        lost.join("\n")
    );
}

/// The control: the reading names a message joined onto one line, and passes the same words
/// wrapped, a row of a report, a column of a query, a literal that wraps over lines and a comment.
#[test]
fn the_reading_names_a_lost_wrap_and_passes_what_is_laid_out_on_purpose() {
    // Built here, so that this file's own text carries no run of spaces for the reading above.
    let gap = " ".repeat(22);
    let joined = format!(
        "let said = \"the branch moved while this host was reading it, so{gap}what it read differs\";"
    );
    assert_eq!(
        lost_breaks(&joined),
        [(
            1,
            format!("the branch moved while this host was reading it, so{gap}what it read differs")
        )]
    );

    let wrapped = format!(
        "let said = \"the branch moved while this host was reading it, so \\\n{gap}what it read differs\";"
    );
    assert!(lost_breaks(&wrapped).is_empty(), "{wrapped}");

    // A raw byte string whose content ends in a backslash leaves the next literal the one read.
    let after_raw = format!("let bytes = br\"\\\"; let said = \"left{gap}right\";");
    assert_eq!(
        lost_breaks(&after_raw),
        [(1, format!("left{gap}right"))],
        "{after_raw}"
    );

    // An escaped quote is a character, and the literal after it is the one read.
    let after_quote = format!("let both = ['\\'','\"']; let said = \"left{gap}right\";");
    assert_eq!(
        lost_breaks(&after_quote),
        [(1, format!("left{gap}right"))],
        "{after_quote}"
    );

    let row = " ".repeat(16);
    let laid_out = [
        format!("/* \"left{gap}right\" */ let kept = 1;"),
        format!("/* a /* nested */ \"left{gap}right\" */ let kept = 1;"),
        format!("let raw = r#\"left{gap}right\"#;"),
        format!("let raw = br#\"left{gap}right\"#;"),
        format!("let raw = cr\"left{gap}right\";"),
        format!("let program = \"first line\n{gap}second line\";"),
        format!("let runs = \"one\\\n{gap}two\";"),
        format!("println!(\"  verdict{row}not valid: the read does not end\");"),
        format!("let column = \"revision{row}INTEGER NOT NULL,\";"),
        "let program = \"fn f() {\\n    body();\\n}\";".to_owned(),
        format!("let quote = '\"'; // so{gap}what it read"),
    ];
    for source in laid_out {
        assert!(lost_breaks(&source).is_empty(), "{source}");
    }
}
