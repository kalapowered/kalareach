//! The scan of an attributes file for a driver Git would be told to run.
//!
//! Git runs a `filter`, a `diff` or a `merge` driver only when a configuration names a program for
//! it, and the configuration the broker admits names none. A file that selects a driver would then
//! be handled by Git as if it selected none: Git LFS's `filter=lfs` would store pointer files in
//! place of the content. The danger is that silence, so a file that selects a driver this release
//! cannot run is refused before Git starts.
//!
//! The scan reads a line as Git does. The blanks are a space, a tab, a carriage return and a line
//! feed and no other byte. The pattern is a quoted string that unquotes, or else the text up to the
//! first blank; every token after it is an attribute, up to the next blank, and a value is all of
//! the token after its first `=`, quotation marks included.
//!
//! Two things Git does depend on where the bytes came from or on how it stores a line, so the scan
//! reads the file more than one way and reports what any reading shows. Git reads a line as a C
//! string, which ends at its first NUL, so each line is read cut at the NUL and whole. Git removes a
//! UTF-8 byte order mark from line 1 of a file it reads from disk and keeps it in a copy from the
//! index or a tree, so a file that starts with the mark is read with it and without it.

use crate::frame::invocation::RefusedKind;
use crate::refusal::Refusal;

/// The most bytes of one attributes file the scan reads.
pub const MAX_ATTRIBUTES_BYTES: usize = 1024 * 1024;

/// The names of Git's built-in diff drivers, which select a hunk-header pattern and start no
/// program. These are the 25 names of the built-in hunk-header patterns in the attribute manual of
/// Git for Windows 2.55.0.windows.5, the Git that Windows hosts use, in the manual's order.
pub const BUILT_IN_DIFF_DRIVERS: &[&str] = &[
    "ada", "bash", "bibtex", "cpp", "csharp", "css", "dts", "elixir", "fortran", "fountain",
    "golang", "html", "java", "kotlin", "markdown", "matlab", "objc", "pascal", "perl", "php",
    "python", "ruby", "rust", "scheme", "tex",
];

/// The values of `merge` that name Git's own strategies, not a driver.
pub const BUILT_IN_MERGE_VALUES: &[&str] = &["text", "binary", "union"];

/// The refusal for a file over [`MAX_ATTRIBUTES_BYTES`].
pub const RULE_SIZE: &str = "attributes-size";
/// The refusal for a `filter` that selects a driver.
pub const RULE_FILTER: &str = "attributes-filter";
/// The refusal for a `diff` that selects a driver Git does not have built in.
pub const RULE_DIFF: &str = "attributes-diff";
/// The refusal for a `merge` that selects a driver.
pub const RULE_MERGE: &str = "attributes-merge";
/// The refusal for a macro definition.
pub const RULE_MACRO: &str = "attributes-macro";

/// Scans the bytes of one attributes file.
///
/// Refused: a `filter` attribute set, or given any value; a `diff` given a value that is not the
/// name of a built-in driver; a `merge` given a value other than `text`, `binary` or `union`; a
/// negated or unset attribute given a value; any line that defines a macro. Allowed: `diff`,
/// `-diff`, `!diff`, `merge`, `-merge`, `!merge`, `-filter`, `!filter` and every other attribute.
///
/// A refusal names the rule and the line, never the pattern or the value.
///
/// # Errors
///
/// Returns a refusal of kind `repository` for the first line that selects a driver or defines a
/// macro, and for a file over [`MAX_ATTRIBUTES_BYTES`].
pub fn scan_attributes(bytes: &[u8]) -> Result<(), Refusal> {
    if bytes.len() > MAX_ATTRIBUTES_BYTES {
        return Err(refusal(
            RULE_SIZE,
            "an attributes file of this repository is too large for this release",
        ));
    }
    scan_text(bytes)?;
    // Git removes a byte order mark from the start of line 1 of a file it reads from disk (the
    // working tree and `info/attributes`) and keeps it in a copy from the index or a tree. The
    // scan does not know which it was given, so it reads the file both ways.
    if let Some(without) = bytes.strip_prefix(BYTE_ORDER_MARK) {
        scan_text(without)?;
    }
    Ok(())
}

/// The UTF-8 encoding of U+FEFF.
const BYTE_ORDER_MARK: &[u8] = b"\xef\xbb\xbf";

/// Scans the lines of a text, each as Git reads it and whole.
fn scan_text(bytes: &[u8]) -> Result<(), Refusal> {
    for (index, line) in bytes.split(|byte| *byte == b'\n').enumerate() {
        let at = index + 1;
        // Git reads a line as a C string, which ends at its first NUL; what follows is invisible
        // to it. The line is read cut there, which is what Git sees, and whole, which shows what
        // a reader that does not stop at a NUL would see; either reading may refuse.
        let seen = line.split(|byte| *byte == 0).next().unwrap_or_default();
        scan_line(seen, at)?;
        if seen.len() != line.len() {
            scan_line(line, at)?;
        }
    }
    Ok(())
}

/// Scans one line, the bytes between two line feeds or up to a NUL.
fn scan_line(line: &[u8], at: usize) -> Result<(), Refusal> {
    let line = skip_blanks(line);
    if line.is_empty() || line.starts_with(b"#") {
        return Ok(());
    }
    let (pattern, attributes) = read_pattern(line);
    if pattern.starts_with(MACRO_PREFIX) {
        return Err(line_refusal(
            RULE_MACRO,
            "defines an attribute macro, which this release does not support",
            at,
        ));
    }
    // Every token after the pattern is an attribute, up to the next blank, and a value is
    // everything after the first `=` of its token.
    for token in attributes
        .split(|byte| is_blank(*byte))
        .filter(|token| !token.is_empty())
    {
        if let Some((rule, detail)) = selects_driver(token) {
            return Err(line_refusal(rule, detail, at));
        }
    }
    Ok(())
}

/// The bytes Git separates a pattern and its attributes by, and the only ones: a space, a tab, a
/// carriage return and a line feed. A form feed, a control byte and DEL are ordinary bytes. A line
/// feed ends the line before any byte of it is tested, so it is not listed here.
const fn is_blank(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\r')
}

fn skip_blanks(line: &[u8]) -> &[u8] {
    let start = line
        .iter()
        .position(|byte| !is_blank(*byte))
        .unwrap_or(line.len());
    &line[start..]
}

/// Splits a line, with its leading blanks gone, into its pattern and the rest, as Git does. A
/// pattern that opens with a quotation mark and unquotes ends at the closing one, and its
/// attributes may follow with no blank between. Any other pattern, and one that does not unquote,
/// is the text up to the first blank.
fn read_pattern(line: &[u8]) -> (Vec<u8>, &[u8]) {
    if line.starts_with(b"\"")
        && let Some((pattern, end)) = unquote(line)
    {
        return (pattern, &line[end..]);
    }
    let end = line
        .iter()
        .position(|byte| is_blank(*byte))
        .unwrap_or(line.len());
    (line[..end].to_vec(), &line[end..])
}

/// Unquotes a string that opens with a quotation mark, as Git's C-style unquoting does: `\a`, `\b`,
/// `\f`, `\n`, `\r`, `\t`, `\v`, `\\`, `\"` and three octal digits that start with 0 to 3. Returns
/// the bytes (a control escape as a NUL: only a macro prefix reads them) and where the text after
/// the closing quotation mark begins, or `None` for an escape Git does not know and for a string
/// that is not closed.
fn unquote(line: &[u8]) -> Option<(Vec<u8>, usize)> {
    let mut bytes = Vec::new();
    let mut at = 1;
    loop {
        match *line.get(at)? {
            b'"' => return Some((bytes, at + 1)),
            b'\\' => {
                at += 1;
                let unescaped = match *line.get(at)? {
                    // A control byte, which can begin no macro prefix, so its value is not kept.
                    b'a' | b'b' | b'f' | b'n' | b'r' | b't' | b'v' => 0,
                    escaped @ (b'\\' | b'"') => escaped,
                    first @ b'0'..=b'3' => {
                        let (second, third) = (*line.get(at + 1)?, *line.get(at + 2)?);
                        if !matches!(second, b'0'..=b'7') || !matches!(third, b'0'..=b'7') {
                            return None;
                        }
                        at += 2;
                        ((first - b'0') << 6) | ((second - b'0') << 3) | (third - b'0')
                    }
                    _ => return None,
                };
                bytes.push(unescaped);
                at += 1;
            }
            byte => {
                bytes.push(byte);
                at += 1;
            }
        }
    }
}

/// The start of a line that defines a macro.
const MACRO_PREFIX: &[u8] = b"[attr]";

/// Whether one piece of a line selects a driver, and the rule and text that refuse it.
fn selects_driver(piece: &[u8]) -> Option<(&'static str, &'static str)> {
    let (negated, rest) = match piece.split_first() {
        Some((b'-' | b'!', rest)) => (true, rest),
        _ => (false, piece),
    };
    let (name, value) = match rest.iter().position(|byte| *byte == b'=') {
        Some(at) => (&rest[..at], Some(&rest[at + 1..])),
        None => (rest, None),
    };
    let builtin = |names: &[&str]| {
        !negated && value.is_some_and(|value| names.iter().any(|name| name.as_bytes() == value))
    };
    match name {
        b"filter" if negated && value.is_none() => None,
        b"filter" => Some((
            RULE_FILTER,
            "stores files through a conversion program (Git LFS, for example), which this release does not support",
        )),
        b"diff" if value.is_none() || builtin(BUILT_IN_DIFF_DRIVERS) => None,
        b"diff" => Some((
            RULE_DIFF,
            "names a diff driver that this release does not support",
        )),
        b"merge" if value.is_none() || builtin(BUILT_IN_MERGE_VALUES) => None,
        b"merge" => Some((
            RULE_MERGE,
            "names a merge driver that this release does not support",
        )),
        _ => None,
    }
}

fn refusal(rule: &'static str, detail: &str) -> Refusal {
    Refusal::new(RefusedKind::Repository, rule, detail)
}

fn line_refusal(rule: &'static str, detail: &str, line: usize) -> Refusal {
    refusal(rule, &format!("line {line} of an attributes file {detail}"))
}
