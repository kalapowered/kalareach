//! The scan of an attributes file for a driver Git would be told to run.
//!
//! Git runs a `filter`, a `diff` or a `merge` driver only when a configuration names a program for
//! it, and the configuration the broker admits names none. A file that selects a driver would then
//! be handled by Git as if it selected none: Git LFS's `filter=lfs` would store pointer files in
//! place of the content. The danger is that silence, so a file that selects a driver this release
//! cannot run is refused before Git starts.
//!
//! The scan reads text. It cuts a line into the pieces Git could take for an attribute, at any
//! byte up to the space and at every quotation mark, and looks at each piece after the pattern, so
//! a spelling Git would read differently can only make it refuse more, never less.

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
    for (index, line) in bytes.split(|byte| *byte == b'\n').enumerate() {
        let line = line.trim_ascii_start();
        if line.is_empty() || line.starts_with(b"#") {
            continue;
        }
        let at = index + 1;
        if line.starts_with(MACRO_PREFIX) {
            return Err(line_refusal(
                RULE_MACRO,
                "defines an attribute macro, which this release does not support",
                at,
            ));
        }
        // The first piece is the pattern, unless it opens with a quotation mark: Git may or may
        // not read such a pattern as quoted, and an attribute may follow its closing quotation
        // mark with no space between, so a quotation mark ends a piece and every piece of such a
        // line is looked at.
        let skip = usize::from(!line.starts_with(b"\""));
        for piece in line
            .split(|byte| *byte <= b' ' || *byte == 0x7f || *byte == b'"')
            .filter(|piece| !piece.is_empty())
            .skip(skip)
        {
            if let Some((rule, detail)) = selects_driver(piece) {
                return Err(line_refusal(rule, detail, at));
            }
        }
    }
    Ok(())
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
