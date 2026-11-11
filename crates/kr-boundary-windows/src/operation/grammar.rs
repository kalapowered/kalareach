//! The grammars of the typed elements: a path, a revision, a count and a message.
//!
//! Each function answers with the rule that refused, or the form the command line carries. None of
//! them copies the refused text into its answer. Every text is a Rust string, so it is valid text
//! that converts to UTF-16 and back without loss; what remains is the characters and the shapes.

use crate::frame::invocation::{MAX_MESSAGE_BYTES, MAX_PATH_BYTES, MAX_REV_BYTES};
use crate::names::{BRANCH_PREFIX, is_branch_name, is_oid};

/// The most paths a command takes after `--`.
pub const MAX_PATHS: usize = 256;
/// The most components a path has.
pub const MAX_PATH_COMPONENTS: usize = 32;
/// The most steps a revision has after its base: `^`, `^{commit}`, `~N` and `^N`.
pub const MAX_REVISION_STEPS: usize = 4;

/// A path that is longer than [`MAX_PATH_BYTES`].
pub const RULE_PATH_LENGTH: &str = "operation-path-length";
/// A path with more than [`MAX_PATH_COMPONENTS`] components.
pub const RULE_PATH_DEPTH: &str = "operation-path-depth";
/// A path outside the grammar.
pub const RULE_PATH: &str = "operation-path";
/// A revision outside the grammar.
pub const RULE_REVISION: &str = "operation-revision";
/// A revision longer than [`MAX_REV_BYTES`].
pub const RULE_REVISION_LENGTH: &str = "operation-revision-length";
/// A message over [`MAX_MESSAGE_BYTES`] or over the bound of its use.
pub const RULE_MESSAGE_LENGTH: &str = "operation-message-length";
/// A message with a control character other than a tab or a newline.
pub const RULE_MESSAGE_CONTROL: &str = "operation-message-control";
/// A message with an empty first line, or with a newline where one line is required.
pub const RULE_MESSAGE_LINES: &str = "operation-message-lines";

/// Whether a character is one the broker refuses in any element: a control character below 0x20 or
/// 0x7f.
#[must_use]
pub fn is_control(character: char) -> bool {
    character < ' ' || character == '\u{7f}'
}

/// Checks a path: relative, written with `/`, and made of components that Windows and Git both
/// read as ordinary names. A path that is exactly `.` is the tree's root.
///
/// # Errors
///
/// Returns the rule that refused.
pub fn path(text: &str) -> Result<(), &'static str> {
    if text.len() > MAX_PATH_BYTES {
        return Err(RULE_PATH_LENGTH);
    }
    if text == "." {
        return Ok(());
    }
    if text.split('/').count() > MAX_PATH_COMPONENTS {
        return Err(RULE_PATH_DEPTH);
    }
    if text.split('/').all(component) {
        Ok(())
    } else {
        Err(RULE_PATH)
    }
}

/// The names Windows reads as a device, with or without an extension, in any case.
const DEVICES: &[&str] = &["con", "prn", "aux", "nul"];

fn component(text: &str) -> bool {
    if text.is_empty() || text == "." || text == ".." {
        return false;
    }
    if text
        .chars()
        .any(|c| is_control(c) || matches!(c, '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|'))
    {
        return false;
    }
    if text.ends_with(['.', ' ']) {
        return false;
    }
    let lower = text.to_ascii_lowercase();
    let stem = lower.split('.').next().unwrap_or_default().trim_end();
    if DEVICES.contains(&stem) || numbered_device(stem) {
        return false;
    }
    // `.git` in any case, and the short name NTFS gives it.
    if lower == ".git" || short_git_name(&lower) {
        return false;
    }
    true
}

fn numbered_device(stem: &str) -> bool {
    ["com", "lpt"].iter().any(|prefix| {
        stem.strip_prefix(prefix)
            .is_some_and(|digit| matches!(digit.as_bytes(), [b'1'..=b'9']))
    })
}

fn short_git_name(lower: &str) -> bool {
    lower
        .strip_prefix("git~")
        .is_some_and(|digits| !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()))
}

/// Checks a message: at most `max_bytes`, no control character but tab and newline, a first line
/// that is not empty, and, where `one_line`, no newline.
///
/// # Errors
///
/// Returns the rule that refused.
pub fn message(text: &str, max_bytes: usize, one_line: bool) -> Result<(), &'static str> {
    debug_assert!(max_bytes <= MAX_MESSAGE_BYTES);
    if text.len() > max_bytes.min(MAX_MESSAGE_BYTES) {
        return Err(RULE_MESSAGE_LENGTH);
    }
    if text
        .chars()
        .any(|c| is_control(c) && c != '\t' && c != '\n')
    {
        return Err(RULE_MESSAGE_CONTROL);
    }
    if text.is_empty() || text.starts_with('\n') || (one_line && text.contains('\n')) {
        return Err(RULE_MESSAGE_LINES);
    }
    Ok(())
}

/// A decimal count: digits only, no sign, no leading zero, within the bounds.
#[must_use]
pub fn count(text: &str, min: u32, max: u32) -> Option<u32> {
    let canonical = !text.is_empty()
        && text.len() <= 10
        && text.bytes().all(|b| b.is_ascii_digit())
        && (text == "0" || !text.starts_with('0'));
    if !canonical {
        return None;
    }
    text.parse::<u32>()
        .ok()
        .filter(|value| (min..=max).contains(value))
}

/// What a revision may start with, for the readers: the qualified forms the broker resolves.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Base {
    /// What a client writes: `HEAD`, a branch name, an identifier.
    Client,
    /// What a reader takes: `HEAD`, `refs/heads/<name>`, `refs/tags/<name>`, an identifier.
    Qualified,
}

/// Checks a revision as a client writes it and returns the form the command line carries: `HEAD`
/// or a branch name or an identifier, followed by at most [`MAX_REVISION_STEPS`] steps of `^`,
/// `^{commit}`, `~N` and `^N`. A branch name is qualified as `refs/heads/<name>`, so a tag never
/// answers to it.
///
/// # Errors
///
/// Returns the rule that refused.
pub fn revision(text: &str) -> Result<String, &'static str> {
    revision_of(text, Base::Client)
}

/// Checks a revision as a reader takes it: like [`revision`], with the base written in full as
/// `HEAD`, `refs/heads/<name>`, `refs/tags/<name>` or an identifier.
///
/// # Errors
///
/// Returns the rule that refused.
pub fn qualified_revision(text: &str) -> Result<(), &'static str> {
    revision_of(text, Base::Qualified).map(|_| ())
}

fn revision_of(text: &str, kind: Base) -> Result<String, &'static str> {
    if text.len() > MAX_REV_BYTES {
        return Err(RULE_REVISION_LENGTH);
    }
    let split = text.find(['^', '~']).unwrap_or(text.len());
    let (base, steps) = text.split_at(split);
    let carried = match (kind, base) {
        (_, "HEAD") => "HEAD".to_owned(),
        (_, oid) if is_oid(oid) => oid.to_owned(),
        (Base::Client, name) if is_branch_name(name) => format!("{BRANCH_PREFIX}{name}"),
        (Base::Qualified, full) if qualified_name(full) => full.to_owned(),
        _ => return Err(RULE_REVISION),
    };
    steps_of(steps)?;
    Ok(format!("{carried}{steps}"))
}

fn qualified_name(text: &str) -> bool {
    text.strip_prefix(BRANCH_PREFIX)
        .or_else(|| text.strip_prefix("refs/tags/"))
        .is_some_and(is_branch_name)
}

fn steps_of(mut rest: &str) -> Result<(), &'static str> {
    let mut steps = 0;
    while !rest.is_empty() {
        steps += 1;
        if steps > MAX_REVISION_STEPS {
            return Err(RULE_REVISION);
        }
        if let Some(after) = rest.strip_prefix("^{commit}") {
            rest = after;
        } else if let Some(after) = rest.strip_prefix('^') {
            let digits = leading_digits(after);
            if !digits.is_empty() && count(digits, 1, 1000).is_none() {
                return Err(RULE_REVISION);
            }
            rest = &after[digits.len()..];
        } else if let Some(after) = rest.strip_prefix('~') {
            let digits = leading_digits(after);
            if count(digits, 1, 1000).is_none() {
                return Err(RULE_REVISION);
            }
            rest = &after[digits.len()..];
        } else {
            return Err(RULE_REVISION);
        }
    }
    Ok(())
}

fn leading_digits(text: &str) -> &str {
    let end = text
        .bytes()
        .position(|b| !b.is_ascii_digit())
        .unwrap_or(text.len());
    &text[..end]
}
