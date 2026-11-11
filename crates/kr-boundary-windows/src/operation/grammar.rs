//! The grammars of the typed elements: a path, a revision, a count and a message.
//!
//! Each function answers with the rule that refused, or the form the command line carries. None of
//! them copies the refused text into its answer. Every text is a Rust string, so it is valid text
//! that converts to UTF-16 and back without loss; what remains is the characters and the shapes.

use crate::frame::invocation::{MAX_MESSAGE_BYTES, MAX_PATH_BYTES, MAX_REV_BYTES};
use crate::names::{BRANCH_PREFIX, TAG_PREFIX, is_branch_name, is_device_name, is_oid};

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

fn component(text: &str) -> bool {
    // `.` and `..` end in a dot and are refused with the names that do.
    if text.is_empty() {
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
    if is_device_name(text) {
        return false;
    }
    let lower = text.to_ascii_lowercase();
    // `.git` in any case, and the short name NTFS gives it.
    if lower == ".git" || short_git_name(&lower) {
        return false;
    }
    true
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
    // An empty text has no digits to parse and is refused by the parse below.
    let canonical = text.len() <= 10
        && text.bytes().all(|b| b.is_ascii_digit())
        && (text == "0" || !text.starts_with('0'));
    if !canonical {
        return None;
    }
    text.parse::<u32>()
        .ok()
        .filter(|value| (min..=max).contains(value))
}

/// Checks a revision as a client writes it and returns the form the command line carries: `HEAD`
/// or a branch name or an identifier, followed by at most [`MAX_REVISION_STEPS`] steps of `^`,
/// `^{commit}`, `~N` and `^N`. A branch name is qualified as `refs/heads/<name>`, so a tag never
/// answers to it.
///
/// [`MAX_REV_BYTES`] bounds the text as the client writes it, and it is the only bound of a
/// revision: the prefix this adds is not counted against it, since the readers take the base and
/// the steps apart ([`split_revision`]).
///
/// # Errors
///
/// Returns the rule that refused.
pub fn revision(text: &str) -> Result<Revision, &'static str> {
    if text.len() > MAX_REV_BYTES {
        return Err(RULE_REVISION_LENGTH);
    }
    let (base, steps) = split_at_steps(text);
    let (carried, branch) = if base == "HEAD" || is_oid(base) {
        (base.to_owned(), None)
    } else if is_branch_name(base) {
        let reference = format!("{BRANCH_PREFIX}{base}");
        (reference.clone(), Some(reference))
    } else {
        return Err(RULE_REVISION);
    };
    steps_of(steps)?;
    Ok(Revision {
        spec: format!("{carried}{steps}"),
        branch,
    })
}

/// A revision as [`revision`] qualified it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Revision {
    /// The form the command line carries: the base, qualified, and the steps.
    pub spec: String,
    /// The reference `refs/heads/<name>` the revision starts at, when its base is a branch name. A
    /// revision that starts at `HEAD` or an identifier has none. It comes from the grammar's own
    /// parse of the base, so no check of a reference can be lost for want of parsing it again.
    pub branch: Option<String>,
}

/// Takes a qualified revision, as [`revision`] returns it or as a reader is given it, apart into
/// its base and its steps. The base is `HEAD`, an identifier, `refs/heads/<name>` or
/// `refs/tags/<name>`, and the steps are at most [`MAX_REVISION_STEPS`]; both are bounded by their
/// own grammars, so this has no bound on the whole.
///
/// # Errors
///
/// Returns the rule that refused.
pub fn split_revision(qualified: &str) -> Result<(&str, &str), &'static str> {
    let (base, steps) = split_at_steps(qualified);
    if !(base == "HEAD" || is_oid(base) || qualified_name(base)) {
        return Err(RULE_REVISION);
    }
    steps_of(steps)?;
    Ok((base, steps))
}

fn split_at_steps(text: &str) -> (&str, &str) {
    text.split_at(text.find(['^', '~']).unwrap_or(text.len()))
}

fn qualified_name(text: &str) -> bool {
    text.strip_prefix(BRANCH_PREFIX)
        .or_else(|| text.strip_prefix(TAG_PREFIX))
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
