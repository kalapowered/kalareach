//! The grammar of the names a request and a repository use: a branch, a reference under
//! `refs/heads/`, and an object identifier. These are the grammars the broker admits, which are
//! narrower than Git's own, so that a name never needs Git to decide what it means.

use crate::frame::invocation::MAX_NAME_BYTES;

/// What a reference to a branch starts with.
pub const BRANCH_PREFIX: &str = "refs/heads/";

/// What a reference to a tag starts with.
pub const TAG_PREFIX: &str = "refs/tags/";

/// The digits of an object identifier of the only object format the broker admits, SHA-1.
pub const OID_DIGITS: usize = 40;

/// Whether `name` is a branch name: components joined by `/`, each of one letter or digit followed
/// by letters, digits, `.`, `_` and `-`; at most 200 bytes; no `..`; no component ending in
/// `.lock`; no trailing `.` or `/`. The character set also rules out `@{`, `//`, a leading `/`, a
/// component that starts with `.` or `-`, spaces and every character Git refuses in a name.
#[must_use]
pub fn is_branch_name(name: &str) -> bool {
    if name.len() > MAX_NAME_BYTES || name.contains("..") || name.ends_with('.') {
        return false;
    }
    name.split('/').all(|component| {
        let mut bytes = component.bytes();
        bytes
            .next()
            .is_some_and(|first| first.is_ascii_alphanumeric())
            && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
            && !component.ends_with(".lock")
    })
}

/// Whether `text` is an object identifier: [`OID_DIGITS`] lowercase hexadecimal digits.
#[must_use]
pub fn is_oid(text: &str) -> bool {
    text.len() == OID_DIGITS
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
