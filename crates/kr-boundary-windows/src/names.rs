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

/// The names Windows reads as a device, with or without an extension, in any case. `CONIN$` and
/// `CONOUT$` are the console's input and output.
const DEVICES: &[&str] = &["con", "prn", "aux", "nul", "conin$", "conout$"];

/// Whether Windows reads a path component as a device: the text before its first dot, without
/// trailing spaces, is a device name in any case. `COM` and `LPT` with one digit from 0 to 9, or
/// with one of the superscript digits 1, 2 and 3, are devices; Windows documents the digits 1 to 9
/// and the superscripts, and what the pinned system does with `COM0` and `LPT0` is not recorded,
/// so they are refused as well.
#[must_use]
pub fn is_device_name(component: &str) -> bool {
    let lower = component.to_ascii_lowercase();
    let stem = lower.split('.').next().unwrap_or_default().trim_end();
    DEVICES.contains(&stem) || numbered_device(stem)
}

fn numbered_device(stem: &str) -> bool {
    ["com", "lpt"].iter().any(|prefix| {
        stem.strip_prefix(prefix).is_some_and(|digit| {
            let mut chars = digit.chars();
            matches!(
                (chars.next(), chars.next()),
                (Some('0'..='9' | '\u{b9}' | '\u{b2}' | '\u{b3}'), None)
            )
        })
    })
}

/// Whether `name` is a branch name: components joined by `/`, each of one letter or digit followed
/// by letters, digits, `.`, `_` and `-`; at most 200 bytes; no `..`; no component ending in
/// `.lock`; no component that is a device name ([`is_device_name`]: on Windows the file of
/// `refs/heads/com1` is a device path); no trailing `.` or `/`. The character set also rules out `@{`, `//`, a leading `/`, a
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
            && !is_device_name(component)
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
