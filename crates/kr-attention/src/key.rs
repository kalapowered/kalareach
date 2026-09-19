//! Deriving an item's key from the subject the condition is about.
//!
//! A key has to be three things at once: derived, so rebuilding the inbox from the retained events
//! produces the keys it had before; bounded and printable, because it travels on the wire and a
//! client acknowledges by it; and total, because a subject is sometimes a command line or the body
//! of a notification an application wrote, and neither is bounded or well behaved.
//!
//! An identifier minted when an item is raised would satisfy the last two and fail the first: a
//! replay would give the same condition a new key, and section 24's idempotent reconstruction
//! would produce a second inbox. Refusing a subject this module cannot key would satisfy the first
//! two and fail the third: a multi-line command or a long notice would be consumed and then
//! silently dropped, and section 25 requires both of those to reach Attention.
//!
//! So a subject that is already short and printable is used as it is, and any other is replaced by
//! a digest of its exact bytes. The digest is deterministic, so a replay lands on the same item;
//! it is the same length whatever it covers, so the key is bounded; and it is over the whole
//! subject, so two different commands never share one.

use core::fmt::Write;

use kr_protocol::attention::{AttentionKey, AttentionRule};
use sha2::{Digest, Sha256};

/// The character a derived subject starts with, and that no subject used as it stands may.
///
/// Reserving it is what stops a notification body shaped like a digest from landing on the key
/// another subject derives.
pub const DERIVED_MARKER: char = '~';

/// Longest subject used as it stands.
///
/// It leaves room for the longest rule identifier and the separator inside the key's own
/// bound, with the margin a new rule name would need.
pub const MAX_PLAIN_SUBJECT_LEN: usize = 160;

/// How many hexadecimal characters of the digest a derived subject carries.
///
/// Thirty-two is 128 bits. Two subjects of one rule would have to collide in all of them to be
/// confused for each other, which is not a thing a session produces by accident or an application
/// produces on purpose.
pub const DIGEST_CHARS: usize = 32;

/// Returns the key for one rule and one subject.
///
/// # Panics
///
/// Never. Every subject this produces is inside the key's own bound and free of control
/// characters, which is the whole of what [`AttentionKey::of`] refuses.
#[must_use]
pub fn attention_key(rule: AttentionRule, subject: &str) -> AttentionKey {
    AttentionKey::of(rule, &keyable(subject)).expect("a derived subject is always well formed")
}

/// Returns the form of `subject` a key carries.
#[must_use]
pub fn keyable(subject: &str) -> String {
    let plain = !subject.is_empty()
        && subject.len() <= MAX_PLAIN_SUBJECT_LEN
        && !subject.starts_with(DERIVED_MARKER)
        && !subject.chars().any(char::is_control);
    if plain {
        return subject.to_owned();
    }
    let digest = Sha256::digest(subject.as_bytes());
    let mut derived = String::with_capacity(DIGEST_CHARS + 1);
    derived.push(DERIVED_MARKER);
    for byte in digest.iter().take(DIGEST_CHARS / 2) {
        write!(derived, "{byte:02x}").expect("writing to a string cannot fail");
    }
    derived
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_short_printable_subject_is_used_as_it_stands() {
        assert_eq!(keyable("req-1"), "req-1");
        let key = attention_key(AttentionRule::PendingApproval, "req-1");
        assert_eq!(key.as_str(), "attention.pending_approval|req-1");
    }

    #[test]
    fn a_subject_a_key_cannot_carry_is_derived_from_its_exact_bytes() {
        for subject in [
            "",
            "one\nline",
            "a\u{0}b",
            &"s".repeat(MAX_PLAIN_SUBJECT_LEN + 1),
        ] {
            let derived = keyable(subject);
            assert!(derived.starts_with('~'), "{subject:?} was derived");
            assert_eq!(derived.len(), DIGEST_CHARS + 1);
            assert_eq!(derived, keyable(subject), "the derivation is deterministic");
            let key = attention_key(AttentionRule::CommandFailed, subject);
            assert!(key.as_str().len() <= kr_protocol::attention::MAX_ATTENTION_KEY_LEN);
        }
    }

    #[test]
    fn two_subjects_that_differ_get_two_keys() {
        let left = attention_key(
            AttentionRule::CommandFailed,
            &format!("a{}", "x".repeat(400)),
        );
        let right = attention_key(
            AttentionRule::CommandFailed,
            &format!("b{}", "x".repeat(400)),
        );
        assert_ne!(left, right);
    }

    #[test]
    fn a_derived_subject_cannot_be_forged_by_a_plain_one() {
        // The marker is reserved. A notification body shaped like a digest is derived rather than
        // used as it stands, so it cannot land on the key another subject derives.
        let forged = keyable("~00112233445566778899aabbccddeeff");
        assert!(forged.starts_with(DERIVED_MARKER));
        assert_ne!(forged, "~00112233445566778899aabbccddeeff");
    }
}
