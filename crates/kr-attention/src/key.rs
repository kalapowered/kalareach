//! Deriving an item's key from the subject the condition is about.
//!
//! A key has to be four things at once: derived, so rebuilding the inbox from the retained events
//! produces the keys it had before; bounded, because it travels on the wire and a client
//! acknowledges and continues a page by it; total, because a subject is sometimes a command line
//! or the body of a notification an application wrote, and neither is bounded or well behaved; and
//! free of the session's own text, because a key reaches every caller that may read the inbox and
//! a caller the host cannot narrow retained content to is served the record without that text.
//!
//! An identifier minted when an item is raised would satisfy the last three and fail the first: a
//! replay would give the same condition a new key, and section 24's idempotent reconstruction
//! would produce a second inbox. Carrying the subject itself would satisfy the first and fail the
//! last: a command line or a notification body would travel inside the key to a caller the item's
//! own text is withheld from.
//!
//! So every subject is replaced by a digest of its exact bytes. The digest is deterministic, so a
//! replay lands on the same item; it is the same length whatever it covers, so the key is bounded;
//! it is over the whole subject, so two different commands never share one; and it carries none of
//! what it was taken over.

use core::fmt::Write;

use kr_protocol::attention::{AttentionKey, AttentionRule};
use sha2::{Digest, Sha256};

/// The character every derived subject starts with.
///
/// It is what makes a key legible as a derivation rather than as something a session wrote.
pub const DERIVED_MARKER: char = '~';

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

/// Returns the form of `subject` a key carries: a digest of its exact bytes, and nothing else.
#[must_use]
pub fn keyable(subject: &str) -> String {
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
    fn a_key_carries_a_digest_rather_than_the_subject() {
        for subject in [
            "req-1",
            "git push --force origin main",
            "the build finished",
            "",
            "one\nline",
            "a\u{0}b",
            &"s".repeat(400),
        ] {
            let derived = keyable(subject);
            assert!(
                derived.starts_with(DERIVED_MARKER),
                "{subject:?} is derived"
            );
            assert_eq!(derived.len(), DIGEST_CHARS + 1);
            assert_eq!(derived, keyable(subject), "the derivation is deterministic");
            let key = attention_key(AttentionRule::CommandFailed, subject);
            assert!(key.as_str().len() <= kr_protocol::attention::MAX_ATTENTION_KEY_LEN);
            if !subject.is_empty() {
                assert!(
                    !key.as_str().contains(subject),
                    "{subject:?} does not travel inside its own key"
                );
            }
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
    fn one_subject_under_two_rules_gets_two_keys() {
        let approval = attention_key(AttentionRule::PendingApproval, "req-1");
        let input = attention_key(AttentionRule::PendingInput, "req-1");
        assert_ne!(approval, input);
        assert!(
            approval
                .as_str()
                .starts_with("attention.pending_approval|~")
        );
    }
}
