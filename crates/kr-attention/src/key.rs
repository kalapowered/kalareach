//! Deriving an item's key from the subject the condition is about.
//!
//! A key has to be five things at once: derived, so rebuilding the inbox from the retained events
//! produces the keys it had before; bounded, because it travels on the wire and a client
//! acknowledges and continues a page by it; total, because a subject is sometimes a command line
//! or the body of a notification an application wrote, and neither is bounded or well behaved;
//! free of the session's own text, because a key reaches every caller that may read the inbox and
//! a caller the host cannot narrow retained content to is served the record without that text; and
//! **not answerable**, because a digest anybody can compute is one a reader can try candidate
//! texts against until one of them matches.
//!
//! An identifier minted when an item is raised would satisfy the last four and fail the first: a
//! replay would give the same condition a new key, and section 24's idempotent reconstruction
//! would produce a second inbox. A plain digest satisfies the first four and fails the last: there
//! are not many things a notification says, and trying them is cheap.
//!
//! So a key carries a digest of the subject under a secret of the store's own. It is deterministic
//! inside that store, so a replay lands on the same item; it is the same length whatever it
//! covers, so the key is bounded; it is over the whole subject, so two subjects never share one;
//! it carries none of what it was taken over; and without the secret it cannot be checked against
//! a guess.

use core::fmt::Write;

use hmac::{Hmac, KeyInit, Mac};
use kr_protocol::attention::{AttentionKey, AttentionRule};
use sha2::Sha256;

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

/// How many bytes the secret a store derives its keys under is.
pub const SECRET_BYTES: usize = 32;

/// The secret one store derives its keys under.
///
/// It is random, it is written down with the rest of the state, and it never leaves the host: a
/// key is only useful for naming an item, and a reader who cannot compute one cannot ask whether a
/// guess produced it. Two stores therefore give the same subject different keys, which is exactly
/// what stops a key being a name anybody can work out.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct KeySecret([u8; SECRET_BYTES]);

impl core::fmt::Debug for KeySecret {
    /// Prints that there is one, and never what it is.
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("KeySecret(..)")
    }
}

impl Default for KeySecret {
    fn default() -> Self {
        Self::fresh()
    }
}

impl KeySecret {
    /// Returns a new random secret.
    #[must_use]
    pub fn fresh() -> Self {
        let mut bytes = [0u8; SECRET_BYTES];
        bytes[..16].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
        bytes[16..].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
        Self(bytes)
    }

    /// Returns the secret a store read back.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; SECRET_BYTES]) -> Self {
        Self(bytes)
    }

    /// Returns the bytes a store writes down.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; SECRET_BYTES] {
        &self.0
    }

    /// Returns the key for one rule and one subject.
    ///
    /// # Panics
    ///
    /// Never. Every subject this produces is inside the key's own bound and free of control
    /// characters, which is the whole of what [`AttentionKey::of`] refuses.
    #[must_use]
    pub fn attention_key(&self, rule: AttentionRule, subject: &str) -> AttentionKey {
        AttentionKey::of(rule, &self.keyable(subject))
            .expect("a derived subject is always well formed")
    }

    /// Returns the form of `subject` a key carries: a digest under this secret, and nothing else.
    #[must_use]
    pub fn keyable(&self, subject: &str) -> String {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(&self.0).expect("this length is one HMAC accepts");
        mac.update(subject.as_bytes());
        let digest = mac.finalize().into_bytes();
        let mut derived = String::with_capacity(DIGEST_CHARS + 1);
        derived.push(DERIVED_MARKER);
        for byte in digest.iter().take(DIGEST_CHARS / 2) {
            write!(derived, "{byte:02x}").expect("writing to a string cannot fail");
        }
        derived
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_carries_a_digest_rather_than_the_subject() {
        let secret = KeySecret::fresh();
        for subject in [
            "req-1",
            "git push --force origin main",
            "the build finished",
            "",
            "one\nline",
            "a\u{0}b",
            &"s".repeat(400),
        ] {
            let derived = secret.keyable(subject);
            assert!(
                derived.starts_with(DERIVED_MARKER),
                "{subject:?} is derived"
            );
            assert_eq!(derived.len(), DIGEST_CHARS + 1);
            assert_eq!(
                derived,
                secret.keyable(subject),
                "the derivation is deterministic inside one store"
            );
            let key = secret.attention_key(AttentionRule::CommandFailed, subject);
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
    fn a_reader_without_the_secret_cannot_answer_the_key_from_a_guess() {
        // The whole of the attack this closes: there are not many things a notification says, so a
        // reader served the record without its text tries the candidates. Under a secret it does
        // not hold, none of them produces the key it was given.
        let host = KeySecret::fresh();
        let guesser = KeySecret::fresh();
        let subject = "s-1|deployment succeeded";
        let served = host.attention_key(AttentionRule::ApplicationNotice, subject);
        for guess in ["s-1|deployment succeeded", "s-1|deployment failed"] {
            assert_ne!(
                guesser.attention_key(AttentionRule::ApplicationNotice, guess),
                served,
                "a guess checked without the store's own secret answers nothing"
            );
        }
        assert_eq!(
            host.attention_key(AttentionRule::ApplicationNotice, subject),
            served,
            "and the host itself still lands on the same item"
        );
    }

    #[test]
    fn two_subjects_that_differ_get_two_keys() {
        let secret = KeySecret::fresh();
        let left = secret.attention_key(
            AttentionRule::CommandFailed,
            &format!("a{}", "x".repeat(400)),
        );
        let right = secret.attention_key(
            AttentionRule::CommandFailed,
            &format!("b{}", "x".repeat(400)),
        );
        assert_ne!(left, right);
    }

    #[test]
    fn one_subject_under_two_rules_gets_two_keys() {
        let secret = KeySecret::fresh();
        let approval = secret.attention_key(AttentionRule::PendingApproval, "req-1");
        let input = secret.attention_key(AttentionRule::PendingInput, "req-1");
        assert_ne!(approval, input);
        assert!(
            approval
                .as_str()
                .starts_with("attention.pending_approval|~")
        );
    }

    #[test]
    fn a_secret_never_prints_itself() {
        let secret = KeySecret::from_bytes([7; SECRET_BYTES]);
        assert_eq!(format!("{secret:?}"), "KeySecret(..)");
    }
}
