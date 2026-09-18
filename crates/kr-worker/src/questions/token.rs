//! The caller token: what is issued, what is stored, and what is checked.
//!
//! Section 11 asks for two records of one token: a verification hash, so a presented token can be
//! checked, and a locally encrypted copy, so an exact idempotent retry can be answered with the
//! same token it was answered with the first time. Both are keyed by a symmetric key the ledger
//! generates when it opens and holds in this process's memory alone.
//!
//! That key is what bounds the token's retention. A question's source access ends when the worker
//! does, because the worker is the session; the sealed copies on disk stop being readable at
//! exactly that moment, without anything having to remember to erase them.
//!
//! The token is bound to its question. Both the tag and the sealed copy cover the question
//! identifier, so a token lifted from one question cannot be presented for another even by the
//! application that owns both.

use kr_crypto::secret::SymmetricKey;
use kr_crypto::{aead, kdf};
use kr_protocol::ids::QuestionId;
use kr_protocol::question::CallerToken;

use crate::questions::error::{QuestionError, Result};

/// The domain the sealed copy and the tag are separated by.
const DOMAIN: &[u8] = b"kr-question/caller-token/1";

/// Generates a token from the operating system's random generator.
///
/// # Errors
///
/// Returns [`QuestionError::Unavailable`] when no random bytes are available.
pub fn issue() -> Result<CallerToken> {
    let secret = SymmetricKey::random()
        .map_err(|error| QuestionError::unavailable(format!("no token material: {error}")))?;
    Ok(CallerToken::new(secret.expose().to_vec()))
}

/// Returns the keyed verification tag for one token of one question.
#[must_use]
pub fn tag(key: &SymmetricKey, question_id: QuestionId, token: &CallerToken) -> Vec<u8> {
    kdf::hmac_sha256(key, &covered(question_id, token.as_slice()))
        .as_bytes()
        .to_vec()
}

/// Checks a presented token against the stored tag.
///
/// # Errors
///
/// Returns [`QuestionError::TokenRejected`] when the token is the wrong length or does not match.
pub fn verify(
    key: &SymmetricKey,
    question_id: QuestionId,
    presented: &CallerToken,
    stored: &[u8],
) -> Result<()> {
    if !presented.is_well_formed() {
        return Err(QuestionError::TokenRejected {
            detail: "that is not a token this host issued".to_owned(),
        });
    }
    let expected = <[u8; kr_protocol::scalars::Mac256::LEN]>::try_from(stored)
        .map(kr_protocol::scalars::Mac256::from_bytes)
        .map_err(|_| QuestionError::TokenRejected {
            detail: "the stored verification tag could not be read".to_owned(),
        })?;
    kdf::verify_hmac_sha256(key, &covered(question_id, presented.as_slice()), &expected).map_err(
        |_| QuestionError::TokenRejected {
            detail: "that token does not belong to this question".to_owned(),
        },
    )
}

/// Seals a copy of the token for an idempotent retry to be answered from.
///
/// # Errors
///
/// Returns [`QuestionError::Unavailable`] when the cipher is unavailable.
pub fn seal(
    key: &SymmetricKey,
    question_id: QuestionId,
    token: &CallerToken,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let (nonce, ciphertext) =
        aead::seal(key, &associated(question_id), token.as_slice()).map_err(|error| {
            QuestionError::unavailable(format!("the token could not be sealed: {error}"))
        })?;
    Ok((nonce.as_bytes().to_vec(), ciphertext))
}

/// Opens the sealed copy of a token.
///
/// # Errors
///
/// Returns [`QuestionError::Unavailable`] when the stored copy cannot be opened, which is what a
/// sealed copy from a previous worker looks like.
pub fn unseal(
    key: &SymmetricKey,
    question_id: QuestionId,
    nonce: &[u8],
    sealed: &[u8],
) -> Result<CallerToken> {
    let nonce = <[u8; kr_protocol::scalars::Nonce192::LEN]>::try_from(nonce)
        .map(kr_protocol::scalars::Nonce192::from_bytes)
        .map_err(|_| QuestionError::unavailable("the stored nonce is not the right length"))?;
    let opened = aead::open(key, &nonce, &associated(question_id), sealed).map_err(|error| {
        QuestionError::unavailable(format!(
            "the stored token copy could not be opened: {error}"
        ))
    })?;
    Ok(CallerToken::new(opened.expose().to_vec()))
}

/// The bytes the tag covers: the domain, the question and the token.
fn covered(question_id: QuestionId, token: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(DOMAIN.len() + 16 + token.len());
    input.extend_from_slice(DOMAIN);
    input.extend_from_slice(question_id.get().as_bytes());
    input.extend_from_slice(token);
    input
}

/// The associated data the sealed copy is bound to.
fn associated(question_id: QuestionId) -> Vec<u8> {
    let mut data = Vec::with_capacity(DOMAIN.len() + 16);
    data.extend_from_slice(DOMAIN);
    data.extend_from_slice(question_id.get().as_bytes());
    data
}

#[cfg(test)]
mod tests {
    use kr_protocol::scalars::Uuid;

    use super::*;

    fn question(byte: u8) -> QuestionId {
        QuestionId::new(Uuid::from_bytes([byte; 16]))
    }

    #[test]
    fn a_token_verifies_against_its_own_question_and_no_other() {
        let key = SymmetricKey::random().expect("a key");
        let token = issue().expect("a token");
        let stored = tag(&key, question(1), &token);
        assert!(verify(&key, question(1), &token, &stored).is_ok());
        assert!(verify(&key, question(2), &token, &stored).is_err());
    }

    #[test]
    fn another_token_does_not_verify() {
        let key = SymmetricKey::random().expect("a key");
        let stored = tag(&key, question(1), &issue().expect("a token"));
        let other = issue().expect("another token");
        assert!(verify(&key, question(1), &other, &stored).is_err());
    }

    #[test]
    fn a_sealed_copy_opens_to_the_token_it_was_made_from() {
        let key = SymmetricKey::random().expect("a key");
        let token = issue().expect("a token");
        let (nonce, sealed) = seal(&key, question(1), &token).expect("seals");
        let opened = unseal(&key, question(1), &nonce, &sealed).expect("opens");
        assert_eq!(opened.as_slice(), token.as_slice());
        assert!(unseal(&key, question(2), &nonce, &sealed).is_err());
    }

    #[test]
    fn a_copy_from_another_key_cannot_be_opened() {
        let token = issue().expect("a token");
        let (nonce, sealed) =
            seal(&SymmetricKey::random().expect("a key"), question(1), &token).expect("seals");
        let other = SymmetricKey::random().expect("another key");
        assert!(unseal(&other, question(1), &nonce, &sealed).is_err());
    }

    #[test]
    fn a_token_is_thirty_two_bytes_and_never_repeats() {
        let first = issue().expect("a token");
        let second = issue().expect("another token");
        assert_eq!(
            first.as_slice().len(),
            kr_protocol::question::CALLER_TOKEN_BYTES
        );
        assert_ne!(first.as_slice(), second.as_slice());
    }
}
