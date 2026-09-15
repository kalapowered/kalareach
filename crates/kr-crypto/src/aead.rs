//! The XChaCha20-Poly1305 AEAD the pairing bundle exchange uses.
//!
//! Every message has a fresh 24-byte nonce from libsodium's random generator and additional
//! authenticated data the caller builds. `kr-pairing` supplies that data: deterministic CBOR
//! carrying the protocol domain, the transcript, the direction, the sequence number and the
//! message type.

use kr_protocol::scalars::Nonce192;

use crate::error::{CryptoError, Result};
use crate::secret::{SecretVec, SymmetricKey};
use crate::sodium;

/// Bytes the AEAD adds to a plaintext.
pub const TAG_LEN: usize = sodium::AEAD_TAG_LEN;

/// Generates a fresh 24-byte nonce.
///
/// # Errors
///
/// Returns an error when libsodium is unavailable.
pub fn random_nonce() -> Result<Nonce192> {
    let mut bytes = [0u8; sodium::AEAD_NONCE_LEN];
    sodium::random_bytes(&mut bytes)?;
    Ok(Nonce192::from_bytes(bytes))
}

/// Encrypts `plaintext` under `key` with a fresh nonce.
///
/// Returns the nonce and the ciphertext. The nonce is generated here rather than accepted from a
/// caller, so no caller can repeat one.
///
/// # Errors
///
/// Returns an error when libsodium is unavailable or reports a failure.
pub fn seal(key: &SymmetricKey, aad: &[u8], plaintext: &[u8]) -> Result<(Nonce192, Vec<u8>)> {
    let nonce = random_nonce()?;
    let ciphertext = sodium::aead_encrypt(plaintext, aad, nonce.as_bytes(), key.expose())?;
    Ok((nonce, ciphertext))
}

/// Decrypts a ciphertext under `key`, `nonce` and `aad`.
///
/// # Errors
///
/// Returns [`CryptoError::Authentication`] when the ciphertext, the nonce or the additional
/// authenticated data does not match. The three are indistinguishable from outside, which is the
/// point.
pub fn open(
    key: &SymmetricKey,
    nonce: &Nonce192,
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<SecretVec> {
    let plaintext = sodium::aead_decrypt(ciphertext, aad, nonce.as_bytes(), key.expose())?;
    Ok(SecretVec::new(plaintext))
}

/// Returns the ciphertext length a plaintext of `plaintext_len` bytes produces.
#[must_use]
pub const fn sealed_len(plaintext_len: usize) -> usize {
    plaintext_len + TAG_LEN
}

/// Returns the plaintext length a ciphertext of `ciphertext_len` bytes carries.
///
/// # Errors
///
/// Returns [`CryptoError::Truncated`] when the ciphertext is shorter than one tag.
pub const fn opened_len(ciphertext_len: usize) -> Result<usize> {
    match ciphertext_len.checked_sub(TAG_LEN) {
        Some(len) => Ok(len),
        None => Err(CryptoError::Truncated {
            what: "an XChaCha20-Poly1305 ciphertext",
            minimum: TAG_LEN,
            actual: ciphertext_len,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sealed_message_opens_under_the_same_additional_data() {
        let key = SymmetricKey::random().expect("a key");
        let (nonce, ciphertext) = seal(&key, b"aad", b"plaintext").expect("a ciphertext");
        assert_eq!(ciphertext.len(), sealed_len(b"plaintext".len()));
        let opened = open(&key, &nonce, b"aad", &ciphertext).expect("the plaintext");
        assert_eq!(opened.expose(), b"plaintext");
    }

    #[test]
    fn different_additional_data_fails() {
        let key = SymmetricKey::random().expect("a key");
        let (nonce, ciphertext) = seal(&key, b"aad", b"plaintext").expect("a ciphertext");
        assert!(matches!(
            open(&key, &nonce, b"other", &ciphertext),
            Err(CryptoError::Authentication { .. })
        ));
    }

    #[test]
    fn a_different_nonce_fails() {
        let key = SymmetricKey::random().expect("a key");
        let (_, ciphertext) = seal(&key, b"aad", b"plaintext").expect("a ciphertext");
        let other = random_nonce().expect("a nonce");
        assert!(open(&key, &other, b"aad", &ciphertext).is_err());
    }

    #[test]
    fn two_seals_use_two_nonces() {
        let key = SymmetricKey::random().expect("a key");
        let (first, _) = seal(&key, b"", b"x").expect("a ciphertext");
        let (second, _) = seal(&key, b"", b"x").expect("a ciphertext");
        assert_ne!(first, second);
    }

    #[test]
    fn a_ciphertext_shorter_than_a_tag_is_truncated() {
        assert!(matches!(
            opened_len(TAG_LEN - 1),
            Err(CryptoError::Truncated { .. })
        ));
        assert_eq!(opened_len(TAG_LEN), Ok(0));
    }
}
