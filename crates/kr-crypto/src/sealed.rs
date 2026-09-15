//! `crypto_box_easy` sealing between two paired devices.
//!
//! Mailbox envelopes, notification previews and backup key wraps are all sealed this way: from one
//! device's private key to another device's public key, with a fresh 24-byte nonce from
//! libsodium's random generator.
//!
//! The two purposes have separate functions rather than one generic pair. A stored-envelope key
//! and a notification-preview key are different types, so the compiler rejects a caller that seals
//! archive material to the key the notification extension holds.

use kr_protocol::scalars::{Nonce192, NotificationPreviewKey, StoredEnvelopeKey};

use crate::error::Result;
use crate::keys::{NotificationPreviewKeyPair, StoredEnvelopeKeyPair};
use crate::secret::SecretVec;
use crate::sodium;

/// Bytes `crypto_box_easy` adds to a plaintext.
pub const MAC_LEN: usize = sodium::BOX_MAC_LEN;

/// Generates a fresh 24-byte nonce.
///
/// # Errors
///
/// Returns an error when libsodium is unavailable.
pub fn random_nonce() -> Result<Nonce192> {
    let mut bytes = [0u8; sodium::BOX_NONCE_LEN];
    sodium::random_bytes(&mut bytes)?;
    Ok(Nonce192::from_bytes(bytes))
}

/// Seals a stored-envelope payload for one recipient.
///
/// # Errors
///
/// Returns an error when libsodium is unavailable or reports a failure.
pub fn seal_stored_envelope(
    sender: &StoredEnvelopeKeyPair,
    recipient: &StoredEnvelopeKey,
    plaintext: &[u8],
) -> Result<(Nonce192, Vec<u8>)> {
    let nonce = random_nonce()?;
    let ciphertext = sodium::box_easy(
        plaintext,
        nonce.as_bytes(),
        recipient.as_bytes(),
        sender.secret().expose(),
    )?;
    Ok((nonce, ciphertext))
}

/// Opens a stored-envelope payload.
///
/// The sender's public key is supplied by the caller, which decrypts only against previously
/// paired sender keys.
///
/// # Errors
///
/// Returns [`crate::CryptoError::Authentication`] when the ciphertext does not authenticate.
pub fn open_stored_envelope(
    recipient: &StoredEnvelopeKeyPair,
    sender: &StoredEnvelopeKey,
    nonce: &Nonce192,
    ciphertext: &[u8],
) -> Result<SecretVec> {
    let plaintext = sodium::box_open_easy(
        ciphertext,
        nonce.as_bytes(),
        sender.as_bytes(),
        recipient.secret().expose(),
    )?;
    Ok(SecretVec::new(plaintext))
}

/// Seals a notification preview for one recipient.
///
/// # Errors
///
/// Returns an error when libsodium is unavailable or reports a failure.
pub fn seal_notification_preview(
    sender: &NotificationPreviewKeyPair,
    recipient: &NotificationPreviewKey,
    plaintext: &[u8],
) -> Result<(Nonce192, Vec<u8>)> {
    let nonce = random_nonce()?;
    let ciphertext = sodium::box_easy(
        plaintext,
        nonce.as_bytes(),
        recipient.as_bytes(),
        sender.secret().expose(),
    )?;
    Ok((nonce, ciphertext))
}

/// Opens a notification preview.
///
/// # Errors
///
/// Returns [`crate::CryptoError::Authentication`] when the ciphertext does not authenticate.
pub fn open_notification_preview(
    recipient: &NotificationPreviewKeyPair,
    sender: &NotificationPreviewKey,
    nonce: &Nonce192,
    ciphertext: &[u8],
) -> Result<SecretVec> {
    let plaintext = sodium::box_open_easy(
        ciphertext,
        nonce.as_bytes(),
        sender.as_bytes(),
        recipient.secret().expose(),
    )?;
    Ok(SecretVec::new(plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::CryptoError;

    #[test]
    fn a_stored_envelope_opens_for_its_recipient() {
        let sender = StoredEnvelopeKeyPair::generate().expect("a keypair");
        let recipient = StoredEnvelopeKeyPair::generate().expect("a keypair");
        let (nonce, ciphertext) =
            seal_stored_envelope(&sender, recipient.public(), b"body").expect("a ciphertext");
        let opened = open_stored_envelope(&recipient, sender.public(), &nonce, &ciphertext)
            .expect("the plaintext");
        assert_eq!(opened.expose(), b"body");
    }

    #[test]
    fn another_recipient_cannot_open_it() {
        let sender = StoredEnvelopeKeyPair::generate().expect("a keypair");
        let recipient = StoredEnvelopeKeyPair::generate().expect("a keypair");
        let other = StoredEnvelopeKeyPair::generate().expect("a keypair");
        let (nonce, ciphertext) =
            seal_stored_envelope(&sender, recipient.public(), b"body").expect("a ciphertext");
        assert!(matches!(
            open_stored_envelope(&other, sender.public(), &nonce, &ciphertext),
            Err(CryptoError::Authentication { .. })
        ));
    }

    #[test]
    fn another_sender_key_does_not_authenticate() {
        let sender = StoredEnvelopeKeyPair::generate().expect("a keypair");
        let impostor = StoredEnvelopeKeyPair::generate().expect("a keypair");
        let recipient = StoredEnvelopeKeyPair::generate().expect("a keypair");
        let (nonce, ciphertext) =
            seal_stored_envelope(&sender, recipient.public(), b"body").expect("a ciphertext");
        assert!(open_stored_envelope(&recipient, impostor.public(), &nonce, &ciphertext).is_err());
    }

    #[test]
    fn a_notification_preview_opens_for_its_recipient() {
        let sender = NotificationPreviewKeyPair::generate().expect("a keypair");
        let recipient = NotificationPreviewKeyPair::generate().expect("a keypair");
        let (nonce, ciphertext) =
            seal_notification_preview(&sender, recipient.public(), b"preview")
                .expect("a ciphertext");
        let opened = open_notification_preview(&recipient, sender.public(), &nonce, &ciphertext)
            .expect("the plaintext");
        assert_eq!(opened.expose(), b"preview");
    }

    #[test]
    fn two_seals_use_two_nonces() {
        let sender = StoredEnvelopeKeyPair::generate().expect("a keypair");
        let recipient = StoredEnvelopeKeyPair::generate().expect("a keypair");
        let (first, _) = seal_stored_envelope(&sender, recipient.public(), b"x").expect("sealed");
        let (second, _) = seal_stored_envelope(&sender, recipient.public(), b"x").expect("sealed");
        assert_ne!(first, second);
    }
}
