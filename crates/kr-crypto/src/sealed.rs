//! `crypto_box_easy` sealing between two paired devices.
//!
//! Mailbox envelopes, notification previews and backup key wraps are all sealed this way: from one
//! device's private key to another device's public key, with a fresh 24-byte nonce from
//! libsodium's random generator.
//!
//! The two purposes have separate functions rather than one generic pair. A stored-envelope key
//! and a notification-preview key are different types, so the compiler rejects a caller that seals
//! archive material to the key the notification extension holds.
//!
//! [`answer_mailbox_claim`] is the one place a key agreement is taken on its own rather than
//! inside a box. It exists for one question a mailbox asks, it answers that question with a value
//! that means nothing anywhere else, and the agreement itself never leaves this module.

use kr_protocol::mailbox::mailbox_claim_value;
use kr_protocol::scalars::{Digest256, Nonce192, NotificationPreviewKey, StoredEnvelopeKey};

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

/// Answers the challenge a service hands a device that says a mailbox is its own.
///
/// A mailbox is addressed by the identifier of the recipient's stored-envelope key, and every
/// paired peer knows that key: it is what they seal to. What distinguishes the recipient is the
/// private half, so the service offers an ephemeral X25519 key and asks for
/// [`kr_protocol::mailbox::mailbox_claim_value`] of the agreement. This is the recipient's side of
/// that, and it is the only key agreement in this crate taken outside a box.
///
/// It gives back the value and never the agreement. A raw shared secret is a general-purpose key,
/// and a function that handed one out would be a key-exchange surface that anything could build
/// on; the value it becomes here is bound to this domain, to this challenge and to this mailbox,
/// and proves possession without being usable for anything else. The agreement is wiped before
/// this returns.
///
/// # Errors
///
/// Returns an error when libsodium is unavailable, and when the ephemeral key is one that agrees
/// to nothing: a point of small order sends every private key to the same secret, so a value
/// derived from it would prove possession of nothing.
pub fn answer_mailbox_claim(
    recipient: &StoredEnvelopeKeyPair,
    ephemeral: &StoredEnvelopeKey,
) -> Result<Digest256> {
    let mut agreed = sodium::scalarmult(recipient.secret().expose(), ephemeral.as_bytes())?;
    let value = mailbox_claim_value(ephemeral, recipient.public(), &agreed);
    sodium::memzero(&mut agreed);
    Ok(value)
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
    fn a_claim_is_answered_by_the_key_the_mailbox_is_addressed_by_and_by_no_other() {
        let recipient = StoredEnvelopeKeyPair::generate().expect("a keypair");
        let ephemeral = StoredEnvelopeKeyPair::generate().expect("the challenge's key");

        let answer = answer_mailbox_claim(&recipient, ephemeral.public()).expect("an answer");
        assert_eq!(
            answer,
            answer_mailbox_claim(&recipient, ephemeral.public()).expect("the same answer"),
            "one challenge has one answer"
        );

        // The other side of the agreement, which is what the service holds: it knows the
        // ephemeral private half and the recipient's public key, and derives the same value.
        let mut agreed =
            crate::sodium::scalarmult(ephemeral.secret().expose(), recipient.public().as_bytes())
                .expect("the agreement the service takes");
        assert_eq!(
            answer,
            kr_protocol::mailbox::mailbox_claim_value(
                ephemeral.public(),
                recipient.public(),
                &agreed
            ),
            "the value the recipient derives is the value the service expects"
        );
        crate::sodium::memzero(&mut agreed);

        // A device that knows the recipient's public key and not its private half is exactly who
        // the challenge is there to turn away.
        let peer = StoredEnvelopeKeyPair::generate().expect("a paired peer");
        assert_ne!(
            answer,
            answer_mailbox_claim(&peer, ephemeral.public()).expect("a peer's own answer")
        );

        // And an answer belongs to the challenge it was made for.
        let next = StoredEnvelopeKeyPair::generate().expect("the next challenge's key");
        assert_ne!(
            answer,
            answer_mailbox_claim(&recipient, next.public()).expect("another challenge's answer")
        );
    }

    #[test]
    fn a_challenge_key_that_agrees_to_nothing_is_refused_rather_than_answered() {
        let recipient = StoredEnvelopeKeyPair::generate().expect("a keypair");
        // A point of small order sends every private key to the same shared secret, so a service
        // offering one would learn an answer that proves possession of nothing.
        let useless = StoredEnvelopeKey::from_bytes([0u8; 32]);
        assert!(matches!(
            answer_mailbox_claim(&recipient, &useless),
            Err(CryptoError::Library {
                name: "crypto_scalarmult",
                ..
            })
        ));
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
