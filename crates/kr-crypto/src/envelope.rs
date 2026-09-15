//! Sealing and opening mailbox envelopes.
//!
//! An envelope is sealed once per recipient with `crypto_box_easy`. Opening one checks three
//! things before the payload is handed back:
//!
//! 1. the ciphertext authenticates under the recipient's key and a **previously paired** sender
//!    key the caller supplies;
//! 2. the key identifiers inside the authenticated plaintext name those two keys;
//! 3. the untrusted routing record matches the authenticated fields.
//!
//! A payload that carries authority of its own is signed before encryption, and
//! [`open_envelope`] refuses to return one whose signature the caller has not verified: the
//! signature check is a required argument rather than a later step a caller can forget.

use std::collections::BTreeMap;

use kr_protocol::ids::EnvelopeId;
use kr_protocol::mailbox::{
    EnvelopePlaintext, EnvelopeRouting, SealedEnvelope, mailbox_size_bucket,
    replay_id_retained_until_ms,
};
use kr_protocol::pairing::KeyPurpose;
use kr_protocol::scalars::{Bytes, StoredEnvelopeKey, U64};

use crate::error::{CryptoError, Result};
use crate::keys::{StoredEnvelopeKeyPair, key_id};
use crate::sealed;

/// Seals one envelope for one recipient.
///
/// The plaintext's key identifiers are checked against the two keys actually used, so an envelope
/// cannot claim to come from a key that did not seal it.
///
/// # Errors
///
/// Returns [`CryptoError::BindingMismatch`] when a key identifier in the plaintext does not name
/// the key used, and a library error when libsodium fails.
pub fn seal_envelope(
    sender: &StoredEnvelopeKeyPair,
    recipient: &StoredEnvelopeKey,
    plaintext: &EnvelopePlaintext,
) -> Result<SealedEnvelope> {
    if plaintext.sender_key_id != sender.key_id() {
        return Err(CryptoError::BindingMismatch {
            what: "the sender key identifier in the envelope",
        });
    }
    if plaintext.recipient_key_id != key_id(KeyPurpose::StoredEnvelope, recipient.as_bytes()) {
        return Err(CryptoError::BindingMismatch {
            what: "the recipient key identifier in the envelope",
        });
    }
    let encoded = kr_cbor::to_canonical_vec(plaintext)?;
    let (nonce, ciphertext) = sealed::seal_stored_envelope(sender, recipient, &encoded)?;
    Ok(SealedEnvelope {
        routing: EnvelopeRouting {
            envelope_id: plaintext.envelope_id,
            recipient_key_id: plaintext.recipient_key_id,
            sender_key_id: plaintext.sender_key_id,
            expires_at_ms: plaintext.expires_at_ms,
            size_bucket_bytes: U64::new(mailbox_size_bucket(encoded.len() as u64)),
        },
        nonce,
        ciphertext: Bytes::new(ciphertext),
    })
}

/// Opens one envelope against a previously paired sender key.
///
/// `verify_payload` is called for any payload type that carries authority, with the payload bytes.
/// It returns the issuer's own verification result, so an authorisation-bearing payload can never
/// be accepted on the strength of the pairwise box alone.
///
/// # Errors
///
/// Returns [`CryptoError::Authentication`] when the box does not authenticate or when
/// `verify_payload` rejects the payload, and [`CryptoError::BindingMismatch`] when a key
/// identifier or a routing field does not match the authenticated plaintext.
pub fn open_envelope<F>(
    recipient: &StoredEnvelopeKeyPair,
    sender: &StoredEnvelopeKey,
    sealed_envelope: &SealedEnvelope,
    verify_payload: F,
) -> Result<EnvelopePlaintext>
where
    F: FnOnce(&EnvelopePlaintext) -> Result<()>,
{
    let opened = sealed::open_stored_envelope(
        recipient,
        sender,
        &sealed_envelope.nonce,
        sealed_envelope.ciphertext.as_slice(),
    )?;
    let plaintext: EnvelopePlaintext =
        kr_cbor::from_canonical_slice(opened.expose(), &kr_cbor::Limits::DEFAULT)?;

    if plaintext.sender_key_id != key_id(KeyPurpose::StoredEnvelope, sender.as_bytes()) {
        return Err(CryptoError::BindingMismatch {
            what: "the sender key identifier in the envelope",
        });
    }
    if plaintext.recipient_key_id != recipient.key_id() {
        return Err(CryptoError::BindingMismatch {
            what: "the recipient key identifier in the envelope",
        });
    }
    if !sealed_envelope.routing.matches(&plaintext) {
        return Err(CryptoError::BindingMismatch {
            what: "the routing record outside the envelope",
        });
    }
    if plaintext.payload_type.bears_authority() {
        verify_payload(&plaintext)?;
    }
    Ok(plaintext)
}

/// The replay identifiers a recipient has already accepted.
///
/// Section 20 keeps replay identifiers until expiry plus one day, so an envelope cannot be
/// redelivered after its own deadline has passed but before the record of it would have been
/// dropped.
#[derive(Debug, Default)]
pub struct ReplayLedger {
    retained: BTreeMap<EnvelopeId, u64>,
}

impl ReplayLedger {
    /// Creates an empty ledger.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records an envelope as accepted, rejecting one that has been seen before.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::BindingMismatch`] when the envelope has already been accepted.
    pub fn admit(&mut self, plaintext: &EnvelopePlaintext) -> Result<()> {
        if self.retained.contains_key(&plaintext.envelope_id) {
            return Err(CryptoError::BindingMismatch {
                what: "a replayed envelope identifier",
            });
        }
        self.retained.insert(
            plaintext.envelope_id,
            replay_id_retained_until_ms(plaintext.expires_at_ms.get()),
        );
        Ok(())
    }

    /// Drops the identifiers whose retention has ended at `now_ms`.
    pub fn expire(&mut self, now_ms: u64) {
        self.retained.retain(|_, until| *until > now_ms);
    }

    /// Returns how many identifiers are retained.
    #[must_use]
    pub fn len(&self) -> usize {
        self.retained.len()
    }

    /// Returns true when nothing is retained.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.retained.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::ids::EnvelopeId;
    use kr_protocol::mailbox::{EnvelopeVersion, MailboxPayloadType};
    use kr_protocol::scalars::{Nullable, TimestampMs, Uuid};

    fn plaintext(
        sender: &StoredEnvelopeKeyPair,
        recipient: &StoredEnvelopeKeyPair,
        payload_type: MailboxPayloadType,
    ) -> EnvelopePlaintext {
        EnvelopePlaintext {
            version: EnvelopeVersion::V1,
            envelope_id: EnvelopeId::new(Uuid::from_bytes([5; 16])),
            sender_key_id: sender.key_id(),
            recipient_key_id: recipient.key_id(),
            payload_type,
            created_at_ms: TimestampMs::new(1_000),
            expires_at_ms: TimestampMs::new(61_000),
            grant_id: Nullable::null(),
            environment_id: Nullable::null(),
            session_id: Nullable::null(),
            session_epoch: Nullable::null(),
            payload: Bytes::new(b"body".to_vec()),
        }
    }

    #[test]
    fn an_envelope_round_trips_and_declares_its_size_bucket() {
        let sender = StoredEnvelopeKeyPair::generate().expect("a keypair");
        let recipient = StoredEnvelopeKeyPair::generate().expect("a keypair");
        let plaintext = plaintext(&sender, &recipient, MailboxPayloadType::SyncChange);
        let sealed_envelope =
            seal_envelope(&sender, recipient.public(), &plaintext).expect("a sealed envelope");
        assert_eq!(sealed_envelope.routing.size_bucket_bytes.get(), 1024);
        let opened = open_envelope(&recipient, sender.public(), &sealed_envelope, |_| {
            unreachable!("a sync change carries no authority")
        })
        .expect("the plaintext");
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn a_rewritten_routing_record_is_rejected() {
        let sender = StoredEnvelopeKeyPair::generate().expect("a keypair");
        let recipient = StoredEnvelopeKeyPair::generate().expect("a keypair");
        let plaintext = plaintext(&sender, &recipient, MailboxPayloadType::SyncChange);
        let mut sealed_envelope =
            seal_envelope(&sender, recipient.public(), &plaintext).expect("a sealed envelope");
        sealed_envelope.routing.expires_at_ms = TimestampMs::new(999_999);
        assert!(matches!(
            open_envelope(&recipient, sender.public(), &sealed_envelope, |_| Ok(())),
            Err(CryptoError::BindingMismatch {
                what: "the routing record outside the envelope"
            })
        ));
    }

    #[test]
    fn an_authority_bearing_payload_must_pass_its_own_signature_check() {
        let sender = StoredEnvelopeKeyPair::generate().expect("a keypair");
        let recipient = StoredEnvelopeKeyPair::generate().expect("a keypair");
        let plaintext = plaintext(&sender, &recipient, MailboxPayloadType::RevocationRequest);
        let sealed_envelope =
            seal_envelope(&sender, recipient.public(), &plaintext).expect("a sealed envelope");
        assert!(matches!(
            open_envelope(&recipient, sender.public(), &sealed_envelope, |_| Err(
                CryptoError::Authentication {
                    what: "the revocation request signature"
                }
            )),
            Err(CryptoError::Authentication { .. })
        ));
        assert!(open_envelope(&recipient, sender.public(), &sealed_envelope, |_| Ok(())).is_ok());
    }

    #[test]
    fn an_envelope_that_lies_about_its_sender_is_rejected() {
        let sender = StoredEnvelopeKeyPair::generate().expect("a keypair");
        let recipient = StoredEnvelopeKeyPair::generate().expect("a keypair");
        let mut plaintext = plaintext(&sender, &recipient, MailboxPayloadType::SyncChange);
        plaintext.sender_key_id = recipient.key_id();
        assert!(matches!(
            seal_envelope(&sender, recipient.public(), &plaintext),
            Err(CryptoError::BindingMismatch { .. })
        ));
    }

    #[test]
    fn an_unpaired_sender_key_does_not_open_the_envelope() {
        let sender = StoredEnvelopeKeyPair::generate().expect("a keypair");
        let impostor = StoredEnvelopeKeyPair::generate().expect("a keypair");
        let recipient = StoredEnvelopeKeyPair::generate().expect("a keypair");
        let plaintext = plaintext(&sender, &recipient, MailboxPayloadType::SyncChange);
        let sealed_envelope =
            seal_envelope(&sender, recipient.public(), &plaintext).expect("a sealed envelope");
        assert!(
            open_envelope(&recipient, impostor.public(), &sealed_envelope, |_| Ok(())).is_err()
        );
    }

    #[test]
    fn a_replayed_envelope_is_rejected_until_its_retention_ends() {
        let sender = StoredEnvelopeKeyPair::generate().expect("a keypair");
        let recipient = StoredEnvelopeKeyPair::generate().expect("a keypair");
        let plaintext = plaintext(&sender, &recipient, MailboxPayloadType::SyncChange);
        let mut ledger = ReplayLedger::new();
        assert!(ledger.admit(&plaintext).is_ok());
        assert!(ledger.admit(&plaintext).is_err());
        // The envelope expires at 61 s; the identifier is kept for one more day.
        ledger.expire(61_000 + 86_400_000 - 1);
        assert_eq!(ledger.len(), 1);
        ledger.expire(61_000 + 86_400_000);
        assert!(ledger.is_empty());
        assert!(ledger.admit(&plaintext).is_ok());
    }
}
