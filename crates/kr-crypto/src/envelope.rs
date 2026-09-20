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
//!
//! # Padding
//!
//! Section 20 puts envelope sizes in declared buckets. A bucket that only described the plaintext
//! would describe nothing: the ciphertext would still be the plaintext's length plus a constant.
//! The plaintext is therefore padded to its bucket before encryption, with libsodium's
//! ISO/IEC 7816-4 padding, and the padding is inside the box. The declared bucket is recomputed
//! from the unpadded length when the envelope is opened and compared with both the padded length
//! and the routing record, so a service cannot declare one size and store another.
//!
//! This reduces precision. It does not hide traffic patterns, and section 20 says so.

mod paired;

use std::collections::BTreeMap;

use kr_protocol::ids::EnvelopeId;
use kr_protocol::mailbox::{
    EnvelopePlaintext, EnvelopeRouting, MailboxPayloadType, SMALL_MAILBOX_PLAINTEXT_BYTES,
    SealedEnvelope, granularity_for_bucket, mailbox_granularity, mailbox_size_bucket,
    replay_id_retained_until_ms,
};
use kr_protocol::pairing::KeyPurpose;
use kr_protocol::scalars::{Bytes, StoredEnvelopeKey, U64};

use crate::error::{CryptoError, Result};
use crate::keys::{StoredEnvelopeKeyPair, key_id};
use crate::sealed;
use crate::sodium;

pub use paired::{PairedSenders, open_delivered_envelope};

/// Seals one envelope for one recipient.
///
/// The plaintext's key identifiers are checked against the two keys actually used, so an envelope
/// cannot claim to come from a key that did not seal it. The canonical plaintext is then padded to
/// its declared size bucket before it is encrypted.
///
/// # Errors
///
/// Returns [`CryptoError::BindingMismatch`] when a key identifier in the plaintext does not name
/// the key used, [`CryptoError::TooLarge`] for a notification preview over the 16 KiB band where
/// the notification and mailbox bucket rules agree, and a library error when libsodium fails.
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

    let (padded, bucket) = pad_plaintext(plaintext)?;
    let mut padded = padded;
    let sealed_result = sealed::seal_stored_envelope(sender, recipient, &padded);
    sodium::memzero(&mut padded);
    let (nonce, ciphertext) = sealed_result?;
    Ok(SealedEnvelope {
        routing: EnvelopeRouting {
            envelope_id: plaintext.envelope_id,
            recipient_key_id: plaintext.recipient_key_id,
            sender_key_id: plaintext.sender_key_id,
            expires_at_ms: plaintext.expires_at_ms,
            payload_type: plaintext.payload_type,
            thread_id: plaintext.thread_id,
            size_bucket_bytes: U64::new(bucket),
        },
        nonce,
        ciphertext: Bytes::new(ciphertext),
    })
}

/// Encodes an envelope's plaintext and pads it to its declared size bucket.
///
/// It is crate-private because the padded buffer holds the plaintext in the clear; a caller
/// receives a sealed envelope, never this. The vector generator uses it so a fixed-nonce vector
/// pads exactly as a real envelope does.
pub(crate) fn pad_plaintext(plaintext: &EnvelopePlaintext) -> Result<(Vec<u8>, u64)> {
    let mut encoded = kr_cbor::to_canonical_vec(plaintext)?;
    let content_len = encoded.len() as u64;
    if plaintext.payload_type == MailboxPayloadType::NotificationPreview
        && content_len > SMALL_MAILBOX_PLAINTEXT_BYTES
    {
        // Below 16 KiB the notification rule and the mailbox rule are the same 1 KiB granularity.
        // Above it they diverge, and a reader that has only the padded length could not tell which
        // rule produced it, so a preview that large is refused rather than padded ambiguously.
        sodium::memzero(&mut encoded);
        return Err(CryptoError::TooLarge {
            what: "a notification preview",
            limit: SMALL_MAILBOX_PLAINTEXT_BYTES as usize,
            actual: content_len as usize,
        });
    }
    pad_to_bucket(&mut encoded)
}

/// Pads a canonical encoding to its declared size bucket and clears the input.
///
/// One padding rule covers a mailbox envelope and a synchronised object, because section 20 gives
/// them the same declared buckets. The input is cleared whatever the outcome: it holds the
/// plaintext in the clear, and a caller that kept it would be keeping the thing the padding is
/// there to hide the length of.
pub(crate) fn pad_to_bucket(encoded: &mut [u8]) -> Result<(Vec<u8>, u64)> {
    let content_len = encoded.len() as u64;
    let granularity = mailbox_granularity(content_len);
    let bucket = mailbox_size_bucket(content_len);

    // The padded buffer is allocated at its final size, so it never reallocates and never leaves a
    // copy of the plaintext behind in an abandoned allocation.
    let mut padded = Vec::with_capacity(bucket as usize);
    padded.extend_from_slice(encoded);
    sodium::memzero(encoded);
    padded.resize(bucket as usize, 0);
    let padded_len = sodium::pad(&mut padded, content_len as usize, granularity as usize)?;
    if padded_len as u64 != bucket {
        sodium::memzero(&mut padded);
        return Err(CryptoError::BindingMismatch {
            what: "the padded length of an envelope",
        });
    }
    Ok((padded, bucket))
}

/// Returns how many bytes of a padded plaintext are content.
///
/// The three bands do not overlap, so the granularity is recovered from the padded length before
/// the padding is removed, and the bucket is then recomputed from the content length and compared
/// with the length that arrived. A padded length that is not one of section 20's buckets, or one
/// that is not its own content's bucket, is refused here rather than decoded.
pub(crate) fn unpadded_len(opened: &[u8]) -> Result<usize> {
    let padded_len = opened.len() as u64;
    let granularity = granularity_for_bucket(padded_len).ok_or(CryptoError::BindingMismatch {
        what: "the padded length of an envelope, which is not a declared size bucket",
    })?;
    let content_len = sodium::unpad(opened, granularity as usize)?;
    if mailbox_size_bucket(content_len as u64) != padded_len {
        return Err(CryptoError::BindingMismatch {
            what: "the padded length of an envelope, which is not its content's bucket",
        });
    }
    Ok(content_len)
}

/// Opens one envelope against a previously paired sender key.
///
/// `verify_payload` is called for any payload type that carries authority. It returns the issuer's
/// own verification result, so an authorisation-bearing payload can never be accepted on the
/// strength of the pairwise box alone.
///
/// # Errors
///
/// Returns [`CryptoError::Authentication`] when the box does not authenticate, when the padding is
/// malformed or when `verify_payload` rejects the payload, and [`CryptoError::BindingMismatch`]
/// when a key identifier, a routing field, the declared bucket or the expiry does not match the
/// authenticated plaintext.
pub fn open_envelope<F>(
    recipient: &StoredEnvelopeKeyPair,
    sender: &StoredEnvelopeKey,
    sealed_envelope: &SealedEnvelope,
    now_ms: u64,
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

    let padded_len = opened.len() as u64;
    let content_len = unpadded_len(opened.expose())?;
    if sealed_envelope.routing.size_bucket_bytes.get() != padded_len {
        return Err(CryptoError::BindingMismatch {
            what: "the declared size bucket outside the envelope",
        });
    }

    let plaintext: EnvelopePlaintext =
        kr_cbor::from_canonical_slice(&opened.expose()[..content_len], &kr_cbor::Limits::DEFAULT)?;

    if plaintext.payload_type == MailboxPayloadType::NotificationPreview
        && content_len as u64 > SMALL_MAILBOX_PLAINTEXT_BYTES
    {
        // The sealing side refuses one this large, and so does this side: a paired sender is
        // authenticated, not trusted, and a preview padded by the mailbox rule above 16 KiB would
        // be a size the notification rule never produces.
        return Err(CryptoError::TooLarge {
            what: "a notification preview",
            limit: SMALL_MAILBOX_PLAINTEXT_BYTES as usize,
            actual: content_len,
        });
    }

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
    if now_ms >= plaintext.expires_at_ms.get() {
        return Err(CryptoError::BindingMismatch {
            what: "the expiry of an envelope, which has passed",
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

    /// Records an envelope as accepted, rejecting one that has been seen before or has expired.
    ///
    /// The expiry check is what makes the retention window meaningful: without it, an envelope
    /// could be replayed after its own deadline had passed and the record of it had been dropped.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::BindingMismatch`] when the envelope has already been accepted or has
    /// expired.
    pub fn admit(&mut self, plaintext: &EnvelopePlaintext, now_ms: u64) -> Result<()> {
        if now_ms >= plaintext.expires_at_ms.get() {
            return Err(CryptoError::BindingMismatch {
                what: "the expiry of an envelope, which has passed",
            });
        }
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

    /// Returns the retained identifiers and the instant each may be forgotten.
    ///
    /// The durable store belongs to the controller, which owns the host's databases. This ledger
    /// is the rule; the controller persists what it returns and restores it at startup, so a
    /// restart does not reopen the replay window.
    pub fn entries(&self) -> impl Iterator<Item = (EnvelopeId, u64)> + '_ {
        self.retained.iter().map(|(id, until)| (*id, *until))
    }

    /// Rebuilds a ledger from a durable store.
    #[must_use]
    pub fn restore(entries: impl IntoIterator<Item = (EnvelopeId, u64)>) -> Self {
        Self {
            retained: entries.into_iter().collect(),
        }
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
    use kr_protocol::mailbox::EnvelopeVersion;
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
            thread_id: Nullable::null(),
            payload: Bytes::new(b"body".to_vec()),
        }
    }

    #[test]
    fn an_envelope_round_trips_and_is_padded_to_its_bucket() {
        let sender = StoredEnvelopeKeyPair::generate().expect("a keypair");
        let recipient = StoredEnvelopeKeyPair::generate().expect("a keypair");
        let plaintext = plaintext(&sender, &recipient, MailboxPayloadType::SyncChange);
        let sealed_envelope =
            seal_envelope(&sender, recipient.public(), &plaintext).expect("a sealed envelope");

        // The ciphertext is the bucket plus the box's own MAC, not the plaintext plus a constant.
        assert_eq!(sealed_envelope.routing.size_bucket_bytes.get(), 1024);
        assert_eq!(
            sealed_envelope.ciphertext.len() as u64,
            1024 + crate::sealed::MAC_LEN as u64
        );

        let opened = open_envelope(&recipient, sender.public(), &sealed_envelope, 2_000, |_| {
            unreachable!("a sync change carries no authority")
        })
        .expect("the plaintext");
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn two_envelopes_of_different_sizes_share_one_ciphertext_length() {
        let sender = StoredEnvelopeKeyPair::generate().expect("a keypair");
        let recipient = StoredEnvelopeKeyPair::generate().expect("a keypair");
        let mut short = plaintext(&sender, &recipient, MailboxPayloadType::SyncChange);
        short.payload = Bytes::new(vec![1; 8]);
        let mut long = plaintext(&sender, &recipient, MailboxPayloadType::SyncChange);
        long.payload = Bytes::new(vec![1; 400]);
        let first = seal_envelope(&sender, recipient.public(), &short).expect("sealed");
        let second = seal_envelope(&sender, recipient.public(), &long).expect("sealed");
        assert_eq!(first.ciphertext.len(), second.ciphertext.len());
        assert_eq!(
            first.routing.size_bucket_bytes,
            second.routing.size_bucket_bytes
        );
    }

    #[test]
    fn a_rewritten_size_bucket_is_rejected() {
        let sender = StoredEnvelopeKeyPair::generate().expect("a keypair");
        let recipient = StoredEnvelopeKeyPair::generate().expect("a keypair");
        let plaintext = plaintext(&sender, &recipient, MailboxPayloadType::SyncChange);
        let mut sealed_envelope =
            seal_envelope(&sender, recipient.public(), &plaintext).expect("a sealed envelope");
        sealed_envelope.routing.size_bucket_bytes = U64::new(2048);
        assert!(matches!(
            open_envelope(
                &recipient,
                sender.public(),
                &sealed_envelope,
                2_000,
                |_| Ok(())
            ),
            Err(CryptoError::BindingMismatch {
                what: "the declared size bucket outside the envelope"
            })
        ));
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
            open_envelope(
                &recipient,
                sender.public(),
                &sealed_envelope,
                2_000,
                |_| Ok(())
            ),
            Err(CryptoError::BindingMismatch {
                what: "the routing record outside the envelope"
            })
        ));
    }

    #[test]
    fn an_expired_envelope_is_not_opened() {
        let sender = StoredEnvelopeKeyPair::generate().expect("a keypair");
        let recipient = StoredEnvelopeKeyPair::generate().expect("a keypair");
        let plaintext = plaintext(&sender, &recipient, MailboxPayloadType::SyncChange);
        let sealed_envelope =
            seal_envelope(&sender, recipient.public(), &plaintext).expect("a sealed envelope");
        assert!(matches!(
            open_envelope(
                &recipient,
                sender.public(),
                &sealed_envelope,
                61_000,
                |_| Ok(())
            ),
            Err(CryptoError::BindingMismatch {
                what: "the expiry of an envelope, which has passed"
            })
        ));
    }

    #[test]
    fn an_authority_bearing_payload_must_pass_its_own_signature_check() {
        let sender = StoredEnvelopeKeyPair::generate().expect("a keypair");
        let recipient = StoredEnvelopeKeyPair::generate().expect("a keypair");
        let plaintext = plaintext(
            &sender,
            &recipient,
            MailboxPayloadType::SignedAuthorityObject,
        );
        let sealed_envelope =
            seal_envelope(&sender, recipient.public(), &plaintext).expect("a sealed envelope");
        assert!(matches!(
            open_envelope(&recipient, sender.public(), &sealed_envelope, 2_000, |_| {
                Err(CryptoError::Authentication {
                    what: "the forwarded object's signature",
                })
            }),
            Err(CryptoError::Authentication { .. })
        ));
        assert!(
            open_envelope(
                &recipient,
                sender.public(),
                &sealed_envelope,
                2_000,
                |_| Ok(())
            )
            .is_ok()
        );
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
            open_envelope(
                &recipient,
                impostor.public(),
                &sealed_envelope,
                2_000,
                |_| Ok(())
            )
            .is_err()
        );
    }

    #[test]
    fn an_oversized_notification_preview_is_refused() {
        let sender = StoredEnvelopeKeyPair::generate().expect("a keypair");
        let recipient = StoredEnvelopeKeyPair::generate().expect("a keypair");
        let mut plaintext = plaintext(&sender, &recipient, MailboxPayloadType::NotificationPreview);
        plaintext.payload = Bytes::new(vec![0; 17 * 1024]);
        assert!(matches!(
            seal_envelope(&sender, recipient.public(), &plaintext),
            Err(CryptoError::TooLarge { .. })
        ));
    }

    #[test]
    fn a_replayed_envelope_is_rejected_and_an_expired_one_is_never_admitted() {
        let sender = StoredEnvelopeKeyPair::generate().expect("a keypair");
        let recipient = StoredEnvelopeKeyPair::generate().expect("a keypair");
        let plaintext = plaintext(&sender, &recipient, MailboxPayloadType::SyncChange);
        let mut ledger = ReplayLedger::new();
        assert!(ledger.admit(&plaintext, 2_000).is_ok());
        assert!(ledger.admit(&plaintext, 2_000).is_err());

        // The envelope expires at 61 s; the identifier is kept for one more day.
        ledger.expire(61_000 + 86_400_000 - 1);
        assert_eq!(ledger.len(), 1);
        ledger.expire(61_000 + 86_400_000);
        assert!(ledger.is_empty());

        // Once the record is gone the envelope is long expired, so it is still refused.
        assert!(matches!(
            ledger.admit(&plaintext, 61_000 + 86_400_000),
            Err(CryptoError::BindingMismatch {
                what: "the expiry of an envelope, which has passed"
            })
        ));
    }

    #[test]
    fn a_ledger_survives_a_restart_through_its_durable_store() {
        let sender = StoredEnvelopeKeyPair::generate().expect("a keypair");
        let recipient = StoredEnvelopeKeyPair::generate().expect("a keypair");
        let plaintext = plaintext(&sender, &recipient, MailboxPayloadType::SyncChange);
        let mut ledger = ReplayLedger::new();
        ledger.admit(&plaintext, 2_000).expect("admitted");
        let persisted: Vec<_> = ledger.entries().collect();

        let mut restored = ReplayLedger::restore(persisted);
        assert_eq!(restored.len(), 1);
        assert!(restored.admit(&plaintext, 2_000).is_err());
    }
}
