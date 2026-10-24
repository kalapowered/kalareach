//! Opening a sealed notification preview.
//!
//! A preview is sealed once per device to the device's notification-preview key, by the host's
//! notification-preview key, and reaches the device with a routing record beside it that the
//! service that carried it could have altered. Opening one checks, in this order:
//!
//! 1. the routing record says it is a notification preview, is still live, and declares a size
//!    bucket the notification rule produces, with the ciphertext the length that bucket seals to;
//! 2. the ciphertext authenticates under the recipient's key and the sender's, and its padding is
//!    well formed and rounds to the declared bucket;
//! 3. the key identifiers inside the authenticated plaintext name those two keys under the
//!    notification-preview purpose;
//! 4. the routing record outside the envelope matches the authenticated fields.
//!
//! The host's own tests open what the host sealed through this function, and a phone's receiver
//! opens through the same one, so the two cannot come to disagree about what a valid preview is.

use kr_protocol::mailbox::{
    EnvelopePlaintext, MailboxPayloadType, SEAL_OVERHEAD_BYTES, SealedEnvelope,
    granularity_for_bucket, notification_granularity,
};
use kr_protocol::pairing::KeyPurpose;
use kr_protocol::scalars::NotificationPreviewKey;

use super::unpad_notification_preview;
use crate::error::CryptoError;
use crate::keys::{NotificationPreviewKeyPair, key_id};
use crate::sealed;

/// Why a sealed preview was not opened.
///
/// Every refusal is a reason to show the generic alert. The variants say which check refused, in
/// words that name no content.
#[derive(Debug)]
pub enum PreviewRefusal {
    /// The envelope's own lifetime has run out.
    Expired,
    /// The routing record, or the authenticated plaintext, does not declare a notification
    /// preview.
    NotAPreview,
    /// The declared size bucket is not one the notification rule produces, is not the length that
    /// was sealed, or is not the one the plaintext rounds to.
    Size,
    /// The authenticated plaintext is not an envelope plaintext.
    Malformed,
    /// The authenticated key identifiers do not name the keys that opened it.
    Keys,
    /// The routing record outside the envelope does not match what was sealed.
    Routing,
    /// The ciphertext did not authenticate, its padding is malformed, or the library failed.
    Crypto(CryptoError),
}

impl PreviewRefusal {
    /// A short, fixed name for the refusal, which a receiver may log: it names the check that
    /// refused and nothing of what was refused.
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        match self {
            Self::Expired => "expired",
            Self::NotAPreview => "not_a_preview",
            Self::Size => "size",
            Self::Malformed => "malformed",
            Self::Keys => "keys",
            Self::Routing => "routing",
            Self::Crypto(CryptoError::Authentication { .. }) => "authentication",
            Self::Crypto(CryptoError::BindingMismatch { .. } | CryptoError::TooLarge { .. }) => {
                "size"
            }
            Self::Crypto(_) => "crypto",
        }
    }

    /// The refusal in words, for an error that carries text.
    #[must_use]
    pub const fn words(&self) -> &'static str {
        match self {
            Self::Expired => "this preview envelope has expired",
            Self::NotAPreview => "a routing record that does not declare a notification preview",
            Self::Size => "a preview's declared size bucket is not the one its plaintext rounds to",
            Self::Malformed => "a sealed preview does not carry an envelope plaintext",
            Self::Keys => {
                "a preview's authenticated key identifiers do not name the keys that opened it"
            }
            Self::Routing => "a preview's routing record does not match what was sealed",
            Self::Crypto(_) => "a sealed preview did not open",
        }
    }
}

impl From<CryptoError> for PreviewRefusal {
    fn from(error: CryptoError) -> Self {
        Self::Crypto(error)
    }
}

/// Opens one sealed notification preview, checking the untrusted routing record against what the
/// seal authenticated, and returns the authenticated plaintext.
///
/// # Errors
///
/// Returns the first check that refused, as a [`PreviewRefusal`].
pub fn open_notification_envelope(
    recipient: &NotificationPreviewKeyPair,
    sender: &NotificationPreviewKey,
    envelope: &SealedEnvelope,
    now_ms: u64,
) -> Result<EnvelopePlaintext, PreviewRefusal> {
    if now_ms >= envelope.routing.expires_at_ms.get() {
        return Err(PreviewRefusal::Expired);
    }
    if envelope.routing.payload_type != MailboxPayloadType::NotificationPreview {
        return Err(PreviewRefusal::NotAPreview);
    }
    let bucket = envelope.routing.size_bucket_bytes.get();
    if granularity_for_bucket(bucket) != Some(notification_granularity())
        || envelope.ciphertext.as_slice().len() as u64 != bucket.saturating_add(SEAL_OVERHEAD_BYTES)
    {
        return Err(PreviewRefusal::Size);
    }
    let opened = sealed::open_notification_preview(
        recipient,
        sender,
        &envelope.nonce,
        envelope.ciphertext.as_slice(),
    )?;
    let padded = opened.expose();
    if padded.len() as u64 != bucket {
        return Err(PreviewRefusal::Size);
    }
    // The padding must end in the last block of the bucket and the content must be that bucket's:
    // both are refused here, so there is nothing to compare again afterwards.
    let unpadded = unpad_notification_preview(padded)?;
    let plaintext: EnvelopePlaintext =
        kr_cbor::from_canonical_slice(unpadded, &kr_cbor::Limits::DEFAULT)
            .map_err(|_| PreviewRefusal::Malformed)?;
    if plaintext.payload_type != MailboxPayloadType::NotificationPreview {
        return Err(PreviewRefusal::NotAPreview);
    }
    if plaintext.sender_key_id != key_id(KeyPurpose::NotificationPreview, sender.as_bytes())
        || plaintext.recipient_key_id
            != key_id(
                KeyPurpose::NotificationPreview,
                recipient.public().as_bytes(),
            )
    {
        return Err(PreviewRefusal::Keys);
    }
    if plaintext.envelope_id != envelope.routing.envelope_id
        || plaintext.expires_at_ms != envelope.routing.expires_at_ms
        || plaintext.sender_key_id != envelope.routing.sender_key_id
        || plaintext.recipient_key_id != envelope.routing.recipient_key_id
        || plaintext.thread_id != envelope.routing.thread_id
    {
        return Err(PreviewRefusal::Routing);
    }
    Ok(plaintext)
}
