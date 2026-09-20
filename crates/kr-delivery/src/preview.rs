//! Sealing a notification preview, and the two size bounds section 16 puts around it.
//!
//! # One key, and only one thing it opens
//!
//! Section 16 registers a separate X25519 key through the paired device's authenticated channel
//! with purpose `notification_preview` and a key revision, and says preview envelopes use that key
//! **only**: *ordinary mailbox records, archive key wraps and recovery bundles MUST NOT use it*.
//!
//! Three things hold that here, and none of them is a rule somebody remembers:
//!
//! * the key is a [`NotificationPreviewKey`], which is a different Rust type from a
//!   stored-envelope key, and [`kr_crypto::sealed::seal_notification_preview`] takes nothing else;
//! * the authenticated key identifiers inside the sealed plaintext are built with
//!   [`KeyPurpose::NotificationPreview`], and a key identifier covers the purpose as well as the
//!   bytes, so the same 32 bytes registered for two purposes produce two different identifiers;
//! * [`PreviewKeys`](crate::destination::PreviewKeys) is where a revision and the bounded previous
//!   key live, so rotation is a value with a deadline on it rather than a key somebody keeps.
//!
//! # Two bounds, measured rather than estimated
//!
//! *Limit preview text plus inner metadata to 1,800 bytes before encryption and padding, and
//! measure the complete provider payload after encryption and base64. Keep that complete payload
//! below 3,500 bytes; move excess details to a referenced encrypted object instead of relying on
//! an approximate expansion ratio.*
//!
//! So there are two checks and they are on different things. [`check_preview_bound`] is on the
//! canonical bytes of the body **before** anything is done to it. [`check_payload_bound`] is on
//! the request body a host will actually send, base64 and all, which is the only figure a provider
//! sees. Neither multiplies the other by a ratio, which is the sentence's own instruction.
//!
//! With these two numbers the **outer** bound is the one that bites first. A body near the
//! 1,800-byte inner bound pads to a three-kibibyte bucket, and three kibibytes of ciphertext in
//! base64 is already past 3,500 bytes on its own. So a producer that only checked the inner bound
//! would build requests a gateway refuses, which is exactly what section 16 means by *rather than
//! relying on an approximate expansion ratio*: the expansion is not a ratio, it is a bucket, and a
//! bucket is a step.
//!
//! The remedy is section 16's own: the excess moves to a referenced encrypted object.
//! [`PreviewBody::referring_to`] is that move, and the producer applies it when either bound
//! refuses the first attempt.
//!
//! # Padding
//!
//! Section 20 pads a preview to a declared kibibyte bucket before it is encrypted, with
//! ISO/IEC 7816-4 padding inside the box, so a ciphertext length describes a bucket rather than a
//! message. [`pad_to_bucket`] is that rule, and the crate's own test seals a padded plaintext and
//! opens it through `kr_crypto::envelope::open_envelope`, which unpads with libsodium: the two
//! agree byte for byte or that test fails.

use base64::Engine as _;
use serde::{Deserialize, Serialize};

use kr_crypto::keys::{NotificationPreviewKeyPair, key_id};
use kr_protocol::ids::{EnvelopeId, EnvironmentId, NotificationId, SessionId};
use kr_protocol::mailbox::{
    EnvelopePlaintext, EnvelopeRouting, EnvelopeVersion, MailboxPayloadType, SEAL_OVERHEAD_BYTES,
    SMALL_MAILBOX_PLAINTEXT_BYTES, mailbox_granularity, mailbox_size_bucket,
};
use kr_protocol::pairing::KeyPurpose;
use kr_protocol::push::{
    MAX_PREVIEW_PLAINTEXT_BYTES, MAX_PROVIDER_PAYLOAD_BYTES, PushAlert, PushDeliveryRequest,
    provider_payload_within_policy,
};
use kr_protocol::scalars::{Bytes, NotificationPreviewKey, Nullable, TimestampMs, U64};

use crate::error::{DeliveryError, Result};

/// The ISO/IEC 7816-4 padding marker: the first byte of the padding is `0x80`.
const PAD_MARKER: u8 = 0x80;

/// What a preview carries inside the seal.
///
/// Everything here is behind the box. The plaintext alert a locked screen shows is not: it is
/// [`PushAlert`], which is one of six fixed sentences, and it is not a field of this type because
/// it is not something this body may describe differently.
///
/// `summary` is the one line naming the subject, the same line the attention item carries. It is
/// the only free text anywhere in a notification, and it never leaves the seal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreviewBody {
    /// Which generic alert accompanies this preview, repeated inside the seal.
    ///
    /// The device checks it against the one it was shown, so a gateway that changed the alert in
    /// transit is visible to the reader that can open the preview.
    pub alert: PushAlert,
    /// The attention rule this was raised under.
    pub rule: String,
    /// One line naming the subject.
    pub summary: String,
    /// The session it belongs to, when it belongs to one.
    pub session_id: Nullable<SessionId>,
    /// The environment it belongs to, when it belongs to one.
    pub environment_id: Nullable<EnvironmentId>,
    /// The encrypted object the excess detail moved into, when it did not fit.
    pub detail_object: Nullable<EnvelopeId>,
    /// When the host observed the condition, in UTC milliseconds.
    pub observed_at_ms: TimestampMs,
}

impl PreviewBody {
    /// Returns the canonical bytes this body is measured and sealed as.
    ///
    /// # Errors
    ///
    /// Returns [`DeliveryError::Encoding`] when the body cannot be represented in KR-CBOR-1.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        Ok(kr_cbor::to_canonical_vec(self)?)
    }

    /// Returns the body with its summary replaced by a reference to an encrypted object.
    ///
    /// Section 16's remedy for a payload that does not fit: the excess moves to a referenced
    /// encrypted object rather than being trimmed by a guessed ratio. What stays is the rule, the
    /// identifiers and the reference; what goes is the text.
    #[must_use]
    pub fn referring_to(&self, detail_object: EnvelopeId) -> Self {
        Self {
            summary: String::new(),
            detail_object: Nullable::some(detail_object),
            ..self.clone()
        }
    }
}

/// Checks section 16's 1,800-byte bound on the preview text plus its inner metadata.
///
/// # Errors
///
/// Returns [`DeliveryError::PreviewTooLarge`] when the canonical body is over the bound, and
/// [`DeliveryError::Encoding`] when it cannot be encoded.
pub fn check_preview_bound(body: &PreviewBody) -> Result<Vec<u8>> {
    let encoded = body.canonical_bytes()?;
    let actual = encoded.len() as u64;
    if actual > MAX_PREVIEW_PLAINTEXT_BYTES {
        return Err(DeliveryError::PreviewTooLarge {
            limit: MAX_PREVIEW_PLAINTEXT_BYTES,
            actual,
        });
    }
    Ok(encoded)
}

/// Pads a canonical plaintext to its declared size bucket, ISO/IEC 7816-4.
///
/// The bucket is strictly larger than the plaintext, so there is always at least one padding byte
/// and the marker can be removed unambiguously.
///
/// # Errors
///
/// Returns [`DeliveryError::PreviewTooLarge`] for a plaintext past the 16 KiB band, where the
/// notification rule and the mailbox rule stop agreeing and a reader with only the padded length
/// could not tell which produced it. `kr_crypto` refuses the same length for the same reason.
pub fn pad_to_bucket(plaintext: &[u8]) -> Result<(Vec<u8>, u64)> {
    let content_len = plaintext.len() as u64;
    if content_len > SMALL_MAILBOX_PLAINTEXT_BYTES {
        return Err(DeliveryError::PreviewTooLarge {
            limit: SMALL_MAILBOX_PLAINTEXT_BYTES,
            actual: content_len,
        });
    }
    let bucket = mailbox_size_bucket(content_len);
    let mut padded = Vec::with_capacity(bucket as usize);
    padded.extend_from_slice(plaintext);
    padded.push(PAD_MARKER);
    padded.resize(bucket as usize, 0);
    Ok((padded, bucket))
}

/// Removes ISO/IEC 7816-4 padding from a plaintext of `bucket` bytes.
///
/// # Errors
///
/// Returns [`DeliveryError::JournalUnreadable`] when the buffer carries no marker, which is a
/// buffer that was not padded by this rule.
pub fn unpad(padded: &[u8]) -> Result<&[u8]> {
    let marker = padded
        .iter()
        .rposition(|byte| *byte != 0)
        .filter(|position| padded[*position] == PAD_MARKER)
        .ok_or(DeliveryError::JournalUnreadable(
            "a padded plaintext carries no ISO/IEC 7816-4 marker",
        ))?;
    Ok(&padded[..marker])
}

/// One preview, sealed and measured.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedPreview {
    /// The envelope, ready to travel inside a delivery request.
    pub envelope: kr_protocol::mailbox::SealedEnvelope,
    /// The canonical body's length before padding and encryption, in bytes.
    pub plaintext_bytes: u64,
    /// The revision of the recipient key it was sealed to.
    pub recipient_revision: u64,
}

/// What a preview is sealed for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreviewTarget {
    /// The recipient's `notification_preview` key.
    pub recipient: NotificationPreviewKey,
    /// Its revision, as the paired device declared it.
    pub revision: u64,
}

/// Seals one preview to a destination's notification-preview key.
///
/// The envelope's expiry is the notification's own, which is what the gateway checks: a service
/// asked to hold a preview longer than the notification it belongs to would be holding it for
/// nothing.
///
/// # Errors
///
/// Returns [`DeliveryError::PreviewTooLarge`] when the body is over section 16's 1,800-byte
/// bound, and [`DeliveryError::Crypto`] when libsodium reports a failure.
pub fn seal_preview(
    sender: &NotificationPreviewKeyPair,
    target: &PreviewTarget,
    envelope_id: EnvelopeId,
    body: &PreviewBody,
    created_at_ms: TimestampMs,
    expires_at_ms: TimestampMs,
) -> Result<SealedPreview> {
    let payload = check_preview_bound(body)?;
    let plaintext_bytes = payload.len() as u64;
    // Both identifiers are built under the notification-preview purpose. A key identifier covers
    // the purpose as well as the key, so an identifier built here can never name the same key
    // registered as a stored-envelope key, and a reader that expects one will not accept the
    // other.
    let plaintext = EnvelopePlaintext {
        version: EnvelopeVersion::V1,
        envelope_id,
        sender_key_id: key_id(KeyPurpose::NotificationPreview, sender.public().as_bytes()),
        recipient_key_id: key_id(KeyPurpose::NotificationPreview, target.recipient.as_bytes()),
        payload_type: MailboxPayloadType::NotificationPreview,
        created_at_ms,
        expires_at_ms,
        grant_id: Nullable::null(),
        environment_id: body.environment_id,
        session_id: body.session_id,
        session_epoch: Nullable::null(),
        thread_id: Nullable::null(),
        payload: Bytes::new(payload),
    };
    let encoded = kr_cbor::to_canonical_vec(&plaintext)?;
    let (padded, bucket) = pad_to_bucket(&encoded)?;
    let (nonce, ciphertext) =
        kr_crypto::sealed::seal_notification_preview(sender, &target.recipient, &padded)?;
    Ok(SealedPreview {
        envelope: kr_protocol::mailbox::SealedEnvelope {
            routing: EnvelopeRouting {
                envelope_id,
                recipient_key_id: plaintext.recipient_key_id,
                sender_key_id: plaintext.sender_key_id,
                expires_at_ms,
                payload_type: MailboxPayloadType::NotificationPreview,
                thread_id: Nullable::null(),
                size_bucket_bytes: U64::new(bucket),
            },
            nonce,
            ciphertext: Bytes::new(ciphertext),
        },
        plaintext_bytes,
        recipient_revision: target.revision,
    })
}

/// Opens a preview this host sealed, which is what a test and a local reader do.
///
/// # Errors
///
/// Returns [`DeliveryError::Crypto`] when the ciphertext does not authenticate under the two keys
/// supplied, and [`DeliveryError::JournalUnreadable`] when what it opens is not a padded preview.
pub fn open_preview(
    recipient: &NotificationPreviewKeyPair,
    sender: &NotificationPreviewKey,
    envelope: &kr_protocol::mailbox::SealedEnvelope,
) -> Result<PreviewBody> {
    let opened = kr_crypto::sealed::open_notification_preview(
        recipient,
        sender,
        &envelope.nonce,
        envelope.ciphertext.as_slice(),
    )?;
    let plaintext: EnvelopePlaintext =
        kr_cbor::from_canonical_slice(unpad(opened.expose())?, &kr_cbor::Limits::DEFAULT)
            .map_err(|error| DeliveryError::Encoding(error.to_string()))?;
    if plaintext.payload_type != MailboxPayloadType::NotificationPreview {
        return Err(DeliveryError::JournalUnreadable(
            "a sealed preview does not carry a notification preview",
        ));
    }
    kr_cbor::from_canonical_slice(plaintext.payload.as_slice(), &kr_cbor::Limits::DEFAULT)
        .map_err(|error| DeliveryError::Encoding(error.to_string()))
}

/// The length of the request body a host will send, in bytes.
///
/// It is the complete JSON document, with the sealed preview base64url inside it, which is what
/// section 16 means by *after encryption and base64*. No expansion ratio is applied to anything:
/// the built body is measured.
///
/// # Errors
///
/// Returns [`DeliveryError::Encoding`] when the request cannot be serialised.
pub fn measure_payload(request: &PushDeliveryRequest) -> Result<u64> {
    Ok(encode_request(request)?.len() as u64)
}

/// Serialises a delivery request the way it travels.
///
/// # Errors
///
/// Returns [`DeliveryError::Encoding`] when the request cannot be serialised.
pub fn encode_request(request: &PushDeliveryRequest) -> Result<Vec<u8>> {
    serde_json::to_vec(request).map_err(|error| DeliveryError::Encoding(error.to_string()))
}

/// Checks section 16's 3,500-byte bound on the built provider payload.
///
/// # Errors
///
/// Returns [`DeliveryError::PayloadTooLarge`] when the measured body is not below the bound. The
/// caller's remedy is to move the excess into a referenced encrypted object and build again; it is
/// not to trim the text and hope.
pub fn check_payload_bound(request: &PushDeliveryRequest) -> Result<u64> {
    let measured = measure_payload(request)?;
    if provider_payload_within_policy(measured) {
        Ok(measured)
    } else {
        Err(DeliveryError::PayloadTooLarge {
            limit: MAX_PROVIDER_PAYLOAD_BYTES,
            actual: measured,
        })
    }
}

/// Returns the base64url form of a sealed preview's ciphertext, as the wire carries it.
///
/// It exists so a test can measure the same bytes the gateway will, without going through serde.
#[must_use]
pub fn base64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Returns the ciphertext length a padded plaintext of `bucket` bytes seals to.
///
/// [`PushDeliveryRequest::preview_is_well_formed`] checks exactly this, so a producer that builds
/// a preview any other way has built one the gateway refuses.
#[must_use]
pub const fn sealed_length(bucket: u64) -> u64 {
    bucket.saturating_add(SEAL_OVERHEAD_BYTES)
}

/// Returns the granularity a preview of `plaintext_len` bytes is padded to.
#[must_use]
pub const fn preview_granularity(plaintext_len: u64) -> u64 {
    mailbox_granularity(plaintext_len)
}

/// The generic alert text a device shows when it cannot open a preview.
///
/// It is here so that nothing in this crate has to build one: a producer chooses a [`PushAlert`]
/// and the sentence comes from the protocol.
#[must_use]
pub const fn generic_text(alert: PushAlert) -> &'static str {
    alert.generic_text()
}

/// Derives a notification identifier: 128 random bits, with nothing of the work in them.
#[must_use]
pub fn fresh_notification_id() -> NotificationId {
    NotificationId::new(kr_protocol::scalars::Uuid::from_bytes(
        *uuid::Uuid::new_v4().as_bytes(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_crypto::keys::StoredEnvelopeKeyPair;
    use kr_protocol::scalars::Uuid;

    fn body(summary: &str) -> PreviewBody {
        PreviewBody {
            alert: PushAlert::ApprovalWaiting,
            rule: "attention.pending_approval".to_owned(),
            summary: summary.to_owned(),
            session_id: Nullable::null(),
            environment_id: Nullable::null(),
            detail_object: Nullable::null(),
            observed_at_ms: TimestampMs::new(1_700_000_000_000),
        }
    }

    fn envelope_id() -> EnvelopeId {
        EnvelopeId::new(Uuid::from_bytes([7; 16]))
    }

    fn request_with(
        envelope: kr_protocol::mailbox::SealedEnvelope,
        expires: TimestampMs,
    ) -> PushDeliveryRequest {
        PushDeliveryRequest {
            collapse_id: kr_protocol::ids::CollapseId::new(Uuid::from_bytes([3; 16])),
            expires_at_ms: expires,
            hints: kr_protocol::push::PushPlatformHints {
                alert: PushAlert::ApprovalWaiting,
                urgency: kr_protocol::push::PushUrgency::Attention,
            },
            notification_id: fresh_notification_id(),
            preview: Nullable::some(envelope),
            sender_record_id: kr_protocol::ids::PushSenderRecordId::new(Uuid::from_bytes([4; 16])),
        }
    }

    #[test]
    fn a_preview_opens_for_the_key_it_was_sealed_to_and_no_other() {
        let host = NotificationPreviewKeyPair::generate().expect("a keypair");
        let device = NotificationPreviewKeyPair::generate().expect("a keypair");
        let other = NotificationPreviewKeyPair::generate().expect("a keypair");
        let sealed = seal_preview(
            &host,
            &PreviewTarget {
                recipient: *device.public(),
                revision: 3,
            },
            envelope_id(),
            &body("an approval is waiting"),
            TimestampMs::new(1_000),
            TimestampMs::new(2_000),
        )
        .expect("a sealed preview");
        let opened = open_preview(&device, host.public(), &sealed.envelope).expect("the body");
        assert_eq!(opened.summary, "an approval is waiting");
        assert!(
            open_preview(&other, host.public(), &sealed.envelope).is_err(),
            "a preview opens for its own recipient key only"
        );
    }

    #[test]
    fn a_preview_key_identifier_is_never_a_stored_envelope_key_identifier() {
        let device = NotificationPreviewKeyPair::generate().expect("a keypair");
        let bytes = device.public().as_bytes();
        assert_ne!(
            key_id(KeyPurpose::NotificationPreview, bytes),
            key_id(KeyPurpose::StoredEnvelope, bytes),
            "the purpose is inside the identifier, so one registration cannot serve both"
        );
    }

    #[test]
    fn a_sealed_preview_names_the_notification_preview_purpose_on_both_sides() {
        let host = NotificationPreviewKeyPair::generate().expect("a keypair");
        let device = NotificationPreviewKeyPair::generate().expect("a keypair");
        let sealed = seal_preview(
            &host,
            &PreviewTarget {
                recipient: *device.public(),
                revision: 1,
            },
            envelope_id(),
            &body("x"),
            TimestampMs::new(1_000),
            TimestampMs::new(2_000),
        )
        .expect("a sealed preview");
        assert_eq!(
            sealed.envelope.routing.recipient_key_id,
            key_id(KeyPurpose::NotificationPreview, device.public().as_bytes())
        );
        assert_eq!(
            sealed.envelope.routing.sender_key_id,
            key_id(KeyPurpose::NotificationPreview, host.public().as_bytes())
        );
        assert_eq!(
            sealed.envelope.routing.payload_type,
            MailboxPayloadType::NotificationPreview
        );
    }

    #[test]
    fn the_padding_is_the_one_libsodium_removes() {
        // The cross-check that keeps this module's padding and `kr_crypto`'s the same rule: a
        // plaintext padded here, sealed with the stored-envelope primitive and opened through
        // `kr_crypto::envelope::open_envelope`, which unpads with libsodium. A disagreement of one
        // byte fails here rather than on a device.
        let host = StoredEnvelopeKeyPair::generate().expect("a keypair");
        let device = StoredEnvelopeKeyPair::generate().expect("a keypair");
        let plaintext = EnvelopePlaintext {
            version: EnvelopeVersion::V1,
            envelope_id: envelope_id(),
            sender_key_id: key_id(KeyPurpose::StoredEnvelope, host.public().as_bytes()),
            recipient_key_id: key_id(KeyPurpose::StoredEnvelope, device.public().as_bytes()),
            payload_type: MailboxPayloadType::StateReference,
            created_at_ms: TimestampMs::new(1_000),
            expires_at_ms: TimestampMs::new(2_000),
            grant_id: Nullable::null(),
            environment_id: Nullable::null(),
            session_id: Nullable::null(),
            session_epoch: Nullable::null(),
            thread_id: Nullable::null(),
            payload: Bytes::new(b"a reference".to_vec()),
        };
        let encoded = kr_cbor::to_canonical_vec(&plaintext).expect("canonical bytes");
        let (padded, bucket) = pad_to_bucket(&encoded).expect("a padded plaintext");
        let (nonce, ciphertext) =
            kr_crypto::sealed::seal_stored_envelope(&host, device.public(), &padded)
                .expect("a ciphertext");
        let sealed = kr_protocol::mailbox::SealedEnvelope {
            routing: EnvelopeRouting {
                envelope_id: plaintext.envelope_id,
                recipient_key_id: plaintext.recipient_key_id,
                sender_key_id: plaintext.sender_key_id,
                expires_at_ms: plaintext.expires_at_ms,
                payload_type: plaintext.payload_type,
                thread_id: Nullable::null(),
                size_bucket_bytes: U64::new(bucket),
            },
            nonce,
            ciphertext: Bytes::new(ciphertext),
        };
        let opened =
            kr_crypto::envelope::open_envelope(&device, host.public(), &sealed, 1_500, |_| Ok(()))
                .expect("libsodium unpads what this module padded");
        assert_eq!(opened.payload.as_slice(), b"a reference");
        assert_eq!(unpad(&padded).expect("the plaintext"), encoded.as_slice());
    }

    #[test]
    fn a_sealed_preview_is_shaped_the_way_the_gateway_checks_for() {
        let host = NotificationPreviewKeyPair::generate().expect("a keypair");
        let device = NotificationPreviewKeyPair::generate().expect("a keypair");
        let expires = TimestampMs::new(1_700_000_100_000);
        let sealed = seal_preview(
            &host,
            &PreviewTarget {
                recipient: *device.public(),
                revision: 1,
            },
            envelope_id(),
            &body("an approval is waiting"),
            TimestampMs::new(1_700_000_000_000),
            expires,
        )
        .expect("a sealed preview");
        let request = request_with(sealed.envelope.clone(), expires);
        assert!(
            request.preview_is_well_formed(),
            "the bucket, the expiry and the ciphertext length are what a gateway checks"
        );
        assert_eq!(
            sealed.envelope.ciphertext.as_slice().len() as u64,
            sealed_length(sealed.envelope.routing.size_bucket_bytes.get())
        );
    }

    #[test]
    fn a_preview_body_over_eighteen_hundred_bytes_is_refused_before_anything_is_sealed() {
        let host = NotificationPreviewKeyPair::generate().expect("a keypair");
        let device = NotificationPreviewKeyPair::generate().expect("a keypair");
        let error = seal_preview(
            &host,
            &PreviewTarget {
                recipient: *device.public(),
                revision: 1,
            },
            envelope_id(),
            &body(&"x".repeat(2_000)),
            TimestampMs::new(1_000),
            TimestampMs::new(2_000),
        )
        .expect_err("the bound is checked before the seal");
        assert!(matches!(
            error,
            DeliveryError::PreviewTooLarge {
                limit: MAX_PREVIEW_PLAINTEXT_BYTES,
                ..
            }
        ));
    }

    #[test]
    fn the_payload_bound_is_measured_on_the_built_body_and_not_estimated() {
        let host = NotificationPreviewKeyPair::generate().expect("a keypair");
        let device = NotificationPreviewKeyPair::generate().expect("a keypair");
        let expires = TimestampMs::new(1_700_000_100_000);
        let sealed = seal_preview(
            &host,
            &PreviewTarget {
                recipient: *device.public(),
                revision: 1,
            },
            envelope_id(),
            &body("an approval is waiting"),
            TimestampMs::new(1_700_000_000_000),
            expires,
        )
        .expect("a sealed preview");
        let request = request_with(sealed.envelope, expires);
        let measured = check_payload_bound(&request).expect("a small preview fits");
        assert!(measured < MAX_PROVIDER_PAYLOAD_BYTES);
        assert_eq!(
            measured,
            encode_request(&request).expect("the body").len() as u64,
            "the figure is the body's own length, not an expansion ratio"
        );
    }

    #[test]
    fn a_preview_at_the_inner_bound_is_refused_by_the_measured_payload_bound() {
        // The two bounds are independent, and this is the case that shows why measuring matters:
        // a body inside the 1,800-byte inner bound pads to a three-kibibyte bucket, and that
        // bucket in base64 is already past 3,500 bytes. An expansion ratio applied to the inner
        // bound would have admitted it.
        let host = NotificationPreviewKeyPair::generate().expect("a keypair");
        let device = NotificationPreviewKeyPair::generate().expect("a keypair");
        let expires = TimestampMs::new(1_700_000_100_000);
        let target = PreviewTarget {
            recipient: *device.public(),
            revision: 1,
        };
        let at_bound = largest_body_inside_the_preview_bound();
        assert!(
            check_preview_bound(&at_bound).is_ok(),
            "this body is inside the inner bound"
        );
        let sealed = seal_preview(
            &host,
            &target,
            envelope_id(),
            &at_bound,
            TimestampMs::new(1_700_000_000_000),
            expires,
        )
        .expect("a sealed preview");
        let error = check_payload_bound(&request_with(sealed.envelope, expires))
            .expect_err("the built payload is over the bound");
        assert!(matches!(
            error,
            DeliveryError::PayloadTooLarge {
                limit: MAX_PROVIDER_PAYLOAD_BYTES,
                ..
            }
        ));

        // Section 16's remedy, and it works: the detail moves to a referenced encrypted object and
        // what is left fits.
        let referring = at_bound.referring_to(envelope_id());
        let sealed = seal_preview(
            &host,
            &target,
            envelope_id(),
            &referring,
            TimestampMs::new(1_700_000_000_000),
            expires,
        )
        .expect("a sealed preview");
        let measured = check_payload_bound(&request_with(sealed.envelope, expires))
            .expect("the reference fits where the detail did not");
        assert!(measured < MAX_PROVIDER_PAYLOAD_BYTES);
    }

    /// The largest body this test can build without crossing the 1,800-byte inner bound.
    fn largest_body_inside_the_preview_bound() -> PreviewBody {
        let mut summary = 1_000;
        loop {
            let candidate = body(&"x".repeat(summary + 1));
            if candidate.canonical_bytes().expect("bytes").len() as u64
                > MAX_PREVIEW_PLAINTEXT_BYTES
            {
                return body(&"x".repeat(summary));
            }
            summary += 1;
        }
    }

    #[test]
    fn a_preview_padded_past_its_bucket_is_refused_by_the_payload_bound() {
        // A preview whose plaintext needed a three-kibibyte bucket, which is what a producer that
        // ignored the inner bound would build. The outer check refuses it on the measured body.
        let host = NotificationPreviewKeyPair::generate().expect("a keypair");
        let device = NotificationPreviewKeyPair::generate().expect("a keypair");
        let expires = TimestampMs::new(1_700_000_100_000);
        let oversized = vec![0u8; 2_500];
        let (padded, bucket) = pad_to_bucket(&oversized).expect("a padded plaintext");
        assert_eq!(bucket, 3 * 1024);
        let (nonce, ciphertext) =
            kr_crypto::sealed::seal_notification_preview(&host, device.public(), &padded)
                .expect("a ciphertext");
        let envelope = kr_protocol::mailbox::SealedEnvelope {
            routing: EnvelopeRouting {
                envelope_id: envelope_id(),
                recipient_key_id: key_id(
                    KeyPurpose::NotificationPreview,
                    device.public().as_bytes(),
                ),
                sender_key_id: key_id(KeyPurpose::NotificationPreview, host.public().as_bytes()),
                expires_at_ms: expires,
                payload_type: MailboxPayloadType::NotificationPreview,
                thread_id: Nullable::null(),
                size_bucket_bytes: U64::new(bucket),
            },
            nonce,
            ciphertext: Bytes::new(ciphertext),
        };
        let request = request_with(envelope, expires);
        assert!(
            request.preview_is_well_formed(),
            "the shape is fine; it is the size that is not"
        );
        let error = check_payload_bound(&request).expect_err("the built payload is too large");
        assert!(matches!(
            error,
            DeliveryError::PayloadTooLarge {
                limit: MAX_PROVIDER_PAYLOAD_BYTES,
                ..
            }
        ));
    }

    #[test]
    fn the_excess_moves_to_a_referenced_object_rather_than_being_trimmed() {
        let long = body(&"x".repeat(1_700));
        let referring = long.referring_to(envelope_id());
        assert_eq!(referring.summary, "");
        assert_eq!(referring.detail_object.as_ref(), Some(&envelope_id()));
        assert_eq!(referring.rule, long.rule, "the metadata stays");
        assert!(
            referring.canonical_bytes().expect("bytes").len()
                < long.canonical_bytes().expect("bytes").len()
        );
    }

    #[test]
    fn the_generic_alert_names_no_session_project_host_or_command() {
        for alert in PushAlert::ALL {
            let text = generic_text(alert);
            assert!(text.starts_with('A') || text.starts_with("Several"));
            assert!(
                text.contains("KalaReach"),
                "the alert says which product and nothing about the work"
            );
        }
    }

    #[test]
    fn base64url_of_a_bucket_is_what_the_payload_measurement_carries() {
        let bucket = 2 * 1024;
        let sealed = vec![0u8; sealed_length(bucket) as usize];
        assert_eq!(base64url(&sealed).len(), (sealed.len() * 4).div_ceil(3));
        assert_eq!(preview_granularity(1_800), 1_024);
    }
}
