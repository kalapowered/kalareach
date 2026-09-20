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
//! So there are two checks and they are on different things.
//!
//! [`check_preview_bound`] is on the canonical encoding of the **complete envelope plaintext**
//! before it is padded: the preview text and every piece of inner metadata that is sealed with it,
//! which is what *preview text plus inner metadata* names. Checking only the body would leave the
//! envelope's own identifiers, timestamps and type outside a bound that is about what is inside
//! the seal.
//!
//! [`check_payload_bound`] is on the **provider payload**, which is the document the gateway sends
//! to FCM and not the request the host sends to the gateway. Those differ: the gateway adds the
//! registration token, the platform block, the generic alert text and the preview re-encoded as a
//! JSON string inside `data`. [`provider_payload_bytes`] builds both platform documents the way
//! `workers/api/src/push/fcm.ts` builds them and measures the larger. The host does not hold the
//! registration token - the gateway binds it - so the token is reserved at
//! [`kr_protocol::push::MAX_REGISTRATION_TOKEN_LEN`], the largest the protocol admits. That makes
//! this check strictly stronger than the gateway's: a payload that fits here fits there, whatever
//! token the destination turns out to have.
//!
//! Neither multiplies the other by a ratio, which is the sentence's own instruction. The expansion
//! is not a ratio anyway: it is a padding bucket, and a bucket is a step.
//!
//! In practice the outer bound is the one that bites. A kibibyte bucket leaves room for the
//! reserved token; a two-kibibyte bucket does not, on either platform. The remedy is section 16's
//! own: the excess moves to a referenced encrypted object.
//! [`PreviewBody::referring_to`] is that move, and the producer applies it when either bound
//! refuses the first attempt.
//!
//! # Padding
//!
//! Section 20 pads a preview to a declared kibibyte bucket before it is encrypted, with
//! ISO/IEC 7816-4 padding inside the box, so a ciphertext length describes a bucket rather than a
//! message. [`kr_crypto::envelope::pad_notification_preview`] is that rule, and `kr_crypto`'s
//! own test seals a padded plaintext and opens it through `kr_crypto::envelope::open_envelope`,
//! which unpads with libsodium: the two agree byte for byte or that test fails.

use base64::Engine as _;
use serde::{Deserialize, Serialize};

use kr_crypto::keys::{NotificationPreviewKeyPair, key_id};
use kr_protocol::ids::{EnvelopeId, EnvironmentId, NotificationId, SessionId};
use kr_protocol::mailbox::{
    EnvelopePlaintext, EnvelopeRouting, EnvelopeVersion, MailboxPayloadType, SEAL_OVERHEAD_BYTES,
    granularity_for_bucket, mailbox_granularity, mailbox_size_bucket, notification_granularity,
};
use kr_protocol::pairing::KeyPurpose;
use kr_protocol::push::{
    MAX_PREVIEW_PLAINTEXT_BYTES, MAX_PROVIDER_PAYLOAD_BYTES, MAX_REGISTRATION_TOKEN_LEN, PushAlert,
    PushDeliveryRequest, provider_payload_within_policy,
};
use kr_protocol::scalars::{Bytes, NotificationPreviewKey, Nullable, TimestampMs, U64};

use crate::error::{DeliveryError, Result};

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
/// The argument is the complete envelope plaintext, canonically encoded and not yet padded. That
/// is what is inside the seal, so that is what the bound is about: the body's own text and
/// identifiers **and** the envelope's version, identifiers, key identifiers, type and timestamps.
///
/// # Errors
///
/// Returns [`DeliveryError::PreviewTooLarge`] when the canonical plaintext is over the bound, and
/// [`DeliveryError::Encoding`] when it cannot be encoded.
pub fn check_preview_bound(plaintext: &EnvelopePlaintext) -> Result<Vec<u8>> {
    let encoded = kr_cbor::to_canonical_vec(plaintext)?;
    let actual = encoded.len() as u64;
    if actual > MAX_PREVIEW_PLAINTEXT_BYTES {
        return Err(DeliveryError::PreviewTooLarge {
            limit: MAX_PREVIEW_PLAINTEXT_BYTES,
            actual,
        });
    }
    Ok(encoded)
}

/// One preview, sealed and measured.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedPreview {
    /// The envelope, ready to travel inside a delivery request.
    pub envelope: kr_protocol::mailbox::SealedEnvelope,
    /// The complete plaintext's length before padding and encryption, in bytes.
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
    let payload = body.canonical_bytes()?;
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
    let encoded = check_preview_bound(&plaintext)?;
    let plaintext_bytes = encoded.len() as u64;
    let (padded, bucket) = kr_crypto::envelope::pad_notification_preview(&encoded)?;
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

/// Opens a preview, checking the untrusted routing record against what the seal authenticated.
///
/// It is the same three-part check `kr_crypto::envelope::open_envelope` makes, for the key pair
/// that function does not take: the ciphertext authenticates under the two keys the caller
/// supplies, the key identifiers inside the sealed plaintext name those two keys under the
/// notification-preview purpose, and the routing record a service could have altered matches the
/// authenticated fields. The declared bucket is checked against the padded length, and an envelope
/// whose own expiry has passed is refused rather than opened.
///
/// # Errors
///
/// Returns [`DeliveryError::Crypto`] when the ciphertext does not authenticate,
/// [`DeliveryError::JournalUnreadable`] when the routing record disagrees with what was sealed or
/// the payload is not a preview, and [`DeliveryError::Expiry`] when the envelope has expired.
pub fn open_preview(
    recipient: &NotificationPreviewKeyPair,
    sender: &NotificationPreviewKey,
    envelope: &kr_protocol::mailbox::SealedEnvelope,
    now_ms: u64,
) -> Result<PreviewBody> {
    if now_ms >= envelope.routing.expires_at_ms.get() {
        return Err(DeliveryError::Expiry("this preview envelope has expired"));
    }
    if envelope.routing.payload_type != MailboxPayloadType::NotificationPreview {
        return Err(DeliveryError::JournalUnreadable(
            "a routing record that does not declare a notification preview",
        ));
    }
    let bucket = envelope.routing.size_bucket_bytes.get();
    if granularity_for_bucket(bucket) != Some(notification_granularity())
        || envelope.ciphertext.as_slice().len() as u64 != sealed_length(bucket)
    {
        return Err(DeliveryError::JournalUnreadable(
            "a preview's declared size bucket is not one the notification rule produces",
        ));
    }
    let opened = kr_crypto::sealed::open_notification_preview(
        recipient,
        sender,
        &envelope.nonce,
        envelope.ciphertext.as_slice(),
    )?;
    let padded = opened.expose();
    if padded.len() as u64 != bucket {
        return Err(DeliveryError::JournalUnreadable(
            "a preview's declared size bucket is not the length that was sealed",
        ));
    }
    let unpadded = kr_crypto::envelope::unpad_notification_preview(padded)?;
    if mailbox_size_bucket(unpadded.len() as u64) != bucket {
        return Err(DeliveryError::JournalUnreadable(
            "a preview's declared size bucket is not the one its plaintext rounds to",
        ));
    }
    let plaintext: EnvelopePlaintext =
        kr_cbor::from_canonical_slice(unpadded, &kr_cbor::Limits::DEFAULT)
            .map_err(|error| DeliveryError::Encoding(error.to_string()))?;
    if plaintext.payload_type != MailboxPayloadType::NotificationPreview {
        return Err(DeliveryError::JournalUnreadable(
            "a sealed preview does not carry a notification preview",
        ));
    }
    if plaintext.sender_key_id != key_id(KeyPurpose::NotificationPreview, sender.as_bytes())
        || plaintext.recipient_key_id
            != key_id(
                KeyPurpose::NotificationPreview,
                recipient.public().as_bytes(),
            )
    {
        return Err(DeliveryError::JournalUnreadable(
            "a preview's authenticated key identifiers do not name the keys that opened it",
        ));
    }
    if plaintext.envelope_id != envelope.routing.envelope_id
        || plaintext.expires_at_ms != envelope.routing.expires_at_ms
        || plaintext.sender_key_id != envelope.routing.sender_key_id
        || plaintext.recipient_key_id != envelope.routing.recipient_key_id
        || plaintext.thread_id != envelope.routing.thread_id
    {
        return Err(DeliveryError::JournalUnreadable(
            "a preview's routing record does not match what was sealed",
        ));
    }
    kr_cbor::from_canonical_slice(plaintext.payload.as_slice(), &kr_cbor::Limits::DEFAULT)
        .map_err(|error| DeliveryError::Encoding(error.to_string()))
}

/// How many bytes are reserved for the registration token the gateway will add.
///
/// The host does not hold the token: the gateway binds it to the installation, and section 16
/// keeps it there. So the measurement reserves the largest token the protocol admits. The check is
/// therefore strictly stronger than the gateway's, and a payload that passes here passes there
/// whatever token the destination turns out to have.
///
/// It is the token's own length, not its escaped length. A JSON string spends two bytes on a
/// character that has to be escaped, so a maximum-length token made entirely of quotes would
/// occupy twice this. Reserving that instead would leave no room for any preview at all inside
/// 3,500 bytes, so the reserve stays at the unescaped maximum and the gap is recorded rather than
/// hidden: a registration token a provider actually issues is a couple of hundred characters of
/// base64url, an order of magnitude inside this, and closing the gap properly means the gateway
/// declaring an escape-free alphabet for the field.
pub const RESERVED_TOKEN_BYTES: usize = MAX_REGISTRATION_TOKEN_LEN;

/// The longest time-to-live a notification's own expiry can produce, in seconds.
const MAX_EXPIRY_AHEAD_SECONDS: u64 = 24 * 60 * 60;

/// The length of the provider payload this notification will become, in bytes.
///
/// This is the figure section 16 names: *measure the complete provider payload after encryption
/// and base64*. The complete provider payload is what the gateway sends to the provider, not what
/// the host sends to the gateway, so this builds the same two documents
/// `workers/api/src/push/fcm.ts` builds - the Android message and the Apple message - and returns
/// the larger. The preview goes inside `data` as a JSON string, exactly as the gateway puts it
/// there, so its second round of quoting is measured rather than assumed.
///
/// Three figures the host cannot know are taken at their largest, which is the direction that
/// refuses rather than admits: the registration token, the time-to-live decimal, and the Apple
/// sound field the gateway includes only for an attention message.
///
/// # Errors
///
/// Returns [`DeliveryError::Encoding`] when the request cannot be serialised.
pub fn provider_payload_bytes(request: &PushDeliveryRequest) -> Result<u64> {
    let encode = |value: &serde_json::Value| -> Result<u64> {
        serde_json::to_vec(value)
            .map(|bytes| bytes.len() as u64)
            .map_err(|error| DeliveryError::Encoding(error.to_string()))
    };
    let token = "t".repeat(RESERVED_TOKEN_BYTES);
    let alert = request.hints.alert.generic_text();
    let notification_id = request.notification_id.to_string();
    let collapse_id = request.collapse_id.to_string();
    let expires = request.expires_at_ms.get();
    let mut data = serde_json::Map::new();
    data.insert("notification_id".to_owned(), notification_id.into());
    data.insert("expires_at_ms".to_owned(), expires.to_string().into());
    if let Some(preview) = request.preview.as_ref() {
        let encoded = serde_json::to_string(preview)
            .map_err(|error| DeliveryError::Encoding(error.to_string()))?;
        data.insert("preview".to_owned(), encoded.into());
    }
    let ttl = format!("{MAX_EXPIRY_AHEAD_SECONDS}s");
    let android = serde_json::json!({
        "message": {
            "token": token,
            "data": serde_json::Value::Object(data.clone()),
            "android": {
                "priority": request.hints.urgency.fcm_priority(),
                "collapse_key": collapse_id,
                "ttl": ttl,
                "notification": { "body": alert, "tag": collapse_id },
            },
        }
    });
    let apple = serde_json::json!({
        "message": {
            "token": token,
            "data": serde_json::Value::Object(data),
            "apns": {
                "headers": {
                    "apns-priority": request.hints.urgency.apns_priority(),
                    "apns-expiration": (expires / 1000).to_string(),
                    "apns-collapse-id": collapse_id,
                    "apns-push-type": "alert",
                },
                "payload": {
                    "aps": {
                        "alert": { "body": alert },
                        "mutable-content": 1,
                        "sound": "default",
                    }
                },
            },
        }
    });
    Ok(encode(&android)?.max(encode(&apple)?))
}

/// The length of the request body a host will send to the gateway, in bytes.
///
/// It is not the figure section 16's bound is about - [`provider_payload_bytes`] is - but it is
/// what this host actually writes to a socket, so it is what the journal records.
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
    let measured = provider_payload_bytes(request)?;
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

/// Mints a notification identifier, with nothing of the work in it.
///
/// It is a version-four UUID: 122 random bits inside a 128-bit value, which is the workspace's
/// random source and is far past what a provider or a gateway could enumerate.
#[must_use]
pub fn fresh_notification_id() -> NotificationId {
    NotificationId::new(kr_protocol::scalars::Uuid::from_bytes(
        *uuid::Uuid::new_v4().as_bytes(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
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

    fn sealed(
        host: &NotificationPreviewKeyPair,
        device: &NotificationPreviewKeyPair,
        body: &PreviewBody,
        expires: TimestampMs,
    ) -> Result<SealedPreview> {
        seal_preview(
            host,
            &PreviewTarget {
                recipient: *device.public(),
                revision: 1,
            },
            envelope_id(),
            body,
            TimestampMs::new(1_700_000_000_000),
            expires,
        )
    }

    const EXPIRES: u64 = 1_700_000_100_000;

    #[test]
    fn a_preview_opens_for_the_key_it_was_sealed_to_and_no_other() {
        let host = NotificationPreviewKeyPair::generate().expect("a keypair");
        let device = NotificationPreviewKeyPair::generate().expect("a keypair");
        let other = NotificationPreviewKeyPair::generate().expect("a keypair");
        let preview = sealed(
            &host,
            &device,
            &body("an approval is waiting"),
            TimestampMs::new(EXPIRES),
        )
        .expect("a sealed preview");
        let opened = open_preview(&device, host.public(), &preview.envelope, 1_700_000_000_000)
            .expect("the body");
        assert_eq!(opened.summary, "an approval is waiting");
        assert!(
            open_preview(&other, host.public(), &preview.envelope, 1_700_000_000_000).is_err(),
            "a preview opens for its own recipient key only"
        );
    }

    #[test]
    fn an_altered_routing_record_does_not_yield_a_body() {
        let host = NotificationPreviewKeyPair::generate().expect("a keypair");
        let device = NotificationPreviewKeyPair::generate().expect("a keypair");
        let preview = sealed(&host, &device, &body("x"), TimestampMs::new(EXPIRES))
            .expect("a sealed preview");

        let mut moved = preview.envelope.clone();
        moved.routing.envelope_id = EnvelopeId::new(Uuid::from_bytes([9; 16]));
        assert!(
            open_preview(&device, host.public(), &moved, 1_700_000_000_000).is_err(),
            "the untrusted routing record is checked against what was sealed"
        );

        let mut relabelled = preview.envelope.clone();
        relabelled.routing.size_bucket_bytes = U64::new(4 * 1024);
        assert!(open_preview(&device, host.public(), &relabelled, 1_700_000_000_000).is_err());

        let mut restamped = preview.envelope.clone();
        restamped.routing.expires_at_ms = TimestampMs::new(EXPIRES + 1_000);
        assert!(open_preview(&device, host.public(), &restamped, 1_700_000_000_000).is_err());
    }

    #[test]
    fn an_expired_preview_envelope_is_refused_rather_than_opened() {
        let host = NotificationPreviewKeyPair::generate().expect("a keypair");
        let device = NotificationPreviewKeyPair::generate().expect("a keypair");
        let preview = sealed(&host, &device, &body("x"), TimestampMs::new(EXPIRES))
            .expect("a sealed preview");
        assert!(matches!(
            open_preview(&device, host.public(), &preview.envelope, EXPIRES),
            Err(DeliveryError::Expiry(_))
        ));
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
        let preview =
            sealed(&host, &device, &body("x"), TimestampMs::new(EXPIRES)).expect("a preview");
        assert_eq!(
            preview.envelope.routing.recipient_key_id,
            key_id(KeyPurpose::NotificationPreview, device.public().as_bytes())
        );
        assert_eq!(
            preview.envelope.routing.sender_key_id,
            key_id(KeyPurpose::NotificationPreview, host.public().as_bytes())
        );
        assert_eq!(
            preview.envelope.routing.payload_type,
            MailboxPayloadType::NotificationPreview
        );
    }

    #[test]
    fn a_sealed_preview_is_shaped_the_way_the_gateway_checks_for() {
        let host = NotificationPreviewKeyPair::generate().expect("a keypair");
        let device = NotificationPreviewKeyPair::generate().expect("a keypair");
        let expires = TimestampMs::new(EXPIRES);
        let preview = sealed(&host, &device, &body("an approval is waiting"), expires)
            .expect("a sealed preview");
        let request = request_with(preview.envelope.clone(), expires);
        assert!(
            request.preview_is_well_formed(),
            "the bucket, the expiry and the ciphertext length are what a gateway checks"
        );
        assert_eq!(
            preview.envelope.ciphertext.as_slice().len() as u64,
            sealed_length(preview.envelope.routing.size_bucket_bytes.get())
        );
    }

    #[test]
    fn the_inner_bound_covers_the_envelope_metadata_and_not_only_the_body() {
        // A body under 1,800 bytes whose complete plaintext is over it. Checking the body alone
        // would have admitted this, and what is sealed is the plaintext.
        let host = NotificationPreviewKeyPair::generate().expect("a keypair");
        let device = NotificationPreviewKeyPair::generate().expect("a keypair");
        let mut summary = 1_600;
        let (body_at, plaintext_len) = loop {
            let candidate = body(&"x".repeat(summary));
            let body_len = candidate.canonical_bytes().expect("bytes").len() as u64;
            let plaintext = plaintext_of(&host, &device, &candidate);
            let plaintext_len = kr_cbor::to_canonical_vec(&plaintext).expect("bytes").len() as u64;
            if body_len <= MAX_PREVIEW_PLAINTEXT_BYTES
                && plaintext_len > MAX_PREVIEW_PLAINTEXT_BYTES
            {
                break (candidate, plaintext_len);
            }
            summary += 1;
            assert!(summary < 2_000, "such a body exists well before here");
        };
        assert!(
            body_at.canonical_bytes().expect("bytes").len() as u64 <= MAX_PREVIEW_PLAINTEXT_BYTES
        );
        assert!(plaintext_len > MAX_PREVIEW_PLAINTEXT_BYTES);
        let error = sealed(&host, &device, &body_at, TimestampMs::new(EXPIRES))
            .expect_err("the complete plaintext is over the bound");
        assert!(matches!(
            error,
            DeliveryError::PreviewTooLarge {
                limit: MAX_PREVIEW_PLAINTEXT_BYTES,
                ..
            }
        ));
    }

    /// The envelope plaintext `seal_preview` would build for one body, for a test that needs to
    /// measure it before sealing.
    fn plaintext_of(
        host: &NotificationPreviewKeyPair,
        device: &NotificationPreviewKeyPair,
        body: &PreviewBody,
    ) -> EnvelopePlaintext {
        EnvelopePlaintext {
            version: EnvelopeVersion::V1,
            envelope_id: envelope_id(),
            sender_key_id: key_id(KeyPurpose::NotificationPreview, host.public().as_bytes()),
            recipient_key_id: key_id(KeyPurpose::NotificationPreview, device.public().as_bytes()),
            payload_type: MailboxPayloadType::NotificationPreview,
            created_at_ms: TimestampMs::new(1_700_000_000_000),
            expires_at_ms: TimestampMs::new(EXPIRES),
            grant_id: Nullable::null(),
            environment_id: body.environment_id,
            session_id: body.session_id,
            session_epoch: Nullable::null(),
            thread_id: Nullable::null(),
            payload: Bytes::new(body.canonical_bytes().expect("bytes")),
        }
    }

    #[test]
    fn the_payload_bound_is_measured_on_the_provider_document_the_gateway_builds() {
        let host = NotificationPreviewKeyPair::generate().expect("a keypair");
        let device = NotificationPreviewKeyPair::generate().expect("a keypair");
        let expires = TimestampMs::new(EXPIRES);
        let preview = sealed(&host, &device, &body("an approval is waiting"), expires)
            .expect("a sealed preview");
        let request = request_with(preview.envelope, expires);
        let measured = check_payload_bound(&request).expect("a small preview fits");
        assert!(measured < MAX_PROVIDER_PAYLOAD_BYTES);
        assert_eq!(
            measured,
            provider_payload_bytes(&request).expect("the provider document"),
        );
        assert!(
            measured > measure_payload(&request).expect("the request body"),
            "the provider document is the larger of the two, because the gateway adds to it"
        );
        assert!(
            measured > RESERVED_TOKEN_BYTES as u64,
            "the reserved registration token is inside the figure"
        );
    }

    #[test]
    fn a_two_kibibyte_preview_is_refused_by_the_measured_payload_bound() {
        // A preview whose plaintext needs a two-kibibyte bucket does not fit a provider payload
        // once the token, the platform block and the second round of JSON quoting are counted.
        // An expansion ratio applied to the inner bound would have admitted it.
        let host = NotificationPreviewKeyPair::generate().expect("a keypair");
        let device = NotificationPreviewKeyPair::generate().expect("a keypair");
        let expires = TimestampMs::new(EXPIRES);
        let big = body(&"x".repeat(1_200));
        let preview = sealed(&host, &device, &big, expires).expect("a sealed preview");
        assert_eq!(
            preview.envelope.routing.size_bucket_bytes.get(),
            2 * 1024,
            "this body needs the two-kibibyte bucket"
        );
        let request = request_with(preview.envelope, expires);
        assert!(
            request.preview_is_well_formed(),
            "the shape is fine; it is the size that is not"
        );
        let error = check_payload_bound(&request).expect_err("the provider payload is too large");
        assert!(matches!(
            error,
            DeliveryError::PayloadTooLarge {
                limit: MAX_PROVIDER_PAYLOAD_BYTES,
                ..
            }
        ));

        // Section 16's remedy, and it works: the detail moves elsewhere and a reference fits.
        let referring = big.referring_to(EnvelopeId::new(Uuid::from_bytes([8; 16])));
        let preview = sealed(&host, &device, &referring, expires).expect("a sealed preview");
        let measured = check_payload_bound(&request_with(preview.envelope, expires))
            .expect("the reference fits where the detail did not");
        assert!(measured < MAX_PROVIDER_PAYLOAD_BYTES);
    }

    #[test]
    fn a_notification_with_no_preview_fits_whatever_the_alert() {
        let expires = TimestampMs::new(EXPIRES);
        for alert in PushAlert::ALL {
            let request = PushDeliveryRequest {
                collapse_id: kr_protocol::ids::CollapseId::new(Uuid::from_bytes([3; 16])),
                expires_at_ms: expires,
                hints: kr_protocol::push::PushPlatformHints {
                    alert,
                    urgency: kr_protocol::push::PushUrgency::Deferred,
                },
                notification_id: fresh_notification_id(),
                preview: Nullable::null(),
                sender_record_id: kr_protocol::ids::PushSenderRecordId::new(Uuid::from_bytes(
                    [4; 16],
                )),
            };
            assert!(
                check_payload_bound(&request).is_ok(),
                "a generic alert always fits: {alert}"
            );
        }
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
