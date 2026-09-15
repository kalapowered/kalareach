//! Mailbox envelopes: the stored-item format of section 20.
//!
//! A mailbox item is a versioned envelope, serialised as deterministic CBOR and encrypted
//! separately for each recipient with `crypto_box_easy`. This module holds the plaintext that the
//! box authenticates, the routing record the service is allowed to see, and the rule that ties one
//! to the other. `kr-crypto` seals and opens them.
//!
//! # Why routing is checked against the plaintext
//!
//! Routing metadata outside the encryption is untrusted. A service can rewrite it, so a reader
//! that acted on it would be acting on the service's word. [`EnvelopeRouting::matches`] states the
//! check: every routing field must equal the field the box authenticated, or the item is dropped.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ids::{EnvelopeId, EnvironmentId, GrantId, SessionEpoch, SessionId};
use crate::scalars::{Bytes, KeyId, Nonce192, Nullable, TimestampMs, U64};

/// The envelope format this build writes and reads.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub enum EnvelopeVersion {
    /// Version 1.
    #[serde(rename = "kr-mailbox/1")]
    V1,
}

/// What an envelope carries.
///
/// The set is closed. A new payload kind is a new schema, not a new string a sender may invent:
/// section 23 forbids unknown fields and strip-and-verify behaviour on signed objects, and the
/// same rule applies to the type that decides how a payload is interpreted.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum MailboxPayloadType {
    /// An announcement that a device's authority feed changed. It announces; it does not carry
    /// authority.
    AuthorityFeedChange,
    /// A signed revocation request published by a remote owner.
    RevocationRequest,
    /// An encrypted notification preview.
    NotificationPreview,
    /// An announcement that a synchronised object changed.
    SyncChange,
}

impl MailboxPayloadType {
    /// Returns true when a payload of this type carries authority of its own.
    ///
    /// Section 20 requires an authorisation-bearing payload to be signed before encryption, so
    /// pairwise message authentication never substitutes for an issuer's grant signature. A reader
    /// that accepts one of these types without verifying the payload's own signature has accepted
    /// the sender's word for authority the sender may not hold.
    #[must_use]
    pub const fn bears_authority(self) -> bool {
        match self {
            Self::AuthorityFeedChange | Self::RevocationRequest => true,
            Self::NotificationPreview | Self::SyncChange => false,
        }
    }
}

/// The authenticated plaintext of one mailbox envelope.
///
/// `crypto_box_easy` authenticates every field below for exactly one recipient. Authorisation-
/// bearing payloads are signed before encryption, so pairwise message authentication never
/// substitutes for an issuer's grant signature.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EnvelopePlaintext {
    /// The envelope format version.
    pub version: EnvelopeVersion,
    /// The envelope identity. It is also the replay identifier.
    pub envelope_id: EnvelopeId,
    /// The sender's stored-envelope key.
    pub sender_key_id: KeyId,
    /// The recipient's stored-envelope key.
    pub recipient_key_id: KeyId,
    /// What the payload is.
    pub payload_type: MailboxPayloadType,
    /// When the sender created it, in UTC milliseconds.
    pub created_at_ms: TimestampMs,
    /// When it expires, in UTC milliseconds.
    pub expires_at_ms: TimestampMs,
    /// The grant the payload acts under, when it has one.
    pub grant_id: Nullable<GrantId>,
    /// The environment the payload targets, when it targets one.
    pub environment_id: Nullable<EnvironmentId>,
    /// The session the payload targets, when it targets one.
    pub session_id: Nullable<SessionId>,
    /// The epoch of that session.
    pub session_epoch: Nullable<SessionEpoch>,
    /// The payload. An authorisation-bearing payload is a signed object's canonical bytes.
    pub payload: Bytes,
}

/// The untrusted routing record a service stores beside the ciphertext.
///
/// The service needs an address and an expiry to deliver and expire the item. It is given nothing
/// else, and what it is given is checked against the decrypted envelope before use.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EnvelopeRouting {
    /// The envelope identity the service indexes by.
    pub envelope_id: EnvelopeId,
    /// The recipient the service delivers to.
    pub recipient_key_id: KeyId,
    /// The sender, so a recipient can select a paired sender key before attempting to open.
    pub sender_key_id: KeyId,
    /// When the service may delete the item, in UTC milliseconds.
    pub expires_at_ms: TimestampMs,
    /// The declared size bucket, in bytes. Quota accounting measures stored bytes, not this.
    pub size_bucket_bytes: U64,
}

impl EnvelopeRouting {
    /// Returns true when every routing field matches the field the box authenticated.
    #[must_use]
    pub fn matches(&self, plaintext: &EnvelopePlaintext) -> bool {
        self.envelope_id == plaintext.envelope_id
            && self.recipient_key_id == plaintext.recipient_key_id
            && self.sender_key_id == plaintext.sender_key_id
            && self.expires_at_ms == plaintext.expires_at_ms
    }
}

/// One envelope sealed for one recipient.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SealedEnvelope {
    /// The routing record the service sees.
    pub routing: EnvelopeRouting,
    /// The fresh 24-byte nonce, from libsodium's random generator.
    pub nonce: Nonce192,
    /// The `crypto_box_easy` output over the canonical plaintext.
    pub ciphertext: Bytes,
}

/// How long a replay identifier is retained past its envelope's expiry, in milliseconds.
pub const REPLAY_ID_RETENTION_MS: u64 = 24 * 60 * 60 * 1000;

/// Returns the instant a replay identifier may be forgotten: expiry plus one day.
#[must_use]
pub const fn replay_id_retained_until_ms(expires_at_ms: u64) -> u64 {
    expires_at_ms.saturating_add(REPLAY_ID_RETENTION_MS)
}

/// One kibibyte.
pub const KIB: u64 = 1024;

/// Plaintext at or below this size rounds to a multiple of one kibibyte.
pub const SMALL_MAILBOX_PLAINTEXT_BYTES: u64 = 16 * KIB;

/// Plaintext at or below this size rounds to a multiple of four kibibytes.
pub const MEDIUM_MAILBOX_PLAINTEXT_BYTES: u64 = 64 * KIB;

/// Returns the declared size bucket of a notification, in bytes.
///
/// Notifications round to one kibibyte.
#[must_use]
pub const fn notification_size_bucket(plaintext_len: u64) -> u64 {
    round_up(plaintext_len, KIB)
}

/// Returns the declared size bucket of a mailbox item, in bytes.
///
/// Plaintext up to 16 KiB rounds to 1 KiB, up to 64 KiB rounds to 4 KiB, and anything larger
/// rounds to 64 KiB.
#[must_use]
pub const fn mailbox_size_bucket(plaintext_len: u64) -> u64 {
    if plaintext_len <= SMALL_MAILBOX_PLAINTEXT_BYTES {
        round_up(plaintext_len, KIB)
    } else if plaintext_len <= MEDIUM_MAILBOX_PLAINTEXT_BYTES {
        round_up(plaintext_len, 4 * KIB)
    } else {
        round_up(plaintext_len, 64 * KIB)
    }
}

/// Rounds `value` up to the next multiple of `granularity`.
const fn round_up(value: u64, granularity: u64) -> u64 {
    if value == 0 {
        return granularity;
    }
    value.div_ceil(granularity).saturating_mul(granularity)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notification_buckets_round_to_one_kibibyte() {
        assert_eq!(notification_size_bucket(0), KIB);
        assert_eq!(notification_size_bucket(1), KIB);
        assert_eq!(notification_size_bucket(KIB), KIB);
        assert_eq!(notification_size_bucket(KIB + 1), 2 * KIB);
    }

    #[test]
    fn mailbox_buckets_follow_the_three_ranges() {
        assert_eq!(mailbox_size_bucket(1), KIB);
        assert_eq!(mailbox_size_bucket(16 * KIB), 16 * KIB);
        assert_eq!(mailbox_size_bucket(16 * KIB + 1), 20 * KIB);
        assert_eq!(mailbox_size_bucket(64 * KIB), 64 * KIB);
        assert_eq!(mailbox_size_bucket(64 * KIB + 1), 128 * KIB);
        assert_eq!(mailbox_size_bucket(200 * KIB), 256 * KIB);
    }

    #[test]
    fn the_authority_bearing_payload_types_are_the_signed_ones() {
        assert!(MailboxPayloadType::AuthorityFeedChange.bears_authority());
        assert!(MailboxPayloadType::RevocationRequest.bears_authority());
        assert!(!MailboxPayloadType::NotificationPreview.bears_authority());
        assert!(!MailboxPayloadType::SyncChange.bears_authority());
    }

    #[test]
    fn a_replay_identifier_outlives_its_envelope_by_one_day() {
        assert_eq!(replay_id_retained_until_ms(1_000), 1_000 + 86_400_000);
        assert_eq!(replay_id_retained_until_ms(u64::MAX), u64::MAX);
    }
}
