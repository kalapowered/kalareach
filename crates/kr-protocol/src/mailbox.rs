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
use zeroize::Zeroizing;

use kr_cbor::CborError;

use crate::ids::{
    DeviceId, EnvelopeId, EnvironmentId, GrantId, MailboxThreadId, SessionEpoch, SessionId,
};
use crate::pairing::{AuthorityRevisionRecord, RevocationRequest};
use crate::scalars::{
    Bytes, Digest256, KeyId, Nonce192, Nullable, Signature64, StoredEnvelopeKey, TimestampMs, U64,
};

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
    /// An announcement that a device's authority feed changed.
    ///
    /// It announces and nothing more. Revocation records live in the durable authority feed, which
    /// has its own retention and is not coalesced with notifications; a device that sees this
    /// announcement synchronises the feed.
    AuthorityFeedChange,
    /// A receipt for one action the host admitted, dispatched or refused.
    ///
    /// It records what happened; it asks for nothing. An action reaches a host over its
    /// authenticated connection and comes back with a receipt, and this is how that receipt reaches
    /// a device that was not connected at the time.
    ActionReceipt,
    /// A reference to state a device can fetch from the host when it reconnects.
    ///
    /// A reference and not the state: what it names is read under current authority from the host
    /// that holds it. It is the repeated kind, so it is the one coalescing is mostly about.
    StateReference,
    /// A signed authority object forwarded to a device: a grant, a revocation request or a host
    /// authority revision record.
    ///
    /// The payload is the signed object's canonical bytes. The issuer's signature is what
    /// authorises it; the envelope only delivers it.
    SignedAuthorityObject,
    /// An encrypted notification preview.
    NotificationPreview,
    /// An announcement that a synchronised object changed.
    SyncChange,
}

impl MailboxPayloadType {
    /// Every payload kind, in declaration order.
    pub const ALL: [Self; 6] = [
        Self::AuthorityFeedChange,
        Self::ActionReceipt,
        Self::StateReference,
        Self::SignedAuthorityObject,
        Self::NotificationPreview,
        Self::SyncChange,
    ];

    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuthorityFeedChange => "authority_feed_change",
            Self::ActionReceipt => "action_receipt",
            Self::StateReference => "state_reference",
            Self::SignedAuthorityObject => "signed_authority_object",
            Self::NotificationPreview => "notification_preview",
            Self::SyncChange => "sync_change",
        }
    }

    /// Returns true when a payload of this type carries authority of its own.
    ///
    /// Section 20 requires an authorisation-bearing payload to be signed before encryption, so
    /// pairwise message authentication never substitutes for an issuer's grant signature. A reader
    /// that accepts such a payload without verifying the payload's own signature has accepted the
    /// sender's word for authority the sender may not hold.
    #[must_use]
    pub const fn bears_authority(self) -> bool {
        match self {
            Self::SignedAuthorityObject => true,
            Self::AuthorityFeedChange
            | Self::ActionReceipt
            | Self::StateReference
            | Self::NotificationPreview
            | Self::SyncChange => false,
        }
    }
}

/// What the payload of a `signed_authority_object` envelope decodes as.
///
/// Section 20 signs an authorisation-bearing payload **before** encryption, so pairwise message
/// authentication can never substitute for an issuer's grant signature. The set is closed, and it
/// is closed on one property: every member carries its issuer's key identifier and a signature
/// over a domain-separated transcript of its own fields. A payload outside it carries no authority
/// a reader could check, so the mailbox does not forward it as authority.
///
/// Nothing here is authority by arriving. [`Self::issuer_key_id`] names the key the signature must
/// verify under, and a reader resolves that name through the authority it already holds: section
/// 19 makes content data, and the envelope supplies no key of its own.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ForwardedAuthority {
    /// A remote owner's signed revocation request.
    RevocationRequest(RevocationRequest),
    /// One ordered authority revision a host issued.
    AuthorityRevision(AuthorityRevisionRecord),
}

/// Which kind of authority object a forwarded payload carries.
///
/// The two are issued by different devices in different roles: a paired owner publishes a
/// revocation request, and only the target host issues an ordered authority revision. A reader
/// resolves an issuer by device **and** by kind for that reason, so a key it records for one role
/// cannot sign for the other.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ForwardedAuthorityKind {
    /// A remote owner's signed revocation request.
    RevocationRequest,
    /// One ordered authority revision a host issued.
    AuthorityRevision,
}

impl ForwardedAuthorityKind {
    /// Every kind, in declaration order.
    pub const ALL: [Self; 2] = [Self::RevocationRequest, Self::AuthorityRevision];

    /// Returns the stable name this kind is reported under.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RevocationRequest => "revocation_request",
            Self::AuthorityRevision => "authority_revision",
        }
    }
}

impl core::fmt::Display for ForwardedAuthorityKind {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl ForwardedAuthority {
    /// Returns which kind of authority object this is.
    #[must_use]
    pub const fn kind(&self) -> ForwardedAuthorityKind {
        match self {
            Self::RevocationRequest(_) => ForwardedAuthorityKind::RevocationRequest,
            Self::AuthorityRevision(_) => ForwardedAuthorityKind::AuthorityRevision,
        }
    }

    /// Returns the device the object says issued it.
    ///
    /// This is the name a reader resolves a key through. Naming a device does not establish that
    /// it issued anything: the key the reader records for that device, in that role, is what the
    /// signature has to verify under, and the identifier the object carries has to be that key's.
    #[must_use]
    pub const fn issuer_device_id(&self) -> DeviceId {
        match self {
            Self::RevocationRequest(request) => request.issuer_device_id,
            Self::AuthorityRevision(record) => record.host_device_id,
        }
    }

    /// Returns the key identifier of the issuer whose signature covers this object.
    ///
    /// It is a name, not a key. What it names is checked against the key the reader records for
    /// [`Self::issuer_device_id`]; an object naming any other key is refused rather than trusted.
    #[must_use]
    pub const fn issuer_key_id(&self) -> KeyId {
        match self {
            Self::RevocationRequest(request) => request.issuer_key_id,
            Self::AuthorityRevision(record) => record.host_key_id,
        }
    }

    /// Returns the issuer's signature over [`Self::signing_input`].
    #[must_use]
    pub const fn signature(&self) -> Signature64 {
        match self {
            Self::RevocationRequest(request) => request.signature,
            Self::AuthorityRevision(record) => record.signature,
        }
    }

    /// Returns the domain the signature covers.
    #[must_use]
    pub const fn domain(&self) -> &'static str {
        match self {
            Self::RevocationRequest(_) => crate::pairing::REVOCATION_DOMAIN,
            Self::AuthorityRevision(_) => crate::pairing::AUTHORITY_REVISION_DOMAIN,
        }
    }

    /// Builds the canonical bytes this object's signature covers.
    ///
    /// # Errors
    ///
    /// Returns a CBOR error when the object cannot be represented in KR-CBOR-1.
    pub fn signing_input(&self) -> Result<Vec<u8>, CborError> {
        match self {
            Self::RevocationRequest(request) => request.signing_input(),
            Self::AuthorityRevision(record) => record.signing_input(),
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
    /// The thread repeated state notifications coalesce in, when the sender asks for coalescing.
    ///
    /// It is authenticated here as well as declared in the routing record, so a recipient can see
    /// that the value the service coalesced by is the value the sender chose.
    pub thread_id: Nullable<MailboxThreadId>,
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
    /// What the payload is.
    ///
    /// The service is told the kind so that it can refuse a kind the mailbox does not carry, which
    /// is section 9's rule that it queues no keystroke, command, decision or closure. It learns the
    /// kind and nothing about the payload; the recipient checks the declaration against the kind
    /// the box authenticated and drops the item when the two differ.
    pub payload_type: MailboxPayloadType,
    /// The thread the item coalesces in, when the sender asks for coalescing.
    ///
    /// Null means the item stands on its own and nothing replaces it. A value is opaque: the
    /// service compares it and never derives anything from it.
    pub thread_id: Nullable<MailboxThreadId>,
    /// The declared size bucket, in bytes: the length of the padded plaintext that was encrypted.
    ///
    /// Quota accounting measures the complete stored ciphertext rather than this figure.
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
            && self.payload_type == plaintext.payload_type
            && self.thread_id == plaintext.thread_id
    }

    /// Returns true when the declared bucket is a length one of section 20's rules produces.
    #[must_use]
    pub const fn bucket_is_declared(&self) -> bool {
        granularity_for_bucket(self.size_bucket_bytes.get()).is_some()
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

/// Bytes `crypto_box_easy` adds to the plaintext it seals.
///
/// A sealed envelope's ciphertext is therefore exactly its declared size bucket plus this, which is
/// what lets a service check that a ciphertext it cannot read was padded to a bucket before it was
/// sealed.
pub const SEAL_OVERHEAD_BYTES: u64 = 16;

/// How long a replay identifier is retained past its envelope's expiry, in milliseconds.
pub const REPLAY_ID_RETENTION_MS: u64 = 24 * 60 * 60 * 1000;

/// The longest a mailbox item may live, in milliseconds (section 9).
pub const MAX_MAILBOX_ITEM_LIFETIME_MS: u64 = 24 * 60 * 60 * 1000;

/// The most items one device's mailbox holds (section 9).
pub const MAX_MAILBOX_ITEMS: u64 = 1_000;

/// The most one stored item may occupy, in bytes.
///
/// A mailbox item travels as a control message, and section 9 bounds a control message at 1 MiB.
/// The bound is on the whole stored item — the ciphertext, the nonce and the routing record — so a
/// producer cannot reach past it by declaring a larger bucket than a message could carry.
pub const MAX_MAILBOX_ITEM_BYTES: u64 = 1024 * 1024;

/// The most stored ciphertext one device's mailbox holds, in bytes (section 9).
///
/// Quota accounting measures the complete stored ciphertext and envelope, not the unpadded
/// plaintext, so a sender cannot store more by padding less.
pub const MAX_MAILBOX_BYTES: u64 = 32 * 1024 * 1024;

/// Returns the instant a replay identifier may be forgotten: expiry plus one day.
#[must_use]
pub const fn replay_id_retained_until_ms(expires_at_ms: u64) -> u64 {
    expires_at_ms.saturating_add(REPLAY_ID_RETENTION_MS)
}

/// Why a sealed envelope is not one this contract admits.
///
/// Every variant is a check a service can make without a key, which is the point: the service
/// stores ciphertext it cannot read, so the only rules it can hold a sender to are the ones about
/// the envelope's shape. [`SealedEnvelope::check_structure`] is the whole of them, in one place, so
/// that a gateway and a producer cannot disagree about what a well-formed item is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum EnvelopeStructureError {
    /// The declared bucket is not a length section 20's padding rules produce.
    #[error("the declared size bucket of {bucket} bytes is not one the padding rules produce")]
    UndeclaredBucket {
        /// The bucket the routing record declared.
        bucket: u64,
    },
    /// The ciphertext is not the declared bucket plus the seal's own overhead.
    #[error("the ciphertext is {len} bytes; a bucket of {bucket} bytes seals to {expected}")]
    CiphertextLength {
        /// The ciphertext length that arrived.
        len: u64,
        /// The declared bucket.
        bucket: u64,
        /// The length the declared bucket seals to.
        expected: u64,
    },
    /// The item expires later than section 9 lets a mailbox item live.
    #[error("an item expires within {limit} ms; this one expires {ahead} ms from now")]
    LifetimeTooLong {
        /// How far ahead the expiry is.
        ahead: u64,
        /// The limit.
        limit: u64,
    },
    /// The item has already expired, so storing it would store something to delete.
    #[error("that item expired {behind} ms ago")]
    AlreadyExpired {
        /// How long ago it expired.
        behind: u64,
    },
    /// The item is larger than a control message may be.
    #[error("a stored item is at most {limit} bytes; this one occupies {stored}")]
    ItemTooLarge {
        /// What the item occupies.
        stored: u64,
        /// The limit.
        limit: u64,
    },
    /// An authority-bearing payload asked to be coalesced.
    ///
    /// Coalescing replaces an older unread item with a newer one of the same thread, and a
    /// forwarded signed object is authority rather than a state notification: section 10 keeps
    /// revocation records outside notification coalescing, so a payload that carries authority
    /// carries no thread identifier either.
    #[error("a payload that carries authority is never coalesced, so it names no thread")]
    AuthorityCoalesced,
}

impl SealedEnvelope {
    /// The bytes this envelope occupies in a mailbox: the ciphertext, the nonce and the routing.
    ///
    /// Quota accounting measures the complete stored ciphertext and envelope, so the figure
    /// includes what the service stores around the ciphertext rather than the ciphertext alone.
    #[must_use]
    pub fn stored_bytes(&self) -> u64 {
        let ciphertext = self.ciphertext.as_slice().len() as u64;
        ciphertext
            .saturating_add(Nonce192::LEN as u64)
            .saturating_add(ROUTING_RECORD_BYTES)
    }

    /// Checks everything about this envelope that needs no key, at `now_ms`.
    ///
    /// # Errors
    ///
    /// Returns the first rule the envelope breaks.
    pub fn check_structure(&self, now_ms: u64) -> Result<(), EnvelopeStructureError> {
        let bucket = self.routing.size_bucket_bytes.get();
        if granularity_for_bucket(bucket).is_none() {
            return Err(EnvelopeStructureError::UndeclaredBucket { bucket });
        }

        let expected = bucket.saturating_add(SEAL_OVERHEAD_BYTES);
        let len = self.ciphertext.as_slice().len() as u64;
        if len != expected {
            return Err(EnvelopeStructureError::CiphertextLength {
                len,
                bucket,
                expected,
            });
        }

        let expires = self.routing.expires_at_ms.get();
        if expires <= now_ms {
            return Err(EnvelopeStructureError::AlreadyExpired {
                behind: now_ms - expires,
            });
        }
        let ahead = expires - now_ms;
        if ahead > MAX_MAILBOX_ITEM_LIFETIME_MS {
            return Err(EnvelopeStructureError::LifetimeTooLong {
                ahead,
                limit: MAX_MAILBOX_ITEM_LIFETIME_MS,
            });
        }

        let stored = self.stored_bytes();
        if stored > MAX_MAILBOX_ITEM_BYTES {
            return Err(EnvelopeStructureError::ItemTooLarge {
                stored,
                limit: MAX_MAILBOX_ITEM_BYTES,
            });
        }

        if self.routing.payload_type.bears_authority() && self.routing.thread_id.is_present() {
            return Err(EnvelopeStructureError::AuthorityCoalesced);
        }

        Ok(())
    }
}

/// What the routing record and the item's own bookkeeping cost in a mailbox, in bytes.
///
/// It is a fixed allowance rather than a measurement: the record is a closed schema of two
/// identifiers, two key identifiers, a timestamp, a payload kind, an optional thread and a counter,
/// so its encoded size varies by a few bytes and a fixed figure keeps one sender's quota from
/// depending on how the service happens to store it.
pub const ROUTING_RECORD_BYTES: u64 = 256;

/// The domain the value that claims a mailbox is derived under.
pub const MAILBOX_CLAIM_DOMAIN: &str = "kr-mailbox-claim/1";

/// What a service asks of a device that says a mailbox is its own.
///
/// A mailbox is addressed by the identifier of the recipient's stored-envelope key, and every
/// paired peer of that recipient knows the key: it is what they seal to. So a service that served
/// a mailbox to whoever asked for it would serve a person's items to their own peers, and a
/// service that gave the mailbox to the first caller would let a peer take it. Neither is
/// acceptable, and neither needs a pairing record to fix: what distinguishes the recipient from
/// everybody who knows its public key is the private half.
///
/// The service generates one ephemeral X25519 keypair per challenge, derives the shared secret
/// with the claimed recipient key, and asks for [`mailbox_claim_value`] of it. Only the holder of
/// the recipient's private key can derive the same secret, so the answer proves possession without
/// the private key leaving the device and without the service holding anything that could open an
/// envelope: the secret is discarded with the challenge.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MailboxClaimChallenge {
    /// The mailbox the challenge is about.
    pub recipient_key_id: KeyId,
    /// The service's ephemeral X25519 public key for this challenge, and for no other.
    pub ephemeral_key: StoredEnvelopeKey,
    /// When the challenge stops being answerable, in UTC milliseconds.
    pub expires_at_ms: TimestampMs,
}

/// How long a claim challenge stays answerable, in milliseconds.
pub const MAILBOX_CLAIM_LIFETIME_MS: u64 = 5 * 60 * 1000;

/// The value that answers one claim challenge.
///
/// `SHA256(CBOR(["kr-mailbox-claim/1", ephemeral_key, recipient_key, shared_secret]))`, where the
/// shared secret is the X25519 agreement of the two keys. Both public keys are inside the hash, so
/// an answer derived for one challenge cannot answer another, and the domain keeps the value from
/// meaning anything anywhere else.
///
/// The agreement is a secret for as long as the challenge can be answered, so the bytes that are
/// hashed are one buffer that is wiped once the digest is taken: [`claim_input`] builds it by
/// hand. A value tree would hold copies of the agreement of its own, and dropping the tree would
/// release them without wiping them. The hash function's own working state is outside this crate.
#[must_use]
pub fn mailbox_claim_value(
    ephemeral_key: &StoredEnvelopeKey,
    recipient_key: &StoredEnvelopeKey,
    shared_secret: &[u8; 32],
) -> Digest256 {
    let input = claim_input(ephemeral_key, recipient_key, shared_secret);
    Digest256::from_bytes(kr_cbor::sha256(input.as_slice()))
}

/// `CBOR(["kr-mailbox-claim/1", ephemeral_key, recipient_key, shared_secret])`, in one buffer that
/// wipes itself when it is dropped.
///
/// The domain and the two keys are public, so they are encoded through the value tree. The
/// agreement is written after them by hand: `0x84` opens a four-element array, and `0x58 0x20` is
/// the head of a 32-byte string. The capacity is exact, so the buffer never grows once the
/// agreement is in it. `the_claim_input_is_the_canonical_encoding` holds these bytes to the
/// value-tree encoder.
fn claim_input(
    ephemeral_key: &StoredEnvelopeKey,
    recipient_key: &StoredEnvelopeKey,
    shared_secret: &[u8; 32],
) -> Zeroizing<Vec<u8>> {
    let public = [
        kr_cbor::encode(&kr_cbor::CanonicalValue::text(MAILBOX_CLAIM_DOMAIN)),
        kr_cbor::encode(&kr_cbor::CanonicalValue::bytes(
            ephemeral_key.as_bytes().as_slice(),
        )),
        kr_cbor::encode(&kr_cbor::CanonicalValue::bytes(
            recipient_key.as_bytes().as_slice(),
        )),
    ];
    let length = 1 + public.iter().map(Vec::len).sum::<usize>() + 2 + shared_secret.len();
    let mut input = Zeroizing::new(Vec::with_capacity(length));
    input.push(0x84);
    for encoded in &public {
        input.extend_from_slice(encoded);
    }
    input.push(0x58);
    input.push(0x20);
    input.extend_from_slice(shared_secret);
    debug_assert_eq!(
        input.len(),
        length,
        "the buffer is sized to exactly what it holds"
    );
    input
}

/// One kibibyte.
pub const KIB: u64 = 1024;

/// Plaintext at or below this size rounds to a multiple of one kibibyte.
pub const SMALL_MAILBOX_PLAINTEXT_BYTES: u64 = 16 * KIB;

/// Plaintext at or below this size rounds to a multiple of four kibibytes.
pub const MEDIUM_MAILBOX_PLAINTEXT_BYTES: u64 = 64 * KIB;

/// Returns the granularity a notification's plaintext is padded to, in bytes.
#[must_use]
pub const fn notification_granularity() -> u64 {
    KIB
}

/// Returns the granularity a mailbox item's plaintext is padded to, in bytes.
///
/// Plaintext up to 16 KiB rounds to 1 KiB, up to 64 KiB rounds to 4 KiB, and anything larger
/// rounds to 64 KiB.
#[must_use]
pub const fn mailbox_granularity(plaintext_len: u64) -> u64 {
    if plaintext_len <= SMALL_MAILBOX_PLAINTEXT_BYTES {
        KIB
    } else if plaintext_len <= MEDIUM_MAILBOX_PLAINTEXT_BYTES {
        4 * KIB
    } else {
        64 * KIB
    }
}

/// Returns the declared size bucket of a notification, in bytes.
#[must_use]
pub const fn notification_size_bucket(plaintext_len: u64) -> u64 {
    round_up_strictly(plaintext_len, notification_granularity())
}

/// Returns the declared size bucket of a mailbox item, in bytes.
#[must_use]
pub const fn mailbox_size_bucket(plaintext_len: u64) -> u64 {
    round_up_strictly(plaintext_len, mailbox_granularity(plaintext_len))
}

/// Returns the granularity a padded plaintext of `bucket` bytes was padded to.
///
/// The three bands do not overlap: 1 KiB granularity produces buckets from 1 KiB to 17 KiB, 4 KiB
/// produces 20 KiB to 68 KiB, and 64 KiB produces 128 KiB upwards. A reader can therefore recover
/// the granularity from the padded length alone, which is what it has before it unpads.
///
/// Returns `None` when `bucket` is not a length any of the three rules produces.
#[must_use]
pub const fn granularity_for_bucket(bucket: u64) -> Option<u64> {
    let granularity = if bucket <= SMALL_MAILBOX_PLAINTEXT_BYTES + KIB {
        KIB
    } else if bucket <= MEDIUM_MAILBOX_PLAINTEXT_BYTES + 4 * KIB {
        4 * KIB
    } else {
        64 * KIB
    };
    if bucket == 0 || !bucket.is_multiple_of(granularity) {
        return None;
    }
    Some(granularity)
}

/// Rounds `value` up to the next multiple of `granularity` that is strictly larger than it.
///
/// The bucket is the length of the *padded* plaintext, and the padding this crate's callers use
/// always adds at least one byte so that it can be removed unambiguously. A plaintext that is
/// already an exact multiple of the granularity therefore rounds to the next multiple rather than
/// to itself.
const fn round_up_strictly(value: u64, granularity: u64) -> u64 {
    value
        .saturating_div(granularity)
        .saturating_add(1)
        .saturating_mul(granularity)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notification_buckets_round_to_one_kibibyte() {
        assert_eq!(notification_size_bucket(0), KIB);
        assert_eq!(notification_size_bucket(1), KIB);
        // An exact multiple rounds up, because the padding always adds at least one byte.
        assert_eq!(notification_size_bucket(KIB), 2 * KIB);
        assert_eq!(notification_size_bucket(KIB + 1), 2 * KIB);
    }

    #[test]
    fn mailbox_buckets_follow_the_three_ranges() {
        assert_eq!(mailbox_size_bucket(1), KIB);
        assert_eq!(mailbox_size_bucket(16 * KIB), 17 * KIB);
        assert_eq!(mailbox_size_bucket(16 * KIB + 1), 20 * KIB);
        assert_eq!(mailbox_size_bucket(64 * KIB), 68 * KIB);
        assert_eq!(mailbox_size_bucket(64 * KIB + 1), 128 * KIB);
        assert_eq!(mailbox_size_bucket(200 * KIB), 256 * KIB);
    }

    #[test]
    fn a_bucket_names_exactly_one_granularity() {
        for len in [0u64, 1, 1023, 16 * KIB, 16 * KIB + 1, 64 * KIB, 200 * KIB] {
            let bucket = mailbox_size_bucket(len);
            assert_eq!(
                granularity_for_bucket(bucket),
                Some(mailbox_granularity(len)),
                "granularity recovered from the bucket for {len} bytes"
            );
        }
        assert_eq!(granularity_for_bucket(0), None);
        assert_eq!(granularity_for_bucket(1), None);
        assert_eq!(granularity_for_bucket(18 * KIB), None);
        assert_eq!(granularity_for_bucket(100 * KIB), None);
    }

    #[test]
    fn every_bucket_leaves_room_for_at_least_one_padding_byte() {
        for len in [0u64, 1, 1023, 1024, 1025, 16 * KIB, 64 * KIB, 200 * KIB] {
            assert!(mailbox_size_bucket(len) > len, "bucket for {len} bytes");
            assert_eq!(mailbox_size_bucket(len) % mailbox_granularity(len), 0);
            assert!(notification_size_bucket(len) > len);
        }
    }

    #[test]
    fn an_item_larger_than_a_control_message_is_refused() {
        // Section 9 bounds a control message at 1 MiB, and a mailbox item travels as one. The
        // bound is on the whole stored item, so a larger bucket cannot reach past it.
        let bucket = 1024 * KIB;
        let envelope = sealed(bucket, 1_000 + MAX_MAILBOX_ITEM_LIFETIME_MS);
        assert!(matches!(
            envelope.check_structure(1_000),
            Err(EnvelopeStructureError::ItemTooLarge { .. })
        ));
        // One bucket down fits, with the nonce and the routing record inside the bound.
        let smaller = sealed(bucket - 64 * KIB, 1_000 + MAX_MAILBOX_ITEM_LIFETIME_MS);
        assert_eq!(smaller.check_structure(1_000), Ok(()));
    }

    #[test]
    fn a_claim_value_names_both_keys_and_the_secret() {
        let ephemeral = StoredEnvelopeKey::from_bytes([1; 32]);
        let recipient = StoredEnvelopeKey::from_bytes([2; 32]);
        let secret = [3u8; 32];

        let value = mailbox_claim_value(&ephemeral, &recipient, &secret);
        assert_eq!(value, mailbox_claim_value(&ephemeral, &recipient, &secret));
        // A different challenge, a different mailbox or a different secret is a different answer,
        // so an answer cannot be carried from one challenge to another.
        assert_ne!(
            value,
            mailbox_claim_value(&StoredEnvelopeKey::from_bytes([9; 32]), &recipient, &secret)
        );
        assert_ne!(
            value,
            mailbox_claim_value(&ephemeral, &StoredEnvelopeKey::from_bytes([9; 32]), &secret)
        );
        assert_ne!(value, mailbox_claim_value(&ephemeral, &recipient, &[9; 32]));
    }

    /// KR-REQ-20.02: the bytes that are hashed are the ones the value-tree encoder writes, so
    /// building them by hand, in one buffer that wipes itself, changes no answer.
    #[test]
    fn the_claim_input_is_the_canonical_encoding() {
        for (ephemeral, recipient, secret) in [
            ([1u8; 32], [2u8; 32], [3u8; 32]),
            ([0x55; 32], [0x66; 32], [0x77; 32]),
            (
                [0; 32],
                [0xff; 32],
                core::array::from_fn(|index| index as u8),
            ),
        ] {
            let ephemeral = StoredEnvelopeKey::from_bytes(ephemeral);
            let recipient = StoredEnvelopeKey::from_bytes(recipient);
            let through_the_tree = kr_cbor::encode(&kr_cbor::signing_value(
                MAILBOX_CLAIM_DOMAIN,
                vec![
                    kr_cbor::CanonicalValue::bytes(ephemeral.as_bytes().as_slice()),
                    kr_cbor::CanonicalValue::bytes(recipient.as_bytes().as_slice()),
                    kr_cbor::CanonicalValue::bytes(secret.as_slice()),
                ],
            ));
            let assembled = claim_input(&ephemeral, &recipient, &secret);
            assert_eq!(assembled.as_slice(), through_the_tree.as_slice());
            assert_eq!(
                mailbox_claim_value(&ephemeral, &recipient, &secret),
                Digest256::from_bytes(kr_cbor::sha256(&through_the_tree))
            );
        }
    }

    /// The value the published vector names, which a service computes on its side from the same
    /// inputs: building the input by hand leaves it where it was.
    #[test]
    fn the_claim_value_is_the_published_vector() {
        let value = mailbox_claim_value(
            &StoredEnvelopeKey::from_bytes([0x55; 32]),
            &StoredEnvelopeKey::from_bytes([0x66; 32]),
            &[0x77; 32],
        );
        let hex = value
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert_eq!(
            hex,
            "8423aebc8cb33464091d17c30a22b1ee0fd55c8c94695b220be680af9fa08435"
        );
    }

    #[test]
    fn the_payload_kinds_are_closed_and_none_of_them_is_an_action() {
        // Section 9 is a list of what a mailbox does not queue: keystrokes, shell commands,
        // approval decisions, process termination and session closure. The set below is what it
        // does carry, and there is no kind an action could arrive under.
        assert_eq!(
            MailboxPayloadType::ALL.map(MailboxPayloadType::as_str),
            [
                "authority_feed_change",
                "action_receipt",
                "state_reference",
                "signed_authority_object",
                "notification_preview",
                "sync_change",
            ]
        );
    }

    #[test]
    fn only_a_forwarded_signed_object_bears_authority() {
        assert!(MailboxPayloadType::SignedAuthorityObject.bears_authority());
        // An announcement is not authority: the device synchronises the feed to learn what
        // changed, and the feed's own signed records carry the authority.
        assert!(!MailboxPayloadType::AuthorityFeedChange.bears_authority());
        assert!(!MailboxPayloadType::ActionReceipt.bears_authority());
        assert!(!MailboxPayloadType::StateReference.bears_authority());
        assert!(!MailboxPayloadType::NotificationPreview.bears_authority());
        assert!(!MailboxPayloadType::SyncChange.bears_authority());
    }

    fn sealed(bucket: u64, expires_at_ms: u64) -> SealedEnvelope {
        SealedEnvelope {
            routing: EnvelopeRouting {
                envelope_id: EnvelopeId::new(crate::scalars::Uuid::from_bytes([1; 16])),
                recipient_key_id: KeyId::from_bytes([2; 32]),
                sender_key_id: KeyId::from_bytes([3; 32]),
                expires_at_ms: TimestampMs::new(expires_at_ms),
                payload_type: MailboxPayloadType::SyncChange,
                thread_id: Nullable::null(),
                size_bucket_bytes: U64::new(bucket),
            },
            nonce: Nonce192::from_bytes([4; 24]),
            ciphertext: Bytes::from(vec![0u8; (bucket + SEAL_OVERHEAD_BYTES) as usize]),
        }
    }

    #[test]
    fn an_envelope_is_admitted_when_its_shape_is_the_one_the_rules_produce() {
        let envelope = sealed(KIB, 1_000 + MAX_MAILBOX_ITEM_LIFETIME_MS);
        assert_eq!(envelope.check_structure(1_000), Ok(()));
        assert!(envelope.routing.bucket_is_declared());
    }

    #[test]
    fn a_bucket_no_padding_rule_produces_is_refused() {
        let envelope = sealed(KIB, 2_000);
        let mut routing = envelope.routing.clone();
        routing.size_bucket_bytes = U64::new(18 * KIB);
        let claimed = SealedEnvelope {
            routing,
            ..envelope
        };
        assert_eq!(
            claimed.check_structure(1_000),
            Err(EnvelopeStructureError::UndeclaredBucket { bucket: 18 * KIB })
        );
        assert!(!claimed.routing.bucket_is_declared());
    }

    #[test]
    fn a_ciphertext_that_is_not_its_bucket_sealed_is_refused() {
        let mut envelope = sealed(KIB, 2_000);
        envelope.ciphertext = Bytes::from(vec![0u8; (KIB + SEAL_OVERHEAD_BYTES - 1) as usize]);
        assert_eq!(
            envelope.check_structure(1_000),
            Err(EnvelopeStructureError::CiphertextLength {
                len: KIB + SEAL_OVERHEAD_BYTES - 1,
                bucket: KIB,
                expected: KIB + SEAL_OVERHEAD_BYTES,
            })
        );
    }

    #[test]
    fn an_item_lives_at_most_one_day_and_never_in_the_past() {
        let long = sealed(KIB, 1_000 + MAX_MAILBOX_ITEM_LIFETIME_MS + 1);
        assert_eq!(
            long.check_structure(1_000),
            Err(EnvelopeStructureError::LifetimeTooLong {
                ahead: MAX_MAILBOX_ITEM_LIFETIME_MS + 1,
                limit: MAX_MAILBOX_ITEM_LIFETIME_MS,
            })
        );
        let past = sealed(KIB, 900);
        assert_eq!(
            past.check_structure(1_000),
            Err(EnvelopeStructureError::AlreadyExpired { behind: 100 })
        );
    }

    #[test]
    fn a_forwarded_signed_object_names_no_thread() {
        let mut envelope = sealed(KIB, 2_000);
        envelope.routing.payload_type = MailboxPayloadType::SignedAuthorityObject;
        envelope.routing.thread_id = Nullable::some(crate::ids::MailboxThreadId::new(
            crate::scalars::Uuid::from_bytes([9; 16]),
        ));
        assert_eq!(
            envelope.check_structure(1_000),
            Err(EnvelopeStructureError::AuthorityCoalesced)
        );
        envelope.routing.thread_id = Nullable::null();
        assert_eq!(envelope.check_structure(1_000), Ok(()));
    }

    #[test]
    fn routing_is_checked_against_the_kind_and_thread_the_box_authenticated() {
        let thread = crate::ids::MailboxThreadId::new(crate::scalars::Uuid::from_bytes([9; 16]));
        let plaintext = EnvelopePlaintext {
            version: EnvelopeVersion::V1,
            envelope_id: EnvelopeId::new(crate::scalars::Uuid::from_bytes([1; 16])),
            sender_key_id: KeyId::from_bytes([3; 32]),
            recipient_key_id: KeyId::from_bytes([2; 32]),
            payload_type: MailboxPayloadType::SyncChange,
            created_at_ms: TimestampMs::new(1_000),
            expires_at_ms: TimestampMs::new(2_000),
            grant_id: Nullable::null(),
            environment_id: Nullable::null(),
            session_id: Nullable::null(),
            session_epoch: Nullable::null(),
            thread_id: Nullable::some(thread),
            payload: Bytes::from(vec![7u8; 4]),
        };
        let mut routing = sealed(KIB, 2_000).routing;
        routing.thread_id = Nullable::some(thread);
        assert!(routing.matches(&plaintext));

        // A service that coalesced by another thread, or relabelled the kind, is caught here.
        let mut relabelled = routing.clone();
        relabelled.payload_type = MailboxPayloadType::NotificationPreview;
        assert!(!relabelled.matches(&plaintext));
        let mut rethreaded = routing;
        rethreaded.thread_id = Nullable::null();
        assert!(!rethreaded.matches(&plaintext));
    }

    #[test]
    fn stored_bytes_measure_the_ciphertext_the_nonce_and_the_routing() {
        let envelope = sealed(KIB, 2_000);
        assert_eq!(
            envelope.stored_bytes(),
            KIB + SEAL_OVERHEAD_BYTES + Nonce192::LEN as u64 + ROUTING_RECORD_BYTES
        );
    }

    #[test]
    fn a_replay_identifier_outlives_its_envelope_by_one_day() {
        assert_eq!(replay_id_retained_until_ms(1_000), 1_000 + 86_400_000);
        assert_eq!(replay_id_retained_until_ms(u64::MAX), u64::MAX);
    }
}
