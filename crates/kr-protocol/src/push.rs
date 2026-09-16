//! Notifications: registration, sender authorisation and delivery (section 16).
//!
//! A host cannot reach a phone that is asleep. A push provider can, so KalaReach sends through one,
//! and the whole of this module exists to make that possible without the provider, the gateway or
//! anyone watching the network learning what the notification says.
//!
//! Three things happen in order, and each one refuses to start before the one before it finished.
//!
//! 1. **Registration.** An installation asks the gateway to bind a provider token to its identity.
//!    The gateway sends a single-use challenge *through the provider, to that token*, and waits for
//!    it to come back signed. An authenticated request proves the caller holds a key; only the
//!    round trip proves the caller receives what is sent to that token.
//! 2. **Authorisation.** The installation authorises one paired host, naming that host's endpoint
//!    and signing keys, and receives a delivery credential to pass to it through the paired
//!    encrypted channel. The authorisation lasts until it is revoked; the credential lasts thirty
//!    days and is renewed by the host proving it still holds the key the installation named.
//! 3. **Delivery.** The host sends an encrypted preview with an opaque identifier, an expiry and a
//!    collapse label. The gateway checks the size, the rate and nothing else, and hands it to the
//!    provider.
//!
//! # What the gateway holds, and what it is not
//!
//! It holds two things worth naming. The provider registration token, because FCM needs the token
//! itself to deliver and to retry, and no hash recovers one: it lives with the gateway's own
//! secrets, and every record in this module carries [`token_digest`] instead, which is what the
//! gateway indexes and counts by. And the digest of each delivery credential, never the credential,
//! so a copy of the database is not a set of working bearers.
//!
//! It is not an account system and not a host authorisation service. Nothing here mentions an
//! account, because none is needed: a self-hosted installation forwards through the official
//! gateway on the strength of its own key.
//!
//! It is not a decryption point either. The preview is sealed to the destination device's
//! notification-preview key (section 10), which the gateway never holds, so no preview text is
//! readable there. What a compromised gateway does have is everything outside the seal: the routing
//! metadata, which host sends to which installation and how often, the alert each notification
//! carries, and the ability to withhold a notification, replay one, or send one of its own with any
//! alert in the vocabulary. The device's own state, not the alert, is what an action is taken
//! against.
//!
//! # What is signed, and by whom
//!
//! | Domain | Signed by | What it states |
//! | --- | --- | --- |
//! | [`PUSH_REGISTRATION_ANSWER_DOMAIN`] | the proposed installation key | The challenge sent to this token arrived here |
//! | [`PUSH_SENDER_BINDING_DOMAIN`] | nobody; it is digested | What an authorisation fixes for its lifetime |
//! | [`PUSH_SENDER_RENEWAL_DOMAIN`] | the host signing key | The host that was authorised is still here |
//! | [`PUSH_SENDER_REVOCATION_DOMAIN`] | the host signing key | This authorisation is finished |
//! | [`PUSH_DELIVERY_DOMAIN`] | nobody; it is digested | Which notification a request is, for deduplication |
//! | [`PUSH_TOKEN_DOMAIN`] | nobody; it is digested | Which provider token a record is about |
//! | [`PUSH_CREDENTIAL_DOMAIN`] | nobody; it is digested | Which stored credential a bearer matches |
//!
//! The four request bodies of [`PushRequest`] are authenticated by
//! [`crate::service::ServiceRequestSignature`], the credential every managed-service method shares:
//! the signature covers [`PushRequest::digest`] as its body digest, and [`PushRequest::method`] is
//! the method that signature must name, so a body for one method cannot be presented under another.
//! Delivery is different: it carries the bearer credential the host was issued, and no signature.

use kr_cbor::{CborError, sha256, signing_value};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ids::{
    CollapseId, InstallationId, NotificationId, PushRegistrationId, PushSenderRecordId,
    PushSenderRevision,
};
use crate::mailbox::{
    SEAL_OVERHEAD_BYTES, SealedEnvelope, granularity_for_bucket, notification_granularity,
};
use crate::method::Method;
use crate::scalars::{
    AuthorisationKey, Digest256, DurationMs, EndpointKey, Nonce256, Nullable, SecretBytes32,
    Signature64, TimestampMs, U64,
};
use crate::service::{GatewayOrigin, ServiceRequestSigner};

/// The domain a registration answer's signature covers.
pub const PUSH_REGISTRATION_ANSWER_DOMAIN: &str = "kr-push-registration/1";

/// The domain the immutable half of a sender record is digested under.
pub const PUSH_SENDER_BINDING_DOMAIN: &str = "kr-push-sender/1";

/// The domain a renewal proof's signature covers.
pub const PUSH_SENDER_RENEWAL_DOMAIN: &str = "kr-push-sender-renewal/1";

/// The domain a revocation's signature covers.
pub const PUSH_SENDER_REVOCATION_DOMAIN: &str = "kr-push-sender-revocation/1";

/// The domain a delivery request is digested under, to recognise one already handled.
pub const PUSH_DELIVERY_DOMAIN: &str = "kr-push-delivery/1";

/// The domain a provider token is digested under.
pub const PUSH_TOKEN_DOMAIN: &str = "kr-push-token/1";

/// The domain a delivery credential's bearer is digested under.
pub const PUSH_CREDENTIAL_DOMAIN: &str = "kr-push-credential/1";

/// How long a registration challenge stays answerable, in milliseconds (section 16).
pub const REGISTRATION_CHALLENGE_LIFETIME_MS: u64 = 5 * 60 * 1000;

/// How long a delivery credential lasts, in milliseconds (section 16).
pub const DELIVERY_CREDENTIAL_LIFETIME_MS: u64 = 30 * 24 * 60 * 60 * 1000;

/// How long before expiry a host may renew its delivery credential, in milliseconds (section 16).
pub const SENDER_RENEWAL_WINDOW_MS: u64 = 7 * 24 * 60 * 60 * 1000;

/// The most preview text plus inner metadata may be before encryption, in bytes (section 16).
///
/// It is a producer bound, enforced where the plaintext exists: the host assembles the preview,
/// checks it against this, and moves anything larger into a referenced encrypted object. A gateway
/// holds no key that opens a preview, so it cannot check this figure and does not try. What it
/// checks is [`MAX_PROVIDER_PAYLOAD_BYTES`] on the request it is about to send.
pub const MAX_PREVIEW_PLAINTEXT_BYTES: u64 = 1_800;

/// The complete provider payload stays below this many bytes, after encryption and base64.
///
/// Section 16 fixes the figure and says to measure rather than estimate: the expansion from
/// plaintext to a JSON provider request is not a ratio anyone should be relying on. The bound is
/// exclusive, as section 16 words it.
pub const MAX_PROVIDER_PAYLOAD_BYTES: u64 = 3_500;

/// Notifications a free destination may receive in a burst (section 16).
pub const FREE_PUSH_BURST: u64 = 20;

/// Notifications a free destination may receive in an hour (section 16).
pub const FREE_PUSH_PER_HOUR: u64 = 60;

/// How often suppressed notifications collapse into one attention update, in milliseconds.
pub const PUSH_COLLAPSE_WINDOW_MS: u64 = 5 * 60 * 1000;

/// A push platform, as the gateway builds a payload for it.
///
/// Both go through FCM HTTP v1. The distinction is the payload: an iOS message carries the APNs
/// alert, `mutable-content`, expiry and collapse headers the notification extension needs, and
/// Firebase forwards it through APNs with KalaReach's registered key and app topic.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum PushPlatform {
    /// Android, through FCM directly.
    Android,
    /// iOS, through FCM to APNs.
    Ios,
}

impl PushPlatform {
    /// Both platforms, in declaration order.
    pub const ALL: [Self; 2] = [Self::Android, Self::Ios];

    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Android => "android",
            Self::Ios => "ios",
        }
    }
}

impl core::fmt::Display for PushPlatform {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The digest one provider token is indexed by.
///
/// It names the destination, and nothing about the caller goes into it. In particular the platform
/// does not: receiving the challenge proves the token reaches this device, and proves nothing about
/// the label the caller put beside it. A digest that included the label would let one device
/// register one token twice, once under each label, and start its rate history again, which is the
/// alias section 16 forbids.
///
/// The gateway indexes and counts by this digest. The token itself is a delivery capability, so it
/// is held where the gateway keeps its own secrets, never in a record that travels: the caller
/// supplies it at registration, the gateway retains it for delivery and retries, and every record
/// in this module carries the digest instead.
#[must_use]
pub fn token_digest(token: &RegistrationToken) -> Digest256 {
    let value = signing_value(
        PUSH_TOKEN_DOMAIN,
        vec![kr_cbor::CanonicalValue::text(token.as_str())],
    );
    Digest256::from_bytes(kr_cbor::sha256_of_canonical(&value))
}

/// The longest a provider registration token may be, in bytes.
///
/// FCM tokens are a few hundred characters and have no published ceiling, so the bound is generous
/// and exists to stop an unbounded allocation rather than to describe a provider.
pub const MAX_REGISTRATION_TOKEN_LEN: usize = 1024;

/// A provider registration token, as the device's SDK issues it.
///
/// It reaches the gateway once, in a registration request, and is never carried in a record that
/// leaves it. Anything holding one can have messages delivered to that device, which is why the
/// records here carry [`token_digest`] instead.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct RegistrationToken(String);

impl core::fmt::Debug for RegistrationToken {
    /// Renders the length and nothing else.
    ///
    /// A token is a delivery capability, so a debug rendering of a registration request, or of the
    /// enclosing [`PushRequest`], must not put one in a log. The length is enough to tell an empty
    /// field from a present one while debugging.
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "RegistrationToken({} bytes)", self.0.len())
    }
}

/// A registration token that is empty, over-long or not printable ASCII.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegistrationTokenError(&'static str);

impl core::fmt::Display for RegistrationTokenError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for RegistrationTokenError {}

impl RegistrationToken {
    /// Validates and wraps a token.
    ///
    /// # Errors
    ///
    /// Returns [`RegistrationTokenError`] naming the rule the text breaks.
    pub fn new(value: impl Into<String>) -> Result<Self, RegistrationTokenError> {
        let value = value.into();
        if value.is_empty() {
            return Err(RegistrationTokenError("a registration token is not empty"));
        }
        if value.len() > MAX_REGISTRATION_TOKEN_LEN {
            return Err(RegistrationTokenError(
                "a registration token is at most 1024 bytes",
            ));
        }
        if value.bytes().any(|byte| !(b'!'..=b'~').contains(&byte)) {
            return Err(RegistrationTokenError(
                "a registration token is printable ASCII without spaces",
            ));
        }
        Ok(Self(value))
    }

    /// Returns the token text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl core::str::FromStr for RegistrationToken {
    type Err = RegistrationTokenError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::new(text)
    }
}

impl<'de> Deserialize<'de> for RegistrationToken {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::new(text).map_err(serde::de::Error::custom)
    }
}

impl JsonSchema for RegistrationToken {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "RegistrationToken".into()
    }

    fn schema_id() -> std::borrow::Cow<'static, str> {
        "kalareach::RegistrationToken".into()
    }

    fn json_schema(_generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "string",
            "minLength": 1,
            "maxLength": MAX_REGISTRATION_TOKEN_LEN,
            "description": "A provider registration token, printable ASCII without spaces. It reaches the gateway once and is never carried in a record that leaves it."
        })
    }
}

/// What a destination may receive, and how excess collapses.
///
/// Free push has its own budget and is never charged against a voice balance (section 17). The
/// policy is fixed when an authorisation is issued and a renewal cannot change it, so a host
/// cannot widen its own allowance by renewing.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct PushRatePolicy {
    /// How many notifications may arrive in a burst.
    pub burst: U64,
    /// How many may arrive in one hour.
    pub sustained_per_hour: U64,
    /// How often excess collapses into one attention update.
    pub collapse_window_ms: DurationMs,
}

impl PushRatePolicy {
    /// The free allowance of section 16: 20 in a burst, 60 an hour, collapsing every five minutes.
    pub const FREE: Self = Self {
        burst: U64::new(FREE_PUSH_BURST),
        sustained_per_hour: U64::new(FREE_PUSH_PER_HOUR),
        collapse_window_ms: DurationMs::new(PUSH_COLLAPSE_WINDOW_MS),
    };

    /// Returns true when this is the free allowance exactly.
    #[must_use]
    pub const fn is_free(&self) -> bool {
        self.burst.get() == FREE_PUSH_BURST
            && self.sustained_per_hour.get() == FREE_PUSH_PER_HOUR
            && self.collapse_window_ms.get() == PUSH_COLLAPSE_WINDOW_MS
    }
}

// ----- Registration -------------------------------------------------------------------------

/// The challenge the gateway sends through the provider to a proposed token.
///
/// It goes to the token, not to the caller. That is the whole point: an authenticated HTTP request
/// proves the caller holds an installation key, and nothing more. Sending a random value to the
/// token and requiring it back signed proves that the installation which holds the key is also the
/// one the provider delivers that token to. Until that returns, the registration stays pending and
/// no sender credential is issued.
///
/// The challenge is single use. An answer consumes it, and a second answer, whether the same one
/// replayed or another arriving at the same moment, finds nothing pending to answer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PushRegistrationChallenge {
    /// The single-use random value the receiver returns.
    pub challenge: Nonce256,
    /// When it stops being answerable, at most [`REGISTRATION_CHALLENGE_LIFETIME_MS`] after issue.
    pub expires_at_ms: TimestampMs,
    /// The gateway that issued it.
    pub gateway_origin: GatewayOrigin,
    /// The installation the pending registration is for.
    pub installation_id: InstallationId,
    /// The platform the token belongs to.
    pub platform: PushPlatform,
    /// This attempt, so an answer cannot complete a different one.
    pub registration_id: PushRegistrationId,
    /// The token the challenge was sent to.
    pub token_digest: Digest256,
}

impl PushRegistrationChallenge {
    /// Returns true when the challenge can still be answered at `now_ms`.
    #[must_use]
    pub const fn is_answerable_at(&self, now_ms: u64) -> bool {
        now_ms < self.expires_at_ms.get()
    }

    /// Returns true when the challenge lasts no longer than section 16 permits.
    #[must_use]
    pub const fn lifetime_within_maximum(&self, issued_at_ms: u64) -> bool {
        let expires = self.expires_at_ms.get();
        expires > issued_at_ms && expires - issued_at_ms <= REGISTRATION_CHALLENGE_LIFETIME_MS
    }

    /// The answer this challenge expects, before the receiver signs it.
    #[must_use]
    pub fn expected_answer(&self) -> PushRegistrationAnswerPayload {
        PushRegistrationAnswerPayload {
            challenge: self.challenge,
            expires_at_ms: self.expires_at_ms,
            gateway_origin: self.gateway_origin.clone(),
            installation_id: self.installation_id,
            platform: self.platform,
            registration_id: self.registration_id,
            token_digest: self.token_digest,
        }
    }
}

/// What a registration answer states, and exactly what its signature covers.
///
/// Every field of the challenge is repeated here and covered by the signature, so an answer is a
/// statement about one attempt, one token and one gateway. Dropping any of them would let an answer
/// collected in one context be presented in another: without the token digest an answer would
/// activate a token nobody proved receipt of; without the origin it would answer a different
/// deployment's challenge; without the registration identifier it would complete whichever attempt
/// happened to be pending.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PushRegistrationAnswerPayload {
    /// The value that arrived through the provider.
    pub challenge: Nonce256,
    /// The expiry the challenge carried.
    pub expires_at_ms: TimestampMs,
    /// The gateway that issued the challenge.
    pub gateway_origin: GatewayOrigin,
    /// The installation the answering key names.
    pub installation_id: InstallationId,
    /// The platform the token belongs to.
    pub platform: PushPlatform,
    /// The attempt being answered.
    pub registration_id: PushRegistrationId,
    /// The token the challenge was sent to.
    pub token_digest: Digest256,
}

impl PushRegistrationAnswerPayload {
    /// Builds the canonical bytes a registration answer's signature covers.
    ///
    /// # Errors
    ///
    /// Returns a CBOR error when the payload cannot be represented in KR-CBOR-1.
    pub fn signing_input(&self) -> Result<Vec<u8>, CborError> {
        Ok(kr_cbor::encode(&signing_value(
            PUSH_REGISTRATION_ANSWER_DOMAIN,
            vec![kr_cbor::to_canonical_value(self)?],
        )))
    }
}

/// The receiver's answer to a challenge, signed by the proposed installation key.
///
/// The receiver answers only for its own locally pending registration and its own public key. It
/// does not sign a challenge that names an attempt it did not start, or an installation identifier
/// that is not the one its key derives, so a challenge aimed at a token in the hope of a reply gets
/// none.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PushRegistrationAnswer {
    /// What the receiver states.
    pub payload: PushRegistrationAnswerPayload,
    /// The public half of the key that answered. Its SHA-256 names the installation.
    pub installation_key: AuthorisationKey,
    /// The signature over [`PushRegistrationAnswerPayload::signing_input`].
    pub signature: Signature64,
}

impl PushRegistrationAnswer {
    /// Returns true when this answers `challenge` exactly.
    ///
    /// It compares the whole payload rather than the challenge value alone. A receiver that agreed
    /// about the random bytes and disagreed about the token, the attempt or the gateway has
    /// answered a different question.
    #[must_use]
    pub fn answers(&self, challenge: &PushRegistrationChallenge) -> bool {
        self.payload == challenge.expected_answer()
    }

    /// Returns true when the key that answered is the installation the payload names.
    #[must_use]
    pub fn key_names_its_installation(&self) -> bool {
        crate::service::installation_id(&self.installation_key) == self.payload.installation_id
    }
}

/// Whether a bound token is still usable.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum PushTokenState {
    /// The provider delivers to it.
    Active,
    /// The provider rejected it as unregistered or invalid.
    ///
    /// Nothing is sent to a disabled token. Only a fresh native registration, which proves receipt
    /// again, puts a token back in service; a host cannot re-enable one by asking.
    Disabled,
}

/// The canonical active binding of one provider token to one installation.
///
/// There is exactly one of these per token digest. That is what stops an installation from
/// registering the same token under a second identity to start its rate history again: a second
/// identity for one token is not an additional binding, it is a replacement, and a replacement has
/// to pass its own challenge. The rate history stays with the digest through that replacement, so
/// the alias gains nothing.
///
/// The token itself is not here. The gateway keeps it where it keeps its own secrets, because it
/// needs the token to deliver; what travels in a record is the digest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PushInstallationBinding {
    /// When the answered challenge bound it, in UTC milliseconds.
    pub bound_at_ms: TimestampMs,
    /// The gateway holding it.
    pub gateway_origin: GatewayOrigin,
    /// The installation the token delivers to.
    pub installation_id: InstallationId,
    /// The public key that installation authenticates with.
    pub installation_key: AuthorisationKey,
    /// The platform the token belongs to.
    pub platform: PushPlatform,
    /// The attempt whose answer established it.
    pub registration_id: PushRegistrationId,
    /// Whether the provider still delivers to the token.
    pub state: PushTokenState,
    /// The token, as the gateway records it.
    pub token_digest: Digest256,
}

impl PushInstallationBinding {
    /// Returns true when a request signed by `key` is an ordinary update of this binding.
    ///
    /// An update re-registers the same key: a token refresh, or the same token re-registered after
    /// a reinstall. Anything else is a replacement, and a replacement takes over only after passing
    /// a fresh challenge.
    #[must_use]
    pub fn is_ordinary_update(&self, key: &AuthorisationKey) -> bool {
        self.installation_key == *key
    }

    /// Returns true when the gateway may send to this binding at all.
    #[must_use]
    pub const fn is_deliverable(&self) -> bool {
        matches!(self.state, PushTokenState::Active)
    }
}

// ----- Sender authorisation -----------------------------------------------------------------

/// What one sender authorisation fixes for its lifetime.
///
/// A renewal proves the host is still there; it is not an opportunity to change what was
/// authorised. Every field a renewal must not touch is here and nowhere else, so
/// [`PushSenderRecord::renewal_preserves_binding`] is a comparison of one digest rather than a list
/// of fields somebody has to remember to extend.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PushSenderBinding {
    /// The gateway holding the authorisation.
    pub gateway_origin: GatewayOrigin,
    /// The host's iroh endpoint identity, so the installation knows which peer it authorised.
    pub host_endpoint_key: EndpointKey,
    /// The host's Ed25519 signing key. Renewal and revocation are proven with it.
    pub host_signing_key: AuthorisationKey,
    /// The destination installation.
    pub installation_id: InstallationId,
    /// What that destination may receive.
    pub rate_policy: PushRatePolicy,
    /// This authorisation.
    pub sender_record_id: PushSenderRecordId,
}

impl PushSenderBinding {
    /// Builds the canonical bytes this binding is digested from.
    ///
    /// # Errors
    ///
    /// Returns a CBOR error when the binding cannot be represented in KR-CBOR-1.
    pub fn signing_input(&self) -> Result<Vec<u8>, CborError> {
        Ok(kr_cbor::encode(&signing_value(
            PUSH_SENDER_BINDING_DOMAIN,
            vec![kr_cbor::to_canonical_value(self)?],
        )))
    }

    /// Builds the binding's digest.
    ///
    /// # Errors
    ///
    /// Returns a CBOR error when the binding cannot be represented in KR-CBOR-1.
    pub fn digest(&self) -> Result<Digest256, CborError> {
        Ok(Digest256::from_bytes(sha256(&self.signing_input()?)))
    }
}

/// Whether a sender authorisation still stands.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum PushSenderState {
    /// The installation's authorisation stands. The credential may be renewed.
    Active,
    /// It was revoked, by unpairing or by the installation key being replaced.
    ///
    /// A revoked record never becomes active again. A host that needs to send after this needs a
    /// new authorisation from the installation, which is a decision made on the device.
    Revoked,
}

/// One installation's authorisation of one host, as the gateway holds it.
///
/// The authorisation and the credential have different lifetimes on purpose. The authorisation is
/// the installation's decision and lasts until the installation revokes it. The credential is a
/// bearer token that a host keeps on disk, so it expires in thirty days and is renewed by proving
/// possession of the key the installation named. An offline host that comes back after its
/// credential expired still renews, because what it proves has not lapsed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PushSenderRecord {
    /// What the installation authorised, and what a renewal may not change.
    pub binding: PushSenderBinding,
    /// When the current credential stops working.
    pub credential_expires_at_ms: TimestampMs,
    /// When the installation authorised the host, in UTC milliseconds.
    pub issued_at_ms: TimestampMs,
    /// The gateway's revision, advanced on every renewal.
    pub revision: PushSenderRevision,
    /// Whether the authorisation still stands.
    pub state: PushSenderState,
}

impl PushSenderRecord {
    /// When the host may start renewing: seven days before the credential expires.
    #[must_use]
    pub const fn renewal_opens_at_ms(&self) -> u64 {
        self.credential_expires_at_ms
            .get()
            .saturating_sub(SENDER_RENEWAL_WINDOW_MS)
    }

    /// Returns true when the current credential is usable at `now_ms`.
    #[must_use]
    pub const fn credential_valid_at(&self, now_ms: u64) -> bool {
        matches!(self.state, PushSenderState::Active)
            && now_ms < self.credential_expires_at_ms.get()
    }

    /// Returns true when the host may renew at `now_ms`.
    ///
    /// Renewal opens seven days before expiry and does not close at expiry. A host that was offline
    /// for a month renews on reconnect: its credential lapsed, the authorisation behind it did not,
    /// and section 16 says that is enough. A revoked record renews never.
    #[must_use]
    pub const fn may_renew_at(&self, now_ms: u64) -> bool {
        matches!(self.state, PushSenderState::Active) && now_ms >= self.renewal_opens_at_ms()
    }

    /// Returns true when the credential lasts no longer than section 16 permits.
    #[must_use]
    pub const fn credential_lifetime_within_maximum(&self, issued_at_ms: u64) -> bool {
        let expires = self.credential_expires_at_ms.get();
        expires > issued_at_ms && expires - issued_at_ms <= DELIVERY_CREDENTIAL_LIFETIME_MS
    }

    /// Returns true when `proposed` leaves the destination, host key and rate policy untouched.
    ///
    /// # Errors
    ///
    /// Returns a CBOR error when either binding cannot be represented in KR-CBOR-1.
    pub fn renewal_preserves_binding(
        &self,
        proposed: &PushSenderBinding,
    ) -> Result<bool, CborError> {
        Ok(self.binding.digest()? == proposed.digest()?)
    }
}

/// The bearer a host presents to deliver, and what it is bound to.
///
/// At issue it goes to the installation, which passes it to the host through the paired encrypted
/// channel: the installation is the one authorising, so the first credential travels the way the
/// authorisation does. At renewal it goes straight to the host, in the answer to the renewal the
/// host itself proved, which is what makes renewal work while the phone is asleep or unreachable.
///
/// It grants delivery to one destination and nothing else: it is not a session, it reads nothing,
/// and it cannot be presented to any other method.
///
/// The gateway stores [`PushDeliveryCredential::secret_digest`], never the secret. A copy of the
/// database is therefore not a set of working credentials.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PushDeliveryCredential {
    /// When it stops working, at most [`DELIVERY_CREDENTIAL_LIFETIME_MS`] after issue.
    pub expires_at_ms: TimestampMs,
    /// The gateway that issued it.
    pub gateway_origin: GatewayOrigin,
    /// The destination installation.
    pub installation_id: InstallationId,
    /// When it was issued or last renewed, in UTC milliseconds.
    pub issued_at_ms: TimestampMs,
    /// The revision of the record it was issued against.
    pub revision: PushSenderRevision,
    /// The bearer itself. It reaches a log or a debug rendering as a redaction.
    pub secret: SecretBytes32,
    /// The authorisation it delivers under.
    pub sender_record_id: PushSenderRecordId,
}

impl PushDeliveryCredential {
    /// Returns true when the credential is usable at `now_ms`.
    #[must_use]
    pub const fn is_valid_at(&self, now_ms: u64) -> bool {
        now_ms >= self.issued_at_ms.get() && now_ms < self.expires_at_ms.get()
    }

    /// Returns true when the credential lasts no longer than section 16 permits.
    #[must_use]
    pub const fn lifetime_within_maximum(&self) -> bool {
        let issued = self.issued_at_ms.get();
        let expires = self.expires_at_ms.get();
        expires > issued && expires - issued <= DELIVERY_CREDENTIAL_LIFETIME_MS
    }

    /// The value the gateway stores and compares a presented bearer against.
    #[must_use]
    pub fn secret_digest(&self) -> Digest256 {
        credential_digest(&self.secret)
    }
}

/// The digest a delivery credential's bearer is stored and matched under.
#[must_use]
pub fn credential_digest(secret: &SecretBytes32) -> Digest256 {
    let value = signing_value(
        PUSH_CREDENTIAL_DOMAIN,
        vec![kr_cbor::CanonicalValue::Bytes(secret.expose().to_vec())],
    );
    Digest256::from_bytes(kr_cbor::sha256_of_canonical(&value))
}

/// What a renewal proof states, and exactly what its signature covers.
///
/// The nonce is the gateway's, handed out for this renewal and accepted once. Without it a captured
/// renewal would be usable for as long as the host key lived; with it, a renewal is a reply to a
/// question the gateway asked a moment ago.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PushSenderRenewalPayload {
    /// The gateway that issued the nonce.
    pub gateway_origin: GatewayOrigin,
    /// The single-use value the gateway handed out for this renewal.
    pub gateway_nonce: Nonce256,
    /// When the host signed, in UTC milliseconds.
    pub requested_at_ms: TimestampMs,
    /// The authorisation being renewed.
    pub sender_record_id: PushSenderRecordId,
}

impl PushSenderRenewalPayload {
    /// Builds the canonical bytes a renewal proof's signature covers.
    ///
    /// # Errors
    ///
    /// Returns a CBOR error when the payload cannot be represented in KR-CBOR-1.
    pub fn signing_input(&self) -> Result<Vec<u8>, CborError> {
        Ok(kr_cbor::encode(&signing_value(
            PUSH_SENDER_RENEWAL_DOMAIN,
            vec![kr_cbor::to_canonical_value(self)?],
        )))
    }
}

/// A host's proof that it still holds the key the installation authorised.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PushSenderRenewal {
    /// What the host states.
    pub payload: PushSenderRenewalPayload,
    /// The host signing key's signature over [`PushSenderRenewalPayload::signing_input`].
    pub signature: Signature64,
}

/// Why a sender authorisation ended.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum PushRevocationReason {
    /// The device and the host were unpaired.
    Unpaired,
    /// The host replaced its signing key, which needs a new authorisation from the installation.
    HostKeyReplaced,
    /// The installation replaced its own key, which revokes every authorisation it had given.
    InstallationKeyReplaced,
}

impl PushRevocationReason {
    /// Every reason, in declaration order.
    pub const ALL: [Self; 3] = [
        Self::Unpaired,
        Self::HostKeyReplaced,
        Self::InstallationKeyReplaced,
    ];

    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unpaired => "unpaired",
            Self::HostKeyReplaced => "host_key_replaced",
            Self::InstallationKeyReplaced => "installation_key_replaced",
        }
    }
}

/// What a revocation states, and exactly what its signature covers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PushSenderRevocationPayload {
    /// The gateway that issued the nonce.
    pub gateway_origin: GatewayOrigin,
    /// The single-use value the gateway handed out for this revocation.
    pub gateway_nonce: Nonce256,
    /// Why the authorisation is ending.
    pub reason: PushRevocationReason,
    /// When the host signed, in UTC milliseconds.
    pub requested_at_ms: TimestampMs,
    /// The authorisation being revoked.
    pub sender_record_id: PushSenderRecordId,
}

impl PushSenderRevocationPayload {
    /// Builds the canonical bytes a revocation's signature covers.
    ///
    /// # Errors
    ///
    /// Returns a CBOR error when the payload cannot be represented in KR-CBOR-1.
    pub fn signing_input(&self) -> Result<Vec<u8>, CborError> {
        Ok(kr_cbor::encode(&signing_value(
            PUSH_SENDER_REVOCATION_DOMAIN,
            vec![kr_cbor::to_canonical_value(self)?],
        )))
    }
}

/// A host's statement that an authorisation is finished.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PushSenderRevocation {
    /// What the host states.
    pub payload: PushSenderRevocationPayload,
    /// The host signing key's signature over [`PushSenderRevocationPayload::signing_input`].
    pub signature: Signature64,
}

// ----- Request bodies -------------------------------------------------------------------------

/// The domain a signed push request body is digested under.
pub const PUSH_REQUEST_DOMAIN: &str = "kr-push-request/1";

/// What a caller sends to begin a registration.
///
/// It proposes a token. It establishes nothing: the gateway records the attempt, sends a challenge
/// through the provider to that token, and waits. A caller that never receives the challenge has
/// only ever had a pending registration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PushRegistrationProposal {
    /// The public key the installation will authenticate with. Its SHA-256 names the installation.
    pub installation_key: AuthorisationKey,
    /// The platform whose payload the gateway should build for this token.
    ///
    /// It is a claim, not a proof: receiving the challenge says the token reaches this device and
    /// nothing about the label beside it. The gateway records it as delivery metadata and never
    /// indexes by it.
    pub platform: PushPlatform,
    /// This attempt. A retry carrying the same value is the same attempt.
    pub registration_id: PushRegistrationId,
    /// The provider token being proposed.
    pub registration_token: RegistrationToken,
}

/// What a caller sends for `push.installation.register`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum PushRegistrationRequest {
    /// Propose a token and ask for the challenge to be sent to it.
    Propose {
        /// The token and the identity proposed for it.
        proposal: PushRegistrationProposal,
    },
    /// Present the challenge, signed, and activate the binding.
    Answer {
        /// The receiver's answer.
        answer: PushRegistrationAnswer,
    },
}

/// What an installation sends for `push.sender.issue`.
///
/// It names one paired host by both of its keys and asks for a credential scoped to that host and
/// this installation. The gateway sets the rate policy; a caller cannot ask for a wider one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PushSenderIssueRequest {
    /// The host's iroh endpoint identity.
    pub host_endpoint_key: EndpointKey,
    /// The host's Ed25519 signing key, which will prove its renewals and its revocation.
    pub host_signing_key: AuthorisationKey,
    /// The authorisation being created. A retry carrying the same value is the same authorisation.
    pub sender_record_id: PushSenderRecordId,
}

/// What a host sends to ask for the nonce its proof will answer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PushSenderNonceRequest {
    /// The authorisation the host is about to renew or revoke.
    pub sender_record_id: PushSenderRecordId,
}

/// What a host sends for `push.sender.renew`.
///
/// Two steps, because the proof answers a nonce the gateway chose. The first asks for the nonce and
/// the second returns it signed, so a captured renewal answers a question that has already been
/// asked and closed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum PushSenderRenewRequest {
    /// Ask for a fresh nonce to renew against.
    Begin {
        /// The authorisation being renewed.
        request: PushSenderNonceRequest,
    },
    /// Present the renewal proof and take the new credential.
    Complete {
        /// The host's proof.
        renewal: PushSenderRenewal,
    },
}

/// What a host sends for `push.sender.revoke`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum PushSenderRevokeRequest {
    /// Ask for a fresh nonce to revoke against.
    Begin {
        /// The authorisation being revoked.
        request: PushSenderNonceRequest,
    },
    /// Present the revocation and end the authorisation.
    Complete {
        /// The host's statement.
        revocation: PushSenderRevocation,
    },
}

/// Every body a signed push method carries.
///
/// One type, so there is one rule for what a service-request signature covers: the signature's
/// `body_digest` is [`PushRequest::digest`], and the method it names is [`PushRequest::method`]. A
/// body built for one method therefore cannot be presented under another, because the signature
/// covers both the body and the method and a verifier checks that they agree.
///
/// Delivery is not here. It carries the bearer credential the host was issued rather than a
/// signature, so it has no body digest to cover.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum PushRequest {
    /// `push.installation.register`.
    InstallationRegister {
        /// The proposal or the answer.
        request: PushRegistrationRequest,
    },
    /// `push.sender.issue`.
    SenderIssue {
        /// The host being authorised.
        request: PushSenderIssueRequest,
    },
    /// `push.sender.renew`.
    SenderRenew {
        /// The nonce request or the proof.
        request: PushSenderRenewRequest,
    },
    /// `push.sender.revoke`.
    SenderRevoke {
        /// The nonce request or the statement.
        request: PushSenderRevokeRequest,
    },
}

impl PushRequest {
    /// The method a signature over this body must name.
    #[must_use]
    pub const fn method(&self) -> Method {
        match self {
            Self::InstallationRegister { .. } => Method::PushInstallationRegister,
            Self::SenderIssue { .. } => Method::PushSenderIssue,
            Self::SenderRenew { .. } => Method::PushSenderRenew,
            Self::SenderRevoke { .. } => Method::PushSenderRevoke,
        }
    }

    /// Who must have signed the request carrying this body.
    ///
    /// Registration and issue are the installation's own decisions, made on the device. Renewal and
    /// revocation are the host's, proven by the key the installation named, which is what lets a
    /// host renew while the phone is asleep and what makes unpairing effective from the host side.
    #[must_use]
    pub const fn signer(&self) -> ServiceRequestSigner {
        match self {
            Self::InstallationRegister { .. } | Self::SenderIssue { .. } => {
                ServiceRequestSigner::Installation
            }
            Self::SenderRenew { .. } | Self::SenderRevoke { .. } => ServiceRequestSigner::Host,
        }
    }

    /// Builds the canonical bytes this body is digested from.
    ///
    /// # Errors
    ///
    /// Returns a CBOR error when the body cannot be represented in KR-CBOR-1.
    pub fn signing_input(&self) -> Result<Vec<u8>, CborError> {
        Ok(kr_cbor::encode(&signing_value(
            PUSH_REQUEST_DOMAIN,
            vec![kr_cbor::to_canonical_value(self)?],
        )))
    }

    /// Builds the digest a service-request signature carries as its `body_digest`.
    ///
    /// # Errors
    ///
    /// Returns a CBOR error when the body cannot be represented in KR-CBOR-1.
    pub fn digest(&self) -> Result<Digest256, CborError> {
        Ok(Digest256::from_bytes(sha256(&self.signing_input()?)))
    }
}

// ----- Delivery -----------------------------------------------------------------------------

/// The generic alert a device shows before anything is decrypted.
///
/// Section 16 requires the plaintext alert to be generic, and this is how: a sender chooses from a
/// closed vocabulary and the text comes from here. A delivery request has no field for text a
/// sender supplies, so command text and approval arguments cannot reach a lock screen by mistake or
/// by a bug in a host. What reaches it is one of six sentences, each of which names no session,
/// project, host or command.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum PushAlert {
    /// Something in a session wants a person.
    SessionNeedsAttention,
    /// An agent is waiting for an approval decision.
    ApprovalWaiting,
    /// An agent asked a question and is waiting for the answer.
    QuestionWaiting,
    /// A turn finished and is waiting to be reviewed.
    WorkComplete,
    /// The host stopped answering.
    HostUnreachable,
    /// Notifications were suppressed and collapsed into this one.
    AttentionUpdate,
}

impl PushAlert {
    /// Every alert, in declaration order.
    pub const ALL: [Self; 6] = [
        Self::SessionNeedsAttention,
        Self::ApprovalWaiting,
        Self::QuestionWaiting,
        Self::WorkComplete,
        Self::HostUnreachable,
        Self::AttentionUpdate,
    ];

    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SessionNeedsAttention => "session_needs_attention",
            Self::ApprovalWaiting => "approval_waiting",
            Self::QuestionWaiting => "question_waiting",
            Self::WorkComplete => "work_complete",
            Self::HostUnreachable => "host_unreachable",
            Self::AttentionUpdate => "attention_update",
        }
    }

    /// The generic English text shown when no preview can be decrypted.
    ///
    /// It names no session, project, host or command, so it is safe on a locked screen and safe in
    /// a provider's logs.
    #[must_use]
    pub const fn generic_text(self) -> &'static str {
        match self {
            Self::SessionNeedsAttention => "A KalaReach session needs attention.",
            Self::ApprovalWaiting => "A KalaReach session is waiting for an approval.",
            Self::QuestionWaiting => "A KalaReach session is waiting for an answer.",
            Self::WorkComplete => "A KalaReach session has work to review.",
            Self::HostUnreachable => "A KalaReach host stopped responding.",
            Self::AttentionUpdate => "Several KalaReach sessions need attention.",
        }
    }
}

impl core::fmt::Display for PushAlert {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// How urgently a provider is asked to deliver.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum PushUrgency {
    /// Deliver now: a person is waiting. FCM `high`, APNs priority 10.
    Attention,
    /// Deliver when convenient. FCM `normal`, APNs priority 5.
    Deferred,
}

impl PushUrgency {
    /// Both urgencies, in declaration order.
    pub const ALL: [Self; 2] = [Self::Attention, Self::Deferred];

    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Attention => "attention",
            Self::Deferred => "deferred",
        }
    }

    /// The FCM Android message priority this asks for.
    #[must_use]
    pub const fn fcm_priority(self) -> &'static str {
        match self {
            Self::Attention => "high",
            Self::Deferred => "normal",
        }
    }

    /// The `apns-priority` header value this asks for.
    #[must_use]
    pub const fn apns_priority(self) -> &'static str {
        match self {
            Self::Attention => "10",
            Self::Deferred => "5",
        }
    }
}

/// What the gateway asks each platform for, beyond the payload itself.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct PushPlatformHints {
    /// Which generic alert to show.
    pub alert: PushAlert,
    /// How urgently to deliver.
    pub urgency: PushUrgency,
}

/// One notification, as a host hands it to the gateway.
///
/// The host writes the underlying event first and then sends this, so a notification that is never
/// delivered has already been recorded somewhere the person can find it.
///
/// Nothing here is a field for plaintext that describes the work. The alert comes from a closed
/// vocabulary, the two identifiers are 128-bit values rather than text, and the preview is a sealed
/// envelope whose shape [`PushDeliveryRequest::preview_is_well_formed`] checks. Those are the
/// checks a gateway can make. What they do not do is inspect a producer: a host that put meaning
/// into its own identifiers, or sealed the wrong thing, has disclosed it to the provider and to the
/// gateway. Keeping the identifiers meaningless and the preview correctly sealed is the producer's
/// obligation, and section 16 places it there.
///
/// Larger detail does not belong here. Section 16 bounds the preview plaintext to
/// [`MAX_PREVIEW_PLAINTEXT_BYTES`] and the complete provider payload to
/// [`MAX_PROVIDER_PAYLOAD_BYTES`], and says to move the excess into a referenced encrypted object
/// rather than trusting an expansion ratio.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PushDeliveryRequest {
    /// The group this replaces others in on the device.
    pub collapse_id: CollapseId,
    /// When the notification stops being worth delivering, in UTC milliseconds.
    ///
    /// Retries stop here. A notification whose moment has passed is not redelivered later.
    pub expires_at_ms: TimestampMs,
    /// What to ask each platform for.
    pub hints: PushPlatformHints,
    /// The notification's identity. The gateway deduplicates by it and never reads it.
    pub notification_id: NotificationId,
    /// The sealed preview, or null when the destination has previews disabled.
    ///
    /// It is a [`SealedEnvelope`], not opaque bytes, so the gateway can check the shape of what it
    /// is forwarding without holding a key that opens it: that the envelope expires when the
    /// notification does, and that its ciphertext is a padded plaintext of a notification-sized
    /// bucket rather than an arbitrary payload. [`PushDeliveryRequest::preview_is_well_formed`] is
    /// that check.
    pub preview: Nullable<SealedEnvelope>,
    /// The authorisation this is delivered under.
    pub sender_record_id: PushSenderRecordId,
}

impl PushDeliveryRequest {
    /// Builds the canonical bytes a delivery request is digested from.
    ///
    /// # Errors
    ///
    /// Returns a CBOR error when the request cannot be represented in KR-CBOR-1.
    pub fn signing_input(&self) -> Result<Vec<u8>, CborError> {
        Ok(kr_cbor::encode(&signing_value(
            PUSH_DELIVERY_DOMAIN,
            vec![kr_cbor::to_canonical_value(self)?],
        )))
    }

    /// Builds the request's digest: what this notification is, as one value.
    ///
    /// Delivery is authenticated by the bearer credential rather than by a signature, so this is
    /// not a signing input. It is how the gateway recognises a request it has already handled: a
    /// retry of the same notification carries the same digest and is answered from the outcome
    /// already recorded, and a second request reusing a notification identifier with anything else
    /// changed is a different digest and a conflict rather than a retry.
    ///
    /// # Errors
    ///
    /// Returns a CBOR error when the request cannot be represented in KR-CBOR-1.
    pub fn digest(&self) -> Result<Digest256, CborError> {
        Ok(Digest256::from_bytes(sha256(&self.signing_input()?)))
    }

    /// Returns true when the notification is still worth delivering at `now_ms`.
    #[must_use]
    pub const fn is_live_at(&self, now_ms: u64) -> bool {
        now_ms < self.expires_at_ms.get()
    }

    /// Returns true when the sealed preview is shaped the way a notification preview is shaped.
    ///
    /// Three things a gateway can check about a ciphertext it cannot read:
    ///
    /// * the envelope expires when the notification does, so the service is never asked to hold one
    ///   longer than the other says;
    /// * the declared size bucket is a notification bucket, a multiple of one kibibyte, which is
    ///   what section 20's padding produces;
    /// * the ciphertext is exactly that bucket plus the seal's overhead, so a payload that was not
    ///   padded to a bucket is refused rather than forwarded.
    ///
    /// They are checks of format and length, and that is all they are. Nothing here proves the
    /// ciphertext is ciphertext, that it was sealed to the right key, or that what it covers is a
    /// preview: a producer that put plaintext in the field and padded it to a bucket would pass.
    /// Only the destination can tell, because only the destination holds the key.
    ///
    /// A request with no preview is well formed: previews can be disabled on the device, and the
    /// generic alert still arrives.
    #[must_use]
    pub fn preview_is_well_formed(&self) -> bool {
        let Some(preview) = self.preview.as_ref() else {
            return true;
        };
        let bucket = preview.routing.size_bucket_bytes.get();
        preview.routing.expires_at_ms == self.expires_at_ms
            && granularity_for_bucket(bucket) == Some(notification_granularity())
            && preview.ciphertext.as_slice().len() as u64 == bucket + SEAL_OVERHEAD_BYTES
    }
}

/// Returns true when a built provider payload is inside the section 16 bound.
///
/// The argument is the length of the complete request body the gateway is about to send, after
/// encryption and after base64, because that is the figure section 16 names and the only one a
/// provider actually sees. The bound is exclusive: section 16 says below 3,500 bytes.
#[must_use]
pub const fn provider_payload_within_policy(payload_len: u64) -> bool {
    payload_len < MAX_PROVIDER_PAYLOAD_BYTES
}

/// What became of one delivery request.
///
/// `Queued` means the provider accepted it for delivery. It does not mean displayed, read or
/// executed, and nothing in KalaReach treats it as though it did: in-app review state comes from
/// host events and client acknowledgements. Every other state says something other than acceptance
/// happened, which is a fact the host needs rather than one to smooth over.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum PushDeliveryState {
    /// The provider accepted it for delivery.
    Queued,
    /// The gateway holds it and is retrying a transient provider failure until it expires.
    ///
    /// It is the honest answer to "did the provider take it", and the answer is not yet. Section 16
    /// retries transient failures with exponential backoff and jitter and stops at expiry, so this
    /// state ends as `queued` or as `expired` and never as anything a host has to poll for. A
    /// duplicate presented while one is retrying is answered `duplicate`, because the request is
    /// already held.
    Retrying,
    /// The destination is over its rate policy; this collapsed into an attention update.
    Collapsed,
    /// This notification identifier was already handled. The earlier outcome stands.
    Duplicate,
    /// The destination token was rejected by the provider and is disabled.
    ///
    /// Nothing more is sent to it until a native registration proves receipt again.
    TokenDisabled,
    /// The provider refused the notification itself, and a retry cannot change that.
    ///
    /// It is the honest answer to a payload the provider will not take: too large, or malformed.
    /// The host fixes what it sent rather than sending it again.
    Refused,
    /// The authorisation this was sent under ended before the provider accepted it.
    ///
    /// A revocation reaches work that is already queued, and a notification that was waiting when
    /// it arrived is not an exception to it. The host needs a new authorisation from the device.
    Revoked,
    /// The gateway stopped trying before the notification's own expiry.
    ///
    /// A provider that refused for long enough, or a destination with more waiting than a gateway
    /// holds for one installation. It is separate from `expired` because the notification's moment
    /// had not passed: the host may still have something to say about it.
    Abandoned,
    /// The notification expired before the provider accepted it.
    Expired,
}

/// Why a notification was suppressed, when it was.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum PushSuppressionReason {
    /// The burst allowance was spent.
    Burst,
    /// The hourly allowance was spent.
    Sustained,
}

/// What the gateway suppressed, so the host can record it.
///
/// The host retains every request it made and reports suppression locally, which is what keeps a
/// suppressed notification from becoming a lost decision: the pending work is still on the host and
/// still visible there.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PushSuppression {
    /// The attention update this collapsed into.
    pub collapsed_into: NotificationId,
    /// When the next attention update may be sent, in UTC milliseconds.
    pub next_update_at_ms: TimestampMs,
    /// Which allowance was spent.
    pub reason: PushSuppressionReason,
    /// How many notifications have collapsed into the current update, including this one.
    pub suppressed_count: U64,
}

/// The gateway's answer to one delivery request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PushDeliveryAck {
    /// When the gateway decided, in UTC milliseconds.
    pub decided_at_ms: TimestampMs,
    /// The notification this answers.
    pub notification_id: NotificationId,
    /// What became of it.
    pub state: PushDeliveryState,
    /// What was suppressed, when anything was.
    pub suppression: Nullable<PushSuppression>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::EnvelopeId;
    use crate::mailbox::EnvelopeRouting;
    use crate::scalars::{Bytes, KeyId, Nonce192, Uuid};

    fn origin() -> GatewayOrigin {
        GatewayOrigin::new("https://reach.kala.to").expect("an origin")
    }

    fn binding() -> PushSenderBinding {
        PushSenderBinding {
            gateway_origin: origin(),
            host_endpoint_key: EndpointKey::from_bytes([1; 32]),
            host_signing_key: AuthorisationKey::from_bytes([2; 32]),
            installation_id: InstallationId::new(Uuid::from_bytes([3; 16])),
            rate_policy: PushRatePolicy::FREE,
            sender_record_id: PushSenderRecordId::new(Uuid::from_bytes([4; 16])),
        }
    }

    fn record(expires_at_ms: u64) -> PushSenderRecord {
        PushSenderRecord {
            binding: binding(),
            credential_expires_at_ms: TimestampMs::new(expires_at_ms),
            issued_at_ms: TimestampMs::new(1_000),
            revision: PushSenderRevision::new(1),
            state: PushSenderState::Active,
        }
    }

    #[test]
    fn the_free_policy_is_the_section_sixteen_allowance() {
        assert!(PushRatePolicy::FREE.is_free());
        assert_eq!(PushRatePolicy::FREE.burst.get(), 20);
        assert_eq!(PushRatePolicy::FREE.sustained_per_hour.get(), 60);
        assert_eq!(PushRatePolicy::FREE.collapse_window_ms.get(), 300_000);
    }

    fn token(text: &str) -> RegistrationToken {
        RegistrationToken::new(text).expect("a registration token")
    }

    #[test]
    fn a_token_digest_names_the_destination_and_nothing_about_the_caller() {
        // The same token is one destination however the caller labels it, so a device cannot hold
        // two rate histories by registering once as Android and once as iOS.
        assert_eq!(token_digest(&token("abc")), token_digest(&token("abc")));
        assert_ne!(token_digest(&token("abc")), token_digest(&token("abd")));
    }

    #[test]
    fn a_registration_token_is_bounded_printable_text() {
        assert!(RegistrationToken::new("fZ9k:APA91bExample").is_ok());
        assert!(RegistrationToken::new("").is_err());
        assert!(RegistrationToken::new("has a space").is_err());
        assert!(RegistrationToken::new("\u{7f}").is_err());
        assert!(RegistrationToken::new("x".repeat(MAX_REGISTRATION_TOKEN_LEN + 1)).is_err());
    }

    #[test]
    fn renewal_opens_seven_days_before_expiry_and_does_not_close() {
        let expires = 40 * 24 * 60 * 60 * 1000;
        let record = record(expires);
        assert_eq!(
            record.renewal_opens_at_ms(),
            expires - SENDER_RENEWAL_WINDOW_MS
        );
        assert!(!record.may_renew_at(record.renewal_opens_at_ms() - 1));
        assert!(record.may_renew_at(record.renewal_opens_at_ms()));
        // The credential has lapsed and the authorisation has not: section 16 still allows this.
        assert!(!record.credential_valid_at(expires + 1));
        assert!(record.may_renew_at(expires + 1));
    }

    #[test]
    fn a_revoked_record_never_renews() {
        let mut record = record(40 * 24 * 60 * 60 * 1000);
        record.state = PushSenderState::Revoked;
        assert!(!record.may_renew_at(record.renewal_opens_at_ms()));
        assert!(!record.may_renew_at(u64::MAX));
        assert!(!record.credential_valid_at(2_000));
    }

    #[test]
    fn a_renewal_that_changes_what_was_authorised_is_not_a_renewal() {
        let record = record(40 * 24 * 60 * 60 * 1000);
        assert!(
            record
                .renewal_preserves_binding(&binding())
                .expect("a digest")
        );

        for changed in [
            PushSenderBinding {
                host_signing_key: AuthorisationKey::from_bytes([9; 32]),
                ..binding()
            },
            PushSenderBinding {
                installation_id: InstallationId::new(Uuid::from_bytes([9; 16])),
                ..binding()
            },
            PushSenderBinding {
                rate_policy: PushRatePolicy {
                    burst: U64::new(200),
                    ..PushRatePolicy::FREE
                },
                ..binding()
            },
            PushSenderBinding {
                host_endpoint_key: EndpointKey::from_bytes([9; 32]),
                ..binding()
            },
        ] {
            assert!(
                !record
                    .renewal_preserves_binding(&changed)
                    .expect("a digest"),
                "a renewal may not change what the installation authorised"
            );
        }
    }

    #[test]
    fn an_answer_is_checked_against_the_whole_challenge() {
        let challenge = PushRegistrationChallenge {
            challenge: Nonce256::from_bytes([5; 32]),
            expires_at_ms: TimestampMs::new(300_000),
            gateway_origin: origin(),
            installation_id: InstallationId::new(Uuid::from_bytes([3; 16])),
            platform: PushPlatform::Ios,
            registration_id: PushRegistrationId::new(Uuid::from_bytes([6; 16])),
            token_digest: token_digest(&token("a-token")),
        };

        let answer = PushRegistrationAnswer {
            payload: challenge.expected_answer(),
            installation_key: AuthorisationKey::from_bytes([2; 32]),
            signature: Signature64::from_bytes([0; 64]),
        };
        assert!(answer.answers(&challenge));

        // The same random value, a different token: a different question.
        let mut elsewhere = answer.clone();
        elsewhere.payload.token_digest = token_digest(&token("another-token"));
        assert!(!elsewhere.answers(&challenge));

        // The same random value, a different attempt.
        let mut other_attempt = answer;
        other_attempt.payload.registration_id = PushRegistrationId::new(Uuid::from_bytes([7; 16]));
        assert!(!other_attempt.answers(&challenge));
    }

    #[test]
    fn an_answering_key_names_its_own_installation() {
        let key = AuthorisationKey::from_bytes([11; 32]);
        let mut answer = PushRegistrationAnswer {
            payload: PushRegistrationAnswerPayload {
                challenge: Nonce256::from_bytes([5; 32]),
                expires_at_ms: TimestampMs::new(300_000),
                gateway_origin: origin(),
                installation_id: crate::service::installation_id(&key),
                platform: PushPlatform::Android,
                registration_id: PushRegistrationId::new(Uuid::from_bytes([6; 16])),
                token_digest: token_digest(&token("a-token")),
            },
            installation_key: key,
            signature: Signature64::from_bytes([0; 64]),
        };
        assert!(answer.key_names_its_installation());

        answer.payload.installation_id = InstallationId::new(Uuid::from_bytes([0; 16]));
        assert!(!answer.key_names_its_installation());
    }

    #[test]
    fn a_challenge_lasts_at_most_five_minutes() {
        let challenge = PushRegistrationChallenge {
            challenge: Nonce256::from_bytes([5; 32]),
            expires_at_ms: TimestampMs::new(1_000 + REGISTRATION_CHALLENGE_LIFETIME_MS),
            gateway_origin: origin(),
            installation_id: InstallationId::new(Uuid::from_bytes([3; 16])),
            platform: PushPlatform::Ios,
            registration_id: PushRegistrationId::new(Uuid::from_bytes([6; 16])),
            token_digest: token_digest(&token("a-token")),
        };
        assert!(challenge.lifetime_within_maximum(1_000));
        assert!(!challenge.lifetime_within_maximum(999));
        assert!(challenge.is_answerable_at(challenge.expires_at_ms.get() - 1));
        assert!(!challenge.is_answerable_at(challenge.expires_at_ms.get()));
    }

    #[test]
    fn a_credential_lasts_at_most_thirty_days() {
        let credential = PushDeliveryCredential {
            expires_at_ms: TimestampMs::new(1_000 + DELIVERY_CREDENTIAL_LIFETIME_MS),
            gateway_origin: origin(),
            installation_id: InstallationId::new(Uuid::from_bytes([3; 16])),
            issued_at_ms: TimestampMs::new(1_000),
            revision: PushSenderRevision::new(1),
            secret: SecretBytes32::from_bytes([8; 32]),
            sender_record_id: PushSenderRecordId::new(Uuid::from_bytes([4; 16])),
        };
        assert!(credential.lifetime_within_maximum());
        assert!(credential.is_valid_at(1_000));
        assert!(!credential.is_valid_at(credential.expires_at_ms.get()));
        assert_eq!(
            credential.secret_digest(),
            credential_digest(&SecretBytes32::from_bytes([8; 32]))
        );
        assert_ne!(
            credential.secret_digest(),
            credential_digest(&SecretBytes32::from_bytes([9; 32]))
        );
    }

    #[test]
    fn every_alert_is_generic() {
        for alert in PushAlert::ALL {
            let text = alert.generic_text();
            assert!(text.starts_with('A') || text.starts_with('S'), "{text}");
            assert!(text.ends_with('.'), "{text}");
        }
        assert_eq!(PushAlert::ALL.len(), 6);
    }

    #[test]
    fn urgency_maps_to_both_providers() {
        assert_eq!(PushUrgency::Attention.fcm_priority(), "high");
        assert_eq!(PushUrgency::Attention.apns_priority(), "10");
        assert_eq!(PushUrgency::Deferred.fcm_priority(), "normal");
        assert_eq!(PushUrgency::Deferred.apns_priority(), "5");
    }

    #[test]
    fn the_payload_bounds_are_the_section_sixteen_figures() {
        assert_eq!(MAX_PREVIEW_PLAINTEXT_BYTES, 1_800);
        assert_eq!(MAX_PROVIDER_PAYLOAD_BYTES, 3_500);
        // Section 16 says below 3,500 bytes, so 3,500 is one too many.
        assert!(provider_payload_within_policy(3_499));
        assert!(!provider_payload_within_policy(3_500));
    }

    fn delivery(preview: Nullable<SealedEnvelope>) -> PushDeliveryRequest {
        PushDeliveryRequest {
            collapse_id: CollapseId::new(Uuid::from_bytes([0xc1; 16])),
            expires_at_ms: TimestampMs::new(2_000),
            hints: PushPlatformHints {
                alert: PushAlert::ApprovalWaiting,
                urgency: PushUrgency::Attention,
            },
            notification_id: NotificationId::new(Uuid::from_bytes([0x71; 16])),
            preview,
            sender_record_id: PushSenderRecordId::new(Uuid::from_bytes([4; 16])),
        }
    }

    fn sealed(expires_at_ms: u64, bucket: u64, ciphertext_len: u64) -> SealedEnvelope {
        SealedEnvelope {
            routing: EnvelopeRouting {
                envelope_id: EnvelopeId::new(Uuid::from_bytes([0xe1; 16])),
                recipient_key_id: KeyId::from_bytes([0x91; 32]),
                sender_key_id: KeyId::from_bytes([0x92; 32]),
                expires_at_ms: TimestampMs::new(expires_at_ms),
                size_bucket_bytes: U64::new(bucket),
            },
            nonce: Nonce192::from_bytes([0x93; 24]),
            ciphertext: Bytes::new(vec![
                0xab;
                usize::try_from(ciphertext_len).expect("a test length")
            ]),
        }
    }

    #[test]
    fn a_preview_is_shaped_like_a_padded_notification_or_refused() {
        let bucket = crate::mailbox::notification_size_bucket(600);
        let request = delivery(Nullable::some(sealed(
            2_000,
            bucket,
            bucket + SEAL_OVERHEAD_BYTES,
        )));
        assert!(request.preview_is_well_formed());
        assert!(request.is_live_at(1_999));
        assert!(!request.is_live_at(2_000));

        // Previews disabled on the device: still a notification, still a generic alert.
        assert!(delivery(Nullable::null()).preview_is_well_formed());

        // An envelope that outlives the notification asks the service to hold it longer.
        let outlives = delivery(Nullable::some(sealed(
            9_000,
            bucket,
            bucket + SEAL_OVERHEAD_BYTES,
        )));
        assert!(!outlives.preview_is_well_formed());

        // A bucket the padding rule never produces.
        let unpadded = delivery(Nullable::some(sealed(
            2_000,
            1_500,
            1_500 + SEAL_OVERHEAD_BYTES,
        )));
        assert!(!unpadded.preview_is_well_formed());

        // A ciphertext that is not its declared bucket plus the seal's overhead.
        let mismatched = delivery(Nullable::some(sealed(2_000, bucket, bucket)));
        assert!(!mismatched.preview_is_well_formed());

        // Two requests that differ anywhere differ in their digest.
        assert_ne!(
            request.digest().expect("a digest"),
            delivery(Nullable::null()).digest().expect("a digest")
        );
    }

    #[test]
    fn a_body_names_the_method_and_the_signer_it_belongs_to() {
        let bodies = [
            (
                PushRequest::InstallationRegister {
                    request: PushRegistrationRequest::Propose {
                        proposal: PushRegistrationProposal {
                            installation_key: AuthorisationKey::from_bytes([2; 32]),
                            platform: PushPlatform::Ios,
                            registration_id: PushRegistrationId::new(Uuid::from_bytes([6; 16])),
                            registration_token: token("a-token"),
                        },
                    },
                },
                Method::PushInstallationRegister,
                ServiceRequestSigner::Installation,
            ),
            (
                PushRequest::SenderIssue {
                    request: PushSenderIssueRequest {
                        host_endpoint_key: EndpointKey::from_bytes([1; 32]),
                        host_signing_key: AuthorisationKey::from_bytes([2; 32]),
                        sender_record_id: PushSenderRecordId::new(Uuid::from_bytes([4; 16])),
                    },
                },
                Method::PushSenderIssue,
                ServiceRequestSigner::Installation,
            ),
            (
                PushRequest::SenderRenew {
                    request: PushSenderRenewRequest::Begin {
                        request: PushSenderNonceRequest {
                            sender_record_id: PushSenderRecordId::new(Uuid::from_bytes([4; 16])),
                        },
                    },
                },
                Method::PushSenderRenew,
                ServiceRequestSigner::Host,
            ),
            (
                PushRequest::SenderRevoke {
                    request: PushSenderRevokeRequest::Begin {
                        request: PushSenderNonceRequest {
                            sender_record_id: PushSenderRecordId::new(Uuid::from_bytes([4; 16])),
                        },
                    },
                },
                Method::PushSenderRevoke,
                ServiceRequestSigner::Host,
            ),
        ];

        let mut digests = Vec::new();
        for (body, method, signer) in &bodies {
            assert_eq!(body.method(), *method);
            assert_eq!(body.signer(), *signer);
            digests.push(body.digest().expect("a body digest"));
        }
        // Each body digests to its own value, so a signature over one cannot cover another.
        for (index, digest) in digests.iter().enumerate() {
            assert!(
                !digests[index + 1..].contains(digest),
                "two bodies share a digest"
            );
        }
    }

    #[test]
    fn a_disabled_token_is_not_delivered_to() {
        let mut binding = PushInstallationBinding {
            bound_at_ms: TimestampMs::new(1_000),
            gateway_origin: origin(),
            installation_id: InstallationId::new(Uuid::from_bytes([3; 16])),
            installation_key: AuthorisationKey::from_bytes([2; 32]),
            platform: PushPlatform::Android,
            registration_id: PushRegistrationId::new(Uuid::from_bytes([6; 16])),
            state: PushTokenState::Active,
            token_digest: token_digest(&token("a-token")),
        };
        assert!(binding.is_deliverable());
        assert!(binding.is_ordinary_update(&AuthorisationKey::from_bytes([2; 32])));
        assert!(!binding.is_ordinary_update(&AuthorisationKey::from_bytes([9; 32])));

        binding.state = PushTokenState::Disabled;
        assert!(!binding.is_deliverable());
    }
}
