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
//! # What the gateway is not
//!
//! It is not an account system and not a host authorisation service. Nothing here mentions an
//! account, because none is needed: a self-hosted installation forwards through the official
//! gateway on the strength of its own key. It is not a decryption point either. The preview is
//! sealed to the destination device's notification-preview key (section 10), which the gateway
//! never holds, so the most a compromised gateway can do is refuse to forward, deliver something
//! the device cannot open, or learn how often a device is notified.
//!
//! # What is signed, and by whom
//!
//! | Domain | Signed by | What it states |
//! | --- | --- | --- |
//! | [`PUSH_REGISTRATION_ANSWER_DOMAIN`] | the proposed installation key | The challenge sent to this token arrived here |
//! | [`PUSH_SENDER_BINDING_DOMAIN`] | nobody; it is digested | What an authorisation fixes for its lifetime |
//! | [`PUSH_SENDER_RENEWAL_DOMAIN`] | the host signing key | The host that was authorised is still here |
//! | [`PUSH_SENDER_REVOCATION_DOMAIN`] | the host signing key | This authorisation is finished |
//! | [`PUSH_DELIVERY_DOMAIN`] | nobody; it is digested | The body a delivery credential was presented for |
//! | [`PUSH_TOKEN_DOMAIN`] | nobody; it is digested | Which provider token a record is about |
//! | [`PUSH_CREDENTIAL_DOMAIN`] | nobody; it is digested | Which stored credential a bearer matches |
//!
//! The requests carrying them are authenticated by [`crate::service::ServiceRequestSignature`],
//! which is the credential every managed-service method shares.

use kr_cbor::{CborError, sha256, signing_value};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ids::{
    CollapseId, InstallationId, NotificationId, PushRegistrationId, PushSenderRecordId,
    PushSenderRevision,
};
use crate::scalars::{
    AuthorisationKey, Bytes, Digest256, DurationMs, EndpointKey, Nonce256, Nullable, SecretBytes32,
    Signature64, TimestampMs, U64,
};
use crate::service::GatewayOrigin;

/// The domain a registration answer's signature covers.
pub const PUSH_REGISTRATION_ANSWER_DOMAIN: &str = "kr-push-registration/1";

/// The domain the immutable half of a sender record is digested under.
pub const PUSH_SENDER_BINDING_DOMAIN: &str = "kr-push-sender/1";

/// The domain a renewal proof's signature covers.
pub const PUSH_SENDER_RENEWAL_DOMAIN: &str = "kr-push-sender-renewal/1";

/// The domain a revocation's signature covers.
pub const PUSH_SENDER_REVOCATION_DOMAIN: &str = "kr-push-sender-revocation/1";

/// The domain a delivery request is digested under.
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
pub const MAX_PREVIEW_PLAINTEXT_BYTES: u64 = 1_800;

/// The most the complete provider payload may be after encryption and base64, in bytes.
///
/// Section 16 fixes the figure and says to measure rather than estimate: the expansion from
/// plaintext to a JSON provider request is not a ratio anyone should be relying on.
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

/// The digest a provider token is recorded under.
///
/// The gateway stores this rather than the token. A registration token is a delivery capability:
/// anything holding one can be sent to through the provider, so the record that survives in a
/// database is the hash and the token itself lives only as long as the request that carried it.
///
/// The platform is inside the digest, so the same bytes registered as an Android token and as an
/// iOS token are two destinations rather than one, and a record cannot be matched across
/// platforms.
#[must_use]
pub fn token_digest(platform: PushPlatform, token: &str) -> Digest256 {
    let value = signing_value(
        PUSH_TOKEN_DOMAIN,
        vec![
            kr_cbor::CanonicalValue::text(platform.as_str()),
            kr_cbor::CanonicalValue::text(token),
        ],
    );
    Digest256::from_bytes(kr_cbor::sha256_of_canonical(&value))
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
/// to pass its own challenge.
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
/// It is returned to the installation once, at issue and at each renewal, and the installation
/// passes it to the host through the paired encrypted channel. It grants delivery to one
/// destination and nothing else: it is not a session, it reads nothing and it cannot be presented
/// to any other method.
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

// ----- Delivery -----------------------------------------------------------------------------

/// The generic alert a device shows before anything is decrypted.
///
/// Section 16 requires the plaintext alert to be generic, and this is how: a sender chooses from a
/// closed vocabulary and the text comes from here. There is no field anywhere in a delivery request
/// for sender-supplied text, so command text and approval arguments cannot reach a lock screen by
/// mistake, by a bug in a host, or by a host that decided to.
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
/// delivered has already been recorded somewhere the person can find it. Nothing here is plaintext
/// that describes the work: the identifier is opaque, the collapse label names no project, the
/// alert comes from a closed vocabulary, and the preview is sealed to the device.
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
    /// The sealed preview envelope, or null when the destination has previews disabled.
    ///
    /// The bytes are a [`crate::mailbox::SealedEnvelope`] whose payload type is a notification
    /// preview. The gateway forwards them; it holds no key that opens them.
    pub preview: Nullable<Bytes>,
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

    /// Builds the request's digest, which the service-request signature covers as the body.
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

    /// Returns true when the sealed preview is inside the plaintext bound before expansion.
    ///
    /// The ciphertext is longer than the plaintext it covers, so a sealed preview inside this bound
    /// certainly covers a plaintext inside it. It is the cheap check; the real one is
    /// [`provider_payload_within_policy`] on the built provider request.
    #[must_use]
    pub fn preview_within_plaintext_bound(&self) -> bool {
        match self.preview.as_ref() {
            None => true,
            Some(preview) => preview.as_slice().len() as u64 <= MAX_PREVIEW_PLAINTEXT_BYTES,
        }
    }
}

/// Returns true when a built provider payload is inside the section 16 bound.
///
/// The argument is the length of the complete request body the gateway is about to send, after
/// encryption and after base64, because that is the figure section 16 names and the only one a
/// provider actually sees.
#[must_use]
pub const fn provider_payload_within_policy(payload_len: u64) -> bool {
    payload_len <= MAX_PROVIDER_PAYLOAD_BYTES
}

/// What became of one delivery request.
///
/// `Queued` means the provider accepted it for delivery. It does not mean displayed, read or
/// executed, and nothing in KalaReach treats it as though it did: in-app review state comes from
/// host events and client acknowledgements.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum PushDeliveryState {
    /// The provider accepted it for delivery.
    Queued,
    /// The destination is over its rate policy; this collapsed into an attention update.
    Collapsed,
    /// This notification identifier was already handled. The earlier outcome stands.
    Duplicate,
    /// The destination token was rejected by the provider and is disabled.
    ///
    /// Nothing more is sent to it until a native registration proves receipt again.
    TokenDisabled,
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
    use crate::scalars::Uuid;

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

    #[test]
    fn a_token_digest_separates_the_platforms() {
        assert_ne!(
            token_digest(PushPlatform::Android, "abc"),
            token_digest(PushPlatform::Ios, "abc")
        );
        assert_eq!(
            token_digest(PushPlatform::Android, "abc"),
            token_digest(PushPlatform::Android, "abc")
        );
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
            token_digest: token_digest(PushPlatform::Ios, "a-token"),
        };

        let answer = PushRegistrationAnswer {
            payload: challenge.expected_answer(),
            installation_key: AuthorisationKey::from_bytes([2; 32]),
            signature: Signature64::from_bytes([0; 64]),
        };
        assert!(answer.answers(&challenge));

        // The same random value, a different token: a different question.
        let mut elsewhere = answer.clone();
        elsewhere.payload.token_digest = token_digest(PushPlatform::Ios, "another-token");
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
                token_digest: token_digest(PushPlatform::Android, "a-token"),
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
            token_digest: token_digest(PushPlatform::Ios, "a-token"),
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
        assert!(provider_payload_within_policy(3_500));
        assert!(!provider_payload_within_policy(3_501));
    }

    #[test]
    fn a_request_with_no_preview_is_inside_the_plaintext_bound() {
        let request = PushDeliveryRequest {
            collapse_id: CollapseId::new("c1").expect("a collapse label"),
            expires_at_ms: TimestampMs::new(2_000),
            hints: PushPlatformHints {
                alert: PushAlert::ApprovalWaiting,
                urgency: PushUrgency::Attention,
            },
            notification_id: NotificationId::new("n1").expect("a notification identifier"),
            preview: Nullable::null(),
            sender_record_id: PushSenderRecordId::new(Uuid::from_bytes([4; 16])),
        };
        assert!(request.preview_within_plaintext_bound());
        assert!(request.is_live_at(1_999));
        assert!(!request.is_live_at(2_000));

        let oversized = PushDeliveryRequest {
            preview: Nullable::some(Bytes::new(vec![0; 1_801])),
            ..request.clone()
        };
        assert!(!oversized.preview_within_plaintext_bound());

        // Two requests that differ anywhere differ in their digest.
        assert_ne!(
            request.digest().expect("a digest"),
            oversized.digest().expect("a digest")
        );
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
            token_digest: token_digest(PushPlatform::Android, "a-token"),
        };
        assert!(binding.is_deliverable());
        assert!(binding.is_ordinary_update(&AuthorisationKey::from_bytes([2; 32])));
        assert!(!binding.is_ordinary_update(&AuthorisationKey::from_bytes([9; 32])));

        binding.state = PushTokenState::Disabled;
        assert!(!binding.is_deliverable());
    }
}
