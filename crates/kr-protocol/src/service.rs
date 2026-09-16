//! The credential every managed-service method authenticates with (sections 16, 17, 23).
//!
//! The `Services` group of section 23 is the whole of what a native installation asks a managed
//! service for: push registration and sender credentials, mailbox reads, authority synchronisation,
//! settings exchange and backup manifests. None of them needs an account. What each one needs is
//! proof that the caller holds the private half of one device authorisation key, and that the
//! request in front of the service is the request that key signed.
//!
//! That is one problem, so it has one answer here rather than one per service. A later service
//! adds a method to the registry and reuses [`ServiceRequestSignature`]; it does not invent a
//! second way of proving the same thing.
//!
//! # What a signature covers
//!
//! `CBOR([domain, payload])`, where the payload is a [`ServiceRequestPayload`]: the gateway origin,
//! the method, a fresh 32-byte nonce, the time the caller signed, and the SHA-256 of the canonical
//! request body. Every one of those five is load bearing.
//!
//! | Field | What omitting it would allow |
//! | --- | --- |
//! | `gateway_origin` | A signature made for one deployment replayed against another |
//! | `method` | A signature for a read presented as the authorisation for a write |
//! | `nonce` | The same signed request accepted twice |
//! | `signed_at_ms` | A captured request held and presented much later |
//! | `body_digest` | The body swapped for another under a signature that still verifies |
//!
//! # Who signs
//!
//! Two kinds of caller reach these methods, so there are two domains and no other difference.
//! A native installation signs under [`SERVICE_REQUEST_DOMAIN`] with its device authorisation key.
//! A host signs under [`SERVICE_REQUEST_HOST_DOMAIN`] with its host signing key, which is how
//! `push.sender.renew`, `push.sender.revoke` and a host's `authority.sync` are proven.
//!
//! Domain separation is what keeps them apart: a signature made as an installation does not verify
//! as a host request, so relabelling one cannot turn it into the other. [`ServiceRequestSigner`]
//! travels beside the signature rather than inside the payload for exactly that reason: it says
//! which domain to check, and a wrong answer fails the check instead of changing what was covered.
//!
//! # Freshness and replay
//!
//! A service admits a signature whose `signed_at_ms` is inside [`SERVICE_REQUEST_FRESHNESS_MS`] of
//! its own clock, in either direction, and remembers the nonce for at least that long afterwards.
//! [`ServiceRequestPayload::is_fresh_at`] is the first check and [`nonce_retained_until_ms`] says
//! how long the second one has to remember. Neither is optional: a window without a replay cache
//! admits the same request repeatedly for five minutes, and a cache without a window has to
//! remember every nonce for ever.
//!
//! # Installation identity
//!
//! [`installation_id`] derives the [`InstallationId`] from the device authorisation key that signs.
//! It is the first 16 bytes of the key's SHA-256, written in the hyphenated form `ids` defines, so
//! the identifier is not a claim: a caller that presents a key and a signature has already proved
//! which installation it is.
//!
//! An identifier is 128 bits, so it names a key rather than proving one. A service therefore keeps
//! the whole key it first saw against that identifier and compares against the key, not the
//! identifier, on every later request: a different key under the same identifier is refused rather
//! than admitted, which is what makes replacing an installation key a deliberate step rather than a
//! side effect of asking.

use kr_cbor::{CborError, sha256, signing_value};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ids::InstallationId;
use crate::method::{Method, MethodGroup};
use crate::pairing::{HTTP_DEFAULT_PORT, HTTPS_DEFAULT_PORT, split_authority, validate_authority};
use crate::scalars::{AuthorisationKey, Digest256, Nonce256, Signature64, TimestampMs, Uuid};

/// The domain an installation's service-request signature covers.
pub const SERVICE_REQUEST_DOMAIN: &str = "kr-service-request/1";

/// The domain a host's service-request signature covers.
pub const SERVICE_REQUEST_HOST_DOMAIN: &str = "kr-service-request/1/host";

/// How far a signature's stated time may be from the service's own, in milliseconds.
///
/// It applies in both directions. A caller's clock can be behind or ahead, and refusing only the
/// past would let a caller stockpile signatures dated forward.
pub const SERVICE_REQUEST_FRESHNESS_MS: u64 = 5 * 60 * 1000;

/// The longest a gateway origin may be, in bytes.
pub const MAX_GATEWAY_ORIGIN_LEN: usize = 128;

/// Which key signed a service request, and therefore which domain it is checked under.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ServiceRequestSigner {
    /// A native installation, signing with its device authorisation key.
    Installation,
    /// A paired host, signing with its host signing key.
    Host,
}

impl ServiceRequestSigner {
    /// Every signer kind, in declaration order.
    pub const ALL: [Self; 2] = [Self::Installation, Self::Host];

    /// The domain this signer's signatures are separated by.
    #[must_use]
    pub const fn domain(self) -> &'static str {
        match self {
            Self::Installation => SERVICE_REQUEST_DOMAIN,
            Self::Host => SERVICE_REQUEST_HOST_DOMAIN,
        }
    }

    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Installation => "installation",
            Self::Host => "host",
        }
    }
}

impl core::fmt::Display for ServiceRequestSigner {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The origin a service request is bound to.
///
/// It is the exact origin the caller addressed, so a signature made for one deployment cannot be
/// replayed against another. A service compares it with its own configured origin and refuses a
/// mismatch rather than accepting a request that was authorised for somebody else's service.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct GatewayOrigin(String);

/// An origin that is not one: empty, over-long, or not an `https://host[:port]` origin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GatewayOriginError(&'static str);

impl core::fmt::Display for GatewayOriginError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for GatewayOriginError {}

impl GatewayOrigin {
    /// Validates and wraps an origin.
    ///
    /// The grammar is the one `pairing` already fixes for a rendezvous origin, because an origin is
    /// an origin: a scheme, a canonically spelled host, an optional non-default port, and nothing
    /// else. Two spellings of one address would otherwise be two signing inputs for one service, and
    /// a verifier comparing text would refuse a request its own caller addressed correctly.
    ///
    /// The one difference is the scheme. `http://` is admitted for a loopback host, which is what a
    /// development deployment serves on; any other plain-HTTP origin is refused here rather than at
    /// the point of use.
    ///
    /// # Errors
    ///
    /// Returns [`GatewayOriginError`] naming the rule the text breaks.
    pub fn new(value: impl Into<String>) -> Result<Self, GatewayOriginError> {
        let value = value.into();
        if value.is_empty() {
            return Err(GatewayOriginError("a gateway origin must not be empty"));
        }
        if value.len() > MAX_GATEWAY_ORIGIN_LEN {
            return Err(GatewayOriginError("a gateway origin is at most 128 bytes"));
        }
        let (authority, default_port) = match (
            value.strip_prefix("https://"),
            value.strip_prefix("http://"),
        ) {
            (Some(authority), _) => (authority, HTTPS_DEFAULT_PORT),
            (None, Some(authority)) => {
                if !is_loopback_authority(authority) {
                    return Err(GatewayOriginError(
                        "only a loopback gateway origin may use http",
                    ));
                }
                (authority, HTTP_DEFAULT_PORT)
            }
            (None, None) => {
                return Err(GatewayOriginError("a gateway origin names its scheme"));
            }
        };
        validate_authority(authority, default_port).map_err(GatewayOriginError)?;
        Ok(Self(value))
    }

    /// Returns the origin text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Display for GatewayOrigin {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl core::str::FromStr for GatewayOrigin {
    type Err = GatewayOriginError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::new(text)
    }
}

impl<'de> Deserialize<'de> for GatewayOrigin {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::new(text).map_err(serde::de::Error::custom)
    }
}

impl JsonSchema for GatewayOrigin {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "GatewayOrigin".into()
    }

    fn schema_id() -> std::borrow::Cow<'static, str> {
        "kalareach::GatewayOrigin".into()
    }

    fn json_schema(_generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "string",
            "minLength": 1,
            "maxLength": MAX_GATEWAY_ORIGIN_LEN,
            "description": "The origin a service request is bound to: scheme, host and optional port, with no path, query, fragment or trailing slash."
        })
    }
}

/// True when `authority` names a loopback host, with or without a port.
///
/// A loopback origin is the only one plain HTTP is admitted for. The three spellings are the ones a
/// development deployment actually serves on; anything else is a service reachable from elsewhere,
/// and a request to it belongs on HTTPS.
fn is_loopback_authority(authority: &str) -> bool {
    match split_authority(authority) {
        Ok((host, _, true)) => host == "::1",
        Ok((host, _, false)) => host == "localhost" || host == "127.0.0.1",
        Err(_) => false,
    }
}

/// What a service-request signature covers, and exactly what it covers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServiceRequestPayload {
    /// The SHA-256 of the canonical request body.
    pub body_digest: Digest256,
    /// The origin the request was addressed to.
    pub gateway_origin: GatewayOrigin,
    /// The method being called.
    pub method: Method,
    /// A fresh 32-byte nonce, from the caller's random generator.
    pub nonce: Nonce256,
    /// When the caller signed, in UTC milliseconds.
    pub signed_at_ms: TimestampMs,
}

impl ServiceRequestPayload {
    /// Builds the canonical bytes a signature by `signer` covers.
    ///
    /// # Errors
    ///
    /// Returns a CBOR error when the payload cannot be represented in KR-CBOR-1.
    pub fn signing_input(&self, signer: ServiceRequestSigner) -> Result<Vec<u8>, CborError> {
        Ok(kr_cbor::encode(&signing_value(
            signer.domain(),
            vec![kr_cbor::to_canonical_value(self)?],
        )))
    }

    /// Returns true when `now_ms` is inside the freshness window either side of the signing time.
    #[must_use]
    pub const fn is_fresh_at(&self, now_ms: u64) -> bool {
        now_ms.abs_diff(self.signed_at_ms.get()) <= SERVICE_REQUEST_FRESHNESS_MS
    }

    /// Returns true when the method named is one a service credential may call.
    ///
    /// The registry's `Services` group is the whole managed-service surface. A signature naming a
    /// host method is refused rather than checked, because no service holds the authority to run
    /// one and a credential that could name one would be a credential the caller could aim at
    /// something else.
    #[must_use]
    pub const fn names_a_service_method(&self) -> bool {
        matches!(self.method.group(), MethodGroup::Services)
    }
}

/// One signed service request.
///
/// It authenticates a request; it authorises nothing by itself. What the caller may do with the
/// method it names is the service's decision, made from the installation record and the records
/// that method reads.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServiceRequestSignature {
    /// What was signed.
    pub payload: ServiceRequestPayload,
    /// Which key signed it, and therefore which domain the signature is checked under.
    pub signer: ServiceRequestSigner,
    /// The Ed25519 public key of that signer.
    pub public_key: AuthorisationKey,
    /// The signature over [`ServiceRequestPayload::signing_input`].
    pub signature: Signature64,
}

impl ServiceRequestSignature {
    /// The installation this signature names, when an installation made it.
    ///
    /// A host request names no installation of its own: the record it acts on says which
    /// installation authorised the host, and the host's key is what proves the request.
    #[must_use]
    pub fn installation(&self) -> Option<InstallationId> {
        match self.signer {
            ServiceRequestSigner::Installation => Some(installation_id(&self.public_key)),
            ServiceRequestSigner::Host => None,
        }
    }

    /// Builds the canonical bytes this signature is checked over.
    ///
    /// # Errors
    ///
    /// Returns a CBOR error when the payload cannot be represented in KR-CBOR-1.
    pub fn signing_input(&self) -> Result<Vec<u8>, CborError> {
        self.payload.signing_input(self.signer)
    }
}

/// The installation a device authorisation key names.
///
/// The first 16 bytes of the key's SHA-256, in the hyphenated form [`crate::ids`] writes an
/// identifier in. It is self-certifying: a caller that signs with the key has proved which
/// installation it is, so the identifier is derived rather than asserted and a caller cannot choose
/// one.
///
/// It names a key; it does not stand in for one. A 128-bit value is short enough that a service
/// compares the whole key it recorded against the key presented, and treats the identifier as the
/// index it looks that key up by.
#[must_use]
pub fn installation_id(key: &AuthorisationKey) -> InstallationId {
    let digest = sha256(key.as_bytes());
    let mut identifier = [0u8; crate::scalars::UUID_LEN];
    identifier.copy_from_slice(&digest[..crate::scalars::UUID_LEN]);
    InstallationId::new(Uuid::from_bytes(identifier))
}

/// Returns the instant a nonce may be forgotten: the signing time plus twice the window.
///
/// Twice, because the window runs in both directions: a signature dated the full window ahead is
/// still admissible for another whole window after it was made, and forgetting its nonce before
/// then would admit it a second time.
#[must_use]
pub const fn nonce_retained_until_ms(signed_at_ms: u64) -> u64 {
    signed_at_ms.saturating_add(2 * SERVICE_REQUEST_FRESHNESS_MS)
}

/// The SHA-256 of a canonical request body, as the payload carries it.
#[must_use]
pub fn body_digest(canonical_body: &[u8]) -> Digest256 {
    Digest256::from_bytes(sha256(canonical_body))
}

/// The largest count a request body may carry as a number.
///
/// It is the largest integer a double-precision reader holds exactly. The other half of this
/// contract is such a reader, so a larger value is one the two halves would not encode the same
/// way; every counter these bodies carry as a quantity travels as a decimal string instead.
const MAX_BODY_COUNT: f64 = 9_007_199_254_740_991.0;

/// A request body that cannot be canonicalised.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum BodyError {
    /// A number that is not an exact count both languages hold identically.
    ///
    /// Every counter these methods carry travels as a decimal string, so a JSON number is either a
    /// small exact count or a value nobody agreed on. The bound is the largest integer a
    /// double-precision reader holds exactly, because the other half of this contract is one: a
    /// value past it is a value the two halves would encode differently, so it is refused rather
    /// than rounded into agreement. A float, a negative and a fraction are refused for the same
    /// reason.
    #[error("a request body carries no number that is not an exact count at or below 2^53-1")]
    Number,
    /// A map whose keys are not canonical, or that repeats one.
    #[error("a request body's members are canonical and distinct: {0}")]
    Members(String),
}

/// The canonical bytes of one request body.
///
/// The bodies of the mailbox, authority-feed, settings-sync and backup-manifest methods are JSON
/// documents rather than protocol objects, and a signature covers bytes rather than a document. So
/// the document is encoded in KR-CBOR-1 — text keys in canonical order, text as text, an exact
/// count as an unsigned integer — and the digest of those bytes is what the signature carries.
/// Both halves of the contract build it from the document they hold, so a caller signs what a
/// service will recompute and nothing depends on how either wrote its JSON.
///
/// # Errors
///
/// Returns [`BodyError`] when the document is outside the subset: a number that is not an exact
/// unsigned integer, or a map that repeats a key.
pub fn canonical_body(body: &serde_json::Value) -> Result<Vec<u8>, BodyError> {
    Ok(kr_cbor::encode(&canonical_body_value(body)?))
}

/// The SHA-256 of [`canonical_body`], which is what a signature's `body_digest` carries.
///
/// # Errors
///
/// Returns [`BodyError`] when the document is outside the subset.
pub fn canonical_body_digest(body: &serde_json::Value) -> Result<Digest256, BodyError> {
    Ok(Digest256::from_bytes(sha256(&canonical_body(body)?)))
}

fn canonical_body_value(body: &serde_json::Value) -> Result<kr_cbor::CanonicalValue, BodyError> {
    use kr_cbor::CanonicalValue;

    match body {
        serde_json::Value::Null => Ok(CanonicalValue::Null),
        serde_json::Value::Bool(value) => Ok(CanonicalValue::Bool(*value)),
        serde_json::Value::Number(number) => {
            // A spelling is not a value: `1000` and `1e3` are one number, and JSON says so, so
            // both encode to the same integer. What is refused is a value rather than a spelling.
            let value = number.as_f64().ok_or(BodyError::Number)?;
            if !value.is_finite()
                || value.fract() != 0.0
                || !(0.0..=MAX_BODY_COUNT).contains(&value)
            {
                return Err(BodyError::Number);
            }
            #[expect(
                clippy::cast_possible_truncation,
                clippy::cast_sign_loss,
                reason = "the value is a non-negative integer at or below 2^53-1"
            )]
            Ok(CanonicalValue::Integer((value as u64).into()))
        }
        serde_json::Value::String(text) => Ok(CanonicalValue::text(text)),
        serde_json::Value::Array(items) => Ok(CanonicalValue::Array(
            items
                .iter()
                .map(canonical_body_value)
                .collect::<Result<Vec<_>, _>>()?,
        )),
        serde_json::Value::Object(members) => {
            let mut map = kr_cbor::CanonicalMap::new();
            for (key, value) in members {
                map.insert(key.clone(), canonical_body_value(value)?)
                    .map_err(|error| BodyError::Members(error.to_string()))?;
            }
            Ok(CanonicalValue::Map(map))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload() -> ServiceRequestPayload {
        ServiceRequestPayload {
            body_digest: body_digest(b"{}"),
            gateway_origin: GatewayOrigin::new("https://reach.kala.to").expect("an origin"),
            method: Method::PushInstallationRegister,
            nonce: Nonce256::from_bytes([7; 32]),
            signed_at_ms: TimestampMs::new(1_767_225_600_000),
        }
    }

    #[test]
    fn the_two_signer_kinds_cover_different_bytes() {
        let payload = payload();
        let installation = payload
            .signing_input(ServiceRequestSigner::Installation)
            .expect("an installation signing input");
        let host = payload
            .signing_input(ServiceRequestSigner::Host)
            .expect("a host signing input");
        assert_ne!(installation, host);
    }

    #[test]
    fn freshness_runs_both_ways() {
        let payload = payload();
        let signed = payload.signed_at_ms.get();
        assert!(payload.is_fresh_at(signed));
        assert!(payload.is_fresh_at(signed + SERVICE_REQUEST_FRESHNESS_MS));
        assert!(payload.is_fresh_at(signed - SERVICE_REQUEST_FRESHNESS_MS));
        assert!(!payload.is_fresh_at(signed + SERVICE_REQUEST_FRESHNESS_MS + 1));
        assert!(!payload.is_fresh_at(signed - SERVICE_REQUEST_FRESHNESS_MS - 1));
    }

    #[test]
    fn a_nonce_outlives_the_window_it_could_still_be_presented_in() {
        let signed = 1_000_000;
        assert_eq!(
            nonce_retained_until_ms(signed),
            signed + 2 * SERVICE_REQUEST_FRESHNESS_MS
        );
        assert_eq!(nonce_retained_until_ms(u64::MAX), u64::MAX);
    }

    #[test]
    fn a_body_is_digested_from_the_document_rather_than_from_its_text() {
        // Two spellings of one document. The canonical encoding is the same bytes, so the digest a
        // signature carries does not depend on how either side wrote its JSON.
        let one: serde_json::Value =
            serde_json::from_str("{\"b\":\"two\",\"a\":1}").expect("a document");
        let other: serde_json::Value =
            serde_json::from_str("{ \"a\" : 1 , \"b\" : \"two\" }").expect("a document");
        assert_eq!(
            canonical_body_digest(&one).expect("a digest"),
            canonical_body_digest(&other).expect("a digest")
        );

        // A different document is a different digest.
        let different: serde_json::Value =
            serde_json::from_str("{\"a\":1,\"b\":\"three\"}").expect("a document");
        assert_ne!(
            canonical_body_digest(&one).expect("a digest"),
            canonical_body_digest(&different).expect("a digest")
        );
    }

    #[test]
    fn a_body_carries_no_number_that_is_not_an_exact_count() {
        for text in [
            "{\"limit\":1.5}",
            "{\"limit\":-1}",
            "{\"limit\":9007199254740993}",
        ] {
            let body: serde_json::Value = serde_json::from_str(text).expect("a document");
            assert_eq!(
                canonical_body_digest(&body),
                Err(BodyError::Number),
                "{text}"
            );
        }

        let counted: serde_json::Value =
            serde_json::from_str("{\"limit\":32}").expect("a document");
        assert!(canonical_body_digest(&counted).is_ok());

        // One number written two ways is one document, so it is one digest: the other half of this
        // contract cannot tell the two spellings apart, and neither should this one.
        let exponent: serde_json::Value =
            serde_json::from_str("{\"limit\":1e3}").expect("a document");
        let plain: serde_json::Value =
            serde_json::from_str("{\"limit\":1000}").expect("a document");
        assert_eq!(
            canonical_body_digest(&exponent).expect("a digest"),
            canonical_body_digest(&plain).expect("a digest")
        );
    }

    #[test]
    fn only_the_services_group_may_be_named() {
        let mut payload = payload();
        assert!(payload.names_a_service_method());
        payload.method = Method::SessionRead;
        assert!(!payload.names_a_service_method());
    }

    #[test]
    fn an_installation_identifier_is_derived_from_the_key() {
        let key = AuthorisationKey::from_bytes([3; 32]);
        let derived = installation_id(&key);
        assert_eq!(derived, installation_id(&key));
        assert_ne!(
            derived,
            installation_id(&AuthorisationKey::from_bytes([4; 32]))
        );
        // The first sixteen bytes of the key's SHA-256, and nothing rearranged.
        assert_eq!(&derived.get().as_bytes()[..], &sha256(key.as_bytes())[..16]);
    }

    #[test]
    fn a_host_request_names_no_installation_of_its_own() {
        let signature = ServiceRequestSignature {
            payload: payload(),
            signer: ServiceRequestSigner::Host,
            public_key: AuthorisationKey::from_bytes([9; 32]),
            signature: Signature64::from_bytes([0; 64]),
        };
        assert_eq!(signature.installation(), None);
    }

    #[test]
    fn an_origin_is_a_scheme_a_host_and_a_port() {
        for origin in [
            "https://reach.kala.to",
            "https://reach.kala.to:8443",
            "http://127.0.0.1:8787",
            "http://localhost:8787",
            "http://localhost",
            "https://[::1]:8787",
            "http://[::1]:8787",
            "https://[2001:db8::1]",
        ] {
            assert!(GatewayOrigin::new(origin).is_ok(), "{origin}");
        }

        // Every one of these is a second spelling of an origin, or not an origin at all. One
        // service with two spellings is one request with two signing inputs.
        for origin in [
            "https://reach.kala.to/",
            "https://REACH.kala.to",
            "https://reach.kala.to/api",
            "https://reach.kala.to?x=1",
            "https://user@reach.kala.to",
            "http://reach.kala.to",
            "http://[2001:db8::1]",
            "reach.kala.to",
            "https://",
            "https://reach.kala.to:http",
            "https://reach.kala.to:443",
            "https://reach.kala.to:08443",
            "https://reach.kala.to:0",
            "https://reach.kala.to:99999",
            "http://localhost:80",
            "https://[::1]junk",
            "http://[::1]junk",
            "https://[:::]",
            "https://[2001:db8::1",
            "https://[0:0:0:0:0:0:0:1]",
            "https://reach.kala.to.",
            "https://192.0.2.001",
            "https://2001:db8::1",
        ] {
            assert!(GatewayOrigin::new(origin).is_err(), "{origin}");
        }

        assert!(GatewayOrigin::new("x".repeat(MAX_GATEWAY_ORIGIN_LEN + 1)).is_err());
    }
}
