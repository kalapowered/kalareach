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
//! which installation it is, and two installations cannot share an identifier without sharing a
//! key. A service stores the key it first saw against that identifier and refuses a later request
//! carrying a different key, which is what makes replacing an installation key a deliberate step
//! rather than a side effect of asking.

use kr_cbor::{CborError, sha256, signing_value};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ids::InstallationId;
use crate::method::{Method, MethodGroup};
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
    /// An origin is a scheme, a host and an optional port, and nothing else: no path, no query, no
    /// fragment, no credentials and no trailing slash. Two spellings of one address would otherwise
    /// produce two different signing inputs for the same service, and a verifier comparing text
    /// would refuse a request its own caller addressed correctly.
    ///
    /// `http://` is admitted only for a loopback host, which is what a development deployment
    /// serves on. Any other plain-HTTP origin is refused here rather than at the point of use.
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
        let secure = value.strip_prefix("https://");
        let plain = value.strip_prefix("http://");
        let authority = match (secure, plain) {
            (Some(authority), _) => authority,
            (None, Some(authority)) if is_loopback_authority(authority) => authority,
            (None, Some(_)) => {
                return Err(GatewayOriginError(
                    "only a loopback gateway origin may use http",
                ));
            }
            (None, None) => {
                return Err(GatewayOriginError("a gateway origin names its scheme"));
            }
        };
        validate_authority(authority)?;
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

/// Splits an authority into its host and its optional port.
///
/// A bracketed address literal holds colons of its own, so the port is whatever follows the closing
/// bracket rather than whatever follows the last colon.
fn split_authority(authority: &str) -> (&str, Option<&str>) {
    if authority.starts_with('[') {
        return match authority.find(']') {
            Some(end) => {
                let (host, rest) = authority.split_at(end + 1);
                (host, rest.strip_prefix(':'))
            }
            None => (authority, None),
        };
    }
    match authority.rsplit_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (authority, None),
    }
}

/// True when `authority` names a loopback host, with or without a port.
fn is_loopback_authority(authority: &str) -> bool {
    let (host, _) = split_authority(authority);
    host == "localhost" || host == "127.0.0.1" || host == "[::1]"
}

/// Checks the host and optional port of an origin.
fn validate_authority(authority: &str) -> Result<(), GatewayOriginError> {
    if authority.is_empty() {
        return Err(GatewayOriginError("a gateway origin names a host"));
    }
    if authority.contains('/') || authority.contains('?') || authority.contains('#') {
        return Err(GatewayOriginError(
            "a gateway origin carries no path, query or fragment",
        ));
    }
    if authority.contains('@') {
        return Err(GatewayOriginError(
            "a gateway origin carries no credentials",
        ));
    }
    let (host, port) = split_authority(authority);
    if host.is_empty() {
        return Err(GatewayOriginError("a gateway origin names a host"));
    }
    let literal = host
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'));
    let permitted = match literal {
        Some(address) => {
            !address.is_empty()
                && address
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() || byte == b':' || byte == b'.')
        }
        None => host.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'.' || byte == b'-'
        }),
    };
    if !permitted {
        return Err(GatewayOriginError(
            "a gateway origin's host is lower-case and carries no escapes",
        ));
    }
    if let Some(port) = port
        && (port.is_empty() || port.len() > 5 || !port.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return Err(GatewayOriginError("a gateway origin's port is a number"));
    }
    Ok(())
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
/// installation it is, so the identifier is derived rather than asserted and a caller cannot
/// choose one. Two installations share an identifier only by sharing a key.
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
        assert!(GatewayOrigin::new("https://reach.kala.to").is_ok());
        assert!(GatewayOrigin::new("https://reach.kala.to:8443").is_ok());
        assert!(GatewayOrigin::new("http://127.0.0.1:8787").is_ok());
        assert!(GatewayOrigin::new("http://localhost:8787").is_ok());
        assert!(GatewayOrigin::new("https://[::1]:8787").is_ok());
        assert!(GatewayOrigin::new("http://[::1]:8787").is_ok());
        assert!(GatewayOrigin::new("https://[2001:db8::1]").is_ok());

        // A second spelling of one address is a second signing input.
        assert!(GatewayOrigin::new("https://reach.kala.to/").is_err());
        assert!(GatewayOrigin::new("https://REACH.kala.to").is_err());
        assert!(GatewayOrigin::new("https://reach.kala.to/api").is_err());
        assert!(GatewayOrigin::new("https://user@reach.kala.to").is_err());
        assert!(GatewayOrigin::new("http://reach.kala.to").is_err());
        assert!(GatewayOrigin::new("reach.kala.to").is_err());
        assert!(GatewayOrigin::new("https://").is_err());
        assert!(GatewayOrigin::new("https://reach.kala.to:http").is_err());
        assert!(GatewayOrigin::new("http://[2001:db8::1]").is_err());
        assert!(GatewayOrigin::new("https://[2001:db8::1").is_err());
        assert!(GatewayOrigin::new("x".repeat(MAX_GATEWAY_ORIGIN_LEN + 1)).is_err());
    }
}
