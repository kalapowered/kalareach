//! The managed relay-lease client.
//!
//! A relay carries nothing for a pair of endpoints until it holds a lease signed by an issuer key
//! it pins, and only the service can issue one: it holds the ledger the bytes are reserved from and
//! the admission key the relay trusts. So a client's whole part in section 17's payment path is one
//! request, and this is it.
//!
//! # What this crate supplies and what it does not
//!
//! Two things are left to the embedder, because neither belongs in a client library. An HTTP
//! exchange is [`ServiceHttp`]: a desktop build, a mobile build and a test each reach the network
//! differently, and a library that chose for them would be a library one of them could not use. And
//! the private key is [`ServiceSigner`]: the device authorisation key lives in the operating
//! system's secure store and the host signing key lives in the controller, so what this module asks
//! for is a signature rather than a key.
//!
//! What this module owns is everything between: the exact bytes the credential covers, the exact
//! bytes the body digest covers, the request shape and what each answer means.
//!
//! # One body, two representations
//!
//! The request travels as JSON and its digest is taken over canonical KR-CBOR-1, so both come from
//! one type through serde: the scalars of [`kr_protocol::scalars`] write a counter as a decimal
//! string in JSON and as an integer in CBOR, and an identifier as hyphenated text in JSON and as
//! its sixteen bytes in CBOR. JSON is therefore never what a signature covers, and a client that
//! formatted its request differently still produces the digest the service rebuilds.
//!
//! # The credential
//!
//! Decision D-018 gives every managed-service method one credential: a signature over the gateway
//! origin, the method, a fresh nonce, the time and the digest of the canonical body. It is the
//! credential [`kr_protocol::service`] defines, field for field and domain for domain. The payload
//! is built here rather than with [`kr_protocol::service::ServiceRequestPayload`] for one reason:
//! that type carries a [`kr_protocol::method::Method`], and the two relay methods are not entries
//! in that registry yet. When they are, delete [`RelayRequestPayload`] and build the payload with
//! that type instead; the bytes are identical, which is what the vector in
//! `crates/kr-client/tests/relay_service.rs` holds this module to alongside the service's own.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use kr_cbor::{CborError, sha256, signing_value};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{RelayInstanceId, RelayLeaseId, RelayRegion, RelayReservationId};
use kr_protocol::relay::{RelayLeaseAck, SignedRelayLease};
use kr_protocol::scalars::{
    AuthorisationKey, Digest256, EndpointKey, Nonce256, Nullable, Signature64, TimestampMs, U64,
};
use kr_protocol::service::{GatewayOrigin, ServiceRequestSigner};
use serde::{Deserialize, Serialize};

use super::ServiceFuture;
use super::{LeaseEndReason, LeasePayer, LeaseRequest, RelayDirection, RelayLeaseService};
use crate::error::{ClientError, Result};

/// The domain a lease request's body digest covers.
pub const RELAY_LEASE_REQUEST_DOMAIN: &str = "kr-relay-lease-request/1";

/// The domain a revocation request's body digest covers.
pub const RELAY_LEASE_REVOKE_DOMAIN: &str = "kr-relay-lease-revoke/1";

/// The method name a lease request's credential covers.
pub const RELAY_LEASE_ISSUE_METHOD: &str = "relay.lease.issue";

/// The method name a revocation request's credential covers.
pub const RELAY_LEASE_REVOKE_METHOD: &str = "relay.lease.revoke";

/// The path a lease request is addressed to.
pub const RELAY_LEASE_PATH: &str = "/api/relay/lease";

/// The path a revocation request is addressed to.
pub const RELAY_LEASE_REVOKE_PATH: &str = "/api/relay/lease/revoke";

/// One HTTP exchange, as the embedder performs it.
///
/// The body is JSON and the answer is whatever the service sent, status and bytes. Nothing here
/// retries: asking again for a pair that already holds a lease revises that lease, so whether to
/// ask again is the caller's decision rather than a library's.
pub trait ServiceHttp: Send + Sync + std::fmt::Debug {
    /// Posts a JSON body and returns what came back.
    fn post_json<'a>(
        &'a self,
        url: &'a str,
        body: &'a [u8],
    ) -> ServiceFuture<'a, ServiceHttpAnswer>;
}

/// What an HTTP exchange returned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceHttpAnswer {
    /// The status the service answered with.
    pub status: u16,
    /// The body, which is the service's envelope whether the status was a success or not.
    pub body: Vec<u8>,
}

/// What signs a managed-service request.
///
/// An installation signs with its device authorisation key and a host with its host signing key,
/// and the two are separated by domain, so the signer says which domain to check rather than
/// changing what was covered. The private key never reaches this module.
pub trait ServiceSigner: Send + Sync + std::fmt::Debug {
    /// Whether an installation or a host is signing.
    fn signer(&self) -> ServiceRequestSigner;

    /// The public half of the key that signs.
    fn public_key(&self) -> AuthorisationKey;

    /// Signs the canonical bytes of one credential.
    ///
    /// # Errors
    ///
    /// Returns an error when the key is unavailable or the signature could not be made.
    fn sign(&self, message: &[u8]) -> Result<Signature64>;
}

/* -------------------------------------------------------------------------- */
/* What a client sends                                                         */
/* -------------------------------------------------------------------------- */

/// The body of a lease request, in the one shape both representations come from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RelayLeaseIssueBody {
    /// The endpoint that may send.
    pub source_endpoint_key: EndpointKey,
    /// The endpoint that may receive.
    pub destination_endpoint_key: EndpointKey,
    /// Whether the reverse direction is permitted too.
    pub direction: RelayDirection,
    /// The cumulative bytes asked for.
    pub byte_ceiling: U64,
    /// Seconds the lease should last, from now.
    pub duration_seconds: u32,
    /// The region the requester would rather be carried in. A hint.
    pub region_preference: Nullable<String>,
    /// Who pays, or null for the default: the account this caller has selected, else itself.
    pub payer: Nullable<LeasePayer>,
    /// The lease being refilled, or null to issue a new one.
    pub lease_id: Nullable<RelayLeaseId>,
}

impl RelayLeaseIssueBody {
    /// Builds the body of one request.
    #[must_use]
    pub fn of(request: &LeaseRequest) -> Self {
        Self {
            source_endpoint_key: request.source,
            destination_endpoint_key: request.destination,
            direction: request.direction,
            byte_ceiling: U64::new(request.byte_ceiling),
            duration_seconds: request.duration_seconds,
            region_preference: Nullable(request.region_preference.clone()),
            payer: Nullable(request.payer.clone()),
            lease_id: Nullable(request.lease_id),
        }
    }

    /// The bytes this body's digest is taken over.
    ///
    /// # Errors
    ///
    /// Returns a CBOR error when the body cannot be represented in KR-CBOR-1.
    pub fn signing_input(&self) -> std::result::Result<Vec<u8>, CborError> {
        Ok(kr_cbor::encode(&signing_value(
            RELAY_LEASE_REQUEST_DOMAIN,
            vec![kr_cbor::to_canonical_value(self)?],
        )))
    }
}

/// The body of a revocation request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RelayLeaseRevokeBody {
    /// The lease to end.
    pub lease_id: RelayLeaseId,
    /// Why it is ending.
    pub reason: LeaseEndReason,
}

impl RelayLeaseRevokeBody {
    /// The bytes this body's digest is taken over.
    ///
    /// # Errors
    ///
    /// Returns a CBOR error when the body cannot be represented in KR-CBOR-1.
    pub fn signing_input(&self) -> std::result::Result<Vec<u8>, CborError> {
        Ok(kr_cbor::encode(&signing_value(
            RELAY_LEASE_REVOKE_DOMAIN,
            vec![kr_cbor::to_canonical_value(self)?],
        )))
    }
}

/// What a relay control request's credential covers.
///
/// The five facts of decision D-018, in the shape that decision fixes. It is
/// [`kr_protocol::service::ServiceRequestPayload`] with the method as text rather than as a registry
/// entry, and nothing else; see this module's note on why.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RelayRequestPayload {
    /// The SHA-256 of the canonical request body.
    pub body_digest: Digest256,
    /// The origin the request was addressed to.
    pub gateway_origin: GatewayOrigin,
    /// The method being called.
    pub method: String,
    /// A fresh 32-byte nonce.
    pub nonce: Nonce256,
    /// When the caller signed, in UTC milliseconds.
    pub signed_at_ms: TimestampMs,
}

impl RelayRequestPayload {
    /// Builds the canonical bytes a signature by `signer` covers.
    ///
    /// # Errors
    ///
    /// Returns a CBOR error when the payload cannot be represented in KR-CBOR-1.
    pub fn signing_input(
        &self,
        signer: ServiceRequestSigner,
    ) -> std::result::Result<Vec<u8>, CborError> {
        Ok(kr_cbor::encode(&signing_value(
            signer.domain(),
            vec![kr_cbor::to_canonical_value(self)?],
        )))
    }
}

/// One credential, as it travels beside the body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RelayRequestSignature {
    /// What was signed.
    pub payload: RelayRequestPayload,
    /// Which key signed it, and therefore which domain it is checked under.
    pub signer: ServiceRequestSigner,
    /// The public half of that key.
    pub public_key: AuthorisationKey,
    /// The signature over [`RelayRequestPayload::signing_input`].
    pub signature: Signature64,
}

/// A signed request, as the service receives it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedRelayRequest<T> {
    /// What the caller wants done.
    pub body: T,
    /// The proof that a key the service will check made this request.
    pub signature: RelayRequestSignature,
}

/* -------------------------------------------------------------------------- */
/* What the service answers                                                    */
/* -------------------------------------------------------------------------- */

/// What a principal has spent of its monthly relay allowance.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayAllowance {
    /// The allowance for the current period, in bytes.
    pub allowance: U64,
    /// Bytes settled or reported by a live reservation. A reported byte is a spent byte.
    pub used: U64,
    /// Bytes held and not yet reported.
    pub reserved: U64,
    /// The calendar month in UTC the figures belong to, or null for a standing total.
    pub period: Nullable<String>,
    /// True once usage has reached the allowance.
    pub exhausted: bool,
}

/// A warning the service raised about the allowance.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayWarning {
    /// The fraction of the allowance that had been used, in percent: 80 or 95.
    pub threshold: u32,
    /// When it was raised, as an RFC 3339 instant.
    pub raised_at: String,
}

/// What is left of the one bounded grace this principal gets.
///
/// Section 17 grants 15 minutes or 100 MiB after the first exhaustion, whichever ends first, shared
/// across every connection of the principal, and requires the remaining interval to be visible
/// before the relay closes. [`Self::remaining_ms`] is that interval.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayGraceRemainder {
    /// When the first exhaustion happened.
    pub started_at: String,
    /// When the grace ends, whatever is left of its bytes.
    pub ends_at: String,
    /// Milliseconds left before the relay closes.
    pub remaining_ms: U64,
    /// Bytes left of the shared allowance.
    pub remaining_bytes: U64,
}

/// A lease the service issued and installed.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayLeaseGrant {
    /// The signed lease, exactly as the relay holds it.
    pub lease: SignedRelayLease,
    /// Where the requester's endpoint connects.
    pub relay_url: String,
    /// The relay instance carrying the pair.
    pub relay_instance_id: RelayInstanceId,
    /// The region that instance serves.
    pub region: RelayRegion,
    /// The revision of the admission key that signed the lease.
    pub issuer_key_revision: U64,
    /// What the relay answered, or null when it did not answer.
    ///
    /// Null is not a failure. The lease is signed and recorded and the bytes are held, so a client
    /// may present it; a relay that never received it refuses the traffic rather than carrying it
    /// unpaid, which is section 17's rule that control-plane loss permits only the already-reserved
    /// bounded remainder.
    pub installed: Nullable<RelayLeaseAck>,
    /// The principal that is billed, as the ledger names it.
    pub payer: String,
    /// The reservation the lease spends from.
    pub reservation_id: RelayReservationId,
    /// What the allowance has left.
    pub allowance: RelayAllowance,
    /// The warnings raised about it.
    pub warnings: Vec<RelayWarning>,
    /// What is left of the shared grace, or null when the principal is not in grace.
    pub grace: Nullable<RelayGraceRemainder>,
}

/// Why no lease was issued, and what to do instead.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayLeaseRefusal {
    /// The principal that would have been billed.
    pub payer: String,
    /// What happened, in English. Safe to display.
    pub message: String,
    /// Paths that still work: a direct connection, or a self-hosted relay.
    pub alternatives: Vec<String>,
    /// What the allowance has left.
    pub allowance: RelayAllowance,
    /// The warnings raised about it.
    pub warnings: Vec<RelayWarning>,
    /// What is left of the shared grace, or null when the principal is not in grace.
    pub grace: Nullable<RelayGraceRemainder>,
    /// Seconds after which the same request could succeed, when that is known.
    #[serde(default)]
    pub retry_after_seconds: Option<u64>,
}

/// The answer to a lease request, as the service tags it.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum TaggedAnswer {
    Issued(Box<RelayLeaseGrant>),
    Exhausted(Box<RelayLeaseRefusal>),
    Unavailable(Box<RelayLeaseRefusal>),
}

/// What a lease request was answered with.
///
/// Three answers, because three things can be true and only one of them is a failure of the
/// request. A lease was issued; the payer's allowance is spent, which section 17 reports as
/// unavailable managed capacity with the paths that still work; or the service has no relay to
/// offer, which is the same kind of answer about a different limit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RelayLeaseAnswer {
    /// A lease, installed on the relay named in it.
    Granted(Box<RelayLeaseGrant>),
    /// The payer's allowance is spent.
    Exhausted(Box<RelayLeaseRefusal>),
    /// Managed relay capacity cannot be offered for this request right now.
    Unavailable(Box<RelayLeaseRefusal>),
}

impl RelayLeaseAnswer {
    /// The grant, when there was one.
    #[must_use]
    pub fn granted(&self) -> Option<&RelayLeaseGrant> {
        match self {
            Self::Granted(grant) => Some(grant),
            Self::Exhausted(_) | Self::Unavailable(_) => None,
        }
    }

    /// The refusal, when there was one.
    #[must_use]
    pub fn refused(&self) -> Option<&RelayLeaseRefusal> {
        match self {
            Self::Granted(_) => None,
            Self::Exhausted(refusal) | Self::Unavailable(refusal) => Some(refusal),
        }
    }

    /// What is left of the bounded grace, whichever answer this is.
    ///
    /// Section 17 requires the remaining interval to be visible before the relay closes, and a
    /// request that is refused is exactly when a client needs it.
    #[must_use]
    pub fn grace(&self) -> Option<&RelayGraceRemainder> {
        match self {
            Self::Granted(grant) => grant.grace.as_ref(),
            Self::Exhausted(refusal) | Self::Unavailable(refusal) => refusal.grace.as_ref(),
        }
    }
}

impl From<TaggedAnswer> for RelayLeaseAnswer {
    fn from(answer: TaggedAnswer) -> Self {
        match answer {
            TaggedAnswer::Issued(grant) => Self::Granted(grant),
            TaggedAnswer::Exhausted(refusal) => Self::Exhausted(refusal),
            TaggedAnswer::Unavailable(refusal) => Self::Unavailable(refusal),
        }
    }
}

/// What one reservation was charged.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelaySettlement {
    /// The reservation.
    pub reservation_id: String,
    /// The cumulative bytes the unbroken run of receipts proves.
    pub bytes_receipted: U64,
    /// The cumulative bytes charged to the allowance.
    pub bytes_settled: U64,
    /// How the figure was arrived at: `receipts`, `conservative` or `pending`.
    pub basis: String,
    /// When the reservation was settled, or null while it is still open.
    pub settled_at: Nullable<String>,
}

/// What ending a lease did.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayLeaseEnding {
    /// The lease that was ended.
    pub lease_id: RelayLeaseId,
    /// The revision the revocation installed.
    pub revision: U64,
    /// What the relay answered, or null when it could not be reached.
    pub relay: Nullable<RelayLeaseAck>,
    /// What the reservation was charged, and on what evidence.
    pub settlement: RelaySettlement,
    /// What is left of the shared grace, or null when the principal is not in grace.
    pub grace: Nullable<RelayGraceRemainder>,
}

/* -------------------------------------------------------------------------- */
/* The client                                                                  */
/* -------------------------------------------------------------------------- */

/// The managed relay-lease client.
#[derive(Clone, Debug)]
pub struct ManagedRelayLeaseService {
    origin: GatewayOrigin,
    http: Arc<dyn ServiceHttp>,
    signer: Arc<dyn ServiceSigner>,
}

impl ManagedRelayLeaseService {
    /// Builds a client against one gateway.
    #[must_use]
    pub fn new(
        origin: GatewayOrigin,
        http: Arc<dyn ServiceHttp>,
        signer: Arc<dyn ServiceSigner>,
    ) -> Self {
        Self {
            origin,
            http,
            signer,
        }
    }

    /// The origin this client addresses.
    #[must_use]
    pub const fn origin(&self) -> &GatewayOrigin {
        &self.origin
    }

    /// Builds the credential for one body.
    fn credential(
        &self,
        method: &str,
        digest: Digest256,
        signed_at_ms: u64,
        nonce: Nonce256,
    ) -> Result<RelayRequestSignature> {
        let payload = RelayRequestPayload {
            body_digest: digest,
            gateway_origin: self.origin.clone(),
            method: method.to_owned(),
            nonce,
            signed_at_ms: TimestampMs::new(signed_at_ms),
        };
        let kind = self.signer.signer();
        let message = payload.signing_input(kind)?;

        Ok(RelayRequestSignature {
            payload,
            signer: kind,
            public_key: self.signer.public_key(),
            signature: self.signer.sign(&message)?,
        })
    }

    /// Sends one signed request and returns the `data` of its envelope.
    async fn call<T: Serialize>(
        &self,
        path: &str,
        method: &str,
        body: T,
        signing_input: Vec<u8>,
    ) -> Result<serde_json::Value> {
        let signature = self.credential(
            method,
            Digest256::from_bytes(sha256(&signing_input)),
            now_ms(),
            Nonce256::from_bytes(fresh_nonce()?),
        )?;

        let request = serde_json::to_vec(&SignedRelayRequest { body, signature })
            .map_err(|error| malformed(format!("a request could not be written: {error}")))?;
        let url = format!("{}{path}", self.origin.as_str());
        let answer = self.http.post_json(&url, &request).await?;

        data_of(&answer)
    }
}

impl RelayLeaseService for ManagedRelayLeaseService {
    fn issue<'a>(&'a self, request: &'a LeaseRequest) -> ServiceFuture<'a, RelayLeaseAnswer> {
        Box::pin(async move {
            let body = RelayLeaseIssueBody::of(request);
            let signing_input = body.signing_input()?;
            let data = self
                .call(
                    RELAY_LEASE_PATH,
                    RELAY_LEASE_ISSUE_METHOD,
                    body,
                    signing_input,
                )
                .await?;
            let answer: TaggedAnswer = serde_json::from_value(data)
                .map_err(|error| malformed(format!("a lease answer: {error}")))?;
            Ok(answer.into())
        })
    }

    fn revoke<'a>(
        &'a self,
        lease_id: RelayLeaseId,
        reason: LeaseEndReason,
    ) -> ServiceFuture<'a, RelayLeaseEnding> {
        Box::pin(async move {
            let body = RelayLeaseRevokeBody { lease_id, reason };
            let signing_input = body.signing_input()?;
            let data = self
                .call(
                    RELAY_LEASE_REVOKE_PATH,
                    RELAY_LEASE_REVOKE_METHOD,
                    body,
                    signing_input,
                )
                .await?;
            serde_json::from_value(data)
                .map_err(|error| malformed(format!("a revocation answer: {error}")))
        })
    }
}

/// The `data` of a service envelope, or the refusal it carried.
///
/// A refusal is the service's answer about the request rather than a transport failure, so it
/// arrives as the error the service named. The codes are the ones every route of this service uses;
/// the mapping is to the protocol's own, so a caller reacts to one vocabulary.
fn data_of(answer: &ServiceHttpAnswer) -> Result<serde_json::Value> {
    #[derive(Deserialize)]
    struct Envelope {
        ok: bool,
        #[serde(default)]
        data: Option<serde_json::Value>,
        #[serde(default)]
        error: Option<Refusal>,
    }

    #[derive(Deserialize)]
    struct Refusal {
        code: String,
        message: String,
    }

    let envelope: Envelope = serde_json::from_slice(&answer.body)
        .map_err(|error| malformed(format!("a service answer: {error}")))?;

    if envelope.ok {
        return envelope
            .data
            .ok_or_else(|| malformed("a service answer carries data".to_owned()));
    }

    let refusal = envelope
        .error
        .ok_or_else(|| malformed("a refusal carries an error".to_owned()))?;

    Err(ClientError::Host(ProtocolError::new(
        code_of(&refusal.code),
        refusal.message,
    )))
}

/// The protocol code one service error code means.
fn code_of(code: &str) -> ErrorCode {
    match code {
        "UNAUTHENTICATED" | "FORBIDDEN" | "REAUTHENTICATION_REQUIRED" => {
            ErrorCode::PermissionDenied
        }
        "RATE_LIMITED" => ErrorCode::RateLimited,
        "QUOTA_EXHAUSTED" => ErrorCode::QuotaExceeded,
        "NOT_CONFIGURED" => ErrorCode::HostNotConfigured,
        "INTERNAL" => ErrorCode::UpstreamUnavailable,
        _ => ErrorCode::InvalidArgument,
    }
}

/// An answer this client could not read, as the error a caller reacts to.
fn malformed(message: String) -> ClientError {
    ClientError::Host(ProtocolError::new(ErrorCode::InvalidArgument, message))
}

/// This machine's clock, in UTC milliseconds.
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| {
            u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
        })
}

/// A fresh nonce from the operating system's generator.
fn fresh_nonce() -> Result<[u8; 32]> {
    let mut nonce = [0u8; 32];
    kr_crypto::random_bytes(&mut nonce)
        .map_err(|error| malformed(format!("a nonce could not be drawn: {error}")))?;
    Ok(nonce)
}
