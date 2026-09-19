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
use crate::retry::UserAction;

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
/// What an implementation owes this client, because the answers above are read on these terms:
///
/// - send the body as `application/json` and read the answer as bytes, whatever its content type:
///   an error page from something in front of the service is an answer this client classifies
///   rather than a case an implementation has to recognise;
/// - return the status and the body for every answer, including a refusal, because the envelope a
///   refusal carries is what names the reason and the delay;
/// - bound what is read, and treat a body that exceeds that bound as an error rather than a
///   truncated answer: half an envelope is not a refusal. A relay lease answer is a few kilobytes;
/// - send every header it is given and keep none of them: a header can carry a credential, and a
///   client library that logged its own requests would be the thing that leaked it;
/// - never retry. Asking again for a pair that already holds a lease revises that lease, and a
///   request that was delivered and not answered may have issued one, so whether to ask again is
///   the caller's decision. An exchange that failed after the request left is an error; this client
///   reports an answer it cannot read as an unknown outcome for the same reason.
pub trait ServiceHttp: Send + Sync + std::fmt::Debug {
    /// Posts a JSON body and returns what came back.
    ///
    /// `headers` are the request headers beside `content-type`, lower-cased, in the order this
    /// client built them. A signed managed-service request carries none, because its credential is
    /// inside the body; a request authorised by an account token carries that token's
    /// `authorization` header, and an implementation sends the values it is given without
    /// recording them.
    fn post_json<'a>(
        &'a self,
        url: &'a str,
        body: &'a [u8],
        headers: &'a [(&'a str, &'a str)],
    ) -> ServiceFuture<'a, ServiceHttpAnswer>;
}

/// What an HTTP exchange returned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceHttpAnswer {
    /// The status the service answered with.
    pub status: u16,
    /// The body as it arrived. It is this service's envelope when the answer came from this
    /// service, and something else when it came from anything in front of it.
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
/// before the relay closes.
///
/// These figures are that window, which is the principal's rather than any one connection's. A
/// connection stops at the earlier of the window's end and its own lease's deadline, and
/// [`RelayLease::effective_deadline_ms`] is the figure the relay enforces for it: the two differ
/// when the reservation's deadline comes first, which a billing period ending inside the window is
/// enough to cause. So a client counting down one connection counts down to its lease, and a client
/// showing the account counts down to this.
///
/// [`RelayLease::effective_deadline_ms`]: kr_protocol::relay::RelayLease::effective_deadline_ms
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayGraceRemainder {
    /// When the first exhaustion happened.
    pub started_at: String,
    /// When the window ends, whatever is left of its bytes.
    pub ends_at: String,
    /// Milliseconds left of the window, for the principal rather than for one connection.
    pub remaining_ms: U64,
    /// Bytes left of the window, across every connection of this principal.
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
        let answer = self.http.post_json(&url, &request, &[]).await?;

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
            let answer: TaggedAnswer = serde_json::from_value(data).map_err(|error| {
                // The service answered, so a lease may have been issued and installed. What this
                // client cannot do is say which answer it was, and a caller must not retry blindly.
                unreadable(
                    200,
                    &format!("this client cannot read its lease answer: {error}"),
                )
            })?;
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
            serde_json::from_value(data).map_err(|error| {
                // The lease may be fenced and its reservation settling. Asking again is safe, which
                // is why a revocation is idempotent, but this client cannot say what happened.
                unreadable(
                    200,
                    &format!("this client cannot read its revocation answer: {error}"),
                )
            })
        })
    }
}

/// The `data` of a service envelope, or the refusal it carried.
///
/// A refusal is the service's answer about the request rather than a transport failure, so it
/// arrives as the error the service named, with the delay it asked for when it named one. The codes
/// are the ones every route of this service uses; the mapping is to the protocol's own, so a caller
/// reacts to one vocabulary.
///
/// A body that is not this service's envelope is not a refusal at all, and it is not this caller's
/// mistake either: it is a proxy's error page, a truncated answer, or something that is not this
/// service. [`unreadable`] is what those become, classified by the status that carried them.
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
        /// The service names this in camel case, as its whole envelope does.
        #[serde(default, rename = "retryAfterSeconds")]
        retry_after_seconds: Option<u64>,
    }

    let Ok(envelope) = serde_json::from_slice::<Envelope>(&answer.body) else {
        return Err(unreadable(
            answer.status,
            "its answer is not one this client reads",
        ));
    };

    if envelope.ok {
        return envelope
            .data
            .ok_or_else(|| unreadable(answer.status, "its answer carries no data"));
    }

    let Some(refusal) = envelope.error else {
        return Err(unreadable(answer.status, "its refusal names no error"));
    };

    let (code, action) = classify(&refusal.code, answer.status);
    let error = ProtocolError::new(code, refusal.message);

    // Always the service's own variant, with or without a delay. What a person is told about a
    // refusal turns on who refused and why, and the service's own code says more than the protocol
    // code it maps to, so the action is decided here rather than from the code afterwards.
    Err(ClientError::Refused {
        error,
        retry_after_seconds: refusal.retry_after_seconds,
        action,
    })
}

/// The protocol code one service error code means, and what a person does about it.
///
/// The status decides the codes this service does not name, because a body carrying an unknown code
/// is either a newer service or something in front of it: a fault is not a field the caller chose.
///
/// Two of the service's codes map to one protocol code and mean different things to a person. A
/// caller that is not authenticated signs in; an authenticated account that may not spend here does
/// not, and telling it to sign in again would send somebody round a loop they are already through.
/// Section 23's required set has one `PERMISSION_DENIED`, so the difference is carried as the
/// action beside it rather than as a code the protocol does not define.
fn classify(code: &str, status: u16) -> (ErrorCode, UserAction) {
    match code {
        "UNAUTHENTICATED" | "REAUTHENTICATION_REQUIRED" => {
            (ErrorCode::PermissionDenied, UserAction::SignIn)
        }
        "FORBIDDEN" => (ErrorCode::PermissionDenied, UserAction::FixConfiguration),
        "RATE_LIMITED" => (ErrorCode::RateLimited, UserAction::Wait),
        "QUOTA_EXHAUSTED" => (ErrorCode::QuotaExceeded, UserAction::Wait),
        "NOT_CONFIGURED" => (ErrorCode::HostNotConfigured, UserAction::FixConfiguration),
        "INTERNAL" => (ErrorCode::UpstreamUnavailable, UserAction::Wait),
        "INVALID_REQUEST" | "NOT_FOUND" | "METHOD_NOT_ALLOWED" => {
            (ErrorCode::InvalidArgument, UserAction::Update)
        }
        _ if status >= 500 => (ErrorCode::UpstreamUnavailable, UserAction::Wait),
        _ => (ErrorCode::InvalidArgument, UserAction::Update),
    }
}

/// An answer this client could not read, classified by the status that carried it.
///
/// What a caller may do about it turns on one question: whether the request may have been carried
/// out. A success status with an unreadable body is the dangerous case, because a lease may now
/// exist, a reservation may be held and a relay may be carrying it, so it is reported as an unknown
/// outcome and never retried automatically. A fault or a rate limit is transient. Anything else
/// without an envelope never reached this service's own routes, which is a configuration between
/// here and it rather than a value this caller chose.
fn unreadable(status: u16, what: &str) -> ClientError {
    let code = if (200..300).contains(&status) {
        ErrorCode::OutcomeUnknown
    } else if status >= 500 || status == 408 || status == 429 {
        ErrorCode::UpstreamUnavailable
    } else {
        ErrorCode::HostNotConfigured
    };

    ClientError::Host(ProtocolError::new(
        code,
        format!("the service answered {status} and {what}"),
    ))
}

/// A request this client could not build, which is a local fault rather than an answer.
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
