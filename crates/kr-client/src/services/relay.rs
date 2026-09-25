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
//! # An answer that went missing
//!
//! A lease request that reached the service may have reserved bytes, issued a lease and installed
//! it on a relay, whatever came back. When this client cannot tell, it reports `OUTCOME_UNKNOWN`:
//! for a success status whose body it cannot read, and for a 502 or 504 with no envelope of the
//! service's, which is a gateway in front of it saying the service's answer never reached it.
//! Nothing asks again by itself. A caller finds out before it asks for anything else, by asking
//! again for the same pair with the same cumulative ceiling. The service answers a pair that
//! already holds a lease with that lease rather than a second one, and holds no more bytes than the
//! ceiling names, so the answer is the lease the first request issued, or a new one when it issued
//! none. The caller then uses that lease or ends it with a revocation. A revocation whose answer
//! went missing is simply asked again, because a repeated revocation finishes whatever the first
//! did not and answers with the settlement as it stands.
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
//! Every managed-service method is proven by one credential: a signature over the gateway
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
use kr_protocol::error::ErrorCode;
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
use crate::shown::{ServiceMessage, Shown};

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
/// - never send again a request that may have reached the service. Asking again for a pair that
///   already holds a lease revises that lease, and a request that was delivered and not answered
///   may have issued one, so whether to ask again is the caller's decision. An exchange that failed
///   after the request left is an error; this client reports a success it cannot read, and a
///   gateway's 502 or 504, as an unknown outcome for the same reason. Carrying a request of which
///   no byte was written on another connection is not sending it again: nothing arrived to be
///   repeated.
pub trait ServiceHttp: Send + Sync + std::fmt::Debug {
    /// Posts a JSON body and returns what came back.
    ///
    /// `headers` are the request headers beside `content-type`, lower-cased, in the order this
    /// client built them. A signed managed-service request's credential is inside the body, so the
    /// credential needs no header. A request for something an account owns also carries that
    /// account's token as its `authorization` header, beside the credential when the request is
    /// signed, and an implementation sends the values it is given without recording them.
    fn post_json<'a>(
        &'a self,
        url: &'a str,
        body: &'a [u8],
        headers: &'a [(&'a str, &'a str)],
    ) -> ServiceFuture<'a, ServiceHttpAnswer>;
}

/// What an HTTP exchange returned.
#[derive(Clone, PartialEq, Eq)]
pub struct ServiceHttpAnswer {
    /// The status the service answered with.
    pub status: u16,
    /// The body as it arrived. It is this service's envelope when the answer came from this
    /// service, and something else when it came from anything in front of it.
    pub body: Vec<u8>,
}

impl std::fmt::Debug for ServiceHttpAnswer {
    /// The status, the class it falls in and how many bytes came back. Never the bytes: see this
    /// module's note on what is never rendered.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ServiceHttpAnswer")
            .field("status", &self.status)
            .field("class", &status_class(self.status))
            .field("body_bytes", &self.body.len())
            .finish()
    }
}

/// Which class of answer a status falls in, in the words a person reads.
///
/// It is what a rendering says instead of the body: enough to tell a success from a refusal and a
/// refusal from a fault, and nothing that came off the wire.
const fn status_class(status: u16) -> &'static str {
    match status {
        100..=199 => "informational",
        200..=299 => "success",
        300..=399 => "redirection",
        400..=499 => "refusal",
        500..=599 => "fault",
        _ => "not a status",
    }
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
/// The five facts that make it this request and no other. It is
/// [`kr_protocol::service::ServiceRequestPayload`] with the method as text rather than as a registry
/// entry, and nothing else; see this module's note on why.
#[derive(Clone, PartialEq, Eq, Serialize)]
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

impl std::fmt::Debug for RelayRequestPayload {
    /// The method and the gateway it was addressed to. Never the nonce or the body digest, which
    /// are the parts of a credential that belong to one request and to nothing else.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RelayRequestPayload")
            .field("method", &self.method)
            .field("gateway_origin", &self.gateway_origin.as_str())
            .finish_non_exhaustive()
    }
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
#[derive(Clone, PartialEq, Eq, Serialize)]
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

impl std::fmt::Debug for RelayRequestSignature {
    /// The method and which kind of key signed. Never the signature, the public key or the payload
    /// the signature covers.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RelayRequestSignature")
            .field("method", &self.payload.method)
            .field("signer", &self.signer)
            .finish_non_exhaustive()
    }
}

/// A signed request, as the service receives it.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignedRelayRequest<T> {
    /// What the caller wants done.
    pub body: T,
    /// The proof that a key the service will check made this request.
    pub signature: RelayRequestSignature,
}

impl<T> std::fmt::Debug for SignedRelayRequest<T> {
    /// The method and which kind of key signed. The body is not rendered whatever it is, which is
    /// also why this implementation asks nothing of `T`: a request body that could be printed is a
    /// request body that will be.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SignedRelayRequest")
            .field("method", &self.signature.payload.method)
            .field("signer", &self.signature.signer)
            .finish_non_exhaustive()
    }
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
#[derive(Clone, PartialEq, Eq, Deserialize)]
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

impl std::fmt::Debug for RelayLeaseGrant {
    /// Where the lease can be used and what it is worth, and never the signed lease itself: that
    /// carries the issuer's signature, which is a credential the relay checks.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RelayLeaseGrant")
            .field("lease_id", &self.lease.lease.lease_id)
            .field("relay_instance_id", &self.relay_instance_id)
            .field("region", &self.region)
            .field("payer", &self.payer)
            .field("reservation_id", &self.reservation_id)
            .field("installed", &self.installed.0.is_some())
            .finish_non_exhaustive()
    }
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

        let request =
            serde_json::to_vec(&SignedRelayRequest { body, signature }).map_err(|error| {
                malformed(crate::shown!(
                    "a request could not be written: {}",
                    Shown::json(&error)
                ))
            })?;
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
                    crate::shown!(
                        "this client cannot read its lease answer: {}",
                        Shown::json(&error)
                    ),
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
                    crate::shown!(
                        "this client cannot read its revocation answer: {}",
                        Shown::json(&error)
                    ),
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
/// service. [`unreadable`] is what those become, classified by the status that carried them, and a
/// text that names one member twice anywhere is one of them ([`super::json::read`]).
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

    let envelope = super::json::read::<Envelope>(&answer.body).map_err(|fault| {
        unreadable(
            answer.status,
            crate::shown!("its answer is not one this client reads: {}", fault),
        )
    })?;

    if envelope.ok {
        return envelope
            .data
            .ok_or_else(|| unreadable(answer.status, "its answer carries no data"));
    }

    let Some(refusal) = envelope.error else {
        return Err(unreadable(answer.status, "its refusal names no error"));
    };

    let (code, action) = classify(&refusal.code, answer.status);
    let error = crate::error::refusal(
        code,
        Shown::service(&ServiceMessage::from_refusal(refusal.message)),
    );

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
/// Three of the service's codes map to one protocol code and mean different things to a person, and
/// section 23's required set has one `PERMISSION_DENIED`, so the difference is carried as the
/// action beside it rather than as a code the protocol does not define.
///
/// A lease request is proven by the credential this device mints for itself, so a service that
/// would not admit it is answering about a wrong origin, a method the signature does not name, a
/// body it does not cover, a clock outside the freshness window or a nonce already spent. None of
/// those is a login, so `UNAUTHENTICATED` asks for the configuration. An account session that has
/// to be renewed is a login, and that is the code the service has for it. An authenticated account
/// that may not spend here is neither: telling it to sign in again would send somebody round a loop
/// they are already through.
fn classify(code: &str, status: u16) -> (ErrorCode, UserAction) {
    match code {
        "UNAUTHENTICATED" => (ErrorCode::PermissionDenied, UserAction::FixConfiguration),
        "REAUTHENTICATION_REQUIRED" => (ErrorCode::PermissionDenied, UserAction::SignIn),
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
/// out. Two answers say it may, and both are reported as an unknown outcome and never retried
/// automatically, because a lease may now exist, a reservation may be held and a relay may be
/// carrying it. One is a success status with an unreadable body. The other is a 502 or 504 with no
/// envelope: a gateway in front of the service saying that the service's answer did not reach it,
/// which it can say after passing the request on. Any other fault or a rate limit is transient.
/// Anything else without an envelope never reached this service's own routes, which is a
/// configuration between here and it rather than a value this caller chose.
fn unreadable(status: u16, what: impl Into<Shown>) -> ClientError {
    let code = if (200..300).contains(&status) || status == 502 || status == 504 {
        ErrorCode::OutcomeUnknown
    } else if status >= 500 || status == 408 || status == 429 {
        ErrorCode::UpstreamUnavailable
    } else {
        ErrorCode::HostNotConfigured
    };

    ClientError::refusal(
        code,
        crate::shown!("the service answered {} and {}", status, what.into()),
    )
}

/// A request this client could not build, which is a local fault rather than an answer.
fn malformed(message: impl Into<Shown>) -> ClientError {
    ClientError::refusal(ErrorCode::InvalidArgument, message.into())
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
    kr_crypto::random_bytes(&mut nonce).map_err(|error| {
        malformed(crate::shown!(
            "a nonce could not be drawn: {}",
            Shown::crypto(&error)
        ))
    })?;
    Ok(nonce)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::rendering::{NEVER_RENDERED, renders_only};

    /// A request body that would print the marker if anything rendered a body.
    #[derive(Debug)]
    struct Body {
        #[allow(dead_code, reason = "it is here to be rendered, and never is")]
        note: String,
    }

    fn origin() -> GatewayOrigin {
        GatewayOrigin::new("https://reach.kala.to").expect("an origin")
    }

    fn credential() -> RelayRequestSignature {
        RelayRequestSignature {
            payload: RelayRequestPayload {
                body_digest: Digest256::from_bytes([0x5a; 32]),
                gateway_origin: origin(),
                method: RELAY_LEASE_ISSUE_METHOD.to_owned(),
                nonce: Nonce256::from_bytes([0x3c; 32]),
                signed_at_ms: TimestampMs::new(1_800_000_000_000),
            },
            signer: ServiceRequestSigner::Installation,
            public_key: AuthorisationKey::from_bytes([0x11; 32]),
            signature: Signature64::from_bytes([0x22; 64]),
        }
    }

    /// One issued lease whose signature, read as base64url, spells the marker.
    ///
    /// A signature is 64 bytes and travels as 86 unpadded base64url characters, every one of them
    /// from an alphabet the marker is spelled in, so a rendering that printed the signature would
    /// print the marker.
    fn grant() -> RelayLeaseGrant {
        let signature = format!("{NEVER_RENDERED}{}", "A".repeat(86 - NEVER_RENDERED.len()));
        let key = kr_protocol::scalars::to_base64url(&[9u8; 32]);
        let lease = serde_json::json!({
            "lease_id": "11111111-1111-1111-1111-111111111111",
            "revision": "1",
            "reservation_id": "22222222-2222-2222-2222-222222222222",
            "source_endpoint_key": kr_protocol::scalars::to_base64url(&[1u8; 32]),
            "destination_endpoint_key": kr_protocol::scalars::to_base64url(&[2u8; 32]),
            "direction": "bidirectional",
            "payer": { "installation": { "installation_id": "33333333-3333-3333-3333-333333333333" } },
            "payer_authorisation": "host_selected",
            "byte_ceiling": "4194304",
            "expires_at_ms": "1800000300000",
            "relay_scope": {
                "ingress_relay_instance_id": "44444444-4444-4444-4444-444444444444",
                "egress_relay_instance_id": "44444444-4444-4444-4444-444444444444"
            },
            "metering_relay_instance_id": "44444444-4444-4444-4444-444444444444",
            "metering_role": "ingress",
            "grace": serde_json::Value::Null,
            "issuer_key": key
        });
        let answer = serde_json::json!({
            "ok": true,
            "data": {
                "state": "issued",
                "lease": { "lease": lease, "signature": signature },
                "relay_url": "https://relay-1.reach.kala.to",
                "relay_instance_id": "44444444-4444-4444-4444-444444444444",
                "region": "eu-central",
                "issuer_key_revision": "1",
                "installed": serde_json::Value::Null,
                "payer": "installation:33333333-3333-3333-3333-333333333333",
                "reservation_id": "22222222-2222-2222-2222-222222222222",
                "allowance": {
                    "allowance": "10737418240", "used": "0", "reserved": "4194304",
                    "period": "2026-09", "exhausted": false
                },
                "warnings": [],
                "grace": serde_json::Value::Null
            }
        });

        let data = data_of(&ServiceHttpAnswer {
            status: 200,
            body: serde_json::to_vec(&answer).expect("an envelope"),
        })
        .expect("the service's envelope");
        let answer: TaggedAnswer = serde_json::from_value(data).expect("an issued lease");
        match RelayLeaseAnswer::from(answer) {
            RelayLeaseAnswer::Granted(grant) => *grant,
            RelayLeaseAnswer::Exhausted(_) | RelayLeaseAnswer::Unavailable(_) => {
                unreachable!("the answer says issued")
            }
        }
    }

    #[test]
    fn a_rendering_of_a_request_a_credential_or_an_answer_carries_none_of_it() {
        let request = SignedRelayRequest {
            body: Body {
                note: NEVER_RENDERED.to_owned(),
            },
            signature: credential(),
        };
        renders_only(
            &request,
            r#"SignedRelayRequest{method:"relay.lease.issue",signer:Installation,..}"#,
        );
        renders_only(
            &request.signature,
            r#"RelayRequestSignature{method:"relay.lease.issue",signer:Installation,..}"#,
        );
        renders_only(
            &request.signature.payload,
            r#"RelayRequestPayload{method:"relay.lease.issue",gateway_origin:"https://reach.kala.to",..}"#,
        );

        // An answer that succeeded and an answer that was refused. Both are reached by a
        // diagnostic: the first by an `expect_err` that did not get the error it expected, the
        // second by anything that reports what came back.
        let succeeded = ServiceHttpAnswer {
            status: 200,
            body: format!(r#"{{"ok":true,"data":{{"note":"{NEVER_RENDERED}"}}}}"#).into_bytes(),
        };
        renders_only(
            &succeeded,
            &format!(
                r#"ServiceHttpAnswer{{status:200,class:"success",body_bytes:{}}}"#,
                succeeded.body.len()
            ),
        );
        let refused = ServiceHttpAnswer {
            status: 402,
            body: format!(
                r#"{{"ok":false,"error":{{"code":"QUOTA_EXHAUSTED","message":"{NEVER_RENDERED}"}}}}"#
            )
            .into_bytes(),
        };
        renders_only(
            &refused,
            &format!(
                r#"ServiceHttpAnswer{{status:402,class:"refusal",body_bytes:{}}}"#,
                refused.body.len()
            ),
        );
    }

    #[test]
    fn a_rendering_of_an_issued_lease_carries_neither_the_lease_nor_its_signature() {
        // The signed lease is the relay's own credential: the issuer's signature is what the relay
        // pins its trust to, and a diagnostic that printed one would print it in full.
        let grant = grant();

        // The control: the signature really is findable as text, so a rendering that printed it
        // would be caught by the assertion below rather than passing for want of a marker.
        assert!(
            format!("{:?}", grant.lease.signature).contains(NEVER_RENDERED),
            "the fixture's signature spells the marker"
        );

        renders_only(
            &grant,
            concat!(
                r#"RelayLeaseGrant{lease_id:RelayLeaseId(Uuid(11111111-1111-1111-1111-111111111111)),"#,
                r#"relay_instance_id:RelayInstanceId(Uuid(44444444-4444-4444-4444-444444444444)),"#,
                r#"region:RelayRegion("eu-central"),"#,
                r#"payer:"installation:33333333-3333-3333-3333-333333333333","#,
                r#"reservation_id:RelayReservationId(Uuid(22222222-2222-2222-2222-222222222222)),"#,
                r#"installed:false,..}"#,
            ),
        );

        // And the answer that carries it renders through it rather than round it.
        let answer = RelayLeaseAnswer::Granted(Box::new(grant));
        assert!(!format!("{answer:?}").contains(NEVER_RENDERED));
        assert!(!format!("{answer:#?}").contains(NEVER_RENDERED));
    }

    #[test]
    fn an_answer_this_client_cannot_read_is_reported_without_quoting_it() {
        // The body that could not be read is the one carrying the marker, so an error that quoted
        // any of what came back would carry it.
        let error = data_of(&ServiceHttpAnswer {
            status: 200,
            body: NEVER_RENDERED.as_bytes().to_vec(),
        })
        .expect_err("that is not this service's envelope");
        for rendering in [
            error.to_string(),
            format!("{error:?}"),
            format!("{error:#?}"),
        ] {
            assert!(!rendering.contains(NEVER_RENDERED), "{rendering}");
        }
        assert_eq!(error.code(), ErrorCode::OutcomeUnknown);
    }

    #[test]
    fn a_refusal_carries_the_services_own_message_and_nothing_else_of_the_answer() {
        // The one thing of an answer that does reach a caller, because it is written to be shown
        // to a person. Everything else of the same answer does not.
        let error = data_of(&ServiceHttpAnswer {
            status: 402,
            body: format!(
                r#"{{"ok":false,"error":{{"code":"QUOTA_EXHAUSTED","message":"Your relay allowance is spent.","detail":"{NEVER_RENDERED}"}}}}"#
            )
            .into_bytes(),
        })
        .expect_err("a refusal");

        assert!(error.to_string().contains("Your relay allowance is spent."));
        for rendering in [
            error.to_string(),
            format!("{error:?}"),
            format!("{error:#?}"),
        ] {
            assert!(!rendering.contains(NEVER_RENDERED), "{rendering}");
        }
        assert_eq!(error.code(), ErrorCode::QuotaExceeded);
    }

    #[test]
    fn a_status_is_rendered_as_the_class_it_falls_in() {
        assert_eq!(status_class(100), "informational");
        assert_eq!(status_class(204), "success");
        assert_eq!(status_class(302), "redirection");
        assert_eq!(status_class(409), "refusal");
        assert_eq!(status_class(503), "fault");
        assert_eq!(status_class(700), "not a status");
    }
}
