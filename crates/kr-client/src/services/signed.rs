//! One signed managed-service call, and what its answer means.
//!
//! The mailbox, the authority feed and settings sync are three services with one way in. Each
//! method is a POST of a JSON document to a path, authenticated by one credential per method: a
//! signature over the gateway origin, the method, a fresh nonce, the time and the digest of the
//! canonical request body. So the call is written once here and each adapter supplies its path,
//! its method and its body.
//!
//! # What the digest covers
//!
//! These bodies are JSON documents rather than protocol objects, so
//! [`kr_protocol::service::canonical_body_digest`] is what the signature carries: the KR-CBOR-1
//! encoding of the document, with text keys in canonical order and an exact count as an unsigned
//! integer. The document that is digested is the document that is sent, so the service recomputes
//! the digest from the bytes it received and neither half depends on how the other wrote its JSON.
//!
//! # What is never rendered
//!
//! A request body carries a credential and an answer carries whatever answered, so the types here
//! write their own [`std::fmt::Debug`] under this module's rule: the method, the signer kind and
//! the gateway, and nothing that travelled.

use std::fmt;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::method::Method;
use kr_protocol::scalars::{AuthorisationKey, Nonce256, TimestampMs};
use kr_protocol::service::{
    BodyError, GatewayOrigin, ServiceRequestPayload, ServiceRequestSignature, ServiceRequestSigner,
    canonical_body_digest,
};
use serde::{Deserialize, Serialize};

use super::relay::{ServiceHttp, ServiceHttpAnswer, ServiceSigner};
use crate::error::{ClientError, Result};
use crate::retry::UserAction;

/// The exchange a managed-service adapter makes its calls through.
///
/// One gateway, one signer, one transport. An adapter holds this and knows nothing about
/// credentials, envelopes or status codes.
#[derive(Clone)]
pub struct SignedService {
    origin: GatewayOrigin,
    http: Arc<dyn ServiceHttp>,
    signer: Arc<dyn ServiceSigner>,
}

impl fmt::Debug for SignedService {
    /// The gateway and which kind of key signs for it. Never the key and never a request.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignedService")
            .field("gateway_origin", &self.origin.as_str())
            .field("signer", &self.signer.signer())
            .finish_non_exhaustive()
    }
}

impl SignedService {
    /// Builds the exchange one adapter uses.
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

    /// The gateway these calls are addressed to.
    #[must_use]
    pub const fn origin(&self) -> &GatewayOrigin {
        &self.origin
    }

    /// Whether an installation or a host signs for this caller.
    #[must_use]
    pub fn signer_kind(&self) -> ServiceRequestSigner {
        self.signer.signer()
    }

    /// The public half of the key that signs.
    #[must_use]
    pub fn public_key(&self) -> AuthorisationKey {
        self.signer.public_key()
    }

    /// Sends one signed request and returns the `data` of the service's envelope.
    ///
    /// `request_limit` is the most bytes the service admits for the whole signed request, which
    /// each method states for itself. A request past it is refused here rather than sent, because
    /// a service that stops reading at its own limit answers a request it never saw whole, and a
    /// caller told "too large" by this client knows it was this client that said so.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Refused`] for a refusal the service named, and
    /// [`ClientError::Host`] for a request this client would not send, a transport failure and an
    /// answer this client cannot read.
    pub async fn call<B: Serialize>(
        &self,
        path: &str,
        method: Method,
        body: &B,
        request_limit: usize,
    ) -> Result<serde_json::Value> {
        let document = serde_json::to_value(body).map_err(|error| {
            malformed(format!(
                "a request could not be written: {}",
                super::json_fault(&error)
            ))
        })?;
        let request = self.signed(method, document)?;
        if request.len() > request_limit {
            return Err(malformed(format!(
                "a {method} request is at most {request_limit} bytes and this one is {}",
                request.len()
            )));
        }
        let url = format!("{}{path}", self.origin.as_str());
        let answer = self.http.post_json(&url, &request, &[]).await?;
        data_of(&answer)
    }

    /// The bytes of one signed request: the document, and the credential over its digest.
    fn signed(&self, method: Method, document: serde_json::Value) -> Result<Vec<u8>> {
        let payload = ServiceRequestPayload {
            // The failure names which rule the body broke and nothing of the body: a count it
            // cannot carry, or members that are not canonical and distinct.
            body_digest: canonical_body_digest(&document).map_err(|error| {
                malformed(match error {
                    BodyError::Number => {
                        "a request body carries no number that is not an exact count"
                    }
                    BodyError::Members(_) => "a request body's members are canonical and distinct",
                })
            })?,
            gateway_origin: self.origin.clone(),
            method,
            nonce: Nonce256::from_bytes(fresh_nonce()?),
            signed_at_ms: TimestampMs::new(now_ms()),
        };
        // The credential names the method it authorises, and the set it may name is the managed
        // surface. A credential for a host method would be a credential aimed at something no
        // service holds the authority to run.
        if !payload.names_a_service_method() {
            return Err(malformed(format!(
                "{method} is not a method a managed service serves"
            )));
        }

        let signer = self.signer.signer();
        let signature = ServiceRequestSignature {
            signature: self.signer.sign(&payload.signing_input(signer)?)?,
            payload,
            signer,
            public_key: self.signer.public_key(),
        };

        serde_json::to_vec(&SignedServiceRequest {
            body: document,
            signature,
        })
        .map_err(|error| {
            malformed(format!(
                "a request could not be written: {}",
                super::json_fault(&error)
            ))
        })
    }
}

/// A signed request, as the service receives it.
#[derive(Serialize)]
struct SignedServiceRequest {
    /// The document the digest covers.
    body: serde_json::Value,
    /// The proof that a key the service will check made this request.
    signature: ServiceRequestSignature,
}

impl fmt::Debug for SignedServiceRequest {
    /// The method and which kind of key signed. Never the body, the credential or the signature.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignedServiceRequest")
            .field("method", &self.signature.payload.method)
            .field("signer", &self.signature.signer)
            .finish_non_exhaustive()
    }
}

/// The `data` of a service envelope, or the refusal it carried.
///
/// A refusal is the service's answer about the request rather than a transport failure, so it
/// arrives as the error the service named, with the delay it asked for when it named one.
///
/// A body that is not this service's envelope is not a refusal at all: it is something in front of
/// the service, a truncated answer, or something that is not this service. [`unreadable`] is what
/// those become, classified by the status that carried them.
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
    Err(ClientError::Refused {
        error: ProtocolError::new(code, refusal.message),
        retry_after_seconds: refusal.retry_after_seconds,
        action,
    })
}

/// The protocol code one service error code means, and what a person does about it.
///
/// The status decides the codes this service does not name, because a body carrying an unknown code
/// is either a newer service or something in front of it.
///
/// Two of the service's codes map to one protocol code and mean different things to a person, and
/// section 23's required set has one `PERMISSION_DENIED`, so the difference is carried as the
/// action beside it rather than as a code the protocol does not define.
///
/// Neither of them is a sign-in. These methods are proven by a credential this device mints for
/// itself, not by an account, so a credential the service would not admit is a wrong origin, a
/// method the signature does not name, a body it does not cover, a clock outside the freshness
/// window or a nonce already spent. Signing in changes none of those: what does is this device's
/// own configuration, so `UNAUTHENTICATED` asks for that and `FORBIDDEN` says this key may not do
/// this, which is a matter for the host's records rather than for a login.
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
/// out. A success status with an unreadable body is the dangerous case, because the service acted
/// and this client cannot see what it did, so it is an unknown outcome and never retried
/// automatically. A fault or a rate limit is transient. Anything else without an envelope never
/// reached this service's own routes, which is a configuration between here and it.
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

/// An answer that was read and is not the shape this client expected.
///
/// The service answered, so whatever it did is done; what this client lacks is the answer. It is
/// therefore an unknown outcome, like any other answer that could not be read.
///
/// What it says about the answer is [`super::json_fault`] and nothing else: an answer carries
/// whatever answered, and `serde_json`'s own message would quote the part it rejected.
pub(crate) fn unreadable_answer(what: &str, error: &serde_json::Error) -> ClientError {
    ClientError::Host(ProtocolError::new(
        ErrorCode::OutcomeUnknown,
        format!(
            "this client cannot read {what}: {}",
            super::json_fault(error)
        ),
    ))
}

/// A request this client would not send. Nothing left this device.
pub(crate) fn malformed(message: impl Into<String>) -> ClientError {
    ClientError::Host(ProtocolError::new(
        ErrorCode::InvalidArgument,
        message.into(),
    ))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::rendering::{NEVER_RENDERED, renders_only};

    fn origin() -> GatewayOrigin {
        GatewayOrigin::new("https://reach.kala.to").expect("an origin")
    }

    fn credential() -> ServiceRequestSignature {
        let payload = ServiceRequestPayload {
            body_digest: canonical_body_digest(&serde_json::json!({})).expect("a digest"),
            gateway_origin: origin(),
            method: Method::AuthoritySync,
            nonce: Nonce256::from_bytes([0x3c; 32]),
            signed_at_ms: TimestampMs::new(1_800_000_000_000),
        };
        ServiceRequestSignature {
            payload,
            signer: ServiceRequestSigner::Host,
            public_key: AuthorisationKey::from_bytes([0x11; 32]),
            signature: kr_protocol::scalars::Signature64::from_bytes([0x22; 64]),
        }
    }

    #[test]
    fn a_rendering_of_a_signed_request_carries_neither_its_body_nor_its_credential() {
        let request = SignedServiceRequest {
            body: serde_json::json!({ "note": NEVER_RENDERED }),
            signature: credential(),
        };
        renders_only(
            &request,
            r#"SignedServiceRequest{method:AuthoritySync,signer:Host,..}"#,
        );
    }

    #[test]
    fn a_refusal_carries_the_services_own_message_and_nothing_else_of_the_answer() {
        let error = data_of(&ServiceHttpAnswer {
            status: 403,
            body: format!(
                r#"{{"ok":false,"error":{{"code":"FORBIDDEN","message":"Only the host issues its own revisions.","detail":"{NEVER_RENDERED}"}}}}"#
            )
            .into_bytes(),
        })
        .expect_err("a refusal");

        assert!(
            error
                .to_string()
                .contains("Only the host issues its own revisions.")
        );
        for rendering in [
            error.to_string(),
            format!("{error:?}"),
            format!("{error:#?}"),
        ] {
            assert!(!rendering.contains(NEVER_RENDERED), "{rendering}");
        }
        assert_eq!(error.code(), ErrorCode::PermissionDenied);
    }

    #[test]
    fn an_answer_this_client_cannot_read_is_reported_without_quoting_it() {
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
    fn a_success_with_no_data_is_an_unknown_outcome_rather_than_an_empty_answer() {
        let error = data_of(&ServiceHttpAnswer {
            status: 200,
            body: br#"{"ok":true}"#.to_vec(),
        })
        .expect_err("an envelope with no data");
        assert_eq!(error.code(), ErrorCode::OutcomeUnknown);
    }
}
