//! The push gateway's signed calls, and the one way a signed push request is built.
//!
//! Section 16 has an installation do three things at the gateway: propose the provider token it
//! was given, answer the challenge the gateway sends through the provider to that token, and
//! authorise one paired host. A host does the other two (renew and revoke). All four are signed
//! managed-service requests whose body is a [`PushRequest`], and all four are built by
//! [`signed_push_request`], so the digest the signature covers is [`PushRequest::digest`], the
//! signer's domain is the signer's own, and a body written for one method cannot be presented under
//! another. The host's renewals and the phone's receiver both build theirs here.
//!
//! # What an answer is read as
//!
//! The gateway's envelope is read by the one reader every managed service shares, so a text that
//! names a member twice is not an answer, and what a failure says is where the text failed and
//! never what it held. A refusal arrives as [`crate::ClientError::Refused`] with the code the
//! gateway named, which is what a caller reads to tell "this installation has no active push
//! destination" (`FORBIDDEN`) from "ask again later" (`RATE_LIMITED`).
//!
//! # What is never rendered
//!
//! A delivery credential's bearer, a provider token and a signature travel in these requests and
//! answers. The types here write their own [`std::fmt::Debug`]: what the call is, and nothing that
//! travelled.

use std::fmt;
use std::sync::Arc;

use kr_crypto::keys::AuthorisationKeyPair;
use kr_crypto::sign::{SigningTranscript, sign};
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::PushRegistrationId;
use kr_protocol::ids::PushSenderRecordId;
use kr_protocol::push::{
    PUSH_REGISTRATION_ANSWER_DOMAIN, PushDeliveryCredential, PushInstallationBinding,
    PushRegistrationAnswer, PushRegistrationProposal, PushRegistrationRequest, PushRequest,
    PushSenderIssueRequest, PushSenderRecord,
};
use kr_protocol::scalars::{AuthorisationKey, Nonce256, Signature64, TimestampMs};
use kr_protocol::service::{
    GatewayOrigin, SERVICE_REQUEST_FRESHNESS_MS, ServiceRequestPayload, ServiceRequestSignature,
    ServiceRequestSigner,
};
use serde::{Deserialize, Serialize};

use super::relay::{ServiceHttp, ServiceSigner};
use super::signed::{SignedService, malformed, unreadable_answer};
use super::{PushService, ServiceFuture};
use crate::error::{ClientError, Result};
use crate::shown::Shown;

/// The route `push.installation.register` is presented on.
pub const REGISTER_ROUTE: &str = "/api/push/installation/register";

/// The route `push.sender.issue` is presented on.
pub const ISSUE_ROUTE: &str = "/api/push/sender/issue";

/// The most bytes one signed push request is: the gateway reads no more.
pub const MAX_PUSH_REQUEST_BYTES: usize = 16 * 1024;

/// The route one body is presented on, by the method it belongs to.
#[must_use]
pub const fn route_for(body: &PushRequest) -> &'static str {
    match body {
        PushRequest::InstallationRegister { .. } => REGISTER_ROUTE,
        PushRequest::SenderIssue { .. } => ISSUE_ROUTE,
        PushRequest::SenderRenew { .. } => "/api/push/sender/renew",
        PushRequest::SenderRevoke { .. } => "/api/push/sender/revoke",
    }
}

/// A signed request, as the gateway reads it.
#[derive(Serialize)]
struct SignedPushRequest<'a> {
    body: &'a PushRequest,
    signature: ServiceRequestSignature,
}

impl fmt::Debug for SignedPushRequest<'_> {
    /// The method and which kind of key signed. Never the body or the signature.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignedPushRequest")
            .field("method", &self.signature.payload.method)
            .field("signer", &self.signature.signer)
            .finish_non_exhaustive()
    }
}

/// Builds the bytes of one signed push request: the body, and the credential over its digest.
///
/// `signed_at_ms` is the instant the caller signs at and `nonce` is a fresh value from the caller's
/// random generator. The signature names the gateway the request is addressed to and the method
/// the body belongs to, and the signer says which key signs, so the transcript it signs is the one
/// the gateway checks under that key's domain and no other.
///
/// # Errors
///
/// Returns a refusal when the body cannot be digested, when `signed_at_ms` is outside the window a
/// gateway admits a signature in by this device's clock, when the signer will not sign, or when the
/// request is past [`MAX_PUSH_REQUEST_BYTES`]. Nothing has been sent in any of those cases.
pub fn signed_push_request(
    origin: &GatewayOrigin,
    body: &PushRequest,
    signer: &dyn ServiceSigner,
    signed_at_ms: u64,
    nonce: [u8; 32],
) -> Result<Vec<u8>> {
    let payload = ServiceRequestPayload {
        body_digest: body.digest().map_err(|error| {
            malformed(crate::shown!(
                "a push request could not be digested: {}",
                Shown::cbor(&error)
            ))
        })?,
        gateway_origin: origin.clone(),
        method: body.method(),
        nonce: Nonce256::from_bytes(nonce),
        signed_at_ms: TimestampMs::new(signed_at_ms),
    };
    if !payload.names_a_service_method() {
        return Err(malformed(crate::shown!(
            "{} is not a method a managed service serves",
            body.method()
        )));
    }
    if signer.signer() != body.signer() {
        return Err(malformed(crate::shown!(
            "{} is signed by {}, and this key signs as {}",
            body.method(),
            body.signer().as_str(),
            signer.signer().as_str()
        )));
    }
    if !payload.is_fresh_at(now_ms()) {
        return Err(ClientError::refusal(
            ErrorCode::ClockUntrusted,
            crate::shown!(
                "an attempt signed at {} is outside the {} ms a gateway admits a signature in, by \
                 this device's clock",
                signed_at_ms,
                SERVICE_REQUEST_FRESHNESS_MS
            ),
        ));
    }
    let kind = signer.signer();
    let signature = ServiceRequestSignature {
        signature: signer.sign(&payload.signing_input(kind)?)?,
        payload,
        signer: kind,
        public_key: signer.public_key(),
    };
    let request = serde_json::to_vec(&SignedPushRequest { body, signature }).map_err(|error| {
        malformed(crate::shown!(
            "a push request could not be written: {}",
            Shown::json(&error)
        ))
    })?;
    if request.len() > MAX_PUSH_REQUEST_BYTES {
        return Err(malformed(crate::shown!(
            "a push request is at most {} bytes and this one is {}",
            MAX_PUSH_REQUEST_BYTES,
            request.len()
        )));
    }
    Ok(request)
}

/// [`signed_push_request`], signed now with a nonce drawn from the operating system's generator.
///
/// # Errors
///
/// As [`signed_push_request`], and when no nonce can be drawn.
pub fn signed_push_request_now(
    origin: &GatewayOrigin,
    body: &PushRequest,
    signer: &dyn ServiceSigner,
) -> Result<Vec<u8>> {
    let mut nonce = [0_u8; 32];
    kr_crypto::random_bytes(&mut nonce).map_err(|error| {
        malformed(crate::shown!(
            "a nonce could not be drawn: {}",
            Shown::crypto(&error)
        ))
    })?;
    signed_push_request(origin, body, signer, now_ms(), nonce)
}

/// This machine's clock, in UTC milliseconds.
fn now_ms() -> u64 {
    kr_ipc::now_ms().get()
}

/// An installation's authorisation key, signing the two kinds of statement an installation makes
/// to the push gateway: a managed-service request and the answer to a registration challenge.
///
/// It refuses to sign anything else, so the seam cannot be used to sign a pairing bundle, a grant
/// or an action. The registration answer is the only thing a receiver signs.
pub struct InstallationSigner {
    key: AuthorisationKeyPair,
}

impl InstallationSigner {
    /// Signs with `key`.
    #[must_use]
    pub const fn new(key: AuthorisationKeyPair) -> Self {
        Self { key }
    }
}

impl fmt::Debug for InstallationSigner {
    /// Names the type and nothing of the key.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InstallationSigner")
            .finish_non_exhaustive()
    }
}

impl ServiceSigner for InstallationSigner {
    fn signer(&self) -> ServiceRequestSigner {
        ServiceRequestSigner::Installation
    }

    fn public_key(&self) -> AuthorisationKey {
        *self.key.public()
    }

    fn sign(&self, message: &[u8]) -> Result<Signature64> {
        let transcript = [
            ServiceRequestSigner::Installation.domain(),
            PUSH_REGISTRATION_ANSWER_DOMAIN,
        ]
        .into_iter()
        .find_map(|domain| SigningTranscript::from_canonical_bytes(domain, message.to_vec()).ok())
        .ok_or_else(|| {
            malformed(
                "an installation's key signs a managed-service request or the answer to a \
                 registration challenge",
            )
        })?;
        sign(&self.key, &transcript).map_err(|error| {
            malformed(crate::shown!(
                "the request could not be signed: {}",
                Shown::crypto(&error)
            ))
        })
    }
}

/// What `push.installation.register` answers a proposal with: the attempt waiting for its challenge
/// to come back, or the binding an answer activated.
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Registration {
    /// The challenge was recorded and is waiting for its answer.
    Pending {
        /// The attempt now waiting. An answer names it.
        registration_id: PushRegistrationId,
        /// When the challenge stops being answerable.
        challenge_expires_at_ms: TimestampMs,
        /// Whether the gateway got the challenge as far as the provider. False leaves the
        /// registration pending, and the caller proposes again.
        challenge_sent: bool,
    },
    /// An answer activated the binding.
    Active {
        /// The canonical active binding for this token.
        binding: Box<PushInstallationBinding>,
        /// The authorisations the gateway revoked to activate it: a replacement key ends every
        /// authorisation the installation it replaced had given.
        revoked_sender_records: Vec<PushSenderRecordId>,
    },
}

impl fmt::Debug for Registration {
    /// Which state it is. Never an identifier or a binding.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pending { .. } => formatter.write_str("Registration::Pending"),
            Self::Active { .. } => formatter.write_str("Registration::Active"),
        }
    }
}

/// What `push.sender.issue` answers: the authorisation as the gateway now holds it, and the
/// credential to hand the host.
#[derive(Clone, Deserialize)]
pub struct Issued {
    /// The authorisation as the gateway now holds it.
    pub record: PushSenderRecord,
    /// The credential. It is returned once: the gateway keeps only its digest.
    pub credential: PushDeliveryCredential,
}

impl fmt::Debug for Issued {
    /// That a credential was issued. Never the credential.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Issued(..)")
    }
}

/// The calls an installation makes to the push gateway.
#[derive(Clone)]
pub struct PushGateway {
    service: SignedService,
}

impl fmt::Debug for PushGateway {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PushGateway")
            .field("service", &self.service)
            .finish()
    }
}

impl PushGateway {
    /// The installation `signer` names, calling the gateway at `origin` over `http`.
    #[must_use]
    pub fn new(
        origin: GatewayOrigin,
        http: Arc<dyn ServiceHttp>,
        signer: Arc<dyn ServiceSigner>,
    ) -> Self {
        Self {
            service: SignedService::new(origin, http, signer).leaving_delays_to_the_caller(),
        }
    }

    async fn call<T: for<'de> Deserialize<'de>>(&self, body: &PushRequest) -> Result<T> {
        let data = self
            .service
            .push_call(route_for(body), body, MAX_PUSH_REQUEST_BYTES)
            .await?;
        serde_json::from_value(data)
            .map_err(|error| unreadable_answer("what a push gateway answered", &error))
    }
}

/// Every call returns the gateway's refusal, or why nothing was answered.
impl PushService for PushGateway {
    fn propose<'a>(
        &'a self,
        proposal: PushRegistrationProposal,
    ) -> ServiceFuture<'a, Registration> {
        Box::pin(async move {
            self.call(&PushRequest::InstallationRegister {
                request: PushRegistrationRequest::Propose { proposal },
            })
            .await
        })
    }

    fn answer<'a>(&'a self, answer: PushRegistrationAnswer) -> ServiceFuture<'a, Registration> {
        Box::pin(async move {
            self.call(&PushRequest::InstallationRegister {
                request: PushRegistrationRequest::Answer { answer },
            })
            .await
        })
    }

    fn issue<'a>(&'a self, request: PushSenderIssueRequest) -> ServiceFuture<'a, Issued> {
        Box::pin(async move { self.call(&PushRequest::SenderIssue { request }).await })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use kr_crypto::sign::verify;
    use kr_protocol::scalars::Digest256;

    use super::*;
    use crate::services::relay::ServiceHttpAnswer;

    const VECTORS: &str = include_str!("../../../../fixtures/push/push.json");

    fn vectors() -> serde_json::Value {
        serde_json::from_str(VECTORS).expect("the push vectors")
    }

    /// One vector case, by identifier.
    fn case(id: &str) -> serde_json::Value {
        vectors()["cases"]
            .as_array()
            .expect("the cases")
            .iter()
            .find(|case| case["id"] == id)
            .unwrap_or_else(|| panic!("the vector {id}"))
            .clone()
    }

    /// The body a vector case records, as the gateway reads it.
    fn body(id: &str) -> PushRequest {
        serde_json::from_value(case(id)["json"].clone()).expect("a push request body")
    }

    fn hex(digest: Digest256) -> String {
        digest
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    fn origin() -> GatewayOrigin {
        GatewayOrigin::new("https://reach.kala.to").expect("an origin")
    }

    fn installation() -> InstallationSigner {
        InstallationSigner::new(AuthorisationKeyPair::generate().expect("a key pair"))
    }

    /// A body is signed under the digest the vectors record for it, by the key and the domain its
    /// signer names: the request is the body and a credential whose signature verifies.
    #[test]
    fn a_signed_push_request_is_the_body_and_a_signature_over_the_digest_the_vectors_record() {
        let signer = installation();
        let body = body("body_registration_propose");
        assert_eq!(
            hex(body.digest().expect("a digest")),
            case("body_registration_propose")["sha256"],
            "the digest the signature covers is the vectors' own"
        );
        let request = signed_push_request(&origin(), &body, &signer, now_ms(), [7; 32])
            .expect("a signed request");
        let sent: serde_json::Value = serde_json::from_slice(&request).expect("a JSON request");
        assert_eq!(sent["body"], case("body_registration_propose")["json"]);
        let signature: ServiceRequestSignature =
            serde_json::from_value(sent["signature"].clone()).expect("a signature");
        assert_eq!(signature.payload.method, body.method());
        assert_eq!(
            signature.payload.body_digest,
            body.digest().expect("a digest")
        );
        assert_eq!(signature.payload.gateway_origin, origin());
        assert_eq!(signature.signer, ServiceRequestSigner::Installation);
        let transcript = SigningTranscript::from_canonical_bytes(
            ServiceRequestSigner::Installation.domain(),
            signature.signing_input().expect("a signing input"),
        )
        .expect("a transcript");
        verify(&signer.public_key(), &transcript, &signature.signature)
            .expect("the signature verifies under the installation's key");
    }

    /// A body is signed only by the kind of key it names: a host's renewal cannot be signed as an
    /// installation, and an installation's registration cannot be signed as the host.
    #[test]
    fn a_body_is_signed_only_by_the_kind_of_key_it_names() {
        let host_body = body("body_sender_renew_begin");
        assert_eq!(host_body.signer(), ServiceRequestSigner::Host);
        let refused =
            signed_push_request(&origin(), &host_body, &installation(), now_ms(), [7; 32])
                .expect_err("an installation does not sign a host's request");
        assert_eq!(refused.code(), ErrorCode::InvalidArgument);
    }

    /// The installation's key signs a managed-service request and the answer to a registration
    /// challenge, and nothing else: a statement under any other domain is refused before it is
    /// signed.
    #[test]
    fn an_installations_key_signs_a_request_and_a_registration_answer_and_nothing_else() {
        let signer = installation();
        let answer: PushRegistrationAnswer =
            serde_json::from_value(case("registration_answer")["json"].clone()).expect("an answer");
        let input = answer.payload.signing_input().expect("a signing input");
        let signature = signer.sign(&input).expect("the answer is signed");
        let transcript =
            SigningTranscript::from_canonical_bytes(PUSH_REGISTRATION_ANSWER_DOMAIN, input)
                .expect("a transcript");
        verify(&signer.public_key(), &transcript, &signature)
            .expect("the answer's signature verifies under the installation's key");

        let other = SigningTranscript::from_elements("kr-pairing-bundle/1", Vec::new());
        let refused = signer
            .sign(other.as_bytes())
            .expect_err("a statement under another domain is not signed");
        assert_eq!(refused.code(), ErrorCode::InvalidArgument);
    }

    /// What a rendering of a signer, a registration, a credential or a signed request prints is
    /// held to the exact fields it may: which state or call it is, and nothing of a key.
    #[test]
    fn a_rendering_of_a_signer_a_registration_a_credential_or_a_request_carries_none_of_it() {
        use crate::services::rendering::renders_only;

        let signer = installation();
        renders_only(&signer, "InstallationSigner{..}");

        let records = vectors()["records"].clone();
        let issued: Issued = serde_json::from_value(serde_json::json!({
            "record": records["sender_record"],
            "credential": records["delivery_credential"],
        }))
        .expect("an issued credential");
        renders_only(&issued, "Issued(..)");
        let active: Registration = serde_json::from_value(serde_json::json!({
            "state": "active",
            "binding": records["installation_binding"],
            "revoked_sender_records": [],
        }))
        .expect("a registration");
        renders_only(&active, "Registration::Active");

        let request = SignedPushRequest {
            body: &body("body_registration_propose"),
            signature: serde_json::from_value(serde_json::json!({
                "payload": {
                    "body_digest": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    "gateway_origin": "https://reach.kala.to",
                    "method": "push.installation.register",
                    "nonce": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                    "signed_at_ms": "1767225600000",
                },
                "signer": "installation",
                "public_key": "ERERERERERERERERERERERERERERERERERERERERERE",
                "signature": "XFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXFxcXA",
            }))
            .expect("a signature"),
        };
        renders_only(
            &request,
            "SignedPushRequest{method:PushInstallationRegister,signer:Installation,..}",
        );
    }

    /// Answers from a script and records what it was asked.
    struct Gateway {
        answers: Mutex<Vec<(u16, serde_json::Value)>>,
        asked: Mutex<Vec<(String, Vec<u8>)>>,
    }

    impl fmt::Debug for Gateway {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("Gateway")
        }
    }

    impl ServiceHttp for Gateway {
        fn post_json<'a>(
            &'a self,
            url: &'a str,
            body: &'a [u8],
            headers: &'a [(&'a str, &'a str)],
        ) -> ServiceFuture<'a, ServiceHttpAnswer> {
            assert!(headers.is_empty(), "a signed push request sends no headers");
            self.asked
                .lock()
                .expect("what was asked")
                .push((url.to_owned(), body.to_vec()));
            let (status, answer) = self.answers.lock().expect("the answers").remove(0);
            Box::pin(async move {
                Ok(ServiceHttpAnswer {
                    status,
                    body: serde_json::to_vec(&answer).expect("an answer"),
                })
            })
        }
    }

    /// The gateway client in the push slot of a set of service clients, which is where a process
    /// holds it, and what it was asked.
    fn gateway(answers: Vec<(u16, serde_json::Value)>) -> (Arc<dyn PushService>, Arc<Gateway>) {
        let stand_in = Arc::new(Gateway {
            answers: Mutex::new(answers),
            asked: Mutex::new(Vec::new()),
        });
        let clients = crate::services::ServiceClients {
            push: Some(Arc::new(PushGateway::new(
                origin(),
                Arc::clone(&stand_in) as Arc<dyn ServiceHttp>,
                Arc::new(installation()),
            ))),
            ..crate::services::ServiceClients::none()
        };
        assert!(
            clients.holds(crate::services::ManagedService::Push),
            "the slot is filled"
        );
        (clients.push.expect("the push slot"), stand_in)
    }

    fn proposal() -> PushRegistrationProposal {
        match body("body_registration_propose") {
            PushRequest::InstallationRegister {
                request: PushRegistrationRequest::Propose { proposal },
            } => proposal,
            other => panic!("not a proposal: {other:?}"),
        }
    }

    /// What the gateway answers to each of the installation's three calls is read as the records the
    /// vectors carry, and each call, made through the push slot, goes to its own route with a
    /// request the gateway can check.
    #[tokio::test]
    async fn the_gateway_client_reads_what_the_gateway_answers_each_call_with() {
        let records = vectors()["records"].clone();
        let (client, stand_in) = gateway(vec![
            (
                200,
                serde_json::json!({ "ok": true, "data": {
                    "state": "pending",
                    "registration_id": "2e749a03-c158-4d62-a019-6f3bd784215c",
                    "challenge_expires_at_ms": "1767225900000",
                    "challenge_sent": true,
                }}),
            ),
            (
                200,
                serde_json::json!({ "ok": true, "data": {
                    "state": "active",
                    "binding": records["installation_binding"],
                    "revoked_sender_records": [],
                }}),
            ),
            (
                200,
                serde_json::json!({ "ok": true, "data": {
                    "record": records["sender_record"],
                    "credential": records["delivery_credential"],
                }}),
            ),
        ]);

        let pending = client.propose(proposal()).await.expect("a proposal");
        assert!(matches!(
            pending,
            Registration::Pending {
                challenge_sent: true,
                ..
            }
        ));
        let answer: PushRegistrationAnswer =
            serde_json::from_value(case("registration_answer")["json"].clone()).expect("an answer");
        let active = client.answer(answer).await.expect("an answer is taken");
        assert!(matches!(active, Registration::Active { .. }));
        let issue = match body("body_sender_issue") {
            PushRequest::SenderIssue { request } => request,
            other => panic!("not an issue: {other:?}"),
        };
        let issued = client.issue(issue).await.expect("a credential");
        assert_eq!(
            issued.credential.sender_record_id,
            issued.record.binding.sender_record_id
        );

        let asked = stand_in.asked.lock().expect("what was asked");
        assert_eq!(
            asked
                .iter()
                .map(|(url, _)| url.as_str())
                .collect::<Vec<_>>(),
            [
                "https://reach.kala.to/api/push/installation/register",
                "https://reach.kala.to/api/push/installation/register",
                "https://reach.kala.to/api/push/sender/issue",
            ]
        );
        for (_, request) in asked.iter() {
            let sent: serde_json::Value = serde_json::from_slice(request).expect("a request");
            let signature: ServiceRequestSignature =
                serde_json::from_value(sent["signature"].clone()).expect("a signature");
            let body: PushRequest = serde_json::from_value(sent["body"].clone()).expect("a body");
            assert_eq!(
                signature.payload.body_digest,
                body.digest().expect("a digest")
            );
            assert_eq!(signature.payload.method, body.method());
        }
    }

    /// A refusal the gateway names reaches the caller with its code, which is how "this
    /// installation has no active push destination" is told from "ask again later".
    #[tokio::test]
    async fn a_refusal_reaches_the_caller_with_the_code_the_gateway_named() {
        let (client, _) = gateway(vec![(
            403,
            serde_json::json!({ "ok": false, "error": {
                "code": "FORBIDDEN",
                "message": "This installation has no active push destination.",
            }}),
        )]);
        let issue = match body("body_sender_issue") {
            PushRequest::SenderIssue { request } => request,
            other => panic!("not an issue: {other:?}"),
        };
        let refused = client.issue(issue).await.expect_err("a refusal");
        assert!(matches!(
            refused,
            ClientError::Refused {
                service_code: Some("FORBIDDEN"),
                ..
            }
        ));
    }
}
