//! The managed relay-lease client, against a service that answers the way the real one does.
//!
//! Three things have to hold for a client to be able to obtain a lease at all, and each is checked
//! here. The credential covers the five facts that make it this request, over the canonical
//! encoding of
//! the body rather than over the JSON that carries it. The request the service receives is the
//! request this client meant to send, field for field. And every answer the service gives is one
//! this client reads: a lease, an allowance that is spent, capacity that is unavailable, and a
//! refusal that names a code.
//!
//! The vectors are the load-bearing part. `signing_input_hex` for each body is pinned here and in
//! `workers/api/test/relay/vectors.json` in the website repository, where the service rebuilds the
//! same bytes from the JSON it received. Nothing is shared between the two implementations, so a
//! drift in either fails a suite rather than showing up as leases that mysteriously stop verifying.

use std::sync::{Arc, Mutex};

use kr_client::retry::{RequestClass, UserAction};
use kr_client::services::relay::{
    ManagedRelayLeaseService, RelayLeaseIssueBody, RelayLeaseRevokeBody, RelayPayerSignInBody,
};
use kr_client::services::{
    AccountToken, LeaseEndReason, LeasePayer, LeaseRequest, RelayDirection, RelayLeaseAnswer,
    RelayLeaseService, ServiceHttp, ServiceHttpAnswer, ServiceSigner,
};
use kr_client::{ClientError, Result};
use kr_crypto::keys::AuthorisationKeyPair;
use kr_crypto::sign::{SigningTranscript, sign, verify};
use kr_protocol::error::{ErrorCode, RetryCategory};
use kr_protocol::ids::RelayLeaseId;
use kr_protocol::relay::RelayLeaseState;
use kr_protocol::scalars::{AuthorisationKey, EndpointKey, Signature64, Uuid};
use kr_protocol::service::{GatewayOrigin, ServiceRequestSigner};

/// The canonical bytes a lease request's digest is taken over, for the request `issue_request()`
/// builds, and their digest.
///
/// Pinned on both sides of the contract: the same two strings are the `lease_request` case of
/// `workers/api/test/relay/vectors.json` in the website repository, where the service rebuilds
/// these bytes from the JSON it received.
const LEASE_REQUEST_HEX: &str = "8278186b722d72656c61792d6c656173652d726571756573742f31a86570617965726c696e7374616c6c6174696f6e686c656173655f6964f669646972656374696f6e6d6269646972656374696f6e616c6c627974655f6365696c696e671a00400000706475726174696f6e5f7365636f6e647319012c71726567696f6e5f707265666572656e63656a65752d63656e7472616c73736f757263655f656e64706f696e745f6b657958200101010101010101010101010101010101010101010101010101010101010101781864657374696e6174696f6e5f656e64706f696e745f6b657958200202020202020202020202020202020202020202020202020202020202020202";
const LEASE_REQUEST_SHA256: &str =
    "881c444baf4654ce066f19140796089b116d3b87a41ce36e0da2528b66a69e4d";

/// The canonical bytes an installation's credential covers, for [`fixed_payload`].
const CREDENTIAL_HEX: &str = "82746b722d736572766963652d726571756573742f31a5656e6f6e636558203c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c666d6574686f647172656c61792e6c656173652e69737375656b626f64795f64696765737458205a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a6c7369676e65645f61745f6d731b000001a3185c50006e676174657761795f6f726967696e7568747470733a2f2f72656163682e6b616c612e746f";

/// The same under the host domain, which is the whole of the difference between the two signers.
const CREDENTIAL_HOST_HEX: &str = "8278196b722d736572766963652d726571756573742f312f686f7374a5656e6f6e636558203c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c666d6574686f647172656c61792e6c656173652e69737375656b626f64795f64696765737458205a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a6c7369676e65645f61745f6d731b000001a3185c50006e676174657761795f6f726967696e7568747470733a2f2f72656163682e6b616c612e746f";

/// The same, for the revocation `RelayLeaseRevokeBody` builds.
const LEASE_REVOKE_HEX: &str = "82776b722d72656c61792d6c656173652d7265766f6b652f31a266726561736f6e6866696e6973686564686c656173655f69645011111111111111111111111111111111";
const LEASE_REVOKE_SHA256: &str =
    "cb78aa32039121f529ecfe4468e34203864841d37fb56c04bf3748ebe7044524";

/// A service that records what it was sent and answers with what it was told to.
#[derive(Debug)]
struct Recorder {
    sent: Mutex<Vec<Sent>>,
    answer: Mutex<ServiceHttpAnswer>,
}

/// One request as it was sent: where, with what body, and under what headers.
type Sent = (String, Vec<u8>, Vec<(String, String)>);

impl Recorder {
    fn new(body: &str) -> Arc<Self> {
        Arc::new(Self {
            sent: Mutex::new(Vec::new()),
            answer: Mutex::new(ServiceHttpAnswer {
                status: 200,
                body: body.as_bytes().to_vec(),
            }),
        })
    }

    fn answer_with(&self, status: u16, body: &str) {
        *self.answer.lock().expect("the answer") = ServiceHttpAnswer {
            status,
            body: body.as_bytes().to_vec(),
        };
    }

    fn last(&self) -> (String, serde_json::Value) {
        let sent = self.sent.lock().expect("what was sent");
        let (url, body, _) = sent.last().expect("one request").clone();
        (
            url,
            serde_json::from_slice(&body).expect("a request this client wrote"),
        )
    }

    /// The headers of the latest request, beside the credential in its body.
    fn last_headers(&self) -> Vec<(String, String)> {
        let sent = self.sent.lock().expect("what was sent");
        sent.last().expect("one request").2.clone()
    }
}

impl ServiceHttp for Recorder {
    fn post_json<'a>(
        &'a self,
        url: &'a str,
        body: &'a [u8],
        headers: &'a [(&'a str, &'a str)],
    ) -> kr_client::services::ServiceFuture<'a, ServiceHttpAnswer> {
        // A signed relay request carries its credential in the body, so it sends no headers of
        // its own unless an account owns what it asks for. Recorded rather than ignored, so a test
        // can assert on what was sent.
        self.sent.lock().expect("what was sent").push((
            url.to_owned(),
            body.to_vec(),
            headers
                .iter()
                .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
                .collect(),
        ));
        let answer = self.answer.lock().expect("the answer").clone();
        Box::pin(async move { Ok(answer) })
    }
}

/// An installation's device authorisation key, held the way a client holds one.
#[derive(Debug)]
struct Installation {
    pair: AuthorisationKeyPair,
    kind: ServiceRequestSigner,
}

impl Installation {
    fn new(kind: ServiceRequestSigner) -> Arc<Self> {
        Arc::new(Self {
            pair: AuthorisationKeyPair::generate().expect("a key pair"),
            kind,
        })
    }
}

impl ServiceSigner for Installation {
    fn signer(&self) -> ServiceRequestSigner {
        self.kind
    }

    fn public_key(&self) -> AuthorisationKey {
        *self.pair.public()
    }

    fn sign(&self, message: &[u8]) -> Result<Signature64> {
        // The transcript type refuses bytes that are not a domain-tagged array, so a signer cannot
        // be handed arbitrary bytes to sign under a domain it holds a key for.
        let transcript =
            SigningTranscript::from_canonical_bytes(self.kind.domain(), message.to_vec())
                .expect("a domain-tagged transcript");
        Ok(sign(&self.pair, &transcript).expect("a signature"))
    }
}

fn origin() -> GatewayOrigin {
    GatewayOrigin::new("https://reach.kala.to").expect("an origin")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The request every vector in this file is built from.
fn issue_request() -> LeaseRequest {
    LeaseRequest {
        source: EndpointKey::from_bytes([1; 32]),
        destination: EndpointKey::from_bytes([2; 32]),
        direction: RelayDirection::Bidirectional,
        byte_ceiling: 4 * 1024 * 1024,
        duration_seconds: 300,
        region_preference: Some("eu-central".to_owned()),
        payer: Some(LeasePayer::Installation),
        lease_id: None,
    }
}

/// The lease a service answers with, in the shape the route serves.
fn granted_answer() -> String {
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
        "issuer_key": kr_protocol::scalars::to_base64url(&[9u8; 32])
    });

    serde_json::json!({
        "ok": true,
        "data": {
            "state": "issued",
            "lease": { "lease": lease, "signature": kr_protocol::scalars::to_base64url(&[7u8; 64]) },
            "relay_url": "https://relay-1.reach.kala.to",
            "relay_instance_id": "44444444-4444-4444-4444-444444444444",
            "region": "eu-central",
            "issuer_key_revision": "1",
            "installed": {
                "lease_id": "11111111-1111-1111-1111-111111111111",
                "revision": "1",
                "state": "installed",
                "bytes_consumed": "0",
                "bytes_remaining": "4194304",
                "grace_remaining_ms": serde_json::Value::Null
            },
            "payer": "installation:33333333-3333-3333-3333-333333333333",
            "reservation_id": "22222222-2222-2222-2222-222222222222",
            "allowance": {
                "allowance": "10737418240",
                "used": "0",
                "reserved": "4194304",
                "period": "2026-09",
                "exhausted": false
            },
            "warnings": [],
            "grace": serde_json::Value::Null
        }
    })
    .to_string()
}

/// The answer a service gives a principal whose allowance is spent.
fn exhausted_answer() -> String {
    serde_json::json!({
        "ok": true,
        "data": {
            "state": "exhausted",
            "payer": "installation:33333333-3333-3333-3333-333333333333",
            "message": "The relay allowance for this period is used up.",
            "alternatives": [
                "A direct connection between the devices, which needs no managed relay.",
                "A self-hosted relay configured in the service settings."
            ],
            "allowance": {
                "allowance": "10737418240",
                "used": "10737418240",
                "reserved": "0",
                "period": "2026-09",
                "exhausted": true
            },
            "warnings": [{ "threshold": 80, "raised_at": "2026-09-16T10:00:00.000Z" }],
            "grace": {
                "started_at": "2026-09-16T12:00:00.000Z",
                "ends_at": "2026-09-16T12:15:00.000Z",
                "remaining_ms": "600000",
                "remaining_bytes": "104857600"
            }
        }
    })
    .to_string()
}

#[tokio::test]
async fn the_credential_covers_the_canonical_body() {
    let http = Recorder::new(&granted_answer());
    let signer = Installation::new(ServiceRequestSigner::Installation);
    let service = ManagedRelayLeaseService::new(origin(), http.clone(), signer.clone());
    let request = issue_request();

    let answer = service.issue(&request).await.expect("a lease");
    assert!(answer.granted().is_some());

    let (url, sent) = http.last();
    assert_eq!(url, "https://reach.kala.to/api/relay/lease");
    assert!(
        http.last_headers().is_empty(),
        "a lease request sends no headers beside its credential"
    );

    // The body is what this client meant to send, in the representation the service reads.
    let body = &sent["body"];
    assert_eq!(body["direction"], "bidirectional");
    assert_eq!(body["byte_ceiling"], "4194304");
    assert_eq!(body["duration_seconds"], 300);
    assert_eq!(body["region_preference"], "eu-central");
    assert_eq!(body["payer"], "installation");
    assert!(body["lease_id"].is_null());

    // The credential names the five facts, and the digest is over the canonical body rather than
    // over the JSON that carried it.
    let payload = &sent["signature"]["payload"];
    assert_eq!(payload["gateway_origin"], "https://reach.kala.to");
    assert_eq!(payload["method"], "relay.lease.issue");
    assert_eq!(sent["signature"]["signer"], "installation");

    let canonical = RelayLeaseIssueBody::of(&request)
        .signing_input()
        .expect("canonical bytes");
    let digest = kr_cbor::sha256(&canonical);
    assert_eq!(
        payload["body_digest"],
        kr_protocol::scalars::to_base64url(&digest)
    );

    // And the signature verifies as the installation's, under the installation domain.
    let signature = payload_signature(&sent);
    let covered = SigningTranscript::from_canonical_bytes(
        ServiceRequestSigner::Installation.domain(),
        covered_bytes(&sent),
    )
    .expect("a domain-tagged transcript");
    verify(&signer.public_key(), &covered, &signature)
        .expect("the credential verifies under the key it presents");
}

#[tokio::test]
async fn the_signing_input_is_the_bytes_the_service_rebuilds() {
    let canonical = RelayLeaseIssueBody::of(&issue_request())
        .signing_input()
        .expect("canonical bytes");

    assert_eq!(hex(&canonical), LEASE_REQUEST_HEX);
    assert_eq!(hex(&kr_cbor::sha256(&canonical)), LEASE_REQUEST_SHA256);

    let revoke = RelayLeaseRevokeBody {
        lease_id: RelayLeaseId::new(Uuid::from_bytes([0x11; 16])),
        reason: LeaseEndReason::Finished,
    }
    .signing_input()
    .expect("canonical bytes");
    assert_eq!(hex(&revoke), LEASE_REVOKE_HEX);
    assert_eq!(hex(&kr_cbor::sha256(&revoke)), LEASE_REVOKE_SHA256);

    // The two domains are separate, so a body built for one method cannot be presented under the
    // other however the outer credential is labelled.
    assert_ne!(hex(&canonical), hex(&revoke));

    // And the credential itself, over a fixed payload, because the service rebuilds these bytes
    // from the five fields it received before it verifies anything.
    let credential = fixed_payload()
        .signing_input(ServiceRequestSigner::Installation)
        .expect("canonical bytes");
    let host = fixed_payload()
        .signing_input(ServiceRequestSigner::Host)
        .expect("canonical bytes");
    assert_eq!(hex(&credential), CREDENTIAL_HEX);
    assert_eq!(hex(&host), CREDENTIAL_HOST_HEX);
    assert_ne!(hex(&credential), hex(&host));
}

#[tokio::test]
async fn an_exhausted_allowance_is_an_answer_with_the_grace_left() {
    let http = Recorder::new(&exhausted_answer());
    let service = ManagedRelayLeaseService::new(
        origin(),
        http.clone(),
        Installation::new(ServiceRequestSigner::Installation),
    );

    let answer = service.issue(&issue_request()).await.expect("an answer");

    let refusal = match &answer {
        RelayLeaseAnswer::Exhausted(refusal) => refusal.clone(),
        other => panic!("an exhausted answer, not {other:?}"),
    };
    assert!(refusal.allowance.exhausted);
    assert_eq!(refusal.alternatives.len(), 2);
    assert_eq!(
        refusal.warnings.first().map(|warning| warning.threshold),
        Some(80)
    );

    // Section 17 requires the remaining interval to be visible before the relay closes, and this is
    // the request that is refused: the interval comes back with the refusal.
    let grace = answer.grace().expect("the grace remainder");
    assert_eq!(grace.remaining_ms.get(), 600_000);
    assert_eq!(grace.remaining_bytes.get(), 104_857_600);
    assert!(answer.granted().is_none());
}

/// KR-REQ-04.19: a lease answer that names one member twice is not an answer this client reads.
/// One reader would send traffic to the first relay and another to the second, and a lease may
/// have been issued whichever it was, so it is an unknown outcome and nothing retries it.
#[tokio::test]
async fn a_lease_answer_that_names_a_member_twice_is_an_unknown_outcome() {
    let answer = granted_answer();
    let once = r#""relay_url":"https://relay-1.reach.kala.to""#;
    let repeated = answer.replacen(
        once,
        r#""relay_url":"https://relay-1.reach.kala.to","relay_url":"https://relay-2.reach.kala.to""#,
        1,
    );
    assert_ne!(
        repeated, answer,
        "the answer names the relay once to begin with"
    );
    let http = Recorder::new(&repeated);
    let service = ManagedRelayLeaseService::new(
        origin(),
        http.clone(),
        Installation::new(ServiceRequestSigner::Installation),
    );

    let error = service
        .issue(&issue_request())
        .await
        .expect_err("a member named twice");
    assert_eq!(error.code(), ErrorCode::OutcomeUnknown);
    assert_eq!(error.code().retry_category(), RetryCategory::OutcomeUnknown);

    // The control: the same answer naming it once is a lease.
    http.answer_with(200, &answer);
    let answer = service.issue(&issue_request()).await.expect("a lease");
    assert!(answer.granted().is_some());
}

#[tokio::test]
async fn a_refusal_arrives_as_the_code_the_service_named() {
    let http = Recorder::new(&granted_answer());
    let service = ManagedRelayLeaseService::new(
        origin(),
        http.clone(),
        Installation::new(ServiceRequestSigner::Host),
    );

    http.answer_with(
        403,
        &serde_json::json!({
            "ok": false,
            "error": {
                "code": "FORBIDDEN",
                "message": "A host names the account it is spending."
            }
        })
        .to_string(),
    );

    let error = service
        .issue(&issue_request())
        .await
        .expect_err("a refusal");
    assert_eq!(error.code(), ErrorCode::PermissionDenied);
    // The code and the action are shared with a credential the service did not admit, so the
    // service's own code is what tells the two apart.
    assert_eq!(error.service_code(), Some("FORBIDDEN"));
    // A refusal the service named no delay for is still the service's own, rather than one that
    // reads as the host's.
    assert!(matches!(
        error,
        ClientError::Refused {
            retry_after_seconds: None,
            ..
        }
    ));
    // An account that is signed in and may not spend here is told to change a setting. Telling it
    // to sign in again would send somebody round a loop they are already through.
    assert_eq!(error.user_action(), UserAction::FixConfiguration);
    assert!(
        !error
            .decision(RequestClass::IdempotentRead)
            .retries_automatically()
    );

    // The same protocol code, from a service that would not admit the credential this device minted
    // for itself. Section 23's required set has one code for all of these, so the service carries
    // the difference itself, and this one is not a login: the origin, the method, the digest, the
    // clock or the nonce is what a person changes.
    http.answer_with(
        401,
        &serde_json::json!({
            "ok": false,
            "error": {
                "code": "UNAUTHENTICATED",
                "message": "That is not a signature this service can check."
            }
        })
        .to_string(),
    );
    let error = service
        .issue(&issue_request())
        .await
        .expect_err("a refusal");
    assert_eq!(error.code(), ErrorCode::PermissionDenied);
    assert_eq!(error.user_action(), UserAction::FixConfiguration);
    assert_eq!(error.service_code(), Some("UNAUTHENTICATED"));

    // And the one that is a login: an account session the service will not renew by itself.
    http.answer_with(
        401,
        &serde_json::json!({
            "ok": false,
            "error": {
                "code": "REAUTHENTICATION_REQUIRED",
                "message": "Sign in again to keep spending this account's allowance."
            }
        })
        .to_string(),
    );
    let error = service
        .issue(&issue_request())
        .await
        .expect_err("a refusal");
    assert_eq!(error.code(), ErrorCode::PermissionDenied);
    assert_eq!(error.user_action(), UserAction::SignIn);

    http.answer_with(
        501,
        &serde_json::json!({
            "ok": false,
            "error": { "code": "NOT_CONFIGURED", "message": "no admission key" }
        })
        .to_string(),
    );
    let error = service
        .issue(&issue_request())
        .await
        .expect_err("a refusal");
    assert_eq!(error.code(), ErrorCode::HostNotConfigured);

    // A rate limit carries the delay the service asked for, where a caller can act on it.
    http.answer_with(
        429,
        &serde_json::json!({
            "ok": false,
            "error": {
                "code": "RATE_LIMITED",
                "message": "Too many requests from this network.",
                "retryAfterSeconds": 42
            }
        })
        .to_string(),
    );
    let error = service
        .issue(&issue_request())
        .await
        .expect_err("a rate limit");
    assert_eq!(error.code(), ErrorCode::RateLimited);
    assert!(matches!(
        error,
        ClientError::Refused {
            retry_after_seconds: Some(42),
            ..
        }
    ));

    // An answer this client cannot read, after a request the service accepted. A lease may exist,
    // so the outcome is unknown rather than an argument the caller got wrong, and nothing retries
    // an unknown outcome on its own.
    http.answer_with(200, "{\"ok\":true,\"data\":{\"state\":\"something-else\"}}");
    let error = service
        .issue(&issue_request())
        .await
        .expect_err("an unreadable answer");
    assert_eq!(error.code(), ErrorCode::OutcomeUnknown);
    assert_eq!(error.code().retry_category(), RetryCategory::OutcomeUnknown);

    // A proxy's error page is not a refusal and not a caller's mistake: it is transient, because
    // asking again after it may well work. A 502 or 504 is a lost answer instead, tested below.
    http.answer_with(503, "<html><body>Service Unavailable</body></html>");
    let error = service
        .issue(&issue_request())
        .await
        .expect_err("a gateway fault");
    assert_eq!(error.code(), ErrorCode::UpstreamUnavailable);
    assert_eq!(error.code().retry_category(), RetryCategory::Transient);

    // And an answer from something that is not this service's routes at all is a configuration
    // between here and it, which no amount of retrying fixes.
    http.answer_with(404, "not found");
    let error = service
        .issue(&issue_request())
        .await
        .expect_err("a wrong origin");
    assert_eq!(error.code(), ErrorCode::HostNotConfigured);
}

/// KR-REQ-04.11: a lease answer that something in front of the service lost is an unknown outcome.
/// The service has the request, and may have issued and installed a lease, when a gateway answers
/// 502 or 504 with a page of its own, so nothing asks again by itself. The same holds for a
/// revocation. The service's own answer arrives in its envelope and is read by the code it names,
/// whatever the status, and a success this client cannot read stays an unknown outcome.
#[tokio::test]
async fn a_lease_answer_a_gateway_lost_is_an_unknown_outcome() {
    let http = Recorder::new(&granted_answer());
    let service = ManagedRelayLeaseService::new(
        origin(),
        http.clone(),
        Installation::new(ServiceRequestSigner::Installation),
    );

    for (status, page) in [
        (502, "<html><body>Bad Gateway</body></html>"),
        (504, "<html><body>Gateway Timeout</body></html>"),
    ] {
        http.answer_with(status, page);
        let error = service
            .issue(&issue_request())
            .await
            .expect_err("an answer the gateway lost");
        // The service received the request, so a lease may exist for the pair.
        let (url, sent) = http.last();
        assert_eq!(url, "https://reach.kala.to/api/relay/lease", "{status}");
        assert_eq!(sent["body"]["byte_ceiling"], "4194304", "{status}");
        assert_eq!(error.code(), ErrorCode::OutcomeUnknown, "{status}");
        assert_eq!(
            error.code().retry_category(),
            RetryCategory::OutcomeUnknown,
            "{status}"
        );
        assert!(
            !error
                .decision(RequestClass::IdempotentRead)
                .retries_automatically(),
            "{status}"
        );

        let error = service
            .revoke(
                RelayLeaseId::new(Uuid::from_bytes([0x11; 16])),
                LeaseEndReason::Finished,
            )
            .await
            .expect_err("an answer the gateway lost");
        assert_eq!(error.code(), ErrorCode::OutcomeUnknown, "{status}");
    }

    // The controls. A gateway status that carries the service's own envelope is not an answer the
    // gateway lost: it is the service's, read by the code it names.
    http.answer_with(
        502,
        &serde_json::json!({
            "ok": false,
            "error": { "code": "RATE_LIMITED", "message": "Too many requests from this network." }
        })
        .to_string(),
    );
    let error = service
        .issue(&issue_request())
        .await
        .expect_err("the service's own refusal");
    assert_eq!(error.code(), ErrorCode::RateLimited);
    assert_eq!(error.code().retry_category(), RetryCategory::Transient);

    // A success this client cannot read.
    http.answer_with(200, "not an envelope");
    let error = service
        .issue(&issue_request())
        .await
        .expect_err("an unreadable success");
    assert_eq!(error.code(), ErrorCode::OutcomeUnknown);
}

#[tokio::test]
async fn a_revocation_reports_what_the_reservation_settled() {
    let http = Recorder::new(
        &serde_json::json!({
            "ok": true,
            "data": {
                "lease_id": "11111111-1111-1111-1111-111111111111",
                "revision": "2",
                "relay": serde_json::Value::Null,
                "settlement": {
                    "reservation_id": "22222222-2222-2222-2222-222222222222",
                    "bytes_receipted": "1048576",
                    "bytes_settled": "1048576",
                    "basis": "receipts",
                    "settled_at": "2026-09-16T12:00:00.000Z"
                },
                "grace": serde_json::Value::Null
            }
        })
        .to_string(),
    );
    let service = ManagedRelayLeaseService::new(
        origin(),
        http.clone(),
        Installation::new(ServiceRequestSigner::Installation),
    );

    let lease_id = RelayLeaseId::new(Uuid::from_bytes([0x11; 16]));
    let ending = service
        .revoke(lease_id, LeaseEndReason::Unpaired)
        .await
        .expect("an ending");

    assert_eq!(ending.lease_id, lease_id);
    assert_eq!(ending.revision.get(), 2);
    let settlement = ending.settlement.as_ref().expect("the charge is settled");
    assert_eq!(settlement.basis, "receipts");
    assert_eq!(settlement.bytes_settled.get(), 1_048_576);

    let (url, sent) = http.last();
    assert_eq!(url, "https://reach.kala.to/api/relay/lease/revoke");
    assert!(
        http.last_headers().is_empty(),
        "a revocation sends no headers beside its credential"
    );
    assert_eq!(sent["body"]["reason"], "unpaired");
    assert_eq!(
        sent["body"]["lease_id"],
        "11111111-1111-1111-1111-111111111111"
    );
    assert_eq!(sent["signature"]["payload"]["method"], "relay.lease.revoke");
}

/// A revocation the relay confirmed, whose charge the service could not settle yet, answers with no
/// settlement. It is an ending all the same: the relay says the lease is revoked, and revoking again
/// answers with the settlement as it stands.
#[tokio::test]
async fn a_revocation_whose_charge_is_not_known_yet_ends_the_lease_without_a_settlement() {
    let http = Recorder::new(
        &serde_json::json!({
            "ok": true,
            "data": {
                "lease_id": "11111111-1111-1111-1111-111111111111",
                "revision": "2",
                "relay": {
                    "lease_id": "11111111-1111-1111-1111-111111111111",
                    "revision": "2",
                    "state": "revoked",
                    "bytes_consumed": "1048576",
                    "bytes_remaining": "0",
                    "grace_remaining_ms": serde_json::Value::Null
                },
                "settlement": serde_json::Value::Null,
                "grace": serde_json::Value::Null
            }
        })
        .to_string(),
    );
    let service = ManagedRelayLeaseService::new(
        origin(),
        http.clone(),
        Installation::new(ServiceRequestSigner::Installation),
    );

    let lease_id = RelayLeaseId::new(Uuid::from_bytes([0x11; 16]));
    let ending = service
        .revoke(lease_id, LeaseEndReason::Finished)
        .await
        .unwrap_or_else(|error| panic!("an ending, not {:?}: {error}", error.code()));

    assert_eq!(ending.lease_id, lease_id);
    assert_eq!(ending.revision.get(), 2);
    let relay = ending
        .relay
        .as_ref()
        .expect("the relay confirmed the revocation");
    assert_eq!(relay.state, RelayLeaseState::Revoked);
    assert!(
        !ending.settlement.is_present(),
        "the charge is not known yet"
    );
}

/// KR-REQ-04.11: the service's own failure while it handled a lease request leaves the request's
/// outcome unknown, because the service can fail after it reserved bytes and installed a lease. So
/// nothing asks again by itself, and a caller finds out by sending the same request again. A
/// revocation that failed the same way stays transient, because a repeated revocation finishes
/// whatever the first did not.
#[tokio::test]
async fn the_services_own_failure_of_a_lease_request_leaves_its_outcome_unknown() {
    let http = Recorder::new(&granted_answer());
    let service = ManagedRelayLeaseService::new(
        origin(),
        http.clone(),
        Installation::new(ServiceRequestSigner::Installation),
    );
    http.answer_with(
        500,
        &serde_json::json!({
            "ok": false,
            "error": { "code": "INTERNAL", "message": "The request could not be completed." }
        })
        .to_string(),
    );

    let error = service
        .issue(&issue_request())
        .await
        .expect_err("the service's own failure");
    let (url, _) = http.last();
    assert_eq!(url, "https://reach.kala.to/api/relay/lease");
    assert_eq!(error.code(), ErrorCode::OutcomeUnknown);
    assert_eq!(error.code().retry_category(), RetryCategory::OutcomeUnknown);
    assert_eq!(error.user_action(), UserAction::CheckTheOutcome);
    assert!(
        !error
            .decision(RequestClass::IdempotentRead)
            .retries_automatically()
    );

    // The control: a revocation is asked again as it was, so its failure is one to wait out.
    let error = service
        .revoke(
            RelayLeaseId::new(Uuid::from_bytes([0x11; 16])),
            LeaseEndReason::Finished,
        )
        .await
        .expect_err("the service's own failure");
    assert_eq!(error.code(), ErrorCode::UpstreamUnavailable);
    assert_eq!(error.code().retry_category(), RetryCategory::Transient);
    assert_eq!(error.user_action(), UserAction::Wait);
}

#[tokio::test]
async fn an_account_payer_names_the_authorisation_that_made_it_one() {
    let http = Recorder::new(&granted_answer());
    let service = ManagedRelayLeaseService::new(
        origin(),
        http.clone(),
        Installation::new(ServiceRequestSigner::Installation),
    );

    let mut request = issue_request();
    request.payer = Some(LeasePayer::Account {
        account_id: "acct-7".to_owned(),
        authorisation_id: "55555555-5555-5555-5555-555555555555".to_owned(),
    });

    service.issue(&request).await.expect("a lease");

    let (_, sent) = http.last();
    assert_eq!(sent["body"]["payer"]["account"]["account_id"], "acct-7");
    assert_eq!(
        sent["body"]["payer"]["account"]["authorisation_id"],
        "55555555-5555-5555-5555-555555555555"
    );
}

/// One credential payload with nothing about it left to the clock.
fn fixed_payload() -> kr_client::services::relay::RelayRequestPayload {
    kr_client::services::relay::RelayRequestPayload {
        body_digest: kr_protocol::scalars::Digest256::from_bytes([0x5a; 32]),
        gateway_origin: origin(),
        method: "relay.lease.issue".to_owned(),
        nonce: kr_protocol::scalars::Nonce256::from_bytes([0x3c; 32]),
        signed_at_ms: kr_protocol::scalars::TimestampMs::new(1_800_000_000_000),
    }
}

/// The signature the credential presented.
fn payload_signature(sent: &serde_json::Value) -> Signature64 {
    let text = sent["signature"]["signature"]
        .as_str()
        .expect("a signature");
    let bytes = kr_protocol::scalars::from_base64url(text).expect("base64url");
    Signature64::from_bytes(<[u8; 64]>::try_from(bytes.as_slice()).expect("64 bytes"))
}

/// The bytes the credential covered, rebuilt from what was sent.
fn covered_bytes(sent: &serde_json::Value) -> Vec<u8> {
    rebuilt_payload(&sent["signature"]["payload"])
        .signing_input(ServiceRequestSigner::Installation)
        .expect("canonical bytes")
}

/// The payload a credential carried, rebuilt from what was sent.
fn rebuilt_payload(payload: &serde_json::Value) -> kr_client::services::relay::RelayRequestPayload {
    let digest =
        kr_protocol::scalars::from_base64url(payload["body_digest"].as_str().expect("a digest"))
            .expect("base64url");
    let nonce = kr_protocol::scalars::from_base64url(payload["nonce"].as_str().expect("a nonce"))
        .expect("base64url");

    kr_client::services::relay::RelayRequestPayload {
        body_digest: kr_protocol::scalars::Digest256::from_bytes(
            <[u8; 32]>::try_from(digest.as_slice()).expect("32 bytes"),
        ),
        gateway_origin: origin(),
        method: payload["method"].as_str().expect("a method").to_owned(),
        nonce: kr_protocol::scalars::Nonce256::from_bytes(
            <[u8; 32]>::try_from(nonce.as_slice()).expect("32 bytes"),
        ),
        signed_at_ms: kr_protocol::scalars::TimestampMs::new(
            payload["signed_at_ms"]
                .as_str()
                .expect("a time")
                .parse()
                .expect("a counter"),
        ),
    }
}

#[tokio::test]
async fn a_client_with_no_relay_service_says_so() {
    use kr_client::services::NullService;

    let error = NullService
        .issue(&issue_request())
        .await
        .expect_err("nothing is configured");
    assert_eq!(error.code(), ErrorCode::HostNotConfigured);
    assert!(matches!(error, ClientError::ServiceNotConfigured(what) if what == "relay leases"));
}

/// The authorisation a payer sign-in is answered with, in the shape the route serves.
fn signed_in_answer(valid_until: &str) -> String {
    serde_json::json!({
        "ok": true,
        "data": {
            "authorisation": {
                "authorisation_id": "55555555-5555-5555-5555-555555555555",
                "account_id": ACCOUNT,
                "subject_kind": "host",
                "subject": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
                "byte_ceiling": "8388608",
                "valid_from": "2026-10-17T10:00:00.000Z",
                "valid_until": valid_until,
                "selected_at": "2026-10-17T10:00:00.000Z",
                "withdrawn_at": null
            }
        }
    })
    .to_string()
}

/// The account a payer sign-in names.
const ACCOUNT: &str = "3f2b8c1e-5d4a-4e6f-9a7b-1c2d3e4f5a6b";

/// A host that is signed in asks the relay service to make its account the payer. The request is
/// proven twice: by the host's credential over the canonical body, and by the bearer token of the
/// sign-in. The answer is the authorisation, and a lease request names it as its payer.
#[tokio::test]
async fn a_payer_sign_in_presents_the_credential_and_the_account_token() {
    let http = Recorder::new(&signed_in_answer("2026-10-17T11:00:00.000Z"));
    let signer = Installation::new(ServiceRequestSigner::Host);
    let service = ManagedRelayLeaseService::new(origin(), http.clone(), signer.clone());
    let token = AccountToken::new("the-access-token").expect("a token");

    let authorisation = service
        .sign_in_payer(ACCOUNT, &token)
        .await
        .expect("an authorisation");

    let (url, sent) = http.last();
    assert_eq!(
        url,
        "https://reach.kala.to/api/relay/payer-authorisation/sign-in"
    );
    assert_eq!(
        http.last_headers(),
        vec![(
            "authorization".to_owned(),
            "Bearer the-access-token".to_owned()
        )]
    );
    assert_eq!(sent["body"], serde_json::json!({ "account_id": ACCOUNT }));
    let payload = &sent["signature"]["payload"];
    assert_eq!(payload["method"], "relay.payer.sign_in");
    assert_eq!(sent["signature"]["signer"], "host");
    let canonical = RelayPayerSignInBody {
        account_id: ACCOUNT.to_owned(),
    }
    .signing_input()
    .expect("canonical bytes");
    assert_eq!(
        payload["body_digest"],
        kr_protocol::scalars::to_base64url(&kr_cbor::sha256(&canonical))
    );
    let covered = SigningTranscript::from_canonical_bytes(
        ServiceRequestSigner::Host.domain(),
        rebuilt_payload(payload)
            .signing_input(ServiceRequestSigner::Host)
            .expect("canonical bytes"),
    )
    .expect("a domain-tagged transcript");
    verify(&signer.public_key(), &covered, &payload_signature(&sent))
        .expect("the credential verifies under the host's key");

    assert_eq!(
        authorisation.valid_until_ms(),
        Some(1_792_234_800_000),
        "the end of the authorisation, on the service's clock"
    );
    assert!(
        authorisation.payer()
            == LeasePayer::Account {
                account_id: ACCOUNT.to_owned(),
                authorisation_id: "55555555-5555-5555-5555-555555555555".to_owned(),
            },
        "a lease request names the account and the authorisation the sign-in opened"
    );
}

/// The payer sign-in's body is the bytes the service rebuilds, held to the vector both sides pin.
#[test]
fn the_payer_sign_in_body_is_the_bytes_the_service_rebuilds() {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("../../../fixtures/relay/requests.json"))
            .expect("the vectors");
    let case = fixture["cases"]
        .as_array()
        .and_then(|cases| cases.iter().find(|case| case["id"] == "payer_sign_in"))
        .expect("the payer sign-in vector");
    let body = RelayPayerSignInBody {
        account_id: case["json"]["account_id"]
            .as_str()
            .expect("an account")
            .to_owned(),
    };
    let canonical = body.signing_input().expect("canonical bytes");
    assert_eq!(hex(&canonical), case["cbor_hex"].as_str().expect("bytes"));
    assert_eq!(
        hex(&kr_cbor::sha256(&canonical)),
        case["sha256"].as_str().expect("a digest")
    );
}

/// A sign-in only the person can mend is the service's `REAUTHENTICATION_REQUIRED`, which this
/// client reports as a sign-in to make and names, so a caller can take a fresh token once before it
/// asks the person. The service's own failure is safe to ask again: a repeat under the same sign-in
/// reads the same authorisation, so it is a transient fault and not an unknown outcome.
#[tokio::test]
async fn a_payer_sign_in_the_service_turns_back_says_what_to_do() {
    let http = Recorder::new(&signed_in_answer("2026-10-17T11:00:00.000Z"));
    let service = ManagedRelayLeaseService::new(
        origin(),
        http.clone(),
        Installation::new(ServiceRequestSigner::Host),
    );
    let token = AccountToken::new("the-access-token").expect("a token");

    http.answer_with(
        401,
        r#"{"ok":false,"error":{"code":"REAUTHENTICATION_REQUIRED","message":"Sign this device in again."}}"#,
    );
    let error = service
        .sign_in_payer(ACCOUNT, &token)
        .await
        .expect_err("the person has to sign in");
    assert_eq!(error.service_code(), Some("REAUTHENTICATION_REQUIRED"));
    assert_eq!(error.user_action(), UserAction::SignIn);

    http.answer_with(
        500,
        r#"{"ok":false,"error":{"code":"INTERNAL","message":"Try again."}}"#,
    );
    let error = service
        .sign_in_payer(ACCOUNT, &token)
        .await
        .expect_err("the service failed");
    assert_eq!(error.code(), ErrorCode::UpstreamUnavailable);
    assert_eq!(error.user_action(), UserAction::Wait);
}
