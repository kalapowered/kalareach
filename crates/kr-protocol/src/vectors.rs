//! The cross-language vectors under `fixtures/service/` and `fixtures/push/`.
//!
//! Every value here is built from the types in this crate and a fixed set of test bytes, so the
//! documents are byte stable and the TypeScript package can assert the same encodings. Rust is
//! canonical: a change to a type changes these documents, and `kr-protocol-gen --check` fails until
//! the committed vectors are regenerated.
//!
//! Each case publishes four things about one record: the JSON representation a managed service
//! carries, the canonical KR-CBOR-1 bytes its signature or digest covers, the SHA-256 of those
//! bytes, and the same value written in the description grammar `fixtures/cbor` uses. A consumer
//! that can produce the bytes from the JSON has implemented the contract; one that only matches the
//! digest has not.
//!
//! The signatures in the JSON are fixed test bytes rather than verifiable signatures. Signature
//! vectors need a signing implementation and live with the cryptography fixtures.

use kr_cbor::CanonicalValue;
use serde::Serialize;
use serde_json::{Value, json};

use crate::ids::{
    CollapseId, EnvelopeId, NotificationId, PushRegistrationId, PushSenderRecordId,
    PushSenderRevision,
};
use crate::mailbox::{
    EnvelopeRouting, SEAL_OVERHEAD_BYTES, SealedEnvelope, notification_size_bucket,
};
use crate::method::Method;
use crate::push::{
    DELIVERY_CREDENTIAL_LIFETIME_MS, FREE_PUSH_BURST, FREE_PUSH_PER_HOUR,
    MAX_PREVIEW_PLAINTEXT_BYTES, MAX_PROVIDER_PAYLOAD_BYTES, PUSH_COLLAPSE_WINDOW_MS, PushAlert,
    PushDeliveryRequest, PushInstallationBinding, PushPlatform, PushPlatformHints, PushRatePolicy,
    PushRegistrationAnswer, PushRegistrationChallenge, PushRegistrationProposal,
    PushRegistrationRequest, PushRequest, PushRevocationReason, PushSenderBinding,
    PushSenderIssueRequest, PushSenderRecord, PushSenderRenewRequest, PushSenderRenewal,
    PushSenderRenewalPayload, PushSenderRevocation, PushSenderRevocationPayload,
    PushSenderRevokeRequest, PushSenderState, PushTokenState, REGISTRATION_CHALLENGE_LIFETIME_MS,
    RegistrationToken, SENDER_RENEWAL_WINDOW_MS, token_digest,
};
use crate::scalars::{
    AuthorisationKey, Bytes, EndpointKey, KeyId, Nonce192, Nonce256, Nullable, SecretBytes32,
    Signature64, TimestampMs, U64, Uuid,
};
use crate::service::{
    GatewayOrigin, SERVICE_REQUEST_FRESHNESS_MS, ServiceRequestPayload, ServiceRequestSignature,
    ServiceRequestSigner, body_digest, installation_id,
};

/// The service-request credential vectors.
pub const SERVICE_REQUESTS_FILE_NAME: &str = "requests.json";

/// The push registration, authorisation and delivery vectors.
pub const PUSH_FILE_NAME: &str = "push.json";

/// The test installation key. Test material: nothing signs with its private half.
const INSTALLATION_KEY: [u8; 32] = [0x11; 32];
/// The test host signing key.
const HOST_SIGNING_KEY: [u8; 32] = [0x22; 32];
/// The test host endpoint key.
const HOST_ENDPOINT_KEY: [u8; 32] = [0x33; 32];
/// The test registration token, as a provider would issue one.
const REGISTRATION_TOKEN: &str = "fZ9k-test-registration-token:APA91bExample";
/// A fixed instant, 2026-01-01T00:00:00Z in UTC milliseconds.
const NOW_MS: u64 = 1_767_225_600_000;

/// Origins a gateway accepts. Both languages must accept every one.
const ACCEPTED_ORIGINS: &[&str] = &[
    "https://reach.kala.to",
    "https://reach.kala.to:8443",
    "https://ns1.reach.kala.to",
    "https://192.0.2.10",
    "https://[2001:db8::1]",
    "https://[2001:db8::1]:8443",
    "http://localhost",
    "http://localhost:8787",
    "http://127.0.0.1:8787",
    "http://[::1]:8787",
];

/// Origins a gateway refuses. Both languages must refuse every one.
const REFUSED_ORIGINS: &[&str] = &[
    "https://reach.kala.to/",
    "https://reach.kala.to/api",
    "https://reach.kala.to?x=1",
    "https://reach.kala.to#x",
    "https://REACH.kala.to",
    "https://user@reach.kala.to",
    "https://reach.kala.to:443",
    "https://reach.kala.to:08443",
    "https://reach.kala.to:0",
    "https://reach.kala.to:99999",
    "https://reach.kala.to:http",
    "https://reach.kala.to.",
    "https://reach..kala.to",
    "https://-reach.kala.to",
    "https://reach.kala.to-",
    "https://192.0.2.001",
    "https://0xc0000201",
    "https://2001:db8::1",
    "https://[2001:0db8::1]",
    "https://[0:0:0:0:0:0:0:1]",
    "https://[::ffff:192.0.2.1]",
    "https://[::1]junk",
    "https://[2001:db8::1",
    "https://[:::]",
    "https://",
    "http://reach.kala.to",
    "http://[2001:db8::1]",
    "http://localhost:80",
    "reach.kala.to",
    "ftp://reach.kala.to",
];

fn origin() -> GatewayOrigin {
    GatewayOrigin::new("https://reach.kala.to").expect("the production gateway origin")
}

fn sender_record_id() -> PushSenderRecordId {
    PushSenderRecordId::new(Uuid::from_bytes([
        0x5b, 0x1f, 0x2c, 0x8d, 0x41, 0x6a, 0x47, 0x0e, 0x9c, 0x3d, 0x0a, 0x7e, 0x55, 0x12, 0x88,
        0xb4,
    ]))
}

fn registration_id() -> PushRegistrationId {
    PushRegistrationId::new(Uuid::from_bytes([
        0x2e, 0x74, 0x9a, 0x03, 0xc1, 0x58, 0x4d, 0x62, 0xa0, 0x19, 0x6f, 0x3b, 0xd7, 0x84, 0x21,
        0x5c,
    ]))
}

/// Returns every generated vector file as a name and its exact contents.
///
/// # Panics
///
/// Panics when a document cannot be built, which would mean a type in this crate cannot be
/// represented in KR-CBOR-1 rather than a runtime condition.
#[must_use]
pub fn generated_files() -> Vec<(&'static str, String)> {
    vec![
        (SERVICE_REQUESTS_FILE_NAME, render(&service_requests())),
        (PUSH_FILE_NAME, render(&push())),
    ]
}

fn render(value: &Value) -> String {
    let mut text = serde_json::to_string_pretty(value).expect("generated JSON is serialisable");
    text.push('\n');
    text
}

/// Writes the description grammar `fixtures/cbor` uses for one canonical value.
fn describe(value: &CanonicalValue) -> Value {
    match value {
        CanonicalValue::Integer(integer) => json!({ "int": integer.get().to_string() }),
        CanonicalValue::Bytes(bytes) => json!({ "bytes": hex(bytes) }),
        CanonicalValue::Text(text) => json!({ "text": text }),
        CanonicalValue::Bool(value) => json!({ "bool": value }),
        CanonicalValue::Null => json!({ "null": Value::Null }),
        CanonicalValue::Array(items) => {
            json!({ "array": items.iter().map(describe).collect::<Vec<_>>() })
        }
        CanonicalValue::Map(map) => json!({
            "map": map
                .entries()
                .iter()
                .map(|(key, entry)| json!([key, describe(entry)]))
                .collect::<Vec<_>>()
        }),
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push_str(&format!("{byte:02x}"));
    }
    text
}

/// One case: the record, the bytes its signature or digest covers, and the digest.
fn case<T: Serialize + ?Sized>(
    id: &str,
    description: &str,
    domain: &str,
    record: &T,
    signed: &[u8],
) -> Value {
    let value = kr_cbor::decode(signed, &kr_cbor::Limits::default())
        .expect("the signing input is valid KR-CBOR-1");
    json!({
        "cbor_hex": hex(signed),
        "description": description,
        "domain": domain,
        "id": id,
        "json": serde_json::to_value(record).expect("the record is serialisable"),
        "sha256": hex(&kr_cbor::sha256(signed)),
        "value": describe(&value),
    })
}

fn note() -> &'static str {
    "Values use the same description grammar as fixtures/cbor. cbor_hex is the canonical KR-CBOR-1 \
     encoding of CBOR([domain, payload]), the bytes a signature or a digest covers; sha256 is its \
     digest. json is the managed HTTP representation of the whole record, signature included. The \
     signatures and secrets in json are fixed test bytes, not verifiable material: signature \
     vectors need a signing implementation and live with the cryptography fixtures."
}

/// The vectors for the credential every managed-service method authenticates with.
fn service_requests() -> Value {
    let key = AuthorisationKey::from_bytes(INSTALLATION_KEY);
    let host_key = AuthorisationKey::from_bytes(HOST_SIGNING_KEY);

    let installation_payload = ServiceRequestPayload {
        body_digest: body_digest(b"{\"platform\":\"ios\"}"),
        gateway_origin: origin(),
        method: Method::PushInstallationRegister,
        nonce: Nonce256::from_bytes([0x41; 32]),
        signed_at_ms: TimestampMs::new(NOW_MS),
    };
    let installation = ServiceRequestSignature {
        payload: installation_payload.clone(),
        signer: ServiceRequestSigner::Installation,
        public_key: key,
        signature: Signature64::from_bytes([0x5a; 64]),
    };

    let host_payload = ServiceRequestPayload {
        body_digest: body_digest(b"{\"sender_record_id\":\"renew\"}"),
        gateway_origin: origin(),
        method: Method::PushSenderRenew,
        nonce: Nonce256::from_bytes([0x42; 32]),
        signed_at_ms: TimestampMs::new(NOW_MS),
    };
    let host = ServiceRequestSignature {
        payload: host_payload.clone(),
        signer: ServiceRequestSigner::Host,
        public_key: host_key,
        signature: Signature64::from_bytes([0x5b; 64]),
    };

    // The same payload under the other domain. It proves the separation is in the bytes rather
    // than in the label beside them: one signature can never serve as the other.
    let crossed = installation_payload
        .signing_input(ServiceRequestSigner::Host)
        .expect("a host signing input");

    json!({
        "name": "requests",
        "description": "The installation credential every managed-service method authenticates with: the exact bytes each signature covers.",
        "note": note(),
        "freshness_ms": SERVICE_REQUEST_FRESHNESS_MS.to_string(),
        "installation_identity": {
            "public_key": serde_json::to_value(key).expect("a key"),
            "installation_id": installation_id(&key).to_string(),
            "derivation": "The first sixteen bytes of the SHA-256 of the device authorisation public key, written in hyphenated form."
        },
        "origins": {
            "description": "Every origin a gateway accepts, and every spelling it refuses. One address has one spelling, because two spellings of one service are two signing inputs for one request.",
            "accepted": ACCEPTED_ORIGINS,
            "refused": REFUSED_ORIGINS
        },
        "cases": [
            case(
                "installation_request",
                "A native installation registering a push token, signed by its device authorisation key.",
                crate::service::SERVICE_REQUEST_DOMAIN,
                &installation,
                &installation
                    .signing_input()
                    .expect("an installation signing input"),
            ),
            case(
                "host_request",
                "A paired host renewing its delivery credential, signed by its host signing key.",
                crate::service::SERVICE_REQUEST_HOST_DOMAIN,
                &host,
                &host.signing_input().expect("a host signing input"),
            ),
            json!({
                "id": "same_payload_other_domain",
                "description": "The installation payload above, encoded under the host domain. The bytes differ, so an installation's signature can never be presented as a host's.",
                "domain": crate::service::SERVICE_REQUEST_HOST_DOMAIN,
                "cbor_hex": hex(&crossed),
                "sha256": hex(&kr_cbor::sha256(&crossed)),
                "value": describe(
                    &kr_cbor::decode(&crossed, &kr_cbor::Limits::default())
                        .expect("valid KR-CBOR-1")
                ),
            }),
        ],
    })
}

/// The vectors for push registration, sender authorisation and delivery.
fn push() -> Value {
    let key = AuthorisationKey::from_bytes(INSTALLATION_KEY);
    let installation = installation_id(&key);
    let token = RegistrationToken::new(REGISTRATION_TOKEN).expect("a registration token");
    let digest = token_digest(&token);

    let challenge = PushRegistrationChallenge {
        challenge: Nonce256::from_bytes([0x61; 32]),
        expires_at_ms: TimestampMs::new(NOW_MS + REGISTRATION_CHALLENGE_LIFETIME_MS),
        gateway_origin: origin(),
        installation_id: installation,
        platform: PushPlatform::Ios,
        registration_id: registration_id(),
        token_digest: digest,
    };
    let answer = PushRegistrationAnswer {
        payload: challenge.expected_answer(),
        installation_key: key,
        signature: Signature64::from_bytes([0x5c; 64]),
    };

    let binding = PushInstallationBinding {
        bound_at_ms: TimestampMs::new(NOW_MS + 1_200),
        gateway_origin: origin(),
        installation_id: installation,
        installation_key: key,
        platform: PushPlatform::Ios,
        registration_id: registration_id(),
        state: PushTokenState::Active,
        token_digest: digest,
    };

    let sender_binding = PushSenderBinding {
        gateway_origin: origin(),
        host_endpoint_key: EndpointKey::from_bytes(HOST_ENDPOINT_KEY),
        host_signing_key: AuthorisationKey::from_bytes(HOST_SIGNING_KEY),
        installation_id: installation,
        rate_policy: PushRatePolicy::FREE,
        sender_record_id: sender_record_id(),
    };
    let record = PushSenderRecord {
        binding: sender_binding.clone(),
        credential_expires_at_ms: TimestampMs::new(NOW_MS + DELIVERY_CREDENTIAL_LIFETIME_MS),
        issued_at_ms: TimestampMs::new(NOW_MS),
        revision: PushSenderRevision::new(1),
        state: PushSenderState::Active,
    };
    let credential = crate::push::PushDeliveryCredential {
        expires_at_ms: TimestampMs::new(NOW_MS + DELIVERY_CREDENTIAL_LIFETIME_MS),
        gateway_origin: origin(),
        installation_id: installation,
        issued_at_ms: TimestampMs::new(NOW_MS),
        revision: PushSenderRevision::new(1),
        secret: SecretBytes32::from_bytes([0x77; 32]),
        sender_record_id: sender_record_id(),
    };

    let renewal = PushSenderRenewal {
        payload: PushSenderRenewalPayload {
            gateway_origin: origin(),
            gateway_nonce: Nonce256::from_bytes([0x71; 32]),
            requested_at_ms: TimestampMs::new(
                NOW_MS + DELIVERY_CREDENTIAL_LIFETIME_MS - SENDER_RENEWAL_WINDOW_MS,
            ),
            sender_record_id: sender_record_id(),
        },
        signature: Signature64::from_bytes([0x5d; 64]),
    };
    let revocation = PushSenderRevocation {
        payload: PushSenderRevocationPayload {
            gateway_origin: origin(),
            gateway_nonce: Nonce256::from_bytes([0x72; 32]),
            reason: PushRevocationReason::Unpaired,
            requested_at_ms: TimestampMs::new(NOW_MS + 86_400_000),
            sender_record_id: sender_record_id(),
        },
        signature: Signature64::from_bytes([0x5e; 64]),
    };

    let expires_at_ms = TimestampMs::new(NOW_MS + 900_000);
    let bucket = notification_size_bucket(600);
    let preview = SealedEnvelope {
        routing: EnvelopeRouting {
            envelope_id: EnvelopeId::new(Uuid::from_bytes([0x8a; 16])),
            recipient_key_id: KeyId::from_bytes([0x91; 32]),
            sender_key_id: KeyId::from_bytes([0x92; 32]),
            expires_at_ms,
            size_bucket_bytes: U64::new(bucket),
        },
        nonce: Nonce192::from_bytes([0x93; 24]),
        ciphertext: Bytes::new(vec![
            0xab;
            usize::try_from(bucket + SEAL_OVERHEAD_BYTES)
                .expect("a notification bucket fits in memory")
        ]),
    };
    let delivery = PushDeliveryRequest {
        collapse_id: CollapseId::new(Uuid::from_bytes([
            0xc8, 0xb1, 0xf0, 0xa4, 0x1d, 0x27, 0x4e, 0x53, 0x8b, 0x6f, 0x02, 0x9a, 0x77, 0x45,
            0xd1, 0x30,
        ])),
        expires_at_ms,
        hints: PushPlatformHints {
            alert: PushAlert::ApprovalWaiting,
            urgency: crate::push::PushUrgency::Attention,
        },
        notification_id: NotificationId::new(Uuid::from_bytes([
            0x0f, 0x3a, 0x9c, 0x7e, 0x51, 0xd2, 0x4b, 0x08, 0xa6, 0x14, 0x3e, 0x85, 0xcb, 0x60,
            0x9f, 0x22,
        ])),
        preview: Nullable::some(preview),
        sender_record_id: sender_record_id(),
    };
    let without_preview = PushDeliveryRequest {
        preview: Nullable::null(),
        ..delivery.clone()
    };

    let propose = PushRequest::InstallationRegister {
        request: PushRegistrationRequest::Propose {
            proposal: PushRegistrationProposal {
                installation_key: key,
                platform: PushPlatform::Ios,
                registration_id: registration_id(),
                registration_token: token.clone(),
            },
        },
    };
    let answer_body = PushRequest::InstallationRegister {
        request: PushRegistrationRequest::Answer {
            answer: answer.clone(),
        },
    };
    let issue_body = PushRequest::SenderIssue {
        request: PushSenderIssueRequest {
            host_endpoint_key: EndpointKey::from_bytes(HOST_ENDPOINT_KEY),
            host_signing_key: AuthorisationKey::from_bytes(HOST_SIGNING_KEY),
            sender_record_id: sender_record_id(),
        },
    };
    let renew_body = PushRequest::SenderRenew {
        request: PushSenderRenewRequest::Complete {
            renewal: renewal.clone(),
        },
    };
    let revoke_body = PushRequest::SenderRevoke {
        request: PushSenderRevokeRequest::Complete {
            revocation: revocation.clone(),
        },
    };

    let signed_propose = ServiceRequestSignature {
        payload: ServiceRequestPayload {
            body_digest: propose.digest().expect("a body digest"),
            gateway_origin: origin(),
            method: propose.method(),
            nonce: Nonce256::from_bytes([0x43; 32]),
            signed_at_ms: TimestampMs::new(NOW_MS),
        },
        signer: propose.signer(),
        public_key: key,
        signature: Signature64::from_bytes([0x5f; 64]),
    };
    let signed_renew = ServiceRequestSignature {
        payload: ServiceRequestPayload {
            body_digest: renew_body.digest().expect("a body digest"),
            gateway_origin: origin(),
            method: renew_body.method(),
            nonce: Nonce256::from_bytes([0x44; 32]),
            signed_at_ms: TimestampMs::new(NOW_MS + 86_400_000),
        },
        signer: renew_body.signer(),
        public_key: AuthorisationKey::from_bytes(HOST_SIGNING_KEY),
        signature: Signature64::from_bytes([0x60; 64]),
    };

    json!({
        "name": "push",
        "description": "Push registration, sender authorisation and delivery: the exact bytes each signature and digest covers.",
        "note": note(),
        "limits": {
            "registration_challenge_lifetime_ms": REGISTRATION_CHALLENGE_LIFETIME_MS.to_string(),
            "delivery_credential_lifetime_ms": DELIVERY_CREDENTIAL_LIFETIME_MS.to_string(),
            "sender_renewal_window_ms": SENDER_RENEWAL_WINDOW_MS.to_string(),
            "max_preview_plaintext_bytes": MAX_PREVIEW_PLAINTEXT_BYTES.to_string(),
            "max_provider_payload_bytes": MAX_PROVIDER_PAYLOAD_BYTES.to_string(),
            "free_burst": FREE_PUSH_BURST.to_string(),
            "free_per_hour": FREE_PUSH_PER_HOUR.to_string(),
            "collapse_window_ms": PUSH_COLLAPSE_WINDOW_MS.to_string()
        },
        "token": {
            "platform": PushPlatform::Ios.as_str(),
            "registration_token": REGISTRATION_TOKEN,
            "token_digest": serde_json::to_value(digest).expect("a digest"),
            "derivation": "SHA-256 of CBOR([\"kr-push-token/1\", token]). The platform is not in it: receiving the challenge proves the token reaches this device and nothing about the label beside it, so a digest that included the label would let one device hold two destinations."
        },
        "request_methods": [
            { "body": "body_registration_propose", "method": propose.method().as_str(), "signer": propose.signer().as_str() },
            { "body": "body_registration_answer", "method": answer_body.method().as_str(), "signer": answer_body.signer().as_str() },
            { "body": "body_sender_issue", "method": issue_body.method().as_str(), "signer": issue_body.signer().as_str() },
            { "body": "body_sender_renew", "method": renew_body.method().as_str(), "signer": renew_body.signer().as_str() },
            { "body": "body_sender_revoke", "method": revoke_body.method().as_str(), "signer": revoke_body.signer().as_str() }
        ],
        "alerts": PushAlert::ALL
            .iter()
            .map(|alert| json!({ "alert": alert.as_str(), "text": alert.generic_text() }))
            .collect::<Vec<_>>(),
        "records": {
            "installation_binding": serde_json::to_value(&binding).expect("a binding"),
            "sender_record": serde_json::to_value(&record).expect("a record"),
            "delivery_credential": serde_json::to_value(&credential).expect("a credential"),
            "credential_digest": serde_json::to_value(credential.secret_digest()).expect("a digest")
        },
        "cases": [
            case(
                "registration_answer",
                "The answer a receiver returns for the challenge sent to its token, signed by the proposed installation key.",
                crate::push::PUSH_REGISTRATION_ANSWER_DOMAIN,
                &answer,
                &answer.payload.signing_input().expect("an answer signing input"),
            ),
            case(
                "sender_binding",
                "What one sender authorisation fixes for its lifetime. A renewal that changes any of it produces a different digest.",
                crate::push::PUSH_SENDER_BINDING_DOMAIN,
                &sender_binding,
                &sender_binding.signing_input().expect("a binding signing input"),
            ),
            case(
                "sender_renewal",
                "A host proving it still holds the key the installation named, over a nonce the gateway issued.",
                crate::push::PUSH_SENDER_RENEWAL_DOMAIN,
                &renewal,
                &renewal.payload.signing_input().expect("a renewal signing input"),
            ),
            case(
                "sender_revocation",
                "A host ending an authorisation after unpairing. A revoked record never renews.",
                crate::push::PUSH_SENDER_REVOCATION_DOMAIN,
                &revocation,
                &revocation.payload.signing_input().expect("a revocation signing input"),
            ),
            case(
                "delivery_request",
                "One notification with a sealed preview. The digest is how the gateway recognises a request it has already handled.",
                crate::push::PUSH_DELIVERY_DOMAIN,
                &delivery,
                &delivery.signing_input().expect("a delivery signing input"),
            ),
            case(
                "delivery_request_without_preview",
                "The same notification with previews disabled on the device. The generic alert still reaches the lock screen.",
                crate::push::PUSH_DELIVERY_DOMAIN,
                &without_preview,
                &without_preview.signing_input().expect("a delivery signing input"),
            ),
            case(
                "body_registration_propose",
                "The body of the request that proposes a token. The service-request signature covers its digest.",
                crate::push::PUSH_REQUEST_DOMAIN,
                &propose,
                &propose.signing_input().expect("a body signing input"),
            ),
            case(
                "body_registration_answer",
                "The body of the request that presents the answered challenge.",
                crate::push::PUSH_REQUEST_DOMAIN,
                &answer_body,
                &answer_body.signing_input().expect("a body signing input"),
            ),
            case(
                "body_sender_issue",
                "The body of the request that authorises one paired host.",
                crate::push::PUSH_REQUEST_DOMAIN,
                &issue_body,
                &issue_body.signing_input().expect("a body signing input"),
            ),
            case(
                "body_sender_renew",
                "The body of the request that presents a renewal proof.",
                crate::push::PUSH_REQUEST_DOMAIN,
                &renew_body,
                &renew_body.signing_input().expect("a body signing input"),
            ),
            case(
                "body_sender_revoke",
                "The body of the request that ends an authorisation.",
                crate::push::PUSH_REQUEST_DOMAIN,
                &revoke_body,
                &revoke_body.signing_input().expect("a body signing input"),
            ),
            case(
                "signed_registration_propose",
                "The whole request: the body above, its digest inside a service-request signature, under the method the body names.",
                crate::service::SERVICE_REQUEST_DOMAIN,
                &signed_propose,
                &signed_propose.signing_input().expect("a request signing input"),
            ),
            case(
                "signed_sender_renew",
                "The host-proven renewal request, signed under the host domain the body's signer names.",
                crate::service::SERVICE_REQUEST_HOST_DOMAIN,
                &signed_renew,
                &signed_renew.signing_input().expect("a request signing input"),
            ),
        ],
        "rate_policy": serde_json::to_value(PushRatePolicy::FREE).expect("a policy"),
        "rate_policy_fields": {
            "burst": U64::new(FREE_PUSH_BURST).to_string(),
            "sustained_per_hour": U64::new(FREE_PUSH_PER_HOUR).to_string(),
            "collapse_window_ms": U64::new(PUSH_COLLAPSE_WINDOW_MS).to_string()
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn fixture(relative: &str) -> String {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(relative);
        std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
    }

    /// KR-REQ-16.05: the origin lists are the verdicts this crate actually gives.
    #[test]
    fn the_published_origin_lists_are_what_the_host_decides() {
        for accepted in ACCEPTED_ORIGINS {
            assert!(
                GatewayOrigin::new(*accepted).is_ok(),
                "a published accepted origin is refused: {accepted}"
            );
        }
        for refused in REFUSED_ORIGINS {
            assert!(
                GatewayOrigin::new(*refused).is_err(),
                "a published refused origin is accepted: {refused}"
            );
        }
    }

    /// KR-REQ-16.05, KR-REQ-16.08: the committed vectors are what this crate produces.
    #[test]
    fn the_committed_vectors_match_the_types() {
        assert_eq!(
            fixture("fixtures/service/requests.json"),
            render(&service_requests()),
            "run `cargo run -p kr-protocol --bin kr-protocol-gen` and commit the result"
        );
        assert_eq!(
            fixture("fixtures/push/push.json"),
            render(&push()),
            "run `cargo run -p kr-protocol --bin kr-protocol-gen` and commit the result"
        );
    }
}
