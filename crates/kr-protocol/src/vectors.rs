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

use crate::account::{
    BackupPolicy, ClientVersion, ExternalProviderPolicy, ORGANISATION_POLICY_DOMAIN,
    OrganisationPolicy, OrganisationPolicyPayload, OrganisationRecoveryRecipient,
};
use crate::archive::{
    ARCHIVE_DESCRIPTOR_VERSION, ArchiveDescriptor, BACKUP_PUBLICATION_DOMAIN, BACKUP_WRITER_DOMAIN,
    BackupGenerationPublication, BackupGenerationPublicationPayload, BackupWriterRecord,
    BackupWriterRecordPayload, EncryptedObjectRef, KeyWrapContext, KeyWrapFormat, KeyWrapPurpose,
    SealedKeyWrap, TrustedWriter,
};
use crate::ids::{
    ArchiveId, BackupGeneration, BackupObjectId, BackupWriterRevision, CollapseId, DeviceId,
    EnvelopeId, EnvironmentId, MailboxThreadId, NotificationId, OrganisationId,
    OrganisationPolicyRevision, PluginId, PolicyKeyRevision, PushRegistrationId,
    PushSenderRecordId, PushSenderRevision, RevocationRequestId, SyncCollectionId, SyncConflictId,
    SyncObjectId, SyncRevisionId,
};
use crate::mailbox::{
    EnvelopePlaintext, EnvelopeRouting, EnvelopeVersion, MAX_MAILBOX_BYTES,
    MAX_MAILBOX_ITEM_LIFETIME_MS, MAX_MAILBOX_ITEMS, MailboxPayloadType, SEAL_OVERHEAD_BYTES,
    SealedEnvelope, mailbox_size_bucket, notification_size_bucket,
};
use crate::method::Method;
use crate::pairing::{
    AUTHORITY_REVISION_DOMAIN, AuthorityRevisionRecord, REVOCATION_DOMAIN, RevocationRequest,
    RevocationTarget,
};
use crate::push::{
    DELIVERY_CREDENTIAL_LIFETIME_MS, FREE_PUSH_BURST, FREE_PUSH_PER_HOUR,
    MAX_PREVIEW_PLAINTEXT_BYTES, MAX_PROVIDER_PAYLOAD_BYTES, PUSH_COLLAPSE_WINDOW_MS, PushAlert,
    PushDeliveryRequest, PushInstallationBinding, PushPlatform, PushPlatformHints, PushRatePolicy,
    PushRegistrationAnswer, PushRegistrationChallenge, PushRegistrationProposal,
    PushRegistrationRequest, PushRequest, PushRevocationReason, PushSenderBinding,
    PushSenderIssueRequest, PushSenderNonceRequest, PushSenderRecord, PushSenderRenewRequest,
    PushSenderRenewal, PushSenderRenewalPayload, PushSenderRevocation, PushSenderRevocationPayload,
    PushSenderRevokeRequest, PushSenderState, PushTokenState, REGISTRATION_CHALLENGE_LIFETIME_MS,
    RegistrationToken, SENDER_RENEWAL_WINDOW_MS, token_digest,
};
use crate::scalars::{
    AuthorisationKey, Bytes, CanonicalSet, Digest256, DurationMs, EndpointKey, KeyId, Nonce192,
    Nonce256, Nullable, SecretBytes32, Signature64, StoredEnvelopeKey, TimestampMs, U64, Uuid,
};
use crate::service::{
    GatewayOrigin, SERVICE_REQUEST_FRESHNESS_MS, ServiceRequestPayload, ServiceRequestSignature,
    ServiceRequestSigner, body_digest, installation_id,
};
use crate::sync::{
    MAX_SYNC_CONFLICT_COPIES, MAX_SYNC_OBJECT_PLAINTEXT_BYTES, MAX_SYNC_OBJECTS_PER_COLLECTION,
    SealedSyncObject, SyncConflictCopy, SyncObjectKind, SyncObjectRecord,
};

/// The service-request credential vectors.
pub const SERVICE_REQUESTS_FILE_NAME: &str = "requests.json";

/// The push registration, authorisation and delivery vectors.
pub const PUSH_FILE_NAME: &str = "push.json";

/// The mailbox, authority feed, settings sync, backup manifest and host policy vectors.
pub const SERVICES_FILE_NAME: &str = "services.json";

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

/// The key the published key-identifier vectors are derived from. Test material.
const IDENTIFIED_KEY: [u8; 32] = [0x44; 32];

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
        (SERVICES_FILE_NAME, render(&services())),
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
            payload_type: MailboxPayloadType::NotificationPreview,
            thread_id: Nullable::null(),
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
    let renew_begin = PushRequest::SenderRenew {
        request: PushSenderRenewRequest::Begin {
            request: PushSenderNonceRequest {
                sender_record_id: sender_record_id(),
            },
        },
    };
    let renew_body = PushRequest::SenderRenew {
        request: PushSenderRenewRequest::Complete {
            renewal: renewal.clone(),
        },
    };
    let revoke_begin = PushRequest::SenderRevoke {
        request: PushSenderRevokeRequest::Begin {
            request: PushSenderNonceRequest {
                sender_record_id: sender_record_id(),
            },
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
            { "body": "body_sender_renew_begin", "method": renew_begin.method().as_str(), "signer": renew_begin.signer().as_str() },
            { "body": "body_sender_revoke_begin", "method": revoke_begin.method().as_str(), "signer": revoke_begin.signer().as_str() },
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
                "body_sender_renew_begin",
                "The body of the request that asks for the nonce a renewal will answer.",
                crate::push::PUSH_REQUEST_DOMAIN,
                &renew_begin,
                &renew_begin.signing_input().expect("a body signing input"),
            ),
            case(
                "body_sender_revoke_begin",
                "The body of the request that asks for the nonce a revocation will answer.",
                crate::push::PUSH_REQUEST_DOMAIN,
                &revoke_begin,
                &revoke_begin.signing_input().expect("a body signing input"),
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

/// The vectors for the mailbox, the authority feed, settings sync, backup manifests and policy.
///
/// Five of the seven cases are signing inputs, because five of these records carry a signature
/// somebody other than the service checks: a remote owner's revocation request, a host's authority
/// revision, a collection owner's writer enrolment, a writer's published generation and an
/// organisation's signed policy. The mailbox and sync cases are canonical encodings rather than
/// signing inputs: what authenticates a mailbox item is the box around it, and a synchronised
/// object is compared by revision rather than signed, so what both languages must agree on is the
/// encoding of the record itself.
fn services() -> Value {
    let recipient_key_id = KeyId::from_bytes([0x91; 32]);
    let sender_key_id = KeyId::from_bytes([0x92; 32]);
    let thread = MailboxThreadId::new(Uuid::from_bytes([
        0x3f, 0x1c, 0x88, 0x0a, 0x52, 0x6d, 0x4b, 0x19, 0x8e, 0x27, 0x0d, 0x61, 0xaa, 0x34, 0x77,
        0x90,
    ]));
    let envelope_id = EnvelopeId::new(Uuid::from_bytes([
        0x8a, 0x44, 0x1e, 0x7b, 0x29, 0x03, 0x4c, 0x5d, 0xb1, 0x6e, 0x38, 0x92, 0xcf, 0x05, 0x61,
        0x2d,
    ]));
    let expires_at_ms = TimestampMs::new(NOW_MS + MAX_MAILBOX_ITEM_LIFETIME_MS);
    let bucket = mailbox_size_bucket(320);

    let plaintext = EnvelopePlaintext {
        version: EnvelopeVersion::V1,
        envelope_id,
        sender_key_id,
        recipient_key_id,
        payload_type: MailboxPayloadType::SyncChange,
        created_at_ms: TimestampMs::new(NOW_MS),
        expires_at_ms,
        grant_id: Nullable::null(),
        environment_id: Nullable::some(EnvironmentId::new(Uuid::from_bytes([0x21; 16]))),
        session_id: Nullable::null(),
        session_epoch: Nullable::null(),
        thread_id: Nullable::some(thread),
        payload: Bytes::new(vec![0x7a; 16]),
    };
    let item = SealedEnvelope {
        routing: EnvelopeRouting {
            envelope_id,
            recipient_key_id,
            sender_key_id,
            expires_at_ms,
            payload_type: MailboxPayloadType::SyncChange,
            thread_id: Nullable::some(thread),
            size_bucket_bytes: U64::new(bucket),
        },
        nonce: Nonce192::from_bytes([0x93; 24]),
        ciphertext: Bytes::new(vec![
            0xab;
            usize::try_from(bucket + SEAL_OVERHEAD_BYTES)
                .expect("a bucket fits in memory")
        ]),
    };
    let plaintext_bytes =
        kr_cbor::encode(&kr_cbor::to_canonical_value(&plaintext).expect("an envelope plaintext"));

    let host_device_id = DeviceId::new(Uuid::from_bytes([0x4d; 16]));
    let request_id = RevocationRequestId::new(Uuid::from_bytes([
        0x6b, 0x0e, 0x77, 0x31, 0x9a, 0x45, 0x4f, 0x82, 0xb3, 0x58, 0x1d, 0x0c, 0xe6, 0x24, 0x93,
        0x11,
    ]));
    let revocation = RevocationRequest {
        request_id,
        issuer_device_id: DeviceId::new(Uuid::from_bytes([0x2c; 16])),
        host_device_id,
        target: RevocationTarget::Devices {
            device_ids: [DeviceId::new(Uuid::from_bytes([0x5e; 16]))]
                .into_iter()
                .collect(),
        },
        issued_at_ms: TimestampMs::new(NOW_MS),
        issuer_key_id: KeyId::from_bytes([0x71; 32]),
        signature: Signature64::from_bytes([0x5c; 64]),
    };
    let revision = AuthorityRevisionRecord {
        host_device_id,
        authority_revision: crate::ids::AuthorityRevision::new(12),
        previous_revision: crate::ids::AuthorityRevision::new(11),
        applied_requests: [request_id].into_iter().collect(),
        issued_at_ms: TimestampMs::new(NOW_MS + 1_000),
        host_key_id: KeyId::from_bytes([0x72; 32]),
        signature: Signature64::from_bytes([0x5d; 64]),
    };

    let collection_id = SyncCollectionId::new(Uuid::from_bytes([0x33; 16]));
    let object_id = SyncObjectId::new(Uuid::from_bytes([0x34; 16]));
    let sync_bucket = mailbox_size_bucket(200);
    let sealed_object = SealedSyncObject {
        nonce: Nonce192::from_bytes([0x94; 24]),
        size_bucket_bytes: U64::new(sync_bucket),
        ciphertext: Bytes::new(vec![
            0xcd;
            usize::try_from(sync_bucket + SEAL_OVERHEAD_BYTES)
                .expect("a bucket fits in memory")
        ]),
    };
    let record = SyncObjectRecord {
        collection_id,
        kind: SyncObjectKind::Settings,
        object_id,
        revision: SyncRevisionId::new(Uuid::from_bytes([0x35; 16])),
        object: sealed_object.clone(),
        updated_at_ms: TimestampMs::new(NOW_MS),
    };
    let conflict = SyncConflictCopy {
        conflict_id: SyncConflictId::new(Uuid::from_bytes([0x36; 16])),
        object_id,
        kind: SyncObjectKind::Draft,
        expected_revision: Nullable::some(SyncRevisionId::new(Uuid::from_bytes([0x37; 16]))),
        current_revision: SyncRevisionId::new(Uuid::from_bytes([0x35; 16])),
        object: sealed_object,
        recorded_at_ms: TimestampMs::new(NOW_MS + 60_000),
    };

    let archive_id = ArchiveId::new(Uuid::from_bytes([0x38; 16]));
    let manifest = EncryptedObjectRef {
        object_id: BackupObjectId::new(Uuid::from_bytes([0x39; 16])),
        encrypted_object_hash: Digest256::from_bytes([0x3a; 32]),
        encrypted_len: U64::new(65_536),
    };
    let writer_key_id = KeyId::from_bytes([0x73; 32]);
    let enrolment = BackupWriterRecordPayload {
        archive_id,
        writer: TrustedWriter {
            writer_key_id,
            signing_key: AuthorisationKey::from_bytes([0x74; 32]),
            enrolled_at_ms: TimestampMs::new(NOW_MS),
        },
        writer_revision: BackupWriterRevision::new(1),
        owner_key_id: KeyId::from_bytes([0x75; 32]),
        enrolled_at_ms: TimestampMs::new(NOW_MS),
    };
    let writer_record = BackupWriterRecord {
        payload: enrolment.clone(),
        signature: Signature64::from_bytes([0x5f; 64]),
    };
    let publication_payload = BackupGenerationPublicationPayload {
        descriptor: ArchiveDescriptor {
            version: U64::new(ARCHIVE_DESCRIPTOR_VERSION),
            archive_id,
            backup_generation: BackupGeneration::new(7),
            encrypted_manifest: manifest.clone(),
            manifest_key_wraps: vec![SealedKeyWrap {
                context: KeyWrapContext {
                    format: KeyWrapFormat::V1,
                    purpose: KeyWrapPurpose::ManifestKey,
                    archive_id,
                    backup_generation: BackupGeneration::new(7),
                    object_id: manifest.object_id,
                    encrypted_object_hash: manifest.encrypted_object_hash,
                    sender_key_id: writer_key_id,
                    recipient_key_id,
                },
                nonce: Nonce192::from_bytes([0x95; 24]),
                ciphertext: Bytes::new(vec![0xef; 48]),
            }],
        },
        writer_key_id,
        published_at_ms: TimestampMs::new(NOW_MS + 120_000),
    };
    let publication = BackupGenerationPublication {
        payload: publication_payload.clone(),
        signature: Signature64::from_bytes([0x60; 64]),
    };

    let policy_payload = OrganisationPolicyPayload {
        organisation_id: OrganisationId::new(Uuid::from_bytes([0x3b; 16])),
        policy_revision: OrganisationPolicyRevision::new(4),
        adapter_allowlist: Nullable::some(
            ["kalareach.codex", "kalareach.claude-code"]
                .into_iter()
                .map(|name| PluginId::new(name).expect("a plugin identifier"))
                .collect::<CanonicalSet<PluginId>>(),
        ),
        minimum_client_version: Nullable::some(
            ClientVersion::new("1.4.0").expect("a client version"),
        ),
        maximum_grant_lifetime_ms: Nullable::some(DurationMs::new(7 * 24 * 60 * 60 * 1000)),
        external_providers: ExternalProviderPolicy::OrganisationOnly,
        backup: BackupPolicy {
            required: true,
            recovery_recipient: Nullable::some(OrganisationRecoveryRecipient {
                recipient_key_id: KeyId::from_bytes([0x76; 32]),
                recipient_key: StoredEnvelopeKey::from_bytes([0x77; 32]),
                name: "Kala Holdings recovery".to_owned(),
                named_at_ms: TimestampMs::new(NOW_MS),
            }),
        },
        audit_retention_days: U64::new(365),
        issued_at_ms: TimestampMs::new(NOW_MS),
        key_revision: PolicyKeyRevision::new(2),
    };
    let policy = OrganisationPolicy {
        payload: policy_payload.clone(),
        signature: Signature64::from_bytes([0x61; 64]),
    };
    policy_payload
        .check_structure()
        .expect("the published policy passes its own checks");

    json!({
        "name": "services",
        "description": "The mailbox, the authority feed, settings sync, backup manifests and organisation policy: what a managed service stores, and the exact bytes each signature covers.",
        "note": note(),
        "key_identifiers": {
            "description": "SHA256(CBOR([\"kr-key-id/1\", purpose, key])) for one 32-byte key declared under each purpose. A service derives the identifier from the key a caller presents rather than believing a claimed one, so the same bytes under two purposes name two different keys.",
            "domain": crate::pairing::KEY_ID_DOMAIN,
            "public_key": serde_json::to_value(AuthorisationKey::from_bytes(IDENTIFIED_KEY))
                .expect("a key"),
            "identifiers": crate::pairing::KeyPurpose::ALL
                .iter()
                .map(|purpose| {
                    json!({
                        "purpose": purpose.as_str(),
                        "key_id": serde_json::to_value(crate::pairing::key_id(
                            *purpose,
                            &IDENTIFIED_KEY,
                        ))
                        .expect("a key identifier"),
                        "key_id_hex": hex(crate::pairing::key_id(*purpose, &IDENTIFIED_KEY).as_bytes())
                    })
                })
                .collect::<Vec<_>>()
        },
        "mailbox_limits": {
            "item_lifetime_ms": U64::new(MAX_MAILBOX_ITEM_LIFETIME_MS).to_string(),
            "items_per_device": U64::new(MAX_MAILBOX_ITEMS).to_string(),
            "bytes_per_device": U64::new(MAX_MAILBOX_BYTES).to_string(),
            "seal_overhead_bytes": U64::new(SEAL_OVERHEAD_BYTES).to_string(),
            "payload_types": MailboxPayloadType::ALL.map(MailboxPayloadType::as_str),
            "coalesced_payload_types": MailboxPayloadType::ALL
                .iter()
                .filter(|kind| !kind.bears_authority())
                .map(|kind| kind.as_str())
                .collect::<Vec<_>>()
        },
        "sync_limits": {
            "object_plaintext_bytes": U64::new(MAX_SYNC_OBJECT_PLAINTEXT_BYTES).to_string(),
            "objects_per_collection": U64::new(MAX_SYNC_OBJECTS_PER_COLLECTION).to_string(),
            "conflict_copies_per_object": U64::new(MAX_SYNC_CONFLICT_COPIES).to_string(),
            "object_kinds": SyncObjectKind::ALL.map(SyncObjectKind::as_str)
        },
        "cases": [
            json!({
                "id": "mailbox_item",
                "description": "One sealed mailbox item. The routing record declares the payload kind, the coalescing thread and the size bucket; the plaintext authenticates every one of them, so a service that relabelled or re-threaded an item is caught when the recipient opens it.",
                "domain": Value::Null,
                "cbor_hex": hex(&plaintext_bytes),
                "sha256": hex(&kr_cbor::sha256(&plaintext_bytes)),
                "json": {
                    "plaintext": serde_json::to_value(&plaintext).expect("a plaintext"),
                    "sealed": serde_json::to_value(&item).expect("an item")
                },
                "stored_bytes": U64::new(item.stored_bytes()).to_string(),
                "value": describe(
                    &kr_cbor::decode(&plaintext_bytes, &kr_cbor::Limits::default())
                        .expect("valid KR-CBOR-1")
                ),
            }),
            case(
                "revocation_request",
                "A remote owner's signed revocation request. It carries no host revision at all: only the target host issues its ordered revisions, so a device cannot assign one to its own request.",
                REVOCATION_DOMAIN,
                &revocation,
                &revocation.signing_input().expect("a revocation signing input"),
            ),
            case(
                "authority_revision_record",
                "The host's own ordered authority revision, naming the requests it applied and the revision it follows.",
                AUTHORITY_REVISION_DOMAIN,
                &revision,
                &revision.signing_input().expect("a revision signing input"),
            ),
            json!({
                "id": "sync_object_record",
                "description": "One synchronised object as the service holds it: the kind, the revision the content was accepted as, and the sealed object. Nothing about what it contains is outside the encryption.",
                "domain": Value::Null,
                "cbor_hex": hex(&kr_cbor::encode(
                    &kr_cbor::to_canonical_value(&record).expect("a sync record")
                )),
                "sha256": hex(&kr_cbor::sha256(&kr_cbor::encode(
                    &kr_cbor::to_canonical_value(&record).expect("a sync record")
                ))),
                "json": serde_json::to_value(&record).expect("a sync record"),
                "stored_bytes": U64::new(record.object.stored_bytes()).to_string(),
                "value": describe(&kr_cbor::to_canonical_value(&record).expect("a sync record")),
            }),
            json!({
                "id": "sync_conflict_copy",
                "description": "A write that lost its comparison, kept unchanged for the person to choose from. The revision it expected and the revision the object held are both recorded; no clock decides between them.",
                "domain": Value::Null,
                "cbor_hex": hex(&kr_cbor::encode(
                    &kr_cbor::to_canonical_value(&conflict).expect("a conflict copy")
                )),
                "sha256": hex(&kr_cbor::sha256(&kr_cbor::encode(
                    &kr_cbor::to_canonical_value(&conflict).expect("a conflict copy")
                ))),
                "json": serde_json::to_value(&conflict).expect("a conflict copy"),
                "value": describe(
                    &kr_cbor::to_canonical_value(&conflict).expect("a conflict copy")
                ),
            }),
            case(
                "backup_writer_record",
                "The collection owner's enrolment of the writer that may publish its generations, signed by the owner's authorisation key.",
                BACKUP_WRITER_DOMAIN,
                &writer_record,
                &enrolment.signing_input().expect("an enrolment signing input"),
            ),
            case(
                "backup_generation_publication",
                "One published generation: the public descriptor, signed by the enrolled writer, so a device verifies the writer's own statement rather than the service's word about it.",
                BACKUP_PUBLICATION_DOMAIN,
                &publication,
                &publication_payload
                    .signing_input()
                    .expect("a publication signing input"),
            ),
            case(
                "organisation_policy",
                "One revision of an organisation's host policy, signed by the revision of its policy-signing key that a host follows the chain to. It narrows what a host allows and carries no content key.",
                ORGANISATION_POLICY_DOMAIN,
                &policy,
                &policy_payload.signing_input().expect("a policy signing input"),
            ),
        ],
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
        assert_eq!(
            fixture("fixtures/service/services.json"),
            render(&services()),
            "run `cargo run -p kr-protocol --bin kr-protocol-gen` and commit the result"
        );
    }
}
