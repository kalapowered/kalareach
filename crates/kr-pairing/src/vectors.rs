//! The cross-language vectors under `fixtures/pairing/`.
//!
//! SPAKE2 draws fresh randomness for every attempt, so a vector cannot fix the exchange itself.
//! What it can fix, and what section 10 actually pins down, is everything derived from it: the
//! context `C`, its hash, the two role identities, the transcript `T` for two given library
//! messages, the five HKDF keys for a given shared key, both confirmation tags, the bundle
//! additional authenticated data, the `pair.finish` tag, the verification value, the direct
//! transcript `D` and its proofs, and the two QR payload encodings.
//!
//! Every input below is a literal. They are test material and nothing else pairs with them.

use std::path::Path;

use kr_protocol::grant::{EnvironmentSelector, GrantExpiry, HistoryScope, SessionSelector};
use kr_protocol::ids::{AttemptId, InvitationId, PairingSequence};
use kr_protocol::pairing::{
    BundleDirection, BundleMessageType, CLIENT_IDENTITY_DOMAIN, CodeQrPayload, DIRECT_DOMAIN,
    DIRECT_VERIFY_DOMAIN, DevicePublicKeys, DirectQrPayload, DirectTranscript, HKDF_INFO_STRINGS,
    HOST_IDENTITY_DOMAIN, Locator, NetworkConfig, PAIRING_DOMAIN, PairingContext, ProposedGrant,
    QR_PAYLOAD_VERSION, QrPayload, RendezvousOrigin, ShortCode, VERIFY_DOMAIN, bundle_aad,
    direct_verification_value, finish_mac_input, verification_value,
};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{
    AuthorisationKey, CanonicalSet, Digest256, EndpointKey, Nonce256, NotificationPreviewKey,
    Nullable, SecretBytes32, StoredEnvelopeKey, TimestampMs, Uuid,
};
use serde_json::{Value, json};

use crate::code::EnteredCode;
use crate::error::{PairingError, Result};
use crate::transcript::AttemptKeys;

/// The short-code transcript vectors.
pub const TRANSCRIPT_FILE_NAME: &str = "transcript.json";

/// The direct-mode vectors.
pub const DIRECT_FILE_NAME: &str = "direct.json";

/// The code parsing and QR payload vectors.
pub const CODES_FILE_NAME: &str = "codes.json";

/// The fixed shared key the derivations are vectored from.
const SHARED_KEY: [u8; 32] = [0x5a; 32];
/// The fixed host library message.
const MESSAGE_A: [u8; 33] = [0x41; 33];
/// The fixed candidate library message.
const MESSAGE_B: [u8; 33] = [0x42; 33];
/// The fixed invitation secret of the direct vector.
const DIRECT_SECRET: [u8; 32] = [0x7b; 32];

fn context() -> PairingContext {
    PairingContext {
        rendezvous_origin: RendezvousOrigin::new("https://reach.kala.to").expect("an origin"),
        locator: Locator::new("aB3x").expect("a locator"),
        invitation_id: InvitationId::new(Uuid::from_bytes([0x11; 16])),
        attempt_id: AttemptId::new(Uuid::from_bytes([0x22; 16])),
        host_nonce: Nonce256::from_bytes([0x33; 32]),
        client_nonce: Nonce256::from_bytes([0x44; 32]),
    }
}

fn keys(seed: u8) -> DevicePublicKeys {
    DevicePublicKeys {
        transport: EndpointKey::from_bytes([seed; 32]),
        authorisation: AuthorisationKey::from_bytes([seed.wrapping_add(1); 32]),
        stored_envelope: StoredEnvelopeKey::from_bytes([seed.wrapping_add(2); 32]),
        notification_preview: NotificationPreviewKey::from_bytes([seed.wrapping_add(3); 32]),
    }
}

fn proposal() -> ProposedGrant {
    ProposedGrant {
        parent_grant_id: Nullable::null(),
        environment_selector: EnvironmentSelector::Any,
        session_selector: SessionSelector::Any,
        actions: [ActionRight::SessionView].into_iter().collect(),
        history: HistoryScope {
            lower_bound_ms: Nullable::null(),
            include_live_screen: false,
            named_questions: CanonicalSet::new(),
            named_approvals: CanonicalSet::new(),
        },
        expiry: GrantExpiry::At {
            expires_at_ms: TimestampMs::new(1_764_003_600_000),
        },
        organisation: Nullable::null(),
    }
}

fn direct_transcript() -> DirectTranscript {
    DirectTranscript {
        invitation_id: InvitationId::new(Uuid::from_bytes([0x11; 16])),
        host_endpoint_id: EndpointKey::from_bytes([0x60; 32]),
        client_endpoint_id: EndpointKey::from_bytes([0x70; 32]),
        host_keys: keys(0x60),
        client_keys: keys(0x70),
        proposed_grant_digest: Digest256::from_bytes(kr_cbor::sha256(
            &kr_cbor::to_canonical_vec(&proposal()).expect("canonical bytes"),
        )),
        host_nonce: Nonce256::from_bytes([0x55; 32]),
        client_nonce: Nonce256::from_bytes([0x66; 32]),
        expires_at_ms: TimestampMs::new(1_764_000_600_000),
    }
}

/// Returns every generated fixture document as a file name and its exact contents.
///
/// # Errors
///
/// Returns an error when a value is outside KR-CBOR-1 or libsodium is unavailable.
pub fn generated_files() -> Result<Vec<(&'static str, String)>> {
    Ok(vec![
        (TRANSCRIPT_FILE_NAME, render(&transcript_vectors()?)),
        (DIRECT_FILE_NAME, render(&direct_vectors()?)),
        (CODES_FILE_NAME, render(&code_vectors()?)),
    ])
}

fn render(value: &Value) -> String {
    let mut text = serde_json::to_string_pretty(value).expect("generated JSON is serialisable");
    text.push('\n');
    text
}

fn transcript_vectors() -> Result<Value> {
    let context = context();
    let transcript = context.transcript(&MESSAGE_A, &MESSAGE_B);
    let derived = AttemptKeys::derive(&SHARED_KEY, transcript)?;

    let host_bundle_hash = Digest256::from_bytes([0x88; 32]);
    let client_bundle_hash = Digest256::from_bytes([0x99; 32]);
    let finish = finish_mac_input(
        context.invitation_id,
        context.attempt_id,
        transcript,
        &EnteredKeys::HOST_ENDPOINT,
        &EnteredKeys::CLIENT_ENDPOINT,
        host_bundle_hash,
        client_bundle_hash,
    );

    let mut aads = Vec::new();
    for (direction, message_type) in [
        (BundleDirection::HostToClient, BundleMessageType::HostBundle),
        (
            BundleDirection::ClientToHost,
            BundleMessageType::ClientBundle,
        ),
    ] {
        for sequence in 0..2u64 {
            aads.push(json!({
                "direction": direction.as_str(),
                "message_type": message_type.as_str(),
                "sequence": sequence,
                "aad_hex": hex::encode(bundle_aad(
                    transcript,
                    direction,
                    PairingSequence::new(sequence),
                    message_type,
                )),
            }));
        }
    }

    Ok(json!({
        "name": "transcript",
        "description": "The short-code context, identities, transcript, HKDF keys, confirmation tags, bundle additional data, pair.finish tag and verification value, from fixed inputs.",
        "note": "SPAKE2 draws fresh randomness per attempt, so the two library messages and the shared key below are fixed literals rather than the output of an exchange. Everything else is derived from them exactly as a real attempt derives it.",
        "domain": PAIRING_DOMAIN,
        "context": {
            "rendezvous_origin": context.rendezvous_origin.as_str(),
            "locator": context.locator.as_str(),
            "invitation_id_hex": hex::encode(context.invitation_id.get().as_bytes()),
            "attempt_id_hex": hex::encode(context.attempt_id.get().as_bytes()),
            "host_nonce_hex": hex::encode(context.host_nonce.as_bytes()),
            "client_nonce_hex": hex::encode(context.client_nonce.as_bytes()),
            "canonical_hex": hex::encode(context.to_canonical_bytes()),
            "context_hash_hex": hex::encode(context.context_hash().as_bytes()),
        },
        "identities": {
            "host_domain": HOST_IDENTITY_DOMAIN,
            "host_hex": hex::encode(context.host_identity()),
            "client_domain": CLIENT_IDENTITY_DOMAIN,
            "client_hex": hex::encode(context.client_identity()),
        },
        "exchange": {
            "shared_key_hex": hex::encode(SHARED_KEY),
            "message_a_hex": hex::encode(MESSAGE_A),
            "message_b_hex": hex::encode(MESSAGE_B),
            "transcript_hex": hex::encode(kr_cbor::encode(&kr_cbor::CanonicalValue::Array(vec![
                context.to_canonical_value(),
                kr_cbor::CanonicalValue::bytes(MESSAGE_A.as_slice()),
                kr_cbor::CanonicalValue::bytes(MESSAGE_B.as_slice()),
            ]))),
            "transcript_sha256_hex": hex::encode(transcript.as_bytes()),
        },
        "hkdf": {
            "description": "HKDF-SHA256 with the shared key as input key material and the transcript as salt, under the five literal information strings.",
            "info_strings": HKDF_INFO_STRINGS,
            "client_confirm_key_hex": hex::encode(derived.client_confirm.expose()),
            "host_confirm_key_hex": hex::encode(derived.host_confirm.expose()),
            "client_to_host_key_hex": hex::encode(derived.client_to_host.expose()),
            "host_to_client_key_hex": hex::encode(derived.host_to_client.expose()),
            "iroh_bind_key_hex": hex::encode(derived.iroh_bind.expose()),
        },
        "confirmation": {
            "description": "The client tag comes first; the host verifies it in constant time and answers with its own.",
            "client_tag_hex": hex::encode(derived.client_confirmation(transcript).as_bytes()),
            "host_tag_hex": hex::encode(derived.host_confirmation(transcript).as_bytes()),
        },
        "bundle_additional_data": aads,
        "finish": {
            "description": "The pair.finish tag covers both endpoint identities and both bundle hashes under the iroh-bind key.",
            "host_endpoint_hex": hex::encode(EnteredKeys::HOST_ENDPOINT.as_bytes()),
            "client_endpoint_hex": hex::encode(EnteredKeys::CLIENT_ENDPOINT.as_bytes()),
            "host_bundle_hash_hex": hex::encode(host_bundle_hash.as_bytes()),
            "client_bundle_hash_hex": hex::encode(client_bundle_hash.as_bytes()),
            "message_hex": hex::encode(&finish),
            "tag_hex": hex::encode(derived.binding_tag(&finish).as_bytes()),
        },
        "verification_value": {
            "domain": VERIFY_DOMAIN,
            "value": verification_value(transcript, host_bundle_hash, client_bundle_hash),
        },
    }))
}

/// The two endpoint identities the finish vector uses.
struct EnteredKeys;

impl EnteredKeys {
    const HOST_ENDPOINT: EndpointKey = EndpointKey::from_bytes([0x60; 32]);
    const CLIENT_ENDPOINT: EndpointKey = EndpointKey::from_bytes([0x70; 32]);
}

fn direct_vectors() -> Result<Value> {
    let transcript = direct_transcript();
    let bytes = transcript.to_canonical_bytes();
    let secret = SecretBytes32::from_bytes(DIRECT_SECRET);
    Ok(json!({
        "name": "direct",
        "description": "The direct transcript D, its digest, the secret proof over it and the verification value.",
        "note": "The invitation secret below is test material. A real one is 256 random bits from libsodium.",
        "domain": DIRECT_DOMAIN,
        "transcript": {
            "invitation_id_hex": hex::encode(transcript.invitation_id.get().as_bytes()),
            "host_endpoint_hex": hex::encode(transcript.host_endpoint_id.as_bytes()),
            "client_endpoint_hex": hex::encode(transcript.client_endpoint_id.as_bytes()),
            "proposed_grant_digest_hex": hex::encode(transcript.proposed_grant_digest.as_bytes()),
            "host_nonce_hex": hex::encode(transcript.host_nonce.as_bytes()),
            "client_nonce_hex": hex::encode(transcript.client_nonce.as_bytes()),
            "expires_at": transcript.expires_at_ms.get(),
            "canonical_hex": hex::encode(&bytes),
            "canonical_sha256_hex": hex::encode(kr_cbor::sha256(&bytes)),
        },
        "secret_proof": {
            "description": "HMAC-SHA256(invitation_secret, D).",
            "secret_hex": hex::encode(DIRECT_SECRET),
            "tag_hex": hex::encode(crate::direct::secret_proof(&secret, &transcript).as_bytes()),
        },
        "verification_value": {
            "domain": DIRECT_VERIFY_DOMAIN,
            "value": direct_verification_value(&transcript),
        },
    }))
}

fn code_vectors() -> Result<Value> {
    let accepted = [
        "aB3x-Yz7-9Qw",
        "aB3xYz79Qw",
        " aB3x Yz7 9Qw ",
        "aB3x--Yz7--9Qw",
    ];
    let mut accepted_cases = Vec::new();
    for entry in accepted {
        let code = EnteredCode::parse(entry).map_err(|_| PairingError::MalformedCode)?;
        accepted_cases.push(json!({
            "entered": entry,
            "normalised": code.normalised(),
            "locator": code.locator().as_str(),
        }));
    }

    let rejected = [
        ("too_short", "aB3xYz79Q"),
        ("too_long", "aB3xYz79QwX"),
        ("empty", ""),
        ("zero_is_not_in_the_alphabet", "0B3xYz79Qw"),
        ("capital_o_is_not_in_the_alphabet", "OB3xYz79Qw"),
        ("capital_i_is_not_in_the_alphabet", "IB3xYz79Qw"),
        ("lower_l_is_not_in_the_alphabet", "lB3xYz79Qw"),
        ("punctuation", "aB3xYz79Q!"),
        ("non_ascii", "aB3xYz79Qé"),
    ];

    let code_payload = QrPayload::Code(CodeQrPayload {
        rendezvous_origin: RendezvousOrigin::new("https://reach.kala.to").expect("an origin"),
        code: ShortCode::new("aB3x-Yz7-9Qw").expect("a code"),
    });
    let direct_payload = QrPayload::Direct(Box::new(DirectQrPayload {
        invitation_id: InvitationId::new(Uuid::from_bytes([0x11; 16])),
        endpoint_id: EndpointKey::from_bytes([0x60; 32]),
        network_config: NetworkConfig {
            relay_urls: vec![
                kr_protocol::pairing::NetworkHint::new("https://relay.kala.to").expect("a hint"),
            ],
            pkarr_publisher_url: kr_protocol::scalars::Nullable::some(
                kr_protocol::pairing::NetworkHint::new("https://discovery.kala.to/pkarr")
                    .expect("a hint"),
            ),
            pkarr_resolver_url: kr_protocol::scalars::Nullable::some(
                kr_protocol::pairing::NetworkHint::new("https://discovery.kala.to/pkarr")
                    .expect("a hint"),
            ),
            dns_origin: kr_protocol::scalars::Nullable::some(
                kr_protocol::pairing::NetworkHint::new("discovery.kala.to").expect("a hint"),
            ),
            direct_addresses: vec![
                kr_protocol::pairing::NetworkHint::new("192.0.2.1:41234").expect("a hint"),
            ],
        },
        secret: SecretBytes32::from_bytes(DIRECT_SECRET),
        proposed_grant: proposal(),
        expires_at_ms: TimestampMs::new(1_764_000_600_000),
    }));

    Ok(json!({
        "name": "codes",
        "description": "Short-code parsing and the two QR payload encodings.",
        "alphabet": kr_protocol::pairing::BASE58_ALPHABET,
        "display_form": "XXXX-XXX-XXX",
        "parsing": {
            "description": "Parsing removes ASCII spaces and hyphens, preserves case and requires exactly ten alphabet characters.",
            "accepted": accepted_cases,
            "rejected": rejected
                .iter()
                .map(|(id, entered)| json!({"id": id, "entered": entered}))
                .collect::<Vec<_>>(),
        },
        "qr": {
            "description": "Both payload formats in their canonical KR-CBOR-1 encodings. A parser requires an explicit supported mode.",
            "version": QR_PAYLOAD_VERSION,
            "code": {
                "mode": code_payload.mode(),
                "canonical_hex": hex::encode(code_payload.to_canonical_bytes()?.as_slice()),
                "text": code_payload.to_text()?.as_str(),
            },
            "direct": {
                "mode": direct_payload.mode(),
                "canonical_hex": hex::encode(direct_payload.to_canonical_bytes()?.as_slice()),
                "text": direct_payload.to_text()?.as_str(),
            },
        },
    }))
}

/// Returns the directory the vectors are written to, under `repository_root`.
#[must_use]
pub fn fixture_directory(repository_root: &Path) -> std::path::PathBuf {
    repository_root.join("fixtures/pairing")
}
