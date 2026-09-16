//! The cross-language vectors under `fixtures/crypto/`.
//!
//! Every value here is derived from a fixed test key, so the documents are byte stable and both
//! languages can check the same numbers. The signature vectors sign the exact canonical bytes that
//! `fixtures/cbor/digests.json` and `fixtures/protocol/transcripts.json` already publish, which is
//! what section 23 asks for: the signature covers the validated encoding, not a re-serialisation.
//!
//! The test seeds below are literals in the source. They are test material and nothing else signs
//! or decrypts with them.

use std::path::Path;

use kr_protocol::archive::{
    KeyWrapContext, KeyWrapFormat, KeyWrapPurpose, RecoveryContext, SealedKeyWrap,
    key_wrap_plaintext,
};
use kr_protocol::ids::{
    ArchiveId, BackupGeneration, BackupObjectId, EnvelopeId, EnvironmentId, GrantId, SessionEpoch,
    SessionId,
};
use kr_protocol::mailbox::{
    EnvelopePlaintext, EnvelopeRouting, EnvelopeVersion, MailboxPayloadType, SealedEnvelope,
    mailbox_size_bucket, notification_size_bucket,
};
use kr_protocol::pairing::KeyPurpose;
use kr_protocol::scalars::{Bytes, Digest256, Nonce192, Nullable, TimestampMs, U64, Uuid};
use serde_json::{Value, json};

use crate::error::{CryptoError, Result};
use crate::kdf::{self, RecoverySeed};
use crate::keys::{
    AuthorisationKeyPair, AuthorisationSeed, StoredEnvelopeKeyPair, StoredEnvelopeSeed, key_id,
};
use crate::secret::SymmetricKey;
use crate::sign::SigningTranscript;
use crate::sodium;

/// The Ed25519 signature vectors.
pub const SIGNATURES_FILE_NAME: &str = "signatures.json";

/// The mailbox envelope and key wrap vectors.
pub const ENVELOPES_FILE_NAME: &str = "envelopes.json";

/// The key derivation vectors.
pub const KDF_FILE_NAME: &str = "kdf.json";

/// The relay signature vectors.
pub const RELAY_FILE_NAME: &str = "relay.json";

/// The test authorisation seed of the host side.
const HOST_AUTHORISATION_SEED: [u8; 32] = [0xa1; 32];
/// The test authorisation seed of the client side.
const CLIENT_AUTHORISATION_SEED: [u8; 32] = [0xb2; 32];
/// The test stored-envelope seed of the sender.
const SENDER_ENVELOPE_SEED: [u8; 32] = [0xa3; 32];
/// The test stored-envelope seed of the recipient.
const RECIPIENT_ENVELOPE_SEED: [u8; 32] = [0xb4; 32];
/// The fixed nonce the envelope vector uses. A real envelope always uses a fresh random nonce.
const ENVELOPE_NONCE: [u8; 24] = [0xc5; 24];
/// The fixed nonce the key wrap vector uses.
const KEY_WRAP_NONCE: [u8; 24] = [0xc6; 24];
/// The test recovery seed.
const RECOVERY_SEED: [u8; 32] = [0xd7; 32];
/// The test seed of a relay instance key.
const RELAY_INSTANCE_SEED: [u8; 32] = [0xf1; 32];
/// The test seed of the service admission key that signs relay leases.
const SERVICE_ADMISSION_SEED: [u8; 32] = [0xf2; 32];
/// The test object key of the key wrap vector.
const OBJECT_KEY: [u8; 32] = [0xe8; 32];

/// The host's authorisation keypair in the vectors.
///
/// The fixture documents are checked against the same key material in Rust and in TypeScript, and
/// the seed constructors are crate-private, so the identities are exposed here rather than rebuilt
/// from raw bytes by a test.
///
/// # Errors
///
/// Returns an error when libsodium is unavailable.
pub fn host_authorisation_key() -> Result<AuthorisationKeyPair> {
    AuthorisationKeyPair::from_seed(AuthorisationSeed::from_stored_bytes(
        &HOST_AUTHORISATION_SEED,
    )?)
}

/// The client's authorisation keypair in the vectors.
///
/// # Errors
///
/// Returns an error when libsodium is unavailable.
pub fn client_authorisation_key() -> Result<AuthorisationKeyPair> {
    AuthorisationKeyPair::from_seed(AuthorisationSeed::from_stored_bytes(
        &CLIENT_AUTHORISATION_SEED,
    )?)
}

/// The envelope sender's stored-envelope keypair in the vectors.
///
/// # Errors
///
/// Returns an error when libsodium is unavailable.
pub fn envelope_sender_key() -> Result<StoredEnvelopeKeyPair> {
    StoredEnvelopeKeyPair::from_seed(StoredEnvelopeSeed::from_stored_bytes(
        &SENDER_ENVELOPE_SEED,
    )?)
}

/// The envelope recipient's stored-envelope keypair in the vectors.
///
/// # Errors
///
/// Returns an error when libsodium is unavailable.
pub fn envelope_recipient_key() -> Result<StoredEnvelopeKeyPair> {
    StoredEnvelopeKeyPair::from_seed(StoredEnvelopeSeed::from_stored_bytes(
        &RECIPIENT_ENVELOPE_SEED,
    )?)
}

/// The recovery seed in the vectors.
///
/// # Errors
///
/// Returns an error when libsodium is unavailable.
pub fn recovery_seed() -> Result<RecoverySeed> {
    RecoverySeed::from_stored_bytes(&RECOVERY_SEED)
}

/// Returns every generated fixture document as a file name and its exact contents.
///
/// `repository_root` is the directory that holds `fixtures/`, because the signature vectors read
/// the canonical bytes the protocol fixtures already publish.
///
/// # Errors
///
/// Returns an error when a source fixture cannot be read or parsed, or when libsodium fails.
pub fn generated_files(repository_root: &Path) -> Result<Vec<(&'static str, String)>> {
    Ok(vec![
        (SIGNATURES_FILE_NAME, render(&signatures(repository_root)?)),
        (ENVELOPES_FILE_NAME, render(&envelopes()?)),
        (KDF_FILE_NAME, render(&derivations()?)),
        (RELAY_FILE_NAME, render(&relay_signatures(repository_root)?)),
    ])
}

/// The relay tier's signatures over the objects in `fixtures/relay/`.
///
/// Two keys and four documents. The service admission key signs leases and revocations; the relay
/// instance key signs receipts and its own registration. A verifier in any language can take the
/// signing input the relay fixtures already publish, the public key here, and the signature, and
/// check all three agree — which is the whole of what a relay does before it forwards a payload,
/// and the whole of what the service does before it records a receipt.
fn relay_signatures(repository_root: &Path) -> Result<Value> {
    use kr_protocol::relay::{
        RELAY_INSTANCE_DOMAIN, RELAY_LEASE_DOMAIN, RELAY_RECEIPT_DOMAIN, RELAY_REVOKE_DOMAIN,
    };

    let instance = crate::relay::RelayInstanceKeyPair::from_seed_bytes(&RELAY_INSTANCE_SEED)?;
    let admission =
        crate::relay::ServiceAdmissionKeyPair::from_seed_bytes(&SERVICE_ADMISSION_SEED)?;

    let mut cases = Vec::new();
    for (file, source) in [
        ("fixtures/relay/leases.json", "relay/leases"),
        ("fixtures/relay/receipts.json", "relay/receipts"),
        ("fixtures/relay/instances.json", "relay/instances"),
    ] {
        let document = read_fixture(repository_root, file)?;
        let listed = document
            .get("cases")
            .and_then(Value::as_array)
            .ok_or_else(|| CryptoError::SecretStore {
                message: format!("{source} has no cases array"),
            })?;
        for case in listed {
            let id =
                case.get("id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| CryptoError::SecretStore {
                        message: format!("a case in {source} has no identifier"),
                    })?;
            let domain = case.get("domain").and_then(Value::as_str).ok_or_else(|| {
                CryptoError::SecretStore {
                    message: format!("case {id} in {source} names no domain"),
                }
            })?;
            let hex = case
                .get("signing_input_hex")
                .and_then(Value::as_str)
                .ok_or_else(|| CryptoError::SecretStore {
                    message: format!("case {id} in {source} has no signing input"),
                })?;
            let message = decode_hex(hex)?;
            let transcript = SigningTranscript::from_canonical_bytes(domain, message.clone())?;

            // The object names the key it is to be verified under. If that is not the key signing
            // it here, the vector would publish a signature that authorises nothing, so the seeds
            // and the relay fixtures are held to each other rather than drifting apart quietly.
            let named = case.get("json").and_then(|json| {
                json.get("issuer_key")
                    .or_else(|| json.get("instance_key"))
                    .and_then(Value::as_str)
            });
            if let Some(named) = named {
                let admission_public = admission.public();
                let expected = match domain {
                    RELAY_LEASE_DOMAIN | RELAY_REVOKE_DOMAIN => admission_public.as_bytes(),
                    _ => instance.public().as_bytes(),
                };
                if kr_protocol::scalars::to_base64url(expected) != named {
                    return Err(CryptoError::SecretStore {
                        message: format!(
                            "case {id} in {source} names a key the vectors do not sign with; \
                             regenerate fixtures/relay with {}",
                            kr_protocol::scalars::to_base64url(expected)
                        ),
                    });
                }
            }

            let (signer, signature) = match domain {
                RELAY_LEASE_DOMAIN | RELAY_REVOKE_DOMAIN => (
                    "service_admission",
                    crate::sign::sign(admission.inner(), &transcript)?,
                ),
                RELAY_RECEIPT_DOMAIN | RELAY_INSTANCE_DOMAIN => {
                    ("relay_instance", instance.sign_transcript(&transcript)?)
                }
                other => {
                    return Err(CryptoError::SecretStore {
                        message: format!(
                            "case {id} in {source} signs under an unknown domain {other}"
                        ),
                    });
                }
            };

            cases.push(json!({
                "id": format!("{source}:{id}"),
                "description": case.get("description").and_then(Value::as_str).unwrap_or_default(),
                "domain": domain,
                "signer": signer,
                "message_hex": hex,
                "message_sha256": hex::encode(kr_cbor::sha256(&message)),
                "signature_hex": hex::encode(signature.as_bytes()),
            }));
        }
    }

    Ok(json!({
        "name": "relay",
        "description": "Ed25519 signatures over the relay objects in fixtures/relay, by the two keys section 17 puts around a relay.",
        "note": "message_hex is the signing input the relay fixtures publish: CBOR([domain, object]). A verifier checks the signature against the named signer's public key and those exact bytes; it never re-encodes the object from its JSON representation to obtain them.",
        "signers": {
            "relay_instance": {
                "description": "The key one relay instance signs receipts and its own registration with. Generated on the host; this seed is test material.",
                "seed_hex": hex::encode(RELAY_INSTANCE_SEED),
                "public_key_hex": hex::encode(instance.public().as_bytes()),
            },
            "service_admission": {
                "description": "The key the managed service signs leases and revocations with, and which a relay pins.",
                "seed_hex": hex::encode(SERVICE_ADMISSION_SEED),
                "public_key_hex": hex::encode(admission.public().as_bytes()),
            },
        },
        "cases": cases,
    }))
}

fn render(value: &Value) -> String {
    let mut text = serde_json::to_string_pretty(value).expect("generated JSON is serialisable");
    text.push('\n');
    text
}

fn read_fixture(repository_root: &Path, relative: &str) -> Result<Value> {
    let path = repository_root.join(relative);
    let text = std::fs::read_to_string(&path).map_err(|error| CryptoError::SecretStore {
        message: format!("read {}: {error}", path.display()),
    })?;
    serde_json::from_str(&text).map_err(|error| CryptoError::SecretStore {
        message: format!("parse {}: {error}", path.display()),
    })
}

fn decode_hex(hex: &str) -> Result<Vec<u8>> {
    hex::decode(hex).map_err(|error| CryptoError::SecretStore {
        message: format!("a fixture hex string is malformed: {error}"),
    })
}

/// One case this crate signs, read out of a source fixture document.
struct SourceCase {
    /// The case identifier, prefixed by the document it came from.
    id: String,
    /// The description the source document gives it.
    description: String,
    /// The domain its canonical bytes are separated by.
    domain: String,
    /// Those canonical bytes.
    message: Vec<u8>,
}

/// Collects the signable cases from one source fixture document.
fn source_cases(document: &Value, list: &str, source: &str) -> Result<Vec<SourceCase>> {
    let cases = document
        .get(list)
        .and_then(Value::as_array)
        .ok_or_else(|| CryptoError::SecretStore {
            message: format!("{source} has no {list} array"),
        })?;
    let mut collected = Vec::with_capacity(cases.len());
    for case in cases {
        let id =
            case.get("id")
                .and_then(Value::as_str)
                .ok_or_else(|| CryptoError::SecretStore {
                    message: format!("a case in {source} has no identifier"),
                })?;
        let hex =
            case.get("hex")
                .and_then(Value::as_str)
                .ok_or_else(|| CryptoError::SecretStore {
                    message: format!("case {id} in {source} has no canonical bytes"),
                })?;
        let domain =
            case.get("domain")
                .and_then(Value::as_str)
                .ok_or_else(|| CryptoError::SecretStore {
                    message: format!("case {id} in {source} names no domain"),
                })?;
        collected.push(SourceCase {
            id: format!("{source}:{id}"),
            description: case
                .get("description")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            domain: domain.to_owned(),
            message: decode_hex(hex)?,
        });
    }
    Ok(collected)
}

fn signatures(repository_root: &Path) -> Result<Value> {
    let host = AuthorisationKeyPair::from_seed(AuthorisationSeed::from_stored_bytes(
        &HOST_AUTHORISATION_SEED,
    )?)?;
    let client = AuthorisationKeyPair::from_seed(AuthorisationSeed::from_stored_bytes(
        &CLIENT_AUTHORISATION_SEED,
    )?)?;

    let digests = read_fixture(repository_root, "fixtures/cbor/digests.json")?;
    let transcripts = read_fixture(repository_root, "fixtures/protocol/transcripts.json")?;
    // Only domain-separated transcripts are signed. `digest_cases` holds a complete mutation
    // object, which is hashed rather than signed: section 23 authenticates a live mutation through
    // the connection and its receipt digest, so signing that object here would publish a vector
    // for an operation the protocol does not perform.
    let mut sources = source_cases(&digests, "signing_input_cases", "cbor/digests")?;
    sources.extend(source_cases(&transcripts, "cases", "protocol/transcripts")?);

    let mut cases = Vec::with_capacity(sources.len());
    for case in &sources {
        let transcript =
            SigningTranscript::from_canonical_bytes(&case.domain, case.message.clone())?;
        let signature = crate::sign::sign(&host, &transcript)?;
        cases.push(json!({
            "id": case.id,
            "description": case.description,
            "domain": case.domain,
            "message_hex": hex::encode(&case.message),
            "message_sha256": hex::encode(kr_cbor::sha256(&case.message)),
            "signature_hex": hex::encode(signature.as_bytes()),
        }));
    }

    // RFC 8032 section 7.1 test vector 1, so a reader can confirm that this is standard Ed25519
    // and not a variant. It signs the empty message, which is not a transcript, so it goes through
    // the libsodium wrapper directly rather than through the signing interface.
    let rfc_seed = decode_hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")?;
    let rfc = AuthorisationKeyPair::from_seed(AuthorisationSeed::from_stored_bytes(&rfc_seed)?)?;
    let rfc_signature = sodium::sign_detached(b"", rfc_expanded(&rfc_seed)?.expose())?;

    Ok(json!({
        "name": "signatures",
        "description": "Ed25519 signatures over the canonical bytes the CBOR and protocol fixtures publish, plus the negative cases a verifier must reject.",
        "note": "Every signature is deterministic: Ed25519 derives its nonce from the key and the message. The seeds below are test material.",
        "keys": {
            "host": {
                "seed_hex": hex::encode(HOST_AUTHORISATION_SEED),
                "public_key_hex": hex::encode(host.public().as_bytes()),
                "key_id_hex": hex::encode(host.key_id().as_bytes()),
            },
            "client": {
                "seed_hex": hex::encode(CLIENT_AUTHORISATION_SEED),
                "public_key_hex": hex::encode(client.public().as_bytes()),
                "key_id_hex": hex::encode(client.key_id().as_bytes()),
            },
        },
        "key_id_domain": kr_protocol::pairing::KEY_ID_DOMAIN,
        "rfc_8032_test_vector_1": {
            "description": "RFC 8032 section 7.1 test vector 1: the empty message.",
            "seed_hex": hex::encode(&rfc_seed),
            "public_key_hex": hex::encode(rfc.public().as_bytes()),
            "message_hex": "",
            "signature_hex": hex::encode(rfc_signature),
        },
        "cases": cases,
        "connect_proofs": connect_proofs(&host, &client, &sources)?,
        "negative_cases": negative_cases(&host, &client, &sources[0].domain, &sources[0].message)?,
    }))
}

/// Returns the expanded Ed25519 secret key of a seed, for the one vector that signs raw bytes.
fn rfc_expanded(seed: &[u8]) -> Result<crate::secret::Secret<64>> {
    let seed: [u8; 32] = seed.try_into().map_err(|_| CryptoError::SecretStore {
        message: "an Ed25519 seed is 32 bytes".to_owned(),
    })?;
    let (_, mut expanded) = sodium::sign_seed_keypair(&seed)?;
    let held = crate::secret::Secret::from_bytes(expanded);
    sodium::memzero(&mut expanded);
    Ok(held)
}

/// Builds the mutual `kr-connect/1` proof over the published connection transcript.
///
/// Section 23 requires both proofs: one signature proves that one device signed the transcript, not
/// that the connection has two authorised ends. The vector publishes both so a TypeScript client
/// can check the pair it will receive.
fn connect_proofs(
    host: &AuthorisationKeyPair,
    client: &AuthorisationKeyPair,
    sources: &[SourceCase],
) -> Result<Value> {
    let case = sources
        .iter()
        .find(|case| case.domain == kr_protocol::hello::CONNECT_DOMAIN)
        .ok_or_else(|| CryptoError::SecretStore {
            message: "the protocol fixtures publish no kr-connect/1 transcript".to_owned(),
        })?;
    let transcript = SigningTranscript::from_canonical_bytes(&case.domain, case.message.clone())?;
    Ok(json!({
        "description": "Both kr-connect/1 proofs over the transcript fixtures/protocol/transcripts.json publishes. A verifier requires both.",
        "domain": case.domain,
        "transcript_hex": hex::encode(&case.message),
        "transcript_sha256": hex::encode(kr_cbor::sha256(&case.message)),
        "client_signature_hex": hex::encode(crate::sign::sign(client, &transcript)?.as_bytes()),
        "host_signature_hex": hex::encode(crate::sign::sign(host, &transcript)?.as_bytes()),
    }))
}

/// Builds the three cases a verifier must reject.
fn negative_cases(
    host: &AuthorisationKeyPair,
    client: &AuthorisationKeyPair,
    domain: &str,
    message: &[u8],
) -> Result<Value> {
    let transcript = SigningTranscript::from_canonical_bytes(domain, message.to_vec())?;
    let signature = crate::sign::sign(host, &transcript)?;
    Ok(json!([
        {
            "id": "wrong_key",
            "description": "The host signature over the first case, offered against the client public key. Verification must fail.",
            "message_hex": hex::encode(message),
            "public_key_hex": hex::encode(client.public().as_bytes()),
            "signature_hex": hex::encode(signature.as_bytes()),
        },
        {
            "id": "flipped_message_bit",
            "description": "The host signature over the first case, offered against that message with its last byte flipped. Verification must fail.",
            "message_hex": hex::encode(flip_last(message)),
            "public_key_hex": hex::encode(host.public().as_bytes()),
            "signature_hex": hex::encode(signature.as_bytes()),
        },
        {
            "id": "flipped_signature_bit",
            "description": "The host signature over the first case with its last byte flipped. Verification must fail.",
            "message_hex": hex::encode(message),
            "public_key_hex": hex::encode(host.public().as_bytes()),
            "signature_hex": hex::encode(flip_last(signature.as_bytes())),
        },
    ]))
}

fn flip_last(bytes: &[u8]) -> Vec<u8> {
    let mut flipped = bytes.to_vec();
    if let Some(last) = flipped.last_mut() {
        *last ^= 0x01;
    }
    flipped
}

fn envelope_plaintext(
    sender_key_id_hex: &str,
    recipient_key_id_hex: &str,
) -> Result<EnvelopePlaintext> {
    Ok(EnvelopePlaintext {
        version: EnvelopeVersion::V1,
        envelope_id: EnvelopeId::new(Uuid::from_bytes([0x21; 16])),
        sender_key_id: kr_protocol::scalars::KeyId::from_bytes(
            decode_hex(sender_key_id_hex)?
                .try_into()
                .map_err(|_| CryptoError::SecretStore {
                    message: "a key identifier is 32 bytes".to_owned(),
                })?,
        ),
        recipient_key_id: kr_protocol::scalars::KeyId::from_bytes(
            decode_hex(recipient_key_id_hex)?
                .try_into()
                .map_err(|_| CryptoError::SecretStore {
                    message: "a key identifier is 32 bytes".to_owned(),
                })?,
        ),
        payload_type: MailboxPayloadType::AuthorityFeedChange,
        created_at_ms: TimestampMs::new(1_764_000_000_000),
        expires_at_ms: TimestampMs::new(1_764_000_600_000),
        grant_id: Nullable::some(GrantId::new(Uuid::from_bytes([0x22; 16]))),
        environment_id: Nullable::some(EnvironmentId::new(Uuid::from_bytes([0x23; 16]))),
        session_id: Nullable::some(SessionId::new(Uuid::from_bytes([0x24; 16]))),
        session_epoch: Nullable::some(SessionEpoch::V1),
        payload: Bytes::new(b"kr-authority-feed-change".to_vec()),
    })
}

fn envelopes() -> Result<Value> {
    let sender = envelope_sender_key()?;
    let recipient = envelope_recipient_key()?;

    let plaintext = envelope_plaintext(
        &hex::encode(sender.key_id().as_bytes()),
        &hex::encode(recipient.key_id().as_bytes()),
    )?;
    let canonical = kr_cbor::to_canonical_vec(&plaintext)?;
    // A real envelope generates its own nonce, which a reproducible vector cannot use. The vector
    // therefore pads exactly as `seal_envelope` does and seals with a fixed nonce through the
    // libsodium wrapper. Everything a reader checks goes through the ordinary opening path.
    let (mut padded, bucket) = crate::envelope::pad_plaintext(&plaintext)?;
    let ciphertext = sodium::box_easy(
        &padded,
        &ENVELOPE_NONCE,
        recipient.public().as_bytes(),
        sender.secret().expose(),
    )?;
    sodium::memzero(&mut padded);
    let sealed_envelope = SealedEnvelope {
        routing: EnvelopeRouting {
            envelope_id: plaintext.envelope_id,
            recipient_key_id: plaintext.recipient_key_id,
            sender_key_id: plaintext.sender_key_id,
            expires_at_ms: plaintext.expires_at_ms,
            size_bucket_bytes: U64::new(bucket),
        },
        nonce: Nonce192::from_bytes(ENVELOPE_NONCE),
        ciphertext: Bytes::new(ciphertext),
    };

    let context = KeyWrapContext {
        format: KeyWrapFormat::V1,
        purpose: KeyWrapPurpose::ManifestKey,
        archive_id: ArchiveId::new(Uuid::from_bytes([0x31; 16])),
        backup_generation: BackupGeneration::new(4),
        object_id: BackupObjectId::new(Uuid::from_bytes([0x32; 16])),
        encrypted_object_hash: Digest256::from_bytes([0x33; 32]),
        sender_key_id: sender.key_id(),
        recipient_key_id: recipient.key_id(),
    };
    let mut wrap_plaintext = key_wrap_plaintext(&context, &OBJECT_KEY)?;
    let wrap_ciphertext = sodium::box_easy(
        &wrap_plaintext,
        &KEY_WRAP_NONCE,
        recipient.public().as_bytes(),
        sender.secret().expose(),
    )?;
    sodium::memzero(&mut wrap_plaintext);
    let wrap = SealedKeyWrap {
        context: context.clone(),
        nonce: Nonce192::from_bytes(KEY_WRAP_NONCE),
        ciphertext: Bytes::new(wrap_ciphertext),
    };

    Ok(json!({
        "name": "envelopes",
        "description": "Mailbox envelope and backup key wrap encodings, sealed with crypto_box_easy under fixed test keys and nonces.",
        "note": "A real envelope and a real key wrap always use a fresh random 24-byte nonce. These nonces are fixed so the vector is reproducible; the padding, the encodings and the checks are the ordinary ones.",
        "keys": {
            "sender": {
                "seed_hex": hex::encode(SENDER_ENVELOPE_SEED),
                "public_key_hex": hex::encode(sender.public().as_bytes()),
                "key_id_hex": hex::encode(sender.key_id().as_bytes()),
            },
            "recipient": {
                "seed_hex": hex::encode(RECIPIENT_ENVELOPE_SEED),
                "public_key_hex": hex::encode(recipient.public().as_bytes()),
                "key_id_hex": hex::encode(recipient.key_id().as_bytes()),
            },
        },
        "envelope": {
            "description": "One mailbox envelope: its authenticated plaintext, that plaintext's canonical encoding, and the sealed object a recipient opens.",
            "plaintext_json": serde_json::to_value(&plaintext).expect("an envelope is serialisable"),
            "canonical_hex": hex::encode(&canonical),
            "canonical_sha256": hex::encode(kr_cbor::sha256(&canonical)),
            "padded_len": bucket,
            "opened_at_ms": plaintext.created_at_ms.get(),
            "sealed_json": serde_json::to_value(&sealed_envelope).expect("a sealed envelope is serialisable"),
        },
        "key_wrap": {
            "description": "One manifest key wrap: CBOR([context, object_key]) sealed for the recipient.",
            "object_key_hex": hex::encode(OBJECT_KEY),
            "context_json": serde_json::to_value(&context).expect("a context is serialisable"),
            "canonical_hex": hex::encode(key_wrap_plaintext(&context, &OBJECT_KEY)?),
            "sealed_json": serde_json::to_value(&wrap).expect("a wrap is serialisable"),
        },
        "size_buckets": {
            "description": "The declared size buckets of section 20. A plaintext is padded to its bucket before encryption, so the bucket is always strictly larger than the plaintext. Quota accounting measures the complete stored ciphertext.",
            "notification": [
                {"plaintext_bytes": 0, "bucket_bytes": notification_size_bucket(0)},
                {"plaintext_bytes": 1, "bucket_bytes": notification_size_bucket(1)},
                {"plaintext_bytes": 1024, "bucket_bytes": notification_size_bucket(1024)},
                {"plaintext_bytes": 1025, "bucket_bytes": notification_size_bucket(1025)},
            ],
            "mailbox": [
                {"plaintext_bytes": 1, "bucket_bytes": mailbox_size_bucket(1)},
                {"plaintext_bytes": 16384, "bucket_bytes": mailbox_size_bucket(16384)},
                {"plaintext_bytes": 16385, "bucket_bytes": mailbox_size_bucket(16385)},
                {"plaintext_bytes": 65536, "bucket_bytes": mailbox_size_bucket(65536)},
                {"plaintext_bytes": 65537, "bucket_bytes": mailbox_size_bucket(65537)},
                {"plaintext_bytes": 204800, "bucket_bytes": mailbox_size_bucket(204800)},
            ],
        },
    }))
}

/// The retrieval context of the recovery vector.
fn recovery_context() -> RecoveryContext {
    RecoveryContext {
        service_origin: "https://reach.kala.to".to_owned(),
        bundle_locator: "kr-recovery-vector-locator".to_owned(),
    }
}

fn derivations() -> Result<Value> {
    let seed = recovery_seed()?;
    let bundle_key = seed.bundle_key()?;
    let recipient = seed.recipient()?;

    let ikm = [0x0bu8; 22];
    let salt: Vec<u8> = (0u8..=0x0c).collect();
    let info: Vec<u8> = (0xf0u8..=0xf9).collect();
    let rfc_5869 = kdf::hkdf_sha256(&ikm, &salt, &info)?;

    let hmac_key = SymmetricKey::from_bytes([0x4a; 32]);
    let hmac_tag = kdf::hmac_sha256(&hmac_key, b"kr-crypto vector message");

    Ok(json!({
        "name": "kdf",
        "description": "Key derivation vectors: RFC 5869 HKDF-SHA256, HMAC-SHA256 and the KRRECOV1 recovery subkeys.",
        "note": "The recovery seed below is test material. A real seed is 256 random bits from libsodium.",
        "hkdf_sha256": {
            "description": "RFC 5869 appendix A.1, truncated to the 32-byte output this build derives.",
            "ikm_hex": hex::encode(ikm),
            "salt_hex": hex::encode(&salt),
            "info_hex": hex::encode(&info),
            "okm_hex": hex::encode(rfc_5869.expose()),
        },
        "hmac_sha256": {
            "description": "HMAC-SHA256 under a fixed 32-byte key.",
            "key_hex": hex::encode(hmac_key.expose()),
            "message_utf8": "kr-crypto vector message",
            "tag_hex": hex::encode(hmac_tag.as_bytes()),
        },
        "recovery": {
            "description": "libsodium crypto_kdf with context KRRECOV1: subkey 1 is the recovery-bundle key and subkey 2 seeds the recovery recipient's crypto_box keypair.",
            "context_binding": {
                "description": "The key a bundle is actually encrypted under: HKDF-SHA256 over the subkey-1 key, salted with the canonical retrieval context. A bundle served from another origin or under another locator does not authenticate.",
                "context_json": serde_json::to_value(recovery_context()).expect("a context is serialisable"),
                "context_salt_hex": hex::encode(recovery_context().to_canonical_bytes()?),
                "bundle_key_hex": hex::encode(seed.bundle_key_for(&recovery_context())?.expose()),
            },
            "context": kr_protocol::archive::RECOVERY_KDF_CONTEXT,
            "seed_hex": hex::encode(RECOVERY_SEED),
            "seed_checksum_hex": hex::encode(seed.checksum()),
            "bundle_subkey_id": kr_protocol::archive::RECOVERY_BUNDLE_SUBKEY_ID,
            "bundle_key_hex": hex::encode(bundle_key.expose()),
            "recipient_subkey_id": kr_protocol::archive::RECOVERY_RECIPIENT_SUBKEY_ID,
            "recipient_public_key_hex": hex::encode(recipient.public().as_bytes()),
            "recipient_key_id_hex": hex::encode(
                key_id(KeyPurpose::StoredEnvelope, recipient.public().as_bytes()).as_bytes()
            ),
        },
    }))
}
