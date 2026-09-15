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

use kr_protocol::archive::{KeyWrapContext, KeyWrapFormat, KeyWrapPurpose, key_wrap_plaintext};
use kr_protocol::ids::{
    ArchiveId, BackupGeneration, BackupObjectId, EnvelopeId, EnvironmentId, GrantId, SessionEpoch,
    SessionId,
};
use kr_protocol::mailbox::{
    EnvelopePlaintext, EnvelopeVersion, MailboxPayloadType, mailbox_size_bucket,
    notification_size_bucket,
};
use kr_protocol::pairing::KeyPurpose;
use kr_protocol::scalars::{Bytes, Digest256, Nullable, TimestampMs, Uuid};
use serde_json::{Value, json};

use crate::error::{CryptoError, Result};
use crate::kdf::{self, RecoverySeed};
use crate::keys::{
    AuthorisationKeyPair, AuthorisationSeed, StoredEnvelopeKeyPair, StoredEnvelopeSeed, key_id,
};
use crate::secret::SymmetricKey;
use crate::sodium;

/// The Ed25519 signature vectors.
pub const SIGNATURES_FILE_NAME: &str = "signatures.json";

/// The mailbox envelope and key wrap vectors.
pub const ENVELOPES_FILE_NAME: &str = "envelopes.json";

/// The key derivation vectors.
pub const KDF_FILE_NAME: &str = "kdf.json";

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
/// The test object key of the key wrap vector.
const OBJECT_KEY: [u8; 32] = [0xe8; 32];

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
    ])
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

/// Collects `(id, description, canonical bytes)` from one source fixture document.
fn source_cases(
    document: &Value,
    list: &str,
    source: &str,
) -> Result<Vec<(String, String, Vec<u8>)>> {
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
        collected.push((
            format!("{source}:{id}"),
            case.get("description")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            decode_hex(hex)?,
        ));
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
    let mut sources = source_cases(&digests, "digest_cases", "cbor/digests")?;
    sources.extend(source_cases(
        &digests,
        "signing_input_cases",
        "cbor/digests",
    )?);
    sources.extend(source_cases(&transcripts, "cases", "protocol/transcripts")?);

    let mut cases = Vec::with_capacity(sources.len());
    for (id, description, message) in &sources {
        let signature = crate::sign::sign_bytes(&host, message)?;
        cases.push(json!({
            "id": id,
            "description": description,
            "message_hex": hex::encode(message),
            "signature_hex": hex::encode(signature.as_bytes()),
        }));
    }

    // RFC 8032 section 7.1 test vector 1, so a reader can confirm that this is standard Ed25519
    // and not a variant.
    let rfc_seed = decode_hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")?;
    let rfc = AuthorisationKeyPair::from_seed(AuthorisationSeed::from_stored_bytes(&rfc_seed)?)?;
    let rfc_signature = crate::sign::sign_bytes(&rfc, b"")?;

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
            "signature_hex": hex::encode(rfc_signature.as_bytes()),
        },
        "cases": cases,
        "negative_cases": [
            {
                "id": "wrong_key",
                "description": "The host signature over the first case, offered against the client public key. Verification must fail.",
                "message_hex": hex::encode(&sources[0].2),
                "public_key_hex": hex::encode(client.public().as_bytes()),
                "signature_hex": hex::encode(crate::sign::sign_bytes(&host, &sources[0].2)?.as_bytes()),
            },
            {
                "id": "flipped_message_bit",
                "description": "The host signature over the first case, offered against that message with its last byte flipped. Verification must fail.",
                "message_hex": hex::encode(flip_last(&sources[0].2)),
                "public_key_hex": hex::encode(host.public().as_bytes()),
                "signature_hex": hex::encode(crate::sign::sign_bytes(&host, &sources[0].2)?.as_bytes()),
            },
            {
                "id": "flipped_signature_bit",
                "description": "The host signature over the first case with its last byte flipped. Verification must fail.",
                "message_hex": hex::encode(&sources[0].2),
                "public_key_hex": hex::encode(host.public().as_bytes()),
                "signature_hex": hex::encode(flip_last(crate::sign::sign_bytes(&host, &sources[0].2)?.as_bytes())),
            },
        ],
    }))
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
    let sender = StoredEnvelopeKeyPair::from_seed(StoredEnvelopeSeed::from_stored_bytes(
        &SENDER_ENVELOPE_SEED,
    )?)?;
    let recipient = StoredEnvelopeKeyPair::from_seed(StoredEnvelopeSeed::from_stored_bytes(
        &RECIPIENT_ENVELOPE_SEED,
    )?)?;

    let plaintext = envelope_plaintext(
        &hex::encode(sender.key_id().as_bytes()),
        &hex::encode(recipient.key_id().as_bytes()),
    )?;
    let encoded = kr_cbor::to_canonical_vec(&plaintext)?;
    let ciphertext = sodium::box_easy(
        &encoded,
        &ENVELOPE_NONCE,
        recipient.public().as_bytes(),
        sender.secret().expose(),
    )?;

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
    let wrap_plaintext = key_wrap_plaintext(&context, &OBJECT_KEY)?;
    let wrap_ciphertext = sodium::box_easy(
        &wrap_plaintext,
        &KEY_WRAP_NONCE,
        recipient.public().as_bytes(),
        sender.secret().expose(),
    )?;

    Ok(json!({
        "name": "envelopes",
        "description": "Mailbox envelope and backup key wrap encodings, with crypto_box_easy output under fixed test keys and nonces.",
        "note": "A real envelope and a real key wrap always use a fresh random 24-byte nonce. These nonces are fixed so the vector is reproducible.",
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
            "description": "The authenticated plaintext of one mailbox envelope, its canonical encoding and its crypto_box_easy ciphertext.",
            "plaintext_json": serde_json::to_value(&plaintext).expect("an envelope is serialisable"),
            "canonical_hex": hex::encode(&encoded),
            "canonical_sha256": hex::encode(kr_cbor::sha256(&encoded)),
            "nonce_hex": hex::encode(ENVELOPE_NONCE),
            "ciphertext_hex": hex::encode(&ciphertext),
            "declared_size_bucket_bytes": mailbox_size_bucket(encoded.len() as u64),
        },
        "key_wrap": {
            "description": "The authenticated plaintext of one manifest key wrap, CBOR([context, object_key]), and its crypto_box_easy ciphertext.",
            "object_key_hex": hex::encode(OBJECT_KEY),
            "context_json": serde_json::to_value(&context).expect("a context is serialisable"),
            "canonical_hex": hex::encode(&wrap_plaintext),
            "nonce_hex": hex::encode(KEY_WRAP_NONCE),
            "ciphertext_hex": hex::encode(&wrap_ciphertext),
        },
        "size_buckets": {
            "description": "The declared size buckets of section 20. Quota accounting measures the complete stored ciphertext, not these.",
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

fn derivations() -> Result<Value> {
    let seed = RecoverySeed::from_stored_bytes(&RECOVERY_SEED)?;
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
