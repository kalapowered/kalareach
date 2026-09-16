//! The committed vectors under `fixtures/crypto/` must be reproducible from the Rust code.
//!
//! The TypeScript package checks the same documents with the Node runtime's own primitives, so a
//! value that drifts in one language fails in both.
//!
//! Everything here goes through the crate's public interface. The libsodium boundary is private,
//! so a test cannot reach a raw primitive any more than a caller can.

use std::path::{Path, PathBuf};

use kr_crypto::keys::key_id;
use kr_crypto::secret::SymmetricKey;
use kr_crypto::sign::SigningTranscript;
use kr_crypto::vectors::{
    client_authorisation_key, envelope_recipient_key, envelope_sender_key, generated_files,
    host_authorisation_key, recovery_seed,
};
use kr_crypto::{archive, envelope, kdf, sign};
use kr_protocol::archive::{KeyWrapContext, SealedKeyWrap};
use kr_protocol::mailbox::{SealedEnvelope, mailbox_size_bucket, notification_size_bucket};
use kr_protocol::pairing::KeyPurpose;
use kr_protocol::scalars::{
    AuthorisationKey, Mac256, RelayInstanceKey, ServiceAdmissionKey, Signature64,
};
use serde_json::Value;

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn fixture(name: &str) -> Value {
    let path = repository_root().join("fixtures/crypto").join(name);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    serde_json::from_str(&text).expect("a fixture is JSON")
}

fn bytes(value: &Value, pointer: &str) -> Vec<u8> {
    let hex = value
        .pointer(pointer)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{pointer} is a hex string"));
    hex::decode(hex).expect("a fixture hex string decodes")
}

fn fixed<const N: usize>(value: &Value, pointer: &str) -> [u8; N] {
    <[u8; N]>::try_from(bytes(value, pointer).as_slice())
        .unwrap_or_else(|_| panic!("{pointer} is {N} bytes"))
}

#[test]
fn the_committed_vectors_match_the_rust_code() {
    let root = repository_root();
    for (name, expected) in generated_files(&root).expect("the vectors are generated") {
        let path = root.join("fixtures/crypto").join(name);
        let actual = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
        assert_eq!(
            actual,
            expected,
            "{} is out of date; run `cargo run -p kr-crypto --bin kr-crypto-vectors`",
            path.display()
        );
    }
}

#[test]
fn generation_is_deterministic() {
    let root = repository_root();
    assert_eq!(
        generated_files(&root).expect("the vectors are generated"),
        generated_files(&root).expect("the vectors are generated")
    );
}

#[test]
fn every_signature_vector_verifies_and_every_negative_case_fails() {
    let document = fixture("signatures.json");
    let host = host_authorisation_key().expect("the host key");
    let client = client_authorisation_key().expect("the client key");
    assert_eq!(
        host.public().as_bytes(),
        &fixed::<32>(&document, "/keys/host/public_key_hex")
    );
    assert_eq!(
        host.key_id().as_bytes(),
        &fixed::<32>(&document, "/keys/host/key_id_hex")
    );
    assert_eq!(
        client.public().as_bytes(),
        &fixed::<32>(&document, "/keys/client/public_key_hex")
    );

    let cases = document["cases"].as_array().expect("cases");
    assert!(!cases.is_empty(), "the vector covers the published bytes");
    for case in cases {
        let message = hex::decode(case["message_hex"].as_str().expect("a message")).expect("hex");
        let domain = case["domain"].as_str().expect("a domain");
        // The bytes are accepted as a transcript only because they are a domain-separated array.
        let transcript =
            SigningTranscript::from_canonical_bytes(domain, message).expect("a transcript");
        assert_eq!(
            transcript.digest().as_bytes(),
            &fixed::<32>(case, "/message_sha256")
        );
        let signature = Signature64::from_bytes(fixed(case, "/signature_hex"));
        assert!(
            sign::verify(host.public(), &transcript, &signature).is_ok(),
            "case {} does not verify",
            case["id"]
        );
        // Signing it again gives the same bytes: Ed25519 is deterministic.
        assert_eq!(
            sign::sign(&host, &transcript).expect("a signature"),
            signature
        );
    }

    let domain = cases[0]["domain"].as_str().expect("a domain");
    for case in document["negative_cases"]
        .as_array()
        .expect("negative cases")
    {
        let message = hex::decode(case["message_hex"].as_str().expect("a message")).expect("hex");
        let public = AuthorisationKey::from_bytes(fixed(case, "/public_key_hex"));
        let signature = Signature64::from_bytes(fixed(case, "/signature_hex"));
        let Ok(transcript) = SigningTranscript::from_canonical_bytes(domain, message) else {
            // A flipped byte can break the encoding as well as the signature; either way the case
            // is rejected, which is what it is there to show.
            continue;
        };
        assert!(
            sign::verify(&public, &transcript, &signature).is_err(),
            "negative case {} verified",
            case["id"]
        );
    }
}

#[test]
fn the_connection_proof_vector_needs_both_signatures() {
    let document = fixture("signatures.json");
    let host = host_authorisation_key().expect("the host key");
    let client = client_authorisation_key().expect("the client key");
    let transcript = SigningTranscript::from_canonical_bytes(
        document["connect_proofs"]["domain"]
            .as_str()
            .expect("a domain"),
        bytes(&document, "/connect_proofs/transcript_hex"),
    )
    .expect("the connection transcript");
    assert_eq!(
        transcript.digest().as_bytes(),
        &fixed::<32>(&document, "/connect_proofs/transcript_sha256")
    );

    let client_proof =
        Signature64::from_bytes(fixed(&document, "/connect_proofs/client_signature_hex"));
    let host_proof =
        Signature64::from_bytes(fixed(&document, "/connect_proofs/host_signature_hex"));
    assert!(sign::verify(client.public(), &transcript, &client_proof).is_ok());
    assert!(sign::verify(host.public(), &transcript, &host_proof).is_ok());

    // Neither proof stands in for the other: a holder of one transport key cannot substitute the
    // authorised application identity.
    assert!(sign::verify(host.public(), &transcript, &client_proof).is_err());
    assert!(sign::verify(client.public(), &transcript, &host_proof).is_err());
}

#[test]
fn the_rfc_8032_vector_confirms_standard_ed25519() {
    let document = fixture("signatures.json");
    // RFC 8032 section 7.1 test vector 1: the public key of that seed and its signature over the
    // empty message, reproduced by this build's key derivation.
    assert_eq!(
        hex::encode(bytes(&document, "/rfc_8032_test_vector_1/public_key_hex")),
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    );
    assert_eq!(
        hex::encode(bytes(&document, "/rfc_8032_test_vector_1/signature_hex")),
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    );
}

#[test]
fn the_envelope_vector_opens_and_its_declared_bucket_holds() {
    let document = fixture("envelopes.json");
    let sender = envelope_sender_key().expect("the sender key");
    let recipient = envelope_recipient_key().expect("the recipient key");
    assert_eq!(
        sender.public().as_bytes(),
        &fixed::<32>(&document, "/keys/sender/public_key_hex")
    );
    assert_eq!(
        recipient.key_id().as_bytes(),
        &fixed::<32>(&document, "/keys/recipient/key_id_hex")
    );

    let sealed: SealedEnvelope =
        serde_json::from_value(document["envelope"]["sealed_json"].clone())
            .expect("a sealed envelope");
    let opened = envelope::open_envelope(
        &recipient,
        sender.public(),
        &sealed,
        document["envelope"]["opened_at_ms"]
            .as_u64()
            .expect("an instant"),
        |_| Ok(()),
    )
    .expect("the envelope opens");

    let canonical = bytes(&document, "/envelope/canonical_hex");
    assert_eq!(
        kr_cbor::to_canonical_vec(&opened).expect("canonical bytes"),
        canonical,
        "the envelope re-encodes to the bytes the vector publishes"
    );
    assert_eq!(
        kr_cbor::sha256(&canonical).as_slice(),
        bytes(&document, "/envelope/canonical_sha256").as_slice()
    );
    assert_eq!(
        sealed.routing.size_bucket_bytes.get(),
        mailbox_size_bucket(canonical.len() as u64)
    );
    // The stored ciphertext is the bucket plus the box's own 16-byte tag, not the plaintext plus a
    // constant, so two envelopes in one bucket are the same size on the wire.
    assert_eq!(
        sealed.ciphertext.len() as u64,
        sealed.routing.size_bucket_bytes.get() + 16
    );
    assert!(sealed.ciphertext.len() as u64 > canonical.len() as u64 + 16);
}

#[test]
fn the_key_wrap_vector_opens_for_its_recipient_only() {
    let document = fixture("envelopes.json");
    let sender = envelope_sender_key().expect("the sender key");
    let recipient = envelope_recipient_key().expect("the recipient key");
    let wrap: SealedKeyWrap =
        serde_json::from_value(document["key_wrap"]["sealed_json"].clone()).expect("a wrap");
    let context: KeyWrapContext =
        serde_json::from_value(document["key_wrap"]["context_json"].clone()).expect("a context");

    let key = archive::unwrap_object_key(&recipient, sender.public(), &wrap, &context)
        .expect("the wrap opens");
    assert_eq!(
        key.expose(),
        &fixed::<32>(&document, "/key_wrap/object_key_hex")
    );

    let canonical =
        kr_protocol::archive::key_wrap_plaintext(&context, key.expose()).expect("the plaintext");
    assert_eq!(canonical, bytes(&document, "/key_wrap/canonical_hex"));

    // The sender is not the recipient, even though crypto_box opens in both directions.
    assert!(archive::unwrap_object_key(&sender, recipient.public(), &wrap, &context).is_err());
}

#[test]
fn the_derivation_vectors_recompute() {
    let document = fixture("kdf.json");
    let okm = kdf::hkdf_sha256(
        &bytes(&document, "/hkdf_sha256/ikm_hex"),
        &bytes(&document, "/hkdf_sha256/salt_hex"),
        &bytes(&document, "/hkdf_sha256/info_hex"),
    )
    .expect("an output key");
    assert_eq!(
        okm.expose(),
        &fixed::<32>(&document, "/hkdf_sha256/okm_hex")
    );
    // RFC 5869 appendix A.1, so a reader can confirm this is standard HKDF-SHA256.
    assert_eq!(
        hex::encode(okm.expose()),
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
    );

    let key = SymmetricKey::from_bytes(fixed(&document, "/hmac_sha256/key_hex"));
    let message = document["hmac_sha256"]["message_utf8"]
        .as_str()
        .expect("a message");
    let tag = kdf::hmac_sha256(&key, message.as_bytes());
    assert_eq!(
        tag.as_bytes(),
        &fixed::<32>(&document, "/hmac_sha256/tag_hex")
    );
    assert!(
        kdf::verify_hmac_sha256(
            &key,
            message.as_bytes(),
            &Mac256::from_bytes(fixed(&document, "/hmac_sha256/tag_hex"))
        )
        .is_ok()
    );

    let seed = recovery_seed().expect("the recovery seed");
    assert_eq!(
        seed.checksum().as_slice(),
        bytes(&document, "/recovery/seed_checksum_hex").as_slice()
    );
    assert_eq!(
        seed.bundle_key().expect("a bundle key").expose(),
        &fixed::<32>(&document, "/recovery/bundle_key_hex")
    );
    let recipient = seed.recipient().expect("a recovery recipient");
    assert_eq!(
        recipient.public().as_bytes(),
        &fixed::<32>(&document, "/recovery/recipient_public_key_hex")
    );
    assert_eq!(
        key_id(KeyPurpose::StoredEnvelope, recipient.public().as_bytes()).as_bytes(),
        &fixed::<32>(&document, "/recovery/recipient_key_id_hex")
    );
    assert_eq!(
        document["recovery"]["context"].as_str(),
        Some(kr_protocol::archive::RECOVERY_KDF_CONTEXT)
    );

    // The context-bound key differs from the master bundle key, which is what makes an origin or
    // locator substitution fail.
    let context: kr_protocol::archive::RecoveryContext =
        serde_json::from_value(document["recovery"]["context_binding"]["context_json"].clone())
            .expect("a retrieval context");
    let bound = seed.bundle_key_for(&context).expect("a key");
    assert_eq!(
        bound.expose(),
        &fixed::<32>(&document, "/recovery/context_binding/bundle_key_hex")
    );
    assert!(!bound.constant_time_eq(&seed.bundle_key().expect("a bundle key")));
    assert_eq!(
        context.to_canonical_bytes().expect("the salt"),
        bytes(&document, "/recovery/context_binding/context_salt_hex")
    );
}

#[test]
fn the_size_bucket_vector_matches_the_published_rule() {
    let document = fixture("envelopes.json");
    for case in document["size_buckets"]["mailbox"]
        .as_array()
        .expect("mailbox buckets")
    {
        let plaintext = case["plaintext_bytes"].as_u64().expect("a size");
        let bucket = case["bucket_bytes"].as_u64().expect("a bucket");
        assert_eq!(
            mailbox_size_bucket(plaintext),
            bucket,
            "bucket for {plaintext} bytes"
        );
        assert!(bucket > plaintext, "the bucket leaves room for padding");
    }
    for case in document["size_buckets"]["notification"]
        .as_array()
        .expect("notification buckets")
    {
        let plaintext = case["plaintext_bytes"].as_u64().expect("a size");
        assert_eq!(
            notification_size_bucket(plaintext),
            case["bucket_bytes"].as_u64().expect("a bucket"),
            "bucket for {plaintext} bytes"
        );
    }
}

#[test]
fn every_relay_vector_verifies_under_the_key_its_signer_names() {
    let document = fixture("relay.json");
    let relay =
        RelayInstanceKey::from_bytes(fixed(&document, "/signers/relay_instance/public_key_hex"));
    let admission = ServiceAdmissionKey::from_bytes(fixed(
        &document,
        "/signers/service_admission/public_key_hex",
    ));

    let cases = document["cases"].as_array().expect("cases");
    assert!(!cases.is_empty(), "the vector covers the relay objects");

    for case in cases {
        let message = hex::decode(case["message_hex"].as_str().expect("a message")).expect("hex");
        let domain = case["domain"].as_str().expect("a domain");
        let transcript = SigningTranscript::from_canonical_bytes(domain, message.clone())
            .expect("a domain-separated transcript");
        assert_eq!(
            transcript.digest().as_bytes(),
            &fixed::<32>(case, "/message_sha256")
        );
        let signature = Signature64::from_bytes(fixed(case, "/signature_hex"));

        match case["signer"].as_str().expect("a signer") {
            "relay_instance" => {
                relay_keys::verify_relay_object_bytes(&relay, &transcript, &signature)
                    .unwrap_or_else(|error| panic!("case {} does not verify: {error}", case["id"]));
                // The other key does not answer for it: the two are separate authorities, not two
                // spellings of one.
                assert!(
                    relay_keys::verify_admission_object_bytes(&admission, &transcript, &signature)
                        .is_err(),
                    "case {} verified under the admission key",
                    case["id"]
                );
            }
            "service_admission" => {
                relay_keys::verify_admission_object_bytes(&admission, &transcript, &signature)
                    .unwrap_or_else(|error| panic!("case {} does not verify: {error}", case["id"]));
                assert!(
                    relay_keys::verify_relay_object_bytes(&relay, &transcript, &signature).is_err(),
                    "case {} verified under the instance key",
                    case["id"]
                );
            }
            other => panic!("case {} names an unknown signer {other}", case["id"]),
        }
    }
}

/// The relay verifiers, reached the way a caller outside this crate reaches them.
mod relay_keys {
    use kr_crypto::Result;
    use kr_crypto::sign::{SigningTranscript, verify};
    use kr_protocol::scalars::{
        AuthorisationKey, RelayInstanceKey, ServiceAdmissionKey, Signature64,
    };

    pub fn verify_relay_object_bytes(
        key: &RelayInstanceKey,
        transcript: &SigningTranscript,
        signature: &Signature64,
    ) -> Result<()> {
        verify(
            &AuthorisationKey::from_bytes(*key.as_bytes()),
            transcript,
            signature,
        )
    }

    pub fn verify_admission_object_bytes(
        key: &ServiceAdmissionKey,
        transcript: &SigningTranscript,
        signature: &Signature64,
    ) -> Result<()> {
        verify(
            &AuthorisationKey::from_bytes(*key.as_bytes()),
            transcript,
            signature,
        )
    }
}
