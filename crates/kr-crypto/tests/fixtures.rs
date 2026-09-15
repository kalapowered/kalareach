//! The committed vectors under `fixtures/crypto/` must be reproducible from the Rust code.
//!
//! The TypeScript package checks the same documents, so a value that drifts in one language fails
//! in both.

use std::path::{Path, PathBuf};

use kr_crypto::kdf::{self, RecoverySeed};
use kr_crypto::keys::{
    AuthorisationKeyPair, AuthorisationSeed, StoredEnvelopeKeyPair, StoredEnvelopeSeed, key_id,
};
use kr_crypto::secret::SymmetricKey;
use kr_crypto::vectors::generated_files;
use kr_crypto::{sign, sodium};
use kr_protocol::mailbox::EnvelopePlaintext;
use kr_protocol::pairing::KeyPurpose;
use kr_protocol::scalars::{AuthorisationKey, Mac256, Signature64};
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
    let host = AuthorisationKey::from_bytes(fixed(&document, "/keys/host/public_key_hex"));
    assert_eq!(
        key_id(KeyPurpose::Authorisation, host.as_bytes()).as_bytes(),
        &fixed::<32>(&document, "/keys/host/key_id_hex")
    );

    let cases = document["cases"].as_array().expect("cases");
    assert!(!cases.is_empty(), "the vector covers the published bytes");
    for case in cases {
        let message = hex::decode(case["message_hex"].as_str().expect("a message")).expect("hex");
        let signature = Signature64::from_bytes(fixed(case, "/signature_hex"));
        assert!(
            sign::verify_bytes(&host, &message, &signature).is_ok(),
            "case {} does not verify",
            case["id"]
        );
    }

    for case in document["negative_cases"]
        .as_array()
        .expect("negative cases")
    {
        let message = hex::decode(case["message_hex"].as_str().expect("a message")).expect("hex");
        let public = AuthorisationKey::from_bytes(fixed(case, "/public_key_hex"));
        let signature = Signature64::from_bytes(fixed(case, "/signature_hex"));
        assert!(
            sign::verify_bytes(&public, &message, &signature).is_err(),
            "negative case {} verified",
            case["id"]
        );
    }
}

#[test]
fn the_rfc_8032_vector_confirms_standard_ed25519() {
    let document = fixture("signatures.json");
    let seed =
        AuthorisationSeed::from_stored_bytes(&bytes(&document, "/rfc_8032_test_vector_1/seed_hex"))
            .expect("a seed");
    let key = AuthorisationKeyPair::from_seed(seed).expect("a keypair");
    assert_eq!(
        key.public().as_bytes(),
        &fixed::<32>(&document, "/rfc_8032_test_vector_1/public_key_hex")
    );
    let signature = sign::sign_bytes(&key, b"").expect("a signature");
    assert_eq!(
        signature.as_bytes(),
        &fixed::<64>(&document, "/rfc_8032_test_vector_1/signature_hex")
    );
}

#[test]
fn the_envelope_vector_reproduces_its_canonical_bytes_and_ciphertext() {
    let document = fixture("envelopes.json");
    let sender = StoredEnvelopeKeyPair::from_seed(
        StoredEnvelopeSeed::from_stored_bytes(&bytes(&document, "/keys/sender/seed_hex"))
            .expect("a seed"),
    )
    .expect("a keypair");
    let recipient = StoredEnvelopeKeyPair::from_seed(
        StoredEnvelopeSeed::from_stored_bytes(&bytes(&document, "/keys/recipient/seed_hex"))
            .expect("a seed"),
    )
    .expect("a keypair");
    assert_eq!(
        sender.public().as_bytes(),
        &fixed::<32>(&document, "/keys/sender/public_key_hex")
    );

    let canonical = bytes(&document, "/envelope/canonical_hex");
    let plaintext: EnvelopePlaintext =
        kr_cbor::from_canonical_slice(&canonical, &kr_cbor::Limits::DEFAULT)
            .expect("the vector is a valid envelope");
    assert_eq!(
        kr_cbor::to_canonical_vec(&plaintext).expect("canonical bytes"),
        canonical,
        "the envelope re-encodes to the bytes it arrived in"
    );
    assert_eq!(
        kr_cbor::sha256(&canonical).as_slice(),
        bytes(&document, "/envelope/canonical_sha256").as_slice()
    );

    // The vector uses a fixed nonce, which the ordinary sealing functions never accept, so the
    // check goes through the wrapper the vector itself used.
    let nonce: [u8; 24] = fixed(&document, "/envelope/nonce_hex");
    let ciphertext = bytes(&document, "/envelope/ciphertext_hex");
    let (_, recipient_secret) =
        sodium::box_seed_keypair(&fixed(&document, "/keys/recipient/seed_hex")).expect("a keypair");
    let opened = sodium::box_open_easy(
        &ciphertext,
        &nonce,
        sender.public().as_bytes(),
        &recipient_secret,
    )
    .expect("the envelope opens for its recipient");
    assert_eq!(opened, canonical);
    assert_eq!(recipient.key_id(), plaintext.recipient_key_id);
    assert_eq!(sender.key_id(), plaintext.sender_key_id);
}

#[test]
fn the_key_wrap_vector_reproduces_its_canonical_bytes() {
    let document = fixture("envelopes.json");
    let context: kr_protocol::archive::KeyWrapContext =
        serde_json::from_value(document["key_wrap"]["context_json"].clone())
            .expect("a wrap context");
    let object_key: [u8; 32] = fixed(&document, "/key_wrap/object_key_hex");
    let canonical =
        kr_protocol::archive::key_wrap_plaintext(&context, &object_key).expect("canonical bytes");
    assert_eq!(canonical, bytes(&document, "/key_wrap/canonical_hex"));
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

    let seed = RecoverySeed::from_stored_bytes(&bytes(&document, "/recovery/seed_hex"))
        .expect("a recovery seed");
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
}

#[test]
fn the_size_bucket_vector_matches_the_published_rule() {
    let document = fixture("envelopes.json");
    for case in document["size_buckets"]["mailbox"]
        .as_array()
        .expect("mailbox buckets")
    {
        let plaintext = case["plaintext_bytes"].as_u64().expect("a size");
        assert_eq!(
            kr_protocol::mailbox::mailbox_size_bucket(plaintext),
            case["bucket_bytes"].as_u64().expect("a bucket"),
            "bucket for {plaintext} bytes"
        );
    }
    for case in document["size_buckets"]["notification"]
        .as_array()
        .expect("notification buckets")
    {
        let plaintext = case["plaintext_bytes"].as_u64().expect("a size");
        assert_eq!(
            kr_protocol::mailbox::notification_size_bucket(plaintext),
            case["bucket_bytes"].as_u64().expect("a bucket"),
            "bucket for {plaintext} bytes"
        );
    }
}
