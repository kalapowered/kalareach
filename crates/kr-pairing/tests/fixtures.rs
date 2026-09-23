//! The committed vectors under `fixtures/pairing/` must be reproducible from the Rust code.
//!
//! `packages/protocol/test/pairing.test.ts` recomputes the same numbers with the Node runtime's
//! own SHA-256, HMAC-SHA256 and HKDF-SHA256, so a value that drifts in one language fails in both.

use std::path::{Path, PathBuf};

use kr_pairing::code::EnteredCode;
use kr_pairing::vectors::generated_files;
use kr_protocol::pairing::{BASE58_ALPHABET, QrPayload};
use serde_json::Value;

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn fixture(name: &str) -> Value {
    let path = repository_root().join("fixtures/pairing").join(name);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    serde_json::from_str(&text).expect("a fixture is JSON")
}

fn text(value: &Value, pointer: &str) -> String {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{pointer} is a string"))
        .to_owned()
}

fn bytes(value: &Value, pointer: &str) -> Vec<u8> {
    hex::decode(text(value, pointer)).expect("a fixture hex string decodes")
}

/// KR-REQ-10.20, KR-REQ-10.22: the published pairing vectors are exactly what the Rust code
/// derives.
#[test]
fn the_committed_vectors_match_the_rust_code() {
    for (name, expected) in generated_files().expect("the vectors are generated") {
        let path = repository_root().join("fixtures/pairing").join(name);
        let actual = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
        assert_eq!(
            actual,
            expected,
            "{} is out of date; run `cargo run -p kr-pairing --bin kr-pairing-vectors`",
            path.display()
        );
    }
}

#[test]
fn generation_is_deterministic() {
    assert_eq!(
        generated_files().expect("the vectors are generated"),
        generated_files().expect("the vectors are generated")
    );
}

/// KR-REQ-10.20, KR-REQ-10.22: the vector names the context domain, the two role domains and the
/// five literal HKDF information strings.
#[test]
fn the_transcript_vector_names_the_specified_domains_and_labels() {
    let document = fixture("transcript.json");
    assert_eq!(document["domain"], "kr-pair/spake2-ed25519/1");
    assert_eq!(document["identities"]["host_domain"], "kr-pair/host");
    assert_eq!(document["identities"]["client_domain"], "kr-pair/client");
    assert_eq!(document["verification_value"]["domain"], "kr-pair/verify/1");
    assert_eq!(
        document["hkdf"]["info_strings"]
            .as_array()
            .expect("five strings")
            .iter()
            .map(|value| value.as_str().expect("a string"))
            .collect::<Vec<_>>(),
        vec![
            "kr-pair/1/client-confirm",
            "kr-pair/1/host-confirm",
            "kr-pair/1/client-to-host",
            "kr-pair/1/host-to-client",
            "kr-pair/1/iroh-bind",
        ]
    );
}

/// KR-REQ-10.20: `C` is the seven-member array in the specified order, and `CH` is its hash.
#[test]
fn the_context_hashes_to_what_the_vector_publishes() {
    let document = fixture("transcript.json");
    let canonical = bytes(&document, "/context/canonical_hex");
    assert_eq!(
        hex::encode(kr_cbor::sha256(&canonical)),
        text(&document, "/context/context_hash_hex")
    );
    // `C` is an array whose first element is the domain literal.
    let value = kr_cbor::decode(&canonical, &kr_cbor::Limits::DEFAULT).expect("a value");
    let kr_cbor::CanonicalValue::Array(items) = &value else {
        panic!("C is an array");
    };
    assert_eq!(items.len(), 7);
    assert_eq!(
        items[0].as_text(),
        Some(document["domain"].as_str().expect("a domain"))
    );
    assert_eq!(
        hex::encode(kr_cbor::encode(&value)),
        text(&document, "/context/canonical_hex"),
        "the context re-encodes to the bytes it publishes"
    );
}

/// KR-REQ-10.22: `T` hashes `C` and both library messages, host first.
#[test]
fn the_transcript_hashes_the_context_and_both_messages_in_order() {
    let document = fixture("transcript.json");
    let transcript = bytes(&document, "/exchange/transcript_hex");
    assert_eq!(
        hex::encode(kr_cbor::sha256(&transcript)),
        text(&document, "/exchange/transcript_sha256_hex")
    );
    let value = kr_cbor::decode(&transcript, &kr_cbor::Limits::DEFAULT).expect("a value");
    let kr_cbor::CanonicalValue::Array(items) = &value else {
        panic!("the transcript is an array");
    };
    assert_eq!(items.len(), 3, "C, message A, message B");
    let kr_cbor::CanonicalValue::Bytes(message_a) = &items[1] else {
        panic!("message A is a byte string");
    };
    assert_eq!(
        hex::encode(message_a),
        text(&document, "/exchange/message_a_hex")
    );
}

/// KR-REQ-10.22, KR-REQ-10.23: five independent 32-byte keys, and distinct tags for each use.
#[test]
fn the_five_keys_and_both_tags_are_distinct() {
    let document = fixture("transcript.json");
    let keys = [
        "/hkdf/client_confirm_key_hex",
        "/hkdf/host_confirm_key_hex",
        "/hkdf/client_to_host_key_hex",
        "/hkdf/host_to_client_key_hex",
        "/hkdf/iroh_bind_key_hex",
    ]
    .map(|pointer| text(&document, pointer));
    for (index, left) in keys.iter().enumerate() {
        assert_eq!(left.len(), 64, "a 32-byte key");
        for right in &keys[index + 1..] {
            assert_ne!(left, right);
        }
    }
    assert_ne!(
        text(&document, "/confirmation/client_tag_hex"),
        text(&document, "/confirmation/host_tag_hex")
    );
    assert_ne!(
        text(&document, "/finish/tag_hex"),
        text(&document, "/confirmation/client_tag_hex")
    );
}

/// KR-REQ-10.24: the bundle additional data is CBOR([domain, T, direction, sequence, type]).
#[test]
fn every_bundle_additional_data_case_is_distinct() {
    let document = fixture("transcript.json");
    let cases = document["bundle_additional_data"]
        .as_array()
        .expect("the cases");
    assert_eq!(cases.len(), 4);
    let mut seen = std::collections::BTreeSet::new();
    for case in cases {
        let aad = case["aad_hex"].as_str().expect("a hex string");
        assert!(
            seen.insert(aad),
            "each direction, type and sequence differs"
        );
        let value = kr_cbor::decode(&hex::decode(aad).expect("hex"), &kr_cbor::Limits::DEFAULT)
            .expect("a value");
        let kr_cbor::CanonicalValue::Array(items) = &value else {
            panic!("the additional data is an array");
        };
        assert_eq!(items.len(), 5, "domain, T, direction, sequence, type");
        assert_eq!(items[0].as_text(), Some("kr-pair/spake2-ed25519/1"));
    }
}

/// KR-REQ-10.28, KR-REQ-10.37: both verification values are eight hexadecimal characters.
#[test]
fn the_verification_values_are_eight_hexadecimal_characters() {
    for (name, pointer) in [
        ("transcript.json", "/verification_value/value"),
        ("direct.json", "/verification_value/value"),
    ] {
        let value = text(&fixture(name), pointer);
        assert_eq!(value.len(), 8, "{name}");
        assert!(value.bytes().all(|byte| byte.is_ascii_hexdigit()), "{name}");
    }
}

/// KR-REQ-10.36: `D` is the ten-member array section 10 lists, in order.
#[test]
fn the_direct_transcript_is_an_array_in_the_specified_order() {
    let document = fixture("direct.json");
    assert_eq!(document["domain"], "kr-pair/direct/1");
    assert_eq!(
        document["verification_value"]["domain"],
        "kr-pair/direct-verify/1"
    );
    let canonical = bytes(&document, "/transcript/canonical_hex");
    assert_eq!(
        hex::encode(kr_cbor::sha256(&canonical)),
        text(&document, "/transcript/canonical_sha256_hex")
    );
    let value = kr_cbor::decode(&canonical, &kr_cbor::Limits::DEFAULT).expect("a value");
    let kr_cbor::CanonicalValue::Array(items) = &value else {
        panic!("D is an array");
    };
    assert_eq!(items.len(), 10);
    assert_eq!(items[0].as_text(), Some("kr-pair/direct/1"));
}

/// KR-REQ-10.11, KR-REQ-10.04: codes are Base58, displayed `XXXX-XXX-XXX`, and parse as the vector
/// says.
#[test]
fn every_parsing_case_behaves_as_the_vector_says() {
    let document = fixture("codes.json");
    assert_eq!(document["alphabet"], BASE58_ALPHABET);
    assert_eq!(document["display_form"], "XXXX-XXX-XXX");

    for case in document["parsing"]["accepted"]
        .as_array()
        .expect("accepted cases")
    {
        let entered = case["entered"].as_str().expect("a string");
        let code = EnteredCode::parse(entered).unwrap_or_else(|_| panic!("{entered} parses"));
        assert_eq!(
            code.normalised(),
            case["normalised"].as_str().expect("a string")
        );
        assert_eq!(
            code.locator().as_str(),
            case["locator"].as_str().expect("a string")
        );
    }
    for case in document["parsing"]["rejected"]
        .as_array()
        .expect("rejected cases")
    {
        let entered = case["entered"].as_str().expect("a string");
        assert!(
            EnteredCode::parse(entered).is_err(),
            "{} should be rejected",
            case["id"]
        );
    }
}

/// KR-REQ-10.38: both QR payloads decode from, and re-encode to, their published canonical bytes.
#[test]
fn both_qr_payloads_round_trip_from_their_published_bytes() {
    let document = fixture("codes.json");
    for mode in ["code", "direct"] {
        let canonical = bytes(&document, &format!("/qr/{mode}/canonical_hex"));
        let payload = QrPayload::from_canonical_bytes(&canonical).expect("a payload");
        assert_eq!(payload.mode(), mode);
        assert_eq!(
            hex::encode(payload.to_canonical_bytes().expect("bytes").as_slice()),
            hex::encode(&canonical),
            "the payload re-encodes to the bytes it arrived in"
        );
        let text_form = text(&document, &format!("/qr/{mode}/text"));
        assert_eq!(
            QrPayload::from_text(&text_form).expect("a payload").mode(),
            mode
        );
    }
}

/// KR-REQ-10.09: the PAKE is the RustCrypto `spake2` crate, pinned to exactly 0.4.0 in the
/// workspace and resolved to that one version, and its profile is `Spake2<Ed25519Group>`.
#[test]
fn the_pake_is_the_pinned_spake2_release() {
    let manifest = std::fs::read_to_string(repository_root().join("Cargo.toml"))
        .expect("the workspace manifest");
    assert!(
        manifest
            .lines()
            .any(|line| line.trim() == r#"spake2 = "=0.4.0""#),
        "the workspace pins spake2 to exactly 0.4.0"
    );
    let lock =
        std::fs::read_to_string(repository_root().join("Cargo.lock")).expect("the lock file");
    let resolved: Vec<&str> = lock
        .split("[[package]]")
        .filter(|package| package.contains("\nname = \"spake2\"\n"))
        .collect();
    assert_eq!(resolved.len(), 1, "one spake2 in the dependency graph");
    assert!(resolved[0].contains("\nversion = \"0.4.0\"\n"));
    assert!(
        resolved[0]
            .contains("\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n"),
        "the maintained crate from the public registry"
    );
    assert_eq!(kr_pairing::spake::SPAKE2_VERSION, "0.4.0");
    assert_eq!(kr_pairing::spake::SPAKE2_PROFILE, "Spake2<Ed25519Group>");
}
