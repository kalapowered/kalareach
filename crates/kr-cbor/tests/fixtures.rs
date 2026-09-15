//! Conformance tests driven by the shared fixtures under `fixtures/cbor/`.
//!
//! The TypeScript package loads the same files and asserts the same bytes, digests and error
//! classes.

use std::path::PathBuf;

use kr_cbor::{
    CanonicalMap, CanonicalValue, CborError, Limits, decode, encode, sha256, signing_digest,
    signing_input,
};
use serde_json::Value as Json;

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/cbor")
}

fn load(name: &str) -> Json {
    let path = fixture_dir().join(name);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|error| panic!("parse {}: {error}", path.display()))
}

/// Parses the fixture value grammar into a canonical value.
fn parse_value(description: &Json) -> CanonicalValue {
    let object = description
        .as_object()
        .expect("a value description is an object");
    assert_eq!(object.len(), 1, "a value description has exactly one key");
    let (kind, payload) = object.iter().next().expect("one entry");
    match kind.as_str() {
        "int" => {
            let text = payload.as_str().expect("int payload is a decimal string");
            CanonicalValue::integer(text.parse::<i128>().expect("decimal integer"))
                .expect("fixture integer is inside the 64-bit argument range")
        }
        "bytes" => CanonicalValue::Bytes(
            hex::decode(payload.as_str().expect("bytes payload is hex")).expect("valid hex"),
        ),
        "text" => CanonicalValue::text(payload.as_str().expect("text payload is a string")),
        "bool" => CanonicalValue::Bool(payload.as_bool().expect("bool payload is a boolean")),
        "null" => CanonicalValue::Null,
        "array" => CanonicalValue::Array(
            payload
                .as_array()
                .expect("array payload is an array")
                .iter()
                .map(parse_value)
                .collect(),
        ),
        "map" => {
            let mut map = CanonicalMap::new();
            for entry in payload
                .as_array()
                .expect("map payload is an array of pairs")
            {
                let pair = entry.as_array().expect("map entry is a pair");
                assert_eq!(pair.len(), 2, "map entry is a pair");
                let key = pair[0].as_str().expect("map key is text").to_owned();
                map.insert(key, parse_value(&pair[1]))
                    .expect("fixture map has no duplicate keys");
            }
            CanonicalValue::Map(map)
        }
        other => panic!("unknown value kind {other}"),
    }
}

fn parse_limits(description: Option<&Json>) -> Limits {
    let mut limits = Limits::DEFAULT;
    let Some(object) = description.and_then(Json::as_object) else {
        return limits;
    };
    for (key, value) in object {
        let value =
            usize::try_from(value.as_u64().expect("limit is a number")).expect("fits usize");
        match key.as_str() {
            "max_message_len" => limits.max_message_len = value,
            "max_depth" => limits.max_depth = value,
            "max_items" => limits.max_items = value,
            "max_collection_len" => limits.max_collection_len = value,
            "max_bytes_len" => limits.max_bytes_len = value,
            "max_text_len" => limits.max_text_len = value,
            other => panic!("unknown limit {other}"),
        }
    }
    limits
}

fn cases(document: &Json, key: &str) -> Vec<Json> {
    document[key]
        .as_array()
        .unwrap_or_else(|| panic!("{key} is an array"))
        .clone()
}

fn check_valid_file(name: &str) -> usize {
    let document = load(name);
    let cases = cases(&document, "cases");
    assert!(!cases.is_empty(), "{name} has cases");
    for case in &cases {
        let id = case["id"].as_str().expect("case id");
        let expected = hex::decode(case["hex"].as_str().expect("case hex")).expect("valid hex");
        let value = parse_value(&case["value"]);

        let encoded = encode(&value);
        assert_eq!(
            hex::encode(&encoded),
            hex::encode(&expected),
            "{name}/{id}: encoding does not match the fixture bytes"
        );

        let decoded = decode(&expected, &Limits::DEFAULT)
            .unwrap_or_else(|error| panic!("{name}/{id}: decode failed: {error}"));
        assert_eq!(decoded, value, "{name}/{id}: decoded value differs");

        assert_eq!(
            encode(&decoded),
            expected,
            "{name}/{id}: re-encoding the decoded value is not byte identical"
        );
    }
    cases.len()
}

#[test]
fn integer_fixtures_round_trip() {
    assert!(check_valid_file("integers.json") >= 20);
}

#[test]
fn string_fixtures_round_trip() {
    assert!(check_valid_file("strings.json") >= 15);
}

#[test]
fn map_ordering_fixtures_round_trip() {
    assert!(check_valid_file("map-ordering.json") >= 8);
}

#[test]
fn null_and_absent_fixtures_round_trip() {
    assert!(check_valid_file("null-and-absent.json") >= 4);
}

#[test]
fn structure_fixtures_round_trip() {
    assert!(check_valid_file("structures.json") >= 5);
}

#[test]
fn absent_and_null_have_different_digests() {
    let document = load("null-and-absent.json");
    let cases = cases(&document, "cases");
    let find = |id: &str| {
        cases
            .iter()
            .find(|case| case["id"] == id)
            .unwrap_or_else(|| panic!("case {id}"))
            .clone()
    };
    let absent = parse_value(&find("field_absent")["value"]);
    let null = parse_value(&find("field_null")["value"]);
    assert_ne!(encode(&absent), encode(&null));
    assert_eq!(
        hex::encode(sha256(&encode(&absent))),
        document["digests"]["field_absent_sha256"]
            .as_str()
            .expect("digest"),
    );
    assert_eq!(
        hex::encode(sha256(&encode(&null))),
        document["digests"]["field_null_sha256"]
            .as_str()
            .expect("digest"),
    );
}

#[test]
fn non_ascii_text_is_not_normalised() {
    let document = load("strings.json");
    let cases = cases(&document, "cases");
    let bytes_for = |id: &str| {
        let case = cases
            .iter()
            .find(|case| case["id"] == id)
            .unwrap_or_else(|| panic!("case {id}"));
        encode(&parse_value(&case["value"]))
    };
    assert_ne!(
        bytes_for("text_nfc"),
        bytes_for("text_nfd"),
        "precomposed and decomposed forms must stay byte distinct"
    );
    assert_ne!(
        bytes_for("text_sharp_s"),
        bytes_for("text_upper"),
        "no case folding is performed on signed text"
    );
}

#[test]
fn invalid_fixtures_are_rejected_with_the_named_rule() {
    let document = load("invalid.json");
    let cases = cases(&document, "cases");
    assert!(cases.len() >= 50, "invalid fixtures cover the profile");
    for case in &cases {
        let id = case["id"].as_str().expect("case id");
        let bytes = hex::decode(case["hex"].as_str().expect("case hex")).expect("valid hex");
        let expected = case["rule"].as_str().expect("expected rule");
        let limits = parse_limits(case.get("limits"));
        match decode(&bytes, &limits) {
            Ok(value) => panic!("{id}: expected {expected}, decoded {value:?}"),
            Err(error) => assert_eq!(
                error.rule(),
                expected,
                "{id}: wrong rule ({error}) for {}",
                case["hex"].as_str().unwrap_or_default()
            ),
        }
    }
}

#[test]
fn every_error_rule_is_covered_by_a_fixture() {
    let document = load("invalid.json");
    let covered: Vec<String> = cases(&document, "cases")
        .iter()
        .map(|case| case["rule"].as_str().expect("rule").to_owned())
        .collect();
    for rule in [
        "empty_input",
        "unexpected_end",
        "trailing_bytes",
        "input_too_large",
        "non_shortest_integer",
        "non_shortest_length",
        "indefinite_length",
        "break_outside_indefinite",
        "reserved_additional_info",
        "tag",
        "float",
        "undefined",
        "simple_value",
        "non_text_map_key",
        "duplicate_key",
        "unsorted_map_keys",
        "invalid_utf8",
        "depth_limit",
        "count_limit",
        "collection_limit",
        "length_limit",
    ] {
        assert!(
            covered.iter().any(|entry| entry == rule),
            "no fixture covers {rule}"
        );
    }
}

#[test]
fn digest_fixtures_match() {
    let document = load("digests.json");
    for case in cases(&document, "digest_cases") {
        let id = case["id"].as_str().expect("case id");
        let value = parse_value(&case["value"]);
        let encoded = encode(&value);
        assert_eq!(
            hex::encode(&encoded),
            case["hex"].as_str().expect("hex"),
            "{id}: bytes"
        );
        assert_eq!(
            hex::encode(sha256(&encoded)),
            case["sha256"].as_str().expect("sha256"),
            "{id}: digest"
        );
    }
}

#[test]
fn signing_input_fixtures_match() {
    let document = load("digests.json");
    for case in cases(&document, "signing_input_cases") {
        let id = case["id"].as_str().expect("case id");
        let domain = case["domain"].as_str().expect("domain");
        let elements: Vec<CanonicalValue> = case["elements"]
            .as_array()
            .expect("elements")
            .iter()
            .map(parse_value)
            .collect();
        let bytes = signing_input(domain, elements.clone()).expect("signing input");
        assert_eq!(
            hex::encode(&bytes),
            case["hex"].as_str().expect("hex"),
            "{id}: signing input bytes"
        );
        assert_eq!(
            hex::encode(signing_digest(domain, elements).expect("digest")),
            case["sha256"].as_str().expect("sha256"),
            "{id}: signing input digest"
        );
        assert_eq!(
            decode(&bytes, &Limits::DEFAULT).expect("signing input decodes"),
            parse_value(&case["value"]),
            "{id}: signing input value"
        );
    }
}

#[test]
fn decoding_rejects_anything_the_encoder_cannot_produce() {
    // Every valid fixture re-encodes to itself; this asserts the inverse for a hand-built value
    // that the encoder would order differently.
    let mut map = CanonicalMap::new();
    map.insert("aa".to_owned(), CanonicalValue::integer(2).expect("int"))
        .expect("insert");
    map.insert("z".to_owned(), CanonicalValue::integer(1).expect("int"))
        .expect("insert");
    let encoded = encode(&CanonicalValue::Map(map));
    assert_eq!(hex::encode(&encoded), "a2617a0162616102");

    // The same entries in source order are not canonical.
    let unsorted = hex::decode("a262616102617a01").expect("hex");
    assert!(matches!(
        decode(&unsorted, &Limits::DEFAULT),
        Err(CborError::UnsortedMapKeys { .. })
    ));
}
