//! Profile rules that are not expressed as byte fixtures.

use kr_cbor::{
    CanonicalMap, CanonicalValue, CborError, Limits, compare_keys, decode, encode,
    from_canonical_slice, from_ciborium, to_canonical_value, to_canonical_vec,
    to_canonical_vec_within,
};
use serde::{Deserialize, Serialize};

/// Encodes one text string exactly as the canonical encoder does, for the ordering proof.
fn encoded_key(key: &str) -> Vec<u8> {
    encode(&CanonicalValue::text(key))
}

#[test]
fn key_order_is_the_bytewise_order_of_the_complete_encoded_key() {
    let mut keys: Vec<String> = vec![
        String::new(),
        "a".to_owned(),
        "b".to_owned(),
        "A".to_owned(),
        "z".to_owned(),
        "aa".to_owned(),
        "ab".to_owned(),
        "\u{e9}".to_owned(),
        "\u{4f60}".to_owned(),
        "a".repeat(22),
        "z".repeat(23),
        "a".repeat(24),
        "a".repeat(255),
        "a".repeat(256),
        "b".repeat(255),
    ];
    keys.push("a".repeat(65_535));
    keys.push("a".repeat(65_536));

    for left in &keys {
        for right in &keys {
            assert_eq!(
                compare_keys(left, right),
                encoded_key(left).cmp(&encoded_key(right)),
                "ordering disagrees for keys of length {} and {}",
                left.len(),
                right.len()
            );
        }
    }
}

#[test]
fn key_order_is_not_the_order_of_the_key_text() {
    // "aa" < "z" as text, but "z" has the shorter encoded key and sorts first.
    assert!("aa" < "z");
    assert_eq!(compare_keys("z", "aa"), core::cmp::Ordering::Less);
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct Example {
    session_epoch: u64,
    label: String,
    enabled: bool,
    payload: Option<u64>,
}

#[test]
fn serde_round_trips_through_canonical_bytes() {
    let value = Example {
        session_epoch: 1,
        label: "caf\u{e9}".to_owned(),
        enabled: true,
        payload: None,
    };
    let bytes = to_canonical_vec(&value).expect("encode");
    let decoded: Example = from_canonical_slice(&bytes, &Limits::DEFAULT).expect("decode");
    assert_eq!(decoded, value);

    // Serialising the decoded value produces identical bytes.
    assert_eq!(to_canonical_vec(&decoded).expect("re-encode"), bytes);
}

#[test]
fn serde_output_is_canonically_ordered() {
    let value = Example {
        session_epoch: 1,
        label: "x".to_owned(),
        enabled: false,
        payload: Some(7),
    };
    let bytes = to_canonical_vec(&value).expect("encode");
    let decoded = decode(&bytes, &Limits::DEFAULT).expect("decode");
    let map = decoded.as_map().expect("map");
    let keys: Vec<&str> = map.entries().iter().map(|(key, _)| key.as_str()).collect();
    assert_eq!(keys, ["label", "enabled", "payload", "session_epoch"]);
}

#[test]
fn floats_cannot_be_serialised() {
    let error = to_canonical_value(&1.5f64).expect_err("floats are forbidden");
    assert_eq!(error.rule(), "unrepresentable");
}

#[test]
fn tags_cannot_be_converted_from_ciborium() {
    let tagged = ciborium::value::Value::Tag(0, Box::new(ciborium::value::Value::Text("x".into())));
    let error = from_ciborium(&tagged).expect_err("tags are forbidden");
    assert_eq!(error.rule(), "unrepresentable");
}

#[test]
fn integers_outside_the_argument_range_are_rejected() {
    assert_eq!(
        CanonicalValue::integer(i128::from(u64::MAX) + 1)
            .expect_err("above the range")
            .rule(),
        "integer_out_of_range"
    );
    assert_eq!(
        CanonicalValue::integer(-(1i128 << 64) - 1)
            .expect_err("below the range")
            .rule(),
        "integer_out_of_range"
    );
    assert!(CanonicalValue::integer(-(1i128 << 64)).is_ok());
    assert!(CanonicalValue::integer(i128::from(u64::MAX)).is_ok());
}

#[test]
fn duplicate_keys_cannot_be_built_in_memory() {
    let mut map = CanonicalMap::new();
    map.insert("a".to_owned(), CanonicalValue::Null)
        .expect("first");
    let error = map
        .insert("a".to_owned(), CanonicalValue::Null)
        .expect_err("second");
    assert_eq!(error.rule(), "duplicate_key");
}

#[test]
fn outbound_limits_are_enforced_before_the_peer_sees_the_message() {
    let value = Example {
        session_epoch: 1,
        label: "x".repeat(64),
        enabled: true,
        payload: None,
    };
    let limits = Limits::DEFAULT.with_max_message_len(16);
    let error = to_canonical_vec_within(&value, &limits).expect_err("over the limit");
    assert_eq!(error.rule(), "input_too_large");

    let limits = Limits {
        max_text_len: 8,
        ..Limits::DEFAULT
    };
    assert_eq!(
        to_canonical_vec_within(&value, &limits)
            .expect_err("text over the limit")
            .rule(),
        "length_limit"
    );
}

#[test]
fn deserialisation_never_sees_a_non_canonical_message() {
    // {"enabled": true, "label": "x", "payload": null, "session_epoch": 1} with the keys in the
    // wrong order is rejected before serde runs.
    let mut canonical = to_canonical_vec(&Example {
        session_epoch: 1,
        label: "x".to_owned(),
        enabled: true,
        payload: None,
    })
    .expect("encode");
    // Swap the first two entries so the wire order is wrong.
    let unsorted = {
        let decoded = decode(&canonical, &Limits::DEFAULT).expect("decode");
        let map = decoded.as_map().expect("map").clone();
        let mut entries = map.into_entries();
        entries.swap(0, 1);
        let mut out = vec![0xa4];
        for (key, value) in entries {
            out.extend_from_slice(&encode(&CanonicalValue::text(key)));
            out.extend_from_slice(&encode(&value));
        }
        out
    };
    assert!(matches!(
        from_canonical_slice::<Example>(&unsorted, &Limits::DEFAULT),
        Err(CborError::UnsortedMapKeys { .. })
    ));

    // A trailing byte is rejected too.
    canonical.push(0x00);
    assert!(matches!(
        from_canonical_slice::<Example>(&canonical, &Limits::DEFAULT),
        Err(CborError::TrailingBytes { .. })
    ));
}

#[test]
fn an_empty_collection_does_not_consume_the_depth_of_its_members() {
    // An empty array or map has no children, so it fits wherever a scalar fits. Inbound and
    // outbound limits have to agree about that.
    let limits = Limits {
        max_depth: 1,
        ..Limits::DEFAULT
    };
    for hex_bytes in ["80", "a0", "00"] {
        let bytes = hex::decode(hex_bytes).expect("hex");
        let value = decode(&bytes, &limits)
            .unwrap_or_else(|error| panic!("{hex_bytes} at depth 1: {error}"));
        value
            .check_limits(&limits)
            .unwrap_or_else(|error| panic!("{hex_bytes} outbound at depth 1: {error}"));
    }

    // One member does consume it.
    let bytes = hex::decode("8100").expect("hex");
    assert_eq!(
        decode(&bytes, &limits)
            .expect_err("a member is one level deeper")
            .rule(),
        "depth_limit"
    );
    assert_eq!(
        CanonicalValue::Array(vec![CanonicalValue::integer(0).expect("int")])
            .check_limits(&limits)
            .expect_err("outbound agrees")
            .rule(),
        "depth_limit"
    );

    // An empty collection nested at the limit is still accepted by both directions.
    let nested = hex::decode("818180").expect("hex");
    let limits = Limits {
        max_depth: 2,
        ..Limits::DEFAULT
    };
    assert_eq!(
        decode(&nested, &limits).expect_err("three levels").rule(),
        "depth_limit"
    );
    let two_levels = hex::decode("8180").expect("hex");
    assert!(decode(&two_levels, &limits).is_ok());
}
