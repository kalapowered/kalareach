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

/// KR-REQ-23.01: map keys sort by the bytewise order of their complete encoded keys, across every
/// head width a text key can have.
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

/// KR-REQ-23.01: key order is decided by the encoded key, not by the key text.
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

/// KR-REQ-23.01: a value serialised through serde comes out in canonical key order.
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

/// KR-REQ-23.02: a float is outside the permitted type set and cannot be encoded.
#[test]
fn floats_cannot_be_serialised() {
    let error = to_canonical_value(&1.5f64).expect_err("floats are forbidden");
    assert_eq!(error.rule(), "unrepresentable");
}

/// KR-REQ-23.02: a tag is outside the permitted type set and cannot be encoded.
#[test]
fn tags_cannot_be_converted_from_ciborium() {
    let tagged = ciborium::value::Value::Tag(0, Box::new(ciborium::value::Value::Text("x".into())));
    let error = from_ciborium(&tagged).expect_err("tags are forbidden");
    assert_eq!(error.rule(), "unrepresentable");
}

/// KR-REQ-23.02: integers are permitted across the 64-bit argument range, both ends included.
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

/// KR-REQ-23.02: a map cannot hold a duplicate key, so none can be encoded.
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

/// KR-REQ-23.04: the length limits hold for what this side sends as well as for what it reads.
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

/// KR-REQ-23.05: wire order and trailing bytes are validated before serde deserialisation runs.
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

/// KR-REQ-23.04: the depth limit counts levels the same way inbound and outbound.
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

/// KR-REQ-23.04: a declared length or member count is checked against its limit, and against the
/// bytes the message actually carries, before anything is reserved for it; nesting is checked
/// before the decoder descends. A decoder that reserved or recursed first could not pass: each
/// declaration below asks for more than any allocator can supply, and the nesting is deeper than a
/// test thread's stack.
#[test]
fn limits_are_checked_before_anything_a_message_declares_is_reserved() {
    // Every head declares isize::MAX bytes or members and nothing follows it.
    let enormous = u64::try_from(isize::MAX)
        .expect("isize::MAX is positive")
        .to_be_bytes();
    let declaring = |initial: u8| {
        let mut bytes = vec![initial];
        bytes.extend_from_slice(&enormous);
        bytes
    };
    let byte_string = declaring(0x5b);
    let text_string = declaring(0x7b);
    let array = declaring(0x9b);
    let map = declaring(0xbb);

    // Under the default limits each declaration is refused by the limit it breaks.
    for (bytes, rule) in [
        (&byte_string, "length_limit"),
        (&text_string, "length_limit"),
        (&array, "collection_limit"),
        (&map, "collection_limit"),
    ] {
        assert_eq!(
            decode(bytes, &Limits::DEFAULT)
                .expect_err("a declaration over its limit")
                .rule(),
            rule
        );
    }

    // With every limit opened up, the input itself still bounds what may be reserved: a
    // declaration longer than the bytes that follow it is refused before anything is allocated.
    let open = Limits {
        max_message_len: usize::MAX,
        max_depth: usize::MAX,
        max_items: usize::MAX,
        max_collection_len: usize::MAX,
        max_bytes_len: usize::MAX,
        max_text_len: usize::MAX,
    };
    for bytes in [&byte_string, &text_string, &array, &map] {
        assert_eq!(
            decode(bytes, &open)
                .expect_err("a declaration longer than the input")
                .rule(),
            "unexpected_end"
        );
    }

    // The item budget is spent by the declaration, before any member is read or reserved: an
    // array declaring a thousand members that are all present is refused against a budget of ten.
    let mut counted = vec![0x99, 0x03, 0xe8];
    counted.resize(counted.len() + 1_000, 0x00);
    let budget = Limits {
        max_items: 10,
        ..Limits::DEFAULT
    };
    assert_eq!(
        decode(&counted, &budget)
            .expect_err("a thousand members against a budget of ten")
            .rule(),
        "count_limit"
    );

    // A hundred thousand nested arrays stop at the depth limit instead of descending.
    let mut nested = vec![0x81; 100_000];
    nested.push(0x00);
    assert_eq!(
        decode(&nested, &Limits::DEFAULT)
            .expect_err("nesting past the limit")
            .rule(),
        "depth_limit"
    );
}

/// KR-REQ-23.05, KR-REQ-09.02: duplicate keys, unsorted keys and invalid UTF-8 are refused by the
/// strict decoder before serde runs. Serde on its own accepts all three orderings and keeps the
/// last of two duplicates, so the error each one gets names the wire rule rather than a schema
/// mismatch.
#[test]
fn duplicates_disorder_and_invalid_text_never_reach_deserialisation() {
    use std::collections::BTreeMap;

    // {"a": 1, "a": 2}: serde alone would keep the second value.
    let duplicated = hex::decode("a2616101616102").expect("hex");
    let lenient: BTreeMap<String, u64> =
        ciborium::from_reader(duplicated.as_slice()).expect("serde alone accepts it");
    assert_eq!(lenient.get("a"), Some(&2));
    assert!(matches!(
        from_canonical_slice::<BTreeMap<String, u64>>(&duplicated, &Limits::DEFAULT),
        Err(CborError::DuplicateKey { .. })
    ));

    // {"b": 1, "a": 2}: serde alone does not look at the order.
    let unsorted = hex::decode("a2616201616102").expect("hex");
    let lenient: BTreeMap<String, u64> =
        ciborium::from_reader(unsorted.as_slice()).expect("serde alone accepts it");
    assert_eq!(lenient.len(), 2);
    assert!(matches!(
        from_canonical_slice::<BTreeMap<String, u64>>(&unsorted, &Limits::DEFAULT),
        Err(CborError::UnsortedMapKeys { .. })
    ));

    // A text string holding a lone continuation byte, as a value and as a map key.
    let invalid_value = hex::decode("6180").expect("hex");
    assert!(matches!(
        from_canonical_slice::<String>(&invalid_value, &Limits::DEFAULT),
        Err(CborError::InvalidUtf8 { .. })
    ));
    let invalid_key = hex::decode("a1618001").expect("hex");
    assert!(matches!(
        from_canonical_slice::<BTreeMap<String, u64>>(&invalid_key, &Limits::DEFAULT),
        Err(CborError::InvalidUtf8 { .. })
    ));
}
