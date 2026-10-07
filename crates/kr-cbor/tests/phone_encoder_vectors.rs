//! The encodings the paired phones' CBOR encoders are held to.
//!
//! The phones sign the voice confirmation challenge in Swift and in Kotlin, each with an encoder of
//! its own. Each phone's ceremony test (`VoiceCeremonyTests.swift`, `VoiceCeremonyTest.kt`) carries
//! the same four lists below as literals, so an encoder that disagrees with this one on a head
//! size, a multi-byte character or a map key's order is found on the phone. The lists are this
//! encoder's own output: a literal typed out in three languages would agree with itself and with
//! nothing else, so this test is what ties the three to the host.

use std::collections::BTreeMap;

use kr_cbor::CanonicalValue;

/// Unsigned integers at every point the head changes size.
const UNSIGNED_BOUNDARIES: &[(u64, &str)] = &[
    (0, "00"),
    (23, "17"),
    (24, "1818"),
    (255, "18ff"),
    (256, "190100"),
    (65_535, "19ffff"),
    (65_536, "1a00010000"),
    (4_294_967_295, "1affffffff"),
    (4_294_967_296, "1b0000000100000000"),
    (u64::MAX, "1bffffffffffffffff"),
];

/// For a string of this many bytes: the head of a byte string and of a text string.
const LENGTH_HEADS: &[(usize, &str, &str)] = &[
    (0, "40", "60"),
    (23, "57", "77"),
    (24, "5818", "7818"),
    (255, "58ff", "78ff"),
    (256, "590100", "790100"),
];

/// Text whose characters are more than one byte each: the head counts bytes, not characters.
const MULTIBYTE_TEXT: &[(&str, &str)] = &[("é", "62c3a9"), ("日本", "66e697a5e69cac")];

/// Maps with one unsigned value per key, and their bytes: shortest encoded key first, then by the
/// key's bytes, which puts "z" before "aa" and "ab" before "é".
const MAP_ORDER: &[(&[(&str, u64)], &str)] = &[
    (&[("b", 1), ("a", 2)], "a2616102616201"),
    (&[("aa", 1), ("b", 2)], "a261620262616101"),
    (&[("é", 1), ("z", 2)], "a2617a0262c3a901"),
    (&[("é", 1), ("ab", 2)], "a26261620262c3a901"),
];

#[test]
fn the_phone_encoder_vectors_are_what_the_host_encodes() {
    for (value, expected) in UNSIGNED_BOUNDARIES {
        let encoded = kr_cbor::to_canonical_vec(value).expect("an unsigned integer encodes");
        assert_eq!(hex::encode(encoded), *expected, "{value}");
    }
    for (length, bytes_head, text_head) in LENGTH_HEADS {
        let bytes = kr_cbor::encode(&CanonicalValue::Bytes(vec![1; *length]));
        assert_eq!(
            hex::encode(bytes),
            format!("{bytes_head}{}", "01".repeat(*length))
        );
        let text = kr_cbor::to_canonical_vec(&"a".repeat(*length)).expect("text encodes");
        assert_eq!(
            hex::encode(text),
            format!("{text_head}{}", "61".repeat(*length))
        );
    }
    for (text, expected) in MULTIBYTE_TEXT {
        let encoded = kr_cbor::to_canonical_vec(text).expect("text encodes");
        assert_eq!(hex::encode(encoded), *expected, "{text}");
    }
    for (entries, expected) in MAP_ORDER {
        let map: BTreeMap<String, u64> = entries
            .iter()
            .map(|(key, value)| ((*key).to_owned(), *value))
            .collect();
        let encoded = kr_cbor::to_canonical_vec(&map).expect("a map encodes");
        assert_eq!(hex::encode(encoded), *expected, "{entries:?}");
    }
}
