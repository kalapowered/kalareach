//! What a failure says: the rule it broke and where, and nothing it read.
//!
//! A message can carry anything its sender put in it, a secret included, and a failure is written
//! to logs and shown to people. So every rendering of a [`CborError`], `Display` and both `Debug`
//! forms, says the rule and a place built from this program's own text: an offset, a count, the
//! schema's name for an object, and a path of array indices, declared members and map entries by
//! position. A marker goes into each piece of text a failure can read from a message, through the
//! decoder, the map builders, the schema check and serde, and no rendering may hold it. The control
//! holds failures with a place to still saying it, so that a rendering which said nothing at all
//! would not pass as one that said nothing it should not.

use std::collections::BTreeMap;
use std::sync::Arc;

use kr_cbor::{
    CanonicalMap, CanonicalValue, CborError, Extensions, Limits, Member, ObjectShape, Shape,
    TaggedShape, Undeclared, check, decode, from_canonical_slice, to_canonical_value,
};
use serde::{Deserialize, Serialize};

/// Stands for everything a failure must not show.
const MARKER: &str = "kr-marker-7c1e";

/// Every way a failure renders.
fn renderings(error: &CborError) -> [String; 3] {
    [
        error.to_string(),
        format!("{error:?}"),
        format!("{error:#?}"),
    ]
}

/// Holds every rendering of `error` to naming its rule and carrying no marker.
fn assert_unmarked(what: &str, error: &CborError) {
    for rendering in renderings(error) {
        assert!(!rendering.contains(MARKER), "{what}: {rendering}");
    }
    assert!(
        format!("{error:?}").starts_with(error.rule()),
        "{what}: the debug form names the rule first: {error:?}"
    );
}

/// A text string's bytes, for a string shorter than 24 bytes.
fn text(value: &str) -> Vec<u8> {
    let length = u8::try_from(value.len()).expect("a short string");
    assert!(length < 24, "a one-byte head");
    let mut bytes = vec![0x60 | length];
    bytes.extend_from_slice(value.as_bytes());
    bytes
}

/// A map of small integers under `keys`, in the order given, which need not be canonical.
fn map_bytes(keys: &[String]) -> Vec<u8> {
    let count = u8::try_from(keys.len()).expect("a small map");
    let mut bytes = vec![0xa0 | count];
    for (value, key) in keys.iter().enumerate() {
        bytes.extend(text(key));
        bytes.push(u8::try_from(value).expect("a small integer"));
    }
    bytes
}

fn int(value: i128) -> CanonicalValue {
    CanonicalValue::integer(value).expect("in range")
}

fn map(entries: &[(&str, CanonicalValue)]) -> CanonicalValue {
    CanonicalValue::Map(
        CanonicalMap::from_entries(
            entries
                .iter()
                .map(|(key, value)| ((*key).to_owned(), value.clone())),
        )
        .expect("distinct keys"),
    )
}

fn object(name: &str, fields: &[(&str, Shape)]) -> Arc<ObjectShape> {
    Arc::new(ObjectShape {
        name: Some(name.to_owned()),
        fields: fields
            .iter()
            .map(|(field, shape)| ((*field).to_owned(), shape.clone()))
            .collect::<BTreeMap<_, _>>(),
        undeclared: Undeclared::Refuse,
    })
}

/// `Target { items: [Item], labels: {data -> Item}, answers: {data -> Answer} }`, with
/// `Item { name }` and `Answer` told apart by `kind`.
fn target() -> Shape {
    let item = Shape::Object(object("Item", &[("name", Shape::Scalar)]));
    let answer = Shape::Tagged(Arc::new(TaggedShape::new(
        Some("Answer".to_owned()),
        "kind".to_owned(),
        [(
            "text".to_owned(),
            object(
                "Answer",
                &[("kind", Shape::Scalar), ("text", Shape::Scalar)],
            ),
        )]
        .into_iter()
        .collect(),
    )));
    Shape::Object(object(
        "Target",
        &[
            ("items", Shape::Array(Arc::new(item.clone()))),
            ("labels", Shape::Map(Arc::new(item))),
            ("answers", Shape::Map(Arc::new(answer))),
        ],
    ))
}

/// Every undeclared key is an ordinary field.
struct NoMembers;

impl Extensions for NoMembers {
    fn classify(&self, _object: &ObjectShape, _key: &str) -> Member {
        Member::Field
    }
}

/// A key with a dot names an extension, and none is negotiated.
struct NoneNegotiated;

impl Extensions for NoneNegotiated {
    fn classify(&self, _object: &ObjectShape, key: &str) -> Member {
        if key.contains('.') {
            Member::Refused
        } else {
            Member::Field
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Counted {
    count: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Kind {
    Plain,
}

#[derive(Debug, Serialize, Deserialize)]
struct Kinded {
    kind: Kind,
}

/// A value whose serialisation fails with a message of its own.
struct Refusing;

impl Serialize for Refusing {
    fn serialize<S: serde::Serializer>(&self, _serializer: S) -> Result<S::Ok, S::Error> {
        Err(serde::ser::Error::custom(format!("cannot write {MARKER}")))
    }
}

#[test]
fn a_failure_says_nothing_it_read_from_the_message() {
    // The byte rules on map keys, as the decoder meets them.
    let duplicate = decode(
        &map_bytes(&[MARKER.to_owned(), MARKER.to_owned()]),
        &Limits::DEFAULT,
    )
    .expect_err("a repeated key");
    assert_eq!(duplicate.rule(), "duplicate_key");
    assert_unmarked("a duplicate key the decoder read", &duplicate);

    let unsorted = decode(
        &map_bytes(&[format!("{MARKER}b"), format!("{MARKER}a")]),
        &Limits::DEFAULT,
    )
    .expect_err("keys out of order");
    assert_eq!(unsorted.rule(), "unsorted_map_keys");
    assert_unmarked("keys out of order the decoder read", &unsorted);

    // And as a map built from entries meets them.
    let built =
        CanonicalMap::from_entries([(MARKER.to_owned(), int(1)), (MARKER.to_owned(), int(2))])
            .expect_err("a repeated key");
    assert_unmarked("a duplicate key in built entries", &built);
    let sorted = CanonicalMap::from_sorted_entries(vec![
        (format!("{MARKER}b"), int(1)),
        (format!("{MARKER}a"), int(2)),
    ])
    .expect_err("keys out of order");
    assert_unmarked("keys out of order in sorted entries", &sorted);
    let inserted = {
        let mut entries = CanonicalMap::new();
        entries
            .insert(MARKER.to_owned(), int(1))
            .expect("the first");
        entries
            .insert(MARKER.to_owned(), int(2))
            .expect_err("the second")
    };
    assert_unmarked("a duplicate key inserted", &inserted);

    // The schema check: an undeclared key, and the keys of a map keyed by data on the way to it.
    let shape = target();
    let undeclared =
        check(&map(&[(MARKER, int(1))]), &shape, &NoMembers).expect_err("an undeclared key");
    assert_eq!(undeclared.rule(), "unknown_field");
    assert_unmarked("an undeclared key", &undeclared);

    let under_a_key = check(
        &map(&[(
            "labels",
            map(&[(MARKER, map(&[("name", int(1)), (MARKER, int(2))]))]),
        )]),
        &shape,
        &NoMembers,
    )
    .expect_err("an undeclared key under a data key");
    assert_unmarked("an undeclared key under a data key", &under_a_key);

    let variant = check(
        &map(&[(
            "answers",
            map(&[(MARKER, map(&[("kind", CanonicalValue::text(MARKER))]))]),
        )]),
        &shape,
        &NoMembers,
    )
    .expect_err("a variant the schema does not have");
    assert_eq!(variant.rule(), "unknown_variant");
    assert_unmarked("a variant the schema does not have", &variant);

    let dotted = format!("{MARKER}.extension");
    let extension = check(&map(&[(dotted.as_str(), int(1))]), &shape, &NoneNegotiated)
        .expect_err("an extension that is not negotiated");
    assert_eq!(extension.rule(), "unnegotiated_extension");
    assert_unmarked("an extension that is not negotiated", &extension);

    // Serde's own messages quote what they refused.
    let mistyped = from_canonical_slice::<Counted>(
        &kr_cbor::encode(&map(&[("count", CanonicalValue::text(MARKER))])),
        &Limits::DEFAULT,
    )
    .expect_err("text where a number belongs");
    assert_eq!(mistyped.rule(), "deserialize_failed");
    assert_unmarked("text where a number belongs", &mistyped);

    let unknown = from_canonical_slice::<Kinded>(
        &kr_cbor::encode(&map(&[("kind", CanonicalValue::text(MARKER))])),
        &Limits::DEFAULT,
    )
    .expect_err("a variant the type does not have");
    assert_unmarked("a variant the type does not have", &unknown);

    let unwritable = to_canonical_value(&Refusing).expect_err("a value that refuses");
    assert_eq!(unwritable.rule(), "serialize_failed");
    assert_unmarked("a value that refuses to be written", &unwritable);

    // Each variant that holds text from a message, with the marker in every such field. The
    // object's place and a tag's name are the schema's words, never the message's.
    for failure in [
        CborError::DuplicateKey {
            key: MARKER.to_owned(),
        },
        CborError::UnsortedMapKeys {
            previous: MARKER.to_owned(),
            current: MARKER.to_owned(),
        },
        CborError::UnknownField {
            at: "Draft at /items/0".to_owned(),
            field: MARKER.to_owned(),
        },
        CborError::UnknownVariant {
            at: "Answer".to_owned(),
            tag: "kind".to_owned(),
            variant: MARKER.to_owned(),
        },
        CborError::UnnegotiatedExtension {
            at: "Metadata".to_owned(),
            extension: MARKER.to_owned(),
        },
        CborError::Deserialize {
            message: format!("invalid type: string \"{MARKER}\", expected u64"),
        },
        CborError::Serialize {
            message: MARKER.to_owned(),
        },
    ] {
        assert_unmarked(failure.rule(), &failure);
    }
}

#[test]
fn a_failure_still_says_its_rule_and_its_place() {
    // Offsets and counts.
    for (failure, said) in [
        (CborError::UnexpectedEnd { offset: 12 }, "offset 12"),
        (CborError::TrailingBytes { count: 3 }, "3 trailing"),
        (CborError::NonShortestInteger { offset: 7 }, "offset 7"),
        (
            CborError::CollectionLimit {
                len: 70_000,
                limit: 65_536,
            },
            "70000 members exceeds the limit of 65536",
        ),
        (
            CborError::InputTooLarge {
                len: 9_000,
                limit: 4_096,
            },
            "9000 bytes exceeds the 4096-byte",
        ),
    ] {
        for rendering in renderings(&failure) {
            assert!(rendering.contains(said), "{rendering}");
        }
        assert!(format!("{failure:?}").starts_with(failure.rule()));
    }

    // The schema's name for the object, and a path of indices, declared members and map entries
    // by position.
    let shape = target();
    let in_array = check(
        &map(&[(
            "items",
            CanonicalValue::Array(vec![
                map(&[("name", int(1))]),
                map(&[("name", int(1)), ("zz", int(2))]),
            ]),
        )]),
        &shape,
        &NoMembers,
    )
    .expect_err("refused");
    assert_eq!(
        in_array.to_string(),
        "Item at /items/1 carries a field it does not declare"
    );
    assert_eq!(
        format!("{in_array:?}"),
        "unknown_field: Item at /items/1 carries a field it does not declare"
    );

    let in_map = check(
        &map(&[(
            "labels",
            map(&[
                ("first", map(&[("name", int(1))])),
                ("second", map(&[("name", int(1)), ("zz", int(2))])),
            ]),
        )]),
        &shape,
        &NoMembers,
    )
    .expect_err("refused");
    assert_eq!(
        in_map.to_string(),
        "Item at /labels/[entry 1] carries a field it does not declare"
    );

    let variant = check(
        &map(&[(
            "answers",
            map(&[("only", map(&[("kind", CanonicalValue::text("other"))]))]),
        )]),
        &shape,
        &NoMembers,
    )
    .expect_err("refused");
    assert_eq!(
        variant.to_string(),
        "Answer at /answers/[entry 0] names a variant in \"kind\" that its schema does not have"
    );

    let extension = check(&map(&[("a.b", int(1))]), &shape, &NoneNegotiated).expect_err("refused");
    assert_eq!(
        extension.to_string(),
        "Target carries a member of an extension that is not negotiated there"
    );
}
