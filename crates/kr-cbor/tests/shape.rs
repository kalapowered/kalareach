//! The schema-directed check a message passes before typed decoding.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::sync::Arc;

use kr_cbor::{
    CanonicalMap, CanonicalValue, CborError, Extensions, Member, ObjectShape, Shape, TaggedShape,
    Undeclared, check,
};

/// Every undeclared key is an ordinary field.
struct NoMembers;

impl Extensions for NoMembers {
    fn classify(&self, _object: &ObjectShape, _key: &str) -> Member {
        Member::Field
    }
}

/// Keys that start with `ext.` are extension members; `ext.admitted` is admitted in `Admits` only,
/// with any value, and `ext.block` in `Admits` only, as a closed object declaring `level`.
struct Dotted;

impl Extensions for Dotted {
    fn classify(&self, target: &ObjectShape, key: &str) -> Member {
        match (key, target.name.as_deref()) {
            ("ext.admitted", Some("Admits")) => Member::Admitted(Arc::new(Shape::Any)),
            ("ext.block", Some("Admits")) => Member::Admitted(Arc::new(object(
                "Block",
                &[("level", Shape::Scalar)],
                Undeclared::Refuse,
            ))),
            (key, _) if key.starts_with("ext.") => Member::Refused,
            _ => Member::Field,
        }
    }
}

fn object(name: &str, fields: &[(&str, Shape)], undeclared: Undeclared) -> Shape {
    Shape::Object(Arc::new(ObjectShape {
        name: Some(name.to_owned()),
        fields: fields
            .iter()
            .map(|(field, shape)| ((*field).to_owned(), shape.clone()))
            .collect::<BTreeMap<_, _>>(),
        undeclared,
    }))
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

fn int(value: i128) -> CanonicalValue {
    CanonicalValue::integer(value).expect("in range")
}

/// `Target { session: Scalar, tags: [Scalar], labels: {data -> Item} }` with `Item { name }`.
fn target(undeclared: Undeclared) -> Shape {
    let item = object("Item", &[("name", Shape::Scalar)], Undeclared::Refuse);
    object(
        "Target",
        &[
            ("session", Shape::Scalar),
            ("items", Shape::Array(Arc::new(item.clone()))),
            ("labels", Shape::Map(Arc::new(item))),
        ],
        undeclared,
    )
}

fn item(name: &str) -> CanonicalValue {
    map(&[("name", CanonicalValue::text(name))])
}

#[test]
fn a_closed_object_admits_its_declared_fields_and_borrows_the_value() {
    let value = map(&[
        ("session", int(1)),
        ("items", CanonicalValue::Array(vec![item("a")])),
        ("labels", map(&[("any key at all", item("b"))])),
    ]);
    let checked = check(&value, &target(Undeclared::Refuse), &NoMembers).expect("declared");
    assert!(matches!(checked.value, Cow::Borrowed(_)));
    assert!(checked.members.is_empty());
}

#[test]
fn an_undeclared_key_is_refused_where_it_is_found() {
    let shape = target(Undeclared::Refuse);
    let top = map(&[("session", int(1)), ("zz", int(2))]);
    assert_eq!(
        check(&top, &shape, &NoMembers).expect_err("refused"),
        CborError::UnknownField {
            at: "Target".to_owned(),
            field: "zz".to_owned()
        }
    );

    let in_array = map(&[(
        "items",
        CanonicalValue::Array(vec![item("a"), map(&[("name", int(1)), ("zz", int(2))])]),
    )]);
    assert_eq!(
        check(&in_array, &shape, &NoMembers).expect_err("refused"),
        CborError::UnknownField {
            at: "Item at /items/1".to_owned(),
            field: "zz".to_owned()
        }
    );

    // The keys of a map keyed by data are not fields; its values are still checked, and a failure
    // names an entry by its position, never by the key the message gave it.
    let in_map = map(&[(
        "labels",
        map(&[("a/b~c", map(&[("name", int(1)), ("zz", int(2))]))]),
    )]);
    let error = check(&in_map, &shape, &NoMembers).expect_err("refused");
    assert_eq!(error.rule(), "unknown_field");
    assert_eq!(
        error.to_string(),
        "Item at /labels/[entry 0] carries a field it does not declare"
    );
}

#[test]
fn a_value_of_another_kind_is_left_to_the_typed_layer() {
    let shape = target(Undeclared::Refuse);
    for value in [
        CanonicalValue::text("not an object"),
        map(&[("items", CanonicalValue::text("not an array"))]),
        map(&[("session", map(&[("zz", int(1))]))]),
    ] {
        check(&value, &shape, &NoMembers).expect("nothing here the check reads");
    }
}

#[test]
fn a_variant_is_read_by_the_first_shape_that_takes_it() {
    // An externally tagged enum: `"unit"`, or `{"with": {"x": ...}}`.
    let with = object(
        "Choice",
        &[(
            "with",
            object("With", &[("x", Shape::Scalar)], Undeclared::Refuse),
        )],
        Undeclared::Refuse,
    );
    let shape = Shape::OneOf(vec![with, Shape::Scalar].into());

    check(&CanonicalValue::text("unit"), &shape, &NoMembers).expect("a unit variant");
    check(&map(&[("with", map(&[("x", int(1))]))]), &shape, &NoMembers).expect("a variant");

    // An unknown variant is refused at the top.
    assert_eq!(
        check(&map(&[("other", int(1))]), &shape, &NoMembers).expect_err("refused"),
        CborError::UnknownField {
            at: "Choice".to_owned(),
            field: "other".to_owned()
        }
    );

    // A known variant with an unknown field reports the refusal found deepest.
    assert_eq!(
        check(
            &map(&[("with", map(&[("x", int(1)), ("zz", int(2))]))]),
            &shape,
            &NoMembers
        )
        .expect_err("refused"),
        CborError::UnknownField {
            at: "With at /with".to_owned(),
            field: "zz".to_owned()
        }
    );
}

#[test]
fn read_only_metadata_loses_an_unknown_field_before_typed_decoding() {
    let shape = object(
        "Metadata",
        &[
            ("known", Shape::Scalar),
            ("nested", target(Undeclared::Ignore)),
        ],
        Undeclared::Ignore,
    );
    let value = map(&[
        ("known", int(1)),
        ("later", int(2)),
        ("nested", map(&[("session", int(3)), ("newer", int(4))])),
    ]);
    let checked = check(&value, &shape, &NoMembers).expect("ignored");
    assert_eq!(
        checked.value.into_owned(),
        map(&[("known", int(1)), ("nested", map(&[("session", int(3))]))])
    );
    assert!(
        checked.members.is_empty(),
        "an ignored field is never delivered"
    );
}

#[test]
fn an_extension_member_is_admitted_or_refused_by_the_policy_before_any_other_rule() {
    let admits = object("Admits", &[("known", Shape::Scalar)], Undeclared::Refuse);
    let metadata = object("Metadata", &[("known", Shape::Scalar)], Undeclared::Ignore);

    let value = map(&[("known", int(1)), ("ext.admitted", map(&[("a", int(2))]))]);
    let checked = check(&value, &admits, &Dotted).expect("admitted");
    assert_eq!(checked.value.into_owned(), map(&[("known", int(1))]));
    assert_eq!(checked.members.len(), 1);
    assert_eq!(checked.members[0].object.as_deref(), Some("Admits"));
    assert_eq!(checked.members[0].path, "");
    assert_eq!(checked.members[0].key, "ext.admitted");
    assert_eq!(checked.members[0].value, map(&[("a", int(2))]));

    // Not admitted in this object: refused even though the object ignores unknown fields.
    let error = check(&value, &metadata, &Dotted).expect_err("refused");
    assert_eq!(
        error,
        CborError::UnnegotiatedExtension {
            at: "Metadata".to_owned(),
            extension: "ext.admitted".to_owned()
        }
    );
    assert_eq!(error.rule(), "unnegotiated_extension");
}

#[test]
fn a_variant_that_refuses_gives_back_the_members_it_admitted() {
    // The first variant admits the member and then refuses a later field (keys are read in
    // canonical order, shorter first); the second takes the value without admitting anything.
    let later = "a_longer_undeclared_key";
    let first = object("Admits", &[("known", Shape::Scalar)], Undeclared::Refuse);
    let second = object(
        "Second",
        &[
            ("known", Shape::Scalar),
            ("ext.admitted", Shape::Any),
            (later, Shape::Scalar),
        ],
        Undeclared::Refuse,
    );
    let shape = Shape::OneOf(vec![first.clone(), second].into());
    let value = map(&[("known", int(1)), ("ext.admitted", int(2)), (later, int(3))]);
    assert_eq!(
        check(&value, &first, &Dotted).expect_err("the first variant alone refuses"),
        CborError::UnknownField {
            at: "Admits".to_owned(),
            field: later.to_owned()
        }
    );
    let checked = check(&value, &shape, &Dotted).expect("the second variant");
    assert!(checked.members.is_empty());
    assert!(matches!(checked.value, Cow::Borrowed(_)));
}

#[test]
fn an_opaque_value_is_not_read() {
    let shape = object("Envelope", &[("params", Shape::Any)], Undeclared::Refuse);
    let value = map(&[(
        "params",
        map(&[("anything", int(1)), ("ext.other", int(2))]),
    )]);
    check(&value, &shape, &Dotted).expect("opaque");
}

/// `{"kind": "text", "text": ...}` or `{"kind": "number", "number": ...}`, told apart by `kind`.
fn tagged() -> Shape {
    let variant = |kind: &str, field: &str| {
        let Shape::Object(object) = object(
            "Answer",
            &[("kind", Shape::Scalar), (field, Shape::Scalar)],
            Undeclared::Refuse,
        ) else {
            unreachable!("an object shape");
        };
        (kind.to_owned(), object)
    };
    Shape::Tagged(Arc::new(TaggedShape::new(
        Some("Answer".to_owned()),
        "kind".to_owned(),
        [variant("text", "text"), variant("number", "number")]
            .into_iter()
            .collect(),
    )))
}

#[test]
fn a_tagged_variant_is_checked_against_the_variant_its_tag_names() {
    let shape = tagged();
    check(
        &map(&[
            ("kind", CanonicalValue::text("text")),
            ("text", CanonicalValue::text("x")),
        ]),
        &shape,
        &NoMembers,
    )
    .expect("the variant its tag names");

    // The fields of one variant under the tag of another: the tag decides, as it does for the typed
    // decoder, so the field is undeclared.
    assert_eq!(
        check(
            &map(&[
                ("kind", CanonicalValue::text("number")),
                ("text", CanonicalValue::text("x"))
            ]),
            &shape,
            &NoMembers
        )
        .expect_err("refused"),
        CborError::UnknownField {
            at: "Answer".to_owned(),
            field: "text".to_owned()
        }
    );

    let error = check(
        &map(&[
            ("kind", CanonicalValue::text("other")),
            ("text", CanonicalValue::text("x")),
        ]),
        &shape,
        &NoMembers,
    )
    .expect_err("refused");
    assert_eq!(
        error,
        CborError::UnknownVariant {
            at: "Answer".to_owned(),
            tag: "kind".to_owned(),
            variant: "other".to_owned()
        }
    );
    assert_eq!(error.rule(), "unknown_variant");

    // Without a tag no one variant applies: a key no variant declares is refused, and the rest is
    // the typed layer's, which refuses the missing tag.
    assert_eq!(
        check(&map(&[("zz", int(1))]), &shape, &NoMembers).expect_err("refused"),
        CborError::UnknownField {
            at: "Answer".to_owned(),
            field: "zz".to_owned()
        }
    );
    check(
        &map(&[("text", CanonicalValue::text("x"))]),
        &shape,
        &NoMembers,
    )
    .expect("declared by a variant");
}

#[test]
fn an_admitted_member_is_checked_against_its_own_schema_before_it_is_taken_out() {
    let admits = object("Admits", &[("known", Shape::Scalar)], Undeclared::Refuse);
    let value = map(&[("known", int(1)), ("ext.block", map(&[("level", int(2))]))]);
    let checked = check(&value, &admits, &Dotted).expect("admitted");
    assert_eq!(checked.value.into_owned(), map(&[("known", int(1))]));
    assert_eq!(checked.members[0].key, "ext.block");
    assert_eq!(checked.members[0].value, map(&[("level", int(2))]));

    let widened = map(&[
        ("known", int(1)),
        ("ext.block", map(&[("level", int(2)), ("zz", int(3))])),
    ]);
    assert_eq!(
        check(&widened, &admits, &Dotted).expect_err("refused"),
        CborError::UnknownField {
            at: "Block at /ext.block".to_owned(),
            field: "zz".to_owned()
        }
    );
}
