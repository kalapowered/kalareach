//! What one `input.write` carries: raw bytes, or the console's key records.
//!
//! The wire values are written here by hand, member by member, and are not read off the types, so
//! a change to a name, a tag or a number's form fails against what a peer sends. Each variant is
//! read from its KR-CBOR-1 wire value and from the JSON the published schema names, and what the
//! union refuses is refused: the bytes written as text, a tag it does not know, a member a record
//! has no place for, a member it lacks.

use kr_cbor::{CanonicalMap, CanonicalValue, Limits};
use kr_protocol::envelope::ParamsValue;
use kr_protocol::hello::PackageVersion;
use kr_protocol::ids::{AttachmentId, BuildId, InputLeaseEpoch, InputSequence, SessionId};
use kr_protocol::input::{ConsoleKey, InputContent, InputWriteParams};
use kr_protocol::local::LocalBuild;
use kr_protocol::retained::{CodecError, Level};
use kr_protocol::scalars::{Bytes, Uuid};
use serde_json::json;

fn map(members: Vec<(&str, CanonicalValue)>) -> CanonicalValue {
    let mut map = CanonicalMap::new();
    for (name, value) in members {
        map.insert(name.to_owned(), value).expect("a new member");
    }
    CanonicalValue::Map(map)
}

fn number(value: i128) -> CanonicalValue {
    CanonicalValue::integer(value).expect("a number")
}

/// A key record as the wire carries it: six members, the numbers as integers.
fn key_value(
    virtual_key: u16,
    unicode: u16,
    key_down: bool,
    control_keys: u32,
    repeat: u16,
) -> CanonicalValue {
    map(vec![
        ("virtual_key", number(virtual_key.into())),
        ("scan_code", number(0x1e)),
        ("unicode", number(unicode.into())),
        ("key_down", CanonicalValue::Bool(key_down)),
        ("control_keys", number(control_keys.into())),
        ("repeat", number(repeat.into())),
    ])
}

fn key(
    virtual_key: u16,
    unicode: u16,
    key_down: bool,
    control_keys: u32,
    repeat: u16,
) -> ConsoleKey {
    ConsoleKey {
        virtual_key,
        scan_code: 0x1e,
        unicode,
        key_down,
        control_keys,
        repeat,
    }
}

/// A write as the wire carries it, with `input` as its input.
fn write_with(input: CanonicalValue) -> ParamsValue {
    ParamsValue::new(map(vec![
        ("session_id", CanonicalValue::Bytes(vec![0x51; 16])),
        ("attachment_id", CanonicalValue::Bytes(vec![0x61; 16])),
        ("epoch", number(3)),
        ("sequence", number(7)),
        ("input", input),
    ]))
}

fn write_of(input: InputContent) -> InputWriteParams {
    InputWriteParams {
        session_id: SessionId::new(Uuid::from_bytes([0x51; 16])),
        attachment_id: AttachmentId::new(Uuid::from_bytes([0x61; 16])),
        epoch: InputLeaseEpoch::new(3),
        sequence: InputSequence::new(7),
        input,
    }
}

fn bytes_input() -> CanonicalValue {
    map(vec![
        ("kind", CanonicalValue::Text("bytes".to_owned())),
        ("bytes", CanonicalValue::Bytes(b"\x1b[A\xffq".to_vec())),
    ])
}

fn keys_input() -> CanonicalValue {
    map(vec![
        ("kind", CanonicalValue::Text("console_keys".to_owned())),
        (
            "keys",
            CanonicalValue::Array(vec![
                key_value(0x41, 0x61, true, 0x20, 1),
                key_value(0x41, 0x61, false, 0x20, 1),
            ]),
        ),
    ])
}

/// Both variants are read from the wire value a peer sends and written back as the same bytes.
#[test]
fn both_variants_read_from_the_wire_and_write_back_unchanged() {
    for (wire, expected) in [
        (
            bytes_input(),
            InputContent::Bytes {
                bytes: Bytes::new(b"\x1b[A\xffq".to_vec()),
            },
        ),
        (
            keys_input(),
            InputContent::ConsoleKeys {
                keys: vec![
                    key(0x41, 0x61, true, 0x20, 1),
                    key(0x41, 0x61, false, 0x20, 1),
                ],
            },
        ),
    ] {
        let sent = write_with(wire);
        let read: InputWriteParams = sent.to_typed().expect("the wire value reads");
        assert_eq!(read, write_of(expected));
        let written = ParamsValue::from_typed(&read).expect("it writes");
        assert_eq!(
            kr_cbor::encode(written.as_value()),
            kr_cbor::encode(sent.as_value())
        );
    }
}

/// The JSON the schema names for each variant: the bytes as unpadded base64url, the records as
/// objects of six members.
#[test]
fn both_variants_read_from_the_json_the_schema_names() {
    let document = |input: serde_json::Value| {
        json!({
            "session_id": "51515151-5151-5151-5151-515151515151",
            "attachment_id": "61616161-6161-6161-6161-616161616161",
            "epoch": "3",
            "sequence": "7",
            "input": input,
        })
    };
    let bytes: InputWriteParams = serde_json::from_value(document(json!({
        "kind": "bytes",
        "bytes": kr_protocol::scalars::to_base64url(b"\x1b[A\xffq"),
    })))
    .expect("the bytes variant reads");
    assert_eq!(
        bytes,
        write_of(InputContent::Bytes {
            bytes: Bytes::new(b"\x1b[A\xffq".to_vec())
        })
    );
    let keys: InputWriteParams = serde_json::from_value(document(json!({
        "kind": "console_keys",
        "keys": [{
            "virtual_key": 65, "scan_code": 30, "unicode": 97,
            "key_down": true, "control_keys": 32, "repeat": 1,
        }],
    })))
    .expect("the key records variant reads");
    assert_eq!(
        keys,
        write_of(InputContent::ConsoleKeys {
            keys: vec![key(65, 97, true, 32, 1)]
        })
    );
    assert_eq!(
        serde_json::to_value(&keys).expect("it writes")["input"]["kind"],
        "console_keys"
    );
}

/// What the union refuses: bytes written as text, a union with no tag, a tag it does not know, a
/// record with a seventh member or without one of its six, a variant carrying the other's member,
/// and a number out of its type's range.
#[test]
fn the_union_refuses_what_it_has_no_place_for() {
    let refused = |input: CanonicalValue| write_with(input).to_typed::<InputWriteParams>().is_err();
    // The bytes as text: the wire has the byte string and nothing else.
    assert!(refused(map(vec![
        ("kind", CanonicalValue::Text("bytes".to_owned())),
        (
            "bytes",
            CanonicalValue::Text(kr_protocol::scalars::to_base64url(b"q"))
        ),
    ])));
    assert!(refused(map(vec![(
        "kind",
        CanonicalValue::Text("scancodes".to_owned())
    )])));
    assert!(refused(map(vec![(
        "bytes",
        CanonicalValue::Bytes(b"q".to_vec())
    )])));
    // A variant keeps to its own members.
    assert!(refused(map(vec![
        ("kind", CanonicalValue::Text("bytes".to_owned())),
        ("bytes", CanonicalValue::Bytes(b"q".to_vec())),
        ("keys", CanonicalValue::Array(Vec::new())),
    ])));
    assert!(refused(map(vec![
        ("kind", CanonicalValue::Text("console_keys".to_owned())),
        ("keys", CanonicalValue::Array(Vec::new())),
        ("bytes", CanonicalValue::Bytes(b"q".to_vec())),
    ])));
    // A record has six members.
    let seventh = map(vec![
        ("virtual_key", number(65)),
        ("scan_code", number(30)),
        ("unicode", number(97)),
        ("key_down", CanonicalValue::Bool(true)),
        ("control_keys", number(0)),
        ("repeat", number(1)),
        ("extended", CanonicalValue::Bool(true)),
    ]);
    let missing = map(vec![
        ("virtual_key", number(65)),
        ("scan_code", number(30)),
        ("unicode", number(97)),
        ("key_down", CanonicalValue::Bool(true)),
        ("control_keys", number(0)),
    ]);
    for record in [seventh, missing] {
        assert!(refused(map(vec![
            ("kind", CanonicalValue::Text("console_keys".to_owned())),
            ("keys", CanonicalValue::Array(vec![record])),
        ])));
    }
    let wide = map(vec![
        ("virtual_key", number(65_536)),
        ("scan_code", number(30)),
        ("unicode", number(97)),
        ("key_down", CanonicalValue::Bool(true)),
        ("control_keys", number(0)),
        ("repeat", number(1)),
    ]);
    assert!(refused(map(vec![
        ("kind", CanonicalValue::Text("console_keys".to_owned())),
        ("keys", CanonicalValue::Array(vec![wide])),
    ])));
}

/// A write says which variant it is and how much it carries, and nothing a person typed: not a
/// byte, and not a number of a key record.
#[test]
fn a_write_prints_its_variant_and_its_size_and_nothing_it_carries() {
    let bytes = InputContent::Bytes {
        bytes: Bytes::new(b"hunter2".to_vec()),
    };
    assert_eq!(format!("{bytes:?}"), "Bytes { len: 7 }");
    let keys = InputContent::ConsoleKeys {
        keys: vec![key(0x48, 0x1234, true, 0x1111, 77); 3],
    };
    assert_eq!(format!("{keys:?}"), "ConsoleKeys { count: 3 }");
    assert_eq!(
        format!("{:?}", key(0x48, 0x1234, true, 0x1111, 77)),
        "ConsoleKey { .. }"
    );
    for rendering in [
        format!("{:?}", write_of(keys.clone())),
        format!("{:#?}", write_of(keys)),
        format!("{:?}", write_of(bytes)),
    ] {
        for carried in ["4660", "4369", "1234", "1111", "hunter", "72"] {
            assert!(!rendering.contains(carried), "{rendering}");
        }
    }
}

/// The retained level's worker, from the build it states.
fn retained_worker() -> Level {
    let level = Level::of(Some(&LocalBuild {
        build_id: BuildId::new("kr-worker/0.1.0").expect("a build identifier"),
        protocol_version: PackageVersion::new(0, 77, 0),
    }))
    .expect("the retained level");
    assert!(!level.is_this());
    level
}

/// The write a device sends today and the write the release before read, as the two releases wrote
/// the same values: the daemon writes the first as the second for a retained worker, and sends a
/// worker of its own level what it was given. The pair is called here by hand because the retained
/// table lists no definition of this write: `InputWriteParams` is not a root of the surface.
#[test]
fn a_write_for_a_retained_worker_is_what_the_release_before_wrote() {
    let current = include_bytes!("../retained/0.77/golden/input-write.current.cbor");
    let retained = include_bytes!("../retained/0.77/golden/input-write.retained.cbor");
    let sent = ParamsValue::new(kr_cbor::decode(current, &Limits::DEFAULT).expect("a value"));
    let typed: InputWriteParams = sent.to_typed().expect("the current write reads");
    assert_eq!(
        typed,
        write_of(InputContent::Bytes {
            bytes: Bytes::new(b"\x1b[A\xffq".to_vec())
        })
    );
    assert_eq!(
        kr_cbor::to_canonical_vec(&typed).expect("it writes"),
        current,
        "the current bytes are what this build writes"
    );
    let written = retained_worker()
        .encode_input_write(&sent)
        .expect("a bytes write has a counterpart");
    assert_eq!(kr_cbor::encode(written.as_value()), retained);
    assert_eq!(
        Level::this().encode_input_write(&sent).expect("unchanged"),
        sent
    );
}

/// Key records have no counterpart at the level before, and nothing is written for it: the refusal
/// names them. A write the current type does not read is refused as the type refuses it, not as a
/// lack of the level.
#[test]
fn key_records_have_no_counterpart_at_a_retained_worker_and_a_malformed_write_is_not_one() {
    match retained_worker().encode_input_write(&write_with(keys_input())) {
        Err(CodecError::NotInLevel { refusal, .. }) => {
            assert!(refusal.to_string().contains("console_keys"), "{refusal}");
        }
        other => panic!("expected a refusal by name, got {other:?}"),
    }
    let malformed = write_with(map(vec![(
        "kind",
        CanonicalValue::Text("console_keys".to_owned()),
    )]));
    assert!(matches!(
        retained_worker().encode_input_write(&malformed),
        Err(CodecError::Cbor(_))
    ));
}

/// A retained level that reads the union is sent the write as it was given: the rewrite is for the
/// levels below it, and a key-record write reaches a worker of such a level whole.
#[test]
fn a_write_for_a_retained_level_that_reads_the_union_is_sent_as_it_is() {
    use kr_protocol::retained::RetainedLevel;
    use kr_protocol::update::CompatibilityLevel;

    let level = Level::retained(Box::leak(Box::new(RetainedLevel::new(
        CompatibilityLevel::of(PackageVersion::new(0, 78, 0)),
        "",
        "",
        "",
        &[],
        &[],
    ))));
    assert!(!level.is_this());
    for write in [write_with(keys_input()), write_with(bytes_input())] {
        assert_eq!(level.encode_input_write(&write).expect("unchanged"), write);
    }
}
