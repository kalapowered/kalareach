//! Closed mutation schemas, read-only metadata that may carry optional fields, and extensions
//! negotiated by identifier and schema hash.

use std::collections::BTreeMap;

use kr_cbor::{CanonicalMap, CanonicalValue};
use kr_protocol::envelope::ParamsValue;
use kr_protocol::extension::{
    self, ExtensionDefinition, ExtensionError, ExtensionId, ExtensionOffers, NegotiatedExtensions,
};
use kr_protocol::hostinfo::{EnvironmentListResult, EnvironmentSummary, HostInfoResult};
use kr_protocol::question::QuestionAnswerParams;
use kr_protocol::scalars::{Digest256, Nullable, TimestampMs, U64, Uuid};
use kr_protocol::wire::{self, READ_ONLY_METADATA};
use serde_json::{Value, json};

fn host_info() -> HostInfoResult {
    HostInfoResult {
        build_id: kr_protocol::ids::BuildId::new("kr/0.1.0+test").expect("a build identifier"),
        protocol_version: kr_protocol::hello::ProtocolVersion::new(1, 0),
        environment_id: kr_protocol::ids::EnvironmentId::new(Uuid::from_bytes([3; 16])),
        generation: kr_protocol::ids::ControllerGeneration::new(1),
        boot_identity: kr_protocol::identity::BootIdentity {
            source: kr_protocol::identity::BootIdentitySource::BootTime,
            value: kr_protocol::scalars::Bytes::new(vec![1, 2, 3, 4]),
        },
        started_at_ms: TimestampMs::new(1_700_000_000_000),
        live_sessions: U64::new(0),
        session_limit: U64::new(8),
        default_worker_profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
        power: kr_protocol::desktop::SleepInhibitionState {
            holder: Nullable::null(),
            ..kr_protocol::desktop::SleepInhibitionState::off(
                kr_protocol::desktop::InhibitionMechanism::None,
                kr_protocol::desktop::PowerSource::Unknown,
            )
        },
    }
}

/// `value` with `entries` added to its top-level map.
fn with(value: &impl serde::Serialize, entries: &[(&str, CanonicalValue)]) -> CanonicalValue {
    let CanonicalValue::Map(map) = kr_cbor::to_canonical_value(value).expect("a value") else {
        unreachable!("a map");
    };
    let mut all = map.into_entries();
    all.extend(
        entries
            .iter()
            .map(|(key, value)| ((*key).to_owned(), value.clone())),
    );
    CanonicalValue::Map(CanonicalMap::from_entries(all).expect("distinct keys"))
}

fn level(value: i128) -> CanonicalValue {
    CanonicalValue::Map(
        CanonicalMap::from_entries([(
            "level".to_owned(),
            CanonicalValue::integer(value).expect("in range"),
        )])
        .expect("one key"),
    )
}

/// The member schema the test extension adds to a `host.info` result.
fn thermal_schema() -> Value {
    json!({
        "type": "object",
        "properties": {"level": {"type": "integer", "minimum": 0}},
        "required": ["level"],
        "additionalProperties": false
    })
}

fn thermal_id() -> ExtensionId {
    ExtensionId::new("org.example.thermal").expect("an identifier")
}

fn thermal() -> ExtensionDefinition {
    ExtensionDefinition::new(
        thermal_id(),
        [("HostInfoResult".to_owned(), thermal_schema())]
            .into_iter()
            .collect(),
    )
    .expect("a definition")
}

/// KR-REQ-23.14: a mutation's parameter schema is closed for the negotiated version. A field the
/// schema does not declare is refused before typed decoding, never stripped.
#[test]
fn a_mutation_schema_refuses_a_field_it_does_not_declare() {
    let params: QuestionAnswerParams = serde_json::from_value(json!({
        "session_id": "b4a1bc38-157d-4e84-bf52-1137b15b462b",
        "question_id": "3de5e6cb-bf21-49c1-8d34-b9a8729539da",
        "expected_revision": "2",
        "answer": {"kind": "choice", "choice_id": "yes"}
    }))
    .expect("parameters");
    let widened = with(&params, &[("urgency", CanonicalValue::text("high"))]);
    let error = ParamsValue::new(widened)
        .to_typed::<QuestionAnswerParams>()
        .expect_err("refused");
    assert_eq!(error.rule(), "unknown_field", "{error}");
    assert_eq!(wire::refusal_code(&error).as_str(), "UNSUPPORTED_SCHEMA");

    let plain = ParamsValue::from_typed(&params).expect("a value");
    assert_eq!(
        plain.to_typed::<QuestionAnswerParams>().expect("declared"),
        params
    );
}

/// KR-REQ-23.14: read-only metadata may carry an explicitly optional field that a receiver does not
/// know. A `host.info` or `environment.list` result with a field a newer host added is read, and the
/// field is not delivered; a closed object inside the metadata still refuses one.
#[test]
fn read_only_metadata_may_carry_an_optional_field_a_receiver_does_not_know() {
    let info = host_info();
    let newer = with(&info, &[("thermal_state", CanonicalValue::text("nominal"))]);
    let read: HostInfoResult = wire::from_value(&newer).expect("an ignored field");
    assert_eq!(read, info);

    let summary = EnvironmentSummary {
        environment_id: kr_protocol::ids::EnvironmentId::new(Uuid::from_bytes([3; 16])),
        label: "laptop".to_owned(),
        os: "macos".to_owned(),
        arch: "aarch64".to_owned(),
        os_user: "person".to_owned(),
        runtime_directory: "/run/kr".to_owned(),
        state_directory: "/var/kr".to_owned(),
        live_sessions: U64::new(1),
    };
    let listing = CanonicalValue::Map(
        CanonicalMap::from_entries([(
            "environments".to_owned(),
            CanonicalValue::Array(vec![with(
                &summary,
                &[("zone", CanonicalValue::text("eu"))],
            )]),
        )])
        .expect("one key"),
    );
    let read: EnvironmentListResult = wire::from_value(&listing).expect("an ignored field");
    assert_eq!(read.environments, vec![summary]);

    let CanonicalValue::Map(fields) = kr_cbor::to_canonical_value(&info).expect("a value") else {
        unreachable!("a map");
    };
    let entries = fields.into_entries().into_iter().map(|(key, value)| {
        if key == "boot_identity" {
            let CanonicalValue::Map(boot) = value else {
                unreachable!("a map");
            };
            let mut boot = boot.into_entries();
            boot.push(("zz".to_owned(), CanonicalValue::Bool(true)));
            (
                key,
                CanonicalValue::Map(CanonicalMap::from_entries(boot).expect("distinct")),
            )
        } else {
            (key, value)
        }
    });
    let inner = CanonicalValue::Map(CanonicalMap::from_entries(entries).expect("distinct"));
    let error = wire::from_value::<HostInfoResult>(&inner).expect_err("refused");
    assert_eq!(error.rule(), "unknown_field", "{error}");
}

/// KR-REQ-23.14: only a read method's result is ever read-only metadata. No parameter schema,
/// envelope, handshake message, signed object, event or write result reaches an object that may
/// carry fields a receiver ignores, so a mutation schema stays closed by construction.
#[test]
fn read_only_metadata_is_reachable_only_from_read_results() {
    let bundle = kr_protocol::schema::protocol_schema();
    let definitions = bundle["$defs"].as_object().expect("definitions");
    let marked: Vec<&String> = definitions
        .iter()
        .filter(|(_, schema)| schema.get(READ_ONLY_METADATA) == Some(&Value::Bool(true)))
        .map(|(name, _)| name)
        .collect();
    assert_eq!(
        marked,
        [
            "EnvironmentListResult",
            "EnvironmentSummary",
            "HostInfoResult"
        ],
        "the read-only metadata types"
    );

    let references = |schema: &Value| -> Vec<String> {
        let text = schema.to_string();
        text.match_indices("\"#/$defs/")
            .map(|(start, _)| {
                let rest = &text[start + 9..];
                rest[..rest.find('"').expect("a closing quote")].to_owned()
            })
            .collect()
    };
    let reaches = |root: &Value| -> bool {
        let mut pending = references(root);
        let mut seen = std::collections::BTreeSet::new();
        while let Some(next) = pending.pop() {
            if marked.contains(&&next) {
                return true;
            }
            if seen.insert(next.clone()) {
                pending.extend(references(&definitions[&next]));
            }
        }
        false
    };
    let read_results: Vec<String> = kr_protocol::method::REGISTRY
        .iter()
        .filter(|entry| entry.effect == kr_protocol::authority::EffectClass::Read)
        .map(|entry| format!("{}_result", entry.name.replace('.', "_")))
        .collect();
    for (root, schema) in bundle["properties"].as_object().expect("roots") {
        if root == "identifiers" || !reaches(schema) {
            continue;
        }
        assert!(
            read_results.contains(root),
            "{root} reaches read-only metadata but is not a read method's result"
        );
    }
}

/// KR-REQ-23.14: an extension identifier is two or more dot-separated lower-case segments, which is
/// what tells its member from a field.
#[test]
fn an_extension_identifier_is_dotted_lower_case() {
    for good in ["org.example.thermal", "a.b", "kr.voice-2.v1_0"] {
        ExtensionId::new(good).expect(good);
    }
    let too_long = format!("{}.b", "a".repeat(63));
    for bad in [
        "thermal",
        "Org.example",
        ".a",
        "a.",
        "a..b",
        "a.b c",
        too_long.as_str(),
    ] {
        assert_eq!(
            ExtensionId::new(bad),
            Err(ExtensionError::InvalidId),
            "{bad}"
        );
    }
    ExtensionId::new(format!("{}.b", "a".repeat(62))).expect("64 bytes");
}

/// KR-REQ-23.14: the schema hash covers the identifier, every type the extension extends and the
/// exact member schema, and nothing else.
#[test]
fn the_schema_hash_covers_the_identifier_the_types_and_the_exact_schema() {
    let base = thermal();
    let members = base.members().clone();

    // The hash is SHA-256 of KR-CBOR-1 ["kr-extension/1", identifier, {type: schema}].
    let mut map = CanonicalMap::new();
    map.insert(
        "HostInfoResult".to_owned(),
        kr_cbor::to_canonical_value(&thermal_schema()).expect("a schema"),
    )
    .expect("one key");
    let input = kr_cbor::signing_input(
        extension::SCHEMA_DOMAIN,
        vec![
            CanonicalValue::text("org.example.thermal"),
            CanonicalValue::Map(map),
        ],
    )
    .expect("an input");
    assert_eq!(
        base.schema_hash(),
        Digest256::from_bytes(kr_cbor::sha256(&input))
    );

    let other_id = extension::schema_hash(
        &ExtensionId::new("org.example.thermal2").expect("an identifier"),
        &members,
    )
    .expect("a hash");
    let mut other_schema = members.clone();
    other_schema.insert(
        "HostInfoResult".to_owned(),
        json!({"type": "object", "properties": {"level": {"type": "integer"}}, "additionalProperties": false}),
    );
    let mut more_types = members.clone();
    more_types.insert("EnvironmentSummary".to_owned(), thermal_schema());
    for (what, hash) in [
        ("identifier", other_id),
        (
            "schema",
            extension::schema_hash(&thermal_id(), &other_schema).expect("a hash"),
        ),
        (
            "types",
            extension::schema_hash(&thermal_id(), &more_types).expect("a hash"),
        ),
    ] {
        assert_ne!(
            hash,
            base.schema_hash(),
            "the hash does not cover the {what}"
        );
    }
    assert_eq!(
        extension::schema_hash(&thermal_id(), &members).expect("a hash"),
        base.schema_hash(),
        "the same schema hashes the same"
    );

    // A schema that KR-CBOR-1 cannot carry has no hash.
    let mut fraction = members;
    fraction.insert("EnvironmentSummary".to_owned(), json!({"maximum": 0.5}));
    assert!(matches!(
        extension::schema_hash(&thermal_id(), &fraction),
        Err(ExtensionError::UnrepresentableSchema { .. })
    ));
}

/// KR-REQ-23.14: an extension extends read-only metadata only, so a member taken out before typed
/// decoding is never one a signature or a digest covers.
#[test]
fn an_extension_may_extend_read_only_metadata_only() {
    for target in [
        "MutationRequest",
        "Grant",
        "SessionReadResult",
        "NoSuchType",
    ] {
        assert_eq!(
            ExtensionDefinition::new(
                thermal_id(),
                [(target.to_owned(), thermal_schema())]
                    .into_iter()
                    .collect()
            ),
            Err(ExtensionError::NotReadOnlyMetadata {
                target: target.to_owned()
            })
        );
    }
}

/// KR-REQ-23.14: the host selects exactly the offered extensions it holds with the identical hash.
/// A host without an extension, or with another schema for it, leaves it out rather than refusing
/// the offer, and a client refuses a selection that names one it did not offer with that hash.
#[test]
fn an_extension_is_selected_only_by_identifier_and_identical_hash() {
    let ours = thermal();
    let offered = extension::offer(std::slice::from_ref(&ours));
    assert_eq!(offered.get(&thermal_id()), Some(&ours.schema_hash()));

    assert_eq!(
        extension::select(&offered, std::slice::from_ref(&ours)),
        offered
    );
    assert!(
        extension::select(&offered, &[]).is_empty(),
        "a host without it"
    );
    let theirs = ExtensionDefinition::new(
        thermal_id(),
        [(
            "HostInfoResult".to_owned(),
            json!({"type": "object", "properties": {"level": {"type": "string"}}, "additionalProperties": false}),
        )]
        .into_iter()
        .collect(),
    )
    .expect("a definition");
    assert!(
        extension::select(&offered, std::slice::from_ref(&theirs)).is_empty(),
        "a host with another schema"
    );
    assert!(extension::select(&ExtensionOffers::new(), std::slice::from_ref(&ours)).is_empty());

    extension::check_selection(&offered, &offered).expect("the offered extension");
    extension::check_selection(&offered, &ExtensionOffers::new()).expect("none selected");
    let unoffered: ExtensionOffers = [(theirs.id().clone(), theirs.schema_hash())]
        .into_iter()
        .collect();
    assert_eq!(
        extension::check_selection(&offered, &unoffered),
        Err(ExtensionError::NotOffered {
            extension: "org.example.thermal".to_owned()
        })
    );
    assert!(extension::check_selection(&ExtensionOffers::new(), &offered).is_err());

    // This build implements none, so it offers none and every selection it makes is empty.
    assert!(extension::implemented().is_empty());
    assert!(extension::offer(&extension::implemented()).is_empty());
}

/// KR-REQ-23.14: a message that uses an extension the connection did not negotiate is refused
/// before typed decoding. On a connection that negotiated it, the member is checked against the
/// extension's schema, taken out before typed decoding and returned beside the message.
#[test]
fn a_message_may_use_only_an_extension_its_connection_negotiated() {
    let ours = thermal();
    let selected = extension::offer(std::slice::from_ref(&ours));
    let negotiated = NegotiatedExtensions::from_selection(&selected, std::slice::from_ref(&ours));
    assert!(!negotiated.is_empty());

    let info = host_info();
    let extended = with(&info, &[("org.example.thermal", level(2))]);

    let read = wire::from_value_extended::<HostInfoResult>(&extended, &negotiated)
        .expect("a negotiated member");
    assert_eq!(read.message, info);
    assert_eq!(read.members.len(), 1);
    assert_eq!(read.members[0].key, "org.example.thermal");
    assert_eq!(read.members[0].object.as_deref(), Some("HostInfoResult"));
    assert_eq!(read.members[0].path, "");
    assert_eq!(read.members[0].value, level(2));

    for (what, extensions) in [
        ("no extension", NegotiatedExtensions::none()),
        (
            "another selection",
            NegotiatedExtensions::from_selection(&BTreeMap::new(), std::slice::from_ref(&ours)),
        ),
    ] {
        let error =
            wire::from_value_extended::<HostInfoResult>(&extended, &extensions).expect_err(what);
        assert_eq!(error.rule(), "unnegotiated_extension", "{what}: {error}");
        assert_eq!(wire::refusal_code(&error).as_str(), "UNSUPPORTED_SCHEMA");
    }
    let error = wire::from_value::<HostInfoResult>(&extended).expect_err("no extension");
    assert_eq!(error.rule(), "unnegotiated_extension");

    // The member's own schema is closed.
    let widened = with(
        &info,
        &[(
            "org.example.thermal",
            CanonicalValue::Map(
                CanonicalMap::from_entries([
                    (
                        "level".to_owned(),
                        CanonicalValue::integer(2).expect("in range"),
                    ),
                    ("zz".to_owned(), CanonicalValue::Bool(true)),
                ])
                .expect("distinct"),
            ),
        )],
    );
    let error =
        wire::from_value_extended::<HostInfoResult>(&widened, &negotiated).expect_err("refused");
    assert_eq!(error.rule(), "unknown_field", "{error}");

    // A negotiated extension extends only the types it names: the same member in an object it does
    // not extend is refused, and so is any member in a closed object.
    let summary = EnvironmentSummary {
        environment_id: kr_protocol::ids::EnvironmentId::new(Uuid::from_bytes([3; 16])),
        label: "laptop".to_owned(),
        os: "macos".to_owned(),
        arch: "aarch64".to_owned(),
        os_user: "person".to_owned(),
        runtime_directory: "/run/kr".to_owned(),
        state_directory: "/var/kr".to_owned(),
        live_sessions: U64::new(1),
    };
    let elsewhere = with(&summary, &[("org.example.thermal", level(2))]);
    let error = wire::from_value_extended::<EnvironmentSummary>(&elsewhere, &negotiated)
        .expect_err("not extended here");
    assert_eq!(error.rule(), "unnegotiated_extension");

    let boot = with(&info.boot_identity, &[("org.example.thermal", level(2))]);
    let error =
        wire::from_value_extended::<kr_protocol::identity::BootIdentity>(&boot, &negotiated)
            .expect_err("a closed object");
    assert_eq!(error.rule(), "unnegotiated_extension");
}
