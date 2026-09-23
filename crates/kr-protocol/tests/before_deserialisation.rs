//! A protocol message is read in the order section 9 requires: every byte rule, then the
//! message's schema, then typed decoding.

use std::cell::Cell;
use std::path::Path;

use kr_cbor::{CborError, Limits};
use kr_protocol::envelope::{MutationRequest, ParamsValue, Response};
use kr_protocol::frame::{FrameCodec, StreamKind};
use kr_protocol::hello::ClientOffer;
use kr_protocol::hostinfo::{EnvironmentListResult, HostInfoResult};
use kr_protocol::question::QuestionAnswerParams;
use kr_protocol::wire::{self, READ_ONLY_METADATA};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

thread_local! {
    /// How often the typed decoder has been asked to build a [`Probe`] on this thread.
    static TYPED_DECODES: Cell<usize> = const { Cell::new(0) };
}

/// A message that counts every time the typed decoder is asked to build one.
#[derive(Debug, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct Probe {
    label: String,
    count: u64,
}

impl<'de> Deserialize<'de> for Probe {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Fields {
            label: String,
            count: u64,
        }

        TYPED_DECODES.with(|calls| calls.set(calls.get() + 1));
        let fields = Fields::deserialize(deserializer)?;
        Ok(Self {
            label: fields.label,
            count: fields.count,
        })
    }
}

fn typed_decodes() -> usize {
    TYPED_DECODES.with(Cell::get)
}

fn reset() {
    TYPED_DECODES.with(|calls| calls.set(0));
}

/// `{"count": 1, "label": "x"}` with one change made to its bytes.
fn probe_bytes(change: &str) -> Vec<u8> {
    let count = [&[0x65][..], b"count", &[0x01]].concat();
    let label = [&[0x65][..], b"label", &[0x61, b'x']].concat();
    match change {
        "none" => [&[0xa2][..], &count, &label].concat(),
        "duplicate_key" => {
            let again = [&[0x65][..], b"count", &[0x02]].concat();
            [&[0xa3][..], &count, &again, &label].concat()
        }
        "invalid_utf8" => {
            let broken = [&[0x65][..], b"label", &[0x61, 0xff]].concat();
            [&[0xa2][..], &count, &broken].concat()
        }
        "unknown_field" => {
            let extra = [&[0x62][..], b"zz", &[0xf5]].concat();
            [&[0xa3][..], &extra, &count, &label].concat()
        }
        other => unreachable!("no change named {other}"),
    }
}

/// KR-REQ-09.02: duplicate keys, invalid UTF-8 and an unknown field are refused before the typed
/// decoder is asked to build anything, on each path a message is read by: bytes, a frame and an
/// opaque value inside a message.
#[test]
fn a_refused_message_never_reaches_the_typed_decoder() {
    let codec = FrameCodec::new(StreamKind::Control);
    for rule in ["duplicate_key", "invalid_utf8", "unknown_field"] {
        let bytes = probe_bytes(rule);

        reset();
        let error = wire::decode::<Probe>(&bytes, &Limits::DEFAULT).expect_err("refused");
        assert_eq!(error.rule(), rule, "{error}");
        assert_eq!(typed_decodes(), 0, "{rule}: the typed decoder ran");

        reset();
        let frame = codec.encode(&bytes).expect("a frame");
        let error = codec.decode_message::<Probe>(&frame).expect_err("refused");
        assert!(
            matches!(&error, kr_protocol::frame::FrameError::Cbor(cbor) if cbor.rule() == rule),
            "{rule}: {error}"
        );
        assert_eq!(
            typed_decodes(),
            0,
            "{rule}: the typed decoder ran on a frame"
        );
    }

    // An opaque value inside a message has already passed the byte rules; its own schema is
    // checked when it is read.
    let opaque = ParamsValue::new(
        kr_cbor::decode(&probe_bytes("unknown_field"), &Limits::DEFAULT).expect("bytes"),
    );
    reset();
    let error = opaque.to_typed::<Probe>().expect_err("refused");
    assert_eq!(error.rule(), "unknown_field", "{error}");
    assert_eq!(
        typed_decodes(),
        0,
        "the typed decoder ran on an opaque value"
    );

    // The probe does see typed decoding when it happens: the plain typed decoder is asked to build
    // the same message and refuses it itself.
    reset();
    let error =
        kr_cbor::from_canonical_slice::<Probe>(&probe_bytes("unknown_field"), &Limits::DEFAULT)
            .expect_err("refused");
    assert_eq!(error.rule(), "deserialize_failed", "{error}");
    assert_eq!(typed_decodes(), 1);

    // And a message that passes both checks reaches the typed decoder exactly once.
    reset();
    let probe = wire::decode::<Probe>(&probe_bytes("none"), &Limits::DEFAULT).expect("admitted");
    assert_eq!(
        probe,
        Probe {
            label: "x".to_owned(),
            count: 1
        }
    );
    assert_eq!(typed_decodes(), 1);
}

/// An answer told apart by its `kind`, which counts every time the typed decoder is asked to build
/// one.
#[derive(Debug, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum TaggedProbe {
    Text { text: String },
    Number { number: u64 },
}

impl<'de> Deserialize<'de> for TaggedProbe {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
        enum Fields {
            Text { text: String },
            Number { number: u64 },
        }

        TYPED_DECODES.with(|calls| calls.set(calls.get() + 1));
        Ok(match Fields::deserialize(deserializer)? {
            Fields::Text { text } => Self::Text { text },
            Fields::Number { number } => Self::Number { number },
        })
    }
}

/// KR-REQ-09.02: a variant told apart by a tag is checked against the variant the tag names, as the
/// typed decoder selects it. A field of another variant under that tag, or a tag naming no variant,
/// is refused before the typed decoder is asked to build anything.
#[test]
fn a_tagged_message_is_checked_against_the_variant_its_tag_names() {
    let tagged = |kind: &str, field: &str, value: kr_cbor::CanonicalValue| {
        let map = kr_cbor::CanonicalMap::from_entries([
            ("kind".to_owned(), kr_cbor::CanonicalValue::text(kind)),
            (field.to_owned(), value),
        ])
        .expect("distinct keys");
        kr_cbor::encode(&kr_cbor::CanonicalValue::Map(map))
    };
    let text = || kr_cbor::CanonicalValue::text("x");

    reset();
    let error = wire::decode::<TaggedProbe>(&tagged("number", "text", text()), &Limits::DEFAULT)
        .expect_err("refused");
    assert_eq!(error.rule(), "unknown_field", "{error}");
    assert_eq!(
        typed_decodes(),
        0,
        "the typed decoder ran on another variant's field"
    );

    reset();
    let error = wire::decode::<TaggedProbe>(&tagged("other", "text", text()), &Limits::DEFAULT)
        .expect_err("refused");
    assert_eq!(error.rule(), "unknown_variant", "{error}");
    assert_eq!(wire::refusal_code(&error).as_str(), "UNSUPPORTED_SCHEMA");
    assert_eq!(
        typed_decodes(),
        0,
        "the typed decoder ran on an unknown variant"
    );

    reset();
    let answer = wire::decode::<TaggedProbe>(&tagged("text", "text", text()), &Limits::DEFAULT)
        .expect("admitted");
    assert_eq!(
        answer,
        TaggedProbe::Text {
            text: "x".to_owned()
        }
    );
    assert_eq!(typed_decodes(), 1);
}

fn fixture(name: &str) -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/cbor")
        .join(name);
    serde_json::from_str(&std::fs::read_to_string(&path).expect("fixture")).expect("json")
}

/// Reads `bytes` as the named root message and returns what typed decoding produced, encoded.
fn read(schema: &str, bytes: &[u8]) -> Result<Vec<u8>, CborError> {
    fn encoded<T: Serialize>(value: &T) -> Vec<u8> {
        kr_cbor::to_canonical_vec(value).expect("a typed value encodes")
    }
    let limits = Limits::DEFAULT;
    Ok(match schema {
        "response" => encoded(&wire::decode::<Response>(bytes, &limits)?),
        "mutation_request" => encoded(&wire::decode::<MutationRequest>(bytes, &limits)?),
        "client_offer" => encoded(&wire::decode::<ClientOffer>(bytes, &limits)?),
        "question_answer_params" => encoded(&wire::decode::<QuestionAnswerParams>(bytes, &limits)?),
        "host_info_result" => encoded(&wire::decode::<HostInfoResult>(bytes, &limits)?),
        "environment_list_result" => {
            encoded(&wire::decode::<EnvironmentListResult>(bytes, &limits)?)
        }
        other => unreachable!("no fixture reads a {other}"),
    })
}

/// KR-REQ-09.02: every refusal in `fixtures/cbor/before-deserialisation.json` names the rule that
/// made it and the error code it answers with, and every admitted case reaches typed decoding with
/// exactly the bytes the fixture gives.
#[test]
fn the_fixture_refusals_name_their_rule_and_their_code() {
    let document = fixture("before-deserialisation.json");
    let cases = document["cases"].as_array().expect("cases");
    let mut rules = std::collections::BTreeSet::new();
    for case in cases {
        let id = case["id"].as_str().expect("id");
        let bytes = hex::decode(case["hex"].as_str().expect("hex")).expect("hex");
        let schema = case["schema"].as_str().expect("schema");
        match (case.get("rule"), read(schema, &bytes)) {
            (Some(rule), Err(error)) => {
                assert_eq!(error.rule(), rule, "{id}: {error}");
                assert_eq!(
                    wire::refusal_code(&error).as_str(),
                    case["code"],
                    "{id}: {error}"
                );
                rules.insert(error.rule());
            }
            (Some(rule), Ok(_)) => panic!("{id}: admitted, expected {rule}"),
            (None, Ok(typed)) => assert_eq!(
                hex::encode(typed),
                case["checked_hex"].as_str().expect("checked hex"),
                "{id}"
            ),
            (None, Err(error)) => panic!("{id}: refused with {error}"),
        }
    }
    for rule in [
        "duplicate_key",
        "invalid_utf8",
        "unknown_field",
        "unknown_variant",
        "unnegotiated_extension",
    ] {
        assert!(rules.contains(rule), "no fixture is refused with {rule}");
    }
}

/// Calls `visit` with every schema the published document holds for a message, and where it is.
fn published(bundle: &Value, visit: &mut dyn FnMut(&str, &serde_json::Map<String, Value>)) {
    fn walk(
        schema: &Value,
        at: &str,
        visit: &mut dyn FnMut(&str, &serde_json::Map<String, Value>),
    ) {
        let Value::Object(keywords) = schema else {
            return;
        };
        visit(at, keywords);
        for (keyword, value) in keywords {
            match (keyword.as_str(), value) {
                ("properties" | "patternProperties" | "$defs", Value::Object(members)) => {
                    for (name, member) in members {
                        walk(member, &format!("{at}/{keyword}/{name}"), visit);
                    }
                }
                ("oneOf" | "anyOf", Value::Array(branches)) => {
                    for (index, branch) in branches.iter().enumerate() {
                        walk(branch, &format!("{at}/{keyword}/{index}"), visit);
                    }
                }
                ("items" | "additionalProperties", member) => {
                    walk(member, &format!("{at}/{keyword}"), visit);
                }
                _ => {}
            }
        }
    }
    for (root, schema) in bundle["properties"].as_object().expect("roots") {
        // The identifier vocabulary is a list of named types, not a message.
        if root != "identifiers" {
            walk(schema, &format!("#/properties/{root}"), visit);
        }
    }
    for (name, schema) in bundle["$defs"].as_object().expect("definitions") {
        // A method table row is published as data and never read from the wire.
        if name != "MethodEntry" {
            walk(schema, &format!("#/$defs/{name}"), visit);
        }
    }
}

/// KR-REQ-09.02: every object the published schema declares says whether it is closed. An object
/// that is not marked read-only metadata is closed in the schema as well as in the check, so a
/// receiver reading the schema and the check agree about every unknown field.
#[test]
fn every_published_object_is_closed_or_marked_read_only_metadata() {
    let bundle = kr_protocol::schema::protocol_schema();
    let mut objects = 0;
    published(&bundle, &mut |at, keywords| {
        let object = keywords.get("type") == Some(&Value::String("object".to_owned()))
            || keywords.contains_key("properties");
        let data_map = !keywords.contains_key("properties")
            && (keywords.contains_key("patternProperties")
                || matches!(keywords.get("additionalProperties"), Some(Value::Object(_))));
        if !object || data_map {
            return;
        }
        objects += 1;
        let closed = keywords.get("additionalProperties") == Some(&Value::Bool(false));
        let metadata = keywords.get(READ_ONLY_METADATA) == Some(&Value::Bool(true));
        assert!(
            closed != metadata,
            "{at} must be closed or marked read-only metadata, and not both"
        );
    });
    assert!(objects > 500, "{objects} objects");
}

/// KR-REQ-09.02: the check reads every keyword the published schema uses to describe structure.
/// A new structural keyword would pass the check by without a look, so it fails here first.
#[test]
fn the_published_schema_uses_only_keywords_the_check_reads() {
    let bundle = kr_protocol::schema::protocol_schema();
    let mut seen = std::collections::BTreeSet::new();
    published(&bundle, &mut |_, keywords| {
        seen.extend(keywords.keys().cloned());
    });

    // What the check reads, and the annotations and scalar constraints it leaves to typed
    // decoding.
    let read = [
        "$ref",
        "additionalProperties",
        "anyOf",
        "const",
        "items",
        "oneOf",
        "patternProperties",
        "properties",
        "type",
        READ_ONLY_METADATA,
    ];
    let left_to_typed_decoding = [
        "contentEncoding",
        "default",
        "description",
        "enum",
        "format",
        "maxItems",
        "maxLength",
        "maximum",
        "minItems",
        "minLength",
        "minimum",
        "pattern",
        "required",
        "tsType",
        "uniqueItems",
    ];
    for keyword in &seen {
        assert!(
            read.contains(&keyword.as_str()) || left_to_typed_decoding.contains(&keyword.as_str()),
            "the published schema uses {keyword}, which the check does not know"
        );
    }
}

/// KR-REQ-09.02: every set of alternatives with more than one object is told apart the way the
/// typed decoder tells it apart: each object declares one key of its own, or every object carries a
/// tag field with a text constant of its own. The check never has to guess which variant a message
/// is.
#[test]
fn every_union_of_objects_is_told_apart_by_a_key_or_a_tag() {
    let bundle = kr_protocol::schema::protocol_schema();
    let definitions = bundle["$defs"].as_object().expect("definitions").clone();
    let resolve = |schema: &Value| -> Value {
        schema["$ref"]
            .as_str()
            .and_then(|reference| reference.strip_prefix("#/$defs/"))
            .map_or_else(|| schema.clone(), |name| definitions[name].clone())
    };
    let mut unions = 0;
    published(&bundle, &mut |at, keywords| {
        for combinator in ["oneOf", "anyOf"] {
            let Some(Value::Array(branches)) = keywords.get(combinator) else {
                continue;
            };
            let objects: Vec<serde_json::Map<String, Value>> = branches
                .iter()
                .map(resolve)
                .filter_map(|branch| branch["properties"].as_object().cloned())
                .collect();
            if objects.len() < 2 {
                continue;
            }
            unions += 1;
            let mut single_keys = std::collections::BTreeSet::new();
            let by_key = objects.iter().all(|properties| {
                properties.len() == 1 && single_keys.insert(properties.keys().next().cloned())
            });
            let by_tag = objects[0].keys().any(|field| {
                let mut constants = std::collections::BTreeSet::new();
                objects.iter().all(|properties| {
                    properties
                        .get(field)
                        .and_then(|schema| schema["const"].as_str())
                        .is_some_and(|constant| constants.insert(constant.to_owned()))
                })
            });
            assert!(by_key || by_tag, "{at}/{combinator} cannot be told apart");
        }
    });
    assert!(unions > 20, "{unions} unions of objects");
}

/// KR-REQ-23.14: no declared field has a dot in its name, so a key with one is always an extension
/// member and never a field a schema declares.
#[test]
fn no_declared_field_name_has_a_dot() {
    let bundle = kr_protocol::schema::protocol_schema();
    published(&bundle, &mut |at, keywords| {
        if let Some(Value::Object(properties)) = keywords.get("properties") {
            for field in properties.keys() {
                assert!(!field.contains('.'), "{at} declares {field}");
            }
        }
    });
}

/// KR-REQ-09.02: no published type refers to itself, so compiling a schema never has to stop at a
/// reference it is still compiling.
#[test]
fn no_published_type_is_recursive() {
    let bundle = kr_protocol::schema::protocol_schema();
    let definitions = bundle["$defs"].as_object().expect("definitions");
    let references = |schema: &Value| -> std::collections::BTreeSet<String> {
        let text = schema.to_string();
        text.match_indices("\"#/$defs/")
            .map(|(start, _)| {
                let rest = &text[start + 9..];
                rest[..rest.find('"').expect("a closing quote")].to_owned()
            })
            .collect()
    };
    for name in definitions.keys() {
        let mut reached = std::collections::BTreeSet::new();
        let mut pending: Vec<String> = references(&definitions[name]).into_iter().collect();
        while let Some(next) = pending.pop() {
            assert!(
                definitions.contains_key(&next),
                "{name} refers to {next}, which is not defined"
            );
            if reached.insert(next.clone()) {
                pending.extend(references(&definitions[&next]));
            }
        }
        assert!(!reached.contains(name), "{name} refers to itself");
    }
}
