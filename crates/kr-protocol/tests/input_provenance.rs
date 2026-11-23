//! What the answers to terminal input carry: how the action reached the application.
//!
//! The wire values are written here by hand, member by member, and are not read off the types. An
//! answer built before the member existed is bytes a worker of an earlier package sent, and it
//! still reads and writes back as the same bytes; an answer with the member round-trips; and the
//! launch's answer keeps the shape it has at the earlier package.

use kr_cbor::{CanonicalMap, CanonicalValue};
use kr_protocol::envelope::ParamsValue;
use kr_protocol::input::{InputLeaseResult, InputWriteResult};
use kr_protocol::root::{EditorBufferRevision, FenceId, PromptGeneration, ShellLaunchResult};
use kr_protocol::scalars::{U64, Uuid};

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

fn text(value: &str) -> CanonicalValue {
    CanonicalValue::Text(value.to_owned())
}

/// `answer` with one more member, as a peer that knows a member the type does not would send it.
fn with_member(answer: &ParamsValue, name: &str, value: CanonicalValue) -> ParamsValue {
    let CanonicalValue::Map(members) = answer.as_value().clone() else {
        unreachable!("an answer is a map");
    };
    let mut members = members.into_entries();
    members.push((name.to_owned(), value));
    ParamsValue::new(CanonicalValue::Map(
        CanonicalMap::from_entries(members).expect("a new member"),
    ))
}

/// An `input.write` answer as a worker sends it, with the provenance a worker that names it adds.
fn write_answer(provenance: Option<&str>) -> ParamsValue {
    let mut members = vec![
        ("sequence", number(7)),
        ("forwarded_bytes", number(12)),
        ("held_prefix_bytes", number(0)),
    ];
    if let Some(provenance) = provenance {
        members.push(("provenance", text(provenance)));
    }
    ParamsValue::new(map(members))
}

/// An `input.interrupt` or `input.release` answer, with the provenance an interrupt adds.
fn lease_answer(provenance: Option<&str>) -> ParamsValue {
    let mut members = vec![(
        "lease",
        map(vec![
            ("epoch", number(3)),
            ("holder", CanonicalValue::Bytes(vec![0x61; 16])),
            ("connection_id", CanonicalValue::Bytes(vec![0x71; 16])),
            ("next_sequence", number(8)),
        ]),
    )];
    if let Some(provenance) = provenance {
        members.push(("provenance", text(provenance)));
    }
    ParamsValue::new(map(members))
}

/// The same bytes, read by the type and written back.
fn written_back<
    T: serde::Serialize + serde::de::DeserializeOwned + kr_protocol::wire::WireMessage,
>(
    sent: &ParamsValue,
) -> Vec<u8> {
    let read: T = sent.to_typed().expect("the wire value reads");
    let written = ParamsValue::from_typed(&read).expect("it writes");
    kr_cbor::encode(written.as_value())
}

/// KR-REQ-12.09: an answer from a worker that does not name the provenance reads, and writes back
/// as the same bytes, with no member on the wire; one that names it reads and writes back unchanged.
#[test]
fn an_input_answer_reads_with_and_without_the_provenance_and_writes_back_unchanged() {
    for provenance in [None, Some("terminal_input")] {
        let sent = write_answer(provenance);
        assert_eq!(
            written_back::<InputWriteResult>(&sent),
            kr_cbor::encode(sent.as_value()),
            "an input.write answer, provenance {provenance:?}"
        );
        let sent = lease_answer(provenance);
        assert_eq!(
            written_back::<InputLeaseResult>(&sent),
            kr_cbor::encode(sent.as_value()),
            "an input.interrupt answer, provenance {provenance:?}"
        );
    }
}

/// KR-REQ-12.09: the member is an enumerated word and nothing else, and an answer cannot carry it
/// twice or as null: an absent member is the only unset one.
#[test]
fn the_provenance_is_the_one_word_the_protocol_names_and_never_null() {
    for word in ["upstream_typed_rpc", "authenticated_hook_response"] {
        // Every word of the enumeration reads; the worker decides which one it sends.
        assert!(
            write_answer(Some(word))
                .to_typed::<InputWriteResult>()
                .is_ok()
        );
        assert!(
            lease_answer(Some(word))
                .to_typed::<InputLeaseResult>()
                .is_ok()
        );
    }
    for refused in ["terminal", "Terminal_Input", ""] {
        assert!(
            write_answer(Some(refused))
                .to_typed::<InputWriteResult>()
                .is_err(),
            "{refused:?} is no provenance"
        );
        assert!(
            lease_answer(Some(refused))
                .to_typed::<InputLeaseResult>()
                .is_err(),
            "{refused:?} is no provenance"
        );
    }
    let null = with_member(&write_answer(None), "provenance", CanonicalValue::Null);
    assert!(
        null.to_typed::<InputWriteResult>().is_err(),
        "a null is not an unset member"
    );
}

/// The members of the published schema: an optional property naming `ActionProvenance` on the two
/// input answers, and none on the launch's answer.
#[test]
fn the_schema_names_the_provenance_as_an_optional_member_of_the_two_input_answers_only() {
    let bundle = kr_protocol::schema::protocol_schema();
    let definition = |name: &str| bundle["$defs"][name].clone();
    for name in ["InputWriteResult", "InputLeaseResult"] {
        let schema = definition(name);
        let property = &schema["properties"]["provenance"];
        assert!(
            property.to_string().contains("#/$defs/ActionProvenance"),
            "{name} names its provenance: {property}"
        );
        assert!(
            !schema["required"]
                .as_array()
                .expect("required members")
                .iter()
                .any(|required| required == "provenance"),
            "{name} does not require it"
        );
        assert_eq!(schema["additionalProperties"], false, "{name} stays closed");
    }
    let launch = definition("ShellLaunchResult");
    assert!(
        launch["properties"].get("provenance").is_none(),
        "the launch's answer keeps its earlier shape: {launch}"
    );
}

/// KR-REQ-12.09: the launch's answer keeps the shape it has at the earlier package. It is closed,
/// so an answer that names a provenance is not one it reads, which is what a reader built from that
/// package does with it.
#[test]
fn the_launch_answer_keeps_its_earlier_shape() {
    let launch = ParamsValue::from_typed(&ShellLaunchResult {
        fence_id: FenceId::new(Uuid::from_bytes([0x41; 16])),
        prompt_generation: PromptGeneration(U64::new(2)),
        buffer_revision: EditorBufferRevision(U64::new(5)),
    })
    .expect("it writes");
    assert_eq!(
        written_back::<ShellLaunchResult>(&launch),
        kr_cbor::encode(launch.as_value()),
        "the launch answer of the earlier package reads and writes back unchanged"
    );
    let named = with_member(&launch, "provenance", text("terminal_input"));
    assert!(
        named.to_typed::<ShellLaunchResult>().is_err(),
        "a launch answer that names a provenance is not one it reads"
    );
}

/// The answer to `input.write` as a reader built from the 0.78 package has it: closed, with the
/// three members that package named.
#[derive(Debug, serde::Deserialize, serde::Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct EarlierWriteResult {
    sequence: kr_protocol::ids::InputSequence,
    forwarded_bytes: U64,
    held_prefix_bytes: U64,
}

/// The answer to `input.interrupt` and `input.release` as that reader has it.
#[derive(Debug, serde::Deserialize, serde::Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct EarlierLeaseResult {
    lease: kr_protocol::input::InputLeaseState,
}

/// KR-REQ-12.09: a strict reader built from the 0.78 package reads the answers a worker sends that
/// names no provenance, which is every answer of a release, and a release's answer to `input.release`;
/// and it refuses, by the member it does not know, the answer to a write or an interrupt that names
/// one. No 0.78 product reader decodes these two answers, so no product is affected; this is the
/// break the release notes name.
#[test]
fn a_strict_reader_of_the_earlier_package_cannot_read_an_input_answer_that_names_a_provenance() {
    let unnamed = write_answer(None);
    assert!(
        unnamed.to_typed::<EarlierWriteResult>().is_ok(),
        "an answer that names no provenance reads"
    );
    assert!(lease_answer(None).to_typed::<EarlierLeaseResult>().is_ok());

    let named = write_answer(Some("terminal_input"));
    let refusal = named
        .to_typed::<EarlierWriteResult>()
        .expect_err("the earlier reader refuses the answer to a write that names one");
    assert_eq!(refusal.rule(), "unknown_field", "{refusal}");
    let named = lease_answer(Some("terminal_input"));
    let refusal = named
        .to_typed::<EarlierLeaseResult>()
        .expect_err("and the answer to an interrupt");
    assert_eq!(refusal.rule(), "unknown_field", "{refusal}");
}
