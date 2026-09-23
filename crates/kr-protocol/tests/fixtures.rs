//! Cross-language conformance tests driven by `fixtures/protocol/`.
//!
//! The TypeScript package loads the same files and asserts the same bytes and digests.

use std::path::PathBuf;
use std::str::FromStr;

use kr_cbor::{CanonicalMap, CanonicalValue, Limits, decode, encode};
use kr_protocol::digest::{MUTATION_DOMAIN, mutation_digest, mutation_signing_input};
use kr_protocol::envelope::{ActionTarget, MutationRequest, ParamsValue};
use kr_protocol::frame::{FrameCodec, StreamKind};
use kr_protocol::hello::{
    CONNECT_DOMAIN, ClientOffer, HostSelection, ProtocolVersion, ReceiveLimits, connect_transcript,
    connect_transcript_digest,
};
use kr_protocol::ids::{
    ActionId, ActionWindowId, ActorId, AgentBindingRevision, ApplicationInstanceId, BootEpoch,
    BuildId, CapabilityId, ClockEpoch, ConnectionId, DeviceId, DeviceKeyRevision, EnvironmentId,
    GrantId, RequestId, SessionEpoch, SessionId,
};
use kr_protocol::method::{Method, MethodVersion};
use kr_protocol::scalars::{CanonicalSet, DurationMs, EndpointKey, Nonce256, Nullable, Uuid};
use serde_json::Value as Json;

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/protocol")
}

fn load(name: &str) -> Json {
    let path = fixture_dir().join(name);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|error| panic!("parse {}: {error}", path.display()))
}

/// Parses the fixture value grammar into a canonical value.
fn parse_value(description: &Json) -> CanonicalValue {
    let object = description.as_object().expect("value description object");
    assert_eq!(object.len(), 1, "a value description has exactly one key");
    let (kind, payload) = object.iter().next().expect("one entry");
    match kind.as_str() {
        "int" => CanonicalValue::integer(
            payload
                .as_str()
                .expect("decimal string")
                .parse::<i128>()
                .expect("decimal integer"),
        )
        .expect("inside the 64-bit argument range"),
        "bytes" => {
            CanonicalValue::Bytes(hex::decode(payload.as_str().expect("hex")).expect("valid hex"))
        }
        "text" => CanonicalValue::text(payload.as_str().expect("string")),
        "bool" => CanonicalValue::Bool(payload.as_bool().expect("boolean")),
        "null" => CanonicalValue::Null,
        "array" => CanonicalValue::Array(
            payload
                .as_array()
                .expect("array")
                .iter()
                .map(parse_value)
                .collect(),
        ),
        "map" => {
            let mut map = CanonicalMap::new();
            for entry in payload.as_array().expect("array of pairs") {
                let pair = entry.as_array().expect("pair");
                map.insert(
                    pair[0].as_str().expect("text key").to_owned(),
                    parse_value(&pair[1]),
                )
                .expect("no duplicate keys");
            }
            CanonicalValue::Map(map)
        }
        other => panic!("unknown value kind {other}"),
    }
}

fn case<'a>(document: &'a Json, id: &str) -> &'a Json {
    document["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .find(|case| case["id"] == id)
        .unwrap_or_else(|| panic!("case {id}"))
}

fn uuid(text: &str) -> Uuid {
    Uuid::from_str(text).expect("valid uuid")
}

fn capabilities() -> CanonicalSet<CapabilityId> {
    ["semantic.updates", "terminal.direct"]
        .into_iter()
        .map(|name| CapabilityId::new(name).expect("capability name"))
        .collect()
}

fn client_offer() -> ClientOffer {
    ClientOffer {
        offered_versions: vec![ProtocolVersion::new(1, 0)],
        build_id: BuildId::new("kr/0.1.0+fixture").expect("build id"),
        device_id: DeviceId::new(uuid("9c2f1a6e-4b77-4f10-9f2a-6de0f5c4a311")),
        device_key_revision: DeviceKeyRevision::new(1),
        capabilities: capabilities(),
        max_receive: ReceiveLimits::default(),
        client_nonce: Nonce256::from_bytes([0x11; 32]),
        extensions: kr_protocol::extension::ExtensionOffers::new(),
    }
}

fn host_selection() -> HostSelection {
    HostSelection {
        host_nonce: Nonce256::from_bytes([0x22; 32]),
        client_nonce: Nonce256::from_bytes([0x11; 32]),
        connection_id: ConnectionId::new(uuid("7f1c0f2a-2c1e-4c61-9d2e-0b9f8a7c6d55")),
        selected_version: ProtocolVersion::new(1, 0),
        capabilities: capabilities(),
        limits: ReceiveLimits::default(),
        endpoint_id: EndpointKey::from_bytes([0x44; 32]),
        device_id: DeviceId::new(uuid("2a4b6c8d-0e1f-4a2b-8c3d-4e5f60718293")),
        device_key_revision: DeviceKeyRevision::new(1),
        boot_epoch: BootEpoch::new(7),
        clock_epoch: ClockEpoch::new(3),
        extensions: kr_protocol::extension::ExtensionOffers::new(),
    }
}

fn mutation_request() -> MutationRequest {
    let mut expected = CanonicalMap::new();
    expected
        .insert(
            "approval_request_id".to_owned(),
            CanonicalValue::text("upstream-opaque-request-id"),
        )
        .expect("insert");
    expected
        .insert(
            "request_revision".to_owned(),
            CanonicalValue::integer(3).expect("int"),
        )
        .expect("insert");
    expected
        .insert("state".to_owned(), CanonicalValue::text("pending"))
        .expect("insert");

    let mut params = CanonicalMap::new();
    params
        .insert("decision".to_owned(), CanonicalValue::text("deny"))
        .expect("insert");

    MutationRequest {
        request_id: RequestId::new(41),
        method: Method::AgentApprovalRespond.into(),
        method_version: MethodVersion::V1,
        action_id: ActionId::new(uuid("e52e8d1a-6818-4be7-b4b8-f93a8b1c0c6d")),
        grant_id: Nullable::some(GrantId::new(uuid("39a6b26e-e8fd-4e0c-9a37-8f3dc4911641"))),
        target: ActionTarget {
            environment_id: EnvironmentId::new(uuid("3de5e6cb-bf21-49c1-8d34-b9a8729539da")),
            session_id: Nullable::some(SessionId::new(uuid(
                "b4a1bc38-157d-4e84-bf52-1137b15b462b",
            ))),
            session_epoch: Nullable::some(SessionEpoch::V1),
            application_instance_id: Nullable::some(ApplicationInstanceId::new(uuid(
                "4fe334a4-e934-4bb8-81c7-568252d9cd84",
            ))),
            agent_binding_revision: Nullable::some(AgentBindingRevision::new(2)),
        },
        expected: ParamsValue::new(CanonicalValue::Map(expected)),
        action_window_id: ActionWindowId::new("host-issued-window-id").expect("window id"),
        requested_ttl_ms: DurationMs::new(120_000),
        params: ParamsValue::new(CanonicalValue::Map(params)),
    }
}

fn actor_id() -> ActorId {
    ActorId::new("device:9c2f1a6e-4b77-4f10-9f2a-6de0f5c4a311").expect("actor id")
}

/// Asserts that `message` serialises to the fixture bytes and that the fixture bytes decode back.
fn assert_matches_fixture<T>(document: &Json, id: &str, message: &T)
where
    T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
{
    let case = case(document, id);
    let expected_hex = case["cbor_hex"].as_str().expect("cbor_hex");
    let expected = hex::decode(expected_hex).expect("valid hex");

    let encoded = kr_cbor::to_canonical_vec(message).expect("encode");
    assert_eq!(hex::encode(&encoded), expected_hex, "{id}: encoded bytes");

    let described = parse_value(&case["value"]);
    assert_eq!(
        hex::encode(encode(&described)),
        expected_hex,
        "{id}: the fixture description and its bytes disagree"
    );

    let decoded_value = decode(&expected, &Limits::DEFAULT).expect("decode");
    assert_eq!(decoded_value, described, "{id}: decoded value");

    let decoded: T = kr_cbor::from_canonical_slice(&expected, &Limits::DEFAULT).expect("typed");
    assert_eq!(&decoded, message, "{id}: typed round trip");

    let framed = FrameCodec::new(StreamKind::Control)
        .encode(&encoded)
        .expect("frame");
    assert_eq!(
        hex::encode(&framed),
        case["frame_hex"].as_str().expect("frame_hex"),
        "{id}: framed bytes"
    );
}

/// KR-REQ-23.13: the client's hello carries its offered versions, build, device, capabilities,
/// receive limits and a fresh nonce, in the published bytes.
#[test]
fn client_offer_matches_fixture() {
    let document = load("frames.json");
    assert_matches_fixture(&document, "client_offer", &client_offer());
}

/// KR-REQ-23.13: the host's answer carries its nonce, the client's nonce, the connection identity,
/// the selected version, capabilities and limits, its endpoint and device, and its boot and clock
/// epochs, in the published bytes.
#[test]
fn host_selection_matches_fixture() {
    let document = load("frames.json");
    assert_matches_fixture(&document, "host_selection", &host_selection());
}

/// KR-REQ-09.01: a mutation's elements, in the published bytes.
#[test]
fn mutation_request_matches_fixture() {
    let document = load("frames.json");
    assert_matches_fixture(&document, "mutation_request", &mutation_request());
}

/// KR-REQ-23.11: every published frame is a four-byte length and one canonical object.
#[test]
fn every_frame_fixture_round_trips_as_bytes() {
    // KR-REQ-01.25: canonical bytes are a preserved contract: every published envelope encodes to
    // exactly its committed bytes and frame, and decodes back to exactly its committed value.
    // KR-REQ-04.08: every published message travels as a four-byte length followed by one
    // canonical CBOR object, on the stream kind the fixture names.
    let document = load("frames.json");
    let cases = document["cases"].as_array().expect("cases");
    assert!(cases.len() >= 7, "frames fixture covers the envelope types");
    for case in cases {
        let id = case["id"].as_str().expect("id");
        let described = parse_value(&case["value"]);
        let encoded = encode(&described);
        assert_eq!(
            hex::encode(&encoded),
            case["cbor_hex"].as_str().expect("cbor_hex"),
            "{id}: bytes"
        );
        assert_eq!(
            decode(&encoded, &Limits::DEFAULT).expect("decode"),
            described,
            "{id}: value"
        );
        let kind = match case["stream_kind"].as_str().expect("stream_kind") {
            "control" => StreamKind::Control,
            "terminal_input" => StreamKind::TerminalInput,
            "attachment_chunks" => StreamKind::AttachmentChunks,
            other => panic!("{id}: unknown stream kind {other}"),
        };
        let framed = FrameCodec::new(kind).encode(&encoded).expect("frame");
        assert_eq!(
            hex::encode(&framed),
            case["frame_hex"].as_str().expect("frame_hex"),
            "{id}: frame"
        );
    }
}

#[test]
fn receipt_and_notification_fixtures_decode_into_types() {
    use kr_protocol::envelope::{Notification, Response};
    use kr_protocol::frame::StreamHeader;
    use kr_protocol::receipt::{ReceiptResponse, ReceiptState};

    // KR-REQ-01.25: a receipt, an error response, a notification and a stream header decode from
    // their committed bytes into the typed model and re-encode to exactly those bytes.
    let document = load("frames.json");

    let receipt_bytes = hex::decode(
        case(&document, "receipt_response")["cbor_hex"]
            .as_str()
            .expect("hex"),
    )
    .expect("hex");
    let receipt: ReceiptResponse =
        kr_cbor::from_canonical_slice(&receipt_bytes, &Limits::DEFAULT).expect("receipt");
    assert_eq!(receipt.receipt.state, ReceiptState::Accepted);
    assert_eq!(
        kr_cbor::to_canonical_vec(&receipt).expect("re-encode"),
        receipt_bytes
    );

    let error_bytes = hex::decode(
        case(&document, "error_response")["cbor_hex"]
            .as_str()
            .expect("hex"),
    )
    .expect("hex");
    let response: Response =
        kr_cbor::from_canonical_slice(&error_bytes, &Limits::DEFAULT).expect("response");
    assert_eq!(
        kr_cbor::to_canonical_vec(&response).expect("re-encode"),
        error_bytes
    );

    let notification_bytes = hex::decode(
        case(&document, "notification")["cbor_hex"]
            .as_str()
            .expect("hex"),
    )
    .expect("hex");
    let notification: Notification =
        kr_cbor::from_canonical_slice(&notification_bytes, &Limits::DEFAULT).expect("notification");
    assert_eq!(
        kr_cbor::to_canonical_vec(&notification).expect("re-encode"),
        notification_bytes
    );

    let header_bytes = hex::decode(
        case(&document, "stream_header")["cbor_hex"]
            .as_str()
            .expect("hex"),
    )
    .expect("hex");
    let header = StreamHeader::decode(&header_bytes).expect("header");
    assert_eq!(header.encode().expect("re-encode"), header_bytes);
}

/// KR-REQ-23.15: the kr-connect/1 transcript covers the complete offer, the complete selection and
/// both endpoint identities, in the published bytes.
#[test]
fn connect_transcript_matches_fixture() {
    // KR-REQ-01.25: the signed fields of a connection are a preserved contract: the transcript both
    // proofs sign is exactly the committed bytes and digest, under the committed domain.
    let document = load("transcripts.json");
    let case = case(&document, "connect_transcript");
    assert_eq!(case["domain"].as_str().expect("domain"), CONNECT_DOMAIN);

    let client_endpoint = EndpointKey::from_bytes(
        hex::decode(case["client_endpoint_id"].as_str().expect("hex"))
            .expect("hex")
            .try_into()
            .expect("32 bytes"),
    );
    let host_endpoint = EndpointKey::from_bytes(
        hex::decode(case["host_endpoint_id"].as_str().expect("hex"))
            .expect("hex")
            .try_into()
            .expect("32 bytes"),
    );

    let transcript = connect_transcript(
        &client_offer(),
        &host_selection(),
        &client_endpoint,
        &host_endpoint,
    )
    .expect("transcript");
    assert_eq!(hex::encode(&transcript), case["hex"].as_str().expect("hex"));

    let digest = connect_transcript_digest(
        &client_offer(),
        &host_selection(),
        &client_endpoint,
        &host_endpoint,
    )
    .expect("digest");
    assert_eq!(
        hex::encode(digest.as_bytes()),
        case["sha256"].as_str().expect("sha256")
    );
}

/// KR-REQ-23.07: the mutation digest's signing input, in the published bytes.
#[test]
fn mutation_digest_matches_fixture() {
    // KR-REQ-01.25: the fields a mutation's digest covers are a preserved contract: its signing
    // input is exactly the committed bytes and digest, under the committed domain.
    let document = load("transcripts.json");
    let case = case(&document, "mutation_digest");
    assert_eq!(case["domain"].as_str().expect("domain"), MUTATION_DOMAIN);

    let request = mutation_request();
    let signing_input = mutation_signing_input(&request, &actor_id()).expect("signing input");
    assert_eq!(
        hex::encode(&signing_input),
        case["hex"].as_str().expect("hex")
    );
    assert_eq!(
        hex::encode(
            mutation_digest(&request, &actor_id())
                .expect("digest")
                .as_bytes()
        ),
        case["sha256"].as_str().expect("sha256")
    );
}

/// KR-REQ-23.07: the connection-local request identifier is outside the digest; the freshness
/// window and the actor are inside it.
#[test]
fn the_digest_ignores_request_id_but_covers_the_action_window() {
    let request = mutation_request();
    let baseline = mutation_digest(&request, &actor_id()).expect("digest");

    // An exact retry on a new connection carries a different request_id and must not look like a
    // different payload.
    let retry = MutationRequest {
        request_id: RequestId::new(9_001),
        ..mutation_request()
    };
    assert_eq!(
        mutation_digest(&retry, &actor_id()).expect("digest"),
        baseline
    );

    // Replacing the freshness window changes the payload, so it is a new first admission.
    let rewindowed = MutationRequest {
        action_window_id: ActionWindowId::new("another-window").expect("window id"),
        ..mutation_request()
    };
    assert_ne!(
        mutation_digest(&rewindowed, &actor_id()).expect("digest"),
        baseline
    );

    // A different actor holding the same action identifier is a different de-duplication key.
    let other_actor = ActorId::new("device:2a4b6c8d-0e1f-4a2b-8c3d-4e5f60718293").expect("actor");
    assert_ne!(
        mutation_digest(&request, &other_actor).expect("digest"),
        baseline
    );
}

/// KR-REQ-23.07: the mutation digest covers the method and its version, the grant, every field of
/// the target, the preconditions, the action identifier, the freshness window and time to live,
/// and the parameters: changing any one of them changes the digest.
#[test]
fn the_digest_covers_every_field_a_mutation_is_admitted_on() {
    let baseline = mutation_digest(&mutation_request(), &actor_id()).expect("digest");
    let other = |text: &str| -> Uuid { uuid(text) };
    let target = mutation_request().target;
    let mut preconditions = CanonicalMap::new();
    preconditions
        .insert("state".to_owned(), CanonicalValue::text("resolved"))
        .expect("insert");
    let mut params = CanonicalMap::new();
    params
        .insert("decision".to_owned(), CanonicalValue::text("allow"))
        .expect("insert");

    let variants: Vec<(&str, MutationRequest)> = vec![
        (
            "method",
            MutationRequest {
                method: Method::AgentTurnCancel.into(),
                ..mutation_request()
            },
        ),
        (
            "method version",
            MutationRequest {
                method_version: MethodVersion(2),
                ..mutation_request()
            },
        ),
        (
            "grant",
            MutationRequest {
                grant_id: Nullable::some(GrantId::new(other(
                    "5d6e7f80-9a1b-4c2d-8e3f-a0b1c2d3e4f5",
                ))),
                ..mutation_request()
            },
        ),
        (
            "no grant",
            MutationRequest {
                grant_id: Nullable::null(),
                ..mutation_request()
            },
        ),
        (
            "environment",
            MutationRequest {
                target: ActionTarget {
                    environment_id: EnvironmentId::new(other(
                        "11111111-2222-4333-8444-555555555555",
                    )),
                    ..target.clone()
                },
                ..mutation_request()
            },
        ),
        (
            "session",
            MutationRequest {
                target: ActionTarget {
                    session_id: Nullable::some(SessionId::new(other(
                        "2a4b6c8d-0e1f-4a2b-8c3d-4e5f60718293",
                    ))),
                    ..target.clone()
                },
                ..mutation_request()
            },
        ),
        (
            "session epoch",
            MutationRequest {
                target: ActionTarget {
                    session_epoch: Nullable::some(SessionEpoch::new(2)),
                    ..target.clone()
                },
                ..mutation_request()
            },
        ),
        (
            "application instance",
            MutationRequest {
                target: ActionTarget {
                    application_instance_id: Nullable::some(ApplicationInstanceId::new(other(
                        "9c2f1a6e-4b77-4f10-9f2a-6de0f5c4a311",
                    ))),
                    ..target.clone()
                },
                ..mutation_request()
            },
        ),
        (
            "agent binding revision",
            MutationRequest {
                target: ActionTarget {
                    agent_binding_revision: Nullable::some(AgentBindingRevision::new(3)),
                    ..target.clone()
                },
                ..mutation_request()
            },
        ),
        (
            "preconditions",
            MutationRequest {
                expected: ParamsValue::new(CanonicalValue::Map(preconditions)),
                ..mutation_request()
            },
        ),
        (
            "action",
            MutationRequest {
                action_id: ActionId::new(other("7f1c0f2a-2c1e-4c61-9d2e-0b9f8a7c6d55")),
                ..mutation_request()
            },
        ),
        (
            "freshness window",
            MutationRequest {
                action_window_id: ActionWindowId::new("host-issued-window-2").expect("window"),
                ..mutation_request()
            },
        ),
        (
            "time to live",
            MutationRequest {
                requested_ttl_ms: DurationMs::new(60_000),
                ..mutation_request()
            },
        ),
        (
            "parameters",
            MutationRequest {
                params: ParamsValue::new(CanonicalValue::Map(params)),
                ..mutation_request()
            },
        ),
    ];
    for (what, variant) in &variants {
        assert_ne!(
            mutation_digest(variant, &actor_id()).expect("digest"),
            baseline,
            "the digest does not cover the {what}"
        );
    }

    let signing_input = mutation_signing_input(&mutation_request(), &actor_id()).expect("input");
    let decoded = decode(&signing_input, &Limits::DEFAULT).expect("canonical");
    let CanonicalValue::Array(items) = decoded else {
        panic!("the signing input is a domain-separated array");
    };
    assert_eq!(items[0], CanonicalValue::text(MUTATION_DOMAIN));
    let CanonicalValue::Map(covered) = &items[1] else {
        panic!("the covered fields are a map");
    };
    let names: Vec<&str> = covered
        .entries()
        .iter()
        .map(|(key, _)| key.as_str())
        .collect();
    assert_eq!(
        names,
        [
            "method",
            "params",
            "target",
            "actor_id",
            "expected",
            "grant_id",
            "action_id",
            "method_version",
            "action_window_id",
            "requested_ttl_ms",
        ],
        "the covered fields, in canonical order, and nothing from the diagnostic JSON"
    );
}
