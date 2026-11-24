//! The frames and the descriptor of the plugin host protocol `kr-plugin-host/4`.
//!
//! Every member of the protocol round-trips through KR-CBOR-1 (the descriptor, a file, through
//! JSON), every record refuses a member it does not have, the descriptor has to carry the build of
//! the host, and the frames that carry the most fit the control frame. The leaf records that
//! `kr-plugin-host/3` and this protocol share are taken from the frames recorded from a real
//! session of `kr-plugin-host/3`, so no value here is written by hand where a real one exists.

use kr_cbor::{CanonicalMap, CanonicalValue};
use kr_plugin_service::launcher::HostIdentity;
use kr_plugin_service::protocol::{
    BindingRegistration, CallValue, DecodeCall, EncodeCall, Frame, HostHealth, HostProtocol,
    HostVerifyProof, Notice, PrepareActionCall, Request, RequestBody, ResponseBody, WireAttachment,
    WireDecoded, WireEncoded, WireFacts, WireNode, WirePlan, WireSourceEvent,
};
use kr_plugin_service::protocol4::{
    BindingRegistration4, CallValue4, Checkpointed, Consumed, Frame4, HostDescriptor4, Notice4,
    RecordState, Request4, RequestBody4, ResponseBody4, Through,
};
use kr_plugin_service::vocabulary::MAX_NODE_BYTES;
use kr_protocol::frame::StreamKind;
use kr_protocol::hello::PackageVersion;
use kr_protocol::ids::{BuildId, EnvironmentId, MAX_OPAQUE_ID_LEN, SourceEventHandle};
use kr_protocol::local::LocalBuild;
use kr_protocol::scalars::{Nonce256, Uuid};
use kr_protocol::worker::ReservationId;
use serde::Serialize;
use serde::de::DeserializeOwned;

const RECORD: &str = include_str!("recorded/host-3-session-frames.json");

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("hexadecimal"))
        .collect()
}

/// The requests and the frames of the recorded session of `kr-plugin-host/3`.
fn recorded() -> (Vec<Request>, Vec<Frame>) {
    let record: serde_json::Value = serde_json::from_str(RECORD).expect("the record");
    let limits = StreamKind::Control.cbor_limits();
    let (mut requests, mut frames) = (Vec::new(), Vec::new());
    for entry in record["frames"].as_array().expect("the frames") {
        let kind = entry["kind"].as_str().expect("a kind");
        let bytes = unhex(entry["hex"].as_str().expect("the bytes"));
        if kind.starts_with("request:") {
            requests.push(kr_cbor::from_canonical_slice(&bytes, &limits).expect("a request"));
        } else {
            frames.push(kr_cbor::from_canonical_slice(&bytes, &limits).expect("a frame"));
        }
    }
    (requests, frames)
}

fn request_of(name: &str) -> RequestBody {
    recorded()
        .0
        .into_iter()
        .map(|request| request.body)
        .find(|body| body.name() == name)
        .unwrap_or_else(|| panic!("the record holds no {name} request"))
}

fn response_of<T>(pick: impl Fn(ResponseBody) -> Option<T>) -> T {
    recorded()
        .1
        .into_iter()
        .find_map(|frame| match frame {
            Frame::Response { body, .. } => pick(body),
            Frame::Notice(_) => None,
        })
        .expect("the record holds the answer")
}

fn call_value_of<T>(pick: impl Fn(CallValue) -> Option<T>) -> T {
    response_of(|body| match body {
        ResponseBody::Called {
            value: Some(value), ..
        } => pick(value),
        _ => None,
    })
}

fn handle(text: &str) -> SourceEventHandle {
    SourceEventHandle::new(text).expect("a bounded handle")
}

fn binding_id() -> Uuid {
    Uuid::from_bytes([3; 16])
}

fn registration() -> BindingRegistration {
    let RequestBody::RegisterBinding(registration) = request_of("register_binding") else {
        panic!("a registration");
    };
    *registration
}

fn event() -> WireSourceEvent {
    let RequestBody::Event { event, .. } = request_of("event") else {
        panic!("an event");
    };
    event
}

fn facts() -> WireFacts {
    registration().facts
}

fn decode_call() -> DecodeCall {
    let RequestBody::Decode(call) = request_of("decode") else {
        panic!("a decode");
    };
    *call
}

fn encode_call() -> EncodeCall {
    let RequestBody::Encode(call) = request_of("encode") else {
        panic!("an encode");
    };
    *call
}

fn prepare_call() -> PrepareActionCall {
    let RequestBody::PrepareAction(call) = request_of("prepare_action") else {
        panic!("a prepare");
    };
    *call
}

fn through() -> Through {
    Through {
        native: Some(handle("se-3")),
        terminal: Some(handle("se-4")),
    }
}

fn consumed() -> Consumed {
    Consumed {
        registration: 7,
        generation: 2,
        clean: true,
        native: Some(handle("se-3")),
        terminal: None,
    }
}

/// Decodes `bytes` as the type of `like`.
fn decoded_like<T: DeserializeOwned + Serialize>(bytes: &[u8], _like: &T) -> T {
    kr_cbor::from_canonical_slice(bytes, &StreamKind::Control.cbor_limits())
        .expect("the frame decodes")
}

/// Checks that a value reads back as it was written. A macro, so that the assertion is in the case
/// that calls it.
macro_rules! round_trip {
    ($value:expr) => {{
        let value = $value;
        let bytes = kr_cbor::to_canonical_vec(value).expect("the frame encodes");
        let decoded = decoded_like(&bytes, value);
        assert_eq!(&decoded, value);
    }};
}

fn descriptor(build: LocalBuild) -> HostDescriptor4 {
    let identity =
        HostIdentity::generate(EnvironmentId::new(Uuid::from_bytes([1; 16]))).expect("an identity");
    HostDescriptor4 {
        protocol: HostProtocol::V4.name.to_owned(),
        environment_id: identity.environment_id(),
        reservation_id: ReservationId::new(Uuid::from_bytes([2; 16])),
        endpoint: "/run/kr/p4.sock".to_owned(),
        boot_identity: identity.boot_identity().clone(),
        process_start_identity: identity.process_start_identity().clone(),
        host_public_key: *identity.public_key(),
        build,
    }
}

fn a_build() -> LocalBuild {
    LocalBuild {
        build_id: BuildId::new("kr-plugin-host/0.79.0").expect("a build identifier"),
        protocol_version: PackageVersion::new(0, 79, 0),
    }
}

/// F-rt: every request of the protocol round-trips, those with the new members both ways.
#[test]
fn every_request_of_the_protocol_round_trips() {
    let binding_id = binding_id();
    for body in [
        RequestBody4::Hello {
            protocol: HostProtocol::V4.name.to_owned(),
        },
        RequestBody4::Verify {
            nonce: Nonce256::from_bytes([4; 32]),
        },
        RequestBody4::RegisterBinding(Box::new(BindingRegistration4 {
            registration: 11,
            binding: registration(),
        })),
        RequestBody4::Event {
            binding_id,
            event: event(),
        },
        RequestBody4::Snapshot {
            binding_id,
            deadline_ms: 200,
        },
        RequestBody4::PrepareAction(Box::new(prepare_call())),
        RequestBody4::Checkpoint {
            binding_id,
            deadline_ms: 200,
        },
        RequestBody4::Restore {
            binding_id,
            registration: 11,
            state: b"state".to_vec(),
            through: Some(through()),
            deadline_ms: 200,
        },
        RequestBody4::Restore {
            binding_id,
            registration: 11,
            state: b"state".to_vec(),
            through: None,
            deadline_ms: 200,
        },
        RequestBody4::Restore {
            binding_id,
            registration: 11,
            state: b"state".to_vec(),
            through: Some(Through {
                native: None,
                terminal: Some(handle("se-4")),
            }),
            deadline_ms: 200,
        },
        RequestBody4::Unbind { binding_id },
        RequestBody4::Health,
        RequestBody4::Decode(Box::new(decode_call())),
        RequestBody4::Encode(Box::new(encode_call())),
        RequestBody4::ReviseFacts {
            binding_id,
            facts: facts(),
        },
        RequestBody4::ReviseAttachments {
            binding_id,
            attachments: vec![WireAttachment {
                attachment_id: "a-1".to_owned(),
                name: "notes.txt".to_owned(),
                media_type: "text/plain".to_owned(),
                size_bytes: 12,
                completed_at_ms: 9,
            }],
        },
        RequestBody4::Privacy { private: true },
    ] {
        round_trip!(&Request4 {
            request_id: 9,
            body: body.clone(),
        });
        assert!(!body.name().is_empty());
    }
}

/// F-rt: every answer and every notice of the protocol round-trips.
#[test]
fn every_answer_and_every_notice_of_the_protocol_round_trips() {
    let plan: WirePlan = call_value_of(|value| match value {
        CallValue::Plan(plan) => Some(*plan),
        _ => None,
    });
    let decoded: WireDecoded = call_value_of(|value| match value {
        CallValue::Decoded(decoded) => Some(*decoded),
        _ => None,
    });
    let encoded: WireEncoded = call_value_of(|value| match value {
        CallValue::Encoded(encoded) => Some(*encoded),
        _ => None,
    });
    let proof: HostVerifyProof = response_of(|body| match body {
        ResponseBody::Verified(proof) => Some(*proof),
        _ => None,
    });
    let health: HostHealth = response_of(|body| match body {
        ResponseBody::Health(health) => Some(*health),
        _ => None,
    });
    let nodes: Vec<WireNode> = recorded()
        .1
        .into_iter()
        .find_map(|frame| match frame {
            Frame::Notice(Notice::Document { nodes, .. }) => Some(nodes),
            _ => None,
        })
        .expect("the record holds a document");
    let called = |value, fault, document, record| ResponseBody4::Called {
        value,
        fault,
        document,
        record,
    };
    for body in [
        ResponseBody4::Hello {
            protocol: HostProtocol::V4.name.to_owned(),
            descriptor: Box::new(descriptor(a_build())),
        },
        ResponseBody4::Verified(Box::new(proof)),
        ResponseBody4::Registered {
            registration: 11,
            origin: "compiled".to_owned(),
            elapsed_ms: 5,
        },
        ResponseBody4::Admitted {
            admission: "queued".to_owned(),
            lost_events: 2,
            lost_bytes: 300,
            free_bytes: 8_000_000,
        },
        called(Some(CallValue4::Document), None, Some(3), None),
        called(Some(CallValue4::Plan(Box::new(plan))), None, None, None),
        called(
            Some(CallValue4::Checkpointed(Box::new(Checkpointed {
                state: b"resumable".to_vec(),
                consumed: Some(consumed()),
            }))),
            None,
            Some(3),
            None,
        ),
        called(
            Some(CallValue4::Checkpointed(Box::new(Checkpointed {
                state: b"resumable".to_vec(),
                consumed: None,
            }))),
            None,
            None,
            None,
        ),
        called(
            Some(CallValue4::Decoded(Box::new(decoded))),
            None,
            None,
            None,
        ),
        called(
            Some(CallValue4::Encoded(Box::new(encoded))),
            None,
            None,
            None,
        ),
        called(None, Some("the component declined".to_owned()), None, None),
        called(
            Some(CallValue4::Document),
            None,
            None,
            Some(RecordState::Set),
        ),
        called(
            Some(CallValue4::Document),
            None,
            None,
            Some(RecordState::NotSet),
        ),
        called(None, None, None, None),
        ResponseBody4::Unbound { existed: true },
        ResponseBody4::Revised,
        ResponseBody4::PrivacySet { private: false },
        ResponseBody4::Health(Box::new(health)),
        ResponseBody4::Refused {
            request: "restore".to_owned(),
            detail: "a handle over the bound".to_owned(),
            disabled: false,
        },
    ] {
        round_trip!(&Frame4::Response {
            reply_to: 9,
            body: body.clone(),
        });
    }

    let binding_id = binding_id();
    for notice in [
        Notice4::Document {
            binding_id,
            registration: 11,
            call: "observe".to_owned(),
            document: 4,
            last: true,
            nodes,
        },
        Notice4::Gap {
            binding_id,
            registration: 11,
            events: 3,
            bytes: 300,
            documents: 1,
            first: Some(handle("se-1")),
            last: Some(handle("se-3")),
        },
        Notice4::Gap {
            binding_id,
            registration: 11,
            events: 0,
            bytes: 0,
            documents: 2,
            first: None,
            last: None,
        },
        Notice4::Fault {
            binding_id,
            registration: 11,
            call: "observe".to_owned(),
            detail: "trapped".to_owned(),
            faults_in_window: 1,
            event: Some(handle("se-2")),
            generation: 3,
        },
        Notice4::Disabled {
            binding_id,
            registration: 11,
            reason: "disabled".to_owned(),
        },
        Notice4::Consumed {
            binding_id,
            registration: 11,
            generation: 2,
            clean: false,
            native: Some(handle("se-3")),
            terminal: Some(handle("se-4")),
        },
    ] {
        assert_eq!(notice.binding_id(), binding_id);
        assert_eq!(notice.registration(), 11);
        round_trip!(&Frame4::Notice(notice));
    }
}

/// F-rt: the descriptor of the host is a file, and reads back as it was written.
#[test]
fn the_descriptor_reads_back_as_it_was_written() {
    let written = descriptor(a_build());
    let text = serde_json::to_string(&written).expect("a descriptor writes");
    let read: HostDescriptor4 = serde_json::from_str(&text).expect("a descriptor reads");
    assert_eq!(read, written);
}

/// A record with a member added to it, as another build could write it.
fn with_a_member<T: Serialize>(value: &T) -> CanonicalValue {
    let mut encoded = kr_cbor::to_canonical_value(value).expect("the record encodes");
    let CanonicalValue::Map(map) = &mut encoded else {
        panic!("a record is a map");
    };
    map.insert("added".to_owned(), CanonicalValue::Null)
        .expect("the member is added");
    encoded
}

fn refused_with_a_member<T: Serialize + DeserializeOwned>(value: &T, what: &str) {
    assert!(
        kr_cbor::from_canonical_value::<T>(&with_a_member(value)).is_err(),
        "{what} reads a member it does not have"
    );
}

/// The record of `value` as a document, read back as the same type, and with a member added at
/// `place` (a JSON pointer; empty for the record itself). The reading is by serde itself, which
/// shows the record's own `deny_unknown_fields`: the codec refuses any member its target drops, so it
/// shows nothing of the attribute.
fn read_with_a_member<T>(value: &T, place: &str) -> Result<T, serde_json::Error>
where
    T: Serialize + DeserializeOwned + PartialEq + core::fmt::Debug,
{
    let mut document = serde_json::to_value(value).expect("the record is a document");
    let read: T = serde_json::from_value(document.clone()).expect("the record reads back");
    assert_eq!(&read, value);
    document
        .pointer_mut(place)
        .expect("the place is in the record")
        .as_object_mut()
        .expect("the place is an object")
        .insert("added".to_owned(), serde_json::Value::Null);
    serde_json::from_value(document)
}

/// Checks that serde refuses a member the record or variant at `place` does not have. A macro, so
/// that the assertion is in the case that calls it.
macro_rules! closed_in_serde {
    ($value:expr, $place:expr, $what:expr) => {
        assert!(
            read_with_a_member($value, $place).is_err(),
            "{} reads a member it does not have in serde",
            $what
        )
    };
}

/// F-closed: a record of the protocol is closed, and refuses a member it does not have.
#[test]
fn a_member_a_record_does_not_have_is_refused() {
    refused_with_a_member(&through(), "Through");
    refused_with_a_member(&consumed(), "Consumed");
    closed_in_serde!(&through(), "", "Through");
    closed_in_serde!(&consumed(), "", "Consumed");
    // The struct variants of the four enums, read in the byte-free frames.
    let gap = Notice4::Gap {
        binding_id: binding_id(),
        registration: 1,
        events: 1,
        bytes: 1,
        documents: 0,
        first: None,
        last: None,
    };
    closed_in_serde!(&Frame4::Notice(gap), "/notice/gap", "Notice4");
    let called = Frame4::Response {
        reply_to: 1,
        body: ResponseBody4::Called {
            value: None,
            fault: Some("declined".to_owned()),
            document: None,
            record: None,
        },
    };
    closed_in_serde!(&called, "/response", "Frame4");
    closed_in_serde!(&called, "/response/body/called", "ResponseBody4");
    let unbind = Request4 {
        request_id: 1,
        body: RequestBody4::Unbind {
            binding_id: binding_id(),
        },
    };
    closed_in_serde!(&unbind, "/body/unbind", "RequestBody4");
    refused_with_a_member(
        &Checkpointed {
            state: b"s".to_vec(),
            consumed: Some(consumed()),
        },
        "Checkpointed",
    );
    refused_with_a_member(
        &BindingRegistration4 {
            registration: 1,
            binding: registration(),
        },
        "BindingRegistration4",
    );
    refused_with_a_member(
        &Request4 {
            request_id: 1,
            body: RequestBody4::Health,
        },
        "Request4",
    );

    let mut descriptor =
        serde_json::to_value(descriptor(a_build())).expect("a descriptor is a document");
    descriptor["added"] = serde_json::Value::Null;
    assert!(
        serde_json::from_value::<HostDescriptor4>(descriptor).is_err(),
        "HostDescriptor4 reads a member it does not have"
    );
}

/// F-build: a descriptor that does not carry the host's build is not one.
#[test]
fn a_descriptor_without_the_build_of_the_host_is_refused() {
    let mut document =
        serde_json::to_value(descriptor(a_build())).expect("a descriptor is a document");
    document
        .as_object_mut()
        .expect("a descriptor is an object")
        .remove("build");
    assert!(serde_json::from_value::<HostDescriptor4>(document).is_err());
}

/// F-handle: a handle over the bound is refused where a cursor is read, and one at the bound is not.
#[test]
fn a_handle_over_the_bound_is_refused_where_a_cursor_is_read() {
    let cursor = |text: String| {
        CanonicalValue::Map(
            CanonicalMap::from_entries([
                ("native".to_owned(), CanonicalValue::Text(text)),
                ("terminal".to_owned(), CanonicalValue::Null),
            ])
            .expect("a map"),
        )
    };
    let at_the_bound = "h".repeat(MAX_OPAQUE_ID_LEN);
    let read = kr_cbor::from_canonical_value::<Through>(&cursor(at_the_bound.clone()))
        .expect("a handle at the bound is read");
    assert_eq!(read.native, Some(handle(&at_the_bound)));
    for (what, text) in [
        ("over the bound", "h".repeat(MAX_OPAQUE_ID_LEN + 1)),
        ("empty", String::new()),
    ] {
        assert!(
            kr_cbor::from_canonical_value::<Through>(&cursor(text)).is_err(),
            "a handle {what} is read"
        );
    }
}

/// F-size: the frames that carry the most fit the control frame, with the largest state a call may
/// return, the longest handles, and the largest numbers in every member.
#[test]
fn the_frames_that_carry_the_most_fit_the_control_frame() {
    let limit = StreamKind::Control.max_payload_len();
    let longest = || handle(&"h".repeat(MAX_OPAQUE_ID_LEN));
    let state = vec![0xA5_u8; usize::try_from(MAX_NODE_BYTES).expect("a size")];
    let answer = Frame4::Response {
        reply_to: u64::MAX,
        body: ResponseBody4::Called {
            value: Some(CallValue4::Checkpointed(Box::new(Checkpointed {
                state: state.clone(),
                consumed: Some(Consumed {
                    registration: u64::MAX,
                    generation: u32::MAX,
                    clean: true,
                    native: Some(longest()),
                    terminal: Some(longest()),
                }),
            }))),
            fault: None,
            document: Some(u64::MAX),
            record: None,
        },
    };
    let restore = Request4 {
        request_id: u64::MAX,
        body: RequestBody4::Restore {
            binding_id: binding_id(),
            registration: u64::MAX,
            state,
            through: Some(Through {
                native: Some(longest()),
                terminal: Some(longest()),
            }),
            deadline_ms: u64::MAX,
        },
    };
    for (what, bytes) in [
        (
            "a checkpoint",
            kr_cbor::to_canonical_vec(&answer).expect("encodes"),
        ),
        (
            "a restore",
            kr_cbor::to_canonical_vec(&restore).expect("encodes"),
        ),
    ] {
        assert!(
            bytes.len() <= limit,
            "{what} with the largest state takes {} bytes of the {limit} a control frame holds",
            bytes.len()
        );
    }
}
