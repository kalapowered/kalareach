//! The section 6 identity and object model.
//!
//! Each object in the section 6 table is its own type, with its own named definition in the
//! published schema and the representation its row states. Types that cannot stand in for one
//! another are what keep a session identifier from being accepted where an environment identifier
//! is expected, and the named definitions carry the same separation to the TypeScript package.

use std::any::TypeId;
use std::str::FromStr;

use kr_cbor::{CanonicalValue, Limits, decode, from_canonical_slice, to_canonical_vec};
use kr_protocol::authority::{CapabilityRequirement, EffectClass, RevisionBinding};
use kr_protocol::envelope::{ActionTarget, TargetError};
use kr_protocol::ids::{
    ActionId, AgentBindingRevision, AgentThreadId, AgentTurnId, ApplicationInstanceId,
    ApprovalRequestId, CapabilityId, CapabilityRevision, ControllerGeneration, DeviceId, DraftId,
    DraftRevision, EnvironmentId, GrantId, MachineId, QuestionId, QuestionRevision,
    RemoteDispatchLeaseId, SessionEpoch, SessionId, SessionRef, StreamCursor,
};
use kr_protocol::method::lookup;
use kr_protocol::scalars::{EndpointKey, Nullable, Uuid};
use kr_protocol::schema::protocol_schema;
use serde_json::Value as Json;

/// How one object is represented on the wire and in the published schema.
#[derive(Clone, Copy, Debug)]
enum Shape {
    /// A 128-bit identifier: a 16-byte string on the wire and a hyphenated UUID in JSON.
    Uuid,
    /// An unsigned 64-bit counter or position: an integer on the wire and a decimal string in JSON.
    Counter,
    /// Bounded opaque text that originates outside KalaReach.
    Opaque,
}

fn uuid(text: &str) -> Uuid {
    Uuid::from_str(text).expect("a valid UUID")
}

/// Asserts that no two of the named objects share a Rust type.
///
/// A type alias would give two names one type; a newtype gives each name its own.
fn assert_distinct(objects: &[(&str, TypeId)]) {
    for (index, (left_name, left)) in objects.iter().enumerate() {
        for (right_name, right) in &objects[index + 1..] {
            assert_ne!(
                left, right,
                "{left_name} and {right_name} are the same type"
            );
        }
    }
}

/// Asserts that the published vocabulary names `object` with its own definition of `shape`.
fn assert_object(schema: &Json, object: &str, definition_name: &str, shape: Shape) {
    let reference = schema["properties"]["identifiers"]["properties"][object]["$ref"]
        .as_str()
        .unwrap_or_else(|| panic!("{object} is not in the published vocabulary"));
    assert_eq!(
        reference,
        format!("#/$defs/{definition_name}"),
        "{object} has a definition of its own"
    );
    let definition = &schema["$defs"][definition_name];
    assert_eq!(definition["type"], "string", "{definition_name}");
    match shape {
        Shape::Uuid => assert_eq!(definition["format"], "uuid", "{definition_name}"),
        Shape::Counter => assert_eq!(
            definition["pattern"], "^(0|[1-9][0-9]*)$",
            "{definition_name}"
        ),
        Shape::Opaque => {
            assert_eq!(definition["minLength"], 1, "{definition_name}");
            assert_eq!(definition["maxLength"], 256, "{definition_name}");
        }
    }
}

/// Returns the canonical bytes of `value`.
fn wire<T: serde::Serialize>(value: &T) -> Vec<u8> {
    to_canonical_vec(value).expect("canonical bytes")
}

/// KR-REQ-06.01: the logical machine group, the environment, the iroh endpoint and the session are
/// four distinct objects: four types that cannot stand in for one another, four named definitions
/// in the published schema, and an endpoint that is a 32-byte public key where the other three are
/// 16-byte identifiers, so neither kind decodes as the other.
#[test]
fn a_machine_an_environment_an_endpoint_and_a_session_are_distinct_objects() {
    assert_distinct(&[
        ("machine_id", TypeId::of::<MachineId>()),
        ("environment_id", TypeId::of::<EnvironmentId>()),
        ("endpoint_id", TypeId::of::<EndpointKey>()),
        ("session_id", TypeId::of::<SessionId>()),
    ]);

    let schema = protocol_schema();
    assert_object(&schema, "machine_id", "MachineId", Shape::Uuid);
    assert_object(&schema, "environment_id", "EnvironmentId", Shape::Uuid);
    assert_object(&schema, "session_id", "SessionId", Shape::Uuid);
    let endpoint_definition = &schema["$defs"]["EndpointKey"];
    assert_eq!(endpoint_definition["contentEncoding"], "base64url");
    assert_eq!(endpoint_definition["pattern"], "^[A-Za-z0-9_-]{43}$");

    let machine = MachineId::new(uuid("11111111-2222-4333-8444-555555555555"));
    let environment = EnvironmentId::new(uuid("3de5e6cb-bf21-49c1-8d34-b9a8729539da"));
    let session = SessionId::new(uuid("b4a1bc38-157d-4e84-bf52-1137b15b462b"));
    let endpoint = EndpointKey::from_bytes([0x44; 32]);
    for identifier in [wire(&machine), wire(&environment), wire(&session)] {
        assert_eq!(
            decode(&identifier, &Limits::DEFAULT).expect("canonical"),
            CanonicalValue::Bytes(identifier[1..].to_vec())
        );
        assert_eq!(identifier.len(), 17, "a 16-byte string and its head");
        assert!(
            from_canonical_slice::<EndpointKey>(&identifier, &Limits::DEFAULT).is_err(),
            "a 16-byte identifier is not an endpoint key"
        );
    }
    assert_eq!(wire(&endpoint).len(), 34, "a 32-byte string and its head");
    assert!(
        from_canonical_slice::<SessionId>(&wire(&endpoint), &Limits::DEFAULT).is_err(),
        "an endpoint key is not a session identifier"
    );
}

/// KR-REQ-06.02: version 1 defines exactly one session epoch, 1. It is an integer on the wire, a
/// session reference cannot leave it out, and a mutation target that names a session must name
/// its epoch too.
#[test]
fn the_session_epoch_is_one_wherever_a_session_is_named() {
    assert_eq!(SessionEpoch::V1.get(), 1);
    assert_eq!(hex::encode(wire(&SessionEpoch::V1)), "01");
    assert_object(
        &protocol_schema(),
        "session_epoch",
        "SessionEpoch",
        Shape::Counter,
    );

    let session = SessionId::new(uuid("b4a1bc38-157d-4e84-bf52-1137b15b462b"));
    let reference = SessionRef {
        session_id: session,
        session_epoch: SessionEpoch::V1,
    };
    let json = serde_json::to_value(reference).expect("json");
    assert_eq!(json["session_epoch"], "1");
    assert!(
        serde_json::from_str::<SessionRef>(
            r#"{"session_id":"b4a1bc38-157d-4e84-bf52-1137b15b462b"}"#
        )
        .is_err(),
        "a session reference always carries its epoch"
    );

    let environment = EnvironmentId::new(uuid("3de5e6cb-bf21-49c1-8d34-b9a8729539da"));
    let without_epoch = ActionTarget {
        session_id: Nullable::some(session),
        ..ActionTarget::environment(environment)
    };
    assert_eq!(
        without_epoch.validate(),
        Err(TargetError::SessionEpochMismatch)
    );
    let with_epoch = ActionTarget {
        session_epoch: Nullable::some(SessionEpoch::V1),
        ..without_epoch
    };
    assert_eq!(with_epoch.validate(), Ok(()));
}

/// KR-REQ-06.04: the foreground application instance, the upstream thread, the agent binding
/// revision and the upstream turn are four distinct objects. The instance is a KalaReach
/// identifier; the thread and the turn are bounded upstream text; the binding revision is a
/// counter, and a target that names an application instance cannot leave it out.
#[test]
fn an_application_its_thread_its_binding_and_its_turn_are_distinct_objects() {
    assert_distinct(&[
        (
            "application_instance_id",
            TypeId::of::<ApplicationInstanceId>(),
        ),
        ("agent_thread_id", TypeId::of::<AgentThreadId>()),
        (
            "agent_binding_revision",
            TypeId::of::<AgentBindingRevision>(),
        ),
        ("agent_turn_id", TypeId::of::<AgentTurnId>()),
    ]);

    let schema = protocol_schema();
    assert_object(
        &schema,
        "application_instance_id",
        "ApplicationInstanceId",
        Shape::Uuid,
    );
    assert_object(&schema, "agent_thread_id", "AgentThreadId", Shape::Opaque);
    assert_object(
        &schema,
        "agent_binding_revision",
        "AgentBindingRevision",
        Shape::Counter,
    );
    assert_object(&schema, "agent_turn_id", "AgentTurnId", Shape::Opaque);

    // Upstream identifiers are correlation data: bounded, never empty, never a control character.
    AgentThreadId::new("thread_019a").expect("an upstream thread");
    AgentTurnId::new("turn-7").expect("an upstream turn");
    for rejected in [String::new(), "t".repeat(257), "a\nb".to_owned()] {
        assert!(
            AgentThreadId::new(rejected.clone()).is_err(),
            "{rejected:?}"
        );
        assert!(AgentTurnId::new(rejected.clone()).is_err(), "{rejected:?}");
    }

    // A target naming an application instance carries the binding revision it was addressed at,
    // and a binding revision means nothing without the instance it belongs to.
    let session = ActionTarget {
        session_id: Nullable::some(SessionId::new(uuid("b4a1bc38-157d-4e84-bf52-1137b15b462b"))),
        session_epoch: Nullable::some(SessionEpoch::V1),
        ..ActionTarget::environment(EnvironmentId::new(uuid(
            "3de5e6cb-bf21-49c1-8d34-b9a8729539da",
        )))
    };
    let instance = ApplicationInstanceId::new(uuid("4fe334a4-e934-4bb8-81c7-568252d9cd84"));
    let unbound = ActionTarget {
        application_instance_id: Nullable::some(instance),
        ..session.clone()
    };
    assert_eq!(
        unbound.validate(),
        Err(TargetError::BindingRevisionMismatch)
    );
    let orphaned = ActionTarget {
        agent_binding_revision: Nullable::some(AgentBindingRevision::new(2)),
        ..session.clone()
    };
    assert_eq!(
        orphaned.validate(),
        Err(TargetError::BindingRevisionMismatch)
    );
    let bound = ActionTarget {
        agent_binding_revision: Nullable::some(AgentBindingRevision::new(2)),
        ..unbound
    };
    assert_eq!(bound.validate(), Ok(()));
}

/// KR-REQ-06.05: an action, an upstream approval request and a stream position are distinct
/// objects. An action identifier is a 16-byte KalaReach identifier; an approval request
/// identifier stays the upstream's own opaque text and is never turned into a KalaReach
/// identifier; a cursor is an ordered unsigned 64-bit position.
#[test]
fn an_action_an_approval_request_and_a_stream_position_are_distinct_objects() {
    assert_distinct(&[
        ("action_id", TypeId::of::<ActionId>()),
        ("approval_request_id", TypeId::of::<ApprovalRequestId>()),
        ("stream_cursor", TypeId::of::<StreamCursor>()),
    ]);

    let schema = protocol_schema();
    assert_object(&schema, "action_id", "ActionId", Shape::Uuid);
    assert_object(
        &schema,
        "approval_request_id",
        "ApprovalRequestId",
        Shape::Opaque,
    );
    assert_object(&schema, "stream_cursor", "StreamCursor", Shape::Counter);

    let action = ActionId::new(uuid("e52e8d1a-6818-4be7-b4b8-f93a8b1c0c6d"));
    assert_eq!(
        hex::encode(wire(&action)),
        "50e52e8d1a68184be7b4b8f93a8b1c0c6d"
    );

    // An upstream JSON-RPC identifier keeps its own spelling and stays text on the wire.
    let approval = ApprovalRequestId::new("upstream-opaque-request-id").expect("an upstream id");
    assert_eq!(
        decode(&wire(&approval), &Limits::DEFAULT).expect("canonical"),
        CanonicalValue::text("upstream-opaque-request-id")
    );
    assert!(
        from_canonical_slice::<ActionId>(&wire(&approval), &Limits::DEFAULT).is_err(),
        "an upstream identifier is never a KalaReach action identifier"
    );
    assert!(ApprovalRequestId::new("").is_err());
    assert!(ApprovalRequestId::new("r".repeat(257)).is_err());

    // A cursor is an ordered position that reaches the full unsigned 64-bit range.
    assert!(StreamCursor::new(41) < StreamCursor::new(42));
    let last = StreamCursor::new(u64::MAX);
    assert_eq!(hex::encode(wire(&last)), "1bffffffffffffffff");
    assert_eq!(
        from_canonical_slice::<StreamCursor>(&wire(&last), &Limits::DEFAULT).expect("decodes"),
        last
    );
}

/// KR-REQ-06.08: a question and the revision a person answers, a paired device, a host-issued
/// grant, and a device-owned draft and its revision are distinct objects, and the method registry
/// binds answering or cancelling a question to the question revision and updating a draft to the
/// draft revision. The refusal of any other revision is checked where the methods run.
#[test]
fn questions_devices_grants_and_drafts_are_distinct_objects() {
    assert_distinct(&[
        ("question_id", TypeId::of::<QuestionId>()),
        ("question_revision", TypeId::of::<QuestionRevision>()),
        ("device_id", TypeId::of::<DeviceId>()),
        ("grant_id", TypeId::of::<GrantId>()),
        ("draft_id", TypeId::of::<DraftId>()),
        ("draft_revision", TypeId::of::<DraftRevision>()),
    ]);

    let schema = protocol_schema();
    assert_object(&schema, "question_id", "QuestionId", Shape::Uuid);
    assert_object(
        &schema,
        "question_revision",
        "QuestionRevision",
        Shape::Counter,
    );
    assert_object(&schema, "device_id", "DeviceId", Shape::Uuid);
    assert_object(&schema, "grant_id", "GrantId", Shape::Uuid);
    assert_object(&schema, "draft_id", "DraftId", Shape::Uuid);
    assert_object(&schema, "draft_revision", "DraftRevision", Shape::Counter);

    for (method, binding) in [
        ("question.answer", RevisionBinding::QuestionRevision),
        ("question.cancel", RevisionBinding::QuestionRevision),
        ("draft.update", RevisionBinding::DraftRevision),
    ] {
        let entry = lookup(method).expect("listed");
        assert!(
            matches!(
                entry.capability,
                CapabilityRequirement::Required { revision, .. } if revision == binding
            ),
            "{method} is bound to the exact {binding:?}"
        );
    }
}

/// KR-REQ-06.10: a capability and its revision are objects of their own, and the method registry
/// never lets capability evidence stand alone: a write that asks for it also names the rights or
/// the basis it needs, and a read that asks for it names the resources its scoped read is decided
/// on. The controller generation and the remote dispatch lease are objects of their own, a counter
/// and a random identifier. The grant decision that ignores capabilities is checked where it runs.
#[test]
fn capabilities_and_dispatch_fences_are_distinct_objects() {
    assert_distinct(&[
        ("capability_id", TypeId::of::<CapabilityId>()),
        ("capability_revision", TypeId::of::<CapabilityRevision>()),
        (
            "controller_generation",
            TypeId::of::<ControllerGeneration>(),
        ),
        (
            "remote_dispatch_lease_id",
            TypeId::of::<RemoteDispatchLeaseId>(),
        ),
    ]);

    let schema = protocol_schema();
    assert_object(&schema, "capability_id", "CapabilityId", Shape::Opaque);
    assert_object(
        &schema,
        "capability_revision",
        "CapabilityRevision",
        Shape::Counter,
    );
    assert_object(
        &schema,
        "controller_generation",
        "ControllerGeneration",
        Shape::Counter,
    );
    assert_object(
        &schema,
        "remote_dispatch_lease_id",
        "RemoteDispatchLeaseId",
        Shape::Uuid,
    );

    for entry in kr_protocol::method::REGISTRY {
        if matches!(entry.capability, CapabilityRequirement::Required { .. }) {
            let authority = match entry.effect {
                EffectClass::Write => !entry.required_rights.is_empty(),
                EffectClass::Read => !entry.resource_selectors.is_empty(),
            };
            assert!(
                authority,
                "{} asks for capability evidence and no authority",
                entry.name
            );
        }
    }
}
