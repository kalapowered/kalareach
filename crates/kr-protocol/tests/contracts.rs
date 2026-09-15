//! The receipt transition contract, error codes, grants, framing and the two representations.

use std::collections::BTreeSet;
use std::str::FromStr;

use kr_cbor::Limits;
use kr_protocol::error::{ErrorCode, ProtocolError, RetryCategory};
use kr_protocol::frame::{FrameCodec, FrameError, StreamHeader, StreamKind, StreamResource};
use kr_protocol::grant::{
    EnvironmentSelector, Grant, GrantExpiry, HistoryScope, OrganisationRequirement, SessionSelector,
};
use kr_protocol::hello::{PROTOCOL_VERSION, ProtocolVersion, select_version};
use kr_protocol::ids::{
    ActorId, AttachmentId, AuthorityRevision, ConnectionId, DeviceId, EnvironmentId, GrantId,
    OrganisationId, RequestId, SessionEpoch, SessionId, StreamId,
};
use kr_protocol::limits::{
    MAX_ATTACHMENT_FRAME_LEN, MAX_CONTROL_FRAME_LEN, MAX_INPUT_FRAME_LEN, MAX_STREAM_HEADER_LEN,
};
use kr_protocol::method::{Method, MethodVersion};
use kr_protocol::receipt::{Receipt, ReceiptState, RejectionReason, TransitionError};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{Digest256, Nullable, TimestampMs, U64, Uuid};

fn uuid(text: &str) -> Uuid {
    Uuid::from_str(text).expect("valid uuid")
}

// ----- receipt transition contract ----------------------------------------------------------

fn receipt(state: ReceiptState, revision: u64) -> Receipt {
    Receipt {
        action_id: kr_protocol::ids::ActionId::new(uuid("e52e8d1a-6818-4be7-b4b8-f93a8b1c0c6d")),
        actor_id: ActorId::new("device:test").expect("actor"),
        method: Method::AgentApprovalRespond.into(),
        method_version: MethodVersion::V1,
        revision: U64::new(revision),
        state,
        reason: Nullable::null(),
        payload_digest: Digest256::from_bytes([0; 32]),
        accepted_deadline_ms: Nullable::null(),
        error: Nullable::null(),
        updated_at_ms: TimestampMs::new(1_789_012_345_678),
    }
}

#[test]
fn the_permitted_transitions_are_exactly_the_contract() {
    use ReceiptState::{Accepted, Applied, Dispatching, Received, Refused, Rejected, Unknown};
    let expected: &[(ReceiptState, &[ReceiptState])] = &[
        (Received, &[Accepted, Rejected]),
        (Accepted, &[Dispatching, Rejected]),
        (Dispatching, &[Applied, Refused, Unknown]),
        (Applied, &[]),
        (Refused, &[]),
        (Rejected, &[]),
        (Unknown, &[Applied, Refused]),
    ];
    for (state, permitted) in expected {
        assert_eq!(state.permitted_transitions(), *permitted, "{state}");
        for target in ReceiptState::ALL {
            assert_eq!(
                state.can_transition_to(*target),
                permitted.contains(target),
                "{state} -> {target}"
            );
        }
    }
}

#[test]
fn a_dispatch_marker_is_never_followed_by_a_rejection() {
    // Section 9: no dispatching -> rejected transition may imply that an uncertain side effect did
    // not happen.
    for state in [
        ReceiptState::Dispatching,
        ReceiptState::Unknown,
        ReceiptState::Applied,
        ReceiptState::Refused,
    ] {
        assert!(state.has_dispatch_marker(), "{state}");
        assert!(!state.can_transition_to(ReceiptState::Rejected), "{state}");
    }
    assert!(!ReceiptState::Received.has_dispatch_marker());
    assert!(!ReceiptState::Accepted.has_dispatch_marker());
    assert!(!ReceiptState::Rejected.has_dispatch_marker());
}

#[test]
fn received_is_never_durable_and_terminal_states_are_final() {
    assert!(!ReceiptState::Received.is_durable());
    for state in ReceiptState::ALL
        .iter()
        .filter(|s| **s != ReceiptState::Received)
    {
        assert!(state.is_durable(), "{state}");
    }
    for state in [
        ReceiptState::Applied,
        ReceiptState::Refused,
        ReceiptState::Rejected,
    ] {
        assert!(state.is_terminal());
        assert!(state.permitted_transitions().is_empty());
    }
    assert!(!ReceiptState::Unknown.is_terminal());
}

#[test]
fn the_state_machine_rejects_a_forbidden_edge() {
    let mut subject = receipt(ReceiptState::Dispatching, 3);
    assert_eq!(
        subject.advance(
            ReceiptState::Rejected,
            U64::new(4),
            Some(RejectionReason::Cancelled)
        ),
        Err(TransitionError::Forbidden {
            from: ReceiptState::Dispatching,
            to: ReceiptState::Rejected
        })
    );
    assert_eq!(subject.state, ReceiptState::Dispatching);
    assert_eq!(subject.revision, U64::new(3));
}

#[test]
fn the_state_machine_requires_an_increasing_revision() {
    let mut subject = receipt(ReceiptState::Accepted, 5);
    assert_eq!(
        subject.advance(ReceiptState::Dispatching, U64::new(5), None),
        Err(TransitionError::RevisionNotIncreasing {
            current: 5,
            next: 5
        })
    );
    assert!(
        subject
            .advance(ReceiptState::Dispatching, U64::new(6), None)
            .is_ok()
    );
    assert_eq!(subject.revision, U64::new(6));
}

#[test]
fn a_rejection_names_its_reason_and_nothing_else_carries_one() {
    let mut subject = receipt(ReceiptState::Accepted, 1);
    assert_eq!(
        subject.advance(ReceiptState::Rejected, U64::new(2), None),
        Err(TransitionError::ReasonRequired)
    );
    assert_eq!(
        subject.advance(
            ReceiptState::Dispatching,
            U64::new(2),
            Some(RejectionReason::Expired)
        ),
        Err(TransitionError::ReasonNotPermitted {
            state: ReceiptState::Dispatching
        })
    );
    assert!(
        subject
            .advance(
                ReceiptState::Rejected,
                U64::new(2),
                Some(RejectionReason::Cancelled)
            )
            .is_ok()
    );
    assert_eq!(subject.reason, Nullable::some(RejectionReason::Cancelled));
}

#[test]
fn a_full_dispatch_path_reaches_an_authoritative_outcome() {
    let mut subject = receipt(ReceiptState::Received, 0);
    assert!(
        subject
            .advance(ReceiptState::Accepted, U64::new(1), None)
            .is_ok()
    );
    assert!(
        subject
            .advance(ReceiptState::Dispatching, U64::new(2), None)
            .is_ok()
    );
    assert!(
        subject
            .advance(ReceiptState::Unknown, U64::new(3), None)
            .is_ok()
    );
    // Only authoritative reconciliation resolves an unknown outcome.
    assert!(
        subject
            .advance(ReceiptState::Applied, U64::new(4), None)
            .is_ok()
    );
    assert!(subject.state.is_terminal());
    assert_eq!(
        subject.advance(ReceiptState::Refused, U64::new(5), None),
        Err(TransitionError::Forbidden {
            from: ReceiptState::Applied,
            to: ReceiptState::Refused
        })
    );
}

// ----- error codes ---------------------------------------------------------------------------

#[test]
fn every_required_error_code_is_defined_with_a_stable_string() {
    let required = [
        "INVALID_ARGUMENT",
        "UNSUPPORTED_SCHEMA",
        "UNSUPPORTED_CAPABILITY",
        "PERMISSION_DENIED",
        "PAIRING_EXPIRED",
        "PAIRING_REJECTED",
        "PAIRING_AUTH_FAILED",
        "PAIRING_ATTEMPTS_EXHAUSTED",
        "RENDEZVOUS_UNAVAILABLE",
        "RENDEZVOUS_CONFIG_ERROR",
        "UNKNOWN_SESSION",
        "AMBIGUOUS_SESSION",
        "AMBIGUOUS_ATTACHMENT",
        "TERMINAL_UNAVAILABLE",
        "TERMINAL_PROBE_FAILED",
        "INPUT_INCOMPATIBLE",
        "SESSION_CLOSED",
        "SESSION_LIMIT",
        "RESOURCE_UNAVAILABLE",
        "HOST_NOT_CONFIGURED",
        "ENVIRONMENT_UNAVAILABLE",
        "DESKTOP_UNAVAILABLE",
        "STALE_SESSION",
        "LEASE_LOST",
        "GEOMETRY_NOT_OWNER",
        "DRAFT_CONFLICT",
        "EDITOR_BUSY",
        "ID_CONFLICT",
        "UPSTREAM_UNAVAILABLE",
        "OUTCOME_UNKNOWN",
        "RESYNC_REQUIRED",
        "QUOTA_EXCEEDED",
        "RATE_LIMITED",
        "SERVICE_CAPACITY",
        "CLOCK_UNTRUSTED",
        "STORAGE_UNAVAILABLE",
        "SHELL_INTEGRATION_UNSUPPORTED",
        "ATTACHMENT_INTEGRITY",
        "REPOSITORY_UNTRUSTED",
        "PACKAGE_UNAVAILABLE_OFFLINE",
        "PLUGIN_GRANT_REQUIRED",
        "PLUGIN_DISABLED",
        "QUESTION_RESOLVED",
        "QUESTION_EXPIRED",
        "NOT_IN_KR_SESSION",
        "OWNER_CONFIRMATION_REQUIRED",
        "CAUSAL_LIMIT",
        "SOURCE_CHANGED",
    ];
    for name in required {
        let code = ErrorCode::from_wire(name).unwrap_or_else(|| panic!("{name} is missing"));
        assert_eq!(code.as_str(), name);
        assert_eq!(ErrorCode::from_str(name).expect("parses"), code);
    }
    assert_eq!(ErrorCode::ALL.len(), required.len());
    let unique: BTreeSet<&str> = ErrorCode::ALL.iter().map(|code| code.as_str()).collect();
    assert_eq!(unique.len(), required.len());
    assert!(ErrorCode::from_wire("NOT_A_CODE").is_none());
}

#[test]
fn error_codes_serialise_as_their_stable_strings() {
    for code in ErrorCode::ALL {
        let json = serde_json::to_string(code).expect("json");
        assert_eq!(json, format!("\"{}\"", code.as_str()));
        let wire = kr_cbor::to_canonical_vec(code).expect("cbor");
        assert_eq!(
            kr_cbor::decode(&wire, &Limits::DEFAULT).expect("decode"),
            kr_cbor::CanonicalValue::text(code.as_str())
        );
    }
}

#[test]
fn the_uncertain_and_resync_codes_have_their_required_retry_categories() {
    assert_eq!(
        ErrorCode::OutcomeUnknown.retry_category(),
        RetryCategory::OutcomeUnknown
    );
    assert!(
        !ErrorCode::OutcomeUnknown
            .retry_category()
            .permits_automatic_retry()
    );
    assert_eq!(
        ErrorCode::ResyncRequired.retry_category(),
        RetryCategory::Resync
    );
    for code in [
        ErrorCode::UnsupportedSchema,
        ErrorCode::UnsupportedCapability,
        ErrorCode::PermissionDenied,
        ErrorCode::InvalidArgument,
    ] {
        assert_eq!(
            code.retry_category(),
            RetryCategory::ConfigurationChange,
            "{code} is an authentication or schema failure"
        );
        assert!(!code.retry_category().permits_automatic_retry());
    }
    for code in [
        ErrorCode::RateLimited,
        ErrorCode::ServiceCapacity,
        ErrorCode::UpstreamUnavailable,
        ErrorCode::StorageUnavailable,
    ] {
        assert!(code.retry_category().permits_automatic_retry(), "{code}");
    }
}

#[test]
fn a_constructed_error_carries_the_category_of_its_code() {
    for code in ErrorCode::ALL {
        let error = ProtocolError::new(*code, "message");
        assert_eq!(error.retry, code.retry_category());
        assert!(error.is_consistent());
        assert!(!error.diagnostic_id.is_present());
    }
}

// ----- grants ---------------------------------------------------------------------------------

fn base_grant() -> Grant {
    Grant {
        grant_id: GrantId::new(uuid("39a6b26e-e8fd-4e0c-9a37-8f3dc4911641")),
        parent_grant_id: Nullable::null(),
        issuer_device_id: DeviceId::new(uuid("9c2f1a6e-4b77-4f10-9f2a-6de0f5c4a311")),
        recipient_device_id: DeviceId::new(uuid("2a4b6c8d-0e1f-4a2b-8c3d-4e5f60718293")),
        authority_revision: AuthorityRevision::new(4),
        environment_selector: EnvironmentSelector::Any,
        session_selector: SessionSelector::Any,
        actions: [
            ActionRight::SessionView,
            ActionRight::TerminalInput,
            ActionRight::AgentPrompt,
        ]
        .into_iter()
        .collect(),
        history: HistoryScope {
            lower_bound_ms: Nullable::some(TimestampMs::new(1_000)),
            include_live_screen: true,
            named_questions: BTreeSet::new(),
            named_approvals: BTreeSet::new(),
        },
        expiry: GrantExpiry::At {
            expires_at_ms: TimestampMs::new(10_000),
        },
        organisation: Nullable::null(),
    }
}

#[test]
fn delegation_narrows_and_never_extends() {
    let parent = base_grant();
    let child = Grant {
        grant_id: GrantId::new(uuid("5d6e7f80-9a1b-4c2d-8e3f-a0b1c2d3e4f5")),
        parent_grant_id: Nullable::some(parent.grant_id),
        actions: [ActionRight::SessionView].into_iter().collect(),
        environment_selector: EnvironmentSelector::These {
            environment_ids: [EnvironmentId::new(uuid(
                "3de5e6cb-bf21-49c1-8d34-b9a8729539da",
            ))]
            .into_iter()
            .collect(),
        },
        session_selector: SessionSelector::These {
            session_ids: [SessionId::new(uuid("b4a1bc38-157d-4e84-bf52-1137b15b462b"))]
                .into_iter()
                .collect(),
        },
        history: HistoryScope {
            lower_bound_ms: Nullable::some(TimestampMs::new(5_000)),
            include_live_screen: false,
            named_questions: BTreeSet::new(),
            named_approvals: BTreeSet::new(),
        },
        expiry: GrantExpiry::At {
            expires_at_ms: TimestampMs::new(9_000),
        },
        ..base_grant()
    };
    assert!(child.narrows(&parent));

    // A later lower bound narrows; an earlier one would see history the parent cannot.
    let deeper_history = Grant {
        history: HistoryScope {
            lower_bound_ms: Nullable::some(TimestampMs::new(500)),
            ..child.history.clone()
        },
        ..child.clone()
    };
    assert!(!deeper_history.narrows(&parent));

    let longer = Grant {
        expiry: GrantExpiry::Never,
        ..child.clone()
    };
    assert!(!longer.narrows(&parent));

    let wider_actions = Grant {
        actions: [ActionRight::SessionView, ActionRight::HostManage]
            .into_iter()
            .collect(),
        ..child.clone()
    };
    assert!(!wider_actions.narrows(&parent));

    let wider_sessions = Grant {
        session_selector: SessionSelector::Any,
        ..child.clone()
    };
    assert!(
        wider_sessions.narrows(&parent),
        "the parent already selects any session"
    );

    let orphan = Grant {
        parent_grant_id: Nullable::null(),
        ..child.clone()
    };
    assert!(!orphan.narrows(&parent), "a delegation names its parent");
}

#[test]
fn an_organisation_requirement_cannot_be_dropped_by_delegation() {
    let parent = Grant {
        organisation: Nullable::some(OrganisationRequirement {
            organisation_id: OrganisationId::new(uuid("11111111-2222-4333-8444-555555555555")),
            policy_revision: AuthorityRevision::new(2),
        }),
        ..base_grant()
    };
    let child = Grant {
        grant_id: GrantId::new(uuid("5d6e7f80-9a1b-4c2d-8e3f-a0b1c2d3e4f5")),
        parent_grant_id: Nullable::some(parent.grant_id),
        actions: [ActionRight::SessionView].into_iter().collect(),
        organisation: Nullable::null(),
        ..base_grant()
    };
    assert!(!child.narrows(&parent));
}

#[test]
fn a_personal_owner_grant_never_expires_and_an_expired_one_stays_expired() {
    assert!(GrantExpiry::Never.is_valid_at(u64::MAX));
    let expiring = GrantExpiry::At {
        expires_at_ms: TimestampMs::new(10),
    };
    assert!(expiring.is_valid_at(9));
    assert!(!expiring.is_valid_at(10));
    assert!(!expiring.is_valid_at(11));
}

#[test]
fn the_action_vocabulary_is_the_closed_section_10_set() {
    let expected = [
        "session.view",
        "terminal.input",
        "terminal.geometry",
        "terminal.geometry.transfer",
        "terminal.palette",
        "agent.prompt",
        "agent.cancel",
        "agent.approval.respond",
        "question.respond",
        "files.read",
        "files.upload",
        "files.apply_diff",
        "project.create",
        "workspace.manage",
        "changeset.create",
        "session.create",
        "session.rename",
        "session.close",
        "session.share",
        "automation.manage",
        "host.manage",
    ];
    let actual: Vec<&str> = ActionRight::ALL
        .iter()
        .map(|right| right.as_str())
        .collect();
    assert_eq!(actual, expected);
    assert!(ActionRight::from_wire("voice.speak").is_none());
}

// ----- framing ---------------------------------------------------------------------------------

#[test]
fn frame_bounds_follow_the_stream_kind() {
    assert_eq!(StreamKind::Control.max_frame_len(), MAX_CONTROL_FRAME_LEN);
    assert_eq!(
        StreamKind::TerminalInput.max_frame_len(),
        MAX_INPUT_FRAME_LEN
    );
    assert_eq!(
        StreamKind::AttachmentChunks.max_frame_len(),
        MAX_ATTACHMENT_FRAME_LEN
    );
    // The larger attachment bound cannot be selected on a control stream.
    assert!(StreamKind::AttachmentChunks.max_frame_len() > StreamKind::Control.max_frame_len());
}

#[test]
fn a_declared_length_is_rejected_before_the_payload_is_allocated() {
    let codec = FrameCodec::new(StreamKind::TerminalInput);
    let declared = u32::try_from(MAX_INPUT_FRAME_LEN + 1).expect("fits");
    assert_eq!(
        codec.decode_length(declared.to_be_bytes()),
        Err(FrameError::PayloadTooLarge {
            len: MAX_INPUT_FRAME_LEN + 1,
            limit: MAX_INPUT_FRAME_LEN
        })
    );
    // The same length is accepted on an attachment stream.
    assert!(
        FrameCodec::new(StreamKind::AttachmentChunks)
            .decode_length(declared.to_be_bytes())
            .is_ok()
    );
    // The check happens on the four-byte prefix alone, with no payload in hand.
    assert_eq!(
        codec.decode_length(u32::MAX.to_be_bytes()),
        Err(FrameError::PayloadTooLarge {
            len: u32::MAX as usize,
            limit: MAX_INPUT_FRAME_LEN
        })
    );
    assert_eq!(
        codec.decode_length([0, 0, 0, 0]),
        Err(FrameError::EmptyPayload)
    );
}

#[test]
fn frames_round_trip_and_report_what_is_missing() {
    let codec = FrameCodec::new(StreamKind::Control);
    let payload = kr_cbor::to_canonical_vec(&RequestId::new(41)).expect("encode");
    let framed = codec.encode(&payload).expect("frame");
    assert_eq!(framed.len(), 4 + payload.len());
    let (decoded, consumed) = codec.decode(&framed).expect("decode");
    assert_eq!(decoded, payload.as_slice());
    assert_eq!(consumed, framed.len());

    assert_eq!(
        codec.decode(&framed[..2]),
        Err(FrameError::Incomplete { needed: 2 })
    );
    assert_eq!(
        codec.decode(&framed[..framed.len() - 1]),
        Err(FrameError::Incomplete { needed: 1 })
    );

    // Two frames back to back are consumed one at a time.
    let mut stream = framed.clone();
    stream.extend_from_slice(&framed);
    let (_, consumed) = codec.decode(&stream).expect("first");
    let (second, _) = codec.decode(&stream[consumed..]).expect("second");
    assert_eq!(second, payload.as_slice());
}

#[test]
fn a_stream_header_stays_inside_its_bound() {
    let header = StreamHeader {
        kind: StreamKind::TerminalOutput,
        connection_id: ConnectionId::new(uuid("7f1c0f2a-2c1e-4c61-9d2e-0b9f8a7c6d55")),
        stream_id: Nullable::some(StreamId::new("session.output").expect("stream id")),
        resource: StreamResource {
            environment_id: EnvironmentId::new(uuid("3de5e6cb-bf21-49c1-8d34-b9a8729539da")),
            session_id: Nullable::some(SessionId::new(uuid(
                "b4a1bc38-157d-4e84-bf52-1137b15b462b",
            ))),
            attachment_id: Nullable::some(AttachmentId::new(uuid(
                "5d6e7f80-9a1b-4c2d-8e3f-a0b1c2d3e4f5",
            ))),
            transfer_id: Nullable::null(),
        },
    };
    let encoded = header.encode().expect("encode");
    assert!(encoded.len() <= MAX_STREAM_HEADER_LEN);
    assert_eq!(StreamHeader::decode(&encoded).expect("decode"), header);
    assert_eq!(
        StreamHeader::decode(&vec![0u8; MAX_STREAM_HEADER_LEN + 1]),
        Err(FrameError::HeaderTooLarge {
            len: MAX_STREAM_HEADER_LEN + 1,
            limit: MAX_STREAM_HEADER_LEN
        })
    );
}

// ----- the two representations -----------------------------------------------------------------

#[test]
fn a_uuid_is_sixteen_bytes_on_the_wire_and_hyphenated_text_in_json() {
    let value = SessionId::new(uuid("b4a1bc38-157d-4e84-bf52-1137b15b462b"));
    let wire = kr_cbor::to_canonical_vec(&value).expect("cbor");
    assert_eq!(hex::encode(&wire), "50b4a1bc38157d4e84bf521137b15b462b");
    assert_eq!(
        serde_json::to_string(&value).expect("json"),
        "\"b4a1bc38-157d-4e84-bf52-1137b15b462b\""
    );
    let from_json: SessionId =
        serde_json::from_str("\"b4a1bc38-157d-4e84-bf52-1137b15b462b\"").expect("parse");
    assert_eq!(from_json, value);
    let from_wire: SessionId =
        kr_cbor::from_canonical_slice(&wire, &Limits::DEFAULT).expect("parse");
    assert_eq!(from_wire, value);
    assert!(serde_json::from_str::<SessionId>("\"not-a-uuid\"").is_err());
}

#[test]
fn a_counter_is_an_integer_on_the_wire_and_a_decimal_string_in_json() {
    let value = U64::new(18_446_744_073_709_551_615);
    assert_eq!(
        hex::encode(kr_cbor::to_canonical_vec(&value).expect("cbor")),
        "1bffffffffffffffff"
    );
    assert_eq!(
        serde_json::to_string(&value).expect("json"),
        "\"18446744073709551615\""
    );
    // A hand-written diagnostic document that uses a JSON number still parses.
    assert_eq!(
        serde_json::from_str::<U64>("41").expect("number"),
        U64::new(41)
    );
    assert_eq!(
        serde_json::from_str::<U64>("\"41\"").expect("string"),
        U64::new(41)
    );
    assert!(serde_json::from_str::<U64>("\"041\"").is_err());
    assert!(serde_json::from_str::<U64>("-1").is_err());
}

#[test]
fn opaque_bytes_are_a_byte_string_on_the_wire_and_base64url_in_json() {
    let value = Digest256::from_bytes([0xff; 32]);
    let wire = kr_cbor::to_canonical_vec(&value).expect("cbor");
    assert_eq!(&hex::encode(&wire)[..2], "58");
    assert_eq!(
        serde_json::to_string(&value).expect("json"),
        "\"__________________________________________8\""
    );
    let from_json: Digest256 =
        serde_json::from_str("\"__________________________________________8\"").expect("parse");
    assert_eq!(from_json, value);
    // Padded, wrong-length or non-canonical base64url is rejected, exactly as in TypeScript.
    assert!(serde_json::from_str::<Digest256>("\"AAAA\"").is_err());
    assert!(
        kr_protocol::scalars::from_base64url("AA==").is_err(),
        "padding is not part of the representation"
    );
    assert!(
        kr_protocol::scalars::from_base64url("A+/A").is_err(),
        "standard base64 characters are not base64url characters"
    );
    assert!(
        kr_protocol::scalars::from_base64url("AB").is_err(),
        "non-zero trailing bits are a second encoding of the same bytes"
    );
    assert_eq!(
        kr_protocol::scalars::from_base64url("AA").expect("canonical"),
        vec![0u8]
    );
}

#[test]
fn a_nullable_field_must_be_present() {
    #[derive(serde::Deserialize, Debug, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct Closed {
        value: Nullable<U64>,
    }
    assert_eq!(
        serde_json::from_str::<Closed>(r#"{"value": null}"#).expect("explicit null"),
        Closed {
            value: Nullable::null()
        }
    );
    assert!(
        serde_json::from_str::<Closed>("{}").is_err(),
        "null is not omission: a missing field is an error"
    );
    assert!(serde_json::from_str::<Closed>(r#"{"value": "1", "extra": 1}"#).is_err());
}

#[test]
fn mutation_schemas_are_closed() {
    use kr_protocol::envelope::MutationRequest;
    let document = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/protocol/frames.json"),
    )
    .expect("fixture");
    let document: serde_json::Value = serde_json::from_str(&document).expect("json");
    let case = document["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .find(|case| case["id"] == "mutation_request")
        .expect("case");
    let bytes = hex::decode(case["cbor_hex"].as_str().expect("hex")).expect("hex");
    let request: MutationRequest =
        kr_cbor::from_canonical_slice(&bytes, &Limits::DEFAULT).expect("mutation");
    assert!(request.target.validate().is_ok());

    // Adding an unknown field rejects rather than being stripped.
    let mut value = kr_cbor::decode(&bytes, &Limits::DEFAULT).expect("decode");
    if let kr_cbor::CanonicalValue::Map(map) = &mut value {
        let mut entries = map.clone().into_entries();
        entries.push(("zz_unknown".to_owned(), kr_cbor::CanonicalValue::Bool(true)));
        entries.sort_by(|left, right| kr_cbor::compare_keys(&left.0, &right.0));
        *map = kr_cbor::CanonicalMap::from_sorted_entries(entries).expect("sorted");
    }
    let extended = kr_cbor::encode(&value);
    assert!(
        kr_cbor::from_canonical_slice::<MutationRequest>(&extended, &Limits::DEFAULT).is_err(),
        "an unknown field in a closed mutation schema must reject"
    );
}

#[test]
fn a_target_states_fields_that_agree_with_each_other() {
    use kr_protocol::envelope::{ActionTarget, TargetError};
    let environment = EnvironmentId::new(uuid("3de5e6cb-bf21-49c1-8d34-b9a8729539da"));
    assert!(ActionTarget::environment(environment).validate().is_ok());

    let session_only = ActionTarget {
        session_id: Nullable::some(SessionId::new(uuid("b4a1bc38-157d-4e84-bf52-1137b15b462b"))),
        ..ActionTarget::environment(environment)
    };
    assert_eq!(
        session_only.validate(),
        Err(TargetError::SessionEpochMismatch)
    );

    let application_without_session = ActionTarget {
        application_instance_id: Nullable::some(kr_protocol::ids::ApplicationInstanceId::new(
            uuid("4fe334a4-e934-4bb8-81c7-568252d9cd84"),
        )),
        agent_binding_revision: Nullable::some(kr_protocol::ids::AgentBindingRevision::new(2)),
        ..ActionTarget::environment(environment)
    };
    assert_eq!(
        application_without_session.validate(),
        Err(TargetError::ApplicationWithoutSession)
    );

    let missing_binding = ActionTarget {
        session_id: Nullable::some(SessionId::new(uuid("b4a1bc38-157d-4e84-bf52-1137b15b462b"))),
        session_epoch: Nullable::some(SessionEpoch::V1),
        application_instance_id: Nullable::some(kr_protocol::ids::ApplicationInstanceId::new(
            uuid("4fe334a4-e934-4bb8-81c7-568252d9cd84"),
        )),
        ..ActionTarget::environment(environment)
    };
    assert_eq!(
        missing_binding.validate(),
        Err(TargetError::BindingRevisionMismatch)
    );
}

// ----- version negotiation ---------------------------------------------------------------------

#[test]
fn version_selection_takes_the_highest_mutually_supported_minor() {
    let supported = [ProtocolVersion::new(1, 3)];
    assert_eq!(
        select_version(&[ProtocolVersion::new(1, 7)], &supported).expect("selected"),
        ProtocolVersion::new(1, 3)
    );
    assert_eq!(
        select_version(&[ProtocolVersion::new(1, 1)], &supported).expect("selected"),
        ProtocolVersion::new(1, 1)
    );
    assert_eq!(
        select_version(
            &[ProtocolVersion::new(2, 0), ProtocolVersion::new(1, 2)],
            &supported
        )
        .expect("selected"),
        ProtocolVersion::new(1, 2)
    );
}

#[test]
fn a_major_mismatch_is_an_unsupported_schema() {
    assert_eq!(
        select_version(&[ProtocolVersion::new(2, 0)], &[PROTOCOL_VERSION]),
        Err(ErrorCode::UnsupportedSchema)
    );
    assert_eq!(
        select_version(&[], &[PROTOCOL_VERSION]),
        Err(ErrorCode::UnsupportedSchema)
    );
}

#[test]
fn the_session_epoch_is_fixed_at_one_in_version_one() {
    assert_eq!(SessionEpoch::V1.get(), 1);
    assert_eq!(PROTOCOL_VERSION, ProtocolVersion::new(1, 0));
}
