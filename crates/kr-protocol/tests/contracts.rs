//! The receipt transition contract, error codes, grants, framing and the two representations.

use std::collections::BTreeSet;
use std::str::FromStr;

use kr_cbor::{CanonicalValue, Limits};
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
use kr_protocol::scalars::{CanonicalSet, Digest256, Nullable, TimestampMs, U64, Uuid};

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
    // KR-REQ-01.25: the receipt state transitions are a preserved behavioural contract: the
    // implementation permits exactly the specified edges and no other.
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

/// KR-REQ-23.55: every required error code exists with its stable wire string, and no other
/// code does.
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

/// KR-REQ-23.55: an error code is its stable string on the wire and in JSON.
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

/// KR-REQ-23.55: each code carries the retry category section 23 gives it.
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
        ErrorCode::PairingAuthFailed,
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

/// KR-REQ-23.55: an error is a stable code, a plain message, its retry category and an optional
/// opaque diagnostic identifier.
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
            named_questions: CanonicalSet::new(),
            named_approvals: CanonicalSet::new(),
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
            named_questions: CanonicalSet::new(),
            named_approvals: CanonicalSet::new(),
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
        "voice.use",
    ];
    let actual: Vec<&str> = ActionRight::ALL
        .iter()
        .map(|right| right.as_str())
        .collect();
    assert_eq!(actual, expected);
    assert!(ActionRight::from_wire("voice.speak").is_none());
}

// ----- framing ---------------------------------------------------------------------------------

/// KR-REQ-23.12: control frames are at most 1 MiB and input frames at most 64 KiB; an attachment
/// frame carries a 1 MiB chunk plus at most 4 KiB of metadata and framing, a bound a control stream
/// cannot select.
#[test]
fn frame_bounds_cover_the_complete_frame() {
    use kr_protocol::frame::FRAME_LENGTH_PREFIX_LEN;

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

    // The bound is on the bytes that go on the wire, length prefix included. A payload at the
    // limit plus its prefix still fits inside the stated allowance, and one byte more does not.
    for kind in StreamKind::ALL {
        let codec = FrameCodec::new(*kind);
        assert_eq!(
            codec.max_payload_len() + FRAME_LENGTH_PREFIX_LEN,
            kind.max_frame_len(),
            "{kind:?}"
        );
        let largest = codec
            .encode(&vec![0u8; codec.max_payload_len()])
            .expect("a payload at the limit");
        assert_eq!(largest.len(), kind.max_frame_len(), "{kind:?}");
        assert!(
            codec
                .encode(&vec![0u8; codec.max_payload_len() + 1])
                .is_err(),
            "{kind:?}: one byte over must be rejected"
        );
    }

    // An attachment frame carries a 1 MiB chunk plus at most 4 KiB of metadata and framing.
    assert_eq!(
        StreamKind::AttachmentChunks.max_frame_len(),
        1024 * 1024 + 4 * 1024
    );
    assert_eq!(MAX_CONTROL_FRAME_LEN, 1024 * 1024);
    assert_eq!(MAX_INPUT_FRAME_LEN, 64 * 1024);
    assert_eq!(kr_protocol::limits::MAX_ATTACHMENT_CHUNK_LEN, 1024 * 1024);
    assert_eq!(kr_protocol::limits::MAX_ATTACHMENT_METADATA_LEN, 4 * 1024);

    // A full chunk with its descriptor fits an attachment frame and no control frame.
    let chunk = kr_protocol::transfer::UploadChunkParams {
        transfer_id: kr_protocol::ids::TransferId::new(uuid(
            "5d6e7f80-9a1b-4c2d-8e3f-a0b1c2d3e4f5",
        )),
        chunk: kr_protocol::transfer::ChunkDescriptor {
            index: U64::new(u64::MAX),
            byte_len: U64::new(1024 * 1024),
            digest: Digest256::from_bytes([0xff; 32]),
        },
        bytes: vec![0xa5; 1024 * 1024].into(),
    };
    let framed = FrameCodec::new(StreamKind::AttachmentChunks)
        .encode_message(&chunk)
        .expect("a full chunk fits an attachment frame");
    assert!(framed.len() <= MAX_ATTACHMENT_FRAME_LEN);
    assert!(
        FrameCodec::new(StreamKind::Control)
            .encode_message(&chunk)
            .is_err(),
        "a control stream cannot carry a full chunk"
    );
}

/// KR-REQ-23.11: a frame is a four-byte big-endian length, checked against the stream kind's bound
/// from the prefix alone, before the payload exists.
#[test]
fn a_declared_length_is_rejected_before_the_payload_is_allocated() {
    let codec = FrameCodec::new(StreamKind::TerminalInput);
    let limit = codec.max_payload_len();
    let declared = u32::try_from(limit + 1).expect("fits");
    assert_eq!(
        codec.decode_length(declared.to_be_bytes()),
        Err(FrameError::PayloadTooLarge {
            len: limit + 1,
            limit
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
            limit
        })
    );
    assert_eq!(
        codec.decode_length([0, 0, 0, 0]),
        Err(FrameError::EmptyPayload)
    );
}

/// KR-REQ-23.11: a frame is its four-byte length prefix followed by exactly one payload.
#[test]
fn frames_round_trip_and_report_what_is_missing() {
    // KR-REQ-04.08: a structured message is length-delimited CBOR: a four-byte length and one
    // canonical object, decoded one frame at a time from a stream that carries several.
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

/// KR-REQ-23.11: a stream header declaring its kind and resource is bounded at 1 KiB, and one
/// byte more is refused before it is read.
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

    // The bound is the 1 KiB section 23 states: a header of exactly 1,024 bytes is read as a
    // header, and one byte more is refused for its length alone.
    assert_eq!(MAX_STREAM_HEADER_LEN, 1_024);
    assert!(!matches!(
        StreamHeader::decode(&[0u8; 1_024]),
        Err(FrameError::HeaderTooLarge { .. })
    ));
    assert_eq!(
        StreamHeader::decode(&[0u8; 1_025]),
        Err(FrameError::HeaderTooLarge {
            len: 1_025,
            limit: 1_024
        })
    );
}

// ----- the two representations -----------------------------------------------------------------

/// KR-REQ-23.03: a UUID is a 16-byte string on the wire.
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

/// KR-REQ-23.03: null is not omission: a nullable field must still be present.
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

/// KR-REQ-23.14, KR-REQ-09.02: a mutation schema is closed; an unknown field is refused rather than
/// stripped.
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

/// KR-REQ-09.01: a mutation's target states its exact environment, session and epoch, and the
/// fields it names agree with each other.
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

/// KR-REQ-23.13: the negotiated version is the highest one both sides listed.
#[test]
fn version_selection_takes_the_highest_version_both_sides_listed() {
    // KR-REQ-20.24: the protocol version is negotiated: the selection is the highest version both
    // peers list, whatever else either of them offers.
    let supported = [
        ProtocolVersion::new(1, 1),
        ProtocolVersion::new(1, 2),
        ProtocolVersion::new(1, 3),
    ];
    assert_eq!(
        select_version(
            &[ProtocolVersion::new(1, 1), ProtocolVersion::new(1, 2)],
            &supported
        )
        .expect("selected"),
        ProtocolVersion::new(1, 2)
    );
    assert_eq!(
        select_version(
            &[ProtocolVersion::new(2, 0), ProtocolVersion::new(1, 1)],
            &supported
        )
        .expect("selected"),
        ProtocolVersion::new(1, 1)
    );
}

/// KR-REQ-23.13: a version neither side listed is never selected.
#[test]
fn version_selection_never_assumes_an_unlisted_version_is_supported() {
    // Supporting 1.3 says nothing about 1.1. A peer enumerates what it supports.
    assert_eq!(
        select_version(&[ProtocolVersion::new(1, 1)], &[ProtocolVersion::new(1, 3)]),
        Err(ErrorCode::UnsupportedSchema)
    );
    assert_eq!(
        select_version(&[ProtocolVersion::new(1, 7)], &[ProtocolVersion::new(1, 3)]),
        Err(ErrorCode::UnsupportedSchema)
    );
}

/// KR-REQ-23.13: a major mismatch is UNSUPPORTED_SCHEMA.
#[test]
fn a_major_mismatch_is_an_unsupported_schema() {
    // KR-REQ-20.24: a peer that shares no supported version with this build is refused as
    // UNSUPPORTED_SCHEMA rather than served under a version it never offered.
    assert_eq!(
        select_version(&[ProtocolVersion::new(2, 0)], &[PROTOCOL_VERSION]),
        Err(ErrorCode::UnsupportedSchema)
    );
    assert_eq!(
        select_version(&[], &[PROTOCOL_VERSION]),
        Err(ErrorCode::UnsupportedSchema)
    );
}

/// KR-REQ-06.02: the session epoch is fixed at 1 in protocol version 1.
#[test]
fn the_session_epoch_is_fixed_at_one_in_version_one() {
    assert_eq!(SessionEpoch::V1.get(), 1);
    assert_eq!(PROTOCOL_VERSION, ProtocolVersion::new(1, 0));
}

// ----- closed schemas and exact encodings ------------------------------------------------------

#[test]
fn a_scoped_selector_round_trips_through_its_own_wire_encoding() {
    // An enum variant must not change the representation of the scalars inside it. A tagged
    // representation that buffers the content would hand the inner identifier a human-readable
    // deserializer and reject the 16-byte wire form.
    let selector = EnvironmentSelector::These {
        environment_ids: [EnvironmentId::new(uuid(
            "3de5e6cb-bf21-49c1-8d34-b9a8729539da",
        ))]
        .into_iter()
        .collect(),
    };
    let wire = kr_cbor::to_canonical_vec(&selector).expect("encode");
    assert_eq!(
        kr_cbor::from_canonical_slice::<EnvironmentSelector>(&wire, &Limits::DEFAULT)
            .expect("decode"),
        selector
    );

    let json = serde_json::to_string(&selector).expect("json");
    assert!(
        json.contains("3de5e6cb-bf21-49c1-8d34-b9a8729539da"),
        "{json}"
    );
    assert_eq!(
        serde_json::from_str::<EnvironmentSelector>(&json).expect("parse"),
        selector
    );

    let empty = SessionSelector::None;
    let wire = kr_cbor::to_canonical_vec(&empty).expect("encode");
    assert_eq!(
        kr_cbor::from_canonical_slice::<SessionSelector>(&wire, &Limits::DEFAULT).expect("decode"),
        empty
    );
}

/// KR-REQ-23.14: closed schemas hold inside enum variants too; nothing is stripped.
#[test]
fn an_unknown_field_is_rejected_even_on_a_variant_that_carries_none() {
    // A tagged representation accepts and discards extra fields on a unit variant, which is the
    // strip-and-verify behaviour section 23 forbids.
    assert!(
        serde_json::from_str::<GrantExpiry>(r#"{"never": {"expires_at_ms": "1"}}"#).is_err(),
        "a payload on a variant that carries none must reject"
    );
    assert_eq!(
        serde_json::from_str::<GrantExpiry>(r#""never""#).expect("plain variant"),
        GrantExpiry::Never
    );
    assert!(
        serde_json::from_str::<GrantExpiry>(r#"{"at": {"expires_at_ms": "1", "extra": 2}}"#)
            .is_err(),
        "an unknown field inside a variant must reject"
    );
    assert_eq!(
        serde_json::from_str::<GrantExpiry>(r#"{"at": {"expires_at_ms": "1"}}"#).expect("variant"),
        GrantExpiry::At {
            expires_at_ms: TimestampMs::new(1)
        }
    );
}

/// KR-REQ-23.06: a set inside a signed object re-encodes to the exact bytes it arrived in.
#[test]
fn a_canonical_set_re_encodes_to_the_bytes_it_arrived_in() {
    // A signed object is verified against the bytes it arrived in, so a set inside one cannot
    // reorder or deduplicate on the way through.
    let capabilities: CanonicalSet<kr_protocol::ids::CapabilityId> =
        ["semantic.updates", "terminal.direct"]
            .into_iter()
            .map(|name| kr_protocol::ids::CapabilityId::new(name).expect("name"))
            .collect();
    let wire = kr_cbor::to_canonical_vec(&capabilities).expect("encode");
    let decoded: CanonicalSet<kr_protocol::ids::CapabilityId> =
        kr_cbor::from_canonical_slice(&wire, &Limits::DEFAULT).expect("decode");
    assert_eq!(
        kr_cbor::to_canonical_vec(&decoded).expect("re-encode"),
        wire,
        "a received set must re-encode to the same bytes"
    );

    // The same members in the wrong order, and a repeated member, are both rejected rather than
    // silently normalised.
    let unsorted = kr_cbor::encode(&CanonicalValue::Array(vec![
        CanonicalValue::text("terminal.direct"),
        CanonicalValue::text("semantic.updates"),
    ]));
    assert!(
        kr_cbor::from_canonical_slice::<CanonicalSet<kr_protocol::ids::CapabilityId>>(
            &unsorted,
            &Limits::DEFAULT
        )
        .is_err()
    );
    let repeated = kr_cbor::encode(&CanonicalValue::Array(vec![
        CanonicalValue::text("semantic.updates"),
        CanonicalValue::text("semantic.updates"),
    ]));
    assert!(
        kr_cbor::from_canonical_slice::<CanonicalSet<kr_protocol::ids::CapabilityId>>(
            &repeated,
            &Limits::DEFAULT
        )
        .is_err()
    );
}

/// KR-REQ-23.06: a signed grant re-encodes to the exact bytes it arrived in.
#[test]
fn a_grant_re_encodes_to_the_bytes_it_arrived_in() {
    let grant = base_grant();
    let wire = kr_cbor::to_canonical_vec(&grant).expect("encode");
    let decoded: Grant = kr_cbor::from_canonical_slice(&wire, &Limits::DEFAULT).expect("decode");
    assert_eq!(decoded, grant);
    assert_eq!(
        kr_cbor::to_canonical_vec(&decoded).expect("re-encode"),
        wire
    );
}

#[test]
fn opaque_parameters_keep_every_integer_exact_in_json() {
    use kr_protocol::envelope::ParamsValue;

    let mut map = kr_cbor::CanonicalMap::new();
    map.insert(
        "big".to_owned(),
        CanonicalValue::integer(i128::from(u64::MAX)).expect("int"),
    )
    .expect("insert");
    map.insert("small".to_owned(), CanonicalValue::integer(3).expect("int"))
        .expect("insert");
    let params = ParamsValue::new(CanonicalValue::Map(map));

    // A JSON number cannot carry 2^64-1, and a reader cannot tell which integers were counters, so
    // every integer renders as a decimal string.
    let json = serde_json::to_string(&params).expect("json");
    assert_eq!(json, r#"{"big":"18446744073709551615","small":"3"}"#);

    // The wire form is unaffected: integers stay integers.
    let wire = kr_cbor::to_canonical_vec(&params).expect("cbor");
    assert_eq!(
        hex::encode(&wire),
        "a2636269671bffffffffffffffff65736d616c6c03"
    );
}

/// KR-REQ-23.06: only the one encoding a signature can be checked against is accepted.
#[test]
fn an_alternate_representation_of_the_same_typed_value_is_rejected() {
    use kr_cbor::CborError;
    use kr_protocol::envelope::Outcome;
    use kr_protocol::ids::CapabilityId;

    // A unit variant has one canonical form: its name as text. The same value also arrives as a
    // single-entry map holding null, which deserialises identically but serialises back to the
    // text form, so a signature taken over the map form would not verify against the value.
    let text_form = hex::decode("656e65766572").expect("hex");
    assert_eq!(
        kr_cbor::from_canonical_slice::<GrantExpiry>(&text_form, &Limits::DEFAULT)
            .expect("the canonical form"),
        GrantExpiry::Never
    );
    let map_form = hex::decode("a1656e65766572f6").expect("hex");
    assert!(
        matches!(
            kr_cbor::from_canonical_slice::<GrantExpiry>(&map_form, &Limits::DEFAULT),
            Err(CborError::NonCanonical)
        ),
        "a second representation of the same value must be rejected"
    );

    // The same applies inside a set, where the order check alone would not notice.
    let member_map_form = kr_cbor::encode(&CanonicalValue::Array(vec![CanonicalValue::Map(
        kr_cbor::CanonicalMap::from_entries([("session.view".to_owned(), CanonicalValue::Null)])
            .expect("map"),
    )]));
    assert!(matches!(
        kr_cbor::from_canonical_slice::<CanonicalSet<ActionRight>>(
            &member_map_form,
            &Limits::DEFAULT
        ),
        Err(CborError::NonCanonical)
    ));

    // And to a variant that carries data: "ok" alone is not the encoding of any Outcome.
    let bare = kr_cbor::encode(&CanonicalValue::text("ok"));
    assert!(matches!(
        kr_cbor::from_canonical_slice::<Outcome>(&bare, &Limits::DEFAULT),
        Err(CborError::NonCanonical)
    ));

    // A plain string enum still round trips through its own form.
    let capability = CapabilityId::new("terminal.direct").expect("name");
    let wire = kr_cbor::to_canonical_vec(&capability).expect("encode");
    assert_eq!(
        kr_cbor::from_canonical_slice::<CapabilityId>(&wire, &Limits::DEFAULT).expect("decode"),
        capability
    );
}

/// KR-REQ-23.03: a timestamp is schema-declared integer UTC milliseconds: an unsigned integer
/// on the wire, never a tagged date, a float or a date string.
#[test]
fn a_timestamp_is_integer_milliseconds_on_the_wire() {
    let value = TimestampMs::new(1_789_012_345_678);
    let wire = kr_cbor::to_canonical_vec(&value).expect("cbor");
    assert_eq!(hex::encode(&wire), "1b000001a08972034e");
    assert_eq!(
        kr_cbor::from_canonical_slice::<TimestampMs>(&wire, &Limits::DEFAULT).expect("decodes"),
        value
    );
    for (refused, what) in [
        ("c11b000001a08972034e", "an epoch-time tag"),
        ("fb427a08972034e000", "a float"),
        (
            "74323032362d30392d32335430303a30303a30305a",
            "a date string",
        ),
    ] {
        let bytes = hex::decode(refused).expect("hex");
        assert!(
            kr_cbor::from_canonical_slice::<TimestampMs>(&bytes, &Limits::DEFAULT).is_err(),
            "{what} is not a timestamp"
        );
    }
}

/// KR-REQ-23.14: read-only metadata may carry a field its schema declares optional, present or
/// absent, and a field no schema declares is refused there just as it is in a mutation.
#[test]
fn read_only_metadata_may_carry_an_explicitly_optional_field_and_nothing_else() {
    use kr_protocol::recovery::{HistoryGap, HistoryGapCause};

    let without = HistoryGap {
        from_cursor: U64::new(1),
        to_cursor: U64::new(5),
        cause: None,
    };
    let with = HistoryGap {
        cause: Some(HistoryGapCause::Retention),
        ..without
    };
    for gap in [without, with] {
        let wire = kr_cbor::to_canonical_vec(&gap).expect("cbor");
        assert_eq!(
            kr_cbor::from_canonical_slice::<HistoryGap>(&wire, &Limits::DEFAULT).expect("decodes"),
            gap
        );
    }
    let absent = kr_cbor::decode(
        &kr_cbor::to_canonical_vec(&without).expect("cbor"),
        &Limits::DEFAULT,
    )
    .expect("decode");
    assert!(
        absent.as_map().expect("a map").get("cause").is_none(),
        "an absent optional field is not on the wire at all"
    );

    let mut entries = absent.as_map().expect("a map").clone().into_entries();
    entries.push(("zz_unknown".to_owned(), CanonicalValue::Bool(true)));
    entries.sort_by(|left, right| kr_cbor::compare_keys(&left.0, &right.0));
    let extended = kr_cbor::encode(&CanonicalValue::Map(
        kr_cbor::CanonicalMap::from_sorted_entries(entries).expect("sorted"),
    ));
    assert!(
        kr_cbor::from_canonical_slice::<HistoryGap>(&extended, &Limits::DEFAULT).is_err(),
        "an undeclared field is refused even in read-only metadata"
    );
}

/// KR-REQ-09.01: a mutation carries its action identifier as a 16-byte UUIDv4, the grant it is
/// claimed under, the exact environment, session and epoch, the method that is its kind, its
/// subject preconditions and a requested lifetime bounded at five minutes, and none of them can be
/// left out. The authenticated actor is the host's to add, and the digest binds it.
#[test]
fn a_mutation_carries_every_element_its_admission_depends_on() {
    use kr_protocol::envelope::MutationRequest;

    let document: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../fixtures/protocol/frames.json"),
        )
        .expect("fixture"),
    )
    .expect("json");
    let case = document["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .find(|case| case["id"] == "mutation_request")
        .expect("case");
    let bytes = hex::decode(case["cbor_hex"].as_str().expect("hex")).expect("hex");
    let request: MutationRequest =
        kr_cbor::from_canonical_slice(&bytes, &Limits::DEFAULT).expect("mutation");

    assert_eq!(request.action_id.get().version(), 4);
    let value = kr_cbor::decode(&bytes, &Limits::DEFAULT).expect("decode");
    let map = value.as_map().expect("a map");
    assert!(
        matches!(map.get("action_id"), Some(CanonicalValue::Bytes(bytes)) if bytes.len() == 16),
        "the action identifier is 16 bytes on the wire"
    );
    assert!(request.grant_id.is_present());
    assert!(request.target.session_id.is_present());
    assert_eq!(
        request.target.session_epoch,
        Nullable::some(SessionEpoch::V1)
    );
    assert!(request.target.validate().is_ok());
    assert_eq!(
        request.method.method(),
        Some(Method::AgentApprovalRespond),
        "the method is the action's kind"
    );
    let CanonicalValue::Map(expected) = request.expected.as_value() else {
        panic!("the preconditions are a map");
    };
    assert!(
        !expected.is_empty(),
        "the mutation states its subject preconditions"
    );
    assert!(request.requested_ttl_ms.get() <= kr_protocol::limits::MAX_MUTATION_TTL.get());
    assert_eq!(kr_protocol::limits::MAX_MUTATION_TTL.get(), 300_000);

    for field in [
        "action_id",
        "grant_id",
        "target",
        "method",
        "method_version",
        "expected",
        "action_window_id",
        "requested_ttl_ms",
        "params",
    ] {
        let entries: Vec<(String, CanonicalValue)> = map
            .entries()
            .iter()
            .filter(|(key, _)| key != field)
            .cloned()
            .collect();
        let without = kr_cbor::encode(&CanonicalValue::Map(
            kr_cbor::CanonicalMap::from_sorted_entries(entries).expect("sorted"),
        ));
        assert!(
            kr_cbor::from_canonical_slice::<MutationRequest>(&without, &Limits::DEFAULT).is_err(),
            "a mutation without {field} is refused"
        );
    }

    let actor = ActorId::new("device:9c2f1a6e-4b77-4f10-9f2a-6de0f5c4a311").expect("actor");
    let other = ActorId::new("device:2a4b6c8d-0e1f-4a2b-8c3d-4e5f60718293").expect("actor");
    assert_ne!(
        kr_protocol::digest::mutation_digest(&request, &actor).expect("digest"),
        kr_protocol::digest::mutation_digest(&request, &other).expect("digest"),
        "the digest binds the actor the host authenticated"
    );
}

/// KR-REQ-23.56: a capability that needs a permission, a revocation still pending on a worker and a
/// voice start whose creation is unknown are typed results, each in its own schema. None of them
/// is an error code, and no spelling of one parses as a code.
#[test]
fn resource_states_are_typed_results_and_never_error_codes() {
    use kr_protocol::action::{BarrierState, RevocationBarrier, WorkerBarrier};
    use kr_protocol::desktop::CapabilityState;
    use kr_protocol::voice::{VoiceStartOutcome, VoiceStartResult};

    for spelling in [
        "PERMISSION_REQUIRED",
        "RESTART_REQUIRED",
        "PENDING_REVOCATION",
        "REVOCATION_PENDING",
        "CREATION_UNKNOWN",
        "permission_required",
        "creation_unknown",
    ] {
        assert!(
            ErrorCode::from_wire(spelling).is_none(),
            "{spelling} is a resource state, not an error code"
        );
    }

    let state = kr_cbor::to_canonical_vec(&CapabilityState::PermissionRequired).expect("cbor");
    assert_eq!(
        kr_cbor::decode(&state, &Limits::DEFAULT).expect("decode"),
        CanonicalValue::text("permission_required")
    );
    assert!(!CapabilityState::PermissionRequired.is_available());

    let pending = RevocationBarrier {
        authority_revision: AuthorityRevision::new(4),
        workers: vec![WorkerBarrier {
            session_id: SessionId::new(uuid("b4a1bc38-157d-4e84-bf52-1137b15b462b")),
            state: BarrierState::Pending,
            acknowledged_revision: Nullable::null(),
            rejected_actions: Vec::new(),
            possibly_executed: Vec::new(),
            omitted_actions: U64::new(0),
            names_pending: U64::new(0),
            detail: "the worker has not acknowledged".to_owned(),
        }],
    };
    assert!(!pending.holds());
    let wire = kr_cbor::to_canonical_vec(&pending).expect("cbor");
    assert_eq!(
        kr_cbor::from_canonical_slice::<RevocationBarrier>(&wire, &Limits::DEFAULT)
            .expect("decodes"),
        pending
    );

    let unknown = VoiceStartResult {
        outcome: VoiceStartOutcome::CreationUnknown {
            attempt_id: "attempt-1".to_owned(),
            message: "The call may have been created; nothing was retried.".to_owned(),
        },
    };
    let wire = kr_cbor::to_canonical_vec(&unknown).expect("cbor");
    let value = kr_cbor::decode(&wire, &Limits::DEFAULT).expect("decode");
    let outcome = value
        .as_map()
        .and_then(|map| map.get("outcome"))
        .and_then(CanonicalValue::as_map)
        .expect("a typed outcome");
    assert!(outcome.get("creation_unknown").is_some());
    assert_eq!(
        kr_cbor::from_canonical_slice::<VoiceStartResult>(&wire, &Limits::DEFAULT)
            .expect("decodes"),
        unknown
    );
}
