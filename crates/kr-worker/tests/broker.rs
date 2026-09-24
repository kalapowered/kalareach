//! The trusted broker: processes, credentials, source frames, grants, decoding trust, arbitration,
//! action tokens, launch profiles and capability evidence.
//!
//! Each test is named for the requirement row it closes, so a reader can go from a row to the
//! behaviour that establishes it without searching. Where a test establishes less than its row
//! asks for, the name says what it does establish and the comment says what is left.

use kr_protocol::agent::{
    AgentApprovalRespondParams, AgentApprovalRespondResult, AgentMutationTarget,
};
use kr_protocol::broker::{
    ActionName, ActionProvenance, ActionTokenClaim, AuthenticationState, BinaryIdentity,
    BrokerGrant, BrokerGrants, DecodedProjection, DecodingTrust, InstanceCapabilityIdentity,
    InstanceCapabilityRecord, InstanceCapabilityState, InstanceEvidenceSource,
    InstanceInvalidation, IntegrationMode, LaunchProfile, LaunchRefusal, OfferedDecision,
};
use kr_protocol::gateway::{
    DeclarativeEntry, DeclarativeTable, DownstreamRequestId, NativeFraming, NativeMethodClass,
    PendingKind, PendingResource, PendingState, RichMethodEntry, RichMethodTable, RichOperation,
};
use kr_protocol::identity::{ProcessStartIdentity, ProcessStartSource};
use kr_protocol::ids::{
    ActorId, AgentBindingRevision, AgentThreadId, ApplicationInstanceId, BrokerBindingId,
    CapabilityId, CapabilityRevision, EnvironmentId, GatewayConnectionId, GrantId, LaunchProfileId,
    MethodTableVersion, PendingResourceId, PluginId, PublisherId, SessionId, SourceEventHandle,
    StreamCursor, UpstreamMethod, UpstreamRequestId,
};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{Digest256, Nullable, TimestampMs, U64, Uuid};
#[cfg(unix)]
use kr_worker::broker::InstanceEnding;
use kr_worker::broker::{
    Broker, BrokerError, BrokerTransport, Caller, Credential, ForegroundMark, Invocation,
    ManagedProcess, MutationAdmission, PendingTransmission, Probe, ReconcileScope, TransportHandle,
    UpstreamBody, UpstreamDispatch, UpstreamOutcome, UpstreamRequest, subject,
};
use kr_worker::persistence::JournalHealth;

mod common;

const CREDENTIAL: [u8; 32] = [9; 32];

fn session() -> SessionId {
    SessionId::new(Uuid::from_bytes([1; 16]))
}

fn instance(byte: u8) -> ApplicationInstanceId {
    ApplicationInstanceId::new(Uuid::from_bytes([byte; 16]))
}

fn binding(byte: u8) -> BrokerBindingId {
    BrokerBindingId::new(Uuid::from_bytes([byte; 16]))
}

fn permission_method() -> UpstreamMethod {
    UpstreamMethod::new("session/request_permission").expect("a valid method name")
}

fn actor(name: &str) -> ActorId {
    ActorId::new(name).expect("a valid actor principal")
}

fn capability(name: &str) -> CapabilityId {
    CapabilityId::new(name).expect("a valid capability name")
}

fn process_identity(pid: u64, start: u64) -> ProcessStartIdentity {
    ProcessStartIdentity::new(pid, ProcessStartSource::MacosProcBsdInfo, start)
}

fn managed(instance_id: ApplicationInstanceId, dedicated: bool) -> ManagedProcess {
    managed_as(instance_id, dedicated, process_identity(41, 900))
}

fn managed_as(
    instance_id: ApplicationInstanceId,
    dedicated: bool,
    process: ProcessStartIdentity,
) -> ManagedProcess {
    ManagedProcess::new(
        instance_id,
        process.clone(),
        TransportHandle {
            transport: BrokerTransport::PrivateSocket,
            application_instance_id: instance_id,
            executable_digest: Digest256::from_bytes([3; 32]),
            process,
        },
        Credential::from_bytes(CREDENTIAL),
        dedicated,
        TimestampMs::new(1),
    )
}

fn trust(methods: &[UpstreamMethod], may_encode: bool) -> DecodingTrust {
    DecodingTrust {
        plugin_id: PluginId::new("kalareach.codex").expect("valid"),
        publisher_id: PublisherId::new("kalareach").expect("valid"),
        package_digest: Digest256::from_bytes([5; 32]),
        methods: methods.iter().cloned().collect(),
        schema_versions: ["kr-approval/1".to_owned()].into_iter().collect(),
        max_decisions: U64::new(4),
        may_encode_response: may_encode,
        granted_at: TimestampMs::new(1),
    }
}

fn projection() -> DecodedProjection {
    DecodedProjection {
        schema_version: "kr-approval/1".to_owned(),
        summary: "the agent wants to write a file".to_owned(),
        decisions: vec![
            OfferedDecision {
                option_id: "allow".to_owned(),
                label: "Allow".to_owned(),
            },
            OfferedDecision {
                option_id: "deny".to_owned(),
                label: "Deny".to_owned(),
            },
        ],
    }
}

fn profile(mode: IntegrationMode, digest: [u8; 32], version: &str) -> LaunchProfile {
    LaunchProfile {
        profile_id: LaunchProfileId::new("lp-1").expect("valid"),
        environment_id: EnvironmentId::new(Uuid::from_bytes([1; 16])),
        binary: BinaryIdentity {
            resolved_path: "/usr/local/bin/codex".to_owned(),
            digest: Digest256::from_bytes(digest),
            version: version.to_owned(),
            distribution: "homebrew".to_owned(),
        },
        arguments: vec!["codex".to_owned(), "--resume".to_owned()],
        authentication: AuthenticationState::Authenticated,
        mode,
        resolved_at: TimestampMs::new(10),
    }
}

fn request(connection: u64, id: &str) -> DownstreamRequestId {
    DownstreamRequestId::new(
        GatewayConnectionId::new(connection),
        UpstreamRequestId::new(id).expect("valid"),
    )
}

fn scope(instance_id: ApplicationInstanceId, connection: u64) -> ReconcileScope {
    ReconcileScope {
        application_instance_id: instance_id,
        connection: GatewayConnectionId::new(connection),
    }
}

fn evidence(
    name: &str,
    state: InstanceCapabilityState,
    trigger: InstanceInvalidation,
    instance_id: ApplicationInstanceId,
) -> InstanceCapabilityRecord {
    InstanceCapabilityRecord {
        capability_id: capability(name),
        capability_version: "1".to_owned(),
        application_instance_id: instance_id,
        identity: InstanceCapabilityIdentity {
            binary_digest: Nullable::some(Digest256::from_bytes([3; 32])),
            ..InstanceCapabilityIdentity::default()
        },
        revision: CapabilityRevision::new(1),
        state,
        source: InstanceEvidenceSource::HostProbe,
        invalidated_by: [trigger].into_iter().collect(),
        disabled_reason: if state.is_usable() {
            Nullable::null()
        } else {
            Nullable::some("this installation cannot do it".to_owned())
        },
        observed_at: TimestampMs::new(1),
    }
}

fn invocation(instance_id: ApplicationInstanceId, revision: u64, action: &str) -> Invocation {
    Invocation {
        actor_id: actor("device-1"),
        grant: BrokerGrant::UpstreamAction,
        grant_id: Some(GrantId::new(Uuid::from_bytes([7; 16]))),
        application_instance_id: instance_id,
        binding_revision: AgentBindingRevision::new(revision),
        action: ActionName::new(action).expect("valid"),
        draft_id: None,
        capability: None,
        parameters: b"{\"text\":\"hello\"}".to_vec(),
    }
}

fn package() -> PluginId {
    PluginId::new("kalareach.codex").expect("valid")
}

fn declarative_table() -> DeclarativeTable {
    let mut table = DeclarativeTable {
        plugin_id: PluginId::new("kalareach.codex").expect("valid"),
        publisher_id: PublisherId::new("kalareach").expect("valid"),
        table_version: MethodTableVersion::new(1),
        upstream_protocol_version: "1".to_owned(),
        digest: Digest256::from_bytes([1; 32]),
        framing: NativeFraming::JsonLines,
        request_id_field: "id".to_owned(),
        response_id_field: "id".to_owned(),
        method_field: "method".to_owned(),
        params_field: "params".to_owned(),
        result_field: "result".to_owned(),
        error_field: "error".to_owned(),
        entries: vec![
            DeclarativeEntry {
                method: permission_method(),
                class: NativeMethodClass::Mutation,
                expects_response: true,
                approval_option_field: Nullable::some("option_id".to_owned()),
                reverse: Nullable::null(),
            },
            DeclarativeEntry {
                method: UpstreamMethod::new("session/update").expect("valid"),
                class: NativeMethodClass::Observation,
                expects_response: false,
                approval_option_field: Nullable::null(),
                reverse: Nullable::null(),
            },
        ],
    };
    table.digest = table.canonical_digest().expect("encodable");
    table
}

fn rich_table() -> RichMethodTable {
    RichMethodTable {
        table_version: MethodTableVersion::new(1),
        upstream_protocol_version: "1".to_owned(),
        entries: vec![RichMethodEntry {
            method: UpstreamMethod::new("session/cancel").expect("valid"),
            class: NativeMethodClass::Mutation,
            required_right: ActionRight::AgentCancel,
            operation: Nullable::some(RichOperation::TurnCancel),
            provenance: ActionProvenance::UpstreamTypedRpc,
        }],
    }
}

/// Gives one broker what an approval answer needs: the capability evidence the mutation is
/// checked against, and a transport on the connection the answer goes out on.
fn equip(broker: &Broker) -> std::sync::Arc<RecordingUpstream> {
    broker
        .record_capability(evidence(
            "agent.approval",
            InstanceCapabilityState::QualifiedAvailable,
            InstanceInvalidation::BindingChanged,
            instance(2),
        ))
        .expect("the evidence is recorded");
    let upstream = std::sync::Arc::new(RecordingUpstream::default());
    broker
        .bind_dispatch(instance(2), std::sync::Arc::clone(&upstream) as _)
        .expect("the transport is bound");
    broker.bind_connection_dispatch(
        GatewayConnectionId::new(1),
        std::sync::Arc::clone(&upstream) as _,
    );
    upstream
}

/// A transport that records what it was asked to carry, and answers as an upstream would.
#[derive(Debug, Default)]
struct RecordingUpstream {
    submitted: std::sync::Mutex<Vec<UpstreamRequest>>,
}

impl RecordingUpstream {
    fn submitted(&self) -> Vec<UpstreamRequest> {
        self.submitted
            .lock()
            .expect("the record is not poisoned")
            .clone()
    }
}

impl UpstreamDispatch for RecordingUpstream {
    fn admit(&self, _request: &UpstreamRequest) -> Result<(), BrokerError> {
        Ok(())
    }

    fn submit(&self, request: &UpstreamRequest) -> Result<PendingTransmission, BrokerError> {
        self.submitted
            .lock()
            .expect("the record is not poisoned")
            .push(request.clone());
        let upstream_request_id = match &request.body {
            UpstreamBody::Approval {
                upstream_request_id,
                ..
            } => upstream_request_id.clone(),
            _ => UpstreamRequestId::new("upstream-1").expect("valid"),
        };
        Ok(PendingTransmission::settled(Ok(UpstreamOutcome {
            upstream_request_id: Some(upstream_request_id),
            turn_id: request.turn_id.clone(),
            provenance: ActionProvenance::UpstreamTypedRpc,
        })))
    }
}

/// A transport that stops the host at the moment the bytes go.
///
/// Section 24 puts the durable marker before the effect so that this state is readable
/// afterwards: the marker is in, the answer may already have reached the upstream, and nothing
/// records what came of it. Reconciliation, not a second answer, is what settles it.
#[derive(Debug, Default)]
struct StoppingUpstream;

const STOPPED: &str =
    "this test stops the host here, after the marker and before the outcome is recorded";

impl UpstreamDispatch for StoppingUpstream {
    fn admit(&self, _request: &UpstreamRequest) -> Result<(), BrokerError> {
        Ok(())
    }

    fn submit(&self, _request: &UpstreamRequest) -> Result<PendingTransmission, BrokerError> {
        panic!("{STOPPED}")
    }
}

/// Puts the transport that stops the host on the connection answers go out on.
///
/// An admission carries the transport it was taken with, so this is bound before the answer is
/// admitted rather than after.
fn stop_the_host_at_the_bytes(broker: &Broker) {
    broker.bind_connection_dispatch(
        GatewayConnectionId::new(1),
        std::sync::Arc::new(StoppingUpstream) as _,
    );
}

/// Runs one step that transmits over that transport, and checks the host stopped in it.
fn stopping(step: impl FnOnce()) {
    let stopped = std::panic::catch_unwind(std::panic::AssertUnwindSafe(step));
    let payload = stopped.expect_err("the host stopped where the transport stops it");
    assert_eq!(
        payload.downcast_ref::<String>().map(String::as_str),
        Some(STOPPED)
    );
}

fn caller(name: &str) -> Caller {
    Caller {
        actor_id: actor(name),
        grant_id: Some(GrantId::new(Uuid::from_bytes([7; 16]))),
    }
}

fn respond(resource_id: PendingResourceId, option_id: &str) -> AgentApprovalRespondParams {
    AgentApprovalRespondParams {
        target: AgentMutationTarget {
            subject: subject(session(), instance(2)),
            binding_revision: AgentBindingRevision::new(1),
        },
        resource_id,
        option_id: option_id.to_owned(),
    }
}

/// Reserves one approval's transmission, the way `agent.approval.respond` does before it writes.
fn reserve(
    broker: &Broker,
    resource_id: PendingResourceId,
    option_id: &str,
    now: u64,
) -> Result<MutationAdmission, BrokerError> {
    broker.admit_approval(
        &caller("device-1"),
        &respond(resource_id, option_id),
        TimestampMs::new(now),
    )
}

/// Answers one approval the way the method does: admit, mark, transmit, settle.
async fn answer(
    broker: &Broker,
    resource_id: PendingResourceId,
    option_id: &str,
    now: u64,
) -> Result<AgentApprovalRespondResult, BrokerError> {
    broker
        .agent_approval_respond(
            &caller("device-1"),
            &respond(resource_id, option_id),
            TimestampMs::new(now),
        )
        .await
        .map(|(result, _)| result)
}

/// A broker with one instance, one process, one binding and one native connection.
fn broker_with(grants: BrokerGrants, decoding: Option<DecodingTrust>) -> Broker {
    broker_recording(grants, decoding).0
}

/// The same broker, with the transport its connection answers on handed back.
fn broker_recording(
    grants: BrokerGrants,
    decoding: Option<DecodingTrust>,
) -> (Broker, std::sync::Arc<RecordingUpstream>) {
    let broker = Broker::open(None, session(), JournalHealth::shared()).expect("the broker opens");
    broker
        .register_instance(
            instance(2),
            IntegrationMode::Gateway,
            Some(LaunchProfileId::new("lp-1").expect("valid")),
            Some(managed(instance(2), true)),
        )
        .expect("the instance is registered");
    broker
        .bind(
            binding(9),
            instance(2),
            PluginId::new("kalareach.codex").expect("valid"),
            PublisherId::new("kalareach").expect("valid"),
            Digest256::from_bytes([5; 32]),
            grants,
            decoding,
            TimestampMs::new(1),
        )
        .expect("the binding is recorded");
    broker
        .pin_table(instance(2), declarative_table(), rich_table())
        .expect("the installed tables are pinned");
    broker
        .open_native_connection(
            instance(2),
            &CREDENTIAL,
            &process_identity(41, 900),
            &package(),
            "1",
        )
        .expect("the native connection is authenticated");
    // An answer goes out on the connection whose resource it resolves. Without a transport there
    // is nothing to carry one, and nothing settles.
    let upstream = equip(&broker);
    (broker, upstream)
}

fn permission_frame(id: &str) -> String {
    format!(r#"{{"id":{id},"method":"session/request_permission"}}"#)
}

/// Forwards one native request and returns the opaque resource the broker recorded for it.
fn forward(broker: &Broker, id: &str, now: u64) -> Result<PendingResource, BrokerError> {
    let frame = permission_frame(id);
    let (_, opaque) = broker.forward_native(
        GatewayConnectionId::new(1),
        frame.as_bytes(),
        TimestampMs::new(now),
    )?;
    Ok(opaque.expect("this method expects a response"))
}

/// Forwards one native request and has a decoder interpret it, the way the gateway does.
fn offer(
    broker: &Broker,
    instance_id: ApplicationInstanceId,
    binding_id: BrokerBindingId,
    id: &str,
    now: u64,
) -> Result<PendingResource, BrokerError> {
    let _ = instance_id;
    let opaque = forward(broker, id, now)?;
    broker.interpret(
        binding_id,
        opaque.resource_id,
        projection(),
        None,
        TimestampMs::new(now + 1),
    )
}

/// KR-REQ-11.22: the broker owns the processes it launched, their credentials, their source
/// frames and the arbitration over what those frames imply.
#[tokio::test]
async fn kr_req_11_22_the_broker_owns_the_process_identity_the_source_and_the_arbitration() {
    let broker = broker_with(
        BrokerGrants::granted([BrokerGrant::ApprovalInterpreter]),
        Some(trust(&[permission_method()], true)),
    );

    // The process is the broker's, by full identity rather than by identifier.
    let process = managed(instance(2), true);
    assert!(process.authenticates(&CREDENTIAL, &process_identity(41, 900)));
    assert!(!process.authenticates(&CREDENTIAL, &process_identity(41, 901)));

    // The source frame is the broker's, immutable, and identified by its digest.
    let body = permission_frame("11");
    let handle = broker
        .record_source(instance(2), body.as_bytes(), TimestampMs::new(2))
        .expect("the frame is recorded");
    let held = broker
        .source(instance(2), &handle)
        .expect("the broker holds it");
    assert_eq!(held.bytes(), body.as_bytes());
    assert_eq!(
        held.digest,
        Digest256::from_bytes(kr_cbor::sha256(body.as_bytes()))
    );

    // The arbitration is the broker's: the opaque request is recorded before it is forwarded, and
    // it is not answerable until a granted decoder has interpreted it.
    let opaque = forward(&broker, "11", 3).expect("forwarded");
    assert_eq!(opaque.kind, PendingKind::ReverseRpc);
    assert!(!opaque.interpretation_verified);
    assert!(
        answer(&broker, opaque.resource_id, "allow", 4)
            .await
            .is_err(),
        "a pending opaque request is not an actionable approval"
    );

    let interpreted = broker
        .interpret(
            binding(9),
            opaque.resource_id,
            projection(),
            None,
            TimestampMs::new(5),
        )
        .expect("the interpretation is accepted");
    assert_eq!(interpreted.resource_id, opaque.resource_id);
    assert_eq!(interpreted.kind, PendingKind::Approval);
    assert!(interpreted.interpretation_verified);
    assert_eq!(
        broker
            .pending(interpreted.resource_id)
            .expect("the broker holds the resource")
            .state,
        PendingState::Pending
    );
}

/// KR-REQ-11.23: a transport handle names the executable and the process identity it reaches,
/// both halves are required to authenticate, and a credential has no accessor and no rendering.
///
/// What this does not establish is that a component never receives one: a component is in another
/// process and the runtime's own suite covers what crosses that boundary.
#[test]
fn kr_req_11_23_a_handle_names_the_executable_and_both_halves_authenticate() {
    let process = managed(instance(2), true);
    assert_eq!(
        process.handle.executable_digest,
        Digest256::from_bytes([3; 32]),
        "a handle names the executable it reaches"
    );
    assert_eq!(process.handle.process, process_identity(41, 900));
    assert_eq!(
        process.handle.application_instance_id,
        instance(2),
        "a handle names the upstream identity it reaches"
    );

    // Both halves are required: the secret alone, from another process, authenticates nothing.
    assert!(process.authenticates(&CREDENTIAL, &process_identity(41, 900)));
    assert!(!process.authenticates(&CREDENTIAL, &process_identity(42, 900)));
    assert!(!process.authenticates(&[8; 32], &process_identity(41, 900)));

    // There is no accessor that returns a credential's bytes, and the debug rendering carries
    // none, so nothing this host hands to a component can carry one.
    let rendered = format!("{:?}", Credential::from_bytes(CREDENTIAL));
    assert_eq!(rendered, "Credential(<redacted>)");
    let whole_process = format!("{process:?}");
    assert!(whole_process.contains("Credential(<redacted>)"));
    assert!(!whole_process.contains("0909"));

    // A transcript tail is a supported transport and is not one the forwarding path uses.
    assert!(BrokerTransport::PrivateSocket.carries_forwarding());
    assert!(!BrokerTransport::TranscriptTail.carries_forwarding());
}

/// KR-REQ-11.24: observation, upstream action and approval interpretation are three grants, and
/// holding one is never holding another.
#[test]
fn kr_req_11_24_the_three_grants_are_held_separately() {
    let broker = broker_with(BrokerGrants::granted([BrokerGrant::Observation]), None);
    let grants = broker.grants(binding(9)).expect("the binding is there");
    assert!(grants.holds(BrokerGrant::Observation));
    assert!(!grants.holds(BrokerGrant::UpstreamAction));
    assert!(!grants.holds(BrokerGrant::ApprovalInterpreter));
    assert!(grants.is_display_only());

    // An observation binding asked to prepare an effect is refused before its component runs.
    let refused = broker.issue_token(
        binding(9),
        &invocation(instance(2), 1, "prompt.submit"),
        TimestampMs::new(2),
    );
    assert!(matches!(refused, Err(BrokerError::Grant(_))));

    // Withdrawing one grant leaves the others exactly as they were.
    let broker = broker_with(
        BrokerGrants::granted([
            BrokerGrant::Observation,
            BrokerGrant::UpstreamAction,
            BrokerGrant::ApprovalInterpreter,
        ]),
        Some(trust(&[permission_method()], true)),
    );
    broker
        .withdraw_grant(binding(9), BrokerGrant::UpstreamAction)
        .expect("the grant is withdrawn");
    let grants = broker.grants(binding(9)).expect("the binding is there");
    assert!(grants.holds(BrokerGrant::Observation));
    assert!(!grants.holds(BrokerGrant::UpstreamAction));
    assert!(grants.holds(BrokerGrant::ApprovalInterpreter));
}

/// KR-REQ-11.25: decoding trust is explicit, belongs to one package, and a display-only component
/// cannot create an approval whatever it reports.
#[test]
fn kr_req_11_25_decoding_trust_is_explicit_and_display_only_creates_no_approval() {
    let display_only = broker_with(BrokerGrants::granted([BrokerGrant::Observation]), None);
    let refusal = offer(&display_only, instance(2), binding(9), "11", 2)
        .expect_err("a display-only component creates no approval");
    assert!(matches!(refusal, BrokerError::Grant(_)));

    // The interpreter grant alone is not trust either: a record naming the method is required.
    let untrusted = broker_with(
        BrokerGrants::granted([BrokerGrant::ApprovalInterpreter]),
        Some(trust(
            &[UpstreamMethod::new("fs/read_text_file").expect("valid")],
            true,
        )),
    );
    let refusal = offer(&untrusted, instance(2), binding(9), "11", 2)
        .expect_err("a decoder trusted for another method is refused");
    assert!(matches!(refusal, BrokerError::PermissionDenied { .. }));

    // Trust without the grant it depends on is refused when it is offered, not stored.
    let broker = Broker::open(None, session(), JournalHealth::shared()).expect("the broker opens");
    broker
        .register_instance(instance(2), IntegrationMode::Gateway, None, None)
        .expect("the instance is registered");
    let refusal = broker
        .bind(
            binding(9),
            instance(2),
            PluginId::new("kalareach.codex").expect("valid"),
            PublisherId::new("kalareach").expect("valid"),
            Digest256::from_bytes([5; 32]),
            BrokerGrants::granted([BrokerGrant::Observation]),
            Some(trust(&[permission_method()], true)),
            TimestampMs::new(1),
        )
        .expect_err("trust needs the grant it depends on");
    assert!(matches!(refusal, BrokerError::PermissionDenied { .. }));

    // And one package's trust is never another's: the record names the package it was granted to.
    let refusal = broker
        .bind(
            binding(9),
            instance(2),
            PluginId::new("someone.else").expect("valid"),
            PublisherId::new("someone").expect("valid"),
            Digest256::from_bytes([7; 32]),
            BrokerGrants::granted([BrokerGrant::ApprovalInterpreter]),
            Some(trust(&[permission_method()], true)),
            TimestampMs::new(1),
        )
        .expect_err("another package cannot bind with this trust");
    assert!(matches!(refusal, BrokerError::PermissionDenied { .. }));
}

/// KR-REQ-11.26: the broker checks decoder role, application binding, source generation, schema
/// policy and non-reuse, and retains the ledger that says what it checked.
#[test]
fn kr_req_11_26_the_broker_checks_role_binding_generation_and_reuse_and_retains_its_ledger() {
    let directory = std::env::temp_dir().join(format!("kr-broker-{}", kr_ipc::new_uuid()));
    std::fs::create_dir_all(&directory).expect("the directory is created");
    let path = directory.join("session.sqlite");

    let resource_id = {
        let broker = Broker::open(Some(&path), session(), JournalHealth::shared())
            .expect("the broker opens");
        broker
            .register_instance(
                instance(2),
                IntegrationMode::Gateway,
                None,
                Some(managed(instance(2), true)),
            )
            .expect("the instance is registered");
        broker
            .register_instance(
                instance(3),
                IntegrationMode::Gateway,
                None,
                Some(managed(instance(3), true)),
            )
            .expect("the instance is registered");
        broker
            .bind(
                binding(9),
                instance(2),
                PluginId::new("kalareach.codex").expect("valid"),
                PublisherId::new("kalareach").expect("valid"),
                Digest256::from_bytes([5; 32]),
                BrokerGrants::granted([BrokerGrant::ApprovalInterpreter]),
                Some(trust(&[permission_method()], true)),
                TimestampMs::new(1),
            )
            .expect("the binding is recorded");
        broker
            .pin_table(instance(2), declarative_table(), rich_table())
            .expect("the installed tables are pinned");
        broker
            .open_native_connection(
                instance(2),
                &CREDENTIAL,
                &process_identity(41, 900),
                &package(),
                "1",
            )
            .expect("the native connection is authenticated");

        // Binding: a request of another application is not this binding's to interpret. The
        // frame is not a thing a caller names at all: the broker recorded it with the request.
        broker
            .pin_table(instance(3), declarative_table(), rich_table())
            .expect("the installed tables are pinned");
        broker
            .open_native_connection(
                instance(3),
                &CREDENTIAL,
                &process_identity(41, 900),
                &package(),
                "1",
            )
            .expect("the other instance's connection is authenticated");
        let elsewhere = broker
            .forward_native(
                GatewayConnectionId::new(2),
                permission_frame("99").as_bytes(),
                TimestampMs::new(2),
            )
            .expect("forwarded")
            .1
            .expect("it expects a response");
        assert!(matches!(
            broker.interpret(
                binding(9),
                elsewhere.resource_id,
                projection(),
                None,
                TimestampMs::new(3),
            ),
            Err(BrokerError::PermissionDenied { .. })
        ));

        let opaque = forward(&broker, "11", 4).expect("forwarded");

        // Schema policy: a projection outside the trust's declared schema is refused.
        let mut foreign = projection();
        foreign.schema_version = "kr-approval/99".to_owned();
        assert!(matches!(
            broker.interpret(
                binding(9),
                opaque.resource_id,
                foreign,
                None,
                TimestampMs::new(5),
            ),
            Err(BrokerError::Trust(_))
        ));

        let resource = broker
            .interpret(
                binding(9),
                opaque.resource_id,
                projection(),
                None,
                TimestampMs::new(6),
            )
            .expect("the interpretation is accepted");

        // Non-reuse: one request takes one interpretation, and the source it came from is spent.
        assert!(matches!(
            broker.interpret(
                binding(9),
                opaque.resource_id,
                projection(),
                None,
                TimestampMs::new(7),
            ),
            Err(BrokerError::Arbitration(_) | BrokerError::PreconditionFailed { .. })
        ));

        // Source generation: a request recorded before the owner changed is refused after it.
        let stale = forward(&broker, "13", 8).expect("forwarded");
        broker
            .advance_binding(instance(2), None, TimestampMs::new(9))
            .expect("the selected thread changed");
        assert!(matches!(
            broker.interpret(
                binding(9),
                stale.resource_id,
                projection(),
                None,
                TimestampMs::new(10),
            ),
            Err(BrokerError::PreconditionFailed { .. })
        ));

        resource.resource_id
    };

    // The ledger is retained across a restart, and it says whose interpretation this was, over
    // which bytes, and exactly which decisions were offered.
    let restarted =
        Broker::open(Some(&path), session(), JournalHealth::shared()).expect("the broker reopens");
    let entry = restarted
        .decoding(resource_id)
        .expect("the read succeeds")
        .expect("the entry survived the restart");
    assert_eq!(entry.publisher_id.as_str(), "kalareach");
    assert_eq!(entry.plugin_id.as_str(), "kalareach.codex");
    assert_eq!(entry.package_digest, Digest256::from_bytes([5; 32]));
    assert_eq!(entry.method, permission_method());
    assert_eq!(entry.upstream_request_id.as_str(), "11");
    assert_eq!(
        entry.source_bytes.as_slice(),
        permission_frame("11").as_bytes()
    );
    assert!(entry.offers("allow"));
    assert!(entry.offers("deny"));
    assert!(
        !entry.offers("allow_always"),
        "an answer the request never offered is not one this host can encode"
    );
    assert_eq!(
        restarted
            .pending(resource_id)
            .expect("the resource survived the restart")
            .state,
        PendingState::Pending
    );
    let _ = std::fs::remove_dir_all(&directory);
}

/// KR-REQ-11.27: one resolution per pending resource, and a reconnect reconciles an answer that
/// went without reissuing it.
#[tokio::test]
async fn kr_req_11_27_one_resolution_each_and_a_reconnect_leaves_a_sent_answer_uncertain() {
    let (broker, upstream) = broker_recording(
        BrokerGrants::granted([BrokerGrant::ApprovalInterpreter]),
        Some(trust(&[permission_method()], true)),
    );
    let resource = offer(&broker, instance(2), binding(9), "11", 2).expect("the offer is accepted");
    stop_the_host_at_the_bytes(&broker);

    let admitted =
        reserve(&broker, resource.resource_id, "allow", 4).expect("the first answer reserves it");
    assert!(
        reserve(&broker, resource.resource_id, "allow", 5).is_err(),
        "a second answer cannot reserve a resource the first one holds"
    );

    // A decision the request never offered is refused, and the resource it was offered for is
    // left answerable: the reservation goes back with the claim.
    let other = offer(&broker, instance(2), binding(9), "12", 2).expect("another offer");
    assert!(
        reserve(&broker, other.resource_id, "allow_always", 5).is_err(),
        "a decision the request never offered is never admitted"
    );
    assert_eq!(
        broker.pending(other.resource_id).expect("recorded").state,
        PendingState::Pending,
        "a refused answer leaves the resource answerable"
    );

    // The answer leaves this host. The marker goes in immediately before the bytes, and this host
    // stops before anything records what came of them.
    stopping(|| {
        let _ = broker.record_approval(&admitted, TimestampMs::new(6));
    });
    assert_eq!(
        broker
            .pending(resource.resource_id)
            .expect("recorded")
            .state,
        PendingState::Claimed,
        "the marker is in and no outcome is recorded"
    );

    // The connection comes back and the upstream still lists the request. This host cannot tell
    // whether its answer landed, so the resource is uncertain and is never answered again.
    let reconciliation = broker
        .reconcile(
            scope(instance(2), 1),
            &[request(1, "11"), request(1, "12")],
            TimestampMs::new(8),
        )
        .expect("the reconnect reconciles");
    assert_eq!(reconciliation.uncertain, vec![resource.resource_id]);
    assert_eq!(
        reconciliation.still_pending,
        vec![other.resource_id],
        "one the upstream still holds and nothing was sent for stays answerable"
    );
    assert_eq!(
        broker
            .pending(resource.resource_id)
            .expect("recorded")
            .state,
        PendingState::Uncertain
    );
    assert!(
        answer(&broker, resource.resource_id, "allow", 9)
            .await
            .is_err(),
        "a reconnect never reissues an uncertain response"
    );
    // And the admission that was in force before the reconnect settles nothing either: its
    // permit was spent when the bytes went, so there is no second transmission to make.
    assert!(
        broker
            .record_approval(&admitted, TimestampMs::new(10))
            .is_err()
    );
    assert_eq!(
        upstream.submitted().len(),
        0,
        "the one answer that went was carried by the transport that stopped"
    );
}

/// KR-REQ-11.28: an action token binds the actor, the grant, the revision, the declared action
/// and the parameter hash, and the broker rejects a change to any of them.
#[test]
fn kr_req_11_28_an_action_token_binds_actor_grant_revision_action_and_parameters() {
    let broker = broker_with(
        BrokerGrants::granted([BrokerGrant::UpstreamAction, BrokerGrant::Observation]),
        None,
    );
    let prepared = invocation(instance(2), 1, "prompt.submit");
    let token = broker
        .issue_token(binding(9), &prepared, TimestampMs::new(2))
        .expect("the token is issued");
    assert_eq!(token.actor_id, actor("device-1"));
    assert_eq!(token.grant, BrokerGrant::UpstreamAction);
    assert_eq!(token.binding_revision, AgentBindingRevision::new(1));
    assert_eq!(token.action.as_str(), "prompt.submit");

    // Every binding is checked at the broker, one changed field at a time.
    /// One field of a presented claim, changed.
    type Tamper = fn(&mut ActionTokenClaim);

    let tampering: Vec<(&str, Tamper)> = vec![
        ("actor", |claim| claim.actor_id = actor("device-2")),
        ("grant", |claim| claim.grant = BrokerGrant::Observation),
        ("grant record", |claim| {
            claim.grant_id = Nullable::some(GrantId::new(Uuid::from_bytes([8; 16])));
        }),
        ("application", |claim| {
            claim.application_instance_id = instance(3);
        }),
        ("revision", |claim| {
            claim.binding_revision = AgentBindingRevision::new(2);
        }),
        ("action", |claim| {
            claim.action = ActionName::new("turn.cancel").expect("valid");
        }),
        ("parameters", |claim| {
            claim.parameter_hash = Digest256::from_bytes([0; 32]);
        }),
    ];
    for (what, tamper) in tampering {
        let token = broker
            .issue_token(binding(9), &prepared, TimestampMs::new(3))
            .expect("the token is issued");
        let mut claim = ActionTokenClaim::from(&token);
        tamper(&mut claim);
        assert!(
            broker.spend_token(&claim).is_err(),
            "a changed {what} must not spend the token"
        );
    }

    let token = broker
        .issue_token(binding(9), &prepared, TimestampMs::new(4))
        .expect("the token is issued");
    let claim = ActionTokenClaim::from(&token);
    broker.spend_token(&claim).expect("the token is spent");
    assert!(
        broker.spend_token(&claim).is_err(),
        "one invocation's authority is spent once"
    );

    // A grant withdrawn after the token was issued is authority the token no longer carries.
    let token = broker
        .issue_token(binding(9), &prepared, TimestampMs::new(5))
        .expect("the token is issued");
    broker
        .withdraw_grant(binding(9), BrokerGrant::UpstreamAction)
        .expect("the grant is withdrawn");
    assert!(
        broker.spend_token(&ActionTokenClaim::from(&token)).is_err(),
        "a token whose grant has been withdrawn is not authority"
    );
}

/// KR-REQ-12.02: a launch profile records the resolved executable, distribution, version,
/// argument vector, authentication state and integration mode.
#[test]
fn kr_req_12_02_a_launch_profile_records_what_was_resolved() {
    let broker = Broker::open(None, session(), JournalHealth::shared()).expect("the broker opens");
    let intent = broker
        .prepare_launch(
            profile(IntegrationMode::Gateway, [3; 32], "0.9.1"),
            ForegroundMark::idle(4),
            None,
        )
        .expect("the launch is prepared");
    let resolved = broker
        .execute_launch(&intent, &ForegroundMark::idle(4), instance(2))
        .expect("the launch runs");
    assert_eq!(resolved.binary.resolved_path, "/usr/local/bin/codex");
    assert_eq!(resolved.binary.distribution, "homebrew");
    assert_eq!(resolved.binary.version, "0.9.1");
    assert_eq!(resolved.arguments, vec!["codex", "--resume"]);
    assert_eq!(resolved.authentication, AuthenticationState::Authenticated);
    assert_eq!(resolved.mode, IntegrationMode::Gateway);
    assert_eq!(
        broker
            .profile_of(instance(2))
            .expect("the profile is recorded")
            .profile_id,
        resolved.profile_id
    );
}

/// KR-REQ-12.03: a stale launch is refused, and the refusal is the whole answer.
///
/// What this establishes is the refusal and that nothing was started. That there is no path which
/// writes the command into the foreground application's input is a property of the code: the
/// refusal returns before anything is produced, and no function in this module writes bytes. The
/// end-to-end demonstration of an untouched terminal belongs to the gateway suite.
#[test]
fn kr_req_12_03_a_stale_launch_is_refused_and_starts_nothing() {
    let broker = Broker::open(None, session(), JournalHealth::shared()).expect("the broker opens");
    let intent = broker
        .prepare_launch(
            profile(IntegrationMode::Gateway, [3; 32], "0.9.1"),
            ForegroundMark::idle(4),
            None,
        )
        .expect("the launch is prepared");
    let occupied = ForegroundMark {
        application_instance_id: Some(instance(9)),
        prompt_revision: 4,
    };
    let refusal = broker
        .execute_launch(&intent, &occupied, instance(2))
        .expect_err("a stale launch is refused");
    assert!(matches!(
        refusal,
        BrokerError::Launch(LaunchRefusal::ForegroundChanged)
    ));
    assert!(
        broker.profile_of(instance(2)).is_none(),
        "a refused launch starts nothing"
    );

    // A prompt that moved is refused too, with its own reason.
    let moved = broker
        .execute_launch(&intent, &ForegroundMark::idle(5), instance(2))
        .expect_err("a moved prompt is refused");
    assert!(matches!(
        moved,
        BrokerError::Launch(LaunchRefusal::PromptMoved)
    ));
    assert!(broker.profile_of(instance(2)).is_none());
}

/// KR-REQ-12.05 and KR-REQ-02.10: no second agent process runs against one saved conversation,
/// and selecting another conversation moves the reservation rather than leaving both taken.
#[test]
fn kr_req_12_05_no_second_process_runs_against_one_saved_conversation() {
    let broker = Broker::open(None, session(), JournalHealth::shared()).expect("the broker opens");
    let first = broker
        .prepare_launch(
            profile(IntegrationMode::Gateway, [3; 32], "0.9.1"),
            ForegroundMark::idle(4),
            Some("thread-7".to_owned()),
        )
        .expect("the launch is prepared");
    broker
        .execute_launch(&first, &ForegroundMark::idle(4), instance(2))
        .expect("the first execution runs");
    broker
        .register_instance(
            instance(2),
            IntegrationMode::Gateway,
            None,
            Some(managed(instance(2), true)),
        )
        .expect("the instance is registered");

    let second = broker
        .prepare_launch(
            profile(IntegrationMode::Gateway, [3; 32], "0.9.1"),
            ForegroundMark::idle(4),
            Some("thread-7".to_owned()),
        )
        .expect("the launch is prepared");
    let refusal = broker
        .execute_launch(&second, &ForegroundMark::idle(4), instance(3))
        .expect_err("a second execution of the same conversation is refused");
    assert!(matches!(
        refusal,
        BrokerError::Launch(LaunchRefusal::ConversationAlreadyLive {
            application_instance_id
        }) if application_instance_id == instance(2)
    ));

    // The running instance selects another conversation. The one it left is free; the one it took
    // is not, and neither is stale.
    broker
        .advance_binding(
            instance(2),
            Some(AgentThreadId::new("thread-8").expect("valid")),
            TimestampMs::new(5),
        )
        .expect("the selection changes");
    assert_eq!(broker.conversation_owner("thread-7"), None);
    assert_eq!(broker.conversation_owner("thread-8"), Some(instance(2)));
    broker
        .execute_launch(&second, &ForegroundMark::idle(4), instance(3))
        .expect("the conversation it left is free for another execution");
}

/// KR-REQ-11.16: a probe declares what it will do and how long it may take before it runs, and a
/// source that cannot establish a working capability never claims one.
///
/// What this establishes is the admission contract for probes. Running one against a real upstream
/// and measuring its deadline is the acceptance owner's, because it needs an upstream to probe.
#[test]
fn kr_req_11_16_a_probe_is_bounded_and_disclosed_before_it_runs() {
    let broker = Broker::open(None, session(), JournalHealth::shared()).expect("the broker opens");
    broker
        .register_instance(
            instance(2),
            IntegrationMode::Gateway,
            None,
            Some(managed(instance(2), true)),
        )
        .expect("the instance is registered");

    let undisclosed = Probe {
        capability_id: capability("agent.prompt"),
        declared_operations: Vec::new(),
        destructive: false,
        isolated_context: None,
        budget_ms: 500,
    };
    assert!(
        broker
            .record_probe(
                &undisclosed,
                evidence(
                    "agent.prompt",
                    InstanceCapabilityState::QualifiedAvailable,
                    InstanceInvalidation::BinaryChanged,
                    instance(2)
                )
            )
            .is_err(),
        "a probe that declares nothing is not one the host runs"
    );

    let destructive = Probe {
        capability_id: capability("agent.prompt"),
        declared_operations: vec!["submit a prompt".to_owned()],
        destructive: true,
        isolated_context: None,
        budget_ms: 500,
    };
    assert!(
        broker
            .record_probe(
                &destructive,
                evidence(
                    "agent.prompt",
                    InstanceCapabilityState::QualifiedAvailable,
                    InstanceInvalidation::BinaryChanged,
                    instance(2)
                )
            )
            .is_err(),
        "a destructive probe needs its own isolated test context"
    );

    let unbounded = Probe {
        capability_id: capability("agent.prompt"),
        declared_operations: vec!["list the upstream's advertised commands".to_owned()],
        destructive: false,
        isolated_context: None,
        budget_ms: 60_000,
    };
    assert!(
        broker
            .record_probe(
                &unbounded,
                evidence(
                    "agent.prompt",
                    InstanceCapabilityState::QualifiedAvailable,
                    InstanceInvalidation::BinaryChanged,
                    instance(2)
                )
            )
            .is_err(),
        "a probe is a bounded question, not a test suite"
    );

    let disclosed = Probe {
        capability_id: capability("agent.prompt"),
        declared_operations: vec!["list the upstream's advertised commands".to_owned()],
        destructive: false,
        isolated_context: None,
        budget_ms: 500,
    };
    broker
        .record_probe(
            &disclosed,
            evidence(
                "agent.prompt",
                InstanceCapabilityState::QualifiedAvailable,
                InstanceInvalidation::BinaryChanged,
                instance(2),
            ),
        )
        .expect("a bounded, disclosed probe records its result");

    // Evidence is not permission: a signed record cannot say a capability works on this host.
    let mut signed = evidence(
        "agent.cancel",
        InstanceCapabilityState::QualifiedAvailable,
        InstanceInvalidation::BinaryChanged,
        instance(2),
    );
    signed.source = InstanceEvidenceSource::SignedRecord;
    assert!(broker.record_capability(signed).is_err());
}

/// KR-REQ-11.17: evidence is invalidated by the change it is about, an installed upgrade leaves a
/// running binding's pinned evidence alone, and an action rechecks its own capability revision on
/// the dispatch path rather than only when a client asks.
#[test]
fn kr_req_11_17_an_action_rechecks_its_capability_and_an_upgrade_spares_a_pinned_binding() {
    let broker = broker_with(BrokerGrants::granted([BrokerGrant::UpstreamAction]), None);
    broker
        .record_capability(evidence(
            "agent.prompt",
            InstanceCapabilityState::QualifiedAvailable,
            InstanceInvalidation::BinaryChanged,
            instance(2),
        ))
        .expect("recorded");

    let with_capability = |name: &str, read_at: Option<CapabilityRevision>| {
        let mut prepared = invocation(instance(2), 1, "prompt.submit");
        prepared.capability = Some((capability(name), read_at));
        prepared
    };

    // The action path itself performs the recheck.
    broker
        .issue_token(
            binding(9),
            &with_capability("agent.prompt", Some(CapabilityRevision::new(1))),
            TimestampMs::new(2),
        )
        .expect("the revision the caller read is the one held");
    assert!(
        broker
            .issue_token(
                binding(9),
                &with_capability("agent.prompt", Some(CapabilityRevision::new(2))),
                TimestampMs::new(3)
            )
            .is_err(),
        "an action prepared against a revision that has moved is refused"
    );

    assert_eq!(
        broker.invalidate_capabilities(
            InstanceInvalidation::BinaryChanged,
            "the executable was upgraded",
            TimestampMs::new(20)
        ),
        1
    );
    assert!(
        broker
            .issue_token(
                binding(9),
                &with_capability("agent.prompt", None),
                TimestampMs::new(21)
            )
            .is_err(),
        "an upgraded binary invalidates the evidence that was about the binary"
    );
    broker
        .issue_token(
            binding(9),
            &with_capability("agent.approval", None),
            TimestampMs::new(22),
        )
        .expect("a running binding's pinned evidence survives an installed upgrade");

    // And the recheck happens again when the token is spent, not only when it is issued: evidence
    // withdrawn while the component was working is evidence the dispatch no longer has.
    let token = broker
        .issue_token(
            binding(9),
            &with_capability("agent.approval", None),
            TimestampMs::new(23),
        )
        .expect("the token is issued");
    assert_eq!(
        broker.invalidate_capabilities(
            InstanceInvalidation::BindingChanged,
            "the selected thread changed",
            TimestampMs::new(24)
        ),
        1
    );
    assert!(
        broker.spend_token(&ActionTokenClaim::from(&token)).is_err(),
        "a token whose capability evidence was withdrawn is not authority to dispatch"
    );
}

/// KR-REQ-01.02: the capability map is per installation, and no source that cannot try something
/// here can say it works here.
#[test]
fn kr_req_01_02_the_capability_map_is_per_installation() {
    let broker = Broker::open(None, session(), JournalHealth::shared()).expect("the broker opens");
    broker
        .register_instance(
            instance(2),
            IntegrationMode::Gateway,
            None,
            Some(managed(instance(2), true)),
        )
        .expect("the instance is registered");
    broker
        .register_instance(
            instance(3),
            IntegrationMode::NativeTerminal,
            None,
            Some(managed(instance(3), true)),
        )
        .expect("the instance is registered");
    broker
        .record_capability(evidence(
            "agent.prompt",
            InstanceCapabilityState::QualifiedAvailable,
            InstanceInvalidation::BinaryChanged,
            instance(2),
        ))
        .expect("recorded");
    broker
        .record_capability(evidence(
            "agent.prompt",
            InstanceCapabilityState::MissingInstallation,
            InstanceInvalidation::BinaryChanged,
            instance(3),
        ))
        .expect("recorded");

    let gateway = broker.capabilities(instance(2));
    let terminal = broker.capabilities(instance(3));
    assert_eq!(
        gateway
            .record(&capability("agent.prompt"))
            .expect("recorded")
            .state,
        InstanceCapabilityState::QualifiedAvailable
    );
    assert_eq!(
        terminal
            .record(&capability("agent.prompt"))
            .expect("recorded")
            .state,
        InstanceCapabilityState::MissingInstallation,
        "two installations of one agent have two maps"
    );

    // The only source that can say a capability works here is one that tried it here.
    assert!(InstanceEvidenceSource::HostProbe.can_establish_qualified());
    assert!(InstanceEvidenceSource::LiveBinding.can_establish_qualified());
    assert!(!InstanceEvidenceSource::SignedRecord.can_establish_qualified());
    assert!(!InstanceEvidenceSource::PackageDeclaration.can_establish_qualified());
}

/// KR-REQ-07.67: a native exit names the backend to stop by its full process identity; closing an
/// attachment names nothing and leaves a real child process running.
// Unix only: a dedicated backend is a managed gateway launch, and Windows has no managed gateway.
#[cfg(unix)]
#[test]
fn kr_req_07_67_a_native_exit_names_its_backend_and_closing_an_attachment_leaves_it_running() {
    // A real child, started by this test and stopped by it. `sleep` is on the internal disk and
    // needs nothing from the workspace.
    let mut child = std::process::Command::new("/bin/sleep")
        .arg("30")
        .spawn()
        .expect("the child starts");
    let pid = u64::from(child.id());
    let identity = process_identity(pid, 12_345);

    let broker = Broker::open(None, session(), JournalHealth::shared()).expect("the broker opens");
    broker
        .register_instance(
            instance(2),
            IntegrationMode::Gateway,
            None,
            Some(managed_as(instance(2), true, identity.clone())),
        )
        .expect("the instance is registered");
    broker.attach(instance(2));
    broker.attach(instance(2));

    let closed = broker.end(instance(2), InstanceEnding::AttachmentClosed);
    assert!(!closed.instance_ended);
    assert_eq!(closed.backend, None);
    assert_eq!(closed.attachments_remaining, 1);
    broker
        .binding_state(instance(2))
        .expect("the instance is still running");
    assert!(
        child.try_wait().expect("the child can be polled").is_none(),
        "closing an attachment does not end the process in the worker's terminal"
    );

    let exited = broker.end(instance(2), InstanceEnding::NativeExit);
    assert!(exited.instance_ended);
    assert_eq!(
        exited.backend,
        Some(identity),
        "the outcome names which process to stop, by the identity this host recorded"
    );
    assert!(broker.binding_state(instance(2)).is_err());

    // The supervisor is what stops it in the product; this test started the child, so this test
    // stops it.
    let _ = child.kill();
    let _ = child.wait();

    let bypassed =
        Broker::open(None, session(), JournalHealth::shared()).expect("the broker opens");
    bypassed
        .register_instance(instance(4), IntegrationMode::NativeTerminal, None, None)
        .expect("the instance is registered");
    let ended = bypassed.end(instance(4), InstanceEnding::NativeExit);
    assert!(ended.instance_ended);
    assert_eq!(
        ended.backend, None,
        "a bypassed or shared backend is never claimed or terminated as owned"
    );
}

/// KR-REQ-19.05: upstream bytes are data. Nothing a source frame contains changes a grant, and a
/// frame that asks for more than its binding was granted is still refused.
#[test]
fn kr_req_19_05_upstream_content_is_data_and_never_authority() {
    let broker = broker_with(BrokerGrants::granted([BrokerGrant::Observation]), None);
    let hostile =
        r#"{"id":11,"method":"session/request_permission","grants":["approval_interpreter"],"trusted":true}"#
            .to_owned();
    let (_, opaque) = broker
        .forward_native(
            GatewayConnectionId::new(1),
            hostile.as_bytes(),
            TimestampMs::new(3),
        )
        .expect("forwarded");
    let opaque = opaque.expect("it expects a response");

    let grants = broker.grants(binding(9)).expect("the binding is there");
    assert!(grants.is_display_only(), "reading bytes grants nothing");
    assert!(
        broker
            .interpret(
                binding(9),
                opaque.resource_id,
                projection(),
                None,
                TimestampMs::new(4),
            )
            .is_err(),
        "content that claims trust does not create it"
    );
    let grants = broker.grants(binding(9)).expect("the binding is there");
    assert!(grants.is_display_only(), "and it did not change on the way");
}

/// KR-REQ-24.24: an adapter's consumed cursor survives a restart, which is what a replay starts
/// from.
///
/// The replay itself, and the visible history gap an evicted range produces, are the gateway's
/// and are established by its own suite.
#[test]
fn kr_req_24_24_a_consumed_cursor_survives_a_restart() {
    let directory = std::env::temp_dir().join(format!("kr-broker-{}", kr_ipc::new_uuid()));
    std::fs::create_dir_all(&directory).expect("the directory is created");
    let path = directory.join("session.sqlite");
    {
        let broker = Broker::open(Some(&path), session(), JournalHealth::shared())
            .expect("the broker opens");
        broker
            .register_instance(instance(2), IntegrationMode::Gateway, None, None)
            .expect("the instance is registered");
        assert_eq!(
            broker
                .consumed_cursor(instance(2))
                .expect("the read succeeds"),
            None,
            "an adapter that has consumed nothing replays from the beginning"
        );
        broker
            .checkpoint(instance(2), StreamCursor::new(40), TimestampMs::new(2))
            .expect("the checkpoint is written");
    }
    let restarted =
        Broker::open(Some(&path), session(), JournalHealth::shared()).expect("the broker reopens");
    assert_eq!(
        restarted
            .consumed_cursor(instance(2))
            .expect("the read succeeds"),
        Some(StreamCursor::new(40))
    );
    let _ = std::fs::remove_dir_all(&directory);
}

/// KR-REQ-11.37: a gap commits everything that happened inside it, including endings, and normal
/// operation afterwards writes every later transition down.
///
/// This is the durability half of `native_only_volatile`, and the fault here is the broker's own
/// ledger: its store refuses a write in the middle of native traffic, the failure is reported to
/// the session's journal condition where it happens, and the receipt path and the broker are both
/// behind the fence from that moment. The fence itself, the native arbitration that continues
/// through it and `UPSTREAM_UNAVAILABLE` are the gateway's.
#[tokio::test]
async fn kr_req_11_37_a_committed_gap_records_what_happened_inside_it_and_restores_durable_writes()
{
    let mut store = common::SharedStore::open();
    let path = store.path.clone();

    let (surviving, withdrawn) = {
        let broker =
            Broker::open(Some(&path), session(), store.health()).expect("the broker opens");
        broker
            .register_instance(
                instance(2),
                IntegrationMode::Gateway,
                None,
                Some(managed(instance(2), true)),
            )
            .expect("the instance is registered");
        broker
            .bind(
                binding(9),
                instance(2),
                PluginId::new("kalareach.codex").expect("valid"),
                PublisherId::new("kalareach").expect("valid"),
                Digest256::from_bytes([5; 32]),
                BrokerGrants::granted([BrokerGrant::ApprovalInterpreter]),
                Some(trust(&[permission_method()], true)),
                TimestampMs::new(1),
            )
            .expect("the binding is recorded");

        broker
            .pin_table(instance(2), declarative_table(), rich_table())
            .expect("the installed tables are pinned");
        broker
            .open_native_connection(
                instance(2),
                &CREDENTIAL,
                &process_identity(41, 900),
                &package(),
                "1",
            )
            .expect("the native connection is authenticated");
        equip(&broker);

        let surviving =
            offer(&broker, instance(2), binding(9), "11", 2).expect("the offer is accepted");
        let withdrawn =
            offer(&broker, instance(2), binding(9), "12", 4).expect("the offer is accepted");

        // The ledger's store stops taking writes. The next native request meets it: the request
        // is still recorded, in memory, and its interpretation is refused because rich work is
        // now fenced.
        broker
            .refuse_ledger_writes(true)
            .expect("the store is put in query-only mode");
        let during = forward(&broker, "13", 7).expect("the native request is still recorded");
        assert_eq!(
            during.durability,
            kr_protocol::session::Durability::Volatile
        );
        assert!(
            !store.journal.health().is_healthy(),
            "the ledger's failure is the session's journal condition, which the receipt path reads"
        );
        assert_eq!(
            broker.mode(),
            kr_protocol::gateway::GatewayMode::NativeOnlyVolatile
        );
        let fenced = broker
            .interpret(
                binding(9),
                during.resource_id,
                projection(),
                None,
                TimestampMs::new(8),
            )
            .expect_err("rich approvals are fenced while the store is faulted");
        assert_eq!(
            fenced.code(),
            kr_protocol::error::ErrorCode::UpstreamUnavailable
        );

        // The upstream withdraws one of them inside the gap. That ending is what a recovery that
        // only committed unresolved resources would lose.
        broker
            .upstream_resolved(&request(1, "12"), TimestampMs::new(8))
            .expect("the upstream answered it itself");

        // The store takes writes again. The journal writes its own gap and calls the condition
        // healthy, which is what lets the broker commit its own.
        broker
            .refuse_ledger_writes(false)
            .expect("the store takes writes again");
        store.recover_journal(9);
        broker
            .recover(TimestampMs::new(9))
            .expect("the gap is committed");
        // Rich work does not come back yet: the pending identifiers have to be reconciled with
        // the same upstream first.
        assert!(
            answer(&broker, surviving.resource_id, "allow", 10)
                .await
                .is_err(),
            "committing the gap is not the same as reconciling the upstream"
        );
        broker
            .reconcile_recovered(
                broker.recovery_generation(),
                scope(instance(2), 1),
                &[
                    Broker::downstream(
                        GatewayConnectionId::new(1),
                        UpstreamRequestId::new("11").expect("valid"),
                    ),
                    Broker::downstream(
                        GatewayConnectionId::new(1),
                        UpstreamRequestId::new("13").expect("valid"),
                    ),
                ],
                TimestampMs::new(11),
            )
            .expect("the upstream said what it still holds, and rich work resumes");

        // Normal operation again: an admitted answer goes and is written down, although the
        // resource's own history says it lived through a gap.
        answer(&broker, surviving.resource_id, "allow", 12)
            .await
            .expect("the upstream took it");

        (surviving.resource_id, withdrawn.resource_id)
    };

    // A restart reads back what the gap committed and what happened after it.
    let restarted =
        Broker::open(Some(&path), session(), JournalHealth::shared()).expect("the broker reopens");
    assert!(
        restarted.pending(surviving).is_none(),
        "a resolved resource is not one a restart offers again"
    );
    assert!(
        restarted.pending(withdrawn).is_none(),
        "an ending inside the gap was committed rather than left pending for ever"
    );
}

/// The broker holds a bounded number of unconsumed source frames.
///
/// A connector that never decodes anything is a connector whose oldest frames this host forgets,
/// rather than a session whose memory grows for the rest of the day.
#[test]
fn unconsumed_source_frames_are_bounded() {
    let broker = broker_with(BrokerGrants::granted([BrokerGrant::Observation]), None);
    let mut handles: Vec<SourceEventHandle> = Vec::new();
    for index in 0..(kr_worker::broker::MAX_RETAINED_FRAMES + 8) {
        handles.push(
            broker
                .record_source(
                    instance(2),
                    format!("{{\"id\":{index}}}").as_bytes(),
                    TimestampMs::new(index as u64),
                )
                .expect("the frame is recorded"),
        );
    }
    assert!(
        broker.source(instance(2), &handles[0]).is_none(),
        "the oldest unconsumed frame is the one that goes"
    );
    assert!(
        broker
            .source(instance(2), handles.last().expect("a handle"))
            .is_some(),
        "the newest is still there"
    );
}

/// KR-REQ-11.16 and KR-REQ-11.17: evidence names the exact installation it was gathered against,
/// and every field it names is compared with what this host established itself.
#[test]
fn kr_req_11_17_evidence_names_the_package_publisher_schema_and_binary_it_was_gathered_against() {
    let broker = broker_with(BrokerGrants::granted([BrokerGrant::UpstreamAction]), None);

    // A record that names the package, its bytes, its publisher, its schema and the binary this
    // host is talking to is accepted.
    let mut complete = evidence(
        "agent.prompt",
        InstanceCapabilityState::QualifiedAvailable,
        InstanceInvalidation::BinaryChanged,
        instance(2),
    );
    complete.identity.plugin_id = Nullable::some(package());
    complete.identity.package_digest = Nullable::some(Digest256::from_bytes([5; 32]));
    complete.identity.publisher_id = Nullable::some(PublisherId::new("kalareach").expect("valid"));
    complete.identity.schema_version =
        Nullable::some(kr_protocol::broker::MethodTableVersionText("1".to_owned()));
    complete.identity.binding_id = Nullable::some(binding(9));
    broker
        .record_capability(complete.clone())
        .expect("evidence about this installation is recorded");

    // Each field on its own is enough to make the record about something else.
    let mut other_package = complete.clone();
    other_package.identity.plugin_id =
        Nullable::some(PluginId::new("vendor.other").expect("valid"));
    let mut other_bytes = complete.clone();
    other_bytes.identity.package_digest = Nullable::some(Digest256::from_bytes([6; 32]));
    let mut other_publisher = complete.clone();
    other_publisher.identity.publisher_id =
        Nullable::some(PublisherId::new("someone-else").expect("valid"));
    let mut other_schema = complete.clone();
    other_schema.identity.schema_version =
        Nullable::some(kr_protocol::broker::MethodTableVersionText("2".to_owned()));
    let mut other_binary = complete.clone();
    other_binary.identity.binary_digest = Nullable::some(Digest256::from_bytes([9; 32]));
    for (what, mut record) in [
        ("another package", other_package),
        ("other package bytes", other_bytes),
        ("another publisher", other_publisher),
        ("another upstream schema", other_schema),
        ("another binary", other_binary),
    ] {
        // A newer revision, so what refuses the record is the identity check rather than the map
        // refusing to move backwards.
        record.revision = CapabilityRevision::new(2);
        let refusal = broker
            .record_capability(record)
            .expect_err("evidence about something else is refused");
        assert!(
            matches!(
                refusal,
                BrokerError::InvalidArgument(_) | BrokerError::StaleBinding { .. }
            ),
            "evidence about {what} is not evidence about this installation: {refusal:?}"
        );
    }

    // And a field this host cannot check is refused rather than believed: package bytes with no
    // binding names bytes nothing loaded, and a schema with no pinned table names a protocol
    // nothing qualified.
    let mut unbound_bytes = complete.clone();
    unbound_bytes.identity.binding_id = Nullable::null();
    unbound_bytes.revision = CapabilityRevision::new(2);
    assert!(
        broker.record_capability(unbound_bytes).is_err(),
        "package bytes are known through the binding that loaded them"
    );
    let mut unnamed_package = complete.clone();
    unnamed_package.identity.plugin_id = Nullable::null();
    unnamed_package.identity.package_digest = Nullable::null();
    unnamed_package.identity.publisher_id = Nullable::null();
    unnamed_package.revision = CapabilityRevision::new(2);
    assert!(
        broker.record_capability(unnamed_package).is_err(),
        "a schema version says nothing without the package it belongs to"
    );

    // An instance with no launch profile and no managed process has no binary identity, so
    // evidence about a binary is refused instead of accepted unchecked.
    let adopted = Broker::open(None, session(), JournalHealth::shared()).expect("the broker opens");
    adopted
        .register_instance(instance(4), IntegrationMode::Gateway, None, None)
        .expect("the instance is registered");
    let mut about_a_binary = evidence(
        "agent.prompt",
        InstanceCapabilityState::QualifiedAvailable,
        InstanceInvalidation::BinaryChanged,
        instance(4),
    );
    about_a_binary.identity.plugin_id = Nullable::null();
    assert!(
        adopted.record_capability(about_a_binary).is_err(),
        "there is nothing here to check a binary digest against"
    );
}
