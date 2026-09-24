//! The gateway core, the native proxy contract and volatile-native mode.
//!
//! Each test is named for the requirement row it closes. Where a test establishes less than its
//! row asks for, the name says what it does establish and the comment says what is left and who
//! owns it.

use kr_protocol::agent::{AgentApprovalRespondParams, AgentApprovalRespondResult};
use kr_protocol::broker::{
    ActionProvenance, BrokerGrant, BrokerGrants, DecodedProjection, DecodingTrust,
    InstanceCapabilityIdentity, InstanceCapabilityRecord, InstanceCapabilityState,
    InstanceEvidenceSource, InstanceInvalidation, IntegrationMode, OfferedDecision,
};
use kr_protocol::error::ErrorCode;
use kr_protocol::gateway::{
    DeclarativeEntry, DeclarativeTable, GatewayMode, NativeFraming, NativeMethodClass, PendingKind,
    PendingState, ReverseOperation, RichMethodEntry, RichMethodTable, RichOperation,
};
use kr_protocol::identity::{ProcessStartIdentity, ProcessStartSource};
use kr_protocol::ids::{
    ActorId, AgentBindingRevision, ApplicationInstanceId, BrokerBindingId, CapabilityId,
    CapabilityRevision, EnvironmentId, GatewayConnectionId, GrantId, MethodTableVersion,
    PendingResourceId, PluginId, PublisherId, SessionId, UpstreamMethod, UpstreamRequestId,
};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{Digest256, Nullable, TimestampMs, U64, Uuid};
use kr_protocol::session::Durability;
use kr_worker::broker::{
    Broker, BrokerError, BrokerTransport, Caller, ConnectionOrigin, Credential, ManagedProcess,
    MutationAdmission, PendingTransmission, ReconcileScope, TransportHandle, UpstreamBody,
    UpstreamDispatch, UpstreamOutcome, UpstreamRequest, subject,
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

fn method(name: &str) -> UpstreamMethod {
    UpstreamMethod::new(name).expect("a valid method name")
}

fn actor(name: &str) -> ActorId {
    ActorId::new(name).expect("a valid actor principal")
}

fn process_identity(pid: u64, start: u64) -> ProcessStartIdentity {
    ProcessStartIdentity::new(pid, ProcessStartSource::MacosProcBsdInfo, start)
}

fn managed(instance_id: ApplicationInstanceId) -> ManagedProcess {
    let process = process_identity(41, 900);
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
        true,
        TimestampMs::new(1),
    )
}

fn trust() -> DecodingTrust {
    DecodingTrust {
        plugin_id: PluginId::new("kalareach.codex").expect("valid"),
        publisher_id: PublisherId::new("kalareach").expect("valid"),
        package_digest: Digest256::from_bytes([5; 32]),
        methods: [method("session/request_permission")].into_iter().collect(),
        schema_versions: ["kr-approval/1".to_owned()].into_iter().collect(),
        max_decisions: U64::new(4),
        may_encode_response: true,
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

fn package() -> PluginId {
    PluginId::new("kalareach.codex").expect("valid")
}

fn table() -> DeclarativeTable {
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
                method: method("fs/write_text_file"),
                class: NativeMethodClass::Mutation,
                expects_response: true,
                approval_option_field: Nullable::null(),
                reverse: Nullable::null(),
            },
            DeclarativeEntry {
                method: method("session/request_permission"),
                class: NativeMethodClass::Mutation,
                expects_response: true,
                approval_option_field: Nullable::some("option_id".to_owned()),
                reverse: Nullable::null(),
            },
            DeclarativeEntry {
                method: method("session/update"),
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

fn rich() -> RichMethodTable {
    RichMethodTable {
        table_version: MethodTableVersion::new(1),
        upstream_protocol_version: "1".to_owned(),
        entries: vec![
            RichMethodEntry {
                method: method("session/cancel"),
                class: NativeMethodClass::Mutation,
                required_right: ActionRight::AgentCancel,
                operation: Nullable::some(RichOperation::TurnCancel),
                provenance: ActionProvenance::UpstreamTypedRpc,
            },
            RichMethodEntry {
                method: method("session/set_provider_key"),
                class: NativeMethodClass::Unsupported,
                required_right: ActionRight::AgentPrompt,
                operation: Nullable::null(),
                provenance: ActionProvenance::UpstreamTypedRpc,
            },
        ],
    }
}

/// One request frame. `id` is the identifier's JSON literal, so a caller chooses between the
/// number `11` and the string `"11"` the way an upstream does.
fn frame(id: &str, method_name: &str) -> String {
    format!(r#"{{"id":{id},"method":"{method_name}"}}"#)
}

/// One response frame, with the identifier written as the JSON literal `id`.
fn response(id: &str) -> String {
    format!(r#"{{"id":{id},"result":{{"outcome":"allow"}}}}"#)
}

/// A worker with one instance, one authenticated native connection and one trusted decoder.
/// A transport that records what it was asked to carry, and answers as an upstream would.
///
/// An answer reaches its upstream through one of these in the product: section 12's bundled
/// adapters are the plugins repository's, and each drives its own connection. What it establishes
/// here is that the resource settles on a transmission rather than on a caller's say-so.
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
/// Section 24 puts the durable marker before the effect so that exactly this state is readable
/// afterwards: the marker is in, the answer may already have reached the upstream, and nothing
/// records what came of it. It is the state a worker that died mid-answer comes back to, and it
/// is reconciliation, not a second answer, that settles it.
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

fn caller(name: &str) -> Caller {
    Caller {
        actor_id: actor(name),
        grant_id: Some(GrantId::new(Uuid::from_bytes([7; 16]))),
    }
}

fn respond(resource_id: PendingResourceId, option_id: &str) -> AgentApprovalRespondParams {
    AgentApprovalRespondParams {
        target: kr_protocol::agent::AgentMutationTarget {
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

/// Answers one approval and stops the host at the moment its bytes go.
///
/// What is left behind is a resource with a committed dispatch marker and no recorded outcome,
/// which is what a restart reads back and what reconciliation has to settle.
fn answer_and_stop(
    broker: &Broker,
    upstream: &std::sync::Arc<RecordingUpstream>,
    resource_id: PendingResourceId,
    now: u64,
) {
    broker.bind_connection_dispatch(
        GatewayConnectionId::new(1),
        std::sync::Arc::new(StoppingUpstream),
    );
    // The host stops inside `submit`, which the admission reaches before anything is awaited,
    // so the stop is caught here rather than in a future nobody polls.
    let stopped = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let admitted = broker
            .admit_approval(
                &caller("device-1"),
                &respond(resource_id, "allow"),
                TimestampMs::new(now),
            )
            .expect("the answer is admitted");
        let _ = broker.record_approval(&admitted, TimestampMs::new(now));
    }));
    let payload = stopped.expect_err("the host stopped where the transport stops it");
    assert_eq!(
        payload.downcast_ref::<String>().map(String::as_str),
        Some(STOPPED)
    );
    broker.bind_connection_dispatch(
        GatewayConnectionId::new(1),
        std::sync::Arc::clone(upstream) as _,
    );
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

fn gateway_recording(
    path: Option<&std::path::Path>,
) -> (Broker, std::sync::Arc<RecordingUpstream>) {
    gateway_tabled(path, table())
}

fn gateway_tabled(
    path: Option<&std::path::Path>,
    declarative: DeclarativeTable,
) -> (Broker, std::sync::Arc<RecordingUpstream>) {
    gateway_built(path, JournalHealth::shared(), declarative)
}

/// A gateway whose broker keeps its ledger beside a session's receipt journal and reads that
/// journal's condition, as a worker's does.
fn gateway_sharing(store: &common::SharedStore) -> (Broker, std::sync::Arc<RecordingUpstream>) {
    gateway_built(Some(&store.path), store.health(), table())
}

fn gateway_built(
    path: Option<&std::path::Path>,
    health: std::sync::Arc<JournalHealth>,
    declarative: DeclarativeTable,
) -> (Broker, std::sync::Arc<RecordingUpstream>) {
    let broker = Broker::open(path, session(), health).expect("the broker opens");
    broker
        .register_instance(
            instance(2),
            IntegrationMode::Gateway,
            None,
            Some(managed(instance(2))),
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
            Some(trust()),
            TimestampMs::new(1),
        )
        .expect("the binding is recorded");
    broker
        .pin_table(instance(2), declarative, rich())
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
    // An answer is checked against the installation's own evidence for what it does, and it goes
    // out on the connection whose resource it resolves: without a transport there is nothing to
    // carry one and nothing settles.
    broker
        .record_capability(InstanceCapabilityRecord {
            capability_id: CapabilityId::new("agent.approval").expect("valid"),
            capability_version: "1".to_owned(),
            application_instance_id: instance(2),
            identity: InstanceCapabilityIdentity::default(),
            revision: CapabilityRevision::new(1),
            state: InstanceCapabilityState::QualifiedAvailable,
            source: InstanceEvidenceSource::HostProbe,
            invalidated_by: [InstanceInvalidation::BindingChanged].into_iter().collect(),
            disabled_reason: Nullable::null(),
            observed_at: TimestampMs::new(1),
        })
        .expect("the evidence is recorded");
    let upstream = std::sync::Arc::new(RecordingUpstream::default());
    broker
        .bind_dispatch(instance(2), std::sync::Arc::clone(&upstream) as _)
        .expect("the transport is bound");
    broker.bind_connection_dispatch(
        GatewayConnectionId::new(1),
        std::sync::Arc::clone(&upstream) as _,
    );
    (broker, upstream)
}

fn gateway(path: Option<&std::path::Path>) -> Broker {
    gateway_recording(path).0
}

fn journal_path() -> std::path::PathBuf {
    let directory = std::env::temp_dir().join(format!("kr-gateway-{}", kr_ipc::new_uuid()));
    std::fs::create_dir_all(&directory).expect("the directory is created");
    directory.join("session.sqlite")
}

/// Forwards one request and interprets it, the way a live gateway does.
fn approval(
    broker: &Broker,
    id: &str,
    now: u64,
) -> Result<kr_protocol::gateway::PendingResource, BrokerError> {
    let body = frame(id, "session/request_permission");
    let (_, opaque) = broker.forward_native(
        GatewayConnectionId::new(1),
        body.as_bytes(),
        TimestampMs::new(now),
    )?;
    let opaque = opaque.expect("this method expects a response");
    broker.interpret(
        binding(9),
        opaque.resource_id,
        projection(),
        None,
        TimestampMs::new(now + 1),
    )
}

/// KR-REQ-11.30: the qualified declarative table is interpreted by core code, and any request it
/// does not classify is presumed mutating and suspends rich mutations.
#[test]
fn kr_req_11_30_the_core_classifies_with_the_table_and_presumes_an_unknown_request_mutates() {
    let broker = gateway(None);

    let observed = broker
        .forward_native(
            GatewayConnectionId::new(1),
            frame("1", "session/update").as_bytes(),
            TimestampMs::new(2),
        )
        .expect("forwarded");
    assert_eq!(
        observed.0.classification.class,
        NativeMethodClass::Observation
    );
    assert!(observed.0.classification.declared);
    assert!(observed.1.is_none(), "an observation expects no response");
    assert!(
        !broker
            .binding_state(instance(2))
            .expect("the instance is there")
            .rich_mutations_suspended
    );

    let unknown = broker
        .forward_native(
            GatewayConnectionId::new(1),
            frame("2", "vendor/undocumented").as_bytes(),
            TimestampMs::new(3),
        )
        .expect("forwarded exactly as it is");
    assert_eq!(unknown.0.classification.class, NativeMethodClass::Mutation);
    assert!(!unknown.0.classification.declared);
    assert!(
        unknown.1.is_some(),
        "a request the table does not describe still becomes a pending resource"
    );
    let state = broker
        .binding_state(instance(2))
        .expect("the instance is there");
    assert!(
        state.rich_mutations_suspended,
        "rich mutations wait until the binding is reconciled"
    );
    assert!(
        state
            .suspension_reason
            .as_ref()
            .is_some_and(|reason| reason.contains("vendor/undocumented"))
    );
}

/// KR-REQ-11.31: a component fault disables the rich capability, and native traffic keeps moving.
#[test]
fn kr_req_11_31_a_disabled_component_stops_rich_meaning_and_no_native_recording() {
    let broker = gateway(None);
    approval(&broker, "1", 2).expect("an interpretation before the fault");

    broker.disable_rich(binding(9), "three faults in one minute");
    assert!(
        broker
            .rich_disabled(binding(9))
            .is_some_and(|reason| reason.contains("three faults"))
    );

    // Native forwarding is untouched: the frame is read, classified and recorded.
    let forwarded = broker
        .forward_native(
            GatewayConnectionId::new(1),
            frame("2", "fs/write_text_file").as_bytes(),
            TimestampMs::new(5),
        )
        .expect("the native path does not depend on the component");
    let opaque = forwarded.1.expect("it expects a response");
    assert_eq!(opaque.kind, PendingKind::ReverseRpc);
    assert!(!opaque.interpretation_verified);

    // And its answer is still arbitrated.
    let answered = broker
        .native_answer_through(
            GatewayConnectionId::new(1),
            response("2").as_bytes(),
            TimestampMs::new(6),
            |_| Ok(()),
        )
        .expect("the native answer is arbitrated");
    assert_eq!(answered.state, PendingState::Resolved);

    // The rich meaning is what stopped.
    let refusal = approval(&broker, "3", 7).expect_err("rich interpretation is disabled");
    assert_eq!(refusal.code(), ErrorCode::UnsupportedCapability);
}

/// KR-REQ-11.32 and KR-REQ-11.36: only an authenticated worker-launched native connection uses
/// the forwarding path, and nothing can relabel itself native to reach it.
#[test]
fn kr_req_11_32_only_the_launch_binding_and_the_private_exchange_open_a_native_connection() {
    let broker = gateway(None);

    // A rich client connects and is refused the native path.
    broker
        .open_connection(instance(2), ConnectionOrigin::RichClient, &package(), "1")
        .expect("a rich client connects");
    let refusal = broker
        .forward_native(
            GatewayConnectionId::new(2),
            frame("1", "fs/write_text_file").as_bytes(),
            TimestampMs::new(2),
        )
        .expect_err("a rich client cannot forward natively");
    assert_eq!(refusal.code(), ErrorCode::PermissionDenied);

    // A component cannot either.
    broker
        .open_connection(instance(2), ConnectionOrigin::Component, &package(), "1")
        .expect("a component connects");
    assert!(
        broker
            .forward_native(
                GatewayConnectionId::new(3),
                frame("1", "fs/write_text_file").as_bytes(),
                TimestampMs::new(3),
            )
            .is_err()
    );

    // And a caller that presents the wrong secret, or the wrong process, gets no native
    // connection at all.
    assert!(
        broker
            .open_native_connection(
                instance(2),
                &[8; 32],
                &process_identity(41, 900),
                &package(),
                "1",
            )
            .is_err(),
        "an environment variable that leaked is not a launch binding"
    );
    assert!(
        broker
            .open_native_connection(
                instance(2),
                &CREDENTIAL,
                &process_identity(42, 900),
                &package(),
                "1",
            )
            .is_err(),
        "the private exchange without the process binding is not enough either"
    );
}

/// KR-REQ-11.33: the encode, recheck, claim and dispatch transaction, and a native answer that
/// arrives during encoding wins.
#[tokio::test]
async fn kr_req_11_33_a_native_answer_before_the_recheck_wins_and_the_rich_answer_is_told_so() {
    let broker = gateway(None);
    let resource = approval(&broker, "1", 2).expect("the interpretation is accepted");

    // The component has encoded its answer. Before the rich answer reaches the recheck, the
    // person answers in the terminal and the native path takes the one admission.
    let answered = broker
        .native_answer_through(
            GatewayConnectionId::new(1),
            response("1").as_bytes(),
            TimestampMs::new(5),
            |_| Ok(()),
        )
        .expect("the native client answered first");
    assert_eq!(answered.state, PendingState::Resolved);

    // The rich answer now reaches the recheck, and there is nothing to admit.
    let refusal = answer(&broker, resource.resource_id, "allow", 6)
        .await
        .expect_err("the native answer already resolved it");
    assert_eq!(refusal.code(), ErrorCode::QuestionResolved);
    assert_eq!(
        broker
            .pending(resource.resource_id)
            .expect("the resource is still recorded")
            .state,
        PendingState::Resolved,
        "the later rich response is told the resolved state"
    );

    // The ordinary order, and the whole of it is one admission: it reserves the resource, marks
    // it, transmits it and settles it, and nothing outside it can do any of those.
    let second = approval(&broker, "2", 7).expect("another interpretation");
    let applied = answer(&broker, second.resource_id, "allow", 8)
        .await
        .expect("the upstream took it");
    assert_eq!(
        applied.mutation.provenance,
        ActionProvenance::UpstreamTypedRpc
    );
    assert_eq!(applied.state, PendingState::Resolved);
    assert_eq!(
        broker.pending(second.resource_id).expect("recorded").state,
        PendingState::Resolved
    );
}

/// KR-REQ-12.13: downstream identifiers are namespaced by connection, and one resource takes one
/// atomic response transition.
#[test]
fn kr_req_12_13_downstream_identifiers_are_namespaced_and_transition_once() {
    let broker = gateway(None);
    broker
        .register_instance(
            instance(3),
            IntegrationMode::Gateway,
            None,
            Some(managed(instance(3))),
        )
        .expect("the instance is registered");
    broker
        .pin_table(instance(3), table(), rich())
        .expect("the installed tables are pinned");
    broker
        .open_native_connection(
            instance(3),
            &CREDENTIAL,
            &process_identity(41, 900),
            &package(),
            "1",
        )
        .expect("a second native connection");

    // Both connections call their request "1". They are two resources.
    let first = broker
        .forward_native(
            GatewayConnectionId::new(1),
            frame("1", "fs/write_text_file").as_bytes(),
            TimestampMs::new(2),
        )
        .expect("forwarded")
        .1
        .expect("it expects a response");
    let second = broker
        .forward_native(
            GatewayConnectionId::new(2),
            frame("1", "fs/write_text_file").as_bytes(),
            TimestampMs::new(3),
        )
        .expect("forwarded")
        .1
        .expect("it expects a response");
    assert_ne!(first.resource_id, second.resource_id);
    assert_ne!(first.request, second.request);
    assert_eq!(first.request.upstream, second.request.upstream);

    // Answering on one connection resolves that connection's resource and not the other's.
    broker
        .native_answer_through(
            GatewayConnectionId::new(1),
            response("1").as_bytes(),
            TimestampMs::new(4),
            |_| Ok(()),
        )
        .expect("arbitrated");
    assert_eq!(
        broker.pending(first.resource_id).expect("recorded").state,
        PendingState::Resolved
    );
    assert_eq!(
        broker.pending(second.resource_id).expect("recorded").state,
        PendingState::Pending
    );

    // And a second answer to the same identifier is refused rather than applied twice.
    assert!(
        broker
            .native_answer_through(
                GatewayConnectionId::new(1),
                response("1").as_bytes(),
                TimestampMs::new(5),
                |_| Ok(()),
            )
            .is_err(),
        "one resource takes one response transition"
    );
}

/// KR-REQ-12.11: both mutators reach the upstream through the gateway, the upstream's own
/// identifiers are preserved, and a resolution is fanned out to every attached observer.
#[test]
fn kr_req_12_11_both_mutators_are_admitted_by_the_gateway_and_observers_are_listed() {
    let broker = gateway(None);
    broker
        .open_connection(instance(2), ConnectionOrigin::RichClient, &package(), "1")
        .expect("a rich client connects");
    broker
        .pin_table(instance(3), table(), rich())
        .expect("the installed tables are pinned");
    broker
        .open_connection(instance(3), ConnectionOrigin::RichClient, &package(), "1")
        .expect("a client of another instance connects");

    // The native terminal's request keeps its own identifier through the gateway.
    let native = broker
        .forward_native(
            GatewayConnectionId::new(1),
            frame("\"upstream-7\"", "fs/write_text_file").as_bytes(),
            TimestampMs::new(2),
        )
        .expect("forwarded")
        .1
        .expect("it expects a response");
    // A string identifier keeps its quotes, so it can never be the number of the same digits.
    assert_eq!(native.request.upstream.as_str(), "\"upstream-7\"");

    // The rich client's mutation goes through the same gateway, against the closed table.
    let rich_call = broker
        .admit_rich(
            GatewayConnectionId::new(2),
            &method("session/cancel"),
            UpstreamRequestId::new("upstream-8").expect("valid"),
        )
        .expect("a listed rich method is admitted");
    assert_eq!(rich_call.request.upstream.as_str(), "upstream-8");
    assert_eq!(rich_call.entry.required_right, ActionRight::AgentCancel);
    assert!(
        broker
            .admit_rich(
                GatewayConnectionId::new(2),
                &method("vendor/undocumented"),
                UpstreamRequestId::new("upstream-9").expect("valid"),
            )
            .is_err(),
        "an unknown rich mutation is rejected"
    );

    // The observers of this instance are its own, and no other instance's.
    assert_eq!(
        broker.observers(instance(2)),
        vec![GatewayConnectionId::new(1), GatewayConnectionId::new(2)]
    );
    assert_eq!(
        broker.observers(instance(3)),
        vec![GatewayConnectionId::new(3)]
    );
}

/// KR-REQ-12.13: a JSON-RPC identifier is a string or a number, and the two are not the same
/// identifier. A response also has to be a response: a frame naming a method is a request, and a
/// request must never resolve the resource whose identifier it happens to carry.
#[test]
fn kr_req_12_13_an_identifier_keeps_its_json_type_and_a_request_resolves_nothing() {
    let broker = gateway(None);
    let number = broker
        .forward_native(
            GatewayConnectionId::new(1),
            frame("11", "fs/write_text_file").as_bytes(),
            TimestampMs::new(2),
        )
        .expect("forwarded")
        .1
        .expect("it expects a response");
    let text = broker
        .forward_native(
            GatewayConnectionId::new(1),
            frame("\"11\"", "fs/write_text_file").as_bytes(),
            TimestampMs::new(3),
        )
        .expect("forwarded")
        .1
        .expect("it expects a response");
    assert_ne!(
        number.request, text.request,
        "the number 11 and the string \"11\" are two upstream requests"
    );
    assert_eq!(number.request.upstream.as_str(), "11");
    assert_eq!(text.request.upstream.as_str(), "\"11\"");
    assert_ne!(number.resource_id, text.resource_id);

    // The upstream answers the numeric one. The string one is untouched.
    let answered = broker
        .native_answer_through(
            GatewayConnectionId::new(1),
            response("11").as_bytes(),
            TimestampMs::new(4),
            |_| Ok(()),
        )
        .expect("the response correlates");
    assert_eq!(answered.resource_id, number.resource_id);
    assert_eq!(
        broker
            .pending(text.resource_id)
            .expect("the string request is still held")
            .state,
        PendingState::Pending
    );

    // A second request that carries a live identifier is still a request.
    assert!(
        broker
            .native_answer_through(
                GatewayConnectionId::new(1),
                frame("\"11\"", "fs/write_text_file").as_bytes(),
                TimestampMs::new(5),
                |_| Ok(()),
            )
            .is_err(),
        "a frame that names a method is a request and resolves nothing"
    );
    // And a frame that says neither that it succeeded nor that it failed is not an answer, nor is
    // one that says both.
    for not_a_response in [
        r#"{"id":"11"}"#,
        r#"{"id":"11","result":{"outcome":"allow"},"error":{"code":-1}}"#,
    ] {
        assert!(
            broker
                .native_answer_through(
                    GatewayConnectionId::new(1),
                    not_a_response.as_bytes(),
                    TimestampMs::new(6),
                    |_| Ok(()),
                )
                .is_err(),
            "a response names exactly one of its result and its error"
        );
    }
    assert_eq!(
        broker
            .pending(text.resource_id)
            .expect("the string request is still held")
            .state,
        PendingState::Pending,
        "nothing a request could not answer moved it"
    );
    // An error member that reports no failure is not a failure either.
    for not_a_failure in [
        r#"{"id":"11","error":null}"#,
        r#"{"id":"11","error":{}}"#,
        r#"{"id":"11","error":{"code":-32601}}"#,
        r#"{"id":"11","error":{"message":"no such method"}}"#,
        r#"{"id":"11","error":{"code":"-32601","message":"no such method"}}"#,
        r#"{"id":"11","error":{"code":-3.5,"message":"no such method"}}"#,
        // Whole, and outside the range a code is read into.
        r#"{"id":"11","error":{"code":9223372036854775808,"message":"no such method"}}"#,
    ] {
        assert!(
            broker
                .native_answer_through(
                    GatewayConnectionId::new(1),
                    not_a_failure.as_bytes(),
                    TimestampMs::new(7),
                    |_| Ok(()),
                )
                .is_err(),
            "an error carries a code and a message or it resolves nothing"
        );
    }
    assert_eq!(
        broker
            .pending(text.resource_id)
            .expect("the string request is still held")
            .state,
        PendingState::Pending
    );

    // An integer is an integer however it is spelled, so refusing one of these would leave a
    // resource pending on a real answer. The rule itself is exercised in full by the gateway's
    // own unit test.
    for (id, spelling) in [
        (
            "21",
            r#"{"id":21,"error":{"code":-9223372036854775808,"message":"no such method"}}"#,
        ),
        (
            "22",
            r#"{"id":22,"error":{"code":-32601.0,"message":"no such method"}}"#,
        ),
        (
            "23",
            r#"{"id":23,"error":{"code":-3.2601e4,"message":"no such method"}}"#,
        ),
        (
            "24",
            r#"{"id":24,"error":{"code":-0,"message":"no such method"}}"#,
        ),
    ] {
        let opened = broker
            .forward_native(
                GatewayConnectionId::new(1),
                frame(id, "fs/write_text_file").as_bytes(),
                TimestampMs::new(9),
            )
            .expect("forwarded")
            .1
            .expect("it expects a response");
        let answered = broker
            .native_answer_through(
                GatewayConnectionId::new(1),
                spelling.as_bytes(),
                TimestampMs::new(10),
                |_| Ok(()),
            )
            .unwrap_or_else(|error| panic!("an integral code is an integer: {spelling}: {error}"));
        assert_eq!(answered.resource_id, opened.resource_id);
    }

    // The upstream's own failure is an answer.
    let failed = broker
        .native_answer_through(
            GatewayConnectionId::new(1),
            r#"{"id":"11","error":{"code":-32601,"message":"no such method"}}"#.as_bytes(),
            TimestampMs::new(8),
            |_| Ok(()),
        )
        .expect("an error response correlates");
    assert_eq!(failed.resource_id, text.resource_id);
}

/// KR-REQ-12.16: a reverse filesystem or terminal request runs in the agent's own host
/// environment, under the user the agent runs as.
#[test]
fn kr_req_12_16_a_reverse_request_names_the_agents_own_environment_and_user() {
    let broker = gateway(None);
    let reverse = broker
        .reverse_request(
            GatewayConnectionId::new(1),
            UpstreamRequestId::new("11").expect("valid"),
            ReverseOperation::FilesystemWrite,
            EnvironmentId::new(Uuid::from_bytes([1; 16])),
            "ada",
        )
        .expect("the reverse request is built");
    assert_eq!(reverse.site.application_instance_id, instance(2));
    assert_eq!(reverse.site.os_user, "ada");
    assert_eq!(
        reverse.site.environment_id,
        EnvironmentId::new(Uuid::from_bytes([1; 16])),
        "the site comes from the connection, not from the request"
    );
    assert_eq!(reverse.provenance, ActionProvenance::UpstreamTypedRpc);
    assert_eq!(
        ReverseOperation::FilesystemRead.class(),
        NativeMethodClass::Observation
    );
    assert_eq!(
        ReverseOperation::Terminal.class(),
        NativeMethodClass::Mutation
    );

    // A rich client does not own an upstream, so it cannot ask this host to do anything on one's
    // behalf.
    broker
        .open_connection(instance(2), ConnectionOrigin::RichClient, &package(), "1")
        .expect("a rich client connects");
    assert!(
        broker
            .reverse_request(
                GatewayConnectionId::new(2),
                UpstreamRequestId::new("12").expect("valid"),
                ReverseOperation::Terminal,
                EnvironmentId::new(Uuid::from_bytes([1; 16])),
                "ada",
            )
            .is_err()
    );
}

/// KR-REQ-12.09: an action records how it actually reached the upstream.
#[tokio::test]
async fn kr_req_12_09_an_admitted_answer_records_the_provenance_it_reached_the_upstream_by() {
    let broker = gateway(None);
    let resource = approval(&broker, "1", 2).expect("the interpretation is accepted");
    let applied = answer(&broker, resource.resource_id, "allow", 4)
        .await
        .expect("the answer is applied");
    assert_eq!(
        applied.mutation.provenance,
        ActionProvenance::UpstreamTypedRpc,
        "an answer over the gateway's typed connection is a typed result"
    );

    // Terminal input is the provenance that cannot carry an authoritative result, and the
    // vocabulary says so rather than leaving it to a caller's judgement.
    assert!(ActionProvenance::UpstreamTypedRpc.is_authoritative());
    assert!(ActionProvenance::AuthenticatedHookResponse.is_authoritative());
    assert!(!ActionProvenance::TerminalInput.is_authoritative());
}

/// KR-REQ-11.35 and KR-REQ-11.36: `native_only_volatile` fences rich work, keeps native
/// arbitration, exposes the gap, relabels nothing, and answers `UPSTREAM_UNAVAILABLE`.
#[tokio::test]
async fn kr_req_11_35_the_fence_keeps_native_recording_and_arbitration_and_exposes_the_gap() {
    let mut store = common::SharedStore::open();
    let (broker, _upstream) = gateway_sharing(&store);
    let claimed = approval(&broker, "1", 2).expect("an interpretation before the fault");
    let untouched = approval(&broker, "4", 2).expect("another one before the fault");
    let _reserved = reserve(&broker, claimed.resource_id, "allow", 4)
        .expect("its transmission is reserved before the fault");

    // The receipt journal faults during live traffic: the store refuses an acceptance. The broker
    // reads that same condition, so its fence is up at its very next decision.
    store.fault_acceptance();
    assert_eq!(broker.mode(), GatewayMode::NativeOnlyVolatile);
    assert_eq!(
        broker.gap().expect("the gap is open").carried_pending.get(),
        1,
        "an identifier that was already claimed is carried rather than forgotten"
    );

    // Native traffic continues, and it is arbitrated in memory.
    let opaque = broker
        .forward_native(
            GatewayConnectionId::new(1),
            frame("2", "fs/write_text_file").as_bytes(),
            TimestampMs::new(6),
        )
        .expect("the native path keeps working")
        .1
        .expect("it expects a response");
    assert_eq!(opaque.durability, Durability::Volatile);
    broker
        .native_answer_through(
            GatewayConnectionId::new(1),
            response("2").as_bytes(),
            TimestampMs::new(7),
            |_| Ok(()),
        )
        .expect("the native answer is arbitrated in memory");

    // Rich work is refused, and the refusal is `UPSTREAM_UNAVAILABLE` rather than a hidden second
    // backend or a quietly downgraded answer. The forwarding half of that attempt still happens,
    // which is the whole point of the mode: the request reaches the upstream, and only the rich
    // meaning waits.
    let fenced = approval(&broker, "3", 8).expect_err("rich interpretation is fenced");
    assert_eq!(fenced.code(), ErrorCode::UpstreamUnavailable);
    let rich_refusal = broker
        .admit_rich(
            GatewayConnectionId::new(1),
            &method("session/cancel"),
            UpstreamRequestId::new("9").expect("valid"),
        )
        .expect_err("a rich mutation is fenced");
    assert_eq!(rich_refusal.code(), ErrorCode::UpstreamUnavailable);
    let answer_refusal = answer(&broker, untouched.resource_id, "allow", 9)
        .await
        .expect_err("a rich approval is fenced");
    assert_eq!(answer_refusal.code(), ErrorCode::UpstreamUnavailable);

    // The gap is exposed while it is open, and it counts what passed through it.
    let gap = broker.gap().expect("the gap is open");
    assert!(gap.is_open());
    assert_eq!(
        gap.native_requests.get(),
        2,
        "the forwarded request and the forwarding half of the fenced rich attempt"
    );
    assert_eq!(gap.native_responses.get(), 1);
    assert!(gap.fenced_rich_operations.get() >= 1);
    assert!(
        gap.reason.contains("full"),
        "the gap names what the store said: {}",
        gap.reason
    );

    // Nothing is relabelled: a rich client is still a rich client, and it still cannot forward.
    broker
        .open_connection(instance(2), ConnectionOrigin::RichClient, &package(), "1")
        .expect("a rich client connects");
    assert!(
        broker
            .forward_native(
                GatewayConnectionId::new(2),
                frame("10", "fs/write_text_file").as_bytes(),
                TimestampMs::new(10),
            )
            .is_err(),
        "no request is relabelled native to enter this path"
    );
}

/// KR-REQ-11.37: after storage recovers the gap is committed and pending identifiers are
/// reconciled with the same upstream before rich work comes back.
#[tokio::test]
async fn kr_req_11_37_recovery_commits_the_gap_and_reconciles_before_rich_work_returns() {
    let mut store = common::SharedStore::open();
    let path = store.path.clone();
    let (surviving, answered) = {
        let (broker, upstream) = gateway_sharing(&store);
        let surviving = approval(&broker, "1", 2).expect("an interpretation before the fault");
        let answered = approval(&broker, "2", 4).expect("another one");
        // An answer went before the fault and this host never recorded what came of it.
        answer_and_stop(&broker, &upstream, answered.resource_id, 6);

        store.fault_acceptance();
        assert_eq!(broker.mode(), GatewayMode::NativeOnlyVolatile);
        // Live traffic through the gap.
        broker
            .forward_native(
                GatewayConnectionId::new(1),
                frame("3", "fs/write_text_file").as_bytes(),
                TimestampMs::new(8),
            )
            .expect("the native path keeps working");

        // The broker's gap is the second half of the journal's: it is not committed while the
        // journal still calls the store faulted.
        let early = broker
            .recover(TimestampMs::new(9))
            .expect_err("the journal has not recovered yet");
        assert_eq!(early.code(), ErrorCode::UpstreamUnavailable);
        assert_eq!(broker.mode(), GatewayMode::NativeOnlyVolatile);
        store.recover_journal(9);
        broker
            .recover(TimestampMs::new(9))
            .expect("the gap is committed");
        assert_eq!(
            broker.mode(),
            GatewayMode::Recovering,
            "committing the gap is not the same as reconciling the upstream"
        );
        assert!(
            answer(&broker, surviving.resource_id, "allow", 10)
                .await
                .is_err(),
            "rich work does not come back before the pending identifiers are reconciled"
        );

        // Reconciliation with the same upstream: the request it still lists stays, and the one
        // this host answered is uncertain and is never answered again. Rich work returns with it.
        let (reconciliation, finished) = broker
            .reconcile_recovered(
                broker.recovery_generation(),
                ReconcileScope {
                    application_instance_id: instance(2),
                    connection: GatewayConnectionId::new(1),
                },
                &[Broker::downstream(
                    GatewayConnectionId::new(1),
                    UpstreamRequestId::new("1").expect("valid"),
                )],
                TimestampMs::new(11),
            )
            .expect("the reconnect reconciles");
        assert_eq!(reconciliation.still_pending, vec![surviving.resource_id]);
        assert_eq!(reconciliation.uncertain, vec![answered.resource_id]);
        assert_eq!(
            finished
                .expect("this was the last upstream that owed one")
                .to,
            GatewayMode::Normal
        );
        assert_eq!(broker.mode(), GatewayMode::Normal);
        assert!(
            broker.gap().is_none(),
            "a committed gap is no longer an open one"
        );

        // Rich work is back. The answer is given up rather than sent, so the resource stays
        // answerable and a restart has something to read back.
        let resumed = reserve(&broker, surviving.resource_id, "allow", 12)
            .expect("rich approvals work again");
        broker.abandon(&resumed);
        (surviving.resource_id, answered.resource_id)
    };

    // And what the gap committed is what a restart reads back.
    let restarted =
        Broker::open(Some(&path), session(), JournalHealth::shared()).expect("the broker reopens");
    assert_eq!(
        restarted
            .recorded(answered)
            .expect("the read succeeds")
            .expect("the answered one is recorded")
            .state,
        PendingState::Uncertain,
        "an answer that may already have landed is never answered again"
    );
    assert!(
        restarted.pending(answered).is_none(),
        "and it is not offered as something still answerable"
    );
    assert!(
        restarted.pending(surviving).is_some(),
        "the one the upstream still has comes back answerable"
    );
}

/// An unfinished recovery survives a restart, and so does the connection numbering.
///
/// A crash between committing the gap and reconciling the upstream must not leave a resource this
/// host may already have answered claimable again, and a restarted worker must not put a new
/// connection's identifiers in an old connection's namespace.
#[tokio::test]
async fn a_restart_comes_back_fenced_and_numbers_its_connections_above_what_it_wrote() {
    let mut store = common::SharedStore::open();
    let path = store.path.clone();
    let resource_id = {
        let (broker, _upstream) = gateway_sharing(&store);
        let resource = approval(&broker, "1", 2).expect("an interpretation");
        store.fault_acceptance();
        assert_eq!(broker.mode(), GatewayMode::NativeOnlyVolatile);
        store.recover_journal(5);
        broker
            .recover(TimestampMs::new(5))
            .expect("the gap is committed");
        assert_eq!(broker.mode(), GatewayMode::Recovering);
        // And here the worker dies, before any upstream said what it still holds.
        resource.resource_id
    };

    let restarted =
        Broker::open(Some(&path), session(), JournalHealth::shared()).expect("the broker reopens");
    assert_eq!(
        restarted.mode(),
        GatewayMode::Recovering,
        "a recovery this host did not finish is one it comes back in the middle of"
    );
    assert!(
        answer(&restarted, resource_id, "allow", 10).await.is_err(),
        "nothing is answerable until an upstream has been reconciled"
    );
    assert!(
        restarted.next_connection().get() > 1,
        "a new connection is numbered above every identifier this ledger holds"
    );
}

/// Rich work comes back when every upstream that owed a reconciliation has given one.
#[tokio::test]
async fn a_recovery_waits_for_every_upstream_that_owed_it_a_reconciliation() {
    let mut store = common::SharedStore::open();
    let (broker, _upstream) = gateway_built(None, store.health(), table());
    broker
        .register_instance(
            instance(3),
            IntegrationMode::Gateway,
            None,
            Some(managed(instance(3))),
        )
        .expect("the instance is registered");
    broker
        .pin_table(instance(3), table(), rich())
        .expect("the installed tables are pinned");
    broker
        .open_native_connection(
            instance(3),
            &CREDENTIAL,
            &process_identity(41, 900),
            &package(),
            "1",
        )
        .expect("a second native connection");

    let first = approval(&broker, "1", 2).expect("an interpretation");
    let second = broker
        .forward_native(
            GatewayConnectionId::new(2),
            frame("2", "fs/write_text_file").as_bytes(),
            TimestampMs::new(3),
        )
        .expect("forwarded")
        .1
        .expect("it expects a response");

    store.fault_acceptance();
    assert_eq!(broker.mode(), GatewayMode::NativeOnlyVolatile);
    store.recover_journal(5);
    broker
        .recover(TimestampMs::new(5))
        .expect("the gap is committed");

    let (_, finished) = broker
        .reconcile_recovered(
            broker.recovery_generation(),
            ReconcileScope {
                application_instance_id: instance(2),
                connection: GatewayConnectionId::new(1),
            },
            &[Broker::downstream(
                GatewayConnectionId::new(1),
                UpstreamRequestId::new("1").expect("valid"),
            )],
            TimestampMs::new(6),
        )
        .expect("the first upstream reconciles");
    assert!(
        finished.is_none(),
        "one upstream says nothing about another's pending identifiers"
    );
    assert_eq!(broker.mode(), GatewayMode::Recovering);
    assert!(
        answer(&broker, first.resource_id, "allow", 7)
            .await
            .is_err()
    );

    let (_, finished) = broker
        .reconcile_recovered(
            broker.recovery_generation(),
            ReconcileScope {
                application_instance_id: instance(3),
                connection: GatewayConnectionId::new(2),
            },
            &[Broker::downstream(
                GatewayConnectionId::new(2),
                UpstreamRequestId::new("2").expect("valid"),
            )],
            TimestampMs::new(8),
        )
        .expect("the second upstream reconciles");
    assert!(finished.is_some(), "and that was the last one that owed");
    assert_eq!(broker.mode(), GatewayMode::Normal);
    assert!(broker.pending(second.resource_id).is_some());
    answer(&broker, first.resource_id, "allow", 9)
        .await
        .expect("rich work is back");
}

/// KR-REQ-12.10: the worker's own agent, terminal and gateway request state survives a restart of
/// the process that holds it.
///
/// What this establishes is the worker half: the broker's state is in the worker's journal and
/// comes back. That a control-daemon restart does not touch the worker at all is the daemon's,
/// and `KR-ACC-006` covers it end to end.
#[test]
fn kr_req_12_10_gateway_request_state_survives_reopening_the_workers_own_journal() {
    let path = journal_path();
    let (opaque, interpreted) = {
        let broker = gateway(Some(&path));
        let opaque = broker
            .forward_native(
                GatewayConnectionId::new(1),
                frame("1", "fs/write_text_file").as_bytes(),
                TimestampMs::new(2),
            )
            .expect("forwarded")
            .1
            .expect("it expects a response");
        let interpreted = approval(&broker, "2", 3).expect("interpreted");
        broker
            .checkpoint(
                instance(2),
                kr_protocol::ids::StreamCursor::new(40),
                TimestampMs::new(5),
            )
            .expect("the adapter's cursor is recorded");
        (opaque.resource_id, interpreted.resource_id)
    };

    let restarted =
        Broker::open(Some(&path), session(), JournalHealth::shared()).expect("the broker reopens");
    let recovered_opaque = restarted
        .pending(opaque)
        .expect("the opaque request came back");
    assert_eq!(recovered_opaque.state, PendingState::Pending);
    assert!(
        !recovered_opaque.interpretation_verified,
        "an opaque request comes back opaque"
    );
    let recovered = restarted
        .pending(interpreted)
        .expect("the interpreted request came back");
    assert!(recovered.interpretation_verified);
    assert_eq!(recovered.kind, PendingKind::Approval);
    assert!(
        restarted
            .decoding(interpreted)
            .expect("the read succeeds")
            .is_some(),
        "and so did the record of whose interpretation it was"
    );
    assert_eq!(
        restarted
            .consumed_cursor(instance(2))
            .expect("the read succeeds"),
        Some(kr_protocol::ids::StreamCursor::new(40))
    );
    let _ = std::fs::remove_dir_all(path.parent().expect("a directory"));
}

/// KR-REQ-11.27 and KR-REQ-11.33: one exclusive admission carries one answer, whichever writer
/// takes it, and the second writer is refused before its bytes go.
///
/// Recording competing answers afterwards is not the contract. Section 11 gives every pending
/// resource one resolution, and a resolution is bytes reaching the upstream, so what has to be
/// impossible is the second transmission.
#[tokio::test]
async fn kr_req_11_27_one_exclusive_admission_carries_one_answer_whichever_writer_takes_it() {
    let (broker, upstream) = gateway_recording(None);

    // The rich writer takes the admission first. The native answer that follows is refused, and
    // the frame is never forwarded: the closure below would have run if it had been.
    let first = approval(&broker, "1", 2).expect("the interpretation is accepted");
    let admitted = reserve(&broker, first.resource_id, "allow", 3)
        .expect("the rich answer reserves the resource");
    let forwarded = std::cell::Cell::new(false);
    let refusal = broker
        .native_answer_through(
            GatewayConnectionId::new(1),
            response("1").as_bytes(),
            TimestampMs::new(4),
            |_| {
                forwarded.set(true);
                Ok(())
            },
        )
        .expect_err("a rich answer already holds the one admission");
    assert_eq!(refusal.code(), ErrorCode::PermissionDenied);
    assert!(
        !forwarded.get(),
        "the second answer is refused before its bytes go, not recorded after they have gone"
    );

    // The rich writer's own answer then goes, and it is the frame the core prepared for that
    // resource: it names the connection the resource was asked on and the request it answers.
    broker
        .record_approval(&admitted, TimestampMs::new(5))
        .expect("the admitted answer goes");
    let carried: Vec<UpstreamBody> = upstream
        .submitted()
        .iter()
        .map(|request| request.body.clone())
        .collect();
    let [
        UpstreamBody::Approval {
            response: prepared, ..
        },
    ] = carried.as_slice()
    else {
        panic!("one approval answer was carried");
    };
    assert_eq!(prepared.request().connection, GatewayConnectionId::new(1));
    assert_eq!(
        *prepared.request(),
        first.request,
        "the prepared answer names the resource it was admitted for"
    );

    // The other order. The native writer takes the admission, and the rich claim that reaches the
    // recheck afterwards finds nothing to claim.
    let second = approval(&broker, "2", 5).expect("another interpretation");
    let native = broker
        .admit_native_answer(
            GatewayConnectionId::new(1),
            response("2").as_bytes(),
            TimestampMs::new(6),
        )
        .expect("the native client's answer is admitted");
    assert_eq!(native.resource_id, second.resource_id);
    let taken = answer(&broker, second.resource_id, "allow", 7)
        .await
        .expect_err("the native writer holds the admission");
    assert_eq!(taken.code(), ErrorCode::QuestionResolved);
    broker
        .native_answer_sent(&native, TimestampMs::new(8))
        .expect("the native answer reached the upstream");
    assert_eq!(
        broker.pending(second.resource_id).expect("recorded").state,
        PendingState::Resolved
    );

    // And an answer whose fate nobody can establish leaves the resource uncertain rather than
    // answerable, so a reconnect never reissues it.
    let third = approval(&broker, "3", 9).expect("a third interpretation");
    let lost = broker
        .admit_native_answer(
            GatewayConnectionId::new(1),
            response("3").as_bytes(),
            TimestampMs::new(10),
        )
        .expect("admitted");
    broker
        .native_answer_uncertain(&lost, TimestampMs::new(11))
        .expect("the send failed after the marker");
    assert_eq!(
        broker.pending(third.resource_id).expect("recorded").state,
        PendingState::Uncertain
    );
}

/// KR-REQ-11.37: a reconciliation belongs to one recovery, and a scope that appears during a
/// recovery joins what it owes.
///
/// Two windows closed here. A storage failure during recovery opens a new recovery, and an
/// acknowledgement in flight from the one that failed must not finish it. And an upstream whose
/// first request arrives while the recovery is running has not said what it holds, so rich work
/// does not come back over it.
#[tokio::test]
async fn kr_req_11_37_a_reconciliation_names_its_recovery_and_a_new_scope_joins_what_it_owes() {
    let mut store = common::SharedStore::open();
    let (broker, _upstream) = gateway_sharing(&store);
    let first = approval(&broker, "1", 2).expect("interpreted");
    let also = approval(&broker, "3", 2).expect("interpreted");

    store.fault_acceptance();
    assert_eq!(broker.mode(), GatewayMode::NativeOnlyVolatile);
    store.recover_journal(4);
    broker
        .recover(TimestampMs::new(4))
        .expect("the gap is committed");
    let first_recovery = broker.recovery_generation();

    // Storage fails again during the recovery. The fence goes back over the same gap at the
    // broker's next decision, and the recovery that will close it is a new one.
    store.fault_acceptance();
    assert_eq!(broker.mode(), GatewayMode::NativeOnlyVolatile);
    assert!(
        broker.gap().expect("the gap reopened").is_open(),
        "the gap that recovery was closing is open again"
    );
    store.recover_journal(6);
    broker
        .recover(TimestampMs::new(6))
        .expect("the gap is committed again");
    let second_recovery = broker.recovery_generation();
    assert_ne!(first_recovery, second_recovery);

    // The acknowledgement prepared under the first recovery is about a moment that has passed.
    // It says the upstream holds nothing, which applied would cancel both resources; it is refused
    // before anything is written, so both the live resources and their rows are as they were.
    let live_before = broker.pending_resources();
    let rows_before: Vec<_> = [first.resource_id, also.resource_id]
        .into_iter()
        .map(|id| broker.recorded(id).expect("the ledger reads"))
        .collect();
    let stale = broker
        .reconcile_recovered(
            first_recovery,
            ReconcileScope {
                application_instance_id: instance(2),
                connection: GatewayConnectionId::new(1),
            },
            &[],
            TimestampMs::new(7),
        )
        .expect_err("a reconciliation from the recovery that failed finishes nothing");
    assert_eq!(stale.code(), ErrorCode::InvalidArgument);
    assert_eq!(
        broker.pending_resources(),
        live_before,
        "the stale list changed no live resource"
    );
    let rows_after: Vec<_> = [first.resource_id, also.resource_id]
        .into_iter()
        .map(|id| broker.recorded(id).expect("the ledger reads"))
        .collect();
    assert_eq!(rows_after, rows_before, "and no ledger row");
    assert_eq!(broker.mode(), GatewayMode::Recovering);
    assert!(
        answer(&broker, first.resource_id, "allow", 8)
            .await
            .is_err(),
        "rich work has not come back"
    );

    // A second upstream records its first request while the recovery is running. It has not said
    // what it holds either, so it joins what this recovery owes and finishing the first one does
    // not lift the fence.
    broker
        .pin_table(instance(2), table(), rich())
        .expect("the installed tables are pinned");
    broker
        .open_native_connection(
            instance(2),
            &CREDENTIAL,
            &process_identity(41, 900),
            &package(),
            "1",
        )
        .expect("a second native connection is authenticated");
    broker
        .forward_native(
            GatewayConnectionId::new(2),
            frame("7", "session/request_permission").as_bytes(),
            TimestampMs::new(9),
        )
        .expect("the native path continues through a recovery");

    let (_, waiting) = broker
        .reconcile_recovered(
            second_recovery,
            ReconcileScope {
                application_instance_id: instance(2),
                connection: GatewayConnectionId::new(1),
            },
            &[],
            TimestampMs::new(10),
        )
        .expect("the first upstream reconciles");
    assert!(
        waiting.is_none(),
        "a scope that appeared during the recovery is one the recovery owes"
    );
    assert_eq!(broker.mode(), GatewayMode::Recovering);

    let (_, finished) = broker
        .reconcile_recovered(
            second_recovery,
            ReconcileScope {
                application_instance_id: instance(2),
                connection: GatewayConnectionId::new(2),
            },
            &[],
            TimestampMs::new(11),
        )
        .expect("and the upstream that appeared reconciles too");
    assert!(finished.is_some());
    assert_eq!(broker.mode(), GatewayMode::Normal);
}

/// KR-REQ-11.25 and KR-REQ-11.30: a qualified table's digest names the protocol semantics it
/// declares, so altering framing, a classification or a reverse operation cannot keep it.
#[test]
fn kr_req_11_25_a_tables_digest_names_the_semantics_it_declares() {
    let broker = gateway(None);

    // What the core interprets frames with is what this host installed. The connection named its
    // package and presented nothing about the protocol.
    let pinned = broker
        .pinned_table(instance(2), &package())
        .expect("the installed table is held");
    assert_eq!(pinned.table, table());
    assert_eq!(
        broker
            .connection(GatewayConnectionId::new(1))
            .expect("the connection is open")
            .table,
        table(),
        "a connection is read with the installed table, not one it supplied"
    );

    // Three alterations, each keeping the qualified table's own digest. Every one of them is a
    // different instruction to the core, and every one of them is refused.
    let qualified = table();
    let mut reframed = qualified.clone();
    reframed.framing = NativeFraming::ContentLength;
    let mut reclassified = qualified.clone();
    reclassified.entries[0].class = NativeMethodClass::Observation;
    let mut reversed = qualified.clone();
    reversed.entries[0].reverse = Nullable::some(ReverseOperation::FilesystemWrite);
    for (what, altered) in [
        ("framing", reframed),
        ("a classification", reclassified),
        ("a reverse operation", reversed),
    ] {
        assert_ne!(
            altered.canonical_digest().expect("encodable"),
            qualified.digest,
            "{what} is part of what the digest covers"
        );
        let refusal = broker
            .pin_table(instance(2), altered, rich())
            .expect_err("a table whose digest is not its own content is refused");
        assert_eq!(
            refusal.code(),
            ErrorCode::UnsupportedCapability,
            "{what} altered under the qualified digest is refused"
        );
    }

    // And a package with nothing installed opens nothing.
    let refusal = broker
        .open_native_connection(
            instance(2),
            &CREDENTIAL,
            &process_identity(41, 900),
            &PluginId::new("vendor.unqualified").expect("valid"),
            "1",
        )
        .expect_err("nothing is pinned for that package");
    assert_eq!(refusal.code(), ErrorCode::PermissionDenied);
}

/// KR-REQ-11.26 and KR-REQ-12.06: restoring a connection checks every resource it retained, in
/// whichever order they are read.
#[test]
fn kr_req_11_26_a_restoration_checks_every_resource_the_connection_retained() {
    let mut stale_first = 0_usize;
    let mut stale_second = 0_usize;
    // Resources are identified by random handles, so the order a connection's retained resources
    // are read in is not the order they were created in. The refusal has to hold either way, so
    // the scenario runs until both orders have been seen.
    for _ in 0..200 {
        let broker = gateway(None);
        let connection = GatewayConnectionId::new(1);
        let current = broker
            .forward_native(
                connection,
                frame("1", "session/request_permission").as_bytes(),
                TimestampMs::new(2),
            )
            .expect("forwarded")
            .1
            .expect("it expects a response")
            .resource_id;
        // The upstream owner changes, and a request recorded after it belongs to the execution
        // that is running now.
        broker
            .advance_binding(instance(2), None, TimestampMs::new(3))
            .expect("the binding advances");
        let newer = broker
            .forward_native(
                connection,
                frame("2", "session/request_permission").as_bytes(),
                TimestampMs::new(4),
            )
            .expect("forwarded")
            .1
            .expect("it expects a response")
            .resource_id;
        broker.close_connection(connection);

        let order: Vec<_> = broker
            .pending_resources()
            .into_iter()
            .filter(|resource| resource.request.connection == connection)
            .map(|resource| resource.resource_id)
            .collect();
        assert_eq!(order.len(), 2);
        if order[0] == current {
            stale_first += 1;
        } else {
            assert_eq!(order[0], newer);
            stale_second += 1;
        }

        let refusal = broker
            .restore_native_connection(
                connection,
                instance(2),
                &CREDENTIAL,
                &process_identity(41, 900),
                &package(),
                "1",
            )
            .expect_err("a connection holding an old execution's resources is not restored");
        assert_eq!(refusal.code(), ErrorCode::PermissionDenied);
        if stale_first > 0 && stale_second > 0 {
            return;
        }
    }
    panic!("both read orders should have occurred: {stale_first} and {stale_second}");
}

/// KR-REQ-11.33 and KR-REQ-12.08: a table that declares no answer member answers nothing.
///
/// The decision goes in the member the connector's own table names. A table that names none
/// describes no way to answer its requests, and saying so at admission is what keeps the refusal
/// in front of the claim and the marker rather than behind them.
#[tokio::test]
async fn kr_req_11_33_a_table_that_names_no_answer_member_refuses_before_anything_is_marked() {
    // An installation whose table says nothing about where a decision goes.
    let mut silent = table();
    for entry in &mut silent.entries {
        entry.approval_option_field = Nullable::null();
    }
    silent.digest = silent.canonical_digest().expect("encodable");
    let (broker, upstream) = gateway_tabled(None, silent);
    let resource = approval(&broker, "1", 2).expect("the interpretation is accepted");

    let refusal = answer(&broker, resource.resource_id, "allow", 4)
        .await
        .expect_err("this table describes no way to answer its own requests");
    assert_eq!(refusal.code(), ErrorCode::UnsupportedCapability);
    assert!(
        upstream.submitted().is_empty(),
        "nothing was written for an answer this host cannot encode"
    );
    assert_eq!(
        broker
            .pending(resource.resource_id)
            .expect("recorded")
            .state,
        PendingState::Pending,
        "and the resource is left as it was found, with its reservation given back"
    );
}

/// KR-REQ-11.27: a reconnect gives back a reservation nothing was sent under.
///
/// The two halves of reconciliation are the difference the marker makes. A resource this host had
/// reserved but not marked is answerable again once the upstream says it still holds the request;
/// one it had marked is uncertain for ever.
#[tokio::test]
async fn kr_req_11_27_a_reconnect_gives_back_a_reservation_nothing_was_sent_under() {
    let (broker, upstream) = gateway_recording(None);
    let reserved = approval(&broker, "1", 2).expect("the interpretation is accepted");
    let admitted =
        reserve(&broker, reserved.resource_id, "allow", 4).expect("its transmission is reserved");
    assert_eq!(
        broker
            .pending(reserved.resource_id)
            .expect("recorded")
            .state,
        PendingState::Claimed
    );

    let reconciliation = broker
        .reconcile(
            ReconcileScope {
                application_instance_id: instance(2),
                connection: GatewayConnectionId::new(1),
            },
            &[Broker::downstream(
                GatewayConnectionId::new(1),
                UpstreamRequestId::new("1").expect("valid"),
            )],
            TimestampMs::new(6),
        )
        .expect("the reconnect reconciles");
    assert_eq!(reconciliation.released, vec![reserved.resource_id]);
    assert!(reconciliation.uncertain.is_empty());
    assert_eq!(
        broker
            .pending(reserved.resource_id)
            .expect("recorded")
            .state,
        PendingState::Pending,
        "nothing was sent under that reservation, so the resource is answerable again"
    );

    // The admission that held it settles nothing afterwards, and a fresh answer goes.
    assert!(
        broker
            .record_approval(&admitted, TimestampMs::new(7))
            .is_err()
    );
    let applied = answer(&broker, reserved.resource_id, "allow", 8)
        .await
        .expect("it is answerable");
    assert_eq!(applied.state, PendingState::Resolved);
    assert_eq!(upstream.submitted().len(), 1, "one answer went in the end");
}

/// KR-REQ-11.37, KR-REQ-11.35 and KR-REQ-11.27: a store that fails under a settlement keeps what
/// happened, and a store that fails again during recovery falls back without changing anything it
/// did not write.
///
/// The answer's marker is recorded and its bytes go; then the ledger refuses the settlement. The
/// answer did go, so it is settled in memory as a transition of the gap, behind the fence the
/// failure raised, and the recovery commits it. The store then fails again, first under the
/// recovery's own commit and then under a reconciliation: each falls back to the fence, and the
/// resource the failed reconciliation would have ended is exactly as it was, live and in its row.
#[tokio::test]
async fn kr_req_11_37_a_store_failing_under_settlement_or_recovery_keeps_what_happened_and_nothing_else()
 {
    let mut store = common::SharedStore::open();
    let (broker, upstream) = gateway_sharing(&store);
    let answered = approval(&broker, "1", 2).expect("interpreted");
    let open = approval(&broker, "2", 2).expect("interpreted");

    // The answer's marker is written and its bytes go. Then the store refuses the settlement.
    let admitted = reserve(&broker, answered.resource_id, "allow", 3).expect("admitted");
    let in_flight = broker
        .record_approval(&admitted, TimestampMs::new(3))
        .expect("the marker is written and the answer goes");
    broker
        .refuse_ledger_writes(true)
        .expect("the store is put in query-only mode");
    let settled = in_flight
        .settled(TimestampMs::new(4))
        .await
        .expect("the answer went, and that is what the caller is told");
    assert_eq!(settled.state, PendingState::Resolved);
    let live = broker.pending(answered.resource_id).expect("held");
    assert_eq!(live.state, PendingState::Resolved);
    assert_eq!(live.durability, Durability::Volatile);
    assert_eq!(
        broker
            .recorded(answered.resource_id)
            .expect("the ledger reads")
            .expect("recorded")
            .state,
        PendingState::Claimed,
        "the store has the marker and not the settlement it refused"
    );
    assert_eq!(broker.mode(), GatewayMode::NativeOnlyVolatile);
    assert!(!store.journal.health().is_healthy());
    assert_eq!(upstream.submitted().len(), 1);
    assert!(
        answer(&broker, answered.resource_id, "allow", 5)
            .await
            .is_err(),
        "an answered request is not answered again"
    );

    // Storage seems to return, and fails again under the recovery's own commit.
    store.recover_journal(10);
    let failed = broker
        .recover(TimestampMs::new(10))
        .expect_err("the store refuses the gap");
    assert_eq!(failed.code(), ErrorCode::StorageUnavailable);
    assert_eq!(broker.mode(), GatewayMode::NativeOnlyVolatile);
    assert!(
        !store.journal.health().is_healthy(),
        "and says so to the receipt path"
    );

    // It returns for real: the gap commits the settlement the store refused.
    broker
        .refuse_ledger_writes(false)
        .expect("the store takes writes again");
    store.recover_journal(11);
    broker
        .recover(TimestampMs::new(11))
        .expect("the gap is committed");
    assert_eq!(
        broker
            .recorded(answered.resource_id)
            .expect("the ledger reads")
            .expect("recorded")
            .state,
        PendingState::Resolved,
        "what happened inside the gap is what was committed"
    );

    // And fails once more, under a reconciliation that would end the open request.
    let before = (
        broker.pending(open.resource_id),
        broker.recorded(open.resource_id).expect("the ledger reads"),
    );
    broker
        .refuse_ledger_writes(true)
        .expect("the store is put in query-only mode");
    let refused = broker
        .reconcile_recovered(
            broker.recovery_generation(),
            ReconcileScope {
                application_instance_id: instance(2),
                connection: GatewayConnectionId::new(1),
            },
            &[],
            TimestampMs::new(12),
        )
        .expect_err("a reconciliation that cannot be written is not applied");
    assert_eq!(refused.code(), ErrorCode::StorageUnavailable);
    assert_eq!(broker.mode(), GatewayMode::NativeOnlyVolatile);
    assert_eq!(
        (
            broker.pending(open.resource_id),
            broker.recorded(open.resource_id).expect("the ledger reads"),
        ),
        before,
        "the open request is as it was, live and in its row"
    );

    // Rich work comes back only after the gap is committed and the upstream reconciled.
    broker
        .refuse_ledger_writes(false)
        .expect("the store takes writes again");
    store.recover_journal(13);
    broker
        .recover(TimestampMs::new(13))
        .expect("the gap is committed");
    assert!(
        answer(&broker, open.resource_id, "allow", 14)
            .await
            .is_err()
    );
    let (_, finished) = broker
        .reconcile_recovered(
            broker.recovery_generation(),
            ReconcileScope {
                application_instance_id: instance(2),
                connection: GatewayConnectionId::new(1),
            },
            &[Broker::downstream(
                GatewayConnectionId::new(1),
                UpstreamRequestId::new("2").expect("valid"),
            )],
            TimestampMs::new(15),
        )
        .expect("the upstream says what it still holds");
    assert!(finished.is_some());
    answer(&broker, open.resource_id, "allow", 16)
        .await
        .expect("rich work is back");
    assert_eq!(
        upstream.submitted().len(),
        2,
        "each request was answered once"
    );
}

/// The scope one recovery owes on this suite's one connection.
fn owed_scope() -> ReconcileScope {
    ReconcileScope {
        application_instance_id: instance(2),
        connection: GatewayConnectionId::new(1),
    }
}

/// KR-REQ-11.35 and KR-REQ-11.37: a fault the journal recovered from before the broker decided
/// anything is still the broker's gap, and one that opens during a recovery sends it back.
///
/// Nothing asks the broker anything between the journal faulting and the journal recovering, so
/// the condition is healthy again by the time the broker next looks. The work it carried in
/// between went unrecorded all the same: it enters the fence it missed, commits the gap and owes
/// the upstream a reconciliation. A second fault that opens and recovers while that recovery is
/// running, again unseen, sends the recovery back to the fence under a new generation, and the
/// reconciliation prepared under the old one is refused.
#[tokio::test]
async fn kr_req_11_37_a_fault_the_broker_never_saw_is_still_its_gap_and_its_recovery_falls_back() {
    let mut store = common::SharedStore::open();
    let (broker, _upstream) = gateway_sharing(&store);
    let held = approval(&broker, "1", 2).expect("an interpretation before the fault");
    let still_open = [Broker::downstream(
        GatewayConnectionId::new(1),
        UpstreamRequestId::new("1").expect("valid"),
    )];

    store.fault_acceptance();
    store.recover_journal(3);
    assert_eq!(
        broker.mode(),
        GatewayMode::NativeOnlyVolatile,
        "the fault the broker did not see is the first thing it applies"
    );
    assert_eq!(
        broker
            .pending(held.resource_id)
            .expect("still held")
            .durability,
        Durability::Volatile,
        "and what it held lived through the gap"
    );
    let first = broker
        .recover(TimestampMs::new(4))
        .expect("the gap is committed");
    assert_eq!(first.to, GatewayMode::Recovering);
    assert_eq!(
        broker.recorded_gaps().expect("the ledger reads").len(),
        1,
        "the interval is written down"
    );

    store.fault_acceptance();
    store.recover_journal(5);
    assert_eq!(
        broker.mode(),
        GatewayMode::NativeOnlyVolatile,
        "a fault inside the recovery sends it back, seen or not"
    );
    assert!(broker.recovery_generation() > first.generation);
    let stale = broker
        .reconcile_recovered(
            first.generation,
            owed_scope(),
            &still_open,
            TimestampMs::new(6),
        )
        .expect_err("a reconciliation prepared under the recovery that fell back");
    assert_eq!(stale.code(), ErrorCode::InvalidArgument);
    assert_eq!(
        broker.pending(held.resource_id).expect("still held").state,
        PendingState::Pending,
        "and it changed nothing"
    );

    let second = broker
        .recover(TimestampMs::new(7))
        .expect("the gap is committed again");
    let (reconciliation, finished) = broker
        .reconcile_recovered(
            second.generation,
            owed_scope(),
            &still_open,
            TimestampMs::new(8),
        )
        .expect("the upstream says what it still holds");
    assert_eq!(reconciliation.still_pending, vec![held.resource_id]);
    assert_eq!(
        finished.map(|finished| finished.to),
        Some(GatewayMode::Normal)
    );
    assert_eq!(
        broker.recorded_gaps().expect("the ledger reads").len(),
        1,
        "the second fault reopened the same interval rather than opening another"
    );
}

/// KR-REQ-11.35: native work goes on while a recovery writes the gap, and what it did is in what
/// the recovery commits.
///
/// The recovery is held twice over. First at its own pause, after it has read the gap and let the
/// broker's lock go, and then by the store itself: another connection holds the database's write
/// lock, and the recovery's own connection announces when it has begun waiting for that lock.
/// Native work is carried at both points, the second only once that wait has begun. The recovery
/// then finds the gap changed, writes it again, and leaves the fence only with that work committed.
#[tokio::test]
async fn kr_req_11_35_native_work_goes_on_while_a_recovery_is_held_at_its_write() {
    let mut store = common::SharedStore::open();
    let (broker, _upstream) = gateway_sharing(&store);
    let broker = std::sync::Arc::new(broker);
    let held = approval(&broker, "1", 2).expect("an interpretation before the fault");
    store.fault_acceptance();
    store.recover_journal(3);

    let holder = rusqlite::Connection::open(&store.path).expect("the store opens");
    holder
        .execute_batch("BEGIN IMMEDIATE")
        .expect("the write lock is taken");
    let waiting = broker
        .announce_when_a_recovery_waits_for_the_store()
        .expect("the recovery has a connection of its own");
    let (arrived, release) = broker.pause_before_recovery_write();
    let recovering = {
        let broker = std::sync::Arc::clone(&broker);
        std::thread::spawn(move || broker.recover(TimestampMs::new(4)))
    };
    arrived
        .recv_timeout(common::LIVENESS_DEADLINE)
        .expect("the recovery reaches its write");

    // At its write, with the broker's lock released: a new request is recorded and arbitrated.
    let (_, arrived_meanwhile) = broker
        .forward_native(
            GatewayConnectionId::new(1),
            frame("2", "session/request_permission").as_bytes(),
            TimestampMs::new(5),
        )
        .expect("native work goes on while the recovery waits to write");
    let arrived_meanwhile = arrived_meanwhile.expect("it expects a response");
    release.send(()).expect("the recovery goes on");
    waiting
        .recv_timeout(common::LIVENESS_DEADLINE)
        .expect("the recovery's write waits for the store");

    // In its write, which the store holds up: the upstream withdraws its first request.
    broker
        .upstream_resolved(&held.request, TimestampMs::new(6))
        .expect("native work goes on while the store holds the recovery's write");
    assert!(
        !recovering.is_finished(),
        "the recovery cannot finish while the store holds its write"
    );
    holder
        .execute_batch("ROLLBACK")
        .expect("the write lock is let go");
    let recovered = recovering
        .join()
        .expect("the recovery is joined")
        .expect("the gap is committed");
    assert_eq!(recovered.to, GatewayMode::Recovering);

    // What native work did while the gap was being written is what the recovery committed.
    let recorded = broker
        .recorded(arrived_meanwhile.resource_id)
        .expect("the ledger reads")
        .expect("the request recorded during the write is committed");
    assert_eq!(recorded.durability, Durability::Volatile);
    assert_eq!(recorded.state, PendingState::Pending);
    assert_eq!(
        broker
            .recorded(held.resource_id)
            .expect("the ledger reads")
            .expect("the withdrawn request is committed")
            .state,
        PendingState::Cancelled,
        "and so is the withdrawal made while the store held the write"
    );
}

/// KR-REQ-11.35, KR-REQ-11.36 and KR-REQ-11.37: while the fence is up nothing that needs its
/// record is taken, and nothing that holds the broker's lock writes to the store.
///
/// A component bound, a grant changed, an adapter's checkpoint and an ordinary reconciliation all
/// need their record, and the store is what failed. Each is refused before the store is reached,
/// so an empty list from an upstream cancels nothing, and each is taken again once the recovery
/// is complete.
#[tokio::test]
async fn kr_req_11_37_nothing_that_needs_its_record_is_taken_while_the_fence_is_up() {
    let mut store = common::SharedStore::open();
    let (broker, _upstream) = gateway_sharing(&store);
    let held = approval(&broker, "1", 2).expect("an interpretation before the fault");
    store.fault_acceptance();
    assert_eq!(broker.mode(), GatewayMode::NativeOnlyVolatile);

    let bind = |at: u64| {
        broker.bind(
            binding(10),
            instance(2),
            PluginId::new("kalareach.other").expect("valid"),
            PublisherId::new("kalareach").expect("valid"),
            Digest256::from_bytes([6; 32]),
            BrokerGrants::granted([BrokerGrant::ApprovalInterpreter]),
            None,
            TimestampMs::new(at),
        )
    };
    let fenced = |outcome: Result<(), BrokerError>, what: &str| {
        let error = outcome.expect_err(what);
        assert!(
            matches!(error, BrokerError::LedgerUnavailable { .. }),
            "{what} is refused because nothing can be recorded: {error}"
        );
        assert_eq!(error.code(), ErrorCode::StorageUnavailable);
    };
    fenced(bind(3), "binding a component");
    assert!(
        broker.binding_record(binding(10)).is_none(),
        "and nothing was bound"
    );
    fenced(
        broker.withdraw_grant(binding(9), BrokerGrant::ApprovalInterpreter),
        "changing a grant",
    );
    assert!(
        broker
            .binding_record(binding(9))
            .expect("still bound")
            .grants
            .holds(BrokerGrant::ApprovalInterpreter),
        "and the grant is as it was"
    );
    fenced(
        broker.checkpoint(
            instance(2),
            kr_protocol::ids::StreamCursor::new(1),
            TimestampMs::new(3),
        ),
        "an adapter checkpoint",
    );
    fenced(
        broker
            .reconcile(owed_scope(), &[], TimestampMs::new(3))
            .map(|_| ()),
        "an ordinary reconciliation",
    );
    assert_eq!(
        broker.pending(held.resource_id).expect("still held").state,
        PendingState::Pending,
        "and the empty list cancelled nothing"
    );

    store.recover_journal(4);
    broker
        .recover(TimestampMs::new(4))
        .expect("the gap is committed");
    let (_, finished) = broker
        .reconcile_recovered(
            broker.recovery_generation(),
            owed_scope(),
            &[Broker::downstream(
                GatewayConnectionId::new(1),
                UpstreamRequestId::new("1").expect("valid"),
            )],
            TimestampMs::new(5),
        )
        .expect("the upstream says what it still holds");
    assert!(finished.is_some());
    bind(6).expect("a component is bound once the recovery is complete");
    broker
        .checkpoint(
            instance(2),
            kr_protocol::ids::StreamCursor::new(1),
            TimestampMs::new(6),
        )
        .expect("and an adapter's checkpoint is written");
}

/// KR-REQ-11.35 and KR-REQ-11.37: a recovery finishes without waiting for a store another
/// connection is writing, and without calling that store failed.
///
/// Finishing takes the broker's lock, because the finish and the fence coming down are one
/// decision. Another connection holds the database's write lock, so the finish cannot be written:
/// it is refused at once rather than after the busy timeout, nothing is reported to the journal
/// condition, and the broker stays recovering. Once the store is free, the next pass finishes.
#[tokio::test]
async fn kr_req_11_37_a_recovery_finishes_without_waiting_for_a_busy_store() {
    let mut store = common::SharedStore::open();
    let (broker, _upstream) = gateway_sharing(&store);
    approval(&broker, "1", 2).expect("an interpretation before the fault");
    store.fault_acceptance();
    store.recover_journal(3);
    broker
        .recover(TimestampMs::new(4))
        .expect("the gap is committed");
    assert_eq!(broker.mode(), GatewayMode::Recovering);

    let holder = rusqlite::Connection::open(&store.path).expect("the store opens");
    holder
        .execute_batch("BEGIN IMMEDIATE")
        .expect("the write lock is taken");
    assert!(
        broker.reconcile_connected(TimestampMs::new(5)).is_none(),
        "the finish is not written while another connection holds the store"
    );
    assert!(
        store.health().is_healthy(),
        "a busy store is not a failed one: had the finish waited out the busy timeout, the store \
         would have been reported failed"
    );
    assert_eq!(
        broker.mode(),
        GatewayMode::Recovering,
        "and the broker is still recovering"
    );
    holder
        .execute_batch("ROLLBACK")
        .expect("the write lock is let go");

    let finished = broker
        .reconcile_connected(TimestampMs::new(6))
        .expect("the next pass finishes");
    assert_eq!(finished.to, GatewayMode::Normal);
    assert_eq!(
        broker.recorded_gaps().expect("the ledger reads").len(),
        1,
        "with the gap's final accounting written"
    );
}
