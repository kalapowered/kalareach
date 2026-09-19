//! The gateway core, the native proxy contract and volatile-native mode.
//!
//! Each test is named for the requirement row it closes. Where a test establishes less than its
//! row asks for, the name says what it does establish and the comment says what is left and who
//! owns it.

use kr_protocol::broker::{
    ActionProvenance, BrokerGrant, BrokerGrants, DecodedProjection, DecodingTrust, IntegrationMode,
    OfferedDecision,
};
use kr_protocol::error::ErrorCode;
use kr_protocol::gateway::{
    DeclarativeEntry, DeclarativeTable, GatewayMode, NativeFraming, NativeMethodClass, PendingKind,
    PendingState, ReverseOperation, RichMethodEntry, RichMethodTable,
};
use kr_protocol::identity::{ProcessStartIdentity, ProcessStartSource};
use kr_protocol::ids::{
    ActorId, ApplicationInstanceId, BrokerBindingId, EnvironmentId, GatewayConnectionId,
    MethodTableVersion, PluginId, PublisherId, SessionId, UpstreamMethod, UpstreamRequestId,
};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{Digest256, TimestampMs, U64, Uuid};
use kr_protocol::session::Durability;
use kr_worker::broker::{
    Broker, BrokerError, BrokerTransport, ConnectionOrigin, Credential, ManagedProcess,
    ReconcileScope, TransportHandle,
};

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

fn table() -> DeclarativeTable {
    DeclarativeTable {
        plugin_id: PluginId::new("kalareach.codex").expect("valid"),
        publisher_id: PublisherId::new("kalareach").expect("valid"),
        table_version: MethodTableVersion::new(1),
        upstream_protocol_version: "1".to_owned(),
        digest: Digest256::from_bytes([1; 32]),
        framing: NativeFraming::JsonLines,
        request_id_field: "id".to_owned(),
        response_id_field: "id".to_owned(),
        method_field: "method".to_owned(),
        result_field: "result".to_owned(),
        error_field: "error".to_owned(),
        entries: vec![
            DeclarativeEntry {
                method: method("fs/write_text_file"),
                class: NativeMethodClass::Mutation,
                expects_response: true,
            },
            DeclarativeEntry {
                method: method("session/request_permission"),
                class: NativeMethodClass::Mutation,
                expects_response: true,
            },
            DeclarativeEntry {
                method: method("session/update"),
                class: NativeMethodClass::Observation,
                expects_response: false,
            },
        ],
    }
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
                provenance: ActionProvenance::UpstreamTypedRpc,
            },
            RichMethodEntry {
                method: method("session/set_provider_key"),
                class: NativeMethodClass::Unsupported,
                required_right: ActionRight::AgentPrompt,
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
fn gateway(path: Option<&std::path::Path>) -> Broker {
    let broker = Broker::open(path, session()).expect("the broker opens");
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
        .open_native_connection(
            GatewayConnectionId::new(1),
            instance(2),
            &CREDENTIAL,
            &process_identity(41, 900),
            table(),
            rich(),
            "1",
        )
        .expect("the native connection is authenticated");
    broker
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
        .native_answer(
            GatewayConnectionId::new(1),
            response("2").as_bytes(),
            TimestampMs::new(6),
        )
        .expect("the native answer is arbitrated");
    assert_eq!(answered.state, PendingState::Cancelled);

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
        .open_connection(
            GatewayConnectionId::new(2),
            instance(2),
            ConnectionOrigin::RichClient,
            table(),
            rich(),
            "1",
        )
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
        .open_connection(
            GatewayConnectionId::new(3),
            instance(2),
            ConnectionOrigin::Component,
            table(),
            rich(),
            "1",
        )
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
                GatewayConnectionId::new(4),
                instance(2),
                &[8; 32],
                &process_identity(41, 900),
                table(),
                rich(),
                "1",
            )
            .is_err(),
        "an environment variable that leaked is not a launch binding"
    );
    assert!(
        broker
            .open_native_connection(
                GatewayConnectionId::new(5),
                instance(2),
                &CREDENTIAL,
                &process_identity(42, 900),
                table(),
                rich(),
                "1",
            )
            .is_err(),
        "the private exchange without the process binding is not enough either"
    );
}

/// KR-REQ-11.33: the encode, recheck, claim and dispatch transaction, and a native answer that
/// arrives during encoding wins.
#[test]
fn kr_req_11_33_a_native_answer_before_the_recheck_wins_and_the_rich_answer_is_told_so() {
    let broker = gateway(None);
    let resource = approval(&broker, "1", 2).expect("the interpretation is accepted");

    // The component has encoded its answer. Before the rich answer reaches the recheck, the
    // upstream answers itself.
    let answered = broker
        .native_answer(
            GatewayConnectionId::new(1),
            response("1").as_bytes(),
            TimestampMs::new(5),
        )
        .expect("the upstream answered its own request");
    assert_eq!(answered.state, PendingState::Cancelled);

    // The rich answer now reaches the recheck, and there is nothing to claim.
    let refusal = broker
        .claim(
            resource.resource_id,
            &actor("device-1"),
            TimestampMs::new(6),
        )
        .expect_err("the native answer already resolved it");
    assert_eq!(refusal.code(), ErrorCode::QuestionResolved);
    assert_eq!(
        broker
            .pending(resource.resource_id)
            .expect("the resource is still recorded")
            .state,
        PendingState::Cancelled,
        "the later rich response is told the resolved state"
    );

    // The ordinary order: claim, then admit the dispatch, then resolve.
    let second = approval(&broker, "2", 7).expect("another interpretation");
    let claim = broker
        .claim(second.resource_id, &actor("device-1"), TimestampMs::new(8))
        .expect("claimed");
    let admission = broker
        .admit_dispatch(&claim, "allow")
        .expect("the answer is admitted");
    assert_eq!(admission.provenance, ActionProvenance::UpstreamTypedRpc);
    broker
        .resolve(&claim, TimestampMs::new(9))
        .expect("the upstream confirmed it");
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
        .open_native_connection(
            GatewayConnectionId::new(2),
            instance(3),
            &CREDENTIAL,
            &process_identity(41, 900),
            table(),
            rich(),
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
        .native_answer(
            GatewayConnectionId::new(1),
            response("1").as_bytes(),
            TimestampMs::new(4),
        )
        .expect("arbitrated");
    assert_eq!(
        broker.pending(first.resource_id).expect("recorded").state,
        PendingState::Cancelled
    );
    assert_eq!(
        broker.pending(second.resource_id).expect("recorded").state,
        PendingState::Pending
    );

    // And a second answer to the same identifier is refused rather than applied twice.
    assert!(
        broker
            .native_answer(
                GatewayConnectionId::new(1),
                response("1").as_bytes(),
                TimestampMs::new(5),
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
        .open_connection(
            GatewayConnectionId::new(2),
            instance(2),
            ConnectionOrigin::RichClient,
            table(),
            rich(),
            "1",
        )
        .expect("a rich client connects");
    broker
        .open_connection(
            GatewayConnectionId::new(3),
            instance(3),
            ConnectionOrigin::RichClient,
            table(),
            rich(),
            "1",
        )
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
        .native_answer(
            GatewayConnectionId::new(1),
            response("11").as_bytes(),
            TimestampMs::new(4),
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
            .native_answer(
                GatewayConnectionId::new(1),
                frame("\"11\"", "fs/write_text_file").as_bytes(),
                TimestampMs::new(5),
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
                .native_answer(
                    GatewayConnectionId::new(1),
                    not_a_response.as_bytes(),
                    TimestampMs::new(6),
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
        // Parsing has already rounded these, so the code this host would report is not the code
        // the upstream wrote.
        r#"{"id":"11","error":{"code":-32601.0,"message":"no such method"}}"#,
        r#"{"id":"11","error":{"code":1.00000000000000001,"message":"no such method"}}"#,
        r#"{"id":"11","error":{"code":1e-400,"message":"no such method"}}"#,
    ] {
        assert!(
            broker
                .native_answer(
                    GatewayConnectionId::new(1),
                    not_a_failure.as_bytes(),
                    TimestampMs::new(7),
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

    // A code beyond a signed 64-bit word is still an integer, and refusing it would leave a
    // resource pending on a real answer.
    for (id, spelling) in [
        (
            "21",
            r#"{"id":21,"error":{"code":-9223372036854775808,"message":"no such method"}}"#,
        ),
        (
            "22",
            r#"{"id":22,"error":{"code":9223372036854775808,"message":"no such method"}}"#,
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
            .native_answer(
                GatewayConnectionId::new(1),
                spelling.as_bytes(),
                TimestampMs::new(10),
            )
            .unwrap_or_else(|error| panic!("an integral code is an integer: {spelling}: {error}"));
        assert_eq!(answered.resource_id, opened.resource_id);
    }

    // The upstream's own failure is an answer.
    let failed = broker
        .native_answer(
            GatewayConnectionId::new(1),
            r#"{"id":"11","error":{"code":-32601,"message":"no such method"}}"#.as_bytes(),
            TimestampMs::new(8),
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
        .open_connection(
            GatewayConnectionId::new(2),
            instance(2),
            ConnectionOrigin::RichClient,
            table(),
            rich(),
            "1",
        )
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
#[test]
fn kr_req_12_09_an_admitted_answer_records_the_provenance_it_reached_the_upstream_by() {
    let broker = gateway(None);
    let resource = approval(&broker, "1", 2).expect("the interpretation is accepted");
    let claim = broker
        .claim(
            resource.resource_id,
            &actor("device-1"),
            TimestampMs::new(4),
        )
        .expect("claimed");
    let admission = broker
        .admit_dispatch(&claim, "allow")
        .expect("the answer is admitted");
    assert_eq!(
        admission.provenance,
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
#[test]
fn kr_req_11_35_the_fence_keeps_native_recording_and_arbitration_and_exposes_the_gap() {
    let broker = gateway(None);
    let claimed = approval(&broker, "1", 2).expect("an interpretation before the fault");
    broker
        .claim(claimed.resource_id, &actor("device-1"), TimestampMs::new(4))
        .expect("claimed before the fault");

    // The journal faults during live traffic.
    let transition = broker
        .enter_volatile("the journal could not be written", TimestampMs::new(5))
        .expect("the fence is entered");
    assert_eq!(transition.to, GatewayMode::NativeOnlyVolatile);
    assert_eq!(
        transition.gap.carried_pending.get(),
        1,
        "an identifier that was already claimed is carried rather than forgotten"
    );
    assert_eq!(broker.mode(), GatewayMode::NativeOnlyVolatile);

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
        .native_answer(
            GatewayConnectionId::new(1),
            response("2").as_bytes(),
            TimestampMs::new(7),
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
    let claim_refusal = broker
        .claim(claimed.resource_id, &actor("device-2"), TimestampMs::new(9))
        .expect_err("a rich approval is fenced");
    assert_eq!(claim_refusal.code(), ErrorCode::UpstreamUnavailable);

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
    assert!(gap.reason.contains("journal"));

    // Nothing is relabelled: a rich client is still a rich client, and it still cannot forward.
    broker
        .open_connection(
            GatewayConnectionId::new(2),
            instance(2),
            ConnectionOrigin::RichClient,
            table(),
            rich(),
            "1",
        )
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
#[test]
fn kr_req_11_37_recovery_commits_the_gap_and_reconciles_before_rich_work_returns() {
    let path = journal_path();
    let (surviving, answered) = {
        let broker = gateway(Some(&path));
        let surviving = approval(&broker, "1", 2).expect("an interpretation before the fault");
        let answered = approval(&broker, "2", 4).expect("another one");
        let claim = broker
            .claim(
                answered.resource_id,
                &actor("device-1"),
                TimestampMs::new(6),
            )
            .expect("claimed");
        broker
            .admit_dispatch(&claim, "allow")
            .expect("an answer went before the fault");

        broker
            .enter_volatile("the journal could not be written", TimestampMs::new(7))
            .expect("the fence is entered");
        // Live traffic through the gap.
        broker
            .forward_native(
                GatewayConnectionId::new(1),
                frame("3", "fs/write_text_file").as_bytes(),
                TimestampMs::new(8),
            )
            .expect("the native path keeps working");

        broker
            .recover(TimestampMs::new(9))
            .expect("the gap is committed");
        assert_eq!(
            broker.mode(),
            GatewayMode::Recovering,
            "committing the gap is not the same as reconciling the upstream"
        );
        assert!(
            broker
                .claim(
                    surviving.resource_id,
                    &actor("device-1"),
                    TimestampMs::new(10)
                )
                .is_err(),
            "rich work does not come back before the pending identifiers are reconciled"
        );

        // Reconciliation with the same upstream: the request it still lists stays, and the one
        // this host answered is uncertain and is never answered again. Rich work returns with it.
        let (reconciliation, finished) = broker
            .reconcile_recovered(
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

        // Rich work is back.
        broker
            .claim(
                surviving.resource_id,
                &actor("device-1"),
                TimestampMs::new(12),
            )
            .expect("rich approvals work again");
        (surviving.resource_id, answered.resource_id)
    };

    // And what the gap committed is what a restart reads back.
    let restarted = Broker::open(Some(&path), session()).expect("the broker reopens");
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
    let _ = std::fs::remove_dir_all(path.parent().expect("a directory"));
}

/// An unfinished recovery survives a restart, and so does the connection numbering.
///
/// A crash between committing the gap and reconciling the upstream must not leave a resource this
/// host may already have answered claimable again, and a restarted worker must not put a new
/// connection's identifiers in an old connection's namespace.
#[test]
fn a_restart_comes_back_fenced_and_numbers_its_connections_above_what_it_wrote() {
    let path = journal_path();
    let resource_id = {
        let broker = gateway(Some(&path));
        let resource = approval(&broker, "1", 2).expect("an interpretation");
        broker
            .enter_volatile("the journal could not be written", TimestampMs::new(4))
            .expect("the fence is entered");
        broker
            .recover(TimestampMs::new(5))
            .expect("the gap is committed");
        assert_eq!(broker.mode(), GatewayMode::Recovering);
        // And here the worker dies, before any upstream said what it still holds.
        resource.resource_id
    };

    let restarted = Broker::open(Some(&path), session()).expect("the broker reopens");
    assert_eq!(
        restarted.mode(),
        GatewayMode::Recovering,
        "a recovery this host did not finish is one it comes back in the middle of"
    );
    assert!(
        restarted
            .claim(resource_id, &actor("device-1"), TimestampMs::new(10))
            .is_err(),
        "nothing is claimable until an upstream has been reconciled"
    );
    assert!(
        restarted.next_connection().get() > 1,
        "a new connection is numbered above every identifier this ledger holds"
    );
    let _ = std::fs::remove_dir_all(path.parent().expect("a directory"));
}

/// Rich work comes back when every upstream that owed a reconciliation has given one.
#[test]
fn a_recovery_waits_for_every_upstream_that_owed_it_a_reconciliation() {
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
        .open_native_connection(
            GatewayConnectionId::new(2),
            instance(3),
            &CREDENTIAL,
            &process_identity(41, 900),
            table(),
            rich(),
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

    broker
        .enter_volatile("the journal could not be written", TimestampMs::new(4))
        .expect("the fence is entered");
    broker
        .recover(TimestampMs::new(5))
        .expect("the gap is committed");

    let (_, finished) = broker
        .reconcile_recovered(
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
        broker
            .claim(first.resource_id, &actor("device-1"), TimestampMs::new(7))
            .is_err()
    );

    let (_, finished) = broker
        .reconcile_recovered(
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
    broker
        .claim(first.resource_id, &actor("device-1"), TimestampMs::new(9))
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

    let restarted = Broker::open(Some(&path), session()).expect("the broker reopens");
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
