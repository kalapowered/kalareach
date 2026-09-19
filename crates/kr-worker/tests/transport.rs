//! The worker-owned transport that drives the gateway, over a real bound endpoint.
//!
//! Every test here starts a listener the host actually binds and connects real sockets to it, so
//! what is established is the path rather than the decision: a frame is read off a socket,
//! classified by the connection's own qualified table, recorded, forwarded, answered, and the
//! answer is read back off the other socket.

use std::sync::Arc;

use kr_protocol::broker::{
    BrokerGrant, BrokerGrants, DecodedProjection, DecodingTrust, IntegrationMode, OfferedDecision,
};
use kr_protocol::gateway::{
    DeclarativeEntry, DeclarativeTable, NativeFraming, NativeMethodClass, PendingState,
    ReverseOperation, RichMethodEntry, RichMethodTable, RichOperation,
};
use kr_protocol::identity::{ProcessStartIdentity, ProcessStartSource};
use kr_protocol::ids::{
    ActorId, ApplicationInstanceId, BrokerBindingId, EnvironmentId, GatewayConnectionId,
    MethodTableVersion, PluginId, PublisherId, SessionId, UpstreamMethod,
};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{Digest256, Nullable, TimestampMs, U64, Uuid};
use kr_worker::broker::{
    BoundEndpoint, Broker, BrokerTransport, Credential, Framing, Link, ManagedProcess,
    TransportHandle,
};
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _};

const CREDENTIAL: [u8; 32] = [9; 32];

fn session() -> SessionId {
    SessionId::new(Uuid::from_bytes([1; 16]))
}

fn instance() -> ApplicationInstanceId {
    ApplicationInstanceId::new(Uuid::from_bytes([2; 16]))
}

fn binding() -> BrokerBindingId {
    BrokerBindingId::new(Uuid::from_bytes([9; 16]))
}

fn method(name: &str) -> UpstreamMethod {
    UpstreamMethod::new(name).expect("valid")
}

fn process_identity() -> ProcessStartIdentity {
    ProcessStartIdentity::new(41, ProcessStartSource::MacosProcBsdInfo, 900)
}

fn managed() -> ManagedProcess {
    ManagedProcess::new(
        instance(),
        process_identity(),
        TransportHandle {
            transport: BrokerTransport::PrivateSocket,
            application_instance_id: instance(),
            executable_digest: Digest256::from_bytes([3; 32]),
            process: process_identity(),
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

fn target() -> kr_protocol::agent::AgentMutationTarget {
    kr_protocol::agent::AgentMutationTarget {
        subject: kr_worker::broker::subject(session(), instance()),
        binding_revision: kr_protocol::ids::AgentBindingRevision::new(1),
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
                method: method("fs/read_text_file"),
                class: NativeMethodClass::Observation,
                expects_response: true,
                approval_option_field: Nullable::null(),
                reverse: Nullable::some(ReverseOperation::FilesystemRead),
            },
            DeclarativeEntry {
                method: method("session/request_permission"),
                class: NativeMethodClass::Mutation,
                expects_response: true,
                // This upstream reads its decision from `behavior`, which is why the table says
                // so rather than the core assuming a member name.
                approval_option_field: Nullable::some("behavior".to_owned()),
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
            // Ordered by method, as a qualified table is. Three of the four need one right
            // between them, and each is still its own upstream method.
            rich_entry(
                "session/answer",
                ActionRight::AgentApprovalRespond,
                Some(RichOperation::ApprovalRespond),
                NativeMethodClass::Mutation,
            ),
            rich_entry(
                "session/cancel",
                ActionRight::AgentCancel,
                Some(RichOperation::TurnCancel),
                NativeMethodClass::Mutation,
            ),
            rich_entry(
                "session/prompt",
                ActionRight::AgentPrompt,
                Some(RichOperation::PromptSubmit),
                NativeMethodClass::Mutation,
            ),
            rich_entry(
                "session/queue",
                ActionRight::AgentPrompt,
                Some(RichOperation::PromptQueue),
                NativeMethodClass::Mutation,
            ),
            rich_entry(
                "session/set_provider_key",
                ActionRight::AgentPrompt,
                None,
                NativeMethodClass::Unsupported,
            ),
            rich_entry(
                "session/steer",
                ActionRight::AgentPrompt,
                Some(RichOperation::TurnSteer),
                NativeMethodClass::Mutation,
            ),
        ],
    }
}

fn rich_entry(
    name: &str,
    required_right: ActionRight,
    operation: Option<RichOperation>,
    class: NativeMethodClass,
) -> RichMethodEntry {
    RichMethodEntry {
        method: method(name),
        class,
        required_right,
        operation: Nullable::from(operation),
        provenance: kr_protocol::broker::ActionProvenance::UpstreamTypedRpc,
    }
}

/// A short private directory, because a socket path has a small bound on every Unix.
fn private_directory() -> std::path::PathBuf {
    let name: String = kr_ipc::new_uuid()
        .to_string()
        .chars()
        .filter(char::is_ascii_hexdigit)
        .take(8)
        .collect();
    let directory = std::env::temp_dir().join(format!("kr-t-{name}"));
    std::fs::create_dir_all(&directory).expect("the directory is created");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
            .expect("the directory is made private");
    }
    directory
}

/// The capability evidence every agent mutation in this suite acts under.
fn record_capabilities(broker: &Broker) {
    for name in [
        "agent.prompt",
        "agent.prompt.queue",
        "agent.steer",
        "agent.cancel",
        "agent.approval",
    ] {
        broker
            .record_capability(kr_protocol::broker::InstanceCapabilityRecord {
                capability_id: kr_protocol::ids::CapabilityId::new(name).expect("valid"),
                capability_version: "1".to_owned(),
                application_instance_id: instance(),
                identity: kr_protocol::broker::InstanceCapabilityIdentity::default(),
                revision: kr_protocol::ids::CapabilityRevision::new(1),
                state: kr_protocol::broker::InstanceCapabilityState::QualifiedAvailable,
                source: kr_protocol::broker::InstanceEvidenceSource::HostProbe,
                invalidated_by: [kr_protocol::broker::InstanceInvalidation::BindingChanged]
                    .into_iter()
                    .collect(),
                disabled_reason: Nullable::null(),
                observed_at: TimestampMs::new(1),
            })
            .expect("the capability is recorded");
    }
}

/// A broker with one instance, one pinned table and one authenticated native connection.
fn broker() -> Arc<Broker> {
    let broker = Broker::open(None, session()).expect("the broker opens");
    broker
        .register_instance(instance(), IntegrationMode::Gateway, None, Some(managed()))
        .expect("the instance is registered");
    broker
        .bind(
            binding(),
            instance(),
            PluginId::new("kalareach.codex").expect("valid"),
            PublisherId::new("kalareach").expect("valid"),
            Digest256::from_bytes([5; 32]),
            BrokerGrants::granted([BrokerGrant::ApprovalInterpreter]),
            Some(trust()),
            TimestampMs::new(1),
        )
        .expect("the binding is recorded");
    broker
        .pin_table(instance(), table(), rich())
        .expect("the installed tables are pinned");
    broker
        .open_native_connection(
            instance(),
            &CREDENTIAL,
            &process_identity(),
            &package(),
            "1",
        )
        .expect("the native connection is authenticated");
    record_capabilities(&broker);
    Arc::new(broker)
}

/// Builds a link over two real socket pairs and returns the ends a test drives.
async fn link_over_sockets(
    broker: &Arc<Broker>,
) -> (
    Arc<Link>,
    tokio::net::UnixStream,
    tokio::net::UnixStream,
    tokio::task::JoinHandle<()>,
) {
    let (upstream_here, upstream_there) =
        tokio::net::UnixStream::pair().expect("a socket pair is made");
    let (client_here, client_there) =
        tokio::net::UnixStream::pair().expect("a socket pair is made");
    let framing = Framing::new(NativeFraming::JsonLines);
    let (to_upstream, to_client, drain) = kr_worker::broker::writers(
        framing,
        tokio::io::split(upstream_here).1,
        tokio::io::split(client_here).1,
    );
    let drained = tokio::spawn(drain);
    let link = Arc::new(Link::new(
        Arc::clone(broker),
        GatewayConnectionId::new(1),
        framing,
        to_upstream,
        to_client,
        EnvironmentId::new(Uuid::from_bytes([4; 16])),
        "agent-user",
    ));
    (link, upstream_there, client_there, drained)
}

async fn next_line(stream: &mut tokio::io::BufReader<tokio::net::UnixStream>) -> String {
    let mut line = String::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        stream.read_line(&mut line),
    )
    .await
    .expect("a frame arrives")
    .expect("the socket is readable");
    line
}

/// KR-REQ-11.30, KR-REQ-11.32, KR-REQ-12.11 and KR-REQ-12.13: a real transport reads a frame,
/// records it, forwards it, and carries an admitted answer back to the upstream.
#[tokio::test]
async fn kr_req_12_11_a_real_transport_forwards_a_request_and_carries_the_answer_back() {
    let broker = broker();
    let (link, upstream, client, drained) = link_over_sockets(&broker).await;
    let mut client_reader = tokio::io::BufReader::new(client);
    let mut upstream_reader = tokio::io::BufReader::new(upstream);

    // The upstream asks for a permission. The broker records it before it is forwarded, and the
    // client end reads the frame off its own socket.
    let request = br#"{"id":11,"method":"session/request_permission","params":{}}"#;
    let carried = link
        .from_upstream(request, TimestampMs::new(2))
        .expect("the request is carried");
    let kr_worker::broker::Carried::UpstreamRequest {
        method,
        resource_id,
    } = carried
    else {
        panic!("a request is what this was");
    };
    assert_eq!(method, self::method("session/request_permission"));
    let resource_id = resource_id.expect("it expects a response");
    let forwarded = next_line(&mut client_reader).await;
    assert!(forwarded.contains("session/request_permission"));
    assert_eq!(
        broker.pending(resource_id).expect("recorded").state,
        PendingState::Pending
    );

    // A component interprets it, and a rich answer is admitted and dispatched through the same
    // transport. What lands on the upstream's socket is the answer the core prepared.
    broker
        .interpret(
            binding(),
            resource_id,
            projection(),
            None,
            TimestampMs::new(3),
        )
        .expect("the interpretation is accepted");
    let dispatch = link.dispatch().expect("the link carries operations");
    broker.bind_connection_dispatch(GatewayConnectionId::new(1), dispatch);
    let answered = broker
        .agent_approval_respond(
            &kr_worker::broker::Caller {
                actor_id: ActorId::new("device-1").expect("valid"),
                grant_id: None,
            },
            &kr_protocol::agent::AgentApprovalRespondParams {
                target: target(),
                resource_id,
                option_id: "allow".to_owned(),
            },
            TimestampMs::new(4),
        )
        .expect("the answer is admitted and carried")
        .0;
    assert_eq!(answered.state, PendingState::Resolved);
    let answer = next_line(&mut upstream_reader).await;
    let answer: serde_json::Value = serde_json::from_str(answer.trim()).expect("readable");
    assert_eq!(
        answer["id"],
        serde_json::json!(11),
        "the identifier keeps its JSON type"
    );
    assert_eq!(
        answer["result"]["behavior"],
        serde_json::json!("allow"),
        "the decision goes in the member this upstream's table names"
    );
    assert!(
        answer["result"].get("option_id").is_none(),
        "and in no member the core invented"
    );
    drop(link);
    drop(client_reader);
    drop(upstream_reader);
    drained.abort();
}

/// KR-REQ-11.27 and KR-REQ-11.33: the native client's own answer travels the same transport, and a
/// second answer to one request never reaches the upstream.
#[tokio::test]
async fn kr_req_11_27_a_clients_own_answer_travels_the_transport_and_a_second_one_does_not() {
    let broker = broker();
    let (link, upstream, client, drained) = link_over_sockets(&broker).await;
    let mut client_reader = tokio::io::BufReader::new(client);
    let mut upstream_reader = tokio::io::BufReader::new(upstream);

    link.from_upstream(
        br#"{"id":12,"method":"session/request_permission","params":{}}"#,
        TimestampMs::new(2),
    )
    .expect("the request is carried");
    let _ = next_line(&mut client_reader).await;

    // The person answers in the terminal. The answer takes the resource's one admission and is
    // then forwarded, in that order.
    let answer = br#"{"id":12,"result":{"outcome":"allow"}}"#;
    let carried = link
        .from_client(answer, TimestampMs::new(3))
        .expect("the client's own answer is admitted and forwarded");
    let kr_worker::broker::Carried::ClientAnswer { resource_id } = carried else {
        panic!("an answer is what this was");
    };
    let forwarded = next_line(&mut upstream_reader).await;
    assert!(forwarded.contains("\"outcome\":\"allow\""));
    assert_eq!(
        broker.pending(resource_id).expect("recorded").state,
        PendingState::Resolved
    );

    // A second answer to the same request is refused, and nothing more reaches the upstream.
    assert!(
        link.from_client(answer, TimestampMs::new(4)).is_err(),
        "one resource takes one answer"
    );
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(200),
            next_line(&mut upstream_reader),
        )
        .await
        .is_err(),
        "the refusal happened before any bytes went"
    );

    drop(link);
    drop(client_reader);
    drop(upstream_reader);
    drained.abort();
}

/// KR-REQ-12.16: a reverse request runs in the agent's own host environment and is answered on the
/// connection it arrived on.
#[tokio::test]
async fn kr_req_12_16_a_reverse_request_is_performed_and_answered_on_the_same_connection() {
    let broker = broker();
    let (link, upstream, _client, drained) = link_over_sockets(&broker).await;
    let mut upstream_reader = tokio::io::BufReader::new(upstream);

    let directory = private_directory();
    let path = directory.join("note.txt");
    std::fs::write(&path, "what the agent asked for").expect("the file is written");
    let request = format!(
        r#"{{"id":13,"method":"fs/read_text_file","params":{{"path":{}}}}}"#,
        serde_json::to_string(&path.to_string_lossy()).expect("encodable")
    );
    let carried = link
        .from_upstream(request.as_bytes(), TimestampMs::new(2))
        .expect("the reverse request is carried");
    assert_eq!(
        carried,
        kr_worker::broker::Carried::Reverse {
            operation: ReverseOperation::FilesystemRead,
            performed: true,
        }
    );
    let answer = next_line(&mut upstream_reader).await;
    let answer: serde_json::Value = serde_json::from_str(answer.trim()).expect("readable");
    assert_eq!(answer["id"], serde_json::json!(13));
    assert_eq!(
        answer["result"]["content"],
        serde_json::json!("what the agent asked for")
    );

    // Terminal input is not something a reverse request gets: this session's input path holds the
    // lease and records what it wrote.
    drop(link);
    drop(upstream_reader);
    drained.abort();
    let _ = std::fs::remove_dir_all(&directory);
}

/// KR-REQ-12.14 and KR-REQ-11.43: the endpoint the transport runs over is one the host bound, and
/// a connection that reaches it is one the kernel named.
#[tokio::test]
async fn kr_req_12_14_the_transport_runs_over_an_endpoint_this_host_bound() {
    let directory = private_directory();
    let endpoint = BoundEndpoint::bind(&directory).expect("the endpoint binds");
    let address = endpoint.address().clone();
    let kr_worker::broker::ListenerAddress::PrivateSocket(path) = address.clone() else {
        panic!("this platform prefers a private socket");
    };
    let connecting = tokio::spawn(async move {
        let mut stream = tokio::net::UnixStream::connect(&path)
            .await
            .expect("the bridge connects");
        stream
            .write_all(b"{\"id\":1,\"method\":\"session/request_permission\",\"params\":{}}\n")
            .await
            .expect("the bridge writes a frame");
        stream
    });
    let accepted = endpoint.accept().await.expect("the connection is accepted");
    assert!(accepted.peer.from_operating_system());
    assert!(accepted.peer.is_owner());

    // And the frame the bridge wrote is read with the connection's own framing.
    let kr_worker::broker::Stream::Socket(stream) = accepted.stream else {
        panic!("a private socket was bound");
    };
    let mut reader = tokio::io::BufReader::new(stream);
    let frame = next_line(&mut reader).await;
    let framing = Framing::new(NativeFraming::JsonLines);
    let mut buffer = frame.into_bytes();
    let body = framing
        .decode(&mut buffer)
        .expect("readable")
        .expect("a whole frame");
    assert!(String::from_utf8_lossy(&body).contains("session/request_permission"));

    drop(connecting.await.expect("the connecting task finishes"));
    drop(endpoint);
    let _ = std::fs::remove_dir_all(&directory);
}

/// KR-REQ-11.32 and KR-REQ-12.11: the read loop itself, driven by bytes on a socket.
///
/// The tests above hand the link one frame at a time. This one writes into a socket and lets the
/// link's own loop do the framing, so what is established is that a process on the other end of a
/// connection moves a request through the gateway without anything else helping it.
#[tokio::test]
async fn kr_req_11_32_the_read_loop_carries_what_arrives_on_the_socket() {
    let broker = broker();
    let (link, _upstream, client, drained) = link_over_sockets(&broker).await;
    let mut client_reader = tokio::io::BufReader::new(client);

    let (serving_end, mut writing_end) =
        tokio::net::UnixStream::pair().expect("a socket pair is made");
    let reading = {
        let link = Arc::clone(&link);
        tokio::spawn(async move { link.serve(serving_end, true).await })
    };

    // The frame arrives in two writes, which is what a socket does. The loop waits for the whole
    // of it rather than reading half a frame.
    writing_end
        .write_all(br#"{"id":21,"method":"session/request_permission","params":{}}"#)
        .await
        .expect("the upstream writes the frame");
    writing_end
        .write_all(b"\n")
        .await
        .expect("and the newline that ends it");
    let forwarded = next_line(&mut client_reader).await;
    assert!(forwarded.contains("session/request_permission"));
    assert_eq!(
        broker
            .pending_resources()
            .iter()
            .filter(|resource| resource.state == PendingState::Pending)
            .count(),
        1,
        "the loop recorded the request before it forwarded it"
    );

    // The connection ends, and so does the loop.
    drop(writing_end);
    tokio::time::timeout(std::time::Duration::from_secs(5), reading)
        .await
        .expect("the loop ends when its end closes")
        .expect("the loop did not panic");
    drained.abort();
}

/// KR-REQ-12.08 and KR-REQ-12.12: each operation is encoded as the method its own table names,
/// with the turn it acts on, and an operation the table names nothing for is refused at admission.
#[tokio::test]
async fn kr_req_12_08_each_operation_encodes_as_the_method_its_table_names_with_its_turn() {
    let broker = broker();
    let (link, upstream, _client, drained) = link_over_sockets(&broker).await;
    let mut upstream_reader = tokio::io::BufReader::new(upstream);
    broker
        .bind_dispatch(instance(), link.dispatch().expect("it carries operations"))
        .expect("the transport is bound");
    let turn = kr_protocol::ids::AgentTurnId::new("turn-7").expect("valid");
    broker
        .set_turn(instance(), Some(turn.clone()))
        .expect("a turn is running");
    let caller = kr_worker::broker::Caller {
        actor_id: ActorId::new("device-1").expect("valid"),
        grant_id: None,
    };
    let prompt = |text: &str| kr_protocol::agent::AgentPromptParams {
        target: target(),
        draft_id: kr_protocol::scalars::Nullable::null(),
        text: kr_protocol::scalars::Nullable::some(
            kr_protocol::agent::PromptText::new(text).expect("valid"),
        ),
    };

    // Four operations, three of which need one right between them. Each goes out as its own
    // method, with its own parameters, and never as whichever the table happened to list first.
    broker
        .agent_prompt(&caller, &prompt("hello"), false, TimestampMs::new(2))
        .expect("the prompt is applied");
    broker
        .agent_prompt(&caller, &prompt("and then this"), true, TimestampMs::new(3))
        .expect("the queued prompt is applied");
    broker
        .agent_steer(
            &caller,
            &kr_protocol::agent::AgentSteerParams {
                target: target(),
                turn_id: turn.clone(),
                text: kr_protocol::agent::PromptText::new("try the other file").expect("valid"),
            },
            TimestampMs::new(4),
        )
        .expect("the steer is applied");
    broker
        .agent_cancel(
            &caller,
            &kr_protocol::agent::AgentCancelParams {
                target: target(),
                turn_id: turn.clone(),
            },
            TimestampMs::new(5),
        )
        .expect("the cancellation is applied");

    for (method_name, parameters) in [
        (
            "session/prompt",
            serde_json::json!({ "draft_id": null, "text": "hello" }),
        ),
        (
            "session/queue",
            serde_json::json!({ "draft_id": null, "text": "and then this" }),
        ),
        (
            "session/steer",
            serde_json::json!({ "text": "try the other file", "turn_id": "turn-7" }),
        ),
        ("session/cancel", serde_json::json!({ "turn_id": "turn-7" })),
    ] {
        let frame = next_line(&mut upstream_reader).await;
        let frame: serde_json::Value = serde_json::from_str(frame.trim()).expect("readable");
        assert_eq!(
            frame["method"],
            serde_json::json!(method_name),
            "each operation encodes as the method its table names"
        );
        assert_eq!(
            frame["params"], parameters,
            "{method_name} carries exactly what it asks for"
        );
    }

    // A table that names no method for an operation refuses the operation at admission, before
    // anything is marked and before any byte. So does one whose method this build lists as
    // unsupported.
    let bare = Broker::open(None, session()).expect("the broker opens");
    bare.register_instance(instance(), IntegrationMode::Gateway, None, Some(managed()))
        .expect("the instance is registered");
    let mut narrowed = rich();
    narrowed
        .entries
        .retain(|entry| entry.operation.as_ref() != Some(&RichOperation::TurnSteer));
    for entry in &mut narrowed.entries {
        if entry.operation.as_ref() == Some(&RichOperation::TurnCancel) {
            entry.class = NativeMethodClass::Unsupported;
        }
    }
    bare.pin_table(instance(), table(), narrowed)
        .expect("the installed tables are pinned");
    bare.open_native_connection(
        instance(),
        &CREDENTIAL,
        &process_identity(),
        &package(),
        "1",
    )
    .expect("the native connection is authenticated");
    record_capabilities(&bare);
    let bare = Arc::new(bare);
    let (narrow_link, _upstream, _client, other_drain) = link_over_sockets(&bare).await;
    bare.bind_dispatch(
        instance(),
        narrow_link.dispatch().expect("it carries operations"),
    )
    .expect("the transport is bound");
    bare.set_turn(instance(), Some(turn.clone()))
        .expect("a turn is running");
    for (what, refusal) in [
        (
            "a table that names no steer",
            bare.admit_steer(
                &caller,
                &kr_protocol::agent::AgentSteerParams {
                    target: target(),
                    turn_id: turn.clone(),
                    text: kr_protocol::agent::PromptText::new("nowhere to send this")
                        .expect("valid"),
                },
                TimestampMs::new(6),
            )
            .expect_err("it cannot steer"),
        ),
        (
            "a method this build does not support",
            bare.admit_cancel(
                &caller,
                &kr_protocol::agent::AgentCancelParams {
                    target: target(),
                    turn_id: turn,
                },
                TimestampMs::new(7),
            )
            .expect_err("it cannot cancel"),
        ),
    ] {
        assert_eq!(
            refusal.code(),
            kr_protocol::error::ErrorCode::UnsupportedCapability,
            "{what} refuses at admission"
        );
    }

    drop(link);
    drop(upstream_reader);
    drained.abort();
    other_drain.abort();
}
