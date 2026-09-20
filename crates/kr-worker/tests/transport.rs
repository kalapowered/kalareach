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
    BoundEndpoint, Broker, BrokerTransport, Carried, Credential, Duplex, Framing, ManagedProcess,
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
    managed_for(instance())
}

fn managed_for(application_instance_id: ApplicationInstanceId) -> ManagedProcess {
    ManagedProcess::new(
        application_instance_id,
        process_identity(),
        TransportHandle {
            transport: BrokerTransport::PrivateSocket,
            application_instance_id,
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
                method: method("fs/write_text_file"),
                class: NativeMethodClass::Mutation,
                expects_response: true,
                approval_option_field: Nullable::null(),
                reverse: Nullable::some(ReverseOperation::FilesystemWrite),
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
            DeclarativeEntry {
                method: method("session/update"),
                class: NativeMethodClass::Observation,
                expects_response: false,
                approval_option_field: Nullable::null(),
                reverse: Nullable::null(),
            },
            DeclarativeEntry {
                method: method("terminal/create"),
                class: NativeMethodClass::Mutation,
                expects_response: true,
                approval_option_field: Nullable::null(),
                reverse: Nullable::some(ReverseOperation::Terminal),
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
    broker_with_rich(rich())
}

fn broker_with_rich(rich: RichMethodTable) -> Arc<Broker> {
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
        .pin_table(instance(), table(), rich)
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

/// Builds one connection's owner over two real socket pairs and returns the ends a test drives.
async fn duplex_over_sockets(
    broker: &Arc<Broker>,
) -> (
    Arc<Duplex>,
    tokio::net::UnixStream,
    tokio::net::UnixStream,
    tokio::task::JoinHandle<()>,
) {
    let served = duplex_watched(broker).await;
    (served.owner, served.upstream, served.client, served.drained)
}

/// One connection's owner and every end of it a test may drive.
struct Served {
    owner: Arc<Duplex>,
    /// The upstream's own end of the connection.
    upstream: tokio::net::UnixStream,
    /// The native client's own end.
    client: tokio::net::UnixStream,
    /// What the owner reads the upstream through, for a test that drives the read loop.
    upstream_reads: tokio::io::ReadHalf<tokio::net::UnixStream>,
    /// The owner's write task.
    drained: tokio::task::JoinHandle<()>,
    /// The subscription an authorised observer of the instance reads.
    #[allow(dead_code)]
    observations: kr_worker::broker::Observations,
}

/// The same, with every end of the connection and the observer subscription.
async fn duplex_watched(broker: &Arc<Broker>) -> Served {
    let (upstream_here, upstream_there) =
        tokio::net::UnixStream::pair().expect("a socket pair is made");
    let (client_here, client_there) =
        tokio::net::UnixStream::pair().expect("a socket pair is made");
    let framing = Framing::new(NativeFraming::JsonLines);
    let observations = broker.observatory().subscribe(GatewayConnectionId::new(1));
    let (upstream_reads, upstream_writes) = tokio::io::split(upstream_here);
    let (owner, writes) = Duplex::new(
        Arc::clone(broker),
        GatewayConnectionId::new(1),
        framing,
        upstream_writes,
        tokio::io::split(client_here).1,
        EnvironmentId::new(Uuid::from_bytes([4; 16])),
        "agent-user",
    );
    let drained = tokio::spawn(writes);
    Served {
        owner,
        upstream: upstream_there,
        client: client_there,
        upstream_reads,
        drained,
        observations,
    }
}

/// Answers every request this host sends on `upstream`, so an operation reaches its acknowledgement.
///
/// The transport records a mutation as applied only when the upstream has answered it, so a test
/// that sends one needs something on the other end that does. This is that, and it records what
/// it was sent.
fn acknowledge(
    upstream: tokio::net::UnixStream,
    frames: Arc<std::sync::Mutex<Vec<serde_json::Value>>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let (reading, mut writing) = tokio::io::split(upstream);
        let mut reader = tokio::io::BufReader::new(reading);
        loop {
            let mut line = String::new();
            match reader.read_line(&mut line).await {
                Ok(0) | Err(_) => return,
                Ok(_) => {}
            }
            let Ok(frame) = serde_json::from_str::<serde_json::Value>(line.trim()) else {
                continue;
            };
            let identifier = frame["id"].clone();
            frames
                .lock()
                .expect("the record is not poisoned")
                .push(frame);
            let reply = serde_json::json!({ "id": identifier, "result": {} });
            if writing
                .write_all(format!("{reply}\n").as_bytes())
                .await
                .is_err()
            {
                return;
            }
        }
    })
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
    let (owner, upstream, client, drained) = duplex_over_sockets(&broker).await;
    let mut client_reader = tokio::io::BufReader::new(client);
    let mut upstream_reader = tokio::io::BufReader::new(upstream);

    // The upstream asks for a permission. The broker records it before it is forwarded, and the
    // client end reads the frame off its own socket.
    let request = br#"{"id":11,"method":"session/request_permission","params":{}}"#;
    let carried = owner
        .from_upstream(request, TimestampMs::new(2))
        .await
        .expect("the request is carried");
    let Carried::UpstreamRequest {
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
    let dispatch = owner.dispatch().expect("the link carries operations");
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
        .await
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
    drop(owner);
    drop(client_reader);
    drop(upstream_reader);
    drained.abort();
}

/// KR-REQ-11.27 and KR-REQ-11.33: the native client's own answer travels the same transport, and a
/// second answer to one request never reaches the upstream.
#[tokio::test]
async fn kr_req_11_27_a_clients_own_answer_travels_the_transport_and_a_second_one_does_not() {
    let broker = broker();
    let (owner, upstream, client, drained) = duplex_over_sockets(&broker).await;
    let mut client_reader = tokio::io::BufReader::new(client);
    let mut upstream_reader = tokio::io::BufReader::new(upstream);

    owner
        .from_upstream(
            br#"{"id":12,"method":"session/request_permission","params":{}}"#,
            TimestampMs::new(2),
        )
        .await
        .expect("the request is carried");
    let _ = next_line(&mut client_reader).await;

    // The person answers in the terminal. The answer takes the resource's one admission and is
    // then forwarded, in that order.
    let answer = br#"{"id":12,"result":{"outcome":"allow"}}"#;
    let carried = owner
        .from_client(answer, TimestampMs::new(3))
        .await
        .expect("the client's own answer is admitted and forwarded");
    let Carried::ClientAnswer { resource_id, .. } = carried else {
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
        owner
            .from_client(answer, TimestampMs::new(4))
            .await
            .is_err(),
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

    drop(owner);
    drop(client_reader);
    drop(upstream_reader);
    drained.abort();
}

/// KR-REQ-12.16 and KR-REQ-11.23: a reverse request is answered on the connection it arrived on,
/// and nothing of it touches the filesystem outside the host resources this session granted.
///
/// Section 12 executes these "in the selected host environment with scoped broker resources", and
/// a path in a request is not a scoped resource. Until one is resolved through the file authority
/// under an exclusive execution admission, the request is refused with a qualified reason, and the
/// refusal happens before anything could read or write.
#[tokio::test]
async fn kr_req_12_16_a_reverse_request_is_refused_before_any_effect_and_answered_in_place() {
    let broker = broker();
    let (owner, upstream, _client, drained) = duplex_over_sockets(&broker).await;
    let mut upstream_reader = tokio::io::BufReader::new(upstream);

    let directory = private_directory();
    let read_from = directory.join("note.txt");
    let write_to = directory.join("written.txt");
    std::fs::write(&read_from, "what the agent asked for").expect("the file is written");
    for (id, method, params) in [
        (
            13,
            "fs/read_text_file",
            serde_json::json!({ "path": read_from.to_string_lossy() }),
        ),
        (
            14,
            "fs/write_text_file",
            serde_json::json!({ "path": write_to.to_string_lossy(), "content": "anything" }),
        ),
        (15, "terminal/create", serde_json::json!({})),
    ] {
        let request =
            serde_json::json!({ "id": id, "method": method, "params": params }).to_string();
        let carried = owner
            .from_upstream(request.as_bytes(), TimestampMs::new(2))
            .await
            .expect("the reverse request is carried");
        let Carried::Reverse { performed, .. } = carried else {
            panic!("a reverse request is what this was");
        };
        assert!(!performed, "{method} performs nothing without a grant");
        let answer = next_line(&mut upstream_reader).await;
        let answer: serde_json::Value = serde_json::from_str(answer.trim()).expect("readable");
        assert_eq!(
            answer["id"],
            serde_json::json!(id),
            "the answer goes back on the identifier it came in with"
        );
        assert!(
            answer["result"].is_null(),
            "{method} produced no result to report"
        );
        assert!(
            answer["error"]["message"]
                .as_str()
                .is_some_and(|message| message.contains("granted none")),
            "{method} says why rather than failing silently: {}",
            answer["error"]
        );
    }
    assert!(
        !write_to.exists(),
        "a write with no granted resource wrote nothing"
    );

    drop(owner);
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
    let (owner, _upstream, client, drained) = duplex_over_sockets(&broker).await;
    let mut client_reader = tokio::io::BufReader::new(client);

    let (serving_end, mut writing_end) =
        tokio::net::UnixStream::pair().expect("a socket pair is made");
    let reading = {
        let owner = Arc::clone(&owner);
        tokio::spawn(async move { owner.serve(serving_end, true).await })
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
    let served = duplex_watched(&broker).await;
    let (owner, drained) = (Arc::clone(&served.owner), served.drained);
    // The upstream answers every request this host sends it, because a mutation is applied when
    // the upstream has acted on it and not when its bytes left this host.
    let sent = Arc::new(std::sync::Mutex::new(Vec::new()));
    let answering = acknowledge(served.upstream, Arc::clone(&sent));
    let reading = {
        let owner = Arc::clone(&owner);
        tokio::spawn(async move { owner.serve(served.upstream_reads, true).await })
    };
    broker
        .bind_dispatch(instance(), owner.dispatch().expect("it carries operations"))
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
        .await
        .expect("the prompt is applied");
    broker
        .agent_prompt(&caller, &prompt("and then this"), true, TimestampMs::new(3))
        .await
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
        .await
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
        .await
        .expect("the cancellation is applied");

    for (index, (method_name, parameters)) in [
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
    ]
    .into_iter()
    .enumerate()
    {
        let sent = sent.lock().expect("the record is not poisoned");
        let frame = sent
            .get(index)
            .expect("each operation reached the upstream");
        assert_eq!(
            frame["method"],
            serde_json::json!(method_name),
            "each operation encodes as the method its table names"
        );
        assert_eq!(
            frame["params"], parameters,
            "{method_name} carries exactly what it asks for"
        );
        assert!(
            frame["id"].as_str().is_some_and(|id| id.starts_with("kr-")),
            "and under an identifier this host minted rather than one an upstream could mint: {}",
            frame["id"]
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
    let (narrow_owner, _upstream, _client, other_drain) = duplex_over_sockets(&bare).await;
    bare.bind_dispatch(
        instance(),
        narrow_owner.dispatch().expect("it carries operations"),
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

    drop(owner);
    answering.abort();
    reading.abort();
    drained.abort();
    other_drain.abort();
}

/// KR-REQ-11.33 and KR-REQ-12.08: an approval answer is the frame the core prepared, so it needs
/// no rich method of its own.
///
/// The rich table names a method per operation and the core sends nothing it cannot name. An
/// answer is the exception and it is the exception for a reason: it is not encoded from the rich
/// table at all, it is the frame `prepare_response` built from the connection's declarative table.
/// This upstream's rich table names no `ApprovalRespond` method, and the answer still goes, in the
/// member the declarative table names.
#[tokio::test]
async fn kr_req_11_33_an_answer_needs_no_rich_method_of_its_own() {
    let mut narrowed = rich();
    narrowed
        .entries
        .retain(|entry| entry.operation.as_ref() != Some(&RichOperation::ApprovalRespond));
    let broker = broker_with_rich(narrowed);
    let (owner, upstream, client, drained) = duplex_over_sockets(&broker).await;
    let mut client_reader = tokio::io::BufReader::new(client);
    let mut upstream_reader = tokio::io::BufReader::new(upstream);

    let carried = owner
        .from_upstream(
            br#"{"id":11,"method":"session/request_permission","params":{}}"#,
            TimestampMs::new(2),
        )
        .await
        .expect("the request is carried");
    let Carried::UpstreamRequest { resource_id, .. } = carried else {
        panic!("a request is what this was");
    };
    let resource_id = resource_id.expect("it expects a response");
    let _ = next_line(&mut client_reader).await;
    broker
        .interpret(
            binding(),
            resource_id,
            projection(),
            None,
            TimestampMs::new(3),
        )
        .expect("the interpretation is accepted");
    let dispatch = owner.dispatch().expect("the link carries operations");
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
        .await
        .expect("a table with no answer method still answers its own requests")
        .0;
    assert_eq!(answered.state, PendingState::Resolved);
    let answer: serde_json::Value =
        serde_json::from_str(next_line(&mut upstream_reader).await.trim()).expect("readable");
    assert_eq!(answer["id"], serde_json::json!(11));
    assert_eq!(answer["result"]["behavior"], serde_json::json!("allow"));

    // The operations that *are* encoded from the rich table are refused when it names no method
    // for them, which is what makes the answer's exemption an exemption rather than a gap.
    let refusal = broker
        .admit_rich(
            GatewayConnectionId::new(1),
            &method("session/answer"),
            kr_protocol::ids::UpstreamRequestId::new("12").expect("valid"),
        )
        .expect_err("this table names no such method");
    assert_eq!(
        refusal.code(),
        kr_protocol::error::ErrorCode::UnsupportedCapability
    );

    drop(owner);
    drop(client_reader);
    drop(upstream_reader);
    drained.abort();
}

/// A broker with nothing registered yet, for a launch that will register the instance itself.
///
/// The production composition is what registers the instance, with the process it actually
/// started. Nothing here pretends to have launched anything.
fn broker_for_launch() -> Arc<Broker> {
    Arc::new(Broker::open(None, session()).expect("the broker opens"))
}

/// A broker that expects this process on its connections, for the tests that stand in for a bridge.
///
/// The launch itself is proved by the test that starts the forwarder. These two are about what
/// happens to a connection once one reaches the endpoint, so the process the kernel names is this
/// one and the instance's record says so.
fn broker_expecting_this_process() -> (Arc<Broker>, ProcessStartIdentity) {
    let running = kr_ipc::identity::current_process_start_identity().expect("a process identity");
    let broker = Broker::open(None, session()).expect("the broker opens");
    broker
        .register_instance(
            instance(),
            IntegrationMode::Gateway,
            None,
            Some(ManagedProcess::new(
                instance(),
                running.clone(),
                TransportHandle {
                    transport: BrokerTransport::PrivateSocket,
                    application_instance_id: instance(),
                    executable_digest: Digest256::from_bytes([3; 32]),
                    process: running.clone(),
                },
                Credential::from_bytes(CREDENTIAL),
                // Not dedicated: the process on the other end is this test, and a backend this
                // host did not start for itself is never claimed or terminated as owned.
                false,
                TimestampMs::new(1),
            )),
        )
        .expect("the instance is registered");
    broker
        .pin_table(instance(), table(), rich())
        .expect("the installed tables are pinned");
    bind_component(&broker);
    record_capabilities(&broker);
    (Arc::new(broker), running)
}

/// Binds the component whose decoder interprets this connector's approvals.
fn bind_component(broker: &Broker) {
    broker
        .bind(
            binding(),
            instance(),
            package(),
            PublisherId::new("kalareach").expect("valid"),
            Digest256::from_bytes([5; 32]),
            BrokerGrants::granted([
                BrokerGrant::UpstreamAction,
                BrokerGrant::ApprovalInterpreter,
            ]),
            Some(trust()),
            TimestampMs::new(1),
        )
        .expect("the component is bound");
}

/// The forwarder this host ships, as the test build put it on disk.
///
/// The endpoint tests launch a real executable through the same composition production uses, so
/// the process the kernel names on the accepted socket is a process this host started and not the
/// test standing in for one.
fn forwarder() -> std::path::PathBuf {
    let path = std::path::PathBuf::from(env!("CARGO_BIN_EXE_kr-hook"));
    assert!(path.exists(), "the forwarder is built beside this test");
    path
}

/// The launch profile that starts that forwarder.
fn forwarder_profile() -> kr_protocol::broker::LaunchProfile {
    kr_protocol::broker::LaunchProfile {
        profile_id: kr_protocol::ids::LaunchProfileId::new("lp-1").expect("valid"),
        environment_id: EnvironmentId::new(Uuid::from_bytes([4; 16])),
        binary: kr_protocol::broker::BinaryIdentity {
            resolved_path: forwarder().to_string_lossy().into_owned(),
            digest: Digest256::from_bytes([3; 32]),
            version: "0.9.0".to_owned(),
            distribution: "build".to_owned(),
        },
        arguments: Vec::new(),
        authentication: kr_protocol::broker::AuthenticationState::Authenticated,
        mode: IntegrationMode::Gateway,
        resolved_at: TimestampMs::new(1),
    }
}

/// The launch one of these endpoints publishes.
fn launch_for(
    expected: Option<ProcessStartIdentity>,
    native_terminal: Option<ProcessStartIdentity>,
) -> kr_worker::broker::NativeLaunch {
    kr_worker::broker::NativeLaunch {
        profile_id: kr_protocol::ids::LaunchProfileId::new("lp-1").expect("valid"),
        expected_process: expected,
        native_terminal,
        application_instance_id: instance(),
        plugin_id: package(),
        installed_protocol_version: "1".to_owned(),
        framing: Framing::new(NativeFraming::JsonLines),
        site: EnvironmentId::new(Uuid::from_bytes([4; 16])),
        os_user: "agent-user".to_owned(),
    }
}

/// The hello a bridge writes, as hexadecimal over the credential this launch generated.
fn hello_bytes(process: &ProcessStartIdentity, headers: &[(&str, &str)]) -> Vec<u8> {
    let credential: String = CREDENTIAL
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let headers = headers
        .iter()
        .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
        .collect();
    let mut frame = kr_worker::broker::hello_frame(&credential, process, Some("ignored"), &headers);
    frame.push(b'\n');
    frame
}

/// KR-REQ-11.22, KR-REQ-11.32, KR-REQ-11.43, KR-REQ-12.11 and KR-REQ-12.14: a bridge that reaches
/// the bound endpoint becomes a connection this host serves, end to end.
///
/// Nothing here is assembled by the test: the endpoint is bound by the host, the peer identity is
/// the kernel's, the credential is the launch's, the connection is admitted by the broker, the
/// dispatch is registered by the composition, and the owner reads both ends. The bridge is a task
/// in this process rather than a separate executable, so what the kernel names on the accepted
/// socket is this process, which is exactly the process the registration expects.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_12_14_a_bridge_that_reaches_the_endpoint_becomes_a_served_connection() {
    let directory = private_directory();
    let broker = broker_for_launch();
    let mut gateway = kr_worker::broker::NativeGateway::bind(
        Arc::clone(&broker),
        &directory,
        launch_for(None, None),
    )
    .expect("the endpoint binds");

    // The host starts the forwarder, through the same composition production uses. Everything the
    // forwarder needs is published by that call: the endpoint it connects to, the private exchange
    // it presents, and the process identity this host will compare it against.
    let intent = broker
        .prepare_launch(
            forwarder_profile(),
            kr_worker::broker::ForegroundMark::idle(4),
            None,
        )
        .expect("the launch is prepared");
    let mut launched = gateway
        .launch(
            &intent,
            &kr_worker::broker::ForegroundMark::idle(4),
            IntegrationMode::Gateway,
            TimestampMs::new(1),
        )
        .expect("the agent is started");
    broker
        .pin_table(instance(), table(), rich())
        .expect("the installed tables are pinned");
    bind_component(&broker);
    record_capabilities(&broker);
    assert!(
        gateway
            .registration()
            .expect("a launch publishes one")
            .contains("endpoint="),
        "the file the forwarder reads names where to connect"
    );

    let (client_here, client_there) = tokio::net::UnixStream::pair().expect("a socket pair");
    let (client_reads, client_writes) = tokio::io::split(client_here);
    let attached = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        gateway.accept(client_reads, client_writes),
    )
    .await
    .expect("the forwarder reaches the endpoint")
    .expect("it is authenticated and admitted");
    let mut observations = attached.observations;
    let mut client = tokio::io::BufReader::new(client_there);

    // The upstream speaks through the forwarder's own standard input, which is what a launched
    // agent writes to. The request reaches the native terminal through the owner the composition
    // started.
    let mut upstream = launched
        .child
        .stdin
        .take()
        .expect("the forwarder reads input");
    std::io::Write::write_all(
        &mut upstream,
        b"{\"id\":21,\"method\":\"session/request_permission\",\"params\":{}}\n",
    )
    .expect("the agent asks for a permission");
    std::io::Write::flush(&mut upstream).expect("and it goes");
    let forwarded = next_line(&mut client).await;
    assert!(forwarded.contains("session/request_permission"));
    let resource = broker
        .pending_resources()
        .into_iter()
        .find(|resource| resource.state == PendingState::Pending)
        .expect("the request was recorded before it was forwarded");

    // The person answers in the terminal. The answer goes back to the agent over the same
    // connection, and the resource is resolved only once the bytes have gone.
    client
        .get_mut()
        .write_all(b"{\"id\":21,\"result\":{\"outcome\":\"allow\"}}\n")
        .await
        .expect("the person answers");
    let mut answered = String::new();
    let agent = launched
        .child
        .stdout
        .take()
        .expect("the forwarder writes output");
    let mut agent = std::io::BufReader::new(agent);
    std::io::BufRead::read_line(&mut agent, &mut answered).expect("the agent reads its answer");
    assert!(
        answered.contains("\"outcome\":\"allow\""),
        "the answer reached the agent: {answered}"
    );
    let transition = settlement_of(&mut observations, resource.resource_id).await;
    assert_eq!(transition.state, PendingState::Resolved);
    assert_eq!(
        broker
            .pending(resource.resource_id)
            .expect("recorded")
            .state,
        PendingState::Resolved
    );

    let _ = launched.child.kill();
    let _ = launched.child.wait();
    let _ = std::fs::remove_dir_all(&directory);
}

/// KR-REQ-11.43 and KR-REQ-12.14: a bridge that is not this launch does not become a connection.
///
/// Three refusals, each one of the three things section 11 requires: the private exchange of the
/// launch, the process the launch started, and a connection carrying anything a browser adds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_11_43_a_wrong_credential_process_or_browser_origin_is_refused() {
    let running = kr_ipc::identity::current_process_start_identity().expect("a process identity");
    let stranger = ProcessStartIdentity::new(
        running.pid.get().saturating_add(100_000),
        running.source,
        running.start_value.get(),
    );
    for (what, expected, hello) in [
        ("a credential that is not this launch's", running.clone(), {
            let wrong: String = [7_u8; 32]
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            let mut frame = kr_worker::broker::hello_frame(
                &wrong,
                &running,
                None,
                &std::collections::BTreeMap::new(),
            );
            frame.push(b'\n');
            frame
        }),
        (
            "a process that is not the one this host launched",
            stranger,
            hello_bytes(&running, &[]),
        ),
        (
            "a connection carrying what a browser adds",
            running.clone(),
            hello_bytes(&running, &[("origin", "https://example.test")]),
        ),
    ] {
        let directory = private_directory();
        let (broker, _) = broker_expecting_this_process();
        let gateway = kr_worker::broker::NativeGateway::bind(
            Arc::clone(&broker),
            &directory,
            launch_for(Some(expected.clone()), None),
        )
        .expect("the endpoint binds");
        let kr_worker::broker::ListenerAddress::PrivateSocket(path) = gateway.address().clone()
        else {
            panic!("this platform prefers a private socket");
        };
        let connecting = tokio::spawn(async move {
            let mut stream = tokio::net::UnixStream::connect(&path)
                .await
                .expect("the bridge connects");
            let _ = stream.write_all(&hello).await;
            stream
        });
        let (client_here, _client_there) = tokio::net::UnixStream::pair().expect("a socket pair");
        let (client_reads, client_writes) = tokio::io::split(client_here);
        let refused = gateway
            .accept(client_reads, client_writes)
            .await
            .expect_err(what);
        assert_eq!(
            refused.code(),
            kr_protocol::error::ErrorCode::PermissionDenied,
            "{what} is refused"
        );
        assert!(
            broker.connection(GatewayConnectionId::new(1)).is_none(),
            "{what} left no admitted connection behind it"
        );
        drop(connecting.await.expect("the connecting task finished"));
        let _ = std::fs::remove_dir_all(&directory);
    }
}

/// KR-REQ-11.30, KR-REQ-12.11 and KR-REQ-12.13: the two directions never confuse requests that
/// carry the same raw identifier.
///
/// The upstream's request `7`, a notification it sends with no identifier, a reverse request it
/// asks for as `7`, and this host's own request all travel the one connection at once. Each is
/// carried as what it is, and the upstream's answer to its own `7` never resolves this host's
/// request and never the other way round.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_12_13_traffic_in_both_directions_keeps_identifiers_that_look_alike_apart() {
    let broker = broker();
    let served = duplex_watched(&broker).await;
    let owner = Arc::clone(&served.owner);
    let mut client = tokio::io::BufReader::new(served.client);
    broker
        .bind_dispatch(instance(), owner.dispatch().expect("it carries operations"))
        .expect("the transport is bound");

    // The upstream's own request `7`, its notification, and a reverse request it also calls `7`.
    let opaque = owner
        .from_upstream(
            br#"{"id":7,"method":"session/request_permission","params":{}}"#,
            TimestampMs::new(2),
        )
        .await
        .expect("the upstream's own request is carried");
    let Carried::UpstreamRequest { resource_id, .. } = opaque else {
        panic!("a request is what this was");
    };
    let upstream_seven = resource_id.expect("it expects a response");
    let notification = owner
        .from_upstream(
            br#"{"method":"session/update","params":{}}"#,
            TimestampMs::new(3),
        )
        .await;
    assert!(
        matches!(
            notification,
            Ok(Carried::UpstreamRequest {
                resource_id: None,
                ..
            }) | Err(_)
        ),
        "a notification names no request and resolves nothing"
    );
    let reverse = owner
        .from_upstream(
            br#"{"id":7,"method":"fs/read_text_file","params":{"path":"/nowhere"}}"#,
            TimestampMs::new(4),
        )
        .await;
    assert!(
        matches!(reverse, Ok(Carried::Reverse { .. }) | Err(_)),
        "and a reverse request under the same raw identifier is still a reverse request"
    );

    // The native client asks the upstream for something of its own, also under raw seven. It goes
    // out under an identifier of this host's, and the upstream's answer comes back to the client
    // under the identifier the client used.
    let carried = owner
        .from_client(
            br#"{"id":7,"method":"session/update","params":{"from":"the terminal"}}"#,
            TimestampMs::new(5),
        )
        .await
        .expect("the client's own request is carried");
    let Carried::ClientRequest {
        upstream_request_id: forwarded,
        ..
    } = carried
    else {
        panic!("a request of the client's is what this was");
    };
    assert!(
        is_host_minted_text(forwarded.as_str()),
        "it went out under an identifier of this host's: {forwarded}"
    );
    let returned = owner
        .from_upstream(
            format!(r#"{{"id":{forwarded},"result":{{"seen":true}}}}"#).as_bytes(),
            TimestampMs::new(6),
        )
        .await
        .expect("the upstream answers the client's request");
    assert_eq!(
        returned,
        Carried::ClientReply {
            upstream_request_id: forwarded,
            returned: true,
        }
    );
    // The upstream's own request was forwarded to this end first; the reply is what follows it.
    let to_client = loop {
        let line = next_line(&mut client).await;
        let frame: serde_json::Value = serde_json::from_str(line.trim()).expect("readable");
        if frame.get("result").is_some() {
            break frame;
        }
    };
    assert_eq!(
        to_client["id"],
        serde_json::json!(7),
        "the client reads its own identifier back, not this host's"
    );
    assert_eq!(to_client["result"]["seen"], serde_json::json!(true));

    // A client that mints an identifier in this host's namespace is refused, as an upstream is.
    assert!(
        owner
            .from_client(
                br#"{"id":"kr-99","method":"session/update","params":{}}"#,
                TimestampMs::new(7),
            )
            .await
            .is_err(),
        "the client does not get to mint identifiers in this host's namespace either"
    );

    // This host's own request goes out under an identifier of its own, and the upstream answers it.
    let sent = Arc::new(std::sync::Mutex::new(Vec::new()));
    let answering = acknowledge(served.upstream, Arc::clone(&sent));
    let reading = {
        let owner = Arc::clone(&owner);
        tokio::spawn(async move { owner.serve(served.upstream_reads, true).await })
    };
    broker
        .agent_prompt(
            &kr_worker::broker::Caller {
                actor_id: ActorId::new("device-1").expect("valid"),
                grant_id: None,
            },
            &kr_protocol::agent::AgentPromptParams {
                target: target(),
                draft_id: Nullable::null(),
                text: Nullable::some(kr_protocol::agent::PromptText::new("hello").expect("valid")),
            },
            false,
            TimestampMs::new(5),
        )
        .await
        .expect("the prompt is acknowledged by the upstream");
    let mine = {
        let sent = sent.lock().expect("the record is not poisoned");
        sent.last().expect("this host's request went").clone()
    };
    assert_ne!(
        mine["id"],
        serde_json::json!(7),
        "this host does not mint an identifier the upstream is already using"
    );

    // The upstream now answers its *own* request seven. That resolves the resource the upstream's
    // request created, and it does not touch anything this host asked for.
    let carried = owner
        .from_upstream(
            br#"{"id":7,"result":{"outcome":"allow"}}"#,
            TimestampMs::new(6),
        )
        .await
        .expect("the upstream may withdraw its own request");
    assert_eq!(carried, Carried::UpstreamResponse);
    assert_eq!(
        broker.pending(upstream_seven).expect("recorded").state,
        PendingState::Cancelled,
        "the upstream's own seven withdrew the upstream's own request and nothing of this host's"
    );

    // And an upstream that tries to mint an identifier in this host's namespace is refused.
    let intruding = owner
        .from_upstream(
            br#"{"id":"kr-1","method":"session/request_permission","params":{}}"#,
            TimestampMs::new(7),
        )
        .await;
    assert!(
        intruding.is_err(),
        "an upstream does not get to mint identifiers in this host's namespace"
    );

    answering.abort();
    reading.abort();
    served.drained.abort();
    drop(client);
}

/// True when this identifier text is one the host's own namespace covers.
fn is_host_minted_text(text: &str) -> bool {
    text.starts_with("\"kr-")
}

/// Waits for the event that says one resource reached a state nothing follows.
///
/// Every transition is announced, the claim an answer takes among them, so what a test about a
/// settlement waits for is the settlement rather than the next thing this observer is told.
async fn settlement_of(
    observations: &mut kr_worker::broker::Observations,
    resource_id: kr_protocol::ids::PendingResourceId,
) -> kr_worker::broker::ResourceTransition {
    loop {
        let transition =
            tokio::time::timeout(std::time::Duration::from_secs(5), observations.next())
                .await
                .expect("an authorised observer is told")
                .expect("the subscription is live");
        if transition.resource_id == resource_id && transition.state.is_terminal() {
            return transition;
        }
    }
}

/// Drains everything an observer has been told, without waiting for more.
async fn told(observations: &mut kr_worker::broker::Observations) -> Vec<(u64, PendingState)> {
    let mut seen = Vec::new();
    while let Ok(Some(transition)) =
        tokio::time::timeout(std::time::Duration::from_millis(250), observations.next()).await
    {
        seen.push((transition.sequence, transition.state));
    }
    seen
}

/// KR-REQ-12.11, KR-REQ-12.13 and section 24: every transition is committed with the event that
/// announces it, and every authorised observer is told in one order.
///
/// Two connections of one instance watch it and a connection of another instance watches that.
/// Four transitions happen, two of them from tasks racing each other. What each authorised
/// observer reads is the same events in the same order; what the outbox holds is those same
/// events; and the unrelated observer reads none of them.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_12_11_every_transition_is_recorded_with_its_event_and_announced_in_one_order() {
    let broker = broker();
    // A second connection of the same instance, which is a second authorised observer, and one
    // connection of an instance nothing here touches.
    broker
        .open_native_connection(
            instance(),
            &CREDENTIAL,
            &process_identity(),
            &package(),
            "1",
        )
        .expect("a second connection of this instance is authenticated");
    let elsewhere = ApplicationInstanceId::new(Uuid::from_bytes([8; 16]));
    broker
        .register_instance(
            elsewhere,
            IntegrationMode::Gateway,
            None,
            Some(managed_for(elsewhere)),
        )
        .expect("the other instance is registered");
    broker
        .pin_table(elsewhere, table(), rich())
        .expect("its tables are pinned");
    broker
        .open_native_connection(elsewhere, &CREDENTIAL, &process_identity(), &package(), "1")
        .expect("its connection is authenticated");
    let served = duplex_watched(&broker).await;
    let mut first = served.observations;
    let mut second = broker.observatory().subscribe(GatewayConnectionId::new(2));
    let mut unrelated = broker.observatory().subscribe(GatewayConnectionId::new(3));
    let owner = Arc::clone(&served.owner);
    let mut client = tokio::io::BufReader::new(served.client);

    // Two requests of the upstream's, recorded.
    for id in [41, 42] {
        owner
            .from_upstream(
                format!(r#"{{"id":{id},"method":"session/request_permission","params":{{}}}}"#)
                    .as_bytes(),
                TimestampMs::new(2),
            )
            .await
            .expect("the request is carried");
        let _ = next_line(&mut client).await;
    }

    // One is answered by the person and one is withdrawn by the upstream, from two tasks at once.
    // Whatever order they take, every observer is told in the order the broker committed them.
    let answering = {
        let owner = Arc::clone(&owner);
        tokio::spawn(async move {
            owner
                .from_client(
                    br#"{"id":41,"result":{"outcome":"allow"}}"#,
                    TimestampMs::new(3),
                )
                .await
        })
    };
    let withdrawing = {
        let owner = Arc::clone(&owner);
        tokio::spawn(async move {
            owner
                .from_upstream(
                    br#"{"id":42,"result":{"outcome":"deny"}}"#,
                    TimestampMs::new(4),
                )
                .await
        })
    };
    answering
        .await
        .expect("the task finished")
        .expect("the answer goes");
    withdrawing
        .await
        .expect("the task finished")
        .expect("the withdrawal is carried");

    let told_first = told(&mut first).await;
    let told_second = told(&mut second).await;
    assert_eq!(
        told_first, told_second,
        "both authorised observers of this instance read the same events in the same order"
    );
    assert!(
        told(&mut unrelated).await.is_empty(),
        "an observer of another instance is told nothing about this one"
    );
    assert!(
        told_first.windows(2).all(|pair| pair[0].0 < pair[1].0),
        "and each event follows the one before it: {told_first:?}"
    );
    let states: Vec<PendingState> = told_first.iter().map(|(_, state)| *state).collect();
    assert!(
        states.contains(&PendingState::Resolved),
        "the person's answer resolved one: {states:?}"
    );
    assert!(
        states.contains(&PendingState::Cancelled),
        "the upstream withdrew the other: {states:?}"
    );

    // And the outbox holds exactly what was announced, because it was written with it.
    let recorded = broker.transitions_after(0).expect("the outbox reads");
    assert_eq!(
        recorded
            .iter()
            .map(|event| (event.sequence, event.state))
            .collect::<Vec<_>>(),
        told_first,
        "a crash between the change and its event would have shown up here"
    );
    for event in &recorded {
        assert_eq!(event.application_instance_id, instance());
        assert_eq!(
            event.binding_revision,
            kr_protocol::ids::AgentBindingRevision::new(1),
            "the revision in force when it changed"
        );
    }

    served.drained.abort();
}

/// KR-REQ-12.11: a second gateway joins the observers of the first rather than replacing them.
///
/// The registry is the broker's, so binding another endpoint against the same broker adds its
/// connections to the watchers instead of taking delivery away from the ones already there.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_12_11_a_second_gateway_joins_the_observers_of_the_first() {
    let broker = broker();
    let served = duplex_watched(&broker).await;
    let mut first = served.observations;
    let owner = Arc::clone(&served.owner);
    let mut client = tokio::io::BufReader::new(served.client);

    let one = private_directory();
    let another = private_directory();
    let earlier =
        kr_worker::broker::NativeGateway::bind(Arc::clone(&broker), &one, launch_for(None, None))
            .expect("the first endpoint binds");
    let later = kr_worker::broker::NativeGateway::bind(
        Arc::clone(&broker),
        &another,
        launch_for(None, None),
    )
    .expect("the second endpoint binds");
    assert_ne!(
        earlier.address(),
        later.address(),
        "two endpoints, one broker"
    );

    owner
        .from_upstream(
            br#"{"id":71,"method":"session/request_permission","params":{}}"#,
            TimestampMs::new(2),
        )
        .await
        .expect("the request is carried");
    let _ = next_line(&mut client).await;
    owner
        .from_upstream(
            br#"{"id":71,"result":{"outcome":"deny"}}"#,
            TimestampMs::new(3),
        )
        .await
        .expect("the upstream withdraws it");
    assert!(
        !told(&mut first).await.is_empty(),
        "the observer that was already watching is still told"
    );

    served.drained.abort();
    let _ = std::fs::remove_dir_all(&one);
    let _ = std::fs::remove_dir_all(&another);
}

/// KR-REQ-12.11: an observer that has stopped reading is withdrawn, not grown.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_12_11_an_observer_that_falls_behind_is_withdrawn_rather_than_grown() {
    let broker = broker();
    let mut watching = broker.observatory().subscribe(GatewayConnectionId::new(1));
    let served = duplex_watched(&broker).await;
    let owner = Arc::clone(&served.owner);
    let mut client = tokio::io::BufReader::new(served.client);

    // More transitions than one subscription may fall behind by, with nothing reading them.
    let overflow = kr_worker::broker::MAX_QUEUED_OBSERVATIONS + 8;
    for id in 0..overflow {
        let id = id + 100;
        owner
            .from_upstream(
                format!(r#"{{"id":{id},"method":"session/request_permission","params":{{}}}}"#)
                    .as_bytes(),
                TimestampMs::new(2),
            )
            .await
            .expect("the request is carried");
        let _ = next_line(&mut client).await;
        owner
            .from_upstream(
                format!(r#"{{"id":{id},"result":{{"outcome":"deny"}}}}"#).as_bytes(),
                TimestampMs::new(3),
            )
            .await
            .expect("the upstream withdraws it");
    }
    let seen = told(&mut watching).await;
    assert!(
        seen.len() <= kr_worker::broker::MAX_QUEUED_OBSERVATIONS,
        "the queue is bounded: {}",
        seen.len()
    );
    assert!(
        broker.transitions_after(0).expect("the outbox reads").len() >= overflow,
        "and every transition is still recorded, whatever any observer read"
    );

    served.drained.abort();
}

/// KR-REQ-11.30 and KR-REQ-12.13: the native client's own request goes through native admission,
/// and an unclassified one suspends rich mutations before a byte of it is written.
///
/// The terminal is a writer on this connection exactly as the agent is, so a frame it sends is
/// classified with the table this host pinned, recorded with the bytes it was, and — when this
/// host cannot say what it does — it suspends rich mutations first. The upstream here never reads,
/// so the request is still unwritten while all of that is asserted: the record and the suspension
/// are not what happened afterwards, they are what happened before.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_11_30_an_unclassified_client_request_suspends_rich_mutations_before_it_is_written()
{
    let broker = broker();
    // A pipe of a few bytes with nothing reading it: the frame is taken by the owner and its
    // bytes stop in the pipe, so nothing about it has reached the agent while this test runs.
    let (upstream_here, upstream_there) = tokio::io::duplex(8);
    let (client_here, _client_there) = tokio::net::UnixStream::pair().expect("a socket pair");
    let (owner, writes) = Duplex::new(
        Arc::clone(&broker),
        GatewayConnectionId::new(1),
        Framing::new(NativeFraming::JsonLines),
        upstream_here,
        tokio::io::split(client_here).1,
        EnvironmentId::new(Uuid::from_bytes([4; 16])),
        "agent-user",
    );
    let drained = tokio::spawn(writes);
    // Bound, so that what refuses the rich mutation below is the suspension and not the absence of
    // anything to carry it.
    broker
        .bind_dispatch(instance(), owner.dispatch().expect("it carries operations"))
        .expect("the transport is bound");

    // The terminal asks its agent for something this connector's table does not list.
    let carrying = {
        let owner = Arc::clone(&owner);
        tokio::spawn(async move {
            owner
                .from_client(
                    br#"{"id":4,"method":"session/set_mode","params":{"mode":"yolo"}}"#,
                    TimestampMs::new(2),
                )
                .await
        })
    };

    // Before any of it goes: the intent is recorded, the source is retained and rich mutations
    // are suspended.
    let recorded = loop {
        let held = broker.client_requests().expect("the records read");
        if let Some(intent) = held.first() {
            break intent.clone();
        }
        assert!(!carrying.is_finished(), "the frame is still unwritten");
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    };
    assert_eq!(
        recorded.method,
        method("session/set_mode"),
        "the method the terminal named"
    );
    assert_eq!(recorded.classification.class, NativeMethodClass::Mutation);
    assert!(
        !recorded.classification.declared,
        "the table did not classify it, so it is presumed a mutation"
    );
    assert_eq!(
        recorded.outcome,
        kr_worker::broker::ClientRequestOutcome::Recorded,
        "recorded before its bytes went, not after"
    );
    assert!(
        recorded
            .upstream_request_id
            .as_ref()
            .is_some_and(|id| is_host_minted_text(id.as_str())),
        "under the identifier this host forwards it as: {:?}",
        recorded.upstream_request_id
    );
    assert!(
        broker.source(instance(), &recorded.source).is_some(),
        "the bytes the terminal wrote are retained as this instance's own source event"
    );
    let suspended = broker
        .binding_state(instance())
        .expect("the instance reads");
    assert!(
        suspended.rich_mutations_suspended,
        "an unclassified request suspends rich mutations"
    );
    assert!(!carrying.is_finished(), "and none of it has been written");

    // And a rich mutation is refused while that is true, which is the whole point of the order.
    let refused = broker
        .agent_prompt(
            &kr_worker::broker::Caller {
                actor_id: ActorId::new("device-1").expect("valid"),
                grant_id: None,
            },
            &kr_protocol::agent::AgentPromptParams {
                target: target(),
                draft_id: Nullable::null(),
                text: Nullable::some(kr_protocol::agent::PromptText::new("hello").expect("valid")),
            },
            false,
            TimestampMs::new(3),
        )
        .await
        .expect_err("rich mutations are suspended");
    assert_eq!(
        refused.code(),
        kr_protocol::error::ErrorCode::DraftConflict,
        "a precondition the instance has stopped meeting"
    );

    carrying.abort();
    drop(upstream_there);
    drained.abort();
}

/// KR-REQ-11.30: a client request the table does classify is recorded and leaves rich mutations
/// alone, and what became of its bytes is recorded too.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_11_30_a_classified_client_request_is_recorded_and_suspends_nothing() {
    let broker = broker();
    let served = duplex_watched(&broker).await;
    let owner = Arc::clone(&served.owner);
    let mut upstream = tokio::io::BufReader::new(served.upstream);

    let carried = owner
        .from_client(
            br#"{"id":11,"method":"session/update","params":{"from":"the terminal"}}"#,
            TimestampMs::new(2),
        )
        .await
        .expect("the terminal's own request is carried");
    let Carried::ClientRequest {
        classification,
        suspended_rich_mutations,
        ..
    } = carried
    else {
        panic!("a request of the client's is what this was");
    };
    assert!(classification.declared, "the table lists this method");
    assert_eq!(classification.class, NativeMethodClass::Observation);
    assert!(!suspended_rich_mutations);
    assert!(
        !broker
            .binding_state(instance())
            .expect("the instance reads")
            .rich_mutations_suspended,
        "a method this host can classify suspends nothing"
    );
    let _ = next_line(&mut upstream).await;
    let recorded = broker
        .client_requests()
        .expect("the records read")
        .into_iter()
        .next()
        .expect("the request was recorded");
    assert_eq!(recorded.method, method("session/update"));
    assert!(recorded.classification.declared);
    assert_eq!(
        recorded.outcome,
        kr_worker::broker::ClientRequestOutcome::Transmitted,
        "and what became of its bytes is recorded"
    );

    served.drained.abort();
}

/// KR-REQ-09 and KR-REQ-11.33: a write that blocks, one that goes in part and a reply that never
/// comes are never a success, and nothing is sent again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_11_33_a_blocked_partial_or_unanswered_write_is_never_a_success() {
    // A peer that reads nothing. The answer to the client goes into a pipe of a few bytes, so the
    // frame goes in part and stops.
    let broker = broker();
    let (upstream_here, upstream_there) = tokio::io::duplex(8);
    let (client_here, client_there) = tokio::net::UnixStream::pair().expect("a socket pair");
    let mut observations = broker.observatory().subscribe(GatewayConnectionId::new(1));
    let (owner, writes) = Duplex::new(
        Arc::clone(&broker),
        GatewayConnectionId::new(1),
        Framing::new(NativeFraming::JsonLines),
        upstream_here,
        tokio::io::split(client_here).1,
        EnvironmentId::new(Uuid::from_bytes([4; 16])),
        "agent-user",
    );
    let drained = tokio::spawn(writes);
    let mut client = tokio::io::BufReader::new(client_there);

    owner
        .from_upstream(
            br#"{"id":31,"method":"session/request_permission","params":{}}"#,
            TimestampMs::new(2),
        )
        .await
        .expect("the request is carried");
    let _ = next_line(&mut client).await;
    let resource = broker
        .pending_resources()
        .into_iter()
        .find(|resource| resource.state == PendingState::Pending)
        .expect("the request is pending");

    // The person's answer is admitted, and its bytes fill the pipe and stop. What the caller is
    // told is that nothing can be established, and the resource says so.
    let long = "x".repeat(4096);
    let answer =
        serde_json::json!({ "id": 31, "result": { "outcome": "allow", "why": long } }).to_string();
    let refusal = owner
        .from_client(answer.as_bytes(), TimestampMs::new(3))
        .await
        .expect_err("a frame that went in part is not an answer that arrived");
    assert_eq!(
        refusal.code(),
        kr_protocol::error::ErrorCode::UpstreamUnavailable
    );
    assert_eq!(
        broker
            .pending(resource.resource_id)
            .expect("recorded")
            .state,
        PendingState::Uncertain,
        "an answer whose fate nobody can establish leaves the resource uncertain"
    );

    // And it is never sent again: a second attempt is refused by the arbitration rather than
    // writing the same answer twice.
    assert!(
        owner
            .from_client(answer.as_bytes(), TimestampMs::new(4))
            .await
            .is_err(),
        "an uncertain answer is not replayed"
    );
    // What the observers are told is the uncertainty, not a resolution: every authorised watcher
    // of the instance learns the state the resource actually reached.
    let transition = settlement_of(&mut observations, resource.resource_id).await;
    assert_eq!(transition.state, PendingState::Uncertain);
    drop(upstream_there);
    drained.abort();
}

/// KR-REQ-07.67: an intentional native exit stops the dedicated backend, and an attachment closing
/// does not.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_07_67_an_intentional_native_exit_stops_the_dedicated_backend() {
    // A real child process of this test, on the internal disk, which is what a dedicated backend
    // is: something this host started and can name in full.
    let mut child = tokio::process::Command::new("/bin/sh")
        .arg("-c")
        .arg("while true; do sleep 1; done")
        .current_dir(std::env::temp_dir())
        .spawn()
        .expect("the backend starts");
    let pid = child.id().expect("the child has an identifier");
    let identity =
        kr_ipc::identity::process_start_identity(pid).expect("the kernel names the child");
    assert!(matches!(
        kr_ipc::identity::process_state(&identity),
        kr_ipc::identity::ProcessState::Running
    ));

    let stopped =
        kr_worker::broker::stop_backend(&identity, std::time::Duration::from_secs(5)).await;
    assert!(
        stopped.asked,
        "the process this host started was asked to stop"
    );
    assert!(stopped.ended, "and it ended");
    assert!(
        !stopped.forced,
        "a shell that takes a termination signal does not have to be forced"
    );
    let _ = child.wait().await;

    // An identity nothing is running under is never signalled: section 7 stops the process this
    // host started, not whatever holds that identifier now.
    let again = kr_worker::broker::stop_backend(&identity, std::time::Duration::from_secs(1)).await;
    assert!(
        !again.asked,
        "nothing is signalled for a process that has gone"
    );
    assert!(again.ended);
}

/// KR-REQ-07.67: the terminal's own exit ends the connection as an intentional native exit, and a
/// connection that closes while that terminal is still running does not.
///
/// The backend of this instance is not one this host dedicated, so nothing is claimed or
/// terminated as owned, which is section 7's other half. The grace period itself is proved against
/// a real child process above, and a live dedicated backend below.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_07_67_a_terminal_exit_ends_the_connection_and_an_attachment_closing_does_not() {
    for exits in [true, false] {
        let directory = private_directory();
        let (broker, running) = broker_expecting_this_process();
        // A terminal of this host's own, as a real process the kernel names.
        let mut terminal = sleeper();
        let pid = terminal.id().expect("the terminal has an identifier");
        let identity =
            kr_ipc::identity::process_start_identity(pid).expect("the kernel names the terminal");
        let mut launch = launch_for(Some(running.clone()), Some(identity));
        launch.application_instance_id = instance();
        let gateway =
            kr_worker::broker::NativeGateway::bind(Arc::clone(&broker), &directory, launch)
                .expect("the endpoint binds");
        let kr_worker::broker::ListenerAddress::PrivateSocket(path) = gateway.address().clone()
        else {
            panic!("this platform prefers a private socket");
        };
        let bridging = tokio::spawn(async move {
            let mut stream = tokio::net::UnixStream::connect(&path)
                .await
                .expect("the bridge connects");
            stream
                .write_all(&hello_bytes(&running, &[]))
                .await
                .expect("the bridge says who it is");
            stream
        });
        let (client_here, _client_there) = tokio::net::UnixStream::pair().expect("a socket pair");
        let (client_reads, client_writes) = tokio::io::split(client_here);
        let mut attached = gateway
            .accept(client_reads, client_writes)
            .await
            .expect("the bridge is admitted");
        let bridge = bridging.await.expect("the bridge task finished");

        // Either the terminal exits and then the connection closes, or the connection closes and
        // the terminal goes on running.
        if exits {
            terminal.kill().await.expect("the terminal is ended");
            let _ = terminal.wait().await;
        }
        drop(bridge);
        let ended = tokio::time::timeout(std::time::Duration::from_secs(20), attached.served())
            .await
            .expect("the connection ends")
            .expect("its task is joined");
        let watching = attached
            .terminal
            .take()
            .expect("this host started a terminal");
        if exits {
            assert_eq!(
                ended.closure,
                kr_worker::broker::Closure::NativeExit,
                "the terminal exiting is the intentional native exit"
            );
            let stopped =
                tokio::time::timeout(std::time::Duration::from_secs(20), watching.exited())
                    .await
                    .expect("the supervision reports")
                    .expect("its task is joined");
            assert!(
                stopped.is_none(),
                "and a backend this host did not dedicate is never terminated as owned"
            );
            assert!(
                broker.pending_resources().is_empty(),
                "the instance and everything it held have gone"
            );
        } else {
            assert_eq!(
                ended.closure,
                kr_worker::broker::Closure::Detached,
                "an attachment closing is not an exit"
            );
            assert!(
                matches!(
                    kr_ipc::identity::process_state(
                        &kr_ipc::identity::process_start_identity(pid).expect("readable")
                    ),
                    kr_ipc::identity::ProcessState::Running
                ),
                "the terminal is still there"
            );
            // End of file came first and the exit comes now, long after the connection was torn
            // down. The supervision is still watching, so the exit is still the exit.
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            terminal.kill().await.expect("the terminal is ended");
            let _ = terminal.wait().await;
            let stopped =
                tokio::time::timeout(std::time::Duration::from_secs(20), watching.exited())
                    .await
                    .expect("the supervision is still watching after the socket has gone")
                    .expect("its task is joined");
            assert!(
                stopped.is_none(),
                "a backend this host did not dedicate is never terminated as owned"
            );
            assert!(
                broker.binding_state(instance()).is_err(),
                "and the instance the terminal was running ended with it"
            );
        }
        let _ = std::fs::remove_dir_all(&directory);
    }
}

/// KR-REQ-07.67: a terminal exiting stops the live backend this host dedicated to it, whether or
/// not anything about the connection has happened.
///
/// The connection stays open and the backend this host launched stays live for the whole of this
/// test. The terminal exits well after any window a teardown could have waited, and the backend is
/// stopped, because what is watched is the process rather than the socket.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_07_67_a_terminal_that_exits_stops_the_live_backend_dedicated_to_it() {
    let directory = private_directory();
    let broker = broker_for_launch();
    let mut terminal = sleeper();
    let terminal_pid = terminal.id().expect("the terminal has an identifier");
    let terminal_identity = kr_ipc::identity::process_start_identity(terminal_pid)
        .expect("the kernel names the terminal");
    let mut gateway = kr_worker::broker::NativeGateway::bind(
        Arc::clone(&broker),
        &directory,
        launch_for(None, Some(terminal_identity)),
    )
    .expect("the endpoint binds");

    // The backend is the process this host starts for this instance, which is what makes it
    // dedicated. It is alive for the whole of this test until the terminal's exit stops it.
    let intent = broker
        .prepare_launch(
            forwarder_profile(),
            kr_worker::broker::ForegroundMark::idle(4),
            None,
        )
        .expect("the launch is prepared");
    let mut launched = gateway
        .launch(
            &intent,
            &kr_worker::broker::ForegroundMark::idle(4),
            IntegrationMode::Gateway,
            TimestampMs::new(1),
        )
        .expect("the agent is started");
    broker
        .pin_table(instance(), table(), rich())
        .expect("the installed tables are pinned");
    bind_component(&broker);
    record_capabilities(&broker);

    let (client_here, _client_there) = tokio::net::UnixStream::pair().expect("a socket pair");
    let (client_reads, client_writes) = tokio::io::split(client_here);
    let mut attached = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        gateway.accept(client_reads, client_writes),
    )
    .await
    .expect("the forwarder reaches the endpoint")
    .expect("it is authenticated and admitted");
    assert!(
        matches!(
            kr_ipc::identity::process_state(&launched.process),
            kr_ipc::identity::ProcessState::Running
        ),
        "the backend this host launched is serving"
    );

    // Nothing has happened to the connection, and nothing needs to: the terminal exits well after
    // any window a teardown could have waited, and that is the event.
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    terminal.kill().await.expect("the terminal is ended");
    let _ = terminal.wait().await;

    let watching = attached
        .terminal
        .take()
        .expect("this host started a terminal");
    let stopped = tokio::time::timeout(std::time::Duration::from_secs(20), watching.exited())
        .await
        .expect("the supervision reports")
        .expect("its task is joined")
        .expect("a dedicated backend is stopped");
    assert!(stopped.asked, "the backend was asked to stop");
    assert!(stopped.ended, "and this host waited until it had");
    let _ = launched.child.wait();
    assert!(
        matches!(
            kr_ipc::identity::process_state(&launched.process),
            kr_ipc::identity::ProcessState::Ended
        ),
        "the backend has gone"
    );
    assert!(
        broker.binding_state(instance()).is_err(),
        "and the instance the terminal was running ended with it"
    );

    let _ = std::fs::remove_dir_all(&directory);
}

/// A real child process that does nothing until it is ended, on the internal disk.
fn sleeper() -> tokio::process::Child {
    tokio::process::Command::new("/bin/sh")
        .arg("-c")
        .arg("while true; do sleep 1; done")
        .current_dir(std::env::temp_dir())
        .spawn()
        .expect("the process starts")
}
