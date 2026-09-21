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

/// Every transition the outbox holds, read the way a recovery reads it: one page at a time.
fn outbox(broker: &Broker) -> Vec<kr_worker::broker::TransitionEvent> {
    let mut cursor = broker.stream_start();
    let mut recorded = Vec::new();
    loop {
        let replay = broker.replay_after(cursor).expect("the outbox reads");
        recorded.extend(replay.events);
        cursor = replay.cursor;
        if !replay.more {
            return recorded;
        }
    }
}

/// Everything recorded after one position of this broker's current stream.
fn outbox_after(broker: &Broker, sequence: u64) -> Vec<kr_worker::broker::TransitionEvent> {
    let mut cursor = kr_worker::broker::ReplayCursor {
        generation: broker.stream_generation(),
        sequence,
    };
    let mut recorded = Vec::new();
    loop {
        let replay = broker.replay_after(cursor).expect("the outbox reads");
        recorded.extend(replay.events);
        cursor = replay.cursor;
        if !replay.more {
            return recorded;
        }
    }
}

/// The same broker over a journal on disk, which is what a restart reads back.
///
/// The connection comes back with it: a restart numbers its connections above everything the
/// ledger has seen, so the one this opens is not the one the process before it had.
fn broker_at(journal: &std::path::Path) -> (Arc<Broker>, GatewayConnectionId) {
    broker_from(
        Broker::open(Some(journal), session()).expect("the broker opens"),
        rich(),
    )
}

fn broker_with_rich(rich: RichMethodTable) -> Arc<Broker> {
    broker_from(
        Broker::open(None, session()).expect("the broker opens"),
        rich,
    )
    .0
}

fn broker_from(broker: Broker, rich: RichMethodTable) -> (Arc<Broker>, GatewayConnectionId) {
    let broker = Arc::new(broker);
    let connection = prepare_broker(&broker, rich);
    (broker, connection)
}

/// Registers the instance, pins its tables and opens one native connection on a broker.
fn prepare_broker(broker: &Arc<Broker>, rich: RichMethodTable) -> GatewayConnectionId {
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
    let connection = broker
        .open_native_connection(
            instance(),
            &CREDENTIAL,
            &process_identity(),
            &package(),
            "1",
        )
        .expect("the native connection is authenticated");
    record_capabilities(broker);
    connection
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
    duplex_watched_on(broker, GatewayConnectionId::new(1)).await
}

/// The same over one named connection, which a restart's own connection needs.
async fn duplex_watched_on(broker: &Arc<Broker>, connection: GatewayConnectionId) -> Served {
    let (upstream_here, upstream_there) =
        tokio::net::UnixStream::pair().expect("a socket pair is made");
    let (client_here, client_there) =
        tokio::net::UnixStream::pair().expect("a socket pair is made");
    let framing = Framing::new(NativeFraming::JsonLines);
    let observations = broker.observatory().subscribe(connection);
    let (upstream_reads, upstream_writes) = tokio::io::split(upstream_here);
    let (owner, writes) = Duplex::new(
        Arc::clone(broker),
        connection,
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
    let mut attached = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        gateway.accept(client_reads, client_writes),
    )
    .await
    .expect("the forwarder reaches the endpoint")
    .expect("it is authenticated and admitted");
    let mut observations = attached
        .observations
        .take()
        .expect("the composition subscribed this connection");
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
        .await
        .expect("a notification is carried");
    assert_eq!(
        notification,
        Carried::UpstreamRequest {
            method: method("session/update"),
            resource_id: None,
        },
        "a notification names no request and resolves nothing"
    );
    // The upstream reusing its own live identifier is one party naming two requests the same, and
    // that is refused exactly, with nothing performed.
    let duplicate = owner
        .from_upstream(
            br#"{"id":7,"method":"fs/read_text_file","params":{"path":"/nowhere"}}"#,
            TimestampMs::new(4),
        )
        .await
        .expect_err("one identifier names one live request");
    assert_eq!(
        duplicate.code(),
        kr_protocol::error::ErrorCode::InvalidArgument
    );
    // Under an identifier of its own it is a reverse request, refused in place because no host
    // resource has been granted for it.
    let reverse = owner
        .from_upstream(
            br#"{"id":70,"method":"fs/read_text_file","params":{"path":"/nowhere"}}"#,
            TimestampMs::new(4),
        )
        .await
        .expect("a reverse request is carried");
    assert_eq!(
        reverse,
        Carried::Reverse {
            operation: ReverseOperation::FilesystemRead,
            performed: false,
        }
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

/// Waits for one resource to reach a state nothing follows, and returns it.
async fn settled_within(
    broker: &Arc<Broker>,
    resource_id: kr_protocol::ids::PendingResourceId,
    within: std::time::Duration,
) -> Option<PendingState> {
    let deadline = tokio::time::Instant::now() + within;
    loop {
        let state = broker.pending(resource_id).map(|resource| resource.state);
        if state.is_some_and(PendingState::is_terminal) {
            return state;
        }
        if tokio::time::Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
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

    // A third resource, settled by two paths racing each other. One of them wins; the other is
    // refused; and whichever way it goes, the events about that one resource arrive in the order
    // they were committed in and name each other as parents.
    owner
        .from_upstream(
            br#"{"id":43,"method":"session/request_permission","params":{}}"#,
            TimestampMs::new(5),
        )
        .await
        .expect("the request is carried");
    let _ = next_line(&mut client).await;
    let contested = broker
        .pending_resources()
        .into_iter()
        .find(|resource| resource.state == PendingState::Pending)
        .expect("the third request is pending");
    let racing = {
        let owner = Arc::clone(&owner);
        tokio::spawn(async move {
            owner
                .from_client(
                    br#"{"id":43,"result":{"outcome":"allow"}}"#,
                    TimestampMs::new(6),
                )
                .await
        })
    };
    let withdrawing = {
        let owner = Arc::clone(&owner);
        tokio::spawn(async move {
            owner
                .from_upstream(
                    br#"{"id":43,"result":{"outcome":"deny"}}"#,
                    TimestampMs::new(7),
                )
                .await
        })
    };
    let answered = racing.await.expect("the task finished");
    let withdrawn = withdrawing.await.expect("the task finished");
    assert!(
        answered.is_ok() || withdrawn.is_ok(),
        "one of the two settled it"
    );
    let settled = settled_within(
        &broker,
        contested.resource_id,
        std::time::Duration::from_secs(20),
    )
    .await
    .expect("the contested resource reaches a state nothing follows");
    assert!(settled.is_terminal());

    // What the race produced is drained from both observers, so the order it was announced in is
    // compared rather than assumed: two paths settling one resource is exactly where an order
    // could differ between two observers, and it does not.
    let raced_first = told(&mut first).await;
    let raced_second = told(&mut second).await;
    assert_eq!(
        raced_first, raced_second,
        "both observers read the race in the same order"
    );
    assert!(
        raced_first.windows(2).all(|pair| pair[0].0 < pair[1].0),
        "and in the order the transitions committed: {raced_first:?}"
    );
    assert!(
        told(&mut unrelated).await.is_empty(),
        "and the observer of another instance still reads none of it"
    );
    let announced: Vec<(u64, PendingState)> = told_first
        .iter()
        .copied()
        .chain(raced_first.iter().copied())
        .collect();

    // And the outbox holds exactly what was announced, because it was written with it.
    let recorded = outbox(&broker);
    // Each resource's own events form a chain: the first names no parent and every later one
    // names the event before it, so a consumer can see that it has read them in order.
    for resource_id in [contested.resource_id] {
        let chain: Vec<&kr_worker::broker::TransitionEvent> = recorded
            .iter()
            .filter(|event| event.resource_id == resource_id)
            .collect();
        assert!(chain.len() >= 2, "recorded, then settled: {}", chain.len());
        assert_eq!(chain[0].parent_sequence, None, "the first names no parent");
        assert_eq!(
            chain[0].cause,
            kr_worker::broker::TransitionCause::Recorded,
            "and it is the recording"
        );
        for pair in chain.windows(2) {
            assert_eq!(
                pair[1].parent_sequence,
                Some(pair[0].sequence),
                "each event names the one before it"
            );
        }
        assert!(
            chain.last().expect("a last event").state.is_terminal(),
            "the chain ends where the resource did"
        );
    }
    let identifiers: std::collections::BTreeSet<_> =
        recorded.iter().map(|event| event.event_id).collect();
    assert_eq!(
        identifiers.len(),
        recorded.len(),
        "every event identifies itself, which is what a consumer deduplicates on"
    );
    assert_eq!(
        recorded
            .iter()
            .map(|event| (event.sequence, event.state))
            .collect::<Vec<_>>(),
        announced,
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

/// KR-REQ-11.27 and KR-REQ-12.11: a claim is given back when the upstream resolves underneath it.
///
/// A rich answer claims the resource before it dispatches. The upstream can withdraw its own
/// request in that window, and one of the two has to lose: what must not happen is a resource
/// that ends resolved with a claim still on it, or a claim released against a resource the claim
/// never held. Whichever wins, the chain the outbox holds ends terminal and the claim does not
/// outlive it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_11_27_a_claim_is_given_back_when_the_upstream_resolves_underneath_it() {
    let broker = broker();
    let served = duplex_watched(&broker).await;
    let owner = Arc::clone(&served.owner);
    let mut client = tokio::io::BufReader::new(served.client);
    let answered = Arc::new(std::sync::Mutex::new(Vec::new()));
    let upstream_reader = acknowledge(served.upstream, Arc::clone(&answered));

    owner
        .from_upstream(
            br#"{"id":95,"method":"session/request_permission","params":{}}"#,
            TimestampMs::new(2),
        )
        .await
        .expect("the request is carried");
    let _ = next_line(&mut client).await;
    let resource_id = broker
        .pending_resources()
        .into_iter()
        .find(|resource| resource.state == PendingState::Pending)
        .expect("the request is recorded")
        .resource_id;
    broker
        .interpret(
            binding(),
            resource_id,
            projection(),
            None,
            TimestampMs::new(3),
        )
        .expect("the interpretation is verified");
    let dispatch = owner.dispatch().expect("the link carries operations");
    broker.bind_connection_dispatch(GatewayConnectionId::new(1), dispatch);

    // A rich answer and the upstream's own withdrawal, at once.
    let caller = kr_worker::broker::Caller {
        actor_id: ActorId::new("device-1").expect("valid"),
        grant_id: None,
    };
    let params = kr_protocol::agent::AgentApprovalRespondParams {
        target: target(),
        resource_id,
        option_id: "allow".to_owned(),
    };
    let admitted = broker
        .admit_approval(&caller, &params, TimestampMs::new(4))
        .expect("the approval response is admitted and the claim is acquired");
    let claim = admitted.claim().expect("the admission holds a claim");

    let claiming = {
        let broker = Arc::clone(&broker);
        let claim = claim.clone();
        tokio::spawn(async move { broker.release_claim(&claim, TimestampMs::new(5)) })
    };
    let withdrawing = {
        let owner = Arc::clone(&owner);
        tokio::spawn(async move {
            owner
                .from_upstream(
                    br#"{"id":95,"result":{"outcome":"deny"}}"#,
                    TimestampMs::new(6),
                )
                .await
        })
    };
    let rich = claiming.await.expect("the rich task finished");
    let upstream = withdrawing.await.expect("the upstream task finished");
    assert!(
        rich.is_ok() || upstream.is_ok(),
        "one of the two settled it"
    );

    let settled = settled_within(&broker, resource_id, std::time::Duration::from_secs(20))
        .await
        .expect("the resource reaches a state nothing follows");
    assert!(settled.is_terminal());
    let held = broker.pending(resource_id).expect("it is still readable");
    assert!(
        held.state.is_terminal(),
        "a resource nothing can answer any more is not one a claim still holds: {:?}",
        held.state
    );

    // The chain says the same: a claim that was taken was given back or carried into the
    // settlement, and the last event about the resource is the terminal one.
    let recorded = outbox(&broker);
    let chain: Vec<&kr_worker::broker::TransitionEvent> = recorded
        .iter()
        .filter(|event| event.resource_id == resource_id)
        .collect();
    assert!(
        chain
            .last()
            .expect("the resource has events")
            .state
            .is_terminal(),
        "the chain ends where the resource did: {chain:?}"
    );
    let position = chain
        .iter()
        .position(|event| event.cause == kr_worker::broker::TransitionCause::RichClaim)
        .expect("a claim event was recorded on the resource");
    assert!(
        position + 1 < chain.len(),
        "a claim is never the last thing that happened to a resource"
    );

    upstream_reader.abort();
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
    let served = duplex_watched(&broker).await;
    // This connection's own subscription, taken by the composition rather than beside it: a second
    // subscribe for one connection replaces the first, and reading a receiver nobody publishes to
    // would pass this test without proving anything.
    let mut watching = served.observations;
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
        !seen.is_empty(),
        "the observer read what it could before it fell behind"
    );
    assert!(
        seen.len() <= kr_worker::broker::MAX_QUEUED_OBSERVATIONS,
        "and the queue it read from is bounded: {}",
        seen.len()
    );
    // Withdrawn, not grown: nothing after the overflow reaches it, however long it waits.
    owner
        .from_upstream(
            br#"{"id":900,"method":"session/request_permission","params":{}}"#,
            TimestampMs::new(4),
        )
        .await
        .expect("the request is carried");
    let _ = next_line(&mut client).await;
    owner
        .from_upstream(
            br#"{"id":900,"result":{"outcome":"deny"}}"#,
            TimestampMs::new(5),
        )
        .await
        .expect("the upstream withdraws it");
    assert!(
        told(&mut watching).await.is_empty(),
        "a subscription that overflowed is withdrawn rather than resumed"
    );
    assert!(
        outbox(&broker).len() >= overflow,
        "and every transition is still recorded, whatever any observer read"
    );

    served.drained.abort();
}

/// Builds one owner over two in-memory pipes, for the tests that need no real socket.
fn duplex_over_pipes(
    broker: &Arc<Broker>,
    capacity: usize,
) -> (
    Arc<Duplex>,
    tokio::io::DuplexStream,
    tokio::io::DuplexStream,
    impl std::future::Future<Output = ()> + Send + use<>,
) {
    duplex_over_sized_pipes(broker, capacity, capacity)
}

/// The same, with the two pipes sized apart.
///
/// A test about what the upstream end holds needs that end to be the narrow one, and needs the
/// terminal's end wide enough to read what it is told while the other end is blocked.
fn duplex_over_sized_pipes(
    broker: &Arc<Broker>,
    upstream_capacity: usize,
    client_capacity: usize,
) -> (
    Arc<Duplex>,
    tokio::io::DuplexStream,
    tokio::io::DuplexStream,
    impl std::future::Future<Output = ()> + Send + use<>,
) {
    let (upstream_here, upstream_there) = tokio::io::duplex(upstream_capacity);
    let (client_here, client_there) = tokio::io::duplex(client_capacity);
    let (owner, writes) = Duplex::new(
        Arc::clone(broker),
        GatewayConnectionId::new(1),
        Framing::new(NativeFraming::JsonLines),
        upstream_here,
        client_here,
        EnvironmentId::new(Uuid::from_bytes([4; 16])),
        "agent-user",
    );
    (owner, upstream_there, client_there, writes)
}

/// KR-REQ-11.32 and KR-REQ-09: a full byte queue refuses in place, and the connection says so.
///
/// The bound on what one end holds is in bytes, and the frame that meets it is the frame this host
/// has already taken off the socket. Three things follow and all three are tested here. What was
/// admitted before the bound still goes: drainage returns before the write deadline and every one
/// of those frames reaches the upstream, under its own identifier and in the order it was
/// admitted. The bound then refuses a frame the connection's own reader took off the socket, while
/// the queue is full, without taking a byte for it. And that frame is not quietly dropped: the
/// connection that took it ends, and every request the terminal was still waiting on is answered
/// once under the identifier the terminal used.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_11_32_a_full_byte_queue_refuses_in_place_and_ends_the_connection_that_took_it() {
    let broker = broker();
    // An upstream pipe that takes almost nothing, so what is queued for it stays queued, and a
    // terminal end wide enough to read what this host answers while that one is blocked.
    let (owner, mut upstream, mut client, writes) = duplex_over_sized_pipes(&broker, 64, 1 << 20);
    let drained = tokio::spawn(writes);

    // Measured from before any write of this connection can start, so what it bounds is every
    // write deadline that could have run, not only the last one.
    let writing_could_start = std::time::Instant::now();
    // Frames large enough that a handful of them passes the byte bound.
    let padding = "x".repeat(64 * 1024);
    let (admitted, first_refused, refusal) = fill_byte_queue(&owner, &padding, 0).await;
    assert!(
        !admitted.is_empty(),
        "the bound is reached by what was queued, not by the first frame"
    );
    assert!(
        owner.queued_to_upstream() <= kr_worker::broker::MAX_QUEUED_BYTES,
        "nothing beyond the bound was taken"
    );
    assert_eq!(
        refusal.code(),
        kr_protocol::error::ErrorCode::UpstreamUnavailable,
        "and the refusal says the connection could not carry it"
    );

    // Drainage returns. Everything admitted before the bound goes, under its own identifier and in
    // the order it was admitted.
    let mut reader = tokio::io::BufReader::new(&mut upstream);
    let mut arrived = Vec::new();
    while arrived.len() < admitted.len() {
        let line = tokio::time::timeout(
            std::time::Duration::from_secs(20),
            next_line_from(&mut reader),
        )
        .await
        .expect("the queued frames go once the peer reads again");
        let body: serde_json::Value = serde_json::from_str(line.trim()).expect("a frame");
        assert!(
            body.get("id").is_some_and(serde_json::Value::is_string),
            "a forwarded frame carries an identifier this host minted, not the terminal's: {line}"
        );
        arrived.push(
            u32::try_from(
                body.get("params")
                    .and_then(|params| params.get("seq"))
                    .and_then(serde_json::Value::as_u64)
                    .expect("a forwarded frame carries the terminal's parameters untouched"),
            )
            .expect("the identifier this test wrote"),
        );
    }
    assert_eq!(
        arrived, admitted,
        "every frame admitted before the bound reached the upstream, in the order it was admitted"
    );

    // The peer stops reading again and the queue is filled back to the bound, so the frame the
    // connection's own reader is about to take is refused by the byte bound and by nothing else.
    drop(reader);
    let (second, refused_id, _) = fill_byte_queue(&owner, &padding, 1_000).await;
    let held = owner.queued_to_upstream();
    assert!(
        held > 0 && held <= kr_worker::broker::MAX_QUEUED_BYTES,
        "the queue is full again before the reader is given the frame"
    );

    // The refused frame, read off the socket by the connection's own reader. The queue is full
    // while it is processed, no byte is taken for it, and the connection ends. This happens
    // immediately after the fill, so no write deadline has run: what ends the connection is the
    // refusal.
    let (mut feeding, fed) = tokio::io::duplex(1 << 20);
    let serving = {
        let owner = Arc::clone(&owner);
        tokio::spawn(async move { owner.serve(fed, false).await })
    };
    // Under an identifier of its own, so this is one request the terminal made rather than a
    // second submission of one the bound has already refused and answered.
    let taken_id = refused_id.saturating_add(1);
    feeding
        .write_all(format!("{}\n", client_frame(taken_id, &padding)).as_bytes())
        .await
        .expect("the terminal writes the frame this host cannot carry");
    tokio::time::timeout(kr_worker::broker::WRITE_DEADLINE, serving)
        .await
        .expect("the reader ends rather than dropping the frame it took")
        .expect("its task is joined");
    // Every write this connection ever started did so after this point, and none of them has had
    // its deadline yet. So what ended the connection is the refusal and nothing else.
    let took = writing_could_start.elapsed();
    assert!(
        took < kr_worker::broker::WRITE_DEADLINE,
        "the connection ended on the byte bound's refusal rather than on a write that timed out: \
         {took:?}"
    );
    assert!(
        owner.stopping(),
        "a frame that was taken and could not be carried ends the connection"
    );
    assert!(
        owner.queued_to_upstream() <= held,
        "and the refused frame was refused in place: the queue took no byte for it"
    );

    // The terminal is answered once for every request it made, under its own identifiers: the ones
    // still waiting when the connection ended, and the ones the byte bound refused. A refusal is
    // an answer to the terminal, not a silence, and neither is answered twice.
    let told = read_available(&mut client).await;
    let mut answers: std::collections::BTreeMap<u32, usize> = std::collections::BTreeMap::new();
    for line in told.lines().filter(|line| !line.trim().is_empty()) {
        let body: serde_json::Value = serde_json::from_str(line.trim()).expect("a response frame");
        assert!(
            body.get("error").is_some(),
            "a connection that ended answers what it holds with an error: {line}"
        );
        let id = u32::try_from(
            body.get("id")
                .and_then(serde_json::Value::as_u64)
                .expect("a response carries the identifier the terminal used"),
        )
        .expect("the identifier this test wrote");
        *answers.entry(id).or_default() += 1;
    }
    for id in admitted
        .iter()
        .chain(second.iter())
        .chain([&first_refused, &refused_id, &taken_id])
    {
        assert_eq!(
            answers.get(id).copied(),
            Some(1),
            "the terminal is told exactly once about request {id}"
        );
    }
    assert_eq!(
        answers.len(),
        admitted.len() + second.len() + 3,
        "and about nothing else: {answers:?}"
    );

    drained.abort();
}

/// One request the terminal makes of its upstream, padded to a size the byte bound notices.
///
/// The terminal's own number is in the parameters as well as in the envelope, because the envelope
/// identifier is replaced on the way out: this host mints its own for the upstream and maps the
/// answer back. The parameters are forwarded untouched, so they are what says which frame arrived.
fn client_frame(id: u32, padding: &str) -> String {
    format!(r#"{{"id":{id},"method":"session/update","params":{{"seq":{id},"pad":"{padding}"}}}}"#)
}

/// Fills the upstream byte queue to its bound, and returns what was admitted and what was refused.
async fn fill_byte_queue(
    owner: &Arc<Duplex>,
    padding: &str,
    first: u32,
) -> (Vec<u32>, u32, kr_worker::broker::error::BrokerError) {
    let mut admitted = Vec::new();
    for id in first..first.saturating_add(64) {
        match owner
            .from_client(client_frame(id, padding).as_bytes(), TimestampMs::new(2))
            .await
        {
            Ok(_) => admitted.push(id),
            Err(error) => return (admitted, id, error),
        }
    }
    panic!("the byte bound refuses a frame");
}

/// Reads one line from a buffered reader, for a test that follows a stream of frames.
async fn next_line_from<R: tokio::io::AsyncBufRead + Unpin>(reader: &mut R) -> String {
    let mut line = String::new();
    tokio::io::AsyncBufReadExt::read_line(reader, &mut line)
        .await
        .expect("the stream is readable");
    line
}

/// KR-REQ-12.13 and KR-REQ-09: the client's own requests are bounded, given up on a deadline, and
/// cleared when the connection ends.
///
/// The upstream reads everything the terminal asks and answers none of it. What this host holds
/// for it is bounded, the entries do not outlive their deadline, and what is still waiting when
/// the connection ends is given back to the client rather than left in a map nobody reads.
#[tokio::test(start_paused = true)]
async fn kr_req_12_13_a_client_request_the_upstream_never_answers_is_bounded_and_given_up() {
    let broker = broker();
    let (owner, upstream, mut client, writes) = duplex_over_pipes(&broker, 1 << 20);
    let drained = tokio::spawn(writes);

    // One more request than this connection may have outstanding.
    let bound = kr_worker::broker::MAX_FORWARDED_CLIENT_REQUESTS;
    for id in 0..bound {
        owner
            .from_client(
                format!(r#"{{"id":{id},"method":"session/update","params":{{}}}}"#).as_bytes(),
                TimestampMs::new(2),
            )
            .await
            .expect("the terminal's own request is carried");
    }
    assert_eq!(owner.forwarded_client_requests(), bound);
    let refused = owner
        .from_client(
            br#"{"id":9999,"method":"session/update","params":{}}"#,
            TimestampMs::new(3),
        )
        .await
        .expect_err("a connection holds only what it can carry");
    assert_eq!(
        refused.code(),
        kr_protocol::error::ErrorCode::UpstreamUnavailable
    );
    assert_eq!(
        owner.forwarded_client_requests(),
        bound,
        "and the refusal added nothing"
    );
    // The caller is told, and so is the terminal: a request this host refused is answered under
    // the identifier the terminal used, rather than left for a person to wait on.
    let refusal = read_available(&mut client).await;
    assert!(
        refusal.contains("\"id\":9999") && refusal.contains("error"),
        "the terminal reads an error for the request the bound refused: {}",
        &refusal[..refusal.len().min(300)]
    );

    // The upstream reads them and answers none. The deadline is what removes them.
    tokio::time::advance(
        kr_worker::broker::CLIENT_REPLY_DEADLINE + std::time::Duration::from_secs(30),
    )
    .await;
    for _ in 0..200 {
        if owner.forwarded_client_requests() == 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert_eq!(
        owner.forwarded_client_requests(),
        0,
        "nothing waits for a reply that is not coming"
    );
    // And the terminal is told, under its own identifiers.
    let told = read_available(&mut client).await;
    assert!(
        told.contains("\"id\":0") && told.contains("error"),
        "the client reads an error for the request it made: {}",
        &told[..told.len().min(200)]
    );

    // What is still waiting when the connection ends is given up too.
    owner
        .from_client(
            br#"{"id":4242,"method":"session/update","params":{}}"#,
            TimestampMs::new(4),
        )
        .await
        .expect("one more is carried");
    assert_eq!(owner.forwarded_client_requests(), 1);
    owner.shutdown();
    tokio::time::timeout(std::time::Duration::from_secs(30), drained)
        .await
        .expect("the writers finish once admission has closed")
        .expect("their task is joined");
    assert_eq!(
        owner.forwarded_client_requests(),
        0,
        "a connection that ended holds nothing for an upstream that will never speak again"
    );
    let ending = read_available(&mut client).await;
    assert!(
        ending.contains("\"id\":4242") && ending.contains("error"),
        "and the terminal is told about the request that was still waiting: {}",
        &ending[..ending.len().min(300)]
    );
    // Nothing new is admitted afterwards, so nothing is recorded or mapped for a connection whose
    // writers have finished.
    let intents = broker.client_requests().expect("the records read").len();
    assert!(
        owner
            .from_client(
                br#"{"id":4243,"method":"session/update","params":{}}"#,
                TimestampMs::new(5),
            )
            .await
            .is_err(),
        "a connection that has stopped serving admits nothing"
    );
    assert_eq!(
        broker.client_requests().expect("the records read").len(),
        intents,
        "and it records nothing either"
    );
    assert_eq!(owner.forwarded_client_requests(), 0);
    drop(upstream);
}

/// KR-REQ-12.11 and section 24: every event says what class of content its resource holds.
///
/// Section 24 asks an event to carry a content classification. The method class the table gave
/// the request is a different thing, and both are on the event: one says what the method may do,
/// the other what a consumer would be reading if it followed the resource back to its retained
/// frame. An opaque request is the connector's own bytes; once a granted decoder's interpretation
/// is verified, what the resource offers is the decoded proposal.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_12_11_every_event_says_what_class_of_content_its_resource_holds() {
    use kr_worker::persistence::stores::ContentClass;

    let broker = broker();
    let served = duplex_watched(&broker).await;
    let mut observations = served.observations;
    let owner = Arc::clone(&served.owner);
    let mut client = tokio::io::BufReader::new(served.client);

    owner
        .from_upstream(
            br#"{"id":91,"method":"session/request_permission","params":{}}"#,
            TimestampMs::new(2),
        )
        .await
        .expect("the request is carried");
    let _ = next_line(&mut client).await;
    let opaque = broker
        .pending_resources()
        .into_iter()
        .find(|resource| resource.state == PendingState::Pending)
        .expect("the request is recorded");
    assert!(
        !opaque.interpretation_verified,
        "nothing has interpreted it yet"
    );
    let recorded = outbox(&broker);
    let first = recorded
        .iter()
        .find(|event| event.resource_id == opaque.resource_id)
        .expect("its recording is in the outbox");
    assert_eq!(
        first.content,
        ContentClass::TerminalContent,
        "an uninterpreted native frame is the widest class its bytes can be"
    );
    assert_eq!(
        first.classification.class,
        kr_protocol::gateway::NativeMethodClass::Mutation,
        "and the method class is its own field, about what the method may do"
    );

    // A granted decoder's interpretation is verified, which is what makes it answerable.
    broker
        .interpret(
            binding(),
            opaque.resource_id,
            projection(),
            None,
            TimestampMs::new(3),
        )
        .expect("the interpretation is verified");
    let after = outbox_after(&broker, first.sequence);
    let interpreted = after
        .iter()
        .find(|event| event.cause == kr_worker::broker::TransitionCause::Interpreted)
        .expect("the interpretation has an event of its own");
    assert_eq!(
        interpreted.content,
        ContentClass::AuthoredContent,
        "what a person is asked to answer is the decoded proposal, not the frame"
    );
    assert_eq!(
        interpreted.parent_sequence,
        Some(first.sequence),
        "and it follows the recording"
    );

    // An observer reading the live stream is told the same thing the outbox holds.
    let mut live = Vec::new();
    while let Ok(Some(transition)) =
        tokio::time::timeout(std::time::Duration::from_millis(250), observations.next()).await
    {
        live.push((transition.event_id, transition.content));
    }
    for event in recorded.iter().chain(after.iter()) {
        if let Some((_, content)) = live.iter().find(|(id, _)| *id == event.event_id) {
            assert_eq!(
                *content, event.content,
                "the live stream says what the outbox records"
            );
        }
    }
    assert!(
        live.iter().any(|(id, _)| *id == interpreted.event_id),
        "and the interpretation reached the observer"
    );

    served.drained.abort();
}

/// KR-REQ-12.11 and section 24: a restart goes on from the event it last announced.
///
/// The chain is what a consumer reads to know it has the whole of a resource's history. A restart
/// that began a second chain for a resource this host was already answering would make the two
/// indistinguishable, so the last event about each live resource comes back with the resource.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_12_11_a_restart_goes_on_from_the_event_it_last_announced() {
    let directory = private_directory();
    let journal = directory.join("broker.sqlite3");
    let recorded = {
        let (broker, connection) = broker_at(&journal);
        broker
            .forward_native(
                connection,
                br#"{"id":93,"method":"session/request_permission","params":{}}"#,
                TimestampMs::new(2),
            )
            .expect("the request is forwarded");
        outbox(&broker)
    };
    let last = recorded.last().expect("the recording").clone();
    assert_eq!(
        last.parent_sequence, None,
        "the first event names no parent"
    );
    assert_eq!(last.cause, kr_worker::broker::TransitionCause::Recorded);

    // A second process over the same journal: the resource comes back, and so does the event it
    // was last announced under.
    let (restarted, _) = broker_at(&journal);
    let restored = restarted
        .pending_resources()
        .into_iter()
        .find(|resource| resource.resource_id == last.resource_id)
        .expect("the unresolved resource comes back");
    assert_eq!(restored.state, PendingState::Pending);
    restarted
        .upstream_resolved(&restored.request, TimestampMs::new(4))
        .expect("the upstream withdraws its own request");
    let after = outbox_after(&restarted, last.sequence);
    let settlement = after
        .iter()
        .find(|event| event.resource_id == last.resource_id)
        .expect("the settlement is recorded");
    assert!(
        settlement.sequence > last.sequence,
        "the stream has one order across the restart"
    );
    assert_eq!(
        settlement.parent_sequence,
        Some(last.sequence),
        "and the chain goes on from the event this host last announced"
    );
    let _ = std::fs::remove_dir_all(&directory);
}

/// KR-REQ-12.11 and section 24: a position from an earlier run is not read as a position now.
///
/// A transition announced while the journal is faulted spends a number nothing records, and the
/// next run of the host numbers from what it did record — so the same numbers are handed out
/// twice. Comparing a saved number with this run's numbers would therefore hide real events: the
/// one recorded here as sequence 2 is a different event from the one the first run announced as
/// sequence 2. What makes the position readable is the generation beside it. This proves the
/// whole of that: real volatile events before the restart, the same numbers recorded after it,
/// and a replay that resets instead of skipping — before, at and after the point where the new
/// durable maximum passes the saved position.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_12_11_a_position_from_an_earlier_run_replays_the_stream_again() {
    let directory = private_directory();
    let journal = directory.join("broker.sqlite3");

    // One durable transition, then a journal that cannot be written. Everything the first run
    // announces from here on is published and not recorded.
    let (first_run, first_connection) = broker_at(&journal);
    assert_eq!(first_run.stream_generation(), 1);
    first_run
        .forward_native(
            first_connection,
            br#"{"id":101,"method":"session/request_permission","params":{}}"#,
            TimestampMs::new(2),
        )
        .expect("the first request is forwarded");
    let durable = outbox(&first_run);
    assert_eq!(
        durable.len(),
        1,
        "one transition was recorded before the journal faulted"
    );
    assert_eq!(durable[0].sequence, 1);

    first_run
        .enter_volatile("the journal could not be written", TimestampMs::new(3))
        .expect("the gateway enters volatile-native mode");
    for (id, at) in [(102, 4), (103, 5)] {
        first_run
            .forward_native(
                first_connection,
                format!(r#"{{"id":{id},"method":"session/request_permission","params":{{}}}}"#)
                    .as_bytes(),
                TimestampMs::new(at),
            )
            .expect("a volatile request is forwarded");
    }
    let volatile_cursor = kr_worker::broker::ReplayCursor {
        generation: first_run.stream_generation(),
        sequence: 3,
    };
    assert_eq!(
        outbox(&first_run).len(),
        1,
        "the volatile transitions were announced and not recorded"
    );
    let announced = first_run
        .replay_after(kr_worker::broker::ReplayCursor {
            generation: first_run.stream_generation(),
            sequence: 1,
        })
        .expect("the outbox reads");
    assert!(
        announced.gap,
        "and the run that announced them says so to anyone reading from before them"
    );
    drop(first_run);

    // The second run numbers from what was recorded, so it hands out 2 and 3 again.
    let (second_run, second_connection) = broker_at(&journal);
    assert_eq!(
        second_run.stream_generation(),
        2,
        "a new run is a new generation"
    );
    for (id, at) in [(104, 6), (105, 7)] {
        second_run
            .forward_native(
                second_connection,
                format!(r#"{{"id":{id},"method":"session/request_permission","params":{{}}}}"#)
                    .as_bytes(),
                TimestampMs::new(at),
            )
            .expect("a durable request is forwarded");
    }
    let recorded = outbox(&second_run);
    assert_eq!(
        recorded
            .iter()
            .map(|event| event.sequence)
            .collect::<Vec<_>>(),
        vec![1, 2, 3],
        "the same numbers the first run announced are now recorded for other events"
    );

    // The observer reconnects with the position it held. It names the first run, so the whole
    // stream is replayed and the observer is told to start again rather than continue.
    let replayed = second_run
        .replay_after(volatile_cursor)
        .expect("the outbox reads");
    assert!(
        replayed.reset,
        "a position from an earlier run is not comparable with this run's numbers"
    );
    assert_eq!(
        replayed
            .events
            .iter()
            .map(|event| event.sequence)
            .collect::<Vec<_>>(),
        vec![1, 2, 3],
        "so the stream is replayed from its start and nothing recorded is hidden"
    );
    assert_eq!(replayed.cursor.generation, 2);
    assert_eq!(replayed.cursor.sequence, 3);

    // The same holds before and at the point where the new maximum passes the saved position:
    // the answer never depends on how far this run has got.
    for sequence in [2_u64, 3, 4] {
        let replayed = second_run
            .replay_after(kr_worker::broker::ReplayCursor {
                generation: 1,
                sequence,
            })
            .expect("the outbox reads");
        assert!(replayed.reset, "position {sequence} is from another run");
        assert_eq!(
            replayed.events.len(),
            3,
            "and the whole recorded stream comes back for it"
        );
    }

    // A position from this run is compared, not reset.
    let continuing = second_run
        .replay_after(kr_worker::broker::ReplayCursor {
            generation: 2,
            sequence: 2,
        })
        .expect("the outbox reads");
    assert!(!continuing.reset);
    assert_eq!(
        continuing
            .events
            .iter()
            .map(|event| event.sequence)
            .collect::<Vec<_>>(),
        vec![3],
        "a position of this run continues from where it names"
    );

    let _ = std::fs::remove_dir_all(&directory);
}

/// KR-REQ-11.32 and KR-REQ-09: a write that does not finish reports every frame behind it.
///
/// The frames behind a failure are the ones a connection would lose quietly. This runs over the
/// connection the host actually serves: the endpoint is bound by the host, the bridge is admitted
/// through the authenticated accept, and the reading, the writing and the teardown are the ones
/// that composition starts. The bridge then stops reading, so the terminal's own requests queue
/// behind a write that cannot finish. The connection's own supervision ends it: the writers are
/// given the teardown deadline and no longer, both readers finish, every identifier this host was
/// holding is given back, and the terminal is told about each one exactly once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_11_32_a_failed_write_reports_every_frame_behind_it_and_the_writers_finish() {
    let directory = private_directory();
    let (broker, running) = broker_expecting_this_process();
    // The supervision's bound is put far below the deadline one write gets, so what ends this
    // connection is one thing and not either of two. A stuck write gives up after
    // `WRITE_DEADLINE`; this supervision gives the writers a fifth of a second. A connection that
    // ends inside that is a connection this supervision ended, because the write it is waiting on
    // still has seconds of its own left to run.
    let supervised = std::time::Duration::from_millis(200);
    assert!(
        supervised * 4 < kr_worker::broker::WRITE_DEADLINE,
        "the two deadlines have to be far enough apart to tell apart"
    );
    let gateway = kr_worker::broker::NativeGateway::bind(
        Arc::clone(&broker),
        &directory,
        launch_for(Some(running.clone()), None),
    )
    .expect("the endpoint binds")
    .with_teardown_deadline(supervised);
    let kr_worker::broker::ListenerAddress::PrivateSocket(path) = gateway.address().clone() else {
        panic!("this platform prefers a private socket");
    };

    // A bridge that says who it is and then never reads another byte. Everything this host writes
    // to it fills the socket and stays there.
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

    // The terminal's two directions, so its end of the connection can reach end of file while what
    // this host tells it is still readable.
    let (client_in_here, client_in_there) = tokio::io::duplex(1 << 20);
    let (client_out_here, mut client_out_there) = tokio::io::duplex(1 << 20);
    let mut attached = gateway
        .accept(client_in_here, client_out_here)
        .await
        .expect("the bridge is admitted");
    let bridge = bridging.await.expect("the bridge task finished");
    let owner = Arc::clone(&attached.owner);

    // Measured from before the first write can start, so the elapsed time below covers every
    // deadline a write of this connection could have started.
    let ending = std::time::Instant::now();

    // Requests the terminal makes of its upstream: one large enough that the socket cannot take it
    // all, and two behind it.
    let filling = "z".repeat(512 * 1024);
    owner
        .from_client(
            format!(r#"{{"id":71,"method":"session/update","params":{{"why":"{filling}"}}}}"#)
                .as_bytes(),
            TimestampMs::new(2),
        )
        .await
        .expect("the first request is carried");
    for id in [72, 73] {
        owner
            .from_client(
                format!(r#"{{"id":{id},"method":"session/update","params":{{}}}}"#).as_bytes(),
                TimestampMs::new(3),
            )
            .await
            .expect("the requests behind it are carried");
    }
    assert_eq!(owner.forwarded_client_requests(), 3);
    assert!(
        owner.queued_to_upstream() > 0,
        "the write is still waiting on a peer that is not reading"
    );

    // The terminal's end reaches end of file. That is what ends the reading, and the connection's
    // own supervision takes it from there.
    drop(client_in_there);
    let ended = tokio::time::timeout(kr_worker::broker::WRITE_DEADLINE, attached.served())
        .await
        .expect(
            "the supervision ends the connection rather than waiting on a write that cannot finish",
        )
        .expect("its task is joined");
    let took = ending.elapsed();
    assert!(
        took < kr_worker::broker::WRITE_DEADLINE,
        "what ended this connection was the supervision's bound and not the write giving up on \
         its own, which could not have happened yet: {took:?}"
    );
    assert_eq!(
        ended.closure,
        kr_worker::broker::Closure::Detached,
        "the terminal's end closing is a detachment, not an exit"
    );
    assert_eq!(
        owner.forwarded_client_requests(),
        0,
        "every identifier behind the failure is given back"
    );
    assert_eq!(
        owner.queued_to_upstream(),
        0,
        "and every byte the abandoned write reserved is refunded"
    );

    // The terminal is told about each of its own requests, once, under the identifier it used.
    let told = read_available(&mut client_out_there).await;
    let mut answers: std::collections::BTreeMap<u32, usize> = std::collections::BTreeMap::new();
    for line in told.lines().filter(|line| !line.trim().is_empty()) {
        let body: serde_json::Value = serde_json::from_str(line.trim()).expect("a response frame");
        assert!(
            body.get("error").is_some(),
            "a request behind a failed write is answered with an error: {line}"
        );
        let id = u32::try_from(
            body.get("id")
                .and_then(serde_json::Value::as_u64)
                .expect("a response carries the identifier the terminal used"),
        )
        .expect("the identifier this test wrote");
        *answers.entry(id).or_default() += 1;
    }
    for id in [71, 72, 73] {
        assert_eq!(
            answers.get(&id).copied(),
            Some(1),
            "the terminal is told exactly once about the request it made under {id}: {told}"
        );
    }

    drop(bridge);
    let _ = std::fs::remove_dir_all(&directory);
}

/// KR-REQ-11.32: an owner nothing holds any longer ends its connection.
///
/// Nothing inside the owner may outlive the callers that hold it. A supervisor that dropped its
/// handle and left the connection running would leave a terminal talking to a host that has
/// forgotten it, so the last handle going is the connection ending.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_11_32_an_owner_nothing_holds_any_longer_ends_its_connection() {
    let broker = broker();
    let (owner, upstream, client, writes) = duplex_over_pipes(&broker, 1 << 20);
    let driving = tokio::spawn(writes);
    owner
        .from_client(
            br#"{"id":71,"method":"session/update","params":{}}"#,
            TimestampMs::new(2),
        )
        .await
        .expect("the terminal's own request is carried");
    assert_eq!(owner.forwarded_client_requests(), 1);

    // Everything that held it lets go.
    drop(owner);
    tokio::time::timeout(std::time::Duration::from_secs(30), driving)
        .await
        .expect("the owner's own work finishes when nothing holds it")
        .expect("its task is joined");
    drop(upstream);
    drop(client);
}

/// KR-REQ-11.32: an owner dropped while a caller retains a dispatch closes its upstream sender.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_11_32_owner_drop_with_retained_dispatch_closes_upstream() {
    let broker = broker();
    let (owner, upstream, client, writes) = duplex_over_pipes(&broker, 1 << 20);
    let driving = tokio::spawn(writes);
    let dispatch = owner.dispatch().expect("dispatch is created");

    assert!(!dispatch.is_closed());

    // Dropping the owner shuts down the connection.
    drop(owner);
    tokio::time::timeout(std::time::Duration::from_secs(30), driving)
        .await
        .expect("the owner's own work finishes")
        .expect("task is joined");

    // An owner dropped while a caller retains a dispatch closes its upstream sender.
    assert!(
        dispatch.is_closed(),
        "a retained dispatch upstream sender is closed after the owner has dropped"
    );

    drop(upstream);
    drop(client);
}

/// KR-REQ-11.32 and KR-REQ-09: a write that does not finish ends the connection, and every frame
/// behind it is reported as the unsent frame it is.
///
/// The terminal stops reading part way through a frame. What that costs is the connection: nothing
/// is replayed, the resource whose answer was behind it is left uncertain rather than lost, and
/// the owner stops reading both ends rather than going on losing frames quietly.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_11_32_a_write_that_does_not_finish_ends_the_connection() {
    let broker = broker();
    let (upstream_here, upstream_there) = tokio::io::duplex(1 << 20);
    // A terminal whose pipe takes a few bytes and then blocks for ever.
    let (client_here, client_there) = tokio::io::duplex(8);
    let (owner, writes) = Duplex::new(
        Arc::clone(&broker),
        GatewayConnectionId::new(1),
        Framing::new(NativeFraming::JsonLines),
        upstream_here,
        client_here,
        EnvironmentId::new(Uuid::from_bytes([4; 16])),
        "agent-user",
    );
    let driving = tokio::spawn(writes);

    let filling = "z".repeat(8192);
    owner
        .from_upstream(
            format!(
                r#"{{"id":61,"method":"session/request_permission","params":{{"why":"{filling}"}}}}"#
            )
            .as_bytes(),
            TimestampMs::new(2),
        )
        .await
        .expect("the request is carried");

    // The write deadline passes, the frame has gone in part, and the owner stops.
    for _ in 0..400 {
        if owner.stopping() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(
        owner.stopping(),
        "a write that did not finish is a connection this host stops using"
    );
    assert!(
        owner
            .from_client(
                br#"{"id":62,"method":"session/update","params":{}}"#,
                TimestampMs::new(3),
            )
            .await
            .is_err(),
        "and it takes nothing else"
    );
    drop(client_there);
    drop(upstream_there);
    driving.abort();
}

/// KR-REQ-11.32: teardown closes admission and both writers finish, with other handles still live.
///
/// A dispatch and the owner itself are held for the whole of this, which is what production does
/// while a connection is torn down. The writers still end, nothing new is taken, and a frame
/// queued before the shutdown still goes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_11_32_teardown_closes_admission_and_joins_both_writers() {
    let broker = broker();
    let (owner, upstream, client, writes) = duplex_over_pipes(&broker, 1 << 20);
    let driving = tokio::spawn(writes);
    // Held for the whole teardown, exactly as the composition holds them.
    let dispatch = owner.dispatch().expect("it carries operations");
    broker
        .bind_dispatch(
            instance(),
            Arc::clone(&dispatch) as Arc<dyn kr_worker::broker::UpstreamDispatch>,
        )
        .expect("the transport is bound");

    owner
        .from_client(
            br#"{"id":6,"method":"session/update","params":{}}"#,
            TimestampMs::new(2),
        )
        .await
        .expect("a frame queued before the shutdown");
    owner.shutdown();
    tokio::time::timeout(std::time::Duration::from_secs(20), driving)
        .await
        .expect("both writers finish even though the owner and its dispatch are still held")
        .expect("their task is joined");

    // Nothing new is taken once admission has closed.
    let refused = owner
        .from_client(
            br#"{"id":7,"method":"session/update","params":{}}"#,
            TimestampMs::new(3),
        )
        .await
        .expect_err("a connection that has stopped taking frames takes none");
    assert_eq!(
        refused.code(),
        kr_protocol::error::ErrorCode::UpstreamUnavailable
    );
    // And what was queued before it went.
    let mut upstream = upstream;
    let written = read_available(&mut upstream).await;
    assert!(
        written.contains("\"id\":\"kr-1\""),
        "the frame admitted before the shutdown reached the upstream: {written}"
    );
    drop(client);
    drop(dispatch);
}

/// Reads whatever is waiting on one pipe, without waiting for more.
async fn read_available(stream: &mut tokio::io::DuplexStream) -> String {
    let mut held = Vec::new();
    let mut chunk = [0_u8; 8192];
    loop {
        let read = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            tokio::io::AsyncReadExt::read(stream, &mut chunk),
        )
        .await;
        match read {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
            Ok(Ok(bytes)) => held.extend_from_slice(&chunk[..bytes]),
        }
    }
    String::from_utf8_lossy(&held).into_owned()
}

/// KR-REQ-11.32 and KR-REQ-09: a reader goes on correlating while the other end is not draining.
///
/// The terminal has stopped reading, so a frame bound for it fills the pipe and sits there for the
/// whole write deadline. Meanwhile this host's own operation is acknowledged by the upstream. The
/// acknowledgement is correlated and the caller is answered well inside that deadline, because
/// what a write turns out to be is the owner's work and not the reader's.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_11_32_an_acknowledgement_is_correlated_behind_a_blocked_client_bound_frame() {
    let broker = broker();
    let (upstream_here, upstream_there) =
        tokio::net::UnixStream::pair().expect("a socket pair is made");
    // A terminal that reads nothing: a frame bound for it goes in part and stops.
    let (client_here, client_there) = tokio::io::duplex(8);
    let (upstream_reads, upstream_writes) = tokio::io::split(upstream_here);
    let (owner, writes) = Duplex::new(
        Arc::clone(&broker),
        GatewayConnectionId::new(1),
        Framing::new(NativeFraming::JsonLines),
        upstream_writes,
        client_here,
        EnvironmentId::new(Uuid::from_bytes([4; 16])),
        "agent-user",
    );
    let drained = tokio::spawn(writes);
    broker
        .bind_dispatch(instance(), owner.dispatch().expect("it carries operations"))
        .expect("the transport is bound");

    // The agent: it asks the person something first, through the socket, and answers whatever this
    // host sends it afterwards. Nothing here is handed to the owner by the test.
    let filling = "y".repeat(4096);
    let asking = format!(
        "{{\"id\":51,\"method\":\"session/request_permission\",\"params\":{{\"why\":\"{filling}\"}}}}\n"
    );
    let sent = Arc::new(std::sync::Mutex::new(Vec::new()));
    let answering = agent_that_asks_first(upstream_there, asking, Arc::clone(&sent));
    let reading = {
        let owner = Arc::clone(&owner);
        tokio::spawn(async move { owner.serve(upstream_reads, true).await })
    };

    // The reader takes that request off the socket and records it. Its forwarding to the terminal
    // fills the pipe and stops there for the whole write deadline.
    for _ in 0..400 {
        if broker
            .pending_resources()
            .iter()
            .any(|resource| resource.state == PendingState::Pending)
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(
        broker
            .pending_resources()
            .iter()
            .any(|resource| resource.state == PendingState::Pending),
        "the reader took the agent's request off the socket and recorded it"
    );

    // And this host's own operation is acknowledged while that frame is still going nowhere.
    let started = tokio::time::Instant::now();
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
            TimestampMs::new(3),
        )
        .await
        .expect("the upstream acknowledged it");
    let waited = started.elapsed();
    assert!(
        waited < kr_worker::broker::WRITE_DEADLINE,
        "the acknowledgement was correlated in {waited:?}, which is not behind the blocked write"
    );
    assert!(
        !sent.lock().expect("the record is not poisoned").is_empty(),
        "the operation reached the upstream"
    );

    drop(client_there);
    answering.abort();
    reading.abort();
    drained.abort();
}

/// An agent that writes one frame of its own first and then answers everything it is sent.
fn agent_that_asks_first(
    upstream: tokio::net::UnixStream,
    asking: String,
    frames: Arc<std::sync::Mutex<Vec<serde_json::Value>>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let (reading, mut writing) = tokio::io::split(upstream);
        if writing.write_all(asking.as_bytes()).await.is_err() {
            return;
        }
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

    // The terminal asks its agent for something this connector's table does not list. The owner
    // takes the frame and its bytes stop in the pipe, so nothing about it has reached the agent.
    let carried = owner
        .from_client(
            br#"{"id":4,"method":"session/set_mode","params":{"mode":"yolo"}}"#,
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
    assert!(
        !classification.declared,
        "the table did not classify it, so it is presumed a mutation"
    );
    assert_eq!(classification.class, NativeMethodClass::Mutation);
    assert!(suspended_rich_mutations);

    // What was recorded before any of it went, and what it changed before any of it went.
    let recorded = broker
        .client_requests()
        .expect("the records read")
        .into_iter()
        .next()
        .expect("the request was recorded");
    assert_eq!(
        recorded.method,
        method("session/set_mode"),
        "the method the terminal named"
    );
    assert_eq!(recorded.classification.class, NativeMethodClass::Mutation);
    assert!(!recorded.classification.declared);
    assert_eq!(
        recorded.outcome,
        kr_worker::broker::ClientRequestOutcome::Recorded,
        "recorded before its bytes went, not after: the pipe has not taken them"
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

    // The person's answer is admitted, and its bytes fill the pipe and stop. The owner reports
    // what actually reached the socket, and the resource says what that was.
    let long = "x".repeat(4096);
    let answer =
        serde_json::json!({ "id": 31, "result": { "outcome": "allow", "why": long } }).to_string();
    owner
        .from_client(answer.as_bytes(), TimestampMs::new(3))
        .await
        .expect("the answer is admitted and queued");
    let settled = settled_within(
        &broker,
        resource.resource_id,
        std::time::Duration::from_secs(20),
    )
    .await
    .expect("the owner settles what it could not write");
    assert_eq!(
        settled,
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

/// KR-REQ-07.67: a dedicated backend that closes its socket (EOF) while remaining alive is stopped
/// when the terminal subsequently exits.
///
/// A process can close its socket and stay alive. When the socket closes, the attachment is
/// reported as detached, the process continues running, and the terminal supervision continues
/// watching the terminal until its exit stops the dedicated backend.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_07_67_a_dedicated_backend_that_closes_socket_stops_when_terminal_exits() {
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

    // The backend is launched with `--close-after-hello` so it sends hello, closes its socket,
    // and stays alive.
    let mut profile = forwarder_profile();
    profile.arguments = vec!["--close-after-hello".to_owned()];
    let intent = broker
        .prepare_launch(profile, kr_worker::broker::ForegroundMark::idle(4), None)
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

    // The forwarder closes its socket after hello. The connection teardown finishes and reports
    // Closure::Detached, but the dedicated backend process and terminal are still running.
    let ended = tokio::time::timeout(std::time::Duration::from_secs(20), attached.served())
        .await
        .expect("the connection ends")
        .expect("its task is joined");
    assert_eq!(
        ended.closure,
        kr_worker::broker::Closure::Detached,
        "a connection closing before terminal exit is detached"
    );
    assert!(
        matches!(
            kr_ipc::identity::process_state(&launched.process),
            kr_ipc::identity::ProcessState::Running
        ),
        "the dedicated backend stays alive after closing its socket"
    );
    assert!(
        matches!(
            kr_ipc::identity::process_state(
                &kr_ipc::identity::process_start_identity(terminal_pid).expect("readable")
            ),
            kr_ipc::identity::ProcessState::Running
        ),
        "the terminal is still running"
    );

    let watching = attached
        .terminal
        .take()
        .expect("this host started a terminal");

    // End of file came first and the terminal exit comes now. The supervision is still watching,
    // so the exit stops the dedicated backend.
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    terminal.kill().await.expect("the terminal is ended");
    let _ = terminal.wait().await;

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

/// KR-REQ-12.11 and KR-REQ-12.13: a committed transition reaches the views attached to the session.
///
/// This is the production delivery, not a test reading a subscription. The composition subscribes
/// the connection, the broker publishes each transition where it commits it, and the session
/// pipeline hands every one to the views that are attached. What this asserts is that a view is
/// told, in the order the broker committed, and told what the event actually was.
async fn session_runtime_and_stream(
    session_id: SessionId,
    host: &kr_ipc::testing::TempHost,
) -> (
    Arc<kr_worker::runtime::SessionRuntime>,
    kr_worker::output::OutputStream,
) {
    let mut requested = kr_protocol::scalars::CanonicalSet::new();
    requested.insert(kr_protocol::attachment::AttachmentCapability::ObserveTerminal);
    requested.insert(kr_protocol::attachment::AttachmentCapability::Input);
    requested.insert(kr_protocol::attachment::AttachmentCapability::Geometry);
    let config = kr_worker::session::SessionConfig {
        session_id,
        session_epoch: kr_protocol::ids::SessionEpoch::V1,
        environment_id: host.environment_id(),
        display_number: kr_protocol::session::DisplayNumber::new(1),
        shell: kr_worker::testing::posix_script("exec cat"),
        shell_mode: kr_protocol::session::ShellMode::NativeCompat,
        worker_profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
        desktop: kr_protocol::identity::DesktopBinding::none(),
        dimensions: kr_protocol::session::Dimensions::new(80, 24),
        journal_path: Some(host.environment().journal_database(session_id)),
        spool_directory: Some(host.environment().session_spool(session_id)),
        worker_endpoint: None,
        send_queue_bytes: 8 * 1024 * 1024,
        resident_bytes: 1024 * 1024,
        launch_profile: kr_protocol::session::LaunchProfile::default(),
    };
    let mut session = kr_worker::session::Session::open(config).expect("opens");
    session.launch().expect("launches");
    let attachment_id = kr_protocol::ids::AttachmentId::new(Uuid::from_bytes([5; 16]));
    let params = kr_protocol::attachment::SessionAttachParams {
        session_id,
        mode: kr_protocol::attachment::AttachMode::Terminal,
        claim_geometry: true,
        dimensions: Nullable::some(kr_protocol::session::Dimensions::new(80, 24)),
        terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
        requested: requested.clone(),
    };
    session
        .attach(&params, requested, attachment_id)
        .expect("attaches");
    let stream = session.subscribe(attachment_id).expect("subscribes");
    let runtime = Arc::new(
        kr_worker::runtime::SessionRuntime::start(
            session,
            Arc::new(kr_ipc::clock::SystemSharedClock),
        )
        .expect("starts"),
    );
    (runtime, stream)
}

/// The same session, served over the worker's own endpoint, with a client attached to it.
///
/// A view is a client on a socket, and what it is actually told is a frame. A test that reads the
/// session's own queue proves the delivery inside this process and nothing about what a view
/// receives, so the recovery tests below run over this: a real service, a real connection, and the
/// notifications a client decodes.
async fn service_and_attached_client(
    session_id: SessionId,
    host: &kr_ipc::testing::TempHost,
    shell: &str,
    send_queue_bytes: usize,
) -> (
    Arc<kr_worker::service::WorkerService>,
    Arc<kr_worker::runtime::SessionRuntime>,
    kr_ipc::client::LocalClient,
    kr_protocol::ids::AttachmentId,
) {
    let environment = host.environment();
    let environment_id = host.environment_id();
    let display = kr_protocol::session::DisplayNumber::new(1);
    let boot = kr_ipc::identity::boot_identity().expect("a boot identity");
    let process = kr_ipc::identity::current_process_start_identity().expect("a process identity");
    let identity = Arc::new(
        kr_ipc::verify::WorkerIdentity::generate(
            session_id,
            kr_protocol::ids::SessionEpoch::V1,
            boot.clone(),
            process,
            kr_protocol::hello::PROTOCOL_VERSION,
        )
        .expect("a session key"),
    );
    let store =
        kr_crypto::store::open_store_in(&environment.secrets_dir()).expect("a secret store");
    let controller =
        kr_ipc::verify::ControllerIdentity::initialise(store.store.as_ref(), environment_id)
            .expect("a controller identity");
    let config = kr_worker::session::SessionConfig {
        session_id,
        session_epoch: kr_protocol::ids::SessionEpoch::V1,
        environment_id,
        display_number: display,
        shell: kr_worker::testing::posix_script(shell),
        shell_mode: kr_protocol::session::ShellMode::NativeCompat,
        worker_profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
        desktop: kr_protocol::identity::DesktopBinding::none(),
        dimensions: kr_protocol::session::Dimensions::new(80, 24),
        journal_path: Some(environment.journal_database(session_id)),
        spool_directory: Some(environment.session_spool(session_id)),
        worker_endpoint: None,
        send_queue_bytes,
        resident_bytes: 1024 * 1024,
        launch_profile: kr_protocol::session::LaunchProfile::default(),
    };
    let mut session = kr_worker::session::Session::open(config).expect("opens");
    session.launch().expect("launches");
    let runtime = Arc::new(
        kr_worker::runtime::SessionRuntime::start(
            session,
            Arc::new(kr_ipc::clock::SystemSharedClock),
        )
        .expect("starts"),
    );
    let endpoint = environment.worker_endpoint(display).expect("an endpoint");
    let listener = kr_ipc::endpoint::Listener::bind(&endpoint).expect("binds the endpoint");
    let service = Arc::new(
        kr_worker::service::WorkerService::new(
            Arc::clone(&runtime),
            identity,
            endpoint.clone(),
            kr_worker::service::ServiceBinding {
                environment_id,
                boot_identity: boot,
                controller_public_key: *controller.public_key(),
                controller_generation: kr_protocol::ids::ControllerGeneration::new(1),
                journal_path: None,
                build_id: kr_protocol::ids::BuildId::new("kr-test/0").expect("a build"),
            },
        )
        .expect("a worker service"),
    );
    tokio::spawn(Arc::clone(&service).serve(listener));
    let mut client = kr_ipc::client::LocalClient::connect(
        &endpoint,
        kr_protocol::local::LocalClientKind::Cli,
        kr_protocol::ids::BuildId::new("kr-test/0").expect("a build"),
    )
    .await
    .expect("connects");
    let mut requested = kr_protocol::scalars::CanonicalSet::new();
    requested.insert(kr_protocol::attachment::AttachmentCapability::ObserveTerminal);
    let attached: kr_protocol::attachment::SessionAttachResult = client
        .mutate(
            kr_protocol::method::Method::SessionAttach,
            kr_protocol::ids::ActionId::new(kr_ipc::new_uuid()),
            kr_protocol::envelope::ActionTarget {
                environment_id,
                session_id: Nullable::some(session_id),
                session_epoch: Nullable::some(kr_protocol::ids::SessionEpoch::V1),
                application_instance_id: Nullable::null(),
                agent_binding_revision: Nullable::null(),
            },
            &kr_protocol::attachment::SessionAttachParams {
                session_id,
                mode: kr_protocol::attachment::AttachMode::Terminal,
                claim_geometry: false,
                dimensions: Nullable::some(kr_protocol::session::Dimensions::new(80, 24)),
                terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
                requested,
            },
        )
        .await
        .expect("the call reaches the worker")
        .expect("the attach succeeds")
        .to_typed()
        .expect("decodes");
    (service, runtime, client, attached.attachment.attachment_id)
}

/// Subscribes one attachment to its session's events and returns what the worker answered.
async fn subscribe(
    client: &mut kr_ipc::client::LocalClient,
    session_id: SessionId,
    attachment_id: kr_protocol::ids::AttachmentId,
) -> kr_protocol::recovery::EventsSubscribeResult {
    let mut streams = kr_protocol::scalars::CanonicalSet::new();
    streams.insert(kr_protocol::recovery::EventStream::Output);
    client
        .request(
            kr_protocol::method::Method::EventsSubscribe,
            &kr_protocol::recovery::EventsSubscribeParams {
                session_id,
                attachment_id,
                streams,
                from_cursor: Nullable::null(),
            },
        )
        .await
        .expect("the call reaches the worker")
        .expect("the subscription succeeds")
        .to_typed()
        .expect("decodes")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_12_11_a_committed_transition_reaches_an_attached_view() {
    let broker = broker();
    let served = duplex_watched(&broker).await;
    let observations = served.observations;
    let owner = Arc::clone(&served.owner);
    let mut client = tokio::io::BufReader::new(served.client);

    // The session pipeline: deliver_to_views reads from the broker and publishes to the session,
    // which delivers to the attached view's output stream.
    let host = kr_ipc::testing::TempHost::create();
    let (runtime, mut stream) = session_runtime_and_stream(session(), &host).await;

    let carrying = tokio::spawn(kr_worker::broker::attach::deliver_to_views(
        observations,
        Arc::clone(&broker),
        session(),
        Arc::clone(&runtime),
    ));

    owner
        .from_upstream(
            br#"{"id":81,"method":"session/request_permission","params":{}}"#,
            TimestampMs::new(2),
        )
        .await
        .expect("the request is carried");
    let _ = next_line(&mut client).await;
    owner
        .from_client(
            br#"{"id":81,"result":{"outcome":"allow"}}"#,
            TimestampMs::new(3),
        )
        .await
        .expect("the person answers");
    let resource = broker
        .pending_resources()
        .into_iter()
        .next()
        .expect("the resource is held");
    settled_within(
        &broker,
        resource.resource_id,
        std::time::Duration::from_secs(20),
    )
    .await
    .expect("the answer settles it");

    let mut seen = Vec::new();
    while let Ok(Some(delivery)) =
        tokio::time::timeout(std::time::Duration::from_secs(10), stream.recv()).await
    {
        if let kr_worker::output::OutputDelivery::AgentResource { event, bytes } = delivery {
            stream.written(bytes);
            let state = event.state;
            seen.push(*event);
            if state.is_terminal() {
                break;
            }
        }
    }

    assert!(
        seen.windows(2)
            .all(|pair| pair[0].sequence.get() < pair[1].sequence.get()),
        "the views are told in the order the broker committed: {:?}",
        seen.iter()
            .map(|event| event.sequence.get())
            .collect::<Vec<_>>()
    );
    let settled = seen.last().expect("a last event");
    assert_eq!(settled.resource_id, resource.resource_id);
    assert_eq!(settled.state, PendingState::Resolved);
    assert_eq!(settled.session_id, session());
    assert_eq!(
        settled.durability,
        kr_protocol::session::Durability::Durable,
        "and what it says about the record is what the record is"
    );
    assert!(
        settled.parent_sequence.0.is_some(),
        "a settlement names the event before it"
    );

    // Section 24: verify every received view notification against its corresponding outbox record.
    let outbox = outbox(&broker);
    assert!(!seen.is_empty(), "views received notifications");
    for event in &seen {
        let record = outbox
            .iter()
            .find(|entry| entry.event_id == event.event_id)
            .expect("the received notification exists in the outbox");
        assert_eq!(event.sequence.get(), record.sequence);
        assert_eq!(event.resource_id, record.resource_id);
        assert_eq!(
            event.application_instance_id,
            record.application_instance_id
        );
        assert_eq!(event.state, record.state);
        assert_eq!(event.durability, record.durability);
        assert_eq!(event.causal_root, record.causal_root);
        assert_eq!(event.actor_id.0, record.actor_id);
        assert_eq!(
            event.parent_sequence.0.map(|s| s.get()),
            record.parent_sequence
        );
        assert_eq!(
            event.content.as_str(),
            record.content.as_str(),
            "content class matches outbox"
        );
        assert_eq!(
            event.cause.as_str(),
            record.cause.as_str(),
            "cause matches outbox"
        );
    }

    carrying.abort();
    served.drained.abort();
}

/// KR-REQ-12.11 and section 12: an observer that overflows recovers what its queue lost.
///
/// The queue between the broker and this session is bounded, and an observer that is not read
/// loses it. What must not be lost with it is the resolution: the one event a person is waiting
/// for is exactly the one most likely to arrive while a queue is full. So this forces a real
/// overflow — more transitions than the queue holds, with nothing reading it — settles a resource
/// inside the interval the overflow swallowed, and then starts delivery. The settlement cannot
/// reach the view except by replay, because the queue that would have carried it is gone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_12_11_an_overflowed_observer_replays_what_its_queue_lost() {
    let broker = broker();
    let served = duplex_watched(&broker).await;
    let observations = served.observations;
    let owner = Arc::clone(&served.owner);
    let mut upstream_client = tokio::io::BufReader::new(served.client);

    let host = kr_ipc::testing::TempHost::create();
    let (runtime, mut stream) = session_runtime_and_stream(session(), &host).await;

    // Nothing is reading the observation queue yet. Each forwarded request commits one transition,
    // and the queue holds a bounded number of them, so this fills it and then goes past it.
    let overflow = kr_worker::broker::MAX_QUEUED_OBSERVATIONS + 8;
    for index in 0..overflow {
        owner
            .from_upstream(
                format!(
                    r#"{{"id":{},"method":"session/request_permission","params":{{}}}}"#,
                    900 + index
                )
                .as_bytes(),
                TimestampMs::new(2),
            )
            .await
            .expect("the request is carried");
        let _ = next_line(&mut upstream_client).await;
    }

    // The resource settled here is inside the stretch the overflow swallowed: the queue that would
    // have carried its transition was dropped before it committed.
    let resource = broker
        .pending_resources()
        .into_iter()
        .next_back()
        .expect("a resource is held");
    broker
        .upstream_resolved(&resource.request, TimestampMs::new(3))
        .expect("the upstream withdraws its own request");
    let settlement = outbox(&broker)
        .into_iter()
        .rfind(|event| event.resource_id == resource.resource_id)
        .expect("the settlement is recorded");
    assert!(
        settlement.state.is_terminal(),
        "the resource settled while nothing was reading the queue"
    );

    // Delivery starts now. It drains what the queue still holds, finds it closed, takes a fresh
    // one and recovers the rest from the outbox.
    let carrying = tokio::spawn(kr_worker::broker::attach::deliver_to_views(
        observations,
        Arc::clone(&broker),
        session(),
        Arc::clone(&runtime),
    ));

    let mut seen = Vec::new();
    while let Ok(Some(delivery)) =
        tokio::time::timeout(std::time::Duration::from_secs(20), stream.recv()).await
    {
        if let kr_worker::output::OutputDelivery::AgentResource { event, bytes } = delivery {
            stream.written(bytes);
            let settled = event.event_id == settlement.event_id;
            seen.push(*event);
            if settled {
                break;
            }
        }
    }

    assert!(
        seen.iter()
            .any(|event| event.event_id == settlement.event_id),
        "the settlement the overflow swallowed reached the view: {} events seen",
        seen.len()
    );
    assert!(
        seen.windows(2)
            .all(|pair| pair[0].sequence.get() < pair[1].sequence.get()),
        "and the recovery keeps the broker's own order"
    );
    let recorded = outbox(&broker);
    for event in &seen {
        let record = recorded
            .iter()
            .find(|entry| entry.event_id == event.event_id)
            .expect("every delivered event is one the outbox holds");
        assert_eq!(event.sequence.get(), record.sequence);
        assert_eq!(event.state, record.state);
    }

    carrying.abort();
    served.drained.abort();
}

/// KR-REQ-12.11 and section 12: what was announced and never recorded is reported as a gap.
///
/// A stretch the journal could not take is published and not written, so no replay can return it.
/// An observer that overflows inside such a stretch therefore cannot be made whole by the outbox,
/// and the one thing it must not do is hand the views a shorter history that looks complete. It
/// tells them to start again instead.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_12_11_a_recovery_that_cannot_cover_the_interval_tells_the_views_to_start_again() {
    let broker = broker();
    let served = duplex_watched(&broker).await;
    let owner = Arc::clone(&served.owner);
    let mut upstream_client = tokio::io::BufReader::new(served.client);

    let host = kr_ipc::testing::TempHost::create();
    let (runtime, mut stream) = session_runtime_and_stream(session(), &host).await;

    // A recorded backlog larger than one replay page, so the recovery reads several pages and
    // every one of them carries the same news.
    for index in 0..(kr_worker::broker::MAX_REPLAY_EVENTS + 4) {
        owner
            .from_upstream(
                format!(
                    r#"{{"id":{},"method":"session/request_permission","params":{{}}}}"#,
                    2000 + index
                )
                .as_bytes(),
                TimestampMs::new(2),
            )
            .await
            .expect("the request is carried");
        let _ = next_line(&mut upstream_client).await;
    }
    // Then a journal that cannot be written.
    broker
        .enter_volatile("the journal could not be written", TimestampMs::new(3))
        .expect("the gateway enters volatile-native mode");

    // More transitions than the observation queue holds, with nothing reading it. None of them is
    // recorded, so none of them can be replayed.
    for index in 0..(kr_worker::broker::MAX_QUEUED_OBSERVATIONS + 8) {
        owner
            .from_upstream(
                format!(
                    r#"{{"id":{},"method":"session/request_permission","params":{{}}}}"#,
                    700 + index + 1
                )
                .as_bytes(),
                TimestampMs::new(4),
            )
            .await
            .expect("the request is carried");
        let _ = next_line(&mut upstream_client).await;
    }
    assert_eq!(
        outbox(&broker).len(),
        kr_worker::broker::MAX_REPLAY_EVENTS + 4,
        "only the transitions from before the fault were recorded"
    );

    let carrying = tokio::spawn(kr_worker::broker::attach::deliver_to_views(
        served.observations,
        Arc::clone(&broker),
        session(),
        Arc::clone(&runtime),
    ));

    let mut markers = Vec::new();
    while markers.is_empty() {
        match tokio::time::timeout(std::time::Duration::from_secs(20), stream.recv()).await {
            Ok(Some(kr_worker::output::OutputDelivery::AgentResource { bytes, .. })) => {
                stream.written(bytes);
            }
            Ok(Some(kr_worker::output::OutputDelivery::Resync(marker))) => markers.push(marker),
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => break,
        }
    }
    // And nothing more is said about it while the recovery finishes its remaining pages.
    while let Ok(Some(delivery)) =
        tokio::time::timeout(std::time::Duration::from_secs(3), stream.recv()).await
    {
        match delivery {
            kr_worker::output::OutputDelivery::AgentResource { bytes, .. } => {
                stream.written(bytes);
            }
            kr_worker::output::OutputDelivery::Resync(marker) => markers.push(marker),
            _ => {}
        }
    }

    let marker = markers
        .first()
        .expect("the views are told the recovery could not cover it");
    assert_eq!(
        marker.reason,
        kr_protocol::recovery::ResyncReason::AgentStreamGap,
        "and they are told why: what was lost was never written down"
    );
    assert_eq!(
        markers.len(),
        1,
        "one recovery is one piece of news, however many pages it reads"
    );

    carrying.abort();
    served.drained.abort();
}

/// KR-REQ-12.11: delivery that has ended still hands over what it was holding, and takes no queue.
///
/// Teardown and a queue that filled are different endings, and the difference decides two things.
/// What the connection produced before it ended is still the session's to deliver, so it is
/// recovered before delivery stops. And nothing may take a queue for a connection that has gone:
/// one that did would be a queue nothing produces into and nothing closes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_12_11_delivery_recovers_before_it_ends_and_takes_no_queue_after_teardown() {
    let broker = broker();
    let served = duplex_watched(&broker).await;
    let owner = Arc::clone(&served.owner);
    let mut upstream_client = tokio::io::BufReader::new(served.client);

    let host = kr_ipc::testing::TempHost::create();
    let (runtime, mut stream) = session_runtime_and_stream(session(), &host).await;

    for index in 0..(kr_worker::broker::MAX_QUEUED_OBSERVATIONS + 4) {
        owner
            .from_upstream(
                format!(
                    r#"{{"id":{},"method":"session/request_permission","params":{{}}}}"#,
                    600 + index
                )
                .as_bytes(),
                TimestampMs::new(2),
            )
            .await
            .expect("the request is carried");
        let _ = next_line(&mut upstream_client).await;
    }
    let resource = broker
        .pending_resources()
        .into_iter()
        .next_back()
        .expect("a resource is held");
    broker
        .upstream_resolved(&resource.request, TimestampMs::new(3))
        .expect("the upstream withdraws its own request");
    let settlement = outbox(&broker)
        .into_iter()
        .rfind(|event| event.resource_id == resource.resource_id)
        .expect("the settlement is recorded");

    // The connection is torn down before anything reads the queue.
    broker.observatory().withdraw(GatewayConnectionId::new(1));

    let carrying = tokio::spawn(kr_worker::broker::attach::deliver_to_views(
        served.observations,
        Arc::clone(&broker),
        session(),
        Arc::clone(&runtime),
    ));

    let mut seen = Vec::new();
    while let Ok(Some(delivery)) =
        tokio::time::timeout(std::time::Duration::from_secs(20), stream.recv()).await
    {
        if let kr_worker::output::OutputDelivery::AgentResource { event, bytes } = delivery {
            stream.written(bytes);
            let settled = event.event_id == settlement.event_id;
            seen.push(*event);
            if settled {
                break;
            }
        }
    }
    assert!(
        seen.iter()
            .any(|event| event.event_id == settlement.event_id),
        "the settlement reached the views although the connection had ended"
    );

    // And delivery ends of its own accord rather than waiting on a queue it took for a connection
    // that has gone.
    tokio::time::timeout(std::time::Duration::from_secs(20), carrying)
        .await
        .expect("delivery ends after teardown")
        .expect("without panicking");
    assert!(
        !broker
            .observatory()
            .is_watching(GatewayConnectionId::new(1)),
        "and no queue was registered for the connection that was torn down"
    );

    served.drained.abort();
}

/// KR-REQ-12.11 and section 9: a backlog larger than one page recovers in pages.
///
/// A recovery that read the whole backlog at once would allocate it at once and hold the broker
/// for as long as the read took. Both bounds are the point: the page is bounded, and what the
/// broker is doing for everyone else goes on between pages.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_12_11_a_backlog_larger_than_one_page_recovers_in_pages() {
    let broker = broker();
    let served = duplex_watched(&broker).await;
    let owner = Arc::clone(&served.owner);
    let mut upstream_client = tokio::io::BufReader::new(served.client);

    for index in 0..(kr_worker::broker::MAX_REPLAY_EVENTS + 4) {
        owner
            .from_upstream(
                format!(
                    r#"{{"id":{},"method":"session/request_permission","params":{{}}}}"#,
                    5000 + index
                )
                .as_bytes(),
                TimestampMs::new(2),
            )
            .await
            .expect("the request is carried");
        let _ = next_line(&mut upstream_client).await;
    }

    let first = broker
        .replay_after(broker.stream_start())
        .expect("the outbox reads");
    assert_eq!(
        first.events.len(),
        kr_worker::broker::MAX_REPLAY_EVENTS,
        "a page is bounded by what it carries"
    );
    assert!(first.more, "and it says the backlog continues");

    // Between the pages the broker is free: native traffic is served rather than queued behind
    // one observer's recovery.
    owner
        .from_upstream(
            br#"{"id":5999,"method":"session/request_permission","params":{}}"#,
            TimestampMs::new(3),
        )
        .await
        .expect("native traffic continues between the pages of a recovery");
    let _ = next_line(&mut upstream_client).await;

    let second = broker.replay_after(first.cursor).expect("the outbox reads");
    assert!(
        !second.events.is_empty(),
        "the next page continues from where the first ended"
    );
    assert!(
        second.events[0].sequence > first.cursor.sequence,
        "and it starts after it, without repeating"
    );
    assert!(
        second
            .events
            .iter()
            .any(|event| event.causal_root.ends_with(":5999")),
        "including what was committed while the recovery was between pages"
    );

    served.drained.abort();
}

/// KR-REQ-12.11 and KR-REQ-12.13: a view that lost its place is given the broker's state back.
///
/// This is the other half of recovery, and it runs over a real service connection because what it
/// is about is what a client receives. The view's own queue is filled until the worker tells it to
/// resynchronise. A resource then settles while the view is holding nothing — those events are not
/// queued for it at all, by design. What the view is given when it subscribes again is the state
/// as it now stands, at the position it stands at: the resource that settled is gone from it, the
/// ones still open are in it, and the position says which later events it must still apply.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_12_13_a_resynchronised_view_is_given_the_brokers_state_and_its_position() {
    let host = kr_ipc::testing::TempHost::create();
    // A queue small enough that a moment of output passes it, and an application whose output
    // starts after this view has subscribed and stops once the queue is well past its bound. It
    // has to start after the subscription, because output before it is history rather than queue;
    // it has to stop, because the second half of this test is about what a view receives once it
    // has resynchronised, and a terminal that never stops talking would overflow it again.
    let (service, runtime, mut client, attachment_id) = service_and_attached_client(
        session(),
        &host,
        "sleep 2; i=0; while [ $i -lt 5000 ]; do printf 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\\n'; i=$((i+1)); done; sleep 120",
        2048,
    )
    .await;
    // The broker this view's own service holds, which is the one a subscription is answered from.
    let broker = Arc::clone(service.broker());
    let connection = prepare_broker(&broker, rich());
    let served = duplex_watched_on(&broker, connection).await;
    let owner = Arc::clone(&served.owner);
    let mut upstream_client = tokio::io::BufReader::new(served.client);

    let first = subscribe(&mut client, session(), attachment_id).await;
    assert!(
        first.agent_resources.resources.is_empty(),
        "nothing is pending before anything is forwarded"
    );

    let carrying = tokio::spawn(kr_worker::broker::attach::deliver_to_views(
        served.observations,
        Arc::clone(&broker),
        session(),
        Arc::clone(&runtime),
    ));

    // Some resources this view is told about while it is still keeping up.
    for index in 0..4_u64 {
        owner
            .from_upstream(
                format!(
                    r#"{{"id":{},"method":"session/request_permission","params":{{}}}}"#,
                    800 + index
                )
                .as_bytes(),
                TimestampMs::new(2),
            )
            .await
            .expect("the request is carried");
        let _ = next_line(&mut upstream_client).await;
    }

    // The view stops reading. Its queue passes its bound, and the worker tells it to discard what
    // it held rather than holding the session for it. Nothing after this is queued for it.
    let told_to_resynchronise = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        wait_for_resync(&mut client),
    )
    .await
    .expect("the worker tells a view that has fallen behind");
    assert_eq!(
        told_to_resynchronise.reason,
        kr_protocol::recovery::ResyncReason::SendQueueFull
    );

    // A resource settles while the view holds nothing. This is the event a view could not recover
    // from its queue, because it has no queue.
    let settling = broker
        .pending_resources()
        .into_iter()
        .next_back()
        .expect("a resource is held");
    broker
        .upstream_resolved(&settling.request, TimestampMs::new(3))
        .expect("the upstream withdraws its own request");
    let held = broker.pending_resources();
    assert!(
        held.iter()
            .any(|resource| resource.resource_id == settling.resource_id
                && resource.state.is_terminal()),
        "the resource the upstream withdrew is settled"
    );

    // Subscribing again is how a view installs a fresh state, and the state it installs is the
    // broker's own.
    let again = subscribe(&mut client, session(), attachment_id).await;
    let restored: std::collections::BTreeMap<_, _> = again
        .agent_resources
        .resources
        .iter()
        .map(|resource| (resource.resource_id, resource.state))
        .collect();
    assert_eq!(
        restored.get(&settling.resource_id).copied(),
        Some(settling_state(&held, settling.resource_id)),
        "what settled while the view was away is installed as settled, not as still waiting"
    );
    assert!(
        restored
            .get(&settling.resource_id)
            .is_some_and(|state| state.is_terminal()),
        "a view that installs this does not offer a resolved resource as an answerable one"
    );
    for resource in &held {
        assert_eq!(
            restored.get(&resource.resource_id).copied(),
            Some(resource.state),
            "every resource the broker holds is in the state the view installs, as it stands"
        );
    }
    assert_eq!(
        again.agent_resources.stream_generation.get(),
        broker.stream_generation(),
        "the position names the run it belongs to"
    );
    assert!(
        again.agent_resources.cursor.get() >= u64::try_from(held.len()).unwrap_or(0),
        "and it is the position the broker had reached, not the start of the stream"
    );
    assert!(
        !again.agent_resources.continue_after.is_present(),
        "this host arbitrates few enough resources for one page to carry them all"
    );

    // What the view is given for the settlement it was not there for is the record of it. The
    // outbox holds one transition for that resource above the position this view last accounted
    // for, and what the subscription installed has to be that transition's own outcome: a
    // recovered state that disagreed with the record would be a view acting on something that
    // never happened.
    let lost = broker
        .replay_after(kr_worker::broker::ReplayCursor {
            generation: first.agent_resources.stream_generation.get(),
            sequence: first.agent_resources.cursor.get(),
        })
        .expect("the outbox reads")
        .events
        .into_iter()
        .filter(|event| event.resource_id == settling.resource_id && event.state.is_terminal())
        .next_back()
        .expect("the settlement the view was away for is in the outbox after its position");
    let installed = again
        .agent_resources
        .resources
        .iter()
        .find(|resource| resource.resource_id == settling.resource_id)
        .expect("the resource is in the state this view installed");
    assert_eq!(installed.state, lost.state, "the state the outbox recorded");
    assert_eq!(
        installed.durability, lost.durability,
        "and what its history is, durable or lived through a gap"
    );
    assert_eq!(
        installed.classification, lost.classification,
        "and how the method behind it was classified"
    );
    assert!(
        lost.sequence > first.agent_resources.cursor.get()
            && lost.sequence <= again.agent_resources.cursor.get(),
        "the settlement happened inside the interval this view was not there for"
    );

    // The state is only half of recovery. The other half is that the view now receives what
    // happens next, on this same service connection, and that what it receives is what the host
    // wrote down. One more resource settles, and the view is told about it as a notification.
    let next_to_settle = held
        .iter()
        .find(|resource| {
            resource.resource_id != settling.resource_id && !resource.state.is_terminal()
        })
        .expect("another resource is still open");
    let resumed = kr_worker::broker::ReplayCursor {
        generation: again.agent_resources.stream_generation.get(),
        sequence: again.agent_resources.cursor.get(),
    };
    broker
        .upstream_resolved(&next_to_settle.request, TimestampMs::new(4))
        .expect("the upstream withdraws this one too");

    let received = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        wait_for_agent_resource(&mut client, next_to_settle.resource_id),
    )
    .await
    .expect("a subscribed view is told about a transition committed after its snapshot");

    // What arrived is compared with what the host recorded, field by field: an event a view acts
    // on has to be the transition the outbox holds, not a summary of it.
    let recorded = broker
        .replay_after(resumed)
        .expect("the outbox reads")
        .events
        .into_iter()
        .find(|event| event.resource_id == next_to_settle.resource_id)
        .expect("the settlement is in the outbox after the snapshot's position");
    assert_eq!(received.sequence.get(), recorded.sequence);
    assert!(
        received.sequence.get() > again.agent_resources.cursor.get(),
        "a view applies it because its position is above the snapshot's"
    );
    assert_eq!(received.event_id, recorded.event_id);
    assert_eq!(received.stream_generation.get(), broker.stream_generation());
    assert_eq!(received.state, recorded.state);
    assert_eq!(received.durability, recorded.durability);
    assert_eq!(received.causal_root, recorded.causal_root);
    assert_eq!(received.binding_revision, recorded.binding_revision);
    assert_eq!(
        received.application_instance_id,
        recorded.application_instance_id
    );
    assert_eq!(received.actor_id.0, recorded.actor_id);
    assert_eq!(
        received
            .parent_sequence
            .0
            .map(kr_protocol::scalars::U64::get),
        recorded.parent_sequence
    );
    assert_eq!(received.session_id, session());

    carrying.abort();
    served.drained.abort();
}

/// Reads frames until the worker tells this client about one resource's transition.
async fn wait_for_agent_resource(
    client: &mut kr_ipc::client::LocalClient,
    resource_id: kr_protocol::ids::PendingResourceId,
) -> kr_protocol::projection::AgentResourceEvent {
    loop {
        if let kr_protocol::envelope::ControlFrame::Notification(notification) =
            client.recv().await.expect("the worker is serving")
            && notification.event_type.as_str() == kr_protocol::projection::AGENT_RESOURCE_EVENT
        {
            let event: kr_protocol::projection::AgentResourceEvent =
                notification.payload.to_typed().expect("decodes");
            if event.resource_id == resource_id {
                return event;
            }
        }
    }
}

/// KR-REQ-12.11 and KR-REQ-12.13: a state too large for one frame is recovered page by page while
/// the host goes on working.
///
/// How many requests a host is arbitrating is decided by its upstreams, so the state a lost view
/// installs is not a size this host chooses. Here it is deliberately larger than one control
/// frame. The subscription still answers, because what it answers with is a bounded page of a copy
/// taken when its cursor was fixed, and it says where the rest continues.
///
/// A request settles between every two pages, which is the case that decides the contract: a host
/// that refused a continuation whenever its state moved would never let a busy session finish a
/// recovery at all. The pages come out of the copy, so they are one state whatever the host does
/// meanwhile, and what the client ends with - the pages, with the events above the copy's cursor
/// applied to them - is exactly what the host holds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_12_11_a_recovery_larger_than_one_control_frame_is_given_back_in_pages() {
    let host = kr_ipc::testing::TempHost::create();
    // A quiet application and a generous queue: this test is about the size of the state, not
    // about a view falling behind on output.
    let (service, _runtime, mut client, attachment_id) =
        service_and_attached_client(session(), &host, "sleep 120", 1 << 20).await;
    let broker = Arc::clone(service.broker());
    let connection = prepare_broker(&broker, rich());
    let served = duplex_watched_on(&broker, connection).await;
    let owner = Arc::clone(&served.owner);
    // What this host forwards to the agent is read and discarded: the forwarding is how the
    // resources are made, and this test is about the state they add up to.
    let forwarded = tokio::spawn(async move {
        let mut client = served.client;
        let mut chunk = [0_u8; 8192];
        while let Ok(bytes) = tokio::io::AsyncReadExt::read(&mut client, &mut chunk).await {
            if bytes == 0 {
                break;
            }
        }
    });

    // Requests are forwarded until the whole state no longer fits one control frame. The
    // identifiers are padded to what an upstream may use, so the size is reached in the number of
    // requests a session really can produce.
    let padding = "d".repeat(200);
    let mut made = 0_u32;
    let whole = loop {
        for _ in 0..128 {
            owner
                .from_upstream(
                    format!(
                        r#"{{"id":"{padding}-{made}","method":"session/request_permission","params":{{}}}}"#
                    )
                    .as_bytes(),
                    TimestampMs::new(2),
                )
                .await
                .expect("the request is carried");
            made += 1;
        }
        let held = broker.pending_resources();
        let measured = kr_worker::snapshot::wire::measure(&held).expect("the state encodes");
        if measured.bytes > kr_protocol::limits::MAX_CONTROL_FRAME_LEN {
            break held;
        }
        assert!(
            made < 20_000,
            "the state grows with what is forwarded to it"
        );
    };
    assert!(
        kr_worker::snapshot::wire::measure(&whole)
            .expect("the state encodes")
            .bytes
            > kr_protocol::limits::MAX_CONTROL_FRAME_LEN,
        "the state this view has to install is larger than one frame can carry"
    );

    // Subscribing answers with a page, not with the state.
    let first = subscribe(&mut client, session(), attachment_id).await;
    assert!(
        first.agent_resources.resources.len() < whole.len(),
        "one answer carries part of the state"
    );
    assert!(
        first.agent_resources.resources.len() <= kr_worker::broker::MAX_SNAPSHOT_RESOURCES,
        "bounded by how many resources one page carries"
    );
    assert!(
        kr_worker::snapshot::wire::measure(&first)
            .expect("the answer encodes")
            .bytes
            <= kr_protocol::limits::MAX_CONTROL_FRAME_LEN,
        "and the answer itself fits the frame it has to travel in"
    );
    let continuing = first
        .agent_resources
        .continue_after
        .0
        .expect("the state continues past the first page");

    // The rest is read out of the copy, and a request settles between every two pages.
    let mut installed: std::collections::BTreeMap<
        kr_protocol::ids::PendingResourceId,
        kr_protocol::gateway::PendingState,
    > = first
        .agent_resources
        .resources
        .iter()
        .map(|resource| (resource.resource_id, resource.state))
        .collect();
    let mut collected: Vec<kr_protocol::ids::PendingResourceId> = first
        .agent_resources
        .resources
        .iter()
        .map(|resource| resource.resource_id)
        .collect();
    let mut after = Some(continuing);
    let mut pages = 1_usize;
    let mut settled = 0_usize;
    while let Some(resource_id) = after {
        // The host commits a transition between every two pages, and it settles the request with
        // the highest identifier left, which is one no page has carried yet: a page cut from the
        // live arbitration would show it settled, and the copy has to show it as it was. Under a
        // rule that refused a continuation whenever the state moved, the client would stop here
        // for ever.
        let settling = &whole[whole.len() - 1 - settled];
        broker
            .upstream_resolved(
                &settling.request,
                TimestampMs::new(3 + u64::try_from(settled).expect("a small count")),
            )
            .expect("the upstream withdraws its own request");
        settled += 1;

        let page = snapshot_page(
            &mut client,
            session(),
            Some(kr_protocol::projection::AgentResourceSnapshotContinuation {
                snapshot_id: first.agent_resources.snapshot_id,
                after_resource_id: resource_id,
            }),
        )
        .await
        .expect("a copy that has not ended is read to its end")
        .agent_resources;
        assert_eq!(
            page.stream_generation.get(),
            first.agent_resources.stream_generation.get(),
            "every page names the run the first one named"
        );
        assert_eq!(
            page.cursor.get(),
            first.agent_resources.cursor.get(),
            "and the position the copy was taken at, which the host has moved past"
        );
        assert!(
            !page.resources.is_empty(),
            "a continuation that is answered carries something, so the paging ends"
        );
        assert!(
            kr_worker::snapshot::wire::measure(&page)
                .expect("the page encodes")
                .bytes
                <= kr_protocol::limits::MAX_CONTROL_FRAME_LEN
        );
        collected.extend(page.resources.iter().map(|resource| resource.resource_id));
        installed.extend(
            page.resources
                .iter()
                .map(|resource| (resource.resource_id, resource.state)),
        );
        after = page.continue_after.0;
        pages += 1;
        assert!(pages < 1_000, "the paging makes progress");
    }
    assert!(pages > 1, "a state this size takes more than one page");
    assert_eq!(
        settled,
        pages - 1,
        "and the host settled a request before every one of those continuations"
    );

    // The pages are the copy: every resource the host held when it was taken, once each.
    let mut expected: Vec<_> = whole.iter().map(|resource| resource.resource_id).collect();
    expected.sort_unstable();
    let mut sorted = collected.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(
        sorted.len(),
        collected.len(),
        "no resource is carried by two pages"
    );
    assert_eq!(sorted, expected, "and none is left out of all of them");

    // And the copy is a state of the past, not of now: what settled while the client paged is
    // still pending in what it installed, including the requests that settled before the page
    // carrying them was cut.
    for resource_id in whole
        .iter()
        .rev()
        .take(settled)
        .map(|resource| resource.resource_id)
    {
        assert_eq!(
            installed.get(&resource_id),
            Some(&kr_protocol::gateway::PendingState::Pending),
            "a copy does not change under its reader"
        );
    }

    // The way back to now is the events above the copy's cursor, which is what a view applies
    // after it installs the pages. The two together are the host's state exactly.
    let mut cursor = kr_worker::broker::ReplayCursor {
        generation: first.agent_resources.stream_generation.get(),
        sequence: first.agent_resources.cursor.get(),
    };
    let mut replayed = 0_usize;
    loop {
        let replay = broker.replay_after(cursor).expect("the stream is readable");
        assert!(
            !replay.reset,
            "the copy belongs to the run that is still live"
        );
        assert!(!replay.gap, "and nothing after it was lost");
        for event in &replay.events {
            installed.insert(event.resource_id, event.state);
            replayed += 1;
        }
        cursor = replay.cursor;
        if !replay.more {
            break;
        }
    }
    assert_eq!(
        replayed, settled,
        "the stream above the cursor carries what the host did while the client paged"
    );
    let held: std::collections::BTreeMap<_, _> = broker
        .pending_resources()
        .iter()
        .map(|resource| (resource.resource_id, resource.state))
        .collect();
    assert_eq!(
        installed, held,
        "so the pages and the events above them are the state the host is in"
    );

    // A copy that has been read to its end is not there to continue, and that refusal is the only
    // one: the client starts again, and the fresh recovery finishes.
    let refused = snapshot_page(
        &mut client,
        session(),
        Some(kr_protocol::projection::AgentResourceSnapshotContinuation {
            snapshot_id: first.agent_resources.snapshot_id,
            after_resource_id: collected[0],
        }),
    )
    .await
    .expect_err("a copy that has ended is not continued");
    assert_eq!(
        refused.code,
        kr_protocol::error::ErrorCode::ResyncRequired,
        "and the client is told to install a fresh one"
    );

    let fresh = snapshot_page(&mut client, session(), None)
        .await
        .expect("a fresh snapshot is answered")
        .agent_resources;
    assert!(
        fresh.cursor.get() > first.agent_resources.cursor.get(),
        "and it is the state as it now stands"
    );
    let mut again: Vec<_> = fresh
        .resources
        .iter()
        .map(|resource| resource.resource_id)
        .collect();
    let mut after = fresh.continue_after.0;
    while let Some(resource_id) = after {
        let page = snapshot_page(
            &mut client,
            session(),
            Some(kr_protocol::projection::AgentResourceSnapshotContinuation {
                snapshot_id: fresh.snapshot_id,
                after_resource_id: resource_id,
            }),
        )
        .await
        .expect("the retry is read to its end")
        .agent_resources;
        again.extend(page.resources.iter().map(|resource| resource.resource_id));
        after = page.continue_after.0;
    }
    again.sort_unstable();
    assert_eq!(again, expected, "the retry installs the whole state");

    forwarded.abort();
}

/// KR-REQ-12.11: two views recover at once, and neither reads the other's copy.
///
/// One host serves many clients, and a lost view is not a rare event: an overflow that costs one
/// view its place often costs several. Each connection's copy is its own, taken at its own
/// position, so one client's recovery neither waits for another's nor shows it the other's state,
/// and a continuation that names a copy this connection is not reading is refused rather than
/// answered out of the wrong one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_12_11_two_views_recover_out_of_their_own_copies() {
    let host = kr_ipc::testing::TempHost::create();
    let (service, _runtime, mut client, _attachment_id) =
        service_and_attached_client(session(), &host, "sleep 120", 1 << 20).await;
    let broker = Arc::clone(service.broker());
    let connection = prepare_broker(&broker, rich());
    let served = duplex_watched_on(&broker, connection).await;
    let owner = Arc::clone(&served.owner);
    let forwarded = tokio::spawn(async move {
        let mut client = served.client;
        let mut chunk = [0_u8; 8192];
        while let Ok(bytes) = tokio::io::AsyncReadExt::read(&mut client, &mut chunk).await {
            if bytes == 0 {
                break;
            }
        }
    });

    // Enough requests that a recovery takes more than one page.
    for index in 0..(kr_worker::broker::MAX_SNAPSHOT_RESOURCES + 40) {
        owner
            .from_upstream(
                format!(
                    r#"{{"id":"request-{index}","method":"session/request_permission","params":{{}}}}"#
                )
                .as_bytes(),
                TimestampMs::new(2),
            )
            .await
            .expect("the request is carried");
    }
    let whole = broker.pending_resources();
    let last = whole.last().expect("a resource is held").clone();

    let endpoint = host
        .environment()
        .worker_endpoint(kr_protocol::session::DisplayNumber::new(1))
        .expect("an endpoint");
    let mut other = kr_ipc::client::LocalClient::connect(
        &endpoint,
        kr_protocol::local::LocalClientKind::Cli,
        kr_protocol::ids::BuildId::new("kr-test/0").expect("a build"),
    )
    .await
    .expect("connects");

    // One view starts its recovery, the host settles a request, and the other view starts its own.
    // The two copies are of different positions and of different states.
    let mine = snapshot_page(&mut client, session(), None)
        .await
        .expect("the first view is answered")
        .agent_resources;
    broker
        .upstream_resolved(&last.request, TimestampMs::new(3))
        .expect("the upstream withdraws its own request");
    let theirs = snapshot_page(&mut other, session(), None)
        .await
        .expect("the second view is answered")
        .agent_resources;
    assert!(
        theirs.cursor.get() > mine.cursor.get(),
        "the second copy was taken after the host moved"
    );

    // Naming another connection's copy is not a way into it. This is asked while both copies are
    // unfinished, so what refuses it is whose copy it is and not a copy that has ended.
    let refused = snapshot_page(
        &mut other,
        session(),
        Some(kr_protocol::projection::AgentResourceSnapshotContinuation {
            snapshot_id: mine.snapshot_id,
            after_resource_id: mine
                .continue_after
                .0
                .expect("the first view's state continues"),
        }),
    )
    .await
    .expect_err("a connection has no copy of another connection's snapshot");
    assert_eq!(refused.code, kr_protocol::error::ErrorCode::ResyncRequired);

    // Each connection reads its own copy, a page at a time, in step with the other.
    let mut mine_installed = page_states(&mine);
    let mut theirs_installed = page_states(&theirs);
    let mut mine_after = mine.continue_after.0;
    let mut theirs_after = theirs.continue_after.0;
    assert!(
        mine_after.is_some() && theirs_after.is_some(),
        "a state this size takes more than one page either way"
    );
    while mine_after.is_some() || theirs_after.is_some() {
        if let Some(resource_id) = mine_after {
            let page = snapshot_page(
                &mut client,
                session(),
                Some(kr_protocol::projection::AgentResourceSnapshotContinuation {
                    snapshot_id: mine.snapshot_id,
                    after_resource_id: resource_id,
                }),
            )
            .await
            .expect("my copy is still mine to read")
            .agent_resources;
            assert_eq!(
                page.cursor.get(),
                mine.cursor.get(),
                "and it is still the position I started at"
            );
            mine_installed.extend(page_states(&page));
            mine_after = page.continue_after.0;
        }
        if let Some(resource_id) = theirs_after {
            let page = snapshot_page(
                &mut other,
                session(),
                Some(kr_protocol::projection::AgentResourceSnapshotContinuation {
                    snapshot_id: theirs.snapshot_id,
                    after_resource_id: resource_id,
                }),
            )
            .await
            .expect("their copy is still theirs to read")
            .agent_resources;
            assert_eq!(
                page.cursor.get(),
                theirs.cursor.get(),
                "and it is still the position they started at"
            );
            theirs_installed.extend(page_states(&page));
            theirs_after = page.continue_after.0;
        }
    }

    // Both installed the whole state, and each installed its own.
    let expected: std::collections::BTreeSet<_> =
        whole.iter().map(|resource| resource.resource_id).collect();
    assert_eq!(
        mine_installed
            .keys()
            .copied()
            .collect::<std::collections::BTreeSet<_>>(),
        expected
    );
    assert_eq!(
        theirs_installed
            .keys()
            .copied()
            .collect::<std::collections::BTreeSet<_>>(),
        expected
    );
    assert_eq!(
        mine_installed.get(&last.resource_id),
        Some(&kr_protocol::gateway::PendingState::Pending),
        "the copy taken before the settlement still holds the request as pending"
    );
    assert_ne!(
        theirs_installed.get(&last.resource_id),
        Some(&kr_protocol::gateway::PendingState::Pending),
        "and the copy taken after it does not"
    );

    forwarded.abort();
}

/// KR-REQ-12.11: a recovery is cut to what the peer said it can receive, answer and all.
///
/// A page is not the whole answer. The same frame carries the session, its attachments and the
/// cursors, and how much those spend is the session's business rather than this host's. So the
/// host measures the answer it is about to send and cuts the page to what is left of the frame.
/// Here the peer says it can receive a sixteenth of the usual frame and the resources carry long
/// upstream identifiers, which is the case an estimate gets wrong: every answer this test reads
/// has to fit the frame it travelled in, and the client's own decoder would refuse it otherwise.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_12_11_a_recovery_fits_a_peer_that_receives_little() {
    let host = kr_ipc::testing::TempHost::create();
    let (service, _runtime, _client, _attachment_id) =
        service_and_attached_client(session(), &host, "sleep 120", 1 << 20).await;
    let broker = Arc::clone(service.broker());
    let connection = prepare_broker(&broker, rich());
    let served = duplex_watched_on(&broker, connection).await;
    let owner = Arc::clone(&served.owner);
    let forwarded = tokio::spawn(async move {
        let mut client = served.client;
        let mut chunk = [0_u8; 8192];
        while let Ok(bytes) = tokio::io::AsyncReadExt::read(&mut client, &mut chunk).await {
            if bytes == 0 {
                break;
            }
        }
    });

    // Resources an upstream made large: the identifier is the one field it decides the length of,
    // and a page of these passes a small frame long before it passes the count bound.
    let padding = "m".repeat(200);
    for index in 0..300_u32 {
        owner
            .from_upstream(
                format!(
                    r#"{{"id":"{padding}-{index}","method":"session/request_permission","params":{{}}}}"#
                )
                .as_bytes(),
                TimestampMs::new(2),
            )
            .await
            .expect("the request is carried");
    }
    let whole: std::collections::BTreeSet<_> = broker
        .pending_resources()
        .iter()
        .map(|resource| resource.resource_id)
        .collect();

    // A client that says it can receive a sixteenth of the usual control frame.
    let frame = kr_protocol::limits::MAX_CONTROL_FRAME_LEN / 16;
    let mut small = kr_ipc::client::LocalClient::connect_receiving(
        &host
            .environment()
            .worker_endpoint(kr_protocol::session::DisplayNumber::new(1))
            .expect("an endpoint"),
        kr_protocol::local::LocalClientKind::Cli,
        kr_protocol::ids::BuildId::new("kr-test/0").expect("a build"),
        kr_protocol::hello::ReceiveLimits {
            max_control_frame_len: kr_protocol::scalars::U64::new(frame as u64),
            ..kr_protocol::hello::ReceiveLimits::default()
        },
    )
    .await
    .expect("connects");

    // The whole recovery, page by page, with every answer measured against the frame it came in.
    let mut installed: std::collections::BTreeSet<kr_protocol::ids::PendingResourceId> =
        std::collections::BTreeSet::new();
    let mut answer = snapshot_page(&mut small, session(), None)
        .await
        .expect("the first page is answered");
    let mut pages = 0_usize;
    loop {
        // Against the frame less what a stream header spends, which is the whole of what this
        // peer said it can receive: the payload measured here travels inside that.
        let carried = frame - kr_protocol::limits::MAX_STREAM_HEADER_LEN;
        let measured = kr_worker::snapshot::wire::measure(&answer)
            .expect("the answer encodes")
            .bytes;
        assert!(
            measured <= carried,
            "an answer this peer cannot receive is an answer it never gets: {measured} against \
             {carried}"
        );
        installed.extend(
            answer
                .agent_resources
                .resources
                .iter()
                .map(|resource| resource.resource_id),
        );
        pages += 1;
        assert!(pages < 1_000, "the paging makes progress");
        let Some(after) = answer.agent_resources.continue_after.0 else {
            break;
        };
        answer = snapshot_page(
            &mut small,
            session(),
            Some(kr_protocol::projection::AgentResourceSnapshotContinuation {
                snapshot_id: answer.agent_resources.snapshot_id,
                after_resource_id: after,
            }),
        )
        .await
        .expect("a copy that has not ended is read to its end");
    }
    assert!(
        pages > 1,
        "a frame this size cannot carry this state in one page"
    );
    assert_eq!(
        installed, whole,
        "and the pages together are the whole state"
    );

    forwarded.abort();
}

/// What one page of a recovery says each of its resources is.
fn page_states(
    page: &kr_protocol::projection::AgentResourceSnapshot,
) -> std::collections::BTreeMap<
    kr_protocol::ids::PendingResourceId,
    kr_protocol::gateway::PendingState,
> {
    page.resources
        .iter()
        .map(|resource| (resource.resource_id, resource.state))
        .collect()
}

/// Reads one page of a session's snapshot, continuing a paged one where `from` names it.
async fn snapshot_page(
    client: &mut kr_ipc::client::LocalClient,
    session_id: SessionId,
    from: Option<kr_protocol::projection::AgentResourceSnapshotContinuation>,
) -> std::result::Result<
    kr_protocol::recovery::EventsSnapshotResult,
    kr_protocol::error::ProtocolError,
> {
    Ok(client
        .request(
            kr_protocol::method::Method::EventsSnapshot,
            &kr_protocol::recovery::EventsSnapshotParams {
                session_id,
                agent_resources_from: Nullable(from),
            },
        )
        .await
        .expect("the call reaches the worker")?
        .to_typed()
        .expect("decodes"))
}

/// What one resource's state is, as the broker holds it.
fn settling_state(
    held: &[kr_protocol::gateway::PendingResource],
    resource_id: kr_protocol::ids::PendingResourceId,
) -> kr_protocol::gateway::PendingState {
    held.iter()
        .find(|resource| resource.resource_id == resource_id)
        .expect("the broker holds it")
        .state
}

/// Reads frames until the worker tells this client to resynchronise.
async fn wait_for_resync(
    client: &mut kr_ipc::client::LocalClient,
) -> kr_protocol::recovery::ResyncRequired {
    loop {
        match client.recv().await.expect("the worker is serving") {
            kr_protocol::envelope::ControlFrame::Notification(notification)
                if notification.event_type.as_str() == "session.resync" =>
            {
                return notification.payload.to_typed().expect("decodes");
            }
            _ => {}
        }
    }
}
