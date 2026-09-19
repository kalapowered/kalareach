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
    Observatory, TransportHandle,
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
    let observatory = Observatory::new();
    let observations = observatory.subscribe(GatewayConnectionId::new(1));
    let (upstream_reads, upstream_writes) = tokio::io::split(upstream_here);
    let (owner, writes) = Duplex::new(
        Arc::clone(broker),
        GatewayConnectionId::new(1),
        framing,
        upstream_writes,
        tokio::io::split(client_here).1,
        observatory,
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
