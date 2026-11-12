//! What the stream of a gateway connection says about the terminal's conversation and turn, read
//! by the core from the places the installed connector's table names.
//!
//! Each case installs the Codex-shaped test package whose table answers an approval as a response
//! and names where its messages name a thread, a turn and a cleared request, binds it to an
//! instance as a launch does, and opens a connection whose owner the case drives by hand: what the
//! terminal sends goes in through the client end, what the server says through the upstream end.
//! The instance's binding, its suspension and its capability map are read back from the broker.
//!
//! Not claimed: Windows, where no gateway runs.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use kr_protocol::broker::{InstanceCapabilityState, IntegrationMode};
use kr_protocol::gateway::{NativeFraming, PendingState};
use kr_protocol::identity::{ProcessStartIdentity, ProcessStartSource};
use kr_protocol::ids::{
    ApplicationInstanceId, BrokerBindingId, CapabilityId, EnvironmentId, GatewayConnectionId,
    SessionId, UpstreamRequestId,
};
use kr_protocol::scalars::{Digest256, TimestampMs, Uuid};
use kr_worker::broker::binder::MatchedExecutable;
use kr_worker::broker::catalogue::{Admissions, testing};
use kr_worker::broker::connectors::{
    ConnectorSources, InstalledConnector, QualifiedExecutable, fixture,
};
use kr_worker::broker::{
    Broker, BrokerTransport, Carried, Credential, Duplex, Framing, ManagedProcess, TransportHandle,
};
use kr_worker::persistence::JournalHealth;
use tokio::io::AsyncReadExt as _;

mod common;

const NOW: TimestampMs = TimestampMs::new(10);

fn session() -> SessionId {
    SessionId::new(Uuid::from_bytes([1; 16]))
}

fn instance() -> ApplicationInstanceId {
    ApplicationInstanceId::new(Uuid::from_bytes([2; 16]))
}

fn process() -> ProcessStartIdentity {
    ProcessStartIdentity::new(41, ProcessStartSource::MacosProcBsdInfo, 900)
}

fn executable() -> Digest256 {
    Digest256::from_bytes([3; 32])
}

/// A directory of the test's own, removed when it is dropped.
struct Store(PathBuf);

impl Drop for Store {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// One instance bound to the answering Codex-shaped package, with a connection open on its
/// tables and an owner over two pipes.
struct World {
    _store: Store,
    broker: Arc<Broker>,
    owner: Arc<Duplex>,
    /// What the owner wrote to the server.
    upstream: tokio::io::DuplexStream,
    /// What the owner wrote to the terminal.
    _client: tokio::io::DuplexStream,
    connection: GatewayConnectionId,
    writes: tokio::task::JoinHandle<()>,
    /// What an installation hands the worker, kept so a case can hand it a narrower grant.
    admissions: Admissions,
    sources: ConnectorSources,
    source: kr_worker::broker::connectors::ConnectorSource,
}

impl World {
    /// `upstream_capacity` bytes is what the pipe to the server holds before a write waits.
    fn new(upstream_capacity: usize) -> Self {
        Self::opened(upstream_capacity, None)
    }

    /// A world whose broker keeps its ledger beside a session's receipt journal and reads that
    /// journal's condition, as a worker's does.
    fn with_store(shared: &common::SharedStore) -> Self {
        Self::opened(1 << 20, Some(shared))
    }

    /// A world whose table also lists the requests and the reports that a recorded session of the
    /// real terminal and server uses, so that every recorded frame is one the table classifies.
    fn recorded(upstream_capacity: usize) -> Self {
        Self::opened_with(upstream_capacity, None, true)
    }

    fn opened(upstream_capacity: usize, shared: Option<&common::SharedStore>) -> Self {
        Self::opened_with(upstream_capacity, shared, false)
    }

    fn opened_with(
        upstream_capacity: usize,
        shared: Option<&common::SharedStore>,
        recorded: bool,
    ) -> Self {
        let root = std::env::temp_dir().join(format!("kr-stream-{}", kr_ipc::new_uuid()));
        std::fs::create_dir_all(&root).expect("a store directory");
        let store = Store(root);
        let shape = fixture::Shape::codex_backend_answering();
        let mut source = if recorded {
            fixture::package_with_connector(
                &store.0,
                Path::new(fixture::FORWARDER),
                &shape,
                recorded_table(&format!("kalareach/{}", shape.plugin_name)),
            )
        } else {
            fixture::package(&store.0, Path::new(fixture::FORWARDER), &shape)
        }
        .expect("the package is written");
        source.qualified = vec![QualifiedExecutable {
            digest: executable(),
            version: fixture::GATEWAY_QUALIFIED_VERSION.to_owned(),
        }];
        let connector = InstalledConnector::read(source.clone()).expect("the package is read");
        let broker = Arc::new(
            match shared {
                Some(shared) => Broker::open(Some(&shared.path), session(), shared.health()),
                None => Broker::open(None, session(), JournalHealth::shared()),
            }
            .expect("the broker opens"),
        );
        let admissions = Admissions::new();
        let sources = ConnectorSources::new();
        let frame = testing::admit(
            &admissions,
            &sources,
            &broker,
            vec![testing::admitted(&source)],
            1,
        );
        broker
            .register_instance(
                instance(),
                IntegrationMode::Gateway,
                None,
                Some(ManagedProcess::new(
                    instance(),
                    process(),
                    TransportHandle {
                        transport: BrokerTransport::PrivateSocket,
                        application_instance_id: instance(),
                        executable_digest: executable(),
                        process: process(),
                    },
                    Credential::from_bytes([9; 32]),
                    TimestampMs::new(1),
                )),
            )
            .expect("the instance is registered");
        broker
            .bind(
                BrokerBindingId::new(Uuid::from_bytes([7; 16])),
                instance(),
                source.package_digest,
                frame,
                MatchedExecutable {
                    path: "/usr/local/bin/codex".to_owned(),
                    digest: executable(),
                },
                NOW,
            )
            .expect("the package is bound");
        broker
            .withhold_thread(instance())
            .expect("the instance withholds its thread");
        let tables = broker
            .pin_compiled(instance(), &connector, &executable())
            .expect("the compiled tables are pinned");
        let connection = broker
            .open_native_connection(
                instance(),
                &[9; 32],
                &process(),
                &connector.plugin_id(),
                &tables.protocol_version,
            )
            .expect("a native connection opens");
        let (upstream_here, upstream) = tokio::io::duplex(upstream_capacity);
        let (client_here, client) = tokio::io::duplex(1 << 20);
        let (owner, writes) = Duplex::new(
            Arc::clone(&broker),
            connection,
            Framing::new(NativeFraming::JsonLines),
            upstream_here,
            client_here,
            EnvironmentId::new(Uuid::from_bytes([4; 16])),
            "agent-user",
        );
        // What carries an answer out on the connection, as the gateway's own attachment binds it.
        let dispatch = owner.dispatch().expect("the connection has a dispatch");
        broker.bind_connection_dispatch(connection, dispatch.clone());
        broker
            .bind_dispatch(instance(), dispatch)
            .expect("the instance has a transport");
        Self {
            _store: store,
            broker,
            owner,
            upstream,
            _client: client,
            connection,
            writes: tokio::spawn(writes),
            admissions,
            sources,
            source,
        }
    }

    /// The terminal sends a request the server has not answered, and the host's identifier for it.
    async fn terminal_asks(&self, frame: &str) -> UpstreamRequestId {
        match self
            .owner
            .from_client(frame.as_bytes(), NOW)
            .await
            .expect("the request is carried")
        {
            Carried::ClientRequest {
                upstream_request_id,
                ..
            } => upstream_request_id,
            other => panic!("not a request of the terminal's: {other:?}"),
        }
    }

    /// The terminal sends a notification, which no reply follows.
    async fn terminal_says(&self, frame: &str) {
        self.owner
            .from_client(frame.as_bytes(), NOW)
            .await
            .expect("the notification is carried");
    }

    /// The server answers a request of the terminal's, whose identifier this host minted.
    async fn server_answers(&self, id: &UpstreamRequestId, rest: &str) {
        let frame = format!(r#"{{"id":{},{rest}}}"#, id.as_str());
        self.owner
            .from_upstream(frame.as_bytes(), NOW)
            .await
            .expect("the answer is carried");
    }

    /// The server says something of its own.
    async fn server_says(&self, frame: &str) {
        self.owner
            .from_upstream(frame.as_bytes(), NOW)
            .await
            .expect("the frame is carried");
    }

    /// The terminal selects a thread, and the server answers, so the binding names it. What the
    /// server was sent for it is read, so the next line it reads is the case's.
    async fn terminal_selects(&mut self, thread: &str) {
        let selecting = self.terminal_asks(START).await;
        assert_eq!(self.server_reads().await["method"], "thread/start");
        self.server_answers(&selecting, &named(thread)).await;
    }

    /// An answer a rich client prepares for the one pending request, admitted at the binding now.
    fn rich_answer(&self, option: &str) -> kr_protocol::agent::AgentApprovalRespondParams {
        let resource = self.broker.pending_resources()[0].resource_id;
        kr_protocol::agent::AgentApprovalRespondParams {
            target: kr_protocol::agent::AgentMutationTarget {
                subject: kr_worker::broker::subject(session(), instance()),
                binding_revision: self.state().binding_revision,
            },
            resource_id: resource,
            option_id: option.to_owned(),
        }
    }

    fn owner_caller() -> kr_worker::broker::Caller {
        kr_worker::broker::Caller {
            actor_id: kr_protocol::ids::ActorId::new("owner").expect("an actor"),
            grant_id: None,
        }
    }

    /// Reads the next line the owner wrote to the server.
    async fn server_reads(&mut self) -> serde_json::Value {
        let mut line = Vec::new();
        let mut byte = [0_u8; 1];
        loop {
            self.upstream.read_exact(&mut byte).await.expect("a byte");
            if byte[0] == b'\n' {
                break;
            }
            line.push(byte[0]);
        }
        serde_json::from_slice(&line).expect("a frame")
    }

    fn thread(&self) -> Option<String> {
        self.state().thread_id.0.map(|thread| thread.to_string())
    }

    fn turn(&self) -> Option<String> {
        self.state().turn_id.0.map(|turn| turn.to_string())
    }

    fn state(&self) -> kr_protocol::agent::AgentBindingState {
        self.broker
            .binding_state(instance())
            .expect("the instance is held")
    }

    /// Why rich mutations wait, while they do.
    fn waiting(&self) -> Option<String> {
        self.state().suspension_reason.0
    }

    fn revision(&self) -> u64 {
        self.state().binding_revision.get()
    }

    /// Lets the deadline for the terminal's own requests pass, and waits for the owner to give up
    /// what the server did not answer.
    async fn past_the_deadline(&self) {
        tokio::time::advance(
            kr_worker::broker::CLIENT_REPLY_DEADLINE + std::time::Duration::from_secs(30),
        )
        .await;
        for _ in 0..200 {
            if self.owner.forwarded_client_requests() == 0 {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        panic!("the owner did not give up what the server never answered");
    }
}

impl Drop for World {
    fn drop(&mut self) {
        self.writes.abort();
    }
}

/// The methods a recorded session uses that the Codex-shaped table does not list: each is a read
/// or a report, with the wire name it travels under and the way it travels. A frame of a method
/// the table does not list suspends rich work, so without them no frame of the recording could be
/// checked for suspending it.
const RECORDED_ROUTES: &[(&str, &str, &str)] = &[
    ("model.list", "model/list", "host_to_upstream"),
    (
        "config-requirements.read",
        "configRequirements/read",
        "host_to_upstream",
    ),
    (
        "collaboration-mode.list",
        "collaborationMode/list",
        "host_to_upstream",
    ),
    ("hooks.list", "hooks/list", "host_to_upstream"),
    ("config.read", "config/read", "host_to_upstream"),
    (
        "thread.loaded.list",
        "thread/loaded/list",
        "host_to_upstream",
    ),
    ("skills.list", "skills/list", "host_to_upstream"),
    ("plugin.list", "plugin/list", "host_to_upstream"),
    (
        "thread.settings.updated",
        "thread/settings/updated",
        "upstream_to_host",
    ),
    (
        "thread.status.changed",
        "thread/status/changed",
        "upstream_to_host",
    ),
    ("notice.warning", "warning", "upstream_to_host"),
    ("notice.error", "error", "upstream_to_host"),
    ("item.started", "item/started", "upstream_to_host"),
    ("item.completed", "item/completed", "upstream_to_host"),
];

/// The Codex-shaped table with `RECORDED_ROUTES` listed as observations.
fn recorded_table(plugin_id: &str) -> String {
    let mut table: serde_json::Value =
        serde_json::from_str(&fixture::gateway_connector_json_answering(plugin_id, true))
            .expect("the fixture table reads");
    for (method, wire, direction) in RECORDED_ROUTES {
        table["routes"].as_array_mut().expect("routes").push(
            serde_json::json!({ "method": method, "wire_name": wire, "direction": direction }),
        );
        table["methods"]
            .as_array_mut()
            .expect("methods")
            .push(serde_json::json!({
                "method": method,
                "class": "observation",
                "evidence": "Reads or reports and changes nothing",
            }));
    }
    serde_json::to_string_pretty(&table).expect("the table encodes")
}

const START: &str = r#"{"id":1,"method":"thread/start","params":{}}"#;
const LEAVE_OTHER: &str =
    r#"{"id":3,"method":"thread/unsubscribe","params":{"threadId":"thread-9"}}"#;
const LEAVE_ONE: &str =
    r#"{"id":4,"method":"thread/unsubscribe","params":{"threadId":"thread-1"}}"#;
const REFUSED: &str = r#""error":{"code":-32600,"message":"no such thread"}"#;
const UNLISTED: &str = r#"{"id":7,"method":"fuzzyFileSearch","params":{"query":"x"}}"#;
const RESUME: &str = r#"{"id":2,"method":"thread/resume","params":{"threadId":"thread-2"}}"#;

fn binding_id() -> BrokerBindingId {
    BrokerBindingId::new(Uuid::from_bytes([7; 16]))
}

fn named(thread: &str) -> String {
    format!(r#""result":{{"thread":{{"id":"{thread}"}}}}"#)
}

fn turn_event(method: &str, thread: &str, turn: &str) -> String {
    format!(
        r#"{{"method":"{method}","params":{{"threadId":"{thread}","turn":{{"id":"{turn}"}}}}}}"#
    )
}

impl World {
    /// What a rich client sends to act on the instance, at the binding now.
    fn target(&self) -> kr_protocol::agent::AgentMutationTarget {
        kr_protocol::agent::AgentMutationTarget {
            subject: kr_worker::broker::subject(session(), instance()),
            binding_revision: self.state().binding_revision,
        }
    }

    fn prompt(&self, text: &str) -> kr_protocol::agent::AgentPromptParams {
        kr_protocol::agent::AgentPromptParams {
            target: self.target(),
            draft_id: kr_protocol::scalars::Nullable::null(),
            text: kr_protocol::scalars::Nullable::some(
                kr_protocol::agent::PromptText::new(text).expect("a prompt"),
            ),
        }
    }

    fn turn_id(turn: &str) -> kr_protocol::ids::AgentTurnId {
        kr_protocol::ids::AgentTurnId::new(turn).expect("a turn")
    }

    /// Reads the one request the host sends the server and answers it as the server would, with
    /// `rest` as what follows the identifier. What was sent is returned.
    async fn served(&mut self, rest: &str) -> serde_json::Value {
        let sent = self.server_reads().await;
        let id = UpstreamRequestId::new(sent["id"].to_string()).expect("an identifier");
        self.server_answers(&id, rest).await;
        sent
    }

    /// Asserts nothing was written to the server, once what the owner took has been settled.
    ///
    /// The owner counts a frame from the moment it takes it until its writer has settled it, and
    /// the writer settles it a moment after the frame's last byte is in the stream: a case that has
    /// just read a frame the owner wrote can meet it still counted. So this waits until the owner
    /// counts nothing, which is when every frame it took is in the stream, and reads the stream
    /// then, where a byte of one would be found at once: a writer that is slow to run cannot make
    /// a frame look absent, and no delay decides the case. The wait ends only a writer that never
    /// settles a frame it took. It claims no more than that nothing further was written: the count
    /// falls before the frame's completion work has run. The read is outside the runtime's budget,
    /// which would otherwise answer it as not ready while the bytes are there.
    async fn nothing_written(&mut self) {
        use futures_util::FutureExt as _;
        let started = std::time::Instant::now();
        while self.owner.queued_to_upstream() > 0 {
            assert!(
                started.elapsed() < std::time::Duration::from_secs(30),
                "the owner did not settle the frames it took: {} bytes are still counted",
                self.owner.queued_to_upstream()
            );
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
        let mut byte = [0_u8; 1];
        let read =
            tokio::task::coop::unconstrained(self.upstream.read_exact(&mut byte)).now_or_never();
        assert!(read.is_none(), "the server was sent a byte: {byte:?}");
    }
}

/// KR-REQ-11.36: a prompt a rich client types reaches the server as the request the connector's
/// table spells for it, with the thread the binding holds and the text it carries.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_11_36_a_typed_prompt_is_the_request_the_connectors_table_spells() {
    let mut world = World::new(1 << 20);
    world.terminal_selects("thread-1").await;
    let params = world.prompt("hello");
    let broker = Arc::clone(&world.broker);
    let (result, sent) = tokio::join!(
        async {
            broker
                .agent_prompt(&World::owner_caller(), &params, false, NOW)
                .await
        },
        world.served(r#""result":{"turn":{"id":"turn-7"}}"#),
    );
    assert_eq!(sent["method"], "turn/start");
    assert_eq!(
        sent["params"],
        serde_json::json!({
            "threadId": "thread-1",
            "input": [{ "type": "text", "text": "hello" }]
        })
    );
    let result = result.expect("the prompt is carried");
    assert_eq!(
        result.turn_id.0.map(|turn| turn.to_string()).as_deref(),
        Some("turn-7"),
        "the turn the reply names, where the table says it does"
    );
}

/// KR-REQ-12.12 and KR-REQ-11.36: a steer names the turn it expects to be running and a
/// cancellation the turn it stops, each with the thread, and the reply to a steer names its turn
/// where the table says.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_12_12_a_steer_and_a_cancellation_name_the_turn_and_the_thread_the_table_spells() {
    let mut world = World::new(1 << 20);
    world.terminal_selects("thread-1").await;
    world
        .server_says(&turn_event("turn/started", "thread-1", "turn-7"))
        .await;
    assert_eq!(world.turn().as_deref(), Some("turn-7"));

    let steer = kr_protocol::agent::AgentSteerParams {
        target: world.target(),
        turn_id: World::turn_id("turn-7"),
        text: kr_protocol::agent::PromptText::new("the other file").expect("a steer"),
    };
    let broker = Arc::clone(&world.broker);
    let (steered, sent) = tokio::join!(
        async {
            broker
                .agent_steer(&World::owner_caller(), &steer, NOW)
                .await
        },
        world.served(r#""result":{"turnId":"turn-8"}"#),
    );
    assert_eq!(sent["method"], "turn/steer");
    assert_eq!(
        sent["params"],
        serde_json::json!({
            "threadId": "thread-1",
            "expectedTurnId": "turn-7",
            "input": [{ "type": "text", "text": "the other file" }]
        })
    );
    assert_eq!(
        steered
            .expect("the steer is carried")
            .turn_id
            .0
            .map(|turn| turn.to_string())
            .as_deref(),
        Some("turn-8"),
        "the turn the reply names, where the table says it does, and not the one asked for"
    );

    let cancel = kr_protocol::agent::AgentCancelParams {
        target: world.target(),
        turn_id: World::turn_id("turn-7"),
    };
    let (cancelled, sent) = tokio::join!(
        async {
            broker
                .agent_cancel(&World::owner_caller(), &cancel, NOW)
                .await
        },
        world.served(r#""result":{}"#),
    );
    assert_eq!(sent["method"], "turn/interrupt");
    assert_eq!(
        sent["params"],
        serde_json::json!({ "threadId": "thread-1", "turnId": "turn-7" })
    );
    cancelled.expect("the cancellation is carried");
}

/// KR-REQ-12.12: what the table does not declare, and what its template cannot be filled for, is
/// refused before the marker with nothing written.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_12_12_an_operation_the_table_does_not_spell_or_cannot_fill_writes_nothing() {
    let mut world = World::new(1 << 20);
    world.terminal_selects("thread-1").await;
    let caller = World::owner_caller();

    // The table spells no queue, so the capability map says so and the call is refused.
    let queued = world
        .broker
        .agent_prompt(&caller, &world.prompt("later"), true, NOW)
        .await
        .expect_err("a queue is not declared");
    assert!(
        matches!(
            queued,
            kr_worker::broker::BrokerError::UnsupportedCapability { .. }
        ),
        "{queued:?}"
    );
    world.nothing_written().await;

    // A prompt that names a draft would leave the draft's content out.
    let mut named = world.prompt("unused");
    named.text = kr_protocol::scalars::Nullable::null();
    named.draft_id = kr_protocol::scalars::Nullable::some(kr_protocol::ids::DraftId::new(
        kr_protocol::scalars::Uuid::from_bytes([5; 16]),
    ));
    let drafted = world
        .broker
        .agent_prompt(&caller, &named, false, NOW)
        .await
        .expect_err("a draft's content is not carried");
    assert!(
        drafted.to_string().contains("draft"),
        "the refusal says why: {drafted}"
    );
    world.nothing_written().await;

    // A steer of a turn that is not the one running, and a cancellation with none running.
    let steer = kr_protocol::agent::AgentSteerParams {
        target: world.target(),
        turn_id: World::turn_id("turn-9"),
        text: kr_protocol::agent::PromptText::new("x").expect("a steer"),
    };
    world
        .broker
        .agent_steer(&caller, &steer, NOW)
        .await
        .expect_err("no turn is running");
    world.nothing_written().await;

    // A prompt over a running turn is not a queued one.
    world
        .server_says(&turn_event("turn/started", "thread-1", "turn-7"))
        .await;
    let over = world
        .broker
        .agent_prompt(&caller, &world.prompt("again"), false, NOW)
        .await
        .expect_err("a turn is running");
    assert!(
        matches!(
            over,
            kr_worker::broker::BrokerError::PreconditionFailed { .. }
        ),
        "{over:?}"
    );
    world.nothing_written().await;
}

/// The declaration of the action the Codex-shaped package registers for cancelling a turn.
fn cancel_declaration() -> kr_plugin_sdk::effect::ActionDeclaration {
    serde_json::from_value(serde_json::json!({
        "id": "turn.cancel",
        "label": "Cancel the turn",
        "effect": "upstream.cancel",
        "implementation": { "type": "upstream_cancel" },
        "parameters": { "parameters": [] },
        "description": "Stop the turn that is running",
        "confirmation_required": false
    }))
    .expect("the declaration reads")
}

/// KR-REQ-11.28 and KR-REQ-23.30: an action the package declares as a cancellation of the running
/// turn is carried out by the host from the connector's own template. The host issues the token
/// for the invocation and spends it against its own plan, so the admission has the checks a
/// component's plan passes, and with no turn running nothing is admitted and nothing is written.
/// KR-REQ-09.06 and KR-REQ-23.46, the part about cancelling after dispatch: the cancellation of a
/// running turn is an action of its own, admitted by the host under a token it issues for it and
/// spent once, written to the upstream as a separate operation naming the thread and the turn, and
/// settled with a result that names the turn it cancelled. The route from `action.cancel` to this
/// action is not shown here.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_11_28_a_declared_cancellation_is_written_from_the_template_under_its_own_token() {
    let mut world = World::new(1 << 20);
    let binding_id = BrokerBindingId::new(Uuid::from_bytes([7; 16]));
    let declaration = cancel_declaration();
    let refused = world
        .broker
        .register_actions(binding_id, [&declaration])
        .expect("the action is registered");
    assert!(refused.is_empty(), "{refused:?}");
    world.terminal_selects("thread-1").await;
    let invoke = |world: &World| kr_protocol::agent::PluginActionInvokeParams {
        target: world.target(),
        plugin_id: kr_protocol::ids::PluginId::new("kalareach.codex").expect("a plugin"),
        action: kr_protocol::broker::ActionName::new("turn.cancel").expect("an action"),
        draft_id: kr_protocol::scalars::Nullable::null(),
        resource_id: kr_protocol::scalars::Nullable::null(),
        parameters: kr_protocol::scalars::Bytes::new(b"{}".to_vec()),
    };
    let caller = World::owner_caller();

    // No turn is running: the template cannot be filled, so the action is refused before its
    // marker, and the token the admission spent is consumed with it.
    let none = world
        .broker
        .admit_host_cancel(&caller, binding_id, &invoke(&world), NOW)
        .expect_err("no turn is running");
    assert!(
        matches!(
            none,
            kr_worker::broker::BrokerError::PreconditionFailed { .. }
        ),
        "{none:?}"
    );
    world.nothing_written().await;

    // A turn runs. The admission carries a plan, and taking it writes the template.
    world
        .server_says(&turn_event("turn/started", "thread-1", "turn-7"))
        .await;
    // A cancellation names no request.
    let mut naming = invoke(&world);
    naming.resource_id = kr_protocol::scalars::Nullable::some(
        kr_protocol::ids::PendingResourceId::new(Uuid::from_bytes([6; 16])),
    );
    let named_one = world
        .broker
        .admit_host_cancel(&caller, binding_id, &naming, NOW)
        .expect_err("a cancellation acts on the running turn");
    assert!(
        matches!(
            named_one,
            kr_worker::broker::BrokerError::InvalidArgument(_)
        ),
        "{named_one:?}"
    );
    world.nothing_written().await;
    let admitted = world
        .broker
        .admit_host_cancel(&caller, binding_id, &invoke(&world), NOW)
        .expect("the declared cancellation is admitted");
    assert!(
        admitted.carries_a_validated_plan(),
        "the host's plan is the declaration"
    );
    let taken = world
        .broker
        .take_plugin_action(&admitted)
        .expect("its permit is taken");
    let (dispatch, request) = taken.transmission();
    let pending = dispatch.submit(&request).expect("the request is queued");
    let in_flight = taken.submitted(pending);
    let (settled, sent) = tokio::join!(in_flight.settled(), world.served(r#""result":{}"#));
    assert_eq!(sent["method"], "turn/interrupt");
    assert_eq!(
        sent["params"],
        serde_json::json!({ "threadId": "thread-1", "turnId": "turn-7" })
    );
    assert_eq!(
        settled
            .expect("the upstream answered")
            .mutation
            .0
            .expect("the action reached the upstream")
            .turn_id
            .0
            .map(|turn| turn.to_string())
            .as_deref(),
        Some("turn-7"),
        "the receipt names the turn it cancelled"
    );

    // The token was spent with the admission, so the same invocation cannot be carried twice: its
    // permit is gone.
    assert!(world.broker.take_plugin_action(&admitted).is_err());
}

fn component_declaration(id: &str, effect: &str) -> kr_plugin_sdk::effect::ActionDeclaration {
    serde_json::from_value(serde_json::json!({
        "id": id,
        "label": "A component's action",
        "effect": effect,
        "implementation": { "type": "component" },
        "parameters": { "parameters": [] },
        "description": "An action the package's component prepares",
        "confirmation_required": false
    }))
    .expect("the declaration reads")
}

/// A plan a component returns, claiming `operation` for `action` over the empty arguments.
fn component_plan(
    action: &str,
    operation: kr_protocol::broker::PreparedOperation,
    arguments: &[u8],
) -> kr_protocol::broker::PreparedEffect {
    kr_protocol::broker::PreparedEffect {
        action: kr_protocol::broker::ActionName::new(action).expect("an action"),
        class: kr_protocol::authority::EffectClass::Write,
        operation,
        draft_id: kr_protocol::scalars::Nullable::null(),
        argument_hash: Digest256::from_bytes(kr_cbor::sha256(arguments)),
    }
}

/// KR-REQ-23.30 and KR-REQ-11.28: a component's plan for a cancellation is carried through the
/// table's template under the token the host issued for the invocation, and what it may not
/// prepare, or prepare for other arguments, is refused before anything is written.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_23_30_a_components_cancellation_is_carried_and_what_it_may_not_prepare_is_refused()
{
    use kr_protocol::broker::PreparedOperation;
    let mut world = World::new(1 << 20);
    let binding = binding_id();
    let cancel = component_declaration("cancel.by.component", "upstream.cancel");
    let prompt = component_declaration("prompt.by.component", "upstream.prompt");
    let refused = world
        .broker
        .register_actions(binding, [&cancel, &prompt])
        .expect("the actions are registered");
    assert!(refused.is_empty(), "{refused:?}");
    world.terminal_selects("thread-1").await;
    world
        .server_says(&turn_event("turn/started", "thread-1", "turn-7"))
        .await;
    let invoke = |world: &World, action: &str| kr_protocol::agent::PluginActionInvokeParams {
        target: world.target(),
        plugin_id: kr_protocol::ids::PluginId::new("kalareach.codex").expect("a plugin"),
        action: kr_protocol::broker::ActionName::new(action).expect("an action"),
        draft_id: kr_protocol::scalars::Nullable::null(),
        resource_id: kr_protocol::scalars::Nullable::null(),
        parameters: kr_protocol::scalars::Bytes::new(b"{}".to_vec()),
    };
    let caller = World::owner_caller();

    // An action that is not registered as a cancellation the host carries out is not carried out
    // by the host's own route, whatever it is called.
    let not_the_hosts = world
        .broker
        .admit_host_cancel(
            &caller,
            binding,
            &invoke(&world, "cancel.by.component"),
            NOW,
        )
        .expect_err("a component's action is not the host's cancellation");
    assert!(
        matches!(
            not_the_hosts,
            kr_worker::broker::BrokerError::InvalidArgument(_)
        ),
        "{not_the_hosts:?}"
    );
    world.nothing_written().await;

    // A plan that prepares another operation than the action's declaration says.
    let admitted = world
        .broker
        .admit_plugin_action(
            &caller,
            binding,
            &invoke(&world, "cancel.by.component"),
            None,
            NOW,
        )
        .expect("the invocation is admitted");
    let wrong = world
        .broker
        .validate_effect(
            &admitted,
            &component_plan(
                "cancel.by.component",
                PreparedOperation::UpstreamSubmit,
                b"{}",
            ),
        )
        .expect_err("a cancellation action cannot prepare a prompt");
    assert!(
        matches!(wrong, kr_worker::broker::BrokerError::InvalidArgument(_)),
        "{wrong:?}"
    );
    world.broker.abandon(&admitted);
    world.nothing_written().await;

    // A plan over arguments the token does not cover.
    let admitted = world
        .broker
        .admit_plugin_action(
            &caller,
            binding,
            &invoke(&world, "cancel.by.component"),
            None,
            NOW,
        )
        .expect("the invocation is admitted");
    let other = world
        .broker
        .validate_effect(
            &admitted,
            &component_plan(
                "cancel.by.component",
                PreparedOperation::UpstreamCancel,
                b"{\"x\":1}",
            ),
        )
        .expect_err("another argument hash");
    assert!(
        matches!(other, kr_worker::broker::BrokerError::Token(_)),
        "{other:?}"
    );
    world.broker.abandon(&admitted);
    world.nothing_written().await;

    // The plan the declaration allows is written as the cancellation template.
    let admitted = world
        .broker
        .admit_plugin_action(
            &caller,
            binding,
            &invoke(&world, "cancel.by.component"),
            None,
            NOW,
        )
        .expect("the invocation is admitted");
    world
        .broker
        .validate_effect(
            &admitted,
            &component_plan(
                "cancel.by.component",
                PreparedOperation::UpstreamCancel,
                b"{}",
            ),
        )
        .expect("the plan is the action's own");
    let taken = world
        .broker
        .take_plugin_action(&admitted)
        .expect("its permit is taken");
    let (dispatch, request) = taken.transmission();
    let pending = dispatch.submit(&request).expect("the request is queued");
    let in_flight = taken.submitted(pending);
    let (settled, sent) = tokio::join!(in_flight.settled(), world.served(r#""result":{}"#));
    assert_eq!(sent["method"], "turn/interrupt");
    assert_eq!(
        sent["params"],
        serde_json::json!({ "threadId": "thread-1", "turnId": "turn-7" })
    );
    settled.expect("the upstream answered");

    // A component's prompt has no source in the table: it is refused when the plan names it,
    // before the marker, and nothing is written.
    let admitted = world
        .broker
        .admit_plugin_action(
            &caller,
            binding,
            &invoke(&world, "prompt.by.component"),
            None,
            NOW,
        )
        .expect("the invocation is admitted");
    let unsourced = world
        .broker
        .validate_effect(
            &admitted,
            &component_plan(
                "prompt.by.component",
                PreparedOperation::UpstreamSubmit,
                b"{}",
            ),
        )
        .expect_err("the table spells no source for a component's prompt");
    assert!(
        matches!(&unsourced, kr_worker::broker::BrokerError::UnsupportedCapability { detail } if detail.contains("source")),
        "{unsourced:?}"
    );
    world.broker.abandon(&admitted);
    world.nothing_written().await;
}

/// KR-REQ-12.06: a terminal behind the gateway selects a conversation, and the instance's binding
/// is the conversation the server's reply names, from the stream and nowhere else.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_12_06_the_thread_a_selection_reply_names_is_the_binding_and_rich_mutations_resume()
{
    let world = World::new(1 << 20);
    // Before any reply names a conversation, nothing vouches for one.
    assert_eq!(world.thread(), None);
    assert!(
        world
            .waiting()
            .is_some_and(|reason| reason.contains("not read")),
        "{:?}",
        world.waiting()
    );
    let first_revision = world.revision();

    // While the request is in flight the instance waits for its own reason, and the terminal's
    // request is carried.
    let selecting = world.terminal_asks(START).await;
    assert!(
        world
            .waiting()
            .is_some_and(|reason| reason.contains("has not answered")),
        "{:?}",
        world.waiting()
    );
    world.server_answers(&selecting, &named("thread-1")).await;
    assert_eq!(world.thread().as_deref(), Some("thread-1"));
    assert_eq!(world.waiting(), None);
    assert_eq!(world.revision(), first_revision + 1);

    // The turn the server says started in the bound thread is the running turn; one in another
    // thread, an end of a turn that is not running and a turn of the same name in another thread
    // are not.
    world
        .server_says(&turn_event("turn/started", "thread-other", "turn-x"))
        .await;
    assert_eq!(world.turn(), None);
    world
        .server_says(&turn_event("turn/started", "thread-1", "turn-1"))
        .await;
    assert_eq!(world.turn().as_deref(), Some("turn-1"));
    world
        .server_says(&turn_event("turn/completed", "thread-1", "turn-0"))
        .await;
    assert_eq!(world.turn().as_deref(), Some("turn-1"));
    world
        .server_says(&turn_event("turn/completed", "thread-other", "turn-1"))
        .await;
    assert_eq!(world.turn().as_deref(), Some("turn-1"));
    world
        .server_says(&turn_event("turn/completed", "thread-1", "turn-1"))
        .await;
    assert_eq!(world.turn(), None);

    // A reply that names the thread the instance already has changes no revision.
    let again = world.terminal_asks(START).await;
    world.server_answers(&again, &named("thread-1")).await;
    assert_eq!(world.revision(), first_revision + 1);
    assert_eq!(world.waiting(), None);

    // A resume into another thread moves the binding and ends the turn that was running.
    world
        .server_says(&turn_event("turn/started", "thread-1", "turn-2"))
        .await;
    let resuming = world.terminal_asks(RESUME).await;
    world.server_answers(&resuming, &named("thread-2")).await;
    assert_eq!(world.thread().as_deref(), Some("thread-2"));
    assert_eq!(world.turn(), None, "a conversation has its own turn");
    assert_eq!(world.revision(), first_revision + 2);
}

/// KR-REQ-12.06: a conversation the terminal leaves is no longer the binding, whether the server
/// closes it or the terminal unsubscribes from it, and one it did not name changes nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_12_06_a_conversation_the_terminal_leaves_is_not_the_binding_any_more() {
    let world = World::new(1 << 20);
    let selecting = world.terminal_asks(START).await;
    world.server_answers(&selecting, &named("thread-1")).await;
    let selected = world.revision();

    world
        .server_says(r#"{"method":"thread/closed","params":{"threadId":"thread-other"}}"#)
        .await;
    assert_eq!(world.thread().as_deref(), Some("thread-1"));
    assert_eq!(world.revision(), selected);

    world
        .server_says(r#"{"method":"thread/closed","params":{"threadId":"thread-1"}}"#)
        .await;
    assert_eq!(world.thread(), None);
    assert!(world.waiting().is_some(), "no conversation is bound");
    assert_eq!(world.revision(), selected + 1);

    let selecting = world.terminal_asks(RESUME).await;
    world.server_answers(&selecting, &named("thread-2")).await;
    assert_eq!(world.thread().as_deref(), Some("thread-2"));
    assert_eq!(world.waiting(), None);
    let bound = world.revision();

    // The terminal unsubscribes from a thread it is not in: the binding stands, and the request
    // holds nothing back while it is in flight. From the one it is in, and the server's success
    // reply: the binding ends.
    let other = world
        .terminal_asks(r#"{"id":3,"method":"thread/unsubscribe","params":{"threadId":"thread-9"}}"#)
        .await;
    assert_eq!(
        world.waiting(),
        None,
        "a leave of another conversation holds nothing"
    );
    world.server_answers(&other, r#""result":{}"#).await;
    assert_eq!(world.thread().as_deref(), Some("thread-2"));
    assert_eq!(world.waiting(), None);
    assert_eq!(world.revision(), bound);
    let leaving = world
        .terminal_asks(r#"{"id":4,"method":"thread/unsubscribe","params":{"threadId":"thread-2"}}"#)
        .await;
    world.server_answers(&leaving, r#""result":{}"#).await;
    assert_eq!(world.thread(), None);
    assert!(world.waiting().is_some());
}

/// KR-REQ-12.06: replies come in any order, and an older one never restores a conversation the
/// terminal has left or clears the uncertainty of a later request.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_12_06_an_older_reply_never_restores_what_a_later_request_left() {
    let world = World::new(1 << 20);
    let older = world.terminal_asks(START).await;
    let newer = world.terminal_asks(RESUME).await;
    assert!(world.waiting().is_some());
    world.server_answers(&newer, &named("thread-2")).await;
    assert_eq!(
        world.thread(),
        None,
        "the older request has not been answered"
    );
    assert!(
        world
            .waiting()
            .is_some_and(|reason| reason.contains("has not answered")),
        "{:?}",
        world.waiting()
    );
    // The older reply arrives last and names another thread: the last selection decides, and the
    // thread the older one named is never bound.
    let revision = world.revision();
    world.server_answers(&older, &named("thread-1")).await;
    assert_eq!(world.thread().as_deref(), Some("thread-2"));
    assert_eq!(world.revision(), revision + 1, "one advance, to the newest");
    assert_eq!(world.waiting(), None);

    // The newer of two requests is given up (its deadline passed, its connection ended): what
    // became of it is unknown, and the older one's success reply does not say.
    let world = World::new(1 << 20);
    let older = world.terminal_asks(START).await;
    let newer = world.terminal_asks(RESUME).await;
    world
        .broker
        .client_request_given_up(world.connection, &newer, true);
    assert!(
        world
            .waiting()
            .is_some_and(|reason| reason.contains("unknown")),
        "{:?}",
        world.waiting()
    );
    world.server_answers(&older, &named("thread-1")).await;
    assert_eq!(world.thread(), None, "an older reply adopts nothing");
    assert!(world.waiting().is_some(), "and clears nothing");
    // A request after both, answered, names the conversation and ends the wait.
    let latest = world.terminal_asks(START).await;
    world.server_answers(&latest, &named("thread-3")).await;
    assert_eq!(world.thread().as_deref(), Some("thread-3"));
    assert_eq!(world.waiting(), None);

    // The newer of two requests is refused by the server: the older one is then the newest that
    // may name the conversation, and its success reply is adopted.
    let world = World::new(1 << 20);
    let older = world.terminal_asks(START).await;
    let newer = world.terminal_asks(RESUME).await;
    world
        .server_answers(
            &newer,
            r#""error":{"code":-32600,"message":"no such thread"}"#,
        )
        .await;
    assert!(
        world.waiting().is_some(),
        "the older request is still in flight"
    );
    world.server_answers(&older, &named("thread-1")).await;
    assert_eq!(world.thread().as_deref(), Some("thread-1"));
    assert_eq!(world.waiting(), None);
}

/// KR-REQ-12.06: each way a selecting request can end says something different about what the
/// server did, and the instance waits only where that is unknown.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_12_06_a_selection_that_ends_without_naming_a_thread_waits_only_where_its_outcome_is_unknown()
 {
    let world = World::new(1 << 20);
    let selecting = world.terminal_asks(START).await;
    world.server_answers(&selecting, &named("thread-1")).await;
    let selected = world.revision();

    // The server refused it: the terminal changes its conversation only on a success reply that
    // names it, so the binding stands and nothing waits.
    let refused = world.terminal_asks(RESUME).await;
    world
        .server_answers(
            &refused,
            r#""error":{"code":-32600,"message":"no such thread"}"#,
        )
        .await;
    assert_eq!(world.thread().as_deref(), Some("thread-1"));
    assert_eq!(world.waiting(), None);
    assert_eq!(world.revision(), selected);

    // A success reply that names no thread says nothing about the conversation.
    let unreadable = world.terminal_asks(RESUME).await;
    world.server_answers(&unreadable, r#""result":{}"#).await;
    assert!(
        world
            .waiting()
            .is_some_and(|reason| reason.contains("unknown")),
        "{:?}",
        world.waiting()
    );
    // Selecting again, and being answered, ends the wait.
    let again = world.terminal_asks(RESUME).await;
    world.server_answers(&again, &named("thread-2")).await;
    assert_eq!(world.thread().as_deref(), Some("thread-2"));
    assert_eq!(world.waiting(), None);

    // A request the server never saw leaves nothing behind.
    let never_sent = world.terminal_asks(RESUME).await;
    assert!(world.waiting().is_some());
    world
        .broker
        .client_request_given_up(world.connection, &never_sent, false);
    assert_eq!(world.waiting(), None);
}

/// KR-REQ-11.30: a frame of a method the table does not classify suspends rich mutations, and the
/// suspension lifts only when a selection admitted after it has named the thread and every
/// unlisted request before that selection has been answered.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_11_30_an_unlisted_frame_waits_for_a_selection_made_after_it() {
    let world = World::new(1 << 20);
    let selecting = world.terminal_asks(START).await;
    world.server_answers(&selecting, &named("thread-1")).await;
    assert_eq!(world.waiting(), None);

    // The server sends a method the table does not list: what it changed is unknown.
    world
        .server_says(r#"{"method":"thread/reverted","params":{"threadId":"thread-1"}}"#)
        .await;
    assert!(
        world
            .waiting()
            .is_some_and(|reason| reason.contains("not classified")),
        "{:?}",
        world.waiting()
    );
    // A selection admitted before the frame and answered after it does not lift what came
    // between.
    let before = world.terminal_asks(RESUME).await;
    world
        .server_says(r#"{"method":"thread/reverted","params":{"threadId":"thread-1"}}"#)
        .await;
    world.server_answers(&before, &named("thread-2")).await;
    assert!(
        world
            .waiting()
            .is_some_and(|reason| reason.contains("not classified")),
        "{:?}",
        world.waiting()
    );
    // One admitted after it lifts it.
    let after = world.terminal_asks(RESUME).await;
    world.server_answers(&after, &named("thread-2")).await;
    assert_eq!(world.waiting(), None);

    // The terminal's own unlisted request: until it is answered, a selection after it lifts
    // nothing; once answered, the next one does.
    let unlisted = world
        .terminal_asks(r#"{"id":7,"method":"fuzzyFileSearch","params":{"query":"x"}}"#)
        .await;
    assert!(world.waiting().is_some());
    let selecting = world.terminal_asks(RESUME).await;
    world.server_answers(&selecting, &named("thread-2")).await;
    assert!(
        world.waiting().is_some(),
        "the unlisted request has no reply yet"
    );
    world.server_answers(&unlisted, r#""result":{}"#).await;
    assert!(world.waiting().is_some(), "and the lift needs a selection");
    let selecting = world.terminal_asks(RESUME).await;
    world.server_answers(&selecting, &named("thread-2")).await;
    assert_eq!(world.waiting(), None);
}

/// KR-REQ-12.08: the connection's tables say what a client can do here, and the map says so.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_12_08_a_gateway_connections_capability_evidence_follows_its_tables_and_its_life() {
    let world = World::new(1 << 20);
    let capability = |name: &str| {
        world
            .broker
            .capabilities(instance())
            .record(&CapabilityId::new(name).expect("a capability"))
            .cloned()
            .unwrap_or_else(|| panic!("{name} is recorded"))
    };
    // The package answers an approval and is trusted to, and spells a way to submit a prompt, steer
    // a turn and cancel it. It spells none to queue a prompt, and says so.
    let approval = capability("agent.approval");
    assert_eq!(
        approval.state,
        InstanceCapabilityState::QualifiedAvailable,
        "{:?}",
        approval.disabled_reason
    );
    for name in ["agent.prompt", "agent.steer", "agent.cancel"] {
        let held = capability(name);
        assert_eq!(
            held.state,
            InstanceCapabilityState::QualifiedAvailable,
            "{name}: {:?}",
            held.disabled_reason
        );
    }
    let queue = capability("agent.prompt.queue");
    assert_eq!(queue.state, InstanceCapabilityState::Incompatible);
    assert!(
        queue
            .disabled_reason
            .0
            .is_some_and(|reason| reason.contains("declares no way to queue a prompt")),
        "the reason names the table"
    );

    // A change of binding invalidates evidence about the old one, and the connection writes it
    // again: the capability is usable and its revision moved.
    let selecting = world.terminal_asks(START).await;
    world.server_answers(&selecting, &named("thread-1")).await;
    let renewed = capability("agent.approval");
    assert_eq!(renewed.state, InstanceCapabilityState::QualifiedAvailable);
    assert!(renewed.revision.get() > approval.revision.get());
    assert_eq!(
        renewed.identity.binding_revision.0,
        Some(world.state().binding_revision)
    );

    // The connection's end withdraws it.
    world.broker.close_connection(world.connection);
    let ended = capability("agent.approval");
    assert_eq!(ended.state, InstanceCapabilityState::TemporarilyUnavailable);
    assert!(ended.disabled_reason.0.is_some());
}

const ASK: &str = r#"{"id":"approval-1","method":"item/commandExecution/requestApproval","params":{"itemId":"item-1","startedAtMs":0,"threadId":"thread-1","turnId":"turn-1"}}"#;
const RESOLVED: &str = r#"{"method":"serverRequest/resolved","params":{"threadId":"thread-1","requestId":"approval-1"}}"#;

/// KR-REQ-11.33: a request the table answers as a response is recorded, forwarded and then
/// interpreted under the binding's trust, with the decisions the table maps.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_11_33_an_approval_the_table_answers_is_interpreted_under_the_bindings_trust() {
    let world = World::new(1 << 20);
    world.server_says(ASK).await;
    let resources = world.broker.pending_resources();
    assert_eq!(resources.len(), 1, "{resources:?}");
    let resource = &resources[0];
    assert_eq!(resource.state, PendingState::Pending);
    assert!(resource.interpretation_verified, "a decoder may read it");
    let offered = world
        .broker
        .decoding(resource.resource_id)
        .expect("the ledger reads")
        .expect("the interpretation is recorded");
    assert_eq!(
        offered
            .projection
            .decisions
            .iter()
            .map(|decision| (decision.option_id.as_str(), decision.label.as_str()))
            .collect::<Vec<_>>(),
        [
            ("accept", "Allow once"),
            ("accept-for-session", "Allow for the session"),
            ("decline", "Decline"),
            ("decline-and-stop", "Decline and stop"),
        ]
    );
}

/// KR-REQ-11.33: the server's word that a request was answered or cleared settles a request nobody
/// answered and leaves an answer that is being written to its writer, which says whether it went.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_11_33_the_server_clearing_a_request_never_settles_an_answer_that_is_being_written()
{
    // Nobody answered it: the server cleared it alone.
    let world = World::new(1 << 20);
    world.server_says(ASK).await;
    let id = world.broker.pending_resources()[0].resource_id;
    world.server_says(RESOLVED).await;
    assert_eq!(
        world.broker.pending(id).expect("held").state,
        PendingState::Cancelled
    );
    // Said again, or about a request this host never recorded, it changes nothing and the
    // connection goes on.
    world.server_says(RESOLVED).await;
    world
        .server_says(
            r#"{"method":"serverRequest/resolved","params":{"threadId":"thread-1","requestId":"never-asked"}}"#,
        )
        .await;
    assert_eq!(
        world.broker.pending(id).expect("held").state,
        PendingState::Cancelled
    );

    // The terminal answered it, and its bytes wait: the pipe to the server holds eight bytes
    // until this case reads it. The server's notice that it was answered comes before the write
    // is accounted for, and decides nothing.
    let mut world = World::new(8);
    world.server_says(ASK).await;
    let id = world.broker.pending_resources()[0].resource_id;
    world
        .owner
        .from_client(
            br#"{"id":"approval-1","result":{"decision":"accept"}}"#,
            NOW,
        )
        .await
        .expect("the terminal's answer is carried");
    assert_eq!(
        world.broker.pending(id).expect("held").state,
        PendingState::Claimed,
        "the write has not finished"
    );
    world.server_says(RESOLVED).await;
    assert_eq!(
        world.broker.pending(id).expect("held").state,
        PendingState::Claimed,
        "the writer decides"
    );
    // The server reads the answer; the writer finishes; the resource is resolved.
    let mut taken = [0_u8; 128];
    let mut got = 0;
    while !taken[..got].ends_with(b"\n") {
        got += world
            .upstream
            .read(&mut taken[got..])
            .await
            .expect("the server reads");
    }
    let started = std::time::Instant::now();
    while world.broker.pending(id).expect("held").state != PendingState::Resolved {
        assert!(
            started.elapsed() < std::time::Duration::from_secs(30),
            "the answer settles once written"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

/// KR-REQ-11.33: the same holds for a rich answer that is being written: the server's notice that
/// the request was answered comes before the write is accounted for and decides nothing, and the
/// writer's settlement says the answer went.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_11_33_the_server_clearing_a_request_never_settles_a_rich_answer_being_written() {
    let mut world = World::new(8);
    world.terminal_selects("thread-1").await;
    world.server_says(ASK).await;
    let id = world.broker.pending_resources()[0].resource_id;
    let admitted = world
        .broker
        .admit_approval(&World::owner_caller(), &world.rich_answer("accept"), NOW)
        .expect("the rich answer is admitted");
    let in_flight = world
        .broker
        .record_approval(&admitted, NOW)
        .expect("its marker is written and its bytes are queued");
    assert_eq!(
        world.broker.pending(id).expect("held").state,
        PendingState::Claimed,
        "the write has not finished"
    );
    world.server_says(RESOLVED).await;
    assert_eq!(
        world.broker.pending(id).expect("held").state,
        PendingState::Claimed,
        "the writer decides"
    );
    // The server reads the answer, and the writer settles it as resolved.
    let upstream = &mut world.upstream;
    let (settled, written) = tokio::join!(in_flight.settled(NOW), async {
        let mut taken = [0_u8; 256];
        let mut got = 0;
        while !taken[..got].ends_with(b"\n") {
            got += upstream
                .read(&mut taken[got..])
                .await
                .expect("the server reads");
        }
        taken[..got].to_vec()
    });
    assert_eq!(
        settled.expect("the answer went").state,
        PendingState::Resolved
    );
    assert!(
        String::from_utf8_lossy(&written).contains("\"decision\":\"accept\""),
        "{}",
        String::from_utf8_lossy(&written)
    );
    assert_eq!(
        world.broker.pending(id).expect("held").state,
        PendingState::Resolved
    );
}

const TERMINAL_ANSWERS: &[u8] = br#"{"id":"approval-1","result":{"decision":"decline"}}"#;

/// KR-REQ-11.33: a rich answer is written as the response to the request, in the shape the table
/// names, with the value the table maps the decision to.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_11_33_a_rich_answer_is_the_response_the_table_writes_with_the_decisions_mapped_value()
 {
    let mut world = World::new(1 << 20);
    world.terminal_selects("thread-1").await;
    world.server_says(ASK).await;
    let (result, _) = world
        .broker
        .agent_approval_respond(
            &World::owner_caller(),
            &world.rich_answer("decline-and-stop"),
            NOW,
        )
        .await
        .expect("the answer reaches the server");
    let _ = result;
    assert_eq!(
        world.server_reads().await,
        serde_json::json!({ "id": "approval-1", "result": { "decision": "cancel" } })
    );
    let id = world.broker.pending_resources()[0].resource_id;
    assert_eq!(
        world.broker.pending(id).expect("held").state,
        PendingState::Resolved
    );
}

/// KR-REQ-11.33: a native answer that arrives after a rich answer was admitted and before its
/// marker takes the transmission, and the rich answer returns where the resource stands, sending
/// nothing. One answer reaches the server.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_11_33_a_native_answer_during_encoding_wins_and_the_rich_answer_sends_nothing() {
    let mut world = World::new(1 << 20);
    world.terminal_selects("thread-1").await;
    world.server_says(ASK).await;
    let id = world.broker.pending_resources()[0].resource_id;

    // The rich answer is admitted: the resource is claimed and its one transmission reserved.
    let admitted = world
        .broker
        .admit_approval(&World::owner_caller(), &world.rich_answer("accept"), NOW)
        .expect("the rich answer is admitted");
    assert_eq!(
        world.broker.pending(id).expect("held").state,
        PendingState::Claimed
    );
    // The terminal answers before the rich answer's marker: the connection carries it.
    let carried = world
        .owner
        .from_client(TERMINAL_ANSWERS, NOW)
        .await
        .expect("the terminal's answer is not refused");
    assert!(
        matches!(carried, Carried::ClientAnswer { .. }),
        "{carried:?}"
    );
    // The rich answer reaches its marker and finds the resource taken: it sends nothing, and the
    // refusal says where the resource stands.
    let refused = world
        .broker
        .record_approval(&admitted, NOW)
        .expect_err("the marker is refused");
    assert!(refused.proven_unsent(), "{refused:?}");
    assert_eq!(
        refused.code(),
        kr_protocol::error::ErrorCode::QuestionResolved
    );
    assert!(
        matches!(
            &refused,
            kr_worker::broker::BrokerError::NotTransmitted(cause)
                if matches!(**cause, kr_worker::broker::BrokerError::AnswerOvertaken { .. })
        ),
        "{refused:?}"
    );
    // The native answer is the one that reaches the server, and settles the resource.
    assert_eq!(
        world.server_reads().await,
        serde_json::json!({ "id": "approval-1", "result": { "decision": "decline" } })
    );
    let started = std::time::Instant::now();
    while world.broker.pending(id).expect("held").state != PendingState::Resolved {
        assert!(started.elapsed() < std::time::Duration::from_secs(30));
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

/// KR-REQ-11.33: a native answer that arrives after a rich answer's marker is not forwarded and
/// does not end the connection, and the connection carries what follows.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_11_33_a_native_answer_after_a_rich_one_is_not_forwarded_and_the_connection_goes_on()
{
    let mut world = World::new(1 << 20);
    world.terminal_selects("thread-1").await;
    world.server_says(ASK).await;
    let id = world.broker.pending_resources()[0].resource_id;
    world
        .broker
        .agent_approval_respond(&World::owner_caller(), &world.rich_answer("accept"), NOW)
        .await
        .expect("the answer reaches the server");

    let carried = world
        .owner
        .from_client(TERMINAL_ANSWERS, NOW)
        .await
        .expect("a late answer is not a fault of the connection");
    assert!(
        matches!(
            carried,
            Carried::ClientAnswerLate { resource_id, state }
                if resource_id == id && state == PendingState::Resolved
        ),
        "{carried:?}"
    );
    assert!(!world.owner.stopping());
    // One answer reached the server, and what the terminal sends next is carried behind it.
    assert_eq!(
        world.server_reads().await,
        serde_json::json!({ "id": "approval-1", "result": { "decision": "accept" } })
    );
    let next = world
        .terminal_asks(r#"{"id":9,"method":"account/read","params":{}}"#)
        .await;
    let forwarded = world.server_reads().await;
    assert_eq!(forwarded["method"], "account/read");
    assert_eq!(
        forwarded["id"].as_str(),
        Some(next.as_str().trim_matches('"'))
    );
}

/// KR-REQ-11.33: an answer to a request the server cleared is not forwarded either.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_11_33_an_answer_to_a_request_the_server_cleared_is_not_forwarded() {
    let world = World::new(1 << 20);
    world.server_says(ASK).await;
    world.server_says(RESOLVED).await;
    let carried = world
        .owner
        .from_client(TERMINAL_ANSWERS, NOW)
        .await
        .expect("a late answer is not a fault of the connection");
    assert!(
        matches!(
            carried,
            Carried::ClientAnswerLate {
                state: PendingState::Cancelled,
                ..
            }
        ),
        "{carried:?}"
    );
    assert!(!world.owner.stopping());
}

/// KR-REQ-12.06: a rich answer admitted before the terminal selected another conversation is
/// stopped when its permit is taken, sends nothing, and gives the request back.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_12_06_a_rich_answer_admitted_before_a_selection_is_stopped_at_its_take() {
    let mut world = World::new(1 << 20);
    world.terminal_selects("thread-1").await;
    world.server_says(ASK).await;
    let id = world.broker.pending_resources()[0].resource_id;
    let admitted = world
        .broker
        .admit_approval(&World::owner_caller(), &world.rich_answer("accept"), NOW)
        .expect("the rich answer is admitted");

    // The terminal asks to change its conversation, and the server answers.
    let selecting = world.terminal_asks(RESUME).await;
    let refused = world
        .broker
        .record_approval(&admitted, NOW)
        .expect_err("the permit is stale");
    assert!(refused.proven_unsent(), "{refused:?}");
    assert_eq!(
        world.broker.pending(id).expect("held").state,
        PendingState::Pending,
        "the claim was given back"
    );
    world.server_answers(&selecting, &named("thread-2")).await;

    // The request was asked under the conversation the terminal left, and is not answerable at the
    // new binding: it is refused as stale, and still pending.
    let stale = world
        .broker
        .agent_approval_respond(&World::owner_caller(), &world.rich_answer("accept"), NOW)
        .await
        .expect_err("a request of the old conversation is stale");
    assert_eq!(stale.code(), kr_protocol::error::ErrorCode::StaleSession);
    assert_eq!(
        world.broker.pending(id).expect("held").state,
        PendingState::Pending
    );
}

/// KR-REQ-12.06: a success reply that came while a newer request was in flight is the binding
/// when that newer request is refused, whichever way round the replies come.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_12_06_a_success_is_applied_when_the_newer_request_is_refused() {
    let world = World::new(1 << 20);
    let first = world.terminal_asks(START).await;
    world.server_answers(&first, &named("thread-1")).await;
    let bound = world.revision();

    let older = world.terminal_asks(RESUME).await;
    let newer = world.terminal_asks(START).await;
    world.server_answers(&older, &named("thread-2")).await;
    assert_eq!(world.thread().as_deref(), Some("thread-1"));
    assert!(world.waiting().is_some(), "the newer request is in flight");
    world.server_answers(&newer, REFUSED).await;
    assert_eq!(
        world.thread().as_deref(),
        Some("thread-2"),
        "the server applied the older request, and the newer one changed nothing"
    );
    assert_eq!(world.waiting(), None);
    assert_eq!(world.revision(), bound + 1);

    // The other way round: the refusal first, then the success.
    let older = world.terminal_asks(START).await;
    let newer = world.terminal_asks(RESUME).await;
    world.server_answers(&newer, REFUSED).await;
    world.server_answers(&older, &named("thread-3")).await;
    assert_eq!(world.thread().as_deref(), Some("thread-3"));
    assert_eq!(world.waiting(), None);
}

/// KR-REQ-12.06: a leave of another conversation changes nothing and hides nothing, and a leave of
/// the bound one is not lost to a selection that is then refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_12_06_a_leave_neither_hides_a_selection_nor_is_lost_to_a_refused_one() {
    let world = World::new(1 << 20);
    let first = world.terminal_asks(START).await;
    world.server_answers(&first, &named("thread-1")).await;

    // A selection, then a leave of a conversation the terminal is not in, answered first.
    let selecting = world.terminal_asks(START).await;
    let leaving = world.terminal_asks(LEAVE_OTHER).await;
    world.server_answers(&leaving, r#""result":{}"#).await;
    assert!(world.waiting().is_some(), "the selection is in flight");
    world.server_answers(&selecting, &named("thread-5")).await;
    assert_eq!(
        world.thread().as_deref(),
        Some("thread-5"),
        "the server started the conversation the terminal is now in"
    );
    assert_eq!(world.waiting(), None);

    // A leave of the bound conversation, then a selection the server refuses.
    let world = World::new(1 << 20);
    let first = world.terminal_asks(START).await;
    world.server_answers(&first, &named("thread-1")).await;
    let leaving = world.terminal_asks(LEAVE_ONE).await;
    let selecting = world.terminal_asks(RESUME).await;
    world.server_answers(&leaving, r#""result":{}"#).await;
    world.server_answers(&selecting, REFUSED).await;
    assert_eq!(world.thread(), None, "the terminal left that conversation");
    assert!(
        world
            .waiting()
            .is_some_and(|reason| reason.contains("not read")),
        "{:?}",
        world.waiting()
    );

    // A selection and then a leave of what it selected, answered the other way round.
    let world = World::new(1 << 20);
    let selecting = world.terminal_asks(START).await;
    let leaving = world
        .terminal_asks(r#"{"id":4,"method":"thread/unsubscribe","params":{"threadId":"thread-4"}}"#)
        .await;
    world.server_answers(&leaving, r#""result":{}"#).await;
    world.server_answers(&selecting, &named("thread-4")).await;
    assert_eq!(world.thread(), None, "the terminal selected it and left it");
    assert!(world.waiting().is_some());
}

/// KR-REQ-12.06 and KR-REQ-11.30: a request the server never answered, given up at its deadline,
/// leaves what it did unknown: a selection that did not answer holds the instance back until the
/// next one names the conversation, and a request of an unlisted method keeps the suspension it
/// caused for as long as the connection lives.
#[tokio::test(start_paused = true)]
async fn kr_req_12_06_a_request_given_up_at_its_deadline_leaves_what_it_did_unknown() {
    // A selection the server never answers.
    let world = World::new(1 << 20);
    let first = world.terminal_asks(START).await;
    world.server_answers(&first, &named("thread-1")).await;
    let _silent = world.terminal_asks(RESUME).await;
    world.past_the_deadline().await;
    assert!(
        world
            .waiting()
            .is_some_and(|reason| reason.contains("unknown")),
        "{:?}",
        world.waiting()
    );
    assert_eq!(world.thread().as_deref(), Some("thread-1"));
    // A selection that is answered names the conversation and ends the wait.
    let selecting = world.terminal_asks(RESUME).await;
    world.server_answers(&selecting, &named("thread-2")).await;
    assert_eq!(world.thread().as_deref(), Some("thread-2"));
    assert_eq!(world.waiting(), None);

    // A request of a method the table does not list, never answered: the server may still be
    // carrying it out, so no selection after it says the conversation is as it was.
    let world = World::new(1 << 20);
    let first = world.terminal_asks(START).await;
    world.server_answers(&first, &named("thread-1")).await;
    let _unlisted = world.terminal_asks(UNLISTED).await;
    world.past_the_deadline().await;
    for thread in ["thread-2", "thread-3"] {
        let selecting = world.terminal_asks(RESUME).await;
        world.server_answers(&selecting, &named(thread)).await;
        assert_eq!(world.thread().as_deref(), Some(thread));
        assert!(
            world
                .waiting()
                .is_some_and(|reason| reason.contains("not classified")),
            "no selection says what the unlisted request did: {:?}",
            world.waiting()
        );
    }
}

/// KR-REQ-12.06: a conversation another live execution owns is never published as this instance's
/// binding, and the instance says why it waits until a conversation that can be bound is selected.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_12_06_a_conversation_another_execution_owns_is_never_published() {
    let world = World::new(1 << 20);
    let other = ApplicationInstanceId::new(Uuid::from_bytes([8; 16]));
    world
        .broker
        .register_instance(other, IntegrationMode::Gateway, None, None)
        .expect("another instance is registered");
    world
        .broker
        .advance_binding(
            other,
            Some(kr_protocol::ids::AgentThreadId::new("thread-9").expect("a thread")),
            NOW,
        )
        .expect("it owns a conversation");

    let selecting = world.terminal_asks(START).await;
    world.server_answers(&selecting, &named("thread-9")).await;
    assert_eq!(
        world.thread(),
        None,
        "the owned conversation is not published"
    );
    assert!(
        world.waiting().is_some_and(|reason| {
            reason.starts_with(&format!("{}: ", kr_worker::broker::CONVERSATION_NOT_BOUND))
        }),
        "{:?}",
        world.waiting()
    );
    let selecting = world.terminal_asks(RESUME).await;
    world.server_answers(&selecting, &named("thread-2")).await;
    assert_eq!(world.thread().as_deref(), Some("thread-2"));
    assert_eq!(world.waiting(), None);
}

/// KR-REQ-12.08: the capability the connection records for approvals follows what the binding may
/// do: a narrower grant, a withdrawn right to answer and a component fault each end it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_12_08_the_approval_evidence_follows_the_bindings_grants_and_faults() {
    let approval = |world: &World| {
        world
            .broker
            .capabilities(instance())
            .record(&CapabilityId::new("agent.approval").expect("a capability"))
            .cloned()
            .expect("it is recorded")
    };

    // A narrower grant handed to the worker by the installation.
    let mut world = World::new(1 << 20);
    assert_eq!(
        approval(&world).state,
        InstanceCapabilityState::QualifiedAvailable
    );
    world.source.granted.retain(|capability| {
        *capability != kr_plugin_sdk::capability::PluginCapability::ApprovalRespond
    });
    kr_worker::broker::catalogue::testing::admit(
        &world.admissions,
        &world.sources,
        &world.broker,
        vec![testing::admitted(&world.source)],
        2,
    );
    assert_eq!(
        approval(&world).state,
        InstanceCapabilityState::Incompatible,
        "{:?}",
        approval(&world).disabled_reason
    );

    // A revocation its repository published, under the policy that disables at the next admission,
    // and the revocation no longer standing.
    let world = World::new(1 << 20);
    let package = testing::admitted(&world.source);
    let revoked = kr_protocol::admission::ReleaseState {
        revocation: kr_protocol::scalars::Nullable::some(
            kr_protocol::admission::AdmissionRevocation {
                reason: "compromised".to_owned(),
                revoked_at: TimestampMs::new(5),
                statement: "Do not run this release.".to_owned(),
            },
        ),
        ..testing::release_of(&package)
    };
    testing::hand_over(
        &world.admissions,
        &world.sources,
        &world.broker,
        testing::Snapshot {
            policy: kr_protocol::admission::RevocationPolicy::DisableAtNextAdmission,
            releases: vec![revoked],
            ..testing::Snapshot::admitting(2, vec![package.clone()])
        },
    );
    assert_eq!(
        approval(&world).state,
        InstanceCapabilityState::Incompatible,
        "a revoked release's binding answers nothing"
    );
    testing::admit(
        &world.admissions,
        &world.sources,
        &world.broker,
        vec![package],
        3,
    );
    assert_eq!(
        approval(&world).state,
        InstanceCapabilityState::QualifiedAvailable,
        "and a revocation that no longer stands lifts it"
    );

    // The right to answer withdrawn from the binding.
    let world = World::new(1 << 20);
    world
        .broker
        .withdraw_answering(binding_id())
        .expect("the right is withdrawn");
    assert_eq!(
        approval(&world).state,
        InstanceCapabilityState::Incompatible
    );

    // A component fault.
    let world = World::new(1 << 20);
    world.broker.disable_rich(binding_id(), "a component fault");
    assert_eq!(
        approval(&world).state,
        InstanceCapabilityState::Incompatible
    );
}

/// KR-REQ-12.06 and KR-REQ-11.30: a rich answer admitted before a leave or an unlisted frame is
/// stopped when its permit is taken, and one admitted before its connection ended is told that
/// nothing was sent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_12_06_a_held_permit_is_stopped_by_a_leave_an_unlisted_frame_and_a_closed_connection()
 {
    let caller = World::owner_caller();
    // Each case has a world of its own: a request belongs to the conversation it was asked in.
    for (what, then) in [
        (
            "a frame of an unlisted method",
            r#"{"method":"thread/reverted","params":{"threadId":"thread-1"}}"#,
        ),
        (
            "the server ending the conversation",
            r#"{"method":"thread/closed","params":{"threadId":"thread-1"}}"#,
        ),
    ] {
        let mut world = World::new(1 << 20);
        world.terminal_selects("thread-1").await;
        world.server_says(ASK).await;
        let id = world.broker.pending_resources()[0].resource_id;
        let admitted = world
            .broker
            .admit_approval(&caller, &world.rich_answer("accept"), NOW)
            .expect("admitted");
        world.server_says(then).await;
        let refused = world
            .broker
            .mark_approval(&admitted, NOW)
            .err()
            .unwrap_or_else(|| panic!("{what} stops a permit admitted before it"));
        assert!(refused.proven_unsent(), "{what}: {refused:?}");
        assert_eq!(
            world.broker.pending(id).expect("held").state,
            PendingState::Pending,
            "{what}: the claim was given back"
        );
    }

    // The connection ends between the admission and the take: nothing can be sent, and the
    // refusal is one this host decided, not an outcome nobody can establish.
    let mut world = World::new(1 << 20);
    world.terminal_selects("thread-1").await;
    world.server_says(ASK).await;
    let id = world.broker.pending_resources()[0].resource_id;
    let admitted = world
        .broker
        .admit_approval(&caller, &world.rich_answer("accept"), NOW)
        .expect("admitted");
    world.owner.shutdown();
    let Err(refused) = world.broker.mark_approval(&admitted, NOW) else {
        panic!("the transport is closed, so nothing is marked");
    };
    assert!(refused.proven_unsent(), "{refused:?}");
    assert_eq!(
        refused.code(),
        kr_protocol::error::ErrorCode::UpstreamUnavailable
    );
    assert_eq!(
        world.broker.pending(id).expect("held").state,
        PendingState::Pending
    );
}

/// Waits until the resource is in `state`, within the liveness bound.
async fn state_of(world: &World, id: kr_protocol::ids::PendingResourceId, state: PendingState) {
    let started = std::time::Instant::now();
    while world.broker.pending(id).expect("held").state != state {
        assert!(
            started.elapsed() < std::time::Duration::from_secs(30),
            "{id} did not become {state:?}: {:?}",
            world.broker.pending(id)
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

/// KR-REQ-11.33, KR-REQ-11.35 and KR-REQ-11.37: the receipt journal faults after a rich answer
/// was admitted and before its dispatch marker is written. The marker that cannot be written is
/// the rich answer's refusal, proven before any byte, so the terminal's answer is the one that
/// goes and settles the request, volatile, and the gap commits that settlement when the store
/// recovers. This is the order in which the rich answer loses to a journal fault, which a
/// committed marker followed by a failed transmission is not.
///
/// Not claimed: Windows, where no gateway runs.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_11_35_a_journal_fault_before_the_rich_marker_leaves_the_terminals_answer_the_one_that_goes()
 {
    let mut store = common::SharedStore::open();
    let mut world = World::with_store(&store);
    world.terminal_selects("thread-1").await;
    world.server_says(ASK).await;
    let id = world.broker.pending_resources()[0].resource_id;
    let admitted = world
        .broker
        .admit_approval(&World::owner_caller(), &world.rich_answer("accept"), NOW)
        .expect("the rich answer is admitted");

    store.fault_acceptance();
    let Err(fenced) = world.broker.mark_approval(&admitted, NOW) else {
        panic!("the marker cannot be written under a fault");
    };
    assert!(fenced.proven_unsent(), "{fenced:?}");
    assert_eq!(
        world.broker.pending(id).expect("held").state,
        PendingState::Pending,
        "the claim was given back"
    );

    // The terminal's answer is carried through the fault and settles the request.
    let carried = world
        .owner
        .from_client(TERMINAL_ANSWERS, NOW)
        .await
        .expect("the terminal's answer is carried");
    assert!(
        matches!(carried, Carried::ClientAnswer { .. }),
        "{carried:?}"
    );
    state_of(&world, id, PendingState::Resolved).await;
    let sent = world.server_reads().await;
    assert_eq!(sent["id"], "approval-1");
    assert_eq!(
        sent["result"]["decision"], "decline",
        "the one answer upstream is the terminal's"
    );
    assert_eq!(
        world.broker.pending(id).expect("held").durability,
        kr_protocol::session::Durability::Volatile,
        "the settlement was made while the journal was faulted"
    );

    // Storage returns, and the gap commits what the settlement was.
    store.recover_journal(20);
    world
        .broker
        .recover(TimestampMs::new(20))
        .expect("the broker commits its gap");
    assert_eq!(
        world.broker.pending(id).expect("held").state,
        PendingState::Resolved
    );
}

/// KR-REQ-11.33, KR-REQ-11.35 and KR-REQ-11.37: the receipt journal faults after the rich answer's
/// dispatch marker is written. The rich bytes go, the terminal's later answer is not forwarded and
/// does not end the connection, and the settlement is volatile and committed at recovery.
///
/// Not claimed: Windows, where no gateway runs.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_11_35_a_journal_fault_after_the_rich_marker_leaves_the_rich_answer_the_one_that_goes()
 {
    let mut store = common::SharedStore::open();
    let mut world = World::with_store(&store);
    world.terminal_selects("thread-1").await;
    world.server_says(ASK).await;
    let id = world.broker.pending_resources()[0].resource_id;
    let admitted = world
        .broker
        .admit_approval(&World::owner_caller(), &world.rich_answer("accept"), NOW)
        .expect("the rich answer is admitted");
    let marked = world
        .broker
        .mark_approval(&admitted, NOW)
        .expect("the marker is committed");

    store.fault_acceptance();
    let (dispatch, request) = marked.transmission();
    let pending = dispatch.submit(&request).expect("the bytes are queued");
    let in_flight = marked.submitted(pending);
    let settled = in_flight.settled(NOW).await.expect("the answer went");
    assert_eq!(settled.state, PendingState::Resolved);
    let sent = world.server_reads().await;
    assert_eq!(sent["result"]["decision"], "accept");

    // The terminal's answer comes late: it is not forwarded, and the connection goes on.
    let late = world
        .owner
        .from_client(TERMINAL_ANSWERS, NOW)
        .await
        .expect("a late answer does not end the connection");
    assert!(
        matches!(
            late,
            Carried::ClientAnswerLate {
                state: PendingState::Resolved,
                ..
            }
        ),
        "{late:?}"
    );
    assert_eq!(
        world.broker.pending(id).expect("held").durability,
        kr_protocol::session::Durability::Volatile
    );
    store.recover_journal(20);
    world
        .broker
        .recover(TimestampMs::new(20))
        .expect("the broker commits its gap");
    assert_eq!(
        world.broker.pending(id).expect("held").state,
        PendingState::Resolved
    );
}

/// KR-REQ-11.33 and KR-REQ-11.35, an upstream that disconnects after dispatch: a
/// committed marker followed by a transmission that fails part way is not a refusal. The server has
/// the first bytes of the answer and then goes. The answer's fate is unknown, the connection a
/// failed write ends serves the terminal nothing more, the request stays uncertain, and nobody
/// sends it again: a second answer from either writer is refused.
///
/// This is an approval's answer. A dispatched mutation whose connection ends is
/// `agent_service.rs`'s `kr_req_09_05_a_connection_that_ended_settles_nothing`.
///
/// The stream is the gateway's, which no shipped package selects, so this case is not the fault
/// tests' upstream disconnect; the application's channel is the route a package takes, and
/// `channels.rs` holds that.
///
/// Not claimed: Windows, where no gateway runs.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_11_35_a_committed_marker_followed_by_a_failed_transmission_leaves_the_request_uncertain()
 {
    let store = common::SharedStore::open();
    // The pipe to the server holds eight bytes, so the answer's frame goes out in parts.
    let mut world = World::opened(8, Some(&store));
    world.terminal_selects("thread-1").await;
    world.server_says(ASK).await;
    let id = world.broker.pending_resources()[0].resource_id;
    let admitted = world
        .broker
        .admit_approval(&World::owner_caller(), &world.rich_answer("accept"), NOW)
        .expect("the rich answer is admitted");
    let marked = world
        .broker
        .mark_approval(&admitted, NOW)
        .expect("the marker is committed");
    let (dispatch, request) = marked.transmission();
    let pending = dispatch.submit(&request).expect("the frame is queued");
    let in_flight = marked.submitted(pending);

    // The server reads the first bytes of the answer, which is what it has of it, and goes.
    let mut first = [0_u8; 8];
    world
        .upstream
        .read_exact(&mut first)
        .await
        .expect("the first bytes of the answer reached the server");
    drop(std::mem::replace(
        &mut world.upstream,
        tokio::io::duplex(1).0,
    ));
    let failed = in_flight
        .settled(NOW)
        .await
        .expect_err("the answer did not finish");
    assert!(
        !failed.proven_unsent(),
        "after the marker and some bytes nobody can establish what happened: {failed:?}"
    );
    state_of(&world, id, PendingState::Uncertain).await;

    // A write that failed ended the connection, so the terminal's answer comes to a connection
    // that no longer serves, and nothing is written for it. The request stays uncertain: no
    // writer answers it again, the rich one included.
    world
        .owner
        .from_client(TERMINAL_ANSWERS, NOW)
        .await
        .expect_err("the connection ended with the failed write");
    let again = world
        .broker
        .admit_approval(&World::owner_caller(), &world.rich_answer("accept"), NOW)
        .expect_err("an answer that may have gone is not asked for again");
    assert_eq!(
        again.code(),
        kr_protocol::error::ErrorCode::QuestionResolved
    );
    assert_eq!(
        world.broker.pending(id).expect("held").state,
        PendingState::Uncertain
    );
}

/// KR-REQ-12.06, the part about a thread mutation submitted under an earlier selection: a steer
/// admitted before the terminal asked to change its conversation is stopped when its permit is
/// taken: nothing is written and the refusal is proven unsent. Only a steer is admitted here; the
/// declared cancellation is the case below. Not shown here: the `DRAFT_CONFLICT` or `STALE_SESSION`
/// code, which the case does not read.
///
/// Not claimed: Windows, where no gateway runs.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_12_06_a_mutation_and_an_action_admitted_before_a_selection_are_stopped_at_their_take()
 {
    let mut world = World::new(1 << 20);
    let binding = binding_id();
    let declaration = cancel_declaration();
    world
        .broker
        .register_actions(binding, [&declaration])
        .expect("the action is registered");
    world.terminal_selects("thread-1").await;
    world
        .server_says(&turn_event("turn/started", "thread-1", "turn-7"))
        .await;
    let caller = World::owner_caller();

    // A steer admitted, then the terminal asks to change its conversation: the take refuses it.
    let steer = kr_protocol::agent::AgentSteerParams {
        target: world.target(),
        turn_id: World::turn_id("turn-7"),
        text: kr_protocol::agent::PromptText::new("steer").expect("a steer"),
    };
    let admitted = world
        .broker
        .admit_steer(&caller, &steer, NOW)
        .expect("the steer is admitted");
    let _selecting = world.terminal_asks(RESUME).await;
    assert_eq!(
        world.server_reads().await["method"],
        "thread/resume",
        "the terminal's own request reached the server"
    );
    let Err(stopped) = world.broker.take_mutation(&admitted) else {
        panic!("a permit admitted before a selection is stopped");
    };
    assert!(stopped.proven_unsent(), "{stopped:?}");
    world.nothing_written().await;
}

/// KR-REQ-12.06 and KR-REQ-11.28: the same for the declared cancellation, whose token the
/// admission spent.
///
/// KR-REQ-23.30, the part about the thread an action was admitted under: a declared cancellation
/// whose conversation the server ended before its permit was taken is stopped there, proven unsent.
/// Not shown here: a component's plan, since the host writes this action from the connector's
/// template.
///
/// Not claimed: Windows, where no gateway runs.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_11_28_a_declared_cancellation_admitted_before_a_leave_is_stopped_at_its_take() {
    let mut world = World::new(1 << 20);
    let binding = binding_id();
    let declaration = cancel_declaration();
    world
        .broker
        .register_actions(binding, [&declaration])
        .expect("the action is registered");
    world.terminal_selects("thread-1").await;
    world
        .server_says(&turn_event("turn/started", "thread-1", "turn-7"))
        .await;
    let invoke = kr_protocol::agent::PluginActionInvokeParams {
        target: world.target(),
        plugin_id: kr_protocol::ids::PluginId::new("kalareach.codex").expect("a plugin"),
        action: kr_protocol::broker::ActionName::new("turn.cancel").expect("an action"),
        draft_id: kr_protocol::scalars::Nullable::null(),
        resource_id: kr_protocol::scalars::Nullable::null(),
        parameters: kr_protocol::scalars::Bytes::new(b"{}".to_vec()),
    };
    let admitted = world
        .broker
        .admit_host_cancel(&World::owner_caller(), binding, &invoke, NOW)
        .expect("the declared cancellation is admitted");
    // The server ends the conversation the cancellation was admitted under.
    world
        .server_says(r#"{"method":"thread/closed","params":{"threadId":"thread-1"}}"#)
        .await;
    let Err(stopped) = world.broker.take_plugin_action(&admitted) else {
        panic!("a permit admitted before a leave is stopped");
    };
    assert!(stopped.proven_unsent(), "{stopped:?}");
    world.nothing_written().await;
}

/// KR-REQ-12.06 and KR-REQ-12.04: a success reply kept for the requests before it is not applied
/// after the server said something that changes what applying it would mean: it closed the
/// conversation the reply selected, or reported a turn in one the terminal is not bound to. The
/// instance then waits for the next selection that is answered, and a notification about another
/// conversation changes nothing.
///
/// Not claimed: Windows, where no gateway runs.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_12_06_a_notification_after_a_kept_reply_decides_what_the_terminal_is_in() {
    const RESUME_ONE: &str =
        r#"{"id":5,"method":"thread/resume","params":{"threadId":"thread-1"}}"#;
    let closed = |thread: &str| {
        format!(r#"{{"method":"thread/closed","params":{{"threadId":"{thread}"}}}}"#)
    };

    // The bound conversation is resumed again, its reply kept while another selection is open, and
    // the server closes it: no later refusal restores it.
    let world = World::new(1 << 20);
    let first = world.terminal_asks(START).await;
    world.server_answers(&first, &named("thread-1")).await;
    let again = world.terminal_asks(RESUME_ONE).await;
    let other = world.terminal_asks(RESUME).await;
    world.server_answers(&again, &named("thread-1")).await;
    world.server_says(&closed("thread-1")).await;
    world.server_answers(&other, REFUSED).await;
    assert_eq!(
        world.thread(),
        None,
        "the server closed the conversation the terminal had selected"
    );
    assert!(world.waiting().is_some());

    // Another conversation is selected, its reply kept, and the server closes it: the binding is
    // not that conversation, and the instance does not stay on the old one as though nothing
    // happened.
    let world = World::new(1 << 20);
    let first = world.terminal_asks(START).await;
    world.server_answers(&first, &named("thread-1")).await;
    let older = world.terminal_asks(RESUME).await;
    let newer = world.terminal_asks(START).await;
    world.server_answers(&older, &named("thread-2")).await;
    world.server_says(&closed("thread-2")).await;
    world.server_answers(&newer, REFUSED).await;
    assert_ne!(world.thread().as_deref(), Some("thread-2"));
    assert!(
        world
            .waiting()
            .is_some_and(|reason| reason.contains("unknown")),
        "{:?}",
        world.waiting()
    );
    // The next selection that is answered names the conversation and ends the wait.
    let selecting = world.terminal_asks(RESUME).await;
    world.server_answers(&selecting, &named("thread-3")).await;
    assert_eq!(world.thread().as_deref(), Some("thread-3"));
    assert_eq!(world.waiting(), None);

    // A turn reported in the conversation a kept reply selected comes before the binding names it,
    // so the binding is not taken without it.
    let world = World::new(1 << 20);
    let first = world.terminal_asks(START).await;
    world.server_answers(&first, &named("thread-1")).await;
    let older = world.terminal_asks(RESUME).await;
    let newer = world.terminal_asks(START).await;
    world.server_answers(&older, &named("thread-2")).await;
    world
        .server_says(&turn_event("turn/started", "thread-2", "turn-5"))
        .await;
    world.server_answers(&newer, REFUSED).await;
    assert_ne!(world.thread().as_deref(), Some("thread-2"));
    assert!(world.waiting().is_some());

    // A notification about a conversation no kept reply named changes nothing.
    let world = World::new(1 << 20);
    let first = world.terminal_asks(START).await;
    world.server_answers(&first, &named("thread-1")).await;
    let older = world.terminal_asks(RESUME).await;
    let newer = world.terminal_asks(START).await;
    world.server_answers(&older, &named("thread-2")).await;
    world.server_says(&closed("thread-9")).await;
    world
        .server_says(&turn_event("turn/started", "thread-9", "turn-5"))
        .await;
    world.server_answers(&newer, REFUSED).await;
    assert_eq!(world.thread().as_deref(), Some("thread-2"));
    assert_eq!(world.waiting(), None);
}

/// KR-REQ-12.04, KR-REQ-12.12 and KR-REQ-11.36: a prompt admitted while no turn ran is stopped at
/// its take once a turn started, and a steer or a cancellation admitted for a turn is stopped once
/// that turn ended or another began: the binding's revision does not move with a turn, so the take
/// reads the turn again. Nothing is written, and the refusal is proven.
///
/// Not claimed: Windows, where no gateway runs.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_12_04_a_mutation_admitted_before_a_turn_began_or_ended_is_stopped_at_its_take() {
    let mut world = World::new(1 << 20);
    world.terminal_selects("thread-1").await;
    let caller = World::owner_caller();

    // A prompt admitted while no turn ran, and a turn that started before it was taken.
    let admitted = world
        .broker
        .admit_prompt(&caller, &world.prompt("hello"), false, NOW)
        .expect("a prompt is admitted while no turn runs");
    world
        .server_says(&turn_event("turn/started", "thread-1", "turn-7"))
        .await;
    let Err(stopped) = world.broker.take_mutation(&admitted) else {
        panic!("a prompt over a turn that began is stopped at its take");
    };
    assert!(stopped.proven_unsent(), "{stopped:?}");
    world.nothing_written().await;

    // A steer admitted for the running turn, and the turn ended before it was taken.
    let steer = kr_protocol::agent::AgentSteerParams {
        target: world.target(),
        turn_id: World::turn_id("turn-7"),
        text: kr_protocol::agent::PromptText::new("steer").expect("a steer"),
    };
    let admitted = world
        .broker
        .admit_steer(&caller, &steer, NOW)
        .expect("the steer is admitted");
    world
        .server_says(&turn_event("turn/completed", "thread-1", "turn-7"))
        .await;
    let Err(stopped) = world.broker.take_mutation(&admitted) else {
        panic!("a steer of a turn that ended is stopped at its take");
    };
    assert!(stopped.proven_unsent(), "{stopped:?}");
    world.nothing_written().await;

    // A cancellation admitted for one turn, and another began in its place.
    world
        .server_says(&turn_event("turn/started", "thread-1", "turn-8"))
        .await;
    let cancel = kr_protocol::agent::AgentCancelParams {
        target: world.target(),
        turn_id: World::turn_id("turn-8"),
    };
    let admitted = world
        .broker
        .admit_cancel(&caller, &cancel, NOW)
        .expect("the cancellation is admitted");
    world
        .server_says(&turn_event("turn/started", "thread-1", "turn-9"))
        .await;
    let Err(stopped) = world.broker.take_mutation(&admitted) else {
        panic!("a cancellation of a turn that was replaced is stopped at its take");
    };
    assert!(stopped.proven_unsent(), "{stopped:?}");
    world.nothing_written().await;

    // The turn is the one it was admitted for: the take goes through and the frame is written.
    let admitted = world
        .broker
        .admit_cancel(
            &caller,
            &kr_protocol::agent::AgentCancelParams {
                target: world.target(),
                turn_id: World::turn_id("turn-9"),
            },
            NOW,
        )
        .expect("the cancellation is admitted");
    let taken = world
        .broker
        .take_mutation(&admitted)
        .expect("nothing changed since the admission");
    let (dispatch, request) = taken.transmission();
    let _pending = dispatch
        .submit(&request)
        .expect("the frame is queued for the server");
    assert_eq!(world.server_reads().await["method"], "turn/interrupt");
}

/// KR-REQ-11.33 and KR-REQ-12.08: a rich answer admitted before its decoder's authority was
/// withdrawn, by the owner or by a narrower installation, is stopped at its take: no marker, no
/// byte, the request answerable again. A revocation or a fault disables the binding's rich
/// capabilities and lets what it already admitted finish.
///
/// Not claimed: Windows, where no gateway runs.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_11_33_an_answer_admitted_before_its_authority_was_withdrawn_is_stopped_at_its_take()
{
    // The owner withdraws the right to answer.
    let mut world = World::new(1 << 20);
    world.terminal_selects("thread-1").await;
    world.server_says(ASK).await;
    let id = world.broker.pending_resources()[0].resource_id;
    let admitted = world
        .broker
        .admit_approval(&World::owner_caller(), &world.rich_answer("accept"), NOW)
        .expect("the rich answer is admitted");
    world
        .broker
        .withdraw_answering(binding_id())
        .expect("the right is withdrawn");
    let refused = world
        .broker
        .record_approval(&admitted, NOW)
        .expect_err("the decoder may no longer answer");
    assert!(refused.proven_unsent(), "{refused:?}");
    assert_eq!(
        world.broker.pending(id).expect("held").state,
        PendingState::Pending,
        "the claim was given back"
    );
    world.nothing_written().await;

    // A narrower installation takes the grant away.
    let mut world = World::new(1 << 20);
    world.terminal_selects("thread-1").await;
    world.server_says(ASK).await;
    let id = world.broker.pending_resources()[0].resource_id;
    let admitted = world
        .broker
        .admit_approval(&World::owner_caller(), &world.rich_answer("accept"), NOW)
        .expect("the rich answer is admitted");
    world.source.granted.retain(|capability| {
        *capability != kr_plugin_sdk::capability::PluginCapability::ApprovalRespond
    });
    testing::admit(
        &world.admissions,
        &world.sources,
        &world.broker,
        vec![testing::admitted(&world.source)],
        2,
    );
    let refused = world
        .broker
        .record_approval(&admitted, NOW)
        .expect_err("the installation no longer lets the package answer");
    assert!(refused.proven_unsent(), "{refused:?}");
    assert_eq!(
        world.broker.pending(id).expect("held").state,
        PendingState::Pending
    );
    world.nothing_written().await;

    // A component fault disables the binding's rich capabilities after the admission, and the
    // answer that was admitted goes.
    let mut world = World::new(1 << 20);
    world.terminal_selects("thread-1").await;
    world.server_says(ASK).await;
    let id = world.broker.pending_resources()[0].resource_id;
    let admitted = world
        .broker
        .admit_approval(&World::owner_caller(), &world.rich_answer("accept"), NOW)
        .expect("the rich answer is admitted");
    world.broker.disable_rich(binding_id(), "a component fault");
    world
        .broker
        .record_approval(&admitted, NOW)
        .expect("what was admitted finishes")
        .settled(NOW)
        .await
        .expect("and completes");
    state_of(&world, id, PendingState::Resolved).await;
    let written = world.server_reads().await;
    assert_eq!(written["id"], "approval-1");
    assert_eq!(written["result"]["decision"], "accept");
}

impl World {
    /// What the instance's history holds, oldest first: the kind, the text, the binding revision
    /// each entry was observed under and the turn it names.
    fn history(&self) -> Vec<(String, String, u64, Option<String>)> {
        self.broker
            .replay(
                instance(),
                None,
                &kr_worker::broker::GrantLowerBound {
                    from: kr_protocol::ids::StreamCursor::new(1),
                },
                kr_protocol::semantic::MAX_SEMANTIC_SNAPSHOT_BYTES,
            )
            .expect("the history replays")
            .entries
            .into_iter()
            .map(|entry| {
                (
                    entry.kind,
                    entry.text,
                    entry.binding_revision.get(),
                    entry.turn_id.0.map(|turn| turn.to_string()),
                )
            })
            .collect()
    }
}

/// KR-REQ-12.04: what a gateway-served terminal's stream says about its conversation and its turn
/// is recorded as history, each entry under the binding revision and the turn it was seen under,
/// so a reader later knows which owner and which turn it belongs to whatever the binding has moved
/// on to. A turn the binding left running is recorded under the revision it ran in, and a message
/// about a conversation the terminal is not in records nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_12_04_what_the_stream_says_of_the_conversation_and_the_turn_is_recorded_under_them()
{
    let world = World::new(1 << 20);
    assert_eq!(world.history(), []);
    let before = world.revision();
    let entry = |kind: &str, text: &str, revision: u64, turn: Option<&str>| {
        (
            kind.to_owned(),
            text.to_owned(),
            revision,
            turn.map(str::to_owned),
        )
    };

    // A conversation selected, and a turn run in it.
    let selecting = world.terminal_asks(START).await;
    world.server_answers(&selecting, &named("thread-1")).await;
    let one = before + 1;
    world
        .server_says(&turn_event("turn/started", "thread-other", "turn-x"))
        .await;
    world
        .server_says(&turn_event("turn/started", "thread-1", "turn-1"))
        .await;
    world
        .server_says(&turn_event("turn/completed", "thread-1", "turn-0"))
        .await;
    world
        .server_says(&turn_event("turn/completed", "thread-1", "turn-1"))
        .await;
    assert_eq!(
        world.history(),
        [
            entry("thread.started", "thread-1", one, None),
            entry("turn.started", "turn-1", one, Some("turn-1")),
            entry("turn.ended", "turn-1", one, Some("turn-1")),
        ]
    );

    // A turn still running when the terminal resumes another conversation was the old owner's:
    // it is recorded as dropped under the revision it ran in, before the binding moves.
    world
        .server_says(&turn_event("turn/started", "thread-1", "turn-2"))
        .await;
    let resuming = world.terminal_asks(RESUME).await;
    world.server_answers(&resuming, &named("thread-2")).await;
    let two = one + 1;
    assert_eq!(
        world.history()[3..],
        [
            entry("turn.started", "turn-2", one, Some("turn-2")),
            entry("turn.dropped", "turn-2", one, Some("turn-2")),
            entry("thread.started", "thread-2", two, None),
        ]
    );

    // The server closes a conversation the terminal is not in, and then the one it is in.
    world
        .server_says(r#"{"method":"thread/closed","params":{"threadId":"thread-other"}}"#)
        .await;
    assert_eq!(
        world.history().len(),
        6,
        "another conversation's end is not ours"
    );
    world
        .server_says(r#"{"method":"thread/closed","params":{"threadId":"thread-2"}}"#)
        .await;
    let three = two + 1;
    assert_eq!(
        world.history()[6..],
        [entry("thread.ended", "thread-2", three, None)]
    );

    // The terminal leaves a conversation by its own request.
    let selecting = world.terminal_asks(RESUME).await;
    world.server_answers(&selecting, &named("thread-2")).await;
    let four = three + 1;
    let leaving = world
        .terminal_asks(r#"{"id":4,"method":"thread/unsubscribe","params":{"threadId":"thread-2"}}"#)
        .await;
    world.server_answers(&leaving, r#""result":{}"#).await;
    assert_eq!(
        world.history()[7..],
        [
            entry("thread.started", "thread-2", four, None),
            entry("thread.ended", "thread-2", four + 1, None),
        ]
    );
}

/// What a real 0.155.1 terminal and server exchanged, recorded offline: the terminal's start, the
/// question typed at it (the first recording) or sent as the host sends a device's prompt (the
/// second), and the thread the terminal starts for its own purposes, the title of the conversation,
/// with its turn and its leave. Each frame is its direction, its kind, its method, its identifier,
/// and the marks the reader's cases need: the thread and turn it names (labelled in order of
/// appearance) and the members that say what a thread is for. No prompt or reply text is in them.
const TYPED_RECORDING: &str = include_str!("fixtures/terminal-title-thread-typed.json");
const DEVICE_RECORDING: &str = include_str!("fixtures/terminal-title-thread-device.json");

/// Replays one recording through the connection owner, every frame in its recorded direction: the
/// terminal's requests and notification as the terminal sends them, the server's replies and
/// notifications as the server sends them, and the host's own submission of a device's prompt as the
/// host sends it, through the broker's prompt. A frame the replay does not know fails the case with
/// its kind, and so does a request the server was not sent or a reply that no request waits for.
/// From the conversation's first reply on, the binding is checked after each frame: it names the
/// conversation's own thread at its revision, with the turn the conversation is running, and rich
/// work is not suspended.
///
/// The recording lacks the end of the title thread's turn (the offline server never answered a
/// model), and none is made up: the case reads the helper's leave while its turn is still running.
async fn replay_recording(recording: &str) {
    let facts: Vec<serde_json::Value> = serde_json::from_str(recording).expect("a recording");
    let mut world = World::recorded(1 << 24);
    // The requests the server has not answered, by method and recorded identifier, oldest first.
    let mut open: std::collections::BTreeMap<
        (String, String),
        std::collections::VecDeque<UpstreamRequestId>,
    > = Default::default();
    // The host's own submission: the request the server was sent and the call that waits for it.
    let mut submission: Option<(
        UpstreamRequestId,
        tokio::task::JoinHandle<kr_worker::broker::Result<kr_protocol::agent::AgentMutationResult>>,
    )> = None;
    let mark = |fact: &serde_json::Value, name: &str| -> Option<String> {
        fact["marks"].as_array().and_then(|marks| {
            marks.iter().filter_map(|m| m.as_str()).find_map(|m| {
                m.strip_prefix(&format!("{name}="))
                    .map(|value| value.trim_matches('"').to_owned())
            })
        })
    };
    let thread_of = |label: &str| format!("thread-{}", &label[1..]);
    let turn_of = |label: &str| format!("turn-{}", &label[1..]);
    // What the binding says once the conversation's own thread is selected, and the turn it runs.
    let mut conversation: Option<(String, u64)> = None;
    let mut running: Option<String> = None;
    let mut replayed = 0;
    for fact in &facts {
        let (direction, kind, method) = (
            fact["direction"].as_str().expect("a direction"),
            fact["kind"].as_str().expect("a kind"),
            fact["method"].as_str().expect("a method"),
        );
        let id = fact["id"].as_str().unwrap_or("").to_owned();
        let at = format!("{direction} {kind} {method} {id}");
        let thread = mark(fact, "thread").map(|label| thread_of(&label));
        let turn = mark(fact, "turn").map(|label| turn_of(&label));
        match (direction, kind) {
            ("C>S", "request") => {
                let params = match method {
                    "thread/start" => format!(
                        r#"{{"ephemeral":{},"threadSource":"{}"}}"#,
                        mark(fact, "ephemeral").expect("a mark"),
                        mark(fact, "threadSource").expect("a mark")
                    ),
                    "turn/start" => format!(
                        r#"{{"threadId":"{}","input":[]}}"#,
                        thread.as_deref().expect("a thread")
                    ),
                    "thread/unsubscribe" => format!(
                        r#"{{"threadId":"{}"}}"#,
                        thread.as_deref().expect("a thread")
                    ),
                    _ => "{}".to_owned(),
                };
                let asked = world
                    .terminal_asks(&format!(
                        r#"{{"id":{},"method":"{method}","params":{params}}}"#,
                        serde_json::to_string(&id).expect("an identifier")
                    ))
                    .await;
                let sent = server_read_within(&mut world, &at).await;
                assert_eq!(sent["method"], method, "{at}: the server was sent another");
                open.entry((method.to_owned(), id))
                    .or_default()
                    .push_back(asked);
            }
            ("C>S", "notification") => {
                world
                    .terminal_says(&format!(r#"{{"method":"{method}"}}"#))
                    .await;
                let sent = server_read_within(&mut world, &at).await;
                assert_eq!(sent["method"], method, "{at}: the server was sent another");
            }
            ("S>C", "reply") => {
                let asked = open
                    .get_mut(&(method.to_owned(), id))
                    .and_then(std::collections::VecDeque::pop_front)
                    .unwrap_or_else(|| panic!("{at}: no request of the terminal's waits for it"));
                let rest = match method {
                    "thread/start" => format!(
                        r#""result":{{"thread":{{"id":"{}","ephemeral":{},"threadSource":"{}"}}}}"#,
                        thread.as_deref().expect("a thread"),
                        mark(fact, "ephemeral").expect("a mark"),
                        mark(fact, "threadSource").expect("a mark")
                    ),
                    "turn/start" => format!(
                        r#""result":{{"turn":{{"id":"{}"}}}}"#,
                        turn.as_deref().expect("a turn")
                    ),
                    "thread/unsubscribe" => r#""result":{"status":"unsubscribed"}"#.to_owned(),
                    _ => r#""result":{}"#.to_owned(),
                };
                world.server_answers(&asked, &rest).await;
                if method == "thread/start" && conversation.is_none() {
                    conversation = thread.clone().map(|own| (own, world.revision()));
                }
            }
            ("S>C", "notification") => {
                let params = match (thread.as_deref(), turn.as_deref()) {
                    (Some(thread), Some(turn)) => {
                        serde_json::json!({ "threadId": thread, "turn": { "id": turn } })
                    }
                    (Some(thread), None) => serde_json::json!({ "threadId": thread }),
                    _ => serde_json::json!({}),
                };
                world
                    .server_says(
                        &serde_json::json!({ "method": method, "params": params }).to_string(),
                    )
                    .await;
                if method == "turn/started"
                    && thread.as_ref() == conversation.as_ref().map(|(own, _)| own)
                {
                    running = turn;
                }
            }
            ("H>S", "request") => {
                assert_eq!(method, "turn/start", "{at}: the host sends a prompt");
                let params = world.prompt("hello");
                let broker = Arc::clone(&world.broker);
                let call = tokio::spawn(async move {
                    broker
                        .agent_prompt(&World::owner_caller(), &params, false, NOW)
                        .await
                });
                let sent = server_read_within(&mut world, &at).await;
                assert_eq!(sent["method"], "turn/start", "{at}");
                assert_eq!(
                    sent["params"]["threadId"].as_str(),
                    thread.as_deref(),
                    "{at}: the device's prompt goes to the conversation's thread"
                );
                let sent_id = UpstreamRequestId::new(sent["id"].to_string()).expect("an id");
                submission = Some((sent_id, call));
            }
            ("S>H", "reply") => {
                let (sent_id, call) = submission
                    .take()
                    .unwrap_or_else(|| panic!("{at}: the host has sent no prompt"));
                world
                    .server_answers(
                        &sent_id,
                        &format!(
                            r#""result":{{"turn":{{"id":"{}"}}}}"#,
                            turn.as_deref().expect("a turn")
                        ),
                    )
                    .await;
                let carried = call
                    .await
                    .expect("the call ends")
                    .expect("the prompt is carried");
                assert_eq!(
                    carried.turn_id.0.map(|turn| turn.to_string()),
                    turn,
                    "{at}: the reply's turn"
                );
            }
            _ => panic!("{at}: a recorded frame the replay does not know"),
        }
        replayed += 1;
        if let Some((thread, revision)) = &conversation {
            assert_eq!(world.thread().as_ref(), Some(thread), "after {at}");
            assert_eq!(world.revision(), *revision, "after {at}");
            assert_eq!(world.turn(), running, "after {at}");
            assert_eq!(world.waiting(), None, "after {at}");
        }
    }
    assert_eq!(replayed, facts.len(), "every recorded frame was replayed");
    assert!(
        conversation.is_some(),
        "the recording selects a conversation"
    );
}

/// Reads the next line the owner wrote to the server, or fails with the frame that was to be there.
async fn server_read_within(world: &mut World, at: &str) -> serde_json::Value {
    tokio::time::timeout(std::time::Duration::from_secs(30), world.server_reads())
        .await
        .unwrap_or_else(|_| panic!("{at}: the server was sent nothing"))
}

/// A thread the terminal starts for its own purposes (the real terminal asks for the title of a
/// conversation in one, ephemeral and sourced from the system) is not the conversation
/// the terminal is in: the binding keeps the conversation's thread, its revision and its turn
/// through that thread's start, its turn and its leave, whether the prompt was typed at the
/// terminal or sent by a device.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_12_06_a_thread_the_terminal_starts_for_its_own_purposes_is_not_the_conversation() {
    replay_recording(TYPED_RECORDING).await;
    replay_recording(DEVICE_RECORDING).await;
}

/// The request the terminal makes for the title of a conversation: a thread of its own, ephemeral
/// and sourced from the system, that it never shows.
const HELPER_START: &str = r#"{"id":"helper-1","method":"thread/start","params":{"ephemeral":true,"threadSource":"system"}}"#;
const HELPER_LEAVE: &str =
    r#"{"id":"helper-2","method":"thread/unsubscribe","params":{"threadId":"thread-2"}}"#;

/// What a reply that starts a thread says of it, with the marks the terminal's own start carries.
fn named_thread(thread: &str, ephemeral: bool, source: &str) -> String {
    format!(
        r#""result":{{"thread":{{"id":"{thread}","ephemeral":{ephemeral},"threadSource":"{source}"}}}}"#
    )
}

/// A world whose conversation is `thread-1`, running `turn-1`, with the queue its completion
/// notices go to.
async fn running_conversation() -> (World, Arc<kr_worker::notices::SessionNotices>) {
    let mut world = World::new(1 << 20);
    let notices = Arc::new(kr_worker::notices::SessionNotices::default());
    world.broker.set_session_notices(Arc::clone(&notices));
    world.terminal_selects("thread-1").await;
    world
        .server_says(&turn_event("turn/started", "thread-1", "turn-1"))
        .await;
    assert_eq!(world.turn().as_deref(), Some("turn-1"));
    (world, notices)
}

/// KR-REQ-12.06: a request that meets every condition of its route starts a thread the terminal
/// never shows. It selects nothing and holds nothing back, its reply names no conversation, a turn
/// in its thread is not the conversation's turn and its end is no completion of the conversation's,
/// and the thread's leave changes nothing. The same flow on the next prompt changes nothing either.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_12_06_a_request_that_meets_every_condition_selects_nothing_and_holds_nothing() {
    let (world, notices) = running_conversation().await;
    let revision = world.revision();
    for round in 1..=2_u32 {
        let helper = format!("thread-{}", round + 1);
        let turn = format!("turn-{}", round + 1);
        let start = HELPER_START.replace("helper-1", &format!("helper-start-{round}"));
        let asked = world.terminal_asks(&start).await;
        assert_eq!(
            world.waiting(),
            None,
            "the hidden request holds nothing back"
        );
        world
            .server_answers(&asked, &named_thread(&helper, true, "system"))
            .await;
        for (event, at) in [("turn/started", "started"), ("turn/completed", "ended")] {
            world.server_says(&turn_event(event, &helper, &turn)).await;
            assert_eq!(world.thread().as_deref(), Some("thread-1"), "{at}");
            assert_eq!(world.turn().as_deref(), Some("turn-1"), "{at}");
            assert_eq!(world.waiting(), None, "{at}");
        }
        assert_eq!(
            notices.front(),
            None,
            "the helper's turn completed nothing of the conversation's"
        );
        let leave = HELPER_LEAVE
            .replace("helper-2", &format!("helper-leave-{round}"))
            .replace("thread-2", &helper);
        let leaving = world.terminal_asks(&leave).await;
        assert_eq!(
            world.waiting(),
            None,
            "the helper's leave holds nothing back"
        );
        world.server_answers(&leaving, r#""result":{}"#).await;
        assert_eq!(world.thread().as_deref(), Some("thread-1"));
        assert_eq!(world.turn().as_deref(), Some("turn-1"));
        assert_eq!(world.revision(), revision, "the binding never moved");
        assert_eq!(world.waiting(), None);
    }
    // The conversation's own turn ends as the conversation's: one completion, for its turn.
    world
        .server_says(&turn_event("turn/completed", "thread-1", "turn-1"))
        .await;
    assert_eq!(world.turn(), None);
    assert_eq!(
        notices.front(),
        Some(kr_protocol::attention::SessionEventNotice::TurnCompleted {
            turn_id: World::turn_id("turn-1")
        })
    );
}

/// KR-REQ-12.06: a request whose parameters are an object and whose member is absent or holds a
/// value of another type, and one that meets some of its route's conditions and not all, is a
/// selection as every request of a route with no conditions is: the reply's thread is the binding.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_12_06_a_request_that_does_not_meet_every_condition_is_a_selection() {
    for params in [
        r#"{"ephemeral":"true","threadSource":"system"}"#,
        r#"{"ephemeral":1,"threadSource":"system"}"#,
        r#"{"ephemeral":true,"threadSource":true}"#,
        r#"{"ephemeral":true,"threadSource":null}"#,
        r#"{"ephemeral":true,"threadSource":["system"]}"#,
        r#"{"ephemeral":true,"threadSource":"user"}"#,
        r#"{"ephemeral":false,"threadSource":"system"}"#,
        r#"{"ephemeral":true}"#,
        r#"{"threadSource":"system"}"#,
        r#"{}"#,
    ] {
        let (world, _notices) = running_conversation().await;
        let revision = world.revision();
        let asked = world
            .terminal_asks(&format!(
                r#"{{"id":"start-2","method":"thread/start","params":{params}}}"#
            ))
            .await;
        assert!(
            world.waiting().is_some(),
            "{params}: the request is a selection in flight"
        );
        world
            .server_answers(&asked, &named_thread("thread-2", true, "system"))
            .await;
        assert_eq!(world.thread().as_deref(), Some("thread-2"), "{params}");
        assert_eq!(world.revision(), revision + 1, "{params}");
        assert_eq!(
            world.turn(),
            None,
            "{params}: the turn went with the thread"
        );
        assert_eq!(world.waiting(), None, "{params}");
    }
}

/// KR-REQ-12.06: a hidden thread the terminal drops without a leave changes nothing: its turn
/// never ends, it is never left, and the conversation's turn, binding and completion are its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_12_06_a_hidden_thread_dropped_with_no_leave_changes_nothing() {
    let (world, notices) = running_conversation().await;
    let revision = world.revision();
    let asked = world.terminal_asks(HELPER_START).await;
    world
        .server_answers(&asked, &named_thread("thread-2", true, "system"))
        .await;
    world
        .server_says(&turn_event("turn/started", "thread-2", "turn-2"))
        .await;
    // The helper's turn is never reported ended and the thread is never left.
    world
        .server_says(&turn_event("turn/completed", "thread-1", "turn-1"))
        .await;
    assert_eq!(world.thread().as_deref(), Some("thread-1"));
    assert_eq!(world.revision(), revision);
    assert_eq!(world.turn(), None);
    assert_eq!(world.waiting(), None);
    assert_eq!(
        notices.front(),
        Some(kr_protocol::attention::SessionEventNotice::TurnCompleted {
            turn_id: World::turn_id("turn-1")
        })
    );
}

/// KR-REQ-12.06: a leave of a conversation other than the bound one, a request or a notification,
/// opens nothing and holds nothing back, whatever the server answers it, and the turn that runs is
/// the conversation's still. It is kept only where a selection is open or its reply waits, since
/// that selection may be the conversation the leave names.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_12_06_a_leave_of_another_conversation_opens_nothing_and_suspends_nothing() {
    let (world, _notices) = running_conversation().await;
    let revision = world.revision();
    for answer in [r#""result":{"status":"notSubscribed"}"#, REFUSED] {
        let leaving = world.terminal_asks(LEAVE_OTHER).await;
        assert_eq!(world.waiting(), None, "nothing is in flight");
        world.server_answers(&leaving, answer).await;
        assert_eq!(world.thread().as_deref(), Some("thread-1"));
        assert_eq!(world.turn().as_deref(), Some("turn-1"));
        assert_eq!(world.revision(), revision);
        assert_eq!(world.waiting(), None);
    }
    world
        .server_says(r#"{"method":"thread/closed","params":{"threadId":"thread-9"}}"#)
        .await;
    assert_eq!(world.thread().as_deref(), Some("thread-1"));
    assert_eq!(world.waiting(), None);

    // A selection open: the leave is kept in order with it, and ends what the selection named.
    let world = World::new(1 << 20);
    let first = world.terminal_asks(START).await;
    world.server_answers(&first, &named("thread-1")).await;
    let selecting = world.terminal_asks(RESUME).await;
    let leaving = world
        .terminal_asks(r#"{"id":5,"method":"thread/unsubscribe","params":{"threadId":"thread-2"}}"#)
        .await;
    assert!(
        world.waiting().is_some(),
        "the leave may name the selection"
    );
    world.server_answers(&selecting, &named("thread-2")).await;
    world.server_answers(&leaving, r#""result":{}"#).await;
    assert_eq!(world.thread(), None, "the terminal selected it and left it");
    assert!(world.waiting().is_some());

    // A selection's reply that waits for an older request: the leave is kept in order with it too.
    let world = World::new(1 << 20);
    let first = world.terminal_asks(START).await;
    world.server_answers(&first, &named("thread-1")).await;
    let leaving_first = world.terminal_asks(LEAVE_ONE).await;
    let selecting = world.terminal_asks(RESUME).await;
    world.server_answers(&selecting, &named("thread-2")).await;
    let leaving = world
        .terminal_asks(r#"{"id":5,"method":"thread/unsubscribe","params":{"threadId":"thread-2"}}"#)
        .await;
    world.server_answers(&leaving_first, r#""result":{}"#).await;
    world.server_answers(&leaving, r#""result":{}"#).await;
    assert_eq!(world.thread(), None, "the terminal selected it and left it");
    assert!(world.waiting().is_some());
}

/// KR-REQ-12.06: `/new` in the order the terminal sends it (the new conversation's start, its
/// reply, then the old conversation's leave, twice) ends with the new conversation bound and
/// nothing held back, and `/quit`'s leave of the bound one gives no conversation, with no fall
/// back to the one before.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_12_06_a_new_conversation_stays_bound_when_the_old_one_is_left_and_a_quit_leaves_none()
 {
    let (world, _notices) = running_conversation().await;
    let user_start = r#"{"id":"new-1","method":"thread/start","params":{"ephemeral":false,"threadSource":"user"}}"#;
    let asked = world.terminal_asks(user_start).await;
    assert!(
        world.waiting().is_some(),
        "a conversation the terminal shows is a selection"
    );
    world
        .server_answers(&asked, &named_thread("thread-2", false, "user"))
        .await;
    assert_eq!(world.thread().as_deref(), Some("thread-2"));
    assert_eq!(
        world.turn(),
        None,
        "the old conversation's turn went with it"
    );
    let bound = world.revision();
    for id in ["old-leave-1", "old-leave-2"] {
        let leaving = world
            .terminal_asks(&format!(
                r#"{{"id":"{id}","method":"thread/unsubscribe","params":{{"threadId":"thread-1"}}}}"#
            ))
            .await;
        assert_eq!(
            world.waiting(),
            None,
            "{id}: the old conversation's leave holds nothing"
        );
        world
            .server_answers(&leaving, r#""result":{"status":"unsubscribed"}"#)
            .await;
        assert_eq!(world.thread().as_deref(), Some("thread-2"), "{id}");
        assert_eq!(world.revision(), bound, "{id}");
        assert_eq!(world.waiting(), None, "{id}");
    }

    // `/quit` leaves the bound one: no conversation, and the earlier one does not return.
    let quitting = world
        .terminal_asks(
            r#"{"id":"quit-1","method":"thread/unsubscribe","params":{"threadId":"thread-2"}}"#,
        )
        .await;
    assert!(
        world.waiting().is_some(),
        "the bound conversation's leave is in flight"
    );
    world
        .server_answers(&quitting, r#""result":{"status":"unsubscribed"}"#)
        .await;
    assert_eq!(world.thread(), None);
    assert_eq!(world.revision(), bound + 1);
    assert!(
        world
            .waiting()
            .is_some_and(|reason| reason.contains("not read"))
    );
}

/// What a device's prompt meets: the thread the request that carries it names, or the refusal.
async fn device_prompt(world: &mut World) -> Result<String, String> {
    let admitted =
        match world
            .broker
            .admit_prompt(&World::owner_caller(), &world.prompt("hello"), false, NOW)
        {
            Ok(admitted) => admitted,
            Err(refused) => return Err(refused.to_string()),
        };
    let taken = world
        .broker
        .take_mutation(&admitted)
        .expect("nothing changed since the admission");
    let (dispatch, request) = taken.transmission();
    let _pending = dispatch
        .submit(&request)
        .expect("the frame is queued for the server");
    let sent = world.server_reads().await;
    assert_eq!(sent["method"], "turn/start");
    Ok(sent["params"]["threadId"]
        .as_str()
        .expect("a thread")
        .to_owned())
}

/// Walks the terminal's title flow once, sending a device's prompt at each boundary of it, and
/// returns what each met: before the helper's start, between its start and its reply, between its
/// reply and its turn, during its turn, between its turn's end and its leave, with its leave in
/// flight, and after its leave. `round` numbers the flow: the helper is `thread-{round + 1}` and
/// its turn `turn-{round + 1}`, so a second flow starts a thread of its own.
async fn prompts_at_each_boundary(
    world: &mut World,
    round: u32,
) -> Vec<(&'static str, Result<String, String>)> {
    let (helper, turn) = (
        format!("thread-{}", round + 1),
        format!("turn-{}", round + 1),
    );
    let start = HELPER_START.replace("helper-1", &format!("helper-start-{round}"));
    let leave = HELPER_LEAVE
        .replace("helper-2", &format!("helper-leave-{round}"))
        .replace("thread-2", &helper);
    let mut met = vec![("before the start", device_prompt(world).await)];
    let asked = world.terminal_asks(&start).await;
    assert_eq!(world.server_reads().await["method"], "thread/start");
    met.push((
        "between its start and its reply",
        device_prompt(world).await,
    ));
    world
        .server_answers(&asked, &named_thread(&helper, true, "system"))
        .await;
    met.push(("between its reply and its turn", device_prompt(world).await));
    world
        .server_says(&turn_event("turn/started", &helper, &turn))
        .await;
    met.push(("during its turn", device_prompt(world).await));
    world
        .server_says(&turn_event("turn/completed", &helper, &turn))
        .await;
    met.push(("between its turn and its leave", device_prompt(world).await));
    let leaving = world.terminal_asks(&leave).await;
    assert_eq!(world.server_reads().await["method"], "thread/unsubscribe");
    met.push(("with its leave in flight", device_prompt(world).await));
    world.server_answers(&leaving, r#""result":{}"#).await;
    met.push(("after its leave", device_prompt(world).await));
    met
}

/// KR-REQ-11.36 and KR-REQ-12.06: a device's prompt sent at any point of the title flow of the
/// terminal goes to the conversation's thread, or is refused for the conversation's own running
/// turn. It never goes to the hidden thread, and the hidden thread's turn never refuses it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_11_36_a_devices_prompt_at_each_boundary_of_the_title_flow_never_meets_the_hidden_thread()
 {
    // The conversation's turn runs through two title flows: each prompt is refused for that turn.
    let (mut world, _notices) = running_conversation().await;
    for round in 1..=2 {
        for (boundary, met) in prompts_at_each_boundary(&mut world, round).await {
            let refusal = met.expect_err(boundary);
            assert!(
                refusal.contains("turn-1 is running"),
                "round {round}, {boundary}: {refusal}"
            );
            assert!(
                !refusal.contains(&format!("turn-{}", round + 1)),
                "round {round}, {boundary}: {refusal}"
            );
        }
    }
    // The server was sent the terminal's requests for the two hidden threads and no prompt.
    world.nothing_written().await;

    // The conversation is idle: each prompt goes to its thread, including while a hidden thread's
    // turn runs, in the second flow as in the first.
    let mut world = World::new(1 << 20);
    world.terminal_selects("thread-1").await;
    for round in 1..=2 {
        for (boundary, met) in prompts_at_each_boundary(&mut world, round).await {
            assert_eq!(met.as_deref(), Ok("thread-1"), "round {round}, {boundary}");
        }
    }
}

/// The Codex server decodes a positional array as the parameters of a start, in the order of its
/// fields: here the 26 positions of a start, with `ephemeral` true at position 16 and
/// `threadSource` "system" at position 19.
const ARRAY_START: &str = r#"{"id":"array-1","method":"thread/start","params":[null,null,false,null,null,null,null,null,null,null,null,null,null,null,null,null,true,null,null,"system",null,null,null,null,null,false]}"#;

/// Whether rich work waits because a request of the terminal's that changes its conversation has
/// not been answered.
fn in_flight(waiting: Option<String>) -> bool {
    waiting.is_some_and(|reason| reason.contains("the server has not answered"))
}

/// Whether rich work waits for the reason the stream gives when what became of the terminal's last
/// request to change its conversation is not known. The other reasons it gives (a request still in
/// flight, no thread read yet, an unlisted frame) say "unknown" too, so this is the hold's own text.
fn unknown(waiting: Option<String>) -> bool {
    waiting.is_some_and(|reason| reason.contains("what became of the terminal's last request"))
}

/// KR-REQ-12.06: on a route whose table states conditions, a request whose parameters are not an
/// object can be neither tested nor trusted. It is not hidden and its reply is not adopted: from
/// its admission what the terminal is in is unknown, and rich work waits, until a later selection
/// that can be read is answered. A route that states no condition reads every request as before.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_12_06_a_request_the_conditions_cannot_be_read_in_is_neither_hidden_nor_a_selection()
{
    let mut world = World::new(1 << 20);
    world.terminal_selects("thread-1").await;
    let revision = world.revision();

    // The array the server reads as a hidden start: the binding is unknown from the request on.
    let asked = world.terminal_asks(ARRAY_START).await;
    assert_eq!(world.server_reads().await["method"], "thread/start");
    assert!(unknown(world.waiting()), "{:?}", world.waiting());
    world
        .server_answers(&asked, &named_thread("thread-2", true, "system"))
        .await;
    assert_eq!(world.thread().as_deref(), Some("thread-1"), "never adopted");
    assert_eq!(world.revision(), revision);
    assert!(unknown(world.waiting()), "{:?}", world.waiting());
    world
        .server_says(&turn_event("turn/started", "thread-2", "turn-2"))
        .await;
    let leaving = world.terminal_asks(HELPER_LEAVE).await;
    assert_eq!(world.server_reads().await["method"], "thread/unsubscribe");
    world.server_answers(&leaving, r#""result":{}"#).await;
    assert!(
        unknown(world.waiting()),
        "the helper's leave does not end it: {:?}",
        world.waiting()
    );
    // A device's prompt is refused for the unknown thread and sent nowhere.
    let refusal = device_prompt(&mut world).await.expect_err("a prompt waits");
    assert!(refusal.contains("unknown"), "{refusal}");
    world.nothing_written().await;
    // The next selection that can be read is adopted.
    let selecting = world.terminal_asks(START).await;
    assert_eq!(world.server_reads().await["method"], "thread/start");
    world.server_answers(&selecting, &named("thread-3")).await;
    assert_eq!(world.thread().as_deref(), Some("thread-3"));
    assert_eq!(world.waiting(), None);
    assert_eq!(device_prompt(&mut world).await.as_deref(), Ok("thread-3"));

    // Parameters that are no object at all: null, text, a number, an empty array and none.
    for (params, member) in [
        ("null", r#","params":null"#),
        (r#""system""#, r#","params":"system""#),
        ("7", r#","params":7"#),
        ("[]", r#","params":[]"#),
        ("absent", ""),
    ] {
        let mut world = World::new(1 << 20);
        world.terminal_selects("thread-1").await;
        let asked = world
            .terminal_asks(&format!(
                r#"{{"id":"odd-1","method":"thread/start"{member}}}"#
            ))
            .await;
        assert!(unknown(world.waiting()), "{params}: {:?}", world.waiting());
        world
            .server_answers(&asked, &named_thread("thread-2", false, "user"))
            .await;
        assert_eq!(world.thread().as_deref(), Some("thread-1"), "{params}");
        assert!(unknown(world.waiting()), "{params}: {:?}", world.waiting());
    }

    // An earlier selection's reply does not end it; a later one does.
    let mut world = World::new(1 << 20);
    world.terminal_selects("thread-1").await;
    let earlier = world.terminal_asks(RESUME).await;
    world.terminal_asks(ARRAY_START).await;
    world.server_answers(&earlier, &named("thread-2")).await;
    assert!(unknown(world.waiting()), "{:?}", world.waiting());
    let later = world.terminal_asks(START).await;
    world.server_answers(&later, &named("thread-3")).await;
    assert_eq!(world.thread().as_deref(), Some("thread-3"));
    assert_eq!(world.waiting(), None);

    // A route that states no condition reads every request as before: an array selects.
    let world = World::new(1 << 20);
    let first = world.terminal_asks(START).await;
    world.server_answers(&first, &named("thread-1")).await;
    let asked = world
        .terminal_asks(r#"{"id":"resume-1","method":"thread/resume","params":["thread-2"]}"#)
        .await;
    world.server_answers(&asked, &named("thread-2")).await;
    assert_eq!(world.thread().as_deref(), Some("thread-2"));
}

/// KR-REQ-12.06: the helper's leave while a visible start is open stays in order with that start,
/// whichever reply comes first, and a hidden start admitted while a visible resume is open changes
/// neither the resume's reply nor what waits for it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_12_06_a_helpers_leave_and_start_do_not_disturb_a_visible_request_in_flight() {
    // `/new` while the helper's leave comes: both orders of the two replies end on the new thread.
    for leave_first in [false, true] {
        let mut world = World::new(1 << 20);
        world.terminal_selects("thread-1").await;
        let started = world.terminal_asks(HELPER_START).await;
        world
            .server_answers(&started, &named_thread("thread-2", true, "system"))
            .await;
        let selecting = world
            .terminal_asks(
                r#"{"id":"new-1","method":"thread/start","params":{"ephemeral":false,"threadSource":"user"}}"#,
            )
            .await;
        let leaving = world.terminal_asks(HELPER_LEAVE).await;
        assert!(
            world.waiting().is_some(),
            "{leave_first}: both are in flight"
        );
        let (first, second) = if leave_first {
            (&leaving, &selecting)
        } else {
            (&selecting, &leaving)
        };
        let new_thread = named_thread("thread-3", false, "user");
        let (first_rest, second_rest) = if leave_first {
            (r#""result":{}"#.to_owned(), new_thread)
        } else {
            (new_thread, r#""result":{}"#.to_owned())
        };
        world.server_answers(first, &first_rest).await;
        // Between the two replies the other is still in flight: nothing is applied, rich work waits
        // for it, and the binding is the conversation the terminal had.
        assert_eq!(world.thread().as_deref(), Some("thread-1"), "{leave_first}");
        assert!(
            in_flight(world.waiting()),
            "{leave_first}: the other request is in flight: {:?}",
            world.waiting()
        );
        world.server_answers(second, &second_rest).await;
        assert_eq!(world.thread().as_deref(), Some("thread-3"), "{leave_first}");
        assert_eq!(world.waiting(), None, "{leave_first}");
    }

    // A hidden start admitted while a visible resume is open: the resume is the selection.
    for hidden_first in [false, true] {
        let world = World::new(1 << 20);
        let first = world.terminal_asks(START).await;
        world.server_answers(&first, &named("thread-1")).await;
        let resuming = world.terminal_asks(RESUME).await;
        let hidden = world.terminal_asks(HELPER_START).await;
        assert!(
            world.waiting().is_some(),
            "{hidden_first}: the resume is in flight"
        );
        let hidden_reply = named_thread("thread-9", true, "system");
        if hidden_first {
            world.server_answers(&hidden, &hidden_reply).await;
            assert!(world.waiting().is_some(), "the resume is still in flight");
            world.server_answers(&resuming, &named("thread-2")).await;
        } else {
            world.server_answers(&resuming, &named("thread-2")).await;
            assert_eq!(world.waiting(), None, "the hidden start waits for nothing");
            world.server_answers(&hidden, &hidden_reply).await;
        }
        assert_eq!(
            world.thread().as_deref(),
            Some("thread-2"),
            "{hidden_first}"
        );
        assert_eq!(world.waiting(), None, "{hidden_first}");
    }
}

/// KR-REQ-12.06: a hidden request that is given up as unknown, because the server may have read it,
/// holds nothing back and leaves the binding where it was: nothing was waiting for its reply.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_12_06_a_hidden_request_given_up_as_unknown_holds_nothing() {
    let (world, _notices) = running_conversation().await;
    let revision = world.revision();
    let asked = world.terminal_asks(HELPER_START).await;
    world
        .broker
        .client_request_given_up(world.connection, &asked, true);
    assert_eq!(world.thread().as_deref(), Some("thread-1"));
    assert_eq!(world.turn().as_deref(), Some("turn-1"));
    assert_eq!(world.revision(), revision);
    assert_eq!(world.waiting(), None);

    // A visible start given up the same way holds the instance, as it always did.
    let asked = world.terminal_asks(START).await;
    world
        .broker
        .client_request_given_up(world.connection, &asked, true);
    assert!(unknown(world.waiting()), "{:?}", world.waiting());
}

/// KR-REQ-11.33 and KR-REQ-12.06: an approval the server asks on the helper's turn is not
/// attributed to a thread. What a device is shown is what it is shown for any approval of the
/// instance: one pending resource, interpreted, with the table's decisions. This pins that limit; it
/// does not claim the approval is the conversation's.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_11_33_an_approval_on_the_helpers_turn_is_listed_as_the_instances() {
    let (world, _notices) = running_conversation().await;
    let asked = world.terminal_asks(HELPER_START).await;
    world
        .server_answers(&asked, &named_thread("thread-2", true, "system"))
        .await;
    world
        .server_says(&turn_event("turn/started", "thread-2", "turn-2"))
        .await;
    world
        .server_says(
            r#"{"id":"approval-2","method":"item/commandExecution/requestApproval","params":{"itemId":"item-2","startedAtMs":0,"threadId":"thread-2","turnId":"turn-2"}}"#,
        )
        .await;
    let resources = world.broker.pending_resources();
    assert_eq!(resources.len(), 1, "{resources:?}");
    assert_eq!(resources[0].application_instance_id, instance());
    assert_eq!(resources[0].state, PendingState::Pending);
    assert!(
        resources[0].interpretation_verified,
        "a decoder may read it"
    );
    assert_eq!(world.thread().as_deref(), Some("thread-1"));
    assert_eq!(world.turn().as_deref(), Some("turn-1"));
}

/// KR-REQ-12.06: what ends the unknown that an unreadable request leaves. The server's refusal, or
/// the knowledge that the frame never went, says that no thread was started, so the binding is as
/// it was and a device's prompt goes to the bound thread again. A success reply, which names a
/// thread no reading of the request can attribute, and an outcome that was lost keep it unknown
/// until a selection that can be read is answered.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_12_06_an_unreadable_request_the_server_refuses_or_that_never_went_leaves_the_binding_as_it_was()
 {
    // A refusal, for each shape the server refuses (it decodes parameters only from an object or an
    // array) and for the array it could read.
    for (shape, frame) in [
        (
            "null",
            r#"{"id":"odd-1","method":"thread/start","params":null}"#,
        ),
        ("none", r#"{"id":"odd-1","method":"thread/start"}"#),
        ("array", ARRAY_START),
    ] {
        let mut world = World::new(1 << 20);
        world.terminal_selects("thread-1").await;
        let revision = world.revision();
        let asked = world.terminal_asks(frame).await;
        assert_eq!(world.server_reads().await["method"], "thread/start");
        assert!(unknown(world.waiting()), "{shape}: {:?}", world.waiting());
        world.server_answers(&asked, REFUSED).await;
        assert_eq!(world.waiting(), None, "{shape}: the refusal ends it");
        assert_eq!(world.thread().as_deref(), Some("thread-1"), "{shape}");
        assert_eq!(world.revision(), revision, "{shape}");
        assert_eq!(
            device_prompt(&mut world).await.as_deref(),
            Ok("thread-1"),
            "{shape}"
        );
    }

    // A frame that never went: the server never saw it.
    let mut world = World::new(1 << 20);
    world.terminal_selects("thread-1").await;
    let asked = world.terminal_asks(ARRAY_START).await;
    assert!(unknown(world.waiting()), "{:?}", world.waiting());
    world
        .broker
        .client_request_given_up(world.connection, &asked, false);
    assert_eq!(world.waiting(), None, "an unsent frame is no thread");
    assert_eq!(world.thread().as_deref(), Some("thread-1"));

    // A success reply and a lost outcome keep it unknown, until a selection that can be read is
    // answered.
    for lost in [false, true] {
        let mut world = World::new(1 << 20);
        world.terminal_selects("thread-1").await;
        let asked = world.terminal_asks(ARRAY_START).await;
        assert_eq!(world.server_reads().await["method"], "thread/start");
        if lost {
            world
                .broker
                .client_request_given_up(world.connection, &asked, true);
        } else {
            world
                .server_answers(&asked, &named_thread("thread-2", true, "system"))
                .await;
        }
        assert!(unknown(world.waiting()), "{lost}: {:?}", world.waiting());
        assert_eq!(world.thread().as_deref(), Some("thread-1"), "{lost}");
        let refusal = device_prompt(&mut world).await.expect_err("a prompt waits");
        assert!(refusal.contains("what became of"), "{lost}: {refusal}");
        let selecting = world.terminal_asks(START).await;
        assert_eq!(world.server_reads().await["method"], "thread/start");
        world.server_answers(&selecting, &named("thread-3")).await;
        assert_eq!(world.thread().as_deref(), Some("thread-3"), "{lost}");
        assert_eq!(world.waiting(), None, "{lost}");
    }
}

/// KR-REQ-12.06: only a request can hold. A notification of a selecting method whose parameters are
/// not an object has no reply and starts no thread any more than the same frame in object form.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_12_06_a_notification_of_a_selecting_method_with_odd_parameters_changes_nothing() {
    let mut world = World::new(1 << 20);
    world.terminal_selects("thread-1").await;
    let revision = world.revision();
    for frame in [
        r#"{"method":"thread/start","params":[]}"#,
        r#"{"method":"thread/start","params":null}"#,
        r#"{"method":"thread/start"}"#,
        r#"{"method":"thread/start","params":{}}"#,
    ] {
        world.terminal_says(frame).await;
        assert_eq!(world.server_reads().await["method"], "thread/start");
        assert_eq!(world.waiting(), None, "{frame}");
        assert_eq!(world.thread().as_deref(), Some("thread-1"), "{frame}");
        assert_eq!(world.revision(), revision, "{frame}");
    }
}

/// KR-REQ-12.06: the replies of an unreadable request and a readable selection come in either
/// order. A selection admitted after the unreadable request and answered names the conversation the
/// terminal is in, whichever reply comes last, and the unreadable request's reply then changes
/// nothing; one admitted before it is answered leaves the unknown to the unreadable request.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_12_06_a_selection_answered_after_an_unreadable_request_names_the_conversation() {
    for (reply, unreadable_reply) in [
        ("success", named_thread("thread-9", true, "system")),
        ("refusal", REFUSED.to_owned()),
    ] {
        let mut world = World::new(1 << 20);
        world.terminal_selects("thread-1").await;
        let unreadable = world.terminal_asks(ARRAY_START).await;
        let selecting = world.terminal_asks(START).await;
        assert_eq!(world.server_reads().await["method"], "thread/start");
        assert_eq!(world.server_reads().await["method"], "thread/start");
        world.server_answers(&selecting, &named("thread-2")).await;
        assert_eq!(world.thread().as_deref(), Some("thread-2"), "{reply}");
        assert_eq!(
            world.waiting(),
            None,
            "{reply}: the selection answered after it names the conversation"
        );
        world.server_answers(&unreadable, &unreadable_reply).await;
        assert_eq!(world.thread().as_deref(), Some("thread-2"), "{reply}");
        assert_eq!(world.waiting(), None, "{reply}");
        assert_eq!(
            device_prompt(&mut world).await.as_deref(),
            Ok("thread-2"),
            "{reply}"
        );
    }

    // The selection was admitted before the unreadable request: its reply does not end the unknown.
    let mut world = World::new(1 << 20);
    world.terminal_selects("thread-1").await;
    let selecting = world.terminal_asks(START).await;
    let unreadable = world.terminal_asks(ARRAY_START).await;
    assert_eq!(world.server_reads().await["method"], "thread/start");
    assert_eq!(world.server_reads().await["method"], "thread/start");
    world.server_answers(&selecting, &named("thread-2")).await;
    assert_eq!(world.thread().as_deref(), Some("thread-2"));
    assert!(unknown(world.waiting()), "{:?}", world.waiting());
    world
        .server_answers(&unreadable, &named_thread("thread-9", true, "system"))
        .await;
    assert!(unknown(world.waiting()), "{:?}", world.waiting());
}
