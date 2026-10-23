//! What the stream of a gateway connection says about the terminal's conversation and turn, read
//! by the core from the places the installed connector's table names.
//!
//! Each case installs the Codex-shaped test package whose table answers an approval as a response
//! and names where its messages name a thread, a turn and a cleared request, binds it to an
//! instance as a launch does, and opens a connection whose owner the case drives by hand: what the
//! terminal sends goes in through the client end, what the server says through the upstream end.
//! The instance's binding, its suspension and its capability map are read back from the broker.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-12.06 | the thread a success reply to a selecting request names is the instance's binding, the revision advances only when the thread changed, and rich mutations resume; they wait while a selection is in flight and after one whose outcome is unknown, an older reply never restores a conversation the terminal left, a conversation another execution owns is never published, a turn or a leave about another thread changes nothing, replies are applied in the order their requests were admitted once none is in flight (a success whose newer request is then refused is the binding; a leave of another conversation does not hide an older selection; a leave of the bound conversation survives a newer request that is refused), a notification that closes a conversation a kept reply selected, or reports a turn in it, leaves the terminal's conversation unknown instead of letting the reply restore it; and a request given up at its deadline keeps the instance suspended until a selection names the conversation |
//! | KR-REQ-12.04 | a prompt, a steer or a cancellation admitted before a turn began or ended is stopped at its take, which reads the turn again; a turn reported in a conversation a kept reply selected is not taken without that reply being weighed |
//! | KR-REQ-11.30 | an unlisted frame keeps rich mutations suspended until a selection admitted after it has named the thread and every unlisted request before that has been answered |
//! | KR-REQ-12.08 | a gateway connection's capability evidence says what its tables let a client do, follows each change of binding, and ends with the connection |
//! | KR-REQ-11.33 | a request the connector's table answers as a response is interpreted under the binding's trust; the server's own word that it was answered settles what nobody answered and leaves an answer that is being written to its writer; an answer admitted before its decoder's authority was withdrawn is stopped at its take, and one admitted before a fault finishes |
//! | KR-REQ-11.36 | a typed prompt reaches the server as the request the connector's table spells, naming the thread the binding holds, and the reply's turn is read where the table says |
//! | KR-REQ-11.28 | an action the package declares as a cancellation is admitted with a token the host issues and spends against its own plan, and is written as the connector's template for a cancellation naming the thread and the running turn; with no turn running it is refused with nothing written |
//! | KR-REQ-23.30 | a component's plan for the action declared as a cancellation is validated against the token the host issued and is written through the same template; a plan that prepares another operation, or whose arguments are not the ones the token covers, is refused before anything is written; a component's prompt has no source in the table and is refused before the marker |
//! | KR-REQ-12.12 | the rich table lists exactly the operations the table declares; one it does not declare is refused with nothing written, and so is a prompt over a running turn, one that names a draft and a steer of a turn that is not the running one |
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

    fn opened(upstream_capacity: usize, shared: Option<&common::SharedStore>) -> Self {
        let root = std::env::temp_dir().join(format!("kr-stream-{}", kr_ipc::new_uuid()));
        std::fs::create_dir_all(&root).expect("a store directory");
        let store = Store(root);
        let mut source = fixture::package(
            &store.0,
            Path::new(fixture::FORWARDER),
            &fixture::Shape::codex_backend_answering(),
        )
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

    // The terminal unsubscribes from a thread it is not in: the binding stands. From the one it is
    // in, and the server's success reply: the binding ends.
    let other = world
        .terminal_asks(r#"{"id":3,"method":"thread/unsubscribe","params":{"threadId":"thread-9"}}"#)
        .await;
    assert!(world.waiting().is_some(), "the request is in flight");
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
        world
            .waiting()
            .is_some_and(|reason| reason.contains("cannot be bound")),
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

/// KR-REQ-11.33 and KR-REQ-11.35: a committed marker followed by a transmission that fails is not
/// a refusal. The answer's fate is unknown, the connection a failed write ends serves the terminal
/// nothing more, the request stays uncertain, and nobody sends it again.
///
/// Not claimed: Windows, where no gateway runs.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_11_35_a_committed_marker_followed_by_a_failed_transmission_leaves_the_request_uncertain()
 {
    let store = common::SharedStore::open();
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

    // The server's end of the pipe is gone: the bytes cannot be written.
    drop(std::mem::replace(
        &mut world.upstream,
        tokio::io::duplex(1).0,
    ));
    let (dispatch, request) = marked.transmission();
    let failed = match dispatch.submit(&request) {
        Ok(pending) => marked.submitted(pending).settled(NOW).await.err(),
        Err(error) => Some(marked.refused(error)),
    };
    let failed = failed.expect("the answer could not be written");
    assert!(
        !failed.proven_unsent(),
        "after the marker nobody can establish what happened: {failed:?}"
    );
    state_of(&world, id, PendingState::Uncertain).await;

    // A write that failed ended the connection, so the terminal's answer comes to a connection
    // that no longer serves, and nothing is written for it. The request stays uncertain: no
    // writer answers it again.
    world
        .owner
        .from_client(TERMINAL_ANSWERS, NOW)
        .await
        .expect_err("the connection ended with the failed write");
    assert_eq!(
        world.broker.pending(id).expect("held").state,
        PendingState::Uncertain
    );
}

/// KR-REQ-12.06: a prompt, a steer or a declared cancellation admitted before the terminal asked
/// to change its conversation is stopped when its permit is taken: nothing is written and the
/// refusal is proven.
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
