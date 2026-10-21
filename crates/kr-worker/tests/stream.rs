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
//! | KR-REQ-12.06 | the thread a success reply to a selecting request names is the instance's binding, the revision advances only when the thread changed, and rich mutations resume; they wait while a selection is in flight and after one whose outcome is unknown, an older reply never restores a conversation the terminal left, a conversation another execution owns is never published, and a turn or a leave about another thread changes nothing |
//! | KR-REQ-11.30 | an unlisted frame keeps rich mutations suspended until a selection admitted after it has named the thread and every unlisted request before that has been answered |
//! | KR-REQ-12.08 | a gateway connection's capability evidence says what its tables let a client do, follows each change of binding, and ends with the connection |
//! | KR-REQ-11.33 | a request the connector's table answers as a response is interpreted under the binding's trust; the server's own word that it was answered settles what nobody answered and leaves an answer that is being written to its writer |
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
}

impl World {
    /// `upstream_capacity` bytes is what the pipe to the server holds before a write waits.
    fn new(upstream_capacity: usize) -> Self {
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
            Broker::open(None, session(), JournalHealth::shared()).expect("the broker opens"),
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
        Self {
            _store: store,
            broker,
            owner,
            upstream,
            _client: client,
            connection,
            writes: tokio::spawn(writes),
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
}

impl Drop for World {
    fn drop(&mut self) {
        self.writes.abort();
    }
}

const START: &str = r#"{"id":1,"method":"thread/start","params":{}}"#;
const RESUME: &str = r#"{"id":2,"method":"thread/resume","params":{"threadId":"thread-2"}}"#;

fn named(thread: &str) -> String {
    format!(r#""result":{{"thread":{{"id":"{thread}"}}}}"#)
}

fn turn_event(method: &str, thread: &str, turn: &str) -> String {
    format!(
        r#"{{"method":"{method}","params":{{"threadId":"{thread}","turn":{{"id":"{turn}"}}}}}}"#
    )
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
    assert_eq!(world.thread().as_deref(), Some("thread-2"));
    assert_eq!(world.waiting(), None, "the newest request is answered");
    // The older reply arrives last and names another thread: nothing changes.
    let revision = world.revision();
    world.server_answers(&older, &named("thread-1")).await;
    assert_eq!(world.thread().as_deref(), Some("thread-2"));
    assert_eq!(world.revision(), revision);

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
    // The package answers an approval and is trusted to; it declares no way to submit, queue,
    // steer or cancel, and says so.
    let approval = capability("agent.approval");
    assert_eq!(
        approval.state,
        InstanceCapabilityState::QualifiedAvailable,
        "{:?}",
        approval.disabled_reason
    );
    for name in [
        "agent.prompt",
        "agent.prompt.queue",
        "agent.steer",
        "agent.cancel",
    ] {
        let held = capability(name);
        assert_eq!(held.state, InstanceCapabilityState::Incompatible, "{name}");
        assert!(
            held.disabled_reason
                .0
                .is_some_and(|reason| reason.contains("declares no way")),
            "{name}"
        );
    }

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
    let mut taken = vec![0_u8; 128];
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
