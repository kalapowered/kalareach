//! KR-REQ-03.27 through the control daemon: while a storage call holds a session, the host's sleep
//! scan never counts less for that session than it counted before the hold.
//!
//! One real daemon with the sleep setting on, a real worker it adopts (the worker's own service,
//! with its evidence loop, its broker and its question ledger) and an agent whose frames go into
//! that broker as the connector's would. A seam holds the worker's session, and the worker then
//! answers `session.read` from what it keeps outside the session, with `held` set. Each case
//! counts what the host's own read of the sleep demand says before the hold, during it and after
//! it, and asserts first that the worker's answer is a held one, so that a case that never reached
//! a hold fails at its premise.
//!
//! The counts are `(sessions with work, pending requests)`, which `host.info` carries and which
//! hold on every platform; whether the machine is kept awake for them is the platform's.

#![cfg(unix)]

mod net_support;

use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use kr_protocol::broker::IntegrationMode;
use kr_protocol::desktop::SleepInhibitionSetting;
use kr_protocol::gateway::NativeFraming;
use kr_protocol::hostinfo::HostInfoResult;
use kr_protocol::identity::{ProcessStartIdentity, ProcessStartSource};
use kr_protocol::ids::{ApplicationInstanceId, BrokerBindingId, ConnectionId, EnvironmentId};
use kr_protocol::method::Method;
use kr_protocol::scalars::{Digest256, Nullable, TimestampMs, Uuid};
use kr_protocol::session::{ApplicationState, SessionReadParams, SessionReadResult};
use kr_worker::broker::binder::MatchedExecutable;
use kr_worker::broker::catalogue::{Admissions, testing};
use kr_worker::broker::connectors::{
    ConnectorSources, InstalledConnector, QualifiedExecutable, fixture,
};
use kr_worker::broker::{
    BrokerTransport, Carried, Credential, Duplex, Framing, ManagedProcess, TransportHandle,
};
use net_support::Host;
use net_support::worker::{Adopted, Worker};
use tokio::io::AsyncReadExt as _;

/// How long a case waits for the worker to reach a state it made.
const REACH: Duration = Duration::from_secs(20);
/// How long a case watches the host's count while a hold stands. The scan answers within a
/// second, so this is several scans.
const WATCH: Duration = Duration::from_secs(3);
/// How long a case waits for the host's count to come to a value it expects.
const COUNT_BOUND: Duration = Duration::from_secs(60);

const AGENT_NOW: TimestampMs = TimestampMs::new(10);
const AGENT_START: &str = r#"{"id":1,"method":"thread/start","params":{}}"#;
const TURN_7_STARTED: &str =
    r#"{"method":"turn/started","params":{"threadId":"thread-1","turn":{"id":"turn-7"}}}"#;
const TURN_7_ENDED: &str =
    r#"{"method":"turn/completed","params":{"threadId":"thread-1","turn":{"id":"turn-7"}}}"#;
const TURN_8_STARTED: &str =
    r#"{"method":"turn/started","params":{"threadId":"thread-1","turn":{"id":"turn-8"}}}"#;

/// No turn running, no question open.
const IDLE: (u64, u64) = (0, 0);
/// An agent at work.
const BUSY: (u64, u64) = (1, 0);
/// A question open.
const ASKED: (u64, u64) = (0, 1);

/// A daemon with the sleep setting on that has adopted one worker, and an agent bound to that
/// worker's broker.
struct Rig {
    agent: Agent,
    adopted: Adopted,
}

impl Rig {
    async fn start() -> Self {
        let mut document = kr_protocol::hostinfo::configuration::ConfigurationDocument::empty();
        document.preferences.sleep_inhibition =
            kr_protocol::scalars::Nullable::some(SleepInhibitionSetting::BatteryToo);
        let adopted = Adopted::start_with_document(1, &document).await;
        let mut agent = bind_agent(&adopted.workers[0]).await;
        agent.selects_a_thread().await;
        Self { agent, adopted }
    }

    fn worker(&self) -> &Worker {
        &self.adopted.workers[0]
    }

    fn host(&self) -> &Host {
        &self.adopted.host
    }

    /// What the host's own read of the sleep demand counts now, which makes the scan run.
    async fn counts(&self) -> (u64, u64) {
        let mut local = self.host().client().await;
        let info: HostInfoResult = local
            .request(Method::HostInfo, &())
            .await
            .expect("the call reaches the daemon")
            .expect("host.info is served on the local socket")
            .to_typed()
            .expect("a result of the declared shape");
        (
            info.power.sessions_with_work.get(),
            info.power.pending_requests.get(),
        )
    }

    /// Waits until the host counts `expected`, and fails with what it counted last.
    async fn counts_become(&self, expected: (u64, u64), what: &str) {
        let deadline = Instant::now() + COUNT_BOUND;
        loop {
            let counted = self.counts().await;
            if counted == expected {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "{what}: the host counted {counted:?} and never {expected:?}"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Reads the host's count for [`WATCH`] and fails at the first read that is not `expected`.
    async fn counts_stay(&self, expected: (u64, u64), what: &str) {
        let until = Instant::now() + WATCH;
        while Instant::now() < until {
            let counted = self.counts().await;
            assert_eq!(
                counted, expected,
                "{what}: the host counted {counted:?} and not {expected:?} while the hold stood"
            );
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
    }

    /// The application state the worker's input domain holds, which is what a held answer says.
    fn domain_state(&self) -> Option<ApplicationState> {
        self.worker().runtime().input().lock().application_state()
    }

    async fn domain_state_becomes(&self, expected: Option<ApplicationState>, what: &str) {
        let deadline = Instant::now() + REACH;
        while self.domain_state() != expected {
            assert!(
                Instant::now() < deadline,
                "{what}: the worker's domain said {:?} and never {expected:?}",
                self.domain_state()
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// Reads the session at the worker's own socket and says whether the worker gave a held
    /// answer, which is what a case's premise stands on.
    async fn the_worker_answers_held(&self) -> bool {
        let mut client = self.worker().client().await;
        let read: SessionReadResult = tokio::time::timeout(
            REACH,
            client.request(
                Method::SessionRead,
                &SessionReadParams {
                    session_id: self.worker().session_id,
                },
            ),
        )
        .await
        .expect("the worker answers a read of its session within a bound")
        .expect("the call reaches the worker")
        .expect("the worker serves the read")
        .to_typed()
        .expect("a result of the declared shape");
        read.held
    }

    /// Holds the worker's session until the returned end lets it go, and asserts that the worker
    /// then answers held.
    async fn hold_the_session(&self, what: &str) -> std::sync::mpsc::Sender<()> {
        let (held, release) = self.worker().runtime().hold_the_session();
        tokio::time::timeout(REACH, held)
            .await
            .unwrap_or_else(|_| panic!("{what}: the session was not held within {REACH:?}"))
            .expect("the hold was dropped before it was reached");
        assert!(
            self.the_worker_answers_held().await,
            "{what}: the worker did not give a held answer while the session was held"
        );
        release
    }
}

/// One gateway instance bound to the worker's broker, and the connection that its application's
/// frames travel on.
struct Agent {
    owner: Arc<Duplex>,
    upstream: tokio::io::DuplexStream,
    _client: tokio::io::DuplexStream,
    writes: tokio::task::JoinHandle<()>,
    _package: tempfile::TempDir,
}

impl Drop for Agent {
    fn drop(&mut self) {
        self.writes.abort();
    }
}

async fn bind_agent(worker: &Worker) -> Agent {
    let instance = ApplicationInstanceId::new(Uuid::from_bytes([2; 16]));
    let process = || ProcessStartIdentity::new(41, ProcessStartSource::MacosProcBsdInfo, 900);
    let executable = Digest256::from_bytes([3; 32]);
    let package = tempfile::tempdir().expect("a directory for the package");
    let mut source = fixture::package(
        package.path(),
        Path::new(fixture::FORWARDER),
        &fixture::Shape::codex_backend_answering(),
    )
    .expect("the package is written");
    source.qualified = vec![QualifiedExecutable {
        digest: executable,
        version: fixture::GATEWAY_QUALIFIED_VERSION.to_owned(),
    }];
    let connector = InstalledConnector::read(source.clone()).expect("the package is read");
    let broker = worker.service.broker();
    let frame = testing::admit(
        &Admissions::new(),
        &ConnectorSources::new(),
        broker,
        vec![testing::admitted(&source)],
        1,
    );
    broker
        .register_instance(
            instance,
            IntegrationMode::Gateway,
            None,
            Some(ManagedProcess::new(
                instance,
                process(),
                TransportHandle {
                    transport: BrokerTransport::PrivateSocket,
                    application_instance_id: instance,
                    executable_digest: executable,
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
            instance,
            source.package_digest,
            frame,
            MatchedExecutable {
                path: "/usr/local/bin/codex".to_owned(),
                digest: executable,
            },
            AGENT_NOW,
        )
        .expect("the package is bound");
    broker
        .withhold_thread(instance)
        .expect("the instance withholds its thread");
    let tables = broker
        .pin_compiled(instance, &connector, &executable)
        .expect("the compiled tables are pinned");
    let connection = broker
        .open_native_connection(
            instance,
            &[9; 32],
            &process(),
            &connector.plugin_id(),
            &tables.protocol_version,
        )
        .expect("a native connection opens");
    let (upstream_here, upstream) = tokio::io::duplex(1 << 20);
    let (client_here, client) = tokio::io::duplex(1 << 20);
    let (owner, writes) = Duplex::new(
        Arc::clone(broker),
        connection,
        Framing::new(NativeFraming::JsonLines),
        upstream_here,
        client_here,
        EnvironmentId::new(Uuid::from_bytes([4; 16])),
        "agent-user",
    );
    let dispatch = owner.dispatch().expect("the connection has a dispatch");
    broker.bind_connection_dispatch(connection, dispatch.clone());
    broker
        .bind_dispatch(instance, dispatch)
        .expect("the instance has a transport");
    Agent {
        owner,
        upstream,
        _client: client,
        writes: tokio::spawn(writes),
        _package: package,
    }
}

impl Agent {
    /// The server says something of its own, as the broker receives it from the application.
    async fn says(&self, frame: &str) {
        tokio::time::timeout(REACH, self.owner.from_upstream(frame.as_bytes(), AGENT_NOW))
            .await
            .unwrap_or_else(|_| panic!("the frame was not carried within {REACH:?}"))
            .expect("the frame is carried");
    }

    /// The terminal selects a thread and the server answers, so that the binding names it.
    async fn selects_a_thread(&mut self) {
        let selecting = match self
            .owner
            .from_client(AGENT_START.as_bytes(), AGENT_NOW)
            .await
            .expect("the request is carried")
        {
            Carried::ClientRequest {
                upstream_request_id,
                ..
            } => upstream_request_id,
            other => panic!("not a request of the terminal's: {other:?}"),
        };
        self.reads_a_line().await;
        self.says(&format!(
            r#"{{"id":{},"result":{{"thread":{{"id":"thread-1"}}}}}}"#,
            selecting.as_str()
        ))
        .await;
    }

    async fn reads_a_line(&mut self) {
        let mut byte = [0_u8; 1];
        loop {
            self.upstream.read_exact(&mut byte).await.expect("a byte");
            if byte[0] == b'\n' {
                return;
            }
        }
    }
}

/// A turn that the scan counted ends inside a hold, and none follows. The worker says that nothing
/// is happening, which is true; the host keeps its count until the hold ends, as it does when a
/// hold keeps the worker from answering at all, and counts the truth after.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_turn_that_ends_in_the_hold_keeps_the_count_until_the_hold_ends() {
    let rig = Rig::start().await;
    rig.agent.says(TURN_7_STARTED).await;
    rig.counts_become(BUSY, "the scan sees the turn").await;
    let release = rig.hold_the_session("the turn ends in the hold").await;
    rig.agent.says(TURN_7_ENDED).await;
    rig.domain_state_becomes(Some(ApplicationState::ShellReady), "the turn ended")
        .await;
    rig.counts_stay(BUSY, "after the turn ended").await;
    let _ = release.send(());
    rig.counts_become(IDLE, "after the hold ended").await;
}

/// A turn that the scan counted ends and a new one starts inside one hold. The host counts the
/// agent at work all through, and still does once the hold has ended.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_turn_that_ends_and_a_new_one_that_starts_in_one_hold_keep_the_count() {
    let rig = Rig::start().await;
    rig.agent.says(TURN_7_STARTED).await;
    rig.counts_become(BUSY, "the scan sees the turn").await;
    let release = rig.hold_the_session("one hold").await;
    rig.agent.says(TURN_7_ENDED).await;
    rig.domain_state_becomes(Some(ApplicationState::ShellReady), "the first turn ended")
        .await;
    rig.counts_stay(BUSY, "between the turns").await;
    rig.agent.says(TURN_8_STARTED).await;
    rig.domain_state_becomes(Some(ApplicationState::AgentBusy), "the second turn")
        .await;
    rig.counts_stay(BUSY, "under the second turn").await;
    let _ = release.send(());
    rig.counts_become(BUSY, "after the hold ended").await;
}

/// The scan counted nothing, and a turn starts inside a hold: a held answer RAISES the count,
/// which is what the landing adds to what main does (main's read does not return, and its count
/// stays where it was).
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_turn_that_starts_in_a_hold_after_a_scan_that_saw_no_demand_raises_the_count() {
    let rig = Rig::start().await;
    rig.counts_become(IDLE, "the scan sees nothing").await;
    let release = rig.hold_the_session("the turn starts in the hold").await;
    rig.agent.says(TURN_7_STARTED).await;
    rig.counts_become(BUSY, "the held answer says the turn")
        .await;
    rig.counts_stay(BUSY, "while the hold stands").await;
    let _ = release.send(());
    rig.counts_become(BUSY, "after the hold ended").await;
}

/// A turn that the scan counted ends inside a hold, and a broker commit then stands before the
/// next turn starts: the new frame and the loop's read both wait for the broker's lock, so the
/// worker's answers say what the loop recorded last, which is that nothing is happening, while a
/// turn runs. The host keeps counting the agent at work.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_turn_that_starts_behind_a_stalled_broker_commit_keeps_the_count() {
    let rig = Rig::start().await;
    rig.agent.says(TURN_7_STARTED).await;
    rig.counts_become(BUSY, "the scan sees the turn").await;
    let release = rig
        .hold_the_session("the broker commit stands in the hold")
        .await;
    rig.agent.says(TURN_7_ENDED).await;
    rig.domain_state_becomes(Some(ApplicationState::ShellReady), "the turn ended")
        .await;
    let (stood, let_go) = rig.worker().service.broker().hold_the_state();
    tokio::time::timeout(REACH, stood)
        .await
        .expect("the broker's lock was held within a bound")
        .expect("the hold was dropped before it was reached");
    // The next turn starts, and its frame waits for the lock on a task of its own: the case does
    // not wait for it.
    let owner = Arc::clone(&rig.agent.owner);
    let starting = tokio::spawn(async move {
        owner
            .from_upstream(TURN_8_STARTED.as_bytes(), AGENT_NOW)
            .await
    });
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        !starting.is_finished(),
        "the new turn's frame was carried while the broker's lock was held"
    );
    assert_eq!(
        rig.domain_state(),
        Some(ApplicationState::ShellReady),
        "the worker's domain says what the loop recorded before the broker stood"
    );
    rig.counts_stay(BUSY, "while a turn runs behind the broker's commit")
        .await;
    let _ = let_go.send(());
    starting
        .await
        .expect("the frame's task ended")
        .expect("the frame is carried once the lock is let go");
    let _ = release.send(());
    rig.counts_become(BUSY, "after the commit and the hold ended")
        .await;
}

/// Two questions are open and the scan counted them. A storage call holds the session by a write
/// transaction in the file that the question ledger shares, one question runs out of time, and
/// the ledger's expiry write fails after its busy wait. The other question stays open, so the
/// host keeps counting a request waiting for a person.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_question_whose_expiry_write_fails_beside_one_that_stays_open_keeps_the_count() {
    let rig = Rig::start().await;
    let worker = rig.worker();
    let ask = |request: &str, expiry_ms: Option<u64>| {
        worker
            .service
            .questions()
            .create(
                &kr_worker::questions::VerifiedSource {
                    process: kr_ipc::identity::current_process_start_identity()
                        .expect("a process identity"),
                    executable: Some("/bin/agent".to_owned()),
                    session_member: true,
                    ancestry: true,
                    launch_channel: true,
                    connection_id: ConnectionId::new(kr_ipc::new_uuid()),
                },
                &kr_protocol::question::QuestionCreateParams {
                    session_id: worker.session_id,
                    request_id: request.to_owned(),
                    agent_name: Nullable::some("an agent".to_owned()),
                    context: "the release is tagged".to_owned(),
                    question: format!("Publish the release ({request})?"),
                    kind: kr_protocol::question::QuestionKind::Confirm,
                    choices: Vec::new(),
                    requested_expiry_ms: expiry_ms.map_or_else(Nullable::null, |ms| {
                        Nullable::some(kr_protocol::scalars::DurationMs::new(ms))
                    }),
                    wait_ms: Nullable::null(),
                },
                kr_worker::questions::Now {
                    utc_ms: kr_ipc::now_ms(),
                    boot_ms: kr_ipc::clock::boot_elapsed_ms(),
                },
            )
            .expect("a verified source asks");
    };
    ask("short", Some(4_000));
    ask("long", None);
    rig.counts_become(ASKED, "the scan sees the questions")
        .await;
    // The maintenance pass's prune stands inside an open write transaction, which holds the
    // session and the file's one write lock.
    let (arrived, release) = {
        let mut session = worker.runtime().session();
        let journal = session.journal_mut().expect("this session keeps a journal");
        journal.stall_next_prune_blocking()
    };
    let service = Arc::clone(&worker.service);
    let pass = tokio::spawn(async move { service.maintain_now() });
    tokio::time::timeout(REACH, arrived)
        .await
        .expect("the prune reached its stall within a bound")
        .expect("the stall was dropped before it was reached");
    assert!(
        rig.the_worker_answers_held().await,
        "the worker did not give a held answer while the prune stood"
    );
    // The short question runs out of time while the hold stands, and the loop's wake asks the
    // ledger's reader, whose expiry write meets the write lock and fails after its busy wait.
    tokio::time::sleep(Duration::from_secs(5)).await;
    rig.agent.says(TURN_7_STARTED).await;
    rig.agent.says(TURN_7_ENDED).await;
    rig.counts_stay(ASKED, "after the ledger's expiry write failed")
        .await;
    let _ = release.send(());
    pass.await.expect("the maintenance pass ended");
    rig.counts_become(ASKED, "after the hold ended: the long question is open")
        .await;
}
