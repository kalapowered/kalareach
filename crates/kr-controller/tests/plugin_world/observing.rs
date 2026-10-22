//! The world the plugin observation suite shares: a real daemon, a real worker service with a real
//! broker, journal and pseudo-terminal session, a real plugin host started by the daemon, and the
//! worker's own link and pump registering and feeding the components of several bindings.
//!
//! Two things are played. The upstream is a scripted peer behind the production gateway
//! transport: it records what the worker writes, answers a request of the native terminal, and
//! sends whatever frame a case asks it to. The native terminal is the other end of that transport:
//! it reads every frame the worker forwards to it, all the time, and writes a request on demand.
//! Everything between them is the product.
//!
//! The components are `recording`, which keeps an account of what it was offered and returns it as
//! its checkpoint, so that a case reads what a component received through the link's own client;
//! or any other fixture a case names.

#![allow(
    dead_code,
    reason = "each suite that includes this world uses the part of it that it needs"
)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use kr_plugin_service::vocabulary::BindingId;
use kr_protocol::broker::{BrokerGrant, BrokerGrants, DecodingTrust, IntegrationMode};
use kr_protocol::identity::{ProcessStartIdentity, ProcessStartSource};
use kr_protocol::ids::{
    ActionId, ApplicationInstanceId, BrokerBindingId, PendingResourceId, PluginId, PublisherId,
    QuestionId, UpstreamMethod,
};
use kr_protocol::scalars::{Digest256, Nullable, TimestampMs, U64, Uuid};
use kr_worker::broker::binder::Streams;
use kr_worker::broker::{
    BrokerTransport, Credential, ManagedProcess, TransportHandle, UpstreamDispatch,
};
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _};

use super::acting::{installed, rich};
use super::{Epoch, Hosted, PATIENCE, component, hosted_running, until};

/// The instance every binding here observes.
pub fn instance() -> ApplicationInstanceId {
    ApplicationInstanceId::new(Uuid::from_bytes([2; 16]))
}

/// The package whose table the connection reads.
pub fn package() -> PluginId {
    PluginId::new("kalareach.codex").expect("a plugin identifier")
}

/// Another package, whose bindings are on the same instance and are not offered this connection's
/// frames.
pub fn other_package() -> PluginId {
    PluginId::new("kalareach.other").expect("a plugin identifier")
}

/// The binding made with `number`.
pub fn binding(number: u8) -> BrokerBindingId {
    BrokerBindingId::new(Uuid::from_bytes([100 + number; 16]))
}

/// The runtime's name for it.
pub fn service_id(number: u8) -> BindingId {
    BindingId::new(binding(number).get())
}

/// One binding to make.
#[derive(Clone, Debug)]
pub struct Spec {
    /// Its number, which names it.
    pub number: u8,
    /// The package it runs: the connection's own, or another.
    pub own_package: bool,
    /// The streams its installation lets its component be offered.
    pub streams: Streams,
    /// Whether it holds the `Observation` grant.
    pub observation: bool,
    /// The component it ships, where it ships one.
    pub component: Option<&'static str>,
    /// Whether it holds the approval interpreter's grant and the trust to decode the connector's
    /// approval request.
    pub interpreting: bool,
}

impl Spec {
    /// A binding of the connection's own package granted both streams, with the recording
    /// component.
    pub fn observer(number: u8) -> Self {
        Self {
            number,
            own_package: true,
            streams: Streams {
                semantic: true,
                terminal: true,
            },
            observation: true,
            component: Some("recording"),
            interpreting: false,
        }
    }

    /// A binding of the connection's own package that reads the connector's approval request into
    /// an approval a person answers, and ships no component.
    pub fn interpreter(number: u8) -> Self {
        Self {
            number,
            own_package: true,
            streams: Streams {
                semantic: false,
                terminal: false,
            },
            observation: false,
            component: None,
            interpreting: true,
        }
    }

    /// The same, granted the connector's own frames only.
    pub fn semantic_only(number: u8) -> Self {
        Self {
            streams: Streams {
                semantic: true,
                terminal: false,
            },
            ..Self::observer(number)
        }
    }

    /// The same, granted the terminal's output only.
    pub fn terminal_only(number: u8) -> Self {
        Self {
            streams: Streams {
                semantic: false,
                terminal: true,
            },
            ..Self::observer(number)
        }
    }

    /// With another component.
    #[must_use]
    pub const fn shipping(mut self, component: &'static str) -> Self {
        self.component = Some(component);
        self
    }

    /// Of another package.
    #[must_use]
    pub const fn of_another_package(mut self) -> Self {
        self.own_package = false;
        self
    }

    /// Holding the grant and no stream.
    #[must_use]
    pub const fn without_a_stream(mut self) -> Self {
        self.streams = Streams {
            semantic: false,
            terminal: false,
        };
        self
    }
}

/// What a case starts the world with.
#[derive(Clone, Debug)]
pub struct Options {
    /// Whether the plugin host's epoch runs or is held.
    pub epoch: Epoch,
    /// The command the session runs.
    pub shell: String,
    /// The bindings to make.
    pub bindings: Vec<Spec>,
}

impl Options {
    /// Held epoch, a shell that waits, and these bindings.
    pub fn with(bindings: Vec<Spec>) -> Self {
        Self {
            epoch: Epoch::Held,
            shell: "exec cat".to_owned(),
            bindings,
        }
    }
}

/// What a `recording` component says it was offered.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Account {
    /// Times `bind` ran.
    pub binds: u64,
    /// Events observed.
    pub observes: u64,
    /// Snapshots taken.
    pub snapshots: u64,
    /// Restores.
    pub restores: u64,
    /// The last eight events, oldest first.
    pub seen: Vec<Seen>,
    /// The identifiers of the last thirty-two requests offered, oldest first.
    pub requests: Vec<String>,
}

/// One event a component observed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Seen {
    /// Where it came from, in the SDK's words.
    pub provenance: String,
    /// The request identifier it carried, or `-`.
    pub request: String,
    /// How many bytes it held.
    pub len: usize,
    /// The digest of its bytes (FNV-1a, 64 bits).
    pub digest: u64,
}

impl Account {
    fn parse(text: &str) -> Self {
        let mut account = Self::default();
        for part in text.split(';') {
            let Some((key, value)) = part.split_once('=') else {
                continue;
            };
            let count = || value.parse::<u64>().unwrap_or(0);
            match key {
                "bind" => account.binds = count(),
                "observe" => account.observes = count(),
                "snapshot" => account.snapshots = count(),
                "restore" => account.restores = count(),
                "seen" => {
                    account.seen = value
                        .split('|')
                        .filter(|item| !item.is_empty())
                        .filter_map(|item| {
                            let mut fields = item.split('/');
                            Some(Seen {
                                provenance: fields.next()?.to_owned(),
                                request: fields.next()?.to_owned(),
                                len: fields.next()?.parse().ok()?,
                                digest: u64::from_str_radix(fields.next()?, 16).ok()?,
                            })
                        })
                        .collect();
                }
                "requests" => {
                    account.requests = value
                        .split('|')
                        .filter(|item| !item.is_empty())
                        .map(str::to_owned)
                        .collect();
                }
                _ => {}
            }
        }
        account
    }
}

/// The digest `recording` computes of an event's bytes.
pub fn digest(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    hash
}

/// The native terminal's end of the production transport.
pub struct Terminal {
    lines: Mutex<Vec<String>>,
    arrived: tokio::sync::Notify,
    writes: tokio::sync::Mutex<tokio::io::WriteHalf<tokio::net::UnixStream>>,
}

impl Terminal {
    /// Every line the worker has forwarded to the terminal, in order.
    pub fn lines(&self) -> Vec<String> {
        self.lines.lock().expect("not poisoned").clone()
    }

    /// Writes one frame as the native terminal, which a response to the upstream's request is.
    ///
    /// # Panics
    ///
    /// Panics when the frame cannot be written.
    pub async fn write(&self, frame: &serde_json::Value) {
        self.writes
            .lock()
            .await
            .write_all(format!("{frame}\n").as_bytes())
            .await
            .expect("the terminal writes its frame");
    }

    /// Writes one request of the terminal's own and waits for the reply to it.
    ///
    /// # Panics
    ///
    /// Panics when the reply does not come back.
    pub async fn round_trip(&self, id: u64) {
        let request = format!("{{\"id\":{id},\"method\":\"session/prompt\",\"params\":{{}}}}\n");
        self.writes
            .lock()
            .await
            .write_all(request.as_bytes())
            .await
            .expect("the terminal writes its request");
        let wanted = format!("\"id\":{id},\"result\"");
        until("the reply to the terminal's request", || async {
            self.lines()
                .iter()
                .any(|line| line.contains(&wanted))
                .then_some(())
        })
        .await;
    }
}

/// The world.
pub struct Observing {
    pub hosted: Hosted,
    /// What a case sends the worker as the upstream.
    sender: tokio::sync::mpsc::UnboundedSender<String>,
    /// What the worker forwards to the native terminal.
    pub terminal: Arc<Terminal>,
    /// The frames the worker wrote to the upstream.
    pub written: Arc<Mutex<Vec<String>>>,
    _owner: Arc<kr_worker::broker::Duplex>,
    _tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Observing {
    /// Starts the world, or returns `None` when the test components are not built.
    pub async fn start(options: Options) -> Option<Self> {
        let mut components = Vec::new();
        for name in options.bindings.iter().filter_map(|spec| spec.component) {
            if !components.contains(&name) {
                components.push(name);
            }
        }
        let mut installed_components = Vec::new();
        let hosted = hosted_running(options.epoch, None, &options.shell).await;
        for name in &components {
            let wasm = component(name)?;
            installed_components.push((*name, install_named(&hosted, name, &wasm)));
        }
        let broker = hosted._service.broker();
        let process = ProcessStartIdentity::new(41, ProcessStartSource::MacosProcBsdInfo, 900);
        broker
            .register_instance(
                instance(),
                IntegrationMode::Gateway,
                None,
                Some(ManagedProcess::new(
                    instance(),
                    process.clone(),
                    TransportHandle {
                        transport: BrokerTransport::PrivateSocket,
                        application_instance_id: instance(),
                        executable_digest: Digest256::from_bytes([3; 32]),
                        process: process.clone(),
                    },
                    Credential::from_bytes([9; 32]),
                    TimestampMs::new(1),
                )),
            )
            .expect("the instance is registered");

        for spec in &options.bindings {
            let (plugin, digest_byte) = if spec.own_package {
                (package(), 5)
            } else {
                (other_package(), 6)
            };
            let mut grants = Vec::new();
            if spec.observation {
                grants.push(BrokerGrant::Observation);
            }
            if spec.interpreting {
                grants.push(BrokerGrant::ApprovalInterpreter);
            }
            let trust = spec.interpreting.then(|| DecodingTrust {
                plugin_id: plugin.clone(),
                publisher_id: PublisherId::new("kalareach").expect("a publisher"),
                package_digest: Digest256::from_bytes([digest_byte; 32]),
                methods: [UpstreamMethod::new("session/request_permission").expect("a method")]
                    .into_iter()
                    .collect(),
                schema_versions: [kr_worker::broker::connectors::DECISION_SCHEMA.to_owned()]
                    .into_iter()
                    .collect(),
                max_decisions: U64::new(4),
                may_encode_response: true,
                granted_at: TimestampMs::new(1),
            });
            broker
                .bind_descriptor(
                    binding(spec.number),
                    instance(),
                    plugin.clone(),
                    PublisherId::new("kalareach").expect("a publisher"),
                    Digest256::from_bytes([digest_byte; 32]),
                    BrokerGrants::granted(grants),
                    trust,
                    TimestampMs::new(1),
                )
                .expect("the binding is recorded");
            broker
                .grant_streams(binding(spec.number), spec.streams)
                .expect("the streams are granted");
            let Some(name) = spec.component else {
                continue;
            };
            let source = &installed_components
                .iter()
                .find(|(installed, _)| *installed == name)
                .expect("the component was installed")
                .1;
            broker
                .ship_component(
                    binding(spec.number),
                    kr_protocol::admission::LiveRelease {
                        plugin_id: plugin,
                        publisher_id: PublisherId::new("kalareach").expect("a publisher"),
                        version: "1.0.0".to_owned(),
                        package_digest: Digest256::from_bytes([digest_byte; 32]),
                        origin: kr_protocol::admission::ReleaseOrigin {
                            repository_id: "official".to_owned(),
                            enrolment_key: "test".to_owned(),
                        },
                    },
                    kr_worker::broker::ledger::BoundExecutable {
                        path: "/bin/sh".to_owned(),
                        digest: Digest256::from_bytes([3; 32]),
                        version: None,
                    },
                    kr_worker::broker::component::BoundComponent {
                        path: source.path.clone(),
                        digest: Digest256::from_bytes(*source.digest.as_bytes()),
                        bytes: source.bytes,
                        refusal: None,
                    },
                )
                .expect("the binding ships its component");
        }

        // The production transport over two socket pairs: the upstream's, which a case sends
        // frames into and which answers the terminal's requests, and the native terminal's, which
        // collects every frame the worker forwards to it.
        broker
            .pin_table(instance(), installed(), table(), rich())
            .expect("the installed tables are pinned");
        broker
            .pin_reading(instance(), &package(), reading())
            .expect("the reading is pinned");
        broker
            .open_native_connection(instance(), &[9; 32], &process, &package(), "1")
            .expect("the native connection is authenticated");
        let (here, there) = tokio::net::UnixStream::pair().expect("a socket pair");
        let (upstream_reads, upstream_writes) = tokio::io::split(here);
        let (client_here, client_there) = tokio::net::UnixStream::pair().expect("a socket pair");
        let (client_reads, client_writes) = tokio::io::split(client_here);
        let (owner, writes) = kr_worker::broker::Duplex::new(
            Arc::clone(broker),
            kr_protocol::ids::GatewayConnectionId::new(1),
            kr_worker::broker::Framing::new(kr_protocol::gateway::NativeFraming::JsonLines),
            upstream_writes,
            client_writes,
            hosted.environment_id,
            "agent-user",
        );
        broker
            .bind_dispatch(
                instance(),
                owner.dispatch().expect("it carries operations") as Arc<dyn UpstreamDispatch>,
            )
            .expect("the transport is bound");
        let written = Arc::new(Mutex::new(Vec::new()));
        let (sender, injected) = tokio::sync::mpsc::unbounded_channel();
        let mut tasks = vec![
            tokio::spawn(upstream(there, Arc::clone(&written), injected)),
            tokio::spawn(writes),
            tokio::spawn({
                let owner = Arc::clone(&owner);
                async move { owner.serve(upstream_reads, true).await }
            }),
            tokio::spawn({
                let owner = Arc::clone(&owner);
                async move { owner.serve(client_reads, false).await }
            }),
        ];
        let (reads, terminal_writes) = tokio::io::split(client_there);
        let terminal = Arc::new(Terminal {
            lines: Mutex::new(Vec::new()),
            arrived: tokio::sync::Notify::new(),
            writes: tokio::sync::Mutex::new(terminal_writes),
        });
        tasks.push(tokio::spawn({
            let terminal = Arc::clone(&terminal);
            async move {
                let mut lines = tokio::io::BufReader::new(reads).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    terminal.lines.lock().expect("not poisoned").push(line);
                    terminal.arrived.notify_waiters();
                }
            }
        }));
        // The worker's own link asks the daemon for the plugin runtime, registers each component
        // and feeds it, as it does for a package a person installed.
        tasks.push(tokio::spawn(kr_worker::plugin_runtime::link(
            kr_worker::plugin_runtime::RuntimeRequest {
                session_id: hosted.session_id,
                rendezvous: hosted
                    .environment()
                    .rendezvous_endpoint()
                    .expect("an endpoint")
                    .as_path()
                    .to_path_buf(),
                environment: hosted.environment(),
            },
            Arc::downgrade(broker),
        )));
        Some(Self {
            hosted,
            sender,
            terminal,
            written,
            _owner: owner,
            _tasks: tasks,
        })
    }

    /// The broker.
    pub fn broker(&self) -> &Arc<kr_worker::broker::Broker> {
        self.hosted._service.broker()
    }

    /// Sends the worker one frame, as the upstream.
    pub fn send(&self, frame: &serde_json::Value) {
        self.sender
            .send(frame.to_string())
            .expect("the upstream is running");
    }

    /// Everything the session has retained of the terminal's output, as text.
    pub fn output(&self) -> String {
        let session = self.hosted._runtime.session();
        let mut seen = Vec::new();
        let mut cursor = 0_u64;
        while let Ok(page) = session.history_page(cursor, 1024 * 1024) {
            if page.bytes.as_slice().is_empty() {
                break;
            }
            seen.extend_from_slice(page.bytes.as_slice());
            cursor = page.next_cursor.get();
        }
        String::from_utf8_lossy(&seen).into_owned()
    }

    /// Waits until a binding is registered and ready to be offered observations.
    pub async fn until_ready(&self, number: u8) {
        let lane = self.broker().observation();
        until("the binding to be ready", || async {
            lane.is_ready(binding(number)).then_some(())
        })
        .await;
    }

    /// Asks a `recording` component what it was offered, through the link's own connection.
    pub async fn account(&self, number: u8) -> Option<Account> {
        let client = self.broker().component_calls().client()?;
        let called = client
            .checkpoint(service_id(number), Duration::from_secs(5))
            .await
            .ok()?;
        let state = called.state?;
        Some(Account::parse(&String::from_utf8_lossy(&state)))
    }

    /// Waits until a component's account satisfies `wanted`, and returns it.
    pub async fn until_account(
        &self,
        number: u8,
        what: &str,
        wanted: impl Fn(&Account) -> bool,
    ) -> Account {
        until(what, || async {
            self.account(number).await.filter(|account| wanted(account))
        })
        .await
    }

    /// What a person is told of a binding's component.
    pub fn report(&self, number: u8) -> Option<kr_protocol::admission::ComponentReport> {
        self.broker()
            .live_bindings()
            .into_iter()
            .find(|live| live.binding_id == binding(number))
            .and_then(|live| live.component.0)
    }

    /// The reason a binding's component report gives, or empty.
    pub fn reason(&self, number: u8) -> String {
        self.report(number)
            .and_then(|report| report.reason.0)
            .unwrap_or_default()
    }

    /// Waits until the reason a binding's report gives contains `part`, and returns it.
    ///
    /// # Panics
    ///
    /// Panics, saying where the binding stands, when the report never says it.
    pub async fn until_reason(&self, number: u8, part: &str) -> String {
        let said = tokio::time::timeout(PATIENCE, async {
            loop {
                let reason = self.reason(number);
                if reason.contains(part) {
                    return reason;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await;
        match said {
            Ok(reason) => reason,
            Err(_) => panic!(
                "waited {PATIENCE:?} for the report to say {part:?}; it says {:?}, the binding is \
                 {:?}; {}",
                self.reason(number),
                self.broker().rich_disabled(binding(number)),
                self.diagnostics(number)
            ),
        }
    }

    /// Waits until the lane holds a state for a binding that says `part`, and returns it.
    pub async fn until_held(&self, number: u8, part: &str) -> String {
        let lane = self.broker().observation();
        until(
            &format!("the state held for the component to say {part:?}"),
            || async {
                let state =
                    String::from_utf8_lossy(&lane.held_state(binding(number))?).into_owned();
                state.contains(part).then_some(state)
            },
        )
        .await
    }

    /// What a failing case needs to see of the lane, the client and the terminal.
    pub fn diagnostics(&self, number: u8) -> String {
        let lane = self.broker().observation();
        let output = self.output();
        let tail: String = output
            .chars()
            .rev()
            .take(160)
            .collect::<String>()
            .chars()
            .rev()
            .collect();
        format!(
            "lane: {:?}, held {} bytes, {} waiting, {} in flight; view: {:?}; client hand-off: \
             {:?} bytes; report: {:?}; output is {} bytes, highest line {:?}, ends {tail:?}",
            lane.account(),
            lane.held_bytes(),
            lane.waiting(),
            lane.in_flight(),
            lane.view(binding(number)),
            self.broker()
                .component_calls()
                .client()
                .map(|client| client.offered_bytes()),
            self.reason(number),
            output.len(),
            highest_line(&output),
        )
    }

    // -- what the worker holds live, as a person reads it ----------------------------------------

    /// The local owner, on the worker's own socket.
    pub async fn owner(&self) -> kr_ipc::client::LocalClient {
        kr_ipc::client::LocalClient::connect(
            &self.hosted.endpoint,
            kr_protocol::local::LocalClientKind::Cli,
            super::build(),
        )
        .await
        .expect("the owner connects to the worker")
    }

    /// What a call to the session is addressed to.
    pub fn target(&self) -> kr_protocol::envelope::ActionTarget {
        kr_protocol::envelope::ActionTarget {
            environment_id: self.hosted.environment_id,
            session_id: Nullable::some(self.hosted.session_id),
            session_epoch: Nullable::some(kr_protocol::ids::SessionEpoch::V1),
            application_instance_id: Nullable::null(),
            agent_binding_revision: Nullable::null(),
        }
    }

    /// Attaches the owner's terminal to the session, which leaves a receipt.
    pub async fn attach(&self, window: &mut kr_ipc::client::LocalClient) -> ActionId {
        let action_id = ActionId::new(kr_ipc::new_uuid());
        let params = kr_protocol::attachment::SessionAttachParams {
            session_id: self.hosted.session_id,
            mode: kr_protocol::attachment::AttachMode::Terminal,
            claim_geometry: false,
            dimensions: Nullable::some(kr_protocol::session::Dimensions::new(80, 24)),
            terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
            requested: [kr_protocol::attachment::AttachmentCapability::ObserveTerminal]
                .into_iter()
                .collect(),
        };
        window
            .mutate(
                kr_protocol::method::Method::SessionAttach,
                action_id,
                self.target(),
                &params,
            )
            .await
            .expect("the call reaches the worker")
            .expect("the attach is admitted");
        action_id
    }

    /// The agent in the session asks a person a question, which is pending in the worker's ledger.
    pub fn ask(&self) -> (QuestionId, kr_protocol::question::CallerToken) {
        let (asked, _) = self
            .hosted
            ._service
            .questions()
            .create(
                &asker(),
                &kr_protocol::question::QuestionCreateParams {
                    session_id: self.hosted.session_id,
                    request_id: "push-anyway".to_owned(),
                    kind: kr_protocol::question::QuestionKind::Confirm,
                    context: "Two tests are failing.".to_owned(),
                    question: "Push the branch anyway?".to_owned(),
                    choices: Vec::new(),
                    agent_name: Nullable::some("kr-test-agent".to_owned()),
                    requested_expiry_ms: Nullable::some(kr_protocol::scalars::DurationMs::new(
                        600_000,
                    )),
                    wait_ms: Nullable::null(),
                },
                now(),
            )
            .expect("the agent asks");
        assert_eq!(
            asked.question.state,
            kr_protocol::question::QuestionState::Pending
        );
        (asked.question.question_id, asked.caller_token)
    }

    /// What the agent that asked reads back about its question.
    pub fn read_back(
        &self,
        question_id: QuestionId,
        caller_token: kr_protocol::question::CallerToken,
    ) -> kr_protocol::question::Question {
        self.hosted
            ._service
            .questions()
            .read_own(
                &asker(),
                &kr_protocol::question::QuestionReadOwnParams {
                    session_id: self.hosted.session_id,
                    question_id,
                    caller_token,
                    wait_ms: Nullable::null(),
                },
                now(),
            )
            .expect("the agent reads its own question")
            .0
            .question
    }

    /// The receipt, the question and the approval the worker holds, as the owner reads them.
    pub async fn live(
        &self,
        window: &mut kr_ipc::client::LocalClient,
        action_id: ActionId,
        question_id: QuestionId,
        approval: PendingResourceId,
    ) -> Live {
        use kr_protocol::method::Method;
        let receipt: kr_protocol::receipt::ActionReadResult = read(
            window,
            Method::ActionRead,
            &kr_protocol::receipt::ActionReadParams {
                action_id,
                session_id: None,
            },
        )
        .await;
        let questions: kr_protocol::question::QuestionReadResult = read(
            window,
            Method::QuestionRead,
            &kr_protocol::question::QuestionReadParams {
                session_id: self.hosted.session_id,
                question_id: Nullable::some(question_id),
                include_resolved: true,
            },
        )
        .await;
        let snapshot: kr_protocol::recovery::EventsSnapshotResult = read(
            window,
            Method::EventsSnapshot,
            &kr_protocol::recovery::EventsSnapshotParams {
                session_id: self.hosted.session_id,
                agent_resources_from: Nullable::null(),
            },
        )
        .await;
        Live {
            receipt: receipt.receipt,
            question: questions
                .questions
                .into_iter()
                .find(|question| question.question_id == question_id)
                .expect("the question is read"),
            approval: snapshot
                .agent_resources
                .resources
                .into_iter()
                .find(|resource| resource.resource_id == approval),
        }
    }

    /// The owner answers the question yes.
    pub async fn answer_yes(
        &self,
        window: &mut kr_ipc::client::LocalClient,
        question: &kr_protocol::question::Question,
    ) -> kr_protocol::question::QuestionResolveResult {
        window
            .mutate(
                kr_protocol::method::Method::QuestionAnswer,
                ActionId::new(kr_ipc::new_uuid()),
                self.target(),
                &kr_protocol::question::QuestionAnswerParams {
                    session_id: self.hosted.session_id,
                    question_id: question.question_id,
                    expected_revision: question.revision,
                    answer: kr_protocol::question::QuestionAnswer::Decision { decided: true },
                },
            )
            .await
            .expect("the call reaches the worker")
            .expect("the owner answers")
            .to_typed()
            .expect("decodes")
    }

    /// Tells the session its privacy generation on the daemon's authority connection, as the
    /// daemon does, and returns once the worker has answered.
    pub async fn tell_privacy(
        &self,
        authority: &mut kr_ipc::client::BoundLink,
        generation: u64,
        enabled: bool,
    ) {
        use kr_protocol::envelope::ControlFrame;
        authority
            .send(&ControlFrame::PrivacyGeneration(
                kr_protocol::privacy::PrivacyGenerationNotice {
                    environment_id: self.hosted.environment_id,
                    generation: U64::new(generation),
                    enabled,
                },
            ))
            .await
            .expect("writes the notice");
        let acknowledged = tokio::time::timeout(PATIENCE, async {
            loop {
                match authority.recv().await.expect("the worker answers") {
                    ControlFrame::PrivacyGenerationAck(ack) => return ack,
                    ControlFrame::Notification(_) | ControlFrame::Event(_) => {}
                    other => panic!("the worker answered {other:?}"),
                }
            }
        })
        .await
        .expect("the worker acknowledges the privacy generation in time");
        assert_eq!(acknowledged.generation.get(), generation);
    }
}

/// The receipt, the question and the approval the worker holds, as the owner reads them.
#[derive(Debug, PartialEq, Eq)]
pub struct Live {
    pub receipt: kr_protocol::receipt::Receipt,
    pub question: kr_protocol::question::Question,
    /// The approval, while the snapshot still holds it.
    pub approval: Option<kr_protocol::gateway::PendingResource>,
}

/// One read of the worker, by the owner.
async fn read<T: serde::Serialize, R: kr_protocol::wire::WireMessage>(
    window: &mut kr_ipc::client::LocalClient,
    method: kr_protocol::method::Method,
    params: &T,
) -> R {
    tokio::time::timeout(PATIENCE, window.request(method, params))
        .await
        .unwrap_or_else(|_| panic!("{} is answered within {PATIENCE:?}", method.as_str()))
        .expect("the call reaches the worker")
        .unwrap_or_else(|error| panic!("{} is answered: {error:?}", method.as_str()))
        .to_typed()
        .expect("decodes")
}

/// The agent in the session that asks, as the worker binds a helper: this process.
fn asker() -> kr_worker::questions::binding::VerifiedSource {
    kr_worker::questions::binding::VerifiedSource {
        process: kr_ipc::identity::current_process_start_identity().expect("a process identity"),
        executable: Some("kr-test-agent".to_owned()),
        session_member: true,
        ancestry: true,
        launch_channel: true,
        connection_id: kr_protocol::ids::ConnectionId::new(Uuid::from_bytes([3; 16])),
    }
}

fn now() -> kr_worker::questions::Now {
    kr_worker::questions::Now {
        utc_ms: kr_ipc::now_ms(),
        boot_ms: kr_ipc::clock::boot_elapsed_ms(),
    }
}

/// Puts a component where the daemon says components are, under a directory of its own, so that
/// bindings of several components can be registered side by side.
fn install_named(
    hosted: &Hosted,
    name: &str,
    wasm: &[u8],
) -> kr_plugin_service::protocol::ComponentSource {
    let store = hosted
        .environment()
        .state_dir()
        .join("catalogue")
        .join("repositories");
    let directory = store.join(format!("enrolment-{name}"));
    std::fs::create_dir_all(&directory).expect("a store directory");
    std::fs::write(directory.join("component.wasm"), wasm).expect("the component");
    kr_plugin_service::protocol::ComponentSource {
        path: format!("enrolment-{name}/component.wasm"),
        digest: kr_plugin_sdk::digest::PayloadDigest::of(wasm),
        bytes: wasm.len() as u64,
    }
}

/// The connector table the package ships: what the upstream and the terminal may send.
pub fn table() -> kr_protocol::gateway::DeclarativeTable {
    use kr_protocol::gateway::{DeclarativeEntry, NativeMethodClass};
    let entry = |method: &str, class, expects_response| DeclarativeEntry {
        method: kr_protocol::ids::UpstreamMethod::new(method).expect("valid"),
        class,
        expects_response,
        approval_option_field: Nullable::null(),
        reverse: Nullable::null(),
    };
    let mut table = kr_protocol::gateway::DeclarativeTable {
        plugin_id: package(),
        publisher_id: PublisherId::new("kalareach").expect("a publisher"),
        table_version: kr_protocol::ids::MethodTableVersion::new(1),
        upstream_protocol_version: "1".to_owned(),
        digest: Digest256::from_bytes([1; 32]),
        framing: kr_protocol::gateway::NativeFraming::JsonLines,
        request_id_field: "id".to_owned(),
        response_id_field: "id".to_owned(),
        method_field: "method".to_owned(),
        params_field: "params".to_owned(),
        result_field: "result".to_owned(),
        error_field: "error".to_owned(),
        // In the order of the method names, which a table's digest depends on.
        entries: vec![
            entry(
                "account/login",
                NativeMethodClass::CredentialOrConfiguration,
                true,
            ),
            entry("item/updated", NativeMethodClass::Observation, false),
            entry("session/prompt", NativeMethodClass::Mutation, true),
            entry(
                "session/request_permission",
                NativeMethodClass::Mutation,
                true,
            ),
        ],
    };
    table.digest = table.canonical_digest().expect("encodable");
    table
}

/// How the application reads the answer to an approval: the connector's decision response.
fn reading() -> kr_worker::broker::reading::Reading {
    let decision = |option: &str, label: &str| kr_protocol::broker::OfferedDecision {
        option_id: option.to_owned(),
        label: label.to_owned(),
    };
    let mut reading = kr_worker::broker::reading::Reading::spelling(&rich());
    reading.answers = Some(kr_worker::broker::reading::AnswerShape {
        methods: [UpstreamMethod::new("session/request_permission").expect("a method")]
            .into_iter()
            .collect(),
        result_member: "outcome".to_owned(),
        values: [("allow", "allow"), ("deny", "deny")]
            .into_iter()
            .map(|(decision, value)| (decision.to_owned(), value.to_owned()))
            .collect(),
        offered: vec![decision("allow", "Allow"), decision("deny", "Deny")],
    });
    reading
}

/// The frame of a notification the table lists, carrying `payload`.
pub fn notification(payload: &str) -> serde_json::Value {
    serde_json::json!({ "method": "item/updated", "params": { "payload": payload } })
}

/// The frame of a request the table lists, which the upstream is waiting on.
pub fn request(id: u64) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "method": "session/request_permission",
        "params": { "tool": "write" }
    })
}

/// The frame of a method the table lists as a credential.
pub fn credential(id: u64) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "method": "account/login",
        "params": { "token": "a-credential" }
    })
}

/// The frame of a method the table does not list.
pub fn unlisted() -> serde_json::Value {
    serde_json::json!({ "method": "thread/unlisted", "params": {} })
}

/// The scripted upstream: it records what the worker writes, answers the terminal's own requests,
/// and writes what a case sends.
async fn upstream(
    stream: tokio::net::UnixStream,
    written: Arc<Mutex<Vec<String>>>,
    mut injected: tokio::sync::mpsc::UnboundedReceiver<String>,
) {
    let (reader, mut writer) = tokio::io::split(stream);
    let mut lines = tokio::io::BufReader::new(reader).lines();
    loop {
        tokio::select! {
            sent = injected.recv() => {
                let Some(frame) = sent else {
                    return;
                };
                if writer.write_all(format!("{frame}\n").as_bytes()).await.is_err() {
                    return;
                }
            }
            read = lines.next_line() => {
                let Ok(Some(line)) = read else {
                    return;
                };
                let frame = serde_json::from_str::<serde_json::Value>(&line).ok();
                written.lock().expect("not poisoned").push(line);
                // A request of the terminal's own is answered; a response to the upstream's
                // request has no method and is only recorded.
                if let Some(frame) = frame
                    && frame.get("method").is_some()
                    && let Some(id) = frame.get("id")
                {
                    let reply = serde_json::json!({ "id": id, "result": { "ok": true } });
                    if writer.write_all(format!("{reply}\n").as_bytes()).await.is_err() {
                        return;
                    }
                }
            }
        }
    }
}

/// How long a case lets the daemon and the host settle before it gives up on a start.
pub const START_PATIENCE: Duration = PATIENCE;

/// The highest `kalareach-<n>` line in the terminal's output.
pub fn highest_line(text: &str) -> Option<u64> {
    text.match_indices("kalareach-")
        .filter_map(|(at, _)| {
            let rest = &text[at + "kalareach-".len()..];
            let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
            digits.parse::<u64>().ok()
        })
        .max()
}

/// How many questions of the shell's the terminal has answered.
pub fn answered(text: &str) -> usize {
    text.matches("answered-").count()
}
