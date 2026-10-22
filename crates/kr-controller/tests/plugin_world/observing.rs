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
use kr_protocol::broker::{BrokerGrant, BrokerGrants, IntegrationMode};
use kr_protocol::identity::{ProcessStartIdentity, ProcessStartSource};
use kr_protocol::ids::{ApplicationInstanceId, BrokerBindingId, PluginId, PublisherId};
use kr_protocol::scalars::{Digest256, Nullable, TimestampMs, Uuid};
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
    /// The component it ships.
    pub component: &'static str,
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
            component: "recording",
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
        self.component = component;
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
        for spec in &options.bindings {
            if !components.contains(&spec.component) {
                components.push(spec.component);
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
            let source = &installed_components
                .iter()
                .find(|(name, _)| *name == spec.component)
                .expect("the component was installed")
                .1;
            broker
                .bind_descriptor(
                    binding(spec.number),
                    instance(),
                    plugin.clone(),
                    PublisherId::new("kalareach").expect("a publisher"),
                    Digest256::from_bytes([digest_byte; 32]),
                    if spec.observation {
                        BrokerGrants::granted([BrokerGrant::Observation])
                    } else {
                        BrokerGrants::granted([])
                    },
                    None,
                    TimestampMs::new(1),
                )
                .expect("the binding is recorded");
            broker
                .grant_streams(binding(spec.number), spec.streams)
                .expect("the streams are granted");
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
            .pin_reading(
                instance(),
                &package(),
                kr_worker::broker::reading::Reading::spelling(&rich()),
            )
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
        loop {
            let Ok(page) = session.history_page(cursor, 1024 * 1024) else {
                break;
            };
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
    pub async fn until_reason(&self, number: u8, part: &str) -> String {
        until(&format!("the report to say {part:?}"), || async {
            let reason = self.reason(number);
            reason.contains(part).then_some(reason)
        })
        .await
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
