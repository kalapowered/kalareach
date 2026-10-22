//! The world the plugin-action suites share: a real daemon, this test process as the worker it
//! started, a real plugin host with the preparing component registered for one binding, and a
//! scripted upstream behind the production transport.
//!
//! The upstream is the one thing played: a scripted peer that records the frames the worker writes
//! and answers them as a vendor's server would. Everything between a request and that peer is the
//! product.

#![allow(
    dead_code,
    reason = "each suite that includes this world uses the part of it that it needs"
)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use kr_ipc::client::{Client, Codec, LocalClient};
use kr_plugin_sdk::identity::PluginIdentity;
use kr_plugin_sdk::ids::RepositoryGeneration;
use kr_plugin_sdk::version::PackageVersion;
use kr_plugin_service::client::PluginClient;
use kr_plugin_service::vocabulary::{BindingActivity, BindingFacts, BindingId};
use kr_protocol::admission::ComponentState;
use kr_protocol::agent::{AgentMutationTarget, PluginActionInvokeParams};
use kr_protocol::broker::{
    ActionName, BrokerGrant, BrokerGrants, InstanceCapabilityIdentity, InstanceCapabilityRecord,
    InstanceCapabilityState, InstanceEvidenceSource, InstanceInvalidation, IntegrationMode,
};
use kr_protocol::envelope::{ActionTarget, ControlFrame, MutationRequest, Outcome, ParamsValue};
use kr_protocol::identity::{ProcessStartIdentity, ProcessStartSource};
use kr_protocol::ids::{
    ActionId, AgentBindingRevision, ApplicationInstanceId, BrokerBindingId, CapabilityId,
    CapabilityRevision, PluginId, PublisherId, RequestId, SessionEpoch,
};
use kr_protocol::local::LocalClientKind;
use kr_protocol::method::{Method, MethodVersion};
use kr_protocol::receipt::{ActionReadParams, ActionReadResult};
use kr_protocol::receipt::{Receipt, ReceiptState};
use kr_protocol::scalars::{Bytes, Digest256, DurationMs, Nullable, TimestampMs, Uuid};
use kr_worker::broker::{
    BrokerTransport, Credential, ManagedProcess, TransportHandle, UpstreamDispatch, subject,
};

use super::{Epoch, Hosted, PATIENCE, build, component, hosted_on, install};

pub fn instance() -> ApplicationInstanceId {
    ApplicationInstanceId::new(Uuid::from_bytes([2; 16]))
}

pub fn binding() -> BrokerBindingId {
    BrokerBindingId::new(Uuid::from_bytes([9; 16]))
}

pub fn package() -> PluginId {
    PluginId::new("kalareach.codex").expect("a plugin identifier")
}

pub fn capability(name: &str) -> CapabilityId {
    CapabilityId::new(name).expect("a capability identifier")
}

/// The actions the component prepares, each declared as the package declares an action its
/// component prepares: a cancellation, a prompt, and a cancellation the component prepares wrongly
/// in one way each.
pub const ACTIONS: &[(&str, &str)] = &[
    ("turn.cancel", "upstream.cancel"),
    ("prompt.send", "upstream.prompt"),
    ("cancel.reasoned", "upstream.cancel"),
    ("attach.photo", "upstream.attachment"),
    ("attach.other", "upstream.attachment"),
    ("attach.as.cancel", "upstream.attachment"),
    ("cancel.other.action", "upstream.cancel"),
    ("cancel.other.class", "upstream.cancel"),
    ("cancel.as.prompt", "upstream.cancel"),
    ("cancel.other.arguments", "upstream.cancel"),
    ("prompt.with.fields", "upstream.prompt"),
    ("prompt.other.method", "upstream.prompt"),
    ("cancel.terminal", "upstream.cancel"),
    ("cancel.present", "upstream.cancel"),
    ("cancel.fault", "upstream.cancel"),
    ("cancel.loop", "upstream.cancel"),
];

/// What the scripted upstream was written, one frame per line.
pub type Written = Arc<Mutex<Vec<String>>>;

/// How the scripted upstream answers what it is written.
#[derive(Clone, Debug)]
pub enum Upstream {
    /// With a success carrying the request's own identifier.
    Answers,
    /// With an error that proves the frame was not acted on, carrying the request's own
    /// identifier.
    Refuses,
    /// With nothing: the worker's wait for it ends at its own bound.
    Silent,
    /// With a success, once the test lets it go.
    Holds(Arc<tokio::sync::Notify>),
    /// With a success once it has opened the file the frame's attachment names and found in it the
    /// size and the digest the frame says, under a grant that has not expired and is for this
    /// environment, as a receiver that is to acknowledge an attachment does, and with an error that
    /// proves nothing was done otherwise.
    Reads,
}

/// Whether the frame names a file the receiver can read, under a grant that has not expired and is
/// valid in `environment`, and the file holds what the frame says.
fn the_file_is_as_framed(line: &str, environment: &str) -> bool {
    let Ok(frame) = serde_json::from_str::<serde_json::Value>(line) else {
        return false;
    };
    let attachment = &frame["params"]["attachment"];
    let grant = &attachment["read_grant"];
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_millis());
    if grant["environment_id"].as_str() != Some(environment)
        || !grant["expires_at_ms"]
            .as_u64()
            .is_some_and(|expires| u128::from(expires) > now_ms)
    {
        return false;
    }
    let Some(path) = grant["path"].as_str() else {
        return false;
    };
    let Ok(bytes) = std::fs::read(path) else {
        return false;
    };
    let digest = Digest256::from_bytes(kr_cbor::sha256(&bytes));
    attachment["byte_len"].as_u64() == Some(bytes.len() as u64)
        && serde_json::to_value(digest).ok().as_ref() == Some(&attachment["content_digest"])
}

/// A daemon, this process as the worker of one session, a real plugin host with the preparing
/// component registered for one binding, and a scripted upstream behind the production transport.
pub struct Acting {
    pub hosted: Hosted,
    /// The connection this test registered the component over, where it registered it by hand.
    pub runtime: Option<Arc<PluginClient>>,
    pub written: Written,
    /// How the scripted upstream answers.
    pub upstream: Arc<Mutex<Upstream>>,
    /// The transport's owner, which lives as long as the test, and its write task and the
    /// scripted peer.
    pub _owner: Arc<kr_worker::broker::Duplex>,
    pub _tasks: Vec<tokio::task::JoinHandle<()>>,
    /// The native terminal's end of the transport, where the world serves one: its lines in and
    /// out.
    pub native: Option<tokio::sync::Mutex<NativeTerminal>>,
    /// The binding revision the world's invocations are prepared at.
    pub revision: AgentBindingRevision,
}

/// The native terminal's end of the production transport: the frames it writes go to the upstream
/// through the broker's native admission, and the upstream's replies come back to it.
pub struct NativeTerminal {
    lines: tokio::io::Lines<tokio::io::BufReader<tokio::io::ReadHalf<tokio::net::UnixStream>>>,
    writes: tokio::io::WriteHalf<tokio::net::UnixStream>,
}

/// What the world is started with, beyond how its component is registered.
#[derive(Clone, Copy)]
struct Options {
    /// Whether the plugin host's epoch runs, so that a component is stopped by its deadline, or is
    /// held still.
    epoch: Epoch,
    /// Whether the world serves a native terminal on the transport.
    native_terminal: bool,
    /// Whether the connector spells a cancellation as a template, with a thread bound and a turn
    /// running, so that a plan for a cancellation is written from the template and what the table
    /// spells nothing for is refused, rather than written as the host's own frame.
    templated: bool,
}

impl Options {
    const DEFAULT: Self = Self {
        epoch: Epoch::Held,
        native_terminal: false,
        templated: false,
    };
}

/// How the component comes to be registered with the plugin runtime and handed to the worker.
enum Registration {
    /// The test registers it over a connection of its own, and sets that connection on the broker.
    /// `told` says whether the worker has been told where the component stands, as its link tells
    /// it once the runtime has the component.
    ByHand { told: bool },
    /// The worker's own link asks the daemon for the runtime, registers the component and hands
    /// the connection to the broker, as it does for a package a person installed.
    ByLink,
}

impl Acting {
    pub async fn start() -> Option<Self> {
        Self::assemble(Registration::ByHand { told: true }, None, Options::DEFAULT).await
    }

    /// Starts the world with a connector that spells a cancellation as a template, a thread bound
    /// and a turn running.
    pub async fn start_templated() -> Option<Self> {
        Self::assemble(
            Registration::ByHand { told: true },
            None,
            Options {
                templated: true,
                ..Options::DEFAULT
            },
        )
        .await
    }

    /// Starts the world with the worker's deadlines measured on `clock`, which the test moves by
    /// hand.
    pub async fn start_on(clock: Arc<dyn kr_transport::clock::ContinuousClock>) -> Option<Self> {
        Self::assemble(
            Registration::ByHand { told: true },
            Some(clock),
            Options::DEFAULT,
        )
        .await
    }

    /// Starts the world; `registered` says whether the worker has been told where the component
    /// stands, as its link tells it once the runtime has the component.
    pub async fn start_with(registered: bool) -> Option<Self> {
        Self::assemble(
            Registration::ByHand { told: registered },
            None,
            Options::DEFAULT,
        )
        .await
    }

    /// Starts the world with the worker's own link running: nothing is registered by the test, and
    /// the plugin runtime is not asked for until the link asks the daemon for it.
    pub async fn start_linked() -> Option<Self> {
        Self::assemble(Registration::ByLink, None, Options::DEFAULT).await
    }

    /// Starts the world as a component that faults is met in a shipped host: the worker's own link
    /// runs, so the runtime's notice that it disabled a binding reaches the broker; the plugin
    /// host's epoch runs, so a call into the component is stopped when its deadline passes; and a
    /// native terminal is served on the transport, so traffic that does not wait for the component
    /// can be shown going on.
    pub async fn start_faulting() -> Option<Self> {
        Self::assemble(
            Registration::ByLink,
            None,
            Options {
                epoch: Epoch::Running,
                native_terminal: true,
                templated: false,
            },
        )
        .await
    }

    async fn assemble(
        registration: Registration,
        clock: Option<Arc<dyn kr_transport::clock::ContinuousClock>>,
        options: Options,
    ) -> Option<Self> {
        let wasm = component("preparing")?;
        let hosted = hosted_on(options.epoch, clock).await;
        let source = install(&hosted.environment(), &wasm);
        let runtime = match registration {
            Registration::ByHand { .. } => Some(Arc::new(hosted.runtime().await)),
            Registration::ByLink => None,
        };
        let service = &hosted._service;
        let broker = service.broker();
        let process = ProcessStartIdentity::new(41, ProcessStartSource::MacosProcBsdInfo, 900);

        // The instance the actions act on, with the capabilities they need.
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
        broker
            .bind_descriptor(
                binding(),
                instance(),
                package(),
                PublisherId::new("kalareach").expect("a publisher"),
                Digest256::from_bytes([5; 32]),
                BrokerGrants::granted([BrokerGrant::UpstreamAction, BrokerGrant::Observation]),
                None,
                TimestampMs::new(1),
            )
            .expect("the binding is recorded");
        if options.templated {
            // The terminal's conversation and the running turn, as the stream names them.
            broker
                .advance_binding(
                    instance(),
                    Some(kr_protocol::ids::AgentThreadId::new("thread-1").expect("a thread")),
                    TimestampMs::new(2),
                )
                .expect("the binding names a thread");
            broker
                .set_turn(
                    instance(),
                    Some(kr_protocol::ids::AgentTurnId::new("turn-7").expect("a turn")),
                )
                .expect("a turn is running");
        }
        for name in ["agent.prompt", "agent.cancel"] {
            broker
                .record_capability(InstanceCapabilityRecord {
                    capability_id: capability(name),
                    capability_version: "1".to_owned(),
                    application_instance_id: instance(),
                    identity: InstanceCapabilityIdentity::default(),
                    revision: CapabilityRevision::new(1),
                    state: InstanceCapabilityState::QualifiedAvailable,
                    source: InstanceEvidenceSource::HostProbe,
                    invalidated_by: [InstanceInvalidation::BindingChanged].into_iter().collect(),
                    disabled_reason: Nullable::null(),
                    observed_at: TimestampMs::new(1),
                })
                .expect("the capability is recorded");
        }
        broker
            .register_actions(
                binding(),
                &ACTIONS
                    .iter()
                    .map(|(id, effect)| declared(id, effect))
                    .collect::<Vec<_>>(),
            )
            .expect("the actions are registered");

        // The production transport over a socket pair, and a scripted peer that records what it
        // is written and answers every request.
        let (rich_table, reading) = if options.templated {
            let hole = |name: &str| serde_json::json!({ "$": name });
            let mut table = rich();
            table.entries.push(kr_protocol::gateway::RichMethodEntry {
                method: kr_protocol::ids::UpstreamMethod::new("turn/interrupt").expect("valid"),
                class: kr_protocol::gateway::NativeMethodClass::Mutation,
                required_right: kr_protocol::rights::ActionRight::AgentCancel,
                operation: Nullable::some(kr_protocol::gateway::RichOperation::TurnCancel),
                provenance: kr_protocol::broker::ActionProvenance::UpstreamTypedRpc,
            });
            table
                .entries
                .sort_by(|left, right| left.method.as_str().cmp(right.method.as_str()));
            let mut reading = kr_worker::broker::reading::Reading::default();
            reading.operations.insert(
                kr_protocol::gateway::RichOperation::TurnCancel,
                kr_worker::broker::reading::OperationTemplate {
                    method: kr_protocol::ids::UpstreamMethod::new("turn/interrupt").expect("valid"),
                    params: serde_json::json!({
                        "threadId": hole("thread_id"),
                        "turnId": hole("turn_id"),
                    }),
                    reply_turn: None,
                },
            );
            (table, reading)
        } else {
            (
                rich(),
                kr_worker::broker::reading::Reading::spelling(&rich()),
            )
        };
        broker
            .pin_table(instance(), installed(), table(), rich_table)
            .expect("the installed tables are pinned");
        broker
            .pin_reading(instance(), &package(), reading)
            .expect("what the connector spells is pinned");
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
        let written = Written::default();
        let upstream = Arc::new(Mutex::new(Upstream::Answers));
        let peer = tokio::spawn(scripted_upstream(
            there,
            Arc::clone(&written),
            Arc::clone(&upstream),
            hosted.environment_id.to_string(),
        ));
        let driving = tokio::spawn(writes);
        // The owner reads the upstream's answers, which is what a mutation's receipt waits for.
        let reading = tokio::spawn({
            let owner = Arc::clone(&owner);
            async move { owner.serve(upstream_reads, true).await }
        });

        // The package contributes attachments by an upload to its upstream, and the worker asks the
        // daemon for the drafts they are offered from.
        broker
            .register_attachments(binding(), Some(contribution()))
            .expect("the contribution is registered");
        broker
            .drafts()
            .connect(kr_worker::daemon_link::DaemonLink::new(
                hosted.session_id,
                hosted
                    .environment()
                    .rendezvous_endpoint()
                    .expect("an endpoint")
                    .as_path()
                    .to_path_buf(),
            ));
        let mut tasks = vec![peer, driving, reading];
        let native = options.native_terminal.then(|| {
            // The owner reads the native terminal's frames, which is what carries them upstream.
            tasks.push(tokio::spawn({
                let owner = Arc::clone(&owner);
                async move { owner.serve(client_reads, false).await }
            }));
            let (reads, writes) = tokio::io::split(client_there);
            tokio::sync::Mutex::new(NativeTerminal {
                lines: tokio::io::AsyncBufReadExt::lines(tokio::io::BufReader::new(reads)),
                writes,
            })
        });
        match (&registration, runtime.as_ref()) {
            (Registration::ByHand { told }, Some(runtime)) => {
                // The component is registered with the runtime the way the worker's link registers
                // it, and the worker is told where it stands.
                runtime
                    .register(
                        BindingId::new(binding().get()),
                        &PluginIdentity::new(
                            PluginId::new("kalareach/preparing").expect("an identifier"),
                            PackageVersion::parse("1.0.0").expect("a version"),
                            source.digest,
                            RepositoryGeneration::new(1),
                        ),
                        &BindingFacts {
                            plugin_id: "kalareach/preparing".to_owned(),
                            binding_revision: 1,
                            activity: BindingActivity::Idle,
                            thread_id: None,
                            turn_id: None,
                            updated_at_ms: 0,
                            held_rights: Vec::new(),
                        },
                        "/bin/sh",
                        &source,
                    )
                    .await
                    .expect("the component registers in the runtime");
                broker.component_calls().set(Some(Arc::clone(runtime)));
                if *told {
                    broker.set_component_state(binding(), ComponentState::Registered, None);
                }
            }
            _ => {
                // The binding ships the component, and the link does the rest.
                broker
                    .ship_component(
                        binding(),
                        kr_protocol::admission::LiveRelease {
                            plugin_id: package(),
                            publisher_id: PublisherId::new("kalareach").expect("a publisher"),
                            version: "1.0.0".to_owned(),
                            package_digest: Digest256::from_bytes([5; 32]),
                            origin: kr_protocol::admission::ReleaseOrigin {
                                repository_id: "official".to_owned(),
                                enrolment_key: "test".to_owned(),
                            },
                        },
                        kr_protocol::ids::RepositoryGeneration::new(1),
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
                    .expect("the binding ships the component");
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
            }
        }
        Some(Self {
            hosted,
            runtime,
            written,
            upstream,
            _owner: owner,
            _tasks: tasks,
            native,
            revision: if options.templated {
                AgentBindingRevision::new(2)
            } else {
                AgentBindingRevision::new(1)
            },
        })
    }

    pub async fn client(&self) -> LocalClient {
        LocalClient::connect(&self.hosted.endpoint, LocalClientKind::Cli, build())
            .await
            .expect("connects to the worker")
    }

    pub fn invocation(
        &self,
        client: &Client<impl Codec>,
        action: &str,
        parameters: &[u8],
    ) -> MutationRequest {
        MutationRequest {
            request_id: RequestId::new(1),
            method: Method::PluginActionInvoke.into(),
            method_version: MethodVersion::V1,
            action_id: ActionId::new(kr_ipc::new_uuid()),
            grant_id: Nullable::null(),
            target: ActionTarget {
                environment_id: self.hosted.environment_id,
                session_id: Nullable::some(self.hosted.session_id),
                session_epoch: Nullable::some(SessionEpoch::V1),
                application_instance_id: Nullable::some(instance()),
                agent_binding_revision: Nullable::some(self.revision),
            },
            expected: ParamsValue::empty(),
            action_window_id: client.action_window().action_window_id.clone(),
            requested_ttl_ms: DurationMs::new(60_000),
            params: ParamsValue::from_typed(&PluginActionInvokeParams {
                target: AgentMutationTarget {
                    subject: subject(self.hosted.session_id, instance()),
                    binding_revision: self.revision,
                },
                plugin_id: package(),
                action: ActionName::new(action).expect("an action name"),
                draft_id: Nullable::null(),
                resource_id: Nullable::null(),
                parameters: Bytes::from(parameters.to_vec()),
            })
            .expect("encodes"),
        }
    }

    /// A prompt that names `draft_id`, as a caller at this machine sends it to the daemon, which
    /// records the draft as sent and passes the prompt to this worker.
    pub fn prompting(
        &self,
        client: &Client<impl Codec>,
        draft_id: kr_protocol::ids::DraftId,
    ) -> MutationRequest {
        let mut mutation = self.invocation(client, "turn.cancel", b"{}");
        mutation.method = Method::AgentPromptSubmit.into();
        mutation.params = ParamsValue::from_typed(&kr_protocol::agent::AgentPromptParams {
            target: AgentMutationTarget {
                subject: subject(self.hosted.session_id, instance()),
                binding_revision: self.revision,
            },
            draft_id: Nullable::some(draft_id),
            text: Nullable::null(),
        })
        .expect("encodes");
        mutation
    }

    /// One request of the native terminal's, carried upstream through the broker's native
    /// admission and answered by the scripted upstream: the frame the terminal wrote is on the
    /// upstream's record, and the reply that comes back to the terminal is the answer to it.
    ///
    /// # Panics
    ///
    /// Panics when this world serves no native terminal, or the reply does not come back.
    pub async fn native_round_trip(&self, id: u64) {
        use tokio::io::AsyncWriteExt as _;

        let mut terminal = self
            .native
            .as_ref()
            .expect("this world serves a native terminal")
            .lock()
            .await;
        let request = format!("{{\"id\":{id},\"method\":\"session/prompt\",\"params\":{{}}}}\n");
        terminal
            .writes
            .write_all(request.as_bytes())
            .await
            .expect("the terminal writes its request");
        let reply = tokio::time::timeout(PATIENCE, terminal.lines.next_line())
            .await
            .expect("the reply comes back")
            .expect("the terminal reads")
            .expect("the transport is still open");
        let reply: serde_json::Value = serde_json::from_str(&reply).expect("a JSON reply");
        assert_eq!(reply["id"], id, "the reply is to the request: {reply}");
        assert!(
            reply.get("result").is_some(),
            "and it is an answer: {reply}"
        );
    }

    /// What the scripted upstream has been written so far.
    pub fn frames(&self) -> Vec<String> {
        self.written.lock().expect("not poisoned").clone()
    }

    /// Stops the plugin host, the way a machine that is slow to schedule it looks to a caller.
    pub fn stop_host(&self) -> ProcessStartIdentity {
        let host = self.hosted.published().expect("the host is published");
        signal(&host, rustix::process::Signal::STOP);
        host
    }
}

impl Drop for Acting {
    fn drop(&mut self) {
        self.hosted._service.broker().component_calls().set(None);
        // A host this test stopped is let go, so the harness can end it.
        if let Some(host) = self.hosted.published() {
            signal(&host, rustix::process::Signal::CONT);
        }
        let _ = &self.runtime;
    }
}

pub fn signal(process: &ProcessStartIdentity, signal: rustix::process::Signal) {
    let pid = rustix::process::Pid::from_raw(i32::try_from(process.pid.get()).expect("a pid"))
        .expect("a process");
    let _ = rustix::process::kill_process(pid, signal);
}

/// One action as the package declares it: prepared by its component. `cancel.reasoned` declares a
/// required text parameter and the others declare none.
pub fn declared(id: &str, effect: &str) -> kr_plugin_sdk::effect::ActionDeclaration {
    let parameters = if id.starts_with("attach.") {
        serde_json::json!([{
            "name": "attachment",
            "kind": { "type": "attachment_handle" },
            "label": "Attachment",
            "required": true,
        }])
    } else if id == "cancel.reasoned" {
        serde_json::json!([{
            "name": "reason",
            "kind": { "type": "text", "max_length": 20, "multiline": false },
            "label": "Reason",
            "required": true,
        }])
    } else {
        serde_json::json!([])
    };
    serde_json::from_value(serde_json::json!({
        "id": id,
        "label": id,
        "effect": effect,
        "implementation": { "type": "component" },
        "parameters": { "parameters": parameters },
        "description": format!("{id}, as the package declares it"),
        "confirmation_required": false,
    }))
    .expect("a declaration the manifest format reads")
}

/// An action the host carries out itself by redrawing the package's own document.
pub fn presented(id: &str) -> kr_plugin_sdk::effect::ActionDeclaration {
    serde_json::from_value(serde_json::json!({
        "id": id,
        "label": id,
        "effect": "observe",
        "implementation": { "type": "presentation" },
        "parameters": { "parameters": [] },
        "description": format!("{id}, redrawn by the host"),
        "confirmation_required": false,
    }))
    .expect("a declaration the manifest format reads")
}

pub fn installed() -> kr_worker::broker::PackageIdentity {
    kr_worker::broker::PackageIdentity {
        plugin_id: package(),
        publisher_id: PublisherId::new("kalareach").expect("a publisher"),
        package_digest: Digest256::from_bytes([5; 32]),
    }
}

/// The connector table the package ships: a method the native terminal may send.
pub fn table() -> kr_protocol::gateway::DeclarativeTable {
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
        entries: vec![kr_protocol::gateway::DeclarativeEntry {
            method: kr_protocol::ids::UpstreamMethod::new("session/prompt").expect("valid"),
            class: kr_protocol::gateway::NativeMethodClass::Mutation,
            expects_response: true,
            approval_option_field: Nullable::null(),
            reverse: Nullable::null(),
        }],
    };
    table.digest = table.canonical_digest().expect("encodable");
    table
}

/// The closed rich table: the methods an action of this package goes out as, which for each action
/// is its own name, under the right its class needs.
pub fn rich() -> kr_protocol::gateway::RichMethodTable {
    let mut entries: Vec<_> = ACTIONS
        .iter()
        .map(|(name, effect)| kr_protocol::gateway::RichMethodEntry {
            method: kr_protocol::ids::UpstreamMethod::new(*name).expect("valid"),
            class: kr_protocol::gateway::NativeMethodClass::Mutation,
            required_right: if *effect == "upstream.prompt" || *effect == "upstream.attachment" {
                kr_protocol::rights::ActionRight::AgentPrompt
            } else {
                kr_protocol::rights::ActionRight::AgentCancel
            },
            operation: Nullable::null(),
            provenance: kr_protocol::broker::ActionProvenance::UpstreamTypedRpc,
        })
        .collect();
    // A table is in the order of its method names.
    entries.sort_by(|left, right| left.method.as_str().cmp(right.method.as_str()));
    kr_protocol::gateway::RichMethodTable {
        table_version: kr_protocol::ids::MethodTableVersion::new(1),
        upstream_protocol_version: "1".to_owned(),
        entries,
    }
}

/// The upstream: records each line it is written and answers it with a success carrying the
/// request's own identifier.
pub async fn scripted_upstream(
    stream: tokio::net::UnixStream,
    written: Written,
    behaviour: Arc<Mutex<Upstream>>,
    environment: String,
) {
    use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _};
    let (reader, mut writer) = tokio::io::split(stream);
    let mut lines = tokio::io::BufReader::new(reader).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        let id = serde_json::from_str::<serde_json::Value>(&line)
            .ok()
            .and_then(|frame| frame.get("id").cloned());
        let readable = the_file_is_as_framed(&line, &environment);
        written.lock().expect("not poisoned").push(line);
        let Some(id) = id else {
            continue;
        };
        let how = behaviour.lock().expect("not poisoned").clone();
        let reply = match how {
            Upstream::Answers => serde_json::json!({ "id": id, "result": { "ok": true } }),
            Upstream::Refuses => {
                // The reserved code that says the frame was not a call the upstream could make,
                // which proves nothing was done.
                serde_json::json!({ "id": id, "error": { "code": -32602, "message": "refused" } })
            }
            Upstream::Silent => continue,
            Upstream::Holds(release) => {
                release.notified().await;
                serde_json::json!({ "id": id, "result": { "ok": true } })
            }
            Upstream::Reads if readable => {
                serde_json::json!({ "id": id, "result": { "ok": true } })
            }
            Upstream::Reads => {
                serde_json::json!({ "id": id, "error": { "code": -32602, "message": "refused" } })
            }
        };
        if writer
            .write_all(format!("{reply}\n").as_bytes())
            .await
            .is_err()
        {
            return;
        }
    }
}

pub async fn send(client: &mut Client<impl Codec>, mutation: MutationRequest) -> Outcome {
    client
        .send(&ControlFrame::Mutation(Box::new(mutation)))
        .await
        .expect("writes the mutation");
    answer(client, None).await
}

/// Reads frames until the response to `request_id` (or to the next request, where none is named)
/// arrives.
pub async fn answer(client: &mut Client<impl Codec>, request_id: Option<u64>) -> Outcome {
    loop {
        match client.recv().await.expect("the worker answers") {
            ControlFrame::Response(response)
                if request_id.is_none_or(|wanted| response.request_id.get() == wanted) =>
            {
                return response.outcome;
            }
            ControlFrame::Response(other) => {
                panic!(
                    "an answer to {} arrived out of turn",
                    other.request_id.get()
                )
            }
            ControlFrame::Notification(_) | ControlFrame::Event(_) => {}
            other => panic!("the worker answered {other:?}"),
        }
    }
}

/// Asks for an action's receipt on `client`, and does not wait for the answer.
pub async fn ask_for_receipt(client: &mut Client<impl Codec>, action_id: ActionId) {
    client
        .send(&ControlFrame::Request(kr_protocol::envelope::Request {
            request_id: RequestId::new(900),
            method: Method::ActionRead.into(),
            method_version: MethodVersion::V1,
            params: ParamsValue::from_typed(&ActionReadParams {
                action_id,
                session_id: None,
            })
            .expect("encodes"),
        }))
        .await
        .expect("writes the request");
}

/// Reads the answer to a request that [`ask_for_receipt`] made: the receipt, or what the worker
/// said instead of one.
pub async fn receipt_or_refusal(client: &mut Client<impl Codec>) -> Result<Receipt, String> {
    match answer(client, Some(900)).await {
        Outcome::Ok(value) => Ok(value
            .to_typed::<ActionReadResult>()
            .expect("decodes")
            .receipt),
        Outcome::Error(error) => Err(format!("{error:?}")),
    }
}

/// Reads the answer to a request that [`ask_for_receipt`] made.
pub async fn receipt_answered(client: &mut Client<impl Codec>) -> Option<Receipt> {
    receipt_or_refusal(client).await.ok()
}

/// Asks for an action's receipt on `client`.
pub async fn read_receipt(client: &mut Client<impl Codec>, action_id: ActionId) -> Option<Receipt> {
    ask_for_receipt(client, action_id).await;
    receipt_answered(client).await
}

/// Waits until the action's receipt is in any state but `accepted`, and returns it.
pub async fn until_settled(client: &mut Client<impl Codec>, action_id: ActionId) -> Receipt {
    let deadline = tokio::time::Instant::now() + PATIENCE;
    loop {
        ask_for_receipt(client, action_id).await;
        let last = match receipt_or_refusal(client).await {
            Ok(receipt) if receipt.state != ReceiptState::Accepted => return receipt,
            Ok(receipt) => format!("the receipt was {:?}", receipt.state),
            Err(refusal) => format!("the worker answered {refusal}"),
        };
        assert!(
            tokio::time::Instant::now() < deadline,
            "waited for the receipt to leave accepted: {last}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Waits until the action's receipt is in `state`.
pub async fn until_receipt(
    client: &mut Client<impl Codec>,
    action_id: ActionId,
    state: ReceiptState,
) -> Receipt {
    let deadline = tokio::time::Instant::now() + PATIENCE;
    loop {
        ask_for_receipt(client, action_id).await;
        let last = match receipt_or_refusal(client).await {
            Ok(receipt) if receipt.state == state => return receipt,
            Ok(receipt) => format!("the receipt was {:?}", receipt.state),
            Err(refusal) => format!("the worker answered {refusal}"),
        };
        assert!(
            tokio::time::Instant::now() < deadline,
            "waited for the receipt to be {state:?}: {last}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// What the package contributes: images of a size the fixtures stay under, offered by an upload to
/// the upstream.
pub fn contribution() -> kr_plugin_sdk::effect::AttachmentContribution {
    kr_plugin_sdk::effect::AttachmentContribution {
        accepted_media_types: vec!["image/png".to_owned()],
        max_bytes: kr_plugin_sdk::scalars::U64::new(1024 * 1024),
        max_count: kr_plugin_sdk::scalars::Count::new(4),
        insertion: kr_plugin_sdk::effect::AttachmentInsertion::UpstreamUpload,
        external_destination: kr_plugin_sdk::scalars::Nullable(None),
    }
}

/// What changes while an action's component prepares it, between the action's admission and the
/// moment it comes back to be dispatched.
pub enum Change {
    /// The binding's grant is withdrawn.
    Grant,
    /// The package registers the action again as another class its component prepares.
    Declaration,
    /// The package registers the action again as one the host carries out itself, which needs
    /// nothing from the plan it was prepared for.
    Presentation,
    /// The binding moves to another revision, as a thread selection does.
    Binding,
    /// The daemon announces an authority revision, which revokes what was admitted under the one
    /// before.
    Authority,
    /// The connection the action was accepted on ends.
    Connection,
}

/// The principal the local owner's connection to the worker acts as, and so the owner of the
/// drafts and uploads a test makes for it through the daemon's transfer service.
pub fn local_actor() -> kr_protocol::ids::ActorId {
    kr_protocol::ids::ActorId::new(format!("local:{}", kr_ipc::paths::current_uid()))
        .expect("a principal")
}

impl Acting {
    /// The transfer service the daemon hosts.
    pub fn transfers(&self) -> Arc<kr_transfer::TransferService> {
        Arc::clone(
            self.hosted
                .controller
                .as_ref()
                .expect("a daemon")
                .transfer()
                .service(),
        )
    }

    /// Publishes a file through the daemon's transfer service, as the local owner, under `name`.
    pub fn publish(&self, bytes: &[u8], name: &str) -> kr_protocol::transfer::AttachmentHandle {
        use kr_protocol::transfer::{
            ChunkDescriptor, UploadBeginParams, UploadChunkParams, UploadFinishParams,
        };
        let service = self.transfers();
        let actor = local_actor();
        let digest = Digest256::from_bytes(kr_cbor::sha256(bytes));
        let length = kr_protocol::scalars::U64::new(bytes.len() as u64);
        let begun = service
            .upload_begin(
                &actor,
                &UploadBeginParams {
                    environment_id: self.hosted.environment_id,
                    session_id: Nullable::some(self.hosted.session_id),
                    device_id: Nullable::null(),
                    declared_byte_len: length,
                    declared_digest: digest,
                    declared_media_type: "image/png".to_owned(),
                    original_file_name: name.to_owned(),
                },
                None,
            )
            .expect("reserves the upload");
        service
            .upload_chunk(
                &actor,
                &UploadChunkParams {
                    transfer_id: begun.transfer_id,
                    chunk: ChunkDescriptor {
                        index: kr_protocol::scalars::U64::new(0),
                        byte_len: length,
                        digest,
                    },
                    bytes: Bytes::new(bytes.to_vec()),
                },
                None,
            )
            .expect("takes the chunk");
        service
            .upload_finish(
                &actor,
                &UploadFinishParams {
                    transfer_id: begun.transfer_id,
                    declared_byte_len: length,
                    declared_digest: digest,
                },
                None,
            )
            .expect("publishes the attachment")
            .handle
    }

    /// A draft for the session and the instance the actions act on, as the local owner made it.
    pub fn new_draft(&self) -> kr_protocol::transfer::DraftRecord {
        self.new_draft_for(instance())
    }

    /// A draft for the session and for `application_instance_id`, as the local owner made it.
    pub fn new_draft_for(
        &self,
        application_instance_id: ApplicationInstanceId,
    ) -> kr_protocol::transfer::DraftRecord {
        self.transfers()
            .draft_create(
                &local_actor(),
                &kr_protocol::transfer::DraftCreateParams {
                    environment_id: self.hosted.environment_id,
                    device_id: Nullable::null(),
                    session_id: Nullable::some(self.hosted.session_id),
                    application_instance_id: Nullable::some(application_instance_id),
                    text: "have a look at this".to_owned(),
                },
                None,
            )
            .expect("creates the draft")
            .draft
    }

    /// Binds a published file to a draft, as a typed submission the package offers.
    ///
    /// The daemon makes this binding only for a path an integration declared, so it is made through
    /// the transfer service here, as that integration's binding.
    pub fn bind(
        &self,
        draft: &kr_protocol::transfer::DraftRecord,
        handle: &kr_protocol::transfer::AttachmentHandle,
    ) -> kr_protocol::transfer::DraftRecord {
        self.bind_by(
            draft,
            handle,
            kr_protocol::transfer::InsertionMethod::TypedSubmission,
        )
    }

    /// Binds a published file to a draft, to be inserted by `method`.
    pub fn bind_by(
        &self,
        draft: &kr_protocol::transfer::DraftRecord,
        handle: &kr_protocol::transfer::AttachmentHandle,
        method: kr_protocol::transfer::InsertionMethod,
    ) -> kr_protocol::transfer::DraftRecord {
        self.transfers()
            .draft_add_attachment(
                &local_actor(),
                &kr_protocol::transfer::AgentDraftAddAttachmentParams {
                    draft_id: draft.draft_id,
                    expected_revision: draft.revision,
                    transfer_id: handle.transfer_id,
                    contribution: kr_protocol::transfer::AttachmentContribution {
                        operation_id: "attach".to_owned(),
                        accepted_media_types: vec!["image/png".to_owned()],
                        max_byte_len: kr_protocol::scalars::U64::new(1024 * 1024),
                        max_count: kr_protocol::scalars::U64::new(4),
                        insertion_method: method,
                        external_destination: Nullable::null(),
                        model_media_capability: false,
                    },
                },
                None,
            )
            .expect("binds the attachment")
            .draft
    }

    /// The draft as the daemon holds it.
    pub fn draft(&self, draft_id: kr_protocol::ids::DraftId) -> kr_protocol::transfer::DraftRecord {
        self.transfers()
            .draft(&local_actor(), draft_id)
            .expect("reads the draft")
    }

    /// The call that offers `attachment` of `draft_id` to the agent through `action`.
    pub fn offering(
        &self,
        client: &Client<impl Codec>,
        action: &str,
        draft_id: kr_protocol::ids::DraftId,
        attachment: kr_protocol::ids::TransferId,
    ) -> MutationRequest {
        let mut mutation = self.invocation(
            client,
            action,
            format!(r#"{{"attachment":"{attachment}"}}"#).as_bytes(),
        );
        let mut params: PluginActionInvokeParams = mutation.params.to_typed().expect("decodes");
        params.draft_id = Nullable::some(draft_id);
        mutation.params = ParamsValue::from_typed(&params).expect("encodes");
        mutation
    }
}

impl Acting {
    /// Makes `change` to what `action` was accepted under, while its component is held. A change
    /// of the connection takes `asking`, which is the connection the action was accepted on.
    pub async fn change(&self, change: Change, action: &str, asking: &mut Option<LocalClient>) {
        let broker = self.hosted._service.broker();
        match change {
            Change::Grant => broker
                .withdraw_grant(binding(), BrokerGrant::UpstreamAction)
                .expect("the grant is withdrawn"),
            Change::Declaration => {
                broker
                    .register_actions(binding(), &[declared(action, "upstream.prompt")])
                    .expect("the package re-registers the action as another class");
            }
            Change::Presentation => {
                broker
                    .register_actions(binding(), &[presented(action)])
                    .expect("the package re-registers the action as a presentation");
            }
            Change::Binding => {
                broker
                    .advance_binding(instance(), None, TimestampMs::new(2))
                    .expect("the binding moves");
            }
            Change::Authority => {
                let mut daemon = self
                    .hosted
                    .daemon_connection(kr_protocol::local::ControllerConnectionRole::Authority)
                    .await;
                daemon
                    .announce_revision(kr_protocol::worker::AuthorityRevisionNotice {
                        environment_id: self.hosted.environment_id,
                        revision: kr_protocol::ids::AuthorityRevision::new(2),
                        reach: kr_protocol::worker::RevisionReach::Host,
                        evidence_from: 0,
                    })
                    .await
                    .expect("the worker installs the revision");
            }
            // The socket is shut down before it is dropped: a process another case has started
            // holds a copy of the descriptor until it executes, and the connection does not end
            // while a copy is held.
            Change::Connection => {
                if let Some(mut client) = asking.take() {
                    client
                        .writer()
                        .shut_down(std::net::Shutdown::Both)
                        .expect("shuts the client's socket down");
                }
            }
        }
    }
}

/// Names the uncertain earlier action a request supersedes, as a later request on a subject with an
/// uncertain outcome must.
pub fn supersede(mutation: &mut MutationRequest, earlier: &Receipt) {
    let mut expected = kr_cbor::CanonicalMap::new();
    expected
        .insert(
            kr_protocol::action::SUPERSEDES_ACTION_KEY.to_owned(),
            kr_cbor::to_canonical_value(&earlier.action_id).expect("encodes"),
        )
        .expect("one key");
    expected
        .insert(
            kr_protocol::action::SUPERSEDES_REVISION_KEY.to_owned(),
            kr_cbor::to_canonical_value(&earlier.revision).expect("encodes"),
        )
        .expect("another key");
    mutation.expected = ParamsValue::new(kr_cbor::CanonicalValue::Map(expected));
}

/// A paired device, as the daemon vouches for it to a worker whose daemon is of `generation`, with
/// a grant it checked at authority revision 1.
pub fn a_paired_device(
    generation: kr_protocol::ids::ControllerGeneration,
) -> kr_protocol::actor::ActorEnvelope {
    kr_protocol::actor::ActorEnvelope {
        actor_id: kr_protocol::ids::ActorId::new("device:a-test-phone").expect("an actor"),
        ingress: kr_protocol::actor::ActorIngress::PairedDevice,
        device_id: Nullable::some(kr_protocol::ids::DeviceId::new(Uuid::from_bytes([9; 16]))),
        grant_id: Nullable::some(kr_protocol::ids::GrantId::new(Uuid::from_bytes([8; 16]))),
        grant_revision: Nullable::some(kr_protocol::ids::AuthorityRevision::new(1)),
        controller_generation: generation,
        connection_id: kr_protocol::ids::ConnectionId::new(Uuid::from_bytes([7; 16])),
    }
}

/// The daemon's announcement to the worker of authority revision `revision`, over its authority
/// connection, which the worker acknowledges.
pub async fn announce(authority: &mut kr_ipc::client::BoundLink, acting: &Acting, revision: u64) {
    authority
        .announce_revision(kr_protocol::worker::AuthorityRevisionNotice {
            environment_id: acting.hosted.environment_id,
            revision: kr_protocol::ids::AuthorityRevision::new(revision),
            reach: kr_protocol::worker::RevisionReach::Host,
            evidence_from: 0,
        })
        .await
        .expect("the worker installs the revision");
}

/// A remote dispatch lease of the worker's generation for revision `revision` that ends `ms` from
/// now on the machine's clock.
pub fn a_lease(acting: &Acting, revision: u64, ms: u64) -> kr_protocol::local::ForwardedLease {
    kr_protocol::local::ForwardedLease {
        lease_id: kr_protocol::ids::RemoteDispatchLeaseId::new(kr_ipc::new_uuid()),
        controller_generation: acting.hosted.controller_generation,
        authority_revision: kr_protocol::ids::AuthorityRevision::new(revision),
        deadline_boot_ms: kr_protocol::scalars::U64::new(kr_ipc::clock::boot_elapsed_ms() + ms),
    }
}

/// Reads `action_id`'s receipt for the device over its proxy, as the daemon reads it for the
/// device, or nothing where the worker has none to show.
pub async fn the_devices_receipt(
    proxy: &mut kr_ipc::client::BoundLink,
    device: &kr_protocol::actor::ActorEnvelope,
    action_id: ActionId,
) -> Option<Receipt> {
    proxy
        .send(&ControlFrame::ForwardedRead(Box::new(
            kr_protocol::local::ForwardedRequest {
                request: kr_protocol::envelope::Request {
                    request_id: RequestId::new(900),
                    method: Method::ActionRead.into(),
                    method_version: MethodVersion::V1,
                    params: ParamsValue::from_typed(&ActionReadParams {
                        action_id,
                        session_id: None,
                    })
                    .expect("encodes"),
                },
                actor: device.clone(),
                authority_deadline_boot_ms: Nullable::null(),
                history: None,
            },
        )))
        .await
        .expect("writes the read");
    match answer(proxy, Some(900)).await {
        Outcome::Ok(value) => Some(
            value
                .to_typed::<ActionReadResult>()
                .expect("decodes")
                .receipt,
        ),
        Outcome::Error(_) => None,
    }
}

/// Reads `action_id`'s receipt for the device over its proxy until it is in `state`, which for
/// `accepted` is when the daemon's action is waiting for its component.
pub async fn until_the_devices_receipt_is(
    proxy: &mut kr_ipc::client::BoundLink,
    device: &kr_protocol::actor::ActorEnvelope,
    action_id: ActionId,
    state: ReceiptState,
) -> Receipt {
    for _ in 0..2_400 {
        if let Some(receipt) = the_devices_receipt(proxy, device, action_id).await
            && receipt.state == state
        {
            return receipt;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("the forwarded action's receipt never read {state:?}");
}
