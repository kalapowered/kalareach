//! A paired device's view of the broker's pending resources, held to its grant's history scope.
//!
//! Section 10 lets an invitation name current approvals, which its holder may decide however early
//! they were recorded, and says that without that scope a pending-resource snapshot cannot bypass
//! the history filter. A device reads a session through the control daemon, which sends each read
//! to the session's worker with the history scope of the device's grant. `events.subscribe` and
//! `events.snapshot` answer with the resources the broker arbitrates, a page at a time, and the
//! subscription then carries each transition the broker commits. These tests forward a device's
//! attach, subscription and snapshots as the daemon does, drive the broker's own transitions, and
//! start the delivery of those transitions to the views themselves, so each test decides when a
//! queued transition arrives. What they check is what arrives on the device's connection, before
//! any cursor rule a client would apply.
//!
//! The rule is the one the approval record read follows: an approval the grant names is shown while
//! it can still be decided, and everything else by the moment it was recorded. A live view whose
//! grant keeps no history reaches what is recorded from the moment its first subscription began.
//! Each test puts the same transitions past two controls, the local owner in a window of its own
//! and the same device reading without a scope, and both are shown every resource and every
//! transition.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-10.51 | every `kr_req_10_51_` test here |

use std::collections::{BTreeSet, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use kr_ipc::client::LocalClient;
use kr_ipc::endpoint::Listener;
use kr_ipc::verify::{ControllerIdentity, WorkerIdentity};
use kr_protocol::actor::{ActorEnvelope, ActorIngress};
use kr_protocol::agent::{AgentApprovalRespondParams, AgentMutationTarget};
use kr_protocol::attachment::{
    AttachMode, AttachmentCapability, SessionAttachParams, SessionAttachResult, SessionDetachParams,
};
use kr_protocol::broker::{
    BrokerGrant, BrokerGrants, DecodedProjection, DecodingTrust, IntegrationMode, OfferedDecision,
};
use kr_protocol::envelope::{
    ActionTarget, ControlFrame, MutationRequest, Outcome, ParamsValue, Request,
};
use kr_protocol::error::ProtocolError;
use kr_protocol::gateway::{
    DeclarativeEntry, DeclarativeTable, NativeFraming, NativeMethodClass, PendingKind,
    PendingResource, PendingState, RichMethodTable,
};
use kr_protocol::grant::HistoryScope;
use kr_protocol::hello::PROTOCOL_VERSION;
use kr_protocol::identity::{
    DesktopBinding, ProcessStartIdentity, ProcessStartSource, WorkerProfile,
};
use kr_protocol::ids::{
    ActionId, ActionWindowId, ActorId, AgentBindingRevision, ApplicationInstanceId, AttachmentId,
    AuthorityRevision, BrokerBindingId, BuildId, CapabilityId, CapabilityRevision, ConnectionId,
    ControllerGeneration, DeviceId, GatewayConnectionId, GrantId, MethodTableVersion,
    PendingResourceId, PluginId, PublisherId, RequestId, SessionEpoch, SessionId, UpstreamMethod,
};
use kr_protocol::local::{
    ControllerConnectionRole, ForwardedMutation, ForwardedRequest, LocalClientKind,
};
use kr_protocol::method::{Method, MethodVersion};
use kr_protocol::projection::{
    AGENT_RESOURCE_EVENT, AgentResourceCause, AgentResourceContentClass, AgentResourceEvent,
    AgentResourceSnapshot, AgentResourceSnapshotContinuation,
};
use kr_protocol::recovery::{
    EventStream, EventsSnapshotParams, EventsSnapshotResult, EventsSubscribeParams,
    EventsSubscribeResult,
};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{CanonicalSet, Digest256, Nullable, TimestampMs, U64, Uuid};
use kr_protocol::session::{ClosureReason, Dimensions, DisplayNumber, Durability, ShellMode};
use kr_worker::broker::{
    BrokerError, BrokerTransport, Credential, ManagedProcess, MutationAdmission, Observations,
    PendingTransmission, TransportHandle, UpstreamDispatch, UpstreamOutcome, UpstreamRequest,
    subject,
};
use kr_worker::history_filter::{HistoryFilter, ViewerScope, WithheldReason};
use kr_worker::runtime::SessionRuntime;
use kr_worker::service::{ServiceBinding, WorkerService};
use kr_worker::session::{Session as TerminalSession, SessionConfig};

mod common;

use common::LIVENESS_DEADLINE;

/// When the requests that predate every grant's bound here arrived.
const BEFORE: u64 = 2_000;

/// The moment the grants with a bound reach back to.
const BOUND: u64 = 5_000;

/// When the requests inside that bound arrived.
const AFTER: u64 = 9_000;

/// The deadline every upstream puts on its requests: far enough ahead that answering is possible.
const DEADLINE: TimestampMs = TimestampMs::new(4_102_444_800_000);

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

fn instance() -> ApplicationInstanceId {
    ApplicationInstanceId::new(Uuid::from_bytes([2; 16]))
}

fn binding() -> BrokerBindingId {
    BrokerBindingId::new(Uuid::from_bytes([9; 16]))
}

fn plugin() -> PluginId {
    PluginId::new("kalareach.codex").expect("a plugin")
}

fn publisher() -> PublisherId {
    PublisherId::new("kalareach").expect("a publisher")
}

fn package_digest() -> Digest256 {
    Digest256::from_bytes([5; 32])
}

fn permission() -> UpstreamMethod {
    UpstreamMethod::new("session/request_permission").expect("a method")
}

/// The decisions the decoder offers, in the order the upstream offered them.
fn offered() -> Vec<OfferedDecision> {
    vec![
        OfferedDecision {
            option_id: "allow".to_owned(),
            label: "Allow this once".to_owned(),
        },
        OfferedDecision {
            option_id: "reject".to_owned(),
            label: "Reject".to_owned(),
        },
    ]
}

fn projection() -> DecodedProjection {
    DecodedProjection {
        schema_version: "kr-approval/1".to_owned(),
        summary: "the agent wants to write /srv/notes.txt".to_owned(),
        decisions: offered(),
    }
}

/// A request identifier no other request of this suite uses, on any connection.
fn next_request() -> RequestId {
    static NEXT: AtomicU64 = AtomicU64::new(1_000_000);
    RequestId::new(NEXT.fetch_add(1, Ordering::Relaxed))
}

/// One native request, as the upstream writes it, under an identifier of its own.
fn request_frame() -> Vec<u8> {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    format!(
        r#"{{"id":{id},"method":"session/request_permission","params":{{"path":"/srv/notes.txt","options":[{{"optionId":"allow","name":"Allow this once"}},{{"optionId":"reject","name":"Reject"}}]}}}}"#
    )
    .into_bytes()
}

/// Now, as the broker is told the time of each transition these tests drive.
fn now() -> TimestampMs {
    kr_ipc::now_ms()
}

/// Waits for one exchange with the worker, and fails the test naming what it waited for rather
/// than hanging when a handler stops answering.
async fn within<T>(what: &str, work: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(LIVENESS_DEADLINE, work)
        .await
        .unwrap_or_else(|_| panic!("{what} within {LIVENESS_DEADLINE:?}"))
}

/// A transport that takes every answer at once.
#[derive(Debug, Default)]
struct Answering;

impl UpstreamDispatch for Answering {
    fn admit(&self, _request: &UpstreamRequest) -> Result<(), BrokerError> {
        Ok(())
    }

    fn submit(&self, request: &UpstreamRequest) -> Result<PendingTransmission, BrokerError> {
        Ok(PendingTransmission::settled(Ok(UpstreamOutcome {
            upstream_request_id: None,
            turn_id: request.turn_id.clone(),
            provenance: kr_protocol::broker::ActionProvenance::UpstreamTypedRpc,
        })))
    }
}

fn process(pid: u64) -> ProcessStartIdentity {
    ProcessStartIdentity::new(pid, ProcessStartSource::MacosProcBsdInfo, 900)
}

fn managed(instance: ApplicationInstanceId, pid: u64) -> ManagedProcess {
    ManagedProcess::new(
        instance,
        process(pid),
        TransportHandle {
            transport: BrokerTransport::PrivateSocket,
            application_instance_id: instance,
            executable_digest: Digest256::from_bytes([3; 32]),
            process: process(pid),
        },
        Credential::from_bytes([9; 32]),
        true,
        TimestampMs::new(1),
    )
}

fn approval_table() -> DeclarativeTable {
    let mut table = DeclarativeTable {
        plugin_id: plugin(),
        publisher_id: publisher(),
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
        entries: vec![DeclarativeEntry {
            method: permission(),
            class: NativeMethodClass::Mutation,
            expects_response: true,
            approval_option_field: Nullable::some("option_id".to_owned()),
            reverse: Nullable::null(),
        }],
    };
    table.digest = table.canonical_digest().expect("encodable");
    table
}

/// A worker serving one session, with one instance whose package's decoder may interpret and
/// answer approval requests, and the native connection its requests arrive on.
struct Host {
    _temp: kr_ipc::testing::TempHost,
    service: Arc<WorkerService>,
    runtime: Arc<SessionRuntime>,
    session_id: SessionId,
    environment_id: kr_protocol::ids::EnvironmentId,
    endpoint: kr_ipc::paths::Endpoint,
    /// The control daemon's identity, to forward a paired device's requests as the daemon does.
    controller: Arc<ControllerIdentity>,
    /// The boot the daemon proves its generation against.
    boot: kr_protocol::identity::BootIdentity,
    /// The native connection the requests arrive on.
    connection: GatewayConnectionId,
    /// The transitions that connection observes, queued until the test starts delivering them.
    observations: Option<Observations>,
    /// The delivery of those transitions to the session's views, once it has started.
    delivering: Option<tokio::task::JoinHandle<()>>,
}

impl Host {
    /// Starts delivering the observed transitions to the session's views, the queued ones first.
    fn deliver(&mut self) {
        let observations = self
            .observations
            .take()
            .expect("delivery starts once per test");
        self.delivering = Some(tokio::spawn(kr_worker::broker::attach::deliver_to_views(
            observations,
            Arc::clone(self.service.broker()),
            self.session_id,
            Arc::clone(&self.runtime),
        )));
    }

    fn target(&self) -> ActionTarget {
        ActionTarget {
            environment_id: self.environment_id,
            session_id: Nullable::some(self.session_id),
            session_epoch: Nullable::some(SessionEpoch::V1),
            application_instance_id: Nullable::null(),
            agent_binding_revision: Nullable::null(),
        }
    }

    /// A terminal of the session's own size that watches the session.
    fn terminal(&self) -> SessionAttachParams {
        SessionAttachParams {
            session_id: self.session_id,
            mode: AttachMode::Terminal,
            claim_geometry: false,
            dimensions: Nullable::some(Dimensions::new(80, 24)),
            terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
            requested: [AttachmentCapability::ObserveTerminal]
                .into_iter()
                .collect(),
        }
    }

    /// Ends the delivery and closes the session.
    fn finish(self) {
        if let Some(delivering) = self.delivering.as_ref() {
            delivering.abort();
        }
        self.runtime
            .close(ClosureReason::CloseRequested)
            .1
            .release();
    }
}

async fn host() -> Host {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let environment_id = temp.environment_id();
    let session_id = SessionId::new(kr_ipc::new_uuid());
    let boot = kr_ipc::identity::boot_identity().expect("a boot identity");
    let current = kr_ipc::identity::current_process_start_identity().expect("a process identity");
    let identity = Arc::new(
        WorkerIdentity::generate(
            session_id,
            SessionEpoch::V1,
            boot.clone(),
            current,
            PROTOCOL_VERSION,
        )
        .expect("a session key"),
    );
    let store =
        kr_crypto::store::open_store_in(&environment.secrets_dir()).expect("a secret store");
    let controller = Arc::new(
        ControllerIdentity::initialise(store.store.as_ref(), environment_id)
            .expect("a controller identity"),
    );
    let config = SessionConfig {
        session_id,
        session_epoch: SessionEpoch::V1,
        environment_id,
        display_number: DisplayNumber::new(1),
        shell: kr_worker::testing::posix_script("exec cat"),
        shell_mode: ShellMode::NativeCompat,
        worker_profile: WorkerProfile::HeadlessUser,
        desktop: DesktopBinding::none(),
        dimensions: Dimensions::new(80, 24),
        journal_path: Some(environment.journal_database(session_id)),
        spool_directory: Some(environment.session_spool(session_id)),
        worker_endpoint: None,
        send_queue_bytes: 1024 * 1024,
        resident_bytes: 64 * 1024,
        time: kr_worker::action::time::TimeSources::system(),
        launch_profile: kr_protocol::session::LaunchProfile::default(),
    };
    let journal_path = config.journal_path.clone().expect("the harness journals");
    if let Some(parent) = journal_path.parent() {
        std::fs::create_dir_all(parent).expect("the journal directory");
    }
    let mut session = TerminalSession::open(config).expect("opens the session");
    session.launch().expect("launches the shell");
    let runtime = Arc::new(
        SessionRuntime::start(session, Arc::new(kr_ipc::clock::SystemSharedClock))
            .expect("starts the runtime"),
    );
    let endpoint = environment
        .worker_endpoint(DisplayNumber::new(1))
        .expect("an endpoint");
    let listener = Listener::bind(&endpoint).expect("binds the endpoint");
    let service = Arc::new(
        WorkerService::new(
            Arc::clone(&runtime),
            identity,
            endpoint.clone(),
            ServiceBinding {
                environment_id,
                boot_identity: boot.clone(),
                controller_public_key: *controller.public_key(),
                controller_generation: ControllerGeneration::new(1),
                journal_path: Some(journal_path),
                build_id: build(),
            },
        )
        .expect("a worker service"),
    );
    tokio::spawn(Arc::clone(&service).serve(listener));

    let broker = service.broker();
    broker
        .register_instance(
            instance(),
            IntegrationMode::Gateway,
            None,
            Some(managed(instance(), 41)),
        )
        .expect("the instance is registered");
    broker
        .bind(
            binding(),
            instance(),
            plugin(),
            publisher(),
            package_digest(),
            BrokerGrants::granted([
                BrokerGrant::UpstreamAction,
                BrokerGrant::ApprovalInterpreter,
            ]),
            Some(DecodingTrust {
                plugin_id: plugin(),
                publisher_id: publisher(),
                package_digest: package_digest(),
                methods: [permission()].into_iter().collect(),
                schema_versions: ["kr-approval/1".to_owned()].into_iter().collect(),
                max_decisions: U64::new(4),
                may_encode_response: true,
                granted_at: TimestampMs::new(1),
            }),
            TimestampMs::new(1),
        )
        .expect("the binding carries the interpreter grant");
    broker
        .record_capability(kr_protocol::broker::InstanceCapabilityRecord {
            capability_id: CapabilityId::new("agent.approval").expect("a capability"),
            capability_version: "1".to_owned(),
            application_instance_id: instance(),
            identity: kr_protocol::broker::InstanceCapabilityIdentity::default(),
            revision: CapabilityRevision::new(1),
            state: kr_protocol::broker::InstanceCapabilityState::QualifiedAvailable,
            source: kr_protocol::broker::InstanceEvidenceSource::HostProbe,
            invalidated_by: [kr_protocol::broker::InstanceInvalidation::BindingChanged]
                .into_iter()
                .collect(),
            disabled_reason: Nullable::null(),
            observed_at: TimestampMs::new(1),
        })
        .expect("the evidence is recorded");
    broker
        .pin_table(
            instance(),
            kr_worker::broker::PackageIdentity {
                plugin_id: plugin(),
                publisher_id: publisher(),
                package_digest: package_digest(),
            },
            approval_table(),
            RichMethodTable {
                table_version: MethodTableVersion::new(1),
                upstream_protocol_version: "1".to_owned(),
                entries: vec![kr_protocol::gateway::RichMethodEntry {
                    method: UpstreamMethod::new("session/cancel").expect("a method"),
                    class: NativeMethodClass::Mutation,
                    required_right: ActionRight::AgentCancel,
                    operation: Nullable::some(kr_protocol::gateway::RichOperation::TurnCancel),
                    provenance: kr_protocol::broker::ActionProvenance::UpstreamTypedRpc,
                }],
            },
        )
        .expect("the installed tables are pinned");
    let connection = broker
        .open_native_connection(instance(), &[9; 32], &process(41), &plugin(), "1")
        .expect("the native connection is authenticated");
    broker.bind_connection_dispatch(connection, Arc::new(Answering) as Arc<dyn UpstreamDispatch>);
    // Observed from the start, and read by nobody until the test says so.
    let observations = broker.observatory().subscribe(connection);
    Host {
        _temp: temp,
        service,
        runtime,
        session_id,
        environment_id,
        endpoint,
        controller,
        boot,
        connection,
        observations: Some(observations),
        delivering: None,
    }
}

/// Records one native request that arrived at `at_ms`. Until a decoder interprets it, it is a
/// request of the upstream's the broker holds opaquely, a reverse call.
fn arrive(host: &Host, at_ms: u64) -> PendingResourceId {
    host.service
        .broker()
        .forward_native(host.connection, &request_frame(), TimestampMs::new(at_ms))
        .expect("forwarded")
        .1
        .expect("it expects a response")
        .resource_id
}

/// Has the package's decoder interpret a recorded request, which makes it an approval.
fn interpret(host: &Host, resource_id: PendingResourceId) {
    host.service
        .broker()
        .interpret(binding(), resource_id, projection(), Some(DEADLINE), now())
        .expect("interpreted");
}

/// Records one native request that arrived at `at_ms`, and interprets it: an approval.
fn offer(host: &Host, at_ms: u64) -> PendingResourceId {
    let resource_id = arrive(host, at_ms);
    interpret(host, resource_id);
    resource_id
}

/// The upstream withdraws one of its requests.
fn withdraw(host: &Host, resource_id: PendingResourceId) {
    let broker = host.service.broker();
    let request = broker.pending(resource_id).expect("held").request;
    broker
        .upstream_resolved(&request, now())
        .expect("the upstream withdrew it");
}

/// A person's answer claims one approval.
fn claim(host: &Host, resource_id: PendingResourceId) -> MutationAdmission {
    host.service
        .broker()
        .admit_approval(
            &kr_worker::broker::Caller {
                actor_id: ActorId::new("local:a-test-user").expect("an actor"),
                grant_id: None,
            },
            &AgentApprovalRespondParams {
                target: AgentMutationTarget {
                    subject: subject(host.session_id, instance()),
                    binding_revision: AgentBindingRevision::new(1),
                },
                resource_id,
                option_id: "allow".to_owned(),
            },
            now(),
        )
        .expect("an answer claims the approval")
}

/// The answer is given back before anything went, so the approval can be answered again.
fn release(host: &Host, admitted: &MutationAdmission) {
    host.service
        .broker()
        .release_claim(
            &admitted.claim().expect("the admission holds a claim"),
            now(),
        )
        .expect("the claim is given back");
}

/// The claimed answer goes to the upstream, which takes it.
async fn resolve(host: &Host, admitted: &MutationAdmission) {
    host.service
        .broker()
        .record_approval(admitted, now())
        .expect("carried")
        .settled(now())
        .await
        .expect("answered");
}

/// A request recorded now, which every view in these tests that reaches the live moment is shown:
/// the transition a test waits for to know that everything committed before it has been judged.
fn marker(host: &Host) -> PendingResourceId {
    arrive(host, now().get())
}

/// A grant's history scope reaching back to `lower_bound_ms` (none keeps no retained history),
/// including the live screen, and naming the approvals it names by the resource the broker
/// arbitrates for each.
fn reach(lower_bound_ms: Option<u64>, named: &[PendingResourceId]) -> HistoryScope {
    HistoryScope {
        lower_bound_ms: Nullable(lower_bound_ms.map(TimestampMs::new)),
        include_live_screen: true,
        named_questions: CanonicalSet::new(),
        named_approvals: named.iter().copied().collect(),
    }
}

/// The envelope the control daemon vouches for a paired device acting under a grant.
fn device() -> ActorEnvelope {
    ActorEnvelope {
        actor_id: ActorId::new("device:a-test-phone").expect("an actor"),
        ingress: ActorIngress::PairedDevice,
        device_id: Nullable::some(DeviceId::new(Uuid::from_bytes([9; 16]))),
        grant_id: Nullable::some(GrantId::new(Uuid::from_bytes([8; 16]))),
        grant_revision: Nullable::some(AuthorityRevision::new(1)),
        controller_generation: ControllerGeneration::new(1),
        connection_id: ConnectionId::new(Uuid::from_bytes([7; 16])),
    }
}

/// One view of the session: a connection, who it reads as, and the resource events it has been
/// sent that the test has not looked at yet.
struct Viewer {
    client: LocalClient,
    /// The device the daemon forwards this connection's requests for; `None` is the local owner in
    /// a window of its own.
    device: Option<ActorEnvelope>,
    /// The history scope the daemon sends with each of the device's reads, when it sends one.
    scope: Option<HistoryScope>,
    /// The attachment this view subscribes.
    attachment: Option<AttachmentId>,
    /// Resource events that arrived while the test was waiting for an answer.
    told: VecDeque<AgentResourceEvent>,
}

impl Viewer {
    /// A paired device, over a link the daemon opened for its connection, reading with `scope`.
    async fn device(host: &Host, scope: Option<HistoryScope>) -> Self {
        let mut client = within(
            "the daemon's connection",
            LocalClient::connect(&host.endpoint, LocalClientKind::Controller, build()),
        )
        .await
        .expect("connects as the daemon");
        within(
            "the role",
            client.writer().write_message(&ControlFrame::ControllerRole(
                ControllerConnectionRole::Proxy,
            )),
        )
        .await
        .expect("declares the role");
        match within("the worker's answer to the role", client.recv())
            .await
            .expect("the worker answers")
        {
            ControlFrame::ControllerRole(ControllerConnectionRole::Proxy) => {}
            other => panic!("the worker answered {other:?}"),
        }
        let identity = Arc::clone(&host.controller);
        let boot = host.boot.clone();
        within(
            "the worker's acceptance of the generation",
            client.present_generation(move |nonce| {
                identity
                    .generation_token(ControllerGeneration::new(1), &boot, nonce)
                    .map_err(kr_ipc::IpcError::from)
            }),
        )
        .await
        .expect("the worker accepts the generation");
        Self {
            client,
            device: Some(device()),
            scope,
            attachment: None,
            told: VecDeque::new(),
        }
    }

    /// The local owner, in a window of its own on the worker's socket.
    async fn owner(host: &Host) -> Self {
        let client = within(
            "a window's connection",
            LocalClient::connect(&host.endpoint, LocalClientKind::Cli, build()),
        )
        .await
        .expect("connects");
        Self {
            client,
            device: None,
            scope: None,
            attachment: None,
            told: VecDeque::new(),
        }
    }

    /// Writes one frame and returns the worker's answer to it, keeping the resource events that
    /// arrive first.
    async fn call(
        &mut self,
        frame: ControlFrame,
        request_id: RequestId,
    ) -> Result<ParamsValue, ProtocolError> {
        within("the worker's answer", async {
            self.client
                .writer()
                .write_message(&frame)
                .await
                .expect("writes the request");
            loop {
                match self.client.recv().await.expect("the worker answers") {
                    ControlFrame::Response(response) if response.request_id == request_id => {
                        return match response.outcome {
                            Outcome::Ok(value) => Ok(value),
                            Outcome::Error(error) => Err(error),
                        };
                    }
                    ControlFrame::Notification(notification)
                        if notification.event_type.as_str() == AGENT_RESOURCE_EVENT =>
                    {
                        self.told.push_back(
                            notification
                                .payload
                                .to_typed()
                                .expect("a resource event decodes"),
                        );
                    }
                    _ => {}
                }
            }
        })
        .await
    }

    /// Reads `method`: forwarded by the daemon for the device, with its scope, or in the window.
    async fn read<T: serde::Serialize>(
        &mut self,
        method: Method,
        params: &T,
    ) -> Result<ParamsValue, ProtocolError> {
        let request_id = next_request();
        let request = Request {
            request_id,
            method: method.into(),
            method_version: MethodVersion::V1,
            params: ParamsValue::from_typed(params).expect("encodes"),
        };
        let frame = match self.device.as_ref() {
            Some(actor) => ControlFrame::ForwardedRead(Box::new(ForwardedRequest {
                request,
                actor: actor.clone(),
                authority_deadline_boot_ms: Nullable::some(U64::new(
                    kr_ipc::clock::boot_elapsed_ms() + 30_000,
                )),
                history: self.scope.clone(),
            })),
            None => ControlFrame::Request(request),
        };
        self.call(frame, request_id).await
    }

    /// Makes one mutation: forwarded by the daemon for the device, admitted under a grant that
    /// lets it watch the session, or in the window.
    async fn mutate<T: serde::Serialize>(
        &mut self,
        host: &Host,
        method: Method,
        params: &T,
    ) -> ParamsValue {
        match self.device.clone() {
            Some(actor) => {
                let request_id = next_request();
                let mutation = MutationRequest {
                    request_id,
                    method: method.into(),
                    method_version: MethodVersion::V1,
                    action_id: ActionId::new(kr_ipc::new_uuid()),
                    target: host.target(),
                    params: ParamsValue::from_typed(params).expect("encodes"),
                    grant_id: Nullable::null(),
                    expected: ParamsValue::empty(),
                    action_window_id: ActionWindowId::new("forwarded")
                        .expect("a window identifier"),
                    requested_ttl_ms: kr_protocol::limits::DEFAULT_MUTATION_TTL,
                };
                let frame = ControlFrame::Forwarded(Box::new(ForwardedMutation {
                    mutation,
                    actor,
                    grant_rights: [ActionRight::SessionView].into_iter().collect(),
                    accepted_deadline_boot_ms: U64::new(kr_ipc::clock::boot_elapsed_ms() + 30_000),
                }));
                self.call(frame, request_id)
                    .await
                    .unwrap_or_else(|error| panic!("{} is admitted: {error:?}", method.as_str()))
            }
            None => within(
                "the window's mutation",
                self.client.mutate(
                    method,
                    ActionId::new(kr_ipc::new_uuid()),
                    host.target(),
                    params,
                ),
            )
            .await
            .expect("the call reaches the worker")
            .unwrap_or_else(|error| panic!("{} is admitted: {error:?}", method.as_str())),
        }
    }

    /// Attaches a terminal that watches the session.
    async fn attach(&mut self, host: &Host) -> AttachmentId {
        let attached: SessionAttachResult = self
            .mutate(host, Method::SessionAttach, &host.terminal())
            .await
            .to_typed()
            .expect("an attachment");
        let attachment_id = attached.attachment.attachment_id;
        self.attachment = Some(attachment_id);
        attachment_id
    }

    /// Detaches this view's terminal.
    async fn detach(&mut self, host: &Host) {
        let attachment_id = self.attachment.take().expect("an attachment");
        self.mutate(
            host,
            Method::SessionDetach,
            &SessionDetachParams {
                attachment_id: Nullable::some(attachment_id),
                line_token: Nullable::null(),
            },
        )
        .await;
    }

    /// Subscribes this view's terminal to the session's events, and returns the first page of the
    /// resources the subscription starts from.
    async fn subscribe(&mut self, host: &Host) -> AgentResourceSnapshot {
        let params = EventsSubscribeParams {
            session_id: host.session_id,
            attachment_id: self.attachment.expect("an attachment to subscribe"),
            streams: [EventStream::Output].into_iter().collect(),
            from_cursor: Nullable::null(),
        };
        let subscribed: EventsSubscribeResult = self
            .read(Method::EventsSubscribe, &params)
            .await
            .expect("the subscription is answered")
            .to_typed()
            .expect("a subscription");
        subscribed.agent_resources
    }

    /// Takes a snapshot, or reads the page a continuation names.
    async fn snapshot(
        &mut self,
        host: &Host,
        from: Option<AgentResourceSnapshotContinuation>,
    ) -> Result<AgentResourceSnapshot, ProtocolError> {
        let params = EventsSnapshotParams {
            session_id: host.session_id,
            agent_resources_from: Nullable(from),
        };
        self.read(Method::EventsSnapshot, &params)
            .await
            .map(|answer| {
                answer
                    .to_typed::<EventsSnapshotResult>()
                    .expect("a snapshot")
                    .agent_resources
            })
    }

    /// Reads the pages that follow `first`, and returns every resource the snapshot holds.
    async fn whole(&mut self, host: &Host, first: &AgentResourceSnapshot) -> Vec<PendingResource> {
        let mut resources = first.resources.clone();
        let mut after = first.continue_after.0;
        while let Some(after_resource_id) = after {
            let page = self
                .snapshot(
                    host,
                    Some(AgentResourceSnapshotContinuation {
                        snapshot_id: first.snapshot_id,
                        after_resource_id,
                    }),
                )
                .await
                .expect("a snapshot that has not ended is read to its end");
            resources.extend(page.resources);
            after = page.continue_after.0;
        }
        resources
    }

    /// Returns every resource event this view is sent, in order, up to and including the first
    /// one `last` picks out.
    async fn told_until(
        &mut self,
        last: impl Fn(&AgentResourceEvent) -> bool,
    ) -> Vec<AgentResourceEvent> {
        let mut told = Vec::new();
        let arrived = tokio::time::timeout(LIVENESS_DEADLINE, async {
            loop {
                let event = match self.told.pop_front() {
                    Some(event) => event,
                    None => loop {
                        if let ControlFrame::Notification(notification) =
                            self.client.recv().await.expect("the worker is serving")
                            && notification.event_type.as_str() == AGENT_RESOURCE_EVENT
                        {
                            break notification
                                .payload
                                .to_typed()
                                .expect("a resource event decodes");
                        }
                    },
                };
                let found = last(&event);
                told.push(event);
                if found {
                    return;
                }
            }
        })
        .await;
        assert!(
            arrived.is_ok(),
            "the awaited event within {LIVENESS_DEADLINE:?}; told {:?}",
            summary(&told)
        );
        told
    }

    /// Returns every resource event this view is sent up to and including the first about `last`.
    async fn told_through(&mut self, last: PendingResourceId) -> Vec<AgentResourceEvent> {
        self.told_until(|event| event.resource_id == last).await
    }
}

/// The resources a page or a snapshot carries, in the order it carries them.
fn carried(resources: &[PendingResource]) -> Vec<PendingResourceId> {
    resources
        .iter()
        .map(|resource| resource.resource_id)
        .collect()
}

/// The same resources, in identifier order, which is the order a snapshot carries them in.
fn sorted(resources: &[PendingResourceId]) -> Vec<PendingResourceId> {
    let mut sorted = resources.to_vec();
    sorted.sort_unstable();
    sorted
}

/// What each event was about and what its resource became, for a failure message.
fn summary(events: &[AgentResourceEvent]) -> Vec<(String, PendingState, u64)> {
    events
        .iter()
        .map(|event| {
            (
                event.resource_id.to_string(),
                event.state,
                event.sequence.get(),
            )
        })
        .collect()
}

/// The events about one resource, in the order they were sent.
fn about(events: &[AgentResourceEvent], resource_id: PendingResourceId) -> Vec<AgentResourceEvent> {
    events
        .iter()
        .filter(|event| event.resource_id == resource_id)
        .cloned()
        .collect()
}

/// The events about one resource that came after a snapshot's position.
///
/// A control reads without a scope and is told the transitions a snapshot covers as well, as a
/// view always was; this is the part of what it was told that a device's view can be compared with.
fn about_after(
    events: &[AgentResourceEvent],
    resource_id: PendingResourceId,
    snapshot: &AgentResourceSnapshot,
) -> Vec<AgentResourceEvent> {
    about(events, resource_id)
        .into_iter()
        .filter(|event| {
            event.stream_generation != snapshot.stream_generation
                || event.sequence.get() > snapshot.cursor.get()
        })
        .collect()
}

/// The resources a run of events was about.
fn resources_in(events: &[AgentResourceEvent]) -> BTreeSet<PendingResourceId> {
    events.iter().map(|event| event.resource_id).collect()
}

/// A device and both controls, each attached and subscribed: the device under `scope`, the local
/// owner in a window of its own, and the same device reading without a scope.
struct Views {
    phone: Viewer,
    owner: Viewer,
    unscoped: Viewer,
    /// The first page each subscription started from, in the same order.
    phone_page: AgentResourceSnapshot,
    owner_page: AgentResourceSnapshot,
    unscoped_page: AgentResourceSnapshot,
}

async fn views(host: &Host, scope: HistoryScope) -> Views {
    let mut phone = Viewer::device(host, Some(scope)).await;
    phone.attach(host).await;
    let phone_page = phone.subscribe(host).await;
    let mut owner = Viewer::owner(host).await;
    owner.attach(host).await;
    let owner_page = owner.subscribe(host).await;
    let mut unscoped = Viewer::device(host, None).await;
    unscoped.attach(host).await;
    let unscoped_page = unscoped.subscribe(host).await;
    Views {
        phone,
        owner,
        unscoped,
        phone_page,
        owner_page,
        unscoped_page,
    }
}

// -------------------------------------------------------------------------------------------------
// The snapshot
// -------------------------------------------------------------------------------------------------

/// KR-REQ-10.51: a device's snapshot carries the approval its grant names while it can still be
/// decided, and what was recorded at or after the moment its grant reaches back to, whatever its
/// kind. It carries no approval the grant does not name, no request from before that moment, and
/// no named approval that has already ended. The subscription's first page, a fresh snapshot on
/// the same connection and a snapshot on a connection that subscribed nothing all answer alike.
/// The controls are shown every resource.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_10_51_a_devices_snapshot_carries_what_its_grant_reaches_and_nothing_older() {
    let host = host().await;
    let unnamed = offer(&host, BEFORE);
    let request = arrive(&host, BEFORE);
    let named = offer(&host, BEFORE);
    let at_the_bound = offer(&host, BOUND);
    let later_request = arrive(&host, AFTER);
    let ended = offer(&host, BEFORE);
    withdraw(&host, ended);
    let every = sorted(&[unnamed, request, named, at_the_bound, later_request, ended]);
    let reached = sorted(&[named, at_the_bound, later_request]);

    let scope = reach(Some(BOUND), &[named, ended]);
    let mut views = views(&host, scope.clone()).await;
    assert_eq!(
        carried(&views.phone_page.resources),
        reached,
        "the device's subscription starts from what its grant reaches"
    );
    let fresh = views
        .phone
        .snapshot(&host, None)
        .await
        .expect("a fresh snapshot is answered");
    assert_eq!(
        carried(&fresh.resources),
        reached,
        "and so does a fresh snapshot on the same connection"
    );
    let mut unsubscribed = Viewer::device(&host, Some(scope)).await;
    let alone = unsubscribed
        .snapshot(&host, None)
        .await
        .expect("a snapshot is answered");
    assert_eq!(
        carried(&alone.resources),
        reached,
        "and a snapshot on a connection that subscribed nothing"
    );

    assert_eq!(carried(&views.owner_page.resources), every, "the owner");
    assert_eq!(
        carried(&views.unscoped_page.resources),
        every,
        "a read without a scope"
    );
    let unscoped_fresh = views
        .unscoped
        .snapshot(&host, None)
        .await
        .expect("a fresh snapshot is answered");
    assert_eq!(carried(&unscoped_fresh.resources), every);
    host.finish();
}

/// KR-REQ-10.51: a grant that keeps no retained history is shown the current approval it names,
/// and of everything else only what is recorded after its view began: the screen that is showing
/// and what follows it. A name is for an approval, so a request the grant names that is not one is
/// held to the same rule. Without the live screen, such a grant is shown the named approval and
/// nothing that follows it. The controls are shown everything.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_10_51_a_grant_that_keeps_no_history_is_shown_the_approval_it_names_and_what_follows()
 {
    let mut host = host().await;
    let named = offer(&host, BEFORE);
    let unnamed = offer(&host, BEFORE);
    let named_request = arrive(&host, BEFORE);
    let recorded_earlier = offer(&host, AFTER);
    let every = sorted(&[named, unnamed, named_request, recorded_earlier]);

    let mut views = views(&host, reach(None, &[named, named_request])).await;
    assert_eq!(
        carried(&views.phone_page.resources),
        [named],
        "a grant that keeps no history is shown the approval it names and nothing older"
    );
    let mut without_the_screen = Viewer::device(
        &host,
        Some(HistoryScope {
            include_live_screen: false,
            ..reach(None, &[named])
        }),
    )
    .await;
    without_the_screen.attach(&host).await;
    assert_eq!(
        carried(&without_the_screen.subscribe(&host).await.resources),
        [named]
    );
    assert_eq!(carried(&views.owner_page.resources), every);
    assert_eq!(carried(&views.unscoped_page.resources), every);

    host.deliver();
    let began = now().get();
    let recorded_since = offer(&host, began);
    let recorded_as_of_old = offer(&host, BEFORE);
    let last = marker(&host);
    let phone = views.phone.told_through(last).await;
    assert_eq!(
        resources_in(&phone),
        [recorded_since, last].into_iter().collect(),
        "a live view is told what is recorded after it began, and nothing recorded before: {:?}",
        summary(&phone)
    );
    let owner = views.owner.told_through(last).await;
    assert!(
        [recorded_since, recorded_as_of_old, last]
            .iter()
            .all(|resource_id| !about(&owner, *resource_id).is_empty()),
        "the owner is told everything: {:?}",
        summary(&owner)
    );
    let unscoped = views.unscoped.told_through(last).await;
    assert_eq!(resources_in(&unscoped), resources_in(&owner));

    // The approval it names reaches the view without the screen, and nothing else does.
    let admitted = claim(&host, named);
    let blind = without_the_screen
        .told_until(|event| event.resource_id == named && event.state == PendingState::Claimed)
        .await;
    assert_eq!(
        resources_in(&blind),
        [named].into_iter().collect(),
        "{:?}",
        summary(&blind)
    );
    drop(admitted);
    host.finish();
}

// -------------------------------------------------------------------------------------------------
// The transitions that follow it
// -------------------------------------------------------------------------------------------------

/// KR-REQ-10.51: a transition the snapshot already covers is dropped for the device's view before
/// anything is decided about it, whatever it says. A named approval that ended before the device
/// subscribed is not in the device's snapshot, and the transitions that recorded it, committed
/// before the subscription and delivered after it, do not reach the device either: judged on
/// their own, the first of them would pass as a current named approval. The controls are told
/// every one of them, as before.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_10_51_a_transition_the_snapshot_covers_is_dropped_whatever_it_says() {
    let mut host = host().await;
    // Nothing is delivered yet: each of these transitions waits in the queue.
    let ended = offer(&host, BEFORE);
    withdraw(&host, ended);
    let shown = offer(&host, AFTER);
    let mut views = views(&host, reach(Some(BOUND), &[ended])).await;
    assert_eq!(carried(&views.phone_page.resources), [shown]);

    host.deliver();
    let last = marker(&host);
    let phone = views.phone.told_through(last).await;
    assert_eq!(
        resources_in(&phone),
        [last].into_iter().collect(),
        "every transition committed before the subscription is covered by its snapshot: {:?}",
        summary(&phone)
    );
    for control in [&mut views.owner, &mut views.unscoped] {
        let told = control.told_through(last).await;
        assert_eq!(
            about(&told, ended).last().map(|event| event.state),
            Some(PendingState::Cancelled),
            "{:?}",
            summary(&told)
        );
        assert!(!about(&told, shown).is_empty(), "{:?}", summary(&told));
    }
    host.finish();
}

/// KR-REQ-10.51: after the snapshot, each transition is decided by the same rule. Every transition
/// of an approval the device was shown reaches it, through a claim given back and on to its end;
/// a request recorded since the moment the grant reaches back to reaches it from its first
/// transition; nothing about a request from before that moment does, however it changes, and a
/// request recorded now with an earlier moment is judged by that moment. The controls are told
/// every transition.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_10_51_later_transitions_reach_a_devices_view_by_the_same_rule() {
    let mut host = host().await;
    let named = offer(&host, BEFORE);
    let unnamed = offer(&host, BEFORE);
    let request = arrive(&host, BEFORE);
    let mut views = views(&host, reach(Some(BOUND), &[named])).await;
    assert_eq!(carried(&views.phone_page.resources), [named]);
    host.deliver();

    let answer = claim(&host, named);
    release(&host, &answer);
    let answer = claim(&host, named);
    resolve(&host, &answer).await;
    let other = claim(&host, unnamed);
    release(&host, &other);
    withdraw(&host, unnamed);
    withdraw(&host, request);
    let recent = offer(&host, AFTER);
    withdraw(&host, recent);
    let backdated = offer(&host, BEFORE);
    let last = marker(&host);

    let owner = views.owner.told_through(last).await;
    let unscoped = views.unscoped.told_through(last).await;
    assert_eq!(summary(&owner), summary(&unscoped));
    for resource_id in [named, unnamed, request, recent, backdated] {
        assert!(
            !about(&owner, resource_id).is_empty(),
            "the owner is told about {resource_id}: {:?}",
            summary(&owner)
        );
    }
    let phone = views.phone.told_through(last).await;
    assert_eq!(
        about(&phone, named),
        about_after(&owner, named, &views.phone_page),
        "every transition of the named approval, its end included"
    );
    assert_eq!(
        about(&phone, named).last().map(|event| event.state),
        Some(PendingState::Resolved)
    );
    assert_eq!(
        about(&phone, recent),
        about_after(&owner, recent, &views.phone_page),
        "every transition of a request recorded inside the bound"
    );
    assert_eq!(
        resources_in(&phone),
        [named, recent, last].into_iter().collect(),
        "and nothing about a request from before the bound: {:?}",
        summary(&phone)
    );
    host.finish();
}

/// KR-REQ-10.51: a request the grant names is held to the bound while it is a reverse call, since
/// a name is for an approval, and reaches the device once it is interpreted as one. Its transitions
/// are delivered after the interpretation here, so they are judged by what the resource is when
/// they arrive; a named request that is never interpreted stays withheld to its end. The controls
/// are told every transition.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_10_51_a_named_request_reaches_the_device_once_it_is_an_approval() {
    let mut host = host().await;
    let interpreted = arrive(&host, BEFORE);
    let stays_a_request = arrive(&host, BEFORE);
    let mut views = views(&host, reach(Some(BOUND), &[interpreted, stays_a_request])).await;
    assert!(
        views.phone_page.resources.is_empty(),
        "a named request that is not an approval is held to the bound: {:?}",
        carried(&views.phone_page.resources)
    );

    // Both wait in the queue until after the interpretation.
    interpret(&host, interpreted);
    withdraw(&host, stays_a_request);
    host.deliver();
    withdraw(&host, interpreted);
    let last = marker(&host);

    let owner = views.owner.told_through(last).await;
    let phone = views.phone.told_through(last).await;
    let after_the_snapshot = about_after(&owner, interpreted, &views.phone_page);
    assert_eq!(
        after_the_snapshot.first().map(|event| event.state),
        Some(PendingState::Pending),
        "the interpretation is a transition of its own: {:?}",
        summary(&owner)
    );
    assert_eq!(
        about(&phone, interpreted),
        after_the_snapshot,
        "the device is told from the interpretation on, its end included: {:?}",
        summary(&phone)
    );
    assert!(
        about(&phone, stays_a_request).is_empty(),
        "{:?}",
        summary(&phone)
    );
    assert!(!about(&owner, stays_a_request).is_empty());
    let unscoped = views.unscoped.told_through(last).await;
    assert_eq!(summary(&unscoped), summary(&owner));
    host.finish();
}

/// KR-REQ-10.51: a transition recovered from the outbox is held to the same rule as one delivered
/// live. Nothing reads the queue while more transitions are committed than it holds, so it
/// overflows and the delivery recovers the rest from what the broker recorded. The device is told
/// what its grant reaches and nothing else; the controls are told every recovered transition.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_10_51_a_recovered_transition_is_held_to_the_same_rule() {
    let mut host = host().await;
    let named = offer(&host, BEFORE);
    let unnamed = offer(&host, BEFORE);
    let mut views = views(&host, reach(Some(BOUND), &[named])).await;

    let old: Vec<PendingResourceId> = (0..kr_worker::broker::MAX_QUEUED_OBSERVATIONS + 8)
        .map(|_| arrive(&host, BEFORE))
        .collect();
    let answer = claim(&host, named);
    withdraw(&host, unnamed);
    let recent = arrive(&host, AFTER);
    host.deliver();
    let last = marker(&host);

    let owner = views.owner.told_through(last).await;
    assert!(
        old.iter()
            .all(|resource_id| !about(&owner, *resource_id).is_empty()),
        "the owner is told every transition, the recovered ones included"
    );
    let unscoped = views.unscoped.told_through(last).await;
    assert_eq!(summary(&unscoped), summary(&owner));
    let phone = views.phone.told_through(last).await;
    assert_eq!(
        resources_in(&phone),
        [named, recent, last].into_iter().collect(),
        "the device is told what its grant reaches, recovered or not: {:?}",
        summary(&phone)
    );
    assert_eq!(
        about(&phone, named).last().map(|event| event.state),
        Some(PendingState::Claimed)
    );
    drop(answer);
    host.finish();
}

/// KR-REQ-10.51: a snapshot too large for one page is filtered before it is paged, so no page
/// carries a resource the grant does not reach and the pages are the resources it does. What the
/// device was shown is the whole snapshot and not the page it has read: an approval its grant
/// names that ends before the device has read the page carrying it is told about, though its end
/// alone would be withheld, and the page still carries it as the copy had it. The owner's pages
/// carry every resource.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_10_51_a_shown_approval_that_ends_before_its_page_is_read_is_told_about() {
    let mut host = host().await;
    let old: Vec<PendingResourceId> = (0..8).map(|_| offer(&host, BEFORE)).collect();
    let named: Vec<PendingResourceId> = (0..kr_worker::broker::MAX_SNAPSHOT_RESOURCES + 20)
        .map(|_| offer(&host, BEFORE))
        .collect();

    let mut phone = Viewer::device(&host, Some(reach(Some(BOUND), &named))).await;
    phone.attach(&host).await;
    let first = phone.subscribe(&host).await;
    assert!(
        first.continue_after.is_present(),
        "the snapshot takes more than one page"
    );
    host.deliver();
    let on_a_later_page = *named
        .iter()
        .find(|resource_id| {
            !first
                .resources
                .iter()
                .any(|held| held.resource_id == **resource_id)
        })
        .expect("an approval the first page does not carry");
    withdraw(&host, on_a_later_page);
    let last = marker(&host);
    let told = phone.told_through(last).await;
    assert_eq!(
        about(&told, on_a_later_page)
            .iter()
            .map(|event| event.state)
            .collect::<Vec<_>>(),
        [PendingState::Cancelled],
        "the end of an approval on a page the device has not read yet: {:?}",
        summary(&told)
    );
    assert_eq!(
        resources_in(&told),
        [on_a_later_page, last].into_iter().collect(),
        "{:?}",
        summary(&told)
    );

    let pages = phone.whole(&host, &first).await;
    assert_eq!(
        sorted(&carried(&pages)),
        sorted(&named),
        "the pages are what the grant reaches"
    );
    assert_eq!(
        pages
            .iter()
            .find(|resource| resource.resource_id == on_a_later_page)
            .map(|resource| resource.state),
        Some(PendingState::Pending),
        "a page is cut from the copy taken with the subscription"
    );

    let mut owner = Viewer::owner(&host).await;
    let owners_first = owner
        .snapshot(&host, None)
        .await
        .expect("a snapshot is answered");
    let owners = owner.whole(&host, &owners_first).await;
    let mut every = old;
    every.extend(named);
    every.push(last);
    assert_eq!(sorted(&carried(&owners)), sorted(&every));
    host.finish();
}

// -------------------------------------------------------------------------------------------------
// What a subscription keeps
// -------------------------------------------------------------------------------------------------

/// KR-REQ-10.51: a live view's moment is the one its attachment's first subscription began at. A
/// fresh snapshot on that connection and a second subscription of the attachment keep it, so what
/// was recorded since then stays in what they carry; a snapshot on a connection that subscribed
/// nothing reaches from its own moment, and once the attachment has gone, so does a snapshot on
/// the connection it was subscribed on.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_10_51_a_live_view_keeps_the_moment_its_first_subscription_began() {
    let mut host = host().await;
    let earlier = offer(&host, AFTER);
    let scope = reach(None, &[]);
    let mut phone = Viewer::device(&host, Some(scope.clone())).await;
    phone.attach(&host).await;
    let first = phone.subscribe(&host).await;
    assert!(
        first.resources.is_empty(),
        "nothing was recorded after the view began: {:?}",
        carried(&first.resources)
    );
    host.deliver();
    let recorded_since = arrive(&host, now().get());
    let told = phone.told_through(recorded_since).await;
    assert_eq!(resources_in(&told), [recorded_since].into_iter().collect());
    // The moment moves on, so a view that began now would not reach it.
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;

    let fresh = phone
        .snapshot(&host, None)
        .await
        .expect("a fresh snapshot is answered");
    assert_eq!(
        carried(&fresh.resources),
        [recorded_since],
        "a fresh snapshot keeps the moment the view began"
    );
    assert_eq!(
        carried(&phone.subscribe(&host).await.resources),
        [recorded_since],
        "and so does a second subscription of the same attachment"
    );
    let mut unsubscribed = Viewer::device(&host, Some(scope)).await;
    assert!(
        unsubscribed
            .snapshot(&host, None)
            .await
            .expect("a snapshot is answered")
            .resources
            .is_empty(),
        "a connection that subscribed nothing reaches from its own moment"
    );

    phone.detach(&host).await;
    assert!(
        phone
            .snapshot(&host, None)
            .await
            .expect("a snapshot is answered")
            .resources
            .is_empty(),
        "and once the attachment has gone, the connection it was subscribed on does too"
    );
    let mut owner = Viewer::owner(&host).await;
    assert_eq!(
        carried(
            &owner
                .snapshot(&host, None)
                .await
                .expect("a snapshot is answered")
                .resources
        ),
        sorted(&[earlier, recorded_since])
    );
    host.finish();
}

/// KR-REQ-10.51: a fresh snapshot on a subscribed connection replaces what the view's transitions
/// are judged by: its position, the resources it was shown, and the scope the snapshot's read came
/// with. A transition the fresh snapshot covers is dropped, though the first one did not cover it,
/// and an approval the new scope no longer names is no longer told about, though the first
/// snapshot showed it. The owner is told both.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_10_51_a_fresh_snapshot_replaces_what_the_view_is_judged_by() {
    let mut host = host().await;
    let named = offer(&host, BEFORE);
    let recent = offer(&host, AFTER);
    let mut phone = Viewer::device(&host, Some(reach(Some(BOUND), &[named]))).await;
    phone.attach(&host).await;
    assert_eq!(
        carried(&phone.subscribe(&host).await.resources),
        sorted(&[named, recent])
    );
    let mut owner = Viewer::owner(&host).await;
    owner.attach(&host).await;
    owner.subscribe(&host).await;

    // Committed after the subscription and before the fresh snapshot, and delivered after both.
    let covered = claim(&host, recent);
    phone.scope = Some(reach(Some(BOUND), &[]));
    let fresh = phone
        .snapshot(&host, None)
        .await
        .expect("a fresh snapshot is answered");
    assert_eq!(carried(&fresh.resources), [recent]);
    host.deliver();
    let unnamed_now = claim(&host, named);
    release(&host, &covered);
    let last = marker(&host);

    let told = phone.told_through(last).await;
    assert_eq!(
        about(&told, recent)
            .iter()
            .map(|event| event.state)
            .collect::<Vec<_>>(),
        [PendingState::Pending],
        "the claim the fresh snapshot covers is dropped, and the release after it is told: {:?}",
        summary(&told)
    );
    assert!(about(&told, named).is_empty(), "{:?}", summary(&told));
    let owner_told = owner.told_through(last).await;
    assert!(
        about(&owner_told, recent)
            .iter()
            .any(|event| event.state == PendingState::Claimed)
    );
    assert!(
        about(&owner_told, named)
            .iter()
            .any(|event| event.state == PendingState::Claimed)
    );
    drop(unnamed_now);
    host.finish();
}

/// KR-REQ-10.51: a transition made while the journal is faulted is judged exactly as any other. The
/// broker keeps its arbitration in memory through the fault and announces what it could not record,
/// so the device is told about a request recorded inside its bound and about the end of an approval
/// it was shown, and not about requests from before its bound. The owner is told every one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_10_51_a_transition_while_the_journal_is_faulted_is_judged_the_same() {
    let mut host = host().await;
    let named = offer(&host, BEFORE);
    let unnamed = offer(&host, BEFORE);
    let mut views = views(&host, reach(Some(BOUND), &[named])).await;
    host.deliver();

    host.service
        .broker()
        .refuse_ledger_writes(true)
        .expect("the store is put in query-only mode");
    let recent = arrive(&host, AFTER);
    let old = arrive(&host, BEFORE);
    withdraw(&host, named);
    withdraw(&host, unnamed);
    let last = marker(&host);

    let phone = views.phone.told_through(last).await;
    assert_eq!(
        resources_in(&phone),
        [recent, named, last].into_iter().collect(),
        "{:?}",
        summary(&phone)
    );
    assert!(
        about(&phone, recent)
            .iter()
            .all(|event| event.durability == Durability::Volatile),
        "announced and not recorded"
    );
    assert_eq!(
        about(&phone, named).last().map(|event| event.state),
        Some(PendingState::Cancelled)
    );
    let owner = views.owner.told_through(last).await;
    for resource_id in [recent, old, named, unnamed] {
        assert!(
            !about(&owner, resource_id).is_empty(),
            "{:?}",
            summary(&owner)
        );
    }
    let unscoped = views.unscoped.told_through(last).await;
    assert_eq!(summary(&unscoped), summary(&owner));
    host.finish();
}

// -------------------------------------------------------------------------------------------------
// The rule, and the session boundary the delivery hands every transition to
// -------------------------------------------------------------------------------------------------

/// KR-REQ-10.51: one rule for every kind of resource the broker arbitrates. An approval the grant
/// names is admitted while it can still be decided, and by the bound once it has ended, as the
/// approval record read decides it; a name is for an approval, so a reverse call and an action this
/// host prepared against the upstream are decided by the bound, whatever the grant names. A
/// resource recorded at the bound is inside it, and without `session.view` nothing is admitted.
#[test]
fn kr_req_10_51_one_rule_decides_every_kind_of_resource() {
    let named = PendingResourceId::new(Uuid::from_bytes([0x71; 16]));
    let unnamed = PendingResourceId::new(Uuid::from_bytes([0x72; 16]));
    let filter = HistoryFilter::new(ViewerScope::from_history(
        &reach(Some(BOUND), &[named]),
        true,
    ));
    for state in PendingState::ALL.iter().copied() {
        assert_eq!(
            filter.admit_resource(PendingKind::Approval, named, BEFORE, state),
            if state.is_terminal() {
                Err(WithheldReason::NotNamedByTheGrant)
            } else {
                Ok(())
            },
            "a named approval, {state:?}"
        );
        for kind in [PendingKind::ReverseRpc, PendingKind::UpstreamAction] {
            assert_eq!(
                filter.admit_resource(kind, named, BEFORE, state),
                Err(WithheldReason::BeforeHistoryBound),
                "a name is for an approval: {kind:?}, {state:?}"
            );
        }
        for kind in PendingKind::ALL.iter().copied() {
            assert_eq!(
                filter.admit_resource(kind, unnamed, BOUND, state),
                Ok(()),
                "at the bound: {kind:?}, {state:?}"
            );
            assert!(
                filter
                    .admit_resource(kind, unnamed, BOUND - 1, state)
                    .is_err(),
                "before the bound: {kind:?}, {state:?}"
            );
        }
    }
    let blind = HistoryFilter::new(ViewerScope::from_history(&reach(Some(0), &[named]), false));
    for kind in PendingKind::ALL.iter().copied() {
        assert_eq!(
            blind.admit_resource(kind, named, AFTER, PendingState::Pending),
            Err(WithheldReason::NoSessionView),
            "{kind:?}"
        );
    }
}

/// KR-REQ-10.51: a live view's scope. A grant that keeps no retained history and includes the live
/// screen reaches what is recorded from the moment the view began, a grant with a bound keeps its
/// bound, and one without the live screen reaches nothing it does not name.
#[test]
fn kr_req_10_51_a_live_view_reaches_what_is_recorded_from_the_moment_it_began() {
    let began = 7_000;
    let resource = PendingResourceId::new(Uuid::from_bytes([0x73; 16]));
    let live = ViewerScope::from_history(&reach(None, &[]), true).live_from(began);
    assert_eq!(live.lower_bound_ms(), Some(began));
    let live = HistoryFilter::new(live);
    assert_eq!(
        live.admit_resource(
            PendingKind::ReverseRpc,
            resource,
            began,
            PendingState::Pending
        ),
        Ok(())
    );
    assert_eq!(
        live.admit_resource(
            PendingKind::ReverseRpc,
            resource,
            began - 1,
            PendingState::Pending
        ),
        Err(WithheldReason::BeforeHistoryBound)
    );
    assert_eq!(
        ViewerScope::from_history(&reach(Some(BOUND), &[]), true)
            .live_from(began)
            .lower_bound_ms(),
        Some(BOUND),
        "a bound the grant set stays"
    );
    let without_the_screen = HistoryScope {
        include_live_screen: false,
        ..reach(None, &[])
    };
    assert_eq!(
        ViewerScope::from_history(&without_the_screen, true)
            .live_from(began)
            .lower_bound_ms(),
        None,
        "without the live screen there is no view to follow"
    );
}

/// The broker's record of one resource, as the delivery reads it before it locks the session.
fn held(host: &Host, resource_id: PendingResourceId) -> PendingResource {
    host.service
        .broker()
        .pending(resource_id)
        .expect("the broker holds it")
}

/// A request the broker would hold as recorded at `at_ms` under `resource_id`, for a transition
/// handed to the session directly.
fn request_like(host: &Host, resource_id: PendingResourceId, at_ms: u64) -> PendingResource {
    let template = held(host, arrive(host, at_ms));
    PendingResource {
        resource_id,
        ..template
    }
}

/// One transition of `resource_id` at `sequence` of the stream run `generation`, as the delivery
/// hands it to the session.
fn transition(
    host: &Host,
    resource_id: PendingResourceId,
    state: PendingState,
    generation: u64,
    sequence: u64,
) -> AgentResourceEvent {
    AgentResourceEvent {
        session_id: host.session_id,
        application_instance_id: instance(),
        resource_id,
        state,
        content: AgentResourceContentClass::ApplicationNotice,
        durability: Durability::Durable,
        cause: AgentResourceCause::Upstream,
        actor_id: Nullable::null(),
        causal_root: format!("synthetic:{sequence}"),
        binding_revision: AgentBindingRevision::new(1),
        stream_generation: U64::new(generation),
        sequence: U64::new(sequence),
        event_id: Uuid::from_bytes(*kr_ipc::new_uuid().as_bytes()),
        parent_sequence: Nullable::null(),
    }
}

/// What a run of events was, one entry per event, for comparing what two views were told.
fn told_as(events: &[AgentResourceEvent]) -> Vec<(PendingResourceId, PendingState, u64, u64)> {
    events
        .iter()
        .map(|event| {
            (
                event.resource_id,
                event.state,
                event.stream_generation.get(),
                event.sequence.get(),
            )
        })
        .collect()
}

/// KR-REQ-10.51: a transition of another run of the broker's stream cannot be placed against the
/// view's snapshot, so the filter alone decides it, and what the view was shown is neither
/// consulted nor changed. The shown approval's transition of another run whose resource cannot be
/// read, and its end, are withheld, and the approval is still shown afterwards; a recent request's
/// transition of another run is told and does not make the request shown. A transition of the
/// snapshot's own run at its position is dropped however shown its resource is. The transitions
/// are handed to the session as the delivery hands it every one, since this host's broker runs one
/// stream; the owner and a read without a scope are told every one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_10_51_a_transition_of_another_run_is_decided_by_the_filter_alone() {
    let host = host().await;
    let named = offer(&host, BEFORE);
    let mut views = views(&host, reach(Some(BOUND), &[named])).await;
    assert_eq!(carried(&views.phone_page.resources), [named]);
    let generation = views.phone_page.stream_generation.get();
    let another = generation + 1;
    let position = views.phone_page.cursor.get();
    let approval = held(&host, named);
    let recent = PendingResourceId::new(Uuid::from_bytes([0x74; 16]));
    let recent_request = request_like(&host, recent, AFTER);
    let last = PendingResourceId::new(Uuid::from_bytes([0x75; 16]));
    let last_request = request_like(&host, last, now().get());

    let sent = [
        (
            transition(&host, named, PendingState::Claimed, another, position + 1),
            None,
        ),
        (
            transition(&host, named, PendingState::Resolved, another, position + 2),
            Some(&approval),
        ),
        (
            transition(
                &host,
                named,
                PendingState::Claimed,
                generation,
                position + 3,
            ),
            None,
        ),
        (
            transition(&host, recent, PendingState::Pending, another, position + 4),
            Some(&recent_request),
        ),
        (
            transition(
                &host,
                recent,
                PendingState::Claimed,
                generation,
                position + 5,
            ),
            None,
        ),
        (
            transition(&host, named, PendingState::Claimed, generation, position),
            Some(&approval),
        ),
        (
            transition(&host, last, PendingState::Pending, generation, position + 6),
            Some(&last_request),
        ),
    ];
    for (event, resource) in &sent {
        host.runtime
            .session()
            .publish_agent_resource(event, *resource);
    }

    let phone = views.phone.told_through(last).await;
    let expected: Vec<AgentResourceEvent> = [2, 3, 6]
        .into_iter()
        .map(|index| sent[index].0.clone())
        .collect();
    assert_eq!(
        told_as(&phone),
        told_as(&expected),
        "the device is told the shown approval's own run, and the recent request of another run"
    );
    let every: Vec<AgentResourceEvent> = sent.iter().map(|(event, _)| event.clone()).collect();
    for control in [&mut views.owner, &mut views.unscoped] {
        assert_eq!(told_as(&control.told_through(last).await), told_as(&every));
    }
    host.finish();
}

/// KR-REQ-10.51: a transition whose resource the broker cannot read reaches only a view that was
/// already shown that resource, and its end takes the resource out of what the view was shown.
/// Within one run the broker reads every resource it has recorded, from its arbitration or its
/// ledger, so these transitions are handed to the session as the delivery hands it one whose
/// resource it could not read: a resource recorded only in memory by an earlier run is one. The
/// owner and a read without a scope are told every one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_10_51_a_resource_the_broker_cannot_read_reaches_only_a_view_shown_it() {
    let host = host().await;
    let named = offer(&host, BEFORE);
    let unnamed = offer(&host, BEFORE);
    let mut views = views(&host, reach(Some(BOUND), &[named])).await;
    assert_eq!(carried(&views.phone_page.resources), [named]);
    let generation = views.phone_page.stream_generation.get();
    let position = views.phone_page.cursor.get();
    let never_held = PendingResourceId::new(Uuid::from_bytes([0x76; 16]));
    let last = PendingResourceId::new(Uuid::from_bytes([0x77; 16]));
    let last_request = request_like(&host, last, now().get());

    let sent = [
        (
            transition(
                &host,
                named,
                PendingState::Claimed,
                generation,
                position + 1,
            ),
            None,
        ),
        (
            transition(
                &host,
                unnamed,
                PendingState::Claimed,
                generation,
                position + 2,
            ),
            None,
        ),
        (
            transition(
                &host,
                never_held,
                PendingState::Pending,
                generation,
                position + 3,
            ),
            None,
        ),
        (
            transition(
                &host,
                named,
                PendingState::Resolved,
                generation,
                position + 4,
            ),
            None,
        ),
        (
            transition(
                &host,
                named,
                PendingState::Pending,
                generation,
                position + 5,
            ),
            None,
        ),
        (
            transition(&host, last, PendingState::Pending, generation, position + 6),
            Some(&last_request),
        ),
    ];
    for (event, resource) in &sent {
        host.runtime
            .session()
            .publish_agent_resource(event, *resource);
    }

    let phone = views.phone.told_through(last).await;
    let expected: Vec<AgentResourceEvent> = [0, 3, 5]
        .into_iter()
        .map(|index| sent[index].0.clone())
        .collect();
    assert_eq!(
        told_as(&phone),
        told_as(&expected),
        "the device is told about what it was shown, up to its end, and about nothing it was not"
    );
    let every: Vec<AgentResourceEvent> = sent.iter().map(|(event, _)| event.clone()).collect();
    for control in [&mut views.owner, &mut views.unscoped] {
        assert_eq!(told_as(&control.told_through(last).await), told_as(&every));
    }
    host.finish();
}
