//! Section 23's state recovery reads - `events.subscribe`, `events.snapshot`, `history.page` and
//! `action.read` - bounded by the stream cursor and the present view authority over their subject,
//! and paged to what their reader can receive.
//!
//! `history.page`'s cursor and range are proved in the persistence suite. These prove the rest,
//! each through the worker's real endpoint, handshake and forwarding: a read names its own session
//! and a subscription its own attachment; a page of the resources a snapshot or a subscription
//! carries is cut to the frame its reader declared, and a reader that follows the continuations
//! reads every resource once; a subscription from a cursor retention has passed is told the range
//! and the bound that took it; a paired device's snapshot and subscription are held to its grant's
//! present view on every page, beside the local owner, who is shown everything, and the device is
//! refused retained history outright; and a receipt answers only the actor whose action it is, only
//! for this worker's own session, and only in a frame its reader can receive.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-23.48 | every `kr_req_23_48_` test here |

#![cfg(unix)]

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use kr_ipc::client::LocalClient;
use kr_ipc::endpoint::Listener;
use kr_ipc::verify::{ControllerIdentity, WorkerIdentity};
use kr_protocol::actor::{ActorEnvelope, ActorIngress};
use kr_protocol::attachment::{
    AttachMode, AttachmentCapability, SessionAttachParams, SessionAttachResult,
};
use kr_protocol::broker::{
    BrokerGrant, BrokerGrants, DecodingTrust, InstanceCapabilityRecord, IntegrationMode,
};
use kr_protocol::envelope::{ActionTarget, ControlFrame, Outcome, ParamsValue, Request, Response};
use kr_protocol::error::ProtocolError;
use kr_protocol::frame::{FrameCodec, StreamKind};
use kr_protocol::gateway::{
    DeclarativeEntry, DeclarativeTable, NativeFraming, NativeMethodClass, RichMethodTable,
};
use kr_protocol::grant::HistoryScope;
use kr_protocol::hello::{PROTOCOL_VERSION, ReceiveLimits};
use kr_protocol::identity::{
    DesktopBinding, ProcessStartIdentity, ProcessStartSource, WorkerProfile,
};
use kr_protocol::ids::{
    ActionId, ActorId, ApplicationInstanceId, AuthorityRevision, BrokerBindingId, BuildId,
    CapabilityId, CapabilityRevision, ConnectionId, ControllerGeneration, DeviceId,
    GatewayConnectionId, GrantId, MethodTableVersion, PendingResourceId, PluginId, PublisherId,
    RequestId, SessionEpoch, SessionId, UpstreamMethod,
};
use kr_protocol::local::{ForwardedRequest, LocalClientKind};
use kr_protocol::method::{Method, MethodVersion};
use kr_protocol::projection::AgentResourceSnapshotContinuation;
use kr_protocol::receipt::{ActionReadParams, ActionReadResult};
use kr_protocol::recovery::{
    EventStream, EventsSnapshotParams, EventsSnapshotResult, EventsSubscribeParams,
    EventsSubscribeResult, HistoryGapCause,
};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{Digest256, Nullable, TimestampMs, U64, Uuid};
use kr_protocol::session::{Dimensions, DisplayNumber, ShellMode};
use kr_worker::broker::{
    BrokerError, BrokerTransport, Credential, ManagedProcess, PendingTransmission, TransportHandle,
    UpstreamDispatch, UpstreamOutcome, UpstreamRequest,
};
use kr_worker::persistence::retention::OutputRetention;
use kr_worker::runtime::SessionRuntime;
use kr_worker::service::{ServiceBinding, WorkerService};
use kr_worker::session::{Session as TerminalSession, SessionConfig};

mod common;

use common::LIVENESS_DEADLINE;

/// The smallest control frame a peer may declare.
const FRAME: usize = kr_transport::scheduler::MIN_CONTROL_FRAME_LEN;

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

/// One native request, as the upstream writes it, under an identifier of its own.
fn request_frame() -> Vec<u8> {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    let id = NEXT.fetch_add(1, Ordering::Relaxed);
    format!(
        r#"{{"id":{id},"method":"session/request_permission","params":{{"path":"/srv/notes.txt","options":[{{"optionId":"allow","name":"Allow this once"}},{{"optionId":"reject","name":"Reject"}}]}}}}"#
    )
    .into_bytes()
}

/// A request identifier no other request of this suite uses.
fn next_request() -> RequestId {
    static NEXT: AtomicU64 = AtomicU64::new(1_000_000);
    RequestId::new(NEXT.fetch_add(1, Ordering::Relaxed))
}

/// Waits for one exchange with the worker, and fails naming what it waited for rather than hanging.
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

/// A worker serving one session, with one instance whose native requests the broker holds.
struct Host {
    _temp: kr_ipc::testing::TempHost,
    service: Arc<WorkerService>,
    runtime: Arc<SessionRuntime>,
    session_id: SessionId,
    environment_id: kr_protocol::ids::EnvironmentId,
    endpoint: kr_ipc::paths::Endpoint,
    /// The control daemon's identity, to forward a paired device's reads as the daemon does.
    controller: Arc<ControllerIdentity>,
    /// The boot the daemon proves its generation against.
    boot: kr_protocol::identity::BootIdentity,
    /// The native connection the requests arrive on.
    connection: GatewayConnectionId,
}

impl Host {
    fn target(&self) -> ActionTarget {
        ActionTarget {
            environment_id: self.environment_id,
            session_id: Nullable::some(self.session_id),
            session_epoch: Nullable::some(SessionEpoch::V1),
            application_instance_id: Nullable::null(),
            agent_binding_revision: Nullable::null(),
        }
    }

    /// A terminal that watches the session.
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
}

#[allow(clippy::too_many_lines)]
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
        .bind_descriptor(
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
        .expect("the binding is bound");
    broker
        .record_capability(InstanceCapabilityRecord {
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
    }
}

/// Records one native request that arrived at `at_ms`: a resource the broker now holds.
fn arrive(host: &Host, at_ms: u64) -> PendingResourceId {
    host.service
        .broker()
        .forward_native(host.connection, &request_frame(), TimestampMs::new(at_ms))
        .expect("forwarded")
        .1
        .expect("it expects a response")
        .resource_id
}

/// What a peer that receives the smallest frame declares.
fn smallest() -> ReceiveLimits {
    ReceiveLimits {
        max_control_frame_len: U64::new(FRAME as u64),
        ..ReceiveLimits::default()
    }
}

/// The local owner, on the worker's own socket, receiving `limits`.
async fn owner(host: &Host, limits: ReceiveLimits) -> LocalClient {
    within(
        "a local connection",
        LocalClient::connect_receiving(&host.endpoint, LocalClientKind::Cli, build(), limits),
    )
    .await
    .expect("connects")
}

/// Connects as the control daemon and proves the generation, to forward a device's reads.
async fn daemon(host: &Host) -> LocalClient {
    daemon_receiving(host, ReceiveLimits::default()).await
}

/// Connects as the control daemon receiving `limits`, and proves the generation.
async fn daemon_receiving(host: &Host, limits: ReceiveLimits) -> LocalClient {
    let mut daemon = within(
        "the daemon's connection",
        LocalClient::connect_receiving(
            &host.endpoint,
            LocalClientKind::Controller,
            build(),
            limits,
        ),
    )
    .await
    .expect("connects as the daemon");
    let identity = Arc::clone(&host.controller);
    let boot = host.boot.clone();
    within(
        "the worker's acceptance of the generation",
        daemon.present_generation(move |nonce| {
            identity
                .generation_token(ControllerGeneration::new(1), &boot, nonce)
                .map_err(kr_ipc::IpcError::from)
        }),
    )
    .await
    .expect("the worker accepts the generation");
    daemon
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

/// A grant's history scope reaching back to `lower_bound_ms`.
fn reaching_back_to(lower_bound_ms: u64) -> HistoryScope {
    HistoryScope {
        lower_bound_ms: Nullable::some(TimestampMs::new(lower_bound_ms)),
        include_live_screen: true,
        named_questions: kr_protocol::scalars::CanonicalSet::new(),
        named_approvals: kr_protocol::scalars::CanonicalSet::new(),
    }
}

/// Forwards one device's read as the daemon does, with the scope of the device's grant.
async fn forwarded<T: serde::Serialize>(
    daemon: &mut LocalClient,
    scope: Option<HistoryScope>,
    method: Method,
    params: &T,
) -> Result<ParamsValue, ProtocolError> {
    let request_id = next_request();
    let read = ControlFrame::ForwardedRead(Box::new(ForwardedRequest {
        request: Request {
            request_id,
            method: method.into(),
            method_version: MethodVersion::V1,
            params: ParamsValue::from_typed(params).expect("encodes"),
        },
        authority_deadline_boot_ms: Nullable::some(U64::new(
            kr_ipc::clock::boot_elapsed_ms() + 30_000,
        )),
        actor: device(),
        history: scope,
    }));
    within("the worker's answer", async {
        daemon
            .writer()
            .write_message(&read)
            .await
            .expect("writes the read");
        loop {
            match daemon.recv().await.expect("the worker answers") {
                ControlFrame::Response(response) if response.request_id == request_id => {
                    return match response.outcome {
                        Outcome::Ok(value) => Ok(value),
                        Outcome::Error(error) => Err(error),
                    };
                }
                _ => {}
            }
        }
    })
    .await
}

/// Forwards one of the device's mutations as the daemon does, admitted under a grant that lets it
/// watch the session.
async fn forwarded_mutation<T: serde::Serialize>(
    daemon: &mut LocalClient,
    host: &Host,
    method: Method,
    params: &T,
) -> Result<ParamsValue, ProtocolError> {
    let request_id = next_request();
    let mutation = ControlFrame::Forwarded(Box::new(kr_protocol::local::ForwardedMutation {
        mutation: kr_protocol::envelope::MutationRequest {
            request_id,
            method: method.into(),
            method_version: MethodVersion::V1,
            action_id: ActionId::new(kr_ipc::new_uuid()),
            grant_id: Nullable::null(),
            target: host.target(),
            expected: ParamsValue::empty(),
            action_window_id: kr_protocol::ids::ActionWindowId::new("forwarded")
                .expect("a window identifier"),
            requested_ttl_ms: kr_protocol::limits::DEFAULT_MUTATION_TTL,
            params: ParamsValue::from_typed(params).expect("encodes"),
        },
        actor: device(),
        grant_rights: [ActionRight::SessionView].into_iter().collect(),
        accepted_deadline_boot_ms: U64::new(kr_ipc::clock::boot_elapsed_ms() + 30_000),
        history: None,
        screen_basis: None,
    }));
    within("the worker's answer", async {
        daemon
            .writer()
            .write_message(&mutation)
            .await
            .expect("writes the mutation");
        loop {
            match daemon.recv().await.expect("the worker answers") {
                ControlFrame::Response(response) if response.request_id == request_id => {
                    return match response.outcome {
                        Outcome::Ok(value) => Ok(value),
                        Outcome::Error(error) => Err(error),
                    };
                }
                _ => {}
            }
        }
    })
    .await
}

/// Asserts that an answer, framed as the worker frames it, is inside a frame of `frame` bytes.
fn fits(answer: &ParamsValue, frame: usize) {
    let framed = FrameCodec::new(StreamKind::Control)
        .encode_message(&ControlFrame::Response(Response {
            request_id: RequestId::new(u64::MAX),
            outcome: Outcome::Ok(answer.clone()),
        }))
        .expect("the answer frames");
    assert!(
        framed.len() <= frame,
        "the answer is {} bytes framed, and the reader said it receives {frame}",
        framed.len()
    );
}

/// Reads every page of a snapshot on `reader`, following each continuation, holding each page to
/// `frame`, and returns the resources in the order the pages carried them and how many pages it
/// took.
async fn every_page(
    reader: &mut LocalClient,
    host: &Host,
    frame: usize,
) -> (Vec<PendingResourceId>, usize) {
    let mut from = None;
    let mut seen = Vec::new();
    let mut pages = 0;
    loop {
        let answer = within(
            "the worker's snapshot",
            reader.request(
                Method::EventsSnapshot,
                &EventsSnapshotParams {
                    session_id: host.session_id,
                    agent_resources_from: Nullable(from),
                },
            ),
        )
        .await
        .expect("the call reaches the worker")
        .expect("a snapshot");
        fits(&answer, frame);
        let snapshot: EventsSnapshotResult = answer.to_typed().expect("a snapshot decodes");
        pages += 1;
        seen.extend(
            snapshot
                .agent_resources
                .resources
                .iter()
                .map(|resource| resource.resource_id),
        );
        match snapshot.agent_resources.continue_after.0 {
            Some(after_resource_id) => {
                from = Some(AgentResourceSnapshotContinuation {
                    snapshot_id: snapshot.agent_resources.snapshot_id,
                    after_resource_id,
                });
            }
            None => return (seen, pages),
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_23_48_a_read_names_its_own_session_and_a_subscription_its_own_attachment() {
    // The subject of a state recovery read is the session, and of a subscription the attachment
    // being served. A read naming a session this endpoint does not serve is refused, and an
    // attachment is subscribed by the connection that made it and by no other.
    let host = host().await;
    let mut made_it = owner(&host, ReceiveLimits::default()).await;
    let mut another = owner(&host, ReceiveLimits::default()).await;

    let elsewhere = SessionId::new(kr_ipc::new_uuid());
    within(
        "the worker's answer",
        made_it.request(
            Method::EventsSnapshot,
            &EventsSnapshotParams {
                session_id: elsewhere,
                agent_resources_from: Nullable::null(),
            },
        ),
    )
    .await
    .expect("the call reaches the worker")
    .expect_err("another session is not this endpoint's to show");

    let attached: SessionAttachResult = within(
        "the attach",
        made_it.mutate(
            Method::SessionAttach,
            ActionId::new(kr_ipc::new_uuid()),
            host.target(),
            &host.terminal(),
        ),
    )
    .await
    .expect("the call reaches the worker")
    .map(|value| value.to_typed().expect("decodes"))
    .expect("attaches");
    let subscription = EventsSubscribeParams {
        session_id: host.session_id,
        attachment_id: attached.attachment.attachment_id,
        streams: [EventStream::Output].into_iter().collect(),
        from_cursor: Nullable::null(),
    };
    within(
        "the worker's answer",
        another.request(Method::EventsSubscribe, &subscription),
    )
    .await
    .expect("the call reaches the worker")
    .expect_err("an attachment another connection made is not this one's to subscribe");
    within(
        "the worker's answer",
        made_it.request(Method::EventsSubscribe, &subscription),
    )
    .await
    .expect("the call reaches the worker")
    .expect("the connection that made the attachment subscribes it");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_23_48_a_snapshot_is_cut_to_its_readers_frame_and_every_resource_is_read_once() {
    // The page bound. A reader declared the smallest frame a peer may, and the broker holds more
    // resources than one such frame carries: every page fits that frame, and following the
    // continuations reads each resource once.
    let host = host().await;
    let arrived: BTreeSet<PendingResourceId> =
        (0..60).map(|index| arrive(&host, 1_000 + index)).collect();
    let mut reader = owner(&host, smallest()).await;
    let (seen, pages) = every_page(&mut reader, &host, FRAME).await;
    assert!(
        pages > 1,
        "sixty resources are more than one frame this small carries"
    );
    assert_eq!(seen.len(), arrived.len(), "each resource is read once");
    assert_eq!(seen.into_iter().collect::<BTreeSet<_>>(), arrived);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_23_48_a_subscription_is_cut_to_its_readers_frame_and_told_what_its_cursor_missed() {
    // The cursor bound and the page bound together. A subscription from a cursor the session's
    // own cap has already evicted is told the range and the bound that took it, and the resources
    // it starts from are cut to the frame its reader declared.
    let host = host().await;
    for index in 0..60 {
        arrive(&host, 1_000 + index);
    }
    {
        let mut session = host.runtime.session();
        for _ in 0..32 {
            session.ingest_output(&[b'x'; 8192]);
        }
        let held = session.retained_output_bytes();
        let taken = session.apply_output_retention(
            OutputRetention::new(
                std::time::Duration::from_secs(7 * 24 * 60 * 60),
                1024 * 1024 * 1024,
                1024,
            ),
            held,
            kr_ipc::now_ms(),
            true,
        );
        assert!(!taken.is_empty(), "the session cap took the oldest output");
    }
    let mut reader = owner(&host, smallest()).await;
    let attached: SessionAttachResult = within(
        "the attach",
        reader.mutate(
            Method::SessionAttach,
            ActionId::new(kr_ipc::new_uuid()),
            host.target(),
            &host.terminal(),
        ),
    )
    .await
    .expect("the call reaches the worker")
    .map(|value| value.to_typed().expect("decodes"))
    .expect("attaches");
    let answer = within(
        "the worker's subscription",
        reader.request(
            Method::EventsSubscribe,
            &EventsSubscribeParams {
                session_id: host.session_id,
                attachment_id: attached.attachment.attachment_id,
                streams: [EventStream::Output].into_iter().collect(),
                from_cursor: Nullable::some(U64::new(0)),
            },
        ),
    )
    .await
    .expect("the call reaches the worker")
    .expect("subscribed");
    fits(&answer, FRAME);
    let subscribed: EventsSubscribeResult = answer.to_typed().expect("decodes");
    let gap = subscribed
        .gap
        .0
        .expect("the range the cap took is reported");
    assert_eq!(gap.from_cursor.get(), 0);
    assert_eq!(gap.to_cursor, subscribed.oldest_retained_cursor);
    assert_eq!(gap.cause, Some(HistoryGapCause::SessionCapacity));
    assert!(
        subscribed.agent_resources.continue_after.is_present(),
        "the resources it starts from were cut to the frame"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_23_48_a_devices_snapshot_is_held_to_its_grants_present_view() {
    // Present view authority. The local owner is shown every resource the broker holds; a paired
    // device, whose read the daemon forwards with its grant's history scope, is shown what that
    // scope reaches and nothing recorded before it.
    let host = host().await;
    let early: BTreeSet<PendingResourceId> =
        (0..3).map(|index| arrive(&host, 1_000 + index)).collect();
    let late: BTreeSet<PendingResourceId> =
        (0..2).map(|index| arrive(&host, 5_000 + index)).collect();

    let mut window = owner(&host, ReceiveLimits::default()).await;
    let (seen, _) = every_page(
        &mut window,
        &host,
        kr_protocol::limits::MAX_CONTROL_FRAME_LEN,
    )
    .await;
    assert_eq!(
        seen.into_iter().collect::<BTreeSet<_>>(),
        early.union(&late).copied().collect(),
        "the owner is shown everything"
    );

    let mut daemon = daemon(&host).await;
    let answer = forwarded(
        &mut daemon,
        Some(reaching_back_to(3_000)),
        Method::EventsSnapshot,
        &EventsSnapshotParams {
            session_id: host.session_id,
            agent_resources_from: Nullable::null(),
        },
    )
    .await
    .expect("the device's snapshot is answered");
    let snapshot: EventsSnapshotResult = answer.to_typed().expect("decodes");
    let shown: BTreeSet<PendingResourceId> = snapshot
        .agent_resources
        .resources
        .iter()
        .map(|resource| resource.resource_id)
        .collect();
    assert_eq!(
        shown, late,
        "the device is shown what its grant reaches, and nothing older"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_23_48_a_receipt_answers_only_the_actor_whose_action_it_is() {
    // A receipt is keyed by the actor and the action together, so an action identifier is not a
    // way to read somebody else's result: the owner reads its own receipt and not a device's, and
    // the device reads its own and not the owner's.
    let host = host().await;
    let mut window = owner(&host, ReceiveLimits::default()).await;
    let owners = ActionId::new(kr_ipc::new_uuid());
    within(
        "the attach",
        window.mutate(
            Method::SessionAttach,
            owners,
            host.target(),
            &host.terminal(),
        ),
    )
    .await
    .expect("the call reaches the worker")
    .expect("attaches");
    let devices = kr_worker::journal::action_id_from([4; 16]);
    {
        let mut session = host.runtime.session();
        session
            .journal_mut()
            .expect("a journal")
            .accept(&kr_worker::journal::Submission {
                actor_id: device().actor_id,
                action_id: devices,
                method: Method::SessionAttach.into(),
                method_version: MethodVersion::V1,
                payload_digest: Digest256::from_bytes([4; 32]),
                subject_digest: Digest256::from_bytes([4; 32]),
                intent: vec![0xa0],
                accepted_deadline_ms: Some(TimestampMs::new(kr_ipc::now_ms().get() + 120_000)),
                now_ms: kr_ipc::now_ms(),
            })
            .expect("the device's action is admitted");
    }
    let read = |action_id| ActionReadParams {
        action_id,
        session_id: None,
    };

    let own: ActionReadResult = within(
        "the read",
        window.request(Method::ActionRead, &read(owners)),
    )
    .await
    .expect("the call reaches the worker")
    .expect("the owner reads its own receipt")
    .to_typed()
    .expect("decodes");
    assert_eq!(own.receipt.action_id, owners);
    within(
        "the read",
        window.request(Method::ActionRead, &read(devices)),
    )
    .await
    .expect("the call reaches the worker")
    .expect_err("the device's receipt is not the owner's to read");

    let mut daemon = daemon(&host).await;
    let theirs: ActionReadResult = forwarded(&mut daemon, None, Method::ActionRead, &read(devices))
        .await
        .expect("the device reads its own receipt")
        .to_typed()
        .expect("decodes");
    assert_eq!(theirs.receipt.action_id, devices);
    forwarded(&mut daemon, None, Method::ActionRead, &read(owners))
        .await
        .expect_err("the owner's receipt is not the device's to read");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_23_48_retained_history_is_served_to_the_owner_and_not_to_a_paired_device() {
    // A history page is a byte range and a grant's history scope is a moment in time, so nothing
    // narrows one to the other: the local owner is served the page, and a paired device, whose
    // read the daemon forwards, is refused it rather than served more than its grant allows.
    let host = host().await;
    {
        let mut session = host.runtime.session();
        session.ingest_output(b"kr-retained-output");
    }
    let params = kr_protocol::recovery::HistoryPageParams {
        session_id: host.session_id,
        from_cursor: U64::new(0),
        max_bytes: U64::new(4096),
    };
    let mut window = owner(&host, ReceiveLimits::default()).await;
    let page: kr_protocol::recovery::HistoryPageResult =
        within("the page", window.request(Method::HistoryPage, &params))
            .await
            .expect("the call reaches the worker")
            .expect("the owner is served the page")
            .to_typed()
            .expect("decodes");
    assert!(!page.bytes.is_empty());
    let mut daemon = daemon(&host).await;
    let refused = forwarded(
        &mut daemon,
        Some(reaching_back_to(0)),
        Method::HistoryPage,
        &params,
    )
    .await
    .expect_err("a paired device is not served retained history");
    assert_eq!(
        refused.code,
        kr_protocol::error::ErrorCode::PermissionDenied,
        "{refused:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_23_48_a_receipt_read_names_its_own_session_and_fits_its_readers_frame() {
    // `action.read` is a state recovery read like the others: one that names a session names its
    // own, and its answer - the receipt and the result it keeps - is held to the frame its reader
    // declared, refused with both sizes rather than sent in a frame the reader has to discard.
    let host = host().await;
    let caller =
        ActorId::new(format!("local:{}", kr_ipc::paths::current_uid())).expect("the local caller");
    let action_id = kr_worker::journal::action_id_from([6; 16]);
    // A result larger than the smallest frame, kept with the owner's action.
    let result = kr_cbor::to_canonical_vec(&"r".repeat(20_000)).expect("encodes");
    {
        let mut session = host.runtime.session();
        let journal = session.journal_mut().expect("a journal");
        journal
            .accept(&kr_worker::journal::Submission {
                actor_id: caller.clone(),
                action_id,
                method: Method::SessionAttach.into(),
                method_version: MethodVersion::V1,
                payload_digest: Digest256::from_bytes([6; 32]),
                subject_digest: Digest256::from_bytes([6; 32]),
                intent: vec![0xa0],
                accepted_deadline_ms: Some(TimestampMs::new(kr_ipc::now_ms().get() + 120_000)),
                now_ms: kr_ipc::now_ms(),
            })
            .expect("the owner's action is admitted");
        journal
            .mark_dispatching(caller.clone(), action_id, kr_ipc::now_ms())
            .expect("dispatched");
        journal
            .settle(
                caller,
                action_id,
                kr_protocol::receipt::ReceiptState::Applied,
                Some(result.as_slice()),
                None,
                kr_ipc::now_ms(),
            )
            .expect("settled with its result");
    }
    let read = |session_id| ActionReadParams {
        action_id,
        session_id,
    };

    // The control: its own session, named, read by a reader whose frame holds the answer.
    let mut window = owner(&host, ReceiveLimits::default()).await;
    let own: ActionReadResult = within(
        "the read",
        window.request(Method::ActionRead, &read(Some(host.session_id))),
    )
    .await
    .expect("the call reaches the worker")
    .expect("its own session's receipt is read")
    .to_typed()
    .expect("decodes");
    assert_eq!(own.receipt.action_id, action_id);
    assert!(own.result.is_present(), "with the result it keeps");

    let elsewhere = SessionId::new(kr_ipc::new_uuid());
    let refused = within(
        "the read",
        window.request(Method::ActionRead, &read(Some(elsewhere))),
    )
    .await
    .expect("the call reaches the worker")
    .expect_err("a read naming another session is not this endpoint's to answer");
    assert!(
        refused.message.contains(&elsewhere.to_string()),
        "{refused:?}"
    );

    let mut small = owner(&host, smallest()).await;
    let refused = within("the read", small.request(Method::ActionRead, &read(None)))
        .await
        .expect("the call reaches the worker, and its answer reaches the reader")
        .expect_err("an answer larger than the reader's frame is refused");
    assert!(
        refused.message.contains(&FRAME.to_string())
            || refused
                .message
                .contains(&(FRAME + kr_protocol::limits::MAX_STREAM_HEADER_LEN).to_string()),
        "the refusal names the frame: {refused:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_23_48_a_devices_subscription_is_held_to_its_grant_and_its_frame_on_every_page() {
    // A subscription's resources are paged as a snapshot's are, and every page of a device's is
    // held to both bounds: the present view its grant reaches, and the frame its daemon connection
    // declared. The owner's pages, at the same frame, carry every resource once.
    let host = host().await;
    let early: BTreeSet<PendingResourceId> =
        (0..40).map(|index| arrive(&host, 1_000 + index)).collect();
    let late: BTreeSet<PendingResourceId> =
        (0..100).map(|index| arrive(&host, 5_000 + index)).collect();

    let mut daemon = daemon_receiving(&host, smallest()).await;
    let attached: SessionAttachResult =
        forwarded_mutation(&mut daemon, &host, Method::SessionAttach, &host.terminal())
            .await
            .expect("the device attaches")
            .to_typed()
            .expect("decodes");
    let answer = forwarded(
        &mut daemon,
        Some(reaching_back_to(3_000)),
        Method::EventsSubscribe,
        &EventsSubscribeParams {
            session_id: host.session_id,
            attachment_id: attached.attachment.attachment_id,
            streams: [EventStream::Output].into_iter().collect(),
            from_cursor: Nullable::null(),
        },
    )
    .await
    .expect("the device's subscription is answered");
    fits(&answer, FRAME);
    let first = answer
        .to_typed::<EventsSubscribeResult>()
        .expect("decodes")
        .agent_resources;
    let mut shown: Vec<PendingResourceId> = first
        .resources
        .iter()
        .map(|resource| resource.resource_id)
        .collect();
    let mut pages = 1;
    let mut after = first.continue_after.0;
    while let Some(after_resource_id) = after {
        let answer = forwarded(
            &mut daemon,
            Some(reaching_back_to(3_000)),
            Method::EventsSnapshot,
            &EventsSnapshotParams {
                session_id: host.session_id,
                agent_resources_from: Nullable::some(AgentResourceSnapshotContinuation {
                    snapshot_id: first.snapshot_id,
                    after_resource_id,
                }),
            },
        )
        .await
        .expect("a page the subscription began is read");
        fits(&answer, FRAME);
        let page = answer
            .to_typed::<EventsSnapshotResult>()
            .expect("decodes")
            .agent_resources;
        shown.extend(page.resources.iter().map(|resource| resource.resource_id));
        pages += 1;
        after = page.continue_after.0;
    }
    assert!(pages > 1, "the resources took more than one page");
    assert_eq!(shown.len(), late.len(), "each resource once: {shown:?}");
    assert_eq!(
        shown.into_iter().collect::<BTreeSet<_>>(),
        late,
        "every page is held to what the grant reaches"
    );

    let mut window = owner(&host, smallest()).await;
    let (seen, pages) = every_page(&mut window, &host, FRAME).await;
    assert!(pages > 1);
    assert_eq!(seen.len(), early.len() + late.len(), "each resource once");
    assert_eq!(
        seen.into_iter().collect::<BTreeSet<_>>(),
        early.union(&late).copied().collect(),
        "the owner is shown everything"
    );
}
