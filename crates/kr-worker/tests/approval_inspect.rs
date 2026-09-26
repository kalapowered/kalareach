//! A person reads what an approval's decoder read and what it offered: `agent.approval.inspect`.
//!
//! Section 11 makes an installed decoder part of the trust boundary. Wire provenance proves which
//! connection supplied a request, and nothing proves that the decoder read it correctly, so the
//! approval ledger keeps the decoder's package and publisher, the original source, the native
//! request identifier, the offered decisions, the deadline and where the request stands, open to
//! inspection. These tests read that record on the worker's own socket, through the client
//! library's typed read where a person's client would use it, and hold the answer to what the test
//! itself gave the broker rather than to what the broker says about itself. They also read it, and
//! the agent's shared state, as the control daemon forwards a paired device's read: narrowed by
//! section 10's one host-side filter to the history scope of the grant the daemon decided it under.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-11.26 | `kr_req_11_26_a_local_caller_reads_what_the_decoder_read_and_offered`, `kr_req_11_26_the_record_says_where_the_request_stands_once_answered`, `kr_req_11_26_another_instances_resource_and_one_never_decoded_answer_unknown`, `kr_req_11_26_a_device_reads_the_approval_records_its_grants_scope_reaches` |
//! | KR-REQ-10.51 | `kr_req_10_51_a_named_approval_is_read_while_current_although_it_predates_the_bound`, `kr_req_10_51_a_named_approval_that_has_ended_answers_as_unknown`, `kr_req_10_51_a_name_excepts_its_own_resource_and_no_other_with_the_same_upstream_identifier` |
//! | KR-REQ-23.39 | `kr_req_23_39_a_device_reads_the_agent_history_its_grants_scope_reaches` |

use std::sync::Arc;

use kr_client::ipc::IpcTransport;
use kr_ipc::client::LocalClient;
use kr_ipc::endpoint::Listener;
use kr_ipc::verify::{ControllerIdentity, WorkerIdentity};
use kr_protocol::actor::{ActorEnvelope, ActorIngress};
use kr_protocol::agent::{
    AgentApprovalInspectParams, AgentApprovalInspectResult, AgentApprovalRespondParams,
    AgentCapabilitiesParams, AgentMutationTarget, AgentSnapshotParams, AgentSnapshotResult,
    AgentSubject,
};
use kr_protocol::broker::{
    BrokerGrant, BrokerGrants, DecodedProjection, DecodingTrust, IntegrationMode, OfferedDecision,
};
use kr_protocol::envelope::{
    ActionTarget, ControlFrame, MutationRequest, Outcome, ParamsValue, Request,
};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::gateway::{
    DeclarativeEntry, DeclarativeTable, NativeFraming, NativeMethodClass, PendingState,
    RichMethodTable,
};
use kr_protocol::grant::HistoryScope;
use kr_protocol::hello::PROTOCOL_VERSION;
use kr_protocol::identity::{
    DesktopBinding, ProcessStartIdentity, ProcessStartSource, WorkerProfile,
};
use kr_protocol::ids::{
    ActionId, ActorId, AgentBindingRevision, ApplicationInstanceId, AuthorityRevision,
    BrokerBindingId, BuildId, CapabilityId, CapabilityRevision, ConnectionId, ControllerGeneration,
    DeviceId, GatewayConnectionId, GrantId, MethodTableVersion, PendingResourceId, PluginId,
    PublisherId, RequestId, SessionEpoch, SessionId, UpstreamMethod, UpstreamRequestId,
};
use kr_protocol::local::{ForwardedRequest, LocalClientKind};
use kr_protocol::method::{Method, MethodVersion};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{Digest256, DurationMs, Nullable, TimestampMs, U64, Uuid};
use kr_protocol::session::{Dimensions, DisplayNumber, ShellMode};
use kr_worker::broker::{
    BrokerError, BrokerTransport, Credential, ManagedProcess, PendingTransmission, TransportHandle,
    UpstreamDispatch, UpstreamOutcome, UpstreamRequest, subject,
};
use kr_worker::runtime::SessionRuntime;
use kr_worker::service::{ServiceBinding, WorkerService};
use kr_worker::session::{Session as TerminalSession, SessionConfig};

mod common;

use common::LIVENESS_DEADLINE;

/// When the upstream's request arrived, which is when the broker recorded its source frame.
const RECORDED_AT: TimestampMs = TimestampMs::new(2);

/// When the decoder's interpretation was written, a moment after the request arrived.
const DECODED_AT: TimestampMs = TimestampMs::new(3);

/// The deadline the upstream put on its request: far enough ahead that answering it is possible.
const DEADLINE: TimestampMs = TimestampMs::new(4_102_444_800_000);

/// When the agent said something a grant issued later does not reach back to.
const SAID_EARLY: TimestampMs = TimestampMs::new(1_000);

/// When the agent said something later.
const SAID_LATER: TimestampMs = TimestampMs::new(3_000);

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

fn instance() -> ApplicationInstanceId {
    ApplicationInstanceId::new(Uuid::from_bytes([2; 16]))
}

/// A second instance in the same session, running the same package under its own binding.
fn other_instance() -> ApplicationInstanceId {
    ApplicationInstanceId::new(Uuid::from_bytes([3; 16]))
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

/// One native request, exactly as the upstream wrote it.
fn request_frame(id: u64, padding: usize) -> Vec<u8> {
    format!(
        r#"{{"id":{id},"method":"session/request_permission","params":{{"path":"/srv/notes.txt","note":"{}","options":[{{"optionId":"allow","name":"Allow this once"}},{{"optionId":"reject","name":"Reject"}}]}}}}"#,
        "n".repeat(padding)
    )
    .into_bytes()
}

struct Host {
    _temp: kr_ipc::testing::TempHost,
    service: Arc<WorkerService>,
    session_id: SessionId,
    endpoint: kr_ipc::paths::Endpoint,
    environment_id: kr_protocol::ids::EnvironmentId,
    /// The control daemon's identity, to forward a paired device's read as the daemon does.
    controller: Arc<ControllerIdentity>,
    /// The boot the daemon proves its generation against.
    boot: kr_protocol::identity::BootIdentity,
    /// The native connection the approvals arrive on.
    connection: GatewayConnectionId,
    /// What carries an answer out.
    upstream: Arc<CountingUpstream>,
}

/// A transport that answers at once and counts what it was asked to carry.
#[derive(Debug, Default)]
struct CountingUpstream {
    carried: std::sync::atomic::AtomicUsize,
}

impl UpstreamDispatch for CountingUpstream {
    fn admit(&self, _request: &UpstreamRequest) -> Result<(), BrokerError> {
        Ok(())
    }

    fn submit(&self, request: &UpstreamRequest) -> Result<PendingTransmission, BrokerError> {
        self.carried
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
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

/// Starts a worker serving one session, with one instance whose package's decoder may interpret
/// and answer approval requests, and the authenticated native connection its requests arrive on.
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
        // A shell that lasts as long as the session does: it ends when the session closes its
        // terminal, not at a time of its own.
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
    let upstream = Arc::new(CountingUpstream::default());
    broker.bind_connection_dispatch(
        connection,
        Arc::clone(&upstream) as Arc<dyn UpstreamDispatch>,
    );
    Host {
        _temp: temp,
        service,
        session_id,
        endpoint,
        environment_id,
        controller,
        boot,
        connection,
        upstream,
    }
}

/// Records one native request, as it arrives, without interpreting it.
fn arrive(host: &Host, frame: &[u8]) -> PendingResourceId {
    host.service
        .broker()
        .forward_native(host.connection, frame, RECORDED_AT)
        .expect("forwarded")
        .1
        .expect("it expects a response")
        .resource_id
}

/// Records one native request and has the package's decoder interpret it.
fn offer(host: &Host, frame: &[u8]) -> PendingResourceId {
    let resource_id = arrive(host, frame);
    host.service
        .broker()
        .interpret(
            binding(),
            resource_id,
            projection(),
            Some(DEADLINE),
            DECODED_AT,
        )
        .expect("interpreted")
        .resource_id
}

fn params(
    host: &Host,
    instance: ApplicationInstanceId,
    resource_id: PendingResourceId,
) -> AgentApprovalInspectParams {
    AgentApprovalInspectParams {
        subject: subject(host.session_id, instance),
        resource_id,
    }
}

/// Waits for one exchange with the worker, and fails the test naming what it waited for rather
/// than hanging when a handler stops answering.
async fn within<T>(what: &str, work: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(LIVENESS_DEADLINE, work)
        .await
        .unwrap_or_else(|_| panic!("{what} within {LIVENESS_DEADLINE:?}"))
}

/// The client library a person's client uses, on this worker's own socket.
async fn client(host: &Host) -> kr_client::Session {
    let transport = within(
        "a local connection",
        IpcTransport::connect(&host.endpoint, build()),
    )
    .await
    .expect("a local connection");
    kr_client::Session::start(transport.shared()).expect("a session")
}

/// Reads the record through the client library, and returns the host's refusal as it arrives.
async fn inspect(
    client: &kr_client::Session,
    params: &AgentApprovalInspectParams,
) -> Result<AgentApprovalInspectResult, ProtocolError> {
    match within("the worker's answer", client.inspect_approval(params)).await {
        Ok(record) => Ok(record),
        Err(kr_client::ClientError::Host(error)) => Err(error),
        Err(other) => panic!("the host answers the read: {other}"),
    }
}

/// Connects as the control daemon and proves the generation this worker accepts.
async fn daemon(host: &Host) -> LocalClient {
    daemon_receiving(host, kr_protocol::hello::ReceiveLimits::default()).await
}

/// Connects as the control daemon declaring what it receives, and proves the generation.
async fn daemon_receiving(host: &Host, limits: kr_protocol::hello::ReceiveLimits) -> LocalClient {
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

/// Writes one frame and returns the worker's answer to it.
async fn exchange(client: &mut LocalClient, frame: ControlFrame) -> Outcome {
    within("the worker's answer", async {
        client
            .writer()
            .write_message(&frame)
            .await
            .expect("writes the frame");
        loop {
            match client.recv().await.expect("the worker answers") {
                ControlFrame::Response(response) => return response.outcome,
                ControlFrame::Notification(_) | ControlFrame::Event(_) => {}
                other => panic!("the worker answered {other:?}"),
            }
        }
    })
    .await
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

/// The envelope the control daemon vouches for a caller on its own local socket, naming the
/// grant the caller acts under when it acts under one.
fn local(under_a_grant: bool) -> ActorEnvelope {
    ActorEnvelope {
        actor_id: ActorId::new("local:a-test-user").expect("an actor"),
        ingress: ActorIngress::LocalIpc,
        device_id: Nullable::null(),
        grant_id: if under_a_grant {
            Nullable::some(GrantId::new(Uuid::from_bytes([6; 16])))
        } else {
            Nullable::null()
        },
        grant_revision: if under_a_grant {
            Nullable::some(AuthorityRevision::new(1))
        } else {
            Nullable::null()
        },
        controller_generation: ControllerGeneration::new(1),
        connection_id: ConnectionId::new(Uuid::from_bytes([5; 16])),
    }
}

/// One read, forwarded by the control daemon for the actor it vouches for.
fn forwarded<T: serde::Serialize>(
    method: Method,
    params: &T,
    request_id: u64,
    actor: ActorEnvelope,
) -> ControlFrame {
    ControlFrame::ForwardedRead(Box::new(ForwardedRequest {
        request: Request {
            request_id: RequestId::new(request_id),
            method: method.into(),
            method_version: MethodVersion::V1,
            params: ParamsValue::from_typed(params).expect("encodes"),
        },
        authority_deadline_boot_ms: if actor.grant_id.is_present() {
            Nullable::some(U64::new(kr_ipc::clock::boot_elapsed_ms() + 30_000))
        } else {
            Nullable::null()
        },
        actor,
        history: None,
    }))
}

/// One read, forwarded by the control daemon for the actor it vouches for, with the history scope
/// of the grant the daemon decided it under.
fn scoped<T: serde::Serialize>(
    method: Method,
    params: &T,
    request_id: u64,
    actor: ActorEnvelope,
    history: HistoryScope,
) -> ControlFrame {
    let mut frame = forwarded(method, params, request_id, actor);
    if let ControlFrame::ForwardedRead(read) = &mut frame {
        read.history = Some(history);
    }
    frame
}

/// A grant's history scope reaching back to `lower_bound_ms` (none: no retained history), naming
/// the approvals it names by the resource the broker arbitrates for each.
fn reach(lower_bound_ms: Option<u64>, named_approvals: &[PendingResourceId]) -> HistoryScope {
    HistoryScope {
        lower_bound_ms: Nullable(lower_bound_ms.map(TimestampMs::new)),
        include_live_screen: true,
        named_questions: kr_protocol::scalars::CanonicalSet::new(),
        named_approvals: named_approvals.iter().copied().collect(),
    }
}

/// Replaces the identifiers a refusal names with placeholders, leaving what it says about them.
fn shape(error: &ProtocolError, resource_id: PendingResourceId, host: &Host) -> String {
    error
        .message
        .replace(&resource_id.to_string(), "<resource>")
        .replace(&instance().to_string(), "<instance>")
        .replace(&other_instance().to_string(), "<instance>")
        .replace(&host.session_id.to_string(), "<session>")
}

/// KR-REQ-11.26: the local owner reads, on the worker's own socket, exactly what the decoder was
/// given and what it offered: the original bytes and their digest, the native request identifier
/// and method, the decisions in the upstream's order, the deadline, and whose package's decoder it
/// was. The record is placed at the moment the request arrived, not at the later moment it was
/// interpreted, and a request still waiting for an answer says so.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_11_26_a_local_caller_reads_what_the_decoder_read_and_offered() {
    let host = host().await;
    let frame = request_frame(11, 0);
    let resource_id = offer(&host, &frame);
    let client = client(&host).await;

    let record = inspect(&client, &params(&host, instance(), resource_id))
        .await
        .expect("the owner reads the record");

    assert_eq!(record.resource_id, resource_id);
    assert_eq!(record.state, PendingState::Pending);
    assert_eq!(
        record.recorded_at, RECORDED_AT,
        "the record belongs to the moment the request arrived"
    );
    let decoding = &record.decoding;
    assert_eq!(decoding.source_bytes.as_slice(), frame.as_slice());
    assert_eq!(
        decoding.source_digest,
        Digest256::from_bytes(kr_cbor::sha256(&frame))
    );
    assert_eq!(decoding.method, permission());
    assert_eq!(
        decoding.upstream_request_id,
        UpstreamRequestId::new("11").expect("the identifier's JSON form")
    );
    assert_eq!(decoding.projection, projection());
    assert_eq!(
        decoding.projection.decisions,
        offered(),
        "the decisions the decoder offered, in the order the upstream offered them"
    );
    assert_eq!(decoding.plugin_id, plugin());
    assert_eq!(decoding.publisher_id, publisher());
    assert_eq!(decoding.package_digest, package_digest());
    assert_eq!(decoding.binding_id, binding());
    assert_eq!(decoding.deadline_ms, Nullable::some(DEADLINE));
    assert_eq!(decoding.decoded_at, DECODED_AT);
    assert_eq!(
        Some(decoding),
        host.service
            .broker()
            .decoding(resource_id)
            .expect("the ledger reads")
            .as_ref(),
        "and it is the ledger's own record, whole"
    );

    client.close();
}

/// KR-REQ-11.26: a resource of another instance, one no decoder interpreted and one this host does
/// not hold are one refusal with one text, so the answer does not say which it was and carries
/// nothing of another instance's record. Named with its own instance, the same resource is read.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_11_26_another_instances_resource_and_one_never_decoded_answer_unknown() {
    let host = host().await;
    host.service
        .broker()
        .register_instance(
            other_instance(),
            IntegrationMode::Gateway,
            None,
            Some(managed(other_instance(), 42)),
        )
        .expect("a second instance of the session");
    let decoded = offer(&host, &request_frame(11, 0));
    let opaque = arrive(&host, &request_frame(12, 0));
    let absent = PendingResourceId::new(Uuid::from_bytes([0xab; 16]));
    let client = client(&host).await;

    let mut shapes = Vec::new();
    for (case, subject_instance, resource_id) in [
        ("another instance's resource", other_instance(), decoded),
        ("a resource no decoder interpreted", instance(), opaque),
        ("a resource this host does not hold", instance(), absent),
    ] {
        let error = inspect(&client, &params(&host, subject_instance, resource_id))
            .await
            .expect_err(case);
        assert_eq!(error.code, ErrorCode::StaleSession, "{case}");
        for withheld in ["kalareach.codex", "session/request_permission", "allow"] {
            assert!(
                !error.message.contains(withheld),
                "{case}: the refusal carries nothing of the record: {}",
                error.message
            );
        }
        shapes.push(shape(&error, resource_id, &host));
    }
    assert!(
        shapes.windows(2).all(|pair| pair[0] == pair[1]),
        "one refusal with one text: {shapes:?}"
    );

    // A session this worker does not serve is refused as the other agent reads refuse it.
    let elsewhere = AgentApprovalInspectParams {
        subject: AgentSubject {
            session_id: SessionId::new(Uuid::from_bytes([0xcd; 16])),
            application_instance_id: instance(),
        },
        resource_id: decoded,
    };
    let error = inspect(&client, &elsewhere)
        .await
        .expect_err("another session");
    assert_eq!(error.code, ErrorCode::StaleSession);

    // The control: the same resource, named with the instance it belongs to, is read.
    let record = inspect(&client, &params(&host, instance(), decoded))
        .await
        .expect("its own instance reads it");
    assert_eq!(record.resource_id, decoded);

    client.close();
}

/// KR-REQ-11.26: the record says where the request stands, and the answer path is the one it was.
/// An owner who reads the record and then answers the approval finds it resolved on the next read,
/// with the same bytes and the same offered decisions, and the transport carried the answer once.
/// A local `agent.snapshot` is answered as before.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_11_26_the_record_says_where_the_request_stands_once_answered() {
    let host = host().await;
    let resource_id = offer(&host, &request_frame(11, 0));
    let reader = client(&host).await;
    let before = inspect(&reader, &params(&host, instance(), resource_id))
        .await
        .expect("the record before the answer");
    assert_eq!(before.state, PendingState::Pending);

    let mut owner = within(
        "a local connection",
        LocalClient::connect(&host.endpoint, LocalClientKind::Cli, build()),
    )
    .await
    .expect("connects");
    let answer = MutationRequest {
        request_id: RequestId::new(21),
        method: Method::AgentApprovalRespond.into(),
        method_version: MethodVersion::V1,
        action_id: ActionId::new(kr_ipc::new_uuid()),
        grant_id: Nullable::null(),
        target: ActionTarget {
            environment_id: host.environment_id,
            session_id: Nullable::some(host.session_id),
            session_epoch: Nullable::some(SessionEpoch::V1),
            application_instance_id: Nullable::some(instance()),
            agent_binding_revision: Nullable::some(AgentBindingRevision::new(1)),
        },
        expected: ParamsValue::empty(),
        action_window_id: owner.action_window().action_window_id.clone(),
        requested_ttl_ms: DurationMs::new(60_000),
        params: ParamsValue::from_typed(&AgentApprovalRespondParams {
            target: AgentMutationTarget {
                subject: subject(host.session_id, instance()),
                binding_revision: AgentBindingRevision::new(1),
            },
            resource_id,
            option_id: "allow".to_owned(),
        })
        .expect("encodes"),
    };
    let outcome = exchange(&mut owner, ControlFrame::Mutation(Box::new(answer))).await;
    assert!(
        matches!(outcome, Outcome::Ok(_)),
        "the approval is answered as before: {outcome:?}"
    );
    assert_eq!(
        host.upstream
            .carried
            .load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the transport carried the answer once"
    );

    let after = inspect(&reader, &params(&host, instance(), resource_id))
        .await
        .expect("the record after the answer");
    assert_eq!(after.state, PendingState::Resolved);
    assert_eq!(after.recorded_at, before.recorded_at);
    assert_eq!(
        after.decoding, before.decoding,
        "answering changes where the request stands, not what the decoder read or offered"
    );

    let snapshot = exchange(
        &mut owner,
        ControlFrame::Request(Request {
            request_id: RequestId::new(22),
            method: Method::AgentSnapshot.into(),
            method_version: MethodVersion::V1,
            params: ParamsValue::from_typed(&AgentSnapshotParams {
                subject: subject(host.session_id, instance()),
                from_node: Nullable::null(),
            })
            .expect("encodes"),
        }),
    )
    .await;
    assert!(
        matches!(snapshot, Outcome::Ok(_)),
        "a local snapshot is answered as before: {snapshot:?}"
    );

    reader.close();
}

/// A read the control daemon forwards for a paired device without the history scope of the grant it
/// decided the read under does not reach the record or the history: nothing here could hold the
/// answer to the scope, so the worker refuses both with the reason, and the refusal carries
/// nothing of the record. The control is the agent read that carries no history:
/// `agent.capabilities` is served through the same frame.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_paired_devices_read_without_a_scope_is_refused_with_its_reason() {
    let host = host().await;
    let resource_id = offer(&host, &request_frame(11, 0));
    converse(&host);
    let mut daemon = daemon(&host).await;

    for (request_id, frame) in [
        (
            31,
            forwarded(
                Method::AgentApprovalInspect,
                &params(&host, instance(), resource_id),
                31,
                device(),
            ),
        ),
        (
            33,
            forwarded(Method::AgentSnapshot, &snapshot_params(&host), 33, device()),
        ),
    ] {
        let refused = exchange(&mut daemon, frame).await;
        let Outcome::Error(error) = refused else {
            panic!("read {request_id} without a scope is refused: {refused:?}");
        };
        assert_eq!(error.code, ErrorCode::UnsupportedCapability, "{request_id}");
        assert!(
            error.message.contains("history scope"),
            "the refusal says why: {}",
            error.message
        );
        for withheld in [
            "kalareach.codex",
            "session/request_permission",
            "allow",
            "said",
        ] {
            assert!(
                !error.message.contains(withheld),
                "the refusal carries nothing of the record or the history: {}",
                error.message
            );
        }
    }

    let capabilities = exchange(
        &mut daemon,
        forwarded(
            Method::AgentCapabilities,
            &AgentCapabilitiesParams {
                subject: subject(host.session_id, instance()),
            },
            32,
            device(),
        ),
    )
    .await;
    assert!(
        matches!(capabilities, Outcome::Ok(_)),
        "the same frame carries a read that holds no history: {capabilities:?}"
    );
}

/// The host's one intersection of a grant with a request holds this method to the right its entry
/// names: a grant without `session.view` is refused for it, whatever else it carries, and one with
/// it passes that rule, on the local socket and from a paired device alike.
#[test]
fn a_grant_without_session_view_is_refused_by_the_methods_rights() {
    use kr_controller::grants::{AccessRequest, GrantRecord, HostPolicy, Refusal, decide};
    use kr_protocol::grant::{EnvironmentSelector, Grant, GrantExpiry, SessionSelector};
    use kr_protocol::scalars::CanonicalSet;
    use kr_transport::clock::{ContinuousClock as _, ManualClock};

    let session_id = SessionId::new(Uuid::from_bytes([4; 16]));
    let environment_id = kr_protocol::ids::EnvironmentId::new(Uuid::from_bytes([5; 16]));
    let grant = |actions: &[ActionRight]| Grant {
        grant_id: GrantId::new(Uuid::from_bytes([1; 16])),
        parent_grant_id: Nullable::null(),
        issuer_device_id: DeviceId::new(Uuid::from_bytes([2; 16])),
        recipient_device_id: DeviceId::new(Uuid::from_bytes([3; 16])),
        authority_revision: AuthorityRevision::new(1),
        environment_selector: EnvironmentSelector::Any,
        session_selector: SessionSelector::Any,
        actions: actions.iter().copied().collect(),
        history: HistoryScope {
            lower_bound_ms: Nullable::some(TimestampMs::new(0)),
            include_live_screen: true,
            named_questions: CanonicalSet::new(),
            named_approvals: CanonicalSet::new(),
        },
        expiry: GrantExpiry::Never,
        organisation: Nullable::null(),
    };
    let decision = |grant: &Grant, ingress: ActorIngress| {
        let record = GrantRecord {
            grant: grant.clone(),
            session_id: None,
            issued_at_ms: 1_000,
            activated_at_ms: Some(1_000),
            revoked_at_ms: None,
            revoked_by_parent: None,
        };
        decide(
            grant,
            &record,
            &mut HostPolicy::personal(AuthorityRevision::new(1)),
            AccessRequest {
                method: Method::AgentApprovalInspect,
                ingress,
                environment_id,
                session_id: Some(session_id),
                claims_geometry: false,
                own_subject: None,
                now_ms: 5_000,
                continuous_now: ManualClock::new().now(),
            },
        )
    };

    let without = grant(&[
        ActionRight::AgentApprovalRespond,
        ActionRight::AgentPrompt,
        ActionRight::FilesRead,
    ]);
    assert_eq!(
        decision(&without, ActorIngress::LocalIpc).expect_err("no session.view"),
        Refusal::MissingRight {
            right: ActionRight::SessionView
        }
    );
    let with = grant(&[ActionRight::SessionView]);
    assert!(
        decision(&with, ActorIngress::LocalIpc).is_ok(),
        "session.view is the right the entry names"
    );
    assert!(
        decision(&with, ActorIngress::PairedDevice).is_ok(),
        "a paired device reads the record under session.view"
    );
    assert_eq!(
        decision(&without, ActorIngress::PairedDevice).expect_err("no session.view"),
        Refusal::MissingRight {
            right: ActionRight::SessionView
        }
    );
}

/// A peer that said it can receive less than the record is refused with the sizes, rather than
/// sent a frame it would have to discard, and the same connection reads a record that fits.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_record_larger_than_the_peers_frame_is_refused_with_its_size() {
    let host = host().await;
    let large = offer(&host, &request_frame(11, 100 * 1024));
    let small = offer(&host, &request_frame(12, 0));
    let limits = kr_protocol::hello::ReceiveLimits {
        max_control_frame_len: U64::new(64 * 1024),
        ..kr_protocol::hello::ReceiveLimits::default()
    };
    let mut peer = within(
        "a local connection",
        LocalClient::connect_receiving(&host.endpoint, LocalClientKind::Cli, build(), limits),
    )
    .await
    .expect("connects");
    // What the record costs in canonical bytes, which is what the refusal has to name beside what
    // the peer can receive.
    let required = kr_cbor::to_canonical_vec(
        &host
            .service
            .broker()
            .inspect_approval(
                &params(&host, instance(), large),
                &kr_worker::history_filter::HistoryFilter::new(
                    kr_worker::history_filter::ViewerScope::owner(),
                ),
            )
            .expect("the broker reads the record"),
    )
    .expect("the record encodes")
    .len();
    assert!(required > 64 * 1024, "the record is past the peer's frame");

    let refused = within(
        "the worker's answer",
        peer.request(
            Method::AgentApprovalInspect,
            &params(&host, instance(), large),
        ),
    )
    .await
    .expect("the worker answers");
    let error = refused.expect_err("a record past the peer's frame is refused");
    assert_eq!(error.code, ErrorCode::InvalidArgument);
    assert!(
        error.message.contains(&required.to_string()),
        "the refusal says what the record needs: {}",
        error.message
    );
    assert!(
        error.message.contains(&(64 * 1024).to_string()),
        "the refusal says what the peer can receive: {}",
        error.message
    );

    let read = within(
        "the worker's answer",
        peer.request(
            Method::AgentApprovalInspect,
            &params(&host, instance(), small),
        ),
    )
    .await
    .expect("the worker answers")
    .expect("a record that fits is read on the same connection");
    let record: AgentApprovalInspectResult = read.to_typed().expect("the record decodes");
    assert_eq!(record.resource_id, small);
}

/// Section 10 narrows the history a grant reaches in the shared host-side filter, and a grant's
/// history scope does not reach this worker with a forwarded read. So a caller acting under a
/// grant is refused with that reason, and nothing of the record, whichever socket the daemon
/// heard it on. The local owner the daemon vouches for, acting under no grant, reads the whole
/// record, as it does on the worker's own socket.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_read_under_a_grant_is_refused_with_its_reason_and_the_local_owner_is_served() {
    let host = host().await;
    let resource_id = offer(&host, &request_frame(11, 0));
    let mut daemon = daemon(&host).await;

    let refused = exchange(
        &mut daemon,
        forwarded(
            Method::AgentApprovalInspect,
            &params(&host, instance(), resource_id),
            41,
            local(true),
        ),
    )
    .await;
    let Outcome::Error(error) = refused else {
        panic!("a read under a grant is refused: {refused:?}");
    };
    assert_eq!(error.code, ErrorCode::UnsupportedCapability);
    assert!(
        error.message.contains("history scope"),
        "the refusal says why: {}",
        error.message
    );
    for withheld in ["kalareach.codex", "session/request_permission", "allow"] {
        assert!(
            !error.message.contains(withheld),
            "the refusal carries nothing of the record: {}",
            error.message
        );
    }

    let served = exchange(
        &mut daemon,
        forwarded(
            Method::AgentApprovalInspect,
            &params(&host, instance(), resource_id),
            42,
            local(false),
        ),
    )
    .await;
    let Outcome::Ok(value) = served else {
        panic!("the local owner reads the record: {served:?}");
    };
    let record: AgentApprovalInspectResult = value.to_typed().expect("the record decodes");
    assert_eq!(record.resource_id, resource_id);
    assert_eq!(record.decoding.projection.decisions, offered());
}

/// Records two things the agent said, one early and one later, in the instance's history.
fn converse(host: &Host) {
    let broker = host.service.broker();
    broker
        .observe(instance(), "message", "said early", SAID_EARLY)
        .expect("observed");
    broker
        .observe(instance(), "message", "said later", SAID_LATER)
        .expect("observed");
}

/// The texts of a snapshot's entries, in order.
fn said(snapshot: &AgentSnapshotResult) -> Vec<&str> {
    snapshot
        .entries
        .iter()
        .map(|entry| entry.text.as_str())
        .collect()
}

fn snapshot_params(host: &Host) -> AgentSnapshotParams {
    AgentSnapshotParams {
        subject: subject(host.session_id, instance()),
        from_node: Nullable::null(),
    }
}

/// Section 10's history rule narrows the grant a caller acts under, and a caller the control daemon
/// vouches for on its own local socket can act under one as well as a paired device can. An agent
/// snapshot forwarded for such a caller is not the local owner's whole history: the grant's scope
/// does not reach this worker with the read, so nothing the agent said reaches the caller, and the
/// refusal says why. The local owner, forwarded under no grant or on the worker's own socket,
/// reads the whole history as before.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_snapshot_forwarded_for_a_local_caller_under_a_grant_carries_none_of_the_history() {
    let host = host().await;
    converse(&host);
    let mut daemon = daemon(&host).await;

    let under_a_grant = exchange(
        &mut daemon,
        forwarded(
            Method::AgentSnapshot,
            &snapshot_params(&host),
            51,
            local(true),
        ),
    )
    .await;
    if let Outcome::Ok(value) = &under_a_grant {
        let snapshot: AgentSnapshotResult = value.to_typed().expect("the snapshot decodes");
        panic!(
            "a caller under a grant whose scope never reached the worker read the history: {:?}",
            said(&snapshot)
        );
    }
    let Outcome::Error(error) = under_a_grant else {
        panic!("the snapshot is refused: {under_a_grant:?}");
    };
    assert_eq!(error.code, ErrorCode::UnsupportedCapability);
    assert!(
        error.message.contains("history scope"),
        "the refusal says why: {}",
        error.message
    );
    assert!(
        !error.message.contains("said"),
        "the refusal carries nothing of the history: {}",
        error.message
    );

    // The local owner the daemon vouches for, acting under no grant, reads the whole history.
    let forwarded_owner = exchange(
        &mut daemon,
        forwarded(
            Method::AgentSnapshot,
            &snapshot_params(&host),
            52,
            local(false),
        ),
    )
    .await;
    let Outcome::Ok(value) = forwarded_owner else {
        panic!("the local owner reads the snapshot: {forwarded_owner:?}");
    };
    let snapshot: AgentSnapshotResult = value.to_typed().expect("the snapshot decodes");
    assert_eq!(said(&snapshot), ["said early", "said later"]);
    assert_eq!(snapshot.withheld_entries, U64::new(0));

    // And so does the owner on the worker's own socket.
    let mut owner = within(
        "a local connection",
        LocalClient::connect(&host.endpoint, LocalClientKind::Cli, build()),
    )
    .await
    .expect("connects");
    let value = within(
        "the worker's answer",
        owner.request(Method::AgentSnapshot, &snapshot_params(&host)),
    )
    .await
    .expect("the worker answers")
    .expect("the owner reads the snapshot on the worker's own socket");
    let snapshot: AgentSnapshotResult = value.to_typed().expect("the snapshot decodes");
    assert_eq!(said(&snapshot), ["said early", "said later"]);
    assert_eq!(snapshot.withheld_entries, U64::new(0));
}

/// The answer to a read that was served, decoded.
fn answered<T: kr_protocol::wire::WireMessage>(outcome: Outcome) -> T {
    let Outcome::Ok(value) = outcome else {
        panic!("the read is answered: {outcome:?}");
    };
    value.to_typed().expect("the answer decodes")
}

/// The refusal a read was answered with.
fn refusal(outcome: Outcome) -> ProtocolError {
    let Outcome::Error(error) = outcome else {
        panic!("the read is refused: {outcome:?}");
    };
    error
}

/// Records what the agent said around the moment a grant reaches back to, out of time order the
/// way a clock stepped backwards leaves it: three things said before that moment, before, between
/// and after two things said since.
fn converse_around(host: &Host, grant_reaches_back_to: u64) {
    let broker = host.service.broker();
    for (text, at) in [
        ("before the grant, first", grant_reaches_back_to - 1_000),
        ("under the grant, first", grant_reaches_back_to + 500),
        ("before the grant, between", grant_reaches_back_to - 500),
        ("under the grant, second", grant_reaches_back_to + 1_000),
        ("before the grant, last", grant_reaches_back_to - 800),
    ] {
        broker
            .observe(instance(), "message", text, TimestampMs::new(at))
            .expect("observed");
    }
}

/// KR-REQ-23.39: a paired device reads an agent's shared state through the session's worker, and
/// section 10's one host-side filter holds it to the scope of the grant the daemon decided the
/// read under: what the agent said since the moment the grant reaches back to, in order, with a
/// count of what it withheld, whether that came before, between or after what it kept. A grant
/// that keeps no retained history reads none of it. A scope narrows whoever carries one, the
/// owner's ingress included; the owner with no scope reads everything, as before.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_23_39_a_device_reads_the_agent_history_its_grants_scope_reaches() {
    let host = host().await;
    converse_around(&host, 2_000);
    let mut daemon = daemon(&host).await;
    let snapshot = |request_id: u64, actor: ActorEnvelope, history: HistoryScope| {
        scoped(
            Method::AgentSnapshot,
            &snapshot_params(&host),
            request_id,
            actor,
            history,
        )
    };

    let reached: AgentSnapshotResult =
        answered(exchange(&mut daemon, snapshot(61, device(), reach(Some(2_000), &[]))).await);
    assert_eq!(
        said(&reached),
        ["under the grant, first", "under the grant, second"]
    );
    assert_eq!(
        reached.withheld_entries,
        U64::new(3),
        "the answer says how much it withheld"
    );
    assert!(!reached.continuation.is_present());
    assert!(!reached.history_gap, "a filtered answer is not an eviction");

    let nothing: AgentSnapshotResult =
        answered(exchange(&mut daemon, snapshot(62, device(), reach(None, &[]))).await);
    assert!(
        nothing.entries.is_empty(),
        "no retained history reads none of it, the live screen included: {:?}",
        said(&nothing)
    );
    assert_eq!(nothing.withheld_entries, U64::new(5));

    let narrowed: AgentSnapshotResult = answered(
        exchange(
            &mut daemon,
            snapshot(63, local(false), reach(Some(2_000), &[])),
        )
        .await,
    );
    assert_eq!(
        said(&narrowed),
        ["under the grant, first", "under the grant, second"]
    );

    let whole: AgentSnapshotResult = answered(
        exchange(
            &mut daemon,
            forwarded(
                Method::AgentSnapshot,
                &snapshot_params(&host),
                64,
                local(false),
            ),
        )
        .await,
    );
    assert_eq!(said(&whole).len(), 5);
    assert_eq!(whole.withheld_entries, U64::new(0));
}

/// KR-REQ-11.26: a paired device reads an approval's record through the session's worker when the
/// scope of its grant reaches the moment the request arrived, the bound itself included. A record
/// older than the bound, or any record under a grant that keeps no retained history, is answered
/// exactly as a resource this host does not hold, so the answer does not say that a record exists
/// outside the scope, and it carries nothing of the record.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_11_26_a_device_reads_the_approval_records_its_grants_scope_reaches() {
    let host = host().await;
    let frame = request_frame(11, 0);
    let resource_id = offer(&host, &frame);
    let absent = PendingResourceId::new(Uuid::from_bytes([0xab; 16]));
    let mut daemon = daemon(&host).await;
    let inspect = |request_id: u64, resource_id: PendingResourceId, history: HistoryScope| {
        scoped(
            Method::AgentApprovalInspect,
            &params(&host, instance(), resource_id),
            request_id,
            device(),
            history,
        )
    };

    for (request_id, bound) in [(71, 0), (72, RECORDED_AT.get())] {
        let record: AgentApprovalInspectResult = answered(
            exchange(
                &mut daemon,
                inspect(request_id, resource_id, reach(Some(bound), &[])),
            )
            .await,
        );
        assert_eq!(record.resource_id, resource_id);
        assert_eq!(record.recorded_at, RECORDED_AT);
        assert_eq!(record.decoding.source_bytes.as_slice(), frame.as_slice());
        assert_eq!(record.decoding.projection.decisions, offered());
    }

    let unknown = refusal(exchange(&mut daemon, inspect(73, absent, reach(Some(0), &[]))).await);
    assert_eq!(unknown.code, ErrorCode::StaleSession);
    for (request_id, history) in [
        (74, reach(Some(RECORDED_AT.get() + 1), &[])),
        (75, reach(None, &[])),
    ] {
        let withheld =
            refusal(exchange(&mut daemon, inspect(request_id, resource_id, history)).await);
        assert_eq!(withheld.code, ErrorCode::StaleSession, "{request_id}");
        assert_eq!(
            shape(&withheld, resource_id, &host),
            shape(&unknown, absent, &host),
            "a record outside the scope answers exactly as one this host does not hold"
        );
        for carried in ["kalareach.codex", "session/request_permission", "allow"] {
            assert!(
                !withheld.message.contains(carried),
                "the refusal carries nothing of the record: {}",
                withheld.message
            );
        }
    }
}

/// Records one native request on `connection` and has the package's decoder interpret it.
fn offer_on(host: &Host, connection: GatewayConnectionId, frame: &[u8]) -> PendingResourceId {
    let resource_id = host
        .service
        .broker()
        .forward_native(connection, frame, RECORDED_AT)
        .expect("forwarded")
        .1
        .expect("it expects a response")
        .resource_id;
    host.service
        .broker()
        .interpret(
            binding(),
            resource_id,
            projection(),
            Some(DEADLINE),
            DECODED_AT,
        )
        .expect("interpreted")
        .resource_id
}

/// A person's answer to one approval, as the broker admits it.
fn answer(host: &Host, resource_id: PendingResourceId) -> AgentApprovalRespondParams {
    AgentApprovalRespondParams {
        target: AgentMutationTarget {
            subject: subject(host.session_id, instance()),
            binding_revision: AgentBindingRevision::new(1),
        },
        resource_id,
        option_id: "allow".to_owned(),
    }
}

/// The actor an answer is admitted for.
fn answering() -> kr_worker::broker::Caller {
    kr_worker::broker::Caller {
        actor_id: ActorId::new("local:a-test-user").expect("an actor"),
        grant_id: None,
    }
}

/// Where a record the grant reaches stands.
fn state_read(outcome: Outcome) -> PendingState {
    answered::<AgentApprovalInspectResult>(outcome).state
}

/// KR-REQ-10.51: a grant names an approval by the resource the broker arbitrates for it, and a
/// paired device holding that grant reads the record while the approval can still be decided,
/// pending and then claimed by an answer on its way, although the request arrived before the moment
/// the grant reaches back to. A grant that keeps no retained history reads it too. The controls are
/// the same record under the same grants without the name, which is withheld as unknown.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_10_51_a_named_approval_is_read_while_current_although_it_predates_the_bound() {
    let host = host().await;
    let resource_id = offer(&host, &request_frame(11, 0));
    let absent = PendingResourceId::new(Uuid::from_bytes([0xab; 16]));
    let mut daemon = daemon(&host).await;
    let inspect = |request_id: u64, resource_id: PendingResourceId, history: HistoryScope| {
        scoped(
            Method::AgentApprovalInspect,
            &params(&host, instance(), resource_id),
            request_id,
            device(),
            history,
        )
    };
    let past = Some(RECORDED_AT.get() + 1);
    let unknown = refusal(exchange(&mut daemon, inspect(100, absent, reach(past, &[]))).await);

    let pending = exchange(
        &mut daemon,
        inspect(101, resource_id, reach(past, &[resource_id])),
    )
    .await;
    assert_eq!(state_read(pending), PendingState::Pending);
    let live_only = exchange(
        &mut daemon,
        inspect(102, resource_id, reach(None, &[resource_id])),
    )
    .await;
    assert_eq!(
        state_read(live_only),
        PendingState::Pending,
        "a grant that keeps no retained history reads the current approval it names"
    );
    for (request_id, history) in [(103, reach(past, &[])), (104, reach(None, &[]))] {
        let withheld =
            refusal(exchange(&mut daemon, inspect(request_id, resource_id, history)).await);
        assert_eq!(
            shape(&withheld, resource_id, &host),
            shape(&unknown, absent, &host),
            "without the name the record answers as unknown ({request_id})"
        );
    }

    let admitted = host
        .service
        .broker()
        .admit_approval(&answering(), &answer(&host, resource_id), DECODED_AT)
        .expect("an answer claims the approval");
    let claimed = exchange(
        &mut daemon,
        inspect(105, resource_id, reach(past, &[resource_id])),
    )
    .await;
    assert_eq!(
        state_read(claimed),
        PendingState::Claimed,
        "an approval an answer has claimed can still be decided"
    );
    drop(admitted);
}

/// KR-REQ-10.51: the exception is for the exact current decision. Once the approval has ended,
/// answered, withdrawn by its upstream or left uncertain, the same name no longer reaches past the
/// bound, and the record answers exactly as one this host does not hold. The control for each is
/// the same record under a grant whose bound reaches it, which reads it in its ended state.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_10_51_a_named_approval_that_has_ended_answers_as_unknown() {
    let host = host().await;
    let broker = host.service.broker();
    let absent = PendingResourceId::new(Uuid::from_bytes([0xab; 16]));

    let resolved = offer(&host, &request_frame(21, 0));
    let admitted = broker
        .admit_approval(&answering(), &answer(&host, resolved), DECODED_AT)
        .expect("admitted");
    broker
        .record_approval(&admitted, DECODED_AT)
        .expect("carried")
        .settled(DECODED_AT)
        .await
        .expect("answered");

    let withdrawn = offer(&host, &request_frame(22, 0));
    let request = broker.pending(withdrawn).expect("held").request;
    broker
        .upstream_resolved(&request, DECODED_AT)
        .expect("the upstream withdrew it");

    let uncertain = offer(&host, &request_frame(23, 0));
    let admitted = broker
        .admit_approval(&answering(), &answer(&host, uncertain), DECODED_AT)
        .expect("admitted");
    // The marker is written and nothing says what became of the bytes.
    drop(broker.mark_approval(&admitted, DECODED_AT).expect("marked"));

    let mut daemon = daemon(&host).await;
    let inspect = |request_id: u64, resource_id: PendingResourceId, history: HistoryScope| {
        scoped(
            Method::AgentApprovalInspect,
            &params(&host, instance(), resource_id),
            request_id,
            device(),
            history,
        )
    };
    let past = Some(RECORDED_AT.get() + 1);
    let unknown = refusal(exchange(&mut daemon, inspect(110, absent, reach(past, &[]))).await);
    for (request_id, resource_id, ended) in [
        (111, resolved, PendingState::Resolved),
        (114, withdrawn, PendingState::Cancelled),
        (117, uncertain, PendingState::Uncertain),
    ] {
        let within = exchange(
            &mut daemon,
            inspect(request_id, resource_id, reach(Some(0), &[])),
        )
        .await;
        assert_eq!(
            state_read(within),
            ended,
            "the record exists, and has ended"
        );
        for (next, history) in [
            (1, reach(past, &[resource_id])),
            (2, reach(None, &[resource_id])),
        ] {
            let withheld = refusal(
                exchange(
                    &mut daemon,
                    inspect(request_id + next, resource_id, history),
                )
                .await,
            );
            assert_eq!(withheld.code, ErrorCode::StaleSession, "{ended:?}");
            assert_eq!(
                shape(&withheld, resource_id, &host),
                shape(&unknown, absent, &host),
                "an ended approval is an old record like any other: {ended:?}"
            );
        }
    }
}

/// KR-REQ-10.51: a name picks out one resource. Two native connections of the instance both call
/// their first request `1`, and a grant naming the resource recorded on one reads that record and
/// not the other, which answers as unknown; a grant naming a resource this host does not hold
/// excepts neither.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_10_51_a_name_excepts_its_own_resource_and_no_other_with_the_same_upstream_identifier()
 {
    let host = host().await;
    let broker = host.service.broker();
    let other_connection = broker
        .open_native_connection(instance(), &[9; 32], &process(41), &plugin(), "1")
        .expect("a second native connection of the instance");
    let named = offer_on(&host, host.connection, &request_frame(1, 0));
    let unnamed = offer_on(&host, other_connection, &request_frame(1, 0));
    assert_ne!(named, unnamed);
    for resource_id in [named, unnamed] {
        assert_eq!(
            broker
                .decoding(resource_id)
                .expect("the ledger reads")
                .map(|entry| entry.upstream_request_id),
            Some(UpstreamRequestId::new("1").expect("an identifier")),
            "both requests carry the upstream identifier 1"
        );
    }
    let absent = PendingResourceId::new(Uuid::from_bytes([0xab; 16]));
    let mut daemon = daemon(&host).await;
    let inspect = |request_id: u64, resource_id: PendingResourceId, history: HistoryScope| {
        scoped(
            Method::AgentApprovalInspect,
            &params(&host, instance(), resource_id),
            request_id,
            device(),
            history,
        )
    };
    let past = Some(RECORDED_AT.get() + 1);
    let unknown = refusal(exchange(&mut daemon, inspect(120, absent, reach(past, &[]))).await);

    let read: AgentApprovalInspectResult =
        answered(exchange(&mut daemon, inspect(121, named, reach(past, &[named]))).await);
    assert_eq!(read.resource_id, named);
    for (request_id, resource_id, names) in [
        (122, unnamed, named),
        (123, named, absent),
        (124, unnamed, absent),
    ] {
        let withheld = refusal(
            exchange(
                &mut daemon,
                inspect(request_id, resource_id, reach(past, &[names])),
            )
            .await,
        );
        assert_eq!(
            shape(&withheld, resource_id, &host),
            shape(&unknown, absent, &host),
            "a name excepts its own resource only ({request_id})"
        );
    }
}

/// The scope is decided before the size of the answer: a record outside the scope is answered as
/// unknown however large it is, so its size does not say that it exists. The same record inside
/// the scope is refused with both sizes, as before.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_oversized_record_outside_the_scope_answers_as_unknown() {
    let host = host().await;
    let large = offer(&host, &request_frame(11, 100 * 1024));
    let mut daemon = daemon_receiving(
        &host,
        kr_protocol::hello::ReceiveLimits {
            max_control_frame_len: U64::new(64 * 1024),
            ..kr_protocol::hello::ReceiveLimits::default()
        },
    )
    .await;
    let inspect = |request_id: u64, history: HistoryScope| {
        scoped(
            Method::AgentApprovalInspect,
            &params(&host, instance(), large),
            request_id,
            device(),
            history,
        )
    };

    let outside = refusal(
        exchange(
            &mut daemon,
            inspect(91, reach(Some(RECORDED_AT.get() + 1), &[])),
        )
        .await,
    );
    assert_eq!(outside.code, ErrorCode::StaleSession, "{outside:?}");
    assert!(
        !outside.message.contains(&(64 * 1024).to_string()),
        "the refusal says nothing about the record's size: {}",
        outside.message
    );

    let inside = refusal(exchange(&mut daemon, inspect(92, reach(Some(0), &[]))).await);
    assert_eq!(inside.code, ErrorCode::InvalidArgument, "{inside:?}");
    assert!(inside.message.contains(&(64 * 1024).to_string()));
}

/// A worker states, in its answer to a hello, that it reads the history scope a forwarded read
/// carries, which is what a daemon reads before it sends one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_worker_states_that_it_reads_a_forwarded_scope() {
    let host = host().await;
    let client = within(
        "a local connection",
        LocalClient::connect(&host.endpoint, LocalClientKind::Controller, build()),
    )
    .await
    .expect("connects");
    assert!(
        kr_protocol::local::reads_history_scopes(&client.acknowledgement().capabilities),
        "stated: {:?}",
        client.acknowledgement().capabilities
    );
}
