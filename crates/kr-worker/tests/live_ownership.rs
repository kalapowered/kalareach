//! Section 24's owner of a session's live receipts, approvals and questions: the worker's own
//! journal and its in-memory broker. They survive a restart of the control daemon and of a plugin,
//! because neither holds any of them, and a worker's death ends their live authority and leaves
//! what it dispatched without an answer `unknown`.
//!
//! Each event is driven as the worker meets it. A daemon restart is the daemon's connection ending
//! with nothing said, and a replacement proving the next generation on the worker's real endpoint.
//! A plugin that reconnects is its connection ending, and the process this worker launched
//! connecting again under the identifier its requests were recorded under. A fresh launch of the
//! plugin, a process of its own, is refused that identifier: the broker restores one only to the
//! launch that made it, so a new execution never answers what an earlier one was asked. A worker's
//! death is a real one: this test binary is run again as a child process that writes its journal
//! and its question ledger as the worker does and is killed with `SIGKILL`, and the archive then
//! takes the journal over and recovers it.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-24.06 | every `kr_req_24_06_` test here |

#![cfg(unix)]

use std::io::{BufRead as _, Write as _};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use kr_controller::archive::{ArchiveService, OwnershipRefusal};
use kr_ipc::client::LocalClient;
use kr_ipc::endpoint::Listener;
use kr_ipc::verify::{ControllerIdentity, WorkerIdentity};
use kr_protocol::actor::{ActorEnvelope, ActorIngress};
use kr_protocol::attachment::{AttachMode, AttachmentCapability, SessionAttachParams};
use kr_protocol::broker::{
    BrokerGrant, BrokerGrants, DecodingTrust, InstanceCapabilityRecord, IntegrationMode,
};
use kr_protocol::envelope::{
    ActionTarget, ControlFrame, MutationRequest, Outcome, ParamsValue, Request,
};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::gateway::{
    DeclarativeEntry, DeclarativeTable, DownstreamRequestId, NativeFraming, NativeMethodClass,
    PendingResource, PendingState, RichMethodTable,
};
use kr_protocol::hello::PROTOCOL_VERSION;
use kr_protocol::identity::{
    DesktopBinding, ProcessStartIdentity, ProcessStartSource, WorkerProfile,
};
use kr_protocol::ids::{
    ActionId, ActionWindowId, ActorId, ApplicationInstanceId, BrokerBindingId, BuildId,
    CapabilityId, CapabilityRevision, ConnectionId, ControllerGeneration, GatewayConnectionId,
    MethodTableVersion, PendingResourceId, PluginId, PublisherId, QuestionId, RequestId,
    SessionEpoch, SessionId, UpstreamMethod, UpstreamRequestId,
};
use kr_protocol::local::{ForwardedMutation, ForwardedRequest, LocalClientKind};
use kr_protocol::method::{Method, MethodVersion};
use kr_protocol::question::{
    CallerToken, Question, QuestionAnswer, QuestionAnswerParams, QuestionCreateParams,
    QuestionKind, QuestionReadOwnParams, QuestionReadParams, QuestionReadResult,
    QuestionResolveResult, QuestionState,
};
use kr_protocol::receipt::{ActionReadParams, ActionReadResult, Receipt, ReceiptState};
use kr_protocol::recovery::{EventsSnapshotParams, EventsSnapshotResult};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{CanonicalSet, Digest256, DurationMs, Nullable, TimestampMs, U64, Uuid};
use kr_protocol::session::{Dimensions, DisplayNumber, ShellMode};
use kr_worker::broker::{
    BrokerError, BrokerTransport, Credential, ManagedProcess, PendingTransmission, ReconcileScope,
    TransportHandle, UpstreamDispatch, UpstreamOutcome, UpstreamRequest,
};
use kr_worker::journal::{Journal, Submission};
use kr_worker::questions::binding::VerifiedSource;
use kr_worker::questions::{Now, QuestionError, Questions};
use kr_worker::runtime::SessionRuntime;
use kr_worker::service::{ServiceBinding, WorkerService};
use kr_worker::session::{Session as TerminalSession, SessionConfig};

mod common;

use common::LIVENESS_DEADLINE;

/// Where the worker half of the death test writes its journal.
const JOURNAL: &str = "KR_LIVE_OWNERSHIP_JOURNAL";

/// The session the worker half writes its journal for.
const SESSION: &str = "KR_LIVE_OWNERSHIP_SESSION";

/// The name of the worker half, as the test harness selects it.
const WORKER_HALF: &str = "the_worker_half_of_the_death_test";

/// What the worker half prints once everything it holds is committed.
const HOLDING: &str = "kr-live-ownership: the worker holds its journal";

/// The private exchange the plugin's launch was given.
const CREDENTIAL: [u8; 32] = [9; 32];

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

/// The request the plugin's upstream writes as request `id`: a permission it asks a person for.
fn permission_request(id: u64) -> Vec<u8> {
    format!(
        r#"{{"id":{id},"method":"session/request_permission","params":{{"path":"/srv/notes.txt","options":[{{"optionId":"allow","name":"Allow this once"}},{{"optionId":"reject","name":"Reject"}}]}}}}"#
    )
    .into_bytes()
}

/// The native client's answer to request `id`.
fn permission_answer(id: u64) -> Vec<u8> {
    format!(r#"{{"id":{id},"result":{{"outcome":"allow"}}}}"#).into_bytes()
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

/// The start identity of the plugin process numbered `pid`.
fn process(pid: u64) -> ProcessStartIdentity {
    ProcessStartIdentity::new(pid, ProcessStartSource::MacosProcBsdInfo, 900 + pid)
}

/// The plugin this worker launched, as process `pid`.
fn launched(instance: ApplicationInstanceId, pid: u64) -> ManagedProcess {
    ManagedProcess::new(
        instance,
        process(pid),
        TransportHandle {
            transport: BrokerTransport::PrivateSocket,
            application_instance_id: instance,
            executable_digest: Digest256::from_bytes([3; 32]),
            process: process(pid),
        },
        Credential::from_bytes(CREDENTIAL),
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

/// A worker serving one session, with one plugin whose native requests the broker holds.
struct Host {
    _temp: kr_ipc::testing::TempHost,
    service: Arc<WorkerService>,
    session_id: SessionId,
    environment_id: kr_protocol::ids::EnvironmentId,
    endpoint: kr_ipc::paths::Endpoint,
    /// The control daemon's identity, which signs every generation a daemon proves.
    controller: Arc<ControllerIdentity>,
    /// The boot the daemon proves its generation against.
    boot: kr_protocol::identity::BootIdentity,
    /// The plugin's native connection, which its requests arrive on.
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
            runtime,
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
            Some(launched(instance(), 41)),
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
        .open_native_connection(instance(), &CREDENTIAL, &process(41), &plugin(), "1")
        .expect("the native connection is authenticated");
    broker.bind_connection_dispatch(connection, Arc::new(Answering) as Arc<dyn UpstreamDispatch>);
    Host {
        _temp: temp,
        service,
        session_id,
        environment_id,
        endpoint,
        controller,
        boot,
        connection,
    }
}

/// Records the plugin's request `id`, arriving now: an approval the broker holds for a person.
fn arrive(host: &Host, id: u64) -> PendingResourceId {
    host.service
        .broker()
        .forward_native(host.connection, &permission_request(id), kr_ipc::now_ms())
        .expect("forwarded")
        .1
        .expect("it expects a response")
        .resource_id
}

/// The agent in the session that asks, as the worker binds a helper: this process.
fn asker() -> VerifiedSource {
    VerifiedSource {
        process: kr_ipc::identity::current_process_start_identity().expect("a process identity"),
        executable: Some("kr-test-agent".to_owned()),
        session_member: true,
        ancestry: true,
        launch_channel: true,
        connection_id: ConnectionId::new(Uuid::from_bytes([3; 16])),
    }
}

/// What the agent asks.
fn asking(session_id: SessionId) -> QuestionCreateParams {
    QuestionCreateParams {
        session_id,
        request_id: "push-anyway".to_owned(),
        kind: QuestionKind::Confirm,
        context: "Two tests are failing.".to_owned(),
        question: "Push the branch anyway?".to_owned(),
        choices: Vec::new(),
        agent_name: Nullable::some("kr-test-agent".to_owned()),
        requested_expiry_ms: Nullable::some(DurationMs::new(600_000)),
        wait_ms: Nullable::null(),
    }
}

fn now() -> Now {
    Now {
        utc_ms: kr_ipc::now_ms(),
        boot_ms: kr_ipc::clock::boot_elapsed_ms(),
    }
}

/// The agent asks, and the question is pending in the worker's ledger. Returns what it asked and
/// the token the agent reads its answer with.
fn ask(host: &Host) -> (QuestionId, CallerToken) {
    let (asked, _) = host
        .service
        .questions()
        .create(&asker(), &asking(host.session_id), now())
        .expect("the agent asks");
    assert_eq!(asked.question.state, QuestionState::Pending);
    (asked.question.question_id, asked.caller_token)
}

/// What the agent that asked reads back about its question.
fn read_back(host: &Host, question_id: QuestionId, caller_token: CallerToken) -> Question {
    host.service
        .questions()
        .read_own(
            &asker(),
            &QuestionReadOwnParams {
                session_id: host.session_id,
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

/// The answer a person gives the question at `revision`.
fn yes(host: &Host, question: &Question) -> QuestionAnswerParams {
    QuestionAnswerParams {
        session_id: host.session_id,
        question_id: question.question_id,
        expected_revision: question.revision,
        answer: QuestionAnswer::Decision { decided: true },
    }
}

/// The local owner, on the worker's own socket.
async fn owner(host: &Host) -> LocalClient {
    within(
        "a local connection",
        LocalClient::connect(&host.endpoint, LocalClientKind::Cli, build()),
    )
    .await
    .expect("connects")
}

/// A control daemon connecting and proving `generation`, with what the worker said to it.
async fn prove(
    host: &Host,
    generation: u8,
) -> (
    LocalClient,
    Result<kr_protocol::worker::GenerationAccepted, kr_ipc::IpcError>,
) {
    let mut daemon = within(
        "the daemon's connection",
        LocalClient::connect(&host.endpoint, LocalClientKind::Controller, build()),
    )
    .await
    .expect("connects as the daemon");
    let identity = Arc::clone(&host.controller);
    let boot = host.boot.clone();
    let accepted = within(
        "the worker's answer to the generation",
        daemon.present_generation(move |nonce| {
            identity
                .generation_token(
                    ControllerGeneration::new(u64::from(generation)),
                    &boot,
                    nonce,
                )
                .map_err(kr_ipc::IpcError::from)
        }),
    )
    .await;
    (daemon, accepted)
}

/// A control daemon of `generation`, which the worker accepts.
async fn daemon(host: &Host, generation: u8) -> LocalClient {
    let (daemon, accepted) = prove(host, generation).await;
    accepted.expect("the worker accepts the generation");
    daemon
}

/// A person on this machine, whose requests the daemon of `generation` forwards over a
/// connection of that daemon's.
fn person(generation: u8) -> ActorEnvelope {
    ActorEnvelope {
        actor_id: person_id(),
        ingress: ActorIngress::LocalIpc,
        device_id: Nullable::null(),
        grant_id: Nullable::null(),
        grant_revision: Nullable::null(),
        controller_generation: ControllerGeneration::new(u64::from(generation)),
        connection_id: ConnectionId::new(Uuid::from_bytes([generation; 16])),
    }
}

fn person_id() -> ActorId {
    ActorId::new("local:501").expect("an actor")
}

/// Writes one frame to the worker and returns its answer to `request_id`.
async fn exchange(
    daemon: &mut LocalClient,
    frame: ControlFrame,
    request_id: RequestId,
) -> Result<ParamsValue, ProtocolError> {
    within("the worker's answer", async {
        daemon
            .writer()
            .write_message(&frame)
            .await
            .expect("writes the frame");
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

/// Forwards one of a person's mutations, as the daemon does.
async fn forward<T: serde::Serialize>(
    daemon: &mut LocalClient,
    host: &Host,
    person: &ActorEnvelope,
    action_id: ActionId,
    method: Method,
    params: &T,
) -> Result<ParamsValue, ProtocolError> {
    let request_id = next_request();
    let frame = ControlFrame::Forwarded(Box::new(ForwardedMutation {
        mutation: MutationRequest {
            request_id,
            method: method.into(),
            method_version: MethodVersion::V1,
            action_id,
            grant_id: Nullable::null(),
            target: host.target(),
            expected: ParamsValue::empty(),
            action_window_id: ActionWindowId::new("forwarded").expect("a window identifier"),
            requested_ttl_ms: kr_protocol::limits::DEFAULT_MUTATION_TTL,
            params: ParamsValue::from_typed(params).expect("encodes"),
        },
        actor: person.clone(),
        // A person on this machine acts under no grant, so there are no rights to narrow them by.
        grant_rights: CanonicalSet::new(),
        accepted_deadline_boot_ms: U64::new(kr_ipc::clock::boot_elapsed_ms() + 120_000),
        history: None,
        screen_basis: None,
    }));
    exchange(daemon, frame, request_id).await
}

/// Who reads what the worker holds: the local owner on the worker's own socket, or a control
/// daemon forwarding a person's reads.
enum Reader<'a> {
    Owner(&'a mut LocalClient),
    Daemon(&'a mut LocalClient, ActorEnvelope),
}

impl Reader<'_> {
    async fn read<T: serde::Serialize>(&mut self, method: Method, params: &T) -> ParamsValue {
        let answer = match self {
            Self::Owner(client) => within("the owner's read", client.request(method, params))
                .await
                .expect("the call reaches the worker"),
            Self::Daemon(daemon, person) => {
                let request_id = next_request();
                let frame = ControlFrame::ForwardedRead(Box::new(ForwardedRequest {
                    request: Request {
                        request_id,
                        method: method.into(),
                        method_version: MethodVersion::V1,
                        params: ParamsValue::from_typed(params).expect("encodes"),
                    },
                    // A person on this machine holds an authority that does not run out.
                    authority_deadline_boot_ms: Nullable::null(),
                    actor: person.clone(),
                    history: None,
                }));
                exchange(daemon, frame, request_id).await
            }
        };
        answer.unwrap_or_else(|error| panic!("{} is answered: {error:?}", method.as_str()))
    }
}

/// The receipt, the question and the approval the worker holds, as one reader is shown them.
#[derive(Debug, PartialEq, Eq)]
struct Held {
    receipt: Receipt,
    question: Question,
    approval: PendingResource,
}

impl Held {
    async fn read(
        reader: &mut Reader<'_>,
        host: &Host,
        action_id: ActionId,
        question_id: QuestionId,
        approval: PendingResourceId,
    ) -> Self {
        let receipt: ActionReadResult = reader
            .read(
                Method::ActionRead,
                &ActionReadParams {
                    action_id,
                    session_id: None,
                },
            )
            .await
            .to_typed()
            .expect("a receipt");
        let questions: QuestionReadResult = reader
            .read(
                Method::QuestionRead,
                &QuestionReadParams {
                    session_id: host.session_id,
                    question_id: Nullable::some(question_id),
                    include_resolved: true,
                },
            )
            .await
            .to_typed()
            .expect("the questions");
        let snapshot: EventsSnapshotResult = reader
            .read(
                Method::EventsSnapshot,
                &EventsSnapshotParams {
                    session_id: host.session_id,
                    agent_resources_from: Nullable::null(),
                },
            )
            .await
            .to_typed()
            .expect("a snapshot");
        Self {
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
                .find(|resource| resource.resource_id == approval)
                .expect("the approval is in the snapshot"),
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_24_06_a_daemon_restart_keeps_the_receipt_the_approval_and_the_question() {
    // The daemon holds none of them: the receipt is in the worker's journal, the question in its
    // ledger, and the approval in its broker. So a daemon that goes without a word, and the one
    // that replaces it, find them exactly as they were, and what is pending is still live.
    let host = host().await;
    let (question_id, caller_token) = ask(&host);
    let approval = arrive(&host, 1);

    let mut first = daemon(&host, 1).await;
    let action_id = ActionId::new(kr_ipc::new_uuid());
    forward(
        &mut first,
        &host,
        &person(1),
        action_id,
        Method::SessionAttach,
        &host.terminal(),
    )
    .await
    .expect("the person's attach is admitted");
    let before = Held::read(
        &mut Reader::Daemon(&mut first, person(1)),
        &host,
        action_id,
        question_id,
        approval,
    )
    .await;
    assert_eq!(before.question.state, QuestionState::Pending);
    assert_eq!(before.approval.state, PendingState::Pending);

    // The daemon goes, as a killed daemon goes: its connection ends and nothing is said. Its
    // replacement proves the next generation, and the one before it is fenced.
    drop(first);
    let mut second = daemon(&host, 2).await;
    assert_eq!(
        host.service.accepted_generation(),
        Some(ControllerGeneration::new(2))
    );
    let (_stale, fenced) = prove(&host, 1).await;
    fenced.expect_err("a daemon of the earlier generation is refused");

    let after = Held::read(
        &mut Reader::Daemon(&mut second, person(2)),
        &host,
        action_id,
        question_id,
        approval,
    )
    .await;
    assert_eq!(
        after, before,
        "the receipt, the question and the approval are where the first daemon left them"
    );

    // What is pending is live: the person answers the question through the replacement, and the
    // agent that asked reads the answer.
    let answered: QuestionResolveResult = forward(
        &mut second,
        &host,
        &person(2),
        ActionId::new(kr_ipc::new_uuid()),
        Method::QuestionAnswer,
        &yes(&host, &after.question),
    )
    .await
    .expect("the answer is admitted")
    .to_typed()
    .expect("decodes");
    assert_eq!(answered.state, QuestionState::Answered);
    let told = read_back(&host, question_id, caller_token);
    let record = told.answer.as_ref().expect("the agent is told the answer");
    assert_eq!(record.answer, QuestionAnswer::Decision { decided: true });
    assert_eq!(record.actor_id, person_id());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_24_06_a_plugin_that_reconnects_finds_the_receipt_the_approval_and_the_question() {
    // The plugin holds none of them either. Its connection ending is not an answer to the request
    // it made; the process this worker launched connects again under the identifier its request
    // was recorded under, says the request is still open, and answers it there.
    let host = host().await;
    let (question_id, caller_token) = ask(&host);
    let approval = arrive(&host, 1);
    let mut window = owner(&host).await;
    let action_id = ActionId::new(kr_ipc::new_uuid());
    within(
        "the attach",
        window.mutate(
            Method::SessionAttach,
            action_id,
            host.target(),
            &host.terminal(),
        ),
    )
    .await
    .expect("the call reaches the worker")
    .expect("attaches");
    let before = Held::read(
        &mut Reader::Owner(&mut window),
        &host,
        action_id,
        question_id,
        approval,
    )
    .await;
    assert_eq!(before.question.state, QuestionState::Pending);
    assert_eq!(before.approval.state, PendingState::Pending);

    let broker = host.service.broker();
    broker.close_connection(host.connection);
    assert_eq!(
        broker.pending(approval).map(|resource| resource.state),
        Some(PendingState::Pending),
        "a connection ending is not an answer"
    );

    // A fresh launch of the plugin, a process of its own, is not given the identifier: the
    // broker restores one only to the process it launched, presenting that launch's private
    // exchange.
    let fresh = broker
        .restore_native_connection(
            host.connection,
            instance(),
            &CREDENTIAL,
            &process(42),
            &plugin(),
            "1",
        )
        .expect_err("another process is not the launch that made the connection");
    assert!(
        matches!(fresh, BrokerError::PermissionDenied { .. }),
        "{fresh}"
    );

    // The launched process reconnects and says what it still has open.
    broker
        .restore_native_connection(
            host.connection,
            instance(),
            &CREDENTIAL,
            &process(41),
            &plugin(),
            "1",
        )
        .expect("the launched process restores its connection");
    broker.bind_connection_dispatch(
        host.connection,
        Arc::new(Answering) as Arc<dyn UpstreamDispatch>,
    );
    let reconciled = broker
        .reconcile(
            ReconcileScope {
                application_instance_id: instance(),
                connection: host.connection,
            },
            &[DownstreamRequestId::new(
                host.connection,
                UpstreamRequestId::new("1").expect("an identifier"),
            )],
            kr_ipc::now_ms(),
        )
        .expect("the reconnect reconciles");
    assert_eq!(
        reconciled.still_pending,
        vec![approval],
        "the request the plugin still has open stays answerable"
    );

    let after = Held::read(
        &mut Reader::Owner(&mut window),
        &host,
        action_id,
        question_id,
        approval,
    )
    .await;
    assert_eq!(
        after, before,
        "the receipt, the question and the approval are where the plugin left them"
    );

    // The approval is answered on the restored connection, once, and the question by the owner.
    let answered = broker
        .native_answer_through(
            host.connection,
            &permission_answer(1),
            kr_ipc::now_ms(),
            |_| Ok(()),
        )
        .expect("the answer is carried on the restored connection");
    assert_eq!(answered.resource_id, approval);
    assert_eq!(answered.state, PendingState::Resolved);
    let resolved: QuestionResolveResult = within(
        "the answer",
        window.mutate(
            Method::QuestionAnswer,
            ActionId::new(kr_ipc::new_uuid()),
            host.target(),
            &yes(&host, &after.question),
        ),
    )
    .await
    .expect("the call reaches the worker")
    .expect("the owner answers")
    .to_typed()
    .expect("decodes");
    assert_eq!(resolved.state, QuestionState::Answered);
    assert!(
        read_back(&host, question_id, caller_token)
            .answer
            .is_present(),
        "the agent is told the answer"
    );
}

/// The action the worker had sent on its way when it died.
fn dispatched() -> ActionId {
    ActionId::new(Uuid::from_bytes([6; 16]))
}

/// A person's request that the session close, as the worker accepted it.
fn close_intent() -> Submission {
    Submission {
        actor_id: person_id(),
        action_id: dispatched(),
        method: Method::SessionClose.into(),
        method_version: MethodVersion::V1,
        payload_digest: Digest256::from_bytes([6; 32]),
        subject_digest: Digest256::from_bytes([6; 32]),
        intent: vec![0xa0],
        accepted_deadline_ms: Some(TimestampMs::new(kr_ipc::now_ms().get() + 120_000)),
        now_ms: kr_ipc::now_ms(),
    }
}

/// The worker half: writes what a worker holds to the journal `KR_LIVE_OWNERSHIP_JOURNAL` names,
/// says so, and waits to be killed. It does nothing at all unless the death test started it.
#[test]
#[ignore = "the worker half of the death test, run only as that test's own child process"]
fn the_worker_half_of_the_death_test() {
    let (Some(path), Some(session)) = (std::env::var_os(JOURNAL), std::env::var_os(SESSION)) else {
        return;
    };
    let path = std::path::PathBuf::from(path);
    let session_id = SessionId::new(
        session
            .to_str()
            .and_then(|text| text.parse::<Uuid>().ok())
            .expect("a session identifier"),
    );
    // A person's close is accepted, and the worker writes its dispatch marker before the effect.
    let mut journal = Journal::open(&path).expect("the worker opens its journal");
    journal
        .accept(&close_intent())
        .expect("the intent is committed");
    journal
        .mark_dispatching(person_id(), dispatched(), kr_ipc::now_ms())
        .expect("the marker is committed before the effect");
    // And an agent in the session asks. The agent is this process, so it ends with the worker, as
    // the processes of a session end when their worker's session is closed.
    let questions = Questions::open(Some(path.as_path()), session_id, SessionEpoch::V1)
        .expect("the question ledger opens");
    questions
        .create(&asker(), &asking(session_id), now())
        .expect("the agent asks");
    let mut out = std::io::stdout();
    writeln!(out, "{HOLDING}").expect("says so");
    out.flush().expect("says so now");
    // Killed here. Should the test that started this process end without killing it, its end of
    // this pipe closes and this returns.
    let mut line = String::new();
    let _ = std::io::stdin().read_line(&mut line);
}

#[test]
fn kr_req_24_06_a_workers_death_ends_what_it_held_live_and_leaves_its_dispatch_unknown() {
    let temp = kr_ipc::testing::TempHost::create();
    let archive = ArchiveService::new(temp.environment());
    let session_id = SessionId::new(kr_ipc::new_uuid());
    let path = archive.paths().journal_database(session_id);
    std::fs::create_dir_all(path.parent().expect("a parent")).expect("the journal directory");

    let mut worker = Command::new(std::env::current_exe().expect("this test binary"))
        .args([
            WORKER_HALF,
            "--exact",
            "--ignored",
            "--test-threads=1",
            "--nocapture",
        ])
        .env(JOURNAL, &path)
        .env(SESSION, session_id.to_string())
        .current_dir(temp.root())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the worker starts");
    let mut said = Vec::new();
    let mut holding = false;
    for line in std::io::BufReader::new(worker.stdout.take().expect("its output"))
        .lines()
        .map_while(Result::ok)
    {
        if line.contains(HOLDING) {
            holding = true;
            break;
        }
        said.push(line);
    }
    if !holding {
        let ended = worker.wait_with_output().expect("the worker ended");
        panic!(
            "the worker never said it held its journal: {said:?} {}",
            String::from_utf8_lossy(&ended.stderr)
        );
    }
    let identity =
        kr_ipc::identity::process_start_identity(worker.id()).expect("the worker's identity");

    // While the worker runs, its journal is its own.
    let refused = archive
        .take_ownership(session_id, DisplayNumber::new(1), &identity)
        .expect_err("a running worker keeps its journal");
    assert!(
        refused.to_string().contains(
            &OwnershipRefusal::WorkerAlive {
                session: session_id.to_string(),
            }
            .to_string()
        ),
        "{refused}"
    );

    // The worker dies: nothing is released, nothing is flushed and nothing is closed.
    worker.kill().expect("the worker is killed");
    let ended = worker.wait().expect("the worker is reaped");
    assert_eq!(
        std::os::unix::process::ExitStatusExt::signal(&ended),
        Some(9),
        "the worker ended by SIGKILL: {ended}"
    );

    let ownership = archive
        .take_ownership(session_id, DisplayNumber::new(1), &identity)
        .expect("the dead worker's journal is taken over");
    let recovered = archive
        .recover_journal(&ownership)
        .expect("the journal recovers");
    assert_eq!(
        recovered.left_unknown, 1,
        "the marker the worker committed survived its death"
    );
    let receipt = archive
        .receipt(session_id, &person_id(), dispatched(), true)
        .expect("reads the receipt")
        .receipt;
    assert_eq!(
        receipt.state,
        ReceiptState::Unknown,
        "what went without an answer is unknown, not done and not undone"
    );
    assert_eq!(
        receipt.error.as_ref().map(|error| error.code),
        Some(ErrorCode::OutcomeUnknown)
    );
    assert!(
        Journal::open(&path)
            .expect("the journal opens again")
            .mark_dispatching(person_id(), dispatched(), kr_ipc::now_ms())
            .is_err(),
        "and it is never sent again"
    );

    // Nor is the question the worker held left to be answered: the agent that asked went with it.
    let questions = Questions::open(Some(path.as_path()), session_id, SessionEpoch::V1)
        .expect("the question ledger opens");
    let (read, _) = questions
        .read(
            &QuestionReadParams {
                session_id,
                question_id: Nullable::null(),
                include_resolved: true,
            },
            now(),
        )
        .expect("reads the questions");
    let [question] = read.questions.as_slice() else {
        panic!("the worker held one question: {:?}", read.questions);
    };
    assert_eq!(question.state, QuestionState::Expired);
    let refused = questions
        .answer(
            &person_id(),
            None,
            &QuestionAnswerParams {
                session_id,
                question_id: question.question_id,
                expected_revision: question.revision,
                answer: QuestionAnswer::Decision { decided: true },
            },
            now(),
        )
        .expect_err("nobody answers it now");
    assert!(
        matches!(refused, QuestionError::Expired { .. }),
        "{refused}"
    );
}
