//! The agent mutations through the real dispatch path: the receipt each refusal writes, and where
//! the transport work happens relative to the session boundary.
//!
//! The suites beside this one drive the broker directly, which is where the decisions live. What
//! this one establishes is the half that only the service can show: that a refusal the host can
//! make is a rejection with a receipt rather than an outcome nobody can establish, and that an
//! upstream that is slow to answer does not hold the session's own lock while it thinks.

use std::sync::Arc;

use kr_ipc::client::LocalClient;
use kr_ipc::endpoint::Listener;
use kr_ipc::verify::{ControllerIdentity, WorkerIdentity};
use kr_protocol::agent::{AgentMutationTarget, AgentPromptParams, PromptText};
use kr_protocol::broker::{BrokerGrant, BrokerGrants, IntegrationMode};
use kr_protocol::envelope::{
    ActionTarget, ControlFrame, MutationRequest, Outcome, ParamsValue, Request,
};
use kr_protocol::error::ErrorCode;
use kr_protocol::hello::PROTOCOL_VERSION;
use kr_protocol::identity::{
    DesktopBinding, ProcessStartIdentity, ProcessStartSource, WorkerProfile,
};
use kr_protocol::ids::{
    ActionId, AgentBindingRevision, ApplicationInstanceId, BrokerBindingId, BuildId, CapabilityId,
    CapabilityRevision, ControllerGeneration, PluginId, PublisherId, RequestId, SessionEpoch,
    SessionId,
};
use kr_protocol::method::{Method, MethodVersion};
use kr_protocol::receipt::ReceiptState;
use kr_protocol::scalars::{Digest256, DurationMs, Nullable, TimestampMs, Uuid};
use kr_protocol::session::{Dimensions, DisplayNumber, ShellMode};
use kr_worker::broker::{
    BrokerError, BrokerTransport, Credential, ManagedProcess, PendingTransmission, TransportHandle,
    UpstreamDispatch, UpstreamOutcome, UpstreamRequest, subject,
};
use kr_worker::pty::ShellCommand;
use kr_worker::runtime::SessionRuntime;
use kr_worker::service::{ServiceBinding, WorkerService};
use kr_worker::session::{Session, SessionConfig};

struct Host {
    _temp: kr_ipc::testing::TempHost,
    service: Arc<WorkerService>,
    session_id: SessionId,
    endpoint: kr_ipc::paths::Endpoint,
    environment_id: kr_protocol::ids::EnvironmentId,
    journal_path: std::path::PathBuf,
}

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

fn instance() -> ApplicationInstanceId {
    ApplicationInstanceId::new(Uuid::from_bytes([2; 16]))
}

fn binding() -> BrokerBindingId {
    BrokerBindingId::new(Uuid::from_bytes([9; 16]))
}

fn capability(name: &str) -> CapabilityId {
    CapabilityId::new(name).expect("valid")
}

/// A transport that takes as long as it is told to, so a test can watch what waits for it.
#[derive(Debug)]
struct SlowUpstream {
    holds: std::time::Duration,
    carried: std::sync::atomic::AtomicUsize,
}

impl UpstreamDispatch for SlowUpstream {
    fn admit(&self, _request: &kr_worker::broker::UpstreamRequest) -> Result<(), BrokerError> {
        Ok(())
    }

    fn submit(&self, request: &UpstreamRequest) -> Result<PendingTransmission, BrokerError> {
        std::thread::sleep(self.holds);
        self.carried
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(PendingTransmission::settled(Ok(UpstreamOutcome {
            upstream_request_id: None,
            turn_id: request.turn_id.clone(),
            provenance: kr_protocol::broker::ActionProvenance::UpstreamTypedRpc,
        })))
    }
}

async fn host() -> Host {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let environment_id = temp.environment_id();
    let session_id = SessionId::new(kr_ipc::new_uuid());
    let boot = kr_ipc::identity::boot_identity().expect("a boot identity");
    let process = kr_ipc::identity::current_process_start_identity().expect("a process identity");
    let identity = Arc::new(
        WorkerIdentity::generate(
            session_id,
            SessionEpoch::V1,
            boot.clone(),
            process,
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
        shell: ShellCommand {
            program: "/bin/sh".to_owned(),
            arguments: vec!["-c".to_owned(), "sleep 30".to_owned()],
            cwd: "/".to_owned(),
            environment: vec![("PATH".to_owned(), "/usr/bin:/bin".to_owned())],
        },
        shell_mode: ShellMode::NativeCompat,
        worker_profile: WorkerProfile::HeadlessUser,
        desktop: DesktopBinding::none(),
        dimensions: Dimensions::new(80, 24),
        journal_path: Some(environment.journal_database(session_id)),
        spool_directory: Some(environment.session_spool(session_id)),
        send_queue_bytes: 1024 * 1024,
        resident_bytes: 64 * 1024,
    };
    let journal_path = config.journal_path.clone().expect("the harness journals");
    let journal_path_for_tests = journal_path.clone();
    if let Some(parent) = journal_path.parent() {
        std::fs::create_dir_all(parent).expect("the journal directory");
    }
    let mut session = Session::open(config).expect("opens the session");
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
                boot_identity: boot,
                controller_public_key: *controller.public_key(),
                controller_generation: ControllerGeneration::new(1),
                journal_path: Some(journal_path),
                build_id: build(),
            },
        )
        .expect("a worker service"),
    );
    tokio::spawn(Arc::clone(&service).serve(listener));
    Host {
        _temp: temp,
        service,
        session_id,
        endpoint,
        environment_id,
        journal_path: journal_path_for_tests,
    }
}

/// Registers the instance every test here acts on, with the capability a prompt needs.
fn register(host: &Host, dispatch: Option<Arc<dyn UpstreamDispatch>>) {
    let broker = host.service.broker();
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
                    process,
                },
                Credential::from_bytes([9; 32]),
                true,
                TimestampMs::new(1),
            )),
        )
        .expect("the instance is registered");
    broker
        .bind(
            binding(),
            instance(),
            PluginId::new("kalareach.codex").expect("valid"),
            PublisherId::new("kalareach").expect("valid"),
            Digest256::from_bytes([5; 32]),
            BrokerGrants::granted([BrokerGrant::UpstreamAction]),
            None,
            TimestampMs::new(1),
        )
        .expect("the binding is recorded");
    broker
        .record_capability(kr_protocol::broker::InstanceCapabilityRecord {
            capability_id: capability("agent.prompt"),
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
        .expect("the capability is recorded");
    if let Some(dispatch) = dispatch {
        broker
            .bind_dispatch(instance(), dispatch)
            .expect("the transport is bound");
    }
}

async fn cli(host: &Host) -> LocalClient {
    LocalClient::connect(&host.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects")
}

use kr_protocol::local::LocalClientKind;

fn prompt_mutation(client: &LocalClient, host: &Host, request_id: u64) -> MutationRequest {
    MutationRequest {
        request_id: RequestId::new(request_id),
        method: Method::AgentPromptSubmit.into(),
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
        action_window_id: client.action_window().action_window_id.clone(),
        requested_ttl_ms: DurationMs::new(60_000),
        params: ParamsValue::from_typed(&AgentPromptParams {
            target: AgentMutationTarget {
                subject: subject(host.session_id, instance()),
                binding_revision: AgentBindingRevision::new(1),
            },
            draft_id: Nullable::null(),
            text: Nullable::some(PromptText::new("hello").expect("valid")),
        })
        .expect("encodes"),
    }
}

async fn send(client: &mut LocalClient, mutation: MutationRequest) -> Outcome {
    client
        .writer()
        .write_message(&ControlFrame::Mutation(Box::new(mutation)))
        .await
        .expect("writes the mutation");
    loop {
        match client.recv().await.expect("the worker answers") {
            ControlFrame::Response(response) => return response.outcome,
            ControlFrame::Notification(_) | ControlFrame::Event(_) => {}
            other => panic!("the worker answered {other:?}"),
        }
    }
}

async fn receipt(client: &mut LocalClient, action_id: ActionId) -> kr_protocol::receipt::Receipt {
    let outcome = {
        client
            .writer()
            .write_message(&ControlFrame::Request(Request {
                request_id: RequestId::new(900),
                method: Method::ActionRead.into(),
                method_version: MethodVersion::V1,
                params: ParamsValue::from_typed(&kr_protocol::receipt::ActionReadParams {
                    action_id,
                    session_id: None,
                })
                .expect("encodes"),
            }))
            .await
            .expect("writes the request");
        loop {
            match client.recv().await.expect("the worker answers") {
                ControlFrame::Response(response) => break response.outcome,
                ControlFrame::Notification(_) | ControlFrame::Event(_) => {}
                other => panic!("the worker answered {other:?}"),
            }
        }
    };
    let Outcome::Ok(value) = outcome else {
        panic!("the receipt is readable: {outcome:?}");
    };
    let result: kr_protocol::receipt::ActionReadResult =
        value.to_typed().expect("the result decodes");
    result.receipt
}

/// KR-REQ-12.06: a mutation with no upstream to reach is refused with a receipt that says it was
/// refused, not one that says nobody can tell.
#[tokio::test]
async fn kr_req_12_06_a_mutation_with_no_upstream_is_refused_before_its_marker() {
    let host = host().await;
    register(&host, None);
    let mut client = cli(&host).await;
    let mutation = prompt_mutation(&client, &host, 11);
    let action_id = mutation.action_id;
    let outcome = send(&mut client, mutation).await;
    let Outcome::Error(error) = outcome else {
        panic!("a prompt with no transport is refused: {outcome:?}");
    };
    assert_eq!(error.code, ErrorCode::UnsupportedCapability);
    let receipt = receipt(&mut client, action_id).await;
    assert_eq!(
        receipt.state,
        ReceiptState::Rejected,
        "a refusal this host can decide is a rejection rather than an outcome nobody can \
         establish"
    );
}

/// KR-REQ-12.04 and KR-REQ-12.06: an admitted operation leaves the session boundary before its
/// bytes go, so two of them overlap instead of queueing behind one another.
///
/// The transport here holds each submission for 700 ms. If the transmission happened inside the
/// session boundary the two prompts would be serial, because that boundary is one mutation at a
/// time and terminal ingestion needs the same mutex. They are not, so they overlap.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_12_04_an_admitted_operation_leaves_the_session_boundary_before_it_transmits() {
    let host = host().await;
    let holds = std::time::Duration::from_millis(700);
    let upstream = Arc::new(SlowUpstream {
        holds,
        carried: std::sync::atomic::AtomicUsize::new(0),
    });
    register(
        &host,
        Some(Arc::clone(&upstream) as Arc<dyn UpstreamDispatch>),
    );

    // Both clients are connected first, so what they wait for is each other and not a handshake.
    let mut first = cli(&host).await;
    let mut second = cli(&host).await;
    let one = prompt_mutation(&first, &host, 12);
    let two = prompt_mutation(&second, &host, 13);

    let started = std::time::Instant::now();
    let (left, right) = tokio::join!(
        tokio::spawn(async move { send(&mut first, one).await }),
        async move {
            // A moment behind, so the second one is admitted while the first is with its upstream
            // rather than before it got there.
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            send(&mut second, two).await
        }
    );
    let elapsed = started.elapsed();
    assert!(
        matches!(left.expect("the first task finishes"), Outcome::Ok(_)),
        "the first prompt was applied"
    );
    assert!(matches!(right, Outcome::Ok(_)), "{right:?}");
    assert!(
        elapsed < holds * 2,
        "two prompts took {elapsed:?}, which is what queueing one behind the other would cost"
    );
    assert_eq!(
        upstream.carried.load(std::sync::atomic::Ordering::SeqCst),
        2,
        "both prompts reached the upstream"
    );
}

/// A transport that makes the receipt journal unwritable while the operation is being admitted.
///
/// It takes the journal's own write lock from a second connection, which is what a journal that
/// has stopped accepting writes looks like from inside this host: the admission has been taken and
/// the dispatch marker cannot be committed.
#[derive(Debug)]
struct JournalHoldingUpstream {
    journal: std::path::PathBuf,
    held: std::sync::Mutex<Option<rusqlite::Connection>>,
    carried: std::sync::atomic::AtomicUsize,
}

impl JournalHoldingUpstream {
    fn release(&self) {
        drop(
            self.held
                .lock()
                .expect("the lock record is not poisoned")
                .take(),
        );
    }
}

impl UpstreamDispatch for JournalHoldingUpstream {
    fn admit(&self, _request: &UpstreamRequest) -> Result<(), BrokerError> {
        let connection = rusqlite::Connection::open(&self.journal).expect("the journal opens");
        connection
            .execute_batch("BEGIN IMMEDIATE;")
            .expect("the write lock is taken");
        *self.held.lock().expect("the lock record is not poisoned") = Some(connection);
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

/// KR-REQ-09 and KR-REQ-12.06: a dispatch marker this host could not write leaves nothing
/// executable behind it.
///
/// The admission is taken before the marker, so the window this closes is the one between them.
/// The journal stops accepting writes inside it: the marker fails, the admission is given up, and
/// nothing reaches the upstream. What the caller is told is a storage failure, and the receipt does
/// not say the prompt was applied.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_12_06_a_marker_that_could_not_be_written_leaves_nothing_to_transmit() {
    let host = host().await;
    let upstream = Arc::new(JournalHoldingUpstream {
        journal: host.journal_path.clone(),
        held: std::sync::Mutex::new(None),
        carried: std::sync::atomic::AtomicUsize::new(0),
    });
    register(
        &host,
        Some(Arc::clone(&upstream) as Arc<dyn UpstreamDispatch>),
    );
    let mut client = cli(&host).await;
    let mutation = prompt_mutation(&client, &host, 14);
    let action_id = mutation.action_id;

    let outcome = send(&mut client, mutation).await;
    let Outcome::Error(error) = outcome else {
        panic!("a marker that could not be written is not an applied prompt: {outcome:?}");
    };
    assert_eq!(error.code, ErrorCode::StorageUnavailable);
    assert_eq!(
        upstream.carried.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "the admission was given up, so nothing carried the operation"
    );

    // Storage comes back, and what the receipt says is that the intent was committed and no
    // dispatch marker was ever written for it.
    upstream.release();
    let receipt = receipt(&mut client, action_id).await;
    assert_eq!(
        receipt.state,
        ReceiptState::Accepted,
        "the marker was never written, so the receipt has not moved past acceptance"
    );
}

/// A transport that records what it was asked to carry, for a test that expects nothing carried.
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

fn approval_table() -> kr_protocol::gateway::DeclarativeTable {
    let mut table = kr_protocol::gateway::DeclarativeTable {
        plugin_id: PluginId::new("kalareach.codex").expect("valid"),
        publisher_id: PublisherId::new("kalareach").expect("valid"),
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
            method: kr_protocol::ids::UpstreamMethod::new("session/request_permission")
                .expect("valid"),
            class: kr_protocol::gateway::NativeMethodClass::Mutation,
            expects_response: true,
            approval_option_field: Nullable::some("option_id".to_owned()),
            reverse: Nullable::null(),
        }],
    };
    table.digest = table.canonical_digest().expect("encodable");
    table
}

/// Opens the gateway this host's approvals arrive on, and offers one interpreted approval.
///
/// The host set up by `register` is the rich half. This is the native half: the qualified table,
/// the authenticated connection, the transport that would carry an answer out, and one request a
/// decoder has given meaning to.
fn offer_approval(
    host: &Host,
    upstream: Arc<CountingUpstream>,
) -> kr_protocol::ids::PendingResourceId {
    let broker = host.service.broker();
    broker
        .bind(
            binding(),
            instance(),
            PluginId::new("kalareach.codex").expect("valid"),
            PublisherId::new("kalareach").expect("valid"),
            Digest256::from_bytes([5; 32]),
            BrokerGrants::granted([
                BrokerGrant::UpstreamAction,
                BrokerGrant::ApprovalInterpreter,
            ]),
            Some(kr_protocol::broker::DecodingTrust {
                plugin_id: PluginId::new("kalareach.codex").expect("valid"),
                publisher_id: PublisherId::new("kalareach").expect("valid"),
                package_digest: Digest256::from_bytes([5; 32]),
                methods: [
                    kr_protocol::ids::UpstreamMethod::new("session/request_permission")
                        .expect("valid"),
                ]
                .into_iter()
                .collect(),
                schema_versions: ["kr-approval/1".to_owned()].into_iter().collect(),
                max_decisions: kr_protocol::scalars::U64::new(4),
                may_encode_response: true,
                granted_at: TimestampMs::new(1),
            }),
            TimestampMs::new(1),
        )
        .expect("the binding carries the interpreter grant");
    record_evidence(
        host,
        "agent.approval",
        CapabilityRevision::new(1),
        kr_protocol::broker::InstanceCapabilityState::QualifiedAvailable,
    );
    broker
        .pin_table(
            instance(),
            approval_table(),
            kr_protocol::gateway::RichMethodTable {
                table_version: kr_protocol::ids::MethodTableVersion::new(1),
                upstream_protocol_version: "1".to_owned(),
                entries: vec![kr_protocol::gateway::RichMethodEntry {
                    method: kr_protocol::ids::UpstreamMethod::new("session/cancel").expect("valid"),
                    class: kr_protocol::gateway::NativeMethodClass::Mutation,
                    required_right: kr_protocol::rights::ActionRight::AgentCancel,
                    operation: Nullable::some(kr_protocol::gateway::RichOperation::TurnCancel),
                    provenance: kr_protocol::broker::ActionProvenance::UpstreamTypedRpc,
                }],
            },
        )
        .expect("the installed tables are pinned");
    broker
        .open_native_connection(
            instance(),
            &[9; 32],
            &ProcessStartIdentity::new(41, ProcessStartSource::MacosProcBsdInfo, 900),
            &PluginId::new("kalareach.codex").expect("valid"),
            "1",
        )
        .expect("the native connection is authenticated");
    broker.bind_connection_dispatch(
        kr_protocol::ids::GatewayConnectionId::new(1),
        upstream as Arc<dyn UpstreamDispatch>,
    );
    let opaque = broker
        .forward_native(
            kr_protocol::ids::GatewayConnectionId::new(1),
            br#"{"id":11,"method":"session/request_permission"}"#,
            TimestampMs::new(2),
        )
        .expect("forwarded")
        .1
        .expect("it expects a response");
    broker
        .interpret(
            binding(),
            opaque.resource_id,
            kr_protocol::broker::DecodedProjection {
                schema_version: "kr-approval/1".to_owned(),
                summary: "the agent wants to write a file".to_owned(),
                decisions: vec![kr_protocol::broker::OfferedDecision {
                    option_id: "allow".to_owned(),
                    label: "Allow".to_owned(),
                }],
            },
            None,
            TimestampMs::new(3),
        )
        .expect("interpreted")
        .resource_id
}

fn record_evidence(
    host: &Host,
    name: &str,
    revision: CapabilityRevision,
    state: kr_protocol::broker::InstanceCapabilityState,
) {
    host.service
        .broker()
        .record_capability(kr_protocol::broker::InstanceCapabilityRecord {
            capability_id: capability(name),
            capability_version: "1".to_owned(),
            application_instance_id: instance(),
            identity: kr_protocol::broker::InstanceCapabilityIdentity::default(),
            revision,
            state,
            source: kr_protocol::broker::InstanceEvidenceSource::HostProbe,
            invalidated_by: [kr_protocol::broker::InstanceInvalidation::BindingChanged]
                .into_iter()
                .collect(),
            disabled_reason: if state.is_usable() {
                Nullable::null()
            } else {
                Nullable::some("this installation cannot do it".to_owned())
            },
            observed_at: TimestampMs::new(1),
        })
        .expect("the evidence is recorded");
}

fn approval_mutation(
    client: &LocalClient,
    host: &Host,
    request_id: u64,
    resource_id: kr_protocol::ids::PendingResourceId,
) -> MutationRequest {
    MutationRequest {
        request_id: RequestId::new(request_id),
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
        action_window_id: client.action_window().action_window_id.clone(),
        requested_ttl_ms: DurationMs::new(60_000),
        params: ParamsValue::from_typed(&kr_protocol::agent::AgentApprovalRespondParams {
            target: AgentMutationTarget {
                subject: subject(host.session_id, instance()),
                binding_revision: AgentBindingRevision::new(1),
            },
            resource_id,
            option_id: "allow".to_owned(),
        })
        .expect("encodes"),
    }
}

/// KR-REQ-11.33 and KR-REQ-09: a resource the native path resolved first leaves the rich answer a
/// rejection with a receipt, not an outcome nobody can establish.
///
/// Here the resource is already resolved when the mutation is sent. The harder case, where it is
/// resolved *inside* the interval between the receipt acceptance and the admission, is the test
/// below this one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_11_33_a_natively_resolved_resource_leaves_the_rich_answer_a_rejection() {
    let host = host().await;
    let upstream = Arc::new(CountingUpstream::default());
    register(&host, None);
    let resource_id = offer_approval(&host, Arc::clone(&upstream));

    // The person answers in the terminal. That answer takes the resource's one transmission.
    host.service
        .broker()
        .native_answer_through(
            kr_protocol::ids::GatewayConnectionId::new(1),
            br#"{"id":11,"result":{"option_id":"allow"}}"#,
            TimestampMs::new(4),
            |_| Ok(()),
        )
        .expect("the native answer is carried");

    let mut client = cli(&host).await;
    let mutation = approval_mutation(&client, &host, 15, resource_id);
    let action_id = mutation.action_id;
    let outcome = send(&mut client, mutation).await;
    let Outcome::Error(error) = outcome else {
        panic!("a resolved resource takes no second answer: {outcome:?}");
    };
    assert_eq!(error.code, ErrorCode::QuestionResolved);
    assert_eq!(
        upstream.carried.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "the rich path wrote no frame"
    );
    let receipt = receipt(&mut client, action_id).await;
    assert_eq!(
        receipt.state,
        ReceiptState::Rejected,
        "a refusal this host can decide is a rejection, and it never reached the marker"
    );
}

/// KR-REQ-11.17 and KR-REQ-09: evidence withdrawn before the service admits is a rejection too.
///
/// The other door: the capability the answer needs is invalidated rather than the resource being
/// resolved. Again the interval version follows below.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_11_17_evidence_withdrawn_before_the_service_admits_is_a_rejection() {
    let host = host().await;
    let upstream = Arc::new(CountingUpstream::default());
    register(&host, None);
    let resource_id = offer_approval(&host, Arc::clone(&upstream));

    // The probe that said this installation can answer approvals is superseded by one that says
    // it cannot.
    record_evidence(
        &host,
        "agent.approval",
        CapabilityRevision::new(2),
        kr_protocol::broker::InstanceCapabilityState::TemporarilyUnavailable,
    );

    let mut client = cli(&host).await;
    let mutation = approval_mutation(&client, &host, 16, resource_id);
    let action_id = mutation.action_id;
    let outcome = send(&mut client, mutation).await;
    let Outcome::Error(error) = outcome else {
        panic!("an answer needs evidence that this installation can give it: {outcome:?}");
    };
    assert_eq!(error.code, ErrorCode::UnsupportedCapability);
    assert_eq!(
        upstream.carried.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "the rich path wrote no frame"
    );
    let receipt = receipt(&mut client, action_id).await;
    assert_eq!(receipt.state, ReceiptState::Rejected);
    assert_eq!(
        host.service
            .broker()
            .pending(resource_id)
            .expect("retained")
            .state,
        kr_protocol::gateway::PendingState::Pending,
        "and the resource is left answerable, with nothing reserved against it"
    );
}

/// Reads one receipt's durable state, and every state its event log holds, from a second reader.
///
/// The service's own answer is not evidence about what is on disk. This opens the journal file
/// beside it, which is how a test can say what a restart would read back.
fn durable(host: &Host, action_id: ActionId) -> (Option<String>, Vec<String>) {
    let connection = rusqlite::Connection::open(&host.journal_path).expect("the journal opens");
    let state = connection
        .query_row(
            "SELECT state FROM receipts WHERE action_id = ?1",
            rusqlite::params![action_id.get().as_bytes().as_slice()],
            |row| row.get::<_, String>(0),
        )
        .ok();
    let mut statement = connection
        .prepare("SELECT state FROM receipt_events WHERE action_id = ?1 ORDER BY revision")
        .expect("the event log is readable");
    let events = statement
        .query_map(
            rusqlite::params![action_id.get().as_bytes().as_slice()],
            |row| row.get::<_, String>(0),
        )
        .expect("the event log is readable")
        .map(|row| row.expect("a row"))
        .collect();
    (state, events)
}

/// KR-REQ-11.33, KR-REQ-11.17 and KR-REQ-09: what changes inside the interval between the durable
/// acceptance and the broker's admission is still a rejection, and still sends nothing.
///
/// This is the window the admission was moved across. The service used to finish its own checks
/// before the receipt marker and admit the mutation afterwards, so a native resolution or an
/// invalidation arriving in between produced a zero-send refusal recorded as an outcome nobody
/// could establish. The service pauses here with its receipt committed as `accepted` and no
/// dispatch marker written, the interference lands, and the refusal is a rejection.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_11_33_what_changes_inside_the_admission_interval_is_still_a_rejection() {
    for door in ["the native answer", "the evidence"] {
        let host = host().await;
        let upstream = Arc::new(CountingUpstream::default());
        register(&host, None);
        let resource_id = offer_approval(&host, Arc::clone(&upstream));
        let mut client = cli(&host).await;
        let mutation = approval_mutation(&client, &host, 17, resource_id);
        let action_id = mutation.action_id;

        let (arrived, release) = host.service.pause_before_admission();
        let sending = tokio::spawn(async move {
            let outcome = send(&mut client, mutation).await;
            (outcome, client)
        });
        // Bounded, because the service keeps the other end of this channel: a request that
        // answered without reaching the pause would leave an unbounded wait rather than a failure.
        tokio::task::spawn_blocking(move || {
            arrived
                .recv_timeout(std::time::Duration::from_secs(20))
                .expect("the service reached the pause before its admission")
        })
        .await
        .expect("the wait finishes");

        // The receipt is durably accepted and nothing has been marked for dispatch.
        let (state, events) = durable(&host, action_id);
        assert_eq!(state.as_deref(), Some("accepted"), "{door}");
        assert!(
            !events.iter().any(|event| event == "dispatching"),
            "{door}: no dispatch marker has been written"
        );

        let expected = if door == "the native answer" {
            host.service
                .broker()
                .native_answer_through(
                    kr_protocol::ids::GatewayConnectionId::new(1),
                    br#"{"id":11,"result":{"option_id":"allow"}}"#,
                    TimestampMs::new(5),
                    |_| Ok(()),
                )
                .expect("the native answer is carried");
            ErrorCode::QuestionResolved
        } else {
            record_evidence(
                &host,
                "agent.approval",
                CapabilityRevision::new(2),
                kr_protocol::broker::InstanceCapabilityState::TemporarilyUnavailable,
            );
            ErrorCode::UnsupportedCapability
        };
        release.send(()).expect("the service is let go");

        let (outcome, client) = sending.await.expect("the mutation is answered");
        let mut client = client;
        let Outcome::Error(error) = outcome else {
            panic!("{door}: this answer cannot go: {outcome:?}");
        };
        assert_eq!(error.code, expected, "{door}");
        assert_eq!(
            upstream.carried.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "{door}: the rich path wrote no frame"
        );
        let receipt = receipt(&mut client, action_id).await;
        assert_eq!(
            receipt.state,
            ReceiptState::Rejected,
            "{door}: a refusal decided before the marker is a rejection"
        );
        let (state, events) = durable(&host, action_id);
        assert_eq!(state.as_deref(), Some("rejected"), "{door}");
        assert!(
            !events.iter().any(|event| event == "dispatching"),
            "{door}: and no dispatch marker was ever written"
        );
    }
}

/// KR-REQ-09 and KR-REQ-11.27: an approval whose dispatch marker the receipt journal refused
/// leaves its reservation back where it was.
///
/// The marker is the receipt's, and the reservation is the broker's. They live in one journal
/// file, so the failure here is made specific rather than file-wide: a trigger on the receipt
/// table refuses exactly the `accepted → dispatching` update of an approval, and every broker
/// table stays writable. The service abandons the admission it took, which gives the resource's
/// one transmission back — and the proof of that is the answer that goes afterwards.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_11_27_an_approval_whose_marker_was_refused_leaves_the_resource_answerable() {
    let host = host().await;
    let upstream = Arc::new(CountingUpstream::default());
    register(&host, None);
    let resource_id = offer_approval(&host, Arc::clone(&upstream));

    // The receipt journal refuses this one transition, and nothing else.
    let journal = rusqlite::Connection::open(&host.journal_path).expect("the journal opens");
    journal
        .execute_batch(
            "CREATE TRIGGER refuse_approval_dispatch BEFORE UPDATE ON receipts
             WHEN OLD.state = 'accepted' AND NEW.state = 'dispatching'
                  AND OLD.method = 'agent.approval.respond'
             BEGIN SELECT RAISE(ABORT, 'this dispatch marker cannot be written'); END;",
        )
        .expect("the trigger is installed");

    let mut client = cli(&host).await;
    let mutation = approval_mutation(&client, &host, 18, resource_id);
    let action_id = mutation.action_id;
    let outcome = send(&mut client, mutation).await;
    let Outcome::Error(error) = outcome else {
        panic!("a marker that could not be written is not an applied answer: {outcome:?}");
    };
    assert_eq!(error.code, ErrorCode::StorageUnavailable);
    assert_eq!(
        upstream.carried.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "the admission was given up, so nothing carried the answer"
    );

    let (state, events) = durable(&host, action_id);
    assert_eq!(state.as_deref(), Some("accepted"));
    assert!(!events.iter().any(|event| event == "dispatching"));
    assert_eq!(
        host.service
            .broker()
            .pending(resource_id)
            .expect("retained")
            .state,
        kr_protocol::gateway::PendingState::Pending,
        "the reservation went back with the admission"
    );
    let dispatched: i64 = journal
        .query_row(
            "SELECT dispatched FROM broker_pending WHERE resource_id = ?1",
            rusqlite::params![resource_id.get().as_bytes().as_slice()],
            |row| row.get(0),
        )
        .expect("the broker's own row is readable and its tables are writable");
    assert_eq!(dispatched, 0, "and no broker dispatch marker was written");

    // Which the next answer proves: the resource is still answerable, and it settles once.
    host.service
        .broker()
        .native_answer_through(
            kr_protocol::ids::GatewayConnectionId::new(1),
            br#"{"id":11,"result":{"option_id":"allow"}}"#,
            TimestampMs::new(6),
            |_| Ok(()),
        )
        .expect("the resource was left answerable");
    assert_eq!(
        host.service
            .broker()
            .pending(resource_id)
            .expect("retained")
            .state,
        kr_protocol::gateway::PendingState::Resolved,
        "and answering it once is what ends it"
    );
}

/// A transport that takes the operation and does not say what came of it until it is let go.
///
/// This is what a real upstream looks like between the bytes leaving this host and the upstream
/// answering: the operation is with it, and nothing about its outcome is known.
#[derive(Debug)]
struct WaitingUpstream {
    release: std::sync::Mutex<Option<tokio::sync::oneshot::Receiver<()>>>,
    carried: std::sync::atomic::AtomicUsize,
}

impl UpstreamDispatch for WaitingUpstream {
    fn admit(&self, _request: &UpstreamRequest) -> Result<(), BrokerError> {
        Ok(())
    }

    fn submit(&self, request: &UpstreamRequest) -> Result<PendingTransmission, BrokerError> {
        self.carried
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let waiting = self
            .release
            .lock()
            .expect("the record is not poisoned")
            .take();
        let turn_id = request.turn_id.clone();
        Ok(PendingTransmission::carried(async move {
            if let Some(waiting) = waiting {
                let _ = waiting.await;
            }
            Ok(UpstreamOutcome {
                upstream_request_id: None,
                turn_id,
                provenance: kr_protocol::broker::ActionProvenance::UpstreamTypedRpc,
            })
        }))
    }
}

/// KR-REQ-12.11 and KR-REQ-11.32: one connection goes on serving its client while that client's
/// own mutation is still with the upstream.
///
/// Section 12 has the same socket carry this client's keystrokes, its interrupt and its keepalive.
/// The prompt is admitted, the marker is committed and the operation is with the upstream, which
/// has not answered. Everything else this connection asks for is answered while that is true, and
/// the prompt's own answer arrives when the upstream speaks.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_11_32_input_interrupt_and_keepalive_are_served_during_a_pending_mutation() {
    let host = host().await;
    let (release, waiting) = tokio::sync::oneshot::channel();
    let mut release = Some(release);
    let upstream = Arc::new(WaitingUpstream {
        release: std::sync::Mutex::new(Some(waiting)),
        carried: std::sync::atomic::AtomicUsize::new(0),
    });
    register(
        &host,
        Some(Arc::clone(&upstream) as Arc<dyn UpstreamDispatch>),
    );
    let mut client = cli(&host).await;
    // The connection's own keepalive runs on its own timer, started when the connection was
    // established. The prompt is sent part way through that interval, so the beat this test waits
    // for falls inside the window in which the prompt is outstanding rather than racing the
    // worker's own submission deadline.
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    let mutation = prompt_mutation(&client, &host, 21);
    let action_id = mutation.action_id;

    // The prompt goes, and nothing is read for it yet: it is with the upstream.
    client
        .writer()
        .write_message(&ControlFrame::Mutation(Box::new(mutation)))
        .await
        .expect("writes the prompt");
    // The transport has the operation before anything else is asked of this connection.
    for _ in 0..200 {
        if upstream.carried.load(std::sync::atomic::Ordering::SeqCst) == 1 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(
        upstream.carried.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the prompt reached the transport"
    );

    // The same connection asks for the lease, interrupts and reads its own receipt, and every one
    // of those is answered while the prompt is still outstanding.
    let lease = MutationRequest {
        request_id: RequestId::new(22),
        method: Method::InputAcquire.into(),
        method_version: MethodVersion::V1,
        action_id: ActionId::new(kr_ipc::new_uuid()),
        grant_id: Nullable::null(),
        target: ActionTarget {
            environment_id: host.environment_id,
            session_id: Nullable::some(host.session_id),
            session_epoch: Nullable::some(SessionEpoch::V1),
            application_instance_id: Nullable::null(),
            agent_binding_revision: Nullable::null(),
        },
        expected: ParamsValue::empty(),
        action_window_id: client.action_window().action_window_id.clone(),
        requested_ttl_ms: DurationMs::new(60_000),
        params: ParamsValue::from_typed(&kr_protocol::input::InputAcquireParams {
            session_id: host.session_id,
            attachment_id: kr_protocol::ids::AttachmentId::new(kr_ipc::new_uuid()),
            expected_epoch: Nullable::null(),
        })
        .expect("encodes"),
    };
    client
        .writer()
        .write_message(&ControlFrame::Mutation(Box::new(lease)))
        .await
        .expect("writes the lease request");

    // An interrupt on the same connection, which is the other thing section 12 has this socket
    // carry while a mutation is outstanding.
    let interrupt = MutationRequest {
        request_id: RequestId::new(23),
        method: Method::InputInterrupt.into(),
        method_version: MethodVersion::V1,
        action_id: ActionId::new(kr_ipc::new_uuid()),
        grant_id: Nullable::null(),
        target: ActionTarget {
            environment_id: host.environment_id,
            session_id: Nullable::some(host.session_id),
            session_epoch: Nullable::some(SessionEpoch::V1),
            application_instance_id: Nullable::null(),
            agent_binding_revision: Nullable::null(),
        },
        expected: ParamsValue::empty(),
        action_window_id: client.action_window().action_window_id.clone(),
        requested_ttl_ms: DurationMs::new(60_000),
        params: ParamsValue::from_typed(&kr_protocol::input::InputInterruptParams {
            session_id: host.session_id,
            attachment_id: kr_protocol::ids::AttachmentId::new(kr_ipc::new_uuid()),
            epoch: kr_protocol::ids::InputLeaseEpoch::new(1),
            action: kr_protocol::input::InterruptAction::NativeInterrupt,
        })
        .expect("encodes"),
    };
    client
        .writer()
        .write_message(&ControlFrame::Mutation(Box::new(interrupt)))
        .await
        .expect("writes the interrupt");

    // The answers come back in the order this connection can produce them, and the one for the
    // prompt is not among them until the upstream has spoken.
    let mut lease_answered = false;
    let mut interrupt_answered = false;
    let mut prompt_answered = false;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    while !lease_answered || !interrupt_answered {
        let frame = tokio::time::timeout_at(deadline, client.recv())
            .await
            .expect("this connection keeps answering")
            .expect("the worker answers");
        match frame {
            ControlFrame::Response(response) => {
                if response.request_id == RequestId::new(22) {
                    lease_answered = true;
                } else if response.request_id == RequestId::new(23) {
                    interrupt_answered = true;
                } else if response.request_id == RequestId::new(21) {
                    prompt_answered = true;
                }
            }
            ControlFrame::Notification(_) | ControlFrame::Event(_) => {}
            other => panic!("the worker answered {other:?}"),
        }
    }
    assert!(
        !prompt_answered,
        "the prompt is not answered before its upstream has said anything"
    );
    assert_eq!(
        receipt(&mut client, action_id).await.state,
        kr_protocol::receipt::ReceiptState::Dispatching,
        "and its receipt says the operation is with the upstream"
    );

    // The connection's own keepalive is read straight off the socket, because the ordinary client
    // absorbs one on its caller's behalf and this test is about the worker still sending it. The
    // upstream is let go once the beat has been seen, and the prompt's own response follows on the
    // same connection.
    let (mut reader, _writer, _acknowledgement) = client.into_halves();
    let mut beat = false;
    let answered = loop {
        let frame: ControlFrame = tokio::time::timeout_at(deadline, reader.read_message())
            .await
            .expect("this connection keeps answering")
            .expect("the worker answers");
        match frame {
            ControlFrame::Event(kr_protocol::envelope::ControlEvent::Keepalive) => {
                beat = true;
                release_once(&mut release);
            }
            ControlFrame::Response(response) if response.request_id == RequestId::new(21) => {
                break response.outcome;
            }
            _ => {}
        }
    };
    assert!(
        beat,
        "the connection's keepalive went out while the prompt was outstanding"
    );
    assert!(matches!(answered, Outcome::Ok(_)), "{answered:?}");
}

/// Lets the transport go once, from a loop that may come round again.
fn release_once(release: &mut Option<tokio::sync::oneshot::Sender<()>>) {
    if let Some(release) = release.take() {
        let _ = release.send(());
    }
}
