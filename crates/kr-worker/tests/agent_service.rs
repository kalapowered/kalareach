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
    BrokerError, BrokerTransport, Credential, ManagedProcess, TransportHandle, UpstreamDispatch,
    UpstreamOutcome, UpstreamRequest, subject,
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

    fn submit(&self, request: &UpstreamRequest) -> Result<UpstreamOutcome, BrokerError> {
        std::thread::sleep(self.holds);
        self.carried
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(UpstreamOutcome {
            upstream_request_id: None,
            turn_id: request.turn_id.clone(),
            provenance: kr_protocol::broker::ActionProvenance::UpstreamTypedRpc,
        })
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
