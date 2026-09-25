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
use kr_worker::runtime::SessionRuntime;
use kr_worker::service::{ServiceBinding, WorkerService};
use kr_worker::session::{Session, SessionConfig};

mod common;

use common::LIVENESS_DEADLINE;

struct Host {
    _temp: kr_ipc::testing::TempHost,
    service: Arc<WorkerService>,
    session_id: SessionId,
    endpoint: kr_ipc::paths::Endpoint,
    environment_id: kr_protocol::ids::EnvironmentId,
    journal_path: std::path::PathBuf,
    /// The control daemon's identity, to forward a paired device's request as the daemon does.
    controller: Arc<ControllerIdentity>,
    /// The boot the daemon proves its generation against.
    boot: kr_protocol::identity::BootIdentity,
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

/// A transport whose upstream answers the first prompt only once a second prompt has been
/// transmitted, and which records at each transmission whether the session boundary was free.
///
/// The first prompt's answer is what an upstream that is slow to answer looks like from here: the
/// bytes have gone and the answer has not come. It is a pending outcome rather than a call that
/// does not return, because that is what a transport hands back, and because a call that does not
/// return holds the runtime thread it was made on.
#[derive(Debug)]
struct RendezvousUpstream {
    /// The session whose boundary each transmission is checked against.
    runtime: Arc<SessionRuntime>,
    /// How long a wait for what the check expects is given before it counts as not having
    /// happened.
    patience: std::time::Duration,
    /// Whether this transport takes the session boundary itself as it transmits the first prompt,
    /// and keeps it until that prompt is answered. That is the negative control: from outside the
    /// worker, it is what a transmission made inside the boundary looks like.
    keeps_the_boundary: bool,
    /// How many prompts have been transmitted.
    carried: std::sync::atomic::AtomicUsize,
    /// Whether the session boundary could be taken while each transmission was being made, by the
    /// order in which the transmissions began.
    boundary_free: std::sync::Mutex<std::collections::BTreeMap<usize, bool>>,
    /// Told once the first prompt has been transmitted, and the negative control's boundary is
    /// held.
    first_transmitted: tokio::sync::Notify,
    /// Set once the second prompt has been transmitted.
    second_transmitted: Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
    /// Whether the second prompt was transmitted before the first prompt's answer was given, once
    /// that answer has been given.
    second_during_first: Arc<std::sync::Mutex<Option<bool>>>,
}

impl RendezvousUpstream {
    fn new(
        runtime: Arc<SessionRuntime>,
        patience: std::time::Duration,
        keeps_the_boundary: bool,
    ) -> Self {
        Self {
            runtime,
            patience,
            keeps_the_boundary,
            carried: std::sync::atomic::AtomicUsize::new(0),
            boundary_free: std::sync::Mutex::new(std::collections::BTreeMap::new()),
            first_transmitted: tokio::sync::Notify::new(),
            second_transmitted: Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new())),
            second_during_first: Arc::new(std::sync::Mutex::new(None)),
        }
    }

    /// Whether the session boundary can be taken while this transmission is being made.
    ///
    /// It is taken from another thread. The transport is called on the worker's own, so a boundary
    /// this transmission was inside would be held by the caller waiting here, and the other thread
    /// would wait for it until the patience ran out.
    fn boundary_is_free(&self) -> bool {
        let (taken, told) = std::sync::mpsc::channel();
        let runtime = Arc::clone(&self.runtime);
        std::thread::spawn(move || {
            drop(runtime.session());
            let _ = taken.send(());
        });
        told.recv_timeout(self.patience).is_ok()
    }

    /// Takes the session boundary on a thread of its own, and keeps it until the returned sender
    /// is dropped.
    ///
    /// `None` when the boundary could not be taken within the liveness bound. A worker that left
    /// the boundary before transmitting never gets here; a worker that transmits from inside it
    /// holds it, and this ends rather than waiting for it. The thread gives the boundary back as
    /// soon as it has it once nobody is waiting for it.
    fn keep_the_boundary(&self) -> Option<std::sync::mpsc::Sender<()>> {
        let (held, holding) = std::sync::mpsc::channel();
        let (release, released) = std::sync::mpsc::channel::<()>();
        let runtime = Arc::clone(&self.runtime);
        std::thread::spawn(move || {
            let session = runtime.session();
            if held.send(()).is_ok() {
                let _ = released.recv();
            }
            drop(session);
        });
        holding
            .recv_timeout(LIVENESS_DEADLINE)
            .ok()
            .map(|()| release)
    }

    /// What the two transmissions showed.
    fn seen(&self) -> (Vec<bool>, Option<bool>) {
        (
            self.boundary_free
                .lock()
                .expect("the record is not poisoned")
                .values()
                .copied()
                .collect(),
            *self
                .second_during_first
                .lock()
                .expect("the record is not poisoned"),
        )
    }
}

impl UpstreamDispatch for RendezvousUpstream {
    fn admit(&self, _request: &UpstreamRequest) -> Result<(), BrokerError> {
        Ok(())
    }

    fn submit(&self, request: &UpstreamRequest) -> Result<PendingTransmission, BrokerError> {
        let index = self
            .carried
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let first = index == 0;
        let kept = (first && self.keeps_the_boundary)
            .then(|| self.keep_the_boundary())
            .flatten();
        if first {
            // The first prompt has been handed over, so the second may go.
            self.first_transmitted.notify_one();
        }
        let free = self.boundary_is_free();
        self.boundary_free
            .lock()
            .expect("the record is not poisoned")
            .insert(index, free);
        let outcome = UpstreamOutcome {
            upstream_request_id: None,
            turn_id: request.turn_id.clone(),
            provenance: kr_protocol::broker::ActionProvenance::UpstreamTypedRpc,
        };
        if !first {
            let (transmitted, changed) = &*self.second_transmitted;
            *transmitted.lock().expect("the flag is not poisoned") = true;
            changed.notify_all();
            return Ok(PendingTransmission::settled(Ok(outcome)));
        }
        let second = Arc::clone(&self.second_transmitted);
        let during = Arc::clone(&self.second_during_first);
        let patience = self.patience;
        Ok(PendingTransmission::carried(async move {
            // Waited for on the runtime's blocking pool, so no worker thread is held while this
            // upstream has not answered.
            let met = tokio::task::spawn_blocking(move || {
                let (transmitted, changed) = &*second;
                let flag = transmitted.lock().expect("the flag is not poisoned");
                let (flag, _) = changed
                    .wait_timeout_while(flag, patience, |transmitted| !*transmitted)
                    .expect("the flag is not poisoned");
                *flag
            })
            .await
            .unwrap_or(false);
            *during.lock().expect("the record is not poisoned") = Some(met);
            drop(kept);
            Ok(outcome)
        }))
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
        shell: kr_worker::testing::posix_script("sleep 30"),
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
    Host {
        _temp: temp,
        service,
        session_id,
        endpoint,
        environment_id,
        journal_path: journal_path_for_tests,
        controller,
        boot,
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

/// What two prompts sent through the worker to a [`RendezvousUpstream`] came to.
#[derive(Debug)]
struct TwoPrompts {
    /// Whether the session boundary could be taken while each transmission was being made, in the
    /// order the transmissions began.
    boundary_free: Vec<bool>,
    /// Whether the second prompt was transmitted while the first was with its upstream, once the
    /// first prompt's answer was given.
    second_during_first: Option<bool>,
    /// What each prompt was answered with, the first prompt's first.
    answers: [Outcome; 2],
    /// How many prompts reached the upstream.
    carried: usize,
}

impl TwoPrompts {
    fn both_applied(&self) -> bool {
        self.answers
            .iter()
            .all(|answer| matches!(answer, Outcome::Ok(_)))
    }
}

/// Sends two prompts through the worker to a [`RendezvousUpstream`], the second once the first has
/// been transmitted, and returns what came of them.
///
/// Its own waits are three liveness bounds, so they outlast every wait of the transport's own: at
/// most two waits of `patience` in the check, or the negative control's bounded wait for the
/// boundary and two short ones. A worker that holds the boundary across a transmission is then
/// reported by the check rather than by one of these waits running out.
async fn two_prompts(patience: std::time::Duration, keeps_the_boundary: bool) -> TwoPrompts {
    let outlasting = LIVENESS_DEADLINE * 3;
    let host = host().await;
    let upstream = Arc::new(RendezvousUpstream::new(
        Arc::clone(host.service.runtime()),
        patience,
        keeps_the_boundary,
    ));
    register(
        &host,
        Some(Arc::clone(&upstream) as Arc<dyn UpstreamDispatch>),
    );

    // Both clients are connected first, so what they wait for is each other and not a handshake.
    let mut first = cli(&host).await;
    let mut second = cli(&host).await;
    let one = prompt_mutation(&first, &host, 12);
    let two = prompt_mutation(&second, &host, 13);

    let answered_first =
        tokio::spawn(async move { tokio::time::timeout(outlasting, send(&mut first, one)).await });
    // The second prompt goes once the first has been transmitted, so it arrives while the first
    // is with its upstream rather than before it got there.
    tokio::time::timeout(outlasting, upstream.first_transmitted.notified())
        .await
        .expect("the first prompt was transmitted");
    let answered_second = tokio::time::timeout(outlasting, send(&mut second, two))
        .await
        .expect("the second prompt was answered");
    let answered_first = answered_first
        .await
        .expect("the first prompt's task finishes")
        .expect("the first prompt was answered");
    let (boundary_free, second_during_first) = upstream.seen();
    TwoPrompts {
        boundary_free,
        second_during_first,
        answers: [answered_first, answered_second],
        carried: upstream.carried.load(std::sync::atomic::Ordering::SeqCst),
    }
}

/// KR-REQ-12.04 and KR-REQ-12.06: an admitted operation leaves the session boundary before its
/// bytes go, so two of them overlap instead of queueing behind one another.
///
/// What is checked is an order, not a duration. At each transmission the transport takes the
/// session boundary from another thread, which it can do only if the worker left the boundary
/// before it transmitted: terminal ingestion needs the same mutex, so a slow upstream would
/// otherwise stop a person typing. And the first prompt's upstream answers only once a second
/// prompt has been transmitted. That second prompt is sent after the first has gone, and it can be
/// admitted and transmitted while the first is still with its upstream only if neither the
/// session boundary nor the dispatch barrier is held for the length of a transmission. The waits
/// are liveness bounds; a host of any speed passes or fails this the same way.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_12_04_an_admitted_operation_leaves_the_session_boundary_before_it_transmits() {
    let seen = two_prompts(LIVENESS_DEADLINE, false).await;
    assert_eq!(
        seen.boundary_free,
        [true, true],
        "the session boundary was free while each prompt was being transmitted: {seen:?}"
    );
    assert_eq!(
        seen.second_during_first,
        Some(true),
        "the second prompt was admitted and transmitted while the first was with its upstream: \
         {seen:?}"
    );
    assert!(seen.both_applied(), "both prompts were applied: {seen:?}");
    assert_eq!(seen.carried, 2, "both prompts reached the upstream");
}

/// The check above against a transport that takes the session boundary as it transmits the first
/// prompt, and keeps it until that prompt is answered: what a transmission made inside the
/// boundary looks like from outside the worker. Both halves of the check see it. The boundary
/// could not be taken during that transmission, and the second prompt could not be admitted until
/// the first had been answered.
///
/// Neither result depends on the wait it comes from. The boundary is kept until the first prompt
/// is answered, and that answer is given only after both waits have ended, so nothing either wait
/// looks for can happen however long it lasts. That is why a second is enough here.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_transmission_that_keeps_the_session_boundary_fails_the_same_check() {
    let seen = two_prompts(std::time::Duration::from_secs(1), true).await;
    assert_eq!(
        seen.boundary_free.first(),
        Some(&false),
        "the boundary could not be taken during the first transmission: {seen:?}"
    );
    assert_eq!(
        seen.second_during_first,
        Some(false),
        "the second prompt was not transmitted while the first was with its upstream: {seen:?}"
    );
    assert!(
        seen.both_applied(),
        "both prompts were applied once the boundary was given back: {seen:?}"
    );
    assert_eq!(seen.carried, 2, "both prompts reached the upstream");
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

/// Section 9 and KR-REQ-12.06: a dispatch marker this host could not write leaves nothing
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

/// The installed package this suite's tables are pinned with and its bindings run.
fn installed() -> kr_worker::broker::PackageIdentity {
    kr_worker::broker::PackageIdentity {
        plugin_id: PluginId::new("kalareach.codex").expect("valid"),
        publisher_id: PublisherId::new("kalareach").expect("valid"),
        package_digest: Digest256::from_bytes([5; 32]),
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
fn offer_approval<U: UpstreamDispatch + 'static>(
    host: &Host,
    upstream: Arc<U>,
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
            installed(),
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

/// KR-REQ-11.33 and section 9: a resource the native path resolved first leaves the rich answer a
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

/// KR-REQ-11.17 and section 9: evidence withdrawn before the service admits is a rejection too.
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

/// KR-REQ-11.33, KR-REQ-11.17 and section 9: what changes inside the interval between the durable
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
                .recv_timeout(LIVENESS_DEADLINE)
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

/// Section 9 and KR-REQ-11.27: an approval whose dispatch marker the receipt journal refused
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
    // A real terminal attachment on this connection, taken before anything is outstanding. Its
    // identifier is what the lease, the keystrokes and the interrupt all name.
    let attached: kr_protocol::attachment::SessionAttachResult = client
        .mutate(
            Method::SessionAttach,
            ActionId::new(kr_ipc::new_uuid()),
            action_target(&host),
            &terminal_attachment(host.session_id),
        )
        .await
        .expect("reaches the worker")
        .expect("the terminal attaches")
        .to_typed()
        .expect("decodes");
    let attachment_id = attached.attachment.attachment_id;

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
    let deadline = tokio::time::Instant::now() + LIVENESS_DEADLINE;
    while tokio::time::Instant::now() < deadline {
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

    // The same connection takes the input lease, types, interrupts and reads its own receipt, and
    // every one of those succeeds while the prompt is still outstanding.
    let lease = MutationRequest {
        request_id: RequestId::new(22),
        method: Method::InputAcquire.into(),
        method_version: MethodVersion::V1,
        action_id: ActionId::new(kr_ipc::new_uuid()),
        grant_id: Nullable::null(),
        target: action_target(&host),
        expected: ParamsValue::empty(),
        action_window_id: client.action_window().action_window_id.clone(),
        requested_ttl_ms: DurationMs::new(60_000),
        params: ParamsValue::from_typed(&kr_protocol::input::InputAcquireParams {
            session_id: host.session_id,
            attachment_id,
            expected_epoch: Nullable::null(),
        })
        .expect("encodes"),
    };
    client
        .writer()
        .write_message(&ControlFrame::Mutation(Box::new(lease)))
        .await
        .expect("writes the lease request");

    let deadline = tokio::time::Instant::now() + LIVENESS_DEADLINE;
    let leased: kr_protocol::input::InputAcquireResult =
        answer_to(&mut client, RequestId::new(22), deadline)
            .await
            .expect("the lease is granted while the prompt is outstanding")
            .to_typed()
            .expect("decodes");
    let epoch = leased.lease.epoch;

    // Keystrokes, under the lease this connection holds.
    client
        .writer()
        .write_message(&ControlFrame::Request(Request {
            request_id: RequestId::new(24),
            method: Method::InputWrite.into(),
            method_version: MethodVersion::V1,
            params: ParamsValue::from_typed(&kr_protocol::input::InputWriteParams {
                session_id: host.session_id,
                attachment_id,
                epoch,
                sequence: kr_protocol::ids::InputSequence::new(0),
                bytes: kr_protocol::scalars::Bytes::new(b"hello".to_vec()),
            })
            .expect("encodes"),
        }))
        .await
        .expect("writes the input");
    let written: kr_protocol::input::InputWriteResult =
        answer_to(&mut client, RequestId::new(24), deadline)
            .await
            .expect("the keystrokes are accepted while the prompt is outstanding")
            .to_typed()
            .expect("decodes");
    assert_eq!(
        written.forwarded_bytes.get(),
        5,
        "every byte the person typed reached the terminal"
    );

    // An interrupt on the same connection, which is the other thing section 12 has this socket
    // carry while a mutation is outstanding.
    let interrupt = MutationRequest {
        request_id: RequestId::new(23),
        method: Method::InputInterrupt.into(),
        method_version: MethodVersion::V1,
        action_id: ActionId::new(kr_ipc::new_uuid()),
        grant_id: Nullable::null(),
        target: action_target(&host),
        expected: ParamsValue::empty(),
        action_window_id: client.action_window().action_window_id.clone(),
        requested_ttl_ms: DurationMs::new(60_000),
        params: ParamsValue::from_typed(&kr_protocol::input::InputInterruptParams {
            session_id: host.session_id,
            attachment_id,
            epoch,
            action: kr_protocol::input::InterruptAction::NativeInterrupt,
        })
        .expect("encodes"),
    };
    client
        .writer()
        .write_message(&ControlFrame::Mutation(Box::new(interrupt)))
        .await
        .expect("writes the interrupt");
    let interrupted: kr_protocol::input::InputLeaseResult =
        answer_to(&mut client, RequestId::new(23), deadline)
            .await
            .expect("the interrupt is carried out while the prompt is outstanding")
            .to_typed()
            .expect("decodes");
    assert_eq!(
        interrupted.lease.epoch, epoch,
        "the interrupt ran under the lease this connection holds"
    );

    assert_eq!(
        receipt(&mut client, action_id).await.state,
        kr_protocol::receipt::ReceiptState::Dispatching,
        "and the prompt's receipt still says the operation is with the upstream"
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

    // And the operation the upstream acknowledged is applied, which is what the receipt the caller
    // reads has to say once its own answer has arrived.
    let mut client = cli(&host).await;
    assert_eq!(
        receipt(&mut client, action_id).await.state,
        kr_protocol::receipt::ReceiptState::Applied,
        "the upstream acknowledged it, so the receipt says so"
    );
}

/// The target every mutation of this connection acts on.
fn action_target(host: &Host) -> ActionTarget {
    ActionTarget {
        environment_id: host.environment_id,
        session_id: Nullable::some(host.session_id),
        session_epoch: Nullable::some(SessionEpoch::V1),
        application_instance_id: Nullable::null(),
        agent_binding_revision: Nullable::null(),
    }
}

/// A terminal attachment that asks to observe and to type.
fn terminal_attachment(session_id: SessionId) -> kr_protocol::attachment::SessionAttachParams {
    let mut requested = kr_protocol::scalars::CanonicalSet::new();
    requested.insert(kr_protocol::attachment::AttachmentCapability::ObserveTerminal);
    requested.insert(kr_protocol::attachment::AttachmentCapability::Input);
    kr_protocol::attachment::SessionAttachParams {
        session_id,
        mode: kr_protocol::attachment::AttachMode::Terminal,
        claim_geometry: false,
        dimensions: Nullable::some(Dimensions::new(80, 24)),
        // Declared, because the worker has to know what this terminal's keys mean before it will
        // carry a person's keystrokes to the application.
        terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
        requested,
    }
}

/// Reads this connection's answer to one request, ignoring everything else it carries.
async fn answer_to(
    client: &mut LocalClient,
    request_id: RequestId,
    deadline: tokio::time::Instant,
) -> Result<ParamsValue, kr_protocol::error::ProtocolError> {
    loop {
        let frame = tokio::time::timeout_at(deadline, client.recv())
            .await
            .expect("this connection keeps answering")
            .expect("the worker answers");
        match frame {
            ControlFrame::Response(response) if response.request_id == request_id => {
                return match response.outcome {
                    Outcome::Ok(value) => Ok(value),
                    Outcome::Error(failure) => Err(failure),
                };
            }
            ControlFrame::Response(_)
            | ControlFrame::Notification(_)
            | ControlFrame::Event(_)
            | ControlFrame::Receipt(_) => {}
            other => panic!("the worker answered {other:?}"),
        }
    }
}

/// Lets the transport go once, from a loop that may come round again.
fn release_once(release: &mut Option<tokio::sync::oneshot::Sender<()>>) {
    if let Some(release) = release.take() {
        let _ = release.send(());
    }
}

/// The connector table this host pins for the real transport below.
fn upstream_table() -> kr_protocol::gateway::DeclarativeTable {
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

/// The closed rich table that names the method a prompt goes out as.
fn upstream_rich() -> kr_protocol::gateway::RichMethodTable {
    kr_protocol::gateway::RichMethodTable {
        table_version: kr_protocol::ids::MethodTableVersion::new(1),
        upstream_protocol_version: "1".to_owned(),
        entries: vec![kr_protocol::gateway::RichMethodEntry {
            method: kr_protocol::ids::UpstreamMethod::new("session/prompt").expect("valid"),
            class: kr_protocol::gateway::NativeMethodClass::Mutation,
            required_right: kr_protocol::rights::ActionRight::AgentPrompt,
            operation: Nullable::some(kr_protocol::gateway::RichOperation::PromptSubmit),
            provenance: kr_protocol::broker::ActionProvenance::UpstreamTypedRpc,
        }],
    }
}

/// One end of a connected pair of local sockets: a Unix socket pair where the platform has one,
/// and otherwise a loopback connection, which is what this host's own endpoint is there.
#[cfg(unix)]
type SocketStream = tokio::net::UnixStream;
#[cfg(not(unix))]
type SocketStream = tokio::net::TcpStream;

/// Makes one connected pair of local sockets.
#[cfg(unix)]
fn socket_pair() -> (SocketStream, SocketStream) {
    tokio::net::UnixStream::pair().expect("a socket pair is made")
}

/// Makes one connected pair of local sockets, over loopback.
#[cfg(not(unix))]
fn socket_pair() -> (SocketStream, SocketStream) {
    let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .expect("a loopback listener binds");
    let here = std::net::TcpStream::connect(listener.local_addr().expect("it has an address"))
        .expect("the loopback connection is made");
    let (there, _) = listener
        .accept()
        .expect("the loopback connection is accepted");
    let ready = |stream: std::net::TcpStream| {
        stream
            .set_nodelay(true)
            .expect("the connection sends at once");
        stream
            .set_nonblocking(true)
            .expect("the connection is made non-blocking");
        tokio::net::TcpStream::from_std(stream).expect("the runtime takes the connection")
    };
    (ready(here), ready(there))
}

/// Section 9 and KR-REQ-11.33: a request that went in full and was never answered leaves a receipt
/// nobody can read as applied.
///
/// The transport here is the real one, over a real socket pair. The upstream reads the whole frame
/// and says nothing, which is the case a queue-shaped transport cannot tell from success: the
/// bytes went, so nothing failed, and the upstream never acted, so nothing succeeded. What the
/// caller is told and what the receipt says is that nobody can establish it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_09_a_request_that_went_and_was_never_answered_leaves_an_unknown_receipt() {
    let host = host().await;
    register(&host, None);
    let broker = host.service.broker();
    broker
        .pin_table(instance(), installed(), upstream_table(), upstream_rich())
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
    let (upstream_here, upstream_there) = socket_pair();
    let (client_here, _client_there) = socket_pair();
    let (owner, writes) = kr_worker::broker::Duplex::new(
        Arc::clone(broker),
        kr_protocol::ids::GatewayConnectionId::new(1),
        kr_worker::broker::Framing::new(kr_protocol::gateway::NativeFraming::JsonLines),
        upstream_here,
        tokio::io::split(client_here).1,
        kr_protocol::ids::EnvironmentId::new(Uuid::from_bytes([4; 16])),
        "agent-user",
    );
    let driving = tokio::spawn(writes);
    broker
        .bind_dispatch(instance(), owner.dispatch().expect("it carries operations"))
        .expect("the transport is bound");

    // An upstream that reads everything and answers nothing.
    let read = Arc::new(std::sync::Mutex::new(String::new()));
    let reading = {
        let read = Arc::clone(&read);
        tokio::spawn(async move {
            let (reader, _writer) = tokio::io::split(upstream_there);
            let mut reader = tokio::io::BufReader::new(reader);
            loop {
                let mut line = String::new();
                match tokio::io::AsyncBufReadExt::read_line(&mut reader, &mut line).await {
                    Ok(0) | Err(_) => return,
                    Ok(_) => read
                        .lock()
                        .expect("the record is not poisoned")
                        .push_str(&line),
                }
            }
        })
    };

    let mut client = cli(&host).await;
    let mutation = prompt_mutation(&client, &host, 31);
    let action_id = mutation.action_id;
    let outcome = tokio::time::timeout(LIVENESS_DEADLINE, send(&mut client, mutation))
        .await
        .expect("the worker answers within its own deadline");
    let Outcome::Error(failure) = outcome else {
        panic!("an operation nobody acknowledged is not a success: {outcome:?}");
    };
    assert_eq!(
        failure.code,
        ErrorCode::UpstreamUnavailable,
        "the transport says the upstream did not answer"
    );
    assert!(
        read.lock()
            .expect("the record is not poisoned")
            .contains("session/prompt"),
        "and the whole frame did reach the upstream: {}",
        read.lock().expect("the record is not poisoned")
    );
    assert_eq!(
        receipt(&mut client, action_id).await.state,
        ReceiptState::Unknown,
        "a frame that went and was never acknowledged is never applied and never refused"
    );
    let carried = read
        .lock()
        .expect("the record is not poisoned")
        .matches("session/prompt")
        .count();
    assert_eq!(carried, 1, "the operation went exactly once");

    // The same action again. Its receipt is the one this host already wrote, and nothing about it
    // reaches the upstream a second time: an outcome nobody can establish is never retried.
    let mut repeat = prompt_mutation(&client, &host, 32);
    repeat.action_id = action_id;
    let repeated = tokio::time::timeout(LIVENESS_DEADLINE, send(&mut client, repeat))
        .await
        .expect("the worker answers");
    // The worker answers with the receipt it already wrote rather than carrying the action out
    // again, which is what makes repeating one safe.
    let Outcome::Ok(value) = repeated else {
        panic!("the recorded receipt is what a repeat is answered with: {repeated:?}");
    };
    let replayed = format!("{:?}", value.as_value());
    assert!(
        replayed.contains("unknown"),
        "the receipt this host already wrote is what a repeat is answered with: {replayed}"
    );
    assert_eq!(
        read.lock()
            .expect("the record is not poisoned")
            .matches("session/prompt")
            .count(),
        carried,
        "and nothing of it went a second time"
    );
    assert_eq!(
        receipt(&mut client, action_id).await.state,
        ReceiptState::Unknown,
        "its receipt still says what it said"
    );

    reading.abort();
    driving.abort();
}

/// KR-REQ-11.35 and KR-REQ-11.37: the receipt journal and the broker's ledger are behind one
/// fence, and the host's own maintenance takes both out of it.
///
/// A fault of either store is the session's one journal condition. The receipt journal refusing an
/// acceptance fences the broker at its next decision, and the broker's ledger refusing a write
/// fences the receipt path: a prompt is refused before its marker either way. When the store takes
/// writes again, the maintenance pass writes the journal's gap first and then the broker's, and a
/// prompt is applied again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_11_37_one_fence_covers_the_receipt_journal_and_the_ledger_and_maintenance_lifts_it()
{
    let host = host().await;
    let upstream = Arc::new(CountingUpstream::default());
    register(
        &host,
        Some(Arc::clone(&upstream) as Arc<dyn UpstreamDispatch>),
    );
    let broker = Arc::clone(host.service.broker());
    let mut client = cli(&host).await;
    let mutation = prompt_mutation(&client, &host, 31);
    let applied = send(&mut client, mutation).await;
    assert!(matches!(applied, Outcome::Ok(_)), "{applied:?}");

    // The receipt journal refuses an acceptance: the store is full.
    let mut next = 0_u16;
    {
        let mut session = host.service.runtime().session();
        let journal = session.journal_mut().expect("the session journals");
        common::refuse_acceptance(journal, &mut next);
    }
    assert_eq!(
        broker.mode(),
        kr_protocol::gateway::GatewayMode::NativeOnlyVolatile,
        "the broker reads the journal's own condition, so it is behind the fence at once"
    );
    let mutation = prompt_mutation(&client, &host, 32);
    let refused = send(&mut client, mutation).await;
    let Outcome::Error(error) = refused else {
        panic!("a prompt is refused while the store is faulted: {refused:?}");
    };
    assert_eq!(error.code, ErrorCode::StorageUnavailable);

    // The store takes writes again. Maintenance writes the journal's gap, then the broker's, and
    // with no upstream owing a reconciliation rich work is back.
    {
        let mut session = host.service.runtime().session();
        session
            .journal_mut()
            .expect("the session journals")
            .release_size_cap()
            .expect("the store may grow again");
    }
    host.service.recover_storage_now();
    assert_eq!(broker.mode(), kr_protocol::gateway::GatewayMode::Normal);
    let mutation = prompt_mutation(&client, &host, 33);
    let applied = send(&mut client, mutation).await;
    assert!(matches!(applied, Outcome::Ok(_)), "{applied:?}");

    // Now the ledger refuses a write. That failure is the same condition, so the receipt path is
    // fenced by it before any prompt reaches the broker.
    broker
        .refuse_ledger_writes(true)
        .expect("the ledger's store is put in query-only mode");
    let failed = broker
        .checkpoint(
            instance(),
            kr_protocol::ids::StreamCursor::new(1),
            TimestampMs::new(40),
        )
        .expect_err("the ledger's store refuses the write");
    assert_eq!(failed.code(), ErrorCode::StorageUnavailable);
    let mutation = prompt_mutation(&client, &host, 34);
    let refused = send(&mut client, mutation).await;
    let Outcome::Error(error) = refused else {
        panic!("a prompt is refused while the ledger is faulted: {refused:?}");
    };
    assert_eq!(error.code, ErrorCode::StorageUnavailable);
    assert_eq!(
        broker.mode(),
        kr_protocol::gateway::GatewayMode::NativeOnlyVolatile
    );

    broker
        .refuse_ledger_writes(false)
        .expect("the ledger takes writes again");
    host.service.recover_storage_now();
    assert_eq!(broker.mode(), kr_protocol::gateway::GatewayMode::Normal);
    let mutation = prompt_mutation(&client, &host, 35);
    let applied = send(&mut client, mutation).await;
    assert!(matches!(applied, Outcome::Ok(_)), "{applied:?}");
    assert_eq!(
        upstream.carried.load(std::sync::atomic::Ordering::SeqCst),
        3,
        "only the prompts admitted outside the fence reached the upstream"
    );
}

/// KR-REQ-11.37: a receipt fault the broker never saw is still the broker's gap, and the host's
/// own maintenance recovers it.
///
/// Nothing asks the broker anything between the journal faulting and its store taking writes
/// again, so by the time maintenance runs the condition is healthy. Maintenance writes the
/// journal's gap first, and then the broker applies the fault it missed, enters the fence, writes
/// its own gap and, with nothing owed, returns to normal operation.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_11_37_a_receipt_fault_the_broker_never_saw_is_still_its_gap() {
    let host = host().await;
    register(&host, None);
    let broker = Arc::clone(host.service.broker());
    let before = broker.recovery_generation();
    assert!(broker.recorded_gaps().expect("the ledger reads").is_empty());

    {
        let mut session = host.service.runtime().session();
        let journal = session.journal_mut().expect("the session journals");
        common::refuse_acceptance(journal, &mut 0);
        journal
            .release_size_cap()
            .expect("the store may grow again");
    }
    host.service.recover_storage_now();

    assert!(
        broker.recovery_generation() > before,
        "the broker went behind the fence it missed"
    );
    assert_eq!(
        broker.recorded_gaps().expect("the ledger reads").len(),
        1,
        "and wrote its own gap down"
    );
    assert_eq!(
        broker.mode(),
        kr_protocol::gateway::GatewayMode::Normal,
        "with nothing owed, rich work is back"
    );
}

/// Registers the plugin action the resource tests below call, on the approval tests' binding: a
/// component's `upstream.prompt` that names the pending resource it acts on.
fn register_answer_action(host: &Host) {
    let declared: kr_plugin_sdk::effect::ActionDeclaration =
        serde_json::from_value(serde_json::json!({
            "id": "approval.answer",
            "label": "Answer",
            "effect": "upstream.prompt",
            "implementation": { "type": "component" },
            "parameters": { "parameters": [] },
            "description": "A prompt its component prepares",
            "confirmation_required": false,
        }))
        .expect("a declaration the manifest format reads");
    host.service
        .broker()
        .register_actions(binding(), &[declared])
        .expect("the action is registered");
}

/// Offers one request on a second instance, so a pending resource exists that the first instance
/// cannot answer.
fn offer_elsewhere(host: &Host) -> kr_protocol::ids::PendingResourceId {
    let broker = host.service.broker();
    let elsewhere = ApplicationInstanceId::new(Uuid::from_bytes([3; 16]));
    let process = ProcessStartIdentity::new(42, ProcessStartSource::MacosProcBsdInfo, 901);
    broker
        .register_instance(
            elsewhere,
            IntegrationMode::Gateway,
            None,
            Some(ManagedProcess::new(
                elsewhere,
                process.clone(),
                TransportHandle {
                    transport: BrokerTransport::PrivateSocket,
                    application_instance_id: elsewhere,
                    executable_digest: Digest256::from_bytes([3; 32]),
                    process: process.clone(),
                },
                Credential::from_bytes([8; 32]),
                true,
                TimestampMs::new(1),
            )),
        )
        .expect("the second instance is registered");
    broker
        .pin_table(
            elsewhere,
            installed(),
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
        .expect("the second instance's tables are pinned");
    let connection = broker
        .open_native_connection(
            elsewhere,
            &[8; 32],
            &process,
            &PluginId::new("kalareach.codex").expect("valid"),
            "1",
        )
        .expect("the second native connection is authenticated");
    broker
        .forward_native(
            connection,
            br#"{"id":21,"method":"session/request_permission"}"#,
            TimestampMs::new(2),
        )
        .expect("forwarded")
        .1
        .expect("it expects a response")
        .resource_id
}

/// Sends one `plugin.action.invoke` naming a pending resource, or none, and returns the refusal
/// code and the state of the receipt it left.
async fn plugin_answer(
    client: &mut LocalClient,
    host: &Host,
    request_id: u64,
    resource_id: Nullable<kr_protocol::ids::PendingResourceId>,
) -> (ErrorCode, ReceiptState) {
    let mutation = MutationRequest {
        request_id: RequestId::new(request_id),
        method: Method::PluginActionInvoke.into(),
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
        params: ParamsValue::from_typed(&kr_protocol::agent::PluginActionInvokeParams {
            target: AgentMutationTarget {
                subject: subject(host.session_id, instance()),
                binding_revision: AgentBindingRevision::new(1),
            },
            plugin_id: PluginId::new("kalareach.codex").expect("valid"),
            action: kr_protocol::broker::ActionName::new("approval.answer").expect("valid"),
            draft_id: Nullable::null(),
            resource_id,
            parameters: kr_protocol::scalars::Bytes::from(br#"{"decision":"allow"}"#.to_vec()),
        })
        .expect("encodes"),
    };
    let action_id = mutation.action_id;
    let outcome = send(client, mutation).await;
    let Outcome::Error(error) = outcome else {
        panic!("this host transmits no plugin action: {outcome:?}");
    };
    (error.code, receipt(client, action_id).await.state)
}

/// KR-REQ-12.18 and section 9: a plugin action that names a pending resource is checked against
/// that resource before its dispatch marker. An unknown resource, one that belongs to another
/// instance and one already answered are each refused for that reason, with a receipt that says
/// so. Naming none, or one this instance can still answer, passes the check and meets the refusal
/// every plugin action meets here, and the resource is left exactly as it was.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_12_18_a_plugin_answer_is_refused_for_the_resource_it_names() {
    let host = host().await;
    let upstream = Arc::new(CountingUpstream::default());
    register(
        &host,
        Some(Arc::clone(&upstream) as Arc<dyn UpstreamDispatch>),
    );
    let live = offer_approval(&host, Arc::clone(&upstream));
    register_answer_action(&host);
    let foreign = offer_elsewhere(&host);
    let unknown = kr_protocol::ids::PendingResourceId::new(Uuid::from_bytes([0x5a; 16]));
    let mut client = cli(&host).await;

    // The controls: the resource check passes, and the refusal is the one every plugin action
    // meets here. Nothing about the live resource changed.
    assert_eq!(
        plugin_answer(&mut client, &host, 40, Nullable::null()).await,
        (ErrorCode::UnsupportedCapability, ReceiptState::Rejected)
    );
    assert_eq!(
        plugin_answer(&mut client, &host, 41, Nullable::some(live)).await,
        (ErrorCode::UnsupportedCapability, ReceiptState::Rejected)
    );
    assert_eq!(
        host.service
            .broker()
            .pending(live)
            .expect("the resource is still held")
            .state,
        kr_protocol::gateway::PendingState::Pending,
        "a checked resource is not claimed"
    );

    // Each refusal names the resource's own reason.
    assert_eq!(
        plugin_answer(&mut client, &host, 42, Nullable::some(unknown)).await,
        (ErrorCode::StaleSession, ReceiptState::Rejected)
    );
    assert_eq!(
        plugin_answer(&mut client, &host, 43, Nullable::some(foreign)).await,
        (ErrorCode::PermissionDenied, ReceiptState::Rejected)
    );
    host.service
        .broker()
        .native_answer_through(
            kr_protocol::ids::GatewayConnectionId::new(1),
            br#"{"id":11,"result":{"option_id":"allow"}}"#,
            TimestampMs::new(4),
            |_| Ok(()),
        )
        .expect("the native answer is carried");
    assert_eq!(
        plugin_answer(&mut client, &host, 44, Nullable::some(live)).await,
        (ErrorCode::QuestionResolved, ReceiptState::Rejected)
    );

    assert_eq!(
        upstream.carried.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "nothing was carried to the upstream"
    );
}

/// A Claude Code channel served for this suite's instance on the host's own broker: the instance
/// launched, the connector read from a package laid out as the store extracts it, the package
/// bound and its actions registered as the installation's binder will, and the channel server's
/// end of the connection to drive.
struct ServedChannel {
    lines: tokio::io::Lines<tokio::io::BufReader<tokio::io::ReadHalf<tokio::io::DuplexStream>>>,
    writes: tokio::io::WriteHalf<tokio::io::DuplexStream>,
    connector: Arc<kr_worker::broker::connectors::InstalledConnector>,
    root: std::path::PathBuf,
    _retire: tokio::sync::oneshot::Sender<()>,
}

impl ServedChannel {
    async fn open(host: &Host) -> Self {
        use kr_worker::broker::bridge::{
            AdmittedBridge, BridgeProcess, BridgeStream, BridgeSurface,
        };
        use kr_worker::broker::connectors::{InstalledConnector, decoding_trust, fixture};
        let broker = Arc::clone(host.service.broker());
        let launched = ProcessStartIdentity::new(41, ProcessStartSource::MacosProcBsdInfo, 900);
        broker
            .register_instance(
                instance(),
                IntegrationMode::NativeBridge,
                None,
                Some(ManagedProcess::new(
                    instance(),
                    launched.clone(),
                    TransportHandle {
                        transport: BrokerTransport::PrivateSocket,
                        application_instance_id: instance(),
                        executable_digest: Digest256::from_bytes([3; 32]),
                        process: launched.clone(),
                    },
                    Credential::from_bytes([9; 32]),
                    false,
                    TimestampMs::new(1),
                )),
            )
            .expect("the launched instance is registered");
        let root = std::env::temp_dir().join(format!("kr-channel-{}", kr_ipc::new_uuid()));
        std::fs::create_dir_all(&root).expect("the store's directory");
        let source =
            fixture::claude_code_package(&root, std::path::Path::new("/opt/kalareach/bin/kr-hook"))
                .expect("the package is written");
        let connector =
            Arc::new(InstalledConnector::read(source).expect("the installed package reads"));
        let package_binding = BrokerBindingId::new(Uuid::from_bytes([0x33; 16]));
        broker
            .bind(
                package_binding,
                instance(),
                connector.plugin_id(),
                PublisherId::new("kalareach").expect("valid"),
                connector.package_digest(),
                BrokerGrants::granted([BrokerGrant::ApprovalInterpreter]),
                decoding_trust(&connector, TimestampMs::new(1)),
                TimestampMs::new(1),
            )
            .expect("the package is bound");
        broker
            .register_actions(package_binding, &connector.manifest().actions)
            .expect("its actions are registered");
        let (ours, theirs) = tokio::io::duplex(64 * 1024);
        let (reader, writer) = tokio::io::split(theirs);
        let admitted = AdmittedBridge {
            surface: BridgeSurface::Channel,
            process: BridgeProcess {
                identity: ProcessStartIdentity::new(43, ProcessStartSource::MacosProcBsdInfo, 902),
                starter: Some(launched),
                started: None,
            },
            stream: BridgeStream::new(
                Box::new(reader),
                Box::new(writer),
                Vec::new(),
                kr_worker::broker::Framing::new(kr_protocol::gateway::NativeFraming::JsonLines),
            ),
        };
        let (retire, retired) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(kr_worker::broker::channels::serve(
            kr_worker::broker::channels::ChannelLaunch {
                broker,
                application_instance_id: instance(),
                connector: Arc::clone(&connector),
                version: Some(fixture::QUALIFIED_VERSION.to_owned()),
                site: host.environment_id,
                os_user: "person".to_owned(),
                views: None,
            },
            admitted,
            async move {
                let _ = retired.await;
            },
        ));
        let (ours_reader, writes) = tokio::io::split(ours);
        Self {
            lines: tokio::io::AsyncBufReadExt::lines(tokio::io::BufReader::new(ours_reader)),
            writes,
            connector,
            root,
            _retire: retire,
        }
    }

    /// Relays one tool approval, as the forwarder does, and waits for it to be interpreted.
    async fn relay(
        &mut self,
        host: &Host,
        request_id: &str,
    ) -> kr_protocol::ids::PendingResourceId {
        let frame = serde_json::json!({
            "method": "notifications/claude/channel/permission_request",
            "params": {
                "request_id": request_id,
                "tool_name": "Bash",
                "description": "List the files here",
                "input_preview": "ls -la",
            },
        });
        tokio::io::AsyncWriteExt::write_all(&mut self.writes, format!("{frame}\n").as_bytes())
            .await
            .expect("the frame is written");
        let started = tokio::time::Instant::now();
        loop {
            let found = host
                .service
                .broker()
                .pending_resources()
                .into_iter()
                .find(|resource| {
                    resource.request.upstream.as_str() == format!("\"{request_id}\"")
                        && resource.interpretation_verified
                });
            if let Some(resource) = found {
                return resource.resource_id;
            }
            assert!(
                started.elapsed() < LIVENESS_DEADLINE,
                "the approval is interpreted"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }

    /// Reads the next frame this host wrote on the channel.
    async fn next(&mut self) -> serde_json::Value {
        let line = tokio::time::timeout(LIVENESS_DEADLINE, self.lines.next_line())
            .await
            .expect("the channel is written to in time")
            .expect("the channel reads")
            .expect("the channel is open");
        serde_json::from_str(&line).expect("a frame is JSON")
    }
}

impl Drop for ServedChannel {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// One `plugin.action.invoke` of the channel package's answer action.
fn channel_answer(
    client: &LocalClient,
    host: &Host,
    connector: &kr_worker::broker::connectors::InstalledConnector,
    request_id: u64,
    resource_id: kr_protocol::ids::PendingResourceId,
    decision: &str,
) -> MutationRequest {
    MutationRequest {
        request_id: RequestId::new(request_id),
        method: Method::PluginActionInvoke.into(),
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
        params: ParamsValue::from_typed(&kr_protocol::agent::PluginActionInvokeParams {
            target: AgentMutationTarget {
                subject: subject(host.session_id, instance()),
                binding_revision: AgentBindingRevision::new(1),
            },
            plugin_id: connector.plugin_id(),
            action: kr_protocol::broker::ActionName::new("approval.answer").expect("valid"),
            draft_id: Nullable::null(),
            resource_id: Nullable::some(resource_id),
            parameters: kr_protocol::scalars::Bytes::from(
                serde_json::to_vec(&serde_json::json!({ "decision": decision })).expect("encodes"),
            ),
        })
        .expect("encodes"),
    }
}

/// KR-REQ-12.18 and KR-REQ-11.34: with the Claude Code package bound as the installation's binder
/// will bind it, `plugin.action.invoke` of its answer action writes the application's own verdict
/// on the channel, once, from the table's decision destination with no component involved, and
/// returns the action's own result with a receipt that says it was applied.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_12_18_a_plugin_answer_goes_out_on_the_channel_and_reports_the_action() {
    let host = host().await;
    let mut channel = ServedChannel::open(&host).await;
    let resource_id = channel.relay(&host, "abcde").await;
    let mut client = cli(&host).await;

    let mutation = channel_answer(&client, &host, &channel.connector, 60, resource_id, "allow");
    let action_id = mutation.action_id;
    let outcome = send(&mut client, mutation).await;
    let Outcome::Ok(result) = outcome else {
        panic!("the answer is carried: {outcome:?}");
    };
    let result: kr_protocol::agent::PluginActionInvokeResult =
        result.to_typed().expect("the action's own result");
    assert_eq!(result.action.as_str(), "approval.answer");
    assert_eq!(
        result.mutation.provenance,
        kr_protocol::broker::ActionProvenance::UpstreamTypedRpc
    );
    assert_eq!(
        channel.next().await,
        serde_json::json!({
            "method": "notifications/claude/channel/permission",
            "params": { "request_id": "abcde", "behavior": "allow" }
        })
    );
    assert_eq!(
        receipt(&mut client, action_id).await.state,
        ReceiptState::Applied
    );
    assert_eq!(
        host.service
            .broker()
            .pending(resource_id)
            .expect("held")
            .state,
        kr_protocol::gateway::PendingState::Resolved
    );

    // Once: the resource has its answer, and a second one is refused before its marker.
    let again = channel_answer(&client, &host, &channel.connector, 61, resource_id, "deny");
    let again_id = again.action_id;
    assert!(matches!(send(&mut client, again).await, Outcome::Error(_)));
    assert_eq!(
        receipt(&mut client, again_id).await.state,
        ReceiptState::Rejected
    );
}

/// A transport whose `submit` blocks until it is let go: one whose queue is held somewhere this
/// host cannot see.
#[derive(Debug)]
struct BlockingUpstream {
    release: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
}

impl UpstreamDispatch for BlockingUpstream {
    fn admit(&self, _request: &UpstreamRequest) -> Result<(), BrokerError> {
        Ok(())
    }

    fn submit(&self, _request: &UpstreamRequest) -> Result<PendingTransmission, BrokerError> {
        let _ = self
            .release
            .lock()
            .expect("the release is not poisoned")
            .recv_timeout(std::time::Duration::from_secs(120));
        Ok(PendingTransmission::settled(Ok(UpstreamOutcome {
            upstream_request_id: None,
            turn_id: None,
            provenance: kr_protocol::broker::ActionProvenance::UpstreamTypedRpc,
        })))
    }
}

/// Section 9: an admitted operation whose transport blocks while it takes the operation is answered
/// when the upstream deadline passes, as an outcome nobody can establish, and not whenever the
/// transport lets go.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_transport_that_blocks_as_it_takes_an_operation_meets_the_upstream_deadline() {
    let host = host().await;
    let (release, held) = std::sync::mpsc::channel();
    register(
        &host,
        Some(Arc::new(BlockingUpstream {
            release: std::sync::Mutex::new(held),
        }) as Arc<dyn UpstreamDispatch>),
    );
    let mut client = cli(&host).await;
    let mutation = prompt_mutation(&client, &host, 70);
    let action_id = mutation.action_id;
    let started = tokio::time::Instant::now();
    let deadline = kr_worker::service::UPSTREAM_SUBMIT_DEADLINE;
    let outcome = tokio::time::timeout(
        deadline + std::time::Duration::from_secs(30),
        send(&mut client, mutation),
    )
    .await
    .expect("the caller is answered at the deadline, not when the transport lets go");
    let waited = started.elapsed();
    let _ = release.send(());
    let Outcome::Error(error) = outcome else {
        panic!("a transmission that never finished is not applied: {outcome:?}");
    };
    assert_eq!(error.code, ErrorCode::UpstreamUnavailable);
    assert!(
        waited < deadline + std::time::Duration::from_secs(20),
        "answered after {waited:?}, at a deadline of {deadline:?}"
    );
    assert_eq!(
        receipt(&mut client, action_id).await.state,
        ReceiptState::Unknown,
        "whether it reached the upstream cannot be established"
    );
}

/// The state one pending resource is in now.
fn state_of(
    host: &Host,
    resource_id: kr_protocol::ids::PendingResourceId,
) -> kr_protocol::gateway::PendingState {
    host.service
        .broker()
        .pending(resource_id)
        .expect("the resource is held")
        .state
}

/// Section 9 and KR-REQ-11.27: an answer whose transport blocks while it takes it is settled as
/// uncertain when the upstream deadline passes, before its receipt is recorded and before its
/// caller hears; the transport letting go afterwards, and saying it took the answer, settles
/// nothing again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_09_an_answer_whose_transport_blocks_is_uncertain_before_its_caller_hears() {
    let host = host().await;
    let (release, held) = std::sync::mpsc::channel();
    register(&host, None);
    let resource_id = offer_approval(
        &host,
        Arc::new(BlockingUpstream {
            release: std::sync::Mutex::new(held),
        }),
    );
    let mut client = cli(&host).await;
    let mutation = approval_mutation(&client, &host, 71, resource_id);
    let action_id = mutation.action_id;
    let deadline = kr_worker::service::UPSTREAM_SUBMIT_DEADLINE;
    let outcome = tokio::time::timeout(
        deadline + std::time::Duration::from_secs(30),
        send(&mut client, mutation),
    )
    .await
    .expect("the caller is answered at the deadline, not when the transport lets go");
    let when_answered = state_of(&host, resource_id);
    let Outcome::Error(error) = outcome else {
        panic!("an answer that never finished going is not applied: {outcome:?}");
    };
    assert_eq!(error.code, ErrorCode::UpstreamUnavailable);
    assert_eq!(
        when_answered,
        kr_protocol::gateway::PendingState::Uncertain,
        "the resource was settled before the caller heard"
    );

    let _ = release.send(());
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    assert_eq!(
        state_of(&host, resource_id),
        kr_protocol::gateway::PendingState::Uncertain,
        "what the transport did afterwards settles nothing again"
    );
    assert_eq!(
        receipt(&mut client, action_id).await.state,
        ReceiptState::Unknown
    );
}

/// Section 9 and KR-REQ-11.27: an answer the transport took and the upstream never acknowledged is
/// settled as uncertain at the upstream deadline, before its caller hears.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_09_an_answer_never_acknowledged_is_uncertain_before_its_caller_hears() {
    let host = host().await;
    let (_never, waiting) = tokio::sync::oneshot::channel::<()>();
    register(&host, None);
    let resource_id = offer_approval(
        &host,
        Arc::new(WaitingUpstream {
            release: std::sync::Mutex::new(Some(waiting)),
            carried: std::sync::atomic::AtomicUsize::new(0),
        }),
    );
    let mut client = cli(&host).await;
    let mutation = approval_mutation(&client, &host, 72, resource_id);
    let action_id = mutation.action_id;
    let deadline = kr_worker::service::UPSTREAM_SUBMIT_DEADLINE;
    let outcome = tokio::time::timeout(
        deadline + std::time::Duration::from_secs(30),
        send(&mut client, mutation),
    )
    .await
    .expect("the caller is answered at the deadline");
    let when_answered = state_of(&host, resource_id);
    let Outcome::Error(error) = outcome else {
        panic!("an answer nobody acknowledged is not applied: {outcome:?}");
    };
    assert_eq!(error.code, ErrorCode::UpstreamUnavailable);
    assert_eq!(
        when_answered,
        kr_protocol::gateway::PendingState::Uncertain,
        "the resource was settled before the caller heard"
    );
    assert_eq!(
        receipt(&mut client, action_id).await.state,
        ReceiptState::Unknown
    );
}

/// Connects as the control daemon and proves the generation this worker accepts.
async fn daemon(host: &Host) -> LocalClient {
    let mut daemon = LocalClient::connect(&host.endpoint, LocalClientKind::Controller, build())
        .await
        .expect("connects as the daemon");
    let identity = Arc::clone(&host.controller);
    let boot = host.boot.clone();
    daemon
        .present_generation(move |nonce| {
            identity
                .generation_token(ControllerGeneration::new(1), &boot, nonce)
                .map_err(kr_ipc::IpcError::from)
        })
        .await
        .expect("the worker accepts the generation");
    daemon
}

/// One `plugin.action.invoke` of the suite's package on the suite's instance.
fn plugin_invocation(
    host: &Host,
    request_id: u64,
    action_window_id: kr_protocol::ids::ActionWindowId,
    action: &str,
    resource_id: Nullable<kr_protocol::ids::PendingResourceId>,
    parameters: &[u8],
) -> MutationRequest {
    MutationRequest {
        request_id: RequestId::new(request_id),
        method: Method::PluginActionInvoke.into(),
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
        action_window_id,
        requested_ttl_ms: DurationMs::new(60_000),
        params: ParamsValue::from_typed(&kr_protocol::agent::PluginActionInvokeParams {
            target: AgentMutationTarget {
                subject: subject(host.session_id, instance()),
                binding_revision: AgentBindingRevision::new(1),
            },
            plugin_id: PluginId::new("kalareach.codex").expect("valid"),
            action: kr_protocol::broker::ActionName::new(action).expect("valid"),
            draft_id: Nullable::null(),
            resource_id,
            parameters: kr_protocol::scalars::Bytes::from(parameters.to_vec()),
        })
        .expect("encodes"),
    }
}

/// Forwards one mutation as the control daemon does for a paired device acting under a grant
/// that carries `grant_rights`.
async fn forward_as_device(
    daemon: &mut LocalClient,
    mutation: &MutationRequest,
    grant_rights: &[kr_protocol::rights::ActionRight],
) -> std::result::Result<ParamsValue, kr_protocol::error::ProtocolError> {
    let envelope = kr_protocol::actor::ActorEnvelope {
        actor_id: kr_protocol::ids::ActorId::new("device:a-test-phone").expect("an actor"),
        ingress: kr_protocol::actor::ActorIngress::PairedDevice,
        device_id: Nullable::some(kr_protocol::ids::DeviceId::new(Uuid::from_bytes([9; 16]))),
        grant_id: Nullable::some(kr_protocol::ids::GrantId::new(Uuid::from_bytes([8; 16]))),
        grant_revision: Nullable::some(kr_protocol::ids::AuthorityRevision::new(1)),
        controller_generation: ControllerGeneration::new(1),
        connection_id: kr_protocol::ids::ConnectionId::new(Uuid::from_bytes([7; 16])),
    };
    daemon
        .forward(
            mutation,
            &envelope,
            &grant_rights.iter().copied().collect(),
            kr_protocol::scalars::U64::new(kr_ipc::clock::boot_elapsed_ms() + 30_000),
        )
        .await
        .expect("the forward reaches the worker")
}

/// Registers one action of each class a paired device could invoke on the approval tests'
/// binding, as the package declares them: an answer through the connector table's decision
/// destination, and a prompt and an attachment its component prepares.
fn register_class_actions(host: &Host) {
    let declared = |id: &str, effect: &str, implementation: serde_json::Value| {
        serde_json::from_value::<kr_plugin_sdk::effect::ActionDeclaration>(serde_json::json!({
            "id": id,
            "label": id,
            "effect": effect,
            "implementation": implementation,
            "parameters": { "parameters": [] },
            "description": format!("{id}, as the package declares it"),
            "confirmation_required": false,
        }))
        .expect("a declaration the manifest format reads")
    };
    let refused = host
        .service
        .broker()
        .register_actions(
            binding(),
            &[
                declared(
                    "request.answer",
                    "approval.respond",
                    serde_json::json!({ "type": "decision_destination", "decision": "decision" }),
                ),
                declared(
                    "prompt.send",
                    "upstream.prompt",
                    serde_json::json!({ "type": "component" }),
                ),
                declared(
                    "draft.attach",
                    "upstream.attachment",
                    serde_json::json!({ "type": "component" }),
                ),
            ],
        )
        .expect("the actions are registered");
    assert!(refused.is_empty(), "{refused:?}");
}

/// Offers one more request on the approval tests' connection, interpreted by their binding.
fn offer_another(host: &Host, id: u64) -> kr_protocol::ids::PendingResourceId {
    let broker = host.service.broker();
    let opaque = broker
        .forward_native(
            kr_protocol::ids::GatewayConnectionId::new(1),
            format!(r#"{{"id":{id},"method":"session/request_permission"}}"#).as_bytes(),
            TimestampMs::new(4),
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
            TimestampMs::new(5),
        )
        .expect("interpreted")
        .resource_id
}

/// KR-REQ-11.47 and KR-REQ-23.30: `plugin.action.invoke` holds a caller acting under a grant to
/// the rights its action's declared class needs, as the method's entry says it intersects them: an
/// answer needs `agent.approval.respond`, a prompt `agent.prompt`, and an attachment `agent.prompt`
/// and `files.upload`. A paired device whose grant lacks one is refused before the marker, and
/// nothing is carried. One whose grant holds them passes, and so does the local owner, who acts
/// under no grant: each answer is admitted and carried, and the prompt and the attachment meet the
/// refusal every component action meets here.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_11_47_a_forwarded_action_needs_the_rights_of_its_class() {
    use kr_protocol::rights::ActionRight;
    let host = host().await;
    let upstream = Arc::new(CountingUpstream::default());
    register(
        &host,
        Some(Arc::clone(&upstream) as Arc<dyn UpstreamDispatch>),
    );
    let first = offer_approval(&host, Arc::clone(&upstream));
    let second = offer_another(&host, 12);
    register_class_actions(&host);
    let mut daemon = daemon(&host).await;
    let window = || kr_protocol::ids::ActionWindowId::new("forwarded").expect("a window");
    let every = [
        ActionRight::AgentApprovalRespond,
        ActionRight::AgentPrompt,
        ActionRight::FilesUpload,
    ];
    let without = |missing: ActionRight| {
        every
            .iter()
            .copied()
            .filter(|right| *right != missing)
            .collect::<Vec<_>>()
    };
    let decision = br#"{"decision":"allow"}"#.as_slice();

    for (request_id, action, resource, parameters, missing) in [
        (
            100,
            "request.answer",
            Nullable::some(first),
            decision,
            ActionRight::AgentApprovalRespond,
        ),
        (
            101,
            "prompt.send",
            Nullable::null(),
            b"{}".as_slice(),
            ActionRight::AgentPrompt,
        ),
        (
            102,
            "draft.attach",
            Nullable::null(),
            b"{}".as_slice(),
            ActionRight::FilesUpload,
        ),
    ] {
        let refusal = forward_as_device(
            &mut daemon,
            &plugin_invocation(&host, request_id, window(), action, resource, parameters),
            &without(missing),
        )
        .await
        .expect_err(action);
        assert_eq!(
            refusal.code,
            ErrorCode::PermissionDenied,
            "{action} without {}: {refusal:?}",
            missing.as_str()
        );
    }
    assert_eq!(
        upstream.carried.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "nothing was carried"
    );
    assert_eq!(
        host.service
            .broker()
            .pending(first)
            .expect("still held")
            .state,
        kr_protocol::gateway::PendingState::Pending,
        "and the request is still pending"
    );

    for (request_id, action) in [(110, "prompt.send"), (111, "draft.attach")] {
        let refusal = forward_as_device(
            &mut daemon,
            &plugin_invocation(&host, request_id, window(), action, Nullable::null(), b"{}"),
            &every,
        )
        .await
        .expect_err("no component's prepared effect reaches this broker");
        assert_eq!(
            refusal.code,
            ErrorCode::UnsupportedCapability,
            "{action}, with the rights its class needs: {refusal:?}"
        );
    }
    forward_as_device(
        &mut daemon,
        &plugin_invocation(
            &host,
            112,
            window(),
            "request.answer",
            Nullable::some(first),
            decision,
        ),
        &every,
    )
    .await
    .expect("an answer under a grant with its right is admitted and carried");

    let mut client = cli(&host).await;
    for (request_id, action) in [(120, "prompt.send"), (121, "draft.attach")] {
        let mutation = plugin_invocation(
            &host,
            request_id,
            client.action_window().action_window_id.clone(),
            action,
            Nullable::null(),
            b"{}",
        );
        let Outcome::Error(refusal) = send(&mut client, mutation).await else {
            panic!("no component's prepared effect reaches this broker");
        };
        assert_eq!(
            refusal.code,
            ErrorCode::UnsupportedCapability,
            "{action}, from the local owner: {refusal:?}"
        );
    }
    let mutation = plugin_invocation(
        &host,
        122,
        client.action_window().action_window_id.clone(),
        "request.answer",
        Nullable::some(second),
        decision,
    );
    let outcome = send(&mut client, mutation).await;
    assert!(
        matches!(outcome, Outcome::Ok(_)),
        "the local owner's answer is admitted and carried: {outcome:?}"
    );
    assert_eq!(
        upstream.carried.load(std::sync::atomic::Ordering::SeqCst),
        2,
        "the two answers were carried"
    );
}
