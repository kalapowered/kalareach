//! The revocation barrier, the dispatch lease and the admission a mutation carries.
//!
//! Section 9 draws one distinction these tests exist to hold: the bounded lease stops stale remote
//! work, and it is **not** the barrier. "Cutting a network path or merely waiting for a lease timer
//! is not completion: a paused worker could already be inside a dispatch transition." So every
//! test here uses a real worker on a real socket, with a real journal, and the worker really is
//! paused: the revocation is announced while the worker cannot answer, and what the daemon reports
//! in the meantime is `pending` with per-worker status.
//!
//! KR-ACC-022 is the whole sequence: pause after durable acceptance, revoke during the worker's
//! isolation, wait for the true barrier, resume, and prove that no affected undispatched action
//! executed.

use std::sync::Arc;
use std::time::Duration;

use kr_controller::authority::{AdmissionContext, AdmittedMutation, AuthorityBarrier};
use kr_controller::error::ControllerError;
use kr_controller::registry::{LaunchPhase, Registry};
use kr_controller::service::{Clocks, Controller, ControllerSetup, WallClock};
use kr_controller::supervision::{LaunchOutcome, WorkerLaunch, WorkerSupervisor};
use kr_crypto::store::{StoreSelection, open_store_in};
use kr_ipc::client::LocalClient;
use kr_ipc::endpoint::Listener;
use kr_ipc::verify::{ControllerIdentity, WorkerIdentity};
use kr_protocol::action::BarrierState;
use kr_protocol::envelope::{ActionTarget, ControlFrame, MutationRequest, Outcome, ParamsValue};
use kr_protocol::error::ErrorCode;
use kr_protocol::hello::PROTOCOL_VERSION;
use kr_protocol::identity::{DesktopBinding, WorkerProfile};
use kr_protocol::ids::{
    ActionId, ActorId, AuthorityRevision, BuildId, ConnectionId, ControllerGeneration,
    EnvironmentId, RequestId, SessionEpoch, SessionId,
};
use kr_protocol::local::LocalClientKind;
use kr_protocol::method::{Method, MethodVersion};
use kr_protocol::receipt::{ReceiptState, RejectionReason};
use kr_protocol::scalars::{Digest256, DurationMs, Nullable, TimestampMs, Uuid};
use kr_protocol::session::{
    Dimensions, DisplayNumber, Presentation, SessionCreateParams, ShellMode,
};
use kr_transport::clock::{ContinuousClock as _, ManualClock};
use kr_transport::lease::LeaseRefusal;
use kr_worker::journal::Submission;
use kr_worker::runtime::SessionRuntime;
use kr_worker::service::{ServiceBinding, WorkerService};
use kr_worker::session::{Session, SessionConfig};

/// How long a test waits for an exchange with a worker it has not paused.
const REACHABLE: Duration = Duration::from_secs(10);

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

fn actor(name: &str) -> ActorId {
    ActorId::new(name).expect("a principal")
}

/// A revocation's barrier once the daemon has announced it again as often as a busy worker needs.
///
/// A worker takes its dispatch boundary without waiting when an announcement arrives, and refuses
/// the announcement while anything else holds it: the generation another of the daemon's links
/// presents, a mutation and a maintenance pass each hold it for a moment. A refused announcement
/// leaves that worker `pending`, which section 9 makes the answer and not a failure, and the fence
/// stays owed, so a status read or a start announces again. A page of the evidence that follows
/// an acknowledgement is refused for the same reason, and the daemon asks for it again itself,
/// after a pause that grows and within a bound; a worker that is still busy after the bound leaves
/// the rest of its names to the next announcement, and the barrier holds and the fence is settled
/// by then, so only a proxy that opens or a later barrier makes one. A test that needs the whole
/// of a report therefore announces again until `settled` accepts it, and never reads the first
/// answer as the last. One deadline bounds the whole wait: it is checked before each
/// announcement, and each announcement is cut off at it.
async fn announced_until(
    controller: &Controller,
    first: kr_protocol::action::RevocationBarrier,
    settled: impl Fn(&kr_protocol::action::RevocationBarrier) -> bool,
) -> kr_protocol::action::RevocationBarrier {
    let mut barrier = first;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    while !settled(&barrier) {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the revocation did not settle within a minute of announcements: {barrier:?}"
        );
        tokio::task::yield_now().await;
        barrier = tokio::time::timeout_at(deadline, controller.announce_authority_revision())
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "the revocation did not settle within a minute of announcements: {barrier:?}"
                )
            })
            .expect("the revocation is announced again");
    }
    barrier
}

fn action(byte: u8) -> ActionId {
    ActionId::new(Uuid::from_bytes([byte; 16]))
}

/// A submission recorded at this machine's own wall clock.
///
/// The retention period is real, so a record seeded at a fixed moment in 1970 would be pruned the
/// first time the worker admitted anything.
fn submission(byte: u8, actor_id: &ActorId) -> Submission {
    let now_ms = kr_ipc::now_ms();
    Submission {
        actor_id: actor_id.clone(),
        action_id: action(byte),
        method: Method::AgentApprovalRespond.into(),
        method_version: MethodVersion::V1,
        payload_digest: Digest256::from_bytes([byte; 32]),
        subject_digest: Digest256::from_bytes([byte ^ 0xff; 32]),
        intent: vec![0xa0],
        accepted_deadline_ms: Some(TimestampMs::new(now_ms.get() + 120_000)),
        now_ms,
    }
}

/// One real worker, on one real socket, with one real journal.
struct Worker {
    /// First, so a worker served apart has ended before the temporary tree is removed.
    _apart: Option<ApartWorker>,
    _temp: kr_ipc::testing::TempHost,
    runtime: Arc<SessionRuntime>,
    service: Arc<WorkerService>,
    session_id: SessionId,
    endpoint: kr_ipc::paths::Endpoint,
    controller: Arc<ControllerIdentity>,
    boot: kr_protocol::identity::BootIdentity,
    environment_id: EnvironmentId,
}

impl Worker {
    /// The worker's runtimes of its own, which a case that stops its tasks has to name.
    fn apart(&self) -> &ApartWorker {
        self._apart
            .as_ref()
            .expect("a worker whose tasks a test stops is served apart")
    }
}

async fn worker() -> Worker {
    worker_serving(false).await
}

/// As [`worker`], with the worker's session runtime and connections on runtimes of their own, as
/// [`hosted_worker_apart`] has them.
async fn worker_apart() -> Worker {
    worker_serving(true).await
}

/// The worker as [`worker`] makes it, served on this test's runtime, or on runtimes of its own when
/// `apart`.
async fn worker_serving(apart: bool) -> Worker {
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
    let store = open_store_in(&environment.secrets_dir()).expect("a secret store");
    let controller = Arc::new(
        ControllerIdentity::initialise(store.store.as_ref(), environment_id)
            .expect("a controller identity"),
    );
    let config = SessionConfig {
        session_id,
        session_epoch: SessionEpoch::V1,
        environment_id,
        display_number: DisplayNumber::new(1),
        // A root program that outlives the suite and ends with its terminal, so a test that
        // takes a minute does not find the session closed because its shell ran out.
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
    let mut session = Session::open(config).expect("opens the session");
    session.launch().expect("launches the shell");
    let endpoint = environment
        .worker_endpoint(DisplayNumber::new(1))
        .expect("an endpoint");
    let binding = ServiceBinding {
        environment_id,
        boot_identity: boot.clone(),
        controller_public_key: *controller.public_key(),
        controller_generation: ControllerGeneration::new(1),
        journal_path: Some(environment.journal_database(session_id)),
        build_id: build(),
    };
    let (runtime, service, apart_worker) = if apart {
        let (runtime, service, worker) =
            ApartWorker::start(session, identity, endpoint.clone(), binding).await;
        (runtime, service, Some(worker))
    } else {
        let runtime = Arc::new(
            SessionRuntime::start(
                session,
                std::sync::Arc::new(kr_ipc::clock::SystemSharedClock),
            )
            .expect("starts the runtime"),
        );
        let listener = Listener::bind(&endpoint).expect("binds the endpoint");
        let service = Arc::new(
            WorkerService::new(Arc::clone(&runtime), identity, endpoint.clone(), binding)
                .expect("a worker service"),
        );
        tokio::spawn(Arc::clone(&service).serve(listener));
        (runtime, service, None)
    };
    Worker {
        _apart: apart_worker,
        _temp: temp,
        runtime,
        service,
        session_id,
        endpoint,
        controller,
        boot,
        environment_id,
    }
}

/// Connects as the control daemon of `generation` and proves it.
async fn daemon(worker: &Worker, generation: u64) -> LocalClient {
    let mut client = LocalClient::connect(&worker.endpoint, LocalClientKind::Controller, build())
        .await
        .expect("connects");
    let identity = Arc::clone(&worker.controller);
    let boot = worker.boot.clone();
    client
        .present_generation(move |nonce| {
            identity
                .generation_token(ControllerGeneration::new(generation), &boot, nonce)
                .map_err(kr_ipc::IpcError::from)
        })
        .await
        .expect("the worker accepts the generation");
    client
}

/// Submits one real mutation through the worker's own endpoint, and returns what it did.
///
/// A real action rather than a written row: what a revocation has to be proved against is an
/// action this host actually admitted, with the receipt its own dispatch path wrote.
async fn submit_real_action(worker: &Worker, client: &mut LocalClient) -> ActionId {
    let mut requested = kr_protocol::scalars::CanonicalSet::new();
    requested.insert(kr_protocol::attachment::AttachmentCapability::ObserveTerminal);
    let action_id = ActionId::new(kr_ipc::new_uuid());
    let target = ActionTarget {
        environment_id: worker.environment_id,
        session_id: Nullable::some(worker.session_id),
        session_epoch: Nullable::some(SessionEpoch::V1),
        application_instance_id: Nullable::null(),
        agent_binding_revision: Nullable::null(),
    };
    client
        .mutate(
            Method::SessionAttach,
            action_id,
            target,
            &kr_protocol::attachment::SessionAttachParams {
                session_id: worker.session_id,
                mode: kr_protocol::attachment::AttachMode::Terminal,
                claim_geometry: false,
                dimensions: Nullable::some(Dimensions::new(80, 24)),
                terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
                requested,
            },
        )
        .await
        .expect("reaches the worker")
        .expect("the attachment is accepted");
    action_id
}

/// Seeds the worker's journal with one intent this host accepted and never dispatched.
///
/// A real mutation cannot be left in that state through the endpoint: the worker's dispatch path is
/// serial and settles what it admits before it answers, so an accepted intent with no marker is
/// what a worker holds after it restarted mid-admission. Writing one is the only way to arrange
/// it, and it is the state section 9's fence is about.
fn seed_undispatched(worker: &Worker, device: &ActorId) {
    let mut session = worker.runtime.session();
    let journal = session.journal_mut().expect("a journal");
    journal
        .accept(&submission(1, device))
        .expect("an undispatched intent");
}

fn notice(worker: &Worker, revision: u64) -> kr_protocol::worker::AuthorityRevisionNotice {
    kr_protocol::worker::AuthorityRevisionNotice {
        environment_id: worker.environment_id,
        revision: AuthorityRevision::new(revision),
        evidence_from: 0,
    }
}

/// The name of one fenced action, as a report holds it.
fn fenced(actor_id: &ActorId, byte: u8) -> kr_protocol::action::FencedAction {
    kr_protocol::action::FencedAction {
        actor_id: actor_id.clone(),
        action_id: action(byte),
    }
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-09.12, 09.13, KR-ACC-022
// ---------------------------------------------------------------------------------------------

/// Holds the worker's session until it is released, which is how this suite isolates a worker.
///
/// It runs on a thread of its own rather than in the test, because the lock is not reentrant and a
/// test that held it could not then ask the worker anything. While it is held the worker cannot
/// reach its journal, so it cannot install an authority revision: an announcement that arrives
/// stops inside the worker's own revocation handler, which is precisely the case section 9 warns
/// about, a paused worker that could already be inside a dispatch transition.
struct Pause {
    release: Option<std::sync::mpsc::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

/// How long a holder of a worker's session or dispatch boundary is given to take it.
///
/// A liveness bound and not a measurement: a holder takes it as soon as nothing else holds it, and
/// one that has not by now never will, which the case then reports instead of waiting for.
const HOLD_DEADLINE: Duration = Duration::from_secs(120);

impl Pause {
    /// Holds the session of a worker served apart, which the case names with `_apart`: a task of
    /// the worker that waits for the session waits on a thread of the worker's own runtime.
    async fn hold(runtime: &Arc<SessionRuntime>, _apart: &ApartWorker) -> Self {
        let (release, wait) = std::sync::mpsc::channel::<()>();
        let (held, confirmed) = tokio::sync::oneshot::channel::<()>();
        let runtime = Arc::clone(runtime);
        // A thread of its own and not one of the runtime's blocking pool: a holder that never
        // gets the session must not be what keeps this test's runtime from ending.
        let thread = std::thread::spawn(move || {
            let _session = runtime.session();
            let _ = held.send(());
            // Held until the test releases it. The receiver ends when the sender is dropped, so a
            // test that panics does not leave the worker locked for the rest of the suite.
            let _ = wait.recv();
        });
        tokio::time::timeout(HOLD_DEADLINE, confirmed)
            .await
            .expect("the session was not held in time")
            .expect("the holder ended without holding the session");
        Self {
            release: Some(release),
            thread: Some(thread),
        }
    }

    async fn release(mut self) {
        drop(self.release.take());
        if let Some(thread) = self.thread.take() {
            thread.join().expect("the holding thread finishes");
        }
    }
}

/// KR-REQ-09.12, KR-REQ-09.13, KR-ACC-022: the revocation reports `pending` while the worker is
/// isolated, holds when the worker acknowledges, names what may already have been dispatched, and
/// kills nothing.
///
/// In production the worker is its own process; here its session runtime and its connections run
/// on runtimes of their own, apart from each other, so isolating it blocks the session's tasks that
/// want the session on the threads of the runtime they run on, and stops neither the threads that
/// serve this test nor the ones that serve the connection. With them on one runtime, a task of the
/// session that woke while the session was held (its monitor wakes at times no case chooses: on
/// Unix on every child process this test binary's other cases end) could block the thread a
/// connection's task had been made runnable on, and the announcement that task was to read would
/// go unread until the hold ended.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_revocation_is_pending_while_a_worker_is_isolated_and_holds_when_it_resumes() {
    let worker = worker_apart().await;
    let device = actor("device:phone");

    // One action this host really admitted, through its own endpoint and its own dispatch path,
    // and one intent it accepted and never dispatched. The fence has to account for both.
    let mut caller = LocalClient::connect(&worker.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    let dispatched = submit_real_action(&worker, &mut caller).await;
    let local = actor(&format!("local:{}", kr_ipc::paths::current_uid()));
    seed_undispatched(&worker, &device);

    let barrier = AuthorityBarrier::new(ControllerGeneration::new(1), AuthorityRevision::new(3));
    let binding = barrier.bind(worker.session_id);
    let mut client = daemon(&worker, 1).await;
    barrier.acknowledge(
        worker.session_id,
        binding,
        AuthorityRevision::new(3),
        evidence(Vec::new(), Vec::new()),
    );
    assert!(
        barrier
            .begin_round()
            .report(AuthorityRevision::new(3), [worker.session_id])
            .holds()
    );
    assert_eq!(worker.runtime.state().as_str(), "live");

    // The worker is isolated after its intents were durably accepted.
    let paused = Pause::hold(&worker.runtime, worker.apart()).await;
    barrier.revoke(AuthorityRevision::new(4));

    // The revocation is announced while the worker is isolated. The exchange is kept alive on its
    // own task, because the worker will answer it once it is released and the answer is the
    // acknowledgement this barrier waits for.
    let reaching = worker.service.announcement_inside_boundary();
    let announcement = notice(&worker, 4);
    let announcing = tokio::spawn(async move {
        let ack = client.announce_revision(announcement).await;
        (client, ack)
    });

    // The worker says so once the announcement has taken its dispatch boundary and goes on to the
    // session, which is held: the case is about an announcement that is inside the isolated
    // worker's handler, and until it is, the check below would be about one that had not arrived.
    // The worker says so through a standard channel end, so the wait is a blocking call on a
    // blocking thread, and its bound is a duration of the standard clock. The bound only keeps an
    // announcement that never arrives from holding the suite up.
    let reached =
        tokio::task::spawn_blocking(move || reaching.recv_timeout(Duration::from_secs(30)).is_ok())
            .await
            .expect("the waiting thread finishes");
    if !reached {
        // What the announcement has met, read as this message is made: whether the client's task
        // has finished with an answer (a refusal or a transport failure among them), and how many
        // announcements the worker has refused for the boundary so far.
        let met = if announcing.is_finished() {
            format!(
                "answered {:?}",
                announcing.await.map(|(_client, answer)| answer)
            )
        } else {
            "not answered".to_owned()
        };
        panic!(
            "the announcement never took the worker's dispatch boundary ({met}; the worker refused \
             {} announcements for the boundary)",
            worker.service.refusals_for_the_boundary()
        );
    }
    assert!(
        !announcing.is_finished(),
        "the isolated worker cannot acknowledge the revision"
    );
    let pending = barrier
        .begin_round()
        .report(AuthorityRevision::new(4), [worker.session_id]);
    assert!(!pending.holds());
    assert_eq!(pending.pending(), vec![worker.session_id]);
    assert_eq!(pending.workers[0].state, BarrierState::Pending);
    assert!(pending.workers[0].detail.contains("not complete"));

    // Nothing was killed to force the revocation through, and nothing about the worker's own
    // journal moved while it could not reach it.
    paused.release().await;
    let (_client, ack) = tokio::time::timeout(REACHABLE, announcing)
        .await
        .expect("the released worker answers")
        .expect("the announcement task finishes");
    let ack = ack.expect("the worker acknowledges the revision");
    assert_eq!(ack.session_id, worker.session_id);
    assert_eq!(ack.revision, AuthorityRevision::new(4));
    let fence = ack
        .fence
        .clone()
        .expect("the worker reports what its fence did");
    assert_eq!(
        fence.rejected_actions,
        vec![fenced(&device, 1)],
        "the undispatched intent is fenced, under the actor whose intent it was"
    );
    assert_eq!(
        fence.omitted.get(),
        0,
        "this fence named everything it affected"
    );
    let named = fence
        .possibly_executed
        .iter()
        .find(|action| action.action_id == dispatched)
        .expect("the action whose dispatch transition won the race is named");
    assert_eq!(
        named.actor_id, local,
        "named under the principal that submitted it"
    );
    assert_eq!(
        named.state,
        ReceiptState::Applied,
        "its receipt state says how much is known about what it did"
    );

    barrier.acknowledge(worker.session_id, binding, ack.revision, ack.fence.clone());
    let complete = barrier
        .begin_round()
        .report(AuthorityRevision::new(4), [worker.session_id]);
    assert!(complete.holds(), "{complete:?}");
    assert_eq!(complete.workers[0].state, BarrierState::Acknowledged);
    assert_eq!(
        complete.workers[0].rejected_actions,
        vec![fenced(&device, 1)]
    );
    assert_eq!(complete.possibly_executed().len(), 1);

    // No affected undispatched action executed: the one with no marker is `rejected(revoked)`, and
    // the one that had already won the serial race is exactly where it was.
    {
        let mut session = worker.runtime.session();
        let journal = session.journal_mut().expect("a journal");
        let fenced = journal
            .read(device, action(1))
            .expect("reads")
            .expect("a receipt");
        assert_eq!(fenced.state, ReceiptState::Rejected);
        assert_eq!(fenced.reason.as_ref(), Some(&RejectionReason::Revoked));
        assert_eq!(
            fenced.error.as_ref().map(|error| error.code),
            Some(ErrorCode::PermissionDenied)
        );
        let settled = journal
            .read(local, dispatched)
            .expect("reads")
            .expect("a receipt");
        assert_eq!(
            settled.state,
            ReceiptState::Applied,
            "nothing claims an action past its marker did not happen"
        );
    }
    let _ = &caller;
    assert_eq!(
        worker.runtime.state().as_str(),
        "live",
        "no healthy shell is killed to force the revocation to complete"
    );
    let _ = &worker.service;
}

/// KR-REQ-09.12: an announcement from a controller this worker no longer answers to is refused,
/// and leaves no fence behind for the host to run on its behalf.
///
/// What a worker records when it cannot fence at once is a revision it owes, and its own
/// maintenance runs that fence later with no caller involved. A control path whose authority has
/// been replaced must not be able to put work there, and this is what that looks like from
/// outside: the refusal, the journal with nothing named under the revision it asked for, and the
/// intent still where it was.
///
/// This caller is refused before the dispatch boundary is even reached for, so what this proves is
/// the outcome rather than the recording path: it neither reaches the place where a revision is
/// recorded nor waits for the maintenance that would run it. A replacement landing *between* the
/// check and the record is what that path has to survive, and nothing outside this process can
/// interleave those two, because they are one operation under one lock.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn an_announcement_from_a_replaced_controller_leaves_no_fence_behind() {
    let worker = worker().await;
    let device = actor("device:phone");
    seed_undispatched(&worker, &device);

    // Two control paths, the later one holding this environment's authority. The first is what a
    // daemon that has been replaced still has: an open connection the worker refuses rather than a
    // socket that closed.
    let mut replaced = daemon(&worker, 1).await;
    let mut bound = daemon(&worker, 2).await;

    let Err(refusal) = tokio::time::timeout(
        REACHABLE,
        replaced.announce_revision(kr_protocol::worker::AuthorityRevisionNotice {
            environment_id: worker.environment_id,
            revision: AuthorityRevision::new(9),
            evidence_from: 0,
        }),
    )
    .await
    .expect("the worker answers rather than leaving a replaced controller waiting") else {
        panic!("a replaced controller's announcement is refused");
    };
    let refusal = refusal.to_string();
    assert!(
        refusal.contains("a later controller connection holds this environment's authority"),
        "refused for the authority it no longer holds: {refusal}"
    );
    assert!(
        !refusal.contains("pending"),
        "the refusal that leaves a revision to fence is not the one it got: {refusal}"
    );

    // Nothing was fenced and nothing is waiting to be: the intent is where it was, and the
    // revision that announcement named has no evidence of its own.
    {
        let mut session = worker.runtime.session();
        let journal = session.journal_mut().expect("a journal");
        let held = journal
            .read(device.clone(), action(1))
            .expect("reads")
            .expect("a receipt");
        assert_eq!(
            held.state,
            ReceiptState::Accepted,
            "a replaced controller fences nothing"
        );
        let page = journal.evidence_page(9, 0).expect("a page");
        assert!(page.rejected.is_empty());
        assert!(page.possibly_executed.is_empty());
        assert_eq!(page.omitted, 0, "nothing was named and nothing was lost");
    }

    // The controller that does hold authority announces the same revision, and this worker fences
    // for it. The refusal above was about who was asking, not about the revision.
    let ack = tokio::time::timeout(
        REACHABLE,
        bound.announce_revision(kr_protocol::worker::AuthorityRevisionNotice {
            environment_id: worker.environment_id,
            revision: AuthorityRevision::new(9),
            evidence_from: 0,
        }),
    )
    .await
    .expect("the worker answers the controller that holds authority")
    .expect("the worker acknowledges the revision");
    assert_eq!(ack.revision, AuthorityRevision::new(9));
    assert_eq!(
        ack.fence
            .as_ref()
            .expect("the worker reports what its fence did")
            .rejected_actions,
        vec![fenced(&device, 1)]
    );
    let _ = &worker.service;
}

/// KR-REQ-09.12: cutting the path is not completion, and only an acknowledgement or a confirmed
/// ending completes a worker's barrier.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cutting_the_path_is_not_completion_and_only_an_ending_resolves_a_silent_worker() {
    let worker = worker().await;
    let device = actor("device:phone");
    seed_undispatched(&worker, &device);

    let barrier = AuthorityBarrier::new(ControllerGeneration::new(1), AuthorityRevision::new(3));
    let binding = barrier.bind(worker.session_id);
    let client = daemon(&worker, 1).await;
    barrier.acknowledge(
        worker.session_id,
        binding,
        AuthorityRevision::new(3),
        evidence(Vec::new(), Vec::new()),
    );

    // The daemon loses the path rather than the worker losing its authority. Renewal stops, which
    // is the bounded half; the barrier does not hold, which is the other half.
    barrier.revoke(AuthorityRevision::new(4));
    barrier.stop_renewal(worker.session_id, binding);
    drop(client);
    assert!(barrier.is_fenced(worker.session_id));
    let pending = barrier
        .begin_round()
        .report(AuthorityRevision::new(4), [worker.session_id]);
    assert!(
        !pending.holds(),
        "cutting the path stops renewal and completes nothing"
    );

    // The undispatched intent is still there, because nothing has installed the revision.
    {
        let mut session = worker.runtime.session();
        let journal = session.journal_mut().expect("a journal");
        let held = journal
            .read(device.clone(), action(1))
            .expect("reads")
            .expect("a receipt");
        assert_eq!(held.state, ReceiptState::Accepted);
    }
    assert_eq!(worker.runtime.state().as_str(), "live");

    // The worker is confirmed ended, which answers the question the other way section 9 permits.
    // What confirms it is not in this type: section 9 requires the daemon to *verify* that the
    // execution has ended, which is the reconciliation the daemon performs against the recorded
    // process identities. This records the verdict; the closure that records the worker's end is
    // where the verdict is reached, and it calls this in the section that records it. A round
    // that began while the worker ran still reports it, ended, whatever it was forgotten for.
    let round = barrier.begin_round();
    barrier.worker_ended(worker.session_id);
    let complete = round.report(AuthorityRevision::new(4), [worker.session_id]);
    assert!(complete.holds());
    assert_eq!(complete.workers[0].state, BarrierState::Ended);
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-09.10, 09.11
// ---------------------------------------------------------------------------------------------

/// KR-REQ-09.10: remote dispatch needs a live lease from the current generation and revision, the
/// lease lasts at most five seconds on the continuous clock, renewal happens only after the worker
/// has acknowledged the revision, and losing the generation binding stops renewal.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn remote_dispatch_needs_a_live_lease_from_the_current_generation_and_revision() {
    let worker = worker().await;
    let clock = ManualClock::new();
    let barrier = AuthorityBarrier::new(ControllerGeneration::new(1), AuthorityRevision::new(3));
    let binding = barrier.bind(worker.session_id);

    // Before the worker has acknowledged anything there is no lease to be had. This is the race
    // the contract names: renewal can occur only after the worker has installed the revision.
    assert_eq!(
        barrier
            .renew(worker.session_id, ControllerGeneration::new(1), &clock)
            .expect("the generator is available"),
        Err(LeaseRefusal::RevisionNotAcknowledged)
    );

    let mut client = daemon(&worker, 1).await;
    let ack = tokio::time::timeout(REACHABLE, client.announce_revision(notice(&worker, 3)))
        .await
        .expect("the worker answers")
        .expect("the worker acknowledges");
    barrier.acknowledge(worker.session_id, binding, ack.revision, ack.fence);

    let lease = barrier
        .renew(worker.session_id, ControllerGeneration::new(1), &clock)
        .expect("the generator is available")
        .expect("a lease");
    assert_eq!(lease.generation, ControllerGeneration::new(1));
    assert_eq!(lease.authority_revision, AuthorityRevision::new(3));
    assert!(
        lease.remaining(clock.now()) <= kr_transport::lease::MAX_LEASE,
        "a lease is at most five seconds"
    );
    assert_eq!(kr_transport::lease::MAX_LEASE, Duration::from_secs(5));

    // The deadline is checked at the moment of the dispatch rather than trusted from a timer that
    // fired earlier.
    assert!(lease.permits(
        clock.now(),
        ControllerGeneration::new(1),
        AuthorityRevision::new(3)
    ));
    clock.advance(Duration::from_secs(6));
    assert!(
        !lease.permits(
            clock.now(),
            ControllerGeneration::new(1),
            AuthorityRevision::new(3)
        ),
        "a lease that was valid when the action was queued proves nothing"
    );

    // A replacement generation cannot renew a lease it did not issue, so it cannot adopt an
    // envelope queued under the generation it replaced.
    assert_eq!(
        barrier
            .renew(worker.session_id, ControllerGeneration::new(2), &clock)
            .expect("the generator is available"),
        Err(LeaseRefusal::GenerationReplaced)
    );

    // And advancing the revision invalidates every outstanding lease at once, because a lease
    // carries the revision it was issued at.
    barrier.revoke(AuthorityRevision::new(4));
    assert!(!lease.permits(
        clock.now(),
        ControllerGeneration::new(1),
        AuthorityRevision::new(4)
    ));
    assert_eq!(
        barrier
            .renew(worker.session_id, ControllerGeneration::new(1), &clock)
            .expect("the generator is available"),
        Err(LeaseRefusal::RevisionNotAcknowledged)
    );

    // Losing the generation binding stops renewal even after a fresh acknowledgement over the path
    // that was lost.
    barrier.stop_renewal(worker.session_id, binding);
    barrier.acknowledge(
        worker.session_id,
        binding,
        AuthorityRevision::new(4),
        evidence(Vec::new(), Vec::new()),
    );
    assert_eq!(
        barrier
            .renew(worker.session_id, ControllerGeneration::new(1), &clock)
            .expect("the generator is available"),
        Err(LeaseRefusal::RevisionNotAcknowledged)
    );
    assert!(barrier.current_lease(worker.session_id).is_none());
}

/// KR-REQ-09.11: local input and stopping owned execution never depend on the remote lease.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn local_input_and_stopping_owned_execution_never_depend_on_the_remote_lease() {
    let worker = worker().await;
    let clock = ManualClock::new();
    let barrier = AuthorityBarrier::new(ControllerGeneration::new(1), AuthorityRevision::new(3));
    barrier.bind(worker.session_id);
    // No lease exists and none can be issued: the worker has acknowledged nothing.
    assert_eq!(
        barrier
            .renew(worker.session_id, ControllerGeneration::new(1), &clock)
            .expect("the generator is available"),
        Err(LeaseRefusal::RevisionNotAcknowledged)
    );
    assert!(barrier.current_lease(worker.session_id).is_none());

    // A local operating-system caller attaches, takes the input lease and types. None of it asks
    // for a remote dispatch lease.
    let mut client = LocalClient::connect(&worker.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    let target = ActionTarget {
        environment_id: worker.environment_id,
        session_id: Nullable::some(worker.session_id),
        session_epoch: Nullable::some(SessionEpoch::V1),
        application_instance_id: Nullable::null(),
        agent_binding_revision: Nullable::null(),
    };
    let mut requested = kr_protocol::scalars::CanonicalSet::new();
    requested.insert(kr_protocol::attachment::AttachmentCapability::ObserveTerminal);
    requested.insert(kr_protocol::attachment::AttachmentCapability::Input);
    let attached: kr_protocol::attachment::SessionAttachResult = client
        .mutate(
            Method::SessionAttach,
            ActionId::new(kr_ipc::new_uuid()),
            target.clone(),
            &kr_protocol::attachment::SessionAttachParams {
                session_id: worker.session_id,
                mode: kr_protocol::attachment::AttachMode::Terminal,
                claim_geometry: false,
                dimensions: Nullable::some(Dimensions::new(80, 24)),
                terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
                requested,
            },
        )
        .await
        .expect("reaches the worker")
        .expect("the attachment is accepted")
        .to_typed()
        .expect("decodes");
    let acquired: kr_protocol::input::InputAcquireResult = client
        .mutate(
            Method::InputAcquire,
            ActionId::new(kr_ipc::new_uuid()),
            target.clone(),
            &kr_protocol::input::InputAcquireParams {
                session_id: worker.session_id,
                attachment_id: attached.attachment.attachment_id,
                expected_epoch: Nullable::null(),
            },
        )
        .await
        .expect("reaches the worker")
        .expect("the lease is acquired")
        .to_typed()
        .expect("decodes");
    client
        .request(
            Method::InputWrite,
            &kr_protocol::input::InputWriteParams {
                session_id: worker.session_id,
                attachment_id: attached.attachment.attachment_id,
                epoch: acquired.lease.epoch,
                sequence: kr_protocol::ids::InputSequence::new(0),
                bytes: kr_protocol::scalars::Bytes::new(b"echo\n".to_vec()),
            },
        )
        .await
        .expect("reaches the worker")
        .expect("local input reaches the terminal without a remote lease");

    // And stopping owned execution does not depend on it either.
    let closed = client
        .mutate(
            Method::SessionClose,
            ActionId::new(kr_ipc::new_uuid()),
            target,
            &kr_protocol::session::SessionCloseParams {
                session_id: worker.session_id,
            },
        )
        .await
        .expect("reaches the worker");
    assert!(
        closed.is_ok(),
        "stopping owned execution does not need a remote lease: {closed:?}"
    );
}

// ---------------------------------------------------------------------------------------------
// The admission a mutation carries into its transaction
// ---------------------------------------------------------------------------------------------

/// A supervisor that records whether it was asked to start anything, and starts nothing.
#[derive(Debug, Default)]
struct CountingSupervisor {
    started: Arc<std::sync::atomic::AtomicUsize>,
}

impl WorkerSupervisor for CountingSupervisor {
    fn start(&self, _launch: &WorkerLaunch) -> LaunchOutcome {
        self.started
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        LaunchOutcome::NotStarted {
            detail: "this test starts no workers".to_owned(),
        }
    }

    fn describe(&self) -> &'static str {
        "a supervisor that counts what it was asked to start"
    }
}

struct Daemon {
    _temp: kr_ipc::testing::TempHost,
    controller: Arc<Controller>,
    environment_id: EnvironmentId,
    endpoint: kr_ipc::paths::Endpoint,
    registry_path: std::path::PathBuf,
    started: Arc<std::sync::atomic::AtomicUsize>,
}

async fn daemon_host() -> Daemon {
    daemon_host_on(Clocks::system()).await
}

/// A daemon that measures its deadlines on `clocks`, which a test can move by hand.
async fn daemon_host_on(clocks: Clocks) -> Daemon {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let environment_id = temp.environment_id();
    let secrets = environment.secrets_dir();
    let registry_path = environment.registry_database();
    let started = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let controller = Controller::start_on_clocks(
        ControllerSetup {
            paths: environment.clone(),
            environment_id,
            identity: Box::new(move || {
                let store =
                    open_store_in(&secrets).expect("a secret store for the test environment");
                Ok(
                    ControllerIdentity::open(store.store.as_ref(), environment_id, false)
                        .expect("an identity"),
                )
            }),
            secret_store: StoreSelection::File,
            boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
            supervisor: Box::new(CountingSupervisor {
                started: Arc::clone(&started),
            }),
            worker_program: std::path::PathBuf::from("/nonexistent/kr-worker"),
            build_id: build(),
            release: "0".to_owned(),
            shell_packages: None,
            terminal: Box::new(kr_controller::supervision::NoTerminal),
        },
        clocks,
    )
    .await
    .expect("the daemon starts");
    let endpoint = environment.controller_endpoint().expect("an endpoint");
    let listener = Listener::bind(&endpoint).expect("binds the endpoint");
    tokio::spawn(Arc::clone(&controller).serve_clients(listener));
    Daemon {
        _temp: temp,
        controller,
        environment_id,
        endpoint,
        registry_path,
        started,
    }
}

/// KR-REQ-09.09, KR-REQ-09.16: a mutation admitted before its deadline and reaching its store
/// transaction after it is refused inside the transaction, not before the wait and not after the
/// effect.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_mutation_whose_admission_lapses_before_its_transaction_is_refused_inside_it() {
    let daemon = daemon_host().await;
    let mut client = LocalClient::connect(&daemon.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");

    // A lifetime of zero: the deadline the daemon accepts is the moment it accepts it, so the
    // transaction is reached after it has passed. The create is admitted, its reservation is
    // written, and then it is refused rather than starting a shell.
    let mutation = MutationRequest {
        request_id: RequestId::new(1),
        method: Method::SessionCreate.into(),
        method_version: MethodVersion::V1,
        action_id: ActionId::new(kr_ipc::new_uuid()),
        grant_id: Nullable::null(),
        target: ActionTarget {
            environment_id: daemon.environment_id,
            session_id: Nullable::null(),
            session_epoch: Nullable::null(),
            application_instance_id: Nullable::null(),
            agent_binding_revision: Nullable::null(),
        },
        expected: ParamsValue::empty(),
        action_window_id: client.action_window().action_window_id.clone(),
        requested_ttl_ms: DurationMs::new(0),
        params: ParamsValue::from_typed(&SessionCreateParams {
            environment_id: daemon.environment_id,
            presentation: Presentation::Invisible,
            shell: Nullable::null(),
            shell_mode: ShellMode::NativeCompat,
            cwd: Nullable::some("/".to_owned()),
            dimensions: Nullable::null(),
            worker_profile: WorkerProfile::HeadlessUser,
            environment_snapshot: Vec::new(),
            palette: Nullable::null(),
            launch_profile: kr_protocol::session::LaunchProfile::default(),
            terminal: Nullable::null(),
        })
        .expect("encodes"),
    };
    client
        .writer()
        .write_message(&ControlFrame::Mutation(Box::new(mutation)))
        .await
        .expect("writes the mutation");
    let outcome = loop {
        match client.recv().await.expect("the daemon answers") {
            ControlFrame::Response(response) => break response.outcome,
            ControlFrame::Notification(_) | ControlFrame::Event(_) => {}
            other => panic!("the daemon answered {other:?}"),
        }
    };
    let Outcome::Error(error) = outcome else {
        panic!("a create whose admission has lapsed must not start a shell");
    };
    assert_eq!(error.code, ErrorCode::PermissionDenied);
    assert_eq!(
        daemon.started.load(std::sync::atomic::Ordering::Acquire),
        0,
        "nothing was asked to start"
    );

    // The refusal happened inside the transaction: the reservation was written and then failed,
    // rather than never existing.
    let registry = Registry::open(&daemon.registry_path, daemon.environment_id)
        .expect("opens the registry beside the daemon");
    let failed = registry
        .reservations_in(LaunchPhase::Failed)
        .expect("reads the failed reservations");
    assert_eq!(
        failed.len(),
        1,
        "the reservation was written and then failed, rather than never existing"
    );
    assert!(
        registry
            .reservations_in(LaunchPhase::Spawned)
            .expect("reads the spawned reservations")
            .is_empty(),
        "nothing is left recorded as spawned"
    );
    let _ = &daemon.controller;
}

/// A mutation admitted while its lifetime was live, and reaching its store transaction after that
/// lifetime ran out, is refused inside the transaction.
///
/// The contention is real: one task holds the daemon's registry lock while the other's admission
/// expires waiting for it. That is the case a check before the wait cannot catch, because before
/// the wait the admission still stood.
///
/// The daemon measures its deadlines on a clock this test moves, so the order is the test's and
/// not the machine's: the holder has the registry, the write is queued for it, and only then does
/// the lifetime run out. A real delay would have to be long enough for the holder to get there on
/// a loaded machine and short enough to end inside the lifetime, and no length is both.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_mutation_admitted_before_its_deadline_is_refused_when_the_lock_wait_outlasts_it() {
    let clock = ManualClock::new();
    let daemon = daemon_host_on(Clocks {
        continuous: Arc::new(clock.clone()),
        wall: WallClock::system(),
    })
    .await;
    let client = LocalClient::connect(&daemon.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    // A connection has to be admitted for an admission to be built from it, which is what the
    // hello exchange above did.
    let connection = client.acknowledgement().connection_id;
    let revision = AuthorityRevision::new(1);

    // A lifetime of six hundred milliseconds: live when the mutation is admitted, gone by the time
    // the lock is free.
    let live = AdmittedMutation {
        connection_id: connection,
        admitted_revision: revision,
        deadline: daemon
            .controller
            .continuous_now()
            .checked_add(Duration::from_millis(600)),
    };
    assert!(
        daemon
            .controller
            .enter_admitted(&live, |_| Ok(()))
            .await
            .is_ok(),
        "the admission stands before the wait"
    );

    // One task holds the registry, says so, and keeps it until the test lets it go. The receiver
    // ends when the sender is dropped, so a test that panics does not leave the daemon locked.
    let (holds, held) = tokio::sync::oneshot::channel::<()>();
    let (release, released) = std::sync::mpsc::channel::<()>();
    let holder = Arc::clone(&daemon.controller);
    let carried = AdmittedMutation { ..live };
    let holding = tokio::spawn(async move {
        holder
            .enter_admitted(&carried, move |_| {
                holds.send(()).expect("the test is waiting");
                // A blocking wait inside the closure, because the closure is what holds the lock
                // and nothing is awaited inside it.
                let _ = released.recv();
                Ok(())
            })
            .await
    });
    held.await.expect("the holder has the registry");

    // The other write is driven until it is *in* the wait: one poll, and it answers pending,
    // because the registry it needs is the one the holder has.
    let mut waiting = Box::pin(daemon.controller.enter_admitted(&live, |_| Ok(())));
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    assert!(
        std::future::Future::poll(waiting.as_mut(), &mut context).is_pending(),
        "the write is queued for the registry rather than done"
    );

    // The registry stays held past the lifetime, and then it is free.
    clock.advance(Duration::from_secs(2));
    release.send(()).expect("the holder is waiting for this");
    assert!(
        holding.await.expect("the holder finishes").is_ok(),
        "the task that got there first wrote under an admission that still stood"
    );
    let Err(error) = waiting.await else {
        panic!("a mutation whose lifetime ran out while it waited is refused inside the write");
    };
    assert!(
        matches!(error, ControllerError::WindowExpired { .. }),
        "refused for its lifetime rather than written: {error}"
    );
}

/// The same, for a revocation that lands while the mutation waits.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_mutation_whose_authority_is_withdrawn_during_the_lock_wait_is_refused_inside_it() {
    let daemon = daemon_host().await;
    let client = LocalClient::connect(&daemon.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    let connection = client.acknowledgement().connection_id;
    let admission = AdmittedMutation {
        connection_id: connection,
        admitted_revision: AuthorityRevision::new(1),
        deadline: daemon
            .controller
            .continuous_now()
            .checked_add(Duration::from_secs(120)),
    };
    assert!(
        daemon
            .controller
            .enter_admitted(&admission, |_| Ok(()))
            .await
            .is_ok()
    );

    // The authority this connection was admitted under is withdrawn. The deadline is untouched, so
    // what refuses the write is the revocation rather than the clock.
    daemon
        .controller
        .revoke_authority()
        .await
        .expect("the revocation is recorded");
    let Err(error) = daemon
        .controller
        .enter_admitted(&admission, |_| Ok(()))
        .await
    else {
        panic!("a mutation admitted under withdrawn authority is refused inside the write");
    };
    assert_eq!(error.code(), ErrorCode::PermissionDenied);
}

/// The registration half, withdrawn *during* the wait rather than before it.
///
/// Three things have to be ordered for this to be the case it claims to be, and sleeps do not
/// order them. One task holds the daemon's registry. The guarded write is then polled once and
/// answers pending, which is what being inside the wait means. The connection's registration goes
/// while it is in there, and the holder does not let go until it has seen it go: so nothing can
/// have taken the registry in between, and the refusal the write gets is one decided inside its
/// wait rather than before it.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_mutation_whose_registration_is_withdrawn_during_the_lock_wait_is_refused_inside_it() {
    let daemon = daemon_host().await;
    let client = LocalClient::connect(&daemon.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    let connection = client.acknowledgement().connection_id;
    let admission = AdmittedMutation {
        connection_id: connection,
        admitted_revision: AuthorityRevision::new(1),
        deadline: daemon
            .controller
            .continuous_now()
            .checked_add(Duration::from_secs(120)),
    };
    assert!(
        daemon
            .controller
            .enter_admitted(&admission, |_| Ok(()))
            .await
            .is_ok(),
        "the admission stands before the wait"
    );

    // The holder takes the registry and says so, then waits to be told the connection has gone.
    let (holds, held) = tokio::sync::oneshot::channel::<()>();
    let (withdrawn, withdrawal) = std::sync::mpsc::channel::<()>();
    let holder = Arc::clone(&daemon.controller);
    let checking = Arc::clone(&daemon.controller);
    let carried = AdmittedMutation { ..admission };
    let holding = tokio::spawn(async move {
        holder
            .enter_admitted(&carried, move |registry| {
                holds.send(()).expect("the test is waiting");
                withdrawal
                    .recv()
                    .expect("the test says when the connection goes");
                // The registry is still held here, and this is the same check the queued write
                // will make with it. Seeing the admission lapse from inside proves the
                // registration went while the store was held, which is what leaves the waiter
                // still waiting. The bound is so that a daemon that never noticed fails this test
                // rather than holding it up.
                let deadline = std::time::Instant::now() + Duration::from_secs(10);
                while std::time::Instant::now() < deadline {
                    if checking.check_admission(registry, &carried).is_err() {
                        return Ok(true);
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                Ok(false)
            })
            .await
    });
    held.await.expect("the holder has the registry");

    // The waiter calls the guarded write and is driven until it is *in* the wait: one poll, and
    // it answers pending, because the registry it needs is the one the holder has. Nothing here
    // depends on a timer or on a sleep being long enough.
    let queued = AdmittedMutation { ..admission };
    let mut waiting = Box::pin(daemon.controller.enter_admitted(&queued, |_| Ok(())));
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    assert!(
        std::future::Future::poll(waiting.as_mut(), &mut context).is_pending(),
        "the write is queued for the registry rather than done"
    );

    // The connection goes now, with the write inside its wait and the registry still held.
    drop(client);
    withdrawn.send(()).expect("the holder is waiting for this");
    assert!(
        holding
            .await
            .expect("the holder finishes")
            .expect("the holder wrote under an admission that still stood"),
        "the registration went while the holder still had the registry"
    );

    let Err(error) = waiting.await else {
        panic!("a mutation whose registration went while it waited is refused inside the write");
    };
    assert_eq!(
        error.code(),
        ErrorCode::PermissionDenied,
        "refused rather than written: {error}"
    );
}

/// KR-REQ-09.22: a connection that offers to hold no outstanding mutation is refused at this
/// daemon's handshake, as it is at a worker's.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_connection_that_admits_no_mutation_is_refused_by_the_daemon() {
    let daemon = daemon_host().await;
    let connection = kr_ipc::endpoint::Connection::connect(&daemon.endpoint)
        .await
        .expect("connects");
    let (mut reader, mut writer) =
        kr_ipc::framed::split(connection, kr_protocol::frame::StreamKind::Control);
    writer
        .write_message(&ControlFrame::Hello(kr_protocol::local::LocalHello {
            offered_versions: vec![PROTOCOL_VERSION],
            build_id: build(),
            client: LocalClientKind::Cli,
            capabilities: kr_protocol::scalars::CanonicalSet::new(),
            max_receive: kr_protocol::hello::ReceiveLimits {
                max_outstanding_mutations: kr_protocol::scalars::U64::new(0),
                ..kr_protocol::hello::ReceiveLimits::default()
            },
            origin: None,
        }))
        .await
        .expect("writes the hello");
    let frame: ControlFrame = reader.read_message().await.expect("the daemon answers");
    let ControlFrame::Response(response) = frame else {
        panic!("a connection that admits nothing is refused: {frame:?}");
    };
    let Outcome::Error(error) = response.outcome else {
        panic!("a connection that admits nothing is refused");
    };
    assert_eq!(error.code, ErrorCode::InvalidArgument);
}

/// KR-REQ-09.16, KR-REQ-23.24: a retry whose freshness *and* authority have both gone is refused
/// for the authority, rather than answered because the freshness went first.
///
/// Both are gone before the retry is submitted, which is the ordinary case rather than a race: what
/// this proves is the order the admission answers in. A withdrawal that happens *during* a wait is
/// `a_mutation_whose_registration_is_withdrawn_during_the_lock_wait_is_refused_inside_it`.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_retry_whose_authority_also_lapsed_is_refused_rather_than_answered() {
    let hosted = hosted_worker().await;
    let mut client = LocalClient::connect(&hosted.client_endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    let local = actor(&format!("local:{}", kr_ipc::paths::current_uid()));
    let action_id = ActionId::new(kr_ipc::new_uuid());
    let close = MutationRequest {
        request_id: RequestId::new(9),
        method: Method::SessionClose.into(),
        method_version: MethodVersion::V1,
        action_id,
        grant_id: Nullable::null(),
        target: ActionTarget {
            environment_id: hosted.environment_id,
            session_id: Nullable::some(hosted.session_id),
            session_epoch: Nullable::some(SessionEpoch::V1),
            application_instance_id: Nullable::null(),
            agent_binding_revision: Nullable::null(),
        },
        expected: ParamsValue::empty(),
        action_window_id: client.action_window().action_window_id.clone(),
        // No lifetime at all, so the freshness is gone by the time the daemon looks again.
        requested_ttl_ms: DurationMs::new(0),
        params: ParamsValue::from_typed(&kr_protocol::session::SessionCloseParams {
            session_id: hosted.session_id,
        })
        .expect("encodes"),
    };
    // The worker holds this action settled, so the only thing standing between the caller and its
    // receipt is what the daemon decides.
    {
        let digest = kr_protocol::digest::mutation_digest(&close, &local).expect("a digest");
        let subject = kr_protocol::action::subject_digest(&close).expect("a subject");
        let mut session = hosted.runtime.session();
        let journal = session.journal_mut().expect("a journal");
        let now_ms = kr_ipc::now_ms();
        journal
            .accept(&Submission {
                actor_id: local.clone(),
                action_id,
                method: Method::SessionClose.into(),
                method_version: MethodVersion::V1,
                payload_digest: digest,
                subject_digest: subject,
                intent: kr_cbor::to_canonical_vec(&close).expect("encodes"),
                accepted_deadline_ms: Some(TimestampMs::new(now_ms.get() + 120_000)),
                now_ms,
            })
            .expect("an admitted intent");
        journal
            .reject(
                local,
                action_id,
                RejectionReason::StalePreconditions,
                None,
                now_ms,
            )
            .expect("a settled action");
    }

    // The authority this connection was admitted under is withdrawn as well. Both lapsed; the
    // answer is the one nothing can get past.
    hosted
        .controller
        .revoke_authority()
        .await
        .expect("the revocation is recorded");
    let answered = submit(&mut client, close).await;
    let Outcome::Error(error) = answered else {
        panic!("a retry under withdrawn authority is refused: {answered:?}");
    };
    assert_eq!(error.code, ErrorCode::PermissionDenied);
}

/// The guarded write refuses an admission that carries no freshness.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_guarded_write_refuses_an_admission_with_no_freshness() {
    let daemon = daemon_host().await;
    let client = LocalClient::connect(&daemon.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    let connection = client.acknowledgement().connection_id;
    // A retry's admission: it may be answered from what this host already holds, and it may not
    // write. The authority half still stands, which is why the deadline is the only thing absent.
    let retry = AdmittedMutation {
        connection_id: connection,
        admitted_revision: AuthorityRevision::new(1),
        deadline: None,
    };
    let refused = daemon.controller.enter_admitted(&retry, |_| Ok(())).await;
    let Err(error) = refused else {
        panic!("an admission with no freshness may not write");
    };
    assert_eq!(error.code(), ErrorCode::PermissionDenied);
    // And the same admission with a deadline writes, so what refused it was the absence rather
    // than anything else about it.
    let admitted = AdmittedMutation {
        deadline: daemon
            .controller
            .continuous_now()
            .checked_add(Duration::from_secs(120)),
        ..retry
    };
    assert!(
        daemon
            .controller
            .enter_admitted(&admitted, |_| Ok(()))
            .await
            .is_ok()
    );
}

/// The admission contract itself, over every way it can lapse.
#[test]
fn an_admission_carried_into_a_transaction_is_refused_for_each_way_it_can_lapse() {
    let clock = ManualClock::new();
    let admitted = AdmittedMutation {
        connection_id: ConnectionId::new(Uuid::from_bytes([1; 16])),
        admitted_revision: AuthorityRevision::new(3),
        deadline: clock.now().checked_add(Duration::from_secs(120)),
    };
    let context = |revision: u64, registered: bool| AdmissionContext {
        now: clock.now(),
        authority_revision: AuthorityRevision::new(revision),
        registered,
    };
    assert!(admitted.check(context(3, true)).is_ok());
    assert!(
        admitted.check(context(4, true)).is_err(),
        "a revocation during the wait refuses the write"
    );
    assert!(
        admitted.check(context(3, false)).is_err(),
        "a withdrawn registration refuses the write"
    );
    clock.advance(Duration::from_secs(121));
    assert!(
        admitted.check(context(3, true)).is_err(),
        "a deadline that passed during the wait refuses the write"
    );
}

/// KR-REQ-09.16, KR-REQ-23.24: a retry of an action this host may already hold is answered after
/// its window is gone, because a receipt outlives the freshness that admitted it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_retry_reaches_its_retained_answer_after_its_window_stops_admitting_anything() {
    let daemon = daemon_host().await;
    let mut client = LocalClient::connect(&daemon.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    let session_id = SessionId::new(kr_ipc::new_uuid());

    // A session this host closed. Its receipt is the closure record, which is what a retry of the
    // close is owed however long ago the window that admitted the original went.
    {
        let mut registry = Registry::open(&daemon.registry_path, daemon.environment_id)
            .expect("opens the registry beside the daemon");
        registry
            .record_closure(&kr_protocol::session::ClosureRecord {
                session_id,
                session_epoch: SessionEpoch::V1,
                reason: kr_protocol::session::ClosureReason::CloseRequested,
                root_exit_code: Nullable::some(kr_protocol::scalars::U64::new(0)),
                root_signal: Nullable::null(),
                terminated: Vec::new(),
                surviving: Vec::new(),
                ownership_coverage: kr_protocol::session::OwnershipCoverage::Complete,
                durability: kr_protocol::session::Durability::Durable,
                closed_at_ms: kr_ipc::now_ms(),
            })
            .expect("records the closure");
    }

    // A window identifier this host never issued, which is what a retry carries once the original
    // window has expired or its connection has gone.
    let unusable = kr_protocol::ids::ActionWindowId::new("kr-window-this-host-never-issued")
        .expect("a window identifier");
    let close = |window: kr_protocol::ids::ActionWindowId| MutationRequest {
        request_id: RequestId::new(2),
        method: Method::SessionClose.into(),
        method_version: MethodVersion::V1,
        action_id: ActionId::new(kr_ipc::new_uuid()),
        grant_id: Nullable::null(),
        target: ActionTarget {
            environment_id: daemon.environment_id,
            session_id: Nullable::some(session_id),
            session_epoch: Nullable::some(SessionEpoch::V1),
            application_instance_id: Nullable::null(),
            agent_binding_revision: Nullable::null(),
        },
        expected: ParamsValue::empty(),
        action_window_id: window,
        requested_ttl_ms: DurationMs::new(kr_protocol::limits::DEFAULT_MUTATION_TTL.get()),
        params: ParamsValue::from_typed(&kr_protocol::session::SessionCloseParams { session_id })
            .expect("encodes"),
    };
    let outcome = submit(&mut client, close(unusable.clone())).await;
    let Outcome::Ok(value) = outcome else {
        panic!("a retry is answered from what this host holds: {outcome:?}");
    };
    let result: kr_protocol::session::SessionCloseResult =
        value.to_typed().expect("the close result decodes");
    assert_eq!(result.session_id, session_id);
    assert_eq!(result.state, kr_protocol::session::SessionState::Closed);
    assert!(
        result.closure.is_present(),
        "the answer carries the closure this host recorded"
    );

    // The window is still what admits a *new* action. A create presenting the same unusable
    // window is refused, because this daemon holds the retained record for a create itself and a
    // first admission needs freshness.
    let create = MutationRequest {
        request_id: RequestId::new(3),
        method: Method::SessionCreate.into(),
        method_version: MethodVersion::V1,
        action_id: ActionId::new(kr_ipc::new_uuid()),
        grant_id: Nullable::null(),
        target: ActionTarget {
            environment_id: daemon.environment_id,
            session_id: Nullable::null(),
            session_epoch: Nullable::null(),
            application_instance_id: Nullable::null(),
            agent_binding_revision: Nullable::null(),
        },
        expected: ParamsValue::empty(),
        action_window_id: unusable,
        requested_ttl_ms: DurationMs::new(kr_protocol::limits::DEFAULT_MUTATION_TTL.get()),
        params: ParamsValue::from_typed(&SessionCreateParams {
            environment_id: daemon.environment_id,
            presentation: Presentation::Invisible,
            shell: Nullable::null(),
            shell_mode: ShellMode::NativeCompat,
            cwd: Nullable::some("/".to_owned()),
            dimensions: Nullable::null(),
            worker_profile: WorkerProfile::HeadlessUser,
            environment_snapshot: Vec::new(),
            palette: Nullable::null(),
            launch_profile: kr_protocol::session::LaunchProfile::default(),
            terminal: Nullable::null(),
        })
        .expect("encodes"),
    };
    let refused = submit(&mut client, create).await;
    let Outcome::Error(error) = refused else {
        panic!("a window that admits nothing admits no new action: {refused:?}");
    };
    assert_eq!(
        error.code,
        ErrorCode::PermissionDenied,
        "a window that admits nothing is a refusal for a first admission"
    );
    assert_eq!(
        daemon.started.load(std::sync::atomic::Ordering::Acquire),
        0,
        "nothing was asked to start"
    );
}

/// KR-REQ-23.24: a retained action is disclosed under current authority and not otherwise.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_retained_action_is_disclosed_under_current_authority_and_not_under_withdrawn_authority()
{
    let daemon = daemon_host().await;
    let mut client = LocalClient::connect(&daemon.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    let action_id = ActionId::new(kr_ipc::new_uuid());
    let create = |window: kr_protocol::ids::ActionWindowId| MutationRequest {
        request_id: RequestId::new(6),
        method: Method::SessionCreate.into(),
        method_version: MethodVersion::V1,
        action_id,
        grant_id: Nullable::null(),
        target: ActionTarget {
            environment_id: daemon.environment_id,
            session_id: Nullable::null(),
            session_epoch: Nullable::null(),
            application_instance_id: Nullable::null(),
            agent_binding_revision: Nullable::null(),
        },
        expected: ParamsValue::empty(),
        action_window_id: window,
        requested_ttl_ms: DurationMs::new(kr_protocol::limits::DEFAULT_MUTATION_TTL.get()),
        params: ParamsValue::from_typed(&SessionCreateParams {
            environment_id: daemon.environment_id,
            presentation: Presentation::Invisible,
            shell: Nullable::null(),
            shell_mode: ShellMode::NativeCompat,
            cwd: Nullable::some("/".to_owned()),
            dimensions: Nullable::null(),
            worker_profile: WorkerProfile::HeadlessUser,
            environment_snapshot: Vec::new(),
            palette: Nullable::null(),
            launch_profile: kr_protocol::session::LaunchProfile::default(),
            terminal: Nullable::null(),
        })
        .expect("encodes"),
    };

    // The create reserves a session and then fails, because this daemon's supervisor starts
    // nothing. What matters here is that the reservation is retained under this action.
    let window = client.action_window().action_window_id.clone();
    let first = submit(&mut client, create(window.clone())).await;
    assert!(matches!(first, Outcome::Error(_)), "{first:?}");
    let reserved = Registry::open(&daemon.registry_path, daemon.environment_id)
        .expect("opens the registry beside the daemon")
        .reservation_for_token(
            &actor(&format!("local:{}", kr_ipc::paths::current_uid())),
            action_id.get(),
        )
        .expect("reads")
        .expect("the action is retained");
    assert_eq!(reserved.payload_digest.as_bytes().len(), 32);

    // The authority this connection was admitted under is withdrawn. The retained record is still
    // there, and this connection may no longer be told about it.
    daemon
        .controller
        .revoke_authority()
        .await
        .expect("the revocation is recorded");
    let withdrawn = submit(&mut client, create(window.clone())).await;
    let Outcome::Error(error) = withdrawn else {
        panic!("a retained action is not disclosed under withdrawn authority: {withdrawn:?}");
    };
    assert_eq!(error.code, ErrorCode::PermissionDenied);

    // A connection admitted under the authority now in force reads the same retained action. The
    // record survived the revocation; what the revocation withdrew was the connection.
    let mut replacement = LocalClient::connect(&daemon.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects again");
    // The window the original was admitted under, not this connection's own: an exact retry is the
    // same payload, and the window is part of what the digest covers. A retained action is
    // answered before the window is looked at, which is what lets a retry reach its answer at all.
    let again = submit(&mut replacement, create(window)).await;
    let Outcome::Error(error) = again else {
        panic!("this retained action failed, so its retry reports that: {again:?}");
    };
    assert_ne!(
        error.code,
        ErrorCode::PermissionDenied,
        "the retained action is answered rather than refused for authority"
    );
    assert_ne!(
        error.code,
        ErrorCode::IdConflict,
        "the retry is the same payload, so it is a retry rather than a reused identifier"
    );
    assert_eq!(
        daemon.started.load(std::sync::atomic::Ordering::Acquire),
        1,
        "the retry was answered from the retained record rather than started again"
    );
}

/// A real mutation through this daemon's own dispatch path, admitted while its lifetime was live
/// and reaching its transaction after that lifetime had gone.
/// KR-REQ-07.10: a create request expires, and one that has expired starts nothing.
///
/// The daemon measures its deadlines on a clock this test moves. The create is stopped once the
/// daemon has taken it and looked for an earlier answer to it, which is after the daemon has read
/// the time it arrived and before it admits anything; the lifetime runs out there, and the create
/// is then let go. A real delay would have to be long enough for the create to be taken on a
/// loaded machine and short enough to end inside the lifetime, and no length is both. A lifetime
/// that runs out while another task holds the store is
/// `a_mutation_admitted_before_its_deadline_is_refused_when_the_lock_wait_outlasts_it`.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_create_that_queues_past_its_lifetime_is_refused_without_starting_anything() {
    let clock = ManualClock::new();
    let daemon = daemon_host_on(Clocks {
        continuous: Arc::new(clock.clone()),
        wall: WallClock::system(),
    })
    .await;
    let mut client = LocalClient::connect(&daemon.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    // The create is stopped here once the daemon has taken it. A pause the daemon holds, rather
    // than another task's hold on its store, because the create goes through the socket and
    // nothing on this side says when the daemon has read the time it arrived.
    let (arrived, go) = daemon.controller.pause_retained_lookup();

    let create = MutationRequest {
        request_id: RequestId::new(4),
        method: Method::SessionCreate.into(),
        method_version: MethodVersion::V1,
        action_id: ActionId::new(kr_ipc::new_uuid()),
        grant_id: Nullable::null(),
        target: ActionTarget {
            environment_id: daemon.environment_id,
            session_id: Nullable::null(),
            session_epoch: Nullable::null(),
            application_instance_id: Nullable::null(),
            agent_binding_revision: Nullable::null(),
        },
        expected: ParamsValue::empty(),
        action_window_id: client.action_window().action_window_id.clone(),
        requested_ttl_ms: DurationMs::new(300),
        params: ParamsValue::from_typed(&SessionCreateParams {
            environment_id: daemon.environment_id,
            presentation: Presentation::Invisible,
            shell: Nullable::null(),
            shell_mode: ShellMode::NativeCompat,
            cwd: Nullable::some("/".to_owned()),
            dimensions: Nullable::null(),
            worker_profile: WorkerProfile::HeadlessUser,
            environment_snapshot: Vec::new(),
            palette: Nullable::null(),
            launch_profile: kr_protocol::session::LaunchProfile::default(),
            terminal: Nullable::null(),
        })
        .expect("encodes"),
    };
    let creating = tokio::spawn(async move {
        let outcome = submit(&mut client, create).await;
        (client, outcome)
    });
    tokio::time::timeout(Duration::from_secs(30), arrived)
        .await
        .expect("the daemon takes the create")
        .expect("the pause belongs to this daemon");
    // The create arrived with three hundred milliseconds to live, and two seconds pass before the
    // daemon goes on with it.
    clock.advance(Duration::from_secs(2));
    go.send(()).expect("the create is waiting for this");
    let (_client, outcome) = tokio::time::timeout(Duration::from_secs(30), creating)
        .await
        .expect("the daemon answers the create")
        .expect("the creating task finishes");
    let Outcome::Error(error) = outcome else {
        panic!("a create that queued past its lifetime must not start a shell");
    };
    assert_eq!(error.code, ErrorCode::PermissionDenied);
    assert_eq!(
        daemon.started.load(std::sync::atomic::Ordering::Acquire),
        0,
        "nothing was asked to start"
    );
    let registry = Registry::open(&daemon.registry_path, daemon.environment_id)
        .expect("opens the registry beside the daemon");
    assert!(
        registry
            .reservations_in(LaunchPhase::Spawned)
            .expect("reads the spawned reservations")
            .is_empty(),
        "nothing is left recorded as spawned"
    );
    assert_eq!(
        registry
            .reservations_in(LaunchPhase::Failed)
            .expect("reads the failed reservations")
            .len(),
        1,
        "the reservation was written and then failed, rather than never existing"
    );
}

/// A supervisor that starts nothing and reports this process as the worker it started.
///
/// The rendezvous checks the connecting process against the identity the launcher reported, so a
/// test that performs the worker's side of the rendezvous itself reports its own identity here.
/// Nothing is spawned: rule out a second process and what is left is this one.
#[derive(Debug)]
struct RendezvousSupervisor {
    launched: std::sync::Mutex<Option<std::sync::mpsc::Sender<WorkerLaunch>>>,
}

impl WorkerSupervisor for RendezvousSupervisor {
    fn start(&self, launch: &WorkerLaunch) -> LaunchOutcome {
        if let Some(sender) = self
            .launched
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
        {
            let _ = sender.send(launch.clone());
        }
        LaunchOutcome::Started(
            kr_ipc::identity::current_process_start_identity().expect("a process identity"),
        )
    }

    fn describe(&self) -> &'static str {
        "a supervisor that hands the rendezvous to this process"
    }
}

/// One daemon and one worker it really spawned, verified through the real rendezvous.
struct Hosted {
    /// First, so a worker served apart has ended before the temporary tree is removed.
    _apart: Option<ApartWorker>,
    _temp: Arc<kr_ipc::testing::TempHost>,
    controller: Arc<Controller>,
    client_endpoint: kr_ipc::paths::Endpoint,
    endpoint: kr_ipc::paths::Endpoint,
    journal_path: std::path::PathBuf,
    environment_id: EnvironmentId,
    session_id: SessionId,
    runtime: Arc<SessionRuntime>,
    service: Arc<WorkerService>,
}

impl Hosted {
    /// The worker's service, for a test that stops one of its tasks or holds a lock one of them
    /// wants.
    ///
    /// Such a task waits on a thread, and on this test's runtime that thread could be one the
    /// test's own waits need, so a worker whose tasks a test stops is served apart
    /// ([`hosted_worker_apart`]).
    fn service_to_stop(&self) -> &Arc<WorkerService> {
        let _ = self.apart();
        &self.service
    }

    /// The worker's runtimes of its own, which a case that stops its tasks has to name.
    fn apart(&self) -> &ApartWorker {
        self._apart
            .as_ref()
            .expect("a worker whose tasks a test stops is served apart")
    }
}

/// One daemon, and the rendezvous every worker it starts is verified through.
struct HostedDaemon {
    temp: Arc<kr_ipc::testing::TempHost>,
    environment: kr_ipc::paths::EnvironmentPaths,
    environment_id: EnvironmentId,
    controller: Arc<Controller>,
    client_endpoint: kr_ipc::paths::Endpoint,
    rendezvous_endpoint: kr_ipc::paths::Endpoint,
    launches: Arc<std::sync::Mutex<std::sync::mpsc::Receiver<WorkerLaunch>>>,
}

/// Starts a daemon whose supervisor starts nothing and hands this process each launch it is asked
/// for, with the endpoints a client and a worker reach it on.
async fn hosted_daemon() -> HostedDaemon {
    let temp = Arc::new(kr_ipc::testing::TempHost::create());
    let environment = temp.environment();
    let environment_id = temp.environment_id();
    let secrets = environment.secrets_dir();
    let (launched, launches) = std::sync::mpsc::channel::<WorkerLaunch>();
    let controller = Controller::start(ControllerSetup {
        paths: environment.clone(),
        environment_id,
        identity: Box::new(move || {
            let store = open_store_in(&secrets).expect("a secret store for the test environment");
            Ok(
                ControllerIdentity::open(store.store.as_ref(), environment_id, false)
                    .expect("an identity"),
            )
        }),
        secret_store: StoreSelection::File,
        boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
        supervisor: Box::new(RendezvousSupervisor {
            launched: std::sync::Mutex::new(Some(launched)),
        }),
        worker_program: std::path::PathBuf::from("/nonexistent/kr-worker"),
        build_id: build(),
        release: "0".to_owned(),
        shell_packages: None,
        terminal: Box::new(kr_controller::supervision::NoTerminal),
    })
    .await
    .expect("the daemon starts");
    let client_endpoint = environment.controller_endpoint().expect("an endpoint");
    tokio::spawn(
        Arc::clone(&controller)
            .serve_clients(Listener::bind(&client_endpoint).expect("binds the client endpoint")),
    );
    let rendezvous_endpoint = environment.rendezvous_endpoint().expect("an endpoint");
    tokio::spawn(Arc::clone(&controller).serve_rendezvous(
        Listener::bind(&rendezvous_endpoint).expect("binds the rendezvous endpoint"),
    ));
    HostedDaemon {
        temp,
        environment,
        environment_id,
        controller,
        client_endpoint,
        rendezvous_endpoint,
        launches: Arc::new(std::sync::Mutex::new(launches)),
    }
}

/// Starts a daemon, creates a session through it, and performs the worker's side of the
/// rendezvous in this process so the daemon ends up with a verified worker it can announce to.
async fn hosted_worker() -> Hosted {
    add_worker(&hosted_daemon().await, false).await
}

/// As [`hosted_worker`], with the worker's session runtime and connections on runtimes of their
/// own.
///
/// In production the worker is its own process. A test that holds its session for as long as the
/// daemon takes to give up on it (several seconds, each step of the daemon's round bounded) would
/// stop every task of a worker that shares the test's runtime and wants the session, the session's
/// own monitor among them, and a stopped task stops the thread that runs it: the thread that
/// drives that runtime's sockets and timers among others, so that nothing of the daemon moved
/// again. Served apart, the worker's stopped tasks stop only its own threads.
async fn hosted_worker_apart() -> Hosted {
    add_worker(&hosted_daemon().await, true).await
}

/// Creates one more session through `daemon` and performs the worker's side of the rendezvous in
/// this process, so the daemon has one more verified worker it can announce to. The worker's
/// session runtime, and the connections the worker serves, run on this test's runtime, or on
/// runtimes of their own when `apart`.
async fn add_worker(daemon: &HostedDaemon, apart: bool) -> Hosted {
    let environment = daemon.environment.clone();
    let environment_id = daemon.environment_id;
    let client_endpoint = daemon.client_endpoint.clone();
    let rendezvous_endpoint = daemon.rendezvous_endpoint.clone();
    let launches = Arc::clone(&daemon.launches);

    // The create goes on its own task: the daemon answers it only once the worker it started has
    // reported ready, and reporting ready is what this test does next.
    let creating = tokio::spawn({
        let client_endpoint = client_endpoint.clone();
        async move {
            let mut client = LocalClient::connect(&client_endpoint, LocalClientKind::Cli, build())
                .await
                .expect("connects");
            let create = MutationRequest {
                request_id: RequestId::new(1),
                method: Method::SessionCreate.into(),
                method_version: MethodVersion::V1,
                action_id: ActionId::new(kr_ipc::new_uuid()),
                grant_id: Nullable::null(),
                target: ActionTarget {
                    environment_id,
                    session_id: Nullable::null(),
                    session_epoch: Nullable::null(),
                    application_instance_id: Nullable::null(),
                    agent_binding_revision: Nullable::null(),
                },
                expected: ParamsValue::empty(),
                action_window_id: client.action_window().action_window_id.clone(),
                requested_ttl_ms: DurationMs::new(kr_protocol::limits::MAX_MUTATION_TTL.get()),
                params: ParamsValue::from_typed(&SessionCreateParams {
                    environment_id,
                    presentation: Presentation::Invisible,
                    shell: Nullable::null(),
                    shell_mode: ShellMode::NativeCompat,
                    cwd: Nullable::some("/".to_owned()),
                    dimensions: Nullable::null(),
                    worker_profile: WorkerProfile::HeadlessUser,
                    environment_snapshot: Vec::new(),
                    palette: Nullable::null(),
                    launch_profile: kr_protocol::session::LaunchProfile::default(),
                    terminal: Nullable::null(),
                })
                .expect("encodes"),
            };
            submit(&mut client, create).await
        }
    });

    // The launch the daemon asked for. Nothing was started, so this process answers for it.
    let launch = tokio::task::spawn_blocking(move || {
        launches
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .recv_timeout(Duration::from_secs(20))
            .expect("the daemon asks for a worker")
    })
    .await
    .expect("the waiting thread finishes");
    let session_id = launch.session_id;
    let boot = kr_ipc::identity::boot_identity().expect("a boot identity");
    let identity = Arc::new(
        WorkerIdentity::generate(
            session_id,
            SessionEpoch::V1,
            boot.clone(),
            kr_ipc::identity::current_process_start_identity().expect("a process identity"),
            PROTOCOL_VERSION,
        )
        .expect("a session key"),
    );

    let connection = kr_ipc::endpoint::Connection::connect(&rendezvous_endpoint)
        .await
        .expect("connects to the rendezvous");
    let (mut reader, mut writer) =
        kr_ipc::framed::split(connection, kr_protocol::frame::StreamKind::Control);
    writer
        .write_message(&ControlFrame::Hello(kr_protocol::local::LocalHello {
            offered_versions: vec![PROTOCOL_VERSION],
            build_id: build(),
            client: LocalClientKind::Worker,
            capabilities: kr_protocol::scalars::CanonicalSet::new(),
            max_receive: kr_protocol::hello::ReceiveLimits::default(),
            origin: None,
        }))
        .await
        .expect("writes the hello");
    let acknowledgement: ControlFrame = reader.read_message().await.expect("the daemon answers");
    assert!(
        matches!(acknowledgement, ControlFrame::HelloAck(_)),
        "the daemon acknowledges the worker: {acknowledgement:?}"
    );
    writer
        .write_message(&ControlFrame::Rendezvous(
            identity
                .rendezvous(launch.reservation_id)
                .expect("a startup claim"),
        ))
        .await
        .expect("writes the startup claim");
    let specification: ControlFrame = reader.read_message().await.expect("the daemon answers");
    let ControlFrame::LaunchSpec(specification) = specification else {
        panic!("the daemon sends a launch specification: {specification:?}");
    };

    // The session this worker owns, on the endpoint its display number names.
    let journal_path = environment.journal_database(session_id);
    let config = SessionConfig {
        session_id,
        session_epoch: SessionEpoch::V1,
        environment_id,
        display_number: specification.display_number,
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
    let mut session = Session::open(config).expect("opens the session");
    session.launch().expect("launches the shell");
    let endpoint = environment
        .worker_endpoint(specification.display_number)
        .expect("an endpoint");
    let binding = ServiceBinding {
        environment_id,
        boot_identity: boot,
        controller_public_key: specification.controller_public_key,
        controller_generation: specification.controller_generation,
        journal_path: Some(journal_path.clone()),
        build_id: build(),
    };
    let (runtime, service, apart_worker) = if apart {
        // The session's own tasks run on a runtime of their own, apart from the connections: its
        // monitor locks the session each time it wakes, and on this test's runtime, or on the
        // connections', a held session would stop the thread that runs it.
        let (runtime, service, worker) =
            ApartWorker::start(session, Arc::clone(&identity), endpoint.clone(), binding).await;
        (runtime, service, Some(worker))
    } else {
        let runtime = Arc::new(
            SessionRuntime::start(
                session,
                std::sync::Arc::new(kr_ipc::clock::SystemSharedClock),
            )
            .expect("starts the runtime"),
        );
        let service = Arc::new(
            WorkerService::new(
                Arc::clone(&runtime),
                Arc::clone(&identity),
                endpoint.clone(),
                binding,
            )
            .expect("a worker service"),
        );
        let listener = Listener::bind(&endpoint).expect("binds the worker endpoint");
        tokio::spawn(Arc::clone(&service).serve(listener));
        (runtime, service, None)
    };
    let ready = {
        let session = runtime.session();
        kr_protocol::worker::WorkerReady {
            session_id,
            endpoint: endpoint.as_text(),
            root_process: session.root_identity().expect("a root process"),
            shell_path: kr_worker::testing::posix_shell(),
            dimensions: session.geometry().dimensions,
            session: Box::new(session.summary()),
        }
    };
    writer
        .write_message(&ControlFrame::WorkerReady(ready))
        .await
        .expect("reports ready");
    let created = tokio::time::timeout(Duration::from_secs(20), creating)
        .await
        .expect("the daemon answers the create")
        .expect("the creating task finishes");
    assert!(
        matches!(created, Outcome::Ok(_)),
        "the session is created: {created:?}"
    );
    Hosted {
        _apart: apart_worker,
        _temp: Arc::clone(&daemon.temp),
        controller: Arc::clone(&daemon.controller),
        client_endpoint,
        endpoint,
        journal_path,
        environment_id,
        session_id,
        runtime,
        service,
    }
}

/// A worker whose session runtime and connections run apart from this test's runtime, as a worker's
/// do in its own process, and apart from each other. It ends, with its runtimes, when this is
/// dropped.
///
/// The session's own tasks (its monitor among them, which wakes at times no case chooses) run on a
/// runtime of their own, and the service with its connections on another. A case holds the session
/// for seconds, where a worker's process holds it for one operation, and a task that waits for it
/// blocks the thread it runs on. A task made runnable on a thread and then left behind by a task
/// that blocks it waits in that thread's run slot, where no other thread of the runtime takes it
/// from, until the block ends: with the monitor on the connections' runtime, a connection's task
/// could wait there for as long as a hold lasted, and the announcement it was to read would go
/// unread. The service's own tasks that take the session or the boundary still run on the
/// connections' runtime, and a case that holds either holds up the ones it meets.
struct ApartWorker {
    /// The thread that keeps the connections' runtime polling, ended before that runtime is told to
    /// stop.
    awake: Option<Awake>,
    connections: Option<Apart>,
    session: Option<Apart>,
}

/// A runtime on a thread of its own, which runs until this is dropped.
struct Apart {
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Apart {
    /// Starts a runtime of `threads` threads named `name` on a thread of its own, and runs `serve`
    /// on it with that runtime's handle and the end that says it is stopped. `serve` returns when
    /// that end resolves, and the runtime ends after it.
    fn start<F, Fut>(name: &'static str, threads: usize, serve: F) -> Self
    where
        F: FnOnce(tokio::runtime::Handle, tokio::sync::oneshot::Receiver<()>) -> Fut
            + Send
            + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let thread = std::thread::Builder::new()
            .name(name.to_owned())
            .spawn(move || {
                let apart = tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(threads)
                    .thread_name(name)
                    .enable_all()
                    .build()
                    .expect("a runtime for the worker");
                let handle = apart.handle().clone();
                apart.block_on(serve(handle, stopped));
            })
            .expect("a thread for the worker's runtime");
        Self {
            stop: Some(stop),
            thread: Some(thread),
        }
    }

    /// Ends the runtime and waits for it, so the worker is gone when the tree under it is removed;
    /// a runtime that has not ended in ten seconds is left to end on its own.
    fn end(&mut self) {
        drop(self.stop.take());
        if let Some(thread) = self.thread.take() {
            let waiting = std::time::Instant::now();
            while !thread.is_finished() && waiting.elapsed() < Duration::from_secs(10) {
                std::thread::sleep(Duration::from_millis(5));
            }
            if thread.is_finished() {
                let _ = thread.join();
            }
        }
    }
}

impl ApartWorker {
    /// Starts `session`'s runtime on a runtime of its own, and a service for it on another, bound
    /// at `endpoint` before this returns.
    async fn start(
        session: Session,
        identity: Arc<WorkerIdentity>,
        endpoint: kr_ipc::paths::Endpoint,
        binding: ServiceBinding,
    ) -> (Arc<SessionRuntime>, Arc<WorkerService>, Self) {
        let (made, session_made) = tokio::sync::oneshot::channel();
        let session_apart = Apart::start("apart-session", 2, move |_, stopped| async move {
            let runtime = Arc::new(
                SessionRuntime::start(
                    session,
                    std::sync::Arc::new(kr_ipc::clock::SystemSharedClock),
                )
                .expect("starts the runtime"),
            );
            let _ = made.send(Arc::clone(&runtime));
            let _ = stopped.await;
        });
        let runtime = session_made.await.expect("the session starts");

        let (ready, started) = tokio::sync::oneshot::channel();
        let served = Arc::clone(&runtime);
        let connections = Apart::start("apart-worker", 4, move |handle, stopped| async move {
            let service = Arc::new(
                WorkerService::new(served, identity, endpoint.clone(), binding)
                    .expect("a worker service"),
            );
            let listener = Listener::bind(&endpoint).expect("binds the worker endpoint");
            let _ = ready.send((Arc::clone(&service), handle));
            tokio::select! {
                _ = service.serve(listener) => {}
                _ = stopped => {}
            }
        });
        let (service, handle) = started.await.expect("the worker starts");
        (
            runtime,
            service,
            Self {
                awake: Some(Awake::start(handle)),
                connections: Some(connections),
                session: Some(session_apart),
            },
        )
    }
}

/// What keeps a worker's connections' runtime reading its sockets and firing its timers while one
/// of its tasks is stopped: a thread that hands the runtime a task every few milliseconds, for as
/// long as the worker lives.
///
/// A task of that runtime that waits, inside a pause or for a lock, holds a thread of it, as the
/// worker's own process would hold one of its own. When that is the thread that was reading the
/// runtime's sockets and every other thread is asleep, nothing reads a socket or fires a timer
/// until it comes back: the daemon's announcement would sit unread until the daemon's own bound on
/// the exchange ran out, and a case that waits for the worker to refuse it would be waiting for the
/// release it has not yet given. A task handed to the runtime from outside wakes a sleeping thread,
/// which polls the sockets and timers when it goes to sleep again. A task comes every few
/// milliseconds, which is far inside the daemon's exchange bound; a thread of the runtime has to be
/// free to take it.
struct Awake {
    stop: Option<std::sync::mpsc::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Awake {
    fn start(runtime: tokio::runtime::Handle) -> Self {
        let (stop, stopped) = std::sync::mpsc::channel::<()>();
        let thread = std::thread::spawn(move || {
            // Until the sender is dropped.
            while let Err(std::sync::mpsc::RecvTimeoutError::Timeout) =
                stopped.recv_timeout(Duration::from_millis(5))
            {
                drop(runtime.spawn(async {}));
            }
        });
        Self {
            stop: Some(stop),
            thread: Some(thread),
        }
    }
}

impl Drop for Awake {
    fn drop(&mut self) {
        drop(self.stop.take());
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for ApartWorker {
    fn drop(&mut self) {
        drop(self.awake.take());
        // The connections first, so that nothing calls into the session after its own tasks have
        // stopped. Neither side waits for the other, so each end has a bound of its own; a runtime
        // that has not ended by then is left to end on its own, and a thread of it that is waiting
        // for a lock is left waiting until the lock is let go.
        if let Some(connections) = self.connections.as_mut() {
            connections.end();
        }
        if let Some(session) = self.session.as_mut() {
            session.end();
        }
    }
}

/// KR-ACC-022: the whole sequence through this daemon's own revocation path - a worker isolated
/// after its intents were durably accepted, a revocation announced while it cannot answer, the
/// barrier reported pending in the meantime, and no affected undispatched action executed.
///
/// The worker is held for the daemon's whole round, which is as long as the daemon bounds its
/// steps, and the worker's session runtime and connections run on runtimes of their own for it,
/// so that the worker's stopped tasks cannot stop this runtime's threads.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_revocation_through_the_daemon_holds_only_once_the_isolated_worker_has_fenced() {
    let hosted = hosted_worker_apart().await;
    let device = actor("device:phone");
    // An intent this worker accepted durably and never dispatched. That is what a worker holds
    // after it accepted an intent and stopped before its dispatch marker: the serial path writes
    // the marker in the same locked step, so nothing else can leave one behind.
    {
        let mut session = hosted.runtime.session();
        let journal = session.journal_mut().expect("a journal");
        journal
            .accept(&submission(1, &device))
            .expect("an undispatched intent");
    }

    // The worker is isolated. The revocation goes out through the daemon's own path while it
    // cannot answer, and the report says pending for it with the reason. Nothing reads the
    // session while it is held: that is what isolation means here, and the state is read before
    // and after rather than during.
    assert_eq!(hosted.runtime.state().as_str(), "live");
    assert!(
        hosted
            .controller
            .revision_pending()
            .await
            .expect("the daemon reports what is pending")
            .is_empty(),
        "nothing is pending before the revocation"
    );
    let paused = Pause::hold(&hosted.runtime, hosted.apart()).await;
    // The daemon's own round: it records the revocation, announces it to the worker within the
    // bound it gives each step, and reports. The worker is held, so it cannot acknowledge, and the
    // round ends with the worker pending. That report is what the case is about, and it comes when
    // the round ends, not after a time fixed beforehand.
    // The round runs on its own task, and this waits for its report on a blocking thread with a
    // bound of the standard clock: a runtime that stopped could not fire a timer of its own, and
    // the failure is then this case's, with the session released as it unwinds.
    let (reported, report) = std::sync::mpsc::channel();
    tokio::spawn({
        let controller = Arc::clone(&hosted.controller);
        async move {
            let _ = reported.send(controller.revoke_authority().await);
        }
    });
    let first = tokio::task::spawn_blocking(move || report.recv_timeout(Duration::from_secs(120)))
        .await
        .expect("the waiting thread finishes")
        .expect("the revocation reports")
        .expect("the revocation is recorded");
    assert_eq!(
        first.pending(),
        vec![hosted.session_id],
        "a worker that cannot answer is pending rather than complete"
    );
    assert!(!first.holds(), "{first:?}");
    let pending = hosted
        .controller
        .revision_pending()
        .await
        .expect("the daemon reports what is pending");
    assert_eq!(
        pending,
        vec![hosted.session_id],
        "a worker that cannot answer is pending rather than complete"
    );

    // Released. The worker answers, its fence rejects the undispatched intent, and the barrier
    // holds only then.
    paused.release().await;
    let barrier = announced_until(&hosted.controller, first, |barrier| barrier.holds()).await;
    assert_eq!(
        hosted.runtime.state().as_str(),
        "live",
        "nothing was killed to make the revocation complete"
    );
    let reported = barrier
        .workers
        .iter()
        .find(|worker| worker.session_id == hosted.session_id)
        .expect("this worker is in the report");
    assert_eq!(reported.state, BarrierState::Acknowledged);
    assert_eq!(
        reported.rejected_actions,
        vec![fenced(&device, 1)],
        "the fence named the intent it took back, under the actor whose intent it was"
    );
    assert!(
        hosted
            .controller
            .revision_pending()
            .await
            .expect("reads")
            .is_empty(),
        "nothing is pending once the barrier holds"
    );

    // And the affected action produced no effect: no dispatch marker was ever written for it, and
    // its receipt says the revocation rejected it.
    let mut session = hosted.runtime.session();
    let journal = session.journal_mut().expect("a journal");
    let receipt = journal
        .read(device, action(1))
        .expect("reads")
        .expect("a receipt");
    assert_eq!(receipt.state, ReceiptState::Rejected);
    assert_eq!(receipt.reason.as_ref(), Some(&RejectionReason::Revoked));
    assert!(!receipt.state.has_dispatch_marker());
}

/// KR-ACC-022: a mutation that is inside the dispatch boundary when a revocation arrives finishes
/// as one action, and the fence names it rather than taking it back.
///
/// This is the race section 9 warns about - "a paused worker could already be inside a dispatch
/// transition" - and the ordering is what makes it answerable: the fence takes the same serial
/// boundary a dispatch does, so it reads the action either before its marker or after it, never
/// during. Here it is after: the effect happened, and what the revocation can honestly say is that
/// it happened.
///
/// The worker is served apart, as a worker is in production: the mutation stopped inside the
/// boundary stops a thread of the worker's own runtime and none that serves this test.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn an_action_inside_the_dispatch_boundary_is_named_rather_than_taken_back() {
    let hosted = hosted_worker_apart().await;
    let mut client = LocalClient::connect(&hosted.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects to the worker");
    let local = actor(&format!("local:{}", kr_ipc::paths::current_uid()));

    // The worker stops the next mutation it takes the moment it holds the dispatch boundary, so
    // the action is inside the boundary, with nothing else able to enter and nothing else held.
    let (inside, release) = hosted.service_to_stop().pause_inside_boundary();
    let action_id = ActionId::new(kr_ipc::new_uuid());
    let mut requested = kr_protocol::scalars::CanonicalSet::new();
    requested.insert(kr_protocol::attachment::AttachmentCapability::ObserveTerminal);
    let attach = MutationRequest {
        request_id: RequestId::new(8),
        method: Method::SessionAttach.into(),
        method_version: MethodVersion::V1,
        action_id,
        grant_id: Nullable::null(),
        target: ActionTarget {
            environment_id: hosted.environment_id,
            session_id: Nullable::some(hosted.session_id),
            session_epoch: Nullable::some(SessionEpoch::V1),
            application_instance_id: Nullable::null(),
            agent_binding_revision: Nullable::null(),
        },
        expected: ParamsValue::empty(),
        action_window_id: client.action_window().action_window_id.clone(),
        requested_ttl_ms: DurationMs::new(kr_protocol::limits::DEFAULT_MUTATION_TTL.get()),
        params: ParamsValue::from_typed(&kr_protocol::attachment::SessionAttachParams {
            session_id: hosted.session_id,
            mode: kr_protocol::attachment::AttachMode::Terminal,
            claim_geometry: false,
            dimensions: Nullable::some(Dimensions::new(80, 24)),
            terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
            requested,
        })
        .expect("encodes"),
    };
    let attaching = tokio::spawn(async move {
        let answered = submit(&mut client, attach).await;
        (client, answered)
    });
    // The worker says so once the mutation holds the boundary. Until then the revocation below
    // could be the one that takes it, and the case would be about a different order. The pause
    // hands over standard channel ends, so the wait is a blocking call and runs on a blocking
    // thread. The bound only keeps a mutation that never arrives from holding the suite up.
    let arrived =
        tokio::task::spawn_blocking(move || inside.recv_timeout(Duration::from_secs(30)).is_ok())
            .await
            .expect("the waiting thread finishes");
    assert!(arrived, "the mutation never took the dispatch boundary");
    assert!(
        !attaching.is_finished(),
        "the mutation is inside the boundary, stopped there"
    );

    // The revocation is announced while the mutation is in there. It cannot read the journal
    // between the acceptance and the marker, because the fence takes the same boundary, and a
    // worker that cannot take it refuses without waiting. So the daemon's first report comes back
    // while the mutation is still stopped.
    let refused = hosted.service.refusals_for_the_boundary();
    let first = tokio::time::timeout(
        Duration::from_secs(60),
        hosted.controller.revoke_authority(),
    )
    .await
    .expect("the revocation reports")
    .expect("the revocation is recorded");
    // The first report says pending for this worker, and that is the contract rather than a
    // failure: the worker was inside a dispatch transition when the announcement arrived, and
    // section 9 makes a worker that has not answered pending rather than assumed. What it must not
    // say is that the barrier held over an action it had not accounted for. The worker met the
    // boundary the mutation held and refused for it, which is the race this case is about: a report
    // that came back because the daemon's bound on the exchange ran out, with the announcement
    // still unread, would be pending for another reason.
    assert!(
        hosted.service.refusals_for_the_boundary() > refused,
        "the worker did not meet the boundary the mutation held: {first:?}"
    );
    assert_eq!(first.pending(), vec![hosted.session_id], "{first:?}");
    assert!(
        first.workers[0].detail.contains("not complete"),
        "{:?}",
        first.workers[0].detail
    );
    release.send(()).expect("the mutation is waiting for this");

    let (_client, answered) = tokio::time::timeout(Duration::from_secs(30), attaching)
        .await
        .expect("the mutation is answered")
        .expect("the attaching task finishes");
    assert!(
        matches!(answered, Outcome::Ok(_)),
        "the action was admitted before the revocation and it happened: {answered:?}"
    );

    // The effect happened once, and the receipt says so.
    assert_eq!(
        hosted.runtime.session().attachments().len(),
        1,
        "one attachment, not two and not none"
    );
    let receipt = {
        let mut session = hosted.runtime.session();
        let journal = session.journal_mut().expect("a journal");
        journal
            .read(local, action_id)
            .expect("reads")
            .expect("a receipt")
    };
    assert_eq!(receipt.state, ReceiptState::Applied);

    // Announced again until the barrier holds, as a status read does while the fence is owed. What
    // it says about the action is what the receipt says: the fence read it after its marker, so it
    // is named rather than rejected.
    let barrier = announced_until(&hosted.controller, first, |barrier| barrier.holds()).await;
    let reported = barrier
        .workers
        .iter()
        .find(|worker| worker.session_id == hosted.session_id)
        .expect("this worker is in the report");
    let named = reported
        .possibly_executed
        .iter()
        .find(|action| action.action_id == action_id)
        .expect("the action inside the boundary is named");
    assert_eq!(named.state, ReceiptState::Applied);
    assert!(
        !reported
            .rejected_actions
            .iter()
            .any(|rejected| rejected.action_id == action_id),
        "an action past its marker is never taken back"
    );
    assert_eq!(hosted.runtime.state().as_str(), "live");
}

/// KR-ACC-022: an action this host really admitted and never dispatched is taken back by the
/// revocation, and its effect never happens.
///
/// The intent is left where section 9 says a fence finds one: accepted durably, with no dispatch
/// marker. This host writes the marker in the same locked step as the acceptance, so the way to be
/// in that state is for the marker's own write to fail, which is what a full disk or a refusing
/// store does and what this test arranges.
///
/// What this does *not* stage is a dispatcher paused between the acceptance and the marker and
/// resumed afterwards: nothing outside that locked step can interleave with it, so there is no
/// point to pause at. The recovery case - a worker that stopped inside the step and came back - is
/// `a_restart_turns_a_dispatch_marker_without_an_outcome_into_unknown_and_never_redispatches` and
/// `recovery_rejects_an_accepted_intent_and_frees_what_it_held` in the receipts suite.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn an_intent_admitted_and_never_dispatched_is_taken_back_and_never_takes_effect() {
    let hosted = hosted_worker().await;
    let mut client = LocalClient::connect(&hosted.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects to the worker");
    let local = actor(&format!("local:{}", kr_ipc::paths::current_uid()));

    // The store refuses the dispatch marker, and nothing else.
    rusqlite::Connection::open(&hosted.journal_path)
        .expect("the worker's own journal")
        .execute_batch(
            "CREATE TRIGGER refuse_marker BEFORE UPDATE OF state ON receipts
             WHEN new.state = 'dispatching'
             BEGIN SELECT RAISE(ABORT, 'this store refused the write'); END;",
        )
        .expect("the store will refuse the marker");

    let action_id = ActionId::new(kr_ipc::new_uuid());
    let mut requested = kr_protocol::scalars::CanonicalSet::new();
    requested.insert(kr_protocol::attachment::AttachmentCapability::ObserveTerminal);
    let attach = MutationRequest {
        request_id: RequestId::new(10),
        method: Method::SessionAttach.into(),
        method_version: MethodVersion::V1,
        action_id,
        grant_id: Nullable::null(),
        target: ActionTarget {
            environment_id: hosted.environment_id,
            session_id: Nullable::some(hosted.session_id),
            session_epoch: Nullable::some(SessionEpoch::V1),
            application_instance_id: Nullable::null(),
            agent_binding_revision: Nullable::null(),
        },
        expected: ParamsValue::empty(),
        action_window_id: client.action_window().action_window_id.clone(),
        requested_ttl_ms: DurationMs::new(kr_protocol::limits::DEFAULT_MUTATION_TTL.get()),
        params: ParamsValue::from_typed(&kr_protocol::attachment::SessionAttachParams {
            session_id: hosted.session_id,
            mode: kr_protocol::attachment::AttachMode::Terminal,
            claim_geometry: false,
            dimensions: Nullable::some(Dimensions::new(80, 24)),
            terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
            requested,
        })
        .expect("encodes"),
    };
    let refused = submit(&mut client, attach).await;
    assert!(
        matches!(refused, Outcome::Error(_)),
        "the marker could not be written, so the action was not dispatched: {refused:?}"
    );
    {
        let mut session = hosted.runtime.session();
        let journal = session.journal_mut().expect("a journal");
        let receipt = journal
            .read(local.clone(), action_id)
            .expect("reads")
            .expect("the intent was committed");
        assert_eq!(
            receipt.state,
            ReceiptState::Accepted,
            "admitted durably and never dispatched"
        );
        assert!(!receipt.state.has_dispatch_marker());
    }
    assert!(
        hosted.runtime.session().attachments().is_empty(),
        "nothing was dispatched, so nothing happened"
    );
    rusqlite::Connection::open(&hosted.journal_path)
        .expect("the worker's own journal")
        .execute_batch("DROP TRIGGER refuse_marker;")
        .expect("the store accepts writes again");

    // The revocation goes out through the daemon's own path. The fence finds the intent this host
    // admitted and never dispatched, takes it back, and names it.
    let first = hosted
        .controller
        .revoke_authority()
        .await
        .expect("the revocation is recorded");
    let barrier = announced_until(&hosted.controller, first, |barrier| barrier.holds()).await;
    let reported = barrier
        .workers
        .iter()
        .find(|worker| worker.session_id == hosted.session_id)
        .expect("this worker is in the report");
    assert_eq!(
        reported.rejected_actions,
        vec![kr_protocol::action::FencedAction {
            actor_id: local.clone(),
            action_id,
        }],
        "the intent it took back is named under the actor whose intent it was"
    );
    assert!(
        !reported
            .possibly_executed
            .iter()
            .any(|action| action.action_id == action_id),
        "an intent with no marker is taken back rather than named as possibly executed"
    );

    // And the affected action produced no effect: the attachment never existed, the shell is
    // alive, and the receipt says the revocation rejected it.
    assert!(hosted.runtime.session().attachments().is_empty());
    assert_eq!(hosted.runtime.state().as_str(), "live");
    let mut session = hosted.runtime.session();
    let journal = session.journal_mut().expect("a journal");
    let receipt = journal
        .read(local, action_id)
        .expect("reads")
        .expect("a receipt");
    assert_eq!(receipt.state, ReceiptState::Rejected);
    assert_eq!(receipt.reason.as_ref(), Some(&RejectionReason::Revoked));
    assert!(!receipt.state.has_dispatch_marker());
}

/// KR-REQ-09.16, KR-REQ-23.24: a retry the worker answers with a receipt reaches the caller as
/// that receipt, and a deadline that ran out while the retry queued does not stop it.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_retry_the_worker_answers_with_a_receipt_reaches_the_caller_as_one() {
    let hosted = hosted_worker().await;
    let mut client = LocalClient::connect(&hosted.client_endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    let local = actor(&format!("local:{}", kr_ipc::paths::current_uid()));
    let action_id = ActionId::new(kr_ipc::new_uuid());
    let close = MutationRequest {
        request_id: RequestId::new(7),
        method: Method::SessionClose.into(),
        method_version: MethodVersion::V1,
        action_id,
        grant_id: Nullable::null(),
        target: ActionTarget {
            environment_id: hosted.environment_id,
            session_id: Nullable::some(hosted.session_id),
            session_epoch: Nullable::some(SessionEpoch::V1),
            application_instance_id: Nullable::null(),
            agent_binding_revision: Nullable::null(),
        },
        expected: ParamsValue::empty(),
        action_window_id: client.action_window().action_window_id.clone(),
        // A lifetime of nought: the deadline the daemon accepts is the moment it accepts it, so
        // the retry reaches the worker with nothing left of it.
        requested_ttl_ms: DurationMs::new(0),
        params: ParamsValue::from_typed(&kr_protocol::session::SessionCloseParams {
            session_id: hosted.session_id,
        })
        .expect("encodes"),
    };

    // The worker already holds this action, settled without a result: that is what a close refused
    // for its preconditions leaves behind. The digest is the caller's own, computed the way the
    // worker computes it, because a retry is only a retry when the payload is the same.
    {
        let digest = kr_protocol::digest::mutation_digest(&close, &local).expect("a digest");
        let subject = kr_protocol::action::subject_digest(&close).expect("a subject");
        let mut session = hosted.runtime.session();
        let journal = session.journal_mut().expect("a journal");
        let now_ms = kr_ipc::now_ms();
        journal
            .accept(&Submission {
                actor_id: local.clone(),
                action_id,
                method: Method::SessionClose.into(),
                method_version: MethodVersion::V1,
                payload_digest: digest,
                subject_digest: subject,
                intent: kr_cbor::to_canonical_vec(&close).expect("encodes"),
                accepted_deadline_ms: Some(TimestampMs::new(now_ms.get() + 120_000)),
                now_ms,
            })
            .expect("an admitted intent");
        journal
            .reject(
                local.clone(),
                action_id,
                RejectionReason::StalePreconditions,
                None,
                now_ms,
            )
            .expect("a settled action with no result");
    }

    // The retry goes through the daemon. Its freshness is gone, the worker holds the receipt, and
    // what comes back is that receipt rather than a decoding failure or a second close.
    let answered = submit(&mut client, close).await;
    let Outcome::Ok(value) = answered else {
        panic!("a retry is answered from what the worker holds: {answered:?}");
    };
    let reply: kr_protocol::receipt::ReceiptResponse =
        value.to_typed().expect("the receipt decodes");
    assert_eq!(reply.receipt.action_id, action_id);
    assert_eq!(reply.receipt.state, ReceiptState::Rejected);
    assert_eq!(
        reply.receipt.reason.as_ref(),
        Some(&RejectionReason::StalePreconditions)
    );
    assert_eq!(
        hosted.runtime.state().as_str(),
        "live",
        "the retry answered from the record rather than closing anything"
    );
}

/// Accepts `count` intents from `device` that the worker never dispatches, more than one
/// acknowledgement carries when `count` is, so that a fence that takes them back reports them in
/// pages.
fn seed_undispatched_intents(hosted: &Hosted, device: &ActorId, count: usize) {
    let mut session = hosted.runtime.session();
    let journal = session.journal_mut().expect("a journal");
    for index in 0..count {
        let mut bytes = [0_u8; 16];
        bytes[..8].copy_from_slice(&(index as u64 + 1).to_be_bytes());
        let mut submission = submission(1, device);
        submission.action_id = ActionId::new(Uuid::from_bytes(bytes));
        submission.payload_digest =
            Digest256::from_bytes([u8::try_from(index % 251).unwrap_or(0); 32]);
        journal.accept(&submission).expect("an admitted intent");
    }
}

/// The worker's dispatch boundary, held on a thread of its own until the test lets it go: what an
/// announcement meets while a mutation, a generation another link presents or a maintenance pass
/// is inside it.
///
/// The worker is served apart. A task of the worker that wants the boundary while it is held, a
/// generation another link presents or the maintenance pass among them, waits for it on a thread,
/// and on this test's runtime that thread could be one this test's own waits need.
struct HeldBoundary {
    release: Option<std::sync::mpsc::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl HeldBoundary {
    async fn take(hosted: &Hosted) -> Self {
        let (release, wait) = std::sync::mpsc::channel::<()>();
        let (held, confirmed) = tokio::sync::oneshot::channel::<()>();
        let service = Arc::clone(hosted.service_to_stop());
        let thread = std::thread::spawn(move || {
            let _boundary = service.hold_the_dispatch_boundary();
            let _ = held.send(());
            // Held until the test lets it go, or until the test ends without doing so.
            let _ = wait.recv();
        });
        tokio::time::timeout(HOLD_DEADLINE, confirmed)
            .await
            .expect("the boundary was not held in time")
            .expect("the holder ended without holding the boundary");
        Self {
            release: Some(release),
            thread: Some(thread),
        }
    }

    async fn release(mut self) {
        drop(self.release.take());
        if let Some(thread) = self.thread.take() {
            thread.join().expect("the holding thread finishes");
        }
    }
}

/// KR-REQ-09.13: a fence whose evidence does not fit one acknowledgement is delivered in pages,
/// and the revocation's report names every action once the daemon has collected them all.
///
/// A page the worker refuses because its dispatch boundary is held is asked for again by the
/// daemon itself, which the case that holds the boundary between an acknowledgement and its pages
/// shows. This case still announces again itself ([`announced_until`]), because its first
/// announcement can be refused whole, which leaves the worker pending, and so that it decides what
/// the pages carry and not when the daemon next announces.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_revocation_collects_every_name_a_fence_produced_even_across_pages() {
    let hosted = hosted_worker().await;
    let device = actor("device:phone");
    // More intents than one acknowledgement carries, so the answer has to come in pages.
    let affected = kr_protocol::action::MAX_NAMED_FENCED_ACTIONS * 2 + 5;
    seed_undispatched_intents(&hosted, &device, affected);

    let first = hosted
        .controller
        .revoke_authority()
        .await
        .expect("the revocation is recorded");
    let barrier = announced_until(&hosted.controller, first, |barrier| {
        barrier.holds()
            && barrier
                .workers
                .iter()
                .find(|worker| worker.session_id == hosted.session_id)
                .is_some_and(|worker| worker.names_pending.get() == 0)
    })
    .await;
    let reported = barrier
        .workers
        .iter()
        .find(|worker| worker.session_id == hosted.session_id)
        .expect("this worker is in the report");
    assert_eq!(
        reported.rejected_actions.len(),
        affected,
        "every intent the fence took back is named, however many pages it took"
    );
    assert_eq!(reported.omitted_actions.get(), 0);
    assert!(
        reported
            .rejected_actions
            .iter()
            .all(|named| named.actor_id == device),
        "each one is named under the actor whose intent it was"
    );
}

/// A revocation's announcement, stopped once a worker's acknowledgement is recorded and before the
/// pages of evidence that follow it are asked for, with the end that lets it go on.
struct Stopped {
    announcing:
        tokio::task::JoinHandle<kr_controller::Result<kr_protocol::action::RevocationBarrier>>,
    go: tokio::sync::oneshot::Sender<()>,
}

/// Revokes this host's authority and returns the announcement at the stop of the one worker.
///
/// The first announcement may itself be refused whole by whatever else is inside the worker's
/// boundary at that moment, which leaves the worker pending and never reaches the stop: it is
/// announced again until an acknowledgement does.
async fn stopped_after_the_acknowledgement(controller: &Arc<Controller>) -> Stopped {
    let mut revoking = true;
    for _ in 0..50 {
        let (mut arrived, go) = controller.stop_after_an_acknowledgement_for_tests();
        let mut announcing = {
            let controller = Arc::clone(controller);
            tokio::spawn(async move {
                if revoking {
                    controller.revoke_authority().await
                } else {
                    controller.announce_authority_revision().await
                }
            })
        };
        revoking = false;
        tokio::select! {
            reached = &mut arrived => {
                reached.expect("the announcement reached the stop");
                return Stopped { announcing, go };
            }
            finished = &mut announcing => {
                finished
                    .expect("the announcing task finishes")
                    .expect("the revocation is announced");
            }
        }
    }
    panic!("no announcement was acknowledged");
}

/// One worker's part of a revocation's report.
fn worker_report(
    barrier: &kr_protocol::action::RevocationBarrier,
    session_id: SessionId,
) -> &kr_protocol::action::WorkerBarrier {
    barrier
        .workers
        .iter()
        .find(|worker| worker.session_id == session_id)
        .expect("this worker is in the report")
}

/// KR-REQ-09.13: a page of fence evidence that the worker refuses because its dispatch boundary
/// is held is asked for again, so the revocation's report names every action its fence took back
/// without another announcement.
///
/// The announcement is stopped once the worker has acknowledged and before the daemon asks for the
/// pages that follow, and the worker's boundary is taken there: the first page is met with a
/// refusal, which the worker counts. The boundary is let go once it has been refused, and the
/// report has to be whole when the announcement returns.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_page_refused_while_the_worker_is_inside_its_dispatch_boundary_is_asked_for_again() {
    let hosted = hosted_worker_apart().await;
    let device = actor("device:phone");
    let affected = kr_protocol::action::MAX_NAMED_FENCED_ACTIONS * 2 + 5;
    seed_undispatched_intents(&hosted, &device, affected);

    let stopped = stopped_after_the_acknowledgement(&hosted.controller).await;
    let refused = hosted.service.refusals_for_the_boundary();
    let boundary = HeldBoundary::take(&hosted).await;
    stopped
        .go
        .send(())
        .expect("the announcement is waiting at the stop");
    tokio::time::timeout(
        Duration::from_secs(60),
        hosted.service.refused_for_the_boundary_beyond(refused),
    )
    .await
    .expect("the first page is refused while the boundary is held");
    boundary.release().await;

    let barrier = tokio::time::timeout(Duration::from_secs(60), stopped.announcing)
        .await
        .expect("the announcement returns")
        .expect("the announcing task finishes")
        .expect("the revocation is announced");
    assert!(barrier.holds(), "{barrier:?}");
    let reported = worker_report(&barrier, hosted.session_id);
    assert_eq!(
        reported.rejected_actions.len(),
        affected,
        "every intent the fence took back is named by the announcement that was refused a page"
    );
    assert_eq!(reported.names_pending.get(), 0);
    assert_eq!(reported.omitted_actions.get(), 0);
}

/// KR-REQ-09.13: a worker that refuses every page of a fence's evidence is asked for the first of
/// them a bounded number of times, and what it still owes is reported as pending, not waited for.
///
/// The worker's boundary is held from the moment it has acknowledged until the announcement
/// returns, so it refuses every page the daemon asks for: the first ask and the ten retries after
/// it. The report says the barrier holds, names what the acknowledgement carried and counts the
/// rest as pending, and an announcement made after the worker is free names all of it.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_worker_that_refuses_every_page_is_asked_a_bounded_number_of_times_and_its_names_stay_pending()
 {
    let hosted = hosted_worker_apart().await;
    let device = actor("device:phone");
    let affected = kr_protocol::action::MAX_NAMED_FENCED_ACTIONS * 2 + 5;
    seed_undispatched_intents(&hosted, &device, affected);

    let stopped = stopped_after_the_acknowledgement(&hosted.controller).await;
    let refused = hosted.service.refusals_for_the_boundary();
    let boundary = HeldBoundary::take(&hosted).await;
    stopped
        .go
        .send(())
        .expect("the announcement is waiting at the stop");
    // It returns while the worker is still refusing, which is the bound.
    let barrier = tokio::time::timeout(Duration::from_secs(120), stopped.announcing)
        .await
        .expect("the announcement returns although the worker refuses every page")
        .expect("the announcing task finishes")
        .expect("the revocation is announced");
    assert_eq!(
        hosted.service.refusals_for_the_boundary() - refused,
        11,
        "the first ask and ten retries, and no more"
    );
    assert!(barrier.holds(), "{barrier:?}");
    let reported = worker_report(&barrier, hosted.session_id);
    let named = reported.rejected_actions.len();
    assert!(named > 0 && named < affected, "{named} of {affected}");
    assert_eq!(
        reported.names_pending.get(),
        (affected - named) as u64,
        "every name the acknowledgement did not carry is counted as pending"
    );

    boundary.release().await;
    // Announced again until the report is whole: another holder of the boundary can refuse an
    // announcement whole, and what this shows is that a later announcement completes the names.
    let later = announced_until(&hosted.controller, barrier, |barrier| {
        barrier.holds()
            && worker_report(barrier, hosted.session_id)
                .names_pending
                .get()
                == 0
    })
    .await;
    let reported = worker_report(&later, hosted.session_id);
    assert_eq!(reported.rejected_actions.len(), affected);
}

/// KR-REQ-09.13: a page the worker refuses for now uses none of the pages an announcement may
/// collect, so a worker that was busy for a moment is still collected from to the end.
///
/// The announcement may collect two pages after the acknowledgement's, which is what a fence of
/// this many names needs. The worker's boundary is taken before the first of them is asked for and
/// let go once it has been refused, so the announcement asks again, and one that counted the
/// refusal as a page would stop a page short.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_refused_page_uses_none_of_the_pages_an_announcement_may_collect() {
    let hosted = hosted_worker_apart().await;
    hosted.controller.limit_evidence_pages_for_tests(2);
    let device = actor("device:phone");
    let affected = kr_protocol::action::MAX_NAMED_FENCED_ACTIONS * 2 + 5;
    seed_undispatched_intents(&hosted, &device, affected);

    let stopped = stopped_after_the_acknowledgement(&hosted.controller).await;
    let refused = hosted.service.refusals_for_the_boundary();
    let boundary = HeldBoundary::take(&hosted).await;
    stopped
        .go
        .send(())
        .expect("the announcement is waiting at the stop");
    tokio::time::timeout(
        Duration::from_secs(60),
        hosted.service.refused_for_the_boundary_beyond(refused),
    )
    .await
    .expect("the first page is refused while the boundary is held");
    boundary.release().await;

    let barrier = tokio::time::timeout(Duration::from_secs(60), stopped.announcing)
        .await
        .expect("the announcement returns")
        .expect("the announcing task finishes")
        .expect("the revocation is announced");
    let reported = worker_report(&barrier, hosted.session_id);
    assert_eq!(reported.rejected_actions.len(), affected);
    assert_eq!(reported.names_pending.get(), 0);
}

/// KR-REQ-09.13: an announcement asks every worker for its acknowledgement before it asks any
/// worker for a page of evidence, so a worker that keeps refusing its pages, and is asked again for
/// seconds, holds up no other worker's acknowledgement.
///
/// Two workers on one daemon, each with a fence of more than one page. The daemon records each
/// announcement as it sends it, before any worker has read it: an acknowledgement asks from nought
/// and a page asks from where the last one ended, so an announcement in which an acknowledgement
/// follows a page asked one worker for its page before it had asked the other for its
/// acknowledgement. What is decided is the order of what the daemon asks and not what a worker
/// answers, so it holds whatever refuses, times out or is slow at the moment: that only changes how
/// many announcements it takes. Each announcement is checked, and the announcements go on until
/// every name is collected and one of them has asked every worker for both its acknowledgement and
/// a page. A daemon that asked for a worker's pages as soon as that worker had acknowledged would
/// put one worker's page before the other's acknowledgement in that announcement, so the case
/// cannot end without meeting the order it is there to refuse.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn an_announcement_asks_every_worker_for_its_acknowledgement_before_it_asks_for_any_page() {
    let daemon = hosted_daemon().await;
    let hosts = [
        add_worker(&daemon, false).await,
        add_worker(&daemon, false).await,
    ];
    let device = actor("device:phone");
    let affected = kr_protocol::action::MAX_NAMED_FENCED_ACTIONS * 2 + 5;
    for hosted in &hosts {
        seed_undispatched_intents(hosted, &device, affected);
    }

    let deadline = tokio::time::Instant::now() + Duration::from_secs(180);
    let mut asked_everyone_both = false;
    let mut last_report = String::from("none");
    let mut announcements = 0;
    let barrier = loop {
        assert!(
            tokio::time::Instant::now() < deadline,
            "before the case's three minutes ran out ({announcements} announcements made) the \
             names were not all collected, the barrier did not hold, or no announcement asked \
             every worker for both an acknowledgement and a page (asked: {asked_everyone_both}); \
             the last report: {last_report}"
        );
        let before = daemon.controller.announcements_sent_for_tests().len();
        let announced = if announcements == 0 {
            tokio::time::timeout_at(deadline, daemon.controller.revoke_authority()).await
        } else {
            tokio::time::timeout_at(deadline, daemon.controller.announce_authority_revision()).await
        };
        announcements += 1;
        let barrier = announced
            .unwrap_or_else(|_| {
                panic!("announcement {announcements} did not end before the case's time ran out")
            })
            .expect("the revocation is announced");
        let sent = daemon.controller.announcements_sent_for_tests()[before..].to_vec();
        let mut paged = false;
        for announcement in &sent {
            if announcement.evidence_from > 0 {
                paged = true;
            } else {
                assert!(
                    !paged,
                    "announcement {announcements} asked for a page of evidence before it asked \
                     every worker for its acknowledgement: {sent:?}"
                );
            }
        }
        // An announcement that asked every worker for both its acknowledgement and a page. A daemon
        // that collected a worker's pages as soon as it had acknowledged would have asked the first
        // worker for its page before it asked the second for its acknowledgement, whichever worker
        // answers in time.
        asked_everyone_both |= hosts.iter().all(|hosted| {
            let own = sent
                .iter()
                .filter(|each| each.session_id == hosted.session_id);
            own.clone().any(|each| each.evidence_from == 0)
                && own.clone().any(|each| each.evidence_from > 0)
        });
        let collected = hosts.iter().all(|hosted| {
            let reported = worker_report(&barrier, hosted.session_id);
            reported.names_pending.get() == 0 && reported.rejected_actions.len() == affected
        });
        if barrier.holds() && collected && asked_everyone_both {
            break barrier;
        }
        last_report = format!("{barrier:?}");
    };
    for hosted in &hosts {
        assert_eq!(
            worker_report(&barrier, hosted.session_id)
                .omitted_actions
                .get(),
            0
        );
    }
}

/// Writes one mutation to this daemon and returns what it answered.
async fn submit(client: &mut LocalClient, mutation: MutationRequest) -> Outcome {
    client
        .writer()
        .write_message(&ControlFrame::Mutation(Box::new(mutation)))
        .await
        .expect("writes the mutation");
    loop {
        match client.recv().await.expect("the daemon answers") {
            ControlFrame::Response(response) => return response.outcome,
            ControlFrame::Notification(_) | ControlFrame::Event(_) => {}
            other => panic!("the daemon answered {other:?}"),
        }
    }
}

/// The evidence one fence pass reported, as a barrier records it: complete in one page.
fn evidence(
    rejected: Vec<ActionId>,
    possibly_executed: Vec<kr_protocol::action::PossiblyExecutedAction>,
) -> Option<kr_protocol::action::FenceEvidence> {
    let device = actor("device:phone");
    Some(kr_protocol::action::FenceEvidence {
        rejected_actions: rejected
            .into_iter()
            .map(|action_id| kr_protocol::action::FencedAction {
                actor_id: device.clone(),
                action_id,
            })
            .collect(),
        possibly_executed,
        remaining: kr_protocol::scalars::U64::new(0),
        omitted: kr_protocol::scalars::U64::new(0),
    })
}

/// Presents one startup claim on the daemon's rendezvous endpoint, the way a launched worker does,
/// and returns the launch specification it is given, if any, with the connection it arrived on.
async fn present_claim(
    endpoint: &kr_ipc::paths::Endpoint,
    claim: kr_protocol::worker::WorkerRendezvous,
) -> (
    Option<Box<kr_protocol::worker::WorkerLaunchSpec>>,
    kr_ipc::framed::FrameReader,
    kr_ipc::framed::FrameWriter,
) {
    let connection = kr_ipc::endpoint::Connection::connect(endpoint)
        .await
        .expect("connects to the rendezvous");
    let (mut reader, mut writer) =
        kr_ipc::framed::split(connection, kr_protocol::frame::StreamKind::Control);
    writer
        .write_message(&ControlFrame::Hello(kr_protocol::local::LocalHello {
            offered_versions: vec![PROTOCOL_VERSION],
            build_id: build(),
            client: LocalClientKind::Worker,
            capabilities: kr_protocol::scalars::CanonicalSet::new(),
            max_receive: kr_protocol::hello::ReceiveLimits::default(),
            origin: None,
        }))
        .await
        .expect("writes the hello");
    let acknowledgement: ControlFrame = reader.read_message().await.expect("the daemon answers");
    assert!(
        matches!(acknowledgement, ControlFrame::HelloAck(_)),
        "the daemon acknowledges a worker: {acknowledgement:?}"
    );
    writer
        .write_message(&ControlFrame::Rendezvous(claim))
        .await
        .expect("writes the startup claim");
    let answer = tokio::time::timeout(
        Duration::from_secs(20),
        reader.read_message::<ControlFrame>(),
    )
    .await
    .expect("the daemon answers or closes the exchange");
    let specification = match answer {
        Ok(ControlFrame::LaunchSpec(specification)) => Some(specification),
        _ => None,
    };
    (specification, reader, writer)
}

/// KR-REQ-07.08: the private startup exchange binds a launched worker to its own reservation. A
/// claim on that reservation from a worker of another session is refused before any launch
/// specification is given; the worker the reservation was made for is given the specification of
/// exactly its own session; and a second claim on the reservation while that one holds it is
/// refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_startup_exchange_binds_a_worker_to_its_own_reservation() {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let environment_id = temp.environment_id();
    let secrets = environment.secrets_dir();
    let (launched, launches) = std::sync::mpsc::channel::<WorkerLaunch>();
    let controller = Controller::start(ControllerSetup {
        paths: environment.clone(),
        environment_id,
        identity: Box::new(move || {
            let store = open_store_in(&secrets).expect("a secret store for the test environment");
            Ok(
                ControllerIdentity::open(store.store.as_ref(), environment_id, false)
                    .expect("an identity"),
            )
        }),
        secret_store: StoreSelection::File,
        boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
        supervisor: Box::new(RendezvousSupervisor {
            launched: std::sync::Mutex::new(Some(launched)),
        }),
        worker_program: std::path::PathBuf::from("/nonexistent/kr-worker"),
        build_id: build(),
        release: "0".to_owned(),
        shell_packages: None,
        terminal: Box::new(kr_controller::supervision::NoTerminal),
    })
    .await
    .expect("the daemon starts");
    let client_endpoint = environment.controller_endpoint().expect("an endpoint");
    tokio::spawn(
        Arc::clone(&controller)
            .serve_clients(Listener::bind(&client_endpoint).expect("binds the client endpoint")),
    );
    let rendezvous = environment.rendezvous_endpoint().expect("an endpoint");
    tokio::spawn(
        Arc::clone(&controller)
            .serve_rendezvous(Listener::bind(&rendezvous).expect("binds the rendezvous endpoint")),
    );

    // A create, on a task of its own: the daemon answers it only once a worker reports ready, and
    // no worker here ever does.
    let creating = tokio::spawn({
        let client_endpoint = client_endpoint.clone();
        async move {
            let mut client = LocalClient::connect(&client_endpoint, LocalClientKind::Cli, build())
                .await
                .expect("connects");
            client
                .mutate(
                    Method::SessionCreate,
                    ActionId::new(kr_ipc::new_uuid()),
                    ActionTarget {
                        environment_id,
                        session_id: Nullable::null(),
                        session_epoch: Nullable::null(),
                        application_instance_id: Nullable::null(),
                        agent_binding_revision: Nullable::null(),
                    },
                    &SessionCreateParams {
                        environment_id,
                        presentation: Presentation::Invisible,
                        shell: Nullable::null(),
                        shell_mode: ShellMode::NativeCompat,
                        cwd: Nullable::some("/".to_owned()),
                        dimensions: Nullable::null(),
                        worker_profile: WorkerProfile::HeadlessUser,
                        environment_snapshot: Vec::new(),
                        palette: Nullable::null(),
                        launch_profile: kr_protocol::session::LaunchProfile::default(),
                        terminal: Nullable::null(),
                    },
                )
                .await
        }
    });
    let launch = tokio::task::spawn_blocking(move || {
        launches
            .recv_timeout(Duration::from_secs(20))
            .expect("the daemon asks for a worker")
    })
    .await
    .expect("the waiting thread finishes");
    let boot = kr_ipc::identity::boot_identity().expect("a boot identity");
    let process = kr_ipc::identity::current_process_start_identity().expect("a process identity");
    let worker_for = |session_id: SessionId| {
        WorkerIdentity::generate(
            session_id,
            SessionEpoch::V1,
            boot.clone(),
            process.clone(),
            PROTOCOL_VERSION,
        )
        .expect("a session key")
    };

    // A worker of another session claiming this reservation is given nothing.
    let stranger = worker_for(SessionId::new(kr_ipc::new_uuid()));
    let (refused, _, _) = present_claim(
        &rendezvous,
        stranger
            .rendezvous(launch.reservation_id)
            .expect("a startup claim"),
    )
    .await;
    assert!(
        refused.is_none(),
        "a claim naming another session is not given a launch specification"
    );

    // The worker the reservation was made for is given its own session's specification, and
    // keeps its exchange open.
    let own = worker_for(launch.session_id);
    let (specification, _held_reader, _held_writer) = present_claim(
        &rendezvous,
        own.rendezvous(launch.reservation_id)
            .expect("a startup claim"),
    )
    .await;
    let specification = specification.expect("the reservation's own worker is given its launch");
    assert_eq!(specification.session_id, launch.session_id);
    assert_eq!(specification.environment_id, environment_id);
    assert_eq!(specification.display_number, launch.display_number);

    // A second claim on the same reservation is refused, whoever makes it.
    let (again, _, _) = present_claim(
        &rendezvous,
        worker_for(launch.session_id)
            .rendezvous(launch.reservation_id)
            .expect("a startup claim"),
    )
    .await;
    assert!(
        again.is_none(),
        "a reservation already claimed is not given a second launch"
    );
    creating.abort();
}
