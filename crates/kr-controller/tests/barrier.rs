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
use kr_controller::registry::{LaunchPhase, Registry};
use kr_controller::service::{Controller, ControllerSetup};
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
use kr_worker::pty::ShellCommand;
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
    _temp: kr_ipc::testing::TempHost,
    runtime: Arc<SessionRuntime>,
    service: Arc<WorkerService>,
    session_id: SessionId,
    endpoint: kr_ipc::paths::Endpoint,
    controller: Arc<ControllerIdentity>,
    boot: kr_protocol::identity::BootIdentity,
    environment_id: EnvironmentId,
}

async fn worker() -> Worker {
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
        shell: ShellCommand {
            program: "/bin/sh".to_owned(),
            // A root program that outlives the suite and ends with its terminal, so a test that
            // takes a minute does not find the session closed because its shell ran out.
            arguments: vec!["-c".to_owned(), "exec cat".to_owned()],
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
    let mut session = Session::open(config).expect("opens the session");
    session.launch().expect("launches the shell");
    let runtime = Arc::new(
        SessionRuntime::start(
            session,
            std::sync::Arc::new(kr_ipc::clock::SystemSharedClock),
        )
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
                journal_path: Some(environment.journal_database(session_id)),
                build_id: build(),
            },
        )
        .expect("a worker service"),
    );
    tokio::spawn(Arc::clone(&service).serve(listener));
    Worker {
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
/// It runs on a blocking thread rather than in the test, because the lock is not reentrant and a
/// test that held it could not then ask the worker anything. While it is held the worker cannot
/// reach its journal, so it cannot install an authority revision: an announcement that arrives
/// stops inside the worker's own revocation handler, which is precisely the case section 9 warns
/// about, a paused worker that could already be inside a dispatch transition.
struct Pause {
    release: Option<std::sync::mpsc::Sender<()>>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl Pause {
    async fn hold(runtime: &Arc<SessionRuntime>) -> Self {
        let (release, wait) = std::sync::mpsc::channel::<()>();
        let (held, confirmed) = std::sync::mpsc::channel::<()>();
        let runtime = Arc::clone(runtime);
        let task = tokio::task::spawn_blocking(move || {
            let _session = runtime.session();
            held.send(()).expect("the test is waiting");
            // Held until the test releases it. The receiver ends when the sender is dropped, so a
            // test that panics does not leave the worker locked for the rest of the suite.
            let _ = wait.recv();
        });
        confirmed.recv().expect("the session is held");
        Self {
            release: Some(release),
            task: Some(task),
        }
    }

    async fn release(mut self) {
        drop(self.release.take());
        if let Some(task) = self.task.take() {
            task.await.expect("the holding thread finishes");
        }
    }
}

/// KR-REQ-09.12, KR-REQ-09.13, KR-ACC-022: the revocation reports `pending` while the worker is
/// isolated, holds when the worker acknowledges, names what may already have been dispatched, and
/// kills nothing.
///
/// The thread count is deliberate. In production the worker is its own process; here it shares this
/// runtime, so isolating it blocks every one of its tasks that wants the session, and a runtime
/// with only a handful of threads would starve the test that is doing the isolating. Sixteen is
/// comfortably more than the worker's tasks plus its connections.
#[tokio::test(flavor = "multi_thread", worker_threads = 16)]
async fn a_revocation_is_pending_while_a_worker_is_isolated_and_holds_when_it_resumes() {
    let worker = worker().await;
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
            .report(AuthorityRevision::new(3), [worker.session_id])
            .holds()
    );
    assert_eq!(worker.runtime.state().as_str(), "live");

    // The worker is isolated after its intents were durably accepted.
    let paused = Pause::hold(&worker.runtime).await;
    barrier.revoke(AuthorityRevision::new(4));

    // The revocation is announced while the worker is isolated. The exchange is kept alive on its
    // own task, because the worker will answer it once it is released and the answer is the
    // acknowledgement this barrier waits for.
    let announcement = notice(&worker, 4);
    let announcing = tokio::spawn(async move {
        let ack = client.announce_revision(announcement).await;
        (client, ack)
    });

    // Long enough for the announcement to reach the worker and stop inside its handler. The wait
    // is on a blocking thread rather than a timer: the worker shares this runtime, and every one
    // of its tasks that wants the session is stopped while the session is held, so a timer this
    // runtime has to fire is not something to depend on here.
    tokio::task::spawn_blocking(|| std::thread::sleep(Duration::from_millis(300)))
        .await
        .expect("the waiting thread finishes");
    assert!(
        !announcing.is_finished(),
        "the isolated worker cannot acknowledge the revision"
    );
    let pending = barrier.report(AuthorityRevision::new(4), [worker.session_id]);
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
    let complete = barrier.report(AuthorityRevision::new(4), [worker.session_id]);
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
    let pending = barrier.report(AuthorityRevision::new(4), [worker.session_id]);
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
    // process identities. This records the verdict; `Controller::announce_authority_revision` is
    // where the verdict is reached, and it calls this only after `reconcile` has established that
    // the worker is gone.
    barrier.worker_ended(worker.session_id);
    let complete = barrier.report(AuthorityRevision::new(4), [worker.session_id]);
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
// The admission a mutation carries into its transaction (lead decision D-030)
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

    fn describe(&self) -> String {
        "a supervisor that counts what it was asked to start".to_owned()
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
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let environment_id = temp.environment_id();
    let secrets = environment.secrets_dir();
    let registry_path = environment.registry_database();
    let started = Arc::new(std::sync::atomic::AtomicUsize::new(0));
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
        supervisor: Box::new(CountingSupervisor {
            started: Arc::clone(&started),
        }),
        worker_program: std::path::PathBuf::from("/nonexistent/kr-worker"),
        build_id: build(),
        release: "0".to_owned(),
    })
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

/// Lead decision D-030: a mutation admitted while its lifetime was live, and reaching its store
/// transaction after that lifetime ran out, is refused inside the transaction.
///
/// The contention is real: one task holds the daemon's registry lock while the other's admission
/// expires waiting for it. That is the case a check before the wait cannot catch, because before
/// the wait the admission still stood.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_mutation_admitted_before_its_deadline_is_refused_when_the_lock_wait_outlasts_it() {
    let daemon = daemon_host().await;
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

    // One task holds the registry for two seconds; the other's admission expires inside its wait.
    let holder = Arc::clone(&daemon.controller);
    let held = AdmittedMutation { ..live };
    let holding = tokio::spawn(async move {
        holder
            .enter_admitted(&held, |_| {
                // A blocking sleep inside the closure, because the closure is what holds the lock
                // and nothing is awaited inside it.
                std::thread::sleep(Duration::from_secs(2));
                Ok(())
            })
            .await
    });
    tokio::task::spawn_blocking(|| std::thread::sleep(Duration::from_millis(100)))
        .await
        .expect("the waiting thread finishes");

    let waited = daemon.controller.enter_admitted(&live, |_| Ok(())).await;
    assert!(
        holding.await.expect("the holder finishes").is_ok(),
        "the task that got there first wrote under an admission that still stood"
    );
    let Err(error) = waited else {
        panic!("a mutation whose lifetime ran out while it waited is refused inside the write");
    };
    assert_eq!(
        error.code(),
        ErrorCode::PermissionDenied,
        "refused rather than written: {error}"
    );
}

/// Lead decision D-030: the same, for a revocation that lands while the mutation waits.
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

/// Lead decision D-030: the registration half, withdrawn *during* the wait rather than before it.
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

/// Lead decision D-030: the guarded write refuses an admission that carries no freshness.
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

/// Lead decision D-030: a real mutation through this daemon's own dispatch path, admitted while
/// its lifetime was live and reaching its transaction after another holder released the lock.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_create_that_queues_past_its_lifetime_is_refused_without_starting_anything() {
    let daemon = daemon_host().await;
    let mut client = LocalClient::connect(&daemon.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects");
    let connection = client.acknowledgement().connection_id;

    // Another holder takes this daemon's store for a second and a half. The create below is
    // admitted with three hundred milliseconds to live, so its own transaction is reached after
    // its lifetime has gone: the case a check before the wait cannot catch.
    let holder = Arc::clone(&daemon.controller);
    let held = AdmittedMutation {
        connection_id: connection,
        admitted_revision: AuthorityRevision::new(1),
        deadline: daemon
            .controller
            .continuous_now()
            .checked_add(Duration::from_secs(120)),
    };
    let holding = tokio::spawn(async move {
        holder
            .enter_admitted(&held, |_| {
                std::thread::sleep(Duration::from_millis(1_500));
                Ok(())
            })
            .await
    });
    tokio::task::spawn_blocking(|| std::thread::sleep(Duration::from_millis(100)))
        .await
        .expect("the waiting thread finishes");

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
        })
        .expect("encodes"),
    };
    let outcome = submit(&mut client, create).await;
    assert!(
        holding.await.expect("the holder finishes").is_ok(),
        "the task that got there first wrote under an admission that still stood"
    );
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

    fn describe(&self) -> String {
        "a supervisor that hands the rendezvous to this process".to_owned()
    }
}

/// One daemon and one worker it really spawned, verified through the real rendezvous.
struct Hosted {
    _temp: kr_ipc::testing::TempHost,
    controller: Arc<Controller>,
    client_endpoint: kr_ipc::paths::Endpoint,
    endpoint: kr_ipc::paths::Endpoint,
    journal_path: std::path::PathBuf,
    environment_id: EnvironmentId,
    session_id: SessionId,
    runtime: Arc<SessionRuntime>,
    _service: Arc<WorkerService>,
}

/// Starts a daemon, creates a session through it, and performs the worker's side of the
/// rendezvous in this process so the daemon ends up with a verified worker it can announce to.
async fn hosted_worker() -> Hosted {
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
                })
                .expect("encodes"),
            };
            submit(&mut client, create).await
        }
    });

    // The launch the daemon asked for. Nothing was started, so this process answers for it.
    let launch = tokio::task::spawn_blocking(move || {
        launches
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
        shell: ShellCommand {
            program: "/bin/sh".to_owned(),
            arguments: vec!["-c".to_owned(), "exec cat".to_owned()],
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
    let mut session = Session::open(config).expect("opens the session");
    session.launch().expect("launches the shell");
    let runtime = Arc::new(
        SessionRuntime::start(
            session,
            std::sync::Arc::new(kr_ipc::clock::SystemSharedClock),
        )
        .expect("starts the runtime"),
    );
    let endpoint = environment
        .worker_endpoint(specification.display_number)
        .expect("an endpoint");
    let listener = Listener::bind(&endpoint).expect("binds the worker endpoint");
    let service = Arc::new(
        WorkerService::new(
            Arc::clone(&runtime),
            Arc::clone(&identity),
            endpoint.clone(),
            ServiceBinding {
                environment_id,
                boot_identity: boot,
                controller_public_key: specification.controller_public_key,
                controller_generation: specification.controller_generation,
                journal_path: Some(journal_path.clone()),
                build_id: build(),
            },
        )
        .expect("a worker service"),
    );
    tokio::spawn(Arc::clone(&service).serve(listener));
    let ready = {
        let session = runtime.session();
        kr_protocol::worker::WorkerReady {
            session_id,
            endpoint: endpoint.as_text(),
            root_process: session.root_identity().expect("a root process"),
            shell_path: "/bin/sh".to_owned(),
            dimensions: session.geometry().dimensions,
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
        _temp: temp,
        controller,
        client_endpoint,
        endpoint,
        journal_path,
        environment_id,
        session_id,
        runtime,
        _service: service,
    }
}

/// KR-ACC-022: the whole sequence through this daemon's own revocation path - a worker isolated
/// after its intents were durably accepted, a revocation announced while it cannot answer, the
/// barrier reported pending in the meantime, and no affected undispatched action executed.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_revocation_through_the_daemon_holds_only_once_the_isolated_worker_has_fenced() {
    let hosted = hosted_worker().await;
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
    let paused = Pause::hold(&hosted.runtime).await;
    let revoking = tokio::spawn({
        let controller = Arc::clone(&hosted.controller);
        async move { controller.revoke_authority().await }
    });
    tokio::task::spawn_blocking(|| std::thread::sleep(Duration::from_millis(300)))
        .await
        .expect("the waiting thread finishes");
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
    eprintln!("marker: the mutation answered");
    let barrier = tokio::time::timeout(Duration::from_secs(30), revoking)
        .await
        .expect("the revocation reports")
        .expect("the revoking task finishes")
        .expect("the revocation is recorded");
    assert!(barrier.holds(), "{barrier:?}");
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
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn an_action_inside_the_dispatch_boundary_is_named_rather_than_taken_back() {
    let hosted = hosted_worker().await;
    let mut client = LocalClient::connect(&hosted.endpoint, LocalClientKind::Cli, build())
        .await
        .expect("connects to the worker");
    let local = actor(&format!("local:{}", kr_ipc::paths::current_uid()));

    // The session is held, so the mutation below takes the dispatch boundary and then waits for
    // it. That is the pause: the action is inside the boundary, with nothing else able to enter.
    let paused = Pause::hold(&hosted.runtime).await;
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
    tokio::task::spawn_blocking(|| std::thread::sleep(Duration::from_millis(300)))
        .await
        .expect("the waiting thread finishes");
    assert!(
        !attaching.is_finished(),
        "the mutation is inside the boundary, waiting for the session"
    );

    // The revocation is announced while the mutation is in there. It cannot read the journal
    // between the acceptance and the marker, because the fence takes the same boundary.
    let revoking = tokio::spawn({
        let controller = Arc::clone(&hosted.controller);
        async move { controller.revoke_authority().await }
    });
    tokio::task::spawn_blocking(|| std::thread::sleep(Duration::from_millis(300)))
        .await
        .expect("the waiting thread finishes");
    paused.release().await;

    let (_client, answered) = tokio::time::timeout(Duration::from_secs(30), attaching)
        .await
        .expect("the mutation is answered")
        .expect("the attaching task finishes");
    assert!(
        matches!(answered, Outcome::Ok(_)),
        "the action was admitted before the revocation and it happened: {answered:?}"
    );
    let first = tokio::time::timeout(Duration::from_secs(60), revoking)
        .await
        .expect("the revocation reports")
        .expect("the revoking task finishes")
        .expect("the revocation is recorded");
    // The first report says pending for this worker, and that is the contract rather than a
    // failure: the worker was inside a dispatch transition when the announcement arrived, and
    // section 9 makes a worker that has not answered pending rather than assumed. What it must not
    // say is that the barrier held over an action it had not accounted for.
    assert_eq!(first.pending(), vec![hosted.session_id], "{first:?}");
    assert!(
        first.workers[0].detail.contains("not complete"),
        "{:?}",
        first.workers[0].detail
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

    // Announced again, which is what a daemon does for a worker it reported pending. The barrier
    // holds now, and what it says about the action is what the receipt says: the fence read it
    // after its marker, so it is named rather than rejected.
    let barrier = hosted
        .controller
        .announce_authority_revision()
        .await
        .expect("the revocation is announced again");
    assert!(barrier.holds(), "{barrier:?}");
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
    let barrier = hosted
        .controller
        .revoke_authority()
        .await
        .expect("the revocation is recorded");
    assert!(barrier.holds(), "{barrier:?}");
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

/// KR-REQ-09.13: a fence whose evidence does not fit one acknowledgement is delivered in pages,
/// and the revocation's report names every action.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_revocation_collects_every_name_a_fence_produced_even_across_pages() {
    let hosted = hosted_worker().await;
    let device = actor("device:phone");
    // More intents than one acknowledgement carries, so the answer has to come in pages.
    let affected = kr_protocol::action::MAX_NAMED_FENCED_ACTIONS * 2 + 5;
    {
        let mut session = hosted.runtime.session();
        let journal = session.journal_mut().expect("a journal");
        for index in 0..affected {
            let mut bytes = [0_u8; 16];
            bytes[..8].copy_from_slice(&(index as u64 + 1).to_be_bytes());
            let mut submission = submission(1, &device);
            submission.action_id = ActionId::new(Uuid::from_bytes(bytes));
            submission.payload_digest =
                Digest256::from_bytes([u8::try_from(index % 251).unwrap_or(0); 32]);
            journal.accept(&submission).expect("an admitted intent");
        }
    }

    let barrier = hosted
        .controller
        .revoke_authority()
        .await
        .expect("the revocation is recorded");
    assert!(barrier.holds(), "{:?}", barrier.pending());
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
