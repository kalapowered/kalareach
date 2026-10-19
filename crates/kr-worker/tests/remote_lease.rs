//! The remote dispatch lease at the worker (section 9).
//!
//! A mutation the control daemon forwards for a paired device is dispatched only under a live lease
//! from the current controller generation and authority revision, valid for five seconds at most,
//! which the worker checks in its serial path immediately before the dispatch marker. Renewal
//! reaches the worker only after the worker has acknowledged the revision, and a replacement
//! generation cannot adopt what its predecessor queued. A local caller's forwarded action and a
//! device's `session.close` do not depend on the lease.
//!
//! Every case here goes through the real endpoint, the real handshake and the real signatures: a
//! check that holds only when called directly is not a check.

use std::sync::Arc;
use std::time::Duration;

use kr_ipc::client::{BoundLink, Client, Codec};
use kr_ipc::endpoint::Listener;
use kr_ipc::verify::{ControllerIdentity, WorkerIdentity};
use kr_protocol::actor::{ActorEnvelope, ActorIngress};
use kr_protocol::attachment::{AttachMode, AttachmentCapability, SessionAttachParams};
use kr_protocol::envelope::{ActionTarget, ControlFrame, MutationRequest, Outcome, ParamsValue};
use kr_protocol::error::ErrorCode;
use kr_protocol::hello::PROTOCOL_VERSION;
use kr_protocol::identity::{DesktopBinding, WorkerProfile};
use kr_protocol::ids::{
    ActionId, ActionWindowId, ActorId, AuthorityRevision, BuildId, ConnectionId,
    ControllerGeneration, DeviceId, GrantId, RemoteDispatchLeaseId, RequestId, SessionEpoch,
    SessionId,
};
use kr_protocol::local::{ControllerConnectionRole, ForwardedLease, ForwardedMutation};
use kr_protocol::method::{Method, MethodVersion};
use kr_protocol::receipt::{ReceiptState, RejectionReason};
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{CanonicalSet, DurationMs, Nullable, U64, Uuid};
use kr_protocol::session::{Dimensions, DisplayNumber, ShellMode};
use kr_protocol::worker::{AuthorityRevisionNotice, RevisionReach};
use kr_transport::clock::{ContinuousClock, ManualClock};
use kr_worker::runtime::SessionRuntime;
use kr_worker::service::{ServiceBinding, WorkerService};
use kr_worker::session::{Session, SessionConfig};

/// How long a test waits for something it waits for by condition, and fails after. Nothing is
/// decided by it.
const WAIT: Duration = Duration::from_secs(60);

/// What the accepted deadline of the frames below is: far past anything a lease allows, so that
/// what refuses a lapsed lease is the lease and not the deadline.
const TWO_MINUTES_MS: u64 = 120_000;

struct Host {
    _temp: kr_ipc::testing::TempHost,
    service: Arc<WorkerService>,
    session_id: SessionId,
    endpoint: kr_ipc::paths::Endpoint,
    controller: Arc<ControllerIdentity>,
    boot: kr_protocol::identity::BootIdentity,
    environment_id: kr_protocol::ids::EnvironmentId,
}

fn build() -> BuildId {
    BuildId::new("kr-test/0").expect("a build identifier")
}

/// A worker that accepted generation 1 when it was started, on the machine's clocks.
async fn host() -> Host {
    host_on(None).await
}

/// A worker whose deadlines are measured on `clock`, which the test moves by hand.
async fn host_on(clock: Option<Arc<dyn ContinuousClock>>) -> Host {
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
    let journal_path = config.journal_path.clone();
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
    let mut service = WorkerService::new(
        Arc::clone(&runtime),
        identity,
        endpoint.clone(),
        ServiceBinding {
            environment_id,
            boot_identity: boot.clone(),
            controller_public_key: *controller.public_key(),
            controller_generation: ControllerGeneration::new(1),
            journal_path,
            build_id: build(),
        },
    )
    .expect("a worker service");
    if let Some(clock) = clock {
        service = service.on_clock(clock);
    }
    let service = Arc::new(service);
    tokio::spawn(Arc::clone(&service).serve(listener));
    Host {
        _temp: temp,
        service,
        session_id,
        endpoint,
        controller,
        boot,
        environment_id,
    }
}

/// A connection of the control daemon's of `generation`, declaring `role` first when it has one:
/// the daemon's authority connection declares none, and the link that carries a device declares a
/// proxy.
async fn link(host: &Host, generation: u64, role: Option<ControllerConnectionRole>) -> BoundLink {
    let mut client = BoundLink::connect(&host.endpoint, build())
        .await
        .expect("connects");
    if let Some(role) = role {
        client
            .send(&ControlFrame::ControllerRole(role))
            .await
            .expect("declares the role");
        match client.recv().await.expect("the worker answers") {
            ControlFrame::ControllerRole(declared) => assert_eq!(declared, role),
            other => panic!("the worker answered {other:?}"),
        }
    }
    let identity = Arc::clone(&host.controller);
    let boot = host.boot.clone();
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

async fn proxy(host: &Host, generation: u64) -> BoundLink {
    link(host, generation, Some(ControllerConnectionRole::Proxy)).await
}

fn notice(host: &Host, revision: u64) -> AuthorityRevisionNotice {
    AuthorityRevisionNotice {
        environment_id: host.environment_id,
        revision: AuthorityRevision::new(revision),
        reach: RevisionReach::Host,
        evidence_from: 0,
    }
}

/// The daemon's announcement of `revision` over its authority connection, which the worker
/// acknowledges.
async fn announce(authority: &mut BoundLink, host: &Host, revision: u64) {
    let acknowledged = authority
        .announce_revision(notice(host, revision))
        .await
        .expect("the worker acknowledges the revision");
    assert_eq!(acknowledged.revision.get(), revision);
}

fn boot_now_ms() -> u64 {
    kr_ipc::clock::boot_elapsed_ms()
}

/// A lease of `generation` and `revision` that ends `ms` from now on the machine's clock.
fn lease(generation: u64, revision: u64, ms: u64) -> ForwardedLease {
    ForwardedLease {
        lease_id: RemoteDispatchLeaseId::new(kr_ipc::new_uuid()),
        controller_generation: ControllerGeneration::new(generation),
        authority_revision: AuthorityRevision::new(revision),
        deadline_boot_ms: U64::new(boot_now_ms() + ms),
    }
}

fn actor() -> ActorId {
    ActorId::new("device:lease-test").expect("a principal")
}

fn target(host: &Host) -> ActionTarget {
    ActionTarget {
        environment_id: host.environment_id,
        session_id: Nullable::some(host.session_id),
        session_epoch: Nullable::some(SessionEpoch::V1),
        application_instance_id: Nullable::null(),
        agent_binding_revision: Nullable::null(),
    }
}

/// A `session.attach`, a mutation with an effect a test can see: an attachment, or none.
fn attach(host: &Host) -> MutationRequest {
    let mut requested = CanonicalSet::new();
    requested.insert(AttachmentCapability::ObserveTerminal);
    MutationRequest {
        request_id: RequestId::new(1),
        method: Method::SessionAttach.into(),
        method_version: MethodVersion::V1,
        action_id: ActionId::new(kr_ipc::new_uuid()),
        grant_id: Nullable::null(),
        target: target(host),
        expected: ParamsValue::empty(),
        action_window_id: ActionWindowId::new("forwarded").expect("a window identifier"),
        requested_ttl_ms: DurationMs::new(TWO_MINUTES_MS),
        params: ParamsValue::from_typed(&SessionAttachParams {
            session_id: host.session_id,
            mode: AttachMode::Terminal,
            claim_geometry: false,
            dimensions: Nullable::some(Dimensions::new(80, 24)),
            terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
            requested,
        })
        .expect("encodes"),
    }
}

/// A `session.close`.
fn close(host: &Host) -> MutationRequest {
    MutationRequest {
        method: Method::SessionClose.into(),
        params: ParamsValue::from_typed(&kr_protocol::session::SessionCloseParams {
            session_id: host.session_id,
        })
        .expect("encodes"),
        ..attach(host)
    }
}

/// What the daemon forwards for a paired device: the mutation under an envelope of `generation`
/// that was validated at `revision`, the lease it took (when it took one), and an accepted deadline
/// two minutes out.
fn for_a_device(
    mutation: &MutationRequest,
    generation: u64,
    revision: u64,
    lease: Option<ForwardedLease>,
) -> ControlFrame {
    forwarded(
        mutation,
        ActorIngress::PairedDevice,
        generation,
        revision,
        lease,
    )
}

fn forwarded(
    mutation: &MutationRequest,
    ingress: ActorIngress,
    generation: u64,
    revision: u64,
    lease: Option<ForwardedLease>,
) -> ControlFrame {
    let device = ingress == ActorIngress::PairedDevice;
    ControlFrame::Forwarded(Box::new(ForwardedMutation {
        mutation: mutation.clone(),
        actor: ActorEnvelope {
            actor_id: if device {
                actor()
            } else {
                ActorId::new("local:501").expect("a principal")
            },
            ingress,
            device_id: if device {
                Nullable::some(DeviceId::new(Uuid::from_bytes([9; 16])))
            } else {
                Nullable::null()
            },
            grant_id: if device {
                Nullable::some(GrantId::new(Uuid::from_bytes([8; 16])))
            } else {
                Nullable::null()
            },
            grant_revision: if device {
                Nullable::some(AuthorityRevision::new(revision))
            } else {
                Nullable::null()
            },
            controller_generation: ControllerGeneration::new(generation),
            connection_id: ConnectionId::new(Uuid::from_bytes([7; 16])),
        },
        grant_rights: if device {
            [ActionRight::SessionView].into_iter().collect()
        } else {
            CanonicalSet::new()
        },
        accepted_deadline_boot_ms: U64::new(boot_now_ms() + TWO_MINUTES_MS),
        history: None,
        screen_basis: None,
        lease,
    }))
}

/// What the worker answers `frame` with, whichever kind of response it is.
async fn answer_to(client: &mut Client<impl Codec>, frame: ControlFrame) -> Outcome {
    client.send(&frame).await.expect("writes the frame");
    loop {
        let received = tokio::time::timeout(WAIT, client.recv())
            .await
            .expect("the worker answers in time")
            .expect("the worker answers");
        match received {
            ControlFrame::Response(response) => return response.outcome,
            ControlFrame::RetainedResponse(response) => return response.outcome,
            ControlFrame::Notification(_) | ControlFrame::Event(_) => {}
            other => panic!("the worker answered {other:?}"),
        }
    }
}

/// What the journal holds of an action of the device's.
fn receipt_of(host: &Host, mutation: &MutationRequest) -> kr_protocol::receipt::Receipt {
    let mut session = host.service.runtime().session();
    session
        .journal_mut()
        .expect("a journal")
        .read(actor(), mutation.action_id)
        .expect("reads")
        .expect("the action has a receipt")
}

/// Asserts that this action was dispatched.
#[track_caller]
fn dispatched(host: &Host, mutation: &MutationRequest, outcome: &Outcome) {
    assert!(matches!(outcome, Outcome::Ok(_)), "{outcome:?}");
    let receipt = receipt_of(host, mutation);
    assert_eq!(receipt.state, ReceiptState::Applied, "{receipt:?}");
}

/// Asserts that this action was refused, and that it was rejected before it had a dispatch marker
/// for `reason`.
#[track_caller]
fn refused(host: &Host, mutation: &MutationRequest, outcome: &Outcome, reason: RejectionReason) {
    let Outcome::Error(error) = outcome else {
        panic!("the dispatch was refused, not {outcome:?}");
    };
    assert_eq!(error.code, ErrorCode::PermissionDenied, "{error:?}");
    let receipt = receipt_of(host, mutation);
    assert_eq!(receipt.state, ReceiptState::Rejected, "{receipt:?}");
    assert_eq!(receipt.reason.as_ref(), Some(&reason), "{receipt:?}");
    assert!(!receipt.state.has_dispatch_marker());
}

/// Holds the worker's dispatch boundary on a thread of its own until it is released.
struct HeldBoundary {
    release: Option<std::sync::mpsc::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl HeldBoundary {
    async fn take(host: &Host) -> Self {
        let (release, wait) = std::sync::mpsc::channel::<()>();
        let (held, confirmed) = tokio::sync::oneshot::channel::<()>();
        let service = Arc::clone(&host.service);
        let thread = std::thread::spawn(move || {
            let _boundary = service.hold_the_dispatch_boundary();
            let _ = held.send(());
            let _ = wait.recv();
        });
        tokio::time::timeout(WAIT, confirmed)
            .await
            .expect("the boundary is held in time")
            .expect("the holder ended without holding the boundary");
        Self {
            release: Some(release),
            thread: Some(thread),
        }
    }

    fn release(mut self) {
        drop(self.release.take());
        if let Some(thread) = self.thread.take() {
            thread.join().expect("the holding thread finishes");
        }
    }
}

/// KR-REQ-09.10: a remote dispatch the worker cannot match to a live lease is rejected before its
/// dispatch marker, and one it can is dispatched.
///
/// The lease has to be there, name the generation the connection proved and the envelope speaks
/// for, name the revision the worker acknowledged to that generation, and name the revision it has
/// installed. The last two are two facts: an owed fence installs a revision with no
/// acknowledgement, and the next announcement of it acknowledges what is installed.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_remote_dispatch_the_worker_cannot_match_to_a_live_lease_is_rejected_before_its_marker() {
    let host = host().await;
    let mut authority = link(&host, 1, None).await;
    let mut device = proxy(&host, 1).await;
    announce(&mut authority, &host, 3).await;

    // A lease of the generation and revision the worker acknowledged is a dispatch.
    let matching = attach(&host);
    let answered = answer_to(
        &mut device,
        for_a_device(&matching, 1, 3, Some(lease(1, 3, 4_000))),
    )
    .await;
    dispatched(&host, &matching, &answered);

    // Each of these is a refusal, and none leaves a dispatch marker.
    let lacking = attach(&host);
    let answered = answer_to(&mut device, for_a_device(&lacking, 1, 3, None)).await;
    refused(&host, &lacking, &answered, RejectionReason::Revoked);

    let another_generation = attach(&host);
    let answered = answer_to(
        &mut device,
        for_a_device(&another_generation, 1, 3, Some(lease(2, 3, 4_000))),
    )
    .await;
    refused(
        &host,
        &another_generation,
        &answered,
        RejectionReason::Revoked,
    );

    let adopted = attach(&host);
    let answered = answer_to(
        &mut device,
        for_a_device(&adopted, 2, 3, Some(lease(1, 3, 4_000))),
    )
    .await;
    refused(&host, &adopted, &answered, RejectionReason::Revoked);

    // An announcement the worker had to refuse for its dispatch boundary leaves a revision owed,
    // and the worker's own maintenance installs it with nothing acknowledged. The acknowledged
    // revision is still the earlier one, so a lease for it is for a revision that is not installed.
    let boundary = HeldBoundary::take(&host).await;
    authority
        .announce_revision(notice(&host, 4))
        .await
        .expect_err("the worker is inside a dispatch transition");
    boundary.release();
    host.service.fence_what_is_owed_for_tests();

    let acknowledged_and_not_installed = attach(&host);
    let answered = answer_to(
        &mut device,
        for_a_device(
            &acknowledged_and_not_installed,
            1,
            4,
            Some(lease(1, 3, 4_000)),
        ),
    )
    .await;
    refused(
        &host,
        &acknowledged_and_not_installed,
        &answered,
        RejectionReason::Revoked,
    );

    // And a lease for the installed revision is for one that nothing has acknowledged.
    let installed_and_not_acknowledged = attach(&host);
    let answered = answer_to(
        &mut device,
        for_a_device(
            &installed_and_not_acknowledged,
            1,
            4,
            Some(lease(1, 4, 4_000)),
        ),
    )
    .await;
    refused(
        &host,
        &installed_and_not_acknowledged,
        &answered,
        RejectionReason::Revoked,
    );

    // The next announcement of it acknowledges what is installed, and the lease is honoured.
    announce(&mut authority, &host, 4).await;
    let renewed = attach(&host);
    let answered = answer_to(
        &mut device,
        for_a_device(&renewed, 1, 4, Some(lease(1, 4, 4_000))),
    )
    .await;
    dispatched(&host, &renewed, &answered);

    // A retry of an action that was dispatched is answered from its receipt, with or without a
    // lease that is still good: a receipt outlives the authority that admitted it.
    let again = answer_to(&mut device, for_a_device(&matching, 1, 4, None)).await;
    assert!(matches!(again, Outcome::Ok(_)), "{again:?}");
    assert_eq!(receipt_of(&host, &matching).state, ReceiptState::Applied);
}

/// KR-REQ-09.10: renewal reaches the worker only after the worker has acknowledged the revision,
/// the acknowledgement is of the highest revision it was told, and a lease of an older revision is
/// no lease once a newer one is installed.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn renewal_waits_for_the_workers_acknowledgement_and_never_goes_backwards() {
    let host = host().await;
    let mut authority = link(&host, 1, None).await;
    let mut device = proxy(&host, 1).await;

    // The race the contract names: a lease for a revision the worker has not been told of.
    let early = attach(&host);
    let answered = answer_to(
        &mut device,
        for_a_device(&early, 1, 3, Some(lease(1, 3, 4_000))),
    )
    .await;
    refused(&host, &early, &answered, RejectionReason::Revoked);

    announce(&mut authority, &host, 3).await;
    let first = attach(&host);
    let answered = answer_to(
        &mut device,
        for_a_device(&first, 1, 3, Some(lease(1, 3, 4_000))),
    )
    .await;
    dispatched(&host, &first, &answered);

    // A newer revision is installed and acknowledged: the lease of the one before is refused and
    // one of the new revision is dispatched.
    announce(&mut authority, &host, 4).await;
    let behind = attach(&host);
    let answered = answer_to(
        &mut device,
        for_a_device(&behind, 1, 4, Some(lease(1, 3, 4_000))),
    )
    .await;
    refused(&host, &behind, &answered, RejectionReason::Revoked);
    let second = attach(&host);
    let answered = answer_to(
        &mut device,
        for_a_device(&second, 1, 4, Some(lease(1, 4, 4_000))),
    )
    .await;
    dispatched(&host, &second, &answered);

    // The daemon asks for the older revisions' evidence after the newer one is acknowledged. The
    // worker answers; what it has acknowledged does not move back, so the lease of the newest
    // revision is still honoured.
    announce(&mut authority, &host, 3).await;
    let after = attach(&host);
    let answered = answer_to(
        &mut device,
        for_a_device(&after, 1, 4, Some(lease(1, 4, 4_000))),
    )
    .await;
    dispatched(&host, &after, &answered);
}

/// KR-REQ-09.10: a remote action queued under one generation is refused after a replacement
/// advances it, and a replacement cannot adopt an envelope its predecessor queued: its lease and
/// its envelope speak for the generation the worker no longer accepts, and the replacement's own
/// are honoured only once the worker has acknowledged to it.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_remote_action_queued_under_one_generation_is_refused_after_a_replacement_advances_it() {
    let host = host().await;
    let mut first_authority = link(&host, 1, None).await;
    let mut first_device = proxy(&host, 1).await;
    announce(&mut first_authority, &host, 3).await;

    // The generation that was in force dispatches under its lease.
    let before = attach(&host);
    let answered = answer_to(
        &mut first_device,
        for_a_device(&before, 1, 3, Some(lease(1, 3, 4_000))),
    )
    .await;
    dispatched(&host, &before, &answered);

    // What the first generation had queued: an envelope of generation 1 with its lease.
    let queued = attach(&host);
    let old = for_a_device(&queued, 1, 3, Some(lease(1, 3, 4_000)));

    // A replacement takes the worker's authority.
    let mut second_authority = link(&host, 2, None).await;
    let mut second_device = proxy(&host, 2).await;

    // The old generation's own link is fenced, so what it queued does not reach a marker.
    let answered = answer_to(&mut first_device, old.clone()).await;
    assert!(matches!(answered, Outcome::Error(_)), "{answered:?}");

    // And the replacement cannot send the queued envelope on as its own.
    let answered = answer_to(&mut second_device, old).await;
    refused(&host, &queued, &answered, RejectionReason::Revoked);

    // Its own envelope and lease are not honoured before the worker has acknowledged anything to
    // it...
    let unacknowledged = attach(&host);
    let answered = answer_to(
        &mut second_device,
        for_a_device(&unacknowledged, 2, 3, Some(lease(2, 3, 4_000))),
    )
    .await;
    refused(&host, &unacknowledged, &answered, RejectionReason::Revoked);

    // ...and are once it has.
    announce(&mut second_authority, &host, 3).await;
    let own = attach(&host);
    let answered = answer_to(
        &mut second_device,
        for_a_device(&own, 2, 3, Some(lease(2, 3, 4_000))),
    )
    .await;
    dispatched(&host, &own, &answered);
}

/// What a dispatch with a lease that ends `lease_ms` after it reaches the worker comes to when the
/// worker's clock has moved `moved` by the time the dispatch boundary lets it go: the frame is held
/// inside the boundary, after the worker has measured what is left of its deadlines on its own
/// clock, so the move is what the lapse is.
async fn dispatched_after(
    host: &Host,
    clock: &ManualClock,
    authority: &mut BoundLink,
    lease_ms: u64,
    moved: Duration,
) -> (MutationRequest, Outcome) {
    announce(authority, host, 3).await;
    let mut device = proxy(host, 1).await;
    let (inside, release) = host.service.pause_inside_boundary();
    let mutation = attach(host);
    let frame = for_a_device(&mutation, 1, 3, Some(lease(1, 3, lease_ms)));
    let answering = tokio::spawn(async move {
        let outcome = answer_to(&mut device, frame).await;
        (device, outcome)
    });
    assert!(
        tokio::task::spawn_blocking(move || inside.recv_timeout(WAIT).is_ok())
            .await
            .expect("the wait ends"),
        "the dispatch reached the boundary"
    );
    clock.advance(moved);
    release.send(()).expect("the dispatch is waiting to go on");
    let (_device, outcome) = answering.await.expect("the dispatch ends");
    (mutation, outcome)
}

/// KR-REQ-09.10: the worker holds a lease to what it names and to five seconds, measured on its own
/// clock inside the dispatch boundary, whatever the accepted deadline still allows.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_lease_is_held_to_what_it_names_and_to_five_seconds_inside_the_boundary() {
    let clock = ManualClock::new();

    // A lease of two seconds is spent after three.
    {
        let host = host_on(Some(Arc::new(clock.clone()))).await;
        let mut authority = link(&host, 1, None).await;
        let (mutation, outcome) =
            dispatched_after(&host, &clock, &mut authority, 2_000, Duration::from_secs(3)).await;
        refused(&host, &mutation, &outcome, RejectionReason::Expired);
    }
    // A lease that names ten minutes is held to five seconds, and is spent after six.
    {
        let host = host_on(Some(Arc::new(clock.clone()))).await;
        let mut authority = link(&host, 1, None).await;
        let (mutation, outcome) = dispatched_after(
            &host,
            &clock,
            &mut authority,
            600_000,
            Duration::from_secs(6),
        )
        .await;
        refused(&host, &mutation, &outcome, RejectionReason::Expired);
    }
    // The same lease, two seconds on, is still good: the five seconds is not a shorter bound.
    {
        let host = host_on(Some(Arc::new(clock.clone()))).await;
        let mut authority = link(&host, 1, None).await;
        let (mutation, outcome) = dispatched_after(
            &host,
            &clock,
            &mut authority,
            600_000,
            Duration::from_secs(2),
        )
        .await;
        dispatched(&host, &mutation, &outcome);
    }
}

/// KR-REQ-09.11: what is local, and stopping what is owned, does not depend on the lease. With
/// nothing acknowledged and no lease a local caller's forwarded mutation is dispatched, and so is a
/// paired device's `session.close`.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_local_forwarded_action_and_a_devices_stop_need_no_lease() {
    let host = host().await;
    let mut daemon = link(&host, 1, None).await;
    let mut device = proxy(&host, 1).await;

    let local = attach(&host);
    let answered = answer_to(
        &mut daemon,
        forwarded(&local, ActorIngress::LocalIpc, 1, 0, None),
    )
    .await;
    assert!(matches!(answered, Outcome::Ok(_)), "{answered:?}");

    let stop = close(&host);
    let answered = answer_to(&mut device, for_a_device(&stop, 1, 0, None)).await;
    assert!(matches!(answered, Outcome::Ok(_)), "{answered:?}");
    tokio::time::timeout(WAIT, host.service.runtime().wait_closed())
        .await
        .expect("the closure finishes");
}
