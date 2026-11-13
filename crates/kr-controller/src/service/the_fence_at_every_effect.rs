//! What the local door asks again where a retained answer goes back and where a mutation lands.
//!
//! A mutation is admitted under a fence this host owes, a registration and a deadline, and each
//! of the places it waits can outlast them. These tests drive the local door's own entry points
//! and read back what each left: an answer a retry was or was not given, and what was written.

use std::sync::Arc;
use std::time::Duration;

use kr_ipc::peer::PeerIdentity;
use kr_protocol::envelope::{ActionTarget, ControlFrame, MutationRequest, Outcome, ParamsValue};
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{ActionId, ActionWindowId, ActorId, ConnectionId, RequestId};
use kr_protocol::method::{Method, MethodVersion};
use kr_protocol::privacy::PrivacySetParams;
use kr_protocol::scalars::{DurationMs, Nullable};
use kr_transport::clock::ManualClock;
use kr_transport::window::{AcceptedDeadline, DeadlineBound};

use crate::service::{Clocks, Controller, WallClock};

/// How long a deadline a test hands a mutation lasts, on the clock the test moves.
const STANDING: Duration = Duration::from_secs(60);

/// A daemon on a tree of its own, on a continuous clock the test moves, with a supervisor that
/// starts nothing.
pub(super) async fn daemon() -> (kr_ipc::testing::TempHost, Arc<Controller>, ManualClock) {
    let temp = kr_ipc::testing::TempHost::create();
    let clock = ManualClock::new();
    let controller = Controller::start_on_clocks(
        super::a_floor_owed_its_record::setup(&temp),
        Clocks {
            continuous: Arc::new(clock.clone()),
            wall: WallClock::system(),
        },
    )
    .await
    .expect("the daemon starts");
    (temp, controller, clock)
}

/// Registers one connection, the way a caller's handshake does.
pub(super) async fn admitted(controller: &Controller) -> (ConnectionId, ActorId) {
    let connection_id = ConnectionId::new(kr_ipc::new_uuid());
    let actor_id = ActorId::new("local:test").expect("a principal");
    controller
        .admit_connection(
            connection_id,
            &actor_id,
            &PeerIdentity {
                uid: kr_ipc::paths::current_uid(),
                gid: 0,
                pid: None,
            },
            kr_protocol::local::LocalClientKind::Cli,
        )
        .await
        .expect("the connection is registered");
    (connection_id, actor_id)
}

/// A mutation that sets privacy mode to `enabled`, under a fresh action identifier.
fn privacy_request(temp: &kr_ipc::testing::TempHost, enabled: bool) -> MutationRequest {
    MutationRequest {
        request_id: RequestId::new(1),
        method: Method::PrivacySet.into(),
        method_version: MethodVersion::V1,
        action_id: ActionId::new(kr_ipc::new_uuid()),
        grant_id: Nullable::null(),
        target: ActionTarget::environment(temp.environment_id()),
        expected: ParamsValue::empty(),
        action_window_id: ActionWindowId::new("local:test").expect("a window"),
        requested_ttl_ms: DurationMs::new(30_000),
        params: ParamsValue::from_typed(&PrivacySetParams { enabled }).expect("encodes"),
    }
}

/// The deadline a first admission of a mutation carries in these tests.
pub(super) fn accepted(controller: &Controller) -> AcceptedDeadline {
    AcceptedDeadline {
        deadline: controller
            .clock
            .now()
            .checked_add(STANDING)
            .expect("a deadline"),
        bound: DeadlineBound::RequestedTtl,
    }
}

/// Performs one mutation for the first time and returns the connection it arrived on.
///
/// A privacy change is claimed and its answer retained, so a retry of it is a retained answer.
async fn performed_once(
    temp: &kr_ipc::testing::TempHost,
    controller: &Arc<Controller>,
) -> (ConnectionId, ActorId, MutationRequest) {
    let (connection_id, actor_id) = admitted(controller).await;
    let mutation = privacy_request(temp, true);
    let revision = controller
        .admitted_revision(connection_id)
        .expect("the connection is registered");
    let answered = controller
        .write_method(
            &actor_id,
            &mutation,
            Method::PrivacySet,
            connection_id,
            None,
            Some(accepted(controller)),
            Some(revision),
        )
        .await
        .into_answer_for_test();
    assert!(
        matches!(
            answered,
            ControlFrame::Response(kr_protocol::envelope::Response {
                outcome: Outcome::Ok(_),
                ..
            })
        ),
        "the first admission is answered: {answered:?}"
    );
    (connection_id, actor_id, mutation)
}

/// What the local door tells of what a write came to, once the write has been performed: the
/// reply for `mutation` on `connection_id`, under the revision the connection was admitted under
/// when the write began, as the door reads it beside the registration check.
pub(super) async fn told_now(
    controller: &Controller,
    connection_id: ConnectionId,
    mutation: &MutationRequest,
    settled: impl std::future::Future<Output = crate::given::Settled<ControlFrame>>,
) -> ControlFrame {
    let admitted = controller.admitted_revision(connection_id).ok();
    let settled = settled.await;
    crate::given::local_door::told(
        settled,
        &crate::given::local_door::Standing::new(
            controller,
            connection_id,
            admitted,
            mutation.request_id,
        ),
    )
    .await
    .into_frame()
}

/// The refusal a frame carries, when it carries one.
pub(super) fn refusal(frame: &ControlFrame) -> Option<&kr_protocol::error::ProtocolError> {
    match frame {
        ControlFrame::Response(kr_protocol::envelope::Response {
            outcome: Outcome::Error(error),
            ..
        }) => Some(error),
        _ => None,
    }
}

/// KR-REQ-09.12: a retry on the local door is answered from what the action produced only while
/// this host owes no fence it could not raise. The control: the same retry with no fence owed is
/// answered, and is again once the fence is gone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_fence_this_host_owes_stops_a_local_retrys_retained_answer() {
    let (temp, controller, _clock) = daemon().await;
    let (connection_id, actor_id, mutation) = performed_once(&temp, &controller).await;

    let answered = controller
        .perform(&actor_id, connection_id, None, mutation.clone())
        .await;
    assert!(
        refusal(&answered).is_none(),
        "with no fence owed the retry is answered: {answered:?}"
    );

    controller.hold_fence(true);
    let refused = controller
        .perform(&actor_id, connection_id, None, mutation.clone())
        .await;
    told_as_not_shown(refusal(&refused).unwrap_or_else(|| {
        panic!("a retained answer is not given back while a fence is owed: {refused:?}")
    }));

    controller.hold_fence(false);
    let answered = controller
        .perform(&actor_id, connection_id, None, mutation)
        .await;
    assert!(
        refusal(&answered).is_none(),
        "once the fence is gone the retry is answered again: {answered:?}"
    );
}

/// KR-REQ-09.12: a retry whose registration is replaced after the revision it carries was read,
/// while it waits to go back, is refused. Another device's revocation stamps every surviving
/// registration with the revision it advanced to, which is the authority the retry was admitted
/// under having been replaced.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_registration_replaced_while_a_retry_waits_stops_its_retained_answer() {
    let (temp, controller, _clock) = daemon().await;
    let (connection_id, actor_id, mutation) = performed_once(&temp, &controller).await;

    let (arrived, release) = controller.pause_retained_lookup();
    let retrying = tokio::spawn({
        let controller = Arc::clone(&controller);
        async move {
            controller
                .perform(&actor_id, connection_id, None, mutation)
                .await
        }
    });
    tokio::time::timeout(Duration::from_secs(30), arrived)
        .await
        .expect("the retry reaches the place it is stopped at")
        .expect("the pause is armed");
    // Another device's revocation, landing while the retry waited.
    {
        let mut registry = controller.registry.lock().await;
        registry
            .advance_authority_revision()
            .expect("the revision advances");
        let revision = registry
            .authority_revision()
            .expect("the revision in force");
        let mut registrations = controller.admitted_write();
        for connection in registrations.values_mut() {
            connection.admitted_revision = revision;
        }
    }
    release.send(()).expect("the retry goes on");

    let refused = retrying.await.expect("the retry finishes");
    told_as_not_shown(refusal(&refused).unwrap_or_else(|| {
        panic!("a retry admitted before the replacement is not answered after it: {refused:?}")
    }));
}

/// KR-REQ-09.12: a retained answer stays readable after the window that admitted its action has
/// gone, because the check it is asked is the one a receipt needs and carries no deadline.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_retained_answer_outlives_the_window_that_admitted_its_action() {
    let (temp, controller, clock) = daemon().await;
    let (connection_id, actor_id, mutation) = performed_once(&temp, &controller).await;

    clock.advance(STANDING * 10);

    let answered = controller
        .perform(&actor_id, connection_id, None, mutation)
        .await;
    assert!(
        refusal(&answered).is_none(),
        "the receipt is read after its window is gone: {answered:?}"
    );
}

/// Another device's revocation: the revision advances and every surviving registration is stamped
/// with it, which is what a revocation that withdraws one device does to the rest.
pub(super) async fn another_devices_revocation_lands(controller: &Controller) {
    let mut registry = controller.registry.lock().await;
    registry
        .advance_authority_revision()
        .expect("the revision advances");
    let revision = registry
        .authority_revision()
        .expect("the revision in force");
    let mut registrations = controller.admitted_write();
    for connection in registrations.values_mut() {
        connection.admitted_revision = revision;
    }
}

/// A supervisor that counts the launches it is asked for, and starts nothing.
#[derive(Debug, Default)]
pub(super) struct CountingSupervisor {
    pub(super) asked: Arc<std::sync::atomic::AtomicUsize>,
}

impl crate::supervision::WorkerSupervisor for CountingSupervisor {
    fn start(
        &self,
        _launch: &crate::supervision::WorkerLaunch,
    ) -> crate::supervision::LaunchOutcome {
        self.asked.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        crate::supervision::LaunchOutcome::NotStarted {
            detail: "this test starts no workers".to_owned(),
        }
    }

    fn describe(&self) -> &'static str {
        "a supervisor that counts every launch and starts nothing"
    }
}

/// KR-REQ-09.12: a create carries the revision `perform` read before it waited, not one read after.
/// Another device's revocation lands between the two: the registration survives under the new
/// revision, which is the authority the create was admitted under having been replaced, so no
/// worker is started. The control: the same create under the revision in force reaches its launch.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_create_admitted_before_a_revocation_starts_nothing_after_it() {
    use kr_protocol::session::{LaunchProfile, Presentation, SessionCreateParams, ShellMode};

    let temp = kr_ipc::testing::TempHost::create();
    let launches = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut setup = super::a_floor_owed_its_record::setup(&temp);
    setup.supervisor = Box::new(CountingSupervisor {
        asked: Arc::clone(&launches),
    });
    let controller = Controller::start(setup).await.expect("the daemon starts");
    let environment_id = temp.environment_id();
    let create = |token: u8| {
        let params = SessionCreateParams {
            environment_id,
            presentation: Presentation::Invisible,
            shell: Nullable::null(),
            shell_mode: ShellMode::NativeCompat,
            cwd: Nullable::some("/".to_owned()),
            dimensions: Nullable::null(),
            worker_profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
            environment_snapshot: Vec::new(),
            palette: Nullable::null(),
            launch_profile: LaunchProfile::default(),
            terminal: Nullable::null(),
        };
        MutationRequest {
            request_id: RequestId::new(1),
            method: Method::SessionCreate.into(),
            method_version: MethodVersion::V1,
            action_id: ActionId::new(kr_protocol::scalars::Uuid::from_bytes([token; 16])),
            grant_id: Nullable::null(),
            target: ActionTarget::environment(environment_id),
            expected: ParamsValue::empty(),
            action_window_id: ActionWindowId::new("local:test").expect("a window"),
            requested_ttl_ms: DurationMs::new(30_000),
            params: ParamsValue::from_typed(&params).expect("encodes"),
        }
    };

    let (connection_id, actor_id) = admitted(&controller).await;
    let captured = controller
        .admitted_revision(connection_id)
        .expect("the connection is registered");
    another_devices_revocation_lands(&controller).await;
    let answered = controller
        .write_method(
            &actor_id,
            &create(1),
            Method::SessionCreate,
            connection_id,
            None,
            Some(accepted(&controller)),
            Some(captured),
        )
        .await
        .into_answer_for_test();
    let error = refusal(&answered).unwrap_or_else(|| {
        panic!("a create admitted before the revocation is refused: {answered:?}")
    });
    assert_eq!(error.code, ErrorCode::PermissionDenied, "{error:?}");
    assert_eq!(
        error.message,
        crate::authority::AdmissionLapse::Revoked.to_string()
    );
    assert_eq!(
        launches.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "no worker is started for it"
    );

    // The control: the revision the connection stands under now reaches the launch.
    let current = controller
        .admitted_revision(connection_id)
        .expect("the connection is registered");
    let _ = controller
        .write_method(
            &actor_id,
            &create(2),
            Method::SessionCreate,
            connection_id,
            None,
            Some(accepted(&controller)),
            Some(current),
        )
        .await
        .into_answer_for_test();
    assert_eq!(
        launches.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "a create under the revision in force asks for its launch"
    );
}

/// KR-REQ-09.12: a close carries the revision `perform` read before it waited. The worker is sent
/// nothing for one admitted before another device's revocation; the control, under the revision in
/// force, is forwarded.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_close_admitted_before_a_revocation_is_not_forwarded_after_it() {
    use super::a_close_a_worker_never_answers as world;

    let recorded: world::Recorded = Arc::default();
    let world::Silent {
        _temp,
        controller,
        environment_id,
        session_id,
        accepted: window,
        serving,
        ..
    } = world::fake_worker(Some(Arc::clone(&recorded))).await;
    world::acknowledged(&controller, session_id);
    let (connection_id, actor_id) = admitted(&controller).await;
    let captured = controller
        .admitted_revision(connection_id)
        .expect("the connection is registered");
    another_devices_revocation_lands(&controller).await;
    let forwarded = || {
        recorded
            .lock()
            .expect("the record is not poisoned")
            .iter()
            .filter(|frame| matches!(frame, ControlFrame::Forwarded(_)))
            .count()
    };

    let answered = controller
        .write_method(
            &actor_id,
            &world::close_request(environment_id, session_id),
            Method::SessionClose,
            connection_id,
            None,
            Some(window),
            Some(captured),
        )
        .await
        .into_answer_for_test();
    let error = refusal(&answered).unwrap_or_else(|| {
        panic!("a close admitted before the revocation is refused: {answered:?}")
    });
    assert_eq!(error.code, ErrorCode::PermissionDenied, "{error:?}");
    assert_eq!(
        error.message,
        crate::authority::AdmissionLapse::Revoked.to_string()
    );
    assert_eq!(forwarded(), 0, "the worker is sent no close");

    // The control: the revision the connection stands under now is forwarded.
    let current = controller
        .admitted_revision(connection_id)
        .expect("the connection is registered");
    let _ = controller
        .write_method(
            &actor_id,
            &world::close_request(environment_id, session_id),
            Method::SessionClose,
            connection_id,
            None,
            Some(window),
            Some(current),
        )
        .await
        .into_answer_for_test();
    assert_eq!(
        forwarded(),
        1,
        "a close under the revision in force is sent"
    );
    serving.abort();
}

/// KR-REQ-09.12: an authority change carries the revision `perform` read before it waited. A
/// revocation of a device admitted before another device's revocation changes nothing; the
/// control, under the revision in force, is performed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_authority_change_admitted_before_a_revocation_changes_nothing_after_it() {
    let (temp, controller, _clock) = daemon().await;
    let (connection_id, actor_id) = admitted(&controller).await;
    let captured = controller
        .admitted_revision(connection_id)
        .expect("the connection is registered");
    another_devices_revocation_lands(&controller).await;
    let revoke = |device: u8| MutationRequest {
        request_id: RequestId::new(1),
        method: Method::DeviceRevoke.into(),
        method_version: MethodVersion::V1,
        action_id: ActionId::new(kr_ipc::new_uuid()),
        grant_id: Nullable::null(),
        target: ActionTarget::environment(temp.environment_id()),
        expected: ParamsValue::empty(),
        action_window_id: ActionWindowId::new("local:test").expect("a window"),
        requested_ttl_ms: DurationMs::new(30_000),
        params: ParamsValue::from_typed(&kr_protocol::sharing::DeviceRevokeParams {
            device_id: kr_protocol::ids::DeviceId::new(kr_protocol::scalars::Uuid::from_bytes(
                [device; 16],
            )),
        })
        .expect("encodes"),
    };

    let stale = revoke(1);
    let revision_before = controller.policy().authority_revision();
    let answered = controller
        .write_method(
            &actor_id,
            &stale,
            Method::DeviceRevoke,
            connection_id,
            None,
            Some(accepted(&controller)),
            Some(captured),
        )
        .await
        .into_answer_for_test();
    let error = refusal(&answered).unwrap_or_else(|| {
        panic!("a change admitted before the revocation is refused: {answered:?}")
    });
    assert_eq!(error.code, ErrorCode::PermissionDenied, "{error:?}");
    assert_eq!(
        error.message,
        crate::authority::AdmissionLapse::Revoked.to_string()
    );
    assert_eq!(
        controller.policy().authority_revision(),
        revision_before,
        "the refused change advanced nothing"
    );

    // The control: the revision the connection stands under now.
    let current = controller
        .admitted_revision(connection_id)
        .expect("the connection is registered");
    let answered = controller
        .write_method(
            &actor_id,
            &revoke(2),
            Method::DeviceRevoke,
            connection_id,
            None,
            Some(accepted(&controller)),
            Some(current),
        )
        .await
        .into_answer_for_test();
    assert!(
        refusal(&answered).is_none(),
        "a change under the revision in force is performed: {answered:?}"
    );
}

/// KR-REQ-09.12: a method that takes no admission into a service is still refused on a connection
/// whose registration was withdrawn while the call waited. The control: the same methods, on a
/// connection whose registration stands, are not refused for authority.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_method_that_takes_no_admission_is_refused_on_a_withdrawn_registration() {
    let (temp, controller, _clock) = daemon().await;
    let (connection_id, actor_id) = admitted(&controller).await;
    let captured = controller
        .admitted_revision(connection_id)
        .expect("the connection is registered");
    let request = |method: Method| MutationRequest {
        request_id: RequestId::new(1),
        method: method.into(),
        method_version: MethodVersion::V1,
        action_id: ActionId::new(kr_ipc::new_uuid()),
        grant_id: Nullable::null(),
        target: ActionTarget::environment(temp.environment_id()),
        expected: ParamsValue::empty(),
        action_window_id: ActionWindowId::new("local:test").expect("a window"),
        requested_ttl_ms: DurationMs::new(30_000),
        params: ParamsValue::empty(),
    };
    let methods = [
        Method::EnvironmentEnrol,
        Method::EnvironmentForget,
        Method::EnvironmentRefresh,
        Method::HostUpdateHandover,
        Method::BackupEnable,
        Method::BackupBundleWrite,
        Method::AccountSignIn,
        Method::AccountSignOut,
        Method::AccountStorageSignIn,
        Method::AccountStorageSignOut,
    ];

    // The control first: nothing here is refused for authority while the registration stands.
    for method in [
        Method::EnvironmentEnrol,
        Method::EnvironmentForget,
        Method::EnvironmentRefresh,
    ] {
        let answered = controller
            .write_method(
                &actor_id,
                &request(method),
                method,
                connection_id,
                None,
                Some(accepted(&controller)),
                Some(captured),
            )
            .await
            .into_answer_for_test();
        assert!(
            refusal(&answered).is_none_or(|error| !error.message.contains("withdrawn")),
            "{method:?} on a standing registration: {answered:?}"
        );
    }

    controller.admitted_write().remove(&connection_id);
    for method in methods {
        let answered = controller
            .write_method(
                &actor_id,
                &request(method),
                method,
                connection_id,
                None,
                Some(accepted(&controller)),
                Some(captured),
            )
            .await
            .into_answer_for_test();
        let error = refusal(&answered)
            .unwrap_or_else(|| panic!("{method:?} on a withdrawn registration: {answered:?}"));
        assert_eq!(error.code, ErrorCode::PermissionDenied, "{method:?}");
        assert!(error.message.contains("withdrawn"), "{method:?}: {error:?}");
    }
}

/// A worker the lease issuer has bound and holds the acknowledgement of the revision in force from,
/// the way a worker that answered an announcement is, and the envelope a paired device's mutation
/// to it carries over a connection registered at that revision.
fn acknowledged_worker_and_a_paired_device(
    controller: &Controller,
) -> (
    kr_protocol::ids::SessionId,
    kr_protocol::actor::ActorEnvelope,
) {
    let revision = controller.leases.authority_revision();
    let session_id = kr_protocol::ids::SessionId::new(kr_ipc::new_uuid());
    let binding = controller.leases.bind(session_id);
    assert!(
        controller
            .leases
            .acknowledge(session_id, binding, revision, None)
    );
    (session_id, a_paired_device(controller))
}

/// The envelope a paired device's mutation carries over a connection registered at the revision in
/// force.
pub(super) fn a_paired_device(controller: &Controller) -> kr_protocol::actor::ActorEnvelope {
    use kr_protocol::actor::{ActorEnvelope, ActorIngress};

    let revision = controller.leases.authority_revision();
    let connection_id = ConnectionId::new(kr_ipc::new_uuid());
    let actor_id = ActorId::new("device:test").expect("a principal");
    controller.admitted_write().insert(
        connection_id,
        super::AdmittedConnection::new(actor_id.clone(), revision),
    );
    ActorEnvelope {
        actor_id,
        ingress: ActorIngress::PairedDevice,
        device_id: Nullable::null(),
        grant_id: Nullable::null(),
        grant_revision: Nullable::some(revision),
        controller_generation: controller.generation,
        connection_id,
    }
}

/// KR-REQ-09.12: a lease is refused while this host owes a fence it could not raise. A debt is
/// published without the revision moving, so the lease issuer still holds the worker's
/// acknowledgement of the revision in force and would renew on it; the refusal is the fence's own,
/// and it is not the one an announcement to the worker could change. The control: with no debt the
/// same worker is given its lease, and is again once the fence is gone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lease_is_refused_while_this_host_owes_a_fence() {
    let (_temp, controller, _clock) = daemon().await;
    let (session_id, actor) = acknowledged_worker_and_a_paired_device(&controller);

    let lease = controller
        .dispatch_lease(session_id, &actor)
        .await
        .expect("with no fence owed the worker is given its lease");
    assert!(lease.is_some());

    controller.hold_fence(true);
    let refused = controller
        .dispatch_lease(session_id, &actor)
        .await
        .expect_err("a fence owed refuses the lease");
    let super::LeaseDenied::Stopped(error) = refused else {
        panic!("a fence is not what an announcement to the worker changes: {refused:?}");
    };
    assert!(error.to_string().contains("fence"), "{error}");

    controller.hold_fence(false);
    controller
        .dispatch_lease(session_id, &actor)
        .await
        .expect("once the fence is gone the lease is given again");
}

/// KR-REQ-09.12: the lease issuer adopts a barrier's revision before the debts the barrier
/// captured are let go. Stopped where the registrations have been withdrawn and the issuer has not
/// yet adopted the revision, the debts are still published, so a lease asked for there is refused;
/// at the base they were already let go, and the issuer, still at the revision it was
/// acknowledged at, issued one. After the barrier the worker, which has acknowledged only the
/// revision it replaced, is asked to acknowledge the new one, which no fence is owed for.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_lease_is_issued_between_a_barriers_withdrawal_and_the_issuers_adoption_of_its_revision()
{
    let (_temp, controller, _clock) = daemon().await;
    let (session_id, actor) = acknowledged_worker_and_a_paired_device(&controller);
    let before = controller.leases.authority_revision();
    let debt = controller
        .owe_debt("a withdrawal", super::Reach::Host)
        .expect("the debt is written");

    let (arrived, release) = controller.before_the_leases_adopt.arm();
    let raising = tokio::spawn({
        let controller = Arc::clone(&controller);
        async move {
            let own = controller.publish_debts(&[(debt, super::Reach::Host)]);
            controller.barrier(own).await
        }
    });
    arrival(arrived).await;

    let asked = controller.dispatch_lease(session_id, &actor).await;
    let refused = asked.expect_err("no lease is issued while the withdrawal is owed");
    let super::LeaseDenied::Stopped(error) = refused else {
        panic!("it is the fence that refuses: {refused:?}");
    };
    assert!(error.to_string().contains("fence"), "{error}");
    assert_eq!(
        controller.leases.authority_revision(),
        before,
        "the issuer has not adopted the revision yet"
    );

    release.send(()).expect("the barrier goes on");
    raising
        .await
        .expect("the barrier ends")
        .expect("the barrier is raised");
    assert!(controller.leases.authority_revision() > before);
    let refused = controller
        .dispatch_lease(session_id, &actor)
        .await
        .expect_err("a worker that has not acknowledged the new revision holds no lease");
    assert!(
        matches!(refused, super::LeaseDenied::NotAcknowledged(_)),
        "{refused:?}"
    );
}

/// Waits until a change says it has reached the place it is stopped at, and fails the test when it
/// does not within thirty seconds.
async fn arrival(arrived: std::sync::mpsc::Receiver<()>) {
    tokio::task::spawn_blocking(move || arrived.recv_timeout(Duration::from_secs(30)))
        .await
        .expect("the waiting thread finishes")
        .expect("the change reaches the place it is stopped at");
}

/// KR-REQ-09.12: a forwarded mutation whose lease is refused for the fence this host owes is
/// refused with that fence, and no announcement is made to the worker for it. This daemon has no
/// directory entry for the worker, so an announcement would end the forward with the unknown
/// session instead.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_forward_stopped_by_the_fence_starts_no_announcement() {
    let (_temp, controller, _clock) = daemon().await;
    let (session_id, actor) = acknowledged_worker_and_a_paired_device(&controller);
    let accepted = accepted(&controller);

    let (arrived, release) = controller.before_the_lease.arm();
    let (forwarded, ()) = tokio::join!(
        controller.forwarded_deadline(session_id, &actor, accepted),
        async {
            tokio::time::timeout(Duration::from_secs(30), arrived)
                .await
                .expect("the forward reaches the place it is stopped at")
                .expect("the pause is armed");
            controller.hold_fence(true);
            release.send(()).expect("the forward goes on");
        }
    );
    let refused = forwarded.expect_err("a fence owed stops the forward");
    assert!(
        matches!(
            refused,
            crate::error::ControllerError::PermissionDenied { .. }
        ),
        "{refused}"
    );
    assert!(refused.to_string().contains("fence"), "{refused}");
}

/// KR-REQ-09.12: a lease taken just before a debt was published still bounds the action that holds
/// it, to the five seconds section 9 gives a lease, and nothing renews it once the withdrawal's
/// revision has been adopted and the barrier that would announce it has stopped. The worker held
/// the revision in force with its fence reported, so it was complete before; it has not
/// acknowledged the new revision, so it is pending now. Once the clock
/// is past the lease's deadline the action has run out of deadline and a lease asked for after it
/// is refused. The control: with no debt, a forward after the same lapse is given a new lease.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_lease_taken_before_a_debt_is_published_lapses_and_is_not_renewed() {
    let (_temp, controller, clock) = daemon().await;
    let (session_id, actor) = acknowledged_worker_and_a_paired_device(&controller);
    let before = controller.leases.authority_revision();
    let binding = controller.leases.binding(session_id);
    assert!(controller.leases.acknowledge(
        session_id,
        binding,
        before,
        Some(kr_protocol::action::FenceEvidence {
            rejected_actions: Vec::new(),
            possibly_executed: Vec::new(),
            remaining: kr_protocol::scalars::U64::ZERO,
            omitted: kr_protocol::scalars::U64::ZERO,
        }),
    ));
    assert!(
        controller
            .leases
            .begin_round()
            .report(before, [session_id])
            .holds(),
        "the worker held the revision in force before anything was withdrawn"
    );
    let accepted = accepted(&controller);

    // The control: no debt, and a forward after the lapse is given a new lease.
    controller
        .forwarded_deadline(session_id, &actor, accepted)
        .await
        .expect("the forward is given its lease");
    let first = controller
        .leases
        .current_lease(session_id)
        .expect("the forward took a lease");
    clock.advance(kr_transport::lease::MAX_LEASE + Duration::from_secs(1));
    controller
        .forwarded_deadline(session_id, &actor, accepted)
        .await
        .expect("with no fence owed a forward after the lapse renews");
    assert_ne!(
        controller.leases.current_lease(session_id),
        Some(first),
        "the lease was renewed"
    );

    // A lease taken just before the debt is published.
    let forwarded = controller
        .forwarded_deadline(session_id, &actor, accepted)
        .await
        .expect("the forward is given its lease");
    let lease = controller
        .leases
        .current_lease(session_id)
        .expect("the forward took a lease");
    assert!(
        forwarded.deadline_boot_ms.get() > 0
            && lease.remaining(controller.clock.now()) <= kr_transport::lease::MAX_LEASE,
        "the deadline the worker is given is bounded by the lease: {forwarded:?}"
    );

    // The debt is published, the barrier adopts the revision the withdrawal advanced to, and stops
    // before its announcement travels.
    controller.hold_fence(true);
    let withdrawn = kr_protocol::ids::AuthorityRevision::new(before.get() + 1);
    controller.leases.revoke(withdrawn);
    assert!(
        !lease.permits(controller.clock.now(), controller.generation, withdrawn),
        "the revision moved, so the lease no longer permits a dispatch"
    );

    clock.advance(kr_transport::lease::MAX_LEASE + Duration::from_secs(1));
    assert_eq!(
        crate::service::remaining_deadline(
            &*controller.shared_clock,
            &*controller.clock,
            accepted.deadline,
            Some(lease.deadline),
        ),
        None,
        "the action that held the lease has run out of deadline"
    );
    let refused = controller
        .dispatch_lease(session_id, &actor)
        .await
        .expect_err("nothing renews the lease");
    assert!(
        matches!(refused, super::LeaseDenied::NotAcknowledged(_)),
        "the worker has not acknowledged the revision the withdrawal advanced to: {refused:?}"
    );
    assert_eq!(
        controller.leases.current_lease(session_id),
        Some(lease),
        "the lease the action held is the last one issued"
    );
    let report = controller
        .leases
        .begin_round()
        .report(withdrawn, [session_id]);
    assert!(!report.holds(), "the worker is pending: {report:?}");
    assert_eq!(
        report.workers[0].state,
        kr_protocol::action::BarrierState::Pending
    );
}

/// A mutation of `method` under a fresh action identifier, carrying `params`.
pub(super) fn mutation_of(
    temp: &kr_ipc::testing::TempHost,
    method: Method,
    params: ParamsValue,
) -> MutationRequest {
    MutationRequest {
        request_id: RequestId::new(1),
        method: method.into(),
        method_version: MethodVersion::V1,
        action_id: ActionId::new(kr_ipc::new_uuid()),
        grant_id: Nullable::null(),
        target: ActionTarget::environment(temp.environment_id()),
        expected: ParamsValue::empty(),
        action_window_id: ActionWindowId::new("local:test").expect("a window"),
        requested_ttl_ms: DurationMs::new(30_000),
        params,
    }
}

/// The admission a first admission of a mutation carries on `connection_id`.
pub(super) fn carried(
    controller: &Controller,
    connection_id: ConnectionId,
) -> crate::authority::AdmittedMutation {
    crate::authority::AdmittedMutation {
        connection_id,
        admitted_revision: controller
            .admitted_revision(connection_id)
            .expect("the connection is registered"),
        deadline: Some(accepted(controller).deadline),
    }
}

/// What a refusal in `answer` says, when it is one.
pub(super) fn refused_for_a_fence(error: &kr_protocol::error::ProtocolError) {
    assert_eq!(error.code, ErrorCode::PermissionDenied, "{error:?}");
    assert!(error.message.contains("fence"), "{error:?}");
}

/// What the local door tells a copy a service read from its record and withheld, because the
/// authority the copy arrived under no longer stands: that what became of the action is not shown,
/// which says nothing of the record and nothing of the authority, since the refusal of the authority
/// is a definite word and an earlier attempt may have carried the action out.
fn told_as_not_shown(error: &kr_protocol::error::ProtocolError) {
    assert_eq!(error.code, ErrorCode::OutcomeUnknown, "{error:?}");
    assert_eq!(
        error.message,
        crate::error::ControllerError::outcome_not_shown().to_string(),
        "{error:?}"
    );
}

/// KR-REQ-09.09, 09.12 and 26.16: a transfer action another attempt recorded after the local door's
/// own lookup found nothing is not given back while this host owes a fence it could not raise, or
/// to a connection whose registration is gone. The control: the same late attempt, with nothing
/// owed, is answered from the record.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_transfer_action_recorded_before_a_late_attempt_is_not_given_back_while_a_fence_is_owed()
{
    let (temp, controller, _clock) = daemon().await;
    let (connection_id, actor_id) = admitted(&controller).await;
    let params = kr_protocol::transfer::DraftCreateParams {
        environment_id: temp.environment_id(),
        device_id: Nullable::null(),
        session_id: Nullable::null(),
        application_instance_id: Nullable::null(),
        text: "recorded by the first attempt".to_owned(),
    };
    let mutation = mutation_of(
        &temp,
        Method::DraftCreate,
        ParamsValue::from_typed(&params).expect("encodes"),
    );
    let first = controller
        .write_method(
            &actor_id,
            &mutation,
            Method::DraftCreate,
            connection_id,
            None,
            Some(accepted(&controller)),
            controller.admitted_revision(connection_id).ok(),
        )
        .await
        .into_answer_for_test();
    assert!(refusal(&first).is_none(), "the first attempt: {first:?}");

    // The late attempt reaches the service itself, as one does that began before the record was
    // written: nothing in front of it has looked for the action.
    let admission = carried(&controller, connection_id);
    let late = || {
        controller.transfer().write(
            &actor_id,
            &mutation,
            Method::DraftCreate,
            crate::transfer::TransferAdmission::new(Arc::clone(&controller), admission),
            None,
        )
    };
    let given = late().await;
    assert!(given.is_copied(), "the late attempt is given the record");
    given
        .into_answer_for_test()
        .expect("with nothing owed the late attempt is answered from the record");

    controller.hold_fence(true);
    let refused = late()
        .await
        .into_withheld()
        .expect_err("a fence this host owes stops the retained answer");
    refused_for_a_fence(&refused);
    controller.hold_fence(false);
    late()
        .await
        .into_answer_for_test()
        .expect("once the fence is gone it is answered again");

    controller.admitted_write().remove(&connection_id);
    let refused = late()
        .await
        .into_withheld()
        .expect_err("a registration that is gone stops the retained answer");
    assert_eq!(refused.code, ErrorCode::PermissionDenied, "{refused:?}");
}

/// KR-REQ-09.09: the local door's answer for a transfer action whose copy the service read from its
/// record and withheld while this host owes a fence. The caller at this machine is told that what
/// became of the action is not shown, as a paired device is, and not the refusal of the authority,
/// which is a definite word and says the action did not happen. The control is the same copy with
/// nothing owed, which is given the record.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_transfer_copy_a_service_withheld_is_told_at_the_local_door_as_not_shown() {
    let (temp, controller, _clock) = daemon().await;
    let (connection_id, actor_id) = admitted(&controller).await;
    let params = kr_protocol::transfer::DraftCreateParams {
        environment_id: temp.environment_id(),
        device_id: Nullable::null(),
        session_id: Nullable::null(),
        application_instance_id: Nullable::null(),
        text: "recorded by the first attempt".to_owned(),
    };
    let mutation = mutation_of(
        &temp,
        Method::DraftCreate,
        ParamsValue::from_typed(&params).expect("encodes"),
    );
    // Performed as the local door does once its own look for a record has found none, which is what
    // a copy admitted before another copy records reaches.
    let attempt = || {
        told_now(
            &controller,
            connection_id,
            &mutation,
            controller.write_method(
                &actor_id,
                &mutation,
                Method::DraftCreate,
                connection_id,
                None,
                Some(accepted(&controller)),
                controller.admitted_revision(connection_id).ok(),
            ),
        )
    };
    let first = attempt().await;
    assert!(refusal(&first).is_none(), "the first attempt: {first:?}");
    let control = attempt().await;
    assert!(
        refusal(&control).is_none(),
        "with nothing owed the copy is given the record: {control:?}"
    );

    controller.hold_fence(true);
    let withheld = attempt().await;
    controller.hold_fence(false);
    let told = refusal(&withheld)
        .unwrap_or_else(|| panic!("a fence this host owes stops the copy: {withheld:?}"));
    assert_eq!(
        told.code,
        ErrorCode::OutcomeUnknown,
        "the caller is told the outcome is not shown, and not the authority's refusal: {told:?}"
    );
}

/// KR-REQ-09.09, 09.12 and 26.16: the same for an authority change another attempt recorded between
/// the local door's lookup and this attempt's claim.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_authority_change_recorded_before_a_late_attempts_claim_is_not_given_back_while_a_fence_is_owed()
 {
    let (temp, controller, _clock) = daemon().await;
    let (connection_id, actor_id) = admitted(&controller).await;
    let mutation = mutation_of(&temp, Method::GrantRevoke, ParamsValue::empty());
    // What the first attempt recorded: a claim with the answer it came to.
    let digest = kr_protocol::digest::mutation_digest(&mutation, &actor_id).expect("a digest");
    let grants = controller.sharing().grants();
    let crate::grants::ActionClaim::Claimed { hold } = grants
        .claim_action(&actor_id, mutation.action_id, &digest, 1)
        .expect("the claim is written")
    else {
        panic!("the first claim of an action is this attempt's");
    };
    grants
        .retain_result(&hold, &kr_cbor::encode(ParamsValue::empty().as_value()), 2)
        .expect("the answer is recorded");
    drop(hold);

    let late = || async {
        controller
            .authority_change(
                &actor_id,
                super::authority_changes::AuthorityCaller::Owner,
                &mutation,
                Method::GrantRevoke,
                carried(&controller, connection_id),
            )
            .await
            .into_answer_for_test()
    };
    late()
        .await
        .expect("with nothing owed the late attempt is answered from the record");

    controller.hold_fence(true);
    let refused = late()
        .await
        .expect_err("a fence this host owes stops the retained answer");
    assert_eq!(
        refused.to_protocol_error().code,
        ErrorCode::PermissionDenied,
        "{refused:?}"
    );
    assert!(refused.to_string().contains("fence"), "{refused}");
    controller.hold_fence(false);
    late()
        .await
        .expect("once the fence is gone it is answered again");

    // The fence lands while the answer is being read, after the claim found the record: the check
    // that decides is the one made with the answer in hand.
    let (arrived, release) = controller.pause_retained_lookup();
    let waiting = tokio::spawn({
        let controller = Arc::clone(&controller);
        let actor_id = actor_id.clone();
        let mutation = mutation.clone();
        let carried = carried(&controller, connection_id);
        async move {
            controller
                .authority_change(
                    &actor_id,
                    super::authority_changes::AuthorityCaller::Owner,
                    &mutation,
                    Method::GrantRevoke,
                    carried,
                )
                .await
                .into_answer_for_test()
        }
    });
    tokio::time::timeout(Duration::from_secs(30), arrived)
        .await
        .expect("the late attempt reaches the place it is stopped at")
        .expect("the pause is armed");
    controller.hold_fence(true);
    release.send(()).expect("the late attempt goes on");
    let refused = waiting
        .await
        .expect("the late attempt finishes")
        .expect_err("a fence that landed while the answer was read stops it");
    refused_for_a_fence(&refused.to_protocol_error());
    controller.hold_fence(false);
}

/// KR-REQ-09.09, 09.12 and 26.16: the same for a privacy change, whose claim another attempt may
/// settle between the lookup and this attempt's claim.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_privacy_change_recorded_before_a_late_attempts_claim_is_not_given_back_while_a_fence_is_owed()
 {
    let (temp, controller, _clock) = daemon().await;
    let (connection_id, actor_id, mutation) = performed_once(&temp, &controller).await;
    let late = || {
        told_now(
            &controller,
            connection_id,
            &mutation,
            controller.write_method(
                &actor_id,
                &mutation,
                Method::PrivacySet,
                connection_id,
                None,
                Some(accepted(&controller)),
                controller.admitted_revision(connection_id).ok(),
            ),
        )
    };
    let answered = late().await;
    assert!(
        refusal(&answered).is_none(),
        "with nothing owed the late attempt is answered from the record: {answered:?}"
    );

    controller.hold_fence(true);
    let refused = late().await;
    told_as_not_shown(refusal(&refused).unwrap_or_else(|| {
        panic!("a fence this host owes stops the retained answer: {refused:?}")
    }));
    controller.hold_fence(false);
    let answered = late().await;
    assert!(
        refusal(&answered).is_none(),
        "once the fence is gone it is answered again: {answered:?}"
    );

    // The fence lands while the answer is being read, after the claim found the record: the check
    // that decides is the one made with the answer in hand.
    let (arrived, release) = controller.pause_retained_lookup();
    let waiting = tokio::spawn({
        let controller = Arc::clone(&controller);
        let actor_id = actor_id.clone();
        let mutation = mutation.clone();
        async move {
            let admitted = controller.admitted_revision(connection_id).ok();
            controller
                .write_method(
                    &actor_id,
                    &mutation,
                    Method::PrivacySet,
                    connection_id,
                    None,
                    Some(accepted(&controller)),
                    admitted,
                )
                .await
                .into_answer_for_test()
        }
    });
    tokio::time::timeout(Duration::from_secs(30), arrived)
        .await
        .expect("the late attempt reaches the place it is stopped at")
        .expect("the pause is armed");
    controller.hold_fence(true);
    release.send(()).expect("the late attempt goes on");
    let refused = waiting.await.expect("the late attempt finishes");
    refused_for_a_fence(refusal(&refused).unwrap_or_else(|| {
        panic!("a fence that landed while the answer was read stops it: {refused:?}")
    }));
    controller.hold_fence(false);
}

/// KR-REQ-09.09, 09.12 and 26.16: a privacy change that was applied is answered as applied when what
/// it came to cannot be kept. A retry of it is told its outcome is not known and is not performed
/// again, which is what the claim left behind. The control: with the receipt kept, the change is
/// answered and applied the same way.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_privacy_change_that_was_applied_is_not_answered_as_failed_when_its_receipt_cannot_be_kept()
 {
    let (temp, controller, _clock) = daemon().await;
    let (connection_id, actor_id) = admitted(&controller).await;
    let enabled = || controller.privacy.status(kr_ipc::now_ms()).enabled;
    let write = |mutation: &'_ MutationRequest| {
        let controller = Arc::clone(&controller);
        let actor_id = actor_id.clone();
        let mutation = mutation.clone();
        async move {
            controller
                .write_method(
                    &actor_id,
                    &mutation,
                    Method::PrivacySet,
                    connection_id,
                    None,
                    Some(accepted(&controller)),
                    controller.admitted_revision(connection_id).ok(),
                )
                .await
                .into_answer_for_test()
        }
    };
    assert!(!enabled(), "privacy mode starts off");
    let kept = write(&privacy_request(&temp, true)).await;
    assert!(refusal(&kept).is_none(), "the control: {kept:?}");
    assert!(enabled(), "the control: the change was applied");

    // The store takes no write of a receipt, as on a full disk.
    let registry = rusqlite::Connection::open(temp.environment().registry_database())
        .expect("opens the registry");
    registry
        .execute_batch(
            "CREATE TRIGGER refuse_receipts BEFORE UPDATE ON authority_receipts
             BEGIN SELECT RAISE(ABORT, 'no room'); END;",
        )
        .expect("the fault is in place");
    let turned_off = privacy_request(&temp, false);
    let unkept = write(&turned_off).await;
    assert!(
        refusal(&unkept).is_none(),
        "the change was applied, and that is what the caller is told: {unkept:?}"
    );
    assert!(!enabled(), "the change was applied");
    registry
        .execute_batch("DROP TRIGGER refuse_receipts;")
        .expect("the fault is cleared");

    // A later action turns it on again. A retry of the one whose receipt was lost is told its
    // outcome is not known, and does not turn it off a second time.
    let on_again = write(&privacy_request(&temp, true)).await;
    assert!(refusal(&on_again).is_none(), "{on_again:?}");
    assert!(enabled());
    let retried = write(&turned_off).await;
    assert_eq!(
        refusal(&retried)
            .unwrap_or_else(|| panic!(
                "a retry of an unfinished action is not answered: {retried:?}"
            ))
            .code,
        ErrorCode::OutcomeUnknown
    );
    assert!(enabled(), "the retry was not performed again");
}

/// KR-REQ-09.09, 09.12 and 26.16: the methods that take no admission into a service are
/// refused while this host owes a fence it could not raise. The control: with nothing owed, none is
/// refused for a fence.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_methods_that_take_no_admission_are_refused_while_a_fence_is_owed() {
    let (temp, controller, _clock) = daemon().await;
    let (connection_id, actor_id) = admitted(&controller).await;
    let captured = controller
        .admitted_revision(connection_id)
        .expect("the connection is registered");
    let methods = [
        Method::EnvironmentEnrol,
        Method::EnvironmentForget,
        Method::EnvironmentRefresh,
        Method::HostUpdateHandover,
        Method::BackupEnable,
        Method::BackupBundleWrite,
        Method::AccountSignIn,
        Method::AccountSignOut,
        Method::AccountStorageSignIn,
        Method::AccountStorageSignOut,
    ];
    let answer = |method: Method| {
        let controller = Arc::clone(&controller);
        let actor_id = actor_id.clone();
        let mutation = mutation_of(&temp, method, ParamsValue::empty());
        async move {
            controller
                .write_method(
                    &actor_id,
                    &mutation,
                    method,
                    connection_id,
                    None,
                    Some(accepted(&controller)),
                    Some(captured),
                )
                .await
                .into_answer_for_test()
        }
    };
    for method in methods {
        let answered = answer(method).await;
        assert!(
            refusal(&answered).is_none_or(|error| !error.message.contains("fence")),
            "{method:?} with nothing owed: {answered:?}"
        );
    }
    controller.hold_fence(true);
    for method in methods {
        let answered = answer(method).await;
        refused_for_a_fence(
            refusal(&answered)
                .unwrap_or_else(|| panic!("{method:?} while a fence is owed: {answered:?}")),
        );
    }
}

/// An enrolment of an environment, for the record this host keeps of them.
fn enrolment_of(byte: u8) -> kr_protocol::identity::EnvironmentEnrolment {
    use kr_protocol::identity::{EnvironmentAccess, EnvironmentEnrolment};
    use kr_protocol::scalars::{TimestampMs, Uuid};
    EnvironmentEnrolment {
        environment_id: kr_protocol::ids::EnvironmentId::new(Uuid::from_bytes([byte; 16])),
        access: EnvironmentAccess::WslDistribution,
        label: "ubuntu".to_owned(),
        target: "ubuntu-target".to_owned(),
        os_user: "kala".to_owned(),
        helper_path: "/usr/local/bin/kr".to_owned(),
        clipboard_destination: Nullable::null(),
        approved_at_ms: TimestampMs::new(0),
    }
}

/// Runs `call` and stops it once it holds this host's record of its environments and before it
/// asks the admission again, lets `meanwhile` happen there, and lets it go on: what lands while it
/// is stopped there is what the call is asked about, so a check made before the call had the record
/// cannot have seen it.
async fn stopped_after_the_environment_record_is_taken<T: Send + 'static>(
    controller: &Controller,
    call: impl std::future::Future<Output = T> + Send + 'static,
    meanwhile: impl FnOnce(),
) -> T {
    let (arrived, release) = controller.after_the_environment_record_is_taken.arm();
    let waiting = tokio::spawn(call);
    arrival(arrived).await;
    meanwhile();
    release.send(()).expect("the call goes on");
    waiting.await.expect("the call finishes")
}

/// KR-REQ-09.09, 09.12 and 26.16: a fence this host owes that lands after an environment record
/// change holds the record stops it, so the record is not changed. The control: with nothing owed,
/// the same changes are made.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_fence_that_lands_once_an_environment_change_holds_the_record_stops_it() {
    use kr_protocol::identity::{
        EnvironmentEnrolParams, EnvironmentForgetParams, EnvironmentRefreshParams,
    };
    let (temp, controller, _clock) = daemon().await;
    let (connection_id, actor_id) = admitted(&controller).await;
    let carried = crate::authority::AdmittedMutation {
        connection_id,
        admitted_revision: controller
            .admitted_revision(connection_id)
            .expect("the connection is registered"),
        deadline: None,
    };
    let change = |method: Method, params: ParamsValue| {
        let controller = Arc::clone(&controller);
        let mutation = mutation_of(&temp, method, params);
        let actor =
            super::routes::local_actor(actor_id.clone(), connection_id, controller.generation);
        async move {
            controller
                .environment_record(&actor, false, &mutation, method, carried)
                .await
        }
    };
    let enrol = |byte: u8| {
        change(
            Method::EnvironmentEnrol,
            ParamsValue::from_typed(&EnvironmentEnrolParams {
                enrolment: enrolment_of(byte),
            })
            .expect("encodes"),
        )
    };
    let forget = |byte: u8| {
        change(
            Method::EnvironmentForget,
            ParamsValue::from_typed(&EnvironmentForgetParams {
                environment_id: enrolment_of(byte).environment_id,
            })
            .expect("encodes"),
        )
    };
    let refresh = |byte: u8| {
        change(
            Method::EnvironmentRefresh,
            ParamsValue::from_typed(&EnvironmentRefreshParams {
                environment_id: enrolment_of(byte).environment_id,
                start: false,
            })
            .expect("encodes"),
        )
    };
    let recorded = |byte: u8| {
        let state_dir = controller.paths.state_dir().to_path_buf();
        let environment_id = enrolment_of(byte).environment_id;
        crate::bridge::store::Store::with_locked(&state_dir, |store| {
            Ok(store.enrolment(environment_id).is_some())
        })
        .expect("the record opens")
    };

    // The control: nothing owed, so the changes are made. A refresh asks the platform, which this
    // machine may not have, and what it must not be is a refusal for a fence.
    enrol(1).await.into_answer_for_test().expect("enrolled");
    assert!(recorded(1));
    if let Err(error) = refresh(1).await.into_answer_for_test() {
        assert!(!error.to_string().contains("fence"), "{error}");
    }

    // The fence lands while each change holds the record.
    let fence_lands = || controller.hold_fence(true);
    let refused =
        stopped_after_the_environment_record_is_taken(&controller, enrol(2), fence_lands).await;
    controller.hold_fence(false);
    refused_for_a_fence(
        &refused
            .into_answer_for_test()
            .expect_err("an enrolment is stopped")
            .to_protocol_error(),
    );
    assert!(!recorded(2), "the enrolment was not made");
    let refused =
        stopped_after_the_environment_record_is_taken(&controller, forget(1), fence_lands).await;
    controller.hold_fence(false);
    refused_for_a_fence(
        &refused
            .into_answer_for_test()
            .expect_err("a forgetting is stopped")
            .to_protocol_error(),
    );
    assert!(recorded(1), "the record was not forgotten");
    let refused =
        stopped_after_the_environment_record_is_taken(&controller, refresh(1), fence_lands).await;
    controller.hold_fence(false);
    refused_for_a_fence(
        &refused
            .into_answer_for_test()
            .expect_err("a refresh is stopped")
            .to_protocol_error(),
    );

    forget(1)
        .await
        .into_answer_for_test()
        .expect("forgotten once nothing is owed");
    assert!(!recorded(1));
}

/// Where a platform raises the fence this host owes while a refresh waits on it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum RaisesAt {
    /// Never: the test raises it, or none.
    Never,
    /// While it looks at the environment for the first time.
    TheFirstLook,
    /// While it starts the environment.
    TheStart,
}

/// A platform that says the environment is stopped until it has been started, or that it is
/// running, and raises a fence on this host where it is told to.
struct SteppedPlatform {
    controller: std::sync::Weak<Controller>,
    raises_at: RaisesAt,
    /// Whether the environment answers as running without being started.
    running: bool,
    /// How far the first look moves the daemon's clock on.
    takes: Option<(ManualClock, Duration)>,
    started: std::sync::atomic::AtomicBool,
}

impl SteppedPlatform {
    fn new(controller: &Arc<Controller>, raises_at: RaisesAt, running: bool) -> Arc<Self> {
        Arc::new(Self {
            controller: Arc::downgrade(controller),
            raises_at,
            running,
            takes: None,
            started: std::sync::atomic::AtomicBool::new(false),
        })
    }

    /// A platform whose first look takes `time` on `clock`.
    fn slow(controller: &Arc<Controller>, clock: &ManualClock, time: Duration) -> Arc<Self> {
        Arc::new(Self {
            controller: Arc::downgrade(controller),
            raises_at: RaisesAt::Never,
            running: false,
            takes: Some((clock.clone(), time)),
            started: std::sync::atomic::AtomicBool::new(false),
        })
    }

    fn raise(&self) {
        if let Some(controller) = self.controller.upgrade() {
            controller.hold_fence(true);
        }
    }

    fn was_started(&self) -> bool {
        self.started.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl crate::bridge::store::Observer for SteppedPlatform {
    fn observe(
        &self,
        _: &kr_protocol::identity::EnvironmentEnrolment,
    ) -> crate::error::Result<kr_protocol::identity::EnvironmentPresence> {
        use kr_protocol::identity::EnvironmentPresence;
        if self.running || self.was_started() {
            return Ok(EnvironmentPresence::Running);
        }
        if self.raises_at == RaisesAt::TheFirstLook {
            self.raise();
        }
        if let Some((clock, time)) = &self.takes {
            clock.advance(*time);
        }
        Ok(EnvironmentPresence::EnvironmentStopped)
    }

    fn start(&self, _: &kr_protocol::identity::EnvironmentEnrolment) -> crate::error::Result<()> {
        self.started
            .store(true, std::sync::atomic::Ordering::SeqCst);
        if self.raises_at == RaisesAt::TheStart {
            self.raise();
        }
        Ok(())
    }
}

/// A daemon with three enrolled environments and one connection, for tests of what a fence that
/// lands while an environment refresh runs stops.
struct Refreshing {
    temp: kr_ipc::testing::TempHost,
    controller: Arc<Controller>,
    carried: crate::authority::AdmittedMutation,
    actor_id: ActorId,
    connection_id: ConnectionId,
    clock: ManualClock,
}

impl Refreshing {
    async fn start() -> Self {
        use kr_protocol::identity::EnvironmentEnrolParams;
        let (temp, controller, clock) = daemon().await;
        let (connection_id, actor_id) = admitted(&controller).await;
        let carried = crate::authority::AdmittedMutation {
            connection_id,
            admitted_revision: controller
                .admitted_revision(connection_id)
                .expect("the connection is registered"),
            deadline: None,
        };
        let rig = Self {
            temp,
            controller,
            carried,
            actor_id,
            connection_id,
            clock,
        };
        for byte in [1, 2, 3] {
            let mutation = mutation_of(
                &rig.temp,
                Method::EnvironmentEnrol,
                ParamsValue::from_typed(&EnvironmentEnrolParams {
                    enrolment: enrolment_of(byte),
                })
                .expect("encodes"),
            );
            rig.record_change(Method::EnvironmentEnrol, mutation)
                .await
                .expect("enrolled");
        }
        rig
    }

    fn record_change(
        &self,
        method: Method,
        mutation: MutationRequest,
    ) -> impl std::future::Future<Output = crate::error::Result<ParamsValue>> + Send + 'static {
        self.record_change_under(method, mutation, self.carried)
    }

    fn record_change_under(
        &self,
        method: Method,
        mutation: MutationRequest,
        carried: crate::authority::AdmittedMutation,
    ) -> impl std::future::Future<Output = crate::error::Result<ParamsValue>> + Send + 'static {
        let controller = Arc::clone(&self.controller);
        let actor = super::routes::local_actor(
            self.actor_id.clone(),
            self.connection_id,
            controller.generation,
        );
        async move {
            controller
                .environment_record(&actor, false, &mutation, method, carried)
                .await
                .into_answer_for_test()
        }
    }

    /// A refresh of the environment `byte` enrolled, asked to start it or not.
    fn refresh(
        &self,
        byte: u8,
        start: bool,
    ) -> impl std::future::Future<Output = crate::error::Result<ParamsValue>> + Send + 'static {
        use kr_protocol::identity::EnvironmentRefreshParams;
        self.record_change(
            Method::EnvironmentRefresh,
            mutation_of(
                &self.temp,
                Method::EnvironmentRefresh,
                ParamsValue::from_typed(&EnvironmentRefreshParams {
                    environment_id: enrolment_of(byte).environment_id,
                    start,
                })
                .expect("encodes"),
            ),
        )
    }

    /// A refresh of the environment `byte` enrolled, accepted under a deadline `within` from now on
    /// the daemon's clock.
    fn refresh_within(
        &self,
        byte: u8,
        start: bool,
        within: Duration,
    ) -> impl std::future::Future<Output = crate::error::Result<ParamsValue>> + Send + 'static {
        use kr_protocol::identity::EnvironmentRefreshParams;
        self.record_change_under(
            Method::EnvironmentRefresh,
            mutation_of(
                &self.temp,
                Method::EnvironmentRefresh,
                ParamsValue::from_typed(&EnvironmentRefreshParams {
                    environment_id: enrolment_of(byte).environment_id,
                    start,
                })
                .expect("encodes"),
            ),
            crate::authority::AdmittedMutation {
                deadline: Some(
                    self.controller
                        .clock
                        .now()
                        .checked_add(within)
                        .expect("a deadline"),
                ),
                ..self.carried
            },
        )
    }

    /// What this host last recorded of the environment `byte` enrolled.
    fn recorded_status(&self, byte: u8) -> kr_protocol::identity::EnvironmentPresence {
        let state_dir = self.controller.paths.state_dir().to_path_buf();
        let environment_id = enrolment_of(byte).environment_id;
        crate::bridge::store::Store::with_locked(&state_dir, |store| {
            Ok(store
                .list(None, kr_ipc::now_ms().get())
                .into_iter()
                .find(|row| row.enrolment.environment_id == environment_id)
                .map(|row| row.status))
        })
        .expect("the record opens")
        .expect("the environment is enrolled")
    }

    /// What this host last recorded of the integration of the environment `byte` enrolled.
    #[cfg(unix)]
    fn recorded_readiness(&self, byte: u8) -> kr_protocol::identity::EnvironmentReadiness {
        let state_dir = self.controller.paths.state_dir().to_path_buf();
        let environment_id = enrolment_of(byte).environment_id;
        crate::bridge::store::Store::with_locked(&state_dir, |store| {
            Ok(store
                .list(None, kr_ipc::now_ms().get())
                .into_iter()
                .find(|row| row.enrolment.environment_id == environment_id)
                .map(|row| row.readiness))
        })
        .expect("the record opens")
        .expect("the environment is enrolled")
    }
}

/// KR-REQ-09.09: a fence that lands while a refresh waits on the platform stops what it was about
/// to do next. One that lands during the first look stops the start, and the refresh is refused
/// with nothing recorded and nothing started; with no start asked for it stops the record.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_fence_that_lands_while_a_refresh_looks_at_the_environment_stops_the_start_and_the_record()
 {
    use kr_protocol::identity::EnvironmentPresence;
    let rig = Refreshing::start().await;
    for (byte, start) in [(1, false), (2, true)] {
        let platform = SteppedPlatform::new(&rig.controller, RaisesAt::TheFirstLook, false);
        rig.controller.ask_instead(platform.clone());
        let refused = rig
            .refresh(byte, start)
            .await
            .expect_err("the refresh is refused");
        rig.controller.hold_fence(false);
        refused_for_a_fence(&refused.to_protocol_error());
        assert!(!platform.was_started(), "start asked for: {start}");
        assert_eq!(
            rig.recorded_status(byte),
            EnvironmentPresence::Stale,
            "start asked for: {start}"
        );
    }
}

/// KR-REQ-09.09: a refresh whose deadline passes while the platform looks at the environment does
/// not start it: the refresh is refused as expired, nothing is started and nothing is recorded. The
/// control: a refresh whose deadline stands starts the environment.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refresh_whose_deadline_passes_while_the_platform_looks_does_not_start_the_environment() {
    use kr_protocol::identity::EnvironmentPresence;
    let rig = Refreshing::start().await;
    let slow = SteppedPlatform::slow(&rig.controller, &rig.clock, Duration::from_secs(11));
    rig.controller.ask_instead(slow.clone());
    let expired = rig
        .refresh_within(1, true, Duration::from_secs(10))
        .await
        .expect_err("the deadline passed before the start");
    assert!(
        matches!(expired, crate::error::ControllerError::WindowExpired { .. }),
        "{expired}"
    );
    assert!(!slow.was_started());
    assert_eq!(rig.recorded_status(1), EnvironmentPresence::Stale);

    let standing = SteppedPlatform::slow(&rig.controller, &rig.clock, Duration::from_secs(1));
    rig.controller.ask_instead(standing.clone());
    rig.refresh_within(2, true, Duration::from_secs(10))
        .await
        .expect("a deadline that stands lets the refresh start the environment");
    assert!(standing.was_started());
}

/// KR-REQ-09.09: a fence that lands while a refresh starts the environment stops the record, and
/// the refresh is then an outcome this host does not know and not a refusal it keeps: the start is
/// not undone by the record not being made.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_fence_that_lands_while_a_refresh_starts_the_environment_is_an_unknown_outcome() {
    use kr_protocol::identity::EnvironmentPresence;
    let rig = Refreshing::start().await;
    let platform = SteppedPlatform::new(&rig.controller, RaisesAt::TheStart, false);
    rig.controller.ask_instead(platform.clone());
    let unknown = rig
        .refresh(1, true)
        .await
        .expect_err("the record is refused after a start");
    rig.controller.hold_fence(false);
    assert!(platform.was_started());
    assert_eq!(unknown.code(), ErrorCode::OutcomeUnknown, "{unknown}");
    assert!(
        !matches!(
            unknown.code().retry_category(),
            kr_protocol::error::RetryCategory::NoRetry
                | kr_protocol::error::RetryCategory::ConfigurationChange
        ),
        "no claim keeps it as a refusal"
    );
    assert_eq!(rig.recorded_status(1), EnvironmentPresence::Stale);
}

/// KR-REQ-09.09, the outcome of a refresh whose look fails after its start: the environment was
/// started and the platform then could not be asked about it, so the refresh is an outcome this host
/// does not know and not a refusal it keeps, and nothing is recorded. The control is a platform that
/// cannot be asked at all: nothing was started, and the failure is not told as an unknown outcome.
/// Not shown here: a fence, an expiry or a withdrawn registration at the same place, which the
/// cases beside this one show.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refresh_whose_look_fails_after_its_start_is_an_unknown_outcome() {
    use kr_protocol::identity::EnvironmentPresence;
    let rig = Refreshing::start().await;

    let platform = LosesTheLook::after_the_start();
    rig.controller.ask_instead(platform.clone());
    let unknown = rig
        .refresh(1, true)
        .await
        .expect_err("the look after the start failed");
    assert!(platform.was_started());
    assert_eq!(unknown.code(), ErrorCode::OutcomeUnknown, "{unknown}");
    assert!(
        !matches!(
            unknown.code().retry_category(),
            kr_protocol::error::RetryCategory::NoRetry
                | kr_protocol::error::RetryCategory::ConfigurationChange
        ),
        "no claim keeps it as a refusal"
    );
    assert_eq!(rig.recorded_status(1), EnvironmentPresence::Stale);

    // The control: the platform that cannot be asked before anything is started.
    let platform = LosesTheLook::from_the_first_look();
    rig.controller.ask_instead(platform.clone());
    let failed = rig
        .refresh(2, true)
        .await
        .expect_err("the first look failed");
    assert!(!platform.was_started());
    assert_ne!(failed.code(), ErrorCode::OutcomeUnknown, "{failed}");
    assert_eq!(rig.recorded_status(2), EnvironmentPresence::Stale);
}

/// A platform that cannot be asked about the environment: from its first look, or once it has been
/// told to start it.
struct LosesTheLook {
    from_the_first_look: bool,
    started: std::sync::atomic::AtomicBool,
}

impl LosesTheLook {
    fn after_the_start() -> Arc<Self> {
        Arc::new(Self {
            from_the_first_look: false,
            started: std::sync::atomic::AtomicBool::new(false),
        })
    }

    fn from_the_first_look() -> Arc<Self> {
        Arc::new(Self {
            from_the_first_look: true,
            started: std::sync::atomic::AtomicBool::new(false),
        })
    }

    fn was_started(&self) -> bool {
        self.started.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl crate::bridge::store::Observer for LosesTheLook {
    fn observe(
        &self,
        _: &kr_protocol::identity::EnvironmentEnrolment,
    ) -> crate::error::Result<kr_protocol::identity::EnvironmentPresence> {
        if self.from_the_first_look || self.was_started() {
            return Err(crate::error::ControllerError::supervision(
                "the platform did not answer",
            ));
        }
        Ok(kr_protocol::identity::EnvironmentPresence::EnvironmentStopped)
    }

    fn start(&self, _: &kr_protocol::identity::EnvironmentEnrolment) -> crate::error::Result<()> {
        self.started
            .store(true, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }
}

/// KR-REQ-09.09: a fence that lands after a refresh has recorded what the platform said leaves the
/// refresh answered, with the observation recorded, and says that no bridge was opened.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_fence_that_lands_after_a_refresh_is_recorded_leaves_it_answered_with_no_bridge() {
    use kr_protocol::identity::{EnvironmentPresence, EnvironmentRefreshResult};
    let rig = Refreshing::start().await;
    rig.controller
        .ask_instead(SteppedPlatform::new(&rig.controller, RaisesAt::Never, true));
    let (arrived, release) = rig.controller.after_the_environment_is_recorded.arm();
    let waiting = tokio::spawn(rig.refresh(1, false));
    arrival(arrived).await;
    rig.controller.hold_fence(true);
    release.send(()).expect("the refresh goes on");
    let answered = waiting
        .await
        .expect("the refresh finishes")
        .expect("a refresh that has run is answered");
    rig.controller.hold_fence(false);
    let result: EnvironmentRefreshResult = answered.to_typed().expect("a result");
    assert_eq!(result.row.status, EnvironmentPresence::Running);
    assert!(result.verification.0.is_none());
    assert!(
        result.connection.contains("no bridge was opened") && result.connection.contains("fence"),
        "{}",
        result.connection
    );
    assert_eq!(rig.recorded_status(1), EnvironmentPresence::Running);
}

/// KR-REQ-09.09: a fence that lands while a bridge is being opened leaves the refresh answered
/// and not refused: the refresh has run, and what cannot be recorded of the bridge is said in the
/// answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_fence_that_lands_while_a_refresh_opens_a_bridge_leaves_it_answered() {
    use kr_protocol::identity::{EnvironmentPresence, EnvironmentRefreshResult};
    let rig = Refreshing::start().await;
    rig.controller
        .ask_instead(SteppedPlatform::new(&rig.controller, RaisesAt::Never, true));
    // The record's pause fires first where the refresh takes the record and again where the
    // bridge's outcome is recorded; the second is armed while the first holds the refresh.
    let (first, release_first) = rig.controller.after_the_environment_record_is_taken.arm();
    let waiting = tokio::spawn(rig.refresh(1, false));
    arrival(first).await;
    let (second, release_second) = rig.controller.after_the_environment_record_is_taken.arm();
    release_first.send(()).expect("the refresh goes on");
    arrival(second).await;
    rig.controller.hold_fence(true);
    release_second.send(()).expect("the refresh goes on");
    let answered = waiting
        .await
        .expect("the refresh finishes")
        .expect("a refresh that has run is answered");
    rig.controller.hold_fence(false);
    let result: EnvironmentRefreshResult = answered.to_typed().expect("a result");
    assert_eq!(result.row.status, EnvironmentPresence::Running);
    assert!(result.verification.0.is_none());
    assert!(
        result.connection.contains("did not record") && result.connection.contains("fence"),
        "{}",
        result.connection
    );
    assert_eq!(rig.recorded_status(1), EnvironmentPresence::Running);
}

/// Set in the program that runs the case below again, which finds the stand-in for the launcher
/// first on its search path.
#[cfg(unix)]
const WITH_AN_ANSWERING_BRIDGE: &str = "KR_TEST_HOST_WITH_AN_ANSWERING_BRIDGE";

/// The case's name as the test program lists it.
#[cfg(unix)]
const THE_ANSWERING_BRIDGE_CASE: &str = "service::the_fence_at_every_effect::a_fence_that_lands_after_a_bridge_has_answered_says_the_answer_was_not_recorded";

/// What the destination's helper writes to the stand-in's output when a bridge is opened to the
/// environment `byte` enrolled: its acknowledgement and its answer to the one read a refresh makes.
#[cfg(unix)]
fn what_an_answering_helper_writes(byte: u8) -> Vec<u8> {
    use kr_protocol::envelope::Response;
    use kr_protocol::frame::{FrameCodec, StreamKind};
    use kr_protocol::hello::{ActionWindow, PROTOCOL_VERSION};
    use kr_protocol::identity::{BootIdentity, BootIdentitySource, BridgeFrame, BridgeHelloAck};
    use kr_protocol::ids::{BootEpoch, BuildId};
    use kr_protocol::local::{LocalBuild, LocalRole};
    use kr_protocol::scalars::{Bytes, TimestampMs, U64, Uuid};

    let connection_id = ConnectionId::new(Uuid::from_bytes([0x5c; 16]));
    let frames = [
        BridgeFrame::HelloAck(Box::new(BridgeHelloAck {
            protocol_version: PROTOCOL_VERSION,
            build: Some(LocalBuild::this(BuildId::new("kr/0.1.0").expect("a build"))),
            base: kr_protocol::identity::DestinationBase {
                home: "/home/kala".to_owned(),
                variables: Vec::new(),
            },
            environment_id: enrolment_of(byte).environment_id,
            os_user: "kala".to_owned(),
            role: LocalRole::Controller,
            connection_id,
            boot_identity: BootIdentity {
                source: BootIdentitySource::LinuxBootId,
                value: Bytes::new(b"fixture-boot".to_vec()),
            },
            max_frame_len: U64::new(65_536),
            action_window: ActionWindow {
                action_window_id: ActionWindowId::new("w-fixture").expect("a window"),
                connection_id,
                boot_epoch: BootEpoch::new(1),
                issued_at_ms: TimestampMs::new(100),
                valid_for_ms: DurationMs::new(120_000),
            },
        })),
        BridgeFrame::Control(Box::new(ControlFrame::Response(Response {
            request_id: RequestId::new(1),
            outcome: Outcome::Ok(ParamsValue::empty()),
        }))),
    ];
    let codec = FrameCodec::new(StreamKind::Control);
    frames
        .iter()
        .flat_map(|frame| codec.encode_message(frame).expect("a bridge frame encodes"))
        .collect()
}

/// Runs the case below again as a program whose search path finds, first, a `wsl.exe` that answers
/// a bridge as the helper of the environment `enrolment_of(1)` names would.
///
/// The launcher is a program of a fixed name that a refresh finds on the search path, and a search
/// path belongs to the whole process, so a case that wants a bridge to answer cannot change it for
/// itself. The stand-in is placed and started once here, where nothing is timed.
#[cfg(unix)]
fn run_again_with_an_answering_bridge() {
    let kept = tempfile::tempdir().expect("a directory for the stand-in");
    let bin = kept.path().join("bin");
    std::fs::create_dir_all(&bin).expect("the stand-in's directory");
    let answer = kept.path().join("answer");
    std::fs::write(&answer, what_an_answering_helper_writes(1)).expect("the answer");
    let answer_path = answer.to_str().expect("a temporary path is text");
    assert!(
        !answer_path.contains('\''),
        "the stand-in quotes its answer with single quotes: {answer_path}"
    );
    let text = kept.path().join("wsl.exe.text");
    std::fs::write(
        &text,
        format!(
            "#!/bin/sh\ncase \"$1\" in\n  --version) exit 0 ;;\nesac\n/bin/cat '{answer_path}'\nexec /bin/cat >/dev/null\n"
        ),
    )
    .expect("the stand-in's text");
    kr_ipc::testing::place_and_start_once(&text, &bin.join("wsl.exe"), &["--version"]);

    let mut path = std::ffi::OsString::from(bin.as_os_str());
    if let Some(inherited) = std::env::var_os("PATH") {
        path.push(":");
        path.push(inherited);
    }
    let output = std::process::Command::new(std::env::current_exe().expect("this test program"))
        .args(["--exact", THE_ANSWERING_BRIDGE_CASE, "--test-threads=1"])
        .env("PATH", path)
        .env(WITH_AN_ANSWERING_BRIDGE, "1")
        .output()
        .expect("this test program runs again");
    let report = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && report.contains("1 passed"),
        "{report}{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// KR-REQ-09.09, one recheck of five only: the recheck of authority by an owed fence. A fence that
/// lands after a bridge has answered, and before this host records what answered, leaves the
/// refresh answered and not refused, and says that the bridge answered and was not recorded: the
/// answer establishes nothing, and the same bridge records once nothing is owed.
///
/// The destination answers through a stand-in for the launcher, so the bridge really opens and
/// really answers. Not shown here: the rechecks of expiry, identity, binding and preconditions, a
/// fence at the other places a refresh waits, which the cases beside this one show, or a
/// registration withdrawn at this one.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_fence_that_lands_after_a_bridge_has_answered_says_the_answer_was_not_recorded() {
    use kr_protocol::identity::{EnvironmentPresence, EnvironmentRefreshResult};
    if std::env::var_os(WITH_AN_ANSWERING_BRIDGE).is_none() {
        run_again_with_an_answering_bridge();
        return;
    }
    let rig = Refreshing::start().await;
    rig.controller
        .ask_instead(SteppedPlatform::new(&rig.controller, RaisesAt::Never, true));
    // The record's pause fires first where the refresh takes the record and again where the
    // bridge's outcome is recorded, which is after the bridge has answered.
    let (first, release_first) = rig.controller.after_the_environment_record_is_taken.arm();
    let waiting = tokio::spawn(rig.refresh(1, false));
    arrival(first).await;
    let (second, release_second) = rig.controller.after_the_environment_record_is_taken.arm();
    release_first.send(()).expect("the refresh goes on");
    arrival(second).await;
    rig.controller.hold_fence(true);
    release_second.send(()).expect("the refresh goes on");
    let answered = waiting
        .await
        .expect("the refresh finishes")
        .expect("a refresh that has run is answered");
    rig.controller.hold_fence(false);
    let result: EnvironmentRefreshResult = answered.to_typed().expect("a result");
    assert_eq!(result.row.status, EnvironmentPresence::Running);
    assert!(
        result.verification.0.is_none(),
        "an answer this host did not record is not told as an environment's: {:?}",
        result.verification
    );
    assert!(
        result.connection.contains("the bridge answered")
            && result.connection.contains("did not record")
            && result.connection.contains("fence"),
        "{}",
        result.connection
    );
    assert!(
        !result.row.readiness.channel_scoped,
        "the answer established no scoped channel: {:?}",
        result.row.readiness
    );
    assert_eq!(rig.recorded_status(1), EnvironmentPresence::Running);
    assert!(
        !rig.recorded_readiness(1).channel_scoped,
        "the answer established nothing"
    );

    // The control: with nothing owed the same bridge answers and the refresh records it.
    let recorded: EnvironmentRefreshResult = rig
        .refresh(1, false)
        .await
        .expect("a refresh with nothing owed is answered")
        .to_typed()
        .expect("a result");
    assert!(
        recorded.verification.0.is_some(),
        "the bridge answered: {}",
        recorded.connection
    );
    assert!(
        recorded.row.readiness.channel_scoped,
        "the bridge's answer is recorded once nothing is owed: {:?}",
        recorded.row.readiness
    );
    assert!(rig.recorded_readiness(1).channel_scoped);
}

/// KR-REQ-09.09, 09.12 and 26.16: a machine group step another attempt recorded is not given back
/// to a late attempt, one that finds the claim after waiting for the step lock, while this host owes
/// a fence it could not raise: it is told that what became of the action is not shown. The control:
/// with nothing owed, the same late attempt is answered from the receipt, and is again once the
/// fence is gone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_machine_group_step_recorded_before_a_late_attempts_claim_is_not_given_back_while_a_fence_is_owed()
 {
    use kr_protocol::machine::{MachineExpected, MachineSplitParams};
    let (temp, controller, _clock) = daemon().await;
    let (connection_id, actor_id) = admitted(&controller).await;
    let group = controller
        .machine_report()
        .expect("this daemon serves a machine group record");
    let mutation = mutation_of(
        &temp,
        Method::MachineSplit,
        ParamsValue::from_typed(&MachineSplitParams {
            expected: MachineExpected {
                machine_id: group.machine_id,
                revision: group.revision,
            },
        })
        .expect("encodes"),
    );
    let attempt = || {
        told_now(
            &controller,
            connection_id,
            &mutation,
            controller.write_method(
                &actor_id,
                &mutation,
                Method::MachineSplit,
                connection_id,
                None,
                Some(accepted(&controller)),
                controller.admitted_revision(connection_id).ok(),
            ),
        )
    };
    let first = attempt().await;
    assert!(refusal(&first).is_none(), "the first attempt: {first:?}");

    let late = attempt().await;
    assert!(
        refusal(&late).is_none(),
        "with nothing owed the late attempt is answered from the receipt: {late:?}"
    );

    controller.hold_fence(true);
    let refused = attempt().await;
    told_as_not_shown(refusal(&refused).unwrap_or_else(|| {
        panic!("a fence this host owes stops the retained answer: {refused:?}")
    }));
    controller.hold_fence(false);
    let answered = attempt().await;
    assert!(
        refusal(&answered).is_none(),
        "once the fence is gone it is answered again: {answered:?}"
    );

    controller.admitted_write().remove(&connection_id);
    let refused = attempt().await;
    assert_eq!(
        refusal(&refused)
            .unwrap_or_else(|| panic!("a registration that is gone stops it: {refused:?}"))
            .code,
        ErrorCode::PermissionDenied
    );
}

/// KR-REQ-26.16, the part about a change affecting authority fencing dispatch: a fence that lands
/// while a late attempt holds the machine group's step lock stops the answer it found there. The
/// attempt has waited for the lock and found its action recorded; the fence is raised with the
/// lock held and the answer in hand, so only a check made after the record is found, and not one
/// made before the lock was taken, sees it. It is raised twice: as a fence this host owes, and by
/// a revocation of this host's authority that is acknowledged while the lock is held. Each time the
/// late attempt is told that what became of the action is not shown. The control: the same late
/// attempt, with nothing raised while it is stopped there, is answered from the receipt.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_fence_that_lands_while_a_late_attempt_holds_the_step_lock_stops_the_answer_it_found() {
    use kr_protocol::machine::{MachineExpected, MachineSplitParams};
    let (temp, controller, _clock) = daemon().await;
    let (connection_id, actor_id) = admitted(&controller).await;
    let group = controller
        .machine_report()
        .expect("this daemon serves a machine group record");
    let mutation = mutation_of(
        &temp,
        Method::MachineSplit,
        ParamsValue::from_typed(&MachineSplitParams {
            expected: MachineExpected {
                machine_id: group.machine_id,
                revision: group.revision,
            },
        })
        .expect("encodes"),
    );
    let attempt = |controller: Arc<Controller>| {
        let actor_id = actor_id.clone();
        let mutation = mutation.clone();
        async move {
            told_now(
                &controller,
                connection_id,
                &mutation,
                controller.write_method(
                    &actor_id,
                    &mutation,
                    Method::MachineSplit,
                    connection_id,
                    None,
                    Some(accepted(&controller)),
                    controller.admitted_revision(connection_id).ok(),
                ),
            )
            .await
        }
    };
    let first = attempt(Arc::clone(&controller)).await;
    assert!(refusal(&first).is_none(), "the first attempt: {first:?}");

    // A late attempt stopped where it holds the step lock with the recorded answer in hand.
    let stopped_with_the_lock = || async {
        let (arrived, release) = controller.pause_retained_lookup();
        let waiting = tokio::spawn(attempt(Arc::clone(&controller)));
        tokio::time::timeout(Duration::from_secs(30), arrived)
            .await
            .expect("the late attempt reaches the place it is stopped at")
            .expect("the pause is armed");
        assert!(
            controller.a_machine_step_holds_the_step_lock(),
            "the late attempt holds the step lock where it is stopped"
        );
        (waiting, release)
    };

    let (waiting, release) = stopped_with_the_lock().await;
    release.send(()).expect("the late attempt goes on");
    let answered = waiting.await.expect("the late attempt finishes");
    assert!(
        refusal(&answered).is_none(),
        "with nothing raised the late attempt is answered from the receipt: {answered:?}"
    );

    let (waiting, release) = stopped_with_the_lock().await;
    controller.hold_fence(true);
    release.send(()).expect("the late attempt goes on");
    let refused = waiting.await.expect("the late attempt finishes");
    told_as_not_shown(refusal(&refused).unwrap_or_else(|| {
        panic!("a fence raised while the step lock was held stops the answer: {refused:?}")
    }));
    controller.hold_fence(false);
    assert!(
        !controller.a_machine_step_holds_the_step_lock(),
        "the refused attempt let the lock go"
    );

    // A revocation of this host's authority, acknowledged while the lock is held, withdraws the
    // registration the late attempt was admitted under.
    let (waiting, release) = stopped_with_the_lock().await;
    let acknowledged = controller
        .revoke_authority()
        .await
        .expect("the revocation is acknowledged");
    assert!(
        acknowledged
            .workers
            .iter()
            .all(|worker| worker.state != kr_protocol::action::BarrierState::Pending),
        "no barrier is pending when the revocation is acknowledged"
    );
    release.send(()).expect("the late attempt goes on");
    let refused = waiting.await.expect("the late attempt finishes");
    let withheld = refusal(&refused).unwrap_or_else(|| {
        panic!(
            "a revocation acknowledged while the step lock was held stops the answer: {refused:?}"
        )
    });
    told_as_not_shown(withheld);
    assert!(
        !controller.a_machine_step_holds_the_step_lock(),
        "the refused attempt let the lock go"
    );
}

/// KR-REQ-09.09, the authority part, at the local door: an agent-tool installation another attempt
/// recorded is not shown to a late attempt while this host owes a fence it could not raise, and the
/// conflict a reused identifier meets is the fence's own refusal, which says nothing was done. The
/// control: with nothing owed the late attempt is given what the first was told, and the reused
/// identifier is a conflict.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_installation_recorded_before_a_late_attempts_lookup_is_not_shown_at_the_door_while_a_fence_is_owed()
 {
    use kr_protocol::skill::{AgentTarget, AgentToolsParams, InstallScope};
    let (temp, controller, _clock) = daemon().await;
    let (connection_id, actor_id) = admitted(&controller).await;
    let project = tempfile::TempDir::new().expect("a project directory of this test's own");
    let installing = |directory: &std::path::Path| {
        mutation_of(
            &temp,
            Method::AgentToolsInstall,
            ParamsValue::from_typed(&AgentToolsParams {
                agent: AgentTarget::Codex,
                scope: InstallScope::Project,
                project_dir: Nullable::some(directory.display().to_string()),
            })
            .expect("encodes"),
        )
    };
    // The door's future is large: it is kept off this case's own stack.
    let at_the_door = |mutation: MutationRequest| {
        let controller = Arc::clone(&controller);
        let actor_id = actor_id.clone();
        Box::pin(async move {
            told_now(
                &controller,
                connection_id,
                &mutation,
                controller.write_method(
                    &actor_id,
                    &mutation,
                    Method::AgentToolsInstall,
                    connection_id,
                    None,
                    Some(accepted(&controller)),
                    controller.admitted_revision(connection_id).ok(),
                ),
            )
            .await
        })
    };
    let mutation = installing(project.path());
    let first = at_the_door(mutation.clone()).await;
    assert!(
        refusal(&first).is_none(),
        "the first attempt installs: {first:?}"
    );
    assert_eq!(
        at_the_door(mutation.clone()).await,
        first,
        "with nothing owed the late attempt is answered from the record"
    );
    let reused = MutationRequest {
        action_id: mutation.action_id,
        ..installing(&project.path().join("another"))
    };
    assert_eq!(
        refusal(&at_the_door(reused.clone()).await)
            .expect("a reused identifier is a conflict")
            .code,
        ErrorCode::IdConflict
    );

    controller.hold_fence(true);
    let duplicate = at_the_door(mutation.clone()).await;
    told_as_not_shown(refusal(&duplicate).expect("a duplicate under a fence is refused"));
    let conflict = at_the_door(reused).await;
    refused_for_a_fence(
        refusal(&conflict).unwrap_or_else(|| panic!("the fence's own refusal: {conflict:?}")),
    );
    controller.hold_fence(false);
}

/// KR-REQ-09.09, the authority part: an agent-tool installation another attempt recorded after the
/// local door's own lookup found nothing is not given back to a late attempt while this host owes a
/// fence it could not raise, or to a connection whose registration was replaced after the revision
/// the attempt carries was read. What the host keeps of the action goes back under the same
/// authority whatever it is: the receipt, and the conflict a reused identifier meets. The control:
/// the same late attempt, with nothing owed, is answered from the record, and is again once the
/// fence is gone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_installation_recorded_before_a_late_attempts_lookup_is_not_given_back_while_a_fence_is_owed()
 {
    use kr_protocol::skill::{AgentTarget, AgentToolsParams, InstallScope};
    let (temp, controller, _clock) = daemon().await;
    let (connection_id, actor_id) = admitted(&controller).await;
    let captured = controller
        .admitted_revision(connection_id)
        .expect("the connection is registered");
    let project = tempfile::TempDir::new().expect("a project directory of this test's own");
    let installing = |directory: &std::path::Path| {
        mutation_of(
            &temp,
            Method::AgentToolsInstall,
            ParamsValue::from_typed(&AgentToolsParams {
                agent: AgentTarget::Codex,
                scope: InstallScope::Project,
                project_dir: Nullable::some(directory.display().to_string()),
            })
            .expect("encodes"),
        )
    };
    // The late attempt reaches the service itself, as one does that began before the record was
    // written: nothing in front of it has looked for the action.
    let attempt = |mutation: MutationRequest| {
        let controller = Arc::clone(&controller);
        let actor_id = actor_id.clone();
        async move {
            controller
                .write_method(
                    &actor_id,
                    &mutation,
                    Method::AgentToolsInstall,
                    connection_id,
                    None,
                    Some(accepted(&controller)),
                    Some(captured),
                )
                .await
                .into_answer_for_test()
        }
    };
    let mutation = installing(project.path());
    let first = attempt(mutation.clone()).await;
    assert!(
        refusal(&first).is_none(),
        "the first attempt installs: {first:?}"
    );

    let late = attempt(mutation.clone()).await;
    assert_eq!(
        late, first,
        "with nothing owed the late attempt is answered from the record"
    );
    let other = project.path().join("another");
    let reused = MutationRequest {
        action_id: mutation.action_id,
        ..installing(&other)
    };
    let conflict = attempt(reused.clone()).await;
    assert_eq!(
        refusal(&conflict)
            .unwrap_or_else(|| panic!("a reused identifier is a conflict: {conflict:?}"))
            .code,
        ErrorCode::IdConflict
    );

    controller.hold_fence(true);
    let refused = attempt(mutation.clone()).await;
    refused_for_a_fence(refusal(&refused).unwrap_or_else(|| {
        panic!("a fence this host owes stops the retained answer: {refused:?}")
    }));
    let refused = attempt(reused.clone()).await;
    refused_for_a_fence(refusal(&refused).unwrap_or_else(|| {
        panic!("a fence this host owes stops what it keeps of the action: {refused:?}")
    }));
    controller.hold_fence(false);
    let again = attempt(mutation.clone()).await;
    assert_eq!(again, first, "once the fence is gone it is answered again");

    // Another device's revocation replaces the registration after the late attempt's revision was
    // read.
    {
        let mut registry = controller.registry.lock().await;
        registry
            .advance_authority_revision()
            .expect("the revision advances");
        let revision = registry
            .authority_revision()
            .expect("the revision in force");
        for connection in controller.admitted_write().values_mut() {
            connection.admitted_revision = revision;
        }
    }
    let refused = attempt(mutation).await;
    let replaced = refusal(&refused).unwrap_or_else(|| {
        panic!("a registration replaced since stops the retained answer: {refused:?}")
    });
    assert_eq!(replaced.code, ErrorCode::PermissionDenied, "{replaced:?}");
    assert_eq!(
        replaced.message,
        crate::authority::AdmissionLapse::Revoked.to_string()
    );
}

/// KR-REQ-09.09, 09.12 and 26.16: an environment record change another attempt recorded is not
/// given back to a late attempt while this host owes a fence, including one that lands while the
/// answer is read, after the claim found the record. The control: with nothing owed, the same late
/// attempt is answered from the record.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_environment_change_recorded_before_a_late_attempts_claim_is_not_given_back_while_a_fence_is_owed()
 {
    use kr_protocol::identity::EnvironmentEnrolParams;
    let (temp, controller, _clock) = daemon().await;
    let (connection_id, actor_id) = admitted(&controller).await;
    let mutation = mutation_of(
        &temp,
        Method::EnvironmentEnrol,
        ParamsValue::from_typed(&EnvironmentEnrolParams {
            enrolment: enrolment_of(1),
        })
        .expect("encodes"),
    );
    let attempt = |controller: Arc<Controller>| {
        let actor_id = actor_id.clone();
        let mutation = mutation.clone();
        async move {
            controller
                .write_method(
                    &actor_id,
                    &mutation,
                    Method::EnvironmentEnrol,
                    connection_id,
                    None,
                    Some(accepted(&controller)),
                    controller.admitted_revision(connection_id).ok(),
                )
                .await
                .into_answer_for_test()
        }
    };
    let first = attempt(Arc::clone(&controller)).await;
    assert!(refusal(&first).is_none(), "the first attempt: {first:?}");
    let late = attempt(Arc::clone(&controller)).await;
    assert!(
        refusal(&late).is_none(),
        "with nothing owed the late attempt is answered from the record: {late:?}"
    );

    // The fence lands while the answer is being read, after the claim found the record, and so
    // after the check every environment method takes before it is claimed: the check that decides
    // is the one made with the answer in hand.
    let (arrived, release) = controller.pause_retained_lookup();
    let waiting = tokio::spawn(attempt(Arc::clone(&controller)));
    tokio::time::timeout(Duration::from_secs(30), arrived)
        .await
        .expect("the late attempt reaches the place it is stopped at")
        .expect("the pause is armed");
    controller.hold_fence(true);
    release.send(()).expect("the late attempt goes on");
    let refused = waiting.await.expect("the late attempt finishes");
    refused_for_a_fence(refusal(&refused).unwrap_or_else(|| {
        panic!("a fence that landed while the answer was read stops it: {refused:?}")
    }));
    controller.hold_fence(false);
    let answered = attempt(Arc::clone(&controller)).await;
    assert!(
        refusal(&answered).is_none(),
        "once the fence is gone it is answered again: {answered:?}"
    );
}

/// KR-REQ-03.13, KR-REQ-09.09, 09.12 and 26.16: a refresh from a connection that came over a
/// process bridge is refused before the platform is asked, and that refusal is kept under the
/// claim like any other outcome. Its retry finds the record and is given the refusal back only
/// while this host owes no fence, including one that lands while the answer is read. The control:
/// with nothing owed, the retry is answered from the record, with the bridge's refusal.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refresh_refused_for_the_bridge_it_came_over_is_not_given_back_while_a_fence_is_owed() {
    use kr_protocol::identity::EnvironmentRefreshParams;
    let (temp, controller, _clock) = daemon().await;
    let (connection_id, actor_id) = admitted(&controller).await;
    let mutation = mutation_of(
        &temp,
        Method::EnvironmentRefresh,
        ParamsValue::from_typed(&EnvironmentRefreshParams {
            environment_id: enrolment_of(2).environment_id,
            start: true,
        })
        .expect("encodes"),
    );
    let origin = kr_protocol::local::BridgeOrigin {
        environment_id: kr_protocol::ids::EnvironmentId::new(
            kr_protocol::scalars::Uuid::from_bytes([0x0a; 16]),
        ),
        ingress: kr_protocol::actor::ActorIngress::LocalIpc,
        clipboard_writes: false,
    };
    let attempt = |controller: Arc<Controller>| {
        let actor_id = actor_id.clone();
        let mutation = mutation.clone();
        async move {
            controller
                .write_method(
                    &actor_id,
                    &mutation,
                    Method::EnvironmentRefresh,
                    connection_id,
                    Some(origin),
                    Some(accepted(&controller)),
                    controller.admitted_revision(connection_id).ok(),
                )
                .await
                .into_answer_for_test()
        }
    };
    let refused_for_the_bridge = |answer: &ControlFrame| {
        let error =
            refusal(answer).unwrap_or_else(|| panic!("a bridged refresh is refused: {answer:?}"));
        assert_eq!(error.code, ErrorCode::PermissionDenied, "{error:?}");
        assert!(error.message.contains("process bridge"), "{error:?}");
    };
    refused_for_the_bridge(&attempt(Arc::clone(&controller)).await);
    refused_for_the_bridge(&attempt(Arc::clone(&controller)).await);

    // The fence lands while the answer is being read, after the claim found the record: the check
    // that decides is the one made with the answer in hand.
    let (arrived, release) = controller.pause_retained_lookup();
    let waiting = tokio::spawn(attempt(Arc::clone(&controller)));
    tokio::time::timeout(Duration::from_secs(30), arrived)
        .await
        .expect("the retry reaches the place it is stopped at")
        .expect("the pause is armed");
    controller.hold_fence(true);
    release.send(()).expect("the retry goes on");
    let refused = waiting.await.expect("the retry finishes");
    refused_for_a_fence(refusal(&refused).unwrap_or_else(|| {
        panic!("a fence that landed while the answer was read stops it: {refused:?}")
    }));
    controller.hold_fence(false);
    refused_for_the_bridge(&attempt(Arc::clone(&controller)).await);
}

/// KR-REQ-09.09, 09.12 and 26.16: a refresh of an ssh host asks its helper who it is by running
/// ssh, and a fence this host owes stops that, as it stops the platform command and the bridge of
/// the other access classes. The refusal is the fence's, and nothing is registered for the host.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_fence_this_host_owes_stops_an_ssh_hosts_refresh_before_its_helper_is_run() {
    use kr_protocol::identity::{
        EnvironmentAccess, EnvironmentEnrolParams, EnvironmentRefreshParams,
    };
    let (temp, controller, _clock) = daemon().await;
    let (connection_id, actor_id) = admitted(&controller).await;
    let carried = crate::authority::AdmittedMutation {
        connection_id,
        admitted_revision: controller
            .admitted_revision(connection_id)
            .expect("the connection is registered"),
        deadline: None,
    };
    let mut enrolment = enrolment_of(3);
    enrolment.access = EnvironmentAccess::SshHost;
    enrolment.target = "build.example".to_owned();
    let environment_id = enrolment.environment_id;
    let actor = super::routes::local_actor(actor_id, connection_id, controller.generation);
    controller
        .environment_record(
            &actor,
            false,
            &mutation_of(
                &temp,
                Method::EnvironmentEnrol,
                ParamsValue::from_typed(&EnvironmentEnrolParams { enrolment }).expect("encodes"),
            ),
            Method::EnvironmentEnrol,
            carried,
        )
        .await
        .into_answer_for_test()
        .expect("the ssh host is enrolled");

    controller.hold_fence(true);
    let refused = controller
        .environment_record(
            &actor,
            false,
            &mutation_of(
                &temp,
                Method::EnvironmentRefresh,
                ParamsValue::from_typed(&EnvironmentRefreshParams {
                    environment_id,
                    start: false,
                })
                .expect("encodes"),
            ),
            Method::EnvironmentRefresh,
            carried,
        )
        .await
        .into_answer_for_test()
        .expect_err("a refresh is stopped while a fence is owed");
    refused_for_a_fence(&refused.to_protocol_error());
}

/// KR-REQ-09.09, 09.12 and 26.16: what an ssh host's helper answered is written to the enrolment
/// record only while this host owes no fence. The control: with nothing owed, a refusal takes back
/// the scoped channel an earlier answer established. With a fence that lands after the helper has
/// answered, the refresh is refused for the fence and the channel stands. The refresh's actor is a
/// paired device's, which no helper is started for, so the answer is the refusal and nothing runs.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_fence_that_lands_after_an_ssh_hosts_helper_answered_stops_what_the_answer_would_write() {
    use kr_protocol::identity::{
        EnvironmentAccess, EnvironmentEnrolParams, EnvironmentRefreshParams,
    };
    let (temp, controller, _clock) = daemon().await;
    let (connection_id, actor_id) = admitted(&controller).await;
    let carried = crate::authority::AdmittedMutation {
        connection_id,
        admitted_revision: controller
            .admitted_revision(connection_id)
            .expect("the connection is registered"),
        deadline: None,
    };
    let mut enrolment = enrolment_of(4);
    enrolment.access = EnvironmentAccess::SshHost;
    enrolment.target = "build.example".to_owned();
    let environment_id = enrolment.environment_id;
    let mut actor = super::routes::local_actor(actor_id, connection_id, controller.generation);
    controller
        .environment_record(
            &actor,
            false,
            &mutation_of(
                &temp,
                Method::EnvironmentEnrol,
                ParamsValue::from_typed(&EnvironmentEnrolParams { enrolment }).expect("encodes"),
            ),
            Method::EnvironmentEnrol,
            carried,
        )
        .await
        .into_answer_for_test()
        .expect("the ssh host is enrolled");
    actor.ingress = kr_protocol::actor::ActorIngress::PairedDevice;

    let state_dir = controller.paths.state_dir().to_path_buf();
    // The scoped channel an earlier answer established, which a refusal takes back.
    let establish = || {
        crate::bridge::store::Store::with_locked(&state_dir, |store| {
            let instance = store
                .instance_of(environment_id)
                .expect("an approved record");
            store.record_bridge_outcome(
                environment_id,
                instance,
                crate::bridge::store::BridgeAnswer::Answered,
                0,
            )
        })
        .expect("the channel is recorded");
    };
    let scoped = || {
        crate::bridge::store::Store::with_locked(&state_dir, |store| {
            Ok(store
                .row_of(environment_id, 0)
                .expect("the record is there")
                .readiness
                .channel_scoped)
        })
        .expect("the record opens")
    };
    let refresh = || {
        let controller = Arc::clone(&controller);
        let actor = actor.clone();
        let mutation = mutation_of(
            &temp,
            Method::EnvironmentRefresh,
            ParamsValue::from_typed(&EnvironmentRefreshParams {
                environment_id,
                start: false,
            })
            .expect("encodes"),
        );
        async move {
            controller
                .environment_record(
                    &actor,
                    false,
                    &mutation,
                    Method::EnvironmentRefresh,
                    carried,
                )
                .await
        }
    };

    establish();
    assert!(scoped(), "the channel is established");
    refresh()
        .await
        .into_answer_for_test()
        .expect("with nothing owed the refresh is answered");
    assert!(
        !scoped(),
        "with nothing owed the refusal took the channel back"
    );

    establish();
    assert!(scoped(), "the channel is established again");
    let refused = stopped_after_the_environment_record_is_taken(&controller, refresh(), || {
        controller.hold_fence(true);
    })
    .await;
    controller.hold_fence(false);
    refused_for_a_fence(
        &refused
            .into_answer_for_test()
            .expect_err("a fence that landed after the answer stops its write")
            .to_protocol_error(),
    );
    assert!(
        scoped(),
        "what the answer would have written was not written"
    );
}

/// KR-REQ-09.09: a refresh of an environment that no process bridge reaches answers with the row
/// of the enrolment record and nothing the request did, so the service gives it as a copy of that
/// record; the enrolment of that environment is the request's own effect.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refresh_of_an_environment_no_bridge_reaches_is_given_as_a_copy_of_its_record() {
    use kr_protocol::identity::{
        EnvironmentAccess, EnvironmentEnrolParams, EnvironmentRefreshParams,
        EnvironmentRefreshResult,
    };
    let rig = Refreshing::start().await;
    let actor = super::routes::local_actor(
        rig.actor_id.clone(),
        rig.connection_id,
        rig.controller.generation,
    );
    let mut enrolment = enrolment_of(9);
    enrolment.access = EnvironmentAccess::PairedHost;
    let environment_id = enrolment.environment_id;

    let enrol = mutation_of(
        &rig.temp,
        Method::EnvironmentEnrol,
        ParamsValue::from_typed(&EnvironmentEnrolParams { enrolment }).expect("encodes"),
    );
    let enrolled = rig
        .controller
        .environment_record(&actor, false, &enrol, Method::EnvironmentEnrol, rig.carried)
        .await;
    assert!(
        !enrolled.is_copied() && !enrolled.is_withheld(),
        "an enrolment is what this request did"
    );
    enrolled.into_answer_for_test().expect("enrolled");

    let refresh = mutation_of(
        &rig.temp,
        Method::EnvironmentRefresh,
        ParamsValue::from_typed(&EnvironmentRefreshParams {
            environment_id,
            start: false,
        })
        .expect("encodes"),
    );
    let refreshed = rig
        .controller
        .environment_record(
            &actor,
            false,
            &refresh,
            Method::EnvironmentRefresh,
            rig.carried,
        )
        .await;
    assert!(
        refreshed.is_copied(),
        "the row of an environment no bridge reaches is the record's"
    );
    let result: EnvironmentRefreshResult = refreshed
        .into_answer_for_test()
        .expect("a refresh is answered")
        .to_typed()
        .expect("a result");
    assert!(!result.started);
    assert!(
        result.connection.contains("process bridge"),
        "{}",
        result.connection
    );
}

/// KR-REQ-09.09: an installation answers a repeat from the action record it kept, so the service
/// gives the repeat as a copy; a record it cannot read says that a record exists, so that is a
/// copy too. The first attempt is the request's own effect.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_installation_answered_from_its_record_is_given_as_a_copy() {
    use kr_protocol::skill::{AgentTarget, AgentToolsParams, InstallScope};

    /// The files under `directory` that hold a finished action's record.
    fn action_records(directory: &std::path::Path, found: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(directory).expect("a directory reads") {
            let path = entry.expect("an entry").path();
            if path.is_dir() {
                action_records(&path, found);
            } else if let Ok(text) = std::fs::read_to_string(&path)
                && let Ok(record) = serde_json::from_str::<serde_json::Value>(&text)
                && record.get("state").and_then(serde_json::Value::as_str) == Some("applied")
                && record.get("digest").is_some()
            {
                found.push(path);
            }
        }
    }

    let (temp, controller, _clock) = daemon().await;
    let (connection_id, actor_id) = admitted(&controller).await;
    let carried = crate::authority::AdmittedMutation {
        connection_id,
        admitted_revision: controller
            .admitted_revision(connection_id)
            .expect("the connection is registered"),
        deadline: controller.clock.now().checked_add(Duration::from_secs(60)),
    };
    let project = tempfile::TempDir::new().expect("a project directory of this test's own");
    let mutation = mutation_of(
        &temp,
        Method::AgentToolsInstall,
        ParamsValue::from_typed(&AgentToolsParams {
            agent: AgentTarget::Codex,
            scope: InstallScope::Project,
            project_dir: Nullable::some(project.path().display().to_string()),
        })
        .expect("encodes"),
    );
    let install =
        || controller.agent_tools_change(&actor_id, &mutation, Method::AgentToolsInstall, carried);

    let first = install().await;
    assert!(
        !first.is_copied() && !first.is_withheld(),
        "the first attempt is what this request did"
    );
    first
        .into_answer_for_test()
        .expect("the first attempt installs");

    let repeat = install().await;
    assert!(repeat.is_copied(), "a repeat is the record's answer");
    repeat.into_answer_for_test().expect("a repeat is answered");

    let mut records = Vec::new();
    action_records(controller.paths.state_dir(), &mut records);
    assert_eq!(records.len(), 1, "one action record: {records:?}");
    std::fs::write(&records[0], "not a record").expect("the record is spoiled");
    let unread = install().await;
    assert!(
        unread.is_copied(),
        "a record this host cannot read says a record exists"
    );
    unread
        .into_answer_for_test()
        .expect_err("an unreadable record is not an answer");
}

/// KR-REQ-09.09: what `organisation.policy.apply` answers is made from the policies the host holds,
/// which were applied earlier, so the service gives every answer of it as a copy, a refusal
/// included.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn what_organisation_policy_apply_answers_is_given_as_a_copy_of_the_policies_held() {
    let (temp, controller, _clock) = daemon().await;
    let (connection_id, _actor_id) = admitted(&controller).await;
    let carried = crate::authority::AdmittedMutation {
        connection_id,
        admitted_revision: controller
            .admitted_revision(connection_id)
            .expect("the connection is registered"),
        deadline: controller.clock.now().checked_add(Duration::from_secs(60)),
    };
    let given = controller
        .organisation_policy_apply(
            &mutation_of(&temp, Method::OrganisationPolicyApply, ParamsValue::empty()),
            carried,
        )
        .await;
    assert!(given.is_copied(), "the answer derives from policies held");
    given
        .into_answer_for_test()
        .expect_err("a request that names no policy is refused");
}

/// KR-REQ-09.09: a request whose envelope and stored object name different sessions is refused from
/// what the transfer journal stores, so that refusal is what a record says and is given back as a
/// copy of it, not as the request's own refusal.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_refusal_from_a_stored_subject_is_given_back_as_a_copy_of_the_record() {
    use kr_protocol::transfer::{DraftCreateParams, DraftCreateResult, DraftUpdateParams};
    let (temp, controller, _clock) = daemon().await;
    let (connection_id, actor_id) = admitted(&controller).await;
    let captured = controller
        .admitted_revision(connection_id)
        .expect("the connection is registered");
    let create = mutation_of(
        &temp,
        Method::DraftCreate,
        ParamsValue::from_typed(&DraftCreateParams {
            environment_id: temp.environment_id(),
            device_id: Nullable::null(),
            session_id: Nullable::null(),
            application_instance_id: Nullable::null(),
            text: "a draft that belongs to no session".to_owned(),
        })
        .expect("encodes"),
    );
    let ControlFrame::Response(response) = controller
        .write_method(
            &actor_id,
            &create,
            Method::DraftCreate,
            connection_id,
            None,
            Some(accepted(&controller)),
            Some(captured),
        )
        .await
        .into_answer_for_test()
    else {
        panic!("a create is answered with a response");
    };
    let Outcome::Ok(created) = response.outcome else {
        panic!("the draft is created: {response:?}");
    };
    let created: DraftCreateResult = created.to_typed().expect("decodes");

    let update = MutationRequest {
        target: ActionTarget {
            environment_id: temp.environment_id(),
            session_id: Nullable::some(kr_protocol::ids::SessionId::new(kr_ipc::new_uuid())),
            session_epoch: Nullable::some(kr_protocol::ids::SessionEpoch::V1),
            application_instance_id: Nullable::null(),
            agent_binding_revision: Nullable::null(),
        },
        ..mutation_of(
            &temp,
            Method::DraftUpdate,
            ParamsValue::from_typed(&DraftUpdateParams {
                draft_id: created.draft.draft_id,
                expected_revision: created.draft.revision,
                text: "changed".to_owned(),
            })
            .expect("encodes"),
        )
    };
    let refusal = controller
        .transfer()
        .check_subject_of_record(&actor_id, &update, Method::DraftUpdate)
        .await
        .expect("the stored subject is read")
        .expect("the request and the draft name different sessions")
        .copied();
    assert!(
        refusal.is_copied(),
        "the refusal is what the journal stores"
    );
    assert_eq!(
        refusal.into_answer_for_test().code,
        ErrorCode::InvalidArgument
    );
}

/// The file that holds an installation's own record: the one that lists what was changed.
fn installation_record(directory: &std::path::Path) -> Option<std::path::PathBuf> {
    for entry in std::fs::read_dir(directory).expect("a directory reads") {
        let path = entry.expect("an entry").path();
        if path.is_dir() {
            if let Some(found) = installation_record(&path) {
                return Some(found);
            }
        } else if let Ok(text) = std::fs::read_to_string(&path)
            && let Ok(record) = serde_json::from_str::<serde_json::Value>(&text)
            && record.get("manifest").is_some()
        {
            return Some(path);
        }
    }
    None
}

/// An installation of the Codex tools at project scope in `project`, under a fresh identifier.
fn installation_in(temp: &kr_ipc::testing::TempHost, project: &std::path::Path) -> MutationRequest {
    use kr_protocol::skill::{AgentTarget, AgentToolsParams, InstallScope};

    mutation_of(
        temp,
        Method::AgentToolsInstall,
        ParamsValue::from_typed(&AgentToolsParams {
            agent: AgentTarget::Codex,
            scope: InstallScope::Project,
            project_dir: Nullable::some(project.display().to_string()),
        })
        .expect("encodes"),
    )
}

/// The admission a first attempt on `connection_id` carries.
fn carried_on(
    controller: &Controller,
    connection_id: ConnectionId,
) -> crate::authority::AdmittedMutation {
    crate::authority::AdmittedMutation {
        connection_id,
        admitted_revision: controller
            .admitted_revision(connection_id)
            .expect("the connection is registered"),
        deadline: controller.clock.now().checked_add(Duration::from_secs(60)),
    }
}

/// KR-REQ-09.09: an installation record this host cannot read says that a record exists, so the
/// refusal is given as a copy of it, not as the request's own refusal, whether the record's bytes
/// cannot be read or they do not parse.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_installation_record_this_host_cannot_read_is_given_as_a_copy() {
    let (temp, controller, _clock) = daemon().await;
    let (connection_id, actor_id) = admitted(&controller).await;
    let carried = carried_on(&controller, connection_id);
    let project = tempfile::TempDir::new().expect("a project directory of this test's own");
    controller
        .agent_tools_change(
            &actor_id,
            &installation_in(&temp, project.path()),
            Method::AgentToolsInstall,
            carried,
        )
        .await
        .into_answer_for_test()
        .expect("the first attempt installs");

    // A different request for the same installation meets the record the first one left, which
    // is spoiled in two ways: bytes that are no text, and text that is no record.
    let record = installation_record(controller.paths.state_dir())
        .expect("the installation left its record");
    for spoiled in [&[0xff_u8, 0xfe][..], b"this is not a record".as_slice()] {
        std::fs::write(&record, spoiled).expect("the record is spoiled");
        let unread = controller
            .agent_tools_change(
                &actor_id,
                &installation_in(&temp, project.path()),
                Method::AgentToolsInstall,
                carried,
            )
            .await;
        assert!(
            unread.is_copied(),
            "a record this host cannot read says a record exists"
        );
        unread
            .into_answer_for_test()
            .expect_err("an unreadable record is no answer");
    }
}

/// KR-REQ-09.09: a file of the agent's own that this host cannot read says nothing of a record, so
/// the refusal is the request's own, not a copy.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_file_of_the_agents_this_host_cannot_read_is_the_requests_own_refusal() {
    let (temp, controller, _clock) = daemon().await;
    let (connection_id, actor_id) = admitted(&controller).await;
    let project = tempfile::TempDir::new().expect("a project directory of this test's own");
    // The skill's documentation is a directory where the installation would put a file, which
    // reading as a file refuses.
    let skills = project
        .path()
        .join(".agents")
        .join("skills")
        .join(kr_protocol::skill::SKILL_NAME);
    std::fs::create_dir_all(skills.join("SKILL.md")).expect("a directory stands in the way");

    let refused = controller
        .agent_tools_change(
            &actor_id,
            &installation_in(&temp, project.path()),
            Method::AgentToolsInstall,
            carried_on(&controller, connection_id),
        )
        .await;
    assert!(
        !refused.is_copied() && !refused.is_withheld(),
        "nothing about the request's own files names a record"
    );
    assert!(matches!(
        refused.into_answer_for_test(),
        Err(crate::error::ControllerError::Storage { .. })
    ));
}

use super::the_end_of_a_write_is_told_under_its_authority::not_shown;

/// What the door tells of `mutation`'s first admission once its route has answered. With `fence`,
/// this host comes to owe a fence after the route has answered and before the answer is told, which
/// is where the door's strict check meets it.
async fn performed_with_a_fence_landing_before_the_telling(
    controller: &Arc<Controller>,
    connection_id: ConnectionId,
    actor_id: &ActorId,
    mutation: &MutationRequest,
    fence: bool,
) -> ControlFrame {
    let pause = fence.then(|| controller.pause_before_a_reply_is_told());
    let performing = tokio::spawn({
        let (controller, actor_id, mutation) =
            (Arc::clone(controller), actor_id.clone(), mutation.clone());
        async move {
            let method = mutation.method.method().expect("a method");
            told_now(
                &controller,
                connection_id,
                &mutation,
                controller.write_method(
                    &actor_id,
                    &mutation,
                    method,
                    connection_id,
                    None,
                    Some(accepted(&controller)),
                    controller.admitted_revision(connection_id).ok(),
                ),
            )
            .await
        }
    });
    if let Some((arrived, release)) = pause {
        tokio::time::timeout(Duration::from_secs(30), arrived)
            .await
            .expect("the route answers")
            .expect("the pause is armed");
        controller.hold_fence(true);
        release.send(()).expect("the door goes on");
    }
    let told = performing.await.expect("the door tells it");
    controller.hold_fence(false);
    told
}

/// KR-REQ-09.09: what `organisation.policy.apply` answers is made from the policies the host holds,
/// so the door tells it only while no fence is owed: with none, a request that names no policy is
/// given its refusal as it is; with a fence owed once the route has answered, it is not shown.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn what_organisation_policy_apply_answers_is_not_shown_when_a_fence_lands_after_the_read() {
    let (temp, controller, _clock) = daemon().await;
    let (connection_id, actor_id) = admitted(&controller).await;
    let mutation = mutation_of(&temp, Method::OrganisationPolicyApply, ParamsValue::empty());

    let told = performed_with_a_fence_landing_before_the_telling(
        &controller,
        connection_id,
        &actor_id,
        &mutation,
        false,
    )
    .await;
    let given = refusal(&told).unwrap_or_else(|| panic!("a request naming no policy: {told:?}"));
    assert_ne!(given.code, ErrorCode::OutcomeUnknown, "{given:?}");

    let told = performed_with_a_fence_landing_before_the_telling(
        &controller,
        connection_id,
        &actor_id,
        &mutation,
        true,
    )
    .await;
    not_shown(&told);
}

/// KR-REQ-09.09: the row a refresh answers for an environment that no process bridge reaches is the
/// enrolment record's, so the door tells it only while no fence is owed: with none, the refresh is
/// answered; with a fence owed once the route has answered, it is not shown.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_row_a_refresh_answers_from_a_record_is_not_shown_when_a_fence_lands_after_the_read() {
    use kr_protocol::identity::{
        EnvironmentAccess, EnvironmentEnrolParams, EnvironmentRefreshParams,
    };
    let rig = Refreshing::start().await;
    let mut enrolment = enrolment_of(9);
    enrolment.access = EnvironmentAccess::PairedHost;
    let environment_id = enrolment.environment_id;
    let enrol = mutation_of(
        &rig.temp,
        Method::EnvironmentEnrol,
        ParamsValue::from_typed(&EnvironmentEnrolParams { enrolment }).expect("encodes"),
    );
    let enrolled = performed_with_a_fence_landing_before_the_telling(
        &rig.controller,
        rig.connection_id,
        &rig.actor_id,
        &enrol,
        false,
    )
    .await;
    assert!(refusal(&enrolled).is_none(), "enrolled: {enrolled:?}");

    let refresh = || {
        mutation_of(
            &rig.temp,
            Method::EnvironmentRefresh,
            ParamsValue::from_typed(&EnvironmentRefreshParams {
                environment_id,
                start: false,
            })
            .expect("encodes"),
        )
    };
    let told = performed_with_a_fence_landing_before_the_telling(
        &rig.controller,
        rig.connection_id,
        &rig.actor_id,
        &refresh(),
        false,
    )
    .await;
    assert!(
        refusal(&told).is_none(),
        "the refresh is answered: {told:?}"
    );
    let told = performed_with_a_fence_landing_before_the_telling(
        &rig.controller,
        rig.connection_id,
        &rig.actor_id,
        &refresh(),
        true,
    )
    .await;
    not_shown(&told);
}

/// KR-REQ-09.09: an installation record this host cannot read says that a record exists, so the
/// refusal is the record's and the door tells it only while no fence is owed: with none, the
/// refusal is given as it is; with a fence owed once the route has answered, it is not shown.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_installation_record_this_host_cannot_read_is_not_shown_when_a_fence_lands_after_the_read()
 {
    let (temp, controller, _clock) = daemon().await;
    let (connection_id, actor_id) = admitted(&controller).await;
    let project = tempfile::TempDir::new().expect("a project directory of this test's own");
    let installed = performed_with_a_fence_landing_before_the_telling(
        &controller,
        connection_id,
        &actor_id,
        &installation_in(&temp, project.path()),
        false,
    )
    .await;
    assert!(refusal(&installed).is_none(), "installed: {installed:?}");
    let record = installation_record(controller.paths.state_dir())
        .expect("the installation left its record");
    std::fs::write(&record, b"this is not a record").expect("the record is spoiled");

    let told = performed_with_a_fence_landing_before_the_telling(
        &controller,
        connection_id,
        &actor_id,
        &installation_in(&temp, project.path()),
        false,
    )
    .await;
    let given =
        refusal(&told).unwrap_or_else(|| panic!("an unreadable record is no answer: {told:?}"));
    assert_ne!(given.code, ErrorCode::OutcomeUnknown, "{given:?}");
    let told = performed_with_a_fence_landing_before_the_telling(
        &controller,
        connection_id,
        &actor_id,
        &installation_in(&temp, project.path()),
        true,
    )
    .await;
    not_shown(&told);
}

/// KR-REQ-09.09: the refusal that a request and a stored object name different sessions is what the
/// transfer journal stores, so the door tells it only while no fence is owed: with none, the refusal
/// is given as it is; with a fence owed once the route has answered, it is not shown.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_refusal_from_a_stored_subject_is_not_shown_when_a_fence_lands_after_the_read() {
    use kr_protocol::transfer::{DraftCreateParams, DraftCreateResult, DraftUpdateParams};
    let (temp, controller, _clock) = daemon().await;
    let (connection_id, actor_id) = admitted(&controller).await;
    let create = mutation_of(
        &temp,
        Method::DraftCreate,
        ParamsValue::from_typed(&DraftCreateParams {
            environment_id: temp.environment_id(),
            device_id: Nullable::null(),
            session_id: Nullable::null(),
            application_instance_id: Nullable::null(),
            text: "a draft that belongs to no session".to_owned(),
        })
        .expect("encodes"),
    );
    let created = performed_with_a_fence_landing_before_the_telling(
        &controller,
        connection_id,
        &actor_id,
        &create,
        false,
    )
    .await;
    let ControlFrame::Response(response) = created else {
        panic!("a create is answered with a response");
    };
    let Outcome::Ok(created) = response.outcome else {
        panic!("the draft is created: {response:?}");
    };
    let created: DraftCreateResult = created.to_typed().expect("decodes");

    let update = || MutationRequest {
        target: ActionTarget {
            environment_id: temp.environment_id(),
            session_id: Nullable::some(kr_protocol::ids::SessionId::new(kr_ipc::new_uuid())),
            session_epoch: Nullable::some(kr_protocol::ids::SessionEpoch::V1),
            application_instance_id: Nullable::null(),
            agent_binding_revision: Nullable::null(),
        },
        ..mutation_of(
            &temp,
            Method::DraftUpdate,
            ParamsValue::from_typed(&DraftUpdateParams {
                draft_id: created.draft.draft_id,
                expected_revision: created.draft.revision,
                text: "changed".to_owned(),
            })
            .expect("encodes"),
        )
    };
    let told = performed_with_a_fence_landing_before_the_telling(
        &controller,
        connection_id,
        &actor_id,
        &update(),
        false,
    )
    .await;
    let given = refusal(&told).unwrap_or_else(|| panic!("the subjects differ: {told:?}"));
    assert_eq!(given.code, ErrorCode::InvalidArgument, "{given:?}");
    let told = performed_with_a_fence_landing_before_the_telling(
        &controller,
        connection_id,
        &actor_id,
        &update(),
        true,
    )
    .await;
    not_shown(&told);
}

/// KR-REQ-09.09: a repeat of `account.sign_out` is answered from the claim the first attempt left.
/// The method takes no admission into the service, so the door's entry check is all that stands
/// before the lookup, and a fence this host comes to owe at the lookup, after that check, is what
/// the door's strict check meets: the repeat is not shown. The control: with no fence the repeat is
/// given the first attempt's answer, and is again once the fence is gone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_sign_out_answered_from_its_claim_is_not_shown_when_a_fence_lands_at_the_lookup() {
    use super::a_recorded_answer_another_copy_wrote::answered_after_a_fence_lands_at_the_check;
    let (temp, controller, _clock) = daemon().await;
    let (connection_id, actor_id) = admitted(&controller).await;
    let mutation = mutation_of(
        &temp,
        Method::AccountSignOut,
        ParamsValue::from_typed(&kr_protocol::host_account::AccountSignOutParams {})
            .expect("encodes"),
    );
    // Each attempt runs on a task of its own, so that the door's future is not held on the case's
    // stack beside the pause that stops it.
    let attempt = || {
        let (controller, actor_id, mutation) =
            (Arc::clone(&controller), actor_id.clone(), mutation.clone());
        async move {
            tokio::spawn(async move {
                told_now(
                    &controller,
                    connection_id,
                    &mutation,
                    controller.write_method(
                        &actor_id,
                        &mutation,
                        Method::AccountSignOut,
                        connection_id,
                        None,
                        Some(accepted(&controller)),
                        controller.admitted_revision(connection_id).ok(),
                    ),
                )
                .await
            })
            .await
            .expect("the door tells it")
        }
    };
    let first = attempt().await;
    assert!(refusal(&first).is_none(), "the first attempt: {first:?}");
    let again = attempt().await;
    assert_eq!(again, first, "with no fence the repeat is given the record");

    let told = answered_after_a_fence_lands_at_the_check(&controller, attempt()).await;
    not_shown(&told);

    let after = attempt().await;
    assert_eq!(after, first, "once the fence is gone it is answered again");
}
