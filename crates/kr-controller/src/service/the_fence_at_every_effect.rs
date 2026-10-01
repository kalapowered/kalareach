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
async fn daemon() -> (kr_ipc::testing::TempHost, Arc<Controller>, ManualClock) {
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
async fn admitted(controller: &Controller) -> (ConnectionId, ActorId) {
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
        )
        .await
        .expect("the connection is registered");
    (connection_id, actor_id)
}

/// A mutation that sets privacy mode, under a fresh action identifier.
fn privacy_request(temp: &kr_ipc::testing::TempHost) -> MutationRequest {
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
        params: ParamsValue::from_typed(&PrivacySetParams { enabled: true }).expect("encodes"),
    }
}

/// The deadline a first admission of a mutation carries in these tests.
fn accepted(controller: &Controller) -> AcceptedDeadline {
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
    let mutation = privacy_request(temp);
    let revision = controller
        .admitted_revision(connection_id)
        .expect("the connection is registered");
    let answered = controller
        .write_method(
            &actor_id,
            &mutation,
            Method::PrivacySet,
            connection_id,
            Some(accepted(controller)),
            Some(revision),
        )
        .await;
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

/// The refusal a frame carries, when it carries one.
fn refusal(frame: &ControlFrame) -> Option<&kr_protocol::error::ProtocolError> {
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
        .perform(&actor_id, connection_id, mutation.clone())
        .await;
    assert!(
        refusal(&answered).is_none(),
        "with no fence owed the retry is answered: {answered:?}"
    );

    controller.hold_fence(true);
    let refused = controller
        .perform(&actor_id, connection_id, mutation.clone())
        .await;
    let error = refusal(&refused).unwrap_or_else(|| {
        panic!("a retained answer is not given back while a fence is owed: {refused:?}")
    });
    assert_eq!(error.code, ErrorCode::PermissionDenied, "{error:?}");
    assert!(error.message.contains("fence"), "{error:?}");

    controller.hold_fence(false);
    let answered = controller.perform(&actor_id, connection_id, mutation).await;
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
        async move { controller.perform(&actor_id, connection_id, mutation).await }
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
        let mut registrations = controller.admitted_table();
        for connection in registrations.values_mut() {
            connection.admitted_revision = revision;
        }
    }
    release.send(()).expect("the retry goes on");

    let refused = retrying.await.expect("the retry finishes");
    let error = refusal(&refused).unwrap_or_else(|| {
        panic!("a retry admitted before the replacement is not answered after it: {refused:?}")
    });
    assert_eq!(error.code, ErrorCode::PermissionDenied, "{error:?}");
    assert_eq!(
        error.message,
        crate::authority::AdmissionLapse::Revoked.to_string()
    );
}

/// KR-REQ-09.12: a retained answer stays readable after the window that admitted its action has
/// gone, because the check it is asked is the one a receipt needs and carries no deadline.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_retained_answer_outlives_the_window_that_admitted_its_action() {
    let (temp, controller, clock) = daemon().await;
    let (connection_id, actor_id, mutation) = performed_once(&temp, &controller).await;

    clock.advance(STANDING * 10);

    let answered = controller.perform(&actor_id, connection_id, mutation).await;
    assert!(
        refusal(&answered).is_none(),
        "the receipt is read after its window is gone: {answered:?}"
    );
}

/// Another device's revocation: the revision advances and every surviving registration is stamped
/// with it, which is what a revocation that withdraws one device does to the rest.
async fn another_devices_revocation_lands(controller: &Controller) {
    let mut registry = controller.registry.lock().await;
    registry
        .advance_authority_revision()
        .expect("the revision advances");
    let revision = registry
        .authority_revision()
        .expect("the revision in force");
    let mut registrations = controller.admitted_table();
    for connection in registrations.values_mut() {
        connection.admitted_revision = revision;
    }
}

/// A supervisor that counts the launches it is asked for, and starts nothing.
#[derive(Debug, Default)]
struct CountingSupervisor {
    asked: Arc<std::sync::atomic::AtomicUsize>,
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
            Some(accepted(&controller)),
            Some(captured),
        )
        .await;
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
            Some(accepted(&controller)),
            Some(current),
        )
        .await;
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
            Some(window),
            Some(captured),
        )
        .await;
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
            Some(window),
            Some(current),
        )
        .await;
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
    let answered = controller
        .write_method(
            &actor_id,
            &stale,
            Method::DeviceRevoke,
            connection_id,
            Some(accepted(&controller)),
            Some(captured),
        )
        .await;
    let error = refusal(&answered).unwrap_or_else(|| {
        panic!("a change admitted before the revocation is refused: {answered:?}")
    });
    assert_eq!(error.code, ErrorCode::PermissionDenied, "{error:?}");
    assert_eq!(
        error.message,
        crate::authority::AdmissionLapse::Revoked.to_string()
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
            Some(accepted(&controller)),
            Some(current),
        )
        .await;
    assert!(
        refusal(&answered).is_none(),
        "a change under the revision in force is performed: {answered:?}"
    );
}
