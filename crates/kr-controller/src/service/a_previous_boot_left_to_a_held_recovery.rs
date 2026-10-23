//! The sessions a daemon finds recorded in an earlier boot, when another recovery holds one.
//!
//! A worker row left by an earlier boot is closed as the host's restart. Where another recovery
//! holds the session's stores, the daemon leaves the row as it is and records the boot it runs in
//! all the same, so that nothing the boot makes is read as a session of the one before. The session
//! is closed with the reason it has when its worker is next found gone.

use kr_protocol::identity::{BootIdentity, BootIdentitySource};
use kr_protocol::ids::{ActorId, SessionId};
use kr_protocol::scalars::{Bytes, Digest256};
use kr_protocol::session::ClosureReason;

use crate::service::Controller;
use crate::service::net::tests::{daemon, setup, started, stopped};

/// Records a worker of a session whose process has ended, as an earlier boot left it.
pub(super) async fn recorded_ended_worker(
    controller: &Controller,
    temp: &kr_ipc::testing::TempHost,
) -> SessionId {
    recorded_worker(
        controller,
        temp,
        kr_ipc::identity::ended_process_identity(4_000_003),
    )
    .await
}

/// Records a worker of a session whose process is `process`, as an earlier boot left it.
async fn recorded_worker(
    controller: &Controller,
    temp: &kr_ipc::testing::TempHost,
    process: kr_protocol::identity::ProcessStartIdentity,
) -> SessionId {
    let mut registry = controller.registry.lock().await;
    let reservation = registry
        .reserve(
            &ActorId::new("local:test").expect("a principal"),
            kr_ipc::new_uuid(),
            Digest256::from_bytes([0x6e; 32]),
            &kr_cbor::to_canonical_vec(&super::a_create_that_launches_nothing::create_params(
                temp.environment_id(),
            ))
            .expect("encodes"),
            kr_ipc::now_ms(),
        )
        .expect("reserves")
        .reservation;
    registry
        .record_launch(reservation.reservation_id, &process)
        .expect("records the launcher");
    registry
        .set_phase(
            reservation.reservation_id,
            crate::registry::LaunchPhase::Spawned,
        )
        .expect("spawned");
    let key = *kr_crypto::keys::AuthorisationKeyPair::generate()
        .expect("a key")
        .public();
    registry
        .claim_rendezvous(reservation.reservation_id, key)
        .expect("claims");
    registry
        .record_worker(
            reservation.reservation_id,
            &crate::registry::WorkerRecord {
                session_id: reservation.session_id,
                display_number: reservation.display_number,
                public_key: key,
                process_identity: process,
                endpoint: temp
                    .environment()
                    .worker_endpoint(reservation.display_number)
                    .expect("an endpoint")
                    .as_text(),
                profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
                state: kr_protocol::session::SessionState::Live,
                acknowledged_revision: kr_protocol::ids::AuthorityRevision::new(0),
            },
            &kr_protocol::identity::DesktopBinding::none(),
        )
        .expect("records the worker");
    reservation.session_id
}

/// KR-REQ-24.18: a session of an earlier boot that another recovery holds is left as it is by the
/// daemon that starts over it, and closed as the host's restart, not as a crash, once the recovery
/// is done and its dead worker is reconciled.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_session_another_recovery_holds_is_closed_as_the_hosts_restart_once_the_recovery_is_done()
{
    let temp = kr_ipc::testing::TempHost::create();
    let controller = daemon(&temp).await;
    let session_id = recorded_ended_worker(&controller, &temp).await;
    let display = controller
        .registry
        .lock()
        .await
        .workers()
        .expect("the registry answers")
        .into_iter()
        .find(|row| row.session_id == session_id)
        .expect("the worker is recorded")
        .display_number;
    stopped(controller).await;

    let next_boot = BootIdentity {
        source: BootIdentitySource::MacosBootSessionUuid,
        value: Bytes::new(vec![0x5c; 16]),
    };
    let archive = crate::archive::ArchiveService::new(temp.environment());
    let ended = kr_ipc::identity::ended_process_identity(4_000_003);
    let recovery = archive
        .take_ownership(session_id, display, &ended)
        .expect("another recovery holds the session");

    let controller = started(|| Controller::start(setup(&temp, next_boot.clone()))).await;
    assert!(
        controller
            .registry
            .lock()
            .await
            .closure(session_id)
            .expect("the registry answers")
            .is_none(),
        "a session another recovery holds is not closed from under it"
    );

    drop(recovery);
    let closure = controller
        .reconcile(session_id)
        .await
        .expect("the registry answers")
        .expect("the dead worker's session is closed once nothing holds it");
    assert_eq!(closure.reason, ClosureReason::HostShutdown);
    assert!(
        closure.surviving.is_empty(),
        "a worker of an earlier boot owned nothing that outlived the boot: {closure:?}"
    );
    assert!(
        !controller
            .project()
            .service()
            .holds()
            .has_session(session_id),
        "and its session is no longer a writer"
    );
}

/// KR-REQ-24.18: a worker the kernel says is running is not one an earlier boot left, whatever the
/// record of the boot says, and the daemon that starts over it closes nothing and unpublishes
/// nothing of it. Without the skip, the start would write the host's restart over a session whose
/// worker runs on.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_worker_the_kernel_says_is_running_is_not_closed_as_the_hosts_restart() {
    let temp = kr_ipc::testing::TempHost::create();
    let controller = daemon(&temp).await;
    let running = kr_ipc::identity::current_process_start_identity().expect("a process identity");
    let session_id = recorded_worker(&controller, &temp, running).await;
    stopped(controller).await;

    let next_boot = BootIdentity {
        source: BootIdentitySource::MacosBootSessionUuid,
        value: Bytes::new(vec![0x5d; 16]),
    };
    let controller = started(|| Controller::start(setup(&temp, next_boot.clone()))).await;
    let registry = controller.registry.lock().await;
    assert!(
        registry
            .closure(session_id)
            .expect("the registry answers")
            .is_none(),
        "a session whose worker runs is not closed by the start of another boot"
    );
    assert!(
        registry
            .workers()
            .expect("the registry answers")
            .iter()
            .any(|row| row.session_id == session_id),
        "and its worker row is kept"
    );
}
