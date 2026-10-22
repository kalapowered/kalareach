//! The sessions a daemon finds recorded in an earlier boot, when another recovery holds one.
//!
//! A worker row left by an earlier boot is closed as the host's restart. Where another recovery
//! holds the session's stores, the daemon leaves the row as it is, and the record of the earlier boot
//! with it, so that the next start in the same boot closes the session and gives it the reason it
//! has.

use kr_protocol::identity::{BootIdentity, BootIdentitySource};
use kr_protocol::ids::{ActorId, SessionId};
use kr_protocol::scalars::{Bytes, Digest256};
use kr_protocol::session::ClosureReason;

use crate::service::Controller;
use crate::service::net::tests::{daemon, setup, started, stopped};

/// Records a worker of a session whose process has ended, as an earlier boot left it.
async fn recorded_ended_worker(
    controller: &Controller,
    temp: &kr_ipc::testing::TempHost,
) -> SessionId {
    let process = kr_ipc::identity::ended_process_identity(4_000_003);
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
/// daemon that starts over it, and the record of that boot stays, so the next daemon of the same boot
/// closes it as the host's restart once the recovery is done. Without the record staying, the next
/// start finds this boot already recorded and never looks at the session as one of an earlier boot.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_session_another_recovery_holds_is_closed_as_the_hosts_restart_by_the_next_start() {
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
    stopped(controller).await;

    drop(recovery);
    let controller = started(|| Controller::start(setup(&temp, next_boot.clone()))).await;
    let closure = controller
        .registry
        .lock()
        .await
        .closure(session_id)
        .expect("the registry answers")
        .expect("the next start closed the session");
    assert_eq!(closure.reason, ClosureReason::HostShutdown);
}
