//! The answer to a revocation made by a paired device.
//!
//! The barrier a revocation raises is host-wide: it names every worker the host holds, a worker's
//! session, and the actions its fence named. A device may know of the sessions its grants reach and
//! no others, so the answer it is given names the workers of the sessions the revoked grants cover.

use kr_protocol::ids::{DeviceId, SessionId};

use super::a_transfer_left_unanswered::{daemon, numbered_owner_share};
use super::a_voice_grant_on_the_floor::paired;
use super::{Audience, Controller};

/// A worker recorded for a new session, whose process is this one: alive, answering nobody, so its
/// barrier is pending whoever asks.
async fn recorded_worker(controller: &Controller, temp: &kr_ipc::testing::TempHost) -> SessionId {
    let environment_id = temp.environment_id();
    let actor_id = kr_protocol::ids::ActorId::new("local:test").expect("a principal");
    let process = kr_ipc::identity::current_process_start_identity().expect("this process");
    let mut registry = controller.registry.lock().await;
    let reservation = registry
        .reserve(
            &actor_id,
            kr_ipc::new_uuid(),
            kr_protocol::scalars::Digest256::from_bytes([0x6e; 32]),
            &kr_cbor::to_canonical_vec(&super::a_create_that_launches_nothing::create_params(
                environment_id,
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

/// KR-REQ-23.49: a device that revokes a share it delegated is told of the workers of the sessions
/// that share covers and of no other session, and the owner who revokes the same is told of every
/// worker. The control is the owner's answer, which names both sessions' workers.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_that_revokes_is_told_of_the_workers_of_its_own_sessions_only() {
    let (temp, controller) = daemon().await;
    let ours = recorded_worker(&controller, &temp).await;
    let elsewhere = recorded_worker(&controller, &temp).await;
    let holder: DeviceId = paired(&controller, 1, None).device_id;
    let device_share = numbered_owner_share(&controller, ours, holder, 1);
    let owner_share = numbered_owner_share(&controller, ours, holder, 3);
    assert_ne!(ours, elsewhere);

    let sessions = |answer: &kr_protocol::sharing::RevocationResult| {
        let mut named: Vec<SessionId> = answer
            .barrier
            .workers
            .iter()
            .map(|worker| worker.session_id)
            .collect();
        named.sort();
        named
    };
    let told_to_a_device = controller
        .revoke_grant(device_share.grant_id, Audience::Device, None, None)
        .await
        .expect("the device revokes");
    assert_eq!(sessions(&told_to_a_device), vec![ours]);
    assert_eq!(told_to_a_device.barrier.workers_total.get(), 1);

    let told_to_the_owner = controller
        .revoke_grant(owner_share.grant_id, Audience::Host, None, None)
        .await
        .expect("the owner revokes");
    let mut both = vec![ours, elsewhere];
    both.sort();
    assert_eq!(sessions(&told_to_the_owner), both);
}
