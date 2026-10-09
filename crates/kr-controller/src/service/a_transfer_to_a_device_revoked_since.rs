//! A transfer of control to a device that was revoked after the transfer was planned.
//!
//! The plan reads the receiving device once, and the confirmation is spent and the registry lock
//! waited for after that. A device revocation takes the same lock across its writes, so the record
//! read where the grant is written is the one the grant is written against: a device revoked in the
//! meantime is not handed control, and holds no active grant afterwards.

use kr_protocol::ids::{ActorId, DeviceId, SessionId};
use kr_protocol::scalars::{TimestampMs, Uuid};

use super::a_transfer_left_unanswered::{Ceremony, confirmed, daemon, owner_share, plan_of};
use super::a_voice_grant_on_the_floor::paired;
use crate::service::Controller;

/// KR-REQ-23.49: a transfer to a device revoked since the plan was built is refused and writes
/// nothing, and the grant it would have handed over is still held. The control is the same
/// transfer to a device that is paired, which writes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_transfer_to_a_device_revoked_since_its_plan_writes_nothing() {
    let (_temp, controller) = daemon().await;
    let actor_id = ActorId::new("local:test").expect("a principal");
    let host_device_id = DeviceId::new(controller.paths().environment_id().get());
    let session_id = SessionId::new(Uuid::from_bytes([0xa0; 16]));
    let giver = paired(&controller, 1, None).device_id;
    let revoked = paired(&controller, 2, None).device_id;
    let taker = paired(&controller, 3, None).device_id;
    let source = owner_share(&controller, session_id, giver);
    let grants = controller.sharing().grants();

    // The plan was built while the device was paired, and the device is revoked before the write.
    let plan = plan_of(
        &controller,
        session_id,
        &source,
        revoked,
        Controller::transfer_identity(
            &actor_id,
            kr_protocol::ids::ActionId::new(Uuid::from_bytes([5; 16])),
        ),
    );
    controller
        .devices()
        .revoke(revoked, TimestampMs::new(kr_ipc::now_ms().get()))
        .expect("the device is revoked");
    controller
        .transfer_control(
            &plan,
            &confirmed(&plan, host_device_id),
            &Ceremony,
            None,
            None,
        )
        .await
        .expect_err("a revoked device is not handed control");
    assert!(
        grants
            .record(plan.new_grant_id)
            .expect("readable")
            .is_none(),
        "no grant was written for it"
    );
    assert!(
        grants
            .record(source.grant_id)
            .expect("readable")
            .expect("present")
            .revoked_at_ms
            .is_none(),
        "and the grant to be given up is still held"
    );

    // The same transfer to a device that is paired is written.
    let plan = plan_of(
        &controller,
        session_id,
        &source,
        taker,
        Controller::transfer_identity(
            &actor_id,
            kr_protocol::ids::ActionId::new(Uuid::from_bytes([6; 16])),
        ),
    );
    controller
        .transfer_control(
            &plan,
            &confirmed(&plan, host_device_id),
            &Ceremony,
            None,
            None,
        )
        .await
        .expect("a paired device is handed control");
    assert!(
        grants
            .record(plan.new_grant_id)
            .expect("readable")
            .is_some()
    );
}
