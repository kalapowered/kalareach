//! What a refusal the authority feed raises does to work a remote connection had admitted.
//!
//! The refusal changes policy and moves the epoch and withdraws no registration, so the
//! checks every mutation asks again where it commits have to read it themselves.

use std::sync::Arc;

use kr_protocol::ids::ConnectionId;

use super::a_transfer_left_unanswered::daemon;
use super::{AdmittedConnection, Controller};
use crate::authority::AdmittedMutation;
use crate::error::ControllerError;

/// A registration of a connection through the network, and one of a client at this machine, both
/// at the revision in force, and the admissions they carry.
fn registered(controller: &Arc<Controller>) -> (AdmittedMutation, AdmittedMutation) {
    let revision = controller.policy().authority_revision();
    let remote = ConnectionId::new(kr_ipc::new_uuid());
    let local = ConnectionId::new(kr_ipc::new_uuid());
    let actor = kr_protocol::ids::ActorId::new("local:test").expect("a principal");
    let mut table = controller.admitted_table();
    table.insert(remote, AdmittedConnection::new(actor.clone(), revision));
    table.insert(
        local,
        AdmittedConnection::local(actor, revision, kr_protocol::local::LocalClientKind::Cli),
    );
    drop(table);
    let carried = |connection_id| AdmittedMutation {
        connection_id,
        admitted_revision: revision,
        deadline: controller
            .clock
            .now()
            .checked_add(std::time::Duration::from_secs(60)),
    };
    (carried(remote), carried(local))
}

async fn asked(controller: &Controller, admission: &AdmittedMutation) -> [bool; 2] {
    let registry = controller.registry.lock().await;
    [
        controller.check_admission(&registry, admission).is_ok(),
        controller.check_registration(admission).is_ok(),
    ]
}

/// KR-REQ-24.15: a connection through the network that had been admitted before the feed raised
/// either refusal is refused where it commits, by both checks every mutation asks, and the
/// client at this machine is not. The refusals are read together: lifting one leaves the other in
/// force, and lifting the only one that stands lets the connection go on.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_connection_admitted_before_a_feed_refusal_rose_is_refused_where_it_commits() {
    let (_temp, controller) = daemon().await;
    let (remote, local) = registered(&controller);
    assert_eq!(
        asked(&controller, &remote).await,
        [true, true],
        "the control"
    );

    controller.authority_feed_withdrawal_unverified(true).await;
    assert_eq!(asked(&controller, &remote).await, [false, false]);
    assert_eq!(
        asked(&controller, &local).await,
        [true, true],
        "the owner at this machine is not refused by the feed"
    );
    let refused = controller
        .check_registration(&remote)
        .expect_err("the refusal stands");
    assert!(
        matches!(&refused, ControllerError::PermissionDenied { detail }
            if detail.contains("an owner this host does not know")),
        "{refused:?}"
    );

    controller.authority_feed_withdrawal_unverified(false).await;
    assert_eq!(
        asked(&controller, &remote).await,
        [true, true],
        "lifted, the connection goes on"
    );

    controller
        .authority_feed_behind(u64::MAX)
        .await
        .expect("the registry reads");
    controller.authority_feed_withdrawal_unverified(true).await;
    controller.authority_feed_withdrawal_unverified(false).await;
    assert_eq!(
        asked(&controller, &remote).await,
        [false, false],
        "one refusal lifted, the other stands"
    );
}
