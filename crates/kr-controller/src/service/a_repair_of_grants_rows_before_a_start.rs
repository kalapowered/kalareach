//! A repair of grants rows made while the host is stopped, and the start that follows it.
//!
//! The repair writes one fence debt, which the start publishes and its barrier retires, and the
//! registry it leaves answers the methods that a row that cannot be read stood in the way of.

use kr_protocol::sharing::{GrantListParams, GrantListResult};

use super::a_floor_owed_its_record::daemon;
use super::a_revocation_beside_a_row_that_cannot_be_read::{
    device_id, grant_id, is_live, issue, key,
};
use super::a_voice_grant_on_the_floor::paired;
use super::one_barrier_for_every_restriction::{beside, owed, revision};
use super::{Audience, Controller};

/// What the host's grant list answers, listing as the person at this machine.
fn listed(controller: &Controller) -> crate::error::Result<GrantListResult> {
    controller
        .grant_list(
            controller.sharing().host_device_id(),
            &kr_protocol::envelope::ParamsValue::from_typed(&GrantListParams {
                session_id: kr_protocol::scalars::Nullable::null(),
                include_resolved: true,
            })
            .expect("encodes"),
        )
        .map(|answer| answer.to_typed().expect("a list"))
}

/// The repair of a stopped host writes one debt before the daemon starts, and the start publishes
/// it and raises the barrier that retires it: the revision moves once and nothing is owed after.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_debt_the_repair_wrote_is_paid_by_the_daemons_start() {
    let temp = kr_ipc::testing::TempHost::create();
    let controller = daemon(&temp).await;
    issue(&controller, 0x41, None, device_id(0xe1));
    issue(&controller, 0x42, Some(0x41), device_id(0xe2));
    beside(&temp)
        .execute_batch(&format!(
            "UPDATE grants SET grant = X'00' WHERE grant_id = {};",
            key(grant_id(0x41))
        ))
        .expect("the record no longer decodes");
    let before = revision(&controller).await;
    super::net::tests::stopped(controller).await;

    let repaired = crate::grants::repair::apply(
        &temp.environment().registry_database(),
        kr_ipc::now_ms().get(),
        1,
    )
    .expect("the repair")
    .expect("there was something to repair");
    assert!(repaired.fence_owed, "the repair says a fence is owed");
    let rows: i64 = beside(&temp)
        .query_row("SELECT COUNT(*) FROM fence_debt", [], |row| row.get(0))
        .expect("counts");
    assert_eq!(rows, 1, "the repair wrote exactly one debt");

    let controller = daemon(&temp).await;
    assert_eq!(
        revision(&controller).await,
        before + 1,
        "the start publishes the debt and its barrier retires it, once"
    );
    assert!(
        owed(&controller).is_empty(),
        "nothing is owed after the start"
    );
    drop(controller);
}

/// After the repair a device revocation, a grant revocation and a grant list answer, where the
/// list refused beside the row that cannot be read.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn after_the_repair_a_device_revocation_a_grant_revocation_and_a_grant_list_answer() {
    let temp = kr_ipc::testing::TempHost::create();
    let controller = daemon(&temp).await;
    let held = paired(&controller, 1, None).device_id;
    issue(&controller, 0x41, None, held);
    issue(&controller, 0x43, None, device_id(0xe2));
    let withdrawn = issue(&controller, 0x44, Some(0x43), device_id(0xe3));
    let root = issue(&controller, 0x45, None, device_id(0xe4));
    beside(&temp)
        .execute_batch(&format!(
            "UPDATE grants SET grant = X'00' WHERE grant_id = {};",
            key(grant_id(0x43))
        ))
        .expect("the record no longer decodes");
    listed(&controller).expect_err("the list refuses beside the row that cannot be read");
    super::net::tests::stopped(controller).await;
    crate::grants::repair::apply(
        &temp.environment().registry_database(),
        kr_ipc::now_ms().get(),
        2,
    )
    .expect("the repair")
    .expect("there was something to repair");

    let controller = daemon(&temp).await;
    let listing = listed(&controller).expect("the list answers once the row is gone");
    assert!(
        listing
            .grants
            .iter()
            .any(|summary| summary.grant.grant_id == root),
        "the list holds the grant that was readable and placed"
    );
    assert!(
        !is_live(&temp, &key(withdrawn)),
        "the grant that hung below the removed row is withdrawn"
    );
    controller
        .revoke_device_authority(held, None, None)
        .await
        .expect("the device revocation answers");
    controller
        .revoke_grant(root, Audience::Host, None, None)
        .await
        .expect("the grant revocation answers");
    assert!(!is_live(&temp, &key(root)), "the grant is revoked");
    drop(controller);
}
