//! What a refusal the authority feed raises does to work a remote connection had admitted.
//!
//! The refusal changes policy and moves the epoch and withdraws no registration, so the
//! checks every mutation asks again where it commits have to read it themselves.

use std::sync::Arc;

use kr_protocol::grant::Grant;
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

    controller.raise_the_unverified_withdrawal_refusal().await;
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

    controller
        .settle_unverified_withdrawals(None)
        .await
        .expect("the directory reads");
    assert_eq!(
        asked(&controller, &remote).await,
        [true, true],
        "lifted, the connection goes on"
    );

    controller
        .authority_feed_behind(u64::MAX)
        .await
        .expect("the registry reads");
    controller.raise_the_unverified_withdrawal_refusal().await;
    controller
        .settle_unverified_withdrawals(None)
        .await
        .expect("the directory reads");
    assert_eq!(
        asked(&controller, &remote).await,
        [false, false],
        "one refusal lifted, the other stands"
    );
}

/// A registration of a connection through the network under `grant`, at the revision in force, and
/// the admission it carries.
fn registered_under(controller: &Arc<Controller>, grant: Grant) -> AdmittedMutation {
    let revision = controller.policy().authority_revision();
    let connection_id = ConnectionId::new(kr_ipc::new_uuid());
    let actor = kr_protocol::ids::ActorId::new("local:test").expect("a principal");
    controller.admitted_table().insert(
        connection_id,
        AdmittedConnection::new(actor, revision).under(grant),
    );
    AdmittedMutation {
        connection_id,
        admitted_revision: revision,
        deadline: controller
            .clock
            .now()
            .checked_add(std::time::Duration::from_secs(60)),
    }
}

/// KR-REQ-24.15: the removal of this host from its feed reaches a share a connection acts under,
/// as it reaches the grant the connection was admitted under: a share keeps the organisation
/// requirement of what it was delegated from, so it rests on the feed when the pairing grant does
/// not. The control: a share that requires no organisation is left alone, and so is the connection
/// before the removal.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_connection_acting_under_a_share_that_rests_on_the_feed_is_refused_after_the_removal() {
    use super::a_voice_grant_on_the_floor::{paired, paired_needing_a_lease};

    let (_temp, controller) = daemon().await;
    let under_an_organisations_share =
        registered_under(&controller, paired(&controller, 1, None).grant);
    controller.note_share(
        under_an_organisations_share.connection_id,
        &paired_needing_a_lease(
            &controller,
            2,
            &[kr_protocol::rights::ActionRight::SessionView],
        )
        .grant,
    );
    let under_a_personal_share = registered_under(&controller, paired(&controller, 3, None).grant);
    controller.note_share(
        under_a_personal_share.connection_id,
        &paired(&controller, 4, None).grant,
    );
    for admission in [&under_an_organisations_share, &under_a_personal_share] {
        assert_eq!(
            asked(&controller, admission).await,
            [true, true],
            "the control"
        );
    }

    controller
        .authority_feed_removed("https://feed.example")
        .await
        .expect("the removal is written down");
    assert_eq!(
        asked(&controller, &under_an_organisations_share).await,
        [false, false],
        "a share that rests on the feed is refused where it commits"
    );
    assert_eq!(
        asked(&controller, &under_a_personal_share).await,
        [true, true],
        "a share that does not is left alone"
    );
}

/// KR-REQ-24.15: the removal of this host from its feed is a refusal of one kind of grant, and it
/// holds work admitted before it as the other two refusals do. A connection under a grant that
/// rests on the feed, an organisation's, or a personal one once the owner has bounded offline
/// validity, is refused where it commits; one under the default owner grant is not, which stays
/// usable without the feed, and the owner at this machine never is.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_connection_admitted_before_the_feed_removed_the_host_is_refused_by_the_kind_of_its_grant()
 {
    use super::a_voice_grant_on_the_floor::{paired, paired_needing_a_lease};

    let (_temp, controller) = daemon().await;
    let (_, local) = registered(&controller);
    let personal = registered_under(&controller, paired(&controller, 1, None).grant);
    let organisational = registered_under(
        &controller,
        paired_needing_a_lease(
            &controller,
            2,
            &[kr_protocol::rights::ActionRight::SessionView],
        )
        .grant,
    );
    for admission in [&personal, &organisational] {
        assert_eq!(
            asked(&controller, admission).await,
            [true, true],
            "the control"
        );
    }

    controller
        .authority_feed_removed("https://feed.example")
        .await
        .expect("the removal is written down");
    assert_eq!(
        asked(&controller, &organisational).await,
        [false, false],
        "a grant that rests on the feed is refused where it commits"
    );
    let refused = controller
        .check_registration(&organisational)
        .expect_err("the removal stands");
    assert!(
        matches!(&refused, ControllerError::PermissionDenied { detail }
            if detail.contains("authority feed")),
        "{refused:?}"
    );
    assert_eq!(
        asked(&controller, &personal).await,
        [true, true],
        "the default owner grant stays usable"
    );
    assert_eq!(asked(&controller, &local).await, [true, true]);

    controller
        .update_policy(|policy| {
            policy.set_offline_validity(Some(kr_protocol::sharing::OfflineValidityPolicy {
                maximum_offline_ms: kr_protocol::scalars::DurationMs::new(60 * 60 * 1000),
                last_synchronised_at_ms: kr_protocol::scalars::Nullable::some(
                    kr_protocol::scalars::TimestampMs::new(kr_ipc::now_ms().get()),
                ),
            }));
        })
        .expect("the owner bounds offline validity");
    assert_eq!(
        asked(&controller, &personal).await,
        [false, false],
        "a personal grant rests on the feed once offline validity is bounded"
    );
    assert_eq!(asked(&controller, &local).await, [true, true]);
}
