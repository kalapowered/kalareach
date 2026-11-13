//! What the local door tells of a copy when a barrier that is not host-wide restamps the
//! connection's registration between the service's own check and the reply.
//!
//! A copy states what an earlier request did, so it is told only under the exact revision the
//! request was admitted under. A barrier that withdraws some connections stamps every survivor with
//! the revision it set, which says that authority moved on this host after the admission: the
//! copy is not shown, the effect stands, and a repeat on the same connection is admitted under the
//! new revision and answered from the record.

use std::sync::Arc;
use std::time::Duration;

use kr_protocol::envelope::{ControlFrame, MutationRequest, ParamsValue};
use kr_protocol::ids::{ActorId, ConnectionId};
use kr_protocol::method::Method;

use super::Reach;
use super::a_recorded_answer_another_copy_wrote::a_workflow_install;
use super::the_end_of_a_write_is_told_under_its_authority::not_shown;
use super::the_fence_at_every_effect::{
    accepted, admitted, daemon, mutation_of, refusal, told_now,
};
use crate::service::Controller;

/// A withdrawal of one device, as another request's `device.revoke` raises it: the barrier
/// withdraws the connections that act under that device and stamps the rest with its revision.
pub(super) async fn another_devices_withdrawal(controller: &Controller) {
    let device = Reach::Device(kr_protocol::ids::DeviceId::new(
        kr_protocol::scalars::Uuid::from_bytes([0x71; 16]),
    ));
    let debt = controller
        .owe_debt("a device", device.clone())
        .expect("the debt is written");
    let own = controller.publish_debts(&[(debt, device)]);
    controller.barrier(own).await.expect("a barrier");
}

/// What the door tells of `mutation` on the connection, as the route's own result is told. With
/// `restamped` another device's withdrawal completes once the route has answered and before the
/// answer is told.
async fn told_on(
    controller: &Arc<Controller>,
    (connection_id, actor_id): &(ConnectionId, ActorId),
    method: Method,
    mutation: &MutationRequest,
    restamped: bool,
) -> ControlFrame {
    let pause = restamped.then(|| controller.pause_after_a_route_answers());
    let telling = tokio::spawn({
        let (controller, actor_id, mutation) =
            (Arc::clone(controller), actor_id.clone(), mutation.clone());
        let connection_id = *connection_id;
        async move {
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
        another_devices_withdrawal(controller).await;
        release.send(()).expect("the door goes on");
    }
    telling.await.expect("the door tells it")
}

/// KR-REQ-09.09: the answer an automation action's repeat reads from the journal is a copy. It is
/// told while the registration stands under the revision it was admitted under; a withdrawal of
/// another device that restamps the registration after the journal's own check has the door tell
/// it is not shown, with the connection standing; a repeat on the same connection is admitted under
/// the new revision and answered from the record. A fresh result meets the light check and is told
/// across a restamp (`a_result_is_not_shown_once_the_connection_is_withdrawn_after_the_route_answers`).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_module_copy_across_a_restamp_is_not_shown_and_its_repeat_is_answered() {
    use super::a_recorded_answer_another_copy_wrote::{materialisation, setting_quiet_hours};

    let (temp, controller, _clock) = daemon().await;
    let who = admitted(&controller).await;
    // The first attempt of each is answered, with a result (automation, attention) or with the
    // refusal the change-set module keeps as the action's answer; the repeat reads that record.
    let requests = [
        ("automation", a_workflow_install(&temp, &controller)),
        ("attention", setting_quiet_hours(&temp)),
        ("change set", materialisation(&temp)),
    ];
    for (name, mutation) in requests {
        let method = mutation.method.method().expect("a method");
        let first = told_on(&controller, &who, method, &mutation, false).await;
        let repeat = told_on(&controller, &who, method, &mutation, false).await;
        assert_eq!(
            repeat, first,
            "{name}: with no restamp the repeat is given the record's answer"
        );

        let before = controller
            .admitted_revision(who.0)
            .expect("it stands")
            .get();
        let across = told_on(&controller, &who, method, &mutation, true).await;
        not_shown(&across);
        let after = controller
            .admitted_revision(who.0)
            .expect("the connection stands")
            .get();
        assert!(
            after > before,
            "{name}: the registration was restamped: {before} then {after}"
        );

        let again = told_on(&controller, &who, method, &mutation, false).await;
        assert_eq!(
            again, first,
            "{name}: a repeat on the same connection is answered from the record"
        );
    }
}

/// KR-REQ-09.09: every answer to `membership.present` is a copy, a refusal of the lease included,
/// so a restamp between the route and the reply has the door tell it is not shown where it tells
/// the refusal when nothing moved. The lease of a real presentation, with its repeat, is the case
/// of the organisation's suite.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_membership_answer_across_a_restamp_is_not_shown() {
    let (temp, controller, _clock) = daemon().await;
    let who = admitted(&controller).await;
    let mutation = mutation_of(&temp, Method::MembershipPresent, ParamsValue::empty());

    let refused = told_on(
        &controller,
        &who,
        Method::MembershipPresent,
        &mutation,
        false,
    )
    .await;
    assert_eq!(
        refusal(&refused)
            .expect("a lease that is no lease is refused")
            .code,
        kr_protocol::error::ErrorCode::InvalidArgument,
        "with no restamp the refusal is told: {refused:?}"
    );
    let across = told_on(
        &controller,
        &who,
        Method::MembershipPresent,
        &mutation,
        true,
    )
    .await;
    not_shown(&across);
}

/// KR-REQ-09.09: the first attempt of a claimed action answers for itself and is told across a
/// restamp, as any result of its own effect is; the repeat reads what the first recorded and is a
/// copy, so across a restamp it is not shown; a repeat on the same connection afterwards is
/// answered.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_claimed_actions_repeat_is_a_copy_across_a_restamp_and_its_first_attempt_is_not() {
    let (temp, controller, _clock) = daemon().await;
    let who = admitted(&controller).await;
    let mutation = mutation_of(
        &temp,
        Method::AccountSignOut,
        ParamsValue::from_typed(&kr_protocol::host_account::AccountSignOutParams {})
            .expect("encodes"),
    );

    let first = told_on(&controller, &who, Method::AccountSignOut, &mutation, true).await;
    assert!(
        refusal(&first).is_none(),
        "the first attempt's own result is told across a restamp: {first:?}"
    );
    let across = told_on(&controller, &who, Method::AccountSignOut, &mutation, true).await;
    not_shown(&across);
    let again = told_on(&controller, &who, Method::AccountSignOut, &mutation, false).await;
    assert_eq!(
        again, first,
        "the repeat on the same connection is answered"
    );
}

/// KR-REQ-09.09: a report that lists what earlier exports left is a copy whatever it says, so a
/// restamp has the door tell it is not shown, where the answer is given when nothing moved.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_derived_report_across_a_restamp_is_not_shown() {
    let (temp, controller, _clock) = daemon().await;
    let who = admitted(&controller).await;
    let mutation = mutation_of(
        &temp,
        Method::PrivacyRetainedDelete,
        ParamsValue::from_typed(&kr_protocol::privacy::PrivacyRetainedDeleteParams {
            reference: "no such copy".to_owned(),
        })
        .expect("encodes"),
    );

    let control = told_on(
        &controller,
        &who,
        Method::PrivacyRetainedDelete,
        &mutation,
        false,
    )
    .await;
    assert!(
        !matches!(
            refusal(&control).map(|error| error.code),
            Some(kr_protocol::error::ErrorCode::OutcomeUnknown)
        ),
        "with nothing moved the answer is told: {control:?}"
    );
    let across = told_on(
        &controller,
        &who,
        Method::PrivacyRetainedDelete,
        &mutation,
        true,
    )
    .await;
    not_shown(&across);
}
