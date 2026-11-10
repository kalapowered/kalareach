//! What a paired device is told of a copy that a service read from its own record and withheld.
//!
//! A service that gives back what another copy recorded asks the authority check once the answer is
//! in hand, and a copy that check stops is refused for the authority, not told the record. The door
//! asks its own check next, for every answer it tells as a copy, and that one can pass: the fence
//! that stopped the service is gone by then. The service's refusal must not then be told as the
//! copy's kept answer, which would say the action did not happen when another copy carried it out.
//! So a service says that it withheld the copy, and the door tells the device the outcome is not
//! shown, whatever the device's authority is by then.

use std::sync::Arc;

use kr_protocol::envelope::{ControlFrame, MutationRequest, Outcome, ParamsValue, Response};
use kr_protocol::error::ErrorCode;
use kr_protocol::method::Method;
use kr_protocol::scalars::Nullable;

use super::a_copy_from_a_services_record::{EVERY_RIGHT, a_join, mutation_of, refusal_of};
use super::decision::Answered;
use super::write_boundary::paired_connection;
use crate::service::Controller;
use crate::service::a_close_a_worker_never_answers as fake;

/// How long a case waits for a copy to reach the place it is stopped at.
const WAIT_BOUND: std::time::Duration = std::time::Duration::from_secs(30);

/// Serves `mutation` twice at once as [`two_copies`] does, and, when `fence` is set, has a fence
/// this host owes land while the copy that found the record is at its service's own check, and be
/// gone again when the door asks its check once the service has answered.
///
/// The first copy is stopped before its effect. The second performs and records. The first goes on
/// and is stopped at the check its service asks with the record in hand, where the fence lands.
/// The door's check comes next; the case lets it find the fence gone. A door that tells the service's
/// refusal as the copy's answer then sends it to a device that has authority again.
async fn two_copies_with_a_fence_between_the_checks(
    controller: &Arc<Controller>,
    connection: &super::RemoteConnection,
    mutation: &MutationRequest,
    fence: bool,
) -> (Answered, Answered) {
    let (arrived, go) = controller.before_the_effect.arm();
    let first = connection.answer_now(ControlFrame::Mutation(Box::new(mutation.clone())));
    tokio::pin!(first);
    tokio::select! {
        arrived = tokio::time::timeout(WAIT_BOUND, arrived) => {
            arrived
                .expect("the first copy reaches the place it is stopped at")
                .expect("the pause is armed");
        }
        early = &mut first => panic!("the first copy was answered before its effect: {early:?}"),
    }
    let fresh = connection
        .answer_now(ControlFrame::Mutation(Box::new(mutation.clone())))
        .await
        .expect("the second copy is answered");
    let (at_the_service, go_service) = controller.pause_retained_lookup();
    go.send(()).expect("the first copy goes on");
    tokio::select! {
        arrived = tokio::time::timeout(WAIT_BOUND, at_the_service) => {
            arrived
                .expect("the first copy reaches its service's check")
                .expect("the pause is armed");
        }
        early = &mut first => panic!("the first copy was answered before its service's check: {early:?}"),
    }
    if fence {
        controller.hold_fence(true);
    }
    let (at_the_door, go_door) = controller.pause_retained_lookup();
    go_service.send(()).expect("the service's check goes on");
    let copied = tokio::select! {
        arrived = tokio::time::timeout(WAIT_BOUND, at_the_door) => {
            arrived
                .expect("a copy the door tells as a kept answer reaches the door's check")
                .expect("the pause is armed");
            controller.hold_fence(false);
            go_door.send(()).expect("the door's check goes on");
            first.await
        }
        answered = &mut first => answered,
    };
    controller.hold_fence(false);
    (copied.expect("the first copy is answered"), fresh)
}

/// What a copy the service read from its record and withheld is told, because a fence this host
/// owed stopped it at the service's check, when the fence is gone by the time the door asks its own
/// check: the outcome is not shown, and not the service's refusal. The refusal is the service's word
/// about authority at its check; told as the copy's kept answer to a device that has authority now,
/// it would say the action did not happen when another copy carried it out. The control: with no
/// fence owed, the copy is given the result the other copy recorded.
async fn a_copy_a_service_withheld_is_told_as_not_shown(
    method: Method,
    byte: u8,
    params: impl Fn(&fake::Silent) -> ParamsValue,
) {
    let world = fake::fake_worker(None).await;
    let controller = &world.controller;
    let (connection, _) = paired_connection(controller, byte, EVERY_RIGHT);

    let control = mutation_of(&world, &connection, method, 91, params(&world));
    let (copied, fresh) =
        two_copies_with_a_fence_between_the_checks(controller, &connection, &control, false).await;
    for answered in [&copied, &fresh] {
        assert!(
            matches!(
                answered.frame(),
                ControlFrame::Response(Response {
                    outcome: Outcome::Ok(_),
                    ..
                })
            ),
            "{method:?}: with no fence owed both copies are given the result: {:?}",
            answered.frame()
        );
    }

    let raced = mutation_of(&world, &connection, method, 92, params(&world));
    let (copied, fresh) =
        two_copies_with_a_fence_between_the_checks(controller, &connection, &raced, true).await;
    assert!(
        matches!(
            fresh.frame(),
            ControlFrame::Response(Response {
                outcome: Outcome::Ok(_),
                ..
            })
        ),
        "{method:?}: the copy that performed is answered as ever: {:?}",
        fresh.frame()
    );
    let told = refusal_of(&copied);
    assert_eq!(
        told.code,
        ErrorCode::OutcomeUnknown,
        "{method:?}: the copy the service withheld is not refused as the record's answer: {told:?}"
    );
    assert_eq!(told.message, super::outcome_not_shown().message);
    world.serving.abort();
}

/// KR-REQ-09.09: a machine group step whose copy the service read from its record and withheld,
/// because a fence this host owed stopped it at the service's check, is told the outcome is not
/// shown when the fence is gone by the time the door asks its own check. The machine group's
/// service gives a record back through the shared check.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_machine_group_step_a_service_withheld_is_told_as_not_shown() {
    a_copy_a_service_withheld_is_told_as_not_shown(Method::MachineJoin, 99, a_join).await;
}

/// KR-REQ-09.09: an attention change whose copy the store read from its record and withheld,
/// because a fence this host owed stopped it at the store's check, is told the outcome is not shown
/// when the fence is gone by the time the door asks its own check. The store gives a record back
/// through the check its write asks once the answer is in hand.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_attention_change_a_service_withheld_is_told_as_not_shown() {
    a_copy_a_service_withheld_is_told_as_not_shown(Method::AttentionQuietHours, 100, |_| {
        ParamsValue::from_typed(&kr_protocol::attention::AttentionQuietHoursParams {
            quiet_hours: Nullable::null(),
        })
        .expect("encodes")
    })
    .await;
}
