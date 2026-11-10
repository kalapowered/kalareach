//! What a paired device is told of an action while the attempt that claimed it is still running.
//!
//! The claim is written before the effect, and the attempt that wrote it carries the action out and
//! records what it came to. A copy of the action that arrives meanwhile is not performed and has no
//! answer to be given: the first attempt may complete the effect at any moment, or has. A transient
//! word says nothing took effect, so it is not the word for the copy; the outcome is unknown, and
//! the device asks again under the same identifier for the answer.

use kr_protocol::envelope::{ActionTarget, ControlFrame, MutationRequest, ParamsValue};
use kr_protocol::error::ErrorCode;
use kr_protocol::method::Method;
use kr_protocol::scalars::Nullable;

use super::a_copy_from_a_services_record::{
    EVERY_RIGHT, mutation_of, refusal_of, with_a_voice_grant,
};
use super::write_boundary::paired_connection;
use crate::grants::ActionClaim;
use crate::service::a_close_a_worker_never_answers as fake;

/// Writes the claim of `mutation`'s action as an attempt that is still running holds it, and
/// returns the hold: the claim goes back with it.
fn claimed_as_running(
    world: &fake::Silent,
    connection: &super::RemoteConnection,
    mutation: &MutationRequest,
) -> crate::grants::ClaimHold {
    let actor = connection.device.principal();
    let digest = kr_protocol::digest::mutation_digest(mutation, &actor).expect("a digest");
    match world
        .controller
        .sharing()
        .grants()
        .claim_action(&actor, mutation.action_id, &digest, kr_ipc::now_ms().get())
        .expect("the claim is written")
    {
        ActionClaim::Claimed { hold } => hold,
        ActionClaim::Recorded(_) => panic!("the action was claimed before"),
    }
}

/// A mutation of `method` whose action is claimed by an attempt that is still running is served
/// again, and the device is told the outcome is unknown.
async fn a_copy_of_a_running_action_is_told_the_outcome_is_unknown(
    method: Method,
    byte: u8,
    params: impl FnOnce(&fake::Silent) -> ParamsValue,
) {
    let world = fake::fake_worker(None).await;
    let (connection, _) = paired_connection(&world.controller, byte, EVERY_RIGHT);
    if method == Method::VoiceStop {
        with_a_voice_grant(&world.controller, &connection);
    }
    let mutation = mutation_of(&world, &connection, method, 91, params(&world));
    let hold = claimed_as_running(&world, &connection, &mutation);

    let answered = connection
        .answer_now(ControlFrame::Mutation(Box::new(mutation)))
        .await
        .expect("the copy is answered");
    let told = refusal_of(&answered);
    assert_eq!(told.code, ErrorCode::OutcomeUnknown, "{method:?}: {told:?}");
    drop(hold);
    world.serving.abort();
}

/// KR-REQ-09.09: an authority change (`grant.redeem`).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_copy_of_an_authority_change_that_is_running_is_told_the_outcome_is_unknown() {
    a_copy_of_a_running_action_is_told_the_outcome_is_unknown(Method::GrantRedeem, 70, |_| {
        ParamsValue::from_typed(&kr_protocol::sharing::GrantRedeemParams {
            invitation_id: kr_protocol::ids::InvitationId::new(kr_ipc::new_uuid()),
        })
        .expect("encodes")
    })
    .await;
}

/// KR-REQ-09.09: a machine group step.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_copy_of_a_machine_group_step_that_is_running_is_told_the_outcome_is_unknown() {
    a_copy_of_a_running_action_is_told_the_outcome_is_unknown(Method::MachineSplit, 71, |_| {
        ParamsValue::from_typed(&kr_protocol::machine::MachineSplitParams {
            expected: kr_protocol::machine::MachineExpected {
                machine_id: kr_protocol::ids::MachineId::new(kr_ipc::new_uuid()),
                revision: kr_protocol::scalars::U64::new(7),
            },
        })
        .expect("encodes")
    })
    .await;
}

/// KR-REQ-09.09: a change of the voice grant.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_copy_of_a_voice_change_that_is_running_is_told_the_outcome_is_unknown() {
    a_copy_of_a_running_action_is_told_the_outcome_is_unknown(Method::VoiceStop, 72, |_| {
        ParamsValue::from_typed(&kr_protocol::voice::VoiceStopParams {
            voice_session_id: kr_protocol::ids::VoiceSessionId::new(kr_ipc::new_uuid()),
        })
        .expect("encodes")
    })
    .await;
}

/// KR-REQ-09.09: a session's rename. The copy that the door's look for a record misses claims the
/// action itself, and finds the claim of an attempt that has begun since.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_rename_that_finds_another_attempt_running_is_told_the_outcome_is_unknown() {
    let world = fake::fake_worker(None).await;
    let controller = &world.controller;
    let (connection, _) = paired_connection(controller, 73, EVERY_RIGHT);
    let mut mutation = mutation_of(&world, &connection, Method::SessionRename, 91, {
        ParamsValue::from_typed(&kr_protocol::describe::SessionRenameParams {
            session_id: world.session_id,
            title: Nullable::some("a name".to_owned()),
        })
        .expect("encodes")
    });
    mutation.target = ActionTarget {
        environment_id: world.environment_id,
        session_id: Nullable::some(world.session_id),
        session_epoch: Nullable::some(kr_protocol::ids::SessionEpoch::V1),
        application_instance_id: Nullable::null(),
        agent_binding_revision: Nullable::null(),
    };

    // The copy is stopped before its effect, once the door has found no record of the action. The
    // other attempt then claims it, and is still running when the copy goes on to claim it.
    let (arrived, go) = controller.before_the_effect.arm();
    let (answered, hold) = tokio::join!(
        connection.answer_now(ControlFrame::Mutation(Box::new(mutation.clone()))),
        async {
            tokio::time::timeout(std::time::Duration::from_secs(30), arrived)
                .await
                .expect("the copy reaches the place it is stopped at")
                .expect("the pause is armed");
            let hold = claimed_as_running(&world, &connection, &mutation);
            go.send(()).expect("the copy goes on");
            hold
        }
    );
    let told = refusal_of(&answered.expect("the copy is answered"));
    assert_eq!(told.code, ErrorCode::OutcomeUnknown, "{told:?}");
    drop(hold);
    world.serving.abort();
}

/// KR-REQ-09.09: a session's rename whose copy meets another attempt's claim is told the outcome is
/// unknown as a copy of that attempt's record, so a fence this host owes, which lands once the claim
/// has been met, stops it: the device is told that what became of the action is not shown, and not
/// that the authority is gone, which is a definite word. The copy is stopped before its effect,
/// once the door has found no record, and the other attempt then claims the action. The fence lands
/// while the copy is at the check it is asked with the claim in hand, and is gone again when the
/// door asks its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_rename_that_finds_another_attempt_running_is_not_told_after_a_fence_lands() {
    let wait = std::time::Duration::from_secs(30);
    let world = fake::fake_worker(None).await;
    let controller = &world.controller;
    let (connection, _) = paired_connection(controller, 74, EVERY_RIGHT);
    let mut mutation = mutation_of(&world, &connection, Method::SessionRename, 92, {
        ParamsValue::from_typed(&kr_protocol::describe::SessionRenameParams {
            session_id: world.session_id,
            title: Nullable::some("a name".to_owned()),
        })
        .expect("encodes")
    });
    mutation.target = ActionTarget {
        environment_id: world.environment_id,
        session_id: Nullable::some(world.session_id),
        session_epoch: Nullable::some(kr_protocol::ids::SessionEpoch::V1),
        application_instance_id: Nullable::null(),
        agent_binding_revision: Nullable::null(),
    };

    let (arrived, go) = controller.before_the_effect.arm();
    let copy = connection.answer_now(ControlFrame::Mutation(Box::new(mutation.clone())));
    tokio::pin!(copy);
    tokio::select! {
        arrived = tokio::time::timeout(wait, arrived) => {
            arrived
                .expect("the copy reaches the place it is stopped at")
                .expect("the pause is armed");
        }
        early = &mut copy => panic!("the copy was answered before its effect: {early:?}"),
    }
    let hold = claimed_as_running(&world, &connection, &mutation);
    let (at_the_service, go_service) = controller.pause_retained_lookup();
    go.send(()).expect("the copy goes on");
    tokio::select! {
        arrived = tokio::time::timeout(wait, at_the_service) => {
            arrived
                .expect("the copy reaches the check it is asked with the claim in hand")
                .expect("the pause is armed");
        }
        early = &mut copy => panic!("the copy was answered before that check: {early:?}"),
    }
    controller.hold_fence(true);
    let (at_the_door, go_door) = controller.pause_retained_lookup();
    go_service.send(()).expect("the check goes on");
    let answered = tokio::select! {
        arrived = tokio::time::timeout(wait, at_the_door) => {
            arrived
                .expect("a copy the door tells as a kept answer reaches the door's check")
                .expect("the pause is armed");
            controller.hold_fence(false);
            go_door.send(()).expect("the door's check goes on");
            copy.await
        }
        answered = &mut copy => answered,
    };
    controller.hold_fence(false);
    drop(hold);
    let told = refusal_of(&answered.expect("the copy is answered"));
    assert_eq!(told.code, ErrorCode::OutcomeUnknown, "{told:?}");
    assert_eq!(told.message, super::outcome_not_shown().message);
    world.serving.abort();
}
