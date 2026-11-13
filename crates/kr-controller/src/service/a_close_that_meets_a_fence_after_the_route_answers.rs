//! What the local door tells of a close once the route has answered and authority has moved.
//!
//! The close goes to the worker that owns the session, which keeps its own receipts, so the daemon
//! cannot tell the worker's first answer from a copy of an earlier one: the whole answer is a copy,
//! and the door tells it only under the strict check. The same holds for the answer a duplicate
//! close is given from the closure record, which is a record of what an earlier close did.

use std::sync::Arc;
use std::time::Duration;

use kr_protocol::envelope::{ControlFrame, MutationRequest};
use kr_protocol::ids::{ActorId, ConnectionId};
use kr_protocol::method::Method;
use kr_transport::window::AcceptedDeadline;

use super::a_close_a_worker_never_answers as world;
use super::a_copy_meets_a_restamp::another_devices_withdrawal;
use super::a_migration_and_a_recovery_of_one_session::closure_of;
use super::the_fence_at_every_effect::{admitted, refusal, told_now};
use crate::service::Controller;

/// What happens between the route's answer and the door's telling of it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Between {
    Nothing,
    /// This host comes to owe a fence it could not raise.
    AFence,
    /// Another device's authority is withdrawn, which stamps this connection's registration with a
    /// new revision and leaves the connection standing with no fence owed.
    AnotherDevicesWithdrawal,
}

/// What the door tells of `mutation`, a close, with `between` happening once the route has answered
/// and before the answer is told.
async fn close_told(
    controller: &Arc<Controller>,
    (connection_id, actor_id): &(ConnectionId, ActorId),
    window: AcceptedDeadline,
    mutation: &MutationRequest,
    between: Between,
) -> ControlFrame {
    let pause = (between != Between::Nothing).then(|| controller.pause_before_a_reply_is_told());
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
                    Method::SessionClose,
                    connection_id,
                    None,
                    Some(window),
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
        match between {
            Between::AFence => controller.hold_fence(true),
            Between::AnotherDevicesWithdrawal => another_devices_withdrawal(controller).await,
            Between::Nothing => {}
        }
        release.send(()).expect("the door goes on");
    }
    let told = telling.await.expect("the door tells it");
    controller.hold_fence(false);
    told
}

/// Whether `frame` is the refusal that says what became of the action is not shown.
fn is_not_shown(frame: &ControlFrame) -> bool {
    refusal(frame).is_some_and(|error| {
        error.code == kr_protocol::error::ErrorCode::OutcomeUnknown
            && error.message == crate::error::ControllerError::outcome_not_shown().to_string()
    })
}

/// KR-REQ-09.09: a first close, answered by the worker the session runs in, is told as the worker
/// answered it while no fence is owed, whatever the worker's own word is; a fence this host comes to
/// owe after the worker's answer has arrived and before it is told keeps the answer from the caller,
/// who is told that what became of the action is not shown.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_first_close_a_worker_answers_is_not_shown_when_a_fence_lands_after_its_answer() {
    let recorded: world::Recorded = Arc::default();
    let world::Silent {
        _temp,
        controller,
        environment_id,
        session_id,
        accepted: window,
        serving,
        ..
    } = world::fake_worker(Some(Arc::clone(&recorded))).await;
    world::acknowledged(&controller, session_id);
    let who = admitted(&controller).await;

    let told = close_told(
        &controller,
        &who,
        window,
        &world::close_request(environment_id, session_id),
        Between::Nothing,
    )
    .await;
    assert!(
        refusal(&told).is_some() && !is_not_shown(&told),
        "with no fence the worker's own answer is told: {told:?}"
    );
    let told = close_told(
        &controller,
        &who,
        window,
        &world::close_request(environment_id, session_id),
        Between::AFence,
    )
    .await;
    assert!(is_not_shown(&told), "the answer is not shown: {told:?}");
    serving.abort();
}

/// KR-REQ-09.09: the answer a duplicate close is given from the closure record, when the session is
/// no longer in the directory, is told while no fence is owed; a fence this host comes to owe after
/// the record was read and before the answer is told keeps it from the caller.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_duplicate_close_answered_from_the_closure_record_is_not_shown_when_a_fence_lands_after_it()
 {
    let world::Silent {
        _temp,
        controller,
        environment_id,
        accepted: window,
        serving,
        ..
    } = world::fake_worker(None).await;
    let closed = kr_protocol::ids::SessionId::new(kr_ipc::new_uuid());
    controller
        .registry
        .lock()
        .await
        .record_closure(&closure_of(closed))
        .expect("the closure is recorded");
    let who = admitted(&controller).await;

    let told = close_told(
        &controller,
        &who,
        window,
        &world::close_request(environment_id, closed),
        Between::Nothing,
    )
    .await;
    assert!(
        refusal(&told).is_none(),
        "with no fence the closure record's answer is told: {told:?}"
    );
    let told = close_told(
        &controller,
        &who,
        window,
        &world::close_request(environment_id, closed),
        Between::AFence,
    )
    .await;
    assert!(is_not_shown(&told), "the answer is not shown: {told:?}");
    serving.abort();
}

/// KR-REQ-09.09: the accepted price of telling a worker's answer as a copy. Another device's
/// withdrawal that completes between a first close's effect and its reply stamps the connection's
/// registration with a new revision, and the answer is not shown although the connection stands and
/// no fence is owed. The close was sent to the worker once and stands; the same close asked again on
/// the same connection is admitted under the new revision, reaches the worker, which answers it from
/// its receipt, and is told.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn another_devices_withdrawal_between_a_first_closes_effect_and_its_reply_is_not_shown_and_the_close_stands()
 {
    let recorded: world::Recorded = Arc::default();
    let world::Silent {
        _temp,
        controller,
        environment_id,
        session_id,
        accepted: window,
        serving,
        ..
    } = world::fake_worker(Some(Arc::clone(&recorded))).await;
    world::acknowledged(&controller, session_id);
    let who = admitted(&controller).await;
    let forwarded = || {
        recorded
            .lock()
            .expect("the record is not poisoned")
            .iter()
            .filter(|frame| matches!(frame, ControlFrame::Forwarded(_)))
            .count()
    };
    let close = world::close_request(environment_id, session_id);

    let told = close_told(
        &controller,
        &who,
        window,
        &close,
        Between::AnotherDevicesWithdrawal,
    )
    .await;
    assert!(is_not_shown(&told), "the answer is not shown: {told:?}");
    assert_eq!(forwarded(), 1, "the worker was sent the close once");
    assert!(
        controller.admitted_revision(who.0).is_ok(),
        "the connection stands"
    );

    let again = close_told(&controller, &who, window, &close, Between::Nothing).await;
    assert!(
        refusal(&again).is_some() && !is_not_shown(&again),
        "the close asked again is told as the worker answers it: {again:?}"
    );
    assert_eq!(
        forwarded(),
        2,
        "the repeat reached the worker, which answers from its receipt"
    );
    serving.abort();
}
