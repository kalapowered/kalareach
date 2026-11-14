//! What the local door tells of a close once the route has answered and authority has moved.
//!
//! The close goes to the worker that owns the session, which keeps its own receipts, so the daemon
//! cannot tell the worker's first answer from a copy of an earlier one: the whole answer is a copy,
//! and the door tells it only under the strict check. The same holds for the answer a duplicate
//! close is given from the closure record, which is a record of what an earlier close did.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use kr_ipc::endpoint::Listener;
use kr_ipc::framed::split;
use kr_ipc::verify::WorkerIdentity;
use kr_protocol::envelope::{ControlFrame, MutationRequest, Outcome, ParamsValue, Response};
use kr_protocol::frame::StreamKind;
use kr_protocol::ids::{ActionId, ActorId, ConnectionId, SessionId};
use kr_protocol::method::Method;
use kr_protocol::scalars::{CanonicalSet, Nullable};
use kr_protocol::session::{Durability, SessionCloseResult, SessionState};
use kr_protocol::worker::AuthorityRevisionAck;
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
/// no longer in the directory, is a copy: it is told while no fence is owed and the connection's
/// registration is the one the request was admitted under. A fence this host comes to owe after the
/// record was read and before the answer is told keeps it from the caller, and so does another
/// device's withdrawal that completes there, which leaves the connection standing with no fence
/// owed and stamps its registration with a newer revision (a result of this route is withheld under
/// a fence whatever its label, so only the restamp tells a copy from a first answer). The repeat
/// on the same connection is admitted under the new revision and answered from the record.
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
    let told = close_told(
        &controller,
        &who,
        window,
        &world::close_request(environment_id, closed),
        Between::AnotherDevicesWithdrawal,
    )
    .await;
    assert!(
        is_not_shown(&told),
        "a copy is not told under another revision than its request was admitted under: {told:?}"
    );
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
        "the repeat is admitted under the new revision and answered: {told:?}"
    );
    serving.abort();
}

/// What a worker that accepts a close has kept of the closes it was sent.
#[derive(Default)]
struct Kept {
    /// The closes it carried out: one for each action it was sent, whatever the repeats.
    closes: usize,
    /// Every close frame it was sent, repeats included.
    forwarded: usize,
    /// The answer it gave each action, which it gives again to a repeat of that action instead of
    /// closing again.
    answers: Vec<(ActionId, ParamsValue)>,
}

/// The acceptance a worker gives a close: the session is closing, as the worker describes it.
fn acceptance(session_id: SessionId) -> ParamsValue {
    let mut session = world::read_result(session_id).session;
    session.state = SessionState::Closing;
    ParamsValue::from_typed(&SessionCloseResult {
        session_id,
        state: SessionState::Closing,
        durability: Durability::Durable,
        closure: Nullable::null(),
        session: Some(session),
    })
    .expect("encodes")
}

/// What an accepting worker answers `frame` with, after the handshake: the revision announced to it
/// is installed, a close it has not seen is carried out and accepted, a repeat of one it has seen is
/// answered with the answer it kept, and the daemon's own read of the session is answered.
fn accepting_answers(
    frame: &ControlFrame,
    identity: &WorkerIdentity,
    kept: &Mutex<Kept>,
) -> Vec<ControlFrame> {
    let answer = |request_id, outcome| {
        vec![ControlFrame::Response(Response {
            request_id,
            outcome,
        })]
    };
    match frame {
        ControlFrame::AuthorityRevision(notice) => {
            vec![ControlFrame::AuthorityRevisionAck(AuthorityRevisionAck {
                session_id: identity.session_id(),
                revision: notice.revision,
                fence: None,
            })]
        }
        ControlFrame::Forwarded(forwarded) => {
            let mutation = &forwarded.mutation;
            let mut kept = kept.lock().unwrap_or_else(PoisonError::into_inner);
            kept.forwarded += 1;
            let kept_answer = kept
                .answers
                .iter()
                .find(|(action, _)| *action == mutation.action_id)
                .map(|(_, answer)| answer.clone());
            let given = kept_answer.unwrap_or_else(|| {
                kept.closes += 1;
                let accepted = acceptance(identity.session_id());
                kept.answers.push((mutation.action_id, accepted.clone()));
                accepted
            });
            answer(mutation.request_id, Outcome::Ok(given))
        }
        ControlFrame::Request(request) if request.method == Method::SessionRead.into() => answer(
            request.request_id,
            Outcome::Ok(
                ParamsValue::from_typed(&world::read_result(identity.session_id()))
                    .expect("encodes"),
            ),
        ),
        _ => Vec::new(),
    }
}

/// An endpoint that proves itself as a worker and then accepts every close it is sent, keeping its
/// answer to each action so that a repeat is answered from it and closes nothing again.
fn serve_accepting_worker(
    listener: Listener,
    identity: Arc<WorkerIdentity>,
    endpoint_text: String,
    kept: Arc<Mutex<Kept>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            let Ok((connection, peer)) = listener.accept().await else {
                return;
            };
            let (identity, endpoint_text, kept) = (
                Arc::clone(&identity),
                endpoint_text.clone(),
                Arc::clone(&kept),
            );
            tokio::spawn(async move {
                let (mut reader, mut writer) = split(connection, StreamKind::Control);
                let connection_id = ConnectionId::new(kr_ipc::new_uuid());
                while let Ok(frame) = reader.read_message::<ControlFrame>().await {
                    let answers = world::handshake(
                        &frame,
                        &identity,
                        &endpoint_text,
                        connection_id,
                        &peer,
                        &CanonicalSet::new(),
                    )
                    .unwrap_or_else(|| accepting_answers(&frame, &identity, &kept));
                    for answer in answers {
                        if writer.write_message(&answer).await.is_err() {
                            return;
                        }
                    }
                }
            });
        }
    })
}

/// The close result a frame carries, when it carries one.
fn close_result(frame: &ControlFrame) -> Option<SessionCloseResult> {
    match frame {
        ControlFrame::Response(Response {
            outcome: Outcome::Ok(value),
            ..
        }) => value.to_typed().ok(),
        _ => None,
    }
}

/// A close, and the same close asked again, to a worker that accepts it and keeps its answer.
struct Closed {
    /// What the door told of the close, with `between` happening once the route had answered.
    first: ControlFrame,
    /// What the door told of the same close asked again with nothing between.
    repeat: ControlFrame,
    /// The closes the worker had carried out when the first was told.
    closes_after_the_first: usize,
    /// The closes it had carried out when the repeat was told.
    closes: usize,
    /// The close frames it had been sent when the repeat was told.
    forwarded: usize,
    /// Whether this daemon held the session as closing when the first was told.
    closing: bool,
}

/// Asks a worker that accepts closes to close its session, with `between` happening once the route
/// has answered and before the answer is told, and then asks the same close again.
async fn a_close_and_its_repeat(between: Between) -> Closed {
    let kept: Arc<Mutex<Kept>> = Arc::default();
    let world::Silent {
        _temp,
        controller,
        environment_id,
        session_id,
        accepted: window,
        serving,
        ..
    } = world::fake_world({
        let kept = Arc::clone(&kept);
        move |listener, identity, endpoint_text| {
            serve_accepting_worker(listener, identity, endpoint_text, kept)
        }
    })
    .await;
    world::acknowledged(&controller, session_id);
    let who = admitted(&controller).await;
    let close = world::close_request(environment_id, session_id);
    let counts = || {
        let kept = kept.lock().unwrap_or_else(PoisonError::into_inner);
        (kept.closes, kept.forwarded)
    };

    let first = close_told(&controller, &who, window, &close, between).await;
    let (closes_after_the_first, _) = counts();
    let closing = controller
        .directory
        .lock()
        .await
        .ending(session_id)
        .is_some_and(|read| read.session.state == SessionState::Closing);
    let repeat = close_told(&controller, &who, window, &close, Between::Nothing).await;
    let (closes, forwarded) = counts();
    serving.abort();
    Closed {
        first,
        repeat,
        closes_after_the_first,
        closes,
        forwarded,
        closing,
    }
}

/// KR-REQ-09.09: a close that a worker accepts is told as the worker accepted it while no fence is
/// owed, and the worker answers the same close asked again from the answer it kept, closing nothing
/// again. The control of the cases below.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_close_a_worker_accepts_is_told_and_its_repeat_is_answered_from_the_workers_receipt() {
    let closed = a_close_and_its_repeat(Between::Nothing).await;
    let accepted = close_result(&closed.first)
        .unwrap_or_else(|| panic!("the acceptance is told: {:?}", closed.first));
    assert_eq!(accepted.state, SessionState::Closing);
    assert!(
        closed.closing,
        "this daemon holds the session as closing once the acceptance is settled"
    );
    assert_eq!(
        closed.closes_after_the_first, 1,
        "one close was carried out"
    );
    assert_eq!(
        close_result(&closed.repeat),
        Some(accepted),
        "the repeat is answered with the answer the worker kept"
    );
    assert_eq!(closed.closes, 1, "the repeat closed nothing again");
    assert_eq!(closed.forwarded, 2, "the repeat reached the worker");
}

/// What a close that a worker accepted leaves when the door does not tell the acceptance: the
/// worker carried the close out once and this daemon holds the session as closing, so the effect
/// stands, and the same close asked again is answered from what the worker kept, with nothing
/// closed a second time.
fn the_close_stands_and_its_repeat_is_answered(closed: &Closed) {
    assert!(
        is_not_shown(&closed.first),
        "the acceptance is not shown: {:?}",
        closed.first
    );
    assert_eq!(
        closed.closes_after_the_first, 1,
        "the close was carried out"
    );
    assert!(
        closed.closing,
        "this daemon holds the session as closing: the acceptance was settled before it was withheld"
    );
    let repeat = close_result(&closed.repeat)
        .unwrap_or_else(|| panic!("the repeat is answered: {:?}", closed.repeat));
    assert_eq!(repeat.state, SessionState::Closing);
    assert_eq!(closed.closes, 1, "the repeat closed nothing again");
    assert_eq!(
        closed.forwarded, 2,
        "the repeat reached the worker, which answered from the answer it kept"
    );
}

/// KR-REQ-09.09: a fence this host comes to owe after a worker's acceptance of a close has arrived
/// keeps the acceptance from the caller, who is told that what became of the action is not shown;
/// the close stands, and the same close asked once the fence is gone is answered from the worker's
/// receipt.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_close_a_worker_accepts_is_not_shown_when_a_fence_lands_after_it_and_the_close_stands() {
    the_close_stands_and_its_repeat_is_answered(&a_close_and_its_repeat(Between::AFence).await);
}

/// KR-REQ-09.09: the accepted price of telling a worker's answer as a copy. Another device's
/// withdrawal that completes between a first close's route answer and its reply stamps the
/// connection's registration with a new revision, and the acceptance is not shown although the
/// connection stands and no fence is owed. The close stands; the same close asked again on the same
/// connection is admitted under the new revision and answered from the worker's receipt.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn another_devices_withdrawal_between_a_first_closes_effect_and_its_reply_is_not_shown_and_the_close_stands()
 {
    the_close_stands_and_its_repeat_is_answered(
        &a_close_and_its_repeat(Between::AnotherDevicesWithdrawal).await,
    );
}
