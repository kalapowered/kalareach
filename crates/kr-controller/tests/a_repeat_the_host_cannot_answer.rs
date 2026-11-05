//! What a paired device is told when it presents again an action the host had already routed, and
//! the host cannot show it what became of it.
//!
//! One real daemon on the loopback network, a real worker it adopts, and a paired device over the
//! transport. The device sends an action, the worker carries it out, and the device presents the
//! same request again on a connection of its own choosing, as a client does when an answer was
//! lost. A client takes a definite refusal for the host's word that nothing was done and drops the
//! action, so when this host refuses the repeat on its own account (the window another connection
//! holds, a connection opened for something else, a grant that has gone, a worker that has ended)
//! it tells the device that the outcome is unknown. A request the host had not routed is refused as
//! it always was, and so is a reused identifier carrying another request. Each case reads what the
//! worker holds as well as what the device was told.

mod net_support;

use kr_protocol::envelope::ControlFrame;
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{ActionId, GrantId, QuestionRevision, SessionId};
use kr_protocol::method::Method;
use kr_protocol::question::{QuestionAnswerParams, QuestionState};
use kr_protocol::receipt::ReceiptState;
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::Nullable;
use kr_protocol::session::{
    SessionCloseParams, SessionCloseResult, SessionOpenParams, SessionState,
};
use kr_protocol::sharing::{RoleSelection, SessionRole};

use net_support::environment::{Environment, Paired, from, resolved, yes};
use net_support::worker::{revoke, share};
use net_support::{Host, RawDevice, refusal};

const ANSWERING: [ActionRight; 2] = [ActionRight::SessionView, ActionRight::QuestionRespond];
const CLOSING: [ActionRight; 2] = [ActionRight::SessionView, ActionRight::SessionClose];

/// The device is told the outcome is unknown, in the host's one sentence for it.
fn assert_unknown(told: &ProtocolError) {
    assert_eq!(told.code, ErrorCode::OutcomeUnknown, "{told:?}");
    assert!(
        told.message.contains("may have been carried out"),
        "{told:?}"
    );
}

/// A connection to the host as the paired device `paired` is.
async fn another_connection(host: &Host, paired: &Paired) -> RawDevice {
    RawDevice::connect(host, &paired._device, &paired._record).await
}

/// Opens `connection` for the host (no session) or for one session, under the pairing grant or the
/// grant named.
async fn open(connection: &RawDevice, session: Option<SessionId>, grant: Option<GrantId>) {
    connection
        .read(
            Method::SessionOpen,
            &SessionOpenParams {
                session_id: Nullable(session),
                grant_id: Nullable(grant),
            },
        )
        .await
        .expect("the connection is opened");
}

/// A share of the environment's session that lets its holder answer `question`.
async fn a_share_that_answers(
    environment: &Environment,
    paired: &Paired,
    question: &kr_protocol::question::Question,
) -> GrantId {
    let selection = RoleSelection {
        include_question_respond: true,
        named_questions: kr_protocol::scalars::CanonicalSet::from_iter([question.question_id]),
        ..RoleSelection::plain(SessionRole::Viewer)
    };
    share(
        &environment.host,
        environment.worker.session_id,
        &paired._device,
        &paired._record,
        selection,
    )
    .await
    .grant_id
}

/// The device answers its question under the share it names, which the worker takes.
async fn answered_under(
    environment: &Environment,
    paired: &Paired,
    share: GrantId,
    action: ActionId,
    params: &QuestionAnswerParams,
) -> kr_protocol::ids::ActionWindowId {
    let window = paired.connection.action_window_id();
    let first = resolved(
        paired
            .connection
            .mutate_naming_in(
                share,
                window.clone(),
                Method::QuestionAnswer,
                action,
                environment.target(),
                params,
            )
            .await
            .expect("the device answers under its share"),
    );
    assert_eq!(first.state, QuestionState::Answered);
    window
}

/// The worker the action went to has ended, and the host holds a route for the action but no worker
/// to ask for the receipt. The repeat arrives on a connection that was not issued its window.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_repeat_after_its_worker_has_ended_is_told_the_outcome_is_unknown() {
    let environment = Environment::start().await;
    let question = environment.worker.ask("ended");
    let device = environment.device(from(&ANSWERING, 1)).await;
    let params = yes(&environment, &question);
    let target = environment.target();
    let action = ActionId::new(kr_ipc::new_uuid());
    let window = device.connection.action_window_id();

    let first = resolved(
        device
            .connection
            .mutate_in(
                window.clone(),
                Method::QuestionAnswer,
                action,
                target.clone(),
                &params,
            )
            .await
            .expect("the device answers"),
    );
    assert_eq!(first.state, QuestionState::Answered);
    assert_eq!(
        environment.worker.held(&question).state,
        QuestionState::Answered,
        "the worker took the answer"
    );
    environment.worker.stop().await;

    let again = another_connection(&environment.host, &device).await;
    let told = refusal(
        again
            .mutate_in(window, Method::QuestionAnswer, action, target, &params)
            .await,
    );
    assert_unknown(&told);
    again.close();
    device.connection.close();
    environment.host.stop().await;
}

/// The control of the case above: an action the host never routed, presented on a connection that
/// was not issued its window, is refused for the window, and the worker took nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_request_the_host_never_routed_is_refused_for_its_window() {
    let environment = Environment::start().await;
    let question = environment.worker.ask("unrouted");
    let device = environment.device(from(&ANSWERING, 1)).await;
    let params = yes(&environment, &question);
    let window = device.connection.action_window_id();

    let again = another_connection(&environment.host, &device).await;
    let told = refusal(
        again
            .mutate_in(
                window,
                Method::QuestionAnswer,
                ActionId::new(kr_ipc::new_uuid()),
                environment.target(),
                &params,
            )
            .await,
    );
    assert_eq!(told.code, ErrorCode::PermissionDenied, "{told:?}");
    assert_eq!(
        environment.worker.held(&question).state,
        QuestionState::Pending
    );
    again.close();
    device.connection.close();
    environment.stop().await;
}

/// A reused identifier carrying another request is refused as such, whatever the connection: the
/// request the host refuses is not the one it routed.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_reused_identifier_carrying_another_request_is_still_a_conflict() {
    let environment = Environment::start().await;
    let question = environment.worker.ask("conflict");
    let device = environment.device(from(&ANSWERING, 1)).await;
    let params = yes(&environment, &question);
    let action = ActionId::new(kr_ipc::new_uuid());
    let window = device.connection.action_window_id();
    device
        .connection
        .mutate_in(
            window.clone(),
            Method::QuestionAnswer,
            action,
            environment.target(),
            &params,
        )
        .await
        .expect("the device answers");

    let another = QuestionAnswerParams {
        expected_revision: QuestionRevision::new(params.expected_revision.get() + 1),
        ..params
    };
    let told = refusal(
        device
            .connection
            .mutate_in(
                window,
                Method::QuestionAnswer,
                action,
                environment.target(),
                &another,
            )
            .await,
    );
    assert_eq!(told.code, ErrorCode::IdConflict, "{told:?}");
    device.connection.close();
    environment.stop().await;
}

/// A refusal the worker recorded for an action is the worker's word, and a repeat is told it: only
/// what the host refuses on its own account is told as unknown.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_repeat_the_worker_answers_with_its_refusal_is_still_refused() {
    let environment = Environment::start().await;
    let question = environment.worker.ask("refused");
    let device = environment.device(from(&ANSWERING, 1)).await;
    let stale = QuestionAnswerParams {
        expected_revision: QuestionRevision::new(question.revision.get() + 1),
        ..yes(&environment, &question)
    };
    let action = ActionId::new(kr_ipc::new_uuid());
    let window = device.connection.action_window_id();
    let first = refusal(
        device
            .connection
            .mutate_in(
                window.clone(),
                Method::QuestionAnswer,
                action,
                environment.target(),
                &stale,
            )
            .await,
    );
    assert_ne!(first.code, ErrorCode::OutcomeUnknown, "{first:?}");

    let answered = device
        .connection
        .try_answer_in(
            None,
            window,
            Method::QuestionAnswer,
            action,
            environment.target(),
            &stale,
        )
        .await
        .expect("the host answers the repeat");
    match &answered {
        ControlFrame::Receipt(response) => assert!(
            matches!(
                response.receipt.state,
                ReceiptState::Refused | ReceiptState::Rejected
            ),
            "{answered:?}"
        ),
        ControlFrame::Response(response) => {
            let error = match &response.outcome {
                kr_protocol::envelope::Outcome::Error(error) => error,
                kr_protocol::envelope::Outcome::Ok(_) => panic!("{answered:?}"),
            };
            assert_ne!(error.code, ErrorCode::OutcomeUnknown, "{answered:?}");
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(
        environment.worker.held(&question).state,
        QuestionState::Pending,
        "the worker took nothing"
    );
    device.connection.close();
    environment.stop().await;
}

/// A close ends its worker, so the repeat of one whose answer was lost finds the session closed.
/// The host holds the closure record, and answers the repeat from it, on a connection that was not
/// issued the close's window, as it answers a close made after the closure.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_repeated_close_is_answered_from_the_closure_record_on_another_connection() {
    let environment = Environment::start().await;
    let device = environment.device(from(&CLOSING, 1)).await;
    let params = SessionCloseParams {
        session_id: environment.worker.session_id,
    };
    let target = environment.target();
    let action = ActionId::new(kr_ipc::new_uuid());
    let window = device.connection.action_window_id();

    device
        .connection
        .mutate_in(
            window.clone(),
            Method::SessionClose,
            action,
            target.clone(),
            &params,
        )
        .await
        .expect("the worker accepts the close");
    let closure = environment.worker.runtime().wait_closed().await;
    environment
        .host
        .controller()
        .retire(&closure)
        .await
        .expect("the closure is recorded");

    let again = another_connection(&environment.host, &device).await;
    let answered: SessionCloseResult = again
        .mutate_in(window, Method::SessionClose, action, target, &params)
        .await
        .expect("the closure record answers the repeat")
        .to_typed()
        .expect("a close result");
    assert_eq!(answered.state, SessionState::Closed);
    again.close();
    device.connection.close();
    environment.stop().await;
}

/// A device that may close a session but may not read what became of an action is not shown the
/// closure either, and is told the outcome is unknown.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_repeated_close_a_device_may_not_read_is_told_the_outcome_is_unknown() {
    let environment = Environment::start().await;
    let device = environment
        .device(from(&[ActionRight::SessionClose], 1))
        .await;
    let params = SessionCloseParams {
        session_id: environment.worker.session_id,
    };
    let target = environment.target();
    let action = ActionId::new(kr_ipc::new_uuid());
    let window = device.connection.action_window_id();

    device
        .connection
        .mutate_in(
            window.clone(),
            Method::SessionClose,
            action,
            target.clone(),
            &params,
        )
        .await
        .expect("the worker accepts the close");
    let closure = environment.worker.runtime().wait_closed().await;
    environment
        .host
        .controller()
        .retire(&closure)
        .await
        .expect("the closure is recorded");

    let again = another_connection(&environment.host, &device).await;
    let told = refusal(
        again
            .mutate_in(window, Method::SessionClose, action, target, &params)
            .await,
    );
    assert_unknown(&told);
    again.close();
    device.connection.close();
    environment.stop().await;
}

/// A repeat of an action taken under a share arrives on a connection opened for the host alone, or
/// for the session under the pairing grant, and the host does not serve it there. It is not told
/// the action was refused; the connection opened under the share itself is answered from the
/// worker's receipt, as a repeat always was.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_repeat_on_a_connection_opened_for_something_else_is_told_the_outcome_is_unknown() {
    let environment = Environment::start_reserved().await;
    let question = environment.worker.ask("shared");
    let device = environment
        .device(from(&[ActionRight::SessionView], 1))
        .await;
    let held = a_share_that_answers(&environment, &device, &question).await;
    let params = yes(&environment, &question);
    let action = ActionId::new(kr_ipc::new_uuid());
    let window = answered_under(&environment, &device, held, action, &params).await;
    assert_eq!(
        environment.worker.held(&question).state,
        QuestionState::Answered,
        "the worker took the answer"
    );

    let session = environment.worker.session_id;
    let for_the_host = another_connection(&environment.host, &device).await;
    open(&for_the_host, None, None).await;
    let for_the_session = another_connection(&environment.host, &device).await;
    open(&for_the_session, Some(session), None).await;
    for connection in [&for_the_host, &for_the_session] {
        let told = refusal(
            connection
                .mutate_naming_in(
                    held,
                    window.clone(),
                    Method::QuestionAnswer,
                    action,
                    environment.target(),
                    &params,
                )
                .await,
        );
        assert_unknown(&told);
    }

    // The control: the connection opened under the share answers the repeat from the receipt.
    let under_the_share = another_connection(&environment.host, &device).await;
    open(&under_the_share, Some(session), Some(held)).await;
    let repeated = resolved(
        under_the_share
            .mutate_naming_in(
                held,
                window,
                Method::QuestionAnswer,
                action,
                environment.target(),
                &params,
            )
            .await
            .expect("the repeat is answered from the worker's receipt"),
    );
    assert_eq!(repeated.state, QuestionState::Answered);
    for connection in [for_the_host, for_the_session, under_the_share] {
        connection.close();
    }
    device.connection.close();
    environment.stop().await;
}

/// The share an action was taken under is revoked before the repeat. The device no longer holds
/// the grant the repeat names, and is not told the action it took under it was refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_repeat_under_a_share_that_has_been_revoked_is_told_the_outcome_is_unknown() {
    let environment = Environment::start_reserved().await;
    let question = environment.worker.ask("revoked");
    let device = environment
        .device(from(&[ActionRight::SessionView], 1))
        .await;
    let held = a_share_that_answers(&environment, &device, &question).await;
    let params = yes(&environment, &question);
    let action = ActionId::new(kr_ipc::new_uuid());
    let window = answered_under(&environment, &device, held, action, &params).await;
    revoke(&environment.host, held).await;
    assert_eq!(
        environment.worker.held(&question).state,
        QuestionState::Answered,
        "the worker took the answer"
    );

    let again = another_connection(&environment.host, &device).await;
    let told = refusal(
        again
            .mutate_naming_in(
                held,
                window,
                Method::QuestionAnswer,
                action,
                environment.target(),
                &params,
            )
            .await,
    );
    assert_unknown(&told);
    again.close();
    device.connection.close();
    environment.stop().await;
}
