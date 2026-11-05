//! What a paired device is told when this host will not show it the answer to an action that its
//! worker carried out.
//!
//! One real daemon on the loopback network, a real worker it adopts, and a paired device over the
//! transport that answers a question the worker holds. The host decides again whether the device
//! may be shown an answer before it writes it, and the device's standing can change between the
//! worker's carrying the action out and that decision. A client that takes a refusal for the
//! host's word that nothing was done drops an action that landed, so the host never refuses one:
//! it tells the device that the outcome is unknown. Each case reads what the worker's own ledger
//! holds as well as what the device was told.

mod net_support;

use std::future::Future;

use kr_protocol::error::{ErrorCode, RetryCategory};
use kr_protocol::ids::{ActionId, QuestionRevision};
use kr_protocol::method::Method;
use kr_protocol::question::{QuestionAnswerParams, QuestionState};
use kr_protocol::rights::ActionRight;

use net_support::environment::{Environment, from, resolved, yes};

const VIEWING: [ActionRight; 2] = [ActionRight::SessionView, ActionRight::QuestionRespond];

/// Runs `call` to the pause it was armed for, raises the refusal the authority feed puts on remote
/// grants there, lets the call go, and returns what it answered.
///
/// A call that is answered before it reaches its pause fails the case at once, instead of leaving
/// it to wait for a pause that cannot come.
async fn refused_at_its_pause<T>(
    environment: &Environment,
    pause: (
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
    ),
    call: impl Future<Output = T>,
) -> T {
    let (arrived, go) = pause;
    tokio::pin!(call);
    tokio::select! {
        arrived = arrived => arrived.expect("the call arrives at its pause"),
        _ = &mut call => panic!("the call was answered before it reached its pause"),
    }
    environment
        .host
        .controller()
        .raise_the_unverified_withdrawal_refusal()
        .await;
    go.send(()).expect("the call waits at its pause");
    call.await
}

/// An answer the worker took, whose grant the authority feed refuses before the reply is written,
/// is told to the device as an outcome that is unknown. The worker holds the answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn an_answer_the_worker_took_is_not_refused_when_the_grant_is_refused_before_the_reply() {
    let environment = Environment::start().await;
    let question = environment.worker.ask("taken");
    let device = environment.device(from(&VIEWING, 1)).await;
    let params = yes(&environment, &question);

    let told = refused_at_its_pause(
        &environment,
        environment.host.pause_after_the_worker_answered(),
        device.connection.mutate(
            Method::QuestionAnswer,
            ActionId::new(kr_ipc::new_uuid()),
            environment.target(),
            &params,
        ),
    )
    .await;

    assert_eq!(
        environment.worker.held(&question).state,
        QuestionState::Answered,
        "the worker took the answer"
    );
    let told = net_support::refusal(told);
    assert_eq!(told.code, ErrorCode::OutcomeUnknown, "{told:?}");
    assert!(
        told.message.contains("may have been carried out"),
        "{told:?}"
    );
    device.connection.close();
    environment.stop().await;
}

/// The control of the case above: an answer the worker refused is still refused, and it is the
/// refusal that replaces it. The host does not turn every refusal into an unknown outcome.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn an_answer_the_worker_refused_is_still_refused_when_the_grant_is_refused_before_the_reply()
{
    let environment = Environment::start().await;
    let question = environment.worker.ask("refused");
    let device = environment.device(from(&VIEWING, 1)).await;
    let stale = QuestionAnswerParams {
        expected_revision: QuestionRevision::new(question.revision.get() + 1),
        ..yes(&environment, &question)
    };

    let told = refused_at_its_pause(
        &environment,
        environment.host.pause_after_the_worker_answered(),
        device.connection.mutate(
            Method::QuestionAnswer,
            ActionId::new(kr_ipc::new_uuid()),
            environment.target(),
            &stale,
        ),
    )
    .await;

    assert_eq!(
        environment.worker.held(&question).state,
        QuestionState::Pending,
        "the worker took nothing"
    );
    let told = net_support::refusal(told);
    assert_eq!(told.code, ErrorCode::PermissionDenied, "{told:?}");
    assert_ne!(
        told.code.retry_category(),
        RetryCategory::OutcomeUnknown,
        "{told:?}"
    );
    device.connection.close();
    environment.stop().await;
}

/// A device that lost its reply presents the same action again, and the worker answers from the
/// receipt it holds. When the grant is refused by the authority feed after that and before the
/// reply is written, the device is told the outcome is unknown and not that it is refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_repeat_the_worker_answers_from_its_receipt_is_not_refused_when_the_grant_is_refused_before_the_reply()
 {
    let environment = Environment::start().await;
    let question = environment.worker.ask("repeated");
    let device = environment.device(from(&VIEWING, 1)).await;
    let action = ActionId::new(kr_ipc::new_uuid());
    let params = yes(&environment, &question);
    // The host renews the window a connection holds, and a repeat under another window is another
    // request, so both presentations go under the one the first was made under.
    let window = device.connection.action_window_id();

    let first = resolved(
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
            .expect("the device answers"),
    );
    assert_eq!(first.state, QuestionState::Answered);

    let told = refused_at_its_pause(
        &environment,
        environment.host.pause_retained_lookup(),
        device.connection.mutate_in(
            window,
            Method::QuestionAnswer,
            action,
            environment.target(),
            &params,
        ),
    )
    .await;

    assert_eq!(
        environment.worker.held(&question).state,
        QuestionState::Answered
    );
    let told = net_support::refusal(told);
    assert_eq!(told.code, ErrorCode::OutcomeUnknown, "{told:?}");
    assert!(
        told.message.contains("may have been carried out"),
        "{told:?}"
    );
    device.connection.close();
    environment.stop().await;
}
