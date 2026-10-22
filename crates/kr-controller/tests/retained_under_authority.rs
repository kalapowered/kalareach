//! Retained results read under the reader's present authority, through the control daemon.
//!
//! One real daemon on the loopback network, started the way a host starts one, and a real worker it
//! adopts: the worker's own service on its own socket, with its journal, its spool and its shell,
//! run in this process as the privacy and attention suites run one. A paired device reaches the
//! daemon over the network and submits the action identifiers it is given, so a test can present
//! the same action again, and read it by its identifier, as a device that lost its reply does.
//!
//! What each test asserts is read from the daemon's answer to a device, and from the worker's own
//! ledger and journal where a test says what was kept: a device is shown what its present authority
//! reaches of what an action produced, and what the worker keeps is not changed by who reads it.

mod net_support;

use kr_protocol::error::ErrorCode;
use kr_protocol::ids::ActionId;
use kr_protocol::method::Method;
use kr_protocol::question::{QuestionAnswer, QuestionCancelParams, QuestionState};
use kr_protocol::receipt::{ActionReadResult, ReceiptState};
use kr_protocol::rights::ActionRight;

use net_support::environment::{Environment, from, read_by_id, resolved, yes};
use net_support::worker::revoke;

// ---------------------------------------------------------------------------------------------
// The tests
// ---------------------------------------------------------------------------------------------

/// KR-REQ-10.49: a device that may answer is shown the answer's question only if it may view the
/// session, and may answer only a question its history reaches. One that views and reaches it is
/// shown the question whole; one that may respond and not view is told the state and none of the
/// question, and still answers; one whose history begins after the question was asked is refused
/// as for a question the session does not hold, and the question is left pending.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_10_49_a_device_is_shown_a_question_it_answers_as_far_as_its_authority_reaches() {
    let environment = Environment::start().await;
    let viewing = environment.worker.ask("viewing");
    let responding = environment.worker.ask("responding");
    let before = environment.worker.ask("before-the-bound");
    let rights = [ActionRight::SessionView, ActionRight::QuestionRespond];

    // Reaches it and views the session.
    let viewer = environment.device(from(&rights, 1)).await;
    let answered = resolved(
        viewer
            .connection
            .mutate(
                Method::QuestionAnswer,
                ActionId::new(kr_ipc::new_uuid()),
                environment.target(),
                &yes(&environment, &viewing),
            )
            .await
            .expect("the device answers"),
    );
    assert_eq!(answered.state, QuestionState::Answered);
    let shown = answered.question().expect("it is shown the question");
    assert_eq!(shown.question, viewing.question);
    assert_eq!(
        shown.answer.as_ref().map(|record| record.answer.clone()),
        Some(QuestionAnswer::Decision { decided: true })
    );

    // May respond, and not view.
    let responder = environment
        .device(from(&[ActionRight::QuestionRespond], 1))
        .await;
    let answered = resolved(
        responder
            .connection
            .mutate(
                Method::QuestionAnswer,
                ActionId::new(kr_ipc::new_uuid()),
                environment.target(),
                &yes(&environment, &responding),
            )
            .await
            .expect("a device that may respond answers"),
    );
    assert_eq!(answered.state, QuestionState::Answered);
    assert_eq!(answered.question_id, responding.question_id);
    assert_eq!(answered.question(), None);
    assert!(
        !serde_json::to_string(&answered)
            .expect("encodes")
            .contains("Publish the release")
    );
    assert_eq!(
        environment.worker.held(&responding).state,
        QuestionState::Answered,
        "what it answered is held whole"
    );

    // Views, and its history begins after the question.
    let late = environment
        .device(from(&rights, before.created_at_ms.get() + 60_000))
        .await;
    let refused = late
        .connection
        .mutate(
            Method::QuestionAnswer,
            ActionId::new(kr_ipc::new_uuid()),
            environment.target(),
            &yes(&environment, &before),
        )
        .await
        .expect_err("a question before the device's bound is not its to answer");
    assert_eq!(refused.code, ErrorCode::PermissionDenied, "{refused}");
    assert!(
        !refused.message.contains("Publish the release"),
        "{refused}"
    );
    assert_eq!(
        environment.worker.held(&before).state,
        QuestionState::Pending
    );
    let cancelled = late
        .connection
        .mutate(
            Method::QuestionCancel,
            ActionId::new(kr_ipc::new_uuid()),
            environment.target(),
            &QuestionCancelParams {
                session_id: environment.worker.session_id,
                question_id: before.question_id,
                expected_revision: before.revision,
            },
        )
        .await
        .expect_err("nor to cancel");
    assert_eq!(cancelled.code, ErrorCode::PermissionDenied, "{cancelled}");
    assert_eq!(
        environment.worker.held(&before).state,
        QuestionState::Pending
    );
    environment.stop().await;
}

/// KR-REQ-23.34: `action.read` by the action's identifier is decided over the session the action
/// was performed on: a device that may view it and whose history reaches the question reads the
/// receipt and the question, and a device that may respond and not view is refused, and so is a
/// retry of its answer, which is also a read of the receipt. A device is told nothing of what its
/// action produced by presenting it again once the right to view the session is gone.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_23_34_an_action_is_read_by_its_identifier_only_under_view_authority_over_its_session()
 {
    let environment = Environment::start().await;
    let rights = [ActionRight::SessionView, ActionRight::QuestionRespond];

    for views in [true, false] {
        let question = environment
            .worker
            .ask(if views { "read-viewing" } else { "read-blind" });
        let device = environment
            .device(from(
                if views {
                    &rights
                } else {
                    &[ActionRight::QuestionRespond]
                },
                1,
            ))
            .await;
        let action_id = ActionId::new(kr_ipc::new_uuid());
        let params = yes(&environment, &question);
        let first = resolved(
            device
                .connection
                .mutate(
                    Method::QuestionAnswer,
                    action_id,
                    environment.target(),
                    &params,
                )
                .await
                .expect("answered"),
        );
        assert_eq!(first.question().is_some(), views, "the first answer");

        let read = device
            .connection
            .read::<_>(Method::ActionRead, &read_by_id(action_id))
            .await;
        let retried = device
            .connection
            .mutate(
                Method::QuestionAnswer,
                action_id,
                environment.target(),
                &params,
            )
            .await;
        if views {
            let read: ActionReadResult = read
                .expect("a device that may view reads its receipt")
                .to_typed()
                .expect("a receipt");
            assert_eq!(read.receipt.state, ReceiptState::Applied);
            let result = resolved(read.result.0.expect("the result is kept"));
            assert_eq!(result.question(), first.question());
            let again = resolved(retried.expect("a retry is answered from the receipt"));
            assert_eq!(again.question(), first.question());
        } else {
            let denied = read.expect_err("a device that may not view is not told what it did");
            assert_eq!(denied.code, ErrorCode::PermissionDenied, "{denied}");
            let denied = retried.expect_err("nor by presenting it again");
            assert_eq!(denied.code, ErrorCode::PermissionDenied, "{denied}");
        }
        device.connection.close();
    }
    environment.stop().await;
}

/// KR-REQ-23.24: an exact duplicate of an action that kept a result is answered with that result,
/// as it was kept, and does nothing a second time; and the answer is owed only while the device's
/// authority stands.
///
/// A device answers a question and presents the same action again. The worker holds one receipt and
/// one resolution, so the duplicate is answered from them: it is the same answer, byte for byte,
/// the question stays at the revision the first answer left it, and the receipt is not rewritten.
/// Once the grant is withdrawn the same presentation is refused, or the connection ends, before any
/// answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_23_24_a_duplicate_of_an_action_with_a_result_is_answered_with_it_while_authority_stands()
 {
    let environment = Environment::start().await;
    let question = environment.worker.ask("answered-once");
    let rights = [ActionRight::SessionView, ActionRight::QuestionRespond];
    let device = environment.device(from(&rights, 1)).await;
    let action_id = ActionId::new(kr_ipc::new_uuid());
    let params = yes(&environment, &question);

    let first = device
        .connection
        .mutate(
            Method::QuestionAnswer,
            action_id,
            environment.target(),
            &params,
        )
        .await
        .expect("answered");
    let resolution = environment.worker.held(&question);
    assert_eq!(resolution.state, QuestionState::Answered);
    let receipt: ActionReadResult = device
        .connection
        .read::<_>(Method::ActionRead, &read_by_id(action_id))
        .await
        .expect("a device that may view reads its receipt")
        .to_typed()
        .expect("a receipt");

    let again = device
        .connection
        .mutate(
            Method::QuestionAnswer,
            action_id,
            environment.target(),
            &params,
        )
        .await
        .expect("a duplicate is answered");
    assert_eq!(
        again, first,
        "the duplicate is answered with the result the first attempt kept"
    );
    assert_eq!(
        environment.worker.held(&question).revision,
        resolution.revision,
        "the question was answered once"
    );
    let reread: ActionReadResult = device
        .connection
        .read::<_>(Method::ActionRead, &read_by_id(action_id))
        .await
        .expect("the receipt is read again")
        .to_typed()
        .expect("a receipt");
    assert_eq!(
        reread.receipt.revision, receipt.receipt.revision,
        "the duplicate wrote nothing to the receipt"
    );

    revoke(&environment.host, device._record.grant.grant_id).await;
    let after = device
        .connection
        .try_mutate(
            Method::QuestionAnswer,
            action_id,
            environment.target(),
            &params,
        )
        .await;
    assert!(
        !matches!(after, Some(Ok(_))),
        "a device whose grant is withdrawn is given no answer by presenting its action again: {after:?}"
    );
    environment.stop().await;
}
