//! A controller restart and the action windows of the connections it ended, against a real daemon
//! with a worker it adopts and a paired device.

mod net_support;

use kr_protocol::envelope::ParamsValue;
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::ActionId;
use kr_protocol::method::Method;
use kr_protocol::question::QuestionState;
use kr_protocol::receipt::{ActionReadResult, ReceiptState};
use kr_protocol::rights::ActionRight;

use net_support::environment::{Environment, from, read_by_id, resolved, yes};
use net_support::{Device, RawDevice, pair_with};

/// KR-REQ-09.15: a controller restart ends first admission through the windows its connections
/// held, and an action the host had already accepted keeps the deadline it was accepted with. A
/// device that answered a question under the window its connection was given, and whose
/// connection ended with the restart, connects again to the new controller. Presenting a new
/// answer under the old window is refused and does nothing; the window its new connection holds
/// admits it. Presenting the accepted answer again under the old window is answered from the
/// worker's record, with the deadline its receipt named before the restart.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn kr_req_09_15_a_controller_restart_ends_admission_through_an_old_window_and_keeps_an_accepted_deadline()
 {
    let environment = Environment::start().await;
    let accepted_question = environment.worker.ask("accepted-before-the-restart");
    let later_question = environment.worker.ask("asked-after-the-restart");
    let device = Device::create().await;
    let record = pair_with(
        &environment.host,
        &device,
        &environment.owner,
        from(&[ActionRight::SessionView, ActionRight::QuestionRespond], 1),
    )
    .await;

    // An answer accepted under the window the first connection was given.
    let before = RawDevice::connect(&environment.host, &device, &record).await;
    let old_window = before.action_window_id();
    let accepted_action = ActionId::new(kr_ipc::new_uuid());
    let accepted_params = yes(&environment, &accepted_question);
    let first = resolved(
        before
            .mutate(
                Method::QuestionAnswer,
                accepted_action,
                environment.target(),
                &accepted_params,
            )
            .await
            .expect("answered under its connection's window"),
    );
    assert_eq!(first.state, QuestionState::Answered);
    let as_receipt =
        |read: ParamsValue| -> ActionReadResult { read.to_typed().expect("a receipt") };
    let committed = as_receipt(
        before
            .read(Method::ActionRead, &read_by_id(accepted_action))
            .await
            .expect("the receipt is read"),
    )
    .receipt
    .accepted_deadline_ms;
    assert!(
        committed.is_present(),
        "the host named the deadline it accepted the action with"
    );

    // The controller restarts. Its connections end with it; the worker and its records stay.
    before.close();
    let Environment {
        host,
        owner,
        worker,
    } = environment;
    let environment = Environment {
        host: host.restart().await,
        owner,
        worker,
    };
    environment.until_adopted().await;

    let after = RawDevice::connect(&environment.host, &device, &record).await;
    assert_ne!(
        after.action_window_id(),
        old_window,
        "the new controller issued its own window to the new connection"
    );

    // A first admission through the old window is refused, and nothing is done.
    let refused = after
        .mutate_in(
            old_window.clone(),
            Method::QuestionAnswer,
            ActionId::new(kr_ipc::new_uuid()),
            environment.target(),
            &yes(&environment, &later_question),
        )
        .await
        .expect_err("a window the restarted controller never issued admits nothing");
    assert_eq!(refused.code, ErrorCode::PermissionDenied, "{refused}");
    assert_eq!(
        environment.worker.held(&later_question).state,
        QuestionState::Pending,
        "the refused answer did nothing"
    );

    // The window the new connection holds admits the same answer: the refusal was the window's.
    let answered = resolved(
        after
            .mutate(
                Method::QuestionAnswer,
                ActionId::new(kr_ipc::new_uuid()),
                environment.target(),
                &yes(&environment, &later_question),
            )
            .await
            .expect("answered under the new connection's window"),
    );
    assert_eq!(answered.state, QuestionState::Answered);

    // The action accepted before the restart is answered from its record under the old window it
    // was accepted with, and its receipt still names the deadline it had.
    let again = resolved(
        after
            .mutate_in(
                old_window,
                Method::QuestionAnswer,
                accepted_action,
                environment.target(),
                &accepted_params,
            )
            .await
            .expect("an exact retry of an accepted action is answered from its record"),
    );
    assert_eq!(again.question(), first.question());
    let receipt_after = as_receipt(
        after
            .read(Method::ActionRead, &read_by_id(accepted_action))
            .await
            .expect("the receipt is read"),
    )
    .receipt;
    assert_eq!(receipt_after.state, ReceiptState::Applied);
    assert_eq!(
        receipt_after.accepted_deadline_ms, committed,
        "an exact retry never receives a new deadline"
    );
    after.close();
    environment.stop().await;
}
