//! What the local door tells of a write whose own effect has run, once the route has answered.
//!
//! The door asks the answer what it stands on where it tells it, and not where the effect ran: a
//! result of an effect that ran is shown only while the caller's registration stands and no fence
//! is owed; otherwise the caller is told what became of it is not shown, and a refusal that says
//! nothing was done is told as the check's own refusal. A request whose own effect withdrew the
//! whole host through a barrier it raised is the one result that outlives the withdrawal of its
//! own connection, and only until another barrier moves the revision.

use std::sync::Arc;
use std::time::Duration;

use kr_protocol::envelope::{ControlFrame, MutationRequest, ParamsValue};
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{ConnectionId, RequestId};
use kr_protocol::method::Method;
use kr_protocol::sharing::GrantRevokeParams;

use super::the_fence_at_every_effect::{
    accepted, admitted, daemon, mutation_of, refusal, refused_for_a_fence, told_now,
};
use super::{Controller, Reach};
use crate::given::local_door::{Standing, told};
use crate::given::{Given, Settled};

/// The not-shown refusal.
pub(super) fn not_shown(frame: &ControlFrame) {
    let error = refusal(frame).unwrap_or_else(|| panic!("a refusal was told: {frame:?}"));
    assert_eq!(error.code, ErrorCode::OutcomeUnknown, "{error:?}");
    assert_eq!(
        error.message,
        crate::error::ControllerError::outcome_not_shown().to_string(),
        "{error:?}"
    );
}

/// The confirmation of a restored policy: a first admission that keeps no record of its action and
/// answers with a result of this request's own effect.
fn a_result(temp: &kr_ipc::testing::TempHost) -> (Method, MutationRequest) {
    (
        Method::HostPolicyConfirm,
        mutation_of(
            temp,
            Method::HostPolicyConfirm,
            ParamsValue::from_typed(&kr_protocol::organisation::HostPolicyConfirmParams {})
                .expect("encodes"),
        ),
    )
}

/// A revocation of a grant this host does not hold: a first admission that answers with a refusal
/// that says nothing was done.
fn a_definite_refusal(temp: &kr_ipc::testing::TempHost) -> (Method, MutationRequest) {
    (
        Method::GrantRevoke,
        mutation_of(
            temp,
            Method::GrantRevoke,
            ParamsValue::from_typed(&GrantRevokeParams {
                grant_id: kr_protocol::ids::GrantId::new(kr_ipc::new_uuid()),
            })
            .expect("encodes"),
        ),
    )
}

/// What the door tells of `mutation` on a connection of its own, with `meanwhile` done once the
/// route has answered and before the answer is told.
async fn told_after_the_route_answers(
    controller: &Arc<Controller>,
    (method, mutation): (Method, MutationRequest),
    meanwhile: impl FnOnce(ConnectionId),
) -> ControlFrame {
    let (connection_id, actor_id) = admitted(controller).await;
    let (arrived, release) = controller.pause_after_a_route_answers();
    let telling = tokio::spawn({
        let controller = Arc::clone(controller);
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
    tokio::time::timeout(Duration::from_secs(30), arrived)
        .await
        .expect("the route answers")
        .expect("the pause is armed");
    meanwhile(connection_id);
    release.send(()).expect("the door goes on");
    telling.await.expect("the door tells it")
}

/// KR-REQ-09.09, 09.12: a result of an effect that ran is not shown to a caller whose connection
/// was withdrawn while the route answered, and a refusal that says nothing was done is told as the
/// refusal of the authority. The controls: the connection stands, and a registration restamped by
/// a revocation that did not withdraw this one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_result_is_not_shown_once_the_connection_is_withdrawn_after_the_route_answers() {
    let (temp, controller, _clock) = daemon().await;

    let given = told_after_the_route_answers(&controller, a_result(&temp), |_| {}).await;
    assert!(
        refusal(&given).is_none(),
        "the connection stands: {given:?}"
    );
    let given = told_after_the_route_answers(&controller, a_definite_refusal(&temp), |_| {}).await;
    assert_eq!(
        refusal(&given).expect("a refusal").code,
        ErrorCode::InvalidArgument,
        "the connection stands, so the route's own refusal is told: {given:?}"
    );

    // Another device's revocation restamps every registration and withdraws none of them.
    let restamped = told_after_the_route_answers(&controller, a_result(&temp), |_| {
        controller
            .admitted_write()
            .values_mut()
            .for_each(|connection| {
                connection.admitted_revision = kr_protocol::ids::AuthorityRevision::new(
                    connection.admitted_revision.get() + 1,
                );
            });
    })
    .await;
    assert!(
        refusal(&restamped).is_none(),
        "a result of this request's own effect is told while its registration stands: {restamped:?}"
    );

    let gone = told_after_the_route_answers(&controller, a_result(&temp), |connection_id| {
        controller.deregister(connection_id);
    })
    .await;
    not_shown(&gone);
    let gone =
        told_after_the_route_answers(&controller, a_definite_refusal(&temp), |connection_id| {
            controller.deregister(connection_id)
        })
        .await;
    assert_eq!(
        refusal(&gone).expect("a refusal").code,
        ErrorCode::PermissionDenied,
        "a refusal that says nothing was done is told as the refusal of the authority: {gone:?}"
    );
}

/// KR-REQ-09.09, 09.12: a result is not shown while this host owes a fence it could not raise,
/// whether or not the connection stands, and a refusal that says nothing was done is the fence's.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_result_is_not_shown_while_a_fence_is_owed_after_the_route_answers() {
    let (temp, controller, _clock) = daemon().await;
    let owed = told_after_the_route_answers(&controller, a_result(&temp), |_| {
        controller.hold_fence(true);
    })
    .await;
    not_shown(&owed);
    controller.hold_fence(false);
    let owed = told_after_the_route_answers(&controller, a_definite_refusal(&temp), |_| {
        controller.hold_fence(true);
    })
    .await;
    refused_for_a_fence(refusal(&owed).expect("a refusal"));
    controller.hold_fence(false);
}

/// KR-REQ-09.09, 09.12: the four modules' first admissions are told as the end of a write is:
/// whatever answer a module gives, a result is not shown once the connection is withdrawn or a fence
/// is owed, and a refusal that says nothing was done is the check's own; a registration restamped
/// by a withdrawal that did not take this one changes nothing for either. Each leg runs on a daemon
/// of its own, so that every request is a first attempt.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_four_modules_first_admissions_are_told_under_the_authority_they_end_with() {
    use super::a_recorded_answer_another_copy_wrote::{
        a_workflow_install, cancellation, materialisation, setting_quiet_hours,
    };

    type Route = fn(&kr_ipc::testing::TempHost, &Controller) -> MutationRequest;
    let routes: [(&str, Route); 4] = [
        ("automation", |temp, controller| {
            a_workflow_install(temp, controller)
        }),
        ("attention", |temp, _| setting_quiet_hours(temp)),
        ("change set", |temp, _| materialisation(temp)),
        ("project", |temp, _| cancellation(temp)),
    ];
    let mut results = 0;
    for (name, route) in routes {
        let leg = |meanwhile: fn(&Controller, ConnectionId)| async move {
            let (temp, controller, _clock) = daemon().await;
            let mutation = route(&temp, &controller);
            let method = mutation.method.method().expect("a method");
            let controller_for_the_leg = Arc::clone(&controller);
            told_after_the_route_answers(&controller, (method, mutation), move |connection_id| {
                meanwhile(&controller_for_the_leg, connection_id);
            })
            .await
        };
        let control = leg(|_, _| {}).await;
        let withdrawn = leg(|controller, connection_id| controller.deregister(connection_id)).await;
        let fenced = leg(|controller, _| controller.hold_fence(true)).await;
        let restamped = leg(|controller, _| {
            controller
                .admitted_write()
                .values_mut()
                .for_each(|connection| {
                    connection.admitted_revision = kr_protocol::ids::AuthorityRevision::new(
                        connection.admitted_revision.get() + 1,
                    );
                });
        })
        .await;
        // A result, and a word that does not say the action was not done, may be of an effect that
        // ran: the door does not show it once the authority it ends with has gone.
        if refusal(&control).is_none_or(|error| !crate::given::is_definite(error)) {
            results += usize::from(refusal(&control).is_none());
            not_shown(&withdrawn);
            not_shown(&fenced);
            assert_eq!(
                refusal(&restamped).map(|error| error.code),
                refusal(&control).map(|error| error.code),
                "{name}: the answer is told across a restamp: {restamped:?}"
            );
        } else {
            let said = refusal(&control).expect("a refusal").code;
            assert_eq!(
                refusal(&withdrawn).expect("a refusal").code,
                ErrorCode::PermissionDenied,
                "{name}: a refusal that says nothing was done is the authority's: {withdrawn:?}"
            );
            refused_for_a_fence(refusal(&fenced).expect("a refusal"));
            assert_eq!(
                refusal(&restamped).expect("a refusal").code,
                said,
                "{name}: the refusal is told across a restamp: {restamped:?}"
            );
        }
    }
    assert!(
        results >= 2,
        "two of the four answer with a result: {results}"
    );
}

/// What the door tells of `settled` for `connection_id`, admitted under `admitted`.
async fn told_as(
    controller: &Controller,
    connection_id: ConnectionId,
    settled: Settled<ControlFrame>,
) -> ControlFrame {
    let admitted = controller.admitted_revision(connection_id).ok();
    told(
        settled,
        &Standing::new(controller, connection_id, admitted, RequestId::new(1)),
    )
    .await
    .into_frame()
}

/// A result of a write that carries `withdrew`.
fn a_result_carrying(withdrew: Option<super::barrier::HostWithdrawal>) -> Settled<ControlFrame> {
    Settled::withdrawing(
        Given::fresh(super::respond(RequestId::new(1), Ok(ParamsValue::empty()))),
        withdrew,
    )
}

/// A request's own host-wide debt, published and handed to its barrier.
fn a_host_wide_debt(controller: &Controller, what: &str) -> super::barrier::OwnBarrier {
    let debt = controller.owe_debt(what, Reach::Host).expect("written");
    controller.publish_debts(&[(debt, Reach::Host)])
}

/// KR-REQ-09.09, 09.12: the barrier a request's own effect raised withdraws every connection of
/// the host, the request's own included, and the result is still told: the proof of it is the one
/// thing that outlives it. The control: the same result with no proof is not shown, because the
/// connection is gone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_result_is_told_after_the_barrier_the_request_itself_raised_withdrew_its_connection() {
    let (_temp, controller, _clock) = daemon().await;
    let (connection_id, _) = admitted(&controller).await;
    let (_barrier, proof) = controller
        .barrier_proving(a_host_wide_debt(
            &controller,
            "the request's own withdrawal",
        ))
        .await
        .expect("the barrier");
    assert!(
        controller.authorised(connection_id).is_err(),
        "a host-wide barrier withdrew the request's own connection"
    );
    assert!(proof.is_some(), "its own debt, alone, is the proof");
    let told = told_as(&controller, connection_id, a_result_carrying(proof)).await;
    assert!(refusal(&told).is_none(), "the result is told: {told:?}");

    let (connection_id, _) = admitted(&controller).await;
    let (_barrier, _proof) = controller
        .barrier_proving(a_host_wide_debt(
            &controller,
            "the request's own withdrawal",
        ))
        .await
        .expect("the barrier");
    let told = told_as(&controller, connection_id, a_result_carrying(None)).await;
    not_shown(&told);
}

/// KR-REQ-09.09, 09.12: the proof stands for the revision the request's barrier set. A withdrawal
/// that completes after it, before the result is told, moves the revision and the result is not
/// shown; so is a fence that is owed then.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_proof_does_not_outlive_a_later_withdrawal_or_an_owed_fence() {
    let (_temp, controller, _clock) = daemon().await;
    let (connection_id, _) = admitted(&controller).await;
    let (_barrier, proof) = controller
        .barrier_proving(a_host_wide_debt(
            &controller,
            "the request's own withdrawal",
        ))
        .await
        .expect("the barrier");
    controller
        .barrier(a_host_wide_debt(
            &controller,
            "another request's withdrawal",
        ))
        .await
        .expect("a second barrier");
    let told = told_as(&controller, connection_id, a_result_carrying(proof)).await;
    not_shown(&told);

    let (connection_id, _) = admitted(&controller).await;
    let (_barrier, proof) = controller
        .barrier_proving(a_host_wide_debt(
            &controller,
            "the request's own withdrawal",
        ))
        .await
        .expect("the barrier");
    controller.hold_fence(true);
    let told = told_as(&controller, connection_id, a_result_carrying(proof)).await;
    not_shown(&told);
    controller.hold_fence(false);
}

/// KR-REQ-09.09, 09.12: a barrier that also captured another request's host-wide debt is no proof
/// of its own request's withdrawal, so the result is not shown.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_barrier_that_took_another_requests_host_debt_proves_nothing() {
    let (_temp, controller, _clock) = daemon().await;
    let (connection_id, _) = admitted(&controller).await;
    // Another request's debt, published and on its way to a barrier of its own, which this
    // request's barrier captures with its own.
    let others = a_host_wide_debt(&controller, "another request's withdrawal");
    let (_barrier, proof) = controller
        .barrier_proving(a_host_wide_debt(
            &controller,
            "the request's own withdrawal",
        ))
        .await
        .expect("the barrier");
    drop(others);
    assert!(proof.is_none(), "a debt that is not its own was captured");
    let told = told_as(&controller, connection_id, a_result_carrying(proof)).await;
    not_shown(&told);
}

/// KR-REQ-09.09, 09.12: a write that raised no barrier of its own is not shown its result when
/// another request's withdrawal removes its connection, whatever that write is.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_write_with_no_barrier_of_its_own_is_not_shown_its_result_after_anothers_withdrawal() {
    let (_temp, controller, _clock) = daemon().await;
    let (connection_id, _) = admitted(&controller).await;
    controller
        .barrier(a_host_wide_debt(
            &controller,
            "another request's withdrawal",
        ))
        .await
        .expect("the barrier");
    let told = told_as(&controller, connection_id, a_result_carrying(None)).await;
    not_shown(&told);
}

/// KR-REQ-09.09, 09.12: what a write's own effect made is told while the registration stands, and
/// what derives from older records (a copy, a report of earlier exports, a list in force) only
/// under the strict check, which asks the exact revision the connection was admitted under. The
/// same registration restamped by a revocation that did not withdraw it tells the first and not
/// the second.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_copy_is_told_only_under_the_revision_it_was_admitted_under() {
    let (_temp, controller, _clock) = daemon().await;
    let (connection_id, _) = admitted(&controller).await;
    let answer = || super::respond(RequestId::new(1), Ok(ParamsValue::empty()));
    let admitted_under = controller.admitted_revision(connection_id).ok();
    let told = |settled| async {
        told(
            settled,
            &Standing::new(
                &controller,
                connection_id,
                admitted_under,
                RequestId::new(1),
            ),
        )
        .await
        .into_frame()
    };

    let copy = told(Settled::of(Given::copied(answer()))).await;
    assert!(refusal(&copy).is_none(), "with nothing replaced: {copy:?}");
    controller
        .admitted_write()
        .values_mut()
        .for_each(|connection| {
            connection.admitted_revision =
                kr_protocol::ids::AuthorityRevision::new(connection.admitted_revision.get() + 1);
        });
    let copy = told(Settled::of(Given::copied(answer()))).await;
    not_shown(&copy);
    let fresh = told(Settled::of(Given::fresh(answer()))).await;
    assert!(
        refusal(&fresh).is_none(),
        "a result of this request's own effect needs only the registration: {fresh:?}"
    );
}

/// KR-REQ-09.09, 09.12: a barrier that advanced the revision between the publication of the
/// request's own debt and its own barrier, the debt pass's for another request's debt, withdrew
/// the connection before the request's own barrier did, so the proof is refused and the result
/// is not shown.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_barrier_of_the_debt_pass_before_the_requests_own_proves_nothing() {
    let (_temp, controller, _clock) = daemon().await;
    let (connection_id, _) = admitted(&controller).await;
    let own = a_host_wide_debt(&controller, "the request's own withdrawal");
    // Another request's debt, left to the debt pass, which raises its barrier first.
    let other = controller
        .owe_debt("another request's withdrawal", Reach::Host)
        .expect("written");
    drop(controller.publish_debts(&[(other, Reach::Host)]));
    controller
        .raise_owed_barrier()
        .await
        .expect("the pass's barrier");
    let (_barrier, proof) = controller.barrier_proving(own).await.expect("the barrier");
    assert!(
        proof.is_none(),
        "a barrier advanced the revision after the debt was published"
    );
    let told = told_as(&controller, connection_id, a_result_carrying(proof)).await;
    not_shown(&told);
}

/// KR-REQ-09.09, 09.12: a fence owed by a restriction that published its debt while the proof was
/// waiting for the registry is seen, and the result is not shown: the revision and the fence are
/// read under the registry's lock.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_debt_published_while_the_proof_waits_for_the_registry_stops_the_result() {
    let (_temp, controller, _clock) = daemon().await;
    let (connection_id, _) = admitted(&controller).await;
    let (_barrier, proof) = controller
        .barrier_proving(a_host_wide_debt(
            &controller,
            "the request's own withdrawal",
        ))
        .await
        .expect("the barrier");
    assert!(proof.is_some(), "its own debt, alone, is the proof");
    let registry = controller.registry.lock().await;
    let telling = tokio::spawn({
        let controller = Arc::clone(&controller);
        async move { told_as(&controller, connection_id, a_result_carrying(proof)).await }
    });
    // Another request's restriction publishes its debt while the registry is held, as one does.
    controller.hold_fence(true);
    drop(registry);
    not_shown(&telling.await.expect("the door tells it"));
    controller.hold_fence(false);
}
