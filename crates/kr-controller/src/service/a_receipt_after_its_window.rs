//! What a receipt is given back under once the window that admitted its action has passed.
//!
//! Section 9 keeps a receipt readable under current authority after its window has expired, and
//! admits no new action under an expired window. A copy of an action another copy recorded is not a
//! new action, so a copy whose window passed while it waited (for the registry, for a store's lock,
//! for a thread) is given the record, under the authority half of the admission; only an action that
//! has no record is refused for its window, and a mutation that carries no freshness at all is
//! refused where it would be performed.
//!
//! Each case lets the first copy record under a live window, passes the window, and asks the service
//! for the late copy: the record, as a copy. The control is an action with no record under the same
//! passed window, which is refused for it.

use std::time::Duration;

use kr_protocol::envelope::{MutationRequest, ParamsValue};
use kr_protocol::error::ErrorCode;
use kr_protocol::method::Method;
use kr_protocol::scalars::Nullable;
use kr_transport::clock::ManualClock;

use super::a_recorded_answer_another_copy_wrote::{
    attention_answer, cancellation, changeset_answer, materialisation, project_answer_under,
    setting_quiet_hours,
};
use super::the_fence_at_every_effect::{accepted, admitted, carried, daemon, mutation_of, refusal};
use crate::authority::AdmittedMutation;

/// Passes the window of every admission the cases carry, which standing is a minute.
fn the_window_passes(clock: &ManualClock) {
    clock.advance(Duration::from_secs(61));
}

/// What an action with no record is refused with when its window has passed, or when it carries no
/// freshness at all: a refusal of authority on the wire, whose words are about the deadline.
fn refused_for_its_window(error: &kr_protocol::error::ProtocolError) {
    assert_eq!(error.code, ErrorCode::PermissionDenied, "{error:?}");
    assert!(
        error.message.contains("deadline") || error.message.contains("freshness"),
        "the refusal is the window's, and not a fence or a registration's: {error:?}"
    );
}

/// The same admission, as a retry carries it once its own window is gone: no deadline at all.
fn without_freshness(admission: AdmittedMutation) -> AdmittedMutation {
    AdmittedMutation {
        deadline: None,
        ..admission
    }
}

/// KR-REQ-09.09, the project service: an action another copy recorded is given to a copy whose
/// window has passed, as a copy, and so is it to a copy that carries no freshness at all. An action
/// with no record is refused for its window or for carrying none.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_project_action_another_copy_recorded_is_given_back_after_its_window_has_passed() {
    let (temp, controller, clock) = daemon().await;
    let (connection_id, actor_id) = admitted(&controller).await;
    let admission = carried(&controller, connection_id);
    let mutation = cancellation(&temp);
    let first = project_answer_under(&controller, &actor_id, &mutation, admission).await;
    assert!(!first.is_copied(), "the first copy answers for itself");
    let first = first
        .into_answer_for_test()
        .expect_err("the service refuses it");

    the_window_passes(&clock);
    for late in [admission, without_freshness(admission)] {
        let given = project_answer_under(&controller, &actor_id, &mutation, late).await;
        assert!(given.is_copied(), "the late copy is given the record");
        assert_eq!(
            given.into_answer_for_test().expect_err("the kept refusal"),
            first,
            "it is given what the first copy was told"
        );
        let new = cancellation(&temp);
        let refused = project_answer_under(&controller, &actor_id, &new, late)
            .await
            .into_answer_for_test()
            .expect_err("an action with no record is refused for its window");
        refused_for_its_window(&refused);
    }
}

/// KR-REQ-09.09, the workflow journal: as for the project service.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_automation_action_another_copy_recorded_is_given_back_after_its_window_has_passed() {
    let (temp, controller, clock) = daemon().await;
    let (connection_id, actor_id) = admitted(&controller).await;
    let admission = carried(&controller, connection_id);
    let enabling = || {
        mutation_of(
            &temp,
            Method::WorkflowEnable,
            ParamsValue::from_typed(&kr_protocol::automation::WorkflowEnableParams {
                workflow_id: kr_protocol::ids::WorkflowId::new(kr_ipc::new_uuid()),
                revision: kr_protocol::scalars::U64::new(1),
            })
            .expect("encodes"),
        )
    };
    let mutation = enabling();
    let ask = async |request: &MutationRequest, admission: AdmittedMutation| {
        controller
            .automation_mutation(&actor_id, request, Method::WorkflowEnable, admission, None)
            .await
    };
    let first = ask(&mutation, admission).await;
    assert!(!first.is_copied(), "the first copy answers for itself");
    let first = first
        .into_answer_for_test()
        .expect_err("a workflow nobody installed is refused");

    the_window_passes(&clock);
    for late in [admission, without_freshness(admission)] {
        let given = ask(&mutation, late).await;
        assert!(given.is_copied(), "the late copy is given the record");
        assert_eq!(
            given.into_answer_for_test().expect_err("the kept refusal"),
            first,
            "it is given what the first copy was told"
        );
        let refused = ask(&enabling(), late)
            .await
            .into_answer_for_test()
            .expect_err("an action with no record is refused for its window");
        refused_for_its_window(&refused);
    }
}

/// KR-REQ-09.09, the attention store: as for the project service.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_attention_action_another_copy_recorded_is_given_back_after_its_window_has_passed() {
    let (temp, controller, clock) = daemon().await;
    let (connection_id, actor_id) = admitted(&controller).await;
    let admission = carried(&controller, connection_id);
    let mutation = setting_quiet_hours(&temp);
    let first = attention_answer(&controller, &actor_id, &mutation, admission).await;
    assert!(!first.is_copied(), "the first copy answers for itself");
    let first = first.into_answer_for_test().expect("the window is set");

    the_window_passes(&clock);
    for late in [admission, without_freshness(admission)] {
        let given = attention_answer(&controller, &actor_id, &mutation, late).await;
        assert!(given.is_copied(), "the late copy is given the record");
        assert_eq!(
            given.into_answer_for_test().expect("the record's answer"),
            first,
            "it is given what the first copy was told"
        );
        let refused = attention_answer(&controller, &actor_id, &setting_quiet_hours(&temp), late)
            .await
            .into_answer_for_test()
            .expect_err("an action with no record is refused for its window");
        refused_for_its_window(&refused);
    }
}

/// KR-REQ-09.09, the catalogue: a receipt another copy kept is given to a copy whose window has
/// passed, as a copy. An action with no receipt is refused for its window.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_catalogue_receipt_another_copy_kept_is_given_back_after_its_window_has_passed() {
    let (temp, controller, clock) = daemon().await;
    let (connection_id, actor_id) = admitted(&controller).await;
    let admission = carried(&controller, connection_id);
    let pinning = || {
        mutation_of(
            &temp,
            Method::CataloguePin,
            ParamsValue::from_typed(&kr_protocol::catalogue::CataloguePinParams {
                environment_id: temp.environment_id(),
                catalogue_id: "nobody-enrolled-this".to_owned(),
                generation: Nullable(Some(kr_protocol::ids::RepositoryGeneration::new(1))),
            })
            .expect("encodes"),
        )
    };
    let ask = async |request: &MutationRequest| {
        let admission: std::sync::Arc<dyn crate::catalogue::Admission> = std::sync::Arc::new(
            crate::catalogue::DaemonAdmission::new(std::sync::Arc::clone(&controller), admission),
        );
        controller
            .catalogue()
            .write(
                &actor_id,
                request,
                Method::CataloguePin,
                None,
                admission,
                None,
            )
            .await
    };
    let mutation = pinning();
    let first = ask(&mutation).await;
    assert!(!first.is_copied(), "the first copy answers for itself");
    let first = first
        .into_answer_for_test()
        .expect_err("a catalogue nobody enrolled is refused");

    the_window_passes(&clock);
    let given = ask(&mutation).await;
    assert!(given.is_copied(), "the late copy is given the receipt");
    assert_eq!(
        given.into_answer_for_test().expect_err("the kept refusal"),
        first,
        "it is given what the first copy was told"
    );
    let refused = ask(&pinning())
        .await
        .into_answer_for_test()
        .expect_err("an action with no receipt is refused for its window");
    refused_for_its_window(&refused);
}

/// KR-REQ-09.09, the disclosed checks: the answer another copy was given goes back to a copy whose
/// window has passed, and to one that carries no freshness at all. A first start is refused for
/// its window or for carrying none.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_capability_check_another_copy_answered_is_given_back_after_its_window_has_passed() {
    use super::a_recorded_answer_another_copy_wrote::capability_request;

    let (temp, controller, clock) = daemon().await;
    let (connection_id, actor_id) = admitted(&controller).await;
    let admission = carried(&controller, connection_id);
    let mutation = capability_request(&temp, None, None);
    let first = controller
        .start_capability_checks(&actor_id, &mutation, admission)
        .await
        .into_answer_for_test()
        .expect("the first copy is answered");

    the_window_passes(&clock);
    for late in [admission, without_freshness(admission)] {
        let given = controller
            .start_capability_checks(&actor_id, &mutation, late)
            .await
            .into_answer_for_test()
            .expect("the late copy is given the record");
        assert_eq!(given, first, "it is given what the first copy was told");
        let refused = controller
            .start_capability_checks(&actor_id, &capability_request(&temp, None, None), late)
            .await
            .into_answer_for_test()
            .expect_err("a first start is refused for its window");
        refused_for_its_window(&refused.to_protocol_error());
    }
}

/// `mutation` as the local door performs it once its own look for a record has found none, under
/// the deadline `accepted`.
async fn at_the_local_door(
    controller: &std::sync::Arc<super::Controller>,
    connection_id: kr_protocol::ids::ConnectionId,
    actor_id: &kr_protocol::ids::ActorId,
    mutation: &MutationRequest,
    method: Method,
    accepted: kr_transport::window::AcceptedDeadline,
) -> kr_protocol::envelope::ControlFrame {
    controller
        .write_method(
            actor_id,
            mutation,
            method,
            connection_id,
            None,
            Some(accepted),
            controller.admitted_revision(connection_id).ok(),
        )
        .await
        .into_answer_for_test()
}

/// KR-REQ-09.09, the local door's attention route: a copy whose window passed after the door's own
/// look for a record found none is given the record another copy wrote, and not refused for its
/// window before the store reads it. An action with no record is still refused for its window.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_copy_at_the_local_attention_route_is_given_the_record_after_its_window_has_passed() {
    use kr_protocol::envelope::{ControlFrame, Outcome, Response};

    let (temp, controller, clock) = daemon().await;
    let (connection_id, actor_id) = admitted(&controller).await;
    let admission = carried(&controller, connection_id);
    let accepted = accepted(&controller);
    let mutation = setting_quiet_hours(&temp);
    let first = attention_answer(&controller, &actor_id, &mutation, admission)
        .await
        .into_answer_for_test()
        .expect("the window is set");

    the_window_passes(&clock);
    let late = at_the_local_door(
        &controller,
        connection_id,
        &actor_id,
        &mutation,
        Method::AttentionQuietHours,
        accepted,
    )
    .await;
    let ControlFrame::Response(Response {
        outcome: Outcome::Ok(given),
        ..
    }) = late
    else {
        panic!("the late copy is given the record: {late:?}");
    };
    assert_eq!(given, first, "it is given what the first copy was told");

    let refused = at_the_local_door(
        &controller,
        connection_id,
        &actor_id,
        &setting_quiet_hours(&temp),
        Method::AttentionQuietHours,
        accepted,
    )
    .await;
    refused_for_its_window(
        refusal(&refused).expect("an action with no record is refused for its window"),
    );
}

/// KR-REQ-09.09, the local door's change-set route: a copy whose window passed after the door's own
/// look for a record found none is given the record another copy wrote, and not refused for its
/// window before the service reads it. An action with no record is still refused for its window.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_copy_at_the_local_change_set_route_is_given_the_record_after_its_window_has_passed() {
    let (temp, controller, clock) = daemon().await;
    let (connection_id, actor_id) = admitted(&controller).await;
    let admission = carried(&controller, connection_id);
    let accepted = accepted(&controller);
    let mutation = materialisation(&temp);
    let first = changeset_answer(&controller, &actor_id, &mutation, admission)
        .await
        .into_answer_for_test()
        .expect_err("a version nobody captured is refused, and the refusal is kept");

    the_window_passes(&clock);
    let late = at_the_local_door(
        &controller,
        connection_id,
        &actor_id,
        &mutation,
        Method::ChangesetMaterialize,
        accepted,
    )
    .await;
    assert_eq!(
        refusal(&late),
        Some(&first),
        "the late copy is given what the first copy was told: {late:?}"
    );

    let refused = at_the_local_door(
        &controller,
        connection_id,
        &actor_id,
        &materialisation(&temp),
        Method::ChangesetMaterialize,
        accepted,
    )
    .await;
    refused_for_its_window(
        refusal(&refused).expect("an action with no record is refused for its window"),
    );
}
