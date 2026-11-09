use std::sync::Arc;

use kr_protocol::error::ErrorCode;

use super::a_close_a_worker_never_answers::{self as world, Recorded};

/// KR-REQ-23.24: a worker that cannot say what became of a close answers `OUTCOME_UNKNOWN`, and the
/// daemon tells its caller exactly that. Reported as a refusal of the request, it would hide the
/// one thing the caller needs: that the close may have happened, so the action has to be named and
/// read back and not asked again under another identifier. The answer is a whole exchange, so the
/// worker's link goes back and its lease renews.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_worker_that_cannot_say_what_became_of_a_close_is_reported_as_unknown() {
    let recorded: Recorded = Arc::default();
    let served = world::fake_world({
        let recorded = Arc::clone(&recorded);
        move |listener, identity, endpoint_text| {
            world::serve_fake_worker(
                listener,
                identity,
                endpoint_text,
                Some(recorded),
                ErrorCode::OutcomeUnknown,
            )
        }
    })
    .await;
    world::acknowledged(&served.controller, served.session_id);
    let carried = world::admission(&served.controller, served.accepted).await;

    let error = served
        .controller
        .session_close(
            &world::close_request(served.environment_id, served.session_id),
            &served.actor,
            Some(served.accepted),
            carried,
        )
        .await
        .expect_err("a worker that cannot say what became of the close gives no closure");
    assert_eq!(
        error.code(),
        ErrorCode::OutcomeUnknown,
        "the worker's own answer reaches the caller: {error}"
    );
    assert!(
        !served.controller.leases.is_fenced(served.session_id),
        "a complete answer gave nothing up"
    );
    served.serving.abort();
}
