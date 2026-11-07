//! What a repeat of an authority change is told when the record of its first attempt cannot be
//! read, at the two lookups that stand before an authority change is admitted.
//!
//! The registry keeps a claim for each authority change the host performed, and a repeat is answered
//! from it. A registry that cannot read the claim is not one that holds none: the change may have
//! been made, so the repeat is told that what became of it is not known, and not a transient word,
//! which says that nothing took effect and has the change sent again as though nothing had.

use kr_protocol::envelope::{ActionTarget, ControlFrame, MutationRequest, Outcome, ParamsValue};
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{ActionId, ActionWindowId, ActorId, GrantId, RequestId};
use kr_protocol::method::{Method, MethodVersion};
use kr_protocol::scalars::{DurationMs, Nullable};
use kr_protocol::sharing::GrantRevokeParams;

use super::a_transfer_left_unanswered::daemon;

/// A `grant.revoke` under a fresh action.
fn revoke_request(temp: &kr_ipc::testing::TempHost) -> MutationRequest {
    MutationRequest {
        request_id: RequestId::new(1),
        method: Method::GrantRevoke.into(),
        method_version: MethodVersion::V1,
        action_id: ActionId::new(kr_ipc::new_uuid()),
        grant_id: Nullable::null(),
        target: ActionTarget::environment(temp.environment_id()),
        expected: ParamsValue::empty(),
        action_window_id: ActionWindowId::new("local:test").expect("a window"),
        requested_ttl_ms: DurationMs::new(30_000),
        params: ParamsValue::from_typed(&GrantRevokeParams {
            grant_id: GrantId::new(kr_ipc::new_uuid()),
        })
        .expect("encodes"),
    }
}

/// The error a frame carries.
fn told(frame: Option<ControlFrame>) -> kr_protocol::error::ProtocolError {
    let Some(ControlFrame::Response(response)) = frame else {
        panic!("a repeat the registry cannot be asked about is answered: {frame:?}");
    };
    let Outcome::Error(error) = response.outcome else {
        panic!("the repeat is refused: {response:?}");
    };
    error
}

/// KR-REQ-09.09: a repeat asked of a registry that cannot read the claims is told the outcome is
/// unknown, by the lookup that waits for the freshness an authority change needs and by the one a
/// caller that cannot wait stands behind.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_repeat_of_an_authority_change_the_registry_cannot_be_asked_about_is_told_the_outcome_is_unknown()
 {
    let (temp, controller) = daemon().await;
    let actor_id = ActorId::new("local:test").expect("a principal");
    let mutation = revoke_request(&temp);

    let registry = rusqlite::Connection::open(temp.environment().registry_database())
        .expect("the registry opens beside the daemon's own handle");
    registry
        .busy_timeout(std::time::Duration::from_secs(10))
        .expect("waits for the daemon's own writes");
    registry
        .execute_batch("ALTER TABLE authority_receipts RENAME TO authority_receipts_aside;")
        .expect("the claims cannot be read");

    let waiting = told(
        controller
            .retained_authority_answer(&actor_id, &mutation)
            .await,
    );
    let not_waiting = told(controller.retained_authority_change(&actor_id, &mutation));
    registry
        .execute_batch("ALTER TABLE authority_receipts_aside RENAME TO authority_receipts;")
        .expect("the claims can be read again");
    assert_eq!(waiting.code, ErrorCode::OutcomeUnknown, "{waiting:?}");
    assert_eq!(
        not_waiting.code,
        ErrorCode::OutcomeUnknown,
        "{not_waiting:?}"
    );
}
