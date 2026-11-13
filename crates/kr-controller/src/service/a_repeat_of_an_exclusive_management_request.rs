//! What the request for the owner's confirmation of a change of exclusive management says of a
//! repeat.
//!
//! The challenge is recorded with the action that asked for it, and a repeat of the action is given
//! the challenge the first was given, before the change is described again: the change may be made
//! by then, and the answer the repeat is owed is the challenge it was given. That answer is read from
//! the record of an earlier submission, which the door tells a device by, so the service says so. The
//! submission that issued the challenge does not.

use kr_protocol::confirmation::{ConfirmationSubject, OwnerConfirmationRequestParams};
use kr_protocol::ids::ActionId;
use kr_protocol::method::Method;

use super::an_owner_establishes_the_clock::{Door, distrusting};
use crate::service::net::owner::Caller;

/// KR-REQ-09.09: the repeat of a request to end exclusive management is given the challenge the
/// first was given, as a copy of its record; the first is not a copy.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_repeated_request_to_end_exclusive_management_is_answered_as_a_copy_of_its_record() {
    let (temp, controller, ..) = distrusting().await;
    controller
        .update_policy(|policy| policy.set_exclusively_managed(true))
        .expect("the host is made exclusively organisation-managed");
    let door = Door::open(&temp, &controller).await;
    let action = ActionId::new(kr_ipc::new_uuid());
    let request = door.mutation(
        Method::OwnerConfirmationRequest,
        action,
        30_000,
        &OwnerConfirmationRequestParams {
            subject: ConfirmationSubject::SetExclusiveManagement { exclusive: false },
        },
    );
    let revision = controller.admitted_revision(door.connection_id()).ok();
    let deadline = Some(door.accepted().deadline);
    let mut asked = Vec::new();
    for _ in 0..2 {
        let given = controller
            .pairing_write(
                Caller::local(door.actor_id().clone()),
                Method::OwnerConfirmationRequest,
                &request,
                controller.pairing_admission(door.connection_id(), revision, deadline),
                controller.pairing_standing(door.connection_id(), revision),
                controller.pairing_guard(door.connection_id(), revision, deadline),
                controller.pairing_life(deadline),
            )
            .await;
        asked.push(given);
    }
    let [first, again] = <[_; 2]>::try_from(asked).expect("two answers");
    assert!(
        !first.is_copied(),
        "the submission that issued the challenge is not a copy"
    );
    let first = first
        .into_answer_for_test()
        .expect("the first request is answered");
    assert!(
        again.is_copied(),
        "the repeat is answered from the record of the first"
    );
    assert_eq!(
        again
            .into_answer_for_test()
            .expect("the repeat is answered"),
        first,
        "with the challenge the first was given"
    );

    // The identifier reused for another request is this host's word about the identifier, and no
    // copy of the record.
    let other = door.mutation(
        Method::OwnerConfirmationRequest,
        action,
        30_000,
        &OwnerConfirmationRequestParams {
            subject: ConfirmationSubject::SetExclusiveManagement { exclusive: true },
        },
    );
    let reused = controller
        .pairing_write(
            Caller::local(door.actor_id().clone()),
            Method::OwnerConfirmationRequest,
            &other,
            controller.pairing_admission(door.connection_id(), revision, deadline),
            controller.pairing_standing(door.connection_id(), revision),
            controller.pairing_guard(door.connection_id(), revision, deadline),
            controller.pairing_life(deadline),
        )
        .await;
    assert!(
        !reused.is_copied(),
        "a reused identifier is not answered from the record of the first"
    );
    let refused = reused
        .into_answer_for_test()
        .expect_err("the reuse is refused");
    assert_eq!(
        refused.to_protocol_error().code,
        kr_protocol::error::ErrorCode::IdConflict
    );
}
