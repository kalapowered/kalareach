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

/// KR-REQ-09.09: two copies of one request meet at the lock every challenge is issued under, and
/// the second is given the challenge the first recorded. The second copy has passed every lookup of
/// the action before the first is recorded, so it finds the record only after it holds that lock,
/// and it is answered from the guard it holds: both copies are answered with one challenge, the
/// second as a copy. A watchdog ends the process where the second waits for the lock it holds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_copy_that_finds_the_challenge_the_first_recorded_under_the_lock_it_holds_is_answered() {
    const BOUND: std::time::Duration = std::time::Duration::from_secs(20);

    let finished = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    {
        let finished = std::sync::Arc::clone(&finished);
        std::thread::spawn(move || {
            std::thread::sleep(BOUND * 3);
            if !finished.load(std::sync::atomic::Ordering::SeqCst) {
                eprintln!(
                    "a copy of a request that finds the first one's record waits for the lock it holds"
                );
                std::process::exit(1);
            }
        });
    }
    let (temp, controller, ..) = distrusting().await;
    controller
        .update_policy(|policy| policy.set_exclusively_managed(true))
        .expect("the host is made exclusively organisation-managed");
    let door = Door::open(&temp, &controller).await;
    let request = door.mutation(
        Method::OwnerConfirmationRequest,
        ActionId::new(kr_ipc::new_uuid()),
        30_000,
        &OwnerConfirmationRequestParams {
            subject: ConfirmationSubject::SetExclusiveManagement { exclusive: false },
        },
    );
    let revision = controller.admitted_revision(door.connection_id()).ok();
    let deadline = Some(door.accepted().deadline);
    let copy = || {
        let controller = std::sync::Arc::clone(&controller);
        let request = request.clone();
        let (actor, connection_id) = (door.actor_id().clone(), door.connection_id());
        async move {
            controller
                .pairing_write(
                    Caller::local(actor),
                    Method::OwnerConfirmationRequest,
                    &request,
                    controller.pairing_admission(connection_id, revision, deadline),
                    controller.pairing_standing(connection_id, revision),
                    controller.pairing_guard(connection_id, revision, deadline),
                    controller.pairing_life(deadline),
                )
                .await
        }
    };

    // The second copy stops after its lookups found nothing, and before it takes the lock.
    let (at_the_lock, let_the_second_go) =
        controller.pause_before_the_challenges_of_a_confirmation();
    let second = tokio::spawn(copy());
    tokio::task::spawn_blocking(move || at_the_lock.recv_timeout(BOUND))
        .await
        .expect("the wait for the second copy ends")
        .expect("the second copy reaches the lock");

    // The first copy is recorded while the second waits.
    let first = tokio::time::timeout(BOUND, copy())
        .await
        .expect("the first copy is answered while the second waits");
    assert!(!first.is_copied(), "the first copy issued the challenge");
    let first = first
        .into_answer_for_test()
        .expect("the first copy is answered");
    let_the_second_go.send(()).expect("the second copy goes on");

    let second = tokio::time::timeout(BOUND, second)
        .await
        .expect("the second copy is answered once the first is recorded")
        .expect("the second copy ends");
    assert!(
        second.is_copied(),
        "the second copy is answered from the record of the first"
    );
    assert_eq!(
        second
            .into_answer_for_test()
            .expect("the second copy is answered"),
        first,
        "with the challenge the first copy was given"
    );
    finished.store(true, std::sync::atomic::Ordering::SeqCst);
}
