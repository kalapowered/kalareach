//! What the establishment of the host's clock asks again where it commits.
//!
//! An establishment spends the owner's confirmation, ends the host's distrust of its clock and a
//! lost clock continuity, and records its action, all in one transaction that commits while the
//! connection's registration is held standing. The owner's confirmation, the registration, the
//! fence this host may owe and the deadline the request was admitted under can each change while
//! it waits for the clock, so each of these tests stops the effect there with a pause of this
//! host's own, changes one thing, and lets it go on.

use std::sync::Arc;
use std::time::Duration;

use kr_protocol::confirmation::{HostClockEstablishParams, HostClockEstablishResult};
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::ActionId;
use kr_protocol::method::Method;

use super::an_owner_establishes_the_clock::{
    Door, code, confirmed_at, distrusting, proven, registry,
};
use crate::service::net::owner::Caller;

/// What lapses while the effect waits.
#[derive(Clone, Copy, Debug)]
enum Lapse {
    /// The host gains an owner, which ends the terminal's authority.
    AnOwnerAppears,
    /// The deadline the request was admitted under passes.
    TheDeadlinePasses,
    /// The host owes a fence it could not raise.
    AFenceIsOwed,
    /// The connection's registration is withdrawn.
    TheRegistrationIsWithdrawn,
}

/// Stops the effect after it has chosen the confirmation it spends, lets `lapse` happen, and lets
/// it go on: it is refused, and nothing it would have written is.
async fn an_establishment_that_lapses_while_it_waits(lapse: Lapse) {
    let (temp, controller, continuous, ..) = distrusting().await;
    let door = Door::open(&temp, &controller).await;
    let challenge = door.challenge().await;
    door.answer(&challenge.request).await.expect("answered");
    let (arrived, go) = controller
        .owner_authority()
        .pauses
        .before_the_transaction
        .arm();
    let attempt = tokio::spawn({
        let door = door.clone();
        async move { door.establish().await }
    });
    arrived.await.expect("the effect chose its confirmation");

    match lapse {
        Lapse::AnOwnerAppears => {
            registry(&temp)
                .execute(
                    "INSERT INTO host_owner (id, how, established_at_ms) VALUES (0, 'migrated', 1)",
                    [],
                )
                .expect("the host gains an owner");
        }
        Lapse::TheDeadlinePasses => continuous.advance(Duration::from_secs(61)),
        Lapse::AFenceIsOwed => controller.hold_fence(true),
        Lapse::TheRegistrationIsWithdrawn => {
            controller.admitted_table().remove(&door.connection_id());
        }
    }
    go.send(()).expect("the effect goes on");
    let refused = attempt.await.expect("the effect ends");

    let expected = match lapse {
        Lapse::AnOwnerAppears => ErrorCode::OwnerConfirmationRequired,
        _ => ErrorCode::PermissionDenied,
    };
    assert_eq!(code(refused), expected, "{lapse:?}");
    assert!(
        !proven(&controller),
        "{lapse:?}: the host still distrusts its clock"
    );
    assert_eq!(confirmed_at(&temp), None, "{lapse:?}: nothing was written");

    // The control: what lapsed is restored and the same confirmation, which the refusal left
    // answered, establishes the clock. A host that gained an owner stays one.
    match lapse {
        Lapse::AnOwnerAppears => return,
        Lapse::AFenceIsOwed => controller.hold_fence(false),
        Lapse::TheDeadlinePasses | Lapse::TheRegistrationIsWithdrawn => {}
    }
    let door = Door::open(&temp, &controller).await;
    door.establish().await.unwrap_or_else(|error| {
        panic!("{lapse:?}: the same confirmation establishes it: {error:?}")
    });
    assert!(proven(&controller), "{lapse:?}");
}

/// KR-REQ-09.19, KR-REQ-10.53: authority that lapses while an establishment waits for the clock is
/// asked again where it commits. A host that gains an owner no longer takes the terminal's
/// confirmation, and a deadline that passed, a fence the host owes and a registration that was
/// withdrawn each refuse the effect. Each leaves the clock distrusted and the owner's confirmation
/// answered.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn authority_that_lapses_while_the_establishment_waits_stops_it() {
    for lapse in [
        Lapse::AnOwnerAppears,
        Lapse::TheDeadlinePasses,
        Lapse::AFenceIsOwed,
        Lapse::TheRegistrationIsWithdrawn,
    ] {
        an_establishment_that_lapses_while_it_waits(lapse).await;
    }
}

/// KR-REQ-09.12, KR-REQ-09.19: the registration an establishment was admitted under is held
/// standing from the check to the commit, so a withdrawal is ordered wholly before the effect or
/// wholly after it. The effect is stopped inside its commit, after every row is written and checked
/// and before the commit: the table of registrations is held there, and is free once it commits.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_registration_is_held_through_the_commit() {
    let (temp, controller, ..) = distrusting().await;
    let door = Door::open(&temp, &controller).await;
    let challenge = door.challenge().await;
    door.answer(&challenge.request).await.expect("answered");
    let (arrived, go) = controller.owner_authority().pauses.inside_the_commit.arm();
    let attempt = tokio::spawn({
        let door = door.clone();
        async move { door.establish().await }
    });
    arrived.await.expect("the effect reached its commit");
    assert!(
        controller.admitted.try_lock().is_err(),
        "the registrations are held while the effect commits"
    );
    go.send(()).expect("the effect commits");
    attempt.await.expect("the effect ends").expect("it commits");
    assert!(
        controller.admitted.try_lock().is_ok(),
        "and are free once it has"
    );
    assert!(proven(&controller));
}

/// KR-REQ-09.19: two copies of one action meet at the record. While the first is committing, an
/// exact copy and a request that reuses the identifier wait for the challenges; when the first has
/// committed, the copy is given its result without spending the second answered confirmation, and
/// the reuse is refused without spending it either.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_copies_of_one_action_establish_the_clock_once() {
    let (temp, controller, ..) = distrusting().await;
    let door = Door::open(&temp, &controller).await;
    let first = door.challenge().await;
    door.answer(&first.request).await.expect("answered");
    let second = door.challenge().await;
    door.answer(&second.request).await.expect("answered");

    let owner = Arc::clone(controller.owner_authority());
    let caller = Caller::local(door.actor_id().clone());
    let revision = controller.admitted_revision(door.connection_id()).ok();
    let guard = controller.pairing_guard(
        door.connection_id(),
        revision,
        Some(door.accepted().deadline),
    );
    let action_id = ActionId::new(kr_ipc::new_uuid());
    let digest = |ttl_ms: u64| {
        kr_protocol::digest::mutation_digest(
            &door.mutation(
                Method::HostClockEstablish,
                action_id,
                ttl_ms,
                &HostClockEstablishParams {},
            ),
            door.actor_id(),
        )
        .expect("a digest")
    };
    let boot = controller.boot_epoch;
    let establish = |ttl_ms: u64| {
        let (owner, caller, guard) = (Arc::clone(&owner), caller.clone(), Arc::clone(&guard));
        let action = (action_id, digest(ttl_ms));
        tokio::task::spawn_blocking(move || {
            owner.establish_clock(&caller, action, boot, guard.as_ref())
        })
    };

    let (arrived, go) = owner.pauses.inside_the_commit.arm();
    let committing = establish(30_000);
    arrived.await.expect("the first copy reached its commit");
    let copy = establish(30_000);
    let reuse = establish(30_001);
    go.send(()).expect("the first copy commits");

    let result: HostClockEstablishResult = committing
        .await
        .expect("the first copy ends")
        .expect("and establishes the clock");
    assert_eq!(result.confirmation_id, first.request.confirmation_id);
    assert_eq!(
        copy.await.expect("the copy ends").expect("and is answered"),
        result,
        "an exact copy is given the first copy's result"
    );
    assert_eq!(
        code(
            reuse
                .await
                .expect("the reuse ends")
                .map_err(|error| error.to_protocol_error())
        ),
        ErrorCode::IdConflict
    );
    let spent: i64 = registry(&temp)
        .query_row(
            "SELECT COUNT(*) FROM owner_confirmations WHERE consumed_at_ms IS NOT NULL",
            [],
            |row| row.get(0),
        )
        .expect("counts the spent confirmations");
    assert_eq!(
        spent, 1,
        "one confirmation was spent, and the second is still answered"
    );
    assert!(proven(&controller));
}
