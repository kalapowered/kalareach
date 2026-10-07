//! What the establishment of the host's clock asks again where it commits.
//!
//! An establishment spends the owner's confirmation, ends the host's distrust of its clock and a
//! lost clock continuity, and records its action, all in one transaction that commits while the
//! connection's registration is held standing. The owner's confirmation, the registration, the
//! fence this host may owe and the deadline the request was admitted under can each change while
//! it waits for the clock or for the directory's connection, so each of these tests stops the
//! effect at one of those waits with a pause of this host's own, changes one thing, and lets it go
//! on.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use kr_protocol::confirmation::{HostClockEstablishParams, HostClockEstablishResult};
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::ActionId;
use kr_protocol::method::Method;

use super::an_owner_establishes_the_clock::{
    Door, code, confirmed_at, distrusting, paired, proven, registry,
};
use crate::service::net::owner::Caller;

/// Where the effect is stopped.
#[derive(Clone, Copy, Debug)]
enum At {
    /// After it chose the confirmation it spends, before it takes the clock and the directory.
    BeforeTheClock,
    /// After it holds the directory's connection and its transaction, before it asks its
    /// registration again.
    AfterTheConnection,
}

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

/// Stops the effect at `at`, lets `lapse` happen, and lets it go on: it is refused, and nothing it
/// would have written is.
async fn an_establishment_that_lapses_while_it_waits(at: At, lapse: Lapse) {
    let what = format!("{lapse:?} {at:?}");
    let (temp, controller, continuous, ..) = distrusting().await;
    let door = Door::open(&temp, &controller).await;
    let challenge = door.challenge().await;
    door.answer(&challenge.request).await.expect("answered");
    let pauses = &controller.owner_authority().pauses;
    let (arrived, go) = match at {
        At::BeforeTheClock => pauses.before_the_transaction.arm(),
        At::AfterTheConnection => pauses.after_the_connection.arm(),
    };
    let attempt = tokio::spawn({
        let door = door.clone();
        async move { door.establish().await }
    });
    arrived.await.expect("the effect reached the wait");

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
    assert_eq!(code(refused), expected, "{what}");
    assert!(
        !proven(&controller),
        "{what}: the host still distrusts its clock"
    );
    assert_eq!(confirmed_at(&temp), None, "{what}: nothing was written");

    // The control: what lapsed is restored and the same confirmation, which the refusal left
    // answered, establishes the clock. A host that gained an owner stays one.
    match lapse {
        Lapse::AnOwnerAppears => return,
        Lapse::AFenceIsOwed => controller.hold_fence(false),
        Lapse::TheDeadlinePasses | Lapse::TheRegistrationIsWithdrawn => {}
    }
    let door = Door::open(&temp, &controller).await;
    door.establish()
        .await
        .unwrap_or_else(|error| panic!("{what}: the same confirmation establishes it: {error:?}"));
    assert!(proven(&controller), "{what}");
}

/// KR-REQ-09.19, KR-REQ-10.53: authority that lapses while an establishment waits is asked again
/// where it commits. Waiting for the clock, a host that gains an owner no longer takes the
/// terminal's confirmation, and a deadline that passed, a fence the host owes and a registration
/// that was withdrawn each refuse the effect; so do the last three after the effect holds the
/// directory's connection. Each leaves the clock distrusted and the owner's confirmation
/// answered.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn authority_that_lapses_while_the_establishment_waits_stops_it() {
    for (at, lapse) in [
        (At::BeforeTheClock, Lapse::AnOwnerAppears),
        (At::BeforeTheClock, Lapse::TheDeadlinePasses),
        (At::BeforeTheClock, Lapse::AFenceIsOwed),
        (At::BeforeTheClock, Lapse::TheRegistrationIsWithdrawn),
        (At::AfterTheConnection, Lapse::TheDeadlinePasses),
        (At::AfterTheConnection, Lapse::AFenceIsOwed),
        (At::AfterTheConnection, Lapse::TheRegistrationIsWithdrawn),
    ] {
        an_establishment_that_lapses_while_it_waits(at, lapse).await;
    }
}

/// KR-REQ-09.19, KR-REQ-10.05: the signer of the confirmation an establishment chose can lose its
/// authority before the effect commits. An owner device answers the challenge, the effect chooses
/// that answer, the device is revoked while the effect waits, and the commit refuses: the answer
/// was given under authority this host no longer holds, and nothing is written. The control is a
/// new confirmation, which the person at the terminal gives.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_signer_revoked_while_the_establishment_waits_cannot_spend_its_answer() {
    let (temp, controller, ..) = distrusting().await;
    let keys = kr_crypto::keys::DeviceKeys::generate().expect("keys");
    let device = paired(
        &controller,
        &keys,
        0x41,
        &[kr_protocol::rights::ActionRight::HostManage],
        kr_protocol::grant::GrantExpiry::Never,
    );
    let door = Door::open(&temp, &controller).await;
    let challenge = door.challenge().await;
    door.answer_as_device(&challenge.request, &keys)
        .await
        .expect("the owner device answers");
    let (arrived, go) = controller
        .owner_authority()
        .pauses
        .before_the_transaction
        .arm();
    let attempt = tokio::spawn({
        let door = door.clone();
        async move { door.establish().await }
    });
    arrived.await.expect("the effect chose the device's answer");

    controller
        .devices()
        .revoke(device.device_id, kr_ipc::now_ms())
        .expect("the device is revoked");
    go.send(()).expect("the effect goes on");

    assert_eq!(
        code(attempt.await.expect("the effect ends")),
        ErrorCode::OwnerConfirmationRequired
    );
    assert!(!proven(&controller), "the host still distrusts its clock");
    assert_eq!(confirmed_at(&temp), None, "nothing was written");

    door.the_owner_establishes().await;
    assert!(proven(&controller));
}

/// KR-REQ-09.12, KR-REQ-09.19: the registration an establishment was admitted under is held
/// standing from the check to the commit, so a withdrawal is ordered wholly before the effect or
/// wholly after it. The effect is stopped inside its commit, after every row is written and
/// checked and before the commit, and a withdrawal started there does not complete until the
/// effect has committed: it reads the clock as established when it does.
///
/// That the withdrawal waits is decided by the lock a withdrawal takes, which is the one thing
/// that says so without a delay: the registrations are held while the effect commits.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_withdrawal_started_inside_the_commit_completes_after_it() {
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

    let withdrawal = {
        let controller = Arc::clone(&controller);
        let connection_id = door.connection_id();
        let database = temp.environment().registry_database();
        std::thread::spawn(move || {
            controller.deregister(connection_id);
            rusqlite::Connection::open(database)
                .expect("opens the registry")
                .query_row(
                    "SELECT confirmed_at_ms FROM network_clock WHERE id = 0",
                    [],
                    |row| row.get::<_, Option<i64>>(0),
                )
                .expect("the clock record is readable")
        })
    };
    assert!(
        controller.admitted.try_lock().is_err(),
        "the registrations are held while the effect commits"
    );
    go.send(()).expect("the effect commits");

    attempt.await.expect("the effect ends").expect("it commits");
    assert!(
        withdrawal.join().expect("the withdrawal ends").is_some(),
        "the withdrawal completed after the commit, and found the clock established"
    );
    assert!(proven(&controller));
}

/// KR-REQ-09.19: a connection that goes away while an establishment is on its way does not cut it.
/// The future awaiting the effect is dropped inside the commit, and the effect still ends with the
/// clock established and the confirmation spent, both or neither: here both, since it had passed
/// every check. A retry of the action is answered from its record.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_connection_that_goes_away_does_not_cut_the_establishment() {
    let (temp, controller, ..) = distrusting().await;
    let door = Door::open(&temp, &controller).await;
    let challenge = door.challenge().await;
    door.answer(&challenge.request).await.expect("answered");
    let (arrived, go) = controller.owner_authority().pauses.inside_the_commit.arm();
    let original = door.mutation(
        Method::HostClockEstablish,
        ActionId::new(kr_ipc::new_uuid()),
        30_000,
        &HostClockEstablishParams {},
    );
    let revision = controller.admitted_revision(door.connection_id()).ok();
    let deadline = Some(door.accepted().deadline);
    let task = tokio::spawn({
        let controller = Arc::clone(&controller);
        let caller = Caller::local(door.actor_id().clone());
        let connection_id = door.connection_id();
        let mutation = original.clone();
        async move {
            let admission = controller.pairing_admission(connection_id, revision, deadline);
            let guard = controller.pairing_guard(connection_id, revision, deadline);
            controller
                .pairing_write(
                    caller,
                    Method::HostClockEstablish,
                    &mutation,
                    admission,
                    guard,
                )
                .await
        }
    });
    arrived.await.expect("the effect reached its commit");

    task.abort();
    assert!(
        task.await
            .expect_err("the future was dropped")
            .is_cancelled()
    );
    go.send(()).expect("the effect commits");

    // The effect holds the challenges until it has finished: listing them waits for it.
    let owner = Arc::clone(controller.owner_authority());
    let caller = Caller::local(door.actor_id().clone());
    tokio::task::spawn_blocking(move || owner.pending(&caller))
        .await
        .expect("the listing ends")
        .expect("the owner lists what it can answer");
    assert!(confirmed_at(&temp).is_some(), "the clock was established");
    assert!(proven(&controller));
    let retried: HostClockEstablishResult = door
        .perform(original)
        .await
        .expect("a retry of the action is answered from its record");
    assert_eq!(retried.confirmation_id, challenge.request.confirmation_id);
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
    // Both are on their way to the challenges the first one holds before it is let go.
    while owner.pauses.entered.load(Ordering::SeqCst) < 3 {
        tokio::task::yield_now().await;
    }
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
