//! What a request's footing reads of a barrier, a fence and a registration without taking a lock.
//!
//! The footing holds copies that each writer sets under its own lock: the registration's latch,
//! the flag of a fence owed, and the revision in memory. These tests drive the writers of a real
//! daemon and read the footing back at the places a barrier is stopped in, so that each member is
//! shown to change where its writer changes it, and in the order that a reader relies on.

use std::sync::Arc;
use std::time::Duration;

use kr_protocol::method::Method;
use kr_transport::clock::ContinuousClock;

use super::a_floor_owed_its_record::{daemon, daemon_passing_by_hand, until};
use super::a_result_the_lease_ended_over::connected_under_a_lease;
use super::one_barrier_for_every_restriction::{beside, owed, revision};
use super::the_fence_at_every_effect::{admitted, daemon as daemon_on_clocks};
use super::{Ask, Lapse, LeasedLapse, Reach};
use crate::authority::AdmissionLapse;

/// Waits until a change says it has reached the place it is stopped at, and fails the test when it
/// does not within thirty seconds.
async fn arrival(arrived: std::sync::mpsc::Receiver<()>) {
    tokio::task::spawn_blocking(move || arrived.recv_timeout(Duration::from_secs(30)))
        .await
        .expect("the waiting thread finishes")
        .expect("the change reaches the place it is stopped at");
}

/// A fence held by the test seam sets the flag that the fence's check reads, and letting it go
/// clears it: the footing of a request is refused while the flag is set, and no lock is taken to
/// say so.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_fence_held_by_the_test_seam_sets_the_flag_and_letting_it_go_clears_it() {
    let (_temp, controller, _clock) = daemon_on_clocks().await;
    let (connection_id, _actor) = admitted(&controller).await;
    let footing = controller
        .footing_on(connection_id, None)
        .expect("the connection is registered");

    assert_eq!(footing.ask(Ask::MUTATION), Ok(()));
    controller.hold_fence(true);
    assert!(controller.copies.fence_is_owed());
    assert_eq!(footing.ask(Ask::MUTATION), Err(Lapse::FenceOwed));
    controller
        .check_fence()
        .expect_err("the fence's check reads the flag");
    // A read asks no fence.
    assert_eq!(footing.ask(Ask::READ), Ok(()));
    controller.hold_fence(false);
    assert!(!controller.copies.fence_is_owed());
    assert_eq!(footing.ask(Ask::MUTATION), Ok(()));
    controller.check_fence().expect("no fence is owed");
}

/// A change publishes its debts and the flag is set; its barrier then withdraws the registration
/// and raises the revision, and clears the flag last. Stopped between the withdrawal and the
/// issuer's adoption of the revision, the registration's latch is set, the stored revision has
/// moved, the revision in memory has not, and the flag is still set: a reader finds the members in
/// the order that the barrier makes true.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_barrier_sets_the_latch_and_raises_the_revision_before_it_clears_the_flag() {
    let (_temp, controller, _clock) = daemon_on_clocks().await;
    let (connection_id, _actor) = admitted(&controller).await;
    let footing = controller
        .footing_on(connection_id, None)
        .expect("the connection is registered");
    let before = revision(&controller).await;
    assert_eq!(controller.copies.revision(), before);

    let debt = controller
        .owe_debt("a withdrawal", Reach::Host)
        .expect("the debt is written");
    let own = controller.publish_debts(&[(debt, Reach::Host)]);
    assert!(controller.copies.fence_is_owed(), "the debt is published");
    assert_eq!(footing.ask(Ask::MUTATION), Err(Lapse::FenceOwed));

    let (arrived, release) = controller.before_the_leases_adopt.arm();
    let raising = tokio::spawn({
        let controller = std::sync::Arc::clone(&controller);
        async move { controller.barrier(own).await }
    });
    arrival(arrived).await;
    // The barrier holds the registry here, so the stored revision is read after it lets go.
    assert_eq!(
        controller.copies.revision(),
        before,
        "the revision in memory follows the issuer, which has not adopted it"
    );
    assert!(
        controller.copies.fence_is_owed(),
        "the debt is still published"
    );
    assert_eq!(
        footing.ask(Ask::READ),
        Err(Lapse::Admission(AdmissionLapse::Deregistered)),
        "the registration went with the barrier, and its latch with it"
    );
    assert_eq!(footing.ask(Ask::MUTATION), Err(Lapse::FenceOwed));

    release.send(()).expect("the barrier goes on");
    raising
        .await
        .expect("the barrier ends")
        .expect("the barrier is raised");
    assert!(
        !controller.copies.fence_is_owed(),
        "the barrier retired the debt"
    );
    assert_eq!(
        revision(&controller).await,
        before + 1,
        "the registry moved"
    );
    assert_eq!(controller.copies.revision(), before + 1);
    // With the flag clear, the revision is read next and says the authority was withdrawn.
    assert_eq!(
        footing.ask(Ask::MUTATION),
        Err(Lapse::Admission(AdmissionLapse::Revoked))
    );
    controller
        .footing_on(connection_id, None)
        .expect_err("the registration is gone");
}

/// Another device's revocation raises the revision and leaves this registration standing, stamped
/// with the new revision: a footing made before it is refused by its revision alone, and one made
/// after it stands.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_barrier_for_another_device_raises_the_revision_and_leaves_the_registration() {
    let (_temp, controller, _clock) = daemon_on_clocks().await;
    let (connection_id, _actor) = admitted(&controller).await;
    let footing = controller
        .footing_on(connection_id, None)
        .expect("the connection is registered");
    let before = controller.copies.revision();

    let other = Reach::Device(kr_protocol::ids::DeviceId::new(kr_ipc::new_uuid()));
    let debt = controller
        .owe_debt("another device's withdrawal", other.clone())
        .expect("the debt is written");
    let own = controller.publish_debts(&[(debt, other)]);
    controller
        .barrier(own)
        .await
        .expect("the barrier is raised");

    assert_eq!(controller.copies.revision(), before + 1);
    assert!(!controller.copies.fence_is_owed());
    assert_eq!(
        footing.ask(Ask::MUTATION),
        Err(Lapse::Admission(AdmissionLapse::Revoked))
    );
    assert_eq!(footing.ask(Ask::KEPT_ANSWER), footing.ask(Ask::MUTATION));
    assert_eq!(footing.ask(Ask::LOCAL_CLOSE), footing.ask(Ask::MUTATION));
    // The registration stands, and a read holds no revision.
    assert_eq!(footing.ask(Ask::READ), Ok(()));
    assert_eq!(footing.ask(Ask::NETWORK_CLOSE_CLAIM), Ok(()));
    let later = controller
        .footing_on(connection_id, None)
        .expect("the registration stands");
    assert_eq!(later.ask(Ask::MUTATION), Ok(()));
}

/// The revision in memory starts from the revision the registry persisted, so a daemon that
/// starts again does not read a revision below the one its requests are admitted under.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_revision_in_memory_starts_from_the_persisted_revision() {
    let temp = kr_ipc::testing::TempHost::create();
    let controller = daemon(&temp).await;
    controller.revoke_authority().await.expect("a barrier");
    controller
        .revoke_authority()
        .await
        .expect("another barrier");
    let persisted = revision(&controller).await;
    assert!(persisted >= 2);
    assert_eq!(controller.copies.revision(), persisted);
    super::net::tests::stopped(controller).await;

    let controller = daemon(&temp).await;
    assert_eq!(
        controller.copies.revision(),
        revision(&controller).await,
        "the revision in memory is the revision the registry holds"
    );
    assert!(controller.copies.revision() >= persisted);
}

/// A start that finds a fence debt on disk and cannot raise its barrier publishes the debt, and
/// the flag is set with it: nothing is admitted until a barrier retires it, and the barrier that
/// does clears the flag.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_start_that_cannot_raise_its_barrier_sets_the_flag_for_the_debt_it_published() {
    let temp = kr_ipc::testing::TempHost::create();
    let controller = daemon(&temp).await;
    controller
        .owe_debt("a change the daemon stopped in", Reach::Host)
        .expect("written");
    super::net::tests::stopped(controller).await;

    let registry = beside(&temp);
    registry
        .execute_batch(
            "CREATE TRIGGER refuse_revision BEFORE UPDATE OF authority_revision ON environment
                 BEGIN SELECT RAISE(ABORT, 'no room'); END;",
        )
        .expect("the fault is in place");
    let (controller, passes) = daemon_passing_by_hand(&temp).await;
    assert!(
        controller.copies.fence_is_owed(),
        "the debt the start published sets the flag"
    );
    assert_eq!(
        super::Footing::untargeted(std::sync::Arc::clone(&controller.copies)).ask(Ask::SIGN_IN),
        Err(Lapse::FenceOwed)
    );
    registry
        .execute_batch("DROP TRIGGER refuse_revision;")
        .expect("the fault is cleared");

    passes.send(()).expect("the pass is running");
    until(
        "the first pass raising the debt and clearing the flag",
        async || !controller.copies.fence_is_owed() && owed(&controller).is_empty(),
    )
    .await;
}

/// A held method's reading of the local owner's lease returns the bound of the lease it chose
/// beside the lease's end, a footing that holds that bound is refused once the lease's time has
/// come, and a method that needs no lease holds none.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_held_methods_reading_of_the_lease_returns_the_chosen_leases_bound_beside_its_end() {
    let (_temp, controller, clock, _writer, _reader) = connected_under_a_lease().await;

    let held = controller
        .local_hold(Method::SessionRead)
        .expect("the lease is live");
    let end = held.end.expect("a lease has an end");
    let footing = super::Footing::untargeted(Arc::clone(&controller.copies))
        .holding(held.bound.expect("a lease has a bound"));
    assert_eq!(footing.ask(Ask::SIGN_IN), Ok(()));

    clock.advance(end.saturating_duration_since(clock.now()));
    assert_eq!(
        footing.ask(Ask::SIGN_IN),
        Err(LeasedLapse::Lapse(Lapse::LeaseEnded))
    );
    controller
        .local_hold(Method::SessionRead)
        .expect_err("no lease is live now");

    let free = controller
        .local_hold(Method::GrantList)
        .expect("a method that needs no lease is served");
    assert!(free.end.is_none() && free.bound.is_none());
}
