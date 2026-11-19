//! What a change of the host's policy, an answer to the owner and the establishment of the clock
//! wait for, and what the local owner's published standing says.
//!
//! A policy commit holds the policy's lock across its storage writes, which wait for the device
//! directory's connection. A check that runs inside a transaction on that connection must not wait
//! for the policy's lock, so it reads the standing the policy in force published. These cases hold
//! one lock on each side of the wait and show that neither side waits for the other. A case that
//! waits does so on a channel with a failure bound, and a case that waits owns its runtime and its
//! daemon in a [`Rig`] that a failed case leaves where it stands, so a thread stuck in a lock
//! turns into a failed assertion and not into a hang in the runtime's drop. The cases that only
//! read what the policy published wait for no other thread and run on the test runtime.

use std::mem::ManuallyDrop;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use kr_crypto::keys::AuthorisationKeyPair;
use kr_protocol::account::MEMBERSHIP_LEASE_MAX_LIFETIME_MS;
use kr_protocol::ids::{AccountId, ActorId};
use kr_protocol::scalars::{DurationMs, Nullable, TimestampMs};
use kr_protocol::sharing::OfflineValidityPolicy;
use kr_transport::clock::ManualClock;

use super::a_transfer_left_unanswered::daemon;
use super::an_owner_establishes_the_clock::{Door, distrusting, proven};
use super::{Clocks, Controller, WallClock};
use crate::error::ControllerError;
use crate::grants::organisation::LEASE_CLOCK_MARGIN_MS;
use crate::grants::organisation::testing::TestOrganisation;
use crate::service::net::devices::ObservedUtc;
use crate::service::net::tests::{daemon_on, manual_clocks};

/// How long a wait of these cases lasts before the case fails. Nothing is decided by it: a case
/// that gets there has found a lock that is not let go.
const BOUND: Duration = Duration::from_secs(30);

/// A runtime of four workers and the daemon on it, for a case that holds locks on threads of its
/// own.
pub(super) struct Rig {
    pub(super) runtime: tokio::runtime::Runtime,
    pub(super) temp: kr_ipc::testing::TempHost,
    pub(super) controller: Arc<Controller>,
}

impl Rig {
    /// Starts the daemon `start` makes on a new runtime. A case wraps what it gets in
    /// [`ManuallyDrop`] and ends it with [`finish`], so that a case that panics at any wait leaves
    /// the runtime and the daemon where they stand.
    pub(super) fn new<F>(start: F) -> ManuallyDrop<Self>
    where
        F: std::future::Future<Output = (kr_ipc::testing::TempHost, Arc<Controller>)>,
    {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .expect("a runtime");
        let (temp, controller) = runtime.block_on(start);
        ManuallyDrop::new(Self {
            runtime,
            temp,
            controller,
        })
    }
}

/// Ends a case that passed: only now are the daemon and the runtime dropped.
pub(super) fn finish(rig: ManuallyDrop<Rig>) {
    let Rig {
        runtime,
        temp,
        controller,
    } = ManuallyDrop::into_inner(rig);
    drop(controller);
    drop(runtime);
    drop(temp);
}

/// A bounded offline validity measured from `synchronised`.
fn offline_bound(synchronised: u64) -> OfflineValidityPolicy {
    OfflineValidityPolicy {
        maximum_offline_ms: DurationMs::new(60_000),
        last_synchronised_at_ms: Nullable::some(TimestampMs::new(synchronised)),
    }
}

/// Waits for `count` reports on `reports`, inside one failure bound, and returns the names of the
/// threads that reported with the answer each gave.
fn reports(
    reports: &mpsc::Receiver<(&'static str, bool)>,
    count: usize,
) -> Vec<(&'static str, bool)> {
    let deadline = Instant::now() + BOUND;
    let mut heard = Vec::new();
    while heard.len() < count {
        match reports.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(report) => heard.push(report),
            Err(_) => break,
        }
    }
    heard
}

/// KR-REQ-24.15, section 10: a policy commit that holds the policy's lock and waits for the device
/// directory's connection, and an answer that holds the connection and asks whether the caller is
/// still served, do not wait for each other. The caller is built before the transaction, as the
/// door builds it, on a host that is not exclusively managed, so deciding it again calls the
/// check. One thread holds the policy's lock inside a change whose synchronisation moves the
/// offline bound, which makes the commit read the connection after the change returns; the other
/// holds the connection inside a transaction and decides the caller again. Both are let go once
/// each holds its lock, and both finish.
#[test]
fn a_policy_commit_and_an_answer_to_the_owner_do_not_wait_for_each_other() {
    let rig = Rig::new(daemon());
    let controller = Arc::clone(&rig.controller);
    let synchronised = kr_ipc::now_ms().get();
    controller
        .update_policy(|policy| policy.set_offline_validity(Some(offline_bound(synchronised))))
        .expect("a bounded offline validity is chosen");
    let actor = ActorId::new("local:test").expect("a principal");
    let caller = controller.local_caller(&actor);

    let (policy_held_tx, policy_held) = mpsc::channel::<()>();
    let (connection_held_tx, connection_held) = mpsc::channel::<()>();
    let (done_tx, done) = mpsc::channel::<(&'static str, bool)>();
    {
        let (controller, done_tx) = (Arc::clone(&controller), done_tx.clone());
        std::thread::spawn(move || {
            let mut met = false;
            let committed = controller.update_policy(|policy| {
                let _ = policy_held_tx.send(());
                met = connection_held.recv_timeout(BOUND).is_ok();
                policy.note_feed_synchronised(synchronised + 1);
            });
            let _ = done_tx.send(("the policy commit", met && committed.is_ok()));
        });
    }
    {
        let controller = Arc::clone(&controller);
        std::thread::spawn(move || {
            let answered = controller.devices.transaction(|_| {
                let _ = connection_held_tx.send(());
                let met = policy_held.recv_timeout(BOUND).is_ok();
                let _ = caller.decided_now();
                Ok(met)
            });
            let _ = done_tx.send(("the answer to the owner", answered.unwrap_or(false)));
        });
    }

    let heard = reports(&done, 2);
    let names: Vec<_> = heard.iter().map(|(name, _)| *name).collect();
    assert!(
        names.contains(&"the policy commit") && names.contains(&"the answer to the owner"),
        "the policy commit holds the policy's lock and waits for the directory's connection, \
         and the answer holds the connection and waits for the policy's lock; finished: {names:?}"
    );
    assert!(
        heard.iter().all(|(_, met)| *met),
        "each side held its lock when the other did: {heard:?}"
    );
    finish(rig);
}

/// KR-REQ-24.15: a commit whose write is refused publishes no standing, and one whose write
/// succeeds publishes it only after the write. The standing loaded before each call is the value
/// the write sees, so a standing stored before the write, or kept after it failed, is seen by an
/// assertion inside the write and after the call. A change that refuses publishes nothing either.
#[test]
fn a_commit_that_cannot_be_written_publishes_no_standing() {
    let rig = Rig::new(daemon());
    let controller = Arc::clone(&rig.controller);
    controller
        .update_policy(|policy| policy.set_exclusively_managed(true))
        .expect("the host is exclusively managed");
    assert!(
        controller.local_owner_is_closed(),
        "an exclusively managed host with no lease is closed to its local owner"
    );
    let before = controller.local_owner_standing.load_full();

    let failed = controller.commit_policy(
        |policy| {
            policy.set_exclusively_managed(false);
            Ok(())
        },
        |_, _, ()| {
            assert!(
                Arc::ptr_eq(&controller.local_owner_standing.load_full(), &before),
                "nothing is published before the write"
            );
            Err(ControllerError::InvalidArgument(
                "the write is refused".to_owned(),
            ))
        },
        |()| Ok(()),
    );
    assert!(failed.is_err(), "the write's refusal is the commit's");
    assert!(
        Arc::ptr_eq(&controller.local_owner_standing.load_full(), &before),
        "a commit whose write failed publishes no standing"
    );
    assert!(
        controller.local_owner_is_closed(),
        "and the host stays closed"
    );

    let refused = controller.commit_policy(
        |_| Err::<(), _>(ControllerError::InvalidArgument("refused".to_owned())),
        |_, _, ()| panic!("a refused change writes nothing"),
        |()| Ok(()),
    );
    assert!(refused.is_err());
    assert!(
        Arc::ptr_eq(&controller.local_owner_standing.load_full(), &before),
        "a change that refuses publishes no standing"
    );

    controller
        .commit_policy(
            |policy| {
                policy.set_exclusively_managed(false);
                Ok(())
            },
            |grants, snapshot, ()| {
                assert!(
                    Arc::ptr_eq(&controller.local_owner_standing.load_full(), &before),
                    "nothing is published until the write has succeeded"
                );
                grants.store_policy(snapshot)
            },
            |()| Ok(()),
        )
        .expect("the commit is written");
    assert!(
        !Arc::ptr_eq(&controller.local_owner_standing.load_full(), &before),
        "a commit that was written publishes its standing"
    );
    assert!(
        !controller.local_owner_is_closed(),
        "and the host no longer needs a lease"
    );
    finish(rig);
}

/// KR-REQ-24.15: a feed refusal raised while an establishment of the clock is on its way, a policy
/// commit that waits for the directory, and that establishment do not wait for one another in a
/// ring. The establishment stops before it takes anything of its own. A policy commit then holds
/// the policy's lock, and the raise holds the registration hold for writing and waits for the
/// policy's lock. The establishment is let go: it takes the registration hold, the clock's state
/// and the directory's connection in the crate's order, so it waits behind the raise only, and the
/// commit's wait for the connection ends. All three finish, and the establishment's answer is the
/// established result (the connection is a local one, which the raise does not refuse).
#[test]
fn a_feed_raise_a_policy_commit_and_a_clock_establishment_do_not_wait_in_a_ring() {
    let rig = Rig::new(async {
        let (temp, controller, ..) = distrusting().await;
        (temp, controller)
    });
    let controller = Arc::clone(&rig.controller);
    let synchronised = kr_ipc::now_ms().get();
    controller
        .update_policy(|policy| policy.set_offline_validity(Some(offline_bound(synchronised))))
        .expect("a bounded offline validity is chosen");
    let door = rig.runtime.block_on(async {
        let door = Door::open(&rig.temp, &controller).await;
        let challenge = door.challenge().await;
        door.answer(&challenge.request).await.expect("answered");
        door
    });
    let pauses = &controller.owner_authority().pauses;
    let (done_tx, done) = mpsc::channel::<(&'static str, bool)>();
    let wait = |arrived: tokio::sync::oneshot::Receiver<()>, what: &str| {
        rig.runtime
            .block_on(async { tokio::time::timeout(BOUND, arrived).await })
            .unwrap_or_else(|_| panic!("{what}"))
            .unwrap_or_else(|_| panic!("{what}"));
    };

    // The establishment is through the door and has chosen its confirmation: it holds the
    // challenges and nothing else.
    let (chosen, go_on) = pauses.before_the_transaction.arm();
    {
        let done_tx = done_tx.clone();
        rig.runtime.spawn(async move {
            let established = door.establish().await;
            let _ = done_tx.send(("the establishment", established.is_ok()));
        });
    }
    wait(chosen, "the establishment chose its confirmation");

    // A policy commit holds the policy's lock inside its change, and goes on to the directory when
    // it is let go.
    let (policy_held_tx, policy_held) = mpsc::channel::<()>();
    let (release_tx, release) = mpsc::channel::<()>();
    {
        let (controller, done_tx) = (Arc::clone(&controller), done_tx.clone());
        std::thread::spawn(move || {
            let committed = controller.update_policy(|policy| {
                let _ = policy_held_tx.send(());
                let _ = release.recv_timeout(BOUND);
                policy.note_feed_synchronised(synchronised + 1);
            });
            let _ = done_tx.send(("the policy commit", committed.is_ok()));
        });
    }
    policy_held
        .recv_timeout(BOUND)
        .expect("the policy commit holds the policy's lock");

    // The raise holds the registration hold for writing and waits for the policy's lock.
    {
        let (controller, done_tx) = (Arc::clone(&controller), done_tx.clone());
        rig.runtime.spawn(async move {
            controller.raise_the_unverified_withdrawal_refusal().await;
            let _ = done_tx.send(("the feed's raise", true));
        });
    }
    let deadline = Instant::now() + BOUND;
    while controller.withdrawals_waiting.load(Ordering::SeqCst) == 0
        || controller.commit_hold.try_read().is_ok()
    {
        assert!(
            Instant::now() < deadline,
            "the raise did not take the registration hold for writing"
        );
        std::thread::yield_now();
    }

    // The establishment goes on to the stop that stands before the registration hold. At the base
    // of the cure it holds the clock's state and the directory's connection there; after it, it
    // holds nothing.
    let (at_the_hold, go_to_the_hold) = pauses.before_the_registration_hold.arm();
    go_on.send(()).expect("the establishment goes on");
    wait(
        at_the_hold,
        "the establishment reached the registration hold",
    );
    release_tx.send(()).expect("the policy commit goes on");
    go_to_the_hold
        .send(())
        .expect("the establishment takes the hold");

    let heard = reports(&done, 3);
    let names: Vec<_> = heard.iter().map(|(name, _)| *name).collect();
    assert!(
        names.contains(&"the establishment")
            && names.contains(&"the policy commit")
            && names.contains(&"the feed's raise"),
        "the raise holds the registration hold and waits for the policy's lock, the commit holds \
         the policy's lock and waits for the directory's connection, and the establishment holds \
         the connection and waits for the registration hold; finished: {names:?}"
    );
    assert!(
        heard.iter().all(|(_, ok)| *ok),
        "all three ended well: {heard:?}"
    );
    assert!(proven(&controller), "the clock was established");
    finish(rig);
}

/// The organisation a host is enrolled in, the key the host's local owner proves and the
/// account its lease names, on a daemon whose clocks the case moves.
struct Leased {
    controller: Arc<Controller>,
    continuous: ManualClock,
    wall: Arc<std::sync::atomic::AtomicU64>,
    organisation: TestOrganisation,
    key: AuthorisationKeyPair,
    account: AccountId,
}

/// The two ends a lease the case presented has.
#[derive(Clone, Copy, Debug)]
struct Ends {
    continuous: kr_transport::clock::ContinuousInstant,
    utc_ms: u64,
}

impl Leased {
    /// Starts a daemon on `clocks` and enrols it in an organisation, with no lease and no
    /// exclusive management.
    async fn start(
        temp: &kr_ipc::testing::TempHost,
        continuous: ManualClock,
        wall: Arc<std::sync::atomic::AtomicU64>,
        clocks: Clocks,
    ) -> Self {
        let controller = daemon_on(temp, clocks).await;
        let now = wall.load(Ordering::SeqCst);
        let organisation = TestOrganisation::new(0x31, now - 60 * 60 * 1000);
        let reading = ObservedUtc {
            now: TimestampMs::new(now),
            behind_ms: 0,
        };
        controller
            .update_policy(|policy| {
                let verified = policy
                    .verify_enrolment(&organisation.authority(now), Some(&reading))
                    .expect("the chain verifies");
                let revision = policy.authority_revision();
                policy.enrol(verified, revision).expect("the host enrols");
            })
            .expect("the enrolment is written down");
        Self {
            controller,
            continuous,
            wall,
            organisation,
            key: AuthorisationKeyPair::generate().expect("a key"),
            account: AccountId::new("ada").expect("an account"),
        }
    }

    /// Lets `by` pass on both clocks.
    fn pass(&self, by: Duration) {
        self.continuous.advance(by);
        self.wall.fetch_add(
            u64::try_from(by.as_millis()).expect("a duration"),
            Ordering::SeqCst,
        );
    }

    /// Presents a lease issued now for the host's own local owner, and returns the ends it has:
    /// its signed expiry in UTC, and the same time on the continuous clock, less the margin
    /// installation takes off.
    fn present(&self) -> Ends {
        let issued = self.wall.load(Ordering::SeqCst);
        let lease = self.organisation.lease(
            &self.account,
            *self.key.public(),
            issued,
            &[kr_protocol::rights::ActionRight::SessionView],
        );
        let ends = Ends {
            continuous: self
                .controller
                .clock
                .now()
                .checked_add(Duration::from_millis(
                    MEMBERSHIP_LEASE_MAX_LIFETIME_MS - LEASE_CLOCK_MARGIN_MS,
                ))
                .expect("an instant"),
            utc_ms: issued + MEMBERSHIP_LEASE_MAX_LIFETIME_MS,
        };
        self.controller
            .present_membership_lease(
                self.controller.local_owner_device(),
                self.key.public(),
                &lease,
                None,
                None,
            )
            .expect("the presentation is written down")
            .expect("the lease installs");
        ends
    }

    /// Whether the host is exclusively managed and no lease the case presented is live now,
    /// worked out from the ends the case chose and the clocks' readings.
    fn expected_closed(&self, exclusive: bool, live: &[Ends]) -> bool {
        let now = self.controller.clock.now();
        let now_ms = self.wall.load(Ordering::SeqCst);
        exclusive
            && !live
                .iter()
                .any(|ends| now < ends.continuous && now_ms < ends.utc_ms)
    }

    /// Asserts that the local owner is closed out exactly when `expected_closed` says.
    fn agrees(&self, step: &str, exclusive: bool, live: &[Ends]) {
        assert_eq!(
            self.controller.local_owner_is_closed(),
            self.expected_closed(exclusive, live),
            "{step}"
        );
    }
}

/// KR-REQ-24.15, section 10: the local owner is closed out of everything but recovery exactly when
/// the host is exclusively managed and no lease of its own key is live, after every kind of change
/// the policy commits: exclusive management set, the host's lease presented, renewed with later
/// ends, the enrolment withdrawn, exclusive management ended. The answer is checked against what
/// the case works out from the ends it chose, at readings before and at each end, and a value
/// loaded before a commit keeps the answer of the policy it came from while the new one answers
/// the new policy's.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_local_owner_standing_follows_every_change_the_policy_commits() {
    let temp = kr_ipc::testing::TempHost::create();
    let (continuous, wall, clocks) = manual_clocks();
    let host = Leased::start(&temp, continuous, wall, clocks).await;
    let controller = Arc::clone(&host.controller);
    let organisation_id = host.organisation.organisation_id;
    let second = Duration::from_secs(1);

    host.agrees("a host that is not exclusively managed", false, &[]);

    controller
        .update_policy(|policy| policy.set_exclusively_managed(true))
        .expect("exclusive management is set");
    assert!(controller.local_owner_is_closed());
    host.agrees("exclusive management with no lease", true, &[]);

    // The host's lease is presented, and the owner is served until its first end.
    let first = host.present();
    assert!(!controller.local_owner_is_closed());
    host.agrees(
        "the host's lease is installed by its presentation",
        true,
        &[first],
    );
    host.pass(Duration::from_millis(
        MEMBERSHIP_LEASE_MAX_LIFETIME_MS - LEASE_CLOCK_MARGIN_MS - 1_000,
    ));
    host.agrees("a second before the lease's end", true, &[first]);
    assert!(!controller.local_owner_is_closed());
    host.pass(second);
    host.agrees("at the lease's end", true, &[first]);
    assert!(controller.local_owner_is_closed(), "the lease has ended");

    // A lease is presented again and renewed with later ends: the renewal's ends, not the first
    // lease's, decide.
    let renewed = host.present();
    host.pass(Duration::from_secs(60));
    let later = host.present();
    host.agrees("the renewal", true, &[renewed, later]);
    host.pass(Duration::from_millis(
        MEMBERSHIP_LEASE_MAX_LIFETIME_MS - LEASE_CLOCK_MARGIN_MS - 60_000,
    ));
    // The first lease's own end has come and the renewal's has not.
    host.agrees(
        "between the first lease's end and the renewal's",
        true,
        &[renewed, later],
    );
    assert!(
        !controller.local_owner_is_closed(),
        "the renewal's later end serves the owner"
    );
    host.pass(Duration::from_secs(61));
    host.agrees("after the renewal's end", true, &[renewed, later]);
    assert!(controller.local_owner_is_closed());

    // Ending exclusive management from the closed state opens the host.
    controller
        .update_policy(|policy| policy.set_exclusively_managed(false))
        .expect("exclusive management ends");
    assert!(!controller.local_owner_is_closed());
    host.agrees("exclusive management ended", false, &[]);

    // Set again with a live lease, then the enrolment withdrawn: the value loaded before the
    // withdrawal still answers that the owner is served, and the new one that it is not.
    controller
        .update_policy(|policy| policy.set_exclusively_managed(true))
        .expect("exclusive management is set again");
    let live = host.present();
    host.agrees(
        "a new lease after exclusive management is set again",
        true,
        &[live],
    );
    let retained = controller.local_owner_standing.load_full();
    controller
        .update_policy(|policy| policy.withdraw(organisation_id))
        .expect("the enrolment is withdrawn");
    assert!(
        controller.local_owner_is_closed(),
        "no lease answers for the local owner once its enrolment is gone"
    );
    host.agrees("the enrolment withdrawn", true, &[]);
    assert_ne!(
        retained.bound(controller.clock.now(), host.wall.load(Ordering::SeqCst)),
        crate::grants::policy::LocalOwnerBound::Closed,
        "the value loaded before the withdrawal answers for the policy it came from"
    );
}

/// KR-REQ-24.15: while the host's lease is renewed, a reader that asks whether the local owner is
/// closed out gets an answer, and it is the answer of the policy before the renewal or the one
/// after it. The renewal is stopped inside the publication of the lease's cell, before the swap
/// and after it, on the thread that presents it and with the policy's lock held; a reader on
/// another thread asks at each stop. Both policies have a live lease, so the answer is not closed
/// at either stop, and it comes without waiting for the policy's lock. The case owns its runtime
/// and daemon, and the renewal reports through a channel with a failure bound, so a renewal that
/// is stuck fails the case where it waits.
#[test]
fn a_reader_sees_the_old_standing_or_the_new_one_while_the_host_lease_is_renewed() {
    let (continuous, wall, clocks) = manual_clocks();
    let mut leased = None;
    let rig = Rig::new(async {
        let temp = kr_ipc::testing::TempHost::create();
        let host = Leased::start(&temp, continuous, wall, clocks).await;
        let controller = Arc::clone(&host.controller);
        leased = Some(host);
        (temp, controller)
    });
    let host = Arc::new(leased.expect("the host started"));
    host.controller
        .update_policy(|policy| policy.set_exclusively_managed(true))
        .expect("exclusive management is set");
    host.present();
    host.pass(Duration::from_secs(60));
    let issued = host.wall.load(Ordering::SeqCst);
    let lease = host.organisation.lease(
        &host.account,
        *host.key.public(),
        issued,
        &[kr_protocol::rights::ActionRight::SessionView],
    );

    let (built_tx, built) = mpsc::channel::<()>();
    let (swap_tx, swapping) = mpsc::channel::<()>();
    let (swapped_tx, swapped) = mpsc::channel::<()>();
    let (finish_tx, finishing) = mpsc::channel::<()>();
    let (renewed_tx, renewed) = mpsc::channel();
    {
        let host = Arc::clone(&host);
        std::thread::spawn(move || {
            // The stops are this thread's own, and each fires once.
            crate::grants::policy::publishing::stop_before_the_swap(move || {
                let _ = built_tx.send(());
                let _ = swapping.recv_timeout(BOUND);
            });
            crate::grants::policy::publishing::stop_after_the_swap(move || {
                let _ = swapped_tx.send(());
                let _ = finishing.recv_timeout(BOUND);
            });
            let _ = renewed_tx.send(host.controller.present_membership_lease(
                host.controller.local_owner_device(),
                host.key.public(),
                &lease,
                None,
                None,
            ));
        });
    }
    let read = |when: &str| {
        let (answer_tx, answer) = mpsc::channel();
        let controller = Arc::clone(&host.controller);
        std::thread::spawn(move || {
            let _ = answer_tx.send(controller.local_owner_is_closed());
        });
        answer.recv_timeout(BOUND).unwrap_or_else(|_| {
            panic!("a reader waited for the policy's lock {when}, which the renewal holds")
        })
    };

    built
        .recv_timeout(BOUND)
        .expect("the renewal built its snapshot");
    assert!(
        !read("before the lease's cell is swapped"),
        "the owner is served under the policy before the renewal"
    );
    swap_tx.send(()).expect("the renewal goes on");
    swapped
        .recv_timeout(BOUND)
        .expect("the renewal swapped its snapshot in");
    assert!(
        !read("after the lease's cell is swapped, before the policy is in force"),
        "the owner is served under either policy"
    );
    finish_tx.send(()).expect("the renewal goes on");
    renewed
        .recv_timeout(BOUND)
        .expect("the renewal ended inside its bound")
        .expect("the renewal is written down")
        .expect("the lease installs");
    assert!(!host.controller.local_owner_is_closed());
    finish(rig);
}

/// KR-REQ-24.15: the standing is read on the continuous clock first and the wall clock after it,
/// as the locked answer is. The wall clock's reading moves the continuous clock past the lease's
/// continuous end, once, on the case's own thread, with the wall reading itself below the lease's
/// UTC end. Read in the order the documentation fixes, the lease is live, and the owner is served;
/// read the other way round, the continuous clock would already be past its end.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_local_owner_standing_reads_the_continuous_clock_before_the_wall_clock() {
    let temp = kr_ipc::testing::TempHost::create();
    let (continuous, wall, clocks) = manual_clocks();
    let case_thread = std::thread::current().id();
    let armed = Arc::new(AtomicBool::new(false));
    let moved = Arc::new(Mutex::new(0_usize));
    let clocks = Clocks {
        wall: {
            let (armed, moved, continuous, wall) = (
                Arc::clone(&armed),
                Arc::clone(&moved),
                continuous.clone(),
                Arc::clone(&wall),
            );
            WallClock::from_fn(move || {
                // Only a reading on the case's own thread, once and after the lease is set up, moves
                // the continuous clock: a task of the daemon reading the wall clock first must not.
                if std::thread::current().id() == case_thread && armed.swap(false, Ordering::SeqCst)
                {
                    *moved.lock().expect("the count") += 1;
                    continuous.advance(Duration::from_millis(MEMBERSHIP_LEASE_MAX_LIFETIME_MS));
                }
                wall.load(Ordering::SeqCst)
            })
        },
        ..clocks
    };
    let host = Leased::start(&temp, continuous, wall, clocks).await;
    host.controller
        .update_policy(|policy| policy.set_exclusively_managed(true))
        .expect("exclusive management is set");
    let ends = host.present();

    armed.store(true, Ordering::SeqCst);
    assert!(
        !host.controller.local_owner_is_closed(),
        "the lease is live at the continuous reading taken before the wall clock moved it"
    );
    assert_eq!(
        *moved.lock().expect("the count"),
        1,
        "the wall clock was read once"
    );
    assert!(
        host.controller.clock.now() >= ends.continuous,
        "and the continuous clock is past the lease's end afterwards"
    );
    assert!(
        host.controller.local_owner_is_closed(),
        "a reading after that finds the lease ended"
    );
}
