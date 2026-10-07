//! Every collection that lets go of a record by the wall clock reads one host time contract.
//!
//! The transfer sweep's de-duplication records, the voice coordinator's spent delegations and the
//! attention store's action records are forgotten when the wall clock says they are old, and the
//! wall clock is the one thing section 9 lets a host doubt. A rollback any reader finds withholds
//! all three, and the owner's one retrust frees all three: no collection keeps a private opinion
//! of the clock. Each test runs a real daemon on clocks it moves by hand.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use kr_protocol::ids::{ActionId, DeviceId};
use kr_protocol::scalars::{Digest256, Uuid};
use kr_transfer::service::RetainedOutcome;
use kr_voice::seams::VoiceAuthority as _;

use super::a_sweep_on_a_clock_in_doubt::{aged, kept, swept};
use super::a_voice_grant_on_the_floor::authority;
use crate::service::Controller;
use crate::service::net::tests::{daemon_on, manual_clocks, stopped};

const DAY: u64 = 86_400_000;

/// What the daemon's three collections hold, and the way to ask each of them to forget.
struct Collections<'a> {
    temp: &'a kr_ipc::testing::TempHost,
    controller: &'a Arc<Controller>,
    voice: crate::voice::GrantAuthority,
    device: DeviceId,
    delegation: kr_protocol::voice::VoiceDelegationId,
}

impl<'a> Collections<'a> {
    fn new(temp: &'a kr_ipc::testing::TempHost, controller: &'a Arc<Controller>) -> Self {
        Self {
            temp,
            controller,
            voice: authority(controller),
            device: DeviceId::new(kr_ipc::new_uuid()),
            delegation: kr_protocol::voice::VoiceDelegationId::new("item_one")
                .expect("an identifier"),
        }
    }

    /// Spends the delegation, and says whether this was a first spend.
    fn spend(&self) -> bool {
        self.voice
            .spend_delegation(
                self.device,
                &self.delegation,
                ActionId::new(kr_ipc::new_uuid()),
                self.controller.settled_now_ms(),
            )
            .expect("asked")
    }

    /// Puts one record of each kind into its store, as old as a clock can say.
    ///
    /// The daemon sweeps once as it starts and the attention store forgets on its first pass, so
    /// the records are put in only once the clock is in doubt: a pass that ran at any moment from
    /// then on finds a clock it cannot prove.
    fn age_one_of_each(&self) {
        self.age_the_transfer_record();
        let attention = self.attention_store();
        attention
            .execute(
                "INSERT INTO attention_actions (actor, action_id, method, digest, answer, \
                 recorded_at_ms) VALUES ('a', '1', 'attention.acknowledge', x'00', x'00', 1)",
                [],
            )
            .expect("the attention store takes a record");
    }

    /// Puts one de-duplication record into the transfer store, as old as a clock can say.
    fn age_the_transfer_record(&self) {
        self.controller
            .transfer()
            .service()
            .record_action(
                &kr_transport::listener::device_principal(&DeviceId::new(kr_ipc::new_uuid())),
                Uuid::from_bytes([1; 16]),
                "upload.cancel",
                Digest256::from_bytes([1; 32]),
                &RetainedOutcome::Ok(vec![0xa0]),
            )
            .expect("the service records an action");
        aged(self.temp);
    }

    fn attention_store(&self) -> rusqlite::Connection {
        let store = rusqlite::Connection::open(
            self.temp
                .environment()
                .state_dir()
                .join("attention.sqlite3"),
        )
        .expect("opens the attention store");
        store
            .busy_timeout(Duration::from_secs(10))
            .expect("waits for the daemon's own use");
        store
    }

    fn attention_kept(&self) -> i64 {
        self.attention_store()
            .query_row("SELECT COUNT(*) FROM attention_actions", [], |row| {
                row.get(0)
            })
            .expect("counts the records")
    }

    /// One pass of each collection.
    async fn pass(&self) {
        swept(self.controller).await;
        self.controller
            .attention()
            .tick_and_forget(0)
            .await
            .expect("the attention pass runs");
    }

    /// Whether the collections hold everything they were given, after a pass of each.
    async fn forgot_nothing(&self) -> bool {
        self.pass().await;
        kept(self.temp) == 1 && self.attention_kept() == 1 && !self.spend()
    }
}

/// KR-REQ-09.14, KR-REQ-09.18, KR-REQ-09.19: a wall clock that went backwards withholds every forgetting, and
/// the owner's one retrust frees every forgetting. A record of each kind is as old as the clock can
/// say; the clock goes back by more than the tolerance, and then reads a plausible later moment.
/// The transfer sweep, the voice spend and the attention store's pass each keep their record. After
/// the owner's one establishment each lets go of its record.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_rollback_withholds_every_forgetting_and_one_retrust_frees_them() {
    let temp = kr_ipc::testing::TempHost::create();
    let (_continuous, wall, clocks) = manual_clocks();
    let controller = daemon_on(&temp, clocks).await;
    let collections = Collections::new(&temp, &controller);
    let start = wall.load(Ordering::SeqCst);
    let retention = kr_protocol::limits::DEDUPLICATION_RETENTION.get();
    let trust = || {
        controller
            .lifetimes()
            .clock_trust()
            .sample(controller.devices())
            .expect("the host samples its clock")
    };

    assert!(trust().is_some(), "the clock is proven where it starts");
    assert!(collections.spend(), "a first spend");
    wall.store(start - 60_000, Ordering::SeqCst);
    assert!(trust().is_none(), "the step back is found");
    collections.age_one_of_each();
    wall.store(start + retention + DAY, Ordering::SeqCst);

    assert!(
        collections.forgot_nothing().await,
        "a clock that went backwards and was not established again forgets nothing"
    );

    super::an_owner_establishes_the_clock::the_owner_establishes(&temp, &controller).await;
    collections.pass().await;
    assert_eq!(kept(&temp), 0, "the transfer record is forgotten");
    assert_eq!(
        collections.attention_kept(),
        0,
        "the attention record is forgotten"
    );
    assert!(collections.spend(), "the spent delegation is forgotten");
}

/// KR-REQ-09.18: a step back smaller than the time between two readings is a rollback. The wall
/// clock reads ten seconds behind where sixty seconds of continuous time put it, which a comparison
/// against the last wall reading alone does not see. It is found by whoever asks, it withholds the
/// transfer sweep, and the owner's establishment clears it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_step_back_smaller_than_the_time_between_two_readings_withholds_forgetting() {
    let temp = kr_ipc::testing::TempHost::create();
    let (continuous, wall, clocks) = manual_clocks();
    let controller = daemon_on(&temp, clocks).await;
    let collections = Collections::new(&temp, &controller);
    let start = wall.load(Ordering::SeqCst);
    let retention = kr_protocol::limits::DEDUPLICATION_RETENTION.get();
    let trust = || {
        controller
            .lifetimes()
            .clock_trust()
            .sample(controller.devices())
            .expect("the host samples its clock")
    };

    assert!(trust().is_some(), "the clock is proven where it starts");
    continuous.advance(Duration::from_secs(60));
    wall.store(start + 50_000, Ordering::SeqCst);
    assert!(
        trust().is_none(),
        "the wall clock lags the continuous clock by more than the tolerance"
    );
    collections.age_one_of_each();
    wall.store(start + retention + DAY, Ordering::SeqCst);
    swept(&controller).await;
    assert_eq!(kept(&temp), 1, "the transfer sweep forgets nothing");

    super::an_owner_establishes_the_clock::the_owner_establishes(&temp, &controller).await;
    assert!(trust().is_some(), "an established clock is proven again");
    swept(&controller).await;
    assert_eq!(
        kept(&temp),
        0,
        "the established clock has outlived the retention"
    );
}

/// KR-REQ-09.14, KR-REQ-09.18: a continuous clock that runs fast against the wall clock withholds
/// no forgetting, and a rollback larger than the allowance still withholds all of them. The
/// continuous clock runs fifty parts per million fast for thirty days and an hour, read every hour
/// as the host's decisions read it: the host never doubts its clock, so a spent delegation and a
/// de-duplication record that outlived their retention are forgotten. After thirty days and an hour
/// more, a wall clock six minutes behind where it stood withholds the transfer sweep and the voice
/// spend, which have both outlived their retention, until the owner establishes the clock. (The
/// attention store also needs the platform's time service or the owner's confirmation, which a
/// test on a host with no qualified time service cannot assume.)
///
/// The wall clock is computed from the continuous one, so that one step of the test moves both, and
/// each step is taken while the clock decision's lock is held, so that a reader of the daemon's own
/// that runs meanwhile takes both its readings before the step or both after it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_continuous_clock_that_runs_fast_for_thirty_days_withholds_no_forgetting() {
    use kr_transport::clock::ContinuousClock as _;

    let temp = kr_ipc::testing::TempHost::create();
    let continuous = kr_transport::clock::ManualClock::new();
    let start = kr_ipc::now_ms().get();
    let rolled_back = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let clocks = crate::service::Clocks {
        continuous: Arc::new(continuous.clone()),
        wall: crate::service::WallClock::from_fn({
            let continuous = continuous.clone();
            let rolled_back = Arc::clone(&rolled_back);
            move || {
                let elapsed_ms = u64::try_from(continuous.now().since_anchor().as_millis())
                    .expect("a manual clock stays within u64");
                // True time is 50 parts per million less than the continuous clock says.
                start + elapsed_ms * 1_000_000 / 1_000_050 - rolled_back.load(Ordering::SeqCst)
            }
        }),
    };
    let controller = daemon_on(&temp, clocks).await;
    let collections = Collections::new(&temp, &controller);
    let trust = || {
        controller
            .lifetimes()
            .clock_trust()
            .sample(controller.devices())
            .expect("the host samples its clock")
    };
    let thirty_days_and_an_hour = || {
        for hour in 0..30 * 24 + 1 {
            controller
                .lifetimes()
                .clock_trust()
                .while_no_reader_reads(|| {
                    continuous.advance(Duration::from_millis(3_600_000 + 180));
                });
            assert!(trust().is_some(), "hour {hour}: the clock is still proven");
        }
    };

    assert!(trust().is_some(), "the clock is proven where it starts");
    assert!(collections.spend(), "a first spend");
    thirty_days_and_an_hour();
    collections.age_the_transfer_record();
    swept(&controller).await;
    assert_eq!(
        kept(&temp),
        0,
        "the sweep forgets what outlived its retention"
    );
    assert!(collections.spend(), "the spent delegation is forgotten");

    thirty_days_and_an_hour();
    rolled_back.store(360_000, Ordering::SeqCst);
    assert!(trust().is_none(), "six minutes back is a rollback");
    collections.age_the_transfer_record();
    swept(&controller).await;
    assert_eq!(kept(&temp), 1, "the transfer sweep forgets nothing");
    assert!(
        !collections.spend(),
        "the spend has outlived its retention and is kept"
    );

    super::an_owner_establishes_the_clock::the_owner_establishes(&temp, &controller).await;
    swept(&controller).await;
    assert_eq!(kept(&temp), 0, "the established clock frees the sweep");
    assert!(collections.spend(), "and the voice spend");
}

/// The record an earlier build's attention store kept of its clock, as that build wrote it: a
/// store that was trusted and then found the wall clock going backwards.
const EARLIER_BUILD_AFTER_A_ROLLBACK: &[u8] =
    include_bytes!("../../tests/fixtures/earlier-attention-clock/rolled_back.cbor");

/// KR-REQ-09.18: a distrust the attention store recorded before the host held one record of the
/// clock is not lost by the change. A daemon started over the earlier file distrusts its clock,
/// withholds the transfer sweep and ends only when the owner establishes the clock again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_distrust_recorded_by_the_attention_store_is_carried_forward() {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    std::fs::create_dir_all(environment.state_dir()).expect("the state directory");
    let file = environment.state_dir().join("attention-time.cbor");
    std::fs::write(&file, EARLIER_BUILD_AFTER_A_ROLLBACK).expect("the earlier build's record");
    let (_continuous, wall, clocks) = manual_clocks();
    let controller = daemon_on(&temp, clocks).await;
    let collections = Collections::new(&temp, &controller);
    let retention = kr_protocol::limits::DEDUPLICATION_RETENTION.get();
    let trust = || {
        controller
            .lifetimes()
            .clock_trust()
            .sample(controller.devices())
            .expect("the host samples its clock")
    };

    assert!(
        trust().is_none(),
        "the clock the earlier build had found going backwards is not trusted"
    );
    assert!(!file.exists(), "the earlier file is taken in and removed");
    collections.age_one_of_each();
    wall.store(
        wall.load(Ordering::SeqCst) + retention + DAY,
        Ordering::SeqCst,
    );
    swept(&controller).await;
    assert_eq!(kept(&temp), 1, "the transfer sweep forgets nothing");

    super::an_owner_establishes_the_clock::the_owner_establishes(&temp, &controller).await;
    swept(&controller).await;
    assert_eq!(
        kept(&temp),
        0,
        "the established clock has outlived the retention"
    );
}

/// The record an earlier build's attention store kept of a clock it never trusted: one whose first
/// reading of the platform's time service did not qualify, so nothing says whether the clock
/// itself ever went backwards.
const EARLIER_BUILD_THAT_NEVER_TRUSTED: &[u8] =
    include_bytes!("../../tests/fixtures/earlier-attention-clock/never_trusted.cbor");

/// KR-REQ-09.14, KR-REQ-09.19: a clock an earlier build never trusted holds every forgetting and
/// quiet hours, and holds no decision about a grant, until the owner establishes it. A daemon
/// started over that file keeps the transfer record, the voice spend and the attention record that
/// have outlived their retention, withholds quiet hours, and goes on deciding an expiring grant,
/// the host's reading of its clock being proven all the while: the file cannot say whether only the
/// platform's time service failed. The owner's establishment frees the three and quiet hours.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_clock_an_earlier_build_never_trusted_holds_every_forgetting_until_the_owner_says_so() {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    std::fs::create_dir_all(environment.state_dir()).expect("the state directory");
    std::fs::write(
        environment.state_dir().join("attention-time.cbor"),
        EARLIER_BUILD_THAT_NEVER_TRUSTED,
    )
    .expect("the earlier build's record");
    let (_continuous, wall, clocks) = manual_clocks();
    let controller = daemon_on(&temp, clocks).await;
    let collections = Collections::new(&temp, &controller);
    let retention = kr_protocol::limits::DEDUPLICATION_RETENTION.get();
    let device = super::an_owner_establishes_the_clock::expiring_device(
        &controller,
        wall.load(Ordering::SeqCst) + 2 * retention,
    );

    assert!(collections.spend(), "a first spend");
    collections.age_one_of_each();
    wall.store(
        wall.load(Ordering::SeqCst) + retention + DAY,
        Ordering::SeqCst,
    );
    assert!(
        super::an_owner_establishes_the_clock::proven(&controller),
        "the host does not doubt its wall clock: only what forgets by it is held"
    );
    assert!(
        super::an_owner_establishes_the_clock::decides(&controller, &device),
        "a grant that expires is decided all the same"
    );
    assert!(
        !controller.attention().quiet_hours_provable(),
        "quiet hours are not enforced on a clock the host holds"
    );
    assert!(
        collections.forgot_nothing().await,
        "a clock an earlier build never trusted forgets nothing"
    );

    super::an_owner_establishes_the_clock::the_owner_establishes(&temp, &controller).await;
    assert!(
        controller.attention().quiet_hours_provable(),
        "the owner's word frees quiet hours"
    );
    collections.pass().await;
    assert_eq!(kept(&temp), 0, "the transfer record is forgotten");
    assert_eq!(
        collections.attention_kept(),
        0,
        "the attention record is forgotten"
    );
    assert!(collections.spend(), "the spent delegation is forgotten");
}

/// KR-REQ-09.19: the platform evidence hold withholds attention and nothing else, and only the
/// owner lifts it. It is set when the platform's time service is found unqualified while the owner
/// has not confirmed the clock; here it is recorded before the daemon starts. The transfer sweep is
/// not held by it and the attention store's forgetting is, whatever the adapter reads; the owner's
/// establishment confirms the clock, and attention forgets again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_platform_evidence_hold_withholds_attention_until_the_owner_confirms_the_clock() {
    let temp = kr_ipc::testing::TempHost::create();
    let (_continuous, wall, clocks) = manual_clocks();
    let controller = daemon_on(&temp, clocks.clone()).await;
    stopped(controller).await;
    rusqlite::Connection::open(temp.environment().registry_database())
        .expect("opens the registry")
        .execute(
            "INSERT INTO network_clock (id, observed_ms, evidence_hold_at_ms) VALUES (0, ?1, ?1)
             ON CONFLICT (id) DO UPDATE SET evidence_hold_at_ms = ?1",
            [i64::try_from(wall.load(Ordering::SeqCst)).expect("a time")],
        )
        .expect("the evidence hold is recorded");
    let controller = daemon_on(&temp, clocks).await;
    let collections = Collections::new(&temp, &controller);
    let retention = kr_protocol::limits::DEDUPLICATION_RETENTION.get();
    let watched = |qualified: bool| {
        controller
            .lifetimes()
            .clock_trust()
            .watch(controller.devices(), qualified)
            .expect("the host watches its clock")
            .proven
    };

    assert!(
        !watched(true),
        "a qualified reading of the platform's time service does not lift the hold"
    );
    assert!(
        !controller.attention().quiet_hours_provable(),
        "quiet hours are not enforced under the hold"
    );
    collections.age_one_of_each();
    wall.store(
        wall.load(Ordering::SeqCst) + retention + DAY,
        Ordering::SeqCst,
    );
    collections.pass().await;
    assert_eq!(kept(&temp), 0, "the transfer sweep is not held by it");
    assert_eq!(
        collections.attention_kept(),
        1,
        "the attention store forgets nothing"
    );

    super::an_owner_establishes_the_clock::the_owner_establishes(&temp, &controller).await;
    assert!(
        watched(false),
        "the owner's confirmation proves the clock without the platform's word"
    );
    assert!(
        controller.attention().quiet_hours_provable(),
        "and quiet hours are enforced again"
    );
    collections.pass().await;
    assert_eq!(
        collections.attention_kept(),
        0,
        "the attention store forgets again"
    );
}
