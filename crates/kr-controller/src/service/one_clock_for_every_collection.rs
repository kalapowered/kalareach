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
use crate::service::net::tests::{daemon_on, manual_clocks};

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
    fn age_one_of_each(&self) {
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
        let attention = self.attention_store();
        attention
            .execute(
                "INSERT INTO attention_actions (actor, action_id, method, digest, answer, \
                 recorded_at_ms) VALUES ('a', '1', 'attention.acknowledge', x'00', x'00', 1)",
                [],
            )
            .expect("the attention store takes a record");
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
/// one `establish` each lets go of its record.
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
    collections.age_one_of_each();
    wall.store(start - 60_000, Ordering::SeqCst);
    assert!(trust().is_none(), "the step back is found");
    wall.store(start + retention + DAY, Ordering::SeqCst);

    assert!(
        collections.forgot_nothing().await,
        "a clock that went backwards and was not established again forgets nothing"
    );

    controller
        .lifetimes()
        .clock_trust()
        .establish(controller.devices())
        .expect("the owner establishes the clock");
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
/// transfer sweep, and one `establish` clears it.
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
    collections.age_one_of_each();
    continuous.advance(Duration::from_secs(60));
    wall.store(start + 50_000, Ordering::SeqCst);
    assert!(
        trust().is_none(),
        "the wall clock lags the continuous clock by more than the tolerance"
    );
    wall.store(start + retention + DAY, Ordering::SeqCst);
    swept(&controller).await;
    assert_eq!(kept(&temp), 1, "the transfer sweep forgets nothing");

    controller
        .lifetimes()
        .clock_trust()
        .establish(controller.devices())
        .expect("the owner establishes the clock");
    assert!(trust().is_some(), "an established clock is proven again");
    swept(&controller).await;
    assert_eq!(
        kept(&temp),
        0,
        "the established clock has outlived the retention"
    );
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

    controller
        .lifetimes()
        .clock_trust()
        .establish(controller.devices())
        .expect("the owner establishes the clock");
    swept(&controller).await;
    assert_eq!(
        kept(&temp),
        0,
        "the established clock has outlived the retention"
    );
}
