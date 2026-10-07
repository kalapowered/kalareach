//! The transfer service's de-duplication records, forgotten on a clock this host can prove.
//!
//! Every collection of this host that lets go of a record by the wall clock passes one check
//! first: the clock has not gone backwards without an owner establishing it again, and this boot's
//! clock continuity is not lost. This is the transfer sweep, run by a real daemon on a clock the
//! test moves by hand.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use kr_protocol::ids::DeviceId;
use kr_protocol::scalars::{Digest256, Uuid};
use kr_transfer::service::RetainedOutcome;

use crate::service::Controller;
use crate::service::net::tests::{daemon_on, manual_clocks};

/// How many de-duplication records the transfer service holds.
pub(super) fn kept(temp: &kr_ipc::testing::TempHost) -> i64 {
    let store = rusqlite::Connection::open(kr_transfer::staging::StagingArea::store_path(
        &temp.environment(),
    ))
    .expect("opens the transfer store");
    store
        .query_row("SELECT COUNT(*) FROM actions", [], |row| row.get(0))
        .expect("counts the records")
}

/// Makes every record the service holds as old as the clock can say.
pub(super) fn aged(temp: &kr_ipc::testing::TempHost) {
    let store = rusqlite::Connection::open(kr_transfer::staging::StagingArea::store_path(
        &temp.environment(),
    ))
    .expect("opens the transfer store");
    store
        .busy_timeout(std::time::Duration::from_secs(10))
        .expect("waits for the daemon's own use");
    store
        .execute("UPDATE actions SET recorded_at_ms = 1", [])
        .expect("ages the record");
}

pub(super) async fn swept(controller: &Arc<Controller>) {
    controller
        .transfer()
        .sweep(&Arc::downgrade(controller))
        .await
        .expect("the sweep runs");
}

/// KR-REQ-09.14: a record that has outlived its retention is forgotten only on a clock this host
/// can prove. While the wall clock has gone backwards and an owner has not established it again,
/// the sweep forgets nothing, and a record stamped while the clock was wrong stays a record. The
/// control is the same sweep once the owner has established the clock.
///
/// The daemon sweeps once as it starts, so the clock is put in doubt before the record exists: a
/// sweep that ran at any moment from then on finds a clock it cannot prove.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_de_duplication_record_is_forgotten_only_on_a_clock_this_host_can_prove() {
    let temp = kr_ipc::testing::TempHost::create();
    let (_continuous, wall, clocks) = manual_clocks();
    let controller = daemon_on(&temp, clocks).await;
    let start = wall.load(Ordering::SeqCst);
    let trust = || {
        controller
            .lifetimes()
            .clock_trust()
            .sample(controller.devices())
            .expect("the host samples its clock")
    };
    // The mark this host measures a step back against is where the clock is now, and then the
    // clock goes back by more than the tolerance.
    assert!(trust().is_some(), "the clock is proven where it starts");
    wall.store(start - 60_000, Ordering::SeqCst);
    assert!(trust().is_none(), "the step back is found");

    controller
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
    aged(&temp);

    swept(&controller).await;
    assert_eq!(
        kept(&temp),
        1,
        "a clock that went backwards and was not established again forgets nothing"
    );

    controller
        .lifetimes()
        .clock_trust()
        .establish(controller.devices())
        .expect("the owner establishes the clock");
    swept(&controller).await;
    assert_eq!(
        kept(&temp),
        0,
        "an established clock has outlived the retention"
    );
}

/// KR-REQ-09.14: a reading taken before the owner corrected a wrong clock never reaches a record
/// stamped after the correction. The clock is put in doubt first, so that no sweep can run
/// meanwhile, and then the wall clock reads a late moment, the floor is written down at it, and
/// the sweep takes its reading and stops at the clock question. The wall clock is wound back and
/// the owner establishes it; a record is stamped; the sweep goes on. The host's answer is yes, the
/// sweep counts from the earlier of its two readings, and the record stamped after the correction
/// is kept while the old one is forgotten.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reading_from_before_the_clock_was_corrected_forgets_nothing_stamped_after_it() {
    let temp = kr_ipc::testing::TempHost::create();
    let (_continuous, wall, clocks) = manual_clocks();
    let controller = daemon_on(&temp, clocks).await;
    let start = wall.load(Ordering::SeqCst);
    let late = start + kr_protocol::limits::DEDUPLICATION_RETENTION.get() + 86_400_000;
    let trust = || {
        controller
            .lifetimes()
            .clock_trust()
            .sample(controller.devices())
            .expect("the host samples its clock")
    };

    // The clock is put in doubt: the host has seen the wall clock at a late moment and then far
    // behind it, and an owner has not established it again. No sweep forgets anything now.
    wall.store(late, Ordering::SeqCst);
    assert!(trust().is_some(), "a forward step is accepted");
    wall.store(start, Ordering::SeqCst);
    assert!(trust().is_none(), "the step back is found");
    wall.store(late, Ordering::SeqCst);
    controller.settled_now_ms();

    let service = Arc::clone(controller.transfer().service());
    let actor = kr_transport::listener::device_principal(&DeviceId::new(kr_ipc::new_uuid()));
    let record = |byte: u8| {
        service
            .record_action(
                &actor,
                Uuid::from_bytes([byte; 16]),
                "upload.cancel",
                Digest256::from_bytes([byte; 32]),
                &RetainedOutcome::Ok(vec![0xa0]),
            )
            .expect("the service records an action");
    };
    record(1);
    aged(&temp);
    let (arrived, go, sweep) = controller
        .transfer()
        .sweep_paused_at_the_clock(&Arc::downgrade(&controller));
    let sweep = tokio::spawn(sweep);
    arrived.await.expect("the sweep reached the clock question");

    // The owner corrects the clock and establishes it, and a record is stamped.
    wall.store(start, Ordering::SeqCst);
    controller
        .lifetimes()
        .clock_trust()
        .establish(controller.devices())
        .expect("the owner establishes the clock");
    record(2);
    go.send(()).expect("the sweep goes on");
    sweep
        .await
        .expect("the sweep ends")
        .expect("the sweep runs");

    assert_eq!(
        kept(&temp),
        1,
        "the record stamped after the correction is kept, and the old one is forgotten"
    );
}
