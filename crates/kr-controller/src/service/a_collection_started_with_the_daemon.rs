//! What the daemon collects of the sessions that have closed, begun by the daemon itself.
//!
//! A session that has closed has no worker and so no maintenance tick: its output would stay past
//! seven days, its receipts past thirty, and its spool would count against the host's 1 GiB for as
//! long as the files lasted. These cases run a real daemon over an environment that holds such
//! sessions, and look at the files.

use std::time::Duration;

use kr_ipc::testing::TempHost;
use kr_protocol::ids::{ActorId, SessionEpoch, SessionId};
use kr_protocol::scalars::{Nullable, TimestampMs};
use kr_protocol::session::{
    ClosureReason, ClosureRecord, DisplayNumber, Durability, OwnershipCoverage,
};
use kr_worker::history::{OutputHistory, SpoolLayout};
use kr_worker::journal::{Journal, Submission};
use kr_worker::persistence::retention::OutputRetention;

use crate::archive::ArchiveService;
use crate::service::Controller;
use crate::service::net::tests::{daemon, daemon_on, manual_clocks};

const DAY_MS: u64 = 24 * 60 * 60 * 1000;

/// A pass is waited for by what it counts, with a bound so that a daemon that never collects fails
/// the case and does not hang it.
const PASS_BOUND: Duration = Duration::from_secs(60);

fn closure(session_id: SessionId, closed_days_ago: u64) -> ClosureRecord {
    ClosureRecord {
        session_id,
        session_epoch: SessionEpoch::V1,
        reason: ClosureReason::CloseRequested,
        root_exit_code: Nullable::null(),
        root_signal: Nullable::null(),
        terminated: Vec::new(),
        surviving: Vec::new(),
        ownership_coverage: OwnershipCoverage::Incomplete,
        durability: Durability::Durable,
        closed_at_ms: TimestampMs::new(kr_ipc::now_ms().get() - closed_days_ago * DAY_MS),
    }
}

fn submission(byte: u8) -> Submission {
    Submission {
        actor_id: ActorId::new("test:collection").expect("an actor"),
        action_id: kr_worker::journal::action_id_from([byte; 16]),
        method: kr_protocol::method::Method::SessionClose.into(),
        method_version: kr_protocol::method::MethodVersion::V1,
        payload_digest: kr_protocol::scalars::Digest256::from_bytes([byte; 32]),
        subject_digest: kr_protocol::scalars::Digest256::from_bytes([byte; 32]),
        intent: vec![0xa0],
        accepted_deadline_ms: Some(TimestampMs::new(kr_ipc::now_ms().get() + 120_000)),
        now_ms: kr_ipc::now_ms(),
    }
}

/// Makes every file in a session's spool as old as `days`.
fn age_spool(archive: &ArchiveService, session_id: SessionId, days: u64) {
    let when = std::time::SystemTime::now() - Duration::from_millis(days * DAY_MS);
    for entry in std::fs::read_dir(archive.paths().session_spool(session_id)).expect("a spool") {
        let path = entry.expect("an entry").path();
        std::fs::File::options()
            .write(true)
            .open(&path)
            .and_then(|file| file.set_modified(when))
            .expect("ages the file");
    }
}

/// A closed session whose journal holds a receipt `receipt_days` old and one from now, and whose
/// spool holds `bytes` bytes of output `output_days` old, in segments of eight.
fn closed_session(
    archive: &ArchiveService,
    closed_days_ago: u64,
    receipt_days: u64,
    bytes: usize,
    output_days: u64,
) -> SessionId {
    let session_id = SessionId::new(kr_ipc::new_uuid());
    closed_session_as(
        archive,
        session_id,
        closed_days_ago,
        receipt_days,
        bytes,
        output_days,
    );
    session_id
}

/// [`closed_session`] for the session `session_id`.
fn closed_session_as(
    archive: &ArchiveService,
    session_id: SessionId,
    closed_days_ago: u64,
    receipt_days: u64,
    bytes: usize,
    output_days: u64,
) {
    let path = archive.paths().journal_database(session_id);
    std::fs::create_dir_all(path.parent().expect("a parent")).expect("the journal directory");
    {
        let mut journal = Journal::open(&path).expect("a journal");
        journal
            .record_closure(&closure(session_id, closed_days_ago))
            .expect("records the closure");
        journal.accept(&submission(1)).expect("a first receipt");
        journal.accept(&submission(2)).expect("a second one");
    }
    if receipt_days > 0 {
        rusqlite::Connection::open(&path)
            .expect("opens the store")
            .execute(
                "UPDATE receipts SET created_at_ms = ?1, created_boot = 'an-earlier-boot'
                 WHERE action_id = ?2",
                rusqlite::params![
                    i64::try_from(kr_ipc::now_ms().get() - receipt_days * DAY_MS).expect("a time"),
                    kr_worker::journal::action_id_from([1; 16])
                        .get()
                        .as_bytes()
                        .as_slice(),
                ],
            )
            .expect("ages the first receipt");
    }
    spool(archive, session_id, bytes, output_days);
}

fn spool(archive: &ArchiveService, session_id: SessionId, bytes: usize, days: u64) {
    let mut history = OutputHistory::with_spool(
        8,
        archive.paths().session_spool(session_id),
        SpoolLayout::new(8, 1 << 30),
    )
    .expect("a spool");
    history.append(&vec![b'x'; bytes]);
    drop(history);
    age_spool(archive, session_id, days);
}

/// Publishes a descriptor for a worker that is running, as a worker does when it starts.
fn publish_the_worker_of(archive: &ArchiveService, session_id: SessionId) {
    let descriptor = kr_protocol::worker::WorkerDescriptor {
        session_id,
        session_epoch: SessionEpoch::V1,
        environment_id: archive.paths().environment_id(),
        display_number: DisplayNumber::new(1),
        boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
        process_start_identity: kr_ipc::identity::current_process_start_identity()
            .expect("this process"),
        protocol_version: kr_protocol::hello::PROTOCOL_VERSION,
        endpoint: "/tmp/kr-collection-test.sock".to_owned(),
        worker_public_key: kr_protocol::scalars::AuthorisationKey::from_bytes([7; 32]),
        worker_profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
        published_at_ms: kr_ipc::now_ms(),
    };
    kr_ipc::descriptor::publish(archive.paths(), &descriptor).expect("publishes the descriptor");
}

/// Waits until the daemon's collection has ended `passes` passes.
async fn after_passes(controller: &Controller, passes: u64) {
    let mut seen = controller.collection().passes();
    tokio::time::timeout(PASS_BOUND, seen.wait_for(|ended| *ended >= passes))
        .await
        .expect("the daemon's collection ran")
        .expect("the collection is still there");
}

fn receipts(archive: &ArchiveService, session_id: SessionId) -> u64 {
    archive.archive(session_id).expect("reads").receipts
}

fn oldest(archive: &ArchiveService, session_id: SessionId) -> u64 {
    archive
        .archive(session_id)
        .expect("reads")
        .oldest_retained_cursor
}

/// KR-REQ-20.21: a daemon begins collecting what closed sessions retain as it starts, with nobody
/// asking. A session whose output is past seven days and whose first receipt is past thirty has both
/// removed, and says so as gaps and counts; the receipt inside its thirty days stays. A session
/// inside both periods keeps everything.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_daemon_collects_what_closed_sessions_retain_as_it_starts() {
    let temp = TempHost::create();
    let archive = ArchiveService::new(temp.environment());
    let old = closed_session(&archive, 40, 31, 16, 8);
    let young = closed_session(&archive, 1, 0, 16, 1);

    let controller = daemon(&temp).await;
    after_passes(&controller, 1).await;

    assert_eq!(oldest(&archive, old), 16, "the output past seven days went");
    assert_eq!(
        receipts(&archive, old),
        1,
        "and the receipt past thirty days"
    );
    assert_eq!(
        oldest(&archive, young),
        0,
        "a session inside its period keeps its output"
    );
    assert_eq!(receipts(&archive, young), 2, "and its receipts");
}

/// KR-REQ-09.14, KR-REQ-20.21: a clock the host cannot prove removes nothing by age, whatever the
/// files say. The control is the same files once the owner has established the clock.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_clock_the_host_cannot_prove_collects_nothing_by_age_from_a_closed_session() {
    let temp = TempHost::create();
    let (_continuous, wall, clocks) = manual_clocks();
    let controller = daemon_on(&temp, clocks).await;
    after_passes(&controller, 1).await;
    let archive = controller.archive();
    let start = wall.load(std::sync::atomic::Ordering::SeqCst);
    let trust = || {
        controller
            .lifetimes()
            .clock_trust()
            .sample(controller.devices())
            .expect("the host samples its clock")
    };
    assert!(trust().is_some(), "the clock is proven where it starts");
    wall.store(start - 60_000, std::sync::atomic::Ordering::SeqCst);
    assert!(trust().is_none(), "the step back is found");

    let old = closed_session(&archive, 40, 31, 16, 8);
    let blocking = std::sync::Arc::clone(&controller);
    let pass = tokio::task::spawn_blocking(move || {
        blocking.collect_closed_sessions(OutputRetention::DEFAULT, true)
    })
    .await
    .expect("the pass ran");
    assert!(pass.failures.is_empty(), "{pass:?}");
    assert_eq!(oldest(&archive, old), 0, "an unproved clock took no output");
    assert_eq!(receipts(&archive, old), 2, "and no receipt");

    super::an_owner_establishes_the_clock::the_owner_establishes(&temp, &controller).await;
    let blocking = std::sync::Arc::clone(&controller);
    tokio::task::spawn_blocking(move || {
        blocking.collect_closed_sessions(OutputRetention::DEFAULT, true)
    })
    .await
    .expect("the pass ran");
    assert_eq!(
        oldest(&archive, old),
        16,
        "an established clock took the output"
    );
    assert_eq!(receipts(&archive, old), 1);
}

/// KR-REQ-24.18: a session another recovery holds is left to it. The pass says it left one, takes
/// nothing, and takes the session on the next pass once the recovery is done.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_session_a_recovery_holds_is_left_to_it_and_collected_after() {
    let temp = TempHost::create();
    let controller = daemon(&temp).await;
    after_passes(&controller, 1).await;
    let archive = controller.archive();
    let old = closed_session(&archive, 40, 31, 16, 8);
    let ended = kr_ipc::identity::ended_process_identity(1);
    let recovery = archive
        .take_ownership(old, DisplayNumber::new(1), &ended)
        .expect("a recovery holds the session");

    let blocking = std::sync::Arc::clone(&controller);
    let pass = tokio::task::spawn_blocking(move || {
        blocking.collect_closed_sessions(OutputRetention::DEFAULT, true)
    })
    .await
    .expect("the pass ran");
    assert_eq!(pass.held, 1, "{pass:?}");
    assert_eq!(oldest(&archive, old), 0, "nothing was taken from under it");

    drop(recovery);
    let blocking = std::sync::Arc::clone(&controller);
    let pass = tokio::task::spawn_blocking(move || {
        blocking.collect_closed_sessions(OutputRetention::DEFAULT, true)
    })
    .await
    .expect("the pass ran");
    assert_eq!(pass.held, 0, "{pass:?}");
    assert_eq!(oldest(&archive, old), 16);
}

/// KR-REQ-24.18: a worker hands its closure over before it exits, and the closure erases the
/// registry's row of it, so a closed session whose worker's process still runs is left alone: the
/// worker may still write what a collection would open. The reservation names the process the
/// launch ran, and the session is collected once the kernel says that process has ended.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_closed_session_whose_workers_process_still_runs_is_left_alone_until_it_ends() {
    let temp = TempHost::create();
    let controller = daemon(&temp).await;
    after_passes(&controller, 1).await;
    let archive = controller.archive();
    let reservation = {
        let mut registry = controller.registry.lock().await;
        let admission = registry
            .reserve(
                &ActorId::new("local:test").expect("a principal"),
                kr_ipc::new_uuid(),
                kr_protocol::scalars::Digest256::from_bytes([0x5f; 32]),
                &[],
                kr_ipc::now_ms(),
            )
            .expect("reserves");
        registry
            .record_launch(
                admission.reservation.reservation_id,
                &kr_ipc::identity::current_process_start_identity().expect("this process"),
            )
            .expect("records the process the launch ran");
        admission.reservation
    };
    let old = reservation.session_id;
    closed_session_as(&archive, old, 40, 31, 16, 8);
    // The closure is in the registry, which is what erases the worker's row.
    controller
        .retire(&closure(old, 40))
        .await
        .expect("the closure is recorded");
    let pass = |controller: &std::sync::Arc<Controller>| {
        let blocking = std::sync::Arc::clone(controller);
        async move {
            tokio::task::spawn_blocking(move || {
                blocking.collect_closed_sessions(OutputRetention::DEFAULT, true)
            })
            .await
            .expect("the pass ran")
        }
    };
    pass(&controller).await;
    assert_eq!(
        oldest(&archive, old),
        0,
        "a running process's stores are not taken"
    );
    assert_eq!(receipts(&archive, old), 2);

    controller
        .registry
        .lock()
        .await
        .record_launch(
            reservation.reservation_id,
            &kr_ipc::identity::ended_process_identity(4_000_002),
        )
        .expect("records that the process ended");
    pass(&controller).await;
    assert_eq!(oldest(&archive, old), 16, "once it has ended they are");
    assert_eq!(receipts(&archive, old), 1);
}

/// KR-REQ-20.20: the host-wide cap holds with live sessions and closed ones together. The spools of
/// two closed sessions and of a session that is live add up to 120 bytes under a cap of 64. The
/// daemon takes the oldest closed output first, down to the cap; a live session's own pass, from the
/// same reading of the host, then finds nothing over. In the other order the live session gives up
/// its output first and the daemon takes the rest of the excess, and the host is under the cap
/// either way.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_host_wide_cap_holds_with_live_sessions_and_closed_ones_together() {
    let retention = OutputRetention::new(Duration::from_secs(7 * 24 * 60 * 60), 64, 1 << 20);
    let measured = |archive: &ArchiveService| {
        kr_worker::history::retained_bytes_under(&archive.paths().spool_dir())
    };
    for collector_first in [true, false] {
        let temp = TempHost::create();
        let controller = daemon(&temp).await;
        after_passes(&controller, 1).await;
        let archive = controller.archive();
        let oldest_closed = closed_session(&archive, 3, 0, 40, 3);
        let newer_closed = closed_session(&archive, 2, 0, 40, 2);
        let live_session = SessionId::new(kr_ipc::new_uuid());
        let mut live = OutputHistory::with_spool(
            8,
            archive.paths().session_spool(live_session),
            SpoolLayout::new(8, 1 << 30),
        )
        .expect("a live session's spool");
        live.append(&[b'y'; 40]);
        // A live session's worker has published itself: this process stands in for it.
        publish_the_worker_of(&archive, live_session);
        assert_eq!(measured(&archive), 120);

        let spools = archive.paths().spool_dir();
        let live_pass = |live: &mut OutputHistory| {
            live.apply_retention_to_host(&spools, retention, kr_ipc::now_ms(), true)
        };
        let collect = |controller: &std::sync::Arc<Controller>| {
            let blocking = std::sync::Arc::clone(controller);
            async move {
                tokio::task::spawn_blocking(move || {
                    blocking.collect_closed_sessions(retention, false)
                })
                .await
                .expect("the pass ran")
            }
        };
        if collector_first {
            let pass = collect(&controller).await;
            assert!(pass.failures.is_empty(), "{pass:?}");
            assert_eq!(pass.output_bytes, 56, "{pass:?}");
            assert_eq!(
                oldest(&archive, oldest_closed),
                40,
                "the oldest closed output went whole"
            );
            assert_eq!(
                oldest(&archive, newer_closed),
                16,
                "and the newer gave up the rest"
            );
            assert!(
                live_pass(&mut live).is_empty(),
                "the live session finds the host under its cap"
            );
            assert_eq!(live.oldest_retained_cursor(), 0);
        } else {
            let taken = live_pass(&mut live);
            assert!(
                !taken.is_empty(),
                "the live session sees the host over its cap"
            );
            let pass = collect(&controller).await;
            assert!(pass.failures.is_empty(), "{pass:?}");
        }
        assert!(
            measured(&archive) <= 64,
            "the host holds {} bytes, collector first: {collector_first}",
            measured(&archive)
        );
    }
}

/// KR-REQ-20.21, section 14: a file submitted to a closed session follows the session's retention.
/// While the session still holds a receipt, or its closure is inside thirty days, the file is kept.
/// Once nothing the retention governs is left and the closure is thirty-one days old, the sweep may
/// let it go, and only on a clock the host can prove.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_submitted_file_follows_its_sessions_retention_on_a_clock_the_host_can_prove() {
    let temp = TempHost::create();
    let (_continuous, wall, clocks) = manual_clocks();
    let controller = daemon_on(&temp, clocks).await;
    after_passes(&controller, 1).await;
    let archive = controller.archive();
    // Closed thirty-one days ago, with a receipt inside its thirty, and one with nothing at all.
    let holding = closed_session(&archive, 31, 0, 0, 0);
    let spent = {
        let session_id = SessionId::new(kr_ipc::new_uuid());
        let mut journal =
            Journal::open(archive.paths().journal_database(session_id)).expect("a journal");
        journal
            .record_closure(&closure(session_id, 31))
            .expect("records the closure");
        session_id
    };
    let asked: std::collections::BTreeSet<SessionId> = [holding, spent].into_iter().collect();
    let retained = |controller: &std::sync::Arc<Controller>| {
        let blocking = std::sync::Arc::clone(controller);
        let asked = asked.clone();
        async move {
            tokio::task::spawn_blocking(move || blocking.retained_among(&asked))
                .await
                .expect("the question ran")
                .expect("answers")
        }
    };

    let answer = retained(&controller).await;
    assert!(
        answer.contains(&holding),
        "a receipt inside its thirty days keeps it"
    );
    assert!(
        !answer.contains(&spent),
        "nothing is held and the closure is thirty-one days old"
    );

    // The clock is put in doubt: the same question keeps both.
    let start = wall.load(std::sync::atomic::Ordering::SeqCst);
    wall.store(start - 60_000, std::sync::atomic::Ordering::SeqCst);
    assert!(
        controller
            .lifetimes()
            .clock_trust()
            .sample(controller.devices())
            .expect("samples")
            .is_none()
    );
    let answer = retained(&controller).await;
    assert!(
        answer.contains(&holding) && answer.contains(&spent),
        "{answer:?}"
    );
}

/// KR-REQ-20.21: a pass of the collection that waits for a blocking thread keeps nothing of the
/// daemon, and with it the environment's lock, once the daemon's owner has let it go. When its turn
/// comes it finds the daemon gone and does nothing.
///
/// The runtime here has one blocking thread, which the case takes once the daemon's own first pass
/// has ended. A pass is queued as it is asked for, so from then on it waits for that thread.
#[test]
fn a_pass_waiting_to_run_does_not_keep_its_daemon() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(1)
        .enable_all()
        .build()
        .expect("a runtime");
    runtime.block_on(async {
        let temp = TempHost::create();
        let controller = daemon(&temp).await;
        after_passes(&controller, 1).await;

        // The runtime's one blocking thread, taken until the case lets it go.
        let (taken, taking) = tokio::sync::oneshot::channel();
        let (release, held) = std::sync::mpsc::channel::<()>();
        let occupied = tokio::task::spawn_blocking(move || {
            let _ = taken.send(());
            let _ = held.recv();
        });
        taking.await.expect("the blocking thread is taken");

        let daemon = std::sync::Arc::downgrade(&controller);
        let pass = crate::collection::queue_pass(&daemon, true);

        drop(controller);
        let dropped = std::time::Instant::now();
        while daemon.strong_count() > 0 && dropped.elapsed() < Duration::from_secs(5) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(
            daemon.strong_count(),
            0,
            "a pass waiting for its thread keeps nothing of the daemon"
        );

        let _ = release.send(());
        occupied.await.expect("the blocking thread is let go");
        assert!(
            pass.await.expect("the pass ends").is_none(),
            "a pass whose daemon has gone does nothing"
        );
    });
}
