//! The closure record this daemon writes for a worker whose own record it cannot have, and what its
//! registration of the session as a writer does with a record that counts entries it does not list.
//!
//! The record is held to the same budget as a worker's. A fence that watched thousands of processes
//! end, or found thousands still running, writes a record a connection can carry, with the worker
//! this host could not confirm ended listed first so that no budget leaves it out.

use std::time::Duration;

use kr_ipc::testing::TempHost;
use kr_protocol::ids::SessionId;
use kr_protocol::session::{
    CLOSURE_BUDGET_BYTES, ClosureOmission, ClosureReason, ClosureRecord, OmissionReason,
    OwnershipCoverage, SurvivingResource,
};

use super::a_migration_and_a_recovery_of_one_session::{closure_of, written_journal};
use super::a_previous_boot_left_to_a_held_recovery::recorded_ended_worker;
use super::close::{Death, worker_left_nothing};
use super::workers::UNACCOUNTED_WORKER;
use crate::archive::{Ended, Fenced};
use crate::service::Controller;
use crate::service::net::tests::daemon;

/// More than a list of a closure record holds, and more than the budget has room for.
const THOUSANDS: usize = 5_000;

/// What a fence that saw `ended` processes end and found `surviving` still running reports.
fn fenced(session_id: SessionId, ended: usize, surviving: usize) -> Fenced {
    Fenced {
        session_id,
        ended: (0..ended)
            .map(|number| Ended {
                identity: kr_ipc::identity::ended_process_identity(4_100_000 + number as u32),
                forced: false,
                root: false,
            })
            .collect(),
        surviving: (0..surviving)
            .map(|number| SurvivingResource {
                kind: "process".to_owned(),
                detail: format!("/{number}"),
            })
            .collect(),
        coverage: OwnershipCoverage::Incomplete,
        earlier_boot: false,
    }
}

/// Registers a session as a writer, as a launch that may have run does.
fn registered_as_a_writer(controller: &Controller, session_id: SessionId) {
    controller
        .project()
        .service()
        .holds()
        .begin_session(session_id, kr_project::holds::SessionPlace::Unknown)
        .expect("nothing holds anything")
        .keep();
}

fn is_a_writer(controller: &Controller, session_id: SessionId) -> bool {
    controller
        .project()
        .service()
        .holds()
        .has_session(session_id)
}

/// The entry that a worker this host could not confirm ended is listed as.
fn the_unaccounted_worker() -> SurvivingResource {
    SurvivingResource {
        kind: UNACCOUNTED_WORKER.to_owned(),
        detail: "this host closed the session without confirming that its worker, 1, ended"
            .to_owned(),
    }
}

/// A closure that lists `surviving`.
fn leaving(session_id: SessionId, surviving: Vec<SurvivingResource>) -> ClosureRecord {
    ClosureRecord {
        surviving,
        ..closure_of(session_id)
    }
}

/// The entry that counts `ended` processes and `other` survivors a record does not list.
fn not_listed(ended: u64, other: u64) -> SurvivingResource {
    ClosureOmission {
        ended,
        other,
        reason: OmissionReason::Budget,
    }
    .entry()
}

/// A fence that found thousands of processes ended and thousands running, over a worker this host
/// could not confirm ended, gives a record held to the budget whose first entry of `surviving` is
/// that worker, and the registry holds the record that was written.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_daemons_own_record_lists_the_unaccounted_worker_first_and_is_held_to_the_budget() {
    let temp = TempHost::create();
    let controller = daemon(&temp).await;
    let session_id = recorded_ended_worker(&controller, &temp).await;
    let identity = kr_ipc::identity::ended_process_identity(4_000_003);

    let record = controller
        .record_final(
            session_id,
            ClosureReason::WorkerCrash,
            &identity,
            &fenced(session_id, THOUSANDS, THOUSANDS),
            Death::Unconfirmed,
        )
        .await
        .expect("the record is written");

    assert_eq!(
        record
            .surviving
            .first()
            .map(|resource| resource.kind.as_str()),
        Some(UNACCOUNTED_WORKER),
        "the worker that was not confirmed ended is the first entry, so no budget leaves it out"
    );
    let omitted = record
        .omitted()
        .expect("the record says what it does not list");
    assert_eq!(omitted.reason, OmissionReason::Budget);
    assert!(
        omitted.other > 0,
        "survivors were left out: {} listed",
        record.survivors().len()
    );
    assert_eq!(
        record.ownership_coverage,
        OwnershipCoverage::Incomplete,
        "a death nobody confirmed claims nothing, whatever the cut"
    );
    let written = kr_cbor::to_canonical_vec_within(&record, &kr_cbor::Limits::DEFAULT)
        .expect("the codec writes the record");
    assert!(
        written.len() + record.device_extra() <= CLOSURE_BUDGET_BYTES + 2_048,
        "the record as a device is shown it fits the budget and the room the entry takes: {} bytes",
        written.len() + record.device_extra()
    );
    assert_eq!(
        controller
            .registry
            .lock()
            .await
            .closure(session_id)
            .expect("the registry answers"),
        Some(record),
        "and it is the one the registry holds"
    );
}

/// A closure whose only unlisted entries are ended processes leaves nothing running: it ends the
/// session's registration as a writer, as a record that lists no survivor always has, and a worker's
/// journal that holds it shows that the session left nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ended_processes_a_record_does_not_list_leave_nothing_to_wait_for() {
    let temp = TempHost::create();
    let controller = daemon(&temp).await;
    let session_id = recorded_ended_worker(&controller, &temp).await;
    registered_as_a_writer(&controller, session_id);
    let identity = kr_ipc::identity::ended_process_identity(4_000_003);

    let record = controller
        .record_final(
            session_id,
            ClosureReason::WorkerCrash,
            &identity,
            &fenced(session_id, THOUSANDS, 0),
            Death::Confirmed,
        )
        .await
        .expect("the record is written");

    let omitted = record.omitted().expect("ended processes were left out");
    assert!(omitted.ended > 0, "{omitted:?}");
    assert_eq!(omitted.other, 0, "no survivor was left out: {omitted:?}");
    assert!(!record.left_something(), "{omitted:?}");
    assert!(
        !is_a_writer(&controller, session_id),
        "the registration ended with the record that left nothing"
    );

    let archive = crate::archive::ArchiveService::new(controller.paths().clone());
    let kept = SessionId::new(kr_ipc::new_uuid());
    written_journal(
        &controller,
        kept,
        Some(&leaving(kept, vec![not_listed(7, 0)])),
    );
    assert!(
        worker_left_nothing(&archive, kept, false),
        "a journal that counts ended processes and lists no survivor shows nothing left"
    );
}

/// A closure that counts survivors it does not list keeps the registration, whether or not it lists
/// any, and a worker's journal that holds it does not show that the session left nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn survivors_a_record_counts_and_does_not_list_keep_the_registration() {
    let temp = TempHost::create();
    let controller = daemon(&temp).await;
    let session_id = recorded_ended_worker(&controller, &temp).await;
    registered_as_a_writer(&controller, session_id);
    let identity = kr_ipc::identity::ended_process_identity(4_000_003);

    let record = controller
        .record_final(
            session_id,
            ClosureReason::WorkerCrash,
            &identity,
            &fenced(session_id, THOUSANDS, THOUSANDS),
            Death::Confirmed,
        )
        .await
        .expect("the record is written");

    assert!(
        record.omitted().is_some_and(|omitted| omitted.other > 0),
        "survivors were left out"
    );
    assert!(
        is_a_writer(&controller, session_id),
        "the session left something running and the registration stands"
    );

    let archive = crate::archive::ArchiveService::new(controller.paths().clone());
    let counted = SessionId::new(kr_ipc::new_uuid());
    written_journal(
        &controller,
        counted,
        Some(&leaving(counted, vec![not_listed(0, 3)])),
    );
    assert!(
        !worker_left_nothing(&archive, counted, false),
        "a journal that counts survivors and lists none does not show nothing left"
    );
}

/// A record that lists only the worker this host could not confirm ended, and counts survivors it
/// does not list, is not ended by a journal that shows nothing: the registration is kept where the
/// same record without the count is ended.
///
/// Both are given the same journal, which lists nothing, and the same ended worker, so the one that
/// ends is the one that the count does not hold; the other has had the same time to end.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_count_of_survivors_keeps_the_registration_a_journal_that_lists_none_would_end() {
    let temp = TempHost::create();
    let controller = daemon(&temp).await;
    let counted = SessionId::new(kr_ipc::new_uuid());
    let control = SessionId::new(kr_ipc::new_uuid());
    let ended = kr_ipc::identity::ended_process_identity(4_000_003);
    for session_id in [counted, control] {
        registered_as_a_writer(&controller, session_id);
        written_journal(&controller, session_id, Some(&leaving(session_id, vec![])));
    }

    controller.end_session_hold(
        &leaving(counted, vec![the_unaccounted_worker(), not_listed(0, 3)]),
        Some(ended.clone()),
    );
    controller.end_session_hold(
        &leaving(control, vec![the_unaccounted_worker()]),
        Some(ended),
    );

    tokio::time::timeout(Duration::from_secs(30), async {
        while is_a_writer(&controller, control) {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the watch ended the registration of the record with nothing counted");
    assert!(
        is_a_writer(&controller, counted),
        "the registration of the record that counts survivors stands"
    );
}
