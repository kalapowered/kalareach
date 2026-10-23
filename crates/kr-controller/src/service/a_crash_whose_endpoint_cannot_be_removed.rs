//! A worker the kernel confirms has ended, whose published endpoint cannot be removed.
//!
//! Recovery of a session's stores is refused while the endpoint its worker published is still
//! there, but the session is not left open for it: it has ended, and the closure says so. What it
//! says is what the host did: it looked for nothing the session owned, stopped nothing, and read
//! the worker's journal for no closure of its own.

use std::os::unix::fs::PermissionsExt as _;

use kr_protocol::scalars::Nullable;
use kr_protocol::session::{ClosureReason, OwnershipCoverage};

use super::a_previous_boot_left_to_a_held_recovery::recorded_ended_worker;
use crate::service::Controller;
use crate::service::net::tests::{daemon, setup, started, stopped};

/// KR-REQ-24.18: a session whose worker is confirmed gone is closed when the descriptor it
/// published cannot be removed, as a crash. The closure records the worker's end and lists among
/// what the host could not account for that it looked for nothing the session owned, so the
/// session stays registered as a writer; the worker's own journal, which holds a closure of its
/// own here, is not read to find another. Without the closure the session stays open for as long
/// as the file stays, and every look at it finds the same refusal.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_crashed_session_whose_descriptor_cannot_be_removed_is_closed_all_the_same() {
    let temp = kr_ipc::testing::TempHost::create();
    let controller = daemon(&temp).await;
    let session_id = recorded_ended_worker(&controller, &temp).await;
    let environment = temp.environment();
    // A journal that holds a closure its worker wrote for itself.
    let journal_path = environment.journal_database(session_id);
    std::fs::create_dir_all(journal_path.parent().expect("a directory")).expect("the directory");
    {
        let mut journal = kr_worker::journal::Journal::open(&journal_path).expect("opens");
        journal
            .record_closure(&kr_protocol::session::ClosureRecord {
                session_id,
                session_epoch: kr_protocol::ids::SessionEpoch::V1,
                reason: ClosureReason::CloseRequested,
                root_exit_code: Nullable::null(),
                root_signal: Nullable::null(),
                terminated: Vec::new(),
                surviving: Vec::new(),
                ownership_coverage: OwnershipCoverage::Complete,
                durability: kr_protocol::session::Durability::Durable,
                closed_at_ms: kr_ipc::now_ms(),
            })
            .expect("the worker's own closure");
    }
    controller
        .project()
        .service()
        .holds()
        .adopt_session(session_id, kr_project::holds::SessionPlace::Unknown);
    let descriptor = environment.descriptor_file(session_id);
    let directory = descriptor.parent().expect("a directory").to_path_buf();
    std::fs::create_dir_all(&directory).expect("the directory is made");
    std::fs::write(&descriptor, b"a descriptor").expect("the descriptor is written");
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o500))
        .expect("the directory is made unwritable");

    let closed = controller.reconcile(session_id).await;
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
        .expect("the permissions are put back");

    let closure = closed
        .expect("the registry answers")
        .expect("the session is closed all the same");
    assert_eq!(
        closure.reason,
        ClosureReason::WorkerCrash,
        "the worker's own record was not opened"
    );
    assert_eq!(closure.ownership_coverage, OwnershipCoverage::Incomplete);
    let ended = kr_ipc::identity::ended_process_identity(4_000_003);
    assert!(
        closure
            .terminated
            .iter()
            .any(|process| process.identity == ended
                && process.name == Nullable::some("the session's worker".to_owned())),
        "the worker's end, which the kernel confirmed, is in the record: {closure:?}"
    );
    assert!(
        closure.surviving.iter().any(|left| left
            .detail
            .contains("was not looked for and was not stopped")),
        "what the host did not do is listed: {closure:?}"
    );
    assert!(
        controller
            .project()
            .service()
            .holds()
            .has_session(session_id),
        "a session whose owned processes were not accounted for is still a writer"
    );
    assert!(
        descriptor.exists(),
        "control: the descriptor is the file that could not be removed"
    );
}

/// KR-REQ-24.18: a start that finds a crashed session it cannot unpublish registers it as a
/// writer. The start closes it before it registers the sessions it found alive, and a closed
/// session is not one of those, so the closure registers the session itself.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_start_that_closes_a_session_it_cannot_unpublish_holds_its_repository() {
    let temp = kr_ipc::testing::TempHost::create();
    let controller = daemon(&temp).await;
    let session_id = recorded_ended_worker(&controller, &temp).await;
    stopped(controller).await;
    let environment = temp.environment();
    let descriptor = environment.descriptor_file(session_id);
    let directory = descriptor.parent().expect("a directory").to_path_buf();
    std::fs::create_dir_all(&directory).expect("the directory is made");
    std::fs::write(&descriptor, b"a descriptor").expect("the descriptor is written");
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o500))
        .expect("the directory is made unwritable");

    let controller = started(|| {
        Controller::start(setup(
            &temp,
            kr_ipc::identity::boot_identity().expect("a boot identity"),
        ))
    })
    .await;
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
        .expect("the permissions are put back");

    let closure = controller
        .registry
        .lock()
        .await
        .closure(session_id)
        .expect("the registry answers")
        .expect("the start closed the session");
    assert!(
        closure.surviving.iter().any(|left| left
            .detail
            .contains("was not looked for and was not stopped")),
        "{closure:?}"
    );
    assert!(
        controller
            .project()
            .service()
            .holds()
            .has_session(session_id),
        "a session closed at the start with its owned processes unaccounted for is still a writer"
    );
}
