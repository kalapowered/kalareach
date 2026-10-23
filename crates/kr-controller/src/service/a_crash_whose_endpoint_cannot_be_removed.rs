//! A worker the kernel confirms has ended, whose published endpoint cannot be removed.
//!
//! Recovery of a session's stores is refused while the endpoint its worker published is still
//! there, but the session is not left open for it: it has ended, and the closure says so.

use std::os::unix::fs::PermissionsExt as _;

use kr_protocol::scalars::Nullable;
use kr_protocol::session::{ClosureReason, OwnershipCoverage};

use super::a_previous_boot_left_to_a_held_recovery::recorded_ended_worker;
use crate::service::net::tests::daemon;

/// KR-REQ-24.18: a session whose worker is confirmed gone is closed when the descriptor it
/// published cannot be removed, as a crash, saying that this host saw the worker end and accounted
/// for nothing of what the session owned. Without the closure the session stays open for as long as
/// the file stays, and every look at it finds the same refusal.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_crashed_session_whose_descriptor_cannot_be_removed_is_closed_all_the_same() {
    let temp = kr_ipc::testing::TempHost::create();
    let controller = daemon(&temp).await;
    let session_id = recorded_ended_worker(&controller, &temp).await;
    let descriptor = temp.environment().descriptor_file(session_id);
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
    assert_eq!(closure.reason, ClosureReason::WorkerCrash);
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
        descriptor.exists(),
        "control: the descriptor is the file that could not be removed"
    );
}
