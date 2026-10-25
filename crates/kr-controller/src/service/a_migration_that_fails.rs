//! A closed session whose journal is of an earlier schema, and which cannot be brought forward
//! because the migration itself fails.
//!
//! A journal that is held back for now waits for a worker or another recovery, and one that cannot
//! be read is finished with gaps. A migration that was made and failed is neither, and the
//! attention store tries it again. These cases run a real daemon over such a session.

use kr_ipc::testing::TempHost;
use kr_protocol::ids::SessionId;

use super::a_migration_and_a_recovery_of_one_session::{
    after_the_first_pass, closure_of, put_back_to_an_earlier_schema, version_of, written_journal,
};
use crate::attention::ClosedJournal;
use crate::service::net::tests::daemon;

/// A file that takes no write for as long as this lives, and is given its owner's access back.
struct ReadOnly(std::path::PathBuf);

impl ReadOnly {
    fn new(path: std::path::PathBuf) -> Self {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400))
            .expect("the file is made read-only");
        Self(path)
    }
}

impl Drop for ReadOnly {
    fn drop(&mut self) {
        use std::os::unix::fs::PermissionsExt as _;
        // The files beside it take its mode when a look that cannot write opens it.
        for suffix in ["", "-wal", "-shm"] {
            let mut name = self.0.as_os_str().to_owned();
            name.push(suffix);
            let _ = std::fs::set_permissions(
                std::path::PathBuf::from(name),
                std::fs::Permissions::from_mode(0o600),
            );
        }
    }
}

/// KR-REQ-24.18: the attention store is told apart a journal whose migration was made and failed
/// from one that cannot be read, which it finishes with gaps that nothing repairs. It keeps the
/// session closing and tries again; the migration is made by the next try once nothing stops it, and
/// the journal is then read to its end.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_journal_whose_migration_fails_is_not_taken_for_one_that_cannot_be_read() {
    let temp = TempHost::create();
    let controller = daemon(&temp).await;
    after_the_first_pass(&controller).await;
    let session_id = SessionId::new(kr_ipc::new_uuid());
    written_journal(&controller, session_id, None);
    put_back_to_an_earlier_schema(&controller, session_id);
    // Recorded in the registry alone, with no worker and no launch to wait for, so that nothing
    // holds the migration back and no closure tail makes it on a task of its own.
    controller
        .registry
        .lock()
        .await
        .record_closure(&closure_of(session_id))
        .expect("the closure is recorded");
    let path = controller.paths().journal_database(session_id);
    let stopped = ReadOnly::new(path.clone());
    assert!(
        kr_worker::journal::Journal::open(&path).is_err(),
        "an account that ignores file permissions cannot make this migration fail"
    );

    let reach = controller.attention_reach();
    assert!(
        matches!(reach.closed_journal(session_id), ClosedJournal::Failing),
        "a migration that was made and failed is not an unreadable journal"
    );
    assert_eq!(version_of(&controller, session_id), 3);

    // The attention store closes the session through the daemon's reach. It keeps it closing, to
    // try again, and does not finish it with gaps that nothing repairs.
    let attention = controller.attention();
    attention.session_closed(&*reach, session_id).await;
    assert!(
        !attention.finished_with(session_id),
        "the store tries the journal again and does not finish the session over it"
    );

    drop(stopped);
    // The store's next try, which its maintenance loop makes once the wait has passed.
    attention.session_closed(&*reach, session_id).await;
    assert!(
        attention.finished_with(session_id),
        "once nothing stops it the migration is made and the session is read to its end"
    );
    assert_eq!(
        version_of(&controller, session_id),
        kr_worker::persistence::migration::CURRENT
    );
}
