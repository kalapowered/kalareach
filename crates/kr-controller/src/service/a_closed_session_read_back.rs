//! A session that closed, described from the journal its worker left.

use kr_protocol::ids::{SessionEpoch, SessionId};
use kr_protocol::scalars::Nullable;
use kr_protocol::session::{
    ClosureReason, ClosureRecord, DisplayNumber, Durability, OwnershipCoverage, SessionState,
    SessionSummary,
};

/// What a worker wrote of a session while a program held the terminal.
fn written(
    session_id: SessionId,
    environment_id: kr_protocol::ids::EnvironmentId,
) -> SessionSummary {
    SessionSummary {
        session_id,
        session_epoch: SessionEpoch::V1,
        environment_id,
        display_number: DisplayNumber::new(1),
        state: SessionState::Live,
        shell_mode: kr_protocol::session::ShellMode::NativeCompat,
        shell_path: "/bin/sh".to_owned(),
        cwd: "/recovered".to_owned(),
        worker_profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
        desktop: kr_protocol::identity::DesktopBinding::none(),
        created_at_ms: kr_ipc::now_ms(),
        dimensions: kr_protocol::session::Dimensions::new(80, 24),
        attachment_count: kr_protocol::scalars::U64::new(1),
        application_state: Nullable::null(),
        root_process: Nullable::null(),
        closure: Nullable::null(),
        environment_sources: None,
        root: None,
        application: Some("claude".to_owned()),
    }
}

fn closure(session_id: SessionId) -> ClosureRecord {
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
        closed_at_ms: kr_ipc::now_ms(),
    }
}

/// A session that has closed names no application, though the journal its worker
/// left still holds the one it named while a program held the terminal. The rest of what the
/// worker wrote is what a person is shown: the directory the summary names.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_closed_session_read_back_from_its_journal_names_no_application() {
    let temp = kr_ipc::testing::TempHost::create();
    let controller = super::net::tests::daemon(&temp).await;
    let session_id = SessionId::new(kr_ipc::new_uuid());
    let path = controller.paths().journal_database(session_id);
    std::fs::create_dir_all(path.parent().expect("a parent")).expect("the journal directory");
    {
        let mut journal = kr_worker::journal::Journal::open(&path).expect("opens");
        journal
            .record_session(&written(session_id, controller.paths().environment_id()))
            .expect("records the session");
    }

    let closed = controller
        .closed_session(&closure(session_id), DisplayNumber::new(1))
        .await;

    assert_eq!(closed.state, SessionState::Closed);
    assert_eq!(
        closed.cwd, "/recovered",
        "the summary is the one the worker wrote"
    );
    assert_eq!(closed.application, None, "and it names no application");
    drop(controller);
}
