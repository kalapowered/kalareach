//! A session whose output spool meets a disk with no room left.
//!
//! `/dev/full` answers every write with ENOSPC, the error a full filesystem gives, so a segment of
//! the spool that is a link to it takes the first write the spool makes and refuses it the way a
//! full disk would. The spool opens a segment with `create` and `append` and follows a link; a
//! segment already in the directory is adopted as it lies. These cases run a real shell in a real
//! pseudo-terminal, over that spool, and read what the session says of its output afterwards.
//!
//! Linux only: `/dev/full` is a Linux device.

#![cfg(target_os = "linux")]

use std::sync::Arc;
use std::time::Duration;

use kr_protocol::attachment::{AttachMode, AttachmentCapability, SessionAttachParams};
use kr_protocol::identity::{DesktopBinding, WorkerProfile};
use kr_protocol::ids::{AttachmentId, ConnectionId, EnvironmentId, SessionEpoch, SessionId};
use kr_protocol::recovery::HistoryGapCause;
use kr_protocol::scalars::{CanonicalSet, Nullable};
use kr_protocol::session::{ClosureReason, Dimensions, DisplayNumber, SessionState, ShellMode};
use kr_worker::runtime::SessionRuntime;
use kr_worker::session::{Session, SessionConfig};

mod common;

use common::{carries, produced, retained};

/// The resident window, which is far smaller than what the shell prints, so that the first lines
/// are held by the spool alone.
const RESIDENT_BYTES: usize = 4 * 1024;

/// The first segment's name: the spool names a segment by the cursor it starts at.
const FIRST_SEGMENT: &str = "00000000000000000000.out";

/// Prints about 22 KiB, a last line, and then reads what it is typed and prints it back.
const BURST: &str = "n=0; while [ $n -lt 400 ]; do \
        printf 'kr-spool-line-%04d xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\\n' $n; \
        n=$((n + 1)); \
    done; \
    printf 'kr-spool-last-line\\n'; \
    exec cat";

/// What a session said of its output after it printed more than its resident window holds.
struct Burst {
    /// The first page of retained output, from the beginning of the session's cursors.
    first: kr_protocol::recovery::HistoryPageResult,
    /// Everything the session serves, page after page.
    served: Vec<u8>,
    /// The session's state after the burst and after the shell was typed to.
    live: SessionState,
}

fn configuration(
    host: &kr_ipc::testing::TempHost,
    session_id: SessionId,
    environment_id: EnvironmentId,
) -> SessionConfig {
    SessionConfig {
        session_id,
        session_epoch: SessionEpoch::V1,
        environment_id,
        display_number: DisplayNumber::new(1),
        shell: kr_worker::testing::posix_script(BURST),
        shell_mode: ShellMode::NativeCompat,
        worker_profile: WorkerProfile::HeadlessUser,
        desktop: DesktopBinding::none(),
        dimensions: Dimensions::new(80, 24),
        journal_path: Some(host.environment().journal_database(session_id)),
        spool_directory: Some(host.environment().session_spool(session_id)),
        worker_endpoint: None,
        send_queue_bytes: 8 * 1024 * 1024,
        resident_bytes: RESIDENT_BYTES,
        time: kr_worker::action::time::TimeSources::system(),
        launch_profile: kr_protocol::session::LaunchProfile::default(),
    }
}

fn terminal_attachment(session_id: SessionId) -> SessionAttachParams {
    let mut requested = CanonicalSet::new();
    requested.insert(AttachmentCapability::ObserveTerminal);
    requested.insert(AttachmentCapability::Input);
    requested.insert(AttachmentCapability::Geometry);
    SessionAttachParams {
        session_id,
        mode: AttachMode::Terminal,
        claim_geometry: true,
        dimensions: Nullable::some(Dimensions::new(80, 24)),
        terminal_profile_id: Nullable::some("xterm-256color".to_owned()),
        requested,
    }
}

/// Runs the burst in a session whose spool directory holds a link to `/dev/full` as its first
/// segment when `full` is set, and says what the session then serves.
async fn burst(full: bool) -> Burst {
    let host = kr_ipc::testing::TempHost::create();
    let session_id = SessionId::new(kr_ipc::new_uuid());
    let config = configuration(&host, session_id, host.environment_id());
    let spool = config
        .spool_directory
        .clone()
        .expect("the configuration names a spool");
    if full {
        std::fs::create_dir_all(&spool).expect("the spool's directory");
        std::os::unix::fs::symlink("/dev/full", spool.join(FIRST_SEGMENT))
            .expect("a link to the device that has no room");
    }
    let mut session = Session::open(config).expect("opens");
    session.launch().expect("launches");
    let attachment_id = AttachmentId::new(kr_ipc::new_uuid());
    let mut requested = CanonicalSet::new();
    requested.insert(AttachmentCapability::ObserveTerminal);
    requested.insert(AttachmentCapability::Input);
    requested.insert(AttachmentCapability::Geometry);
    session
        .attach(&terminal_attachment(session_id), requested, attachment_id)
        .expect("attaches");
    let runtime =
        SessionRuntime::start(session, Arc::new(kr_ipc::clock::SystemSharedClock)).expect("starts");

    // The shell has printed all of it when its last line is in the output the session serves.
    produced(&runtime, b"kr-spool-last-line\r\n").await;

    // The session goes on: what the shell is typed comes back, through the same output path.
    {
        let mut session = runtime.session();
        session
            .acquire_input(attachment_id, ConnectionId::new(kr_ipc::new_uuid()), None)
            .expect("takes the lease");
        let epoch = session.lease().epoch.get();
        session
            .write_input(
                attachment_id,
                epoch,
                0,
                b"kr-spool-typed-after\n",
                None,
                std::time::Instant::now(),
            )
            .expect("writes");
    }
    runtime.flush_input();
    produced(&runtime, b"kr-spool-typed-after\r\n").await;

    let first = runtime
        .session()
        .history_page(0, 1024 * 1024)
        .expect("the first page reads");
    let served = retained(&runtime);
    let live = runtime.state();

    let runtime = Arc::new(runtime);
    let (_, gate) = runtime.close(ClosureReason::CloseRequested);
    gate.release();
    tokio::time::timeout(Duration::from_secs(120), runtime.wait_closed())
        .await
        .expect("the session closes");
    Burst {
        first,
        served,
        live,
    }
}

/// KR-REQ-27.05, full disks: a spool that meets a disk with no room refuses the write with the
/// filesystem's own error, and the session says so instead of pretending it holds the output.
///
/// The shell prints far more than the resident window holds. With room, the spool holds the first
/// lines and a read from the start of the session is whole, with no gap. With the first segment a
/// link to `/dev/full`, the write is refused: the range the spool did not take reads as a gap whose
/// cause is the spool, the newest lines, which the resident window holds, are served, the output
/// that comes later is served, and the session is live and takes what it is typed.
///
/// What the case shows, and what it does not. The refused write is the first one into a new
/// segment; the spool removes the link when it settles the failure, so the disk is full for that
/// one write and not for the writes after it. The case does not read the reason the spool gives,
/// so a refused open would also pass it; and a write that continues a segment already holding bytes
/// (the usual one) is not the one refused here.
#[tokio::test(flavor = "multi_thread")]
async fn a_spool_that_meets_a_full_disk_says_what_it_could_not_keep_and_the_session_goes_on() {
    let with_room = burst(false).await;
    assert!(
        with_room.first.gap.0.is_none(),
        "a spool with room holds the whole output: {:?}",
        with_room.first.gap
    );
    assert!(
        carries(&with_room.served, b"kr-spool-line-0000"),
        "the control's first line is in what the session serves"
    );

    let full = burst(true).await;
    let gap = full
        .first
        .gap
        .0
        .expect("the output the spool could not take is a gap");
    assert_eq!(gap.from_cursor.get(), 0, "{gap:?}");
    assert_eq!(
        gap.cause,
        Some(HistoryGapCause::SpoolUnavailable),
        "the gap names the spool, which could not write, and no bound that was reached"
    );
    assert!(
        gap.to_cursor.get() > 0,
        "the gap covers what the window no longer holds: {gap:?}"
    );
    assert!(
        !carries(&full.served, b"kr-spool-line-0000"),
        "the first line is neither in the spool nor in the window"
    );
    assert!(
        carries(&full.served, b"kr-spool-last-line"),
        "the newest output is served from the resident window"
    );
    assert!(
        carries(&full.served, b"kr-spool-typed-after"),
        "output that comes after the refusal is served"
    );
    assert_eq!(
        full.live,
        SessionState::Live,
        "a refused write to the spool does not end the session"
    );
}
