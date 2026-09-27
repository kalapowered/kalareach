//! A worker's session in this process: a real pseudo-terminal whose own program writes nothing and
//! waits, so every byte of output is what a test reads into it, on the clocks a test hands it.

use std::path::PathBuf;

use kr_protocol::identity::{DesktopBinding, WorkerProfile};
use kr_protocol::ids::{EnvironmentId, SessionEpoch, SessionId};
use kr_protocol::session::{Dimensions, DisplayNumber, ShellMode};
use kr_worker::action::time::TimeSources;
use kr_worker::session::SessionConfig;

/// Every subscriber's queue, large enough that a client that is read after every byte is never
/// told to begin again for want of room: that is a different property, with tests of its own.
pub const SEND_QUEUE_BYTES: usize = 8 * 1024 * 1024;

/// A session of `columns` by `rows` on the clocks `time`, keeping its receipt journal at
/// `journal_path` when one is given and in memory otherwise.
#[must_use]
pub fn config(
    columns: u16,
    rows: u16,
    time: TimeSources,
    journal_path: Option<PathBuf>,
) -> SessionConfig {
    SessionConfig {
        session_id: SessionId::new(kr_ipc::new_uuid()),
        session_epoch: SessionEpoch::V1,
        environment_id: EnvironmentId::new(kr_ipc::new_uuid()),
        display_number: DisplayNumber::new(1),
        // A program that writes nothing and waits: every byte of output is the test's.
        shell: kr_worker::testing::posix_script("IFS= read -r _"),
        shell_mode: ShellMode::NativeCompat,
        launch_profile: kr_protocol::session::LaunchProfile::default(),
        worker_profile: WorkerProfile::HeadlessUser,
        desktop: DesktopBinding::none(),
        dimensions: Dimensions::new(u64::from(columns), u64::from(rows)),
        journal_path,
        spool_directory: None,
        worker_endpoint: None,
        send_queue_bytes: SEND_QUEUE_BYTES,
        resident_bytes: 4 * 1024 * 1024,
        time,
    }
}
