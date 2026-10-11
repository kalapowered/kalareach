//! A session the tests launch into, and the process group their launches run in.

use std::sync::Arc;

use kr_protocol::ids::SessionId;
use kr_protocol::scalars::Uuid;

/// The session every launch of a test is made for.
#[must_use]
pub fn session() -> SessionId {
    SessionId::new(Uuid::from_bytes([1; 16]))
}

/// The process group every program a test's shell launches runs in, led by a process of the test's
/// own that ends the whole group once the test's process has gone.
///
/// A launched program can wait for something only its test does, and a test that stops early,
/// at a panic or because its process was killed, would otherwise leave the program waiting. The
/// group is ended when the shell is dropped, which a panic's unwinding does too, and the leader
/// ends it by itself once the test's process is gone, which is how a killed test's programs end.
/// The leader is collected only after its group has been ended, so until then its identifier, and
/// with it the group's, can name no other process: ending the group reaches exactly what this
/// shell launched.
pub struct LaunchGroup {
    leader: std::process::Child,
}

impl LaunchGroup {
    /// Starts the group's leader.
    #[must_use]
    pub fn new() -> Self {
        use std::os::unix::process::CommandExt as _;

        // The process to watch is named by this process, not read from the shell's own parent: a
        // test that dies before the shell has looked would leave the shell's parent to be
        // whoever adopted it.
        let leader = std::process::Command::new("/bin/sh")
            .args([
                "-c",
                r#"while kill -0 "$1" 2>/dev/null; do sleep 1; done; kill -KILL 0"#,
                "sh",
                &std::process::id().to_string(),
            ])
            .process_group(0)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("the launches' group leader starts");
        Self { leader }
    }

    /// The group's identifier, for a launch to join.
    #[must_use]
    pub fn id(&self) -> i32 {
        i32::try_from(self.leader.id()).expect("a process identifier")
    }
}

impl Drop for LaunchGroup {
    fn drop(&mut self) {
        let group = rustix::process::Pid::from_child(&self.leader);
        // The leader is uncollected, so the group exists until this signal ends it.
        let _ = rustix::process::kill_process_group(group, rustix::process::Signal::KILL);
        let _ = self.leader.wait();
    }
}

/// A session with one attached view, the way the worker delivers to its clients.
pub struct View {
    /// The session.
    pub runtime: Arc<kr_worker::runtime::SessionRuntime>,
    /// The attached view's stream.
    pub stream: std::sync::Mutex<kr_worker::output::OutputStream>,
}

impl View {
    /// Opens a session whose shell is `cat`, attaches one view to it and subscribes that view.
    ///
    /// # Panics
    ///
    /// Panics when the session cannot be opened, attached to or started.
    #[must_use]
    pub fn open(host: &kr_ipc::testing::TempHost) -> Self {
        let mut requested = kr_protocol::scalars::CanonicalSet::new();
        requested.insert(kr_protocol::attachment::AttachmentCapability::ObserveTerminal);
        let config = kr_worker::session::SessionConfig {
            session_id: session(),
            session_epoch: kr_protocol::ids::SessionEpoch::V1,
            environment_id: host.environment_id(),
            display_number: kr_protocol::session::DisplayNumber::new(1),
            shell: kr_worker::testing::posix_script("exec cat"),
            shell_mode: kr_protocol::session::ShellMode::NativeCompat,
            worker_profile: kr_protocol::identity::WorkerProfile::HeadlessUser,
            desktop: kr_protocol::identity::DesktopBinding::none(),
            dimensions: kr_protocol::session::Dimensions::new(80, 24),
            journal_path: Some(host.environment().journal_database(session())),
            spool_directory: Some(host.environment().session_spool(session())),
            worker_endpoint: None,
            send_queue_bytes: 8 * 1024 * 1024,
            resident_bytes: 1024 * 1024,
            time: kr_worker::action::time::TimeSources::system(),
            launch_profile: kr_protocol::session::LaunchProfile::default(),
        };
        let mut opened = kr_worker::session::Session::open(config).expect("the session opens");
        opened.launch().expect("its shell starts");
        let attachment_id = kr_protocol::ids::AttachmentId::new(Uuid::from_bytes([5; 16]));
        let params = kr_protocol::attachment::SessionAttachParams {
            session_id: session(),
            mode: kr_protocol::attachment::AttachMode::Terminal,
            claim_geometry: false,
            dimensions: kr_protocol::scalars::Nullable::some(
                kr_protocol::session::Dimensions::new(80, 24),
            ),
            terminal_profile_id: kr_protocol::scalars::Nullable::some("xterm-256color".to_owned()),
            requested: requested.clone(),
        };
        opened
            .attach(&params, requested, attachment_id)
            .expect("the view attaches");
        let stream = opened
            .subscribe(attachment_id)
            .expect("the view subscribes");
        let runtime = Arc::new(
            kr_worker::runtime::SessionRuntime::start(
                opened,
                Arc::new(kr_ipc::clock::SystemSharedClock),
            )
            .expect("the session runs"),
        );
        Self {
            runtime,
            stream: std::sync::Mutex::new(stream),
        }
    }
}
