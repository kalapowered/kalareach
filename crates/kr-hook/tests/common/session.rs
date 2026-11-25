//! A session the tests launch into, and the group their launches run in.

use std::sync::Arc;

use kr_protocol::ids::SessionId;
use kr_protocol::scalars::Uuid;

/// The session every launch of a test is made for.
#[must_use]
pub fn session() -> SessionId {
    SessionId::new(Uuid::from_bytes([1; 16]))
}

/// The group every program a test's shell launches runs in, which ends the whole of it once the
/// test's process has gone.
///
/// A launched program can wait for something only its test does, and a test that stops early,
/// at a panic or because its process was killed, would otherwise leave the program waiting. The
/// group is ended when the shell is dropped, which a panic's unwinding does too, and it ends by
/// itself once the test's process is gone, which is how a killed test's programs end.
///
/// On Unix the group is a process group, led by a process of the test's own that ends the group
/// once the test's process has gone: it is collected only after the group has been ended, so until
/// then its identifier, and with it the group's, can name no other process, and ending the group
/// reaches exactly what this shell launched. On Windows it is a job that ends what it holds when
/// its last handle closes, and the test's process holds the only one.
pub struct LaunchGroup {
    #[cfg(unix)]
    leader: std::process::Child,
    #[cfg(windows)]
    job: kr_worker::windows::job::AgentJob,
}

#[cfg(unix)]
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

    /// Starts `command` in the group.
    ///
    /// # Errors
    ///
    /// Returns the system's failure to start the program.
    pub fn spawn(
        &self,
        command: &mut std::process::Command,
    ) -> std::io::Result<std::process::Child> {
        use std::os::unix::process::CommandExt as _;

        command.process_group(self.id()).spawn()
    }
}

#[cfg(windows)]
impl LaunchGroup {
    /// Makes the group's job.
    ///
    /// # Panics
    ///
    /// Panics when the job cannot be made, or does not end what it holds when it is closed.
    #[must_use]
    pub fn new() -> Self {
        Self {
            job: kr_worker::windows::job::AgentJob::create_owning()
                .expect("the launches' job is made"),
        }
    }

    /// Starts `command` in the group.
    ///
    /// The program is created suspended, put in the job and started only then, so nothing it
    /// starts can be outside the job: a program put in the job after it ran could already have
    /// started another. This replaces the creation flags that `command` had.
    ///
    /// # Errors
    ///
    /// Returns the system's failure to start the program, to put it in the job, or to start it
    /// there. A program that was created and could not be put in the job is ended and collected. A
    /// test process that ends between the creation and the placement leaves the program held:
    /// nothing is left that could end it.
    pub fn spawn(
        &self,
        command: &mut std::process::Command,
    ) -> std::io::Result<std::process::Child> {
        use std::os::windows::io::AsHandle as _;

        let held = HeldChild::start(command)?;
        self.job.assign(held.id())?;
        let mut child = held.placed();
        if let Err(error) = kr_ipc::memory_limit::resume(child.as_handle()) {
            end_and_collect(&mut child);
            return Err(std::io::Error::other(error));
        }
        Ok(child)
    }

    /// The identifiers of the processes the job holds.
    ///
    /// # Panics
    ///
    /// Panics when the job cannot be read.
    #[must_use]
    pub fn members(&self) -> Vec<u32> {
        self.job.process_ids().expect("the job's members are read")
    }
}

/// How long a program that has been told to end is waited for.
#[cfg(windows)]
const END_BOUND: std::time::Duration = std::time::Duration::from_secs(10);

/// Ends `child` and collects it, waiting at most [`END_BOUND`] for it to end: a termination that
/// the system refuses leaves the process, and does not leave the case waiting for it.
#[cfg(windows)]
pub fn end_and_collect(child: &mut std::process::Child) {
    let _ = child.kill();
    let until = std::time::Instant::now() + END_BOUND;
    while std::time::Instant::now() < until {
        if !matches!(child.try_wait(), Ok(None)) {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

/// A program created held that no job holds yet.
///
/// It is ended and collected when this is dropped, as when its placement in a job fails or
/// panics, unless [`HeldChild::placed`] has given it up. A test process that ends between the
/// creation and the placement leaves the program held: nothing is left that could end it.
#[cfg(windows)]
pub struct HeldChild(Option<std::process::Child>);

#[cfg(windows)]
impl HeldChild {
    /// Creates the program held. The command's creation flags are replaced.
    ///
    /// # Errors
    ///
    /// Returns the system's failure to create the program.
    pub fn start(command: &mut std::process::Command) -> std::io::Result<Self> {
        kr_ipc::memory_limit::start_held(command)
            .spawn()
            .map(|child| Self(Some(child)))
    }

    /// The program's process identifier.
    ///
    /// # Panics
    ///
    /// Panics when the program has been given up.
    #[must_use]
    pub fn id(&self) -> u32 {
        self.0.as_ref().expect("the program is held").id()
    }

    /// Gives the program up, once a job holds it.
    ///
    /// # Panics
    ///
    /// Panics when the program has been given up.
    #[must_use]
    pub fn placed(mut self) -> std::process::Child {
        self.0.take().expect("the program is held")
    }
}

#[cfg(windows)]
impl Drop for HeldChild {
    fn drop(&mut self) {
        if let Some(mut program) = self.0.take() {
            end_and_collect(&mut program);
        }
    }
}

impl Drop for LaunchGroup {
    #[cfg(unix)]
    fn drop(&mut self) {
        let group = rustix::process::Pid::from_child(&self.leader);
        // The leader is uncollected, so the group exists until this signal ends it.
        let _ = rustix::process::kill_process_group(group, rustix::process::Signal::KILL);
        let _ = self.leader.wait();
    }

    #[cfg(windows)]
    fn drop(&mut self) {
        // What the job holds is ended now and waited for, so that a program still holding a file of
        // the test's tree has let go of it before the tree is removed.
        let _ = self.job.terminate(1);
        let ended = std::time::Instant::now() + super::LIVENESS;
        while std::time::Instant::now() < ended
            && self.job.process_ids().is_ok_and(|left| !left.is_empty())
        {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
}

/// A session with one attached view, the way the worker delivers to its clients.
pub struct View {
    /// The session.
    pub runtime: Arc<kr_worker::runtime::SessionRuntime>,
    /// The attachment the view holds.
    pub attachment_id: kr_protocol::ids::AttachmentId,
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
            attachment_id,
            stream: std::sync::Mutex::new(stream),
        }
    }
}
