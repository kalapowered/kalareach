//! Starting a worker through the platform's own service manager.
//!
//! A worker's lifetime must not belong to the control daemon. If it did, restarting the daemon
//! would close every session, which is the one thing section 2 forbids outright. So the daemon
//! asks the platform to start the worker and then lets go of it:
//!
//! | Platform | How the worker is started | Where its identity comes from |
//! | --- | --- | --- |
//! | macOS | a per-session launchd job, bootstrapped into the GUI domain and started once with `launchctl kickstart -p` | the kickstart output's process identifier, then `proc_pidinfo` |
//! | Linux with systemd | a transient user *service*, `systemd-run --user --unit=... -p Type=exec -p Restart=no` | `systemctl --user show -p MainPID`, then `/proc/<pid>/stat` |
//! | other Unix | a `setsid` launch, reparented to init | the spawned child's identifier, then `/proc` or `proc_pidinfo` |
//! | Windows | the spawned child, outside the daemon's kill-on-close Job | the child's identifier and creation time |
//!
//! `kickstart -p` and not `-k`: the second would restart a job that is already running, which for
//! a session worker would mean killing a live shell to start another one.
//!
//! The identity the launcher reports is recorded against the reservation before the worker
//! connects, and the rendezvous compares it with the connecting peer. That is what stops another
//! process from claiming a reservation it was not started for.

use std::path::{Path, PathBuf};

use kr_protocol::identity::ProcessStartIdentity;
use kr_protocol::worker::ReservationId;

use crate::error::{ControllerError, Result};

/// What a worker needs to be told through its job definition.
///
/// Every field here is non-secret. The shell, the creator's environment and the controller's
/// public key travel over the rendezvous channel instead, after the worker has proved itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkerLaunch {
    /// The reservation the worker was started for.
    pub reservation_id: ReservationId,
    /// The session the reservation allocated.
    pub session_id: kr_protocol::ids::SessionId,
    /// The environment the session belongs to.
    pub environment_id: kr_protocol::ids::EnvironmentId,
    /// The local alias, which also names the worker's endpoint.
    pub display_number: kr_protocol::session::DisplayNumber,
    /// The worker executable.
    pub program: PathBuf,
    /// The controller's owner-only rendezvous socket.
    pub rendezvous: PathBuf,
    /// The per-user runtime directory.
    pub runtime_directory: PathBuf,
    /// The per-user state directory.
    pub state_directory: PathBuf,
    /// Where a generated job definition is written.
    pub jobs_directory: PathBuf,
    /// The directory the worker process runs in.
    ///
    /// Set explicitly on every platform. A worker started through a service manager would
    /// otherwise run in whatever directory that manager happens to be in, and one started by this
    /// daemon directly would run in the daemon's, which is the directory of whoever started the
    /// daemon. Neither is a directory the worker has any claim on, and either can be a volume the
    /// person at the machine expects to be able to unmount.
    pub working_directory: PathBuf,
}

impl WorkerLaunch {
    /// Returns the argument vector the worker is started with.
    ///
    /// Nothing here is a secret, and nothing is assembled by interpolating text into a command
    /// line: the vector is passed as a vector.
    #[must_use]
    pub fn arguments(&self) -> Vec<String> {
        vec![
            "--reservation".to_owned(),
            self.reservation_id.to_string(),
            "--session".to_owned(),
            self.session_id.to_string(),
            "--environment".to_owned(),
            self.environment_id.to_string(),
            "--display".to_owned(),
            self.display_number.to_string(),
            "--rendezvous".to_owned(),
            self.rendezvous.display().to_string(),
            "--runtime-dir".to_owned(),
            self.runtime_directory.display().to_string(),
            "--state-dir".to_owned(),
            self.state_directory.display().to_string(),
        ]
    }

    /// Returns the job label a per-session service uses.
    #[must_use]
    pub fn label(&self) -> String {
        format!("kr-worker-{}", self.reservation_id)
    }
}

/// What asking the platform to start a worker produced.
///
/// The difference between the last two matters more than it looks. "Nothing started" releases the
/// reservation's slot and resolves it for good. "Something may be running" does neither: the host
/// has no evidence that a process is not out there holding a session, so the reservation keeps its
/// slot until something settles the question. Collapsing the two would let a failure that happened
/// *after* a successful spawn free a slot the spawn still occupies.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LaunchOutcome {
    /// The worker started and the kernel described it.
    Started(ProcessStartIdentity),
    /// Nothing was started.
    NotStarted {
        /// What went wrong.
        detail: String,
    },
    /// A process may be running, and this host cannot say whether it is.
    Uncertain {
        /// What went wrong.
        detail: String,
        /// The process identifier the launcher reported, when it reported one.
        pid: Option<u32>,
    },
}

impl LaunchOutcome {
    /// Renders the outcome as the failure a caller is given.
    #[must_use]
    pub fn failure(&self) -> Option<ControllerError> {
        match self {
            Self::Started(_) => None,
            Self::NotStarted { detail } | Self::Uncertain { detail, .. } => {
                Some(ControllerError::supervision(detail.clone()))
            }
        }
    }
}

/// How this host starts workers.
pub trait WorkerSupervisor: Send + Sync + std::fmt::Debug {
    /// Starts a worker and says what happened.
    fn start(&self, launch: &WorkerLaunch) -> LaunchOutcome;

    /// Names this supervisor for diagnostics.
    fn describe(&self) -> String;
}

/// Chooses the supervisor this host can actually use.
///
/// The choice is made by asking the platform, not by assuming it: a macOS host without a GUI login
/// session has no bootstrap domain to put a job in, and a Linux host without systemd has no user
/// manager to ask.
#[must_use]
pub fn detect() -> Box<dyn WorkerSupervisor> {
    #[cfg(target_os = "macos")]
    {
        if LaunchdSupervisor::available() {
            return Box::new(LaunchdSupervisor::new());
        }
    }
    #[cfg(target_os = "linux")]
    {
        if SystemdSupervisor::available() {
            return Box::new(SystemdSupervisor::new());
        }
    }
    Box::new(DetachedSupervisor::new())
}

/// The macOS supervisor: a per-session launchd job in the user's GUI domain.
#[cfg(target_os = "macos")]
#[derive(Debug, Default)]
pub struct LaunchdSupervisor;

#[cfg(target_os = "macos")]
impl LaunchdSupervisor {
    /// Builds the supervisor.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Returns true when this host has a GUI bootstrap domain to put a job in.
    #[must_use]
    pub fn available() -> bool {
        std::process::Command::new("/bin/launchctl")
            .arg("print")
            .arg(format!("gui/{}", kr_ipc::paths::current_uid()))
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    }

    fn write_job(launch: &WorkerLaunch) -> Result<PathBuf> {
        let label = launch.label();
        let path = launch.jobs_directory.join(format!("{label}.plist"));
        let mut arguments = String::new();
        arguments.push_str(&plist_string(&launch.program.display().to_string()));
        for argument in launch.arguments() {
            arguments.push_str(&plist_string(&argument));
        }
        let document = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
             \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
             <plist version=\"1.0\">\n<dict>\n\
             <key>Label</key>{label_value}\
             <key>ProgramArguments</key><array>{arguments}</array>\n\
             <key>RunAtLoad</key><false/>\n\
             <key>KeepAlive</key><false/>\n\
             <key>ProcessType</key>{process_type}\
             <key>WorkingDirectory</key>{working_directory}\
             <key>StandardErrorPath</key>{diagnostics}\
             </dict>\n</plist>\n",
            label_value = plist_string(&label),
            arguments = arguments,
            process_type = plist_string("Interactive"),
            working_directory = plist_string(&launch.working_directory.display().to_string()),
            // A worker that fails before it reaches the rendezvous has nowhere else to say why:
            // it has no terminal, no connection and no journal yet. This file is the one place
            // that diagnosis can go, and it lives in the owner-only state directory.
            diagnostics = plist_string(
                &launch
                    .jobs_directory
                    .join(format!("{label}.diagnostics"))
                    .display()
                    .to_string()
            ),
        );
        kr_ipc::paths::write_owner_only_file(&path, document.as_bytes())
            .map_err(ControllerError::Ipc)?;
        Ok(path)
    }
}

#[cfg(target_os = "macos")]
fn plist_string(value: &str) -> String {
    let escaped = value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");
    format!("<string>{escaped}</string>\n")
}

#[cfg(target_os = "macos")]
impl WorkerSupervisor for LaunchdSupervisor {
    fn start(&self, launch: &WorkerLaunch) -> LaunchOutcome {
        let domain = format!("gui/{}", kr_ipc::paths::current_uid());
        let label = launch.label();
        // Writing the job definition and loading it start nothing: `RunAtLoad` is false, so until
        // the kickstart there is no process to be uncertain about.
        let job = match Self::write_job(launch) {
            Ok(job) => job,
            Err(error) => {
                return LaunchOutcome::NotStarted {
                    detail: error.to_string(),
                };
            }
        };
        // Loading the job starts nothing: `RunAtLoad` is false. A bootstrap that fails therefore
        // leaves nothing running, however it failed.
        if let Err(error) = run(
            "/bin/launchctl",
            &["bootstrap", &domain, &job.display().to_string()],
        ) {
            return LaunchOutcome::NotStarted {
                detail: error.detail(),
            };
        }
        // `-p` starts a job that is not running and prints the process identifier. `-k` would kill
        // a running job first, which for a session worker means killing a live shell.
        //
        // From here the answer can only be uncertain: a kickstart that fails part way through may
        // still have started the job.
        let output = match run(
            "/bin/launchctl",
            &["kickstart", "-p", &format!("{domain}/{label}")],
        ) {
            Ok(output) => output,
            Err(error) => {
                return LaunchOutcome::Uncertain {
                    detail: error.detail(),
                    pid: None,
                };
            }
        };
        let Some(pid) = parse_pid(&output) else {
            return LaunchOutcome::Uncertain {
                detail: format!(
                    "launchctl kickstart did not report a process identifier: {output}"
                ),
                pid: None,
            };
        };
        settle(pid)
    }

    fn describe(&self) -> String {
        "launchd, one bootstrapped job per session in the user's GUI domain".to_owned()
    }
}

/// The systemd supervisor: a transient user service per session.
#[cfg(target_os = "linux")]
#[derive(Debug, Default)]
pub struct SystemdSupervisor;

#[cfg(target_os = "linux")]
impl SystemdSupervisor {
    /// Builds the supervisor.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Returns true when this host has a user service manager to ask.
    #[must_use]
    pub fn available() -> bool {
        // A user manager that answers a property query is a user manager that exists. Running
        // `systemctl` successfully proves only that the binary is installed, which a host with no
        // user manager also has.
        std::process::Command::new("systemctl")
            .args(["--user", "show", "--property=Version", "--value"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    }
}

#[cfg(target_os = "linux")]
impl WorkerSupervisor for SystemdSupervisor {
    fn start(&self, launch: &WorkerLaunch) -> LaunchOutcome {
        let unit = launch.label();
        // A transient *service*, not a scope: `MainPID` is defined for a service, so the launcher
        // has an identity to record. A scope would leave the controller guessing.
        let mut arguments = vec![
            "--user".to_owned(),
            format!("--unit={unit}"),
            "-p".to_owned(),
            "Type=exec".to_owned(),
            "-p".to_owned(),
            "Restart=no".to_owned(),
            "-p".to_owned(),
            format!("WorkingDirectory={}", launch.working_directory.display()),
            "--quiet".to_owned(),
            launch.program.display().to_string(),
        ];
        arguments.extend(launch.arguments());
        let borrowed: Vec<&str> = arguments.iter().map(String::as_str).collect();
        match run("systemd-run", &borrowed) {
            Ok(_) => {}
            // The command never ran, so the manager was never asked.
            Err(RunFailure::NotRun(detail)) => return LaunchOutcome::NotStarted { detail },
            // The command ran and failed. It may have reached the manager before it did, so what
            // happened to the unit is not settled from here.
            Err(RunFailure::Failed(detail)) => {
                return LaunchOutcome::Uncertain { detail, pid: None };
            }
        }
        // The unit exists from here on, so anything that goes wrong afterwards leaves a process
        // that may be running.
        let output = match run(
            "systemctl",
            &["--user", "show", "-p", "MainPID", "--value", &unit],
        ) {
            Ok(output) => output,
            Err(error) => {
                return LaunchOutcome::Uncertain {
                    detail: error.detail(),
                    pid: None,
                };
            }
        };
        let Some(pid) = output.trim().parse::<u32>().ok().filter(|pid| *pid != 0) else {
            return LaunchOutcome::Uncertain {
                detail: format!("the transient service {unit} reported no main process"),
                pid: None,
            };
        };
        settle(pid)
    }

    fn describe(&self) -> String {
        "systemd, one transient user service per session".to_owned()
    }
}

/// The fallback supervisor: a detached process in its own process group.
///
/// This is what a non-systemd Unix host uses, and what a macOS host without a GUI bootstrap domain
/// falls back to. The child has its own process group and no inherited terminal, so nothing aimed
/// at this daemon reaches it, and it is reparented to init when this daemon exits. It has no
/// parent-death signal, and the daemon reconnects to its endpoint rather than to a pipe.
#[derive(Debug, Default)]
pub struct DetachedSupervisor;

impl DetachedSupervisor {
    /// Builds the supervisor.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl WorkerSupervisor for DetachedSupervisor {
    fn start(&self, launch: &WorkerLaunch) -> LaunchOutcome {
        match detached_command(
            &launch.program,
            &launch.arguments(),
            &launch.working_directory,
        ) {
            Ok(child) => settle(child),
            // The spawn itself failed, so no process exists.
            Err(error) => LaunchOutcome::NotStarted {
                detail: error.to_string(),
            },
        }
    }

    fn describe(&self) -> String {
        "a detached process in its own group, reparented to init when this daemon exits".to_owned()
    }
}

#[cfg(unix)]
fn detached_command(program: &Path, arguments: &[String], working_directory: &Path) -> Result<u32> {
    use std::os::unix::process::CommandExt as _;

    // The worker gets its own process group here, and makes itself a session leader as soon as it
    // starts, which is what actually leaves this daemon's session and controlling terminal. Doing
    // the second half in the worker keeps it out of the child-setup path, where the only way to
    // call `setsid` is one this codebase does not allow. It is reparented to init when this daemon
    // exits. This is the fallback for a host with no service manager to ask; where one exists,
    // that manager owns the worker.
    let mut command = std::process::Command::new(program);
    command.process_group(0);
    command.args(arguments);
    // Never the daemon's own directory: the worker outlives this daemon, so a directory inherited
    // from it would be held open by a process nothing can see the parentage of.
    command.current_dir(working_directory);
    command
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    let child = command.spawn().map_err(|error| {
        ControllerError::supervision(format!("start {}: {error}", program.display()))
    })?;
    Ok(child.id())
}

#[cfg(not(unix))]
fn detached_command(program: &Path, arguments: &[String], working_directory: &Path) -> Result<u32> {
    use std::os::windows::process::CommandExt as _;

    // A worker must outlive this daemon. A process started by a daemon that is itself inside a
    // job object with kill-on-close would be killed with it, so the worker breaks away from that
    // job and is given its own console-free process group.
    const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x0100_0000;
    const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
    const DETACHED_PROCESS: u32 = 0x0000_0008;

    let mut command = std::process::Command::new(program);
    command.creation_flags(CREATE_BREAKAWAY_FROM_JOB | CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS);
    command.args(arguments);
    // Never the daemon's own directory, for the same reason as on Unix: a current directory is a
    // handle on a volume, and this process outlives the one that started it.
    command.current_dir(working_directory);
    command
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    let child = command.spawn().map_err(|error| {
        ControllerError::supervision(format!("start {}: {error}", program.display()))
    })?;
    Ok(child.id())
}

/// How long the launcher's reported process is given to become readable.
pub const IDENTITY_SETTLE: std::time::Duration = std::time::Duration::from_secs(2);

/// Reads a started process's identity and says what the launch produced.
///
/// A service manager reports the process identifier as soon as it has spawned the process, which
/// can be before the kernel will answer questions about it: the process may still be part way
/// through replacing its image. Retrying briefly is the difference between recording the identity
/// and refusing a worker that started perfectly well.
#[must_use]
pub fn settle(pid: u32) -> LaunchOutcome {
    match identity_when_available(pid) {
        Ok(identity) => LaunchOutcome::Started(identity),
        // The launcher reported a process and the kernel will not describe it. That is not proof
        // the process never ran, so the reservation keeps its slot.
        Err(error) => LaunchOutcome::Uncertain {
            detail: error.to_string(),
            pid: Some(pid),
        },
    }
}

/// Reads a freshly started process's start identity, allowing for the moment it takes to appear.
///
/// # Errors
///
/// Returns [`ControllerError::Supervision`] when the identity is still unreadable at the deadline.
pub fn identity_when_available(pid: u32) -> Result<ProcessStartIdentity> {
    let deadline = std::time::Instant::now() + IDENTITY_SETTLE;
    loop {
        match kr_ipc::identity::process_start_identity(pid) {
            Ok(identity) => return Ok(identity),
            Err(error) => {
                if std::time::Instant::now() >= deadline {
                    return Err(ControllerError::supervision(format!(
                        "the launcher reported process {pid}, which the kernel will not describe: {error}"
                    )));
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
        }
    }
}

/// Why a launcher command did not produce an answer.
///
/// Only the service managers use this, and only two platforms have one.
///
/// The two are not the same. A command that never ran started nothing. A command that ran and
/// failed part way through may have reached the service manager first, and treating that as
/// "nothing started" would free a slot something may still be occupying.
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[derive(Clone, Debug)]
enum RunFailure {
    /// The command could not be started at all.
    NotRun(String),
    /// The command ran and reported a failure.
    Failed(String),
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
impl RunFailure {
    fn detail(&self) -> String {
        match self {
            Self::NotRun(detail) | Self::Failed(detail) => detail.clone(),
        }
    }
}

/// Runs a service manager's command and returns what it printed.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn run(program: &str, arguments: &[&str]) -> std::result::Result<String, RunFailure> {
    let output = std::process::Command::new(program)
        .args(arguments)
        .output()
        .map_err(|error| RunFailure::NotRun(format!("{program}: {error}")))?;
    if !output.status.success() {
        return Err(RunFailure::Failed(format!(
            "{program} {}: {}",
            arguments.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(target_os = "macos")]
fn parse_pid(output: &str) -> Option<u32> {
    // The documented output names the process, for example "service spawned with pid 4242".
    output
        .split_whitespace()
        .rev()
        .find_map(|word| word.trim_end_matches('.').parse::<u32>().ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::scalars::Uuid;

    fn launch() -> WorkerLaunch {
        WorkerLaunch {
            reservation_id: ReservationId::new(Uuid::from_bytes([1; 16])),
            session_id: kr_protocol::ids::SessionId::new(Uuid::from_bytes([2; 16])),
            environment_id: kr_protocol::ids::EnvironmentId::new(Uuid::from_bytes([3; 16])),
            display_number: kr_protocol::session::DisplayNumber::new(7),
            program: PathBuf::from("/usr/local/bin/kr-worker"),
            rendezvous: PathBuf::from("/run/kr/r.sock"),
            runtime_directory: PathBuf::from("/run/kr"),
            state_directory: PathBuf::from("/var/lib/kr"),
            jobs_directory: PathBuf::from("/var/lib/kr/jobs"),
            working_directory: PathBuf::from(
                "/var/lib/kr/workers/02020202-0202-0202-0202-020202020202",
            ),
        }
    }

    #[test]
    fn the_argument_vector_carries_only_non_secret_facts() {
        let arguments = launch().arguments();
        assert!(arguments.contains(&"--reservation".to_owned()));
        assert!(arguments.contains(&"--session".to_owned()));
        assert!(arguments.contains(&"--rendezvous".to_owned()));
        assert!(
            !arguments.iter().any(|argument| argument.contains("key")
                || argument.contains("token")
                || argument.contains("secret")),
            "no secret reaches the job definition"
        );
    }

    #[test]
    fn the_job_label_names_the_reservation() {
        assert_eq!(
            launch().label(),
            "kr-worker-01010101-0101-0101-0101-010101010101"
        );
    }

    /// The job definition a service manager reads names the directory the worker runs in.
    ///
    /// A worker inheriting a directory is the thing this prevents: the launcher's directory is
    /// whoever started the daemon's, and a service manager's is the system's.
    #[cfg(target_os = "macos")]
    #[test]
    fn the_job_definition_names_the_directory_the_worker_runs_in() {
        let host = kr_ipc::testing::TempHost::create();
        let mut launch = launch();
        launch.jobs_directory = host.environment().jobs_dir();
        let job = LaunchdSupervisor::write_job(&launch).expect("writes the job definition");
        let document = std::fs::read_to_string(job).expect("reads it back");
        assert!(
            document.contains(
                "<key>WorkingDirectory</key><string>/var/lib/kr/workers/02020202-0202-0202-0202-020202020202</string>"
            ),
            "the job names the worker's own directory: {document}"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn the_kickstart_output_yields_the_process_identifier() {
        assert_eq!(parse_pid("service spawned with pid 4242"), Some(4242));
        assert_eq!(parse_pid("spawned process 17.\n"), Some(17));
        assert_eq!(parse_pid("no identifier here"), None);
    }
}
