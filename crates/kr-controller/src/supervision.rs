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

/// How this host starts workers.
pub trait WorkerSupervisor: Send + Sync + std::fmt::Debug {
    /// Starts a worker and returns the identity the launcher reported.
    ///
    /// # Errors
    ///
    /// Returns [`ControllerError::Supervision`] when the worker cannot be started or the launcher
    /// does not report a usable identity.
    fn start(&self, launch: &WorkerLaunch) -> Result<ProcessStartIdentity>;

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
             </dict>\n</plist>\n",
            label_value = plist_string(&label),
            arguments = arguments,
            process_type = plist_string("Interactive"),
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
    fn start(&self, launch: &WorkerLaunch) -> Result<ProcessStartIdentity> {
        let domain = format!("gui/{}", kr_ipc::paths::current_uid());
        let label = launch.label();
        let job = Self::write_job(launch)?;
        run(
            "/bin/launchctl",
            &["bootstrap", &domain, &job.display().to_string()],
        )?;
        // `-p` starts a job that is not running and prints the process identifier. `-k` would kill
        // a running job first, which for a session worker means killing a live shell.
        let output = run(
            "/bin/launchctl",
            &["kickstart", "-p", &format!("{domain}/{label}")],
        )?;
        let pid = parse_pid(&output).ok_or_else(|| {
            ControllerError::supervision(format!(
                "launchctl kickstart did not report a process identifier: {output}"
            ))
        })?;
        kr_ipc::identity::process_start_identity(pid).map_err(ControllerError::Ipc)
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
        std::process::Command::new("systemctl")
            .args(["--user", "is-system-running"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok()
    }
}

#[cfg(target_os = "linux")]
impl WorkerSupervisor for SystemdSupervisor {
    fn start(&self, launch: &WorkerLaunch) -> Result<ProcessStartIdentity> {
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
            "--quiet".to_owned(),
            launch.program.display().to_string(),
        ];
        arguments.extend(launch.arguments());
        let borrowed: Vec<&str> = arguments.iter().map(String::as_str).collect();
        run("systemd-run", &borrowed)?;
        let output = run(
            "systemctl",
            &["--user", "show", "-p", "MainPID", "--value", &unit],
        )?;
        let pid = output.trim().parse::<u32>().ok().filter(|pid| *pid != 0);
        let pid = pid.ok_or_else(|| {
            ControllerError::supervision(format!(
                "the transient service {unit} reported no main process"
            ))
        })?;
        kr_ipc::identity::process_start_identity(pid).map_err(ControllerError::Ipc)
    }

    fn describe(&self) -> String {
        "systemd, one transient user service per session".to_owned()
    }
}

/// The fallback supervisor: a detached, separately sessionised process.
///
/// This is what a non-systemd Unix host uses, and what a macOS host without a GUI bootstrap domain
/// falls back to. The child is reparented to init, so it outlives this daemon; it has no
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
    fn start(&self, launch: &WorkerLaunch) -> Result<ProcessStartIdentity> {
        let child = detached_command(&launch.program, &launch.arguments())?;
        kr_ipc::identity::process_start_identity(child).map_err(ControllerError::Ipc)
    }

    fn describe(&self) -> String {
        "a detached, separately sessionised process reparented to init".to_owned()
    }
}

#[cfg(unix)]
fn detached_command(program: &Path, arguments: &[String]) -> Result<u32> {
    // `setsid` puts the worker in its own session, so it survives this daemon and is reparented to
    // init. Using the system tool keeps this crate free of the unsafe pre-execution hook the same
    // effect would otherwise need.
    let mut command = std::process::Command::new("/usr/bin/setsid");
    command.arg(program);
    command.args(arguments);
    command
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    let child = command.spawn().map_err(|error| {
        ControllerError::supervision(format!("setsid {}: {error}", program.display()))
    })?;
    Ok(child.id())
}

#[cfg(not(unix))]
fn detached_command(program: &Path, arguments: &[String]) -> Result<u32> {
    // Windows workers are explicitly outside the control daemon's kill-on-close Job Object; each
    // worker owns its own per-session Job.
    let mut command = std::process::Command::new(program);
    command.args(arguments);
    command
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    let child = command.spawn().map_err(|error| {
        ControllerError::supervision(format!("start {}: {error}", program.display()))
    })?;
    Ok(child.id())
}

fn run(program: &str, arguments: &[&str]) -> Result<String> {
    let output = std::process::Command::new(program)
        .args(arguments)
        .output()
        .map_err(|error| ControllerError::supervision(format!("{program}: {error}")))?;
    if !output.status.success() {
        return Err(ControllerError::supervision(format!(
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

    #[cfg(target_os = "macos")]
    #[test]
    fn the_kickstart_output_yields_the_process_identifier() {
        assert_eq!(parse_pid("service spawned with pid 4242"), Some(4242));
        assert_eq!(parse_pid("spawned process 17.\n"), Some(17));
        assert_eq!(parse_pid("no identifier here"), None);
    }
}
