//! Starting a worker through the platform's own service manager.
//!
//! A worker's lifetime must not belong to the control daemon. If it did, restarting the daemon
//! would close every session, which is the one thing section 2 forbids outright. So the daemon
//! asks the platform to start the worker and then lets go of it:
//!
//! | Platform | How the worker is started | Where its identity comes from |
//! | --- | --- | --- |
//! | macOS | a per-session launchd job, bootstrapped into the domain the profile names and started once with `launchctl kickstart -p` | the kickstart output's process identifier, then `proc_pidinfo` |
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
//!
//! The profile decides the login context, not only the environment. A desktop-bound worker is
//! started in the graphical login session, and a headless one is started outside it: on macOS in
//! the background domain rather than the graphical one. The fallback supervisor has no domains to
//! choose between, so a worker it starts is in whatever login context this daemon is in, and a
//! headless worker there has the environment stripped rather than a login context of its own.
//!
//! # Services that are not workers
//!
//! A session worker is not the only thing whose lifetime must not belong to the daemon. The plugin
//! runtime is another: a component fault must not reach a session, and a daemon restart must not
//! invalidate every rich binding on the host. So the platform paths above are expressed over
//! [`ServiceLaunch`], which is a label, a program, an argument vector and somewhere to write a job
//! definition, and a worker launch is one of those with a worker's arguments in it. Everything a
//! worker gets from being its own job, a service gets the same way. A service that belongs to no
//! login session is started in the graphical domain and loads under no session type of its own;
//! only a worker names one, because only a worker has a profile.

use std::path::{Path, PathBuf};

use kr_protocol::identity::{ProcessStartIdentity, WorkerProfile};
use kr_protocol::worker::ReservationId;

use kr_shell_integration::host::terminal::{self, Selection, TerminalUnavailable};

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
    /// The selected desktop's own environment, for a platform that does not place a job in a
    /// login session by itself.
    ///
    /// Empty for a headless worker, and empty on the platforms whose service manager puts a
    /// per-user job in the login session that started it. On Linux it carries the graphical
    /// session's display, compositor socket, display authority and message bus, because a user
    /// service manager started at boot has none of them and a worker that inherited nothing would
    /// fail at the first desktop tool it ran.
    pub desktop_environment: Vec<(String, String)>,
    /// How long the worker's execution context lasts.
    ///
    /// It decides which login context the worker is started in, which is a different thing from
    /// which variables it is given: a headless worker that was started inside the graphical login
    /// would have that login's access whatever its environment said.
    pub profile: WorkerProfile,
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

    /// Returns this launch as the job description a supervisor starts.
    #[must_use]
    pub fn service(&self) -> ServiceLaunch {
        ServiceLaunch {
            label: self.label(),
            program: self.program.clone(),
            arguments: self.arguments(),
            jobs_directory: self.jobs_directory.clone(),
            working_directory: self.working_directory.clone(),
        }
    }
}

/// What any service needs to be told through its job definition.
///
/// A label to find the job by, a program, the argument vector it is started with, and somewhere to
/// write a generated job definition. Nothing here is a secret: a process that has to prove who it
/// is generates its own key and presents a signature, rather than being handed one through a job
/// definition that the platform may log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceLaunch {
    /// The job label.
    pub label: String,
    /// The executable.
    pub program: PathBuf,
    /// The arguments, passed as a vector rather than interpolated into a command line.
    pub arguments: Vec<String>,
    /// Where a generated job definition is written.
    pub jobs_directory: PathBuf,
    /// The directory the process runs in.
    ///
    /// Set explicitly on every platform, for every service and not only for workers: a process
    /// started through a service manager would otherwise run in whatever directory that manager
    /// happens to be in, and one started by this daemon directly would run in the daemon's, which
    /// is the directory of whoever started the daemon. Neither is a directory the process has any
    /// claim on, and either can be a volume the person at the machine expects to be able to
    /// unmount.
    pub working_directory: PathBuf,
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

/// How this host starts things whose lifetime must not belong to the daemon.
pub trait WorkerSupervisor: Send + Sync + std::fmt::Debug {
    /// Starts a worker and says what happened.
    fn start(&self, launch: &WorkerLaunch) -> LaunchOutcome;

    /// Names this supervisor for diagnostics.
    fn describe(&self) -> String;

    /// Starts a service that is not a worker, and says what happened.
    ///
    /// The plugin runtime is the first of these: a component fault must not reach a session, and a
    /// daemon restart must not invalidate every rich binding on the host, so it is its own job for
    /// the same reasons a worker is.
    ///
    /// The default refuses by name. A supervisor that can start a worker can start a service, and
    /// the three platform supervisors below do; one that cannot says so rather than pretending to
    /// have started something.
    fn start_service(&self, launch: &ServiceLaunch) -> LaunchOutcome {
        LaunchOutcome::NotStarted {
            detail: format!("{} does not start {}", self.describe(), launch.label),
        }
    }
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

    /// Returns the bootstrap domain a worker of this profile belongs in.
    ///
    /// The graphical domain is the user's Aqua login session: a job in it has that desktop's
    /// access and goes away with the login. The background domain is the same user without it,
    /// which is what a headless profile means on this platform.
    fn domain(profile: WorkerProfile) -> String {
        let uid = kr_ipc::paths::current_uid();
        match profile {
            WorkerProfile::DesktopBound => format!("gui/{uid}"),
            WorkerProfile::HeadlessUser => format!("user/{uid}"),
        }
    }

    /// Returns the session type a job of this profile may be loaded into.
    ///
    /// It is written into the job definition as well as chosen as the domain, so a job that is
    /// somehow bootstrapped into the other domain does not load there.
    const fn session_type(profile: WorkerProfile) -> &'static str {
        match profile {
            WorkerProfile::DesktopBound => "Aqua",
            WorkerProfile::HeadlessUser => "Background",
        }
    }

    /// Writes one job definition, for the session type its launch belongs to.
    ///
    /// A service that is not a worker belongs to no login session and names no type: it is loaded
    /// wherever it is bootstrapped, which is this user's graphical domain.
    fn write_job(launch: &ServiceLaunch, session_type: Option<&str>) -> Result<PathBuf> {
        let label = launch.label.clone();
        let path = launch.jobs_directory.join(format!("{label}.plist"));
        let mut arguments = String::new();
        arguments.push_str(&plist_string(&launch.program.display().to_string()));
        for argument in launch.arguments.clone() {
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
             {session_type}\
             <key>StandardErrorPath</key>{diagnostics}\
             </dict>\n</plist>\n",
            label_value = plist_string(&label),
            arguments = arguments,
            process_type = plist_string("Interactive"),
            working_directory = plist_string(&launch.working_directory.display().to_string()),
            session_type = session_type.map_or_else(String::new, |session_type| format!(
                "<key>LimitLoadToSessionType</key>{}",
                plist_string(session_type)
            )),
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
        // The domain the profile names. A headless worker in the graphical domain would have that
        // login's access however little of its environment it was given.
        self.start_job(
            &launch.service(),
            &Self::domain(launch.profile),
            Some(Self::session_type(launch.profile)),
        )
    }

    fn start_service(&self, launch: &ServiceLaunch) -> LaunchOutcome {
        // A service that is not a worker belongs to no login session, so it names no session type
        // and is bootstrapped into this user's graphical domain, where the daemon itself is.
        self.start_job(
            launch,
            &format!("gui/{}", kr_ipc::paths::current_uid()),
            None,
        )
    }

    fn describe(&self) -> String {
        "launchd, one bootstrapped job per session: the user's graphical domain for a \
         desktop-bound session and the background domain for a headless one"
            .to_owned()
    }
}

#[cfg(target_os = "macos")]
impl LaunchdSupervisor {
    /// Bootstraps one job into a domain and starts it.
    fn start_job(
        &self,
        launch: &ServiceLaunch,
        domain: &str,
        session_type: Option<&str>,
    ) -> LaunchOutcome {
        let label = launch.label.clone();
        // Writing the job definition and loading it start nothing: `RunAtLoad` is false, so until
        // the kickstart there is no process to be uncertain about.
        let job = match Self::write_job(launch, session_type) {
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
            &["bootstrap", domain, &job.display().to_string()],
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
        // A worker's unit carries the selected desktop's own handles. Every other service this
        // manager starts carries none, because nothing else here belongs to a login session.
        self.start_unit(&launch.service(), &launch.desktop_environment)
    }

    fn start_service(&self, launch: &ServiceLaunch) -> LaunchOutcome {
        self.start_unit(launch, &[])
    }

    fn describe(&self) -> String {
        "systemd, one transient user service per session".to_owned()
    }
}

#[cfg(target_os = "linux")]
impl SystemdSupervisor {
    /// Starts one transient unit, with whatever login-session environment its launch carries.
    fn start_unit(&self, launch: &ServiceLaunch, desktop: &[(String, String)]) -> LaunchOutcome {
        let unit = launch.label.clone();
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
        ];
        // The selected desktop's own handles, passed to the unit rather than left to whatever the
        // user manager happens to hold. A manager started at boot holds none of them. They are
        // options to the launcher, so they go before the program it is told to start.
        for (name, value) in desktop {
            arguments.push(format!("--setenv={name}={value}"));
        }
        // Every other handle a login session publishes is removed from what the unit inherits.
        // Setting the collected ones is not enough on its own: the user manager holds one
        // environment for the whole user, so a handle this host did not collect would reach the
        // worker from whichever login imported it, and a worker watching one desktop while its
        // tools reach another is what an execution context has to rule out. The two lists are
        // disjoint, which is what lets this stand although the manager applies it last.
        let cleared: Vec<&str> = crate::desktop::agent::session_variables()
            .into_iter()
            .filter(|name| !desktop.iter().any(|(set, _)| set == name))
            .collect();
        if !cleared.is_empty() {
            arguments.push(format!("--property=UnsetEnvironment={}", cleared.join(" ")));
        }
        arguments.push(launch.program.display().to_string());
        arguments.extend(launch.arguments.clone());
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
        // A worker is given the selected desktop's own handles; nothing else this supervisor
        // starts belongs to a login session, so nothing else is given any.
        self.spawn(&launch.service(), &launch.desktop_environment)
    }

    fn start_service(&self, launch: &ServiceLaunch) -> LaunchOutcome {
        self.spawn(launch, &[])
    }

    fn describe(&self) -> String {
        "a detached process in its own group, reparented to init when this daemon exits".to_owned()
    }
}

impl DetachedSupervisor {
    /// Starts one process, with whatever login-session environment its launch carries.
    fn spawn(&self, launch: &ServiceLaunch, desktop: &[(String, String)]) -> LaunchOutcome {
        match detached_command(
            &launch.program,
            &launch.arguments,
            &launch.working_directory,
            desktop,
        ) {
            Ok(child) => settle(child),
            // The spawn itself failed, so no process exists.
            Err(error) => LaunchOutcome::NotStarted {
                detail: error.to_string(),
            },
        }
    }
}

#[cfg(unix)]
fn detached_command(
    program: &Path,
    arguments: &[String],
    working_directory: &Path,
    desktop: &[(String, String)],
) -> Result<u32> {
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
    // This supervisor launches from the daemon's own environment, so a desktop-bound worker is
    // given the selected login session's handles explicitly rather than inheriting whatever the
    // daemon was started with.
    command.envs(desktop.iter().map(|(name, value)| (name, value)));
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
fn detached_command(
    program: &Path,
    arguments: &[String],
    working_directory: &Path,
    desktop: &[(String, String)],
) -> Result<u32> {
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
    command.envs(desktop.iter().map(|(name, value)| (name, value)));
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

/// Opens a local terminal window on a session this host created.
///
/// Section 7's `terminal` presentation opens an installed terminal application running `kr attach`
/// on the new session, and a session created on a remote device can ask for one too: the daemon is
/// the only party on this host that can open it. Opening one is a separate step from creating the
/// session, so a host that cannot open a window still has the session and says so.
pub trait TerminalPresenter: Send + Sync + std::fmt::Debug {
    /// Opens a window running `command`, and says which application took it.
    ///
    /// `requested` is the application the create request named, which is the first step of section
    /// 7's order and an error rather than a substitution when this host does not have it.
    ///
    /// # Errors
    ///
    /// Returns why no window appeared. The session it was for exists either way.
    fn present(
        &self,
        requested: Option<&str>,
        command: &[String],
    ) -> std::result::Result<Selection, TerminalUnavailable>;

    /// Names this presenter for diagnostics.
    fn describe(&self) -> String;
}

/// The terminal applications installed on this host.
#[derive(Debug, Clone, Copy, Default)]
pub struct InstalledTerminals;

impl TerminalPresenter for InstalledTerminals {
    fn present(
        &self,
        requested: Option<&str>,
        command: &[String],
    ) -> std::result::Result<Selection, TerminalUnavailable> {
        // The order section 7 fixes: what the request named, then the saved preference, then what
        // is detected. This host keeps no saved terminal preference, so the middle step has
        // nothing to offer and detection decides where the request named nothing.
        let available = terminal::detect();
        let selection = terminal::select(requested, None, &available)?;
        terminal::open(&selection, command)?;
        Ok(selection)
    }

    fn describe(&self) -> String {
        "the terminal applications installed on this host".to_owned()
    }
}

/// A host with no terminal application to open.
///
/// A headless installation has no window server and no desktop launcher, so a presentation request
/// is answered with the session and the reason rather than with a window.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoTerminal;

impl TerminalPresenter for NoTerminal {
    fn present(
        &self,
        _requested: Option<&str>,
        _command: &[String],
    ) -> std::result::Result<Selection, TerminalUnavailable> {
        Err(TerminalUnavailable::NoneAvailable)
    }

    fn describe(&self) -> String {
        "a host with no terminal application".to_owned()
    }
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
            desktop_environment: Vec::new(),
            profile: WorkerProfile::HeadlessUser,
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
    fn a_worker_launch_is_a_service_launch_with_a_worker_in_it() {
        let launch = launch();
        let service = launch.service();
        assert_eq!(service.label, launch.label());
        assert_eq!(service.program, launch.program);
        assert_eq!(service.arguments, launch.arguments());
        assert_eq!(service.jobs_directory, launch.jobs_directory);
    }

    #[test]
    fn a_platform_supervisor_starts_a_worker_through_the_service_path() {
        // Every platform supervisor's `start` is its `start_service` with a worker's job
        // description, so the two paths cannot diverge.
        #[derive(Debug, Default)]
        struct Recording(std::sync::Mutex<Vec<ServiceLaunch>>);

        impl WorkerSupervisor for Recording {
            fn start(&self, launch: &WorkerLaunch) -> LaunchOutcome {
                self.start_service(&launch.service())
            }

            fn start_service(&self, launch: &ServiceLaunch) -> LaunchOutcome {
                if let Ok(mut recorded) = self.0.lock() {
                    recorded.push(launch.clone());
                }
                LaunchOutcome::NotStarted {
                    detail: "this supervisor records rather than starts".to_owned(),
                }
            }

            fn describe(&self) -> String {
                "a recording supervisor".to_owned()
            }
        }

        let supervisor = Recording::default();
        let launch = launch();
        let outcome = supervisor.start(&launch);
        assert!(matches!(outcome, LaunchOutcome::NotStarted { .. }));
        let recorded = supervisor.0.lock().expect("the recording");
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].label, launch.label());
        assert_eq!(recorded[0].arguments, launch.arguments());
    }

    #[test]
    fn a_supervisor_that_cannot_start_a_service_says_which_one() {
        #[derive(Debug)]
        struct WorkersOnly;

        impl WorkerSupervisor for WorkersOnly {
            fn start(&self, _launch: &WorkerLaunch) -> LaunchOutcome {
                LaunchOutcome::NotStarted {
                    detail: "not in this test".to_owned(),
                }
            }

            fn describe(&self) -> String {
                "a supervisor for workers only".to_owned()
            }
        }

        let outcome = WorkersOnly.start_service(&ServiceLaunch {
            label: "kr-plugin-host-1".to_owned(),
            program: PathBuf::from("/usr/local/bin/kr-plugin-host"),
            arguments: Vec::new(),
            jobs_directory: PathBuf::from("/var/lib/kr/jobs"),
            working_directory: PathBuf::from("/var/lib/kr/services/kr-plugin-host-1"),
        });
        let LaunchOutcome::NotStarted { detail } = outcome else {
            panic!("a supervisor that cannot start a service started one");
        };
        assert!(detail.contains("kr-plugin-host-1"));
        assert!(detail.contains("workers only"));
    }

    #[test]
    fn the_job_label_names_the_reservation() {
        assert_eq!(
            launch().label(),
            "kr-worker-01010101-0101-0101-0101-010101010101"
        );
    }

    /// The job definition a service manager reads names the directory the process runs in.
    ///
    /// A launched process inheriting a directory is the thing this prevents: the launcher's
    /// directory is whoever started the daemon's, and a service manager's is the system's. It holds
    /// for every service this host starts, not only for workers, which is why the job is written
    /// from a service launch.
    #[cfg(target_os = "macos")]
    #[test]
    fn the_job_definition_names_the_directory_the_worker_runs_in() {
        let host = kr_ipc::testing::TempHost::create();
        let mut launch = launch();
        launch.jobs_directory = host.environment().jobs_dir();
        let job = LaunchdSupervisor::write_job(&launch.service(), Some("Aqua"))
            .expect("writes the job definition");
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
    fn a_headless_worker_is_started_outside_the_graphical_login() {
        let uid = kr_ipc::paths::current_uid();
        assert_eq!(
            LaunchdSupervisor::domain(WorkerProfile::DesktopBound),
            format!("gui/{uid}"),
            "a desktop-bound worker belongs in the graphical login session"
        );
        assert_eq!(
            LaunchdSupervisor::domain(WorkerProfile::HeadlessUser),
            format!("user/{uid}"),
            "a headless worker belongs outside it, or it would inherit its access"
        );
        assert_eq!(
            LaunchdSupervisor::session_type(WorkerProfile::DesktopBound),
            "Aqua"
        );
        assert_eq!(
            LaunchdSupervisor::session_type(WorkerProfile::HeadlessUser),
            "Background"
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
