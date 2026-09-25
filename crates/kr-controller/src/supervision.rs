//! Starting a worker through the platform's own service manager.
//!
//! A worker's lifetime must not belong to the control daemon. If it did, restarting the daemon
//! would close every session, which is the one thing section 2 forbids outright. So the daemon
//! asks the platform to start the worker and then lets go of it:
//!
//! | Platform | How the worker is started | Where its identity comes from |
//! | --- | --- | --- |
//! | macOS | a per-session launchd job, bootstrapped into the domain the profile names and started once with `launchctl kickstart -p` | the kickstart output's process identifier, then `proc_pidinfo` |
//! | Linux with systemd | a transient user *service*, `systemd-run --user --unit=... --collect -p Type=exec -p Restart=no` | `systemctl --user show -p MainPID`, then `/proc/<pid>/stat` |
//! | other Unix | a `setsid` launch, reparented to init | the spawned child's identifier, then `/proc` or `proc_pidinfo` |
//! | Windows | the spawned child, outside the daemon's kill-on-close Job | the child's identifier and creation time |
//!
//! `kickstart -p` and not `-k`: the second would restart a job that is already running, which for
//! a session worker would mean killing a live shell to start another one.
//!
//! launchd keeps a job loaded after its process has exited, until something removes it. So a
//! worker's job is removed once the worker has ended, by [`retire_worker_job`]: when a closure is
//! recorded and the kernel then says the worker's process has gone, and, for every job this
//! environment still has defined, when the daemon starts. A job whose process is still running is
//! never removed, because removing it would end that process. The other supervisors leave no job
//! of this kind behind: a systemd transient service is started with `--collect`, so the manager
//! drops it once its process has ended, whether that process succeeded or failed, and the fallback
//! supervisor defines no job at all.
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
        worker_label(self.reservation_id)
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

/// Returns the job label the worker started for `reservation_id` runs under.
#[must_use]
pub fn worker_label(reservation_id: ReservationId) -> String {
    format!("kr-worker-{reservation_id}")
}

/// Where the definition of the job labelled `label` is written.
fn job_definition(jobs_directory: &Path, label: &str) -> PathBuf {
    jobs_directory.join(format!("{label}.plist"))
}

/// What removing an ended worker's job found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JobRetirement {
    /// Nothing of the job is left: the service manager no longer has it, and its definition has
    /// gone with it. A job this environment never defined, or never loaded, ends here too.
    Gone,
    /// The job's process is still running, so the job was left exactly as it was.
    StillRunning,
    /// What the service manager holds could not be established, or the removal did not take. The
    /// definition is kept, so the next look finds the job again.
    Unsettled(String),
}

/// Returns the reservation of every worker job this environment has a definition for.
///
/// A definition is written before its job is loaded and removed only once the job has gone, so
/// this is every worker job this environment may still have loaded. A file whose name is not a
/// worker job definition, spelt exactly as this host writes one, is not listed: this host does not
/// remove what it did not write.
#[must_use]
pub fn defined_worker_jobs(jobs_directory: &Path) -> Vec<ReservationId> {
    let Ok(entries) = std::fs::read_dir(jobs_directory) else {
        return Vec::new();
    };
    let mut defined: Vec<ReservationId> = entries
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name();
            let label = name.to_str()?.strip_suffix(".plist")?;
            let reservation_id: ReservationId = label.strip_prefix("kr-worker-")?.parse().ok()?;
            (worker_label(reservation_id) == label).then_some(reservation_id)
        })
        .collect();
    defined.sort();
    defined
}

/// Whether this environment has a definition for the job of the worker started for
/// `reservation_id`.
#[must_use]
pub fn defines_worker_job(jobs_directory: &Path, reservation_id: ReservationId) -> bool {
    std::fs::symlink_metadata(job_definition(
        jobs_directory,
        &worker_label(reservation_id),
    ))
    .is_ok()
}

/// Removes what the service manager keeps of a worker's job, once that job's process has ended.
///
/// [`retire_service_job`] for the job of the worker started for `reservation_id`.
#[must_use]
pub fn retire_worker_job(jobs_directory: &Path, reservation_id: ReservationId) -> JobRetirement {
    retire_service_job(jobs_directory, &worker_label(reservation_id))
}

/// Removes what the service manager keeps of one service's job, once that job's process has ended.
///
/// launchd keeps a job loaded after its process exits until something removes it, so without
/// this every session, and every plugin host, would leave one behind for as long as the machine
/// runs. A job whose process is still running is left exactly as it is: removing it would end that
/// process, and a service is ended by its own closure, never by taking its job away. Only a job this
/// environment defined is looked at, under a label this host gives one, and only the job itself and
/// its definition are removed; the diagnostics the job wrote stay where a person can read them.
///
/// The labels this host gives a job are a worker's, `kr-worker-<reservation>`, and a plugin
/// host's, `kr-plugin-host-<reservation>`, each spelt exactly as this host spells it. Any other
/// label is refused rather than looked at, so a file somebody else put in the jobs directory never
/// has a job of that name taken away.
///
/// Only launchd keeps a job of this kind, so on every other platform there is nothing to remove.
#[must_use]
pub fn retire_service_job(jobs_directory: &Path, label: &str) -> JobRetirement {
    if !is_service_label(label) {
        return JobRetirement::Unsettled(format!(
            "{label} is not a label this host gives a job, so it is left alone"
        ));
    }
    #[cfg(target_os = "macos")]
    {
        LaunchdSupervisor::retire(jobs_directory, label)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = jobs_directory;
        JobRetirement::Gone
    }
}

/// The start of each label this host gives a job, before the reservation it was started for.
const SERVICE_LABEL_PREFIXES: [&str; 2] = ["kr-worker-", "kr-plugin-host-"];

/// Whether `label` is one this host gives a job, spelt exactly as this host spells it.
fn is_service_label(label: &str) -> bool {
    SERVICE_LABEL_PREFIXES.iter().any(|prefix| {
        label
            .strip_prefix(prefix)
            .and_then(|reservation| reservation.parse::<ReservationId>().ok())
            .is_some_and(|reservation_id| format!("{prefix}{reservation_id}") == label)
    })
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
    ///
    /// Words written in this source. The name reaches a diagnostic check and a paired device's
    /// answer about what a logout does here, so a supervisor that composed it from something the
    /// platform reported would be sending that text out of this host.
    fn describe(&self) -> &'static str;

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
    ///
    /// Asked within [`SERVICE_MANAGER_BOUND`]: a launchd that does not answer is not one this
    /// host can start a worker through either.
    #[must_use]
    pub fn available() -> bool {
        launchctl_within(&["print", &format!("gui/{}", kr_ipc::paths::current_uid())])
            .is_ok_and(|output| output.status.success())
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
        let path = job_definition(&launch.jobs_directory, &label);
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

    fn describe(&self) -> &'static str {
        "launchd, one bootstrapped job per session: the user's graphical domain for a \
         desktop-bound session and the background domain for a headless one"
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

    /// Removes one job this environment defined, once its process has ended, from whichever of
    /// this user's two domains has it, and then its definition.
    ///
    /// What a removal said where it failed and the job went all the same is reported here, apart
    /// from the answer: the job is gone, and a launchctl that could not be ended or collected is
    /// still something a person reading this daemon's log should see.
    fn retire(jobs_directory: &Path, label: &str) -> JobRetirement {
        let uid = kr_ipc::paths::current_uid();
        let (retirement, said) = Self::retire_from(
            jobs_directory,
            label,
            &[format!("gui/{uid}"), format!("user/{uid}")],
        );
        for failure in said {
            eprintln!("kr-controller: {failure}");
        }
        retirement
    }

    /// Removes one job this environment defined, once its process has ended, from whichever of
    /// `domains` has it, and then its definition.
    ///
    /// Removing a job whose process has ended ends nothing, and nothing starts that job again
    /// between the look and the removal: it is neither run at load nor kept alive, and this host
    /// starts it once, before any of this. A job launchd describes as anything but not running is
    /// treated as running and left alone, so a description this build does not recognise costs a
    /// job left loaded rather than a process ended. A domain that does not exist, such as the
    /// graphical domain of a user who has logged out, has nothing loaded in it, and the next domain
    /// is looked at all the same.
    ///
    /// Returns the answer, and beside it what each removal said where it failed and the job was
    /// gone afterwards all the same: a removal that did not answer, or a launchctl that could not
    /// be ended or collected, is reported rather than dropped because the job went anyway.
    fn retire_from(
        jobs_directory: &Path,
        label: &str,
        domains: &[String],
    ) -> (JobRetirement, Vec<String>) {
        let definition = job_definition(jobs_directory, label);
        match std::fs::symlink_metadata(&definition) {
            Ok(_) => {}
            // Written before a job is loaded and removed only once it has gone, so a job with no
            // definition here is not one this environment has loaded.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return (JobRetirement::Gone, Vec::new());
            }
            Err(error) => {
                return (
                    JobRetirement::Unsettled(format!("{}: {error}", definition.display())),
                    Vec::new(),
                );
            }
        }
        let mut said = Vec::new();
        for domain in domains {
            let target = format!("{domain}/{label}");
            match job_state(&target) {
                JobState::NotLoaded => continue,
                JobState::Running => return (JobRetirement::StillRunning, said),
                JobState::Unknown(detail) => return (JobRetirement::Unsettled(detail), said),
                JobState::Ended => {}
            }
            // Whether the removal took is read back from launchd rather than from this command's
            // own answer: a job something else removed a moment earlier is gone all the same.
            let failure = removal_failure(&target, &launchctl_within(&["bootout", &target]));
            // Whatever the look after it says, what the removal itself said goes with the answer.
            let removal_said = failure.as_deref().map_or_else(String::new, |failure| {
                format!("; removing it said: {failure}")
            });
            match job_state(&target) {
                JobState::NotLoaded => {
                    said.extend(failure.map(|failure| {
                        format!("{target} is gone, and removing it said: {failure}")
                    }))
                }
                JobState::Unknown(detail) => {
                    return (
                        JobRetirement::Unsettled(format!("{detail}{removal_said}")),
                        said,
                    );
                }
                JobState::Running | JobState::Ended => {
                    return (
                        JobRetirement::Unsettled(format!(
                            "{target} is still loaded after it was removed{removal_said}"
                        )),
                        said,
                    );
                }
            }
        }
        let retirement = match std::fs::remove_file(&definition) {
            Ok(()) => JobRetirement::Gone,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => JobRetirement::Gone,
            Err(error) => JobRetirement::Unsettled(format!("{}: {error}", definition.display())),
        };
        (retirement, said)
    }
}

/// What removing a job said, where it said anything but that it removed it.
#[cfg(target_os = "macos")]
fn removal_failure(
    target: &str,
    removal: &std::result::Result<std::process::Output, String>,
) -> Option<String> {
    match removal {
        Ok(output) if output.status.success() => None,
        Ok(output) => Some(format!(
            "launchctl bootout {target} answered {:?}: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr).trim()
        )),
        Err(detail) => Some(detail.clone()),
    }
}

/// What launchd says about one job.
#[cfg(target_os = "macos")]
#[derive(Debug)]
enum JobState {
    /// launchd does not have the job in that domain.
    NotLoaded,
    /// The job is loaded and its process is running, or launchd describes it some other way.
    Running,
    /// The job is loaded and has no process.
    Ended,
    /// launchd's answer could not be read.
    Unknown(String),
}

/// How long one command put to a service manager is given to answer: a question, a removal, a
/// load or a start.
#[cfg(any(target_os = "macos", target_os = "linux"))]
const SERVICE_MANAGER_BOUND: std::time::Duration = std::time::Duration::from_secs(10);

/// How long a command that did not answer is given to be collected once it has been ended.
#[cfg(any(target_os = "macos", target_os = "linux"))]
const COLLECT_BOUND: std::time::Duration = std::time::Duration::from_secs(5);

/// Runs `launchctl` within [`SERVICE_MANAGER_BOUND`], and returns its answer or why there was none.
#[cfg(target_os = "macos")]
fn launchctl_within(arguments: &[&str]) -> std::result::Result<std::process::Output, String> {
    command_within("/bin/launchctl", arguments, SERVICE_MANAGER_BOUND)
        .map_err(|failure| failure.detail())
}

/// Runs one service-manager command, gives it `bound` to answer, and returns its answer or why there
/// was none.
///
/// What it prints is read while it runs, so an answer of any size cannot stall it. It is this
/// process's own child: one that did not answer, could not be waited for, or whose output could not
/// be read is ended and given [`COLLECT_BOUND`] to be collected. The two are deadlines on the
/// command and on its collection; starting it and its readers, and taking in what a collected one
/// left in its pipes, come on top of them. A failure to end or collect it is part of what this
/// returns, and the readers of a command that was not collected are left to finish by themselves.
///
/// A command that could not be started at all is [`RunFailure::NotRun`]; every failure after it
/// started is [`RunFailure::Failed`], because it may have reached the service manager first.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn command_within(
    program: &str,
    arguments: &[&str],
    bound: std::time::Duration,
) -> std::result::Result<std::process::Output, RunFailure> {
    let asked = format!("{program} {}", arguments.join(" "));
    let mut child = std::process::Command::new(program)
        .args(arguments)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|error| RunFailure::NotRun(format!("{program}: {error}")))?;
    let printed = match child.stdout.take().map(read_to_the_end_aside).transpose() {
        Ok(reader) => reader,
        Err(error) => {
            let detail = format!("{asked}: its answer could not be read: {error}");
            return Err(RunFailure::Failed(end_and_collect(&mut child, detail).0));
        }
    };
    let said = match child.stderr.take().map(read_to_the_end_aside).transpose() {
        Ok(reader) => reader,
        Err(error) => {
            let detail = format!("{asked}: what it said could not be read: {error}");
            return Err(RunFailure::Failed(end_and_collect(&mut child, detail).0));
        }
    };
    let deadline = std::time::Instant::now() + bound;
    let ended = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Ok(None) => {
                break Err(format!("{asked} did not answer within {bound:?}"));
            }
            Err(error) => {
                break Err(format!("{asked} could not be waited for: {error}"));
            }
        }
    };
    let (ended, collected) = match ended {
        Ok(status) => (Ok(status), true),
        Err(detail) => {
            let (detail, collected) = end_and_collect(&mut child, detail);
            (Err(RunFailure::Failed(detail)), collected)
        }
    };
    // A collected command has closed its pipes, so both readers have finished or are about to.
    let read = |reader: Option<std::thread::JoinHandle<Vec<u8>>>| {
        reader
            .filter(|_| collected)
            .and_then(|reader| reader.join().ok())
            .unwrap_or_default()
    };
    let (stdout, stderr) = (read(printed), read(said));
    ended.map(|status| std::process::Output {
        status,
        stdout,
        stderr,
    })
}

/// Ends a command this process started and has not collected, and collects it within
/// [`COLLECT_BOUND`]. Returns `detail` with whatever of that failed added to it, and whether the
/// command was collected.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn end_and_collect(child: &mut std::process::Child, mut detail: String) -> (String, bool) {
    if let Err(error) = child.kill() {
        detail.push_str(&format!("; ending it failed: {error}"));
    }
    let deadline = std::time::Instant::now() + COLLECT_BOUND;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return (detail, true),
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Ok(None) => {
                detail.push_str(&format!(
                    "; it was still running {COLLECT_BOUND:?} after it was ended"
                ));
                return (detail, false);
            }
            Err(error) => {
                detail.push_str(&format!("; collecting it failed: {error}"));
                return (detail, false);
            }
        }
    }
}

/// Reads a pipe to its end on a thread of its own, or says why no thread could be made for it.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn read_to_the_end_aside(
    mut pipe: impl std::io::Read + Send + 'static,
) -> std::io::Result<std::thread::JoinHandle<Vec<u8>>> {
    std::thread::Builder::new()
        .name("service manager output".to_owned())
        .spawn(move || {
            let mut bytes = Vec::new();
            let _ = pipe.read_to_end(&mut bytes);
            bytes
        })
}

/// Asks launchd about one job, `<domain>/<label>`.
#[cfg(target_os = "macos")]
fn job_state(target: &str) -> JobState {
    match launchctl_within(&["print", target]) {
        Ok(output) => job_state_answered(
            target,
            output.status.code(),
            &String::from_utf8_lossy(&output.stdout),
            &String::from_utf8_lossy(&output.stderr),
        ),
        Err(detail) => JobState::Unknown(detail),
    }
}

/// Reads what `launchctl print <domain>/<label>` answered: its exit code, its description of the
/// job, and what it said when it would not describe one.
#[cfg(target_os = "macos")]
fn job_state_answered(target: &str, code: Option<i32>, printed: &str, said: &str) -> JobState {
    /// What `launchctl print` exits with for a domain that does not exist.
    const NO_SUCH_DOMAIN: i32 = 112;
    /// What `launchctl print` exits with for a job the domain does not have.
    const NOT_LOADED: i32 = 113;

    match code {
        Some(0) => job_state_described(printed),
        // A job cannot be loaded in a domain that is not there.
        Some(NO_SUCH_DOMAIN | NOT_LOADED) => JobState::NotLoaded,
        _ => JobState::Unknown(format!(
            "launchctl print {target} answered {code:?}: {}",
            said.trim()
        )),
    }
}

/// Reads whether a loaded job has a process from launchd's description of it.
///
/// The job's own state is at the first level of the description, one tab in. Sections nested
/// inside it carry states of their own, which say nothing about the job's process.
#[cfg(target_os = "macos")]
fn job_state_described(description: &str) -> JobState {
    let not_running = description
        .lines()
        .any(|line| line == "\tstate = not running");
    let has_process = description.lines().any(|line| line.starts_with("\tpid = "));
    if not_running && !has_process {
        JobState::Ended
    } else {
        JobState::Running
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
    ///
    /// Asked within [`SERVICE_MANAGER_BOUND`]: a manager that does not answer is not one this host
    /// can start a worker through either.
    #[must_use]
    pub fn available() -> bool {
        // A user manager that answers a property query is a user manager that exists. Running
        // `systemctl` successfully proves only that the binary is installed, which a host with no
        // user manager also has.
        command_within(
            "systemctl",
            &["--user", "show", "--property=Version", "--value"],
            SERVICE_MANAGER_BOUND,
        )
        .is_ok_and(|output| output.status.success())
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

    fn describe(&self) -> &'static str {
        "systemd, one transient user service per session"
    }
}

#[cfg(target_os = "linux")]
impl SystemdSupervisor {
    /// Starts one transient unit, with whatever login-session environment its launch carries.
    fn start_unit(&self, launch: &ServiceLaunch, desktop: &[(String, String)]) -> LaunchOutcome {
        let unit = launch.label.clone();
        // A transient *service*, not a scope: `MainPID` is defined for a service, so the launcher
        // has an identity to record. A scope would leave the controller guessing.
        // `--collect`, so the manager drops the unit once its process has ended however it ended.
        // Without it a unit whose process failed stays listed, failed, until somebody resets it,
        // and nothing here ever would.
        let mut arguments = vec![
            "--user".to_owned(),
            format!("--unit={unit}"),
            "--collect".to_owned(),
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

    fn describe(&self) -> &'static str {
        "a detached process in its own group, reparented to init when this daemon exits"
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

    const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x0100_0000;
    const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
    const DETACHED_PROCESS: u32 = 0x0000_0008;

    // A worker must outlive this daemon. Section 7 asks for it to be independent of the daemon's
    // kill-on-close job, not to break away from every job it might be in: where the daemon runs in
    // no job, or in a job that does not kill its members when it closes, the worker already outlives
    // the daemon and no breakaway is needed or asked for. Breakaway is asked for only when the
    // daemon's own job would kill the worker on close, and that is also the one case where a job
    // that forbids breakaway turns the start into the named failure below.
    let job_flags = kr_ipc::paths::current_job_limit_flags().map_err(|error| {
        ControllerError::supervision(format!("read this process's job: {error}"))
    })?;
    let break_away = worker_must_break_away(job_flags);
    let mut flags = CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS;
    if break_away {
        flags |= CREATE_BREAKAWAY_FROM_JOB;
    }

    let mut command = std::process::Command::new(program);
    command.creation_flags(flags);
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
        // A start that asked to break away is refused with access denied when the daemon's
        // kill-on-close job does not permit breakaway, such as the one a test runner or
        // `cargo test` places its processes in. A worker must outlive the daemon, so it cannot join
        // that job; naming the cause and the setup, rather than the bare "access is denied", is what
        // a person can act on. The start fails here at once and never waits.
        const ERROR_ACCESS_DENIED: i32 = 5;
        if break_away && error.raw_os_error() == Some(ERROR_ACCESS_DENIED) {
            return ControllerError::supervision(format!(
                "could not start a worker as a process independent of this daemon: this daemon runs \
                 inside a job object that kills its members when it closes and does not permit \
                 breakaway, so a worker started here would be killed with the daemon and cannot be \
                 made to outlive it. Run the control daemon outside such a job, through its per-user \
                 service, so a worker can start as an independent process ({})",
                program.display()
            ));
        }
        ControllerError::supervision(format!("start {}: {error}", program.display()))
    })?;
    Ok(child.id())
}

/// Whether a Windows worker this daemon starts must be created outside the daemon's job.
///
/// A worker outlives the daemon, so it must not be a member of a job that kills its members when
/// the daemon closes. `job_flags` is the daemon's own job's limit flags, or `None` when it runs in
/// no job. Breakaway is asked for only when that job kills on close; with no job, or a job that does
/// not kill on close, the worker already outlives the daemon and joining the job is harmless.
#[cfg(not(unix))]
#[must_use]
fn worker_must_break_away(job_flags: Option<u32>) -> bool {
    // `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`.
    const KILL_ON_JOB_CLOSE: u32 = 0x0000_2000;
    job_flags.is_some_and(|flags| flags & KILL_ON_JOB_CLOSE != 0)
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

/// Runs a service manager's command within [`SERVICE_MANAGER_BOUND`] and returns what it printed.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn run(program: &str, arguments: &[&str]) -> std::result::Result<String, RunFailure> {
    let output = command_within(program, arguments, SERVICE_MANAGER_BOUND)?;
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
#[derive(Debug, Clone)]
pub struct InstalledTerminals {
    /// The environment's state directory, where its saved terminal preference is kept.
    state_dir: PathBuf,
}

impl InstalledTerminals {
    /// Returns a presenter that reads one environment's saved preference.
    #[must_use]
    pub const fn in_environment(state_dir: PathBuf) -> Self {
        Self { state_dir }
    }
}

impl TerminalPresenter for InstalledTerminals {
    fn present(
        &self,
        requested: Option<&str>,
        command: &[String],
    ) -> std::result::Result<Selection, TerminalUnavailable> {
        // The order section 7 fixes: what the request named, then this environment's saved
        // preference, then what is detected. A preference that names something no longer installed
        // is not an error, because nobody asked for it just now; a request that does is.
        let available = terminal::detect();
        let preference = terminal::saved_preference(&self.state_dir);
        let selection = terminal::select(requested, preference.as_deref(), &available)?;
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

    /// A Windows worker breaks away from the daemon's job only when that job would kill it when the
    /// daemon closes. The four contexts measured on real machines, each by the limit flags its job
    /// carries, with the outcome the start then has.
    #[cfg(not(unix))]
    #[test]
    fn a_worker_breaks_away_only_from_a_kill_on_close_job() {
        const KILL_ON_JOB_CLOSE: u32 = 0x0000_2000;
        const BREAKAWAY_OK: u32 = 0x0000_0800;

        // A scheduled task, as `win-run.sh` starts one: no job, so the worker already outlives the
        // daemon and the start is an ordinary create.
        assert!(!worker_must_break_away(None));
        // A hosted continuous-integration runner: a job with no kill-on-close (flags 0x0), so the
        // worker outlives the daemon and the start is an ordinary create.
        assert!(!worker_must_break_away(Some(0)));
        // An interactive or SSH logon: a job that kills on close but permits breakaway, so the start
        // asks to break away and is admitted.
        assert!(worker_must_break_away(Some(
            KILL_ON_JOB_CLOSE | BREAKAWAY_OK
        )));
        // `cargo test`: a job that kills on close and forbids breakaway, so the start asks to break
        // away and is refused, which the daemon reports as its named failure.
        assert!(worker_must_break_away(Some(KILL_ON_JOB_CLOSE)));
    }

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

            fn describe(&self) -> &'static str {
                "a recording supervisor"
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

            fn describe(&self) -> &'static str {
                "a supervisor for workers only"
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

    /// A file in the jobs directory is listed as a worker job only where this host wrote it.
    #[test]
    fn only_a_worker_job_definition_this_host_writes_is_listed() {
        let host = kr_ipc::testing::TempHost::create();
        let jobs = host.environment().jobs_dir();
        let defined = ReservationId::new(Uuid::from_bytes([4; 16]));
        // Letters in it, so that its spelling in capitals is another spelling.
        let other = ReservationId::new(Uuid::from_bytes([0xab; 16]));
        for name in [
            format!("{}.plist", worker_label(defined)),
            // What a job wrote, rather than a job.
            format!("{}.diagnostics", worker_label(other)),
            // Another kind of service's job.
            format!("kr-plugin-host-{other}.plist"),
            // Names this host never writes.
            "kr-worker-not-a-reservation.plist".to_owned(),
            format!("kr-worker-{}.plist", other.to_string().to_uppercase()),
        ] {
            std::fs::write(jobs.join(name), b"").expect("writes a file");
        }
        assert_eq!(defined_worker_jobs(&jobs), vec![defined]);
        assert!(defines_worker_job(&jobs, defined));
        // Not `other`: a volume that ignores case holds its capitalised file under this name too.
        assert!(!defines_worker_job(
            &jobs,
            ReservationId::new(Uuid::from_bytes([6; 16]))
        ));
    }

    /// A job this environment never defined is gone as far as this environment is concerned.
    #[test]
    fn a_job_this_environment_never_defined_is_gone() {
        let host = kr_ipc::testing::TempHost::create();
        assert_eq!(
            retire_worker_job(
                &host.environment().jobs_dir(),
                ReservationId::new(kr_ipc::new_uuid())
            ),
            JobRetirement::Gone
        );
    }

    /// launchd's description of a job is read at its own level, and only a job it describes as not
    /// running with no process counts as ended.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_job_has_ended_only_where_launchd_says_it_has_no_process() {
        let ended = "gui/501/kr-worker-x = {\n\tactive count = 0\n\tstate = not running\n\n\
                     \tendpoints = {\n\t\tstate = active\n\t}\n}\n";
        assert!(matches!(job_state_described(ended), JobState::Ended));
        let running = "gui/501/kr-worker-x = {\n\tactive count = 1\n\tstate = running\n\
                       \tpid = 4242\n}\n";
        assert!(matches!(job_state_described(running), JobState::Running));
        // A nested section's state says nothing about the job's own process.
        let nested = "gui/501/kr-worker-x = {\n\tendpoints = {\n\t\tstate = not running\n\t}\n}\n";
        assert!(matches!(job_state_described(nested), JobState::Running));
        // A description this build does not recognise leaves the job where it is.
        let unknown = "gui/501/kr-worker-x = {\n\tstate = spawn scheduled\n}\n";
        assert!(matches!(job_state_described(unknown), JobState::Running));
        assert!(matches!(job_state_described(""), JobState::Running));
    }

    /// A launchd job this test defined, removed from both of this user's domains when the test
    /// ends, however it ends.
    #[cfg(target_os = "macos")]
    struct OwnJob(String);

    #[cfg(target_os = "macos")]
    impl Drop for OwnJob {
        fn drop(&mut self) {
            let uid = kr_ipc::paths::current_uid();
            for domain in ["gui", "user"] {
                let _ = launchctl_within(&["bootout", &format!("{domain}/{uid}/{}", self.0)]);
            }
        }
    }

    /// Requires this user's launchd domains, which a job is started into.
    ///
    /// A host without them starts no job of this kind, so there is nothing for these checks to
    /// look at there, and a check that returned early would be counted as one that passed.
    #[cfg(target_os = "macos")]
    fn launchd_domains_are_here() {
        assert!(
            LaunchdSupervisor::available(),
            "this user has no graphical launchd domain on this host, so no job can be started and \
             this check cannot run"
        );
    }

    /// Waits until launchd describes `target` as loaded with no process.
    #[cfg(target_os = "macos")]
    fn until_ended(target: &str) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            match job_state(target) {
                JobState::Ended => return,
                JobState::Running => {}
                other => panic!("launchd does not describe {target} as loaded: {other:?}"),
            }
            assert!(
                std::time::Instant::now() < deadline,
                "{target} still had a process 30 s after it was started"
            );
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }

    /// Starts a worker's job in this user's background domain whose process ends at once, and waits
    /// until launchd describes it as loaded with no process.
    ///
    /// The program is the system's own, which ignores its arguments, and the job runs in `host`'s
    /// own tree on the internal disk. Returns the job's reservation, its label, its target and the
    /// guard that removes it when the test ends.
    #[cfg(target_os = "macos")]
    fn an_ended_worker_job(
        host: &kr_ipc::testing::TempHost,
    ) -> (ReservationId, String, String, OwnJob) {
        let reservation_id = ReservationId::new(kr_ipc::new_uuid());
        let mut launch = launch();
        launch.reservation_id = reservation_id;
        launch.program = PathBuf::from("/usr/bin/true");
        launch.jobs_directory = host.environment().jobs_dir();
        launch.working_directory = host.root().to_path_buf();
        launch.profile = WorkerProfile::HeadlessUser;
        let label = launch.label();
        let own = OwnJob(label.clone());
        let outcome = LaunchdSupervisor::new().start(&launch);
        assert!(
            !matches!(outcome, LaunchOutcome::NotStarted { .. }),
            "the job was started: {outcome:?}"
        );
        let target = format!("user/{}/{label}", kr_ipc::paths::current_uid());
        until_ended(&target);
        (reservation_id, label, target, own)
    }

    /// A worker's job whose process has ended is removed from launchd, and its definition with
    /// it, while what the job wrote stays.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_worker_job_whose_process_has_ended_goes_with_its_definition() {
        launchd_domains_are_here();
        let host = kr_ipc::testing::TempHost::create();
        let jobs = host.environment().jobs_dir();
        let (reservation_id, label, target, _own) = an_ended_worker_job(&host);

        assert_eq!(
            retire_worker_job(&jobs, reservation_id),
            JobRetirement::Gone
        );
        assert!(
            matches!(job_state(&target), JobState::NotLoaded),
            "launchd no longer has the job"
        );
        assert!(
            !defines_worker_job(&jobs, reservation_id),
            "its definition went with it"
        );
        assert!(
            jobs.join(format!("{label}.diagnostics")).exists(),
            "what the job wrote is kept"
        );
        assert_eq!(
            retire_worker_job(&jobs, reservation_id),
            JobRetirement::Gone,
            "and a second look finds nothing left to remove"
        );
    }

    /// A domain that is not there has nothing loaded in it, and the domains after it are still
    /// looked at: the graphical domain of a user who has logged out does not keep an ended
    /// background job loaded.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_domain_that_is_not_there_does_not_stop_the_removal() {
        launchd_domains_are_here();
        // An account that never has a graphical login, so its graphical domain is never there.
        let absent = "gui/1".to_owned();
        let asked = launchctl_within(&["print", &absent]).expect("launchctl answers");
        assert_eq!(
            asked.status.code(),
            Some(112),
            "launchd says {absent} is not there: {}",
            String::from_utf8_lossy(&asked.stderr)
        );
        let host = kr_ipc::testing::TempHost::create();
        let jobs = host.environment().jobs_dir();
        let (_, label, target, _own) = an_ended_worker_job(&host);

        let domains = [absent, format!("user/{}", kr_ipc::paths::current_uid())];
        assert_eq!(
            LaunchdSupervisor::retire_from(&jobs, &label, &domains),
            (JobRetirement::Gone, Vec::new())
        );
        assert!(
            matches!(job_state(&target), JobState::NotLoaded),
            "the job in the domain after the absent one was removed"
        );
    }

    /// What `launchctl print` answered is read by its exit code first: no domain and no job are
    /// both nothing loaded, a description is read for its process, and anything else is unknown.
    #[cfg(target_os = "macos")]
    #[test]
    fn launchds_answer_is_read_by_its_exit_code() {
        let target = "gui/501/kr-worker-x";
        let ended = "gui/501/kr-worker-x = {\n\tstate = not running\n}\n";
        assert!(matches!(
            job_state_answered(target, Some(112), "", "Could not find domain"),
            JobState::NotLoaded
        ));
        assert!(matches!(
            job_state_answered(target, Some(113), "", "Could not find service"),
            JobState::NotLoaded
        ));
        assert!(matches!(
            job_state_answered(target, Some(0), ended, ""),
            JobState::Ended
        ));
        assert!(matches!(
            job_state_answered(target, Some(1), "", "Bad request."),
            JobState::Unknown(_)
        ));
        assert!(matches!(
            job_state_answered(target, None, ended, ""),
            JobState::Unknown(_)
        ));
    }

    /// A worker's job whose process is still running is left loaded, with its process running and
    /// its definition in place.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_worker_job_whose_process_is_running_is_left_alone() {
        launchd_domains_are_here();
        let host = kr_ipc::testing::TempHost::create();
        let jobs = host.environment().jobs_dir();
        let reservation_id = ReservationId::new(kr_ipc::new_uuid());
        let label = worker_label(reservation_id);
        let own = OwnJob(label.clone());
        // The system's own program that stays, under a worker's label in this user's graphical
        // domain.
        let outcome = LaunchdSupervisor::new().start_service(&ServiceLaunch {
            label: label.clone(),
            program: PathBuf::from("/bin/sleep"),
            arguments: vec!["600".to_owned()],
            jobs_directory: jobs.clone(),
            working_directory: host.root().to_path_buf(),
        });
        let LaunchOutcome::Started(identity) = outcome else {
            panic!("the job was started: {outcome:?}");
        };
        let target = format!("gui/{}/{label}", kr_ipc::paths::current_uid());

        assert_eq!(
            retire_worker_job(&jobs, reservation_id),
            JobRetirement::StillRunning
        );
        assert!(
            matches!(job_state(&target), JobState::Running),
            "the job is still loaded"
        );
        assert_eq!(
            kr_ipc::identity::process_state(&identity),
            kr_ipc::identity::ProcessState::Running,
            "and its process was not ended"
        );
        assert!(
            defines_worker_job(&jobs, reservation_id),
            "and its definition is kept for the next look"
        );

        // This test's own job goes, and launchd ends the process in it as it does.
        drop(own);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while kr_ipc::identity::process_state(&identity) != kr_ipc::identity::ProcessState::Ended {
            assert!(
                std::time::Instant::now() < deadline,
                "the process of this test's own job outlived its removal"
            );
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }

    /// Only a label this host gives a job is looked at: a worker's or a plugin host's, spelt as
    /// this host spells it. Anything else is refused before launchd is asked about it.
    #[test]
    fn a_label_this_host_does_not_give_a_job_is_left_alone() {
        let host = kr_ipc::testing::TempHost::create();
        let jobs = host.environment().jobs_dir();
        // Letters in it, so that its spelling in capitals is another spelling.
        let reservation_id = ReservationId::new(Uuid::from_bytes([0xcd; 16]));
        for label in [
            "com.example.agent".to_owned(),
            "kr-plugin-host-not-a-reservation".to_owned(),
            format!(
                "kr-plugin-host-{}",
                reservation_id.to_string().to_uppercase()
            ),
            format!("kr-helper-{reservation_id}"),
        ] {
            // A definition under that name, which is what a label this host gives would have.
            std::fs::write(jobs.join(format!("{label}.plist")), b"").expect("writes a file");
            let JobRetirement::Unsettled(detail) = retire_service_job(&jobs, &label) else {
                panic!("{label} is not a label this host gives a job, and it was looked at");
            };
            assert!(detail.contains("left alone"), "{detail}");
            assert!(
                jobs.join(format!("{label}.plist")).exists(),
                "and its file is where it was"
            );
        }
        // Both labels this host does give, with nothing defined under them, are gone.
        for label in [
            worker_label(reservation_id),
            format!("kr-plugin-host-{reservation_id}"),
        ] {
            assert_eq!(retire_service_job(&jobs, &label), JobRetirement::Gone);
        }
    }

    /// A service-manager command that does not answer is ended and collected within its bound,
    /// and one that could not be started at all is told apart from one that ran and failed.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn a_service_manager_command_is_given_a_bound_and_told_apart_by_how_it_failed() {
        let started = std::time::Instant::now();
        let Err(RunFailure::Failed(detail)) =
            command_within("/bin/sleep", &["30"], std::time::Duration::from_millis(200))
        else {
            panic!("a command that does not answer within its bound is a failure of one that ran");
        };
        assert!(detail.contains("did not answer within"), "{detail}");
        assert!(
            !detail.contains("still running") && !detail.contains("collecting it failed"),
            "it was ended and collected: {detail}"
        );
        assert!(
            started.elapsed() < COLLECT_BOUND,
            "it was ended long before the thirty seconds it asked for: {:?}",
            started.elapsed()
        );

        assert!(
            matches!(
                command_within(
                    "/nonexistent/service-manager",
                    &[],
                    std::time::Duration::from_secs(1)
                ),
                Err(RunFailure::NotRun(_))
            ),
            "a command that could not be started never reached anything"
        );

        let Err(RunFailure::Failed(detail)) = run("/bin/sh", &["-c", "echo refused >&2; exit 3"])
        else {
            panic!("a command that answered with a failure is a failure of one that ran");
        };
        assert!(
            detail.contains("refused"),
            "it says what it was told: {detail}"
        );
        assert_eq!(
            run("/bin/sh", &["-c", "echo answered"]).expect("a command that answers"),
            "answered\n"
        );
    }

    /// What a removal said is kept wherever it said anything but that it removed the job.
    #[cfg(target_os = "macos")]
    #[test]
    fn what_a_removal_said_is_kept_where_it_failed() {
        use std::os::unix::process::ExitStatusExt as _;

        let answered =
            |raw: i32, said: &str| -> std::result::Result<std::process::Output, String> {
                Ok(std::process::Output {
                    status: std::process::ExitStatus::from_raw(raw),
                    stdout: Vec::new(),
                    stderr: said.as_bytes().to_vec(),
                })
            };
        let target = "gui/501/kr-worker-x";
        assert_eq!(removal_failure(target, &answered(0, "")), None);
        let failed = removal_failure(target, &answered(36 << 8, "Operation now in progress"))
            .expect("a removal that answered a failure");
        assert!(
            failed.contains("Some(36)") && failed.contains("Operation now in progress"),
            "{failed}"
        );
        let unanswered = "launchctl bootout gui/501/kr-worker-x did not answer within 10s; it was \
                          still running 5s after it was ended";
        assert_eq!(
            removal_failure(target, &Err(unanswered.to_owned())).as_deref(),
            Some(unanswered),
            "a launchctl that could not be collected is part of what is reported"
        );
    }

    /// A plugin host's job whose process has ended is removed from launchd, and its definition
    /// with it, the same way a worker's is.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_plugin_host_job_whose_process_has_ended_goes_with_its_definition() {
        launchd_domains_are_here();
        let host = kr_ipc::testing::TempHost::create();
        let jobs = host.environment().jobs_dir();
        let label = format!("kr-plugin-host-{}", kr_ipc::new_uuid());
        let _own = OwnJob(label.clone());
        // The system's own program that ends at once, as a service in this user's graphical
        // domain, which is where a plugin host is started.
        let outcome = LaunchdSupervisor::new().start_service(&ServiceLaunch {
            label: label.clone(),
            program: PathBuf::from("/usr/bin/true"),
            arguments: Vec::new(),
            jobs_directory: jobs.clone(),
            working_directory: host.root().to_path_buf(),
        });
        assert!(
            !matches!(outcome, LaunchOutcome::NotStarted { .. }),
            "the job was started: {outcome:?}"
        );
        let target = format!("gui/{}/{label}", kr_ipc::paths::current_uid());
        until_ended(&target);

        assert_eq!(retire_service_job(&jobs, &label), JobRetirement::Gone);
        assert!(
            matches!(job_state(&target), JobState::NotLoaded),
            "launchd no longer has the job"
        );
        assert!(
            !jobs.join(format!("{label}.plist")).exists(),
            "its definition went with it"
        );
    }

    /// A transient unit whose process failed is collected by the user manager rather than kept
    /// listed as failed.
    ///
    /// It needs a user service manager for this account, which a Linux login session or an
    /// account with lingering enabled has and a hosted CI runner's account does not, so an
    /// ordinary run leaves it out. It runs with `--ignored` on a Linux host whose account has one,
    /// as a developer's workstation or a build host where the account lingers; where there is
    /// none it fails and says so.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "needs a user service manager for this account (`systemctl --user`), which a hosted CI runner's account does not have; it runs with --ignored on a Linux host whose account has one"]
    fn a_transient_unit_whose_process_failed_is_collected() {
        assert!(
            SystemdSupervisor::available(),
            "this account has no user service manager to ask, so this check cannot run here"
        );
        let host = kr_ipc::testing::TempHost::create();
        let unit = format!("kr-test-collect-{}", kr_ipc::new_uuid());
        // A unit this test made, reset when the test ends however it ends, so a manager that kept
        // it keeps nothing of this test's afterwards.
        struct OwnUnit(String);
        impl Drop for OwnUnit {
            fn drop(&mut self) {
                let _ = command_within(
                    "systemctl",
                    &["--user", "reset-failed", &format!("{}.service", self.0)],
                    SERVICE_MANAGER_BOUND,
                );
            }
        }
        let _own = OwnUnit(unit.clone());
        let outcome = SystemdSupervisor::new().start_service(&ServiceLaunch {
            label: unit.clone(),
            program: PathBuf::from("/bin/sh"),
            arguments: vec!["-c".to_owned(), "exit 3".to_owned()],
            jobs_directory: host.environment().jobs_dir(),
            working_directory: host.root().to_path_buf(),
        });
        assert!(
            !matches!(outcome, LaunchOutcome::NotStarted { .. }),
            "the unit was started: {outcome:?}"
        );
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            let shown = command_within(
                "systemctl",
                &[
                    "--user",
                    "show",
                    "--property=LoadState,ActiveState",
                    &format!("{unit}.service"),
                ],
                SERVICE_MANAGER_BOUND,
            )
            .expect("the user manager answers");
            let said = String::from_utf8_lossy(&shown.stdout).into_owned();
            if said.contains("LoadState=not-found") {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the unit whose process failed is still listed 30 s after it started: {said}"
            );
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }
}
