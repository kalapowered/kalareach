//! `kr host startup`, and `kr new` starting this environment's control daemon when none runs.
//!
//! Section 7 lets `kr new` have the per-user controller started on demand only on a host that was
//! set up for it. A host that was not answers `HOST_NOT_CONFIGURED` with the setup action, and the
//! command installs no service, enables no lingering and obtains no privilege on the way. The setup
//! is the one selection `startup.controller` in this environment's configuration document, which
//! `kr host startup` writes as a validated edit with no daemon running and `kr doctor` reports. It
//! chooses one of two starts.
//!
//! The service start, `service`, is for a host whose per-user service manager should start the
//! daemon: `kr host startup --set service` also writes the manager's definition of the daemon and
//! records it, and `kr new` asks the manager to start it, as [`crate::service_manager`] describes.
//! `kr host startup` moving away from it removes exactly what it wrote, and no daemon is ended.
//!
//! The standalone start, `standalone`, is the standalone headless profile, for a host where no
//! service manager was set up to start the daemon. Under it, `kr new` runs the daemon installed
//! beside this command, `kr-controller`, detached from
//! the command: in a session and a process group of its own, with no controlling terminal and none
//! of the command's streams, working in the environment's own state directory and told the
//! environment's own runtime and state roots. It inherits the command's environment, `PATH`
//! included, exactly as a daemon started by hand from the same shell does. Everything else about
//! it is an ordinary start: it keeps its keys where an installed daemon keeps them, serves the
//! private endpoints it always serves, and takes the environment's singleton lock and advances its
//! generation, which is what leaves one daemon when several commands start one at once. The command
//! waits a bounded time for the daemon to answer and then goes on as it would against a daemon that
//! was already running.
//!
//! What such a daemon writes goes to `controller.log` in the environment's state directory, where
//! the service start's daemon writes too, and a daemon that does not answer in time is named in
//! the command's failure with the last line of that log. The command does not end it: a daemon still starting, such as one waiting on a person
//! to allow access to a credential store, may yet come up, and the singleton lock already keeps a
//! second one from serving beside it.

use std::path::PathBuf;
use std::time::Duration;

use kr_client::shown;
use kr_client::shown::Shown;
use kr_ipc::client::LocalClient;
use kr_ipc::paths::{EnvironmentPaths, HostPaths};
use kr_protocol::hostinfo::configuration::{Change, ControllerStartup, DocumentState};
use kr_protocol::local::LocalClientKind;

use crate::cli::StartupArguments;
use crate::error::{CliError, Result};
use crate::resolve::{self, KnownEnvironment};
use crate::service_manager;

/// How long `kr new` waits for a daemon it started to answer on its endpoint.
pub const START_BOUND: Duration = Duration::from_secs(30);

/// How long one attempt to reach a daemon that is already listening is given to be answered.
pub const ANSWER_BOUND: Duration = Duration::from_secs(10);

/// How often the endpoint is tried while the command waits.
const RETRY: Duration = Duration::from_millis(50);

/// The file in an environment's state directory that a daemon the standalone start runs writes to.
pub const LOG_FILE: &str = "controller.log";

/// The largest the log may be when a start begins. A larger one is emptied first, because a log
/// nobody rotates must not grow for as long as the host is installed.
const LOG_LIMIT: u64 = 1024 * 1024;

/// The most of the log a failure reads back.
const LOG_TAIL: u64 = 4096;

/// What this environment's configuration document chooses about starting its control daemon.
#[derive(Clone, PartialEq, Eq)]
pub struct Chosen {
    /// The way of starting it, when the document chooses one.
    pub controller: Option<ControllerStartup>,
    /// Where the document is.
    pub document: PathBuf,
    /// What the document turned out to be.
    pub state: DocumentState,
    /// The revision the document is at, or zero when there is none.
    pub revision: u64,
}

impl Chosen {
    /// Reads this environment's document.
    ///
    /// A document this build cannot use chooses nothing, and says why in `state`.
    #[must_use]
    pub fn read(paths: &EnvironmentPaths) -> Self {
        let loaded = crate::doctor::configuration::load(paths);
        Self {
            controller: loaded
                .document
                .as_ref()
                .and_then(|document| document.startup.controller()),
            document: crate::doctor::configuration::document_path(paths),
            state: loaded.status.state,
            revision: loaded.revision(),
        }
    }

    /// What a person does about this environment when no daemon answers and none may be started.
    fn setup_action(&self) -> Shown {
        if self.state.is_a_problem() {
            shown!(
                "this environment's configuration document, {}, is {}, so it chooses no way of \
                 starting one; start the control daemon, kr-controller, for it, or correct the \
                 document",
                Shown::root(&self.document),
                self.state.as_str()
            )
        } else {
            Shown::said(SETUP_ACTION)
        }
    }
}

/// What a person does about this installation's own environment when no daemon runs and nothing is
/// chosen: start one, or choose which of the two starts `kr new` uses.
#[cfg(unix)]
const SETUP_ACTION: &str = "start the control daemon, kr-controller, for it, or, for this \
                            installation's own environment, choose how kr new starts one: \
                            `kr host startup --set service` has this user's service manager \
                            start it, and `kr host startup --set standalone` starts it detached \
                            from the command";

/// What a person does about this installation's own environment when no daemon runs and nothing is
/// chosen: start one, or choose the standalone start, which is this platform's.
#[cfg(windows)]
const SETUP_ACTION: &str = "start the control daemon, kr-controller, for it, or, for this \
                            installation's own environment, choose how kr new starts one: `kr \
                            host startup --set standalone` has this user's scheduled task start it";

/// Runs `kr host startup`: shows what this environment chooses, or makes a choice as one validated
/// edit of its configuration document.
///
/// Choosing the service start writes the service manager's definition of the daemon first, records
/// it and has the manager take it; choosing anything else removes exactly what the service start
/// wrote. Nothing more changes. No daemon is asked, none is started or ended, and no privilege is
/// obtained; `kr new` reads the choice the next time it finds no daemon running.
///
/// # Errors
///
/// Returns [`CliError::Usage`] for a way of starting this build does not know, for an edit the
/// document refuses and for a definition kr may not replace, each with nothing changed, and what
/// failed otherwise.
pub fn run(paths: &HostPaths, arguments: &StartupArguments, json: bool) -> Result<()> {
    let environment = resolve::select(paths, None)?;
    let change = if arguments.clear {
        Some(None)
    } else {
        arguments
            .set
            .as_deref()
            .map(|value| {
                ControllerStartup::from_wire(value)
                    .map(Some)
                    .ok_or_else(|| {
                        CliError::Usage(shown!(
                            "the value given is not a way of starting the control daemon: \
                             choose {}",
                            Shown::joined(
                                ControllerStartup::ALL.map(|startup| Shown::said(startup.as_str())),
                                " or "
                            )
                        ))
                    })
            })
            .transpose()?
    };
    let changed = match change {
        Some(startup) => changed(&environment.paths, startup)?,
        None => Changed::default(),
    };
    let Changed {
        notes,
        removal,
        #[cfg(windows)]
            task: task_changed,
    } = changed;
    let chosen = Chosen::read(&environment.paths);
    let inspected = service_manager::inspect(
        &environment.paths,
        chosen.controller == Some(ControllerStartup::Service),
    );
    let (inspection, unestablished) = match inspected {
        Some(Ok(inspection)) => (Some(inspection), None),
        Some(Err(why)) => (None, Some(why)),
        None => (None, None),
    };
    #[cfg(windows)]
    let task_report = windows::report(
        &environment.paths,
        chosen.controller == Some(ControllerStartup::Standalone),
    );
    if json {
        let mut document = serde_json::json!({
            "ok": true,
            "environment_id": environment.environment_id.to_string(),
            "startup": {
                "controller": chosen.controller.map(ControllerStartup::as_str),
                "source": if chosen.controller.is_some() {
                    "host_configuration"
                } else {
                    "default"
                },
                "document": chosen.document.display().to_string(),
                "document_state": chosen.state.as_str(),
                "revision": chosen.revision.to_string(),
                "definition": inspection.as_ref().map(service_manager::Inspection::json),
                "definition_unestablished": unestablished.as_ref().map(Shown::as_str),
            },
        });
        #[cfg(windows)]
        {
            if let Some(report) = &task_report {
                document["startup"]["task"] = report.json();
            }
            if let Some(changed) = &task_changed {
                document["task_change"] = changed.json();
            }
        }
        if !removal.removed.is_empty() || !removal.left.is_empty() {
            document["removed"] = serde_json::json!(
                removal
                    .removed
                    .iter()
                    .map(|path| path.display().to_string())
                    .collect::<Vec<_>>()
            );
            document["left"] = serde_json::json!(
                removal
                    .left
                    .iter()
                    .map(|(path, why)| serde_json::json!({
                        "path": path.display().to_string(),
                        "why": why.as_str(),
                    }))
                    .collect::<Vec<_>>()
            );
        }
        if !notes.is_empty() {
            document["notes"] = serde_json::json!(notes);
        }
        crate::report::print_json(&document);
    } else {
        println!("{}", describe(&chosen, inspection.as_ref()));
        #[cfg(windows)]
        {
            if let Some(changed) = &task_changed {
                println!("{}", changed.describe(environment.environment_id));
            }
            if let Some(report) = &task_report {
                println!("{}", report.describe());
            }
        }
        if let Some(why) = &unestablished {
            println!(
                "what the service start has for this environment cannot be established: {why}"
            );
        }
        for path in &removal.removed {
            println!("removed {}", path.display());
        }
        for (path, why) in &removal.left {
            println!("left {}: {why}", path.display());
        }
        for note in &notes {
            println!("{note}");
        }
    }
    Ok(())
}

/// What `kr host startup` changed.
#[derive(Debug, Default)]
struct Changed {
    /// What a person should know about what the service manager holds.
    notes: Vec<String>,
    /// What removing the service start's definition did.
    removal: service_manager::Removal,
    /// What happened to the environment's scheduled task.
    #[cfg(windows)]
    task: Option<windows::TaskChanged>,
}

/// Makes `startup` this environment's choice, as one validated edit of its configuration
/// document, with what each start keeps outside the document brought in line first.
fn changed(environment: &EnvironmentPaths, startup: Option<ControllerStartup>) -> Result<Changed> {
    #[cfg(windows)]
    if startup == Some(ControllerStartup::Service) {
        return Err(CliError::Usage(Shown::said(
            "the service start is not set up on this platform, where the standalone start is: \
             kr host startup --set standalone has this user's scheduled task start the control \
             daemon",
        )));
    }
    let change = Change::ControllerStartup(startup);
    // Refused before anything else is touched, so a document this build must not rewrite
    // leaves the service manager's definition as it was too.
    crate::doctor::configuration::validate(environment, &change)?;
    // A first use of the environment, on a host where no daemon has run yet, as an edit of
    // its document is: the record and the lock live in its state directory.
    environment.create()?;
    // One change at a time, from the definition to the document: held until the document is
    // written, so no other change or start request sees one without the other. The document's
    // own lock is taken inside, after this one, as everywhere.
    let held = service_manager::lock(environment)?;
    let changed = changed_under(environment, startup, &change, &held)?;
    drop(held);
    Ok(changed)
}

/// Brings the service manager's definition in line with `startup`, then writes the document.
#[cfg(unix)]
fn changed_under(
    environment: &EnvironmentPaths,
    startup: Option<ControllerStartup>,
    change: &Change,
    held: &service_manager::Lock,
) -> Result<Changed> {
    let mut changed = Changed::default();
    if startup == Some(ControllerStartup::Service) {
        changed.notes = service_manager::install(environment, held)?.notes;
    } else {
        changed.removal = service_manager::remove(environment, held)?;
        changed.notes.append(&mut changed.removal.notes);
    }
    crate::doctor::configuration::apply(environment, change)?;
    Ok(changed)
}

/// Brings the environment's scheduled task in line with `startup`, then writes the document, and
/// puts the task back as it was when the document is not written.
#[cfg(windows)]
fn changed_under(
    environment: &EnvironmentPaths,
    startup: Option<ControllerStartup>,
    change: &Change,
    _held: &service_manager::Lock,
) -> Result<Changed> {
    Ok(Changed {
        task: Some(windows::change(environment, startup, change)?),
        ..Changed::default()
    })
}

/// What `kr host startup` tells a person.
fn describe(chosen: &Chosen, inspection: Option<&service_manager::Inspection>) -> String {
    let left_over = |text: String| match inspection {
        Some(inspection) if inspection.recorded => format!(
            "{text}\na service definition kr wrote is still installed, and nothing uses it: {}; kr \
             host startup --clear removes it",
            inspection.describe()
        ),
        _ => text,
    };
    match chosen.controller {
        Some(ControllerStartup::Service) => format!(
            "startup: service, from {} at revision {}: kr new asks this user's service manager to \
             start this environment's control daemon when none is running{}",
            chosen.document.display(),
            chosen.revision,
            inspection.map_or_else(String::new, |inspection| format!(
                "; {}",
                inspection.describe()
            ))
        ),
        Some(ControllerStartup::Standalone) => left_over(format!(
            "startup: standalone, from {} at revision {}: {STANDALONE_SAID}",
            chosen.document.display(),
            chosen.revision
        )),
        None if chosen.state.is_a_problem() => left_over(format!(
            "startup: none, because the configuration document {} is {}: kr new starts no \
             control daemon",
            chosen.document.display(),
            chosen.state.as_str()
        )),
        None => left_over(NOTHING_CHOSEN.to_owned()),
    }
}

/// What the standalone start does, as `kr host startup` says it.
#[cfg(unix)]
const STANDALONE_SAID: &str =
    "kr new starts this environment's control daemon itself when none is running";

/// What the standalone start does, as `kr host startup` says it.
#[cfg(windows)]
const STANDALONE_SAID: &str = "kr new has this user's scheduled task for this environment start \
                               its control daemon when none is running";

/// What `kr host startup` says of an environment that chooses no start.
#[cfg(unix)]
const NOTHING_CHOSEN: &str = "startup: none: kr new starts no control daemon, and says what to set \
                              up when none is running; kr host startup --set service has this \
                              user's service manager start it, and kr host startup --set \
                              standalone chooses the standalone start";

/// What `kr host startup` says of an environment that chooses no start.
#[cfg(windows)]
const NOTHING_CHOSEN: &str = "startup: none: kr new starts no control daemon, and says what to set \
                              up when none is running; kr host startup --set standalone chooses \
                              the standalone start, in which this user's scheduled task starts it";

/// A daemon this command started, or had its service manager start.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Started {
    /// Its process identifier, when it is known.
    pub pid: Option<u32>,
    /// The start that started it.
    pub start: ControllerStartup,
    /// The service manager asked, under the service start.
    pub manager: Option<service_manager::Manager>,
}

impl Started {
    /// What `kr new` tells a person it did, for the environment the daemon serves.
    #[must_use]
    pub fn describe(&self, environment: kr_protocol::ids::EnvironmentId) -> Shown {
        let process = self
            .pid
            .map_or_else(|| Shown::said(""), |pid| shown!(" (process {})", pid));
        match self.manager {
            Some(manager) => shown!(
                "{} started the control daemon for environment {}{} under the service start",
                manager.as_str(),
                environment,
                process
            ),
            None => shown!(
                "started the control daemon for environment {}{} under the {} start",
                environment,
                process,
                self.start.as_str()
            ),
        }
    }
}

/// How long each wait of the standalone start is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Bounds {
    /// One attempt to reach a daemon: the connection and the daemon's hello together. A daemon
    /// that accepts the connection and never says hello has not answered.
    answer: Duration,
    /// From the moment this command starts a daemon to the moment one answers.
    start: Duration,
}

/// The waits `kr new` uses.
const BOUNDS: Bounds = Bounds {
    answer: ANSWER_BOUND,
    start: START_BOUND,
};

/// Reaches the environment's control daemon for `kr new`, starting it first, or having the service
/// manager start it, where this environment chooses a start and none is running.
///
/// A daemon is started only when nothing listens on the environment's endpoint at all. One that is
/// there and answers badly, or does not answer, is reported as it is: starting another beside it
/// would be starting a daemon that cannot take the environment.
///
/// # Errors
///
/// Returns [`CliError::HostUnavailable`] with the setup action when no daemon answers and none may
/// be started, and [`CliError::Unfinished`] with `ENVIRONMENT_UNAVAILABLE` when a daemon that is
/// there did not answer within [`ANSWER_BOUND`] or one this command started did not answer within
/// [`START_BOUND`].
pub async fn open_or_start(
    paths: &HostPaths,
    environment: &KnownEnvironment,
) -> Result<(LocalClient, Option<Started>)> {
    open_or_start_within(paths, environment, BOUNDS).await
}

async fn open_or_start_within(
    paths: &HostPaths,
    environment: &KnownEnvironment,
    bounds: Bounds,
) -> Result<(LocalClient, Option<Started>)> {
    let endpoint = environment.paths.controller_endpoint()?;
    let error = match reach(&endpoint, bounds.answer).await {
        Reached::Answered(client) => return Ok((*client, None)),
        Reached::Silent => {
            return Err(unanswered(shown!(
                "the control daemon listening for environment {} accepted the connection and \
                     did not answer within {} seconds; nothing was started beside it",
                environment.environment_id,
                bounds.answer.as_secs_f64()
            )));
        }
        Reached::Refused(error) if nothing_listening(&error) => error,
        Reached::Refused(error) => {
            return Err(resolve::not_running(
                &error,
                Shown::said(resolve::SETUP_ACTION),
            ));
        }
    };
    // The daemon beside this command serves the environment its roots name as this installation's
    // own, and no other, so for any other environment there is nothing to choose here.
    let installation = paths.open_environment_id()?;
    if environment.environment_id != installation {
        return Err(resolve::not_running(
            &error,
            shown!(
                "start the control daemon, kr-controller, for it; the standalone start serves this \
                 installation's own environment, {}, and no other",
                installation
            ),
        ));
    }
    let chosen = Chosen::read(&environment.paths);
    match chosen.controller {
        Some(ControllerStartup::Standalone) => {
            standalone(paths, &environment.paths, &endpoint, bounds).await
        }
        Some(ControllerStartup::Service) => {
            managed(&environment.paths, &endpoint, &error, bounds).await
        }
        None => Err(resolve::not_running(&error, chosen.setup_action())),
    }
}

/// What one attempt to reach a daemon found.
enum Reached {
    /// A daemon answered, and this is the connection to it.
    Answered(Box<LocalClient>),
    /// Something accepted the connection and did not answer within the bound.
    Silent,
    /// The connection failed.
    Refused(kr_ipc::IpcError),
}

/// Makes one attempt to reach the daemon at `endpoint`, the connection and its hello together
/// bounded by `bound`.
async fn reach(endpoint: &kr_ipc::paths::Endpoint, bound: Duration) -> Reached {
    match tokio::time::timeout(
        bound,
        LocalClient::connect(endpoint, LocalClientKind::Cli, crate::build_id()),
    )
    .await
    {
        Ok(Ok(client)) => Reached::Answered(Box::new(client)),
        Ok(Err(error)) => Reached::Refused(error),
        Err(_) => Reached::Silent,
    }
}

/// The failure a daemon that does not answer in time ends `kr new` with.
fn unanswered(message: Shown) -> CliError {
    CliError::Unfinished {
        code: kr_protocol::error::ErrorCode::EnvironmentUnavailable,
        message,
    }
}

/// Whether a failure to reach a daemon says that nothing is listening, rather than that something
/// answered and could not be used.
fn nothing_listening(error: &kr_ipc::IpcError) -> bool {
    matches!(
        error,
        kr_ipc::IpcError::Socket { source, .. }
            if matches!(
                source.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
            )
    )
}

/// Tries the daemon at `endpoint` until one answers or `deadline` passes, each attempt bounded by
/// what is left of the deadline, and runs `between` after every attempt that failed.
///
/// Returns the connection, or what the last attempt found.
async fn answered_by(
    endpoint: &kr_ipc::paths::Endpoint,
    deadline: tokio::time::Instant,
    mut between: impl FnMut(),
) -> std::result::Result<LocalClient, Shown> {
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        let last = match reach(endpoint, left).await {
            Reached::Answered(client) => return Ok(*client),
            Reached::Silent => {
                Shown::said("the endpoint accepted the connection and did not answer")
            }
            Reached::Refused(error) => Shown::ipc(&error),
        };
        between();
        if tokio::time::Instant::now() >= deadline {
            return Err(last);
        }
        tokio::time::sleep(
            RETRY.min(deadline.saturating_duration_since(tokio::time::Instant::now())),
        )
        .await;
    }
}

/// The control daemon the standalone start runs: the one installed beside this command.
///
/// The link a command was run through is followed first, so a `kr` reached through a link on the
/// search path finds the daemon beside the program itself rather than beside the link. It is
/// never looked for on the search path.
///
/// # Errors
///
/// Returns [`CliError::HostUnavailable`] when where this command is installed cannot be read.
pub fn daemon_program() -> Result<PathBuf> {
    let unreadable = |error: std::io::Error| {
        CliError::HostUnavailable(shown!(
            "the standalone start runs the control daemon installed beside this command, and \
             where this command is installed could not be read: {}",
            Shown::io(&error)
        ))
    };
    let this = std::env::current_exe()
        .and_then(std::fs::canonicalize)
        .map_err(unreadable)?;
    // Resolved on Windows, a path carries the verbatim prefix, which the task that runs the daemon
    // would then carry too: the same place is named without it.
    #[cfg(windows)]
    let this = kr_controller::supervision::windows::without_verbatim_prefix(this);
    let directory = this.parent().ok_or_else(|| {
        unreadable(std::io::Error::other(Shown::said(
            "this command's path has no directory",
        )))
    })?;
    Ok(directory.join(format!("kr-controller{}", std::env::consts::EXE_SUFFIX)))
}

/// Starts the daemon detached from this command and waits for it to answer.
///
/// It inherits this command's environment, as a daemon started by hand from the same shell does.
#[cfg(unix)]
async fn standalone(
    paths: &HostPaths,
    environment: &EnvironmentPaths,
    endpoint: &kr_ipc::paths::Endpoint,
    bounds: Bounds,
) -> Result<(LocalClient, Option<Started>)> {
    let program = daemon_program()?;
    if !program.is_file() {
        return Err(CliError::HostUnavailable(shown!(
            "the standalone start runs the control daemon installed beside this command, {}, and \
             there is none there",
            Shown::root(&program)
        )));
    }
    // The directories the daemon works and writes in. It creates them itself as well, and both are
    // the same idempotent creation.
    environment.create()?;
    let log = Log::open(&environment.state_dir().join(LOG_FILE))?;
    let mut child = std::process::Command::new(&program)
        .arg("--runtime-dir")
        .arg(paths.runtime_root())
        .arg("--state-dir")
        .arg(paths.state_root())
        .arg("--own-session")
        .current_dir(environment.state_dir())
        .stdin(std::process::Stdio::null())
        .stdout(log.output()?)
        .stderr(log.output()?)
        .spawn()
        .map_err(|error| {
            CliError::HostUnavailable(shown!(
                "the control daemon {} could not be started: {}",
                Shown::root(&program),
                Shown::io(&error)
            ))
        })?;
    let started = Started {
        pid: Some(child.id()),
        start: ControllerStartup::Standalone,
        manager: None,
    };
    let deadline = tokio::time::Instant::now() + bounds.start;
    // The daemon this command started, or the one another command started first: either way the
    // environment has its daemon, and it is the one the lock let through. The one started here is
    // collected as soon as it ends, so a daemon that could not take the environment is not left
    // waiting on this command.
    let last = match answered_by(endpoint, deadline, || {
        let _ = child.try_wait();
    })
    .await
    {
        Ok(client) => return Ok((client, Some(started))),
        Err(last) => last,
    };
    let state = child.try_wait().ok().flatten().map_or_else(
        || Shown::said("it is still running"),
        |status| shown!("it has ended ({})", status),
    );
    let said = log.last_line().map_or_else(
        || Shown::said("its log holds nothing since it started"),
        |line| last_line_said(&line),
    );
    Err(unanswered(shown!(
        "the control daemon this command started for environment {} (process {}) did not \
             answer within {} seconds: {}; {}, and {}; what it writes is in {}",
        environment.environment_id(),
        child.id(),
        bounds.start.as_secs(),
        last,
        state,
        said,
        Shown::root(&log.path)
    )))
}

/// What a failure says of the last line a daemon's log holds.
///
/// The daemon's refusal of an environment another daemon already holds is said, because it is the
/// daemon's own sentence and names the environment by its identifier. Any other line is whatever
/// the daemon, or a library it uses, wrote, so the failure says that the log holds one and names
/// the log, rather than repeating it.
fn last_line_said(line: &str) -> Shown {
    const HELD: &str = "kr-controller: another control daemon already owns environment ";
    match line
        .strip_prefix(HELD)
        .and_then(|environment| environment.parse::<kr_protocol::ids::EnvironmentId>().ok())
    {
        Some(environment) => shown!(
            "the last line its log holds since it started is: kr-controller: another control \
             daemon already owns environment {}",
            environment
        ),
        None => Shown::said("its log holds a line since it started, which is not repeated here"),
    }
}

/// Asks this user's service manager to start the daemon from the definition kr wrote, and waits
/// for it to answer.
///
/// The definition is checked before the manager is asked: one that has gone, that kr did not
/// write, or that was changed since is `HOST_NOT_CONFIGURED` with the setup action, and nothing is
/// written or started. The daemon inherits the manager's environment rather than this command's,
/// as every service the manager starts does.
#[cfg(unix)]
async fn managed(
    environment: &EnvironmentPaths,
    endpoint: &kr_ipc::paths::Endpoint,
    error: &kr_ipc::IpcError,
    bounds: Bounds,
) -> Result<(LocalClient, Option<Started>)> {
    let refused = |refusal| match refusal {
        service_manager::Refusal::NotSetUp(why) => resolve::not_running(error, why),
        service_manager::Refusal::Failed(why) => unanswered(shown!(
            "the service manager did not start the control daemon for environment {}: {}",
            environment.environment_id(),
            why
        )),
    };
    let blocked = |error: tokio::task::JoinError| {
        CliError::Other(shown!(
            "asking the service manager to start the control daemon failed: {}",
            Shown::task(&error)
        ))
    };
    // The definition first, with the environment's service lock held from here until the manager
    // has been asked: one that is not exactly what kr wrote refuses the start with nothing
    // written, the log included. Each command put to the manager is bounded, and they are waited
    // for off the runtime's own threads.
    let checking = environment.clone();
    let verified = tokio::task::spawn_blocking(move || service_manager::verify(&checking))
        .await
        .map_err(blocked)?
        .map_err(refused)?;
    // The log is checked, and emptied when it has grown too large, before the manager opens it,
    // exactly as for the standalone start; the manager appends to it.
    let log = Log::open(&environment.state_dir().join(LOG_FILE))?;
    let asked = tokio::task::spawn_blocking(move || verified.start())
        .await
        .map_err(blocked)?
        .map_err(refused)?;
    let started = Started {
        pid: asked.pid,
        start: ControllerStartup::Service,
        manager: Some(asked.manager),
    };
    let deadline = tokio::time::Instant::now() + bounds.start;
    let last = match answered_by(endpoint, deadline, || {}).await {
        Ok(client) => return Ok((client, Some(started))),
        Err(last) => last,
    };
    let said = log.last_line().map_or_else(
        || Shown::said("its log holds nothing since it started"),
        |line| last_line_said(&line),
    );
    let process = asked
        .pid
        .map_or_else(|| Shown::said(""), |pid| shown!(" (process {})", pid));
    Err(unanswered(shown!(
        "the control daemon {} started for environment {}{} did not answer within {} seconds: \
         {}; {}; what it writes is in {}",
        asked.manager.as_str(),
        environment.environment_id(),
        process,
        bounds.start.as_secs(),
        last,
        said,
        Shown::root(&log.path)
    )))
}

/// The service start runs the daemon through a per-user service manager, and this platform has
/// none this build writes definitions for.
#[cfg(not(unix))]
async fn managed(
    _environment: &EnvironmentPaths,
    _endpoint: &kr_ipc::paths::Endpoint,
    error: &kr_ipc::IpcError,
    _bounds: Bounds,
) -> Result<(LocalClient, Option<Started>)> {
    Err(resolve::not_running(
        error,
        Shown::said(
            "this environment chooses the service start, which this platform does not have; start \
             the control daemon, kr-controller, for it",
        ),
    ))
}

/// Has this user's scheduled task for the environment start the daemon, and waits for it to
/// answer.
///
/// The task is checked first, under the environment's lock, as the service start checks its
/// definition: one that is missing, that is not this environment's own, or that is not the one
/// this installation registers is `HOST_NOT_CONFIGURED` with the setup action, and nothing is
/// claimed or run. Then a request to start the daemon is left for the task's starter, and the task
/// is run. The starter takes the request and starts the daemon installed beside this command, with
/// its output appended to the log; the Task Scheduler, not this command, is its creator, so it is
/// in none of this command's jobs. The daemon inherits the environment the Task Scheduler gives the
/// user, as every process a task starts does. A request no starter took by the time the command
/// stops waiting is a task the Task Scheduler did not start: it starts one only in a session where
/// the user is signed in.
#[cfg(windows)]
async fn standalone(
    _paths: &HostPaths,
    environment: &EnvironmentPaths,
    endpoint: &kr_ipc::paths::Endpoint,
    bounds: Bounds,
) -> Result<(LocalClient, Option<Started>)> {
    let program = daemon_program()?;
    if !program.is_file() {
        return Err(CliError::HostUnavailable(shown!(
            "the standalone start runs the control daemon installed beside this command, {}, and \
             there is none there",
            Shown::root(&program)
        )));
    }
    environment.create()?;
    // Checked, and emptied when it has grown too large, before the starter opens it: the daemon
    // appends to it.
    let log = Log::open(&environment.state_dir().join(LOG_FILE))?;
    let deadline = tokio::time::Instant::now() + bounds.start;
    let asking = environment.clone();
    let asked = tokio::task::spawn_blocking(move || windows::ask(&asking, &program, bounds.start))
        .await
        .map_err(|error| {
            CliError::Other(shown!(
                "asking this user's scheduled task to start the control daemon failed: {}",
                Shown::task(&error)
            ))
        })??;
    let started = Started {
        pid: None,
        start: ControllerStartup::Standalone,
        manager: None,
    };
    let last = match answered_by(endpoint, deadline, || {}).await {
        Ok(client) => return Ok((client, Some(started))),
        Err(last) => last,
    };
    if !kr_ipc::starter::claim_taken(environment, asked.request) {
        return Err(windows::not_taken(environment, bounds.start, asked.session));
    }
    let said = log.last_line().map_or_else(
        || Shown::said("its log holds nothing since it started"),
        |line| last_line_said(&line),
    );
    Err(unanswered(shown!(
        "the control daemon this user's scheduled task {} started for environment {} did not \
         answer within {} seconds: {}; {}; what it writes is in {}",
        task::name(environment.environment_id()),
        environment.environment_id(),
        bounds.start.as_secs(),
        last,
        said,
        Shown::root(&log.path)
    )))
}

/// The log a daemon the standalone start runs writes to, opened once and checked.
struct Log {
    file: std::fs::File,
    path: PathBuf,
    /// Where this start's part of it begins.
    from: u64,
}

impl Log {
    /// Takes an opened log, emptying it first when it has grown past the limit.
    fn from_file(file: std::fs::File, path: &std::path::Path) -> Result<Self> {
        let failed = |error| CliError::Ipc(kr_ipc::IpcError::io("open", path, error));
        let mut from = file.metadata().map_err(failed)?.len();
        if from > LOG_LIMIT {
            file.set_len(0).map_err(failed)?;
            from = 0;
        }
        Ok(Self {
            file,
            path: path.to_path_buf(),
            from,
        })
    }

    /// The last line written since this start began, read through the handle that was checked.
    ///
    /// Several starts can share the log, so the line is the log's rather than certainly this
    /// start's daemon's.
    fn last_line(&self) -> Option<String> {
        let length = self.file.metadata().ok()?.len();
        let begin = self.from.max(length.saturating_sub(LOG_TAIL));
        let mut bytes = vec![0; usize::try_from(length.saturating_sub(begin)).ok()?];
        let mut read = 0;
        while read < bytes.len() {
            match read_at(&self.file, &mut bytes[read..], begin + read as u64) {
                Ok(0) | Err(_) => break,
                Ok(count) => read += count,
            }
        }
        bytes.truncate(read);
        String::from_utf8_lossy(&bytes)
            .lines()
            .map(str::trim)
            .rfind(|line| !line.is_empty())
            .map(str::to_owned)
    }
}

/// Reads from `file` at `offset`, leaving whatever else holds the file to its own position.
#[cfg(unix)]
fn read_at(file: &std::fs::File, buffer: &mut [u8], offset: u64) -> std::io::Result<usize> {
    std::os::unix::fs::FileExt::read_at(file, buffer, offset)
}

/// Reads from `file` at `offset`. On Windows a positioned read moves this handle's own position,
/// which nothing here uses: the daemon writes through a handle of its own, and only appends.
#[cfg(windows)]
fn read_at(file: &std::fs::File, buffer: &mut [u8], offset: u64) -> std::io::Result<usize> {
    std::os::windows::fs::FileExt::seek_read(file, buffer, offset)
}

#[cfg(windows)]
impl Log {
    /// Opens the log for reading and emptying, never through a link, and takes it only when it is
    /// a regular file whose list grants no account this host does not trust: the checks the
    /// starter makes when it opens the log for the daemon to append to.
    fn open(path: &std::path::Path) -> Result<Self> {
        let file = kr_ipc::starter::open_log(path, kr_ipc::starter::LogAccess::ReadAndTruncate)
            .map_err(|error| match error {
            kr_ipc::IpcError::UntrustedFile { .. } => CliError::HostUnavailable(shown!(
                "{} is not a file of this user's that only this user can read and write, so the \
                 control daemon's output is not written to it; remove it and run kr new again",
                Shown::root(path)
            )),
            other => CliError::Ipc(other),
        })?;
        Self::from_file(file, path)
    }
}

#[cfg(unix)]
impl Log {
    /// Opens the log for appending and reading, never through a link and never waiting on it, and
    /// takes it only when it is a regular file of this user's that nobody else can read or write.
    ///
    /// The mode a file is created with says nothing about a file that was already there, and a
    /// FIFO left where the log belongs would hold the start open before its bound began. So what
    /// was opened is checked, rather than what the name was expected to be.
    fn open(path: &std::path::Path) -> Result<Self> {
        use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

        let failed = |error| CliError::Ipc(kr_ipc::IpcError::io("open", path, error));
        let file = std::fs::OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .map_err(failed)?;
        let about = file.metadata().map_err(failed)?;
        if !about.file_type().is_file()
            || about.uid() != kr_ipc::paths::current_uid()
            || about.mode() & 0o077 != 0
        {
            return Err(CliError::HostUnavailable(shown!(
                "{} is not a file of this user's that only this user can read and write, so the \
                 control daemon's output is not written to it; remove it and run kr new again",
                Shown::root(path)
            )));
        }
        Self::from_file(file, path)
    }

    /// A handle a daemon writes its output through: the same open file, appended to.
    fn output(&self) -> Result<std::fs::File> {
        self.file
            .try_clone()
            .map_err(|error| CliError::Ipc(kr_ipc::IpcError::io("open", &self.path, error)))
    }
}

/// Writes `prior` back as this environment's choice when a write that failed left another one, and
/// says where the choice stands.
///
/// A write can fail after the new document was published: the file is replaced by a rename, and
/// the flush of its directory that follows can fail. So the document is read again, and a choice
/// that is not the prior one is written back as an edit, under the document's own lock, and read
/// again.
#[cfg(any(windows, test))]
fn restore_choice(environment: &EnvironmentPaths, prior: Option<ControllerStartup>) -> Shown {
    if Chosen::read(environment).controller == prior {
        return Shown::said("startup.controller is as it was");
    }
    let _ = crate::doctor::configuration::apply(environment, &Change::ControllerStartup(prior));
    if Chosen::read(environment).controller == prior {
        Shown::said("startup.controller was written back as it was")
    } else {
        Shown::said("startup.controller is not as it was; run kr host startup to see it")
    }
}

/// The standalone start's scheduled task, as this command says it.
///
/// What was read from the Task Scheduler or from a task is said in this command's own words: which
/// way a task differs, never what it holds; that a task under the name is not this environment's,
/// never whose it is; that the Task Scheduler refused, and its exit code, never what it printed.
#[cfg(any(windows, test))]
pub(crate) mod task {
    use std::path::Path;

    use kr_client::shown;
    use kr_client::shown::Shown;
    use kr_controller::supervision::windows::{
        Difference, ForeignReason, LastResult, LogonType, Outcome, ReadBack, Standing, TaskError,
        task_name,
    };
    use kr_protocol::ids::EnvironmentId;

    /// What a person does to have the environment's task registered, or put right.
    pub const SETUP_ACTION: &str = "run kr host startup --set standalone";

    /// The task's name: `KalaReach-` and the first eight digits of the environment's identifier,
    /// the name the Task Scheduler lists it under in its root folder. It is derived here from a
    /// fixed name and an identifier, so it is said whole, as a path this program derived is.
    pub fn name(environment_id: EnvironmentId) -> Shown {
        Shown::root(Path::new(&task_name(environment_id)))
    }

    /// One way the task differs from the one this installation registers.
    pub fn difference(difference: &Difference) -> Shown {
        match difference {
            Difference::Program { .. } => {
                Shown::said("it runs another program than this installation's kr-controller")
            }
            Difference::Arguments { .. } => {
                Shown::said("it gives its program other arguments than this installation's")
            }
            Difference::WorkingDirectory { .. } => {
                Shown::said("it runs in another directory than the environment's state directory")
            }
            Difference::Actions(count) => shown!("it has {} actions, not one", *count),
            Difference::Triggered => {
                Shown::said("it has a trigger, so it runs without being asked")
            }
            Difference::Logon { found, expected } => shown!(
                "it logs on as {}, not {}",
                found.map_or("something kr does not register", LogonType::as_str),
                expected.as_str()
            ),
            Difference::RunLevel(_) => Shown::said("it runs with more than the least privilege"),
            Difference::NotOnBatteries => Shown::said("it does not start on batteries"),
            Difference::StopsOnBatteries => {
                Shown::said("it stops when the machine goes on batteries")
            }
            Difference::WaitsForIdle => Shown::said("it waits for the machine to be idle"),
            Difference::StopsWhenBusy => Shown::said("it stops when the machine stops being idle"),
            Difference::WaitsForNetwork => Shown::said("it waits for a network"),
            Difference::NotOnDemand => Shown::said("it may not be run when asked"),
            Difference::NotParallel(_) => {
                Shown::said("a second run while one is running is not in parallel")
            }
            Difference::TimeLimited(_) => Shown::said("its runs are limited in time"),
            Difference::Priority(_) => Shown::said("it runs at another priority than the normal 5"),
            Difference::Disabled => Shown::said("it is disabled"),
        }
    }

    /// Every way the task differs, one after another.
    pub fn differences(differences: &[Difference]) -> Shown {
        Shown::joined(differences.iter().map(difference), "; ")
    }

    /// Why a task under the environment's name is not its own.
    pub const fn foreign(reason: &ForeignReason) -> &'static str {
        match reason {
            ForeignReason::Unreadable { .. } => {
                "this user cannot read it, so whose it is cannot be established"
            }
            ForeignReason::Account { .. } => "it runs as another account",
            ForeignReason::Environment { .. } => "it belongs to another environment of this user's",
        }
    }

    /// Why a look at, or a change to, the environment's task did not happen.
    pub fn error(error: &TaskError, environment_id: EnvironmentId) -> Shown {
        let name = name(environment_id);
        match error {
            TaskError::Foreign(foreign) => shown!(
                "a task named {} is registered and is not this environment's own: {}; kr neither \
                 replaces nor removes it",
                name,
                self::foreign(&foreign.reason)
            ),
            TaskError::Scheduler {
                asked,
                outcome: Outcome::Ended(Some(code)),
                ..
            } => shown!(
                "the Task Scheduler did not {} the scheduled task {} (exit code {}); schtasks \
                 /Query /TN {} shows what it holds",
                asked.as_str(),
                name,
                *code,
                name
            ),
            TaskError::Scheduler {
                asked,
                outcome: Outcome::Ended(None),
                ..
            } => shown!(
                "the Task Scheduler did not {} the scheduled task {}; schtasks /Query /TN {} shows \
                 what it holds",
                asked.as_str(),
                name,
                name
            ),
            TaskError::Scheduler {
                asked,
                outcome: Outcome::NotStarted,
                ..
            } => shown!(
                "the Task Scheduler could not be asked to {} the scheduled task {}",
                asked.as_str(),
                name
            ),
            TaskError::Scheduler {
                asked,
                outcome: Outcome::Unseen,
                ..
            } => shown!(
                "the Task Scheduler was asked to {} the scheduled task {} and did not answer in \
                 time, so whether it did cannot be told; schtasks /Query /TN {} shows what it \
                 holds",
                asked.as_str(),
                name,
                name
            ),
            TaskError::ReadBack { found, undone, .. } => {
                let found = match found {
                    ReadBack::Differs(differences) => {
                        shown!(
                            "reads back differently ({})",
                            self::differences(differences)
                        )
                    }
                    ReadBack::Gone => Shown::said("cannot be found"),
                    ReadBack::Foreign(foreign) => shown!(
                        "now reads back as a task that is not this environment's own: {}",
                        self::foreign(&foreign.reason)
                    ),
                    ReadBack::Unread(_) => Shown::said("could not be read back"),
                };
                shown!(
                    "the scheduled task {} was changed and {}; the change was {}",
                    name,
                    found,
                    if *undone { "undone" } else { "not undone" }
                )
            }
            TaskError::Locked(_) => shown!(
                "another change to the scheduled task {} held it for longer than the wait, or its \
                 lock could not be taken",
                name
            ),
            TaskError::Unwritten(_) => shown!(
                "the definition of the scheduled task {} could not be written in the environment's \
                 state directory",
                name
            ),
        }
    }

    /// How the task's last run ended, which is one result for all of its runs.
    pub fn last_result(result: LastResult) -> Shown {
        match result {
            LastResult::NotRun => Shown::said("it has not run since it was registered"),
            LastResult::Running => Shown::said("a run of it is under way"),
            LastResult::Ended(0) => Shown::said("its last run succeeded"),
            LastResult::Ended(code) => shown!(
                "its last run ended with code 0x{}",
                Shown::hexadecimal(u64::from(code))
            ),
        }
    }

    /// The word a report's `--json` form gives a last result.
    pub fn last_result_word(result: LastResult) -> String {
        match result {
            LastResult::NotRun => "not_run".to_owned(),
            LastResult::Running => "running".to_owned(),
            LastResult::Ended(code) => format!("0x{code:08x}"),
        }
    }

    /// What the environment's task is, read for a person: whose it is, whether it is the one this
    /// installation registers, and whether a start can use it now.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Report {
        /// The environment.
        pub environment_id: EnvironmentId,
        /// Where its task stands, or why that could not be read.
        pub standing: Result<Standing, TaskError>,
        /// Whether the program the task runs, this installation's daemon, is there.
        pub program_present: bool,
        /// The login session this command runs in, when it could be read.
        pub session: Option<u32>,
        /// How the task's last run ended, when it could be read.
        pub last_result: Option<LastResult>,
    }

    impl Report {
        /// Whose the task is: `own`, `absent`, `foreign` or `unknown`.
        pub const fn ownership(&self) -> &'static str {
            match &self.standing {
                Ok(Standing::Owned(_)) => "own",
                Ok(Standing::Absent) => "absent",
                Ok(Standing::Foreign(_)) => "foreign",
                Err(_) => "unknown",
            }
        }

        /// Whether the task is this environment's own, the one this installation registers, and
        /// runs a program that is there.
        pub fn usable(&self) -> bool {
            matches!(&self.standing, Ok(Standing::Owned(differences)) if differences.is_empty())
                && self.program_present
        }

        /// Whose the task is, whether it is valid, and whether a start can use it, apart.
        pub fn describe(&self) -> Shown {
            let name = name(self.environment_id);
            let whose = match &self.standing {
                Ok(Standing::Absent) => {
                    return shown!(
                        "the scheduled task {} is not registered: {} registers it",
                        name,
                        SETUP_ACTION
                    );
                }
                Ok(Standing::Foreign(foreign)) => {
                    return shown!(
                        "a task named {} is registered and is not this environment's own: {}; kr \
                         neither replaces nor removes it",
                        name,
                        self::foreign(&foreign.reason)
                    );
                }
                Err(error) => {
                    return shown!(
                        "the scheduled task {} cannot be read: {}",
                        name,
                        self::error(error, self.environment_id)
                    );
                }
                Ok(Standing::Owned(differences)) => differences,
            };
            let valid = if !whose.is_empty() {
                shown!(
                    "it differs from the one this installation registers: {}; {} repairs it",
                    differences(whose),
                    SETUP_ACTION
                )
            } else if self.program_present {
                Shown::said("it is the one this installation registers")
            } else {
                Shown::said(
                    "it is the one this installation registers, and the program it runs, this \
                     installation's kr-controller, is not there",
                )
            };
            let available = match self.session {
                Some(0) => Shown::said(
                    "this command runs in no interactive session (login session 0), so whether \
                     you are signed in elsewhere is not known here, and the task starts the \
                     daemon only in a session where you are signed in",
                ),
                Some(session) => shown!(
                    "you are signed in to login session {}, where the task can start the daemon",
                    session
                ),
                None => Shown::said(
                    "this command's login session cannot be read, and the task starts the daemon \
                     only in a session where you are signed in",
                ),
            };
            let last = self.last_result.map_or_else(
                || Shown::said("its last result cannot be read"),
                last_result,
            );
            shown!(
                "the scheduled task {} is this environment's own; {}; {}; {}, for all of its \
                 runs; the daemon it starts runs only while you are signed in, so signing out \
                 ends it and every session",
                name,
                valid,
                available,
                last
            )
        }

        /// The report as a command's `--json` output carries it.
        pub fn json(&self) -> serde_json::Value {
            let differences = match &self.standing {
                Ok(Standing::Owned(differences)) => differences
                    .iter()
                    .map(|found| difference(found).into_string())
                    .collect::<Vec<_>>(),
                _ => Vec::new(),
            };
            serde_json::json!({
                "name": name(self.environment_id).into_string(),
                "ownership": self.ownership(),
                "valid": match &self.standing {
                    Ok(Standing::Owned(found)) => Some(found.is_empty()),
                    _ => None,
                },
                "differences": differences,
                "program_present": self.program_present,
                "session": self.session,
                "interactive": self.session.map(|session| session != 0),
                "last_result": self.last_result.map(last_result_word),
                "ends_at_sign_out": true,
            })
        }
    }
}

/// What the environment's scheduled task is, for `kr doctor`: reported where the standalone start is
/// chosen, and otherwise only where this environment's own task is still registered.
#[cfg(windows)]
pub(crate) fn task_report(environment: &EnvironmentPaths, selected: bool) -> Option<task::Report> {
    windows::report(environment, selected)
}

/// The standalone start on Windows: this user's scheduled task for the environment, which the
/// setup step registers and `kr new` runs.
#[cfg(windows)]
mod windows {
    use std::path::Path;
    use std::time::Duration;

    use kr_client::shown;
    use kr_client::shown::Shown;
    use kr_controller::supervision::windows::{
        self as scheduled, Standing, TaskChange, TaskDefinition,
    };
    use kr_ipc::paths::EnvironmentPaths;
    use kr_protocol::hostinfo::configuration::{Change, ControllerStartup};
    use kr_protocol::scalars::Uuid;

    use super::task;
    use crate::error::{CliError, Result};

    /// The task this installation registers for `environment`: this user's, logging on where the
    /// user is signed in, and running `program`, the daemon installed beside this command, as the
    /// environment's starter.
    fn definition(environment: &EnvironmentPaths, program: &Path) -> Result<TaskDefinition> {
        let user = kr_ipc::starter::current_user_sid().map_err(|error| {
            CliError::HostUnavailable(shown!(
                "this account's security identifier could not be read: {}",
                Shown::io(&error)
            ))
        })?;
        Ok(TaskDefinition::for_setup(user, environment, program))
    }

    /// What `kr host startup` did to the environment's task.
    #[derive(Debug)]
    pub struct TaskChanged {
        /// What changed.
        change: TaskChange,
        /// A task under the name that `--clear` left, and why.
        left: Option<scheduled::TaskError>,
    }

    impl TaskChanged {
        /// What was done, for a person.
        pub fn describe(&self, environment_id: kr_protocol::ids::EnvironmentId) -> Shown {
            let name = task::name(environment_id);
            let done = match &self.change {
                TaskChange::Unchanged if self.left.is_some() => Shown::said("nothing was removed"),
                TaskChange::Unchanged => shown!("the scheduled task {} needed no change", name),
                TaskChange::Registered => shown!("registered the scheduled task {}", name),
                TaskChange::Repaired { .. } => shown!(
                    "registered the scheduled task {} again, as this installation registers it",
                    name
                ),
                TaskChange::Removed { .. } => shown!(
                    "removed the scheduled task {}; a daemon or worker it started keeps running",
                    name
                ),
            };
            match &self.left {
                Some(left) => shown!(
                    "{}; left {}: {}",
                    done,
                    name,
                    task::error(left, environment_id)
                ),
                None => done,
            }
        }

        /// What was done, as a command's `--json` output carries it.
        pub fn json(&self) -> serde_json::Value {
            serde_json::json!({
                "change": match &self.change {
                    TaskChange::Unchanged => "unchanged",
                    TaskChange::Registered => "registered",
                    TaskChange::Repaired { .. } => "repaired",
                    TaskChange::Removed { .. } => "removed",
                },
                "left": self.left.is_some(),
            })
        }
    }

    /// Brings the environment's task in line with `startup` and then writes `change`, the
    /// document's edit, with the environment's lock held by the caller.
    ///
    /// Choosing the standalone start registers the task, or repairs this environment's own; a task
    /// under the name that is not this environment's is refused with nothing changed. Choosing
    /// nothing removes this environment's own task, and a task it could not remove is reported and
    /// left. Either way the task is changed first and the document second; a document that could
    /// not be written has the task put back as it was: a task registered here removed, one
    /// repaired or removed here registered again from what it was.
    pub fn change(
        environment: &EnvironmentPaths,
        startup: Option<ControllerStartup>,
        change: &Change,
    ) -> Result<TaskChanged> {
        let program = super::daemon_program()?;
        let definition = definition(environment, &program)?;
        let environment_id = environment.environment_id();
        let standalone = startup == Some(ControllerStartup::Standalone);
        if standalone && !program.is_file() {
            return Err(CliError::Usage(shown!(
                "the standalone start runs the control daemon installed beside this command, {}, \
                 and there is none there; nothing was changed",
                Shown::root(&program)
            )));
        }
        // Held until the document is written or the task is put back, so another environment
        // whose task shares the name cannot change it in between.
        let registration = scheduled::registration(&definition)
            .map_err(|error| refused(&error, environment_id))?;
        let changed = if standalone {
            let change = registration
                .set_up()
                .map_err(|error| refused(&error, environment_id))?;
            TaskChanged { change, left: None }
        } else {
            match registration.clear() {
                Ok(change) => TaskChanged { change, left: None },
                Err(error) => TaskChanged {
                    change: TaskChange::Unchanged,
                    left: Some(error),
                },
            }
        };
        let prior = super::Chosen::read(environment).controller;
        if let Err(error) = crate::doctor::configuration::apply(environment, change) {
            return Err(put_back(
                environment,
                &registration,
                &changed.change,
                prior,
                &error,
            ));
        }
        Ok(changed)
    }

    /// The failure of a change to the environment's task, which says whether the task is as it
    /// was.
    fn refused(
        error: &scheduled::TaskError,
        environment_id: kr_protocol::ids::EnvironmentId,
    ) -> CliError {
        let said = task::error(error, environment_id);
        match error {
            scheduled::TaskError::Locked(_) => {
                CliError::HostUnavailable(shown!("{}; nothing was changed", said))
            }
            _ if error.changed_nothing() => {
                CliError::Usage(shown!("{}; nothing was changed", said))
            }
            _ => CliError::HostUnavailable(said),
        }
    }

    /// The failure of a document write, with the task put back as it was, or what could not be.
    ///
    /// The prior choice is written back where the failed write left another one, and the task is
    /// put back under the registration the change was made under, which is still held.
    fn put_back(
        environment: &EnvironmentPaths,
        registration: &scheduled::Registration<'_>,
        change: &TaskChange,
        prior: Option<ControllerStartup>,
        error: &CliError,
    ) -> CliError {
        let environment_id = environment.environment_id();
        let choice = super::restore_choice(environment, prior);
        match registration.undo(change) {
            Ok(()) => CliError::Usage(shown!(
                "{}; the scheduled task {} is as it was, and {}",
                *error,
                task::name(environment_id),
                choice
            )),
            Err(undone) => CliError::HostUnavailable(shown!(
                "{}; the scheduled task could not be put back as it was: {}; {}",
                *error,
                task::error(&undone, environment_id),
                choice
            )),
        }
    }

    /// Reads what the environment's task is, for `kr host startup` and `kr doctor`.
    ///
    /// Reported where the standalone start is chosen, and otherwise only where this environment's
    /// own task is still registered, which nothing then uses.
    pub fn report(environment: &EnvironmentPaths, selected: bool) -> Option<task::Report> {
        let program = super::daemon_program().ok()?;
        let definition = definition(environment, &program).ok()?;
        let standing = scheduled::standing(&definition);
        if !selected && !matches!(standing, Ok(Standing::Owned(_))) {
            return None;
        }
        let last_result = match standing {
            Ok(Standing::Owned(_)) => scheduled::last_result(&definition).ok(),
            _ => None,
        };
        Some(task::Report {
            environment_id: environment.environment_id(),
            standing,
            program_present: program.is_file(),
            session: kr_ipc::starter::current_session().ok(),
            last_result,
        })
    }

    /// A request left for the environment's starter, and the task run that is to take it.
    #[derive(Debug)]
    pub struct Asked {
        /// The request the starter takes.
        pub request: Uuid,
        /// The login session this command runs in, when it could be read.
        pub session: Option<u32>,
    }

    /// Checks the environment's task, leaves a request to start the daemon for its starter, and
    /// runs it, all under the environment's lock, which is let go before the command waits.
    ///
    /// The request lapses `bound` from now: a starter the Task Scheduler runs later than that
    /// starts nothing for it.
    pub fn ask(environment: &EnvironmentPaths, program: &Path, bound: Duration) -> Result<Asked> {
        let definition = definition(environment, program)?;
        let environment_id = environment.environment_id();
        let name = task::name(environment_id);
        let held = crate::service_manager::lock(environment)?;
        match scheduled::standing(&definition) {
            Ok(Standing::Owned(differences)) if differences.is_empty() => {}
            Ok(Standing::Owned(differences)) => {
                return Err(CliError::HostUnavailable(shown!(
                    "startup.controller is standalone and the scheduled task {} is not the one \
                     this installation registers: {}; {} to repair it",
                    name,
                    task::differences(&differences),
                    task::SETUP_ACTION
                )));
            }
            Ok(Standing::Absent) => {
                return Err(CliError::HostUnavailable(shown!(
                    "startup.controller is standalone and the scheduled task {} is not registered; \
                     {}",
                    name,
                    task::SETUP_ACTION
                )));
            }
            Ok(Standing::Foreign(foreign)) => {
                return Err(CliError::HostUnavailable(shown!(
                    "startup.controller is standalone and a task named {} is registered that is \
                     not this environment's own: {}; kr neither replaces nor removes it, so remove \
                     it with schtasks /Delete /TN {}, then {}",
                    name,
                    task::foreign(&foreign.reason),
                    name,
                    task::SETUP_ACTION
                )));
            }
            Err(error) => {
                return Err(CliError::HostUnavailable(task::error(
                    &error,
                    environment_id,
                )));
            }
        }
        let boot = kr_ipc::identity::boot_identity().map_err(CliError::Ipc)?;
        let request = kr_ipc::new_uuid();
        let lapses = kr_ipc::clock::boot_elapsed_ms()
            .saturating_add(u64::try_from(bound.as_millis()).unwrap_or(u64::MAX));
        kr_ipc::starter::leave_claim(
            environment,
            &kr_ipc::starter::StartClaim {
                request,
                boot,
                deadline_boot_ms: lapses,
            },
        )
        .map_err(CliError::Ipc)?;
        if let Err(failure) = scheduled::run(&definition) {
            let asked = match failure {
                kr_controller::supervision::RunFailure::NotRun(_) => {
                    Shown::said("could not be asked to run it")
                }
                kr_controller::supervision::RunFailure::Failed(_) => Shown::said("did not run it"),
            };
            return Err(CliError::Unfinished {
                code: kr_protocol::error::ErrorCode::EnvironmentUnavailable,
                message: shown!(
                    "the Task Scheduler {} the scheduled task {} for environment {}, so no control \
                     daemon was started; schtasks /Query /TN {} shows what it holds",
                    asked,
                    name,
                    environment_id,
                    name
                ),
            });
        }
        drop(held);
        Ok(Asked {
            request,
            session: kr_ipc::starter::current_session().ok(),
        })
    }

    /// The failure of a start whose request no starter took: the Task Scheduler did not start the
    /// task's starter, which it does only in a session where the user is signed in.
    pub fn not_taken(
        environment: &EnvironmentPaths,
        bound: Duration,
        session: Option<u32>,
    ) -> CliError {
        let environment_id = environment.environment_id();
        let program = super::daemon_program().ok();
        let last = program
            .and_then(|program| definition(environment, &program).ok())
            .and_then(|definition| scheduled::last_result(&definition).ok())
            .map_or_else(
                || Shown::said("its last result cannot be read"),
                task::last_result,
            );
        let here = match session {
            Some(0) => {
                Shown::said("; this command runs in no interactive session (login session 0)")
            }
            Some(session) => shown!("; this command runs in login session {}", session),
            None => Shown::said(""),
        };
        CliError::Unfinished {
            code: kr_protocol::error::ErrorCode::EnvironmentUnavailable,
            message: shown!(
                "the scheduled task {} was run for environment {} and its starter did not take the \
                 request to start the control daemon within {} seconds, so no daemon was started: \
                 the task starts it only in a session where you are signed in{}; sign in to this \
                 computer, at its console or over remote desktop, and run kr new again ({}, for \
                 all of the task's runs)",
                task::name(environment_id),
                environment_id,
                bound.as_secs(),
                here,
                last
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// KR-REQ-07.12: only an endpoint nothing listens on is one a daemon may be started for.
    #[test]
    fn a_daemon_is_started_only_where_nothing_listens() {
        for kind in [
            std::io::ErrorKind::NotFound,
            std::io::ErrorKind::ConnectionRefused,
        ] {
            assert!(nothing_listening(&kr_ipc::IpcError::socket(
                "connect",
                std::io::Error::from(kind)
            )));
        }
        assert!(!nothing_listening(&kr_ipc::IpcError::socket(
            "connect",
            std::io::Error::from(std::io::ErrorKind::PermissionDenied)
        )));
        assert!(!nothing_listening(&kr_ipc::IpcError::PeerClosed));
    }

    /// KR-REQ-07.13: an environment that chooses nothing is told the setup action, which names every
    /// way a daemon comes to run: started by hand, by the service manager once the service start is
    /// chosen, or by `kr new` once the standalone start is chosen.
    #[test]
    fn an_environment_that_chooses_nothing_is_told_both_ways_to_set_up() {
        let host = kr_ipc::testing::TempHost::create();
        let chosen = Chosen::read(&host.environment());
        assert_eq!(chosen.controller, None);
        assert_eq!(chosen.state, DocumentState::Absent);
        let action = chosen.setup_action();
        assert!(
            action
                .as_str()
                .contains("start the control daemon, kr-controller"),
            "{action}"
        );
        #[cfg(unix)]
        assert!(
            action.as_str().contains("kr host startup --set service")
                && action.as_str().contains("kr host startup --set standalone"),
            "{action}"
        );
        #[cfg(windows)]
        assert!(
            action.as_str().contains("kr host startup --set standalone")
                && !action.as_str().contains("--set service"),
            "the one start this platform has: {action}"
        );

        kr_ipc::paths::write_owner_only_file(
            &crate::doctor::configuration::document_path(&host.environment()),
            br#"{"version": 1, "startup": {"controller": "elsewhere"}}"#,
        )
        .expect("writes a document this build does not read");
        let unusable = Chosen::read(&host.environment());
        assert_eq!(unusable.controller, None);
        assert_eq!(unusable.state, DocumentState::Invalid);
        assert!(
            unusable.setup_action().as_str().contains("is invalid"),
            "{}",
            unusable.setup_action()
        );
    }

    /// KR-REQ-07.12: what `kr new` says it started names the start, and the service manager that
    /// started the daemon under the service start.
    #[test]
    fn what_kr_new_started_names_the_start_and_the_manager() {
        let environment = kr_protocol::ids::EnvironmentId::new(kr_ipc::new_uuid());
        let standalone = Started {
            pid: Some(4242),
            start: ControllerStartup::Standalone,
            manager: None,
        };
        assert_eq!(
            standalone.describe(environment).as_str(),
            format!(
                "started the control daemon for environment {environment} (process 4242) under \
                 the standalone start"
            )
        );
        let service = Started {
            pid: None,
            start: ControllerStartup::Service,
            manager: Some(service_manager::Manager::Systemd),
        };
        assert_eq!(
            service.describe(environment).as_str(),
            format!(
                "systemd started the control daemon for environment {environment} under the \
                 service start"
            )
        );
    }

    /// KR-REQ-07.12: the standalone start serves this installation's own environment and no other,
    /// and refuses another one with what to do about it rather than starting a daemon that would
    /// serve somewhere else.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_standalone_start_serves_this_installations_own_environment_only() {
        let host = kr_ipc::testing::TempHost::create();
        let other = kr_protocol::ids::EnvironmentId::new(kr_ipc::new_uuid());
        let paths = host.paths().environment(other);
        paths.create().expect("a second environment on this host");
        kr_ipc::paths::write_owner_only_file(
            &crate::doctor::configuration::document_path(&paths),
            br#"{"version": 1, "revision": 1, "startup": {"controller": "standalone"}}"#,
        )
        .expect("chooses the standalone start there");
        let Err(refused) = open_or_start(
            host.paths(),
            &KnownEnvironment {
                environment_id: other,
                paths,
            },
        )
        .await
        else {
            panic!("no daemon serves another environment");
        };
        assert_eq!(refused.code(), "HOST_NOT_CONFIGURED");
        let message = refused.to_string();
        assert!(
            message.contains(&format!(
                "the standalone start serves this installation's own environment, {}, and no other",
                host.environment_id()
            )),
            "{message}"
        );
        assert!(
            !host
                .paths()
                .environment(other)
                .state_dir()
                .join(LOG_FILE)
                .exists(),
            "and nothing was started for it"
        );
    }

    /// Something that accepts connections on an environment's endpoint and never says hello.
    #[cfg(unix)]
    struct Silent {
        accepting: tokio::task::JoinHandle<()>,
    }

    #[cfg(unix)]
    impl Silent {
        fn listen(endpoint: &kr_ipc::paths::Endpoint) -> Self {
            let listener = kr_ipc::endpoint::Listener::bind(endpoint).expect("binds the endpoint");
            Self {
                accepting: tokio::spawn(async move {
                    let mut held = Vec::new();
                    while let Ok(accepted) = listener.accept().await {
                        held.push(accepted);
                    }
                }),
            }
        }
    }

    #[cfg(unix)]
    impl Drop for Silent {
        fn drop(&mut self) {
            self.accepting.abort();
        }
    }

    /// KR-REQ-07.12: a daemon that accepts the connection and never answers is waited for no
    /// longer than the bound, both when it is first tried and while a start waits for an answer.
    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread")]
    async fn an_endpoint_that_never_answers_is_waited_for_no_longer_than_the_bound() {
        let host = kr_ipc::testing::TempHost::create();
        let endpoint = host
            .environment()
            .controller_endpoint()
            .expect("an endpoint");
        let _silent = Silent::listen(&endpoint);

        let started = tokio::time::Instant::now();
        assert!(matches!(
            reach(&endpoint, Duration::from_millis(300)).await,
            Reached::Silent
        ));
        let deadline = tokio::time::Instant::now() + Duration::from_millis(500);
        let mut attempts = 0;
        let last = answered_by(&endpoint, deadline, || attempts += 1)
            .await
            .map(|_| ())
            .expect_err("nothing answers");
        assert!(last.as_str().contains("did not answer"), "{last}");
        assert!(attempts >= 1);
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "both waits ended at their bounds: {:?}",
            started.elapsed()
        );
    }

    /// KR-REQ-07.12: with the standalone start chosen, a daemon that is listening and does not
    /// answer is reported as the environment being unavailable, and nothing is started beside it.
    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread")]
    async fn a_daemon_that_does_not_answer_is_reported_and_none_is_started_beside_it() {
        let host = kr_ipc::testing::TempHost::create();
        let environment = host.environment();
        kr_ipc::paths::write_owner_only_file(
            &crate::doctor::configuration::document_path(&environment),
            br#"{"version": 1, "revision": 1, "startup": {"controller": "standalone"}}"#,
        )
        .expect("chooses the standalone start");
        let _silent = Silent::listen(&environment.controller_endpoint().expect("an endpoint"));

        let Err(refused) = open_or_start_within(
            host.paths(),
            &KnownEnvironment {
                environment_id: host.environment_id(),
                paths: environment.clone(),
            },
            Bounds {
                answer: Duration::from_millis(300),
                start: Duration::from_secs(1),
            },
        )
        .await
        else {
            panic!("nothing answered");
        };
        assert_eq!(refused.code(), "ENVIRONMENT_UNAVAILABLE");
        assert!(
            refused
                .to_string()
                .contains("accepted the connection and did not answer within 0.3 seconds"),
            "{refused}"
        );
        assert!(
            !environment.state_dir().join(LOG_FILE).exists(),
            "and no daemon was started beside it"
        );
    }

    /// The log is taken only when it is a regular file of this user's that nobody else can read
    /// or write, and a failure reads back the last line written since its start began.
    #[cfg(unix)]
    #[test]
    fn the_log_is_checked_and_read_from_where_this_start_began() {
        use std::os::unix::fs::PermissionsExt as _;

        let host = kr_ipc::testing::TempHost::create();
        let directory = host.environment().state_dir().to_path_buf();
        let log = directory.join(LOG_FILE);
        let opened = Log::open(&log).expect("opens a new log");
        assert_eq!(opened.from, 0);
        assert_eq!(opened.last_line(), None, "a start that wrote nothing");
        drop(opened);
        std::fs::write(&log, "an earlier start\n").expect("an earlier start's line");
        let opened = Log::open(&log).expect("opens the log");
        assert_eq!(opened.last_line(), None, "which is not this start's");
        std::fs::write(&log, "an earlier start\nthis start\nand its last word\n\n")
            .expect("this start's lines");
        assert_eq!(opened.last_line().as_deref(), Some("and its last word"));

        std::fs::set_permissions(&log, std::fs::Permissions::from_mode(0o644))
            .expect("widens the log");
        assert!(Log::open(&log).is_err(), "a log others can read is refused");

        let fifo = directory.join("fifo-log");
        let made = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .expect("runs mkfifo");
        assert!(made.success());
        assert!(
            Log::open(&fifo).is_err(),
            "a FIFO is refused, and opening it does not wait"
        );

        let link = directory.join("linked-log");
        std::os::unix::fs::symlink(&log, &link).expect("links the log");
        assert!(Log::open(&link).is_err(), "a link is not followed");
    }

    /// The last line of a daemon's log is said only when it is the daemon's own refusal of an
    /// environment another daemon holds, which names that environment by its identifier. Any other
    /// line is replaced.
    #[cfg(unix)]
    #[test]
    fn a_daemons_last_line_is_said_only_when_it_is_its_own_refusal() {
        use crate::shown::marker::{MARKER, assert_unmarked};

        let environment = kr_protocol::ids::EnvironmentId::new(kr_ipc::new_uuid());
        let held =
            format!("kr-controller: another control daemon already owns environment {environment}");
        assert_eq!(
            last_line_said(&held).as_str(),
            format!("the last line its log holds since it started is: {held}")
        );
        for line in [
            MARKER.to_owned(),
            format!("kr-controller: {MARKER}"),
            format!("kr-controller: another control daemon already owns environment {MARKER}"),
            format!("{held} {MARKER}"),
        ] {
            let said = last_line_said(&line);
            assert_eq!(
                said.as_str(),
                "its log holds a line since it started, which is not repeated here",
                "{line}"
            );
            assert_unmarked("a daemon's last line", &[said.into_string()]);
        }
    }

    /// Every finding about a task that was read from the Task Scheduler or from the task itself,
    /// planted with the marker: none of the ways this command says a task repeats what it holds.
    fn marked_findings() -> Vec<kr_controller::supervision::windows::Difference> {
        use crate::shown::marker::MARKER;
        use kr_controller::supervision::windows::{Difference, LogonType};

        vec![
            Difference::Program {
                found: MARKER.to_owned(),
                expected: std::path::PathBuf::from("kr-controller.exe"),
            },
            Difference::Arguments {
                found: MARKER.to_owned(),
                expected: "--starter".to_owned(),
            },
            Difference::WorkingDirectory {
                found: MARKER.to_owned(),
                expected: std::path::PathBuf::from("state"),
            },
            Difference::Actions(2),
            Difference::Triggered,
            Difference::Logon {
                found: Some(LogonType::S4U),
                expected: LogonType::InteractiveToken,
            },
            Difference::Logon {
                found: None,
                expected: LogonType::InteractiveToken,
            },
            Difference::RunLevel(MARKER.to_owned()),
            Difference::NotOnBatteries,
            Difference::StopsOnBatteries,
            Difference::WaitsForIdle,
            Difference::StopsWhenBusy,
            Difference::WaitsForNetwork,
            Difference::NotOnDemand,
            Difference::NotParallel(MARKER.to_owned()),
            Difference::TimeLimited(MARKER.to_owned()),
            Difference::Priority(MARKER.to_owned()),
            Difference::Disabled,
        ]
    }

    /// KR-REQ-07.12: each way a task can differ from the one this installation registers is said
    /// in this command's own words, one of its own for each, and never with what the task holds.
    #[test]
    fn each_way_a_task_differs_is_said_in_this_commands_words() {
        use crate::shown::marker::assert_unmarked;

        let findings = marked_findings();
        let said: Vec<String> = findings
            .iter()
            .map(|finding| task::difference(finding).into_string())
            .collect();
        assert_unmarked("a task's differences", &said);
        let distinct: std::collections::BTreeSet<&String> = said.iter().collect();
        assert_eq!(distinct.len(), said.len(), "each is its own: {said:?}");
        assert_eq!(
            said[5], "it logs on as S4U, not InteractiveToken",
            "a logon is said by the Task Scheduler's own name for it"
        );
        let daemon: Vec<String> = findings.iter().map(ToString::to_string).collect();
        assert!(
            daemon[0].contains(crate::shown::marker::MARKER),
            "the negative control: the daemon's own record of a refused launch says what it read"
        );
    }

    /// KR-REQ-07.12: `kr host startup` and `kr doctor` report whose the environment's scheduled task
    /// is, whether it is the one this installation registers, and whether a start can use it now,
    /// apart; the last result as one for all of the task's runs; and that the daemon it starts ends
    /// when the user signs out. A task read from the Task Scheduler never has what it holds
    /// repeated.
    #[test]
    fn a_task_is_reported_whose_valid_and_available_apart() {
        use crate::shown::marker::{MARKER, assert_unmarked};
        use kr_controller::supervision::windows::{
            Asked, Foreign, ForeignReason, LastResult, Outcome, Standing, TaskError,
        };

        let environment_id = kr_protocol::ids::EnvironmentId::new(kr_ipc::new_uuid());
        let name = kr_controller::supervision::windows::task_name(environment_id);
        let foreign = |reason| Foreign {
            name: name.clone(),
            environment_id,
            reason,
        };
        let report = |standing, program_present, session, last_result| task::Report {
            environment_id,
            standing,
            program_present,
            session,
            last_result,
        };

        let usable = report(
            Ok(Standing::Owned(Vec::new())),
            true,
            Some(2),
            Some(LastResult::Ended(0)),
        );
        assert!(usable.usable());
        let said = usable.describe().into_string();
        for part in [
            name.as_str(),
            "is this environment's own",
            "it is the one this installation registers",
            "you are signed in to login session 2",
            "its last run succeeded, for all of its runs",
            "signing out ends it and every session",
        ] {
            assert!(said.contains(part), "{part}: {said}");
        }
        let json = usable.json();
        assert_eq!(json["ownership"], "own");
        assert_eq!(json["valid"], true);
        assert_eq!(json["program_present"], true);
        assert_eq!(json["session"], 2);
        assert_eq!(json["interactive"], true);
        assert_eq!(json["last_result"], "0x00000000");
        assert_eq!(json["ends_at_sign_out"], true);

        let gone = report(Ok(Standing::Owned(Vec::new())), false, Some(0), None);
        assert!(
            !gone.usable(),
            "a task whose program has gone cannot start the daemon"
        );
        let said = gone.describe().into_string();
        assert!(said.contains("is not there"), "{said}");
        assert!(said.contains("login session 0"), "{said}");
        assert!(said.contains("its last result cannot be read"), "{said}");
        assert_eq!(gone.json()["interactive"], false);

        let stale = report(
            Ok(Standing::Owned(marked_findings())),
            true,
            Some(1),
            Some(LastResult::Ended(0x8007_10e0)),
        );
        assert!(!stale.usable());
        let said = stale.describe().into_string();
        assert!(
            said.contains("it differs from the one this installation registers"),
            "{said}"
        );
        assert!(
            said.contains("kr host startup --set standalone repairs it"),
            "{said}"
        );
        assert!(
            said.contains("its last run ended with code 0x00000000800710e0"),
            "{said}"
        );
        assert_eq!(stale.json()["valid"], false);
        assert_eq!(stale.json()["last_result"], "0x800710e0");

        let absent = report(Ok(Standing::Absent), true, Some(1), None);
        assert_eq!(absent.ownership(), "absent");
        assert!(
            absent
                .describe()
                .as_str()
                .contains("is not registered: run kr host startup --set standalone registers it")
        );
        let not_run = report(
            Ok(Standing::Owned(Vec::new())),
            true,
            None,
            Some(LastResult::NotRun),
        );
        assert!(
            not_run
                .describe()
                .as_str()
                .contains("it has not run since it was registered")
        );
        assert_eq!(not_run.json()["last_result"], "not_run");
        assert_eq!(
            report(
                Ok(Standing::Owned(Vec::new())),
                true,
                None,
                Some(LastResult::Running)
            )
            .json()["last_result"],
            "running"
        );

        let mut renderings = Vec::new();
        for reason in [
            ForeignReason::Unreadable {
                said: MARKER.to_owned(),
            },
            ForeignReason::Account {
                user: MARKER.to_owned(),
                description: MARKER.to_owned(),
            },
            ForeignReason::Environment {
                description: MARKER.to_owned(),
            },
        ] {
            let found = report(
                Ok(Standing::Foreign(foreign(reason.clone()))),
                true,
                Some(1),
                None,
            );
            assert_eq!(found.ownership(), "foreign");
            let said = found.describe().into_string();
            assert!(
                said.contains("is not this environment's own")
                    && said.contains("kr neither replaces nor removes it"),
                "{said}"
            );
            renderings.push(said);
            renderings.push(found.json().to_string());
            renderings.push(
                task::error(&TaskError::Foreign(foreign(reason)), environment_id).into_string(),
            );
        }
        for error in [
            TaskError::Scheduler {
                asked: Asked::Register,
                outcome: Outcome::Ended(Some(1)),
                detail: MARKER.to_owned(),
            },
            TaskError::Scheduler {
                asked: Asked::Query,
                outcome: Outcome::NotStarted,
                detail: MARKER.to_owned(),
            },
            TaskError::Scheduler {
                asked: Asked::Register,
                outcome: Outcome::Unseen,
                detail: MARKER.to_owned(),
            },
            TaskError::Scheduler {
                asked: Asked::Remove,
                outcome: Outcome::Ended(None),
                detail: MARKER.to_owned(),
            },
            TaskError::ReadBack {
                name: MARKER.to_owned(),
                found: kr_controller::supervision::windows::ReadBack::Differs(marked_findings()),
                undone: true,
            },
            TaskError::ReadBack {
                name: MARKER.to_owned(),
                found: kr_controller::supervision::windows::ReadBack::Gone,
                undone: false,
            },
            TaskError::ReadBack {
                name: MARKER.to_owned(),
                found: kr_controller::supervision::windows::ReadBack::Unread(MARKER.to_owned()),
                undone: false,
            },
            TaskError::ReadBack {
                name: MARKER.to_owned(),
                found: kr_controller::supervision::windows::ReadBack::Foreign(foreign(
                    ForeignReason::Account {
                        user: MARKER.to_owned(),
                        description: MARKER.to_owned(),
                    },
                )),
                undone: true,
            },
            TaskError::Locked(MARKER.to_owned()),
            TaskError::Unwritten(MARKER.to_owned()),
        ] {
            let unreadable = report(Err(error.clone()), true, Some(1), None);
            assert_eq!(unreadable.ownership(), "unknown");
            renderings.push(unreadable.describe().into_string());
            renderings.push(unreadable.json().to_string());
            let said = task::error(&error, environment_id).into_string();
            assert!(said.contains(&name), "the task is named: {said}");
            renderings.push(said);
        }
        renderings.push(stale.describe().into_string());
        renderings.push(stale.json().to_string());
        assert_unmarked("the environment's scheduled task", &renderings);
        assert!(
            task::error(
                &TaskError::Scheduler {
                    asked: Asked::Remove,
                    outcome: Outcome::Ended(Some(5)),
                    detail: MARKER.to_owned(),
                },
                environment_id
            )
            .as_str()
            .contains("the Task Scheduler did not remove the scheduled task"),
            "a refusal says what was asked and its exit code"
        );
    }

    /// KR-REQ-07.12: a write of the document that failed after it published the new choice, as a
    /// write whose directory could not be flushed after its rename does, has the prior choice
    /// written back, and says so; a failed write that published nothing leaves the choice as it
    /// was.
    #[test]
    fn a_choice_a_failed_write_published_is_written_back() {
        let host = kr_ipc::testing::TempHost::create();
        let environment = host.environment();
        assert_eq!(
            restore_choice(&environment, None).as_str(),
            "startup.controller is as it was"
        );
        // What a write that renamed its file into place and then failed leaves.
        crate::doctor::configuration::apply(
            &environment,
            &Change::ControllerStartup(Some(ControllerStartup::Standalone)),
        )
        .expect("the new choice is published");
        assert_eq!(
            restore_choice(&environment, None).as_str(),
            "startup.controller was written back as it was"
        );
        assert_eq!(Chosen::read(&environment).controller, None);
        crate::doctor::configuration::apply(
            &environment,
            &Change::ControllerStartup(Some(ControllerStartup::Service)),
        )
        .expect("another choice is published");
        assert_eq!(
            restore_choice(&environment, Some(ControllerStartup::Standalone)).as_str(),
            "startup.controller was written back as it was"
        );
        assert_eq!(
            Chosen::read(&environment).controller,
            Some(ControllerStartup::Standalone)
        );
    }

    /// The daemon a starter starts writes to the log this command reads back.
    #[test]
    fn the_starter_writes_the_log_this_command_reads() {
        assert_eq!(kr_controller::supervision::windows::DAEMON_LOG, LOG_FILE);
    }

    /// A way of starting this build does not know is refused by naming the ones it does, and what
    /// was typed is not repeated.
    #[test]
    fn a_way_of_starting_this_build_does_not_know_is_not_repeated() {
        use crate::shown::marker::{MARKER, assert_unmarked, failure_renderings};

        let host = kr_ipc::testing::TempHost::create();
        let refused = run(
            host.paths(),
            &StartupArguments {
                set: Some(MARKER.to_owned()),
                clear: false,
            },
            false,
        )
        .expect_err("no such way of starting");
        assert_eq!(
            refused.to_string(),
            "the value given is not a way of starting the control daemon: choose standalone or \
             service"
        );
        assert_unmarked(
            "a way of starting this build does not know",
            &failure_renderings(refused),
        );
    }
}
