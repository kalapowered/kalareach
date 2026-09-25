//! `kr host startup`, and `kr new` starting this environment's control daemon when none runs.
//!
//! Section 7 lets `kr new` have the per-user controller started on demand only on a host that was
//! set up for it. A host that was not answers `HOST_NOT_CONFIGURED` with the setup action, and the
//! command installs no service, enables no lingering and obtains no privilege on the way. Where no
//! service manager was set up to start the daemon, the setup is the standalone headless profile:
//! the one selection `startup.controller` in this environment's configuration document, which
//! `kr host startup` writes as a validated edit with no daemon running and `kr doctor` reports.
//!
//! Under it, `kr new` runs the daemon installed beside this command, `kr-controller`, detached from
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
//! What such a daemon writes goes to `controller.log` in the environment's state directory, and a
//! daemon that does not answer in time is named in the command's failure with the last line of
//! that log. The command does not end it: a daemon still starting, such as one waiting on a person
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

/// How long `kr new` waits for a daemon it started to answer on its endpoint.
pub const START_BOUND: Duration = Duration::from_secs(30);

/// How long one attempt to reach a daemon that is already listening is given to be answered.
pub const ANSWER_BOUND: Duration = Duration::from_secs(10);

/// How often the endpoint is tried while the command waits.
#[cfg(unix)]
const RETRY: Duration = Duration::from_millis(50);

/// The file in an environment's state directory that a daemon the standalone start runs writes to.
pub const LOG_FILE: &str = "controller.log";

/// The largest the log may be when a start begins. A larger one is emptied first, because a log
/// nobody rotates must not grow for as long as the host is installed.
#[cfg(unix)]
const LOG_LIMIT: u64 = 1024 * 1024;

/// The most of the log a failure reads back.
#[cfg(unix)]
const LOG_TAIL: u64 = 4096;

/// What this environment's configuration document chooses about starting its control daemon.
#[derive(Clone, Debug, PartialEq, Eq)]
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
            Shown::said(resolve::SETUP_ACTION)
        }
    }
}

/// Runs `kr host startup`: shows what this environment chooses, or makes a choice as one validated
/// edit of its configuration document.
///
/// Nothing else changes. No daemon is asked, none is started, no service is installed and no
/// privilege is obtained; `kr new` reads the choice the next time it finds no daemon running.
///
/// # Errors
///
/// Returns [`CliError::Usage`] for a way of starting this build does not know and for an edit the
/// document refuses, and the failure to write the document otherwise.
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
    if let Some(startup) = change {
        #[cfg(not(unix))]
        if startup == Some(ControllerStartup::Standalone) {
            return Err(CliError::Usage(Shown::said(
                "the standalone start runs the control daemon in a session of its own, which this \
                 platform does not have; start the control daemon, kr-controller, for this \
                 environment",
            )));
        }
        crate::doctor::configuration::apply(
            &environment.paths,
            &Change::ControllerStartup(startup),
        )?;
    }
    let chosen = Chosen::read(&environment.paths);
    if json {
        crate::report::print_json(&serde_json::json!({
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
            },
        }));
    } else {
        println!("{}", describe(&chosen));
    }
    Ok(())
}

/// What `kr host startup` tells a person.
fn describe(chosen: &Chosen) -> String {
    match chosen.controller {
        Some(ControllerStartup::Standalone) => format!(
            "startup: standalone, from {} at revision {}: kr new starts this environment's control \
             daemon itself when none is running",
            chosen.document.display(),
            chosen.revision
        ),
        None if chosen.state.is_a_problem() => format!(
            "startup: none, because the configuration document {} is {}: kr new starts no \
             control daemon",
            chosen.document.display(),
            chosen.state.as_str()
        ),
        None => "startup: none: kr new starts no control daemon, and says what to set up when \
                 none is running; kr host startup --set standalone chooses the standalone start"
            .to_owned(),
    }
}

/// A daemon this command started.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Started {
    /// Its process identifier.
    pub pid: u32,
}

/// How long each wait of the standalone start is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Bounds {
    /// One attempt to reach a daemon: the connection and the daemon's hello together. A daemon
    /// that accepts the connection and never says hello has not answered.
    answer: Duration,
    /// From the moment this command starts a daemon to the moment one answers.
    #[cfg(unix)]
    start: Duration,
}

/// The waits `kr new` uses.
const BOUNDS: Bounds = Bounds {
    answer: ANSWER_BOUND,
    #[cfg(unix)]
    start: START_BOUND,
};

/// Reaches the environment's control daemon for `kr new`, starting it first where this
/// environment chooses the standalone start and none is running.
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
    if chosen.controller != Some(ControllerStartup::Standalone) {
        return Err(resolve::not_running(&error, chosen.setup_action()));
    }
    standalone(paths, &environment.paths, &endpoint, bounds).await
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
#[cfg(unix)]
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
    let started = Started { pid: child.id() };
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
        started.pid,
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
#[cfg(unix)]
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

/// The standalone start runs the daemon in a session of its own, which only Unix has.
#[cfg(not(unix))]
async fn standalone(
    _paths: &HostPaths,
    _environment: &EnvironmentPaths,
    _endpoint: &kr_ipc::paths::Endpoint,
    _bounds: Bounds,
) -> Result<(LocalClient, Option<Started>)> {
    Err(CliError::HostUnavailable(Shown::said(
        "this environment chooses the standalone start, which runs the control daemon in a \
         session of its own, and this platform does not have one; start the control daemon, \
         kr-controller, for it",
    )))
}

/// The log a daemon the standalone start runs writes to, opened once and checked.
#[cfg(unix)]
struct Log {
    file: std::fs::File,
    path: PathBuf,
    /// Where this start's part of it begins.
    from: u64,
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
        let mut from = about.len();
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

    /// A handle a daemon writes its output through: the same open file, appended to.
    fn output(&self) -> Result<std::fs::File> {
        self.file
            .try_clone()
            .map_err(|error| CliError::Ipc(kr_ipc::IpcError::io("open", &self.path, error)))
    }

    /// The last line written since this start began, read through the handle that was checked.
    ///
    /// Several starts can share the log, so the line is the log's rather than certainly this
    /// start's daemon's.
    fn last_line(&self) -> Option<String> {
        use std::os::unix::fs::FileExt as _;

        let length = self.file.metadata().ok()?.len();
        let begin = self.from.max(length.saturating_sub(LOG_TAIL));
        let mut bytes = vec![0; usize::try_from(length.saturating_sub(begin)).ok()?];
        let mut read = 0;
        while read < bytes.len() {
            match self.file.read_at(&mut bytes[read..], begin + read as u64) {
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

    /// KR-REQ-07.13: an environment that chooses nothing is told the setup action, which names both
    /// ways a daemon comes to run: started by hand, or by `kr new` once the start is chosen.
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
            action.as_str().contains("kr host startup --set standalone"),
            "{action}"
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
}
