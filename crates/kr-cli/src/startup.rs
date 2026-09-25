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
//! environment's own runtime and state roots. It searches the platform's own directories for the
//! tools it runs, which is the search path a service manager would have given it, rather than
//! whatever the shell that happened to run the first `kr new` puts first. Everything else about it
//! is an ordinary start: it keeps its keys where an installed daemon keeps them, serves the
//! private endpoints it always serves, and takes the environment's singleton lock and advances its
//! generation, which is what leaves one daemon when several commands start one at once. The command
//! waits a bounded time for the daemon's endpoint and then goes on as it would against a daemon that
//! was already running.
//!
//! What such a daemon writes goes to `controller.log` in the environment's state directory, and a
//! daemon that does not answer in time is named in the command's failure with the last thing it
//! wrote. The command does not end it: a daemon still starting, such as one waiting on a person to
//! allow access to a credential store, may yet come up, and the singleton lock already keeps a
//! second one from serving beside it.

use std::path::PathBuf;
use std::time::Duration;

use kr_ipc::client::LocalClient;
use kr_ipc::paths::{EnvironmentPaths, HostPaths};
use kr_protocol::hostinfo::configuration::{Change, ControllerStartup, DocumentState};
use kr_protocol::local::LocalClientKind;

use crate::cli::StartupArguments;
use crate::error::{CliError, Result};
use crate::resolve::{self, KnownEnvironment};

/// How long `kr new` waits for a daemon it started to answer on its endpoint.
pub const START_BOUND: Duration = Duration::from_secs(30);

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

/// Where a daemon the standalone start runs looks for the programs it runs: the search path a
/// per-user service manager gives a daemon on this platform.
#[cfg(target_os = "macos")]
const SEARCH_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";

/// Where a daemon the standalone start runs looks for the programs it runs: the search path a
/// per-user service manager gives a daemon on this platform.
#[cfg(all(unix, not(target_os = "macos")))]
const SEARCH_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

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
    fn setup_action(&self) -> String {
        if self.state.is_a_problem() {
            format!(
                "this environment's configuration document, {}, is {}, so it chooses no way of \
                 starting one; start the control daemon, kr-controller, for it, or correct the \
                 document",
                self.document.display(),
                self.state.as_str()
            )
        } else {
            resolve::SETUP_ACTION.to_owned()
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
                        CliError::Usage(format!(
                            "{value} is not a way of starting the control daemon: choose {}",
                            ControllerStartup::ALL
                                .map(ControllerStartup::as_str)
                                .join(" or ")
                        ))
                    })
            })
            .transpose()?
    };
    if let Some(startup) = change {
        #[cfg(not(unix))]
        if startup == Some(ControllerStartup::Standalone) {
            return Err(CliError::Usage(
                "the standalone start runs the control daemon in a session of its own, which this \
                 platform does not have; start the control daemon, kr-controller, for this \
                 environment"
                    .to_owned(),
            ));
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

/// Reaches the environment's control daemon for `kr new`, starting it first where this
/// environment chooses the standalone start and none is running.
///
/// A daemon is started only when nothing answers on the environment's endpoint at all. One that is
/// there and answers badly is reported as it is, because starting another beside it would be
/// starting a daemon that cannot take the environment.
///
/// # Errors
///
/// Returns [`CliError::HostUnavailable`] with the setup action when no daemon answers and none may
/// be started, and [`CliError::Unfinished`] with `ENVIRONMENT_UNAVAILABLE` when a daemon this
/// command started did not answer within [`START_BOUND`].
pub async fn open_or_start(
    paths: &HostPaths,
    environment: &KnownEnvironment,
) -> Result<(LocalClient, Option<Started>)> {
    let endpoint = environment.paths.controller_endpoint()?;
    let error = match LocalClient::connect(&endpoint, LocalClientKind::Cli, crate::build_id()).await
    {
        Ok(client) => return Ok((client, None)),
        Err(error) => error,
    };
    if !nothing_listening(&error) {
        return Err(resolve::not_running(&error, resolve::SETUP_ACTION));
    }
    let chosen = Chosen::read(&environment.paths);
    if chosen.controller != Some(ControllerStartup::Standalone) {
        return Err(resolve::not_running(&error, &chosen.setup_action()));
    }
    // The daemon beside this command serves the environment its roots name as this installation's
    // own, and no other.
    let installation = paths.open_environment_id()?;
    if environment.environment_id != installation {
        return Err(resolve::not_running(
            &error,
            &format!(
                "the standalone start runs the control daemon of this installation's own \
                 environment, {installation}; start the control daemon, kr-controller, for {}",
                environment.environment_id
            ),
        ));
    }
    standalone(paths, &environment.paths, &endpoint).await
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
        CliError::HostUnavailable(format!(
            "the standalone start runs the control daemon installed beside this command, and \
             where this command is installed could not be read: {error}"
        ))
    };
    let this = std::env::current_exe()
        .and_then(std::fs::canonicalize)
        .map_err(unreadable)?;
    let directory = this.parent().ok_or_else(|| {
        unreadable(std::io::Error::other(
            "this command's path has no directory",
        ))
    })?;
    Ok(directory.join(format!("kr-controller{}", std::env::consts::EXE_SUFFIX)))
}

/// Starts the daemon detached from this command and waits for its endpoint.
#[cfg(unix)]
async fn standalone(
    paths: &HostPaths,
    environment: &EnvironmentPaths,
    endpoint: &kr_ipc::paths::Endpoint,
) -> Result<(LocalClient, Option<Started>)> {
    let program = daemon_program()?;
    if !program.is_file() {
        return Err(CliError::HostUnavailable(format!(
            "the standalone start runs the control daemon installed beside this command, {}, and \
             there is none there",
            program.display()
        )));
    }
    // The directories the daemon works and writes in. It creates them itself as well, and both are
    // the same idempotent creation.
    environment.create()?;
    let log = environment.state_dir().join(LOG_FILE);
    let (written, from) = open_log(&log)?;
    let output = written
        .try_clone()
        .map_err(|error| CliError::Ipc(kr_ipc::IpcError::io("open", &log, error)))?;
    let mut child = std::process::Command::new(&program)
        .arg("--runtime-dir")
        .arg(paths.runtime_root())
        .arg("--state-dir")
        .arg(paths.state_root())
        .arg("--own-session")
        .current_dir(environment.state_dir())
        .env("PATH", SEARCH_PATH)
        .stdin(std::process::Stdio::null())
        .stdout(output)
        .stderr(written)
        .spawn()
        .map_err(|error| {
            CliError::HostUnavailable(format!(
                "the control daemon {} could not be started: {error}",
                program.display()
            ))
        })?;
    let started = Started { pid: child.id() };
    let deadline = tokio::time::Instant::now() + START_BOUND;
    let last = loop {
        match LocalClient::connect(endpoint, LocalClientKind::Cli, crate::build_id()).await {
            // The daemon this command started, or the one another command started first: either way
            // the environment has its daemon, and it is the one the lock let through.
            Ok(client) => return Ok((client, Some(started))),
            Err(error) if tokio::time::Instant::now() >= deadline => break error,
            Err(_) => {}
        }
        // Collected as soon as it ends, so a daemon that could not take the environment is not
        // left waiting on this command.
        let _ = child.try_wait();
        tokio::time::sleep(RETRY).await;
    };
    let ended = child.try_wait().ok().flatten();
    let state = ended.map_or_else(
        || "it is still running".to_owned(),
        |status| format!("it has ended ({status})"),
    );
    let said = last_line(&log, from).map_or_else(
        || "it wrote nothing".to_owned(),
        |line| format!("the last it wrote was: {line}"),
    );
    Err(CliError::Unfinished {
        code: kr_protocol::error::ErrorCode::EnvironmentUnavailable,
        message: format!(
            "the control daemon this command started for environment {} (process {}) did not \
             answer within {} seconds: {last}; {state}, and {said}; what it writes is in {}",
            environment.environment_id(),
            started.pid,
            START_BOUND.as_secs(),
            log.display()
        ),
    })
}

/// The standalone start runs the daemon in a session of its own, which only Unix has.
#[cfg(not(unix))]
async fn standalone(
    _paths: &HostPaths,
    _environment: &EnvironmentPaths,
    _endpoint: &kr_ipc::paths::Endpoint,
) -> Result<(LocalClient, Option<Started>)> {
    Err(CliError::HostUnavailable(
        "this environment chooses the standalone start, which runs the control daemon in a \
         session of its own, and this platform does not have one; start the control daemon, \
         kr-controller, for it"
            .to_owned(),
    ))
}

/// Opens the log a daemon the standalone start runs writes to: for appending, owner-only, and never
/// through a link. Returns it and where this start's part of it begins.
#[cfg(unix)]
fn open_log(path: &std::path::Path) -> Result<(std::fs::File, u64)> {
    use std::os::unix::fs::OpenOptionsExt as _;

    let failed = |error| CliError::Ipc(kr_ipc::IpcError::io("open", path, error));
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(failed)?;
    let mut length = file.metadata().map_err(failed)?.len();
    if length > LOG_LIMIT {
        file.set_len(0).map_err(failed)?;
        length = 0;
    }
    Ok((file, length))
}

/// The last line written to the log since `from`, when there is one.
#[cfg(unix)]
fn last_line(path: &std::path::Path, from: u64) -> Option<String> {
    use std::io::{Read as _, Seek as _};

    let mut file = std::fs::File::open(path).ok()?;
    let length = file.metadata().ok()?.len();
    file.seek(std::io::SeekFrom::Start(
        from.max(length.saturating_sub(LOG_TAIL)),
    ))
    .ok()?;
    let mut bytes = Vec::new();
    file.take(LOG_TAIL).read_to_end(&mut bytes).ok()?;
    String::from_utf8_lossy(&bytes)
        .lines()
        .map(str::trim)
        .rfind(|line| !line.is_empty())
        .map(str::to_owned)
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
            action.contains("start the control daemon, kr-controller"),
            "{action}"
        );
        assert!(
            action.contains("kr host startup --set standalone"),
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
            unusable.setup_action().contains("is invalid"),
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
                "this installation's own environment, {}",
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

    /// A failure reads back the last thing the daemon it started wrote, from where its start
    /// began.
    #[cfg(unix)]
    #[test]
    fn the_last_line_is_read_from_where_this_start_began() {
        let host = kr_ipc::testing::TempHost::create();
        let log = host.environment().state_dir().join(LOG_FILE);
        let (_, from) = open_log(&log).expect("opens the log");
        assert_eq!(from, 0);
        assert_eq!(last_line(&log, from), None, "a start that wrote nothing");
        std::fs::write(&log, "an earlier start\n").expect("an earlier start's line");
        let (_, from) = open_log(&log).expect("opens the log");
        assert_eq!(last_line(&log, from), None, "which is not this start's");
        std::fs::write(&log, "an earlier start\nthis start\nand its last word\n\n")
            .expect("this start's lines");
        assert_eq!(last_line(&log, from).as_deref(), Some("and its last word"));
    }
}
