//! The service start: a per-user definition that has this user's own service manager start the
//! control daemon.
//!
//! Section 7 lets `kr new` request startup of the configured per-user controller on a host that
//! was set up for it, and this module is that setup and that request. `kr host startup --set
//! service` writes one definition of the control daemon as a per-user service, records exactly
//! what it wrote, and has the manager take it. `kr new` asks the manager to start it when no daemon
//! answers. `kr host startup --clear` removes exactly what was written. `kr new` installs nothing:
//! it starts what the setup installed, and a definition that has gone, that kr did not write, or
//! that was changed after kr wrote it stops the command with its name and the setup action. It is
//! never written again from there.
//!
//! | Platform | Manager | Definition | `kr new` asks it with |
//! | --- | --- | --- | --- |
//! | macOS | launchd | `~/Library/LaunchAgents/kr-controller-<environment>.plist` | `launchctl kickstart -p` |
//! | Linux | the systemd user manager | `kr-controller-<environment>.service` in `$XDG_CONFIG_HOME/systemd/user`, `~/.config` by default | `systemctl --user start` |
//!
//! On macOS the definition is loaded into the user's graphical domain on a host whose sessions are
//! desktop-bound by default, and into the background domain on one whose sessions are headless.
//! The daemon's domain is its login context: in the graphical domain it has what that login has,
//! the login keychain among it, and it ends with the login, as a desktop-bound session does; in the
//! background domain it has no Aqua access and outlives the graphical login, as a headless session
//! does. A host with no graphical login has no graphical domain at all. So the daemon runs where the
//! sessions it creates by default run.
//!
//! The daemon it defines is the `kr-controller` installed beside this command, told this
//! installation's own runtime and state roots, working in the environment's state directory and
//! writing to the same `controller.log` the standalone start's daemon writes to. The manager starts
//! it only when asked, never at login and never again after it ends. It takes the environment's
//! singleton lock and advances its generation like any other daemon, and the manager starts one
//! process for a job however many commands ask at once, so several first commands meet one daemon.
//!
//! The record is `controller-service.json` in the environment's state directory, owner-only: the
//! manager, the label, the domain, the file and its exact contents. The file on disk is compared
//! with it rather than assumed, and a file under the label with no record is not kr's to replace or
//! remove. Removing the definition never ends a daemon the manager is running: launchd keeps the
//! job of a running daemon until that daemon ends, and the user manager keeps a running unit whose
//! file has gone until it stops.

use std::path::{Path, PathBuf};
#[cfg(any(target_os = "macos", target_os = "linux"))]
use std::time::{Duration, Instant};

use kr_ipc::paths::EnvironmentPaths;
use serde::{Deserialize, Serialize};

use crate::error::{CliError, Result};

/// The file in an environment's state directory that records the definition `kr host startup`
/// wrote.
pub const RECORD_FILE: &str = "controller-service.json";

/// The version of the record this build writes and reads.
const RECORD_VERSION: u32 = 1;

/// The largest record, or definition, this build reads: far more than it ever writes.
const READ_LIMIT: u64 = 64 * 1024;

/// How long one command put to the service manager is given to answer.
#[cfg(any(target_os = "macos", target_os = "linux"))]
const MANAGER_BOUND: Duration = Duration::from_secs(10);

/// What a person does to have the definition written again, or written for the first time.
pub const SETUP_ACTION: &str = "run kr host startup --set service";

/// The service manager a definition is written for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Manager {
    /// macOS's launchd.
    Launchd,
    /// The systemd user manager.
    Systemd,
}

impl Manager {
    /// The manager's name, as it names itself.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Launchd => "launchd",
            Self::Systemd => "systemd",
        }
    }
}

/// The label the service manager knows an environment's daemon by: its job's label on macOS, its
/// unit's name, without the suffix, on Linux.
#[must_use]
pub fn label(environment: &EnvironmentPaths) -> String {
    format!("kr-controller-{}", environment.environment_id())
}

/// One definition of an environment's daemon, as this installation writes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Definition {
    /// The manager it is for.
    pub manager: Manager,
    /// The label the manager knows it by.
    pub label: String,
    /// The launchd domain it is loaded into. Linux has one user manager, and no domain.
    pub domain: Option<String>,
    /// Where the file is.
    pub path: PathBuf,
    /// The file's exact contents.
    pub contents: String,
}

impl Definition {
    /// What `launchctl` and `systemctl` call it: `<domain>/<label>`, or `<label>.service`.
    #[must_use]
    pub fn target(&self) -> String {
        target(self.manager, &self.label, self.domain.as_deref())
    }
}

/// What the manager calls a job or a unit.
fn target(manager: Manager, label: &str, domain: Option<&str>) -> String {
    match manager {
        Manager::Launchd => format!("{}/{label}", domain.unwrap_or_default()),
        Manager::Systemd => format!("{label}.service"),
    }
}

/// The record of the definition `kr host startup` wrote.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    /// The version of this record.
    pub version: u32,
    /// The manager the definition is for.
    pub manager: Manager,
    /// The label the manager knows it by.
    pub label: String,
    /// The launchd domain it was loaded into.
    pub domain: Option<String>,
    /// Where the file is.
    pub path: PathBuf,
    /// What was written there.
    pub contents: String,
}

impl Record {
    /// What the manager calls the job or unit this record names.
    #[must_use]
    pub fn target(&self) -> String {
        target(self.manager, &self.label, self.domain.as_deref())
    }

    /// The record of `definition`.
    fn of(definition: &Definition) -> Self {
        Self {
            version: RECORD_VERSION,
            manager: definition.manager,
            label: definition.label.clone(),
            domain: definition.domain.clone(),
            path: definition.path.clone(),
            contents: definition.contents.clone(),
        }
    }

    /// Where an environment's record is.
    fn path(environment: &EnvironmentPaths) -> PathBuf {
        environment.state_dir().join(RECORD_FILE)
    }

    /// Reads an environment's record: none when it has none, and what is wrong with it when it
    /// cannot be used.
    ///
    /// # Errors
    ///
    /// Returns a sentence when a record is there and cannot be read as one this build wrote.
    pub fn read(environment: &EnvironmentPaths) -> std::result::Result<Option<Self>, String> {
        let path = Self::path(environment);
        let bytes = match kr_ipc::paths::read_owner_only_file(&path, READ_LIMIT) {
            Ok(Some(bytes)) => bytes,
            Ok(None) => return Ok(None),
            Err(error) => {
                return Err(format!(
                    "the record {} cannot be read: {error}",
                    path.display()
                ));
            }
        };
        let record: Self = serde_json::from_slice(&bytes).map_err(|error| {
            format!(
                "the record {} is not one this build writes: {error}",
                path.display()
            )
        })?;
        if record.version != RECORD_VERSION {
            return Err(format!(
                "the record {} is at version {}, which this build does not read",
                path.display(),
                record.version
            ));
        }
        Ok(Some(record))
    }

    fn write(environment: &EnvironmentPaths, definition: &Definition) -> Result<()> {
        let contents = serde_json::to_vec_pretty(&Self::of(definition)).map_err(|error| {
            CliError::Other(format!("the record could not be written: {error}"))
        })?;
        kr_ipc::paths::write_owner_only_file(&Self::path(environment), &contents)
            .map_err(CliError::Ipc)
    }
}

/// What the file where a definition belongs turned out to be.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// The file is what this installation writes, and nothing says kr did not write it.
    Matches,
    /// There is no file.
    Missing,
    /// kr wrote the file and it has been changed since.
    Changed,
    /// A file kr did not write is where the definition belongs.
    Foreign,
    /// kr wrote the file and nobody changed it, but this installation writes something else now:
    /// another program, other directories or another domain.
    Outdated,
}

impl State {
    /// The state's wire word.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Matches => "matches",
            Self::Missing => "missing",
            Self::Changed => "changed",
            Self::Foreign => "foreign",
            Self::Outdated => "outdated",
        }
    }

    /// What is wrong with the definition at `path`, and what a person does about it.
    #[must_use]
    pub fn trouble(self, path: &Path) -> Option<String> {
        let path = path.display();
        match self {
            Self::Matches => None,
            Self::Missing => Some(format!(
                "the service definition {path} is missing; {SETUP_ACTION} to write it again"
            )),
            Self::Changed => Some(format!(
                "the service definition {path} was changed after kr wrote it; restore it or remove \
                 it, then {SETUP_ACTION}"
            )),
            Self::Foreign => Some(format!(
                "{path} is a service definition kr did not write, under the label this \
                 environment's daemon has; remove it, then {SETUP_ACTION}"
            )),
            Self::Outdated => Some(format!(
                "the service definition {path} names another program, other directories or \
                 another domain than this installation's; {SETUP_ACTION} to write this \
                 installation's"
            )),
        }
    }
}

/// Compares the file at `path` with what kr recorded writing there and with what this
/// installation writes now.
///
/// kr writes a definition owner-only, as a regular file, so anything else at the path, a link or a
/// file others may write, is not what kr wrote.
fn state(path: &Path, record: Option<&Record>, expected: &[Definition]) -> State {
    let bytes = match kr_ipc::paths::read_owner_only_file(path, READ_LIMIT) {
        Ok(None) => return State::Missing,
        Ok(Some(bytes)) => bytes,
        Err(_) if record.is_some() => return State::Changed,
        Err(_) => return State::Foreign,
    };
    let current = |contents: &str| {
        expected
            .iter()
            .any(|definition| definition.path == path && definition.contents == contents)
    };
    match record {
        Some(record) if bytes == record.contents.as_bytes() => {
            if current(&record.contents) {
                State::Matches
            } else {
                State::Outdated
            }
        }
        Some(_) => State::Changed,
        None if std::str::from_utf8(&bytes).is_ok_and(current) => State::Matches,
        None => State::Foreign,
    }
}

/// What the service start has on this host for an environment, for a person to read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Inspection {
    /// The manager.
    pub manager: Manager,
    /// The label.
    pub label: String,
    /// The launchd domain, when the record names one.
    pub domain: Option<String>,
    /// Where the definition is, or belongs.
    pub path: PathBuf,
    /// What the file there is.
    pub state: State,
    /// Whether kr recorded writing it.
    pub recorded: bool,
}

impl Inspection {
    /// The inspection as a command's `--json` output reports it.
    #[must_use]
    pub fn json(&self) -> serde_json::Value {
        serde_json::json!({
            "manager": self.manager.as_str(),
            "label": self.label,
            "domain": self.domain,
            "path": self.path.display().to_string(),
            "state": self.state.as_str(),
            "recorded": self.recorded,
        })
    }

    /// The inspection as a sentence for a person.
    #[must_use]
    pub fn describe(&self) -> String {
        let job = match &self.domain {
            Some(domain) => format!("the job {} in {domain}", self.label),
            None => format!("the unit {}.service", self.label),
        };
        let found = self.state.trouble(&self.path).unwrap_or_else(|| {
            format!(
                "defined in {}, which matches what kr wrote",
                self.path.display()
            )
        });
        format!("{} starts {job}; {found}", self.manager.as_str())
    }
}

/// Inspects what the service start has for an environment: the recorded definition, or, where
/// `selected` says the service start is chosen and nothing is recorded, where one would be. Nothing
/// is asked of the manager, and an environment with neither has nothing to inspect.
///
/// # Errors
///
/// Returns [`CliError::HostUnavailable`] when the record cannot be read, and what stops a
/// definition being written on this host otherwise.
pub fn inspect(environment: &EnvironmentPaths, selected: bool) -> Result<Option<Inspection>> {
    let record = Record::read(environment).map_err(CliError::HostUnavailable)?;
    let Some(manager) = platform::MANAGER else {
        return Ok(None);
    };
    if record.is_none() && !selected {
        return Ok(None);
    }
    let expected = match &record {
        Some(record) => vec![Definition::write_for(environment, record.domain.clone())?],
        None => platform::domains()
            .into_iter()
            .map(|domain| Definition::write_for(environment, domain))
            .collect::<Result<Vec<_>>>()?,
    };
    let path = record
        .as_ref()
        .map_or_else(|| expected[0].path.clone(), |record| record.path.clone());
    Ok(Some(Inspection {
        manager: record.as_ref().map_or(manager, |record| record.manager),
        label: label(environment),
        domain: record.as_ref().and_then(|record| record.domain.clone()),
        state: state(&path, record.as_ref(), &expected),
        path,
        recorded: record.is_some(),
    }))
}

/// What `kr host startup --set service` did.
#[derive(Debug)]
pub struct Installed {
    /// The definition as it now stands.
    pub inspection: Inspection,
    /// What a person should know about what the manager holds.
    pub notes: Vec<String>,
}

/// Writes the definition of an environment's daemon, records it, and has the manager take it.
///
/// Nothing is written over a definition kr did not write or one changed since it did, and neither
/// the command nor the manager starts the daemon here.
///
/// # Errors
///
/// Returns [`CliError::Usage`] when this host has no service manager to write for, and when a
/// definition kr may not replace is where this one belongs, both with nothing written; and what
/// failed otherwise.
pub fn install(environment: &EnvironmentPaths) -> Result<Installed> {
    platform::available()?;
    let domain = platform::domain_for(environment)?;
    let expected = Definition::write_for(environment, domain)?;
    let record = Record::read(environment).map_err(CliError::Usage)?;
    if let Some(record) = &record
        && record.path != expected.path
    {
        return Err(CliError::Usage(format!(
            "the service definition kr wrote for this environment is {}, and this command would \
             write it at {}; run kr host startup --clear with the home that wrote it first",
            record.path.display(),
            expected.path.display()
        )));
    }
    let before = state(
        &expected.path,
        record.as_ref(),
        std::slice::from_ref(&expected),
    );
    let mut notes = Vec::new();
    match before {
        State::Foreign | State::Changed => {
            return Err(CliError::Usage(
                before.trouble(&expected.path).unwrap_or_default(),
            ));
        }
        State::Matches => {}
        State::Missing | State::Outdated => {
            if let Some(parent) = expected.path.parent() {
                std::fs::create_dir_all(parent).map_err(|error| {
                    CliError::Ipc(kr_ipc::IpcError::io("create", parent, error))
                })?;
            }
            // A definition that is not there is published only if it is still not there, so one
            // that appeared meanwhile is never replaced.
            let written = if before == State::Missing {
                kr_ipc::paths::create_new_owner_only_file(
                    &expected.path,
                    expected.contents.as_bytes(),
                )
            } else {
                kr_ipc::paths::write_owner_only_file(&expected.path, expected.contents.as_bytes())
            };
            written.map_err(|error| {
                CliError::Usage(format!(
                    "the service definition {} could not be written: {error}",
                    expected.path.display()
                ))
            })?;
            // A domain the earlier definition was loaded into and this one is not is let go of.
            if let Some(record) = &record
                && record.domain != expected.domain
            {
                notes.extend(platform::release(record)?);
            }
        }
    }
    Record::write(environment, &expected)?;
    notes.extend(platform::take(&expected, before != State::Matches)?);
    Ok(Installed {
        inspection: Inspection {
            manager: expected.manager,
            label: expected.label.clone(),
            domain: expected.domain.clone(),
            path: expected.path.clone(),
            state: State::Matches,
            recorded: true,
        },
        notes,
    })
}

/// What removing the service start's definition did.
#[derive(Debug, Default)]
pub struct Removal {
    /// Every file removed.
    pub removed: Vec<PathBuf>,
    /// Every file left where it was, and why.
    pub left: Vec<(PathBuf, String)>,
    /// What a person should know about what the manager still holds.
    pub notes: Vec<String>,
}

/// Removes exactly what `kr host startup --set service` wrote for an environment, and its record,
/// without ending a daemon the manager is running.
///
/// An environment with no record has nothing of the service start's to remove. A definition
/// changed after kr wrote it is no longer kr's to remove, and is left, with its record gone.
///
/// # Errors
///
/// Returns [`CliError::Usage`] when the record cannot be read, and what failed while removing.
pub fn remove(environment: &EnvironmentPaths) -> Result<Removal> {
    let Some(record) = Record::read(environment).map_err(CliError::Usage)? else {
        return Ok(Removal::default());
    };
    let mut removal = Removal::default();
    let written = match kr_ipc::paths::read_owner_only_file(&record.path, READ_LIMIT) {
        Ok(Some(bytes)) => Some(bytes == record.contents.as_bytes()),
        Ok(None) => None,
        Err(_) => Some(false),
    };
    match written {
        Some(true) => {
            removal.notes.extend(platform::release(&record)?);
            std::fs::remove_file(&record.path).map_err(|error| {
                CliError::Ipc(kr_ipc::IpcError::io("remove", &record.path, error))
            })?;
            removal.removed.push(record.path.clone());
        }
        Some(false) => removal.left.push((
            record.path.clone(),
            "it was changed after kr wrote it, so it is no longer kr's to remove".to_owned(),
        )),
        None => removal.notes.extend(platform::release(&record)?),
    }
    let recorded = Record::path(environment);
    std::fs::remove_file(&recorded)
        .map_err(|error| CliError::Ipc(kr_ipc::IpcError::io("remove", &recorded, error)))?;
    removal.removed.push(recorded);
    removal.notes.extend(platform::forget(&record));
    Ok(removal)
}

/// Why `kr new` did not have the manager start the daemon.
#[derive(Debug)]
pub enum Refusal {
    /// The service start is not set up as it has to be: what is wrong, and the setup action.
    NotSetUp(String),
    /// The manager was asked and did not start the daemon.
    Failed(String),
}

/// A daemon the manager was asked to start.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Asked {
    /// The manager.
    pub manager: Manager,
    /// The process it runs the daemon as, when it said.
    pub pid: Option<u32>,
}

/// Asks the manager to start an environment's daemon from the definition kr wrote.
///
/// The definition is checked first, and one that is not exactly what kr wrote and this
/// installation writes is a refusal with the setup action: nothing is written and nothing is
/// started. A daemon the manager is already running is the one it reports.
///
/// # Errors
///
/// Returns the refusal.
pub fn start(environment: &EnvironmentPaths) -> std::result::Result<Asked, Refusal> {
    let record = Record::read(environment)
        .map_err(|why| Refusal::NotSetUp(format!("{why}; {SETUP_ACTION}")))?
        .ok_or_else(|| {
            Refusal::NotSetUp(format!(
                "startup.controller is service and no service definition was written for this \
                 environment; {SETUP_ACTION}"
            ))
        })?;
    if platform::MANAGER != Some(record.manager) {
        return Err(Refusal::NotSetUp(format!(
            "the service definition kr recorded is for {}, which this host does not start \
             daemons with; {SETUP_ACTION}",
            record.manager.as_str()
        )));
    }
    let expected = Definition::write_for(environment, record.domain.clone())
        .map_err(|error| Refusal::NotSetUp(format!("{error}; {SETUP_ACTION}")))?;
    let found = state(&record.path, Some(&record), std::slice::from_ref(&expected));
    if let Some(trouble) = found.trouble(&record.path) {
        return Err(Refusal::NotSetUp(trouble));
    }
    platform::start(&record)
}

impl Definition {
    /// The definition this installation writes for `environment`, loaded into `domain` where the
    /// manager has domains.
    ///
    /// # Errors
    ///
    /// Returns [`CliError::HostUnavailable`] when where this command is installed cannot be read,
    /// and [`CliError::Usage`] when a path the definition names cannot be written into one.
    pub fn write_for(environment: &EnvironmentPaths, domain: Option<String>) -> Result<Self> {
        let program = crate::startup::daemon_program()?;
        let state = environment.state_dir();
        let arguments = [
            text(&program)?.to_owned(),
            "--runtime-dir".to_owned(),
            text(environment.runtime_root())?.to_owned(),
            "--state-dir".to_owned(),
            text(environment.state_root())?.to_owned(),
        ];
        let log = state.join(crate::startup::LOG_FILE);
        platform::render(
            &label(environment),
            domain,
            &arguments,
            text(state)?,
            text(&log)?,
        )
    }
}

/// A path as the text a definition names it by: UTF-8, absolute, with no control character and no
/// space at either end, which is every path either manager can be told exactly.
fn text(path: &Path) -> Result<&str> {
    let refused = |why: &str| {
        CliError::Usage(format!(
            "{} cannot be written into a service definition: {why}",
            path.display()
        ))
    };
    let text = path.to_str().ok_or_else(|| refused("it is not UTF-8"))?;
    if !path.is_absolute() {
        return Err(refused("it is not absolute"));
    }
    if text.chars().any(char::is_control) {
        return Err(refused("it holds a control character"));
    }
    if text.trim() != text {
        return Err(refused("it starts or ends with a space"));
    }
    Ok(text)
}

/// Runs one command put to the service manager within [`MANAGER_BOUND`], and returns its answer or
/// why there was none.
///
/// What it prints is read while it runs, so an answer of any size cannot stall it. One that does
/// not answer in time is ended and collected: it is this process's own child.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn run(program: &str, arguments: &[&str]) -> std::result::Result<std::process::Output, String> {
    let asked = format!("{program} {}", arguments.join(" "));
    let mut child = std::process::Command::new(program)
        .args(arguments)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|error| format!("{asked} could not be run: {error}"))?;
    let readers = child
        .stdout
        .take()
        .map(aside)
        .transpose()
        .and_then(|printed| Ok((printed, child.stderr.take().map(aside).transpose()?)));
    let (printed, said) = match readers {
        Ok(readers) => readers,
        Err(error) => {
            // This process's own child, not collected yet, so the number is still its.
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("{asked}: its answer could not be read: {error}"));
        }
    };
    let deadline = Instant::now() + MANAGER_BOUND;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Ok(None) | Err(_) => {
                // This process's own child, not collected yet, so the number is still its.
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!(
                    "{asked} did not answer within {} seconds",
                    MANAGER_BOUND.as_secs()
                ));
            }
        }
    };
    let joined = |reader: Option<std::thread::JoinHandle<Vec<u8>>>| {
        reader
            .and_then(|reader| reader.join().ok())
            .unwrap_or_default()
    };
    Ok(std::process::Output {
        status,
        stdout: joined(printed),
        stderr: joined(said),
    })
}

/// Reads a pipe to its end on a thread of its own.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn aside(
    mut pipe: impl std::io::Read + Send + 'static,
) -> std::io::Result<std::thread::JoinHandle<Vec<u8>>> {
    std::thread::Builder::new()
        .name("service manager answer".to_owned())
        .spawn(move || {
            let mut bytes = Vec::new();
            let _ = pipe.read_to_end(&mut bytes);
            bytes
        })
}

/// What a command that answered with a failure said.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn refused(asked: &str, output: &std::process::Output) -> String {
    format!(
        "{asked} answered {}: {}",
        output.status.code().map_or_else(
            || "without an exit code".to_owned(),
            |code| code.to_string()
        ),
        String::from_utf8_lossy(&output.stderr).trim()
    )
}

/// Whether two paths name the same file, reading through links where both are there.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn same_file(one: &Path, other: &Path) -> bool {
    match (std::fs::canonicalize(one), std::fs::canonicalize(other)) {
        (Ok(one), Ok(other)) => one == other,
        _ => one == other,
    }
}

#[cfg(target_os = "macos")]
mod platform {
    //! launchd.

    use std::path::{Path, PathBuf};

    use kr_ipc::paths::EnvironmentPaths;
    use kr_protocol::identity::WorkerProfile;

    use super::{Asked, Definition, Manager, Record, Refusal, refused, run, same_file, text};
    use crate::error::{CliError, Result};

    /// The manager this platform's definitions are for.
    pub(super) const MANAGER: Option<Manager> = Some(Manager::Launchd);

    const LAUNCHCTL: &str = "/bin/launchctl";

    /// What `launchctl print` exits with for a domain that does not exist.
    const NO_SUCH_DOMAIN: i32 = 112;

    /// What `launchctl print` exits with for a job the domain does not have.
    const NOT_LOADED: i32 = 113;

    /// This user's two domains.
    fn domains_here() -> [String; 2] {
        let uid = kr_ipc::paths::current_uid();
        [format!("gui/{uid}"), format!("user/{uid}")]
    }

    /// Every domain a definition may be written for.
    pub(super) fn domains() -> Vec<Option<String>> {
        domains_here().into_iter().map(Some).collect()
    }

    /// launchd is always there; what it needs is the domain, and that is asked when it is chosen.
    pub(super) fn available() -> Result<()> {
        Ok(())
    }

    /// The domain the environment's default execution profile implies: the graphical domain for a
    /// host whose sessions are desktop-bound, the background domain for a headless one.
    ///
    /// The profile is the one the configuration document chooses, or else the one the platform
    /// establishes, read here the way the daemon reads it.
    pub(super) fn domain_for(environment: &EnvironmentPaths) -> Result<Option<String>> {
        let profile = match kr_controller::config::open(environment).chosen_worker_profile() {
            Some(profile) => profile,
            None => kr_controller::desktop::default_profile(&kr_controller::desktop::current(
                kr_ipc::identity::boot_identity()?,
            )),
        };
        let [graphical, background] = domains_here();
        let domain = match profile {
            WorkerProfile::DesktopBound => graphical,
            WorkerProfile::HeadlessUser => background,
        };
        match run(LAUNCHCTL, &["print", &domain]) {
            Ok(output) if output.status.success() => Ok(Some(domain)),
            Ok(output) => Err(CliError::Usage(format!(
                "this environment's sessions are {} by default, so its daemon belongs in {domain}, \
                 and launchd has no such domain here: {}",
                profile.as_str(),
                refused(&format!("launchctl print {domain}"), &output)
            ))),
            Err(why) => Err(CliError::HostUnavailable(why)),
        }
    }

    /// The session type a job in `domain` loads into.
    fn session_type(domain: &str) -> &'static str {
        if domain.starts_with("gui/") {
            "Aqua"
        } else {
            "Background"
        }
    }

    /// Writes the job definition.
    pub(super) fn render(
        label: &str,
        domain: Option<String>,
        arguments: &[String],
        working_directory: &str,
        log: &str,
    ) -> Result<Definition> {
        let domain = domain.ok_or_else(|| {
            CliError::Usage(
                "a launchd definition is loaded into a domain, and none was named".to_owned(),
            )
        })?;
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .filter(|home| home.is_absolute())
            .ok_or_else(|| {
                CliError::Usage(
                    "HOME is not set to a directory, so there is no LaunchAgents directory to \
                     write the definition in"
                        .to_owned(),
                )
            })?;
        let string = |value: &str| format!("\t<string>{}</string>\n", escaped(value));
        let mut contents = String::from(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
             \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
             <!-- The KalaReach control daemon, started when a kr command finds none running. \
             kr host startup wrote this file and kr host startup --clear removes it. -->\n\
             <plist version=\"1.0\">\n<dict>\n",
        );
        contents.push_str("\t<key>Label</key>\n");
        contents.push_str(&string(label));
        contents.push_str("\t<key>ProgramArguments</key>\n\t<array>\n");
        for argument in arguments {
            contents.push_str(&format!("\t{}", string(argument)));
        }
        contents.push_str("\t</array>\n");
        contents.push_str("\t<key>RunAtLoad</key>\n\t<false/>\n");
        contents.push_str("\t<key>KeepAlive</key>\n\t<false/>\n");
        contents.push_str("\t<key>LimitLoadToSessionType</key>\n");
        contents.push_str(&string(session_type(&domain)));
        contents.push_str("\t<key>ProcessType</key>\n");
        contents.push_str(&string("Interactive"));
        contents.push_str("\t<key>WorkingDirectory</key>\n");
        contents.push_str(&string(working_directory));
        contents.push_str("\t<key>Umask</key>\n\t<integer>63</integer>\n");
        contents.push_str("\t<key>StandardOutPath</key>\n");
        contents.push_str(&string(log));
        contents.push_str("\t<key>StandardErrorPath</key>\n");
        contents.push_str(&string(log));
        contents.push_str("</dict>\n</plist>\n");
        let path = home
            .join("Library/LaunchAgents")
            .join(format!("{label}.plist"));
        text(&path)?;
        Ok(Definition {
            manager: Manager::Launchd,
            label: label.to_owned(),
            domain: Some(domain),
            path,
            contents,
        })
    }

    /// Text as an XML property list's string holds it.
    fn escaped(value: &str) -> String {
        value
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
    }

    /// What launchd holds under one target.
    enum Job {
        NotLoaded,
        Loaded {
            path: Option<PathBuf>,
            program: Option<String>,
            pid: Option<u32>,
        },
    }

    fn job(target: &str) -> std::result::Result<Job, String> {
        let output = run(LAUNCHCTL, &["print", target])?;
        match output.status.code() {
            Some(0) => {
                let printed = String::from_utf8_lossy(&output.stdout);
                let field = |name: &str| {
                    printed.lines().find_map(|line| {
                        line.strip_prefix('\t')?
                            .strip_prefix(name)?
                            .strip_prefix(" = ")
                            .map(str::to_owned)
                    })
                };
                Ok(Job::Loaded {
                    path: field("path").map(PathBuf::from),
                    program: field("program"),
                    pid: field("pid").and_then(|pid| pid.trim().parse().ok()),
                })
            }
            Some(NO_SUCH_DOMAIN | NOT_LOADED) => Ok(Job::NotLoaded),
            _ => Err(refused(&format!("launchctl print {target}"), &output)),
        }
    }

    fn succeeded(arguments: &[&str]) -> std::result::Result<std::process::Output, String> {
        let output = run(LAUNCHCTL, arguments)?;
        if output.status.success() {
            Ok(output)
        } else {
            Err(refused(
                &format!("launchctl {}", arguments.join(" ")),
                &output,
            ))
        }
    }

    /// Loads the definition at `path` into `domain`, and settles a load that another command made
    /// first as a load.
    fn load(domain: &str, target: &str, path: &Path) -> std::result::Result<(), String> {
        let loaded = succeeded(&["bootstrap", domain, &path.display().to_string()]);
        match (loaded, job(target)?) {
            (Ok(_), _) => Ok(()),
            (
                Err(_),
                Job::Loaded {
                    path: Some(from), ..
                },
            ) if same_file(&from, path) => Ok(()),
            (Err(why), _) => Err(why),
        }
    }

    /// Has launchd hold the definition just written: loaded where it was not, and loaded again
    /// where launchd holds an earlier one and runs no daemon from it.
    pub(super) fn take(definition: &Definition, rewritten: bool) -> Result<Vec<String>> {
        let domain = definition.domain.as_deref().unwrap_or_default();
        let target = definition.target();
        let failed = |why: String| CliError::HostUnavailable(why);
        match job(&target).map_err(failed)? {
            Job::NotLoaded => load(domain, &target, &definition.path).map_err(failed)?,
            Job::Loaded { path, pid, program } => {
                let from = path.unwrap_or_default();
                if !same_file(&from, &definition.path) {
                    return Err(CliError::Usage(format!(
                        "launchd holds a job labelled {} in {domain} from another definition, {}; \
                         remove it with launchctl bootout {target}, then run kr host startup --set \
                         service",
                        definition.label,
                        from.display()
                    )));
                }
                if rewritten {
                    match pid {
                        Some(pid) if program != program_of(&definition.contents) => {
                            return Ok(vec![format!(
                                "launchd holds the earlier definition while the daemon it started \
                                 from it runs (process {pid}); run kr host startup --set service \
                                 again once that daemon has ended"
                            )]);
                        }
                        Some(_) => {}
                        None => {
                            succeeded(&["bootout", &target]).map_err(failed)?;
                            load(domain, &target, &definition.path).map_err(failed)?;
                        }
                    }
                }
            }
        }
        Ok(Vec::new())
    }

    /// Lets go of the job a record names without ending a daemon: a job with no process is
    /// removed, and one running a daemon is left to it.
    pub(super) fn release(record: &Record) -> Result<Vec<String>> {
        let target = record.target();
        let failed = |why: String| CliError::HostUnavailable(why);
        match job(&target).map_err(failed)? {
            Job::NotLoaded => Ok(Vec::new()),
            Job::Loaded { path, .. }
                if !path
                    .as_ref()
                    .is_some_and(|path| same_file(path, &record.path)) =>
            {
                Ok(Vec::new())
            }
            Job::Loaded { pid: Some(pid), .. } => Ok(vec![format!(
                "the daemon launchd started (process {pid}) keeps serving, and launchd keeps its \
                 job {target} until that daemon has ended"
            )]),
            Job::Loaded { pid: None, .. } => {
                succeeded(&["bootout", &target]).map_err(failed)?;
                Ok(Vec::new())
            }
        }
    }

    /// Nothing to tell launchd once a definition's file has gone: it read the file when it loaded
    /// it.
    pub(super) fn forget(_record: &Record) -> Vec<String> {
        Vec::new()
    }

    /// Asks launchd to start the job the record names, loading it first where launchd does not
    /// hold it, as it does not after a restart until the domain is set up again.
    pub(super) fn start(record: &Record) -> std::result::Result<Asked, Refusal> {
        let domain = record.domain.as_deref().unwrap_or_default();
        let target = record.target();
        let program = program_of(&record.contents);
        match job(&target).map_err(Refusal::Failed)? {
            Job::NotLoaded => load(domain, &target, &record.path).map_err(Refusal::Failed)?,
            Job::Loaded {
                path,
                program: loaded,
                ..
            } => {
                let from = path.unwrap_or_default();
                if !same_file(&from, &record.path) {
                    return Err(Refusal::NotSetUp(format!(
                        "launchd holds a job labelled {} in {domain} from another definition, {}; \
                         remove it with launchctl bootout {target}, then run kr host startup --set \
                         service",
                        record.label,
                        from.display()
                    )));
                }
                if loaded.is_some() && loaded != program {
                    return Err(Refusal::NotSetUp(format!(
                        "launchd holds an earlier definition of {target}, which runs {}; run kr \
                         host startup --set service to have it take the one kr wrote",
                        loaded.unwrap_or_default()
                    )));
                }
            }
        }
        let output = run(LAUNCHCTL, &["kickstart", "-p", &target]).map_err(Refusal::Failed)?;
        if !output.status.success() {
            return Err(Refusal::Failed(refused(
                &format!("launchctl kickstart -p {target}"),
                &output,
            )));
        }
        Ok(Asked {
            manager: Manager::Launchd,
            pid: String::from_utf8_lossy(&output.stdout).trim().parse().ok(),
        })
    }

    /// The program a definition this module wrote runs: the first of its program arguments.
    fn program_of(contents: &str) -> Option<String> {
        let start = contents.find("<key>ProgramArguments</key>")?;
        let first = contents[start..].find("<string>")? + start + "<string>".len();
        let end = contents[first..].find("</string>")? + first;
        Some(
            contents[first..end]
                .replace("&lt;", "<")
                .replace("&gt;", ">")
                .replace("&amp;", "&"),
        )
    }
}

#[cfg(target_os = "linux")]
mod platform {
    //! The systemd user manager.

    use std::path::PathBuf;

    use kr_ipc::paths::EnvironmentPaths;

    use super::{Asked, Definition, Manager, Record, Refusal, refused, run, same_file, text};
    use crate::error::{CliError, Result};

    /// The manager this platform's definitions are for.
    pub(super) const MANAGER: Option<Manager> = Some(Manager::Systemd);

    const SYSTEMCTL: &str = "systemctl";

    /// The one user manager has no domains.
    pub(super) fn domains() -> Vec<Option<String>> {
        vec![None]
    }

    /// `systemctl --user` with the arguments given, never paging and never asking for a password.
    fn systemctl(arguments: &[&str]) -> std::result::Result<std::process::Output, String> {
        let mut all = vec!["--user", "--no-pager", "--no-ask-password"];
        all.extend_from_slice(arguments);
        run(SYSTEMCTL, &all)
    }

    fn succeeded(arguments: &[&str]) -> std::result::Result<std::process::Output, String> {
        let output = systemctl(arguments)?;
        if output.status.success() {
            Ok(output)
        } else {
            Err(refused(
                &format!("systemctl --user {}", arguments.join(" ")),
                &output,
            ))
        }
    }

    /// Whether a user manager answers: one that answers a property query exists. Having the
    /// `systemctl` program proves only that it is installed.
    pub(super) fn available() -> Result<()> {
        succeeded(&["show", "--property=Version", "--value"])
            .map(|_| ())
            .map_err(|why| {
                CliError::Usage(format!(
                    "this host has no user service manager to start the daemon: {why}; kr host \
                     startup --set standalone has kr new start it itself instead"
                ))
            })
    }

    /// The user manager has no domains to choose between.
    pub(super) fn domain_for(_environment: &EnvironmentPaths) -> Result<Option<String>> {
        Ok(None)
    }

    /// A value as a unit file's command line takes it: one quoted word, with the characters the
    /// manager expands in one written so it takes them as they are.
    fn word(value: &str) -> String {
        let escaped = value
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('%', "%%")
            .replace('$', "$$");
        format!("\"{escaped}\"")
    }

    /// A path as a unit file's path setting takes it, with its specifier character doubled.
    fn setting(value: &str) -> String {
        value.replace('%', "%%")
    }

    /// Writes the unit.
    pub(super) fn render(
        label: &str,
        _domain: Option<String>,
        arguments: &[String],
        working_directory: &str,
        log: &str,
    ) -> Result<Definition> {
        let configuration = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
            .or_else(|| {
                std::env::var_os("HOME")
                    .map(PathBuf::from)
                    .filter(|home| home.is_absolute())
                    .map(|home| home.join(".config"))
            })
            .ok_or_else(|| {
                CliError::Usage(
                    "neither XDG_CONFIG_HOME nor HOME names a directory, so there is no user unit \
                     directory to write the definition in"
                        .to_owned(),
                )
            })?;
        let command: Vec<String> = arguments.iter().map(|argument| word(argument)).collect();
        let contents = format!(
            "# The KalaReach control daemon, started when a kr command finds none running.\n\
             # kr host startup wrote this file and kr host startup --clear removes it.\n\
             [Unit]\n\
             Description=KalaReach control daemon {label}\n\
             \n\
             [Service]\n\
             Type=exec\n\
             ExecStart={}\n\
             WorkingDirectory={}\n\
             UMask=0077\n\
             StandardOutput=append:{}\n\
             StandardError=append:{}\n\
             Restart=no\n",
            command.join(" "),
            setting(working_directory),
            setting(log),
            setting(log),
        );
        let path = configuration
            .join("systemd/user")
            .join(format!("{label}.service"));
        text(&path)?;
        Ok(Definition {
            manager: Manager::Systemd,
            label: label.to_owned(),
            domain: None,
            path,
            contents,
        })
    }

    /// What the user manager holds under one unit name.
    struct Unit {
        load_state: String,
        fragment: Option<PathBuf>,
        pid: Option<u32>,
    }

    fn unit(name: &str) -> std::result::Result<Unit, String> {
        let output = succeeded(&["show", "--property=LoadState,FragmentPath,MainPID", name])?;
        let printed = String::from_utf8_lossy(&output.stdout);
        let field = |key: &str| {
            printed
                .lines()
                .find_map(|line| line.strip_prefix(key)?.strip_prefix('=').map(str::to_owned))
        };
        Ok(Unit {
            load_state: field("LoadState").unwrap_or_default(),
            fragment: field("FragmentPath")
                .filter(|path| !path.is_empty())
                .map(PathBuf::from),
            pid: field("MainPID")
                .and_then(|pid| pid.parse().ok())
                .filter(|pid| *pid != 0),
        })
    }

    /// Has the user manager read the definition just written, and checks that it reads it from
    /// where it was written.
    pub(super) fn take(definition: &Definition, _rewritten: bool) -> Result<Vec<String>> {
        let failed = |why: String| CliError::HostUnavailable(why);
        succeeded(&["daemon-reload"]).map_err(failed)?;
        let name = definition.target();
        let found = unit(&name).map_err(failed)?;
        match found.fragment {
            Some(fragment) if same_file(&fragment, &definition.path) => Ok(Vec::new()),
            fragment => Err(CliError::HostUnavailable(format!(
                "the user manager does not read {} (it has {name} {}): it reads unit files from \
                 another directory than this command writes them to, so the definition is not \
                 in use; kr host startup --clear removes it",
                definition.path.display(),
                fragment.map_or_else(
                    || found.load_state.clone(),
                    |fragment| format!("from {}", fragment.display())
                )
            ))),
        }
    }

    /// The unit's file goes before the manager is told, so there is nothing of it to release
    /// first: a running daemon keeps its unit until it stops.
    pub(super) fn release(record: &Record) -> Result<Vec<String>> {
        Ok(unit(&record.target())
            .ok()
            .and_then(|found| found.pid)
            .map(|pid| {
                vec![format!(
                    "the daemon the user manager started (process {pid}) keeps serving, and the \
                     manager keeps its unit {} until that daemon stops",
                    record.target()
                )]
            })
            .unwrap_or_default())
    }

    /// Tells the user manager that the unit's file has gone.
    pub(super) fn forget(_record: &Record) -> Vec<String> {
        match succeeded(&["daemon-reload"]) {
            Ok(_) => Vec::new(),
            Err(why) => vec![format!(
                "the user manager was not told the definition has gone, and forgets it at its \
                 next reload: {why}"
            )],
        }
    }

    /// Asks the user manager to start the unit the record names.
    pub(super) fn start(record: &Record) -> std::result::Result<Asked, Refusal> {
        let name = record.target();
        let found = unit(&name).map_err(Refusal::Failed)?;
        match &found.fragment {
            Some(fragment) if same_file(fragment, &record.path) => {}
            Some(fragment) => {
                return Err(Refusal::NotSetUp(format!(
                    "the user manager loads {name} from {}, not from the definition kr wrote, {}; \
                     run kr host startup --set service",
                    fragment.display(),
                    record.path.display()
                )));
            }
            None => {
                return Err(Refusal::NotSetUp(format!(
                    "the user manager has not read the definition kr wrote, {} ({name} is {}); run \
                     kr host startup --set service",
                    record.path.display(),
                    found.load_state
                )));
            }
        }
        succeeded(&["start", &name]).map_err(Refusal::Failed)?;
        Ok(Asked {
            manager: Manager::Systemd,
            pid: unit(&name).ok().and_then(|found| found.pid),
        })
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
mod platform {
    //! No per-user service manager this build writes definitions for.

    use kr_ipc::paths::EnvironmentPaths;

    use super::{Asked, Definition, Manager, Record, Refusal};
    use crate::error::{CliError, Result};

    pub(super) const MANAGER: Option<Manager> = None;

    pub(super) fn domains() -> Vec<Option<String>> {
        Vec::new()
    }

    /// Why the service start cannot be set up here, and what to do instead.
    fn unsupported() -> CliError {
        CliError::Usage(
            "the service start writes a per-user launchd job on macOS or a systemd user unit on \
             Linux, and this platform has neither; start the control daemon, kr-controller, for \
             this environment"
                .to_owned(),
        )
    }

    pub(super) fn available() -> Result<()> {
        Err(unsupported())
    }

    pub(super) fn domain_for(_environment: &EnvironmentPaths) -> Result<Option<String>> {
        Err(unsupported())
    }

    pub(super) fn render(
        _label: &str,
        _domain: Option<String>,
        _arguments: &[String],
        _working_directory: &str,
        _log: &str,
    ) -> Result<Definition> {
        Err(unsupported())
    }

    pub(super) fn take(_definition: &Definition, _rewritten: bool) -> Result<Vec<String>> {
        Ok(Vec::new())
    }

    pub(super) fn release(_record: &Record) -> Result<Vec<String>> {
        Ok(Vec::new())
    }

    pub(super) fn forget(_record: &Record) -> Vec<String> {
        Vec::new()
    }

    pub(super) fn start(_record: &Record) -> std::result::Result<Asked, Refusal> {
        Err(Refusal::NotSetUp(
            "this platform has no service start; start the control daemon, kr-controller, for \
             this environment"
                .to_owned(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A definition written at `path` with `contents`, for the comparisons below.
    fn definition(path: &Path, contents: &str) -> Definition {
        Definition {
            manager: Manager::Launchd,
            label: "kr-controller-test".to_owned(),
            domain: Some("gui/501".to_owned()),
            path: path.to_path_buf(),
            contents: contents.to_owned(),
        }
    }

    /// KR-REQ-07.12, KR-REQ-26.04: the file where a definition belongs is compared with what kr
    /// recorded writing and with what this installation writes, and only a file that is both is
    /// one a command may start the daemon from.
    #[cfg(unix)]
    #[test]
    fn a_definition_is_what_kr_recorded_writing_or_it_is_named_for_what_it_is() {
        use std::os::unix::fs::PermissionsExt as _;

        let host = kr_ipc::testing::TempHost::create();
        let path = host.root().join("kr-controller-test.plist");
        let written = definition(&path, "the definition\n");
        let record = Record::of(&written);
        let expected = std::slice::from_ref(&written);

        assert_eq!(state(&path, Some(&record), expected), State::Missing);
        assert_eq!(state(&path, None, expected), State::Missing);

        kr_ipc::paths::write_owner_only_file(&path, written.contents.as_bytes()).expect("writes");
        assert_eq!(state(&path, Some(&record), expected), State::Matches);
        assert_eq!(
            state(&path, None, expected),
            State::Matches,
            "a file exactly as this installation writes it is the definition, recorded or not"
        );
        let elsewhere = definition(&path, "another program's definition\n");
        assert_eq!(
            state(&path, Some(&record), std::slice::from_ref(&elsewhere)),
            State::Outdated,
            "what kr wrote, unchanged, but not what this installation writes now"
        );

        kr_ipc::paths::write_owner_only_file(&path, b"the definition, edited\n").expect("edits");
        assert_eq!(state(&path, Some(&record), expected), State::Changed);
        assert_eq!(state(&path, None, expected), State::Foreign);

        kr_ipc::paths::write_owner_only_file(&path, written.contents.as_bytes()).expect("writes");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("widens");
        assert_eq!(
            state(&path, None, expected),
            State::Foreign,
            "kr writes a definition owner-only, so one others can write is not kr's"
        );
        assert_eq!(state(&path, Some(&record), expected), State::Changed);

        std::fs::remove_file(&path).expect("removes");
        std::os::unix::fs::symlink(host.root().join("elsewhere"), &path).expect("links");
        assert_eq!(
            state(&path, None, expected),
            State::Foreign,
            "a link is not followed"
        );
    }

    /// Every state but a match names the file and the setup action.
    #[test]
    fn every_trouble_names_the_file_and_what_to_do() {
        let path = Path::new("/home/someone/.config/systemd/user/kr-controller-test.service");
        assert_eq!(State::Matches.trouble(path), None);
        for state in [
            State::Missing,
            State::Changed,
            State::Foreign,
            State::Outdated,
        ] {
            let trouble = state.trouble(path).expect("a trouble");
            assert!(
                trouble.contains(&path.display().to_string()) && trouble.contains(SETUP_ACTION),
                "{}: {trouble}",
                state.as_str()
            );
        }
    }

    /// A record is read back as it was written, and one this build does not write is refused
    /// rather than guessed at.
    #[test]
    fn a_record_is_read_back_as_written_and_another_version_is_refused() {
        let host = kr_ipc::testing::TempHost::create();
        let environment = host.environment();
        assert_eq!(Record::read(&environment), Ok(None));
        let written = definition(&host.root().join("kr-controller-test.plist"), "contents\n");
        Record::write(&environment, &written).expect("writes the record");
        let read = Record::read(&environment)
            .expect("reads the record")
            .expect("a record");
        assert_eq!(read, Record::of(&written));
        assert_eq!(read.target(), "gui/501/kr-controller-test");

        let mut other = serde_json::to_value(&read).expect("encodes");
        other["version"] = serde_json::json!(RECORD_VERSION + 1);
        kr_ipc::paths::write_owner_only_file(
            &Record::path(&environment),
            other.to_string().as_bytes(),
        )
        .expect("writes another version");
        assert!(
            Record::read(&environment)
                .expect_err("refused")
                .contains("at version"),
        );
    }

    /// A definition names only paths either manager can be told exactly.
    #[cfg(unix)]
    #[test]
    fn a_path_is_written_into_a_definition_only_when_a_manager_can_take_it_exactly() {
        assert_eq!(text(Path::new("/a/b c/d")).expect("a path"), "/a/b c/d");
        for refused in [
            "relative/path",
            "/a/line\nbreak",
            "/a/tab\there",
            "/a/trailing ",
        ] {
            assert!(
                text(Path::new(refused)).is_err(),
                "{refused:?} cannot be written into a definition"
            );
        }
    }

    /// KR-REQ-07.12: a launchd job runs the daemon with this installation's roots, in the
    /// environment's own directory, only when asked, in the session type its domain loads, and
    /// with every value escaped as a property list's string.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_launchd_job_is_started_only_when_asked_in_its_domains_session_type() {
        let arguments = [
            "/opt/k&r/kr-controller".to_owned(),
            "--runtime-dir".to_owned(),
            "/tmp/<runtime>".to_owned(),
        ];
        let graphical = platform::render(
            "kr-controller-test",
            Some("gui/501".to_owned()),
            &arguments,
            "/state/dir",
            "/state/dir/controller.log",
        )
        .expect("renders");
        let contents = &graphical.contents;
        for expected in [
            "<string>/opt/k&amp;r/kr-controller</string>",
            "<string>/tmp/&lt;runtime&gt;</string>",
            "<key>RunAtLoad</key>\n\t<false/>",
            "<key>KeepAlive</key>\n\t<false/>",
            "<key>LimitLoadToSessionType</key>\n\t<string>Aqua</string>",
            "<key>WorkingDirectory</key>\n\t<string>/state/dir</string>",
            "<key>StandardOutPath</key>\n\t<string>/state/dir/controller.log</string>",
            "<key>Umask</key>\n\t<integer>63</integer>",
        ] {
            assert!(contents.contains(expected), "{expected}: {contents}");
        }
        assert!(
            graphical
                .path
                .ends_with("Library/LaunchAgents/kr-controller-test.plist")
        );
        assert_eq!(graphical.target(), "gui/501/kr-controller-test");
        let background = platform::render(
            "kr-controller-test",
            Some("user/501".to_owned()),
            &arguments,
            "/state/dir",
            "/state/dir/controller.log",
        )
        .expect("renders");
        assert!(
            background
                .contents
                .contains("<key>LimitLoadToSessionType</key>\n\t<string>Background</string>")
        );
    }

    /// KR-REQ-07.12: a systemd user unit runs the daemon with this installation's roots, in the
    /// environment's own directory, only when started, with every word taken exactly as it is.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_user_unit_is_started_only_when_asked_and_takes_every_word_as_it_is() {
        let arguments = [
            "/opt/k r/kr-controller".to_owned(),
            "--state-dir".to_owned(),
            "/tmp/100%/$HOME/\"q\"\\".to_owned(),
        ];
        let unit = platform::render(
            "kr-controller-test",
            None,
            &arguments,
            "/state/50%",
            "/state/50%/controller.log",
        )
        .expect("renders");
        let contents = &unit.contents;
        for expected in [
            "Type=exec\n",
            "ExecStart=\"/opt/k r/kr-controller\" \"--state-dir\" \"/tmp/100%%/$$HOME/\\\"q\\\"\\\\\"\n",
            "WorkingDirectory=/state/50%%\n",
            "StandardOutput=append:/state/50%%/controller.log\n",
            "UMask=0077\n",
            "Restart=no\n",
        ] {
            assert!(contents.contains(expected), "{expected}: {contents}");
        }
        assert!(
            !contents.contains("[Install]"),
            "nothing enables it, so nothing starts it but a command: {contents}"
        );
        assert!(
            unit.path
                .ends_with("systemd/user/kr-controller-test.service")
        );
        assert_eq!(unit.target(), "kr-controller-test.service");
    }
}
