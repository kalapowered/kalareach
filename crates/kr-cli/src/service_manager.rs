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
//! sessions it creates by default run, and a definition in the other domain is out of date.
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
//! remove. Only a regular file is moved, and it is moved aside before it is checked for replacing or
//! removing, so what was checked is exactly what is replaced or removed; one that turns out not to
//! be what kr wrote goes back by a link, which never replaces a file that took its place, or stays
//! aside, and the command says where.
//!
//! What the manager would run has to be exactly the definition as well, by one rule for each
//! manager. launchd must hold the job from kr's file, running exactly its program, arguments and
//! working directory, or hold nothing, in which case the start request loads it; the check before a
//! start request and the request itself each decide from what launchd holds when they ask. The user
//! manager is asked everything through `systemctl --user`, so every question and request reaches
//! the one manager; it must load the unit cleanly from kr's file, have nothing to reload, and read
//! no drop-in for it with a line that could set a command or the start type, so the command comes
//! from kr's file alone; and what it prints must agree: one command, the file's program, words and
//! flags, started as the file says. Whatever else a drop-in sets, such as the daemon's environment
//! or limits, is the host's and the person's.
//!
//! kr never ends a daemon, and never asks a manager to: it loads a definition and asks for a start,
//! and nothing else. A manager holding another form of the job, or another definition under its
//! label, is named with its remedy, `launchctl bootout` or the drop-ins to look in, which is the
//! person's to apply. Removing a definition leaves a running daemon running: launchd keeps its job
//! until its domain ends, and the user manager keeps a running unit whose file has gone until it
//! stops.
//!
//! Every change `kr host startup` makes and every start request holds the environment's
//! `controller-service.lock` while it looks at or changes the definition or the manager's job, and
//! a change holds it until the configuration document is written too, so none of them acts on what
//! another has just changed. The lock is taken before the document's own lock, never after it.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use kr_ipc::paths::EnvironmentPaths;
use serde::{Deserialize, Serialize};

use crate::error::{CliError, Result};

/// The file in an environment's state directory that records the definition `kr host startup`
/// wrote.
pub const RECORD_FILE: &str = "controller-service.json";

/// The file in an environment's state directory whose lock setup, removal and a start request
/// hold.
pub const LOCK_FILE: &str = "controller-service.lock";

/// The version of the record this build writes and reads.
const RECORD_VERSION: u32 = 1;

/// The largest record, or definition, this build reads: far more than it ever writes.
const READ_LIMIT: u64 = 64 * 1024;

/// How long a command waits for another to finish with the service start before it says who holds
/// it: long enough for every command the other puts to the manager to have answered.
const LOCK_WAIT: Duration = Duration::from_secs(60);

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
    /// The program it runs, the first of its arguments.
    pub program: String,
    /// Every argument it runs the program with, the program first.
    pub arguments: Vec<String>,
    /// The directory the program runs in.
    pub working_directory: String,
}

impl Definition {
    /// What `launchctl` and `systemctl` call it: `<domain>/<label>`, or `<label>.service`.
    #[must_use]
    pub fn target(&self) -> String {
        target(self.manager, &self.label, self.domain.as_deref())
    }

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
        let arguments = vec![
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
            arguments,
            text(state)?,
            text(&log)?,
        )
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

/// The service start's lock for one environment, held for as long as its holder looks at or
/// changes the definition or the manager's job.
#[derive(Debug)]
pub struct Lock {
    _file: std::fs::File,
}

/// Takes an environment's service lock for a change `kr host startup` makes, which holds it until
/// the configuration document is written as well.
///
/// # Errors
///
/// Returns [`CliError::HostUnavailable`] when another command holds it for longer than the wait,
/// or it cannot be taken.
pub fn lock(environment: &EnvironmentPaths) -> Result<Lock> {
    Lock::take(environment).map_err(CliError::HostUnavailable)
}

impl Lock {
    /// Takes the environment's lock, waiting [`LOCK_WAIT`] for another command to finish with it.
    fn take(environment: &EnvironmentPaths) -> std::result::Result<Self, String> {
        Self::take_within(environment, LOCK_WAIT)
    }

    /// Takes the environment's lock, waiting at most `wait`.
    ///
    /// The lock is the operating system's, on an open file, so a command that ends however it ends
    /// lets go of it. The file stays where it is.
    fn take_within(
        environment: &EnvironmentPaths,
        wait: Duration,
    ) -> std::result::Result<Self, String> {
        let path = environment.state_dir().join(LOCK_FILE);
        let mut options = std::fs::OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let file = options
            .open(&path)
            .map_err(|error| format!("{} could not be opened: {error}", path.display()))?;
        let deadline = Instant::now() + wait;
        loop {
            match file.try_lock() {
                Ok(()) => return Ok(Self { _file: file }),
                Err(std::fs::TryLockError::WouldBlock) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(std::fs::TryLockError::WouldBlock) => {
                    return Err(format!(
                        "another kr command has held {} for {} seconds while it sets up, removes \
                         or starts this environment's daemon",
                        path.display(),
                        wait.as_secs()
                    ));
                }
                Err(std::fs::TryLockError::Error(error)) => {
                    return Err(format!("{} could not be locked: {error}", path.display()));
                }
            }
        }
    }
}

/// What the file where a definition belongs turned out to be.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// The file is what this installation writes, and the record says kr wrote it.
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
    /// The file is exactly what this installation writes, and kr has no record of writing it.
    Unrecorded,
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
            Self::Unrecorded => "unrecorded",
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
            Self::Unrecorded => Some(format!(
                "the service definition {path} is what kr writes, and kr has no record of writing \
                 it; {SETUP_ACTION} to record it"
            )),
        }
    }
}

/// Compares the file at `path` with what kr recorded writing there and with what this
/// installation writes now, `expected`.
///
/// kr writes a definition owner-only, as a regular file, so anything else at the path, a link or a
/// file others may write, is not what kr wrote.
fn state(path: &Path, record: Option<&Record>, expected: &Definition) -> State {
    let bytes = match kr_ipc::paths::read_owner_only_file(path, READ_LIMIT) {
        Ok(None) => return State::Missing,
        Ok(Some(bytes)) => bytes,
        Err(_) if record.is_some() => return State::Changed,
        Err(_) => return State::Foreign,
    };
    let current = expected.path == path && bytes == expected.contents.as_bytes();
    match record {
        Some(record) if bytes == record.contents.as_bytes() => {
            if current {
                State::Matches
            } else {
                State::Outdated
            }
        }
        Some(_) => State::Changed,
        None if current => State::Unrecorded,
        None => State::Foreign,
    }
}

/// What moving a definition aside for a check found.
#[derive(Debug, PartialEq, Eq)]
enum Moved {
    /// Nothing was there.
    Nothing,
    /// What is there is not a regular file, so it is not what kr wrote, and it was not moved.
    NotRegular,
    /// The file is at this name beside where it was.
    Aside(PathBuf),
}

/// Moves the regular file at `path` to a name of its own beside it, so that what is checked next
/// is exactly what will be replaced or removed.
fn move_aside(path: &Path) -> std::result::Result<Moved, String> {
    match std::fs::symlink_metadata(path) {
        Ok(about) if about.file_type().is_file() => {}
        Ok(_) => return Ok(Moved::NotRegular),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Moved::Nothing),
        Err(error) => return Err(format!("{} could not be read: {error}", path.display())),
    }
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    let aside = path.with_file_name(format!(".{name}.{}.kr-moving", kr_ipc::new_uuid()));
    match std::fs::rename(path, &aside) {
        Ok(()) => Ok(Moved::Aside(aside)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Moved::Nothing),
        Err(error) => Err(format!("{} could not be moved: {error}", path.display())),
    }
}

/// Puts a file moved aside back where it was, unless something has taken its place since, and
/// says where it is otherwise.
///
/// It goes back by a link, which is refused when the name is taken, so a file written there
/// meanwhile is never replaced. What was moved is left where it is when it is no longer a regular
/// file, which is what something replacing it in the moment before it was moved leaves.
fn put_back(aside: &Path, path: &Path) -> std::result::Result<(), String> {
    if !std::fs::symlink_metadata(aside).is_ok_and(|about| about.file_type().is_file()) {
        return Err(format!(
            "it is at {}, because it is not a regular file and kr puts back only what it can link",
            aside.display()
        ));
    }
    std::fs::hard_link(aside, path)
        .and_then(|()| std::fs::remove_file(aside))
        .map_err(|error| {
            format!(
                "it is at {}, because it could not be put back at {}: {error}",
                aside.display(),
                path.display()
            )
        })
}

/// Whether a file moved aside is exactly `contents`, read as kr writes a definition: owner-only
/// and regular.
fn moved_is(aside: &Path, contents: &str) -> bool {
    kr_ipc::paths::read_owner_only_file(aside, READ_LIMIT)
        .is_ok_and(|bytes| bytes.as_deref() == Some(contents.as_bytes()))
}

/// What the service start has on this host for an environment, for a person to read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Inspection {
    /// The manager.
    pub manager: Manager,
    /// The label.
    pub label: String,
    /// The launchd domain the definition is, or would be, loaded into.
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
/// `selected` says the service start is chosen and nothing is recorded, where one would be. The
/// domain is the one the environment's default execution profile implies now. An environment with
/// neither a record nor the choice has nothing to inspect, and nothing is changed either way.
///
/// Returns none when there is nothing to inspect, and why not when what is there cannot be
/// established.
#[must_use]
pub fn inspect(
    environment: &EnvironmentPaths,
    selected: bool,
) -> Option<std::result::Result<Inspection, String>> {
    let record = match Record::read(environment) {
        Ok(record) => record,
        Err(why) => return Some(Err(why)),
    };
    let manager = platform::MANAGER?;
    if record.is_none() && !selected {
        return None;
    }
    let expected = match platform::domain_for(environment)
        .and_then(|domain| Definition::write_for(environment, domain))
    {
        Ok(expected) => expected,
        Err(error) => return Some(Err(error.to_string())),
    };
    let path = record
        .as_ref()
        .map_or_else(|| expected.path.clone(), |record| record.path.clone());
    Some(Ok(Inspection {
        manager: record.as_ref().map_or(manager, |record| record.manager),
        label: label(environment),
        domain: record
            .as_ref()
            .map_or_else(|| expected.domain.clone(), |record| record.domain.clone()),
        state: state(&path, record.as_ref(), &expected),
        path,
        recorded: record.is_some(),
    }))
}

/// What `kr host startup --set service` did.
#[derive(Debug)]
pub struct Installed {
    /// What a person should know about what the manager holds.
    pub notes: Vec<String>,
}

/// Writes the definition of an environment's daemon, records it, and has the manager take it.
///
/// Nothing is written over a definition kr did not write or one changed since it did, and neither
/// the command nor the manager starts the daemon here. The caller holds the environment's service
/// lock, which is why it is asked for.
///
/// # Errors
///
/// Returns [`CliError::Usage`] when this host has no service manager to write for, and when a
/// definition kr may not replace is where this one belongs, both with nothing written; and what
/// failed otherwise, with what was written left recorded for `--clear`.
pub fn install(environment: &EnvironmentPaths, _held: &Lock) -> Result<Installed> {
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
    let before = state(&expected.path, record.as_ref(), &expected);
    let refused = |state: State| CliError::Usage(state.trouble(&expected.path).unwrap_or_default());
    match (before, &record) {
        (State::Foreign | State::Changed, _) => return Err(refused(before)),
        (State::Matches | State::Unrecorded, _) => {}
        (State::Missing, _) => {
            if let Some(parent) = expected.path.parent() {
                std::fs::create_dir_all(parent).map_err(|error| {
                    CliError::Ipc(kr_ipc::IpcError::io("create", parent, error))
                })?;
            }
            publish(&expected)?;
        }
        (State::Outdated, Some(record)) => {
            // The file is moved aside and checked once it is out of the way, so a file changed
            // since it was read above goes back rather than being replaced.
            let aside = match move_aside(&expected.path).map_err(CliError::HostUnavailable)? {
                Moved::Aside(aside) => aside,
                Moved::Nothing => return Err(refused(State::Missing)),
                Moved::NotRegular => return Err(refused(State::Changed)),
            };
            if !moved_is(&aside, &record.contents) {
                return Err(CliError::Usage(match put_back(&aside, &expected.path) {
                    Ok(()) => refused(State::Changed).to_string(),
                    Err(where_it_is) => format!(
                        "the service definition {} was changed after kr wrote it; {where_it_is}",
                        expected.path.display()
                    ),
                }));
            }
            if let Err(error) = publish(&expected) {
                if let Err(where_it_is) = put_back(&aside, &expected.path) {
                    return Err(CliError::HostUnavailable(format!(
                        "{error}; the earlier one: {where_it_is}"
                    )));
                }
                return Err(error);
            }
            let _ = std::fs::remove_file(&aside);
        }
        (State::Outdated, None) => return Err(refused(State::Foreign)),
    }
    let mut notes = Vec::new();
    // The job the earlier definition was loaded as, in a domain this one is not loaded into, is
    // left to its domain; the person is told what it is doing.
    if let Some(record) = &record
        && record.target() != expected.target()
    {
        notes.extend(platform::release(record));
    }
    Record::write(environment, &expected)?;
    notes.extend(platform::take(&expected)?);
    Ok(Installed { notes })
}

/// Publishes a definition where none is, and never over one that appeared meanwhile.
fn publish(definition: &Definition) -> Result<()> {
    kr_ipc::paths::create_new_owner_only_file(&definition.path, definition.contents.as_bytes())
        .map_err(|error| {
            CliError::Usage(format!(
                "the service definition {} could not be written, and whatever is there now is \
                 left as it is: {error}",
                definition.path.display()
            ))
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
/// changed after kr wrote it is no longer kr's to remove, and is left, with its record gone. The
/// manager is not asked to do anything: what it holds is left to it, and the person is told. The
/// caller holds the environment's service lock, which is why it is asked for.
///
/// # Errors
///
/// Returns [`CliError::Usage`] when the record cannot be read, and what failed while removing.
pub fn remove(environment: &EnvironmentPaths, _held: &Lock) -> Result<Removal> {
    let Some(record) = Record::read(environment).map_err(CliError::Usage)? else {
        return Ok(Removal::default());
    };
    let mut removal = Removal::default();
    let changed = "it was changed after kr wrote it, so it is no longer kr's to remove";
    match move_aside(&record.path).map_err(CliError::HostUnavailable)? {
        Moved::Nothing => {}
        Moved::NotRegular => removal.left.push((record.path.clone(), changed.to_owned())),
        Moved::Aside(aside) if moved_is(&aside, &record.contents) => {
            std::fs::remove_file(&aside)
                .map_err(|error| CliError::Ipc(kr_ipc::IpcError::io("remove", &aside, error)))?;
            removal.removed.push(record.path.clone());
        }
        Moved::Aside(aside) => match put_back(&aside, &record.path) {
            Ok(()) => removal.left.push((record.path.clone(), changed.to_owned())),
            Err(where_it_is) => removal
                .left
                .push((aside, format!("{changed}; {where_it_is}"))),
        },
    }
    removal.notes.extend(platform::release(&record));
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
    /// The manager was asked and did not start the daemon, or could not be asked.
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

/// A definition checked for a start request, with the environment's lock held until the request
/// has been made.
#[derive(Debug)]
pub struct Verified {
    record: Record,
    expected: Definition,
    _lock: Lock,
}

/// Checks the definition kr wrote for an environment before `kr new` asks the manager to start
/// the daemon from it, and holds the environment's lock until it has.
///
/// One that is not exactly what kr recorded writing and what this installation writes now, in the
/// domain the environment's default execution profile implies, is a refusal with the setup action,
/// and so is a manager holding anything under its label but that definition. Nothing is written or
/// started, the daemon's log included.
///
/// # Errors
///
/// Returns the refusal.
pub fn verify(environment: &EnvironmentPaths) -> std::result::Result<Verified, Refusal> {
    let not_set_up = || {
        Refusal::NotSetUp(format!(
            "startup.controller is service and no service definition was written for this \
             environment; {SETUP_ACTION}"
        ))
    };
    let read = || {
        Record::read(environment).map_err(|why| Refusal::NotSetUp(format!("{why}; {SETUP_ACTION}")))
    };
    // An environment that never had a definition written has no lock file to take either.
    read()?.ok_or_else(not_set_up)?;
    let lock = Lock::take(environment).map_err(Refusal::Failed)?;
    let record = read()?.ok_or_else(not_set_up)?;
    if platform::MANAGER != Some(record.manager) {
        return Err(Refusal::NotSetUp(format!(
            "the service definition kr recorded is for {}, which this host does not start \
             daemons with; {SETUP_ACTION}",
            record.manager.as_str()
        )));
    }
    let expected = platform::domain_for(environment)
        .and_then(|domain| Definition::write_for(environment, domain))
        .map_err(|error| Refusal::NotSetUp(format!("{error}; {SETUP_ACTION}")))?;
    let found = state(&record.path, Some(&record), &expected);
    if let Some(trouble) = found.trouble(&record.path) {
        return Err(Refusal::NotSetUp(trouble));
    }
    // What the manager holds, last: it has to be this definition, or nothing yet.
    platform::check(&record, &expected)?;
    Ok(Verified {
        record,
        expected,
        _lock: lock,
    })
}

impl Verified {
    /// Asks the manager to start the daemon from the checked definition, loading it first where
    /// the manager holds nothing under its label, and lets go of the environment's lock.
    ///
    /// A daemon the manager is already running is the one it reports.
    ///
    /// # Errors
    ///
    /// Returns the refusal.
    pub fn start(self) -> std::result::Result<Asked, Refusal> {
        platform::start(&self.record, &self.expected)
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

/// Runs one command put to the service manager within [`MANAGER_BOUND`], with `environment` set
/// for it, and returns its answer or why there was none.
///
/// What it prints is read while it runs, so an answer of any size cannot stall it. One that does
/// not answer in time is ended and collected: it is this process's own child.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn run(
    program: &str,
    arguments: &[&str],
    environment: &[(&str, &std::ffi::OsStr)],
) -> std::result::Result<std::process::Output, String> {
    let asked = format!("{program} {}", arguments.join(" "));
    let mut child = std::process::Command::new(program)
        .args(arguments)
        .envs(environment.iter().copied())
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

    use super::{
        Asked, Definition, Manager, Record, Refusal, SETUP_ACTION, refused, run, same_file, text,
    };
    use crate::error::{CliError, Result};

    /// The manager this platform's definitions are for.
    pub(super) const MANAGER: Option<Manager> = Some(Manager::Launchd);

    const LAUNCHCTL: &str = "/bin/launchctl";

    /// What `launchctl print` exits with for a domain that does not exist.
    const NO_SUCH_DOMAIN: i32 = 112;

    /// What `launchctl print` exits with for a job the domain does not have.
    const NOT_LOADED: i32 = 113;

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
        let uid = kr_ipc::paths::current_uid();
        let domain = match profile {
            WorkerProfile::DesktopBound => format!("gui/{uid}"),
            WorkerProfile::HeadlessUser => format!("user/{uid}"),
        };
        match run(LAUNCHCTL, &["print", &domain], &[]) {
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
        arguments: Vec<String>,
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
        for argument in &arguments {
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
            program: arguments[0].clone(),
            arguments,
            working_directory: working_directory.to_owned(),
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
    #[derive(Debug, PartialEq, Eq)]
    pub(super) enum Job {
        NotLoaded,
        Loaded(Loaded),
    }

    /// A job launchd holds, as `launchctl print` describes it.
    #[derive(Debug, Default, PartialEq, Eq)]
    pub(super) struct Loaded {
        path: Option<PathBuf>,
        program: Option<String>,
        arguments: Vec<String>,
        working_directory: Option<String>,
        pid: Option<u32>,
    }

    impl Loaded {
        /// Reads what `launchctl print <domain>/<label>` printed for a loaded job.
        ///
        /// The job's own fields are at the first level of the description, one tab in; its
        /// arguments are the lines two tabs in under `arguments = {`.
        pub(super) fn read(printed: &str) -> Self {
            let mut loaded = Self::default();
            let mut in_arguments = false;
            for line in printed.lines() {
                if in_arguments {
                    match line.strip_prefix("\t\t") {
                        Some(argument) => loaded.arguments.push(argument.to_owned()),
                        None => in_arguments = false,
                    }
                    continue;
                }
                let Some((name, value)) = line.strip_prefix('\t').and_then(|field| {
                    (!field.starts_with('\t'))
                        .then(|| field.split_once(" = "))
                        .flatten()
                }) else {
                    continue;
                };
                match name {
                    "path" => loaded.path = Some(PathBuf::from(value)),
                    "program" => loaded.program = Some(value.to_owned()),
                    "working directory" => loaded.working_directory = Some(value.to_owned()),
                    "pid" => loaded.pid = value.trim().parse().ok(),
                    "arguments" if value == "{" => in_arguments = true,
                    _ => {}
                }
            }
            loaded
        }

        /// Whether launchd would run exactly what `definition` says, from its file.
        fn runs(&self, definition: &Definition) -> bool {
            self.program.as_deref() == Some(definition.program.as_str())
                && self.arguments == definition.arguments
                && self.working_directory.as_deref().is_some_and(|directory| {
                    same_file(
                        Path::new(directory),
                        Path::new(&definition.working_directory),
                    )
                })
        }

        /// Whether it was loaded from the file at `path`.
        fn from(&self, path: &Path) -> bool {
            self.path
                .as_deref()
                .is_some_and(|from| same_file(from, path))
        }
    }

    fn job(target: &str) -> std::result::Result<Job, String> {
        let output = run(LAUNCHCTL, &["print", target], &[])?;
        match output.status.code() {
            Some(0) => Ok(Job::Loaded(Loaded::read(&String::from_utf8_lossy(
                &output.stdout,
            )))),
            Some(NO_SUCH_DOMAIN | NOT_LOADED) => Ok(Job::NotLoaded),
            _ => Err(refused(&format!("launchctl print {target}"), &output)),
        }
    }

    fn succeeded(arguments: &[&str]) -> std::result::Result<std::process::Output, String> {
        let output = run(LAUNCHCTL, arguments, &[])?;
        if output.status.success() {
            Ok(output)
        } else {
            Err(refused(
                &format!("launchctl {}", arguments.join(" ")),
                &output,
            ))
        }
    }

    /// Loads the definition at `path` into `domain`.
    fn load(domain: &str, path: &Path) -> std::result::Result<(), String> {
        succeeded(&["bootstrap", domain, &path.display().to_string()]).map(|_| ())
    }

    /// Why what launchd holds under a definition's label is not exactly that definition, when it is
    /// not: another definition's job, or an earlier form of this one. Either way the remedy is the
    /// person's own `launchctl bootout`, which also ends any daemon the job runs, so kr names it
    /// and does not run it.
    fn held_otherwise(loaded: &Loaded, definition: &Definition) -> Option<String> {
        let target = definition.target();
        let remedy = format!(
            "launchctl bootout {target} removes it, and ends the daemon it runs if it runs one"
        );
        if !loaded.from(&definition.path) {
            return Some(format!(
                "launchd holds a job labelled {} in {} from another definition, {}; {remedy}",
                definition.label,
                definition.domain.as_deref().unwrap_or_default(),
                loaded.path.as_deref().map_or_else(
                    || "one it does not name".to_owned(),
                    |path| path.display().to_string()
                )
            ));
        }
        (!loaded.runs(definition)).then(|| {
            format!(
                "launchd holds an earlier form of {target}, which runs {} {:?}{}; {remedy}",
                loaded.program.as_deref().unwrap_or_default(),
                loaded.arguments,
                loaded
                    .pid
                    .map_or_else(String::new, |pid| format!(" as process {pid}"))
            )
        })
    }

    /// Has launchd hold the definition just written, with the environment's service lock held: it is
    /// loaded where launchd holds nothing under its label. Anything else launchd holds there is
    /// named with its remedy, and the definition stays written and recorded.
    pub(super) fn take(definition: &Definition) -> Result<Vec<String>> {
        let domain = definition.domain.as_deref().unwrap_or_default();
        let target = definition.target();
        let failed = |why: String| CliError::HostUnavailable(why);
        if let Job::Loaded(loaded) = job(&target).map_err(failed)? {
            return match held_otherwise(&loaded, definition) {
                None => Ok(Vec::new()),
                Some(why) => Err(CliError::HostUnavailable(format!(
                    "{why}; then run kr host startup --set service again. The definition is \
                     written and recorded, and kr host startup --clear removes it"
                ))),
            };
        }
        load(domain, &definition.path).map_err(failed)?;
        match job(&target).map_err(failed)? {
            Job::Loaded(loaded) if held_otherwise(&loaded, definition).is_none() => Ok(Vec::new()),
            found => Err(CliError::HostUnavailable(format!(
                "launchd does not hold the definition just loaded as {target}: {found:?}"
            ))),
        }
    }

    /// What a start request does with what launchd holds under the definition's label.
    #[derive(Debug, PartialEq, Eq)]
    pub(super) enum Next {
        /// Nothing is held yet: the definition is loaded first.
        Load,
        /// Exactly the definition is held: the job is started.
        Start,
    }

    /// Decides [`Next`] from what launchd holds: anything but exactly the definition, or nothing,
    /// is a refusal naming its remedy. The check before a start request and the start request
    /// itself both decide by this, each from what launchd holds when it asks.
    pub(super) fn next(found: &Job, expected: &Definition) -> std::result::Result<Next, Refusal> {
        match found {
            Job::NotLoaded => Ok(Next::Load),
            Job::Loaded(loaded) => match held_otherwise(loaded, expected) {
                None => Ok(Next::Start),
                Some(why) => Err(Refusal::NotSetUp(format!("{why}; then {SETUP_ACTION}"))),
            },
        }
    }

    /// Checks, for a start request, that launchd holds exactly the checked definition under its
    /// label, or nothing yet.
    pub(super) fn check(
        record: &Record,
        expected: &Definition,
    ) -> std::result::Result<(), Refusal> {
        next(&job(&record.target()).map_err(Refusal::Failed)?, expected).map(|_| ())
    }

    /// What launchd still holds of a definition kr is removing, or has moved away from, told
    /// rather than changed: launchd keeps a job it loaded until its domain ends, and a job that
    /// runs a daemon keeps it running.
    pub(super) fn release(record: &Record) -> Vec<String> {
        let target = record.target();
        match job(&target) {
            Ok(Job::NotLoaded) => Vec::new(),
            Ok(Job::Loaded(loaded)) if !loaded.from(&record.path) => Vec::new(),
            Ok(Job::Loaded(Loaded { pid: Some(pid), .. })) => vec![format!(
                "the daemon launchd started (process {pid}) keeps serving, and launchd keeps its \
                 job {target} until its domain ends"
            )],
            Ok(Job::Loaded(_)) => vec![format!(
                "launchd keeps the job {target} until its domain ends; kr asks it to start \
                 nothing more, though a start requested earlier may still complete"
            )],
            Err(why) => vec![format!("launchd could not be asked about {target}: {why}")],
        }
    }

    /// Nothing to tell launchd once a definition's file has gone: it read the file when it loaded
    /// it.
    pub(super) fn forget(_record: &Record) -> Vec<String> {
        Vec::new()
    }

    /// Asks launchd to start the job the record names, with the environment's service lock held
    /// since the check. It is loaded first where launchd holds nothing under its label, as after a
    /// restart until the domain has loaded it again.
    ///
    /// The lock keeps other kr commands out, not other `launchctl` callers, so what launchd holds
    /// is decided again here, from what it holds now.
    pub(super) fn start(
        record: &Record,
        expected: &Definition,
    ) -> std::result::Result<Asked, Refusal> {
        let domain = record.domain.as_deref().unwrap_or_default();
        let target = record.target();
        if next(&job(&target).map_err(Refusal::Failed)?, expected)? == Next::Load {
            load(domain, &record.path).map_err(Refusal::Failed)?;
            match job(&target).map_err(Refusal::Failed)? {
                Job::Loaded(loaded) if held_otherwise(&loaded, expected).is_none() => {}
                found => {
                    return Err(Refusal::Failed(format!(
                        "launchd does not hold the definition just loaded as {target}: {found:?}"
                    )));
                }
            }
        }
        let output = run(LAUNCHCTL, &["kickstart", "-p", &target], &[]).map_err(Refusal::Failed)?;
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
}

#[cfg(target_os = "linux")]
mod platform {
    //! The systemd user manager.
    //!
    //! Every question kr puts to it and every request it makes go through `systemctl --user`,
    //! with the runtime directory set for the command, so all of them reach the one manager that
    //! directory belongs to, over the manager's own socket or the user bus as `systemctl` chooses.
    //! What the manager holds is read from `systemctl show`'s key=value lines, and the drop-ins it
    //! names are read from disk.

    use std::path::PathBuf;

    use kr_ipc::paths::EnvironmentPaths;

    use super::{
        Asked, Definition, Manager, READ_LIMIT, Record, Refusal, SETUP_ACTION, refused, run,
        same_file, text,
    };
    use crate::error::{CliError, Result};

    /// The manager this platform's definitions are for.
    pub(super) const MANAGER: Option<Manager> = Some(Manager::Systemd);

    const SYSTEMCTL: &str = "systemctl";

    /// The runtime directory the user manager answers in: `XDG_RUNTIME_DIR` where it names one,
    /// and otherwise the one systemd gives this user.
    fn runtime_directory() -> PathBuf {
        std::env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .filter(|directory| directory.is_absolute())
            .unwrap_or_else(|| PathBuf::from(format!("/run/user/{}", kr_ipc::paths::current_uid())))
    }

    /// `systemctl --user` with the arguments given and the runtime directory set, never paging
    /// and never asking for a password.
    fn systemctl(arguments: &[&str]) -> std::result::Result<std::process::Output, String> {
        let mut all = vec!["--user", "--no-pager", "--no-ask-password"];
        all.extend_from_slice(arguments);
        let runtime = runtime_directory();
        run(SYSTEMCTL, &all, &[("XDG_RUNTIME_DIR", runtime.as_os_str())])
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

    /// A value as a unit file's command line takes it: one quoted word, with the specifier
    /// character doubled. The command carries the prefix that turns environment expansion off, so
    /// a dollar sign is taken as it is.
    pub(super) fn word(value: &str) -> String {
        let escaped = value
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('%', "%%");
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
        arguments: Vec<String>,
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
        // `:` before the program turns environment expansion off for the whole command line.
        let mut command = vec![word(&format!(":{}", arguments[0]))];
        command.extend(arguments[1..].iter().map(|argument| word(argument)));
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
            program: arguments[0].clone(),
            arguments,
            working_directory: working_directory.to_owned(),
        })
    }

    /// The property that lists the command the daemon runs as.
    const START: &str = "ExecStartEx";

    /// The flag a command carries when its line starts with `:`: no environment expansion.
    const NO_ENVIRONMENT_EXPANSION: &str = "no-env-expand";

    /// How the unit kr writes is started.
    const START_TYPE: &str = "exec";

    /// The load state of a unit the manager read without a fault.
    const LOADED: &str = "loaded";

    /// What the user manager holds under one unit name, as `systemctl show` prints it.
    #[derive(Debug, Default, PartialEq, Eq)]
    pub(super) struct Unit {
        pub(super) load_state: String,
        pub(super) fragment: Option<PathBuf>,
        pub(super) drop_ins: Vec<PathBuf>,
        /// Why the drop-in list could not be read back, when it could not.
        pub(super) unread_drop_ins: Option<String>,
        pub(super) need_reload: bool,
        pub(super) start_type: String,
        /// Every `Exec…Ex` line printed, the property and the command as `systemctl show` prints
        /// it; a property that lists no command prints no line.
        pub(super) commands: Vec<(String, String)>,
        pub(super) pid: Option<u32>,
    }

    impl Unit {
        /// Reads the key=value lines `systemctl show` printed for a unit.
        pub(super) fn read(printed: &str) -> Self {
            let mut unit = Self::default();
            for line in printed.lines() {
                let Some((key, value)) = line.split_once('=') else {
                    continue;
                };
                match key {
                    "LoadState" => value.clone_into(&mut unit.load_state),
                    "FragmentPath" => {
                        unit.fragment = (!value.is_empty()).then(|| PathBuf::from(value));
                    }
                    "DropInPaths" => match drop_ins(value) {
                        Ok(paths) => unit.drop_ins = paths,
                        Err(why) => unit.unread_drop_ins = Some(why),
                    },
                    "NeedDaemonReload" => unit.need_reload = value == "yes",
                    "Type" => value.clone_into(&mut unit.start_type),
                    "MainPID" => unit.pid = value.parse().ok().filter(|pid| *pid != 0),
                    _ if key.starts_with("Exec") && key.ends_with("Ex") => {
                        unit.commands.push((key.to_owned(), value.to_owned()));
                    }
                    _ => {}
                }
            }
            unit
        }

        /// Why the user manager would not run the definition kr wrote as kr wrote it, when it
        /// would not, with the drop-ins it reads for the unit named for a person to look in.
        pub(super) fn difference(&self, definition: &Definition) -> Option<String> {
            let why = self.differs(definition)?;
            Some(format!("{why}; {}", self.reads()))
        }

        /// The rule: the manager loads the unit cleanly from kr's file, has read that file since
        /// it last changed, and reads no drop-in for it that sets a command or how it is started,
        /// so the command comes from kr's byte-checked file alone; and what it prints agrees: one
        /// command, the file's, with its program, words and flags as kr wrote them, started the
        /// way the file says. Whatever else a drop-in sets for the unit, its environment, limits
        /// or timeouts, is the host's and the person's own, and kr leaves it to them.
        fn differs(&self, definition: &Definition) -> Option<String> {
            let name = definition.target();
            match &self.fragment {
                Some(fragment) if same_file(fragment, &definition.path) => {}
                Some(fragment) => {
                    return Some(format!(
                        "the user manager loads {name} from {}, not from the definition kr wrote, \
                         {}",
                        fragment.display(),
                        definition.path.display()
                    ));
                }
                None => {
                    return Some(format!(
                        "the user manager has not read the definition kr wrote, {} ({name} is {})",
                        definition.path.display(),
                        self.load_state
                    ));
                }
            }
            if self.load_state != LOADED {
                return Some(format!(
                    "the user manager holds {name} as {}, not as the definition kr wrote loaded \
                     cleanly",
                    self.load_state
                ));
            }
            if self.need_reload {
                return Some(format!(
                    "the user manager has not read {} since it last changed",
                    definition.path.display()
                ));
            }
            if let Some(why) = &self.unread_drop_ins {
                return Some(format!(
                    "kr cannot read back which drop-ins the user manager reads for {name}: {why}"
                ));
            }
            let mut problems = Vec::new();
            let setters: Vec<String> = self
                .drop_ins
                .iter()
                .filter_map(|drop_in| match read_drop_in(drop_in) {
                    Ok(contents) => command_key(&contents)
                        .map(|key| format!("{} sets {key}", drop_in.display())),
                    Err(why) => Some(format!("kr cannot read {}: {why}", drop_in.display())),
                })
                .collect();
            if !setters.is_empty() {
                problems.push(format!(
                    "the command for {name} has to come from the definition kr wrote alone, and a \
                     drop-in may set it: {}",
                    setters.join(", ")
                ));
            }
            let written = printed(definition);
            let starts = self
                .commands
                .iter()
                .filter(|(property, _)| property == START)
                .count();
            let mut held: Vec<String> = self
                .commands
                .iter()
                .filter(|(property, command)| {
                    !(property == START && starts == 1 && command.starts_with(&written))
                })
                .map(|(property, command)| format!("{property}={command}"))
                .collect();
            if starts == 0 {
                held.push(format!("{START} with no command"));
            }
            if self.start_type != START_TYPE {
                held.push(format!("Type={}", self.start_type));
            }
            if !held.is_empty() {
                problems.push(format!(
                    "the user manager would not run {name} as kr wrote it: it holds {}, where kr \
                     wrote {START}={written}… and Type={START_TYPE}, and no other command",
                    held.join(", ")
                ));
            }
            (!problems.is_empty()).then(|| problems.join("; "))
        }

        /// The drop-ins the manager reads for the unit, for a person to look in.
        pub(super) fn reads(&self) -> String {
            if self.drop_ins.is_empty() {
                return "it reads no drop-in for it".to_owned();
            }
            let listed: Vec<String> = self
                .drop_ins
                .iter()
                .map(|drop_in| drop_in.display().to_string())
                .collect();
            format!("the drop-ins it reads for it are {}", listed.join(", "))
        }
    }

    /// A drop-in's text, read as the manager reads it and no further than [`READ_LIMIT`].
    fn read_drop_in(path: &std::path::Path) -> std::result::Result<String, String> {
        use std::io::Read as _;

        let mut bytes = Vec::new();
        std::fs::File::open(path)
            .and_then(|file| file.take(READ_LIMIT + 1).read_to_end(&mut bytes))
            .map_err(|error| error.to_string())?;
        if bytes.len() as u64 > READ_LIMIT {
            return Err(format!("it is larger than the {READ_LIMIT} bytes kr reads"));
        }
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }

    /// The key in a drop-in that could set the daemon's command or how it is started: a key that
    /// starts with `Exec`, or `Type`, compared without regard to case.
    ///
    /// Every line is read on its own, whatever section it is in and whether or not it continues
    /// the one before, and only comment lines and section headers are passed over. So the scan can
    /// refuse a drop-in the manager would read as harmless, and never passes one that sets either.
    pub(super) fn command_key(contents: &str) -> Option<String> {
        contents.lines().find_map(|line| {
            let line = line.trim_start();
            if line.starts_with(['#', ';', '[']) {
                return None;
            }
            let (key, _) = line.split_once('=')?;
            let key = key.trim();
            let lower = key.to_ascii_lowercase();
            (lower.starts_with("exec") || lower == "type").then(|| key.to_owned())
        })
    }

    /// How `systemctl show` begins printing the command a definition names, up to its flags: the
    /// program, the words joined by single spaces, and the flag the `:` prefix sets.
    pub(super) fn printed(definition: &Definition) -> String {
        format!(
            "{{ path={} ; argv[]={} ; flags={NO_ENVIRONMENT_EXPANSION} ; ",
            definition.program,
            definition.arguments.join(" ")
        )
    }

    /// The characters that make `systemctl show` quote a name it prints.
    const QUOTED_FOR: &str = " \t\n\r\"\\`$*?['()<>|&;!";

    /// The drop-in files a `DropInPaths` value lists.
    ///
    /// `systemctl show` separates the names with single spaces and prints each as a shell reads
    /// it: as it is when it holds no space and no character a shell treats specially, and
    /// otherwise in double quotes with `"`, `\`, `` ` `` and `$` escaped by a backslash. A control
    /// character is escaped another way, which is not read back: such a list is refused rather
    /// than guessed at.
    pub(super) fn drop_ins(printed: &str) -> std::result::Result<Vec<PathBuf>, String> {
        let unreadable = |why: &str| format!("{printed:?} {why}");
        let mut paths = Vec::new();
        let mut rest = printed;
        while !rest.is_empty() {
            if let Some(quoted) = rest.strip_prefix('"') {
                let mut path = String::new();
                let mut characters = quoted.char_indices();
                let end = loop {
                    match characters.next() {
                        Some((at, '"')) => break at + 1,
                        Some((_, '\\')) => match characters.next() {
                            Some((_, escaped @ ('"' | '\\' | '`' | '$'))) => path.push(escaped),
                            _ => {
                                return Err(unreadable(
                                    "escapes a character kr does not read back",
                                ));
                            }
                        },
                        Some((_, character)) if character.is_control() => {
                            return Err(unreadable("holds a control character"));
                        }
                        Some((_, character)) => path.push(character),
                        None => return Err(unreadable("ends inside a quoted name")),
                    }
                };
                paths.push(PathBuf::from(path));
                rest = &quoted[end..];
            } else {
                let end = rest.find(' ').unwrap_or(rest.len());
                let word = &rest[..end];
                if word.is_empty() {
                    return Err(unreadable("holds an empty name"));
                }
                if word
                    .chars()
                    .any(|character| character.is_control() || QUOTED_FOR.contains(character))
                {
                    return Err(unreadable("prints unquoted a name that needs quotes"));
                }
                paths.push(PathBuf::from(word));
                rest = &rest[end..];
            }
            match rest.strip_prefix(' ') {
                Some("") => return Err(unreadable("ends with a space")),
                Some(after) => rest = after,
                None if rest.is_empty() => {}
                None => return Err(unreadable("runs two names together")),
            }
        }
        Ok(paths)
    }

    fn unit(name: &str) -> std::result::Result<Unit, String> {
        let output = succeeded(&["show", name])?;
        Ok(Unit::read(&String::from_utf8_lossy(&output.stdout)))
    }

    /// Has the user manager read the definition just written, and checks that it would run it as
    /// kr wrote it. What it holds otherwise is named with the drop-ins it reads, and the definition
    /// stays written and recorded. Drop-ins it applies besides are named too.
    pub(super) fn take(definition: &Definition) -> Result<Vec<String>> {
        let failed = |why: String| CliError::HostUnavailable(why);
        succeeded(&["daemon-reload"]).map_err(failed)?;
        let found = unit(&definition.target()).map_err(failed)?;
        match found.difference(definition) {
            None if found.drop_ins.is_empty() => Ok(Vec::new()),
            None => Ok(vec![format!(
                "the user manager runs {} as kr wrote it, and applies what else these drop-ins set \
                 for it: {}",
                definition.target(),
                found
                    .drop_ins
                    .iter()
                    .map(|drop_in| drop_in.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            )]),
            Some(why) => Err(CliError::HostUnavailable(format!(
                "{why}; then run kr host startup --set service again. The definition is written \
                 and recorded, and kr host startup --clear removes it"
            ))),
        }
    }

    /// Checks, for a start request, that the user manager would run the checked definition as kr
    /// wrote it, and has read it since it last changed.
    pub(super) fn check(
        record: &Record,
        expected: &Definition,
    ) -> std::result::Result<(), Refusal> {
        let found = unit(&record.target()).map_err(Refusal::Failed)?;
        match found.difference(expected) {
            None => Ok(()),
            Some(why) => Err(Refusal::NotSetUp(format!("{why}; then {SETUP_ACTION}"))),
        }
    }

    /// What the user manager still holds of a definition kr is removing, told rather than changed:
    /// a running daemon keeps its unit until it stops.
    pub(super) fn release(record: &Record) -> Vec<String> {
        match unit(&record.target()) {
            Ok(Unit { pid: Some(pid), .. }) => vec![format!(
                "the daemon the user manager started (process {pid}) keeps serving, and the \
                 manager keeps its unit {} until that daemon stops",
                record.target()
            )],
            Ok(_) => Vec::new(),
            Err(why) => vec![format!(
                "the user manager could not be asked about {}: {why}",
                record.target()
            )],
        }
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

    /// Asks the user manager to start the unit the record names, with the environment's service
    /// lock held since the check.
    pub(super) fn start(
        record: &Record,
        _expected: &Definition,
    ) -> std::result::Result<Asked, Refusal> {
        let name = record.target();
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
        _arguments: Vec<String>,
        _working_directory: &str,
        _log: &str,
    ) -> Result<Definition> {
        Err(unsupported())
    }

    pub(super) fn take(_definition: &Definition) -> Result<Vec<String>> {
        Err(unsupported())
    }

    pub(super) fn check(
        _record: &Record,
        _expected: &Definition,
    ) -> std::result::Result<(), Refusal> {
        Err(Refusal::NotSetUp(unsupported().to_string()))
    }

    pub(super) fn release(_record: &Record) -> Vec<String> {
        Vec::new()
    }

    pub(super) fn forget(_record: &Record) -> Vec<String> {
        Vec::new()
    }

    pub(super) fn start(
        _record: &Record,
        _expected: &Definition,
    ) -> std::result::Result<Asked, Refusal> {
        Err(Refusal::NotSetUp(unsupported().to_string()))
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
            program: "/opt/kr/kr-controller".to_owned(),
            arguments: vec![
                "/opt/kr/kr-controller".to_owned(),
                "--state-dir".to_owned(),
                "/state".to_owned(),
            ],
            working_directory: "/state/dir".to_owned(),
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

        assert_eq!(state(&path, Some(&record), &written), State::Missing);
        assert_eq!(state(&path, None, &written), State::Missing);

        kr_ipc::paths::write_owner_only_file(&path, written.contents.as_bytes()).expect("writes");
        assert_eq!(state(&path, Some(&record), &written), State::Matches);
        assert_eq!(
            state(&path, None, &written),
            State::Unrecorded,
            "exactly what this installation writes, with no record of kr writing it"
        );
        let elsewhere = definition(&path, "another program's definition\n");
        assert_eq!(
            state(&path, Some(&record), &elsewhere),
            State::Outdated,
            "what kr wrote, unchanged, but not what this installation writes now"
        );

        kr_ipc::paths::write_owner_only_file(&path, b"the definition, edited\n").expect("edits");
        assert_eq!(state(&path, Some(&record), &written), State::Changed);
        assert_eq!(state(&path, None, &written), State::Foreign);

        kr_ipc::paths::write_owner_only_file(&path, written.contents.as_bytes()).expect("writes");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("widens");
        assert_eq!(
            state(&path, None, &written),
            State::Foreign,
            "kr writes a definition owner-only, so one others can write is not kr's"
        );
        assert_eq!(state(&path, Some(&record), &written), State::Changed);

        std::fs::remove_file(&path).expect("removes");
        std::os::unix::fs::symlink(host.root().join("elsewhere"), &path).expect("links");
        assert_eq!(
            state(&path, None, &written),
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
            State::Unrecorded,
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

    /// Setup, removal and a start request exclude one another: a second holder waits, and says who
    /// holds the lock when its wait runs out.
    #[test]
    fn one_command_at_a_time_holds_the_service_start() {
        let host = kr_ipc::testing::TempHost::create();
        let environment = host.environment();
        let held = Lock::take_within(&environment, Duration::ZERO).expect("the first takes it");
        let refused = Lock::take_within(&environment, Duration::from_millis(100))
            .expect_err("the second waits and gives up");
        assert!(refused.contains(LOCK_FILE), "{refused}");
        drop(held);
        Lock::take_within(&environment, Duration::ZERO).expect("free once the first lets go");
    }

    /// Only a regular file is moved aside for a check; it goes back where it was, and never over a
    /// file that took its place meanwhile.
    #[cfg(unix)]
    #[test]
    fn a_file_moved_aside_goes_back_only_where_nothing_took_its_place() {
        let host = kr_ipc::testing::TempHost::create();
        let path = host.root().join("kr-controller-test.plist");
        assert_eq!(
            move_aside(&path),
            Ok(Moved::Nothing),
            "nothing there to move"
        );

        std::os::unix::fs::symlink(host.root().join("elsewhere"), &path).expect("links");
        assert_eq!(
            move_aside(&path),
            Ok(Moved::NotRegular),
            "a link is not moved, and so is left exactly where it is"
        );
        std::fs::remove_file(&path).expect("removes the link");

        kr_ipc::paths::write_owner_only_file(&path, b"what kr wrote\n").expect("writes");
        let Ok(Moved::Aside(aside)) = move_aside(&path) else {
            panic!("the file is moved");
        };
        assert!(!path.exists() && moved_is(&aside, "what kr wrote\n"));
        assert!(!moved_is(&aside, "something else\n"));
        put_back(&aside, &path).expect("goes back");
        assert!(!aside.exists());
        assert_eq!(std::fs::read(&path).expect("back"), b"what kr wrote\n");

        let Ok(Moved::Aside(aside)) = move_aside(&path) else {
            panic!("the file is moved");
        };
        std::fs::write(&path, b"written meanwhile\n").expect("somebody writes there");
        let left = put_back(&aside, &path).expect_err("not over the new file");
        assert!(left.contains(&aside.display().to_string()), "{left}");
        assert_eq!(std::fs::read(&path).expect("kept"), b"written meanwhile\n");
        assert!(
            aside.exists(),
            "and the moved file is where the sentence says"
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
        let arguments = vec![
            "/opt/k&r/kr-controller".to_owned(),
            "--runtime-dir".to_owned(),
            "/tmp/<runtime>".to_owned(),
        ];
        let graphical = platform::render(
            "kr-controller-test",
            Some("gui/501".to_owned()),
            arguments.clone(),
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
        assert_eq!(graphical.program, "/opt/k&r/kr-controller");
        assert_eq!(graphical.arguments, arguments);
        let background = platform::render(
            "kr-controller-test",
            Some("user/501".to_owned()),
            arguments,
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

    /// What launchd holds is read from its own description: the definition's file, the program,
    /// every argument and the working directory, and a process when there is one.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_loaded_job_is_read_from_launchds_description() {
        let printed = "user/501/kr-controller-test = {\n\
                       \tactive count = 1\n\
                       \tpath = /Users/someone/Library/LaunchAgents/kr-controller-test.plist\n\
                       \tstate = running\n\
                       \n\
                       \tprogram = /opt/kr/kr-controller\n\
                       \targuments = {\n\
                       \t\t/opt/kr/kr-controller\n\
                       \t\t--state-dir\n\
                       \t\t/a b/c\n\
                       \t}\n\
                       \n\
                       \tworking directory = /state/dir\n\
                       \tdefault environment = {\n\
                       \t\tPATH => /usr/bin:/bin\n\
                       \t}\n\
                       \tpid = 4242\n\
                       \tendpoints = {\n\
                       \t\tstate = not running\n\
                       \t}\n\
                       }\n";
        let loaded = platform::Loaded::read(printed);
        assert_eq!(
            loaded,
            platform::Loaded::read(printed),
            "reading is deterministic"
        );
        let debug = format!("{loaded:?}");
        for expected in [
            "/Users/someone/Library/LaunchAgents/kr-controller-test.plist",
            "/opt/kr/kr-controller",
            "\"--state-dir\", \"/a b/c\"",
            "/state/dir",
            "4242",
        ] {
            assert!(debug.contains(expected), "{expected}: {debug}");
        }
        assert!(
            !debug.contains("PATH =>"),
            "nested sections are not arguments: {debug}"
        );
    }

    /// KR-REQ-07.12: a start request loads the definition where launchd holds nothing under its
    /// label, starts the job where launchd holds exactly the definition, and refuses anything else
    /// with its remedy. The check and the request both decide this way, each from what launchd
    /// holds when it asks.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_start_request_loads_starts_or_refuses_what_launchd_holds_when_it_asks() {
        let written = definition(
            Path::new("/Users/someone/Library/LaunchAgents/kr-controller-test.plist"),
            "the job\n",
        );
        let held = |path: &str, extra: &str| {
            platform::Job::Loaded(platform::Loaded::read(&format!(
                "gui/501/kr-controller-test = {{\n\
                 \tpath = {path}\n\
                 \tprogram = /opt/kr/kr-controller\n\
                 \targuments = {{\n\
                 \t\t/opt/kr/kr-controller\n\
                 \t\t--state-dir\n\
                 \t\t/state\n\
                 {extra}\
                 \t}}\n\
                 \n\
                 \tworking directory = /state/dir\n\
                 }}\n"
            )))
        };
        let path = written.path.display().to_string();
        assert_eq!(
            platform::next(&platform::Job::NotLoaded, &written).ok(),
            Some(platform::Next::Load)
        );
        assert_eq!(
            platform::next(&held(&path, ""), &written).ok(),
            Some(platform::Next::Start)
        );
        for (job, what) in [
            (
                held("/Users/someone/Library/LaunchAgents/other.plist", ""),
                "from another definition",
            ),
            (held(&path, "\t\t--worker\n"), "an earlier form"),
        ] {
            match platform::next(&job, &written) {
                Err(Refusal::NotSetUp(why)) => assert!(
                    why.contains(what)
                        && why.contains("launchctl bootout gui/501/kr-controller-test")
                        && why.contains(SETUP_ACTION),
                    "{what}: {why}"
                ),
                other => panic!("{what}: {other:?}"),
            }
        }
    }

    /// KR-REQ-07.12: a systemd user unit runs the daemon with this installation's roots, in the
    /// environment's own directory, only when started, with every word taken exactly as it is,
    /// a dollar sign in the program's own path included.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_user_unit_is_started_only_when_asked_and_takes_every_word_as_it_is() {
        let arguments = vec![
            "/opt/k r$HOME/kr-controller".to_owned(),
            "--state-dir".to_owned(),
            "/tmp/100%/$HOME/\"q\"\\".to_owned(),
        ];
        let unit = platform::render(
            "kr-controller-test",
            None,
            arguments.clone(),
            "/state/50%",
            "/state/50%/controller.log",
        )
        .expect("renders");
        let contents = &unit.contents;
        for expected in [
            "Type=exec\n",
            "ExecStart=\":/opt/k r$HOME/kr-controller\" \"--state-dir\" \"/tmp/100%%/$HOME/\\\"q\\\"\\\\\"\n",
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
        assert_eq!(unit.program, "/opt/k r$HOME/kr-controller");
        assert_eq!(unit.arguments, arguments);
    }

    /// The user manager runs the definition as kr wrote it when it loads the unit cleanly from
    /// kr's file, has read it since it changed, starts it as the file says and prints one command
    /// for it, the file's, program, words and flags as kr wrote them. Anything else is a
    /// difference, and every difference names the drop-ins the manager reads.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_user_unit_differs_when_the_manager_would_run_anything_but_the_definition() {
        let written = Definition {
            manager: Manager::Systemd,
            domain: None,
            label: "kr-controller-test".to_owned(),
            ..definition(
                Path::new("/home/some one/.config/systemd/user/kr-controller-test.service"),
                "the unit\n",
            )
        };
        let path = written.path.display().to_string();
        let exact = format!(
            "{}start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }}",
            platform::printed(&written)
        );
        assert_eq!(
            platform::printed(&written),
            "{ path=/opt/kr/kr-controller ; argv[]=/opt/kr/kr-controller --state-dir /state ; \
             flags=no-env-expand ; "
        );
        let shown = |fragment: &str, drop_ins: &str, commands: &[(&str, &str)], extra: &str| {
            let mut printed = format!(
                "Type=exec\nMainPID=0\nLoadState=loaded\nFragmentPath={fragment}\n\
                 NeedDaemonReload=no\n{extra}"
            );
            if !drop_ins.is_empty() {
                printed.push_str(&format!("DropInPaths={drop_ins}\n"));
            }
            for (property, command) in commands {
                printed.push_str(&format!("{property}={command}\n"));
            }
            platform::Unit::read(&printed)
        };
        let only = [
            ("ExecStart", exact.as_str()),
            ("ExecStartEx", exact.as_str()),
        ];
        let unflagged = exact.replace("flags=no-env-expand", "flags=");

        assert_eq!(shown(&path, "", &only, "").difference(&written), None);

        // Drop-ins on disk, one of them under a directory with a space in its name, as
        // `systemctl show` quotes such a name.
        let host = kr_ipc::testing::TempHost::create();
        let drop_in = |directory: &str, name: &str, contents: &str| {
            let at = host.root().join(directory).join(name);
            std::fs::create_dir_all(at.parent().expect("a directory")).expect("a directory");
            std::fs::write(&at, contents).expect("a drop-in");
            let text = at.display().to_string();
            if text.contains(' ') {
                format!("\"{text}\"")
            } else {
                text
            }
        };
        let kept = [
            drop_in(
                "some one/kr-controller-test.service.d",
                "limits.conf",
                "[Service]\nEnvironment=KR_TEST=1\nLimitNOFILE=4096\n",
            ),
            drop_in(
                "service.d",
                "10-timeout-abort.conf",
                "[Service]\nTimeoutStopFailureMode=abort\n",
            ),
            drop_in(
                "service.d",
                "20-commented.conf",
                "[Service]\n# ExecStart=/bin/true\n  ; Type=notify\n",
            ),
        ];
        assert_eq!(
            shown(&path, &kept.join(" "), &only, "").difference(&written),
            None,
            "drop-ins that leave the command alone are the host's and the person's"
        );
        for (name, contents, key) in [
            (
                "resplit.conf",
                "[Service]\nExecStart=\nExecStart=\":/opt/kr/kr-controller\" \"--state-dir /state\"\n",
                "sets ExecStart",
            ),
            ("type.conf", "[Service]\n  type = notify\n", "sets type"),
            (
                "continued.conf",
                "[Service]\nEnvironment=A=1 \\\nExecStartPre=/bin/true\n",
                "sets ExecStartPre",
            ),
            (
                "unit.conf",
                "[Unit]\nExecCondition=/bin/true\n",
                "sets ExecCondition",
            ),
        ] {
            let listed = drop_in("kr-controller-test.service.d", name, contents);
            let why = shown(&path, &listed, &only, "")
                .difference(&written)
                .expect("refused, though the command prints as kr wrote it");
            assert!(
                why.contains(&format!("{name} {key}")) && why.contains("drop-ins it reads"),
                "{name}: {why}"
            );
        }
        let why = shown(&path, "/nowhere/gone.conf", &only, "")
            .difference(&written)
            .expect("a drop-in kr cannot read is refused");
        assert!(why.contains("kr cannot read /nowhere/gone.conf"), "{why}");
        let other = "{ path=/bin/true ; argv[]=/bin/true ; flags= ; start_time=[n/a] ; \
                     stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }";
        for (unit, what) in [
            (
                shown(
                    "/etc/systemd/user/kr-controller-test.service",
                    "",
                    &only,
                    "",
                ),
                "loads kr-controller-test.service from /etc",
            ),
            (
                shown(&path, "", &[("ExecStartEx", other)], ""),
                "it holds ExecStartEx={ path=/bin/true",
            ),
            (
                shown(&path, "", &[("ExecStartEx", unflagged.as_str())], ""),
                "flags= ;",
            ),
            (
                shown(
                    &path,
                    "",
                    &[("ExecStartEx", exact.as_str()), ("ExecStartPreEx", other)],
                    "",
                ),
                "ExecStartPreEx={ path=/bin/true",
            ),
            (
                shown(
                    &path,
                    "",
                    &[
                        ("ExecStartEx", exact.as_str()),
                        ("ExecStartEx", exact.as_str()),
                    ],
                    "",
                ),
                "it holds ExecStartEx=",
            ),
            (
                shown(
                    &path,
                    "",
                    &[("ExecReloadPostEx", other), ("ExecStartEx", exact.as_str())],
                    "",
                ),
                "ExecReloadPostEx=",
            ),
            (shown(&path, "", &[], ""), "ExecStartEx with no command"),
            (shown(&path, "", &only, "Type=notify\n"), "Type=notify"),
            (
                shown(&path, "", &only, "LoadState=bad-setting\n"),
                "holds kr-controller-test.service as bad-setting",
            ),
            (
                shown(&path, "", &only, "NeedDaemonReload=yes\n"),
                "since it last changed",
            ),
            (
                shown(&path, "\"/a b\\q.conf\"", &only, ""),
                "cannot read back which drop-ins",
            ),
            (
                shown(&path, "\"/a b\\q.conf\"", &only, "NeedDaemonReload=yes\n"),
                "escapes a character kr does not read back",
            ),
        ] {
            let why = unit.difference(&written).expect("a difference");
            assert!(why.contains(what), "{what}: {why}");
            assert!(
                why.contains("drop-in"),
                "every difference names the drop-ins the manager reads: {why}"
            );
        }
        let why = shown(
            "/etc/systemd/user/kr-controller-test.service",
            "/x/y.service.d/a.conf",
            &only,
            "",
        )
        .difference(&written)
        .expect("a difference");
        assert!(
            why.contains("the drop-ins it reads for it are /x/y.service.d/a.conf"),
            "{why}"
        );
        assert!(
            platform::Unit::read("LoadState=not-found\nFragmentPath=\n")
                .difference(&written)
                .expect("not read")
                .contains("has not read the definition")
        );
    }

    /// A drop-in is scanned line by line for a key that could set the daemon's command or its
    /// start type, and anything that could be such a key is taken for one.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_drop_in_that_could_set_the_command_is_found_line_by_line() {
        for (contents, key) in [
            ("[Service]\nExecStart=/bin/true\n", Some("ExecStart")),
            (
                "[Service]\n  ExecStopPost = /bin/true\n",
                Some("ExecStopPost"),
            ),
            ("[Service]\nexecstart=/bin/true\n", Some("execstart")),
            (
                "[Service]\nExecReloadPost=/bin/true\n",
                Some("ExecReloadPost"),
            ),
            ("[Service]\nType=notify\n", Some("Type")),
            ("[Unit]\nExecCondition=/bin/true\n", Some("ExecCondition")),
            (
                "[Service]\nEnvironment=A=1 \\\nExecStart=x\n",
                Some("ExecStart"),
            ),
            (
                "[Service]\nExecStart\\\n=\nExecStart\\\n=/opt/kr/kr-controller\n",
                Some("ExecStart"),
            ),
            (
                "[Service]\r\nExecStart\\\r\n=/bin/true\r\n",
                Some("ExecStart"),
            ),
            ("[Service]\rExecStart=/bin/true\r", Some("ExecStart")),
            ("[Service]\0ExecStart=/bin/true\0", Some("ExecStart")),
            ("\u{feff}ExecStart=/bin/true\n", Some("ExecStart")),
            (
                "[Service]\nEnvironment=A=1 \\\n# a note\nExecStart=/bin/true\n",
                Some("ExecStart"),
            ),
            ("[Service]\nExec\\\nStart=/bin/true\n", Some("Exec Start")),
            ("[Service]\nEnvironment=ExecStart=x\nTimeoutSec=5\n", None),
            ("[Service]\n# ExecStart=x\n; Type=notify\n", None),
            ("[Service]\nTimeoutStopFailureMode=abort\n", None),
            ("", None),
        ] {
            assert_eq!(
                platform::command_key(contents).as_deref(),
                key,
                "{contents:?}"
            );
        }
    }

    /// A `DropInPaths` value is read back name for name: as printed where a name needs no quotes,
    /// with its escapes undone where it is quoted, and refused where it is printed another way.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_list_of_drop_ins_is_read_back_exactly_or_refused() {
        assert_eq!(platform::drop_ins(""), Ok(Vec::new()));
        assert_eq!(
            platform::drop_ins(
                "/usr/lib/systemd/user/service.d/10-timeout-abort.conf \
                 \"/home/some one/x.service.d/a \\\"b\\\" \\\\ \\$c \\`d.conf\" /e/f.conf"
            ),
            Ok(vec![
                PathBuf::from("/usr/lib/systemd/user/service.d/10-timeout-abort.conf"),
                PathBuf::from("/home/some one/x.service.d/a \"b\" \\ $c `d.conf"),
                PathBuf::from("/e/f.conf"),
            ])
        );
        for refused in [
            "\"/a\\nb.conf\"",
            "\"/a b.conf",
            "\"/a b.conf\"/c.conf",
            "/a.conf ",
            "/a;b.conf",
            "/a  /b.conf",
        ] {
            assert!(
                platform::drop_ins(refused).is_err(),
                "{refused:?} is refused rather than guessed at"
            );
        }
    }
}
