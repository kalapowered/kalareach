//! The Windows supervisor's scheduled task.
//!
//! On Windows a worker is created by a starter the Task Scheduler runs, never by the daemon, so it
//! is never in a job the daemon runs in, however those jobs are nested ([`kr_ipc::starter`]). This
//! module holds the task that starter belongs to: the one definition this build registers for an
//! environment, what a registered task is read back as, whether it is this environment's own and
//! whether it is still the one this build expects, and the calls that register, remove and run it.
//!
//! # The task
//!
//! One task per environment, `KalaReach-<prefix>` in the root folder, with no trigger: it runs only
//! when it is asked to. Its principal is the user's own account and its description carries the
//! environment's full identity, and the two together say whose task it is. It runs
//! `kr-controller --starter --runtime-dir <root> --state-dir <root>` in the environment's state
//! directory; at normal priority, because the Task Scheduler's default is below normal and every
//! process a starter creates would inherit it; with its instances in parallel, so two launches
//! handed over at once run two starters; and with no time limit. Nothing in it is secret, and
//! nothing in it belongs to one launch.
//!
//! The setup step always registers it to log on as the user in a session where the user is signed
//! in ([`LogonType::InteractiveToken`]): the starter, and everything it starts, then end with that
//! session's sign-out, and the user's own credential store is there. A machine nobody is signed in
//! to has no such session, and a test host registers [`LogonType::S4U`] through the same definition.
//!
//! The definition and the reading of a registered one are text, and are checked on every platform.
//! Registering, reading back from the Task Scheduler, removing and running need Windows.

use std::path::{Path, PathBuf};

use kr_ipc::paths::EnvironmentPaths;
use kr_protocol::ids::EnvironmentId;

/// How the environment's task logs on to run its starter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogonType {
    /// As the user, in a session where the user is signed in: what the setup step registers.
    InteractiveToken,
    /// As the user with no session of its own, in session 0: for a host nobody is signed in to.
    S4U,
}

impl LogonType {
    /// The Task Scheduler's own name for it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InteractiveToken => "InteractiveToken",
            Self::S4U => "S4U",
        }
    }

    /// Reads the Task Scheduler's name for a logon type this host registers.
    fn parse(text: &str) -> Option<Self> {
        match text {
            "InteractiveToken" => Some(Self::InteractiveToken),
            "S4U" => Some(Self::S4U),
            _ => None,
        }
    }
}

/// Returns the name of the task that starts things for `environment_id`.
#[must_use]
pub fn task_name(environment_id: EnvironmentId) -> String {
    format!("KalaReach-{}", kr_ipc::paths::short_prefix(environment_id))
}

/// What a task's description says before the environment's identity.
const DESCRIPTION_PREFIX: &str = "KalaReach environment ";

/// The file in an environment's state directory that the daemon a starter starts writes to: the
/// log every start of the daemon writes to.
pub const DAEMON_LOG: &str = "controller.log";

/// The task this build registers for one environment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaskDefinition {
    /// The task's name.
    pub name: String,
    /// The account it runs as, as a security identifier's text.
    pub user: String,
    /// The environment it starts things for.
    pub environment_id: EnvironmentId,
    /// How it logs on.
    pub logon: LogonType,
    /// The starter it runs: this installation's `kr-controller`.
    pub starter: PathBuf,
    /// The command line it gives the starter, quoted as a Windows program reads it.
    pub arguments: String,
    /// The directory the starter runs in: the environment's state directory.
    pub working_directory: PathBuf,
}

impl TaskDefinition {
    /// The definition for `environment`, running `starter` as `user` and logging on as `logon`.
    ///
    /// The starter is told the two roots rather than the environment's own directories, as a
    /// worker is: it derives the environment from them, and applying the prefix twice would name a
    /// directory that does not exist.
    #[must_use]
    pub fn new(
        user: impl Into<String>,
        environment: &EnvironmentPaths,
        starter: &Path,
        logon: LogonType,
    ) -> Self {
        let arguments = kr_worker::pty::command_line(&[
            "--starter".into(),
            "--runtime-dir".into(),
            environment.runtime_root().as_os_str().to_owned(),
            "--state-dir".into(),
            environment.state_root().as_os_str().to_owned(),
        ]);
        Self {
            name: task_name(environment.environment_id()),
            user: user.into(),
            environment_id: environment.environment_id(),
            logon,
            starter: starter.to_path_buf(),
            arguments,
            working_directory: environment.state_dir().to_path_buf(),
        }
    }

    /// The definition the setup step registers, which always logs on as the user in a session
    /// where the user is signed in.
    #[must_use]
    pub fn for_setup(
        user: impl Into<String>,
        environment: &EnvironmentPaths,
        starter: &Path,
    ) -> Self {
        Self::new(user, environment, starter, LogonType::InteractiveToken)
    }

    /// The task's description, which carries the environment's full identity.
    #[must_use]
    pub fn description(&self) -> String {
        format!("{DESCRIPTION_PREFIX}{}", self.environment_id)
    }

    /// The definition in the Task Scheduler's XML.
    #[must_use]
    pub fn xml(&self) -> String {
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-16\"?>\r\n\
             <Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\r\n\
             <RegistrationInfo><Description>{description}</Description></RegistrationInfo>\r\n\
             <Triggers />\r\n\
             <Principals><Principal id=\"Author\"><UserId>{user}</UserId>\
             <LogonType>{logon}</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>\r\n\
             <Settings><MultipleInstancesPolicy>Parallel</MultipleInstancesPolicy>\
             <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>\
             <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>\
             <AllowHardTerminate>true</AllowHardTerminate><StartWhenAvailable>false</StartWhenAvailable>\
             <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>\
             <IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings>\
             <AllowStartOnDemand>true</AllowStartOnDemand><Enabled>true</Enabled><Hidden>false</Hidden>\
             <RunOnlyIfIdle>false</RunOnlyIfIdle><WakeToRun>false</WakeToRun>\
             <ExecutionTimeLimit>PT0S</ExecutionTimeLimit><Priority>5</Priority></Settings>\r\n\
             <Actions Context=\"Author\"><Exec><Command>{command}</Command>\
             <Arguments>{arguments}</Arguments><WorkingDirectory>{directory}</WorkingDirectory></Exec></Actions>\r\n\
             </Task>\r\n",
            description = escape(&self.description()),
            user = escape(&self.user),
            logon = self.logon.as_str(),
            command = escape(&self.starter.display().to_string()),
            arguments = escape(&self.arguments),
            directory = escape(&self.working_directory.display().to_string()),
        )
    }
}

/// A task as the Task Scheduler exports it: the fields this host reads, as they were written.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RegisteredTask {
    /// The principal's account, as an identifier or a name.
    pub user: String,
    /// How it logs on, when it is a way this host registers.
    pub logon: Option<LogonType>,
    /// Its description.
    pub description: String,
    /// The program its one action runs.
    pub command: String,
    /// What that action is given.
    pub arguments: String,
    /// The directory that action runs in.
    pub working_directory: String,
    /// What a second run does while one is running.
    pub multiple_instances: String,
    /// How long a run may last.
    pub execution_time_limit: String,
    /// The priority its process runs at.
    pub priority: String,
    /// Whether it is enabled; absent is the default, enabled.
    pub enabled: bool,
    /// The privileges it runs with, as written; absent is the default, `LeastPrivilege`.
    pub run_level: String,
    /// Whether a run may not start on batteries; absent is the default, true.
    pub disallow_start_on_batteries: bool,
    /// Whether a run stops when the machine goes on batteries; absent is the default, true.
    pub stop_going_on_batteries: bool,
    /// Whether a run waits for the machine to be idle; absent is the default, false.
    pub run_only_if_idle: bool,
    /// Whether a run stops when the machine stops being idle; absent is the default, true.
    pub stop_on_idle_end: bool,
    /// Whether a run waits for a network; absent is the default, false.
    pub run_only_if_network: bool,
    /// Whether it may be run when asked; absent is the default, true.
    pub start_on_demand: bool,
    /// How many actions it has.
    pub actions: usize,
    /// Whether it has a trigger, which would run it without its being asked.
    pub triggered: bool,
}

impl RegisteredTask {
    /// Reads a task's exported XML.
    ///
    /// Only the fields this host decides on are read, each within the part of the definition it
    /// belongs to, so a trigger's own `Enabled` is never read as the task's. A setting the export
    /// leaves out is read as the Task Scheduler's documented default for it.
    #[must_use]
    pub fn parse(xml: &str) -> Self {
        let principals = element(xml, "Principals").unwrap_or_default();
        let settings = element(xml, "Settings").unwrap_or_default();
        let idle = element(settings, "IdleSettings").unwrap_or_default();
        let actions = element(xml, "Actions").unwrap_or_default();
        Self {
            user: text(principals, "UserId"),
            logon: element(principals, "LogonType")
                .and_then(|value| LogonType::parse(value.trim())),
            description: text(
                element(xml, "RegistrationInfo").unwrap_or_default(),
                "Description",
            ),
            command: text(actions, "Command"),
            arguments: text(actions, "Arguments"),
            working_directory: text(actions, "WorkingDirectory"),
            multiple_instances: text(settings, "MultipleInstancesPolicy"),
            execution_time_limit: text(settings, "ExecutionTimeLimit"),
            priority: text(settings, "Priority"),
            enabled: flag(settings, "Enabled", true),
            run_level: text(principals, "RunLevel"),
            disallow_start_on_batteries: flag(settings, "DisallowStartIfOnBatteries", true),
            stop_going_on_batteries: flag(settings, "StopIfGoingOnBatteries", true),
            run_only_if_idle: flag(settings, "RunOnlyIfIdle", false),
            stop_on_idle_end: flag(idle, "StopOnIdleEnd", true),
            run_only_if_network: flag(settings, "RunOnlyIfNetworkAvailable", false),
            start_on_demand: flag(settings, "AllowStartOnDemand", true),
            actions: ["Exec", "ComHandler", "SendEmail", "ShowMessage"]
                .into_iter()
                .map(|action| count(actions, action))
                .sum(),
            triggered: element(xml, "Triggers").is_some_and(|triggers| triggers.contains('<')),
        }
    }

    /// Whether this is `expected`'s environment's task: the account it runs as is `expected`'s,
    /// and its description carries that environment's full identity.
    ///
    /// `sid_of` resolves an account's name to its identifier, for an export that names the
    /// account rather than giving its identifier.
    #[must_use]
    pub fn belongs_to(
        &self,
        expected: &TaskDefinition,
        sid_of: impl Fn(&str) -> Option<String>,
    ) -> bool {
        self.whose(expected, sid_of).is_none()
    }

    /// Why this is not `expected`'s environment's task, or `None` when it is: another account's
    /// task, or this account's task for another environment.
    ///
    /// `sid_of` resolves an account's name to its identifier, for an export that names the
    /// account rather than giving its identifier.
    #[must_use]
    pub fn whose(
        &self,
        expected: &TaskDefinition,
        sid_of: impl Fn(&str) -> Option<String>,
    ) -> Option<ForeignReason> {
        let user = self.user.trim();
        let same_user = if user.starts_with("S-1-") {
            user.eq_ignore_ascii_case(&expected.user)
        } else {
            sid_of(user).is_some_and(|sid| sid.eq_ignore_ascii_case(&expected.user))
        };
        if !same_user {
            return Some(ForeignReason::Account {
                user: user.to_owned(),
                description: self.description.trim().to_owned(),
            });
        }
        (self.description.trim() != expected.description()).then(|| ForeignReason::Environment {
            description: self.description.trim().to_owned(),
        })
    }

    /// What makes this task something other than the one `expected` registers, if anything: its
    /// program, what it gives it, the directory, the settings a starter depends on, a trigger, or
    /// a logon this host does not register. Empty when it is the task this build expects.
    #[must_use]
    pub fn differences(&self, expected: &TaskDefinition) -> Vec<Difference> {
        let mut differences = Vec::new();
        if !same_path(&self.command, &expected.starter) {
            differences.push(Difference::Program {
                found: self.command.clone(),
                expected: expected.starter.clone(),
            });
        }
        if self.arguments.trim() != expected.arguments {
            differences.push(Difference::Arguments {
                found: self.arguments.clone(),
                expected: expected.arguments.clone(),
            });
        }
        if !same_path(&self.working_directory, &expected.working_directory) {
            differences.push(Difference::WorkingDirectory {
                found: self.working_directory.clone(),
                expected: expected.working_directory.clone(),
            });
        }
        if self.actions != 1 {
            differences.push(Difference::Actions(self.actions));
        }
        if self.triggered {
            differences.push(Difference::Triggered);
        }
        if self.logon != Some(expected.logon) {
            differences.push(Difference::Logon {
                found: self.logon,
                expected: expected.logon,
            });
        }
        let run_level = self.run_level.trim();
        if !run_level.is_empty() && run_level != "LeastPrivilege" {
            differences.push(Difference::RunLevel(run_level.to_owned()));
        }
        for (differs, difference) in [
            (self.disallow_start_on_batteries, Difference::NotOnBatteries),
            (self.stop_going_on_batteries, Difference::StopsOnBatteries),
            (self.run_only_if_idle, Difference::WaitsForIdle),
            (self.stop_on_idle_end, Difference::StopsWhenBusy),
            (self.run_only_if_network, Difference::WaitsForNetwork),
            (!self.start_on_demand, Difference::NotOnDemand),
        ] {
            if differs {
                differences.push(difference);
            }
        }
        if self.multiple_instances.trim() != "Parallel" {
            differences.push(Difference::NotParallel(self.multiple_instances.clone()));
        }
        if self.execution_time_limit.trim() != "PT0S" {
            differences.push(Difference::TimeLimited(self.execution_time_limit.clone()));
        }
        if self.priority.trim() != "5" {
            differences.push(Difference::Priority(self.priority.clone()));
        }
        if !self.enabled {
            differences.push(Difference::Disabled);
        }
        differences
    }
}

/// One way a registered task differs from the one this build registers.
///
/// What was read from the task is kept for the daemon's own record of a refused launch, which
/// says it. A command that tells a person about it says only which of these it is, in its own
/// words, and never what the task holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Difference {
    /// It runs another program than this installation's starter.
    Program {
        /// The program it runs, as it was read.
        found: String,
        /// This installation's starter.
        expected: PathBuf,
    },
    /// It gives the starter other arguments.
    Arguments {
        /// What it gives, as it was read.
        found: String,
        /// What this build gives.
        expected: String,
    },
    /// It runs in another directory than the environment's state directory.
    WorkingDirectory {
        /// Its directory, as it was read.
        found: String,
        /// The environment's state directory.
        expected: PathBuf,
    },
    /// It has other than one action.
    Actions(usize),
    /// It has a trigger, so it runs without being asked.
    Triggered,
    /// It logs on another way than the one expected.
    Logon {
        /// How it logs on, when it is a way this host registers.
        found: Option<LogonType>,
        /// How the expected task logs on.
        expected: LogonType,
    },
    /// It runs with more than the least privilege; the level, as it was read.
    RunLevel(String),
    /// It does not start on batteries.
    NotOnBatteries,
    /// It stops when the machine goes on batteries.
    StopsOnBatteries,
    /// It waits for the machine to be idle.
    WaitsForIdle,
    /// It stops when the machine stops being idle.
    StopsWhenBusy,
    /// It waits for a network.
    WaitsForNetwork,
    /// It may not be run when asked.
    NotOnDemand,
    /// A second run while one is running is not in parallel; the policy, as it was read.
    NotParallel(String),
    /// Its runs are limited in time; the limit, as it was read.
    TimeLimited(String),
    /// It runs at another priority than the normal 5; the priority, as it was read.
    Priority(String),
    /// It is disabled.
    Disabled,
}

impl std::fmt::Display for Difference {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Program { found, expected } => {
                write!(formatter, "it runs {found}, not {}", expected.display())
            }
            Self::Arguments { found, expected } => {
                write!(
                    formatter,
                    "it gives the starter {found:?}, not {expected:?}"
                )
            }
            Self::WorkingDirectory { found, expected } => {
                write!(formatter, "it runs in {found}, not {}", expected.display())
            }
            Self::Actions(count) => write!(formatter, "it has {count} actions, not one"),
            Self::Triggered => {
                formatter.write_str("it has a trigger, so it runs without being asked")
            }
            Self::Logon { found, expected } => write!(
                formatter,
                "it logs on as {}, not {}",
                found.map_or("something this host does not register", LogonType::as_str),
                expected.as_str()
            ),
            Self::RunLevel(level) => {
                write!(
                    formatter,
                    "it runs at {level}, not with the least privilege"
                )
            }
            Self::NotOnBatteries => formatter.write_str("it does not start on batteries"),
            Self::StopsOnBatteries => {
                formatter.write_str("it stops when the machine goes on batteries")
            }
            Self::WaitsForIdle => formatter.write_str("it waits for the machine to be idle"),
            Self::StopsWhenBusy => {
                formatter.write_str("it stops when the machine stops being idle")
            }
            Self::WaitsForNetwork => formatter.write_str("it waits for a network"),
            Self::NotOnDemand => formatter.write_str("it may not be run when asked"),
            Self::NotParallel(policy) => write!(
                formatter,
                "a second run while one is running is {policy:?}, not in parallel"
            ),
            Self::TimeLimited(limit) => write!(formatter, "its runs are limited to {limit:?}"),
            Self::Priority(priority) => {
                write!(
                    formatter,
                    "it runs at priority {priority:?}, not the normal 5"
                )
            }
            Self::Disabled => formatter.write_str("it is disabled"),
        }
    }
}

/// Why a task under an environment's name is not that environment's own.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ForeignReason {
    /// This user cannot read it, so whose it is cannot be established; what the Task Scheduler
    /// said.
    Unreadable {
        /// The Task Scheduler's own words.
        said: String,
    },
    /// It runs as another account.
    Account {
        /// The account, as the export names it.
        user: String,
        /// Its description, as it was read.
        description: String,
    },
    /// It runs as this user and belongs to another environment.
    Environment {
        /// Its description, as it was read.
        description: String,
    },
}

/// A task under an environment's name that is not that environment's own. It is never replaced
/// or removed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Foreign {
    /// The task's name.
    pub name: String,
    /// The environment the name was looked at for.
    pub environment_id: EnvironmentId,
    /// Why it is not that environment's.
    pub reason: ForeignReason,
}

impl std::fmt::Display for Foreign {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.reason {
            ForeignReason::Unreadable { said } => write!(
                formatter,
                "a task named {} is registered and this user cannot read it ({said})",
                self.name
            ),
            ForeignReason::Account { user, description } => write!(
                formatter,
                "a task named {} is registered for {user} with the description {description:?}, \
                 which is not this user's task for environment {}",
                self.name, self.environment_id
            ),
            ForeignReason::Environment { description } => write!(
                formatter,
                "a task named {} is registered for this user with the description \
                 {description:?}, which is not the task of environment {}",
                self.name, self.environment_id
            ),
        }
    }
}

/// Whether two Windows paths name the same place.
///
/// Case and the separator do not matter there, and neither does the verbatim prefix a resolved
/// path carries. Where both name something that is there, they are also compared as the file
/// system resolves them, so a short name and its long form are the same place.
fn same_path(written: &str, expected: &Path) -> bool {
    let normal = |path: &Path| {
        without_verbatim_prefix(path.to_path_buf())
            .display()
            .to_string()
            .trim()
            .replace('/', "\\")
            .to_lowercase()
    };
    let written = Path::new(written.trim());
    if normal(written) == normal(expected) {
        return true;
    }
    match (
        std::fs::canonicalize(written),
        std::fs::canonicalize(expected),
    ) {
        (Ok(one), Ok(other)) => normal(&one) == normal(&other),
        _ => false,
    }
}

/// A path without the verbatim prefix, `\\?\`, a path resolved on Windows carries: the same place,
/// named as a person and the Task Scheduler name it. Any other path is returned as it is.
#[must_use]
pub fn without_verbatim_prefix(path: PathBuf) -> PathBuf {
    let named = {
        let text = path.as_os_str().to_string_lossy();
        if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
            Some(PathBuf::from(format!(r"\\{rest}")))
        } else {
            text.strip_prefix(r"\\?\")
                .filter(|rest| rest.as_bytes().get(1) == Some(&b':'))
                .map(PathBuf::from)
        }
    };
    named.unwrap_or(path)
}

/// Escapes text for an XML element.
fn escape(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&apos;"),
            other => escaped.push(other),
        }
    }
    escaped
}

/// Reads a boolean element, or `default` when it is absent or not a boolean.
fn flag(xml: &str, name: &str, default: bool) -> bool {
    match element(xml, name).map(str::trim) {
        Some("true") => true,
        Some("false") => false,
        _ => default,
    }
}

/// Reads the text of the first element named `name`, with its entities resolved, or empty.
fn text(xml: &str, name: &str) -> String {
    element(xml, name).map(unescape).unwrap_or_default()
}

/// Returns what the first element named `name` holds, as written, or `None` when there is none.
///
/// An element written empty, `<Name />`, holds nothing. A name is matched whole: `<Exec>` is not
/// found inside `<ExecutionTimeLimit>`.
fn element<'a>(xml: &'a str, name: &str) -> Option<&'a str> {
    let mut from = 0;
    while let Some(at) = xml[from..].find(&format!("<{name}")) {
        let start = from + at + 1 + name.len();
        let rest = &xml[start..];
        match rest.chars().next() {
            Some('>') => {
                let body = &rest[1..];
                let end = body.find(&format!("</{name}>"))?;
                return Some(&body[..end]);
            }
            Some(' ' | '\t' | '\r' | '\n' | '/') => {
                let close = rest.find('>')?;
                if rest[..close].ends_with('/') {
                    return Some("");
                }
                let body = &rest[close + 1..];
                let end = body.find(&format!("</{name}>"))?;
                return Some(&body[..end]);
            }
            _ => from = start,
        }
    }
    None
}

/// Counts the elements named `name` in `xml`, matched whole.
fn count(xml: &str, name: &str) -> usize {
    xml.match_indices(&format!("<{name}"))
        .filter(|(at, _)| {
            xml[at + 1 + name.len()..]
                .chars()
                .next()
                .is_some_and(|next| matches!(next, '>' | ' ' | '/' | '\t' | '\r' | '\n'))
        })
        .count()
}

/// Resolves the five entities XML predefines and numeric character references.
fn unescape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find('&') {
        out.push_str(&rest[..at]);
        let tail = &rest[at..];
        let Some(end) = tail.find(';') else {
            out.push_str(tail);
            return out;
        };
        let entity = &tail[1..end];
        let resolved = match entity {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            _ => entity
                .strip_prefix("#x")
                .and_then(|hex| u32::from_str_radix(hex, 16).ok())
                .or_else(|| {
                    entity
                        .strip_prefix('#')
                        .and_then(|decimal| decimal.parse().ok())
                })
                .and_then(char::from_u32),
        };
        match resolved {
            Some(character) => out.push(character),
            None => out.push_str(&tail[..=end]),
        }
        rest = &tail[end + 1..];
    }
    out.push_str(rest);
    out
}

/// Reads what a Task Scheduler command printed, in whichever encoding it used.
///
/// An export is UTF-16 when it is written as the file it describes and may be the console's code
/// page when it is printed, so both are read: UTF-16 by its byte-order mark or by the zero byte
/// every character of an XML declaration has in its second half, anything else as UTF-8.
#[must_use]
pub fn decode_output(bytes: &[u8]) -> String {
    let utf16 = bytes.starts_with(&[0xff, 0xfe]) || (bytes.len() >= 2 && bytes[1] == 0);
    if utf16 {
        let body = bytes.strip_prefix(&[0xff, 0xfe]).unwrap_or(bytes);
        let units: Vec<u16> = body
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        return String::from_utf16_lossy(&units);
    }
    let body = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(bytes);
    String::from_utf8_lossy(body).into_owned()
}

/// Where an environment's task stands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Standing {
    /// No task has the environment's name.
    Absent,
    /// A task has the name and is not this environment's: another account's, or another
    /// environment's whose identity shares the prefix. It is never replaced or removed.
    Foreign(Foreign),
    /// The environment's own task, with what makes it other than the one this build registers:
    /// empty when it is exactly that one.
    Owned(Vec<Difference>),
}

/// What a change to an environment's task did, so the change can be undone.
///
/// The prior task is kept as the Task Scheduler exported it, which it takes back exactly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TaskChange {
    /// Nothing: the task was already the one asked for, or there was none to remove.
    Unchanged,
    /// No task had the name, and the one asked for was registered.
    Registered,
    /// The environment's own task, which differed, was registered again as asked.
    Repaired {
        /// The task as it was, exported.
        prior: String,
    },
    /// The environment's own task was removed.
    Removed {
        /// The task as it was, exported.
        prior: String,
    },
}

/// What the Task Scheduler was asked when it failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Asked {
    /// To export one task.
    Query,
    /// To list every task this user can see.
    List,
    /// To register a task.
    Register,
    /// To remove a task.
    Remove,
}

impl Asked {
    /// What was asked, as a verb.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Query => "read",
            Self::List => "list",
            Self::Register => "register",
            Self::Remove => "remove",
        }
    }
}

/// Why a look at, or a change to, an environment's task did not happen.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TaskError {
    /// The task under the name is not this environment's own, and it is left as it is.
    Foreign(Foreign),
    /// The Task Scheduler could not be asked, or did not do what it was asked.
    Scheduler {
        /// What it was asked.
        asked: Asked,
        /// The exit code it gave, when it ran and gave one.
        code: Option<i32>,
        /// What went wrong, in the Task Scheduler's own words where it gave any.
        detail: String,
    },
    /// The task was changed and did not read back as the one asked for, so the change was undone;
    /// `undone` says whether undoing it worked.
    ReadBack {
        /// The task's name.
        name: String,
        /// How it differed, or `None` when it could not be found at all.
        differences: Option<Vec<Difference>>,
        /// Whether the change was undone.
        undone: bool,
    },
    /// The lock every change to the task takes could not be taken.
    Locked(String),
    /// The definition could not be written where the Task Scheduler reads it.
    Unwritten(String),
}

impl std::fmt::Display for TaskError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Foreign(foreign) => write!(formatter, "{foreign}, so it is left as it is"),
            Self::Scheduler { detail, .. } | Self::Locked(detail) | Self::Unwritten(detail) => {
                formatter.write_str(detail)
            }
            Self::ReadBack {
                name,
                differences: Some(differences),
                undone,
            } => write!(
                formatter,
                "{name} was changed and reads back differently ({}); the change was {}",
                differences
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join("; "),
                if *undone { "undone" } else { "not undone" }
            ),
            Self::ReadBack {
                name,
                differences: None,
                undone,
            } => write!(
                formatter,
                "{name} was changed and cannot be found; the change was {}",
                if *undone { "undone" } else { "not undone" }
            ),
        }
    }
}

/// How the task's last run ended, for all of its runs together: the Task Scheduler keeps one
/// result for a task whose runs are in parallel, so it says nothing about any one launch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LastResult {
    /// It has not run since it was registered.
    NotRun,
    /// A run is under way.
    Running,
    /// The last run ended with this code: zero when it succeeded.
    Ended(u32),
}

impl LastResult {
    /// The result the Task Scheduler reports as a number.
    #[must_use]
    pub const fn from_code(code: u32) -> Self {
        // `SCHED_S_TASK_HAS_NOT_RUN` and `SCHED_S_TASK_RUNNING`.
        match code {
            0x0004_1303 => Self::NotRun,
            0x0004_1301 => Self::Running,
            code => Self::Ended(code),
        }
    }
}

/// Reads the last result from one line of the Task Scheduler's verbose list in its comma-separated
/// form, whose seventh field it is.
///
/// Every field is quoted and a quote inside one is doubled. The list's words are in the machine's
/// own language, and this field is a number in every language.
#[must_use]
pub fn last_result_in(line: &str) -> Option<LastResult> {
    let field = csv_fields(line).into_iter().nth(6)?;
    let field = field.trim();
    let code = field
        .parse::<i64>()
        .ok()
        .and_then(|code| {
            u32::try_from(code)
                .ok()
                .or_else(|| i32::try_from(code).ok().map(i32::cast_unsigned))
        })
        .or_else(|| {
            field
                .strip_prefix("0x")
                .and_then(|hex| u32::from_str_radix(hex, 16).ok())
        })?;
    Some(LastResult::from_code(code))
}

/// Splits one line of comma-separated fields, each quoted, a doubled quote standing for one.
fn csv_fields(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    let mut characters = line.trim_end_matches(['\r', '\n']).chars().peekable();
    while let Some(character) = characters.next() {
        match character {
            '"' if quoted && characters.peek() == Some(&'"') => {
                field.push('"');
                characters.next();
            }
            '"' => quoted = !quoted,
            ',' if !quoted => fields.push(std::mem::take(&mut field)),
            other => field.push(other),
        }
    }
    fields.push(field);
    fields
}

#[cfg(windows)]
pub use self::platform::{clear, last_result, register, remove, run, set_up, standing, undo};

/// The calls to the Task Scheduler, through `schtasks.exe` from the system directory.
#[cfg(windows)]
mod platform {
    use super::{
        Asked, Foreign, ForeignReason, LastResult, RegisteredTask, Standing, TaskChange,
        TaskDefinition, TaskError, decode_output, last_result_in,
    };
    use crate::supervision::{RunFailure, SERVICE_MANAGER_BOUND, command_within};

    /// The Task Scheduler's command, from the system directory and never from the search path.
    fn schtasks() -> std::path::PathBuf {
        let root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
        std::path::Path::new(&root)
            .join("System32")
            .join("schtasks.exe")
    }

    /// Runs one Task Scheduler command within the service-manager bound.
    fn schtasks_within(
        asked: Asked,
        arguments: &[&str],
    ) -> Result<std::process::Output, TaskError> {
        let program = schtasks();
        command_within(
            &program.display().to_string(),
            arguments,
            SERVICE_MANAGER_BOUND,
        )
        .map_err(|failure| TaskError::Scheduler {
            asked,
            code: None,
            detail: failure.detail(),
        })
    }

    /// What a Task Scheduler command that ran and failed said.
    fn refused(asked: Asked, what: &str, output: &std::process::Output) -> TaskError {
        TaskError::Scheduler {
            asked,
            code: output.status.code(),
            detail: format!("{what}: {}", decode_output(&output.stderr).trim()),
        }
    }

    /// Reads where `definition`'s task stands: absent, another's, or this environment's own and how
    /// it differs from `definition`.
    ///
    /// # Errors
    ///
    /// Returns what went wrong when the Task Scheduler could not be asked, or answered with
    /// something other than a task or its absence.
    pub fn standing(definition: &TaskDefinition) -> Result<Standing, TaskError> {
        read(definition).map(|(standing, _)| standing)
    }

    /// Reads where `definition`'s task stands, with the task as the Task Scheduler exports it when
    /// this user can read it, and nothing otherwise.
    pub(super) fn read(definition: &TaskDefinition) -> Result<(Standing, String), TaskError> {
        let output = schtasks_within(Asked::Query, &["/Query", "/TN", &definition.name, "/XML"])?;
        let foreign = |reason| Foreign {
            name: definition.name.clone(),
            environment_id: definition.environment_id,
            reason,
        };
        if !output.status.success() {
            // Why it could not be read is said in the machine's own language, so it is not read.
            // The list of every task this user can see says whether the name is held at all.
            let said = decode_output(&output.stderr).trim().to_owned();
            if !is_listed(&definition.name)? {
                return Ok((Standing::Absent, String::new()));
            }
            return Ok((
                Standing::Foreign(foreign(ForeignReason::Unreadable { said })),
                String::new(),
            ));
        }
        let exported = decode_output(&output.stdout);
        let registered = RegisteredTask::parse(&exported);
        let sid_of = |name: &str| kr_ipc::starter::account_sid(name).ok();
        let standing = match registered.whose(definition, sid_of) {
            Some(reason) => Standing::Foreign(foreign(reason)),
            None => Standing::Owned(registered.differences(definition)),
        };
        Ok((standing, exported))
    }

    /// Whether a task named `name` is in the Task Scheduler's root folder, as this user sees it.
    fn is_listed(name: &str) -> Result<bool, TaskError> {
        let output = schtasks_within(Asked::List, &["/Query", "/FO", "CSV", "/NH"])?;
        if !output.status.success() {
            return Err(refused(
                Asked::List,
                "the Task Scheduler could not list its tasks",
                &output,
            ));
        }
        let wanted = format!("\\{name}");
        Ok(decode_output(&output.stdout).lines().any(|line| {
            line.trim_start()
                .strip_prefix('"')
                .and_then(|rest| rest.split('"').next())
                .is_some_and(|listed| listed.eq_ignore_ascii_case(&wanted))
        }))
    }

    /// How long a registration waits for another one of the same task to finish.
    const REGISTRATION_BOUND: std::time::Duration = std::time::Duration::from_secs(30);

    /// Holds the one lock every process of this user takes before it changes the task named
    /// `name`, whichever environment it serves: two environments whose identities share a prefix
    /// share the name, and a check of the task followed by a change to it holds only while no other
    /// change of this host's comes between them.
    fn registration_lock(name: &str) -> Result<kr_ipc::starter::NamedLock, TaskError> {
        kr_ipc::starter::NamedLock::acquire(
            &format!("Global\\{name}-registration"),
            REGISTRATION_BOUND,
        )
        .map_err(|error| {
            TaskError::Locked(format!(
                "the registration of {name} could not be locked: {error}"
            ))
        })
    }

    /// Registers `definition`, or brings this environment's own task back to it.
    ///
    /// # Errors
    ///
    /// Returns what went wrong, as [`set_up`] does.
    pub fn register(definition: &TaskDefinition) -> Result<(), TaskError> {
        set_up(definition).map(drop)
    }

    /// Registers `definition` for its environment and says what that changed, so the change can be
    /// undone.
    ///
    /// A task of the same name that is not this environment's is refused and left as it is. This
    /// environment's own task is left as it is when it is already `definition`, and registered
    /// again when it differs, its prior form kept as the Task Scheduler exported it. A name no
    /// task holds is taken only while it is still free. The definition is written to a UTF-16
    /// file in the environment's owner-only state directory for the Task Scheduler to read, and
    /// removed again. The task is read back afterwards and must be exactly `definition`; one that
    /// is not has its change undone, and the refusal says so.
    ///
    /// # Errors
    ///
    /// Returns what went wrong: a foreign task, a registration the Task Scheduler refused, or a
    /// task that did not read back as the one registered.
    pub fn set_up(definition: &TaskDefinition) -> Result<TaskChange, TaskError> {
        let _lock = registration_lock(&definition.name)?;
        let (found, exported) = read(definition)?;
        let change = match found {
            Standing::Foreign(foreign) => return Err(TaskError::Foreign(foreign)),
            Standing::Owned(differences) if differences.is_empty() => {
                return Ok(TaskChange::Unchanged);
            }
            Standing::Owned(_) => {
                create(definition, &definition.xml(), true)?;
                TaskChange::Repaired { prior: exported }
            }
            Standing::Absent => {
                if let Err(error) = create(definition, &definition.xml(), false) {
                    // A creation refused because the name was taken meanwhile, by something that
                    // does not take this lock, leaves that task as it is and says whose it is.
                    return match standing(definition)? {
                        Standing::Foreign(foreign) => Err(TaskError::Foreign(foreign)),
                        _ => Err(error),
                    };
                }
                TaskChange::Registered
            }
        };
        let differences = match standing(definition)? {
            Standing::Owned(differences) if differences.is_empty() => return Ok(change),
            Standing::Owned(differences) => Some(differences),
            Standing::Absent => None,
            Standing::Foreign(foreign) => return Err(TaskError::Foreign(foreign)),
        };
        let undone = revert(definition, &change).is_ok();
        Err(TaskError::ReadBack {
            name: definition.name.clone(),
            differences,
            undone,
        })
    }

    /// Removes this environment's own task, and says whether there was one.
    ///
    /// # Errors
    ///
    /// Returns what went wrong, as [`clear`] does.
    pub fn remove(definition: &TaskDefinition) -> Result<bool, TaskError> {
        clear(definition).map(|change| matches!(change, TaskChange::Removed { .. }))
    }

    /// Removes this environment's own task and says what that changed, its prior form kept as the
    /// Task Scheduler exported it so the removal can be undone.
    ///
    /// A task of the same name that is not this environment's is refused and left as it is.
    /// Removing a task leaves every process it started running: only ending a run would end them,
    /// and this host never ends one.
    ///
    /// # Errors
    ///
    /// Returns what went wrong: a foreign task, or a removal the Task Scheduler refused.
    pub fn clear(definition: &TaskDefinition) -> Result<TaskChange, TaskError> {
        let _lock = registration_lock(&definition.name)?;
        let (found, exported) = read(definition)?;
        match found {
            Standing::Absent => return Ok(TaskChange::Unchanged),
            Standing::Foreign(foreign) => return Err(TaskError::Foreign(foreign)),
            Standing::Owned(_) => {}
        }
        delete(definition)?;
        Ok(TaskChange::Removed { prior: exported })
    }

    /// Undoes `change`, which [`set_up`] or [`clear`] made for `definition`'s environment: a task
    /// registered where there was none is removed, and a task repaired or removed is put back as it
    /// was exported.
    ///
    /// Whatever is under the name now is checked first: a task that is not this environment's own
    /// is never replaced or removed, and one that is gone is put back only while the name is free.
    ///
    /// # Errors
    ///
    /// Returns what went wrong: a foreign task under the name, or a change the Task Scheduler
    /// refused.
    pub fn undo(definition: &TaskDefinition, change: &TaskChange) -> Result<(), TaskError> {
        let _lock = registration_lock(&definition.name)?;
        revert(definition, change)
    }

    /// Undoes `change` while the registration lock is held.
    fn revert(definition: &TaskDefinition, change: &TaskChange) -> Result<(), TaskError> {
        let found = standing(definition)?;
        if let Standing::Foreign(foreign) = found {
            return Err(TaskError::Foreign(foreign));
        }
        match change {
            TaskChange::Unchanged => Ok(()),
            TaskChange::Registered => match found {
                Standing::Owned(_) => delete(definition),
                _ => Ok(()),
            },
            TaskChange::Repaired { prior } | TaskChange::Removed { prior } => {
                create(definition, prior, matches!(found, Standing::Owned(_)))?;
                match standing(definition)? {
                    Standing::Owned(_) => Ok(()),
                    Standing::Foreign(foreign) => Err(TaskError::Foreign(foreign)),
                    Standing::Absent => Err(TaskError::ReadBack {
                        name: definition.name.clone(),
                        differences: None,
                        undone: false,
                    }),
                }
            }
        }
    }

    /// Registers `xml` under `definition`'s name, through the Task Scheduler.
    ///
    /// `replace` says the task under the name is this environment's own, found so under the
    /// registration lock, and is replaced. Otherwise the name was free when it was looked at, and
    /// the creation takes it only if it still is: a definition given as XML without `/F` is
    /// registered as a new task and refused when the name is held, so a task something else made
    /// in the meantime is never replaced.
    fn create(definition: &TaskDefinition, xml: &str, replace: bool) -> Result<(), TaskError> {
        let file = definition
            .working_directory
            .join(format!("{}.xml", definition.name));
        let mut bytes = vec![0xff, 0xfe];
        bytes.extend(xml.encode_utf16().flat_map(u16::to_le_bytes));
        kr_ipc::paths::write_owner_only_file(&file, &bytes).map_err(|error| {
            TaskError::Unwritten(format!(
                "write the definition of {}: {error}",
                definition.name
            ))
        })?;
        let file_text = file.display().to_string();
        let mut arguments = vec!["/Create", "/TN", &definition.name, "/XML", &file_text];
        if replace {
            arguments.push("/F");
        }
        let created = schtasks_within(Asked::Register, &arguments);
        let _ = std::fs::remove_file(&file);
        let output = created?;
        if !output.status.success() {
            return Err(refused(
                Asked::Register,
                &format!("the Task Scheduler did not register {}", definition.name),
                &output,
            ));
        }
        Ok(())
    }

    /// Registers `definition` through the Task Scheduler, as [`create`] does.
    #[cfg(test)]
    pub(super) fn create_task(definition: &TaskDefinition, replace: bool) -> Result<(), TaskError> {
        create(definition, &definition.xml(), replace)
    }

    /// Removes the task under `definition`'s name, which the caller found to be this environment's
    /// own under the registration lock.
    fn delete(definition: &TaskDefinition) -> Result<(), TaskError> {
        let output = schtasks_within(Asked::Remove, &["/Delete", "/TN", &definition.name, "/F"])?;
        if !output.status.success() {
            return Err(refused(
                Asked::Remove,
                &format!("the Task Scheduler did not remove {}", definition.name),
                &output,
            ));
        }
        Ok(())
    }

    /// Reads how the task's last run ended, which is one result for all of its runs.
    ///
    /// # Errors
    ///
    /// Returns what went wrong when the Task Scheduler could not be asked, or its list has no
    /// result for the task.
    pub fn last_result(definition: &TaskDefinition) -> Result<LastResult, TaskError> {
        let output = schtasks_within(
            Asked::Query,
            &["/Query", "/TN", &definition.name, "/V", "/FO", "CSV", "/NH"],
        )?;
        if !output.status.success() {
            return Err(refused(
                Asked::Query,
                &format!("the Task Scheduler could not list {}", definition.name),
                &output,
            ));
        }
        decode_output(&output.stdout)
            .lines()
            .find(|line| !line.trim().is_empty())
            .and_then(last_result_in)
            .ok_or_else(|| TaskError::Scheduler {
                asked: Asked::Query,
                code: None,
                detail: format!(
                    "the Task Scheduler's list of {} has no last result",
                    definition.name
                ),
            })
    }

    /// Asks the Task Scheduler to run `definition`'s task once, now.
    ///
    /// # Errors
    ///
    /// Returns [`RunFailure::NotRun`] when the Task Scheduler could not be asked, and
    /// [`RunFailure::Failed`] when it was asked and did not start the run, which it may have begun
    /// first.
    pub fn run(definition: &TaskDefinition) -> Result<(), RunFailure> {
        let program = schtasks();
        let output = command_within(
            &program.display().to_string(),
            &["/Run", "/I", "/TN", &definition.name],
            SERVICE_MANAGER_BOUND,
        )?;
        if output.status.success() {
            return Ok(());
        }
        Err(RunFailure::Failed(format!(
            "the Task Scheduler did not run {}: {}",
            definition.name,
            decode_output(&output.stderr).trim()
        )))
    }
}

#[cfg(windows)]
pub use self::launching::{StarterExit, TaskSupervisor, run_starter};

/// A launch, from the daemon that hands it over to the starter that creates it.
///
/// The daemon never creates a worker. For each launch it validates the environment's task, opens
/// one instance of the launch pipe, runs the task and waits on that instance; the task's starter
/// reaches it, says which environment it serves, is checked, is handed the launch, creates the
/// process ([`kr_ipc::starter::start_child`]) and reports it. What the daemon records is the
/// identity the starter read from the handle that created the process.
///
/// The outcome follows what the daemon can know. Nothing handed over is [`LaunchOutcome::NotStarted`]:
/// the task was missing, foreign or not this build's, the run failed, no starter came, or the one
/// that came was not this installation's starter. A launch handed over whose answer was lost is
/// [`LaunchOutcome::Uncertain`] with no process identifier, because the starter may have created
/// something. A starter's refusal is `NotStarted` when its child was ended, and `Uncertain` when
/// it could not be.
#[cfg(windows)]
mod launching {
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant};

    use kr_ipc::paths::{EnvironmentPaths, HostPaths};
    use kr_ipc::starter::{self, ChildCommand, LaunchListener, LaunchStream, Reached};
    use kr_protocol::identity::ProcessStartIdentity;
    use kr_protocol::ids::EnvironmentId;
    use serde::{Deserialize, Serialize};

    use super::{Standing, TaskDefinition, run, same_path, standing};
    use crate::supervision::{
        LaunchOutcome, RunFailure, ServiceLaunch, WorkerLaunch, WorkerSupervisor,
    };

    /// The version of the exchange on the launch pipe.
    const LAUNCH_PROTOCOL: u32 = 1;

    /// How long the task's starter is given to reach a launch once the task has been run: the
    /// Task Scheduler starts a process within a second or two, and a machine under load is slower.
    const REACH_BOUND: Duration = Duration::from_secs(30);

    /// How long each message of the exchange is given.
    const EXCHANGE_BOUND: Duration = Duration::from_secs(10);

    /// How long a starter is given to create the process and report it.
    const REPORT_BOUND: Duration = Duration::from_secs(30);

    /// What a person does about a task that is missing, foreign or not this installation's.
    const SETUP_ACTION: &str = "run kr host startup --set standalone";

    /// What a starter says first: the exchange it speaks and the environment it serves.
    #[derive(Debug, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct StarterHello {
        protocol: u32,
        environment: EnvironmentId,
    }

    /// One variable a launch sets for the process it starts.
    #[derive(Debug, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Variable {
        name: String,
        value: String,
    }

    /// The one launch the daemon hands a starter it accepted.
    #[derive(Debug, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Launch {
        program: String,
        arguments: Vec<String>,
        working_directory: String,
        environment: Vec<Variable>,
        /// The daemon's login session, which the process must run in.
        session: u32,
    }

    /// What the daemon answers a starter's hello with.
    #[derive(Debug, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case", deny_unknown_fields)]
    enum Answer {
        /// The launch, for a starter the daemon accepted.
        Launch(Launch),
        /// Nothing, and why.
        Declined { reason: String },
    }

    /// What a starter reports once it has acted on a launch.
    #[derive(Debug, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case", deny_unknown_fields)]
    enum Report {
        /// The process was created, checked and let run.
        Started {
            identity: ProcessStartIdentity,
            session: u32,
            in_job: bool,
        },
        /// The process was not let run, and why; `remaining` when one was created and could not
        /// be ended.
        Refused { detail: String, remaining: bool },
    }

    fn encode<T: Serialize>(message: &T) -> Result<Vec<u8>, String> {
        kr_cbor::to_canonical_vec(message).map_err(|error| format!("encode: {error}"))
    }

    fn decode<T: serde::de::DeserializeOwned + Serialize>(bytes: &[u8]) -> Result<T, String> {
        kr_cbor::from_canonical_slice(bytes, &kr_cbor::Limits::DEFAULT)
            .map_err(|error| format!("decode: {error}"))
    }

    /// The Windows supervisor: every worker, and every service, is created by the environment's
    /// scheduled task's starter, never by this daemon, so none of them is ever in a job this daemon
    /// runs in.
    #[derive(Debug)]
    pub struct TaskSupervisor {
        environment: EnvironmentPaths,
        expected: TaskDefinition,
        reach_bound: Duration,
    }

    impl TaskSupervisor {
        /// A supervisor for `environment`, whose task runs `starter`: this installation's
        /// `kr-controller`.
        ///
        /// # Errors
        ///
        /// Returns the operating system's error when this process's account cannot be read.
        pub fn new(environment: EnvironmentPaths, starter: &Path) -> std::io::Result<Self> {
            let user = starter::current_user_sid()?;
            let expected = TaskDefinition::for_setup(user, &environment, starter);
            Ok(Self::for_definition(environment, expected))
        }

        /// A supervisor for `environment` whose task must be exactly `expected`: a test host that
        /// registered its task with the logon its session allows expects that one.
        #[must_use]
        pub const fn for_definition(
            environment: EnvironmentPaths,
            expected: TaskDefinition,
        ) -> Self {
            Self {
                environment,
                expected,
                reach_bound: REACH_BOUND,
            }
        }

        /// Gives a starter `bound`, rather than the usual half minute, to reach a launch once the
        /// task has been run.
        #[must_use]
        pub const fn with_reach_bound(mut self, bound: Duration) -> Self {
            self.reach_bound = bound;
            self
        }

        /// Hands one launch to the environment's starter and says what came of it.
        fn hand_over(
            &self,
            launch: &ServiceLaunch,
            variables: &[(String, String)],
        ) -> LaunchOutcome {
            let not_started = |detail: String| LaunchOutcome::NotStarted { detail };
            match standing(&self.expected) {
                Ok(Standing::Owned(differences)) if differences.is_empty() => {}
                Ok(Standing::Owned(differences)) => {
                    return not_started(format!(
                        "the environment's task {} is not the one this installation registers ({}): \
                         {SETUP_ACTION} to repair it",
                        self.expected.name,
                        differences
                            .iter()
                            .map(ToString::to_string)
                            .collect::<Vec<_>>()
                            .join("; ")
                    ));
                }
                Ok(Standing::Absent) => {
                    return not_started(format!(
                        "the environment has no task to start workers: {SETUP_ACTION}"
                    ));
                }
                Ok(Standing::Foreign(foreign)) => {
                    return not_started(format!("{foreign}: {SETUP_ACTION} for this environment"));
                }
                Err(error) => return not_started(error.to_string()),
            }
            let (Some(program), Some(working_directory)) =
                (launch.program.to_str(), launch.working_directory.to_str())
            else {
                return not_started(format!(
                    "{} or the directory it runs in is not a path this host can hand over",
                    launch.program.display()
                ));
            };
            let session = match starter::current_session() {
                Ok(session) => session,
                Err(error) => {
                    return not_started(format!("this daemon's login session: {error}"));
                }
            };
            let recorded = kr_ipc::identity::boot_identity()
                .map_err(|error| error.to_string())
                .and_then(|boot| {
                    starter::record_session(
                        &self.environment,
                        &starter::RecordedSession { session, boot },
                    )
                    .map_err(|error| error.to_string())
                });
            if let Err(detail) = recorded {
                return not_started(format!(
                    "the environment's login session could not be recorded: {detail}"
                ));
            }
            let listener = match self
                .environment
                .starter_endpoint()
                .map_err(|error| error.to_string())
                .and_then(|endpoint| {
                    LaunchListener::create(&endpoint).map_err(|error| error.to_string())
                }) {
                Ok(listener) => listener,
                Err(detail) => {
                    return not_started(format!("the launch pipe could not be opened: {detail}"));
                }
            };
            // The launch reaches a starter only through this instance, so a run that failed, or a
            // starter that never came, leaves nothing that could still start it once the instance
            // is dropped.
            if let Err(failure) = run(&self.expected) {
                let detail = match failure {
                    RunFailure::NotRun(detail) | RunFailure::Failed(detail) => detail,
                };
                return not_started(detail);
            }
            let mut stream = match listener.accept(Instant::now() + self.reach_bound) {
                Ok(Some(stream)) => stream,
                Ok(None) => {
                    return not_started(format!(
                        "the environment's task {} was run and no starter reached the launch within \
                         {:?}",
                        self.expected.name, self.reach_bound
                    ));
                }
                Err(error) => {
                    return not_started(format!("waiting for the starter failed: {error}"));
                }
            };
            if let Err(reason) = self.accept_starter(&mut stream, session) {
                // Best effort: a starter that is told why logs nothing and starts nothing either way.
                if let Ok(declined) = encode(&Answer::Declined {
                    reason: reason.clone(),
                }) {
                    let _ = stream.send(&declined, Instant::now() + EXCHANGE_BOUND);
                }
                return not_started(reason);
            }
            let handed = Launch {
                program: program.to_owned(),
                arguments: launch.arguments.clone(),
                working_directory: working_directory.to_owned(),
                environment: variables
                    .iter()
                    .map(|(name, value)| Variable {
                        name: name.clone(),
                        value: value.clone(),
                    })
                    .collect(),
                session,
            };
            let bytes = match encode(&Answer::Launch(handed)) {
                // A frame the pipe would refuse to carry is refused here, before anything leaves
                // this daemon: it is nothing started, not a launch whose answer was lost.
                Ok(bytes) if bytes.len() > starter::MAX_LAUNCH_FRAME => {
                    let detail = format!(
                        "the launch of {} is {} bytes, more than the {} the launch pipe carries",
                        launch.program.display(),
                        bytes.len(),
                        starter::MAX_LAUNCH_FRAME
                    );
                    if let Ok(declined) = encode(&Answer::Declined {
                        reason: detail.clone(),
                    }) {
                        let _ = stream.send(&declined, Instant::now() + EXCHANGE_BOUND);
                    }
                    return not_started(detail);
                }
                Ok(bytes) => bytes,
                Err(detail) => return not_started(detail),
            };
            // From here the starter may have the launch, so a failure is uncertain, never nothing.
            let uncertain = |detail: String| LaunchOutcome::Uncertain { detail, pid: None };
            if let Err(error) = stream.send(&bytes, Instant::now() + EXCHANGE_BOUND) {
                return uncertain(format!(
                    "the launch was handed to the starter and may not have arrived: {error}"
                ));
            }
            let report = match stream
                .receive(Instant::now() + REPORT_BOUND)
                .map_err(|error| error.to_string())
                .and_then(|bytes| decode::<Report>(&bytes))
            {
                Ok(report) => report,
                Err(detail) => {
                    return uncertain(format!(
                        "the starter took the launch and its answer was lost: {detail}"
                    ));
                }
            };
            match report {
                Report::Started {
                    identity,
                    session: started_in,
                    ..
                } if started_in == session => LaunchOutcome::Started(identity),
                Report::Started {
                    session: started_in,
                    ..
                } => uncertain(format!(
                    "the starter reports a process in login session {started_in}, not {session}"
                )),
                Report::Refused {
                    detail,
                    remaining: false,
                } => not_started(detail),
                Report::Refused {
                    detail,
                    remaining: true,
                } => uncertain(detail),
            }
        }

        /// Checks that the process at the other end is this installation's starter, of this user,
        /// in this daemon's session, and that it serves this environment in this exchange.
        fn accept_starter(&self, stream: &mut LaunchStream, session: u32) -> Result<(), String> {
            let peer = stream
                .peer()
                .map_err(|error| format!("the process that reached the launch: {error}"))?;
            if !same_path(&peer.image.display().to_string(), &self.expected.starter) {
                return Err(format!(
                    "process {} reached the launch running {}, not this installation's starter {}",
                    peer.pid,
                    peer.image.display(),
                    self.expected.starter.display()
                ));
            }
            if !peer.same_user {
                return Err(format!(
                    "process {} reached the launch as another account",
                    peer.pid
                ));
            }
            if peer.session != session {
                return Err(format!(
                    "the starter runs in login session {}, not this daemon's {session}: the Task \
                     Scheduler ran it where another session of this user is signed in",
                    peer.session
                ));
            }
            let hello: StarterHello = stream
                .receive(Instant::now() + EXCHANGE_BOUND)
                .map_err(|error| error.to_string())
                .and_then(|bytes| decode(&bytes))
                .map_err(|detail| format!("the starter did not say who it is: {detail}"))?;
            if hello.protocol != LAUNCH_PROTOCOL {
                return Err(format!(
                    "the starter speaks launch exchange {}, not {LAUNCH_PROTOCOL}",
                    hello.protocol
                ));
            }
            if hello.environment != self.expected.environment_id {
                return Err(format!(
                    "the starter serves environment {}, not {}",
                    hello.environment, self.expected.environment_id
                ));
            }
            Ok(())
        }
    }

    impl WorkerSupervisor for TaskSupervisor {
        fn start(&self, launch: &WorkerLaunch) -> LaunchOutcome {
            self.hand_over(&launch.service(), &launch.desktop_environment)
        }

        fn start_service(&self, launch: &ServiceLaunch) -> LaunchOutcome {
            self.hand_over(launch, &[])
        }

        fn describe(&self) -> &'static str {
            "the environment's scheduled task, whose starter creates each worker outside this \
             daemon's jobs"
        }
    }

    /// How long a starter looks for a waiting launch before it looks for a start claim.
    const LOOK_BOUND: Duration = Duration::from_secs(5);

    /// What a starter run ended with, which the Task Scheduler records as the run's result.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    #[repr(u8)]
    pub enum StarterExit {
        /// It created what it was asked to, or found nothing to do.
        Done = 0,
        /// The daemon declined it, or the exchange failed before anything was created.
        Declined = 2,
        /// It refused to let a process run.
        Refused = 3,
        /// The environment or the machine could not be read.
        Unusable = 4,
    }

    /// Runs this process as the environment's starter, for the environment whose roots are given.
    ///
    /// It takes the launch waiting on the environment's launch pipe, if there is one. Otherwise it
    /// takes a start claim, if there is one it may still act on, and starts the environment's
    /// control daemon. Otherwise it creates nothing. Whatever it creates, it creates suspended and
    /// lets run only once [`kr_ipc::starter::start_child`] has checked it.
    #[must_use]
    pub fn run_starter(runtime_root: &Path, state_root: &Path) -> StarterExit {
        let Ok(paths) = HostPaths::new(runtime_root, state_root) else {
            return StarterExit::Unusable;
        };
        let Ok(Some(environment_id)) = paths.recorded_environment_id() else {
            return StarterExit::Unusable;
        };
        let environment = paths.environment(environment_id);
        let Ok(endpoint) = environment.starter_endpoint() else {
            return StarterExit::Unusable;
        };
        match starter::connect(&endpoint, Instant::now() + LOOK_BOUND) {
            Ok(Reached::Connected(stream)) => serve_launch(stream, environment_id),
            Ok(Reached::NoInstance | Reached::Busy) | Err(_) => {
                start_claimed_daemon(&environment, runtime_root, state_root)
            }
        }
    }

    /// Serves the one launch this starter reached.
    fn serve_launch(mut stream: LaunchStream, environment: EnvironmentId) -> StarterExit {
        let hello = StarterHello {
            protocol: LAUNCH_PROTOCOL,
            environment,
        };
        let Ok(bytes) = encode(&hello) else {
            return StarterExit::Declined;
        };
        if stream
            .send(&bytes, Instant::now() + EXCHANGE_BOUND)
            .is_err()
        {
            return StarterExit::Declined;
        }
        let answer = stream
            .receive(Instant::now() + EXCHANGE_BOUND)
            .map_err(|error| error.to_string())
            .and_then(|bytes| decode::<Answer>(&bytes));
        let launch = match answer {
            Ok(Answer::Launch(launch)) => launch,
            Ok(Answer::Declined { .. }) | Err(_) => return StarterExit::Declined,
        };
        let program = PathBuf::from(&launch.program);
        let line = kr_worker::pty::command_line(
            &std::iter::once(launch.program.clone())
                .chain(launch.arguments.iter().cloned())
                .map(std::ffi::OsString::from)
                .collect::<Vec<_>>(),
        );
        let variables: Vec<(String, String)> = launch
            .environment
            .iter()
            .map(|variable| (variable.name.clone(), variable.value.clone()))
            .collect();
        let started = starter::start_child(&ChildCommand {
            application: &program,
            command_line: &line,
            directory: Path::new(&launch.working_directory),
            environment: &variables,
            session: launch.session,
            output: None,
        });
        let (report, exit) = match started {
            Ok(child) => (
                Report::Started {
                    identity: child.identity,
                    session: child.session,
                    in_job: child.in_job,
                },
                StarterExit::Done,
            ),
            Err(refusal) => (
                Report::Refused {
                    detail: refusal.detail,
                    remaining: refusal.remaining_pid.is_some(),
                },
                StarterExit::Refused,
            ),
        };
        // A report that does not arrive leaves the daemon uncertain, which is what it must be:
        // the process, if one was let run, is running.
        if let Ok(bytes) = encode(&report) {
            let _ = stream.send(&bytes, Instant::now() + EXCHANGE_BOUND);
        }
        exit
    }

    /// Starts the environment's control daemon for a start claim this starter took, if there is
    /// one it may still act on.
    fn start_claimed_daemon(
        environment: &EnvironmentPaths,
        runtime_root: &Path,
        state_root: &Path,
    ) -> StarterExit {
        let Ok(boot) = kr_ipc::identity::boot_identity() else {
            return StarterExit::Unusable;
        };
        let taken = match starter::take_claim(environment, &boot, kr_ipc::clock::boot_elapsed_ms())
        {
            Ok(Some(taken)) => taken,
            Ok(None) => return StarterExit::Done,
            Err(_) => return StarterExit::Unusable,
        };
        let (Ok(program), Ok(session)) = (std::env::current_exe(), starter::current_session())
        else {
            return StarterExit::Unusable;
        };
        let line = kr_worker::pty::command_line(&[
            program.as_os_str().to_owned(),
            "--runtime-dir".into(),
            runtime_root.as_os_str().to_owned(),
            "--state-dir".into(),
            state_root.as_os_str().to_owned(),
        ]);
        // What the daemon writes goes to the environment's log, as it does wherever a start runs
        // the daemon. A log that is not a regular file of this user's alone is not written
        // through: the daemon then runs with nothing to write to, and the command that asked for
        // it has already said what is wrong with the log.
        let log = starter::open_log(&environment.state_dir().join(super::DAEMON_LOG)).ok();
        // The admission point: the deadline is read again right before anything is created.
        if !taken.admits(&boot, kr_ipc::clock::boot_elapsed_ms()) {
            return StarterExit::Done;
        }
        match starter::start_child(&ChildCommand {
            application: &program,
            command_line: &line,
            directory: environment.state_dir(),
            environment: &[],
            session,
            output: log.as_ref().map(std::os::windows::io::AsHandle::as_handle),
        }) {
            Ok(_) => StarterExit::Done,
            Err(_) => StarterExit::Refused,
        }
    }
}

/// For suites that host a daemon on Windows: the environment's task registered for a test's own
/// temporary environment, and the supervisor that starts through it.
///
/// A daemon a test hosts runs inside `cargo test`'s job, which kills its members when it closes
/// and forbids breakaway, so a worker it created itself would die with the test. Through the task
/// it creates nothing itself: the task's starter creates the worker, outside that job.
#[cfg(all(windows, feature = "testing"))]
pub mod testing {
    use std::path::{Path, PathBuf};

    use kr_ipc::paths::EnvironmentPaths;

    use super::{LogonType, TaskDefinition, TaskSupervisor, register, remove};

    /// The logon this host can register a task with: the one the setup step registers in a
    /// session where the user is signed in, and the one without a session in session 0, where a
    /// test host runs with nobody signed in.
    ///
    /// # Errors
    ///
    /// Returns the operating system's error when this process's session cannot be read.
    pub fn logon_for_this_session() -> std::io::Result<LogonType> {
        Ok(if kr_ipc::starter::current_session()? == 0 {
            LogonType::S4U
        } else {
            LogonType::InteractiveToken
        })
    }

    /// Finds a binary this workspace built for the test running now.
    ///
    /// No one package's `CARGO_BIN_EXE_` names both `kr-controller` and `kr-worker`, so a suite
    /// finds them where the build put them: beside the directory its own executable is in, which
    /// is `target/<profile>/deps`.
    ///
    /// # Errors
    ///
    /// Returns what to build when the binary is not there.
    pub fn built_binary(name: &str) -> Result<PathBuf, String> {
        let this = std::env::current_exe().map_err(|error| format!("this test: {error}"))?;
        let profile = this
            .parent()
            .and_then(Path::parent)
            .ok_or_else(|| format!("{} is not inside a build directory", this.display()))?;
        let binary = profile.join(format!("{name}.exe"));
        if binary.is_file() {
            Ok(binary)
        } else {
            Err(format!(
                "{} is not built: build it before this suite (cargo build -p {name})",
                binary.display()
            ))
        }
    }

    /// The environment's task, registered for a test and removed when this is dropped, and only
    /// if it is still that environment's own.
    ///
    /// It belongs to the test's host tree rather than to a daemon, so a daemon the test stops and
    /// starts again finds the same task.
    #[derive(Debug)]
    pub struct TestTask {
        definition: TaskDefinition,
    }

    impl TestTask {
        /// Registers `environment`'s task, running `starter`, with the logon this host allows.
        ///
        /// # Errors
        ///
        /// Returns what went wrong when the account, the session or the registration failed.
        pub fn register(environment: &EnvironmentPaths, starter: &Path) -> Result<Self, String> {
            let definition = definition(environment, starter)?;
            register(&definition).map_err(|error| error.to_string())?;
            Ok(Self { definition })
        }

        /// The definition registered.
        #[must_use]
        pub const fn definition(&self) -> &TaskDefinition {
            &self.definition
        }

        /// The supervisor that starts through this task, expecting exactly this definition.
        #[must_use]
        pub fn supervisor(&self, environment: &EnvironmentPaths) -> TaskSupervisor {
            TaskSupervisor::for_definition(environment.clone(), self.definition.clone())
        }
    }

    impl Drop for TestTask {
        fn drop(&mut self) {
            let _ = remove(&self.definition);
        }
    }

    /// Registers `environment`'s task, running the `kr-controller` built beside this test, and
    /// returns it with the supervisor that starts through it.
    ///
    /// # Errors
    ///
    /// Returns what went wrong: the starter not built, or the task not registered.
    pub fn supervisor(
        environment: &EnvironmentPaths,
    ) -> Result<(TestTask, TaskSupervisor), String> {
        let starter = built_binary("kr-controller")?;
        let task = TestTask::register(environment, &starter)?;
        let supervisor = task.supervisor(environment);
        Ok((task, supervisor))
    }

    /// The definition a test host registers for `environment`, running `starter`, with the logon
    /// this host allows.
    ///
    /// # Errors
    ///
    /// Returns what went wrong when the account or the session could not be read.
    pub fn definition(
        environment: &EnvironmentPaths,
        starter: &Path,
    ) -> Result<TaskDefinition, String> {
        let user = kr_ipc::starter::current_user_sid()
            .map_err(|error| format!("this account: {error}"))?;
        let logon = logon_for_this_session().map_err(|error| format!("this session: {error}"))?;
        Ok(TaskDefinition::new(user, environment, starter, logon))
    }
}

#[cfg(test)]
mod tests {
    use kr_ipc::testing::TempHost;

    use super::*;

    const USER: &str = "S-1-5-21-1000-2000-3000-1001";

    fn starter(host: &TempHost) -> PathBuf {
        host.root().join("bin").join("kr-controller.exe")
    }

    /// KR-REQ-07.69: the setup step registers a task that logs on as the user in a session where
    /// the user is signed in, runs only when it is asked, runs its instances in parallel at normal
    /// priority with no time limit, and starts this installation's starter in the environment's
    /// state directory with the two roots.
    #[test]
    fn the_setup_step_registers_an_interactive_logon_that_runs_only_when_asked() {
        let host = TempHost::create();
        let environment = host.environment();
        let definition = TaskDefinition::for_setup(USER, &environment, &starter(&host));
        assert_eq!(definition.logon, LogonType::InteractiveToken);
        assert_eq!(definition.name, task_name(environment.environment_id()));
        let xml = definition.xml();
        for expected in [
            "<LogonType>InteractiveToken</LogonType>",
            "<RunLevel>LeastPrivilege</RunLevel>",
            "<Triggers />",
            "<MultipleInstancesPolicy>Parallel</MultipleInstancesPolicy>",
            "<ExecutionTimeLimit>PT0S</ExecutionTimeLimit>",
            "<Priority>5</Priority>",
            &format!("<UserId>{USER}</UserId>"),
        ] {
            assert!(
                xml.contains(expected),
                "the definition says {expected}: {xml}"
            );
        }
        let read = RegisteredTask::parse(&xml);
        assert_eq!(
            read.description,
            format!("KalaReach environment {}", environment.environment_id())
        );
        assert!(same_path(&read.command, &starter(&host)));
        assert!(same_path(&read.working_directory, environment.state_dir()));
        assert!(
            read.arguments.starts_with("--starter --runtime-dir "),
            "the starter is told it is one, and the roots: {}",
            read.arguments
        );
        assert!(
            read.arguments
                .contains(&environment.runtime_root().display().to_string())
        );
        assert!(
            read.arguments
                .contains(&environment.state_root().display().to_string())
        );
        assert!(!read.triggered);
        assert_eq!(read.actions, 1);
    }

    /// A test host, which has nobody signed in, registers the same definition with the other logon.
    #[test]
    fn a_host_nobody_is_signed_in_to_registers_the_same_task_without_a_session() {
        let host = TempHost::create();
        let environment = host.environment();
        let setup = TaskDefinition::for_setup(USER, &environment, &starter(&host));
        let session_less = TaskDefinition::new(USER, &environment, &starter(&host), LogonType::S4U);
        assert!(session_less.xml().contains("<LogonType>S4U</LogonType>"));
        assert_eq!(
            session_less.xml().replace(
                "<LogonType>S4U</LogonType>",
                "<LogonType>InteractiveToken</LogonType>"
            ),
            setup.xml(),
            "only the logon differs"
        );
    }

    /// A task reads back as the definition it was registered from: this environment's own, and
    /// exactly the one this build registers.
    #[test]
    fn a_task_reads_back_as_the_definition_it_was_registered_from() {
        let host = TempHost::create();
        let definition = TaskDefinition::for_setup(USER, &host.environment(), &starter(&host));
        let read = RegisteredTask::parse(&definition.xml());
        assert!(read.belongs_to(&definition, |_| None));
        assert_eq!(read.differences(&definition), Vec::<Difference>::new());
        assert_eq!(read.logon, Some(LogonType::InteractiveToken));
    }

    /// The Task Scheduler's export adds elements, leaves a default out, reorders what it keeps and
    /// may name the account rather than give its identifier; the task still reads back as this
    /// environment's own and as the one registered.
    #[test]
    fn an_export_is_read_whatever_the_task_scheduler_adds_or_leaves_out() {
        let host = TempHost::create();
        let definition =
            TaskDefinition::new(USER, &host.environment(), &starter(&host), LogonType::S4U);
        let exported = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-16\"?>\r\n\
             <Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\r\n\
             \x20 <RegistrationInfo>\r\n    <Date>2026-09-25T12:00:00</Date>\r\n    <Author>HOST\\me</Author>\r\n\
             \x20   <Description>{description}</Description>\r\n    <URI>\\{name}</URI>\r\n  </RegistrationInfo>\r\n\
             \x20 <Principals>\r\n    <Principal id=\"Author\">\r\n      <UserId>HOST\\me</UserId>\r\n\
             \x20     <LogonType>S4U</LogonType>\r\n    </Principal>\r\n  </Principals>\r\n\
             \x20 <Settings>\r\n    <MultipleInstancesPolicy>Parallel</MultipleInstancesPolicy>\r\n\
             \x20   <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>\r\n\
             \x20   <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>\r\n\
             \x20   <Priority>5</Priority>\r\n    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>\r\n\
             \x20   <IdleSettings>\r\n      <StopOnIdleEnd>false</StopOnIdleEnd>\r\n    </IdleSettings>\r\n  </Settings>\r\n\
             \x20 <Triggers />\r\n\
             \x20 <Actions Context=\"Author\">\r\n    <Exec>\r\n      <Command>{command}</Command>\r\n\
             \x20     <Arguments>{arguments}</Arguments>\r\n      <WorkingDirectory>{directory}</WorkingDirectory>\r\n\
             \x20   </Exec>\r\n  </Actions>\r\n</Task>\r\n",
            description = definition.description(),
            name = definition.name,
            command = escape(&definition.starter.display().to_string().to_uppercase()),
            arguments = escape(&definition.arguments),
            directory = escape(&definition.working_directory.display().to_string()),
        );
        let read = RegisteredTask::parse(&exported);
        let resolve = |name: &str| (name == "HOST\\me").then(|| USER.to_owned());
        assert!(
            read.belongs_to(&definition, resolve),
            "the named account is this user"
        );
        assert!(
            !read.belongs_to(&definition, |_| None),
            "an account nothing resolves is not"
        );
        assert_eq!(
            read.differences(&definition),
            Vec::<Difference>::new(),
            "a default left out and a path in another case are no difference"
        );
    }

    /// A task is this environment's only with this user's account and this environment's full
    /// identity: another account's, or another environment's whose identity shares the prefix,
    /// is someone else's.
    #[test]
    fn a_task_is_this_environments_only_with_its_account_and_its_identity() {
        let host = TempHost::create();
        let ours = TaskDefinition::for_setup(USER, &host.environment(), &starter(&host));
        let theirs_account = TaskDefinition {
            user: "S-1-5-21-1000-2000-3000-1002".to_owned(),
            ..ours.clone()
        };
        let theirs_environment = TaskDefinition {
            environment_id: EnvironmentId::new(kr_ipc::new_uuid()),
            ..ours.clone()
        };
        for other in [theirs_account, theirs_environment] {
            let read = RegisteredTask::parse(&other.xml());
            assert!(!read.belongs_to(&ours, |_| None), "{other:?} is not ours");
        }
    }

    /// Every way a registered task can differ from the one this build registers is named: its
    /// program, what it gives it, the directory, a second action, a trigger, a logon other than the
    /// one expected, a privilege above the least, and each setting a run of the starter depends on:
    /// batteries, idleness, a network, being run when asked, parallel runs, the time limit, the
    /// priority and being enabled. A battery setting left out is the Task Scheduler's default,
    /// which is not this build's.
    #[test]
    fn every_way_a_task_can_differ_from_this_builds_is_named() {
        let host = TempHost::create();
        let definition = TaskDefinition::for_setup(USER, &host.environment(), &starter(&host));
        let xml = definition.xml();
        let changed = |from: &str, to: &str| {
            assert!(xml.contains(from), "the definition has {from}");
            RegisteredTask::parse(&xml.replace(from, to)).differences(&definition)
        };
        let program = escape(&definition.starter.display().to_string());
        let cases = [
            changed(&program, "C:\\elsewhere\\kr-controller.exe"),
            changed("--starter", "--other"),
            changed(
                &format!(
                    "<WorkingDirectory>{}",
                    escape(&definition.working_directory.display().to_string())
                ),
                "<WorkingDirectory>C:\\elsewhere",
            ),
            changed("</Exec>", "</Exec><Exec><Command>cmd.exe</Command></Exec>"),
            changed(
                "<Triggers />",
                "<Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers>",
            ),
            changed(
                "<LogonType>InteractiveToken</LogonType>",
                "<LogonType>Password</LogonType>",
            ),
            changed(
                "<LogonType>InteractiveToken</LogonType>",
                "<LogonType>S4U</LogonType>",
            ),
            changed(
                "<RunLevel>LeastPrivilege</RunLevel>",
                "<RunLevel>HighestAvailable</RunLevel>",
            ),
            changed(
                "<DisallowStartIfOnBatteries>false",
                "<DisallowStartIfOnBatteries>true",
            ),
            changed(
                "<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>",
                "",
            ),
            changed(
                "<StopIfGoingOnBatteries>false",
                "<StopIfGoingOnBatteries>true",
            ),
            changed("<RunOnlyIfIdle>false", "<RunOnlyIfIdle>true"),
            changed("<StopOnIdleEnd>false", "<StopOnIdleEnd>true"),
            changed(
                "<RunOnlyIfNetworkAvailable>false",
                "<RunOnlyIfNetworkAvailable>true",
            ),
            changed("<AllowStartOnDemand>true", "<AllowStartOnDemand>false"),
            changed(
                "<MultipleInstancesPolicy>Parallel",
                "<MultipleInstancesPolicy>IgnoreNew",
            ),
            changed("<ExecutionTimeLimit>PT0S", "<ExecutionTimeLimit>PT72H"),
            changed("<Priority>5", "<Priority>7"),
            changed("<Enabled>true", "<Enabled>false"),
        ];
        for (index, differences) in cases.iter().enumerate() {
            assert_eq!(
                differences.len(),
                1,
                "case {index} is one difference: {differences:?}"
            );
        }
    }

    /// A path resolved on Windows is named without its verbatim prefix, a network path as a
    /// network path; anything else is left as it is.
    #[test]
    fn a_resolved_path_is_named_without_its_verbatim_prefix() {
        for (resolved, named) in [
            (
                r"\\?\C:\Users\me\kr\kr-controller.exe",
                r"C:\Users\me\kr\kr-controller.exe",
            ),
            (
                r"\\?\UNC\server\share\kr-controller.exe",
                r"\\server\share\kr-controller.exe",
            ),
            (r"C:\kr\kr-controller.exe", r"C:\kr\kr-controller.exe"),
            (
                r"\\?\Volume{0}\kr-controller.exe",
                r"\\?\Volume{0}\kr-controller.exe",
            ),
        ] {
            assert_eq!(
                without_verbatim_prefix(PathBuf::from(resolved)),
                PathBuf::from(named)
            );
        }
        assert!(same_path(
            r"\\?\C:\Users\Me\kr\kr-controller.exe",
            Path::new(r"c:/users/me/kr/kr-controller.exe")
        ));
    }

    /// Markup characters in a path survive being written into the definition and read back.
    #[test]
    fn a_path_with_markup_characters_survives_the_definition() {
        let host = TempHost::create();
        let odd = host.root().join("R&D <'tools'>").join("kr-controller.exe");
        let definition = TaskDefinition::for_setup(USER, &host.environment(), &odd);
        let read = RegisteredTask::parse(&definition.xml());
        assert_eq!(read.command, odd.display().to_string());
        assert_eq!(read.differences(&definition), Vec::<Difference>::new());
    }

    /// The last result is read from the verbose list's seventh field in whatever language the
    /// machine's words are in, quoted and with commas inside a field, and as the Task Scheduler's
    /// two running states or a code.
    #[test]
    fn the_last_result_is_read_from_the_verbose_list_in_any_language() {
        let line = |result: &str, when: &str| {
            format!(
                "\"HOST\",\"\\KalaReach-1d6e814d\",\"N/A\",\"Bereit\",\"Nur interaktiv\",\"{when}\",\
                 \"{result}\",\"N/A\",\"C:\\kr\\kr-controller.exe --starter --runtime-dir \"\"C:\\r\"\"\",\
                 \"C:\\s\",\"KalaReach environment 1d6e814d\"\r\n"
            )
        };
        assert_eq!(
            last_result_in(&line("0", "9/25/2026 10:47:32 AM")),
            Some(LastResult::Ended(0))
        );
        assert_eq!(
            last_result_in(&line("267011", "Freitag, 25. September 2026, 10:47:32")),
            Some(LastResult::NotRun),
            "a comma inside a quoted field is the field's"
        );
        assert_eq!(
            last_result_in(&line("267009", "N/A")),
            Some(LastResult::Running)
        );
        assert_eq!(
            last_result_in(&line("-2147020576", "N/A")),
            Some(LastResult::Ended(0x8007_10e0)),
            "a failure code is written as a signed number"
        );
        assert_eq!(
            last_result_in(&line("0x800710E0", "N/A")),
            Some(LastResult::Ended(0x8007_10e0))
        );
        assert_eq!(last_result_in(&line("Bereit", "N/A")), None, "not a number");
        assert_eq!(
            last_result_in("\"HOST\",\"\\KalaReach-1d6e814d\""),
            None,
            "too short"
        );
    }

    /// A task that is not this environment's says why: another account's, or this account's for
    /// another environment; one of this environment's own says nothing.
    #[test]
    fn a_task_that_is_not_the_environments_says_whose_it_is_not() {
        let host = TempHost::create();
        let ours = TaskDefinition::for_setup(USER, &host.environment(), &starter(&host));
        let read = |definition: &TaskDefinition| RegisteredTask::parse(&definition.xml());
        assert_eq!(read(&ours).whose(&ours, |_| None), None);
        let account = TaskDefinition {
            user: "S-1-5-21-1000-2000-3000-1002".to_owned(),
            ..ours.clone()
        };
        assert!(matches!(
            read(&account).whose(&ours, |_| None),
            Some(ForeignReason::Account { .. })
        ));
        let environment = TaskDefinition {
            environment_id: EnvironmentId::new(kr_ipc::new_uuid()),
            ..ours.clone()
        };
        assert!(matches!(
            read(&environment).whose(&ours, |_| None),
            Some(ForeignReason::Environment { .. })
        ));
    }

    /// Each difference is written for the daemon's own record as it always was: what was read and
    /// what was expected.
    #[test]
    fn a_difference_is_written_with_what_was_read_for_the_daemons_record() {
        let host = TempHost::create();
        let definition = TaskDefinition::for_setup(USER, &host.environment(), &starter(&host));
        let differences = RegisteredTask::parse(
            &definition
                .xml()
                .replace("<Priority>5", "<Priority>7")
                .replace("<LogonType>InteractiveToken", "<LogonType>S4U"),
        )
        .differences(&definition);
        let written: Vec<String> = differences.iter().map(ToString::to_string).collect();
        assert_eq!(
            written,
            [
                "it logs on as S4U, not InteractiveToken",
                "it runs at priority \"7\", not the normal 5"
            ]
        );
    }

    /// What the Task Scheduler prints is read whether it wrote UTF-16 or UTF-8.
    #[test]
    fn the_task_schedulers_output_is_read_in_either_encoding() {
        let text = "<Task><Description>é</Description></Task>";
        let mut utf16 = vec![0xff, 0xfe];
        utf16.extend(text.encode_utf16().flat_map(u16::to_le_bytes));
        assert_eq!(decode_output(&utf16), text);
        let bare: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
        assert_eq!(decode_output(&bare), text);
        assert_eq!(decode_output(text.as_bytes()), text);
        let mut marked = vec![0xef, 0xbb, 0xbf];
        marked.extend(text.as_bytes());
        assert_eq!(decode_output(&marked), text);
    }

    /// Registering, reading back, removing and running a real task, on a Windows host.
    #[cfg(windows)]
    mod windows {
        use super::*;

        /// Removes the task a test registered, however the test ends.
        struct Registered(TaskDefinition);

        impl Drop for Registered {
            fn drop(&mut self) {
                let _ = remove(&self.0);
            }
        }

        /// The logon a test host can register: the interactive one needs a session where the
        /// user is signed in, which session 0 is not.
        fn logon() -> LogonType {
            if kr_ipc::starter::current_session().expect("this session") == 0 {
                LogonType::S4U
            } else {
                LogonType::InteractiveToken
            }
        }

        fn definition(host: &TempHost, starter: &Path) -> TaskDefinition {
            TaskDefinition::new(
                kr_ipc::starter::current_user_sid().expect("this account"),
                &host.environment(),
                starter,
                logon(),
            )
        }

        /// A program that ends at once whatever it is given, standing in for the starter where a
        /// test only registers, reads and runs the task.
        fn harmless() -> PathBuf {
            PathBuf::from(std::env::var_os("SystemRoot").expect("the system directory"))
                .join("System32")
                .join("whoami.exe")
        }

        /// A task registered for an environment is that environment's own and exactly as
        /// registered; registering it again changes nothing; removing it leaves nothing, and a
        /// second removal finds nothing.
        #[test]
        fn a_registered_task_is_the_environments_own_and_as_registered() {
            let host = TempHost::create();
            let definition = definition(&host, &harmless());
            assert_eq!(standing(&definition).expect("asked"), Standing::Absent);
            let _registered = Registered(definition.clone());
            register(&definition).expect("registered");
            assert_eq!(
                standing(&definition).expect("asked"),
                Standing::Owned(Vec::new())
            );
            register(&definition).expect("registered again");
            assert_eq!(
                standing(&definition).expect("asked"),
                Standing::Owned(Vec::new())
            );
            assert!(
                remove(&definition).expect("removed"),
                "there was a task to remove"
            );
            assert_eq!(standing(&definition).expect("asked"), Standing::Absent);
            assert!(!remove(&definition).expect("nothing to remove"));
        }

        /// A task under the environment's name that belongs to another environment is refused:
        /// never replaced, never removed.
        #[test]
        fn another_environments_task_under_the_same_name_is_never_replaced_or_removed() {
            let host = TempHost::create();
            let ours = definition(&host, &harmless());
            let theirs = TaskDefinition {
                environment_id: EnvironmentId::new(kr_ipc::new_uuid()),
                ..ours.clone()
            };
            let _theirs = Registered(theirs.clone());
            // Removes the task a registration that wrongly took the name would leave, which is
            // this environment's, so a broken copy of the refusal leaves nothing behind either.
            let _ours = Registered(ours.clone());
            register(&theirs).expect("the other environment's task");
            assert!(matches!(
                standing(&ours).expect("asked"),
                Standing::Foreign(_)
            ));
            assert!(register(&ours).is_err(), "it is not replaced");
            assert!(remove(&ours).is_err(), "it is not removed");
            assert_eq!(
                standing(&theirs).expect("asked"),
                Standing::Owned(Vec::new()),
                "and it is exactly as its own environment registered it"
            );
        }

        /// A creation made for a name that was free when it was looked at, and that something
        /// else took in the meantime, is refused and leaves that task exactly as it is: the
        /// registration never replaces a task it did not find to be the environment's own.
        #[test]
        fn a_creation_for_a_free_name_never_replaces_a_task_that_took_it_meanwhile() {
            let host = TempHost::create();
            let ours = definition(&host, &harmless());
            let theirs = TaskDefinition {
                environment_id: EnvironmentId::new(kr_ipc::new_uuid()),
                ..ours.clone()
            };
            let _theirs = Registered(theirs.clone());
            // Removes the task a creation that wrongly took the name would leave, which is this
            // environment's, so a broken copy of the refusal leaves nothing behind either.
            let _ours = Registered(ours.clone());
            register(&theirs).expect("the task that took the name meanwhile");
            let created = super::super::platform::create_task(&ours, false);
            assert_eq!(
                standing(&theirs).expect("asked"),
                Standing::Owned(Vec::new()),
                "the task that took the name is exactly as it was, whatever the creation said: \
                 {created:?}"
            );
            assert!(
                created.is_err(),
                "and the creation for a free name says it did not take it"
            );
        }

        /// This environment's task, changed after it was registered, is still its own and says
        /// how it differs; registering again brings it back.
        #[test]
        fn a_changed_task_is_named_as_different_and_brought_back() {
            let host = TempHost::create();
            let definition = definition(&host, &harmless());
            let moved = TaskDefinition {
                starter: host.root().join("moved").join("kr-controller.exe"),
                ..definition.clone()
            };
            let _registered = Registered(definition.clone());
            register(&moved).expect("an installation that has since moved");
            let Standing::Owned(differences) = standing(&definition).expect("asked") else {
                panic!("the task is this environment's own");
            };
            assert_eq!(differences.len(), 1, "the program differs: {differences:?}");
            register(&definition).expect("brought back");
            assert_eq!(
                standing(&definition).expect("asked"),
                Standing::Owned(Vec::new())
            );
        }

        /// A registered task runs when it is asked; an absent one does not.
        #[test]
        fn a_registered_task_runs_when_asked_and_an_absent_one_does_not() {
            let host = TempHost::create();
            let definition = definition(&host, &harmless());
            assert!(
                run(&definition).is_err(),
                "nothing is registered under the name yet"
            );
            let _registered = Registered(definition.clone());
            register(&definition).expect("registered");
            run(&definition).expect("the run is started");
        }

        /// The task as the Task Scheduler exports it, which is what a change keeps of the task it
        /// changed.
        fn exported(definition: &TaskDefinition) -> String {
            let (standing, exported) =
                super::super::platform::read(definition).expect("the task is read");
            assert!(
                matches!(standing, Standing::Owned(_)),
                "it is the environment's own: {standing:?}"
            );
            exported
        }

        /// The setup step's change says what it did: a free name registered, the environment's own
        /// task left as it is when it is already the one asked for and registered again when it
        /// differs, keeping what it was; each of those is undone exactly; and a task that is not
        /// the environment's is refused and left as it is.
        #[test]
        fn a_setup_says_what_it_changed_and_that_is_undone_exactly() {
            let host = TempHost::create();
            let definition = definition(&host, &harmless());
            let _registered = Registered(definition.clone());

            let registered = set_up(&definition).expect("registered");
            assert_eq!(registered, TaskChange::Registered);
            assert_eq!(
                standing(&definition).expect("asked"),
                Standing::Owned(Vec::new())
            );
            assert_eq!(
                set_up(&definition).expect("asked again"),
                TaskChange::Unchanged,
                "the task already asked for is left as it is"
            );
            undo(&definition, &registered).expect("undone");
            assert_eq!(standing(&definition).expect("asked"), Standing::Absent);

            // An installation that has since moved: the environment's own task, stale.
            let moved = TaskDefinition {
                starter: host.root().join("moved").join("kr-controller.exe"),
                ..definition.clone()
            };
            set_up(&moved).expect("the earlier installation's task");
            let before = exported(&moved);
            let repaired = set_up(&definition).expect("repaired");
            let TaskChange::Repaired { prior } = &repaired else {
                panic!("the stale task is repaired: {repaired:?}");
            };
            assert_eq!(prior, &before, "and kept as it was");
            assert_eq!(
                standing(&definition).expect("asked"),
                Standing::Owned(Vec::new())
            );
            undo(&definition, &repaired).expect("undone");
            assert_eq!(
                exported(&moved),
                before,
                "the repaired task is put back exactly as it was"
            );
        }

        /// Clearing removes only the environment's own task, keeping what it was so the removal
        /// can be undone exactly; a free name is nothing to remove.
        #[test]
        fn a_clear_removes_only_the_environments_own_and_is_undone_exactly() {
            let host = TempHost::create();
            let definition = definition(&host, &harmless());
            let _registered = Registered(definition.clone());
            assert_eq!(clear(&definition).expect("asked"), TaskChange::Unchanged);
            set_up(&definition).expect("registered");
            let before = exported(&definition);
            let removed = clear(&definition).expect("removed");
            assert_eq!(
                removed,
                TaskChange::Removed {
                    prior: before.clone()
                }
            );
            assert_eq!(standing(&definition).expect("asked"), Standing::Absent);
            undo(&definition, &removed).expect("put back");
            assert_eq!(
                exported(&definition),
                before,
                "the removed task is put back exactly as it was"
            );
        }

        /// A task under the environment's name that is not its own is refused by the setup, the
        /// clear and the undo alike, and is left exactly as it is.
        #[test]
        fn another_environments_task_is_refused_by_every_change() {
            let host = TempHost::create();
            let ours = definition(&host, &harmless());
            let theirs = TaskDefinition {
                environment_id: EnvironmentId::new(kr_ipc::new_uuid()),
                ..ours.clone()
            };
            let _theirs = Registered(theirs.clone());
            let _ours = Registered(ours.clone());
            set_up(&theirs).expect("the other environment's task");
            let before = exported(&theirs);
            assert!(matches!(set_up(&ours), Err(TaskError::Foreign(_))));
            assert!(matches!(clear(&ours), Err(TaskError::Foreign(_))));
            assert!(matches!(
                undo(&ours, &TaskChange::Registered),
                Err(TaskError::Foreign(_))
            ));
            assert!(matches!(
                undo(&ours, &TaskChange::Removed { prior: ours.xml() }),
                Err(TaskError::Foreign(_))
            ));
            assert_eq!(exported(&theirs), before, "and it is exactly as it was");
        }

        /// A task that has not run says so, and once a run of it has ended its result is read.
        #[test]
        fn a_tasks_last_result_is_read_before_and_after_a_run() {
            let host = TempHost::create();
            let definition = definition(&host, &harmless());
            let _registered = Registered(definition.clone());
            set_up(&definition).expect("registered");
            assert_eq!(last_result(&definition).expect("read"), LastResult::NotRun);
            run(&definition).expect("the run is started");
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
            loop {
                match last_result(&definition).expect("read") {
                    // The stand-in program answers the starter's arguments with its own code;
                    // that a code is read at all is what is established here.
                    LastResult::Ended(_) => break,
                    running => assert!(
                        std::time::Instant::now() < deadline,
                        "the run ended within the bound: {running:?}"
                    ),
                }
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
        }
    }
}
