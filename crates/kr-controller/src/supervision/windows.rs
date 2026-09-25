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
        let user = self.user.trim();
        let same_user = if user.starts_with("S-1-") {
            user.eq_ignore_ascii_case(&expected.user)
        } else {
            sid_of(user).is_some_and(|sid| sid.eq_ignore_ascii_case(&expected.user))
        };
        same_user && self.description.trim() == expected.description()
    }

    /// What makes this task something other than the one `expected` registers, if anything: its
    /// program, what it gives it, the directory, the settings a starter depends on, a trigger, or
    /// a logon this host does not register. Empty when it is the task this build expects.
    #[must_use]
    pub fn differences(&self, expected: &TaskDefinition) -> Vec<String> {
        let mut differences = Vec::new();
        if !same_path(&self.command, &expected.starter) {
            differences.push(format!(
                "it runs {}, not {}",
                self.command,
                expected.starter.display()
            ));
        }
        if self.arguments.trim() != expected.arguments {
            differences.push(format!(
                "it gives the starter {:?}, not {:?}",
                self.arguments, expected.arguments
            ));
        }
        if !same_path(&self.working_directory, &expected.working_directory) {
            differences.push(format!(
                "it runs in {}, not {}",
                self.working_directory,
                expected.working_directory.display()
            ));
        }
        if self.actions != 1 {
            differences.push(format!("it has {} actions, not one", self.actions));
        }
        if self.triggered {
            differences.push("it has a trigger, so it runs without being asked".to_owned());
        }
        if self.logon != Some(expected.logon) {
            differences.push(format!(
                "it logs on as {}, not {}",
                self.logon
                    .map_or("something this host does not register", LogonType::as_str),
                expected.logon.as_str()
            ));
        }
        let run_level = self.run_level.trim();
        if !run_level.is_empty() && run_level != "LeastPrivilege" {
            differences.push(format!(
                "it runs at {run_level}, not with the least privilege"
            ));
        }
        for (differs, what) in [
            (
                self.disallow_start_on_batteries,
                "it does not start on batteries",
            ),
            (
                self.stop_going_on_batteries,
                "it stops when the machine goes on batteries",
            ),
            (self.run_only_if_idle, "it waits for the machine to be idle"),
            (
                self.stop_on_idle_end,
                "it stops when the machine stops being idle",
            ),
            (self.run_only_if_network, "it waits for a network"),
            (!self.start_on_demand, "it may not be run when asked"),
        ] {
            if differs {
                differences.push(what.to_owned());
            }
        }
        if self.multiple_instances.trim() != "Parallel" {
            differences.push(format!(
                "a second run while one is running is {:?}, not in parallel",
                self.multiple_instances
            ));
        }
        if self.execution_time_limit.trim() != "PT0S" {
            differences.push(format!(
                "its runs are limited to {:?}",
                self.execution_time_limit
            ));
        }
        if self.priority.trim() != "5" {
            differences.push(format!(
                "it runs at priority {:?}, not the normal 5",
                self.priority
            ));
        }
        if !self.enabled {
            differences.push("it is disabled".to_owned());
        }
        differences
    }
}

/// Whether two Windows paths name the same place: case and the separator do not matter there.
fn same_path(written: &str, expected: &Path) -> bool {
    let normal = |text: &str| text.trim().replace('/', "\\").to_lowercase();
    normal(written) == normal(&expected.display().to_string())
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
    Foreign(String),
    /// The environment's own task, with what makes it other than the one this build registers:
    /// empty when it is exactly that one.
    Owned(Vec<String>),
}

#[cfg(windows)]
pub use self::platform::{register, remove, run, standing};

/// The calls to the Task Scheduler, through `schtasks.exe` from the system directory.
#[cfg(windows)]
mod platform {
    use super::{RegisteredTask, Standing, TaskDefinition, decode_output};
    use crate::supervision::{RunFailure, SERVICE_MANAGER_BOUND, command_within};

    /// The Task Scheduler's command, from the system directory and never from the search path.
    fn schtasks() -> std::path::PathBuf {
        let root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
        std::path::Path::new(&root)
            .join("System32")
            .join("schtasks.exe")
    }

    /// Runs one Task Scheduler command within the service-manager bound.
    fn schtasks_within(arguments: &[&str]) -> Result<std::process::Output, RunFailure> {
        let program = schtasks();
        command_within(
            &program.display().to_string(),
            arguments,
            SERVICE_MANAGER_BOUND,
        )
    }

    /// Reads where `definition`'s task stands: absent, another's, or this environment's own and how
    /// it differs from `definition`.
    ///
    /// # Errors
    ///
    /// Returns what went wrong when the Task Scheduler could not be asked, or answered with
    /// something other than a task or its absence.
    pub fn standing(definition: &TaskDefinition) -> Result<Standing, String> {
        let output = schtasks_within(&["/Query", "/TN", &definition.name, "/XML"])
            .map_err(|failure| failure.detail())?;
        if !output.status.success() {
            // Why it could not be read is said in the machine's own language, so it is not read.
            // The list of every task this user can see says whether the name is held at all.
            let said = decode_output(&output.stderr);
            if !is_listed(&definition.name)? {
                return Ok(Standing::Absent);
            }
            return Ok(Standing::Foreign(format!(
                "a task named {} is registered and this user cannot read it ({})",
                definition.name,
                said.trim()
            )));
        }
        let registered = RegisteredTask::parse(&decode_output(&output.stdout));
        let sid_of = |name: &str| kr_ipc::starter::account_sid(name).ok();
        if !registered.belongs_to(definition, sid_of) {
            return Ok(Standing::Foreign(format!(
                "a task named {} is registered for {} with the description {:?}, which is not \
                 this user's task for environment {}",
                definition.name,
                registered.user.trim(),
                registered.description.trim(),
                definition.environment_id
            )));
        }
        Ok(Standing::Owned(registered.differences(definition)))
    }

    /// Whether a task named `name` is in the Task Scheduler's root folder, as this user sees it.
    fn is_listed(name: &str) -> Result<bool, String> {
        let output = schtasks_within(&["/Query", "/FO", "CSV", "/NH"])
            .map_err(|failure| failure.detail())?;
        if !output.status.success() {
            return Err(format!(
                "the Task Scheduler could not list its tasks: {}",
                decode_output(&output.stderr).trim()
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
    fn registration_lock(name: &str) -> Result<kr_ipc::starter::NamedLock, String> {
        kr_ipc::starter::NamedLock::acquire(
            &format!("Global\\{name}-registration"),
            REGISTRATION_BOUND,
        )
        .map_err(|error| format!("the registration of {name} could not be locked: {error}"))
    }

    /// Registers `definition`, or brings this environment's own task back to it.
    ///
    /// A task of the same name that is not this environment's is refused and left as it is. The
    /// definition is written to a UTF-16 file in the environment's owner-only state directory for
    /// the Task Scheduler to read, and removed again. The task is read back afterwards and must be
    /// exactly the one registered.
    ///
    /// # Errors
    ///
    /// Returns what went wrong: a foreign task, a registration the Task Scheduler refused, or a
    /// task that did not read back as the one registered.
    pub fn register(definition: &TaskDefinition) -> Result<(), String> {
        let _lock = registration_lock(&definition.name)?;
        let replace = match standing(definition)? {
            Standing::Foreign(detail) => return Err(format!("{detail}, so it is left as it is")),
            Standing::Owned(_) => true,
            Standing::Absent => false,
        };
        if let Err(detail) = create_task(definition, replace) {
            // A creation refused because the name was taken meanwhile, by something that does not
            // take this lock, leaves that task as it is and says whose it is.
            return match standing(definition)? {
                Standing::Foreign(foreign) => Err(format!("{foreign}, so it is left as it is")),
                _ => Err(detail),
            };
        }
        match standing(definition)? {
            Standing::Owned(differences) if differences.is_empty() => Ok(()),
            Standing::Owned(differences) => Err(format!(
                "{} was registered and reads back differently: {}",
                definition.name,
                differences.join("; ")
            )),
            Standing::Absent => Err(format!(
                "{} was registered and cannot be found",
                definition.name
            )),
            Standing::Foreign(detail) => Err(detail),
        }
    }

    /// Registers `definition` through the Task Scheduler.
    ///
    /// `replace` says the task under the name is this environment's own, found so under the
    /// registration lock, and is replaced. Otherwise the name was free when it was looked at, and
    /// the creation takes it only if it still is: a definition given as XML without `/F` is
    /// registered as a new task and refused when the name is held, so a task something else made
    /// in the meantime is never replaced.
    pub(super) fn create_task(definition: &TaskDefinition, replace: bool) -> Result<(), String> {
        let file = definition
            .working_directory
            .join(format!("{}.xml", definition.name));
        let mut bytes = vec![0xff, 0xfe];
        bytes.extend(definition.xml().encode_utf16().flat_map(u16::to_le_bytes));
        kr_ipc::paths::write_owner_only_file(&file, &bytes)
            .map_err(|error| format!("write the definition of {}: {error}", definition.name))?;
        let file_text = file.display().to_string();
        let mut arguments = vec!["/Create", "/TN", &definition.name, "/XML", &file_text];
        if replace {
            arguments.push("/F");
        }
        let created = schtasks_within(&arguments);
        let _ = std::fs::remove_file(&file);
        let output = created.map_err(|failure| failure.detail())?;
        if !output.status.success() {
            return Err(format!(
                "the Task Scheduler did not register {}: {}",
                definition.name,
                decode_output(&output.stderr).trim()
            ));
        }
        Ok(())
    }

    /// Removes this environment's own task, and says whether there was one.
    ///
    /// A task of the same name that is not this environment's is refused and left as it is.
    /// Removing a task leaves every process it started running: only ending a run would end them,
    /// and this host never ends one.
    ///
    /// # Errors
    ///
    /// Returns what went wrong: a foreign task, or a removal the Task Scheduler refused.
    pub fn remove(definition: &TaskDefinition) -> Result<bool, String> {
        let _lock = registration_lock(&definition.name)?;
        match standing(definition)? {
            Standing::Absent => return Ok(false),
            Standing::Foreign(detail) => return Err(format!("{detail}, so it is left as it is")),
            Standing::Owned(_) => {}
        }
        let output = schtasks_within(&["/Delete", "/TN", &definition.name, "/F"])
            .map_err(|failure| failure.detail())?;
        if !output.status.success() {
            return Err(format!(
                "the Task Scheduler did not remove {}: {}",
                definition.name,
                decode_output(&output.stderr).trim()
            ));
        }
        Ok(true)
    }

    /// Asks the Task Scheduler to run `definition`'s task once, now.
    ///
    /// # Errors
    ///
    /// Returns [`RunFailure::NotRun`] when the Task Scheduler could not be asked, and
    /// [`RunFailure::Failed`] when it was asked and did not start the run, which it may have begun
    /// first.
    pub fn run(definition: &TaskDefinition) -> Result<(), RunFailure> {
        let output = schtasks_within(&["/Run", "/I", "/TN", &definition.name])?;
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
                        differences.join("; ")
                    ));
                }
                Ok(Standing::Absent) => {
                    return not_started(format!(
                        "the environment has no task to start workers: {SETUP_ACTION}"
                    ));
                }
                Ok(Standing::Foreign(detail)) => {
                    return not_started(format!("{detail}: {SETUP_ACTION} for this environment"));
                }
                Err(detail) => return not_started(detail),
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
            register(&definition)?;
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
        assert_eq!(read.differences(&definition), Vec::<String>::new());
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
            Vec::<String>::new(),
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

    /// Markup characters in a path survive being written into the definition and read back.
    #[test]
    fn a_path_with_markup_characters_survives_the_definition() {
        let host = TempHost::create();
        let odd = host.root().join("R&D <'tools'>").join("kr-controller.exe");
        let definition = TaskDefinition::for_setup(USER, &host.environment(), &odd);
        let read = RegisteredTask::parse(&definition.xml());
        assert_eq!(read.command, odd.display().to_string());
        assert_eq!(read.differences(&definition), Vec::<String>::new());
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
    }
}
