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
        todo!("not built yet")
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
        todo!("not built yet")
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
    /// Whether it is enabled, when the export says; absent is the default, enabled.
    pub enabled: String,
    /// How many actions it has.
    pub actions: usize,
    /// Whether it has a trigger, which would run it without its being asked.
    pub triggered: bool,
}

impl RegisteredTask {
    /// Reads a task's exported XML.
    ///
    /// Only the fields this host decides on are read. An element the export leaves out is read as
    /// empty, which the checks below treat as the Task Scheduler's default where the default is
    /// what this host writes and as a difference otherwise.
    #[must_use]
    pub fn parse(xml: &str) -> Self {
        todo!("not built yet")
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
        todo!("not built yet")
    }

    /// What makes this task something other than the one `expected` registers, if anything: its
    /// program, what it gives it, the directory, the settings a starter depends on, a trigger, or
    /// a logon this host does not register. Empty when it is the task this build expects.
    #[must_use]
    pub fn differences(&self, expected: &TaskDefinition) -> Vec<String> {
        todo!("not built yet")
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
    todo!("not built yet")
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
        todo!("not built yet")
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
        todo!("not built yet")
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
        todo!("not built yet")
    }

    /// Asks the Task Scheduler to run `definition`'s task once, now.
    ///
    /// # Errors
    ///
    /// Returns [`RunFailure::NotRun`] when the Task Scheduler could not be asked, and
    /// [`RunFailure::Failed`] when it was asked and did not start the run, which it may have begun
    /// first.
    pub fn run(definition: &TaskDefinition) -> Result<(), RunFailure> {
        todo!("not built yet")
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
    /// program, what it gives it, the directory, a second action, a trigger, a logon this host
    /// does not register, and each setting the starter depends on.
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
            let _registered = Registered(theirs.clone());
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
