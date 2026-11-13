//! The two ways the installation talks to application control: PowerShell's own cmdlets, which
//! are the channel Windows supports for writing and reading the policy, and the platform's event
//! log, which says which rule refused a program.
//!
//! PowerShell runs by its absolute path with nothing from the caller's environment: its module
//! path is the system's alone, and its temporary directory and working directory are a directory
//! only administrators can write. The AppLocker module is imported by its system path. Only
//! inline commands run, never a script file. PowerShell is the installation's own channel and runs
//! in the setup program's process; the broker never reaches it.
//!
//! The event log is read by the broker's proof, so the program that reads it starts through the
//! broker's one launcher, under the broker's own token.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::env::EnvBlock;
use crate::events::{self, LogEvent};
use crate::policy::Policy;
use crate::quote::quote_command_line;
use crate::window::QueryEnd;

use super::launch::{LaunchError, Outcome, TokenSpec, VerifiedPath};
use super::pipe::Stop;
use super::proof::{Run, run_captured_until};

/// The application-control log that holds the executable collection's events.
const LOG: &str = "Microsoft-Windows-AppLocker/EXE and DLL";

/// What the script that writes the policy prints before the number of the log's newest record.
const RECORD_BEFORE_WRITE: &str = "newest-record-before-write=";

/// A failure to read or write the policy or the log.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A program could not be started.
    // text: applocker-1
    #[error("{what} could not be started: {source}")]
    Start {
        /// What was being started.
        what: &'static str,
        /// The reason.
        source: std::io::Error,
    },
    /// The file that carries the policy to PowerShell could not be made or written.
    // text: applocker-2
    #[error("{what} failed: {source}")]
    File {
        /// What was being done.
        what: &'static str,
        /// The reason.
        source: std::io::Error,
    },
    /// A program ended with a failure.
    // text: applocker-3
    #[error("{what} failed with {status}: {output}")]
    Failed {
        /// What was run.
        what: &'static str,
        /// How it ended.
        status: String,
        /// What it wrote.
        output: String,
    },
    /// A program did not end by its deadline.
    // text: applocker-4
    #[error("{what} did not end by its deadline")]
    TimedOut {
        /// What was run.
        what: &'static str,
        /// Whether the deadline the caller gave set that end, and not the run's own bound.
        by_the_deadline: bool,
    },
    /// The deadline the query was given had passed before it was made.
    // text: applocker-5
    #[error("the deadline passed before the event log was asked")]
    DeadlinePassed,
    /// A program of the proof was not started through the launcher, or its run through the
    /// launcher failed: the words say which, from what the launcher's error says.
    // text: applocker-6
    #[error("{what} {}: {source}", .source.outcome_words())]
    Launch {
        /// What was being started.
        what: &'static str,
        /// The reason.
        source: LaunchError,
        /// Whether the deadline that the query was given is the search's own, and not the query's
        /// bound of its own, which is the earlier of the two when it is the shorter.
        by_the_deadline: bool,
    },
    /// The answer could not be read.
    // text: applocker-7
    #[error("{0}")]
    Unreadable(String),
}

impl Error {
    /// How a query of the log came to an end as far as the search's end is concerned: a deadline that
    /// passed before the query was made, or before its program could start, and a query cut at the
    /// deadline it was given, are each told apart from every other failure.
    #[must_use]
    pub fn query_end(&self) -> QueryEnd {
        match self {
            Error::DeadlinePassed => QueryEnd::DeadlinePassed,
            Error::Launch {
                source: LaunchError::DeadlinePassed,
                by_the_deadline,
                ..
            } => crate::window::launch_deadline_end(*by_the_deadline),
            Error::TimedOut {
                by_the_deadline, ..
            } => QueryEnd::Cut {
                by_the_deadline: *by_the_deadline,
            },
            _ => QueryEnd::Failed,
        }
    }
}

/// The system's Windows directory from the platform's own call, never from the environment: an
/// unelevated session of the same account can set its own variables, and this installation runs
/// the PowerShell found there elevated. When the system cannot say, that is the failure: no fixed
/// folder takes its place.
fn system_root() -> std::io::Result<PathBuf> {
    super::ffi::system_windows_directory()
        .map(PathBuf::from)
        .map_err(|error| {
            std::io::Error::other(format!(
                "the system's Windows directory could not be read: {error}"
            ))
        })
}

/// The drive the system's Windows directory is on, as the system gives it, and never a fixed text.
fn system_drive(root: &Path) -> std::io::Result<std::ffi::OsString> {
    match root.components().next() {
        Some(std::path::Component::Prefix(prefix)) => Ok(prefix.as_os_str().to_owned()),
        _ => Err(std::io::Error::other(format!(
            "the system's Windows directory {} names no drive",
            root.display()
        ))),
    }
}

/// A command for a program that the installer starts. Its environment is emptied and holds only
/// values that the system gives (its Windows directory, the drive that directory is on, and the
/// path to its own programs), so a variable of the session that started the installer reaches no
/// program the installer runs elevated: a Git trace variable, for one, names a file that the
/// program would make or append to with the installer's rights. Its working directory is the
/// system's own program directory, which only the system and the administrators can change.
pub(super) fn trusted_command(program: impl AsRef<std::ffi::OsStr>) -> std::io::Result<Command> {
    let root = system_root()?;
    let system32 = root.join("System32");
    let mut command = Command::new(program);
    command
        .env_clear()
        .env("SystemRoot", &root)
        .env("windir", &root)
        .env("SystemDrive", system_drive(&root)?)
        .env("PATH", &system32)
        .current_dir(&system32);
    Ok(command)
}

/// The directory of the modules that ship with Windows PowerShell, the only place it is told to load
/// modules from.
fn powershell_modules() -> std::io::Result<PathBuf> {
    Ok(system_root()?
        .join("System32")
        .join("WindowsPowerShell")
        .join("v1.0")
        .join("Modules"))
}

/// Runs PowerShell, the installation's channel, and returns what it wrote.
fn run(
    program: &Path,
    arguments: &[&str],
    scratch: &Path,
    what: &'static str,
) -> Result<String, Error> {
    let powershell_modules =
        powershell_modules().map_err(|source| Error::Start { what, source })?;
    // PowerShell's temporary directory and working directory are a new directory of its own, made
    // with its descriptor, and removed when the run ends: nothing it leaves is ever in the staging
    // directory itself.
    let shell = ShellDirectory::new(scratch).map_err(|source| Error::Start { what, source })?;
    let output = trusted_command(program)
        .map_err(|source| Error::Start { what, source })?
        .args(arguments)
        .env("PSModulePath", &powershell_modules)
        .env("TEMP", &shell.0)
        .env("TMP", &shell.0)
        .current_dir(&shell.0)
        .stdin(Stdio::null())
        .output()
        .map_err(|source| Error::Start { what, source })?;
    let text = String::from_utf8_lossy(&output.stdout).into_owned();
    if output.status.success() {
        Ok(text)
    } else {
        Err(Error::Failed {
            what,
            status: output.status.to_string(),
            output: format!(
                "{} {}",
                text.trim(),
                String::from_utf8_lossy(&output.stderr).trim()
            ),
        })
    }
}

/// The directory a PowerShell run uses for its temporary files: new, random, owned by the
/// administrators and removed when the run is over.
struct ShellDirectory(PathBuf);

impl ShellDirectory {
    fn new(under: &Path) -> std::io::Result<ShellDirectory> {
        super::fresh::directory(
            under,
            "shell",
            super::sd::SdKind::AdminDir,
            &super::sd::Principals::default(),
        )
        .map(ShellDirectory)
    }
}

impl Drop for ShellDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The channel to application control, working in a directory only administrators can write.
pub struct Channel {
    scratch: PathBuf,
}

impl Channel {
    /// A channel that uses the directory for its files and its temporary space.
    #[must_use]
    pub fn new(scratch: &Path) -> Channel {
        Channel {
            scratch: scratch.to_owned(),
        }
    }

    fn powershell(&self, command: &str) -> Result<String, Error> {
        let start = |source| Error::Start {
            what: "PowerShell",
            source,
        };
        let program = system_root()
            .map_err(start)?
            .join("System32")
            .join("WindowsPowerShell")
            .join("v1.0")
            .join("powershell.exe");
        let modules = powershell_modules().map_err(start)?;
        let module = modules.join("AppLocker").join("AppLocker.psd1");
        // PowerShell can add a module folder of the person's own to the module path when it
        // starts; the path is set again to the system's own before any module is loaded, and the
        // AppLocker module is loaded by its path.
        let script = format!(
            "$ErrorActionPreference = 'Stop'; $env:PSModulePath = '{}'; Import-Module -Name '{}'; {command}",
            modules.display(),
            module.display()
        );
        run(
            &program,
            &[
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                &script,
            ],
            &self.scratch,
            "PowerShell",
        )
    }

    /// The policy the platform reports as in force, as its own text and in the crate's form.
    ///
    /// # Errors
    ///
    /// Returns an error when PowerShell fails or its answer is not a policy.
    pub fn effective(&self) -> Result<(String, Policy), Error> {
        let text = self.powershell("Get-AppLockerPolicy -Effective -Xml")?;
        let xml = text.trim().to_owned();
        let policy = Policy::parse(&xml).map_err(|error| Error::Unreadable(error.to_string()))?;
        Ok((xml, policy))
    }

    /// Replaces the local policy with the XML given, and returns the number of the newest record of
    /// the application-control log as the same PowerShell process read it right before it wrote the
    /// policy (zero for an empty log). An event with a larger number came after the write began, so
    /// the number is the one a wait for the platform's report of the policy starts from: no other
    /// process reads it, and nothing happens between the read and the write but PowerShell's own
    /// next statement.
    ///
    /// # Errors
    ///
    /// Returns an error when the file cannot be written, PowerShell refuses the policy or the log,
    /// or its answer does not name a record.
    pub fn set(&self, xml: &str) -> Result<u64, Error> {
        // PowerShell reads the policy by its path, so the file is one that did not exist: a random
        // name, made in the directory the installation checked, owned by the administrators in the
        // call that makes it. A file that another account owned or held open could be changed
        // between this write and PowerShell's read.
        let (mut made, file) = super::fresh::named_file(
            &self.scratch,
            "policy",
            ".xml",
            super::sd::SdKind::AdminFile,
        )
        .map_err(|source| Error::File {
            what: "making the policy file",
            source,
        })?;
        let written = made
            .write_all(xml.as_bytes())
            .and_then(|()| made.sync_all());
        drop(made);
        if let Err(source) = written {
            let _ = std::fs::remove_file(&file);
            return Err(Error::File {
                what: "writing the policy file",
                source,
            });
        }
        // An empty log answers with its own error, which is the answer zero; any other error stops
        // the script before the policy is written.
        let text = self.powershell(&format!(
            "$newest = 0; try {{ $newest = [int64](Get-WinEvent -LogName '{LOG}' -MaxEvents 1 -ErrorAction Stop).RecordId }} catch {{ if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') {{ throw }} }}; Set-AppLockerPolicy -XmlPolicy '{}'; Write-Output \"{RECORD_BEFORE_WRITE}$newest\"",
            file.display()
        ));
        // The file served its read: it is removed whatever PowerShell said.
        let _ = std::fs::remove_file(&file);
        let text = text?;
        #[expect(
            clippy::disallowed_methods,
            reason = "a record number that is not a number ends in Error::Unreadable at once; no default stands in for it"
        )]
        let record = text
            .lines()
            .find_map(|line| line.trim().strip_prefix(RECORD_BEFORE_WRITE))
            .and_then(|number| number.trim().parse().ok());
        record.ok_or_else(|| {
                Error::Unreadable(format!(
                    "PowerShell did not say which record the log ended at before the policy was written: {}",
                    text.trim()
                ))
            })
    }
}

/// The longest one query of the event log may take, when the deadline leaves that long.
const QUERY_BOUND: Duration = Duration::from_secs(60);

/// Runs the event log tool with the arguments and returns what it wrote. The query runs no longer
/// than the time left before the deadline, and none starts after it.
fn wevtutil(
    arguments: &[&str],
    scratch: &Path,
    env: &EnvBlock,
    deadline: Instant,
    stop: Option<&Stop>,
) -> Result<String, Error> {
    let what = "the event log query";
    if Instant::now() >= deadline {
        return Err(Error::DeadlinePassed);
    }
    let bound = crate::window::bound(deadline, Instant::now() + QUERY_BOUND);
    let program = system_root()
        .map_err(|source| Error::Start { what, source })?
        .join("System32")
        .join("wevtutil.exe");
    let name = program.display().to_string();
    let mut parts = vec![name.as_str()];
    parts.extend_from_slice(arguments);
    let launch_error = |source| Error::Launch {
        what,
        source,
        by_the_deadline: bound.by_the_window,
    };
    let program = VerifiedPath::new(&program).map_err(launch_error)?;
    let captured = run_captured_until(
        Run {
            token: TokenSpec::Own,
            group: None,
            program,
            command_line: quote_command_line(&parts),
            cwd: scratch,
            env,
        },
        bound.by,
        stop,
    )
    .map_err(launch_error)?;
    let text = String::from_utf8_lossy(&captured.stdout).into_owned();
    match captured.outcome {
        Outcome::Ran(0) => Ok(text),
        Outcome::TimedOut => Err(Error::TimedOut {
            what,
            by_the_deadline: bound.by_the_window,
        }),
        other => Err(Error::Failed {
            what,
            status: format!("{other:?}"),
            output: format!(
                "{} {}",
                text.trim(),
                String::from_utf8_lossy(&captured.stderr).trim()
            ),
        }),
    }
}

fn query(
    extra: &[&str],
    scratch: &Path,
    env: &EnvBlock,
    deadline: Instant,
    stop: Option<&Stop>,
) -> Result<Vec<LogEvent>, Error> {
    let mut arguments = vec!["qe", LOG, "/f:xml", "/e:Events"];
    arguments.extend_from_slice(extra);
    let text = wevtutil(&arguments, scratch, env, deadline, stop)?;
    events::parse(&text).map_err(|error| Error::Unreadable(error.to_string()))
}

/// What the log last said, in a few words, for the text of a proof that did not succeed.
///
/// # Errors
///
/// Returns an error when the query fails.
pub fn latest(
    scratch: &Path,
    env: &EnvBlock,
    deadline: Instant,
    stop: Option<&Stop>,
) -> Result<String, Error> {
    let text = wevtutil(
        &["qe", LOG, "/c:3", "/rd:true", "/f:text"],
        scratch,
        env,
        deadline,
        stop,
    )?;
    let words: Vec<&str> = text.split_whitespace().collect();
    let flat = words.join(" ");
    Ok(if flat.is_empty() {
        "nothing".to_owned()
    } else {
        flat.chars().take(700).collect()
    })
}

/// The newest record number in the log, or zero when it is empty. A failed query is an error: an
/// empty log and a log that could not be read are not the same answer.
///
/// # Errors
///
/// Returns an error when the query fails or its answer cannot be read.
pub fn newest_record(scratch: &Path, env: &EnvBlock, deadline: Instant) -> Result<u64, Error> {
    newest_record_until(scratch, env, deadline, None)
}

/// [`newest_record`] for a request of the broker's service: the query ends at the stop, with the
/// error of a query that ran out of time, and the caller looks at the stop to tell the two apart.
///
/// # Errors
///
/// As for [`newest_record`].
pub fn newest_record_until(
    scratch: &Path,
    env: &EnvBlock,
    deadline: Instant,
    stop: Option<&Stop>,
) -> Result<u64, Error> {
    let events = query(&["/c:1", "/rd:true"], scratch, env, deadline, stop)?;
    Ok(events.iter().map(|event| event.record).max().unwrap_or(0))
}

/// The record number of the platform's first "policy applied" event after a record number, when the
/// log holds one.
///
/// # Errors
///
/// Returns an error when the query fails or its answer cannot be read.
pub fn policy_applied_after(
    record: u64,
    scratch: &Path,
    env: &EnvBlock,
    deadline: Instant,
) -> Result<Option<u64>, Error> {
    let filter = format!(
        "/q:*[System[(EventID={}) and (EventRecordID>{record})]]",
        events::APPLIED
    );
    Ok(query(&[&filter, "/c:1"], scratch, env, deadline, None)?
        .first()
        .map(|event| event.record))
}

/// The refusals the log has recorded after a record number.
///
/// # Errors
///
/// Returns an error when the query fails or its answer cannot be read.
pub fn blocked_after(
    record: u64,
    scratch: &Path,
    env: &EnvBlock,
    deadline: Instant,
    stop: Option<&Stop>,
) -> Result<Vec<LogEvent>, Error> {
    let filter = format!(
        "/q:*[System[(EventID={}) and (EventRecordID>{record})]]",
        events::BLOCKED
    );
    query(&[&filter], scratch, env, deadline, stop)
}
