//! The two ways the installation talks to application control: PowerShell's own cmdlets, which
//! are the channel Windows supports for writing and reading the policy, and the platform's event
//! log, which says which rule refused a program.
//!
//! PowerShell runs by its absolute path with nothing from the caller's environment: its module
//! path is the system's alone, and its temporary directory and working directory are a directory
//! only administrators can write. The AppLocker module is imported by its system path. Only
//! inline commands run, never a script file.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::events::{self, LogEvent};
use crate::policy::Policy;

/// The application-control log that holds the executable collection's events.
const LOG: &str = "Microsoft-Windows-AppLocker/EXE and DLL";

/// A failure to read or write the policy or the log.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A program could not be started.
    #[error("{what} could not be started: {source}")]
    Start {
        /// What was being started.
        what: &'static str,
        /// The reason.
        source: std::io::Error,
    },
    /// A program ended with a failure.
    #[error("{what} failed with {status}: {output}")]
    Failed {
        /// What was run.
        what: &'static str,
        /// How it ended.
        status: String,
        /// What it wrote.
        output: String,
    },
    /// The answer could not be read.
    #[error("{0}")]
    Unreadable(String),
}

fn system_root() -> PathBuf {
    PathBuf::from(std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into()))
}

fn run(
    program: &Path,
    arguments: &[&str],
    scratch: &Path,
    what: &'static str,
) -> Result<String, Error> {
    let root = system_root();
    let system32 = root.join("System32");
    let powershell_modules = system32
        .join("WindowsPowerShell")
        .join("v1.0")
        .join("Modules");
    let output = Command::new(program)
        .args(arguments)
        .env_clear()
        .env("SystemRoot", &root)
        .env("windir", &root)
        .env("SystemDrive", "C:")
        .env("PATH", &system32)
        .env("PSModulePath", &powershell_modules)
        .env("TEMP", scratch)
        .env("TMP", scratch)
        .current_dir(scratch)
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
        let program = system_root()
            .join("System32")
            .join("WindowsPowerShell")
            .join("v1.0")
            .join("powershell.exe");
        let module = system_root()
            .join("System32")
            .join("WindowsPowerShell")
            .join("v1.0")
            .join("Modules")
            .join("AppLocker")
            .join("AppLocker.psd1");
        let script = format!(
            "$ErrorActionPreference = 'Stop'; Import-Module -Name '{}'; {command}",
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

    /// Replaces the local policy with the XML given.
    ///
    /// # Errors
    ///
    /// Returns an error when the file cannot be written or PowerShell refuses the policy.
    pub fn set(&self, xml: &str) -> Result<(), Error> {
        let file = self.scratch.join("policy.xml");
        std::fs::write(&file, xml).map_err(|source| Error::Start {
            what: "writing the policy file",
            source,
        })?;
        self.powershell(&format!(
            "Set-AppLockerPolicy -XmlPolicy '{}'",
            file.display()
        ))?;
        Ok(())
    }
}

fn query(extra: &[&str], scratch: &Path) -> Result<Vec<LogEvent>, Error> {
    let program = system_root().join("System32").join("wevtutil.exe");
    let mut arguments = vec!["qe", LOG, "/f:xml", "/e:Events"];
    arguments.extend_from_slice(extra);
    let text = run(&program, &arguments, scratch, "the event log query")?;
    events::parse(&text).map_err(|error| Error::Unreadable(error.to_string()))
}

/// The newest record number in the log, or zero when it is empty. A failed query is an error: an
/// empty log and a log that could not be read are not the same answer.
///
/// # Errors
///
/// Returns an error when the query fails or its answer cannot be read.
pub fn newest_record(scratch: &Path) -> Result<u64, Error> {
    let events = query(&["/c:1", "/rd:true"], scratch)?;
    Ok(events.iter().map(|event| event.record).max().unwrap_or(0))
}

/// The refusals the log has recorded after a record number.
///
/// # Errors
///
/// Returns an error when the query fails or its answer cannot be read.
pub fn blocked_after(record: u64, scratch: &Path) -> Result<Vec<LogEvent>, Error> {
    let filter = format!(
        "/q:*[System[(EventID={}) and (EventRecordID>{record})]]",
        events::BLOCKED
    );
    query(&[&filter], scratch)
}
