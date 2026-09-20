//! Asking the platform about an enrolled environment, and starting one.
//!
//! Each command here is the one [`crate::bridge::launch`] names, run as an argument vector. The
//! observations are read from what the platform printed; nothing is inferred from an exit status
//! alone, because a runtime that is not installed and a container that is stopped both exit
//! non-zero and mean different things.

use std::process::{Command, Stdio};

use kr_protocol::identity::{EnvironmentAccess, EnvironmentEnrolment, EnvironmentPresence};

use crate::bridge::launch::{self, CONTAINER_RUNTIME};
use crate::bridge::store::Observer;
use crate::error::{ControllerError, Result};

/// The observer that runs the platform's own commands.
#[derive(Clone, Copy, Debug, Default)]
pub struct PlatformObserver;

impl Observer for PlatformObserver {
    fn observe(&self, enrolment: &EnvironmentEnrolment) -> Result<EnvironmentPresence> {
        let command = launch::observe(enrolment)
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?;
        let output = run(&command.program, &command.arguments)?;
        match enrolment.access {
            EnvironmentAccess::WslDistribution => Ok(wsl_state(&output.text, &enrolment.target)),
            EnvironmentAccess::Container => Ok(container_state(&output)),
            EnvironmentAccess::SshHost | EnvironmentAccess::PairedHost => {
                Err(ControllerError::InvalidArgument(
                    "an SSH or paired environment is not observed through a process bridge"
                        .to_owned(),
                ))
            }
        }
    }

    fn start(&self, enrolment: &EnvironmentEnrolment) -> Result<()> {
        let command = launch::start(enrolment)
            .map_err(|error| ControllerError::InvalidArgument(error.to_string()))?;
        let output = run(&command.program, &command.arguments)?;
        if output.code == Some(0) {
            return Ok(());
        }
        Err(ControllerError::supervision(format!(
            "{} could not be started: {}",
            enrolment.label,
            output.text.trim()
        )))
    }
}

/// What one platform command produced.
#[derive(Clone, Debug)]
pub struct CommandOutput {
    /// The exit code, where the platform reported one.
    pub code: Option<i32>,
    /// Standard output and standard error together, as text.
    pub text: String,
}

/// Runs one argument vector and collects what it printed.
///
/// # Errors
///
/// Returns a resource failure when the program is not installed or could not be run. A program
/// that runs and exits non-zero is not a failure here: its output is what says what it found.
pub fn run(program: &str, arguments: &[String]) -> Result<CommandOutput> {
    let output = Command::new(program)
        .args(arguments)
        .stdin(Stdio::null())
        .output()
        .map_err(|error| {
            ControllerError::supervision(format!("{program} could not be run: {error}"))
        })?;
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    // WSL writes its listing as UTF-16 on some builds, so a lossy read of it is a string with a
    // NUL between every character. Dropping those is enough to read a state from it, and it never
    // changes a string that was not encoded that way.
    text.retain(|character| character != '\0');
    text.push_str(&String::from_utf8_lossy(&output.stderr).replace('\0', ""));
    Ok(CommandOutput {
        code: output.status.code(),
        text,
    })
}

/// Returns whether this host has the container runtime an enrolled container needs.
///
/// A host without it can still list and forget its enrolled containers: what it cannot do is
/// observe or start one, and the answer says so by name rather than reporting the container
/// stopped.
#[must_use]
pub fn container_runtime_present() -> bool {
    Command::new(CONTAINER_RUNTIME)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// Reads one distribution's state out of `wsl.exe --list --verbose`.
///
/// The listing is one distribution per line: an optional `*` for the default, the name, the state
/// and the version. A name that is not in the listing is not registered, which is reported as
/// stale rather than as stopped: this host has not observed it at all.
fn wsl_state(listing: &str, target: &str) -> EnvironmentPresence {
    for line in listing.lines() {
        let mut fields = line.trim_start().trim_start_matches('*').split_whitespace();
        let Some(name) = fields.next() else {
            continue;
        };
        if name != target {
            continue;
        }
        return match fields.next() {
            Some("Running") => EnvironmentPresence::Running,
            Some("Stopped" | "Installing" | "Converting") => {
                EnvironmentPresence::EnvironmentStopped
            }
            _ => EnvironmentPresence::Stale,
        };
    }
    EnvironmentPresence::Stale
}

/// Reads a container's state out of `podman container inspect --format {{.State.Running}}`.
///
/// A container that exists answers `true` or `false`. A container that does not exist makes the
/// runtime exit non-zero, and this host has then observed nothing about the identity it enrolled,
/// which is stale rather than stopped.
fn container_state(output: &CommandOutput) -> EnvironmentPresence {
    if output.code != Some(0) {
        return EnvironmentPresence::Stale;
    }
    match output.text.trim() {
        "true" => EnvironmentPresence::Running,
        "false" => EnvironmentPresence::EnvironmentStopped,
        _ => EnvironmentPresence::Stale,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LISTING: &str = "  NAME            STATE           VERSION\n\
                           * Ubuntu-24.04    Running         2\n\
                             Debian          Stopped         2\n";

    #[test]
    fn a_running_distribution_is_read_from_the_listing() {
        assert_eq!(
            wsl_state(LISTING, "Ubuntu-24.04"),
            EnvironmentPresence::Running
        );
    }

    #[test]
    fn a_stopped_distribution_is_reported_as_stopped_rather_than_absent() {
        assert_eq!(
            wsl_state(LISTING, "Debian"),
            EnvironmentPresence::EnvironmentStopped
        );
    }

    #[test]
    fn a_distribution_that_is_not_registered_is_stale_rather_than_stopped() {
        // This host has observed nothing about it. Reporting it stopped would claim an
        // observation that was never made.
        assert_eq!(wsl_state(LISTING, "Fedora"), EnvironmentPresence::Stale);
    }

    #[test]
    fn a_name_that_is_a_prefix_of_another_is_not_matched() {
        assert_eq!(wsl_state(LISTING, "Ubuntu"), EnvironmentPresence::Stale);
    }

    #[test]
    fn a_listing_written_as_utf16_reads_the_same_once_its_nulls_are_dropped() {
        let wide: String = LISTING.chars().flat_map(|c| [c, '\0']).collect();
        let cleaned: String = wide.chars().filter(|c| *c != '\0').collect();
        assert_eq!(
            wsl_state(&cleaned, "Ubuntu-24.04"),
            EnvironmentPresence::Running
        );
    }

    #[test]
    fn a_container_answers_running_stopped_or_nothing_at_all() {
        let running = CommandOutput {
            code: Some(0),
            text: "true\n".to_owned(),
        };
        let stopped = CommandOutput {
            code: Some(0),
            text: "false\n".to_owned(),
        };
        let absent = CommandOutput {
            code: Some(125),
            text: "no such container\n".to_owned(),
        };
        assert_eq!(container_state(&running), EnvironmentPresence::Running);
        assert_eq!(
            container_state(&stopped),
            EnvironmentPresence::EnvironmentStopped
        );
        assert_eq!(container_state(&absent), EnvironmentPresence::Stale);
    }
}
