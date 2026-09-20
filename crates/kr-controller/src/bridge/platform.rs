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

/// Asks the platform whether one destination is running, before there is a record naming it.
///
/// Enrolment needs this: asking a destination which environment it is means running the helper
/// inside it, and running anything inside a stopped distribution starts it. Observing starts
/// nothing, so the question can be put first.
///
/// # Errors
///
/// Returns an invalid-argument failure for an access class that is not a process bridge, and a
/// supervision failure when the platform's own command could not be run.
pub fn destination_state(
    access: EnvironmentAccess,
    target: &str,
    os_user: &str,
    helper_path: &str,
) -> Result<EnvironmentPresence> {
    let enrolment = EnvironmentEnrolment {
        // The identity is what enrolment is about to learn. Nothing below reads it: the platform is
        // asked about the target, which is the name it knows.
        environment_id: kr_protocol::ids::EnvironmentId::new(
            kr_protocol::scalars::Uuid::from_bytes([0; 16]),
        ),
        access,
        label: target.to_owned(),
        target: target.to_owned(),
        os_user: os_user.to_owned(),
        helper_path: helper_path.to_owned(),
        clipboard_destination: kr_protocol::scalars::Nullable::null(),
        approved_at_ms: kr_protocol::scalars::TimestampMs::new(0),
    };
    PlatformObserver.observe(&enrolment)
}

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

/// Decodes process output bytes, correctly handling UTF-16LE (with or without BOM) and UTF-8.
#[must_use]
pub fn decode_output(bytes: &[u8]) -> String {
    if bytes.len() >= 2 && bytes[0] == 0xff && bytes[1] == 0xfe {
        let u16s: Vec<u16> = bytes[2..]
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect();
        return char::decode_utf16(u16s)
            .map(|result| result.unwrap_or(char::REPLACEMENT_CHARACTER))
            .collect();
    }
    if bytes.len() >= 4 && bytes[1] == 0 && bytes[3] == 0 {
        let u16s: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect();
        return char::decode_utf16(u16s)
            .map(|result| result.unwrap_or(char::REPLACEMENT_CHARACTER))
            .collect();
    }
    String::from_utf8_lossy(bytes).into_owned()
}

/// How long a platform command is given before this host gives up on it.
///
/// These run while the enrolment record is locked, so a command that never returns would hold a
/// listing as well as the refresh that started it. Starting a distribution is the slowest of them
/// and takes seconds, not minutes.
pub const PLATFORM_LIMIT: std::time::Duration = std::time::Duration::from_secs(60);

/// Runs one argument vector, ending it when it outlasts `limit`.
///
/// The output is read on threads of its own, because a child that fills a pipe while nobody reads
/// it would wait for a reader that is itself waiting for the child.
fn run_bounded(
    program: &str,
    arguments: &[String],
    limit: std::time::Duration,
) -> Result<std::process::Output> {
    use std::io::Read;

    let mut child = Command::new(program)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| {
            ControllerError::supervision(format!("{program} could not be run: {error}"))
        })?;
    let mut out = child.stdout.take();
    let mut err = child.stderr.take();
    let reading_out = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        if let Some(stream) = out.as_mut() {
            let _ = stream.read_to_end(&mut bytes);
        }
        bytes
    });
    let reading_err = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        if let Some(stream) = err.as_mut() {
            let _ = stream.read_to_end(&mut bytes);
        }
        bytes
    });

    let deadline = std::time::Instant::now() + limit;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    // Only the child this call started, and by the handle it holds.
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
            Err(error) => {
                return Err(ControllerError::supervision(format!(
                    "{program} could not be waited for: {error}"
                )));
            }
        }
    };
    let stdout = reading_out.join().unwrap_or_default();
    let stderr = reading_err.join().unwrap_or_default();
    let Some(status) = status else {
        return Err(ControllerError::supervision(format!(
            "{program} said nothing for {} seconds and was ended",
            limit.as_secs()
        )));
    };
    Ok(std::process::Output {
        status,
        stdout,
        stderr,
    })
}

/// Runs one argument vector and collects what it printed.
///
/// # Errors
///
/// Returns a resource failure when the program is not installed or could not be run. A program
/// that runs and exits non-zero is not a failure here: its output is what says what it found.
pub fn run(program: &str, arguments: &[String]) -> Result<CommandOutput> {
    let output = run_bounded(program, arguments, PLATFORM_LIMIT)?;
    let mut text = decode_output(&output.stdout);
    let stderr = decode_output(&output.stderr);
    if !stderr.is_empty() {
        if !text.is_empty() && !text.ends_with('\n') {
            text.push('\n');
        }
        text.push_str(&stderr);
    }
    // Retain any remaining non-null characters to guard against stray nulls.
    text.retain(|character| character != '\0');
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
/// The listing is one distribution per line: an optional `*` for the default, the name (which may
/// contain spaces), the state and the version. A name that is not in the listing is not
/// registered, which is reported as stale rather than as stopped: this host has not observed it at
/// all.
fn wsl_state(listing: &str, target: &str) -> EnvironmentPresence {
    for line in listing.lines() {
        let trimmed = line.trim_start().trim_start_matches('*').trim();
        if trimmed.is_empty() {
            continue;
        }
        let tokens: Vec<&str> = trimmed.split_whitespace().collect();
        if tokens.len() < 2 {
            continue;
        }
        // When version is present (standard wsl.exe -l -v), the second-to-last token is state.
        if tokens.len() >= 3 {
            let candidate_state = tokens[tokens.len() - 2];
            if matches!(
                candidate_state,
                "Running" | "Stopped" | "Installing" | "Converting" | "Paused"
            ) {
                let name = tokens[..tokens.len() - 2].join(" ");
                if name.eq_ignore_ascii_case(target) || name == target {
                    return match candidate_state {
                        "Running" => EnvironmentPresence::Running,
                        "Stopped" | "Installing" | "Converting" | "Paused" => {
                            EnvironmentPresence::EnvironmentStopped
                        }
                        _ => EnvironmentPresence::Stale,
                    };
                }
            }
        }
        // If version is absent, the last token is candidate state.
        let candidate_state = tokens[tokens.len() - 1];
        if matches!(
            candidate_state,
            "Running" | "Stopped" | "Installing" | "Converting" | "Paused"
        ) {
            let name = tokens[..tokens.len() - 1].join(" ");
            if name.eq_ignore_ascii_case(target) || name == target {
                return match candidate_state {
                    "Running" => EnvironmentPresence::Running,
                    "Stopped" | "Installing" | "Converting" | "Paused" => {
                        EnvironmentPresence::EnvironmentStopped
                    }
                    _ => EnvironmentPresence::Stale,
                };
            }
        }
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
    #[cfg(unix)]
    #[test]
    fn a_platform_command_that_never_returns_is_ended_rather_than_waited_for() {
        // `sleep` stands in for a launcher that has stopped answering. The record lock is held
        // while these run, so a wait with no end would hold a listing as well.
        let started = std::time::Instant::now();
        let error = super::run_bounded(
            "/bin/sleep",
            &["600".to_owned()],
            std::time::Duration::from_millis(200),
        )
        .expect_err("the command is ended");
        assert!(error.to_string().contains("was ended"), "{error}");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(20),
            "it returned after {:?}",
            started.elapsed()
        );
    }

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
    fn a_distribution_with_spaces_in_its_name_is_read_correctly() {
        let listing = "  NAME            STATE           VERSION\n\
                       * Ubuntu-24.04    Running         2\n\
                         My Distro       Running         2\n\
                         Debian Work     Stopped         2\n";
        assert_eq!(
            wsl_state(listing, "My Distro"),
            EnvironmentPresence::Running
        );
        assert_eq!(
            wsl_state(listing, "Debian Work"),
            EnvironmentPresence::EnvironmentStopped
        );
    }

    #[test]
    fn utf16_output_with_bom_is_decoded_faithfully() {
        let text =
            "  NAME            STATE           VERSION\n* My Distro       Running         2\n";
        let mut bytes = vec![0xff, 0xfe]; // UTF-16LE BOM
        for c in text.encode_utf16() {
            bytes.extend_from_slice(&c.to_le_bytes());
        }
        let decoded = decode_output(&bytes);
        assert_eq!(decoded, text);
        assert_eq!(
            wsl_state(&decoded, "My Distro"),
            EnvironmentPresence::Running
        );
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
