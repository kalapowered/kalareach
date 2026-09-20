//! The argument vector each access class is started with.
//!
//! Section 3 writes the WSL invocation out in full:
//!
//! ```text
//! wsl.exe --distribution <name> --user <user> --exec <absolute-kr-path> bridge --stdio
//! ```
//!
//! and asks for the equivalent enrolled container-identifier, user and absolute-helper bridge. So
//! this module builds argument *vectors*, never command lines. Nothing here interpolates a value
//! into a string that another program will parse again: a distribution called `My Distro`, a
//! container whose identifier begins with a dash and a helper path containing a quotation mark all
//! cross as the exact bytes the enrolment recorded, because each is one element of the vector.
//!
//! `--exec` is part of that guarantee on the WSL side. Without it `wsl.exe` hands the rest of the
//! line to the distribution's login shell, which would parse it again.

use kr_protocol::identity::{EnvironmentAccess, EnvironmentEnrolment};

/// The program and arguments one bridge is started with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BridgeCommand {
    /// The program to run on this host.
    pub program: String,
    /// Its arguments, in order, each carried as its own element.
    pub arguments: Vec<String>,
}

/// Why an enrolment cannot be started.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LaunchError {
    /// The access class is not reached by a process bridge.
    NotAProcessBridge {
        /// The class that was asked for.
        access: EnvironmentAccess,
    },
    /// The record is missing something a launch needs.
    Incomplete(kr_protocol::identity::EnrolmentError),
}

impl core::fmt::Display for LaunchError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotAProcessBridge { access } => write!(
                formatter,
                "{} is not reached by a process bridge; an SSH user runs the command line on the \
                 destination host and a paired host is reached through its own endpoint",
                access.as_str()
            ),
            Self::Incomplete(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for LaunchError {}

/// The subcommand and flag every helper is started with.
pub const HELPER_ARGUMENTS: [&str; 2] = ["bridge", "--stdio"];

/// The container runtime this host starts an enrolled container's helper with.
///
/// One runtime, named here rather than searched for: a host that has two of them would otherwise
/// start the helper in whichever was found first, and an enrolment names a container identifier
/// that belongs to exactly one of them.
pub const CONTAINER_RUNTIME: &str = "podman";

/// Builds the command one enrolled environment's helper is started with.
///
/// # Errors
///
/// Returns [`LaunchError::NotAProcessBridge`] for an access class that is not a bridge, and
/// [`LaunchError::Incomplete`] when the record is missing the identity, the user or the absolute
/// helper path.
pub fn command(enrolment: &EnvironmentEnrolment) -> Result<BridgeCommand, LaunchError> {
    enrolment.validate().map_err(LaunchError::Incomplete)?;
    helper_command(
        enrolment.access,
        &enrolment.target,
        &enrolment.os_user,
        &enrolment.helper_path,
    )
}

/// Builds the helper command for a destination that has no record yet.
///
/// Enrolment asks the destination which environment it is before there is a record to name it, so
/// the command is built from the three values that describe where the helper runs. Everything the
/// built command guarantees is the same: values cross as elements of a vector, `--exec` keeps the
/// far side from parsing them again, and `--` ends the runtime's own options.
///
/// # Errors
///
/// As [`command`].
pub fn helper_command(
    access: EnvironmentAccess,
    target: &str,
    os_user: &str,
    helper_path: &str,
) -> Result<BridgeCommand, LaunchError> {
    kr_protocol::identity::validate_destination(access, target, os_user, helper_path)
        .map_err(LaunchError::Incomplete)?;
    match access {
        EnvironmentAccess::WslDistribution => Ok(BridgeCommand {
            program: "wsl.exe".to_owned(),
            arguments: vec![
                "--distribution".to_owned(),
                target.to_owned(),
                "--user".to_owned(),
                os_user.to_owned(),
                // Everything after `--exec` is an argument vector for the program named next. It
                // is not handed to a shell, so no value in it is parsed a second time.
                "--exec".to_owned(),
                helper_path.to_owned(),
                HELPER_ARGUMENTS[0].to_owned(),
                HELPER_ARGUMENTS[1].to_owned(),
            ],
        }),
        EnvironmentAccess::Container => Ok(BridgeCommand {
            program: CONTAINER_RUNTIME.to_owned(),
            arguments: vec![
                "exec".to_owned(),
                "--interactive".to_owned(),
                "--user".to_owned(),
                os_user.to_owned(),
                // `--` ends the runtime's own options, so a container identifier or a helper path
                // that begins with a dash is a value rather than a flag.
                "--".to_owned(),
                target.to_owned(),
                helper_path.to_owned(),
                HELPER_ARGUMENTS[0].to_owned(),
                HELPER_ARGUMENTS[1].to_owned(),
            ],
        }),
        access @ (EnvironmentAccess::SshHost | EnvironmentAccess::PairedHost) => {
            Err(LaunchError::NotAProcessBridge { access })
        }
    }
}

/// Builds the command that asks the platform whether one enrolled environment is running.
///
/// Observing is not starting. Each of these reports state and changes none: `wsl.exe --list
/// --verbose` prints every registered distribution and its state, and `podman container inspect`
/// answers about a container that exists without creating or starting one.
///
/// # Errors
///
/// As [`command`].
pub fn observe(enrolment: &EnvironmentEnrolment) -> Result<BridgeCommand, LaunchError> {
    enrolment.validate().map_err(LaunchError::Incomplete)?;
    match enrolment.access {
        EnvironmentAccess::WslDistribution => Ok(BridgeCommand {
            program: "wsl.exe".to_owned(),
            arguments: vec!["--list".to_owned(), "--verbose".to_owned()],
        }),
        EnvironmentAccess::Container => Ok(BridgeCommand {
            program: CONTAINER_RUNTIME.to_owned(),
            arguments: vec![
                "container".to_owned(),
                "inspect".to_owned(),
                "--format".to_owned(),
                "{{.State.Running}}".to_owned(),
                "--".to_owned(),
                enrolment.target.clone(),
            ],
        }),
        access @ (EnvironmentAccess::SshHost | EnvironmentAccess::PairedHost) => {
            Err(LaunchError::NotAProcessBridge { access })
        }
    }
}

/// Builds the command that starts one enrolled environment.
///
/// Only a refresh, a create or an attach reaches this. A listing never does.
///
/// # Errors
///
/// As [`command`].
pub fn start(enrolment: &EnvironmentEnrolment) -> Result<BridgeCommand, LaunchError> {
    enrolment.validate().map_err(LaunchError::Incomplete)?;
    match enrolment.access {
        // There is no "start a distribution" verb. Running the shortest possible command inside it
        // is what starts one, and `--exec` keeps that command a vector rather than a line.
        EnvironmentAccess::WslDistribution => Ok(BridgeCommand {
            program: "wsl.exe".to_owned(),
            arguments: vec![
                "--distribution".to_owned(),
                enrolment.target.clone(),
                "--user".to_owned(),
                enrolment.os_user.clone(),
                "--exec".to_owned(),
                "/bin/true".to_owned(),
            ],
        }),
        EnvironmentAccess::Container => Ok(BridgeCommand {
            program: CONTAINER_RUNTIME.to_owned(),
            arguments: vec![
                "start".to_owned(),
                "--".to_owned(),
                enrolment.target.clone(),
            ],
        }),
        access @ (EnvironmentAccess::SshHost | EnvironmentAccess::PairedHost) => {
            Err(LaunchError::NotAProcessBridge { access })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::ids::EnvironmentId;
    use kr_protocol::scalars::{Nullable, TimestampMs, Uuid};

    fn enrolment(access: EnvironmentAccess, target: &str, user: &str) -> EnvironmentEnrolment {
        EnvironmentEnrolment {
            environment_id: EnvironmentId::new(Uuid::from_bytes([2; 16])),
            access,
            label: "one".to_owned(),
            target: target.to_owned(),
            os_user: user.to_owned(),
            helper_path: "/usr/local/bin/kr".to_owned(),
            clipboard_destination: Nullable::null(),
            approved_at_ms: TimestampMs::new(0),
        }
    }

    #[test]
    fn the_wsl_invocation_is_the_one_the_specification_writes_out() {
        let command = command(&enrolment(
            EnvironmentAccess::WslDistribution,
            "Ubuntu-24.04",
            "kala",
        ))
        .expect("a command");
        assert_eq!(command.program, "wsl.exe");
        assert_eq!(
            command.arguments,
            vec![
                "--distribution",
                "Ubuntu-24.04",
                "--user",
                "kala",
                "--exec",
                "/usr/local/bin/kr",
                "bridge",
                "--stdio",
            ]
        );
    }

    #[test]
    fn an_argument_vector_preserves_exact_values() {
        // Every one of these would be changed by a shell, and none of them is: each crosses as one
        // element of the vector.
        let awkward = [
            "My Distro",
            "-leading-dash",
            "quote\"inside",
            "space and $HOME and `backtick`",
            "semi;colon && ampersand",
        ];
        for value in awkward {
            let wsl = command(&enrolment(EnvironmentAccess::WslDistribution, value, value))
                .expect("a command");
            assert!(wsl.arguments.contains(&value.to_owned()), "{value}");
            assert_eq!(
                wsl.arguments
                    .iter()
                    .filter(|argument| *argument == value)
                    .count(),
                2,
                "the distribution and the user are both carried whole: {value}"
            );
            // A container is named by the identifier its runtime issued, so the awkward value is
            // the user here. It crosses whole for the same reason.
            let container = command(&enrolment(
                EnvironmentAccess::Container,
                &"0a".repeat(32),
                value,
            ))
            .expect("a command");
            assert!(container.arguments.contains(&value.to_owned()), "{value}");
        }
    }

    #[test]
    fn a_container_named_by_a_reusable_name_is_refused_rather_than_started() {
        // Section 3: a reused human container name is not its identity. The refusal is here,
        // before a runtime is asked to resolve the name to whatever holds it now.
        for name in ["build", "My Distro", "-leading-dash", "0a1b"] {
            let refused = command(&enrolment(EnvironmentAccess::Container, name, "kala"))
                .expect_err("a refusal");
            assert_eq!(
                refused,
                LaunchError::Incomplete(
                    kr_protocol::identity::EnrolmentError::ContainerTargetNotIdentifier
                ),
                "{name}"
            );
            for build in [observe, start] {
                assert!(
                    build(&enrolment(EnvironmentAccess::Container, name, "kala")).is_err(),
                    "{name} is not observed or started by name either"
                );
            }
        }
    }

    #[test]
    fn a_container_is_started_by_its_identifier_and_the_options_are_ended_first() {
        // The whole identifier a runtime issues: sixty-four hexadecimal digits.
        let identifier = "8f3c1d2e4a5b6c7d".repeat(4);
        let command = command(&enrolment(
            EnvironmentAccess::Container,
            &identifier,
            "kala",
        ))
        .expect("a command");
        assert_eq!(command.program, CONTAINER_RUNTIME);
        assert_eq!(
            command.arguments,
            vec![
                "exec",
                "--interactive",
                "--user",
                "kala",
                "--",
                identifier.as_str(),
                "/usr/local/bin/kr",
                "bridge",
                "--stdio",
            ]
        );
        let separator = command
            .arguments
            .iter()
            .position(|argument| argument == "--")
            .expect("the options end");
        let carried = command
            .arguments
            .iter()
            .position(|argument| *argument == identifier)
            .expect("the identifier is carried");
        assert!(separator < carried);
    }

    #[test]
    fn an_ssh_host_and_a_paired_host_are_not_started_as_bridges() {
        for access in [EnvironmentAccess::SshHost, EnvironmentAccess::PairedHost] {
            for build in [command, observe, start] {
                assert_eq!(
                    build(&enrolment(access, "host", "kala")),
                    Err(LaunchError::NotAProcessBridge { access })
                );
            }
        }
    }

    #[test]
    fn a_record_without_an_absolute_helper_path_starts_nothing() {
        let mut relative = enrolment(EnvironmentAccess::WslDistribution, "Ubuntu-24.04", "kala");
        relative.helper_path = "kr".to_owned();
        assert_eq!(
            command(&relative),
            Err(LaunchError::Incomplete(
                kr_protocol::identity::EnrolmentError::HelperPathNotAbsolute
            ))
        );
    }

    #[test]
    fn observing_names_a_command_that_reports_rather_than_starts() {
        let wsl = observe(&enrolment(
            EnvironmentAccess::WslDistribution,
            "Ubuntu-24.04",
            "kala",
        ))
        .expect("a command");
        assert_eq!(wsl.arguments, vec!["--list", "--verbose"]);
        // Nothing in the observation names the helper, so it cannot run one by accident.
        assert!(!wsl.arguments.iter().any(|argument| argument.contains("kr")));

        let container = observe(&enrolment(
            EnvironmentAccess::Container,
            &"8f3c1d2e4a5b6c7d".repeat(4),
            "kala",
        ))
        .expect("a command");
        assert_eq!(container.arguments[0..2], ["container", "inspect"]);
        assert!(
            !container
                .arguments
                .iter()
                .any(|argument| argument == "start")
        );
    }
}
