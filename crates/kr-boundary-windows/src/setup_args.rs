//! The setup program's command line, read before anything of the machine: a wrong command or a bad
//! option is refused with the usage and its exit code whatever state the system's known folders are
//! in, so that the person is told what they typed wrong before a folder that could not be read.

use std::path::PathBuf;

/// What the setup program prints for a command line that is not one.
pub const USAGE: &str = "usage: kr-boundary-setup install|repair --payload DIRECTORY [--person SID]\n       kr-boundary-setup remove\n       kr-boundary-setup status";

/// The exit code of a command line that is refused.
pub const USAGE_EXIT: u8 = 2;

/// What the setup program is asked to do.
#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    /// An installation or, with `repair`, a repair.
    Install {
        /// Whether this is a repair.
        repair: bool,
        /// The directory with the broker and the credential helper.
        payload: PathBuf,
        /// The person to enrol, or the person who runs the setup program.
        person: Option<String>,
    },
    /// A removal.
    Remove,
    /// What the computer has of the installation.
    Status,
}

/// A command line that is refused: what to say before the usage, when something is to be said.
#[derive(Debug, PartialEq, Eq)]
pub struct Rejected {
    /// What was wrong with an option, or none for a command that is not one.
    pub message: Option<String>,
}

/// Reads the command and its options.
///
/// # Errors
///
/// Returns [`Rejected`] for no command, a command that is not one, and an option of an installation
/// or a repair that is not one or has no value, or a missing payload.
pub fn parse(arguments: &[String]) -> Result<Command, Rejected> {
    let refuse = |message: Option<&str>| Rejected {
        message: message.map(str::to_owned),
    };
    let Some(command) = arguments.first() else {
        return Err(refuse(None));
    };
    match command.as_str() {
        "remove" => Ok(Command::Remove),
        "status" => Ok(Command::Status),
        "install" | "repair" => {
            let mut payload = None;
            let mut person = None;
            let mut index = 1;
            while index < arguments.len() {
                match arguments[index].as_str() {
                    "--payload" => {
                        index += 1;
                        payload =
                            Some(PathBuf::from(arguments.get(index).ok_or_else(|| {
                                refuse(Some("--payload needs a directory"))
                            })?));
                    }
                    "--person" => {
                        index += 1;
                        person = Some(
                            arguments
                                .get(index)
                                .ok_or_else(|| refuse(Some("--person needs an identifier")))?
                                .clone(),
                        );
                    }
                    other => return Err(refuse(Some(&format!("unknown argument {other}")))),
                }
                index += 1;
            }
            // The directory with the broker and the credential helper is named by whoever starts
            // the setup program, which knows where its release keeps them.
            let payload = payload.ok_or_else(|| {
                refuse(Some(
                    "--payload names the directory with the broker and the credential helper",
                ))
            })?;
            Ok(Command::Install {
                repair: command == "repair",
                payload,
                person,
            })
        }
        _ => Err(refuse(None)),
    }
}
