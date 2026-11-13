//! The setup program: `install`, `repair`, `remove` and `status`.
//!
//! It runs elevated, started by `kr host boundary`, shows the notice in its own window and takes a
//! typed yes before it changes anything. The yes is read from standard input, so a person types it
//! at the prompt and a test supplies it on a pipe by the same path.

use std::process::ExitCode;

use super::install::{self, Entry, Options, Paths};
use crate::setup_args::{self, Command};

/// Runs the setup program. The command and its options are read first, so that a wrong command or
/// a bad option gets the usage and its exit code before anything of the machine is read.
pub fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let command = match setup_args::parse(&arguments) {
        Ok(command) => command,
        Err(rejected) => {
            if let Some(message) = rejected.message {
                // text: setup-1
                eprintln!("kr-boundary-setup: {message}");
            }
            // text: setup-2
            eprintln!("{}", setup_args::USAGE);
            return ExitCode::from(setup_args::USAGE_EXIT);
        }
    };
    let paths = match Paths::system() {
        Ok(paths) => paths,
        Err(install::Error::KnownFolder(failure)) => {
            // text: setup-3
            eprintln!(
                "kr-boundary-setup: {}",
                crate::remedy::known_folder_unreadable(
                    failure.folder.name(),
                    &super::ffi::system_form(failure.status),
                    command == Command::Remove,
                )
            );
            return ExitCode::from(1);
        }
        Err(error) => {
            eprintln!("kr-boundary-setup: {error}");
            return ExitCode::from(1);
        }
    };
    let outcome = match command {
        Command::Install {
            repair,
            payload,
            person,
        } => {
            let options = Options { payload, person };
            let person = match &options.person {
                Some(person) => Ok(person.clone()),
                None => super::token::current_user().and_then(|user| user.to_text()),
            };
            person.map_err(install::Error::from).and_then(|person| {
                install::confirm(
                    Some(&person),
                    if repair {
                        "repair the boundary"
                    } else {
                        "install the boundary"
                    },
                )?;
                install::install(&paths, &options, repair)
            })
        }
        Command::Remove => install::confirm(None, "remove the boundary")
            .and_then(|()| install::remove(&paths, false)),
        Command::Status => install::entry(&paths).map(|entry| match entry {
            // text: setup-5
            Entry::Fresh => println!(
                "no manifest is recorded, and no service, account or program directory of the installation's names was found"
            ),
            // text: setup-6
            Entry::Installed(manifest) => println!(
                "the manifest records a finished installation: {} recorded objects, {} enrolled",
                manifest.objects.len(),
                manifest.persons.len()
            ),
            // text: setup-7
            Entry::Partial(manifest) => println!(
                "partial: the manifest records an installation that has not finished ({} recorded objects)",
                manifest.objects.len()
            ),
        }),
    };
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            // text: setup-4
            eprintln!("kr-boundary-setup: {error}");
            ExitCode::from(1)
        }
    }
}
