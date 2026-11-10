//! The setup program: `install`, `repair`, `remove` and `status`.
//!
//! It runs elevated, started by `kr host boundary`, shows the notice in its own window and takes a
//! typed yes before it changes anything. The yes is read from standard input, so a person types it
//! at the prompt and a test supplies it on a pipe by the same path.

use std::path::PathBuf;
use std::process::ExitCode;

use super::install::{self, Entry, Options, Paths};

const USAGE: &str = "usage: kr-boundary-setup install|repair [--payload DIRECTORY] [--person SID]\n       kr-boundary-setup remove\n       kr-boundary-setup status";

fn options(arguments: &[String]) -> Result<Options, String> {
    let mut payload = None;
    let mut person = None;
    let mut index = 0;
    while index < arguments.len() {
        match arguments[index].as_str() {
            "--payload" => {
                index += 1;
                payload = Some(PathBuf::from(
                    arguments.get(index).ok_or("--payload needs a directory")?,
                ));
            }
            "--person" => {
                index += 1;
                person = Some(
                    arguments
                        .get(index)
                        .ok_or("--person needs an identifier")?
                        .clone(),
                );
            }
            other => return Err(format!("unknown argument {other}")),
        }
        index += 1;
    }
    let payload = match payload {
        Some(payload) => payload,
        None => std::env::current_exe()
            .map_err(|error| error.to_string())?
            .parent()
            .ok_or("the setup program has no directory")?
            .join("bin"),
    };
    Ok(Options { payload, person })
}

/// Runs the setup program.
pub fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let Some(command) = arguments.first() else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    let paths = Paths::system();
    let outcome = match command.as_str() {
        "install" | "repair" => {
            let repair = command == "repair";
            options(&arguments[1..])
                .map_err(install::Error::Refused)
                .and_then(|options| {
                    let person = match &options.person {
                        Some(person) => person.clone(),
                        None => super::token::current_user()?.to_text(),
                    };
                    install::confirm(
                        &person,
                        if repair {
                            "repair the boundary"
                        } else {
                            "install the boundary"
                        },
                    )?;
                    install::install(&paths, &options, repair)
                })
        }
        "remove" => install::confirm(
            "(no account is enrolled by a removal)",
            "remove the boundary",
        )
        .and_then(|()| install::remove(&paths, false)),
        "status" => install::entry(&paths).map(|entry| match entry {
            Entry::Fresh => println!("not installed"),
            Entry::Installed(manifest) => println!(
                "installed: {} recorded objects, {} enrolled",
                manifest.objects.len(),
                manifest.persons.len()
            ),
            Entry::Partial(manifest) => println!(
                "partial: an installation began and did not finish ({} recorded objects)",
                manifest.objects.len()
            ),
        }),
        _ => {
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("kr-boundary-setup: {error}");
            ExitCode::from(1)
        }
    }
}
