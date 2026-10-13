//! `kr backup`: restoring a backup of this host's data with the recovery kit.
//!
//! | Module | What it owns |
//! | --- | --- |
//! | [`restore`] | The restore itself: the plan, its digest, the confirmation, the files, the record |
//! | [`kit`] | Reading the recovery kit from a file, a pipe or the terminal, and clearing it |
//! | [`directory`] | The folder the files go into, held open for the run |
//! | [`source`] | The control daemon's relay as the place ciphertext is read from |
//! | [`interrupt`] | What ends a run early |

pub mod directory;
pub mod interrupt;
pub mod kit;
pub mod restore;
pub mod source;

use std::io::IsTerminal as _;
use std::sync::Arc;

use kr_client::shown;
use kr_client::shown::Shown;
use kr_ipc::paths::HostPaths;
use kr_protocol::ids::ArchiveId;

use crate::cli::{BackupCommand, BackupRestoreArguments, EnvironmentSelector};
use crate::daemon::Daemon;
use crate::error::{CliError, Result};
use crate::output;
use crate::report::{self, Completion};

use self::directory::Destination;
use self::interrupt::Interrupt;
use self::kit::{Entered, KitSource};
use self::restore::{AtTheTerminal, Decision, Outcome, Privacy as _, Run};
use self::source::{DaemonSource, real_pause};

/// Runs one `kr backup` command and prints its result.
///
/// # Errors
///
/// Returns the refusal or failure that stopped it.
pub async fn run(paths: &HostPaths, command: BackupCommand, json: bool) -> Result<Completion> {
    match command {
        BackupCommand::Restore(arguments) => restore(paths, arguments, json).await,
    }
}

/// What the arguments ask of the confirmation, settled before anything is read.
fn decide(arguments: &BackupRestoreArguments) -> Result<Decision> {
    if arguments.preview {
        return Ok(Decision::Preview);
    }
    if let Some(digest) = &arguments.confirm_plan {
        let digits = digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
        if !digits {
            return Err(CliError::Usage(Shown::said(
                "--confirm-plan takes the digest --preview printed: 64 hexadecimal digits",
            )));
        }
        return Ok(Decision::Confirmed(digest.clone()));
    }
    // A console is not asked: the confirmation there is the digest, given back.
    #[cfg(unix)]
    if std::io::stdin().is_terminal() && report::is_terminal() {
        return Ok(Decision::Ask);
    }
    Err(CliError::Usage(Shown::said(
        "this command shows what it would write before it writes it and needs your confirmation: \
         run it at a terminal, or run it with --preview and then with --confirm-plan and the \
         digest it printed",
    )))
}

async fn restore(
    paths: &HostPaths,
    arguments: BackupRestoreArguments,
    json: bool,
) -> Result<Completion> {
    // What was asked, before anything is read or reached.
    let archive: Option<ArchiveId> = arguments
        .archive
        .as_deref()
        .map(|text| crate::daemon::identifier(text, "an archive"))
        .transpose()?;
    let decision = decide(&arguments)?;
    crate::bind::require_outside(
        &crate::build_id(),
        "a recovery kit is read outside every session, whose output its worker keeps and an \
         agent in it can read",
    )
    .await?;
    let destination = Destination::check(&arguments.into)?;

    let selector = EnvironmentSelector { environment: None };
    let environment = crate::resolve::select(paths, None)?;
    let mut privacy = Daemon::open(paths, &selector).await?;
    let began = privacy.status().await?;
    restore::refuse_while_private(&began)?;
    let source = Arc::new(DaemonSource::new(
        Daemon::open(paths, &selector).await?,
        real_pause(),
    ));

    // The kit: read with a handler installed, so Ctrl-C puts the terminal back and clears it.
    let mut interrupt = Interrupt::install()?;
    let from = arguments
        .kit_file
        .clone()
        .map_or(KitSource::Standard, KitSource::File);
    let read = kit::read(from, &mut interrupt).await?;
    interrupt.arm()?;
    for line in kit::read_back(&read.kit) {
        report::say(&line);
    }
    if read.entered == Entered::Typed {
        let question =
            Shown::said("Type yes if that is the kit you meant, or anything else to stop:");
        let answer = tokio::select! {
            answer = kit::ask_line(&question) => answer?,
            () = interrupt.arrived() => return Err(interrupt::stopped()),
        };
        let yes = answer.is_some_and(|typed| typed.trim().eq_ignore_ascii_case("yes"));
        if !yes {
            return Err(CliError::Other(Shown::said(
                "that was not the kit meant, so nothing was done",
            )));
        }
    }

    let mut held = None;
    let outcome = {
        let run = Run {
            source,
            began: &began,
            destination: &destination,
            environment: environment.environment_id.to_string(),
            archive,
            decision,
        };
        let mut terminal = AtTheTerminal;
        let work = restore::restore_with(run, read.kit, &mut privacy, &mut terminal, &mut held);
        tokio::select! {
            outcome = work => outcome,
            () = interrupt.arrived() => Err(interrupt::stopped()),
        }
    };
    let outcome = match outcome {
        Ok(outcome) => outcome,
        Err(error) => {
            // Whatever ended the run, the files it made are removed, by name, through the handle.
            if let Some(folder) = held.as_mut() {
                for left in folder.clean() {
                    report::say(&left);
                }
            }
            return Err(error);
        }
    };
    print(&outcome, json);
    Ok(Completion::Done)
}

fn print(outcome: &Outcome, json: bool) {
    match outcome {
        Outcome::Previewed(planned) => {
            if json {
                output::document(&planned.document().with("ok", true).with("written", false));
            } else {
                for line in planned.lines() {
                    output::say(&line);
                }
            }
        }
        Outcome::Restored { planned, warnings } => {
            for warning in warnings {
                report::say(warning);
            }
            if json {
                output::document(
                    &planned
                        .document()
                        .with("ok", true)
                        .with("written", true)
                        .with("record", directory::RECORD_NAME)
                        .with("warnings", warnings.clone()),
                );
            } else {
                let files = planned.plan().restored().count();
                output::say(&shown!(
                    "Restored {} files into {}. {} says what was written and what was not.",
                    files,
                    crate::shown::named(planned.folder()),
                    directory::RECORD_NAME
                ));
            }
        }
    }
}
