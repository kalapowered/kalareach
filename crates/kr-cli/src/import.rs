//! `kr host import-journals`: the explicit import of journals this build does not migrate.
//!
//! A host brings a session's journal forward on its own only inside the range of versions its
//! migrations cover. A journal older than that is refused wherever it is opened, and the refusal
//! names this command. It runs against the environment's own files with no daemon: it takes the
//! environment's singleton lock first, which a running daemon holds, and holds it until every
//! journal has been looked at. It needs no method and reaches no process.

use kr_client::shown::Shown;
use kr_controller::archive::{ArchiveService, ImportOutcome};
use kr_controller::error::ControllerError;
use kr_controller::singleton::SingletonLock;
use kr_ipc::paths::HostPaths;

use crate::error::{CliError, Result};
use crate::report::Completion;

/// Imports every journal of this installation's environment that is older than this build's
/// migrations reach, and reports what became of each.
///
/// # Errors
///
/// Returns an error when the environment cannot be resolved, when its daemon or another import
/// holds it, and when its journals or its registry cannot be read. Nothing is imported then. A
/// journal refused on its own account is reported, and the command fails once every journal has
/// been looked at.
pub fn run(paths: &HostPaths, json: bool) -> Result<Completion> {
    let environment = crate::resolve::select(paths, None)?;
    // Held until this function returns, and released by the operating system if it never does.
    let _held = SingletonLock::acquire(
        &environment.paths.singleton_lock(),
        environment.environment_id,
    )
    .map_err(|error| match error {
        ControllerError::AlreadyRunning { .. } => CliError::Other(Shown::said(
            "this environment's daemon or another import holds it; journals are imported only \
             while the daemon is stopped, so stop it and run this again",
        )),
        _ => CliError::Other(Shown::said(
            "this environment's singleton lock could not be taken, so nothing was imported",
        )),
    })?;
    let imported = ArchiveService::new(environment.paths.clone())
        .import_journals()
        .map_err(|_| {
            CliError::Other(Shown::said(
                "this environment's journals or its registry could not be read, so nothing was \
                 imported",
            ))
        })?;
    let refused = imported
        .iter()
        .filter(|done| matches!(done.outcome, ImportOutcome::Refused { .. }))
        .count();
    if json {
        crate::report::print_json(&serde_json::json!({
            "ok": refused == 0,
            "environment_id": environment.environment_id.to_string(),
            "journals": imported
                .iter()
                .map(|done| {
                    let session_id = done.session_id.to_string();
                    match &done.outcome {
                        ImportOutcome::Imported { from, to, receipts } => serde_json::json!({
                            "session_id": session_id,
                            "outcome": "imported",
                            "from_version": from,
                            "to_version": to,
                            "receipts": receipts,
                        }),
                        ImportOutcome::Untouched { version } => serde_json::json!({
                            "session_id": session_id,
                            "outcome": "untouched",
                            "version": version,
                        }),
                        ImportOutcome::Refused { cause, .. } => serde_json::json!({
                            "session_id": session_id,
                            "outcome": "refused",
                            "cause": cause.as_str(),
                        }),
                    }
                })
                .collect::<Vec<_>>(),
        }));
    } else if imported.is_empty() {
        println!("this environment has no journals");
    } else {
        for done in &imported {
            match &done.outcome {
                ImportOutcome::Imported { from, to, receipts } => println!(
                    "session {}: imported from schema version {from} to {to}, keeping {receipts} \
                     receipts",
                    done.session_id
                ),
                ImportOutcome::Untouched { version } => println!(
                    "session {}: at schema version {version}, nothing to import",
                    done.session_id
                ),
                ImportOutcome::Refused { cause, .. } => println!(
                    "session {}: not imported, because {}",
                    done.session_id,
                    cause.describe()
                ),
            }
        }
    }
    if refused == 0 {
        Ok(Completion::Done)
    } else {
        Ok(Completion::Reported(CliError::Other(Shown::said(
            "one or more journals were not imported",
        ))))
    }
}
