//! `kr host import-journals`: the explicit import of journals this build does not migrate.
//!
//! A host brings a session's journal forward on its own only inside the range of versions its
//! migrations cover. A journal older than that is refused wherever it is opened, and the refusal
//! names this command. It runs against the environment's own files with no daemon: it takes the
//! environment's singleton lock first, which a running daemon holds, and holds it until every
//! journal has been looked at. It needs no method and reaches no process.

use kr_client::shown;
use kr_client::shown::Shown;
use kr_controller::archive::{ArchiveService, ImportOutcome, JournalImport};
use kr_controller::error::ControllerError;
use kr_controller::singleton::SingletonLock;
use kr_ipc::paths::HostPaths;
use kr_protocol::ids::EnvironmentId;

use crate::error::{CliError, Result};
use crate::output::{self, Document};
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
    if json {
        output::document(&document(environment.environment_id, &imported));
    } else {
        for line in lines(&imported) {
            output::say(&line);
        }
    }
    if none_refused(&imported) {
        Ok(Completion::Done)
    } else {
        Ok(Completion::Reported(CliError::Other(Shown::said(
            "one or more journals were not imported",
        ))))
    }
}

/// Whether every journal was imported or left alone: what `ok` says, and the exit status with it.
fn none_refused(imported: &[JournalImport]) -> bool {
    !imported
        .iter()
        .any(|done| matches!(done.outcome, ImportOutcome::Refused { .. }))
}

/// The `--json` document: whether no journal was refused, the environment, and what became of each
/// journal.
fn document(environment_id: EnvironmentId, imported: &[JournalImport]) -> Document {
    Document::new()
        .with("ok", none_refused(imported))
        .with("environment_id", output::said(&environment_id))
        .with("journals", imported.iter().map(journal).collect::<Vec<_>>())
}

/// One journal in the document. A refusal is said by its cause's stable name: the reason that
/// names what stopped it stays with the importer.
fn journal(done: &JournalImport) -> Document {
    let entry = Document::new().with("session_id", output::said(&done.session_id));
    match done.outcome {
        ImportOutcome::Imported { from, to, receipts } => entry
            .with("outcome", "imported")
            .with("from_version", from)
            .with("to_version", to)
            .with("receipts", receipts),
        ImportOutcome::Untouched { version } => {
            entry.with("outcome", "untouched").with("version", version)
        }
        ImportOutcome::Refused { cause, .. } => entry
            .with("outcome", "refused")
            .with("cause", cause.as_str()),
    }
}

/// The lines for a person: one for each journal, or one that says there are none. A refusal is
/// said by its cause, as the document says it.
fn lines(imported: &[JournalImport]) -> Vec<Shown> {
    if imported.is_empty() {
        return vec![Shown::said("this environment has no journals")];
    }
    imported
        .iter()
        .map(|done| match done.outcome {
            ImportOutcome::Imported { from, to, receipts } => shown!(
                "session {}: imported from schema version {} to {}, keeping {} receipts",
                done.session_id,
                from,
                to,
                receipts
            ),
            ImportOutcome::Untouched { version } => shown!(
                "session {}: at schema version {}, nothing to import",
                done.session_id,
                version
            ),
            ImportOutcome::Refused { cause, .. } => shown!(
                "session {}: not imported, because {}",
                done.session_id,
                cause.describe()
            ),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use kr_controller::archive::RefusalCause;
    use kr_protocol::ids::SessionId;
    use kr_protocol::scalars::Uuid;

    use super::*;
    use crate::shown::marker::{MARKER, assert_unmarked};

    /// One journal of each outcome. The refusal's reason names what stopped it, here the marker.
    fn each_outcome() -> Vec<JournalImport> {
        vec![
            JournalImport {
                session_id: SessionId::new(Uuid::from_bytes([1; 16])),
                outcome: ImportOutcome::Imported {
                    from: 1,
                    to: 4,
                    receipts: 2,
                },
            },
            JournalImport {
                session_id: SessionId::new(Uuid::from_bytes([2; 16])),
                outcome: ImportOutcome::Untouched { version: 4 },
            },
            JournalImport {
                session_id: SessionId::new(Uuid::from_bytes([3; 16])),
                outcome: ImportOutcome::Refused {
                    cause: RefusalCause::WorkerMayRemain,
                    reason: format!("the descriptor at /run/{MARKER} is still there"),
                },
            },
        ]
    }

    #[test]
    fn the_document_says_what_became_of_each_journal_and_no_refusal_s_reason() {
        let environment_id = EnvironmentId::new(Uuid::from_bytes([9; 16]));
        let imported = each_outcome();
        let written = document(environment_id, &imported).json();
        assert_eq!(
            written,
            serde_json::json!({
                "ok": false,
                "environment_id": environment_id.to_string(),
                "journals": [
                    {
                        "session_id": imported[0].session_id.to_string(),
                        "outcome": "imported",
                        "from_version": 1,
                        "to_version": 4,
                        "receipts": 2,
                    },
                    {
                        "session_id": imported[1].session_id.to_string(),
                        "outcome": "untouched",
                        "version": 4,
                    },
                    {
                        "session_id": imported[2].session_id.to_string(),
                        "outcome": "refused",
                        "cause": "worker_may_remain",
                    },
                ],
            })
        );
        assert_unmarked("the import's document", &[written.to_string()]);
        assert_eq!(
            document(environment_id, &imported[..2]).json()["ok"],
            true,
            "a journal left alone is not a refusal"
        );
    }

    #[test]
    fn a_person_reads_one_line_for_each_journal_and_no_refusal_s_reason() {
        let imported = each_outcome();
        let said = lines(&imported)
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        assert_eq!(
            said,
            [
                format!(
                    "session {}: imported from schema version 1 to 4, keeping 2 receipts",
                    imported[0].session_id
                ),
                format!(
                    "session {}: at schema version 4, nothing to import",
                    imported[1].session_id
                ),
                format!(
                    "session {}: not imported, because a worker may still own it, or what would \
                     say whether one does cannot be read",
                    imported[2].session_id
                ),
            ]
        );
        assert_unmarked("the import's lines", &said);
        assert_eq!(
            lines(&[])
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            ["this environment has no journals"]
        );
    }
}
