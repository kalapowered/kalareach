//! `kr host repair-grants`: the repair of grants rows this build cannot read, and its undo.
//!
//! It runs against the environment's own files with no daemon: it holds the environment's
//! singleton lock, which a running daemon, an update, an import and another repair all hold, and
//! it never opens the registry through the daemon's own open, which migrates. Without `--apply` it
//! lists what it would do and changes nothing, in either mode. With `--json` it writes one document
//! for the run, with the facts the lines state.

use kr_client::shown;
use kr_client::shown::Shown;
use kr_controller::error::ControllerError;
use kr_controller::grants::repair::{self, Found, Refusal};
use kr_controller::registry::SCHEMA_VERSION;
use kr_controller::singleton::SingletonLock;
use kr_ipc::paths::HostPaths;

use crate::cli::RepairGrantsArguments;
use crate::error::{CliError, Result};
use crate::output::{self, Document};
use crate::report::Completion;

/// The sentence a refusal is told in. Every one says that nothing was changed, except the one for a
/// folder that could not be synced after the registry was replaced.
fn said(refusal: Refusal) -> Shown {
    match refusal {
        Refusal::LogBusy => Shown::said(
            "The registry's write-ahead log could not be taken in while another connection uses \
             it. Nothing is changed.",
        ),
        Refusal::OtherBuild { version } => shown!(
            "This registry was written by another build (schema version {}; this build reads \
             {}). Start the host once, or use that build. Nothing is changed.",
            version,
            SCHEMA_VERSION
        ),
        Refusal::NoVersion => {
            Shown::said("This registry holds no readable schema version. Nothing is changed.")
        }
        Refusal::WrongShape => Shown::said(
            "The grants tables of this registry do not have the shape this build reads. Start the \
             host once, or use the build that wrote it. Nothing is changed.",
        ),
        Refusal::RegistryUnreadable => {
            Shown::said("The registry could not be read. Nothing is changed.")
        }
        Refusal::CopyFailed(error) => shown!(
            "The copy of the registry could not be made: {}. Nothing is changed.",
            Shown::io(&error)
        ),
        Refusal::CopyUnreadable => Shown::said(
            "This copy could not be read as a registry of this build. Nothing is changed.",
        ),
        Refusal::CopyOfAnotherEnvironment => Shown::said(
            "This copy was not made from this environment's registry. Nothing is changed.",
        ),
        Refusal::HostRanSinceTheCopy => Shown::said(
            "The host has run since this copy was made, so putting it back would also bring back \
             what was revoked since, and could reuse a controller generation a worker has \
             accepted. Nothing is changed.",
        ),
        Refusal::LeftoverFile(path) => shown!(
            "A file from an earlier undo is in the way: {}. Remove it, then run this command \
             again. Nothing is changed.",
            Shown::root(&path)
        ),
        Refusal::ReplaceFailed(error) => shown!(
            "The registry could not be replaced: {}. Nothing is changed.",
            Shown::io(&error)
        ),
        Refusal::ReplacedButNotSynced(error) => shown!(
            "The registry is back to what the copy held, but its folder could not be synced to \
             disk: {}. If this computer stops before the disk writes it, the earlier registry may \
             come back.",
            Shown::io(&error)
        ),
    }
}

fn refused(refusal: Refusal) -> CliError {
    CliError::Other(said(refusal))
}

/// The rows and grants a repair deals with, as lines: no payload value, device name or path. `done`
/// says whether the repair made the change or only lists what it would.
fn lines_of(found: &Found, done: bool) -> Vec<Shown> {
    let mut lines = Vec::new();
    if !found.damaged.is_empty() {
        let count = u64::try_from(found.damaged.len()).unwrap_or(u64::MAX);
        lines.push(if done {
            shown!("Removed {} grants rows that cannot be read:", count)
        } else {
            shown!("Grants rows that cannot be read: {}.", count)
        });
        for row in &found.damaged {
            let key = row
                .key
                .map_or_else(|| Shown::said("malformed key"), |key| shown!("{}", key));
            lines.push(shown!(
                "  row {}: {}; key {}",
                row.place,
                Shown::said(row.class.phrase()),
                key
            ));
        }
    }
    if !found.withdraw.is_empty() {
        let count = u64::try_from(found.withdraw.len()).unwrap_or(u64::MAX);
        lines.push(if done {
            shown!("Withdrew {} live grants:", count)
        } else {
            shown!("Live grants that would be withdrawn: {}.", count)
        });
        for grant in &found.withdraw {
            lines.push(shown!("  grant {}", *grant));
        }
    }
    lines
}

/// The damaged rows of `found` as the document states them: place, cause and key (null for a key
/// that is not a grant identifier), and no payload value.
fn rows_document(found: &Found) -> Vec<Document> {
    found
        .damaged
        .iter()
        .map(|row| {
            Document::new()
                .with("place", row.place)
                .with("cause", row.class.phrase())
                .with("key", row.key.map(|key| output::said(&key)))
        })
        .collect()
}

/// The grants of `found` that the repair withdraws, as identifiers.
fn grants_document(found: &Found) -> Vec<Shown> {
    found
        .withdraw
        .iter()
        .map(|grant| output::said(grant))
        .collect()
}

/// `kr host repair-grants [--apply] [--undo <copy>]`.
///
/// # Errors
///
/// Returns an error, and changes nothing, when the environment cannot be resolved, another process
/// holds it, the registry is not one this build reads, or a step of the copy or the replacement
/// fails.
pub fn run(paths: &HostPaths, arguments: &RepairGrantsArguments, json: bool) -> Result<Completion> {
    let environment = crate::resolve::select(paths, None)?;
    // Held until this function returns, and released by the operating system if it never does. It
    // is taken without advancing the controller generation or naming a holder.
    let _held = SingletonLock::hold(
        &environment.paths.singleton_lock(),
        environment.environment_id,
    )
    .map_err(|error| match error {
        ControllerError::AlreadyRunning { .. } => CliError::Other(Shown::said(
            "Another process holds this host's environment: the host, an update, an import or \
             another repair. Stop it, then run this command again. Nothing is changed.",
        )),
        _ => CliError::Other(Shown::said(
            "The lock on this environment could not be taken, so nothing was changed.",
        )),
    })?;
    let registry = environment.paths.registry_database();
    match &arguments.undo {
        Some(copy) => undo(
            &registry,
            copy,
            environment.environment_id,
            arguments.apply,
            json,
        ),
        None => repair_grants(&registry, arguments.apply, json),
    }
}

/// What a run that finds nothing to repair says: the sentence, or the document with nothing in it.
fn nothing_to_repair(json: bool) {
    if json {
        output::document(
            &Document::new()
                .with("ok", true)
                .with("applied", false)
                .with("nothing_to_repair", true)
                .with("unreadable_rows", Vec::<Document>::new())
                .with("grants_to_withdraw", Vec::<Shown>::new()),
        );
    } else {
        output::say(&Shown::said(
            "Every grants row can be read and every live grant traces to a root. There is nothing \
             to repair.",
        ));
    }
}

fn repair_grants(registry: &std::path::Path, apply: bool, json: bool) -> Result<Completion> {
    if !apply {
        let found = repair::preview(registry).map_err(refused)?;
        if found.is_empty() {
            nothing_to_repair(json);
            return Ok(Completion::Done);
        }
        if json {
            output::document(
                &Document::new()
                    .with("ok", true)
                    .with("applied", false)
                    .with("nothing_to_repair", false)
                    .with("unreadable_rows", rows_document(&found))
                    .with("grants_to_withdraw", grants_document(&found)),
            );
            return Ok(Completion::Done);
        }
        for line in lines_of(&found, false) {
            output::say(&line);
        }
        output::say(&Shown::said(
            "Nothing is changed. Run with --apply to change it.",
        ));
        return Ok(Completion::Done);
    }
    let unix_seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    let Some(repaired) =
        repair::apply(registry, kr_ipc::now_ms().get(), unix_seconds).map_err(refused)?
    else {
        nothing_to_repair(json);
        return Ok(Completion::Done);
    };
    if json {
        output::document(
            &Document::new()
                .with("ok", true)
                .with("applied", true)
                .with("nothing_to_repair", false)
                .with("copy", Shown::root(&repaired.copy))
                .with("folder", Shown::root(&repaired.folder))
                .with("removed_rows", rows_document(&repaired.found))
                .with("withdrawn_grants", grants_document(&repaired.found))
                .with("fence_owed", repaired.fence_owed),
        );
        return Ok(Completion::Done);
    }
    output::say(&shown!(
        "Copy of the registry before the repair: {}.",
        Shown::root(&repaired.copy)
    ));
    for line in lines_of(&repaired.found, true) {
        output::say(&line);
    }
    if repaired.fence_owed {
        output::say(&Shown::said(
            "One fence is owed; the host pays it when it starts.",
        ));
    }
    output::say(&shown!(
        "To undo: kr host repair-grants --undo {} --apply. Everything written to the registry \
         after this copy was made is lost with it.",
        Shown::root(&repaired.copy)
    ));
    output::say(&shown!(
        "The copy stays until you remove it: remove the folder {} yourself when you no longer \
         need it.",
        Shown::root(&repaired.folder)
    ));
    Ok(Completion::Done)
}

fn undo(
    registry: &std::path::Path,
    copy: &std::path::Path,
    environment_id: kr_protocol::ids::EnvironmentId,
    apply: bool,
    json: bool,
) -> Result<Completion> {
    if !apply {
        let preview = repair::undo_preview(registry, copy, environment_id).map_err(refused)?;
        if json {
            output::document(
                &Document::new()
                    .with("ok", true)
                    .with("applied", false)
                    .with(
                        "grants_live_again",
                        preview
                            .live_again
                            .iter()
                            .map(|grant| output::said(grant))
                            .collect::<Vec<_>>(),
                    ),
            );
            return Ok(Completion::Done);
        }
        output::say(&Shown::said(
            "Putting this copy back withdraws nothing and revokes nothing: it makes the registry \
             what the copy held.",
        ));
        output::say(&shown!(
            "Grants that the repair withdrew and that become live again: {}.",
            u64::try_from(preview.live_again.len()).unwrap_or(u64::MAX)
        ));
        for grant in preview.live_again {
            output::say(&shown!("  grant {}", grant));
        }
        output::say(&Shown::said(
            "Everything written to the registry after the copy was made is lost. Nothing is \
             changed. Run with --apply to change it.",
        ));
        return Ok(Completion::Done);
    }
    repair::undo_apply(registry, copy, environment_id).map_err(refused)?;
    if json {
        output::document(&Document::new().with("ok", true).with("applied", true));
        return Ok(Completion::Done);
    }
    output::say(&Shown::said(
        "The registry is back to what the copy held. Every change made after the copy is gone \
         with it, and the grants the repair withdrew are live again.",
    ));
    Ok(Completion::Done)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The refusal for a folder that could not be synced says the registry was replaced, and never
    /// that nothing is changed.
    #[test]
    fn a_folder_that_could_not_be_synced_after_the_replacement_is_said_as_such() {
        let said = said(Refusal::ReplacedButNotSynced(std::io::Error::from(
            std::io::ErrorKind::PermissionDenied,
        )));
        assert_eq!(
            said.as_str(),
            "The registry is back to what the copy held, but its folder could not be synced to \
             disk: permission denied. If this computer stops before the disk writes it, the \
             earlier registry may come back."
        );
        assert!(!said.as_str().contains("Nothing is changed"));
    }
}
