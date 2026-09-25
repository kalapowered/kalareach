//! `kr diff`: reading changes, and applying or reverting a change-set version explicitly.
//!
//! A read names one subject: a workspace, whose live tree is read, or a change set, whose captured
//! version is. It reports each path with the digest of the content it holds, which is the form an
//! apply names that path's expected state in.
//!
//! An apply or a revert names its destination every time, because there is no default: a new
//! immutable proposal that writes no tree, a Git reference moved only when it holds the value the
//! person expects, or the workspace's own files written in place. Every path the change writes is
//! named with what the person expects it to hold now, and the host checks each one before it writes
//! anything; a destination that is not as expected is refused with nothing written. A write to a
//! working tree is refused until the person passes back each limitation the host states for it.

use kr_ipc::paths::HostPaths;
use kr_protocol::changeset::{
    AffectedVersion, ApplyOutcomeClass, DestinationClass, DiffApplyParams, DiffApplyResult,
    DiffEntry, DiffReadParams, DiffReadResult, ExpectedReference,
};
use kr_protocol::ids::{ChangeSetVersion, WorkspaceId};
use kr_protocol::method::Method;
use kr_protocol::scalars::{Digest256, Nullable};

use crate::cli::{DestinationArgument, DiffApplyArguments, DiffCommand, DiffReadArguments};
use crate::daemon::{Daemon, identifier};
use crate::error::{CliError, Result};
use crate::report;

/// What `--expect` and `--reference-at` take for a path or a reference that does not exist.
const ABSENT: &str = "absent";

/// Runs one `kr diff` command and prints its result.
///
/// # Errors
///
/// Returns a usage mistake, the daemon's refusal, or a transport failure.
pub async fn run(paths: &HostPaths, command: DiffCommand, json: bool) -> Result<()> {
    match command {
        DiffCommand::Read(arguments) => read(paths, &arguments, json).await,
        DiffCommand::Apply(arguments) => apply(paths, &arguments, false, json).await,
        DiffCommand::Revert(arguments) => apply(paths, &arguments, true, json).await,
    }
}

/// `kr diff read`.
async fn read(paths: &HostPaths, arguments: &DiffReadArguments, json: bool) -> Result<()> {
    let workspace: Option<WorkspaceId> = arguments
        .workspace
        .as_deref()
        .map(|text| identifier(text, "a workspace"))
        .transpose()?;
    let change_set = arguments
        .change_set
        .as_deref()
        .map(crate::changeset::change_set_identifier)
        .transpose()?;
    let mut daemon = Daemon::open(paths, &arguments.selector).await?;
    let read: DiffReadResult = daemon
        .read(
            Method::DiffRead,
            &DiffReadParams {
                workspace_id: workspace.map_or_else(Nullable::null, Nullable::some),
                change_set_id: change_set.map_or_else(Nullable::null, Nullable::some),
                version: arguments
                    .version
                    .map(ChangeSetVersion::new)
                    .map_or_else(Nullable::null, Nullable::some),
            },
        )
        .await?;
    if json {
        report::print_json(&report::answer(&read)?);
        return Ok(());
    }
    println!(
        "workspace {} of repository {}",
        read.workspace_id, read.project_repository_id
    );
    if let Some(version) = read.source_version.as_ref() {
        println!(
            "version {} of change set {}",
            version.version.get(),
            version.change_set_id
        );
    }
    println!(
        "base {}{}, head {}{}",
        read.base_revision,
        named(read.base_reference.as_ref()),
        read.head_revision,
        named(read.head_reference.as_ref())
    );
    for entry in read.tracked.iter().chain(&read.untracked) {
        println!("{}", entry_line(entry));
    }
    if read.omitted_entries.get() > 0 {
        println!("and {} more paths", read.omitted_entries.get());
    }
    for limitation in &read.limitations {
        println!("note: {limitation}");
    }
    Ok(())
}

/// `kr diff apply` and `kr diff revert`.
async fn apply(
    paths: &HostPaths,
    arguments: &DiffApplyArguments,
    revert: bool,
    json: bool,
) -> Result<()> {
    let change_set = crate::changeset::change_set_identifier(&arguments.change_set)?;
    let workspace: Option<WorkspaceId> = arguments
        .workspace
        .as_deref()
        .map(|text| identifier(text, "a workspace"))
        .transpose()?;
    let destination = destination(arguments.to);
    let expected_reference = match (&arguments.reference, &arguments.reference_at) {
        (Some(name), Some(value)) => Nullable::some(ExpectedReference {
            name: name.clone(),
            expected_old_value: if value == ABSENT {
                Nullable::null()
            } else {
                Nullable::some(value.clone())
            },
        }),
        _ => Nullable::null(),
    };
    let affected = arguments
        .expect
        .iter()
        .map(|text| expectation(text))
        .collect::<Result<Vec<_>>>()?;
    let mut daemon = Daemon::open(paths, &arguments.selector).await?;
    let applied: DiffApplyResult = daemon
        .mutate(
            if revert {
                Method::DiffRevert
            } else {
                Method::DiffApply
            },
            &DiffApplyParams {
                change_set_id: change_set,
                version: ChangeSetVersion::new(arguments.version),
                destination,
                workspace_id: workspace.map_or_else(Nullable::null, Nullable::some),
                expected_reference,
                affected,
                paths: arguments.paths.clone(),
                preflight_only: arguments.preflight,
                acknowledged_limitations: arguments.acknowledge.clone(),
            },
        )
        .await?;
    if json {
        report::print_json(&report::answer(&applied)?);
    } else {
        print!("{}", outcome(&applied, revert));
    }
    Ok(())
}

const fn destination(argument: DestinationArgument) -> DestinationClass {
    match argument {
        DestinationArgument::Proposal => DestinationClass::Proposal,
        DestinationArgument::Reference => DestinationClass::VersionedReference,
        DestinationArgument::WorkingTree => DestinationClass::SharedExisting,
    }
}

/// Reads one `--expect PATH=DIGEST` or `--expect PATH=absent`.
///
/// The digest is the last part: a path can hold `=`, and a digest cannot.
fn expectation(text: &str) -> Result<AffectedVersion> {
    let Some((path, expected)) = text.rsplit_once('=') else {
        return Err(CliError::Usage(format!(
            "--expect {text}: name a path and what it holds now, as PATH=DIGEST or PATH={ABSENT}"
        )));
    };
    if path.is_empty() {
        return Err(CliError::Usage(format!("--expect {text} names no path")));
    }
    let expected_worktree_digest = if expected == ABSENT {
        Nullable::null()
    } else {
        Nullable::some(digest(expected).ok_or_else(|| {
            CliError::Usage(format!(
                "--expect {text}: {expected} is not a content digest as kr diff read shows one"
            ))
        })?)
    };
    Ok(AffectedVersion {
        path: path.to_owned(),
        expected_worktree_digest,
        expected_index_object_id: Nullable::null(),
        expected_index_mode: Nullable::null(),
        check_index: false,
    })
}

/// Reads a content digest in the form the host prints one.
fn digest(text: &str) -> Option<Digest256> {
    let bytes = kr_protocol::scalars::from_base64url(text).ok()?;
    Some(Digest256::from_bytes(bytes.try_into().ok()?))
}

/// What one apply or revert came to, as lines for a person: the outcome first, then the host's own
/// account of it.
fn outcome(applied: &DiffApplyResult, revert: bool) -> String {
    let done = if revert { "Reverted" } else { "Applied" };
    let place = match applied.destination {
        DestinationClass::Proposal => "as a proposal",
        DestinationClass::VersionedReference => "to the reference",
        DestinationClass::SharedExisting => "to the working tree",
    };
    let mut text = match applied.outcome.as_ref() {
        Some(ApplyOutcomeClass::Applied) => format!("{done} {place}.\n"),
        Some(ApplyOutcomeClass::PreflightConflict) => {
            "The destination was not what the request expected, and nothing was written.\n"
                .to_owned()
        }
        Some(ApplyOutcomeClass::ConflictAfterPartialWrites) => {
            "Some paths were written, and then the destination stopped being what the request \
             expected.\n"
                .to_owned()
        }
        Some(ApplyOutcomeClass::InterruptedApply) => {
            "Some paths were written, and then this host stopped before it finished.\n".to_owned()
        }
        Some(ApplyOutcomeClass::UncertainOutcome) => {
            "This host cannot say what the destination holds now.\n".to_owned()
        }
        // A preflight that found the destination as expected: nothing ran, and the detail says so.
        None => String::new(),
    };
    if !applied.detail.is_empty() {
        text.push_str(&format!("{}\n", applied.detail));
    }
    if let Some(proposal) = applied.proposal_version.as_ref() {
        text.push_str(&format!(
            "proposal: version {} of change set {}\n",
            proposal.version.get(),
            proposal.change_set_id
        ));
    }
    if let Some(reference) = applied.reference.as_ref() {
        text.push_str(&format!(
            "reference {}: {}\n",
            reference.name,
            if reference.updated {
                "moved"
            } else {
                "not moved"
            }
        ));
    }
    for path in &applied.changed_paths {
        text.push_str(&format!("changed: {path}\n"));
    }
    for path in &applied.unresolved_paths {
        text.push_str(&format!("not established: {path}\n"));
    }
    for conflict in &applied.conflicts {
        text.push_str(&format!(
            "conflict: {}: {}\n",
            conflict.path, conflict.detail
        ));
    }
    for limitation in &applied.limitations {
        text.push_str(&format!("note: {limitation}\n"));
    }
    text
}

/// One path of a read as a line for a person, with the digest `--expect` takes for it.
fn entry_line(entry: &DiffEntry) -> String {
    let digest = entry
        .content_digest
        .as_ref()
        .map_or_else(|| ABSENT.to_owned(), report::wire_name);
    format!(
        "{:<18} {:<8} {digest}  {}",
        entry.class.as_str(),
        report::wire_name(&entry.change),
        entry.path
    )
}

/// ` (name)` for a reference that has a name, and nothing for one that has none.
fn named(reference: Option<&String>) -> String {
    reference.map_or_else(String::new, |name| format!(" ({name})"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_expectation_names_a_path_and_what_it_holds() {
        let digest = Digest256::from_bytes([9; 32]);
        let text = format!("docs/a=b.md={}", report::wire_name(&digest));
        let read = expectation(&text).expect("reads");
        assert_eq!(read.path, "docs/a=b.md", "the digest is the last part");
        assert_eq!(read.expected_worktree_digest, Nullable::some(digest));
        assert!(!read.check_index);

        let absent = expectation("new.txt=absent").expect("reads");
        assert_eq!(absent.path, "new.txt");
        assert_eq!(absent.expected_worktree_digest, Nullable::null());

        for wrong in ["no-digest", "=absent", "a.txt=not-a-digest"] {
            assert_eq!(
                expectation(wrong).expect_err(wrong).exit_code(),
                2,
                "{wrong}"
            );
        }
    }
}
