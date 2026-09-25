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
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{ChangeSetVersion, WorkspaceId};
use kr_protocol::method::Method;
use kr_protocol::project::ChangeKind;
use kr_protocol::scalars::{Digest256, Nullable};

use crate::cli::{DestinationArgument, DiffApplyArguments, DiffCommand, DiffReadArguments};
use crate::daemon::{Daemon, identifier};
use crate::error::{CliError, Result};
use crate::report::{self, Completion};

/// What `--expect` and `--reference-at` take for a path or a reference that does not exist.
const ABSENT: &str = "absent";

/// What a read shows for a path whose content it has no digest for and does not know to be absent:
/// a link, something that is not a file, or a file the host could not read.
const UNAVAILABLE: &str = "unavailable";

/// Runs one `kr diff` command and prints its result.
///
/// An apply or a revert the host began and did not finish is reported with everything the host
/// said about it, and the command then fails with that outcome.
///
/// # Errors
///
/// Returns a usage mistake, the daemon's refusal, or a transport failure.
pub async fn run(paths: &HostPaths, command: DiffCommand, json: bool) -> Result<Completion> {
    match command {
        DiffCommand::Read(arguments) => read(paths, &arguments, json)
            .await
            .map(|()| Completion::Done),
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
) -> Result<Completion> {
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
    let unfinished = unfinished(&applied, revert);
    match (&unfinished, json) {
        (None, true) => report::print_json(&report::answer(&applied)?),
        (Some(error), true) => report::print_json(&report::answer_that_failed(&applied, error)?),
        (None, false) => print!("{}", outcome(&applied, revert)),
        (Some(error), false) => {
            print!("{}", outcome(&applied, revert));
            eprintln!("kr: {error}");
        }
    }
    Ok(unfinished.map_or(Completion::Done, Completion::Reported))
}

/// The failure an apply or a revert that did not finish is reported as, or none when it finished.
///
/// A preflight that found the destination as expected ran nothing and is no failure. Every class
/// but an applied change is one: the destination is not what the request asked for, whether
/// nothing, some or an unknown part of the change reached it.
fn unfinished(applied: &DiffApplyResult, revert: bool) -> Option<CliError> {
    let (code, what) = match applied.outcome.as_ref()? {
        ApplyOutcomeClass::Applied => return None,
        ApplyOutcomeClass::PreflightConflict => (
            ErrorCode::DraftConflict,
            "the destination was not what the request expected, and nothing was written",
        ),
        ApplyOutcomeClass::ConflictAfterPartialWrites => (
            ErrorCode::DraftConflict,
            "some paths were written, and then the destination stopped being what the request \
             expected",
        ),
        ApplyOutcomeClass::InterruptedApply => (
            ErrorCode::OutcomeUnknown,
            "some paths were written, and then the host stopped before it finished",
        ),
        ApplyOutcomeClass::UncertainOutcome => (
            ErrorCode::OutcomeUnknown,
            "the host cannot say what the destination holds",
        ),
    };
    Some(CliError::Unfinished {
        code,
        message: format!(
            "the {} did not finish: {what}; the result names each path and what to recover from",
            if revert { "revert" } else { "apply" }
        ),
    })
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
    for progress in &applied.progress {
        text.push_str(&format!(
            "{:<10} {}{}\n",
            progress.state.as_str(),
            progress.path,
            if progress.detail.is_empty() {
                String::new()
            } else {
                format!(": {}", progress.detail)
            }
        ));
    }
    let recovery = &applied.recovery;
    for (what, version) in [
        ("before", recovery.before_version.as_ref()),
        ("after", recovery.after_version.as_ref()),
    ] {
        if let Some(version) = version {
            text.push_str(&format!(
                "the destination {what} it: version {} of change set {}\n",
                version.version.get(),
                version.change_set_id
            ));
        }
    }
    if let Some(staged) = recovery.staged_path.as_ref() {
        text.push_str(&format!("staged at: {staged}\n"));
    }
    for leftover in &recovery.staged_leftovers {
        text.push_str(&format!("left beside a destination path: {leftover}\n"));
    }
    for limitation in &applied.limitations {
        text.push_str(&format!("note: {limitation}\n"));
    }
    text
}

/// One path of a read as a line for a person, with the digest `--expect` takes for it.
///
/// A path with no digest is `absent` only when the read says the path was deleted. Anything else
/// the host could not digest, a link, something that is not a file or a file it could not read, is
/// `unavailable`, which `--expect` does not take, because saying such a path is absent would be
/// an expectation nobody established.
fn entry_line(entry: &DiffEntry) -> String {
    let digest = match (entry.content_digest.as_ref(), entry.change) {
        (Some(digest), _) => report::wire_name(digest),
        (None, ChangeKind::Deleted) => ABSENT.to_owned(),
        (None, ChangeKind::Present | ChangeKind::Unmerged) => UNAVAILABLE.to_owned(),
    };
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
    use kr_protocol::changeset::{PathClass, RecoveryObjects, VersionRef};
    use kr_protocol::ids::{ActionId, ChangeSetId};
    use kr_protocol::project::ContentClass;
    use kr_protocol::scalars::{TimestampMs, Uuid};

    use super::*;

    fn version(number: u64) -> VersionRef {
        VersionRef {
            change_set_id: ChangeSetId::new(Uuid::from_bytes([5; 16])),
            version: ChangeSetVersion::new(number),
        }
    }

    fn result(outcome: Option<ApplyOutcomeClass>) -> DiffApplyResult {
        DiffApplyResult {
            action_id: ActionId::new(Uuid::from_bytes([6; 16])),
            outcome: Nullable(outcome),
            destination: DestinationClass::SharedExisting,
            applied_version: version(1),
            proposal_version: Nullable::null(),
            reference: Nullable::null(),
            changed_paths: vec!["README.md".to_owned()],
            unresolved_paths: vec!["notes.txt".to_owned()],
            conflicts: Vec::new(),
            progress: Vec::new(),
            recovery: RecoveryObjects {
                before_version: Nullable::some(version(2)),
                after_version: Nullable::null(),
                applied_version: Nullable::some(version(1)),
                staged_path: Nullable::null(),
                staged_leftovers: Vec::new(),
                detail: String::new(),
            },
            limitations: Vec::new(),
            detail: "the host stopped".to_owned(),
            decided_at_ms: TimestampMs::new(1),
        }
    }

    #[test]
    fn only_a_change_that_landed_whole_or_a_clean_preflight_is_a_success() {
        assert!(unfinished(&result(Some(ApplyOutcomeClass::Applied)), false).is_none());
        assert!(
            unfinished(&result(None), false).is_none(),
            "a clean preflight"
        );
        for (outcome, code) in [
            (ApplyOutcomeClass::PreflightConflict, "DRAFT_CONFLICT"),
            (
                ApplyOutcomeClass::ConflictAfterPartialWrites,
                "DRAFT_CONFLICT",
            ),
            (ApplyOutcomeClass::InterruptedApply, "OUTCOME_UNKNOWN"),
            (ApplyOutcomeClass::UncertainOutcome, "OUTCOME_UNKNOWN"),
        ] {
            let error = unfinished(&result(Some(outcome)), true).expect("a failure");
            assert_eq!(error.code(), code, "{outcome:?}");
            assert_ne!(error.exit_code(), 0, "{outcome:?}");
            assert!(
                error.to_string().starts_with("the revert did not finish"),
                "{error}"
            );
        }
    }

    #[test]
    fn an_unfinished_apply_says_what_landed_and_what_to_recover_from() {
        let applied = result(Some(ApplyOutcomeClass::InterruptedApply));
        let text = outcome(&applied, false);
        assert!(text.contains("changed: README.md"), "{text}");
        assert!(text.contains("not established: notes.txt"), "{text}");
        assert!(
            text.contains("the destination before it: version 2"),
            "{text}"
        );
        let error = unfinished(&applied, false).expect("a failure");
        let document = report::answer_that_failed(&applied, &error).expect("a document");
        assert_eq!(document["ok"], serde_json::Value::Bool(false));
        assert_eq!(document["code"], "OUTCOME_UNKNOWN");
        assert_eq!(document["exit_code"], 1);
        assert_eq!(document["outcome"], "interrupted_apply");
        assert!(
            document["recovery"]["before_version"].is_object(),
            "the recovery objects are kept: {document}"
        );
    }

    fn entry(change: ChangeKind, digest: Option<Digest256>) -> DiffEntry {
        DiffEntry {
            path: "link".to_owned(),
            class: PathClass::UntrackedFile,
            change,
            content: ContentClass::Unknown,
            byte_len: Nullable::null(),
            base_object_id: Nullable::null(),
            content_digest: Nullable(digest),
        }
    }

    #[test]
    fn a_path_with_no_digest_is_absent_only_when_it_was_deleted() {
        assert!(entry_line(&entry(ChangeKind::Deleted, None)).contains(" absent  link"));
        assert!(entry_line(&entry(ChangeKind::Present, None)).contains(" unavailable  link"));
        assert!(entry_line(&entry(ChangeKind::Unmerged, None)).contains(" unavailable  link"));
        let digest = Digest256::from_bytes([1; 32]);
        assert!(
            entry_line(&entry(ChangeKind::Present, Some(digest)))
                .contains(&report::wire_name(&digest))
        );
    }

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
