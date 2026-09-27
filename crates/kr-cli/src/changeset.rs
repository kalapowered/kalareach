//! `kr changeset`: exact, immutable versions of a workspace's work.
//!
//! A capture reads a workspace under the policy and the file grant the person names, and records
//! one version with its consistency class: what the host could establish about the source, never
//! more. A read names one exact version and every version beside it. A materialisation writes one
//! exact version into a directory of the host's own, so a test or a reviewer runs against exactly
//! that version while the workspace it came from goes on changing.

use kr_ipc::paths::HostPaths;
use kr_protocol::changeset::{
    ChangeSetVersionRecord, ChangesetCaptureParams, ChangesetCaptureResult,
    ChangesetMaterializeParams, ChangesetMaterializeResult, ChangesetReadParams,
    ChangesetReadResult, FileGrant, MaterialisationPurpose, SourceConsistency,
};
use kr_protocol::ids::{ChangeSetId, ChangeSetVersion, WorkspaceId};
use kr_protocol::method::Method;
use kr_protocol::scalars::Nullable;

use crate::cli::{
    ChangesetCaptureArguments, ChangesetCommand, ChangesetMaterializeArguments,
    ChangesetReadArguments, ConsistencyArgument, PurposeArgument,
};
use crate::daemon::{Daemon, identifier};
use crate::error::Result;
use crate::output::{self, Asked, Line, Request, left, right};
use crate::{answer, stdout_line};

/// Runs one `kr changeset` command and prints its result.
///
/// # Errors
///
/// Returns a usage mistake, the daemon's refusal, or a transport failure.
pub async fn run(paths: &HostPaths, command: ChangesetCommand, json: bool) -> Result<()> {
    match command {
        ChangesetCommand::Capture(arguments) => capture(paths, &arguments, json).await,
        ChangesetCommand::Read(arguments) => read(paths, &arguments, json).await,
        ChangesetCommand::Materialize(arguments) => materialize(paths, &arguments, json).await,
    }
}

/// `kr changeset capture`.
async fn capture(
    paths: &HostPaths,
    arguments: &ChangesetCaptureArguments,
    json: bool,
) -> Result<()> {
    let workspace: WorkspaceId = identifier(&arguments.workspace, "a workspace")?;
    let change_set = arguments
        .change_set
        .as_deref()
        .map(change_set_identifier)
        .transpose()?;
    let mut daemon = Daemon::open(paths, &arguments.selector).await?;
    let captured: ChangesetCaptureResult = daemon
        .mutate(
            Method::ChangesetCapture,
            &ChangesetCaptureParams {
                workspace_id: workspace,
                change_set_id: change_set.map_or_else(Nullable::null, Nullable::some),
                // An appended version keeps the label its change set already has.
                label: arguments.label.clone().unwrap_or_default(),
                policy: crate::workspace::policy(&arguments.include),
                grant: FileGrant {
                    included_paths: arguments.include_paths.clone(),
                    excluded_paths: arguments.exclude_paths.clone(),
                    // The host's own secret rules always apply, and the record says so.
                    secret_rules_applied: true,
                },
                quiescence_declared: arguments.quiesced,
                required_consistency: arguments
                    .require
                    .map(consistency)
                    .map_or_else(Nullable::null, Nullable::some),
                pin: arguments.pin,
                session_id: Nullable::null(),
                workflow_run_id: Nullable::null(),
                note: arguments.note.clone(),
            },
        )
        .await?;
    if json {
        output::document(&answer::changeset_capture_result(&captured));
    } else {
        output::line(&stdout_line!(
            "Captured {}.",
            version_words(&captured.version)
        ));
        if captured.pinned {
            output::line(&stdout_line!("It is pinned against its workspace."));
        }
        output::lines(&details(&captured.version));
    }
    Ok(())
}

/// `kr changeset read`.
async fn read(paths: &HostPaths, arguments: &ChangesetReadArguments, json: bool) -> Result<()> {
    let change_set = change_set_identifier(&arguments.change_set)?;
    let mut daemon = Daemon::open(paths, &arguments.selector).await?;
    let read: ChangesetReadResult = daemon
        .read(
            Method::ChangesetRead,
            &ChangesetReadParams {
                change_set_id: change_set,
                version: arguments
                    .version
                    .map(ChangeSetVersion::new)
                    .map_or_else(Nullable::null, Nullable::some),
            },
        )
        .await?;
    if json {
        output::document(&answer::changeset_read_result(&read));
        return Ok(());
    }
    output::line(&version_words(&read.version));
    output::lines(&details(&read.version));
    output::line(&stdout_line!("versions:"));
    for version in &read.versions {
        output::line(&stdout_line!(
            "  {}  {} base {}",
            right(3, &version.version.get()),
            left(16, &version.consistency.as_str()),
            crate::shown::git_revision(&version.base_revision)
        ));
    }
    for materialisation in &read.materialisations {
        output::line(&stdout_line!(
            "materialised {} ({}) at {}",
            output::closed_word(&materialisation.materialisation_id),
            crate::shown::wire_word(materialisation.purpose),
            Asked::path(Request::Changesets, &materialisation.directory_path)
        ));
    }
    for evidence in &read.evidence {
        output::line(&stdout_line!(
            "evidence: {} {}",
            crate::shown::wire_word(evidence.kind),
            crate::shown::exported("EvidenceReference", "detail", &evidence.detail)
        ));
    }
    Ok(())
}

/// `kr changeset materialize`.
async fn materialize(
    paths: &HostPaths,
    arguments: &ChangesetMaterializeArguments,
    json: bool,
) -> Result<()> {
    let change_set = change_set_identifier(&arguments.change_set)?;
    let purpose = purpose(arguments.purpose);
    let mut daemon = Daemon::open(paths, &arguments.selector).await?;
    let materialised: ChangesetMaterializeResult = daemon
        .mutate(
            Method::ChangesetMaterialize,
            &ChangesetMaterializeParams {
                change_set_id: change_set,
                version: ChangeSetVersion::new(arguments.version),
                purpose,
                label: arguments
                    .label
                    .clone()
                    .unwrap_or_else(|| crate::shown::wire_word(purpose).into_string()),
            },
        )
        .await?;
    if json {
        output::document(&answer::changeset_materialize_result(&materialised));
        return Ok(());
    }
    let record = &materialised.materialisation;
    output::line(&stdout_line!(
        "Materialised version {} of change set {} as {} at {}: {} paths written.",
        record.version.version.get(),
        output::closed_word(&record.version.change_set_id),
        output::closed_word(&record.materialisation_id),
        Asked::path(Request::Changesets, &record.directory_path),
        record.paths_written.get()
    ));
    for path in &record.unapplied {
        output::line(&stdout_line!(
            "not written: {}",
            Asked::path(Request::Changesets, path)
        ));
    }
    for limitation in &materialised.limitations {
        output::line(&stdout_line!(
            "note: {}",
            crate::shown::exported("ChangesetMaterializeResult", "limitations", limitation)
        ));
    }
    Ok(())
}

/// Reads a change-set identifier from the command line.
///
/// # Errors
///
/// Returns a usage mistake when the text is not one.
pub fn change_set_identifier(text: &str) -> Result<ChangeSetId> {
    identifier(text, "a change set")
}

const fn consistency(argument: ConsistencyArgument) -> SourceConsistency {
    match argument {
        ConsistencyArgument::PerFile => SourceConsistency::PerFileCapture,
        ConsistencyArgument::Quiesced => SourceConsistency::QuiescedCapture,
        ConsistencyArgument::Atomic => SourceConsistency::AtomicSnapshot,
    }
}

const fn purpose(argument: PurposeArgument) -> MaterialisationPurpose {
    match argument {
        PurposeArgument::Test => MaterialisationPurpose::Test,
        PurposeArgument::Review => MaterialisationPurpose::Review,
        PurposeArgument::Inspection => MaterialisationPurpose::Inspection,
    }
}

/// One version as a line for a person: its label is what they gave it.
fn version_words(version: &ChangeSetVersionRecord) -> Line {
    stdout_line!(
        "version {} of change set {} ({}), {}",
        version.version.get(),
        output::closed_word(&version.change_set_id),
        Asked::text(Request::Changesets, &version.label),
        version.consistency.as_str()
    )
}

/// What one version holds, as lines for a person: its counts, its changes and, as their class and
/// length, what the host says it cannot promise.
fn details(version: &ChangeSetVersionRecord) -> Vec<Line> {
    let paths = version.summary.total_paths.get();
    let mut lines = vec![stdout_line!(
        "  base {}, {} path{}, {} bytes, {} changed",
        crate::shown::git_revision(&version.base_revision),
        paths,
        if paths == 1 { "" } else { "s" },
        version.summary.total_bytes.get(),
        version.changes.len() as u64 + version.omitted_changes.get()
    )];
    for change in &version.changes {
        lines.push(stdout_line!(
            "  {} {} {}",
            left(16, &change.class.as_str()),
            left(8, &crate::shown::wire_word(change.change)),
            Asked::path(Request::Changesets, &change.path)
        ));
    }
    if version.omitted_changes.get() > 0 {
        lines.push(stdout_line!(
            "  and {} more changes",
            version.omitted_changes.get()
        ));
    }
    for exclusion in &version.exclusions {
        lines.push(stdout_line!(
            "  left out: {} ({})",
            Asked::path(Request::Changesets, &exclusion.path),
            exclusion.reason.as_str()
        ));
    }
    for limitation in &version.limitations {
        lines.push(stdout_line!(
            "  note: {}",
            crate::shown::exported("ChangeSetVersionRecord", "limitations", limitation)
        ));
    }
    lines
}
