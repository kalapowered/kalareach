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
use crate::report;

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
        report::print_json(&report::answer(&captured)?);
    } else {
        println!("Captured {}.", version_line(&captured.version));
        if captured.pinned {
            println!("It is pinned against its workspace.");
        }
        print!("{}", details(&captured.version));
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
        report::print_json(&report::answer(&read)?);
        return Ok(());
    }
    println!("{}", version_line(&read.version));
    print!("{}", details(&read.version));
    println!("versions:");
    for version in &read.versions {
        println!(
            "  {:>3}  {:<16} base {}",
            version.version.get(),
            version.consistency.as_str(),
            version.base_revision
        );
    }
    for materialisation in &read.materialisations {
        println!(
            "materialised {} ({}) at {}",
            materialisation.materialisation_id,
            report::wire_name(&materialisation.purpose),
            materialisation.directory_path
        );
    }
    for evidence in &read.evidence {
        println!(
            "evidence: {} {}",
            report::wire_name(&evidence.kind),
            evidence.detail
        );
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
                    .unwrap_or_else(|| report::wire_name(&purpose)),
            },
        )
        .await?;
    if json {
        report::print_json(&report::answer(&materialised)?);
        return Ok(());
    }
    let record = &materialised.materialisation;
    println!(
        "Materialised version {} of change set {} as {} at {}: {} paths written.",
        record.version.version.get(),
        record.version.change_set_id,
        record.materialisation_id,
        record.directory_path,
        record.paths_written.get()
    );
    for path in &record.unapplied {
        println!("not written: {path}");
    }
    for limitation in &materialised.limitations {
        println!("note: {limitation}");
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

/// One version as a line for a person.
fn version_line(version: &ChangeSetVersionRecord) -> String {
    format!(
        "version {} of change set {} ({}), {}",
        version.version.get(),
        version.change_set_id,
        version.label,
        version.consistency.as_str()
    )
}

/// What one version holds, as lines for a person: its counts, its changes and what the host says
/// it cannot promise.
fn details(version: &ChangeSetVersionRecord) -> String {
    let paths = version.summary.total_paths.get();
    let mut text = format!(
        "  base {}, {paths} path{}, {} bytes, {} changed\n",
        version.base_revision,
        if paths == 1 { "" } else { "s" },
        version.summary.total_bytes.get(),
        version.changes.len() as u64 + version.omitted_changes.get()
    );
    for change in &version.changes {
        text.push_str(&format!(
            "  {:<16} {:<8} {}\n",
            change.class.as_str(),
            report::wire_name(&change.change),
            change.path
        ));
    }
    if version.omitted_changes.get() > 0 {
        text.push_str(&format!(
            "  and {} more changes\n",
            version.omitted_changes.get()
        ));
    }
    for exclusion in &version.exclusions {
        text.push_str(&format!(
            "  left out: {} ({})\n",
            exclusion.path,
            exclusion.reason.as_str()
        ));
    }
    for limitation in &version.limitations {
        text.push_str(&format!("  note: {limitation}\n"));
    }
    text
}
