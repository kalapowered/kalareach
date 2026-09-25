//! `kr workspace`: the working copies of a repository that sessions use.
//!
//! A workspace is one of two kinds, and the person names which every time: the repository's own
//! tree, shared and used where it is, or an isolated tree made from a base. There is no default,
//! because the two have different concurrency and different guarantees. An isolated workspace also
//! names how it is separated and where its tree goes, and which classes of the person's uncommitted
//! work it starts with; a class not named is left out of the new tree and stays where it is in the
//! person's own. A shared workspace is the person's own tree, so it keeps every class in place.
//!
//! A creation can be previewed first: the same request with nothing written, answered with what a
//! reviewer would see. A removal never takes what a workspace still holds unless the person says
//! so, and the answer lists what is held.

use kr_client::shown::Shown;
use kr_ipc::paths::HostPaths;
use kr_protocol::ids::{ChangeSetId, WorkspaceId};
use kr_protocol::method::Method;
use kr_protocol::project::{
    InclusionChoice, InclusionPolicy, InclusionPreview, IsolationMechanism, RetentionPolicy,
    WorkspaceCreateParams, WorkspaceCreateResult, WorkspaceKind, WorkspaceListParams,
    WorkspaceListResult, WorkspaceRemoveParams, WorkspaceRemoveResult, WorkspaceSummary,
};
use kr_protocol::scalars::Nullable;

use crate::cli::{
    InclusionArgument, IsolationArgument, WorkspaceCommand, WorkspaceCreateArguments,
    WorkspaceKindArgument, WorkspaceListArguments, WorkspaceRemoveArguments,
};
use crate::daemon::{Daemon, identifier};
use crate::error::{CliError, Result};
use crate::report;

/// Runs one `kr workspace` command and prints its result.
///
/// # Errors
///
/// Returns a usage mistake, the daemon's refusal, or a transport failure.
pub async fn run(paths: &HostPaths, command: WorkspaceCommand, json: bool) -> Result<()> {
    match command {
        WorkspaceCommand::List(arguments) => list(paths, &arguments, json).await,
        WorkspaceCommand::Create(arguments) => create(paths, &arguments, json).await,
        WorkspaceCommand::Remove(arguments) => remove(paths, &arguments, json).await,
    }
}

/// `kr workspace list`.
async fn list(paths: &HostPaths, arguments: &WorkspaceListArguments, json: bool) -> Result<()> {
    let project = arguments
        .project
        .as_deref()
        .map(crate::project::project_identifier)
        .transpose()?;
    let mut daemon = Daemon::open(paths, &arguments.selector).await?;
    let listed: WorkspaceListResult = daemon
        .read(
            Method::WorkspaceList,
            &WorkspaceListParams {
                environment_id: daemon.environment_id(),
                project_repository_id: project.map_or_else(Nullable::null, Nullable::some),
            },
        )
        .await?;
    if json {
        report::print_json(&report::answer(&listed)?);
    } else if listed.workspaces.is_empty() {
        println!("no workspaces");
    } else {
        for workspace in &listed.workspaces {
            println!("{}", line(workspace));
        }
    }
    Ok(())
}

/// `kr workspace create`.
async fn create(paths: &HostPaths, arguments: &WorkspaceCreateArguments, json: bool) -> Result<()> {
    let project = crate::project::project_identifier(&arguments.project)?;
    let base_change_set: Option<ChangeSetId> = arguments
        .base_change_set
        .as_deref()
        .map(|text| identifier(text, "a change set"))
        .transpose()?;
    let (kind, policy) = match arguments.kind {
        // The repository's own tree keeps the person's uncommitted work where it is, so every
        // class is in it; excluding one would need a tree of its own.
        WorkspaceKindArgument::Shared => {
            if !arguments.include.is_empty() {
                return Err(CliError::Usage(Shown::said(
                    "--include chooses what an isolated workspace starts with; a shared one is \
                     the repository's own tree and keeps everything in place",
                )));
            }
            (
                WorkspaceKind::SharedExisting,
                policy(&[InclusionArgument::All]),
            )
        }
        WorkspaceKindArgument::Isolated => (WorkspaceKind::Isolated, policy(&arguments.include)),
    };
    let mut daemon = Daemon::open(paths, &arguments.selector).await?;
    let destination = arguments
        .path
        .as_deref()
        .map(|path| crate::project::destination(daemon.environment_id(), path))
        .transpose()?;
    let label = match (&arguments.label, &destination) {
        (Some(label), _) => label.clone(),
        (None, Some(destination)) => destination.name.clone(),
        (None, None) => "shared".to_owned(),
    };
    let created: WorkspaceCreateResult = daemon
        .mutate(
            Method::WorkspaceCreate,
            &WorkspaceCreateParams {
                project_repository_id: project,
                label,
                kind,
                isolation: arguments
                    .isolation
                    .map(isolation)
                    .map_or_else(Nullable::null, Nullable::some),
                policy,
                base_revision: arguments
                    .base
                    .clone()
                    .map_or_else(Nullable::null, Nullable::some),
                base_change_set_id: base_change_set.map_or_else(Nullable::null, Nullable::some),
                destination: destination.map_or_else(Nullable::null, Nullable::some),
                preview_only: arguments.preview,
            },
        )
        .await?;
    if json {
        report::print_json(&report::answer(&created)?);
        return Ok(());
    }
    match created.workspace.as_ref() {
        Some(workspace) => println!(
            "Created workspace {} ({}) at {}.",
            workspace.workspace_id,
            report::wire_name(&workspace.kind),
            workspace.display_path
        ),
        None => println!("Nothing was created. The workspace would hold:"),
    }
    print!("{}", preview(&created.preview));
    for path in &created.unapplied {
        println!("not carried into the workspace: {path}");
    }
    Ok(())
}

/// `kr workspace remove`.
async fn remove(paths: &HostPaths, arguments: &WorkspaceRemoveArguments, json: bool) -> Result<()> {
    let workspace: WorkspaceId = identifier(&arguments.workspace, "a workspace")?;
    let mut daemon = Daemon::open(paths, &arguments.selector).await?;
    let removed: WorkspaceRemoveResult = daemon
        .mutate(
            Method::WorkspaceRemove,
            &WorkspaceRemoveParams {
                workspace_id: workspace,
                retention: if arguments.remove_retained {
                    RetentionPolicy::RemoveRetained
                } else {
                    RetentionPolicy::KeepEverything
                },
                through_location_id: Nullable::null(),
            },
        )
        .await?;
    if json {
        report::print_json(&report::answer(&removed)?);
        return Ok(());
    }
    println!(
        "Workspace {} is {}.",
        removed.workspace.workspace_id,
        report::wire_name(&removed.workspace.state)
    );
    if removed.working_files_removed {
        println!("Its working files are gone.");
    }
    if !removed.retained.is_empty() {
        println!("It still holds, until you remove it with --remove-retained:");
        for item in &removed.retained {
            println!("  {}: {}", report::wire_name(&item.kind), item.detail);
        }
    }
    Ok(())
}

/// The inclusion policy the classes a person named make: those classes in, every other one out.
#[must_use]
pub fn policy(included: &[InclusionArgument]) -> InclusionPolicy {
    let choice = |class: InclusionArgument| {
        if included.contains(&class) || included.contains(&InclusionArgument::All) {
            InclusionChoice::Include
        } else {
            InclusionChoice::Exclude
        }
    };
    InclusionPolicy {
        dirty_files: choice(InclusionArgument::DirtyFiles),
        untracked_files: choice(InclusionArgument::UntrackedFiles),
        submodules: choice(InclusionArgument::Submodules),
        binary_files: choice(InclusionArgument::BinaryFiles),
        generated_artefacts: choice(InclusionArgument::GeneratedArtefacts),
    }
}

const fn isolation(argument: IsolationArgument) -> IsolationMechanism {
    match argument {
        IsolationArgument::GitWorktree => IsolationMechanism::GitWorktree,
        IsolationArgument::IndependentClone => IsolationMechanism::IndependentClone,
    }
}

/// What a reviewer would see, as lines for a person: the base, each class's counts and what the
/// host says the preview cannot promise.
fn preview(preview: &InclusionPreview) -> String {
    let mut text = format!("  base {}\n", preview.base_revision);
    for count in &preview.counts {
        text.push_str(&format!(
            "  {:<20} {} of {} included\n",
            count.class.as_str(),
            count.included.get(),
            count.total.get()
        ));
    }
    if !preview.counts_complete {
        text.push_str("  the counts are lower bounds\n");
    }
    for limitation in &preview.limitations {
        text.push_str(&format!("  note: {limitation}\n"));
    }
    text
}

/// One workspace as a line for a person.
fn line(workspace: &WorkspaceSummary) -> String {
    format!(
        "{}  {:<15} {:<15} {}  {}",
        workspace.workspace_id,
        report::wire_name(&workspace.kind),
        report::wire_name(&workspace.state),
        workspace.label,
        workspace.display_path,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_class_not_named_is_left_out() {
        let named = policy(&[InclusionArgument::DirtyFiles]);
        assert_eq!(named.dirty_files, InclusionChoice::Include);
        assert_eq!(named.untracked_files, InclusionChoice::Exclude);
        assert_eq!(named.submodules, InclusionChoice::Exclude);
        assert_eq!(named.binary_files, InclusionChoice::Exclude);
        assert_eq!(named.generated_artefacts, InclusionChoice::Exclude);
        assert_eq!(policy(&[]), InclusionPolicy::base_only());
        let every = policy(&[InclusionArgument::All]);
        assert!(
            kr_protocol::project::InclusionClass::EVERY
                .iter()
                .all(|class| every.choice(*class) == InclusionChoice::Include)
        );
    }
}
