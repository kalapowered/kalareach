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

use kr_client::shown;
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
use crate::output::{self, Asked, Line, Request, left};
use crate::{answer, stdout_line};

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
        output::document(&answer::workspace_list_result(&listed));
    } else if listed.workspaces.is_empty() {
        output::say(&Shown::said("no workspaces"));
    } else {
        for workspace in &listed.workspaces {
            output::line(&line(workspace));
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
        output::document(&answer::workspace_create_result(&created));
        return Ok(());
    }
    match created.workspace.as_ref() {
        Some(workspace) => output::line(&stdout_line!(
            "Created workspace {} ({}) at {}.",
            output::closed_word(&workspace.workspace_id),
            crate::shown::wire_word(workspace.kind),
            Asked::text(Request::Workspaces, &workspace.display_path)
        )),
        None => output::say(&Shown::said(
            "Nothing was created. The workspace would hold:",
        )),
    }
    output::lines(&preview(&created.preview));
    for path in &created.unapplied {
        output::line(&stdout_line!(
            "not carried into the workspace: {}",
            Asked::text(Request::Workspaces, path)
        ));
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
        output::document(&answer::workspace_remove_result(&removed));
        return Ok(());
    }
    output::say(&shown!(
        "Workspace {} is {}.",
        output::closed_word(&removed.workspace.workspace_id),
        crate::shown::wire_word(removed.workspace.state)
    ));
    if removed.working_files_removed {
        output::say(&Shown::said("Its working files are gone."));
    }
    if !removed.retained.is_empty() {
        output::say(&Shown::said(
            "It still holds, until you remove it with --remove-retained:",
        ));
        for item in &removed.retained {
            output::say(&shown!(
                "  {}: {}",
                crate::shown::wire_word(item.kind),
                crate::shown::exported("RetainedItem", "detail", &item.detail)
            ));
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

/// What a reviewer would see, as lines for a person: the base, each class's counts and, as their
/// class and length, what the host says the preview cannot promise.
fn preview(preview: &InclusionPreview) -> Vec<Line> {
    let mut lines = vec![stdout_line!(
        "  base {}",
        crate::shown::git_revision(&preview.base_revision)
    )];
    for count in &preview.counts {
        lines.push(stdout_line!(
            "  {} {} of {} included",
            left(20, &count.class.as_str()),
            count.included.get(),
            count.total.get()
        ));
    }
    if !preview.counts_complete {
        lines.push(stdout_line!("  the counts are lower bounds"));
    }
    for limitation in &preview.limitations {
        lines.push(stdout_line!(
            "  note: {}",
            crate::shown::exported("InclusionPreview", "limitations", limitation)
        ));
    }
    lines
}

/// One workspace as a line for a person: its label and path are what the person asked for.
fn line(workspace: &WorkspaceSummary) -> Line {
    stdout_line!(
        "{}  {} {} {}  {}",
        output::closed_word(&workspace.workspace_id),
        left(15, &crate::shown::wire_word(workspace.kind)),
        left(15, &crate::shown::wire_word(workspace.state)),
        Asked::text(Request::Workspaces, &workspace.label),
        Asked::text(Request::Workspaces, &workspace.display_path),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// KR-REQ-23.25: planted text in a workspace's lines shows only where the person asked for it:
    /// its label and its path; a preview's base is said only when it is a revision, and what the
    /// host says a preview cannot promise as its class and its length.
    #[test]
    fn planted_text_in_workspace_lines_shows_only_where_it_was_asked_for() {
        for workspace in crate::output::planted::planted::<WorkspaceSummary>() {
            crate::output::planted::only_asked_lines("kr workspace list", &[line(&workspace)]);
        }
        for inclusion in crate::output::planted::planted::<InclusionPreview>() {
            crate::output::planted::only_asked_lines("kr workspace create", &preview(&inclusion));
        }
    }

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
