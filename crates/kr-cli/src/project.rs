//! `kr project`: the source repositories of an environment.
//!
//! The environment's project service creates, clones and adopts a repository, through the control
//! daemon, and it keeps the record. What a person names here is a directory: a new one whose parent
//! exists, or an existing checkout. The command resolves it against the directory it runs in and
//! sends its parent and its one name inside that parent, which the daemon opens with this host's
//! own authority. Once the service has a repository, it is named by the identifier the service gave
//! it and never by a path again.
//!
//! A clone names its source by its form: an `https://` URL, an ssh remote, the absolute path of a
//! repository on this machine, or the identifier of a repository this environment has registered.
//! The service parses a remote again and refuses one whose form is not the transport named here.

use std::path::Path;

use kr_ipc::paths::HostPaths;
use kr_protocol::ids::{EnvironmentId, ProjectRepositoryId};
use kr_protocol::method::Method;
use kr_protocol::project::{
    AdoptionFlow, CloneSource, DestinationParent, DestinationRequest, ProjectAdoptParams,
    ProjectAdoptResult, ProjectCloneParams, ProjectCloneResult, ProjectInitParams,
    ProjectInitResult, ProjectListParams, ProjectListResult, ProjectSummary, RemoteSpecification,
    RemoteTransport,
};
use kr_protocol::scalars::Nullable;

use crate::cli::{
    ProjectAdoptArguments, ProjectCloneArguments, ProjectCommand, ProjectInitArguments,
    ProjectListArguments,
};
use crate::daemon::{Daemon, identifier};
use crate::error::{CliError, Result};
use crate::report;

/// Runs one `kr project` command and prints its result.
///
/// # Errors
///
/// Returns a usage mistake, the daemon's refusal, or a transport failure.
pub async fn run(paths: &HostPaths, command: ProjectCommand, json: bool) -> Result<()> {
    match command {
        ProjectCommand::List(arguments) => list(paths, &arguments, json).await,
        ProjectCommand::Init(arguments) => init(paths, &arguments, json).await,
        ProjectCommand::Clone(arguments) => clone(paths, &arguments, json).await,
        ProjectCommand::Adopt(arguments) => adopt(paths, &arguments, json).await,
    }
}

/// `kr project list`.
async fn list(paths: &HostPaths, arguments: &ProjectListArguments, json: bool) -> Result<()> {
    let mut daemon = Daemon::open(paths, &arguments.selector).await?;
    let listed: ProjectListResult = daemon
        .read(
            Method::ProjectList,
            &ProjectListParams {
                environment_id: daemon.environment_id(),
            },
        )
        .await?;
    if json {
        report::print_json(&report::answer(&listed)?);
    } else if listed.projects.is_empty() {
        println!("no repositories");
    } else {
        for project in &listed.projects {
            println!("{}", line(project));
        }
    }
    Ok(())
}

/// `kr project init`.
async fn init(paths: &HostPaths, arguments: &ProjectInitArguments, json: bool) -> Result<()> {
    let mut daemon = Daemon::open(paths, &arguments.selector).await?;
    let destination = destination(daemon.environment_id(), &arguments.path)?;
    let label = label_or_name(arguments.label.as_deref(), &destination);
    let created: ProjectInitResult = daemon
        .mutate(
            Method::ProjectInit,
            &ProjectInitParams {
                destination,
                label,
                initial_branch: arguments
                    .initial_branch
                    .clone()
                    .map_or_else(Nullable::null, Nullable::some),
            },
        )
        .await?;
    report_created("Initialised", &created.project, &created, json)
}

/// `kr project clone`.
async fn clone(paths: &HostPaths, arguments: &ProjectCloneArguments, json: bool) -> Result<()> {
    let source = clone_source(arguments)?;
    let mut daemon = Daemon::open(paths, &arguments.selector).await?;
    let destination = destination(daemon.environment_id(), &arguments.path)?;
    let label = label_or_name(arguments.label.as_deref(), &destination);
    let cloned: ProjectCloneResult = daemon
        .mutate(
            Method::ProjectClone,
            &ProjectCloneParams {
                destination,
                label,
                source,
            },
        )
        .await?;
    report_created("Cloned", &cloned.project, &cloned, json)
}

/// `kr project adopt`.
async fn adopt(paths: &HostPaths, arguments: &ProjectAdoptArguments, json: bool) -> Result<()> {
    let mut daemon = Daemon::open(paths, &arguments.selector).await?;
    let destination = destination(daemon.environment_id(), &arguments.path)?;
    let label = label_or_name(arguments.label.as_deref(), &destination);
    let adopted: ProjectAdoptResult = daemon
        .mutate(
            Method::ProjectAdopt,
            &ProjectAdoptParams {
                destination,
                label,
                // The one flow this host has: register the checkout and change nothing inside it.
                flow: AdoptionFlow::ExistingCheckout,
            },
        )
        .await?;
    report_created("Adopted", &adopted.project, &adopted, json)
}

/// Names a directory the way the project service takes one: the directory it is in, which the
/// daemon opens with this host's own authority, and its one name inside that directory.
///
/// A relative path is taken from the directory the command runs in. Nothing is looked up on disk
/// here; the daemon resolves the parent once, and everything after that is relative to its handle.
///
/// # Errors
///
/// Returns [`CliError::Usage`] for a path with no name of its own, such as `/` or one that ends in
/// `..`, and for a path that is not text.
pub fn destination(environment_id: EnvironmentId, path: &Path) -> Result<DestinationRequest> {
    let absolute = std::path::absolute(path).map_err(|error| {
        CliError::Usage(format!(
            "{} cannot be taken from this directory: {error}",
            path.display()
        ))
    })?;
    let (Some(parent), Some(name)) = (absolute.parent(), absolute.file_name()) else {
        return Err(CliError::Usage(format!(
            "{} names no directory of its own inside another one",
            absolute.display()
        )));
    };
    let as_text = |part: &std::ffi::OsStr| {
        part.to_str().map(str::to_owned).ok_or_else(|| {
            CliError::Usage(format!(
                "{} is not a path this host can record, because it is not text",
                absolute.display()
            ))
        })
    };
    Ok(DestinationRequest {
        environment_id,
        parent: DestinationParent::Host {
            path: as_text(parent.as_os_str())?,
        },
        name: as_text(name)?,
    })
}

/// The label a person gave, or the name of the directory when they gave none.
fn label_or_name(label: Option<&str>, destination: &DestinationRequest) -> String {
    label.map_or_else(|| destination.name.clone(), str::to_owned)
}

/// Where a clone's content comes from, by the form of what was typed.
fn clone_source(arguments: &ProjectCloneArguments) -> Result<CloneSource> {
    let text = arguments.source.as_str();
    if let Ok(project_repository_id) = text.parse::<ProjectRepositoryId>() {
        return Ok(CloneSource::Registered {
            project_repository_id,
        });
    }
    let transport = transport_of(text)?;
    Ok(CloneSource::Remote {
        remote: RemoteSpecification {
            remote_name: arguments.remote_name.clone(),
            transport,
            url: text.to_owned(),
            // The service names the provider from the host it resolves, never from the caller.
            provider: String::new(),
            // A local path reaches no network, so it names no broker.
            credential_broker: match transport {
                RemoteTransport::LocalPath => String::new(),
                RemoteTransport::Https | RemoteTransport::Ssh => {
                    arguments.credential_broker.clone()
                }
            },
        },
    })
}

/// Which transport a remote is, by its form.
///
/// The three forms this host clones from, and no fourth: a `git://` URL, a `file://` URL and a
/// remote helper's `transport::address` are refused here, as the service refuses them.
fn transport_of(text: &str) -> Result<RemoteTransport> {
    if text.starts_with("https://") {
        return Ok(RemoteTransport::Https);
    }
    if text.starts_with("ssh://") {
        return Ok(RemoteTransport::Ssh);
    }
    if !text.contains("://") {
        if Path::new(text).is_absolute() {
            return Ok(RemoteTransport::LocalPath);
        }
        // `user@host:path`, which is how an ssh remote is usually written: nothing before the
        // first colon is a slash, and something follows it.
        if let Some((authority, rest)) = text.split_once(':')
            && !authority.is_empty()
            && !authority.contains('/')
            && !rest.is_empty()
            && !rest.starts_with(':')
        {
            return Ok(RemoteTransport::Ssh);
        }
    }
    Err(CliError::Usage(format!(
        "{text} is not a source this host clones from: name an https:// URL, an ssh remote \
         (ssh://host/path or user@host:path), the absolute path of a repository on this machine, \
         or a registered repository's identifier"
    )))
}

/// Prints what a creation made.
fn report_created<T: serde::Serialize>(
    verb: &str,
    project: &ProjectSummary,
    answer: &T,
    json: bool,
) -> Result<()> {
    if json {
        report::print_json(&report::answer(answer)?);
    } else {
        println!(
            "{verb} {} as repository {} at {}.",
            project.label, project.project_repository_id, project.display_path
        );
    }
    Ok(())
}

/// One repository as a line for a person.
fn line(project: &ProjectSummary) -> String {
    format!(
        "{}  {:<8} {:<11} {:>2} workspace{}  {}  {}",
        project.project_repository_id,
        report::wire_name(&project.state),
        report::wire_name(&project.origin),
        project.workspace_count.get(),
        if project.workspace_count.get() == 1 {
            ""
        } else {
            "s"
        },
        project.label,
        project.display_path,
    )
}

/// Reads a repository identifier from the command line.
///
/// # Errors
///
/// Returns [`CliError::Usage`] when the text is not one.
pub fn project_identifier(text: &str) -> Result<ProjectRepositoryId> {
    identifier(text, "a repository")
}

#[cfg(test)]
mod tests {
    use kr_protocol::scalars::Uuid;

    use super::*;

    fn environment() -> EnvironmentId {
        EnvironmentId::new(Uuid::from_bytes([3; 16]))
    }

    #[test]
    fn a_directory_is_its_parent_and_its_one_name() {
        let work = std::env::temp_dir().join("work");
        let destination = destination(environment(), &work.join("fresh")).expect("names");
        assert_eq!(
            destination.parent,
            DestinationParent::Host {
                path: work.display().to_string()
            }
        );
        assert_eq!(destination.name, "fresh");
        assert_eq!(destination.environment_id, environment());
    }

    #[test]
    fn a_relative_directory_is_taken_from_where_the_command_runs() {
        let destination = destination(environment(), Path::new("fresh")).expect("names");
        let here = std::env::current_dir().expect("a current directory");
        assert_eq!(
            destination.parent,
            DestinationParent::Host {
                path: here.display().to_string()
            }
        );
        assert_eq!(destination.name, "fresh");
    }

    #[test]
    fn a_path_with_no_name_of_its_own_is_refused() {
        let refused = destination(environment(), Path::new("/")).expect_err("the root");
        assert_eq!(refused.exit_code(), 2, "{refused}");
    }

    /// A path that ends in `..` names no directory of its own. Windows resolves the `..` itself
    /// when a path is made absolute, so the question only arises elsewhere.
    #[cfg(unix)]
    #[test]
    fn a_path_that_ends_in_its_parent_is_refused() {
        let refused = destination(environment(), Path::new("/srv/work/..")).expect_err("..");
        assert_eq!(refused.exit_code(), 2, "{refused}");
    }

    #[test]
    fn a_source_is_read_by_its_form() {
        let local = std::env::temp_dir().join("work").display().to_string();
        for (text, transport) in [
            ("https://example.invalid/work.git", RemoteTransport::Https),
            ("ssh://example.invalid/srv/work.git", RemoteTransport::Ssh),
            ("git@example.invalid:work.git", RemoteTransport::Ssh),
            (local.as_str(), RemoteTransport::LocalPath),
        ] {
            assert_eq!(transport_of(text).expect(text), transport, "{text}");
        }
        for text in [
            "git://example.invalid/work.git",
            "file:///srv/work",
            "ext::sh -c touch% /tmp/pwned",
            "work",
            "../work",
        ] {
            assert!(transport_of(text).is_err(), "{text} is refused");
        }
    }
}
