//! `kr skill`: installing the contact skill for an agent, and undoing it.
//!
//! The command carries the request to the control daemon, which owns the installation because it
//! owns this host's record of what was written. What comes back is the exact change manifest:
//! every directory created, every file written with the digest of its contents, and the
//! configuration entry added. A removal replays that record, and anything that has changed since
//! is reported and left alone.

use kr_client::shown;
use kr_client::shown::Shown;
use kr_ipc::client::LocalClient;
use kr_protocol::envelope::ActionTarget;
use kr_protocol::ids::{ActionId, EnvironmentId};
use kr_protocol::method::Method;
use kr_protocol::scalars::Nullable;
use kr_protocol::skill::{
    AgentTarget, AgentToolsInstallResult, AgentToolsParams, AgentToolsRemoveResult,
    AgentToolsStatusResult, ChangeManifest, ChangeOperation, InstallScope, InstalledFile,
};

use crate::error::{CliError, Result};
use crate::output::{Asked, Document, Line, Request, left};
use crate::stdout_line;

/// Reads the agent, the scope and the project directory a command named.
///
/// # Errors
///
/// Returns [`CliError::Usage`] when the agent or the scope is not one this host supports, or when
/// a project scope names no directory and none can be resolved.
pub fn parse(agent: &str, scope: &str, project_dir: Option<&str>) -> Result<AgentToolsParams> {
    let agent: AgentTarget = agent.parse().map_err(|_| {
        CliError::Usage(shown!(
            "the agent given is not one this host installs for: {}",
            Shown::joined(
                AgentTarget::ALL
                    .iter()
                    .map(|target| Shown::said(target.as_str())),
                ", "
            )
        ))
    })?;
    let scope: InstallScope = scope
        .parse()
        .map_err(|_| CliError::Usage(Shown::said("the scope is user or project")))?;
    let project_dir = match (scope, project_dir) {
        (InstallScope::Project, Some(directory)) => Some(absolute(directory)?),
        // A project installation without a directory means this one, which is what a person in a
        // project directory expects. It is resolved here so the manifest records where it went.
        (InstallScope::Project, None) => Some(absolute(".")?),
        (InstallScope::User, _) => None,
    };
    Ok(AgentToolsParams {
        agent,
        scope,
        project_dir: Nullable(project_dir),
    })
}

/// Installs the skill and registers the tool server.
///
/// # Errors
///
/// Returns the daemon's refusal.
pub async fn install(
    client: &mut LocalClient,
    environment_id: EnvironmentId,
    params: &AgentToolsParams,
) -> Result<AgentToolsInstallResult> {
    mutate(client, environment_id, Method::AgentToolsInstall, params).await
}

/// Reports what is installed.
///
/// # Errors
///
/// Returns the daemon's refusal.
pub async fn status(
    client: &mut LocalClient,
    params: &AgentToolsParams,
) -> Result<AgentToolsStatusResult> {
    let outcome = client.request(Method::AgentToolsStatus, params).await?;
    decode(outcome.map_err(CliError::Refused)?)
}

/// Undoes what an installation recorded.
///
/// # Errors
///
/// Returns the daemon's refusal.
pub async fn remove(
    client: &mut LocalClient,
    environment_id: EnvironmentId,
    params: &AgentToolsParams,
) -> Result<AgentToolsRemoveResult> {
    mutate(client, environment_id, Method::AgentToolsRemove, params).await
}

/// What the skill's installation holds, which is the agent's files and configuration the person
/// asked about.
fn asked(text: &str) -> Asked {
    Asked::text(Request::AgentFiles, text)
}

/// A path of the skill's installation.
fn asked_path(path: &str) -> Asked {
    Asked::path(Request::AgentFiles, path)
}

/// Renders an installation for a script.
#[must_use]
pub fn installed(result: &AgentToolsInstallResult) -> Document {
    Document::new()
        .with("agent", result.manifest.agent.as_str())
        .with("scope", result.manifest.scope.as_str())
        .with("root", asked_path(&result.manifest.root))
        .with("skill_version", asked(&result.manifest.skill_version))
        .with(
            "entry_point",
            result
                .manifest
                .entry_point
                .iter()
                .map(|part| asked(part))
                .collect::<Vec<_>>(),
        )
        .with("already_installed", result.already_installed)
        .with("finished", result.unresolved.is_empty())
        .with(
            "unresolved",
            result
                .unresolved
                .iter()
                .map(|note| asked_path(note))
                .collect::<Vec<_>>(),
        )
        .with(
            "operations",
            result
                .manifest
                .operations
                .iter()
                .map(operation)
                .collect::<Vec<_>>(),
        )
}

/// Renders an installation's state for a script.
#[must_use]
pub fn reported(result: &AgentToolsStatusResult) -> Document {
    Document::new()
        .with("agent", result.agent.as_str())
        .with("scope", result.scope.as_str())
        .with("root", asked_path(&result.root))
        .with("installed", result.installed)
        .with(
            "skill_version",
            result.skill_version.as_ref().map(|version| asked(version)),
        )
        .with(
            "files",
            result
                .files
                .iter()
                .map(|file| {
                    Document::new()
                        .with("path", asked_path(&file.path))
                        .with("intact", file.is_intact())
                })
                .collect::<Vec<_>>(),
        )
        .with(
            "drift",
            result
                .drift
                .iter()
                .map(|note| asked(note))
                .collect::<Vec<_>>(),
        )
        .with(
            "removal",
            result.removal.iter().map(operation).collect::<Vec<_>>(),
        )
}

/// Renders a removal for a script.
#[must_use]
pub fn removed(result: &AgentToolsRemoveResult) -> Document {
    Document::new()
        .with("agent", result.agent.as_str())
        .with("scope", result.scope.as_str())
        .with(
            "removed",
            result.removed.iter().map(operation).collect::<Vec<_>>(),
        )
        .with(
            "retained",
            result
                .retained
                .iter()
                .map(|note| asked_path(note))
                .collect::<Vec<_>>(),
        )
}

/// Renders an installation as lines for a person.
#[must_use]
pub fn install_lines(result: &AgentToolsInstallResult) -> Vec<Line> {
    let manifest = &result.manifest;
    let mut lines = vec![if result.already_installed {
        stdout_line!(
            "{} {} is already installed for {} at {} scope",
            kr_protocol::skill::SKILL_NAME,
            asked(&manifest.skill_version),
            manifest.agent.as_str(),
            manifest.scope.as_str()
        )
    } else {
        stdout_line!(
            "installed {} {} for {} at {} scope",
            kr_protocol::skill::SKILL_NAME,
            asked(&manifest.skill_version),
            manifest.agent.as_str(),
            manifest.scope.as_str()
        )
    }];
    lines.push(stdout_line!(
        "tool server  {}",
        asked(&manifest.entry_point.join(" "))
    ));
    lines.extend(manifest_lines(manifest));
    for note in &result.unresolved {
        lines.push(stdout_line!("  unresolved {}", asked_path(note)));
    }
    if !result.unresolved.is_empty() {
        lines.push(stdout_line!(
            "this installation is not finished while anything above is unresolved"
        ));
    }
    lines
}

/// Renders the change manifest as lines for a person.
#[must_use]
pub fn manifest_lines(manifest: &ChangeManifest) -> Vec<Line> {
    manifest
        .operations
        .iter()
        .map(|change| stdout_line!("  {}", describe(change)))
        .collect()
}

/// Renders an installation's state as lines for a person.
#[must_use]
pub fn status_lines(result: &AgentToolsStatusResult) -> Vec<Line> {
    if !result.installed {
        let mut lines = vec![stdout_line!(
            "{} is not installed for {} at {} scope",
            kr_protocol::skill::SKILL_NAME,
            result.agent.as_str(),
            result.scope.as_str()
        )];
        // What this host knows about the place it is not installed in. An installation that began
        // and did not finish says so here, and so does every change it may have left behind.
        for note in &result.drift {
            lines.push(stdout_line!("  {}", asked(note)));
        }
        return lines;
    }
    let mut lines = vec![stdout_line!(
        "{} {} is installed for {} at {} scope in {}",
        kr_protocol::skill::SKILL_NAME,
        result
            .skill_version
            .as_ref()
            .map_or_else(|| asked("an unknown version"), |version| asked(version)),
        result.agent.as_str(),
        result.scope.as_str(),
        asked_path(&result.root)
    )];
    for file in &result.files {
        lines.push(stdout_line!(
            "  {} {}",
            left(
                9,
                &if file.is_intact() {
                    "intact"
                } else {
                    "changed"
                }
            ),
            asked_path(&file.path)
        ));
    }
    for note in &result.drift {
        lines.push(stdout_line!("  changed   {}", asked(note)));
    }
    lines
}

/// Renders a removal as lines for a person.
#[must_use]
pub fn remove_lines(result: &AgentToolsRemoveResult) -> Vec<Line> {
    let mut lines = vec![stdout_line!(
        "removed {} for {} at {} scope",
        kr_protocol::skill::SKILL_NAME,
        result.agent.as_str(),
        result.scope.as_str()
    )];
    for change in &result.removed {
        lines.push(stdout_line!("  undone    {}", describe(change)));
    }
    for note in &result.retained {
        lines.push(stdout_line!("  kept      {}", asked_path(note)));
    }
    lines
}

fn describe(change: &ChangeOperation) -> Line {
    match change {
        ChangeOperation::CreateDirectory { path } => {
            stdout_line!("directory {}", asked_path(path))
        }
        ChangeOperation::WriteFile { path, .. } => stdout_line!("file      {}", asked_path(path)),
        ChangeOperation::AddConfigurationEntry { path, entry, .. } => {
            stdout_line!("entry     {} in {}", asked(entry), asked_path(path))
        }
    }
}

fn operation(change: &ChangeOperation) -> Document {
    match change {
        ChangeOperation::CreateDirectory { path } => Document::new()
            .with("operation", "create_directory")
            .with("path", asked_path(path)),
        ChangeOperation::WriteFile { path, digest, .. } => Document::new()
            .with("operation", "write_file")
            .with("path", asked_path(path))
            .with("sha256", crate::shown::hex_digest(&hex(digest.as_bytes()))),
        ChangeOperation::AddConfigurationEntry { path, entry, .. } => Document::new()
            .with("operation", "add_configuration_entry")
            .with("path", asked_path(path))
            .with("entry", asked(entry)),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut text, byte| {
        use std::fmt::Write as _;
        let _ = write!(text, "{byte:02x}");
        text
    })
}

async fn mutate<T: kr_protocol::wire::WireMessage>(
    client: &mut LocalClient,
    environment_id: EnvironmentId,
    method: Method,
    params: &AgentToolsParams,
) -> Result<T> {
    let target = ActionTarget {
        environment_id,
        session_id: Nullable::null(),
        session_epoch: Nullable::null(),
        application_instance_id: Nullable::null(),
        agent_binding_revision: Nullable::null(),
    };
    let action_id = ActionId::new(kr_ipc::new_uuid());
    let outcome = client.mutate(method, action_id, target, params).await?;
    decode(outcome.map_err(CliError::Refused)?)
}

fn decode<T: kr_protocol::wire::WireMessage>(
    value: kr_protocol::envelope::ParamsValue,
) -> Result<T> {
    value.to_typed().map_err(|error| {
        CliError::Other(shown!(
            "the host's answer could not be read: {}",
            Shown::cbor(&error)
        ))
    })
}

fn absolute(directory: &str) -> Result<String> {
    let path = std::path::Path::new(directory);
    let resolved = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| {
                CliError::Other(shown!(
                    "this directory cannot be read: {}",
                    Shown::io(&error)
                ))
            })?
            .join(path)
    };
    // The path is resolved rather than canonicalised, because a project directory that does not
    // exist yet is a usage mistake the daemon reports, not one to guess at here.
    Ok(resolved.display().to_string())
}

/// Returns whether every installed file is still what was written.
#[must_use]
pub fn is_intact(result: &AgentToolsStatusResult) -> bool {
    result.installed && result.drift.is_empty() && result.files.iter().all(InstalledFile::is_intact)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::planted::{only_asked, only_asked_lines, planted};

    /// KR-REQ-23.25: planted text in the skill's answers shows only where the person asked for it
    /// (the agent's own files and configuration: the root, each path, entry and entry point, the
    /// version and the drift the installation reads out of them), in the documents and in the
    /// lines; a file's digest is said only when it is one.
    #[test]
    fn planted_text_in_the_skill_shows_only_where_it_was_asked_for() {
        let mut shown = std::collections::BTreeSet::new();
        for result in planted::<AgentToolsInstallResult>() {
            shown.extend(only_asked("kr skill install", &installed(&result)));
            only_asked_lines("kr skill install", &install_lines(&result));
        }
        for result in planted::<AgentToolsStatusResult>() {
            shown.extend(only_asked("kr skill status", &reported(&result)));
            only_asked_lines("kr skill status", &status_lines(&result));
        }
        for result in planted::<AgentToolsRemoveResult>() {
            shown.extend(only_asked("kr skill remove", &removed(&result)));
            only_asked_lines("kr skill remove", &remove_lines(&result));
        }
        for asked in [
            "root",
            "skill_version",
            "entry_point[]",
            "unresolved[]",
            "operations[].path",
            "operations[].entry",
            "files[].path",
            "drift[]",
            "retained[]",
        ] {
            assert!(
                shown.contains(asked),
                "{asked} shows what was asked for: {shown:?}"
            );
        }
    }

    #[test]
    fn an_unknown_agent_names_the_ones_that_are_supported() {
        let error = parse("some-agent", "user", None).expect_err("refused");
        assert_eq!(error.exit_code(), 2);
        assert!(error.to_string().contains("claude-code"));
        assert!(error.to_string().contains("qoder-cli"));
    }

    /// KR-REQ-23.33: an agent-tools change names its scope, user or project.
    #[test]
    fn a_scope_is_user_or_project() {
        assert!(parse("codex", "global", None).is_err());
        let params = parse("codex", "user", None).expect("parses");
        assert_eq!(params.agent, AgentTarget::Codex);
        assert!(!params.project_dir.is_present());
    }

    /// KR-REQ-23.33: a project scope names the directory it will write to.
    #[test]
    fn a_project_scope_resolves_the_directory_it_will_write_to() {
        // An absolute path is used as it stands. What counts as absolute is the platform's own
        // answer: a Windows path that begins with a separator names the current drive's root and
        // is resolved against it, so the test asks for a path this platform calls absolute.
        let absolute = if cfg!(windows) {
            "C:/somewhere"
        } else {
            "/tmp/somewhere"
        };
        let params = parse("claude-code", "project", Some(absolute)).expect("parses");
        assert_eq!(
            params.project_dir.as_ref().map(String::as_str),
            Some(absolute)
        );
        let here = parse("claude-code", "project", None).expect("parses");
        assert!(here.project_dir.is_present());
    }
}
