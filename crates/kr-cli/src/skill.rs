//! `kr skill`: installing the contact skill for an agent, and undoing it.
//!
//! The command carries the request to the control daemon, which owns the installation because it
//! owns this host's record of what was written. What comes back is the exact change manifest:
//! every directory created, every file written with the digest of its contents, and the
//! configuration entry added. A removal replays that record, and anything that has changed since
//! is reported and left alone.

use kr_ipc::client::LocalClient;
use kr_protocol::envelope::ActionTarget;
use kr_protocol::ids::{ActionId, EnvironmentId};
use kr_protocol::method::Method;
use kr_protocol::scalars::Nullable;
use kr_protocol::skill::{
    AgentTarget, AgentToolsInstallResult, AgentToolsParams, AgentToolsRemoveResult,
    AgentToolsStatusResult, ChangeManifest, ChangeOperation, InstallScope, InstalledFile,
};
use serde_json::{Value, json};

use crate::error::{CliError, Result};

/// Reads the agent, the scope and the project directory a command named.
///
/// # Errors
///
/// Returns [`CliError::Usage`] when the agent or the scope is not one this host supports, or when
/// a project scope names no directory and none can be resolved.
pub fn parse(agent: &str, scope: &str, project_dir: Option<&str>) -> Result<AgentToolsParams> {
    let agent: AgentTarget = agent.parse().map_err(|_| {
        CliError::Usage(format!(
            "{agent} is not one of the agents this host installs for: {}",
            AgentTarget::ALL
                .iter()
                .map(|target| target.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ))
    })?;
    let scope: InstallScope = scope
        .parse()
        .map_err(|_| CliError::Usage(format!("{scope} is not a scope; use user or project")))?;
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

/// Renders an installation for a script.
#[must_use]
pub fn installed(result: &AgentToolsInstallResult) -> Value {
    json!({
        "agent": result.manifest.agent.as_str(),
        "scope": result.manifest.scope.as_str(),
        "root": result.manifest.root,
        "skill_version": result.manifest.skill_version,
        "entry_point": result.manifest.entry_point,
        "already_installed": result.already_installed,
        "finished": result.unresolved.is_empty(),
        "unresolved": result.unresolved,
        "operations": result.manifest.operations.iter().map(operation).collect::<Vec<_>>(),
    })
}

/// Renders an installation's state for a script.
#[must_use]
pub fn reported(result: &AgentToolsStatusResult) -> Value {
    json!({
        "agent": result.agent.as_str(),
        "scope": result.scope.as_str(),
        "root": result.root,
        "installed": result.installed,
        "skill_version": result.skill_version.as_ref().cloned(),
        "files": result.files.iter().map(|file| json!({
            "path": file.path,
            "intact": file.is_intact(),
        })).collect::<Vec<_>>(),
        "drift": result.drift,
        "removal": result.removal.iter().map(operation).collect::<Vec<_>>(),
    })
}

/// Renders a removal for a script.
#[must_use]
pub fn removed(result: &AgentToolsRemoveResult) -> Value {
    json!({
        "agent": result.agent.as_str(),
        "scope": result.scope.as_str(),
        "removed": result.removed.iter().map(operation).collect::<Vec<_>>(),
        "retained": result.retained,
    })
}

/// Renders an installation as lines for a person.
#[must_use]
pub fn install_lines(result: &AgentToolsInstallResult) -> String {
    let mut text = String::new();
    if result.already_installed {
        text.push_str(&format!(
            "{} {} is already installed for {} at {} scope\n",
            kr_protocol::skill::SKILL_NAME,
            result.manifest.skill_version,
            result.manifest.agent,
            result.manifest.scope
        ));
    } else {
        text.push_str(&format!(
            "installed {} {} for {} at {} scope\n",
            kr_protocol::skill::SKILL_NAME,
            result.manifest.skill_version,
            result.manifest.agent,
            result.manifest.scope
        ));
    }
    text.push_str(&format!(
        "tool server  {}\n",
        result.manifest.entry_point.join(" ")
    ));
    text.push_str(&manifest_lines(&result.manifest));
    for note in &result.unresolved {
        text.push_str(&format!("  unresolved {note}\n"));
    }
    if !result.unresolved.is_empty() {
        text.push_str("this installation is not finished while anything above is unresolved\n");
    }
    text
}

/// Renders the change manifest as lines for a person.
#[must_use]
pub fn manifest_lines(manifest: &ChangeManifest) -> String {
    let mut text = String::new();
    for change in &manifest.operations {
        text.push_str(&format!("  {}\n", describe(change)));
    }
    text
}

/// Renders an installation's state as lines for a person.
#[must_use]
pub fn status_lines(result: &AgentToolsStatusResult) -> String {
    if !result.installed {
        let mut text = format!(
            "{} is not installed for {} at {} scope\n",
            kr_protocol::skill::SKILL_NAME,
            result.agent,
            result.scope
        );
        // What this host knows about the place it is not installed in. An installation that began
        // and did not finish says so here, and so does every change it may have left behind.
        for note in &result.drift {
            text.push_str(&format!("  {note}\n"));
        }
        return text;
    }
    let mut text = format!(
        "{} {} is installed for {} at {} scope in {}\n",
        kr_protocol::skill::SKILL_NAME,
        result
            .skill_version
            .as_ref()
            .map_or("an unknown version", String::as_str),
        result.agent,
        result.scope,
        result.root
    );
    for file in &result.files {
        text.push_str(&format!(
            "  {:<9} {}\n",
            if file.is_intact() {
                "intact"
            } else {
                "changed"
            },
            file.path
        ));
    }
    for note in &result.drift {
        text.push_str(&format!("  changed   {note}\n"));
    }
    text
}

/// Renders a removal as lines for a person.
#[must_use]
pub fn remove_lines(result: &AgentToolsRemoveResult) -> String {
    let mut text = format!(
        "removed {} for {} at {} scope\n",
        kr_protocol::skill::SKILL_NAME,
        result.agent,
        result.scope
    );
    for change in &result.removed {
        text.push_str(&format!("  undone    {}\n", describe(change)));
    }
    for note in &result.retained {
        text.push_str(&format!("  kept      {note}\n"));
    }
    text
}

fn describe(change: &ChangeOperation) -> String {
    match change {
        ChangeOperation::CreateDirectory { path } => format!("directory {path}"),
        ChangeOperation::WriteFile { path, .. } => format!("file      {path}"),
        ChangeOperation::AddConfigurationEntry { path, entry, .. } => {
            format!("entry     {entry} in {path}")
        }
    }
}

fn operation(change: &ChangeOperation) -> Value {
    match change {
        ChangeOperation::CreateDirectory { path } => {
            json!({"operation": "create_directory", "path": path})
        }
        ChangeOperation::WriteFile { path, digest, .. } => json!({
            "operation": "write_file",
            "path": path,
            "sha256": hex(digest.as_bytes()),
        }),
        ChangeOperation::AddConfigurationEntry { path, entry, .. } => json!({
            "operation": "add_configuration_entry",
            "path": path,
            "entry": entry,
        }),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut text, byte| {
        use std::fmt::Write as _;
        let _ = write!(text, "{byte:02x}");
        text
    })
}

async fn mutate<T: serde::de::DeserializeOwned + serde::Serialize>(
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

fn decode<T: serde::de::DeserializeOwned + serde::Serialize>(
    value: kr_protocol::envelope::ParamsValue,
) -> Result<T> {
    value
        .to_typed()
        .map_err(|error| CliError::Other(format!("the host's answer could not be read: {error}")))
}

fn absolute(directory: &str) -> Result<String> {
    let path = std::path::Path::new(directory);
    let resolved = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| CliError::Other(format!("this directory cannot be read: {error}")))?
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
