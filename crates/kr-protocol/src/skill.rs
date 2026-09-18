//! Installing the contact skill, and the exact change manifest that installation is.
//!
//! Section 11 requires the installation to name its files, its hashes, its version requirements
//! and its removal operations, and to preserve unrelated settings. That is what [`ChangeManifest`]
//! is: a list of operations, each naming the file it touches and what it expects to find there,
//! and each with an inverse recorded at the same time so a removal is a replay of the record
//! rather than a fresh guess.
//!
//! Two properties make "preserve unrelated settings" checkable rather than hoped for:
//!
//! * A configuration entry is added under a marker. [`MANAGED_MARKER`] says who owns that entry,
//!   and nothing without the marker is ever changed or removed.
//! * Every operation records the digest of what it wrote. A removal that finds a different digest
//!   reports drift and leaves the file alone.

use core::fmt;
use core::str::FromStr;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::scalars::{Digest256, Nullable};

/// The key that marks a configuration entry as this installation's own.
pub const MANAGED_MARKER: &str = "x-kalareach-managed";

/// The skill package this installation carries.
pub const SKILL_NAME: &str = "kalareach-contact";

/// The name the MCP server is registered under.
pub const SERVER_NAME: &str = "kalareach";

/// One agent an installation can target.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum AgentTarget {
    /// Codex.
    Codex,
    /// Claude Code.
    ClaudeCode,
    /// OpenCode.
    Opencode,
    /// Gemini CLI.
    GeminiCli,
    /// Kimi Code CLI.
    KimiCodeCli,
    /// Qoder CLI.
    QoderCli,
}

impl AgentTarget {
    /// Every target, in declaration order.
    pub const ALL: &'static [Self] = &[
        Self::Codex,
        Self::ClaudeCode,
        Self::Opencode,
        Self::GeminiCli,
        Self::KimiCodeCli,
        Self::QoderCli,
    ];

    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Codex => "codex",
            Self::ClaudeCode => "claude-code",
            Self::Opencode => "opencode",
            Self::GeminiCli => "gemini-cli",
            Self::KimiCodeCli => "kimi-code-cli",
            Self::QoderCli => "qoder-cli",
        }
    }

    /// Returns the target for a wire string.
    #[must_use]
    pub fn from_wire(value: &str) -> Option<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|target| target.as_str() == value)
    }
}

impl fmt::Display for AgentTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for AgentTarget {
    type Err = UnknownAgent;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::from_wire(value).ok_or(UnknownAgent)
    }
}

/// A target that is not one of the bundled agents.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnknownAgent;

impl fmt::Display for UnknownAgent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("that is not one of the agents this installation supports")
    }
}

impl std::error::Error for UnknownAgent {}

/// Where an installation is written.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum InstallScope {
    /// This operating-system user's own agent configuration.
    User,
    /// One project directory's agent configuration.
    Project,
}

impl InstallScope {
    /// Returns the stable wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Project => "project",
        }
    }

    /// Returns the scope for a wire string.
    #[must_use]
    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            "user" => Some(Self::User),
            "project" => Some(Self::Project),
            _ => None,
        }
    }
}

impl fmt::Display for InstallScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for InstallScope {
    type Err = UnknownScope;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::from_wire(value).ok_or(UnknownScope)
    }
}

/// A scope that is neither `user` nor `project`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnknownScope;

impl fmt::Display for UnknownScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a scope is user or project")
    }
}

impl std::error::Error for UnknownScope {}

/// One change an installation makes, with its inverse implied by its kind.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum ChangeOperation {
    /// A directory this installation created. Removal deletes it only when it is empty.
    CreateDirectory {
        /// The absolute path.
        path: String,
    },
    /// A file this installation owns outright.
    WriteFile {
        /// The absolute path.
        path: String,
        /// The digest of the content written. A removal that finds different content stops.
        digest: Digest256,
        /// The digest of what was there before, when the file already existed.
        replaced_digest: Nullable<Digest256>,
    },
    /// One entry added to an agent's configuration document, under the managed marker.
    ///
    /// Nothing else in the document is read as this installation's, and nothing else is written.
    AddConfigurationEntry {
        /// The absolute path of the document.
        path: String,
        /// The dotted location of the entry inside it, for example `mcpServers.kalareach`.
        entry: String,
        /// The digest of the entry's value, so a removal can tell an unchanged entry from an
        /// edited one.
        digest: Digest256,
        /// True when the document did not exist and this installation created it.
        created_document: bool,
    },
}

impl ChangeOperation {
    /// Returns the path this operation touches.
    #[must_use]
    pub fn path(&self) -> &str {
        match self {
            Self::CreateDirectory { path }
            | Self::WriteFile { path, .. }
            | Self::AddConfigurationEntry { path, .. } => path,
        }
    }
}

/// The exact set of changes one installation made, and how to undo them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChangeManifest {
    /// The skill version installed.
    pub skill_version: String,
    /// The agent it was installed for.
    pub agent: AgentTarget,
    /// The scope it was installed at.
    pub scope: InstallScope,
    /// The directory the scope resolved to.
    pub root: String,
    /// The command the agent runs to reach the tools.
    pub entry_point: Vec<String>,
    /// Every change, in the order it was applied. A removal replays it in reverse.
    pub operations: Vec<ChangeOperation>,
}

/// What one installed file looks like now.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InstalledFile {
    /// The absolute path.
    pub path: String,
    /// The digest the manifest recorded.
    pub expected_digest: Digest256,
    /// The digest on disk now, or null when the path is gone.
    pub actual_digest: Nullable<Digest256>,
}

impl InstalledFile {
    /// Returns true when the file is present and unchanged since it was installed.
    #[must_use]
    pub fn is_intact(&self) -> bool {
        self.actual_digest.as_ref() == Some(&self.expected_digest)
    }
}

/// Parameters of `agent_tools.install`, `agent_tools.status` and `agent_tools.remove`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentToolsParams {
    /// The agent.
    pub agent: AgentTarget,
    /// The scope.
    pub scope: InstallScope,
    /// The project directory, for project scope.
    pub project_dir: Nullable<String>,
}

/// The result of `agent_tools.install`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentToolsInstallResult {
    /// What was changed, and how to undo it.
    pub manifest: ChangeManifest,
    /// True when the installation was already present and unchanged.
    pub already_installed: bool,
}

/// The result of `agent_tools.status`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentToolsStatusResult {
    /// The agent.
    pub agent: AgentTarget,
    /// The scope.
    pub scope: InstallScope,
    /// The directory the scope resolved to.
    pub root: String,
    /// True when a recorded installation is present.
    pub installed: bool,
    /// The version recorded, when there is one.
    pub skill_version: Nullable<String>,
    /// Each installed file and whether it is still what was written.
    pub files: Vec<InstalledFile>,
    /// What no longer matches the record, in the words a person reads.
    pub drift: Vec<String>,
    /// The operations a removal would run.
    pub removal: Vec<ChangeOperation>,
}

/// The result of `agent_tools.remove`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentToolsRemoveResult {
    /// The agent.
    pub agent: AgentTarget,
    /// The scope.
    pub scope: InstallScope,
    /// What was undone.
    pub removed: Vec<ChangeOperation>,
    /// What was left alone, and why.
    pub retained: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_bundled_agent_has_one_stable_name() {
        let mut names: Vec<&str> = AgentTarget::ALL
            .iter()
            .map(|target| target.as_str())
            .collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), AgentTarget::ALL.len());
        for target in AgentTarget::ALL {
            assert_eq!(AgentTarget::from_wire(target.as_str()), Some(*target));
        }
    }

    #[test]
    fn an_unknown_agent_or_scope_is_refused() {
        assert!("some-other-agent".parse::<AgentTarget>().is_err());
        assert!("global".parse::<InstallScope>().is_err());
        assert_eq!("project".parse::<InstallScope>(), Ok(InstallScope::Project));
    }
}
