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
//! * A configuration entry is named `kalareach`. Nothing is ever replaced or removed there that a
//!   record of this host does not claim, and an entry this host did not write is refused.
//! * Every operation records the digest of what it wrote. A removal that finds a different digest
//!   reports drift and leaves the file alone.

use core::fmt;
use core::str::FromStr;
use std::borrow::Cow;

use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::scalars::{Digest256, Nullable};

/// The skill package this installation carries.
pub const SKILL_NAME: &str = "kalareach-contact";

/// The name the MCP server is registered under.
pub const SERVER_NAME: &str = "kalareach";

/// The most bytes in the word of an agent.
pub const MAX_AGENT_BYTES: usize = 32;

/// The pattern of the word of an agent as the published schema states it, which is the whole of
/// what [`AgentTarget::parse`] checks: the grammar, no ending of `-user` or `-project` and no ending
/// in a segment of sixteen hexadecimal digits, which a record's file name could not tell from a
/// project's digest. A word of one segment ends in it too: the whole word may be those digits.
pub const AGENT_PATTERN: &str =
    "^(?!.*-(user|project)$)(?!(.*-)?[0-9a-f]{16}$)[a-z][a-z0-9]*(-[a-z0-9]+)*$";

/// One of the six agents this host holds the places of, for an installation made with no
/// declaration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CompiledAgent {
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

impl CompiledAgent {
    /// Every compiled agent, in declaration order.
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
}

/// The word that names the agent an installation is for: one of the six compiled agents' words, or
/// a word a package declares.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AgentTarget(Cow<'static, str>);

impl AgentTarget {
    /// Codex.
    pub const CODEX: Self = Self(Cow::Borrowed("codex"));
    /// Claude Code.
    pub const CLAUDE_CODE: Self = Self(Cow::Borrowed("claude-code"));
    /// OpenCode.
    pub const OPENCODE: Self = Self(Cow::Borrowed("opencode"));
    /// Gemini CLI.
    pub const GEMINI_CLI: Self = Self(Cow::Borrowed("gemini-cli"));
    /// Kimi Code CLI.
    pub const KIMI_CODE_CLI: Self = Self(Cow::Borrowed("kimi-code-cli"));
    /// Qoder CLI.
    pub const QODER_CLI: Self = Self(Cow::Borrowed("qoder-cli"));

    /// The six compiled agents' words, in declaration order.
    pub const ALL: &'static [Self] = &[
        Self::CODEX,
        Self::CLAUDE_CODE,
        Self::OPENCODE,
        Self::GEMINI_CLI,
        Self::KIMI_CODE_CLI,
        Self::QODER_CLI,
    ];

    /// Returns the word for a wire string, or says what is wrong with it.
    ///
    /// # Errors
    ///
    /// Returns [`UnknownAgent`] when the text is not in the grammar of a word.
    pub fn parse(value: &str) -> Result<Self, UnknownAgent> {
        match Self::problem(value) {
            None => Ok(Self(Cow::Owned(value.to_owned()))),
            Some(problem) => Err(UnknownAgent(problem)),
        }
    }

    /// What is wrong with `value` as a word, or `None`. The grammar is a lower-case letter, then
    /// lower-case letters and digits, in segments joined by one `-`; at most [`MAX_AGENT_BYTES`]
    /// bytes; not ending in `-user` or `-project`; not ending in a segment of sixteen hexadecimal
    /// digits.
    #[must_use]
    pub fn problem(value: &str) -> Option<&'static str> {
        if value.is_empty() || value.len() > MAX_AGENT_BYTES {
            return Some("a word is one to 32 bytes");
        }
        let segments_are_plain = value.split('-').all(|segment| {
            !segment.is_empty()
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        });
        if !segments_are_plain
            || !value
                .bytes()
                .next()
                .is_some_and(|byte| byte.is_ascii_lowercase())
        {
            return Some(
                "a word starts with a lower-case letter and has lower-case letters and digits in \
                 segments joined by one -",
            );
        }
        if value.ends_with("-user") || value.ends_with("-project") {
            return Some("a word does not end in -user or -project");
        }
        if value.rsplit('-').next().is_some_and(|last| {
            last.len() == 16
                && last
                    .bytes()
                    .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        }) {
            return Some("a word does not end in a segment of sixteen hexadecimal digits");
        }
        None
    }

    /// Returns the wire string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the compiled agent this word names, or `None` for any other word.
    #[must_use]
    pub fn compiled(&self) -> Option<CompiledAgent> {
        CompiledAgent::ALL
            .iter()
            .copied()
            .find(|agent| agent.as_str() == self.as_str())
    }
}

impl From<CompiledAgent> for AgentTarget {
    fn from(agent: CompiledAgent) -> Self {
        Self(Cow::Borrowed(agent.as_str()))
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
        Self::parse(value)
    }
}

impl Serialize for AgentTarget {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for AgentTarget {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::parse(&text).map_err(serde::de::Error::custom)
    }
}

impl JsonSchema for AgentTarget {
    fn schema_name() -> Cow<'static, str> {
        "AgentTarget".into()
    }

    fn schema_id() -> Cow<'static, str> {
        "kalareach::AgentTarget".into()
    }

    fn json_schema(_generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "string",
            "pattern": AGENT_PATTERN,
            "maxLength": MAX_AGENT_BYTES,
            "description": "The word of an agent: one of the six compiled agents, or a word a package declares."
        })
    }
}

/// Text that is not in the grammar of the word of an agent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnknownAgent(&'static str);

impl UnknownAgent {
    /// Why the text is not a word, in a sentence of the protocol crate.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        self.0
    }
}

impl fmt::Display for UnknownAgent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
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
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
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
    /// One entry added to an agent's configuration document, under the name `kalareach`.
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
    /// Every change, in the order it was applied.
    ///
    /// A removal undoes them in the order it can carry out: files and server entries first, then
    /// the directories that held them, deepest first.
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
    /// What an earlier attempt may have written and this one could not account for.
    ///
    /// Empty in the ordinary case. A line here means the installation is not finished: the change
    /// it names is neither owned nor undone, and somebody has to look at it.
    pub unresolved: Vec<String>,
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
        for (target, compiled) in AgentTarget::ALL.iter().zip(CompiledAgent::ALL) {
            assert_eq!(target.compiled(), Some(*compiled));
            assert_eq!(&AgentTarget::from(*compiled), target);
            assert_eq!(
                &AgentTarget::parse(target.as_str()).expect("a word"),
                target
            );
        }
    }

    #[test]
    fn an_unknown_agent_or_scope_is_refused() {
        assert!("Some-other-agent".parse::<AgentTarget>().is_err());
        assert!("some-other-agent".parse::<AgentTarget>().is_ok());
        assert!("global".parse::<InstallScope>().is_err());
        assert_eq!("project".parse::<InstallScope>(), Ok(InstallScope::Project));
    }

    /// A word in the grammar that the host does not know decodes, and encodes as the same string.
    #[test]
    fn a_word_in_the_grammar_that_the_host_does_not_know_decodes() {
        let word: AgentTarget =
            serde_json::from_str("\"amp\"").expect("a word in the grammar decodes");
        assert_eq!(word.as_str(), "amp");
        assert!(word.compiled().is_none());
        assert_eq!(
            serde_json::to_string(&word).expect("a word encodes"),
            "\"amp\""
        );
        assert_eq!(
            serde_json::from_str::<AgentTarget>("\"amp-2\"")
                .expect("a segment of digits decodes")
                .as_str(),
            "amp-2"
        );
    }

    /// A text outside the grammar of a word is refused at decode, and the reserved endings are
    /// refused as the published schema's pattern refuses them.
    #[test]
    fn a_word_outside_the_grammar_is_refused_at_decode() {
        let long = "a".repeat(MAX_AGENT_BYTES + 1);
        for text in [
            "../x",
            "Codex",
            "a b",
            "codex-user",
            "amp-project",
            "amp-0123456789abcdef",
            "amp_",
            "-amp",
            "amp-",
            "1amp",
            "",
            long.as_str(),
        ] {
            assert!(
                serde_json::from_value::<AgentTarget>(serde_json::json!(text)).is_err(),
                "{text:?} is not a word"
            );
            assert!(AgentTarget::parse(text).is_err(), "{text:?} is not a word");
        }
    }

    /// The six compiled words keep the wire strings every earlier build wrote.
    #[test]
    fn the_six_compiled_words_keep_their_wire_strings_and_record_names() {
        let wire: Vec<&str> = AgentTarget::ALL.iter().map(AgentTarget::as_str).collect();
        assert_eq!(
            wire,
            [
                "codex",
                "claude-code",
                "opencode",
                "gemini-cli",
                "kimi-code-cli",
                "qoder-cli"
            ]
        );
        for word in AgentTarget::ALL {
            let decoded: AgentTarget =
                serde_json::from_value(serde_json::json!(word.as_str())).expect("decodes");
            assert_eq!(&decoded, word);
            assert!(decoded.compiled().is_some());
        }
    }
}
