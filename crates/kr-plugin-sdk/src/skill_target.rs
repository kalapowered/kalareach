//! A package's declaration of where the host installs the KalaReach contact skill for an agent
//! that the host does not compile in.
//!
//! The host knows six agents by name. A package that holds `skill_target.install` can name another
//! one in its connector table: a word, and for the user scope, the project scope or both, the
//! folder the skill's files go in and at most one configuration document the tool server's entry is
//! added to. The package supplies places, a format name and the name of a deadline member. It never
//! supplies a byte of what is written, a command, an argument or a server name: the files, the
//! entry's command and its arguments are the core's.
//!
//! A person who manages the host installs the skill for the word with `kr skill install`; the host
//! writes nothing for a declaration before that, and starts no process when it does.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::placement::MAX_COMPONENT_BYTES;

/// The SDK version a connector table first carries the member in: the first release that has it.
pub const ARRIVAL: &str = "0.1.11";

/// The most plain components a declared place has below the home or the project folder.
pub const MAX_COMPONENTS: usize = 3;

/// The most bytes in a word.
pub const MAX_WORD_BYTES: usize = 32;

/// The most bytes in the name of a deadline member.
pub const MAX_FIELD_BYTES: usize = 32;

/// The words of the six agents the host compiles in, which a declaration may not name.
pub const COMPILED_WORDS: [&str; 6] = [
    "codex",
    "claude-code",
    "opencode",
    "gemini-cli",
    "kimi-code-cli",
    "qoder-cli",
];

/// The members of the entry the host writes, which a deadline member may not be named after.
pub const ENTRY_MEMBERS: [&str; 5] = ["type", "command", "args", "env", "enabled"];

/// The agent a package names, and where the host installs the contact skill for it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct SkillTarget {
    /// The word `kr skill install --agent` takes: lower-case letters and digits in segments joined
    /// by one `-`, at most 32 bytes, not one of the six agents the host compiles in, not ending in
    /// `-user` or `-project`, and not ending in a segment of sixteen hexadecimal digits.
    pub word: String,
    /// The places for the account's own installation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<SkillLocation>,
    /// The places for an installation in one project's folder.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<SkillLocation>,
}

/// The places of one scope, each below the home folder or the project folder.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct SkillLocation {
    /// The folder the skill's files go in, as plain components (one to three), the first of them
    /// hidden. The host writes `kalareach-contact` inside it.
    pub skills: Vec<String>,
    /// The configuration document the tool server's entry is added to, where there is one. A
    /// location with none installs the skill's files only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub configuration: Option<SkillConfiguration>,
}

/// One configuration document and how the host writes its entry into it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct SkillConfiguration {
    /// The document, as plain components (one to three), the first of them hidden.
    pub path: Vec<String>,
    /// How the entry is written. A file name ending in `.toml` takes `codex_toml`, and one ending
    /// in `.json` takes the other two.
    pub format: DocumentFormat,
    /// True when other agents read this document too, so that what the host writes there is the
    /// same for every installation and carries no deadline.
    pub shared: bool,
    /// The deadline member the host writes into the entry, where the agent has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deadline: Option<Deadline>,
}

/// The three ways the host writes a configuration entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DocumentFormat {
    /// The table `mcp_servers.kalareach` of a TOML file.
    CodexToml,
    /// `mcpServers.kalareach` of a JSON file, with a command and its arguments.
    JsonCommandArgs,
    /// `mcp.kalareach` of a JSON file, with one command list.
    JsonLocalCommandList,
}

impl DocumentFormat {
    /// The file name suffix a document of this format has.
    #[must_use]
    pub const fn suffix(self) -> &'static str {
        match self {
            Self::CodexToml => ".toml",
            Self::JsonCommandArgs | Self::JsonLocalCommandList => ".json",
        }
    }
}

/// The member of the entry that holds the agent's own deadline for the server.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct Deadline {
    /// The member's name: a letter, then letters, digits and `_`, at most 32 bytes, and not a member
    /// the host writes into the entry (`type`, `command`, `args`, `env`, `enabled`).
    pub field: String,
    /// The unit the agent reads the member in.
    pub unit: DeadlineUnit,
}

/// The unit of a deadline member.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DeadlineUnit {
    /// Whole seconds.
    Seconds,
    /// Whole milliseconds.
    Milliseconds,
}

/// One reason a declaration is refused: a name, and what was found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Problem {
    /// The name, always starting `skill_target.`.
    pub name: &'static str,
    /// What was found, for a reviewer.
    pub detail: String,
}

impl Problem {
    fn new(name: &'static str, detail: impl Into<String>) -> Self {
        Self {
            name,
            detail: detail.into(),
        }
    }

    /// The text a finding carries: the name, then what was found.
    #[must_use]
    pub fn message(&self) -> String {
        format!("{}: {}", self.name, self.detail)
    }

    /// True for a reason about the connector table itself, as against the manifest that does not
    /// request the capability.
    #[must_use]
    pub fn is_about_the_table(&self) -> bool {
        self.name != "skill_target.without_capability"
    }
}

/// Returns true when `word` is in the grammar of a word, whatever else the host knows of it.
#[must_use]
pub fn is_word(word: &str) -> bool {
    word_shape(word).is_none()
}

/// What is wrong with the shape of `word`, or `None`.
fn word_shape(word: &str) -> Option<String> {
    if word.is_empty() || word.len() > MAX_WORD_BYTES {
        return Some(format!(
            "a word is one to {MAX_WORD_BYTES} bytes, and this one is {}",
            word.len()
        ));
    }
    let segments_are_plain = word.split('-').all(|segment| {
        !segment.is_empty()
            && segment
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
    });
    let starts_with_a_letter = word
        .bytes()
        .next()
        .is_some_and(|byte| byte.is_ascii_lowercase());
    if !segments_are_plain || !starts_with_a_letter {
        return Some(
            "a word starts with a lower-case letter and has lower-case letters and digits in \
             segments joined by one -"
                .to_owned(),
        );
    }
    None
}

/// Returns true when `word` would make a record name ambiguous: it ends in `-user` or `-project`,
/// or in a segment of sixteen lower-case hexadecimal digits.
#[must_use]
pub fn is_ambiguous_with_a_record(word: &str) -> bool {
    word.ends_with("-user")
        || word.ends_with("-project")
        || word.rsplit('-').next().is_some_and(|last| {
            last.len() == 16 && last.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
}

/// Returns every reason `target` is refused, none hiding another.
///
/// `requests_the_capability` is whether the package's manifest requests `skill_target.install`.
#[must_use]
pub fn problems(target: &SkillTarget, requests_the_capability: bool) -> Vec<Problem> {
    let mut found = Vec::new();
    if !requests_the_capability {
        found.push(Problem::new(
            "skill_target.without_capability",
            "the package declares a skill target without requesting skill_target.install",
        ));
    }
    if let Some(detail) = word_shape(&target.word) {
        found.push(Problem::new("skill_target.word_shape", detail));
    }
    if COMPILED_WORDS.contains(&target.word.as_str()) {
        found.push(Problem::new(
            "skill_target.word_compiled",
            format!(
                "{} is one of the six agents the host compiles in, whose places the host holds",
                target.word
            ),
        ));
    }
    if is_ambiguous_with_a_record(&target.word) {
        found.push(Problem::new(
            "skill_target.word_ambiguous_with_a_record",
            format!(
                "{} ends the way the name of an installation record does",
                target.word
            ),
        ));
    }
    if target.user.is_none() && target.project.is_none() {
        found.push(Problem::new(
            "skill_target.no_location",
            "a declaration names a user location, a project location or both",
        ));
    }
    for (scope, location) in [("user", &target.user), ("project", &target.project)] {
        if let Some(location) = location {
            location_problems(scope, location, &mut found);
        }
    }
    found
}

fn location_problems(scope: &str, location: &SkillLocation, found: &mut Vec<Problem>) {
    components_problems(scope, "skills", &location.skills, found);
    let Some(configuration) = &location.configuration else {
        return;
    };
    components_problems(scope, "configuration path", &configuration.path, found);
    if same_or_ancestor(&location.skills, &configuration.path) {
        found.push(Problem::new(
            "skill_target.places_overlap",
            format!(
                "in the {scope} location the skills folder and the configuration path are the \
                 same place, or one is inside the other, with ASCII case ignored"
            ),
        ));
    }
    let suffix = configuration.format.suffix();
    if let Some(last) = configuration.path.last()
        && !last.to_ascii_lowercase().ends_with(suffix)
    {
        found.push(Problem::new(
            "skill_target.format_disagrees_with_name",
            format!(
                "in the {scope} location the configuration file {last} does not end in {suffix}, \
                 which its format needs"
            ),
        ));
    }
    if let Some(deadline) = &configuration.deadline {
        if configuration.shared {
            found.push(Problem::new(
                "skill_target.shared_with_deadline",
                format!(
                    "in the {scope} location a shared document carries no deadline, because what \
                     the host writes there is the same for every agent"
                ),
            ));
        }
        if configuration.format == DocumentFormat::JsonLocalCommandList {
            found.push(Problem::new(
                "skill_target.deadline_with_command_list",
                format!(
                    "in the {scope} location the one-command-list form has no member or \
                     environment the host could write a deadline into"
                ),
            ));
        }
        let shape = !deadline.field.is_empty()
            && deadline.field.len() <= MAX_FIELD_BYTES
            && deadline
                .field
                .bytes()
                .next()
                .is_some_and(|byte| byte.is_ascii_alphabetic())
            && deadline
                .field
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_');
        if !shape {
            found.push(Problem::new(
                "skill_target.deadline_field_shape",
                format!(
                    "in the {scope} location a deadline member is a letter, then letters, digits \
                     and _, at most {MAX_FIELD_BYTES} bytes"
                ),
            ));
        } else if ENTRY_MEMBERS
            .iter()
            .any(|member| member.eq_ignore_ascii_case(&deadline.field))
        {
            found.push(Problem::new(
                "skill_target.deadline_field_collides",
                format!(
                    "in the {scope} location the deadline member {} is a member the host writes \
                     into the entry itself",
                    deadline.field
                ),
            ));
        }
    }
}

fn components_problems(scope: &str, what: &str, components: &[String], found: &mut Vec<Problem>) {
    if components.is_empty() {
        found.push(Problem::new(
            "skill_target.no_components",
            format!("in the {scope} location the {what} has no component"),
        ));
        return;
    }
    if components.len() > MAX_COMPONENTS {
        found.push(Problem::new(
            "skill_target.too_deep",
            format!(
                "in the {scope} location the {what} has {} components, and at most \
                 {MAX_COMPONENTS} are allowed",
                components.len()
            ),
        ));
    }
    for component in components {
        if component.len() > MAX_COMPONENT_BYTES {
            found.push(Problem::new(
                "skill_target.component_too_long",
                format!(
                    "in the {scope} location a component of the {what} is longer than \
                     {MAX_COMPONENT_BYTES} bytes"
                ),
            ));
        } else if crate::paths::windows_device(component).is_some() {
            found.push(Problem::new(
                "skill_target.component_reserved_on_windows",
                format!(
                    "in the {scope} location the component {component} of the {what} is a name \
                     Windows opens as a device"
                ),
            ));
        } else if component.ends_with('.') && component != "." && component != ".." {
            found.push(Problem::new(
                "skill_target.component_ends_in_dot",
                format!(
                    "in the {scope} location the component {component} of the {what} ends in a dot"
                ),
            ));
        } else if !crate::placement::is_plain_component(component) {
            found.push(Problem::new(
                "skill_target.component_not_plain",
                format!(
                    "in the {scope} location a component of the {what} is not a plain name of \
                     ASCII letters, digits, space, `.`, `_` and `-`"
                ),
            ));
        }
    }
    if let Some(first) = components.first()
        && !first.starts_with('.')
    {
        found.push(Problem::new(
            "skill_target.not_hidden_first",
            format!("in the {scope} location the first component of the {what} starts with a dot"),
        ));
    }
}

/// True when one list of components is the other, or the start of the other, ignoring ASCII case.
fn same_or_ancestor(left: &[String], right: &[String]) -> bool {
    left.iter()
        .zip(right)
        .all(|(left, right)| left.eq_ignore_ascii_case(right))
}

/// The rules the package contract publishes as `skill_target_rules`.
#[must_use]
pub fn rules() -> serde_json::Value {
    serde_json::json!({
        "arrival": ARRIVAL,
        "capability": "skill_target.install",
        "word_grammar": "a lower-case letter, then lower-case letters and digits, in segments joined by one -",
        "max_word_bytes": MAX_WORD_BYTES,
        "compiled_words": COMPILED_WORDS,
        "word_refusals": [
            "ends in -user or -project",
            "ends in a segment of sixteen hexadecimal digits",
        ],
        "max_components": MAX_COMPONENTS,
        "max_component_bytes": MAX_COMPONENT_BYTES,
        "first_component_hidden": true,
        "formats": [
            { "format": "codex_toml", "suffix": DocumentFormat::CodexToml.suffix() },
            { "format": "json_command_args", "suffix": DocumentFormat::JsonCommandArgs.suffix() },
            { "format": "json_local_command_list", "suffix": DocumentFormat::JsonLocalCommandList.suffix() },
        ],
        "max_deadline_field_bytes": MAX_FIELD_BYTES,
        "entry_members": ENTRY_MEMBERS,
    })
}

/// The seconds the host writes for a deadline in seconds, and the milliseconds for the other unit
/// and for the environment value: the host's own constants, written by the host from them.
const DEADLINE_SECONDS: u32 = 660;

impl DocumentFormat {
    fn phrase(self) -> &'static str {
        match self {
            Self::CodexToml => "as the table mcp_servers.kalareach of a TOML file",
            Self::JsonCommandArgs => {
                "as mcpServers.kalareach of a JSON file, with a command and its arguments"
            }
            Self::JsonLocalCommandList => "as mcp.kalareach of a JSON file, with one command list",
        }
    }
}

impl SkillTarget {
    /// The host's exact reading of this declaration, the text an owner confirms after the label the
    /// host writes before it. It holds no colon, so it holds no label, and it is true for every
    /// declaration the package check allows: a user scope, a project scope or both, with or without
    /// a configuration document, in any of the three formats, shared or not, with or without a
    /// deadline.
    #[must_use]
    pub fn statement(&self) -> String {
        let mut parts = vec![format!(
            "The package names the agent \"{}\" and says where the host installs the KalaReach \
             contact skill for it, on macOS and Linux. Installing this package does not install \
             the skill, and the host starts no process when a person who manages this host \
             installs it.",
            self.word
        )];
        if let Some(location) = &self.user {
            parts.push(location.statement(
                &self.word,
                format!(
                    "For the user scope, kr skill install --agent {} --scope user makes the host \
                     write its own files SKILL.md, TOOLS.md and manifest.json into {}/kalareach-contact/ \
                     under the home folder of the account that runs this host",
                    self.word,
                    location.skills.join("/")
                ),
                "under that home folder",
            ));
        }
        if let Some(location) = &self.project {
            parts.push(location.statement(
                &self.word,
                format!(
                    "For a project, kr skill install --agent {} --scope project --project-dir with \
                     the project folder makes the host write its own files SKILL.md, TOOLS.md and \
                     manifest.json into {}/kalareach-contact/ under that project folder",
                    self.word,
                    location.skills.join("/")
                ),
                "under that folder",
            ));
        }
        let scopes = match (&self.user, &self.project) {
            (Some(_), Some(_)) => "--scope user or --scope project",
            (Some(_), None) => "--scope user",
            _ => "--scope project",
        };
        parts.push(format!(
            "The host keeps the other settings in each configuration file, follows no link below \
             the home folder or the project folder, and replaces no skill file and no entry named \
             kalareach that it did not write. It does not check which program reads these places \
             or how it uses their contents, and another program's own settings may be among them. \
             kr skill remove --agent {} {scopes}, with --project-dir for a project, takes \
             out only what this host wrote and finds unchanged, also after this package is gone, \
             and reports what it leaves in place. Removing the package does not remove the skill.",
            self.word,
            scopes = scopes
        ));
        parts.join(" ")
    }
}

impl SkillLocation {
    fn statement(&self, _word: &str, first: String, folder: &str) -> String {
        let Some(configuration) = &self.configuration else {
            return format!("{first}. The host adds no server entry for this scope.");
        };
        let path = configuration.path.join("/");
        let mut text = format!(
            "{first}, and adds one entry named kalareach to {path} {folder}, {}. The entry starts \
             kr with the arguments agent-tools --stdio",
            configuration.format.phrase()
        );
        match (&configuration.deadline, configuration.shared) {
            (_, true) => text.push_str(&format!(
                ". The package says that other agents also read {path}, so the entry there is the \
                 same for every installation that writes it and sets no time limit, and the host \
                 removes it only when no other installation of this host still claims it."
            )),
            (Some(deadline), false) => {
                let number = match deadline.unit {
                    DeadlineUnit::Seconds => DEADLINE_SECONDS,
                    DeadlineUnit::Milliseconds => DEADLINE_SECONDS * 1_000,
                };
                let unit = match deadline.unit {
                    DeadlineUnit::Seconds => "seconds",
                    DeadlineUnit::Milliseconds => "milliseconds",
                };
                text.push_str(&format!(
                    " and sets {} to {number} ({unit}) and KR_TOOL_DEADLINE_MS to {}.",
                    deadline.field,
                    DEADLINE_SECONDS * 1_000
                ));
            }
            (None, false) => text.push('.'),
        }
        text
    }
}

/// The most characters the host's reading of a skill target has: a word of the longest length,
/// three components of the longest length in each scope, the longest field name and the longest
/// format phrase, for the shared form, which is the longest. The statement carries it with the
/// publisher's and the other readings in the room an owner is shown whole.
pub const MAX_SKILL_TARGET_STATEMENT_CHARS: usize = 3_422;

/// The skill target a connector table declares, or `None` for a table that declares none.
///
/// A table that cannot be read, or whose declaration the package check refuses for a reason about
/// the table, is an error naming the first reason: the host never writes a reading of a
/// declaration it would refuse.
///
/// # Errors
///
/// Returns the reason, as a sentence, when the table cannot be read or its declaration is refused.
pub fn declared_in(table: &[u8]) -> Result<Option<SkillTarget>, String> {
    let table: crate::connector::ConnectorManifest = serde_json::from_slice(table)
        .map_err(|error| format!("the connector table cannot be read: {error}"))?;
    let Some(target) = table.skill_target else {
        return Ok(None);
    };
    match problems(&target, true)
        .into_iter()
        .find(Problem::is_about_the_table)
    {
        Some(problem) => Err(problem.message()),
        None => Ok(Some(target)),
    }
}

/// What the host says of a grant that holds the capability and a table that declares no skill
/// target.
pub const NO_SKILL_TARGET_STATEMENT: &str = "The package declares no skill target.";
