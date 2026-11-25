//! A package's ACP launch: the one way a host starts the package's agent in ACP mode, and the
//! variables it gives the agent's start.
//!
//! ACP mode starts an agent that speaks the Agent Client Protocol on its standard input and
//! output, with KalaReach as its only client. The host starts it with the one argument `--acp`,
//! which no declaration can change, from an environment it builds from nothing: it copies the
//! variables the declaration lists from the person's shell, one name at a time, and sets the
//! constants the declaration lists. The package states that here, in its manifest, so the package
//! hash covers what a host gives the agent. The owner confirms it with the
//! `command_integration.launch` capability on every release, with `approval.decode` and
//! `approval.respond` granted so that an approval the agent asks for can be answered, and turns
//! it on for each package in the host configuration.
//! [`AcpLaunch::statement`] lists every variable the declaration names, so an owner device shows
//! them before the launch is granted.
//!
//! What a declaration may say is closed:
//!
//! * The command is a bare name, the executable name of one of the package's own match rules.
//! * The platforms are `linux` and `mac_os`, each one the package supports.
//! * A variable is a name of letters, digits and underscores that does not begin with `KR_`.
//!   The host copies a passed name only when the person's shell has it. A required name is a
//!   passed name too, and the launch is refused when the shell has no such variable or it is
//!   empty.
//! * A constant is a name and a value on one line. The one value that is not literal is
//!   [`PRIVATE_HOME_PLACEHOLDER`], which stands alone as a whole value and which the host replaces
//!   with the path of a folder it makes new and empty for each start.
//! * The declaration has no argument member: the host passes [`AGENT_ARGUMENT`] and nothing else.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::capability::PluginCapability;
use crate::integration::{command_problem, quoted};
use crate::matching::{MatchRule, OperatingSystem};
use crate::text::{GrantWords, is_forbidden_text_char};

/// The only argument the host passes to the agent in ACP mode.
pub const AGENT_ARGUMENT: &str = "--acp";

/// The text a constant's value holds, as the whole value, where the host writes the path of the
/// folder it makes new and empty for the start.
pub const PRIVATE_HOME_PLACEHOLDER: &str = "{private_home}";

/// The most names one list may hold.
pub const MAX_NAMES: usize = 64;

/// The longest variable name, in bytes.
pub const MAX_NAME_BYTES: usize = 64;

/// The most constants one declaration may set.
pub const MAX_CONSTANTS: usize = 16;

/// The longest constant value, in bytes.
pub const MAX_VALUE_BYTES: usize = 256;

/// What a package declares about starting its agent in ACP mode.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct AcpLaunch {
    /// The command name of the agent, with no directory.
    pub command: String,
    /// The operating systems the host starts the agent on in ACP mode.
    pub platforms: Vec<OperatingSystem>,
    /// The variables the person's shell must have, each non-empty, or the launch is refused. Each
    /// is also a passed name.
    pub required_names: Vec<String>,
    /// The variables the host copies from the person's shell into the agent's start, each only
    /// when the shell has it. No other variable of the shell is copied, whatever its name.
    pub passed_names: Vec<String>,
    /// The variables the host sets itself, in order.
    pub constants: Vec<AcpConstant>,
    /// What the package says the launch does and does not do, in its own words.
    pub grant_statement: GrantWords,
}

/// One variable the host sets in the agent's start.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct AcpConstant {
    /// The variable's name.
    pub name: String,
    /// Its value, or [`PRIVATE_HOME_PLACEHOLDER`] alone.
    pub value: String,
}

impl AcpLaunch {
    /// Returns what the launch does, exactly, as text a person can read.
    ///
    /// Every passed name, every required name and every constant is in it, and so is the one
    /// argument the host passes. Names are written as they are when they have the shape the
    /// contract allows and as JSON strings when they do not, and every constant value is written
    /// as a JSON string, so the text is one line and shows every character a value holds.
    #[must_use]
    pub fn statement(&self) -> String {
        let mut statement = format!(
            "Adds an ACP button for {}, a second way to start it, on {}. Only that button starts \
             it in ACP mode. KalaReach starts it with the one argument {} and adds no other.",
            quoted(&self.command),
            platform_words(&self.platforms),
            quoted(AGENT_ARGUMENT)
        );
        statement.push_str(
            " KalaReach builds the environment of that start from nothing: it copies these \
             variables from your shell, each only when it is set: ",
        );
        statement.push_str(&names_written(&self.passed_names));
        statement.push('.');
        if self.constants.is_empty() {
            statement.push_str(" KalaReach sets no variables.");
        } else {
            let constants: Vec<String> = self
                .constants
                .iter()
                .map(|constant| {
                    format!(
                        "{}={}",
                        name_written(&constant.name),
                        quoted(&constant.value)
                    )
                })
                .collect();
            statement.push_str(" KalaReach sets these variables itself: ");
            statement.push_str(&constants.join(", "));
            statement.push('.');
            if self
                .constants
                .iter()
                .any(|constant| constant.value == PRIVATE_HOME_PLACEHOLDER)
            {
                statement.push_str(&format!(
                    " {PRIVATE_HOME_PLACEHOLDER} stands for a folder that KalaReach makes new and \
                     empty for each start and deletes when the agent ends."
                ));
            }
        }
        statement.push_str(
            " The start is refused when any of these variables is missing from your shell or \
             empty: ",
        );
        statement.push_str(&names_written(&self.required_names));
        statement.push('.');
        statement.push_str(
            " Every other variable of your shell stays out of that start, whatever its name. The \
             agent and the programs it starts add variables of their own, and KalaReach does not \
             promise a fixed environment for them.",
        );
        statement
    }
}

/// Returns the operating systems as a person reads them: "macOS and Linux".
fn platform_words(platforms: &[OperatingSystem]) -> String {
    let words: Vec<&str> = platforms
        .iter()
        .map(|platform| match platform {
            OperatingSystem::Linux => "Linux",
            OperatingSystem::MacOs => "macOS",
            OperatingSystem::Windows => "Windows",
        })
        .collect();
    match words.as_slice() {
        [] => "no platform".to_owned(),
        [only] => (*only).to_owned(),
        [init @ .., last] => format!("{} and {last}", init.join(", ")),
    }
}

/// Returns a variable name as the statement writes it: as it is where it has the shape the
/// contract allows, and as a JSON string where it does not.
fn name_written(name: &str) -> String {
    if name_has_shape(name) {
        name.to_owned()
    } else {
        quoted(name)
    }
}

/// Returns a list of names as the statement writes them, or `none` for an empty list.
fn names_written(names: &[String]) -> String {
    if names.is_empty() {
        return "none".to_owned();
    }
    names
        .iter()
        .map(|name| name_written(name))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Whether `name` is letters, digits and underscores, not beginning with a digit, and within
/// [`MAX_NAME_BYTES`].
fn name_has_shape(name: &str) -> bool {
    let mut bytes = name.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    name.len() <= MAX_NAME_BYTES
        && (first.is_ascii_alphabetic() || first == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

impl AcpLaunch {
    /// Returns every way this declaration breaks the package contract, for a package with these
    /// match rules that supports these operating systems.
    ///
    /// Each reason begins with a word that says what kind it is: `names missing`, `platform`,
    /// `name` or `constant`; the command's own reasons name the ACP launch.
    #[must_use]
    pub fn problems(
        &self,
        match_rules: &[MatchRule],
        supported: &[OperatingSystem],
    ) -> Vec<String> {
        let mut problems = Vec::new();
        if let Some(problem) = command_problem("the ACP launch", &self.command) {
            problems.push(problem);
        } else if !match_rules.iter().any(|rule| {
            rule.executable
                .file_stem
                .eq_ignore_ascii_case(&self.command)
        }) {
            problems.push(format!(
                "the ACP launch's command {} is not the executable name of any of the package's \
                 match rules",
                quoted(&self.command)
            ));
        }
        self.platform_problems(supported, &mut problems);
        self.name_problems(&mut problems);
        self.constant_problems(&mut problems);
        problems
    }

    /// Adds every way the platform list breaks the contract.
    fn platform_problems(&self, supported: &[OperatingSystem], problems: &mut Vec<String>) {
        if self.platforms.is_empty() {
            problems.push("platform: acp_launch lists no platform".to_owned());
        }
        let mut listed = std::collections::BTreeSet::new();
        for platform in &self.platforms {
            if !listed.insert(*platform) {
                problems.push(format!(
                    "platform: acp_launch lists {} more than once",
                    platform.as_str()
                ));
            } else if *platform == OperatingSystem::Windows {
                problems.push(format!(
                    "platform: acp_launch lists {}, which has no ACP launch",
                    platform.as_str()
                ));
            } else if !supported.contains(platform) {
                problems.push(format!(
                    "platform: acp_launch lists {}, which the package's platforms do not support",
                    platform.as_str()
                ));
            }
        }
    }

    /// Adds every way the two name lists break the contract.
    fn name_problems(&self, problems: &mut Vec<String>) {
        if self.required_names.is_empty() {
            problems.push("names missing: acp_launch lists no required name".to_owned());
        }
        for name in &self.required_names {
            if !self.passed_names.contains(name) {
                problems.push(format!(
                    "names missing: required name {} is not in passed_names",
                    quoted(name)
                ));
            }
        }
        for (list, names) in [
            ("required_names", &self.required_names),
            ("passed_names", &self.passed_names),
        ] {
            if names.len() > MAX_NAMES {
                problems.push(format!(
                    "name: {list} lists {} names, over the {MAX_NAMES} one list may",
                    names.len()
                ));
            }
            let mut seen = std::collections::BTreeSet::new();
            for name in names {
                if let Some(problem) = name_problem(name) {
                    problems.push(format!("name: {} in {list} {problem}", quoted(name)));
                }
                if !seen.insert(name.as_str()) {
                    problems.push(format!(
                        "name: {} is listed more than once in {list}",
                        quoted(name)
                    ));
                }
            }
        }
    }

    /// Adds every way the constants break the contract.
    fn constant_problems(&self, problems: &mut Vec<String>) {
        if self.constants.len() > MAX_CONSTANTS {
            problems.push(format!(
                "constant: acp_launch sets {} variables, over the {MAX_CONSTANTS} it may",
                self.constants.len()
            ));
        }
        let mut seen = std::collections::BTreeSet::new();
        for constant in &self.constants {
            let name = quoted(&constant.name);
            if let Some(problem) = name_problem(&constant.name) {
                problems.push(format!("constant: the name {name} {problem}"));
            }
            if !seen.insert(constant.name.as_str()) {
                problems.push(format!("constant: {name} is set more than once"));
            }
            if self.passed_names.contains(&constant.name) {
                problems.push(format!(
                    "constant: {name} is both set by KalaReach and passed from the shell"
                ));
            }
            if let Some(problem) = value_problem(&constant.value) {
                problems.push(format!("constant: the value of {name} {problem}"));
            }
        }
    }
}

/// Returns why a variable name is not one a declaration may list, where it is not.
fn name_problem(name: &str) -> Option<String> {
    if !name_has_shape(name) {
        return Some(format!(
            "is not a variable name: letters, digits and '_' only, not beginning with a digit, \
             and at most {MAX_NAME_BYTES} bytes"
        ));
    }
    if name.starts_with("KR_") {
        return Some("begins with KR_, which only the worker sets".to_owned());
    }
    None
}

/// Returns why a constant's value is not one a declaration may set, where it is not.
fn value_problem(value: &str) -> Option<String> {
    if value.is_empty() {
        return Some("is empty".to_owned());
    }
    if value.len() > MAX_VALUE_BYTES {
        return Some(format!(
            "is {} bytes, over the {MAX_VALUE_BYTES} a value may be",
            value.len()
        ));
    }
    if let Some(character) = value.chars().find(|c| is_forbidden_text_char(*c)) {
        return Some(format!(
            "carries U+{:04X}, which a person reading the declaration could not see",
            u32::from(character)
        ));
    }
    if value != PRIVATE_HOME_PLACEHOLDER && value.contains(['{', '}']) {
        return Some(format!(
            "holds a brace, and only {PRIVATE_HOME_PLACEHOLDER} may stand there, alone as the \
             whole value"
        ));
    }
    None
}

/// Why a host does not start an agent in ACP mode, in the order the host checks.
///
/// Its text is what the person reads, one sentence for each cause.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AcpRefusal {
    /// The owner's switch for this package is off.
    SwitchOff,
    /// The owner has not confirmed this release's launch grant.
    NotConfirmed,
    /// The release does not hold both approval grants.
    ApprovalsMissing,
    /// The host's operating system is not one the declaration lists.
    Platform {
        /// The operating systems the declaration lists, as a person reads them.
        listed: String,
    },
}

impl std::fmt::Display for AcpRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SwitchOff => {
                formatter.write_str("ACP mode is switched off for this agent on this host.")
            }
            Self::NotConfirmed => formatter.write_str(
                "The owner has not confirmed this release's launch grant, so ACP mode is not \
                 available.",
            ),
            Self::ApprovalsMissing => formatter.write_str(
                "ACP mode needs the approval.decode and approval.respond grants, and this \
                 release does not hold both.",
            ),
            Self::Platform { listed } => write!(
                formatter,
                "This release does not offer ACP mode on this platform: it lists {listed}."
            ),
        }
    }
}

impl AcpLaunch {
    /// Returns this declaration when a host may start the agent in ACP mode, and the first cause
    /// that forbids it otherwise.
    ///
    /// `held` is what the installation's grant holds for this release, `switch_on` is the owner's
    /// switch for the package in the host configuration, and `host` is the operating system the
    /// host runs on. The causes are checked in this order: the switch, the owner's confirmation of
    /// the launch grant, the two approval grants, the platform.
    ///
    /// # Errors
    ///
    /// Returns the first [`AcpRefusal`] that applies.
    pub fn admission(
        &self,
        held: &[PluginCapability],
        switch_on: bool,
        host: OperatingSystem,
    ) -> Result<&Self, AcpRefusal> {
        if !switch_on {
            return Err(AcpRefusal::SwitchOff);
        }
        if !held.contains(&PluginCapability::CommandIntegrationLaunch) {
            return Err(AcpRefusal::NotConfirmed);
        }
        if !held.contains(&PluginCapability::ApprovalDecode)
            || !held.contains(&PluginCapability::ApprovalRespond)
        {
            return Err(AcpRefusal::ApprovalsMissing);
        }
        if !self.platforms.contains(&host) {
            return Err(AcpRefusal::Platform {
                listed: platform_words(&self.platforms),
            });
        }
        Ok(self)
    }
}
