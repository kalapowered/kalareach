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

use crate::integration::quoted;
use crate::matching::OperatingSystem;
use crate::text::GrantWords;

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
