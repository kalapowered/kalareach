//! A package's command integration: the command it integrates, the flags it adds to an interactive
//! invocation of that command, and the environment variables it sets for that invocation.
//!
//! Section 12 lets an explicitly enabled command integration add the flags an agent needs to an
//! interactive invocation inside a managed root shell, with the worker-owned backend established
//! before the program starts. The package states the integration here, in its manifest, so what a
//! host adds is the bytes the package hash names: the host reads it only from the verified
//! manifest, never from anything that describes the installation. Asking for it is the
//! `command_integration.launch` capability, which the owner confirms on every release, and the
//! grant shows [`CommandIntegration::statement`], which lists the command, every flag and every
//! variable exactly.
//!
//! What a declaration may say is closed:
//!
//! * The command is a bare name, the executable name of one of the package's own match rules.
//! * The flags are whole argument elements, added in the order declared, each one line of text
//!   with nothing in it that a person reading the grant could not see.
//! * A variable is one of [`PERMITTED_VARIABLES`], by exact name and value. Reserved `KR_` values
//!   come only from the worker, and a variable that loads code, changes a search path or chooses a
//!   startup file changes what a program runs. No list of forbidden names can be complete, so this
//!   list names what is permitted instead, and a new entry is a change to the package contract.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::matching::MatchRule;
use crate::text::{Summary, is_forbidden_text_char};

/// The longest command name an integration may name, in bytes.
pub const MAX_COMMAND_BYTES: usize = 64;

/// The most flags one integration adds.
pub const MAX_FLAGS: usize = 16;

/// The longest one flag may be, in bytes.
pub const MAX_FLAG_BYTES: usize = 4096;

/// The flag that ends a command line's options.
///
/// The host adds an integration's flags in front of the first one a person typed, so an
/// integration that added one itself would turn the person's own options into operands.
pub const END_OF_OPTIONS: &str = "--";

/// One environment variable a package may set for the program it integrates, by exact name and
/// value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PermittedVariable {
    /// The variable's name.
    pub name: &'static str,
    /// The only value it may be given.
    pub value: &'static str,
    /// The application it is for.
    pub application: &'static str,
    /// What it does there, which is why it is permitted.
    pub reason: &'static str,
}

/// Every environment variable a command integration may set.
///
/// Each entry is permitted for one qualified reason, with its value fixed.
pub const PERMITTED_VARIABLES: &[PermittedVariable] = &[PermittedVariable {
    name: "GEMINI_CLI_NO_RELAUNCH",
    value: "true",
    application: "Gemini CLI",
    reason: "Gemini CLI runs the session in the process that was launched rather than in a copy \
             of itself it starts, so its hooks are that process's own",
}];

/// What a package declares about the command it integrates.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct CommandIntegration {
    /// The command name a person types, with no directory.
    pub command: String,
    /// The flags the integration adds to an interactive invocation, each one element of the
    /// argument vector, in the order they are added.
    pub flags: Vec<String>,
    /// The environment variables the integration sets for that invocation, in order.
    pub variables: Vec<IntegrationVariable>,
    /// What the grant tells the person before they accept it, beside the exact list the host
    /// renders from this declaration.
    pub grant_statement: Summary,
}

/// One environment variable a command integration sets.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct IntegrationVariable {
    /// The variable's name.
    pub name: String,
    /// Its value.
    pub value: String,
}

impl CommandIntegration {
    /// Returns what the integration does, exactly, for the grant a person confirms.
    ///
    /// Every flag is written as a JSON string, in the order it is added, and every variable as its
    /// name and its value as a JSON string. Nothing is shortened: a person confirms every byte the
    /// host adds.
    #[must_use]
    pub fn statement(&self) -> String {
        let mut statement = format!("Runs {} in KalaReach sessions", quoted(&self.command));
        if self.flags.is_empty() {
            statement.push_str(" with no arguments added.");
        } else {
            statement.push_str(" with these arguments added, in this order: ");
            let flags: Vec<String> = self.flags.iter().map(|flag| quoted(flag)).collect();
            statement.push_str(&flags.join(" "));
            statement.push('.');
        }
        if self.variables.is_empty() {
            statement.push_str(" It sets no environment variables.");
        } else {
            statement.push_str(" It sets these environment variables: ");
            let variables: Vec<String> = self
                .variables
                .iter()
                .map(|variable| format!("{}={}", variable.name, quoted(&variable.value)))
                .collect();
            statement.push_str(&variables.join(", "));
            statement.push('.');
        }
        statement
    }

    /// Returns every way this declaration breaks the package contract, for a package with these
    /// match rules.
    #[must_use]
    pub fn problems(&self, match_rules: &[MatchRule]) -> Vec<String> {
        let mut problems = Vec::new();
        if let Some(problem) = command_problem(&self.command) {
            problems.push(problem);
        } else if !match_rules.iter().any(|rule| {
            rule.executable
                .file_stem
                .eq_ignore_ascii_case(&self.command)
        }) {
            problems.push(format!(
                "the integration's command {} is not the executable name of any of the package's \
                 match rules",
                quoted(&self.command)
            ));
        }
        if self.flags.len() > MAX_FLAGS {
            problems.push(format!(
                "the integration adds {} flags, over the {MAX_FLAGS} one integration may add",
                self.flags.len()
            ));
        }
        for (index, flag) in self.flags.iter().enumerate() {
            if let Some(problem) = flag_problem(flag) {
                problems.push(format!("flag {index}: {problem}"));
            }
        }
        let mut named = std::collections::BTreeSet::new();
        for variable in &self.variables {
            if !named.insert(variable.name.as_str()) {
                problems.push(format!(
                    "the integration sets {} more than once",
                    quoted(&variable.name)
                ));
            }
            if permitted(variable).is_none() {
                problems.push(format!(
                    "{}={} is not a variable a command integration may set; the permitted ones \
                     are {}",
                    quoted(&variable.name),
                    quoted(&variable.value),
                    PERMITTED_VARIABLES
                        .iter()
                        .map(|permitted| format!("{}={}", permitted.name, quoted(permitted.value)))
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
        }
        if self.flags.is_empty() && self.variables.is_empty() {
            problems.push(
                "the integration adds no flag and sets no variable, so it changes nothing"
                    .to_owned(),
            );
        }
        problems
    }
}

/// Returns the permitted entry a declared variable is, where it is one.
#[must_use]
pub fn permitted(variable: &IntegrationVariable) -> Option<&'static PermittedVariable> {
    PERMITTED_VARIABLES
        .iter()
        .find(|permitted| permitted.name == variable.name && permitted.value == variable.value)
}

/// Returns why a command name is not one an integration may name, where it is not.
fn command_problem(command: &str) -> Option<String> {
    if command.is_empty() {
        return Some("the integration names no command".to_owned());
    }
    if command.len() > MAX_COMMAND_BYTES {
        return Some(format!(
            "the integration's command is {} bytes, over the {MAX_COMMAND_BYTES} a command name \
             may be",
            command.len()
        ));
    }
    if !command
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'-'))
    {
        return Some(format!(
            "the integration's command {} is not a bare command name: letters, digits, '.', \
             '_', '+' and '-' only",
            quoted(command)
        ));
    }
    if command.starts_with(['-', '.']) {
        return Some(format!(
            "the integration's command {} starts with '-' or '.'",
            quoted(command)
        ));
    }
    None
}

/// Returns why one flag is not one an integration may add, where it is not.
fn flag_problem(flag: &str) -> Option<String> {
    if flag.is_empty() {
        return Some("an empty flag adds an empty argument".to_owned());
    }
    if flag.len() > MAX_FLAG_BYTES {
        return Some(format!(
            "{} bytes, over the {MAX_FLAG_BYTES} one flag may be",
            flag.len()
        ));
    }
    if flag == END_OF_OPTIONS {
        return Some(format!(
            "{} ends the options, so the person's own options would become operands",
            quoted(flag)
        ));
    }
    if let Some(character) = flag.chars().find(|c| is_forbidden_text_char(*c)) {
        return Some(format!(
            "it carries U+{:04X}, which a person reading the grant could not see",
            u32::from(character)
        ));
    }
    None
}

/// Writes text as a JSON string, which shows every character it holds.
fn quoted(text: &str) -> String {
    serde_json::to_string(text).unwrap_or_else(|_| format!("{text:?}"))
}

#[cfg(test)]
mod tests {
    use kr_protocol::scalars::Nullable;

    use super::*;
    use crate::ids::PluginName;
    use crate::matching::{ExecutableMatch, MatchConfidence};

    fn rule(file_stem: &str, path_suffix: &[&str]) -> MatchRule {
        MatchRule {
            id: PluginName::new("rule").expect("a literal rule id"),
            executable: ExecutableMatch {
                file_stem: file_stem.to_owned(),
                path_suffix: path_suffix.iter().map(|part| (*part).to_owned()).collect(),
                version_range: Nullable(None),
            },
            distribution: Nullable(None),
            confidence: MatchConfidence::Inferred,
        }
    }

    fn integration(
        command: &str,
        flags: &[&str],
        variables: &[(&str, &str)],
    ) -> CommandIntegration {
        CommandIntegration {
            command: command.to_owned(),
            flags: flags.iter().map(|flag| (*flag).to_owned()).collect(),
            variables: variables
                .iter()
                .map(|(name, value)| IntegrationVariable {
                    name: (*name).to_owned(),
                    value: (*value).to_owned(),
                })
                .collect(),
            grant_statement: Summary::new("Adds the flags the package's bridge needs")
                .expect("a literal summary"),
        }
    }

    #[test]
    fn the_statement_lists_every_flag_and_variable_exactly_and_in_order() {
        let claude = integration(
            "claude",
            &[
                "--dangerously-load-development-channels",
                "plugin:kalareach-channels@skills-dir",
            ],
            &[],
        );
        assert_eq!(
            claude.statement(),
            "Runs \"claude\" in KalaReach sessions with these arguments added, in this order: \
             \"--dangerously-load-development-channels\" \"plugin:kalareach-channels@skills-dir\". \
             It sets no environment variables."
        );
        let gemini = integration("gemini", &[], &[("GEMINI_CLI_NO_RELAUNCH", "true")]);
        assert_eq!(
            gemini.statement(),
            "Runs \"gemini\" in KalaReach sessions with no arguments added. It sets these \
             environment variables: GEMINI_CLI_NO_RELAUNCH=\"true\"."
        );
        // A flag holding JSON is shown whole, with its quotes escaped, and never shortened.
        let long = format!("{{\"hooks\":\"{}\"}}", "x".repeat(3000));
        let statement = integration("qodercli", &["--settings", &long], &[]).statement();
        assert!(
            statement.contains(&serde_json::to_string(&long).expect("a string")),
            "{statement}"
        );
    }

    #[test]
    fn a_command_is_the_executable_name_of_one_of_the_package_s_rules() {
        let rules = [rule("kimi", &[".kimi-code", "bin"])];
        assert!(
            integration("kimi", &["--flag"], &[])
                .problems(&rules)
                .is_empty(),
            "a rule with a directory suffix still names the executable"
        );
        for command in [
            "codex",
            "",
            "bin/kimi",
            "/usr/bin/kimi",
            "-kimi",
            ".kimi",
            "ki mi",
        ] {
            assert!(
                !integration(command, &["--flag"], &[])
                    .problems(&rules)
                    .is_empty(),
                "{command:?} is refused"
            );
        }
        let long = "k".repeat(MAX_COMMAND_BYTES + 1);
        assert!(
            !integration(&long, &["--flag"], &[])
                .problems(&[rule(&long, &[])])
                .is_empty()
        );
    }

    #[test]
    fn a_flag_is_one_whole_visible_argument_and_the_list_is_bounded() {
        let rules = [rule("agent", &[])];
        for flag in ["", "--", "--a\nb", "--\u{202E}a", "--a\u{200B}"] {
            assert!(
                !integration("agent", &[flag], &[])
                    .problems(&rules)
                    .is_empty(),
                "{flag:?} is refused"
            );
        }
        let longest = "f".repeat(MAX_FLAG_BYTES);
        assert!(
            integration("agent", &[&longest], &[])
                .problems(&rules)
                .is_empty()
        );
        let over = "f".repeat(MAX_FLAG_BYTES + 1);
        assert!(
            !integration("agent", &[&over], &[])
                .problems(&rules)
                .is_empty()
        );
        let most: Vec<&str> = std::iter::repeat_n("--f", MAX_FLAGS).collect();
        assert!(integration("agent", &most, &[]).problems(&rules).is_empty());
        let too_many: Vec<&str> = std::iter::repeat_n("--f", MAX_FLAGS + 1).collect();
        assert!(
            !integration("agent", &too_many, &[])
                .problems(&rules)
                .is_empty()
        );
    }

    #[test]
    fn only_a_permitted_variable_with_its_value_is_set() {
        let rules = [rule("gemini", &[])];
        assert!(
            integration("gemini", &[], &[("GEMINI_CLI_NO_RELAUNCH", "true")])
                .problems(&rules)
                .is_empty()
        );
        for (name, value) in [
            ("KR_REGISTRATION", "/tmp/registration.1.2"),
            ("KR_SESSION", "x"),
            ("LD_PRELOAD", "/tmp/x.so"),
            ("DYLD_INSERT_LIBRARIES", "/tmp/x.dylib"),
            ("LUA_INIT", "@/tmp/x.lua"),
            ("BUN_OPTIONS", "--preload /tmp/x.js"),
            ("GCONV_PATH", "/tmp"),
            ("NODE_OPTIONS", "--require /tmp/x.js"),
            ("PATH", "/tmp"),
            ("BASH_ENV", "/tmp/x.sh"),
            ("HOME", "/tmp"),
            ("GEMINI_CLI_NO_RELAUNCH", "1"),
            ("gemini_cli_no_relaunch", "true"),
        ] {
            assert!(
                !integration("gemini", &[], &[(name, value)])
                    .problems(&rules)
                    .is_empty(),
                "{name}={value} is refused"
            );
        }
        assert!(
            !integration(
                "gemini",
                &[],
                &[
                    ("GEMINI_CLI_NO_RELAUNCH", "true"),
                    ("GEMINI_CLI_NO_RELAUNCH", "true")
                ]
            )
            .problems(&rules)
            .is_empty(),
            "a variable set twice"
        );
        assert!(
            !integration("gemini", &[], &[]).problems(&rules).is_empty(),
            "an integration that changes nothing"
        );
    }
}
