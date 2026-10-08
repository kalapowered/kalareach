//! A package's command integration: the command it integrates, the flags it adds to an interactive
//! invocation of that command, and the environment variables it sets for that invocation.
//!
//! Section 12 lets an explicitly enabled command integration add the flags an agent needs to an
//! interactive invocation inside a managed root shell, with the worker-owned backend established
//! before the program starts. The package states the integration here, in its manifest, so what a
//! host adds is the bytes the package hash names: the host reads it only from the verified
//! manifest, never from anything that describes the installation. Asking for it is the
//! `command_integration.launch` capability, which the owner confirms on every release. The plan an
//! installation or a grant is confirmed against holds the capability names and the exact package
//! hash, which covers the declaration, and not [`CommandIntegration::statement`], which lists the
//! command, every flag and every variable exactly, so no confirmation shows it.
//!
//! A declaration may also name a **backend**: an application whose terminal speaks to a server
//! rather than to its own program (Codex's `--remote` terminal and its App Server). The worker
//! starts that server as the session's backend, from the executable the shell resolved for the
//! command and the arguments declared here, and the flag element [`GATEWAY_PLACEHOLDER`] is
//! replaced, once the launch is committed, with the address of the worker-owned gateway the
//! terminal is to connect to. The backend is started only for a plain launch of the terminal: a
//! launch that types an option, or whose first word is not one the declaration lists, runs as
//! typed, because the server would not receive what was typed.
//!
//! What a declaration may say is closed:
//!
//! * The command is a bare name, the executable name of one of the package's own match rules.
//! * The flags are whole argument elements, added in the order declared, each one line of text
//!   with nothing in it that a person reading the declaration could not see. A flag may hold the
//!   forwarder's placeholder (see [`crate::forwarder`]), which the host replaces with the installed
//!   forwarder's path, and the statement says so.
//! * A variable is one of [`PERMITTED_VARIABLES`], by exact name and value. Reserved `KR_` values
//!   come only from the worker, and a variable that loads code, changes a search path or chooses a
//!   startup file changes what a program runs. No list of forbidden names can be complete, so this
//!   list names what is permitted instead, and a new entry is a change to the package contract.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::forwarder;
use crate::matching::MatchRule;
use crate::text::{Summary, is_forbidden_text_char};

/// The longest command name an integration may name, in bytes.
pub const MAX_COMMAND_BYTES: usize = 64;

/// The most flags one integration adds.
pub const MAX_FLAGS: usize = 16;

/// The longest one flag may be, in bytes.
pub const MAX_FLAG_BYTES: usize = 4096;

/// The most arguments a backend is started with.
pub const MAX_BACKEND_ARGUMENTS: usize = 8;

/// The longest one backend argument may be, in bytes.
pub const MAX_BACKEND_ARGUMENT_BYTES: usize = 256;

/// The most words a declaration lists as launching the terminal.
pub const MAX_LAUNCHING_WORDS: usize = 8;

/// The longest one such word may be, in bytes.
pub const MAX_LAUNCHING_WORD_BYTES: usize = 32;

/// The text a flag holds, as a whole element, where the host writes the address of the gateway the
/// terminal connects to.
pub const GATEWAY_PLACEHOLDER: &str = "{gateway}";

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
    /// What the package says its integration does, in its own words.
    pub grant_statement: Summary,
    /// The backend the worker starts for the integrated invocation, where the application's
    /// terminal speaks to a server.
    ///
    /// A package that declares none leaves the member out, so a manifest written before the
    /// member existed reads and hashes exactly as it did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend: Option<IntegrationBackend>,
}

/// The backend a command integration starts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct IntegrationBackend {
    /// The arguments the application's own executable is started with to make the backend, in
    /// order, each one argument element. The executable is the one the shell resolved for the
    /// command; a package cannot name another.
    pub arguments: Vec<String>,
    /// The words that may follow the command name for a launch the backend is started for.
    ///
    /// A launch whose first word is absent, or one of these, and that types no option, is a plain
    /// launch of the terminal. Any other launch (a subcommand that is not a terminal, an option,
    /// a prompt) runs as typed, because the closed list is what the package qualified.
    pub launching_words: Vec<String>,
}

impl IntegrationBackend {
    /// Returns why a launch typed as `typed`, the command name first, is not one the backend is
    /// started for, where it is not.
    ///
    /// The reason names the element and what the declaration allows, and a caller ends it with
    /// what follows from it: the invocation runs as typed.
    #[must_use]
    pub fn refuses(&self, typed: &[String]) -> Option<String> {
        let mut rest = typed.iter().skip(1);
        if let Some(option) = typed.iter().skip(1).find(|word| word.starts_with('-')) {
            return Some(format!(
                "{} is an option, and the gateway serves a launch that types none, because the \
                 backend this session starts does not receive it",
                quoted(option)
            ));
        }
        let first = rest.next()?;
        if self.launching_words.iter().any(|word| word == first) {
            return None;
        }
        Some(format!(
            "{} is not a launch the gateway serves; it serves {}",
            quoted(first),
            if self.launching_words.is_empty() {
                "only the command typed alone".to_owned()
            } else {
                format!(
                    "the command typed alone, or followed by {}",
                    self.launching_words
                        .iter()
                        .map(|word| quoted(word))
                        .collect::<Vec<_>>()
                        .join(" or ")
                )
            }
        ))
    }
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
    /// Returns what the integration does, exactly, as text a person can read.
    ///
    /// Every flag is written as a JSON string, in the order it is added, and every variable as its
    /// name and its value as a JSON string. Nothing is shortened: every flag and every variable
    /// the host adds is in it.
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
            if self.flags.iter().any(|flag| forwarder::mentions(flag)) {
                statement.push_str(&format!(
                    " {} is replaced by the full path of the KalaReach forwarder installed on this \
                     machine, written as the path of a program the application starts.",
                    forwarder::PLACEHOLDER
                ));
            }
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
        if let Some(backend) = &self.backend {
            statement.push_str(&format!(
                " It also starts the program {} names, with these arguments, as the session's \
                 backend, in this order: {}.",
                quoted(&self.command),
                backend
                    .arguments
                    .iter()
                    .map(|argument| quoted(argument))
                    .collect::<Vec<_>>()
                    .join(" ")
            ));
            statement.push_str(&format!(
                " {GATEWAY_PLACEHOLDER} is replaced by the address of the gateway this host \
                 runs for that backend, which the terminal connects to."
            ));
            statement.push_str(&if backend.launching_words.is_empty() {
                " The backend is started only when the command is typed alone.".to_owned()
            } else {
                format!(
                    " The backend is started only when the command is typed alone or followed by {} \
                     and no option.",
                    backend
                        .launching_words
                        .iter()
                        .map(|word| quoted(word))
                        .collect::<Vec<_>>()
                        .join(" or ")
                )
            });
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
        self.backend_problems(&mut problems);
        problems
    }

    /// Adds every way the backend and the flag that names its gateway break the contract.
    fn backend_problems(&self, problems: &mut Vec<String>) {
        let naming: Vec<usize> = self
            .flags
            .iter()
            .enumerate()
            .filter(|(_, flag)| flag.contains(GATEWAY_PLACEHOLDER))
            .map(|(index, _)| index)
            .collect();
        for index in &naming {
            if self.flags[*index] != GATEWAY_PLACEHOLDER {
                problems.push(format!(
                    "flag {index}: {GATEWAY_PLACEHOLDER} stands alone as a whole flag element, \
                     and this one holds more"
                ));
            }
        }
        let Some(backend) = &self.backend else {
            if !naming.is_empty() {
                problems.push(format!(
                    "a flag names {GATEWAY_PLACEHOLDER} and the integration declares no backend, \
                     so there is no gateway to name"
                ));
            }
            return;
        };
        if naming.len() != 1 {
            problems.push(format!(
                "the integration declares a backend and names {GATEWAY_PLACEHOLDER} in {} flags; \
                 the terminal is told where the gateway is by exactly one",
                naming.len()
            ));
        }
        let arguments = backend.arguments.len();
        if arguments == 0 || arguments > MAX_BACKEND_ARGUMENTS {
            problems.push(format!(
                "the backend is started with {arguments} arguments; the range is 1 to \
                 {MAX_BACKEND_ARGUMENTS}"
            ));
        }
        for (index, argument) in backend.arguments.iter().enumerate() {
            if let Some(problem) = backend_argument_problem(argument) {
                problems.push(format!("backend argument {index}: {problem}"));
            }
        }
        if backend.launching_words.len() > MAX_LAUNCHING_WORDS {
            problems.push(format!(
                "the integration lists {} launching words, over the {MAX_LAUNCHING_WORDS} it may",
                backend.launching_words.len()
            ));
        }
        let mut listed = std::collections::BTreeSet::new();
        for word in &backend.launching_words {
            if let Some(problem) = launching_word_problem(word) {
                problems.push(format!("launching word {}: {problem}", quoted(word)));
            }
            if !listed.insert(word.as_str()) {
                problems.push(format!(
                    "the launching word {} is listed more than once",
                    quoted(word)
                ));
            }
        }
    }
}

/// Returns why one backend argument is not one a package may declare, where it is not.
fn backend_argument_problem(argument: &str) -> Option<String> {
    if argument.is_empty() {
        return Some("an empty argument".to_owned());
    }
    if argument.len() > MAX_BACKEND_ARGUMENT_BYTES {
        return Some(format!(
            "{} bytes, over the {MAX_BACKEND_ARGUMENT_BYTES} one backend argument may be",
            argument.len()
        ));
    }
    if let Some(character) = argument.chars().find(|c| is_forbidden_text_char(*c)) {
        return Some(format!(
            "it carries U+{:04X}, which a person reading the declaration could not see",
            u32::from(character)
        ));
    }
    if forwarder::mentions(argument) || argument.contains(GATEWAY_PLACEHOLDER) {
        return Some(
            "a backend argument is written as it stands; neither placeholder is replaced in one"
                .to_owned(),
        );
    }
    None
}

/// Returns why one launching word is not a bare subcommand name, where it is not.
fn launching_word_problem(word: &str) -> Option<String> {
    if word.is_empty() || word.len() > MAX_LAUNCHING_WORD_BYTES {
        return Some(format!(
            "a launching word is 1 to {MAX_LAUNCHING_WORD_BYTES} bytes, and this is {}",
            word.len()
        ));
    }
    if word.starts_with('-') {
        return Some("it starts with '-', which makes it an option, not a word".to_owned());
    }
    if !word
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Some("letters, digits, '_' and '-' only".to_owned());
    }
    None
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
            "it carries U+{:04X}, which a person reading the declaration could not see",
            u32::from(character)
        ));
    }
    // The host writes the forwarder's path where the placeholder stands, so it has to stand where
    // the host can.
    if let Err(error) = forwarder::expand(flag, std::path::Path::new("/kalareach/bin/kr-hook")) {
        return Some(error.to_string());
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
            backend: None,
        }
    }

    fn with_backend(
        mut declared: CommandIntegration,
        backend: &[&str],
        words: &[&str],
    ) -> CommandIntegration {
        declared.backend = Some(IntegrationBackend {
            arguments: backend
                .iter()
                .map(|argument| (*argument).to_owned())
                .collect(),
            launching_words: words.iter().map(|word| (*word).to_owned()).collect(),
        });
        declared
    }

    fn typed(words: &[&str]) -> Vec<String> {
        words.iter().map(|word| (*word).to_owned()).collect()
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
        // The finding names the character a person could not see.
        let hidden = integration("agent", &["--a\u{200B}"], &[]).problems(&rules);
        assert_eq!(hidden.len(), 1, "{hidden:?}");
        assert!(hidden[0].contains("U+200B"), "{hidden:?}");
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
    fn the_forwarder_placeholder_is_allowed_where_the_host_replaces_it_and_the_statement_says_so() {
        let settings = r#"{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"{kr_hook}","args":["qoder-cli","hook"]}]}]}}"#;
        let rules = [rule("agent", &[])];
        let placed = integration("agent", &["--settings", settings], &[]);
        assert!(placed.problems(&rules).is_empty());
        let statement = placed.statement();
        assert!(
            statement.ends_with(
                " {kr_hook} is replaced by the full path of the KalaReach forwarder installed on \
                 this machine, written as the path of a program the application starts. It sets no \
                 environment variables."
            ),
            "{statement}"
        );
        assert!(
            !integration("agent", &["--flag"], &[])
                .statement()
                .contains("{kr_hook}"),
            "a declaration without the placeholder says nothing of it"
        );
        for misplaced in [
            "--hook={kr_hook}",
            "x{kr_hook}",
            "{kr_hook}",
            "\"a{kr_hook}\"",
        ] {
            assert!(
                !integration("agent", &[misplaced], &[])
                    .problems(&rules)
                    .is_empty(),
                "{misplaced:?} is refused"
            );
        }
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

    /// A backend declaration the contract accepts: the terminal is pointed at the gateway by one
    /// flag element, the server is started by the arguments declared, and a launch is a plain one.
    fn codex_like() -> CommandIntegration {
        with_backend(
            integration("codex", &["--remote", GATEWAY_PLACEHOLDER], &[]),
            &["app-server", "--listen", "stdio://"],
            &["resume", "fork"],
        )
    }

    #[test]
    fn kr_req_12_07_a_backend_is_declared_by_arguments_one_gateway_flag_and_closed_words() {
        let rules = [rule("codex", &[])];
        assert!(codex_like().problems(&rules).is_empty());
        // Every way the declaration can break the contract is a finding that says which.
        let broken = |declared: CommandIntegration| declared.problems(&rules);
        let one_of = |problems: Vec<String>, text: &str| {
            assert!(
                problems.iter().any(|problem| problem.contains(text)),
                "{text:?} is not among {problems:?}"
            );
        };
        // No gateway flag, or two, leaves the terminal unable to find the gateway.
        one_of(
            broken(with_backend(
                integration("codex", &["--remote", "unix:///x"], &[]),
                &["app-server"],
                &[],
            )),
            "in 0 flags",
        );
        one_of(
            broken(with_backend(
                integration(
                    "codex",
                    &["--remote", GATEWAY_PLACEHOLDER, GATEWAY_PLACEHOLDER],
                    &[],
                ),
                &["app-server"],
                &[],
            )),
            "in 2 flags",
        );
        // The placeholder is a whole element and needs a backend to name.
        one_of(
            broken(with_backend(
                integration("codex", &["--remote=unix://{gateway}"], &[]),
                &["app-server"],
                &[],
            )),
            "stands alone",
        );
        one_of(
            broken(integration(
                "codex",
                &["--remote", GATEWAY_PLACEHOLDER],
                &[],
            )),
            "declares no backend",
        );
        // The arguments are bounded and written as they stand.
        one_of(
            broken(with_backend(
                integration("codex", &[GATEWAY_PLACEHOLDER], &[]),
                &[],
                &[],
            )),
            "0 arguments",
        );
        let nine = ["a"; MAX_BACKEND_ARGUMENTS + 1];
        one_of(
            broken(with_backend(
                integration("codex", &[GATEWAY_PLACEHOLDER], &[]),
                &nine,
                &[],
            )),
            "arguments; the range is 1 to",
        );
        let long = "x".repeat(MAX_BACKEND_ARGUMENT_BYTES + 1);
        one_of(
            broken(with_backend(
                integration("codex", &[GATEWAY_PLACEHOLDER], &[]),
                &[&long],
                &[],
            )),
            "over the 256",
        );
        for argument in ["", "a\nb", "a\u{200B}b", "{gateway}", "{kr_hook}"] {
            assert!(
                !broken(with_backend(
                    integration("codex", &[GATEWAY_PLACEHOLDER], &[]),
                    &[argument],
                    &[]
                ))
                .is_empty(),
                "{argument:?} is refused"
            );
        }
        // The launching words are bare, bounded and listed once.
        for word in [
            "",
            "-x",
            "--last",
            "a b",
            "a/b",
            &"w".repeat(MAX_LAUNCHING_WORD_BYTES + 1),
        ] {
            assert!(
                !broken(with_backend(
                    integration("codex", &["--remote", GATEWAY_PLACEHOLDER], &[]),
                    &["app-server"],
                    &[word]
                ))
                .is_empty(),
                "{word:?} is refused"
            );
        }
        one_of(
            broken(with_backend(
                integration("codex", &["--remote", GATEWAY_PLACEHOLDER], &[]),
                &["app-server"],
                &["resume", "resume"],
            )),
            "more than once",
        );
    }

    #[test]
    fn kr_req_12_07_a_launch_is_plain_when_it_types_no_option_and_its_first_word_is_listed() {
        let declared = codex_like();
        let backend = declared.backend.as_ref().expect("a backend");
        for plain in [
            typed(&["codex"]),
            typed(&["codex", "resume"]),
            typed(&["codex", "fork"]),
            typed(&["codex", "resume", "0198-session"]),
        ] {
            assert_eq!(backend.refuses(&plain), None, "{plain:?}");
        }
        // Each refusal names the element or the word, so the owner is told why it ran as typed.
        let reason = |words: &[&str]| backend.refuses(&typed(words)).expect("a refusal");
        assert!(reason(&["codex", "-c", "x=y"]).contains("\"-c\" is an option"));
        assert!(reason(&["codex", "resume", "--last"]).contains("\"--last\" is an option"));
        assert!(reason(&["codex", "exec", "task"]).contains("\"exec\" is not a launch"));
        assert!(reason(&["codex", "fix the bug"]).contains("followed by \"resume\" or \"fork\""));
        // A declaration that lists no word serves the command typed alone and nothing else.
        let alone = IntegrationBackend {
            arguments: typed(&["serve"]),
            launching_words: Vec::new(),
        };
        assert_eq!(alone.refuses(&typed(&["agent"])), None);
        assert!(
            alone
                .refuses(&typed(&["agent", "login"]))
                .expect("a refusal")
                .contains("only the command typed alone")
        );
    }

    #[test]
    fn kr_req_12_07_the_statement_shows_the_backend_whole_and_what_replaces_the_gateway_flag() {
        let statement = codex_like().statement();
        assert!(
            statement.contains("\"--remote\" \"{gateway}\""),
            "the flag list shows the placeholder as written: {statement}"
        );
        assert!(
            statement.contains("\"app-server\" \"--listen\" \"stdio://\""),
            "every backend argument is in the statement, in order: {statement}"
        );
        assert!(statement.contains("{gateway} is replaced by the address of the gateway"));
        assert!(statement.contains("followed by \"resume\" or \"fork\" and no option"));
        // A declaration with no backend says nothing about one.
        assert!(
            !integration("agent", &["--flag"], &[])
                .statement()
                .contains("backend")
        );
    }
}
