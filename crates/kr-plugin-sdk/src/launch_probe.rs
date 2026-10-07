//! A package's launch probe: how a host reads the mode an application will run in, from the
//! application itself, before it starts one and when its diagnostics are read.
//!
//! An application may run in a mode a host has to know to start it well. A sandbox the application
//! provisions for itself can be of a kind that cannot start in a Windows service session, and the
//! host would otherwise find that out as a launch that hangs. The application's own diagnostic
//! command reads the mode from the same configuration the launch will use, so the package declares
//! that command here, and the host runs it and reads one string out of what it prints. No host
//! code is keyed to an application: what the host does is only what this declaration says.
//!
//! Asking for it is the `launch.probe` capability, which the owner confirms on every release,
//! because it runs the application's own executable with arguments the package chose, whenever the
//! host's diagnostics are read as well as before a launch the host starts.
//! [`LaunchProbe::statement`] renders what the declaration does, and lists every argument.
//!
//! What a declaration may say is closed:
//!
//! * The arguments are the whole of what the host passes after the options it copies, each one
//!   line of text, at least one so that the application is never started bare.
//! * The carried options are option names, each taking one value, that change which configuration
//!   the diagnostic reads, so the host copies them, with their values, from the launch's own
//!   arguments in front of the declared ones. A short name (`-c`) is read in the forms `-c value`,
//!   `-cvalue` and `-c=value`, and a long name (`--config`) in `--config value` and
//!   `--config=value`, which is how a command-line parser reads them.
//! * The mode is an RFC 6901 JSON Pointer into the JSON the diagnostic prints on standard output,
//!   and has to reach a string.
//! * The refused words are modes the application cannot run with in a Windows service session, the
//!   session the worker runs in when no person is signed in. A launch whose mode is one of them
//!   is a named failure before anything starts.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::text::{Summary, is_forbidden_text_char};

/// The most arguments a probe may pass.
pub const MAX_ARGUMENTS: usize = 8;

/// The longest one argument may be, in bytes.
pub const MAX_ARGUMENT_BYTES: usize = 256;

/// The most option names a probe may carry.
pub const MAX_CARRIED_OPTIONS: usize = 8;

/// The longest option name, in bytes.
pub const MAX_OPTION_BYTES: usize = 32;

/// The longest pointer to the mode, in bytes.
pub const MAX_POINTER_BYTES: usize = 256;

/// The most words a probe may refuse in a service session.
pub const MAX_REFUSED_WORDS: usize = 8;

/// The longest refused word, in bytes.
pub const MAX_WORD_BYTES: usize = 64;

/// The longest mode a host records, in bytes.
pub const MAX_MODE_BYTES: usize = 128;

/// What a package declares about reading the mode its application runs in.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct LaunchProbe {
    /// The arguments the host passes to the application's executable, each one element of the
    /// argument vector, after the options it carries.
    pub arguments: Vec<String>,
    /// The option names, each taking one value, that the host copies with their values from the
    /// launch's own arguments in front of `arguments`.
    pub carried_options: Vec<String>,
    /// An RFC 6901 JSON Pointer to the mode in the JSON the probe prints on standard output.
    pub mode: String,
    /// The modes the application cannot run with in a Windows service session.
    pub refused_in_service_session: Vec<String>,
    /// What the package says its probe does, in its own words.
    pub grant_statement: Summary,
}

impl LaunchProbe {
    /// Returns what the probe does, exactly.
    ///
    /// Every argument, option name and word is written as a JSON string, in order. Nothing is
    /// shortened: every declared argument, carried option name, pointer and refused word is in it.
    /// The values of carried options come from the launch and are not.
    #[must_use]
    pub fn statement(&self) -> String {
        let quoted_all = |items: &[String]| {
            items
                .iter()
                .map(|item| quoted(item))
                .collect::<Vec<_>>()
                .join(" ")
        };
        let mut statement = format!(
            "Runs the application whenever the host's diagnostics are read and before a launch the \
             host starts, with these arguments, in this order: {}.",
            quoted_all(&self.arguments)
        );
        if !self.carried_options.is_empty() {
            statement.push_str(&format!(
                " In front of them it copies these options, with their values, from the launch's \
                 own arguments: {}.",
                quoted_all(&self.carried_options)
            ));
        }
        statement.push_str(&format!(
            " It reads the mode the application runs in from {} of what the application prints.",
            quoted(&self.mode)
        ));
        if !self.refused_in_service_session.is_empty() {
            statement.push_str(&format!(
                " A launch in a Windows service session is refused when the mode is one of: {}.",
                quoted_all(&self.refused_in_service_session)
            ));
        }
        statement
    }

    /// Returns every way this declaration breaks the package contract.
    #[must_use]
    pub fn problems(&self) -> Vec<String> {
        let mut problems = Vec::new();
        if self.arguments.is_empty() {
            problems.push(
                "the probe passes no argument, which would start the application itself".to_owned(),
            );
        }
        if self.arguments.len() > MAX_ARGUMENTS {
            problems.push(format!(
                "the probe passes {} arguments, over the {MAX_ARGUMENTS} one probe may pass",
                self.arguments.len()
            ));
        }
        for (index, argument) in self.arguments.iter().enumerate() {
            if let Some(problem) = line_problem(argument, MAX_ARGUMENT_BYTES) {
                problems.push(format!("argument {index}: {problem}"));
            }
        }
        if self.carried_options.len() > MAX_CARRIED_OPTIONS {
            problems.push(format!(
                "the probe carries {} options, over the {MAX_CARRIED_OPTIONS} one probe may carry",
                self.carried_options.len()
            ));
        }
        let mut named = std::collections::BTreeSet::new();
        for option in &self.carried_options {
            if let Some(problem) = option_problem(option) {
                problems.push(problem);
            } else if !named.insert(option.as_str()) {
                problems.push(format!(
                    "the probe carries {} more than once",
                    quoted(option)
                ));
            }
        }
        if let Some(problem) = pointer_problem(&self.mode) {
            problems.push(problem);
        }
        if self.refused_in_service_session.len() > MAX_REFUSED_WORDS {
            problems.push(format!(
                "the probe refuses {} modes, over the {MAX_REFUSED_WORDS} one probe may",
                self.refused_in_service_session.len()
            ));
        }
        for word in &self.refused_in_service_session {
            if let Some(problem) = line_problem(word, MAX_WORD_BYTES) {
                problems.push(format!("refused mode {}: {problem}", quoted(word)));
            }
        }
        problems
    }

    /// Returns the arguments the host runs the application with for a launch whose own arguments
    /// are `launch`: the declared options carried from it, with their values, and then the
    /// declared arguments.
    ///
    /// Options after a bare `--` are operands and are not carried.
    ///
    /// # Errors
    ///
    /// Returns why the options cannot be carried: one the launch gives no value. A mode read
    /// without it would be a different configuration's, so the host records none.
    pub fn invocation(&self, launch: &[String]) -> Result<Vec<String>, String> {
        let mut carried = Vec::new();
        let mut arguments = launch
            .iter()
            .take_while(|argument| argument.as_str() != "--");
        while let Some(argument) = arguments.next() {
            for option in &self.carried_options {
                if argument == option {
                    let value = arguments.next().ok_or_else(|| {
                        format!("the launch passes {} with no value", quoted(option))
                    })?;
                    carried.push(argument.clone());
                    carried.push(value.clone());
                    break;
                }
                let attached = if option.starts_with("--") {
                    argument.starts_with(&format!("{option}="))
                } else {
                    argument.len() > option.len() && argument.starts_with(option.as_str())
                };
                if attached {
                    carried.push(argument.clone());
                    break;
                }
            }
        }
        carried.extend(self.arguments.iter().cloned());
        Ok(carried)
    }

    /// Reads the mode out of what the probe printed on standard output.
    ///
    /// Returns none for output that is not JSON, a pointer that reaches no string, and a string
    /// that is not at most [`MAX_MODE_BYTES`] bytes of printable text: what the host cannot read
    /// it does not guess at, and records no mode.
    #[must_use]
    pub fn read_mode(&self, output: &[u8]) -> Option<String> {
        let document: serde_json::Value = serde_json::from_slice(output).ok()?;
        let mode = document.pointer(&self.mode)?.as_str()?;
        (!mode.is_empty() && mode.len() <= MAX_MODE_BYTES && !mode.chars().any(char::is_control))
            .then(|| mode.to_owned())
    }

    /// Returns whether a launch whose mode is `mode` is refused in a Windows service session.
    #[must_use]
    pub fn refuses_in_service_session(&self, mode: &str) -> bool {
        self.refused_in_service_session
            .iter()
            .any(|refused| refused == mode)
    }
}

/// Returns why one line of text is not one a probe may hold, where it is not.
fn line_problem(text: &str, limit: usize) -> Option<String> {
    if text.is_empty() {
        return Some("it is empty".to_owned());
    }
    if text.len() > limit {
        return Some(format!("{} bytes, over the {limit} one may be", text.len()));
    }
    text.chars()
        .find(|c| is_forbidden_text_char(*c))
        .map(|character| {
            format!(
                "it carries U+{:04X}, which a person reading the declaration could not see",
                u32::from(character)
            )
        })
}

/// Returns why an option name is not one a probe may carry, where it is not.
fn option_problem(option: &str) -> Option<String> {
    if option.len() > MAX_OPTION_BYTES {
        return Some(format!(
            "the carried option {} is over the {MAX_OPTION_BYTES} bytes a name may be",
            quoted(option)
        ));
    }
    let short = option.len() == 2
        && option.starts_with('-')
        && option.as_bytes()[1].is_ascii_alphanumeric();
    let long = option.len() > 2
        && option.starts_with("--")
        && option[2..]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        && !option.ends_with('-');
    (!short && !long).then(|| {
        format!(
            "the carried option {} is neither a short name (-c) nor a long one (--config)",
            quoted(option)
        )
    })
}

/// Returns why a pointer is not an RFC 6901 JSON Pointer a probe may name, where it is not.
fn pointer_problem(pointer: &str) -> Option<String> {
    if !pointer.starts_with('/') {
        return Some(format!(
            "the mode {} is not a JSON Pointer to a member, which starts with '/'",
            quoted(pointer)
        ));
    }
    if pointer.len() > MAX_POINTER_BYTES {
        return Some(format!(
            "the mode's pointer is {} bytes, over the {MAX_POINTER_BYTES} one may be",
            pointer.len()
        ));
    }
    if pointer.chars().any(is_forbidden_text_char) {
        return Some("the mode's pointer carries text a person could not see".to_owned());
    }
    let mut characters = pointer.chars();
    while let Some(character) = characters.next() {
        if character == '~' && !matches!(characters.next(), Some('0' | '1')) {
            return Some(format!(
                "the mode {} has a '~' that is not '~0' or '~1'",
                quoted(pointer)
            ));
        }
    }
    None
}

/// Writes text as a JSON string, which shows every character it holds.
fn quoted(text: &str) -> String {
    serde_json::to_string(text).unwrap_or_else(|_| format!("{text:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn probe() -> LaunchProbe {
        LaunchProbe {
            arguments: vec!["doctor".to_owned(), "--json".to_owned()],
            carried_options: ["-c", "--config", "--enable", "--disable"]
                .iter()
                .map(|option| (*option).to_owned())
                .collect(),
            mode: "/checks/sandbox.helpers/details/sandbox backend".to_owned(),
            refused_in_service_session: vec!["elevated".to_owned()],
            grant_statement: Summary::new("Reads which sandbox the application will use")
                .expect("a literal summary"),
        }
    }

    fn words(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| (*item).to_owned()).collect()
    }

    /// The vendor's own diagnostic, as the pinned build printed it for each configuration, cut
    /// down to the check the pointer reaches and nothing else.
    fn printed(name: &str) -> Vec<u8> {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/launch_probe")
            .join(name);
        std::fs::read(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
    }

    /// The five spellings the pinned build reads as the same option (each was run against its
    /// diagnostic and read `elevated`) are each carried whole, and what the launch carries
    /// that is not a declared option is left behind.
    #[test]
    fn every_spelling_of_a_declared_option_is_carried_and_nothing_else_is() {
        let declared = probe().arguments.clone();
        for (launch, carried) in [
            (
                &["app-server", "-c", "windows.sandbox=\"elevated\""][..],
                &["-c", "windows.sandbox=\"elevated\""][..],
            ),
            (
                &["-cwindows.sandbox=\"elevated\"", "app-server"][..],
                &["-cwindows.sandbox=\"elevated\""][..],
            ),
            (
                &["-c=windows.sandbox=\"elevated\""][..],
                &["-c=windows.sandbox=\"elevated\""][..],
            ),
            (
                &["--config", "windows.sandbox=\"elevated\""][..],
                &["--config", "windows.sandbox=\"elevated\""][..],
            ),
            (
                &["--config=windows.sandbox=\"elevated\""][..],
                &["--config=windows.sandbox=\"elevated\""][..],
            ),
            (
                &["--enable", "elevated_windows_sandbox", "app-server"][..],
                &["--enable", "elevated_windows_sandbox"][..],
            ),
            (
                &["--disable=elevated_windows_sandbox"][..],
                &["--disable=elevated_windows_sandbox"][..],
            ),
            (&["app-server", "--listen", "stdio://"][..], &[][..]),
        ] {
            let launch = words(launch);
            let mut expected = words(carried);
            expected.extend(declared.clone());
            assert_eq!(probe().invocation(&launch), Ok(expected), "{launch:?}");
        }
    }

    /// An option the vendor refuses to read before its diagnostic (`-p`, which the pinned build
    /// refuses for the diagnostic and for the app server alike) is not one a package carries, so a
    /// launch that passes it contributes nothing to the probe.
    #[test]
    fn an_option_that_is_not_declared_is_not_carried() {
        let launch = words(&["-p", "work", "--profile=work", "--model", "gpt"]);
        assert_eq!(probe().invocation(&launch), Ok(probe().arguments));
    }

    /// Options after a bare `--` are operands, and an option the launch gives no value is one the
    /// probe cannot read around.
    #[test]
    fn the_end_of_options_stops_the_copy_and_a_missing_value_is_refused() {
        let launch = words(&["-c", "a=1", "--", "-c", "b=2"]);
        let mut expected = words(&["-c", "a=1"]);
        expected.extend(probe().arguments);
        assert_eq!(probe().invocation(&launch), Ok(expected));
        let without = probe()
            .invocation(&words(&["app-server", "--config"]))
            .expect_err("a value is missing");
        assert!(without.contains("--config"), "{without}");
    }

    /// The mode is the vendor's own word, read out of its own output: the three configurations the
    /// pinned build was run with print `disabled`, `elevated` and `<redacted>` there, and the host
    /// records each as printed.
    #[test]
    fn the_mode_is_read_as_the_vendor_printed_it() {
        for (name, mode) in [
            ("codex-0.155.1-doctor-none.json", "disabled"),
            ("codex-0.155.1-doctor-elevated.json", "elevated"),
            ("codex-0.155.1-doctor-unelevated.json", "<redacted>"),
        ] {
            assert_eq!(
                probe().read_mode(&printed(name)),
                Some(mode.to_owned()),
                "{name}"
            );
        }
    }

    /// What cannot be read is not guessed at: output that is not JSON, a pointer that reaches
    /// nothing or something that is not a string, and a string that is empty, over-long or holds a
    /// control character each record no mode.
    #[test]
    fn what_cannot_be_read_records_no_mode() {
        let reads = |output: &str| probe().read_mode(output.as_bytes());
        assert_eq!(reads("not json at all"), None);
        assert_eq!(reads("{}"), None);
        assert_eq!(
            reads(r#"{"checks": {"sandbox.helpers": {"details": 7}}}"#),
            None
        );
        let at = |value: &str| {
            format!(
                r#"{{"checks": {{"sandbox.helpers": {{"details": {{"sandbox backend": {value}}}}}}}}}"#
            )
        };
        assert_eq!(reads(&at("\"elevated\"")), Some("elevated".to_owned()));
        assert_eq!(reads(&at("7")), None);
        assert_eq!(reads(&at("null")), None);
        assert_eq!(reads(&at("\"\"")), None);
        assert_eq!(reads(&at("\"line\\nbreak\"")), None);
        assert_eq!(
            reads(&at(&format!("\"{}\"", "x".repeat(MAX_MODE_BYTES + 1)))),
            None
        );
        assert_eq!(
            reads(&at(&format!("\"{}\"", "x".repeat(MAX_MODE_BYTES)))),
            Some("x".repeat(MAX_MODE_BYTES))
        );
    }

    #[test]
    fn only_the_declared_words_are_refused_in_a_service_session() {
        assert!(probe().refuses_in_service_session("elevated"));
        assert!(!probe().refuses_in_service_session("disabled"));
        assert!(!probe().refuses_in_service_session("<redacted>"));
        assert!(!probe().refuses_in_service_session("Elevated"));
    }

    #[test]
    fn a_declaration_within_the_contract_has_no_problem() {
        assert_eq!(probe().problems(), Vec::<String>::new());
    }

    /// What a declaration may not say, each by itself.
    #[test]
    fn a_declaration_outside_the_contract_names_each_problem() {
        let mutated = |change: &dyn Fn(&mut LaunchProbe)| {
            let mut declared = probe();
            change(&mut declared);
            declared.problems()
        };
        let one = |problems: Vec<String>, containing: &str| {
            assert_eq!(problems.len(), 1, "{problems:?}");
            assert!(problems[0].contains(containing), "{problems:?}");
        };
        one(mutated(&|p| p.arguments.clear()), "no argument");
        one(
            mutated(&|p| p.arguments = vec!["x".to_owned(); MAX_ARGUMENTS + 1]),
            "arguments, over",
        );
        one(mutated(&|p| p.arguments[0] = String::new()), "empty");
        one(mutated(&|p| p.arguments[1] = "a\nb".to_owned()), "U+000A");
        one(
            mutated(&|p| p.arguments[1] = "x".repeat(MAX_ARGUMENT_BYTES + 1)),
            "bytes, over",
        );
        for option in [
            "c",
            "-",
            "--",
            "-cc",
            "--a=b",
            "--a b",
            "--config-",
            &format!("--{}", "x".repeat(40)),
        ] {
            one(
                mutated(&|p| p.carried_options = vec![option.to_owned()]),
                "carried option",
            );
        }
        one(
            mutated(&|p| p.carried_options = vec!["-c".to_owned(); 2]),
            "more than once",
        );
        for mode in ["", "checks/x", "/a~2b", "/a~", "/line\nbreak"] {
            one(mutated(&|p| p.mode = mode.to_owned()), "mode");
        }
        one(
            mutated(&|p| p.mode = format!("/{}", "x".repeat(MAX_POINTER_BYTES))),
            "bytes, over",
        );
        one(
            mutated(&|p| {
                p.refused_in_service_session = vec!["x".to_owned(); MAX_REFUSED_WORDS + 1]
            }),
            "refuses",
        );
        one(
            mutated(&|p| p.refused_in_service_session = vec![String::new()]),
            "empty",
        );
    }

    /// The statement lists every argument, option and word in order, and the mode.
    #[test]
    fn the_statement_lists_everything_the_host_passes() {
        assert_eq!(
            probe().statement(),
            "Runs the application whenever the host's diagnostics are read and before a launch the \
             host starts, with these arguments, in this order: \"doctor\" \"--json\". In front of \
             them it copies these options, with their values, from the launch's own arguments: \
             \"-c\" \"--config\" \"--enable\" \"--disable\". It reads the mode the application \
             runs in from \"/checks/sandbox.helpers/details/sandbox backend\" of what the \
             application prints. A launch in a Windows service session is refused when the mode is \
             one of: \"elevated\"."
        );
    }
}
