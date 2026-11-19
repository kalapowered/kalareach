//! The launch variables a package declares for its command integration.
//!
//! A command integration sets environment variables on the program it integrates (see
//! [`crate::integration`]). A package declares each one in the `launch_variables` member of its
//! connector table, which the package hash pins, with the reason a reviewer reads. The host holds
//! the declaration to syntax rules and a floor of reserved names:
//!
//! * the value is `1` or `0`, or repeats exactly a pair of
//!   [`PERMITTED_VARIABLES`](crate::integration::PERMITTED_VARIABLES);
//! * the name is two or more words of upper-case letters and digits joined by `_`, the first
//!   beginning with a letter, at most [`MAX_NAME_BYTES`] bytes, and its first word is the
//!   upper-case first word of the package's plugin name, so a package sets only the switches of
//!   its own vendor;
//! * no name has a first word in [`FLOOR_FIRST_WORDS`] or any word in [`FLOOR_WORDS`].
//!
//! These are syntax rules and a floor, not a classification: they do not establish how a program
//! interprets a variable, and [`RESIDUAL`] says so wherever a person reads the rules.

use std::collections::BTreeSet;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::connector::ConnectorManifest;
use crate::integration::{
    CommandIntegration, IntegrationVariable, PERMITTED_VARIABLES, PermittedVariable, quoted,
};
use crate::text::Summary;
use crate::version::{PackageVersion, VersionRange};

/// The SDK version the `launch_variables` member of a connector table arrived at.
pub const ARRIVAL: &str = "0.1.10";

/// The most variables one package declares.
pub const MAX_LAUNCH_VARIABLES: usize = 4;

/// The longest a declared name may be, in bytes.
pub const MAX_NAME_BYTES: usize = 64;

/// The fewest words a declared name has.
pub const MIN_NAME_WORDS: usize = 2;

/// The only values a declaration may state, apart from a pair of
/// [`PERMITTED_VARIABLES`](crate::integration::PERMITTED_VARIABLES) it repeats exactly.
pub const VALUES: [&str; 2] = ["1", "0"];

/// Words a name may not begin with, in the first position only.
pub const FLOOR_FIRST_WORDS: &[&str] = &[
    "KR", "LD", "DYLD", "BASH", "NODE", "NPM", "BUN", "DENO", "PYTHON", "PERL", "RUBY", "LUA",
    "JAVA", "JDK", "GIT", "GCONV", "SSL", "CURL", "REQUESTS", "COMPLUS", "DOTNET", "CORECLR",
    "COR",
];

/// Words a name may not hold in any position, the first included.
///
/// `CONFIG`, `DIR`, `FILE`, `ROOT`, `TMP` and `TEMP` refuse real switches, such as
/// `AMP_NO_CONFIG_SYNC`. They are kept because a value `1` or `0` can still be read as a relative
/// path (`OPENSSL_CONF=1` makes OpenSSL read a file named `1`).
pub const FLOOR_WORDS: &[&str] = &[
    "PATH",
    "HOME",
    "SHELL",
    "ENV",
    "RC",
    "INIT",
    "STARTUP",
    "PRELOAD",
    "LIBRARY",
    "LIBRARIES",
    "OPTIONS",
    "OPTS",
    "ARGS",
    "PROXY",
    "CERT",
    "CERTS",
    "CA",
    "BUNDLE",
    "TLS",
    "SSL",
    "NODE",
    "CONFIG",
    "DIR",
    "FILE",
    "ROOT",
    "TMP",
    "TEMP",
];

/// The vendor rule, as the package contract states it.
const VENDOR_RULE: &str = "the first word of the name is the upper-case first word of the \
                           package's plugin name, the part of the name before its first '-' or '.'";

/// What the floor costs, as the package contract states it.
const FLOOR_COST: &str = "CONFIG, DIR, FILE, ROOT, TMP and TEMP also refuse real switches, such as \
                          AMP_NO_CONFIG_SYNC; they stay because a value 1 or 0 can be read as a \
                          relative path (OPENSSL_CONF=1 makes OpenSSL read a file named 1)";

/// What the floor is, as the package contract states it.
const FLOOR_NOTE: &str =
    "The floor is defence in depth. It is not a statement of what a variable does.";

/// What the host's checks do not establish. Every place that states the rules carries it whole.
pub const RESIDUAL: &str = "The host checks each declared name and value against its syntax rules \
    and reserved names. These checks do not establish how a program interprets the variable. A \
    program or library can read a permitted value as a relative path or use it to select code or \
    disable checks. A program that starts through a committed integration receives the declared \
    variables. Its child processes can inherit them. An invocation that runs as typed receives no \
    variables added by this integration.";

/// One environment variable a package's command integration sets, with the reason a reviewer
/// reads.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub struct LaunchVariable {
    /// The variable's name.
    pub name: String,
    /// The value the integration sets it to.
    pub value: String,
    /// Why the package needs the variable, in the package's own words. A reviewer reads it; the
    /// owner's statement does not carry it.
    pub reason: Summary,
}

/// What a refusal of a declaration is about. [`Self::name`] is the name a report carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LaunchVariableProblem {
    /// The member is present and lists no entry.
    Empty,
    /// The member lists more than [`MAX_LAUNCH_VARIABLES`] entries.
    TooMany,
    /// A name is not words of upper-case letters and digits joined by `_` of the shape above.
    NameShape,
    /// A name does not begin with the plugin name's upper-case first word.
    NameNotTheVendor,
    /// A name begins with a word of [`FLOOR_FIRST_WORDS`].
    NameReservedFirstWord,
    /// A name holds a word of [`FLOOR_WORDS`].
    NameReservedWord,
    /// Two entries have one name.
    NameTwice,
    /// A value is not `1` or `0` or a pair the contract lists.
    ValueNotPermitted,
    /// A reason is only spaces.
    ReasonMissing,
    /// The table declares variables and the manifest declares no command integration.
    WithoutIntegration,
    /// An entry that no variable of the command integration equals.
    Unused,
    /// A variable of the command integration that no entry declares and the compiled pair does not
    /// cover.
    NotDeclared,
}

impl LaunchVariableProblem {
    /// The name the report carries.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Empty => "launch_variables.empty",
            Self::TooMany => "launch_variables.too_many",
            Self::NameShape => "launch_variables.name_shape",
            Self::NameNotTheVendor => "launch_variables.name_not_the_vendor",
            Self::NameReservedFirstWord => "launch_variables.name_reserved_first_word",
            Self::NameReservedWord => "launch_variables.name_reserved_word",
            Self::NameTwice => "launch_variables.name_twice",
            Self::ValueNotPermitted => "launch_variables.value_not_permitted",
            Self::ReasonMissing => "launch_variables.reason_missing",
            Self::WithoutIntegration => "launch_variables.without_integration",
            Self::Unused => "launch_variables.unused",
            Self::NotDeclared => "launch_variables.not_declared",
        }
    }

    /// Whether the refusal is about the connector table alone. The others are about the table and
    /// the manifest's integration together.
    #[must_use]
    pub const fn is_about_the_table(self) -> bool {
        !matches!(
            self,
            Self::WithoutIntegration | Self::Unused | Self::NotDeclared
        )
    }
}

/// One way a declaration breaks the package contract.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Problem {
    /// Which refusal.
    pub name: LaunchVariableProblem,
    /// What it found, in words.
    pub detail: String,
}

impl Problem {
    fn new(name: LaunchVariableProblem, detail: String) -> Self {
        Self { name, detail }
    }

    /// The text a finding carries: the refusal's name, then what it found.
    #[must_use]
    pub fn message(&self) -> String {
        format!("{}: {}", self.name.name(), self.detail)
    }
}

/// What a package check knows about the variables a command integration may set.
///
/// It is built once from the package's `sdk_range` and connector table, and the integration's
/// check asks it about each variable. It has one constructor, so no caller can build a state the
/// package check would not.
#[derive(Clone, Copy, Debug)]
pub struct LaunchPermits<'a> {
    declared: Option<&'a [LaunchVariable]>,
    compiled_pair: bool,
}

impl<'a> LaunchPermits<'a> {
    /// Returns what a package with this `sdk_range` and this connector table (none, for a package
    /// that ships no table) permits an integration to set.
    ///
    /// The pairs of [`PERMITTED_VARIABLES`] are permitted only to a release that declares no
    /// `launch_variables` and whose range is written in release versions only and admits an SDK
    /// version before [`ARRIVAL`]: such a release was written before the member existed. A range
    /// this check cannot decide never gets them.
    ///
    /// The pairs exist for the Gemini CLI releases that set `GEMINI_CLI_NO_RELAUNCH=true` undeclared:
    /// today the installed copies and published releases of 0.4.0 (`>=0.1.2, <0.2.0`) and 0.5.0
    /// (`>=0.1.3, <0.2.0`), which the seed never replaces and the worker checks again at each
    /// read. Remove them when no supported release's range admits an SDK version before
    /// [`ARRIVAL`], or when support for those immutable releases ends.
    #[must_use]
    pub fn for_package(range: &VersionRange, connector: Option<&'a ConnectorManifest>) -> Self {
        let declared = connector.and_then(|table| table.launch_variables.as_deref());
        let compiled_pair = declared.is_none()
            && !range.has_a_prerelease()
            && PackageVersion::parse(ARRIVAL)
                .is_ok_and(|arrival| range.admits_a_version_below(&arrival));
        Self {
            declared,
            compiled_pair,
        }
    }

    /// Whether the package may set `variable`: it declares that exact name and value, or the pair
    /// is a compiled one this package is held to.
    #[must_use]
    pub fn allows(&self, variable: &IntegrationVariable) -> bool {
        let same = |name: &str, value: &str| name == variable.name && value == variable.value;
        self.declared
            .is_some_and(|entries| entries.iter().any(|entry| same(&entry.name, &entry.value)))
            || (self.compiled_pair
                && PERMITTED_VARIABLES
                    .iter()
                    .any(|pair| same(pair.name, pair.value)))
    }
}

/// Returns the pairs of [`PERMITTED_VARIABLES`], written as the statement writes a variable.
#[must_use]
pub fn compiled_pairs() -> String {
    PERMITTED_VARIABLES
        .iter()
        .map(|pair: &PermittedVariable| format!("{}={}", pair.name, quoted(pair.value)))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Returns the upper-case first word of a plugin name: the part before its first `-` or `.`.
#[must_use]
pub fn vendor_word(plugin_name: &str) -> String {
    plugin_name
        .split(['-', '.'])
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase()
}

/// Whether `value` is one a declaration may state for `name`.
fn value_permitted(name: &str, value: &str) -> bool {
    VALUES.contains(&value)
        || PERMITTED_VARIABLES
            .iter()
            .any(|pair| pair.name == name && pair.value == value)
}

/// Whether `name` has the shape of a declared name: two or more non-empty words of upper-case
/// ASCII letters and digits joined by `_`, the first beginning with a letter, at most
/// [`MAX_NAME_BYTES`] bytes.
fn has_the_shape(name: &str) -> bool {
    let words: Vec<&str> = name.split('_').collect();
    name.len() <= MAX_NAME_BYTES
        && words.len() >= MIN_NAME_WORDS
        && words.iter().all(|word| {
            !word.is_empty()
                && word
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
        })
        && words[0]
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_uppercase())
}

/// Returns every way the declaration breaks the package contract, for a package named
/// `plugin_name` whose manifest has `integration`.
///
/// `declared` is the connector table's `launch_variables` member: absent, present and empty, and
/// present with entries are three cases. An explicit `null` in the table's JSON reads as absent.
/// The order of the checks of a name is the shape, then the vendor word, then the first-word floor,
/// then the any-word floor: a failed shape skips the others, since there is no word to read, and
/// every other one that applies is reported.
#[must_use]
pub fn problems(
    declared: Option<&[LaunchVariable]>,
    plugin_name: &str,
    integration: Option<&CommandIntegration>,
) -> Vec<Problem> {
    let Some(entries) = declared else {
        return Vec::new();
    };
    let mut problems = Vec::new();
    if entries.is_empty() {
        problems.push(Problem::new(
            LaunchVariableProblem::Empty,
            "the table declares launch_variables with no entry; leave the member out to declare \
             none"
                .to_owned(),
        ));
    }
    if entries.len() > MAX_LAUNCH_VARIABLES {
        problems.push(Problem::new(
            LaunchVariableProblem::TooMany,
            format!(
                "the table declares {} launch variables, over the {MAX_LAUNCH_VARIABLES} a \
                 package may declare",
                entries.len()
            ),
        ));
    }
    let vendor = vendor_word(plugin_name);
    let mut named = BTreeSet::new();
    for entry in entries {
        problems.extend(name_problems(&entry.name, plugin_name, &vendor));
        if !named.insert(entry.name.as_str()) {
            problems.push(Problem::new(
                LaunchVariableProblem::NameTwice,
                format!("the table declares {} more than once", quoted(&entry.name)),
            ));
        }
        if !value_permitted(&entry.name, &entry.value) {
            problems.push(Problem::new(
                LaunchVariableProblem::ValueNotPermitted,
                format!(
                    "{}={} is not a value a package may declare: a declared value is 1 or 0, or \
                     one of the pairs the package contract lists ({})",
                    quoted(&entry.name),
                    quoted(&entry.value),
                    compiled_pairs()
                ),
            ));
        }
        if entry.reason.as_str().trim().is_empty() {
            problems.push(Problem::new(
                LaunchVariableProblem::ReasonMissing,
                format!(
                    "the reason for {} is blank; a reviewer reads it",
                    quoted(&entry.name)
                ),
            ));
        }
    }
    if entries.is_empty() {
        return problems;
    }
    match integration {
        None => problems.push(Problem::new(
            LaunchVariableProblem::WithoutIntegration,
            "the table declares launch variables and the manifest declares no command \
             integration, so nothing sets them"
                .to_owned(),
        )),
        Some(integration) => {
            for entry in entries {
                let set = integration
                    .variables
                    .iter()
                    .any(|variable| variable.name == entry.name && variable.value == entry.value);
                if !set {
                    problems.push(Problem::new(
                        LaunchVariableProblem::Unused,
                        format!(
                            "the table declares {}={} and no variable of the command integration \
                             equals it",
                            quoted(&entry.name),
                            quoted(&entry.value)
                        ),
                    ));
                }
            }
        }
    }
    problems
}

/// Returns every way one declared name breaks the rules, in the order they are checked.
fn name_problems(name: &str, plugin_name: &str, vendor: &str) -> Vec<Problem> {
    if !has_the_shape(name) {
        return vec![Problem::new(
            LaunchVariableProblem::NameShape,
            format!(
                "{} is not a launch variable name: a name is two or more non-empty words of \
                 upper-case letters and digits joined by '_', the first beginning with a letter, \
                 at most {MAX_NAME_BYTES} bytes",
                quoted(name)
            ),
        )];
    }
    let mut problems = Vec::new();
    let first = name.split('_').next().unwrap_or_default();
    if first != vendor {
        let rest = if vendor
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_digit())
        {
            "a name cannot begin with a digit, so a package whose plugin name begins with one \
             declares no launch variable"
        } else {
            "a package declares only variables that begin with that word"
        };
        problems.push(Problem::new(
            LaunchVariableProblem::NameNotTheVendor,
            format!(
                "{} does not begin with {vendor}, the upper-case first word of the plugin name \
                 {plugin_name}; {rest}",
                quoted(name)
            ),
        ));
    }
    if FLOOR_FIRST_WORDS.contains(&first) {
        problems.push(Problem::new(
            LaunchVariableProblem::NameReservedFirstWord,
            format!(
                "{} begins with {first}, a word the package contract's floor refuses as a first \
                 word",
                quoted(name)
            ),
        ));
    }
    if let Some(word) = name.split('_').find(|word| FLOOR_WORDS.contains(word)) {
        problems.push(Problem::new(
            LaunchVariableProblem::NameReservedWord,
            format!(
                "{} holds {word}, a word the package contract's floor refuses in any place",
                quoted(name)
            ),
        ));
    }
    problems
}

/// The rules as the package contract publishes them, under
/// `command_integration.launch_variable_rules`.
#[must_use]
pub fn rules() -> Value {
    json!({
        "values": VALUES,
        "max_entries": MAX_LAUNCH_VARIABLES,
        "max_name_bytes": MAX_NAME_BYTES,
        "min_words": MIN_NAME_WORDS,
        "vendor": VENDOR_RULE,
        "floor_first_words": FLOOR_FIRST_WORDS,
        "floor_words": FLOOR_WORDS,
        "floor_cost": FLOOR_COST,
        "floor_note": FLOOR_NOTE,
        "residual": RESIDUAL,
    })
}
