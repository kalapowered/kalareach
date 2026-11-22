//! The plan file: what the report runs and reads in one repository, as data.
//!
//! Each repository keeps its plan at `conformance/plan.toml` (or names another file with `--plan`),
//! and `map` and `run` read it through this loader and nowhere else. A plan that is missing or
//! refused stops the program with exit status 2 before anything runs, and the program never falls
//! back to another plan.
//!
//! The file is data. It names argument vectors and never a shell string. A group is a name the
//! plan chooses; no decision is taken from the name of a group. Each decision the report takes
//! from a selection of groups is derived from the steps the selection holds, by the functions of
//! [`Plan`] that say so.
//!
//! A key whose absence means "none" is optional (`scripts`, `lane_directories`, the `[typescript]`
//! lists and `[terminal_profile]`). The Rust manifests and the ignored-run policy are required: a
//! plan states them, and no default stands in for a repository's own values.
//!
//! A step runs in its `directory` with the plan's `[env]` and its own `env`. A step that reads a
//! file names it as its `output` and passes it to its tool as `{output}`; the report reads that
//! file and no word of the command.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};
use std::process::Command;

use serde::Deserialize;

use crate::plan::{ApplicationsPlan, Platform, Reading, Step, Tests};

/// Where a repository keeps its plan, relative to its root.
pub const PLAN_PATH: &str = "conformance/plan.toml";

/// The programs a step runs: what the repositories' workflows run today.
pub const PROGRAMS: [&str; 5] = ["cargo", "pnpm", "node", "bash", "python3"];

/// The placeholders a command, a variable's value or an output may hold, each as it is written
/// between braces: the evidence directory, the run's scratch directory, the repository, and the
/// step's own output.
pub const PLACEHOLDERS: [&str; 4] = ["evidence", "scratch", "root", "output"];

/// Why a plan was not accepted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal(pub String);

impl std::fmt::Display for Refusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// A name with the reason that goes with it.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reasoned {
    /// What it names: a test filter or a test.
    pub name: String,
    /// Why.
    pub reason: String,
}

/// How a step's output is read, as the file names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReadingKind {
    /// `cargo test` output.
    Cargo,
    /// A build whose success is all there is to record.
    Build,
    /// A package's `test` script, reporting in JSON.
    Vitest,
    /// A phone application's unit tests.
    Lane,
    /// A command whose exit status is all there is to record: a set-up step reads so.
    Exit,
}

/// What a step's skip list is taken from, other than the file.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SkipsFrom {
    /// The programs the run left out of the application matrix.
    Applications,
}

/// One command of the plan, as the file holds it.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StepDef {
    /// Its name, unique in the plan.
    pub id: String,
    /// Its group, one of the plan's.
    pub group: String,
    /// What it runs, in a few words.
    pub what: String,
    /// The platforms it runs on.
    pub platforms: Vec<Platform>,
    /// The program and its arguments, without the words the loader adds (see [`expand`]).
    pub command: Vec<String>,
    /// How its output is read.
    pub reading: ReadingKind,
    /// For a `vitest` reading, the package's directory, relative to the repository.
    #[serde(default)]
    pub package: Option<String>,
    /// For a `lane` reading, how the lane's tool reports the tests it ran.
    #[serde(default)]
    pub lane: Option<Tests>,
    /// Variables it reads from the environment the report was started in, which must be set.
    #[serde(default)]
    pub needs: Vec<String>,
    /// Whether it sets up what later steps need: the report records only its exit status, and its
    /// reading is `exit`. A step that names it in `after` is not run when it failed.
    #[serde(default)]
    pub setup: bool,
    /// The set-up steps that run before it, by `id`: each is an earlier step of the plan, on every
    /// platform this step is on. A selection that holds this step holds them too, whatever their
    /// groups.
    #[serde(default)]
    pub after: Vec<String>,
    /// The directory it runs in, relative to the repository; the repository's root when absent. The
    /// build, the listing of the tests and the run all use it. A `cargo` step's directory is a
    /// workspace root that `[rust] manifests` names, whether it names the directory or not. It is a
    /// literal path: it holds no placeholder.
    #[serde(default)]
    pub directory: Option<String>,
    /// Variables it is run with besides the plan's `[env]`; its value of a name replaces the plan's.
    /// A value may hold the placeholders.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// The one file it writes for the report to read, below `{evidence}/conformance/`: a directory
    /// for a JUnit lane. Its command or one of its variables holds `{output}`, and a Vitest or lane
    /// reading names one.
    #[serde(default)]
    pub output: Option<String>,
    /// A name filter the command passes to the test binaries, and why tests outside it are not run.
    #[serde(default)]
    pub filter: Option<Reasoned>,
    /// Tests the command leaves out by name, each with its reason.
    #[serde(default)]
    pub skips: Vec<Reasoned>,
    /// Where more skips come from at run time.
    #[serde(default)]
    pub skips_from: Option<SkipsFrom>,
    /// The most seconds the step may take, from its start to its end: its build and the listing of
    /// its tests count. The report ends the step's processes when they are spent, so a step with a
    /// limit does not run on Windows. A whole number of seconds from 1 to [`MOST_SECONDS`].
    #[serde(default)]
    pub timeout: Option<i64>,
    /// The `id` of the `[[budget]]` the step spends from, with the other steps that name it.
    #[serde(default)]
    pub budget: Option<String>,
    /// What the step took, in seconds, on each platform it runs on, when it was last measured. The
    /// report cuts a platform's plan into parts of nearly equal time by these when every step that
    /// the cut places states one for that platform. A whole number of seconds from 1 to
    /// [`MOST_SECONDS`], under the name of a platform the step runs on.
    #[serde(default)]
    pub weight: BTreeMap<String, i64>,
    /// The run and the date the `weight` was measured at, which a later reader refreshes it from.
    /// Required with a `weight`, and not given without one.
    #[serde(default)]
    pub weighed: Option<String>,
}

/// The most seconds a step's `timeout` or a budget's `seconds` may be: a day.
pub const MOST_SECONDS: i64 = 86_400;

/// A time that several steps share: the steps that name it spend it in the order of the plan, and the
/// report ends the process of the step that is running when it is spent.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Budget {
    /// Its name, unique in the plan: ASCII letters, digits, `-` and `_`.
    pub id: String,
    /// Its time, in whole seconds from 1 to [`MOST_SECONDS`].
    pub seconds: i64,
}

/// A package no step runs on one platform, and why.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExcludedPackage {
    /// The platform.
    pub platform: Platform,
    /// The package.
    pub package: String,
    /// Why.
    pub reason: String,
}

/// Why a group runs nothing on one platform.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupAbsent {
    /// The group.
    pub group: String,
    /// The platform.
    pub platform: Platform,
    /// Why.
    pub reason: String,
    /// Whether this reason also explains a Rust target that no step ran.
    #[serde(default)]
    pub explains_unrun_rust: bool,
}

/// Why a test no step runs is not run.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Unrun {
    /// A benchmark target that no step of the selection covers, before the sentence that says so.
    pub bench: String,
    /// A TypeScript test that no step runs, when no group says why.
    pub typescript: String,
}

/// A data file of cases that names the rows it covers, and the tests that run its cases.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseTable {
    /// The files, relative to the repository: `*` stands for one path component.
    pub files: String,
    /// The package whose tests run them.
    pub package: String,
    /// The test target.
    pub target: String,
    /// The tests, by name.
    pub tests: Vec<String>,
}

/// How the keyed tests of one target that an ordinary run leaves out (`#[ignore]`) get run.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IgnoredRun {
    /// The package.
    pub package: String,
    /// The target, as the flag that selects it: `--lib`, `--test fence`, `--bench input_latency`.
    pub target: String,
    /// The tests this covers, by the names the map gives them (module path included); every keyed
    /// ignored test of the target when empty. A name that ends in `::` is a module.
    #[serde(default)]
    pub cases: Vec<String>,
    /// Where they run.
    pub runs: Runs,
}

/// Where tests that an ordinary run leaves out are run. The witness lines are literal comparison
/// data: they are never expanded.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Runs {
    /// A command in a file of the repository, given as the whole of its line: the file has to hold
    /// a line with exactly these words (the continuations of a line joined, the white space made
    /// single, a comment at its end left out). If the line selects with `--exact`, it names each
    /// test the entry covers.
    Command {
        /// The file, relative to the repository.
        file: String,
        /// The line.
        line: String,
    },
    /// A command as for `Command` whose test names are not on its own line, because a call or a
    /// list passes them: each test the entry covers is named on a line that begins with the first
    /// of `names_with` (after an opening quote) and holds the rest.
    Supplied {
        /// The file, relative to the repository.
        file: String,
        /// The line.
        line: String,
        /// The words each line that names a test holds, the first of them at its start.
        names_with: Vec<String>,
    },
    /// A step of this plan on Linux, given as the whole of its command: some step has exactly these
    /// words and, if they include `--exact`, names each test the entry covers.
    Plan {
        /// The words of the step, joined with single spaces.
        line: String,
    },
    /// A process the target's own tests start: the file names each helper test in its code.
    Helper {
        /// The file of the target, relative to the repository.
        file: String,
    },
    /// No step of this repository runs them: they are run by hand.
    ByHand {
        /// Why no step runs them.
        why: String,
    },
    /// Nothing runs them, by hand or otherwise: a case that cannot run yet.
    Nowhere {
        /// Why nothing runs them.
        why: String,
    },
}

/// A set of files whose tests another toolchain builds. The report reads their keys. It runs and
/// reads the tests of a lane that names how its tool reports them; the others it shows as not
/// built.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lane {
    /// The group whose selection selects the lane's places, when the lane has one.
    #[serde(default)]
    pub group: Option<String>,
    /// The files, relative to the repository: `*` stands for one path component and `**` for any
    /// number of them.
    pub files: String,
    /// Why this run does not show their results: where they run instead.
    pub reason: String,
    /// How the lane's tool reports the tests it ran, for a lane a step reads.
    #[serde(default)]
    pub reads: Option<Tests>,
}

/// Section 27's terminal conformance matrix, as the report records it.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Terminals {
    /// The terminals.
    pub names: Vec<String>,
    /// Why a terminal of the matrix is not run by this report.
    pub reason: String,
}

/// The TypeScript packages and what steers how they are read. A key that is absent names nothing:
/// no compiler directory and no directory left out.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TypeScript {
    /// Their directories, relative to the repository.
    pub packages: Vec<String>,
    /// The directories of the repository whose own `node_modules` holds the compiler that reads
    /// the packages; the first that does is used. `--typescript-compiler` replaces them.
    #[serde(default)]
    pub compiler_from: Vec<String>,
    /// The names of the directories that no TypeScript file is read below, at any depth.
    #[serde(default)]
    pub skip_directories: Vec<String>,
}

/// The Rust workspaces.
#[derive(Clone, Debug, PartialEq, Eq, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rust {
    /// The manifests `cargo metadata` reads, one workspace each, relative to the repository. Empty
    /// when the repository has no Rust.
    pub manifests: Vec<String>,
}

/// Whether a tree is held to its ignored-run entries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IgnoredPolicy {
    /// `true`: every keyed test an ordinary run leaves out is run by an entry, and every entry is
    /// still where it says. `false`: the check is off for this tree.
    pub held: bool,
}

/// The file that holds the terminal profile the host presents.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TerminalProfileFile {
    /// The file, relative to the repository.
    pub path: String,
}

/// The application matrix's lock.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Applications {
    /// The lock file, relative to the repository.
    pub lock: String,
}

/// The plan of one repository.
#[derive(Clone, Debug, PartialEq, Eq, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    /// The repository's name in the result.
    pub repository: String,
    /// The plan's groups, in the order a full run runs them.
    pub groups: Vec<String>,
    /// The Rust workspaces.
    pub rust: Rust,
    /// Whether the tree is held to its ignored-run entries.
    #[serde(rename = "ignored_runs")]
    pub ignored_policy: IgnoredPolicy,
    /// Whether every full run lists the rows of the specification's tables.
    #[serde(default)]
    pub list_table_rows: bool,
    /// The directories whose files are read for the rows they name, as scripts, relative to the
    /// repository. Absent means none: no script is read.
    #[serde(default)]
    pub scripts: Vec<String>,
    /// The directories whose Kotlin, Swift and Java files are read for the lanes, relative to the
    /// repository. Absent means none: no lane file is read.
    #[serde(default)]
    pub lane_directories: Vec<String>,
    /// Variables every step is run with; a step's own `env` replaces a value of the same name. A
    /// value may hold `{evidence}`, `{scratch}` and `{root}`.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// The time budgets that steps share.
    #[serde(default, rename = "budget")]
    pub budgets: Vec<Budget>,
    /// The steps, in the order every platform runs them.
    #[serde(default, rename = "step")]
    pub steps: Vec<StepDef>,
    /// The packages left out of a platform's plan.
    #[serde(default, rename = "excluded_package")]
    pub excluded_packages: Vec<ExcludedPackage>,
    /// Why a group runs nothing on a platform.
    #[serde(default, rename = "group_absent")]
    pub group_absent: Vec<GroupAbsent>,
    /// Why a test no step runs is not run.
    pub unrun: Unrun,
    /// The case tables kept as data files.
    #[serde(default, rename = "case_table")]
    pub case_tables: Vec<CaseTable>,
    /// The steps that run the keyed tests an ordinary run leaves out.
    #[serde(default, rename = "ignored_run")]
    pub ignored_runs: Vec<IgnoredRun>,
    /// The lanes.
    #[serde(default, rename = "lane")]
    pub lanes: Vec<Lane>,
    /// The terminal matrix, when the plan records one.
    #[serde(default)]
    pub terminals: Option<Terminals>,
    /// The TypeScript packages, when the repository has any.
    #[serde(default)]
    pub typescript: Option<TypeScript>,
    /// The application matrix's lock, when the plan has a step that skips from it.
    #[serde(default)]
    pub applications: Option<Applications>,
    /// The file that holds the terminal profile, when the plan records one: a result of a plan
    /// without it leaves the profile out.
    #[serde(default)]
    pub terminal_profile: Option<TerminalProfileFile>,
}

/// What the placeholders stand for in one run, each as a path with forward slashes.
#[derive(Clone, Copy, Debug, Default)]
pub struct Values<'a> {
    /// The evidence directory.
    pub evidence: &'a str,
    /// The repository.
    pub root: &'a str,
    /// The run's scratch directory.
    pub scratch: &'a str,
}

impl<'a> Values<'a> {
    /// The values of a run whose plan names only its evidence directory.
    #[must_use]
    pub fn evidence(evidence: &'a str) -> Self {
        Self {
            evidence,
            root: "",
            scratch: "",
        }
    }
}

/// `text` with each placeholder given its value. The text is read once, so a value that holds a
/// brace is left as it is. `output` is the step's own, already expanded.
fn fill(text: &str, values: &Values<'_>, output: &str) -> String {
    let mut filled = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(open) = rest.find('{') {
        filled.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        let value = after.find('}').and_then(|close| {
            let value = match &after[..close] {
                "evidence" => values.evidence,
                "scratch" => values.scratch,
                "root" => values.root,
                "output" => output,
                _ => return None,
            };
            Some((value, close))
        });
        if let Some((value, close)) = value {
            filled.push_str(value);
            rest = &after[close + 1..];
        } else {
            filled.push('{');
            rest = after;
        }
    }
    filled.push_str(rest);
    filled
}

/// Whether `text` holds a placeholder of the plan, as the plan wrote it.
fn holds_placeholder(text: &str) -> bool {
    ["{evidence}", "{scratch}", "{root}", "{output}"]
        .iter()
        .any(|placeholder| text.contains(placeholder))
}

/// The step's output with its placeholders given their values.
fn output_of(definition: &StepDef, values: &Values<'_>) -> Option<String> {
    definition
        .output
        .as_ref()
        .map(|output| fill(output, values, ""))
}

/// The variables a step is run with on `platform`: the plan's, then its own, which replace them
/// where `platform` takes the names as one variable, each value with its placeholders given their
/// values. They come in the order of their names. The second list names the variables whose value
/// holds a placeholder, whether or not the value given to it differs.
fn environment_of(
    platform: Platform,
    plan: &Plan,
    definition: &StepDef,
    values: &Values<'_>,
    output: &str,
) -> (Vec<(String, String)>, Vec<String>) {
    let mut merged: Vec<(&String, &String)> = plan.env.iter().collect();
    for (name, value) in &definition.env {
        merged.retain(|(held, _)| !platform.same_variable(held, name));
        merged.push((name, value));
    }
    merged.sort_by(|a, b| a.0.cmp(b.0));
    let mut placeholders = Vec::new();
    let environment = merged
        .into_iter()
        .map(|(name, value)| {
            if holds_placeholder(value) {
                placeholders.push(name.clone());
            }
            (name.clone(), fill(value, values, output))
        })
        .collect();
    (environment, placeholders)
}

/// The components of a relative path, joined with forward slashes: empty for the root.
fn normal(path: &Path) -> String {
    path.components()
        .filter_map(|part| match part {
            Component::Normal(name) => name.to_str(),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// The words the loader adds to a step's command, and the words of its expansion: the command with
/// the placeholders given their values.
///
/// A `cargo test` that leaves each test's output captured is given `--show-output` after a `--`
/// that is added when the command has none. One that shows the output as it is written, with
/// `--nocapture`, is left as it is, and a plan file does not write `--show-output` itself. Then each
/// of `skips` is added as `--skip <name>`, after a `--` when the command still has none. A `--skip`
/// the command already holds stays as it is written.
#[must_use]
pub fn expand(
    definition: &StepDef,
    values: &Values<'_>,
    applications_skips: &[Reasoned],
) -> Vec<String> {
    let output = output_of(definition, values).unwrap_or_default();
    let mut words: Vec<String> = definition
        .command
        .iter()
        .map(|word| fill(word, values, &output))
        .collect();
    if words.first().map(String::as_str) == Some("cargo")
        && words.get(1).map(String::as_str) == Some("test")
        && definition.reading == ReadingKind::Cargo
        && !words.iter().any(|word| word == "--nocapture")
    {
        if !words.iter().any(|word| word == "--") {
            words.push("--".to_owned());
        }
        words.push("--show-output".to_owned());
    }
    for skip in definition.skips.iter().chain(applications_skips) {
        if !words.iter().any(|word| word == "--") {
            words.push("--".to_owned());
        }
        words.push("--skip".to_owned());
        words.push(skip.name.clone());
    }
    words
}

fn line_of(text: &str, offset: usize) -> usize {
    text[..offset.min(text.len())]
        .bytes()
        .filter(|byte| *byte == b'\n')
        .count()
        + 1
}

/// Whether a reason says nothing.
fn blank(text: &str) -> bool {
    text.trim().is_empty()
}

/// The placeholder in `word` that the plan may not use, if any.
fn placeholder_refused(word: &str) -> Option<String> {
    let mut rest = word;
    while let Some(open) = rest.find('{') {
        let after = &rest[open + 1..];
        let Some(close) = after.find('}') else {
            return Some("a `{` that no `}` closes".to_owned());
        };
        let name = &after[..close];
        if !PLACEHOLDERS.contains(&name) {
            return Some(format!("`{{{name}}}`"));
        }
        rest = &after[close + 1..];
    }
    None
}

/// Whether `name` is the name of an environment variable: letters, digits and underscores, not
/// beginning with a digit.
fn variable_name(name: &str) -> bool {
    let mut characters = name.chars();
    characters
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic() || first == '_')
        && characters.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Why a plan may not give the variable `name`, when the report sets it for each step: the step
/// would run without what the report gives it. A name is the same in any case, since Windows takes
/// it so.
fn set_by_the_report(name: &str) -> Option<&'static str> {
    let upper = name.to_ascii_uppercase();
    if upper == "KR_TEST_ARTIFACTS_DIR" {
        Some(
            "the tests write their records and figures there and the report reads them from the \
             evidence directory",
        )
    } else if upper == "CARGO_TERM_COLOR" {
        Some("the report reads Cargo's output and sets it to `never`")
    } else if [
        crate::run::STEP_VARIABLE,
        crate::run::RECORDS_VARIABLE,
        crate::run::OWN_HARNESS_VARIABLE,
    ]
    .contains(&upper.as_str())
    {
        Some("the report's own program reads it while it lists and records the tests")
    } else if upper.starts_with("CARGO_TARGET_") && upper.ends_with("_RUNNER") {
        Some("the report sets it to its own program, which runs each test binary")
    } else {
        None
    }
}

/// The name of `table` that sorts before `name` and differs from it only by case, so that a pair is
/// named once, in the order the table keeps it. A name is the same in any case on Windows, and a
/// plan that holds two of them does not say which value the variable has.
fn differs_only_by_case<'a>(table: &'a BTreeMap<String, String>, name: &str) -> Option<&'a String> {
    table
        .keys()
        .find(|held| held.as_str() < name && held.eq_ignore_ascii_case(name))
}

/// Whether `part` is a name Windows keeps for a device: `con`, `prn`, `aux`, `nul`, `com1` to `com9`
/// or `lpt1` to `lpt9`, in any case, alone or followed by a dot and any extension.
fn windows_device(part: &str) -> bool {
    let stem = part
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    match stem.as_bytes() {
        b"con" | b"prn" | b"aux" | b"nul" => true,
        [b'c', b'o', b'm', digit] | [b'l', b'p', b't', digit] => matches!(digit, b'1'..=b'9'),
        _ => false,
    }
}

/// The parts of `output` below `{evidence}/conformance/`, in lower case, or why it is not a place a
/// step may write its output, in words that follow the output's name. Each part holds ASCII
/// letters, digits, `.`, `-` and `_` and no more, is not empty, `.` or `..` and does not end with a
/// dot or a space, is not a name Windows keeps for a device, and the first is not the report's own
/// directory of logs or its result. The grammar is what every file system of the platforms agrees
/// on, and so a name in ASCII lower case is the one name each takes it for: the file systems of
/// macOS and Windows name one file by `Logs` and `logs`, and Windows by `x` and `x.` too, and a
/// file system may take a letter outside ASCII for another.
fn output_parts(output: &str) -> Result<Vec<String>, String> {
    let Some(rest) = output.strip_prefix("{evidence}/conformance/") else {
        return Err("which is not below `{evidence}/conformance/`".to_owned());
    };
    if rest.contains(['{', '}', '\\']) {
        return Err("which holds a placeholder or a backslash".to_owned());
    }
    let parts: Vec<&str> = rest.split('/').collect();
    if parts.iter().any(|part| matches!(*part, "" | "." | "..")) {
        return Err("which holds `..`, `.` or an empty part".to_owned());
    }
    if parts.iter().any(|part| part.ends_with(['.', ' '])) {
        return Err("which holds a part that ends with a dot or a space".to_owned());
    }
    if let Some(part) = parts.iter().find(|part| {
        !part
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
    }) {
        return Err(format!(
            "whose part `{part}` holds a character outside the portable set: letters, digits, `.`, \
             `-` and `_`"
        ));
    }
    if let Some(part) = parts.iter().find(|part| windows_device(part)) {
        return Err(format!(
            "whose part `{part}` is a name that Windows keeps for a device: `con`, `prn`, `aux`, \
             `nul`, `com1` to `com9` and `lpt1` to `lpt9`, with or without an extension"
        ));
    }
    let parts: Vec<String> = parts.into_iter().map(str::to_ascii_lowercase).collect();
    if matches!(parts[0].as_str(), "logs" | "result.json") {
        return Err("which is the report's own: its logs and its result are there".to_owned());
    }
    Ok(parts)
}

/// The words of `command` that name a script the program runs.
fn script_operands(command: &[String]) -> Vec<&str> {
    let operands = command.iter().skip(1).filter(|word| !word.starts_with('-'));
    match command.first().map(String::as_str) {
        Some("bash" | "python3") => operands.take(1).map(String::as_str).collect(),
        Some("node") => {
            if command.iter().any(|word| word == "--test") {
                operands.map(String::as_str).collect()
            } else {
                operands.take(1).map(String::as_str).collect()
            }
        }
        _ => Vec::new(),
    }
}

/// Why `operand` does not name a place inside the repository, or `None`: it is a relative path that
/// is not empty, holds no `..` and no pattern character (`*`, `?`, `[` or `]`). A pattern names
/// several files and so is no path. A Windows file system refuses `*` and `?` before it looks for
/// the file, and `[` and `]` are patterns of Git's pathspecs, so a path that holds one is refused
/// on every platform. This is a check of the text and looks at no file.
fn outside_refused(operand: &str) -> Option<String> {
    if operand.is_empty() {
        return Some("is empty".to_owned());
    }
    let path = Path::new(operand);
    if path.is_absolute() || operand.starts_with('/') || operand.contains('\\') {
        return Some("is not a relative path".to_owned());
    }
    if path
        .components()
        .any(|part| matches!(part, std::path::Component::ParentDir))
    {
        return Some("holds `..`".to_owned());
    }
    operand
        .contains(['*', '?', '[', ']'])
        .then(|| "holds a pattern character".to_owned())
}

/// Why the place that exists at `root`/`operand` is not inside `root`, or `None`: a link on its way
/// leads out of the repository.
fn left_through_a_link(root: &Path, operand: &str) -> Option<String> {
    match (root.canonicalize(), root.join(operand).canonicalize()) {
        (Ok(root), Ok(place)) => (!place.starts_with(root))
            .then(|| "leads out of the repository through a link".to_owned()),
        (Err(error), _) | (_, Err(error)) => Some(format!("cannot be checked: {error}")),
    }
}

/// Why `operand` is not a file of the repository at `root`, or `None`: a relative path inside it
/// that names a regular file and not a link, by a way that no link takes out of the repository.
fn file_refused(root: &Path, operand: &str) -> Option<String> {
    if let Some(why) = outside_refused(operand) {
        return Some(why);
    }
    match std::fs::symlink_metadata(root.join(operand)) {
        Ok(meta) if meta.file_type().is_symlink() => Some("is a link".to_owned()),
        Ok(meta) if !meta.is_file() => Some("is not a regular file".to_owned()),
        Ok(_) => left_through_a_link(root, operand),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Some("does not exist".to_owned())
        }
        Err(error) => Some(format!("cannot be checked: {error}")),
    }
}

/// Why `operand` is not a directory of the repository at `root`, or `None`: a relative path inside
/// it that names a directory and not a link, by a way that no link takes out of the repository.
fn directory_refused(root: &Path, operand: &str) -> Option<String> {
    if let Some(why) = outside_refused(operand) {
        return Some(why);
    }
    match std::fs::symlink_metadata(root.join(operand)) {
        Ok(meta) if meta.file_type().is_symlink() => Some("is a link".to_owned()),
        Ok(_) if root.join(operand).is_dir() => left_through_a_link(root, operand),
        _ => Some("is not a directory of the repository".to_owned()),
    }
}

/// Why `name` is not the name of one directory, or `None`.
fn name_refused(name: &str) -> Option<String> {
    (name.is_empty() || name.contains(['/', '\\']))
        .then(|| "is not the name of one directory".to_owned())
}

/// Why `operand` is not a script this plan may run from `root`, or `None`: it is a regular file
/// inside the repository that is not a link, and the very name under which Git's index holds a
/// file. Git is asked about the name as a literal, never as a pattern.
fn operand_refused(root: &Path, operand: &str) -> Option<String> {
    if let Some(why) = file_refused(root, operand) {
        return Some(why);
    }
    let output = match Command::new("git")
        .arg("-C")
        .arg(root)
        .args([
            "--literal-pathspecs",
            "ls-files",
            "-z",
            "--error-unmatch",
            "--",
        ])
        .arg(operand)
        .output()
    {
        Ok(output) => output,
        Err(error) => return Some(format!("cannot be checked: git did not run ({error})")),
    };
    match output.status.code() {
        // Git exits 1 for a name that the index does not hold, and 128 for a failure of its own.
        Some(0) => {
            let held = output.stdout.split(|byte| *byte == 0).next().unwrap_or(&[]);
            (held != operand.as_bytes()).then(|| {
                format!(
                    "is not spelled the way the repository's index holds it (`{}`)",
                    String::from_utf8_lossy(held)
                )
            })
        }
        Some(1) => Some("is not a tracked file of the repository".to_owned()),
        code => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let first = stderr.lines().next().unwrap_or_default();
            let status = code.map_or_else(
                || "git was stopped by a signal".to_owned(),
                |code| format!("git ended with status {code}"),
            );
            Some(format!("cannot be checked: {status}: {first}"))
        }
    }
}

impl Plan {
    /// Reads the plan at `path`, or at [`PLAN_PATH`] in `root`.
    ///
    /// # Errors
    ///
    /// Returns why the file cannot be read or is refused.
    pub fn load(root: &Path, path: Option<&Path>) -> Result<Self, Refusal> {
        let path: PathBuf = path.map_or_else(|| root.join(PLAN_PATH), Path::to_path_buf);
        let text = std::fs::read_to_string(&path).map_err(|error| {
            Refusal(format!(
                "the plan {} could not be read: {error}; each repository keeps its plan at \
                 {PLAN_PATH}, or names another file with --plan",
                path.display()
            ))
        })?;
        Self::parse(&text, root).map_err(|refusal| {
            Refusal(format!("the plan {} is refused: {refusal}", path.display()))
        })
    }

    /// Reads a plan from `text`, for a repository at `root`.
    ///
    /// # Errors
    ///
    /// Returns the first reason the plan is refused.
    pub fn parse(text: &str, root: &Path) -> Result<Self, Refusal> {
        let plan: Self = toml::from_str(text).map_err(|error| {
            let line = error.span().map_or(String::new(), |span| {
                format!("line {}: ", line_of(text, span.start))
            });
            Refusal(format!("{line}{}", error.message()))
        })?;
        plan.check(root)?;
        Ok(plan)
    }

    fn check(&self, root: &Path) -> Result<(), Refusal> {
        let refuse = |why: String| Err(Refusal(why));
        for (name, value) in &self.env {
            if !variable_name(name) {
                return refuse(format!(
                    "`[env]` gives `{name}`, which is not a variable name"
                ));
            }
            if let Some(why) = set_by_the_report(name) {
                return refuse(format!(
                    "`[env]` sets `{name}`, which the report sets for each step: {why}"
                ));
            }
            if let Some(other) = differs_only_by_case(&self.env, name) {
                return refuse(format!(
                    "`[env]` gives `{other}` and `{name}`, which differ only by case"
                ));
            }
            if let Some(placeholder) = placeholder_refused(value) {
                return refuse(format!(
                    "`[env]` gives `{name}` a value that holds {placeholder}, which is not a \
                     placeholder of the plan ({})",
                    PLACEHOLDERS.join(", ")
                ));
            }
            if value.contains("{output}") {
                return refuse(format!(
                    "`[env]` gives `{name}` a value that holds `{{output}}`, which belongs to one \
                     step: a step gives it in its own `env`"
                ));
            }
        }
        let mut budget_ids = BTreeSet::new();
        for budget in &self.budgets {
            let id = &budget.id;
            if id.is_empty()
                || !id
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            {
                return refuse(format!(
                    "a `[[budget]]` has the `id` `{id}`, which is not a name: ASCII letters, digits, \
                     `-` and `_`"
                ));
            }
            if !budget_ids.insert(id.as_str()) {
                return refuse(format!("the budget id `{id}` is used twice"));
            }
            if !(1..=MOST_SECONDS).contains(&budget.seconds) {
                return refuse(format!(
                    "budget `{id}` has {} seconds: a time is a whole number of seconds from 1 to \
                     {MOST_SECONDS}",
                    budget.seconds
                ));
            }
        }
        let mut ids = BTreeSet::new();
        let mut outputs: Vec<(&str, Vec<String>)> = Vec::new();
        for step in &self.steps {
            let id = &step.id;
            if !ids.insert(id.as_str()) {
                return refuse(format!("the step id `{id}` is used twice"));
            }
            if !self.groups.contains(&step.group) {
                return refuse(format!(
                    "step `{id}` names the group `{}`, which the plan's groups do not hold",
                    step.group
                ));
            }
            if step.platforms.is_empty() {
                return refuse(format!("step `{id}` names no platform"));
            }
            let Some(program) = step.command.first() else {
                return refuse(format!("step `{id}` has an empty command"));
            };
            if !PROGRAMS.contains(&program.as_str()) {
                return refuse(format!(
                    "step `{id}` runs `{program}`, which is not one of {}",
                    PROGRAMS.join(", ")
                ));
            }
            for word in &step.command {
                if let Some(placeholder) = placeholder_refused(word) {
                    return refuse(format!(
                        "step `{id}` holds {placeholder}, which is not a placeholder of the plan \
                         ({})",
                        PLACEHOLDERS.join(", ")
                    ));
                }
            }
            if step.command.iter().any(|word| word == "--show-output") {
                return refuse(format!(
                    "step `{id}` holds `--show-output`, which the loader adds and a plan file does not write"
                ));
            }
            for name in &step.needs {
                if !variable_name(name) {
                    return refuse(format!(
                        "step `{id}` needs `{name}`, which is not a variable name"
                    ));
                }
            }
            for (name, value) in &step.env {
                if !variable_name(name) {
                    return refuse(format!(
                        "step `{id}` gives `{name}`, which is not a variable name"
                    ));
                }
                if let Some(why) = set_by_the_report(name) {
                    return refuse(format!(
                        "step `{id}` sets `{name}`, which the report sets for each step: {why}"
                    ));
                }
                if let Some(other) = differs_only_by_case(&step.env, name) {
                    return refuse(format!(
                        "step `{id}` gives `{other}` and `{name}`, which differ only by case"
                    ));
                }
                if let Some(placeholder) = placeholder_refused(value) {
                    return refuse(format!(
                        "step `{id}` gives `{name}` a value that holds {placeholder}, which is not \
                         a placeholder of the plan ({})",
                        PLACEHOLDERS.join(", ")
                    ));
                }
            }
            let directory = step.directory.as_deref().unwrap_or_default();
            if let Some(named) = &step.directory {
                if named.contains(['{', '}']) {
                    return refuse(format!(
                        "step `{id}` names the `directory` `{named}`, which holds a placeholder: a \
                         directory is a literal path of the repository"
                    ));
                }
                if let Some(why) = directory_refused(root, named) {
                    return refuse(format!(
                        "step `{id}` names the `directory` `{named}`, which {why}"
                    ));
                }
            }
            for operand in script_operands(&step.command) {
                // The script is read from the step's directory, which is where it runs.
                let place = match normal(Path::new(directory)).as_str() {
                    "" => operand.to_owned(),
                    here => format!("{here}/{operand}"),
                };
                if let Some(why) = operand_refused(root, &place) {
                    return refuse(format!(
                        "step `{id}` runs the script `{operand}`, which {why}"
                    ));
                }
            }
            let holds_output = step.command.iter().any(|word| word.contains("{output}"))
                || step.env.values().any(|value| value.contains("{output}"));
            match &step.output {
                Some(output) => {
                    let parts = match output_parts(output) {
                        Ok(parts) => parts,
                        Err(why) => {
                            return refuse(format!(
                                "step `{id}` names the `output` `{output}`, {why}"
                            ));
                        }
                    };
                    if !holds_output {
                        return refuse(format!(
                            "step `{id}` names an `output` and neither its command nor an `env` \
                             value holds `{{output}}`"
                        ));
                    }
                    if let Some((other, _)) = outputs.iter().find(|(_, theirs)| {
                        let shared = parts.len().min(theirs.len());
                        parts[..shared] == theirs[..shared]
                    }) {
                        return refuse(format!(
                            "the steps `{other}` and `{id}` name outputs that are equal or nested"
                        ));
                    }
                    outputs.push((id.as_str(), parts));
                }
                None if holds_output => {
                    return refuse(format!(
                        "step `{id}` holds `{{output}}` and names no `output`"
                    ));
                }
                None => {}
            }
            match (step.reading, &step.package, &step.lane) {
                (ReadingKind::Vitest, Some(_), None)
                | (ReadingKind::Lane, None, Some(_))
                | (ReadingKind::Cargo | ReadingKind::Build | ReadingKind::Exit, None, None) => {}
                (ReadingKind::Vitest, _, _) => {
                    return refuse(format!(
                        "step `{id}` reads vitest and takes a `package` and no `lane`"
                    ));
                }
                (ReadingKind::Lane, _, _) => {
                    return refuse(format!(
                        "step `{id}` reads a lane and takes a `lane` and no `package`"
                    ));
                }
                (_, _, _) => {
                    return refuse(format!(
                        "step `{id}` takes no `package` or `lane`: its reading does not"
                    ));
                }
            }
            if step.output.is_none()
                && matches!(step.reading, ReadingKind::Vitest | ReadingKind::Lane)
            {
                return refuse(format!(
                    "step `{id}` reads a file and names no `output`: the report reads the file the \
                     output names"
                ));
            }
            let carries =
                step.filter.is_some() || !step.skips.is_empty() || step.skips_from.is_some();
            if carries && program != "cargo" {
                return refuse(format!(
                    "step `{id}` has a filter or skips and does not run `cargo`"
                ));
            }
            if let Some(filter) = &step.filter {
                let words = expand(step, &Values::default(), &[]);
                if !words.contains(&filter.name) {
                    return refuse(format!(
                        "step `{id}` filters by `{}`, which is not a word of its command",
                        filter.name
                    ));
                }
            }
            if step
                .filter
                .as_ref()
                .is_some_and(|filter| blank(&filter.reason))
            {
                return refuse(format!("step `{id}` filters with no reason"));
            }
            if let Some(skip) = step.skips.iter().find(|skip| blank(&skip.reason)) {
                return refuse(format!("step `{id}` skips `{}` with no reason", skip.name));
            }
            if step.skips_from.is_some() && self.applications.is_none() {
                return refuse(format!(
                    "step `{id}` skips from the applications and the plan has no `[applications]`"
                ));
            }
        }
        for (index, step) in self.steps.iter().enumerate() {
            let id = &step.id;
            if step.setup && step.reading != ReadingKind::Exit {
                return refuse(format!(
                    "step `{id}` is a set-up step and reads `{}`: a set-up step reads `exit`",
                    format!("{:?}", step.reading).to_lowercase()
                ));
            }
            for name in &step.after {
                let Some(at) = self.steps.iter().position(|other| other.id == *name) else {
                    return refuse(format!(
                        "step `{id}` is `after` `{name}`, which names no step of the plan"
                    ));
                };
                if at >= index {
                    return refuse(format!(
                        "step `{id}` is `after` `{name}`, which does not come before it in the plan"
                    ));
                }
                let setup = &self.steps[at];
                if !setup.setup {
                    return refuse(format!(
                        "step `{id}` is `after` `{name}`, which is not a set-up step"
                    ));
                }
                if let Some(platform) = step
                    .platforms
                    .iter()
                    .find(|platform| !setup.platforms.contains(platform))
                {
                    return refuse(format!(
                        "step `{id}` runs on {}, where its set-up step `{name}` does not run",
                        platform.name()
                    ));
                }
            }
            for (name, seconds) in &step.weight {
                if !step
                    .platforms
                    .iter()
                    .any(|platform| platform.name() == name.as_str())
                {
                    return refuse(format!(
                        "step `{id}` has a `weight` for `{name}`, which is not a platform it runs on"
                    ));
                }
                if !(1..=MOST_SECONDS).contains(seconds) {
                    return refuse(format!(
                        "step `{id}` has a `weight` of {seconds} seconds for `{name}`: a time is a \
                         whole number of seconds from 1 to {MOST_SECONDS}"
                    ));
                }
            }
            match (
                step.weight.is_empty(),
                step.weighed.as_deref().map(str::trim),
            ) {
                (false, None | Some("")) => {
                    return refuse(format!(
                        "step `{id}` has a `weight` and no `weighed`, which says the run and the date \
                         it was measured at"
                    ));
                }
                (true, Some(_)) => {
                    return refuse(format!("step `{id}` has a `weighed` and no `weight`"));
                }
                _ => {}
            }
            if let Some(seconds) = step.timeout
                && !(1..=MOST_SECONDS).contains(&seconds)
            {
                return refuse(format!(
                    "step `{id}` has a `timeout` of {seconds} seconds: a time is a whole number of \
                     seconds from 1 to {MOST_SECONDS}"
                ));
            }
            if let Some(name) = &step.budget
                && !budget_ids.contains(name.as_str())
            {
                return refuse(format!(
                    "step `{id}` names the budget `{name}`, which no `[[budget]]` of the plan is"
                ));
            }
            if (step.timeout.is_some() || step.budget.is_some())
                && step.platforms.contains(&Platform::Windows)
            {
                return refuse(format!(
                    "step `{id}` has a time limit and runs on `windows`, where the report cannot end \
                     the processes of a step"
                ));
            }
        }
        if let Some(unused) = self.budgets.iter().find(|budget| {
            !self
                .steps
                .iter()
                .any(|step| step.budget.as_deref() == Some(budget.id.as_str()))
        }) {
            return refuse(format!("the budget `{}` is named by no step", unused.id));
        }
        for absent in &self.group_absent {
            if !self.groups.contains(&absent.group) {
                return refuse(format!(
                    "a `[[group_absent]]` names the group `{}`, which the plan's groups do not hold",
                    absent.group
                ));
            }
            if blank(&absent.reason) {
                return refuse(format!(
                    "a `[[group_absent]]` for the group `{}` has no reason",
                    absent.group
                ));
            }
        }
        let mut manifests = BTreeSet::new();
        for manifest in &self.rust.manifests {
            if let Some(why) = file_refused(root, manifest) {
                return refuse(format!(
                    "`[rust] manifests` names `{manifest}`, which {why}"
                ));
            }
            // Two spellings of one path, with or without a `.`, are one manifest.
            let spelled: PathBuf = Path::new(manifest)
                .components()
                .filter(|part| !matches!(part, std::path::Component::CurDir))
                .collect();
            if !manifests.insert(spelled) {
                return refuse(format!("`[rust] manifests` names `{manifest}` twice"));
            }
        }
        // A `cargo` step runs in a workspace root the manifests name: its directory, or the
        // repository's root when it names none.
        for step in &self.steps {
            if step.command.first().map(String::as_str) != Some("cargo") {
                continue;
            }
            let here = normal(Path::new(step.directory.as_deref().unwrap_or_default()));
            if !manifests
                .iter()
                .any(|manifest| Path::new(manifest).parent().map(normal).as_deref() == Some(&here))
            {
                let place = match &step.directory {
                    Some(named) => format!("`{named}`"),
                    None => "the repository's root".to_owned(),
                };
                return refuse(format!(
                    "step `{}` runs `cargo` in {place}, which no `[rust] manifests` entry is the \
                     workspace root of",
                    step.id
                ));
            }
        }
        // A step that reads the output of `cargo test` selects its packages and targets by the flags
        // of its command, and the report reads those flags as Cargo does: a command it cannot read,
        // or that is not `cargo test`, is refused here rather than read as selecting what it does not.
        for step in &self.steps {
            if step.reading == ReadingKind::Cargo
                && let Err(why) = crate::coverage::parse(&step.command)
            {
                return refuse(format!("step `{}` {why}", step.id));
            }
        }
        for (key, directories) in [
            ("scripts", &self.scripts),
            ("lane_directories", &self.lane_directories),
        ] {
            for directory in directories {
                if let Some(why) = directory_refused(root, directory) {
                    return refuse(format!("`{key}` names `{directory}`, which {why}"));
                }
            }
        }
        if let Some(profile) = &self.terminal_profile
            && let Some(why) = file_refused(root, &profile.path)
        {
            return refuse(format!(
                "`[terminal_profile] path` names `{}`, which {why}",
                profile.path
            ));
        }
        if let Some(typescript) = &self.typescript {
            for directory in &typescript.compiler_from {
                if let Some(why) = directory_refused(root, directory) {
                    return refuse(format!(
                        "`[typescript] compiler_from` names `{directory}`, which {why}"
                    ));
                }
            }
            for name in &typescript.skip_directories {
                if let Some(why) = name_refused(name) {
                    return refuse(format!(
                        "`[typescript] skip_directories` names `{name}`, which {why}"
                    ));
                }
            }
        }
        for lane in &self.lanes {
            if let Some(group) = &lane.group
                && !self.groups.contains(group)
            {
                return refuse(format!(
                    "the lane `{}` names the group `{group}`, which the plan's groups do not hold",
                    lane.files
                ));
            }
        }
        for excluded in &self.excluded_packages {
            if blank(&excluded.reason) {
                return refuse(format!(
                    "an `[[excluded_package]]` for `{}` has no reason",
                    excluded.package
                ));
            }
        }
        if let Some(lane) = self.lanes.iter().find(|lane| blank(&lane.reason)) {
            return refuse(format!("the lane `{}` has no reason", lane.files));
        }
        if self
            .terminals
            .as_ref()
            .is_some_and(|terminals| blank(&terminals.reason))
        {
            return refuse("`[terminals]` has no reason".to_owned());
        }
        for run in &self.ignored_runs {
            if let Runs::ByHand { why } | Runs::Nowhere { why } = &run.runs
                && blank(why)
            {
                return refuse(format!(
                    "the `[[ignored_run]]` of `{}` `{}` has no `why`",
                    run.package, run.target
                ));
            }
        }
        let unrun = &self.unrun;
        for (name, text) in [("bench", &unrun.bench), ("typescript", &unrun.typescript)] {
            if blank(text) {
                return refuse(format!("`[unrun]` has no `{name}` reason"));
            }
        }
        if let Some(typescript) = &self.typescript {
            for package in &typescript.packages {
                if let Some(why) = directory_refused(root, package) {
                    return refuse(format!(
                        "`[typescript] packages` names `{package}`, which {why}"
                    ));
                }
            }
        }
        for group in &self.groups {
            if !self.steps.iter().any(|step| &step.group == group) {
                return refuse(format!("the group `{group}` is used by no step"));
            }
        }
        Ok(())
    }

    /// A plan of `steps` only, for a tree that is not a repository with a plan file: every step
    /// runs on every platform, in one group named `group`, and a test no step runs is not run for
    /// one reason. Each command is taken as a plan file holds it, and the steps are expanded when
    /// the plan is asked for them.
    ///
    /// # Panics
    ///
    /// When a step carries skips: a skip names its reason, which only a plan file holds.
    #[doc(hidden)]
    #[must_use]
    pub fn of_steps(group: &str, steps: Vec<Step>) -> Self {
        assert!(
            steps.iter().all(|step| step.skips.is_empty()),
            "a plan of steps holds no skips"
        );
        let mut budgets: Vec<Budget> = Vec::new();
        for (id, seconds) in steps.iter().filter_map(|step| step.budget.as_ref()) {
            if !budgets.iter().any(|budget| budget.id == *id) {
                budgets.push(Budget {
                    id: id.clone(),
                    seconds: i64::try_from(*seconds).unwrap_or(MOST_SECONDS),
                });
            }
        }
        let reason = "no step of this run's selection runs this target on this platform";
        Self {
            repository: "test".to_owned(),
            groups: vec![group.to_owned()],
            rust: Rust {
                manifests: vec!["Cargo.toml".to_owned()],
            },
            unrun: Unrun {
                bench: reason.to_owned(),
                typescript: reason.to_owned(),
            },
            steps: steps
                .into_iter()
                .enumerate()
                .map(|(index, step)| StepDef {
                    id: if step.id.is_empty() {
                        format!("step-{}", index + 1)
                    } else {
                        step.id.clone()
                    },
                    group: step.group,
                    what: step.what,
                    platforms: vec![Platform::Linux, Platform::MacOs, Platform::Windows],
                    command: step.command,
                    setup: step.setup,
                    after: step.after,
                    reading: match step.reading {
                        Reading::Cargo => ReadingKind::Cargo,
                        Reading::Build => ReadingKind::Build,
                        Reading::Exit => ReadingKind::Exit,
                        Reading::Vitest { .. } => ReadingKind::Vitest,
                        Reading::Lane(_) => ReadingKind::Lane,
                    },
                    package: match &step.reading {
                        Reading::Vitest { directory } => Some(directory.clone()),
                        _ => None,
                    },
                    lane: match step.reading {
                        Reading::Lane(tests) => Some(tests),
                        _ => None,
                    },
                    needs: step.needs,
                    directory: (!step.directory.is_empty()).then_some(step.directory),
                    env: step.env.into_iter().collect(),
                    output: step.output,
                    filter: step.filter.map(|(name, reason)| Reasoned { name, reason }),
                    skips: Vec::new(),
                    skips_from: None,
                    timeout: step.timeout.and_then(|seconds| i64::try_from(seconds).ok()),
                    budget: step.budget.map(|(id, _)| id),
                    weight: step.weight.map_or_else(BTreeMap::new, |seconds| {
                        ["linux", "macos", "windows"]
                            .into_iter()
                            .map(|name| (name.to_owned(), i64::try_from(seconds).unwrap_or(1)))
                            .collect()
                    }),
                    weighed: step.weight.map(|_| "a plan made from steps".to_owned()),
                })
                .collect(),
            budgets,
            ..Self::default()
        }
    }

    /// Every group's name, in the plan's order.
    #[must_use]
    pub fn all_groups(&self) -> Vec<String> {
        self.groups.clone()
    }

    /// The steps of the selected `groups` on `platform`, in the plan's order, as the report runs
    /// them. `values` are what the placeholders stand for, and `applications` names the programs
    /// whose cases are left out, each with its reason; a step that skips from the applications is
    /// left out of a plan that has none.
    #[must_use]
    pub fn steps(
        &self,
        platform: Platform,
        groups: &[String],
        values: &Values<'_>,
        applications: Option<&ApplicationsPlan>,
    ) -> Vec<Step> {
        self.selected(Some(platform), groups)
            .filter_map(|definition| {
                let from_applications: Vec<Reasoned> = match (definition.skips_from, applications) {
                    (None, _) => Vec::new(),
                    (Some(SkipsFrom::Applications), None) => return None,
                    (Some(SkipsFrom::Applications), Some(plan)) => plan
                        .left_out
                        .iter()
                        .map(|(id, reason)| Reasoned {
                            name: format!("{id}::"),
                            reason: reason.clone(),
                        })
                        .collect(),
                };
                let output = output_of(definition, values);
                let (env, placeholder_env) = environment_of(
                    platform,
                    self,
                    definition,
                    values,
                    output.as_deref().unwrap_or_default(),
                );
                Some(Step {
                    id: definition.id.clone(),
                    setup: definition.setup,
                    after: definition.after.clone(),
                    group: definition.group.clone(),
                    what: definition.what.clone(),
                    command: expand(definition, values, &from_applications),
                    needs: definition.needs.clone(),
                    directory: definition
                        .directory
                        .as_deref()
                        .map(|directory| normal(Path::new(directory)))
                        .unwrap_or_default(),
                    env,
                    placeholder_env,
                    placeholder_words: definition
                        .command
                        .iter()
                        .enumerate()
                        .filter(|(_, word)| holds_placeholder(word))
                        .map(|(index, _)| index)
                        .collect(),
                    output,
                    reading: match definition.reading {
                        ReadingKind::Cargo => Reading::Cargo,
                        ReadingKind::Build => Reading::Build,
                        ReadingKind::Exit => Reading::Exit,
                        ReadingKind::Vitest => Reading::Vitest {
                            directory: definition.package.clone().unwrap_or_default(),
                        },
                        ReadingKind::Lane => Reading::Lane(definition.lane.unwrap_or(Tests::Junit)),
                    },
                    filter: definition
                        .filter
                        .as_ref()
                        .map(|filter| (filter.name.clone(), filter.reason.clone())),
                    skips: definition
                        .skips
                        .iter()
                        .chain(&from_applications)
                        .map(|skip| (skip.name.clone(), skip.reason.clone()))
                        .collect(),
                    timeout: definition
                        .timeout
                        .and_then(|seconds| u64::try_from(seconds).ok()),
                    weight: definition
                        .weight
                        .get(platform.name())
                        .and_then(|seconds| u64::try_from(*seconds).ok()),
                    budget: definition.budget.as_ref().and_then(|id| {
                        self.budgets
                            .iter()
                            .find(|budget| budget.id == *id)
                            .and_then(|budget| u64::try_from(budget.seconds).ok())
                            .map(|seconds| (id.clone(), seconds))
                    }),
                })
            })
            .collect()
    }

    /// The steps of the selected groups, on `platform` when one is given and on every platform
    /// when none is, and every set-up step that a step of them names in `after`, directly or through
    /// another set-up step, whatever its group.
    fn selected<'a>(
        &'a self,
        platform: Option<Platform>,
        groups: &'a [String],
    ) -> impl Iterator<Item = &'a StepDef> {
        let mut taken: Vec<bool> = self
            .steps
            .iter()
            .map(|step| {
                groups.contains(&step.group)
                    && platform.is_none_or(|platform| step.platforms.contains(&platform))
            })
            .collect();
        // A set-up step comes before the steps that name it, so one pass from the end finds each
        // set-up step that a taken step names, and each that those name.
        for index in (0..self.steps.len()).rev() {
            if taken[index] {
                for name in &self.steps[index].after {
                    if let Some(earlier) = self.steps.iter().position(|step| step.id == *name) {
                        taken[earlier] = true;
                    }
                }
            }
        }
        self.steps
            .iter()
            .zip(taken)
            .filter_map(|(step, taken)| taken.then_some(step))
    }

    /// Whether the selection reads TypeScript: a selected step, on any platform, reads a package's
    /// tests with vitest.
    #[must_use]
    pub fn reads_typescript(&self, groups: &[String]) -> bool {
        self.selected(None, groups)
            .any(|step| step.reading == ReadingKind::Vitest)
    }

    /// Whether a TypeScript place of the package in `directory` belongs to the selection: a
    /// selected step, on any platform, reads that package's tests.
    #[must_use]
    pub fn selects_package(&self, groups: &[String], directory: &str) -> bool {
        self.selected(None, groups).any(|step| {
            step.reading == ReadingKind::Vitest && step.package.as_deref() == Some(directory)
        })
    }

    /// Whether a place of the lane that holds `file` belongs to the selection: the lane names a
    /// group, and the group is selected.
    #[must_use]
    pub fn selects_lane_file(&self, groups: &[String], file: &str) -> bool {
        self.lanes
            .iter()
            .find(|lane| crate::plan::matches(&lane.files, file))
            .and_then(|lane| lane.group.as_ref())
            .is_some_and(|group| groups.contains(group))
    }

    /// Whether a selected step on `platform` runs `pnpm` or `node`, so that their versions are
    /// recorded.
    #[must_use]
    pub fn uses_javascript_tools(&self, platform: Platform, groups: &[String]) -> bool {
        self.selected(Some(platform), groups).any(|step| {
            matches!(
                step.command.first().map(String::as_str),
                Some("pnpm" | "node")
            )
        })
    }

    /// Whether a selected step, on any platform, skips from the application matrix.
    #[must_use]
    pub fn selects_applications(&self, groups: &[String]) -> bool {
        self.selected(None, groups)
            .any(|step| step.skips_from == Some(SkipsFrom::Applications))
    }

    /// Whether a selected step on `platform` skips from the application matrix, so that the run
    /// has to be given the programs the fetch step installed.
    #[must_use]
    pub fn runs_applications(&self, platform: Platform, groups: &[String]) -> bool {
        self.selected(Some(platform), groups)
            .any(|step| step.skips_from == Some(SkipsFrom::Applications))
    }

    /// Why a Rust target that no step of the selection covers is not run: the first reason, in the
    /// plan's order of groups, of a selected group that runs nothing on `platform` and is marked as
    /// explaining it.
    #[must_use]
    pub fn unrun_rust_reason(&self, platform: Platform, groups: &[String]) -> Option<&str> {
        self.groups
            .iter()
            .filter(|group| groups.contains(group))
            .find_map(|group| {
                self.group_absent
                    .iter()
                    .find(|absent| {
                        absent.explains_unrun_rust
                            && absent.platform == platform
                            && absent.group == *group
                    })
                    .map(|absent| absent.reason.as_str())
            })
    }

    /// Why a TypeScript test no step ran is not run: the reason of the first selected group that
    /// holds a step reading TypeScript on some platform and runs nothing on this one, or the plan's
    /// own text.
    #[must_use]
    pub fn typescript_unrun_reason(&self, platform: Platform, groups: &[String]) -> &str {
        self.groups
            .iter()
            .filter(|group| groups.contains(group))
            .filter(|group| {
                self.steps
                    .iter()
                    .any(|step| step.group == **group && step.reading == ReadingKind::Vitest)
            })
            .find_map(|group| {
                self.group_absent
                    .iter()
                    .find(|absent| absent.platform == platform && absent.group == *group)
                    .map(|absent| absent.reason.as_str())
            })
            .unwrap_or(&self.unrun.typescript)
    }

    /// Why `package` is left out of the plan on `platform`, when it is.
    #[must_use]
    pub fn excluded_reason(&self, platform: Platform, package: &str) -> Option<&str> {
        self.excluded_packages
            .iter()
            .find(|excluded| excluded.platform == platform && excluded.package == package)
            .map(|excluded| excluded.reason.as_str())
    }

    /// The packages' directories of the TypeScript the plan reads.
    #[must_use]
    pub fn typescript_packages(&self) -> &[String] {
        self.typescript_list(|typescript| &typescript.packages)
    }

    /// The directories whose installed compiler reads the TypeScript.
    #[must_use]
    pub fn compiler_from(&self) -> &[String] {
        self.typescript_list(|typescript| &typescript.compiler_from)
    }

    /// The names of the directories no TypeScript file is read below.
    #[must_use]
    pub fn skip_directories(&self) -> &[String] {
        self.typescript_list(|typescript| &typescript.skip_directories)
    }

    /// The directories whose files are read as scripts.
    #[must_use]
    pub fn script_directories(&self) -> &[String] {
        &self.scripts
    }

    /// The directories whose Kotlin, Swift and Java files are read for the lanes.
    #[must_use]
    pub fn lane_directories(&self) -> &[String] {
        &self.lane_directories
    }

    fn typescript_list(&self, list: fn(&TypeScript) -> &Vec<String>) -> &[String] {
        self.typescript
            .as_ref()
            .map_or(&[], |typescript| list(typescript).as_slice())
    }

    /// The manifests of the Rust workspaces.
    #[must_use]
    pub fn manifests(&self) -> &[String] {
        &self.rust.manifests
    }

    /// Whether the tree is held to its ignored-run entries.
    #[must_use]
    pub fn holds_ignored_runs(&self) -> bool {
        self.ignored_policy.held
    }

    /// Every step of the plan on Linux, each as the words of its command, with the evidence
    /// directory named `evidence` and no application left out.
    #[must_use]
    pub fn linux_commands(&self) -> Vec<String> {
        self.steps(
            Platform::Linux,
            &self.groups,
            &Values::evidence("evidence"),
            Some(&ApplicationsPlan {
                left_out: Vec::new(),
            }),
        )
        .into_iter()
        .map(|step| step.command.join(" "))
        .collect()
    }
}
