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
//! The schema grows by optional fields. This module holds the fields that core's own plan needs.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Deserialize;

use crate::plan::{ApplicationsPlan, Platform, Reading, Step, Tests};

/// Where a repository keeps its plan, relative to its root.
pub const PLAN_PATH: &str = "conformance/plan.toml";

/// The programs a step runs: what the repositories' workflows run today.
pub const PROGRAMS: [&str; 5] = ["cargo", "pnpm", "node", "bash", "python3"];

/// The placeholders a command may hold, each as it is written between braces.
pub const PLACEHOLDERS: [&str; 1] = ["evidence"];

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
    /// A name filter the command passes to the test binaries, and why tests outside it are not run.
    #[serde(default)]
    pub filter: Option<Reasoned>,
    /// Tests the command leaves out by name, each with its reason.
    #[serde(default)]
    pub skips: Vec<Reasoned>,
    /// Where more skips come from at run time.
    #[serde(default)]
    pub skips_from: Option<SkipsFrom>,
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

/// One reason for each platform.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PerPlatform {
    /// On Linux.
    pub linux: String,
    /// On macOS.
    pub macos: String,
    /// On Windows.
    pub windows: String,
}

impl PerPlatform {
    /// The reason for `platform`.
    #[must_use]
    pub fn get(&self, platform: Platform) -> &str {
        match platform {
            Platform::Linux => &self.linux,
            Platform::MacOs => &self.macos,
            Platform::Windows => &self.windows,
        }
    }
}

/// Why a test no step runs is not run.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Unrun {
    /// A Rust target that no step runs, in general, on each platform.
    pub rust: PerPlatform,
    /// A benchmark target, before the reason for Rust targets in general.
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

/// The TypeScript packages.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TypeScript {
    /// Their directories, relative to the repository.
    pub packages: Vec<String>,
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
    /// Whether every full run lists the rows of the specification's tables.
    #[serde(default)]
    pub list_table_rows: bool,
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
}

impl Default for Unrun {
    fn default() -> Self {
        Self {
            rust: PerPlatform {
                linux: String::new(),
                macos: String::new(),
                windows: String::new(),
            },
            bench: String::new(),
            typescript: String::new(),
        }
    }
}

/// The words the loader adds to a step's command, and the words of its expansion: the command with
/// the placeholders given their values.
///
/// A `cargo test` that leaves each test's output captured is given `--show-output` after a `--`
/// that is added when the command has none. One that shows the output as it is written, with
/// `--nocapture`, is left as it is. Then each of `skips` is added as `--skip <name>`, after a `--`
/// when the command still has none. A `--skip` the command already holds stays as it is written.
#[must_use]
pub fn expand(
    definition: &StepDef,
    evidence: &str,
    applications_skips: &[Reasoned],
) -> Vec<String> {
    let mut words: Vec<String> = definition
        .command
        .iter()
        .map(|word| word.replace("{evidence}", evidence))
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

/// Why `operand` is not a script this plan may run from `root`, or `None`.
fn operand_refused(root: &Path, operand: &str) -> Option<String> {
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
    if std::fs::symlink_metadata(root.join(path)).is_ok_and(|meta| meta.file_type().is_symlink()) {
        return Some("is a link".to_owned());
    }
    match Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["ls-files", "--error-unmatch", "--"])
        .arg(operand)
        .output()
    {
        Ok(output) if output.status.success() => None,
        Ok(_) => Some("is not a tracked file of the repository".to_owned()),
        Err(error) => Some(format!("cannot be checked: git did not run ({error})")),
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
        let mut ids = BTreeSet::new();
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
            for operand in script_operands(&step.command) {
                if let Some(why) = operand_refused(root, operand) {
                    return refuse(format!(
                        "step `{id}` runs the script `{operand}`, which {why}"
                    ));
                }
            }
            match (step.reading, &step.package, &step.lane) {
                (ReadingKind::Vitest, Some(_), None)
                | (ReadingKind::Lane, None, Some(_))
                | (ReadingKind::Cargo | ReadingKind::Build, None, None) => {}
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
            let carries =
                step.filter.is_some() || !step.skips.is_empty() || step.skips_from.is_some();
            if carries && program != "cargo" {
                return refuse(format!(
                    "step `{id}` has a filter or skips and does not run `cargo`"
                ));
            }
            if let Some(filter) = &step.filter {
                let words = expand(step, "", &[]);
                if !words.iter().any(|word| *word == filter.name) {
                    return refuse(format!(
                        "step `{id}` filters by `{}`, which is not a word of its command",
                        filter.name
                    ));
                }
            }
            if step.skips_from.is_some() && self.applications.is_none() {
                return refuse(format!(
                    "step `{id}` skips from the applications and the plan has no `[applications]`"
                ));
            }
        }
        for absent in &self.group_absent {
            if !self.groups.contains(&absent.group) {
                return refuse(format!(
                    "a `[[group_absent]]` names the group `{}`, which the plan's groups do not hold",
                    absent.group
                ));
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
        if let Some(typescript) = &self.typescript {
            for package in &typescript.packages {
                if !root.join(package).is_dir() {
                    return refuse(format!(
                        "`[typescript] packages` names `{package}`, which is not a directory of \
                         the repository"
                    ));
                }
            }
        }
        Ok(())
    }

    /// A plan of `steps` only, for a tree that is not a repository with a plan file: every step
    /// runs on every platform, in one group named `group`.
    #[must_use]
    pub fn of_steps(group: &str, steps: Vec<Step>) -> Self {
        Self {
            repository: "test".to_owned(),
            groups: vec![group.to_owned()],
            steps: steps
                .into_iter()
                .enumerate()
                .map(|(index, step)| StepDef {
                    id: format!("step-{}", index + 1),
                    group: step.group,
                    what: step.what,
                    platforms: vec![Platform::Linux, Platform::MacOs, Platform::Windows],
                    command: step.command,
                    reading: match step.reading {
                        Reading::Cargo => ReadingKind::Cargo,
                        Reading::Build => ReadingKind::Build,
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
                    filter: step.filter.map(|(name, reason)| Reasoned { name, reason }),
                    skips: Vec::new(),
                    skips_from: None,
                })
                .collect(),
            ..Self::default()
        }
    }

    /// Every group's name, in the plan's order.
    #[must_use]
    pub fn all_groups(&self) -> Vec<String> {
        self.groups.clone()
    }

    /// The steps of the selected `groups` on `platform`, in the plan's order, as the report runs
    /// them. `evidence` is the directory the placeholders `{evidence}` stand for, and
    /// `applications` names the programs whose cases are left out, each with its reason; a step that
    /// skips from the applications is left out of a plan that has none.
    #[must_use]
    pub fn steps(
        &self,
        platform: Platform,
        groups: &[String],
        evidence: &str,
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
                Some(Step {
                    group: definition.group.clone(),
                    what: definition.what.clone(),
                    command: expand(definition, evidence, &from_applications),
                    needs: definition.needs.clone(),
                    reading: match definition.reading {
                        ReadingKind::Cargo => Reading::Cargo,
                        ReadingKind::Build => Reading::Build,
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
                })
            })
            .collect()
    }

    /// The steps of the selected groups, on `platform` when one is given and on every platform
    /// when none is.
    fn selected<'a>(
        &'a self,
        platform: Option<Platform>,
        groups: &'a [String],
    ) -> impl Iterator<Item = &'a StepDef> {
        self.steps.iter().filter(move |step| {
            groups.contains(&step.group)
                && platform.is_none_or(|platform| step.platforms.contains(&platform))
        })
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

    /// Why an unrun Rust target is unrun beyond the platform's general reason: the first reason of
    /// a selected group that runs nothing on `platform` and is marked as explaining it.
    #[must_use]
    pub fn unrun_rust_reason(&self, platform: Platform, groups: &[String]) -> Option<&str> {
        groups.iter().find_map(|group| {
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
        self.typescript
            .as_ref()
            .map_or(&[], |typescript| typescript.packages.as_slice())
    }

    /// Every step of the plan on Linux, each as the words of its command, with the evidence
    /// directory named `evidence` and no application left out.
    #[must_use]
    pub fn linux_commands(&self) -> Vec<String> {
        self.steps(
            Platform::Linux,
            &self.groups,
            "evidence",
            Some(&ApplicationsPlan {
                left_out: Vec::new(),
            }),
        )
        .into_iter()
        .map(|step| step.command.join(" "))
        .collect()
    }
}
