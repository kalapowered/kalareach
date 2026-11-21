//! The run: the map, the steps, every keyed test's outcome, and the result keyed by identifier.
//!
//! A test's outcome on this platform is one of five:
//!
//! * `passed` or `failed`, from a step that ran it;
//! * `ignored`, with the reason its attribute gives, when every step that listed it left it out;
//! * `not_run`, with the reason, when no step of this run ran it here: a step left it out by name,
//!   no selected group runs its target on this platform, its lane is another toolchain's, the step
//!   that built it failed before a run of it could be read, or it returned early and said why;
//! * `not_built`, when a step ran its target and this platform's build of it has no such test.
//!
//! An identifier has failed when any of its tests failed, has passed when at least one ran and
//! passed and none failed, and is not run otherwise. An ignored or skipped test is never counted as
//! passed.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use serde::Serialize;

use crate::coverage;
use crate::evidence::{self, Figure, KnownDifference};
use crate::id::{Family, Identifier};
use crate::identity::{self, Commit, PackageVersion, System, TerminalProfile, Toolchain};
use crate::lane::{self, Part};
use crate::libtest::Outcome as LibtestOutcome;
use crate::limits::Budgets;
use crate::map::{self, Binding, Declarations, Map, Place, Reference, TypeScriptRead};
use crate::observe::{self, Observed};
use crate::plan::{self, ApplicationsPlan, Platform};
use crate::plan_file::{Plan, Values};
use crate::run::{self, Blocked, Executed};
use crate::runner_copy;
use crate::scratch::{self, Scratch};
use crate::tree::Deadline;
use crate::workspace::{Package, TargetId, TargetKind};

/// The result's schema identifier.
pub const SCHEMA: &str = "kalareach.conformance/1";

/// A test's outcome on this platform.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// It ran and failed.
    Failed,
    /// It ran and passed.
    Passed,
    /// Every step that listed it left it out.
    Ignored,
    /// No step of this run ran it here.
    NotRun,
    /// A step ran its target, and this platform's build of it has no such test.
    NotBuilt,
    /// It ran and held what the profile defines, and the application it is about reads the same
    /// thing differently: a known difference, which is never a pass.
    KnownDifference,
}

/// What one step came to, in the result.
#[derive(Clone, Debug, Serialize)]
pub struct StepRecord {
    /// Its number, from 1.
    pub number: usize,
    /// Its group.
    pub group: String,
    /// What it runs.
    pub what: String,
    /// The command, as run.
    pub command: String,
    /// Variables it reads.
    pub needs: Vec<String>,
    /// Its exit status.
    pub exit: Option<i32>,
    /// How long it took, in seconds.
    pub seconds: u64,
    /// Its log, relative to the evidence directory.
    pub log: String,
    /// Why it could not be run or read.
    pub error: Option<String>,
    /// The programs its log says could not be run, and what their files looked like when the
    /// step ended.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observation: Option<Observed>,
}

/// One run of one test.
#[derive(Clone, Debug, Serialize)]
pub struct RunRecord {
    /// The step, by number.
    pub step: usize,
    /// What the test came to there.
    pub outcome: Outcome,
    /// The reason given, for a test that step did not run.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// One keyed test of one identifier.
#[derive(Clone, Debug, Serialize)]
pub struct TestRecord {
    /// How the test is named: its package, target and name, or its file and title.
    pub test: String,
    /// Where the key is written.
    pub source: String,
    /// How the key is written.
    pub keyed_by: Binding,
    /// Its outcome on this platform.
    pub outcome: Outcome,
    /// Why it did not run, or why the harness ignored it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Each step that listed it.
    pub runs: Vec<RunRecord>,
    /// The command that reproduces it, where one runs it here.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    /// Variables that command reads.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub needs: Vec<String>,
    /// The known differences it recorded.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub known_differences: Vec<KnownDifference>,
}

/// How many tests came to each outcome.
#[derive(Clone, Copy, Debug, Default, Serialize, PartialEq, Eq)]
pub struct Counts {
    /// Passed.
    pub passed: usize,
    /// Failed.
    pub failed: usize,
    /// Ignored.
    pub ignored: usize,
    /// Not run.
    pub not_run: usize,
    /// Not built.
    pub not_built: usize,
    /// Known differences.
    pub known_difference: usize,
}

impl Counts {
    fn add(&mut self, outcome: &Outcome) {
        match outcome {
            Outcome::Passed => self.passed += 1,
            Outcome::Failed => self.failed += 1,
            Outcome::Ignored => self.ignored += 1,
            Outcome::NotRun => self.not_run += 1,
            Outcome::NotBuilt => self.not_built += 1,
            Outcome::KnownDifference => self.known_difference += 1,
        }
    }
}

/// An identifier's verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// At least one of its tests failed.
    Failed,
    /// At least one ran and passed, and none failed.
    Passed,
    /// None passed or failed, and at least one is a known difference.
    KnownDifference,
    /// None ran here.
    NotRun,
}

/// One identifier in the result.
#[derive(Clone, Debug, Serialize)]
pub struct IdentifierRecord {
    /// Its family.
    pub family: Family,
    /// Its verdict.
    pub verdict: Verdict,
    /// Its tests' outcomes, counted.
    pub counts: Counts,
    /// Its tests.
    pub tests: Vec<TestRecord>,
    /// Where it is named outside any test.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<Reference>,
    /// The figures its measurements recorded in this run.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub figures: Vec<Figure>,
}

/// One application of the matrix.
#[derive(Clone, Debug, Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct ApplicationRecord {
    /// The lock's identifier.
    pub id: String,
    /// The pinned version.
    pub version: String,
    /// `installed`, `unsupported_platform` or `unavailable`.
    pub status: String,
    /// Where it came from.
    #[serde(default)]
    pub url: Option<String>,
    /// The pinned digest of what was fetched.
    #[serde(default)]
    pub sha256: Option<String>,
    /// How it was installed: `release`, or `source` when it was built here from its release's source.
    #[serde(default)]
    pub build: Option<String>,
    /// Why it is not installed.
    #[serde(default)]
    pub reason: Option<String>,
}

/// A known difference, as the result lists it in a section of its own.
#[derive(Clone, Debug, Serialize)]
pub struct KnownDifferenceEntry {
    /// The identifiers of the test that recorded it.
    pub identifiers: Vec<String>,
    /// The difference, with the package, target and test that recorded it.
    #[serde(flatten)]
    pub difference: KnownDifference,
}

/// One terminal of section 27's matrix.
#[derive(Clone, Debug, Serialize)]
pub struct TerminalRecord {
    /// The terminal.
    pub terminal: String,
    /// Its outcome.
    pub outcome: Outcome,
    /// Why.
    pub reason: String,
}

/// The run's identities.
#[derive(Clone, Debug, Serialize)]
pub struct RunRecordHeader {
    /// When it started, in UTC.
    pub started: String,
    /// When it finished, in UTC.
    pub finished: String,
    /// The platform.
    pub platform: String,
    /// The machine.
    pub system: System,
    /// The commit.
    pub commit: Commit,
    /// The toolchain.
    pub toolchain: Toolchain,
    /// The terminal profile, when the plan names the file that holds it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terminal_profile: Option<TerminalProfile>,
    /// The workspace's packages and the TypeScript packages, with their versions.
    pub packages: Vec<PackageVersion>,
    /// The applications, where that group ran.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub applications: Option<Vec<ApplicationRecord>>,
    /// The groups this run selected.
    pub selection: Vec<String>,
    /// The part of the platform's plan this run is, as `number/parts`, when it is one of several.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub part: Option<String>,
    /// Whether the run was asked for the whole terminal matrix.
    pub all_terminals: bool,
    /// Where the evidence is.
    pub evidence_directory: String,
}

/// The totals.
#[derive(Clone, Debug, Default, Serialize)]
pub struct Summary {
    /// Identifiers in the result.
    pub identifiers: usize,
    /// Identifiers that passed.
    pub passed: usize,
    /// Identifiers that failed.
    pub failed: usize,
    /// Identifiers not run.
    pub not_run: usize,
    /// Identifiers whose only outcome is a known difference.
    pub known_difference: usize,
    /// Known differences recorded.
    pub known_differences: usize,
    /// Every test record's outcome, counted.
    pub tests: Counts,
    /// Steps that did not exit 0 or could not be read.
    pub failed_steps: Vec<usize>,
    /// The failed steps whose log names a program the system would not start, whose file
    /// shows damage, and in whose log no test ran and failed.
    pub failed_with_damage_seen: Vec<usize>,
    /// The other failed steps.
    pub failed_otherwise: Vec<usize>,
}

impl Summary {
    /// The line that says how many failed steps carry an observation of a program that could
    /// not be run with damage seen, and how many failed otherwise, when a step failed. It says
    /// what was seen; the run fails whatever it says.
    #[must_use]
    pub fn failure_line(&self) -> Option<String> {
        (!self.failed_steps.is_empty()).then(|| {
            let (failed, damaged) = (self.failed_steps.len(), self.failed_with_damage_seen.len());
            format!(
                "{failed} failed {}: {damaged} {} an observation of a program that could not be \
                 run with damage seen, {} failed otherwise",
                if failed == 1 { "step" } else { "steps" },
                if damaged == 1 { "carries" } else { "carry" },
                self.failed_otherwise.len()
            )
        })
    }
}

/// The result.
#[derive(Clone, Debug, Serialize)]
pub struct Document {
    /// The schema.
    pub schema: &'static str,
    /// The repository.
    pub repository: String,
    /// The run's identities.
    pub run: RunRecordHeader,
    /// The steps.
    pub steps: Vec<StepRecord>,
    /// Each identifier.
    pub identifiers: BTreeMap<String, IdentifierRecord>,
    /// Tests that failed in a step and name no identifier.
    pub failures_outside_identifiers: Vec<String>,
    /// Every known difference the run recorded, with the identifiers of the test that recorded it.
    pub known_differences: Vec<KnownDifferenceEntry>,
    /// What makes this result incomplete, such as evidence a test wrote that could not be read.
    pub problems: Vec<String>,
    /// Section 27's terminal matrix, when the run was asked for it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terminals: Option<Vec<TerminalRecord>>,
    /// What the map noted and carried on past.
    pub warnings: Vec<String>,
    /// The totals.
    pub summary: Summary,
}

impl Document {
    /// Whether the run passed: no identifier failed, every step exited 0 and was read, no test
    /// failed outside an identifier, and, when the whole terminal matrix was asked for, every
    /// terminal ran.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.summary.failed == 0
            && self.summary.failed_steps.is_empty()
            && self.failures_outside_identifiers.is_empty()
            && self.problems.is_empty()
            && self
                .terminals
                .as_ref()
                .is_none_or(|terminals| terminals.iter().all(|t| t.outcome == Outcome::Passed))
    }
}

/// What a run is asked to do.
#[derive(Clone, Debug)]
pub struct Options {
    /// The repository.
    pub root: PathBuf,
    /// The evidence directory, already checked.
    pub evidence: PathBuf,
    /// The groups selected, or `None` for every group.
    pub selection: Option<Vec<String>>,
    /// Whether the whole terminal matrix was asked for.
    pub all_terminals: bool,
    /// The platform.
    pub platform: Platform,
    /// The plan: the steps, tables and reasons the run takes from the repository's plan file.
    pub plan: Plan,
    /// A directory whose installed compiler reads the TypeScript, in place of the plan's
    /// `compiler_from`.
    pub typescript_compiler: Option<PathBuf>,
    /// The applications the fetch step recorded, when that group runs.
    pub applications: Option<Vec<ApplicationRecord>>,
    /// Variables every step is run with, beyond the report's own environment.
    pub environment: Vec<(String, String)>,
    /// The `kr-conformance` program. The run copies it into a directory of its own, compares
    /// the copy's bytes with it, and gives Cargo the copy as the runner of every listing and
    /// every run, so a step that links the program again cannot damage the runner.
    pub lister: PathBuf,
    /// Which part of the platform's plan this run is, as the number of the part from 1 and the
    /// number of parts, when the plan is run in parts by separate runs.
    pub part: Option<(usize, usize)>,
    /// The directory the run makes the copy's own directory in. The program gives the
    /// temporary directory; a case gives a directory that it removes.
    pub runner_base: PathBuf,
}

/// Why a run stopped before it ran anything.
#[derive(Clone, Debug)]
pub enum Stopped {
    /// Mentions the grammar refuses.
    Refused(Vec<map::Refused>),
    /// The map cannot be trusted.
    Problems(Vec<String>),
    /// The evidence directory cannot take this run: it holds an earlier run's report, or the
    /// report's own directory in it could not be made.
    Evidence(String),
    /// The report's own program could not be copied where no step builds, or the copy is not
    /// equal to it. No step has run.
    PrivateCopy(String),
    /// The run's scratch directory could not be made, or would lie in the evidence directory. No
    /// step has run.
    Scratch(String),
    /// The plan cannot be cut into the parts the run is asked for: a budget's steps fall in more than
    /// one. No step has run.
    Plan(String),
    /// A step has a time limit, and this process could not start a command to find whether it can
    /// wait for one, or cannot wait for a command it started, so the limit cannot be kept. No step
    /// has run.
    Host(String),
}

/// The directories a step of `options` builds in that are known from the options, the steps and the
/// environment: the repository, which holds the build directories the plan's scripts name, and the
/// target directory each step's Cargo is given. A step's own variables (the plan's are among them)
/// replace the options', and a name in neither is the report's environment's. A relative target
/// directory lies below the directory its step runs in. A target directory set in Cargo's
/// configuration file is not named.
fn build_directories(options: &Options, steps: &[plan::Step]) -> Vec<PathBuf> {
    let mut directories = vec![options.root.clone()];
    for step in steps {
        let given = options
            .environment
            .iter()
            .chain(&step.env)
            .rfind(|(name, _)| options.platform.same_variable(name, "CARGO_TARGET_DIR"))
            .map(|(_, value)| std::ffi::OsString::from(value))
            .or_else(|| std::env::var_os("CARGO_TARGET_DIR"));
        if let Some(target) = given {
            let built = options.root.join(&step.directory).join(target);
            if !directories.contains(&built) {
                directories.push(built);
            }
        }
    }
    directories
}

/// The groups a run selects: those it names, or every group of the plan.
fn selected_groups(options: &Options) -> Vec<String> {
    options
        .selection
        .clone()
        .unwrap_or_else(|| options.plan.all_groups())
}

/// Builds the map for a run of `options`, reading TypeScript when the selection does.
#[must_use]
pub fn map_for(options: &Options) -> Map {
    let typescript = options.plan.reads_typescript(&selected_groups(options));
    map_declared(options, typescript)
}

/// Builds the map for `options`, reading the plan's TypeScript packages when `typescript` says so.
#[must_use]
pub fn map_declared(options: &Options, typescript: bool) -> Map {
    let plan = &options.plan;
    let commands = plan.linux_commands();
    map::build(
        &options.root,
        &Declarations {
            case_tables: &plan.case_tables,
            lanes: &plan.lanes,
            manifests: plan.manifests(),
            ignored_runs: plan
                .holds_ignored_runs()
                .then_some(plan.ignored_runs.as_slice()),
            plan_commands: &commands,
            typescript: typescript.then(|| TypeScriptRead {
                packages: plan.typescript_packages(),
                skip_directories: plan.skip_directories(),
                compiler_from: plan.compiler_from(),
                compiler: options.typescript_compiler.as_deref(),
            }),
            scripts: plan.script_directories(),
            lane_directories: plan.lane_directories(),
        },
    )
}

/// Refuses the run when a step of `steps` has a time limit and `trial`, which asks whether this
/// process can wait for a command it started, fails.
fn keeps_time_limits(
    steps: &[plan::Step],
    trial: impl FnOnce() -> Result<(), crate::tree::Trial>,
) -> Result<(), Stopped> {
    if !steps
        .iter()
        .any(|step| step.timeout.is_some() || step.budget.is_some())
    {
        return Ok(());
    }
    trial().map_err(|failed| {
        Stopped::Host(match failed {
            crate::tree::Trial::Wait(error) => format!(
                "a step has a time limit, and this process cannot wait for a command it started \
                 ({error}): a parent that ignores SIGCHLD causes this, and a time limit could then \
                 signal a process that is not the step's; start kr-conformance from a parent that \
                 does not ignore SIGCHLD"
            ),
            crate::tree::Trial::Start(error) => format!(
                "a step has a time limit, and this process could not start a command to find \
                 whether it can wait for one ({error})"
            ),
        })
    })
}

/// Runs everything `options` asks for.
///
/// # Errors
///
/// Returns why the run stopped before it ran anything: a mention the grammar refuses, or a map
/// that cannot be trusted.
pub fn run(options: &Options, progress: &mut dyn FnMut(&str)) -> Result<Document, Stopped> {
    let started = timestamp();
    let map = map_for(options);
    if !map.refused.is_empty() {
        return Err(Stopped::Refused(map.refused));
    }
    if !map.problems.is_empty() {
        return Err(Stopped::Problems(map.problems));
    }
    let groups = selected_groups(options);
    // The report's own files are all made new for this run, so nothing an earlier run left can be
    // read as this run's: a directory that already holds a report is refused.
    let own = options.evidence.join("conformance");
    if let Err(error) = std::fs::create_dir(&own) {
        return Err(Stopped::Evidence(
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                format!(
                    "{} holds an earlier run's report; each run takes an evidence directory of its \
                     own",
                    own.display()
                )
            } else {
                format!("{} could not be made: {error}", own.display())
            },
        ));
    }
    let logs = own.join("logs");
    std::fs::create_dir(&logs).map_err(|error| {
        Stopped::Evidence(format!("{} could not be made: {error}", logs.display()))
    })?;
    let mut problems = Vec::new();
    let before = evidence::before(&options.evidence).unwrap_or_else(|problem| {
        problems.push(problem);
        evidence::Before::default()
    });
    let evidence_text = options.evidence.to_string_lossy().replace('\\', "/");
    let applications_plan = options
        .applications
        .as_ref()
        .map(|applications| ApplicationsPlan {
            left_out: applications
                .iter()
                .filter(|application| application.status != "installed")
                .map(|application| {
                    (
                        application.id.clone(),
                        application
                            .reason
                            .clone()
                            .unwrap_or_else(|| format!("{} is not installed here", application.id)),
                    )
                })
                .collect(),
        });
    // A step runs in a directory of the root, so a root given relative to the working directory
    // reaches it only as an absolute path.
    let root_text = std::path::absolute(&options.root)
        .unwrap_or_else(|_| options.root.clone())
        .to_string_lossy()
        .replace('\\', "/");
    let scratch_path = scratch::path_in(&options.runner_base);
    let scratch_text = scratch_path.to_string_lossy().replace('\\', "/");
    let steps = options.plan.steps(
        options.platform,
        &groups,
        &Values {
            evidence: &evidence_text,
            root: &root_text,
            scratch: &scratch_text,
        },
        applications_plan.as_ref(),
    );
    let steps = match options.part {
        Some(part) => {
            if let Some(id) = plan::budget_across_parts(&steps, part.1) {
                return Err(Stopped::Plan(format!(
                    "the steps of budget `{id}` fall in more than one part: a budget's steps run in one part"
                )));
            }
            plan::part_of(steps, part)
        }
        None => steps,
    };
    keeps_time_limits(&steps, crate::tree::waits_for_its_commands)?;
    let runner = runner_copy::private_copy(
        &options.lister,
        &options.runner_base,
        &build_directories(options, &steps),
    )
    .map_err(Stopped::PrivateCopy)?;
    // Held until the result is made: the directory is removed when the run ends.
    let _scratch = Scratch::make(scratch_path, &options.evidence).map_err(Stopped::Scratch)?;
    let runner_records = runner
        .parent()
        .map_or_else(PathBuf::new, |directory| directory.join(run::REFUSALS));
    let mut executed = Vec::new();
    let mut budgets = Budgets::default();
    for (index, step) in steps.iter().enumerate() {
        progress(&format!(
            "step {} of {}: {} ({})",
            index + 1,
            steps.len(),
            step.what,
            step.line()
        ));
        let directory = if step.directory.is_empty() {
            options.root.clone()
        } else {
            options.root.join(&step.directory)
        };
        let environment: Vec<(String, String)> = options
            .environment
            .iter()
            .chain(&step.env)
            .cloned()
            .collect();
        let began = Instant::now();
        let mut deadline = None;
        let mut done = match failed_set_up(step, &executed) {
            Some((number, what, why)) => run::not_run(step, number, &what, &why),
            None => match budgets.deadline(step, began) {
                Err(by) => run::not_run_for_budget(step, by),
                Ok(limit) => {
                    deadline = limit;
                    run::execute(
                        step,
                        index + 1,
                        &run::Place {
                            root: &options.root,
                            directory: &directory,
                            evidence: &options.evidence,
                            environment: &environment,
                            lister: &runner,
                            deadline,
                        },
                        &map.packages,
                    )
                }
            },
        };
        spend_budget(
            &mut budgets,
            step,
            index + 1,
            &done,
            began.elapsed(),
            deadline,
        );
        if done.blocked.is_none() && (done.error.is_some() || done.exit != Some(0)) {
            done.observation = observe::observe_log(
                &options.evidence.join(&done.log),
                &runner_records,
                index + 1,
                SystemTime::now(),
            );
        }
        progress(&format!(
            "  exit {} in {} s{}",
            done.exit
                .map_or_else(|| "none".to_owned(), |code| code.to_string()),
            done.seconds,
            done.error
                .as_ref()
                .map(|error| format!(": {error}"))
                .unwrap_or_default()
        ));
        executed.push(done);
    }
    let known = evidence::known_differences(&options.evidence, &before).unwrap_or_else(|problem| {
        problems.push(problem);
        Vec::new()
    });
    let figures = evidence::figures(&options.evidence, &before).unwrap_or_else(|problem| {
        problems.push(problem);
        BTreeMap::new()
    });
    let gathered = Gathered {
        figures,
        known,
        problems,
    };
    Ok(assemble(
        options, &groups, &map, &executed, gathered, started,
    ))
}

/// Takes the result `done` of `step`, the `number`th of the run, which took `elapsed` under
/// `deadline`, into account in `budgets`. A step that was not run took no time, and spends none of
/// its budget, whatever `elapsed` says; a step that its budget's deadline ended spends all of it.
fn spend_budget(
    budgets: &mut Budgets,
    step: &plan::Step,
    number: usize,
    done: &Executed,
    elapsed: Duration,
    deadline: Option<Deadline>,
) {
    budgets.spend(
        step,
        number,
        elapsed,
        done.blocked.is_none(),
        done.timed_out && deadline.is_some_and(|deadline| deadline.budget),
    );
}

/// The first set-up step that `step` names in `after` and that did not exit 0, could not be run or
/// read, or was not run because a set-up step of its own failed: its number, what it runs and what
/// became of it. A set-up step that has not run is not one:
/// the plan puts each before the steps that name it.
fn failed_set_up(step: &plan::Step, executed: &[Executed]) -> Option<(usize, String, String)> {
    step.after.iter().find_map(|name| {
        let (index, set_up) = executed
            .iter()
            .enumerate()
            .find(|(_, done)| done.step.id == *name)?;
        let why = match (set_up.blocked, &set_up.error, set_up.exit) {
            (Some(Blocked::SetUp(blocker)), _, _) => {
                format!("was not run, because its set-up step {blocker} did not succeed")
            }
            (Some(Blocked::Budget(by)), _, _) => {
                format!("was not run, because its budget was spent by step {by}")
            }
            (None, Some(error), _) => format!("could not be run or read: {error}"),
            (None, None, Some(0)) => return None,
            (None, None, Some(code)) => format!("exited with status {code}"),
            (None, None, None) => "ended without an exit status".to_owned(),
        };
        Some((index + 1, set_up.step.what.clone(), why))
    })
}

/// What the tests left in the evidence directory during a run.
#[derive(Clone, Debug, Default)]
pub struct Gathered {
    /// The figures, by identifier.
    pub figures: BTreeMap<Identifier, Vec<Figure>>,
    /// The known differences.
    pub known: Vec<KnownDifference>,
    /// What could not be read.
    pub problems: Vec<String>,
}

/// Builds the result from what ran.
#[must_use]
pub fn assemble(
    options: &Options,
    groups: &[String],
    map: &Map,
    executed: &[Executed],
    gathered: Gathered,
    started: String,
) -> Document {
    let Gathered {
        mut figures,
        known,
        mut problems,
    } = gathered;
    problems.extend(unowned_lane_cases(options, map, executed));
    let resolver = Resolver::new(options, groups, map, executed, &known);
    problems.extend(resolver.ran_without_cover());
    // The identifiers of each test that recorded a known difference.
    let mut recorded: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut identifiers = BTreeMap::new();
    let mut all: BTreeSet<Identifier> = map.identifiers();
    if options.selection.is_none() && options.plan.list_table_rows {
        all.extend(Identifier::table_rows());
    }
    let mut summary = Summary::default();
    for identifier in all {
        let mut tests = Vec::new();
        // A test keyed twice, by its own comment and by its module's, is one test: the first
        // key, the most particular, is the one recorded.
        let mut seen = BTreeSet::new();
        for (place, key) in map.keys.get(&identifier).into_iter().flatten() {
            for record in resolver.resolve(place, key) {
                if (options.selection.is_none() || resolver.selected(place))
                    && seen.insert(record.test.clone())
                {
                    tests.push(record);
                }
            }
        }
        let references: Vec<Reference> = map
            .references
            .get(&identifier)
            .map(|references| references.iter().cloned().collect())
            .unwrap_or_default();
        let figures = figures.remove(&identifier).unwrap_or_default();
        if options.selection.is_some() && tests.is_empty() && figures.is_empty() {
            continue;
        }
        let mut counts = Counts::default();
        for test in &tests {
            counts.add(&test.outcome);
            summary.tests.add(&test.outcome);
            if !test.known_differences.is_empty() {
                recorded
                    .entry(test.test.clone())
                    .or_default()
                    .insert(identifier.to_string());
            }
        }
        let verdict = if counts.failed > 0 {
            Verdict::Failed
        } else if counts.passed > 0 {
            Verdict::Passed
        } else if counts.known_difference > 0 {
            Verdict::KnownDifference
        } else {
            Verdict::NotRun
        };
        match verdict {
            Verdict::Failed => summary.failed += 1,
            Verdict::Passed => summary.passed += 1,
            Verdict::KnownDifference => summary.known_difference += 1,
            Verdict::NotRun => summary.not_run += 1,
        }
        summary.identifiers += 1;
        identifiers.insert(
            identifier.to_string(),
            IdentifierRecord {
                family: identifier.family(),
                verdict,
                counts,
                tests,
                references,
                figures,
            },
        );
    }
    let failures_outside_identifiers = resolver.failures_outside(map);
    let known_differences: Vec<KnownDifferenceEntry> = known
        .iter()
        .map(|difference| {
            let test = format!(
                "{} {}",
                TargetId {
                    package: difference.package.clone(),
                    kind: TargetKind::Test,
                    name: difference.target.clone(),
                },
                difference.test
            );
            KnownDifferenceEntry {
                identifiers: recorded.get(&test).into_iter().flatten().cloned().collect(),
                difference: difference.clone(),
            }
        })
        .collect();
    summary.known_differences = known_differences.len();
    summary.failed_steps = executed
        .iter()
        .enumerate()
        .filter(|(_, step)| {
            step.error.is_some()
                || step.exit != Some(0)
                || step.binaries.iter().any(|(target, binary)| {
                    // A binary with a harness of its own prints nothing to read; its exit status is
                    // the step's.
                    target
                        .as_ref()
                        .is_some_and(|target| run::has_harness(&map.packages, target))
                        && !binary.readable()
                })
        })
        .map(|(index, _)| index + 1)
        .collect();
    (summary.failed_with_damage_seen, summary.failed_otherwise) =
        summary.failed_steps.iter().partition(|step| {
            executed[**step - 1]
                .observation
                .as_ref()
                .is_some_and(Observed::damage_seen)
        });
    let javascript = options.plan.uses_javascript_tools(options.platform, groups);
    let mut toolchain = identity::toolchain(&options.root, javascript);
    toolchain.typescript.clone_from(&map.typescript_version);
    for step in executed {
        if matches!(step.step.reading, plan::Reading::Lane(_)) {
            for (name, value) in &step.tools {
                toolchain
                    .phones
                    .entry(name.clone())
                    .or_insert_with(|| value.clone());
            }
        }
    }
    let mut packages: Vec<PackageVersion> = map
        .packages
        .iter()
        .map(|package| PackageVersion {
            name: package.name.clone(),
            version: package.version.clone(),
        })
        .collect();
    packages.extend(identity::typescript_packages(
        &options.root,
        options.plan.typescript_packages(),
    ));
    packages.sort();
    Document {
        schema: SCHEMA,
        repository: options.plan.repository.clone(),
        run: RunRecordHeader {
            started,
            finished: timestamp(),
            platform: options.platform.name().to_owned(),
            system: identity::system(&options.root),
            commit: identity::commit(&options.root),
            toolchain,
            terminal_profile: options
                .plan
                .terminal_profile
                .as_ref()
                .map(|file| identity::terminal_profile(&options.root, &file.path)),
            packages,
            applications: options.applications.clone(),
            selection: groups.to_vec(),
            part: options
                .part
                .map(|(number, parts)| format!("{number}/{parts}")),
            all_terminals: options.all_terminals,
            evidence_directory: options.evidence.to_string_lossy().replace('\\', "/"),
        },
        steps: executed
            .iter()
            .enumerate()
            .map(|(index, step)| StepRecord {
                number: index + 1,
                group: step.step.group.clone(),
                what: step.step.what.clone(),
                command: step.step.line(),
                needs: step.step.needs.clone(),
                exit: step.exit,
                seconds: step.seconds,
                log: step.log.clone(),
                error: step.error.clone(),
                observation: step.observation.clone(),
            })
            .collect(),
        identifiers,
        failures_outside_identifiers,
        known_differences,
        problems,
        terminals: options.all_terminals.then(|| {
            options
                .plan
                .terminals
                .iter()
                .flat_map(|terminals| {
                    terminals.names.iter().map(|terminal| TerminalRecord {
                        terminal: terminal.clone(),
                        outcome: Outcome::NotRun,
                        reason: terminals.reason.clone(),
                    })
                })
                .collect()
        }),
        warnings: map.warnings.clone(),
        summary,
    }
}

/// The classes a lane's tool reported that cannot be given to exactly one file of the lane, each
/// with why: no file declares it, or more than one does.
///
/// The files' classes come from reading their sources, which can go wrong in ways no reading can
/// rule out. A case whose class cannot be given to one file fails every file of its lane (see
/// `Resolver::lane`), so a class the reading missed, or listed twice, cannot show as a pass. The
/// limit: a class the reading gives to exactly one file, and the wrong one, stays attributed to
/// that file. That takes a class missed in its own file and listed in another, two misreadings that
/// agree; the case then counts for the other file's rows, and a failure of it still fails the run
/// (it fails those rows, or is listed among the failures outside any row).
fn unattributed_classes(map: &Map, options: &Options, step: &Executed) -> Vec<String> {
    let (Some(cases), plan::Reading::Lane(tests)) = (&step.lane, &step.step.reading) else {
        return Vec::new();
    };
    let files: Vec<&Vec<String>> = map
        .lane_classes
        .iter()
        .filter(|(file, _)| {
            options
                .plan
                .lanes
                .iter()
                .any(|lane| lane.reads == Some(*tests) && plan::matches(&lane.files, file))
        })
        .map(|(_, classes)| classes)
        .collect();
    let classes: BTreeSet<&str> = cases.iter().map(|case| case.class.as_str()).collect();
    classes
        .into_iter()
        .filter_map(|class| {
            match files
                .iter()
                .filter(|declared| lane::declares(declared, class))
                .count()
            {
                1 => None,
                0 => Some(format!("{class}, which no file of the lane declares")),
                _ => Some(format!(
                    "{class}, which more than one file of the lane declares"
                )),
            }
        })
        .collect()
}

/// What is wrong with the cases the lanes' tools reported, as problems of the result.
fn unowned_lane_cases(options: &Options, map: &Map, executed: &[Executed]) -> Vec<String> {
    executed
        .iter()
        .enumerate()
        .flat_map(|(index, step)| {
            unattributed_classes(map, options, step)
                .into_iter()
                .map(move |why| format!("step {}: the lane reported {why}", index + 1))
        })
        .collect()
}

/// Whether a key of `part` covers a case the lane's tool reported, among the cases of the classes
/// of the file the key is in: all of them for the file, those of one class (and the classes nested
/// in it) for a class, one case for a test.
fn covers(part: &Part, case: &lane::Case) -> bool {
    match part {
        Part::File => true,
        Part::Class(class) => lane::declares(std::slice::from_ref(class), &case.class),
        Part::Case { class, name } => case.class == *class && case.name == *name,
    }
}

/// Resolves keyed places to outcomes against what ran.
struct Resolver<'a> {
    options: &'a Options,
    groups: &'a [String],
    map: &'a Map,
    executed: &'a [Executed],
    /// For each target, the steps whose binaries of it ran, with those binaries.
    ran: BTreeMap<&'a TargetId, Vec<(usize, &'a crate::libtest::Binary)>>,
    /// For each step, the targets its command selects in its workspace: none for a step that does
    /// not read the output of `cargo test`.
    covered: Vec<BTreeSet<TargetId>>,
    /// The known differences each test recorded, by the test's package, target and name.
    known: BTreeMap<(&'a str, &'a str, &'a str), Vec<&'a KnownDifference>>,
}

impl<'a> Resolver<'a> {
    fn new(
        options: &'a Options,
        groups: &'a [String],
        map: &'a Map,
        executed: &'a [Executed],
        known: &'a [KnownDifference],
    ) -> Self {
        let mut recorded: BTreeMap<(&str, &str, &str), Vec<&KnownDifference>> = BTreeMap::new();
        for difference in known {
            recorded
                .entry((&difference.package, &difference.target, &difference.test))
                .or_default()
                .push(difference);
        }
        let mut ran: BTreeMap<&TargetId, Vec<(usize, &crate::libtest::Binary)>> = BTreeMap::new();
        for (index, step) in executed.iter().enumerate() {
            for (target, binary) in &step.binaries {
                if let Some(target) = target {
                    ran.entry(target).or_default().push((index, binary));
                }
            }
        }
        Self {
            options,
            groups,
            map,
            executed,
            ran,
            covered: executed
                .iter()
                .map(|done| covered_by(&done.step, &map.packages))
                .collect(),
            known: recorded,
        }
    }

    /// Whether a place belongs to the selected groups.
    fn selected(&self, place: &Place) -> bool {
        match place {
            Place::Rust { target, .. } | Place::RustModule { target, .. } => {
                self.covered.iter().any(|targets| targets.contains(target))
            }
            Place::TypeScript { package, .. } => {
                self.options.plan.selects_package(self.groups, package)
            }
            Place::Lane { file, .. } => self.options.plan.selects_lane_file(self.groups, file),
        }
    }

    fn resolve(&self, place: &Place, key: &map::Key) -> Vec<TestRecord> {
        match place {
            Place::Rust { target, name } => vec![self.rust(target, name, key)],
            Place::RustModule { target, module } => self
                .module_tests(target, module)
                .into_iter()
                .map(|name| self.rust(target, &name, key))
                .collect(),
            Place::TypeScript {
                package,
                file,
                line,
                title,
            } => self.typescript(package, file, *line, title, key),
            Place::Lane { file, part, reason } => self.lane(file, part, reason, key),
        }
    }

    /// The records of one key of a file of a phone lane: one for each case the lane's tool reported
    /// that the key covers (see [`covers`]); or one, when this run's platform does not run the lane,
    /// when the lane's tool reported nothing, when it reported a class that no single file of the
    /// lane declares, or when it reported nothing the key covers.
    fn lane(&self, file: &str, part: &Part, reason: &str, key: &map::Key) -> Vec<TestRecord> {
        // What the record of a key that no case answers is called: the file, the class or the case,
        // so that two keys of a row that cover different things stay two records.
        let named = match part {
            Part::File => file.to_owned(),
            Part::Class(class) => format!("{file} {class}"),
            Part::Case { class, name } => format!("{file} {class}.{name}"),
        };
        let record = |test: String,
                      outcome: Outcome,
                      reason: Option<String>,
                      runs: Vec<RunRecord>,
                      command: Option<String>| TestRecord {
            test,
            source: key.source.clone(),
            keyed_by: key.binding,
            outcome,
            reason,
            runs,
            command,
            needs: Vec::new(),
            known_differences: Vec::new(),
        };
        let reads = self
            .options
            .plan
            .lanes
            .iter()
            .find(|lane| plan::matches(&lane.files, file))
            .and_then(|lane| lane.reads);
        let step = reads.and_then(|reads| {
            self.executed.iter().enumerate().find(
                |(_, step)| matches!(step.step.reading, plan::Reading::Lane(tests) if tests == reads),
            )
        });
        let Some((index, step)) = step else {
            return vec![record(
                named,
                Outcome::NotRun,
                Some(reason.to_owned()),
                Vec::new(),
                None,
            )];
        };
        let failed = |why: String| {
            let run = RunRecord {
                step: index + 1,
                outcome: Outcome::Failed,
                reason: Some(why.clone()),
            };
            vec![record(
                named.clone(),
                Outcome::Failed,
                Some(why),
                vec![run],
                None,
            )]
        };
        if let (Some(_), Some(why)) = (step.blocked, &step.error) {
            let reason = format!("the step that runs the lane's tests was {why}");
            let run = RunRecord {
                step: index + 1,
                outcome: Outcome::NotRun,
                reason: Some(reason.clone()),
            };
            return vec![record(
                named,
                Outcome::NotRun,
                Some(reason),
                vec![run],
                None,
            )];
        }
        let Some(cases) = &step.lane else {
            return failed(format!(
                "the lane's tests did not report: {}",
                step.error.clone().unwrap_or_default()
            ));
        };
        let unattributed = unattributed_classes(self.map, self.options, step);
        if !unattributed.is_empty() {
            return failed(format!(
                "the lane reported {}; a result that cannot be given to one file cannot be given to any row",
                unattributed.join("; ")
            ));
        }
        let declared = self
            .map
            .lane_classes
            .get(file)
            .map_or(&[][..], Vec::as_slice);
        let own: Vec<&lane::Case> = cases
            .iter()
            .filter(|case| lane::declares(declared, &case.class) && covers(part, case))
            .collect();
        if own.is_empty() {
            return failed(match part {
                Part::File => {
                    "the lane ran, and its results hold no test of this file's classes".to_owned()
                }
                Part::Class(class) => {
                    format!("the lane ran, and its results hold no test of the class {class}")
                }
                Part::Case { class, name } => {
                    format!("the lane ran, and its results hold no case {name} of {class}")
                }
            });
        }
        own.into_iter()
            .map(|case| {
                let run = match &case.outcome {
                    LibtestOutcome::Passed => RunRecord {
                        step: index + 1,
                        outcome: Outcome::Passed,
                        reason: None,
                    },
                    LibtestOutcome::Failed => RunRecord {
                        step: index + 1,
                        outcome: Outcome::Failed,
                        reason: case.note.clone(),
                    },
                    LibtestOutcome::Ignored(reason) => RunRecord {
                        step: index + 1,
                        outcome: Outcome::Ignored,
                        reason: reason.clone(),
                    },
                    LibtestOutcome::Skipped(line) => RunRecord {
                        step: index + 1,
                        outcome: Outcome::NotRun,
                        reason: Some(format!("it returned early and said why: {line}")),
                    },
                };
                // The step's own command, less the words that name the place it leaves its results,
                // narrowed to the one case: each script passes what follows `--` on to its tool.
                let output = step.step.output.as_deref();
                let mut words: Vec<String> = step
                    .step
                    .command
                    .iter()
                    .filter(|word| output.is_none_or(|output| !word.contains(output)))
                    .cloned()
                    .collect();
                words.push("--".to_owned());
                match reads {
                    Some(plan::Tests::Xcode) => {
                        words.push(format!("-only-testing:{}", case.selector))
                    }
                    _ => {
                        words.push("--tests".to_owned());
                        words.push(case.selector.clone());
                    }
                }
                let command = words
                    .iter()
                    .map(|word| plan::quote(word))
                    .collect::<Vec<_>>()
                    .join(" ");
                record(
                    format!("{file} {}.{}", case.class, case.name),
                    run.outcome.clone(),
                    run.reason.clone(),
                    vec![run],
                    Some(command),
                )
            })
            .collect()
    }

    /// Every test in a module of a target: what its sources declare and what its binaries listed.
    fn module_tests(&self, target: &TargetId, module: &str) -> Vec<String> {
        let under = |name: &str| module.is_empty() || name.starts_with(&format!("{module}::"));
        let mut names: BTreeSet<String> = self
            .map
            .rust_tests
            .get(target)
            .into_iter()
            .flatten()
            .filter(|name| under(name))
            .cloned()
            .collect();
        for (index, binary) in self.ran.get(target).into_iter().flatten() {
            names.extend(binary.tests.keys().filter(|name| under(name)).cloned());
            let listed = self.executed[*index].listed.get(target);
            names.extend(
                listed
                    .into_iter()
                    .flatten()
                    .filter(|name| under(name))
                    .cloned(),
            );
        }
        names.into_iter().collect()
    }

    fn rust(&self, target: &TargetId, name: &str, key: &map::Key) -> TestRecord {
        if !run::has_harness(&self.map.packages, target) {
            return TestRecord {
                test: format!("{target} {name}"),
                source: key.source.clone(),
                keyed_by: key.binding,
                outcome: Outcome::NotRun,
                reason: Some(
                    "a target with a harness of its own, which reports no test by name".to_owned(),
                ),
                runs: Vec::new(),
                command: None,
                needs: Vec::new(),
                known_differences: Vec::new(),
            };
        }
        let mut runs = Vec::new();
        for (index, binary) in self.ran.get(target).into_iter().flatten() {
            let step = &self.executed[*index].step;
            // The runner recorded, in the file it writes for this step, that it could not start this
            // test program.
            let refused = self.executed[*index]
                .observation
                .as_ref()
                .and_then(|observed| {
                    observed.programs.iter().find(|program| {
                        program.said_by_runner
                            && run::file_name(&program.path) == run::file_name(&binary.executable)
                    })
                });
            // A test of the program that failed shows that it started.
            let a_test_failed = binary
                .tests
                .values()
                .any(|outcome| *outcome == LibtestOutcome::Failed);
            let record = if let (Some(_), false, Some(program)) =
                (&binary.problem, a_test_failed, refused)
            {
                // The program was never started, so none of its tests ran.
                RunRecord {
                    step: index + 1,
                    outcome: Outcome::NotRun,
                    reason: Some(format!(
                        "the program of {target} could not be started in this step: {}; {}",
                        program.lines.first().map_or("", String::as_str),
                        program.file
                    )),
                }
            } else if let Some(problem) = &binary.problem {
                RunRecord {
                    step: index + 1,
                    outcome: Outcome::Failed,
                    reason: Some(format!(
                        "the run of {target} in this step could not be read: {problem}"
                    )),
                }
            } else if let Some(outcome) = binary.tests.get(name) {
                match outcome {
                    LibtestOutcome::Passed => RunRecord {
                        step: index + 1,
                        outcome: Outcome::Passed,
                        reason: None,
                    },
                    LibtestOutcome::Failed => RunRecord {
                        step: index + 1,
                        outcome: Outcome::Failed,
                        reason: None,
                    },
                    LibtestOutcome::Ignored(reason) => RunRecord {
                        step: index + 1,
                        outcome: Outcome::Ignored,
                        reason: Some(
                            reason
                                .clone()
                                .unwrap_or_else(|| "ignored without a reason".to_owned()),
                        ),
                    },
                    LibtestOutcome::Skipped(line) => RunRecord {
                        step: index + 1,
                        outcome: Outcome::NotRun,
                        reason: Some(format!("it returned early and said why: {line}")),
                    },
                }
            } else if let Some((_, reason)) = step
                .filter
                .as_ref()
                .filter(|(filter, _)| !name.contains(filter.as_str()))
            {
                RunRecord {
                    step: index + 1,
                    outcome: Outcome::NotRun,
                    reason: Some(reason.clone()),
                }
            } else if let Some((_, reason)) = step
                .skips
                .iter()
                .find(|(skip, _)| name.contains(skip.as_str()))
            {
                RunRecord {
                    step: index + 1,
                    outcome: Outcome::NotRun,
                    reason: Some(reason.clone()),
                }
            } else if self.executed[*index]
                .listed
                .get(target)
                .is_some_and(|names| names.contains(name))
            {
                RunRecord {
                    step: index + 1,
                    outcome: Outcome::NotRun,
                    reason: Some(filtered_reason(step)),
                }
            } else {
                RunRecord {
                    step: index + 1,
                    outcome: Outcome::NotBuilt,
                    reason: Some(format!(
                        "this platform's build of {target} has no such test"
                    )),
                }
            };
            runs.push(record);
        }
        let (mut outcome, reason) =
            combine(&runs).unwrap_or_else(|| (Outcome::NotRun, Some(self.unrun_reason(target))));
        let known: Vec<KnownDifference> = self
            .known
            .get(&(target.package.as_str(), target.name.as_str(), name))
            .filter(|_| target.kind == TargetKind::Test)
            .into_iter()
            .flatten()
            .map(|difference| (*difference).clone())
            .collect();
        // A test that held what the profile defines and recorded how an application reads it
        // otherwise is a known difference, and never a pass. A test that failed stays failed.
        if outcome == Outcome::Passed && !known.is_empty() {
            outcome = Outcome::KnownDifference;
        }
        TestRecord {
            test: format!("{target} {name}"),
            source: key.source.clone(),
            keyed_by: key.binding,
            outcome,
            reason,
            command: Some(self.rust_command(target, name, &runs)),
            needs: self.needs(target, &runs),
            runs,
            known_differences: known,
        }
    }

    /// The step a record's command is taken from: the one that ran the test (see [`reproducing`]),
    /// and where none did, the first step that selects its target.
    fn reproducing_step<'s>(
        &'s self,
        target: &'s TargetId,
        runs: &[RunRecord],
    ) -> Option<&'s Executed> {
        reproducing(runs)
            .map(|run| &self.executed[run.step - 1])
            .or_else(|| self.covering(target).next())
    }

    /// The steps whose command selects `target`, in plan order.
    fn covering<'s>(&'s self, target: &'s TargetId) -> impl Iterator<Item = &'s Executed> + 's {
        self.executed
            .iter()
            .zip(&self.covered)
            .filter(move |(_, targets)| targets.contains(target))
            .map(|(done, _)| done)
    }

    /// The variables the step its command is taken from reads, and those of its own `env` that hold
    /// a placeholder, which the run gives their values (see [`Self::reproducing_step`]).
    fn needs(&self, target: &TargetId, runs: &[RunRecord]) -> Vec<String> {
        let Some(done) = self.reproducing_step(target, runs) else {
            return Vec::new();
        };
        let mut needs = done.step.needs.clone();
        for variable in &done.step.placeholder_env {
            if !needs.contains(variable) {
                needs.push(variable.clone());
            }
        }
        needs
    }

    /// The targets a step built or ran that no step of the selection covers, each as a problem of the
    /// result: the selection rule and Cargo disagree about them, and the result says so, where a
    /// target left out of the selection would leave its results out without a word.
    fn ran_without_cover(&self) -> Vec<String> {
        let mut found: BTreeMap<&TargetId, usize> = BTreeMap::new();
        for (index, done) in self.executed.iter().enumerate() {
            let targets = done
                .binaries
                .iter()
                .filter_map(|(target, _)| target.as_ref())
                .chain(&done.built);
            for target in targets {
                if !self.covered.iter().any(|set| set.contains(target)) {
                    found.entry(target).or_insert(index + 1);
                }
            }
        }
        found
            .into_iter()
            .map(|(target, step)| {
                format!(
                    "step {step} built or ran {target}, but no step of this selection covers it: \
                     the selection rule and Cargo disagree"
                )
            })
            .collect()
    }

    /// What `target` reads when no step of the selection covers it: the workspace holds no step of
    /// the selection, or it holds one and none selects this target.
    fn uncovered(&self, target: &TargetId) -> &'static str {
        let workspace = self
            .map
            .packages
            .iter()
            .find(|package| package.name == target.package)
            .map_or(".", |package| package.workspace.as_str());
        if self.executed.iter().any(|done| {
            done.step.reading == plan::Reading::Cargo
                && workspace_directory(&done.step.directory) == workspace
        }) {
            "no step of this selection covers this target"
        } else {
            "no step of this selection covers this workspace"
        }
    }

    fn unrun_reason(&self, target: &TargetId) -> String {
        let plan = &self.options.plan;
        if let Some(reason) = plan.excluded_reason(self.options.platform, &target.package) {
            return reason.to_owned();
        }
        if let Some(stopped) = self
            .executed
            .iter()
            .find(|step| step.error.is_some() && step.built.contains(target))
        {
            return format!(
                "{} built this target, and no run of it can be read from that step ({})",
                named(&stopped.step),
                stopped.error.clone().unwrap_or_default()
            );
        }
        let covering: Vec<&Executed> = self.covering(target).collect();
        if let Some(failed) = covering
            .iter()
            .find(|step| step.error.is_some() && step.built.is_empty())
        {
            let why = failed.error.clone().unwrap_or_default();
            let step = named(&failed.step);
            return if failed.blocked.is_some() {
                format!("no step that ran listed this target; {step} was {why}")
            } else {
                format!("no step that ran listed this target; {step} did not build ({why})")
            };
        }
        if let Some(step) = covering.first() {
            return format!(
                "no step that ran listed this target, though {} selects it",
                named(&step.step)
            );
        }
        // Only the groups that run Rust targets say why a Rust target was not run.
        let absent = plan.unrun_rust_reason(self.options.platform, self.groups);
        let covers = self.uncovered(target);
        let base = match (target.kind, absent) {
            (TargetKind::Bench, _) => format!("{}, and {covers}", plan.unrun.bench),
            (_, Some(reason)) => format!("{covers}; {reason}"),
            _ => covers.to_owned(),
        };
        match self.options.part {
            Some((number, parts)) => format!(
                "{base}; this run is part {number} of {parts} of the platform's plan, and another part may run it"
            ),
            None => base,
        }
    }

    /// The command that reproduces a Rust test: the step that ran it, or the first that selects its
    /// target where none did, narrowed to the test's target and the test, and to its package where the
    /// step selects no other package. It runs in the directory of the package's workspace, with the
    /// variables the step sets that hold no placeholder, the step's features and profile, and the
    /// options the step passes the test binary.
    fn rust_command(&self, target: &TargetId, name: &str, runs: &[RunRecord]) -> String {
        let step = self.reproducing_step(target, runs).map(|done| &done.step);
        let mut line = String::new();
        if let Some(directory) = self
            .map
            .packages
            .iter()
            .find(|package| package.name == target.package)
            .map(|package| package.workspace.as_str())
            .filter(|directory| !matches!(*directory, "" | "."))
        {
            line.push_str(&format!("cd {} && ", plan::quote(directory)));
        }
        let mut words = vec!["cargo".to_owned(), "test".to_owned(), "--locked".to_owned()];
        let mut test_arguments: Vec<String> = Vec::new();
        let mut package_named = false;
        if let Some(step) = step {
            for (variable, value) in &step.env {
                if !step.placeholder_env.contains(variable) {
                    line.push_str(&format!("{variable}={} ", plan::quote(value)));
                }
            }
            test_arguments = test_options(step);
            if let (Ok(selection), Some(package)) = (
                coverage::parse(&step.command),
                self.map
                    .packages
                    .iter()
                    .find(|package| package.name == target.package),
            ) {
                let members: Vec<&Package> = self
                    .map
                    .packages
                    .iter()
                    .filter(|member| member.workspace == package.workspace)
                    .collect();
                words.extend(selection.reproduce(package, &members, &step.placeholder_words));
                package_named = true;
            }
        }
        if !package_named {
            words.extend(["-p".to_owned(), target.package.clone()]);
        }
        words.extend(
            target
                .kind
                .selector(&target.name)
                .split(' ')
                .map(str::to_owned),
        );
        words.push("--".to_owned());
        words.extend(test_arguments);
        words.push("--exact".to_owned());
        words.push(name.to_owned());
        line.push_str(
            &words
                .iter()
                .map(|word| plan::quote(word))
                .collect::<Vec<_>>()
                .join(" "),
        );
        line
    }

    /// The records of one keyed TypeScript test: one for each test the run reported at its
    /// location, each under the titles the run gave it, since a table of tests declared by one
    /// call is several tests; or one record, when the run reported none there.
    fn typescript(
        &self,
        package: &str,
        file: &str,
        line: usize,
        title: &str,
        key: &map::Key,
    ) -> Vec<TestRecord> {
        let relative = file.strip_prefix(&format!("{package}/")).unwrap_or(file);
        let record = |test: String,
                      outcome: Outcome,
                      reason: Option<String>,
                      runs: Vec<RunRecord>,
                      command: Option<String>| TestRecord {
            test,
            source: key.source.clone(),
            keyed_by: key.binding,
            outcome,
            reason,
            command,
            needs: Vec::new(),
            runs,
            known_differences: Vec::new(),
        };
        let command = |pattern: String| {
            format!(
                "pnpm --dir {} exec vitest run {} -t {}",
                plan::quote(package),
                plan::quote(relative),
                plan::quote(&pattern)
            )
        };
        let unreported = command(escape_pattern(title));
        if let Some(lane) = self
            .options
            .plan
            .lanes
            .iter()
            .find(|lane| plan::matches(&lane.files, file))
        {
            return vec![record(
                format!("{file} {title}"),
                Outcome::NotBuilt,
                Some(lane.reason.clone()),
                Vec::new(),
                None,
            )];
        }
        let step = self.executed.iter().enumerate().find(|(_, step)| {
            matches!(&step.step.reading, plan::Reading::Vitest { directory } if directory == package)
        });
        let Some((index, step)) = step else {
            let reason = self
                .options
                .plan
                .typescript_unrun_reason(self.options.platform, self.groups)
                .to_owned();
            return vec![record(
                format!("{file} {title}"),
                Outcome::NotRun,
                Some(reason),
                Vec::new(),
                Some(unreported),
            )];
        };
        if let (Some(_), Some(why)) = (step.blocked, &step.error) {
            let run = RunRecord {
                step: index + 1,
                outcome: Outcome::NotRun,
                reason: Some(format!("the step that runs the package's tests was {why}")),
            };
            return vec![record(
                format!("{file} {title}"),
                Outcome::NotRun,
                run.reason.clone(),
                vec![run],
                Some(unreported),
            )];
        }
        let Some(results) = &step.vitest else {
            let run = RunRecord {
                step: index + 1,
                outcome: Outcome::Failed,
                reason: Some(format!(
                    "the package's tests did not report: {}",
                    step.error.clone().unwrap_or_default()
                )),
            };
            return vec![record(
                format!("{file} {title}"),
                Outcome::Failed,
                run.reason.clone(),
                vec![run],
                Some(unreported),
            )];
        };
        let Some(cases) = results.get(&(file.to_owned(), line)) else {
            let run = RunRecord {
                step: index + 1,
                outcome: Outcome::NotRun,
                reason: Some("the package's test script did not report this test".to_owned()),
            };
            return vec![record(
                format!("{file} {title}"),
                Outcome::NotRun,
                run.reason.clone(),
                vec![run],
                Some(unreported),
            )];
        };
        cases
            .iter()
            .zip(case_names(file, cases))
            .map(|(case, test)| {
                let run = match &case.outcome {
                    LibtestOutcome::Passed => RunRecord {
                        step: index + 1,
                        outcome: Outcome::Passed,
                        reason: None,
                    },
                    LibtestOutcome::Failed => RunRecord {
                        step: index + 1,
                        outcome: Outcome::Failed,
                        reason: None,
                    },
                    LibtestOutcome::Ignored(reason) => RunRecord {
                        step: index + 1,
                        outcome: Outcome::Ignored,
                        reason: reason.clone(),
                    },
                    LibtestOutcome::Skipped(line) => RunRecord {
                        step: index + 1,
                        outcome: Outcome::NotRun,
                        reason: Some(format!("it returned early and said why: {line}")),
                    },
                };
                // Vitest matches a pattern against the titles joined by ` > `, outermost first.
                let pattern = format!(
                    "^{}$",
                    case.titles
                        .iter()
                        .map(|title| escape_pattern(title))
                        .collect::<Vec<_>>()
                        .join(" > ")
                );
                record(
                    test,
                    run.outcome.clone(),
                    run.reason.clone(),
                    vec![run],
                    Some(command(pattern)),
                )
            })
            .collect()
    }

    /// Tests that failed in some step and are keyed to no identifier.
    fn failures_outside(&self, map: &Map) -> Vec<String> {
        let keyed: BTreeSet<(&TargetId, &str)> = map
            .keys
            .values()
            .flat_map(|places| places.keys())
            .filter_map(|place| match place {
                Place::Rust { target, name } => Some((target, name.as_str())),
                _ => None,
            })
            .collect();
        let modules: Vec<(&TargetId, &str)> = map
            .keys
            .values()
            .flat_map(|places| places.keys())
            .filter_map(|place| match place {
                Place::RustModule { target, module } => Some((target, module.as_str())),
                _ => None,
            })
            .collect();
        let mut failed = BTreeSet::new();
        for (index, step) in self.executed.iter().enumerate() {
            for (target, binary) in &step.binaries {
                for (name, outcome) in &binary.tests {
                    if *outcome != LibtestOutcome::Failed {
                        continue;
                    }
                    let covered = target.as_ref().is_some_and(|target| {
                        keyed.contains(&(target, name.as_str()))
                            || modules.iter().any(|(module_target, module)| {
                                *module_target == target
                                    && (module.is_empty()
                                        || name.starts_with(&format!("{module}::")))
                            })
                    });
                    if !covered {
                        let where_ = target
                            .as_ref()
                            .map_or_else(|| binary.executable.clone(), ToString::to_string);
                        failed.insert(format!("step {}: {where_} {name}", index + 1));
                    }
                }
            }
            // A lane's case is compared with the keyed files of the step's own lane only: a class
            // of another lane that has the same name is not its class.
            let own_lane = |file: &str| match &step.step.reading {
                plan::Reading::Lane(tests) => self
                    .options
                    .plan
                    .lanes
                    .iter()
                    .any(|lane| lane.reads == Some(*tests) && plan::matches(&lane.files, file)),
                _ => false,
            };
            for case in step.lane.iter().flatten() {
                let keyed_class = map.keys.values().flat_map(|places| places.keys()).any(|place| {
                    matches!(place, Place::Lane { file, part, .. }
                        if own_lane(file)
                            && map.lane_classes.get(file).is_some_and(|classes| lane::declares(classes, &case.class))
                            && covers(part, case))
                });
                if case.outcome == LibtestOutcome::Failed && !keyed_class {
                    failed.insert(format!("step {}: {} {}", index + 1, case.class, case.name));
                }
            }
            if let Some(results) = &step.vitest {
                for ((file, line), cases) in results {
                    let covered = map.keys.values().flat_map(|places| places.keys()).any(|place| {
                        matches!(place, Place::TypeScript { file: f, line: l, .. } if f == file && l == line)
                    });
                    for case in cases {
                        if case.outcome == LibtestOutcome::Failed && !covered {
                            failed.insert(format!(
                                "step {}: {file}:{line} {}",
                                index + 1,
                                case.titles.join(" > ")
                            ));
                        }
                    }
                }
            }
        }
        failed.into_iter().collect()
    }
}

/// The name of each test a run reported at one place: the file and the titles the run gave it.
/// Rows of one table can share a title; each is a test of its own, told apart by its place among
/// the rows with that title, and the command that selects the title runs them all.
fn case_names(file: &str, cases: &[crate::vitest::Case]) -> Vec<String> {
    cases
        .iter()
        .enumerate()
        .map(|(at, case)| {
            let titles = case.titles.join(" > ");
            let rows = cases
                .iter()
                .filter(|other| other.titles == case.titles)
                .count();
            if rows > 1 {
                let row = cases[..=at]
                    .iter()
                    .filter(|other| other.titles == case.titles)
                    .count();
                format!("{file} {titles} (row {row} of the {rows} with this title)")
            } else {
                format!("{file} {titles}")
            }
        })
        .collect()
}

/// The directory of a step's workspace as a package names it: `.` for the repository's root.
fn workspace_directory(directory: &str) -> &str {
    if directory.is_empty() { "." } else { directory }
}

/// The targets that `step`'s command selects in the workspace it runs in: none for a step that does
/// not read the output of `cargo test`, or whose command the loader would have refused.
fn covered_by(step: &plan::Step, packages: &[Package]) -> BTreeSet<TargetId> {
    if step.reading != plan::Reading::Cargo {
        return BTreeSet::new();
    }
    let Ok(selection) = coverage::parse(&step.command) else {
        return BTreeSet::new();
    };
    let here = workspace_directory(&step.directory);
    let members: Vec<&Package> = packages
        .iter()
        .filter(|package| package.workspace == here)
        .collect();
    selection.covers(&members)
}

/// The options a step passes to each test binary, as a command that runs one test repeats them, each
/// with its value. The filters, the options that choose or list tests (`--exact`, `--skip`, `--list`),
/// `--show-output` and `--logfile` go, and so does an option, with its value, whose word holds a
/// placeholder, because the run gives a placeholder its value. The options that take a value are those
/// of the standard test harness: `--skip`, `--logfile`, `--test-threads`, `--color`, `--format`,
/// `--shuffle-seed` and `-Z`, as `--option value` or `--option=value`.
fn test_options(step: &plan::Step) -> Vec<String> {
    let Some(start) = step.command.iter().position(|word| word == "--") else {
        return Vec::new();
    };
    let held = |index: usize| step.placeholder_words.contains(&index);
    let mut kept = Vec::new();
    let mut at = start + 1;
    while at < step.command.len() {
        let index = at;
        let word = step.command[index].as_str();
        at += 1;
        let (name, inline) = match word.split_once('=') {
            Some((name, value)) if word.starts_with("--") => (name, Some(value)),
            _ => (word, None),
        };
        if matches!(
            name,
            "--skip"
                | "--logfile"
                | "--test-threads"
                | "--color"
                | "--format"
                | "--shuffle-seed"
                | "-Z"
        ) {
            let operand = if inline.is_none() && at < step.command.len() {
                at += 1;
                Some(&step.command[at - 1])
            } else {
                None
            };
            let holds = held(index) || (operand.is_some() && held(at - 1));
            if !holds && !matches!(name, "--skip" | "--logfile") {
                kept.push(word.to_owned());
                kept.extend(operand.cloned());
            }
        } else if word.starts_with('-')
            && !held(index)
            && !matches!(word, "--exact" | "--show-output" | "--list")
        {
            kept.push(word.to_owned());
        }
    }
    kept
}

/// A step as a reason names it: its command, and the directory it runs in when that is not the
/// repository's root.
fn named(step: &plan::Step) -> String {
    if step.directory.is_empty() {
        format!("`{}`", step.line())
    } else {
        format!("`cd {} && {}`", plan::quote(&step.directory), step.line())
    }
}

/// Combines a test's runs into one outcome and reason, or `None` when nothing ran it.
fn combine(runs: &[RunRecord]) -> Option<(Outcome, Option<String>)> {
    let with = |wanted: Outcome| runs.iter().filter(move |run| run.outcome == wanted);
    let reasons = |wanted: Outcome| {
        let mut reasons: Vec<String> = with(wanted).filter_map(|run| run.reason.clone()).collect();
        reasons.dedup();
        (!reasons.is_empty()).then(|| reasons.join("; "))
    };
    for outcome in [Outcome::Failed, Outcome::Passed] {
        if with(outcome.clone()).next().is_some() {
            let reason = reasons(outcome.clone());
            return Some((outcome, reason));
        }
    }
    for outcome in [Outcome::Ignored, Outcome::NotRun, Outcome::NotBuilt] {
        if with(outcome.clone()).next().is_some() {
            let reason = reasons(outcome.clone());
            return Some((outcome, reason));
        }
    }
    None
}

/// Why a step's own flags left out a test its binary holds.
fn filtered_reason(step: &plan::Step) -> String {
    let flags: Vec<&str> = step
        .command
        .iter()
        .skip_while(|word| *word != "--")
        .map(String::as_str)
        .collect();
    if flags.contains(&"--ignored") {
        "this step runs only the tests that are ignored by default; another step runs the rest"
            .to_owned()
    } else if flags.contains(&"--exact") {
        "this step runs only the tests it names".to_owned()
    } else {
        "this step's name filter left it out".to_owned()
    }
}

/// Escapes a title for a test-name pattern.
fn escape_pattern(title: &str) -> String {
    let mut escaped = String::with_capacity(title.len());
    for c in title.chars() {
        if "\\^$.|?*+()[]{}".contains(c) {
            escaped.push('\\');
        }
        escaped.push(c);
    }
    escaped
}

/// The time now, in UTC, to the second.
#[must_use]
pub fn timestamp() -> String {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    let days = i64::try_from(seconds / 86_400).unwrap_or(0);
    let rest = seconds % 86_400;
    // Days since 1970-01-01 to a civil date, by Howard Hinnant's algorithm.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rest / 3_600,
        rest % 3_600 / 60,
        rest % 60
    )
}

/// Reads the applications the fetch step recorded in its index.
///
/// # Errors
///
/// Returns why the index could not be read.
pub fn read_applications(cache: &Path) -> Result<Vec<ApplicationRecord>, String> {
    let path = cache.join("index.json");
    let text = std::fs::read_to_string(&path)
        .map_err(|error| format!("{} could not be read: {error}", path.display()))?;
    #[derive(serde::Deserialize)]
    struct Index {
        applications: Vec<ApplicationRecordWithPath>,
    }
    #[derive(serde::Deserialize)]
    struct ApplicationRecordWithPath {
        #[serde(flatten)]
        record: ApplicationRecord,
    }
    let index: Index = serde_json::from_str(&text).map_err(|error| {
        format!(
            "{} is not the index the fetch step writes: {error}",
            path.display()
        )
    })?;
    Ok(index
        .applications
        .into_iter()
        .map(|entry| entry.record)
        .collect())
}

/// The applications the lock pins, as a platform that fetches none of them records them: each
/// not run, with the reason the lock gives for `family` (`windows`, `macos` or `linux`).
///
/// # Errors
///
/// Returns why the lock could not be read.
pub fn lock_applications(
    root: &Path,
    lock: &str,
    family: &str,
) -> Result<Vec<ApplicationRecord>, String> {
    let path = root.join(lock);
    let text = std::fs::read_to_string(&path)
        .map_err(|error| format!("{} could not be read: {error}", path.display()))?;
    let lock: serde_json::Value = serde_json::from_str(&text)
        .map_err(|error| format!("{} is not JSON: {error}", path.display()))?;
    let applications = lock["applications"]
        .as_array()
        .ok_or_else(|| format!("{} lists no applications", path.display()))?;
    Ok(applications
        .iter()
        .filter(|application| application["role"] == "program")
        .map(|application| {
            let name = application["name"].as_str().unwrap_or_default();
            ApplicationRecord {
                id: application["id"].as_str().unwrap_or_default().to_owned(),
                version: application["version"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned(),
                status: "unsupported_platform".to_owned(),
                url: None,
                sha256: None,
                build: None,
                reason: Some(application["not_run"][family].as_str().map_or_else(
                    || format!("no build of {name} is pinned for this platform"),
                    str::to_owned,
                )),
            }
        })
        .collect())
}

/// The evidence directory's result file.
#[must_use]
pub fn result_path(evidence: &Path) -> PathBuf {
    evidence.join("conformance").join("result.json")
}

/// The run a test's record reproduces: the first that ran it, passed or failed, or else the first
/// that listed it. Its command and the variables that command needs both come from that run's
/// step, so a record never names a command without what the command reads.
fn reproducing(runs: &[RunRecord]) -> Option<&RunRecord> {
    runs.iter()
        .find(|run| matches!(run.outcome, Outcome::Passed | Outcome::Failed))
        .or_else(|| runs.first())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// KR-REQ-29.01, the part about reproducible commands: a run with a step that has a time limit is
    /// refused when this process cannot wait for a command it started, with the words the lead
    /// approved; a step with a budget has a limit too, and a plan with no limit asks nothing.
    #[test]
    fn a_run_with_a_time_limit_is_refused_where_a_command_cannot_be_waited_for() {
        use crate::tree::Trial;
        let error = || std::io::Error::other("the error");
        let waiting = || -> Result<(), Trial> { Err(Trial::Wait(error())) };
        let starting = || -> Result<(), Trial> { Err(Trial::Start(error())) };
        let plain = plan::Step::cargo("rust", "a step", &["test"]);
        let mut timed = plain.clone();
        timed.timeout = Some(5);
        let mut budgeted = plain.clone();
        budgeted.budget = Some(("shared".to_owned(), 10));
        let wait_words = "a step has a time limit, and this process cannot wait for a command it started (the error): a parent that ignores SIGCHLD causes this, and a time limit could then signal a process that is not the step's; start kr-conformance from a parent that does not ignore SIGCHLD";
        let start_words = "a step has a time limit, and this process could not start a command to find whether it can wait for one (the error)";
        let asked = std::cell::Cell::new(false);
        let counting = || -> Result<(), Trial> {
            asked.set(true);
            Ok(())
        };
        let mut wrong = Vec::new();
        for (what, steps) in [("a timeout", &timed), ("a budget", &budgeted)] {
            for (how, words, waits) in [
                ("a wait that failed", wait_words, true),
                ("a start that failed", start_words, false),
            ] {
                let given = keeps_time_limits(std::slice::from_ref(steps), || {
                    if waits { waiting() } else { starting() }
                });
                match given {
                    Err(Stopped::Host(said)) if said == words => {}
                    other => wrong.push(format!("{what}, {how}: gave {other:?}")),
                }
            }
        }
        if keeps_time_limits(std::slice::from_ref(&plain), waiting).is_err() {
            wrong.push("a plan with no limit was refused".to_owned());
        }
        if keeps_time_limits(std::slice::from_ref(&timed), counting).is_err() || !asked.get() {
            wrong.push("a host that waits was refused, or the trial was not run".to_owned());
        }
        assert!(wrong.is_empty(), "{wrong:#?}");
    }

    /// KR-REQ-29.01, the part about reproducible commands: the result of a step that was not run
    /// spends none of the budget its step names, whatever time the report measured around it: the
    /// next step of the budget has all of it.
    #[test]
    fn a_result_that_was_not_run_spends_none_of_its_budget_whatever_time_is_given() {
        let mut step = plan::Step::cargo("rust", "a step", &["test"]);
        step.budget = Some(("shared".to_owned(), 10));
        let blocked = run::not_run(&step, 1, "a set-up step", "failed");
        let mut budgets = Budgets::default();
        spend_budget(
            &mut budgets,
            &step,
            2,
            &blocked,
            Duration::from_secs(9),
            None,
        );
        let now = Instant::now();
        let next = budgets
            .deadline(&step, now)
            .expect("a deadline")
            .expect("a limit");
        assert_eq!(next.at.duration_since(now), Duration::from_secs(10));
    }

    #[test]
    fn the_last_line_counts_one_failed_step_in_the_singular() {
        let summary = |failed: &[usize], damaged: &[usize]| Summary {
            failed_steps: failed.to_vec(),
            failed_with_damage_seen: damaged.to_vec(),
            failed_otherwise: failed
                .iter()
                .filter(|step| !damaged.contains(step))
                .copied()
                .collect(),
            ..Summary::default()
        };
        assert_eq!(
            summary(&[1], &[1]).failure_line().unwrap(),
            "1 failed step: 1 carries an observation of a program that could not be run with \
             damage seen, 0 failed otherwise"
        );
        assert_eq!(
            summary(&[1, 2], &[1]).failure_line().unwrap(),
            "2 failed steps: 1 carries an observation of a program that could not be run with \
             damage seen, 1 failed otherwise"
        );
        assert_eq!(
            summary(&[3, 4], &[3, 4]).failure_line().unwrap(),
            "2 failed steps: 2 carry an observation of a program that could not be run with \
             damage seen, 0 failed otherwise"
        );
        assert_eq!(summary(&[], &[]).failure_line(), None);
    }

    #[test]
    fn a_failure_outweighs_a_pass_and_a_pass_outweighs_an_ignore() {
        let run = |outcome: Outcome| RunRecord {
            step: 1,
            outcome,
            reason: None,
        };
        assert_eq!(
            combine(&[run(Outcome::Passed), run(Outcome::Failed)]).map(|c| c.0),
            Some(Outcome::Failed)
        );
        assert_eq!(
            combine(&[run(Outcome::Ignored), run(Outcome::Passed)]).map(|c| c.0),
            Some(Outcome::Passed)
        );
        assert_eq!(
            combine(&[run(Outcome::Ignored), run(Outcome::NotRun)]).map(|c| c.0),
            Some(Outcome::Ignored)
        );
        assert_eq!(combine(&[]), None);
    }

    #[test]
    fn rows_that_share_a_title_are_told_apart_by_their_place_among_them() {
        let case = |title: &str| crate::vitest::Case {
            titles: vec!["relay".to_owned(), title.to_owned()],
            outcome: LibtestOutcome::Passed,
        };
        assert_eq!(
            case_names("t.test.ts", &[case("sends"), case("sends"), case("stops")]),
            [
                "t.test.ts relay > sends (row 1 of the 2 with this title)",
                "t.test.ts relay > sends (row 2 of the 2 with this title)",
                "t.test.ts relay > stops",
            ]
        );
    }

    #[test]
    fn a_timestamp_is_a_utc_instant_to_the_second() {
        let now = timestamp();
        assert_eq!(now.len(), 20, "{now}");
        assert!(now.ends_with('Z'));
        assert!(now.starts_with("20"));
    }

    #[test]
    fn a_title_is_escaped_for_a_pattern() {
        assert_eq!(escape_pattern("a (b) c.d"), "a \\(b\\) c\\.d");
    }
}
