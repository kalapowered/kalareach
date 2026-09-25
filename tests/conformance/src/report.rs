//! The run: the map, the steps, every keyed test's outcome, and the result keyed by identifier.
//!
//! A test's outcome on this platform is one of five:
//!
//! * `passed` or `failed`, from a step that ran it;
//! * `ignored`, with the reason its attribute gives, when every step that listed it left it out;
//! * `not_run`, with the reason, when no step of this run ran it here: a step left it out by name,
//!   no selected group runs its target on this platform, its lane is another toolchain's, or it
//!   returned early and said why;
//! * `not_built`, when a step ran its target and this platform's build of it has no such test.
//!
//! An identifier has failed when any of its tests failed, has passed when at least one ran and
//! passed and none failed, and is not run otherwise. An ignored or skipped test is never counted as
//! passed.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::evidence::{self, Figure, KnownDifference};
use crate::id::{Family, Identifier};
use crate::identity::{self, Commit, PackageVersion, System, TerminalProfile, Toolchain};
use crate::libtest::Outcome as LibtestOutcome;
use crate::map::{self, Binding, Declarations, Map, Place, Reference};
use crate::plan::{self, ApplicationsPlan, Group, Platform};
use crate::run::{self, Executed};
use crate::workspace::{TargetId, TargetKind};

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
    /// The terminal profile.
    pub terminal_profile: TerminalProfile,
    /// The workspace's packages and the TypeScript packages, with their versions.
    pub packages: Vec<PackageVersion>,
    /// The applications, where that group ran.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub applications: Option<Vec<ApplicationRecord>>,
    /// The groups this run selected.
    pub selection: Vec<String>,
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
}

/// The result.
#[derive(Clone, Debug, Serialize)]
pub struct Document {
    /// The schema.
    pub schema: &'static str,
    /// The repository.
    pub repository: &'static str,
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
    pub selection: Option<Vec<Group>>,
    /// Whether the whole terminal matrix was asked for.
    pub all_terminals: bool,
    /// The platform.
    pub platform: Platform,
    /// The data-file case tables.
    pub case_tables: &'static [plan::CaseTable],
    /// The lanes.
    pub lanes: &'static [plan::Lane],
    /// The applications the fetch step recorded, when that group runs.
    pub applications: Option<Vec<ApplicationRecord>>,
    /// Steps to run instead of the plan's, for a tree that is not this repository.
    pub steps: Option<Vec<plan::Step>>,
    /// Variables every step is run with, beyond the report's own environment.
    pub environment: Vec<(String, String)>,
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
}

/// Builds the map for a run of `options`.
#[must_use]
pub fn map_for(options: &Options) -> Map {
    let groups = options
        .selection
        .clone()
        .unwrap_or_else(|| Group::ALL.to_vec());
    map::build(
        &options.root,
        &Declarations {
            case_tables: options.case_tables,
            lanes: options.lanes,
            typescript: groups
                .contains(&Group::TypeScript)
                .then_some(plan::TYPESCRIPT_PACKAGES),
            scripts: &["scripts"],
        },
    )
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
    let groups = options
        .selection
        .clone()
        .unwrap_or_else(|| Group::ALL.to_vec());
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
    for part in ["logs", "vitest"] {
        std::fs::create_dir(own.join(part)).map_err(|error| {
            Stopped::Evidence(format!(
                "{} could not be made: {error}",
                own.join(part).display()
            ))
        })?;
    }
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
    let steps = options.steps.clone().unwrap_or_else(|| {
        plan::steps(
            options.platform,
            &groups,
            &evidence_text,
            applications_plan.as_ref(),
        )
    });
    let mut executed = Vec::new();
    for (index, step) in steps.iter().enumerate() {
        progress(&format!(
            "step {} of {}: {} ({})",
            index + 1,
            steps.len(),
            step.what,
            step.line()
        ));
        let done = run::execute(
            step,
            index + 1,
            &run::Place {
                root: &options.root,
                evidence: &options.evidence,
                environment: &options.environment,
            },
            &map.packages,
        );
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
    groups: &[Group],
    map: &Map,
    executed: &[Executed],
    gathered: Gathered,
    started: String,
) -> Document {
    let Gathered {
        mut figures,
        known,
        problems,
    } = gathered;
    let resolver = Resolver::new(options, groups, map, executed, &known);
    // The identifiers of each test that recorded a known difference.
    let mut recorded: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut identifiers = BTreeMap::new();
    let mut all: BTreeSet<Identifier> = map.identifiers();
    if options.selection.is_none() {
        all.extend(plan::listed_rows());
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
                        && !binary.readable
                })
        })
        .map(|(index, _)| index + 1)
        .collect();
    let typescript = groups.contains(&Group::TypeScript) && options.platform != Platform::Windows;
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
        plan::TYPESCRIPT_PACKAGES,
    ));
    packages.sort();
    Document {
        schema: SCHEMA,
        repository: "kalareach",
        run: RunRecordHeader {
            started,
            finished: timestamp(),
            platform: options.platform.name().to_owned(),
            system: identity::system(&options.root),
            commit: identity::commit(&options.root),
            toolchain: identity::toolchain(&options.root, typescript),
            terminal_profile: identity::terminal_profile(&options.root),
            packages,
            applications: options.applications.clone(),
            selection: groups.iter().map(|group| group.name().to_owned()).collect(),
            all_terminals: options.all_terminals,
            evidence_directory: options.evidence.to_string_lossy().replace('\\', "/"),
        },
        steps: executed
            .iter()
            .enumerate()
            .map(|(index, step)| StepRecord {
                number: index + 1,
                group: step.step.group.name().to_owned(),
                what: step.step.what.clone(),
                command: step.step.line(),
                needs: step
                    .step
                    .needs
                    .iter()
                    .map(|need| (*need).to_owned())
                    .collect(),
                exit: step.exit,
                seconds: step.seconds,
                log: step.log.clone(),
                error: step.error.clone(),
            })
            .collect(),
        identifiers,
        failures_outside_identifiers,
        known_differences,
        problems,
        terminals: options.all_terminals.then(|| {
            plan::TERMINALS
                .iter()
                .map(|terminal| TerminalRecord {
                    terminal: (*terminal).to_owned(),
                    outcome: Outcome::NotRun,
                    reason: plan::TERMINAL_REASON.to_owned(),
                })
                .collect()
        }),
        warnings: map.warnings.clone(),
        summary,
    }
}

/// Resolves keyed places to outcomes against what ran.
struct Resolver<'a> {
    options: &'a Options,
    groups: &'a [Group],
    map: &'a Map,
    executed: &'a [Executed],
    /// For each target, the steps whose binaries of it ran, with those binaries.
    ran: BTreeMap<&'a TargetId, Vec<(usize, &'a crate::libtest::Binary)>>,
    /// Every target some step built to test.
    built: BTreeSet<&'a TargetId>,
    /// The known differences each test recorded, by the test's package, target and name.
    known: BTreeMap<(&'a str, &'a str, &'a str), Vec<&'a KnownDifference>>,
}

impl<'a> Resolver<'a> {
    fn new(
        options: &'a Options,
        groups: &'a [Group],
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
        let mut built = BTreeSet::new();
        for (index, step) in executed.iter().enumerate() {
            for (target, binary) in &step.binaries {
                if let Some(target) = target {
                    ran.entry(target).or_default().push((index, binary));
                }
            }
            built.extend(step.built.iter());
        }
        Self {
            options,
            groups,
            map,
            executed,
            ran,
            built,
            known: recorded,
        }
    }

    /// Whether a place belongs to the selected groups.
    fn selected(&self, place: &Place) -> bool {
        match place {
            Place::Rust { target, .. } | Place::RustModule { target, .. } => {
                self.ran.contains_key(target) || self.built.contains(target)
            }
            Place::TypeScript { .. } | Place::Lane { .. } => {
                self.groups.contains(&Group::TypeScript)
            }
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
            Place::Lane { file, reason } => vec![TestRecord {
                test: file.clone(),
                source: key.source.clone(),
                keyed_by: key.binding,
                outcome: Outcome::NotBuilt,
                reason: Some(reason.clone()),
                runs: Vec::new(),
                command: None,
                needs: Vec::new(),
                known_differences: Vec::new(),
            }],
        }
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
            let record = if !binary.readable {
                RunRecord {
                    step: index + 1,
                    outcome: Outcome::Failed,
                    reason: Some(format!(
                        "the output of {target} in this step could not be read against its summary"
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
            needs: self.needs(&runs),
            runs,
            known_differences: known,
        }
    }

    /// The variables the step that listed a test reads.
    fn needs(&self, runs: &[RunRecord]) -> Vec<String> {
        runs.first()
            .map(|run| {
                self.executed[run.step - 1]
                    .step
                    .needs
                    .iter()
                    .map(|need| (*need).to_owned())
                    .collect()
            })
            .unwrap_or_default()
    }

    fn unrun_reason(&self, target: &TargetId) -> String {
        if self.options.platform == Platform::MacOs
            && let Some((_, reason)) = plan::MACOS_EXCLUDED
                .iter()
                .find(|(package, _)| *package == target.package)
        {
            return (*reason).to_owned();
        }
        if let Some(failed) = self.executed.iter().find(|step| {
            step.error.is_some()
                && step.built.is_empty()
                && matches!(step.step.reading, plan::Reading::Cargo)
        }) {
            return format!(
                "no step that ran listed this target; `{}` did not build ({})",
                failed.step.line(),
                failed.error.clone().unwrap_or_default()
            );
        }
        let absent = self
            .groups
            .iter()
            .find_map(|group| plan::group_absent_reason(*group, self.options.platform));
        match (target.kind, absent) {
            (TargetKind::Bench, _) => format!(
                "a benchmark target: the performance group runs the measurements it holds, and {}",
                plan::unrun_reason(self.options.platform)
            ),
            (_, Some(reason)) if self.options.platform == Platform::Windows => {
                format!("{}; {reason}", plan::unrun_reason(self.options.platform))
            }
            _ => plan::unrun_reason(self.options.platform).to_owned(),
        }
    }

    /// The command that reproduces a Rust test: the step that ran it, narrowed to its package,
    /// its target and the test, or the ordinary `cargo test` of it where no step did.
    fn rust_command(&self, target: &TargetId, name: &str, runs: &[RunRecord]) -> String {
        let step = runs
            .iter()
            .find(|run| matches!(run.outcome, Outcome::Passed | Outcome::Failed))
            .or_else(|| runs.first())
            .map(|run| &self.executed[run.step - 1].step);
        let mut words = vec!["cargo".to_owned(), "test".to_owned(), "--locked".to_owned()];
        let mut test_arguments: Vec<String> = Vec::new();
        if let Some(step) = step {
            if step.command.iter().any(|word| word == "--release") {
                words.push("--release".to_owned());
            }
            let mut after = step
                .command
                .iter()
                .skip_while(|word| *word != "--")
                .skip(1)
                .peekable();
            while let Some(word) = after.next() {
                match word.as_str() {
                    "--skip" => {
                        after.next();
                    }
                    "--exact" | "--show-output" => {}
                    flag if flag.starts_with("--") => test_arguments.push(flag.to_owned()),
                    _ => {}
                }
            }
        }
        words.push("-p".to_owned());
        words.push(target.package.clone());
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
        words
            .iter()
            .map(|word| plan::quote(word))
            .collect::<Vec<_>>()
            .join(" ")
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
            .lanes
            .iter()
            .find(|lane| plan::matches(lane.files, file))
        {
            return vec![record(
                format!("{file} {title}"),
                Outcome::NotBuilt,
                Some(lane.reason.to_owned()),
                Vec::new(),
                None,
            )];
        }
        let step = self.executed.iter().enumerate().find(|(_, step)| {
            matches!(&step.step.reading, plan::Reading::Vitest { directory } if directory == package)
        });
        let Some((index, step)) = step else {
            let reason = plan::group_absent_reason(Group::TypeScript, self.options.platform)
                .unwrap_or("no step of this run's selection runs the TypeScript suites")
                .to_owned();
            return vec![record(
                format!("{file} {title}"),
                Outcome::NotRun,
                Some(reason),
                Vec::new(),
                Some(unreported),
            )];
        };
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
pub fn lock_applications(root: &Path, family: &str) -> Result<Vec<ApplicationRecord>, String> {
    let path = root
        .join("tests")
        .join("conformance")
        .join("applications.lock");
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

#[cfg(test)]
mod tests {
    use super::*;

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
