//! The shapes a step of a plan takes, and the helpers the report applies to them.
//!
//! The repository's plan file, `conformance/plan.toml`, is read by [`crate::plan_file`]. It holds
//! the groups, the steps each platform runs, the tables and the reasons. This module holds what a
//! loaded step is: a command the report runs as it is written and records verbatim in the result,
//! with the way its output is read ([`Reading`]). It also holds the cut of a platform's steps into
//! the parts that separate runs carry out ([`part_of`]), the quoting of a command's words
//! ([`quote`]) and the matching of a file pattern ([`matches()`]).
//!
//! A test that none of the selected groups runs on this platform is reported as not run, with the
//! reason the plan file gives, and never as passed.

use std::collections::BTreeSet;

/// The platforms the report knows how to run on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    /// Linux.
    Linux,
    /// macOS.
    MacOs,
    /// Windows.
    Windows,
}

impl Platform {
    /// The platform this binary was built for.
    #[must_use]
    pub const fn current() -> Self {
        if cfg!(target_os = "macos") {
            Self::MacOs
        } else if cfg!(windows) {
            Self::Windows
        } else {
            Self::Linux
        }
    }

    /// Whether `a` and `b` name one environment variable on this platform: Windows takes names that
    /// differ only by ASCII case as one, and the others compare them as they are written.
    #[must_use]
    pub fn same_variable(self, a: &str, b: &str) -> bool {
        if self == Self::Windows {
            a.eq_ignore_ascii_case(b)
        } else {
            a == b
        }
    }

    /// Its name in the result.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Linux => "linux",
            Self::MacOs => "macos",
            Self::Windows => "windows",
        }
    }
}

/// How a step's output is read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reading {
    /// `cargo test` output: one or more test binaries, each announced by Cargo.
    Cargo,
    /// A build whose success is all there is to record.
    Build,
    /// A command whose exit status is all there is to record: the reading of a set-up step.
    Exit,
    /// A package's `test` script, reporting to the step's output, a JSON file, for the package in
    /// the directory named.
    Vitest {
        /// The package's directory, relative to the repository.
        directory: String,
    },
    /// A phone application's unit tests, which the step's script runs and leaves the results of at
    /// the step's output.
    Lane(Tests),
}

/// How a lane's tool reports the tests it ran.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Tests {
    /// Gradle's JUnit files, one for each test class, in a directory.
    Junit,
    /// The test tree `xcresulttool` prints for an Xcode run's result bundle, in one file.
    Xcode,
}

/// One command of a group.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Step {
    /// Its name, unique in the plan it was loaded from.
    pub id: String,
    /// Its group.
    pub group: String,
    /// What it runs, in a few words.
    pub what: String,
    /// The program and its arguments, as run.
    pub command: Vec<String>,
    /// Variables it reads from the environment the report was started in, which must be set.
    pub needs: Vec<String>,
    /// How its output is read.
    pub reading: Reading,
    /// A name filter the command passes to the test binaries, and why tests outside it are not
    /// run on this platform.
    pub filter: Option<(String, String)>,
    /// Tests the command leaves out by name, each with its reason.
    pub skips: Vec<(String, String)>,
    /// The directory it runs in, relative to the repository and with forward slashes; empty for
    /// the repository's root. Its build, the listing of its tests and its run all use it.
    pub directory: String,
    /// The variables it is run with beyond the report's own, by name, the plan's and its own with
    /// each placeholder given its value.
    pub env: Vec<(String, String)>,
    /// The file it writes for the report to read (a directory, for a JUnit lane), as an absolute
    /// path with forward slashes, when it names one.
    pub output: Option<String>,
    /// Whether it sets up what later steps need: the report records only its exit status, and a
    /// step that names it in `after` is not run when it failed.
    pub setup: bool,
    /// The set-up steps that run before it, by name.
    pub after: Vec<String>,
    /// The most seconds the step may take, from its start to its end, counting the build and the
    /// listing of its tests that come before its run: the report ends its processes at that time.
    pub timeout: Option<u64>,
    /// The time budget it spends from, by `id`, and the budget's seconds.
    pub budget: Option<(String, u64)>,
    /// The names in `env` whose value holds a placeholder. A command that reproduces one of the
    /// step's tests cannot repeat their values, because the run gives a placeholder its value.
    pub placeholder_env: Vec<String>,
    /// The positions in `command` of the words that hold a placeholder, for the same reason.
    pub placeholder_words: Vec<usize>,
}

impl Step {
    /// A `cargo` command of `group`, described as `what`, with the words as a plan file holds them:
    /// the words the loader adds to a command are not written here (see
    /// [`crate::plan_file::expand`]).
    #[must_use]
    pub fn cargo(group: &str, what: &str, arguments: &[&str]) -> Self {
        let mut command = vec!["cargo".to_owned()];
        command.extend(arguments.iter().map(|argument| (*argument).to_owned()));
        Self {
            id: String::new(),
            group: group.to_owned(),
            what: what.to_owned(),
            command,
            needs: Vec::new(),
            reading: Reading::Cargo,
            filter: None,
            skips: Vec::new(),
            directory: String::new(),
            env: Vec::new(),
            output: None,
            setup: false,
            after: Vec::new(),
            timeout: None,
            budget: None,
            placeholder_env: Vec::new(),
            placeholder_words: Vec::new(),
        }
    }

    /// The command as one line, the way the result records it.
    #[must_use]
    pub fn line(&self) -> String {
        self.command
            .iter()
            .map(|word| quote(word))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// Quotes a word for a POSIX shell only when it needs it.
#[must_use]
pub fn quote(word: &str) -> String {
    if !word.is_empty()
        && word
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_./:=,@+%".contains(&b))
    {
        word.to_owned()
    } else {
        format!("'{}'", word.replace('\'', "'\\''"))
    }
}

/// Whether a step is the workspace's tests: the one command that builds and runs the tests of every
/// package, which on a platform that has it is most of the plan's time and cannot be cut by count.
fn runs_the_workspace(step: &Step) -> bool {
    step.reading == Reading::Cargo && step.command.iter().any(|word| word == "--workspace")
}

/// The steps of one part of a platform's plan, for a plan that one job cannot hold and separate runs
/// carry out in parts: the build steps that open the plan, which every part needs for the programs
/// the suites start, and then the remaining steps, cut in order into parts of nearly equal count.
/// A plan that holds the workspace's tests puts that step, with the opening builds, in part 1 by
/// itself, and cuts the other steps into the remaining parts by count. `part` is the number of the
/// part from 1 and the number of parts.
///
/// A set-up step that a step of the plan names in `after` is not cut by count: it goes, in its own
/// place, into every part that holds a step naming it, directly or through another set-up step, so
/// a set-up step runs in each of those parts.
#[must_use]
pub fn part_of(steps: Vec<Step>, part: (usize, usize)) -> Vec<Step> {
    let (number, parts) = part;
    let parts = parts.max(1);
    let named: BTreeSet<&str> = steps
        .iter()
        .flat_map(|step| step.after.iter().map(String::as_str))
        .collect();
    // The steps cut by count: every step but the set-up steps that another step names.
    let cut: Vec<usize> = (0..steps.len())
        .filter(|index| !(steps[*index].setup && named.contains(steps[*index].id.as_str())))
        .collect();
    let opening = cut
        .iter()
        .take_while(|index| steps[**index].reading == Reading::Build)
        .count();
    let alone = if parts > 1 {
        cut.iter()
            .position(|index| runs_the_workspace(&steps[*index]))
            .filter(|slot| *slot >= opening)
    } else {
        None
    };
    let (share, shares) = if alone.is_some() {
        (number.saturating_sub(1), parts - 1)
    } else {
        (number, parts)
    };
    let rest = cut.len() - opening - usize::from(alone.is_some());
    let from = rest * share.saturating_sub(1) / shares;
    let to = rest * share / shares;
    let mut kept = vec![false; steps.len()];
    let mut position = 0;
    for (slot, index) in cut.iter().enumerate() {
        kept[*index] = if slot < opening || (alone == Some(slot) && number == 1) {
            true
        } else if alone == Some(slot) {
            false
        } else {
            let at = position;
            position += 1;
            (from..to).contains(&at)
        };
    }
    // A set-up step comes before the steps that name it, so one pass from the end keeps each set-up
    // step that a kept step names, and each that those name.
    for index in (0..steps.len()).rev() {
        if kept[index] {
            for name in &steps[index].after {
                if let Some(earlier) = steps.iter().position(|step| step.id == *name) {
                    kept[earlier] = true;
                }
            }
        }
    }
    steps
        .into_iter()
        .zip(kept)
        .filter_map(|(step, keep)| keep.then_some(step))
        .collect()
}

/// The variable that lets the one case that writes this machine's credential store run.
pub const SECRET_STORE_VARIABLE: &str = "KR_TEST_PLATFORM_SECRET_STORE";

/// The variable naming the cache the fetch step installed the applications into.
pub const APPLICATIONS_VARIABLE: &str = "KR_CONFORMANCE_APPLICATIONS";

/// The programs whose cases a run leaves out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApplicationsPlan {
    /// Each program with no build installed here, and why.
    pub left_out: Vec<(String, String)>,
}

/// Whether `path` matches a pattern of `*` (one component) and `**` (any number).
#[must_use]
pub fn matches(pattern: &str, path: &str) -> bool {
    fn walk(pattern: &[&str], path: &[&str]) -> bool {
        match (pattern.first(), path.first()) {
            (None, None) => true,
            (Some(&"**"), _) => {
                walk(&pattern[1..], path) || (!path.is_empty() && walk(pattern, &path[1..]))
            }
            (Some(want), Some(have)) => component(want, have) && walk(&pattern[1..], &path[1..]),
            _ => false,
        }
    }
    fn component(want: &str, have: &str) -> bool {
        match want.split_once('*') {
            None => want == have,
            Some((prefix, suffix)) => {
                have.len() >= prefix.len() + suffix.len()
                    && have.starts_with(prefix)
                    && have.ends_with(suffix)
            }
        }
    }
    let pattern: Vec<&str> = pattern.split('/').collect();
    let path: Vec<&str> = path.split('/').collect();
    walk(&pattern, &path)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Core's plan file.
    fn core_plan() -> crate::plan_file::Plan {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        crate::plan_file::Plan::load(&root, None).expect("core's plan file")
    }

    /// Every group of core's plan, in the order a full run runs them.
    fn every_group() -> Vec<String> {
        core_plan().all_groups()
    }

    /// The steps core's plan file gives, as the report runs them.
    fn steps(
        platform: Platform,
        groups: &[impl AsRef<str>],
        evidence: &str,
        applications: Option<&ApplicationsPlan>,
    ) -> Vec<Step> {
        let names: Vec<String> = groups
            .iter()
            .map(|group| group.as_ref().to_owned())
            .collect();
        core_plan().steps(
            platform,
            &names,
            &crate::plan_file::Values::evidence(evidence),
            applications,
        )
    }

    #[test]
    fn the_parts_of_a_plan_each_hold_the_opening_builds_and_together_every_other_step_once() {
        let step = |what: &str, reading: Reading| Step {
            id: String::new(),
            group: "rust".to_owned(),
            what: what.to_owned(),
            command: vec!["cargo".to_owned()],
            needs: Vec::new(),
            reading,
            filter: None,
            skips: Vec::new(),
            directory: String::new(),
            env: Vec::new(),
            output: None,
            setup: false,
            after: Vec::new(),
            timeout: None,
            budget: None,
            placeholder_env: Vec::new(),
            placeholder_words: Vec::new(),
        };
        let mut steps = vec![step("a", Reading::Build), step("b", Reading::Build)];
        steps.extend((0..7).map(|n| step(&format!("t{n}"), Reading::Cargo)));
        let names = |part| -> Vec<String> {
            part_of(steps.clone(), part)
                .into_iter()
                .map(|step| step.what)
                .collect()
        };
        assert_eq!(names((1, 2)), ["a", "b", "t0", "t1", "t2"]);
        assert_eq!(names((2, 2)), ["a", "b", "t3", "t4", "t5", "t6"]);
        assert_eq!(names((1, 1)).len(), steps.len());
    }

    fn named(id: &str, reading: Reading, setup: bool, after: &[&str]) -> Step {
        Step {
            id: id.to_owned(),
            setup,
            after: after.iter().map(|name| (*name).to_owned()).collect(),
            timeout: None,
            budget: None,
            placeholder_env: Vec::new(),
            placeholder_words: Vec::new(),
            ..step_of(id, &["cargo"], reading)
        }
    }

    #[test]
    fn a_set_up_step_goes_into_every_part_that_holds_a_step_naming_it_and_no_other() {
        let steps = vec![
            named("build", Reading::Build, false, &[]),
            named("set", Reading::Exit, true, &[]),
            named("t0", Reading::Cargo, false, &["set"]),
            named("t1", Reading::Cargo, false, &[]),
            named("t2", Reading::Cargo, false, &["set"]),
            named("t3", Reading::Cargo, false, &[]),
        ];
        let ids = |part| -> Vec<String> {
            part_of(steps.clone(), part)
                .into_iter()
                .map(|step| step.id)
                .collect()
        };
        assert_eq!(ids((1, 2)), ["build", "set", "t0", "t1"]);
        assert_eq!(ids((2, 2)), ["build", "set", "t2", "t3"]);
        assert_eq!(ids((2, 4)), ["build", "t1"]);
        assert_eq!(ids((3, 4)), ["build", "set", "t2"]);
        assert_eq!(ids((1, 1)).len(), steps.len());
    }

    #[test]
    fn a_set_up_step_that_another_set_up_step_names_goes_with_it_into_a_part() {
        let steps = vec![
            named("s1", Reading::Exit, true, &[]),
            named("s2", Reading::Exit, true, &["s1"]),
            named("a", Reading::Cargo, false, &[]),
            named("t", Reading::Cargo, false, &["s2"]),
        ];
        let ids = |part| -> Vec<String> {
            part_of(steps.clone(), part)
                .into_iter()
                .map(|step| step.id)
                .collect()
        };
        assert_eq!(ids((1, 2)), ["a"]);
        assert_eq!(ids((2, 2)), ["s1", "s2", "t"]);
    }

    fn step_of(what: &str, command: &[&str], reading: Reading) -> Step {
        Step {
            id: String::new(),
            group: "rust".to_owned(),
            what: what.to_owned(),
            command: command.iter().map(|word| (*word).to_owned()).collect(),
            needs: Vec::new(),
            reading,
            filter: None,
            skips: Vec::new(),
            directory: String::new(),
            env: Vec::new(),
            output: None,
            setup: false,
            after: Vec::new(),
            timeout: None,
            budget: None,
            placeholder_env: Vec::new(),
            placeholder_words: Vec::new(),
        }
    }

    /// Cuts `plan` into `parts` parts and holds that every part opens with the plan's opening
    /// builds and that the other steps of the parts are the plan's, each once.
    fn holds_every_step_once(plan: &[Step], parts: usize) {
        let opening = plan
            .iter()
            .take_while(|step| step.reading == Reading::Build)
            .count();
        let named = |step: &Step| format!("{} :: {}", step.what, step.line());
        let mut seen = Vec::new();
        for number in 1..=parts {
            let part = part_of(plan.to_vec(), (number, parts));
            assert!(part.len() >= opening, "part {number} of {parts}");
            let (builds, others) = part.split_at(opening);
            assert_eq!(
                builds,
                &plan[..opening],
                "builds lead part {number}/{parts}"
            );
            seen.extend(others.iter().map(named));
        }
        let mut expected: Vec<String> = plan[opening..].iter().map(named).collect();
        seen.sort();
        expected.sort();
        assert_eq!(seen, expected, "{parts} parts");
    }

    #[test]
    fn the_workspace_tests_stand_alone_in_part_one_and_the_other_steps_are_cut_by_count() {
        let mut steps = vec![
            step_of("a", &["cargo", "build"], Reading::Build),
            step_of("w", &["cargo", "test", "--workspace"], Reading::Cargo),
        ];
        steps.extend((0..7).map(|n| step_of(&format!("t{n}"), &["cargo", "test"], Reading::Cargo)));
        let names = |part| -> Vec<String> {
            part_of(steps.clone(), part)
                .into_iter()
                .map(|step| step.what)
                .collect()
        };
        assert_eq!(names((1, 2)), ["a", "w"]);
        assert_eq!(
            names((2, 2)),
            ["a", "t0", "t1", "t2", "t3", "t4", "t5", "t6"]
        );
        assert_eq!(names((1, 3)), ["a", "w"]);
        assert_eq!(names((2, 3)), ["a", "t0", "t1", "t2"]);
        assert_eq!(names((3, 3)), ["a", "t3", "t4", "t5", "t6"]);
        assert_eq!(names((1, 1)).len(), steps.len());
        for parts in 1..=3 {
            holds_every_step_once(&steps, parts);
        }
    }

    #[test]
    fn the_macos_plan_opens_with_the_worker_build_and_keeps_the_workspace_tests_alone_in_part_one()
    {
        let applications = ApplicationsPlan {
            left_out: Vec::new(),
        };
        let plan = steps(
            Platform::MacOs,
            &every_group(),
            "/tmp/e",
            Some(&applications),
        );
        assert_eq!(plan[0].reading, Reading::Build);
        assert!(plan[0].command.iter().any(|word| word == "kr-worker"));
        assert!(runs_the_workspace(&plan[1]), "{}", plan[1].line());
        assert_eq!(
            plan.iter()
                .filter(|step| step.reading == Reading::Build)
                .count(),
            1
        );
        for parts in 1..=3 {
            holds_every_step_once(&plan, parts);
        }
        assert_eq!(part_of(plan.clone(), (1, 2)), plan[..2]);
        assert_eq!(part_of(plan.clone(), (1, 1)), plan);
        let second = part_of(plan.clone(), (2, 2));
        assert_eq!(second[0], plan[0]);
        assert_eq!(second[1..], plan[2..]);
    }

    #[test]
    fn a_plan_without_the_workspace_tests_is_cut_by_count_and_empty_groups_leave_empty_parts() {
        for platform in [Platform::Linux, Platform::MacOs, Platform::Windows] {
            let plan = steps(platform, &every_group(), "/tmp/e", None);
            for parts in 1..=3 {
                holds_every_step_once(&plan, parts);
            }
        }
        let only_the_workspace = steps(Platform::MacOs, &["rust"], "/tmp/e", None);
        assert_eq!(only_the_workspace.len(), 1);
        assert_eq!(
            part_of(only_the_workspace.clone(), (1, 2)),
            only_the_workspace
        );
        assert!(part_of(only_the_workspace, (2, 2)).is_empty());
    }

    #[test]
    fn the_windows_plan_is_cut_into_the_two_parts_it_was_cut_into_before_the_workspace_rule() {
        let plan = steps(Platform::Windows, &every_group(), "/tmp/e", None);
        assert!(!plan.iter().any(runs_the_workspace));
        let mut cut = String::new();
        for number in 1..=2 {
            cut.push_str(&format!("part {number}/2\n"));
            for step in part_of(plan.clone(), (number, 2)) {
                cut.push_str(&format!("{} :: {}\n", step.what, step.line()));
            }
        }
        assert_eq!(
            cut,
            include_str!("../tests/fixtures/plan-parts/windows.txt")
        );
    }

    #[test]
    fn a_pattern_matches_one_component_per_star_and_any_number_per_double_star() {
        assert!(matches(
            "tests/shells/*/*/case.json",
            "tests/shells/zsh/fzf/case.json"
        ));
        assert!(!matches(
            "tests/shells/*/*/case.json",
            "tests/shells/zsh/case.json"
        ));
        assert!(matches(
            "fixtures/shell-bridge/*.json",
            "fixtures/shell-bridge/handshake-accept.json"
        ));
        assert!(matches(
            "apps/companion/e2e/**",
            "apps/companion/e2e/companion.spec.ts"
        ));
        assert!(matches(
            "apps/companion/native/ios/Tests/**",
            "apps/companion/native/ios/Tests/a/b.swift"
        ));
        assert!(!matches(
            "apps/companion/e2e/**",
            "apps/companion/test/a.ts"
        ));
    }

    #[test]
    fn a_word_is_quoted_only_when_a_shell_would_split_it() {
        assert_eq!(quote("--test-threads=1"), "--test-threads=1");
        assert_eq!(quote("host::scripted::"), "host::scripted::");
        assert_eq!(quote("a b"), "'a b'");
        assert_eq!(quote("it's"), "'it'\\''s'");
    }

    #[test]
    fn every_platform_runs_the_rust_group_and_windows_runs_no_unix_group() {
        for platform in [Platform::Linux, Platform::MacOs, Platform::Windows] {
            let steps = steps(platform, &every_group(), "/tmp/e", None);
            assert!(
                steps.iter().any(|step| step.group == "rust"),
                "{platform:?}"
            );
            let unix_only = steps.iter().any(|step| {
                ["end-to-end", "performance", "typescript"]
                    .iter()
                    .any(|group| step.group == *group)
            });
            assert_eq!(unix_only, platform != Platform::Windows, "{platform:?}");
        }
    }

    #[test]
    fn a_skipped_case_is_left_out_by_the_command_and_recorded_with_its_reason() {
        let steps = steps(Platform::MacOs, &["rust"], "/tmp/e", None);
        let first = &steps[0];
        assert!(!first.skips.is_empty());
        assert_eq!(
            first
                .command
                .iter()
                .filter(|word| *word == "--skip")
                .count(),
            first.skips.len()
        );
    }

    #[test]
    fn the_applications_left_out_are_skipped_by_prefix() {
        let plan = ApplicationsPlan {
            left_out: vec![("htop".to_owned(), "no build for this platform".to_owned())],
        };
        let steps = steps(Platform::Linux, &["applications"], "/tmp/e", Some(&plan));
        assert_eq!(steps.len(), 1);
        assert!(
            steps[0].line().ends_with("--skip htop::"),
            "{}",
            steps[0].line()
        );
        assert!(steps[0].line().starts_with("cargo test"));
        assert_eq!(steps[0].needs, [APPLICATIONS_VARIABLE.to_owned()]);
    }
}
