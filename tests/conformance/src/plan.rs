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

use std::collections::{BTreeMap, BTreeSet};

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
    /// What the step took on this platform, in seconds, when it was last measured, as the plan
    /// states it with the run it comes from. A plan whose every step that is cut, but the builds that
    /// open it, states one is cut into parts of nearly equal time by these; a plan with such a step
    /// that does not is cut by the count of its steps. An opening build runs in every part and is
    /// never placed by its time.
    pub weight: Option<u64>,
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
            weight: None,
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

/// How a plan's steps are cut into parts: which steps are cut and which of those open the plan, and
/// how the rest are shared, by their time when each states a weight (`timed`) and otherwise by
/// count, with the workspace's tests standing alone in part 1. [`part_of`] and
/// [`budget_across_parts`] place the steps by it.
struct Cut {
    /// The steps that are cut, by index: every step but the set-up steps that another step names.
    steps: Vec<usize>,
    /// How many of them open the plan: the builds that every part runs.
    opening: usize,
    /// For a plan cut by count, the place among them of the workspace's tests, which stand alone in
    /// part 1 when the plan has more than one part. None when the plan is cut by time.
    alone: Option<usize>,
    /// For a plan cut by count, how many parts the remaining steps are cut into.
    shares: usize,
    /// For a plan cut by count, how many remaining steps there are.
    rest: usize,
    /// The part of each remaining step, in their order, when every one of them states a weight:
    /// the parts are then cut by time and no step stands alone. Otherwise none.
    timed: Option<Vec<usize>>,
}

impl Cut {
    fn of(steps: &[Step], parts: usize) -> Self {
        let parts = parts.max(1);
        let named: BTreeSet<&str> = steps
            .iter()
            .flat_map(|step| step.after.iter().map(String::as_str))
            .collect();
        let cut: Vec<usize> = (0..steps.len())
            .filter(|index| !(steps[*index].setup && named.contains(steps[*index].id.as_str())))
            .collect();
        let opening = cut
            .iter()
            .take_while(|index| steps[**index].reading == Reading::Build)
            .count();
        let weighed = parts > 1
            && cut[opening..]
                .iter()
                .all(|index| steps[*index].weight.is_some());
        let alone = if parts > 1 && !weighed {
            cut.iter()
                .position(|index| runs_the_workspace(&steps[*index]))
                .filter(|slot| *slot >= opening)
        } else {
            None
        };
        let shares = if alone.is_some() { parts - 1 } else { parts };
        let rest = cut.len() - opening - usize::from(alone.is_some());
        let timed = weighed.then(|| {
            let seconds: Vec<u64> = cut[opening..]
                .iter()
                .map(|index| steps[*index].weight.unwrap_or(0))
                .collect();
            balanced(&seconds, parts)
        });
        Self {
            steps: cut,
            opening,
            alone,
            shares,
            rest,
            timed,
        }
    }

    /// The part, from 1, that holds the remaining step at `position` among the remaining steps: the
    /// first part whose share ends after it.
    fn part_at(&self, position: usize) -> usize {
        if let Some(parts) = &self.timed {
            return parts[position];
        }
        let share = scaled((position + 1, self.shares, self.rest), true);
        share + usize::from(self.alone.is_some())
    }
}

/// The part, from 1, of each of `seconds` in turn, cutting them in order into `parts` parts of which
/// the longest takes the least time: the least limit that the greedy fill of the parts, each as full
/// as it can be without passing the limit, brings within `parts`. A step longer than the limit has a
/// part to itself. A part has no step when the others are so long that fewer parts than `parts`
/// make the cut.
fn balanced(seconds: &[u64], parts: usize) -> Vec<usize> {
    let fill = |limit: u64| -> Vec<usize> {
        let (mut part, mut load) = (1_usize, 0_u64);
        seconds
            .iter()
            .map(|step| {
                if load > 0 && load.saturating_add(*step) > limit {
                    part += 1;
                    load = 0;
                }
                load = load.saturating_add(*step);
                part
            })
            .collect()
    };
    let used = |limit: u64| fill(limit).last().copied().unwrap_or(1);
    let (mut low, mut high) = (
        seconds.iter().copied().max().unwrap_or(0),
        seconds
            .iter()
            .fold(0_u64, |all, step| all.saturating_add(*step)),
    );
    while low < high {
        let middle = low + (high - low) / 2;
        if used(middle) <= parts {
            high = middle;
        } else {
            low = middle + 1;
        }
    }
    fill(low)
}

/// `a * b / c`, rounded up when `up` and down when not, with the product taken in 128 bits so that
/// it cannot overflow for any `usize` factors. `c` is above 0. A quotient above a `usize` is
/// `usize::MAX`.
fn scaled((a, b, c): (usize, usize, usize), up: bool) -> usize {
    let (a, b, c) = (a as u128, b as u128, c as u128);
    let quotient = if up { (a * b).div_ceil(c) } else { a * b / c };
    usize::try_from(quotient).unwrap_or(usize::MAX)
}

/// The parts that hold a step: every part, or the parts named.
#[derive(Clone, Default)]
struct Held {
    every: bool,
    parts: BTreeSet<usize>,
}

/// The first budget, in the order its steps first appear in the plan, whose steps [`part_of`] puts
/// in more than one of `parts` parts: a budget is spent over the steps that name it in the order
/// they run, and the parts are run one at a time, each by a run of its own, so a budget cannot be
/// spent over steps that run in different runs. A build that opens the plan is in every part, and
/// so is a set-up step in each part that holds a step naming it.
///
/// The parts that hold each step are found from the step's place in the cut, and the plan is not
/// cut once for each part, so the cost does not grow with the number of parts.
#[must_use]
pub fn budget_across_parts(steps: &[Step], parts: usize) -> Option<String> {
    if parts < 2 || steps.iter().all(|step| step.budget.is_none()) {
        return None;
    }
    let cut = Cut::of(steps, parts);
    let mut held = vec![Held::default(); steps.len()];
    let mut position = 0;
    for (slot, index) in cut.steps.iter().enumerate() {
        if slot < cut.opening {
            held[*index].every = true;
        } else if cut.alone == Some(slot) {
            held[*index].parts.insert(1);
        } else {
            held[*index].parts.insert(cut.part_at(position));
            position += 1;
        }
    }
    // A set-up step comes before the steps that name it, so one pass from the end gives each set-up
    // step the parts of the steps that name it, and each that those name.
    for index in (0..steps.len()).rev() {
        for name in &steps[index].after {
            if let Some(earlier) = steps.iter().position(|step| step.id == *name) {
                let later = held[index].clone();
                held[earlier].every |= later.every;
                held[earlier].parts.extend(later.parts);
            }
        }
    }
    let mut order: Vec<&str> = Vec::new();
    let mut spread: BTreeMap<&str, Held> = BTreeMap::new();
    for (step, held) in steps.iter().zip(&held) {
        let Some((id, _)) = &step.budget else {
            continue;
        };
        if !spread.contains_key(id.as_str()) {
            order.push(id);
        }
        let all = spread.entry(id).or_default();
        all.every |= held.every;
        all.parts.extend(held.parts.iter().copied());
    }
    order
        .into_iter()
        .find(|id| spread[id].every || spread[id].parts.len() > 1)
        .map(str::to_owned)
}

/// The steps of one part of a platform's plan, for a plan that one job cannot hold and separate runs
/// carry out in parts: the build steps that open the plan, which every part runs, and then the
/// remaining steps, cut in order into contiguous parts. When every one of them states a weight for
/// the platform, the parts are of least longest time by those weights, and no step stands alone.
/// Otherwise the parts are of nearly equal count, and a plan that holds the workspace's tests puts
/// that step, with the opening builds, in part 1 by itself and cuts the other steps into the
/// remaining parts. `part` is the number of the part from 1 and the number of parts.
///
/// A set-up step that a step of the plan names in `after` is not cut: it goes, in its own
/// place, into every part that holds a step naming it, directly or through another set-up step, so
/// a set-up step runs in each of those parts.
#[must_use]
pub fn part_of(steps: Vec<Step>, part: (usize, usize)) -> Vec<Step> {
    let (number, parts) = part;
    let cut = Cut::of(&steps, parts);
    let mut kept = vec![false; steps.len()];
    let mut position = 0;
    for (slot, index) in cut.steps.iter().enumerate() {
        kept[*index] = if slot < cut.opening || (cut.alone == Some(slot) && number == 1) {
            true
        } else if cut.alone == Some(slot) {
            false
        } else {
            let at = position;
            position += 1;
            cut.part_at(at) == number
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
    fn the_macos_plan_states_every_steps_seconds_and_its_three_parts_take_two_hours_at_most() {
        let steps = steps(Platform::MacOs, &every_group(), "/tmp/evidence", None);
        // A set-up step that another step names is not cut and states no weight.
        let is_set_up =
            |step: &Step| step.setup && steps.iter().any(|s| s.after.contains(&step.id));
        let unweighed: Vec<&str> = steps
            .iter()
            .filter(|step| step.weight.is_none() && !is_set_up(step))
            .map(|step| step.id.as_str())
            .collect();
        assert!(unweighed.is_empty(), "no weight: {unweighed:?}");
        let mut every = Vec::new();
        for number in 1..=3 {
            let part = part_of(steps.clone(), (number, 3));
            let seconds: u64 = part.iter().filter_map(|step| step.weight).sum();
            assert!(
                seconds <= 2 * 3600,
                "macOS part {number} of 3 is estimated at {seconds} seconds"
            );
            every.extend(
                part.into_iter()
                    .skip(1)
                    .filter(|step| !is_set_up(step))
                    .map(|step| step.id),
            );
        }
        // The first step is the build that opens each part, and the others are in one part each.
        let others: Vec<String> = steps
            .iter()
            .skip(1)
            .filter(|step| !is_set_up(step))
            .map(|step| step.id.clone())
            .collect();
        assert_eq!(every, others);
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
            weight: None,
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
            weight: None,
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

    /// `step` with `seconds` as the time it took when last measured.
    fn weighed(mut step: Step, seconds: u64) -> Step {
        step.weight = Some(seconds);
        step
    }

    /// The ids of the steps of one part of `steps`.
    fn part_ids(steps: &[Step], part: (usize, usize)) -> Vec<String> {
        part_of(steps.to_vec(), part)
            .into_iter()
            .map(|step| step.id)
            .collect()
    }

    #[test]
    fn a_plan_whose_steps_all_state_a_weight_is_cut_into_parts_of_nearly_equal_time() {
        let mut steps = vec![weighed(named("build", Reading::Build, false, &[]), 100)];
        let rest = [4000, 3000, 2000, 1500, 1500, 1000, 500, 500];
        for (n, seconds) in rest.into_iter().enumerate() {
            let step = named(&format!("t{n}"), Reading::Cargo, false, &[]);
            steps.push(weighed(step, seconds));
        }
        let mut every = Vec::new();
        for number in 1..=3 {
            let part = part_ids(&steps, (number, 3));
            assert_eq!(part[0], "build", "the opening build is in part {number}");
            every.extend(part.into_iter().skip(1));
            let seconds: u64 = part_of(steps.clone(), (number, 3))
                .iter()
                .map(|step| step.weight.expect("a weight"))
                .sum();
            // The least time the largest part can take is 5,000 seconds of the steps, and the
            // build is in each part: by count the first part would take 7,000.
            assert!(seconds <= 5_100, "part {number} takes {seconds} seconds");
        }
        assert_eq!(every, ["t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7"]);
    }

    #[test]
    fn an_opening_build_that_states_no_weight_leaves_the_plan_cut_by_time() {
        let mut steps = vec![named("build", Reading::Build, false, &[])];
        for (n, seconds) in [4000, 1000, 1000, 1000].into_iter().enumerate() {
            let step = named(&format!("t{n}"), Reading::Cargo, false, &[]);
            steps.push(weighed(step, seconds));
        }
        // By time the first step is a part of its own, and by count the parts would be t0 with t1,
        // and t2 with t3.
        assert_eq!(part_ids(&steps, (1, 2)), ["build", "t0"]);
        assert_eq!(part_ids(&steps, (2, 2)), ["build", "t1", "t2", "t3"]);
    }

    #[test]
    fn a_weighted_plan_does_not_hold_the_workspace_step_by_itself_in_part_1() {
        let mut steps = vec![
            weighed(named("build", Reading::Build, false, &[]), 100),
            weighed(workspace("w"), 6000),
        ];
        for n in 0..4 {
            let step = named(&format!("t{n}"), Reading::Cargo, false, &[]);
            steps.push(weighed(step, 3000));
        }
        assert_eq!(part_ids(&steps, (1, 2)), ["build", "w", "t0"]);
        assert_eq!(part_ids(&steps, (2, 2)), ["build", "t1", "t2", "t3"]);
        // One step without a weight and the plan is cut by count again, with the workspace alone.
        steps[2].weight = None;
        assert_eq!(part_ids(&steps, (1, 2)), ["build", "w"]);
        assert_eq!(part_ids(&steps, (2, 2)), ["build", "t0", "t1", "t2", "t3"]);
    }

    #[test]
    fn the_budget_check_reads_the_weighted_cut_as_the_parts_are_cut() {
        let mut steps = vec![
            weighed(named("build", Reading::Build, false, &[]), 100),
            weighed(budgeted(named("b1", Reading::Cargo, false, &[]), "a"), 1000),
            weighed(budgeted(named("b2", Reading::Cargo, false, &[]), "a"), 1000),
            weighed(named("x", Reading::Cargo, false, &[]), 5000),
        ];
        // By time the two steps of the budget share part 1 and the long step has part 2.
        assert_eq!(part_ids(&steps, (1, 2)), ["build", "b1", "b2"]);
        assert_eq!(budget_across_parts(&steps, 2), None);
        // By count they would stand in different parts.
        for step in &mut steps {
            step.weight = None;
        }
        assert_eq!(budget_across_parts(&steps, 2).as_deref(), Some("a"));
    }

    /// `step` naming the budget `id`.
    fn budgeted(mut step: Step, id: &str) -> Step {
        step.budget = Some((id.to_owned(), 60));
        step
    }

    /// The plan's workspace tests: the one step that stands alone in part 1.
    fn workspace(id: &str) -> Step {
        Step {
            id: id.to_owned(),
            ..step_of(
                "the workspace's tests",
                &["cargo", "test", "--workspace"],
                Reading::Cargo,
            )
        }
    }

    /// The first budget whose steps [`part_of`] puts in more than one part, by cutting the plan once
    /// for each part and looking at where each budget's steps went.
    fn budget_across_parts_by_cutting(steps: &[Step], parts: usize) -> Option<String> {
        let mut first_part: BTreeMap<String, usize> = BTreeMap::new();
        let mut across: BTreeSet<String> = BTreeSet::new();
        for number in 1..=parts.max(1) {
            for step in part_of(steps.to_vec(), (number, parts)) {
                let Some((id, _)) = step.budget else {
                    continue;
                };
                if *first_part.entry(id.clone()).or_insert(number) != number {
                    across.insert(id);
                }
            }
        }
        steps
            .iter()
            .filter_map(|step| step.budget.as_ref())
            .map(|(id, _)| id)
            .find(|id| across.contains(*id))
            .cloned()
    }

    /// KR-REQ-29.01, the part about reproducible commands: the budget whose steps fall in more than one
    /// part is the one that cutting the plan into each part and looking shows, for plans whose
    /// budgets are on steps cut by count, on an opening build, on set-up steps that dependents in
    /// different parts name directly and through another set-up step, and on the workspace's tests
    /// that stand alone, and for every number of parts from 1 to 12.
    #[test]
    fn the_budget_across_parts_is_the_one_that_cutting_the_plan_into_each_part_shows() {
        let t = |id: &str| named(id, Reading::Cargo, false, &[]);
        let plans: Vec<Vec<Step>> = vec![
            vec![
                named("build", Reading::Build, false, &[]),
                budgeted(t("t0"), "a"),
                t("t1"),
                budgeted(t("t2"), "a"),
                t("t3"),
                budgeted(t("t4"), "b"),
                budgeted(t("t5"), "b"),
            ],
            vec![
                budgeted(named("build", Reading::Build, false, &[]), "a"),
                t("t0"),
                t("t1"),
            ],
            vec![
                named("build", Reading::Build, false, &[]),
                budgeted(named("s1", Reading::Exit, true, &[]), "s"),
                named("s2", Reading::Exit, true, &["s1"]),
                t("a"),
                named("t", Reading::Cargo, false, &["s2"]),
                t("u"),
                budgeted(named("v", Reading::Cargo, false, &["s1"]), "s"),
                t("w"),
            ],
            vec![
                named("build", Reading::Build, false, &[]),
                budgeted(workspace("workspace"), "w"),
                budgeted(t("t0"), "w"),
                t("t1"),
                t("t2"),
            ],
            vec![
                named("build", Reading::Build, false, &[]),
                t("t0"),
                t("t1"),
                t("t2"),
            ],
            vec![budgeted(t("t0"), "a"), budgeted(t("t1"), "a")],
        ];
        for (number, plan) in plans.iter().enumerate() {
            for parts in 1..=12 {
                assert_eq!(
                    budget_across_parts(plan, parts),
                    budget_across_parts_by_cutting(plan, parts),
                    "plan {number} cut into {parts} parts"
                );
            }
        }
    }

    /// KR-REQ-29.01, the part about reproducible commands: the check for a budget across parts costs
    /// as much for a trillion parts as for two: it finds where each step falls, and does not cut the
    /// plan once for each part, empty ones too.
    #[test]
    fn the_check_for_a_budget_across_parts_does_not_cut_the_plan_once_for_each_part() {
        let t = |id: &str| named(id, Reading::Cargo, false, &[]);
        let plan = vec![budgeted(t("t0"), "a"), budgeted(t("t1"), "a"), t("t2")];
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = sender.send((
                budget_across_parts(&plan, 1_000_000_000_000),
                budget_across_parts(&plan[2..], 1_000_000_000_000),
            ));
        });
        let (spread, without) = receiver
            .recv_timeout(std::time::Duration::from_secs(20))
            .expect("the check did not return in 20 s");
        assert_eq!(spread.as_deref(), Some("a"));
        assert_eq!(without, None);
    }

    /// KR-REQ-29.01, the part about reproducible commands: a plan cut into `usize::MAX` parts places
    /// each step in the part its place gives, whatever the size of the products that place them, and
    /// the check for a budget across parts finds the budget whose steps are in different parts. Three
    /// steps cut by count go to the parts that the third, two thirds and all of `usize::MAX` mark.
    #[test]
    fn a_plan_cut_into_the_largest_number_of_parts_places_its_steps_and_finds_a_budget_across_them()
    {
        let t = |id: &str| named(id, Reading::Cargo, false, &[]);
        let plan = vec![budgeted(t("t0"), "a"), budgeted(t("t1"), "a"), t("t2")];
        let parts = usize::MAX;
        let wide = parts as u128;
        let at = |third: u128| usize::try_from((wide * third).div_ceil(3)).expect("a usize");
        let ids = |number: usize| -> Vec<String> {
            part_of(plan.clone(), (number, parts))
                .into_iter()
                .map(|step| step.id)
                .collect()
        };
        assert_eq!(budget_across_parts(&plan, parts), Some("a".to_owned()));
        assert_eq!(ids(1), Vec::<String>::new());
        assert_eq!(ids(at(1)), ["t0"]);
        assert_eq!(ids(at(2)), ["t1"]);
        assert_eq!(ids(parts), ["t2"]);
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
            weight: None,
            placeholder_env: Vec::new(),
            placeholder_words: Vec::new(),
        }
    }

    /// Cuts `plan` into `parts` parts and holds that every part opens with the plan's opening
    /// builds and that the other steps of the parts are the plan's, each once, apart from the
    /// set-up steps that other steps name: each of those is in a part that holds a step naming it,
    /// before that step, and in no other part.
    fn holds_every_step_once(plan: &[Step], parts: usize) {
        let opening = plan
            .iter()
            .take_while(|step| step.reading == Reading::Build)
            .count();
        let named = |step: &Step| format!("{} :: {}", step.what, step.line());
        let is_set_up = |step: &Step| step.setup && plan.iter().any(|s| s.after.contains(&step.id));
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
            for (at, step) in others.iter().enumerate() {
                for name in &step.after {
                    assert!(
                        others[..at].iter().any(|before| before.id == *name),
                        "part {number}/{parts} holds `{}` and not `{name}` before it",
                        step.id
                    );
                }
                if is_set_up(step) {
                    assert!(
                        others.iter().any(|later| later.after.contains(&step.id)),
                        "part {number}/{parts} holds the set-up step `{}` and no step that names it",
                        step.id
                    );
                }
            }
            seen.extend(others.iter().filter(|step| !is_set_up(step)).map(named));
        }
        let mut expected: Vec<String> = plan[opening..]
            .iter()
            .filter(|step| !is_set_up(step))
            .map(named)
            .collect();
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
    fn the_macos_plan_opens_with_the_worker_build_and_runs_the_workspace_tests_as_three_steps() {
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
        // The programs that the suites of the three steps start come next, as a set-up step.
        assert!(plan[1].setup, "{}", plan[1].line());
        // The workspace's tests: kr-controller, companion-tauri with kr-worker, and the rest, each
        // naming that set-up step.
        assert!(plan[2].command.iter().any(|word| word == "kr-controller"));
        assert!(plan[3].command.iter().any(|word| word == "companion-tauri"));
        assert!(runs_the_workspace(&plan[4]), "{}", plan[4].line());
        for step in &plan[2..=4] {
            assert_eq!(step.after, [plan[1].id.clone()], "{}", step.line());
        }
        assert_eq!(
            plan.iter().filter(|step| runs_the_workspace(step)).count(),
            1
        );
        assert_eq!(
            plan.iter()
                .filter(|step| step.reading == Reading::Build)
                .count(),
            1
        );
        for parts in 1..=3 {
            holds_every_step_once(&plan, parts);
        }
        assert_eq!(part_of(plan.clone(), (1, 1)), plan);
    }

    #[test]
    fn a_plan_without_weights_is_cut_by_count_and_empty_groups_leave_empty_parts() {
        for platform in [Platform::Linux, Platform::MacOs, Platform::Windows] {
            let plan = steps(platform, &every_group(), "/tmp/e", None);
            for parts in 1..=3 {
                holds_every_step_once(&plan, parts);
            }
        }
        let only_the_workspace = steps(Platform::Linux, &["rust"], "/tmp/e", None);
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
        let first = steps
            .iter()
            .find(|step| !step.setup)
            .expect("a step that runs tests");
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
