//! The keyed tests an ordinary run leaves out, and the steps that run them.
//!
//! A test with `#[ignore]` is skipped by `cargo test` until a command asks for it, with
//! `--ignored` or `--include-ignored`. One that names an acceptance row is that row's evidence, so
//! some step of this repository has to ask for it. This module holds [`plan::IGNORED_RUNS`] to the
//! sources in both directions. Every keyed ignored test has an entry that runs it, and every
//! entry's command is still where the entry says, so a test cannot become ignored, or lose the
//! command that runs it, without the map saying so.
//!
//! The commands are not read for what they mean. An entry names the words one command holds, and
//! the check is that the file still has a line with all of them (the continuations of a line
//! joined, and a line that is only a comment left out), so that the words of two commands never
//! stand in for one. A command that selects tests with `--exact` has to name each test the entry
//! covers. A step of the report's own plan is found in the plan, not in text.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crate::map::{Map, Place};
use crate::plan::{ApplicationsPlan, Group, IgnoredRun, Platform, Runs};
use crate::workspace::TargetId;

/// What the keyed ignored tests in a map and the steps that run them come to.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Findings {
    /// What is wrong, one sentence each, in a stable order. Nothing is wrong when this is empty.
    pub problems: Vec<String>,
    /// The targets whose tests no step runs, and why: run by hand, or run by nothing.
    pub unrun: Vec<String>,
}

/// Holds the keyed ignored tests in `map` to the steps `runs` names.
#[must_use]
pub fn check(map: &Map, root: &Path, runs: &[IgnoredRun]) -> Findings {
    let mut found = Vec::new();
    let mut unrun_notes = Vec::new();

    let keyed = keyed_ignored(map);
    let mut matched = vec![BTreeSet::new(); runs.len()];
    let mut unrun: BTreeMap<&TargetId, Vec<&str>> = BTreeMap::new();
    for (target, names) in &keyed {
        for name in names {
            let places: Vec<usize> = runs
                .iter()
                .enumerate()
                .filter(|(_, run)| covers(run, target, name))
                .map(|(index, _)| index)
                .collect();
            if places.is_empty() {
                unrun.entry(target).or_default().push(name);
            }
            for index in places {
                matched[index].insert(name.clone());
            }
        }
    }
    for (target, names) in unrun {
        found.push(format!(
            "{target}: {} keyed test{} left out of an ordinary run and run by no step \
             `plan::IGNORED_RUNS` names: {}",
            names.len(),
            if names.len() == 1 { " is" } else { "s are" },
            names.join(", ")
        ));
    }

    let plan = plan_commands();
    for (run, matched) in runs.iter().zip(&matched) {
        let name = format!("{} {}", run.package, run.target);
        if matched.is_empty() {
            let cases = if run.cases.is_empty() {
                String::new()
            } else {
                format!(" ({})", run.cases.join(", "))
            };
            found.push(format!(
                "`plan::IGNORED_RUNS` names a step for {name}{cases} that no keyed ignored test needs"
            ));
        } else {
            for case in run
                .cases
                .iter()
                .filter(|case| !matched.iter().any(|name| case_matches(case, name)))
            {
                found.push(format!(
                    "`plan::IGNORED_RUNS` names {case} of {name}, which is not a keyed ignored test"
                ));
            }
        }
        let problem = match run.runs {
            Runs::Command { file, fragments } => missing_command(root, file, fragments, matched),
            Runs::Plan { fragments } => missing_step(&plan, fragments, matched),
            Runs::Helper { file } => missing_helper(root, file),
            Runs::ByHand { why } => {
                unrun_notes.push(format!("{name} is run by hand: {why}"));
                None
            }
            Runs::Nowhere { why } => {
                unrun_notes.push(format!("{name} is run by nothing: {why}"));
                None
            }
        };
        if let Some(problem) = problem {
            found.push(format!("{name}: {problem}"));
        }
    }
    Findings {
        problems: found,
        unrun: unrun_notes,
    }
}

/// Every keyed test each target leaves out of an ordinary run, by name.
fn keyed_ignored(map: &Map) -> BTreeMap<TargetId, BTreeSet<String>> {
    let mut keyed: BTreeMap<TargetId, BTreeSet<String>> = BTreeMap::new();
    for places in map.keys.values() {
        for place in places.keys() {
            match place {
                Place::Rust { target, name } => {
                    keyed
                        .entry(target.clone())
                        .or_default()
                        .insert(name.clone());
                }
                Place::RustModule { target, module } => {
                    let under =
                        |name: &str| module.is_empty() || name.starts_with(&format!("{module}::"));
                    let names = map.rust_tests.get(target).into_iter().flatten();
                    keyed
                        .entry(target.clone())
                        .or_default()
                        .extend(names.filter(|name| under(name)).cloned());
                }
                Place::TypeScript { .. } | Place::Lane { .. } => {}
            }
        }
    }
    keyed
        .into_iter()
        .filter_map(|(target, names)| {
            let ignored = map.ignored_tests.get(&target)?;
            let names: BTreeSet<String> = names.intersection(ignored).cloned().collect();
            (!names.is_empty()).then_some((target, names))
        })
        .collect()
}

/// Whether `run` is the step for the test `name` of `target`.
fn covers(run: &IgnoredRun, target: &TargetId, name: &str) -> bool {
    run.package == target.package
        && run.target == target.kind.selector(&target.name)
        && (run.cases.is_empty() || run.cases.iter().any(|case| case_matches(case, name)))
}

/// Whether a case of an entry names the test `name`: its whole name, or, written with a trailing
/// `::`, the module it is in.
fn case_matches(case: &str, name: &str) -> bool {
    case == name || (case.ends_with("::") && name.starts_with(case))
}

/// Why `file` holds no command with all of `fragments`, or does not name a test the command
/// selects with `--exact`, or `None` when it does both.
fn missing_command(
    root: &Path,
    file: &str,
    fragments: &[&str],
    covered: &BTreeSet<String>,
) -> Option<String> {
    let text = match std::fs::read_to_string(root.join(file)) {
        Ok(text) => text,
        Err(error) => return Some(format!("{file} cannot be read: {error}")),
    };
    if !commands(&text).any(|line| holds_all(&line, fragments)) {
        return Some(format!(
            "{file} holds no command with {}",
            quoted(fragments)
        ));
    }
    unnamed(&text, fragments, covered).map(|short| format!("{file} does not name {short}"))
}

/// Why no step of the report's own plan has all of `fragments`, or does not name a test the step
/// selects with `--exact`, or `None` when it does both.
fn missing_step(plan: &[String], fragments: &[&str], covered: &BTreeSet<String>) -> Option<String> {
    let Some(step) = plan.iter().find(|step| holds_all(step, fragments)) else {
        return Some(format!(
            "the report's plan has no step with {}",
            quoted(fragments)
        ));
    };
    unnamed(step, fragments, covered).map(|short| format!("its step does not name {short}"))
}

/// Why `file` does not start a helper as a process of its own, or `None` when it does: the file of
/// a test that runs one of its own ignored tests holds the flags that ask for an ignored test
/// by name.
fn missing_helper(root: &Path, file: &str) -> Option<String> {
    let text = match std::fs::read_to_string(root.join(file)) {
        Ok(text) => text,
        Err(error) => return Some(format!("{file} cannot be read: {error}")),
    };
    ["--ignored", "--exact"]
        .into_iter()
        .find(|flag| !text.contains(flag))
        .map(|flag| format!("{file} never asks for an ignored test by name: it holds no `{flag}`"))
}

/// A test in `covered` that `text` does not name, when the fragments select tests with `--exact`.
fn unnamed<'a>(text: &str, fragments: &[&str], covered: &'a BTreeSet<String>) -> Option<&'a str> {
    if !fragments
        .iter()
        .any(|fragment| fragment.contains("--exact"))
    {
        return None;
    }
    covered
        .iter()
        .map(|name| name.rsplit("::").next().unwrap_or(name))
        .find(|short| !text.contains(short))
}

fn holds_all(line: &str, fragments: &[&str]) -> bool {
    fragments.iter().all(|fragment| line.contains(fragment))
}

fn quoted(fragments: &[&str]) -> String {
    fragments
        .iter()
        .map(|fragment| format!("`{fragment}`"))
        .collect::<Vec<_>>()
        .join(" and ")
}

/// Every step of the report's plan on Linux, each as the words of its command.
fn plan_commands() -> Vec<String> {
    crate::plan::steps(
        Platform::Linux,
        &Group::ALL,
        "evidence",
        Some(&ApplicationsPlan {
            left_out: Vec::new(),
        }),
    )
    .into_iter()
    .map(|step| step.command.join(" "))
    .collect()
}

/// The commands of a script or a workflow, one to a line: the continuations joined, the white space
/// made single, and the lines that are only a comment left out.
fn commands(text: &str) -> impl Iterator<Item = String> + '_ {
    text.replace("\\\n", " ")
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| line.split_whitespace().collect::<Vec<_>>().join(" "))
        .collect::<Vec<_>>()
        .into_iter()
}
