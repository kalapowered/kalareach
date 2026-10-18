//! The keyed tests an ordinary run leaves out, and the steps that run them.
//!
//! A test with `#[ignore]` is skipped by `cargo test` until a command asks for it, with
//! `--ignored` or `--include-ignored`. One that names an acceptance row is that row's evidence, so
//! some step of this repository has to ask for it: a command in a workflow or in a script. This
//! module holds [`plan::IGNORED_RUNS`] to the sources in both directions. Every keyed ignored test
//! has an entry that runs it, and every entry's command is still in the file it names, so a test
//! cannot become ignored, or lose the command that runs it, without the map saying so.
//!
//! The commands are not read for what they mean. An entry names the words one command holds, and
//! the check is that the file still has a block of lines, with no blank line in it, that holds all
//! of them.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use crate::map::{Map, Place};
use crate::plan::{IgnoredRun, Runs};
use crate::workspace::TargetId;

/// What the keyed ignored tests in a map and the steps that run them come to.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Findings {
    /// What is wrong, one sentence each, in a stable order. Nothing is wrong when this is empty.
    pub problems: Vec<String>,
    /// The targets whose tests are run by hand, and why.
    pub by_hand: Vec<String>,
}

/// Holds the keyed ignored tests in `map` to the steps `runs` names.
#[must_use]
pub fn check(map: &Map, root: &Path, runs: &[IgnoredRun]) -> Findings {
    let mut found = Vec::new();
    let mut by_hand = Vec::new();

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
            for case in run.cases.iter().filter(|case| !matched.contains(**case)) {
                found.push(format!(
                    "`plan::IGNORED_RUNS` names {case} of {name}, which is not a keyed ignored test"
                ));
            }
        }
        match run.runs {
            Runs::Command { file, fragments } => {
                if let Some(problem) = missing_command(root, file, fragments, run.cases) {
                    found.push(format!("{name}: {problem}"));
                }
            }
            Runs::ByHand { why } => by_hand.push(format!("{name} is run by hand: {why}")),
        }
    }
    Findings {
        problems: found,
        by_hand,
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
        && (run.cases.is_empty() || run.cases.contains(&name))
}

/// Why `file` holds no command with all of `fragments`, or does not name one of `cases` to a
/// command that selects tests with `--exact`, or `None` when it does both.
fn missing_command(root: &Path, file: &str, fragments: &[&str], cases: &[&str]) -> Option<String> {
    let text = match std::fs::read_to_string(root.join(file)) {
        Ok(text) => text,
        Err(error) => return Some(format!("{file} cannot be read: {error}")),
    };
    // A command that selects tests by name has to name each of the tests this step is for.
    let by_name = fragments
        .iter()
        .any(|fragment| fragment.contains("--exact"));
    for case in cases.iter().filter(|_| by_name) {
        let short = case.rsplit("::").next().unwrap_or(case);
        if !text.contains(short) {
            return Some(format!("{file} does not name {short}"));
        }
    }
    if commands(&text).any(|line| fragments.iter().all(|fragment| line.contains(fragment))) {
        None
    } else {
        Some(format!(
            "{file} holds no command with {}",
            fragments
                .iter()
                .map(|fragment| format!("`{fragment}`"))
                .collect::<Vec<_>>()
                .join(" and ")
        ))
    }
}

/// The commands of a script or a workflow, one to a block: the lines between blank ones, with the
/// continuations joined, the white space made single and the lines that are only a comment left out.
fn commands(text: &str) -> impl Iterator<Item = String> + '_ {
    let joined = text.replace("\\\n", " ");
    let mut blocks = vec![String::new()];
    for line in joined.lines() {
        let line = line.trim();
        if line.is_empty() {
            blocks.push(String::new());
        } else if !line.starts_with('#') {
            let block = blocks.last_mut().expect("a block");
            block.push(' ');
            block.push_str(&line.split_whitespace().collect::<Vec<_>>().join(" "));
        }
    }
    blocks.into_iter()
}
