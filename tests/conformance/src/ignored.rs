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
//! joined, and what a comment holds left out), so that the words of two commands never stand in for
//! one. A command that selects tests with `--exact` has to name each test the entry covers on that
//! line, or, for an entry that says a call passes the names, on a line with the call's words; and no
//! `--skip` filter of it may select one of them. A step of the report's own plan is found in the
//! plan, not in text. Whether control reaches a command, and what the script does with its result,
//! are not read.

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
            Runs::Command { file, fragments } => {
                missing_command(root, file, fragments, None, matched)
            }
            Runs::Supplied {
                file,
                fragments,
                names_with,
            } => missing_command(root, file, fragments, Some(names_with), matched),
            Runs::Plan { fragments } => missing_step(&plan, fragments, matched),
            Runs::Helper { file } => missing_helper(root, file, matched),
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

/// Why `file` holds no command with all of `fragments` that names the tests it selects and leaves
/// none of them out, or `None` when it holds one.
///
/// A command that selects tests with `--exact` names each of `covered` on its own line, or, when
/// `names_with` is given, on a line that holds all of those words (the call that passes the name to
/// the command). A command leaves a test out when a `--skip` filter selects it.
fn missing_command(
    root: &Path,
    file: &str,
    fragments: &[&str],
    names_with: Option<&[&str]>,
    covered: &BTreeSet<String>,
) -> Option<String> {
    let text = match std::fs::read_to_string(root.join(file)) {
        Ok(text) => text,
        Err(error) => return Some(format!("{file} cannot be read: {error}")),
    };
    let lines: Vec<String> = commands(&text).collect();
    let wrong = |line: &String| {
        let exact = contains_token(line, "--exact");
        narrowed(line, covered, exact).or_else(|| {
            if !exact {
                return None;
            }
            covered
                .iter()
                .find(|name| match names_with {
                    None => !contains_token(line, name),
                    Some(words) => !lines.iter().any(|other| {
                        begins_with(other, words)
                            && holds_all(other, words)
                            && contains_token(other, name)
                    }),
                })
                .map(|name| format!("does not name {name}"))
        })
    };
    let found: Vec<Option<String>> = lines
        .iter()
        .filter(|line| holds_all(line, fragments))
        .map(wrong)
        .collect();
    if found.iter().any(Option::is_none) {
        return None;
    }
    Some(match found.into_iter().next() {
        Some(Some(wrong)) => format!("{file} {wrong}"),
        _ => format!("{file} holds no command with {}", quoted(fragments)),
    })
}

/// The options of the test program that take their value as the next word.
const VALUE_OPTIONS: [&str; 7] = [
    "--test-threads",
    "--color",
    "--format",
    "--logfile",
    "--shuffle-seed",
    "--report-time",
    "--skip",
];

/// Why a command, as the words of one line, runs fewer tests than `covered` or none, or `None`
/// when it does not: it only lists them, a `--skip` filter (as `--skip FILTER` or `--skip=FILTER`)
/// selects one of them, or a filter that names tests by a part of their names, instead of
/// `--exact`, leaves one of them out. A filter selects a test whose name contains it.
fn narrowed(command: &str, covered: &BTreeSet<String>, exact: bool) -> Option<String> {
    let words: Vec<&str> = command.split_whitespace().collect();
    if words.contains(&"--list") {
        return Some("only lists the tests, with `--list`".to_owned());
    }
    let mut skips = Vec::new();
    let mut filters = Vec::new();
    let mut after_cargo = false;
    let mut at = 0;
    while at < words.len() {
        let word = words[at];
        if let Some(value) = word.strip_prefix("--skip=") {
            skips.push(value);
        } else if word == "--skip" {
            if let Some(value) = words.get(at + 1) {
                skips.push(value);
            }
            at += 1;
        } else if !after_cargo {
            after_cargo = word == "--";
        } else if VALUE_OPTIONS.contains(&word) {
            at += 1;
        } else if word.contains(['|', '&', ';', '<', '>', '(', ')', '$']) {
            break;
        } else if !word.starts_with('-') {
            filters.push(word);
        }
        at += 1;
    }
    for skip in skips {
        let skip = skip.trim_matches(['"', '\'']);
        if let Some(name) = covered.iter().find(|name| name.contains(skip)) {
            return Some(format!("skips {name} with `--skip {skip}`"));
        }
    }
    if !exact && !filters.is_empty() {
        let filters: Vec<&str> = filters
            .into_iter()
            .map(|filter| filter.trim_matches(['"', '\'']))
            .collect();
        if let Some(name) = covered
            .iter()
            .find(|name| !filters.iter().any(|filter| name.contains(filter)))
        {
            return Some(format!(
                "selects only {}, which leaves out {name}",
                filters.join(" ")
            ));
        }
    }
    None
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
    if let Some(narrowed) = narrowed(step, covered, contains_token(step, "--exact")) {
        return Some(format!("its step {narrowed}"));
    }
    if contains_token(step, "--exact") {
        return covered
            .iter()
            .find(|name| !contains_token(step, name))
            .map(|name| format!("its step does not name {name}"));
    }
    None
}

/// How far from the line that names a helper test its flags may be, in lines of code.
const HELPER_REACH: usize = 8;

/// Why `file` does not start the helpers `covered` as processes of their own, or `None` when it
/// does: the file names each helper in its code, and within a few lines of that name its code asks
/// for an ignored test by name with `--ignored` and `--exact`. A comment, an attribute and the
/// reason an `#[ignore]` gives are not code.
fn missing_helper(root: &Path, file: &str, covered: &BTreeSet<String>) -> Option<String> {
    let text = match std::fs::read_to_string(root.join(file)) {
        Ok(text) => text,
        Err(error) => return Some(format!("{file} cannot be read: {error}")),
    };
    let code = code_lines(&text);
    for name in covered {
        // A helper may be named once, in a constant, and started by the constant's name.
        let mut words = vec![name.as_str()];
        words.extend(code.iter().filter_map(|line| constant_for(line, name)));
        let named: Vec<usize> = (0..code.len())
            .filter(|&at| {
                !code[at].contains("fn ")
                    && !code[at].starts_with("const ")
                    && !code[at].starts_with("pub const ")
                    && words.iter().any(|word| contains_token(code[at], word))
            })
            .collect();
        if named.is_empty() {
            return Some(format!("{file} never starts {name}"));
        }
        let asks = named.iter().all(|&at| {
            let near = code
                [at.saturating_sub(HELPER_REACH)..(at + HELPER_REACH + 1).min(code.len())]
                .join(" ");
            contains_token(&near, "--ignored") && contains_token(&near, "--exact")
        });
        if !asks {
            return Some(format!(
                "{file} starts {name} without `--ignored` and `--exact` near its name"
            ));
        }
    }
    None
}

/// The name of the constant that `line` declares as the text `value`, when it does.
fn constant_for<'a>(line: &'a str, value: &str) -> Option<&'a str> {
    let declared = line
        .strip_prefix("const ")
        .or_else(|| line.strip_prefix("pub const "))?;
    let (name, rest) = declared.split_once(':')?;
    rest.contains(&format!("\"{value}\""))
        .then_some(name.trim())
}

/// The lines of a Rust file that are code: not a comment, and not an attribute, which may run over
/// several lines.
fn code_lines(text: &str) -> Vec<&str> {
    let mut code = Vec::new();
    let mut open = 0_i32;
    for line in text.lines().map(str::trim) {
        if open > 0 || line.starts_with("#[") || line.starts_with("#![") {
            for c in line.chars() {
                match c {
                    '[' => open += 1,
                    ']' => open -= 1,
                    _ => {}
                }
            }
            open = open.max(0);
        } else if !line.starts_with("//") {
            code.push(line);
        }
    }
    code
}

/// Whether `line` begins with the first of `words`, after an opening quote.
fn begins_with(line: &str, words: &[&str]) -> bool {
    words
        .first()
        .is_some_and(|first| line.trim_start_matches('"').starts_with(first))
}

fn holds_all(line: &str, fragments: &[&str]) -> bool {
    fragments
        .iter()
        .all(|fragment| contains_token(line, fragment))
}

/// Whether `text` holds `word` as whole words: not as the start or the end of a longer name, so
/// that `--test fish` is not found in `--test fish_sources`.
fn contains_token(text: &str, word: &str) -> bool {
    let joins = |c: char| c.is_ascii_alphanumeric() || c == '_' || c == '-';
    text.match_indices(word).any(|(at, _)| {
        text[..at].chars().next_back().is_none_or(|c| !joins(c))
            && text[at + word.len()..]
                .chars()
                .next()
                .is_none_or(|c| !joins(c))
    })
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
/// made single, and what a comment holds left out. A comment on a line that continues another ends
/// the command there, as it does for the shell. A line that only says something is not a command.
fn commands(text: &str) -> impl Iterator<Item = String> + '_ {
    text.replace("\\\n", " ")
        .lines()
        .map(|line| {
            without_comment(line)
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
        })
        .filter(|line| !line.is_empty() && !says(line))
        .collect::<Vec<_>>()
        .into_iter()
}

/// Whether a line only says something: it begins with `echo` or `printf`, so words that look like a
/// command after them are text.
fn says(line: &str) -> bool {
    matches!(line.split_whitespace().next(), Some("echo" | "printf"))
}

/// `line` up to the `#` that begins a comment: one at the start of the line or after white space,
/// quoted or not, so that a quote opened on an earlier line never hides one.
fn without_comment(line: &str) -> &str {
    let mut previous = ' ';
    for (at, c) in line.char_indices() {
        if c == '#' && previous.is_whitespace() {
            return &line[..at];
        }
        previous = c;
    }
    line
}
