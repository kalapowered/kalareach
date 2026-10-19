//! The keyed tests an ordinary run leaves out, and the steps that run them.
//!
//! A test with `#[ignore]` is skipped by `cargo test` until a command asks for it, with
//! `--ignored` or `--include-ignored`. One that names an acceptance row is that row's evidence, so
//! some step of this repository has to ask for it. This module holds [`plan::IGNORED_RUNS`] to the
//! sources in both directions. Every keyed ignored test has an entry that runs it, and every
//! entry's command is still where the entry says, so a test cannot become ignored, or lose the
//! command that runs it, without the map saying so.
//!
//! The commands are not read for what they mean. An entry gives every word of one command, up to the
//! test names, and the check is that the file still has a line with exactly those words as a run
//! (the continuations of a line joined, what a comment holds left out, a line that only says
//! something, such as one that begins with `echo`, not a command), followed by nothing but the tests
//! the entry covers, when the words select by name with `--exact`, and the end of the command. A
//! word added, changed or taken out of the command, a flag, a filter, an option or a second
//! separator, is a command the entry does not name, so none can narrow a run unseen. An entry whose
//! test names a call passes finds them on lines that begin with the call's words. A step of the
//! report's own plan is found in the plan, not in text. Whether control reaches a command, and what
//! the script does with its result, are not read.

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
            Runs::Command { file, command } => missing_command(root, file, command, None, matched),
            Runs::Supplied {
                file,
                command,
                names_with,
            } => missing_command(root, file, command, Some(names_with), matched),
            Runs::Plan { command } => missing_step(&plan, command, matched),
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

/// The words that may stand before a command and leave it running as written.
const BEFORE: [&str; 11] = [
    "run:", "-", "!", "if", "then", "do", "else", "&&", "||", ";", "{",
];

/// Why `file` holds no command with exactly the words `command` that names `covered` and nothing
/// else, or `None` when it holds one.
///
/// A command whose words include `--exact` is followed by each of `covered`, in any order, and by
/// nothing but the end of the command; when `names_with` is given, the tests are named instead on
/// lines that begin with the first of those words and hold the rest (the call that passes the name
/// to the command).
fn missing_command(
    root: &Path,
    file: &str,
    command: &[&str],
    names_with: Option<&[&str]>,
    covered: &BTreeSet<String>,
) -> Option<String> {
    let text = match std::fs::read_to_string(root.join(file)) {
        Ok(text) => text,
        Err(error) => return Some(format!("{file} cannot be read: {error}")),
    };
    if let Some(wrong) = leaves_out(command, covered) {
        return Some(format!("its command {wrong}"));
    }
    let lines: Vec<String> = commands(&text).collect();
    let names_after = names_with.is_none() && command.contains(&"--exact");
    let found: Vec<Option<String>> = lines
        .iter()
        .flat_map(|line| {
            let words: Vec<&str> = line.split_whitespace().collect();
            starts(&words, command)
                .into_iter()
                .map(|start| run_problem(&words, start, command.len(), names_after, covered))
                .collect::<Vec<_>>()
        })
        .collect();
    if found.is_empty() {
        return Some(format!("{file} holds no command with {}", quoted(command)));
    }
    if found.iter().any(Option::is_none) {
        return names_with.and_then(|with| {
            covered
                .iter()
                .find(|name| {
                    !lines.iter().any(|other| {
                        begins_with(other, with)
                            && holds_all(other, with)
                            && contains_token(other, name)
                    })
                })
                .map(|name| format!("{file} does not name {name}"))
        });
    }
    found
        .into_iter()
        .next()
        .flatten()
        .map(|wrong| format!("{file} {wrong}"))
}

/// Where in `words` the run `command` starts.
fn starts(words: &[&str], command: &[&str]) -> Vec<usize> {
    (0..words.len())
        .filter(|&at| words[at..].starts_with(command))
        .collect()
}

/// Why the command that starts at `start` in `words` is not the command as written, or `None`:
/// something that changes how it runs stands before it, a test it should name is missing, or a
/// word follows that the entry does not name.
fn run_problem(
    words: &[&str],
    start: usize,
    length: usize,
    names_after: bool,
    covered: &BTreeSet<String>,
) -> Option<String> {
    if let Some(before) = start.checked_sub(1).map(|at| words[at])
        && !BEFORE.contains(&before)
    {
        return Some(format!(
            "has `{before}` before the command, which may change how it runs"
        ));
    }
    let mut rest = &words[start + length..];
    if names_after {
        let mut named = BTreeSet::new();
        while let Some(name) = rest.first().filter(|word| covered.contains(**word)) {
            named.insert(*name);
            rest = &rest[1..];
        }
        if let Some(name) = covered.iter().find(|name| !named.contains(name.as_str())) {
            return Some(format!("does not name {name}"));
        }
    }
    after_command(rest)
}

/// Why `rest`, the words after a command, is more than its end, or `None`: a redirection (with its
/// target) goes on to the end, and a pipe, a list operator or the end of a substitution ends it.
fn after_command(rest: &[&str]) -> Option<String> {
    let mut at = 0;
    while let Some(word) = rest.get(at) {
        match redirection(word) {
            Some(Redirection::Whole) => {}
            Some(Redirection::NeedsTarget) => at += 1,
            Some(Redirection::Ends) => return None,
            None if word.starts_with(['|', '&', ';', ')', '}']) => return None,
            None => {
                return Some(format!(
                    "has `{word}` after the command that the entry does not name"
                ));
            }
        }
        at += 1;
    }
    None
}

/// What a word is when it is a redirection.
enum Redirection {
    /// All of the word: `2>&1`, `>file`.
    Whole,
    /// The operator alone: its target is the next word.
    NeedsTarget,
    /// A redirection that the end of the command follows in the same word: `2>&1)";`.
    Ends,
}

/// Reads `word` as a redirection, or `None`.
fn redirection(word: &str) -> Option<Redirection> {
    let rest = word.trim_start_matches(|c: char| c.is_ascii_digit());
    let rest = rest.strip_prefix(['>', '<'])?;
    let rest = rest.trim_start_matches(['>', '<']);
    if rest.is_empty() {
        return Some(Redirection::NeedsTarget);
    }
    let target_end = rest.strip_prefix('&').map_or(rest, |duplicate| {
        duplicate.trim_start_matches(|c: char| c.is_ascii_digit() || c == '-')
    });
    let target = target_end
        .find(['|', '&', ';', ')'])
        .map_or(target_end.len(), |at| at);
    if target < target_end.len() {
        Some(Redirection::Ends)
    } else {
        Some(Redirection::Whole)
    }
}

/// Why `command` leaves a test of `covered` out, or `None`: it only lists them or builds them, or a
/// `--skip` filter in it selects one of them. The words are the entry's own, so this holds the table
/// to the tests it says it covers.
fn leaves_out(command: &[&str], covered: &BTreeSet<String>) -> Option<String> {
    if let Some(word) = command
        .iter()
        .find(|word| matches!(**word, "--list" | "--no-run"))
    {
        return Some(format!("does not run the tests, with `{word}`"));
    }
    command.iter().enumerate().find_map(|(at, word)| {
        let skip = word.strip_prefix("--skip=").or_else(|| {
            (*word == "--skip")
                .then(|| command.get(at + 1).copied())
                .flatten()
        })?;
        covered
            .iter()
            .find(|name| name.contains(skip))
            .map(|name| format!("skips {name} with `--skip {skip}`"))
    })
}

/// Why no step of the report's own plan has exactly the words `command`, or does not name a test
/// the step selects with `--exact`, or `None` when it does both.
fn missing_step(plan: &[String], command: &[&str], covered: &BTreeSet<String>) -> Option<String> {
    if let Some(wrong) = leaves_out(command, covered) {
        return Some(format!("its step {wrong}"));
    }
    if !plan
        .iter()
        .any(|step| step.split_whitespace().eq(command.iter().copied()))
    {
        return Some(format!(
            "the report's plan has no step with the words {}",
            quoted(command)
        ));
    }
    if command.contains(&"--exact") {
        return covered
            .iter()
            .find(|name| !command.contains(&name.as_str()))
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

fn quoted(words: &[&str]) -> String {
    format!("`{}`", words.join(" "))
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

/// Whether a line only says something: it begins (after a workflow's `run:`) with `echo`, `printf`
/// or `:`, so words that look like a command after them are text.
fn says(line: &str) -> bool {
    let command = line
        .trim_start_matches("- ")
        .trim_start_matches("run:")
        .trim_start();
    matches!(
        command.split_whitespace().next(),
        Some("echo" | "printf" | ":")
    )
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
