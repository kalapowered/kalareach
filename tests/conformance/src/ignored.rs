//! The keyed tests an ordinary run leaves out, and the steps that run them.
//!
//! A test with `#[ignore]` is skipped by `cargo test` until a command asks for it, with
//! `--ignored` or `--include-ignored`. One that names an acceptance row is that row's evidence, so
//! some step of this repository has to ask for it. This module holds
//! [`crate::plan::IGNORED_RUNS`] to the sources in both directions. Every keyed ignored test has an
//! entry that runs it, and every entry's command is still where the entry says, so a test cannot
//! become ignored, or lose the command that runs it, without the map saying so.
//!
//! The commands are not read for what they mean. An entry gives the whole of one line of a script
//! or a workflow, and the check is that the file still has a line with exactly those words (the
//! continuations of a line joined, the white space made single, a comment at its end left out). A
//! word added to the line, changed in it or taken out of it, whether a flag, a filter, a redirection
//! or what stands before or after the command, is a line the entry does not give, so none can
//! narrow a run unseen: the map refuses it, and says which line of the file is nearest, until the
//! entry is changed to the line as it now is. A line that selects tests with `--exact` has to name
//! each test the entry covers; an entry whose tests a call passes finds them on lines that begin
//! with the call's words. A step of the report's own plan is found in the plan, not in text.
//! Words are separated by a space or a tab and by nothing else, a comment begins at a `#` after a
//! space or a tab, and a backslash and the new line after it are taken out and nothing is put in
//! their place. Those are the shell's rules for the plain text of a command; a quote, an operator
//! or a redirection is only a word of the line, so changing one changes the line. In a workflow (a
//! `.yml` or `.yaml` file) a `run:` field is the exception: it is a plain scalar, where a
//! backslash does not continue the line. Whether control reaches a line, what the script does with
//! its result, the environment a step sets, what other syntax (a here-document, a quoted block
//! over several lines, a folded scalar) makes of a line, and a filter in the line an entry itself
//! gives are not read: the entry is taken as written, held only to the tests it covers by name, by
//! `--skip`, `--list` and `--no-run`.

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
            Runs::Command { file, line } => missing_command(root, file, line, None, matched),
            Runs::Supplied {
                file,
                line,
                names_with,
            } => missing_command(root, file, line, Some(names_with), matched),
            Runs::Plan { line } => missing_step(&plan, line, matched),
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

/// Why `file` holds no line with exactly the words of `line` that names `covered`, or `None` when it
/// holds one.
///
/// A line that selects with `--exact` names each of `covered` among its own words; when
/// `names_with` is given, the tests are named instead on lines that begin with the first of those
/// words and hold the rest (the call that passes the name to the command).
fn missing_command(
    root: &Path,
    file: &str,
    line: &str,
    names_with: Option<&[&str]>,
    covered: &BTreeSet<String>,
) -> Option<String> {
    let text = match std::fs::read_to_string(root.join(file)) {
        Ok(text) => text,
        Err(error) => return Some(format!("{file} cannot be read: {error}")),
    };
    if let Some(wrong) = leaves_out(line, covered) {
        return Some(format!("its line {wrong}"));
    }
    let wanted = words_of(line);
    let workflow = file.ends_with(".yml") || file.ends_with(".yaml");
    let lines: Vec<String> = commands(&text, workflow);
    if !lines.contains(&wanted) {
        return Some(format!(
            "{file} holds no line `{wanted}`{}",
            nearest(&lines, &wanted)
        ));
    }
    let words: Vec<&str> = words(&wanted).collect();
    if words.contains(&"--exact") {
        let named = |name: &String| match names_with {
            None => words.contains(&name.as_str()),
            Some(with) => lines.iter().any(|other| {
                begins_with(other, with) && holds_all(other, with) && contains_token(other, name)
            }),
        };
        return covered
            .iter()
            .find(|name| !named(name))
            .map(|name| format!("{file} does not name {name}"));
    }
    None
}

/// The words of `line` with single spaces between them.
fn words_of(line: &str) -> String {
    words(line).collect::<Vec<_>>().join(" ")
}

/// The words of `text` as a shell reads them: separated by spaces and tabs, and by nothing else. A
/// no-break space, a carriage return or a vertical tab is part of a word, as it is for the shell.
fn words(text: &str) -> impl Iterator<Item = &str> {
    text.split([' ', '\t']).filter(|word| !word.is_empty())
}

/// A hint to put after a missing line: the line of the file that shares most leading words with it.
fn nearest(lines: &[String], wanted: &str) -> String {
    let shared = |line: &String| {
        words(line)
            .zip(words(wanted))
            .take_while(|(a, b)| a == b)
            .count()
    };
    match lines.iter().max_by_key(|line| shared(line)) {
        Some(line) if shared(line) >= 3 => format!("; the nearest line is `{line}`"),
        _ => String::new(),
    }
}

/// Why the line `command` leaves a test of `covered` out, or `None`: it only lists them or builds
/// them, or a `--skip` filter in it selects one of them. The words are the entry's own, so this
/// holds the table to the tests it says it covers.
fn leaves_out(command: &str, covered: &BTreeSet<String>) -> Option<String> {
    let words: Vec<&str> = words(command).collect();
    if let Some(word) = words
        .iter()
        .find(|word| matches!(**word, "--list" | "--no-run"))
    {
        return Some(format!("does not run the tests, with `{word}`"));
    }
    words.iter().enumerate().find_map(|(at, word)| {
        let skip = word.strip_prefix("--skip=").or_else(|| {
            (*word == "--skip")
                .then(|| words.get(at + 1).copied())
                .flatten()
        })?;
        covered
            .iter()
            .find(|name| name.contains(skip))
            .map(|name| format!("skips {name} with `--skip {skip}`"))
    })
}

/// Why no step of the report's own plan has exactly the words `line`, or does not name a test the
/// step selects with `--exact`, or `None` when it does both.
fn missing_step(plan: &[String], line: &str, covered: &BTreeSet<String>) -> Option<String> {
    if let Some(wrong) = leaves_out(line, covered) {
        return Some(format!("its step {wrong}"));
    }
    let wanted = words_of(line);
    if !plan.contains(&wanted) {
        return Some(format!(
            "the report's plan has no step with the words `{wanted}`"
        ));
    }
    let words: Vec<&str> = words(&wanted).collect();
    if words.contains(&"--exact") {
        return covered
            .iter()
            .find(|name| !words.contains(&name.as_str()))
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

/// The commands of a script or a workflow, one to a line: a backslash and the new line after it
/// taken out (nothing put in their place, as the shell does, so a continuation that has no white
/// space beside it joins two words into one), the white space made single, and what a comment holds
/// left out. A comment on a line that continues another ends the command there, as it does for the
/// shell. In a workflow, a `run:` field is a plain scalar, where a backslash is not a continuation:
/// a line that begins `run:` or `- run:` is not joined to the next. Every other line that ends in a
/// backslash is, in every file.
fn commands(text: &str, workflow: bool) -> Vec<String> {
    let mut joined: Vec<String> = Vec::new();
    let mut continuing = false;
    for physical in text.split('\n') {
        let (body, goes_on) = match physical.strip_suffix('\\') {
            Some(body) if !(workflow && is_run_field(physical)) => (body, true),
            _ => (physical, false),
        };
        match joined.last_mut() {
            Some(last) if continuing => last.push_str(body),
            _ => joined.push(body.to_owned()),
        }
        continuing = goes_on;
    }
    joined
        .iter()
        .map(|line| words_of(without_comment(line)))
        .filter(|line| !line.is_empty())
        .collect()
}

/// Whether `line` starts a workflow's `run:` field: its first word is `run:`, or its first two are
/// `-` and `run:`.
fn is_run_field(line: &str) -> bool {
    let mut parts = words(line);
    match parts.next() {
        Some("run:") => true,
        Some("-") => parts.next() == Some("run:"),
        _ => false,
    }
}

/// `line` up to the `#` that begins a comment: one at the start of the line or after white space,
/// quoted or not, so that a quote opened on an earlier line never hides one.
fn without_comment(line: &str) -> &str {
    let mut previous = ' ';
    for (at, c) in line.char_indices() {
        if c == '#' && matches!(previous, ' ' | '\t') {
            return &line[..at];
        }
        previous = c;
    }
    line
}
