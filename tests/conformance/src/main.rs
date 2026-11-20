//! `kr-conformance`: builds the identifier map, runs the suites that hold keyed tests and writes
//! the result keyed by identifier.
//!
//! ```text
//! kr-conformance run --root <repository> --evidence <directory> [--group <name>]...
//!                    [--applications <cache>] [--all-terminals] [--plan <file>]
//! kr-conformance map --root <repository> [--typescript] [--plan <file>]
//! ```
//!
//! `scripts/run-conformance.sh` is the way in: it fetches the applications, builds this binary and
//! runs it. The exit status is 0 when the run passed, 1 when it ran and did not, and 2 when it was
//! refused before running anything: a plan file that is missing or refused, a malformed identifier,
//! a row outside section 21's or section 27's table, an evidence directory outside the platform's
//! temporary directory, a map that cannot be trusted, or a usage error such as an option with no
//! value or a group the plan does not have.

use std::path::PathBuf;
use std::process::ExitCode;

use kr_conformance::evidence;
use kr_conformance::plan::Platform;
use kr_conformance::plan_file::Plan;
use kr_conformance::report::{self, Options, Stopped};

fn usage(problem: &str) -> ExitCode {
    eprintln!("kr-conformance: {problem}");
    eprintln!(
        "usage: kr-conformance run --root <repository> --evidence <directory> [--group <name>]... \
         [--applications <cache>] [--all-terminals] [--part <number>/<parts>] [--plan <file>]\n       kr-conformance map --root <repository> \
         [--typescript] [--plan <file>]"
    );
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let Some(command) = arguments.first() else {
        return usage("no command");
    };
    // Cargo's runner for one test binary while a step's tests are listed, and while they are run.
    if command == "list-one" {
        return ExitCode::from(kr_conformance::run::list_one(&arguments[1..]));
    }
    if command == "run-one" {
        return ExitCode::from(kr_conformance::run::run_one(&arguments[1..]));
    }
    let mut root = None;
    let mut evidence_directory = None;
    let mut groups = Vec::new();
    let mut applications = None;
    let mut all_terminals = false;
    let mut typescript = false;
    let mut part = None;
    let mut plan_path = None;
    let mut rest = arguments[1..].iter();
    while let Some(argument) = rest.next() {
        match argument.as_str() {
            "--root" => match value(&mut rest) {
                Some(path) => root = Some(PathBuf::from(path)),
                None => return usage("--root takes the path of the repository"),
            },
            "--evidence" => match value(&mut rest) {
                Some(path) => evidence_directory = Some(PathBuf::from(path)),
                None => return usage("--evidence takes the path of the evidence directory"),
            },
            "--applications" => match value(&mut rest) {
                Some(path) => applications = Some(PathBuf::from(path)),
                None => return usage("--applications takes the path of the applications cache"),
            },
            "--plan" => match value(&mut rest) {
                Some(path) => plan_path = Some(PathBuf::from(path)),
                None => return usage("--plan takes the path of a plan file"),
            },
            "--group" => match value(&mut rest) {
                Some(group) => groups.push(group.to_owned()),
                None => return usage("--group takes the name of a group of the plan"),
            },
            "--all-terminals" => all_terminals = true,
            "--part" => match rest.next().and_then(|text| parse_part(text)) {
                Some(chosen) => part = Some(chosen),
                None => return usage("--part takes <number>/<parts>, with 1 <= number <= parts"),
            },
            "--typescript" => typescript = true,
            other => return usage(&format!("{other} is not an option")),
        }
    }
    let Some(root) = root else {
        return usage("--root is required");
    };
    // The plan is read before anything runs, and the groups are checked against it.
    let plan = match Plan::load(&root, plan_path.as_deref()) {
        Ok(plan) => plan,
        Err(refusal) => {
            eprintln!("kr-conformance: refused: {refusal}");
            return ExitCode::from(2);
        }
    };
    if let Some(unknown) = groups.iter().find(|group| !plan.groups.contains(group)) {
        return usage(&format!(
            "--group {unknown} is not a group of the plan; it has {}",
            plan.groups.join(", ")
        ));
    }
    match command.as_str() {
        "map" => map(root, plan, typescript),
        "run" => {
            let Some(evidence_directory) = evidence_directory else {
                return usage("--evidence is required");
            };
            run(
                root,
                plan,
                &evidence_directory,
                groups,
                applications,
                all_terminals,
                part,
            )
        }
        other => usage(&format!("{other} is not a command")),
    }
}

/// The value of an option: the next word, unless there is none or it is an option itself.
fn value<'a>(rest: &mut std::slice::Iter<'a, String>) -> Option<&'a str> {
    rest.next()
        .map(String::as_str)
        .filter(|word| !word.starts_with("--"))
}

/// A part of a plan as `<number>/<parts>`: the number of the part from 1, and the number of parts.
fn parse_part(text: &str) -> Option<(usize, usize)> {
    let (number, parts) = text.split_once('/')?;
    let (number, parts): (usize, usize) = (number.parse().ok()?, parts.parse().ok()?);
    (1..=parts).contains(&number).then_some((number, parts))
}

fn map(root: PathBuf, plan: Plan, typescript: bool) -> ExitCode {
    let options = Options {
        root,
        evidence: PathBuf::new(),
        selection: Some(Vec::new()),
        all_terminals: false,
        platform: Platform::current(),
        plan,
        held_to_ignored_runs: true,
        applications: None,
        environment: Vec::new(),
        lister: PathBuf::new(),
        part: None,
        runner_base: PathBuf::new(),
    };
    let map = report::map_declared(&options, typescript);
    let tests: usize = map.keys.values().map(std::collections::BTreeMap::len).sum();
    println!(
        "{} identifiers keyed to {tests} tests; {} named only outside tests; {} refused; {} problems",
        map.keys.len(),
        map.references
            .keys()
            .filter(|identifier| !map.keys.contains_key(identifier))
            .count(),
        map.refused.len(),
        map.problems.len()
    );
    for refused in &map.refused {
        println!("refused {}: {}", refused.source, refused.refusal);
    }
    for problem in &map.problems {
        println!("problem: {problem}");
    }
    for warning in &map.warnings {
        println!("warning: {warning}");
    }
    if map.refused.is_empty() && map.problems.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    }
}

fn run(
    root: PathBuf,
    plan: Plan,
    evidence_directory: &std::path::Path,
    groups: Vec<String>,
    applications: Option<PathBuf>,
    all_terminals: bool,
    part: Option<(usize, usize)>,
) -> ExitCode {
    let evidence = match evidence::check_directory(evidence_directory) {
        Ok(evidence) => evidence,
        Err(refused) => {
            eprintln!("kr-conformance: refused: {}", refused.0);
            return ExitCode::from(2);
        }
    };
    let selection = (!groups.is_empty()).then_some(groups);
    let selected = selection.clone().unwrap_or_else(|| plan.all_groups());
    let platform = Platform::current();
    let applications = match (plan.selects_applications(&selected), applications) {
        (true, Some(cache)) => match report::read_applications(&cache) {
            Ok(records) => Some(records),
            Err(problem) => {
                eprintln!("kr-conformance: {problem}");
                return ExitCode::from(2);
            }
        },
        (true, None) if plan.runs_applications(platform, &selected) => {
            return usage(
                "the applications group needs --applications <cache>, which the fetch step wrote",
            );
        }
        // Nothing is fetched here: each program is recorded with the reason the lock gives.
        (true, None) => match plan.applications.as_ref().map_or_else(
            || Err("the plan names no application lock".to_owned()),
            |lock| report::lock_applications(&root, &lock.lock, platform.name()),
        ) {
            Ok(records) => Some(records),
            Err(problem) => {
                eprintln!("kr-conformance: {problem}");
                return ExitCode::from(2);
            }
        },
        _ => None,
    };
    let lister = match std::env::current_exe() {
        Ok(lister) => lister,
        Err(error) => {
            eprintln!("kr-conformance: this program's own path could not be read: {error}");
            return ExitCode::from(2);
        }
    };
    let options = Options {
        root,
        evidence: evidence.clone(),
        selection,
        all_terminals,
        platform: Platform::current(),
        plan,
        held_to_ignored_runs: true,
        applications,
        environment: Vec::new(),
        lister,
        part,
        runner_base: std::env::temp_dir(),
    };
    let document = match report::run(&options, &mut |line| eprintln!("{line}")) {
        Ok(document) => document,
        Err(Stopped::Refused(refused)) => {
            eprintln!(
                "kr-conformance: refused: {} mentions are not identifiers the report accepts",
                refused.len()
            );
            for refused in refused {
                eprintln!("  {}: {}", refused.source, refused.refusal);
            }
            return ExitCode::from(2);
        }
        Err(Stopped::Problems(problems)) => {
            eprintln!("kr-conformance: the map cannot be trusted:");
            for problem in problems {
                eprintln!("  {problem}");
            }
            return ExitCode::from(2);
        }
        Err(Stopped::Evidence(problem)) => {
            eprintln!("kr-conformance: refused: {problem}");
            return ExitCode::from(2);
        }
        Err(Stopped::PrivateCopy(problem)) => {
            eprintln!("kr-conformance: refused, no step was run: {problem}");
            return ExitCode::from(2);
        }
    };
    let path = report::result_path(&evidence);
    let written = serde_json::to_string_pretty(&document)
        .map_err(|error| error.to_string())
        .and_then(|text| std::fs::write(&path, text + "\n").map_err(|error| error.to_string()));
    if let Err(error) = written {
        eprintln!(
            "kr-conformance: the result could not be written to {}: {error}",
            path.display()
        );
        return ExitCode::from(1);
    }
    let summary = &document.summary;
    println!(
        "{} identifiers: {} passed, {} failed, {} known differences only, {} not run; tests {} passed, \
         {} failed, {} known differences, {} ignored, {} not run, {} not built",
        summary.identifiers,
        summary.passed,
        summary.failed,
        summary.known_difference,
        summary.not_run,
        summary.tests.passed,
        summary.tests.failed,
        summary.tests.known_difference,
        summary.tests.ignored,
        summary.tests.not_run,
        summary.tests.not_built
    );
    for known in &document.known_differences {
        println!(
            "known difference ({}): {}: {}; {}",
            known.identifiers.join(", "),
            known.difference.subject,
            known.difference.application,
            known.difference.grid
        );
    }
    for problem in &document.problems {
        println!("problem: {problem}");
    }
    for (identifier, record) in &document.identifiers {
        if record.verdict == report::Verdict::Failed {
            println!("failed: {identifier}");
        }
    }
    for step in &summary.failed_steps {
        let record = &document.steps[step - 1];
        println!(
            "step {step} did not pass: {} (log {})",
            record.command, record.log
        );
        if let Some(observed) = &record.observation {
            if let Some(log) = &observed.log {
                println!("  its log: {log}");
            }
            for program in &observed.programs {
                println!("  could not run {}: {}", program.path, program.file);
            }
        }
    }
    for failure in &document.failures_outside_identifiers {
        println!("failed outside any identifier: {failure}");
    }
    if let Some(terminals) = &document.terminals {
        for terminal in terminals
            .iter()
            .filter(|terminal| terminal.outcome != report::Outcome::Passed)
        {
            println!("not run: {}: {}", terminal.terminal, terminal.reason);
        }
    }
    println!("result: {}", path.display());
    if let Some(line) = summary.failure_line() {
        println!("{line}");
    }
    if document.passed() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}
