//! `kr-conformance`: builds the identifier map, runs the suites that hold keyed tests and writes
//! the result keyed by identifier.
//!
//! ```text
//! kr-conformance run --root <repository> --evidence <directory> [--group <name>]...
//!                    [--applications <cache>]
//! kr-conformance map --root <repository> [--typescript]
//! ```
//!
//! `scripts/run-conformance.sh` is the way in: it fetches the applications, builds this binary and
//! runs it. The exit status is 0 when the run passed, 1 when it ran and did not, and 2 when it was
//! refused before running anything: a malformed identifier, a row outside section 21's or section
//! 27's table, an evidence directory outside the platform's temporary directory, or a map that
//! cannot be trusted.

use std::path::PathBuf;
use std::process::ExitCode;

use kr_conformance::evidence;
use kr_conformance::plan::{self, Group, Platform};
use kr_conformance::report::{self, Options, Stopped};

fn usage(problem: &str) -> ExitCode {
    eprintln!("kr-conformance: {problem}");
    eprintln!(
        "usage: kr-conformance run --root <repository> --evidence <directory> [--group <name>]... \
         [--applications <cache>]\n       kr-conformance map --root <repository> [--typescript]"
    );
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let Some(command) = arguments.first() else {
        return usage("no command");
    };
    let mut root = None;
    let mut evidence_directory = None;
    let mut groups = Vec::new();
    let mut applications = None;
    let mut typescript = false;
    let mut rest = arguments[1..].iter();
    while let Some(argument) = rest.next() {
        match argument.as_str() {
            "--root" => root = rest.next().map(PathBuf::from),
            "--evidence" => evidence_directory = rest.next().map(PathBuf::from),
            "--applications" => applications = rest.next().map(PathBuf::from),
            "--group" => match rest.next().map(String::as_str).and_then(Group::named) {
                Some(group) => groups.push(group),
                None => {
                    let names: Vec<&str> = Group::ALL.iter().map(|group| group.name()).collect();
                    return usage(&format!("--group takes one of {}", names.join(", ")));
                }
            },
            "--typescript" => typescript = true,
            other => return usage(&format!("{other} is not an option")),
        }
    }
    let Some(root) = root else {
        return usage("--root is required");
    };
    match command.as_str() {
        "map" => map(root, typescript),
        "run" => {
            let Some(evidence_directory) = evidence_directory else {
                return usage("--evidence is required");
            };
            run(root, &evidence_directory, groups, applications)
        }
        other => usage(&format!("{other} is not a command")),
    }
}

fn map(root: PathBuf, typescript: bool) -> ExitCode {
    let options = Options {
        root,
        evidence: PathBuf::new(),
        selection: Some(if typescript {
            vec![Group::Rust, Group::TypeScript]
        } else {
            vec![Group::Rust]
        }),
        platform: Platform::current(),
        case_tables: plan::CASE_TABLES,
        lanes: plan::LANES,
        applications: None,
        steps: None,
        environment: Vec::new(),
    };
    let map = report::map_for(&options);
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
    evidence_directory: &std::path::Path,
    groups: Vec<Group>,
    applications: Option<PathBuf>,
) -> ExitCode {
    let evidence = match evidence::check_directory(evidence_directory) {
        Ok(evidence) => evidence,
        Err(refused) => {
            eprintln!("kr-conformance: refused: {}", refused.0);
            return ExitCode::from(2);
        }
    };
    let selection = (!groups.is_empty()).then_some(groups);
    let runs_applications = selection
        .as_ref()
        .is_none_or(|groups| groups.contains(&Group::Applications));
    let applications = match (runs_applications, applications) {
        (true, Some(cache)) => match report::read_applications(&cache) {
            Ok(records) => Some(records),
            Err(problem) => {
                eprintln!("kr-conformance: {problem}");
                return ExitCode::from(2);
            }
        },
        (true, None) if Platform::current() != Platform::Windows => {
            return usage(
                "the applications group needs --applications <cache>, which the fetch step wrote",
            );
        }
        // Nothing is fetched here: each program is recorded with the reason the lock gives.
        (true, None) => match report::lock_applications(&root, Platform::current().name()) {
            Ok(records) => Some(records),
            Err(problem) => {
                eprintln!("kr-conformance: {problem}");
                return ExitCode::from(2);
            }
        },
        _ => None,
    };
    let options = Options {
        root,
        evidence: evidence.clone(),
        selection,
        platform: Platform::current(),
        case_tables: plan::CASE_TABLES,
        lanes: plan::LANES,
        applications,
        steps: None,
        environment: Vec::new(),
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
    }
    for failure in &document.failures_outside_identifiers {
        println!("failed outside any identifier: {failure}");
    }
    println!("result: {}", path.display());
    if document.passed() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}
