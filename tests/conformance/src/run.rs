//! Runs the plan's steps and keeps what each produced.
//!
//! Every step runs from the repository's root with its output in a log of its own under the
//! evidence directory, `KR_TEST_ARTIFACTS_DIR` naming that directory, so what a test records beside
//! its verdict lands with the result. A `cargo test` step is built once with `--no-run` first,
//! which is how the report learns which package and target each test binary is: two packages can
//! both have a test target called `fixtures`, and only the executable tells them apart.
//!
//! What the build names is what the run is held to. Every test binary it built is asked for its
//! list, and has to be run and read; a binary that does not list, one the log never ran, and a log
//! that cannot be read are each the step's error, so a step can never pass on less output than it
//! was built for. A target with a harness of its own (`harness = false`) is a program that prints
//! neither a list nor verdicts: it is not asked for a list, it is run with the step, and only its
//! exit status, which is the step's, counts.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Instant;

use crate::libtest::{self, Binary};
use crate::plan::{Reading, Step};
use crate::vitest;
use crate::workspace::{Package, TargetId};

/// What one step did.
#[derive(Clone, Debug)]
pub struct Executed {
    /// The step.
    pub step: Step,
    /// Its exit status, when it ran to one.
    pub exit: Option<i32>,
    /// How long it took, in seconds.
    pub seconds: u64,
    /// Its log, relative to the evidence directory.
    pub log: String,
    /// The test binaries it ran, each with the target it is, where that is known.
    pub binaries: Vec<(Option<TargetId>, Binary)>,
    /// The targets it built to test, as its build said.
    pub built: Vec<TargetId>,
    /// Every test each binary it built holds, as the binary lists them: a test a step's filters
    /// left out is listed here and absent from the outcomes, and one this platform's build does
    /// not have is absent from both.
    pub listed: BTreeMap<TargetId, BTreeSet<String>>,
    /// A vitest step's results.
    pub vitest: Option<vitest::Results>,
    /// Why it could not be run or read, when it could not.
    pub error: Option<String>,
}

/// Where a step runs: the repository it runs from, the evidence directory, and the variables it
/// is run with beyond the report's own environment.
#[derive(Clone, Copy, Debug)]
pub struct Place<'a> {
    /// The repository.
    pub root: &'a Path,
    /// The evidence directory.
    pub evidence: &'a Path,
    /// Further variables.
    pub environment: &'a [(String, String)],
}

impl Place<'_> {
    fn command(&self, words: &[String]) -> Command {
        let mut command = Command::new(&words[0]);
        command
            .args(&words[1..])
            .current_dir(self.root)
            .env("KR_TEST_ARTIFACTS_DIR", self.evidence)
            .env("CARGO_TERM_COLOR", "never")
            .envs(self.environment.iter().map(|(name, value)| (name, value)));
        command
    }
}

/// Runs `step`, the `number`th, at `place`, keeping its log under the evidence directory.
#[must_use]
pub fn execute(step: &Step, number: usize, place: &Place<'_>, packages: &[Package]) -> Executed {
    let logs = place.evidence.join("conformance").join("logs");
    let slug: String = step
        .what
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .split('-')
        .filter(|part| !part.is_empty())
        .take(8)
        .collect::<Vec<_>>()
        .join("-");
    let log_name = format!("{number:02}-{slug}.log");
    let log_path = logs.join(&log_name);
    let mut executed = Executed {
        step: step.clone(),
        exit: None,
        seconds: 0,
        log: format!("conformance/logs/{log_name}"),
        binaries: Vec::new(),
        built: Vec::new(),
        listed: BTreeMap::new(),
        vitest: None,
        error: None,
    };
    if let Err(error) = std::fs::create_dir_all(&logs) {
        executed.error = Some(format!("the log directory could not be made: {error}"));
        return executed;
    }
    if let Some(missing) = step
        .needs
        .iter()
        .find(|name| std::env::var_os(name).is_none())
    {
        executed.error = Some(format!("{missing} is not set, and this step reads it"));
        return executed;
    }
    let started = Instant::now();
    let mut executables: BTreeMap<String, TargetId> = BTreeMap::new();
    let tests =
        step.reading == Reading::Cargo && step.command.get(1).is_some_and(|word| word == "test");
    if tests {
        let listed = build_first(step, place, &log_path, packages).and_then(|(built, map)| {
            executed.built = built;
            let listed = list(&map, packages);
            executables = map
                .into_iter()
                .map(|(executable, (target, _))| (executable, target))
                .collect();
            listed
        });
        match listed {
            Ok(listed) => executed.listed = listed,
            Err(error) => {
                executed.seconds = started.elapsed().as_secs();
                executed.error = Some(error);
                return executed;
            }
        }
    }
    let status = run_logged(&step.command, place, &log_path);
    executed.seconds = started.elapsed().as_secs();
    match status {
        Ok(code) => executed.exit = code,
        Err(error) => {
            executed.error = Some(error);
            return executed;
        }
    }
    let output = match std::fs::read(&log_path) {
        Ok(bytes) => libtest::plain(&String::from_utf8_lossy(&bytes)),
        Err(error) => {
            executed.error = Some(format!("the step's log could not be read: {error}"));
            return executed;
        }
    };
    match &step.reading {
        Reading::Cargo => {
            for binary in libtest::read(&output) {
                let target = executables.get(&file_name(&binary.executable)).cloned();
                executed.binaries.push((target, binary));
            }
            if tests {
                executed.error = reconcile(&executables, &executed.binaries, executed.exit);
            }
        }
        Reading::Build => {}
        Reading::Vitest { .. } => {
            let report = step
                .command
                .iter()
                .find_map(|word| word.strip_prefix("--outputFile.json="))
                .map(PathBuf::from);
            match report.map(|path| vitest::read(&path, place.root)) {
                Some(Ok(results)) => executed.vitest = Some(results),
                Some(Err(error)) => executed.error = Some(error),
                None => executed.error = Some("the step names no JSON report".to_owned()),
            }
        }
    }
    executed
}

/// Holds what a step's log ran against what its build made: every test binary built is run once,
/// and nothing else is. Returns the step's error when they differ.
fn reconcile(
    executables: &BTreeMap<String, TargetId>,
    binaries: &[(Option<TargetId>, Binary)],
    exit: Option<i32>,
) -> Option<String> {
    let ran: BTreeSet<String> = binaries
        .iter()
        .filter(|(_, binary)| !binary.executable.starts_with("doc-tests "))
        .map(|(_, binary)| file_name(&binary.executable))
        .collect();
    let missing: Vec<String> = executables
        .iter()
        .filter(|(executable, _)| !ran.contains(*executable))
        .map(|(_, target)| target.to_string())
        .collect();
    if !missing.is_empty() {
        return Some(if exit == Some(0) {
            format!(
                "the step's log shows no run of {}, which its build made",
                missing.join(", ")
            )
        } else {
            format!("the step ended before it ran {}", missing.join(", "))
        });
    }
    let unknown: Vec<&str> = ran
        .iter()
        .filter(|executable| !executables.contains_key(*executable))
        .map(String::as_str)
        .collect();
    (!unknown.is_empty()).then(|| {
        format!(
            "the step's log runs {}, which its build did not make",
            unknown.join(", ")
        )
    })
}

/// The last component of an executable's path, which carries Cargo's hash and so names one build
/// of one target.
fn file_name(path: &str) -> String {
    path.rsplit(['/', '\\']).next().unwrap_or(path).to_owned()
}

/// Whether `target` runs under the standard test harness, as its package's manifest says.
#[must_use]
pub fn has_harness(packages: &[Package], target: &TargetId) -> bool {
    packages
        .iter()
        .flat_map(|package| &package.targets)
        .find(|candidate| candidate.id == *target)
        .is_none_or(|found| found.harness)
}

/// Every test each binary of a step holds, whatever the step's own filters are, as each binary
/// lists them when it is asked directly. A binary with a harness of its own is a program that
/// would run rather than list, so it is not asked.
///
/// # Errors
///
/// Returns the binary that could not be started, did not exit 0, or listed nothing it ended with
/// a count of: a binary that lists nothing would have its tests judged from the run alone.
fn list(
    executables: &BTreeMap<String, (TargetId, PathBuf)>,
    packages: &[Package],
) -> Result<BTreeMap<TargetId, BTreeSet<String>>, String> {
    let mut listed = BTreeMap::new();
    for (target, path) in executables.values() {
        if !has_harness(packages, target) {
            continue;
        }
        let mut command = Command::new(path);
        command.arg("--list").stdin(Stdio::null());
        // The package's directory, as Cargo gives it; and the build's own libraries beside the
        // binary, where a platform looks for the ones it links.
        if let Some(manifest) = packages
            .iter()
            .find(|package| package.name == target.package)
            .and_then(|package| package.manifest.parent())
        {
            command.current_dir(manifest);
        }
        if let Some(directory) = path.parent() {
            let variable = if cfg!(windows) {
                "PATH"
            } else if cfg!(target_os = "macos") {
                "DYLD_FALLBACK_LIBRARY_PATH"
            } else {
                "LD_LIBRARY_PATH"
            };
            let mut paths = vec![directory.to_owned()];
            paths.extend(
                std::env::var_os(variable)
                    .iter()
                    .flat_map(std::env::split_paths),
            );
            if let Ok(joined) = std::env::join_paths(paths) {
                command.env(variable, joined);
            }
        }
        let output = command
            .output()
            .map_err(|error| format!("{target} could not be asked for its tests: {error}"))?;
        if !output.status.success() {
            return Err(format!(
                "{target} did not list its tests (exit {})",
                output
                    .status
                    .code()
                    .map_or_else(|| "by a signal".to_owned(), |code| code.to_string())
            ));
        }
        let mut names = BTreeSet::new();
        let mut counted = false;
        for line in libtest::plain(&String::from_utf8_lossy(&output.stdout)).lines() {
            if let Some(name) = line
                .strip_suffix(": test")
                .or_else(|| line.strip_suffix(": bench"))
            {
                names.insert(name.to_owned());
            } else if is_count(line) {
                counted = true;
            }
        }
        if !counted {
            return Err(format!(
                "{target} listed its tests without the count that ends a list"
            ));
        }
        listed.insert(target.clone(), names);
    }
    Ok(listed)
}

/// Whether `line` is the count a test binary ends its list with: `3 tests, 0 benchmarks`.
fn is_count(line: &str) -> bool {
    let mut words = line.split_whitespace();
    matches!(
        (words.next(), words.next(), words.next(), words.next(), words.next()),
        (Some(tests), Some("test," | "tests,"), Some(benches), Some("benchmark" | "benchmarks"), None)
            if tests.parse::<u64>().is_ok() && benches.parse::<u64>().is_ok()
    )
}

/// A step's build: the targets it built, and which target each executable is, by its file name,
/// with its path.
type Built = (Vec<TargetId>, BTreeMap<String, (TargetId, PathBuf)>);

/// Builds a `cargo test` step's binaries without running them, and returns the targets it built
/// and which target each executable is.
fn build_first(
    step: &Step,
    place: &Place<'_>,
    log_path: &Path,
    packages: &[Package],
) -> Result<Built, String> {
    let mut command: Vec<String> = step
        .command
        .iter()
        .take_while(|word| *word != "--")
        .cloned()
        .collect();
    command.push("--no-run".to_owned());
    command.push("--message-format=json-render-diagnostics".to_owned());
    let mut log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
        .map_err(|error| format!("{} could not be opened: {error}", log_path.display()))?;
    let _ = writeln!(log, "== the build before the run: {}", command.join(" "));
    let output = place
        .command(&command)
        .stdin(Stdio::null())
        .stderr(Stdio::from(
            log.try_clone().map_err(|error| error.to_string())?,
        ))
        .output()
        .map_err(|error| format!("{} could not be started: {error}", command[0]))?;
    if !output.status.success() {
        return Err(format!(
            "the step's tests did not build (exit {}); the log has the compiler's output",
            output
                .status
                .code()
                .map_or_else(|| "by a signal".to_owned(), |code| code.to_string())
        ));
    }
    let mut built = Vec::new();
    let mut executables = BTreeMap::new();
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let Ok(message) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        // A test binary is a target built with the test profile; a program the tests launch is
        // built too, as itself, and is not one.
        if message["reason"] != "compiler-artifact" || message["profile"]["test"] != true {
            continue;
        }
        let Some(executable) = message["executable"].as_str() else {
            continue;
        };
        let Some(source) = message["target"]["src_path"].as_str() else {
            continue;
        };
        let name = message["target"]["name"].as_str().unwrap_or_default();
        let target = packages
            .iter()
            .flat_map(|package| &package.targets)
            .find(|target| target.src_path == Path::new(source) && target.id.name == name)
            .map(|target| target.id.clone());
        if let Some(target) = target {
            executables.insert(
                file_name(executable),
                (target.clone(), PathBuf::from(executable)),
            );
            if !built.contains(&target) {
                built.push(target);
            }
        }
    }
    Ok((built, executables))
}

/// Runs `command` at `place`, its standard output and error both appended to `log`, and returns
/// its exit status (none when a signal ended it).
fn run_logged(
    command: &[String],
    place: &Place<'_>,
    log_path: &Path,
) -> Result<Option<i32>, String> {
    let mut log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
        .map_err(|error| format!("{} could not be opened: {error}", log_path.display()))?;
    let _ = writeln!(log, "== {}", command.join(" "));
    let errors = log.try_clone().map_err(|error| error.to_string())?;
    let status = place
        .command(command)
        .stdin(Stdio::null())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(errors))
        .status()
        .map_err(|error| format!("{} could not be started: {error}", command[0]))?;
    Ok(status.code())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{Binary, file_name, is_count, reconcile};
    use crate::workspace::{TargetId, TargetKind};

    #[test]
    fn a_step_is_held_to_every_test_binary_its_build_made() {
        let target = TargetId {
            package: "p".to_owned(),
            kind: TargetKind::Test,
            name: "t".to_owned(),
        };
        let executables = BTreeMap::from([("t-1".to_owned(), target.clone())]);
        let ran = |executable: &str| {
            (
                Some(target.clone()),
                Binary {
                    executable: executable.to_owned(),
                    ..Binary::default()
                },
            )
        };
        assert_eq!(
            reconcile(&executables, &[ran("target/debug/deps/t-1")], Some(0)),
            None
        );
        assert!(
            reconcile(&executables, &[], Some(0)).is_some_and(|error| error.contains("no run of")),
            "a log with no run of a built binary"
        );
        assert!(
            reconcile(&executables, &[], Some(101))
                .is_some_and(|error| error.contains("ended before")),
            "a step that stopped at a failure"
        );
        assert!(
            reconcile(
                &executables,
                &[ran("target/debug/deps/t-1"), ran("target/debug/deps/u-2")],
                Some(0)
            )
            .is_some_and(|error| error.contains("did not make")),
            "a binary the build did not make"
        );
        let doctests = (
            None,
            Binary {
                executable: "doc-tests p".to_owned(),
                ..Binary::default()
            },
        );
        assert_eq!(
            reconcile(
                &executables,
                &[ran("target/debug/deps/t-1"), doctests],
                Some(0)
            ),
            None,
            "a crate's documentation tests are no binary of the build's"
        );
    }

    #[test]
    fn a_list_ends_with_its_count() {
        assert!(is_count("3 tests, 0 benchmarks"));
        assert!(is_count("1 test, 1 benchmark"));
        assert!(!is_count("tests::a: test"));
        assert!(!is_count("3 tests, 0 benchmarks, more"));
    }

    #[test]
    fn an_executable_is_known_by_its_last_component_on_every_platform() {
        assert_eq!(file_name("/t/debug/deps/fixtures-4bfa"), "fixtures-4bfa");
        assert_eq!(
            file_name("target\\debug\\deps\\fixtures-4bfa.exe"),
            "fixtures-4bfa.exe"
        );
        assert_eq!(file_name("fixtures-4bfa"), "fixtures-4bfa");
    }
}
