//! Runs the plan's steps and keeps what each produced.
//!
//! Every step runs from the repository's root with its output in a log of its own under the
//! evidence directory, `KR_TEST_ARTIFACTS_DIR` naming that directory, so what a test records beside
//! its verdict lands with the result. A `cargo test` step is built once with `--no-run` first,
//! which is how the report learns which package and target each test binary is: two packages can
//! both have a test target called `fixtures`, and only the executable tells them apart.

use std::collections::BTreeMap;
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
    pub listed: BTreeMap<TargetId, std::collections::BTreeSet<String>>,
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
    if step.reading == Reading::Cargo && step.command.get(1).is_some_and(|word| word == "test") {
        match build_first(step, place, &log_path, packages) {
            Ok((built, map)) => {
                executed.built = built;
                executed.listed = list(step, place, &map);
                executables = map;
            }
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
    let output = std::fs::read(&log_path)
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        .unwrap_or_default();
    match &step.reading {
        Reading::Cargo => {
            for binary in libtest::read(&output) {
                let target = executables.get(&file_name(&binary.executable)).cloned();
                executed.binaries.push((target, binary));
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

/// The last component of an executable's path, which carries Cargo's hash and so names one build
/// of one target.
fn file_name(path: &str) -> String {
    path.rsplit(['/', '\\']).next().unwrap_or(path).to_owned()
}

/// Every test each binary of a step holds, as the binaries list them through Cargo, whatever the
/// step's own filters are. A binary that could not list is left out, and its tests are judged
/// from the run alone.
fn list(
    step: &Step,
    place: &Place<'_>,
    executables: &BTreeMap<String, TargetId>,
) -> BTreeMap<TargetId, std::collections::BTreeSet<String>> {
    let mut command: Vec<String> = step
        .command
        .iter()
        .take_while(|word| *word != "--")
        .cloned()
        .collect();
    command.extend(["--".to_owned(), "--list".to_owned()]);
    let Ok(output) = place
        .command(&command)
        .stdin(Stdio::null())
        .stderr(Stdio::piped())
        .output()
    else {
        return BTreeMap::new();
    };
    let mut listed = BTreeMap::new();
    if !output.status.success() {
        return listed;
    }
    // Cargo's lines are on standard error and the binaries' on standard output, so the two are
    // read apart and paired in order: each section Cargo announces, a binary or a crate's
    // documentation tests, prints one list, which ends with its count line.
    let sections: Vec<Option<String>> = String::from_utf8_lossy(&output.stderr)
        .lines()
        .filter_map(|line| {
            let line = line.trim_start();
            if line.starts_with("Doc-tests ") {
                return Some(None);
            }
            let rest = line.strip_prefix("Running ")?;
            let (_, executable) = rest.rsplit_once(" (")?;
            Some(Some(file_name(executable.strip_suffix(')')?)))
        })
        .collect();
    let mut lists: Vec<std::collections::BTreeSet<String>> = Vec::new();
    let mut current = std::collections::BTreeSet::new();
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        if let Some(name) = line
            .strip_suffix(": test")
            .or_else(|| line.strip_suffix(": bench"))
        {
            current.insert(name.to_owned());
        } else if is_count(line) {
            lists.push(std::mem::take(&mut current));
        }
    }
    if lists.len() != sections.len() {
        return listed;
    }
    for (section, names) in sections.into_iter().zip(lists) {
        if let Some(target) = section.and_then(|executable| executables.get(&executable)) {
            listed.insert(target.clone(), names);
        }
    }
    listed
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

/// A step's build: the targets it built, and which target each executable is.
type Built = (Vec<TargetId>, BTreeMap<String, TargetId>);

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
        if message["reason"] != "compiler-artifact" {
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
            executables.insert(file_name(executable), target.clone());
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
    use super::{file_name, is_count};

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
