//! Runs the plan's steps and keeps what each produced.
//!
//! Every step runs from the repository's root with its output in a log of its own under the
//! evidence directory, `KR_TEST_ARTIFACTS_DIR` naming that directory, so what a test records beside
//! its verdict lands with the result. A `cargo test` step is built once with `--no-run` first,
//! which is how the report learns which package and target each test binary is: two packages can
//! both have a test target called `fixtures`, and only the executable tells them apart.
//!
//! What the build names is what the run is held to. Every test binary it built is listed, by the
//! step's own command with this program as Cargo's runner, and has to be run and read; a listing
//! that fails, a binary the log never ran, and a log that cannot be read are each the step's error,
//! so a step can never pass on less output than it was built for. Cargo hands the same runner to
//! rustdoc, whose programs of documentation tests are none of the build's and are keyed nowhere,
//! so the listing passes over them. A target with a harness of its own (`harness = false`) is a
//! program that prints neither a list nor verdicts: the runner does not run it while the tests are
//! listed, it is run with the step, and only its exit status, which is the step's, counts.

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
    /// This program, which Cargo runs each test binary through while the step's tests are listed.
    pub lister: &'a Path,
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
            let listed = list(step, place, &map, packages);
            executables = map;
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

/// The line the lister writes before it runs one test binary to list its tests, then the binary.
pub const LISTING_BEGIN: &str = "\u{1}kr-conformance listing\t";

/// The line the lister writes once that binary has exited: the binary, a tab, its exit status (or
/// `skipped` for a program with a harness of its own, which it does not run).
pub const LISTING_END: &str = "\u{1}kr-conformance listed\t";

/// The variable naming the test binaries with a harness of its own, by file name, comma separated.
pub const OWN_HARNESS_VARIABLE: &str = "KR_CONFORMANCE_OWN_HARNESS";

/// Runs one test binary for Cargo, as its runner, framed by the listing's two marker lines, and
/// returns its exit status: `arguments` are the binary and what Cargo passes it. A binary this
/// run's [`OWN_HARNESS_VARIABLE`] names is not run at all.
#[must_use]
pub fn list_one(arguments: &[String]) -> u8 {
    let Some((executable, rest)) = arguments.split_first() else {
        eprintln!("kr-conformance list-one: no test binary to run");
        return 2;
    };
    let own = std::env::var(OWN_HARNESS_VARIABLE).unwrap_or_default();
    let name = file_name(executable);
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{LISTING_BEGIN}{executable}");
    let _ = out.flush();
    drop(out);
    let status = if own.split(',').any(|entry| entry == name) {
        "skipped".to_owned()
    } else {
        match Command::new(executable).args(rest).status() {
            Ok(status) => status
                .code()
                .map_or_else(|| "a signal".to_owned(), |code| code.to_string()),
            Err(error) => format!("could not start: {error}"),
        }
    };
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{LISTING_END}{executable}\t{status}");
    let _ = out.flush();
    u8::from(!matches!(status.as_str(), "0" | "skipped"))
}

/// The host's target triple, as the toolchain the step builds with names it.
fn host(place: &Place<'_>) -> Result<String, String> {
    let output = place
        .command(&["rustc".to_owned(), "-vV".to_owned()])
        .stdin(Stdio::null())
        .output()
        .map_err(|error| format!("rustc could not be asked for the host: {error}"))?;
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .map(|host| host.trim().to_owned())
        .ok_or_else(|| "rustc named no host".to_owned())
}

/// Every test each binary of a step holds, whatever the step's own filters are, as each binary
/// lists them when Cargo runs it: the step's own command with `-- --list`, so the build is the
/// step's, features and all, and Cargo gives each binary its environment; with this program as
/// Cargo's runner, which frames each binary's list with the binary's own path, so each list is
/// known to be that binary's. A target with a harness of its own is a program that would run
/// rather than list, so the runner does not run it. Rustdoc runs the programs of a crate's
/// documentation tests through the same runner, and [`read_listing`] passes over them.
///
/// # Errors
///
/// Returns the listing that failed, and a listing [`read_listing`] cannot read: a binary that
/// lists nothing would have its tests judged from the run alone.
fn list(
    step: &Step,
    place: &Place<'_>,
    executables: &BTreeMap<String, TargetId>,
    packages: &[Package],
) -> Result<BTreeMap<TargetId, BTreeSet<String>>, String> {
    let lister = place
        .lister
        .to_str()
        .filter(|path| !path.chars().any(char::is_whitespace))
        .ok_or_else(|| {
            format!(
                "{} cannot be Cargo's runner: its path has a space in it",
                place.lister.display()
            )
        })?;
    let variable = format!(
        "CARGO_TARGET_{}_RUNNER",
        host(place)?.to_ascii_uppercase().replace(['-', '.'], "_")
    );
    let own: Vec<&str> = executables
        .iter()
        .filter(|(_, target)| !has_harness(packages, target))
        .map(|(executable, _)| executable.as_str())
        .collect();
    let mut command: Vec<String> = step
        .command
        .iter()
        .take_while(|word| *word != "--")
        .cloned()
        .collect();
    command.extend(["--".to_owned(), "--list".to_owned()]);
    let output = place
        .command(&command)
        .env(&variable, format!("{lister} list-one"))
        .env(OWN_HARNESS_VARIABLE, own.join(","))
        .stdin(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .map_err(|error| format!("the step's tests could not be listed: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "`{}` did not list the step's tests (exit {})",
            command.join(" "),
            output
                .status
                .code()
                .map_or_else(|| "by a signal".to_owned(), |code| code.to_string())
        ));
    }
    read_listing(&String::from_utf8_lossy(&output.stdout), executables, &own)
}

/// Reads what a step's listing printed into the tests each binary of the build's listed; `own`
/// names, by file name, the binaries with a harness of their own, which the runner does not run.
///
/// Cargo hands its runner to rustdoc as well, and rustdoc runs the programs it builds of a crate's
/// documentation tests through it, possibly several at once. Those programs are none of the
/// build's, and documentation tests are keyed nowhere, so their frames and what they print are
/// passed over, as is a list rustdoc prints itself. A line is a binary's only while that binary is
/// the one program open: Cargo runs its test binaries one at a time, before any documentation
/// test, so a binary of the build's whose frame overlaps another program's cannot have its list
/// told apart, and that is the step's error.
///
/// # Errors
///
/// Returns a binary of the build's run beside another program, a frame that ends where none began
/// or never ends, a binary with a standard harness that did not list its tests once and exit 0,
/// and one the build made that the listing never ran.
fn read_listing(
    output: &str,
    executables: &BTreeMap<String, TargetId>,
    own: &[&str],
) -> Result<BTreeMap<TargetId, BTreeSet<String>>, String> {
    let mut listed = BTreeMap::new();
    // The binary of the build's that is open, with the names and counts it has listed so far.
    let mut current: Option<(String, &TargetId, BTreeSet<String>, usize)> = None;
    // The other programs open: rustdoc's.
    let mut others: Vec<String> = Vec::new();
    for line in libtest::plain(output).lines() {
        if let Some(executable) = line.strip_prefix(LISTING_BEGIN) {
            let target = executables.get(&file_name(executable));
            let open = current
                .as_ref()
                .map(|(open, ..)| open)
                .or_else(|| others.last());
            if let Some(open) = open
                && (target.is_some() || current.is_some())
            {
                return Err(format!(
                    "the listing ran {executable} while {open} was running, so their lists cannot \
                     be told apart"
                ));
            }
            match target {
                Some(target) => current = Some((executable.to_owned(), target, BTreeSet::new(), 0)),
                None => others.push(executable.to_owned()),
            }
        } else if let Some(rest) = line.strip_prefix(LISTING_END) {
            let (ended, status) = rest.rsplit_once('\t').unwrap_or((rest, ""));
            if let Some(at) = others.iter().position(|other| other == ended) {
                others.remove(at);
                continue;
            }
            let Some((_, target, names, counts)) =
                current.take().filter(|(open, ..)| open == ended)
            else {
                return Err(format!("the listing ended {ended}, which it had not begun"));
            };
            if status == "skipped" {
                continue;
            }
            if status != "0" || counts != 1 {
                return Err(format!(
                    "{target} did not list its tests (exit {status}, {counts} lists)"
                ));
            }
            listed.insert(target.clone(), names);
        } else if let Some((_, _, names, counts)) = current.as_mut() {
            if let Some(name) = line
                .strip_suffix(": test")
                .or_else(|| line.strip_suffix(": bench"))
            {
                names.insert(name.to_owned());
            } else if is_count(line) {
                *counts += 1;
            }
        }
    }
    if let Some(executable) = current
        .map(|(executable, ..)| executable)
        .or_else(|| others.pop())
    {
        return Err(format!("the listing began {executable} and never ended it"));
    }
    let unlisted: Vec<String> = executables
        .iter()
        .filter(|(executable, target)| {
            !own.contains(&executable.as_str()) && !listed.contains_key(*target)
        })
        .map(|(_, target)| target.to_string())
        .collect();
    if !unlisted.is_empty() {
        return Err(format!(
            "the listing did not run {}, which the step's build made",
            unlisted.join(", ")
        ));
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

/// A step's build: the targets it built, and which target each executable is, by its file name.
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
    use std::collections::{BTreeMap, BTreeSet};

    use super::{Binary, LISTING_BEGIN, LISTING_END, file_name, is_count, read_listing, reconcile};
    use crate::workspace::{TargetId, TargetKind};

    fn test_target(name: &str) -> TargetId {
        TargetId {
            package: "p".to_owned(),
            kind: TargetKind::Test,
            name: name.to_owned(),
        }
    }

    fn begin(executable: &str) -> String {
        format!("{LISTING_BEGIN}{executable}\n")
    }

    fn end(executable: &str, status: &str) -> String {
        format!("{LISTING_END}{executable}\t{status}\n")
    }

    /// A binary of the build's listing `names`, framed as the lister frames it.
    fn listing(executable: &str, names: &[&str]) -> String {
        let mut text = begin(executable);
        for name in names {
            text.push_str(&format!("{name}: test\n"));
        }
        text.push_str(&format!("\n{} tests, 0 benchmarks\n", names.len()));
        text.push_str(&end(executable, "0"));
        text
    }

    #[test]
    fn a_listing_reads_the_builds_binaries_and_passes_over_the_documentation_tests_run_with_them() {
        let executables = BTreeMap::from([
            ("t-1".to_owned(), test_target("t")),
            ("u-2.exe".to_owned(), test_target("u")),
            ("own-3".to_owned(), test_target("own")),
        ]);
        let merged = "/tmp/rustdoctestA1/rust_out";
        let another = r"C:\Users\R\AppData\Local\Temp\rustdoctestB2\rust_out.exe";
        let output = [
            listing("/w/target/debug/deps/t-1", &["a::one", "a::two"]),
            listing(r"D:\w\target\debug\deps\u-2.exe", &["b"]),
            begin("/w/target/debug/deps/own-3"),
            end("/w/target/debug/deps/own-3", "skipped"),
            // Two programs of documentation tests at once, their lines mixed.
            begin(merged),
            begin(another),
            "src/lib.rs - f (line 3): test\n".to_owned(),
            "src/lib.rs - g (line 9): test\n\n1 test, 0 benchmarks\n".to_owned(),
            end(merged, "0"),
            "\n1 test, 0 benchmarks\n".to_owned(),
            end(another, "0"),
            // Documentation tests rustdoc lists itself, running no program.
            "src/lib.rs - h (line 20): test\n\n1 test, 0 benchmarks\n".to_owned(),
        ]
        .concat();
        let listed = read_listing(&output, &executables, &["own-3"]).expect("reads");
        let names = |names: &[&str]| -> BTreeSet<String> {
            names.iter().map(|name| (*name).to_owned()).collect()
        };
        assert_eq!(
            listed,
            BTreeMap::from([
                (test_target("t"), names(&["a::one", "a::two"])),
                (test_target("u"), names(&["b"])),
            ])
        );
    }

    #[test]
    fn a_listing_that_cannot_be_told_apart_or_is_short_is_the_steps_error() {
        let executables = BTreeMap::from([
            ("t-1".to_owned(), test_target("t")),
            ("u-2".to_owned(), test_target("u")),
        ]);
        let first = "/w/target/debug/deps/t-1";
        let second = "/w/target/debug/deps/u-2";
        let doctests = "/tmp/rustdoctestA1/rust_out";
        let read = |parts: &[String]| read_listing(&parts.concat(), &executables, &[]);
        let fails = |parts: &[String], what: &str| match read(parts) {
            Err(error) => assert!(error.contains(what), "{error:?} names {what:?}"),
            Ok(listed) => panic!("read as {listed:?}, where {what:?} was due"),
        };
        assert!(read(&[listing(first, &["a"]), listing(second, &["b"])]).is_ok());
        fails(
            &[
                begin(first),
                begin(doctests),
                "a: test\n\n1 test, 0 benchmarks\n".to_owned(),
                end(doctests, "0"),
                end(first, "0"),
                listing(second, &["b"]),
            ],
            "cannot be told apart",
        );
        fails(
            &[
                begin(doctests),
                listing(first, &["a"]),
                end(doctests, "0"),
                listing(second, &["b"]),
            ],
            "cannot be told apart",
        );
        fails(&[listing(first, &["a"])], "did not run p --test u");
        fails(
            &[
                begin(first),
                "a: test\n".to_owned(),
                end(first, "0"),
                listing(second, &["b"]),
            ],
            "did not list its tests (exit 0, 0 lists)",
        );
        fails(
            &[
                begin(first),
                "\n0 tests, 0 benchmarks\n".to_owned(),
                end(first, "101"),
                listing(second, &["b"]),
            ],
            "did not list its tests (exit 101",
        );
        fails(
            &[
                end(doctests, "0"),
                listing(first, &["a"]),
                listing(second, &["b"]),
            ],
            "had not begun",
        );
        fails(
            &[
                listing(first, &["a"]),
                begin(second),
                "b: test\n".to_owned(),
            ],
            "never ended",
        );
        fails(
            &[
                listing(first, &["a"]),
                listing(second, &["b"]),
                begin(doctests),
            ],
            "never ended",
        );
    }

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
