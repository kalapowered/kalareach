//! Runs the plan's steps and keeps what each produced.
//!
//! Every step runs from the repository's root with its output in a log of its own under the
//! evidence directory, `KR_TEST_ARTIFACTS_DIR` naming that directory, so what a test records beside
//! its verdict lands with the result. A `cargo test` step is built once with `--no-run` first,
//! which is how the report learns which package and target each test binary is: two packages can
//! both have a test target called `fixtures`, and only the executable tells them apart. The calls
//! after the build, the listing and the run, have nothing to build unless a macro wrote a file while
//! a crate compiled: Cargo takes that file for newer than the compile and builds the crate again in
//! the listing. The build dates such a file before it began when `date_before` can tell that no
//! compile of the crate can have read it while another wrote it. When it cannot, it leaves the file
//! to Cargo, which builds the crate again, and the log says why. A listing that builds anyway says
//! so in the log.
//!
//! What the build names is what the run is held to. Every test binary it built is listed, by the
//! step's own command with this program as Cargo's runner, and has to be run and read; a listing
//! that fails, a binary the log never ran, and a log that cannot be read are each the step's error,
//! so a step can never pass on less output than it was built for. Cargo hands the same runner to
//! rustdoc, whose programs of documentation tests are none of the build's and are keyed nowhere,
//! so the listing passes over them. A target with a harness of its own (`harness = false`) is a
//! program that prints neither a list nor verdicts: the runner does not run it while the tests are
//! listed, it is run with the step, and only its exit status, which is the step's, counts.
//!
//! The step then runs with this program as Cargo's runner again, and the runner gives each test
//! binary of the build's that runs under the standard harness the harness's option to write a
//! record of its own: what each test came to, in a file of its own in a directory beside the step's
//! log. The log is shared by everything the tests and the programs they start write, so a line of
//! it can begin in the middle of another; the record has one writer. A binary that ran and left no
//! record that can be read, and a binary the log runs twice, are the step's error.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime};

use crate::lane;
use crate::libtest::{self, Binary, Recording};
use crate::plan::{Reading, Step, Tests};
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
    /// A phone lane's cases, as its tool reported them and the exit status agreed with them.
    pub lane: Option<Vec<lane::Case>>,
    /// What the step's script said it ran with, in the `kr-tool: <name>: <value>` lines it prints.
    pub tools: Vec<(String, String)>,
    /// Why it could not be run or read, when it could not.
    pub error: Option<String>,
    /// What a second run of the step followed, when a file the first run linked could not be
    /// started.
    pub rerun: Option<crate::fault::Rerun>,
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
        lane: None,
        tools: Vec::new(),
        error: None,
        rerun: None,
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
    let mut environment: Vec<(String, String)> = Vec::new();
    let records = logs.join(format!("{}.records", log_name.trim_end_matches(".log")));
    let tests =
        step.reading == Reading::Cargo && step.command.get(1).is_some_and(|word| word == "test");
    if tests {
        let prepared = build_first(step, place, &log_path, packages)
            .and_then(|(built, map)| {
                executed.built = built;
                let listed = list(step, place, &log_path, &map, packages)?;
                executables = map;
                Ok(listed)
            })
            .and_then(|listed| {
                environment =
                    recording(place, &standard_harness(&executables, packages), &records)?;
                Ok(listed)
            });
        match prepared {
            Ok(listed) => executed.listed = listed,
            Err(error) => {
                executed.seconds = started.elapsed().as_secs();
                executed.error = Some(error);
                return executed;
            }
        }
    }
    let status = run_logged(&step.command, place, &log_path, &environment);
    executed.seconds = started.elapsed().as_secs();
    match status {
        Ok(code) => executed.exit = code,
        Err(error) => {
            executed.error = Some(error);
            return executed;
        }
    }
    let output = match std::fs::read(&log_path) {
        Ok(bytes) => {
            let text = String::from_utf8_lossy(&bytes);
            executed.tools = text
                .lines()
                .filter_map(|line| line.strip_prefix(TOOL_LINE))
                .filter_map(|line| line.split_once(": "))
                .map(|(name, value)| {
                    let value = value.trim();
                    (
                        name.to_owned(),
                        if value.is_empty() { "unknown" } else { value }.to_owned(),
                    )
                })
                .collect();
            libtest::plain(&text)
        }
        Err(error) => {
            executed.error = Some(format!("the step's log could not be read: {error}"));
            return executed;
        }
    };
    match &step.reading {
        Reading::Cargo => {
            let records = if tests {
                read_records(
                    &records,
                    &standard_harness(&executables, packages),
                    &executables,
                    &executed.listed,
                )
            } else {
                BTreeMap::new()
            };
            for binary in libtest::read(&output, |executable| {
                match records.get(&file_name(executable)) {
                    Some(Ok(record)) => Recording::Record(record),
                    Some(Err(why)) => Recording::Lost(why),
                    None => Recording::None,
                }
            }) {
                let target = executables.get(&file_name(&binary.executable)).cloned();
                executed.binaries.push((target, binary));
            }
            if tests {
                executed.error = reconcile(&executables, &executed.binaries, executed.exit)
                    .or_else(|| unrecorded(&records, &executed.binaries));
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
        Reading::Lane(tests) => {
            let results = step
                .command
                .iter()
                .find_map(|word| word.strip_prefix("--results="))
                .map(PathBuf::from);
            let read = match (results, tests) {
                (Some(path), Tests::Junit) => lane::read_junit(&path),
                (Some(path), Tests::Xcode) => lane::read_xcode(&path),
                (None, _) => Err("the step names no place for its results".to_owned()),
            };
            match read.and_then(|cases| {
                lane::agree_with_exit(executed.exit, &cases)?;
                Ok(cases)
            }) {
                Ok(cases) => executed.lane = Some(cases),
                Err(error) => executed.error = Some(error),
            }
        }
    }
    executed
}

/// The beginning of a line in which a lane's script says what it ran with.
pub const TOOL_LINE: &str = "kr-tool: ";

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
/// run's [`OWN_HARNESS_VARIABLE`] names is not run at all. A binary that fails, or cannot be
/// started, is also said so on the standard error.
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
    let (status, failure) = if own.split(',').any(|entry| entry == name) {
        ("skipped".to_owned(), None)
    } else {
        match Command::new(executable).args(rest).status() {
            Ok(ended) => (
                ended
                    .code()
                    .map_or_else(|| "a signal".to_owned(), |code| code.to_string()),
                (!ended.success()).then(|| format!("ended with {ended}")),
            ),
            Err(error) => {
                let failure = format!("could not start: {error}");
                (failure.clone(), Some(failure))
            }
        }
    };
    // Cargo shows only that its runner failed, so the reason is also said where a failed listing's
    // error is read from.
    if let Some(failure) = failure {
        eprintln!("kr-conformance list-one: {executable} {failure}");
    }
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{LISTING_END}{executable}\t{status}");
    let _ = out.flush();
    u8::from(!matches!(status.as_str(), "0" | "skipped"))
}

/// Runs one program for Cargo, as its runner, while a step's tests are run, and returns its exit
/// status: `arguments` are the program and what Cargo passes it. Cargo runs every test binary and,
/// for a crate's documentation tests, rustdoc's programs through it. A binary that the run's
/// [`RECORDED_BINARIES`] names is given the option to write its record to a file of its own in
/// [`RECORDS_VARIABLE`]'s directory; any other program runs as it is.
#[must_use]
pub fn run_one(arguments: &[String]) -> u8 {
    let Some((executable, rest)) = arguments.split_first() else {
        eprintln!("kr-conformance run-one: no test binary to run");
        return 2;
    };
    let name = file_name(executable);
    let mut command = Command::new(executable);
    if let Some(records) = std::env::var_os(RECORDS_VARIABLE).map(PathBuf::from)
        && std::fs::read_to_string(records.join(RECORDED_BINARIES))
            .is_ok_and(|list| list.lines().any(|line| line == name))
    {
        command.arg("--logfile").arg(records.join(&name));
    }
    match command.args(rest).status() {
        Ok(status) => status
            .code()
            .and_then(|code| u8::try_from(code).ok())
            .unwrap_or_else(|| {
                // Cargo shows the status of the runner, so the status of the program is said here.
                eprintln!("kr-conformance run-one: {executable} ended with {status}");
                1
            }),
        Err(error) => {
            eprintln!("kr-conformance run-one: {executable} could not start: {error}");
            1
        }
    }
}

/// The variable that makes Cargo run each test binary through this program's `command`, and its
/// value.
fn runner(place: &Place<'_>, command: &str) -> Result<(String, String), String> {
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
    Ok((variable, format!("{lister} {command}")))
}

/// The file names of the binaries of a build that run under the standard harness.
fn standard_harness(
    executables: &BTreeMap<String, TargetId>,
    packages: &[Package],
) -> BTreeSet<String> {
    executables
        .iter()
        .filter(|(_, target)| has_harness(packages, target))
        .map(|(executable, _)| executable.clone())
        .collect()
}

/// The variable naming the directory a run keeps the harness's records in: [`RECORDED_BINARIES`],
/// and one file for each of the binaries it lists, named as the binary is.
pub const RECORDS_VARIABLE: &str = "KR_CONFORMANCE_RECORDS";

/// The file, in the directory [`RECORDS_VARIABLE`] names, that lists by file name the binaries a
/// step's build made that run under the standard harness, one on each line.
pub const RECORDED_BINARIES: &str = "binaries.txt";

/// Makes the directory for the harness's records, and lists in it the binaries of `harness`. It
/// returns the variables that make Cargo run every test binary, and rustdoc's programs, through this
/// program, which gives the binaries listed the option to write a record there.
fn recording(
    place: &Place<'_>,
    harness: &BTreeSet<String>,
    records: &Path,
) -> Result<Vec<(String, String)>, String> {
    let (variable, runner) = runner(place, "run-one")?;
    let list: String = harness.iter().map(|name| format!("{name}\n")).collect();
    std::fs::create_dir(records)
        .and_then(|()| std::fs::write(records.join(RECORDED_BINARIES), list))
        .map_err(|error| format!("{} could not be made: {error}", records.display()))?;
    Ok(vec![
        (variable, runner),
        (
            RECORDS_VARIABLE.to_owned(),
            records.to_string_lossy().into_owned(),
        ),
    ])
}

/// What each binary of `standard`, the build's that run under the standard harness, left as its
/// record, by file name: the record, or why there is none that can be used. `listed` has the tests
/// each target holds, which tell the entries of a record apart.
fn read_records(
    directory: &Path,
    standard: &BTreeSet<String>,
    executables: &BTreeMap<String, TargetId>,
    listed: &BTreeMap<TargetId, BTreeSet<String>>,
) -> BTreeMap<String, Result<libtest::Record, String>> {
    standard
        .iter()
        .map(|name| {
            let record = match std::fs::read(directory.join(name)) {
                Ok(bytes) => {
                    let known = executables
                        .get(name)
                        .and_then(|target| listed.get(target))
                        .cloned()
                        .unwrap_or_default();
                    libtest::read_record(&String::from_utf8_lossy(&bytes), &known)
                        .map_err(|error| format!("its record could not be read: {error}"))
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    Err("the harness left no record of its run".to_owned())
                }
                Err(error) => Err(format!("its record could not be read: {error}")),
            };
            (name.clone(), record)
        })
        .collect()
}

/// The step's error when a binary that ran under the standard harness has no record that can be
/// used, or when one record would stand for two runs.
fn unrecorded(
    records: &BTreeMap<String, Result<libtest::Record, String>>,
    binaries: &[(Option<TargetId>, Binary)],
) -> Option<String> {
    let mut seen = BTreeSet::new();
    let mut twice = Vec::new();
    let mut lost = Vec::new();
    for (_, binary) in binaries {
        if binary.executable.starts_with("doc-tests ") {
            continue;
        }
        let name = file_name(&binary.executable);
        if !seen.insert(name.clone()) {
            twice.push(name.clone());
        }
        if let Some(Err(why)) = records.get(&name) {
            lost.push(format!("{name}: {why}"));
        }
    }
    if !twice.is_empty() {
        return Some(format!(
            "the step's log runs {} more than once, and one record cannot stand for each run",
            twice.join(", ")
        ));
    }
    (!lost.is_empty()).then(|| {
        format!(
            "what the tests of a binary came to is not known: {}",
            lost.join("; ")
        )
    })
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
/// lists nothing would have its tests judged from the run alone. A listing that failed leaves its
/// standard output and standard error in the step's log, and the end of its standard error is
/// named in the error.
fn list(
    step: &Step,
    place: &Place<'_>,
    log_path: &Path,
    executables: &BTreeMap<String, TargetId>,
    packages: &[Package],
) -> Result<BTreeMap<TargetId, BTreeSet<String>>, String> {
    let (variable, runner) = runner(place, "list-one")?;
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
        .env(&variable, runner)
        .env(OWN_HARNESS_VARIABLE, own.join(","))
        .stdin(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .map_err(|error| format!("the step's tests could not be listed: {error}"))?;
    let standard_error = String::from_utf8_lossy(&output.stderr);
    if !output.status.success() {
        let command = command.join(" ");
        let code = output
            .status
            .code()
            .map_or_else(|| "by a signal".to_owned(), |code| code.to_string());
        let kept = keep_failed_listing(
            log_path,
            &format!("`{command}` (exit {code})"),
            &String::from_utf8_lossy(&output.stdout),
            &standard_error,
        )
        .map_or_else(|error| error, |()| "the log has all of it".to_owned());
        return Err(format!(
            "`{command}` did not list the step's tests (exit {code}); {} ({kept})",
            ends_of(&libtest::plain(&standard_error), place.root)
        ));
    }
    // A listing is not a build: the step's tests were built before it. Say so in the log when it
    // compiled anything, which takes time and disk the step's own run does not account for.
    let compiled: Vec<&str> = standard_error
        .lines()
        .map(str::trim_start)
        .filter(|line| line.starts_with("Compiling "))
        .collect();
    if !compiled.is_empty() {
        let _ = append_to_log(
            log_path,
            &format!("== the listing compiled again:\n{}\n", compiled.join("\n")),
        );
    }
    read_listing(&String::from_utf8_lossy(&output.stdout), executables, &own)
}

/// How many of the last lines of a failed listing's standard error the step's error names.
const ERROR_LINES: usize = 6;

/// How many bytes of those lines the step's error keeps at most.
const ERROR_BYTES: usize = 800;

/// The end of a failed listing's standard error as the step's error names it: its last
/// [`ERROR_LINES`] lines that say anything, on one line, the last [`ERROR_BYTES`] bytes of them at
/// most, with the checkout's path left out of them (a result names none). Only what says why the
/// first failed program failed counts ([`what_the_program_said`]): Cargo writes its account of a
/// failure, and its lines for the programs it goes on to, after the program's own words, and they
/// would take the place of the lines that say why.
fn ends_of(standard_error: &str, root: &Path) -> String {
    let resolved = std::fs::canonicalize(root).ok();
    ends_of_root_resolved(standard_error, root, resolved.as_deref())
}

/// [`ends_of`] with the checkout's physical path, `resolved`, given.
fn ends_of_root_resolved(standard_error: &str, root: &Path, resolved: Option<&Path>) -> String {
    let lines = what_the_program_said(standard_error);
    if lines.is_empty() {
        return if standard_error.trim().is_empty() {
            "it wrote nothing to its standard error".to_owned()
        } else {
            "it wrote only Cargo's account of the failure to its standard error".to_owned()
        };
    }
    let mut ends = lines[lines.len().saturating_sub(ERROR_LINES)..].join(" | ");
    // The root as it is given may be relative, or have `..` or a link in it, and the paths in the
    // output are the working directory's own.
    let given = std::path::absolute(root).unwrap_or_else(|_| root.to_path_buf());
    let mut spellings = vec![given.to_string_lossy().into_owned()];
    // The physical path differs from it by a link or a junction on the way. On Windows it has a
    // `\\?\` prefix that Cargo's output does not carry, so it is left out with and without it.
    if let Some(physical) = resolved {
        let physical = physical.to_string_lossy().into_owned();
        spellings.extend(without_the_verbatim_prefix(&physical));
        spellings.push(physical);
    }
    for spelling in spellings.clone() {
        let backslashes = spelling.replace('/', "\\");
        // A path that rustc quotes in a note (a failed link, for one) has each backslash doubled.
        spellings.push(backslashes.replace('\\', "\\\\"));
        spellings.push(backslashes);
        spellings.push(spelling.replace('\\', "/"));
    }
    // A longer spelling first, so that one that contains another is not cut in two.
    spellings.sort_by_key(|spelling| std::cmp::Reverse(spelling.len()));
    for spelling in spellings {
        if spelling.len() > 1 {
            ends = ends.replace(&spelling, "<root>");
        }
    }
    let mut ends = without_machine_paths(&ends);
    if ends.len() > ERROR_BYTES {
        // Three bytes of the limit are the dots.
        let mut from = ends.len() - (ERROR_BYTES - 3);
        while !ends.is_char_boundary(from) {
            from += 1;
        }
        ends = format!("...{}", &ends[from..]);
    }
    format!("its standard error ends: {ends}")
}

/// `text` with each absolute path in it cut to its last component. A result names no path of this
/// machine (the checkout's is `<root>`), and what a test binary, a target directory outside the
/// checkout or the runner is called by is one; the step's log holds every path whole.
fn without_machine_paths(text: &str) -> String {
    let is_mark = |c: char| {
        matches!(
            c,
            '`' | '\'' | '"' | '(' | ')' | '[' | ']' | ',' | ';' | ':'
        )
    };
    text.split(' ')
        .map(|word| {
            let start = word.find(|c| !is_mark(c)).unwrap_or(word.len());
            let end = word.rfind(|c| !is_mark(c)).map_or(start, |last| {
                last + word[last..].chars().next().map_or(0, char::len_utf8)
            });
            let path = &word[start..end];
            let bytes = path.as_bytes();
            let absolute = path.starts_with('/')
                || path.starts_with("\\\\")
                || (bytes.len() > 2
                    && bytes[0].is_ascii_alphabetic()
                    && bytes[1] == b':'
                    && matches!(bytes[2], b'\\' | b'/'));
            match path.rsplit(['/', '\\']).next() {
                Some(last) if absolute && !last.is_empty() => {
                    format!("{}{last}{}", &word[..start], &word[end..])
                }
                _ => word.to_owned(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// `path` without the prefix that Windows gives a physical path: `\\?\C:\a` is `C:\a`, and
/// `\\?\UNC\server\share` is `\\server\share`. None when it has no such prefix.
fn without_the_verbatim_prefix(path: &str) -> Option<String> {
    if let Some(rest) = path.strip_prefix(r"\\?\UNC\") {
        return Some(format!(r"\\{rest}"));
    }
    path.strip_prefix(r"\\?\").map(str::to_owned)
}

/// The lines of `text`, trimmed, that say why Cargo's first failed program failed: the lines before
/// Cargo's first line about it, "error: test failed, to rerun pass ..." (or "error: doctest failed
/// ..."), and the causes Cargo gives after that line. Cargo lets a program write to its standard
/// error as it runs, so what the program said stands before the line. What Cargo says of the
/// program after it (its "Caused by:" blocks, which are all the cause there is when the runner could
/// not start or was killed) is kept, but not a plain exit status, which says nothing the runner's
/// own words do not. The note that follows, the status lines of every program
/// Cargo goes on to when it was told to, and its header "error: N targets failed:" with the
/// indented, backquoted command lines that follow, are left out. A similar line anywhere else is
/// kept.
fn what_the_program_said(text: &str) -> Vec<String> {
    let mut said = Vec::new();
    let mut in_the_account = false;
    let mut lines = text.lines();
    while let Some(line) = lines.next() {
        let trimmed = line.trim();
        if trimmed.is_empty() || is_a_cargo_status_line(line) {
            continue;
        }
        if trimmed.starts_with("error: test failed, to rerun pass")
            || trimmed.starts_with("error: doctest failed, to rerun pass")
        {
            said.extend(causes_cargo_gives(lines));
            break;
        }
        if names_the_targets_that_failed(trimmed) {
            in_the_account = true;
            continue;
        }
        if in_the_account {
            if line.starts_with(char::is_whitespace)
                && trimmed.starts_with('`')
                && trimmed.ends_with('`')
            {
                continue;
            }
            in_the_account = false;
        }
        said.push(trimmed.to_owned());
    }
    said
}

/// Whether `line` is one of Cargo's status lines: a verb, right-aligned in twelve columns, then a
/// space ("    Finished `test` profile ...", "     Running unittests ...", "   Doc-tests a").
/// They say where Cargo was and name the programs it ran, and not why one failed.
fn is_a_cargo_status_line(line: &str) -> bool {
    const VERBS: [&str; 14] = [
        "Compiling",
        "Finished",
        "Running",
        "Doc-tests",
        "Fresh",
        "Checking",
        "Documenting",
        "Blocking",
        "Locking",
        "Updating",
        "Adding",
        "Removing",
        "Downloading",
        "Downloaded",
    ];
    let said = line.trim_start();
    let indent = line.len() - said.len();
    VERBS.iter().any(|verb| {
        indent + verb.len() == 12
            && said
                .strip_prefix(verb)
                .is_some_and(|rest| rest.starts_with(' '))
    })
}

/// The causes in the "Caused by:" blocks that follow a line about a failed program, in `after`, the
/// lines after it. Cargo indents a cause by two spaces, each of its lines when it runs over
/// several, and its own status lines by more; a cause is the lines of its block, joined. A plain
/// exit status of the runner (a number, and not a signal or a Windows status in hexadecimal) is none
/// of them.
fn causes_cargo_gives<'a>(after: impl Iterator<Item = &'a str>) -> Vec<String> {
    let mut causes = Vec::new();
    let mut after = after.filter(|line| !line.trim().is_empty()).peekable();
    while after.next().is_some_and(|line| line.trim() == "Caused by:") {
        let mut cause = Vec::new();
        while let Some(line) =
            after.next_if(|line| line.starts_with("  ") && !line.starts_with("   "))
        {
            cause.push(line.trim());
        }
        if cause.is_empty() {
            break;
        }
        let cause = cause.join(" ");
        if !is_a_plain_exit_status(&cause) {
            causes.push(cause);
        }
    }
    causes
}

/// Whether `cause` is "process didn't exit successfully: `...` (exit status: 3)", or the Windows
/// "(exit code: 3)", with a decimal number.
fn is_a_plain_exit_status(cause: &str) -> bool {
    cause.starts_with("process didn't exit successfully: ")
        && cause
            .strip_suffix(')')
            .and_then(|rest| rest.rsplit_once('('))
            .and_then(|(_, status)| {
                status
                    .strip_prefix("exit status: ")
                    .or_else(|| status.strip_prefix("exit code: "))
            })
            .is_some_and(|number| !number.is_empty() && number.bytes().all(|b| b.is_ascii_digit()))
}

/// Whether `line` is "error: 1 target failed:" or "error: 3 targets failed:".
fn names_the_targets_that_failed(line: &str) -> bool {
    line.strip_prefix("error: ")
        .and_then(|rest| rest.strip_suffix(" failed:"))
        .and_then(|rest| rest.split_once(' '))
        .is_some_and(|(count, noun)| {
            count.parse::<u32>().is_ok() && matches!(noun, "target" | "targets")
        })
}

/// Appends what a failed listing wrote to the step's log, whole: the log is where the next failure
/// of the same kind is read.
fn keep_failed_listing(
    log_path: &Path,
    what: &str,
    standard_output: &str,
    standard_error: &str,
) -> Result<(), String> {
    append_to_log(
        log_path,
        &format!(
            "== the listing failed: {what}\n== its standard output\n{standard_output}\n\
             == its standard error\n{standard_error}\n"
        ),
    )
}

/// Appends `text` to the step's log.
fn append_to_log(log_path: &Path, text: &str) -> Result<(), String> {
    let mut log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)
        .map_err(|error| format!("{} could not be opened: {error}", log_path.display()))?;
    log.write_all(text.as_bytes())
        .map_err(|error| format!("{} could not be written: {error}", log_path.display()))
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
    let began = SystemTime::now();
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
    let mut outputs = Vec::new();
    let mut compiled = Vec::new();
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let Ok(message) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        // The output directory of a build script of a crate of this tree (a path, not a registry),
        // and what this build compiled of such a crate.
        let tree_package = message["package_id"]
            .as_str()
            .filter(|package| package.starts_with("path+"));
        if let Some(package) = tree_package {
            if message["reason"] == "build-script-executed"
                && let Some(directory) = message["out_dir"].as_str()
            {
                outputs.push((package.to_owned(), PathBuf::from(directory)));
                continue;
            }
            if message["reason"] == "compiler-artifact" && message["fresh"] != true {
                compiled.extend(Compiled::from_artifact(package, &message, began));
            }
        }
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
    let dating = date_before(&outputs, &compiled, began);
    if dating.dated > 0 || !dating.left.is_empty() {
        let _ = append_to_log(
            log_path,
            &format!(
                "== files named by a digest that the build wrote were dated before it began, so \
                 that Cargo does not compile their crate again: {}\n{}",
                dating.dated,
                dating
                    .left
                    .iter()
                    .map(|file| format!("{file}\n"))
                    .collect::<String>()
            ),
        );
    }
    Ok((built, executables))
}

/// What a compile of a crate of this tree was, for deciding whether two of them could have run
/// beside each other.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Unit {
    /// The package's library, in a form a program links as Rust.
    Library,
    /// The package's library built with its unit tests, which does not wait for the library.
    LibraryTests,
    /// A program or a test program of the package, which links the library and so waits for it, or
    /// a library that only another language links, which nothing waits for.
    Other,
}

/// A crate of this tree that a build compiled (and did not find fresh), with the files its compile
/// read.
#[derive(Debug)]
struct Compiled {
    /// The package it is of, as Cargo names it in its messages.
    package: String,
    /// What it is.
    unit: Unit,
    /// Rustc's dependency file for it: every file the compile read, when that file could be read.
    read: Option<String>,
}

impl Compiled {
    /// The unit a `compiler-artifact` message of Cargo's describes, unless it is a build script.
    /// `began` is when the build began: only a dependency file written since then is the build's.
    fn from_artifact(
        package: &str,
        message: &serde_json::Value,
        began: SystemTime,
    ) -> Option<Self> {
        let kinds: Vec<&str> = message["target"]["kind"]
            .as_array()?
            .iter()
            .filter_map(serde_json::Value::as_str)
            .collect();
        if kinds.contains(&"custom-build") {
            return None;
        }
        let tests = message["profile"]["test"] == true;
        // What a program can link as Rust, which Cargo makes it wait for. A `cdylib` or a
        // `staticlib` is an output of its own, and nothing waits for it.
        let library = kinds
            .iter()
            .any(|kind| matches!(*kind, "lib" | "rlib" | "dylib" | "proc-macro"));
        let unit = match (library, tests) {
            (true, false) => Unit::Library,
            (true, true) => Unit::LibraryTests,
            (false, _) => Unit::Other,
        };
        let outputs: Vec<PathBuf> = message["executable"]
            .as_str()
            .into_iter()
            .chain(
                message["filenames"]
                    .as_array()?
                    .iter()
                    .filter_map(serde_json::Value::as_str),
            )
            .map(PathBuf::from)
            .collect();
        let name = message["target"]["name"].as_str()?.replace('-', "_");
        Some(Self {
            package: package.to_owned(),
            unit,
            read: dependency_file(&name, &outputs, began)
                .and_then(|path| std::fs::read_to_string(path).ok()),
        })
    }
}

/// Rustc's dependency file for the compile of crate `name` that made `outputs`, which lists every
/// file the compile read. It lies in the `deps` directory, named for the crate and the hash of the
/// compile (`host-<hash>.d` for the program `host-<hash>`, `krate-<hash>.d` for
/// `libkrate-<hash>.rlib`), or for the crate alone when a library has other crate types too
/// (`krate.d` for `libkrate.rlib`). A program that Cargo copied out of `deps` has no hash in its
/// name, and on Windows a program has none in `deps` either (`kalareach_companion.d` for
/// `kalareach_companion.exe`): then the one dependency file of the crate that this build wrote,
/// with a hash in its name or without, is it, and when there are two the file is not told.
fn dependency_file(name: &str, outputs: &[PathBuf], began: SystemTime) -> Option<PathBuf> {
    for output in outputs {
        let directory = output.parent()?;
        if directory.file_name().is_some_and(|last| last == "deps") {
            let stem = output.file_stem()?.to_str()?;
            let stem = if output.extension().is_some_and(|ext| ext == "rlib") {
                stem.strip_prefix("lib").unwrap_or(stem)
            } else {
                stem
            };
            let beside = directory.join(format!("{stem}.d"));
            if beside.is_file() {
                return Some(beside);
            }
        }
    }
    let deps = outputs.first()?.parent()?.join("deps");
    let written: Vec<PathBuf> = std::fs::read_dir(deps)
        .ok()?
        .flatten()
        .filter(|entry| {
            let file = entry.file_name().to_string_lossy().into_owned();
            file.strip_suffix(".d")
                .and_then(|stem| stem.strip_prefix(name))
                .is_some_and(|rest| {
                    rest.is_empty()
                        || rest.strip_prefix('-').is_some_and(|hash| {
                            hash.len() == 16 && hash.bytes().all(|b| b.is_ascii_hexdigit())
                        })
                })
                && entry
                    .metadata()
                    .and_then(|found| found.modified())
                    .is_ok_and(|written| written >= began)
        })
        .map(|entry| entry.path())
        .collect();
    (written.len() == 1).then(|| written[0].clone())
}

/// Whether one of the compiles in `readers`, which all read one file, could have read it while
/// another wrote it. Tauri's macro writes a file directly and only if it is not there, so a compile
/// that finds it there while another is writing it can read part of it.
///
/// Cargo compiles a unit as soon as the ones it needs are done, and a program or a test program
/// needs the whole of its package's library, so it starts after the library's compile has ended.
/// When the library is one of the readers it is the compile that wrote the file, and the programs
/// find it whole and only read it, however many there are. The library's unit tests do not wait for
/// the library, nor do two variants of the library (a profile with `panic = "abort"` builds one
/// beside the one the tests link), nor, when the library does not read the file, two programs or test
/// programs: any of them may write the file while another reads it.
fn may_have_been_read_while_written(readers: &[Unit]) -> bool {
    let count = |wanted: Unit| readers.iter().filter(|unit| **unit == wanted).count();
    let (libraries, with_tests, others) = (
        count(Unit::Library),
        count(Unit::LibraryTests),
        count(Unit::Other),
    );
    libraries > 1
        || with_tests > 1
        || (with_tests == 1 && libraries + others > 0)
        || (libraries == 0 && others > 1)
}

/// What [`date_before`] did.
#[derive(Debug, Default)]
struct Dating {
    /// How many files were given a time.
    dated: usize,
    /// The files it left as they were, and why, and the files it could not give a time.
    left: Vec<String>,
}

/// Gives each content-addressed file in `outputs`, the output directories of the build scripts of
/// this tree's packages, that the build wrote and that no compile can have read while another wrote
/// it, a time a second before `began`.
///
/// Cargo takes a crate for out of date when a file the compile read is newer than the start of that
/// compile. The macros of some crates write a file into the build script's output directory while
/// the crate compiles and read it back at once (Tauri's context macro does it with an
/// application's icon and front end), and that file is newer than the start of the compile that
/// read it. The build is complete and the file is what the compile read, but the next call of
/// Cargo compiles the crate again and links its test programs again, which on a cold target is a
/// second build of the biggest crate of a step.
///
/// That the file is newer is also what shows that a compile read a file another compile was still
/// writing: Tauri's macro writes a file directly, not through a rename, so a compile that finds it
/// present can read part of it. So a file is dated only when it is named by a digest of 64
/// hexadecimal digits, with an extension or none ([`is_named_by_digest`]: Tauri names what its
/// macros write so, and a complete file holds the bytes its name stands for), and only when the
/// compiles that read it (rustc's dependency files say which, by the directory's name and the
/// file's) cannot have read it while another wrote it ([`may_have_been_read_while_written`]): then
/// the compile that wrote it is the one that read it, or the ones that read it started after the
/// writer was done. Any other file keeps its time, and Cargo
/// compiles the crate again in the next call, as it did before. A time only goes back, to before
/// the build, and only for a file the build wrote. The compile that wrote the file is told by
/// nothing but the dependency files, so a package with a compile whose dependency file cannot be
/// read is left alone whole.
fn date_before(outputs: &[(String, PathBuf)], compiled: &[Compiled], began: SystemTime) -> Dating {
    let before = began.checked_sub(Duration::from_secs(1)).unwrap_or(began);
    let mut dating = Dating::default();
    for (package, directory) in outputs {
        let units: Vec<&Compiled> = compiled
            .iter()
            .filter(|unit| unit.package == *package)
            .collect();
        let unreadable = units.iter().any(|unit| unit.read.is_none());
        // The directory that holds the build scripts' (`build`): under it, `companion-tauri-<hash>`
        // holds the output directory `out`, and its name is in every path of a file written there.
        let builds = directory
            .parent()
            .and_then(Path::parent)
            .unwrap_or(directory)
            .to_path_buf();
        let mut pending = vec![directory.clone()];
        while let Some(directory) = pending.pop() {
            let Ok(entries) = std::fs::read_dir(&directory) else {
                continue;
            };
            for entry in entries.flatten() {
                let Ok(kind) = entry.file_type() else {
                    continue;
                };
                if kind.is_dir() {
                    pending.push(entry.path());
                    continue;
                }
                let name = entry.file_name().to_string_lossy().into_owned();
                let written_after = kind.is_file()
                    && is_named_by_digest(&name)
                    && entry
                        .metadata()
                        .and_then(|found| found.modified())
                        .is_ok_and(|written| written > began);
                if !written_after {
                    continue;
                }
                let path = entry.path();
                // The same bytes are named alike wherever a macro writes them (an icon, a page),
                // and every output directory is called `out`, so a dependency file must say the
                // build directory's name and the path under it, whole, after a separator.
                let tail = path.strip_prefix(&builds).map_or_else(
                    |_| name.clone(),
                    |under| {
                        under
                            .components()
                            .map(|part| part.as_os_str().to_string_lossy())
                            .collect::<Vec<_>>()
                            .join("/")
                    },
                );
                let tail = format!("/{tail}");
                let readers: Vec<Unit> = units
                    .iter()
                    .filter(|unit| {
                        unit.read
                            .as_ref()
                            .is_some_and(|read| read.replace('\\', "/").contains(&tail))
                    })
                    .map(|unit| unit.unit)
                    .collect();
                let why = if unreadable {
                    let without: Vec<Unit> = units
                        .iter()
                        .filter(|unit| unit.read.is_none())
                        .map(|unit| unit.unit)
                        .collect();
                    Some(format!(
                        "a compile of the package ({without:?}) has no dependency file to read"
                    ))
                } else if readers.is_empty() {
                    Some("no compile's dependency file names it".to_owned())
                } else if may_have_been_read_while_written(&readers) {
                    Some(format!(
                        "{readers:?} read it, and one could have read it while another wrote it"
                    ))
                } else {
                    None
                };
                if let Some(why) = why {
                    dating
                        .left
                        .push(format!("{} is left to Cargo: {why}", path.display()));
                    continue;
                }
                match std::fs::OpenOptions::new()
                    .write(true)
                    .open(&path)
                    .and_then(|file| file.set_modified(before))
                {
                    Ok(()) => dating.dated += 1,
                    Err(error) => dating
                        .left
                        .push(format!("{} could not be dated: {error}", path.display())),
                }
            }
        }
    }
    dating
}

/// Whether a file name is 64 hexadecimal digits, with an extension or without one.
fn is_named_by_digest(name: &str) -> bool {
    let stem = name.split_once('.').map_or(name, |(stem, _)| stem);
    stem.len() == 64 && stem.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Runs `command` at `place`, its standard output and error both appended to `log`, and returns
/// its exit status (none when a signal ended it).
fn run_logged(
    command: &[String],
    place: &Place<'_>,
    log_path: &Path,
    environment: &[(String, String)],
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
        .envs(environment.iter().map(|(name, value)| (name, value)))
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
    use std::path::Path;
    use std::time::{Duration, SystemTime};

    use super::{
        Binary, Compiled, ERROR_BYTES, LISTING_BEGIN, LISTING_END, Unit, date_before,
        dependency_file, ends_of, ends_of_root_resolved, file_name, is_count, is_named_by_digest,
        libtest, may_have_been_read_while_written, read_listing, reconcile, unrecorded,
    };
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
    fn a_binary_the_log_runs_twice_is_the_steps_error() {
        let ran = |executable: &str| {
            (
                None,
                Binary {
                    executable: executable.to_owned(),
                    ..Binary::default()
                },
            )
        };
        let records = BTreeMap::from([("t-1".to_owned(), Ok(libtest::Record::new()))]);
        let once = [ran("target/debug/deps/t-1"), ran("doc-tests p")];
        assert_eq!(unrecorded(&records, &once), None);
        let twice = [ran("target/debug/deps/t-1"), ran("target/debug/deps/t-1")];
        assert!(
            unrecorded(&records, &twice).is_some_and(|error| error.contains("more than once")),
            "one record would stand for two runs"
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

    #[test]
    fn the_end_of_a_standard_error_leaves_out_the_checkout_and_cargos_account_of_a_failure() {
        // Each way the output can spell the root: as given, with the other separator, and as a
        // note of rustc's quotes it, with each backslash doubled.
        let root = std::env::temp_dir().join("checkout");
        let given = root.to_string_lossy().into_owned();
        let backslashes = given.replace('/', "\\");
        // What Cargo writes after a failed program, and for the programs after it, is not what
        // the failed program said.
        let text = format!(
            "{given}/a\n{}\\b\n{}\\c\n{}\n\
             error: test failed, to rerun pass `-p t --test x`\n\
             \nCaused by:\n  process didn't exit successfully: `lister list-one x --list` (exit status: 1)\n\
             note: test exited abnormally; to see the full output pass --no-capture to the harness.\n\
             \x20    Running tests/y.rs (target/debug/deps/y-0123)\n   Doc-tests t\n\
             error: 2 targets failed:\n    `-p t --lib`\n    `-p t --test x`\n",
            backslashes,
            backslashes.replace('\\', "\\\\"),
            "the volume is full",
        );
        let ends = ends_of(&text, &root);
        assert!(ends.contains("the volume is full"), "{ends}");
        for cargo in [
            "targets failed",
            "rerun pass",
            "Caused by",
            "didn't exit",
            "Running",
            "Doc-tests",
        ] {
            assert!(!ends.contains(cargo), "{cargo}: {ends}");
        }
        assert!(!ends.contains("checkout"), "{ends}");
        assert!(ends.contains("<root>"), "{ends}");
        // A relative root names the working directory: the paths in the output are the
        // directory's own, and a dot is not a path to leave out.
        let here = std::env::current_dir().expect("a working directory");
        let text = format!("disk. (os error 112) {}", here.join("target").display());
        assert_eq!(
            ends_of(&text, Path::new(".")),
            "its standard error ends: disk. (os error 112) <root>/target"
                .replace('/', std::path::MAIN_SEPARATOR_STR)
        );
        assert_eq!(
            ends_of("\n  \n", &root),
            "it wrote nothing to its standard error"
        );
        // A cut inside a character moves to the next one, and the whole stays within the bound.
        let long = format!("{}\n", "\u{e9}".repeat(900));
        let ends = ends_of(&long, &root);
        assert!(
            ends.len() <= "its standard error ends: ".len() + ERROR_BYTES,
            "{}",
            ends.len()
        );
        assert!(ends.contains("...\u{e9}"), "{ends}");
    }

    #[test]
    fn only_cargos_own_account_of_the_failed_targets_is_left_out_of_the_end() {
        // A line that looks like the account but is not stays, with the reason a target failed.
        let text = "`--list` is not supported by this runner\n\
                    error: 3 failures happened\n\
                    error: test failed, to rerun pass `-p t --lib`\n\
                    error: 1 target failed:\n    `-p t --lib`\n";
        let ends = ends_of(text, Path::new("/nowhere"));
        assert_eq!(
            ends,
            "its standard error ends: `--list` is not supported by this runner | error: 3 failures happened"
        );
        // Nothing else was said: the end says so, and does not call the standard error empty.
        let ends = ends_of(
            "error: test failed, to rerun pass `-p t --lib`\nerror: 1 target failed:\n    `-p t --lib`\n",
            Path::new("/nowhere"),
        );
        assert!(ends.contains("only Cargo's account"), "{ends}");
    }

    #[test]
    fn cargos_account_of_a_program_that_could_not_run_is_in_the_end() {
        // The runner never started, or was killed: the program wrote nothing, and the only cause
        // is in Cargo's account, after its line about the program.
        for (cause, shown) in [
            (
                "could not execute process `/x/lister list-one a-0123 --list` (never executed)\n\
                 \nCaused by:\n  No such file or directory (os error 2)",
                ["never executed", "No such file or directory"],
            ),
            (
                "process didn't exit successfully: `/x/lister list-one a-0123 --list` (signal: 9, SIGKILL: kill)",
                ["signal: 9", "SIGKILL"],
            ),
        ] {
            let text = format!(
                "    Finished `test` profile [unoptimized] target(s) in 0.1s\n\
                 \x20    Running unittests src/lib.rs (target/debug/deps/a-0123)\n\
                 error: test failed, to rerun pass `-p a --lib`\n\
                 \nCaused by:\n  {cause}\n\
                 note: test exited abnormally; to see the full output pass --no-capture to the harness.\n\
                 \x20    Running unittests src/lib.rs (target/debug/deps/b-0123)\n   Doc-tests a\n"
            );
            let ends = ends_of(&text, Path::new("/nowhere"));
            for word in shown {
                assert!(ends.contains(word), "{word}: {ends}");
            }
            assert!(
                !ends.contains("b-0123") && !ends.contains("Doc-tests"),
                "{ends}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_root_with_a_dotdot_or_a_link_in_it_is_left_out_by_its_physical_path() {
        let directory = tempfile::tempdir().expect("a directory");
        let real = directory.path().join("real");
        std::fs::create_dir_all(real.join("checkout")).expect("a checkout");
        let link = directory.path().join("link");
        std::os::unix::fs::symlink(&real, &link).expect("a link");
        let physical = std::fs::canonicalize(real.join("checkout")).expect("a physical path");
        for root in [
            link.join("checkout"),
            real.join("checkout").join("..").join("checkout"),
        ] {
            let text = format!("cannot write in {}: no room", physical.display());
            let ends = ends_of(&text, &root);
            assert_eq!(
                ends,
                "its standard error ends: cannot write in <root>: no room",
                "{}",
                root.display()
            );
        }
    }

    #[test]
    fn a_root_resolved_through_a_junction_or_with_a_verbatim_prefix_is_left_out_on_every_platform()
    {
        // Windows resolves a junction, and writes `\\?\` before the physical path; what Cargo
        // prints has neither the link nor the prefix.
        let root = Path::new("link");
        for (resolved, printed) in [
            (r"\\?\D:\real\checkout", r"D:\real\checkout"),
            (r"\\?\UNC\server\share\checkout", r"\\server\share\checkout"),
        ] {
            for text in [
                format!(r"cannot write in {printed}\src\lib.rs: no room"),
                format!(r"cannot write in {resolved}\src\lib.rs: no room"),
                format!(
                    "cannot write in {}/src/lib.rs: no room",
                    printed.replace('\\', "/")
                ),
            ] {
                let ends = ends_of_root_resolved(&text, root, Some(Path::new(resolved)));
                assert!(ends.contains("<root>"), "{ends}");
                assert!(
                    !ends.contains("checkout") && !ends.contains("share"),
                    "{ends}"
                );
            }
        }
    }

    #[test]
    fn compiles_of_a_package_that_could_have_run_beside_each_other_are_told() {
        // Programs and test programs link the library, so they start after it has ended: a file
        // that the library read is whole when they read it, however many of them there are.
        assert!(!may_have_been_read_while_written(&[Unit::Library]));
        assert!(!may_have_been_read_while_written(&[
            Unit::Library,
            Unit::Other
        ]));
        assert!(!may_have_been_read_while_written(&[
            Unit::Library,
            Unit::Other,
            Unit::Other
        ]));
        assert!(!may_have_been_read_while_written(&[Unit::Other]));
        assert!(!may_have_been_read_while_written(&[Unit::LibraryTests]));
        // The library's unit tests do not wait for it, nor do two programs that it did not read
        // the file for wait for each other.
        assert!(may_have_been_read_while_written(&[
            Unit::Library,
            Unit::LibraryTests
        ]));
        assert!(may_have_been_read_while_written(&[
            Unit::Other,
            Unit::Other
        ]));
        assert!(may_have_been_read_while_written(&[
            Unit::LibraryTests,
            Unit::Other
        ]));
        // Two compiles of the library itself are two variants of it, as `panic = "abort"` makes
        // beside the library the tests link, and nothing makes one wait for the other.
        assert!(may_have_been_read_while_written(&[
            Unit::Library,
            Unit::Library
        ]));
    }

    #[test]
    fn a_file_is_told_from_one_of_the_same_name_in_another_output_directory_of_the_package() {
        // The same bytes are named alike wherever a macro writes them, and every build script's
        // output directory is called `out`: a package can have two (a host and a target build, or
        // two feature sets), and the library's compile reading a file in one says nothing of the
        // file in the other, or in a directory under it.
        let directory = tempfile::tempdir().expect("a directory");
        let digest = "5d4140c1a3b2c9d6e7f80a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5";
        let began = SystemTime::now() - Duration::from_secs(10);
        let first = directory.path().join("build").join("p-1111").join("out");
        let second = directory.path().join("build").join("p-2222").join("out");
        for place in [first.clone(), first.join("sub"), second.clone()] {
            std::fs::create_dir_all(&place).expect("a directory");
            std::fs::write(place.join(digest), "x").expect("a file");
        }
        let compiled = |unit, place: &Path| Compiled {
            package: "p".to_owned(),
            unit,
            read: Some(format!("target: {}\n", place.join(digest).display())),
        };
        let dating = date_before(
            &[
                ("p".to_owned(), first.clone()),
                ("p".to_owned(), second.clone()),
            ],
            &[
                compiled(Unit::Library, &first),
                compiled(Unit::Other, &first.join("sub")),
                compiled(Unit::Other, &first.join("sub")),
                compiled(Unit::Other, &second),
                compiled(Unit::Other, &second),
            ],
            began,
        );
        // The library alone read the file in the first output directory, and two programs that it
        // did not wait for read each of the others.
        assert_eq!(dating.dated, 1, "{dating:?}");
        assert_eq!(dating.left.len(), 2, "{dating:?}");
        assert!(
            dating.left.iter().any(|line| line.contains("sub")),
            "{dating:?}"
        );
        assert!(
            dating.left.iter().any(|line| line.contains("p-2222")),
            "{dating:?}"
        );
    }

    #[test]
    fn cargos_status_lines_and_paths_outside_the_checkout_are_not_in_the_end() {
        // A program that says one line leaves room for the lines Cargo wrote before it, and the
        // paths of a target directory outside the checkout are the machine's.
        let text = "    Finished `test` profile [unoptimized] target(s) in 0.1s\n\
                    \x20    Running unittests src/lib.rs (/ext/target/debug/deps/a-0123)\n\
                    kr-conformance list-one: /ext/target/debug/deps/a-0123 ended with exit status: 7\n\
                    cannot write in /ext/cache/a b: the volume is full\n\
                    cannot write in C:\\ext\\cache\\a.exe: the volume is full\n\
                    Running the tests now\n\
                    error: test failed, to rerun pass `-p a --lib`\n\
                    \nCaused by:\n  could not execute process `/ext/bin/lister list-one /ext/target/debug/deps/a-0123 --list` (never executed)\n";
        let ends = ends_of(text, Path::new("/nowhere"));
        for word in ["Finished", "Running unittests", "/ext", "C:", "\\ext"] {
            assert!(!ends.contains(word), "{word}: {ends}");
        }
        for word in [
            "a-0123 ended with exit status: 7",
            "the volume is full",
            "Running the tests now",
            "(never executed)",
            "lister list-one a-0123 --list",
        ] {
            assert!(ends.contains(word), "{word}: {ends}");
        }
    }

    #[test]
    fn a_cause_cargo_gives_over_several_lines_is_kept_whole() {
        // A line break in the runner's path makes Cargo's message run over two lines, and the
        // cause under it has a block of its own.
        let text = "     Running unittests src/lib.rs (target/debug/deps/a-0123)\n\
                    error: test failed, to rerun pass `-p a --lib`\n\
                    \nCaused by:\n  could not execute process `/x/line\n  break/lister list-one a-0123 --list` (never executed)\n\
                    \nCaused by:\n  No such file or directory (os error 2)\n\
                    note: test exited abnormally; to see the full output pass --no-capture to the harness.\n\
                    \x20  Doc-tests a\n";
        let ends = ends_of(text, Path::new("/nowhere"));
        for word in [
            "break/lister",
            "(never executed)",
            "No such file or directory",
        ] {
            assert!(ends.contains(word), "{word}: {ends}");
        }
        assert!(!ends.contains("Doc-tests"), "{ends}");
    }

    #[test]
    fn a_library_that_is_only_dynamic_or_static_is_none_a_program_waits_for() {
        // Cargo makes a program wait for the library of its package when the library can be linked
        // into it as Rust (`lib`, `rlib`, `dylib` or `proc-macro`); a `cdylib` or a `staticlib` is
        // an output of its own, and nothing waits for it.
        let unit = |kinds: &[&str]| {
            let message = serde_json::json!({
                "target": { "kind": kinds, "name": "app" },
                "profile": { "test": false },
                "filenames": ["/nowhere/target/debug/libapp.a"],
            });
            Compiled::from_artifact("p", &message, SystemTime::now())
                .expect("a unit")
                .unit
        };
        assert_eq!(unit(&["lib", "cdylib", "staticlib"]), Unit::Library);
        assert_eq!(unit(&["rlib"]), Unit::Library);
        assert_eq!(unit(&["dylib"]), Unit::Library);
        assert_eq!(unit(&["proc-macro"]), Unit::Library);
        assert_eq!(unit(&["cdylib"]), Unit::Other);
        assert_eq!(unit(&["staticlib"]), Unit::Other);
        assert_eq!(unit(&["cdylib", "staticlib"]), Unit::Other);
    }

    #[test]
    fn only_a_name_that_is_a_digest_marks_a_file_a_macro_writes() {
        let digest = "aa2e526f1f88fa0a23217584974aaaabd32d47342c168c8cf921633943ea0b60";
        assert!(is_named_by_digest(digest));
        assert!(is_named_by_digest(&format!("{digest}.html")));
        assert!(!is_named_by_digest(&digest[1..]));
        assert!(!is_named_by_digest(&format!("g{}", &digest[1..])));
        assert!(!is_named_by_digest("acl-manifests.json"));
        assert!(!is_named_by_digest("push_gateway_origin"));
    }

    #[test]
    fn a_programs_dependency_file_is_found_by_the_names_cargo_gives_it_on_each_platform() {
        let directory = tempfile::tempdir().expect("a directory");
        let deps = directory.path().join("debug").join("deps");
        std::fs::create_dir_all(&deps).expect("a deps directory");
        let began = std::time::SystemTime::now() - std::time::Duration::from_secs(5);
        // A program Cargo copied out of `deps`; Windows has no hash in its names there, Unix has.
        let copied = [directory.path().join("debug").join("kalareach-companion")];
        assert_eq!(dependency_file("kalareach_companion", &copied, began), None);
        std::fs::write(deps.join("kalareach_companion.d"), "x").expect("a file");
        assert_eq!(
            dependency_file("kalareach_companion", &copied, began),
            Some(deps.join("kalareach_companion.d"))
        );
        // Two files of the crate that this build wrote are not told apart.
        std::fs::write(deps.join("kalareach_companion-0123456789abcdef.d"), "x").expect("a file");
        assert_eq!(dependency_file("kalareach_companion", &copied, began), None);
        // The one named for the output in `deps` is it.
        let in_deps = [deps.join("kalareach_companion-0123456789abcdef")];
        assert_eq!(
            dependency_file("kalareach_companion", &in_deps, began),
            Some(deps.join("kalareach_companion-0123456789abcdef.d"))
        );
        // A file from before the build is not this build's.
        let later = std::time::SystemTime::now() + std::time::Duration::from_secs(60);
        assert_eq!(dependency_file("kalareach_companion", &copied, later), None);
    }
}
