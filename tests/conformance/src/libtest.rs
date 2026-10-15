//! Reads `cargo test` output: which binaries ran, and what each of their tests came to.
//!
//! What a test came to is read from the record the harness writes, and not from the output. The
//! output has many writers: the harness writes its result lines to the standard output, and the
//! tests, and the programs they start, write to the standard output and the standard error, often in
//! pieces. A result line that lands between two pieces of a message begins in the middle of another
//! line, and a reader of the output sees no result. The record has one writer. The runner
//! (`run::run_one`) gives each test binary that runs under the standard harness the harness's
//! `--logfile` option, which a stable toolchain accepts where it refuses the harness's structured
//! output, and the harness adds an entry to that file as each test ends:
//!
//! * `ok <name>`;
//! * `failed <name>`, or `failed: <message> <name>`;
//! * `ignored <name>`, or `ignored: <reason> <name>`.
//!
//! A message or a reason can run over several lines, and a line of it can begin as an entry does.
//! The harness ends every entry with the name of its test, and no other line of the record ends
//! with the name of a test the binary lists, unless a line of a message or a reason does. The
//! reading takes that as the rule: an entry ends at the first line that ends with a listed test's
//! name, and a second line that ends with the same name is an error. A line of a message that ends
//! with the name of a test therefore ends its entry too early in one of two ways, and neither
//! passes: the test it names ran, so its own entry ends with that name a second time; or it did
//! not run, so the record has more entries than the summary counts.
//!
//! The harness calls the option deprecated and says so on its standard error before each run, so
//! the log of a binary opens with ``warning: `--logfile` is deprecated``. A toolchain that has
//! dropped the option fails every binary at its arguments, and each of them is the step's error.
//!
//! The output gives what the record does not: Cargo's `Running <source> (<executable>)`, which
//! starts one binary's output, what a test wrote when it returned early, and the harness's summary
//! line, `test result: ok. P passed; F failed; I ignored; ...`. The summary shows that the run ended
//! where the harness meant it to, so a binary whose record does not add up to the summary it
//! printed, or that printed none, is reported as unreadable rather than guessed at. These are still
//! read from lines other writers share. The summary and the `Running` line fail safe when another
//! writer breaks them: the binary is unreadable or the step is in error. A line a test wrote when it
//! returned early is lost when another writer breaks it in a step that shows the output as it is
//! written (`--nocapture`); in a step that captures it, the harness prints it with the test's name
//! in one write after the last test has ended.
//!
//! The programs rustdoc runs for a crate's documentation tests have no record of their own. They
//! are read from the lines the harness prints for each test (`test <name> ... ok`, `... FAILED`,
//! `... ignored` or `... ignored, <reason>`) and the `failures:` list at the end of a run.
//!
//! A test that runs one at a time prints its name before it runs, so whatever it or a process it
//! started writes can land between the name and the verdict. The reading of the output allows for
//! that: a result that is not on its own line is taken from the failure list and the summary.
//!
//! A test that returns early because what it needs is absent passes, and says so on a line of its
//! own that starts with one of [`EARLY_RETURN`], or names itself first and then says
//! [`EARLY_RETURN_NAMED`]: `container: skipped, because podman is not installed`. The reading
//! finds that line in what the test
//! wrote: in its `---- <name> stdout ----` block, which `--show-output` prints for every test
//! that passed; between its name and its verdict, when the tests run one at a time with their
//! output shown as it is written; or anywhere in the run of a binary that ran that one test alone.
//! Such a test is [`Outcome::Skipped`], never a pass. A line of that kind the reading cannot give
//! to one test makes its binary unreadable.

use std::collections::{BTreeMap, BTreeSet};

/// How the suites begin the line a test prints when it returns early, for want of something it
/// needs: `skipped: <why>`, `skipping: <why>`, `not exercised: <why>`.
pub const EARLY_RETURN: &[&str] = &["skipped:", "skipping:", "not exercised"];

/// How a suite that names itself first says a test of it returned early: `<suite>: skipped, because
/// <why>`.
pub const EARLY_RETURN_NAMED: &str = ": skipped, because ";

/// What one test came to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// It ran and passed.
    Passed,
    /// It ran and failed.
    Failed,
    /// The harness did not run it, with the reason its attribute gives, where it gives one.
    Ignored(Option<String>),
    /// It passed without doing what it is for: it returned early and said why, on the line given.
    Skipped(String),
}

/// What the harness wrote of one binary's run, by test name: [`Outcome::Passed`],
/// [`Outcome::Failed`] or [`Outcome::Ignored`].
pub type Record = BTreeMap<String, Outcome>;

/// What a binary's record is when its output is read.
#[derive(Clone, Copy, Debug)]
pub enum Recording<'r> {
    /// None is expected: the programs rustdoc runs for documentation tests, and the targets with a
    /// harness of their own, are read from their lines.
    None,
    /// One is expected and cannot be used, for the reason given.
    Lost(&'r str),
    /// The record.
    Record(&'r Record),
}

/// How an entry of the harness's record begins, and what it came to.
fn entry_start(line: &str) -> Option<&'static str> {
    ["ok", "failed", "ignored"].into_iter().find(|status| {
        line.strip_prefix(status)
            .is_some_and(|rest| rest.starts_with([' ', ':']))
    })
}

/// Reads the record the harness wrote to the file it was given with `--logfile`, for a binary that
/// lists the tests `known`.
///
/// An entry begins with its status at the start of a line. It ends at the first line whose last
/// word is a test of `known`, so a message or a reason of several lines is one entry, even when a
/// line of it looks like the start of another. A test has one entry: a second line that ends with
/// its name means that a line of a message ended an entry too early.
///
/// # Errors
///
/// Returns what cannot be an entry: text before the first one, an entry that ends with no test of
/// `known`, and a second line that ends with a name.
pub fn read_record(text: &str, known: &BTreeSet<String>) -> Result<Record, String> {
    let mut record = Record::new();
    // The entry being read: how it began, and its lines so far.
    let mut open: Option<(&'static str, String)> = None;
    for line in text.lines() {
        let (status, entry) = match open.take() {
            Some((status, mut entry)) => {
                entry.push('\n');
                entry.push_str(line);
                (status, entry)
            }
            None => match entry_start(line) {
                Some(status) => (status, line.to_owned()),
                None if line.is_empty() => continue,
                None => return Err(format!("`{line}` is not an entry of the harness's record")),
            },
        };
        let name = entry
            .rsplit([' ', '\n'])
            .next()
            .filter(|name| known.contains(*name));
        let Some(name) = name else {
            open = Some((status, entry));
            continue;
        };
        if record.contains_key(name) {
            return Err(format!("two lines of the record end with {name}"));
        }
        let outcome = match status {
            "ok" => Outcome::Passed,
            "failed" => Outcome::Failed,
            _ => Outcome::Ignored(
                entry[..entry.len() - name.len()]
                    .trim_end_matches([' ', '\n'])
                    .strip_prefix("ignored: ")
                    .map(str::to_owned)
                    .filter(|reason| !reason.is_empty()),
            ),
        };
        record.insert(name.to_owned(), outcome);
    }
    match open {
        Some((_, entry)) => Err(format!("`{entry}` ends with no test of the binary's")),
        None => Ok(record),
    }
}

/// One binary's run.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Binary {
    /// The executable Cargo said it was running.
    pub executable: String,
    /// The source Cargo named for it, relative to its package.
    pub source: String,
    /// Each test's outcome, by name.
    pub tests: BTreeMap<String, Outcome>,
    /// The summary's counts: passed, failed, ignored, filtered out.
    pub summary: Option<[u64; 4]>,
    /// Why the outcomes cannot be taken for what the binary came to, when they cannot: no record,
    /// no summary, or outcomes that do not add up to it.
    pub problem: Option<String>,
}

impl Binary {
    /// Whether the outcomes read are what the binary came to.
    #[must_use]
    pub fn readable(&self) -> bool {
        self.problem.is_none()
    }
}

/// What has been read of the binary whose output is being read.
#[derive(Default)]
struct Reading {
    /// Each test named so far, with the rest of its line: its verdict, or what it wrote first.
    pending: Vec<(String, String)>,
    /// The names the `failures:` list gives.
    failures: Vec<String>,
    /// Inside the `failures:` part of the output.
    in_failures: bool,
    /// Inside the `successes:` part, which `--show-output` prints.
    in_successes: bool,
    /// The test whose `---- <name> stdout ----` block is being read, in the `successes:` part.
    output_of: Option<String>,
    /// The test named last, which a verdict on a line of its own belongs to.
    last_name: Option<String>,
    /// The first line each test wrote that says it returned early.
    early: BTreeMap<String, String>,
    /// The first such line that no one test's output could be told apart for.
    loose: Option<String>,
}

/// Whether `line` is a test saying it returned early.
fn says_early_return(line: &str) -> bool {
    let line = line.trim_start();
    EARLY_RETURN.iter().any(|marker| line.starts_with(marker)) || line.contains(EARLY_RETURN_NAMED)
}

/// Whether a line's text after a test's name is its verdict rather than something it wrote.
fn is_verdict(rest: &str) -> bool {
    matches!(rest, "ok" | "FAILED") || rest.starts_with("ignored")
}

/// Reads one `cargo test` step's combined output. `recording_of` says what the record is of the
/// binary at an executable path: the outcomes of a binary with a record are the record's, and the
/// output gives the rest.
#[must_use]
pub fn read<'r>(output: &str, recording_of: impl Fn(&str) -> Recording<'r>) -> Vec<Binary> {
    let mut binaries: Vec<Binary> = Vec::new();
    let mut reading = Reading::default();
    // Whether the binary being read has been settled: settling reads what was gathered for it. A
    // binary read from its lines is settled at each summary. A binary with a record is settled once,
    // where its output ends, so that the last summary is its summary and what was gathered for it
    // is all of its output: a failure message that quotes another summary comes before the last.
    let mut settled = false;
    for raw in output.lines() {
        let line = raw.trim_end_matches('\r');
        // Documentation tests are a section of their own, which no target of the report's is.
        let doctests = line
            .trim_start()
            .strip_prefix("Doc-tests ")
            .map(|name| (String::new(), format!("doc-tests {name}")));
        if let Some((source, executable)) = running(line).or(doctests) {
            if let Some(binary) = binaries.last_mut()
                && !settled
            {
                let recording = recording_of(&binary.executable);
                settle(binary, &mut reading, recording);
            }
            binaries.push(Binary {
                executable,
                source,
                ..Binary::default()
            });
            reading = Reading::default();
            settled = false;
            continue;
        }
        let Some(binary) = binaries.last_mut() else {
            continue;
        };
        if let Some(summary) = summary(line) {
            binary.summary = Some(summary);
            let recording = recording_of(&binary.executable);
            if matches!(recording, Recording::None) {
                settle(binary, &mut reading, recording);
                settled = true;
            } else if reading.output_of.is_none() {
                // A summary quoted in a test's output is not where the harness's own sections
                // end. Inside the captured output of a test it is that output; anywhere else, the
                // section a quoted `failures:` or `successes:` line opened ends with it.
                reading.in_successes = false;
                reading.in_failures = false;
            }
            continue;
        }
        if line == "successes:" {
            reading.in_successes = true;
            reading.output_of = None;
            continue;
        }
        if line == "failures:" {
            reading.in_failures = true;
            reading.in_successes = false;
            reading.output_of = None;
            reading.failures.clear();
            continue;
        }
        if reading.in_successes {
            if let Some(name) = line
                .strip_prefix("---- ")
                .and_then(|rest| rest.strip_suffix(" stdout ----"))
            {
                reading.output_of = Some(name.to_owned());
            } else if let Some(name) = &reading.output_of
                && says_early_return(line)
            {
                reading
                    .early
                    .entry(name.clone())
                    .or_insert_with(|| line.trim().to_owned());
            }
            continue;
        }
        if reading.in_failures {
            if let Some(name) = line.strip_prefix("    ").filter(|name| !name.contains(' ')) {
                reading.failures.push(name.to_owned());
            }
            continue;
        }
        if let Some(rest) = line.strip_prefix("test ") {
            let named = rest
                .split_once(" ... ")
                .or_else(|| rest.strip_suffix(" ...").map(|name| (name, "")));
            if let Some((name, verdict)) = named {
                if says_early_return(verdict) {
                    reading
                        .early
                        .entry(name.to_owned())
                        .or_insert_with(|| verdict.trim().to_owned());
                }
                reading.pending.push((name.to_owned(), verdict.to_owned()));
                reading.last_name = Some(name.to_owned());
            }
            continue;
        }
        let running_test = reading.last_name.as_ref().filter(|name| {
            reading
                .pending
                .iter()
                .rev()
                .find(|(pending_name, _)| pending_name == *name)
                .is_some_and(|(_, verdict)| !is_verdict(verdict))
        });
        // A verdict on a line of its own, after whatever a test that runs alone printed.
        if matches!(line, "ok" | "FAILED") {
            if let Some(name) = running_test.cloned()
                && let Some(entry) = reading
                    .pending
                    .iter_mut()
                    .rev()
                    .find(|(pending_name, _)| *pending_name == name)
            {
                entry.1 = line.to_owned();
            }
            continue;
        }
        if says_early_return(line) {
            match running_test.cloned() {
                // Written between a test's name and its verdict: that test's, when tests run one
                // at a time.
                Some(name) => {
                    reading
                        .early
                        .entry(name)
                        .or_insert_with(|| line.trim().to_owned());
                }
                None => {
                    reading.loose.get_or_insert_with(|| line.trim().to_owned());
                }
            }
        }
    }
    if let Some(binary) = binaries.last_mut()
        && !settled
    {
        let recording = recording_of(&binary.executable);
        settle(binary, &mut reading, recording);
    }
    binaries
}

/// Turns what was read for one binary into outcomes, and checks them against its summary. A binary
/// with a record has the record's outcomes; one without, the verdicts of the lines the harness
/// printed.
fn settle(binary: &mut Binary, reading: &mut Reading, recording: Recording<'_>) {
    let Reading {
        pending,
        failures,
        early,
        loose,
        ..
    } = std::mem::take(reading);
    let alone = match recording {
        Recording::Record(record) => record.len(),
        _ => pending.len(),
    } == 1;
    // A test that said it returned early passed without doing what it is for.
    let pass = |name: &str| match early.get(name).or(loose.as_ref().filter(|_| alone)) {
        Some(line) => Outcome::Skipped(line.clone()),
        None => Outcome::Passed,
    };
    match recording {
        Recording::Record(record) => {
            for (name, outcome) in record {
                let outcome = match outcome {
                    Outcome::Passed => pass(name),
                    other => other.clone(),
                };
                binary.tests.insert(name.clone(), outcome);
            }
        }
        // Nothing of what the output says is what the binary came to.
        Recording::Lost(_) => {}
        Recording::None => {
            for (name, verdict) in pending {
                let outcome = if let Some(reason) = verdict.strip_prefix("ignored") {
                    Outcome::Ignored(
                        reason
                            .strip_prefix(", ")
                            .map(str::to_owned)
                            .filter(|r| !r.is_empty()),
                    )
                } else if failures.contains(&name) || verdict == "FAILED" {
                    Outcome::Failed
                } else if verdict == "ok"
                    || binary.summary.is_some_and(|[_, failed, _, _]| failed == 0)
                {
                    // A verdict lost among a test's own output is a pass when nothing in this
                    // binary failed.
                    pass(&name)
                } else {
                    // Something failed, and this test's verdict is not on record: it cannot be
                    // called passed, so it is counted as the thing that is not known to have
                    // passed.
                    Outcome::Failed
                };
                binary.tests.insert(name, outcome);
            }
            for name in failures {
                binary.tests.insert(name, Outcome::Failed);
            }
        }
    }
    let count = |wanted: fn(&Outcome) -> bool| -> u64 {
        binary.tests.values().filter(|o| wanted(o)).count() as u64
    };
    let agrees = binary.summary.map(|[passed, failed, ignored, _]| {
        count(|o| matches!(o, Outcome::Passed | Outcome::Skipped(_))) == passed
            && count(|o| *o == Outcome::Failed) == failed
            && count(|o| matches!(o, Outcome::Ignored(_))) == ignored
    });
    binary.problem = if let Recording::Lost(why) = recording {
        Some(why.to_owned())
    } else if loose.is_some() && !alone {
        // A test said it returned early and the output cannot say which: every pass of this binary
        // is in doubt, so none of it is read.
        Some("a test said it returned early, and the output does not say which".to_owned())
    } else {
        match agrees {
            None => Some("it printed no summary".to_owned()),
            Some(false) => Some("what its tests came to does not add up to its summary".to_owned()),
            Some(true) => None,
        }
    };
}

/// `text` without the colour and style sequences a program writes when it takes its output for a
/// terminal: Cargo's announcements are read by their words, and a sequence inside one would hide it.
#[must_use]
pub fn plain(text: &str) -> String {
    let mut kept = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' && chars.peek() == Some(&'[') {
            chars.next();
            // Parameters and intermediates, up to and including the final byte.
            for next in chars.by_ref() {
                if ('@'..='~').contains(&next) {
                    break;
                }
            }
            continue;
        }
        kept.push(c);
    }
    kept
}

/// `Running unittests src/lib.rs (target/debug/deps/x-hash)` or `Running tests/y.rs (...)`.
fn running(line: &str) -> Option<(String, String)> {
    let rest = line.trim_start().strip_prefix("Running ")?;
    let rest = rest.strip_prefix("unittests ").unwrap_or(rest);
    let (source, executable) = rest.rsplit_once(" (")?;
    let executable = executable.strip_suffix(')')?;
    Some((source.to_owned(), executable.to_owned()))
}

/// `test result: ok. 3 passed; 0 failed; 1 ignored; 0 measured; 2 filtered out; finished in 0.1s`.
fn summary(line: &str) -> Option<[u64; 4]> {
    let rest = line.strip_prefix("test result: ")?;
    let (_, counts) = rest.split_once(". ")?;
    let mut found = [0_u64; 4];
    for part in counts.split("; ") {
        let (number, what) = part.split_once(' ')?;
        let Ok(number) = number.parse::<u64>() else {
            continue;
        };
        match what {
            "passed" => found[0] = number,
            "failed" => found[1] = number,
            "ignored" => found[2] = number,
            _ if what.starts_with("filtered out") => found[3] = number,
            _ => {}
        }
    }
    Some(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    const RUN: &str = "\
   Compiling x v0.1.0
     Running unittests src/lib.rs (target/debug/deps/x-0a1b)

running 3 tests
test tests::passes ... ok
test tests::ignored_plainly ... ignored
test tests::ignored_with_a_reason ... ignored, needs a device; the device lane runs it

test result: ok. 1 passed; 0 failed; 2 ignored; 0 measured; 0 filtered out; finished in 0.00s

     Running tests/flow.rs (target/debug/deps/flow-2c3d)

running 2 tests
test a_good_one ... ok
test a_bad_one ... FAILED

failures:

---- a_bad_one stdout ----
thread 'a_bad_one' panicked at tests/flow.rs:3:5:
the assertion
test a_decoy_line ... ok

failures:
    a_bad_one

test result: FAILED. 1 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
";

    #[test]
    fn each_binary_is_read_with_its_outcomes_and_its_reasons() {
        let binaries = read(RUN, |_| Recording::None);
        assert_eq!(binaries.len(), 2);
        assert_eq!(binaries[0].executable, "target/debug/deps/x-0a1b");
        assert_eq!(binaries[0].source, "src/lib.rs");
        assert_eq!(binaries[0].tests["tests::passes"], Outcome::Passed);
        assert_eq!(
            binaries[0].tests["tests::ignored_plainly"],
            Outcome::Ignored(None)
        );
        assert_eq!(
            binaries[0].tests["tests::ignored_with_a_reason"],
            Outcome::Ignored(Some("needs a device; the device lane runs it".to_owned()))
        );
        assert!(binaries[0].readable());
        assert_eq!(binaries[1].tests["a_bad_one"], Outcome::Failed);
        assert_eq!(binaries[1].tests["a_good_one"], Outcome::Passed);
        assert!(binaries[1].readable(), "{:?}", binaries[1]);
    }

    #[test]
    fn a_verdict_after_a_tests_own_output_is_still_its_verdict() {
        let output = "\
     Running tests/perf.rs (target/release/deps/perf-99)

running 2 tests
test measures ... KR-PERF-007 measurement
  sustained 11.2 MiB/s
ok
test also ... printed without a newline ok
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 9.00s
";
        let binaries = read(output, |_| Recording::None);
        assert_eq!(binaries[0].tests["measures"], Outcome::Passed);
        assert_eq!(binaries[0].tests["also"], Outcome::Passed);
        assert!(binaries[0].readable());
    }

    #[test]
    fn documentation_tests_are_a_section_of_their_own() {
        let output = "\
     Running tests/t.rs (target/debug/deps/t-1)
test one ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
   Doc-tests x
test src/lib.rs - f (line 3) ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
";
        let binaries = read(output, |_| Recording::None);
        assert_eq!(binaries.len(), 2);
        assert_eq!(binaries[0].tests.len(), 1);
        assert_eq!(binaries[1].executable, "doc-tests x");
    }

    #[test]
    fn a_summary_the_outcomes_do_not_add_up_to_is_unreadable() {
        let output = "\
     Running tests/t.rs (target/debug/deps/t-1)
test one ... ok
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
";
        assert!(!read(output, |_| Recording::None)[0].readable());
    }

    #[test]
    fn a_test_that_said_it_returned_early_is_skipped_and_not_passed() {
        // `--show-output` prints what each test that passed wrote, in a block of its own.
        let shown = "\
     Running tests/shells.rs (target/debug/deps/shells-5)

running 4 tests
test drives_fish ... ok
test drives_zsh ... ok
test in_a_container ... ok
test fails ... FAILED

successes:

---- drives_fish stdout ----
fish: /usr/bin/fish
skipped: fish is on neither this test's PATH nor any of its locations

---- drives_zsh stdout ----
zsh: /bin/zsh
a line that says nothing about returning

---- in_a_container stdout ----
container: skipped, because podman is not installed on this machine


successes:
    drives_fish
    drives_zsh
    in_a_container

failures:

---- fails stdout ----
skipped: this is a failure's output, and it failed

failures:
    fails

test result: FAILED. 3 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.10s
";
        let binaries = read(shown, |_| Recording::None);
        assert_eq!(
            binaries[0].tests["drives_fish"],
            Outcome::Skipped(
                "skipped: fish is on neither this test's PATH nor any of its locations".to_owned()
            )
        );
        assert_eq!(binaries[0].tests["drives_zsh"], Outcome::Passed);
        assert_eq!(
            binaries[0].tests["in_a_container"],
            Outcome::Skipped(
                "container: skipped, because podman is not installed on this machine".to_owned()
            )
        );
        assert_eq!(binaries[0].tests["fails"], Outcome::Failed);
        assert!(binaries[0].readable(), "{:?}", binaries[0]);

        // One at a time, with the output written as it comes: the line is the running test's.
        let one_at_a_time = "\
     Running tests/perf.rs (target/release/deps/perf-7)

running 2 tests
test measures ... not exercised: this host has no second filesystem
ok
test also_measures ... KR-PERF-007 measurement
  sustained 11.2 MiB/s
ok

test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 9.00s
";
        let binaries = read(one_at_a_time, |_| Recording::None);
        assert_eq!(
            binaries[0].tests["measures"],
            Outcome::Skipped("not exercised: this host has no second filesystem".to_owned())
        );
        assert_eq!(binaries[0].tests["also_measures"], Outcome::Passed);
        assert!(binaries[0].readable());

        // A binary that ran one test: everything in its run is that test's.
        let alone = "\
     Running benches/input_latency.rs (target/release/deps/input_latency-9)

running 1 test
skipping: the measurement needs a release build
test added_input_forwarding_latency ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 3 filtered out; finished in 0.10s
";
        let binaries = read(alone, |_| Recording::None);
        assert_eq!(
            binaries[0].tests["added_input_forwarding_latency"],
            Outcome::Skipped("skipping: the measurement needs a release build".to_owned())
        );
        assert!(binaries[0].readable());
    }

    #[test]
    fn a_line_saying_a_test_returned_early_that_no_one_test_owns_leaves_the_binary_unreadable() {
        let output = "\
     Running tests/t.rs (target/debug/deps/t-3)

running 2 tests
skipped: one of these returned early
test one ... ok
test two ... ok

test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
";
        assert!(!read(output, |_| Recording::None)[0].readable());
    }

    #[test]
    fn colour_sequences_are_taken_out_of_what_is_read() {
        assert_eq!(
            plain("\u{1b}[1m\u{1b}[92m     Running\u{1b}[0m tests/t.rs (target/debug/deps/t-3)"),
            "     Running tests/t.rs (target/debug/deps/t-3)"
        );
        assert_eq!(plain("no sequences"), "no sequences");
    }

    #[test]
    fn a_binary_that_printed_no_summary_is_unreadable() {
        let output = "     Running tests/t.rs (target/debug/deps/t-1)\ntest one ... ok\n";
        let binaries = read(output, |_| Recording::None);
        assert_eq!(binaries[0].summary, None);
        assert!(!binaries[0].readable());
    }

    fn names(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|name| (*name).to_owned()).collect()
    }

    #[test]
    fn a_result_line_that_begins_inside_another_line_is_still_the_tests_result() {
        // A hosted macOS runner's output (the weights are not on that host). A case wrote its
        // message to the standard error in two pieces, and the harness wrote the line of another
        // case between them, so that line begins in the middle of the case's message. That run had
        // no record: the one below is what the harness would have written, four entries in the
        // order the output shows the tests ending.
        let output = "\
     Running tests/inference.rs (target/debug/deps/inference-8277a519936f4f80)

running 4 tests
the_largest_contexts_are_sent_to_the_real_process_and_none_is_refused_for_its_size: DID NOT RUN: /Users/runner/Library/Caches/kalareach-describe/MiniCPM5-2B-Q4_K_M.gguf is not on this host
test the_largest_contexts_are_sent_to_the_real_process_and_none_is_refused_for_its_size ... ok
the_real_model_stops_a_job_it_is_told_to_cancel: DID NOT RUN: /Users/runner/Library/Caches/kalareach-describe/MiniCPM5-2B-Q4_K_M.gguf is not on this host
the_description_process_runs_the_real_model: DID NOT RUN: /Users/runner/Library/Caches/kalareach-describe/MiniCPM5-2B-Q4_K_M.gguf is not on this hosttest the_real_model_stops_a_job_it_is_told_to_cancel ... ok

test the_description_process_runs_the_real_model ... ok
test the_real_process_names_its_class_and_refuses_a_file_that_is_not_the_profiles ... ok

successes:

successes:
    the_description_process_runs_the_real_model
    the_largest_contexts_are_sent_to_the_real_process_and_none_is_refused_for_its_size
    the_real_model_stops_a_job_it_is_told_to_cancel
    the_real_process_names_its_class_and_refuses_a_file_that_is_not_the_profiles

test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.23s
";
        let known = names(&[
            "the_description_process_runs_the_real_model",
            "the_largest_contexts_are_sent_to_the_real_process_and_none_is_refused_for_its_size",
            "the_real_model_stops_a_job_it_is_told_to_cancel",
            "the_real_process_names_its_class_and_refuses_a_file_that_is_not_the_profiles",
        ]);
        let record = read_record(
            "\
ok the_largest_contexts_are_sent_to_the_real_process_and_none_is_refused_for_its_size
ok the_real_model_stops_a_job_it_is_told_to_cancel
ok the_description_process_runs_the_real_model
ok the_real_process_names_its_class_and_refuses_a_file_that_is_not_the_profiles
",
            &known,
        )
        .expect("a record");
        let binaries = read(output, |_| Recording::Record(&record));
        assert_eq!(binaries[0].tests.len(), 4, "{:?}", binaries[0].tests);
        assert!(
            binaries[0]
                .tests
                .values()
                .all(|outcome| *outcome == Outcome::Passed)
        );
        assert!(binaries[0].readable(), "{:?}", binaries[0].problem);
    }

    #[test]
    fn the_record_gives_each_entry_its_status_its_reason_and_its_name() {
        let record = read_record(
            "\
ok tests::passes
failed tests::fails
failed: test did not panic as expected at tests/t.rs:8:28 tests::no_panic
failed: panic did not contain expected string
      panic message: \"a\"
 expected substring: \"b\" tests::wrong_panic
failed (time limit exceeded) tests::slow
ignored tests::ignored_plainly
ignored: needs a device; the device lane runs it tests::ignored_with_a_reason
ignored: needs a device
and a second line tests::ignored_over_two_lines
",
            &names(&[
                "tests::passes",
                "tests::fails",
                "tests::no_panic",
                "tests::wrong_panic",
                "tests::slow",
                "tests::ignored_plainly",
                "tests::ignored_with_a_reason",
                "tests::ignored_over_two_lines",
            ]),
        )
        .expect("a record");
        let failed = Outcome::Failed;
        assert_eq!(record["tests::passes"], Outcome::Passed);
        assert_eq!(record["tests::fails"], failed);
        assert_eq!(record["tests::no_panic"], failed);
        assert_eq!(record["tests::wrong_panic"], failed);
        assert_eq!(record["tests::slow"], failed);
        assert_eq!(record["tests::ignored_plainly"], Outcome::Ignored(None));
        assert_eq!(
            record["tests::ignored_with_a_reason"],
            Outcome::Ignored(Some("needs a device; the device lane runs it".to_owned()))
        );
        assert_eq!(
            record["tests::ignored_over_two_lines"],
            Outcome::Ignored(Some("needs a device\nand a second line".to_owned()))
        );
        assert_eq!(record.len(), 8);
        assert_eq!(
            read_record("", &BTreeSet::new()).expect("an empty record"),
            Record::new()
        );
    }

    #[test]
    fn a_line_of_a_reason_that_ends_with_a_tests_name_is_refused_or_leaves_the_counts_short() {
        // `b` is ignored for a reason of two lines, the first of which ends with the name of `a`
        // and the second of which starts as an entry does.
        let known = names(&["a", "b", "c"]);
        // The test the line names has run already, or runs later: its own entry ends with its name
        // a second time, whichever entry the harness wrote first.
        for record in [
            "ok a\nignored: a\nok b\nok c\n",
            "ignored: a\nok b\nok a\nok c\n",
        ] {
            assert!(read_record(record, &known).is_err(), "{record}");
        }
        // The test the line names did not run: the record has an entry more than the harness's
        // summary counts, and the binary is unreadable.
        let output = "\
     Running tests/t.rs (target/debug/deps/t-1)
test b ... ignored, a
ok
test result: ok. 1 passed; 0 failed; 1 ignored; 0 measured; 1 filtered out; finished in 0.00s
";
        let record = read_record("ignored: a\nok b\nok c\n", &known).expect("entries");
        assert_eq!(record["a"], Outcome::Ignored(None));
        assert!(!read(output, |_| Recording::Record(&record))[0].readable());
    }

    #[test]
    fn an_ignore_reason_of_several_lines_is_one_entry() {
        let known = names(&["a", "b"]);
        let record = read_record(
            "ignored: needs a device\nok when one is named b\nok a\n",
            &known,
        )
        .expect("a record");
        assert_eq!(
            record["b"],
            Outcome::Ignored(Some("needs a device\nok when one is named".to_owned()))
        );
        assert_eq!(record["a"], Outcome::Passed);
    }

    #[test]
    fn text_that_is_no_entry_of_the_record_is_refused() {
        let known = names(&["tests::a"]);
        assert!(read_record("this is not an entry\nok tests::a\n", &known).is_err());
        assert!(
            read_record("ok tests::b\n", &known).is_err(),
            "an entry ends with a test the binary lists"
        );
        assert!(
            read_record("ok tests::a\nok tests::a\n", &known).is_err(),
            "no test has two entries"
        );
    }

    #[test]
    fn a_record_that_does_not_add_up_to_the_summary_leaves_the_binary_unreadable() {
        let output = "\
     Running tests/t.rs (target/debug/deps/t-1)
test one ... ok
test two ... ok
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
";
        let known = names(&["one", "two"]);
        let whole = read_record("ok one\nok two\n", &known).expect("a record");
        assert!(read(output, |_| Recording::Record(&whole))[0].readable());
        // The run ended before the harness reached its second test, or its record was cut short.
        let short = read_record("ok one\n", &known).expect("a record");
        assert!(!read(output, |_| Recording::Record(&short))[0].readable());
        // The harness printed no summary: the run did not end where it meant to.
        let unfinished = "     Running tests/t.rs (target/debug/deps/t-1)\ntest one ... ok\n";
        assert!(!read(unfinished, |_| Recording::Record(&whole))[0].readable());
    }

    #[test]
    fn a_binary_whose_record_is_lost_is_unreadable_whatever_its_output_says() {
        let output = "\
     Running tests/t.rs (target/debug/deps/t-1)
test one ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
";
        let binaries = read(output, |_| Recording::Lost("the harness left no record"));
        assert!(!binaries[0].readable());
        assert_eq!(
            binaries[0].problem.as_deref(),
            Some("the harness left no record")
        );
        assert!(binaries[0].tests.is_empty());
    }

    #[test]
    fn a_test_that_returned_early_stays_skipped_when_a_failure_message_quotes_a_summary() {
        // The failure message of the last test holds the output of a run of its own, with the
        // summary that run printed; the successes come before it, and the real summary after.
        let output = "\
     Running tests/reads.rs (target/debug/deps/reads-1)

running 2 tests
test drives_fish ... ok
test quotes_a_run ... FAILED

successes:

---- drives_fish stdout ----
not exercised: fish is not on this machine

successes:
    drives_fish

failures:

---- quotes_a_run stdout ----
the child run said:
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

failures:
    quotes_a_run

test result: FAILED. 1 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.10s
";
        let record = read_record(
            "ok drives_fish\nfailed quotes_a_run\n",
            &names(&["drives_fish", "quotes_a_run"]),
        )
        .expect("a record");
        let binaries = read(output, |_| Recording::Record(&record));
        assert_eq!(
            binaries[0].tests["drives_fish"],
            Outcome::Skipped("not exercised: fish is not on this machine".to_owned())
        );
        assert_eq!(binaries[0].tests["quotes_a_run"], Outcome::Failed);
        assert_eq!(binaries[0].summary, Some([1, 1, 0, 0]));
        assert!(binaries[0].readable(), "{:?}", binaries[0].problem);
    }

    #[test]
    fn a_summary_quoted_in_a_tests_output_ends_no_section_of_the_harnesss() {
        // Tests that run one at a time with their output shown: the first quotes the output of a
        // run of its own, with a failure list and its summary, and the second returns early.
        let output = "\
     Running tests/t.rs (target/debug/deps/t-1)

running 2 tests
test a ... the child said:
failures:
    nothing
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
ok
test b ... skipped: no device to drive
ok

test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
";
        let record = read_record("ok a\nok b\n", &names(&["a", "b"])).expect("a record");
        let binaries = read(output, |_| Recording::Record(&record));
        assert_eq!(binaries[0].tests["a"], Outcome::Passed);
        assert_eq!(
            binaries[0].tests["b"],
            Outcome::Skipped("skipped: no device to drive".to_owned())
        );
        assert!(binaries[0].readable(), "{:?}", binaries[0].problem);
    }

    #[test]
    fn a_summary_quoted_in_a_tests_captured_output_is_that_output() {
        let output = "\
     Running tests/t.rs (target/debug/deps/t-1)

running 2 tests
test a ... ok
test b ... ok

successes:

---- a stdout ----
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
skipped: no device to drive

successes:
    a
    b

test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
";
        let record = read_record("ok a\nok b\n", &names(&["a", "b"])).expect("a record");
        let binaries = read(output, |_| Recording::Record(&record));
        assert_eq!(
            binaries[0].tests["a"],
            Outcome::Skipped("skipped: no device to drive".to_owned())
        );
        assert_eq!(binaries[0].tests["b"], Outcome::Passed);
        assert!(binaries[0].readable(), "{:?}", binaries[0].problem);
    }
}
