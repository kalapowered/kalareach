//! Reads `cargo test` output: which binaries ran, and what each of their tests came to.
//!
//! The report reads the test harness's own lines rather than a structured format, because the
//! structured one needs an unstable flag and the pinned toolchain is a stable release. The lines
//! it reads are the ones the harness has printed for years:
//!
//! * Cargo's `Running <source> (<executable>)`, which starts one binary's output;
//! * `test <name> ... ok`, `... FAILED` and `... ignored` or `... ignored, <reason>`;
//! * the `failures:` list at the end of a binary's run;
//! * `test result: ok. P passed; F failed; I ignored; ...`.
//!
//! A test that runs one at a time prints its name before it runs, so whatever it or a process it
//! started writes can land between the name and the verdict. The reading allows for that: a result
//! that is not on its own line is taken from the failure list and the summary, and a binary whose
//! counts do not add up to the summary it printed is reported as unreadable rather than guessed at.
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

use std::collections::BTreeMap;

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
    /// Whether the outcomes read agree with the summary.
    pub readable: bool,
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

/// Reads one `cargo test` step's combined output.
#[must_use]
pub fn read(output: &str) -> Vec<Binary> {
    let mut binaries: Vec<Binary> = Vec::new();
    let mut reading = Reading::default();
    // Whether the binary being read has been settled by its summary: settling reads what was
    // gathered for it, once.
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
                settle(binary, &mut reading);
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
            settle(binary, &mut reading);
            settled = true;
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
        settle(binary, &mut reading);
    }
    binaries
}

/// Turns the lines read for one binary into outcomes, and checks them against its summary.
fn settle(binary: &mut Binary, reading: &mut Reading) {
    let Reading {
        pending,
        failures,
        early,
        loose,
        ..
    } = std::mem::take(reading);
    let alone = pending.len() == 1;
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
        } else if verdict == "ok" || binary.summary.is_some_and(|[_, failed, _, _]| failed == 0) {
            // A verdict lost among a test's own output is a pass when nothing in this binary
            // failed.
            match early.get(&name).or(loose.as_ref().filter(|_| alone)) {
                Some(line) => Outcome::Skipped(line.clone()),
                None => Outcome::Passed,
            }
        } else {
            // Something failed, and this test's verdict is not on record: it cannot be called
            // passed, so it is counted as the thing that is not known to have passed.
            Outcome::Failed
        };
        binary.tests.insert(name, outcome);
    }
    for name in failures {
        binary.tests.insert(name, Outcome::Failed);
    }
    // A test said it returned early and the output cannot say which: every pass of this binary is
    // in doubt, so none of it is read.
    let attributed = loose.is_none() || alone;
    binary.readable = attributed
        && binary.summary.is_some_and(|[passed, failed, ignored, _]| {
            let count = |wanted: fn(&Outcome) -> bool| {
                binary.tests.values().filter(|o| wanted(o)).count() as u64
            };
            count(|o| matches!(o, Outcome::Passed | Outcome::Skipped(_))) == passed
                && count(|o| *o == Outcome::Failed) == failed
                && count(|o| matches!(o, Outcome::Ignored(_))) == ignored
        });
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
        let binaries = read(RUN);
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
        assert!(binaries[0].readable);
        assert_eq!(binaries[1].tests["a_bad_one"], Outcome::Failed);
        assert_eq!(binaries[1].tests["a_good_one"], Outcome::Passed);
        assert!(binaries[1].readable, "{:?}", binaries[1]);
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
        let binaries = read(output);
        assert_eq!(binaries[0].tests["measures"], Outcome::Passed);
        assert_eq!(binaries[0].tests["also"], Outcome::Passed);
        assert!(binaries[0].readable);
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
        let binaries = read(output);
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
        assert!(!read(output)[0].readable);
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
        let binaries = read(shown);
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
        assert!(binaries[0].readable, "{:?}", binaries[0]);

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
        let binaries = read(one_at_a_time);
        assert_eq!(
            binaries[0].tests["measures"],
            Outcome::Skipped("not exercised: this host has no second filesystem".to_owned())
        );
        assert_eq!(binaries[0].tests["also_measures"], Outcome::Passed);
        assert!(binaries[0].readable);

        // A binary that ran one test: everything in its run is that test's.
        let alone = "\
     Running benches/input_latency.rs (target/release/deps/input_latency-9)

running 1 test
skipping: the measurement needs a release build
test added_input_forwarding_latency ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 3 filtered out; finished in 0.10s
";
        let binaries = read(alone);
        assert_eq!(
            binaries[0].tests["added_input_forwarding_latency"],
            Outcome::Skipped("skipping: the measurement needs a release build".to_owned())
        );
        assert!(binaries[0].readable);
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
        assert!(!read(output)[0].readable);
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
        let binaries = read(output);
        assert_eq!(binaries[0].summary, None);
        assert!(!binaries[0].readable);
    }
}
