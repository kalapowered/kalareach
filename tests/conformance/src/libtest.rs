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

use std::collections::BTreeMap;

/// What one test came to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// It ran and passed.
    Passed,
    /// It ran and failed.
    Failed,
    /// The harness did not run it, with the reason its attribute gives, where it gives one.
    Ignored(Option<String>),
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

/// Reads one `cargo test` step's combined output.
#[must_use]
pub fn read(output: &str) -> Vec<Binary> {
    let mut binaries: Vec<Binary> = Vec::new();
    let mut pending: Vec<(String, String)> = Vec::new();
    let mut in_failures = false;
    let mut failures: Vec<String> = Vec::new();
    let mut last_name: Option<String> = None;
    for raw in output.lines() {
        let line = raw.trim_end_matches('\r');
        // Documentation tests are a section of their own, which no target of the report's is.
        let doctests = line
            .trim_start()
            .strip_prefix("Doc-tests ")
            .map(|name| (String::new(), format!("doc-tests {name}")));
        if let Some((source, executable)) = running(line).or(doctests) {
            if let Some(binary) = binaries.last_mut() {
                settle(binary, &mut pending, &mut failures);
            }
            binaries.push(Binary {
                executable,
                source,
                ..Binary::default()
            });
            in_failures = false;
            last_name = None;
            continue;
        }
        let Some(binary) = binaries.last_mut() else {
            continue;
        };
        if let Some(summary) = summary(line) {
            binary.summary = Some(summary);
            settle(binary, &mut pending, &mut failures);
            in_failures = false;
            last_name = None;
            continue;
        }
        if line == "failures:" {
            in_failures = true;
            failures.clear();
            continue;
        }
        if in_failures {
            if let Some(name) = line.strip_prefix("    ").filter(|name| !name.contains(' ')) {
                failures.push(name.to_owned());
            }
            continue;
        }
        if let Some(rest) = line.strip_prefix("test ") {
            if let Some((name, verdict)) = rest.split_once(" ... ") {
                pending.push((name.to_owned(), verdict.to_owned()));
                last_name = Some(name.to_owned());
            } else if let Some(name) = rest.strip_suffix(" ...") {
                pending.push((name.to_owned(), String::new()));
                last_name = Some(name.to_owned());
            }
            continue;
        }
        // A verdict on a line of its own, after whatever a test that runs alone printed.
        if matches!(line, "ok" | "FAILED")
            && let Some(name) = &last_name
            && let Some(entry) = pending
                .iter_mut()
                .rev()
                .find(|(pending_name, _)| pending_name == name)
            && !matches!(entry.1.as_str(), "ok" | "FAILED")
        {
            entry.1 = line.to_owned();
        }
    }
    if let Some(binary) = binaries.last_mut() {
        settle(binary, &mut pending, &mut failures);
    }
    binaries
}

/// Turns the lines read for one binary into outcomes, and checks them against its summary.
fn settle(binary: &mut Binary, pending: &mut Vec<(String, String)>, failures: &mut Vec<String>) {
    for (name, verdict) in pending.drain(..) {
        let outcome = if let Some(reason) = verdict.strip_prefix("ignored") {
            Outcome::Ignored(
                reason
                    .strip_prefix(", ")
                    .map(str::to_owned)
                    .filter(|r| !r.is_empty()),
            )
        } else if failures.contains(&name) || verdict == "FAILED" {
            Outcome::Failed
        } else if verdict == "ok" {
            Outcome::Passed
        } else if binary.summary.is_some_and(|[_, failed, _, _]| failed == 0) {
            // The verdict was lost among a test's own output, and nothing in this binary failed.
            Outcome::Passed
        } else {
            // Something failed, and this test's verdict is not on record: it cannot be called
            // passed, so it is counted as the thing that is not known to have passed.
            Outcome::Failed
        };
        binary.tests.insert(name, outcome);
    }
    for name in failures.drain(..) {
        binary.tests.insert(name, Outcome::Failed);
    }
    binary.readable = binary.summary.is_some_and(|[passed, failed, ignored, _]| {
        let count = |wanted: fn(&Outcome) -> bool| {
            binary.tests.values().filter(|o| wanted(o)).count() as u64
        };
        count(|o| *o == Outcome::Passed) == passed
            && count(|o| *o == Outcome::Failed) == failed
            && count(|o| matches!(o, Outcome::Ignored(_))) == ignored
    });
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
    fn a_binary_that_printed_no_summary_is_unreadable() {
        let output = "     Running tests/t.rs (target/debug/deps/t-1)\ntest one ... ok\n";
        let binaries = read(output);
        assert_eq!(binaries[0].summary, None);
        assert!(!binaries[0].readable);
    }
}
