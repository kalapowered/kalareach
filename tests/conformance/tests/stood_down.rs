//! A case that stood down for want of the account's own launchd is read as a skip of that case,
//! wherever its one-line notice lands in the output of the run.
//!
//! The notice is written on standard error in one write that the test program does not capture, so
//! it lands inside a line of the harness's own: after `test a ... `, after a verdict, or inside
//! another case's line when cases run in parallel. The reader finds it anywhere in a line, takes
//! what stood before it for the line, and refuses a notice it cannot tie to one case of the binary.

#[cfg(unix)]
use std::process::Command;

use kr_conformance::libtest::{Binary, Outcome, Record, Recording, read};

/// The notice of case `case`, as a case's own `announce` writes it.
fn notice(case: &str) -> String {
    kr_ipc::testing::account_launchd::notice(case, "the daemon start")
        .trim_end()
        .to_owned()
}

/// The harness's lines for a binary that ran `names`, around `body`.
fn binary(body: &str, names: &[&str]) -> String {
    format!(
        "     Running tests/t.rs (target/debug/deps/t-1)\n\nrunning {} tests\n{body}\ntest result: ok. {} passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n",
        names.len(),
        names.len()
    )
}

/// What `read` makes of `output`, as a binary read from its lines and as one with a record that
/// holds `names` as passed. The two agree, and that is the answer.
fn reading(output: &str, names: &[&str]) -> Binary {
    let from_lines = read(output, |_| Recording::None);
    let record: Record = names
        .iter()
        .map(|name| ((*name).to_owned(), Outcome::Passed))
        .collect();
    let from_record = read(output, |_| Recording::Record(&record));
    assert_eq!(from_lines.len(), 1, "{output}");
    assert_eq!(from_record.len(), 1, "{output}");
    let (lines, recorded) = (&from_lines[0], &from_record[0]);
    assert_eq!(
        (lines.tests.clone(), lines.readable()),
        (recorded.tests.clone(), recorded.readable()),
        "the two forms read {output}"
    );
    from_lines.into_iter().next().expect("one binary")
}

/// Asserts that case `skipped` is skipped, every other of `names` passed, and the binary readable.
fn assert_skipped(output: &str, names: &[&str], skipped: &str) {
    let read = reading(output, names);
    assert!(read.readable(), "{:?}: {output}", read.problem);
    for name in names {
        match (&read.tests[*name], *name == skipped) {
            (Outcome::Skipped(line), true) => {
                assert!(
                    line.starts_with(&format!("stood down {skipped}: ")),
                    "{line}: {output}"
                );
            }
            (Outcome::Passed, false) => {}
            (other, _) => panic!("{name} read as {other:?}: {output}"),
        }
    }
}

/// Asserts that the binary is unreadable, with the reader's one sentence.
fn assert_unreadable(output: &str, names: &[&str]) {
    let read = reading(output, names);
    assert_eq!(
        read.problem.as_deref(),
        Some("a test said it returned early, and the output does not say which"),
        "{output}"
    );
}

/// A notice is a skip of the case it names wherever it stands in the output: inside the line the case
/// is named on, after another case's verdict, on a line of its own, before the case's own verdict.
#[test]
fn a_stood_down_notice_is_a_skip_of_the_case_it_names_wherever_it_stands_in_the_output() {
    let a = notice("a");
    // (a) inside its own line, the verdict alone on the next.
    assert_skipped(
        &binary(&format!("test a ... {a}\nok\n"), &["a"]),
        &["a"],
        "a",
    );
    // (b) inside another case's line, whose verdict follows alone.
    assert_skipped(
        &binary(&format!("test b ... {a}\nok\ntest a ... ok\n"), &["a", "b"]),
        &["a", "b"],
        "a",
    );
    // (c) between another case's verdict and its newline.
    assert_skipped(
        &binary(&format!("test b ... ok{a}\ntest a ... ok\n"), &["a", "b"]),
        &["a", "b"],
        "a",
    );
    // (d) on a line of its own among the lines `--show-output` prints.
    assert_skipped(
        &binary(
            &format!(
                "test a ... ok\n\nsuccesses:\n\n---- a stdout ----\n{a}\n\nsuccesses:\n    a\n"
            ),
            &["a"],
        ),
        &["a"],
        "a",
    );
    // (e) on a line of its own before the case's own verdict.
    assert_skipped(
        &binary(&format!("test a ... \n{a}\nok\n"), &["a"]),
        &["a"],
        "a",
    );
    // (i) glued to the verdict of a case that passed, in a binary where another case failed: the
    // verdict is the text before the notice, which is not lost among the case's own output.
    let glued = format!(
        "     Running tests/t.rs (target/debug/deps/t-1)\n\nrunning 3 tests\ntest b ... ok{a}\ntest a ... ok\ntest c ... FAILED\n\nfailures:\n\nfailures:\n    c\n\ntest result: FAILED. 2 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\n"
    );
    let glued_read = read(&glued, |_| Recording::None);
    assert!(
        glued_read[0].readable(),
        "{:?}: {glued}",
        glued_read[0].problem
    );
    assert_eq!(glued_read[0].tests["b"], Outcome::Passed, "{glued}");
    assert_eq!(glued_read[0].tests["c"], Outcome::Failed, "{glued}");
    assert!(
        matches!(glued_read[0].tests["a"], Outcome::Skipped(_)),
        "{glued}"
    );
    // (h) the line the suites printed before the notice existed names no case and skips none.
    let read = reading(
        &binary("test a ... ok\n", &["a"]).replace(
            "test a ... ok",
            "the daemon start is not tested here: no domain\ntest a ... ok",
        ),
        &["a"],
    );
    assert!(read.readable(), "{:?}", read.problem);
    assert_eq!(read.tests["a"], Outcome::Passed);
}

/// A notice that names no one case, or a case that is no test of the binary, leaves the binary
/// unreadable, in a binary of two tests and in a binary of one.
#[test]
fn a_stood_down_notice_that_names_no_case_of_the_binary_leaves_it_unreadable() {
    let unnamed = notice("an unnamed case");
    for (body, names) in [
        (
            format!("test a ... {unnamed}\nok\ntest b ... ok\n"),
            vec!["a", "b"],
        ),
        (format!("test a ... {unnamed}\nok\n"), vec!["a"]),
    ] {
        assert_unreadable(&binary(&body, &names), &names);
    }
    // (g) a name that is no test of the binary.
    let stranger = notice("not_a_test_here");
    assert_unreadable(
        &binary(&format!("test a ... {stranger}\nok\n"), &["a"]),
        &["a"],
    );
    assert_unreadable(
        &binary(
            &format!("test a ... {stranger}\nok\ntest b ... ok\n"),
            &["a", "b"],
        ),
        &["a", "b"],
    );
}

/// What a child of the case runs: a case that stands down, by the function the suites call.
#[test]
#[ignore = "run by a child of the case"]
fn a_fixture_that_stands_down() {
    kr_ipc::testing::account_launchd::announce("the daemon start");
}

/// What a child of the case runs: a case that does nothing.
#[test]
#[ignore = "run by a child of the case"]
fn a_fixture_that_passes() {}

/// A real run of the two fixtures, in each way a run can be made, reads the stood-down case as a skip
/// and the other as a pass: parallel, one at a time, one at a time with the output shown, and
/// parallel with the output shown.
#[test]
#[cfg(unix)]
fn a_real_run_with_and_without_shown_output_reads_the_stood_down_case_as_a_skip() {
    let names = ["a_fixture_that_passes", "a_fixture_that_stands_down"];
    let program = std::env::current_exe().expect("this test program's path");
    let ways: [&[&str]; 4] = [
        &[],
        &["--test-threads=1"],
        &["--test-threads=1", "--show-output"],
        &["--show-output"],
    ];
    for way in ways {
        // One pipe for both streams, so that the notice lands where it does in a log made with
        // `2>&1`.
        let output = Command::new("/bin/sh")
            .args(["-c", "exec \"$0\" \"$@\" 2>&1"])
            .arg(&program)
            .args(["--ignored", "--exact"])
            .args(names)
            .args(way)
            .output()
            .expect("the program runs");
        assert!(output.status.success(), "{way:?}: {output:?}");
        let log = format!(
            "     Running tests/stood_down.rs (target/debug/deps/stood_down-1)\n{}",
            String::from_utf8_lossy(&output.stdout)
        );
        let read = reading(&log, &names);
        assert!(read.readable(), "{way:?}: {:?}: {log}", read.problem);
        assert!(
            matches!(&read.tests["a_fixture_that_stands_down"], Outcome::Skipped(line)
                if line.starts_with("stood down a_fixture_that_stands_down: ")),
            "{way:?}: {log}"
        );
        assert_eq!(
            read.tests["a_fixture_that_passes"],
            Outcome::Passed,
            "{way:?}: {log}"
        );
    }
}
