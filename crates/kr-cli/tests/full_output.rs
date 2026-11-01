//! What `kr` does when a stream it writes to has no room left.
//!
//! KR-REQ-27.05, full disks: `/dev/full` answers every write with ENOSPC, the error a full
//! filesystem gives, so a command whose standard output or standard error is that device meets the
//! refusal at the write it makes. Each case runs the built `kr` as a process, once with room as the
//! control and once with the stream on the device.
//!
//! Linux only: `/dev/full` is a Linux device.

#![cfg(target_os = "linux")]

use std::process::{Command, Output, Stdio};

mod support;

/// The exit status a command ends with when it could not write to the terminal.
const TERMINAL_FAILURE: i32 = 6;

/// The exit status of a command line that names no command.
const USAGE_FAILURE: i32 = 2;

/// The device that takes no byte.
fn full() -> Stdio {
    Stdio::from(
        std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/full")
            .expect("opens the device that has no room"),
    )
}

/// Runs the built `kr` with `line`, from the root directory, with the directories of `temp`.
fn run(temp: &kr_ipc::testing::TempHost, line: &[&str], stdout: Stdio, stderr: Stdio) -> Output {
    Command::new(support::kr())
        .args(line)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", temp.root())
        .env("KR_RUNTIME_DIR", temp.paths().runtime_root())
        .env("KR_STATE_DIR", temp.paths().state_root())
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(stdout)
        .stderr(stderr)
        .output()
        .expect("kr runs")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// A command that has succeeded and cannot write its answer to a full standard output says so on
/// standard error and ends with the failure for the terminal, whichever of the program's three ways
/// of writing a line the answer takes: `--version` is a word of the program's own, `shell remove
/// --dry-run` is a set of composed lines and `--json` writes a document.
#[test]
fn a_command_whose_standard_output_has_no_room_says_so_on_standard_error_and_fails() {
    let temp = kr_ipc::testing::TempHost::create();
    for line in [
        &["--version"][..],
        &["shell", "remove", "--dry-run"][..],
        &["--json", "shell", "remove", "--dry-run"][..],
    ] {
        let control = run(&temp, line, Stdio::piped(), Stdio::piped());
        assert_eq!(
            control.status.code(),
            Some(0),
            "kr {line:?} with room: {}",
            text(&control.stderr)
        );
        assert!(
            !control.stdout.is_empty(),
            "kr {line:?} writes its answer on standard output"
        );

        let refused = run(&temp, line, full(), Stdio::piped());
        assert_eq!(
            refused.status.code(),
            Some(TERMINAL_FAILURE),
            "kr {line:?} with a full standard output: {}",
            text(&refused.stderr)
        );
        assert!(
            text(&refused.stderr).contains("standard output"),
            "kr {line:?} names the stream it could not write: {}",
            text(&refused.stderr)
        );
    }
}

/// A command that has failed and cannot write the document that says so to a full standard output
/// says what it could not write on standard error and ends with its own failure.
#[test]
fn a_failure_document_that_a_full_standard_output_refuses_is_said_on_standard_error() {
    let temp = kr_ipc::testing::TempHost::create();
    let line = ["--json", "no-such-command"];
    let control = run(&temp, &line, Stdio::piped(), Stdio::piped());
    assert_eq!(control.status.code(), Some(USAGE_FAILURE));
    assert!(
        text(&control.stdout).contains("\"ok\": false"),
        "the failure is a document on standard output: {}",
        text(&control.stdout)
    );

    let refused = run(&temp, &line, full(), Stdio::piped());
    assert_eq!(
        refused.status.code(),
        Some(USAGE_FAILURE),
        "the command ends with its own failure: {}",
        text(&refused.stderr)
    );
    assert!(
        text(&refused.stderr).contains("standard output"),
        "and says what it could not write: {}",
        text(&refused.stderr)
    );
}

/// A command that fails and cannot write its failure to a full standard error says so on standard
/// output, where it still can, and ends with its own failure.
#[test]
fn a_failure_that_a_full_standard_error_refuses_is_said_on_standard_output() {
    let temp = kr_ipc::testing::TempHost::create();
    let line = ["no-such-command"];
    let control = run(&temp, &line, Stdio::piped(), Stdio::piped());
    assert_eq!(control.status.code(), Some(USAGE_FAILURE));
    assert!(
        !control.stderr.is_empty(),
        "the failure is said on standard error"
    );

    let refused = run(&temp, &line, Stdio::piped(), full());
    assert_eq!(
        refused.status.code(),
        Some(USAGE_FAILURE),
        "the command ends with its own failure: {}",
        text(&refused.stdout)
    );
    assert!(
        text(&refused.stdout).contains("standard error"),
        "and says what it could not write: {}",
        text(&refused.stdout)
    );
}
