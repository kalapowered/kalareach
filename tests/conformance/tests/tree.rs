//! How the report supervises a step's command that has a time limit: when it starts one, which
//! processes it signals, when, and what it keeps of what the command wrote.
//!
//! Each case runs a small shell script under `kr_conformance::tree` with a deadline a few seconds
//! away. Every process a fixture starts waits with `sleep` or `wait`; the pids a case looks at are
//! recorded by the script in a file of the case's own, and a case that fails ends what it left.
#![cfg(unix)]

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Instant;

use kr_conformance::tree::{self, Deadline, GRACE, Waited};

/// A command that runs `script` with `paths` as its arguments, `$1` and on, and reads nothing.
fn bash(script: &str, paths: &[&Path]) -> Command {
    let mut command = Command::new("bash");
    command
        .arg("-c")
        .arg(script)
        .arg("bash")
        .args(paths)
        .stdin(Stdio::null());
    command
}

/// KR-REQ-29.01, the part about reproducible commands: a command whose time is spent before it is
/// to start is not started, whatever work came between the step's commands, and the call does not
/// wait to end what it did not start.
#[test]
fn a_command_whose_time_is_spent_before_it_starts_is_not_started() {
    let place = tempfile::tempdir().expect("a directory");
    let marker = place.path().join("started");
    let script = "printf started > \"$1\"";
    let began = Instant::now();
    let spent = Deadline {
        at: began,
        seconds: 1,
        budget: false,
    };
    let by_output = tree::output(&mut bash(script, &[&marker]), Some(spent)).expect("a call");
    let by_status = tree::status(&mut bash(script, &[&marker]), Some(spent)).expect("a call");
    assert!(matches!(by_output, Waited::TimedOut), "{by_output:?}");
    assert!(matches!(by_status, Waited::TimedOut), "{by_status:?}");
    // An order: a command that was started is asked to end and given the grace.
    assert!(
        began.elapsed() < GRACE,
        "the call took {:?}: it started the command",
        began.elapsed()
    );
    assert!(!marker.exists(), "the command ran");
}
