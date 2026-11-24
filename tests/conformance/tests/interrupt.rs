//! What the report does when it is sent `INT` or `TERM` while a step with a time limit runs: the
//! signal goes on to the step's process group, the report waits for the group, ends what is left by
//! force, records the step as stopped, starts no later step and ends by the signal it was sent. A
//! signal that reaches it while no step with a limit runs has its default action, as it has without
//! the handlers.
//!
//! This file is the case of the forwarding itself, so it is the one place that sends a signal, and
//! the rule that no case sends a signal (`no_recovery.rs`, for `tree.rs`, `execution.rs` and the
//! fixture `time-limits`) does not cover it. A case starts the report's program in a process of its
//! own, sends the signal to that process and to no other, and never to a group. Every process a
//! script starts waits with `sleep` and ends by itself within 61 s, so a case that fails leaves
//! nothing after that. The pids a case looks at are recorded by the scripts in a file of the case's
//! own; a look by number sends nothing and leads to no action.
#![cfg(unix)]

use std::fs::File;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use kr_conformance::report::result_path;
use rustix::process::{Pid, Signal};

const FIXED: &str = "[ignored_runs]
held = false
[unrun]
bench = 'b'
typescript = 't'
";

/// The longest a case waits for the report's program to end.
const BOUND: Duration = Duration::from_secs(60);

/// Records its pid, then its child's, and waits for the child: the group of a step has two
/// processes, and the child ignores `INT` because a shell without job control starts it so. The
/// leader traps `INT` and `TERM` and writes the name of the one it is sent to `<file>.signals`.
const GROUP: &str = "trap 'printf \"%s\\n\" INT >> \"$1.signals\"' INT\ntrap 'printf \"%s\\n\" TERM >> \"$1.signals\"' TERM\nprintf '%s\\n' \"$$\" >> \"$1\"\nsleep 61 &\nprintf '%s\\n' \"$!\" >> \"$1\"\nwait\n";

/// [`GROUP`] with both signals ignored by the whole group, so that only the force ends it.
const IGNORES: &str = "trap '' INT TERM\nprintf '%s\\n' \"$$\" >> \"$1\"\nsleep 61 &\nprintf '%s\\n' \"$!\" >> \"$1\"\nwait\n";

/// [`GROUP`] with `INT` ignored by the whole group, and a leader that, when it is sent `TERM`, writes
/// `TERM` to `<file>.signals` and sends `INT` to its parent, the report's program. The second signal
/// is then sent by the group, after the report selected the first and sent it on, and so within the
/// grace that began with it.
const ANSWERS_TERM_WITH_INT: &str = "trap '' INT\ntrap 'printf \"%s\\n\" TERM >> \"$1.signals\"; kill -INT \"$PPID\"' TERM\nprintf '%s\\n' \"$$\" >> \"$1\"\nsleep 61 &\nprintf '%s\\n' \"$!\" >> \"$1\"\nwait\n";

/// Records its pid and waits 20 s: a step without a limit.
const WAITS: &str = "printf '%s\\n' \"$$\" >> \"$1\"\nsleep 20\n";

/// Ends at once.
const QUICK: &str = "exit 0\n";

/// Records two lines in its file, as [`GROUP`] records two pids, and ends at once: the report's
/// program ends after it, with every line a case waits for already in the file.
const RECORDS_AND_ENDS: &str = "printf '%s\\n' \"$$\" \"$$\" >> \"$1\"\n";

/// Sends `INT` to its parent, the report's program, and ends with status 0 at once: the signal is
/// recorded while the step ends.
const SIGNALS_AND_ENDS: &str = "kill -INT \"$PPID\"\nexit 0\n";

fn git(root: &Path, arguments: &[&str]) {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(arguments)
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("HOME", root)
        .output()
        .expect("git runs");
    assert!(
        output.status.success(),
        "git {arguments:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn copy_into(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).expect("a directory");
    for entry in std::fs::read_dir(from).expect("the fixture") {
        let entry = entry.expect("an entry");
        let target = to.join(entry.file_name());
        if entry.file_type().expect("a type").is_dir() {
            copy_into(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), &target).expect("a file");
        }
    }
}

/// The text of a step: `limits` are its `timeout` line, or none, and `script` is a file under
/// `scripts/` that gets `file`, where it records the pids it starts.
fn step(id: &str, limits: &str, script: &str, file: &Path) -> String {
    format!(
        "[[step]]\nid = '{id}'\ngroup = 'rust'\nwhat = 'the {id} step'\nplatforms = ['linux', 'macos']\nreading = 'build'\n{limits}\ncommand = ['bash', 'scripts/{script}.sh', '{}']\n",
        file.display()
    )
}

/// A run of the report's program, started over a copy of the fixture `time-limits` with a plan of
/// the steps given and the scripts of `scripts`, which are (name, text) pairs.
struct Run {
    child: Child,
    // Held so that what the run made stays until the case ends.
    _directory: tempfile::TempDir,
    evidence: tempfile::TempDir,
    output: PathBuf,
}

impl Run {
    fn start(steps: &[String], scripts: &[(&str, &str)]) -> Self {
        let directory = tempfile::tempdir().expect("a directory");
        let root = directory.path().canonicalize().expect("the copy's root");
        let tree = root.join("tree");
        copy_into(
            &Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests")
                .join("fixtures")
                .join("time-limits"),
            &tree,
        );
        for (name, text) in scripts {
            std::fs::write(tree.join("scripts").join(format!("{name}.sh")), text)
                .expect("a script");
        }
        git(&tree, &["init", "-q"]);
        git(&tree, &["add", "-A"]);
        let plan = root.join("plan.toml");
        std::fs::write(
            &plan,
            format!(
                "repository = 'interrupt'\ngroups = ['rust']\n[rust]\nmanifests = ['Cargo.toml']\n{FIXED}{}",
                steps.concat()
            ),
        )
        .expect("the plan");
        let evidence = tempfile::Builder::new()
            .prefix("kr-conformance-evidence.")
            .tempdir()
            .expect("an evidence directory");
        let output = root.join("output.txt");
        let written = File::create(&output).expect("the output file");
        let mut report = Command::new(env!("CARGO_BIN_EXE_kr-conformance"));
        report
            .args(["run", "--root"])
            .arg(&tree)
            .arg("--evidence")
            .arg(evidence.path())
            .arg("--plan")
            .arg(&plan)
            .args(["--group", "rust"])
            .env_clear()
            .env("HOME", &root)
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("TMPDIR", std::env::temp_dir());
        // The report's first act is `cargo metadata` over the copy. The `cargo` on `PATH` is
        // rustup's, and under the case's own, empty `HOME` it would find no toolchain and install
        // the pinned one from the network on every run. The test's own `cargo`, which cargo gives
        // the test program, is the toolchain's and installs nothing; and no toolchain is installed
        // whatever else is missing, so a case never reaches the network.
        if let Some(cargo) = std::env::var_os("CARGO") {
            report.env("CARGO", cargo);
        }
        let child = report
            .env("RUSTUP_AUTO_INSTALL", "0")
            .stdin(Stdio::null())
            .stdout(written.try_clone().expect("the output file again"))
            .stderr(written)
            .spawn()
            .expect("the report's program starts");
        Self {
            child,
            _directory: directory,
            evidence,
            output,
        }
    }

    /// Sends `signal` to the report's program, and to no other process.
    fn send(&self, signal: Signal) {
        let pid = Pid::from_child(&self.child);
        rustix::process::kill_process(pid, signal).expect("the report's program takes a signal");
    }

    /// How the report's program ended, once it has, within `within`.
    fn ended_within(&mut self, within: Duration) -> ExitStatus {
        let until = Instant::now() + within;
        loop {
            if let Some(status) = self.child.try_wait().expect("a wait") {
                return status;
            }
            assert!(
                Instant::now() < until,
                "the report's program had not ended in {within:?}; it said: {}",
                std::fs::read_to_string(&self.output).unwrap_or_default()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// The result the run wrote.
    fn result(&self) -> serde_json::Value {
        let text =
            std::fs::read_to_string(result_path(self.evidence.path())).unwrap_or_else(|error| {
                panic!(
                    "no result: {error}; the report's program said: {}",
                    std::fs::read_to_string(&self.output).unwrap_or_default()
                )
            });
        serde_json::from_str(&text).expect("the result is JSON")
    }

    /// The pids a script recorded in `file`, once it has recorded `count` of them. A report's
    /// program that has ended fails the wait, whatever the file holds, and the failure shows what
    /// it said: the case signals the report's program next, and one that was waited for is no
    /// longer there to be signalled, so its pid could be another process's.
    fn recorded_pids(&mut self, file: &Path, count: usize) -> Vec<String> {
        let until = Instant::now() + Duration::from_secs(60);
        loop {
            // Asked before the file is read: the call reaps a program that has ended.
            let ended = self.child.try_wait().expect("a wait");
            let text = std::fs::read_to_string(file).unwrap_or_default();
            let pids: Vec<String> = text.lines().map(str::to_owned).collect();
            if let Some(status) = ended {
                panic!(
                    "the report's program ended {status:?} before the case signalled it, with {} \
                     of {count} pids recorded ({text:?}); it said: {}",
                    pids.len(),
                    std::fs::read_to_string(&self.output).unwrap_or_default()
                );
            }
            if pids.len() >= count {
                return pids;
            }
            assert!(
                Instant::now() < until,
                "the script recorded {text:?}, not {count} pids"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

/// Whether the process `pid` exists: a process that has ended and is not reaped yet counts.
fn alive(pid: &str) -> bool {
    let number = pid.parse::<i32>().expect("a pid");
    Pid::from_raw(number).is_some_and(|pid| rustix::process::test_kill_process(pid).is_ok())
}

/// The processes of `pids` that still exist `within` a time after the call, looked at every tenth of
/// a second.
fn left_after(pids: &[String], within: Duration) -> Vec<String> {
    let until = Instant::now() + within;
    loop {
        let left: Vec<String> = pids.iter().filter(|pid| alive(pid)).cloned().collect();
        if left.is_empty() || Instant::now() >= until {
            return left;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// What a run that was sent `signal` (named `words`) while its first step ran must show: the report
/// ended by that signal, the step's processes are gone, the step is recorded as stopped with no exit
/// status and its log says so, the run fails, and the step after it was not run, so its script left
/// no file.
fn assert_stopped_by(signal: Signal, words: &str, script: (&str, &str)) {
    let place = tempfile::tempdir().expect("a directory for the pids");
    let pids = place.path().join("pids.txt");
    let later = place.path().join("later.txt");
    let mut run = Run::start(
        &[
            step("held", "timeout = 600", "held", &pids),
            step("later", "timeout = 600", "later", &later),
        ],
        &[script, ("later", WAITS)],
    );
    let started = run.recorded_pids(&pids, 2);
    run.send(signal);
    let status = run.ended_within(BOUND);
    assert_eq!(
        status.signal(),
        Some(signal.as_raw()),
        "the report's program ended {status:?}; it said: {}",
        std::fs::read_to_string(&run.output).unwrap_or_default()
    );
    let left = left_after(&started, Duration::from_secs(10));
    assert!(left.is_empty(), "processes of the step were left: {left:?}");
    // The group was sent the signal, before the force: its leader wrote the signal's name.
    let sent = std::fs::read_to_string(place.path().join("pids.txt.signals")).unwrap_or_default();
    assert_eq!(sent, format!("{words}\n"), "the group was not sent {words}");
    let result = run.result();
    let held = &result["steps"][0];
    let said = format!("stopped by signal {words}");
    assert_eq!(held["error"], said.as_str(), "{held}");
    assert!(held["exit"].is_null(), "{held}");
    let log = std::fs::read_to_string(
        run.evidence
            .path()
            .join(held["log"].as_str().expect("a log")),
    )
    .expect("the log");
    assert!(log.contains(&format!("== {said}")), "{log}");
    let after = &result["steps"][1];
    assert_eq!(
        after["error"],
        format!("not run because the run was interrupted by signal {words}").as_str(),
        "{after}"
    );
    assert!(!later.exists(), "the step after the interrupted one ran");
    // A step that was not run counts with the failed ones, as it does when its budget is spent.
    assert_eq!(
        result["summary"]["failed_steps"],
        serde_json::json!([1, 2]),
        "{result}"
    );
}

/// KR-REQ-29.01, the part about reproducible commands: an interrupt that reaches the report while a
/// step with a limit runs is sent on to the step's group. The leader waits for its child, which
/// ignores `INT`, so the group ends when the grace is spent.
#[test]
fn an_interrupt_is_sent_on_to_the_steps_group_and_the_run_ends_by_it() {
    assert_stopped_by(Signal::INT, "INT", ("held", GROUP));
}

/// KR-REQ-29.01, the part about reproducible commands: the same for the termination request.
#[test]
fn a_termination_request_is_sent_on_to_the_steps_group_and_the_run_ends_by_it() {
    assert_stopped_by(Signal::TERM, "TERM", ("held", GROUP));
}

/// KR-REQ-29.01, the part about reproducible commands: a group that ignores both signals is ended
/// by force, when the grace has been spent and not before.
#[test]
fn a_group_that_ignores_the_signal_is_ended_by_force_after_the_grace() {
    let place = tempfile::tempdir().expect("a directory for the pids");
    let pids = place.path().join("pids.txt");
    let mut run = Run::start(
        &[step("held", "timeout = 600", "held", &pids)],
        &[("held", IGNORES)],
    );
    let started = run.recorded_pids(&pids, 2);
    let sent = Instant::now();
    run.send(Signal::INT);
    let status = run.ended_within(BOUND);
    let took = sent.elapsed();
    assert_eq!(status.signal(), Some(Signal::INT.as_raw()), "{status:?}");
    assert!(
        took >= kr_conformance::tree::GRACE,
        "the group was ended in {took:?}, before the grace"
    );
    let left = left_after(&started, Duration::from_secs(10));
    assert!(left.is_empty(), "processes of the step were left: {left:?}");
}

/// KR-REQ-29.01, the part about reproducible commands: a signal that reaches the report while no
/// step with a limit runs has its default action, as it has without the handlers: here the first
/// step has a limit and has ended, and the second has none and is running.
#[test]
fn a_signal_outside_a_step_with_a_limit_ends_the_report_as_it_always_did() {
    let place = tempfile::tempdir().expect("a directory for the pids");
    let pids = place.path().join("pids.txt");
    let unused = place.path().join("unused.txt");
    let mut run = Run::start(
        &[
            step("quick", "timeout = 600", "quick", &unused),
            step("waits", "", "waits", &pids),
        ],
        &[("quick", QUICK), ("waits", WAITS)],
    );
    run.recorded_pids(&pids, 1);
    let sent = Instant::now();
    run.send(Signal::INT);
    let status = run.ended_within(Duration::from_secs(15));
    assert_eq!(status.signal(), Some(Signal::INT.as_raw()), "{status:?}");
    assert!(sent.elapsed() < Duration::from_secs(15));
}

/// KR-REQ-29.01, the part about reproducible commands: a signal that reaches the report as the last
/// step ends, with the status 0, leaves that step stopped and the result failed, and not a passed
/// result from a report that then ends by the signal. The step sends the signal to its parent, the
/// report's program, and ends at once, so the signal is recorded while the report waits for it.
#[test]
fn a_signal_that_reaches_the_report_as_the_last_step_ends_leaves_the_step_stopped() {
    let place = tempfile::tempdir().expect("a directory for the pids");
    let unused = place.path().join("unused.txt");
    let mut run = Run::start(
        &[step("last", "timeout = 600", "last", &unused)],
        &[("last", SIGNALS_AND_ENDS)],
    );
    let status = run.ended_within(BOUND);
    assert_eq!(
        status.signal(),
        Some(Signal::INT.as_raw()),
        "the report's program ended {status:?}; it said: {}",
        std::fs::read_to_string(&run.output).unwrap_or_default()
    );
    let result = run.result();
    let last = &result["steps"][0];
    assert_eq!(last["error"], "stopped by signal INT", "{last}");
    assert!(last["exit"].is_null(), "{last}");
    assert_eq!(
        result["summary"]["failed_steps"],
        serde_json::json!([1]),
        "{result}"
    );
}

/// KR-REQ-29.01, the part about reproducible commands: the signal that stops the run is the first
/// the report selects. The case sends `TERM` once. The group's leader answers `TERM`, which the
/// report sends on only after it selected it, with an `INT` to the report, so that signal is
/// recorded in the grace that began with the selection, with no sleep and no second send of the
/// case's own to time. It does not replace the `TERM`, though `INT` comes first in the report's
/// list, and the stopped step, the step after it and the end of the report all name `TERM`.
#[test]
fn a_second_signal_in_the_grace_does_not_change_the_signal_of_the_run() {
    let place = tempfile::tempdir().expect("a directory for the pids");
    let pids = place.path().join("pids.txt");
    let later = place.path().join("later.txt");
    let mut run = Run::start(
        &[
            step("held", "timeout = 600", "held", &pids),
            step("later", "timeout = 600", "later", &later),
        ],
        &[("held", ANSWERS_TERM_WITH_INT), ("later", WAITS)],
    );
    run.recorded_pids(&pids, 2);
    run.send(Signal::TERM);
    let status = run.ended_within(BOUND);
    // The leader wrote this when the report sent it `TERM`, and then sent `INT`: without this line
    // the case would not have sent a second signal.
    let sent = std::fs::read_to_string(place.path().join("pids.txt.signals")).unwrap_or_default();
    assert_eq!(sent, "TERM\n", "the group was not sent TERM");
    assert_eq!(status.signal(), Some(Signal::TERM.as_raw()), "{status:?}");
    let result = run.result();
    assert_eq!(result["steps"][0]["error"], "stopped by signal TERM");
    assert_eq!(
        result["steps"][1]["error"],
        "not run because the run was interrupted by signal TERM"
    );
}

/// A report's program that has ended is not waited for as one that has not, though the file already
/// holds the pids the case asks for: the case would signal a program that is no longer there. The
/// wait fails and says what the report said.
#[test]
fn a_report_that_has_ended_fails_the_wait_for_pids_the_file_already_holds() {
    let place = tempfile::tempdir().expect("a directory for the pids");
    let pids = place.path().join("pids.txt");
    let mut run = Run::start(
        &[step("ends", "timeout = 600", "ends", &pids)],
        &[("ends", RECORDS_AND_ENDS)],
    );
    run.ended_within(BOUND);
    let recorded = std::fs::read_to_string(&pids).unwrap_or_default();
    assert_eq!(
        recorded.lines().count(),
        2,
        "the script recorded {recorded:?}"
    );
    let caught =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run.recorded_pids(&pids, 2)));
    let panic = match caught {
        Ok(pids) => panic!("a report that had ended was waited for as one that had not: {pids:?}"),
        Err(panic) => panic,
    };
    let message = panic.downcast_ref::<String>().cloned().unwrap_or_default();
    assert!(message.contains("the report's program ended"), "{message}");
    assert!(message.contains("it said:"), "{message}");
}
