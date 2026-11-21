//! How the report supervises a step's command that has a time limit: when it starts one, which
//! processes it signals, when, and what it keeps of what the command wrote.
//!
//! Each case runs a small shell script under `kr_conformance::tree` with a deadline a few seconds
//! away. No case sends a signal: the signals that end what a call started are the report's own.
//! Every process a fixture starts waits with `sleep` or `wait` and ends by itself within 61 s, so a
//! case that fails leaves nothing after that. A call runs on a thread, and a case waits for what it
//! gave for a bound, and leaves the thread when the call has not returned. The pids a case looks at
//! are recorded by the script in a file of the case's own; a look by number may give a false red
//! and never leads to an action.
#![cfg(unix)]

use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant};

use kr_conformance::tree::{self, Captured, Deadline, GRACE, Waited};

fn deadline_in(seconds: u64) -> Deadline {
    Deadline {
        at: Instant::now() + Duration::from_secs(seconds),
        seconds,
        budget: false,
    }
}

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

/// What a command that did not end in its time wrote before then.
fn timed_out(waited: Waited<Output>) -> Captured {
    match waited {
        Waited::TimedOut(captured) => captured,
        Waited::Done(output) => panic!("the command ended in its time: {:?}", output.status),
        Waited::NotStarted => panic!("the command was not started"),
    }
}

/// The pids a fixture script recorded in `file`, once it has recorded `count` of them.
fn recorded_pids(file: &Path, count: usize) -> Vec<String> {
    let until = Instant::now() + Duration::from_secs(30);
    loop {
        let text = std::fs::read_to_string(file).unwrap_or_default();
        let pids: Vec<String> = text.lines().map(str::to_owned).collect();
        if pids.len() >= count {
            return pids;
        }
        assert!(
            Instant::now() < until,
            "the fixture recorded {text:?}, not {count} pids"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Whether the process `pid` exists: a process that has ended and is not reaped yet counts.
fn alive(pid: &str) -> bool {
    Command::new("sh")
        .args(["-c", &format!("kill -0 {pid} 2>/dev/null")])
        .status()
        .expect("a shell")
        .success()
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

/// Shell text that writes zero bytes to descriptors 1 and 2, the pieces of `plan` as (descriptor,
/// bytes) in order, with nonblocking writes and its own monotonic deadline: it ends by itself
/// `seconds` after it starts at the latest, with no signal, whatever the reader of its pipes does.
/// A write that a pipe's reader does not take is retried until then, so a case that leaves a call
/// whose reader failed leaves a process that ends by itself.
fn writing(plan: &[(u8, u64)], seconds: u64) -> String {
    let pieces: Vec<String> = plan
        .iter()
        .map(|(descriptor, bytes)| format!("({descriptor},{bytes})"))
        .collect();
    format!(
        "python3 -c \"import os,time,fcntl\nend=time.monotonic()+{seconds}\nfor fd,left in [{}]:\n    fcntl.fcntl(fd,fcntl.F_SETFL,fcntl.fcntl(fd,fcntl.F_GETFL)|os.O_NONBLOCK)\n    while left>0 and time.monotonic()<end:\n        try:\n            left-=os.write(fd,bytes(min(65536,left)))\n        except BlockingIOError:\n            time.sleep(0.01)\n\"",
        pieces.join(",")
    )
}

/// What a call that was supervised gave.
type Call = std::io::Result<Waited<Output>>;

/// The longest a case waits for a call that it expects to return.
const BOUND: Duration = Duration::from_secs(60);

/// A call that runs on a thread of its own. The case waits for what the call gave for a bound that
/// it chooses and, when the call has not returned, leaves the thread: it sends no signal and does
/// not wait for it.
struct Started(Receiver<Call>);

impl Started {
    /// What the call gave, or none when it had not returned `within`.
    fn within(&self, within: Duration) -> Option<Call> {
        self.0.recv_timeout(within).ok()
    }
}

/// Runs `command` under `deadline`, with its standard output captured, on a thread of its own.
fn start(mut command: Command, deadline: Deadline) -> Started {
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = sender.send(tree::output(&mut command, Some(deadline)));
    });
    Started(receiver)
}

/// [`start`], and waits for what the call gave for [`BOUND`]: none when it had not returned.
fn run(command: Command, deadline: Deadline) -> Option<Call> {
    start(command, deadline).within(BOUND)
}

/// What a call that returned in time gave, for a command that started.
fn returned(call: Option<Call>) -> Waited<Output> {
    call.expect("the call did not return in time")
        .expect("a started command")
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
    assert!(matches!(by_output, Waited::NotStarted), "{by_output:?}");
    assert!(matches!(by_status, Waited::NotStarted), "{by_status:?}");
    // An order: a command that was started is asked to end and given the grace.
    assert!(
        began.elapsed() < GRACE,
        "the call took {:?}: it started the command",
        began.elapsed()
    );
    assert!(!marker.exists(), "the command ran");
}

/// KR-REQ-29.01, the part about reproducible commands: a leader that ended while a process of its
/// group still holds the pipe is not reaped until the group is ended: through the wait for the
/// signal that asks to end, through the grace, which a process that ignores that signal outlasts,
/// and up to the signal that ends it by force. The leader and the process are looked at inside the
/// grace.
#[test]
fn a_leader_that_ended_while_a_process_of_its_group_holds_the_pipe_is_not_reaped_before_the_end() {
    let place = tempfile::tempdir().expect("a directory");
    let pids = place.path().join("pids.txt");
    let script = "trap '' TERM\nsleep 61 &\nprintf '%s\\n%s\\n' \"$$\" \"$!\" > \"$1\"\nexit 0";
    let deadline = deadline_in(3);
    let call = start(bash(script, &[&pids]), deadline);
    let started = recorded_pids(&pids, 2);
    assert!(
        Instant::now() < deadline.at,
        "the fixture did not start in time"
    );
    // The signal that asks to end is sent at the deadline and the one that ends by force two
    // seconds later: the window is inside the grace with a second of slack at its end.
    std::thread::sleep(
        (deadline.at + Duration::from_millis(500)).saturating_duration_since(Instant::now()),
    );
    let mut seen = Vec::new();
    while Instant::now() < deadline.at + Duration::from_millis(1200) {
        seen.push((alive(&started[0]), alive(&started[1])));
        std::thread::sleep(Duration::from_millis(100));
    }
    let waited = returned(call.within(BOUND));
    let left = left_after(&started, Duration::from_secs(10));
    assert!(matches!(waited, Waited::TimedOut(_)), "{waited:?}");
    assert!(!seen.is_empty());
    assert!(
        seen.iter().all(|state| *state == (true, true)),
        "the leader and the process that ignores the first signal, in the grace: {seen:?}"
    );
    assert!(
        left.is_empty(),
        "processes of the command were left: {left:?}"
    );
}

/// KR-REQ-29.01, the part about reproducible commands: the group is asked to end first and has the
/// grace to do it: a leader that, asked to, takes a second to write a line to a file and a line to
/// its standard output and end writes them, and is not ended by force before; what it wrote to the
/// standard output is kept.
#[test]
fn the_group_is_asked_to_end_and_has_the_grace_before_it_is_ended_by_force() {
    let place = tempfile::tempdir().expect("a directory");
    let file = place.path().join("ended.txt");
    let pids = place.path().join("pids.txt");
    let script = "trap 'sleep 1; printf \"%s\\n\" ended >> \"$1\"; printf \"%s\\n\" asked; exit 0' TERM\nsleep 61 &\nprintf '%s\\n' \"$!\" > \"$2\"\nwait";
    let waited = returned(run(bash(script, &[&file, &pids]), deadline_in(3)));
    let captured = timed_out(waited);
    let written = std::fs::read_to_string(&file).unwrap_or_default();
    assert_eq!(
        written, "ended\n",
        "the leader was not asked to end, or was not given the grace to"
    );
    assert_eq!(captured.stdout, b"asked\n");
}

/// KR-REQ-29.01, the part about reproducible commands: a process that writes more than a pipe holds
/// when it is asked to end is not blocked on its write, because the pipe is read through the grace:
/// asked to end, it writes 600 000 bytes and then a line to a file, and the report has the line and
/// every byte.
#[test]
fn a_process_that_writes_more_than_a_pipe_holds_when_asked_to_end_is_read_through_the_grace() {
    let place = tempfile::tempdir().expect("a directory");
    let marker = place.path().join("marker.txt");
    let pids = place.path().join("pids.txt");
    // The write is the fixture's own, with a deadline of 20 s, so that it ends by itself if the
    // report does not read what it writes.
    let script = format!(
        "trap '{}; printf \"%s\\n\" done >> \"$1\"; exit 0' TERM\nsleep 61 &\nprintf '%s\\n' \"$!\" > \"$2\"\nwait",
        writing(&[(1, 600_000)], 20)
    );
    let call = run(bash(&script, &[&marker, &pids]), deadline_in(3));
    assert!(
        call.is_some(),
        "the call did not return in time: the process was blocked on its write"
    );
    let captured = timed_out(returned(call));
    let written = std::fs::read_to_string(&marker).unwrap_or_default();
    assert_eq!(
        written, "done\n",
        "the process was ended by force before it had written what it was asked to end with"
    );
    assert_eq!(captured.stdout.len(), 600_000);
}

/// KR-REQ-29.01, the part about reproducible commands: a pipe that a process of the group holds
/// past the leader's end is held no longer than the deadline: the call ends the group then, and
/// the process does not outlast it.
#[test]
fn a_pipe_that_a_process_of_the_group_holds_past_the_leader_s_end_is_ended_at_the_deadline() {
    let place = tempfile::tempdir().expect("a directory");
    let pids = place.path().join("pids.txt");
    let script = "sleep 61 &\nprintf '%s\\n' \"$!\" > \"$1\"";
    let began = Instant::now();
    let call = run(bash(script, &[&pids]), deadline_in(2));
    let started = recorded_pids(&pids, 1);
    let left = left_after(&started, Duration::from_secs(10));
    let waited = returned(call);
    assert!(matches!(waited, Waited::TimedOut(_)), "{waited:?}");
    assert!(
        began.elapsed() < Duration::from_secs(2) + GRACE + Duration::from_secs(30),
        "the call took {:?}",
        began.elapsed()
    );
    assert!(left.is_empty(), "the process that held the pipe was left");
}

/// KR-REQ-29.01, the part about reproducible commands: a pipe that a process outside the group
/// holds does not hold the call past the deadline and the grace, and the pipe is closed when the
/// call returns: the process, which writes a line every fifth of a second, ends on its own by the
/// signal for a write to a pipe with no reader.
#[test]
fn a_pipe_that_a_process_outside_the_group_holds_is_closed_when_the_call_returns() {
    let place = tempfile::tempdir().expect("a directory");
    let pids = place.path().join("pids.txt");
    // Job control puts the background job in a group of its own. The job ends by itself, after 250
    // lines at the most (about 50 s), when no write to a closed pipe has ended it before.
    let script = "set -m\n(i=0; while [ $i -lt 250 ]; do echo tick; sleep 0.2; i=$((i+1)); done) &\nprintf '%s\\n' \"$!\" > \"$1\"";
    let began = Instant::now();
    let call = run(bash(script, &[&pids]), deadline_in(2));
    let started = recorded_pids(&pids, 1);
    let took = began.elapsed();
    // The process has had the whole of the call's time to be written to and is not ended by it.
    let left = left_after(&started, Duration::from_secs(10));
    let captured = timed_out(returned(call));
    assert!(
        took < Duration::from_secs(2) + GRACE + Duration::from_secs(30),
        "the call took {took:?}"
    );
    assert!(!captured.stdout.is_empty(), "the process wrote nothing");
    assert!(
        left.is_empty(),
        "the process that is outside the group still writes: the pipe was left open"
    );
}

/// KR-REQ-29.01, the part about reproducible commands: a case does not wait for a call that the
/// kill of its group cannot end. A job in a group of its own writes to the pipe until the case
/// releases it, under a deadline that is not reached, so the call does not return, and the case
/// has none from it within its bound and sends no signal. Once the job is released the pipe
/// closes, and the thread that the case left gives the call's result.
#[test]
fn a_call_that_the_kill_of_its_group_cannot_end_is_left_at_the_bound_of_the_case() {
    let place = tempfile::tempdir().expect("a directory");
    let release = place.path().join("release");
    // Job control puts the job in a group of its own. It ends when the release file exists, or by
    // itself after 250 lines at the most (about 50 s).
    let script = "set -m\n(i=0; while [ ! -e \"$1\" ] && [ $i -lt 250 ]; do echo tick; sleep 0.2; i=$((i+1)); done) &\nexit 0";
    let began = Instant::now();
    let call = start(bash(script, &[&release]), deadline_in(600));
    let at_the_bound = call.within(Duration::from_secs(2));
    let took = began.elapsed();
    // The barrier is let go before the case asserts, so that a failed case leaves nothing.
    std::fs::write(&release, "").expect("the release file");
    let after = call.within(Duration::from_secs(30));
    assert!(
        at_the_bound.is_none(),
        "the call returned: {at_the_bound:?}"
    );
    assert!(
        took < Duration::from_secs(12),
        "the case waited {took:?} for a bound of 2 s"
    );
    assert!(
        matches!(after, Some(Ok(Waited::Done(_)))),
        "the thread that the case left gave {after:?}, not the call's result"
    );
}

/// KR-REQ-29.01, the part about reproducible commands: what a command wrote before its time was
/// spent is given with the time out: the step's log keeps it.
#[test]
fn what_a_command_wrote_before_its_time_was_spent_is_kept() {
    let place = tempfile::tempdir().expect("a directory");
    let pids = place.path().join("pids.txt");
    let script =
        "printf 'out\\n'; printf 'err\\n' >&2; sleep 61 &\nprintf '%s\\n' \"$!\" > \"$1\"\nwait";
    let mut command = bash(script, &[&pids]);
    command.stderr(Stdio::piped());
    let captured = timed_out(returned(run(command, deadline_in(4))));
    assert_eq!(
        (captured.stdout.as_slice(), captured.stderr.as_slice()),
        (b"out\n".as_slice(), b"err\n".as_slice())
    );
}

/// KR-REQ-29.01, the part about reproducible commands: a command that ends in its time is given
/// whole, though it writes a great deal to its standard error before it writes to its standard
/// output: both pipes are read while the command runs.
#[test]
fn a_command_that_writes_a_great_deal_to_both_pipes_ends_in_its_time_with_all_it_wrote() {
    // The writer is the fixture's own, with a deadline of 50 s for both writes together: if the
    // report does not read both pipes while the command runs, the writer is blocked on the first
    // and ends by itself at the deadline.
    let script = writing(&[(2, 3_000_000), (1, 3_000_000)], 50);
    let mut command = bash(&script, &[]);
    command.stderr(Stdio::piped());
    let waited = returned(run(command, deadline_in(30)));
    let Waited::Done(output) = waited else {
        panic!("the command did not end in its time");
    };
    assert!(output.status.success(), "{:?}", output.status);
    assert_eq!(
        (output.stdout.len(), output.stderr.len()),
        (3_000_000, 3_000_000)
    );
}
