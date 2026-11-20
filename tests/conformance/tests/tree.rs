//! How the report supervises a step's command that has a time limit: when it starts one, which
//! processes it signals, when, and what it keeps of what the command wrote.
//!
//! Each case runs a small shell script under `kr_conformance::tree` with a deadline a few seconds
//! away. Every process a fixture starts waits with `sleep` or `wait`; the pids a case looks at are
//! recorded by the script in a file of the case's own, and a case that fails ends what it left.
#![cfg(unix)]

use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::RecvTimeoutError;
use std::time::{Duration, Instant};

use rustix::process::{Pid, Signal, WaitOptions, kill_process_group, waitpid};

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

/// What a call that was supervised gave.
type Call = std::io::Result<Waited<Output>>;

/// What ends a group that its call did not end: it is given the group's number.
type End = Arc<dyn Fn(Pid) + Send + Sync>;

/// The controller of a fixture command: it starts `command` as the leader of a group of its own and
/// keeps the leader, which [`tree::watch`] supervises on this thread. A watchdog sends `end` the
/// group's number only when the call has not returned `within` a time after the start. A call that
/// has not returned has not reaped the leader, for every wait in `watch` is the last thing it does
/// before it returns, so the leader holds the group's number then and the signal reaches the
/// fixture's group and no other process. The watchdog is dismissed when the call returns, and sends
/// nothing after. Gives none when the watchdog had to send.
fn controlled(
    mut command: Command,
    deadline: Deadline,
    within: Duration,
    end: End,
) -> Option<Call> {
    let mut child = match tree::spawn(&mut command, true) {
        Ok(child) => child,
        Err(error) => return Some(Err(error)),
    };
    let group = Pid::from_child(&child);
    let (dismiss, dismissed) = std::sync::mpsc::channel::<()>();
    let watchdog = std::thread::spawn(move || {
        let late = dismissed.recv_timeout(within) == Err(RecvTimeoutError::Timeout);
        if late {
            end(group);
        }
        late
    });
    let waited = tree::watch(&mut child, deadline);
    drop(dismiss);
    let late = watchdog.join().expect("the watchdog");
    (!late).then_some(waited)
}

/// What ends the group of a fixture that did not end: the signal that cannot be caught.
fn kill_the_group() -> End {
    Arc::new(|group| {
        let _ = kill_process_group(group, Signal::KILL);
    })
}

/// Runs `command` under `deadline` as a controlled fixture on a thread of its own, which gives what
/// the call returned, or none when it did not return in a minute.
fn start(command: Command, deadline: Deadline) -> std::thread::JoinHandle<Option<Call>> {
    std::thread::spawn(move || {
        controlled(command, deadline, Duration::from_secs(60), kill_the_group())
    })
}

/// [`start`], and waits for its end.
fn run(command: Command, deadline: Deadline) -> Option<Call> {
    start(command, deadline).join().expect("the controller")
}

/// What a call that returned in time gave, for a command that started.
fn returned(call: Option<Call>) -> Waited<Output> {
    call.expect("the call did not return in time")
        .expect("a started command")
}

/// KR-REQ-29.01, the part about reproducible commands: the controller of a fixture sends nothing once
/// its call has returned: a command that ends at once, with a watchdog that waits 2 s, and 4 s
/// after the call, no signal was sent. A signal after the call would go to a number that the
/// leader no longer holds.
#[test]
fn the_controller_of_a_fixture_sends_no_signal_after_its_call_has_returned() {
    let sent = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&sent);
    let end: End = Arc::new(move |_| {
        counter.fetch_add(1, Ordering::SeqCst);
    });
    let call = controlled(
        bash("exit 0", &[]),
        deadline_in(30),
        Duration::from_secs(2),
        end,
    );
    assert!(matches!(returned(call), Waited::Done(_)));
    std::thread::sleep(Duration::from_secs(4));
    assert_eq!(
        sent.load(Ordering::SeqCst),
        0,
        "the controller sent a signal after its call had returned"
    );
}

/// KR-REQ-29.01, the part about reproducible commands: the controller of a fixture ends the group
/// of a call that has not returned `within` its time, once: a command that waits 20 s under a
/// deadline of 600 s, with a watchdog that waits 2 s, gives none and is sent one signal.
#[test]
fn the_controller_of_a_fixture_ends_the_group_of_a_call_that_does_not_return_once() {
    let sent = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&sent);
    let end: End = Arc::new(move |group| {
        counter.fetch_add(1, Ordering::SeqCst);
        let _ = kill_process_group(group, Signal::KILL);
    });
    let call = controlled(
        bash("sleep 20", &[]),
        deadline_in(600),
        Duration::from_secs(2),
        end,
    );
    assert!(call.is_none(), "the call returned in time");
    assert_eq!(sent.load(Ordering::SeqCst), 1);
}

/// KR-REQ-29.01, the part about reproducible commands: when the leader was reaped by another waiter,
/// the report's wait for it fails, and the report gives that error and signals nothing: the leader's
/// number may be another process's. The case reaps the leader itself while a process of its group
/// holds the pipe, and a process of the group that writes a line when it is asked to end is
/// looked at after the grace: its file stays empty.
#[test]
fn a_leader_reaped_by_another_waiter_gives_the_error_and_no_signal_is_sent() {
    let place = tempfile::tempdir().expect("a directory");
    let pids = place.path().join("pids.txt");
    let marker = place.path().join("asked.txt");
    // The leader records its pid, and leaves a process of its group that writes `term` to the file
    // when it is asked to end and holds no pipe, and `sleep 5`, which holds the pipe.
    let script = "printf '%s\\n' \"$$\" > \"$1\"\n( trap 'printf \"%s\\n\" term >> \"$2\"; exit 0' TERM; sleep 20 & wait ) >/dev/null 2>&1 &\nsleep 5 &\nexit 0";
    let began = Instant::now();
    let call = start(bash(script, &[&pids, &marker]), deadline_in(20));
    let leader = recorded_pids(&pids, 1);
    let leader = Pid::from_raw(leader[0].parse().expect("a pid")).expect("a process");
    // The report waits for the leader only when the pipe has closed, 5 s on.
    waitpid(Some(leader), WaitOptions::empty()).expect("the leader, which this case reaps");
    let call = call.join().expect("the controller");
    let took = began.elapsed();
    std::thread::sleep(GRACE + Duration::from_secs(1));
    let asked = std::fs::read_to_string(&marker).unwrap_or_default();
    assert!(
        matches!(call, Some(Err(_))),
        "the call gave {call:?}, not the error of a wait that failed"
    );
    assert!(took < Duration::from_secs(15), "the call took {took:?}");
    assert_eq!(asked, "", "a signal was sent to the group");
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
    let waited = returned(call.join().expect("the controller"));
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
    let script = "trap 'head -c 600000 /dev/zero; printf \"%s\\n\" done >> \"$1\"; exit 0' TERM\nsleep 61 &\nprintf '%s\\n' \"$!\" > \"$2\"\nwait";
    let captured = timed_out(returned(run(
        bash(script, &[&marker, &pids]),
        deadline_in(3),
    )));
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
    // Job control puts the background job in a group of its own.
    let script =
        "set -m\n(while :; do echo tick; sleep 0.2; done) &\nprintf '%s\\n' \"$!\" > \"$1\"";
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
    let script = "head -c 3000000 /dev/zero >&2; head -c 3000000 /dev/zero";
    let mut command = bash(script, &[]);
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
