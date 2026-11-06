//! How a session closes when its root shell ends, against a real daemon and a real worker on
//! Windows.
//!
//! The Unix twin of these cases is `lifecycle.rs`, which drives a terminal of its own. Here the
//! daemon runs in this process and starts each worker through the environment's scheduled task,
//! the root shell runs in a pseudo-console, and the test types into it through the terminal it
//! attaches, as `attach_windows.rs` and `default_shell_windows.rs` do. What the person is told is
//! read back with `kr status` and `kr list`, and what became of the processes with the kernel.

#![cfg(windows)]

use std::path::PathBuf;
use std::time::{Duration, Instant};

use kr_ipc::identity::{ProcessState, process_state};
use kr_protocol::identity::ProcessStartIdentity;
use serde_json::Value;

mod support;
#[path = "../../kr-controller/tests/teardown/mod.rs"]
mod teardown;
mod windows_session;

use windows_session::{LIVENESS_DEADLINE, WorkerHost, WorkerTerminal};

/// A program of the system directory.
fn system32(program: &str) -> String {
    PathBuf::from(std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into()))
        .join("System32")
        .join(program)
        .display()
        .to_string()
}

/// What `kr` printed, as JSON, for a command that must succeed.
async fn json_of(host: &WorkerHost, arguments: &[&str]) -> Value {
    let output = host.kr(arguments, &[]).await;
    assert!(
        output.status.success(),
        "kr {arguments:?} failed: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "kr {arguments:?} printed no JSON ({error}): {}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

/// Waits for `kr status` to report the session closed, and returns that report. It fails when the
/// session is not closed within the liveness deadline.
async fn closed_session(host: &WorkerHost, session: &str) -> Value {
    let started = Instant::now();
    loop {
        let output = host.kr(&["status", session, "--json"], &[]).await;
        let said = match serde_json::from_slice::<Value>(&output.stdout) {
            Ok(report) if output.status.success() => {
                if report["state"] == "closed" {
                    return report;
                }
                report.to_string()
            }
            _ => format!(
                "exit {:?}: {}{}",
                output.status.code(),
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ),
        };
        assert!(
            started.elapsed() < LIVENESS_DEADLINE,
            "waited {:?} for session {session} to close; kr status last said {said}",
            started.elapsed()
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// The sessions `kr list` reports, closed ones included.
async fn all_sessions(host: &WorkerHost) -> Vec<Value> {
    let listed = json_of(host, &["--json", "list", "--include-closed"]).await;
    listed["sessions"]
        .as_array()
        .unwrap_or_else(|| panic!("a list of sessions: {listed}"))
        .clone()
}

/// Waits until the process the identity names is gone. It fails when it is still there after the
/// liveness deadline, or when the kernel does not say.
async fn ended(identity: &ProcessStartIdentity, what: &str) {
    let started = Instant::now();
    loop {
        match process_state(identity) {
            ProcessState::Ended => return,
            ProcessState::Running => {}
            ProcessState::Unknown { detail } => {
                panic!("the kernel did not say whether {what} {identity:?} is there: {detail}")
            }
        }
        assert!(
            started.elapsed() < LIVENESS_DEADLINE,
            "{what} {identity:?} was still there {:?} after the session closed",
            started.elapsed()
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// A session whose root program is `program`, with a terminal attached to it, and the identity of
/// the worker its descriptor records.
async fn opened(
    host: &WorkerHost,
    program: &str,
) -> (
    kr_protocol::ids::SessionId,
    WorkerTerminal,
    ProcessStartIdentity,
) {
    let (session, dimensions) = host
        .kr_new(&["--shell-mode", "native_compat", "--shell", program])
        .await
        .session();
    let environment = host.tree.environment();
    let worker = kr_ipc::descriptor::read_all(&environment)
        .expect("reads the runtime directory")
        .into_iter()
        .filter_map(|entry| entry.descriptor.ok())
        .find(|descriptor| descriptor.session_id == session)
        .expect("the session's descriptor is published")
        .process_start_identity;
    let typist = WorkerTerminal::attach(&environment, session, dimensions).await;
    (session, typist, worker)
}

/// What a closed session leaves to show that nothing started its shell again.
///
/// The root shell the closure names and the worker are each gone. A second session is then opened
/// and closed, and the daemon lists exactly the two sessions, both closed, the first with the
/// display number it had and the second with a number of its own.
async fn nothing_started_the_closed_session_again(
    host: &WorkerHost,
    session: kr_protocol::ids::SessionId,
    terminal: WorkerTerminal,
    worker: &ProcessStartIdentity,
    closed: &Value,
) {
    // The terminal is let go, so the worker has nobody left to send the closure to.
    drop(terminal);
    let root: ProcessStartIdentity = closed["closure"]["terminated"]
        .as_array()
        .and_then(|named| {
            named
                .iter()
                .find(|process| process["name"] == "the session's root shell")
        })
        .map(|process| {
            serde_json::from_value(process["start"].clone())
                .unwrap_or_else(|error| panic!("the root shell's identity ({error}): {closed}"))
        })
        .unwrap_or_else(|| panic!("the closure names the root shell: {closed}"));
    ended(&root, "the root shell").await;
    ended(worker, "the worker").await;

    let (next, mut next_terminal, next_worker) = opened(host, &system32("cmd.exe")).await;
    next_terminal.type_line("exit 0").await;
    let second = closed_session(host, &next.to_string()).await;
    drop(next_terminal);
    ended(&next_worker, "the second session's worker").await;

    let sessions = all_sessions(host).await;
    assert_eq!(
        sessions.len(),
        2,
        "the two sessions made are the two listed: {sessions:?}"
    );
    assert!(
        sessions.iter().all(|listed| listed["state"] == "closed"),
        "no session is live again: {sessions:?}"
    );
    let first = sessions
        .iter()
        .find(|listed| listed["session_id"] == session.to_string())
        .unwrap_or_else(|| panic!("the first session is listed: {sessions:?}"));
    assert_eq!(
        first["display_number"], closed["display_number"],
        "the closed session keeps its number: {sessions:?}"
    );
    assert_ne!(
        first["display_number"], second["display_number"],
        "a display number is never used twice: {sessions:?}"
    );
}

/// KR-REQ-07.52: an explicit `exit` typed at the root shell closes the session with the status the
/// shell ended with, and the shell is not started again.
///
/// The root shell is the Windows command shell. The line typed ends it with a status of its own
/// (7), so a closure that carried some other status, or none, is told from the shell's. The
/// session is then closed with the reason a shell's own exit has; the shell and the worker are
/// gone; and a session opened and closed after it finds the first one closed, with its number, and
/// nothing live.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_typed_exit_closes_the_session_with_the_shells_status_and_nothing_starts_it_again() {
    let host = WorkerHost::start().await;
    let (session, mut typist, worker) = opened(&host, &system32("cmd.exe")).await;

    typist.type_line("exit 7").await;
    let closed = closed_session(&host, &session.to_string()).await;
    assert_eq!(closed["closure"]["reason"], "root_exit", "{closed}");
    assert_eq!(closed["closure"]["exit_code"], 7, "{closed}");

    nothing_started_the_closed_session_again(&host, session, typist, &worker, &closed).await;
}

/// KR-REQ-07.52: the end of the root shell's input closes the session just as the shell's own exit
/// does, and the shell is not started again.
///
/// The root program is the system's `nslookup`, which reads its commands from the console until its
/// input ends and then ends with status 0. The end of input a console gives is Ctrl-Z at the start
/// of a line, and in a session of the native-compatible mode it is the program's own: it reaches
/// the program as typed. The line is typed once the program has shown its prompt, so a program
/// that ended by itself before it was asked to would not pass for one that ended on its input.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_end_of_the_shells_input_closes_the_session_and_nothing_starts_it_again() {
    let host = WorkerHost::start().await;
    let (session, mut typist, worker) = opened(&host, &system32("nslookup.exe")).await;

    typist
        .shown(">", "the program shows the prompt it reads its commands at")
        .await;
    typist.type_line("\u{1a}").await;
    let closed = closed_session(&host, &session.to_string()).await;
    assert_eq!(closed["closure"]["reason"], "root_exit", "{closed}");
    assert_eq!(closed["closure"]["exit_code"], 0, "{closed}");

    nothing_started_the_closed_session_again(&host, session, typist, &worker, &closed).await;
}
