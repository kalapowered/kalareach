//! How a session closes when its root shell ends, against a real daemon and a real worker on
//! Windows.
//!
//! The Unix twin of these cases is `lifecycle.rs`, which drives a terminal of its own. Here the
//! daemon runs in this process and starts each worker through the environment's scheduled task,
//! the root shell runs in a pseudo-console, and the test types into it through the terminal it
//! attaches, as `attach_windows.rs` and `default_shell_windows.rs` do. What the person is told is
//! read back with `kr status` and `kr list`.

#![cfg(windows)]

use std::path::PathBuf;
use std::time::{Duration, Instant};

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

/// A second session, opened and closed after the first has closed, and what the daemon lists once
/// both have: the first session once, closed, with the display number it had; the second with a
/// number of its own; and no session live.
async fn nothing_started_the_closed_session_again(
    host: &WorkerHost,
    closed: &str,
    its_display_number: &Value,
) {
    let (next, dimensions) = host
        .kr_new(&[
            "--shell-mode",
            "native_compat",
            "--shell",
            &system32("cmd.exe"),
        ])
        .await
        .session();
    let environment = host.tree.environment();
    let mut typist = WorkerTerminal::attach(&environment, next, dimensions).await;
    typist.type_line("exit 0").await;
    closed_session(host, &next.to_string()).await;
    drop(typist);

    let sessions = all_sessions(host).await;
    let first: Vec<&Value> = sessions
        .iter()
        .filter(|session| session["session_id"] == closed)
        .collect();
    assert_eq!(
        first.len(),
        1,
        "the closed session is listed once: {sessions:?}"
    );
    assert_eq!(first[0]["state"], "closed", "{sessions:?}");
    assert_eq!(
        &first[0]["display_number"], its_display_number,
        "a display number is never used twice: {sessions:?}"
    );
    assert!(
        sessions.iter().all(|session| session["state"] == "closed"),
        "no session is live again: {sessions:?}"
    );
    assert_ne!(
        sessions
            .iter()
            .find(|session| session["session_id"] == next.to_string())
            .map(|session| &session["display_number"]),
        Some(its_display_number),
        "the next session took the closed one's number"
    );
}

/// KR-REQ-07.52: an explicit `exit` typed at the root shell closes the session with the status the
/// shell ended with, and the shell is not started again.
///
/// The root shell is the Windows command shell. The line typed ends it with a status of its own
/// (7), so a closure that carried some other status, or none, is told from the shell's. The
/// session is then closed with the reason a shell's own exit has, and a session opened and closed
/// after it finds the first one closed, listed once, and nothing live.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_typed_exit_closes_the_session_with_the_shells_status_and_nothing_starts_it_again() {
    let host = WorkerHost::start().await;
    let created = host
        .kr_new(&[
            "--shell-mode",
            "native_compat",
            "--shell",
            &system32("cmd.exe"),
        ])
        .await;
    let (session, dimensions) = created.session();
    let environment = host.tree.environment();
    let mut typist = WorkerTerminal::attach(&environment, session, dimensions).await;

    typist.type_line("exit 7").await;
    let closed = closed_session(&host, &session.to_string()).await;
    assert_eq!(closed["closure"]["reason"], "root_exit", "{closed}");
    assert_eq!(closed["closure"]["exit_code"], 7, "{closed}");
    drop(typist);

    let listed = all_sessions(&host).await;
    let display = listed
        .iter()
        .find(|entry| entry["session_id"] == session.to_string())
        .map(|entry| entry["display_number"].clone())
        .unwrap_or_else(|| panic!("the closed session is listed: {listed:?}"));
    nothing_started_the_closed_session_again(&host, &session.to_string(), &display).await;
}

/// KR-REQ-07.52: the end of the root shell's input closes the session just as the shell's own exit
/// does, and the shell is not started again.
///
/// The root program is the system's `nslookup`, which reads its commands from the console until its
/// input ends and then ends with status 0. The end of input a console gives is Ctrl-Z at the start
/// of a line, and in a session of the native-compatible mode it is the program's own: it reaches
/// the program as typed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_end_of_the_shells_input_closes_the_session_and_nothing_starts_it_again() {
    let host = WorkerHost::start().await;
    let created = host
        .kr_new(&[
            "--shell-mode",
            "native_compat",
            "--shell",
            &system32("nslookup.exe"),
        ])
        .await;
    let (session, dimensions) = created.session();
    let environment = host.tree.environment();
    let mut typist = WorkerTerminal::attach(&environment, session, dimensions).await;

    typist.type_line("\u{1a}").await;
    let closed = closed_session(&host, &session.to_string()).await;
    assert_eq!(closed["closure"]["reason"], "root_exit", "{closed}");
    assert_eq!(closed["closure"]["exit_code"], 0, "{closed}");
    drop(typist);

    let listed = all_sessions(&host).await;
    let display = listed
        .iter()
        .find(|entry| entry["session_id"] == session.to_string())
        .map(|entry| entry["display_number"].clone())
        .unwrap_or_else(|| panic!("the closed session is listed: {listed:?}"));
    nothing_started_the_closed_session_again(&host, &session.to_string(), &display).await;
}
