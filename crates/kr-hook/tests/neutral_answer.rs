//! Every observing hook answers exactly the neutral answer, promptly, whatever else happens.
//!
//! The applications read a hook's standard output as its decision. Gemini CLI also reads the
//! hook's standard error as one when standard output is empty, and turns plain text with an exit
//! code other than 0 and 1 into a refusal. So each hook invocation writes exactly `{}` on standard
//! output and exits 0, with nothing on either stream that a decision could be read from, and it
//! does so inside the shortest timeout any registration names: with no worker, with a worker that
//! never answers, with input it cannot read, and with input that never closes.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-12.27 | every test below |
//! | KR-REQ-12.20 | the `gemini-cli` cases |
//! | KR-REQ-12.22 | the `qoder-cli` cases |

mod common;

use std::io::Read as _;
use std::time::{Duration, Instant};

use common::{LIVENESS, Placed, run_holding_input, run_with_input};

/// The members a hook's output decides with, in the three applications' output types.
const DECIDING: [&str; 3] = ["decision", "continue", "hookSpecificOutput"];

/// The shortest timeout any hook registration names: one second, for a session ending.
const SHORTEST_TIMEOUT: Duration = Duration::from_secs(1);

/// How long a hook may wait for its worker before it answers anyway.
const DEADLINE: Duration = kr_hook::hook::HOOK_DEADLINE;

/// One application's hook invocation, and a payload for each event its registration names, as
/// the application writes them on the hook's standard input.
struct Hooks {
    application: &'static str,
    events: Vec<(&'static str, serde_json::Value)>,
}

const THREAD: &str = "4d1c0a57-1b1e-4c3a-9d2e-6a0f0c5b7e11";

fn every_application() -> Vec<Hooks> {
    vec![
        Hooks {
            application: "claude-code",
            events: vec![
                (
                    "SessionStart",
                    serde_json::json!({"session_id": THREAD, "transcript_path": "/tmp/t.jsonl",
                        "cwd": "/tmp", "hook_event_name": "SessionStart", "source": "startup"}),
                ),
                (
                    "SessionEnd",
                    serde_json::json!({"session_id": THREAD, "hook_event_name": "SessionEnd",
                        "reason": "other"}),
                ),
            ],
        },
        Hooks {
            application: "gemini-cli",
            events: vec![
                (
                    "SessionStart",
                    serde_json::json!({"session_id": THREAD, "transcript_path": "/tmp/t.jsonl",
                        "cwd": "/tmp", "hook_event_name": "SessionStart",
                        "timestamp": "2026-09-25T17:39:42.013Z", "source": "startup"}),
                ),
                (
                    "SessionEnd",
                    serde_json::json!({"session_id": THREAD, "transcript_path": "/tmp/t.jsonl",
                        "cwd": "/tmp", "hook_event_name": "SessionEnd",
                        "timestamp": "2026-09-25T17:39:42.193Z", "reason": "exit"}),
                ),
                (
                    "Notification",
                    serde_json::json!({"session_id": THREAD, "transcript_path": "/tmp/t.jsonl",
                        "cwd": "/tmp", "hook_event_name": "Notification",
                        "timestamp": "2026-09-25T17:40:02.000Z", "notification_type": "ToolPermission",
                        "message": "Tool Shell requires execution",
                        "details": {"type": "exec", "title": "Shell", "command": "ls", "rootCommand": "ls"}}),
                ),
            ],
        },
        Hooks {
            application: "qoder-cli",
            events: vec![
                (
                    "SessionStart",
                    serde_json::json!({"session_id": THREAD, "transcript_path": "/tmp/t.jsonl",
                        "cwd": "/tmp", "hook_event_name": "SessionStart",
                        "permission_mode": "default", "source": "startup"}),
                ),
                (
                    "SessionEnd",
                    serde_json::json!({"session_id": THREAD, "transcript_path": "/tmp/t.jsonl",
                        "cwd": "/tmp", "hook_event_name": "SessionEnd",
                        "permission_mode": "default", "reason": "other"}),
                ),
                (
                    "PostToolUse",
                    serde_json::json!({"session_id": THREAD, "hook_event_name": "PostToolUse",
                        "permission_mode": "default", "tool_name": "Bash",
                        "tool_input": {"command": "ls"}, "tool_response": {"stdout": "a\n"},
                        "tool_use_id": "toolu_01"}),
                ),
                (
                    "PostToolUseFailure",
                    serde_json::json!({"session_id": THREAD, "hook_event_name": "PostToolUseFailure",
                        "permission_mode": "default", "tool_name": "Bash",
                        "tool_input": {"command": "false"}, "tool_use_id": "toolu_02",
                        "error": "Command exited with non-zero status code 1",
                        "error_type": "execution_failed", "is_interrupt": false}),
                ),
                (
                    "Notification",
                    serde_json::json!({"session_id": THREAD, "hook_event_name": "Notification",
                        "permission_mode": "default", "notification_type": "permission_prompt",
                        "message": "Agent is requesting permission to run: ls",
                        "title": "Permission Required", "details": {}}),
                ),
            ],
        },
    ]
}

/// Whether what a hook printed could be read as a decision.
///
/// Standard output must be one JSON object that sets none of the deciding members, and standard
/// error, which Gemini CLI reads when standard output is empty, must not name one either.
fn neutral(stdout: &[u8], stderr: &str) -> Result<(), String> {
    let answer: serde_json::Value = serde_json::from_slice(stdout).map_err(|error| {
        format!(
            "standard output is not one JSON document ({error}): {:?}",
            String::from_utf8_lossy(stdout)
        )
    })?;
    let object = answer
        .as_object()
        .ok_or_else(|| format!("standard output is not a JSON object: {answer}"))?;
    for member in DECIDING {
        if object.contains_key(member) {
            return Err(format!("standard output sets {member:?}: {answer}"));
        }
        if stderr.contains(member) {
            return Err(format!("standard error names {member:?}: {stderr}"));
        }
    }
    Ok(())
}

/// KR-REQ-12.27, the check's own control: it refuses a planted refusal, a planted stop and planted
/// event-specific output on standard output, the same on standard error, and output that is not
/// one JSON object, and it accepts the neutral answer beside an ordinary diagnostic.
#[test]
fn kr_req_12_27_the_neutrality_check_refuses_a_planted_decision() {
    for (stdout, stderr) in [
        (&b"{\"continue\": false}\n"[..], ""),
        (&b"{\"decision\": \"deny\", \"reason\": \"no\"}\n"[..], ""),
        (
            &b"{\"hookSpecificOutput\": {\"additionalContext\": \"x\"}}\n"[..],
            "",
        ),
        (&b"{}\n"[..], "{\"continue\": false}"),
        (&b""[..], "{\"decision\": \"block\"}"),
        (&b"allowed\n"[..], ""),
        (&b"[]\n"[..], ""),
    ] {
        assert!(
            neutral(stdout, stderr).is_err(),
            "the check must refuse {:?} with {stderr:?}",
            String::from_utf8_lossy(stdout)
        );
    }
    assert_eq!(
        neutral(b"{}\n", "kr-hook: the worker did not answer in time"),
        Ok(())
    );
}

/// KR-REQ-12.27: outside a launch, each registered event of every application is answered with
/// exactly `{}` and exit 0, inside the shortest timeout any registration names.
#[test]
fn kr_req_12_27_outside_a_launch_every_hook_answers_neutrally() {
    let placed = Placed::new();
    for hooks in every_application() {
        for (event, payload) in &hooks.events {
            let ran = run_with_input(
                placed.command(&[hooks.application, "hook"]),
                payload.to_string().as_bytes(),
            );
            let case = format!("{} {event}", hooks.application);
            assert_eq!(ran.code, Some(0), "{case}: {}", ran.stderr);
            assert_eq!(ran.stdout, b"{}\n", "{case}");
            assert_eq!(neutral(&ran.stdout, &ran.stderr), Ok(()), "{case}");
            assert!(
                ran.took < SHORTEST_TIMEOUT,
                "{case} answered in {:?}",
                ran.took
            );
        }
    }
}

/// KR-REQ-12.27: input a hook cannot read, or an event its registration does not name, changes
/// nothing about the answer.
#[test]
fn kr_req_12_27_input_a_hook_cannot_read_is_answered_neutrally() {
    let placed = Placed::new();
    for hooks in every_application() {
        for input in [
            &b""[..],
            &b"not json"[..],
            &b"[]"[..],
            &b"{}"[..],
            &b"{\"hook_event_name\":\"SessionStart\"}"[..],
            &b"{\"session_id\":\"\",\"hook_event_name\":\"SessionStart\",\"source\":\"startup\"}"[..],
            &b"{\"session_id\":\"4d1c0a57\",\"hook_event_name\":\"BeforeTool\",\"tool_name\":\"x\"}"[..],
            &b"{\"session_id\":\"4d1c0a57\",\"hook_event_name\":\"SessionStart\""[..],
        ] {
            let ran = run_with_input(placed.command(&[hooks.application, "hook"]), input);
            let case = format!("{} {:?}", hooks.application, String::from_utf8_lossy(input));
            assert_eq!(ran.code, Some(0), "{case}: {}", ran.stderr);
            assert_eq!(ran.stdout, b"{}\n", "{case}");
            assert_eq!(neutral(&ran.stdout, &ran.stderr), Ok(()), "{case}");
            assert!(ran.took < SHORTEST_TIMEOUT, "{case}: {:?}", ran.took);
        }
    }
}

/// KR-REQ-12.27: an application that never closes a hook's input cannot hold the hook open.
#[test]
fn kr_req_12_27_input_that_never_closes_cannot_hold_a_hook() {
    let placed = Placed::new();
    for hooks in every_application() {
        let (event, payload) = &hooks.events[0];
        let ran = run_holding_input(
            placed.command(&[hooks.application, "hook"]),
            payload.to_string().as_bytes(),
        );
        let case = format!("{} {event}", hooks.application);
        assert_eq!(ran.code, Some(0), "{case}: {}", ran.stderr);
        assert_eq!(ran.stdout, b"{}\n", "{case}");
        assert_eq!(neutral(&ran.stdout, &ran.stderr), Ok(()), "{case}");
        assert!(ran.took >= DEADLINE, "{case} waited: {:?}", ran.took);
        assert!(ran.took < SHORTEST_TIMEOUT, "{case}: {:?}", ran.took);
    }
}

/// KR-REQ-12.27: inside a launch, a hook declares the bridge it is, the application it was invoked
/// for and `hook`, and a worker that reads the hello and never answers cannot hold it: it answers
/// `{}` at its own deadline, inside the shortest timeout any registration names, and never waits for
/// a person.
#[test]
fn kr_req_12_27_a_worker_that_never_answers_cannot_hold_a_hook() {
    let placed = Placed::new();
    let files = placed.host.root().join("files");
    std::fs::create_dir_all(&files).expect("a directory");
    let credential_file = files.join("credential");
    std::fs::write(&credential_file, "5e".repeat(32)).expect("the credential is written");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&credential_file, std::fs::Permissions::from_mode(0o600))
            .expect("owner-only");
    }
    for hooks in every_application() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a loopback listener");
        listener
            .set_nonblocking(true)
            .expect("the listener is polled");
        let port = listener.local_addr().expect("its address").port();
        let registration = files.join(format!("registration.{}", hooks.application));
        std::fs::write(
            &registration,
            format!(
                "endpoint=127.0.0.1:{port}\nprofile=lp-1\n\
                 instance=02020202-0202-0202-0202-020202020202\npid=1\nstart=1\n\
                 credential={}\nframing=json_lines\n",
                credential_file.display()
            ),
        )
        .expect("the registration is written");
        let (event, payload) = &hooks.events[0];
        let mut command = placed.command(&[hooks.application, "hook"]);
        command.env("KR_REGISTRATION", &registration);
        let input = payload.to_string();
        let running = std::thread::spawn(move || run_with_input(command, input.as_bytes()));
        let case = format!("{} {event}", hooks.application);

        let deadline = Instant::now() + LIVENESS;
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if running.is_finished() {
                        let ran = running.join().expect("the hook ran");
                        panic!(
                            "{case}: the hook ended without connecting, with {:?}: {}",
                            ran.code, ran.stderr
                        );
                    }
                    assert!(
                        Instant::now() < deadline,
                        "{case}: the hook did not connect"
                    );
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("{case}: the listener failed: {error}"),
            }
        };
        stream.set_nonblocking(false).expect("a blocking stream");
        stream
            .set_read_timeout(Some(LIVENESS))
            .expect("a bounded read");
        let mut hello = Vec::new();
        let mut byte = [0_u8; 1];
        while stream.read(&mut byte).expect("the hello is read") == 1 && byte[0] != b'\n' {
            hello.push(byte[0]);
        }
        let hello: serde_json::Value = serde_json::from_slice(&hello).expect("the hello is JSON");
        assert_eq!(
            hello["kr_hello"]["bridge"],
            serde_json::json!({"application": hooks.application, "surface": "hook"}),
            "the hook declares the application it was invoked for"
        );
        // The worker never answers; the stream stays open until the hook has gone.
        let ran = running.join().expect("the hook ran");
        drop(stream);
        assert_eq!(ran.code, Some(0), "{case}: {}", ran.stderr);
        assert_eq!(ran.stdout, b"{}\n", "{case}");
        assert_eq!(neutral(&ran.stdout, &ran.stderr), Ok(()), "{case}");
        assert!(
            ran.took >= DEADLINE,
            "{case} waited for its worker: {:?}",
            ran.took
        );
        assert!(ran.took < SHORTEST_TIMEOUT, "{case}: {:?}", ran.took);
    }
}

/// KR-REQ-12.27: a standard error nobody reads cannot hold a hook. With standard error a pipe that
/// is full before the hook starts, every hook still writes `{}` and exits 0 inside the shortest
/// timeout any registration names. The control, an empty pipe, still gets the diagnostic line.
#[cfg(unix)]
#[test]
fn kr_req_12_27_a_standard_error_nobody_reads_cannot_hold_a_hook() {
    let placed = Placed::new();
    for hooks in every_application() {
        for full in [true, false] {
            let case = format!(
                "{} with standard error {}",
                hooks.application,
                if full { "full" } else { "empty" }
            );
            let (mut diagnostics, writer) = std::io::pipe().expect("a pipe for standard error");
            if full {
                fill(&writer);
            }
            // Input the hook cannot read, which it says so about on standard error.
            let held = run_beside(
                placed.command(&[hooks.application, "hook"]),
                b"not json",
                writer,
            );
            assert!(
                held.answered.is_some_and(|after| after < SHORTEST_TIMEOUT),
                "{case}: no answer within {SHORTEST_TIMEOUT:?}"
            );
            assert_eq!(held.answer, b"{}\n", "{case}");
            assert!(
                held.exited.is_some_and(|after| after < SHORTEST_TIMEOUT),
                "{case}: no exit within {SHORTEST_TIMEOUT:?}: {:?}",
                held.exited
            );
            assert_eq!(held.code, Some(0), "{case}");
            if !full {
                let mut said = String::new();
                diagnostics
                    .read_to_string(&mut said)
                    .expect("the diagnostics are read");
                assert!(
                    said.starts_with("kr-hook: ")
                        && said.ends_with('\n')
                        && said.lines().count() == 1,
                    "{case}: one diagnostic line: {said:?}"
                );
                assert_eq!(neutral(&held.answer, &said), Ok(()), "{case}");
            }
        }
    }
}

/// What a hook did beside a standard error of the test's own.
#[cfg(unix)]
struct Held {
    /// Everything it wrote to standard output.
    answer: Vec<u8>,
    /// How long after its start the first of that arrived, where it did in time.
    answered: Option<Duration>,
    /// Its exit code, where it exited in time.
    code: Option<i32>,
    /// How long after its start it exited, where it did in time.
    exited: Option<Duration>,
}

/// Runs a hook with `input` on its standard input and `diagnostics` as its standard error, for at
/// most [`SHORTEST_TIMEOUT`], and ends it if it is still running then.
#[cfg(unix)]
fn run_beside(
    mut command: std::process::Command,
    input: &[u8],
    diagnostics: std::io::PipeWriter,
) -> Held {
    use std::io::Write as _;
    use std::process::Stdio;

    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::from(diagnostics));
    let started = Instant::now();
    let mut child = command.spawn().expect("the forwarder starts");
    // The command keeps the pipe's writing end until it is dropped, and the control reads the
    // pipe to its end.
    drop(command);
    let mut stdin = child.stdin.take().expect("its input");
    stdin.write_all(input).expect("the input is written");
    drop(stdin);
    let mut stdout = child.stdout.take().expect("its output");
    let (first, arrived) = std::sync::mpsc::channel();
    let reading = std::thread::spawn(move || {
        let mut answer = Vec::new();
        let mut buffer = [0_u8; 64];
        while let Ok(count) = stdout.read(&mut buffer) {
            if count == 0 {
                break;
            }
            if answer.is_empty() {
                let _ = first.send(started.elapsed());
            }
            answer.extend_from_slice(&buffer[..count]);
        }
        answer
    });
    let answered = arrived
        .recv_timeout(SHORTEST_TIMEOUT.saturating_sub(started.elapsed()))
        .ok();
    let (code, exited) = loop {
        if let Some(status) = child.try_wait().expect("the forwarder can be waited on") {
            break (status.code(), Some(started.elapsed()));
        }
        if started.elapsed() >= SHORTEST_TIMEOUT {
            // This test's own child, which it has not collected, so the number is still its.
            let _ = child.kill();
            let _ = child.wait();
            break (None, None);
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    Held {
        answer: reading.join().expect("the output is read"),
        answered,
        code,
        exited,
    }
}

/// Fills a pipe until it takes nothing more, and leaves its writing end blocking again, as the
/// standard error a hook is given would be.
#[cfg(unix)]
fn fill(pipe: &std::io::PipeWriter) {
    use std::io::Write as _;

    rustix::io::ioctl_fionbio(pipe, true).expect("a pipe that says when it is full");
    let mut writer = pipe;
    // Whole pages first, then single bytes, so no room is left that one short line could take.
    for size in [4096_usize, 1] {
        let bytes = vec![b'.'; size];
        loop {
            match writer.write(&bytes) {
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => panic!("the pipe could not be filled: {error}"),
            }
        }
    }
    rustix::io::ioctl_fionbio(pipe, false).expect("the pipe blocks again");
}
