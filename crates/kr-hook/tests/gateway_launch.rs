//! `kr-hook launch` against a backend that runs an application server, with the real worker
//! pieces and a stand-in for the application.
//!
//! This test process plays the root shell, as in the launcher's other suite: it establishes the
//! backend the way a session does, and starts the launcher as its child with the answer's
//! variable. The application is the Codex stand-in (`tests/support/codex-stand-in`), one program
//! that is the server when it is started with `app-server --listen stdio://` and the terminal
//! when it is started with `--remote unix://PATH`, and checks every frame either side writes
//! against the schemas of the release it stands for. The session is a real one, with a journal
//! on disk, so the server is recorded as a root of what it owns. Build the stand-in before a
//! package-scoped run (`cargo build -p kr-codex-stand-in`); a run of the workspace builds it.

#![cfg(unix)]

mod common;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::LIVENESS;
use common::gateway::{COMMAND, Gateway, STUBBORN, directory_of, eventually};
use kr_protocol::identity::ProcessStartIdentity;

/// KR-REQ-12.07 and KR-REQ-07.67: a plain launch of a terminal whose package declares a server is
/// served by a gateway: the server is started in a group of its own and recorded as a root of what
/// the session owns before the program runs, the program connects to the socket the launch named
/// and runs its whole session through it, the instance is a gateway's, and when the program ends
/// the server and the instance end with it.
#[test]
fn kr_req_12_07_a_plain_launch_of_a_terminal_with_a_server_is_served_by_a_gateway() {
    let shell = Gateway::new();
    let answer = shell
        .establish(&["codex"])
        .expect("a backend is established");
    let directory = PathBuf::from(&answer.environment[0].value)
        .parent()
        .expect("the backend's directory")
        .to_path_buf();
    let record = std::fs::read_to_string(directory.join("launch")).expect("the launch record");
    assert!(
        record.contains(&format!("unix://{}", directory.join("gw.sock").display())),
        "the launch record names the gateway's socket: {record}"
    );

    let mut launched = shell.launch(
        &answer,
        "plain",
        &[("KR_STAND_IN", "stay"), ("KR_STAND_IN_COMMAND", COMMAND)],
    );
    // The program's whole session runs through the gateway: it signs in, starts a turn, is asked
    // to approve a command, and the turn completes.
    launched.prints("TUI: the server asks for item/commandExecution/requestApproval");
    launched.prints("TUI: turn/completed");

    // And this is what it ran through: one server, recorded, in a group of its own, running.
    let servers = shell.servers();
    assert_eq!(servers.len(), 1, "{servers:?}");
    let server = servers[0].clone();
    assert_eq!(
        kr_ipc::identity::process_state(&server),
        kr_ipc::identity::ProcessState::Running
    );
    let started = shell.announcement();
    assert_eq!(
        started.instance.mode,
        kr_protocol::broker::IntegrationMode::Gateway
    );

    // The program ends, and the server and the instance end with it.
    let _ = launched.child.kill();
    let _ = launched.ends();
    eventually("the server ended with the program", || {
        kr_ipc::identity::process_state(&server) == kr_ipc::identity::ProcessState::Ended
    });
    let ended = shell.announcement();
    assert!(ended.instance.ended_at.is_present(), "{ended:?}");
}

/// KR-REQ-11.32: only the process the launch registered reaches the gateway, and an upgrade a
/// browser could have sent does not use the admission: another process that speaks a plain upgrade
/// to the socket, while the program has become the terminal and not yet connected, is closed
/// without a word, and the program whose first upgrade is refused for its `Origin` header connects
/// again and runs its whole session.
#[test]
fn kr_req_11_32_only_the_registered_process_reaches_the_gateway() {
    let shell = Gateway::new();
    let answer = shell
        .establish(&["codex"])
        .expect("a backend is established");
    let socket = directory_of(&answer).join("gw.sock");
    let release = shell.placed.host.root().join("connect");
    let (arrived, go) = shell.backends.pause_before_confirming();
    let mut launched = shell.launch(
        &answer,
        "second",
        &[
            ("KR_STAND_IN", "origin,retry-plain,wait-to-connect"),
            ("KR_STAND_IN_COMMAND", COMMAND),
            (
                "KR_STAND_IN_RELEASE",
                release.to_str().expect("a text path"),
            ),
        ],
    );
    // The launch is committed, and the launcher is not yet told: the socket is bound already.
    shell.at_the_confirmation(arrived);
    drop(
        std::os::unix::net::UnixStream::connect(&socket)
            .expect("the socket is bound before the launcher is told"),
    );
    go.send(()).expect("the launch waits");
    // The launcher has become the terminal, which has not connected: it
    // is the registered process, and it runs the code that was hashed, so what keeps another
    // process out is that it is another process.
    launched.prints("TUI: waiting to connect");
    let mut other = std::os::unix::net::UnixStream::connect(&socket).expect("the socket is bound");
    other
        .set_read_timeout(Some(LIVENESS))
        .expect("a read timeout");
    // Closed without a word: the end of the stream, or, where a stream that is closed with unread
    // bytes resets its peer, a reset at the read, or a broken pipe at the write when the close came
    // first. The read follows a write that failed too, because a reply sent before the close stays
    // readable: a word is a reply, and a held connection is a timeout.
    let ended = |error: &std::io::Error| {
        matches!(
            error.kind(),
            std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe
        )
    };
    if let Err(error) = std::io::Write::write_all(
        &mut other,
        b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\
          Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
    ) {
        assert!(ended(&error), "the request could not be written: {error}");
    }
    let mut heard = [0_u8; 16];
    let closed_without_a_word = match std::io::Read::read(&mut other, &mut heard) {
        Ok(read) => read == 0,
        Err(error) => ended(&error),
    };
    assert!(
        closed_without_a_word,
        "another process is closed without a word, though its upgrade is a plain one"
    );
    std::fs::write(&release, b"go").expect("the terminal is released");

    launched.prints("TUI: turn/completed");
    assert!(launched.ends().success());
    assert!(
        launched.printed().contains("did not upgrade"),
        "the first upgrade was refused: {}",
        launched.printed()
    );
}

/// KR-REQ-12.07: a launch whose executable no signed record names, or whose server cannot be
/// started, runs the program as typed: it gets no flag, no server is started and nothing of the
/// launch is left published.
#[test]
fn kr_req_12_07_a_launch_that_cannot_have_a_server_runs_the_program_as_typed() {
    for case in ["no record names the executable", "the directory is gone"] {
        let shell = Gateway::with(case != "no record names the executable", "");
        let work = shell.placed.host.root().join("work");
        std::fs::create_dir_all(&work).expect("a working directory");
        let answer = shell
            .establish_in(&["codex"], &work)
            .expect("a backend is established");
        if case == "the directory is gone" {
            std::fs::remove_dir(&work).expect("the directory is removed");
        }
        let registration = PathBuf::from(&answer.environment[0].value);
        let mut launched = shell.launch(&answer, "typed", &[]);
        // Run as typed, the stand-in is started with no arguments and says what it serves.
        let status = launched.ends();
        assert_eq!(status.code(), Some(2), "{case}: {}", launched.said());
        assert!(
            launched.said().contains("serves `app-server"),
            "{case}: it ran with the arguments it was typed with"
        );
        assert!(shell.servers().is_empty(), "{case}: no server was started");
        assert!(
            !registration.exists(),
            "{case}: the registration was taken back"
        );
        assert!(
            shell.broker.live_bindings().is_empty(),
            "{case}: and so was the binding"
        );
    }
}

/// KR-REQ-12.07: a launcher whose environment a backend cannot be shown, because it holds more
/// than a backend takes or a variable that is not text, runs the program as typed, and no server
/// is started for it.
#[test]
fn kr_req_12_07_an_environment_that_cannot_be_presented_runs_the_program_as_typed() {
    use std::os::unix::ffi::OsStrExt as _;

    let filler: Vec<(String, String)> = (0..40)
        .map(|number| (format!("KR_FILLER_{number}"), "x".repeat(8000)))
        .collect();
    let oversize: Vec<(&std::ffi::OsStr, &std::ffi::OsStr)> = filler
        .iter()
        .map(|(variable, value)| (variable.as_ref(), value.as_ref()))
        .collect();
    let not_text = [(
        std::ffi::OsStr::new("KR_NOT_TEXT"),
        std::ffi::OsStr::from_bytes(b"\xff\xfe"),
    )];
    for (case, own) in [
        ("more than a backend takes", &oversize[..]),
        ("a variable that is not text", &not_text[..]),
    ] {
        let shell = Gateway::new();
        let answer = shell
            .establish(&["codex"])
            .expect("a backend is established");
        let mut launched = shell.launch_with(&answer, "environment", own);
        let status = launched.ends();
        assert_eq!(status.code(), Some(2), "{case}: {}", launched.said());
        assert!(
            launched.said().contains("serves `app-server"),
            "{case}: it ran with the arguments it was typed with"
        );
        assert!(shell.servers().is_empty(), "{case}: no server was started");
    }
}

/// KR-REQ-07.60: a server whose record cannot be written is not left running: a daemon could not
/// stop it after this worker, so the launch is given back and the program runs as typed.
#[test]
fn kr_req_07_60_a_server_whose_record_cannot_be_written_is_not_left_running() {
    let shell = Gateway::new();
    shell.view.runtime.session().refuse_owned_writes();
    let answer = shell
        .establish(&["codex"])
        .expect("a backend is established");
    let mut launched = shell.launch(&answer, "unrecorded", &[]);
    let status = launched.ends();
    assert_eq!(status.code(), Some(2), "{}", launched.said());
    assert!(
        launched.said().contains("serves `app-server"),
        "the program ran with the arguments it was typed with"
    );
    // The server was started and recorded in memory before the record was found unwritten; it is
    // ended, and then forgotten.
    eventually("no server is left running", || {
        shell.servers().iter().all(|server| {
            kr_ipc::identity::process_state(server) == kr_ipc::identity::ProcessState::Ended
        })
    });
}

/// KR-REQ-12.13, KR-REQ-11.27 and KR-REQ-11.33: an approval the server asks the terminal for is an
/// opaque pending resource of the program's instance before the terminal answers it, and the
/// terminal's answer resolves it once, whether the server's request carries an identifier of its
/// own or the one the terminal's request to start a turn carries.
#[test]
fn kr_req_12_13_an_approval_is_a_pending_resource_before_the_terminal_answers_and_resolved_once() {
    for (case, variants) in [
        ("its own identifier", "stay,answer-when-released"),
        (
            "the identifier of the terminal's own request",
            "stay,answer-when-released,colliding-ids",
        ),
    ] {
        let shell = Gateway::new();
        let answer = shell
            .establish(&["codex"])
            .expect("a backend is established");
        let release = shell.placed.host.root().join("answer");
        let mut launched = shell.launch(
            &answer,
            "approval",
            &[
                ("KR_STAND_IN", variants),
                ("KR_STAND_IN_COMMAND", COMMAND),
                (
                    "KR_STAND_IN_RELEASE",
                    release.to_str().expect("a text path"),
                ),
            ],
        );
        launched.prints("TUI: the server asks for item/commandExecution/requestApproval");
        let instance = shell.announcement().instance.application_instance_id;
        // The terminal has read the request and not answered it: the broker holds it already, as a
        // request it does not interpret.
        let pending = shell.broker.pending_resources();
        assert_eq!(pending.len(), 1, "{case}: {pending:?}");
        let resource = pending[0].clone();
        assert_eq!(resource.application_instance_id, instance, "{case}");
        assert_eq!(resource.state, kr_protocol::gateway::PendingState::Pending);
        assert!(!resource.interpretation_verified, "{case}: opaque");
        assert_eq!(
            resource.method.as_str(),
            "item/commandExecution/requestApproval"
        );

        std::fs::write(&release, b"answer").expect("the terminal is released");
        launched.prints("TUI: turn/completed");
        eventually(&format!("{case}: the answer resolved the resource"), || {
            shell
                .broker
                .pending(resource.resource_id)
                .is_some_and(|held| held.state == kr_protocol::gateway::PendingState::Resolved)
        });
        assert_eq!(
            shell.broker.pending_resources().len(),
            1,
            "{case}: one request, one resource"
        );
    }
}

/// KR-REQ-11.32: a message at the connector's limit, which the host lowers from the package's
/// larger statement to its own 1 MiB, is carried both ways through the gateway: the terminal's
/// request to start a turn, and the server's notification of what the agent said.
#[test]
fn kr_req_11_32_a_message_at_the_limit_is_carried_both_ways_through_a_gateway() {
    let shell = Gateway::new();
    let answer = shell
        .establish(&["codex"])
        .expect("a backend is established");
    let mut launched = shell.launch(
        &answer,
        "limit",
        &[("KR_STAND_IN", "stay"), ("KR_STAND_IN_PAD", "1048576")],
    );
    launched.prints("TUI: item/agentMessage/delta");
    launched.prints("TUI: the server asks for item/commandExecution/requestApproval");
}

/// KR-REQ-11.32: a message above the limit ends the connection, and with it the server: the
/// terminal is told the connection is gone and the server is ended.
#[test]
fn kr_req_11_32_a_message_above_the_limit_ends_the_connection_and_the_server() {
    let shell = Gateway::new();
    let answer = shell
        .establish(&["codex"])
        .expect("a backend is established");
    let mut launched = shell.launch(
        &answer,
        "over",
        &[("KR_STAND_IN", "stay"), ("KR_STAND_IN_PAD", "1048577")],
    );
    assert_eq!(launched.ends().code(), Some(1), "{}", launched.printed());
    assert!(
        launched.printed().contains("Error: remote app server"),
        "the terminal was told the connection was gone: {}",
        launched.printed()
    );
    let servers = shell.servers();
    eventually("the server ended with the connection", || {
        servers.iter().all(|server| {
            kr_ipc::identity::process_state(server) == kr_ipc::identity::ProcessState::Ended
        })
    });
}

/// KR-REQ-11.32: a terminal that stops reading, as one that is stopped does, loses its connection
/// when a message cannot reach it, and the server it was served by ends; the terminal itself is
/// left alone.
#[test]
fn kr_req_11_32_a_terminal_that_stops_reading_loses_its_connection_and_its_server_ends() {
    let shell = Gateway::new();
    let answer = shell
        .establish(&["codex"])
        .expect("a backend is established");
    let mut launched = shell.launch(
        &answer,
        "stopped",
        &[
            ("KR_STAND_IN", "stop-reading"),
            ("KR_STAND_IN_PAD", "1048576"),
        ],
    );
    launched.prints("TUI: a turn is running");
    let servers = shell.servers();
    assert_eq!(servers.len(), 1, "{servers:?}");
    eventually("the server ended with the connection", || {
        kr_ipc::identity::process_state(&servers[0]) == kr_ipc::identity::ProcessState::Ended
    });
    assert!(
        launched.child.try_wait().expect("readable").is_none(),
        "the stopped terminal is left alone"
    );
}

/// KR-REQ-12.07: a backend whose runtime directory has a space in its name is served as any other:
/// the address the launcher writes is one element of the program's arguments, and the session runs.
#[test]
fn kr_req_12_07_a_runtime_directory_with_a_space_is_served_as_any_other() {
    let shell = Gateway::with(true, "with space");
    let answer = shell
        .establish(&["codex"])
        .expect("a backend is established");
    let socket = directory_of(&answer).join("gw.sock");
    assert!(
        socket.to_string_lossy().contains("with space"),
        "{socket:?}"
    );
    let mut launched = shell.launch(&answer, "spaced", &[("KR_STAND_IN", "stay")]);
    launched.prints("TUI: turn/completed");
}

/// KR-REQ-11.33: the key a terminal signs in with is forwarded to the server, so that signing in
/// works, and is kept nowhere: not in the broker's resources, and not in a byte of what the
/// session wrote to disk, its ledger included.
#[test]
fn kr_req_11_33_a_credential_a_terminal_signs_in_with_is_kept_nowhere() {
    const KEY: &str = "sk-SECRET-LOGIN-KEY-5c1d9e";
    let shell = Gateway::with_ledger_on_disk();
    let answer = shell
        .establish(&["codex"])
        .expect("a backend is established");
    let mut launched = shell.launch(
        &answer,
        "login",
        &[
            ("KR_STAND_IN", "stay,login"),
            ("KR_STAND_IN_COMMAND", COMMAND),
            ("KR_STAND_IN_API_KEY", KEY),
        ],
    );
    // The server answered the sign-in, so the request reached it, and the session went on.
    launched.prints("TUI: the sign-in was refused; the stand-in goes on");
    launched.prints("TUI: turn/completed");
    let instance = shell.announcement().instance.application_instance_id;
    let intents = shell.broker.client_requests().expect("the records read");
    let kept = |name: &str| {
        let intent = intents
            .iter()
            .find(|intent| intent.method.as_str().contains(name))
            .unwrap_or_else(|| panic!("the {name} request was recorded: {intents:?}"));
        shell.broker.source(instance, &intent.source).is_some()
    };
    assert!(
        kept("turn"),
        "the control: an ordinary request's bytes are retained as a source event"
    );
    assert!(
        !kept("login"),
        "the sign-in request, which carries the key, is retained nowhere"
    );
    let snapshot = format!(
        "{:?} {:?}",
        shell.broker.resource_snapshot(),
        shell.broker.pending_resources()
    );
    assert!(
        !snapshot.contains(KEY),
        "the broker's resources hold the key"
    );
    let _ = launched.child.kill();
    let _ = launched.ends();
    let mut searched = 0_usize;
    let mut directories = vec![shell.placed.host.root().to_path_buf()];
    while let Some(directory) = directories.pop() {
        for entry in std::fs::read_dir(&directory)
            .into_iter()
            .flatten()
            .flatten()
        {
            let path = entry.path();
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            if kind.is_dir() {
                directories.push(path);
            } else if kind.is_file() {
                let bytes = std::fs::read(&path).unwrap_or_default();
                searched += 1;
                assert!(
                    !bytes
                        .windows(KEY.len())
                        .any(|window| window == KEY.as_bytes()),
                    "{} holds the key",
                    path.display()
                );
            }
        }
    }
    assert!(searched > 0, "something was searched");
    assert!(
        shell
            .placed
            .host
            .root()
            .join("broker-ledger.sqlite")
            .is_file(),
        "and the ledger was among it"
    );
}

/// KR-REQ-11.35: a fault in the broker's ledger in the middle of live traffic does not stop the
/// terminal's session: the terminal's answer to an approval still reaches the server and the turn
/// completes, the gateway reads `native_only_volatile` with the gap open, and rich work is refused
/// as unavailable rather than carried out without a record.
#[test]
fn kr_req_11_35_a_ledger_fault_in_live_traffic_keeps_the_session_and_fences_rich_work() {
    use kr_protocol::gateway::GatewayMode;

    let shell = Gateway::with_ledger_on_disk();
    let answer = shell
        .establish(&["codex"])
        .expect("a backend is established");
    let release = shell.placed.host.root().join("answer");
    let mut launched = shell.launch(
        &answer,
        "fault",
        &[
            ("KR_STAND_IN", "stay,answer-when-released"),
            ("KR_STAND_IN_COMMAND", COMMAND),
            (
                "KR_STAND_IN_RELEASE",
                release.to_str().expect("a text path"),
            ),
        ],
    );
    launched.prints("TUI: the server asks for item/commandExecution/requestApproval");
    assert_eq!(shell.broker.mode(), GatewayMode::Normal, "healthy before");
    assert!(shell.broker.gap().is_none());
    shell
        .broker
        .refuse_ledger_writes(true)
        .expect("the ledger stops taking writes");

    // The terminal answers, and the session goes on to its end.
    std::fs::write(&release, b"answer").expect("the terminal is released");
    launched.prints("TUI: turn/completed");
    assert_eq!(shell.broker.mode(), GatewayMode::NativeOnlyVolatile);
    let gap = shell.broker.gap().expect("the gap is open");
    assert!(gap.is_open(), "{gap:?}");
    assert!(
        gap.native_responses.get() >= 1,
        "the answer was arbitrated in memory: {gap:?}"
    );
    let fenced = shell
        .broker
        .require_rich_work()
        .expect_err("rich work is fenced");
    assert_eq!(
        fenced.code(),
        kr_protocol::error::ErrorCode::UpstreamUnavailable
    );
}

/// KR-REQ-07.60: a program that was started and never connects, as one that ran as typed does not,
/// ends the instance and the server at the bound, and the program is left to run.
#[test]
fn kr_req_07_60_a_program_that_never_connects_ends_its_instance_and_server_at_the_bound() {
    let shell = Gateway::new();
    shell.backends.connect_within(Duration::from_secs(5));
    let answer = shell
        .establish(&["codex"])
        .expect("a backend is established");
    // The server is read at the commit, before the bound begins to run.
    let (arrived, go) = shell.backends.pause_before_committing();
    let mut launched = shell.launch(&answer, "idle", &[("KR_STAND_IN", "idle")]);
    shell.at_the_confirmation(arrived);
    let servers = shell.servers();
    assert_eq!(servers.len(), 1, "the server was started and recorded");
    go.send(()).expect("the launch waits");
    let started = shell.announcement();
    assert_eq!(
        started.instance.mode,
        kr_protocol::broker::IntegrationMode::Gateway
    );
    let ended = shell.announcement();
    assert!(ended.instance.ended_at.is_present(), "{ended:?}");
    eventually("the server ended at the bound", || {
        kr_ipc::identity::process_state(&servers[0]) == kr_ipc::identity::ProcessState::Ended
    });
    assert!(
        launched.child.try_wait().expect("readable").is_none(),
        "and the program that never connected is left running"
    );
}

/// KR-REQ-12.07: a launch lost to a retirement between the server being started and the commit
/// runs the program as typed, and the closure that retired the backend ends its server.
#[test]
fn kr_req_12_07_a_launch_lost_to_a_retirement_ends_its_server() {
    let shell = Gateway::new();
    let answer = shell
        .establish(&["codex"])
        .expect("a backend is established");
    let (arrived, release) = shell.backends.pause_before_committing();
    let mut launched = shell.launch(&answer, "lost", &[]);
    shell.at_the_confirmation(arrived);
    let servers = shell.servers();
    assert_eq!(servers.len(), 1, "the server was started before the commit");
    let _ = shell.backends.close();
    // The retirement ends the admission wherever it is, the pause with it, so there may be nobody
    // left to let go; the launch is abandoned either way.
    let _ = release.send(());
    assert_eq!(launched.ends().code(), Some(2), "the program ran as typed");
    // The server belongs to the closure now, which ends it once the acceptance is delivered.
    let _entered = shell.runtime.enter();
    shell
        .runtime
        .block_on(shell.backends.end_servers(tokio::time::Instant::now()));
    eventually("the server ended", || {
        kr_ipc::identity::process_state(&servers[0]) == kr_ipc::identity::ProcessState::Ended
    });
}

/// KR-REQ-12.07: a close ends a backend's instance before it takes down what the backend
/// published, so whoever finds the registration gone finds nothing of the launch held.
#[test]
fn kr_req_12_07_a_close_ends_the_instance_before_it_takes_down_the_registration() {
    let shell = Gateway::new();
    let answer = shell
        .establish(&["codex"])
        .expect("a backend is established");
    let registration = PathBuf::from(&answer.environment[0].value);
    let mut launched = shell.launch(
        &answer,
        "closing",
        &[("KR_STAND_IN", "stay"), ("KR_STAND_IN_COMMAND", COMMAND)],
    );
    launched.prints("TUI: turn/completed");
    let instance = shell.announcement().instance.application_instance_id;
    assert!(shell.broker.binding_state(instance).is_ok(), "bound");
    assert!(registration.exists(), "published");
    let (arrived, go_on) = shell.backends.pause_before_removing_files();
    let backends = Arc::clone(&shell.backends);
    let closing = std::thread::spawn(move || backends.close());
    arrived
        .recv_timeout(LIVENESS)
        .expect("the close reaches the files");
    assert!(
        shell.broker.binding_state(instance).is_err(),
        "the instance and its bindings are gone before anything is taken down"
    );
    assert!(registration.exists(), "and the registration is still there");
    go_on.send(()).expect("the close goes on");
    let _ = closing.join().expect("the close finishes");
    assert!(!registration.exists(), "and then it is taken down");
}

/// KR-REQ-07.60: a session's closure ends the server of a backend after the acceptance of the close
/// is delivered, and what the server started with it. The requester of a close may be a command the
/// server started, so that command is still running when the acceptance is delivered, though the
/// terminal sends a request after the close is admitted and so loses its connection: here the
/// command waits for the test to say the acceptance is out, and shows it was alive. Then the gate
/// is released, and when the closure is over the server and the command have ended, the server
/// among the processes the closure names as terminated.
#[test]
fn kr_req_07_60_a_close_ends_the_server_and_what_it_started_after_the_acceptance() {
    let shell = Gateway::new();
    let answer = shell
        .establish(&["codex"])
        .expect("a backend is established");
    let delivered = shell.placed.host.root().join("delivered");
    let alive = shell.placed.host.root().join("alive");
    // A command that waits for the acceptance to be delivered and then says it was alive.
    let requester = serde_json::json!([
        "/bin/sh",
        "-c",
        "while [ ! -e \"$0\" ]; do sleep 0.25; done; : > \"$1\"; sleep 120",
        delivered,
        alive
    ])
    .to_string();
    let ask = shell.placed.host.root().join("ask");
    let speak = shell.placed.host.root().join("speak");
    let mut launched = shell.launch(
        &answer,
        "closure",
        &[
            (
                "KR_STAND_IN",
                "stay,request-when-released,write-when-released",
            ),
            ("KR_STAND_IN_COMMAND", &requester),
            ("KR_STAND_IN_RELEASE", ask.to_str().expect("a text path")),
            ("KR_STAND_IN_SPEAK", speak.to_str().expect("a text path")),
        ],
    );
    launched.prints("TUI: turn/completed");
    eventually("the session recorded what the server started", || {
        !shell.started_by_servers().is_empty()
    });
    let server = shell.servers().remove(0);
    let started = shell.started_by_servers();
    let _entered = shell.runtime.enter();
    let (acceptance, gate) = shell
        .view
        .runtime
        .close(kr_protocol::session::ClosureReason::CloseRequested);
    assert!(acceptance.initiated);
    // The terminal asks something of the server while the close waits for its acceptance to be
    // delivered. The instance is gone, so the host cannot carry the request and ends the
    // connection, and the terminal with it; the server is not the connection's to end.
    std::fs::write(&ask, b"ask").expect("the terminal is released");
    let status = launched.ends();
    assert_eq!(status.code(), Some(1), "{}", launched.printed());
    // The server writes now, with nobody to carry what it says. Its write has to go, or it would
    // end its commands; the file beside the one that released it says it did.
    std::fs::write(&speak, b"speak").expect("the server is released");
    let spoke = shell.placed.host.root().join("speak.spoke");
    eventually("the server wrote", || spoke.exists());
    assert_eq!(
        std::fs::read_to_string(&spoke).expect("what the server said"),
        "wrote",
        "the server's write failed, so it ended its commands"
    );
    // The acceptance is delivered, and the command that asked for the close is still there to read
    // it: nothing has been signalled.
    std::fs::write(&delivered, b"delivered").expect("the acceptance is delivered");
    eventually(
        "the command was alive when the acceptance was delivered",
        || alive.exists(),
    );
    gate.release();
    let closure = shell
        .runtime
        .block_on(async { tokio::time::timeout(LIVENESS, shell.view.runtime.wait_closed()).await })
        .expect("the session closes");
    for process in std::iter::once(&server).chain(&started) {
        assert_eq!(
            kr_ipc::identity::process_state(process),
            kr_ipc::identity::ProcessState::Ended,
            "{process:?} ended with the session"
        );
    }
    assert!(
        closure
            .terminated
            .iter()
            .any(|terminated| terminated.identity == server && !terminated.forced),
        "the closure names the server, ended without force: {:?}",
        closure.terminated
    );
}

/// KR-REQ-07.60 and KR-REQ-07.53: a server that ignores both the end of its input and a terminate,
/// with a command that ignores a terminate too, is ended by force with the command when the program
/// ends, and neither is forced before five seconds after the program's end began the ending. Each
/// is watched from the moment the program is killed, so a command forced early is seen to be.
#[test]
fn kr_req_07_60_a_stubborn_server_and_its_command_end_by_force_with_the_program() {
    let shell = Gateway::new();
    let answer = shell
        .establish(&["codex"])
        .expect("a backend is established");
    let mut launched = shell.launch(
        &answer,
        "stubborn",
        &[
            ("KR_STAND_IN", "stay,ignore-eof,ignore-term"),
            ("KR_STAND_IN_COMMAND", STUBBORN),
        ],
    );
    launched.prints("TUI: turn/completed");
    // The command is recorded below the server while it runs, and has started a process of its own,
    // which a shell does once it has set up what it ignores: the frames the session carried had it
    // look.
    eventually("the session recorded what the server started", || {
        shell.started_by_servers().len() >= 2
    });
    let server = shell.servers().remove(0);
    let started = shell.started_by_servers();
    let processes: Vec<ProcessStartIdentity> = std::iter::once(server).chain(started).collect();
    let killed = Instant::now();
    let watching = {
        let processes = processes.clone();
        std::thread::spawn(move || {
            let mut seen: Vec<Option<Duration>> = vec![None; processes.len()];
            while seen.iter().any(Option::is_none) && killed.elapsed() < LIVENESS {
                for (process, at) in processes.iter().zip(seen.iter_mut()) {
                    if at.is_none()
                        && kr_ipc::identity::process_state(process)
                            == kr_ipc::identity::ProcessState::Ended
                    {
                        *at = Some(killed.elapsed());
                    }
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            seen
        })
    };
    let _ = launched.child.kill();
    let _ = launched.ends();
    let seen = watching.join().expect("the watch is joined");
    for (process, went) in processes.iter().zip(seen) {
        let went = went.unwrap_or_else(|| panic!("{process:?} ended with the program"));
        assert!(
            went >= Duration::from_secs(5),
            "{process:?} was forced {went:?} after the program was killed"
        );
    }
}

/// KR-REQ-07.61: what the server starts for the program belongs to the program's instance: a
/// process below the server is placed under it, and a process outside the session is placed under
/// no instance.
#[test]
fn kr_req_07_61_a_process_the_server_started_is_placed_under_the_programs_instance() {
    use kr_worker::questions::binding::{AgentBindings as _, AgentPlacement};

    let shell = Gateway::new();
    let answer = shell
        .establish(&["codex"])
        .expect("a backend is established");
    let mut launched = shell.launch(
        &answer,
        "placed",
        &[("KR_STAND_IN", "stay"), ("KR_STAND_IN_COMMAND", COMMAND)],
    );
    launched.prints("TUI: turn/completed");
    let instance = shell.announcement().instance.application_instance_id;
    eventually("the session recorded what the server started", || {
        !shell.started_by_servers().is_empty()
    });
    for process in shell.started_by_servers() {
        match shell.broker.binding_of(&process) {
            AgentPlacement::Bound(binding) => {
                assert_eq!(binding.application_instance_id, instance);
            }
            other => panic!("{process:?} is below the server, and is placed {other:?}"),
        }
    }
    let outside = kr_ipc::identity::current_process_start_identity().expect("this process");
    assert_eq!(
        shell.broker.binding_of(&outside),
        AgentPlacement::Unbound,
        "a process outside the session is under no instance"
    );
}

/// KR-REQ-07.60: a server that dies first, leaving its command running, leaves nothing: the
/// command was recorded while the server ran, and the program's end finds it.
#[test]
fn kr_req_07_60_a_server_that_dies_first_leaves_no_command_behind() {
    let shell = Gateway::new();
    let answer = shell
        .establish(&["codex"])
        .expect("a backend is established");
    let release = shell.placed.host.root().join("release");
    let mut launched = shell.launch(
        &answer,
        "dies",
        &[
            ("KR_STAND_IN", "die-first,answer-when-released"),
            ("KR_STAND_IN_COMMAND", COMMAND),
            (
                "KR_STAND_IN_RELEASE",
                release.to_str().expect("a text path"),
            ),
        ],
    );
    launched.prints("TUI: the server asks for item/commandExecution/requestApproval");
    eventually("the session recorded what the server started", || {
        !shell.started_by_servers().is_empty()
    });
    let started = shell.started_by_servers();
    std::fs::write(&release, b"go").expect("the terminal is released");
    // The server dies as the approval is answered, with its command running; the program loses its
    // connection and leaves with an error.
    assert_eq!(launched.ends().code(), Some(1), "{}", launched.printed());
    for process in &started {
        eventually("what the server started was ended", || {
            kr_ipc::identity::process_state(process) == kr_ipc::identity::ProcessState::Ended
        });
    }
}
