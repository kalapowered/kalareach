//! The stand-in runs on Windows as well as on Unix: its server answers `initialize` on standard
//! input and output, and its terminal reaches a socket a host bound, where the kernel names the
//! terminal as the connecting process.
//!
//! These cases carry no platform gate. Where the program is not built for the platform it says so
//! and ends, and each case fails by showing what it said.

use std::process::Stdio;
use std::time::Duration;

use serde_json::json;
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::process::Command;
use tokio_websockets::ServerBuilder;

mod common;

use common::Gateway;

const PROGRAM: &str = env!("CARGO_BIN_EXE_codex-stand-in");

/// A binary that was just built can take the system most of a minute to start the first time.
const WAIT: Duration = Duration::from_secs(180);

/// The server answers the `initialize` request a client opens a session with.
#[tokio::test]
async fn the_stand_in_answers_initialize_on_windows() {
    let mut server = Command::new(PROGRAM);
    server
        .args(["app-server", "--listen", "stdio://"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut server = server.spawn().expect("the server starts");
    let mut stdin = server.stdin.take().expect("stdin");
    let mut lines = BufReader::new(server.stdout.take().expect("stdout")).lines();
    let mut stderr = server.stderr.take().expect("stderr");

    let request = json!({"id":"initialize","method":"initialize","params":{
        "clientInfo":{"name":"test","title":null,"version":"0"},
        "capabilities":{"experimentalApi":true,"requestAttestation":false,"optOutNotificationMethods":null}}});
    // The program may end before it reads the request: a failed write is read as the program's end.
    let _ = stdin.write_all(format!("{request}\n").as_bytes()).await;
    let line = tokio::time::timeout(WAIT, lines.next_line())
        .await
        .expect("the server writes")
        .expect("it is readable");
    let Some(line) = line else {
        let mut said = String::new();
        let _ = stderr.read_to_string(&mut said).await;
        panic!("the server ended without answering `initialize`; it said: {said}");
    };
    let answer: serde_json::Value = serde_json::from_str(&line).expect("a frame");
    assert_eq!(answer["id"], "initialize", "{line}");
    assert!(answer["result"].is_object(), "{line}");
}

/// The terminal connects to a socket the host bound, and the kernel names the terminal's own
/// process as the one that connected: the host reads no claim the terminal makes.
#[tokio::test]
async fn the_ported_terminal_reads_a_bound_sockets_peer_pid() {
    let gateway = Gateway::bind("smoke");
    let mut terminal = Command::new(PROGRAM);
    terminal
        .arg("--remote")
        .arg(format!("unix://{}", gateway.socket()))
        .arg("hello")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut terminal = terminal.spawn().expect("the terminal starts");
    let started = u64::from(terminal.id().expect("the terminal is running"));

    let connected = tokio::select! {
        connected = gateway.accept() => connected,
        () = tokio::time::sleep(WAIT) => {
            panic!("the terminal did not connect: {}", ended(&mut terminal).await)
        }
        status = terminal.wait() => {
            panic!(
                "the terminal ended with {status:?} before it connected: {}",
                said(&mut terminal).await
            )
        }
    };
    assert_eq!(connected.pid, started, "the kernel names the terminal");

    let (request, _connection) = ServerBuilder::new()
        .accept(connected.stream)
        .await
        .expect("the upgrade");
    assert_eq!(request.uri().path(), "/rpc");
}

/// What the terminal had said when it was ended, for a failure's message.
async fn ended(terminal: &mut tokio::process::Child) -> String {
    let _ = terminal.start_kill();
    said(terminal).await
}

async fn said(terminal: &mut tokio::process::Child) -> String {
    let mut text = String::new();
    if let Some(mut stderr) = terminal.stderr.take() {
        let _ =
            tokio::time::timeout(Duration::from_secs(5), stderr.read_to_string(&mut text)).await;
    }
    text
}
