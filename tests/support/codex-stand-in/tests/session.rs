//! The stand-in speaks the pinned release's protocol on both sides.
//!
//! The server is driven over pipes, the terminal against a gateway the test plays: it accepts the
//! terminal's WebSocket and relays each message to and from a server of the stand-in's own, or
//! sends the terminal frames of its own making.

#![cfg(unix)]

use std::process::Stdio;
use std::time::Duration;

use futures_util::{SinkExt as _, StreamExt as _};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::process::{Child, ChildStdin, Command};
use tokio_websockets::{Message, ServerBuilder};

const PROGRAM: &str = env!("CARGO_BIN_EXE_codex-stand-in");

/// A binary that was just built can take the system most of a minute to start the first time.
const WAIT: Duration = Duration::from_secs(180);

/// The command the server starts: a shell that starts a process of its own and waits for it.
const COMMAND: &str = r#"["/bin/sh", "-c", "sleep 120 & wait"]"#;

fn server(variants: &str, command: Option<&str>) -> Child {
    let mut server = Command::new(PROGRAM);
    server
        .args(["app-server", "--listen", "stdio://"])
        .env("KR_STAND_IN", variants)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    if let Some(command) = command {
        server.env("KR_STAND_IN_COMMAND", command);
    }
    server.spawn().expect("the server starts")
}

async fn write(stdin: &mut ChildStdin, frame: &Value) {
    stdin
        .write_all(format!("{frame}\n").as_bytes())
        .await
        .expect("the server reads");
}

async fn next<R: tokio::io::AsyncBufRead + Unpin>(lines: &mut tokio::io::Lines<R>) -> Value {
    let line = tokio::time::timeout(WAIT, lines.next_line())
        .await
        .expect("the server writes")
        .expect("it is readable")
        .expect("it has not ended");
    serde_json::from_str(&line).expect("a frame")
}

fn initialize() -> Value {
    json!({"id":"initialize","method":"initialize","params":{
        "clientInfo":{"name":"test","title":null,"version":"0"},
        "capabilities":{"experimentalApi":true,"requestAttestation":false,"optOutNotificationMethods":null}}})
}

fn turn_request(thread: &str) -> Value {
    json!({"id":3,"method":"turn/start","params":{
        "threadId":thread,"input":[{"type":"text","text":"go","text_elements":[]}]}})
}

fn status_of(command: &str, arguments: &[&str]) -> Option<String> {
    let output = std::process::Command::new(command)
        .args(arguments)
        .stderr(Stdio::null())
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

/// The server answers a session's requests, asks for one approval and completes the turn when it
/// is answered; it answers a frame the pinned release would not write with an error; its command
/// leads a group of its own, and the command and what it started end with the server's input.
#[tokio::test]
async fn the_server_runs_a_turn_and_ends_its_commands_with_its_input() {
    let mut child = server("", Some(COMMAND));
    let mut stdin = child.stdin.take().expect("stdin");
    let mut lines = BufReader::new(child.stdout.take().expect("stdout")).lines();
    let mut errors = BufReader::new(child.stderr.take().expect("stderr")).lines();

    write(&mut stdin, &initialize()).await;
    assert_eq!(next(&mut lines).await["id"], "initialize");
    assert_eq!(
        next(&mut lines).await["method"],
        "remoteControl/status/changed"
    );
    write(&mut stdin, &json!({"method":"initialized"})).await;
    write(
        &mut stdin,
        &json!({"id":1,"method":"account/read","params":{}}),
    )
    .await;
    assert_eq!(next(&mut lines).await["result"]["requiresOpenaiAuth"], true);

    // A request the pinned release's schema does not allow is answered with an error.
    write(
        &mut stdin,
        &json!({"id":9,"method":"turn/start","params":{"threadId":5,"input":[]}}),
    )
    .await;
    let refused = next(&mut lines).await;
    assert_eq!(refused["id"], 9);
    assert!(refused.get("error").is_some(), "{refused}");

    write(
        &mut stdin,
        &json!({"id":2,"method":"thread/start","params":{}}),
    )
    .await;
    assert!(next(&mut lines).await["result"]["thread"]["id"].is_string());
    assert_eq!(next(&mut lines).await["method"], "thread/started");
    write(&mut stdin, &turn_request("thread-1")).await;
    assert!(next(&mut lines).await["result"]["turn"].is_object());
    assert_eq!(next(&mut lines).await["method"], "turn/started");
    let asked = next(&mut lines).await;
    assert_eq!(asked["method"], "item/commandExecution/requestApproval");
    write(
        &mut stdin,
        &json!({"id":asked["id"],"result":{"decision":"accept"}}),
    )
    .await;
    // The server says the request was answered before it ends the turn.
    let resolved = next(&mut lines).await;
    assert_eq!(resolved["method"], "serverRequest/resolved");
    assert_eq!(resolved["params"]["requestId"], asked["id"]);
    assert_eq!(next(&mut lines).await["method"], "turn/completed");

    // The command leads a group of its own, with a process of its own in it; both are gone when
    // the server's input has ended and the server has gone.
    let started = loop {
        let line = tokio::time::timeout(WAIT, errors.next_line())
            .await
            .expect("the server says it started the command")
            .expect("readable")
            .expect("not ended");
        if let Some(pid) = line.strip_prefix("stand-in: started command ") {
            break pid.trim().to_owned();
        }
    };
    // The command's group is ended by this guard if the test stops before the server has ended it,
    // since the server can end it only while its input is open.
    let mut ending = EndsGroup(Some(started.clone()));
    let group = tokio::time::timeout(WAIT, async {
        loop {
            let members = status_of("/usr/bin/pgrep", &["-g", &started]);
            if members
                .as_deref()
                .is_some_and(|members| members.lines().count() >= 2)
            {
                return members.expect("members");
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the command's group holds the command and a process of its own");
    assert!(group.lines().any(|member| member == started), "{group}");
    assert_eq!(
        status_of("/bin/ps", &["-o", "pgid=", "-p", &started]),
        Some(started.clone())
    );
    drop(stdin);
    let status = tokio::time::timeout(WAIT, child.wait())
        .await
        .expect("the server ends with its input")
        .expect("waited");
    assert!(status.success());
    // An ended process is collected by whatever adopted it, which is not at the same moment.
    tokio::time::timeout(WAIT, async {
        while status_of("/usr/bin/pgrep", &["-g", &started]).is_some() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("nothing of the command's group is left");
    ending.0 = None;
}

/// Ends the process group a test names, when the test stops before it has been ended.
struct EndsGroup(Option<String>);

impl Drop for EndsGroup {
    fn drop(&mut self) {
        let group = self
            .0
            .take()
            .and_then(|group| group.parse::<i32>().ok())
            .and_then(rustix::process::Pid::from_raw);
        if let Some(group) = group {
            let _ = rustix::process::kill_process_group(group, rustix::process::Signal::KILL);
        }
    }
}

/// The server keeps the order the pinned release requires: nothing before `initialize`, no second
/// `initialize`, nothing before `initialized`, and a turn only on a thread it started.
#[tokio::test]
async fn the_server_keeps_the_order_of_a_session() {
    let mut child = server("", None);
    let mut stdin = child.stdin.take().expect("stdin");
    let mut lines = BufReader::new(child.stdout.take().expect("stdout")).lines();
    let refused = |reply: &Value, id: &Value| {
        assert_eq!(&reply["id"], id, "{reply}");
        assert!(reply.get("error").is_some(), "{reply}");
    };

    write(
        &mut stdin,
        &json!({"id":1,"method":"account/read","params":{}}),
    )
    .await;
    refused(&next(&mut lines).await, &json!(1));
    write(&mut stdin, &initialize()).await;
    assert_eq!(next(&mut lines).await["id"], "initialize");
    assert_eq!(
        next(&mut lines).await["method"],
        "remoteControl/status/changed"
    );
    write(&mut stdin, &initialize()).await;
    refused(&next(&mut lines).await, &json!("initialize"));
    // Between `initialize` and `initialized`.
    write(
        &mut stdin,
        &json!({"id":2,"method":"account/read","params":{}}),
    )
    .await;
    refused(&next(&mut lines).await, &json!(2));
    write(&mut stdin, &json!({"method":"initialized"})).await;
    // A turn on a thread nobody started.
    write(&mut stdin, &turn_request("thread-9")).await;
    refused(&next(&mut lines).await, &json!(3));
    write(
        &mut stdin,
        &json!({"id":4,"method":"account/read","params":{}}),
    )
    .await;
    assert_eq!(next(&mut lines).await["id"], 4);
}

/// What the server cannot answer ends it with a status, so that a gateway that changes a frame is
/// found: a notification of the wrong direction, a response to nothing, an identifier that is not
/// the protocol's, and an `initialized` where the pinned release takes none.
#[tokio::test]
async fn the_server_ends_with_a_status_on_a_frame_it_cannot_answer() {
    for (what, frames) in [
        (
            "a notification of the server's own kind",
            vec![
                json!({"method":"turn/completed","params":{"threadId":"t","turn":{"id":"u","items":[],"status":"completed"}}}),
            ],
        ),
        ("a response to nothing", vec![json!({"id":77,"result":{}})]),
        (
            "a fraction for an identifier",
            vec![json!({"id":1.5,"method":"account/read","params":{}})],
        ),
        (
            "a whole number written as a fraction",
            vec![json!({"id":1.0,"method":"account/read","params":{}})],
        ),
        (
            "an integer past 64 bits",
            vec![
                serde_json::from_str(
                    r#"{"id":9223372036854775808,"method":"account/read","params":{}}"#,
                )
                .expect("JSON"),
            ],
        ),
        (
            "an `initialized` before `initialize`",
            vec![json!({"method":"initialized"})],
        ),
        ("a line that is not JSON", vec![]),
    ] {
        let mut child = server("", None);
        let mut stdin = child.stdin.take().expect("stdin");
        for frame in &frames {
            write(&mut stdin, frame).await;
        }
        if frames.is_empty() {
            stdin.write_all(b"not json\n").await.expect("written");
        }
        let status = tokio::time::timeout(WAIT, child.wait())
            .await
            .unwrap_or_else(|_| panic!("{what} ends the server"))
            .expect("waited");
        assert_eq!(status.code(), Some(3), "{what}");
    }
    // The control: a request with a `jsonrpc` member, which the pinned release does not write, is
    // answered with an error and the server goes on.
    let mut child = server("", None);
    let mut stdin = child.stdin.take().expect("stdin");
    let mut lines = BufReader::new(child.stdout.take().expect("stdout")).lines();
    write(
        &mut stdin,
        &json!({"jsonrpc":"2.0","id":5,"method":"account/read","params":{}}),
    )
    .await;
    let refused = next(&mut lines).await;
    assert_eq!(refused["id"], 5);
    assert!(refused.get("error").is_some(), "{refused}");
}

/// What a terminal run came to, against a gateway that relays.
struct Relayed {
    status: Option<i32>,
    screen: String,
    /// Every text message the terminal wrote.
    written: Vec<String>,
    /// The `Origin` header of its upgrade request.
    origin: Option<String>,
}

/// Runs a terminal against a gateway that relays each message to and from a server of the
/// stand-in's own (or, with `drop_after`, drops the connection after that many messages).
async fn relay(variants: &str, environment: &[(&str, &str)], drop_after: Option<usize>) -> Relayed {
    let directory =
        std::env::temp_dir().join(format!("kr-si-{}-{}", std::process::id(), variants.len()));
    std::fs::create_dir_all(&directory).expect("a directory");
    let socket = directory.join(format!("{}.sock", drop_after.map_or(0, |n| n + 1)));
    let _ = std::fs::remove_file(&socket);
    let listener = tokio::net::UnixListener::bind(&socket).expect("a socket");
    let mut terminal = Command::new(PROGRAM);
    terminal
        .arg("--remote")
        .arg(format!("unix://{}", socket.display()))
        .arg("hello")
        .env("KR_STAND_IN", variants)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    for (name, value) in environment {
        terminal.env(name, value);
    }
    let mut terminal = terminal.spawn().expect("the terminal starts");
    let (stream, _) = tokio::time::timeout(WAIT, listener.accept())
        .await
        .expect("the terminal connects")
        .expect("accepted");
    let (request, mut connection) = ServerBuilder::new()
        .accept(stream)
        .await
        .expect("the upgrade");
    assert_eq!(request.uri().path(), "/rpc");
    let origin = request
        .headers()
        .get("origin")
        .map(|value| value.to_str().expect("text").to_owned());
    let mut written = Vec::new();

    let exchange = async {
        let mut backend = server(variants, None);
        let mut input = backend.stdin.take().expect("stdin");
        let mut output = BufReader::new(backend.stdout.take().expect("stdout")).lines();
        loop {
            tokio::select! {
                message = connection.next() => {
                    let Some(Ok(message)) = message else { break };
                    if let Some(text) = message.as_text() {
                        written.push(text.to_owned());
                        if drop_after.is_some_and(|after| written.len() >= after) {
                            break;
                        }
                        input.write_all(format!("{text}\n").as_bytes()).await.expect("relayed");
                    }
                }
                line = output.next_line() => {
                    let Ok(Some(line)) = line else { break };
                    connection.send(Message::text(line)).await.expect("relayed back");
                }
            }
        }
    };
    tokio::time::timeout(WAIT, exchange)
        .await
        .expect("the exchange finishes");
    drop(connection);
    let status = tokio::time::timeout(WAIT, terminal.wait())
        .await
        .expect("the terminal ends")
        .expect("waited");
    let mut screen = String::new();
    terminal
        .stdout
        .take()
        .expect("stdout")
        .read_to_string(&mut screen)
        .await
        .expect("the screen is readable");
    let _ = std::fs::remove_dir_all(&directory);
    Relayed {
        status: status.code(),
        screen,
        written,
        origin,
    }
}

/// The terminal and the server complete a turn through a relay, with the answers the variants
/// give: accepted, declined, an approval that shares an identifier with the terminal's own
/// request, and a sign-in the server refuses; and with a frame padded to a size.
#[tokio::test]
async fn the_terminal_and_the_server_complete_a_turn_through_a_relay() {
    let run = relay("", &[], None).await;
    assert_eq!(run.status, Some(0), "{}", run.screen);
    assert!(run.screen.contains("turn/completed"), "{}", run.screen);
    assert!(run.origin.is_none());
    assert!(
        run.written
            .iter()
            .any(|text| text.contains(r#""decision":"accept""#))
    );

    let run = relay("decline", &[], None).await;
    assert_eq!(run.status, Some(0), "{}", run.screen);
    assert!(
        run.written
            .iter()
            .any(|text| text.contains(r#""decision":"decline""#)),
        "the decision that crossed: {:?}",
        run.written
    );

    // The approval and the terminal's request to start a turn are both outstanding under one
    // identifier, and both are answered.
    let run = relay("colliding-ids", &[], None).await;
    assert_eq!(run.status, Some(0), "{}", run.screen);
    assert!(run.screen.contains("turn/completed"), "{}", run.screen);

    let run = relay("login", &[("KR_STAND_IN_API_KEY", "not-a-key")], None).await;
    assert_eq!(run.status, Some(0), "{}", run.screen);
    assert!(
        run.written
            .iter()
            .any(|text| text.contains("account/login/start") && text.contains("not-a-key")),
        "{:?}",
        run.written
    );

    let run = relay("origin", &[], None).await;
    assert_eq!(run.status, Some(0), "{}", run.screen);
    assert_eq!(run.origin.as_deref(), Some("http://example.test"));

    // The request to start a turn is exactly as long as it was asked to be.
    let run = relay("", &[("KR_STAND_IN_PAD", "5000")], None).await;
    assert_eq!(run.status, Some(0), "{}", run.screen);
    assert!(
        run.written
            .iter()
            .any(|text| text.contains("turn/start") && text.len() == 5000),
        "{:?}",
        run.written.iter().map(String::len).collect::<Vec<_>>()
    );

    // Dropped after its first frames, the terminal leaves with an error, as the pinned one does.
    let run = relay("", &[], Some(3)).await;
    assert_eq!(run.status, Some(1), "{}", run.screen);
    assert!(
        run.screen.contains("Error: remote app server"),
        "{}",
        run.screen
    );
}

/// What the terminal does with a frame the pinned release's server would not write: it leaves
/// with a status, so a gateway that changes one is found.
#[tokio::test]
async fn the_terminal_ends_with_a_status_on_a_frame_the_server_would_not_write() {
    let initialize = json!({"id":"initialize","result":{
        "userAgent":"u","codexHome":"/","platformFamily":"unix","platformOs":"macos"}});
    for (what, reply) in [
        (
            "a result that breaks its schema",
            Message::text(json!({"id":"initialize","result":{}}).to_string()),
        ),
        (
            "a request of the terminal's own kind",
            Message::text(
                json!({"id":"x","method":"turn/start","params":{"threadId":"t","input":[]}})
                    .to_string(),
            ),
        ),
        (
            "a response to nothing",
            Message::text(json!({"id":"nobody","result":{}}).to_string()),
        ),
        (
            "a binary message",
            Message::binary(initialize.to_string().into_bytes()),
        ),
        ("a message that is not JSON", Message::text("not json")),
    ] {
        let directory = std::env::temp_dir().join(format!("kr-si-neg-{}", std::process::id()));
        std::fs::create_dir_all(&directory).expect("a directory");
        let socket = directory.join("n.sock");
        let _ = std::fs::remove_file(&socket);
        let listener = tokio::net::UnixListener::bind(&socket).expect("a socket");
        let mut terminal = Command::new(PROGRAM)
            .arg("--remote")
            .arg(format!("unix://{}", socket.display()))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("the terminal starts");
        let (stream, _) = tokio::time::timeout(WAIT, listener.accept())
            .await
            .expect("the terminal connects")
            .expect("accepted");
        let (_, mut connection) = ServerBuilder::new()
            .accept(stream)
            .await
            .expect("the upgrade");
        // The terminal's first request, then the frame it must not accept.
        let first = tokio::time::timeout(WAIT, connection.next())
            .await
            .expect("it asks");
        assert!(first.is_some());
        connection.send(reply).await.expect("sent");
        let status = tokio::time::timeout(WAIT, terminal.wait())
            .await
            .unwrap_or_else(|_| panic!("{what} ends the terminal"))
            .expect("waited");
        assert_eq!(status.code(), Some(3), "{what}");
        let _ = std::fs::remove_dir_all(&directory);
    }
}
