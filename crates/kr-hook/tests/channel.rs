//! Claude Code's Channels server through the forwarder and the worker's own listener.
//!
//! The worker's gateway launches a stand-in application, which starts `kr-hook claude-code
//! channel` over its own standard input and output, as Claude Code starts a channel server. This
//! test speaks MCP to it as Claude Code does, and speaks the private exchange to it as the worker
//! does, through the connection the worker admitted.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-11.42 | every case: the channel registration's own invocation, admitted by the worker |
//! | KR-REQ-12.18 | `kr_req_12_18_the_channel_negotiates_and_carries_frames_both_ways_and_nothing_else` |
//! | KR-REQ-11.34 | `kr_req_12_18_the_channel_negotiates_and_carries_frames_both_ways_and_nothing_else`: core code alone carries the frames, beside the unchanged terminal |

#![cfg(unix)]

mod common;

use std::io::{BufRead as _, Write as _};
use std::sync::mpsc::Receiver;

use common::launched::{self, Launch};
use common::{LIVENESS, Placed};
use kr_worker::broker::{AdmittedBridge, BridgeSurface};

/// What the channel writes to Claude Code, one JSON document per line, as it arrives.
fn read_lines(launch: &mut Launch) -> Receiver<serde_json::Value> {
    let stdout = launch
        .application
        .stdout
        .take()
        .expect("the channel writes to the application's output");
    let (lines, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in std::io::BufReader::new(stdout).lines() {
            let Ok(line) = line else { break };
            let value = serde_json::from_str(&line).expect("each line is JSON");
            if lines.send(value).is_err() {
                break;
            }
        }
    });
    receiver
}

fn next(lines: &Receiver<serde_json::Value>) -> serde_json::Value {
    lines
        .recv_timeout(LIVENESS)
        .expect("the channel wrote to Claude Code")
}

/// Writes one MCP message to the channel, as Claude Code does.
fn to_channel(launch: &mut Launch, message: &serde_json::Value) {
    let input = launch
        .requests
        .as_mut()
        .expect("the channel's input is open");
    writeln!(input, "{message}").expect("written");
    input.flush().expect("and it goes");
}

async fn from_worker(admitted: &mut AdmittedBridge, frame: &serde_json::Value) {
    admitted
        .stream
        .write_frame(frame.to_string().as_bytes())
        .await
        .expect("the worker writes to the channel");
}

async fn to_worker(admitted: &mut AdmittedBridge) -> Option<serde_json::Value> {
    tokio::time::timeout(LIVENESS, admitted.stream.read_frame())
        .await
        .expect("the channel wrote to the worker, or closed")
        .expect("a whole frame")
        .map(|body| serde_json::from_slice(&body).expect("the frame is JSON"))
}

fn installed(placed: &Placed, surfaces: &[BridgeSurface]) -> kr_worker::broker::InstalledBridge {
    launched::installed(&placed.forwarder, surfaces)
}

fn exit_code(launch: &mut Launch) -> Option<i32> {
    let deadline = std::time::Instant::now() + LIVENESS;
    loop {
        if let Some(status) = launch.application.try_wait().expect("waitable") {
            return status.code();
        }
        assert!(std::time::Instant::now() < deadline, "the channel ended");
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

fn permission_request(request_id: &str, input_preview: &str) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "method": "notifications/claude/channel/permission_request",
        "params": {
            "request_id": request_id,
            "tool_name": "Bash",
            "description": "Run shell command",
            "input_preview": input_preview,
            "added_by_a_later_release": true,
        },
    })
}

fn verdict(request_id: &str, behavior: &str) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "method": "notifications/claude/channel/permission",
        "params": {"request_id": request_id, "behavior": behavior},
    })
}

fn message(content: &str) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "method": "notifications/claude/channel",
        "params": {"content": content, "meta": {"chat_id": "1"}},
    })
}

/// KR-REQ-12.18, KR-REQ-11.34, KR-REQ-11.42: the channel is admitted by the worker, completes
/// Claude Code's handshake declaring the Channels pair at a revision Claude Code registers a
/// channel over, and then carries frames both ways as JSON lines up to the exchange's one-MiB
/// bound: a message into the session, a relayed approval out with its correlation at
/// `params.request_id`, and the verdict back. What fails its check is not forwarded and never
/// becomes a message: a verdict for a request this channel did not relay, a second verdict, a
/// malformed one, a message with an undocumented member and an unknown method. An approval past the
/// bound is left to the terminal. When Claude Code closes its end, the channel exits 0 and the
/// worker reads the end of the connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_12_18_the_channel_negotiates_and_carries_frames_both_ways_and_nothing_else() {
    let placed = Placed::new();
    let mut launch = Launch::channel(
        &placed,
        installed(&placed, &[BridgeSurface::Hook, BridgeSurface::Channel]),
    );
    let lines = read_lines(&mut launch);
    let mut admitted = launch.accept().await.expect("the channel is admitted");
    assert_eq!(admitted.surface, BridgeSurface::Channel);

    to_channel(
        &mut launch,
        &serde_json::json!({
            "jsonrpc": "2.0",
            "id": 0,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "claude-code", "version": "2.1.278"},
            },
        }),
    );
    let answer = next(&lines);
    assert_eq!(answer["id"], 0);
    assert_eq!(answer["result"]["protocolVersion"], "2025-06-18");
    assert_eq!(
        answer["result"]["capabilities"]["experimental"],
        serde_json::json!({"claude/channel": {}, "claude/channel/permission": {}})
    );
    assert!(
        answer["result"]["capabilities"]["tools"].is_null(),
        "no tools"
    );
    assert!(
        answer["result"]["instructions"]
            .as_str()
            .is_some_and(|text| text.contains("<channel source=\"kalareach\">")),
        "{answer}"
    );
    to_channel(
        &mut launch,
        &serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    );

    // A message into the session.
    from_worker(&mut admitted, &message("build failed on main")).await;
    assert_eq!(next(&lines), message("build failed on main"));

    // A tool approval out, with only the four documented fields.
    to_channel(
        &mut launch,
        &permission_request("abcde", "{\"command\":\"ls\"}"),
    );
    assert_eq!(
        to_worker(&mut admitted).await,
        Some(serde_json::json!({
            "jsonrpc": "2.0",
            "method": "notifications/claude/channel/permission_request",
            "params": {
                "request_id": "abcde",
                "tool_name": "Bash",
                "description": "Run shell command",
                "input_preview": "{\"command\":\"ls\"}",
            },
        }))
    );
    // A malformed verdict first: it goes nowhere and leaves the request answerable.
    from_worker(&mut admitted, &verdict("abcde", "yes abcde")).await;
    // The verdict back, correlated by the identifier.
    from_worker(&mut admitted, &verdict("abcde", "allow")).await;
    assert_eq!(next(&lines), verdict("abcde", "allow"));

    // None of these is forwarded, and none becomes a message.
    for refused in [
        verdict("zzzzz", "allow"),
        verdict("abcde", "deny"),
        serde_json::json!({"method": "notifications/claude/channel",
            "params": {"content": "x", "meta": {"chat-id": "1"}}}),
        serde_json::json!({"method": "notifications/claude/channel",
            "params": {"content": "x", "reply_to": "someone"}}),
        serde_json::json!({"method": "tools/call", "id": 7, "params": {"name": "reply"}}),
    ] {
        from_worker(&mut admitted, &refused).await;
    }
    from_worker(&mut admitted, &message("after the refusals")).await;
    assert_eq!(
        next(&lines),
        message("after the refusals"),
        "the next thing Claude Code reads is the next valid frame"
    );

    // A message close to the exchange's bound still goes whole.
    let large = "m".repeat(1_048_000);
    from_worker(&mut admitted, &message(&large)).await;
    let delivered = next(&lines);
    assert_eq!(
        delivered["params"]["content"].as_str().map(str::len),
        Some(large.len())
    );

    // An approval past the bound is not relayed; the next one is.
    to_channel(
        &mut launch,
        &permission_request("bcdef", &"p".repeat(1_100_000)),
    );
    to_channel(&mut launch, &permission_request("cdefg", "{}"));
    assert_eq!(
        to_worker(&mut admitted).await.expect("a frame")["params"]["request_id"],
        "cdefg"
    );

    // Claude Code closes its end.
    drop(launch.requests.take());
    assert_eq!(exit_code(&mut launch), Some(0));
    assert_eq!(
        to_worker(&mut admitted).await,
        None,
        "the worker reads the end of the channel"
    );
}

/// KR-REQ-12.18: when the worker ends the channel, the channel ends its MCP session and exits
/// with a failure that says why, so Claude Code shows the server as gone rather than as a channel
/// nothing will ever reach.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_12_18_a_channel_the_worker_ends_ends_its_session() {
    let placed = Placed::new();
    let mut launch = Launch::channel(&placed, installed(&placed, &[BridgeSurface::Channel]));
    let lines = read_lines(&mut launch);
    let admitted = launch.accept().await.expect("the channel is admitted");
    to_channel(
        &mut launch,
        &serde_json::json!({
            "jsonrpc": "2.0", "id": 0, "method": "initialize",
            "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                "clientInfo": {"name": "claude-code", "version": "2.1.278"}},
        }),
    );
    assert_eq!(next(&lines)["id"], 0);
    to_channel(
        &mut launch,
        &serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    );
    drop(admitted);
    assert_eq!(
        exit_code(&mut launch),
        Some(i32::from(kr_hook::cli::EXIT_FAILURE))
    );
}

/// KR-REQ-05.09, KR-REQ-11.43: a channel the installation did not register is refused before
/// Claude Code's handshake is answered, and the forwarder exits with a failure rather than serving
/// a channel nothing stands behind.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn kr_req_05_09_a_channel_the_installation_does_not_have_is_refused() {
    let placed = Placed::new();
    let mut launch = Launch::channel(&placed, installed(&placed, &[BridgeSurface::Hook]));
    let refused = launch
        .accept()
        .await
        .expect_err("a registration the installation does not have is refused");
    assert_eq!(
        refused.code(),
        kr_protocol::error::ErrorCode::PermissionDenied
    );
    assert!(
        refused.to_string().contains("channel registration"),
        "{refused}"
    );
    assert_eq!(
        exit_code(&mut launch),
        Some(i32::from(kr_hook::cli::EXIT_FAILURE))
    );
}
