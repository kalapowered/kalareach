//! The forwarder's command line, run as the application runs it.
//!
//! | Row | What proves it |
//! | --- | --- |
//! | KR-REQ-11.42 | every test below: the invocations the Claude Code bridge registers parse, and nothing else does |
//! | KR-REQ-11.43 | `outside_a_launch_a_hook_answers_neutrally_and_reaches_for_nothing` |

mod common;

use common::{Placed, run_with_input};

/// A `SessionStart` payload as Claude Code writes it on a hook's standard input.
const SESSION_START: &[u8] = br#"{"session_id":"4d1c0a57-1b1e-4c3a-9d2e-6a0f0c5b7e11","transcript_path":"/tmp/t.jsonl","cwd":"/tmp","hook_event_name":"SessionStart","source":"startup"}"#;

/// KR-REQ-11.42: an unknown application, an unknown surface, a surface in the wrong case, an extra
/// argument or an undeclared flag is refused before anything is read, on standard error, with the
/// usage code, which is not the code Claude Code reads as a request to block.
#[test]
fn kr_req_11_42_anything_but_a_registered_invocation_is_a_usage_error() {
    let placed = Placed::new();
    for arguments in [
        &[][..],
        &["claude-code"][..],
        &["codex", "hook"][..],
        &["claude-code", "hooks"][..],
        &["claude-code", "Hook"][..],
        &["claude-code", "hook", "--session", "4d1c0a57"][..],
        &["claude-code", "channel", "extra"][..],
        &["claude-code", "hook", "--close-after-hello"][..],
        &["relay", "extra"][..],
        &["--help-me"][..],
    ] {
        let ran = run_with_input(placed.command(arguments), SESSION_START);
        assert_eq!(
            ran.code,
            Some(i32::from(kr_hook::cli::EXIT_USAGE)),
            "{arguments:?}: {}",
            ran.stderr
        );
        assert_ne!(ran.code, Some(2), "a usage error never looks like a block");
        assert!(
            ran.stdout.is_empty(),
            "{arguments:?} writes nothing a hook's output could be"
        );
        assert!(
            ran.stderr.contains("Usage"),
            "{arguments:?}: {}",
            ran.stderr
        );
    }

    // Help and the version are answers rather than failures.
    for arguments in [
        &["--help"][..],
        &["--version"][..],
        &["claude-code", "--help"][..],
    ] {
        let ran = run_with_input(placed.command(arguments), b"");
        assert_eq!(ran.code, Some(0), "{arguments:?}");
    }
}

/// KR-REQ-11.42, KR-REQ-11.43: the hook registration's own invocation, in a process whose
/// environment names no launch, reads its event, answers exactly `{}` and exits 0 well inside the
/// shortest timeout the package registers, without a word on standard output beyond the answer.
/// A session identifier in the environment does not change that: it names no registration and no
/// credential.
#[test]
fn outside_a_launch_a_hook_answers_neutrally_and_reaches_for_nothing() {
    let placed = Placed::new();
    for session in [None, Some("4d1c0a57-1b1e-4c3a-9d2e-6a0f0c5b7e11")] {
        let mut command = placed.command(&["claude-code", "hook"]);
        if let Some(session) = session {
            command.env("KR_SESSION", session);
        }
        let ran = run_with_input(command, SESSION_START);
        assert_eq!(ran.code, Some(0), "{}", ran.stderr);
        assert_eq!(ran.stdout, b"{}\n");
        assert!(
            ran.took < std::time::Duration::from_secs(1),
            "answered in {:?}, inside the one-second SessionEnd timeout",
            ran.took
        );
    }
}

/// A `SessionEnd` payload, the event with the shortest timeout the package registers.
const SESSION_END: &[u8] = br#"{"session_id":"4d1c0a57-1b1e-4c3a-9d2e-6a0f0c5b7e11","transcript_path":"/tmp/t.jsonl","cwd":"/tmp","hook_event_name":"SessionEnd","reason":"clear"}"#;

/// KR-REQ-11.42, KR-REQ-12.18: an application that never closes a hook's input cannot hold the
/// hook open. The hook answers `{}` and exits 0 at its own deadline, inside the one-second timeout
/// the package registers for `SessionEnd`.
#[test]
fn kr_req_12_18_a_hook_whose_input_never_closes_still_answers_in_time() {
    let placed = Placed::new();
    let ran = common::run_holding_input(placed.command(&["claude-code", "hook"]), SESSION_END);
    assert_eq!(ran.code, Some(0), "{}", ran.stderr);
    assert_eq!(ran.stdout, b"{}\n");
    assert!(
        ran.took >= kr_hook::claude_code::hook::HOOK_DEADLINE,
        "it waited for its input until its deadline: {:?}",
        ran.took
    );
    assert!(
        ran.took < std::time::Duration::from_secs(1),
        "answered in {:?}, inside the one-second SessionEnd timeout",
        ran.took
    );
}

/// KR-REQ-11.42: the relay needs a registration, and says so rather than guessing at a socket.
#[test]
fn the_relay_without_a_registration_fails_and_says_why() {
    let placed = Placed::new();
    let ran = run_with_input(placed.command(&["relay"]), b"");
    assert_eq!(ran.code, Some(i32::from(kr_hook::cli::EXIT_FAILURE)));
    assert!(ran.stderr.contains("KR_REGISTRATION"), "{}", ran.stderr);
    assert!(ran.stdout.is_empty());
}

/// The MCP handshake Claude Code opens a channel server with.
fn initialize(protocol_version: &str) -> String {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": 0,
        "method": "initialize",
        "params": {
            "protocolVersion": protocol_version,
            "capabilities": {},
            "clientInfo": {"name": "claude-code", "version": "2.1.278"},
        },
    })
    .to_string()
}

/// KR-REQ-11.42, KR-REQ-12.18: the channel registration's own invocation, outside any launch, is
/// an MCP server that completes Claude Code's handshake at a revision Claude Code registers a
/// channel over, declares no Channels capability because nothing is connected behind it, and ends
/// cleanly when Claude Code closes its end.
#[test]
fn outside_a_launch_the_channel_completes_the_handshake_and_declares_nothing() {
    let placed = Placed::new();
    for requested in ["2025-06-18", "2025-11-25", "2026-07-28"] {
        let input = format!(
            "{}\n{}\n",
            initialize(requested),
            serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"})
        );
        let ran = run_with_input(
            placed.command(&["claude-code", "channel"]),
            input.as_bytes(),
        );
        assert_eq!(ran.code, Some(0), "{requested}: {}", ran.stderr);
        let answer: serde_json::Value = serde_json::from_slice(
            ran.stdout
                .split(|byte| *byte == b'\n')
                .next()
                .expect("one answer"),
        )
        .expect("the answer is JSON");
        assert_eq!(answer["id"], 0);
        let negotiated = answer["result"]["protocolVersion"]
            .as_str()
            .expect("a negotiated revision");
        assert!(
            negotiated < "2026-07-28",
            "{requested} negotiated {negotiated}, a revision Claude Code registers a channel over"
        );
        if requested != "2026-07-28" {
            assert_eq!(negotiated, requested);
        }
        assert_eq!(answer["result"]["serverInfo"]["name"], "kalareach");
        assert!(
            answer["result"]["capabilities"]["experimental"].is_null(),
            "nothing is connected, so no Channels capability is declared: {answer}"
        );
    }
}
