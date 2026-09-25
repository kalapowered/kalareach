//! Claude Code's native bridge.
//!
//! The Claude Code plugin package installs three registration files into the user's own Claude
//! Code directory: a plugin manifest, an MCP server entry that starts `kr-hook claude-code channel`
//! over standard input and output, and a hooks file that starts `kr-hook claude-code hook` for
//! `SessionStart`, `SessionEnd`, `PostToolUse`, `PostToolUseFailure` and `Notification`. Claude
//! Code starts both itself, so both run under its permissions and outside the KalaReach plugin
//! sandbox, and both inherit the environment of the session Claude Code runs in.
//!
//! | Item | What it owns |
//! | --- | --- |
//! | [`HOOKS`] | What each hook event reports; [`crate::hook`] runs every hook: prompt, neutral, and never a decision |
//! | [`channel`] | The Channels server: Claude Code's MCP session and the worker's exchange |

pub mod channel;

use crate::hook::{Application, Report};

/// The application name this bridge declares to the worker, as its registration invokes it.
pub const APPLICATION: &str = "claude-code";

/// Claude Code's hooks: the five events the package registers, whose exit codes refuse nothing.
///
/// A session starting after a compaction goes on in the same thread; every other start is a new
/// selection.
pub static HOOKS: Application = Application {
    name: APPLICATION,
    events: &[
        (
            "SessionStart",
            Report::SessionStarted {
                continued_by: Some("compact"),
            },
        ),
        ("SessionEnd", Report::SessionEnded),
        ("PostToolUse", Report::ToolFinished),
        ("PostToolUseFailure", Report::ToolFailed),
        ("Notification", Report::Notification),
    ],
};

#[cfg(test)]
mod tests {
    use super::*;

    fn translated(payload: &serde_json::Value) -> Option<serde_json::Value> {
        let input =
            crate::hook::read_input(payload.to_string().as_bytes()).expect("a hook's input");
        crate::hook::observation(&HOOKS, &input).map(|frame| frame["kr_observation"].clone())
    }

    #[test]
    fn each_registered_event_becomes_its_observation() {
        let thread = "4d1c0a57-1b1e-4c3a-9d2e-6a0f0c5b7e11";
        let cases = [
            (
                serde_json::json!({"session_id": thread, "hook_event_name": "SessionStart", "source": "clear", "model": "m"}),
                serde_json::json!({"event": "thread_started", "thread": thread, "detail": "clear"}),
            ),
            (
                serde_json::json!({"session_id": thread, "hook_event_name": "SessionStart", "source": "compact"}),
                serde_json::json!({"event": "thread_continued", "thread": thread, "detail": "compact"}),
            ),
            (
                serde_json::json!({"session_id": thread, "hook_event_name": "SessionEnd", "reason": "resume"}),
                serde_json::json!({"event": "thread_ended", "thread": thread, "detail": "resume"}),
            ),
            (
                serde_json::json!({"session_id": thread, "hook_event_name": "PostToolUse", "tool_name": "Bash",
                    "tool_input": {"command": "ls", "request_id": "not-a-contact-question"},
                    "tool_response": {"stdout": "x".repeat(4096)}}),
                serde_json::json!({"event": "tool_finished", "thread": thread, "detail": "Bash"}),
            ),
            (
                serde_json::json!({"session_id": thread, "hook_event_name": "PostToolUseFailure", "tool_name": "Bash",
                    "tool_input": "not an object", "error": "Exit code 1", "is_interrupt": false}),
                serde_json::json!({"event": "tool_failed", "thread": thread, "detail": "Bash"}),
            ),
            (
                serde_json::json!({"session_id": thread, "hook_event_name": "Notification",
                    "message": "Claude needs your permission", "notification_type": "permission_prompt"}),
                serde_json::json!({"event": "notification", "thread": thread, "detail": "permission_prompt",
                    "text": "Claude needs your permission"}),
            ),
        ];
        for (payload, expected) in cases {
            assert_eq!(translated(&payload), Some(expected), "{payload}");
        }
    }

    #[test]
    fn a_finished_contact_question_names_its_request_and_nothing_else_does() {
        let thread = "4d1c0a57-1b1e-4c3a-9d2e-6a0f0c5b7e11";
        let asked = |tool: &str, input: serde_json::Value, server: Option<&str>| {
            let mut payload = serde_json::json!({"session_id": thread, "hook_event_name": "PostToolUse",
                "tool_name": tool, "tool_input": input, "tool_response": {"content": []}});
            if let Some(server) = server {
                payload["mcp_server"] = serde_json::json!({"name": server, "source": "user"});
            }
            translated(&payload).expect("an observation")["contact_request"].clone()
        };
        let question =
            serde_json::json!({"request_id": "r-7f3a", "question": "which?", "type": "input"});
        assert_eq!(
            asked("mcp__kalareach__ask_user", question.clone(), None),
            "r-7f3a"
        );
        assert_eq!(
            asked(
                "mcp__kalareach__ask_user",
                question.clone(),
                Some("kalareach")
            ),
            "r-7f3a"
        );
        for (tool, input, server) in [
            (
                "mcp__kalareach__ask_user",
                question.clone(),
                Some("elsewhere"),
            ),
            ("mcp__other__ask_user", question.clone(), None),
            ("mcp__kalareach__wait_for_answer", question.clone(), None),
            (
                "mcp__kalareach__ask_user",
                serde_json::json!({"request_id": 7}),
                None,
            ),
            (
                "mcp__kalareach__ask_user",
                serde_json::json!({"request_id": "  "}),
                None,
            ),
            (
                "mcp__kalareach__ask_user",
                serde_json::json!({"request_id": "x".repeat(257)}),
                None,
            ),
            (
                "mcp__kalareach__ask_user",
                serde_json::json!(["request_id"]),
                None,
            ),
        ] {
            assert!(
                asked(tool, input.clone(), server).is_null(),
                "{tool} {input} {server:?}"
            );
        }
    }

    #[test]
    fn what_cannot_be_reported_is_not() {
        for payload in [
            serde_json::json!({"session_id": "s", "hook_event_name": "PreToolUse", "tool_name": "Bash"}),
            serde_json::json!({"session_id": "", "hook_event_name": "SessionStart", "source": "startup"}),
            serde_json::json!({"session_id": "a\u{7}b", "hook_event_name": "SessionStart"}),
            serde_json::json!({"session_id": "x".repeat(257), "hook_event_name": "SessionStart"}),
        ] {
            assert_eq!(translated(&payload), None, "{payload}");
        }
        assert!(crate::hook::read_input(&b"not json"[..]).is_err());
        assert!(crate::hook::read_input(&br#"{"hook_event_name":"SessionStart"}"#[..]).is_err());
    }
}
