//! Gemini CLI's native bridge: its hooks, and nothing else.
//!
//! The Gemini CLI connector package installs an extension into the user's own Gemini CLI
//! directory, `extensions/kalareach/`: a manifest, and a hooks file that registers
//! `kr-hook gemini-cli hook` for `SessionStart`, `SessionEnd` and `Notification`. Gemini CLI loads
//! an extension's hooks beside the person's own, and runs them whether or not the person trusts
//! the folder. It runs a hook's command with `bash -c`, and bash runs a command of plain words in
//! its own process, so the forwarder is started by Gemini CLI's process with no shell left between
//! them.
//!
//! Those three are events whose decisions Gemini CLI ignores. Gemini CLI reads a hook's standard
//! error as its output when standard output is empty, and turns plain text with an exit code
//! other than 0 and 1 into a refusal; on a finished tool that refusal replaces the result the model
//! reads. A forwarder that is missing, or that refuses its command line, prints exactly that, so the
//! registration names no tool event: on these three, the most such a failure can do is a warning.

use crate::hook::{Application, Report};

/// The application name this bridge declares to the worker, as its registration invokes it.
pub const APPLICATION: &str = "gemini-cli";

/// Gemini CLI's hooks: a session starting, a session ending, and a notification.
///
/// Every start is a new selection. Gemini CLI starts a session at startup, on a resume and after
/// `/clear`, and none of those goes on in the thread that was selected before.
pub static HOOKS: Application = Application {
    name: APPLICATION,
    events: &[
        (
            "SessionStart",
            Report::SessionStarted { continued_by: None },
        ),
        ("SessionEnd", Report::SessionEnded),
        ("Notification", Report::Notification),
    ],
};

#[cfg(test)]
mod tests {
    use super::*;

    const THREAD: &str = "1740a246-b45f-4436-932a-3107700094f5";

    fn translated(payload: &serde_json::Value) -> Option<serde_json::Value> {
        let input =
            crate::hook::read_input(payload.to_string().as_bytes()).expect("a hook's input");
        crate::hook::observation(&HOOKS, &input).map(|frame| frame["kr_observation"].clone())
    }

    /// The payloads Gemini CLI 0.60.0 wrote for a session starting and ending, and the one its
    /// hook reference documents for a tool permission notification, each become their observation.
    #[test]
    fn each_registered_event_becomes_its_observation() {
        let cases = [
            (
                serde_json::json!({"session_id": THREAD, "transcript_path": "/tmp/t.jsonl",
                    "cwd": "/tmp/work", "hook_event_name": "SessionStart",
                    "timestamp": "2026-09-25T17:39:42.013Z", "source": "startup"}),
                serde_json::json!({"event": "thread_started", "thread": THREAD, "detail": "startup"}),
            ),
            (
                serde_json::json!({"session_id": THREAD, "hook_event_name": "SessionStart",
                    "source": "clear"}),
                serde_json::json!({"event": "thread_started", "thread": THREAD, "detail": "clear"}),
            ),
            (
                serde_json::json!({"session_id": THREAD, "hook_event_name": "SessionStart",
                    "source": "resume"}),
                serde_json::json!({"event": "thread_started", "thread": THREAD, "detail": "resume"}),
            ),
            (
                serde_json::json!({"session_id": THREAD, "transcript_path": "/tmp/t.jsonl",
                    "cwd": "/tmp/work", "hook_event_name": "SessionEnd",
                    "timestamp": "2026-09-25T17:39:42.193Z", "reason": "exit"}),
                serde_json::json!({"event": "thread_ended", "thread": THREAD, "detail": "exit"}),
            ),
            (
                serde_json::json!({"session_id": THREAD, "hook_event_name": "Notification",
                    "timestamp": "2026-09-25T17:40:02.000Z", "notification_type": "ToolPermission",
                    "message": "Tool Shell requires execution",
                    "details": {"type": "exec", "title": "Shell", "command": "ls", "rootCommand": "ls"}}),
                serde_json::json!({"event": "notification", "thread": THREAD,
                    "detail": "ToolPermission", "text": "Tool Shell requires execution"}),
            ),
        ];
        for (payload, expected) in cases {
            assert_eq!(translated(&payload), Some(expected), "{payload}");
        }
    }

    /// Every event the registration does not name is answered and reports nothing, a finished
    /// tool included, however it names the contact skill's tool.
    #[test]
    fn an_event_the_registration_does_not_name_reports_nothing() {
        for event in [
            "AfterTool",
            "BeforeTool",
            "BeforeAgent",
            "AfterAgent",
            "BeforeModel",
            "AfterModel",
            "BeforeToolSelection",
            "PreCompress",
            "PostToolUse",
        ] {
            let payload = serde_json::json!({"session_id": THREAD, "hook_event_name": event,
                "tool_name": "mcp_kalareach_ask_user", "tool_input": {"request_id": "r-7f3a"},
                "mcp_context": {"server_name": "kalareach", "tool_name": "ask_user"}});
            assert_eq!(translated(&payload), None, "{event}");
        }
    }
}
