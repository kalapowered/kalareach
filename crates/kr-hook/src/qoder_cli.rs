//! Qoder CLI's native bridge: its hooks, and nothing else.
//!
//! Qoder CLI reads hooks from the person's own settings files and from the settings a launch
//! passes with `--settings`, and runs them beside each other. KalaReach's hooks are passed that way,
//! as inline JSON on the launch, so nothing is written into the person's Qoder CLI directory and
//! the hooks exist only in the sessions KalaReach launches. They register `kr-hook qoder-cli hook`
//! for `SessionStart`, `SessionEnd`, `PostToolUse`, `PostToolUseFailure` and `Notification`, each
//! in exec form, a `command` with its `args`, which Qoder CLI starts itself with no shell between
//! them.
//!
//! On those five events only exit code 2 refuses anything, and Qoder CLI reads standard output
//! only from a hook that exits 0. The forwarder exits 0 with exactly `{}`, and a failure it could
//! not help, a forwarder that is missing or that refuses its command line, is logged by Qoder CLI
//! and changes nothing else.

use crate::hook::{Application, Report};

/// The application name this bridge declares to the worker, as its registration invokes it.
pub const APPLICATION: &str = "qoder-cli";

/// Qoder CLI's hooks: a session starting and ending, a tool finishing and failing, and a
/// notification.
///
/// A session starting after a compaction goes on in the thread it compacted; every other start,
/// at startup, on a resume, after `/clear` or for a new session, is a new selection.
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

    const THREAD: &str = "6b3bbfa1-1e44-480a-ae1f-a44fb86916f2";

    fn translated(payload: &serde_json::Value) -> Option<serde_json::Value> {
        let input =
            crate::hook::read_input(payload.to_string().as_bytes()).expect("a hook's input");
        crate::hook::observation(&HOOKS, &input).map(|frame| frame["kr_observation"].clone())
    }

    /// The payloads Qoder CLI 1.1.63 wrote for a session starting and ending, and the ones its hook
    /// reference documents for the other three events, each become their observation.
    #[test]
    fn each_registered_event_becomes_its_observation() {
        let cases = [
            (
                serde_json::json!({"session_id": THREAD, "transcript_path": "/tmp/t.jsonl",
                    "cwd": "/tmp/work", "hook_event_name": "SessionStart",
                    "permission_mode": "default", "source": "startup"}),
                serde_json::json!({"event": "thread_started", "thread": THREAD, "detail": "startup"}),
            ),
            (
                serde_json::json!({"session_id": THREAD, "hook_event_name": "SessionStart",
                    "source": "new"}),
                serde_json::json!({"event": "thread_started", "thread": THREAD, "detail": "new"}),
            ),
            (
                serde_json::json!({"session_id": THREAD, "hook_event_name": "SessionStart",
                    "source": "compact"}),
                serde_json::json!({"event": "thread_continued", "thread": THREAD, "detail": "compact"}),
            ),
            (
                serde_json::json!({"session_id": THREAD, "transcript_path": "/tmp/t.jsonl",
                    "cwd": "/tmp/work", "hook_event_name": "SessionEnd",
                    "permission_mode": "default", "reason": "other"}),
                serde_json::json!({"event": "thread_ended", "thread": THREAD, "detail": "other"}),
            ),
            (
                serde_json::json!({"session_id": THREAD, "hook_event_name": "PostToolUse",
                    "tool_name": "Write", "tool_input": {"file_path": "/p/f.ts", "content": "x"},
                    "tool_response": {"success": true, "bytes_written": 1024},
                    "tool_use_id": "toolu_01ABC123"}),
                serde_json::json!({"event": "tool_finished", "thread": THREAD, "detail": "Write"}),
            ),
            (
                serde_json::json!({"session_id": THREAD, "hook_event_name": "PostToolUseFailure",
                    "tool_name": "Bash", "tool_input": {"command": "npm test"},
                    "tool_use_id": "toolu_01ABC123",
                    "error": "Command exited with non-zero status code 1",
                    "error_type": "execution_failed", "is_interrupt": false}),
                serde_json::json!({"event": "tool_failed", "thread": THREAD, "detail": "Bash"}),
            ),
            (
                serde_json::json!({"session_id": THREAD, "hook_event_name": "Notification",
                    "notification_type": "permission_prompt",
                    "message": "Agent is requesting permission to run: rm -rf node_modules",
                    "title": "Permission Required", "details": {}}),
                serde_json::json!({"event": "notification", "thread": THREAD,
                    "detail": "permission_prompt",
                    "text": "Agent is requesting permission to run: rm -rf node_modules"}),
            ),
        ];
        for (payload, expected) in cases {
            assert_eq!(translated(&payload), Some(expected), "{payload}");
        }
    }

    /// A finished call of the contact skill's `ask_user`, which Qoder CLI names
    /// `mcp__kalareach__ask_user` and describes in its MCP context, names the request it asked.
    #[test]
    fn a_finished_contact_question_names_its_request() {
        let reported = translated(&serde_json::json!({"session_id": THREAD,
            "hook_event_name": "PostToolUse", "tool_name": "mcp__kalareach__ask_user",
            "tool_input": {"request_id": "r-7f3a", "question": "Which one?", "type": "input"},
            "tool_response": {"content": []}, "tool_use_id": "toolu_02",
            "mcp_context": {"server_name": "kalareach", "tool_name": "ask_user"}}))
        .expect("an observation");
        assert_eq!(reported["contact_request"], "r-7f3a");
    }

    /// Every event the registration does not name is answered and reports nothing.
    #[test]
    fn an_event_the_registration_does_not_name_reports_nothing() {
        for event in [
            "PreToolUse",
            "UserPromptSubmit",
            "PermissionRequest",
            "PermissionDenied",
            "Stop",
            "StopFailure",
            "SubagentStart",
            "SubagentStop",
            "PreCompact",
            "PostCompact",
            "InstructionsLoaded",
            "ConfigChange",
            "CwdChanged",
            "FileChanged",
            "WorktreeCreate",
            "WorktreeRemove",
            "Elicitation",
            "ElicitationResult",
        ] {
            let payload = serde_json::json!({"session_id": THREAD, "hook_event_name": event});
            assert_eq!(translated(&payload), None, "{event}");
        }
    }
}
