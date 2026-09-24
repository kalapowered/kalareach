//! One Claude Code lifecycle or tool hook.
//!
//! A hook here observes. Whatever happens, the forwarder writes exactly `{}` to standard output and
//! exits 0, promptly: a JSON object with no fields is the neutral answer on every event, and exit 0
//! is the code that neither blocks nor reports an error. It never answers `{"continue": false}`,
//! never prints anything a hook's output could be read as, and never waits for a person.
//!
//! Every run is bounded by [`HOOK_DEADLINE`], well inside the shortest timeout the package
//! registers (one second, for `SessionEnd`). When the deadline passes, the answer is written and
//! the process ends, whatever is still in flight.

use std::time::Duration;

use crate::exchange::Exchange;
use crate::registration::{Bridge, Paths, Registration};

/// What a hook declares itself to the worker as.
const BRIDGE: Bridge = Bridge {
    application: super::APPLICATION,
    surface: "hook",
};

/// How long one hook run may take, from start to answer.
///
/// The package registers a one-second timeout for `SessionEnd` and five seconds for the other four
/// events. Claude Code cancels a hook that reaches its timeout and discards its output, so the
/// deadline sits well inside the shorter one.
pub const HOOK_DEADLINE: Duration = Duration::from_millis(500);

/// The most of a hook's input this forwarder reads.
///
/// A `PostToolUse` event carries the tool's whole response, which can be large. It is read to its
/// end so the application's write completes, and past this bound it is left unread.
pub const MAX_HOOK_INPUT_BYTES: u64 = 64 * 1024 * 1024;

/// The answer every hook run writes: a JSON object that sets nothing.
pub const NEUTRAL_ANSWER: &str = "{}";

/// How soon after it started a hook that reported a thread starting, going on or ending answers,
/// at the earliest.
///
/// The worker places those reports by the kernel's record of when each hook started, which counts
/// ten-millisecond ticks on Linux, and it does not place two from one tick against each other.
/// Answering two ticks after the start means a hook the application starts only once this one has
/// answered, as Claude Code does after a session ends, falls in a later tick.
pub const THREAD_REPORT_LINGER: Duration = Duration::from_millis(20);

/// Runs one hook and answers neutrally.
#[must_use]
pub fn run() -> std::process::ExitCode {
    let started = std::time::Instant::now();
    let (finished, outcome) = std::sync::mpsc::channel();
    // The work runs on its own thread so the deadline is kept whatever it is waiting on. When the
    // deadline passes, the answer is written and the process ends, which ends that thread too.
    std::thread::spawn(move || {
        let _ = finished.send(observe(started));
    });
    match outcome.recv_timeout(HOOK_DEADLINE) {
        Ok(Ok(())) => {}
        Ok(Err(failure)) => crate::report(&failure),
        Err(_) => crate::report(&format!(
            "the hook did not finish within {} ms, and answered anyway",
            HOOK_DEADLINE.as_millis()
        )),
    }
    answer()
}

/// How long a hook waits for the worker to finish publishing its launch.
///
/// The worker writes the registration as soon as it knows which process it started, long before
/// the application runs its first hook, so this only covers a hook that races the launch itself.
pub const REGISTRATION_WAIT: Duration = Duration::from_millis(250);

/// Reads the event Claude Code wrote and, inside a launch, reaches the worker with it.
///
/// The observation goes straight behind the hello. The worker reads nothing past the hello until
/// it has admitted the connection, and then reads the observation, applies it and closes the
/// connection. This waits for that close, so an observation that selects a thread has been applied
/// before the hook returns to Claude Code, which holds a session's first response until its
/// `SessionStart` hooks have finished. A thread's report is then held until
/// [`THREAD_REPORT_LINGER`] after `started`.
fn observe(started: std::time::Instant) -> Result<(), String> {
    let input = read_input(std::io::stdin().lock())?;
    // Outside a launch there is nobody to tell, and the answer is the same neutral one.
    let Some(paths) = Paths::from_environment() else {
        return Ok(());
    };
    let Some(observation) = observation(&input) else {
        return Ok(());
    };
    let registration =
        Registration::read(&paths, REGISTRATION_WAIT).map_err(|error| error.to_string())?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("the hook could not start: {error}"))?;
    runtime
        .block_on(async {
            let mut exchange = Exchange::open(&registration, BRIDGE).await?;
            exchange.send(&observation).await?;
            exchange.admitted(HOOK_DEADLINE).await?;
            // The worker closes the connection once it has applied the observation.
            while exchange.receive().await?.is_some() {}
            Ok::<(), crate::exchange::ExchangeError>(())
        })
        .map_err(|error| error.to_string())?;
    if reports_thread(&input) {
        std::thread::sleep(THREAD_REPORT_LINGER.saturating_sub(started.elapsed()));
    }
    Ok(())
}

/// Whether the event is one the worker decides the thread by: a session starting or ending.
fn reports_thread(input: &HookInput) -> bool {
    matches!(
        input.hook_event_name.as_str(),
        "SessionStart" | "SessionEnd"
    )
}

/// The longest detail an observation carries, which is the host's own bound.
pub const MAX_DETAIL_BYTES: usize = 256;

/// The longest text an observation carries, which is the host's own bound.
pub const MAX_TEXT_BYTES: usize = 4096;

/// The longest contact request identifier, which is the longest a question's own may be.
pub const MAX_CONTACT_REQUEST_BYTES: usize = 256;

/// What this forwarder reads of a hook's input.
///
/// Everything else in the payload, a tool's whole response included, is skipped as it is read and
/// never held.
#[derive(Debug, Default, serde::Deserialize)]
pub struct HookInput {
    /// The session the event happened in, which is the thread KalaReach binds to.
    pub session_id: String,
    /// Which event this is.
    pub hook_event_name: String,
    /// How a session started (`SessionStart`).
    #[serde(default)]
    pub source: Option<String>,
    /// Why a session ended (`SessionEnd`).
    #[serde(default)]
    pub reason: Option<String>,
    /// The tool that ran (`PostToolUse`, `PostToolUseFailure`).
    #[serde(default)]
    pub tool_name: Option<String>,
    /// The `request_id` member of the tool's input, where it has a string one.
    #[serde(default, rename = "tool_input", deserialize_with = "request_id_in")]
    pub tool_request_id: Option<String>,
    /// The MCP server the tool came from, where it came from one.
    #[serde(default)]
    pub mcp_server: Option<McpServer>,
    /// Which notification this is (`Notification`).
    #[serde(default)]
    pub notification_type: Option<String>,
    /// The notification's text (`Notification`).
    #[serde(default)]
    pub message: Option<String>,
}

/// The MCP server a tool came from, as Claude Code names it.
#[derive(Debug, Default, serde::Deserialize)]
pub struct McpServer {
    /// Its name.
    #[serde(default)]
    pub name: Option<String>,
}

/// Reads and parses one hook's input, bounded by [`MAX_HOOK_INPUT_BYTES`].
///
/// # Errors
///
/// Returns what went wrong for a payload that is not a hook's input or is past the bound.
pub fn read_input(input: impl std::io::Read) -> Result<HookInput, String> {
    let reader = std::io::BufReader::new(input.take(MAX_HOOK_INPUT_BYTES));
    serde_json::from_reader(reader)
        .map_err(|error| format!("the hook's input is not an event this bridge reads: {error}"))
}

/// Translates one hook's input into the observation the worker reads, or `None` for an event this
/// bridge does not report.
///
/// The five events the package registers each have one: a session starting or ending selects or
/// ends the thread, a tool finishing or failing and a notification are recorded as observed
/// history. A finished call of the contact skill's `ask_user` also names the request it asked, so
/// the worker learns which thread the question was asked in.
#[must_use]
pub fn observation(input: &HookInput) -> Option<serde_json::Value> {
    let thread = kr_protocol::ids::AgentThreadId::new(input.session_id.clone()).ok()?;
    let (event, detail) = match input.hook_event_name.as_str() {
        // A compaction goes on in the same thread; every other start is a new selection.
        "SessionStart" if input.source.as_deref() == Some("compact") => {
            ("thread_continued", input.source.as_deref())
        }
        "SessionStart" => ("thread_started", input.source.as_deref()),
        "SessionEnd" => ("thread_ended", input.reason.as_deref()),
        "PostToolUse" => ("tool_finished", input.tool_name.as_deref()),
        "PostToolUseFailure" => ("tool_failed", input.tool_name.as_deref()),
        "Notification" => ("notification", input.notification_type.as_deref()),
        _ => return None,
    };
    let mut reported = serde_json::Map::new();
    reported.insert("event".to_owned(), serde_json::json!(event));
    reported.insert("thread".to_owned(), serde_json::json!(thread.as_str()));
    if let Some(detail) = detail {
        reported.insert(
            "detail".to_owned(),
            serde_json::json!(bounded(detail, MAX_DETAIL_BYTES)),
        );
    }
    if event == "notification"
        && let Some(message) = &input.message
    {
        reported.insert(
            "text".to_owned(),
            serde_json::json!(bounded(message, MAX_TEXT_BYTES)),
        );
    }
    if event == "tool_finished"
        && let Some(request) = contact_request(input)
    {
        reported.insert("contact_request".to_owned(), serde_json::json!(request));
    }
    Some(serde_json::json!({ "kr_observation": reported }))
}

/// The request identifier of the contact skill's `ask_user` call, when this finished tool call was
/// one.
///
/// Claude Code names an MCP server's tool `mcp__<server>__<tool>`, and the contact skill's server
/// is registered as [`kr_protocol::skill::SERVER_NAME`]. Where Claude Code also reports the server
/// by name, the two must agree.
fn contact_request(input: &HookInput) -> Option<&str> {
    let expected = format!("mcp__{}__ask_user", kr_protocol::skill::SERVER_NAME);
    if input.tool_name.as_deref() != Some(expected.as_str()) {
        return None;
    }
    if let Some(named) = input
        .mcp_server
        .as_ref()
        .and_then(|server| server.name.as_deref())
        && named != kr_protocol::skill::SERVER_NAME
    {
        return None;
    }
    input
        .tool_request_id
        .as_deref()
        .filter(|request| !request.trim().is_empty() && request.len() <= MAX_CONTACT_REQUEST_BYTES)
}

/// Cuts text to at most `limit` bytes, at a character boundary.
fn bounded(text: &str, limit: usize) -> &str {
    if text.len() <= limit {
        return text;
    }
    let mut end = limit;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

/// Reads the `request_id` member of a tool's input without holding the rest of it.
fn request_id_in<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserializer.deserialize_any(RequestIdIn)
}

struct RequestIdIn;

impl<'de> serde::de::Visitor<'de> for RequestIdIn {
    type Value = Option<String>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a tool's input")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        let mut found = None;
        while let Some(key) = map.next_key::<String>()? {
            if key == "request_id" {
                found = match map.next_value::<serde_json::Value>()? {
                    serde_json::Value::String(text) => Some(text),
                    _ => None,
                };
            } else {
                map.next_value::<serde::de::IgnoredAny>()?;
            }
        }
        Ok(found)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        while sequence.next_element::<serde::de::IgnoredAny>()?.is_some() {}
        Ok(None)
    }

    fn visit_bool<E>(self, _: bool) -> Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_i64<E>(self, _: i64) -> Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_u64<E>(self, _: u64) -> Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_str<E>(self, _: &str) -> Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(None)
    }
}

/// Writes the neutral answer and ends with the code that blocks nothing.
fn answer() -> std::process::ExitCode {
    use std::io::Write as _;
    let mut output = std::io::stdout().lock();
    let _ = writeln!(output, "{NEUTRAL_ANSWER}");
    let _ = output.flush();
    std::process::ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    fn translated(payload: &serde_json::Value) -> Option<serde_json::Value> {
        let input = read_input(payload.to_string().as_bytes()).expect("a hook's input");
        observation(&input).map(|frame| frame["kr_observation"].clone())
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

    /// Only a session starting or ending is held back, and never past the deadline.
    #[test]
    fn a_thread_report_is_held_two_ticks_and_inside_the_deadline() {
        assert!(THREAD_REPORT_LINGER < HOOK_DEADLINE);
        for (event, held) in [
            ("SessionStart", true),
            ("SessionEnd", true),
            ("PostToolUse", false),
            ("PostToolUseFailure", false),
            ("Notification", false),
        ] {
            let input = read_input(
                serde_json::json!({"session_id": "t", "hook_event_name": event})
                    .to_string()
                    .as_bytes(),
            )
            .expect("a hook's input");
            assert_eq!(reports_thread(&input), held, "{event}");
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
        assert!(read_input(&b"not json"[..]).is_err());
        assert!(read_input(&br#"{"hook_event_name":"SessionStart"}"#[..]).is_err());
    }

    #[test]
    fn long_text_is_cut_at_a_character_boundary() {
        let message = format!("{}{}", "x".repeat(MAX_TEXT_BYTES - 1), "\u{00e9}");
        let payload = serde_json::json!({"session_id": "s", "hook_event_name": "Notification",
            "message": message, "notification_type": "y".repeat(MAX_DETAIL_BYTES + 10)});
        let reported = translated(&payload).expect("an observation");
        let text = reported["text"].as_str().expect("text");
        assert_eq!(
            text.len(),
            MAX_TEXT_BYTES - 1,
            "the two-byte character did not fit"
        );
        assert_eq!(
            reported["detail"].as_str().expect("detail").len(),
            MAX_DETAIL_BYTES
        );
    }
}
