//! One observing hook, for every application whose registration starts the forwarder as one.
//!
//! A hook here observes. Whatever happens, the forwarder writes exactly `{}` to standard output and
//! exits 0, promptly: a JSON object with no members is the neutral answer on every event of every
//! application this serves, and exit 0 is the code that neither blocks nor reports an error. It
//! never answers with a decision, never prints anything a hook's output could be read as, and
//! never waits for a person.
//!
//! What differs between applications is an [`Application`]: the name the bridge declares, and what
//! each event its registration names reports. The deadline, the input bound, the exchange with the
//! worker and the answer are this module's, the same for all of them.
//!
//! Every run waits for its observation for at most [`HOOK_DEADLINE`] from its start, well inside the
//! shortest timeout any registration names (one second, for a session ending). When that passes,
//! the answer is written and the process ends, whatever is still in flight. The answer goes before
//! anything the run says about itself: a diagnostic goes to standard error after it, and is waited
//! for only until the same deadline, so a standard error nobody reads can hold neither the answer
//! nor the end.

use std::time::Duration;

use crate::exchange::Exchange;
use crate::registration::{Bridge, Paths, Registration};

/// The surface every hook declares itself to the worker as.
pub const SURFACE: &str = "hook";

/// How long a hook waits for its observation, from its start, before it answers anyway. A
/// diagnostic written after the answer is waited for only until the same moment.
///
/// Every registration gives a session ending one second and every other event five. An
/// application cancels a hook that reaches its timeout and discards its output, and Gemini CLI
/// also warns the person, so the deadline sits well inside the shorter one.
pub const HOOK_DEADLINE: Duration = Duration::from_millis(500);

/// The most of a hook's input this forwarder reads.
///
/// A finished tool's event carries the tool's whole response, which can be large. It is read to
/// its end so the application's write completes, and past this bound it is left unread.
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

/// How long a hook waits for the worker to finish publishing its launch.
///
/// The worker writes the registration as soon as it knows which process it started, long before
/// the application runs its first hook, so this only covers a hook that races the launch itself.
pub const REGISTRATION_WAIT: Duration = Duration::from_millis(250);

/// The longest detail an observation carries, which is the host's own bound.
pub const MAX_DETAIL_BYTES: usize = 256;

/// The longest text an observation carries, which is the host's own bound.
pub const MAX_TEXT_BYTES: usize = 4096;

/// The longest contact request identifier, which is the longest a question's own may be.
pub const MAX_CONTACT_REQUEST_BYTES: usize = 256;

/// One application's hooks, as the runner serves them.
#[derive(Debug)]
pub struct Application {
    /// The application name its registration invokes the forwarder with, which is also the
    /// application its bridge declares to the worker.
    pub name: &'static str,
    /// The events its registration names, each with what it reports. An event not named here is
    /// answered and reports nothing.
    pub events: &'static [(&'static str, Report)],
}

impl Application {
    /// What an event reports, where this application's registration names it.
    #[must_use]
    pub fn report(&self, event: &str) -> Option<Report> {
        self.events
            .iter()
            .find(|(name, _)| *name == event)
            .map(|(_, report)| *report)
    }

    /// The bridge a hook of this application declares.
    #[must_use]
    pub const fn bridge(&self) -> Bridge {
        Bridge {
            application: self.name,
            surface: SURFACE,
        }
    }
}

/// What one registered event reports to the worker.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Report {
    /// A session starting, with how it started as its detail: a new selection of its thread.
    SessionStarted {
        /// The start source that means the same thread goes on in a new context of its own, as a
        /// compaction makes, rather than a new selection; `None` where no start does.
        continued_by: Option<&'static str>,
    },
    /// A session ending, with why as its detail.
    SessionEnded,
    /// A tool finishing, with its name as its detail and, for the contact skill's `ask_user`, the
    /// request it asked.
    ToolFinished,
    /// A tool failing, with its name as its detail.
    ToolFailed,
    /// A notification, with its kind as its detail and its message as its text.
    Notification,
}

/// Runs one hook of `application` and answers neutrally.
#[must_use]
pub fn run(application: &'static Application) -> std::process::ExitCode {
    let started = std::time::Instant::now();
    let (finished, outcome) = std::sync::mpsc::channel();
    // The work runs on its own thread so the deadline is kept whatever it is waiting on. When the
    // deadline passes, the answer is written and the process ends, which ends that thread too.
    std::thread::spawn(move || {
        let _ = finished.send(observe(application, started));
    });
    // The wait ends the deadline after the hook's own start, not after the thread above started.
    let failure = match outcome.recv_timeout(HOOK_DEADLINE.saturating_sub(started.elapsed())) {
        Ok(Ok(())) => None,
        Ok(Err(failure)) => Some(failure),
        Err(_) => Some(format!(
            "the hook did not finish within {} ms, and answered anyway",
            HOOK_DEADLINE.as_millis()
        )),
    };
    // The application waits for the answer, and a standard error nobody reads can hold a write to
    // it for as long as nobody reads it. So the answer goes first, and the diagnostic gets what
    // remains of the deadline and no more.
    answer();
    if let Some(failure) = failure {
        crate::report_by(&failure, started + HOOK_DEADLINE);
    }
    std::process::ExitCode::SUCCESS
}

/// Reads the event the application wrote and, inside a launch, reaches the worker with it.
///
/// The observation goes straight behind the hello. The worker reads nothing past the hello until
/// it has admitted the connection, and then reads the observation, applies it and closes the
/// connection. This waits for that close, so an observation that selects a thread has been applied
/// before the hook returns to the application, which may hold a session's first response until
/// its session-start hooks have finished. A thread's report is then held until
/// [`THREAD_REPORT_LINGER`] after `started`.
fn observe(application: &Application, started: std::time::Instant) -> Result<(), String> {
    let input = read_input(std::io::stdin().lock())?;
    // Outside a launch there is nobody to tell, and the answer is the same neutral one.
    let Some(paths) = Paths::from_environment() else {
        return Ok(());
    };
    let Some(observation) = observation(application, &input) else {
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
            let mut exchange = Exchange::open(&registration, application.bridge()).await?;
            deliver(&mut exchange, &observation).await
        })
        .map_err(|error| error.to_string())?;
    if reports_thread(application, &input) {
        std::thread::sleep(THREAD_REPORT_LINGER.saturating_sub(started.elapsed()));
    }
    Ok(())
}

/// Delivers one observation over an exchange whose hello has just been written, and waits until the
/// worker has applied it.
///
/// The observation goes straight behind the hello. A worker that refuses the hello closes the
/// connection without reading anything past it, and that close can land before the observation is
/// written, so the write then finds the connection gone. That is the refusal arriving first, not a
/// failure of the write's own: what the worker answered is read before the write's outcome counts,
/// so a refusal is reported as one, and a write that failed on a connection the worker admitted is
/// still reported as the failure it is.
async fn deliver(
    exchange: &mut Exchange,
    observation: &serde_json::Value,
) -> Result<(), crate::exchange::ExchangeError> {
    let sent = exchange.send(observation).await;
    exchange.admitted(HOOK_DEADLINE).await?;
    sent?;
    // The worker closes the connection once it has applied the observation.
    while exchange.receive().await?.is_some() {}
    Ok(())
}

/// Whether the event is one the worker decides the thread by: a session starting or ending.
fn reports_thread(application: &Application, input: &HookInput) -> bool {
    matches!(
        application.report(&input.hook_event_name),
        Some(Report::SessionStarted { .. } | Report::SessionEnded)
    )
}

/// What this forwarder reads of a hook's input, whichever application wrote it.
///
/// Every application names the session and the event; the rest is read where the event carries
/// it. Everything else in the payload, a tool's whole response included, is skipped as it is read
/// and never held.
#[derive(Debug, Default, serde::Deserialize)]
pub struct HookInput {
    /// The session the event happened in, which is the thread KalaReach binds to.
    pub session_id: String,
    /// Which event this is.
    pub hook_event_name: String,
    /// How a session started.
    #[serde(default)]
    pub source: Option<String>,
    /// Why a session ended.
    #[serde(default)]
    pub reason: Option<String>,
    /// The tool that ran.
    #[serde(default)]
    pub tool_name: Option<String>,
    /// The `request_id` member of the tool's input, where it has a string one.
    #[serde(default, rename = "tool_input", deserialize_with = "request_id_in")]
    pub tool_request_id: Option<String>,
    /// The MCP server the tool came from, as Claude Code names it.
    #[serde(default)]
    pub mcp_server: Option<McpServer>,
    /// The MCP server and tool the tool call went to, as Qoder CLI names them.
    #[serde(default)]
    pub mcp_context: Option<McpContext>,
    /// Which notification this is.
    #[serde(default)]
    pub notification_type: Option<String>,
    /// The notification's text.
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

/// The MCP server and tool a tool call went to, as Qoder CLI names them.
#[derive(Debug, Default, serde::Deserialize)]
pub struct McpContext {
    /// The server's name.
    #[serde(default)]
    pub server_name: Option<String>,
    /// The tool's own name on that server.
    #[serde(default)]
    pub tool_name: Option<String>,
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

/// Translates one hook's input into the observation the worker reads, or `None` for an event the
/// application's registration does not name, or input that names no thread.
///
/// A session starting or ending selects or ends the thread, and a start the application marks as
/// a continuation goes on in it; a tool finishing or failing and a notification are recorded as
/// observed history. A finished call of the contact skill's `ask_user` also names the request it
/// asked, so the worker learns which thread the question was asked in.
#[must_use]
pub fn observation(application: &Application, input: &HookInput) -> Option<serde_json::Value> {
    let report = application.report(&input.hook_event_name)?;
    let thread = kr_protocol::ids::AgentThreadId::new(input.session_id.clone()).ok()?;
    let (event, detail) = match report {
        Report::SessionStarted {
            continued_by: Some(continuation),
        } if input.source.as_deref() == Some(continuation) => {
            ("thread_continued", input.source.as_deref())
        }
        Report::SessionStarted { .. } => ("thread_started", input.source.as_deref()),
        Report::SessionEnded => ("thread_ended", input.reason.as_deref()),
        Report::ToolFinished => ("tool_finished", input.tool_name.as_deref()),
        Report::ToolFailed => ("tool_failed", input.tool_name.as_deref()),
        Report::Notification => ("notification", input.notification_type.as_deref()),
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
    if report == Report::Notification
        && let Some(message) = &input.message
    {
        reported.insert(
            "text".to_owned(),
            serde_json::json!(bounded(message, MAX_TEXT_BYTES)),
        );
    }
    if report == Report::ToolFinished
        && let Some(request) = contact_request(input)
    {
        reported.insert("contact_request".to_owned(), serde_json::json!(request));
    }
    Some(serde_json::json!({ "kr_observation": reported }))
}

/// The request identifier of the contact skill's `ask_user` call, when this finished tool call was
/// one.
///
/// Claude Code and Qoder CLI both name an MCP server's tool `mcp__<server>__<tool>`, and the
/// contact skill's server is registered as [`kr_protocol::skill::SERVER_NAME`]. Where the
/// application also names the server, or the tool on it, every name it gives must agree.
fn contact_request(input: &HookInput) -> Option<&str> {
    let server = kr_protocol::skill::SERVER_NAME;
    let expected = format!("mcp__{server}__ask_user");
    if input.tool_name.as_deref() != Some(expected.as_str()) {
        return None;
    }
    let named = [
        input
            .mcp_server
            .as_ref()
            .and_then(|named| named.name.as_deref()),
        input
            .mcp_context
            .as_ref()
            .and_then(|named| named.server_name.as_deref()),
    ];
    if named.into_iter().flatten().any(|name| name != server) {
        return None;
    }
    if input
        .mcp_context
        .as_ref()
        .and_then(|named| named.tool_name.as_deref())
        .is_some_and(|tool| tool != "ask_user")
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

/// Writes the neutral answer and flushes it, so the application has it before anything else the
/// run does.
fn answer() {
    use std::io::Write as _;
    let mut output = std::io::stdout().lock();
    let _ = writeln!(output, "{NEUTRAL_ANSWER}");
    let _ = output.flush();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every application this forwarder serves.
    const EVERY: [&Application; 3] = [
        &crate::claude_code::HOOKS,
        &crate::gemini_cli::HOOKS,
        &crate::qoder_cli::HOOKS,
    ];

    fn translated(
        application: &Application,
        payload: &serde_json::Value,
    ) -> Option<serde_json::Value> {
        let input = read_input(payload.to_string().as_bytes()).expect("a hook's input");
        observation(application, &input).map(|frame| frame["kr_observation"].clone())
    }

    /// Each application declares itself under its own name, as the `hook` surface, and names each
    /// event it registers once.
    #[test]
    fn each_application_declares_its_own_hook_bridge() {
        let names: Vec<&str> = EVERY.iter().map(|application| application.name).collect();
        assert_eq!(names, ["claude-code", "gemini-cli", "qoder-cli"]);
        for application in EVERY {
            assert_eq!(application.bridge().application, application.name);
            assert_eq!(application.bridge().surface, "hook");
            let mut events: Vec<&str> = application.events.iter().map(|(name, _)| *name).collect();
            let registered = events.len();
            events.sort_unstable();
            events.dedup();
            assert_eq!(events.len(), registered, "{}", application.name);
        }
    }

    /// Only a session starting or ending is held back, and never past the deadline, for every
    /// application.
    #[test]
    fn a_thread_report_is_held_two_ticks_and_inside_the_deadline() {
        assert!(THREAD_REPORT_LINGER < HOOK_DEADLINE);
        for application in EVERY {
            for (event, report) in application.events {
                let input = read_input(
                    serde_json::json!({"session_id": "t", "hook_event_name": event})
                        .to_string()
                        .as_bytes(),
                )
                .expect("a hook's input");
                assert_eq!(
                    reports_thread(application, &input),
                    matches!(report, Report::SessionStarted { .. } | Report::SessionEnded),
                    "{} {event}",
                    application.name
                );
            }
        }
    }

    /// A start is a continuation only where the application names the source that makes one, and
    /// only from that source.
    #[test]
    fn a_continuation_is_the_named_source_and_nothing_else() {
        const WITHOUT: Application = Application {
            name: "no-continuation",
            events: &[(
                "SessionStart",
                Report::SessionStarted { continued_by: None },
            )],
        };
        const WITH: Application = Application {
            name: "continuation",
            events: &[(
                "SessionStart",
                Report::SessionStarted {
                    continued_by: Some("compact"),
                },
            )],
        };
        for (application, source, event) in [
            (&WITHOUT, "compact", "thread_started"),
            (&WITH, "compact", "thread_continued"),
            (&WITH, "Compact", "thread_started"),
            (&WITH, "resume", "thread_started"),
        ] {
            let reported = translated(
                application,
                &serde_json::json!({"session_id": "s", "hook_event_name": "SessionStart", "source": source}),
            )
            .expect("an observation");
            assert_eq!(reported["event"], event, "{} {source}", application.name);
        }
    }

    /// A finished `ask_user` call of the contact skill names its request only when every name the
    /// application gives for the server and the tool agrees, whether it names the server as Claude
    /// Code does or as Qoder CLI does.
    #[test]
    fn a_contact_request_is_named_only_when_every_name_agrees() {
        const FINISHED: Application = Application {
            name: "tools",
            events: &[("PostToolUse", Report::ToolFinished)],
        };
        let asked = |tool: &str, extra: serde_json::Value| {
            let mut payload = serde_json::json!({"session_id": "s", "hook_event_name": "PostToolUse",
                "tool_name": tool, "tool_input": {"request_id": "r-7f3a", "question": "which?"}});
            for (key, value) in extra.as_object().expect("members") {
                payload[key] = value.clone();
            }
            translated(&FINISHED, &payload).expect("an observation")["contact_request"].clone()
        };
        for extra in [
            serde_json::json!({}),
            serde_json::json!({"mcp_server": {"name": "kalareach"}}),
            serde_json::json!({"mcp_context": {"server_name": "kalareach", "tool_name": "ask_user"}}),
            serde_json::json!({"mcp_context": {"server_name": "kalareach"}}),
            serde_json::json!({"mcp_server": {"name": "kalareach"},
                "mcp_context": {"server_name": "kalareach", "tool_name": "ask_user"}}),
        ] {
            assert_eq!(
                asked("mcp__kalareach__ask_user", extra.clone()),
                "r-7f3a",
                "{extra}"
            );
        }
        for (tool, extra) in [
            (
                "mcp__kalareach__ask_user",
                serde_json::json!({"mcp_server": {"name": "elsewhere"}}),
            ),
            (
                "mcp__kalareach__ask_user",
                serde_json::json!({"mcp_context": {"server_name": "elsewhere", "tool_name": "ask_user"}}),
            ),
            (
                "mcp__kalareach__ask_user",
                serde_json::json!({"mcp_context": {"server_name": "kalareach", "tool_name": "wait_for_answer"}}),
            ),
            (
                "mcp__kalareach__ask_user",
                serde_json::json!({"mcp_server": {"name": "kalareach"},
                    "mcp_context": {"server_name": "elsewhere"}}),
            ),
            ("mcp_kalareach_ask_user", serde_json::json!({})),
            ("mcp__other__ask_user", serde_json::json!({})),
        ] {
            assert!(asked(tool, extra.clone()).is_null(), "{tool} {extra}");
        }
    }

    #[test]
    fn long_text_is_cut_at_a_character_boundary() {
        const NOTIFIED: Application = Application {
            name: "notifications",
            events: &[("Notification", Report::Notification)],
        };
        let message = format!("{}{}", "x".repeat(MAX_TEXT_BYTES - 1), "\u{00e9}");
        let payload = serde_json::json!({"session_id": "s", "hook_event_name": "Notification",
            "message": message, "notification_type": "y".repeat(MAX_DETAIL_BYTES + 10)});
        let reported = translated(&NOTIFIED, &payload).expect("an observation");
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

    /// A worker that refuses a hello closes the connection without reading what follows it, and
    /// that close can land before the observation behind the hello is written. The write then
    /// finds the connection gone, and the hook still says the worker refused it rather than that
    /// the write failed.
    ///
    /// The order is made here rather than waited for: the worker's end reads the hello and closes
    /// before the observation is delivered at all.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_refusal_that_closes_before_the_observation_is_written_is_reported_as_one() {
        use std::os::unix::fs::PermissionsExt as _;
        use tokio::io::AsyncBufReadExt as _;

        let host = kr_ipc::testing::TempHost::create();
        let endpoint = host.root().join("endpoint");
        let listener = tokio::net::UnixListener::bind(&endpoint).expect("the endpoint binds");
        let paths = crate::registration::Paths {
            registration: host.root().join("registration"),
        };
        let credential = host.root().join("credential");
        std::fs::write(&credential, "0".repeat(64)).expect("the credential");
        std::fs::set_permissions(&credential, std::fs::Permissions::from_mode(0o600))
            .expect("the credential is the owner's alone");
        std::fs::write(
            &paths.registration,
            format!(
                "endpoint={}\nprofile=p\ninstance=i\npid=1\nstart=1\ncredential={}\n\
                 framing=json_lines\n",
                endpoint.display(),
                credential.display()
            ),
        )
        .expect("the registration");
        let registration =
            Registration::read(&paths, Duration::from_secs(5)).expect("the registration reads");

        let mut exchange = Exchange::open(&registration, crate::claude_code::HOOKS.bridge())
            .await
            .expect("the hook connects and writes its hello");
        let (worker, _) = listener.accept().await.expect("the worker accepts");
        let mut worker = tokio::io::BufReader::new(worker);
        let mut hello = Vec::new();
        worker
            .read_until(b'\n', &mut hello)
            .await
            .expect("the hello arrives");
        assert!(hello.starts_with(br#"{"kr_hello":"#), "{hello:?}");
        // Refused: closed without a word, before anything behind the hello is read.
        drop(worker);

        let observation = serde_json::json!({"kr_observation": {"event": "thread_started"}});
        let delivered = deliver(&mut exchange, &observation).await;
        assert!(
            matches!(delivered, Err(crate::exchange::ExchangeError::Refused)),
            "the hook reports a refusal as a refusal: {delivered:?}"
        );
    }
}
