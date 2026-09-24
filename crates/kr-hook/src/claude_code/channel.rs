//! Claude Code's Channels server.
//!
//! Claude Code starts `kr-hook claude-code channel` as an MCP server over this process's standard
//! input and output. The forwarder terminates MCP here: the handshake, the version negotiation and
//! the capability declaration are this module's, and only the Channels frames cross to the worker,
//! over the private exchange, one JSON line each:
//!
//! | Frame | Direction | What this module checks |
//! | --- | --- | --- |
//! | `notifications/claude/channel` | worker to Claude Code | `content` is text; `meta` holds only text under identifier keys |
//! | `notifications/claude/channel/permission_request` | Claude Code to worker | the four documented fields are text; the identifier is five letters of Claude Code's alphabet |
//! | `notifications/claude/channel/permission` | worker to Claude Code | `behavior` is `allow` or `deny`; `request_id` is one this channel relayed and has not answered |
//!
//! A frame that fails its check is not forwarded, and nothing is ever turned into another kind of
//! frame: a verdict that is malformed or names a request this channel did not relay is dropped
//! here, and never reaches the session as a message. The worker's own arbitration decides which
//! answer goes; this is the last check before the bytes leave KalaReach.
//!
//! The server declares the Channels capabilities only when the worker admitted it. Outside a launch
//! it completes the handshake and declares nothing, because nothing stands behind it.
//!
//! The protocol revision is held below `2026-07-28`, because the Channels documentation says Claude
//! Code does not register a channel server that negotiates that revision on its v2 MCP client
//! runtime.

use std::borrow::Cow;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rmcp::model::{
    CustomNotification, Implementation, ProtocolVersion, ServerCapabilities, ServerConfig,
    ServerNotification,
};
use rmcp::service::{NotificationContext, QuitReason, RoleServer};
use rmcp::{ServerHandler, ServiceExt as _};

use crate::exchange::{Exchange, MAX_MESSAGE_BYTES};
use crate::registration::{Bridge, Paths, Registration};

/// The name this server introduces itself by.
pub const SERVER_NAME: &str = "kalareach";

/// The newest MCP protocol revision this server negotiates.
///
/// Claude Code registers no channel server that negotiates `2026-07-28` on its v2 MCP client
/// runtime, so the newest revision this server offers is the one before it.
pub const NEWEST_REVISION: ProtocolVersion = ProtocolVersion::V_2025_11_25;

/// A message delivered into the session.
pub const CHANNEL_EVENT: &str = "notifications/claude/channel";

/// A tool approval Claude Code relays out.
pub const PERMISSION_REQUEST: &str = "notifications/claude/channel/permission_request";

/// The answer to one relayed tool approval.
pub const PERMISSION_VERDICT: &str = "notifications/claude/channel/permission";

/// How long the channel waits for the worker to finish publishing its launch.
///
/// Claude Code starts its channel servers when its session starts, which is after the worker wrote
/// the registration for the launch, so this only covers a start that races the launch itself.
pub const REGISTRATION_WAIT: Duration = Duration::from_secs(5);

/// How long the channel waits for the worker to admit it before Claude Code is answered.
pub const ADMISSION_DEADLINE: Duration = Duration::from_secs(10);

/// How many relayed approvals the channel remembers, waiting for their answer.
///
/// Claude Code holds one approval dialog open at a time per session, so the bound is generous. The
/// oldest is forgotten first, and a verdict for a forgotten request is refused like any other
/// verdict for a request this channel did not relay.
pub const MAX_RELAYED_REQUESTS: usize = 64;

/// How long a closing channel gives the worker's direction to finish what was already relayed.
const CLOSING: Duration = Duration::from_secs(1);

/// The length of a request identifier Claude Code issues.
pub const REQUEST_ID_LENGTH: usize = 5;

/// What the channel declares itself to the worker as.
const BRIDGE: Bridge = Bridge {
    application: super::APPLICATION,
    surface: "channel",
};

/// What Claude Code tells the model about this channel when the server connects.
const INSTRUCTIONS: &str = "Messages arrive as <channel source=\"kalareach\">. Each is a message \
    from the person running this KalaReach session, sent from another device, and reads as their \
    own words in the terminal would. This channel has no reply tool: answer in the session as you \
    normally would.";

/// Runs the server until Claude Code closes its end, or the worker closes the channel.
#[must_use]
pub fn run() -> std::process::ExitCode {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            crate::report(&format!("the channel could not start: {error}"));
            return std::process::ExitCode::from(crate::cli::EXIT_FAILURE);
        }
    };
    let outcome = runtime.block_on(serve());
    // A read of standard input that is still waiting runs on a blocking thread nothing can
    // interrupt, and a runtime that is dropped waits for it. The process is ending, so the runtime
    // is not waited for: when the worker ends the channel, Claude Code's end may still be open.
    runtime.shutdown_background();
    match outcome {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(failure) => {
            crate::report(&failure);
            std::process::ExitCode::from(crate::cli::EXIT_FAILURE)
        }
    }
}

/// Finds the worker, when this process is inside a launch, and is admitted by it.
///
/// This happens before Claude Code's handshake is answered, so the capabilities Claude Code is
/// told are the ones that hold.
async fn connect() -> Result<Option<Exchange>, String> {
    let Some(paths) = Paths::from_environment() else {
        return Ok(None);
    };
    let registration =
        Registration::read(&paths, REGISTRATION_WAIT).map_err(|error| error.to_string())?;
    let mut exchange = Exchange::open(&registration, BRIDGE)
        .await
        .map_err(|error| error.to_string())?;
    exchange
        .admitted(ADMISSION_DEADLINE)
        .await
        .map_err(|error| error.to_string())?;
    Ok(Some(exchange))
}

async fn serve() -> Result<(), String> {
    let exchange = connect().await?;
    let relayed = Arc::new(Mutex::new(Relayed::default()));
    let (to_worker, mut from_claude) = tokio::sync::mpsc::channel(MAX_RELAYED_REQUESTS);
    let channel = Channel {
        to_worker: exchange.is_some().then_some(to_worker),
        relayed: Arc::clone(&relayed),
    };
    let transport = rmcp::transport::async_rw::AsyncRwTransport::new_server(
        tokio::io::stdin(),
        tokio::io::stdout(),
    );
    let service = channel
        .serve(transport)
        .await
        .map_err(|error| format!("the MCP session could not start: {error}"))?;
    let Some(exchange) = exchange else {
        service
            .waiting()
            .await
            .map_err(|error| format!("the MCP session ended badly: {error}"))?;
        return Ok(());
    };

    let (mut incoming, mut outgoing) = exchange.split();
    // Claude Code to the worker: what the handler relayed, in the order it arrived.
    let sending = tokio::spawn(async move {
        while let Some(frame) = from_claude.recv().await {
            if let Err(error) = outgoing.send(&frame).await {
                return Err(error.to_string());
            }
        }
        outgoing.close().await;
        Ok(())
    });
    // The worker to Claude Code: each frame checked, and forwarded only when it passes.
    let peer = service.peer().clone();
    let stop = service.cancellation_token();
    let receiving = tokio::spawn(async move {
        let ended = loop {
            match incoming.receive().await {
                Ok(Some(frame)) => match to_claude(&frame, &relayed) {
                    Ok(notification) => {
                        if peer.send_notification(notification).await.is_err() {
                            break None;
                        }
                    }
                    Err(refusal) => crate::report(&format!("not forwarded: {refusal}")),
                },
                Ok(None) => break Some("the worker closed the channel".to_owned()),
                Err(error) => break Some(error.to_string()),
            }
        };
        // The worker's end is gone, so the session with Claude Code ends with it. A send to Claude
        // Code that failed is its own end closing, which ends the session by itself.
        if ended.is_some() {
            stop.cancel();
        }
        ended
    });

    let quit = service
        .waiting()
        .await
        .map_err(|error| format!("the MCP session ended badly: {error}"))?;
    match quit {
        // The worker ended the channel, so the session with Claude Code ends with it.
        QuitReason::Cancelled => {
            let ended = receiving.await.ok().flatten();
            sending.abort();
            Err(ended.unwrap_or_else(|| "the channel ended".to_owned()))
        }
        // Claude Code closed its end: the channel is done, and the worker reads its end. What
        // Claude Code relayed before it closed goes out if it can, within a bounded moment.
        _ => {
            receiving.abort();
            let mut sending = sending;
            if tokio::time::timeout(CLOSING, &mut sending).await.is_err() {
                sending.abort();
            }
            Ok(())
        }
    }
}

/// The MCP side of the channel.
#[derive(Clone)]
struct Channel {
    /// Where a relayed approval goes, when the worker admitted this channel.
    to_worker: Option<tokio::sync::mpsc::Sender<serde_json::Value>>,
    /// The approvals relayed and not yet answered.
    relayed: Arc<Mutex<Relayed>>,
}

impl ServerHandler for Channel {
    fn get_info(&self) -> ServerConfig {
        let config = ServerConfig::new(capabilities(self.to_worker.is_some()))
            .with_server_info(Implementation::new(SERVER_NAME, env!("CARGO_PKG_VERSION")));
        if self.to_worker.is_some() {
            config.with_instructions(INSTRUCTIONS)
        } else {
            config
        }
    }

    fn supported_protocol_versions(&self) -> Cow<'static, [ProtocolVersion]> {
        Cow::Borrowed(ProtocolVersion::known_up_to(&NEWEST_REVISION))
    }

    async fn on_custom_notification(
        &self,
        notification: CustomNotification,
        _context: NotificationContext<RoleServer>,
    ) {
        if notification.method != PERMISSION_REQUEST {
            return;
        }
        let Some(to_worker) = &self.to_worker else {
            return;
        };
        match permission_request(notification.params.as_ref()) {
            Ok((frame, request_id)) => {
                self.relayed
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .record(request_id);
                let _ = to_worker.send(frame).await;
            }
            Err(refusal) => crate::report(&format!("not relayed: {refusal}")),
        }
    }
}

/// The capabilities this server declares: the Channels pair when the worker admitted it, and
/// nothing otherwise.
fn capabilities(connected: bool) -> ServerCapabilities {
    if !connected {
        return ServerCapabilities::default();
    }
    let mut experimental = std::collections::BTreeMap::new();
    experimental.insert("claude/channel".to_owned(), serde_json::Map::new());
    experimental.insert(
        "claude/channel/permission".to_owned(),
        serde_json::Map::new(),
    );
    ServerCapabilities::builder()
        .enable_experimental_with(experimental)
        .build()
}

/// The approvals this channel relayed and has not seen answered.
#[derive(Debug, Default)]
struct Relayed {
    waiting: VecDeque<String>,
}

impl Relayed {
    fn record(&mut self, request_id: String) {
        self.waiting.retain(|waiting| waiting != &request_id);
        self.waiting.push_back(request_id);
        while self.waiting.len() > MAX_RELAYED_REQUESTS {
            self.waiting.pop_front();
        }
    }

    /// Takes one request out, so it can be answered once.
    fn take(&mut self, request_id: &str) -> bool {
        let before = self.waiting.len();
        self.waiting.retain(|waiting| waiting != request_id);
        self.waiting.len() != before
    }
}

/// Returns true for an identifier of the shape Claude Code issues: five lowercase letters, without
/// `l`.
fn is_request_id(text: &str) -> bool {
    text.len() == REQUEST_ID_LENGTH
        && text
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() && byte != b'l')
}

/// Checks one relayed approval and builds the frame the worker reads, with its identifier.
///
/// Only the four documented fields are carried. Anything else Claude Code adds is left behind,
/// because the worker's table does not describe it.
fn permission_request(
    params: Option<&serde_json::Value>,
) -> Result<(serde_json::Value, String), String> {
    let params = params
        .and_then(serde_json::Value::as_object)
        .ok_or("a relayed approval carries no parameters")?;
    let field = |name: &str| {
        params
            .get(name)
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| format!("a relayed approval has no text {name}"))
    };
    let request_id = field("request_id")?;
    if !is_request_id(request_id) {
        return Err(format!(
            "a relayed approval's identifier {request_id:?} is not one Claude Code issues"
        ));
    }
    let frame = serde_json::json!({
        "jsonrpc": "2.0",
        "method": PERMISSION_REQUEST,
        "params": {
            "request_id": request_id,
            "tool_name": field("tool_name")?,
            "description": field("description")?,
            "input_preview": field("input_preview")?,
        },
    });
    let length = serde_json::to_vec(&frame).map_or(usize::MAX, |body| body.len());
    if length > MAX_MESSAGE_BYTES {
        return Err(format!(
            "a relayed approval of {length} bytes is past the exchange's bound, so it is answered \
             in the terminal"
        ));
    }
    Ok((frame, request_id.to_owned()))
}

/// Checks one frame the worker sent and builds the notification Claude Code reads.
///
/// A frame is the application's own notification: `method`, `params` and, optionally,
/// `"jsonrpc": "2.0"`, and nothing else. A verdict is checked in full before the request it
/// answers is taken, so a malformed verdict leaves the request answerable by a correct one.
fn to_claude(
    frame: &serde_json::Value,
    relayed: &Mutex<Relayed>,
) -> Result<ServerNotification, String> {
    let frame = frame.as_object().ok_or("a frame is not an object")?;
    if let Some(member) = frame
        .keys()
        .find(|member| !matches!(member.as_str(), "jsonrpc" | "method" | "params"))
    {
        return Err(format!(
            "a frame carries {member:?}, which no notification has"
        ));
    }
    if frame.get("jsonrpc").is_some_and(|version| version != "2.0") {
        return Err("a frame names a JSON-RPC version other than 2.0".to_owned());
    }
    let method = frame
        .get("method")
        .and_then(serde_json::Value::as_str)
        .ok_or("a frame names no method")?;
    let params = frame
        .get("params")
        .and_then(serde_json::Value::as_object)
        .ok_or("a frame carries no parameters")?;
    match method {
        CHANNEL_EVENT => check_channel_event(params)?,
        PERMISSION_VERDICT => check_verdict(params, relayed)?,
        other => {
            return Err(format!(
                "{other:?} is not a notification this channel carries"
            ));
        }
    }
    Ok(ServerNotification::CustomNotification(
        CustomNotification::new(method, Some(serde_json::Value::Object(params.clone()))),
    ))
}

fn check_channel_event(params: &serde_json::Map<String, serde_json::Value>) -> Result<(), String> {
    if let Some(member) = params
        .keys()
        .find(|member| !matches!(member.as_str(), "content" | "meta"))
    {
        return Err(format!(
            "a message carries {member:?}, which a message has not"
        ));
    }
    if !params
        .get("content")
        .is_some_and(serde_json::Value::is_string)
    {
        return Err("a message's content is not text".to_owned());
    }
    if let Some(meta) = params.get("meta") {
        let meta = meta
            .as_object()
            .ok_or("a message's meta is not an object")?;
        for (key, value) in meta {
            let identifier = !key.is_empty()
                && key
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_');
            if !identifier {
                return Err(format!(
                    "a message's meta key {key:?} is not letters, digits and underscores"
                ));
            }
            if !value.is_string() {
                return Err(format!("a message's meta value for {key:?} is not text"));
            }
        }
    }
    Ok(())
}

fn check_verdict(
    params: &serde_json::Map<String, serde_json::Value>,
    relayed: &Mutex<Relayed>,
) -> Result<(), String> {
    if let Some(member) = params
        .keys()
        .find(|member| !matches!(member.as_str(), "request_id" | "behavior"))
    {
        return Err(format!(
            "a verdict carries {member:?}, which a verdict has not"
        ));
    }
    let behavior = params.get("behavior").and_then(serde_json::Value::as_str);
    if !matches!(behavior, Some("allow" | "deny")) {
        return Err("a verdict's behavior is neither allow nor deny".to_owned());
    }
    let request_id = params
        .get("request_id")
        .and_then(serde_json::Value::as_str)
        .filter(|request_id| is_request_id(request_id))
        .ok_or("a verdict names no identifier Claude Code issues")?;
    let taken = relayed
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take(request_id);
    if !taken {
        return Err(format!(
            "a verdict names {request_id:?}, which this channel did not relay or has already \
             answered"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn relayed(ids: &[&str]) -> Mutex<Relayed> {
        let mut relayed = Relayed::default();
        for id in ids {
            relayed.record((*id).to_owned());
        }
        Mutex::new(relayed)
    }

    #[test]
    fn only_claude_codes_identifier_shape_is_an_identifier() {
        for accepted in ["abcde", "zzzzz", "kmnop"] {
            assert!(is_request_id(accepted), "{accepted}");
        }
        for refused in ["abcdl", "abcd", "abcdef", "ABCDE", "abc1e", "", "abcdé"] {
            assert!(!is_request_id(refused), "{refused}");
        }
    }

    #[test]
    fn a_relayed_approval_carries_its_four_fields_and_nothing_else() {
        let (frame, request_id) = permission_request(Some(&serde_json::json!({
            "request_id": "abcde",
            "tool_name": "Bash",
            "description": "Run shell command",
            "input_preview": "{\"command\":\"ls\"}",
            "added_later": "left behind",
        })))
        .expect("relayed");
        assert_eq!(request_id, "abcde");
        assert_eq!(
            frame,
            serde_json::json!({
                "jsonrpc": "2.0",
                "method": PERMISSION_REQUEST,
                "params": {
                    "request_id": "abcde",
                    "tool_name": "Bash",
                    "description": "Run shell command",
                    "input_preview": "{\"command\":\"ls\"}",
                },
            })
        );
        for refused in [
            serde_json::json!(null),
            serde_json::json!({"request_id": "abcde", "tool_name": "Bash", "description": "d"}),
            serde_json::json!({"request_id": "abcdl", "tool_name": "Bash", "description": "d", "input_preview": "p"}),
            serde_json::json!({"request_id": "abcde", "tool_name": 7, "description": "d", "input_preview": "p"}),
            serde_json::json!({"request_id": "abcde", "tool_name": "Bash", "description": "d",
                "input_preview": "x".repeat(MAX_MESSAGE_BYTES)}),
        ] {
            assert!(permission_request(Some(&refused)).is_err(), "{refused}");
        }
    }

    #[test]
    fn a_verdict_goes_once_for_a_request_this_channel_relayed() {
        let waiting = relayed(&["abcde"]);
        let verdict = |id: &str, behavior: &str| {
            serde_json::json!({"jsonrpc": "2.0", "method": PERMISSION_VERDICT,
                "params": {"request_id": id, "behavior": behavior}})
        };
        // A malformed verdict does not use the request up.
        assert!(to_claude(&verdict("abcde", "yes abcde"), &waiting).is_err());
        assert!(to_claude(&verdict("zzzzz", "allow"), &waiting).is_err());
        assert!(to_claude(&verdict("abcde", "allow"), &waiting).is_ok());
        assert!(
            to_claude(&verdict("abcde", "deny"), &waiting).is_err(),
            "a request is answered once"
        );
    }

    #[test]
    fn nothing_the_worker_sends_becomes_a_different_frame() {
        let waiting = relayed(&["abcde"]);
        let refused = [
            serde_json::json!({"method": CHANNEL_EVENT, "params": {"content": "hi", "extra": 1}}),
            serde_json::json!({"method": CHANNEL_EVENT, "params": {"content": 7}}),
            serde_json::json!({"method": CHANNEL_EVENT, "params": {"content": "hi", "meta": {"chat-id": "1"}}}),
            serde_json::json!({"method": CHANNEL_EVENT, "params": {"content": "hi", "meta": {"chat_id": 1}}}),
            serde_json::json!({"method": CHANNEL_EVENT, "params": {"content": "hi"}, "id": 3}),
            serde_json::json!({"jsonrpc": "1.0", "method": CHANNEL_EVENT, "params": {"content": "hi"}}),
            serde_json::json!({"method": "tools/call", "params": {"name": "reply"}}),
            serde_json::json!({"method": PERMISSION_VERDICT, "params": {"request_id": "abcde", "behavior": "allow", "note": "x"}}),
            serde_json::json!({"method": CHANNEL_EVENT}),
            serde_json::json!(["not", "an", "object"]),
        ];
        for frame in refused {
            assert!(to_claude(&frame, &waiting).is_err(), "{frame}");
        }
        let delivered = to_claude(
            &serde_json::json!({"method": CHANNEL_EVENT,
                "params": {"content": "build failed on main", "meta": {"chat_id": "1"}}}),
            &waiting,
        )
        .expect("a message goes");
        let ServerNotification::CustomNotification(delivered) = delivered else {
            panic!("a custom notification");
        };
        assert_eq!(delivered.method, CHANNEL_EVENT);
        assert_eq!(
            delivered.params,
            Some(serde_json::json!({"content": "build failed on main", "meta": {"chat_id": "1"}}))
        );
        // The refused verdict above did not use the relayed request up.
        assert!(waiting.lock().expect("the lock").take("abcde"));
    }

    #[test]
    fn the_channels_pair_is_declared_only_when_connected() {
        let declared = serde_json::to_value(capabilities(true)).expect("serialisable");
        assert_eq!(
            declared,
            serde_json::json!({"experimental": {"claude/channel": {}, "claude/channel/permission": {}}})
        );
        assert_eq!(
            serde_json::to_value(capabilities(false)).expect("serialisable"),
            serde_json::json!({})
        );
    }
}
