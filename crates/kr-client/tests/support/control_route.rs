//! The managed service's voice control route on loopback.
//!
//! The route answers as the service's contract states (`packages/service-contracts/src/voice.ts`
//! and the `LiveSession` object in the web repository's `workers/api/src/voice/service`): the
//! upgrade, `ready` first, a heartbeat answered with `heartbeat_ack`, a context request checked in
//! the service's order and answered `context_accepted` and then `context_admitted` or
//! `context_refused`, a request seen before answered from what the first was given, the rate,
//! usage, the closure. A test of a device that owns a call reaches it through the product's own
//! control client, over TCP and, where it chooses, over TLS from an authority the test issues.
//!
//! A test drives the route's faults (a refused upgrade, a dropped socket, a route that stops
//! answering, a provider that is unavailable) and reads what it saw, and waits for a condition
//! rather than a time: [`ControlRoute::until`].
//!
//! Suites in other crates include this module by its path rather than keep a copy of their own.

#![allow(
    dead_code,
    reason = "each suite that includes this module uses the part of it that it needs"
)]

use std::collections::{HashMap, VecDeque};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use kr_client::services::voice::VoiceSession;
use kr_client::services::voice_control::ControlTarget;
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{Notify, mpsc};
use tokio_rustls::TlsAcceptor;
use tokio_websockets::{Limits, Message, ServerBuilder};

/// How long the route waits for a client to answer its closing handshake.
const CLOSING_HANDSHAKE_WITHIN: Duration = Duration::from_secs(5);

/// The call the route holds.
pub const CALL: &str = "call-1";

/// The account token the route expects a device to present.
pub const TOKEN: &str = "account-token-1";

/// The path of the call's control socket.
pub const PATH: &str = "/api/voice/sessions/call-1/control";

/// How long a test waits for a condition before it fails as stuck.
pub const WATCHDOG: Duration = Duration::from_secs(20);

/// What the route sends to one socket besides its answers.
enum Outbound {
    Text(String),
    Binary(Vec<u8>),
    /// Ends the connection with no closing frame.
    Drop,
    /// Ends the connection with a closing frame.
    Close,
}

/// An upgrade the route accepted.
#[derive(Clone, Debug)]
pub struct Upgrade {
    pub path: String,
    pub authorization: Option<String>,
}

/// A request the route let through to the provider.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sent {
    pub id: String,
    pub command: String,
    pub delegation: Option<String>,
    pub content: Option<String>,
}

/// What the route has seen.
#[derive(Clone, Debug, Default)]
pub struct Report {
    /// Upgrades it accepted, in order.
    pub upgrades: Vec<Upgrade>,
    /// Upgrades it refused.
    pub refused_upgrades: usize,
    /// Sockets open now.
    pub open: usize,
    /// Heartbeats read.
    pub heartbeats: usize,
    /// Every text frame read from a device, whatever became of it.
    pub frames: Vec<String>,
    /// The requests it sent on to the provider, each once.
    pub sent: Vec<Sent>,
    /// The reasons it refused requests for, in order.
    pub refusals: Vec<String>,
    /// How many requests it recognised as ones it had seen.
    pub repeats: usize,
    /// How many times a request was refused for the rate.
    pub rate_refusals: usize,
}

struct State {
    // What the route does.
    refusals: VecDeque<u16>,
    refuse_all: Option<u16>,
    silent: bool,
    provider_down: bool,
    swallow_then_drop: bool,
    accept_then_drop: bool,
    drop_unread: bool,
    drop_after_ready: bool,
    closure_delay: Option<Duration>,
    admissions_twice: bool,
    announced: Vec<String>,
    ready_call: String,
    windows: (Duration, Duration),
    // What it remembers.
    sockets: Vec<(u64, mpsc::UnboundedSender<Outbound>)>,
    next_socket: u64,
    rate: VecDeque<Instant>,
    requests: HashMap<String, (String, Option<String>, usize)>,
    answers: HashMap<String, Value>,
    report: Report,
}

struct Shared {
    state: Mutex<State>,
    changed: Notify,
}

/// A route on loopback.
pub struct ControlRoute {
    origin: String,
    shared: Arc<Shared>,
}

impl ControlRoute {
    /// A route that serves plain sockets on a loopback address.
    pub async fn start() -> Self {
        Self::start_with(None, None).await
    }

    /// A route behind TLS from `authority`, and `windows` for its rate limits when they are not
    /// the service's own (the burst's, then the minute's).
    pub async fn start_with(
        tls: Option<TlsAcceptor>,
        windows: Option<(Duration, Duration)>,
    ) -> Self {
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .expect("a loopback port");
        let port = listener.local_addr().expect("an address").port();
        let scheme = if tls.is_some() { "https" } else { "http" };
        let route = Self::detached(format!("{scheme}://127.0.0.1:{port}"), windows);
        let serving = Arc::clone(&route.shared);
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let (shared, tls) = (Arc::clone(&serving), tls.clone());
                tokio::spawn(async move {
                    match tls {
                        Some(acceptor) => {
                            if let Ok(stream) = acceptor.accept(stream).await {
                                connection(shared, stream).await;
                            }
                        }
                        None => connection(shared, stream).await,
                    }
                });
            }
        });
        route
    }

    /// A route with no listener of its own, for a server that also answers other requests: it
    /// serves the streams it is handed ([`Self::serve`]), and says `origin` is where it answers.
    pub fn detached(origin: String, windows: Option<(Duration, Duration)>) -> Self {
        let shared = Arc::new(Shared {
            state: Mutex::new(State {
                refusals: VecDeque::new(),
                refuse_all: None,
                silent: false,
                provider_down: false,
                swallow_then_drop: false,
                accept_then_drop: false,
                drop_unread: false,
                drop_after_ready: false,
                closure_delay: None,
                admissions_twice: false,
                announced: Vec::new(),
                ready_call: CALL.to_owned(),
                windows: windows.unwrap_or((Duration::from_secs(10), Duration::from_secs(60))),
                sockets: Vec::new(),
                next_socket: 0,
                rate: VecDeque::new(),
                requests: HashMap::new(),
                answers: HashMap::new(),
                report: Report::default(),
            }),
            changed: Notify::new(),
        });
        Self { origin, shared }
    }

    /// Serves one connection a server accepted: the upgrade, and the socket after it.
    pub async fn serve<S>(&self, stream: S)
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        connection(Arc::clone(&self.shared), stream).await;
    }

    /// The origin the route answers on.
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// The control target of the call the route holds.
    pub fn target(&self) -> ControlTarget {
        ControlTarget::at(&self.origin, &self.origin, PATH, CALL).expect("a control target")
    }

    /// Announces a delegation: every open socket is told, and the next `ready` lists it.
    pub fn announce(&self, id: &str, offset_ms: u64) {
        self.edit(|state| state.announced.push(id.to_owned()));
        self.say(&json!({
            "type": "delegation",
            "delegationId": id,
            "offsetMs": offset_ms,
            "note": "A provider delegation identifier is correlation data."
        }));
    }

    /// The delegations the next `ready` lists, replacing the announced ones.
    pub fn list(&self, ids: Vec<String>) {
        self.edit(|state| state.announced = ids);
    }

    /// Sends a frame to every open socket.
    pub fn say(&self, frame: &Value) {
        self.say_text(&frame.to_string());
    }

    /// Sends the text to every open socket as one text frame.
    pub fn say_text(&self, text: &str) {
        self.each_socket(|socket| {
            let _ = socket.send(Outbound::Text(text.to_owned()));
        });
    }

    /// Sends bytes to every open socket as one binary frame.
    pub fn say_binary(&self, bytes: &[u8]) {
        self.each_socket(|socket| {
            let _ = socket.send(Outbound::Binary(bytes.to_vec()));
        });
    }

    /// Ends every open connection with no closing frame.
    pub fn drop_sockets(&self) {
        self.each_socket(|socket| {
            let _ = socket.send(Outbound::Drop);
        });
    }

    /// Refuses the next upgrades with these statuses, one each.
    pub fn refuse_next(&self, statuses: &[u16]) {
        self.edit(|state| state.refusals.extend(statuses.iter().copied()));
    }

    /// Refuses every upgrade with `status` until told not to.
    pub fn refuse_all(&self, status: Option<u16>) {
        self.edit(|state| state.refuse_all = status);
    }

    /// Reads everything and answers nothing.
    pub fn go_silent(&self, silent: bool) {
        self.edit(|state| state.silent = silent);
    }

    /// Refuses requests as the service does while its channel to the provider is down.
    pub fn provider_down(&self, down: bool) {
        self.edit(|state| state.provider_down = down);
    }

    /// Sends the next request on to the provider and drops the connection without answering it.
    pub fn swallow_next_request_and_drop(&self) {
        self.edit(|state| state.swallow_then_drop = true);
    }

    /// Accepts the next request and sends it on to the provider, then drops the connection before
    /// the provider's answer reaches the device.
    pub fn accept_next_request_and_drop_before_its_admission(&self) {
        self.edit(|state| state.accept_then_drop = true);
    }

    /// Drops the connection when the next request arrives, before the route has read it: the
    /// service never had it.
    pub fn drop_next_request_unread(&self) {
        self.edit(|state| state.drop_unread = true);
    }

    /// Ends every connection as soon as it has said `ready`, until told not to.
    pub fn drop_after_ready(&self, drop: bool) {
        self.edit(|state| state.drop_after_ready = drop);
    }

    /// Holds the service's answer to a closure for `delay` after it read the request, as a busy
    /// service does: the closure is read at once and confirmed late.
    pub fn confirm_closures_after(&self, delay: Duration) {
        self.edit(|state| state.closure_delay = Some(delay));
    }

    /// Sends the provider's admission of every request twice, as a socket opened just before the
    /// answer comes hears it when the service broadcasts it and again when it answers a repeat.
    pub fn send_admissions_twice(&self, twice: bool) {
        self.edit(|state| state.admissions_twice = twice);
    }

    /// Makes the next `ready` name another call.
    pub fn name_another_call(&self) {
        self.edit(|state| state.ready_call = "call-2".to_owned());
    }

    /// Reports a usage figure to every open socket.
    pub fn usage(&self, seconds: u64, provisional: bool) {
        self.say(&json!({ "type": "usage", "seconds": seconds, "provisional": provisional }));
    }

    /// Reports the call closed to every open socket and ends their connections.
    pub fn close_call(&self, reason: &str, seconds: u64) {
        self.say(&json!({
            "type": "closed", "reason": reason, "seconds": seconds, "provisional": false
        }));
        self.each_socket(|socket| {
            let _ = socket.send(Outbound::Close);
        });
    }

    /// What the route has seen so far.
    pub fn report(&self) -> Report {
        let state = self.shared.state.lock().expect("the route's state");
        let mut report = state.report.clone();
        report.open = state.sockets.len();
        report
    }

    /// Waits until `condition` holds of what the route has seen. Fails the test when it never
    /// does, which is a hung test and not a measurement.
    pub async fn until(&self, what: &str, condition: impl Fn(&Report) -> bool) -> Report {
        let waiting = async {
            loop {
                let changed = self.shared.changed.notified();
                tokio::pin!(changed);
                // Registered before the report is read, so a change between the two is not lost.
                changed.as_mut().enable();
                let report = self.report();
                if condition(&report) {
                    return report;
                }
                changed.await;
            }
        };
        tokio::time::timeout(WATCHDOG, waiting)
            .await
            .unwrap_or_else(|_| panic!("the route never saw {what}: {:?}", self.report()))
    }

    fn edit(&self, change: impl FnOnce(&mut State)) {
        change(&mut self.shared.state.lock().expect("the route's state"));
        self.shared.changed.notify_waiters();
    }

    fn each_socket(&self, mut act: impl FnMut(&mpsc::UnboundedSender<Outbound>)) {
        let state = self.shared.state.lock().expect("the route's state");
        for (_, socket) in &state.sockets {
            act(socket);
        }
    }
}

/// The call the route holds, as the service's creation answers describe it.
pub fn session() -> VoiceSession {
    serde_json::from_value(json!({
        "callId": CALL,
        "attemptId": "attempt-1",
        "providerSessionId": "live_1",
        "answerSdp": "v=0\r\n",
        "model": "gpt-live-1",
        "closesAt": "2099-01-01T00:10:00Z",
        "reservationEndsAt": "2099-01-01T00:10:15Z",
        "controlPath": PATH,
        "heartbeatSeconds": 20,
        "sidebandReady": true,
        "hold": {
            "reservationId": "hold-1",
            "reserved": "600",
            "ceiling": "600",
            "deadline": "2099-01-01T00:10:15Z"
        },
        "reasoningHold": null,
        "rate": {
            "version": "2026-09",
            "minorUnitsPerSecond": "1",
            "minimumSeconds": 15,
            "currency": "USD"
        },
        "latency": { "creationToAnswerMs": 10, "sidebandReadyMs": 5 },
        "replayed": false,
        "disclosure": ["The managed service can read the conversation."]
    }))
    .expect("a session")
}

/// Serves one connection: refuses its upgrade, or accepts it and serves the socket.
async fn connection<S>(shared: Arc<Shared>, mut stream: S)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let refusal = {
        let mut state = shared.state.lock().expect("the route's state");
        let status = state.refusals.pop_front().or(state.refuse_all);
        if status.is_some() {
            state.report.refused_upgrades += 1;
        }
        status
    };
    if let Some(status) = refusal {
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            let Ok(byte) = stream.read_u8().await else {
                return;
            };
            head.push(byte);
        }
        let answer =
            format!("HTTP/1.1 {status} Scripted\r\ncontent-length: 0\r\nconnection: close\r\n\r\n");
        let _ = stream.write_all(answer.as_bytes()).await;
        let _ = stream.flush().await;
        shared.changed.notify_waiters();
        return;
    }
    let Ok((request, mut socket)) = ServerBuilder::new()
        .limits(Limits::default().max_payload_len(Some(1 << 20)))
        .accept(stream)
        .await
    else {
        return;
    };
    let (outbound, mut inbound) = mpsc::unbounded_channel();
    let (id, ready) = {
        let mut state = shared.state.lock().expect("the route's state");
        state.report.upgrades.push(Upgrade {
            path: request
                .uri()
                .path_and_query()
                .map_or_else(String::new, ToString::to_string),
            authorization: request
                .headers()
                .get("authorization")
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned),
        });
        let id = state.next_socket;
        state.next_socket += 1;
        state.sockets.push((id, outbound));
        let ready = json!({
            "type": "ready",
            "callId": state.ready_call,
            "closesAt": "2099-01-01T00:10:00Z",
            "heartbeatSeconds": 20,
            "delegations": state.announced,
        });
        state.ready_call = CALL.to_owned();
        (id, ready)
    };
    let _ = socket.send(Message::text(ready.to_string())).await;
    shared.changed.notify_waiters();
    let drop_now = shared
        .state
        .lock()
        .expect("the route's state")
        .drop_after_ready;
    // A socket that is to end as it opens is never read, so its connection closes at once.
    loop {
        if drop_now {
            break;
        }
        tokio::select! {
            read = socket.next() => {
                let Some(Ok(message)) = read else { break };
                if message.is_close() {
                    break;
                }
                let Some(text) = message.as_text() else { continue };
                let (answers, drop_after) = answer(&shared, text);
                let late = shared
                    .state
                    .lock()
                    .expect("the route's state")
                    .closure_delay
                    .filter(|_| text.contains(r#""command":"close""#));
                if let Some(delay) = late {
                    tokio::time::sleep(delay).await;
                }
                let answered = !answers.is_empty();
                for answer in answers {
                    if socket.send(Message::text(answer.to_string())).await.is_err() {
                        break;
                    }
                }
                shared.changed.notify_waiters();
                if drop_after {
                    // The service that has answered a closure ends the connection with the closing
                    // handshake, which reads what the client wrote meanwhile: a connection closed with
                    // a frame unread is reset at once, and the reset drops what the route wrote and
                    // had not yet sent, which is the confirmation. A fault that is a lost connection
                    // gives no answer to a closure and ends as it always did.
                    if answered && text.contains(r#""command":"close""#) {
                        let _ = tokio::time::timeout(CLOSING_HANDSHAKE_WITHIN, socket.close()).await;
                    }
                    break;
                }
            }
            told = inbound.recv() => match told {
                None | Some(Outbound::Drop) => break,
                Some(Outbound::Close) => {
                    let _ = socket.close().await;
                    break;
                }
                Some(Outbound::Text(text)) => {
                    if socket.send(Message::text(text)).await.is_err() {
                        break;
                    }
                }
                Some(Outbound::Binary(bytes)) => {
                    if socket.send(Message::binary(bytes)).await.is_err() {
                        break;
                    }
                }
            },
        }
    }
    shared
        .state
        .lock()
        .expect("the route's state")
        .sockets
        .retain(|(socket, _)| *socket != id);
    shared.changed.notify_waiters();
}

/// What the route answers to one text frame, in the service's order, and whether it then drops
/// the connection.
fn answer(shared: &Shared, text: &str) -> (Vec<Value>, bool) {
    let mut state = shared.state.lock().expect("the route's state");
    if state.drop_unread && text.contains(r#""type":"context""#) {
        state.drop_unread = false;
        return (Vec::new(), true);
    }
    state.report.frames.push(text.to_owned());
    if state.silent {
        return (Vec::new(), false);
    }
    let refuse = |state: &mut State, id: &str, reason: &str| {
        state.report.refusals.push(reason.to_owned());
        json!({
            "type": "context_refused", "id": id, "reason": reason,
            "message": format!("Scripted: {reason}.")
        })
    };
    if text.len() > 4096 {
        return (vec![refuse(&mut state, "", "invalid_request")], false);
    }
    let Ok(Value::Object(frame)) = serde_json::from_str::<Value>(text) else {
        return (vec![refuse(&mut state, "", "invalid_request")], false);
    };
    if frame.get("type") == Some(&json!("heartbeat")) && frame.len() == 1 {
        state.report.heartbeats += 1;
        return (
            vec![json!({
                "type": "heartbeat_ack", "closesAt": "2099-01-01T00:10:00Z", "remainingSeconds": 600
            })],
            false,
        );
    }
    let id = frame.get("id").and_then(Value::as_str).unwrap_or_default();
    let command = frame
        .get("command")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let delegation = frame.get("delegationId");
    let content = frame.get("content");
    let text_command = matches!(command, "instructions" | "thinking" | "commentary");
    let shaped = frame.get("type") == Some(&json!("context"))
        && frame.keys().all(|key| {
            ["type", "id", "command", "delegationId", "content"].contains(&key.as_str())
        })
        && !id.is_empty()
        && id.len() <= 128
        && [
            "mute",
            "unmute",
            "instructions",
            "thinking",
            "commentary",
            "close",
        ]
        .contains(&command)
        && delegation
            .is_some_and(|value| value.is_null() || value.as_str().is_some_and(|d| !d.is_empty()))
        && content.is_none_or(Value::is_string)
        && text_command == content.is_some();
    if !shaped {
        return (vec![refuse(&mut state, "", "invalid_request")], false);
    }
    let delegation = delegation.and_then(Value::as_str).map(str::to_owned);
    let content = content.and_then(Value::as_str).map(str::to_owned);
    let bytes = content.as_ref().map_or(0, String::len);
    // A request seen before is answered from what the first was given, and sent to nobody.
    if let Some((first, first_delegation, first_bytes)) = state.requests.get(id).cloned() {
        state.report.repeats += 1;
        if first == command && first_delegation == delegation && first_bytes == bytes {
            let mut answers = vec![json!({ "type": "context_accepted", "id": id })];
            if let Some(admitted) = state.answers.get(id) {
                answers.push(admitted.clone());
            }
            return (answers, false);
        }
        return (vec![refuse(&mut state, id, "identifier_reused")], false);
    }
    if bytes > 500 {
        return (vec![refuse(&mut state, id, "too_long")], false);
    }
    if delegation
        .as_ref()
        .is_some_and(|named| !state.announced.contains(named))
    {
        return (vec![refuse(&mut state, id, "unknown_delegation")], false);
    }
    let now = Instant::now();
    let (burst_window, minute_window) = state.windows;
    while state
        .rate
        .front()
        .is_some_and(|at| now.duration_since(*at) > minute_window)
    {
        state.rate.pop_front();
    }
    let in_minute = state.rate.len();
    let in_burst = state
        .rate
        .iter()
        .filter(|at| now.duration_since(**at) <= burst_window)
        .count();
    if in_minute >= 60 || in_burst >= 10 {
        state.report.rate_refusals += 1;
        state.report.refusals.push("rate".to_owned());
        return (
            vec![json!({
                "type": "context_refused", "id": id, "reason": "rate",
                "message": "That is more context than this call may send in a minute.",
                "retryAfterSeconds": if in_minute >= 60 { 60 } else { 10 }
            })],
            false,
        );
    }
    if state.provider_down {
        return (vec![refuse(&mut state, id, "metering_unavailable")], false);
    }
    state.rate.push_back(now);
    if command == "close" {
        let seconds = 42;
        return (
            vec![
                json!({ "type": "context_accepted", "id": id }),
                json!({
                    "type": "closed", "reason": "client_closed",
                    "seconds": seconds, "provisional": false
                }),
            ],
            true,
        );
    }
    state.requests.insert(
        id.to_owned(),
        (command.to_owned(), delegation.clone(), bytes),
    );
    state.report.sent.push(Sent {
        id: id.to_owned(),
        command: command.to_owned(),
        delegation,
        content,
    });
    let admitted = json!({
        "type": "context_admitted", "id": id,
        "note": "The model received this context.",
        "startMs": null, "endMs": null
    });
    if std::mem::take(&mut state.swallow_then_drop) {
        // The provider has it; the device is never told.
        state.answers.insert(id.to_owned(), admitted);
        return (Vec::new(), true);
    }
    state.answers.insert(id.to_owned(), admitted.clone());
    if std::mem::take(&mut state.accept_then_drop) {
        // The provider has it and the device was told it was accepted, and the answer is lost.
        return (vec![json!({ "type": "context_accepted", "id": id })], true);
    }
    let mut answers = vec![
        json!({ "type": "context_accepted", "id": id }),
        admitted.clone(),
    ];
    if state.admissions_twice {
        answers.push(admitted);
    }
    (answers, false)
}
