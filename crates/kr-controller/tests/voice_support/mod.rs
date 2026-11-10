//! A managed voice service on one loopback port: the routes a host reaches with its account, and
//! the control socket a phone reaches with its own.
//!
//! The service answers as the contract states (`packages/service-contracts/src/voice.ts`), the
//! way `voice_broker.rs`'s stand-in does for a host alone, and the control socket is
//! `control_route.rs`'s, which this serves on the same port, because the origin a host names to a
//! phone is one origin for both. A suite that includes this module by its path gets the whole
//! service, and reads what each side asked of it.
//!
//! The account service is not here: a host is given its sign-in directly ([`StandIn::host_grant`])
//! and a phone has an account service of its own in the suite that needs one. What the control
//! accepts is the bearer tokens the suite names.

#![allow(
    dead_code,
    reason = "each suite that includes this module uses the part of it that it needs"
)]

use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use kr_client::services::account::{AccountToken, IssuedGrant, RefreshToken};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};

#[path = "../../../kr-client/tests/support/control_route.rs"]
pub mod control_route;

pub use control_route::{CALL, ControlRoute, PATH};

/// The access token the host's account holds, which the service's HTTP routes accept.
pub const HOST_TOKEN: &str = "host-access-token";

/// One HTTP request the service received.
#[derive(Clone, Debug)]
pub struct Seen {
    /// Its path.
    pub path: String,
    /// Its `authorization` header.
    pub authorization: Option<String>,
    /// Its JSON body, or null.
    pub body: serde_json::Value,
    /// When it was read in full, in milliseconds since the Unix epoch.
    pub at_ms: u128,
}

/// What the control makes of a token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Disposition {
    /// The account the call belongs to.
    Mine,
    /// Another account: this account has no such call.
    Another,
}

/// How the service answers a start's offer: what it builds from the offer's text, after it has
/// done whatever it does to get one.
type Answering =
    Arc<dyn Fn(String) -> Pin<Box<dyn std::future::Future<Output = String> + Send>> + Send + Sync>;

/// A step of the service that a test can hold: the request is read and counted, and answered once
/// the step is released.
#[derive(Default)]
struct Gate {
    held: std::sync::atomic::AtomicBool,
    freed: tokio::sync::Notify,
}

impl Gate {
    fn hold(&self) {
        self.held.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    fn release(&self) {
        self.held.store(false, std::sync::atomic::Ordering::SeqCst);
        self.freed.notify_waiters();
    }

    async fn pass(&self) {
        loop {
            let freed = self.freed.notified();
            tokio::pin!(freed);
            freed.as_mut().enable();
            if !self.held.load(std::sync::atomic::Ordering::SeqCst) {
                return;
            }
            freed.await;
        }
    }
}

struct State {
    /// The creation of a call, which a test can hold.
    creation: Arc<Gate>,
    /// The closing of a call, which a test can hold.
    closing: Arc<Gate>,
    /// The upgrade of a control socket, which a test can hold.
    upgrades: Arc<Gate>,
    /// How many control upgrades reached the service's gate, whatever became of them.
    upgrade_attempts: usize,
    /// Whether closing a call over HTTP also ends the call's control, as the service does.
    control_follows_close: bool,
    seen: Vec<Seen>,
    /// What the control makes of each bearer token it was told of; any other is not accepted.
    tokens: Vec<(String, Disposition)>,
    answer: Answering,
    upgrades_turned_away: usize,
    /// Whether a close that arrives with the host's token is refused at once, as a service that
    /// cannot close the call does.
    refuse_host_closes: bool,
    /// Whether the first close that arrives with a phone's token is held until it is released and
    /// then refused.
    hold_first_phone_close: bool,
    /// How many closes arrived with a phone's token, whatever became of them.
    phone_closes: usize,
    /// The gate the held phone close waits at.
    phone_close_gate: Arc<Gate>,
    /// Whether the service is down: every connection is ended as it is accepted.
    down: bool,
}

/// What the service does to a close it has been told to fail.
#[derive(Clone, Copy, PartialEq, Eq)]
enum CloseFault {
    /// Refuses it at once.
    Refuse,
    /// Holds it until the test lets it go, and then refuses it.
    HoldThenRefuse,
}

/// A voice service and its control route on a loopback port.
pub struct StandIn {
    origin: String,
    address: std::net::SocketAddr,
    route: Arc<ControlRoute>,
    state: Arc<Mutex<State>>,
    /// The task that accepts connections, until a test closes the port.
    task: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl Drop for StandIn {
    fn drop(&mut self) {
        if let Some(task) = self.task.lock().expect("the stand-in's task").take() {
            task.abort();
        }
    }
}

/// A stream that gives back what was already read from it before it gives what it still holds.
struct Prefixed {
    head: std::io::Cursor<Vec<u8>>,
    inner: TcpStream,
}

impl AsyncRead for Prefixed {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = &mut *self;
        let position = usize::try_from(this.head.position()).unwrap_or(usize::MAX);
        let held = this.head.get_ref();
        if position < held.len() {
            let count = (held.len() - position).min(buffer.remaining());
            buffer.put_slice(&held[position..position + count]);
            this.head.set_position((position + count) as u64);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(context, buffer)
    }
}

impl AsyncWrite for Prefixed {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(context, bytes)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

impl StandIn {
    /// Starts the service on a free loopback port.
    pub async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a loopback port");
        let address = listener.local_addr().expect("an address");
        let origin = format!("http://{address}");
        let route = Arc::new(ControlRoute::detached(origin.clone(), None));
        let state = Arc::new(Mutex::new(State {
            creation: Arc::default(),
            closing: Arc::default(),
            upgrades: Arc::default(),
            upgrade_attempts: 0,
            control_follows_close: false,
            seen: Vec::new(),
            tokens: Vec::new(),
            answer: Arc::new(|_offer| {
                Box::pin(async { "v=0\r\na=answered-by-the-stand-in\r\n".to_owned() })
            }),
            upgrades_turned_away: 0,
            refuse_host_closes: false,
            hold_first_phone_close: false,
            phone_closes: 0,
            phone_close_gate: Arc::default(),
            down: false,
        }));
        let task = accepting(listener, Arc::clone(&route), Arc::clone(&state));
        Self {
            origin,
            address,
            route,
            state,
            task: Mutex::new(Some(task)),
        }
    }

    /// The origin both the routes and the control answer on.
    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// The control route, to drive its faults and read what it saw.
    pub fn control(&self) -> &ControlRoute {
        &self.route
    }

    /// The sign-in the host's account holds, which this service's routes accept.
    pub fn host_grant(&self) -> IssuedGrant {
        IssuedGrant {
            access_token: AccountToken::new(HOST_TOKEN).expect("a token"),
            expires_in_seconds: 3600,
            refresh_token: RefreshToken::new("host-refresh-token").expect("a token"),
            scopes: ["openid", "profile", "email", "offline_access", "voice"]
                .map(str::to_owned)
                .to_vec(),
            subject: "account-1".to_owned(),
        }
    }

    /// Has the control accept `token` as the account the call belongs to.
    pub fn accept_control_token(&self, token: &str) {
        self.tell(token, Some(Disposition::Mine));
    }

    /// Has the control answer `token` as another account's: this account has no such call.
    pub fn treat_as_another_account(&self, token: &str) {
        self.tell(token, Some(Disposition::Another));
    }

    /// Has the control not know `token` at all.
    pub fn forget_control_token(&self, token: &str) {
        self.tell(token, None);
    }

    fn tell(&self, token: &str, disposition: Option<Disposition>) {
        let mut state = self.state.lock().expect("the stand-in's state");
        state.tokens.retain(|(each, _)| each != token);
        if let Some(disposition) = disposition {
            state.tokens.push((token.to_owned(), disposition));
        }
    }

    /// Holds the creation of a call: the request is read and counted, and answered when
    /// [`Self::release_creations`] lets it.
    pub fn hold_creations(&self) {
        let gate = Arc::clone(&self.state.lock().expect("the stand-in's state").creation);
        gate.hold();
    }

    /// Lets the held creations be answered.
    pub fn release_creations(&self) {
        let gate = Arc::clone(&self.state.lock().expect("the stand-in's state").creation);
        gate.release();
    }

    /// Takes the service down: every control socket that is open is dropped with no closing frame,
    /// and every connection made afterwards is accepted and ended at once, so no request and no
    /// upgrade is ever answered. A request already accepted, held at a gate for instance, is still
    /// answered when its gate is released.
    pub fn go_down(&self) {
        self.state.lock().expect("the stand-in's state").down = true;
        self.route.drop_sockets();
    }

    /// Holds the upgrade of every control socket: the request is read and counted
    /// ([`Self::upgrade_attempts`]) and answered, or dropped if the service has gone down meanwhile,
    /// once [`Self::release_upgrades`] lets it.
    pub fn hold_upgrades(&self) {
        let gate = Arc::clone(&self.state.lock().expect("the stand-in's state").upgrades);
        gate.hold();
    }

    /// Lets the held upgrades go on.
    pub fn release_upgrades(&self) {
        let gate = Arc::clone(&self.state.lock().expect("the stand-in's state").upgrades);
        gate.release();
    }

    /// How many control upgrades reached the service, whatever became of them.
    pub fn upgrade_attempts(&self) -> usize {
        self.state
            .lock()
            .expect("the stand-in's state")
            .upgrade_attempts
    }

    /// Waits until `count` control upgrades have reached the service.
    pub async fn until_upgrade_attempts(&self, count: usize) {
        tokio::time::timeout(std::time::Duration::from_secs(60), async {
            while self.upgrade_attempts() < count {
                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("no control upgrade reached the stand-in"));
    }

    /// Takes the service away as a host that is off the network is: its port is closed, so a
    /// connection is refused outright, and every control socket that is open is dropped. A request
    /// made to it was never carried out. [`Self::go_down`] is the other way down: the service takes
    /// the connection and ends it, so a request may have been carried out.
    ///
    /// Returns once the port has refused a connection, which a socket that is still closing does
    /// not do.
    pub async fn refuse_connections(&self) {
        let task = self.task.lock().expect("the stand-in's task").take();
        if let Some(task) = task {
            task.abort();
            // The listener is dropped when the aborted task is, which is waited for here. That
            // closes this process's copy of its socket, and no other.
            let _ = task.await;
        }
        self.route.drop_sockets();
        self.until_refused().await;
    }

    /// Returns once a connection to the port is refused.
    ///
    /// A socket goes on listening until the last copy of it is closed. On Linux and macOS a process
    /// that is being started in this one holds a copy of every socket the program has open, from
    /// the fork until the new program replaces it, which on a busy machine is longer than the
    /// close. Until then the port takes a connection and nothing accepts it: a request made to it
    /// is written, and ended when the last copy goes, which says nothing of whether it was carried
    /// out. It is a condition to wait for, and the wait ends when the port refuses; the minute it
    /// is given only ends a hang, and the panic it ends in counts the probes and says how the last
    /// one ended. Where sockets are not inherited the first probe is refused.
    async fn until_refused(&self) {
        let probes = std::sync::atomic::AtomicUsize::new(0);
        let last_took_its_connection = std::sync::atomic::AtomicBool::new(false);
        tokio::time::timeout(std::time::Duration::from_secs(60), async {
            loop {
                probes.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                last_took_its_connection.store(false, std::sync::atomic::Ordering::Relaxed);
                match TcpStream::connect(self.address).await {
                    Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => return,
                    Err(error) => panic!("the stand-in's port cannot be reached: {error}"),
                    Ok(taken) => {
                        last_took_its_connection.store(true, std::sync::atomic::Ordering::Relaxed);
                        drop(taken);
                        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                    }
                }
            }
        })
        .await
        .unwrap_or_else(|_| {
            let last = if last_took_its_connection.load(std::sync::atomic::Ordering::Relaxed) {
                "took its connection"
            } else {
                "had no answer to its connect"
            };
            panic!(
                "the stand-in's port {} did not refuse a connection in a minute after it was \
                 closed: {} probes, the last {last}",
                self.address,
                probes.load(std::sync::atomic::Ordering::Relaxed)
            )
        });
    }

    /// Brings the service back after [`Self::go_down`] or [`Self::refuse_connections`], on the port
    /// it had. Fails the case if the port cannot be bound again.
    pub async fn come_up(&self) {
        self.state.lock().expect("the stand-in's state").down = false;
        if self.task.lock().expect("the stand-in's task").is_some() {
            return;
        }
        let listener = TcpListener::bind(self.address)
            .await
            .unwrap_or_else(|error| panic!("the stand-in's port was not free again: {error}"));
        let task = accepting(listener, Arc::clone(&self.route), Arc::clone(&self.state));
        *self.task.lock().expect("the stand-in's task") = Some(task);
    }

    /// Has a call closed over HTTP end the call's control with a closure, as the service does when
    /// a host closes a call a device is still controlling.
    pub fn end_the_control_when_a_call_is_closed(&self) {
        self.state
            .lock()
            .expect("the stand-in's state")
            .control_follows_close = true;
    }

    /// Holds the closing of a call as [`Self::hold_creations`] holds its creation.
    pub fn hold_closes(&self) {
        let gate = Arc::clone(&self.state.lock().expect("the stand-in's state").closing);
        gate.hold();
    }

    /// Lets the held closes be answered.
    pub fn release_closes(&self) {
        let gate = Arc::clone(&self.state.lock().expect("the stand-in's state").closing);
        gate.release();
    }

    /// Refuses at once every close that arrives with the host's token, as a service that cannot
    /// close the call does. A close with a phone's token is not touched.
    pub fn refuse_the_hosts_closes(&self) {
        self.state
            .lock()
            .expect("the stand-in's state")
            .refuse_host_closes = true;
    }

    /// Holds the first close that arrives with a phone's token, until
    /// [`Self::release_the_held_phone_close`] lets it go, and then refuses it. A later close with a
    /// phone's token is answered as the service answers one.
    pub fn hold_then_refuse_the_first_phone_close(&self) {
        let gate = {
            let mut state = self.state.lock().expect("the stand-in's state");
            state.hold_first_phone_close = true;
            Arc::clone(&state.phone_close_gate)
        };
        gate.hold();
    }

    /// Lets the held phone close be refused.
    pub fn release_the_held_phone_close(&self) {
        let gate = Arc::clone(
            &self
                .state
                .lock()
                .expect("the stand-in's state")
                .phone_close_gate,
        );
        gate.release();
    }

    /// How many closes arrived with a phone's token, whatever became of them.
    pub fn phone_closes(&self) -> usize {
        self.state
            .lock()
            .expect("the stand-in's state")
            .phone_closes
    }

    /// Has the service answer a start's offer with what `answer` builds from it. The answer is made
    /// when the creation is answered, outside the service's own state, so it may wait for a peer.
    pub fn answer_offers_with<F>(&self, answer: impl Fn(String) -> F + Send + Sync + 'static)
    where
        F: std::future::Future<Output = String> + Send + 'static,
    {
        self.state.lock().expect("the stand-in's state").answer =
            Arc::new(move |offer| Box::pin(answer(offer)));
    }

    /// Every HTTP request received, in order.
    pub fn seen(&self) -> Vec<Seen> {
        self.state
            .lock()
            .expect("the stand-in's state")
            .seen
            .clone()
    }

    /// How many requests for `path` were received.
    pub fn count(&self, path: &str) -> usize {
        self.seen()
            .iter()
            .filter(|request| request.path == path)
            .count()
    }

    /// How many control upgrades were turned away for their token, whatever the reason.
    pub fn upgrades_turned_away(&self) -> usize {
        self.state
            .lock()
            .expect("the stand-in's state")
            .upgrades_turned_away
    }
}

/// Accepts connections on `listener` until the task is ended or the listener fails.
fn accepting(
    listener: TcpListener,
    route: Arc<ControlRoute>,
    state: Arc<Mutex<State>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            if state.lock().expect("the stand-in's state").down {
                drop(stream);
                continue;
            }
            let (route, state) = (Arc::clone(&route), Arc::clone(&state));
            tokio::spawn(async move { serve(stream, &route, &state).await });
        }
    })
}

/// Reads one request's head, and what was read with it.
async fn read_head(stream: &mut TcpStream) -> Option<(String, Vec<u8>)> {
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            return None;
        }
        bytes.extend_from_slice(&chunk[..read]);
        if let Some(end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            return Some((String::from_utf8_lossy(&bytes[..end]).into_owned(), bytes));
        }
        if bytes.len() > 16 * 1024 {
            return None;
        }
    }
}

fn header(head: &str, name: &str) -> Option<String> {
    head.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.eq_ignore_ascii_case(name)
            .then(|| value.trim().to_owned())
    })
}

fn response(status: u16, body: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\
         connection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

async fn serve(mut stream: TcpStream, route: &ControlRoute, state: &Arc<Mutex<State>>) {
    let Some((head, bytes)) = read_head(&mut stream).await else {
        return;
    };
    let authorization = header(&head, "authorization");
    if header(&head, "upgrade").is_some_and(|value| value.eq_ignore_ascii_case("websocket")) {
        let gate = {
            let mut state = state.lock().expect("the stand-in's state");
            state.upgrade_attempts += 1;
            Arc::clone(&state.upgrades)
        };
        gate.pass().await;
        // An upgrade held while the service went down is dropped, as the service drops what it
        // accepts when it is down.
        if state.lock().expect("the stand-in's state").down {
            return;
        }
        let disposition = {
            let state = state.lock().expect("the stand-in's state");
            authorization
                .as_deref()
                .and_then(|value| value.strip_prefix("Bearer "))
                .and_then(|token| {
                    state
                        .tokens
                        .iter()
                        .find(|(each, _)| each == token)
                        .map(|(_, disposition)| *disposition)
                })
        };
        let accepted = disposition == Some(Disposition::Mine);
        let foreign = disposition == Some(Disposition::Another);
        if accepted {
            route
                .serve(Prefixed {
                    head: std::io::Cursor::new(bytes),
                    inner: stream,
                })
                .await;
        } else {
            state
                .lock()
                .expect("the stand-in's state")
                .upgrades_turned_away += 1;
            // Another account's call is one this account has none of; a token nobody issued is
            // not accepted at all.
            let _ = stream
                .write_all(&response(if foreign { 404 } else { 401 }, b"{}"))
                .await;
        }
        return;
    }

    let length = header(&head, "content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    let head_end = head.len() + 4;
    let mut body = bytes[head_end.min(bytes.len())..].to_vec();
    let mut chunk = [0_u8; 4096];
    while body.len() < length {
        let Ok(read) = stream.read(&mut chunk).await else {
            return;
        };
        if read == 0 {
            return;
        }
        body.extend_from_slice(&chunk[..read]);
    }
    let path = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("")
        .to_owned();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
    let fault: Option<CloseFault>;
    let (allowed, answering) = {
        let mut state = state.lock().expect("the stand-in's state");
        state.seen.push(Seen {
            path: path.clone(),
            authorization: authorization.clone(),
            body: parsed.clone(),
            at_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |since| since.as_millis()),
        });
        // The service accepts the host's token for its routes, and the phone's own for the close
        // route a phone may reach it by.
        let allowed = authorization.as_deref() == Some(&format!("Bearer {HOST_TOKEN}"))
            || (path.ends_with("/close")
                && authorization
                    .as_deref()
                    .and_then(|value| value.strip_prefix("Bearer "))
                    .is_some_and(|token| {
                        state
                            .tokens
                            .iter()
                            .any(|(each, kind)| each == token && *kind == Disposition::Mine)
                    }));
        // A close the service is told to fail: the host's, at once, or the first a phone makes,
        // after it has been held.
        fault = if allowed && path.ends_with("/close") {
            let by_the_host = authorization.as_deref() == Some(&format!("Bearer {HOST_TOKEN}"));
            if by_the_host {
                state.refuse_host_closes.then_some(CloseFault::Refuse)
            } else {
                state.phone_closes += 1;
                (state.hold_first_phone_close && state.phone_closes == 1)
                    .then_some(CloseFault::HoldThenRefuse)
            }
        } else {
            None
        };
        (allowed, Arc::clone(&state.answer))
    };
    if !allowed {
        let refusal = br#"{"ok":false,"error":{"code":"UNAUTHENTICATED","message":"No."}}"#;
        let _ = stream.write_all(&response(401, refusal)).await;
        return;
    }
    if let Some(fault) = fault {
        if fault == CloseFault::HoldThenRefuse {
            let gate = Arc::clone(&state.lock().expect("the stand-in's state").phone_close_gate);
            gate.pass().await;
        }
        let refusal = br#"{"ok":false,"error":{"code":"SERVICE_CAPACITY","message":"Busy."}}"#;
        let _ = stream.write_all(&response(503, refusal)).await;
        return;
    }
    let gate = {
        let state = state.lock().expect("the stand-in's state");
        match path.as_str() {
            "/api/voice/sessions" => Some(Arc::clone(&state.creation)),
            other if other.ends_with("/close") => Some(Arc::clone(&state.closing)),
            _ => None,
        }
    };
    if let Some(gate) = gate {
        gate.pass().await;
    }
    if path.ends_with("/close")
        && state
            .lock()
            .expect("the stand-in's state")
            .control_follows_close
    {
        route.close_call("client_closed", 0);
    }
    let data = match path.as_str() {
        "/api/voice/metadata" => serde_json::json!({
            "enabled": true,
            "model": "gpt-live-1",
            "disclosure": ["The managed service can read the conversation."],
            "admissionNote": "An acknowledgement is not execution.",
            "delegationNote": "A delegation identifier is correlation data.",
            "alternatives": ["Your own coding agent"],
            "rate": {
                "version": "2026-09",
                "minorUnitsPerSecond": "1",
                "minimumSeconds": 15,
                "currency": "USD"
            },
            "maximumSessionSeconds": 1800,
            "minimumRequestSeconds": 60,
            "heartbeatSeconds": 20,
            "contextBytes": 500
        }),
        "/api/voice/sessions" => serde_json::json!({
            "callId": CALL,
            "attemptId": "attempt-1",
            "providerSessionId": "live_1",
            "answerSdp": answering(parsed["offerSdp"].as_str().unwrap_or("").to_owned()).await,
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
        }),
        "/api/voice/sessions/call-1/close" => serde_json::json!({
            "callId": CALL,
            "state": "finalised",
            "usageSeconds": 0,
            "usageProvisional": true
        }),
        _ => {
            let refusal =
                br#"{"ok":false,"error":{"code":"NOT_FOUND","message":"No such route."}}"#;
            let _ = stream.write_all(&response(404, refusal)).await;
            return;
        }
    };
    let envelope = serde_json::json!({ "ok": true, "data": data });
    let _ = stream
        .write_all(&response(
            200,
            &serde_json::to_vec(&envelope).expect("an envelope"),
        ))
        .await;
}
