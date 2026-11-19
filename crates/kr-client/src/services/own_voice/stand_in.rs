//! A stand-in for OpenAI and for the host's record, for the suites that start an own-key call
//! without a provider.
//!
//! Compiled only under the `testing` feature. [`STAND_IN_MARKER`] is carried by everything that
//! speaks for OpenAI here and is used at run time, so a scan of a built binary finds it when the
//! stand-in is in the build and only then.

use std::collections::VecDeque;
use std::fmt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use kr_protocol::delivery::SecretText;
use serde_json::{Value, json};
use tokio::sync::mpsc;

use super::{
    AttachFault, Lost, OwnKeySource, OwnVoiceTransport, Reply, SidebandSocket, SocketRead,
    TransportFuture,
};
use crate::services::own_call::{
    CallRow, CallState, LedgerError, LedgerResult, NewCall, OwnCallLedger,
};

/// What every stand-in item carries, so a scan of a built binary can tell it is in the build.
pub const STAND_IN_MARKER: &str = "kr-own-voice-stand-in-marker-7c41";

/// What the testing build's connector answers a daemon that asked for the real transport.
pub const TESTING_REFUSAL: &str =
    "This build of the host is a test build and does not reach OpenAI.";

/// How many times the testing build's connector was asked and refused.
pub static TESTING_REFUSALS: AtomicUsize = AtomicUsize::new(0);

/// What the stand-in answers to a creation.
#[derive(Clone)]
pub enum CreateScript {
    /// A status and a body.
    Answer(u16, Option<Vec<u8>>),
    /// No answer.
    Lost,
    /// The same answer after a wait.
    After(Duration, Box<CreateScript>),
    /// The same answer once the test lets it go.
    Held(Arc<tokio::sync::Notify>, Box<CreateScript>),
}

crate::debug_as_name!(CreateScript);

/// What the stand-in answers to a hangup.
#[derive(Clone)]
pub enum HangupScript {
    /// A status and a body.
    Answer(u16, Option<Vec<u8>>),
    /// No answer.
    Lost,
}

crate::debug_as_name!(HangupScript);

/// The requests the stand-in saw.
#[derive(Clone, Default)]
pub struct Recorded {
    /// The key and the body of each creation.
    pub creates: Vec<(String, Value)>,
    /// The key and the session of each hangup.
    pub hangups: Vec<(String, String)>,
    /// How many times the side channel was attached.
    pub attaches: u32,
    /// Each command written on the side channel.
    pub commands: Vec<Value>,
}

crate::debug_as_name!(Recorded);

struct Script {
    create: VecDeque<CreateScript>,
    hangup: VecDeque<HangupScript>,
    attach: VecDeque<AttachFault>,
    ack: bool,
    answer_close: bool,
    send_started: bool,
}

struct State {
    script: Mutex<Script>,
    recorded: Mutex<Recorded>,
    socket: Mutex<Option<mpsc::UnboundedSender<SocketRead>>>,
    last_body: Mutex<Option<Value>>,
}

/// The stand-in for OpenAI.
#[derive(Clone)]
pub struct StandIn {
    state: Arc<State>,
}

crate::debug_as_name!(StandIn);

impl Default for StandIn {
    fn default() -> Self {
        Self::new()
    }
}

/// The answer a working OpenAI gives to a creation.
#[must_use]
pub fn created_body(session_id: &str) -> Vec<u8> {
    json!({
        "session": { "id": session_id },
        "transport": { "type": "webrtc", "sdp": "v=0\r\ns=answer\r\n" },
    })
    .to_string()
    .into_bytes()
}

/// The body OpenAI answers a hangup for a session it does not know with.
#[must_use]
pub fn not_found_body() -> Vec<u8> {
    json!({ "error": { "type": "invalid_request_error", "code": "session_id_not_found",
        "param": "session_id", "message": "No session found for the provided session_id" } })
    .to_string()
    .into_bytes()
}

impl StandIn {
    /// A stand-in that creates a session, acknowledges every command, answers `session.close`
    /// with `session.closed`, and hangs up with a 200.
    #[must_use]
    pub fn new() -> Self {
        // Read at run time, so a binary that carries the stand-in carries the marker text.
        std::hint::black_box(STAND_IN_MARKER);
        Self {
            state: Arc::new(State {
                script: Mutex::new(Script {
                    create: VecDeque::new(),
                    hangup: VecDeque::new(),
                    attach: VecDeque::new(),
                    ack: true,
                    answer_close: true,
                    send_started: true,
                }),
                recorded: Mutex::new(Recorded::default()),
                socket: Mutex::new(None),
                last_body: Mutex::new(None),
            }),
        }
    }

    fn script(&self) -> std::sync::MutexGuard<'_, Script> {
        self.state
            .script
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// The next creation is answered like this; later ones are answered as a working OpenAI.
    pub fn script_create(&self, script: CreateScript) {
        self.script().create.push_back(script);
    }

    /// The next hangup is answered like this; later ones with a 200.
    pub fn script_hangup(&self, script: HangupScript) {
        self.script().hangup.push_back(script);
    }

    /// The next attach fails like this.
    pub fn fail_attach(&self, fault: AttachFault) {
        self.script().attach.push_back(fault);
    }

    /// Whether commands are acknowledged.
    pub fn acknowledge(&self, on: bool) {
        self.script().ack = on;
    }

    /// Whether `session.close` is answered with `session.closed`.
    pub fn answer_close(&self, on: bool) {
        self.script().answer_close = on;
    }

    /// Whether an attach is followed by `session.started`.
    pub fn send_started(&self, on: bool) {
        self.script().send_started = on;
    }

    /// Sends one event on the current side channel.
    pub fn event(&self, event: &Value) {
        if let Some(socket) = self.socket() {
            let _ = socket.send(SocketRead::Text(event.to_string()));
        }
    }

    /// Ends the current side channel as a lost connection.
    pub fn drop_socket(&self) {
        if let Some(socket) = self.socket() {
            let _ = socket.send(SocketRead::Closed);
        }
    }

    fn socket(&self) -> Option<mpsc::UnboundedSender<SocketRead>> {
        self.state
            .socket
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// What the stand-in saw.
    #[must_use]
    pub fn recorded(&self) -> Recorded {
        self.state
            .recorded
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn record(&self, change: impl FnOnce(&mut Recorded)) {
        change(
            &mut self
                .state
                .recorded
                .lock()
                .unwrap_or_else(PoisonError::into_inner),
        );
    }
}

struct StandSocket {
    inbound: mpsc::UnboundedReceiver<SocketRead>,
    inject: mpsc::UnboundedSender<SocketRead>,
    stand_in: StandIn,
}

impl SidebandSocket for StandSocket {
    fn send(&mut self, text: String) -> TransportFuture<'_, bool> {
        Box::pin(async move {
            let Ok(command) = serde_json::from_str::<Value>(&text) else {
                return false;
            };
            self.stand_in
                .record(|recorded| recorded.commands.push(command.clone()));
            let (ack, answer_close) = {
                let script = self.stand_in.script();
                (script.ack, script.answer_close)
            };
            let kind = command
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let id = command.get("event_id").cloned().unwrap_or(Value::Null);
            let reply = match kind {
                "session.close" if answer_close => Some(json!({
                    "type": "session.closed", "event_id": "e", "client_event_id": id,
                    "reason": "close_requested" })),
                "session.input_audio.mute" if ack => Some(json!({
                    "type": "session.input_audio.muted", "event_id": "e", "client_event_id": id })),
                "session.input_audio.unmute" if ack => Some(json!({
                    "type": "session.input_audio.unmuted", "event_id": "e", "client_event_id": id })),
                "session.instructions.append" if ack => Some(json!({
                    "type": "session.instructions.appended", "event_id": "e", "client_event_id": id,
                    "start_ms": 0, "end_ms": 1 })),
                "session.thinking.append" if ack => Some(json!({
                    "type": "session.thinking.appended", "event_id": "e", "client_event_id": id,
                    "start_ms": 0, "end_ms": 1 })),
                "session.commentary.append" if ack => Some(json!({
                    "type": "session.commentary.appended", "event_id": "e", "client_event_id": id,
                    "start_ms": 0, "end_ms": 1 })),
                _ => None,
            };
            if let Some(reply) = reply {
                let _ = self.inject.send(SocketRead::Text(reply.to_string()));
            }
            true
        })
    }

    fn next(&mut self) -> TransportFuture<'_, SocketRead> {
        Box::pin(async move { self.inbound.recv().await.unwrap_or(SocketRead::Closed) })
    }
}

impl OwnVoiceTransport for StandIn {
    fn create<'a>(
        &'a self,
        key: &'a SecretText,
        body: Vec<u8>,
    ) -> TransportFuture<'a, Result<Reply, Lost>> {
        Box::pin(async move {
            let value = serde_json::from_slice::<Value>(&body).unwrap_or(Value::Null);
            *self
                .state
                .last_body
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = Some(value.clone());
            self.record(|recorded| recorded.creates.push((key.expose().to_owned(), value)));
            let mut script = self.script().create.pop_front().unwrap_or_else(|| {
                CreateScript::Answer(201, Some(created_body("live_u1_stand_in")))
            });
            loop {
                match script {
                    CreateScript::After(wait, next) => {
                        tokio::time::sleep(wait).await;
                        script = *next;
                    }
                    CreateScript::Held(release, next) => {
                        release.notified().await;
                        script = *next;
                    }
                    CreateScript::Lost => return Err(Lost),
                    CreateScript::Answer(status, body) => return Ok(Reply { status, body }),
                }
            }
        })
    }

    fn hangup<'a>(
        &'a self,
        key: &'a SecretText,
        session_id: &'a str,
    ) -> TransportFuture<'a, Result<Reply, Lost>> {
        Box::pin(async move {
            self.record(|recorded| {
                recorded
                    .hangups
                    .push((key.expose().to_owned(), session_id.to_owned()));
            });
            match self.script().hangup.pop_front() {
                Some(HangupScript::Lost) => Err(Lost),
                Some(HangupScript::Answer(status, body)) => Ok(Reply { status, body }),
                None => Ok(Reply {
                    status: 200,
                    body: Some(Vec::new()),
                }),
            }
        })
    }

    fn attach<'a>(
        &'a self,
        _key: &'a SecretText,
        _session_id: &'a str,
    ) -> TransportFuture<'a, Result<Box<dyn SidebandSocket>, AttachFault>> {
        Box::pin(async move {
            if let Some(fault) = self.script().attach.pop_front() {
                return Err(fault);
            }
            self.record(|recorded| recorded.attaches += 1);
            let (inject, inbound) = mpsc::unbounded_channel();
            *self
                .state
                .socket
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = Some(inject.clone());
            if self.script().send_started {
                let asked = self
                    .state
                    .last_body
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .clone()
                    .unwrap_or(Value::Null);
                let mut session = asked.get("session").cloned().unwrap_or(Value::Null);
                session["id"] = json!("live_u1_stand_in");
                session["status"] = json!("active");
                session["expires_at"] = json!(1);
                let _ = inject.send(SocketRead::Text(
                    json!({ "type": "session.started", "event_id": "e0", "session": session })
                        .to_string(),
                ));
            }
            Ok(Box::new(StandSocket {
                inbound,
                inject,
                stand_in: self.clone(),
            }) as Box<dyn SidebandSocket>)
        })
    }
}

/// A key source with a key that tests set, and a count of the reads made of it.
#[derive(Default)]
pub struct StaticKey {
    key: Mutex<Option<String>>,
    unreadable: Mutex<bool>,
    reads: AtomicUsize,
}

crate::debug_as_name!(StaticKey);

impl StaticKey {
    /// A source holding `key`, or none.
    #[must_use]
    pub fn holding(key: Option<&str>) -> Arc<Self> {
        Arc::new(Self {
            key: Mutex::new(key.map(str::to_owned)),
            ..Self::default()
        })
    }

    /// Sets the key the next read answers.
    pub fn set(&self, key: Option<&str>) {
        *self.key.lock().unwrap_or_else(PoisonError::into_inner) = key.map(str::to_owned);
    }

    /// Makes the store refuse.
    pub fn refuse(&self, on: bool) {
        *self
            .unreadable
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = on;
    }

    /// How many times the key was read.
    #[must_use]
    pub fn reads(&self) -> usize {
        self.reads.load(Ordering::Relaxed)
    }
}

impl OwnKeySource for StaticKey {
    fn key(&self) -> Result<Option<SecretText>, super::KeyUnreadable> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        if *self
            .unreadable
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
        {
            return Err(super::KeyUnreadable);
        }
        Ok(self
            .key
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_deref()
            .and_then(|text| SecretText::new(text).ok()))
    }
}

/// A record of calls in memory, with writes that can be made to fail.
#[derive(Default)]
pub struct MemoryLedger {
    rows: Mutex<Vec<CallRow>>,
    fail: Mutex<Vec<&'static str>>,
}

crate::debug_as_name!(MemoryLedger);

impl MemoryLedger {
    /// An empty record.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Makes the named write (`begin`, `record_id`, `record_state`, `record_closed`, `delete`)
    /// fail from now on, or work again.
    pub fn failing(&self, write: &'static str, on: bool) {
        let mut fail = self.fail.lock().unwrap_or_else(PoisonError::into_inner);
        fail.retain(|held| *held != write);
        if on {
            fail.push(write);
        }
    }

    fn check(&self, write: &'static str) -> LedgerResult<()> {
        if self
            .fail
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains(&write)
        {
            Err(LedgerError::said("the record refused"))
        } else {
            Ok(())
        }
    }

    fn rows_mut(&self) -> std::sync::MutexGuard<'_, Vec<CallRow>> {
        self.rows.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Puts a row in as it is.
    pub fn put(&self, row: CallRow) {
        self.rows_mut().push(row);
    }
}

impl OwnCallLedger for MemoryLedger {
    fn begin(&self, call: &NewCall) -> LedgerResult<()> {
        self.check("begin")?;
        self.rows_mut().push(CallRow {
            call: call.clone(),
            state: CallState::Creating,
            provider_session_id: None,
            provider_expires_ms: None,
            closed_ms: None,
        });
        Ok(())
    }

    fn record_id(&self, call_id: &str, session: &str, expires: Option<u64>) -> LedgerResult<()> {
        self.check("record_id")?;
        let mut rows = self.rows_mut();
        let row = rows
            .iter_mut()
            .find(|row| row.call.call_id == call_id && row.state == CallState::Creating)
            .ok_or_else(|| LedgerError::said("no creating row"))?;
        row.state = CallState::Open;
        row.provider_session_id = Some(session.to_owned());
        row.provider_expires_ms = expires;
        Ok(())
    }

    fn record_state(&self, call_id: &str, state: CallState) -> LedgerResult<()> {
        self.check("record_state")?;
        let mut rows = self.rows_mut();
        let row = rows
            .iter_mut()
            .find(|row| row.call.call_id == call_id)
            .ok_or_else(|| LedgerError::said("no row"))?;
        row.state = state;
        Ok(())
    }

    fn record_closed(&self, call_id: &str, closed_ms: u64) -> LedgerResult<()> {
        self.check("record_closed")?;
        let mut rows = self.rows_mut();
        let row = rows
            .iter_mut()
            .find(|row| row.call.call_id == call_id)
            .ok_or_else(|| LedgerError::said("no row"))?;
        row.state = CallState::Closed;
        row.closed_ms = Some(closed_ms);
        Ok(())
    }

    fn rows(&self) -> LedgerResult<Vec<CallRow>> {
        self.check("rows")?;
        Ok(self.rows_mut().clone())
    }

    fn delete(&self, call_id: &str) -> LedgerResult<()> {
        self.check("delete")?;
        self.rows_mut().retain(|row| row.call.call_id != call_id);
        Ok(())
    }

    fn forget_all(&self) -> LedgerResult<u64> {
        self.check("forget_all")?;
        let mut rows = self.rows_mut();
        let count = rows.len() as u64;
        rows.clear();
        Ok(count)
    }
}
