//! The voice call that native code holds, and how Rust reaches it.
//!
//! Section 15 paragraph 2 puts capture, playback and the media connection in native code: the
//! call is a native object, and this module is the only way anything else touches it. [`CallPlatform`]
//! is what a caller asks of it (open a call, make its offer, apply the provider's answer, permit it,
//! mute it, stop it), and [`CallEvents`] is what native code tells back (the connection's state,
//! what the provider sent on its read-only channel, the first audio, what the microphone is doing,
//! the end). Native code reports facts and carries out requests; every decision about them is the
//! caller's.
//!
//! The product's implementation of the trait, on a phone, sends each request to the plugin's native
//! half as a command and takes the call's news from a channel it hands over with the first
//! command. Both are plain JSON; the shapes are the fixtures under `fixtures/call/`, which the
//! tests of this crate, of the Swift package and of the Kotlin module decode alike.
//!
//! News arrives on a bounded queue, and each item carries a number from 1 that native code counts
//! up. News that was lost (a skipped number, a queue that was full, text that is not news, or a
//! loss native code reports itself) is reported as [`Heard::Lost`] where it was lost, after the
//! news that came before it and before any that came after, and never as silence: a caller that
//! cannot tell whether it missed a capture state, a connection failure or the end of the call must
//! not carry on as if it had not.

use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use serde::{Deserialize, Serialize};
use tokio::sync::Notify;

/// How many items of news may wait for the reader before the queue counts them as lost.
pub const EVENT_QUEUE: usize = 256;

/// One call's name, chosen by the caller and echoed by native code in everything it says of it.
///
/// Native code holds one call at a time, and a late message of a call that has ended must not be
/// taken for the news of the call that replaced it.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CallId(String);

impl CallId {
    /// A name for the next call this process opens.
    #[must_use]
    pub fn next() -> Self {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        Self(format!("c{}", COUNTER.fetch_add(1, Ordering::Relaxed)))
    }

    /// The name as native code is given it.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// What the microphone is doing, in native code's own vocabulary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureState {
    /// The microphone is on and the call is carrying it.
    Capturing,
    /// The person muted their own microphone.
    MutedByPerson,
    /// The system interrupted capture, a phone call for instance.
    Interrupted,
    /// The audio route is changing and capture is being set up again.
    RouteChanging,
    /// The system suspended the application's audio.
    SuspendedBySystem,
    /// There is no microphone to carry.
    Unavailable,
    /// No call is holding the microphone.
    Idle,
}

/// The state of the call's media connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionState {
    /// Made, and nothing negotiated.
    New,
    /// Negotiated, and checking where the provider can be reached.
    Connecting,
    /// Media can flow.
    Connected,
    /// Media stopped flowing and may come back.
    Disconnected,
    /// The connection is lost for good.
    Failed,
    /// The connection was closed.
    Closed,
}

/// Whether the person has let the application post notifications, which a running call's
/// notification on Android depends on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    /// The application may post notifications.
    Granted,
    /// It may not.
    Denied,
}

/// Which of the two local silences a mute acts on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mute {
    /// The person's own microphone.
    Microphone,
    /// The model's voice coming out of this device.
    Playback,
}

/// What native code tells Rust of a call.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CallEvent {
    /// The media connection changed state.
    Connection {
        /// The state it is in now.
        state: ConnectionState,
    },
    /// The provider sent something on its read-only events channel.
    ProviderEvent {
        /// What it sent, as the bytes arrived. Data, never authority.
        #[serde(with = "base64_bytes")]
        bytes: Vec<u8>,
    },
    /// The first remote audio track arrived. It reports a track, not audible playback.
    FirstAudio,
    /// The microphone's state changed.
    Capture {
        /// What it is doing now.
        state: CaptureState,
    },
    /// The call ended, whatever ended it, and its microphone is given back.
    Ended,
    /// Native code dropped some news here. It is told to the reader as [`Heard::Lost`] and is
    /// never news of its own.
    Lost,
}

/// One item of news as it crosses from native code, with the call it is about and its number.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventFrame {
    /// The call it is about.
    pub call: CallId,
    /// Its place in that call's news, counted from 1.
    pub seq: u64,
    /// What happened.
    #[serde(flatten)]
    pub event: CallEvent,
}

/// What a reader of a call's news is told.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Heard {
    /// The next item, in order.
    Event(CallEvent),
    /// Some news was lost: the queue was full, a number was skipped, the text that arrived was not
    /// news, or native code said it had dropped some. What the call did since the last item read is
    /// not known.
    Lost,
}

/// Bytes as base64 text on the wire.
mod base64_bytes {
    use base64::Engine as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&base64::engine::general_purpose::STANDARD.encode(bytes))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(deserializer)?;
        base64::engine::general_purpose::STANDARD
            .decode(text)
            .map_err(serde::de::Error::custom)
    }
}

/// One place in a call's queue of news: news, or the mark of news that was lost there.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Entry {
    /// News.
    Event(CallEvent),
    /// Some news was lost here.
    Lost,
}

/// A call's news waiting for its reader: bounded, in order, with a loss kept in its place.
///
/// At most `limit` items of news wait. A provider event that finds the queue full is dropped. Any
/// other news that finds it full takes the place of the oldest provider event waiting, or, when
/// there is none, of the oldest news: what was displaced is lost, and the queue holds the mark of
/// the loss where it happened, one mark for losses that sit together. The end of a call closes
/// the queue, so nothing is queued after it.
#[derive(Debug)]
pub(crate) struct NewsBuffer {
    entries: VecDeque<Entry>,
    limit: usize,
    events: usize,
    closed: bool,
}

impl NewsBuffer {
    pub(crate) fn new(limit: usize) -> Self {
        Self {
            entries: VecDeque::new(),
            limit,
            events: 0,
            closed: false,
        }
    }

    /// Queues one item of news.
    pub(crate) fn push(&mut self, event: CallEvent) {
        if self.closed {
            return;
        }
        if self.events >= self.limit {
            if matches!(event, CallEvent::ProviderEvent { .. }) {
                self.mark_lost();
                return;
            }
            let victim = self
                .entries
                .iter()
                .position(|entry| matches!(entry, Entry::Event(CallEvent::ProviderEvent { .. })))
                .or_else(|| {
                    self.entries
                        .iter()
                        .position(|entry| matches!(entry, Entry::Event(_)))
                });
            if let Some(victim) = victim {
                self.entries[victim] = Entry::Lost;
                self.events -= 1;
                self.merge_marks();
            }
        }
        if matches!(event, CallEvent::Ended) {
            self.closed = true;
        }
        self.entries.push_back(Entry::Event(event));
        self.events += 1;
    }

    /// Records that news was lost after everything queued so far.
    pub(crate) fn mark_lost(&mut self) {
        if !self.closed && !matches!(self.entries.back(), Some(Entry::Lost)) {
            self.entries.push_back(Entry::Lost);
        }
    }

    fn merge_marks(&mut self) {
        let mut merged = VecDeque::with_capacity(self.entries.len());
        for entry in self.entries.drain(..) {
            if entry == Entry::Lost && merged.back() == Some(&Entry::Lost) {
                continue;
            }
            merged.push_back(entry);
        }
        self.entries = merged;
    }

    /// Closes the queue and lets go of what waits in it: nobody will read it, and nothing is
    /// queued after.
    pub(crate) fn close(&mut self) {
        self.entries.clear();
        self.events = 0;
        self.closed = true;
    }

    /// The next place, oldest first.
    pub(crate) fn pop(&mut self) -> Option<Entry> {
        let entry = self.entries.pop_front();
        if matches!(entry, Some(Entry::Event(_))) {
            self.events -= 1;
        }
        entry
    }
}

/// What the writing and reading ends of a call's news share.
#[derive(Debug)]
struct Shared {
    state: Mutex<State>,
    ready: Notify,
    writers: AtomicUsize,
}

#[derive(Debug)]
struct State {
    buffer: NewsBuffer,
    /// The number the next item must have.
    next: u64,
    /// No writer is left: what is queued is the last there is.
    closed: bool,
}

impl Shared {
    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The writing end of a call's news, held by whatever receives it from native code.
#[derive(Debug)]
pub struct EventSink {
    call: CallId,
    shared: Arc<Shared>,
}

impl Clone for EventSink {
    fn clone(&self) -> Self {
        self.shared.writers.fetch_add(1, Ordering::SeqCst);
        Self {
            call: self.call.clone(),
            shared: Arc::clone(&self.shared),
        }
    }
}

impl Drop for EventSink {
    fn drop(&mut self) {
        if self.shared.writers.fetch_sub(1, Ordering::SeqCst) == 1 {
            self.shared.state().closed = true;
            self.shared.ready.notify_one();
        }
    }
}

impl EventSink {
    /// Takes one item from native code. News of another call is a late message and is dropped; a
    /// number already heard is dropped; a number skipped is a loss, told before the item.
    pub fn deliver(&self, frame: EventFrame) {
        if frame.call != self.call {
            return;
        }
        {
            let mut state = self.shared.state();
            if frame.seq < state.next {
                return;
            }
            if frame.seq > state.next {
                state.buffer.mark_lost();
            }
            state.next = frame.seq + 1;
            match frame.event {
                CallEvent::Lost => state.buffer.mark_lost(),
                event => state.buffer.push(event),
            }
        }
        self.shared.ready.notify_one();
    }

    /// Takes one item from native code as the JSON text it arrives as. Text that is not an item is
    /// news that was lost, told to the reader where it arrived.
    pub fn deliver_json(&self, text: &str) {
        match serde_json::from_str::<EventFrame>(text) {
            Ok(frame) => self.deliver(frame),
            Err(_) => {
                self.shared.state().buffer.mark_lost();
                self.shared.ready.notify_one();
            }
        }
    }
}

/// The reading end of a call's news.
#[derive(Debug)]
pub struct CallEvents {
    shared: Arc<Shared>,
}

impl Drop for CallEvents {
    /// A reader that is gone leaves the news nobody to read. On a phone the channel native code
    /// writes to, and the sink with it, lives as long as the process, so what is queued after the
    /// reader is gone would be kept for that long: it is let go of, and nothing more is queued.
    fn drop(&mut self) {
        self.shared.state().buffer.close();
    }
}

impl CallEvents {
    /// The next item of news, or [`Heard::Lost`] where some was lost, or nothing once every sink is
    /// gone and what was queued has been read. On a phone the channel native code writes to lives
    /// as long as the process, so a reader there ends a call by reading its `Ended` news.
    pub async fn recv(&mut self) -> Option<Heard> {
        loop {
            {
                let mut state = self.shared.state();
                match state.buffer.pop() {
                    Some(Entry::Event(event)) => return Some(Heard::Event(event)),
                    Some(Entry::Lost) => return Some(Heard::Lost),
                    None if state.closed => return None,
                    None => {}
                }
            }
            self.shared.ready.notified().await;
        }
    }
}

/// A queue for one call's news, bounded at [`EVENT_QUEUE`].
#[must_use]
pub fn event_queue(call: CallId) -> (EventSink, CallEvents) {
    let shared = Arc::new(Shared {
        state: Mutex::new(State {
            buffer: NewsBuffer::new(EVENT_QUEUE),
            next: 1,
            closed: false,
        }),
        ready: Notify::new(),
        writers: AtomicUsize::new(1),
    });
    (
        EventSink {
            call,
            shared: Arc::clone(&shared),
        },
        CallEvents { shared },
    )
}

/// Why native code could not do what it was asked of a call.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureKind {
    /// The person has not let the application use the microphone.
    MicrophoneRefused,
    /// This device already holds a call.
    AlreadyRunning,
    /// No call by that name is held.
    NoSuchCall,
    /// The call named has ended.
    Ended,
    /// The media engine could not do it.
    Engine,
    /// Native code could not be asked, or answered with a reason this build does not know.
    Unavailable,
}

impl FailureKind {
    /// What a code native code rejected a command with means. A code this build does not know is
    /// [`Self::Unavailable`].
    #[must_use]
    pub fn from_code(code: &str) -> Self {
        match code {
            "microphone_refused" => Self::MicrophoneRefused,
            "already_running" => Self::AlreadyRunning,
            "no_such_call" => Self::NoSuchCall,
            "ended" => Self::Ended,
            "engine" => Self::Engine,
            _ => Self::Unavailable,
        }
    }
}

/// A command native code did not carry out.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct CallFailure {
    /// Why, as a closed set.
    pub kind: FailureKind,
    /// The platform's words for it, for a log.
    pub message: String,
}

impl CallFailure {
    /// A failure of the given kind.
    #[must_use]
    pub fn new(kind: FailureKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }
}

/// What a command can take a moment to answer.
pub type CallFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, CallFailure>> + Send + 'a>>;

/// What opening a call gave back.
#[derive(Debug)]
pub struct OpenedCall {
    /// The call, named.
    pub call: CallId,
    /// Whether notifications are allowed, which a running call's notification depends on.
    pub notifications: Permission,
    /// The call's news.
    pub events: CallEvents,
}

/// What applying the provider's answer showed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Answered {
    /// Whether the answer turns Opus discontinuous transmission on, which stops the stream during
    /// silence.
    pub uses_dtx: bool,
}

/// What native code reports of the call it holds, if it holds one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Held {
    /// The call, when one is held.
    pub call: Option<CallId>,
    /// What the microphone is doing, as the gate shows it.
    pub capture: CaptureState,
    /// Whether the person has muted their microphone. A fact of its own: a microphone that is not
    /// running shows as unavailable whatever the person did.
    pub microphone_muted: bool,
    /// Whether the person has left the model's voice on: false once they silenced it, and false
    /// when no call is held. It says nothing of whether audio is flowing.
    pub playing: bool,
}

/// What a caller asks of the voice call native code holds.
///
/// A phone's implementation is [`NativeCalls`]. A test gives its own, which answers as scripted.
pub trait CallPlatform: Send + Sync {
    /// Opens a call: asks for the microphone and for notifications, makes the connection and the
    /// provider's events channel, and keeps every device input off. Nothing is carried until the
    /// call is permitted.
    fn open(&self) -> CallFuture<'_, OpenedCall>;

    /// Makes the call's offer.
    fn offer<'a>(&'a self, call: &'a CallId) -> CallFuture<'a, String>;

    /// Applies the provider's answer. It starts nothing. An answer the call cannot use is a failure,
    /// and the call ends: native code does not keep a call that is half made.
    fn accept<'a>(&'a self, call: &'a CallId, answer: &'a str) -> CallFuture<'a, Answered>;

    /// Lets the call carry the microphone until `closes_at_epoch_ms`, once the host has started
    /// it. False, and nothing started, when the call is not ready to be permitted (the provider's
    /// answer is not applied yet), is permitted already, or has ended. False with the call ended,
    /// and the news saying so, when the moment has passed or the device refused the audio.
    fn permit<'a>(
        &'a self,
        call: &'a CallId,
        voice_session_id: &'a str,
        closes_at_epoch_ms: u64,
    ) -> CallFuture<'a, bool>;

    /// Silences the person's microphone or the model's voice, or ends the silence.
    fn mute<'a>(&'a self, call: &'a CallId, what: Mute, muted: bool) -> CallFuture<'a, ()>;

    /// Ends the call and gives the microphone back. Local and immediate.
    fn stop<'a>(&'a self, call: &'a CallId) -> CallFuture<'a, ()>;

    /// What native code reports of the call it holds.
    fn held(&self) -> CallFuture<'_, Held>;
}

/// The shapes of the commands Rust sends to native code and of what native code answers, which
/// [`NativeCalls`] speaks and the tests hold to the fixtures.
#[cfg(any(mobile, test))]
mod wire {
    use serde::{Deserialize, Serialize};

    use super::{CallId, Mute, Permission};

    /// The arguments of the command that opens a call.
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    pub(crate) struct OpenRequest<E> {
        pub(crate) call: CallId,
        pub(crate) events: E,
    }

    /// What opening a call answers.
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub(crate) struct OpenResponse {
        pub(crate) notifications: Permission,
    }

    /// The arguments of the commands that name only a call.
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    pub(crate) struct CallRequest<'a> {
        pub(crate) call: &'a CallId,
    }

    /// What making the offer answers.
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub(crate) struct OfferResponse {
        pub(crate) sdp: String,
    }

    /// The arguments of the command that applies the provider's answer.
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    pub(crate) struct AcceptRequest<'a> {
        pub(crate) call: &'a CallId,
        pub(crate) sdp: &'a str,
    }

    /// What applying the answer reports.
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub(crate) struct AcceptResponse {
        pub(crate) uses_dtx: bool,
    }

    /// The arguments of the command that permits the call.
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    pub(crate) struct PermitRequest<'a> {
        pub(crate) call: &'a CallId,
        pub(crate) voice_session_id: &'a str,
        pub(crate) closes_at_epoch_ms: u64,
    }

    /// What permitting the call answers.
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub(crate) struct PermitResponse {
        pub(crate) permitted: bool,
    }

    /// The arguments of the command that silences something.
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    pub(crate) struct MuteRequest<'a> {
        pub(crate) call: &'a CallId,
        pub(crate) what: Mute,
        pub(crate) muted: bool,
    }

    /// What a command with nothing to report answers.
    #[derive(Deserialize)]
    pub(crate) struct Nothing {}
}

#[cfg(any(mobile, test))]
use wire::*;

#[cfg(mobile)]
pub use native::NativeCalls;

#[cfg(mobile)]
mod native {
    use serde::Serialize;
    use serde::de::DeserializeOwned;
    use tauri::{AppHandle, Manager as _, Runtime};

    use super::{
        AcceptRequest, AcceptResponse, Answered, CallFailure, CallFuture, CallId, CallPlatform,
        CallRequest, FailureKind, Held, Mute, MuteRequest, Nothing, OfferResponse, OpenRequest,
        OpenResponse, OpenedCall, PermitRequest, PermitResponse, event_queue,
    };

    /// The voice call of a phone, reached through the platform plugin's native half.
    pub struct NativeCalls<R: Runtime> {
        app: AppHandle<R>,
    }

    impl<R: Runtime> NativeCalls<R> {
        /// The calls of the application `app` runs.
        #[must_use]
        pub const fn new(app: AppHandle<R>) -> Self {
            Self { app }
        }

        async fn command<T: DeserializeOwned>(
            &self,
            method: &str,
            arguments: impl Serialize,
        ) -> Result<T, CallFailure> {
            let platform = self.app.state::<crate::Platform<R>>();
            platform
                .handle
                .run_mobile_plugin_async(method, arguments)
                .await
                .map_err(|error| match error {
                    tauri::plugin::mobile::PluginInvokeError::InvokeRejected(rejected) => {
                        CallFailure::new(
                            rejected
                                .code
                                .as_deref()
                                .map_or(FailureKind::Unavailable, FailureKind::from_code),
                            rejected.message.unwrap_or_default(),
                        )
                    }
                    other => CallFailure::new(FailureKind::Unavailable, other.to_string()),
                })
        }
    }

    impl<R: Runtime> CallPlatform for NativeCalls<R> {
        fn open(&self) -> CallFuture<'_, OpenedCall> {
            Box::pin(async move {
                let call = CallId::next();
                let (sink, events) = event_queue(call.clone());
                // Held by native code for the call's life, so the news reaches this queue
                // whatever the page is doing.
                let channel = tauri::ipc::Channel::<serde_json::Value>::new(move |body| {
                    if let tauri::ipc::InvokeResponseBody::Json(text) = body {
                        sink.deliver_json(&text);
                    }
                    Ok(())
                });
                let opened: OpenResponse = self
                    .command(
                        "callOpen",
                        OpenRequest {
                            call: call.clone(),
                            events: channel,
                        },
                    )
                    .await?;
                Ok(OpenedCall {
                    call,
                    notifications: opened.notifications,
                    events,
                })
            })
        }

        fn offer<'a>(&'a self, call: &'a CallId) -> CallFuture<'a, String> {
            Box::pin(async move {
                let offered: OfferResponse =
                    self.command("callOffer", CallRequest { call }).await?;
                Ok(offered.sdp)
            })
        }

        fn accept<'a>(&'a self, call: &'a CallId, answer: &'a str) -> CallFuture<'a, Answered> {
            Box::pin(async move {
                let accepted: AcceptResponse = self
                    .command("callAccept", AcceptRequest { call, sdp: answer })
                    .await?;
                Ok(Answered {
                    uses_dtx: accepted.uses_dtx,
                })
            })
        }

        fn permit<'a>(
            &'a self,
            call: &'a CallId,
            voice_session_id: &'a str,
            closes_at_epoch_ms: u64,
        ) -> CallFuture<'a, bool> {
            Box::pin(async move {
                let permitted: PermitResponse = self
                    .command(
                        "callPermit",
                        PermitRequest {
                            call,
                            voice_session_id,
                            closes_at_epoch_ms,
                        },
                    )
                    .await?;
                Ok(permitted.permitted)
            })
        }

        fn mute<'a>(&'a self, call: &'a CallId, what: Mute, muted: bool) -> CallFuture<'a, ()> {
            Box::pin(async move {
                let _: Nothing = self
                    .command("callMute", MuteRequest { call, what, muted })
                    .await?;
                Ok(())
            })
        }

        fn stop<'a>(&'a self, call: &'a CallId) -> CallFuture<'a, ()> {
            Box::pin(async move {
                let _: Nothing = self.command("callStop", CallRequest { call }).await?;
                Ok(())
            })
        }

        fn held(&self) -> CallFuture<'_, Held> {
            Box::pin(async move { self.command("callState", serde_json::json!({})).await })
        }
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;

    use super::*;

    /// One command of the fixture the Swift and Kotlin tests decode as well.
    #[derive(Deserialize)]
    struct Case {
        command: String,
        request: serde_json::Value,
        response: serde_json::Value,
    }

    fn cases() -> Vec<Case> {
        serde_json::from_str(include_str!("../fixtures/call/commands.json")).expect("the commands")
    }

    fn of(command: &str, nth: usize) -> Case {
        cases()
            .into_iter()
            .filter(|case| case.command == command)
            .nth(nth)
            .unwrap_or_else(|| panic!("the fixture has no case {nth} of {command}"))
    }

    fn json(value: &impl Serialize) -> serde_json::Value {
        serde_json::to_value(value).expect("it encodes")
    }

    /// Each command Rust sends is the fixture's request, and each answer the fixture holds is one
    /// Rust reads: the shapes the Swift and Kotlin halves are tested against are the ones Rust
    /// speaks.
    #[test]
    fn the_commands_rust_sends_and_the_answers_it_reads_are_the_fixtures() {
        let call = CallId("c1".to_owned());

        let open = of("callOpen", 0);
        assert_eq!(
            json(&OpenRequest {
                call: call.clone(),
                events: "__CHANNEL__:7"
            }),
            open.request
        );
        let opened: OpenResponse = serde_json::from_value(open.response).expect("a response");
        assert_eq!(opened.notifications, Permission::Granted);
        let denied: OpenResponse =
            serde_json::from_value(of("callOpen", 1).response).expect("a response");
        assert_eq!(denied.notifications, Permission::Denied);

        let offer = of("callOffer", 0);
        assert_eq!(json(&CallRequest { call: &call }), offer.request);
        let offered: OfferResponse = serde_json::from_value(offer.response).expect("a response");
        assert!(offered.sdp.contains("m=application"), "{}", offered.sdp);

        let accept = of("callAccept", 0);
        assert_eq!(
            json(&AcceptRequest {
                call: &call,
                sdp: accept.request["sdp"].as_str().expect("the answer")
            }),
            accept.request
        );
        let accepted: AcceptResponse = serde_json::from_value(accept.response).expect("a response");
        assert!(accepted.uses_dtx);

        let permit = of("callPermit", 0);
        assert_eq!(
            json(&PermitRequest {
                call: &call,
                voice_session_id: "5b2f0a3c-8a56-4c53-bb7e-6a4a4a1c9e01",
                closes_at_epoch_ms: 1_760_300_000_000,
            }),
            permit.request
        );
        let permitted: PermitResponse =
            serde_json::from_value(permit.response).expect("a response");
        assert!(permitted.permitted);

        for (nth, (what, muted)) in [(Mute::Microphone, true), (Mute::Playback, false)]
            .into_iter()
            .enumerate()
        {
            let mute = of("callMute", nth);
            assert_eq!(
                json(&MuteRequest {
                    call: &call,
                    what,
                    muted
                }),
                mute.request
            );
            serde_json::from_value::<Nothing>(mute.response).expect("an empty response");
        }

        let stop = of("callStop", 0);
        assert_eq!(json(&CallRequest { call: &call }), stop.request);
        serde_json::from_value::<Nothing>(stop.response).expect("an empty response");

        let holding: Held = serde_json::from_value(of("callState", 0).response).expect("a state");
        assert_eq!(
            holding,
            Held {
                call: Some(call),
                capture: CaptureState::MutedByPerson,
                microphone_muted: true,
                playing: true
            }
        );
        let idle: Held = serde_json::from_value(of("callState", 1).response).expect("a state");
        assert_eq!(idle.call, None);
        assert_eq!(idle.capture, CaptureState::Idle);
        assert!(!idle.microphone_muted);
    }

    /// Each item of news in the fixture is one Rust reads, and writes back as it is.
    #[test]
    fn the_news_native_code_sends_is_the_fixtures() {
        #[derive(Deserialize)]
        struct News {
            name: String,
            frame: serde_json::Value,
        }
        let news: Vec<News> =
            serde_json::from_str(include_str!("../fixtures/call/events.json")).expect("the news");
        assert_eq!(news.len(), 17);
        for each in news {
            let frame: EventFrame = serde_json::from_value(each.frame.clone())
                .unwrap_or_else(|error| panic!("{}: {error}", each.name));
            assert_eq!(json(&frame), each.frame, "{}", each.name);
        }
        let provider: EventFrame = serde_json::from_value(
            serde_json::from_str::<Vec<News>>(include_str!("../fixtures/call/events.json"))
                .expect("the news")[6]
                .frame
                .clone(),
        )
        .expect("a frame");
        let CallEvent::ProviderEvent { bytes } = provider.event else {
            panic!("a provider event");
        };
        assert_eq!(bytes, br#"{"type":"session.created"}"#);
        assert_eq!(
            base64::engine::general_purpose::STANDARD.encode(&bytes),
            "eyJ0eXBlIjoic2Vzc2lvbi5jcmVhdGVkIn0="
        );
    }

    /// Native code rejects a command with a code from a closed set, and a code this build does not
    /// know reads as the platform being unavailable.
    #[test]
    fn a_rejection_is_read_by_its_code() {
        #[derive(Deserialize)]
        struct Failure {
            code: String,
            kind: FailureKind,
        }
        let failures: Vec<Failure> =
            serde_json::from_str(include_str!("../fixtures/call/failures.json")).expect("failures");
        for failure in failures {
            assert_eq!(
                FailureKind::from_code(&failure.code),
                failure.kind,
                "{}",
                failure.code
            );
        }
    }

    fn frame(call: &CallId, seq: u64, event: CallEvent) -> EventFrame {
        EventFrame {
            call: call.clone(),
            seq,
            event,
        }
    }

    /// The kind of news a fixture's step names.
    fn event_of(kind: &str) -> CallEvent {
        match kind {
            "provider" => CallEvent::ProviderEvent {
                bytes: b"{}".to_vec(),
            },
            "connection" => CallEvent::Connection {
                state: ConnectionState::Connected,
            },
            "capture" => CallEvent::Capture {
                state: CaptureState::Capturing,
            },
            "first_audio" => CallEvent::FirstAudio,
            "ended" => CallEvent::Ended,
            other => panic!("the fixture names news of a kind {other}"),
        }
    }

    fn kind_of(entry: Option<Entry>) -> &'static str {
        match entry {
            None => "none",
            Some(Entry::Lost) => "lost",
            Some(Entry::Event(CallEvent::ProviderEvent { .. })) => "provider",
            Some(Entry::Event(CallEvent::Connection { .. })) => "connection",
            Some(Entry::Event(CallEvent::Capture { .. })) => "capture",
            Some(Entry::Event(CallEvent::FirstAudio)) => "first_audio",
            Some(Entry::Event(CallEvent::Ended)) => "ended",
            Some(Entry::Event(CallEvent::Lost)) => panic!("a loss is never queued as news"),
        }
    }

    /// The buffer behaves as the fixture the Swift and Kotlin buffers are tested against says: the
    /// order news went in is the order it comes out, a loss comes out where it happened, whatever
    /// follows it, and the end is never what is dropped.
    #[test]
    fn the_buffer_keeps_the_order_and_tells_a_loss_where_it_happened() {
        #[derive(Deserialize)]
        struct Case {
            name: String,
            limit: usize,
            ops: Vec<String>,
            results: Vec<String>,
        }
        let cases: Vec<Case> =
            serde_json::from_str(include_str!("../fixtures/call/queue.json")).expect("the queue");
        assert!(cases.len() >= 10);
        for case in cases {
            let mut buffer = NewsBuffer::new(case.limit);
            let mut popped = Vec::new();
            for op in &case.ops {
                match op.strip_prefix("push ") {
                    Some(kind) => buffer.push(event_of(kind)),
                    None => popped.push(kind_of(buffer.pop()).to_owned()),
                }
            }
            assert_eq!(popped, case.results, "{}", case.name);
        }
    }

    /// The news of a call is read in the order native code numbered it, and a number that arrives
    /// a second time is not read a second time.
    #[tokio::test]
    async fn news_is_read_in_order() {
        let call = CallId("c1".to_owned());
        let (sink, mut events) = event_queue(call.clone());
        sink.deliver(frame(&call, 1, CallEvent::FirstAudio));
        sink.deliver(frame(&call, 1, CallEvent::FirstAudio));
        sink.deliver(frame(&call, 2, CallEvent::Ended));

        assert_eq!(
            events.recv().await,
            Some(Heard::Event(CallEvent::FirstAudio))
        );
        assert_eq!(events.recv().await, Some(Heard::Event(CallEvent::Ended)));
        drop(sink);
        assert_eq!(events.recv().await, None, "the repeat was not queued");
    }

    /// Nothing follows the end of a call, not even the report of a loss: the end is the last news
    /// there is, and what is told after it would be told of a call that is over.
    #[tokio::test]
    async fn nothing_follows_the_end_of_a_call_not_even_a_loss() {
        let call = CallId("c1".to_owned());
        let (sink, mut events) = event_queue(call.clone());
        sink.deliver(frame(&call, 1, CallEvent::Ended));
        sink.deliver(frame(&call, 3, CallEvent::FirstAudio));
        sink.deliver(frame(&call, 4, CallEvent::Lost));
        sink.deliver_json("not news");
        drop(sink);

        assert_eq!(events.recv().await, Some(Heard::Event(CallEvent::Ended)));
        assert_eq!(events.recv().await, None);
    }

    /// The reader is told the news has ended only when every sink is gone, however many were made.
    #[tokio::test]
    async fn the_news_has_not_ended_while_a_sink_is_left() {
        let call = CallId("c1".to_owned());
        let (sink, mut events) = event_queue(call.clone());
        let other = sink.clone();
        let reader = tokio::spawn(async move { events.recv().await });
        drop(sink);
        tokio::task::yield_now().await;
        assert!(!reader.is_finished(), "a sink is left, so the reader waits");

        other.deliver(frame(&call, 1, CallEvent::FirstAudio));
        drop(other);

        assert_eq!(
            reader.await.expect("the reader ends"),
            Some(Heard::Event(CallEvent::FirstAudio))
        );
    }

    /// News that arrives after the reader is gone is let go of: a sink that outlives its reader
    /// (a phone's channel lives as long as the process) must not keep it.
    #[tokio::test]
    async fn news_is_not_kept_for_a_reader_that_is_gone() {
        let call = CallId("c1".to_owned());
        let (sink, events) = event_queue(call.clone());
        sink.deliver(frame(&call, 1, CallEvent::FirstAudio));
        let kept = || sink.shared.state().buffer.pop().is_some();

        drop(events);
        sink.deliver(frame(
            &call,
            2,
            CallEvent::ProviderEvent { bytes: vec![0; 16] },
        ));
        sink.deliver_json("not news");

        assert!(!kept(), "nothing waits for a reader that is gone");
    }

    /// A skipped number is reported as lost news where the gap is, once, and the item after the
    /// gap is still read.
    #[tokio::test]
    async fn a_gap_in_the_numbers_is_reported_as_lost() {
        let call = CallId("c1".to_owned());
        let (sink, mut events) = event_queue(call.clone());
        sink.deliver(frame(&call, 1, CallEvent::FirstAudio));
        sink.deliver(frame(&call, 3, CallEvent::Ended));

        assert_eq!(
            events.recv().await,
            Some(Heard::Event(CallEvent::FirstAudio))
        );
        assert_eq!(events.recv().await, Some(Heard::Lost));
        assert_eq!(
            events.recv().await,
            Some(Heard::Event(CallEvent::Ended)),
            "the item after the gap is real news and is read"
        );
        drop(sink);
        assert_eq!(events.recv().await, None, "and only once");
    }

    /// News that finds the queue full is lost, and the reader is told so where it was lost, after
    /// the older news it had not read yet and before any later: the end of a call, the last news
    /// there is, is never mistaken for the quiet of a call with nothing to say.
    #[tokio::test]
    async fn news_that_finds_the_queue_full_is_reported_as_lost_in_its_place() {
        let call = CallId("c1".to_owned());
        let (sink, mut events) = event_queue(call.clone());
        let provider = || CallEvent::ProviderEvent { bytes: vec![1] };
        for seq in 1..=(EVENT_QUEUE as u64 + 5) {
            sink.deliver(frame(&call, seq, provider()));
        }
        drop(sink);

        for _ in 0..EVENT_QUEUE {
            assert_eq!(events.recv().await, Some(Heard::Event(provider())));
        }
        assert_eq!(events.recv().await, Some(Heard::Lost));
        assert_eq!(events.recv().await, None);
    }

    /// News of another call is dropped, and text that is not news is lost where it arrived.
    #[tokio::test]
    async fn news_of_another_call_is_dropped_and_text_that_is_not_news_is_lost_in_its_place() {
        let call = CallId("c1".to_owned());
        let other = CallId("c0".to_owned());
        let (sink, mut events) = event_queue(call.clone());
        sink.deliver(frame(&other, 1, CallEvent::Ended));
        sink.deliver(frame(&call, 1, CallEvent::FirstAudio));
        sink.deliver_json("not json");
        sink.deliver(frame(&call, 2, CallEvent::Ended));

        assert_eq!(
            events.recv().await,
            Some(Heard::Event(CallEvent::FirstAudio))
        );
        assert_eq!(events.recv().await, Some(Heard::Lost));
        assert_eq!(events.recv().await, Some(Heard::Event(CallEvent::Ended)));
    }

    /// A reader that is already waiting is woken by news that is lost, not only by news.
    #[tokio::test]
    async fn a_reader_that_waits_is_woken_by_text_that_is_not_news() {
        let call = CallId("c1".to_owned());
        let (sink, mut events) = event_queue(call);
        let reader = tokio::spawn(async move { events.recv().await });
        tokio::task::yield_now().await;

        sink.deliver_json("not json");

        assert_eq!(reader.await.expect("the reader ends"), Some(Heard::Lost));
    }

    /// News native code says it lost is lost to the reader, in its place.
    #[tokio::test]
    async fn a_loss_native_code_reports_is_a_loss_to_the_reader() {
        let call = CallId("c1".to_owned());
        let (sink, mut events) = event_queue(call.clone());
        sink.deliver(frame(&call, 1, CallEvent::FirstAudio));
        sink.deliver(frame(&call, 2, CallEvent::Lost));
        sink.deliver(frame(&call, 3, CallEvent::Ended));

        assert_eq!(
            events.recv().await,
            Some(Heard::Event(CallEvent::FirstAudio))
        );
        assert_eq!(events.recv().await, Some(Heard::Lost));
        assert_eq!(events.recv().await, Some(Heard::Event(CallEvent::Ended)));
    }
}
