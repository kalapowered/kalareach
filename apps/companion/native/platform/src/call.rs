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
//! up. A gap in the numbers, or a queue that was full when news arrived, is reported as
//! [`Heard::Lost`] and never as silence: a caller that cannot tell whether it missed a capture
//! state, a connection failure or the end of the call must not carry on as if it had not.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

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
    /// Some news was lost: the queue was full, or the numbers skipped. What the call did since the
    /// last item read is not known.
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

/// The writing end of a call's news, held by whatever receives it from native code.
#[derive(Clone, Debug)]
pub struct EventSink {
    call: CallId,
    queue: mpsc::Sender<EventFrame>,
    overflowed: Arc<AtomicBool>,
}

impl EventSink {
    /// Takes one item from native code. News of another call is a late message and is dropped; an
    /// item that finds the queue full is counted as lost.
    pub fn deliver(&self, frame: EventFrame) {
        if frame.call != self.call {
            return;
        }
        if let Err(mpsc::error::TrySendError::Full(_)) = self.queue.try_send(frame) {
            self.overflowed.store(true, Ordering::SeqCst);
        }
    }

    /// Takes one item from native code as the JSON text it arrives as. Text that is not an item is
    /// news that was lost.
    pub fn deliver_json(&self, text: &str) {
        match serde_json::from_str::<EventFrame>(text) {
            Ok(frame) => self.deliver(frame),
            Err(_) => self.overflowed.store(true, Ordering::SeqCst),
        }
    }
}

/// The reading end of a call's news.
#[derive(Debug)]
pub struct CallEvents {
    queue: mpsc::Receiver<EventFrame>,
    overflowed: Arc<AtomicBool>,
    /// The number the next item must have.
    next: u64,
    /// An item that arrived after a gap, which is read after the gap is reported.
    after_a_gap: Option<EventFrame>,
}

impl CallEvents {
    /// The next item of news, or [`Heard::Lost`] when some was lost, or nothing once the sink is
    /// gone and the queue is empty.
    pub async fn recv(&mut self) -> Option<Heard> {
        loop {
            if self.overflowed.swap(false, Ordering::SeqCst) {
                return Some(Heard::Lost);
            }
            let frame = match self.after_a_gap.take() {
                Some(frame) => frame,
                None => self.queue.recv().await?,
            };
            match frame.seq.cmp(&self.next) {
                // Heard already.
                std::cmp::Ordering::Less => {}
                std::cmp::Ordering::Equal => {
                    self.next += 1;
                    return Some(Heard::Event(frame.event));
                }
                // Numbers were skipped: the news between is gone. This item is real news and is
                // read next.
                std::cmp::Ordering::Greater => {
                    self.next = frame.seq;
                    self.after_a_gap = Some(frame);
                    return Some(Heard::Lost);
                }
            }
        }
    }
}

/// A queue for one call's news, bounded at [`EVENT_QUEUE`].
#[must_use]
pub fn event_queue(call: CallId) -> (EventSink, CallEvents) {
    let (queue, receiver) = mpsc::channel(EVENT_QUEUE);
    let overflowed = Arc::new(AtomicBool::new(false));
    (
        EventSink {
            call,
            queue,
            overflowed: Arc::clone(&overflowed),
        },
        CallEvents {
            queue: receiver,
            overflowed,
            next: 1,
            after_a_gap: None,
        },
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
    /// What the microphone is doing.
    pub capture: CaptureState,
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

    /// Applies the provider's answer. It starts nothing.
    fn accept<'a>(&'a self, call: &'a CallId, answer: &'a str) -> CallFuture<'a, Answered>;

    /// Lets the call carry the microphone until `closes_at_epoch_ms`, once the host has started
    /// it. False, and nothing changed, when the call is not ready to be permitted.
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
                playing: true
            }
        );
        let idle: Held = serde_json::from_value(of("callState", 1).response).expect("a state");
        assert_eq!(idle.call, None);
        assert_eq!(idle.capture, CaptureState::Idle);
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
        assert_eq!(news.len(), 6);
        for each in news {
            let frame: EventFrame = serde_json::from_value(each.frame.clone())
                .unwrap_or_else(|error| panic!("{}: {error}", each.name));
            assert_eq!(json(&frame), each.frame, "{}", each.name);
        }
        let provider: EventFrame = serde_json::from_value(
            serde_json::from_str::<Vec<News>>(include_str!("../fixtures/call/events.json"))
                .expect("the news")[2]
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

    /// The news of a call is read in the order native code numbered it.
    #[tokio::test]
    async fn news_is_read_in_order() {
        let call = CallId("c1".to_owned());
        let (sink, mut events) = event_queue(call.clone());
        sink.deliver(frame(&call, 1, CallEvent::FirstAudio));
        sink.deliver(frame(&call, 2, CallEvent::Ended));

        assert_eq!(
            events.recv().await,
            Some(Heard::Event(CallEvent::FirstAudio))
        );
        assert_eq!(events.recv().await, Some(Heard::Event(CallEvent::Ended)));
    }

    /// A skipped number is reported as lost news, once, and the item after the gap is still read.
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

    /// A queue that is full when news arrives reports lost news: the reader is never left with a
    /// quiet stream that dropped its end.
    #[tokio::test]
    async fn news_that_finds_the_queue_full_is_reported_as_lost() {
        let call = CallId("c1".to_owned());
        let (sink, mut events) = event_queue(call.clone());
        for seq in 1..=(EVENT_QUEUE as u64 + 5) {
            sink.deliver(frame(&call, seq, CallEvent::FirstAudio));
        }

        assert_eq!(events.recv().await, Some(Heard::Lost));
    }

    /// News of another call, and text that is not news, change nothing but the second is lost.
    #[tokio::test]
    async fn news_of_another_call_is_dropped_and_text_that_is_not_news_is_lost() {
        let call = CallId("c1".to_owned());
        let other = CallId("c0".to_owned());
        let (sink, mut events) = event_queue(call.clone());
        sink.deliver(frame(&other, 1, CallEvent::Ended));
        sink.deliver(frame(&call, 1, CallEvent::FirstAudio));
        sink.deliver_json("not json");

        assert_eq!(events.recv().await, Some(Heard::Lost));
        assert_eq!(
            events.recv().await,
            Some(Heard::Event(CallEvent::FirstAudio))
        );
    }
}
