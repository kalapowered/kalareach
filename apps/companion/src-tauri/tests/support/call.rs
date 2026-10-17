//! Native code as a test describes it: a voice call that does what it is told and says what a
//! test makes it say.
//!
//! The call's media cannot run in a Rust test, so this stands in for it, and the device legs prove
//! the real one. It does what native code does: one call at a time, news in order and numbered,
//! an end it tells, a refusal with the code native code gives. A test reads the commands it was
//! given, in order, and makes it tell news the way the system does.

#![allow(dead_code)]

use std::sync::{Arc, Mutex};

use companion_platform::call::{
    Answered, CallEvent, CallFailure, CallFuture, CallId, CallPlatform, CaptureState,
    ConnectionState, EventFrame, EventSink, FailureKind, Held, Mute, OpenedCall, Permission,
    event_queue,
};

/// What the offer is: a libwebrtc-shaped one, an audio section and the data section.
pub const OFFER: &str = "v=0\r\no=- 4611731400430051336 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n\
    a=group:BUNDLE 0 1\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\nc=IN IP4 0.0.0.0\r\na=mid:0\r\n\
    a=rtpmap:111 opus/48000/2\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n\
    c=IN IP4 0.0.0.0\r\na=mid:1\r\na=sctp-port:5000\r\n";

struct Inner {
    held: Option<(CallId, EventSink, u64)>,
    /// A call that ended without saying so: its channel lives on, as a phone's does for the
    /// process's life.
    ended_silently: Option<(CallId, EventSink, u64)>,
    commands: Vec<String>,
    answer: Option<String>,
    permitted_for: Option<(String, u64)>,
    capture: CaptureState,
    muted: bool,
    playing: bool,
    microphone_refused: bool,
    permit_refused: bool,
    stop_never_returns: bool,
    /// Whether a call that ends tells so.
    tells_the_end: bool,
    /// What a sign of life is answered with, when it is not what the call holds.
    alive_refusal: Option<FailureKind>,
    /// The steps a test holds: a held step has been given and does not return until released.
    held_steps: Vec<&'static str>,
}

/// Native code, as a test describes it.
pub struct ScriptedCalls {
    inner: Mutex<Inner>,
    freed: tokio::sync::Notify,
}

impl ScriptedCalls {
    /// Native code that holds no call and does everything it is asked.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(Inner {
                held: None,
                ended_silently: None,
                commands: Vec::new(),
                answer: None,
                permitted_for: None,
                capture: CaptureState::Idle,
                muted: false,
                playing: true,
                microphone_refused: false,
                permit_refused: false,
                stop_never_returns: false,
                tells_the_end: true,
                alive_refusal: None,
                held_steps: Vec::new(),
            }),
            freed: tokio::sync::Notify::new(),
        })
    }

    fn inner(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().expect("native code's state")
    }

    /// Every command it was given, by name, in order. A mute names what it silences.
    pub fn commands(&self) -> Vec<String> {
        self.inner().commands.clone()
    }

    /// How many times it was given `command`.
    pub fn count(&self, command: &str) -> usize {
        self.inner()
            .commands
            .iter()
            .filter(|each| each.as_str() == command)
            .count()
    }

    /// The answer it was given to apply.
    pub fn answer(&self) -> Option<String> {
        self.inner().answer.clone()
    }

    /// The voice session and the closing moment it was permitted for.
    pub fn permitted_for(&self) -> Option<(String, u64)> {
        self.inner().permitted_for.clone()
    }

    /// Whether it holds a call.
    pub fn holds_a_call(&self) -> bool {
        self.inner().held.is_some()
    }

    /// The person has not allowed the microphone: an open is refused.
    pub fn refuse_the_microphone(&self) {
        self.inner().microphone_refused = true;
    }

    /// The device refuses the audio when the call is permitted.
    pub fn refuse_the_permit(&self) {
        self.inner().permit_refused = true;
    }

    /// A stop that never returns, as an engine that blocks does.
    pub fn never_return_from_a_stop(&self) {
        self.inner().stop_never_returns = true;
    }

    /// Holds `step` (`open`, `offer`, `accept`, `permit` or `stop`): the command is given and counted, and
    /// does not return until [`Self::release`] lets it.
    pub fn hold(&self, step: &'static str) {
        self.inner().held_steps.push(step);
    }

    /// Lets the held `step` go on.
    pub fn release(&self, step: &'static str) {
        self.inner().held_steps.retain(|held| *held != step);
        self.freed.notify_waiters();
    }

    /// Lets `step` go on when the guard is dropped, so a test that fails while it holds a step does
    /// not leave a command waiting for ever.
    pub fn release_when_done(self: &Arc<Self>, step: &'static str) -> ReleaseWhenDropped {
        ReleaseWhenDropped {
            calls: Arc::clone(self),
            step,
        }
    }

    async fn gate(&self, step: &'static str) {
        loop {
            let freed = self.freed.notified();
            tokio::pin!(freed);
            freed.as_mut().enable();
            if !self.inner().held_steps.contains(&step) {
                return;
            }
            freed.await;
        }
    }

    /// The call ends and says nothing of it, as news that was lost would leave it.
    pub fn end_without_saying_so(&self) {
        let mut inner = self.inner();
        inner.ended_silently = inner.held.take();
    }

    /// Answers a sign of life with a refusal of this kind.
    pub fn refuse_signs_as(&self, kind: FailureKind) {
        self.inner().alive_refusal = Some(kind);
    }

    /// Tells news the way the system does: the notification's stop, a failed connection.
    pub fn tell(&self, event: CallEvent) {
        let mut inner = self.inner();
        if let Some((call, sink, seq)) = inner.held.as_mut() {
            *seq += 1;
            sink.deliver(EventFrame {
                call: call.clone(),
                seq: *seq,
                event,
            });
        }
    }

    /// News that skips a number: what the reader is told as news that was lost.
    pub fn lose_some_news(&self) {
        let mut inner = self.inner();
        let inner = &mut *inner;
        if let Some((call, sink, seq)) = inner.held.as_mut().or(inner.ended_silently.as_mut()) {
            *seq += 2;
            sink.deliver(EventFrame {
                call: call.clone(),
                seq: *seq,
                event: CallEvent::FirstAudio,
            });
        }
    }

    /// The connection fails, and native code ends the call, as it does for a connection that has
    /// failed for good: the end is told after the failure.
    pub fn fail_the_connection(&self) {
        let mut inner = self.inner();
        if let Some((call, sink, mut seq)) = inner.held.take() {
            for event in [
                CallEvent::Connection {
                    state: ConnectionState::Failed,
                },
                CallEvent::Ended,
            ] {
                seq += 1;
                sink.deliver(EventFrame {
                    call: call.clone(),
                    seq,
                    event,
                });
            }
        }
        inner.capture = CaptureState::Idle;
    }

    fn named(&self, call: &CallId) -> Result<(), CallFailure> {
        match self.inner().held.as_ref() {
            Some((held, ..)) if held == call => Ok(()),
            _ => Err(CallFailure::new(FailureKind::Ended, "that call has ended")),
        }
    }

    fn state_of(&self) -> Held {
        let inner = self.inner();
        Held {
            call: inner.held.as_ref().map(|(call, ..)| call.clone()),
            capture: inner.capture,
            microphone_muted: inner.muted,
            playing: inner.playing,
        }
    }
}

impl CallPlatform for ScriptedCalls {
    fn open(&self) -> CallFuture<'_, OpenedCall> {
        Box::pin(async move {
            self.inner().commands.push("open".to_owned());
            self.gate("open").await;
            let mut inner = self.inner();
            if inner.microphone_refused {
                return Err(CallFailure::new(
                    FailureKind::MicrophoneRefused,
                    "the microphone is not allowed",
                ));
            }
            if inner.held.is_some() {
                return Err(CallFailure::new(
                    FailureKind::AlreadyRunning,
                    "this device already holds a call",
                ));
            }
            let call = CallId::next();
            let (sink, events) = event_queue(call.clone());
            inner.held = Some((call.clone(), sink, 0));
            Ok(OpenedCall {
                call,
                notifications: Permission::Granted,
                events,
            })
        })
    }

    fn offer<'a>(&'a self, call: &'a CallId) -> CallFuture<'a, String> {
        Box::pin(async move {
            self.named(call)?;
            self.inner().commands.push("offer".to_owned());
            self.gate("offer").await;
            self.named(call)?;
            Ok(OFFER.to_owned())
        })
    }

    fn accept<'a>(&'a self, call: &'a CallId, answer: &'a str) -> CallFuture<'a, Answered> {
        Box::pin(async move {
            self.named(call)?;
            self.inner().commands.push("accept".to_owned());
            self.gate("accept").await;
            self.named(call)?;
            self.inner().answer = Some(answer.to_owned());
            Ok(Answered { uses_dtx: false })
        })
    }

    fn permit<'a>(
        &'a self,
        call: &'a CallId,
        voice_session_id: &'a str,
        closes_at_epoch_ms: u64,
    ) -> CallFuture<'a, bool> {
        Box::pin(async move {
            self.named(call)?;
            self.inner().commands.push("permit".to_owned());
            self.gate("permit").await;
            self.named(call)?;
            {
                let mut inner = self.inner();
                if inner.permit_refused {
                    return Ok(false);
                }
                inner.permitted_for = Some((voice_session_id.to_owned(), closes_at_epoch_ms));
                inner.capture = CaptureState::Capturing;
            }
            self.tell(CallEvent::Capture {
                state: CaptureState::Capturing,
            });
            Ok(true)
        })
    }

    fn mute<'a>(&'a self, call: &'a CallId, what: Mute, muted: bool) -> CallFuture<'a, ()> {
        Box::pin(async move {
            self.named(call)?;
            let mut inner = self.inner();
            inner.commands.push(format!("mute:{what:?}:{muted}"));
            match what {
                Mute::Microphone => {
                    inner.muted = muted;
                    inner.capture = if muted {
                        CaptureState::MutedByPerson
                    } else {
                        CaptureState::Capturing
                    };
                }
                Mute::Playback => inner.playing = !muted,
            }
            Ok(())
        })
    }

    fn stop<'a>(&'a self, call: &'a CallId) -> CallFuture<'a, ()> {
        Box::pin(async move {
            self.inner().commands.push("stop".to_owned());
            self.gate("stop").await;
            if self.inner().stop_never_returns {
                std::future::pending::<()>().await;
            }
            self.named(call)?;
            let tells = self.inner().tells_the_end;
            if tells {
                self.tell(CallEvent::Ended);
            }
            let mut inner = self.inner();
            inner.held = None;
            inner.capture = CaptureState::Idle;
            Ok(())
        })
    }

    fn held(&self) -> CallFuture<'_, Held> {
        Box::pin(async move {
            self.inner().commands.push("held".to_owned());
            Ok(self.state_of())
        })
    }

    fn alive<'a>(&'a self, call: &'a CallId) -> CallFuture<'a, Held> {
        Box::pin(async move {
            self.inner().commands.push("alive".to_owned());
            if let Some(kind) = self.inner().alive_refusal {
                return Err(CallFailure::new(kind, "native code refuses the sign"));
            }
            self.named(call)?;
            Ok(self.state_of())
        })
    }
}

/// Releases a held step of the scripted native code when it is dropped.
pub struct ReleaseWhenDropped {
    calls: Arc<ScriptedCalls>,
    step: &'static str,
}

impl Drop for ReleaseWhenDropped {
    fn drop(&mut self) {
        self.calls.release(self.step);
    }
}
