//! One desktop voice call: what the person holds locally, and what the far end may send it.
//!
//! Section 15 paragraph 2 is the hard constraint: native WebRTC and native platform audio own
//! capture and playback, not a background WebView `getUserMedia` path. This end has the local
//! half of that, and not the connection: the mute controls, the playback silence, the bounded
//! queue of what the provider's channel delivered, and the platform device. Opening a call
//! refuses, because negotiating one is what the desktop cannot do yet, and a call that says it
//! opened when no audio can reach it is worse than one that says it cannot.
//!
//! Section 15 paragraph 6 is the other constraint: the provider's data channel is read-only. The
//! client sends zero bytes on it. What arrives is held, bounded, for whatever reads it.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use webrtc::peer_connection::RTCSessionDescription;

use crate::audio::buffer::PcmRingBuffer;
use crate::audio::device::AudioDevice;
use crate::error::{CommandError, Result};

/// How many provider events are held before the oldest is dropped.
pub const MAX_PENDING_PROVIDER_EVENTS: usize = 256;

/// The largest single provider event this end will hold, in bytes.
///
/// The control socket's own frame bound. An event larger than a frame is not one this client can
/// act on, and holding it would only be storing what the far end sent.
pub const MAX_PROVIDER_EVENT_BYTES: usize = 4096;

/// A running desktop voice call.
pub struct DesktopVoiceCall {
    /// Whether the person has muted their own microphone locally.
    is_muted_by_person: Arc<AtomicBool>,
    /// Whether the model's voice is silenced locally.
    is_playback_muted: Arc<AtomicBool>,
    /// The bounded PCM ring buffer for playback.
    render_ring: Arc<Mutex<PcmRingBuffer>>,
    /// Platform audio capture and render device.
    audio_device: Arc<Mutex<AudioDevice>>,
    /// Milliseconds from answer acceptance to first received audio.
    first_audio_ms: Arc<AtomicU64>,
    /// Time when the call was initiated.
    start_time: Instant,
    /// Deadline in unix epoch milliseconds when this session expires.
    closes_at_ms: Arc<AtomicU64>,
    /// Whether the call has been stopped.
    is_stopped: Arc<AtomicBool>,
    /// The local description a negotiated connection produced.
    ///
    /// A real peer connection is what fills this in, and this build has none, so it stays empty
    /// and acceptance refuses. Section 15 paragraph 3 makes the offer the client's own: one this
    /// end wrote out by hand would name candidates and a fingerprint no transport here holds, and
    /// the provider would answer an offer nothing could carry.
    local_description: Mutex<Option<String>>,
    /// Accepted remote answer SDP.
    answer_sdp: Mutex<Option<String>>,
    /// Events received from the provider's read-only data channel.
    provider_events: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl DesktopVoiceCall {
    /// Creates a new desktop voice call with default 30-minute validity.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying WebRTC or audio subsystem cannot be created.
    pub fn new() -> Result<Self> {
        Self::with_duration_seconds(1800)
    }

    /// Creates a new desktop voice call with an explicit authorised duration.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying WebRTC or audio subsystem cannot be created.
    pub fn with_duration_seconds(duration_seconds: u64) -> Result<Self> {
        let render_ring = Arc::new(Mutex::new(PcmRingBuffer::new()));

        #[cfg(target_os = "macos")]
        let audio_device = Arc::new(Mutex::new(AudioDevice::new(Arc::clone(&render_ring))));
        #[cfg(not(target_os = "macos"))]
        let audio_device = Arc::new(Mutex::new(AudioDevice::new()));

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        Ok(Self {
            is_muted_by_person: Arc::new(AtomicBool::new(false)),
            is_playback_muted: Arc::new(AtomicBool::new(false)),
            render_ring,
            audio_device,
            first_audio_ms: Arc::new(AtomicU64::new(0)),
            start_time: Instant::now(),
            closes_at_ms: Arc::new(AtomicU64::new(now_ms + duration_seconds * 1000)),
            is_stopped: Arc::new(AtomicBool::new(false)),
            local_description: Mutex::new(None),
            answer_sdp: Mutex::new(None),
            provider_events: Arc::new(Mutex::new(Vec::new())),
        })
    }

    /// Sets the deadline in milliseconds when this call session closes.
    pub fn set_closes_at_ms(&self, closes_at_ms: u64) {
        self.closes_at_ms.store(closes_at_ms, Ordering::SeqCst);
    }

    /// The offer this end would send to open a call.
    ///
    /// Section 15 paragraph 3 makes the offer the client's own, and an offer is what a peer
    /// connection produced: the candidates it gathered, the fingerprint of the certificate it
    /// holds, the codecs it will actually carry. This build negotiates no connection on the
    /// desktop, so it has no offer to give and says so.
    ///
    /// It says so rather than writing plausible SDP out by hand, because a hand-written offer
    /// would be answered. The service would hold a call open, the person would be told one had
    /// started, and no audio could ever reach it.
    ///
    /// # Errors
    ///
    /// Returns `UNAVAILABLE` on every call, until this end can negotiate a connection.
    pub async fn offer(&self) -> Result<String> {
        if self.is_stopped.load(Ordering::Relaxed) {
            return Err(CommandError::refused("the call has already been stopped"));
        }

        Err(CommandError::unavailable(
            "this desktop application cannot open a voice call",
        ))
    }

    /// Applies the provider's SDP answer to establish the media path.
    ///
    /// # Errors
    ///
    /// Returns an error if the answer cannot be parsed or applied, if the session has expired,
    /// or if the call has been stopped.
    pub async fn accept(&self, answer_sdp: &str) -> Result<()> {
        let mut device = self
            .audio_device
            .lock()
            .map_err(|_| CommandError::local_failure("internal audio device lock poisoned"))?;

        if self.is_stopped.load(Ordering::SeqCst) {
            return Err(CommandError::refused("the call has already been stopped"));
        }

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let closes_at = self.closes_at_ms.load(Ordering::SeqCst);
        if closes_at > 0 && now_ms >= closes_at {
            return Err(CommandError::refused("the voice call session has expired"));
        }

        // An answer answers a local description, and only a negotiated connection has one. The
        // order matters: a stopped or expired call is refused for what it is, and only a call that
        // could still carry audio is refused for having nothing to carry it on.
        let negotiated = self
            .local_description
            .lock()
            .map(|held| held.is_some())
            .unwrap_or(false);
        if !negotiated {
            return Err(CommandError::unavailable(
                "this call negotiated no connection, so there is nothing for an answer to complete",
            ));
        }

        let _parsed = RTCSessionDescription::answer(answer_sdp.to_owned())
            .map_err(|error| CommandError::invalid(format!("invalid SDP answer: {error}")))?;

        {
            let mut lock = self
                .answer_sdp
                .lock()
                .map_err(|_| CommandError::local_failure("internal state lock poisoned"))?;
            *lock = Some(answer_sdp.to_owned());
        }

        // Start platform audio capture and playback. Calls device.start() unconditionally,
        // which initiates VoiceProcessingIO on macOS and returns UNAVAILABLE on non-macOS.
        let is_muted = Arc::clone(&self.is_muted_by_person);
        device.start(move |_captured_pcm| {
            if !is_muted.load(Ordering::Relaxed) {
                // Media path forwards captured PCM frames to encoder.
            }
        })?;

        Ok(())
    }

    /// Stops the person's voice reaching the model, without ending the call.
    ///
    /// Local and immediate. Section 15 paragraph 10 requires local microphone and speaker
    /// mute to remain available if the broker fails.
    pub fn set_muted_by_person(&self, muted: bool) {
        self.is_muted_by_person.store(muted, Ordering::SeqCst);
    }

    /// Stops the model's voice coming out of this device, without ending the call.
    ///
    /// Section 15 paragraph 13 is explicit: speech interruption stops playback,
    /// never a coding task.
    pub fn set_playback_muted(&self, muted: bool) {
        self.is_playback_muted.store(muted, Ordering::SeqCst);
        if muted {
            let _ = self.render_ring.lock().map(|mut ring| ring.clear());
        }
    }

    /// Whether the person's microphone is muted.
    #[must_use]
    pub fn is_muted_by_person(&self) -> bool {
        self.is_muted_by_person.load(Ordering::SeqCst)
    }

    /// Whether playback is muted.
    #[must_use]
    pub fn is_playback_muted(&self) -> bool {
        self.is_playback_muted.load(Ordering::SeqCst)
    }

    /// Records incoming provider data channel bytes (read-only data channel).
    ///
    /// Bounded, and the oldest is dropped first. What arrives here is written by the provider, so
    /// an unbounded queue would let the far end decide how much memory this process holds.
    pub fn receive_provider_event(&self, bytes: Vec<u8>) {
        if bytes.len() > MAX_PROVIDER_EVENT_BYTES {
            return;
        }
        if let Ok(mut events) = self.provider_events.lock() {
            while events.len() >= MAX_PENDING_PROVIDER_EVENTS {
                events.remove(0);
            }
            events.push(bytes);
        }
    }

    /// Consumes and returns all received provider data channel events.
    #[must_use]
    pub fn drain_provider_events(&self) -> Vec<Vec<u8>> {
        self.provider_events
            .lock()
            .map(|mut guard| guard.drain(..).collect())
            .unwrap_or_default()
    }

    /// Records that the first remote audio packet has arrived (KR-PERF-010).
    pub fn record_first_audio(&self) {
        let elapsed = self.start_time.elapsed().as_millis() as u64;
        let _ =
            self.first_audio_ms
                .compare_exchange(0, elapsed, Ordering::SeqCst, Ordering::Relaxed);
    }

    /// Milliseconds to first remote audio, or None if no audio received yet.
    #[must_use]
    pub fn first_audio_ms(&self) -> Option<u64> {
        let ms = self.first_audio_ms.load(Ordering::Relaxed);
        if ms == 0 { None } else { Some(ms) }
    }

    /// Ends the call and releases audio resources.
    ///
    /// Local and immediate. Serialised against acceptance so capture cannot start after closure.
    pub fn stop(&self) {
        if let Ok(mut device) = self.audio_device.lock() {
            if self.is_stopped.swap(true, Ordering::SeqCst) {
                return;
            }
            device.stop();
        } else {
            self.is_stopped.store(true, Ordering::SeqCst);
        }
        if let Ok(mut ring) = self.render_ring.lock() {
            ring.clear();
        }
    }

    /// Whether the call has been stopped.
    #[must_use]
    pub fn is_stopped(&self) -> bool {
        self.is_stopped.load(Ordering::SeqCst)
    }
}

impl Drop for DesktopVoiceCall {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_local_controls_work_on_a_call_this_build_cannot_open() {
        let call = DesktopVoiceCall::new().expect("call creates");
        assert!(!call.is_muted_by_person());
        assert!(!call.is_playback_muted());
        assert!(!call.is_stopped());

        // No connection is negotiated here, so there is no offer to give. Answering with SDP this
        // end wrote out by hand would have the service hold a call open that no audio could reach.
        let refusal = call.offer().await.expect_err("this build has no offer");
        assert_eq!(
            refusal.code,
            kr_protocol::error::ErrorCode::ResourceUnavailable
        );

        // Mute microphone
        call.set_muted_by_person(true);
        assert!(call.is_muted_by_person());
        call.set_muted_by_person(false);
        assert!(!call.is_muted_by_person());

        // Mute playback
        call.set_playback_muted(true);
        assert!(call.is_playback_muted());
        call.set_playback_muted(false);
        assert!(!call.is_playback_muted());

        // Data channel event reception (read-only)
        call.receive_provider_event(b"test_event".to_vec());
        let events = call.drain_provider_events();
        assert_eq!(events, vec![b"test_event".to_vec()]);

        // What the far end sends does not decide how much this process holds.
        for index in 0..(MAX_PENDING_PROVIDER_EVENTS + 50) {
            call.receive_provider_event(format!("event_{index}").into_bytes());
        }
        call.receive_provider_event(vec![0u8; MAX_PROVIDER_EVENT_BYTES + 1]);
        let held = call.drain_provider_events();
        assert_eq!(held.len(), MAX_PENDING_PROVIDER_EVENTS);
        assert!(
            held.iter()
                .all(|event| event.len() <= MAX_PROVIDER_EVENT_BYTES)
        );

        // Stop call
        call.stop();
        assert!(call.is_stopped());
    }

    #[tokio::test]
    async fn an_answer_to_a_call_that_negotiated_nothing_is_refused() {
        let call = DesktopVoiceCall::new().expect("call creates");
        let refusal = call.accept("v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\n").await.expect_err("there is nothing to complete");
        assert_eq!(
            refusal.code,
            kr_protocol::error::ErrorCode::ResourceUnavailable
        );
        assert!(
            refusal.message.contains("negotiated no connection"),
            "refused for the wrong reason: {}",
            refusal.message
        );
    }

    #[tokio::test]
    async fn stopped_call_acceptance_is_refused() {
        let call = DesktopVoiceCall::new().expect("call creates");
        call.stop();
        assert!(call.is_stopped());

        let refusal = call.accept("v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\n").await.expect_err("a stopped call refuses");
        // Named, so this test fails if the stop guard goes and another refusal covers for it.
        assert!(
            refusal.message.contains("already been stopped"),
            "refused for the wrong reason: {}",
            refusal.message
        );
    }

    #[tokio::test]
    async fn expired_call_acceptance_is_refused() {
        let call = DesktopVoiceCall::new().expect("call creates");
        call.set_closes_at_ms(1); // Expired timestamp

        let refusal = call.accept("v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\nm=audio 9 UDP/TLS/RTP/SAVPF 111\r\n").await.expect_err("an expired call refuses");
        // Named, so this test fails if the deadline guard goes and another refusal covers for it.
        assert!(
            refusal.message.contains("expired"),
            "refused for the wrong reason: {}",
            refusal.message
        );
    }
}
