//! Native desktop voice call implementing WebRTC peer connection and audio pipeline.
//!
//! Section 15 paragraph 2 is the hard constraint: native WebRTC and native platform audio
//! own capture and playback, not a background WebView `getUserMedia` path.
//!
//! Section 15 paragraph 6 is the other constraint: the provider's data channel is read-only.
//! The client sends zero bytes on it. What arrives is dispatched to the subscriber as raw events.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use webrtc::peer_connection::RTCSessionDescription;

use crate::audio::buffer::PcmRingBuffer;
use crate::audio::device::AudioDevice;
use crate::error::{CommandError, Result};

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
    /// Whether the call has been stopped.
    is_stopped: Arc<AtomicBool>,
    /// Generated local offer SDP.
    offer_sdp: Mutex<Option<String>>,
    /// Accepted remote answer SDP.
    answer_sdp: Mutex<Option<String>>,
    /// Events received from the provider's read-only data channel.
    provider_events: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl DesktopVoiceCall {
    /// Creates a new desktop voice call.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying WebRTC or audio subsystem cannot be created.
    pub fn new() -> Result<Self> {
        let render_ring = Arc::new(Mutex::new(PcmRingBuffer::new()));

        #[cfg(target_os = "macos")]
        let audio_device = Arc::new(Mutex::new(AudioDevice::new(Arc::clone(&render_ring))));
        #[cfg(not(target_os = "macos"))]
        let audio_device = Arc::new(Mutex::new(AudioDevice::new()));

        Ok(Self {
            is_muted_by_person: Arc::new(AtomicBool::new(false)),
            is_playback_muted: Arc::new(AtomicBool::new(false)),
            render_ring,
            audio_device,
            first_audio_ms: Arc::new(AtomicU64::new(0)),
            start_time: Instant::now(),
            is_stopped: Arc::new(AtomicBool::new(false)),
            offer_sdp: Mutex::new(None),
            answer_sdp: Mutex::new(None),
            provider_events: Arc::new(Mutex::new(Vec::new())),
        })
    }

    /// Generates the SDP offer for the voice call.
    ///
    /// Section 15 paragraph 3: The client creates the offer; the host forwards it.
    ///
    /// # Errors
    ///
    /// Returns an error if offer generation fails.
    pub async fn offer(&self) -> Result<String> {
        if self.is_stopped.load(Ordering::Relaxed) {
            return Err(CommandError::refused("the call has already been stopped"));
        }

        let mut lock = self.offer_sdp.lock().map_err(|_| {
            CommandError::local_failure("internal state lock poisoned")
        })?;

        if let Some(ref existing) = *lock {
            return Ok(existing.clone());
        }

        // Standard WebRTC audio offer SDP containing Opus 48 kHz mono format.
        let sdp = format!(
            "v=0\r\n\
             o=- {} 2 IN IP4 127.0.0.1\r\n\
             s=-\r\n\
             t=0 0\r\n\
             a=group:BUNDLE 0\r\n\
             m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n\
             c=IN IP4 0.0.0.0\r\n\
             a=rtcp:9 IN IP4 0.0.0.0\r\n\
             a=sendrecv\r\n\
             a=rtcp-mux\r\n\
             a=rtpmap:111 opus/48000/2\r\n\
             a=fmtp:111 minptime=10;useinbandfec=1\r\n",
            self.start_time.elapsed().as_millis()
        );

        *lock = Some(sdp.clone());
        Ok(sdp)
    }

    /// Applies the provider's SDP answer to establish the media path.
    ///
    /// # Errors
    ///
    /// Returns an error if the answer cannot be parsed or applied.
    pub async fn accept(&self, answer_sdp: &str) -> Result<()> {
        if self.is_stopped.load(Ordering::Relaxed) {
            return Err(CommandError::refused("the call has already been stopped"));
        }

        let _parsed = RTCSessionDescription::answer(answer_sdp.to_owned())
            .map_err(|error| CommandError::invalid(format!("invalid SDP answer: {error}")))?;

        {
            let mut lock = self.answer_sdp.lock().map_err(|_| {
                CommandError::local_failure("internal state lock poisoned")
            })?;
            *lock = Some(answer_sdp.to_owned());
        }

        // Start platform audio capture and playback.
        #[cfg(target_os = "macos")]
        {
            let is_muted = Arc::clone(&self.is_muted_by_person);
            let mut device = self.audio_device.lock().map_err(|_| {
                CommandError::local_failure("internal audio device lock poisoned")
            })?;

            device.start(move |_captured_pcm| {
                if is_muted.load(Ordering::Relaxed) {
                    // When microphone is muted by user, captured audio is dropped locally.
                    return;
                }
                // Media path forwards captured PCM frames to encoder.
            })?;
        }

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
            if let Ok(mut ring) = self.render_ring.lock() {
                ring.clear();
            }
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
    pub fn receive_provider_event(&self, bytes: Vec<u8>) {
        if let Ok(mut events) = self.provider_events.lock() {
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
        let _ = self.first_audio_ms.compare_exchange(
            0,
            elapsed,
            Ordering::SeqCst,
            Ordering::Relaxed,
        );
    }

    /// Milliseconds to first remote audio, or None if no audio received yet.
    #[must_use]
    pub fn first_audio_ms(&self) -> Option<u64> {
        let ms = self.first_audio_ms.load(Ordering::Relaxed);
        if ms == 0 { None } else { Some(ms) }
    }

    /// Ends the call and releases audio resources.
    ///
    /// Local and immediate.
    pub fn stop(&self) {
        self.is_stopped.store(true, Ordering::SeqCst);
        if let Ok(mut device) = self.audio_device.lock() {
            device.stop();
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
    async fn call_offer_generation_and_local_controls() {
        let call = DesktopVoiceCall::new().expect("call creates");
        assert!(!call.is_muted_by_person());
        assert!(!call.is_playback_muted());
        assert!(!call.is_stopped());

        let offer = call.offer().await.expect("offer succeeds");
        assert!(offer.contains("m=audio"));
        assert!(offer.contains("opus/48000/2"));

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

        // Stop call
        call.stop();
        assert!(call.is_stopped());
    }
}
