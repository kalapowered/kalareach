//! Native desktop audio and WebRTC subsystem for the voice client.
//!
//! Section 15 paragraph 2 mandates that native WebRTC and native platform audio own capture
//! and playback, excluding any background WebView `getUserMedia` path.
//!
//! This module provides:
//! - WebRTC peer connection, audio track, and SDP offer/answer handling ([`call`]).
//! - Bounded PCM ring buffer at 120 ms target depth with libopus PLC and drop-oldest on overrun ([`buffer`]).
//! - Opus codec encoding, decoding, and PLC at 48 kHz mono ([`codec`]).
//! - macOS VoiceProcessingIO AudioUnit or unavailable error on Linux/Windows ([`device`]).
//! - Dedicated WebSocket control socket and return path with 20-second heartbeat and frame validation ([`control`]).
//! - Unlocked-screen owner verification ceremony and Ed25519 proof signing ([`ceremony`]).

pub mod buffer;
pub mod call;
pub mod ceremony;
pub mod codec;
pub mod control;
pub mod device;

pub use buffer::PcmRingBuffer;
pub use call::DesktopVoiceCall;
pub use ceremony::{confirm_voice_action, sign_voice_confirmation};
pub use codec::OpusCodec;
pub use control::{validate_context_frame, ControlSocketHandler, VoiceHeartbeatFrame};
pub use device::AudioDevice;

use std::sync::{Arc, Mutex, OnceLock};

/// Global holder for the active desktop voice call, if any.
static ACTIVE_CALL: OnceLock<Arc<Mutex<Option<DesktopVoiceCall>>>> = OnceLock::new();

/// Returns the handle to the active call storage.
pub fn active_call_holder() -> &'static Arc<Mutex<Option<DesktopVoiceCall>>> {
    ACTIVE_CALL.get_or_init(|| Arc::new(Mutex::new(None)))
}

/// Stops any currently active desktop voice call and clears the holder.
pub fn stop_active_call() {
    if let Ok(mut lock) = active_call_holder().lock() {
        if let Some(call) = lock.take() {
            call.stop();
        }
    }
}
