//! Native desktop audio and WebRTC subsystem for the voice client.
//!
//! Section 15 paragraph 2 mandates that native WebRTC and native platform audio own capture
//! and playback, excluding any background WebView `getUserMedia` path.
//!
//! What is here:
//! - one call's local state, its mute controls and the bound on what the provider's channel may
//!   leave in memory ([`call`]); opening a call refuses, because this end negotiates no connection;
//! - a bounded PCM ring buffer at 120 ms target depth, dropping the oldest on overrun ([`buffer`]);
//! - Opus encoding, decoding and packet-loss concealment at 48 kHz mono ([`codec`]);
//! - the macOS `VoiceProcessingIO` unit, and a refusal on Linux and Windows ([`device`]);
//! - the control frames' own rules: what each frame must carry, what is refused, the heartbeat's
//!   interval, and which delegations one call may be asked about ([`control`]);
//! - the unlocked-screen ceremony and the signature over the host's challenge ([`ceremony`]).

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
pub use control::{ControlSocketHandler, VoiceHeartbeatFrame, validate_context_frame};
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
    if let Ok(mut lock) = active_call_holder().lock()
        && let Some(call) = lock.take()
    {
        call.stop();
    }
}
