//! What this application reports about a voice call.
//!
//! Section 15 paragraph 2 puts capture, playback and the media path in native code, and a phone's
//! call is its native application's own. This process negotiates no connection and holds no call,
//! on any platform, so it reports a device holding none, and a control with no call to act on is
//! refused rather than answered as if it had silenced something.

mod state;

pub use state::VoiceCallState;

use crate::error::{CommandError, Result};
use state::NO_CALL;

/// This process holds no call, so there is none to stop.
#[must_use]
pub const fn stop_active_call() -> bool {
    false
}

/// This process holds no call.
///
/// # Errors
///
/// Never; the result keeps the shape a report of a held call would have.
pub const fn call_state() -> Result<VoiceCallState> {
    Ok(NO_CALL)
}

/// This process holds no call, so there is nothing to silence.
///
/// # Errors
///
/// Always: this device is not holding a voice call here.
pub fn set_muted() -> Result<VoiceCallState> {
    Err(CommandError::refused(
        "this device is not holding a voice call",
    ))
}
