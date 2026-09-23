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
//!
//! The media stack is built into the desktop application only. A phone's calls are the native
//! application's own, and a phone build of this module holds none: it reports no call, and its
//! mute is refused, in the same words the desktop uses when it holds no call.

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub mod buffer;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub mod call;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub mod ceremony;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub mod codec;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub mod control;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub mod device;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub mod gate;
mod state;

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub use buffer::PcmRingBuffer;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub use call::DesktopVoiceCall;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub use ceremony::{confirm_voice_action, sign_voice_confirmation};
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub use codec::OpusCodec;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub use control::{ControlSocketHandler, VoiceHeartbeatFrame, validate_context_frame};
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub use device::AudioDevice;
pub use state::{Silence, VoiceCallState};

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
use std::sync::{Arc, Mutex, OnceLock};

use crate::error::{CommandError, Result};
use state::NO_CALL;

/// Global holder for the active desktop voice call, if any.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
static ACTIVE_CALL: OnceLock<Arc<Mutex<Option<DesktopVoiceCall>>>> = OnceLock::new();

/// Returns the handle to the active call storage.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub fn active_call_holder() -> &'static Arc<Mutex<Option<DesktopVoiceCall>>> {
    ACTIVE_CALL.get_or_init(|| Arc::new(Mutex::new(None)))
}

/// Takes the holder's lock, or reports that this process lost it.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn held() -> Result<std::sync::MutexGuard<'static, Option<DesktopVoiceCall>>> {
    active_call_holder()
        .lock()
        .map_err(|_| CommandError::local_failure("the voice call lock is poisoned"))
}

/// Whether this device is holding a call that has not been stopped.
#[must_use]
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub fn holding_a_call() -> bool {
    held().is_ok_and(|call| call.as_ref().is_some_and(|running| !running.is_stopped()))
}

/// Holds one negotiated call for the life of the session.
///
/// Refuses rather than replacing: one microphone, one call. The check and the publication happen
/// under the same lock, so two starts racing cannot both believe they won.
///
/// # Errors
///
/// Returns an error when a call is already running or the lock is poisoned.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub fn hold_call(call: DesktopVoiceCall) -> Result<()> {
    let mut holder = held()?;
    hold_in(&mut holder, call)
}

/// Puts one call in a holder, refusing to displace a running one.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn hold_in(holder: &mut Option<DesktopVoiceCall>, call: DesktopVoiceCall) -> Result<()> {
    if holder.as_ref().is_some_and(|running| !running.is_stopped()) {
        return Err(CommandError::refused(
            "this device is already holding a voice call",
        ));
    }
    // A stopped call left in the holder is replaced, and stopped again first: the second stop is
    // what releases the device if the first one only marked it.
    if let Some(previous) = holder.replace(call) {
        previous.stop();
    }
    Ok(())
}

/// Stops the call this device is holding and clears the holder.
///
/// Answers whether there was one, so a closure can say what it actually closed.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub fn stop_active_call() -> bool {
    let Ok(mut holder) = held() else {
        return false;
    };
    stop_in(&mut holder)
}

/// Stops and clears whatever one holder is holding.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn stop_in(holder: &mut Option<DesktopVoiceCall>) -> bool {
    match holder.take() {
        Some(call) => {
            call.stop();
            true
        }
        None => false,
    }
}

/// Reads what the held call is doing.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn state_of(call: Option<&DesktopVoiceCall>) -> VoiceCallState {
    let Some(call) = call.filter(|call| !call.is_stopped()) else {
        return NO_CALL;
    };
    VoiceCallState {
        running: true,
        // The call's own gate: nothing before the host permitted it, and the person's mute kept
        // apart from the call running, because a muted microphone heard nothing, which is what the
        // refusal of an unheard claim is built on.
        capture: call.capture_state(),
        playing: !call.is_playback_muted(),
        first_audio_ms: call.first_audio_ms(),
        // A desktop call opens no control channel to the voice service.
        control: "none",
    }
}

/// What the call this device is holding is doing right now.
///
/// # Errors
///
/// Returns an error when the lock is poisoned.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub fn call_state() -> Result<VoiceCallState> {
    Ok(state_of(held()?.as_ref()))
}

/// Silences the microphone or the speaker, and answers with what changed.
///
/// # Errors
///
/// Returns an error when no call is running or the lock is poisoned.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub fn set_muted(what: Silence, muted: bool) -> Result<VoiceCallState> {
    let holder = held()?;
    mute_in(&holder, what, muted)
}

/// Silences one holder's call.
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn mute_in(
    holder: &Option<DesktopVoiceCall>,
    what: Silence,
    muted: bool,
) -> Result<VoiceCallState> {
    let Some(call) = holder.as_ref().filter(|call| !call.is_stopped()) else {
        return Err(CommandError::refused(
            "this device is not holding a voice call",
        ));
    };
    match what {
        Silence::Microphone => call.set_muted_by_person(muted),
        Silence::Playback => call.set_playback_muted(muted),
    }
    Ok(state_of(Some(call)))
}

/// A phone build holds no call in this process.
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
#[must_use]
pub const fn holding_a_call() -> bool {
    false
}

/// A phone build holds no call in this process, so there is none to stop.
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
#[must_use]
pub const fn stop_active_call() -> bool {
    false
}

/// A phone build holds no call in this process.
///
/// # Errors
///
/// Never; the result keeps the desktop's shape.
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub const fn call_state() -> Result<VoiceCallState> {
    Ok(NO_CALL)
}

/// A phone build holds no call in this process, so there is nothing to silence.
///
/// # Errors
///
/// Always: this device is not holding a voice call here.
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub fn set_muted(_what: Silence, _muted: bool) -> Result<VoiceCallState> {
    Err(CommandError::refused(
        "this device is not holding a voice call",
    ))
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
#[cfg(test)]
mod tests {
    use super::*;

    /// The state a call reports is read from the call, not from what was asked for.
    ///
    /// KR-REQ-15.17: local mute and closure keep working when the broker fails, and that is only
    /// true if what the screen shows about them comes from this device.
    #[test]
    fn the_state_of_a_call_is_what_the_call_says() {
        let call = DesktopVoiceCall::new().expect("a call");
        assert_eq!(state_of(None), NO_CALL);

        let running = state_of(Some(&call));
        assert!(running.running);
        // Held, and not permitted by any host answer, so it captures nothing.
        assert_eq!(running.capture, "idle");
        assert!(running.playing);

        call.set_muted_by_person(true);
        call.set_playback_muted(true);
        let silenced = state_of(Some(&call));
        // The person's own mute is not the call ending: it is still running, and it heard nothing.
        assert!(silenced.running);
        assert!(call.is_muted_by_person());
        assert_eq!(silenced.capture, "idle");
        assert!(!silenced.playing);

        call.stop();
        assert_eq!(state_of(Some(&call)), NO_CALL);
    }

    /// A stopped call is not one this device is holding, however it is still stored.
    #[test]
    fn a_stopped_call_is_not_one_this_device_holds() {
        let call = DesktopVoiceCall::new().expect("a call");
        call.stop();
        assert_eq!(state_of(Some(&call)).capture, "idle");
        assert!(!state_of(Some(&call)).running);
    }

    /// Section 15 paragraph 22: the microphone is never silently activated. A second call over a
    /// running one would be exactly that, so the holder refuses instead of replacing.
    #[test]
    fn one_call_at_a_time() {
        let mut holder = None;
        hold_in(&mut holder, DesktopVoiceCall::new().expect("a call")).expect("the first call");
        let refused = hold_in(&mut holder, DesktopVoiceCall::new().expect("a call"))
            .expect_err("a second call over a running one");
        assert_eq!(
            refused.code,
            kr_protocol::error::ErrorCode::PermissionDenied
        );
        assert!(holder.is_some(), "the running call is still the one held");

        // Once it has been stopped, the device is free and the next call takes the holder.
        stop_in(&mut holder);
        assert!(holder.is_none());
        hold_in(&mut holder, DesktopVoiceCall::new().expect("a call")).expect("the next call");
        assert!(holder.is_some());
    }

    /// A closure says what it closed, so a screen can report the local half honestly.
    #[test]
    fn a_closure_answers_whether_there_was_a_call() {
        let mut holder = None;
        assert!(!stop_in(&mut holder), "there was nothing to close");
        hold_in(&mut holder, DesktopVoiceCall::new().expect("a call")).expect("a call");
        assert!(stop_in(&mut holder), "the call this device held was closed");
        assert!(!stop_in(&mut holder), "and closing again closes nothing");
    }

    /// KR-REQ-15.17: mute acts on the call this device is holding, and refuses when there is none
    /// rather than reporting a silence that nothing is keeping.
    #[test]
    fn mute_refuses_when_no_call_is_running() {
        let mut holder = None;
        let refused = mute_in(&holder, Silence::Microphone, true).expect_err("no call to silence");
        assert_eq!(
            refused.code,
            kr_protocol::error::ErrorCode::PermissionDenied
        );

        hold_in(&mut holder, DesktopVoiceCall::new().expect("a call")).expect("a call");
        let muted = mute_in(&holder, Silence::Microphone, true).expect("the call is silenced");
        // No host answer permitted this call, so there is nothing to capture either way.
        assert_eq!(muted.capture, "idle");
        let playing = mute_in(&holder, Silence::Playback, true).expect("the speaker is silenced");
        assert!(!playing.playing);
        // Silencing the speaker left the microphone exactly as it was: they are two controls.
        assert!(
            holder
                .as_ref()
                .is_some_and(DesktopVoiceCall::is_muted_by_person)
        );
    }
}
