//! What a call's state is, in the words the surface draws, on every platform this application
//! builds for.

use serde::Serialize;

/// Which of the two local silences a control acts on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Silence {
    /// The person's own microphone.
    Microphone,
    /// The model's voice coming out of this device.
    Playback,
}

/// What the call this device is holding is doing, as the screen draws it.
///
/// Read from the call itself rather than remembered anywhere else, so it stays true when nothing
/// can be reached. Section 15 ¶10 keeps local mute and closure working when the broker fails, and
/// a screen told about its own microphone by a service would lose that at the moment it matters.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct VoiceCallState {
    /// Whether this device is holding a call at all.
    pub running: bool,
    /// What the microphone is doing, in the vocabulary the surface draws.
    pub capture: &'static str,
    /// Whether the model's voice is coming out of this device.
    pub playing: bool,
    /// Milliseconds from the answer being applied to the first audio out, once there has been one.
    pub first_audio_ms: Option<u64>,
    /// The call's own control channel to the voice service: `none` when it holds none,
    /// `connected`, or `unreachable`.
    ///
    /// Whether the voice service is answering is a fact about that channel and nothing else. A
    /// host read that failed says nothing about the service, and a screen that inferred the
    /// service's state from one would be reporting the wrong connection.
    pub control: &'static str,
}

/// The state of a device holding no call.
pub(super) const NO_CALL: VoiceCallState = VoiceCallState {
    running: false,
    capture: "idle",
    playing: false,
    first_audio_ms: None,
    control: "none",
};
