# Voice on the client

The companion application owns microphone capture, audio playback, the WebRTC media path, the
provider's read-only data channel, and the device-owner unlocked-screen confirmation ceremony.
It runs on macOS, iOS and Android.

## Native audio, not a WebView path

Section 15 ¶2 explicitly forbids capturing or playing audio through a WebView `getUserMedia` path.
The native client implements media directly:

- **Desktop (macOS)**: `apps/companion/src-tauri/src/audio/` uses `AudioUnit` with
  `kAudioUnitSubType_VoiceProcessingIO` for echo cancellation, automatic gain control, and voice
  isolation. Audio samples are framed as 20ms Opus frames (48 kHz mono) and buffered in a ring buffer
  with 120ms target depth. WebRTC SDP negotiation and data channels are handled in native Rust.
- **iOS**: `apps/companion/native/ios/` uses `AVAudioSession` configured with `.playAndRecord`,
  `.spokenAudio`, `[.allowBluetooth, .defaultToSpeaker, .mixWithOthers]`, and native WebRTC via the
  pinned `stasel/WebRTC` framework.
- **Android**: `apps/companion/native/android/` uses Android's `AudioRecord` / `AudioTrack` and native
  WebRTC via `io.github.webrtc-sdk:android:150.7871.01`, managed under an active microphone foreground
  service.

## Screen lock and background audio

Section 15 ¶21: live voice stays usable after screen lock through the native iOS audio session and
Android's microphone foreground service:

- **iOS**: `UIBackgroundModes` declares `audio`. An explicitly started call maintains its audio session
  across screen locks. If capture is interrupted by an incoming phone call or system audio grab, an
  `AVAudioSession.interruptionNotification` is received and capture state transitions to `interrupted`.
- **Android**: `VoiceMicrophoneService` runs with `foregroundServiceType="microphone"`, holding a
  persistent user-visible notification while a call is active. When the screen locks, the foreground
  service preserves the microphone and speaker channels.
- **Unattended activation forbidden**: Capture is started only upon explicit user gesture (pressing
  "Start voice session"). When a call ends or is revoked, capture stops immediately and background
  audio services are deactivated. The client never activates the microphone unattended.

## Capture states and unheard speech

If capture is muted, interrupted, suspended, or unavailable, the interface displays the state plainly
and enforces the requirement that **unheard speech never authorises an action** (KR-REQ-15.36, KR-ACC-014):

- `capturing`: Microphone is on and carrying the person's voice.
- `muted_by_person`: The person pressed mute.
- `interrupted`: Another call or high-priority audio took the microphone.
- `route_changing`: Switching between speaker, receiver, or Bluetooth.
- `suspended_by_system`: The OS suspended capture.
- `unavailable`: No microphone hardware or permission is available.

Whenever capture is in any state other than `capturing`, the UI displays:
> "Nothing spoken while the microphone was not carrying your voice can authorise an action."

## Append acknowledgements and context admission

The client sends selected context and host results over the control socket as bounded context requests
(`VOICE_CONTEXT_BYTES = 500`). When the service answers with `context_admitted`, the UI shows this as
**admission**, never as execution (KR-REQ-15.17):
> "The model received this. It is not evidence that anything ran on a host; the host's own receipt is
> what says that."

Host action receipts remain the sole authority for what ran on a host.

## Local survival when the broker fails

Muting the microphone, silencing the model's voice ("Stop the voice"), and hanging up the call are
strictly local operations. They act directly on the native media pipeline and do not depend on the
broker or the network.

If the managed broker becomes unreachable during a call:
- Local microphone mute remains available.
- Silencing the model's voice remains available.
- Ending the session remains available.
- Bounded context appends and remote task cancellations are disabled, and the person is informed.

## Speech interruption vs task cancellation

Section 15 ¶13: speech interruption stops playback, not a coding task.
The call controls keep them strictly separated:
- **Stop the voice**: silences the speaker locally. It contacts no host and cancels no task.
- **Cancel the current turn**: sends a typed cancellation naming the current session and turn ID to
  the host. It requires a deliberate confirmation step ("Cancel this turn").

## Unlocked-screen ceremony

Actions requiring unlocked-screen confirmation (session closure, grant changes, arbitrary shell input,
diff application, and external delivery) require a client-signed confirmation over the action hash:
- **macOS**: `LAContext` with biometric / passcode evaluation, followed by Ed25519 signing.
- **iOS**: `LocalAuthentication` (`evaluatePolicy(.deviceOwnerAuthentication)`), followed by CryptoKit Ed25519 signing.
- **Android**: `BiometricPrompt` with device-credential fallback, followed by Ed25519 signing.
- A platform without owner presence refuses with `UNAVAILABLE` rather than falsely answering "verified".
- The signature binds the exact action hash and request ID with the paired device's identity key,
  never a session key. Provider text or model claims cannot produce a valid confirmation.
