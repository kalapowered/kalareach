# Voice on the client

The companion application owns microphone capture, audio playback, the WebRTC media path, the
provider's read-only data channel, and the device-owner unlocked-screen confirmation ceremony.
It runs on macOS, iOS and Android.

## What a person is told before a call exists

`voice.prepare` is a read that creates nothing: no provider session, no reservation, no grant, and
no context leaves the host for it. It answers with the sessions a call would reach, what the voice
grant would permit action by action, the content classes the default context leaves out, the host's
cap on selected context and the origin of the service the call would be brokered through. Beside
those it carries the managed service's own terms, which the host reads from the service's metadata
route for the answer: the model, the disclosure, the rate with its version, the longest call the
service authorises, and whether an operator has the service open (KR-REQ-15.19, KR-REQ-15.09). The
terms travel in the service's words, and a host that could not read them says so instead.

A start names the version of the rate the person was shown. The host passes it to the service
unchanged, and a version that is no longer current comes back as `rate_changed` with the rate as
it is now. Nothing was started, held or charged, and the host wrote no grant for it, so the device
shows the new rate and starts again only when the person accepts it.

It exists because the other two answers come too late. `voice.context` names a voice session, and
there is none before a call; `voice.start` answers with the model and the disclosure, but by then
the metered provider session has been created. A person who declines after reading has to be able
to decline something that cost nothing.

## Native audio, not a WebView path

Section 15 ¶2 explicitly forbids capturing or playing audio through a WebView `getUserMedia` path.
The native client implements media directly:

- **Desktop (macOS)**: `apps/companion/src-tauri/src/audio/` uses `AudioUnit` with
  `kAudioUnitSubType_VoiceProcessingIO` for echo cancellation, automatic gain control, and voice
  isolation. Audio samples are framed as 20ms Opus frames (48 kHz mono) and buffered in a ring buffer
  with 120ms target depth. Opening a desktop call refuses, and says so, rather than answering with
  an offer no transport on this platform could carry.
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

## Context requests and admission

The control-frame rules in `apps/companion/src-tauri/src/audio/control.rs` hold every context
request to the managed service's bounds: an append over `VOICE_CONTEXT_BYTES` (500) is refused
before it would be sent rather than truncated, and a delegation identifier the call never heard is
refused. Reading what the host selected for a call is a read from the host, and the screen shows it
as the host's selection.

A delegation the host admits without performing it is shown as **admission**, never as execution
(KR-REQ-15.17), with the host's note that admission is not evidence anything ran. Host action
receipts remain the sole authority for what ran on a host.

## Local survival when the broker fails

Muting the microphone, silencing the model's voice ("Stop the voice"), and hanging up the call are
strictly local operations. They act directly on the native media pipeline and do not depend on the
broker or the network.

Whether the voice service is answering is the call's own report about its control channel. When a
call reports the service unreachable, the screen says so, and muting the microphone, silencing the
voice and ending the session stay available, as do the requests that go to the host.

## Speech interruption vs task cancellation

Section 15 ¶13: speech interruption stops playback, not a coding task.
The call controls keep them strictly separated:
- **Stop the voice**: silences the speaker locally. It contacts no host and cancels no task.
- **Cancel the current turn**: sends a typed cancellation naming the current session and turn ID to
  the host, after a deliberate confirmation step ("Cancel this turn"). It needs the turn the agent
  is on from the host; while no host answer names one, the control stays off and the screen says
  why.

## Unlocked-screen ceremony

Actions requiring unlocked-screen confirmation (session closure, grant changes, arbitrary shell input,
diff application, and external delivery) require a client-signed confirmation over the action hash:
- **macOS**: `LAContext` with biometric / passcode evaluation, followed by Ed25519 signing.
- **iOS**: `LocalAuthentication` (`evaluatePolicy(.deviceOwnerAuthentication)`), followed by CryptoKit Ed25519 signing.
- **Android**: `BiometricPrompt` with device-credential fallback, followed by Ed25519 signing.
- A platform without owner presence refuses with `UNAVAILABLE` rather than falsely answering "verified".
- The signature binds the exact action hash and request ID with the paired device's identity key,
  never a session key. Provider text or model claims cannot produce a valid confirmation.
