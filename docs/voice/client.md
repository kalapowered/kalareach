# Voice on the client

The companion application holds the parts of a voice call that belong on the device: capture,
playback and the WebRTC connection in native code on each platform, the capture gate that decides
when the microphone may carry speech, the voice screen, and the device-owner confirmation ceremony.
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
- **iOS**: `apps/companion/native/ios/KalaReachNative/VoiceCall.swift` holds a native WebRTC
  connection from the pinned `stasel/WebRTC` framework. Its audio session is WebRTC's
  `RTCAudioSession`, configured for play and record in the voice chat mode, with Bluetooth headsets
  allowed and the speaker by default. WebRTC's audio unit is held off (`useManualAudio`) from the
  moment the session object exists, before any connection, so negotiating starts no recording.
- **Android**: `apps/companion/native/android/android/src/main/java/.../voice/VoiceCall.kt` holds a
  native WebRTC connection from `io.github.webrtc-sdk:android:150.7871.01`, over WebRTC's Java audio
  device, which records through `AudioRecord` and plays through `AudioTrack`. Recording and playout
  are switched off the moment the connection exists, and every recorded frame passes the capture
  gate before the encoder sees it: a frame the gate refuses is replaced with silence.

On iOS and Android the connection reads the provider's data channel and never writes to it. The
voice screen starts a call through the application's own command, which asks this build's call for
an offer before anything else; it has no connection to offer on any platform, so a start from the
screen is refused before the host is asked for anything, and the phone connections above are not
started from the screen.

## Screen lock and background audio

Section 15 ¶21: live voice stays usable after screen lock through the native iOS audio session and
Android's microphone foreground service:

- **iOS**: `UIBackgroundModes` declares `audio`. An explicitly started call maintains its audio session
  across screen locks. If capture is interrupted by an incoming phone call or system audio grab, an
  `AVAudioSession.interruptionNotification` is received and capture state transitions to `interrupted`.
- **Android**: `VoiceCallService` runs with `foregroundServiceType="microphone"`, holding a
  persistent user-visible notification while a call is active. When the screen locks, the foreground
  service preserves the microphone and speaker channels. Every action on the notification names the
  call it was shown for, so one that arrives late reaches that call or nothing.
- **Unattended activation forbidden**: building a call makes its offer with the recorder and the
  microphone track off, and opens no audio session and no foreground service. Nothing records until
  the host's answer to a start permits the call. That answer names the voice session and the moment
  the service closes it. On the phones one control, `VoiceCallControl`, then decides every step,
  and it is the only code that turns a recorder or a microphone on: it takes audio focus and the
  foreground service on Android, or the audio session on iOS, and a refusal of any of them ends the
  call; on Android nothing records until the service holds the foreground; and on every platform
  the microphone carries speech only once audio is arriving from it. Android takes that from its
  recorder's own start and stop, the desktop from the first captured frame, and iOS from the local
  source's count of audio taken in, read four times a second, which grows only while the microphone
  delivers; there the record vouches for time only up to the last reading that saw it grow, however
  capture ends and whatever the screen said while the stop was not yet noticed. The deadline is
  kept on the device's monotonic clock, read again after the platform's own steps so their time
  counts against it. The call ends at the deadline on its own thread rather than the main one. On
  the phones, anything that reaches the call's control after the deadline ends it at once: a
  change, a report from the recorder or the service, or a second permit, including for a call still
  waiting for its foreground service; on iOS a question asked of the call does too. On Android and
  the desktop every frame after the deadline is refused as well; iOS checks no frames, so there the
  microphone keeps its state until the call's own queue runs the end or something reaches the call,
  and audio reported after the deadline is not counted as heard. A stopped call never reopens, and a
  second permit for the same call is refused.
- **One call at a time**: the audio belongs to one call. On iOS a second call is refused before its
  control can change the shared audio, and a change named for a call that does not hold the audio
  does nothing. A call let go of before it opened the audio leaves it free; one that has opened it is
  kept until it ends, and a call whose offer or answer fails ends. On Android the process claims one
  call at a time and refuses a second.

## Capture states and unheard speech

If capture is muted, interrupted, suspended, or unavailable, the interface displays the state
plainly, with the statement that **unheard speech never authorises an action** (KR-REQ-15.36):

- `capturing`: Microphone is on and carrying the person's voice.
- `muted_by_person`: The person pressed mute.
- `interrupted`: Another call or high-priority audio took the microphone.
- `route_changing`: Switching between speaker, receiver, or Bluetooth.
- `suspended_by_system`: The OS suspended capture.
- `unavailable`: No microphone hardware or permission is available, or the recorder has not
  started or has failed.
- `idle`: No call has been permitted, the call has ended, or its deadline has passed.

What the screen shows and whether the microphone carries speech come from the same gate, so the two
cannot disagree. The gate keeps the recent intervals in which capture was on, and answers for the
past only: an instant later than the moment it is asked at, or older than the oldest interval it
kept, is treated as unheard. That record is what a claim that something was said would be checked
against (KR-ACC-014). The screen does not check a delegation against it: delegations reach the
screen from the host, not from the provider's channel.

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
- **Android**: `BiometricPrompt`, followed by Ed25519 signing. From Android 11 it accepts a strong
  biometric or the device credential; before it, a strong biometric only, on a device with a secure
  lock screen, because the older way to allow the credential also admits weak biometrics.
- A platform without owner presence refuses with `UNAVAILABLE` rather than falsely answering "verified".
- The signature binds the exact action hash and request ID with the paired device's identity key,
  never a session key. Provider text or model claims cannot produce a valid confirmation.

The voice screen has no way to reach these ceremonies. A challenge the host sends it is shown with
the host's words and the fact that the screen cannot sign it, and the host does not act on it.
