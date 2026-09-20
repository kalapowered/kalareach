# Voice client architecture

The voice client enables a person to talk to a KalaReach session using natural speech while
preserving the boundary between spoken ideas and authorised actions.

## Surface components

The voice surface is hosted in `apps/companion/src/voice/`:
- `VoiceSurface.tsx`: Renders the provider choice screen before a call, and the live call screen during a call.
- `VoiceRoute.tsx`: Connects the voice surface into the shell across desktop, iOS and Android.
- `model.ts`: Defines data types, capture states, provider choice, context token budgeting, and local control invariants.
- `voice.css`: Accessible layout honoring platform minimum touch targets (44pt iOS, 48dp Android),
  high-contrast modes, dynamic type scaling, and reduced motion.

## What the person is shown before a call (KR-REQ-15.19, KR-REQ-15.09)

The provider choice screen states the voice model and the service that brokers the call, the
managed content access in the deployed service's own words, the context the host has selected with
its estimated token count against the host's cap, and what speaking would be allowed to do. It also
states plainly that a statement from the model that you confirmed something is not a confirmation.
A selection over the cap leaves the start control disabled.

## What the person holds during a call

The call screen puts the capture state first, because that is what decides whether anything spoken
counted. Muting the microphone, silencing the voice and ending the session act on this device and
are never withheld for an unreachable service. Cancelling what the agent is doing is a separate
control, under its own heading, with its own confirmation, and it names the turn it was opened for.
Sending context needs the voice service; cancelling a turn needs the host; the screen says which is
which when one of them is unreachable.

A context request the service acknowledges is shown as admitted, with what admission does not mean
beside it: the model received it, and the host's own receipt is what says anything ran.

## The components underneath

`apps/companion/src-tauri/src/audio/` holds the desktop half: Opus encoding and decoding with
packet-loss concealment at 48 kHz mono, a bounded PCM ring buffer at a 120 ms target depth, the
macOS `VoiceProcessingIO` unit, the rules every control frame is held to, and the unlocked-screen
ceremony. Opening a desktop call refuses, and says so, rather than answering with an offer no
transport here could carry.

`apps/companion/native/ios/` and `apps/companion/native/android/` hold the phone's half: the
platform's own WebRTC stack, the audio session and audio focus, Android's microphone foreground
service with its notification, and each platform's device-owner ceremony.

## The unlocked-screen ceremony (KR-REQ-15.13)

Each platform authenticates the device owner and then signs the host's own challenge with the
paired device's identity key: `LAContext` on macOS, `LocalAuthentication` on iOS, `BiometricPrompt`
with a device-credential fallback on Android. A platform with no such ceremony refuses rather than
answering that the owner was present. The signature covers the exact action the host named, so a
confirmation for one action authorises nothing else, and no provider text can produce one.

| Platform | Capture and playback | Media stack | Device-owner ceremony |
| --- | --- | --- | --- |
| macOS | `VoiceProcessingIO` unit | `webrtc` (Rust) | `LAContext`, Ed25519 |
| iOS | `AVAudioSession` (`.playAndRecord`) | `stasel/WebRTC` | `LocalAuthentication`, Ed25519 |
| Android | `AudioRecord` and `AudioTrack` | `io.github.webrtc-sdk:android` | `BiometricPrompt`, Ed25519 |

## Testing and verification

Run the voice-specific test suite:
```sh
# Component and unit tests
pnpm -C apps/companion test:voice

# Native Android unit tests
./gradlew :krnative:test --rerun-tasks

# Native iOS unit tests
xcodebuild test -scheme KalaReachNativeTests

# Desktop Rust audio tests
cargo test -p companion-tauri

# End-to-end device and simulator verification
bash scripts/e2e-voice-device.sh all
```
