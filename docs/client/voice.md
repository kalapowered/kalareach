# Voice client architecture

The voice client enables a person to talk to a KalaReach session using natural speech while
preserving the boundary between spoken ideas and authorised actions.

## Surface components

The voice surface is hosted in `apps/companion/src/voice/`:
- `VoiceSurface.tsx`: Renders the provider choice screen before a call, and the live call screen during a call.
- `VoiceRoute.tsx`: Connects the voice surface into the shell across desktop, iOS and Android.
- `model.ts`: Defines data types, capture states, the provider choice a preparation becomes, and local control invariants.
- `voice.css`: Accessible layout honoring platform minimum touch targets (44pt iOS, 48dp Android),
  high-contrast modes, dynamic type scaling, and reduced motion.

## Where everything the screen shows comes from

The surface holds no connection. It reaches the host through `src/host/port.ts`, the same named
commands every other screen uses, and it draws only what an answer carried.

| What the screen shows | Where it came from |
| --- | --- |
| The sessions, the scope, the cap and the grant's sentences | `voice.prepare`, from the host's own grants |
| The sessions' names | `session.list` |
| The model, the disclosure, the rate and the call limits | `voice.prepare`, in the managed service's words |
| The voice session, the model, the call and when it closes | `voice.start` |
| The microphone, the speaker and the first audio | the call this device is holding |
| A delegation's state and its words | `voice.delegate` |
| What the host selected for the call | `voice.context`, a read from the host |

No action changes what a person sees before its answer arrives, so a control that failed leaves the
screen saying what is true rather than what was attempted.

## What the person is shown before a call (KR-REQ-15.19, KR-REQ-15.09)

`voice.prepare` is the read that can answer this: the other voice read names a voice session that
does not exist yet, and by the time a start answers, the metered provider session has been created.
Preparing creates nothing, reserves nothing and sends no context, so a person can read what a call
would be and then decline it.

The provider choice screen states the voice model and the service that brokers the call, the
managed content access in the service's own words, the classes a call would carry and the classes
it would leave out, the host's cap on selected context, and what speaking would be allowed to do.
The cap is the host's and so is the enforcement of it: a start the host will not make is shown in
the host's own words.

The rate sits directly above the start control: the price of a second and of a minute in the
service's currency, the least a call is charged, and the most this call can cost. Pressing start
accepts that rate, and the start names the version shown. The host reads these terms from the
service for the answer and passes them on unchanged, so the disclosure, the note on what an
acknowledgement does not mean and the note on delegations each have one wording, the
deployment's.

Without the service's terms there is nothing to accept, so there is no start. The screen says why
in the host's words: the host has no voice service, its provider is not the managed one, or the
service did not answer. When an operator has closed managed voice, the screen lists what still
works instead.

If the rate changes between the reading and the start, the service refuses the start before
anything is held or charged. The new rate replaces the old one on screen, the old one is named
beside it, and the control reads "Start at the new rate". Nothing starts until the person presses
it.

A start also names the preparation it follows, and asks for exactly the sessions that preparation
answered. If what the call would reach, what it could do or the service that would carry it
changed in between, the host refuses the start before anything is asked of a provider, and the
screen reads the preparation again and shows it.

## What the person holds during a call

The call screen puts the capture state first, because that is what decides whether anything spoken
counted. Muting the microphone, silencing the voice and ending the session act on this device and
are never withheld for an unreachable service. Ending a call closes this device's own call first
and tells the host after, and the screen says which of the two happened rather than reporting a
revoked grant it has no answer for.

Cancelling what the agent is doing is a separate control, under its own heading, with its own
confirmation. It needs the turn the agent is on, named by the host; no host answer names one to
this screen, so the control stays off and the screen says why.

Reading what the host selected for the call is a read from the host. The screen shows the host's
selection and sends it nowhere. Both it and a cancellation need the host, and the screen says so
when the host is unreachable. Whether the voice service is answering comes from the call's own
report about its control channel and from nothing else.

A delegation the host admits without performing it is shown as admitted, with the host's note that
admission is not execution. One the host answers with a challenge for the unlocked screen is shown
with the host's words and the fact that this screen has no way to sign a confirmation, so the host
has not acted on it.

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

The end-to-end script reads everything it claims is on screen from an image, with macOS's text
recognition (the Vision framework, compiled with `swiftc`), so it runs on a Mac. Without text
recognition it fails rather than claim anything.
