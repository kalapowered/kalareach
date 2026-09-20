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

## Flow of a voice call

1. **Before voice starts (KR-REQ-15.19, KR-REQ-15.09)**:
   The person is presented with:
   - The selected voice model (e.g. `gpt-live-1`) and broker origin.
   - The deployed service's exact managed content access disclosure.
   - The selected context scope (items, estimated tokens, and token cap).
   - What speaking will be allowed to do (the standing voice grant).
   - Plain statement that model statements do not constitute confirmation.
   If estimated tokens exceed the 8,000-token cap, starting the session is disabled.

2. **Call initiation**:
   The native client generates a WebRTC SDP offer and requests a managed session from KalaReach.
   The broker returns the SDP answer and session ID. Media flows directly between the native client
   and OpenAI via WebRTC; audio does not pass through KalaReach servers.

3. **During a call**:
   - The client streams microphone audio (48 kHz mono Opus).
   - Provider audio plays through the device speaker.
   - Provider events on the read-only data channel are mapped to delegations.
   - The control socket carries periodic 20-second heartbeats and bounded context requests (<= 500 bytes).

4. **Ending a call**:
   Hanging up ends the media streams and immediately revokes the session-bound voice grant on the host.

## Platform implementations

| Platform | Audio capture / playback | WebRTC stack | Unlocked-screen ceremony |
| --- | --- | --- | --- |
| macOS | VoiceProcessingIO AudioUnit | Native Rust WebRTC | `LAContext` + Ed25519 |
| iOS | `AVAudioSession` (.playAndRecord) | `stasel/WebRTC` framework | `LocalAuthentication` + CryptoKit Ed25519 |
| Android | `AudioRecord` / `AudioTrack` | `io.github.webrtc-sdk:android` | `BiometricPrompt` + Ed25519 |

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
