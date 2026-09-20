# Media stack survey and selection for the voice client

Section 15 paragraph 2 requires native WebRTC and native platform audio for capture and playback,
excluding any background WebView `getUserMedia` path. This document surveys candidate stacks for
iOS, Android, and desktop (macOS, Linux, Windows), records licensing and dependency audits, and
settles the pinned dependencies for the client.

## 1. Candidate evaluation

### iOS

| Candidate | Licence | Pinning | Simulator support | Size | Verdict |
| --- | --- | --- | --- | --- | --- |
| **`stasel/WebRTC` XCFramework M153** | BSD-3-Clause | Swift Package Manager `binaryTarget` via `project.yml` with revision pin `4266157cd08f92115de885ab12d87196a8db87e1` and committed `Package.resolved` | `ios-x86_64_arm64-simulator` slice with arm64 included | 12 MB iOS arm64 slice, 28 MB simulator slice | **Chosen** |
| Google prebuilt iOS framework | BSD-3-Clause | No longer published by Google; requires depot_tools source build | N/A | N/A | Rejected: source build is not reproducible within build budget |
| `LiveKitWebRTC` | Apache-2.0 over BSD-3-Clause | SPM, checksummed | Yes | Comparable | Rejected: symbols prefixed with `LK`, unneeded wrapper layer |

Framework checksum: `3e3a8946f27510133e3feed04d05fa23505bbe366e977620503bfc7986c2b78f` (SHA-256).
`MinimumOSVersion` is 12.0 (below project deployment target 14.0). Includes `PrivacyInfo.xcprivacy`.

### Android

| Candidate | Licence | Pinning | Emulator support | Size | Verdict |
| --- | --- | --- | --- | --- | --- |
| **`io.github.webrtc-sdk:android:150.7871.01`** | BSD-3-Clause | Maven Central coordinate with Gradle strict constraint `strictly("150.7871.01")` and checksum gate | `jni/arm64-v8a` and `jni/x86_64` | 49 MB AAR; 12.3 MB `libjingle_peerconnection_so.so` | **Chosen** |
| `org.webrtc:google-webrtc:1.0.32006` | BSD-3-Clause | Maven coordinate | Yes | Smaller | Rejected: unmaintained since 2021; depends on defunct JCenter |
| `io.getstream:stream-webrtc-android` | BSD-3-Clause wrapper | Maven coordinate | Yes | Comparable | Rejected: superfluous Kotlin wrapper layer over the same upstream |

AAR checksum: `0a1627b1a48c2bc17d9a40d62fc47bd45166f44a311e95917f147c402de379b0` (SHA-256).
ELF alignment verification: `PT_LOAD` segments in `jni/arm64-v8a/libjingle_peerconnection_so.so` align to `0x4000` (16 KiB), satisfying Android 15 page alignment constraints.

### Desktop

| Candidate | Licence | Pinning | Verdict |
| --- | --- | --- | --- |
| **`webrtc` `=0.21.0`** | MIT OR Apache-2.0 | crates.io exact lockfile | **Chosen, unconditional**: Pure Rust WebRTC peer connection, signalling, and data channel. Compiles cleanly across targets. |
| **`coreaudio-rs` `=0.14.2`** | MIT OR Apache-2.0 | crates.io exact lockfile | **Chosen for macOS**: Drives `AudioUnit` of `IOType::VoiceProcessingIO` (48 kHz mono duplex unit providing hardware/OS acoustic echo cancellation, noise suppression, and AGC). Safe callback APIs preserve `unsafe_code = "deny"`. |
| **`opus` `=0.4.0`** + **`opusic-sys` `=0.7.5`** | MIT OR Apache-2.0 / BSD-3-Clause | crates.io exact lockfile | **Chosen for macOS**: 48 kHz mono Opus encoding and decoding with native packet-loss concealment (PLC). |
| `cpal` (`0.17.x` / `0.18.x`) | Apache-2.0 | crates.io | **Rejected**: Unconditionally references macOS 14.2 symbols (`AudioHardwareCreateProcessTap`), violating project floor of macOS 13.0. |
| `webrtc-audio-processing` `=2.1.0` | BSD-3-Clause + Apache-2.0 | crates.io | **Rejected**: Downloads external unpinned Abseil if not on system; requires meson/ninja; unneeded on macOS due to native VoiceProcessingIO. |
| Linux / Windows native audio backends | — | — | **Unimplemented in this branch**: Stubs return `CommandError::unavailable`, matching `verify.rs`. Future work: WASAPI capture/render with AEC on Windows; PipeWire/ALSA on Linux. |

## 2. Jitter buffer and receive pipeline design

Rather than relying on unbounded queues or duration-capped buffers that clear periodically, the desktop
receive path implements:
- Direct RTP depacketisation via `webrtc::rtp` and Opus decoding via libopus.
- A bounded PCM ring buffer targeting a 120 ms depth.
- Drop-oldest discipline upon buffer overrun to bound latency rather than allow progressive delay drift.
- Libopus packet loss concealment (PLC) on packet gap/drop.
- Render callback drains directly from the bounded ring buffer.

## 3. License and dependency audit summary

- WebRTC iOS / Android: BSD-3-Clause.
- webrtc-rs (`0.21.0`): MIT OR Apache-2.0.
- opus (`0.4.0`) / opusic-sys (`0.7.5`) / libopus: BSD-3-Clause / MIT OR Apache-2.0.
- coreaudio-rs (`0.14.2`): MIT OR Apache-2.0.
- No GPL, LGPL, or unpinned dependencies introduced.
