# Media stack survey and selection for the voice client

Section 15 paragraph 2 requires native WebRTC and native platform audio for capture and playback,
excluding any background WebView `getUserMedia` path. This document surveys candidate stacks for
iOS and Android, records licensing and dependency audits, and settles the pinned dependencies for
the client.

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

## 2. License and dependency audit summary

- WebRTC iOS / Android: BSD-3-Clause.
- No GPL, LGPL, or unpinned dependencies introduced.
