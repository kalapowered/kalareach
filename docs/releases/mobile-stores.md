# Store bundles for the companion

Two scripts make the bundles that go to Google Play's testing tracks and to TestFlight:
`scripts/store-android.sh` and `scripts/store-ios.sh`. Each one builds a bundle, signs it, holds it
to `apps/companion/scripts/store-bundle.mjs`, and leaves the result in a directory of its own under
`~/Library/Caches/kalareach-store` (`KR_STORE_ROOT` moves it). Neither uploads anything. A build is a
heavy step, so it runs in a build slot, and the emulator leg of the Android script runs inside the
device lease.

## What the scripts read

The signing material stays outside the repository, in `~/.config/kalareach-secrets`
(`KR_SECRETS_DIR` moves it). Each file must be readable by its owner only.

| File | What it is |
| --- | --- |
| `android-upload/kalareach-upload.p12` | The Android upload key, a PKCS12 store with the alias `upload` |
| `android-upload/keystore-password` | Its password |
| `android-upload/upload-certificate.pem` | The upload key's public certificate |
| `apple/asc-api-key.json` | The App Store Connect API key's `key_id`, `issuer_id`, `team_id` and `key_file` |
| `apple/AuthKey_<key id>.p8` | The API key itself, named by `key_file` |
| `firebase-apps/google-services.json` | The Android push configuration (`KR_GOOGLE_SERVICES_JSON` names another) |
| `firebase-apps/GoogleService-Info.plist` | The iOS push configuration (`KR_GOOGLE_SERVICE_INFO` names another) |

A secret is only ever a file whose path a tool receives. The scripts never put a password or a key
on a command line, in the environment or in a log. Before a bundle is recorded, the checker reads
each secret file in its own process, searches every decompressed member of the bundle for its
text, and prints how many places held it. The Firebase files are client configuration. They go
into the bundle as the application's configuration and nowhere else.

## Version and build number

The version is `version` in `src-tauri/tauri.conf.json`. It is the Android `versionName` and the iOS
`CFBundleShortVersionString`. The notification extension's short version is a literal in
`project.yml`, so a change of version touches both files, and the check fails when they differ.

The build number is the count of whole minutes since 2026-10-01T00:00Z. It is the Android
`versionCode` and the iOS `CFBundleVersion`. Each platform keeps a receipt with the highest number
it has built and checked, and a script refuses a number at or below it. That covers a clock set
back, a number given by hand with `--build-number` and a rebuild of an old number. The two
platforms need not agree on a number. A counter in continuous integration has to start above the
receipts.

## Android

`store-android.sh` builds the release bundle for `aarch64` and `x86_64` with the NDK that
`build.gradle.kts` pins, so the native libraries are linked for 16 KB pages. It gives Gradle the
version code through `--config`. Gradle makes an unsigned bundle and never sees the key.

`jarsigner` then signs the bundle with `-storepass:file`, so the password reaches neither a command
line nor the long-lived Gradle process. `store-bundle.mjs --android` reads the finished file:

- the signature verifies and the signer is the upload certificate;
- the manifest has the package, version code and version name asked for, targets API 36, sets no
  `debuggable` flag, permits no cleartext traffic and asks for exactly the permissions the
  application declares;
- the bundle holds the requested architectures, and every loadable segment of every library is
  aligned to 16 KB;
- `bundletool validate` accepts it and its configuration asks for 16 KB page alignment;
- the resource table carries the Firebase project and application of `google-services.json`;
- the class and identifier checks of `pnpm android` pass on it.

`store-android.sh --device <directory>` makes the universal package from the signed bundle with
`bundletool`, signs it with the same key, installs it on the KalaReach emulator, starts it and
records the page size, the installed version and the platform's report on the application's links.
It then runs `e2e-android-release.sh` on that package, so the minified release is held to the TLS
verification check with the store signature on it.

The first bundle goes to Play Console by hand. Play App Signing then holds the key that signs what
people install, and its SHA-256 fingerprint belongs in the `ANDROID_APP_FINGERPRINTS` of the web
service, which serves `/.well-known/assetlinks.json`. The upload certificate does not belong there.
The same entry grants credential access to the application, and the upload key signs no
installed build.

## iOS

`store-ios.sh` runs in three steps.

1. `tauri ios build --no-sign --archive-only` archives the application and its notification
   extension. The build number goes in as the bundle version, a single integer, because `agvtool`
   writes it into every target and the store refuses more than three numbers. Tauri runs without
   any Apple credential in its environment. With the API key present it switches signing off and
   leaves an archive with no entitlements, and the team prefix of the keychain groups expands to
   nothing. A transient `Local.xcconfig` supplies the Firebase file and `AppIdentifierPrefix`.
2. `store-ios-sign.mjs` signs the archive ad hoc, deepest code first, with the entitlements of the
   two source files: the team's prefix in place of the placeholder, the production push
   environment and `get-task-allow` off. The signature names no certificate. It exists so that the
   export finds the entitlements and keeps them.
3. `xcodebuild -exportArchive` signs the build for the App Store, with `-allowProvisioningUpdates`
   and the API key. Xcode uses the cloud-managed Apple Distribution certificate and the App Store
   profiles of both identifiers, creating them when they do not exist. The export must leave the
   login keychain's signing identities and the keychain search list as they were, and the script
   fails when either changes.

`--unsigned-archive` stops after step 2, which needs no Apple account. Whatever the build changes in
the tracked files of `gen/apple` is restored when the script ends, and so is a `Local.xcconfig`
that was there before.

`store-bundle.mjs --ios` reads the exported `.ipa`:

- `codesign` verifies the application and the extension;
- the application's push environment is `production`, neither bundle lets a debugger attach, and
  the associated domains and keychain groups are the ones `identifiers.mjs` expects, the
  application's own group first;
- each bundle has an App Store profile of the team with no device list, and the application's
  profile carries the production push environment;
- the application and the extension have the same `CFBundleVersion` and `CFBundleShortVersionString`;
- the application carries `GoogleService-Info.plist`;
- `privacy-manifest.mjs` and `debug-code.mjs` hold the exported application. The device build is the
  one that is uploaded, and it can link code the Simulator build leaves out, which is why these
  two run on it and not on the Simulator's.

`ITSAppUsesNonExemptEncryption` stays out of `Info.plist` until the export-compliance answer is
given, so App Store Connect asks for it for each build.

## What a person does

The scripts stop at a checked file. Uploading is separate: the first Android bundle through Play
Console, and the iOS build with `xcrun altool --upload-app` and the same API key. The store forms,
the testers' lists, the app-signing fingerprint and the export-compliance answer are entered in the
stores' own consoles.
