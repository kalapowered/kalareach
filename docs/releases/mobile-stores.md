# Store bundles for the companion

Two scripts make the bundles that go to Google Play's testing tracks and to TestFlight:
`scripts/store-android.sh` and `scripts/store-ios.sh`. Each one builds a bundle, signs it, holds it
to `apps/companion/scripts/store-bundle.mjs`, and leaves the result in a directory of its own under
`~/Library/Caches/kalareach-store` (`KR_STORE_ROOT` moves it). Neither uploads anything. A build is a
heavy step, so it runs in a build slot, and the emulator leg of the Android script runs inside the
device lease.

## What the scripts read

The signing material stays outside the repository, in `~/.config/kalareach-secrets`
(`KR_SECRETS_DIR` moves it). The scripts refuse a keystore, a password file, an API key record or an
API key that anyone but its owner can read.

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
on a command line or in the environment. The checker reads each secret file in its own process and
searches for its text before it reads anything else from a bundle: in every decompressed member of
the Android bundle, in every file of the iOS application, and, in a run that reaches its check, in
every file of the output directory (the members of a `.aab`, `.ipa` or `.apk` one by one, and the
`.apks` set through its packages). A signed token, the kind Xcode writes into its export logs from
the API key, counts as a find as well. It prints how many places held one. When a bundle holds
one it reports that and nothing else, because the other messages quote values out of the bundle,
and an error message that quotes a secret is withheld. A run that ends early still searches its
output directory and says so when it finds something. A secret shorter than eight characters is
refused, because it would match anything. The caller's own log of a run, outside the output
directory, is not read. The Firebase files are client configuration and not secrets: they go into
the bundle as the application's configuration, and the build directories keep a copy as they do
of every resource.

## Version and build number

The version is `version` in `src-tauri/tauri.conf.json`. It is the Android `versionName` and the iOS
`CFBundleShortVersionString`. The notification extension's short version is a literal in
`project.yml`, so a change of version touches both files, and the check fails when they differ.

The build number is the count of whole minutes since 2026-10-01T00:00Z. It is the Android
`versionCode` and the iOS `CFBundleVersion`. Each platform keeps a receipt with the highest number
it has built and checked, and a script refuses a number at or below it. That covers a clock set
back, a number given by hand with `--build-number` and a rebuild of an old number. The receipt is
updated under a lock and keeps the larger number, so builds that end together cannot lower it. A
number is also claimed for its platform when a build starts, whatever the version, so two builds
of different versions in one minute cannot both ship it. The two platforms need not agree on a
number. A counter in continuous integration has to start above the receipts.

## Android

`store-android.sh` builds the release bundle for `aarch64` and `x86_64` with the NDK that
`build.gradle.kts` pins, so the native libraries are linked for 16 KB pages. It gives Gradle the
version code through `--config`. Gradle makes an unsigned bundle and never sees the key.

`jarsigner` then signs the bundle with `-storepass:file`, so the password reaches neither a command
line nor the long-lived Gradle process. `store-bundle.mjs --android` reads the finished file:

- the signature verifies, no entry was added after signing, and the signer is the upload
  certificate;
- the manifest has the package, version code and version name asked for, targets API 36, sets no
  `debuggable` or `testOnly` flag, permits no cleartext traffic, declares the verified sign-in link
  `https://reach.kala.to/app/oauth/callback` in one intent filter (the `VIEW` action, the default
  and browsable categories, the `https` scheme, the host and the path), and asks for exactly the
  permissions the checker lists (the application's own and the ones its libraries add), so a
  library that starts to ask for another stops the build;
- the bundle holds the requested architectures, read from the directory names, and every loadable
  segment of every library is aligned to 16 KB;
- `bundletool validate` accepts it and its configuration asks for 16 KB page alignment;
- the resource table carries the Firebase project and application identifiers of
  `google-services.json`;
- the identifier check passes on the signed file, after `pnpm android` ran its class check on the
  unsigned one.

`store-android.sh --device <directory>` makes the universal package from the signed bundle with
`bundletool`, signs it with the same key, installs it on the KalaReach emulator, starts it and
records the page size, the installed version and the platform's report on the application's links.
It then runs `e2e-android-release.sh` on that package, so the minified release is held to the TLS
verification check with the store signature on it.

The first bundle goes to Play Console by hand. Play App Signing then holds the key that signs what
people install, and its SHA-256 fingerprint belongs in the `ANDROID_APP_FINGERPRINTS` of the web
service, which serves `/.well-known/assetlinks.json`. The upload certificate does not belong there.
The same entry grants credential access to the application, and the upload key signs no build
that Play installs.

## iOS

`store-ios.sh` runs in three steps.

1. `tauri ios build --no-sign --archive-only` archives the application and its notification
   extension. The build number goes in as the bundle version, a single integer, because `agvtool`
   writes it into every target and the store refuses more than three numbers. Tauri runs without
   any `APPLE_*` or `IOS_*` variable in its environment: it reads several of them before it looks
   at `--no-sign`, and with a certificate present it imports the certificate into a keychain it
   makes and writes its identity into the project. The archive carries no entitlements of its own,
   and the team prefix of the keychain groups would expand to nothing, so a transient
   `Local.xcconfig` supplies `AppIdentifierPrefix` and the Firebase file.
2. `store-ios-sign.mjs` signs the archive ad hoc, deepest code first, with the entitlements of the
   two source files: the team's prefix in place of the placeholder, the production push
   environment and `get-task-allow` off. The signature names no certificate. It exists so that the
   export finds the entitlements and keeps them. The only keychain group of the extension is the
   shared one.
3. `xcodebuild -exportArchive` signs the build for the App Store, with `-allowProvisioningUpdates`
   and the API key. Xcode uses the cloud-managed Apple Distribution certificate and the App Store
   profiles of both identifiers, creating them when they do not exist. The export must leave the
   login keychain's signing identities and the keychain search list as they were, and the script
   fails when either changes.

`--unsigned-archive` stops after step 2, which needs no Apple account. The build rewrites files
under `gen/apple`, so the script refuses to start when that directory has an uncommitted change or
a new file, or when git cannot say. It puts the directory back when it ends, together with a
`Local.xcconfig` that was there before, and an edit made there while the build runs is lost with
it. When it cannot put something back, the script fails, writes no receipt and names the copy it
kept. The export saves two profiles of its own, `iOS Team Store Provisioning Profile` for each
identifier, under `~/Library/Developer/Xcode/UserData/Provisioning Profiles`. It also writes
request tokens made from the key into two logs, `export/Packaging.log` beside the exported build
and a log bundle in the temporary directory, and the script removes both.

`store-bundle.mjs --ios` reads the exported `.ipa`:

- `codesign` verifies the application and the extension, each is signed by an Apple Distribution
  certificate of the team that its own profile lists, and the entitlements it carries are ones its
  profile allows;
- the application's push environment is `production`, neither bundle lets a debugger attach, and
  the associated domains and keychain groups are the ones `identifiers.mjs` expects, the
  application's own group first;
- every framework and dylib inside a bundle is signed by an Apple Distribution certificate of the
  team, and by the same certificate as the bundle that holds it;
- each bundle has an App Store profile of the team with no device list, and the application's
  profile carries the production push environment;
- the application and the extension have the same `CFBundleVersion` and `CFBundleShortVersionString`;
- the application carries `GoogleService-Info.plist` and says it needs no export documentation
  (`ITSAppUsesNonExemptEncryption` set to false);
- `privacy-manifest.mjs` and `debug-code.mjs` hold the exported application. The device build is the
  one that is uploaded, and it can link code the Simulator build leaves out, which is why these
  two run on it and not on the Simulator's. The privacy check carries one recorded exception, the
  notification extension's import of `fstat`, which libsodium makes to confirm that
  `/dev/urandom` is a character device (the page on the App Store privacy answers states it). The
  check names it by the extension's executable and the symbol, prints it on every run, and fails on
  any other use of an API Apple lists. The checker copies the printed line into the build's record.

## Export compliance

`ITSAppUsesNonExemptEncryption` answers whether the application needs export documentation. Apple's
documentation sets it to NO for an application that uses no encryption or only forms that are
exempt from that documentation. YES needs a code that Apple issues after it has reviewed a
document, and the code goes in `ITSEncryptionExportComplianceCode`.

The application ships industry standard algorithms that the operating system does not provide.
For those, App Store Connect's table of required documentation names one document, the French
encryption declaration, and only for distribution on the App Store in France. France is not
selected, so the key is false in `project.yml` and in the generated `Info.plist`, and the plist has
no `ITSEncryptionExportComplianceCode`. The checker refuses a build whose key is anything else.
With the key false, App Store Connect asks no encryption question about the build. A build that
says YES without a code is refused at upload for an invalid export compliance code.

Before France is selected for the application, the French declaration has to be uploaded, and the
key is checked again against the same two pages.

## What a person does

The scripts stop at a checked file. A build that failed a check, or whose output directory held a
secret, leaves its files and a `store-build.json` whose `holds` is false, and no receipt: it is not
uploaded. A run that stops before its check leaves no record, and no receipt either. On Android,
`holds` covers the bundle's checks; the emulator leg is a separate command whose result is in its own
log and exit status. A failed search of the output directory for the secret fails either script and
leaves no receipt, and an iOS run that is interrupted removes Xcode's logs and searches the
directory before it ends. Uploading is
separate: the first Android bundle through Play Console, and the iOS build with
`xcrun altool --upload-app` and the same API key. The store forms and the testers' lists are
entered in the stores' own consoles. The app-signing fingerprint goes into the web service's
configuration, as above.
