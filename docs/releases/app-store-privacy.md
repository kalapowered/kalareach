# App Store privacy answers for the iOS companion

This page includes the answers to the App Store privacy questions for the iOS companion (bundle identifier `to.kala.reach`). Use these to answer the questions for your developer account in App Store Connect; no build enters them. These answers are based on the privacy manifest in `apps/companion/src-tauri/gen/apple/companion-tauri_iOS/PrivacyInfo.xcprivacy` and on the code named beside each answer.

The script `scripts/ios-privacy-manifest.sh` can be used to build the app for release on the iOS Simulator. The script fails if the app links to any binary that uses APIs from a required reason API category without that category listed in that binary's bundle privacy manifest, or if there are categories listed in the app's privacy manifest that are not used by the app's main executable. However, the build cannot verify the answers for the data questions on this page, so if the data collected by the app changes, it will have to be updated manually here. Run the script whenever dependencies or code that access files, system clocks, or user defaults is changed.

## Answers to enter

The answer to "Do you or your third-party partners collect data from this app?" is Yes, and the answer to the question about tracking is No. For each of the data types in the table below, select that data type and answer the additional questions as its columns say. For data types not in the table, no data is collected, and the section on data that is not collected gives the reason for the types a reader would expect.

| Data type in App Store Connect | Linked to the person | Used for tracking | Purposes | Manifest entry |
| --- | --- | --- | --- | --- |
| Contact Info: Email Address | Yes | No | App Functionality | `NSPrivacyCollectedDataTypeEmailAddress` |
| Identifiers: User ID | Yes | No | App Functionality | `NSPrivacyCollectedDataTypeUserID` |
| Identifiers: Device ID | Yes | No | App Functionality | `NSPrivacyCollectedDataTypeDeviceID`, and the manifest of Firebase Messaging |
| User Content: Audio Data | Yes | No | App Functionality | `NSPrivacyCollectedDataTypeAudioData` |
| User Content: Other User Content | Yes | No | App Functionality | `NSPrivacyCollectedDataTypeOtherUserContent` |
| Usage Data: Other Usage Data | Yes | No | App Functionality | `NSPrivacyCollectedDataTypeOtherUsageData` |
| Diagnostics: Other Diagnostic Data | No | No | App Functionality and Analytics | The manifests of Firebase Messaging, Firebase Installations and Google Data Transport |
| Other Data: Other Data Types | No | No | Analytics | The manifest of Firebase Messaging |

The first six rows are collected by this app and linked to an account or device, and so to a person. They are not used for tracking. The last two rows are collected by Google libraries linked into the app, as their own bundle privacy manifests state, so they are included here but not in the app's privacy manifest; the App Store label covers a third party's collection as well. They can also be found by archiving the app in Xcode (Product, Archive) and choosing Generate Privacy Report from the archive's context menu in the Organizer.

This app does not perform tracking. It does not link to AdSupport or AppTrackingTransparency, it does not contain ad or analytics libraries, and it does not send data to data brokers. The app's own manifest and the manifest of every package in the app have `NSPrivacyTracking` = false and `NSPrivacyTrackingDomains` = [].

Signing in, making voice calls, syncing settings, and account recovery are all opt-in, and the app can be used without any of these features. However, per Apple's guidance, since what the app collects depends on whether the user opts in to these features, all data collected by these features must be disclosed.

## Where each data type goes

| Data type | What leaves the device | Where it goes | Code |
| --- | --- | --- | --- |
| Email Address | The address the person types on the sign-in page, which opens in the system browser. The application reads it back with the account's other details. | The account service at `reach.kala.to`, which mails the sign-in code through its email provider. | `crates/kr-client/src/services/account.rs` and `apps/companion/src-tauri/src/account/` |
| User ID | The account identifier that sign-in returns, and the identifier of this installation, which comes from the key that signs its requests. | The account service, and each managed service that checks the account or the installation: voice, settings sync and recovery. | `crates/kr-client/src/services/account.rs` and `crates/kr-client/src/services/signed.rs` |
| Device ID | The installation key, the endpoint key that relays and the discovery service see, the revocation requests an owner publishes to a host's authority feed, and the notification token that Firebase makes from the Apple push token. | The managed services at `reach.kala.to`, the relay and discovery services a pairing names, Firebase Cloud Messaging (Google) and Apple's push service. | `crates/kr-client/src/services/signed.rs`, `crates/kr-transport/src/endpoint.rs`, `apps/companion/src-tauri/src/revocation.rs` and `apps/companion/native/ios/KalaReachApp/PushStartup.swift` |
| Audio Data | What the person says during a voice call that they start. | The voice provider, OpenAI, directly over WebRTC. The managed broker sees transcript and audio events and discards them before anything is written. | `apps/companion/native/ios/KalaReachNative/VoiceCall.swift`, `apps/companion/native/ios/KalaReachNative/AudioSession.swift` and `crates/kr-client/src/services/voice.rs` |
| Other User Content | The context a voice call is given, as bounded text, and the transcript it returns. The sealed settings, drafts and recovery bundle that settings sync and recovery store. | The voice broker and provider for the length of the call. The sync service, which holds ciphertext it cannot read. | `crates/kr-client/src/services/voice_control.rs`, `apps/companion/src-tauri/src/voice/`, `apps/companion/src-tauri/src/settings/sync.rs`, `apps/companion/src-tauri/src/settings/drafts.rs` and `apps/companion/src-tauri/src/recovery.rs` |
| Other Usage Data | How much of an allowance is used: voice seconds, stored bytes and the bytes that a managed relay forwards between an endpoint pair. | The account ledger and the relay journal of the managed services. | `crates/kr-client/src/services/account.rs` reads the totals; the services that count them are in the web repository |

## Data that is not collected

All data from the terminal, prompts, session text, files, and photos stays between the user's phone and the user's own hosts, using an encrypted connection. A managed relay may forward those bytes between the two endpoints when no direct path exists. It forwards them as they arrive, counts them and keeps none. Camera and photo permissions are used to attach photos and videos to sessions on the user's own hosts.

This application does not request access to, nor read, location, contacts, health, fitness, financial or sensitive information, browsing or search history, or gameplay data. All purchases are made on the website. The application displays usage information, but does not contain a checkout form or accept payment information. When you use a managed service, your caller network address is narrowed to a network prefix before use. This is used solely to limit abuse. It cannot be used to identify your location or device.

## Required reason API

Each Mach-O file in the built release application bundle has been scanned for the use of the APIs in each category listed by Apple. The built application contains three Mach-O files: the executable, `WebRTC.framework` and the notification service extension. The executable uses file timestamps, system boot time and user defaults. `WebRTC.framework` uses file timestamps and system boot time. The extension uses none of the categories, and none of the three uses disk space or active keyboards. Some of the APIs Apple lists, such as `fstatfs` and `fstatvfs`, are not used. They are referenced in unused functions of the `rustix` crate, and when the release version is linked the unused functions are dropped. A debug build keeps these unused functions, and only the release version is used in the application, so only the release build is held to the manifest.

| Category | Reason | Apple's text | Use in the application | Binary |
| --- | --- | --- | --- | --- |
| File timestamp | `C617.1` | "Declare this reason to access the timestamps, size, or other metadata of files inside the app container, app group container, or the app’s CloudKit container." | `stat`, `lstat` and `fstat` through the Rust standard library and the `rustix` crate, called by `kr_ipc` for private directories, owner-only files and the descriptor directory, and by the drafts store, settings, the recovery record, sync membership, Tauri's lookup of its resource directory and the standard library's backtrace symbolizer, which maps the application's own executable. | `KalaReach` |
| File timestamp | `3B52.1` | "Declare this reason to access the timestamps, size, or other metadata of files or directories that the user specifically granted access to, such as using a document picker view controller." | `NSFileModificationDate` in the dialog plugin's file picker (`FilePickerController.getModifiedAtFromUrl`), for the file the person chose. The mobile capability lets the page call the plugin's open command. | `KalaReach` |
| System boot time | `35F9.1` | "Declare this reason to access the system boot time in order to measure the amount of time that has elapsed between events that occurred within the app or to perform calculations to enable timers." | `ProcessInfo.systemUptime` in `CallAdapter`, which measures how long a voice call's owner has been silent so that a call whose owner has gone ends. Nothing derived from it leaves the device. | `KalaReach` |
| User defaults | `CA92.1` | "Declare this reason to access user defaults to read and write information that is only accessible to the app itself." | `NSUserDefaults` in Firebase Core, Firebase Core Internal and GoogleUtilities, which keep installation and heartbeat records there. The application's own code does not use user defaults. | `KalaReach` |

`WebRTC.framework` includes its own privacy manifest, and reports use of the system boot time (`35F9.1` and `8FFB.1`) and file timestamp (`C617.1`) categories (`mach_absolute_time` and `stat`, respectively). The notification service extension does not import any of the APIs listed by Apple, and does not require a privacy manifest.

Two calls have no reason in Apple's list: each reads a file that is not within the application's container and was not selected by the user, and neither reads the file's timestamp. The libsodium library uses `/dev/urandom` as its source of randomness, and calls `fstat` on the file to ensure it is a character device. The call is made when libsodium is initialised; the call stack is `sodium_init` -> `randombytes_stir` -> `randombytes_sysrandom_stir`. The Rust standard library reads the system version property list the first time it checks the availability of a particular operating system version, which Objective-C code in the packages reaches through `__isPlatformVersionAtLeast`. The standard library uses `fstat` on that file to determine the buffer size when reading. The file timestamp category is declared for the container metadata above, and these two calls are stated here and not given a reason they do not match.

## Packages that need their own manifest

The following libraries included in the application are listed by Apple as needing a privacy manifest and, when they are binary dependencies, a signature. The application includes each as a source package using Swift Package Manager with a pinned revision. As such, they are not considered binary dependencies and do not require a signature. However, each library must ship with a privacy manifest, included as a resource bundle at the root of the application, or the check will fail.

| Package | Version | Resource bundle | Manifest declares |
| --- | --- | --- | --- |
| FirebaseCore | 12.19.2 | `Firebase_FirebaseCore.bundle` | User defaults (`CA92.1`) |
| FirebaseCoreInternal | 12.19.2 | `Firebase_FirebaseCoreInternal.bundle` | User defaults (`1C8F.1`) |
| FirebaseInstallations | 12.19.2 | `Firebase_FirebaseInstallations.bundle` | Other Diagnostic Data |
| FirebaseMessaging | 12.19.2 | `Firebase_FirebaseMessaging.bundle` | Device ID, Other Data Types and Other Diagnostic Data |
| GoogleDataTransport | 10.1.1 | `GoogleDataTransport_GoogleDataTransport.bundle` | Other Diagnostic Data |
| GoogleUtilities | 8.1.4 | Seven bundles named `GoogleUtilities_GoogleUtilities-` followed by AppDelegateSwizzler, Environment, Logger, Network, NSData, Reachability or UserDefaults | User defaults (Environment and UserDefaults) and file timestamp (Network) |
| nanopb | 2.30910.1 | `nanopb_nanopb.bundle` | Nothing |
| Promises (FBLPromises) | 2.4.1 | `Promises_FBLPromises.bundle` | Nothing |

The WebRTC library (sourced from the `stasel/WebRTC` package at revision `4266157cd08f`) is a binary framework. Although it is not listed by Apple, it includes a privacy manifest which is bundled in the application in `Frameworks/WebRTC.framework`. The build signs the embedded framework, as the downloaded one is not signed. Additionally, the Firebase package resolves the GoogleAppMeasurement package. However, the library is not linked into the application, and it is not included in the application bundle. There are no analytics libraries included in the application bundle.

Additionally, App Store Connect requires a URL to a public privacy policy. The privacy policy has to state the same practices as this page.
