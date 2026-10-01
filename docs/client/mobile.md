# The companion application on a phone

The iOS and Android builds of `apps/companion` are the same product as the desktop window: one
semantic interface, one design, one set of named commands to the host. What differs is the layout,
the input and what has to survive the operating system taking the process away.

This describes what the product does on a phone, how it is put together and how to run it. Where it
does not do something, the text says so, and those sentences carry as much weight as the rest.

## The two halves

| Half | Where | What it does |
| --- | --- | --- |
| The interface | `apps/companion/src/mobile` | The attention inbox, the sessions and hosts lists, the session's conversation and raw terminal, the composer with the terminal keys, the account screen, and the recovery that keeps a draft |
| The native code | `apps/companion/native/ios`, `apps/companion/native/android` | Push reception, the limited preview key, the audio session, the share sheet and the signing rule — all of which run when no interface is running at all |

The generated Tauri projects are committed at `apps/companion/src-tauri/gen/apple` and
`.../gen/android`, so a clean checkout has the project files without regenerating them. They
reference the hand-written native sources by relative path, which is why those sources live outside
the generated directories: `tauri ios init` and `tauri android init` rewrite what is inside them.

### How the Android native sources reach the application

There are two paths into the Android build and they are not the same.

`apps/companion/native/android` is a Gradle module, `:krnative`. `settings.gradle` includes it by
relative path and the application module depends on it. Nothing in it touches an Android class, so
`./gradlew :krnative:test` runs on a developer's machine with no device.

`apps/companion/native/android/android/src/main/java` is not a module. It holds the classes that do
need the framework — the push receiver, the background worker, the keystore reader, the audio
session and the share sheet — and it reaches the application as a source directory of the
application module's own `main` source set, named in `app/build.gradle.kts`.

Two checks hold that second path:

- `app/build.gradle.kts` resolves the directory at configuration time and fails the build, naming
  the path, when it is not a directory.
- `pnpm -C apps/companion android` reads back each package the build asked for, meaning the variant
  and the formats its own arguments name. It fails when one of them is not there, when the
  packager's record beside it belongs to another variant, or when the dex the application loads
  does not define the two classes the system resolves by name: the messaging service, from the
  manifest, and the background worker, from the request the receiver enqueues. Those two names
  survive a shrinking build, which may rename or remove a class only other code reaches, and
  neither exists unless the module compiled the tree.

The application's merged manifest declares what the compiled code needs: the messaging service
against `com.google.firebase.MESSAGING_EVENT`, unexported, and `POST_NOTIFICATIONS` from the
project's own manifest; Firebase's receiver, component discovery and init provider from
`firebase-messaging`; and WorkManager's own services, its boot receiver and its
`androidx.startup.InitializationProvider` entry from `work-runtime`, which is what initialises the
scheduler without an application class. Read it with the command below rather than assuming it.

`tauri android init` regenerates the project in place, and `gen/android` is committed. It leaves
`settings.gradle`, `app/build.gradle.kts` and `app/src/main/AndroidManifest.xml` alone when they
already exist, and it rewrites `buildSrc/src/main/java/.../BuildTask.kt`, which carries the
archive-tool resolution described below. Read `git diff` after an init and restore what it replaced.

`tauri ios build --debug --target aarch64-sim` produces `KalaReach.app` for the iOS Simulator, and
`tauri android build --debug` produces an APK and an AAB.

Two things a build needs to know:

- **The Android toolchain is named, not inferred.** Android 15 and later run with 16 KB memory
  pages and refuse a library linked for 4 KB ones, so `app/build.gradle.kts` names NDK 28, whose
  linker aligns to 16 KB by default. Point `NDK_HOME` at the same one: the Rust half of the build
  reads that variable and Gradle reads the setting.
- **An Android build goes through `pnpm -C apps/companion android`, not the command line tool
  directly.** One dependency builds a C library from source and runs whatever `ar`, `ranlib` and
  `nm` it finds. On a developer's machine those are the host's, the host's archiver produces an
  *empty* archive for this target, and the application then installs and fails at start with an
  undefined symbol and nothing in the build output to explain it.

  That command resolves the toolchain's own tools from `NDK_HOME` before anything runs, refuses by
  name when it cannot find a toolchain, and refuses when a previous run has left an empty archive,
  because the build script that made it does not notice that the tools have changed:

  ```sh
  export NDK_HOME="$ANDROID_HOME/ndk/28.2.13676358"
  pnpm -C apps/companion android --debug --target aarch64

  # If it says an earlier run left an empty archive, remove that build and run it again:
  cargo clean -p libsodium-sys-stable --target aarch64-linux-android
  ```

  A build started from Android Studio goes through Gradle, which sets the same four tools itself.
- **An iOS build writes into `src-tauri/gen/apple/build` and will not write over itself.** A second
  run in the same tree stops at "Directory not empty"; remove that directory first.

Installed on a simulator or an emulator, each application opens on the attention inbox and says
there is no host on this device, which is the truth about a phone that has not been paired with
one.

## One bundle, two shells

`src/mobile/entry.tsx` chooses the shell from what the platform says it is. A build that is not on
a phone never renders a line of the mobile shell, and a phone never renders the desktop window's.
The design tokens, the motion tokens, the components and the models are shared, so light, dark,
high contrast, reduced transparency and reduced motion reach the phone without a second
implementation.

An address names where the shell opens: `?tab=attention`, `?tab=account`,
`?session=<session id>`. That is how a notification about one session opens that session.

## The attention inbox

The primary surface, across every host and every session. Four states, told apart three ways at
once — a word, a tone and the sentence underneath — because one way is never enough:

| State | What it means |
| --- | --- |
| Waiting for you | A decision the person can take here |
| Action failed | An action that did not happen, with the host's own error code |
| Ready to review | Finished work waiting to be looked at |
| Out of contact | A host this device cannot reach |

The fourth has a rule in it. Losing contact with a host says nothing about what that host's
processes are doing, so the row says exactly that and nothing more, is never counted among the
failures, and offers nothing to decide. Elapsed time is reported as elapsed time.

## Input

- The Camera, photo library, and files items are provided by the platform, and there are buttons
  that will open them. When these buttons are pressed, they open a file input that has already been
  mapped to the correct picker in the webview, and is hidden from assistive technology. This means
  that a screen reader will see one button for each item, with the appropriate name. `capture` opens
  the camera; an image filter opens the photo library; no filter opens the file browser. A picked
  file is uploaded, not held in the screen: the page hands its bytes to native code, which sends
  them through the transfer service, and the file stays on the draft, uploading, uploaded or failed,
  until the person removes it. The phone takes a picked file of up to 1,020 KB, what its connection
  carries in one chunk; a larger one is refused with that reason. A prompt sent from the phone
  carries its text inline and cannot carry the file, so a draft that holds one is not sent until the
  person removes it.
- **The accessory row** carries the keys a software keyboard buries: escape, tab, control, alt, the
  arrows, home, end and the punctuation a shell needs. A modifier has three states (off, held for
  one key, and held) and says which one it is in rather than leaving it to a colour. A tap on a key
  is its press and its release, and leaves the focus where it was.
- **A hardware keyboard** is named the same way as the row, and native code spells both in the
  encoding the program reads, so the row and the keyboard cannot disagree about what Control-C is.
  A chord with the platform's own modifier is left to the platform.
- **The software keyboard** is measured rather than guessed: the difference between the visual and
  the layout viewport is exactly what is covered, and the composer sits above it. While the raw
  terminal controls its program, what the software keyboard types goes to the program: its text as
  text, and its Enter and Backspace as keys. The field holds one invisible character between edits,
  so a Backspace always has something to delete.

## The raw terminal

Control mode and view mode, as on the desktop. In control mode the program inside the terminal owns
the touch, exactly as it owns the wheel, and the view's own pan does not exist: a pan control that
took a one-finger drag would make a pager or an editor unusable. A pinch zooms in either mode,
because nothing on the wire carries a pinch, so zooming takes nothing from anyone. The text scales
with the fingers while they pinch and follows them back if they reverse; when they lift, the zoom
takes the step nearest where they ended, and a pinch that comes back to where it began changes
nothing.

## Coming back

A phone suspends an application, terminates it in the background, changes its network underneath it
and restarts it cold. The draft survives all four. When contact with the host starts, and each time
the application comes to the front, the shell asks the host where each detached draft's conversation
stands, even if the draft is in a different session than the one currently displayed. Each draft is
then offered its rebind. Two rules keep the rest honest.

**A draft is durable; the association is not.** A draft is this device's own record with its own
identity and revision. The attachment that presents it in an editor belongs to the connection, so
losing the connection removes the binding and leaves the draft exactly as it was. Coming back
offers a rebind. An unchanged target gets one. A draft that holds nothing, or was written before
the device knew which conversation the agent was in, goes with the current conversation instead. A
changed application or binding revision is a conflict the person resolves, and a session that has
gone orphans the draft. Nothing is ever submitted automatically.

Note that contact starting here means that contact has started with a host, and not merely that the
connection has changed. Any time the application comes to the front, even if it never lost
connection, the shell reads each detached draft's session and rebinds the draft if its conversation
has not changed. If a draft is empty, or was created when the device was unaware of any
conversation, it is rebound to whatever the current conversation is. Only drafts which are detached
are offered a rebind. If the host does not know a draft's session, or holds it only as closed, the
draft is orphaned. If a draft's conversation has changed, the draft is marked as conflicted. If the
shell is unable to read for any detached draft, for whatever reason, that draft stays detached until
contact with the host starts again or the application next comes to the front.

**The connection coming back is not an outcome.** A submission in flight when contact was lost is
unresolved until a receipt says otherwise. Queued, sent and applied are three different states and
only a receipt produces the third. The banner after a recovery reports what was kept and what has
no confirmed outcome, and ends by saying that nothing was sent again.

## Targets, type and motion

- 44 points on iOS, 48 density-independent pixels on Android, in both dimensions.
- **Text follows the person's text size**, from the smallest setting to the largest accessibility
  size, and spacing is in `rem` so the layout grows with it. Android's web view multiplies the root
  by the font scale itself, and the system restarts the activity when the scale changes, which
  reloads the page at the new size. The activity does not take the change itself, because its web
  view would then keep the old size. iOS's leaves the root at 16px, so the page reads the size of an
  element set in `-apple-system-body`, a font keyword WebKit ties to Dynamic Type, and
  multiplies the root by its ratio to the size at the default setting, as `--text-scale`. That
  follows a change made while the application runs. Sizes on iOS reach three times the base size, so
  there the two bars stop growing at one and a half times it and the terminal grid at twice it, and
  a screen 320 points wide keeps room for its content.
- **An entry in an agent's history is named in words**, such as "Conversation started" or "Tool
  finished", and never by its identifier. A kind this build does not know is called "Update from the
  agent", and its identifier stays on the entry as data.
- Safe-area insets on every edge that can be under a notch, a home indicator or a rounded corner.
- Transitions of 120 to 200 ms; navigation does not animate at all, and neither does streamed text
  or a repeated key.
- A sheet is dragged one to one with the finger, decides on the velocity at release, and can be
  caught and reversed mid-flight. With reduced motion nothing moves by itself: it cross-fades in
  and out, follows the finger during a drag without stretching past its edge, and goes back at once
  when let go short of a dismissal.

## Push, keys and audio, with no interface running

The iOS Notification Service Extension and the Android messaging service are started by the system,
with no application and no JavaScript context anywhere. Each makes one decision, which has its own
tests; neither is connected to a registration with the gateway. A push message carries only strings,
so the iOS extension reads the sealed preview as the JSON text the gateway puts under `preview`. On
Android, the receiver reads from keys which are not sent by the gateway, so it always shows the
generic alert. Both make the same decision in the same order:

On iOS the extension shows the generic alert the payload carried. On Android the receiver shows it
where the payload alone decides the content; work it hands to the scheduler finishes without
publishing anything, so a deferred message shows nothing at all. The decision itself, in both
places, is:

1. A message with no preview shows the generic alert the host chose.
2. A preview this build cannot read, or one whose lifetime has run out, or one addressed to a key
   this device does not hold, shows the generic alert, and none of them touches the keychain.
3. A device that has not been unlocked since it started shows the generic alert.
4. A preview that does not decrypt shows the generic alert.
5. Only a key that opened a live envelope addressed to this device replaces the alert.

The key is a limited preview key and nothing else. On iOS it is in a Keychain access group the
extension is entitled to; the device authorisation key is in this application's own group, which is
listed first so that a write naming no group cannot land in the shared one. Both groups carry the
team prefix the build resolves, and a build that states none refuses to read or write rather than
searching its own default group. On Android the key is wrapped by the hardware-backed keystore.
Nothing here can decrypt: the sealing construction belongs to the shared client library and neither
the extension nor the worker links it, so every preview falls back to the generic alert, which is
the specified behaviour for a preview that cannot be opened. Neither the extension nor the
background worker can sign anything; signing needs the application's own authentication, and they
have none.

Android hands work on rather than attempting it: anything that needs the host, or that would run
past the message callback's budget, goes to the platform's scheduler, which runs it when the device
allows and retries it if it is interrupted.

## Running it

```sh
# The models, the surfaces and the accessibility rules that can be proved without a device.
pnpm -C apps/companion test:mobile

# The packaged applications.
pnpm -C apps/companion android --debug --target aarch64
pnpm -C apps/companion exec tauri ios build --debug --target aarch64-sim

# Both simulators, with a screenshot for each screen a requirement needs.
scripts/e2e-mobile.sh              # both
scripts/e2e-mobile.sh ios
scripts/e2e-mobile.sh android

# The page's text at each Dynamic Type size on the iOS Simulator, and at each font scale on the
# Android emulator, with the setting changed while the application is open.
pnpm -C apps/companion build:harness
apps/companion/e2e/system-text-size.sh
apps/companion/e2e/system-text-size-android.sh path/to/the/harness/app-universal-debug.apk

# The native decisions, on their own, without the application.
cd apps/companion/src-tauri/gen/apple && xcodebuild test \
  -project companion-tauri.xcodeproj -scheme KalaReachNativeTests \
  -sdk iphonesimulator -destination 'platform=iOS Simulator,name=iPhone 17 Pro'
cd apps/companion/src-tauri/gen/android && ./gradlew :krnative:test

# The hand-written Android tree, compiled by the application module. A syntax error anywhere
# under native/android/android/ fails this.
cd apps/companion/src-tauri/gen/android && ./gradlew :app:compileUniversalDebugKotlin

# What the packaged application actually carries. It reads the class definitions out of the dex
# files the application loads -- an APK's root classes*.dex, an AAB's base/dex/classes*.dex -- and
# names anything missing; `--list` prints the whole hand-written half of whatever it is given.
# `pnpm -C apps/companion android` checks the packages that build asked for. Given no path, this
# reads every APK and AAB under app/build/outputs, whichever build left them.
pnpm -C apps/companion android:classes
pnpm -C apps/companion android:classes --list
pnpm -C apps/companion android:classes path/to/app-universal-debug.apk

# The check's own answers, on archives and output directories built for the purpose: an
# application dex, a dex in an asset or an optional feature, a class named but not defined,
# archive comments shaped like the end-of-directory record, a package missing one class, a dex
# layout it does not read, and which packages each form of the build command is checked against.
pnpm -C apps/companion test:android-classes

# The manifest the packaged application was built from.
cat apps/companion/src-tauri/gen/android/app/build/intermediates/packaged_manifests/\
universalDebug/processUniversalDebugManifestForPackage/AndroidManifest.xml
```

`scripts/e2e-mobile.sh` never starts a simulator or an emulator that is already running, stops only
what it started, and changes a device's settings only on one it started itself. A platform that is
not available exits 3 and says so rather than passing quietly. It opens each screen and
photographs it; it does not assert what is on the screen, drive typing, rotate a device or
exercise suspension. Screenshots go to `/tmp`; everything else goes to
`${KR_TEST_ARTIFACTS_DIR:-/tmp/kr-test-artifacts}`. `KR_IOS_DEVICE` and `KR_ANDROID_AVD` choose the
device.

## The boundary on a phone

The same one the desktop window has, with one addition. `capabilities/mobile.json` grants the file
picker and nothing else, applies to iOS and Android only, and is held to that by
`src-tauri/tests/boundary.rs`. There is no shell, no filesystem path, no general HTTP request, and
the page may listen for an event without being able to emit one. The interface is bundled: no
mobile build loads its own code from the managed service.

The account screen offers signing in and shows usage. Signing in hands the passkey ceremony to the
system browser on `reach.kala.to`: iOS's authentication session (an HTTPS callback from iOS 17.4, a
private-use `to.kala.reach:` callback before it), or Android's Auth Tab, with a Custom Tab and a
verified link where the default browser has no Auth Tab. The page asks the backend to sign in and is
told where the device stands; the address the browser opens, its code and the tokens stay in the
backend, and the tokens are kept in the device's secure store (the protected keychain in the
application's own group on iOS, files sealed under a Keystore key on Android). The screen carries
no payment form, no embedded checkout and no control whose purpose is to send a person somewhere to
buy something, and the mobile tests read the rendered screen and fail on any of them. Local
operation needs no account, and the screen says so; what "everything local works" means on a phone
is settled by the host connection, which is the packaging work above.
