# The companion application on a phone

The iOS and Android builds of `apps/companion` are the same product as the desktop window: one
semantic interface, one design, one set of named commands to the host. What differs is the layout,
the input and what has to survive the operating system taking the process away.

This describes what is there, how it is put together and how to run it.

## The two halves

| Half | Where | What it does |
| --- | --- | --- |
| The interface | `apps/companion/src/mobile` | The attention inbox, the sessions and hosts lists, the session's conversation and raw terminal, the composer with the terminal keys, the account screen, and the recovery that keeps a draft |
| The native code | `apps/companion/native/ios`, `apps/companion/native/android` | Push reception, the limited preview key, the audio session, the share sheet and the signing rule — all of which run when no interface is running at all |

The generated Tauri projects are committed at `apps/companion/src-tauri/gen/apple` and
`.../gen/android`, so a clean checkout has the project files without regenerating them. They
reference the hand-written native sources by relative path, which is why those sources live outside
the generated directories: `tauri ios init` and `tauri android init` rewrite what is inside them.

**The packaged applications do not build yet.** The shared native client reaches both mobile
targets through the crate's `cdylib`, and two crates in that graph have no mobile support: `kr-ipc`
has a platform module for Linux, macOS and Windows and none for Android, and `kr-term` pulls in a
terminal library whose `termios` dependency has no iOS support. Until those are resolved, what is
described below is exercised in the platform's own engine on both simulators and by the native
targets' own tests, and `tauri ios build` and `tauri android build` do not complete.

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

- **Camera, photo library and files** are the platform's own pickers, reached through the file
  input each WebView already maps to them. `capture` opens the camera; an image filter opens the
  photo library; no filter opens the file browser.
- **The accessory row** carries the keys a software keyboard buries: escape, tab, control, alt, the
  arrows, home, end and the punctuation a shell needs. A modifier has three states — off, held for
  one key, held — and says which one it is in rather than leaving it to a colour.
- **A hardware keyboard** goes through the same translation, so the row and the keyboard cannot
  disagree about what Control-C is. A chord with the platform's own modifier is left to the
  platform.
- **The software keyboard** is measured rather than guessed: the difference between the visual and
  the layout viewport is exactly what is covered, and the composer sits above it.

## The raw terminal

Control mode and view mode, as on the desktop. In control mode the program inside the terminal owns
the touch, exactly as it owns the wheel, and the view's own pan does not exist: a pan control that
took a one-finger drag would make a pager or an editor unusable. A pinch zooms in either mode,
because nothing on the wire carries a pinch, so zooming takes nothing from anyone.

## Coming back

A phone suspends an application, terminates it in the background, changes its network underneath it
and restarts it cold. All four recover, and two rules keep that honest.

**The draft is durable and the association is not.** A draft is this device's own record with its
own identity and revision. The attachment that presents it in an editor belongs to the connection,
so losing the connection removes the binding and leaves the draft exactly as it was. Coming back
offers a rebind, and only the same authorised device against an unchanged target gets one: a
changed application or binding revision is a conflict the person resolves, and a session that has
gone orphans the draft. Nothing is ever submitted automatically.

The rebind itself is not yet driven by the connection: `rebindAll` is the decision, and the screen
that calls it with what the host reports about each draft's target is not built. A draft that came
back is therefore kept and shown, and is not yet re-bound to an editor.

**The connection coming back is not an outcome.** A submission in flight when contact was lost is
unresolved until a receipt says otherwise. Queued, sent and applied are three different states and
only a receipt produces the third. The banner after a recovery reports what was kept and what has
no confirmed outcome, and ends by saying that nothing was sent again.

## Targets, type and motion

- 44 points on iOS, 48 density-independent pixels on Android, in both dimensions.
- Spacing in `rem`, so the system text size scales the layout with the text.
- Safe-area insets on every edge that can be under a notch, a home indicator or a rounded corner.
- Transitions of 120 to 200 ms; navigation does not animate at all, and neither does streamed text
  or a repeated key.
- A sheet is dragged one to one with the finger, decides on the velocity at release, and can be
  caught and reversed mid-flight. With reduced motion it does not travel: it cross-fades, and the
  gesture still dismisses it.

## Push, keys and audio, with no interface running

The iOS Notification Service Extension and the Android messaging service are started by the system,
with no application and no JavaScript context anywhere. What is built is the decision each of them
makes, with its own tests; registering this device with the gateway, and the payload shape the
gateway actually sends, are not wired up yet. Both make the same decision in the same order:

1. A message with no preview shows the generic alert the host chose.
2. A preview this build cannot read, or one whose lifetime has run out, or one addressed to a key
   this device does not hold, shows the generic alert, and none of them touches the keychain.
3. A device that has not been unlocked since it started shows the generic alert.
4. A preview that does not decrypt shows the generic alert.
5. Only a key that opened a live envelope addressed to this device replaces the alert.

The key is a limited preview key and nothing else: on iOS it belongs in a Keychain access group the
extension is entitled to and the device authorisation key is not, and on Android it is wrapped by
the hardware-backed keystore. The iOS group is named but not yet resolved from the build, so on a
device the extension finds no key and shows the generic alert. Nothing here can decrypt yet either:
the sealing construction belongs to the shared client library and neither the extension nor the
worker links it, so every preview falls back to the generic alert, which is the specified
behaviour for a preview that cannot be opened. Neither the extension nor the background worker can sign anything —
signing needs the application's own authentication, and they have none.

Android hands work on rather than attempting it: anything that needs the host, or that would run
past the message callback's budget, goes to the platform's scheduler, which runs it when the device
allows and retries it if it is interrupted.

## Running it

```sh
# The models, the surfaces and the accessibility rules that can be proved without a device.
pnpm -C apps/companion test:mobile

# Both simulators, with a screenshot for each screen a requirement needs.
scripts/e2e-mobile.sh              # both
scripts/e2e-mobile.sh ios
scripts/e2e-mobile.sh android

# The native decisions, on their own, without the application.
cd apps/companion/src-tauri/gen/apple && xcodebuild test \
  -project companion-tauri.xcodeproj -scheme KalaReachNativeTests \
  -sdk iphonesimulator -destination 'platform=iOS Simulator,name=iPhone 17 Pro'
cd apps/companion/src-tauri/gen/android && ./gradlew :krnative:test
```

`scripts/e2e-mobile.sh` never starts a simulator or an emulator that is already running, stops only
what it started, and changes a device's settings only on one it started itself. A platform that is
not available exits 3 and says so rather than passing quietly. It opens each screen and
photographs it; it does not yet assert what is on the screen, drive typing, rotate a device or
exercise suspension. Screenshots go to `/tmp`; everything else goes to
`${KR_TEST_ARTIFACTS_DIR:-/tmp/kr-test-artifacts}`. `KR_IOS_DEVICE` and `KR_ANDROID_AVD` choose the
device.

## The boundary on a phone

The same one the desktop window has, with one addition. `capabilities/mobile.json` grants the file
picker and nothing else, applies to iOS and Android only, and is held to that by
`src-tauri/tests/boundary.rs`. There is no shell, no filesystem path, no general HTTP request, and
the page may listen for an event without being able to emit one. The interface is bundled: no
mobile build loads its own code from the managed service.

The account screen offers signing in and shows usage. It carries no payment form, no embedded
checkout and no control whose purpose is to send a person somewhere to buy something, and the
mobile tests read the rendered screen and fail on any of them. What is not there yet is the
authentication itself and the call that reads usage: the screen draws what it is given. Everything
local works without an account at all, and the screen says so.
