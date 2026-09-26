# The companion application

The desktop application in `apps/companion`. It shows the attention inbox, the sessions on each
host, the semantic conversation and the raw terminal, and it reaches a host through the same native
client library the command line uses.

## What it is made of

| Part | Where | What it owns |
| --- | --- | --- |
| The interface | `apps/companion/src` | Every screen, in TypeScript and React |
| The native backend | `apps/companion/src-tauri` | The connection, the named commands, the boundary |
| The shared client | `crates/kr-client` | Sessions, cursors, projection, drafts, uploads |

The interface reads protocol values and writes protocol parameters. It holds no connection, no
socket and no path. That is what lets the same screens run on the desktop, where the commands reach
the native backend, and under test, where they reach a host that answers without a machine behind
it.

```text
  the window                      the backend                    the host
  ────────────────────   invoke   ──────────────────   kr-client  ────────
  session_list        ──────────▶ Method::SessionList ──────────▶ session.list
  composer_submit     ──────────▶ …one method each, named in this crate
  open_external       ──────────▶ the scheme policy, then the platform opener
```

Native code tells the page about changes through listeners: the connection's state, the host's
events, where the account stands, pairing, owner confirmations and dropped files. The shell
registers a listener asynchronously and drops whatever it publishes before then. Each listener
therefore resolves only once it is registered, and a screen reads the state it follows only after
that, so no change can fall between the two. Nor does a screen show an answer once its listeners
have stopped, or when they could not be registered. A change that arrives before the read's answer
is at least as new as that answer, and the screen keeps it. A screen that reads again, on a change,
a retry, a refresh or an action, shows only its newest read's answer, and the raw terminal view shows
nothing it read for a session it has left. The conversation reads its document once its stream
listener is registered, and again when the host is heard to be back: the nodes the stream delivers
meanwhile follow the document in the order they arrived, and a node the document already holds is
replaced only by a newer revision of it. In a session, when the launch surface was read at an older
prompt generation than the view has heard since, its buttons start disabled.

Nothing claims contact, or its loss, before an answer says which. Until the first answer the
desktop's bar and the phone's say they are checking the connection, with no status dot, and a phone
session opened from a notification shows no banner about the host. A reason for a lost connection
that is empty or only spaces is no reason: the page takes it in as none, so both bars say they are
not in contact, and setup warns that no host is answering and that no reason was given.

Each raw terminal view, on the desktop and on the phone, reads the session's snapshot and says how
the host presents it: the session's output directly, or a viewport with the host's reason in the
host's own words. It reads the summary of its own attachment and no other, and a viewport whose
worker reported no reason says so, and is never shown as direct.

In view mode a raw view moves its window over the session: up into the history, down the live
screen, and across a session wider than the view. On the desktop the wheel does it (Shift turns a
vertical wheel sideways) and so does a drag; on the phone, a one-finger drag. Four buttons, Up,
Down, Left and Right, move it a page at a time for a keyboard or a screen reader, and each is
disabled where the window can go no further. In control mode the wheel and a drag are the program's
and move nothing, and switching to control mode brings a window in the history back to the live
screen. A drag belongs to the view it began in: taking control, the view ending or the session
changing ends it without sending what it had not sent. The page never decides where the window is.
Native code sends one viewport report at a time, settles each move on the screen the host names for
it, and tells the page a move is settled only with a screen that holds it. Until then the page draws
its last screen shifted to where the waiting moves will put the window, so a move shows at once, and
a drag follows the pointer to the pixel. The footer says where the window is.

A session fits a window as narrow as 320 px. Its actions move below its title, in the same order
and at the same size, a long name or directory wraps whole, and the terminal's badges and footer
controls wrap inside the terminal.

While a phone shows the terminal, the composer under it folds into the terminal's bar. The mode,
the zoom and, in view mode, the four moves take one or two rows. The status takes two lines, one
for the warnings and where the window is and one for what the mode does and how the host presents
the view, each cut short until More shows all of it; a screen reader reads all of it either way.
Then come the terminal keys, and the text field as one line with Send beside it. Attachments are
added in the conversation. While a software keyboard covers part of the session, the bar gives
way to the terminal, its keys and the field, and the field sits on the keyboard's top edge. The
terminal keeps at least four rows at its default size in any case: when the composer needs more
room than is left, it scrolls from the bottom, so the field stays in view. The host is told the
grid the terminal's surface shows.

A selection in either raw view takes the session's own selection colours, except on iOS, which
draws its own highlight over a page's selection. On the desktop a copy gives the selected pieces as
lines laid out by their cells.

## The boundary

The window is a WebView and the WebView is not trusted. Section 13 of the specification fixes what
that means, and each rule is a fact about a file here rather than a convention:

- **The interface is bundled.** `tauri.conf.json` names `../dist`. Nothing loads application code
  from a service.
- **Only named commands.** `src/commands.rs` holds the whole surface as a table. Each command names
  one protocol method in its own body; the page supplies parameters and never a method, a path or a
  command line. An operation with no command cannot be reached from the page.
- **Parameters are parsed, not forwarded.** A command turns the page's JSON into the method's own
  Rust type before anything is sent. The canonical encoding is KR-CBOR-1, where an identifier is a
  byte string and a counter an integer; forwarding the page's JSON would put text on the wire where
  the host expects bytes.
- **A restrictive policy.** No remote scripts, no `unsafe-eval`, nothing framed or embedded, images
  only from the bundle or from bytes this application produced.
- **Markdown is rendered, not injected.** `src/markdown/render.tsx` turns an established parser's
  tokens into elements. It never produces an HTML string, so there is no markup to strip. Raw HTML
  in the source renders as the text it is.
- **Links are checked and opened by the backend.** `https` and `mailto`, and nothing else. A link
  in agent text is a button that asks the backend; the page never navigates, and it is granted no
  opener command of its own.
- **The window stays on the bundle.** The main window is built from its configuration with a
  navigation handler that refuses any top-level navigation away from the bundled interface, and on
  a desktop a handler that refuses new windows.
- **Signing in happens in the system browser.** The account commands take nothing from the page.
  The backend builds the authorisation request, hands it to the default browser (a loopback
  listener on `127.0.0.1:8765` takes the answer) or, on a phone, to the platform's browser-backed
  session, checks the answer and keeps the tokens in the device's secure store. The page is told
  where the device stands and never sees an address, a code or a token.
- **Images come through validated handles.** An image in a session is read by its attachment handle.
  A remote image is a placeholder with its URL and an import action, and the import is one request,
  over `https`, with a declared size limit.
- **Exports are written where a dialog put them.** The page asks for a destination, the platform's
  own save dialog answers, and the backend remembers that answer for exactly one write. A path the
  page names is refused.
- **Pairing's secrets stay native.** The page types a code or asks for the pasteboard to be read,
  and is shown views: an invitation's service and proposed rights in words, an attempt's state, the
  grouped value both devices show, and a confirmation's description. It is never sent an
  invitation's text or secret, a key, a transcript, a challenge or a proof, and it cannot complete
  a confirmation: `owner.confirmation.complete` is a method only native code calls.

`src-tauri/tests/boundary.rs` reads those files and holds them to those sentences.

One hardening switch is deliberately off. `freezePrototype` freezes `Object.prototype` before the
page runs, and the terminal library assigns `toString` to one of its own namespace objects while it
is being evaluated; against a frozen inherited property that assignment throws and the window comes
up empty. The setting is written into `tauri.conf.json` as `false` rather than left out, so the
choice is visible where the rest of the boundary is.

## Pairing with a host

"Pair with a host" is where this computer becomes one of a host's devices, and it runs in native
code, in `src-tauri/src/device`. The page asks for a code or for the pasteboard to be read, and
native code does the rest with `kr-client`'s pairing module:

- This computer's keys are in the platform's secret store, the Keychain, the Credential Manager or
  the Secret Service, under "KalaReach Companion". The name it offers a host is its host name.
- A code's tries are counted in `pairing-budget` in the application's data directory, under a key
  kept in the same store, so a restart, a reboot or a second copy of the application spends from
  the same five.
- The hosts it is paired with, and an attempt still waiting for its owner, are records in
  `pairing`, each written whole and renamed into place. They hold no secret.
- The service it pairs through is `https://reach.kala.to` until the person picks another, and the
  choice is kept in `pairing-origin`.

An invitation on the pasteboard is read by native code, not by the page. A code invitation that
names a service other than this computer's raises the system's own alert, modal to the companion's
window, before anything connects there. The alert names both services, and declining it connects
nowhere. Each change reaches the page as a view on the `kr://pairing` event. The page reads each
view, and the connection's state for the indicator in its top bar, only once its listener is
registered, and keeps a change it heard over a read that answers later.

`src-tauri/tests/pairing.rs` pairs this computer both ways against kr-controller's in-process host,
confirms one request as its owner and declines another. It calls the pairing commands the way the
page does, through the invoke path on Tauri's mock runtime, and keeps every answer and every
payload of the two events the application publishes. None of them carries an invitation's text or
secret, the code's secret characters, a challenge's identifier, nonce or digest, the owner's proof,
the transcript and bundle digests the owner approves, or a key of this computer, the owner or the
host, and a secret planted in one event is found by the same scan. The same suite runs the watcher
against two hosts that share a relay and against a host that answers nothing, and reads a code for
another service through a stub alert that declines and then accepts it.

## An owner's confirmations

On a computer that is one of a host's owner devices, `src-tauri/src/owner.rs` asks each such host
every two seconds what it wants confirmed. Each visit ends within ten seconds, so a host that takes
the connection and answers nothing is out of contact until the next round and holds up no other
host. The requests head Attention, and each row has its title,
its description in one line, the time left, and a button named for this computer's ceremony:
"Confirm with Touch ID", "Confirm with your password" on a Mac without Touch ID, or "Confirm with
Windows Hello". A computer with no ceremony, Linux among them, shows no button and says where to
confirm instead. A request whose description does not match what it would authorise says it could
not be checked, and has no button either.

New requests are announced once, on whichever screen is open, in one message for all that arrive
together, with "Review", which opens Attention and moves focus to the first of them. Requests that
arrive while the message is showing join it in place, so whatever has focus in it keeps focus. "Not
now" sets a request aside until it expires, and it stays aside when the person leaves Attention and
comes back. For a device being added, the row shows the value both devices should show, and a screen
reader hears it spelled out one character at a time.

The button sends native code a reference and nothing else. Native code finds the request it listed
under that reference and asks the operating system, which draws the prompt and prints the
request's description in it:
`LAContext` on macOS, and Windows Hello through `UserConsentVerifier` for this window on Windows.
The prompt is bounded by the challenge's remaining lifetime. Only a confirmation inside it signs,
with this computer's key, and completes the challenge; when the time runs out the prompt is
dismissed and the answer is "not confirmed". Nothing on the page can answer the prompt, so a click
that desktop automation synthesises can start a review and cannot finish one. While a review runs,
the watcher does not connect to another host whose configuration shares the reviewed host's relay,
because that connection would close the endpoint the answer goes over.

## The design system

Newsprint, with light, dark and system modes. `src/styles/tokens.css` holds every colour, the motion
durations and the target sizes; `base.css` the document and the type scale; `components.css` the
components; `views.css` the screens. A component never names a literal colour, so light, dark,
high contrast and reduced transparency are one implementation.

Three rules run through the motion:

- A transition is 120 ms for a press, 160 ms for a state change and 200 ms for a surface arriving.
  Nothing is slower.
- A keyboard-driven change is not animated at all. A key is repeated hundreds of times a day, and
  an animation on one reads as the application hesitating.
- Streamed text and the terminal never animate.

The one gesture is the settings sheet. It tracks the pointer one to one, resists past its own edge,
decides from the velocity at release, and can be caught and reversed mid-flight, because it runs on
a critically damped spring that starts from the value on the screen. With reduced motion it
cross-fades instead, and the same drag still dismisses it.

## Running it

From the repository root:

```sh
pnpm install
pnpm -C apps/companion tauri dev
```

That builds the interface, starts the desktop shell and connects to the controller on this machine.
Without a controller the window still opens and says it is not in contact, which is the state it
has to have anyway.

The interface on its own, in a browser:

```sh
pnpm -C apps/companion dev
```

## Checking it

```sh
pnpm -C apps/companion lint        # ESLint, type-checked
pnpm -C apps/companion typecheck   # both projects
pnpm -C apps/companion test        # unit and component tests, and the semantic-display benchmark
pnpm -C apps/companion e2e         # Playwright, against the built bundle in Chromium and WebKit
pnpm -C apps/companion build       # the production bundle
cargo test -p companion-tauri      # the backend, including the boundary
```

On Windows the same command runs `tests/windows_hello.rs`, which reads what Windows reports about
Windows Hello and checks that the page is sent that ceremony or none. Its tests that raise Windows
Hello's dialog are ignored: they need a signed-in desktop with Windows Hello set up, and the file
says how to run them there. They check that the dialog prints the exact message the review gave
Windows Hello.

The end-to-end run builds a second entry, `harness.html`, which is the same application against a
host that answers without a machine behind it. The production build has one entry and does not carry
it.

Screenshots from the end-to-end run go to `/tmp`, named for what they show.

## Building the application

```sh
pnpm -C apps/companion tauri build
```

macOS is the first target. Windows and Linux compile from the same source; their packaging is not
covered by the checks above.

On Windows, with Microsoft's linker, the build links the application manifest into every binary it
makes, the test binaries included. The native dialogs need version 6 of the common controls, and a
binary without the manifest that selects it cannot start.
