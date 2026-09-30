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
  agent_prompt_submit ──────────▶ Method::AgentPromptSubmit ────▶ the session's own worker
  open_external       ──────────▶ the scheme policy, then the platform opener
```

The agent's methods are each session's own. Native code reaches a session's worker over that
session's own link, the one the terminal view's input already takes, and checks that the process at
the other end is the session's worker before it sends anything; the worker checks this device's
rights itself. A read of the agent names the session and the instance, and a mutation also names
the binding revision the person saw, so an action prepared against a conversation that has since
moved is refused rather than applied to the new one. The attention inbox, review and change sets,
sharing and packages are the daemon's, through the host's local door, and a session's retained
output is read from its worker while it runs and from the daemon's archive once it has ended. An
operation whose parameters or result the protocol does not publish has no command, and the page
refuses it with `UNSUPPORTED_SCHEMA`.

A failure the page shows says the host's own words and, where its code maps to something the person
can do, that action after them: pair the device again, sign in, update, wait, refresh, check
whether it went through, or change a setting. The client library says a host's refusal as its code,
a colon and the host's words, and the page leaves the code out. A failure whose code asks nothing of
the person says the host's words alone. Native code names the action by its key, and the page's
words for each key are the client library's own. A refusal the application makes itself, for a
cause it knows (a size limit, a dropped folder, input the program cannot read), names no action:
its words say what is wrong, and no update, wait or setting would change it.

Native code tells the page about changes through listeners: the connection's state, the host's
events, where the account stands, pairing, owner confirmations and dropped files. The shell
registers a listener asynchronously and drops whatever it publishes before then. Each listener
therefore resolves only once it is registered, and a screen reads the state it follows only after
that, so no change can fall between the two. Nor does a screen show an answer once its listeners
have stopped, or when they could not be registered. A change that arrives before the read's answer
is at least as new as that answer, and the screen keeps it. A screen that reads again, on a change,
a retry, a refresh or an action, shows only its newest read's answer, and the raw terminal view shows
nothing it read for a session it has left. The host announces no new entry in an agent's history,
no change to the attention inbox and no new request an agent is waiting on, so a screen that shows
one reads it again while the page is shown: on a cadence, and at once when the page is shown again
or the host is heard to be back. It has one read on its way at a time, and a read asked for
meanwhile, as after an action, follows it. The inbox and review state are read page by page, and
a list the bound cut short says the host holds more. The conversation reads each agent's history
from the entry after the last one it holds, and counts what the host withheld from this device once
however often it reads; an entry withheld after a read passed its place can go uncounted, so the
count is a lower bound and says "at least". An agent's history goes with it when it ends, so the conversation says when
one it was reading ended before its last entries were read. What a package shows arrives on the
event stream, and a node already held is replaced only by a newer revision of it.

A session has three views: the conversation, the raw terminal and its output. The output view reads
what the session wrote, as the host keeps it, with `history.page`: from the live end, a page at a
time with a cursor and a byte bound, towards older output as the reader scrolls up and newer output
as they scroll down. It holds a bounded run of pages and lets pages go from the far end, and the page
the reader is looking at stays where it is as pages come and go. It shows the text the session
printed, decoded across page boundaries, and leaves out what a terminal would act on: colours,
titles, cursor moves and clipboard writes. Where the host no longer keeps output it says so, and
why. Each view keeps its own place across a change of view: the conversation and the output return
the reader to the node or page they were reading, or to the live end if they were following it.

A session exports two files, each where the platform's save dialog puts it. The semantic archive
holds each entry of every live agent's history as the session's worker gives it, with its time, at
the session's own size, and declares the entries this device's filter withheld, the ones cut short
and the ranges the host no longer kept. The recording holds each screen the raw terminal view drew
while it was open, when it drew it and at the size it drew it, and plays back at the last size. A
screen is written as positions and colours, never as the bytes the session printed. The recording
keeps at most 2,000 screens and 8 MiB of drawing, counted in bytes of UTF-8, and declares the
earlier screens it let go, a screen larger than all of that, and the screens drawn at another size.
Every colour is drawn as the view resolved it through the session's palette; the cursor's shape and
colour, and underline styles other than single and double, are declared rather than drawn, because
a player draws those in its own. Before the terminal view has drawn, there is no recording to
export.

A session is created from the session list, in a directory the person names, with its shell chosen
first. A managed shell is the host's qualified package: Ctrl-D at an empty prompt detaches the view,
and the host reads the shell's editor, so it knows when the prompt is empty. A stock shell is the
system's own, for compatibility: Ctrl-D does what the shell does and can close the session, and the
editor is not read. Where the host describes a session's launch surface, a managed shell's launch
buttons start an agent at the prompt, and a stock shell's show the command to type and start
nothing. Attaching, detaching, closing, file transfer, agents and the terminal work in both. The
creation sheet shows the two side by side before anything exists, and a stock shell is labelled in
the session list, the session's header and settings, and the phone's list. A managed shell the host
cannot qualify is refused with the host's reason; a stock shell is created only when the person
chooses one. The creation sends none of this device's environment: the host decides what the
session starts with.

A draft keeps the conversation it was written for: the agent's instance and the binding revision the
person wrote to. If the agent moves to another conversation while the draft is on screen, the draft
is conflicted and nothing sends it on; the person chooses whether it goes to the new one. A draft
written before the agent was read keeps the first conversation it learns. A file dropped on the
window, or pasted into the composer, is on the draft from that moment, goes through the transfer
service, and stays whether the upload succeeds or fails. A dropped file reaches native code as the
path the platform handed it, so the page never holds its bytes; a pasted file reaches the page
itself, which hands its bytes to native code, up to 64 MiB, for the same upload; a prompt sent from
here carries its text inline and cannot carry the file, so a draft that holds one is not sent until
the person removes it. Nothing that needs a right is offered before the connection has said what it
may do. In a session, when the launch surface was read at an older prompt generation than the view
has heard since, its buttons start disabled.

Nothing claims contact, or its loss, before an answer says which. Until the first answer the
desktop's bar and the phone's say they are checking the connection, with no status dot, and a phone
session opened from a notification shows no banner about the host. A reason for a lost connection
that is empty or only spaces is no reason: the page takes it in as none, so both bars say they are
not in contact, and setup warns that no host is answering and that no reason was given.

Each raw terminal view, on the desktop and on the phone, reads the session's snapshot and says how
the host presents it: the session's output directly, or a viewport with the host's reason in the
host's own words. It reads the summary of its own attachment and no other, and a viewport whose
worker reported no reason says so, and is never shown as direct.

A view attaches only to a worker whose build it can read. A worker outlives an upgrade, and it
states its build and protocol version in its answer to the hello. The view reads that once the
worker has proved who it is, and attaches when the version shares this application's compatibility
level (the same major number and, below 1.0, the same minor number; the patch number never
decides). For a worker of another level, or an earlier one that states none, the view asks the
session for nothing: it ends, names this application's build and the worker's (a worker that
states none is named as an earlier build), gives the protocol versions it knows, and says to close
the session or open it with the application of the worker's build.

A raw view opens in view mode, which takes nothing from anyone: the program gets nothing from the
person, and the view moves its window over the session, up into the history, down the live screen,
and across a session wider than the view. On the desktop the wheel does it (Shift turns a vertical
wheel sideways) and so does a drag; on the phone, a one-finger drag. Four buttons, Up, Down, Left and
Right, move it a page at a time for a keyboard or a screen reader, and each is disabled where the
window can go no further. On a phone with larger text they wrap onto a second line.

Take control is the only way in, and its label says it is a takeover. The view asks the session for
its one input lease, which takes the keys from whoever held them, and a window in the history comes
back to the live screen. While the session answers, the view says it is asking. Once it has control,
the program gets the wheel on both platforms, as wheel events at the session's cell under the
pointer, one turn for each row of scrolling, in the encoding the program chose, and only while the
program reports the mouse. A wheel never becomes arrow keys. On the phone a one-finger drag turns
the wheel the same way, once for each row the finger crosses, at the cell under the finger, and the
terminal keys go to the program; while the view watches, they are disabled. When the program is not
using the wheel, control mode says so and points to Look around, which gives control back at once.
Control also ends when another view takes it, when the program starts reading keys in a form the
view does not send, or when the session refuses the view's input, and the view goes back to view
mode with a sentence on why. Every write under a lease carries its number in the view's input
stream, and after a refused write the view writes under that lease no more: taking control again
starts a new one. A view declares a terminal profile of its own, which the host has not qualified,
so it is always drawn a projection. The host's keyboard table gives that profile the encodings the
view's keys can be spelled in on every platform: the ordinary encoding, `modifyOtherKeys` at level 1
or 2, and the Kitty keyboard protocol's disambiguation and event types. A program that asks for
more, such as the Kitty protocol's report of every key as an escape code, keeps control from the
view, and the view says why.

The page names each key as its platform reported it: the key, the character it makes with nothing
held where the platform says so (Chromium's keyboard layout map, or else the key itself while
neither Shift, Caps Lock, AltGraph nor Option is held), the keypad key it is, the modifiers, the
locks, and whether it went down, repeated or came up. Native code spells the key through the
client's shared encoder in the encoding the program negotiated, and spells a release only for a
press it wrote in an encoding that reports releases. What an input method, dictation or a software
keyboard commits goes as text, once, when it is committed, and never as keys made up for it. A paste
goes as a paste, bracketed when the program asked for that. A chord with Command or the Windows key
stays the platform's, and so do Control-Shift-C and Control-Shift-V off Apple platforms. A key, text
or paste that cannot reach the program as it reads keys now, or before the view holds the session's
screen, does not go: control stays, and the view says why until a key, text or paste does go, in the
mode's sentence on the desktop and above the field on the phone, where it stays in view with a
software keyboard up. The page sends each input once native code has answered the one before, so
inputs reach the program in the order the person made them.

On the desktop the program's keyboard is an invisible field at the cursor's cell, where an input
method opens its candidates, and what the input method composes is drawn there in the session's
colours until it is committed. The field comes next after the mode button in keyboard order, a click
on the terminal that selects nothing puts the focus in it, and the terminal shows a focus ring while
it has the focus. Tab and Shift-Tab go to the program. Control-Tab and Control-Shift-Tab move the
focus to the next control or the one before, and stop at the first and the last. When control or the
view ends and the focus was last in the field or on the mode button, the focus goes to the mode
button, or to Attach again once the view has ended. Focus on Attach again goes to the mode button
once the view is open again, whether the person pressed it or the view opened again by itself,
unless a pointer pressed it: a pointer's press leaves the focus where the pointer put it.

A drag belongs to the view it began in: taking control, the view ending or the session changing
ends it without sending what it had not sent. The page never decides where the window is. Native
code sends one viewport report at a time, settles each move on the screen the host names for it, and
tells the page a move is settled only with a screen that holds it. Until then the page draws its last
screen shifted to where the waiting moves will put the window, so a move shows at once, and a drag
follows the pointer to the pixel. The footer says where the window is.

A session fits a window as narrow as 320 px. Its actions move below its title, in the same order
and at the same size, a long name or directory wraps whole, and the terminal's badges and footer
controls wrap inside the terminal.

While a phone shows the terminal, the composer under it folds into the terminal's bar. The mode, the
zoom and, in view mode, the four moves take one or two rows. The status takes two lines, one for the
warnings and where the window is and one for what the mode does and how the host presents the view,
each cut short until More shows all of it; a screen reader reads all of it either way. Then come the
terminal keys, and the text field as one line with Send beside it. Attachments are added in the
conversation. While the view controls the program, the field is the program's keyboard, in the same
place and at the same size: the draft waits for control to end, Send goes with it, and the field
says Type to the program where a placeholder would. A tap on a terminal key is the key's press and
its release, with the modifiers the row holds for it, and it leaves the focus in the field, so the
software keyboard stays up; a key a hardware keyboard reports as a key takes the row's modifiers
too, and what an input method turns into text, as Android's does with a hardware keyboard's letters,
neither takes them nor lets them go. In the field Control-Tab and Control-Shift-Tab move the focus
on or back in either mode. When control or the view ends and the focus was last in the field, on a
terminal key or on the mode button, the focus goes to the mode button once the bar is back, or to
Attach again once the view has ended, unless the person has put it on another control first;
Attach again does the same once the view is open again, unless a pointer pressed it. While a
software keyboard covers part of the session, the bar gives way to the terminal, its keys and the
field, and the field sits on the keyboard's top edge. The terminal keeps at least four rows at its
default size in any case: when the composer needs more room than is left, it scrolls from the
bottom, so the field stays in view. The host is told the grid the terminal's surface shows.

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
a critically damped spring that starts from the value on the screen. With reduced motion nothing
moves by itself: it cross-fades in and out. A drag is still the person's own motion, so the sheet
follows the pointer and back, stops dead at its edge rather than stretching past it, goes back at
once when let go short of a dismissal, and fades where a dismissal leaves it.

On the phone the settings are not a destination. A session's top bar carries a Settings control
that opens the same sheet over the session, with the appearance choices: the session stays behind
it with its draft, and the choices sit three across while each names itself whole and wrap onto
another row at larger text. The system's back closes the sheet first and leaves the session on the
next. A sheet rests clear of the bottom inset the platform reports.

Where the platform pans the phone's page to keep a focused field in sight, the shell goes with the
visual viewport by as much as it was panned, so nothing of it is above the screen, and what the
keyboard takes of the height is at its foot, the composer above it. This holds where the platform
shrinks the layout viewport to what is visible while it pans, as iOS does the first time a field
takes the focus.

At larger text sizes the phone's inbox breaks a long word, such as a path or a command, where its
row ends instead of running past the screen, and the count on the Attention tab is a circle that
grows with its digits, up and away from the tab's glyph.

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

On macOS the same command opens real windows for two checks with a main thread of their own.
`tests/navigation.rs` holds what the web view does with the navigation handlers. `tests/host_events.rs`
has a scripted session worker push events on a link the application reached as it reaches a real
worker, and a page in a real web view, allowed only what the interface's capability allows, listen
for them through the event API as the interface does: it checks that the page receives each event in
order, with its stream, sequence and type, and its payload as JSON or as null.

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
