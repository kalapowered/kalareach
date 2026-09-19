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
  in agent text is a button that asks the backend; the page never navigates.
- **Images come through validated handles.** An image in a session is read by its attachment handle.
  A remote image is a placeholder with its URL and an import action, and the import is one request,
  over `https`, with a declared size limit.
- **Exports are written where a dialog put them.** The page asks for a destination, the platform's
  own save dialog answers, and the backend remembers that answer for exactly one write. A path the
  page names is refused.

`src-tauri/tests/boundary.rs` reads those files and holds them to those sentences.

One hardening switch is deliberately off. `freezePrototype` freezes `Object.prototype` before the
page runs, and the terminal library assigns `toString` to one of its own namespace objects while it
is being evaluated; against a frozen inherited property that assignment throws and the window comes
up empty. The setting is written into `tauri.conf.json` as `false` rather than left out, so the
choice is visible where the rest of the boundary is.

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
