# KalaReach terminal reference

This describes the terminal engine in `crates/kr-term`: the `kr-vt/1` profile, the sequence class
table, the byte policy, the canonical grid, the query broker, snapshots and the physical-terminal
probe contract.

One idea runs through all of it. A KalaReach session is one terminal with several windows onto it,
and some of those windows are somewhere else entirely. The moment that is true, the ordinary
assumption that the terminal in front of you *is* the terminal stops holding, and a lot of terminal
behaviour that has been fine for forty years stops being fine. A query answered by whichever
terminal happens to be attached gives two different answers to two different attachments. A
clipboard write broadcast to every window puts a password on a laptop nobody is sitting at.

So the engine keeps three things singular: one parse of the output stream, one responder for
queries, and one destination for side effects.

## The pieces

| Module | What it does |
| --- | --- |
| `lexer` | The one lexical pass. Frames sequences, validates UTF-8, bounds control strings, decodes tmux passthrough, keeps original bytes and spans |
| `classify` | The section 8 class table, row by row |
| `policy` | One decision per event, and the bounds on side effects |
| `adapter` | Turns an approved event into the actions the grid library applies |
| `grid` | The canonical screen state, on the pinned terminal library |
| `broker` | The only thing that answers a terminal query |
| `lane` | The trusted, bounded path a reply travels back on |
| `snapshot` | Presentation state, deltas, and side-effect-free restoration |
| `probe` | The bounded handshake with a physical terminal |
| `terminfo` | The private pinned `xterm-256color` database and the XTGETTCAP responder |

## The class table

Every sequence gets exactly one class. There is no sixth class for "probably harmless".

| Class | Meaning |
| --- | --- |
| `D` | Display. Applied to the canonical grid, and forwarded unchanged in direct mode |
| `M` | Mode. Tracked and forwarded live |
| `Q` | Query. Consumed here; the broker answers |
| `S` | Side effect. Consumed here and routed to one named destination under policy |
| `X` | Extension. Consumed, with a rate-limited diagnostic |

`X` is the default. An unrecognised CSI final, an unknown OSC selector, a sequence from a protocol
this profile has never heard of: all consumed, none forwarded. Adding one needs a profile revision
and an explicit class, which is the whole reason the profile has a revision number.

`classify.rs` implements the table in the order the rows appear in the specification, and
`fixtures/terminal/classes.json` holds one case per row with the classes, the spans and the exact
bytes.

A few rows are worth spelling out.

**Named C0 exceptions.** NUL and DEL are `D`. Both are stream padding that every terminal discards,
they appear constantly, and classifying them as `X` would produce a diagnostic per occurrence
without telling anyone anything. Every other C0 control the table does not name is `X`.

**ENQ is a query with no answer.** kr-vt/1 has no answerback string, so the broker consumes the
request and replies with nothing. That is the sequence's own defined behaviour for a terminal
without one, and it is better than letting the request travel on to a terminal that does.

**SD shares a final byte.** `CSI Ps T` is scroll-down. `CSI Ps ; Ps ; Ps ; Ps ; Ps T` is xterm's
highlight mouse tracking, which the profile does not advertise. One parameter is the scroll; more
than one is the tracking request, which is `X`.

**The window-manipulation row splits three ways.** Geometry and window-state reports (`11`, `13`,
`14`, `15`, `16`, `18`, `19`) are `Q`. The title stack (`22`, `23`) is `M`. Everything else asks for
a physical window change and is `X`, because rows and columns belong to the size owner.

**DECSCA is not classified as display.** Nothing in the profile implements selective erase, so the
attribute is `X` and DA1 does not claim `6`. Advertising a capability and then dropping it is worse
than not advertising it.

## The byte policy

kr-vt/1 is a UTF-8 profile, and the lexer validates that properly: shortest form, no surrogates,
nothing above U+10FFFF. Malformed input becomes U+FFFD with a named cause, and the causes are
pinned in `fixtures/terminal/byte-policy.json` rather than left to whatever the decoder happened to
do.

Four rules are easy to get wrong, and each one has a fixture.

**A scalar's continuation bytes are never C1.** `Ü` is `0xC3 0x9C`, and `0x9C` is the eight-bit
string terminator. Inside a scalar it is a continuation byte and nothing else. On ground, where no
scalar can begin with it, a byte in `0x80..=0x9F` is recognised as its C1 control and classified
exactly like the seven-bit form: `0x9B` opens a control sequence, `0x9D` an operating system
command, and so on.

**Inside a control string, only the seven-bit terminator ends it.** The same `0x9C` that is a
terminator on ground is ambiguous inside a title, so kr-vt/1 requires `ESC \` (or BEL, for an
operating system command) there. A title containing `Über` survives intact.

**A well-formed scalar in the C1 range is text, and kr-vt/1 replaces it.** `0xC2 0x9B` decodes to
U+009B, the CSI control. It arrived inside a scalar, so it is never executed; it becomes U+FFFD and
what follows is ordinary text.

**Nothing that is not valid UTF-8 reaches a physical terminal.** A raw eight-bit introducer is
classified like its seven-bit form so the canonical grid still gets it right, but its bytes are
never forwarded. The attachment moves to projected mode at the preceding safe cursor and the engine
renders the result instead. `DirectDisposition` carries this decision on every event:

- `Forward`: the original bytes go to the attachment unchanged.
- `RequireProjection`: the bytes cannot go to a physical terminal, so the attachment projects.
- `Withhold`: the bytes stop here, because the engine answered, routed or dropped them.

### Bounds

A control string is bounded at 64 KiB, except OSC 52 which has its own 1 MiB bound. Past the bound
the lexer stops collecting and starts discarding, and while discarding, `ESC` no longer ends the
string and starts a new sequence. That is the point: the suffix of an oversized payload must never
execute. The string ends at a real terminator, at CAN or SUB, or when the 64 KiB resynchronisation
window runs out, and then the parser is back on ground and reading ordinary output. The discarded
payload is never re-injected.

`ESC ESC` inside a control string is one escape of payload, not a terminator and not an abort. A
tmux passthrough envelope doubles every escape for exactly this reason.

### tmux passthrough

`DCS t` with a payload beginning `mux;` is a passthrough envelope. The lexer undoubles the escapes
and re-lexes the payload with the same parser and the same policy, one level deeper, to a maximum
of four. Beyond four the envelope is discarded with a diagnostic.

Nothing changes inside an envelope. A query at depth three is still answered by the broker and still
never forwarded. What does change is the disposition: an envelope is consumed, so its decoded
display and mode events require projection rather than forwarding.

## The canonical grid

The grid is built on a pinned revision of `wezterm-term`. The library is used for the cell model,
wrapping, scroll regions and the alternate buffer, and it is used through a narrow door.

### Why there is no second parse

The specification forbids trusting two independent parses to agree. This crate removes the second
parse rather than reconciling it. The engine frames and classifies a sequence once, and
`adapter.rs` hands the library an already-decoded action through `Terminal::perform_actions`. The
library never sees a byte of the output stream, so it cannot frame anything differently, and it
never sees a sequence the policy layer withheld.

What remains is the mapping, and that is qualified by measurement rather than by argument. The
library marks a sequence it does not understand as unspecified. When the engine classifies
something as display or mode and the library shrugs, the adapter records it, and every fixture
asserts the count is zero. The two halves have to agree about every sequence in the corpus.

Two sequences are exempt, because the profile owns them outright: the virtualised title stack
(`CSI 22 t` and `CSI 23 t`) and OSC 633. Handing either to the library would produce an
unrecognised action and look like a disagreement where there is none.

### The library qualification record

Repository: `https://github.com/wezterm/wezterm`
Revision: `699fd77b44641c43476c945054cfae6518dbd632`
Patch required: none.

The revision serves kr-vt/1 as it stands, for four reasons.

1. It accepts already-parsed actions, which is what makes the second parse unnecessary rather than
   merely discouraged.
2. The width model is configuration, not a fork. `UnicodeVersion { version: 9, ambiguous_are_wide:
   false }` is exactly the pinned kr-vt/1 model: the last table generation before the Unicode 14
   emoji presentation selectors changed the width of existing sequences, with ambiguous characters
   one cell and combining characters none.
3. Grapheme clustering, in-band resize and DECCOLM never reach it, because the policy layer
   classifies them before the reducer sees anything. Whatever the library supports there is not part
   of the profile.
4. It is constructed with a writer that accepts bytes and delivers none, and counts them. Every
   reply comes from the broker, and every fixture fails if that count is not zero.

Two behaviours of the pinned revision are recorded here because they constrain the *direct*
compatibility profile, which is qualified per physical terminal rather than here.

- **Grapheme clusters take one cell.** A ZWJ emoji sequence such as U+1F469 U+200D U+1F4BB occupies
  two cells in the canonical grid, even though the profile does not advertise mode 2027 and a
  terminal without it would draw four. `fixtures/terminal/width.json` pins both margins of this
  case. A physical profile qualified for direct mode has to cluster the same way.
- **A wide cell may overhang the right margin.** Writing a two-cell character in the last column of
  a five-column grid leaves a six-cell row and sets the pending wrap, where xterm blanks the last
  column and wraps the character. The fixture records the canonical result, and a projected renderer
  clips or safely replaces the overhanging cell.

The Unicode data behind the width model is pinned by the same revision: `emoji-data.txt` dated
2020-01-28 and `emoji-variation-sequences-14.0.0.txt` dated 2021-06-08.

## The query broker

The worker is the only responder. No query is forwarded to an attached terminal, no attached
terminal is asked what it can do on the application's behalf, and no answer describes anything
except the virtual profile and the session's own state. Every reply is built in seven-bit form, so a
reply is always valid UTF-8.

| Query | Answer |
| --- | --- |
| DA1 (`CSI c`, `ESC Z`) | `CSI ? 62 ; 1 ; 22 c` |
| DA2 (`CSI > c`) | `CSI > 41 ; 1 ; 0 c` |
| DA3 (`CSI = c`) | `DCS ! \| 4B520001 ST` |
| DSR status (`CSI 5 n`) | `CSI 0 n` |
| CPR (`CSI 6 n`) | `CSI row ; col R` |
| DECXCPR (`CSI ? 6 n`) | `CSI ? row ; col ; 1 R` |
| Printer (`CSI ? 15 n`) | `CSI ? 13 n` |
| User-defined keys (`CSI ? 25 n`) | `CSI ? 20 n` |
| Keyboard (`CSI ? 26 n`) | `CSI ? 27 ; 1 ; 0 ; 0 n` |
| DECRQM | `CSI [?] mode ; status $ y` |
| Text area (`CSI 18 t`) | `CSI 8 ; rows ; cols t` |
| Screen size (`CSI 19 t`) | `CSI 9 ; rows ; cols t` |
| Window state (`CSI 11 t`) | `CSI 1 t` |
| Pixel geometry (`CSI 13/14/15/16 t`) | Zero |
| XTVERSION (`CSI > q`) | `DCS > \| KalaReach(kr-vt/1) ST` |
| DECRQSS | `DCS 1 $ r <setting> ST`, or `DCS 0 $ r ST` |
| XTGETTCAP | `DCS 1 + r name=value ST`, or `DCS 0 + r name ST` |
| Colour queries | `OSC n ; rgb:RRRR/GGGG/BBBB` with the terminator the request used |
| modifyOtherKeys (`CSI ? Pp m`) | `CSI > 4 ; level m` |
| Kitty keyboard (`CSI ? u`) | `CSI ? flags u` |

DA2 reports a device class, not an identity. Applications read it to decide which sequences to send,
so a VT420-class answer is the useful one; the identity lives in XTVERSION, which names KalaReach
outright. `no_reply_carries_a_physical_terminal_identity` in `tests/broker.rs` asserts that no reply
contains a terminal's name.

The mode reports are where honesty matters most. Mode 2027 and mode 2048 report status `0`, not
recognised, so an application can fall back instead of assuming. DECCOLM reports status `4`,
permanently reset, because the geometry owner decides the column count and nothing the application
sends will change it.

Pixel geometry is reported as zero. Raster graphics are disabled, so nothing needs a pixel size, and
inventing one would be worse than reporting none.

### The response lane

A reply is not input. It needs no human lease, it never acquires one, and it never looks like a
device, a paste or a root command. Only the broker can put anything on the lane, and the lane keeps
replies in the order their queries arrived.

Three bounds apply at once, because a query flood is an ordinary thing for a misbehaving program to
do:

- one reply is at most 8 KiB,
- the queue is at most 128 KiB, and
- the budget is 256 replies per second, which is also the burst size.

When a bound binds, the lane records explicit degraded status and sheds load in a stated order:
refuse over budget first, then collapse an earlier pending reply of the same kind when the queue is
full, and drop only when neither is possible. A cursor report is never collapsed, because two cursor
reports are a sequence rather than two copies of the same fact.

The caller passes its own byte budget to `drain`, so draining the lane can never crowd out the human
input the same loop is delivering. While a bracketed paste is open and the backend is not qualified
to interleave, nothing is taken at all.

Nothing on the lane is history. `reset` drops everything pending, and a reconnecting client is never
sent a reply or a probe answer from before it arrived.

## Side effects

A side effect leaves the terminal, so it goes to exactly one place: the attachment that currently
holds the input lease. With no lease there is no destination, and the effect becomes a durable host
event that a person can see later. There is no broadcast.

| Sequence | Effect |
| --- | --- |
| BEL | One bell to the lease holder. Never replayed, never broadcast |
| OSC 9 (message) | Notification |
| OSC 9 ; 4 | Progress report |
| OSC 99 | Notification |
| OSC 777 ; notify | Notification |
| OSC 52 write | Clipboard write to the lease holder, under its own local policy |
| OSC 52 read | Empty response by default, sent without consulting any client |

Subcommands are recognised explicitly. An OSC 9 with an unrecognised numeric subcommand, an OSC 777
that is not `notify`, an OSC 99 without a payload: all `X`.

OSC 52 has two bounds. The encoded string is bounded at 1 MiB in the lexer, so a larger one is
discarded as an oversized control string and never becomes a clipboard operation at all. Inside that
bound, the policy layer applies its own limit and rejects an oversized write *whole*, because a
truncated secret is still a secret.

## Snapshots and reconnection

A snapshot is presentation state. It is not a serialised process and not a durable parser
checkpoint. It carries the projection generation, the active buffer, the canonical dimensions, the
viewport, the cursor and saved cursors, the margins, the rendition, the tab stops, the character
sets, every tracked mode, the keypad mode, the titles and the virtual title stack, the hyperlink
ranges, the palette with its source, and paged rows with stable identifiers and wrap markers.

### Restoration cannot do anything twice

A terminal's history is full of things that were events when they happened: a bell, a clipboard
write, a notification, a query. Replaying the bytes would do all of them again, to whoever happens
to be attached now.

So restoration does not replay bytes. `restoration_operations` returns `RestoreOp`, a closed set
with no member that can ring, copy, notify, download, launch or ask anything. Modes and the buffer
choice come before the rows, so a client never paints into the wrong buffer, and the cursor comes
last, so the screen is never left mid-repaint with a live cursor on it. Historical hyperlinks are
restored as inert metadata; activating one needs the user and the client's own policy.

### Entering live forwarding

Forwarding may only start where the parser stands on ground: no incomplete scalar and no incomplete
control sequence. Output does not stop for the handoff, so the attachment waits, and if 250 ms pass
without a boundary it stays in projected mode and tries again later. Waiting longer would not make
the stream safer; it would only delay showing the person their screen. `LiveForwardingHandoff`
implements the rule, and it works from the parser's current state rather than from a retained
checkpoint.

### Deltas and history

Each delta names the cursor it continues from. A delta that does not match the cursor a client holds
is not applied; the client asks for a fresh snapshot instead, which is cheaper than reasoning about
what it might have missed. A buffer switch advances the projection generation, which resets the
client's projection.

A history page carries at most 1,000 rows and at most 1 MiB, whichever binds first, and states its
oldest retained row and whether anything below it has been evicted.

### Bounds

| Bound | Value |
| --- | --- |
| Columns | 1 to 2,048 |
| Rows | 1 to 1,024 |
| Cells | 1 to 262,144 |
| In-memory historical rows | 8 MiB per session |
| Canonical screens, metadata and per-cell storage | 64 MiB per session |
| History page | 1,000 rows and 1 MiB |

The three geometry constraints apply at the same time. The independent maxima are not valid
together: 2,048 columns is allowed, 1,024 rows is allowed, and 2,048 by 1,024 is 2,097,152 cells and
is refused. Validation uses checked multiplication and happens before any allocation, and a refusal
names the constraint it hit. The same is true of the session budget: a geometry change that would
not fit is refused before the grid is touched, and the current grid is unchanged.

## The pinned terminfo database

The managed environment supplies its own `xterm-256color` database rather than trusting whatever the
host has installed. The same table answers XTGETTCAP, so an application that reads a capability and
an application that asks for it over the wire get the same answer.

The database is the ncurses `xterm-256color` entry with these deliberate differences:

| Change | Capability | Why |
| --- | --- | --- |
| Removed | `mc5i`, `mc0`, `mc4`, `mc5` | kr-vt/1 has no printer |
| Removed | `meml`, `memu` | Memory lock has no class in this profile |
| Rewritten | `is2`, `rs2` | The reset strings no longer touch DEC private modes 3 or 4; neither is tracked |
| Rewritten | `u8` | States the DA1 reply the broker actually sends |
| Added | `Tc`, `RGB`, `setrgbf`, `setrgbb` | The profile declares truecolour |
| Added | `BE`, `BD`, `PS`, `PE` | The profile supports bracketed paste |

Every advertised output capability is lexed and must land in a class the profile supports. That is
the `coverage` section of `fixtures/terminal/terminfo-xterm-256color.json` and the test
`every_advertised_capability_has_a_class`. A capability whose sequence would be consumed with a
diagnostic is not advertised, which is why this is not the stock entry.

Features negotiated outside terminfo, such as synchronised output through DEC mode 2026, still need
their own profile capability. There is no terminfo capability for them, and there is no implicit
support either.

## Probes

A probe is a short, bounded, synchronous conversation with the terminal a person is sitting in front
of. It happens once, before the application gets any input, and everything about it is designed so
that no answer can arrive later and be mistaken for something the person typed.

The set is fixed: terminal identity, foreground, background, Kitty keyboard flags, synchronised
output, and then primary device attributes. DA1 is last because every qualified terminal answers it
and answers it last, which makes it the terminator: once it arrives, every earlier answer has either
arrived or is never coming.

The whole exchange has one second. A missing answer or a missing terminator fails the attach with
`TERMINAL_PROBE_FAILED`, restores the outer terminal's modes and reports the failure. It never gives
up quietly and starts forwarding on the same stream, because a late answer on that stream would
reach the application as keystrokes.

After a failure that stream is not clean any more. Retrying needs a fresh input context, and
choosing `--no-probe` afterwards does not unsend the questions. `NoProbeProfile` is chosen before
any byte goes out, and it is either a qualified profile saved from an earlier successful probe of
this terminal or the conservative projected profile, which asks the terminal nothing at all.

### The palette

The session has one palette, and a palette query always describes it. A client's private colour
preferences are never disclosed to the application by accident, and a second attachment from a
differently themed terminal does not silently change what the application believes the background
is.

Where the palette came from is recorded, because "the user's terminal told us during the probe" and
"the profile default" are different facts and the session has to be able to say which. The sources
are the profile default, a client preference shared during the probe, the light or dark preset
chosen for a no-probe or invisible creation, and an authorised explicit change made later.

## Diagnostics

Diagnostics are status and events. Nothing here writes into the application's output stream or
paints over a running full-screen program.

An `X`-class sequence in a tight loop would otherwise produce one diagnostic per iteration, so each
kind is rate limited to one per second and the suppressed count travels with the next one that gets
through. A suppressed diagnostic is still counted, because "this happened 40,000 times" is the
interesting part.

## Fixtures

`fixtures/terminal/` holds seven files, generated from the corpus in `crates/kr-term/src/conformance.rs`.

| File | What it pins | Requirements |
| --- | --- | --- |
| `classes.json` | One case per class-table row | KR-REQ-08.15 to 08.39 |
| `byte-policy.json` | Raw C1, malformed UTF-8, nested passthrough, oversized strings | KR-ACC-024, KR-REQ-08.45 to 08.47 |
| `broker.json` | Every query and the exact reply bytes | KR-ACC-001, KR-REQ-08.05 |
| `width.json` | CJK, combining marks, emoji at both margins, delayed wrap, bottom-row scrolling | KR-REQ-08.39 |
| `snapshot.json` | Snapshots mid-output and at alternate-screen transitions | KR-REQ-08.40 |
| `profile.json` | What kr-vt/1 advertises, what it refuses, and the identity bytes | KR-REQ-08.10, KR-REQ-04.02 |
| `terminfo-xterm-256color.json` | The pinned database and the class of every advertised capability | KR-REQ-08.11, KR-REQ-08.35 |

Every case records the classes, the dispositions, the spans, the forwarded byte ranges, the replies,
the side effects and the diagnostics. Three assertions hold across the whole corpus: the grid
library never writes a byte, it never fails to recognise a sequence the engine approved, and no
consumed sequence contributes a forwarded byte.

## Building and checking

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test -p kr-term
cargo run -p kr-term --bin kr-term-fixtures -- --check
```

After changing behaviour, regenerate the fixtures and commit them with the change:

```bash
cargo run -p kr-term --bin kr-term-fixtures
```

The KR-PERF-007 figure comes from an optimised build:

```bash
cargo test -p kr-term --release --test perf -- --nocapture
```

It drains a 5 MiB stream of mixed text, colour changes, cursor movement, wide characters,
hyperlinks, alternate-screen churn and queries, and checks that the response lane, the row cache and
the session budget all stayed inside their bounds while it did.
