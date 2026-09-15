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

`X` is the default, and it is the default twice over. An unrecognised CSI final or an unknown OSC
selector is `X`. So is a *recognised* sequence in a form the profile has not qualified: an
unsupported parameter, subcommand, resource or flag falls through to `X` rather than travelling on
inside a sequence that looks familiar. Recognising the final byte is not the same as supporting
what the sequence says.

`classify.rs` implements the table in the order the rows appear in the specification, and
`fixtures/terminal/classes.json` holds one case per row with the classes, the spans and the exact
bytes.

Some rows are worth spelling out.

**Named C0 exceptions.** NUL and DEL are `D`. Both are stream padding that every terminal discards,
they appear constantly, and classifying them as `X` would produce a diagnostic per occurrence
without telling anyone anything. Every other C0 control the table does not name is `X`.

**ENQ is a query with no answer.** kr-vt/1 has no answerback string, so the broker consumes the
request and replies with nothing. That is the sequence's own defined behaviour for a terminal
without one, and it is better than letting the request travel on to a terminal that does.

**A colon sublist belongs to SGR.** `CSI ? 3 : 7 h` is not a request to set mode 7. The leading
value of a slot is the one the table names, and a sublist anywhere but SGR makes the whole sequence
an extension. So does a sequence the parser could not keep whole: the part it dropped could have
carried a mode the profile refuses.

**SD shares a final byte.** `CSI Ps T` is scroll-down. `CSI Ps ; Ps ; Ps ; Ps ; Ps T` is xterm's
highlight mouse tracking, which the profile does not advertise. One parameter is the scroll; more
than one is the tracking request, which is `X`.

**The window-manipulation row splits three ways.** Geometry and window-state reports (`11`, `13`,
`14`, `15`, `16`, `18`, `19`) are `Q`. The title stack (`22`, `23`) is `M`, and its second parameter
names which title: `0` for both, `1` for the icon name, `2` for the window title, and nothing else.
Everything else asks for a physical window change and is `X`, because rows and columns belong to the
size owner.

A selective push saves only the title it names, so a saved title and an absent one are different
things: popping a title nothing saved leaves the current one alone rather than clearing it.

**A parameter that selects an operation is never reduced.** Counts and coordinates are bounded by
what the grid can act on, because a cursor movement cannot do more than fill the screen. An erase or
tab-clear parameter is not a count: at every value it is a different operation, so reducing it would
quietly do something else. Those values are checked against their own set instead, and a value
outside it is `X`.

**Keyboard negotiation is checked before it travels.** Only `modifyOtherKeys` resource 4 at level 0,
1 or 2 is qualified, and only the Kitty keyboard flags in the profile's subset. `CSI > 16 u` asks
for text association, which the input encoders cannot produce, so it is `X` rather than a flag the
application believes it got. A colon sublist belongs to ordinary SGR and nowhere else, so
`CSI > 4 : 99 m` is not a level.

What is qualified is a mode, and a mode is forwarded live. A direct terminal that did not see the
negotiation would keep sending the old encoding, which is exactly the mismatch the negotiation
exists to prevent. The profile still tracks it, and still keeps it away from the canonical grid,
which has nothing to do with key encodings. Each screen buffer keeps its own Kitty stack, so a
full-screen application's negotiation cannot leak into the shell's when it exits.

**DECSCA is not classified as display.** Nothing in the profile implements selective erase, so the
attribute is `X` and DA1 does not claim `6`. Advertising a capability and then dropping it is worse
than not advertising it.

**Only qualified colour selectors are colours.** The Tektronix colours (OSC 15, 16, 18 and their
resets) have no canonical state here, so asking about one or setting one is `X`.

## Controls inside a sequence

A terminal performs a C0 control where it appears, even in the middle of a control sequence, and
carries on collecting the sequence around it. So does this engine: the controls are kept with the
sequence they were found in, performed in order before it, and each one is decided on its own, so a
bell inside a cursor movement still reaches the lease holder and a line feed still moves the screen.
The sequence itself then happens as though the controls had not been there.

The bytes stop there. Forwarding them would perform each control a second time, once by this engine
and once by the terminal reading the same bytes, and a repainted screen is a smaller price than two
bells. NUL and DEL are the exception both ways: every terminal discards them, so they are discarded
here and the sequence still travels. A sequence carrying more than eight controls is an extension,
because at that point it is not a sequence with controls in it.

## The byte policy

kr-vt/1 is a UTF-8 profile, and the lexer validates that properly: shortest form, no surrogates,
nothing above U+10FFFF. Malformed input becomes U+FFFD with a named cause, and the causes are
pinned in `fixtures/terminal/byte-policy.json` rather than left to whatever the decoder happened to
do.

Five rules are easy to get wrong, and each one has a fixture.

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

**Escape doubling belongs to tmux.** `ESC ESC` is one escape of payload only inside a recognised
tmux passthrough envelope, which doubles escapes for exactly that reason. Anywhere else an `ESC`
that is not followed by `\` abandons the string and starts a new sequence, which is what a physical
terminal does. A general doubling rule would let a title hide a clipboard write: the engine would
frame the whole thing as one title and forward its bytes, and the terminal on the other side would
end the title at the escape and run the clipboard write.

**Nothing that is not plain text reaches a physical terminal.** That covers a raw eight-bit
introducer, and it covers a control-string payload carrying invalid UTF-8 or a control scalar. Such
a sequence is still classified normally and still reaches the canonical grid, with its payload
sanitised into U+FFFD and printable text on the way; its original bytes are never forwarded, because
a terminal would frame them somewhere other than where this engine framed them.
`DirectDisposition` carries the decision on every event:

- `Forward`: the original bytes go to the attachment unchanged.
- `RequireProjection`: the bytes cannot go to a physical terminal, so the attachment projects.
- `Withhold`: the bytes stop here, because the engine answered, routed or consumed them.

The engine withholds in two more cases the class table cannot see: a sequence the canonical grid
does not implement, and a hyperlink that would pass the session's bound. Both are consumed with a
diagnostic, so `FeedOutcome::forward` is what a direct attachment actually sends.

### Bounds

A control string is bounded at 64 KiB, except OSC 52 which has its own 1 MiB bound. Past the bound
the lexer stops collecting and starts discarding in constant memory, and while discarding, `ESC` no
longer ends the string and starts a fresh sequence. The string ends at a real terminator, at CAN or
SUB, or at the end of the stream. It never ends on an elapsed byte count, because a byte count does
not establish a sequence boundary: inventing one is exactly how the suffix of an oversized payload
gets executed.

A sequence prelude is bounded too. Past 256 retained bytes the parser keeps its framing state and
the span length and stops retaining bytes, so `CSI` followed by two megabytes of digits costs
nothing, and the sequence becomes an extension.

A control byte inside a prelude is consumed and ignored rather than abandoning the sequence, so
`CSI 5 NUL ; 3 H` still moves the cursor to row 5, column 3. kr-vt/1 does not execute the embedded
control where a VT terminal would; the parameters are what matter, and losing them to a stray NUL
would be worse.

### tmux passthrough

`DCS t` with a payload beginning `mux;` is a passthrough envelope. The lexer undoubles the escapes
and re-lexes the payload with the same parser and the same policy, one level deeper, to a maximum
of four. Beyond four the envelope is discarded with a diagnostic.

Nothing changes inside an envelope. A query at depth three is still answered by the broker and still
never forwarded. What does change is the disposition: an envelope is consumed, so its decoded
display and mode events require projection rather than forwarding.

### Cells, reads and combining marks

kr-vt/1 uses a pinned legacy codepoint-width model: every scalar that has a width of its own takes
that many cells, ambiguous characters are one cell, and a zero-width scalar takes none and belongs
to the cell before it. A multi-scalar emoji sequence therefore takes one cell per scalar that has a
width: U+1F469 U+200D U+1F4BB is four cells, not two, and a thumbs-up with a skin-tone modifier is
four, not two. The profile does not advertise mode 2027 and does not pretend to implement it.

The grid library's own cluster reducer is more modern than that: it folds emoji sequences, Hangul
jamo and more into single cells. The qualified change is in what the library is given rather than in
the library: a run that is not plain ASCII is cut at every cell, so the reducer never sees two of
them in one call and the cell count follows the pinned model. Listing the joins to cut at would be
faster and wrong, because the list is longer than emoji and grows with the library; cutting at every
cell costs nothing on ordinary output, because plain ASCII is not cut at all.

The library also keeps a row in one of two representations and reads a compact row by clustering its
text again, which would undo the cut. Two things answer that. A cell of the row is read back before
every write, which converts a live row to the representation that remembers where its cells are. And
a bounded copy is kept of any row that was written with a cell the clustering could join, so that a
row compacted anyway is put back as it was. That copy is the exception to there being one store of
state, and it is a narrow one: it holds at most 64 rows, only rows that were actually at risk, and it
is used only to undo a change nothing asked for.

Three rules keep the answer the same however the reads fall.

1. A text run holds back its final cell until the next read, so `e` and a combining acute that
   arrive in different reads still land in one cell.
2. `Engine::quiesce` releases that cell, and the session loop calls it when a read returns nothing.
   A snapshot calls it itself and hands back the output the settling produced, so a settled screen
   is what the snapshot describes and a direct attachment still receives those bytes.
3. A combining mark that arrives *after* the cell has been drawn joins it anyway: the grid writes
   the cell again where it already is, with the mark on it. Nothing moves the cursor, nothing is
   printed and insert mode plays no part, so the marks cannot shift the cells beside it or wrap the
   row, and the width cannot change because a zero-width scalar adds none. Without this, quiescing
   between two scalars would lose the mark. The marks of a cell that arrived together go the same
   way, so that both orders produce the same cell.

The cell a mark joins has to still be the cell that was drawn: a resize reflows the rows and
eviction moves them, so the write checks what is there first and drops the mark rather than
overwriting whatever moved in. The write takes a sequence number of its own, so the row counts as
changed and the mark reaches a client reading deltas.

The result is checked by feeding every case one byte at a time, settling the screen after each byte,
and requiring the same screen as the single-read answer.

A cell is bounded at 64 bytes, which is the per-cell content bound: past it the cell ends and the
next scalar starts a new one, so a run of combining marks cannot become one unbounded cell. The
bound also stops the redraw above from growing a cell without limit across quiet periods.

## The canonical grid

The grid is built on a pinned revision of `wezterm-term`. The library is used for the cell model,
wrapping, scroll regions and the alternate buffer, and it is used through a narrow door.

### Why there is no second parse

The specification forbids trusting two independent parses to agree. This crate removes the second
parse rather than reconciling it. The engine frames and classifies a sequence once, and
`adapter.rs` hands the library an already-decoded action through `Terminal::perform_actions`. The
library never sees a byte of the output stream, so it cannot frame anything differently, and it
never sees a sequence the policy layer withheld.

What remains is the mapping, and it is qualified by measurement rather than by argument. The library
marks a sequence it does not understand as unspecified, at any nesting, and the adapter looks for
that inside mode and colour containers as well as at the top level. When the class table approves
something and the library shrugs, the engine consumes it: the grid does not apply it and the bytes
are not forwarded. Half-understanding a sequence is worse than refusing it, because the canonical
screen and the physical terminal would then disagree about what happened. Every fixture asserts the
count of such sequences is zero for the supported corpus.

Three kinds of sequence never reach the library, because the profile owns them outright:

- the virtualised title stack (`CSI 22 t` and `CSI 23 t`),
- OSC 633, which the library does not model, and
- DEC modes 66, 67, 1007 and 1034, which change what a keyboard or mouse encoder produces and
  nothing about the screen.

### The library qualification record

Repository: `https://github.com/wezterm/wezterm`
Revision: `699fd77b44641c43476c945054cfae6518dbd632`

The revision serves kr-vt/1 for these reasons.

1. It accepts already-parsed actions, which is what makes the second parse unnecessary rather than
   merely discouraged.
2. The width model is configuration, not a fork. `UnicodeVersion { version: 9, ambiguous_are_wide:
   false }` is exactly the pinned kr-vt/1 model: the last table generation before the Unicode 14
   emoji presentation selectors changed the width of existing sequences, with ambiguous characters
   one cell and combining characters none.
3. In-band resize and DECCOLM never reach it, because the policy layer classifies them before the
   reducer sees anything. Whatever the library supports there is not part of the profile.
   Clustering is different: ordinary text does reach its cluster reducer, so the text is cut before
   the joins that would disagree with the pinned width model. See "Cells, reads and combining
   marks".
4. It is constructed with a writer that accepts bytes and delivers none, and counts them. Every
   reply comes from the broker, and every fixture fails if that count is not zero.
5. It clusters the text of one call to its action interface, which is why the engine holds a text
   run's final cell until it knows what follows, and why a mark arriving later is applied by
   drawing that cell again.

The Unicode data behind the width model is pinned by the same revision: `emoji-data.txt` dated
2020-01-28 and `emoji-variation-sequences-14.0.0.txt` dated 2021-06-08.

#### What the revision needs before the profile is complete

Three pieces of state section 8 lists among what a snapshot restores are not reachable from the
pinned revision. All three need the same narrow published patch: a public accessor.

| State | Why the profile needs it | What happens until then |
| --- | --- | --- |
| `TerminalState::pending_wrap()` | Section 8 lists pending wrap among the restored state | The snapshot carries `None`; a reconnecting client re-derives it from the next character it places. At the bottom-right corner that character can change what scrolls, so this is a real gap and not a cosmetic one |
| `TerminalState::saved_cursor()` as a shared reference for both buffers, with the saved rendition, character sets and origin mode among its public fields | Section 8 lists saved cursors among the restored state, and a saved cursor carrying only a position restores the wrong colours from the wrong origin | The snapshot carries `None` for each buffer; a restored session behaves as though nothing was saved until the application saves again. The snapshot's own type carries the full saved state, so only the reading of it is missing |
| `TerminalState::inactive_screen()` | Section 8 requires a restoration sequence to reproduce **both** buffer states, and the accessor the revision exposes returns whichever buffer is active | The snapshot carries the active buffer's rows and `None` for the other. A client that reconnects while a full-screen application is running gets that application's screen and no primary-buffer content until the application exits and the shell redraws |
| `TerminalState::restore_cursor()` leaving newline mode and the shift-out selection alone, and exposing newline mode for reading back | Restoring a cursor clears both in this revision, which xterm does not do, so a direct terminal following the same bytes ends up in a different mode | The profile applies the same rule so that there is one answer, and asks the attachment to project when that changes anything |

The last one is worth being plain about. The worker does maintain both buffers, because the library
holds both; what is missing is a way to read the one that is not showing. Copying the primary
buffer's rows aside on every switch would be a second copy of state that can drift from the first,
which is the failure the single-reducer rule exists to prevent. So the gap is declared rather than
papered over.

#### What constrains the direct compatibility profile

Two behaviours differ from xterm. Neither is a defect in the canonical state, and both mean a
physical terminal has to be qualified against them before direct mode is offered.

- **Cells follow the pinned width model, not the terminal's own clustering.** U+1F469 U+200D
  U+1F4BB takes four cells here. A physical terminal that applies its own grapheme clustering draws
  two, and every later column on that row disagrees, so it is not qualified for direct mode whatever
  it reports. `fixtures/terminal/width.json` pins both margins of this case, along with emoji
  modifiers, regional-indicator pairs and keycap sequences.
- **A wide cell may overhang the right margin.** Writing a two-cell character in the last column of
  a five-column grid leaves a six-cell row and sets the pending wrap, where xterm blanks the last
  column and wraps the character. The fixture records the canonical result, and a projected renderer
  clips or safely replaces the overhanging cell.

## The query broker

The worker is the only responder. No query is forwarded to an attached terminal, no attached
terminal is asked what it can do on the application's behalf, and no answer describes anything
except the virtual profile and the session's own state. Every reply is built by the broker, in
seven-bit form, out of the profile's own bytes: nothing from a request is ever copied into a reply.

| Query | Answer |
| --- | --- |
| DA1 (`CSI c`, `ESC Z`) | `CSI ? 62 ; 22 c` |
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

A cursor report follows origin mode. With DECOM set the application is working in a coordinate space
that starts at the margins, so a report in absolute screen coordinates would send it to the wrong
place.

The mode reports are where honesty matters most. Mode 2027 and mode 2048 report status `0`, not
recognised, so an application can fall back instead of assuming. DECCOLM reports status `4`,
permanently reset, because the geometry owner decides the column count and nothing the application
sends will change it.

Pixel geometry is reported as zero. Raster graphics are disabled, so nothing needs a pixel size, and
inventing one would be worse than reporting none.

The palette is the session's. Colour requests never reach the grid library, so there is one palette
and one thing that answers questions about it.

A colour request may mix mutations with questions: `OSC 4 ; 1 ; #ff0000 ; 2 ; ?` sets one colour and
asks about another. The operations are executed once, in the order they were written, and each
question is answered from the palette as it stands at that point in the request, so
`OSC 4 ; 1 ; ? ; 1 ; #ff0000 ; 1 ; ?` gives two different answers. A request that both asks and
changes stops here and asks the attachment to project, because the change went into the canonical
palette and a physical terminal never saw it. A dynamic-colour request addresses consecutive
selectors, so `OSC 10 ; fg ; bg` sets both.

Every field of a request has to be a colour this palette understands or a question. A field that is
neither is not a smaller request: the canonical palette would not change while a physical terminal's
might, and the two would disagree about the colour of everything drawn afterwards. So the whole
request is an extension.

XTGETTCAP repeats the name it was asked about, so a name is validated before it is repeated: hex
only, bounded length, and printable. Anything else gets the bare failure reply. An application must
not be able to choose the bytes that travel on the trusted lane.

A reply's subject is what decides whether a newer answer may replace a waiting one while the lane is
shedding load, and for a capability or setting report the subject is the name itself rather than a
hash of it. A hash collision there is not a slow lookup: it lets one capability's answer stand in
for another's, and the application reads a reply to a question it never asked.

### The response lane

A reply is not input. It needs no human lease, it never acquires one, and it never looks like a
device, a paste or a root command. Replies are built inside the crate by the broker; anything outside
it can read a reply and write it, and cannot invent one.

Four bounds apply at once, because a query flood is an ordinary thing for a misbehaving program to
do:

- one reply is at most 8 KiB,
- the queue is at most 128 KiB,
- the budget is 256 replies per second, which is also the burst size, and
- a reply that has waited two seconds is dropped rather than written into a conversation that has
  moved on.

When a bound binds, the lane records explicit degraded status and sheds load in a stated order:
refuse over budget first, then collapse an earlier pending reply *about the same subject* when the
queue is full, and drop only when neither is possible. The subject is part of the reply's kind, so a
report about mode 25 can never stand in for a report about mode 7. A cursor report is never
collapsed, because two cursor reports are a sequence rather than two copies of the same fact.

The lane holds replies; the session loop delivers them. `LaneGate` carries what the loop knows about
the write it is about to make, and nothing is taken while a bracketed paste is open on a backend
that cannot interleave, or while a recognised human input frame is part way through being delivered.
The caller also passes its own byte budget, so draining the lane can never crowd out the human input
the same loop is delivering; a reply that does not fit stays where it is, including the first one.

The serial write loop itself belongs to the worker, which owns the pseudo-terminal: ordering a reply
after its query event, closing paste framing on source loss, invalidating an editor fence, and
accounting for every delivered byte are its work. This crate supplies the bounds, the ordering
information (`Response::query_at`) and the gate it needs to do that.

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
| OSC 99 | Notification, when its metadata is inside the qualified subset |
| OSC 777 ; notify | Notification |
| OSC 52 write | Clipboard write to the lease holder, under its own local policy |
| OSC 52 read | Empty response by default, sent without consulting any client |

Subcommands are recognised explicitly, and a value that is present and invalid is never confused
with one that was left out. An OSC 9 with an unrecognised numeric subcommand, an OSC 777 that is not
`notify`, an OSC 99 without a payload, an OSC 9 progress report whose state is outside 0 to 4 or is
not a number at all, a progress percentage above 100: all `X`. OSC 99 metadata is checked key by
key, and the qualified keys are the identifier, the payload part, the done and encoding flags, the
urgency and the display condition; anything else, including a notification action, is `X`. Those
keys are acted on rather than merely allowed: `p` says whether the payload is the title or the body
and `e=1` says it is base64. A notification that says more of it is coming (`d=0`) is `X`, because
this profile delivers a notification when it arrives and nothing would assemble the parts.

OSC 52 has two bounds. The encoded string is bounded at 1 MiB in the lexer, so a larger one is
discarded as an oversized control string and never becomes a clipboard operation at all. Inside that
bound, the policy layer applies its own limit and rejects an oversized write *whole*, because a
truncated secret is still a secret.

## Observations

OSC 7, 133, 633 and 1337 carry what an application says about itself: a working directory, a prompt
boundary, a shell-integration property. `FeedOutcome::observations` carries them, bounded and
labelled with their source.

They are observations and nothing more. A working directory an application printed cannot establish
a filesystem grant, and a prompt marker cannot stand in for an authenticated editor event. They are
carried because a projection and a person find them useful.

## Snapshots and reconnection

A snapshot is presentation state. It is not a serialised process and not a durable parser
checkpoint. It carries the projection generation, the active buffer, the canonical dimensions, the
viewport, the cursor, the margins, the current rendition, the tab stops, the character sets, every
tracked mode, the keypad mode, the keyboard protocol an input encoder has to reproduce, the titles
and the virtual title stack, the hyperlink ranges, the whole palette with its source, and paged rows
with stable identifiers and wrap markers.

Pending wrap, the saved cursor and the inactive buffer's rows are the three fields the pinned
library does not expose; see the narrow patch above. Each is `None` rather than a plausible-looking
default, because a client that is told a saved cursor is at the origin will restore it there.

The cursor a snapshot names is the committed output cursor, not the read offset: it is the point
every delivered event has reached. Taking a snapshot settles the held cell, and `Engine::snapshot`
returns what that settling produced alongside the snapshot, so a direct attachment that is already
forwarding still receives those bytes instead of silently missing them.

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

A delta names the state it continues from: the cursor **and** the projection generation. Both,
because a projection reset can happen without a byte arriving, so the same cursor can name two
different screens and a client that named only the cursor would be handed a delta against a screen
it never saw. A reset drops the bases taken before it rather than refusing them one at a time, and a
geometry change is one, because every row was laid out for the old width and reflows.

The engine keeps a window of the last 64 bases. A base outside the window, or from another
generation, is refused and the client takes a fresh snapshot instead, which is cheaper than
reasoning about what it might have missed. Inside the window, the delta carries the rows that
actually changed since that point, the modes, title, keyboard negotiation, palette and dimensions
that changed with them, and the presentation state a repaint needs: margins, the current rendition,
the tab stops, the character sets and the hyperlink ranges of the rows it carries.

A history page carries at most 1,000 rows and at most 1 MiB, whichever binds first, and states its
oldest retained row and whether anything below it has been evicted. The size counts everything the
page carries, including hyperlink targets and per-run bookkeeping, because a page of short heavily
linked rows would otherwise pass the bound several times over. Rows are built a batch at a time
rather than all at once: the rows that do not fit are rows nobody asked to have built, and rows
carrying long hyperlink targets can cost many times the page bound before the first byte is
counted.

### Bounds

| Bound | Value |
| --- | --- |
| Columns | 1 to 2,048 |
| Rows | 1 to 1,024 |
| Cells | 1 to 262,144 |
| One control sequence's retained bytes | 256 |
| One cell's content | 64 bytes |
| In-memory historical rows | 8 MiB per session |
| Distinct hyperlink targets | 4,096 per session |
| Canonical screens, metadata and per-cell storage | 64 MiB per session |
| History page | 1,000 rows and 1 MiB |

The three geometry constraints apply at the same time. The independent maxima are not valid
together: 2,048 columns is allowed, 1,024 rows is allowed, and 2,048 by 1,024 is 2,097,152 cells and
is refused. Validation uses checked multiplication and happens before any allocation, and a refusal
names the constraint it hit. The same is true of the session budget: a geometry change that would
not fit is refused before the grid is touched, and the current grid is unchanged.

The historical-row bound is enforced rather than reported. The engine measures the retained rows
periodically, and when they pass the bound it lowers the library's scrollback row count so older
rows are evicted as new ones arrive. The new row count is proportional to the overshoot, so the
retained rows converge back under the bound over the following rows rather than oscillating.
Measuring means walking the scrollback, so doing it on every read would cost more than the bound
saves; every 64 reads keeps the overshoot to a fraction of the cache.

What the budget records is what the rows actually cost, not what they are allowed to cost. Recording
the bound instead would make a session that is over its cache look exactly like one that is at it,
and the reading that matters most is the one taken while the cache is too big. While eviction
catches up, `FeedOutcome::resident_pressure` says so on every feed. It is a degradation rather than
a failure, and it is reported there rather than only as a diagnostic, because diagnostics are rate
limited and this is the one a caller must not miss.

A control-sequence parameter is clamped to 65,535 before it reaches the grid. A parameter is a
repeat count, a column or a tab stop, and the grid is at most 2,048 by 1,024, so a larger value
cannot mean more work anyone wants done. A reducer that loops once per unit would happily try:
`CSI 4294967295 I` is five bytes of input and billions of iterations.

## The pinned terminfo database

The managed environment supplies its own `xterm-256color` database rather than trusting whatever the
host has installed. The same table answers XTGETTCAP, so an application that reads a capability and
an application that asks for it over the wire get the same answer.

The database is the ncurses `xterm-256color` entry with these deliberate differences:

| Change | Capability | Why |
| --- | --- | --- |
| Removed | `mc5i`, `mc0`, `mc4`, `mc5` | kr-vt/1 has no printer |
| Removed | `meml`, `memu` | Memory lock has no class in this profile |
| Removed | `Setulc` | The underline colour uses an SGR 58 sublist the canonical grid does not implement |
| Rewritten | `is2`, `rs2` | The reset strings no longer touch DEC private modes 3 or 4; neither is tracked |
| Rewritten | `u8` | States the DA1 reply the broker actually sends |
| Added | `Tc`, `RGB`, `setrgbf`, `setrgbb` | The profile declares truecolour |
| Added | `BE`, `BD`, `PS`, `PE` | The profile supports bracketed paste |

Every advertised output capability is expanded, lexed, and has to land in a class the profile
supports, produce actions the canonical grid recognises, *and* survive the policy layer. Each half
catches a different inconsistency. A capability can lex into a perfectly ordinary control sequence
the grid does not understand; it can also lex and adapt cleanly and still ask for something the
policy layer refuses, which is the same inconsistency as advertising an `X`.

A parameterised capability is a small program, not a template, so the check runs that program. Each
entry carries representative `arguments` and the expansion is computed from the capability's own
value, with a terminfo parameter machine that implements the stack, the arithmetic, the conditionals
and the printf conversions. A sample written out by hand can drift from the value it claims to
illustrate, and a drifting sample proves the wrong thing: an advertised clipboard capability whose
sample used an invalid selection once passed a check its real expansion would have failed. The
expansion each entry produced is in the fixture. That is the `coverage` section of
`fixtures/terminal/terminfo-xterm-256color.json` and the test
`every_advertised_capability_has_a_class`.

Input and report capabilities are not checked there, and the `checked` field says so. A key encoding
and the documented shape of a reply do not appear in the application's output stream, so there is
nothing for the class table to say about them.

Features negotiated outside terminfo, such as synchronised output through DEC mode 2026, still need
their own profile capability. There is no terminfo capability for them, and there is no implicit
support either.

Installing and selecting the compiled database on a host is packaging work, not this crate's: what
lives here is the pinned data and the responder that answers from it.

## Probes

A probe is a short, bounded, synchronous conversation with the terminal a person is sitting in front
of. It happens once, before the application gets any input, and everything about it is designed so
that no answer can arrive later and be mistaken for something the person typed.

Every answer is checked against the form it should have before it is recorded. A device-attributes
reply names at least one attribute, a mode report carries one of the five defined statuses, a
keyboard reply carries flags the profile advertises, and a version reply is not empty. A reply that
does not fit its form is not an answer, so the question stays unanswered and the attach fails: a
capability record built from a reply nobody can read outlives the attach that built it.

`PROBE_SET` lists every question a probe may ask: terminal identity, foreground, background, Kitty
keyboard flags, synchronised output, and then primary device attributes. DA1 is last because every
qualified terminal answers it and answers it last, which makes it the terminator: once it arrives,
every earlier answer has either arrived or is never coming.

A caller passes the questions its qualified profile actually needs, and DA1 is appended whether or
not it asked. **Every question the probe asks must be answered.** Silence is not evidence: a
terminal that ignores a question may be an old build, a multiplexer in the middle, or a terminal
that would have answered a moment later. Treating silence as "this feature is absent" writes a
capability record from an absence of information, and the record then outlives the attach. So the
attach fails with `TERMINAL_PROBE_FAILED`, and that terminal belongs on the `--no-probe` path with a
saved or conservative profile. A profile that does not need a question omits it before anything is
transmitted, which is the honest way to not ask.

The whole exchange has one second. A missing terminator fails the attach with
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

`fixtures/terminal/` holds seven files, generated from the corpus in
`crates/kr-term/src/conformance.rs`.

| File | What it pins | Requirements |
| --- | --- | --- |
| `classes.json` | One case per class-table row, and the unqualified forms of those rows | KR-REQ-08.15 to 08.39 |
| `byte-policy.json` | Raw C1, malformed UTF-8, nested passthrough, oversized strings and preludes, escape doubling | KR-ACC-024, KR-REQ-08.45 to 08.47 |
| `broker.json` | Every query and the exact reply bytes | KR-ACC-001, KR-REQ-08.05 |
| `width.json` | CJK, combining marks, emoji at both margins, emoji modifiers, regional indicators, keycap sequences, delayed wrap, bottom-row scrolling | KR-REQ-08.39 |
| `snapshot.json` | Snapshots mid-output and at alternate-screen transitions | KR-REQ-08.40 |
| `profile.json` | What kr-vt/1 advertises, what it refuses, the identity bytes, and the library record | KR-REQ-08.10, KR-REQ-04.02, KR-REQ-04.24 |
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
