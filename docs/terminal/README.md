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

The flags in force are a mode, and a mode is forwarded live: `CSI = flags ; mode u` goes to a
direct terminal unchanged, because a terminal that did not see the negotiation would keep sending
the old encoding, which is exactly the mismatch the negotiation exists to prevent. The profile
still tracks it, and still keeps it away from the canonical grid, which has nothing to do with key
encodings.

**The Kitty keyboard stack is virtualised, like the title stack.** `CSI > flags u` and
`CSI < count u` stop at the engine. The stack a direct attachment's terminal holds belongs to
whatever was running when the attachment arrived: an application inside the session that emits
`CSI < 65535 u` would empty it, and a program that had pushed an entry before would then pop into a
state that is not its own. So the session keeps a stack of its own, sixteen entries deep, one for
each screen buffer, and a push or a pop leaves the attachment projecting. The restoration that
projection produces installs the resulting flags as an absolute state, so a direct attachment
receives only flag settings and never a push or a pop, and the flags it needs still arrive. A push
or a pop the profile does not qualify is `X`: it changed nothing, so it needs no projection either.

Each screen buffer keeps its own flags and its own stack, so a full-screen application's
negotiation cannot leak into the shell's when it exits, and both travel in a snapshot. A
restoration puts back no more than a session could have built: every entry is masked to the
qualified flags and the stack is cut to its depth, into an array of exactly the entries kept.

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

That model is a release-profile pin, not something read off a terminal's name. A destination
declares a terminfo entry, and two terminals declaring `xterm-256color` can still measure an
ambiguous-width character differently, so an identity counts as width-qualified only once that
terminal has been measured against the pinned table. Nothing is refused over the difference: a
projection addresses every cluster absolutely, so a character a destination draws wider costs that
character's own cell and nothing after it, and the attachment names the destination as unqualified
in what it reports rather than leaving the person to assume otherwise.

The grid library's own cluster reducer is more modern than that: it folds emoji sequences, Hangul
jamo and more into single cells. The qualified change is in what the library is given rather than in
the library: a run that is not plain ASCII is cut at every cell, so the reducer never sees two of
them in one call and the cell count follows the pinned model. Listing the joins to cut at would be
faster and wrong, because the list is longer than emoji and grows with the library; cutting at every
cell costs nothing on ordinary output, because plain ASCII is not cut at all.

The library also keeps a row in one of two representations, and the compact one stores the row as a
single string. Reading that string back by clustering it again would undo the cut, so the pinned
revision has a compact row record where its cells are whenever clustering would not give them back.
A row therefore keeps the cells it was given, on screen and in the scrollback alike.

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

- the virtualised title stack (`CSI 22 t` and `CSI 23 t`) and the virtualised Kitty keyboard stack
  (`CSI > flags u` and `CSI < count u`),
- OSC 633, which the library does not model, and
- DEC modes 66, 67, 1007 and 1034, which change what a keyboard or mouse encoder produces and
  nothing about the screen.

### The library qualification record

Repository: `https://github.com/kalapowered/wezterm`
Revision: `9a9015119497fd5803c35a10ea4ffc503f2a7dfb`

That revision is `https://github.com/wezterm/wezterm` at
`699fd77b44641c43476c945054cfae6518dbd632` plus the four accessors listed below, each of which is
a published change to the smallest surface that gives it.

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

#### The four accessors the revision adds

Section 8 lists four pieces of state that the upstream revision keeps and does not let a consumer
read. Each is a published accessor over the smallest surface that provides it, and each is what a
snapshot needs rather than a convenience.

| Accessor | Why the profile needs it |
| --- | --- |
| `TerminalState::pending_wrap()` | Section 8 lists pending wrap among the restored state. The same cursor coordinates place the next character in different cells with and without it, and at the bottom-right corner that character decides what scrolls |
| `TerminalState::saved_cursor()`, a shared reference to either buffer's saved cursor, with the saved rendition and character sets among its public fields | Section 8 lists saved cursors among the restored state, and a saved cursor that carries only a position restores the wrong colours from the wrong origin. Each buffer keeps its own, so a restoration reads both |
| `TerminalState::inactive_screen()` | Section 8 requires a restoration sequence to reproduce **both** buffer states, and the accessor upstream exposes returns whichever buffer is active. Copying the primary buffer aside on every switch would be a second copy of state that can drift from the first, which is the failure the single-reducer rule exists to prevent |
| `Line::compress_for_scrollback()` keeping the cells, attributes and wrap markers it was given | The pinned width model gives a cell to every scalar that has a width of its own, and the compact row representation used to work out where the cells were by clustering the row's text again, which joined adjacent scalars and dropped the columns they held |

`kr_term::unicode::LIBRARY` carries the same record in the crate, and its `required_patch` list is
empty: the pinned revision exposes everything section 8 asks a snapshot to carry.

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
information (`Response::query_at`) and the gate it needs to do that. Those obligations must be
proved where the pseudo-terminal is, against the worker's own write path: serial delivery, a write
that only partly completes, paste framing closed when the source is lost, replies that stay behind
their queries, and a fence that an intervening write invalidates. A test here could only exercise a
stand-in for the write, which would prove nothing about the write.

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
tracked mode, the keypad mode, the keyboard protocol an input encoder has to reproduce with each
buffer's virtual Kitty stack, the titles and the virtual title stack, the hyperlink ranges, the
whole palette with its source, and paged rows with stable identifiers and wrap markers.

It also carries the pending wrap, the saved cursor of each buffer with the rendition and character
sets that were saved with it, and the rows of the buffer that is not showing. A saved cursor is
`None` only when that buffer has saved none, so a restoration never invents one: a client told a
saved cursor is at the origin would restore it there.

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

### What a projected client receives

A projected attachment is not sent the application's bytes. It is sent the canonical grid as state,
in four kinds of event and always in this order:

| Event | What it carries |
| --- | --- |
| `session.projection.reset` | Discard what is on the screen; a snapshot follows. It names the generation and why |
| `session.projection.snapshot` | Everything a screen is apart from its rows, at one output cursor |
| `session.projection.rows` | One page of rows, for a named buffer, with *that buffer's own* oldest retained row and eviction marker. The last page clears `more` |
| `session.projection.delta` | The rows that changed since a named base, and the state that changed with them |

The reset reasons are the facts a client would otherwise have to guess: the attachment has just
joined, the screen buffer changed, the geometry changed, the client's base fell outside the replay
window, retained rows were evicted, or what changed is larger than one bounded update.

A projected client is reset *in band*: the reset and the fresh snapshot arrive on the stream it is
already reading, so it needs no round trip to ask for what it has been given. That matters most for
a geometry change, which can happen while nothing is printing: a client told out of band would show
the old size until it got round to asking. A direct attachment has no such event and is told to
resynchronise.

A page carries at most 1,000 rows and at most 1 MiB, which are the bounds section 8 puts on a
history page. Both buffers are paged, the one that is not showing first, so a client that later
leaves a full-screen application finds what the shell left behind. Retention belongs to a buffer
rather than to a session: the primary keeps a scrollback and gives its oldest rows up at the cache
bound, the alternate keeps none and numbers its rows from its own beginning, and each buffer's pages
carry its own cutoff. A client that has not received a
page with `more` cleared does not hold a whole screen and does not draw one: mixing live output with
an incomplete repaint is the thing the paging exists to prevent.

### Looking above the live page

A client reads its scrollback through the report it already makes about its window. `attachment.
viewport` carries a `position` beside the physical dimensions: `{"row": …}`, a stable identifier
from the pages the client holds, or `{"above": …}`, how many rows above the live screen's first row
the window starts. A null position is the live screen, which is where every attachment starts, and
the field is always present.
The retained rows of a terminal come this way, through the window that shows them, rather than
through a request for rows on their own.

An `above` distance is resolved once, against the live screen as it stands at the moment of the
report, and the answer says which row the window landed on. That is what a client keeps: a distance
would slide away from what the person is reading as soon as the application printed another line,
while a row identifier stays over the same text.

The host then installs the pages that cover the window, through the subscription the client already
holds and charged to its own send queue: the same reset, header and bounded pages a live screen
arrives as, and the same refusal for a queue too small to carry the smallest of them. The rows come
from the retained rows the session still holds, a bounded run at a time, so a window above the live
page costs what a window on it costs.

A window that names a row the session has given up is answered with the oldest row there is, and
its pages carry that cutoff and the eviction marker. It is never an error: the rows are gone, and
saying so is the answer. While the window stays above the live page it does not move, because the
rows it holds keep their identifiers however much the application writes; the one thing that moves
it is the session giving up rows below it, and that installs the window again with
`history_evicted` as the reason rather than sending an update naming rows the client has dropped.

Live output goes on arriving the whole time. A client parked in its history is still sent every
bounded update, and what it draws is its own decision. A screen installed for such a window carries
two runs of rows: the window's own, from the rows the session retained, and the live screen's
behind them, so a client that has to be drawn again while it is reading its history is still sent
what the session has written. The window's rows are converted first, so a queue that runs out part
way through arrives with the window whole and the live screen behind it emptied. A screen that is
still too large once its pages are built is shortened row by row, every row to the same share of
what is left, and it says so.

Two origins travel with every window, because two different things are measured from them. The
rows a client draws are named by the window's own first row; the cursor's row is a line of the
*live* screen. A window above the live page has those two apart, so the viewport carries the live
screen's first row as well and a client places the cursor against that. Without it a cursor would
land on a line of somebody's history.

A window above the live page can still reach into it, and a row that changed and then scrolled out
of the live screen is a row no bounded update can carry: an update names the rows the screen holds
now. Such a window is drawn again rather than advanced. A window entirely above the live page shows
only retained rows, whose identifiers and content a scroll does not touch, so it is advanced like
any other.

A window above the live page is not the live byte stream, whatever this terminal's size is. An
equal-size terminal that was being handed the session's own bytes is therefore served the canonical
grid while it is reading its history, and returns to the byte stream when its window comes back to
the live screen, at a parser-ground boundary like every other transition into forwarding.

An attachment that is shown the live screen and no retained content beyond it cannot place its
window in the history at all. That is section 10's live-screen exception: the rows above the screen
are content the exception never reached, so the report is refused rather than quietly answered with
the live screen, which would leave the client drawing as though it had moved.

Moving the window is not input: section 8 puts passive scrollback with focus events and terminal
replies among the things that never seize the input lease, and nothing on this path touches it.

Ordinary output is one delta per batch, and never a repaint. A row larger than a page bound is cut
and marked truncated rather than dropped, so a reader can get past it, and the marker is what makes
the degradation explicit rather than a short row that looks like the application's.

Every message is measured whole before it is sent, rows and state together, against the frame's
1 MiB and the encoding's 65,536 values. A delta carries the state that changed with its rows - a
hyperlink change repeats its target, a title stack can hold twenty of them - so rows that fit a page
say nothing about what the rest of the message adds. One that does not fit is not sent: the client is
given a fresh snapshot instead, which pages.

A whole screen is the one message a client cannot use part of, because a client holding some of the
pages holds no screen. So the installation is measured against that subscriber's own send queue, and
a screen larger than the queue it has to cross is cut to it and marked degraded rather than refused,
resynchronised and refused again.

### The projected renderer

The renderer lives in the client, shared between the command and the companion application, so a
canonical cell goes to the same place wherever it is drawn. Three things together stop a glyph the
destination measures differently from moving anything:

1. **Autowrap is off while anything is drawn.** The renderer clears DEC mode 7 before its first cell
   and puts the session's own value back after its last, so nothing it writes can wrap. Repositioning
   after the damage is not enough: a scroll has already moved every row by then.
2. **Every run is placed absolutely.** A run begins with a cursor address, so a glyph measured
   differently moves nothing after it.
3. **A span the destination cannot reproduce is replaced rather than drawn.** The width of a run's
   text is measured against the profile's pinned model and compared with the cell span the session
   gave it. A disagreement means the text cannot be placed at canonical positions, so the span is
   filled with spaces and counted.
4. **The coordinate system is established, not assumed.** A frame clears origin mode, the left and
   right margins and insert mode, and makes the whole screen the scroll region, before its first
   cell. A destination that was being forwarded the stream a moment ago can be in any of those, and
   each one changes where an absolute address lands or what drawing a cell does to its neighbours.
   The session's own are installed after the last row, so a projection that becomes a direct
   presentation leaves the application the terminal it is writing for; a window showing part of the
   grid cannot carry a margin, which is a row of the grid, and reports that instead.

A cluster the window's edge falls inside is never half drawn: it becomes one space for each of its
cells that is inside, which keeps every later cell on its own column. A cursor outside the window is
hidden rather than misplaced, because a person types where the cursor appears to be. What a frame
could not carry is counted rather than hidden: cells outside the window, clusters the edge fell
inside, runs the destination cannot place, soft-wrap markers a drawn row cannot carry, rows the
session had already shortened, the scroll region a window could not carry, and the pending wrap,
which no cursor placement can reproduce.

One thing a projection deliberately does not make identical: an indexed colour nothing overrode.
The snapshot carries the session's dynamic colours and every override an application made, and the
renderer installs those; the rest of the 256 come from the destination's own configuration, which is
exactly what a terminal being forwarded the stream would draw them in. Two destinations with
different themes therefore agree about every colour the session set and keep their own for the ones
it did not.

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
| One hyperlink | 2,048 bytes |
| Canonical screens, metadata and per-cell storage | 64 MiB per session |
| History page | 1,000 rows and 1 MiB |

The three geometry constraints apply at the same time. The independent maxima are not valid
together: 2,048 columns is allowed, 1,024 rows is allowed, and 2,048 by 1,024 is 2,097,152 cells and
is refused. Validation uses checked multiplication and happens before any allocation, and a refusal
names the constraint it hit and returns `INVALID_ARGUMENT`.

#### The cell maximum is a dimension bound, and the budget decides admission

A geometry inside those three constraints is then admitted against the session budget. The
dimension bound says what a request may ask for; the budget says what this session can be given.
They are different questions, and 262,144 cells is the answer to the first one only.

The worst-case resident footprint of a geometry is what both screen buffers can come to at that
size, and it is reserved before the grid is built. A geometry whose footprint does not fit is
refused with `RESOURCE_UNAVAILABLE`, naming the cells that were asked for, what they would cost and
the budget. The reservation is the whole point of the rule: once a geometry is admitted, text
arriving for its screens is never refused, because the room it needs is already held.

Every figure in the reservation is fixed. None of them is read out of the machine the build ran
on, and the reason is that a footprint decides which geometries a session is given: a model built
on `size_of` would admit a geometry on Linux and refuse the same geometry on macOS, where the
records are larger, and the fixture that records the boundary would only be true of the machine
that generated it. A row record is the case that makes the point. The pinned grid library gives
every row a lock for the application data a front end may attach to it, a `std::sync::Mutex` costs
what each platform decides it costs, and a row comes to 144 bytes on macOS against 136 on Linux
and Windows.

So each figure below is the largest that record is on any supported host, and
`crates/kr-term/src/layout.rs` asserts each one against the type the library really uses. A host
whose records are smaller reserves the figure anyway, which is the safe direction: the session
holds room it never needs and the budget stays one number. A host, a toolchain or a library
revision whose *record* grew past its figure fails to build, rather than quietly reserving less
than it allocates.

What those assertions establish is the size of each record, and no more. They say nothing about
the room a vector kept after it was shortened, about what an allocator adds around an allocation,
or about anything a record reaches through a pointer and this model measures separately: a cell's
attribute allocation can grow while the cell itself stays the size it was. The limits recorded
below and in the allocation notes still apply.

One cell of one buffer, in reserved bytes:

| Part | Bytes | Why |
| --- | --- | --- |
| The slot the cell takes in its row | 128 | A row holds its cells in one of two forms and changes between them while it is written, so both can be alive at once, each at twice the cells it holds, beside the offset and the wide-cell bit the compact form keeps for each cell |
| Its text | 128 | 64 bytes of content, at twice what it holds, because a row appends to its string |
| Its attributes | 96 | The allocation a cell keeps for colours, underline colour, link handle and image list |
| Its text's heap header | 32 | A cell's text leaves the cell once it reaches the length of a machine word |
| | **384** | per cell, per buffer; **768** for both |

The rest of the reservation:

| Part | Bytes | Why |
| --- | --- | --- |
| Row arrays | 288 a row | The array slot of every row of both buffers, the primary buffer's 3,500 scrollback slots included, at twice the rows they hold |
| The retained rows' account | 16 a retained row | One charge a retained row, in an array beside the rows, at twice the rows it holds. It keeps the room it grew to after eviction gives rows back |
| Row storage | 136 a screen row | What a row allocates for itself before anything is on it: eighty bytes of room for its text, and a header each for the cell offsets and the wide-cell bits. A retained row's own storage is the row cache's to carry |
| Hyperlink envelope | 17,137,960 | 4,096 targets of 2,048 bytes, at twice what they hold, with the table slots and the first node. One envelope holds every link object the grid keeps, on a screen or on a retained row, so a row scrolling off moves no charge |
| Titles and the virtual stack | 50,208 | Ten entries of two 1,024-byte titles, at twice what they hold, the current pair, and the copy of each title the grid keeps |
| Alert channel | 1,073,152 | 256 alerts of two 1,024-byte strings, at twice what the list holds |

So an 80 by 24 session reserves 20,820,232 bytes of its 67,108,864, and the default invisible
120 by 40 reserves 23,045,640. A full-width 2,048 by 24 terminal is admitted; so is every grid at
that height, because 2,048 columns is the widest section 8 allows. The largest grid the dimensions
allow, 2,048 by 128, would need 220,760,456 bytes, so it is refused before anything is allocated
for it.

There is no single boundary in cells, because a row costs something of its own: the largest cell
count any shape is admitted at is 1,943 by 32, or 62,176 cells, and 61 by 1,002 is refused at
61,122. The boundary by height is what a client cares about, and
`fixtures/terminal/admission.json` records it: 1,554 columns are admitted at 40 rows and 1,555 are
not; 484 at 128 rows and 485 are not; 248 by 248 is the largest square and 249 by 249 is refused;
59 columns are admitted at the full 1,024 rows.

The historical row cache is not in that figure. Section 8 gives it its own 8 MiB bound beside the
64 MiB session budget, so a session's resident state is bounded by the two together and each is
enforced where it belongs. A title is in the figure twice, because it is held twice: the session
keeps it and so does the grid. Both hold the same string, cut to the same length before the grid
sees it.

A resize goes through the same admission. One that does not fit is refused before the grid is
touched, and the geometry, the reservation and the projection are all unchanged.

A resize that does fit has work to do afterwards. Reflowing into fewer columns builds as many rows
as the text needs, which can be many times the rows the new geometry keeps, and it hands a row of
blanks back whole rather than cutting it to the new width. The alternate buffer keeps no history,
so a shorter geometry leaves it holding rows nothing can reach, and scrolling never drops them:
with no scrollback the library removes exactly as many rows as it adds. None of that is undone on
its own, so the buffer that is showing is brought back to what its geometry holds as part of the
resize. Its row count returns to the screen and its scrollback, the alternate buffer's rows above
the screen are dropped, and a row still holding more columns than the screen has is rebuilt at the
width the screen has. Such a row is blank, so rebuilding it loses nothing that was ever going to be
shown, and rebuilding rather than shortening gives back the room it was holding. The buffer that is
not showing cannot be reached that way, so the same is done for it when the buffers swap.

Until the buffers swap, the rows the buffer that is not showing is still holding are counted where
they are: every row record and every cell slot of both buffers is measured, so a screen holding
more rows than its geometry has, or rows wider than its columns, is reported as holding them rather
than reported as if the geometry had already taken effect.

What a row gave up is given back; what the arrays behind them were holding is not. A vector that is
shortened keeps the room it grew to, and the library offers no way to ask for that room back or to
read how much of it there is, so a session that reflowed into one column keeps an array sized for
the rows that reflow produced until the next reflow builds a new one. That room is bounded by the
geometry the session was admitted at and the rows its cache may hold.

Two things the figures below cannot see, then. That room is one. The other is a cell a wide cell
covers: a row is read through the cells it shows, and a column a wide cell covers is not one of
them, so a cell left under a wide one by a scroll that copied it there keeps whatever it held and
no measurement finds it. Both are properties of how the grid library stores a row rather than of
what the session is doing, and both are bounded by a geometry that was admitted.

A cursor restore is a case of its own. The pinned revision clears newline mode and the shift-out
selection when it restores a cursor, which a terminal does not: DECRC restores the cursor, the
rendition and the character-set designations and leaves the rest of the modes where they were. So
what it clears is noted before the restore and put back afterwards, through the same sequences an
application would have used.

The historical-row bound is enforced rather than reported. What the retained rows cost is carried,
charged where each row leaves the screen, and when the charge passes the bound the engine lowers the
library's scrollback row count so older rows are evicted as new ones arrive. That happens after
every grid mutation, so the bound is enforced where the rows arrive rather than at whichever read
comes next: two rows can carry more than the whole of it. Reading every retained row's cells is a
separate thing, needed for what the hyperlink objects cost, and it happens when the stream goes
quiet, when something asks, and every 64 reads otherwise.

Enforcing it needs the primary buffer to be the one showing, because the library drops the rows it
is told to drop as it appends to them and it appends only to the buffer that is showing. Rows can
only join the retained ones by scrolling off the primary screen, which needs it to be showing, with
one exception: a resize taken while the alternate buffer shows reflows the primary buffer too and
can push rows into its history. The measurement follows the primary buffer wherever it is, so the
figure is right and the pressure is reported at once; the rows come back under the bound when the
primary buffer is next shown, which is done at the swap itself rather than at the read after it.

Eviction is one pass and lands under the bound rather than converging towards it. The row count to
keep is read off the rows themselves: the oldest rows are dropped one at a time until the rows still
ahead cost no more than the bound, and that count becomes the library's scrollback size. Each row is
visited at most once. Working the count out from the average cost of a row would leave it wrong
whenever the rows are not all the same size, which is the usual case, and would need a loop with no
proof that it ends.

What the rows cost includes the hyperlinks they hold. Every cell inside a link holds a reference to
the whole link, and the object behind that reference costs far more than its target's characters, so
what is counted is the object: each distinct one on a row, once. Counting only the characters would
let an application hold tens of megabytes inside a budget that said it was using nothing.

Both buffers are measured, because the buffer that is not showing still holds its own: a session
can fill the primary buffer, switch, and fill the alternate one as well. Each distinct link object
is counted once wherever it is held, so a link spanning several rows, or one the pen and a row are
sharing, is not counted again for each place it appears. The link the pen is inside and the links
the two saved cursors carry are counted as well: those are on no row, and a measurement that only
walked rows would report them as free.

What is refused before it is allocated: a geometry that cannot fit, and hyperlinks. A link's cost is
reserved before it is applied, against the hyperlink envelope, and one that will not fit is refused;
refusing one ends the link that was open, because the text that belonged to the refused link must
not end up inside the previous one. What is reserved for a link is at or above what the object turns
out to hold, and a row that is dropped gives nothing back until the objects on it are measured
again, so the reserved figure drifts above the truth while a session prints. A refusal against the
envelope on that figure would refuse a link the session has room for, so the objects are measured
first, before anything is charged for the link being admitted: a measurement replaces the account
with what the grid is holding, and the object this link is for is not on a row yet. The other three
refusals need no measurement, because none of them is against the envelope: a link longer than one
link may be, a parameter field arriving with no target, and a table already holding as many
distinct targets as a session keeps. A link with parameters and no target is refused the same way:
that is a close, and keeping its parameters would let an application hold a session's worth of
identifiers in links nothing can follow. A cell that reaches its content bound drops the marks past
it. The alert channel holds a bounded number of alerts, each cut to a bounded length.

Nothing else is refused. Text, titles and the rows that scroll off all draw on room the geometry
already reserved, so an admitted session can fill its screens, set a title as often as it likes and
push its stack to the bound without meeting a refusal. Rows that scroll off the screen are charged
to the historical cache where they join it, and the cache is brought back under its bound there
rather than at the next measurement: two rows can carry more than the whole of it. A resize moves
rows between a screen and the history, and the two are charged to different bounds, so both are
measured again at the resize.

**What the retained rows cost is carried, not measured.** A row is charged once, where it leaves
the screen, and gives its charge back once, where it is dropped; the running figure is what
`CanonicalGrid::history_bytes` reads, in one read however long the history is. Which rows joined
and which were given up comes from the two ends of the retained range, so a row that arrives while
the library drops an older one is still counted, and each row that joined is reached by its own
index rather than by walking to it.

Nothing on that path reads a row that has already been charged, and nothing needs to. What a row
costs is its cells, the text they hold and the allocations they keep, and once the library has
compressed a row for the scrollback none of those three changes. The library does still touch a retained row: a
palette change and a buffer switch stamp a sequence number on one, so a client repainting knows
what moved. A sequence number is not in the charge, so the charge is the same afterwards. What does
change a charge is a rewrite, and there is one: a resize reflows the retained rows, joining and
splitting them, and cutting a row to a narrower geometry rewrites it. That says so, and the account
is built again from the rows themselves. An erasure needs no rebuild, because it changes no row: it
drops the oldest rows, and their charges come off the front where the account already gives back
the charges of rows the library drops.

One thing does read every retained row: what the hyperlink objects cost. An object is shared, so it
has to be found wherever it sits and counted once, and a row that is not showing can be the only
place one sits. That measurement is not proportional to the reads. It runs every sixty-fourth read,
when the reserved figure says a link's whole charge would not fit, and when something asked for it;
between two of them every link is reserved for where it arrives, so the figure the envelope is
checked against is at or above the truth. A snapshot of the history reads retained rows too, when one is asked for.

Nothing else on the read path reads a retained row's cells. What the session's screens hold is read
from the rows that are showing; what their records cost is read from how many rows there are, which
the library already knows; and what the retained rows hold is carried. The walk that finds the
showing rows still steps over the retained ones, because the library offers no borrow of one row of
a screen that is correct for both halves of the deque its rows sit in, so a retained row costs an
index comparison there and nothing more. `CanonicalGrid::rows_read` counts the rows a measurement
read the cells of, and `a_read_reads_as_many_rows_as_the_geometry_has` holds that a session at its
cache bound reads no more than twice what a session with an empty history reads over the same run.
What the account removes is the walk a *single row leaving the screen* used to cost, which is the
one that grew with the history and happened thousands of times a read.

`CanonicalGrid::measure_history_bytes` is the same figure worked out by walking the rows, and a
test compares the two after every operation of a randomised sequence of prints, resizes, buffer
switches, erasures and evictions. The account's own array is measured too, at the room it is
holding rather than the charges on it. That room is one charge for every row the scrollback may
keep, which is what the geometry reserved for, and the array is brought to it and left there: a row
arriving never allocates, and a row leaving never gives back room the next row would ask for again.
Sizing the room to the charges on it instead would put a pair of reallocations, each copying the
whole history, on the arrival of a single row whenever the rows arriving cost a little more than
the rows they replace.

That is what makes the byte bound affordable. Working the figure out by walking the history made
every read cost what the whole history cost, so a session printing steadily paid a scan of
everything it had retained on every read: on one machine 0.10 MiB/s of scrolling output against
the 5 MiB/s of KR-PERF-007, and a read behind 1,841 retained rows costing sixty-two times a read
behind ninety. `cargo test -p kr-term --release --test perf` asserts both ends of that: the rate on
a stream that scrolls, and that a read behind a full cache costs what a read behind an empty one
costs.

Eviction reads the same figures. The rows to give up are chosen by what each one costs, oldest
first, until what is left costs no more than the bound, so one pass lands under it rather than
converging towards it, and no cell is read to decide. A row count worked out from the average cost
of a row would land on the wrong side of the bound whenever the rows are not all the same size,
which is the usual case.

Where a reservation and a measurement look at the same thing, the reservation is the larger. Both
work a link's parameter table out through the same rounding, from the separators the parameter field
carries on one side and the room the table ended up with on the other; a string is reserved at twice
what it holds, which is the most a doubling allocator keeps for it; and a cell is reserved for every
column it can cover.

What a measurement counts is what the grid is holding rather than a figure standing in for it: a
link's parameter table as it is allocated rather than as many entries as it has, each key and value
at its capacity, the first node the link table opens, the allocation a cell keeps for the colours,
underline colour, link handle and image list that the packed form on the cell cannot hold, counted
for every column the cell covers, the header a cell's text keeps once it has left the cell, and the
room the title stack grew to rather than the entries left on it. Counting only characters would
report a screen of coloured, linked cells as costing what a screen of plain ones costs.

Every measurement is compared with the reservation made for it. `SessionBudget::excess` is what the
measurements found beyond their reservations, and `SessionBudget::committed` is the reservation
plus that, so what a session reports is never below what its measurements found. At a settled
geometry the excess is zero, including on both buffers filled with the most expensive cell there
is, and the tests assert so where each rule is proved. It goes above zero while the buffer that is
not showing is still holding rows a shorter geometry left it, which lasts until the buffers swap.
What the measurements cannot see at all is the room a shortened vector keeps, described above.

What the budget records for the row cache is what the rows actually cost, not what they are allowed
to cost. Recording the bound instead would make a session that is over its cache look exactly like
one that is at it, and the reading that matters most is the one taken while the cache is too big.
While eviction catches up, `FeedOutcome::resident_pressure` says so on every feed. It is a
degradation rather than a failure, and it is reported there rather than only as a diagnostic,
because diagnostics are rate limited and this is the one a caller must not miss.

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

`PROBE_SET` lists the questions this build's own profile asks: terminal identity, foreground,
background, Kitty keyboard flags, synchronised output, and then primary device attributes. A caller
may ask any subset of `ProbeItem`, which also carries the `modifyOtherKeys` level. DA1 is last
because every qualified terminal answers it and answers it last, which makes it the terminator: once
it arrives, every earlier answer has either arrived or is never coming.

A reply to something the caller did not ask is still recorded. A terminal that volunteers one has
told the truth about itself either way, and this is how the command learns the optional state of a
terminal it cannot require an answer from: `kr attach` requires only the terminator, writes the rest
of the questions ahead of it, and records whatever came back. What a terminal chose not to answer is
absent rather than assumed, and nothing is installed on its behalf.

A caller passes the questions its qualified profile actually requires, and DA1 is appended whether
or not it asked. **Every question the probe asks must be answered.** Silence is not evidence: a
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

The provenance travels with every snapshot and with any delta that moves the palette, so a client
can say where the colours it is drawing came from. It is fixed at creation: the choice is made
before the session has produced anything, and an attachment joining later is shown the session's
palette rather than its own. Attachment succession therefore changes neither the colours nor their
source, and a second attachment from a differently themed terminal is shown what the first one was.

`session.create` is where the choice is made. Its `palette` field names either a preset,
`{"preset": "light"}` or `{"preset": "dark"}`, or the colours a client learned from its own bounded
probe of the terminal the person is sitting at, `{"probe": {"foreground": …, "background": …}}`. A
request whose `palette` is null takes the profile default; the field is always present. The host carries the field to the worker in
the launch specification and applies it between opening the session and starting its shell, which
is the only moment it can be applied honestly: the first byte the shell writes is already a screen
somebody could be looking at, and a palette chosen then would be a change rather than a provenance.

An invisible creation cannot name probed colours. It has no terminal, so a provenance recorded as a
client's measurement would be a measurement nobody took; the host refuses it with
`INVALID_ARGUMENT` before it reserves anything, and such a session selects a preset instead. After
creation this path is closed: the seam refuses a palette once the session has produced anything,
and moving a live session's colours is a different thing altogether: an authorised, explicit
palette change, which carries its own right and broadcasts the new canonical state.

## Diagnostics

Diagnostics are status and events. Nothing here writes into the application's output stream or
paints over a running full-screen program.

An `X`-class sequence in a tight loop would otherwise produce one diagnostic per iteration, so each
kind is rate limited to one per second and the suppressed count travels with the next one that gets
through. A suppressed diagnostic is still counted, because "this happened 40,000 times" is the
interesting part.

## Fixtures

`fixtures/terminal/` holds eight files, generated from the corpus in
`crates/kr-term/src/conformance.rs`.

| File | What it pins | Requirements |
| --- | --- | --- |
| `classes.json` | One case per class-table row, and the unqualified forms of those rows | KR-REQ-08.15 to 08.39 |
| `byte-policy.json` | Raw C1, malformed UTF-8, nested passthrough, oversized strings and preludes, escape doubling | KR-ACC-024, KR-REQ-08.45 to 08.47 |
| `broker.json` | Every query and the exact reply bytes | KR-ACC-001, KR-REQ-08.05 |
| `width.json` | CJK, combining marks, emoji at both margins, emoji modifiers, regional indicators, keycap sequences, delayed wrap, bottom-row scrolling | KR-REQ-08.39 |
| `snapshot.json` | Snapshots mid-output and at alternate-screen transitions | KR-REQ-08.40 |
| `admission.json` | The geometries the budget admits and refuses, and the footprint each one reserves, the same on every supported host | KR-REQ-08.71, KR-REQ-08.79 |
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

Regeneration gives the same bytes on every supported host, because every figure the admission
fixture records is fixed rather than read from the machine. So the check above is a check on the
code, not on where it ran.

The KR-PERF-007 figure comes from an optimised build, one test at a time, because three of the
tests in that file are timings and they measure each other otherwise:

```bash
cargo test -p kr-term --release --test perf -- --nocapture --test-threads=1
```

Each rate is what three passes sustained together, every byte they drained over every second they
took, after a warm-up pass that is discarded. Each run records the operating system, the
architecture, the processors and the processor's own name, and prints every pass beside the total.
A rate is a property of the engine, and the first pass through a fresh process is not: it pays for
the allocator growing its arena and for the first touch of every page the grid and the row cache
come to hold. The fastest pass observed is printed as well and decides nothing; nothing in the run
establishes that anything interfered with the others. What the target is asserted against is the
figure the passes sustained together, because that is what a rate target is about: three passes at
3, 3 and 6 MiB/s sustained 3.6 MiB/s and fail.

Every bound is checked before the rate and on every pass, the warm-up included: the response
lane's queue, the session budget and the historical row cache, each at the largest reading any pass
reached rather than the reading it ended on. A bound that was passed halfway through and given back
is a bound that was passed, and a host too slow for the rate still reports whether anything grew
without one. Those readings are the engine's own accounting sampled between reads, so they say
nothing about what a single read held while it was inside one, and nothing about what an allocator
was holding around it.

Where `KR_TEST_ARTIFACTS_DIR` is set, each run writes its host, its figures and its verdict there
before it asserts anything, so a run that fell short keeps the number it measured and the processor
it measured it on rather than only the failure. A run that cannot write it fails rather than
carrying on with nothing kept. The command above sets nothing, so a local run prints its record and
keeps no file; continuous integration sets it and retains the directory.

### What a read costs

A read is one lexical pass over its bytes, a policy decision for each event that pass produced, the
grid work each event asks for, and a measurement of resident state. The cells a read reads are the
cells of the bytes it carries and the cells of a screen, whatever the history behind that screen and
however long the session has been printing. Two things about a measurement still grow with the rows
a session holds. It steps over every retained row to find the rows that are showing, reading none of
them, because the library offers no borrow of one row of a screen that is right for both halves of
the deque its rows sit in. And what the hyperlink objects cost has to be found wherever the objects
sit, which does read every row of both buffers; that one is taken on its own schedule rather than on
every read:

* the lexical pass appends a run of printable bytes in one step rather than a byte at a time, and
  reuses the buffer it collects a sequence in rather than handing it over, so a sequence no longer
  than the room that buffer has already grown to costs no allocation to collect. A sequence longer
  than that still grows the buffer, once for each time the room it has runs out, and a sequence
  longer than the inline form still allocates the copy the event carries;
* a run of text is drawn from the event's own bytes rather than from a copy of it, because the
  profile's width model cuts the run where the library's cluster reducer would not and the copy an
  adaptation would build is never read;
* the actions any other event adapts to are handed to the grid library rather than copied to it on
  the session's own path, and a parameter list is split into the shape the class table is written in
  without growing as it goes. `CanonicalGrid::apply` still returns the actions it applied, for a
  caller that wants them;
* what the screens hold is read from the rows that are showing, what their records cost from how
  many rows there are, and what the retained rows hold is carried. The walk that finds the rows that
  are showing steps over the retained ones for an index comparison each and reads no cell of one;
* what the hyperlink objects cost is the one figure that has to be found wherever the objects sit,
  because an object is shared and a row that is not showing can be the only place one sits. That is
  read every sixty-fourth read, before a link is charged that the reserved figure says would not
  fit, and when something asked.

### What the target measures on real hosts

The figures below are what this engine measured on the hosts it has run on, in September 2026, each
one the rate three passes sustained after a discarded warm-up. Neither stream is reliably the harder
of the two: the one that scrolls pays for every row joining the historical cache, and the plain one
spends most of what it is asked to do on clearing the screen, which writes the cells of every row
the erasure covers that is not already empty.

| Host | Plain stream | Stream that scrolls | Where it was measured |
| --- | --- | --- | --- |
| Apple M4 Pro, 12 processors | 11.9 to 12.4 MiB/s | 10.6 to 11.5 MiB/s | local runs of this revision |
| AMD EPYC 7763 64-Core, 4 processors | 6.1 to 6.2 MiB/s | 5.9 MiB/s | `core-ci` runs 35165588315, 35167627730 and 35169947110 |
| AMD EPYC 9V74 80-Core, 4 processors | 5.9 to 7.5 MiB/s | 6.1 to 7.7 MiB/s | `core-ci` runs 35168759717 and 35164400630 |
| Intel Xeon Platinum 8573C, 4 processors | 8.0 to 8.1 MiB/s | 7.4 to 7.6 MiB/s | `core-ci` runs 35163469612 and 35172122622 |
| Intel Xeon Platinum 8370C, 4 processors | 7.0 MiB/s | 6.4 MiB/s | `core-ci` run 35174246084 |
| Intel Xeon 6973P-C, 4 processors | 9.7 MiB/s | 9.3 MiB/s | `core-ci` run 35175248504 |

The slowest of those hosts is where the comparison is clearest. `core-ci` measured 3.79 MiB/s on the
stream that scrolls, below the target, on an AMD EPYC 7763 twenty minutes before it measured
5.86 MiB/s on one of the same class. What differs between those two runs, in this repository, is
this engine and nothing else; what the two hosts were doing otherwise is not something a hosted
runner tells anybody.

Each row is one host's sampled runs and not a fixed property of that processor. The platform names a
class of processor rather than a machine, and one named class has answered a quarter apart on the
plain stream across the runs behind this revision, so the rows above are not a ranking of
processors. The runs named are `core-ci` runs of this revision's terminal engine, each one retaining
the figures, the processor and the verdict it measured, so a row can be read back to the run it came
from. Two of the EPYC 9V74 runs are 27% apart on the plain stream and 26% apart on the one that
scrolls. The wider end of the EPYC 9V74 row, and the narrower end of the Xeon row, were taken a few
commits before the last change to the output path, which only takes work off it; the rest are of the
engine as it stands.

Section 27 asks a reference host for at least four CPU cores and 8 GiB, so four processors is the
floor a host has to meet the target on, and every four-processor host above meets it on both
streams. A faster host clearing the target does not settle a slower one: the figure is asserted on
every optimised run, so a host that does not reach it says so, and the run keeps the number and the
processor.

It drains a 5 MiB stream of mixed text, colour changes, cursor movement, wide characters,
hyperlinks, alternate-screen churn and queries, and checks that the response lane, the row cache and
the session budget all stayed inside their bounds while it did.

It drains a second 5 MiB stream that scrolls. The first one clears its screen as often as it prints,
so rows rarely leave it and the historical cache stays empty; an application printing into a session
scrolls, every row it prints joins the cache, and the cache is enforced on the way. That is the load
a host actually carries, and it has to hold the target too. Beside it is a benchmark that feeds the
same bytes to two sessions, one whose history is emptied before every read and one whose history is
at its bound and evicting on every row, and asserts that the two reads cost about the same.
