//! A console's mouse, spelled as the report the session's application asked for.
//!
//! A Windows console reports its keys as records, and the session spells them as its terminal asked
//! for. The mouse is not handed on that way: a mouse event is a supported virtual-terminal
//! operation, so an application that asked for mouse reporting is sent the report it asked for, as
//! input bytes, the way a terminal emulator sends it, and an application that did not ask is sent
//! nothing. [`MouseReporting`] learns what the application asked for from the output the session
//! wrote, and [`MouseSpeller`] spells each mouse record the console reports as the report that asks
//! for.
//!
//! The application chooses both the events and the encoding. DEC mode 1000 asks for presses,
//! releases and the wheel; 1002 adds a move with a button held; 1003 adds every move. Mode 1006
//! asks for the SGR encoding, which carries any position and says which button came up; without it
//! the original report is used, which has room for 223 columns and rows and no way to say which
//! button was released. A position the original report has no room for is not reported, as
//! [`kr_keys::mouse`] has it, rather than reported as another cell. The encoding is one choice: mode
//! 1005 asks for UTF-8 coordinates, which are spelled as the original report, and setting either
//! mode replaces the one in force, while resetting the one in force returns the original report
//! and resetting the other changes nothing, as xterm has it.

use kr_keys::{Modifiers, MouseAction, MouseButton, MouseEncoding, MouseEvent, WheelDirection};
use kr_term::classify::CsiView;
use kr_term::event::{DirectDisposition, Event, EventKind};
use kr_term::lexer::Lexer;
use kr_term::modes::{ModeKind, ModeState};
use kr_term::win32::control_keys::{
    LEFT_ALT_PRESSED, LEFT_CTRL_PRESSED, RIGHT_ALT_PRESSED, RIGHT_CTRL_PRESSED, SHIFT_PRESSED,
};

/// The left button, in a console's button state.
const LEFT: u32 = 0x1;
/// The right button, in a console's button state.
const RIGHT: u32 = 0x2;
/// The middle button, in a console's button state.
const MIDDLE: u32 = 0x4;
/// The three buttons a report can name.
const BUTTONS: u32 = LEFT | RIGHT | MIDDLE;

/// The pointer moved.
const MOUSE_MOVED: u32 = 0x1;
/// The second press of a double click.
const DOUBLE_CLICK: u32 = 0x2;
/// The wheel turned, by the signed amount in the upper half of the button state.
const MOUSE_WHEELED: u32 = 0x4;

/// How much the wheel's amount changes for one notch of it.
const WHEEL_DELTA: i16 = 120;

/// One mouse record, with the fields the console reported it in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MouseRecord {
    /// The column of the console's screen buffer the pointer is over.
    pub column: i16,
    /// The row of the console's screen buffer the pointer is over.
    pub row: i16,
    /// Which buttons are down, and in the upper half the amount a wheel turned by.
    pub buttons: u32,
    /// The control-key state, as [`kr_term::win32::control_keys`] names its bits.
    pub control_keys: u32,
    /// Whether this was a move, a double click or a wheel.
    pub flags: u32,
}

/// What the application asked to be told of the mouse.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tracking {
    /// Nothing: the mouse is the person's, for selecting text.
    #[default]
    Off,
    /// Presses, releases and the wheel (mode 1000).
    Clicks,
    /// Those, and a move with a button held (mode 1002).
    Drag,
    /// Those, and every move (mode 1003).
    Motion,
}

/// How a stretch of output is read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reading {
    /// What the application wrote, which the terminal is shown as it is. It is read as a terminal
    /// reads it, and a terminal that keeps its mouse state by another rule than the session's is
    /// written what puts it in the session's state.
    Live,
    /// A screen the session drew for this terminal when it attached or reconnected. A worker of an
    /// earlier build draws a screen's tracking modes one by one in numeric order, the ones that are
    /// off among them (`?1000h ?1002l ?1003l`), and that screen has to be read as what its
    /// application asked for, the widest that is on: a reset of a tracking mode that is not on
    /// changes nothing. Nothing is written after it, because a current worker's screen resets
    /// before it sets. A worker of an earlier build also writes the encoding entries in numeric
    /// order (`?1005h ?1006l`), which leaves Terminal.app and iTerm at the default until the
    /// application sets or resets a mouse encoding, or the next restoration, as it did.
    Restoration,
    /// What this command drew from the session's screen: read as a terminal reads it, and nothing
    /// is written after it. Output of the session that follows a hole in the stream (a frame the
    /// bridge shed, or one that could not be decoded) is read the same way until the next screen,
    /// because the state the reader holds may no longer be the session's.
    Painted,
}

/// What to write to the terminal after the first `at` bytes of the output it has just been shown,
/// so that the terminal ends in the state the session holds: the reset of both encoding modes and
/// the set of the encoding in force.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Follow {
    /// How many bytes of the output come before it.
    pub at: usize,
    /// The encoding in force: 1005 or 1006.
    pub encoding: u32,
}

impl Follow {
    /// The bytes to write.
    #[must_use]
    pub fn bytes(&self) -> Vec<u8> {
        format!("\x1b[?1005;1006l\x1b[?{}h", self.encoding).into_bytes()
    }
}

/// The most bytes one frame of a restoration carries.
///
/// The worker cuts the screen it draws at an attach or a reconnection in frames of at most this
/// many bytes (`MAX_OUTPUT_EVENT_BYTES`, in `kr-worker`'s `service`), and every frame of that
/// screen carries the cursor the live output resumes at. A case in this crate holds the two equal.
pub const RESTORATION_CHUNK: usize = 256 * 1024;

/// Tells the frames of a restoration from live output, by where they arrive.
///
/// A restoration begins with the first delivery of a subscription, and goes on while the frames are
/// full: all of its frames but the last are [`RESTORATION_CHUNK`] bytes long, and all of them carry
/// the cursor the first one carried. A frame that is shorter ends it, and so does one at another
/// cursor.
///
/// The two readings differ in what is written after the output as well as in what a reset of a
/// tracking mode that is not on does: a live frame is followed by what puts Terminal.app and iTerm
/// in the session's encoding, and a frame of a restoration is not. A frame read as the wrong one
/// leaves its state wrong until the application next sets or resets a mode of that state (a
/// tracking mode for the console's tracking, an encoding for the terminal's encoding) or the next
/// restoration puts it right: ordinary output does not.
///
/// Named limits: the first live frame can carry the same cursor as the restoration's, so when the
/// restoration is a whole number of chunks long, that one live frame is read as part of it. A
/// bridge that drops the short last frame of a restoration (the frame that ends it) does the same
/// to the next live frame, which carries the cursor the restoration carried, until the restoration
/// that follows the resync marker the bridge leaves. The frames of a side effect (an
/// operating-system command or a bell, written by the worker's `send_effect`) carry the cursor of
/// their cause, so after such a restoration they read as part of it too; none of them holds a mode
/// setting, so the reading changes no mouse state for them.
#[derive(Debug, Default)]
pub struct Restoration {
    /// The cursor the next frame carries if it continues the restoration.
    open_at: Option<u64>,
}

impl Restoration {
    /// How an output event is read: `first` says it is the first delivery of its subscription, and
    /// the rest is what the event carries.
    pub fn reading(&mut self, first: bool, cursor: u64, length: usize) -> Reading {
        let restoring = first || self.open_at == Some(cursor);
        self.open_at = (restoring && length >= RESTORATION_CHUNK).then_some(cursor);
        if restoring {
            Reading::Restoration
        } else {
            Reading::Live
        }
    }
}

/// How many events of the lexer are held at once while a write is read.
const EVENTS_PER_BATCH: usize = 256;

/// What the session's application has asked for of the mouse, learned from what the session wrote.
///
/// The output is cut into sequences by the lexer the worker cuts it with, under the worker's
/// bounds, and a sequence is acted on only when the worker forwards it: a stretch that is padded
/// or cancelled, a sequence that is too long, one the profile does not carry, and one that the
/// worker never hands to a terminal are what the worker makes of them, because the worker's own
/// lexer and classification decide. The lexer keeps its place across the events of one stream, so a
/// mode setting cut in two between one write and the next is read whole.
///
/// The modes are kept by the worker's own record of them ([`ModeState`]). The tracking is one
/// setting, as a terminal and the session's screen keep it: setting one of the three tracking modes
/// replaces the one in force, and resetting any of them turns tracking off. A full reset of the
/// terminal (`ESC c`) turns every mode off. The encoding is one setting too, as xterm documents it:
/// a set of 1005 or 1006 replaces the one in force, and a reset returns the default only when it
/// names the one in force. Terminal.app and iTerm return the default at a reset of either, so after
/// a sequence that leaves them elsewhere than the session, live output is followed by the resets of
/// both modes and the set of the one in force.
///
/// Whether the application has bracketed paste on is read from the same output, since a console
/// that reports its keys as records reports no paste boundaries and is asked to spell its keys
/// while the application wants them.
pub struct MouseReporting {
    /// The mouse modes, as the worker records them.
    modes: ModeState,
    /// The encoding a terminal holds that returns the default at a reset of either mode.
    reset_by_either: Option<u32>,
    /// The worker's lexer, which cuts the output into sequences.
    lexer: Lexer,
    /// The events of the stretch being read, kept for the room they grew to.
    events: Vec<Event>,
}

impl Default for MouseReporting {
    fn default() -> Self {
        Self {
            modes: ModeState::new(),
            reset_by_either: None,
            lexer: Lexer::new(),
            events: Vec::new(),
        }
    }
}

impl std::fmt::Debug for MouseReporting {
    /// Which kind it is, never what it holds: the lexer keeps bytes of the output it reads.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MouseReporting")
            .finish_non_exhaustive()
    }
}

impl MouseReporting {
    /// Reads output as a terminal reads it, and writes nothing after it.
    #[cfg(test)]
    pub fn observe(&mut self, output: &[u8]) {
        let _ = self.read(output, Reading::Painted);
    }

    /// Reads output the session wrote, which is what the console is shown, and says what the
    /// terminal is to be written after it so that it holds the state the session holds.
    pub fn read(&mut self, output: &[u8], reading: Reading) -> Vec<Follow> {
        let mut follows = Vec::new();
        let origin = self.lexer.offset();
        let mut events = std::mem::take(&mut self.events);
        let mut index = 0;
        // A batch at a time, as the worker's engine reads, so that a large write of short
        // sequences is not held as one event each.
        loop {
            events.clear();
            let finished = self
                .lexer
                .feed_until(output, &mut index, &mut events, EVENTS_PER_BATCH);
            for event in &events {
                if self.apply(event, reading) && reading == Reading::Live && self.differs() {
                    self.reset_by_either = self.encoding_in_force();
                    // A difference after a sequence that set or reset an encoding is the encoding
                    // in force, which the terminal that returned the default is put back to.
                    if let Some(encoding) = self.encoding_in_force() {
                        // The sequence ended at its final byte, which is in this stretch.
                        let end = event.span.end().saturating_sub(origin);
                        follows.push(Follow {
                            at: usize::try_from(end)
                                .map_or(output.len(), |end| end.min(output.len())),
                            encoding,
                        });
                    }
                }
            }
            if finished {
                break;
            }
        }
        events.clear();
        events.shrink_to(EVENTS_PER_BATCH);
        self.events = events;
        follows
    }

    /// Whether a terminal that returns the default at any reset holds another encoding than the
    /// session.
    fn differs(&self) -> bool {
        self.encoding_in_force() != self.reset_by_either
    }

    /// What the application asked to be told of the mouse.
    #[must_use]
    pub fn tracking(&self) -> Tracking {
        if self.modes.is_set(ModeKind::Dec, 1003) {
            Tracking::Motion
        } else if self.modes.is_set(ModeKind::Dec, 1002) {
            Tracking::Drag
        } else if self.modes.is_set(ModeKind::Dec, 1000) {
            Tracking::Clicks
        } else {
            Tracking::Off
        }
    }

    /// The encoding the application asked for.
    #[must_use]
    pub fn encoding(&self) -> MouseEncoding {
        if self.encoding_in_force() == Some(1006) {
            MouseEncoding::Sgr
        } else {
            MouseEncoding::X10
        }
    }

    /// The encoding the application asked for: 1005, 1006, or none for the default.
    #[must_use]
    pub fn encoding_in_force(&self) -> Option<u32> {
        [1005_u16, 1006]
            .into_iter()
            .find(|&mode| self.modes.is_set(ModeKind::Dec, mode))
            .map(u32::from)
    }

    /// Whether the application asked for bracketed paste (DEC mode 2004), which a console reports
    /// no boundaries of while it reports its keys as records.
    #[must_use]
    pub fn bracketed_paste(&self) -> bool {
        self.modes.is_set(ModeKind::Dec, 2004)
    }

    /// Acts on one event of the lexer, and says whether it set or reset an encoding.
    ///
    /// Only what the worker forwards is acted on: a full reset of the terminal, and the setting and
    /// resetting of private modes, of which the mouse's are the ones kept.
    fn apply(&mut self, event: &Event, reading: Reading) -> bool {
        if event.disposition != DirectDisposition::Forward || event.passthrough_depth != 0 {
            return false;
        }
        match &event.kind {
            // A full reset turns every mode off, the mouse's among them.
            EventKind::Esc {
                intermediate: None,
                extra_intermediates: false,
                final_byte: b'c',
            } => {
                self.modes.full_reset();
                self.reset_by_either = None;
                false
            }
            EventKind::Csi {
                params,
                truncated,
                final_byte: final_byte @ (b'h' | b'l'),
            } => {
                let csi = CsiView::with_truncation(params, *final_byte, *truncated);
                if csi.private != Some(b'?') || !csi.intermediates.is_empty() {
                    return false;
                }
                let set = *final_byte == b'h';
                let mut touched = false;
                for slot in &csi.numbers {
                    if let Some(mode) = slot.and_then(|value| u16::try_from(value).ok()) {
                        touched |= self.apply_mode(mode, set, reading);
                    }
                }
                touched
            }
            _ => false,
        }
    }

    /// Applies the setting or resetting of one private mode, and says whether it was an encoding.
    fn apply_mode(&mut self, mode: u16, set: bool, reading: Reading) -> bool {
        match mode {
            // One tracking state: a set of one of the three replaces the one in force, and a
            // reset of any of them turns tracking off, as a terminal does. A screen drawn by a
            // worker of an earlier build is the exception, and only while it is being drawn: it
            // writes every tracking mode it holds, one by one, the ones that are off among them
            // (`?1000h ?1002l ?1003l`), so a reset of a mode that is not on changes nothing
            // there, and the screen is read as what its application asked for, the widest that
            // is on. A current worker draws a screen that resets the three before it sets the
            // one that is on, which reads the same under both rules.
            // Remove the exception when no worker of an earlier build can still be running: when
            // the lowest package version `check_build` accepts in `attach.rs` is at or above the
            // first release that holds the one-state tracking in `kr-term`'s `ModeState`.
            1000 | 1002 | 1003 => {
                if set || reading != Reading::Restoration || self.modes.is_set(ModeKind::Dec, mode)
                {
                    self.modes.set(ModeKind::Dec, mode, set);
                }
                false
            }
            // One encoding state, as xterm documents it: a set of 1005 or 1006 replaces the
            // one in force, and a reset returns the default only when it names the one in
            // force. A terminal that returns the default at a reset of either mode ends
            // elsewhere after a reset of the mode that is not in force. Only the SGR report is
            // spelled, so the console is spelled it while 1006 is the one in force, and the
            // original report otherwise, which is also what UTF-8 coordinates (1005) are
            // spelled as. A screen of a worker of an earlier build that holds both flags on
            // draws `?1005h ?1006h`, which reads as 1006, the later number.
            1005 | 1006 => {
                self.modes.set(ModeKind::Dec, mode, set);
                self.reset_by_either = set.then_some(u32::from(mode));
                true
            }
            // Bracketed paste is one flag, read the same under every reading, and it asks nothing
            // of the terminal: the output is written as it is.
            2004 => {
                self.modes.set(ModeKind::Dec, mode, set);
                false
            }
            _ => false,
        }
    }
}

/// The part of a console's screen buffer that its window shows.
///
/// A mouse record's position is counted in the screen buffer, and what an application is told is
/// counted in the window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Window {
    /// The column of the buffer where the window begins.
    pub left: i16,
    /// The row of the buffer where the window begins.
    pub top: i16,
    /// How many columns the window shows.
    pub columns: u16,
    /// How many rows the window shows.
    pub rows: u16,
}

impl Window {
    /// The window of a console that says nothing of its window, and of a terminal that sends the
    /// reports itself: it begins at the buffer's origin and every cell after it is shown.
    pub const UNBOUNDED: Self = Self {
        left: 0,
        top: 0,
        columns: u16::MAX,
        rows: u16::MAX,
    };

    /// The cell of the window that the buffer's `column` and `row` is, or none when the window does
    /// not show it.
    fn cell(self, column: i16, row: i16) -> Option<(u32, u32)> {
        let within = |position: i16, from: i16, extent: u16| {
            u32::try_from(i32::from(position) - i32::from(from))
                .ok()
                .filter(|cell| *cell < u32::from(extent))
        };
        Some((
            within(column, self.left, self.columns)?,
            within(row, self.top, self.rows)?,
        ))
    }
}

/// Spells the console's mouse records as reports.
///
/// It remembers which buttons the console last said were down, because a record says which are down
/// and a report says which one went down or came up. It also keeps the part of a notch of the wheel
/// that no report has been sent for, because a console with a finely turning wheel reports less
/// than a notch at a time.
#[derive(Debug, Default)]
pub struct MouseSpeller {
    held: u32,
    /// The wheel's turn that is not yet a whole notch, in the direction it turned.
    wheel: i32,
}

impl MouseSpeller {
    /// Forgets the buttons that were down and the part of a notch that was turned. A console that
    /// reports no mouse says nothing of a button let go of meanwhile, so what was down before is
    /// not known to be down when it reports again.
    pub fn forget_the_buttons(&mut self) {
        *self = Self::default();
    }

    /// The bytes that tell the application of `record`, or none when it asked for nothing the
    /// record is.
    ///
    /// `window` is the part of the console's screen buffer its window shows. A record's position is
    /// counted in the buffer and a report's in the window, and a record whose position the window
    /// does not show is told to nobody: it is no cell of the grid the application draws on. The
    /// buttons the record says are down are remembered whether or not anything is reported.
    pub fn spell(
        &mut self,
        record: MouseRecord,
        reporting: &MouseReporting,
        window: Window,
    ) -> Vec<u8> {
        let modifiers = Modifiers {
            shift: record.control_keys & SHIFT_PRESSED != 0,
            alt: record.control_keys & (LEFT_ALT_PRESSED | RIGHT_ALT_PRESSED) != 0,
            control: record.control_keys & (LEFT_CTRL_PRESSED | RIGHT_CTRL_PRESSED) != 0,
            superkey: false,
        };
        let cell = window.cell(record.column, record.row);
        let actions = self.actions(record);
        let Some((column, row)) = cell else {
            return Vec::new();
        };
        let mut report = Vec::new();
        for action in actions {
            report.extend(Self::report(
                MouseEvent {
                    action,
                    column,
                    row,
                    modifiers,
                },
                reporting,
            ));
        }
        report
    }

    /// The bytes that tell the application of `event`, or none when it asked for nothing the event
    /// is. The event is one a console already reports as a cell of its window, such as a report the
    /// console spelled itself ([`SgrMouseFilter`]), so no buffer position is mapped and no button
    /// is remembered.
    #[must_use]
    pub fn report(event: MouseEvent, reporting: &MouseReporting) -> Vec<u8> {
        let asked = match event.action {
            MouseAction::Press(_) | MouseAction::Release(_) | MouseAction::Wheel(_) => {
                Tracking::Clicks
            }
            MouseAction::Drag(_) => Tracking::Drag,
            MouseAction::Motion => Tracking::Motion,
        };
        if reporting.tracking() < asked {
            return Vec::new();
        }
        // A position the encoding has no room for is not told to the application as another.
        kr_keys::mouse(event, reporting.encoding()).unwrap_or_default()
    }

    /// What the pointer did, as a report names it, in the order it happened.
    fn actions(&mut self, record: MouseRecord) -> Vec<MouseAction> {
        if record.flags & MOUSE_WHEELED != 0 {
            let high = u16::try_from(record.buttons >> 16).unwrap_or(0);
            let amount = i32::from(i16::from_ne_bytes(high.to_ne_bytes()));
            // A turn the other way leaves nothing of the turn before it, and no turn leaves it as
            // it was.
            if amount != 0 && (amount > 0) != (self.wheel > 0) {
                self.wheel = 0;
            }
            self.wheel += amount;
            let notches = self.wheel / i32::from(WHEEL_DELTA);
            self.wheel -= notches * i32::from(WHEEL_DELTA);
            let direction = if notches > 0 {
                WheelDirection::Up
            } else {
                WheelDirection::Down
            };
            return (0..notches.unsigned_abs())
                .map(|_| MouseAction::Wheel(direction))
                .collect();
        }
        // A wheel that turns sideways is not told: the reports of this crate's encoder have no
        // button for it.
        if record.flags & !(MOUSE_MOVED | DOUBLE_CLICK) != 0 {
            return Vec::new();
        }
        let now = record.buttons & BUTTONS;
        let before = std::mem::replace(&mut self.held, now);
        if record.flags & MOUSE_MOVED != 0 {
            return match first_of(now) {
                Some(button) => vec![MouseAction::Drag(button)],
                None => vec![MouseAction::Motion],
            };
        }
        let mut actions = Vec::new();
        for (bit, button) in [
            (LEFT, MouseButton::Left),
            (MIDDLE, MouseButton::Middle),
            (RIGHT, MouseButton::Right),
        ] {
            if now & bit != 0 && before & bit == 0 {
                actions.push(MouseAction::Press(button));
            } else if now & bit == 0 && before & bit != 0 {
                actions.push(MouseAction::Release(button));
            }
        }
        actions
    }
}

/// The first of the buttons in `state`, the left one first.
const fn first_of(state: u32) -> Option<MouseButton> {
    if state & LEFT != 0 {
        Some(MouseButton::Left)
    } else if state & MIDDLE != 0 {
        Some(MouseButton::Middle)
    } else if state & RIGHT != 0 {
        Some(MouseButton::Right)
    } else {
        None
    }
}

/// How long bytes that begin a mouse report wait for the rest of it. A lone escape is the Escape
/// key, and a console writes a report it spells in one piece, so what has not become a report by
/// then is text.
pub const HELD_PREFIX_WAIT: std::time::Duration = std::time::Duration::from_millis(25);

/// What [`SgrMouseFilter`] makes of the text a console spelled.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Part {
    /// Text to hand on to the application as it is.
    Text(Vec<u8>),
    /// A mouse report the console spelled, as the event it tells of.
    Report(MouseEvent),
}

/// What the bytes held so far are.
enum Held {
    /// A whole mouse report: its button code, column and row (counted from one) and whether it
    /// says a button came up.
    Report {
        code: u32,
        column: u32,
        row: u32,
        up: bool,
    },
    /// The opening or the closing marker of a bracketed paste.
    Marker { opening: bool },
    /// The beginning of one of those, which more bytes may complete.
    Prefix,
    /// Not the beginning of either.
    Neither,
}

const REPORT_START: &[u8] = b"\x1b[<";
const PASTE_OPENING: &[u8] = b"\x1b[200~";
const PASTE_CLOSING: &[u8] = b"\x1b[201~";
/// The digits a report's button code, column and row may have.
const REPORT_DIGITS: [u32; 3] = [3, 5, 5];

/// Takes the mouse reports out of the text a console spelled.
///
/// A console that spells its keys also spells the mouse, as the reports a terminal sends: `ESC [ <`,
/// the button code, the column and the row, each after a semicolon, and `M`, or `m` when a button
/// came up. Everything else is text. Bytes that begin a report are held until the next byte shows
/// whether they are one, and go on as text when it does not, or when [`flush`](Self::flush) is
/// called because nothing more came. A report is at most 19 bytes, so that is all that is ever
/// held. Between the opening and the closing marker of a bracketed paste nothing is a report, so
/// that a pasted text that holds one reaches the application as the text it is.
#[derive(Debug, Default)]
pub struct SgrMouseFilter {
    held: Vec<u8>,
    pasting: bool,
}

impl SgrMouseFilter {
    /// Whether bytes that may begin a report are held.
    #[must_use]
    pub fn holds(&self) -> bool {
        !self.held.is_empty()
    }

    /// Takes `bytes`, which follow those given before, and returns what they are, in order.
    pub fn push(&mut self, bytes: &[u8]) -> Vec<Part> {
        let mut parts = Vec::new();
        let mut text = Vec::new();
        for &byte in bytes {
            if self.held.is_empty() && byte != 0x1b {
                text.push(byte);
                continue;
            }
            self.held.push(byte);
            loop {
                match self.classify() {
                    Held::Prefix => break,
                    Held::Report {
                        code,
                        column,
                        row,
                        up,
                    } => {
                        self.held.clear();
                        if let Some(event) = event_of(code, column, row, up) {
                            if !text.is_empty() {
                                parts.push(Part::Text(std::mem::take(&mut text)));
                            }
                            parts.push(Part::Report(event));
                        }
                        break;
                    }
                    Held::Marker { opening } => {
                        text.append(&mut self.held);
                        self.pasting = opening;
                        break;
                    }
                    Held::Neither => {
                        // The first byte is text; the ones after it may begin something.
                        text.push(self.held.remove(0));
                        if self.held.first() != Some(&0x1b) {
                            text.append(&mut self.held);
                        }
                        if self.held.is_empty() {
                            break;
                        }
                    }
                }
            }
        }
        if !text.is_empty() {
            parts.push(Part::Text(text));
        }
        parts
    }

    /// The bytes held, as the text they are, when no more are coming.
    pub fn flush(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.held)
    }

    /// What the bytes held are.
    fn classify(&self) -> Held {
        let held = self.held.as_slice();
        let prefix_of = |whole: &[u8]| held.len() <= whole.len() && whole.starts_with(held);
        if self.pasting {
            return if held == PASTE_CLOSING {
                Held::Marker { opening: false }
            } else if prefix_of(PASTE_CLOSING) {
                Held::Prefix
            } else {
                Held::Neither
            };
        }
        if held == PASTE_OPENING {
            return Held::Marker { opening: true };
        }
        if prefix_of(PASTE_OPENING) {
            return Held::Prefix;
        }
        if !held.starts_with(REPORT_START) {
            return if prefix_of(REPORT_START) {
                Held::Prefix
            } else {
                Held::Neither
            };
        }
        let mut fields = [0_u32; 3];
        let mut field = 0;
        let mut digits = 0;
        for &byte in &held[REPORT_START.len()..] {
            match byte {
                b'0'..=b'9' => {
                    digits += 1;
                    if digits > REPORT_DIGITS[field] {
                        return Held::Neither;
                    }
                    fields[field] = fields[field] * 10 + u32::from(byte - b'0');
                }
                b';' if field < 2 && digits > 0 => {
                    field += 1;
                    digits = 0;
                }
                b'M' | b'm' if field == 2 && digits > 0 => {
                    return Held::Report {
                        code: fields[0],
                        column: fields[1],
                        row: fields[2],
                        up: byte == b'm',
                    };
                }
                _ => return Held::Neither,
            }
        }
        Held::Prefix
    }
}

/// The event a report tells of, or none when it tells of nothing an application can be told: a
/// position that is not one, a button or a sideways wheel this crate's encoder has no report for.
fn event_of(code: u32, column: u32, row: u32, up: bool) -> Option<MouseEvent> {
    if column == 0 || row == 0 || code >= 128 {
        return None;
    }
    let button = match code & 0b11 {
        0 => Some(MouseButton::Left),
        1 => Some(MouseButton::Middle),
        2 => Some(MouseButton::Right),
        _ => None,
    };
    let action = if code & 64 != 0 {
        match (code & 0b11, up) {
            (0, false) => MouseAction::Wheel(WheelDirection::Up),
            (1, false) => MouseAction::Wheel(WheelDirection::Down),
            _ => return None,
        }
    } else if code & 32 != 0 {
        button.map_or(MouseAction::Motion, MouseAction::Drag)
    } else if up {
        MouseAction::Release(button?)
    } else {
        MouseAction::Press(button?)
    };
    Some(MouseEvent {
        action,
        column: column - 1,
        row: row - 1,
        modifiers: Modifiers {
            shift: code & 4 != 0,
            alt: code & 8 != 0,
            control: code & 16 != 0,
            superkey: false,
        },
    })
}

/// The console handles Ctrl-C itself, and does not hand it on as a key.
const ENABLE_PROCESSED_INPUT: u32 = 0x1;
/// A read of the console waits for a whole line.
const ENABLE_LINE_INPUT: u32 = 0x2;
/// The console shows what is typed.
const ENABLE_ECHO_INPUT: u32 = 0x4;
/// The console reports a change of its window's size as a record.
const ENABLE_WINDOW_INPUT: u32 = 0x8;
/// The console reports the mouse as records.
const ENABLE_MOUSE_INPUT: u32 = 0x10;
/// The console uses the mouse to select text, a private flag of the console.
const ENABLE_QUICK_EDIT_MODE: u32 = 0x40;
/// A mode that has it sets the private flags as it states them, and a mode that has not leaves
/// them as they are.
const ENABLE_EXTENDED_FLAGS: u32 = 0x80;
/// The console spells the keys itself, as the sequences a terminal sends.
const ENABLE_VIRTUAL_TERMINAL_INPUT: u32 = 0x200;

// The values above are the system's, written out so that the arithmetic below is code on every
// platform and its cases run wherever the tests do. The Windows build holds them to the system's.
#[cfg(windows)]
const _: () = {
    assert!(ENABLE_PROCESSED_INPUT == windows_sys::Win32::System::Console::ENABLE_PROCESSED_INPUT);
    assert!(ENABLE_LINE_INPUT == windows_sys::Win32::System::Console::ENABLE_LINE_INPUT);
    assert!(ENABLE_ECHO_INPUT == windows_sys::Win32::System::Console::ENABLE_ECHO_INPUT);
    assert!(ENABLE_WINDOW_INPUT == windows_sys::Win32::System::Console::ENABLE_WINDOW_INPUT);
    assert!(ENABLE_MOUSE_INPUT == windows_sys::Win32::System::Console::ENABLE_MOUSE_INPUT);
    assert!(ENABLE_QUICK_EDIT_MODE == windows_sys::Win32::System::Console::ENABLE_QUICK_EDIT_MODE);
    assert!(ENABLE_EXTENDED_FLAGS == windows_sys::Win32::System::Console::ENABLE_EXTENDED_FLAGS);
    assert!(
        ENABLE_VIRTUAL_TERMINAL_INPUT
            == windows_sys::Win32::System::Console::ENABLE_VIRTUAL_TERMINAL_INPUT
    );
};

/// The console input mode a record reader needs, made from `saved`, the mode the console had.
///
/// `ENABLE_VIRTUAL_TERMINAL_INPUT` is deliberately absent: it is the console translating records
/// into VT sequences, which is the translation this path exists to avoid. It is asked for
/// ([`keys_spelled_mode`]) only while the session's application has bracketed paste on, because a
/// console that reports records reports no boundaries of a paste, and when the session refuses the
/// records. Line input, echo and
/// the console's own handling of Ctrl-C are absent as well: every key, the interrupt among them,
/// is a record to hand on to the session. Mouse and window-size records are not asked for here:
/// the console keeps the mouse for selecting text, as it does for any command that does not ask for
/// it, until the session's application asks to be told of the mouse ([`mouse_input_mode`]). No
/// private flag is written: the mode has those of `saved` as they were.
#[must_use]
pub const fn record_input_mode(saved: u32) -> u32 {
    saved
        & !(ENABLE_LINE_INPUT
            | ENABLE_ECHO_INPUT
            | ENABLE_PROCESSED_INPUT
            | ENABLE_VIRTUAL_TERMINAL_INPUT
            | ENABLE_MOUSE_INPUT
            | ENABLE_WINDOW_INPUT)
}

/// The console input mode `current` becomes when the session's application starts or stops asking
/// to be told of the mouse. `attached` is the mode the console had when the attachment began.
///
/// While it asks, the console reports the mouse as records. A console that reports its private
/// flags has `ENABLE_EXTENDED_FLAGS` in `attached`, and it no longer uses the mouse to select text
/// once the extended flags are set and quick edit is removed. When the application stops, the
/// console has the mouse again: quick edit comes back if `attached` had it on. Nothing else of
/// `current` changes, so a console that has been asked to spell its keys itself goes on spelling
/// them, and goes on having the mouse flag as `attached` had it ([`keys_spelled_mode`]).
///
/// A console whose mode had no `ENABLE_EXTENDED_FLAGS` reports none of its private flags, whatever
/// they are, and a mode that sets the extended flags sets each of them as that mode states it: the
/// attachment would turn off insert mode and auto position, and quick edit it never learned was on,
/// and the restored mode, which has no extended flags, could not turn them on again. So on such a
/// console no private flag is written at any step: asking sets `ENABLE_MOUSE_INPUT` alone and
/// stopping clears it. The console then reports the mouse as records only while quick edit is off.
#[must_use]
pub const fn mouse_input_mode(current: u32, attached: u32, asked: bool) -> u32 {
    let kept = if current & ENABLE_VIRTUAL_TERMINAL_INPUT != 0 {
        attached & ENABLE_MOUSE_INPUT
    } else {
        0
    };
    if attached & ENABLE_EXTENDED_FLAGS == 0 {
        return if asked {
            current | ENABLE_MOUSE_INPUT
        } else {
            (current & !ENABLE_MOUSE_INPUT) | kept
        };
    }
    if asked {
        (current | ENABLE_MOUSE_INPUT | ENABLE_EXTENDED_FLAGS) & !ENABLE_QUICK_EDIT_MODE
    } else {
        (current & !(ENABLE_MOUSE_INPUT | ENABLE_QUICK_EDIT_MODE))
            | (attached & ENABLE_QUICK_EDIT_MODE)
            | kept
    }
}

/// The console input mode `current` becomes when the console is asked to spell its keys itself
/// (`spelled`), or to report them as records again. `attached` is the mode the console had when the
/// attachment began, and `mouse_asked` says whether the session's application asks to be told of
/// the mouse ([`mouse_input_mode`]).
///
/// A console that spells its keys is given the virtual-terminal flag and keeps `ENABLE_MOUSE_INPUT`
/// and `ENABLE_WINDOW_INPUT` as `attached` had them, which is the input mode of a command that
/// reads bytes (`ControllingTerminal::enter_raw_mode`) and the one in which a console was seen to
/// hand on a paste's two markers whole. The rest of the mouse's flags and the private flags stay as
/// `current` holds them.
///
/// A console that reports records again has both flags off, as the record mode of the attachment
/// has them, except the mouse's while the application asks for the mouse.
#[must_use]
pub const fn keys_spelled_mode(
    current: u32,
    attached: u32,
    mouse_asked: bool,
    spelled: bool,
) -> u32 {
    const KEPT: u32 = ENABLE_MOUSE_INPUT | ENABLE_WINDOW_INPUT;
    if spelled {
        current | ENABLE_VIRTUAL_TERMINAL_INPUT | (attached & KEPT)
    } else {
        let mouse = if mouse_asked { ENABLE_MOUSE_INPUT } else { 0 };
        (current & !(ENABLE_VIRTUAL_TERMINAL_INPUT | KEPT)) | mouse
    }
}

/// Whether a console whose input mode is `mode` spells its keys itself.
#[must_use]
pub const fn keys_are_spelled(mode: u32) -> bool {
    mode & ENABLE_VIRTUAL_TERMINAL_INPUT != 0
}

#[cfg(test)]
mod tests {
    use super::{
        ENABLE_ECHO_INPUT, ENABLE_EXTENDED_FLAGS, ENABLE_LINE_INPUT, ENABLE_MOUSE_INPUT,
        ENABLE_PROCESSED_INPUT, ENABLE_QUICK_EDIT_MODE, ENABLE_VIRTUAL_TERMINAL_INPUT,
        ENABLE_WINDOW_INPUT, Follow, LEFT, MIDDLE, MOUSE_MOVED, MOUSE_WHEELED, MouseRecord,
        MouseReporting, MouseSpeller, RESTORATION_CHUNK, RIGHT, Reading, Restoration, Tracking,
        Window, keys_are_spelled, keys_spelled_mode, mouse_input_mode, record_input_mode,
    };
    use super::{Part, SgrMouseFilter};

    /// A record at `column` and `row` with the buttons and flags the console reported it with.
    fn record(column: i16, row: i16, buttons: u32, flags: u32) -> MouseRecord {
        MouseRecord {
            column,
            row,
            buttons,
            control_keys: 0,
            flags,
        }
    }

    /// What an application that wrote `asked` is told of `records`, in order, on a window that
    /// begins at the buffer's origin.
    fn told(asked: &[u8], records: &[MouseRecord]) -> Vec<u8> {
        let mut reporting = MouseReporting::default();
        reporting.observe(asked);
        let mut speller = MouseSpeller::default();
        records
            .iter()
            .flat_map(|record| speller.spell(*record, &reporting, Window::UNBOUNDED))
            .collect()
    }

    /// The modes an application asks for the mouse with are read from what it writes, set and
    /// reset, and a write that is cut anywhere is read as it would have been whole.
    #[test]
    fn the_modes_that_ask_for_the_mouse_are_read_from_the_output_however_it_is_cut() {
        let asked = b"text\x1b[?1049h\x1b[?1000;1006hmore";
        for cut in 0..=asked.len() {
            let mut reporting = MouseReporting::default();
            reporting.observe(&asked[..cut]);
            reporting.observe(&asked[cut..]);
            assert_eq!(reporting.tracking(), Tracking::Clicks, "cut at {cut}");
            assert_eq!(
                reporting.encoding(),
                kr_keys::MouseEncoding::Sgr,
                "cut at {cut}"
            );
        }
        let mut reporting = MouseReporting::default();
        for (output, tracking) in [
            (&b"\x1b[?1002h"[..], Tracking::Drag),
            (b"\x1b[?1003h", Tracking::Motion),
            (b"\x1b[?1000h", Tracking::Clicks),
            (b"\x1b[?1003l", Tracking::Off),
            (b"\x1b[?1002h", Tracking::Drag),
            (b"\x1b[?1002l", Tracking::Off),
        ] {
            reporting.observe(output);
            assert_eq!(reporting.tracking(), tracking, "{output:?}");
        }
        reporting.observe(b"\x1b[?1006h");
        assert_eq!(reporting.encoding(), kr_keys::MouseEncoding::Sgr);
        reporting.observe(b"\x1b[?1006l");
        assert_eq!(reporting.encoding(), kr_keys::MouseEncoding::X10);
    }

    /// The tracking is one state: a set of one of the three replaces the one in force, a reset of
    /// the one in force turns it off, and a frame drawn from the session's screen resets the three
    /// before it sets the one that is on, so a console that was reporting stops when the session's
    /// application has tracking off.
    #[test]
    fn a_frame_that_resets_the_three_and_sets_one_leaves_that_one_and_nothing_when_none_is_on() {
        let mut reporting = MouseReporting::default();
        reporting.observe(b"\x1b[?1003h");
        assert_eq!(reporting.tracking(), Tracking::Motion);
        reporting.observe(b"\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1002h\x1b[?1006h");
        assert_eq!(reporting.tracking(), Tracking::Drag);
        assert_eq!(reporting.encoding(), kr_keys::MouseEncoding::Sgr);
        reporting.observe(b"\x1b[?1003h\x1b[?1000h");
        assert_eq!(reporting.tracking(), Tracking::Clicks);
        for on in [&b"\x1b[?1000h"[..], b"\x1b[?1002h", b"\x1b[?1003h"] {
            let mut reporting = MouseReporting::default();
            reporting.observe(on);
            reporting.observe(b"\x1b[?1000l\x1b[?1002l\x1b[?1003l");
            assert_eq!(reporting.tracking(), Tracking::Off, "{on:?}");
        }
    }

    /// The encoding is one state, as xterm documents it: a set of 1005 or 1006 replaces the one in
    /// force, and a reset returns the default only when it names the one in force. The console is
    /// spelled the SGR report only while 1006 is the one in force; UTF-8 coordinates are spelled
    /// as the original report, as they always were. A frame drawn from the session's screen resets
    /// both modes and sets the one that is on, and a frame of a worker of an earlier build that holds
    /// both flags on reads as 1006.
    #[test]
    fn the_encoding_is_one_state_and_a_reset_returns_the_default_when_it_names_the_one_in_force() {
        for (output, encoding) in [
            (&b"\x1b[?1006h\x1b[?1005h"[..], kr_keys::MouseEncoding::X10),
            (b"\x1b[?1005h\x1b[?1006h", kr_keys::MouseEncoding::Sgr),
            (b"\x1b[?1005h\x1b[?1006l", kr_keys::MouseEncoding::X10),
            (b"\x1b[?1006h\x1b[?1005l", kr_keys::MouseEncoding::Sgr),
            (b"\x1b[?1006h\x1b[?1006l", kr_keys::MouseEncoding::X10),
            (
                b"\x1b[?1006h\x1b[?1005l\x1b[?1006l",
                kr_keys::MouseEncoding::X10,
            ),
            (
                b"\x1b[?1005l\x1b[?1006l\x1b[?1006h",
                kr_keys::MouseEncoding::Sgr,
            ),
            (
                b"\x1b[?1000h\x1b[?1002l\x1b[?1003l\x1b[?1005h\x1b[?1006h",
                kr_keys::MouseEncoding::Sgr,
            ),
            (
                b"\x1b[?1000h\x1b[?1002l\x1b[?1003l\x1b[?1005l\x1b[?1006h",
                kr_keys::MouseEncoding::Sgr,
            ),
        ] {
            let mut reporting = MouseReporting::default();
            reporting.observe(output);
            assert_eq!(reporting.encoding(), encoding, "{output:?}");
        }
    }

    /// With a current worker, a reset of a tracking mode that is not the one on turns tracking off,
    /// as it does on a terminal: the application is not told of a mouse it turned off, and the
    /// person can select text.
    #[test]
    fn a_reset_of_a_tracking_mode_that_is_not_on_turns_tracking_off_in_live_output() {
        for output in [&b"\x1b[?1002h\x1b[?1000l"[..], b"\x1b[?1003h\x1b[?1002l"] {
            for reading in [Reading::Live, Reading::Painted] {
                let mut reporting = MouseReporting::default();
                let _ = reporting.read(output, reading);
                assert_eq!(
                    reporting.tracking(),
                    Tracking::Off,
                    "{output:?} {reading:?}"
                );
            }
        }
    }

    /// A worker of an earlier build draws a screen with each tracking mode it holds, one by one and
    /// the ones that are off among them, and that screen is read as what the application asked for.
    /// The same bytes in live output are what the application wrote, and turn tracking off.
    #[test]
    fn a_restoration_of_an_earlier_worker_is_read_as_the_widest_tracking_that_is_on() {
        for (frame, tracking) in [
            (
                &b"\x1b[?1000h\x1b[?1002l\x1b[?1003l\x1b[?1006h"[..],
                Tracking::Clicks,
            ),
            (b"\x1b[?1000l\x1b[?1002h\x1b[?1003l", Tracking::Drag),
            (b"\x1b[?1000h\x1b[?1002h\x1b[?1003l", Tracking::Drag),
            (b"\x1b[?1000h\x1b[?1002l\x1b[?1003h", Tracking::Motion),
            (b"\x1b[?1000l\x1b[?1002l\x1b[?1003l", Tracking::Off),
        ] {
            let mut reporting = MouseReporting::default();
            let _ = reporting.read(frame, Reading::Restoration);
            assert_eq!(reporting.tracking(), tracking, "{frame:?}");
        }
        for reading in [Reading::Live, Reading::Painted] {
            let mut reporting = MouseReporting::default();
            let _ = reporting.read(b"\x1b[?1000h\x1b[?1002l\x1b[?1003l", reading);
            assert_eq!(reporting.tracking(), Tracking::Off, "{reading:?}");
        }
    }

    /// A terminal that returns the default at a reset of either encoding mode is written what puts
    /// it in the state the session holds, after the sequence that left it elsewhere: the resets of
    /// both modes and the set of the one in force. That includes a sequence that names several
    /// modes, and one that is cut between two writes.
    #[test]
    fn live_output_that_resets_the_encoding_not_in_force_is_followed_by_what_restores_it() {
        let follows = |output: &[u8]| MouseReporting::default().read(output, Reading::Live);
        let at_the_end = |output: &[u8], encoding: u32| {
            vec![Follow {
                at: output.len(),
                encoding,
            }]
        };
        for (output, encoding) in [
            (&b"\x1b[?1006h\x1b[?1005l"[..], 1006),
            (b"\x1b[?1005h\x1b[?1006l", 1005),
            (b"\x1b[?1005h\x1b[?1006;1000l", 1005),
            (b"\x1b[?1005h\x1b[?1000;1006l", 1005),
        ] {
            assert_eq!(follows(output), at_the_end(output, encoding), "{output:?}");
        }
        // What is written: the reset of both modes, then the set of the one in force.
        assert_eq!(
            Follow {
                at: 0,
                encoding: 1006
            }
            .bytes(),
            b"\x1b[?1005;1006l\x1b[?1006h".to_vec()
        );
        // A reset in the longest list the worker forwards, which is as long as its lexer keeps one
        // sequence, is read whole: nothing is restored that the application cleared. One byte more
        // is a sequence the worker withholds and does not act on, so it is passed over here too,
        // and the encoding it named stays in force.
        let longest = kr_term::lexer::LexLimits::DEFAULT.max_sequence_bytes;
        // Every slot of a list the worker forwards names a mode it tracks (an empty one makes it
        // an extension), so the filler is the modes 1 and 12, which are tracked and not the mouse's.
        let list = |bytes: usize| {
            let mut list = b"\x1b[?".to_vec();
            let mut room = bytes - list.len() - b"1006l".len();
            if room % 2 == 1 {
                list.extend_from_slice(b"12;");
                room -= 3;
            }
            list.extend(b"1;".repeat(room / 2));
            list.extend_from_slice(b"1006l");
            list
        };
        for (bytes, cleared) in [(longest, true), (longest + 1, false)] {
            let mut output = b"\x1b[?1000;1006h".to_vec();
            output.extend_from_slice(&list(bytes));
            assert_eq!(output.len(), 13 + bytes);
            output.extend_from_slice(b"\x1b[?1005l");
            let mut reporting = MouseReporting::default();
            let follows = reporting.read(&output, Reading::Live);
            if cleared {
                assert_eq!(follows, Vec::new());
                assert_eq!(reporting.encoding(), kr_keys::MouseEncoding::X10);
            } else {
                assert_eq!(
                    follows,
                    vec![Follow {
                        at: output.len(),
                        encoding: 1006
                    }]
                );
                assert_eq!(reporting.encoding(), kr_keys::MouseEncoding::Sgr);
            }
        }
        // The sequences that leave every terminal where the session is write nothing.
        for output in [
            &b"\x1b[?1006h"[..],
            b"\x1b[?1006h\x1b[?1006l",
            b"\x1b[?1005h\x1b[?1006h",
            b"\x1b[?1006h\x1b[?1006l\x1b[?1005l",
            b"\x1b[?1000h\x1b[?1002l",
            b"\x1b[?1005l",
        ] {
            assert_eq!(follows(output), Vec::new(), "{output:?}");
        }
        // The follow-up goes after the sequence, wherever the write ends.
        let mut reporting = MouseReporting::default();
        assert_eq!(
            reporting.read(b"ab\x1b[?1005h\x1b[?100", Reading::Live),
            Vec::new()
        );
        assert_eq!(
            reporting.read(b"6lcd\x1b[?1000h", Reading::Live),
            vec![Follow {
                at: 2,
                encoding: 1005
            }]
        );
        // A screen drawn for the terminal and one this command drew write nothing after them.
        for reading in [Reading::Restoration, Reading::Painted] {
            let mut reporting = MouseReporting::default();
            let _ = reporting.read(b"\x1b[?1006h", reading);
            assert_eq!(reporting.read(b"\x1b[?1005l", reading), Vec::new());
        }
    }

    /// A sequence is read where the worker's lexer reads it. Padding keeps a sequence whole, wherever
    /// it comes in it. Cancel and substitute end it, an escape begins another, a raw 8-bit control
    /// ends it, and a slot with nothing in it makes it a sequence the worker does not act on.
    #[test]
    fn a_reset_is_read_as_the_worker_reads_it() {
        // After the set of 1000 and 1006, the application writes each of these and then `?1005l`.
        for (written, cleared) in [
            (&b"\x1b\x00[?1006l"[..], true),
            (b"\x1b\x7f[?1006l", true),
            (b"\x1b[\x00?1006l", true),
            (b"\x1b[?10\x00\x7f06l", true),
            (b"\x1b[?1006\x18l", false),
            (b"\x1b[?1006\x1al", false),
            (b"\x1b[?1006\x1b[?1000h", false),
            (b"\x1b[?1006\x9bl", false),
            (b"\x1b[?;1006l", false),
            (b"\x1b[?1006;l", false),
        ] {
            let mut output = b"\x1b[?1000;1006h".to_vec();
            output.extend_from_slice(written);
            output.extend_from_slice(b"\x1b[?1005l");
            let mut reporting = MouseReporting::default();
            let follows = reporting.read(&output, Reading::Live);
            let expected = if cleared {
                Vec::new()
            } else {
                vec![Follow {
                    at: output.len(),
                    encoding: 1006,
                }]
            };
            assert_eq!(follows, expected, "{written:?}");
            assert_eq!(
                reporting.encoding() == kr_keys::MouseEncoding::Sgr,
                !cleared,
                "{written:?}"
            );
        }
    }

    /// Output is told from a restoration by where it arrives: the first delivery of a subscription
    /// begins one, and it goes on while its frames are full-sized and at the cursor the first one
    /// carried.
    #[test]
    fn a_restoration_ends_at_the_first_frame_that_is_short_or_at_another_cursor() {
        use Reading::{Live, Restoration as Screen};
        let chunk = RESTORATION_CHUNK;
        let mut frames = Restoration::default();
        // Less than one chunk: the one frame; the live frame at the same cursor is live.
        assert_eq!(frames.reading(true, 40, 900), Screen);
        assert_eq!(frames.reading(false, 40, 5), Live);
        // One chunk and one byte: two frames at the cursor.
        let mut frames = Restoration::default();
        assert_eq!(frames.reading(true, 40, chunk), Screen);
        assert_eq!(frames.reading(false, 40, 1), Screen);
        assert_eq!(frames.reading(false, 40, 5), Live);
        // Exactly one chunk: the live frame at the same cursor is read as part of it once, and the
        // next is live; a live frame that is a chunk long after that does not begin another one.
        let mut frames = Restoration::default();
        assert_eq!(frames.reading(true, 40, chunk), Screen);
        assert_eq!(frames.reading(false, 40, 5), Screen);
        assert_eq!(frames.reading(false, 45, chunk), Live);
        assert_eq!(frames.reading(false, 45 + chunk as u64, 5), Live);
        // Exactly two chunks.
        let mut frames = Restoration::default();
        assert_eq!(frames.reading(true, 40, chunk), Screen);
        assert_eq!(frames.reading(false, 40, chunk), Screen);
        assert_eq!(frames.reading(false, 40, 5), Screen);
        assert_eq!(frames.reading(false, 45, 5), Live);
        // A live frame at another cursor ends it, and a frame at the first cursor after that is
        // live.
        let mut frames = Restoration::default();
        assert_eq!(frames.reading(true, 40, chunk), Screen);
        assert_eq!(frames.reading(false, 52, 5), Live);
        assert_eq!(frames.reading(false, 40, 5), Live);
        // The next subscription's first delivery begins a restoration again.
        assert_eq!(frames.reading(true, 90, 12), Screen);
    }

    /// The bound a restoration's frames are cut at is the worker's own.
    #[test]
    fn the_restoration_chunk_is_the_size_the_worker_cuts_its_frames_at() {
        assert_eq!(
            RESTORATION_CHUNK,
            kr_worker::service::MAX_OUTPUT_EVENT_BYTES
        );
    }

    /// A full reset of the terminal turns the mouse's modes off, however the write is cut, and what
    /// only ends in the same letter does not: a control sequence that ends in `c` asks a terminal
    /// what it is.
    #[test]
    fn a_full_reset_turns_the_modes_off_and_a_sequence_ending_in_c_does_not() {
        let set = b"\x1b[?1000h\x1b[?1002h\x1b[?1003h\x1b[?1006h";
        let reset = b"\x1bc";
        for cut in 0..=reset.len() {
            let mut reporting = MouseReporting::default();
            reporting.observe(set);
            reporting.observe(&reset[..cut]);
            reporting.observe(&reset[cut..]);
            assert_eq!(reporting.tracking(), Tracking::Off, "cut at {cut}");
            assert_eq!(
                reporting.encoding(),
                kr_keys::MouseEncoding::X10,
                "cut at {cut}"
            );
        }
        // The modes are asked for again after the reset, as an application that reset does.
        let mut reporting = MouseReporting::default();
        reporting.observe(set);
        reporting.observe(b"\x1bc\x1b[?1000h");
        assert_eq!(reporting.tracking(), Tracking::Clicks);
        assert_eq!(reporting.encoding(), kr_keys::MouseEncoding::X10);
        // A reset after an escape, or in the middle of a sequence the escape ends, is a reset.
        let mut reporting = MouseReporting::default();
        reporting.observe(set);
        reporting.observe(b"\x1b[?10\x1bc");
        assert_eq!(reporting.tracking(), Tracking::Off);
        // A control sequence that ends in `c` is a question, and changes nothing.
        for question in [&b"\x1b[c"[..], b"\x1b[>c", b"\x1b[0c", b"\x1b[=c"] {
            let mut reporting = MouseReporting::default();
            reporting.observe(set);
            reporting.observe(question);
            assert_eq!(reporting.tracking(), Tracking::Motion, "{question:?}");
            assert_eq!(
                reporting.encoding(),
                kr_keys::MouseEncoding::Sgr,
                "{question:?}"
            );
        }
    }

    /// What only looks like a mode setting is not one: a question about a mode, a sequence that is
    /// not private, another final byte, and a mode that is not the mouse's.
    #[test]
    fn what_only_looks_like_a_mode_setting_asks_for_nothing() {
        for output in [
            &b"\x1b[?1000$p"[..],
            b"\x1b[1000h",
            b"\x1b[?1000m",
            b"\x1b[?25h\x1b[?2004h",
            b"\x1b[>1000h",
            b"\x1b[?1000\x18h",
            b"\x1b]?1000h",
        ] {
            let mut reporting = MouseReporting::default();
            reporting.observe(output);
            assert_eq!(reporting.tracking(), Tracking::Off, "{output:?}");
        }
    }

    /// A press and its release are told at the cell, in the encoding the application chose.
    #[test]
    fn a_press_and_its_release_are_told_at_the_cell_in_the_encoding_asked_for() {
        let records = [
            record(2, 3, LEFT, 0),
            record(2, 3, 0, 0),
            record(5, 1, RIGHT, 0),
            record(5, 1, 0, 0),
        ];
        assert_eq!(
            told(b"\x1b[?1000h\x1b[?1006h", &records),
            b"\x1b[<0;3;4M\x1b[<0;3;4m\x1b[<2;6;2M\x1b[<2;6;2m".to_vec()
        );
        // The original report spells every release as button three.
        assert_eq!(
            told(b"\x1b[?1000h", &records[..2]),
            vec![0x1b, b'[', b'M', 32, 35, 36, 0x1b, b'[', b'M', 35, 35, 36]
        );
    }

    /// The window need not begin at the buffer's origin: a position is counted from where it does.
    #[test]
    fn a_position_is_counted_from_where_the_window_begins() {
        let mut reporting = MouseReporting::default();
        reporting.observe(b"\x1b[?1000h\x1b[?1006h");
        let mut speller = MouseSpeller::default();
        let window = Window {
            left: 10,
            top: 38,
            columns: 80,
            rows: 25,
        };
        assert_eq!(
            speller.spell(record(12, 40, LEFT, 0), &reporting, window),
            b"\x1b[<0;3;3M".to_vec()
        );
    }

    /// A record whose position is outside the window is told to nobody, and not as the nearest cell
    /// or the first row or column: only a position inside the window is a cell of the grid.
    #[test]
    fn a_position_outside_the_window_is_told_to_nobody() {
        let window = Window {
            left: 10,
            top: 38,
            columns: 80,
            rows: 25,
        };
        let mut reporting = MouseReporting::default();
        reporting.observe(b"\x1b[?1000h\x1b[?1006h");
        // Each is a press by a speller that has not seen one.
        let spelled = |column, row| {
            MouseSpeller::default().spell(record(column, row, LEFT, 0), &reporting, window)
        };
        // The first and the last cell of the window are inside it.
        assert_eq!(spelled(10, 38), b"\x1b[<0;1;1M".to_vec());
        assert_eq!(spelled(89, 62), b"\x1b[<0;80;25M".to_vec());
        // One cell beyond each edge is not, and neither is a position far off or negative.
        for (column, row) in [
            (9, 40),
            (12, 37),
            (90, 40),
            (12, 63),
            (-1, 40),
            (12, -1),
            (0, 0),
        ] {
            assert_eq!(
                spelled(column, row),
                Vec::<u8>::new(),
                "({column}, {row}) is outside the window"
            );
        }
    }

    /// A record told to nobody still tells the speller what it says: the buttons it holds down and
    /// the turn of the wheel, so that the next record inside the window is read against them.
    #[test]
    fn a_record_told_to_nobody_still_changes_the_buttons_and_the_wheel_the_speller_holds() {
        let window = Window {
            left: 10,
            top: 38,
            columns: 80,
            rows: 25,
        };
        let mut reporting = MouseReporting::default();
        reporting.observe(b"\x1b[?1000h\x1b[?1006h");
        let mut speller = MouseSpeller::default();
        let mut spelled = |record| speller.spell(record, &reporting, window);
        let wheel = |column, amount: i16| {
            record(
                column,
                40,
                u32::from(u16::from_ne_bytes(amount.to_ne_bytes())) << 16,
                MOUSE_WHEELED,
            )
        };
        // A button goes down inside the window and comes up outside it: the next press is a press.
        assert_eq!(spelled(record(12, 40, LEFT, 0)), b"\x1b[<0;3;3M".to_vec());
        assert!(
            spelled(record(9, 40, 0, 0)).is_empty(),
            "the release is outside"
        );
        assert_eq!(spelled(record(12, 40, LEFT, 0)), b"\x1b[<0;3;3M".to_vec());
        // A turn of the wheel outside the window is a notch that nobody is told of and is not kept.
        assert!(spelled(wheel(12, 60)).is_empty(), "half a notch inside");
        assert!(
            spelled(wheel(9, 60)).is_empty(),
            "the notch it makes is outside"
        );
        assert!(
            spelled(wheel(12, 60)).is_empty(),
            "half a notch again, not a notch"
        );
    }

    /// An application is told only of what it asked for: nothing before it asks, a move with a
    /// button held only from mode 1002, and a move with none only in mode 1003.
    #[test]
    fn an_application_is_told_only_of_the_events_it_asked_for() {
        let drag = record(1, 1, LEFT, MOUSE_MOVED);
        let hover = record(1, 1, 0, MOUSE_MOVED);
        let wheel = record(1, 1, 120 << 16, MOUSE_WHEELED);
        let press = record(1, 1, LEFT, 0);
        let all = [press, drag, hover, wheel];
        assert_eq!(told(b"", &all), Vec::<u8>::new(), "nothing was asked");
        assert_eq!(
            told(b"\x1b[?1000h\x1b[?1006h", &all),
            b"\x1b[<0;2;2M\x1b[<64;2;2M".to_vec(),
            "clicks and the wheel"
        );
        assert_eq!(
            told(b"\x1b[?1002h\x1b[?1006h", &all),
            b"\x1b[<0;2;2M\x1b[<32;2;2M\x1b[<64;2;2M".to_vec(),
            "and a move with a button held"
        );
        assert_eq!(
            told(b"\x1b[?1003h\x1b[?1006h", &all),
            b"\x1b[<0;2;2M\x1b[<32;2;2M\x1b[<35;2;2M\x1b[<64;2;2M".to_vec(),
            "and every move"
        );
    }

    /// The wheel is a wheel in the stream, a turn one way or the other, a notch at a time.
    #[test]
    fn the_wheel_is_told_a_notch_at_a_time_in_the_direction_it_turned() {
        let up = record(0, 0, 120 << 16, MOUSE_WHEELED);
        let down = record(0, 0, u32::from(0xff88_u16) << 16, MOUSE_WHEELED);
        let two_down = record(0, 0, u32::from(0xff10_u16) << 16, MOUSE_WHEELED);
        assert_eq!(
            told(b"\x1b[?1000h\x1b[?1006h", &[up, down, two_down]),
            b"\x1b[<64;1;1M\x1b[<65;1;1M\x1b[<65;1;1M\x1b[<65;1;1M".to_vec()
        );
    }

    /// A wheel that turns finely reports less than a notch at a time: a notch is told once the
    /// turns add up to one, the rest of a turn is kept for the next, and a turn the other way
    /// starts again.
    #[test]
    fn a_wheel_that_turns_less_than_a_notch_at_a_time_is_told_when_it_has_turned_one() {
        let up = |amount: i16| {
            record(
                0,
                0,
                u32::from(u16::from_ne_bytes(amount.to_ne_bytes())) << 16,
                MOUSE_WHEELED,
            )
        };
        let reporting = {
            let mut reporting = MouseReporting::default();
            reporting.observe(b"\x1b[?1000h\x1b[?1006h");
            reporting
        };
        let mut speller = MouseSpeller::default();
        let mut spelled = |record| speller.spell(record, &reporting, Window::UNBOUNDED);
        assert_eq!(spelled(up(60)), Vec::<u8>::new(), "half a notch");
        assert_eq!(
            spelled(up(60)),
            b"\x1b[<64;1;1M".to_vec(),
            "the second half"
        );
        assert_eq!(
            spelled(up(200)),
            b"\x1b[<64;1;1M".to_vec(),
            "a notch and 80 over"
        );
        assert_eq!(
            spelled(up(40)),
            b"\x1b[<64;1;1M".to_vec(),
            "the 80 and 40 more"
        );
        assert_eq!(spelled(up(100)), Vec::<u8>::new(), "100 of the next");
        assert_eq!(
            spelled(up(-60)),
            Vec::<u8>::new(),
            "the other way, where nothing of the turn before is left"
        );
        assert_eq!(spelled(up(-60)), b"\x1b[<65;1;1M".to_vec());
        // A record that turns nothing leaves the part of a notch as it was, whichever way it is.
        assert_eq!(spelled(up(60)), Vec::<u8>::new());
        assert_eq!(spelled(up(0)), Vec::<u8>::new());
        assert_eq!(spelled(up(60)), b"\x1b[<64;1;1M".to_vec());
        assert_eq!(spelled(up(-60)), Vec::<u8>::new());
        assert_eq!(spelled(up(0)), Vec::<u8>::new());
        assert_eq!(spelled(up(-60)), b"\x1b[<65;1;1M".to_vec());
    }

    /// A button that was down when the application stopped asking for the mouse is not known to be
    /// down when it asks again: the console said nothing of the release in between, so the next
    /// press is a press.
    #[test]
    fn a_button_let_go_of_while_the_mouse_was_not_asked_for_is_pressed_again_when_it_is() {
        let mut reporting = MouseReporting::default();
        reporting.observe(b"\x1b[?1000h\x1b[?1006h");
        let mut speller = MouseSpeller::default();
        assert_eq!(
            speller.spell(record(0, 0, LEFT, 0), &reporting, Window::UNBOUNDED),
            b"\x1b[<0;1;1M".to_vec()
        );
        speller.forget_the_buttons();
        assert_eq!(
            speller.spell(record(0, 0, LEFT, 0), &reporting, Window::UNBOUNDED),
            b"\x1b[<0;1;1M".to_vec()
        );
    }

    /// A button that goes down while another is held is told as its own press, the second press of
    /// a double click is a press, and the modifiers held come with the report.
    #[test]
    fn a_second_button_a_double_click_and_the_modifiers_are_told_as_they_are() {
        let mut reporting = MouseReporting::default();
        reporting.observe(b"\x1b[?1000h\x1b[?1006h");
        let mut speller = MouseSpeller::default();
        let mut spelled = |record| speller.spell(record, &reporting, Window::UNBOUNDED);
        assert_eq!(spelled(record(0, 0, LEFT, 0)), b"\x1b[<0;1;1M".to_vec());
        assert_eq!(
            spelled(record(0, 0, LEFT | MIDDLE, 0)),
            b"\x1b[<1;1;1M".to_vec(),
            "the middle button went down with the left one held"
        );
        assert_eq!(
            spelled(record(0, 0, 0, 0)),
            b"\x1b[<0;1;1m\x1b[<1;1;1m".to_vec()
        );
        assert_eq!(
            spelled(record(0, 0, LEFT, super::DOUBLE_CLICK)),
            b"\x1b[<0;1;1M".to_vec()
        );
        let held = MouseRecord {
            control_keys: 0x10 | 0x08,
            ..record(0, 0, 0, 0)
        };
        assert_eq!(spelled(held), b"\x1b[<20;1;1m".to_vec());
    }

    /// A position the original report has no room for is not told as another cell.
    #[test]
    fn a_position_the_original_report_has_no_room_for_is_not_told() {
        let far = [record(300, 2, LEFT, 0)];
        assert_eq!(told(b"\x1b[?1000h", &far), Vec::<u8>::new());
        assert_eq!(
            told(b"\x1b[?1000h\x1b[?1006h", &far),
            b"\x1b[<0;301;3M".to_vec(),
            "which the SGR encoding has"
        );
    }

    /// Typing inserts before the text that is there, a private flag of the console.
    const ENABLE_INSERT_MODE: u32 = 0x20;
    /// The cursor goes where typing continues, a private flag of the console.
    const ENABLE_AUTO_POSITION: u32 = 0x100;

    #[cfg(windows)]
    const _: () = {
        assert!(ENABLE_INSERT_MODE == windows_sys::Win32::System::Console::ENABLE_INSERT_MODE);
        assert!(ENABLE_AUTO_POSITION == windows_sys::Win32::System::Console::ENABLE_AUTO_POSITION);
    };

    /// The flags of the console's input mode that are private: set only through the extended flags,
    /// and reported only by a console that reports those.
    const PRIVATE_FLAGS: u32 =
        ENABLE_INSERT_MODE | ENABLE_QUICK_EDIT_MODE | ENABLE_EXTENDED_FLAGS | ENABLE_AUTO_POSITION;

    /// The mode a record reader reads in takes away what would have the console translate keys,
    /// read a line, show what is typed or handle the interrupt, whatever the console had.
    #[test]
    fn the_record_mode_never_asks_the_console_to_translate_for_us() {
        let saved = ENABLE_LINE_INPUT
            | ENABLE_ECHO_INPUT
            | ENABLE_PROCESSED_INPUT
            | ENABLE_VIRTUAL_TERMINAL_INPUT
            | ENABLE_MOUSE_INPUT
            | ENABLE_WINDOW_INPUT;
        let mode = record_input_mode(saved);
        assert_eq!(
            mode & ENABLE_VIRTUAL_TERMINAL_INPUT,
            0,
            "the console's own translation is what records exist to avoid"
        );
        assert_eq!(mode & (ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT), 0);
        assert_eq!(
            mode & (ENABLE_MOUSE_INPUT | ENABLE_WINDOW_INPUT),
            0,
            "no mouse or window-size record is asked for until the application asks for the mouse"
        );
        assert_eq!(
            mode & ENABLE_PROCESSED_INPUT,
            0,
            "the interrupt key is input to forward rather than an event for this process"
        );
    }

    /// The modes an attachment writes to a console, in order: when it begins, when the application
    /// asks for the mouse, when it stops, and the console's own mode put back at the end.
    fn written(attached: u32, spelling: bool) -> [u32; 4] {
        let records = record_input_mode(attached);
        let begun = if spelling {
            keys_spelled_mode(records, attached, false, true)
        } else {
            records
        };
        let asked = mouse_input_mode(begun, attached, true);
        let stopped = mouse_input_mode(asked, attached, false);
        [begun, asked, stopped, attached]
    }

    /// A console that reports its private flags (the native console's mode was 0x1f7) is given the
    /// mouse by removing quick edit under the extended flags, and gets quick edit back.
    #[test]
    fn a_console_that_reports_its_private_flags_has_quick_edit_taken_while_the_mouse_is_asked_for()
    {
        let attached = 0x1f7;
        assert_eq!(
            written(attached, false),
            [0x1e0, 0x1b0, 0x1e0, 0x1f7],
            "begun, asked, stopped and put back"
        );
        // Quick edit that was off is not turned on, and the keys the console spells stay spelled.
        let without = attached & !ENABLE_QUICK_EDIT_MODE;
        assert_eq!(written(without, false), [0x1a0, 0x1b0, 0x1a0, 0x1b7]);
        assert_eq!(
            written(attached, true),
            [0x3f0, 0x3b0, 0x3f0, 0x1f7],
            "the console that spells its keys goes on spelling them, with the mouse flag it had"
        );
    }

    /// A console whose mode has no extended flags reports none of its private flags, and the
    /// attachment writes none of them: asking sets the mouse flag alone, whatever the console
    /// holds that it did not report.
    #[test]
    fn a_console_that_reports_no_private_flag_is_given_no_private_flag_at_any_step() {
        let attached = ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT;
        assert_eq!(written(attached, false), [0, 0x10, 0, 0x7]);
        assert_eq!(
            written(attached, true),
            [0x200, 0x210, 0x200, 0x7],
            "the console that spells its keys goes on spelling them"
        );
        for (spelling, steps) in [
            (false, written(attached, false)),
            (true, written(attached, true)),
        ] {
            for (step, mode) in steps.into_iter().enumerate() {
                assert_eq!(
                    mode & PRIVATE_FLAGS,
                    0,
                    "step {step}, spelling {spelling}: a private flag is written"
                );
            }
        }
        // Flags the console holds without having reported them are neither set nor cleared.
        let held = ENABLE_QUICK_EDIT_MODE | ENABLE_INSERT_MODE | ENABLE_AUTO_POSITION;
        let asked = mouse_input_mode(held, attached, true);
        assert_eq!(asked, held | ENABLE_MOUSE_INPUT);
        assert_eq!(mouse_input_mode(asked, attached, false), held);
    }

    /// The application's bracketed paste is read from its output as its mouse is: set and reset,
    /// among the other modes of one sequence, in a sequence that arrives in two writes, and off
    /// after a full reset of the terminal.
    #[test]
    fn the_applications_bracketed_paste_is_read_from_its_output() {
        let mut reporting = MouseReporting::default();
        assert!(!reporting.bracketed_paste(), "a terminal begins with none");
        reporting.observe(b"text\x1b[?2004h");
        assert!(reporting.bracketed_paste());
        reporting.observe(b"\x1b[?2004l");
        assert!(!reporting.bracketed_paste());
        reporting.observe(b"\x1b[?25l\x1b[?1000;2004h");
        assert!(
            reporting.bracketed_paste(),
            "among the modes of one sequence"
        );
        reporting.observe(b"\x1b[?20");
        reporting.observe(b"04l");
        assert!(
            !reporting.bracketed_paste(),
            "a sequence that arrives in two writes"
        );
        reporting.observe(b"\x1b[?2004h\x1bc");
        assert!(!reporting.bracketed_paste(), "a full reset turns it off");
    }

    /// A screen drawn for this terminal states the application's bracketed paste as live output
    /// does, and reading it writes nothing after it.
    #[test]
    fn a_screen_the_session_drew_states_bracketed_paste_as_live_output_does() {
        for reading in [Reading::Live, Reading::Restoration, Reading::Painted] {
            let mut reporting = MouseReporting::default();
            assert!(reporting.read(b"\x1b[?2004h", reading).is_empty());
            assert!(reporting.bracketed_paste(), "set, read as {reading:?}");
            assert!(reporting.read(b"\x1b[?2004l", reading).is_empty());
            assert!(!reporting.bracketed_paste(), "reset, read as {reading:?}");
        }
    }

    /// Asking the console to spell the keys itself sets its virtual-terminal flag and gives the
    /// mouse and window flags the console had when the attachment began, and changes no other flag.
    /// Giving the keys back as records restores exactly the mode there was, and the application's
    /// stopping to ask for the mouse while the keys are spelled leaves the mouse flag as the console
    /// had it.
    #[test]
    fn spelling_the_keys_keeps_the_mouse_and_window_flags_as_they_were_and_giving_them_back_restores_the_mode()
     {
        const KEPT: u32 = ENABLE_MOUSE_INPUT | ENABLE_WINDOW_INPUT;
        for attached in [
            0x1f7_u32,
            0x1a7,
            0x7,
            0x18,
            ENABLE_WINDOW_INPUT,
            ENABLE_MOUSE_INPUT,
            ENABLE_QUICK_EDIT_MODE | ENABLE_EXTENDED_FLAGS,
        ] {
            let records = record_input_mode(attached);
            let mouse = mouse_input_mode(records, attached, true);
            for (current, asked) in [(records, false), (mouse, true)] {
                let spelled = keys_spelled_mode(current, attached, asked, true);
                let context = format!("attached {attached:#x}, current {current:#x}");
                assert_ne!(spelled & ENABLE_VIRTUAL_TERMINAL_INPUT, 0, "{context}");
                assert_eq!(
                    spelled & KEPT,
                    (current | attached) & KEPT,
                    "the two flags are as the console had them, or as the mouse asked: {context}"
                );
                assert_eq!(
                    spelled & !(ENABLE_VIRTUAL_TERMINAL_INPUT | KEPT),
                    current & !(ENABLE_VIRTUAL_TERMINAL_INPUT | KEPT),
                    "no other flag changes: {context}"
                );
                assert_eq!(
                    keys_spelled_mode(spelled, attached, asked, false),
                    current,
                    "{context}"
                );
                assert_eq!(
                    keys_spelled_mode(current, attached, asked, false),
                    current,
                    "{context}"
                );
            }
            // The application stops asking for the mouse while the keys are spelled: the console
            // is as it was when it began to spell, not as the mouse's flag alone would leave it.
            let asked_and_spelled = keys_spelled_mode(mouse, attached, true, true);
            assert_eq!(
                mouse_input_mode(asked_and_spelled, attached, false),
                keys_spelled_mode(records, attached, false, true),
                "attached {attached:#x}"
            );
        }
    }

    /// The mode a console that spells its keys is given, for the console's usual mode and for one
    /// that had neither the mouse nor the window flag: the virtual-terminal flag on, line, echo and
    /// processed input off, and the two flags as the console had them. A mode is read as saying
    /// whether the keys are spelled by its virtual-terminal flag alone.
    #[test]
    fn a_console_asked_to_spell_its_keys_is_given_the_mode_of_a_command_that_reads_bytes() {
        // The console's usual mode has the mouse flag and not the window flag.
        assert_eq!(record_input_mode(0x1f7), 0x1e0);
        assert_eq!(keys_spelled_mode(0x1e0, 0x1f7, false, true), 0x3f0);
        assert_eq!(keys_spelled_mode(0x1e0, 0x1ff, false, true), 0x3f8);
        assert_eq!(keys_spelled_mode(0x1e0, 0x1e7, false, true), 0x3e0);
        assert_eq!(keys_spelled_mode(0x3f8, 0x1ff, false, false), 0x1e0);
        assert_eq!(keys_spelled_mode(0x3f0, 0x1f7, true, false), 0x1f0);
        assert!(keys_are_spelled(0x3f0));
        assert!(!keys_are_spelled(0x1e0));
        assert!(!keys_are_spelled(0));
    }

    /// What an application that wrote `asked` is told of the text `input`, which a console spelled:
    /// the reports in it as the application asked for them, and the rest as it is.
    fn told_of_text(asked: &[u8], input: &[u8]) -> Vec<u8> {
        let mut reporting = MouseReporting::default();
        reporting.observe(asked);
        let mut filter = SgrMouseFilter::default();
        let mut told = Vec::new();
        for part in filter.push(input) {
            match part {
                Part::Text(text) => told.extend(text),
                Part::Report(event) => told.extend(MouseSpeller::report(event, &reporting)),
            }
        }
        told.extend(filter.flush());
        told
    }

    /// The original report of `code` at `column` and `row`, counted from one.
    fn original(code: u8, column: u8, row: u8) -> Vec<u8> {
        vec![0x1b, b'[', b'M', 32 + code, 32 + column, 32 + row]
    }

    /// Each report the console spells is told as the application asked for it: the events of its
    /// tracking level, in its encoding, and nothing the level has no place for.
    #[test]
    fn a_report_the_console_spelled_is_told_in_the_tracking_and_encoding_the_application_asked_for()
    {
        let press = b"\x1b[<0;2;2M".as_slice();
        let release = b"\x1b[<0;2;2m".as_slice();
        let drag = b"\x1b[<32;2;2M".as_slice();
        let motion = b"\x1b[<35;2;2M".as_slice();
        let up = b"\x1b[<64;2;2M".as_slice();
        let down = b"\x1b[<65;2;2M".as_slice();
        let all = [press, release, drag, motion, up, down].concat();
        assert_eq!(
            told_of_text(b"", &all),
            Vec::<u8>::new(),
            "nothing was asked"
        );
        assert_eq!(
            told_of_text(b"\x1b[?1000h\x1b[?1006h", &all),
            [press, release, up, down].concat(),
            "1000 and SGR: clicks and the wheel"
        );
        assert_eq!(
            told_of_text(b"\x1b[?1002h\x1b[?1006h", &all),
            [press, release, drag, up, down].concat(),
            "1002 and SGR: and a move with a button held"
        );
        assert_eq!(
            told_of_text(b"\x1b[?1003h\x1b[?1006h", &all),
            all,
            "1003 and SGR: and every move"
        );
        let original_encoding = [
            original(0, 2, 2),
            original(3, 2, 2),
            original(64, 2, 2),
            original(65, 2, 2),
        ]
        .concat();
        assert_eq!(
            told_of_text(b"\x1b[?1000h", &all),
            original_encoding,
            "1000 alone: the original report, which has no release of a button"
        );
        assert_eq!(
            told_of_text(b"\x1b[?1000h\x1b[?1005h", &all),
            original_encoding,
            "1005 asks for the original report's bytes"
        );
        assert_eq!(
            told_of_text(b"\x1b[?1000h\x1b[?1006h", b"\x1b[<20;2;2M"),
            b"\x1b[<20;2;2M".to_vec(),
            "Shift and Control held are told"
        );
        let record_told = told(
            b"\x1b[?1000h\x1b[?1006h",
            &[record(1, 1, LEFT, 0), record(1, 1, 0, 0)],
        );
        assert_eq!(
            told_of_text(b"\x1b[?1000h\x1b[?1006h", &[press, release].concat()),
            record_told,
            "a report and a record of the same events are told the same"
        );
    }

    /// A report whose bytes come in two reads, cut anywhere, is the one report, and the text on
    /// either side of it is the text.
    #[test]
    fn a_report_cut_across_two_reads_is_one_report() {
        let whole = b"ab\x1b[<0;10;5Mcd".as_slice();
        let mut once = SgrMouseFilter::default();
        let expected: Vec<Part> = once.push(whole);
        assert_eq!(expected.len(), 3, "text, report, text: {expected:?}");
        for cut in 0..=whole.len() {
            let mut filter = SgrMouseFilter::default();
            let mut parts = filter.push(&whole[..cut]);
            parts.extend(filter.push(&whole[cut..]));
            let mut text = Vec::new();
            let mut reports = Vec::new();
            for part in parts {
                match part {
                    Part::Text(bytes) => text.extend(bytes),
                    Part::Report(event) => reports.push(event),
                }
            }
            assert_eq!(text, b"abcd".to_vec(), "cut at {cut}");
            assert_eq!(reports.len(), 1, "cut at {cut}");
            assert!(!filter.holds(), "cut at {cut}");
        }
    }

    /// Bytes that begin a report and are not one are text, in their place, and a lone escape is
    /// text once nothing more comes.
    #[test]
    fn bytes_that_begin_a_report_and_are_not_one_are_text_in_their_place() {
        let text = |input: &[u8]| {
            let mut filter = SgrMouseFilter::default();
            let mut parts = filter.push(input);
            let held = filter.flush();
            if !held.is_empty() {
                parts.push(Part::Text(held));
            }
            parts
                .into_iter()
                .map(|part| match part {
                    Part::Text(bytes) => bytes,
                    Part::Report(event) => panic!("{input:?} was read as {event:?}"),
                })
                .collect::<Vec<_>>()
                .concat()
        };
        for input in [
            b"\x1b[A".as_slice(),
            b"\x1bx",
            b"\x1b",
            b"\x1b[",
            b"\x1b[<",
            b"\x1b[<0;1",
            b"\x1b[<0;x;1M",
            b"\x1b[<0;1;1X",
            b"\x1b[<1234;1;1M",
            b"\x1b[<0;123456;1M",
            b"\x1b[<;1;1M",
            b"\x1b[<0;;1M",
            b"\x1b\x1b[A",
        ] {
            assert_eq!(text(input), input.to_vec(), "{input:?}");
        }
        let mut filter = SgrMouseFilter::default();
        assert!(filter.push(b"\x1b").is_empty());
        assert!(filter.holds(), "a lone escape is held");
        assert_eq!(filter.flush(), b"\x1b".to_vec());
        assert!(!filter.holds());
        let mut filter = SgrMouseFilter::default();
        let parts = filter.push(b"\x1b\x1b[<0;1;1M");
        assert_eq!(parts.len(), 2, "{parts:?}");
        assert_eq!(parts[0], Part::Text(b"\x1b".to_vec()));
        assert!(matches!(parts[1], Part::Report(_)), "{parts:?}");
    }

    /// A report that tells of nothing an application can be told is taken out and told to nobody.
    #[test]
    fn a_report_that_tells_of_nothing_is_taken_out_and_told_to_nobody() {
        for input in [
            b"\x1b[<0;0;5M".as_slice(),
            b"\x1b[<0;5;0M",
            b"\x1b[<66;1;1M",
            b"\x1b[<64;1;1m",
            b"\x1b[<3;1;1M",
            b"\x1b[<128;1;1M",
        ] {
            let mut filter = SgrMouseFilter::default();
            assert!(filter.push(input).is_empty(), "{input:?}");
            assert!(!filter.holds(), "{input:?}");
        }
    }

    /// Between the markers of a bracketed paste nothing is a report, so a pasted text that holds
    /// one is given to the application as text, and the markers, cut anywhere, are text.
    #[test]
    fn a_paste_is_text_whatever_it_holds_and_its_markers_are_not_reports() {
        let asked = b"\x1b[?1000h\x1b[?1006h";
        let pasted = b"\x1b[200~12\x1b[<0;1;1M\x1b[A\x1b[201~".as_slice();
        assert_eq!(told_of_text(asked, pasted), pasted.to_vec());
        for cut in 0..=pasted.len() {
            let mut filter = SgrMouseFilter::default();
            let mut parts = filter.push(&pasted[..cut]);
            parts.extend(filter.push(&pasted[cut..]));
            parts.push(Part::Text(filter.flush()));
            let told: Vec<u8> = parts
                .into_iter()
                .flat_map(|part| match part {
                    Part::Text(bytes) => bytes,
                    Part::Report(event) => panic!("cut at {cut}: {event:?}"),
                })
                .collect();
            assert_eq!(told, pasted.to_vec(), "cut at {cut}");
        }
        assert_eq!(
            told_of_text(asked, b"\x1b[<0;1;1M\x1b[200~12\x1b[201~\x1b[<0;1;1mZ"),
            b"\x1b[<0;1;1M\x1b[200~12\x1b[201~\x1b[<0;1;1mZ".to_vec(),
            "a report before, a paste, a report after and a letter, with the mouse asked for"
        );
        assert_eq!(
            told_of_text(b"", b"\x1b[<0;1;1M\x1b[200~12\x1b[201~\x1b[<0;1;1mZ"),
            b"\x1b[200~12\x1b[201~Z".to_vec(),
            "the reports are told to nobody when nothing was asked, and the paste is whole"
        );
    }
}
