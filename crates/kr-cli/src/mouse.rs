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
//! [`kr_keys::mouse`] has it, rather than reported as another cell.

use kr_keys::{Modifiers, MouseAction, MouseButton, MouseEncoding, MouseEvent, WheelDirection};
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

/// How many parameters of one sequence are kept. A sequence with more is no mode setting this
/// reads.
const PARAMETERS_KEPT: usize = 32;

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

/// What the session's application has asked for of the mouse, learned from what the session wrote.
///
/// It reads the output as a terminal reads it, a byte at a time, so a mode setting cut in two
/// between one write and the next is read whole.
///
/// The three tracking modes are three settings of their own, as the session's screen keeps them,
/// and what the application asked for is the widest of those that are set. A frame drawn from the
/// screen writes every mode it tracks, the ones that are off among them, so a mode that is reset
/// says nothing of the others.
#[derive(Debug, Default)]
pub struct MouseReporting {
    clicks: bool,
    drag: bool,
    motion: bool,
    sgr: bool,
    scan: Scan,
}

/// Where the reading of the output is.
#[derive(Debug, Default)]
enum Scan {
    /// Outside a sequence.
    #[default]
    Ground,
    /// After an escape.
    Escape,
    /// Inside a control sequence.
    Control(Control),
}

/// A control sequence being read.
#[derive(Debug, Default)]
struct Control {
    /// Whether the first byte after the opening was `?`.
    private: bool,
    /// Whether a byte came that makes the sequence something other than a mode setting.
    other: bool,
    /// Whether any byte after the opening has been read.
    started: bool,
    /// The parameters read, not counting the one being read.
    parameters: Vec<u32>,
    /// The parameter being read.
    number: Option<u32>,
}

impl Control {
    /// Closes the parameter being read, an empty one as zero.
    fn close_number(&mut self) {
        let number = self.number.take().unwrap_or(0);
        if self.parameters.len() < PARAMETERS_KEPT {
            self.parameters.push(number);
        } else {
            self.other = true;
        }
    }
}

impl MouseReporting {
    /// Reads output the session wrote, which is what the console is shown.
    pub fn observe(&mut self, output: &[u8]) {
        for &byte in output {
            self.step(byte);
        }
    }

    /// What the application asked to be told of the mouse.
    #[must_use]
    pub const fn tracking(&self) -> Tracking {
        if self.motion {
            Tracking::Motion
        } else if self.drag {
            Tracking::Drag
        } else if self.clicks {
            Tracking::Clicks
        } else {
            Tracking::Off
        }
    }

    /// The encoding the application asked for.
    #[must_use]
    pub const fn encoding(&self) -> MouseEncoding {
        if self.sgr {
            MouseEncoding::Sgr
        } else {
            MouseEncoding::X10
        }
    }

    fn step(&mut self, byte: u8) {
        self.scan = match std::mem::take(&mut self.scan) {
            Scan::Ground => {
                if byte == 0x1b {
                    Scan::Escape
                } else {
                    Scan::Ground
                }
            }
            Scan::Escape => match byte {
                b'[' => Scan::Control(Control::default()),
                0x1b => Scan::Escape,
                _ => Scan::Ground,
            },
            Scan::Control(mut control) => match byte {
                0x1b => Scan::Escape,
                // Cancel and substitute end a sequence without finishing it.
                0x18 | 0x1a => Scan::Ground,
                // The other controls act where they stand and are no part of the sequence.
                0x00..=0x1f | 0x7f => Scan::Control(control),
                b'?' if !control.started => {
                    control.private = true;
                    control.started = true;
                    Scan::Control(control)
                }
                b'0'..=b'9' => {
                    control.started = true;
                    let digit = u32::from(byte - b'0');
                    control.number = Some(
                        control
                            .number
                            .unwrap_or(0)
                            .saturating_mul(10)
                            .saturating_add(digit),
                    );
                    Scan::Control(control)
                }
                b';' => {
                    control.started = true;
                    control.close_number();
                    Scan::Control(control)
                }
                // Intermediates, and the markers of other kinds of sequence.
                0x20..=0x2f | 0x3a | 0x3c..=0x3f => {
                    control.started = true;
                    control.other = true;
                    Scan::Control(control)
                }
                0x40..=0x7e => {
                    if control.number.is_some() || control.started {
                        control.close_number();
                    }
                    self.apply(&control, byte);
                    Scan::Ground
                }
                _ => Scan::Ground,
            },
        };
    }

    /// Applies a finished control sequence: the setting and resetting of the modes that ask for the
    /// mouse, and nothing else.
    fn apply(&mut self, control: &Control, last: u8) {
        if !control.private || control.other || !matches!(last, b'h' | b'l') {
            return;
        }
        let set = last == b'h';
        for &mode in &control.parameters {
            match mode {
                1000 => self.clicks = set,
                1002 => self.drag = set,
                1003 => self.motion = set,
                1006 => self.sgr = set,
                _ => {}
            }
        }
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
    /// `origin` is the column and row of the console's screen buffer where its window begins, which
    /// a record's position is counted from and a report's is not. The buttons the record says are
    /// down are remembered whether or not anything is reported.
    pub fn spell(
        &mut self,
        record: MouseRecord,
        reporting: &MouseReporting,
        origin: (i16, i16),
    ) -> Vec<u8> {
        let modifiers = Modifiers {
            shift: record.control_keys & SHIFT_PRESSED != 0,
            alt: record.control_keys & (LEFT_ALT_PRESSED | RIGHT_ALT_PRESSED) != 0,
            control: record.control_keys & (LEFT_CTRL_PRESSED | RIGHT_CTRL_PRESSED) != 0,
            superkey: false,
        };
        let cell = |position: i16, from: i16| {
            u32::try_from(i32::from(position) - i32::from(from)).unwrap_or(0)
        };
        let (column, row) = (cell(record.column, origin.0), cell(record.row, origin.1));
        let mut report = Vec::new();
        for action in self.actions(record) {
            let asked = match action {
                MouseAction::Press(_) | MouseAction::Release(_) | MouseAction::Wheel(_) => {
                    Tracking::Clicks
                }
                MouseAction::Drag(_) => Tracking::Drag,
                MouseAction::Motion => Tracking::Motion,
            };
            if reporting.tracking() < asked {
                continue;
            }
            let event = MouseEvent {
                action,
                column,
                row,
                modifiers,
            };
            // A position the encoding has no room for is not told to the application as another.
            if let Ok(bytes) = kr_keys::mouse(event, reporting.encoding()) {
                report.extend_from_slice(&bytes);
            }
        }
        report
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
    use windows_sys::Win32::System::Console as system;

    assert!(ENABLE_PROCESSED_INPUT == system::ENABLE_PROCESSED_INPUT);
    assert!(ENABLE_LINE_INPUT == system::ENABLE_LINE_INPUT);
    assert!(ENABLE_ECHO_INPUT == system::ENABLE_ECHO_INPUT);
    assert!(ENABLE_WINDOW_INPUT == system::ENABLE_WINDOW_INPUT);
    assert!(ENABLE_MOUSE_INPUT == system::ENABLE_MOUSE_INPUT);
    assert!(ENABLE_QUICK_EDIT_MODE == system::ENABLE_QUICK_EDIT_MODE);
    assert!(ENABLE_EXTENDED_FLAGS == system::ENABLE_EXTENDED_FLAGS);
    assert!(ENABLE_VIRTUAL_TERMINAL_INPUT == system::ENABLE_VIRTUAL_TERMINAL_INPUT);
};

/// The console input mode a record reader needs, made from `saved`, the mode the console had.
///
/// `ENABLE_VIRTUAL_TERMINAL_INPUT` is deliberately absent: it is the console translating records
/// into VT sequences, which is the translation this path exists to avoid. Line input, echo and
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
/// them.
///
/// A console whose mode had no `ENABLE_EXTENDED_FLAGS` reports none of its private flags, whatever
/// they are, and a mode that sets the extended flags sets each of them as that mode states it: the
/// attachment would turn off insert mode and auto position, and quick edit it never learned was on,
/// and the restored mode, which has no extended flags, could not turn them on again. So on such a
/// console no private flag is written at any step: asking sets `ENABLE_MOUSE_INPUT` alone and
/// stopping clears it. The console then reports the mouse as records only while quick edit is off.
#[must_use]
pub const fn mouse_input_mode(current: u32, attached: u32, asked: bool) -> u32 {
    if attached & ENABLE_EXTENDED_FLAGS == 0 {
        return if asked {
            current | ENABLE_MOUSE_INPUT
        } else {
            current & !ENABLE_MOUSE_INPUT
        };
    }
    if asked {
        (current | ENABLE_MOUSE_INPUT | ENABLE_EXTENDED_FLAGS) & !ENABLE_QUICK_EDIT_MODE
    } else {
        (current & !(ENABLE_MOUSE_INPUT | ENABLE_QUICK_EDIT_MODE))
            | (attached & ENABLE_QUICK_EDIT_MODE)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ENABLE_ECHO_INPUT, ENABLE_EXTENDED_FLAGS, ENABLE_LINE_INPUT, ENABLE_MOUSE_INPUT,
        ENABLE_PROCESSED_INPUT, ENABLE_QUICK_EDIT_MODE, ENABLE_VIRTUAL_TERMINAL_INPUT, LEFT,
        MIDDLE, MOUSE_MOVED, MOUSE_WHEELED, MouseRecord, MouseReporting, MouseSpeller, RIGHT,
        Tracking, mouse_input_mode, record_input_mode,
    };

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
            .flat_map(|record| speller.spell(*record, &reporting, (0, 0)))
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
            (b"\x1b[?1003l", Tracking::Drag),
            (b"\x1b[?1000h", Tracking::Drag),
            (b"\x1b[?1002l", Tracking::Clicks),
            (b"\x1b[?1000l", Tracking::Off),
        ] {
            reporting.observe(output);
            assert_eq!(reporting.tracking(), tracking, "{output:?}");
        }
        reporting.observe(b"\x1b[?1006h");
        assert_eq!(reporting.encoding(), kr_keys::MouseEncoding::Sgr);
        reporting.observe(b"\x1b[?1006l");
        assert_eq!(reporting.encoding(), kr_keys::MouseEncoding::X10);
    }

    /// A frame drawn from the session's screen writes every mouse mode it tracks, the ones that are
    /// off after the one that is on, and the application has still asked for what it set.
    #[test]
    fn a_mode_that_is_reset_after_one_that_is_set_leaves_what_was_asked_for() {
        let mut reporting = MouseReporting::default();
        reporting.observe(b"\x1b[?1000h\x1b[?1002l\x1b[?1003l\x1b[?1006h\x1b[?2004l");
        assert_eq!(reporting.tracking(), Tracking::Clicks);
        assert_eq!(reporting.encoding(), kr_keys::MouseEncoding::Sgr);
        reporting.observe(b"\x1b[?1000l\x1b[?1002h\x1b[?1003l");
        assert_eq!(reporting.tracking(), Tracking::Drag);
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
        assert_eq!(
            speller.spell(record(12, 40, LEFT, 0), &reporting, (10, 38)),
            b"\x1b[<0;3;3M".to_vec()
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
        let mut spelled = |record| speller.spell(record, &reporting, (0, 0));
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
            speller.spell(record(0, 0, LEFT, 0), &reporting, (0, 0)),
            b"\x1b[<0;1;1M".to_vec()
        );
        speller.forget_the_buttons();
        assert_eq!(
            speller.spell(record(0, 0, LEFT, 0), &reporting, (0, 0)),
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
        let mut spelled = |record| speller.spell(record, &reporting, (0, 0));
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
        use windows_sys::Win32::System::Console as system;

        assert!(ENABLE_INSERT_MODE == system::ENABLE_INSERT_MODE);
        assert!(ENABLE_AUTO_POSITION == system::ENABLE_AUTO_POSITION);
    };

    /// The flags of the console's input mode that are private: set only through the extended flags,
    /// and reported only by a console that reports those.
    const PRIVATE_FLAGS: u32 =
        ENABLE_INSERT_MODE | ENABLE_QUICK_EDIT_MODE | ENABLE_EXTENDED_FLAGS | ENABLE_AUTO_POSITION;

    /// The modes an attachment writes to a console, in order: when it begins, when the application
    /// asks for the mouse, when it stops, and the console's own mode put back at the end.
    fn written(attached: u32, spelling: bool) -> [u32; 4] {
        let begun = record_input_mode(attached)
            | if spelling {
                ENABLE_VIRTUAL_TERMINAL_INPUT
            } else {
                0
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
            [0x3e0, 0x3b0, 0x3e0, 0x1f7],
            "the console that spells its keys goes on spelling them"
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
}
