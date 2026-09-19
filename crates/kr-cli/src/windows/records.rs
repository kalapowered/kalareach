//! Reading console key records, and sending them as the encoding the backend asked for.
//!
//! `ReadConsoleInputW` is the only way to see what a Windows console actually received. The
//! alternative, reading the console as a stream of bytes with `ENABLE_VIRTUAL_TERMINAL_INPUT`, is
//! the console translating those records into VT sequences for you, and the translation is lossy
//! in exactly the places section 8 names: a key coming up has no sequence at all, a repeat count
//! becomes several copies, a surrogate pair becomes whatever the translation made of it, and the
//! scan code is simply gone.
//!
//! What this module does **not** do is invent anything. A record is read, its six fields are
//! carried into [`kr_term::win32::KeyRecord`] unchanged, and the encoder writes them out. There is
//! no path here that decodes a record into a character and encodes that character again with a
//! scan code this host chose: section 8 forbids it, and a remote application that tracks the
//! keyboard itself would be told a key was pressed that nobody pressed.
//!
//! **Which path is used is the session's decision, not this command's.** The worker records what
//! its owned backend asked for, and a client is told which encoding to send. A client that cannot
//! read records, or a session whose backend never asked for them, sends legacy VT input, which is
//! accepted without any claim about scan codes.

#![expect(
    unsafe_code,
    reason = "reading console input records has no safe interface"
)]

use std::os::windows::io::AsRawHandle as _;

use kr_term::win32::{Fidelity, KeyRecord, control_keys, encode_all};
use windows_sys::Win32::System::Console::{
    ENABLE_MOUSE_INPUT, ENABLE_WINDOW_INPUT, GetNumberOfConsoleInputEvents, INPUT_RECORD,
    KEY_EVENT, MOUSE_EVENT, ReadConsoleInputW, WINDOW_BUFFER_SIZE_EVENT,
};

use crate::error::{CliError, Result};

/// How many records one read asks the console for.
///
/// A held key, a paste and an IME commit all arrive as runs of records, so a read that asked for
/// one at a time would make a system call per keystroke of a paste.
const BATCH: usize = 256;

/// The console input this attachment reads, and the encoding it sends.
#[derive(Debug)]
pub struct RecordReader {
    handle: std::fs::File,
    fidelity: Fidelity,
    /// A high surrogate whose low half has not arrived.
    ///
    /// One read of the console can end between the two halves of a character outside the basic
    /// plane, and decoding each read on its own would turn that character into two replacements.
    /// It is held here until the read that completes it.
    pending_high_surrogate: Option<u16>,
}

impl RecordReader {
    /// Opens the console's input for reading records.
    ///
    /// `records` is what the session said its backend asked for. A client told to send legacy VT
    /// input still reads records here - it is the only way to read this console without the
    /// console's own translation - but it reports the fidelity it is actually sending, which is
    /// the legacy path.
    #[must_use]
    pub const fn over(handle: std::fs::File, records: bool) -> Self {
        Self {
            handle,
            fidelity: if records {
                Fidelity::Records
            } else {
                Fidelity::LegacyVt
            },
            pending_high_surrogate: None,
        }
    }

    /// Returns what this reader can honestly say about the input it is sending.
    #[must_use]
    pub const fn fidelity(&self) -> Fidelity {
        self.fidelity
    }

    /// Returns how many events are waiting, without taking any.
    ///
    /// # Errors
    ///
    /// Returns an error when the console will not answer.
    pub fn waiting(&self) -> Result<u32> {
        let mut count = 0_u32;
        // SAFETY: the handle is this reader's own and open for the call, and the count is a local
        // this thread owns.
        let asked = unsafe {
            GetNumberOfConsoleInputEvents(self.handle.as_raw_handle().cast(), &raw mut count)
        };
        if asked == 0 {
            return Err(CliError::Terminal(format!(
                "read the console's input: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(count)
    }

    /// Reads the records the console has, waiting for at least one.
    ///
    /// Every record, in the order the console reported it. A resize, a mouse event and a focus
    /// change are each their own operation in this protocol, so each keeps the detail its dispatch
    /// needs and its place in the order; none of them belongs in a key encoding.
    ///
    /// # Errors
    ///
    /// Returns an error when the console will not answer.
    pub fn read(&mut self) -> Result<Vec<ConsoleEvent>> {
        // SAFETY: an `INPUT_RECORD` is a tagged union of plain integers, and all zeroes is a
        // record of event type zero, which this never reads as a key event.
        let mut buffer: [INPUT_RECORD; BATCH] = unsafe { std::mem::zeroed() };
        let mut read = 0_u32;
        // SAFETY: the handle is this reader's own and open for the call. The buffer is a local
        // this thread owns and the count it is given is its own length; the number read is another
        // local.
        let ok = unsafe {
            ReadConsoleInputW(
                self.handle.as_raw_handle().cast(),
                buffer.as_mut_ptr(),
                u32::try_from(buffer.len()).unwrap_or(1),
                &raw mut read,
            )
        };
        if ok == 0 {
            return Err(CliError::Terminal(format!(
                "read the console's input: {}",
                std::io::Error::last_os_error()
            )));
        }
        let read = usize::try_from(read).unwrap_or(0).min(buffer.len());
        let mut events = Vec::with_capacity(read);
        for record in &buffer[..read] {
            events.push(match u32::from(record.EventType) {
                KEY_EVENT => {
                    // SAFETY: the console reported this record as a key event, which is the field
                    // of the union that is then live.
                    let key = unsafe { record.Event.KeyEvent };
                    ConsoleEvent::Key(KeyRecord {
                        virtual_key: key.wVirtualKeyCode,
                        scan_code: key.wVirtualScanCode,
                        // The character the console produced, read as the UTF-16 code unit it is.
                        // A surrogate pair is two records and stays two records.
                        //
                        // SAFETY: both arms of this union are the same two bytes, and reading them
                        // as the wide character is what `ReadConsoleInputW` produces.
                        unicode: unsafe { key.uChar.UnicodeChar },
                        key_down: key.bKeyDown != 0,
                        control_keys: key.dwControlKeyState,
                        repeat: key.wRepeatCount,
                    })
                }
                MOUSE_EVENT => {
                    // SAFETY: the console reported this record as a mouse event, which is the
                    // field of the union that is then live.
                    let mouse = unsafe { record.Event.MouseEvent };
                    ConsoleEvent::Mouse {
                        column: mouse.dwMousePosition.X,
                        row: mouse.dwMousePosition.Y,
                        buttons: mouse.dwButtonState,
                        control_keys: mouse.dwControlKeyState,
                        flags: mouse.dwEventFlags,
                    }
                }
                WINDOW_BUFFER_SIZE_EVENT => {
                    // SAFETY: as above, for the resize arm of the union.
                    let size = unsafe { record.Event.WindowBufferSizeEvent };
                    ConsoleEvent::Resize {
                        columns: size.dwSize.X,
                        rows: size.dwSize.Y,
                    }
                }
                kind => ConsoleEvent::Other { kind },
            });
        }
        Ok(events)
    }

    /// Reads the console and returns the bytes to send, in the encoding this reader carries.
    ///
    /// # Errors
    ///
    /// Returns an error when the console will not answer.
    pub fn read_encoded(&mut self) -> Result<(Vec<u8>, Vec<ConsoleEvent>)> {
        let events = self.read()?;
        let keys: Vec<KeyRecord> = events
            .iter()
            .filter_map(|event| match event {
                ConsoleEvent::Key(record) => Some(*record),
                _ => None,
            })
            .collect();
        let bytes = match self.fidelity {
            Fidelity::Records => encode_all(&keys),
            // A session whose backend never asked for records is sent what a terminal doing the
            // translation would have sent. No scan code is claimed, because none is sent.
            Fidelity::LegacyVt => self.legacy_input(&keys),
        };
        // Everything that was not a key, in the order it arrived, for its own dispatch.
        let rest = events
            .into_iter()
            .filter(|event| !matches!(event, ConsoleEvent::Key(_)))
            .collect();
        Ok((bytes, rest))
    }

    /// Turns key records into what a legacy VT client would have sent.
    ///
    /// Two kinds of key, and both go through the one encoder every client in this workspace uses,
    /// so a Windows console and a Unix terminal spell a key the same way:
    ///
    /// * a key that produced a character is that character, repeated as many times as the record
    ///   says it repeated;
    /// * a key that produced none but is one the encoder names - an arrow, a function key, Home,
    ///   Delete and the rest - is its sequence, with the modifiers the console reported.
    ///
    /// A key coming up produces nothing: legacy input has no way to say so, and the encoder
    /// refuses to invent one. A dead key and a modifier on its own produce nothing either, because
    /// neither is a key an application receives.
    ///
    /// A character outside the basic plane is two records, and one read of the console can end
    /// between them, so a trailing high surrogate is held here until the read that completes it.
    fn legacy_input(&mut self, keys: &[KeyRecord]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut units: Vec<u16> = self.pending_high_surrogate.take().into_iter().collect();
        for key in keys {
            if !key.key_down {
                continue;
            }
            if key.unicode == 0 {
                // A special key interrupts the text around it, so what is pending is written
                // before its sequence rather than after.
                flush_text(&mut units, &mut out);
                if let Some(bytes) = special_key(key) {
                    out.extend_from_slice(&bytes);
                }
                continue;
            }
            // A repeat applies to the whole character, so a surrogate pair is put together first
            // and repeated afterwards: high, high, low, low would be two replacements around one
            // character.
            if key.is_high_surrogate() {
                units.push(key.unicode);
                continue;
            }
            if key.is_low_surrogate() {
                let high = units
                    .last()
                    .copied()
                    .filter(|unit| (0xD800..=0xDBFF).contains(unit));
                if let Some(high) = high {
                    units.pop();
                    let text = String::from_utf16_lossy(&[high, key.unicode]);
                    flush_text(&mut units, &mut out);
                    for _ in 0..key.repeat.max(1) {
                        out.extend_from_slice(text.as_bytes());
                    }
                } else {
                    units.push(key.unicode);
                }
                continue;
            }
            for _ in 0..key.repeat.max(1) {
                units.push(key.unicode);
            }
        }
        // A high surrogate at the very end is the first half of a character whose second half is
        // in the next read; it waits there rather than being sent broken.
        if units
            .last()
            .is_some_and(|unit| (0xD800..=0xDBFF).contains(unit))
        {
            self.pending_high_surrogate = units.pop();
        }
        flush_text(&mut units, &mut out);
        out
    }
}

/// One record the console reported.
///
/// One stream rather than a list of keys beside a list of everything else, because the order is
/// part of what happened: a key, a click and another key mean something different in any other
/// order, and two lists cannot say which came first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConsoleEvent {
    /// A key went down or came up.
    Key(KeyRecord),
    /// The console's window changed size.
    Resize {
        /// The new width, in columns.
        columns: i16,
        /// The new height, in rows.
        rows: i16,
    },
    /// A mouse event, with the fields the console reported.
    Mouse {
        /// The column the pointer is over.
        column: i16,
        /// The row the pointer is over.
        row: i16,
        /// Which buttons are down.
        buttons: u32,
        /// The control-key state, as [`kr_term::win32::control_keys`] names its bits.
        control_keys: u32,
        /// Whether this was a move, a double click, or a wheel.
        flags: u32,
    },
    /// A record this command does not act on: a focus change or a menu event.
    Other {
        /// The event type the console reported.
        kind: u32,
    },
}

/// The console input mode a record reader needs.
///
/// `ENABLE_VIRTUAL_TERMINAL_INPUT` is deliberately absent: it is the console translating records
/// into VT sequences, which is the translation this path exists to avoid. `ENABLE_WINDOW_INPUT`
/// is present so that a resize arrives as a record rather than being dropped; it is counted as
/// "other" and handled as the separate operation it is.
#[must_use]
pub const fn record_input_mode(saved: u32) -> u32 {
    use windows_sys::Win32::System::Console::{
        ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT, ENABLE_PROCESSED_INPUT, ENABLE_VIRTUAL_TERMINAL_INPUT,
    };

    (saved
        & !(ENABLE_LINE_INPUT
            | ENABLE_ECHO_INPUT
            | ENABLE_PROCESSED_INPUT
            | ENABLE_VIRTUAL_TERMINAL_INPUT))
        | ENABLE_WINDOW_INPUT
        | ENABLE_MOUSE_INPUT
}

/// Writes the code units gathered so far, replacing anything left unpaired.
///
/// A lone surrogate is a keyboard or an application doing something odd. Replacing it is visible;
/// dropping it would look to the person like a key that did nothing at all.
fn flush_text(units: &mut Vec<u16>, out: &mut Vec<u8>) {
    if units.is_empty() {
        return;
    }
    out.extend_from_slice(String::from_utf16_lossy(units).as_bytes());
    units.clear();
}

/// Returns the legacy sequence for a key that produced no character, or `None` for one that is not
/// a key an application receives.
///
/// The spelling is [`kr_client::encoder::key`], the one encoder every client in this workspace
/// uses, so nothing here invents a second one.
fn special_key(record: &KeyRecord) -> Option<Vec<u8>> {
    use kr_client::encoder::{Arrow, Key, KeyEvent, KeyboardEncoding, Modifiers, key};

    let named = match record.virtual_key {
        0x08 => Key::Backspace,
        0x09 => Key::Tab,
        0x0D => Key::Enter,
        0x1B => Key::Escape,
        0x21 => Key::PageUp,
        0x22 => Key::PageDown,
        0x23 => Key::End,
        0x24 => Key::Home,
        0x25 => Key::Arrow(Arrow::Left),
        0x26 => Key::Arrow(Arrow::Up),
        0x27 => Key::Arrow(Arrow::Right),
        0x28 => Key::Arrow(Arrow::Down),
        0x2D => Key::Insert,
        0x2E => Key::Delete,
        // F1 to F24 are consecutive from 0x70.
        code @ 0x70..=0x87 => Key::Function(u8::try_from(code - 0x6F).ok()?),
        // A modifier on its own, a dead key, a lock key: nothing an application receives.
        _ => return None,
    };
    let modifiers = Modifiers {
        shift: record.control_keys & control_keys::SHIFT_PRESSED != 0,
        // AltGr is not Ctrl and Alt held together: it is how a layout produces a character, and
        // reporting it as two modifiers would turn a key into a different one.
        control: !record.is_alt_graph()
            && record.control_keys
                & (control_keys::LEFT_CTRL_PRESSED | control_keys::RIGHT_CTRL_PRESSED)
                != 0,
        alt: !record.is_alt_graph()
            && record.control_keys
                & (control_keys::LEFT_ALT_PRESSED | control_keys::RIGHT_ALT_PRESSED)
                != 0,
        superkey: false,
    };
    // The ordinary encoding, with the arrows in their cursor form. Whether the session's backend
    // put the terminal into application-cursor mode is the session's state rather than the
    // console's, and a console reader has no way to know it.
    key(
        KeyEvent::with(named, modifiers),
        KeyboardEncoding::Legacy {
            application_cursor_keys: false,
        },
    )
    .ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::System::Console::{
        ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT, ENABLE_PROCESSED_INPUT, ENABLE_VIRTUAL_TERMINAL_INPUT,
    };

    fn typed(unicode: u16, repeat: u16) -> KeyRecord {
        KeyRecord {
            virtual_key: 0x41,
            scan_code: 0x1E,
            unicode,
            key_down: true,
            control_keys: 0,
            repeat,
        }
    }

    #[test]
    fn the_record_mode_never_asks_the_console_to_translate_for_us() {
        let saved = ENABLE_LINE_INPUT
            | ENABLE_ECHO_INPUT
            | ENABLE_PROCESSED_INPUT
            | ENABLE_VIRTUAL_TERMINAL_INPUT;
        let mode = record_input_mode(saved);
        assert_eq!(
            mode & ENABLE_VIRTUAL_TERMINAL_INPUT,
            0,
            "the console's own translation is what records exist to avoid"
        );
        assert_eq!(mode & (ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT), 0);
        assert_eq!(
            mode & ENABLE_PROCESSED_INPUT,
            0,
            "the interrupt key is input to forward rather than an event for this process"
        );
        assert_ne!(
            mode & ENABLE_WINDOW_INPUT,
            0,
            "a resize arrives as a record"
        );
    }

    /// A reader over this process's own console, or none when it has not got one.
    fn over_the_console(records: bool) -> Option<RecordReader> {
        std::fs::File::options()
            .read(true)
            .write(true)
            .open("CONIN$")
            .ok()
            .map(|console| RecordReader::over(console, records))
    }

    /// A reader over a handle that is never read, for the encoding decisions alone.
    fn encoder() -> RecordReader {
        RecordReader::over(
            std::fs::File::options()
                .read(true)
                .open("NUL")
                .expect("the null device"),
            false,
        )
    }

    #[test]
    fn legacy_input_carries_the_text_and_nothing_it_cannot_say() {
        let mut reader = encoder();
        // A repeat becomes that many characters, which is what a translation would have sent.
        assert_eq!(reader.legacy_input(&[typed(u16::from(b'a'), 3)]), b"aaa");
        // A key coming up says nothing at all in this encoding.
        let released = KeyRecord {
            key_down: false,
            ..typed(u16::from(b'a'), 1)
        };
        assert!(reader.legacy_input(&[released]).is_empty());
        // A dead key, a function key and a modifier on its own carry no character.
        let dead = KeyRecord {
            unicode: 0,
            ..typed(0, 1)
        };
        assert!(reader.legacy_input(&[dead]).is_empty());
        // And a surrogate pair is put back together rather than sent as two broken halves.
        let high = typed(0xD83D, 1);
        let low = typed(0xDE00, 1);
        assert_eq!(
            reader.legacy_input(&[high, low]),
            "\u{1F600}".as_bytes(),
            "the pair names the character it came from"
        );
    }

    #[test]
    fn a_character_split_across_two_reads_is_still_one_character() {
        // One read of the console can end between the two halves. Decoding each read on its own
        // would turn the character into two replacements, which is a person's emoji becoming two
        // question marks.
        let mut reader = encoder();
        let high = typed(0xD83D, 1);
        let low = typed(0xDE00, 1);
        assert!(
            reader.legacy_input(&[high]).is_empty(),
            "the first half waits for the second rather than being sent broken"
        );
        assert_eq!(reader.legacy_input(&[low]), "\u{1F600}".as_bytes());
        // And a half whose other half never comes is replaced rather than lost, once something
        // else follows it.
        assert!(reader.legacy_input(&[high]).is_empty());
        assert_eq!(
            reader.legacy_input(&[typed(u16::from(b'a'), 1)]),
            "\u{FFFD}a".as_bytes()
        );
    }

    #[test]
    fn a_reader_reports_the_encoding_it_is_actually_sending() {
        // The two are separate on purpose: a client reads records either way, because that is the
        // only way to read this console, but what it sends is what the session asked for and the
        // fidelity it reports is that.
        let Some(reader) = over_the_console(false) else {
            // A test process with no console of its own cannot open one, and this test is about a
            // reader over a console.
            eprintln!("this process has no console, so no reader was opened over one");
            return;
        };
        assert_eq!(reader.fidelity(), Fidelity::LegacyVt);
        assert!(!reader.fidelity().carries_console_scan_codes());
        let Some(records) = over_the_console(true) else {
            return;
        };
        assert_eq!(records.fidelity(), Fidelity::Records);
        assert!(records.fidelity().carries_console_scan_codes());
    }
}
