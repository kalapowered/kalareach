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

use kr_term::win32::{Fidelity, KeyRecord, encode_all};
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
    /// Records that are not key events - a resize, a mouse event, a focus change - are returned
    /// beside the keys rather than counted away, because each of those is its own operation in
    /// this protocol and a caller needs its detail to dispatch it. None of them belongs in a key
    /// encoding.
    ///
    /// # Errors
    ///
    /// Returns an error when the console will not answer.
    pub fn read(&mut self) -> Result<Batch> {
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
        let mut batch = Batch::default();
        for record in &buffer[..read] {
            match u32::from(record.EventType) {
                KEY_EVENT => {}
                MOUSE_EVENT => {
                    // SAFETY: the console reported this record as a mouse event, which is the
                    // field of the union that is then live.
                    let mouse = unsafe { record.Event.MouseEvent };
                    batch.other.push(ConsoleEvent::Mouse {
                        column: mouse.dwMousePosition.X,
                        row: mouse.dwMousePosition.Y,
                        buttons: mouse.dwButtonState,
                        control_keys: mouse.dwControlKeyState,
                        flags: mouse.dwEventFlags,
                    });
                    continue;
                }
                WINDOW_BUFFER_SIZE_EVENT => {
                    // SAFETY: as above, for the resize arm of the union.
                    let size = unsafe { record.Event.WindowBufferSizeEvent };
                    batch.other.push(ConsoleEvent::Resize {
                        columns: size.dwSize.X,
                        rows: size.dwSize.Y,
                    });
                    continue;
                }
                other => {
                    batch.other.push(ConsoleEvent::Other { kind: other });
                    continue;
                }
            }
            // SAFETY: the console reported this record as a key event, which is the field of the
            // union that is then live.
            let key = unsafe { record.Event.KeyEvent };
            batch.keys.push(KeyRecord {
                virtual_key: key.wVirtualKeyCode,
                scan_code: key.wVirtualScanCode,
                // The union here is the character the console produced, read as the UTF-16 code
                // unit it is. A surrogate pair is two records and stays two records.
                //
                // SAFETY: both arms of this union are the same two bytes, and reading them as the
                // wide character is what a console that is read with `ReadConsoleInputW` produces.
                unicode: unsafe { key.uChar.UnicodeChar },
                key_down: key.bKeyDown != 0,
                control_keys: key.dwControlKeyState,
                repeat: key.wRepeatCount,
            });
        }
        Ok(batch)
    }

    /// Reads the console and returns the bytes to send, in the encoding this reader carries.
    ///
    /// # Errors
    ///
    /// Returns an error when the console will not answer.
    pub fn read_encoded(&mut self) -> Result<(Vec<u8>, Vec<ConsoleEvent>)> {
        let batch = self.read()?;
        let bytes = match self.fidelity {
            Fidelity::Records => encode_all(&batch.keys),
            // A session whose backend never asked for records is sent the text the keys produced
            // and nothing else. No scan code is claimed, because none is sent.
            Fidelity::LegacyVt => self.legacy_text(&batch.keys),
        };
        Ok((bytes, batch.other))
    }

    /// Turns key records into the text a legacy VT client would have sent.
    ///
    /// Key-down events with a character, and nothing else. A key coming up produces nothing,
    /// because legacy input has no way to say so; a repeat count becomes that many copies, because
    /// that is what a terminal doing the translation would have sent; and a key with no character
    /// at all - a dead key, a function key, a modifier on its own - produces nothing here, because
    /// this is the text path and a special key's sequence is the input encoder's business rather
    /// than the console's.
    ///
    /// A character outside the basic plane is two records and can be split across two reads, so
    /// the first half is held on this reader until the second arrives.
    fn legacy_text(&mut self, keys: &[KeyRecord]) -> Vec<u8> {
        let mut units: Vec<u16> = self.pending_high_surrogate.take().into_iter().collect();
        for key in keys {
            if !key.key_down || key.unicode == 0 {
                continue;
            }
            for _ in 0..key.repeat.max(1) {
                units.push(key.unicode);
            }
        }
        // A high surrogate at the very end is the first half of a character whose second half is
        // in the next read. Anything else unpaired is a keyboard or an application doing something
        // odd, and is replaced rather than dropped: a key that did nothing at all is worse.
        if units
            .last()
            .is_some_and(|unit| (0xD800..=0xDBFF).contains(unit))
        {
            self.pending_high_surrogate = units.pop();
        }
        String::from_utf16_lossy(&units).into_bytes()
    }
}

/// One read of the console.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Batch {
    /// The key records, in the order the console reported them.
    pub keys: Vec<KeyRecord>,
    /// Everything in the same read that was not a key, in the order it arrived.
    ///
    /// Each of these is its own operation in this protocol - a resize claims geometry, a mouse
    /// event is a mouse event - so each is carried with the detail its dispatch needs rather than
    /// counted and thrown away.
    pub other: Vec<ConsoleEvent>,
}

/// A console record that is not a key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConsoleEvent {
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
        assert_eq!(reader.legacy_text(&[typed(u16::from(b'a'), 3)]), b"aaa");
        // A key coming up says nothing at all in this encoding.
        let released = KeyRecord {
            key_down: false,
            ..typed(u16::from(b'a'), 1)
        };
        assert!(reader.legacy_text(&[released]).is_empty());
        // A dead key, a function key and a modifier on its own carry no character.
        let dead = KeyRecord {
            unicode: 0,
            ..typed(0, 1)
        };
        assert!(reader.legacy_text(&[dead]).is_empty());
        // And a surrogate pair is put back together rather than sent as two broken halves.
        let high = typed(0xD83D, 1);
        let low = typed(0xDE00, 1);
        assert_eq!(
            reader.legacy_text(&[high, low]),
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
            reader.legacy_text(&[high]).is_empty(),
            "the first half waits for the second rather than being sent broken"
        );
        assert_eq!(reader.legacy_text(&[low]), "\u{1F600}".as_bytes());
        // And a half whose other half never comes is replaced rather than lost, once something
        // else follows it.
        assert!(reader.legacy_text(&[high]).is_empty());
        assert_eq!(
            reader.legacy_text(&[typed(u16::from(b'a'), 1)]),
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
