//! Reading console key records, and handing them on as the records they are.
//!
//! `ReadConsoleInputW` is the only way to see what a Windows console actually received. The
//! alternative, reading the console as a stream of bytes with `ENABLE_VIRTUAL_TERMINAL_INPUT`, is
//! the console translating those records into VT sequences for you, and the translation is lossy
//! in exactly the places section 8 names: a key coming up has no sequence at all, a repeat count
//! becomes several copies, a surrogate pair becomes whatever the translation made of it, and the
//! scan code is simply gone.
//!
//! What this module does **not** do is invent anything, or spell anything. A record is read, its
//! six fields are carried into [`kr_term::win32::KeyRecord`] unchanged, and a run of them is given
//! to the caller in the order the console reported it. There is no path here that decodes a record
//! into a character and encodes that character again with a scan code this host chose: section 8
//! forbids it, and a remote application that tracks the keyboard itself would be told a key was
//! pressed that nobody pressed.
//!
//! **Which encoding the keys are sent as is the session's decision, and the worker makes it.** It
//! knows what its owned backend asked for, and it spells the records as the backend asked for them,
//! or as legacy VT input, when they reach it. This reader never learns which.
//!
//! When the session cannot take the records, the console is asked to spell its keys itself, and
//! from then on its bytes are read as bytes ([`RecordReader::read_bytes`]), exactly as the console
//! hands them over: a record is never turned into bytes here.

#![expect(
    unsafe_code,
    reason = "reading console input records has no safe interface"
)]

use kr_client::shown;
use kr_client::shown::Shown;
use std::io::Read as _;
use std::os::windows::io::AsRawHandle as _;

use kr_term::win32::{KeyRecord, PairHold};
use windows_sys::Win32::Foundation::{HANDLE, WAIT_OBJECT_0};
use windows_sys::Win32::System::Console::{
    ENABLE_WINDOW_INPUT, GetNumberOfConsoleInputEvents, INPUT_RECORD, KEY_EVENT, MOUSE_EVENT,
    ReadConsoleInputW, WINDOW_BUFFER_SIZE_EVENT,
};
use windows_sys::Win32::System::Threading::{
    CreateEventW, INFINITE, ResetEvent, SetEvent, WaitForMultipleObjects, WaitForSingleObject,
};

use crate::attach::Woken;
use crate::error::{CliError, Result};

/// How many records one read asks the console for.
///
/// A held key, a paste and an IME commit all arrive as runs of records, so a read that asked for
/// one at a time would make a system call per keystroke of a paste.
const BATCH: usize = 256;

/// An event the thread that reads the console waits on beside the console, so that it can be woken
/// to end or to do what it is asked.
///
/// A read of the console cannot be woken by anything else the thread waits on: it is the console
/// that is waited for, and this is what is waited for with it.
pub struct WakeEvent(std::os::windows::io::OwnedHandle);

impl WakeEvent {
    /// Makes an event that is not set.
    ///
    /// # Errors
    ///
    /// Returns an error when the system will not make one.
    pub fn new() -> Result<Self> {
        use std::os::windows::io::{FromRawHandle as _, RawHandle};

        // SAFETY: no attributes and no name are passed, and the handle that comes back is checked
        // before it is used.
        let event = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
        if event.is_null() {
            return Err(CliError::Terminal(shown!(
                "make an event to wake the console's reader with: {}",
                Shown::io(&std::io::Error::last_os_error())
            )));
        }
        // SAFETY: the handle is a new event this call made and nothing else owns.
        Ok(Self(unsafe {
            std::os::windows::io::OwnedHandle::from_raw_handle(event as RawHandle)
        }))
    }

    /// Sets the event, which ends the wait of a thread that is waiting on it.
    pub fn signal(&self) {
        // SAFETY: the handle is this event's own and open for the call.
        let _ = unsafe { SetEvent(self.0.as_raw_handle() as HANDLE) };
    }

    /// Clears the event, so that the next wait on it waits.
    fn reset(&self) {
        // SAFETY: the handle is this event's own and open for the call.
        let _ = unsafe { ResetEvent(self.0.as_raw_handle() as HANDLE) };
    }

    /// Whether the event is set now, without waiting.
    #[must_use]
    pub fn is_set(&self) -> bool {
        // SAFETY: the handle is this event's own and open for the call.
        unsafe { WaitForSingleObject(self.0.as_raw_handle() as HANDLE, 0) == WAIT_OBJECT_0 }
    }
}

/// The console input this attachment reads.
pub struct RecordReader {
    handle: std::fs::File,
    /// The first half of a character outside the basic plane whose second half has not arrived.
    ///
    /// One read of the console can end between the two halves, and sending each read on its own
    /// would put a character in two writes.
    pairs: PairHold,
}

impl RecordReader {
    /// Opens the console's input for reading records.
    #[must_use]
    pub const fn over(handle: std::fs::File) -> Self {
        Self {
            handle,
            pairs: PairHold::new(),
        }
    }

    /// Waits until the console has input, or `stop` is set, or `asked` is set, and says which.
    ///
    /// A stop that is set is seen first, whatever the console holds. Input the console holds is seen
    /// before a request, so that a reader asked to do something has read everything the console had
    /// before it does it. A request seen is cleared.
    ///
    /// # Errors
    ///
    /// Returns an error when the system will not wait.
    pub fn wait(&self, stop: &WakeEvent, asked: &WakeEvent) -> Result<Woken> {
        let handles: [HANDLE; 3] = [
            stop.0.as_raw_handle() as HANDLE,
            self.handle.as_raw_handle() as HANDLE,
            asked.0.as_raw_handle() as HANDLE,
        ];
        // SAFETY: all three handles are open for the call, the first and third the events' and the
        // second this reader's own, and the array holds exactly the three the count names.
        let woken = unsafe { WaitForMultipleObjects(3, handles.as_ptr(), 0, INFINITE) };
        if woken == WAIT_OBJECT_0 {
            Ok(Woken::Stop)
        } else if woken == WAIT_OBJECT_0 + 1 {
            Ok(Woken::Console)
        } else if woken == WAIT_OBJECT_0 + 2 {
            asked.reset();
            Ok(Woken::Asked)
        } else {
            Err(CliError::Terminal(shown!(
                "wait for the console's input: {}",
                Shown::io(&std::io::Error::last_os_error())
            )))
        }
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
            return Err(CliError::Terminal(shown!(
                "read the console's input: {}",
                Shown::io(&std::io::Error::last_os_error())
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
            return Err(CliError::Terminal(shown!(
                "read the console's input: {}",
                Shown::io(&std::io::Error::last_os_error())
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

    /// Reads the console and returns what to send, in the order it happened.
    ///
    /// A run of keys becomes one [`ReadEvent::Keys`], and anything else keeps its own place between
    /// those runs, because a caller that could not tell whether a click came before or after a
    /// keystroke could not dispatch either of them honestly. The first half of a character outside
    /// the basic plane that ends a run of keys waits for the keys that complete it, across a mouse,
    /// resize, focus or menu record if one comes between, and goes out as it was with the next key.
    ///
    /// # Errors
    ///
    /// Returns an error when the console will not answer.
    pub fn read_events(&mut self) -> Result<Vec<ReadEvent>> {
        let mut out = Vec::new();
        let mut keys: Vec<KeyRecord> = Vec::new();
        for event in self.read()? {
            match event {
                ConsoleEvent::Key(record) => keys.push(record),
                other => {
                    let ready = self.pairs.take(&keys);
                    keys.clear();
                    if !ready.is_empty() {
                        out.push(ReadEvent::Keys(ready));
                    }
                    out.push(ReadEvent::Console(other));
                }
            }
        }
        let ready = self.pairs.take(&keys);
        if !ready.is_empty() {
            out.push(ReadEvent::Keys(ready));
        }
        Ok(out)
    }

    /// Reads the bytes the console hands over, waiting for at least one.
    ///
    /// This is a read of the console as a stream of bytes, for a console that has been asked to
    /// spell its keys itself. It takes what the console gives and changes none of it, a NUL among
    /// the bytes included.
    ///
    /// # Errors
    ///
    /// Returns the console's failure, or the end of its input as `Ok(0)`.
    pub fn read_bytes(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.handle.read(buffer)
    }
}

/// One thing to dispatch, in the order the console reported it.
#[derive(Clone, PartialEq, Eq)]
pub enum ReadEvent {
    /// A run of keys, for the session to spell as its backend asked for.
    Keys(Vec<KeyRecord>),
    /// A record that is its own operation: a resize, a mouse event, or one this command does not
    /// act on.
    Console(ConsoleEvent),
}

impl std::fmt::Debug for ReadEvent {
    /// Which event it is, and how many keys a run carries. Never the keys, which a person typed.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Keys(keys) => formatter
                .debug_struct("Keys")
                .field("count", &keys.len())
                .finish(),
            Self::Console(event) => formatter.debug_tuple("Console").field(event).finish(),
        }
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
/// into VT sequences, which is the translation this path exists to avoid. Line input, echo and
/// the console's own handling of Ctrl-C are absent as well: every key, the interrupt among them,
/// is a record to hand on to the session. Mouse and window-size records are not asked for, since
/// nothing here dispatches them: the console keeps the mouse for selecting text, as it does for any
/// command that does not ask for it.
#[must_use]
pub const fn record_input_mode(saved: u32) -> u32 {
    use windows_sys::Win32::System::Console::{
        ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT, ENABLE_MOUSE_INPUT, ENABLE_PROCESSED_INPUT,
        ENABLE_VIRTUAL_TERMINAL_INPUT,
    };

    saved
        & !(ENABLE_LINE_INPUT
            | ENABLE_ECHO_INPUT
            | ENABLE_PROCESSED_INPUT
            | ENABLE_VIRTUAL_TERMINAL_INPUT
            | ENABLE_MOUSE_INPUT
            | ENABLE_WINDOW_INPUT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::System::Console::{
        ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT, ENABLE_MOUSE_INPUT, ENABLE_PROCESSED_INPUT,
        ENABLE_VIRTUAL_TERMINAL_INPUT,
    };

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
            "nothing here dispatches a mouse or a window-size record, so none is asked for"
        );
        assert_eq!(
            mode & ENABLE_PROCESSED_INPUT,
            0,
            "the interrupt key is input to forward rather than an event for this process"
        );
    }
}
