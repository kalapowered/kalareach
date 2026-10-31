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
//! from then on its text is read as text ([`RecordReader::read_text`]), exactly as the console hands
//! it over: a record is never turned into bytes here. A read of the console's text waits until the
//! console has some to give, and a thread in it cannot be woken without the console losing the next
//! key, so [`RecordReader::text_waiting`] says first whether there is any.

#![expect(
    unsafe_code,
    reason = "reading console input records has no safe interface"
)]

use kr_client::shown;
use kr_client::shown::Shown;
use std::os::windows::io::AsRawHandle as _;

use kr_term::win32::{KeyRecord, PairHold};
use windows_sys::Win32::Foundation::{HANDLE, WAIT_OBJECT_0};
use windows_sys::Win32::System::Console::{
    ENABLE_WINDOW_INPUT, GetNumberOfConsoleInputEvents, INPUT_RECORD, KEY_EVENT, MOUSE_EVENT,
    PeekConsoleInputW, ReadConsoleInputW, ReadConsoleW, WINDOW_BUFFER_SIZE_EVENT,
};
use windows_sys::Win32::System::Threading::{
    CreateEventW, INFINITE, ResetEvent, SetEvent, WaitForMultipleObjects,
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
}

#[link(name = "user32")]
unsafe extern "system" {
    /// The virtual key and modifiers that give a character in the current keyboard layout, in the
    /// low and high byte of the answer, or -1 where there is none.
    safe fn VkKeyScanW(character: u16) -> i16;
}

/// The console input this attachment reads.
pub struct RecordReader {
    handle: std::fs::File,
    /// The key a NUL comes out of the console as in the layout of the thread that opened this
    /// reader, which is not necessarily the console's.
    nul: Option<crate::attach::NulKey>,
    /// The first half of a character outside the basic plane whose second half has not arrived.
    ///
    /// One read of the console can end between the two halves, and sending each read on its own
    /// would put a character in two writes.
    pairs: PairHold,
}

impl RecordReader {
    /// Opens the console's input for reading records.
    #[must_use]
    pub fn over(handle: std::fs::File) -> Self {
        Self {
            handle,
            nul: crate::attach::NulKey::named_by(VkKeyScanW(0)),
            pairs: PairHold::new(),
        }
    }

    /// Waits until the console has input, or `stop` is set, or `asked` is set, and says which.
    ///
    /// A stop that is set is seen first, whatever the console holds. Input the console holds is seen
    /// before a request, so that a reader asked to do something has read everything the console had
    /// before it does it, unless `requests_first` says the request has waited long enough: a
    /// console that never stops having input must not keep a request from being heard. A request
    /// seen is cleared.
    ///
    /// # Errors
    ///
    /// Returns an error when the system will not wait.
    pub fn wait(&self, stop: &WakeEvent, asked: &WakeEvent, requests_first: bool) -> Result<Woken> {
        let stop = stop.0.as_raw_handle() as HANDLE;
        let console = self.handle.as_raw_handle() as HANDLE;
        let asked_handle = asked.0.as_raw_handle() as HANDLE;
        // The first of the handles that is set decides, so the order is the precedence.
        let (handles, kinds) = if requests_first {
            (
                [stop, asked_handle, console],
                [Woken::Stop, Woken::Asked, Woken::Console],
            )
        } else {
            (
                [stop, console, asked_handle],
                [Woken::Stop, Woken::Console, Woken::Asked],
            )
        };
        // SAFETY: all three handles are open for the call, two the events' and one this reader's
        // own, and the array holds exactly the three the count names.
        let woken = unsafe { WaitForMultipleObjects(3, handles.as_ptr(), 0, INFINITE) };
        let index = woken.wrapping_sub(WAIT_OBJECT_0) as usize;
        match kinds.get(index) {
            Some(Woken::Asked) => {
                asked.reset();
                Ok(Woken::Asked)
            }
            Some(kind) => Ok(*kind),
            None => Err(CliError::Terminal(shown!(
                "wait for the console's input: {}",
                Shown::io(&std::io::Error::last_os_error())
            ))),
        }
    }

    /// Returns the first half of a character outside the basic plane that is waiting for its second
    /// half, if one is, and forgets it.
    ///
    /// The reader hands it on at the moment it stops reading records, so that what it was is counted
    /// with the rest and not lost without a trace.
    pub fn held(&mut self) -> Vec<KeyRecord> {
        // Any key going down after the half makes it a half that nothing completes, which the hold
        // lets go; the key used for that is not one of the console's and is not handed on.
        let after = KeyRecord {
            key_down: true,
            ..KeyRecord::DEFAULT
        };
        let mut records = self.pairs.take(&[after]);
        records.pop();
        records
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

    /// Says whether the console holds text, which a read of it answers at once.
    ///
    /// A console that spells its keys itself keeps what it has not handed over as records, and a
    /// read of its text passes over the records that make none (a key coming up, a key going down
    /// with no character that is not the NUL's, a resize, a focus change) and then waits for one that
    /// does. So when none of the records held makes text they are all taken off the queue here, and
    /// the console reports no input until there is some that does. It must be the only reader of the
    /// console.
    ///
    /// # Errors
    ///
    /// Returns the console's failure.
    pub fn text_waiting(&self) -> std::io::Result<bool> {
        // SAFETY: an `INPUT_RECORD` is a tagged union of plain integers, and all zeroes is a
        // record of event type zero, which this never reads as a key event.
        let mut buffer: [INPUT_RECORD; BATCH] = unsafe { std::mem::zeroed() };
        let mut peeked = 0_u32;
        // SAFETY: the handle is this reader's own and open for the call. The buffer is a local this
        // thread owns and the count it is given is its own length; the number peeked is another
        // local.
        let ok = unsafe {
            PeekConsoleInputW(
                self.handle.as_raw_handle().cast(),
                buffer.as_mut_ptr(),
                u32::try_from(buffer.len()).unwrap_or(1),
                &raw mut peeked,
            )
        };
        if ok == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let peeked = usize::try_from(peeked).unwrap_or(0).min(buffer.len());
        let makes_text = buffer[..peeked].iter().any(|record| {
            if u32::from(record.EventType) != KEY_EVENT {
                return false;
            }
            // SAFETY: the console reported this record as a key event, which is the field of the
            // union that is then live. Both arms of the character's union are the same two bytes.
            let (key, unicode) = unsafe {
                (
                    record.Event.KeyEvent,
                    record.Event.KeyEvent.uChar.UnicodeChar,
                )
            };
            crate::attach::key_can_make_text(
                &KeyRecord {
                    virtual_key: key.wVirtualKeyCode,
                    scan_code: key.wVirtualScanCode,
                    unicode,
                    key_down: key.bKeyDown != 0,
                    control_keys: key.dwControlKeyState,
                    repeat: key.wRepeatCount,
                },
                self.nul,
            )
        });
        if makes_text || peeked == 0 {
            return Ok(makes_text);
        }
        // None of them makes any, so a read of the text would pass over every one and wait. They are
        // taken off, which is all that read would have done with them.
        let mut taken = 0_u32;
        // SAFETY: as above; this reads no more records than were peeked, and this thread is the
        // only reader, so they are there.
        let ok = unsafe {
            ReadConsoleInputW(
                self.handle.as_raw_handle().cast(),
                buffer.as_mut_ptr(),
                u32::try_from(peeked).unwrap_or(1),
                &raw mut taken,
            )
        };
        if ok == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(false)
    }

    /// Reads the text the console hands over, as UTF-16, and returns how many units it read.
    ///
    /// This is a read of the console as a stream of text, for a console that has been asked to spell
    /// its keys itself. It takes what the console gives and changes none of it, a NUL among the
    /// units included, and the console's code page has no part in it. Call it only when
    /// [`Self::text_waiting`] has said there is some.
    ///
    /// # Errors
    ///
    /// Returns the console's failure.
    pub fn read_text(&mut self, units: &mut [u16]) -> std::io::Result<usize> {
        let mut read = 0_u32;
        // SAFETY: the handle is this reader's own and open for the call. The buffer is the caller's
        // and the count it is given is its own length in units; the number read is a local. No input
        // control is passed.
        let ok = unsafe {
            ReadConsoleW(
                self.handle.as_raw_handle().cast(),
                units.as_mut_ptr().cast(),
                u32::try_from(units.len()).unwrap_or(1),
                &raw mut read,
                std::ptr::null(),
            )
        };
        if ok == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(usize::try_from(read).unwrap_or(0).min(units.len()))
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
