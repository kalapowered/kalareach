//! The setup dialogue's terminal calls on Windows: the process's error mode and the console API.
//!
//! The crash-dump guard here is narrower than the Unix one. A Unix process is kept out of a core
//! dump by the system. A Windows process can only decline Windows Error Reporting for itself: an
//! administrator's dump policy can still take the process, and so can any process of the same
//! account that may read this process's memory.

#![expect(
    unsafe_code,
    reason = "the error mode and the console have no safe interface"
)]

use std::fs::File;
use std::io::Write as _;
use std::os::windows::io::{AsHandle as _, AsRawHandle as _, OwnedHandle};

use kr_client::shown;
use kr_client::shown::Shown;
use windows_sys::Win32::Foundation::{HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows_sys::Win32::System::Console::{
    ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT, ENABLE_PROCESSED_INPUT, ENABLE_VIRTUAL_TERMINAL_INPUT,
    FlushConsoleInputBuffer, GetConsoleMode, INPUT_RECORD, KEY_EVENT, ReadConsoleInputW,
    SetConsoleMode,
};
use windows_sys::Win32::System::Diagnostics::Debug::{
    EXCEPTION_POINTERS, GetErrorMode, SEM_FAILCRITICALERRORS, SEM_NOGPFAULTERRORBOX,
    SEM_NOOPENFILEERRORBOX, SetErrorMode, SetUnhandledExceptionFilter,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, TerminateProcess, WaitForSingleObject,
};
use zeroize::{Zeroize as _, Zeroizing};

use crate::error::{CliError, Result};

/// What is said before the kit is shown.
pub const KIT_FOLLOWS: &str = "Your recovery kit follows. It is shown once. The console keeps it \
     on screen until you run cls or close the window.";

/// The error mode setup runs under: no Windows Error Reporting, and no dialogue box that waits for
/// a person where the kit is on the screen.
const ERROR_MODE: u32 = SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX;

/// What an unhandled-exception filter returns to have the system end the process without a report.
const EXCEPTION_EXECUTE_HANDLER: i32 = 1;

/// Keeps Windows Error Reporting from taking a report of this process, before the seed exists.
///
/// The process declines the report (`SEM_NOGPFAULTERRORBOX`, which the system documents as not
/// invoking Windows Error Reporting) and ends at once on an unhandled exception, so that no
/// handler of the system's runs while the kit is in memory. A policy an administrator set for the
/// machine, and a process of the same account that can read this one, are outside what this does.
///
/// # Errors
///
/// Returns the refusal when the error mode does not take the flags.
pub fn keep_out_of_a_dump() -> Result<()> {
    let refused = |error: &std::io::Error| {
        CliError::Other(shown!(
            "the recovery kit is not made because this process could not be kept out of a Windows \
             error report: {}",
            Shown::io(error)
        ))
    };
    // SAFETY: neither call takes a pointer; the mode is the process's own.
    let taken = unsafe {
        SetErrorMode(GetErrorMode() | ERROR_MODE);
        GetErrorMode()
    };
    if taken & ERROR_MODE != ERROR_MODE {
        return Err(refused(&std::io::Error::other(
            "the process error mode did not take the flags",
        )));
    }
    // SAFETY: `end_at_once` lives as long as the process and has the signature of a filter.
    unsafe { SetUnhandledExceptionFilter(Some(end_at_once)) };
    Ok(())
}

/// Ends the process at once on an unhandled exception, with the exception's code as its exit code.
unsafe extern "system" fn end_at_once(exception: *const EXCEPTION_POINTERS) -> i32 {
    // SAFETY: the system passes a pointer to the exception it is dispatching, or null.
    let code = unsafe {
        exception
            .as_ref()
            .and_then(|pointers| pointers.ExceptionRecord.as_ref())
            .map_or(1, |record| record.ExceptionCode.cast_unsigned())
    };
    // SAFETY: the process handle is the pseudo handle of this process, which needs no closing.
    unsafe { TerminateProcess(GetCurrentProcess(), code) };
    // The call ends the process. If it ever returned, the system ends it without a report.
    EXCEPTION_EXECUTE_HANDLER
}

/// A new handle to the console on standard input.
fn standard_input() -> Result<OwnedHandle> {
    std::io::stdin()
        .as_handle()
        .try_clone_to_owned()
        .map_err(|error| modes_not_changed(&error))
}

/// The failure to change the console's modes.
fn modes_not_changed(error: &std::io::Error) -> CliError {
    CliError::Terminal(shown!(
        "the console's modes could not be changed: {}",
        Shown::io(error)
    ))
}

/// Throws away the input waiting on the console.
fn flush(handle: HANDLE) -> std::io::Result<()> {
    // SAFETY: the caller's handle is open for the length of the call.
    if unsafe { FlushConsoleInputBuffer(handle) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// The failure to throw away the input waiting on the console.
fn not_thrown_away(error: &std::io::Error) -> CliError {
    CliError::Terminal(shown!(
        "the console's waiting input could not be thrown away: {}",
        Shown::io(error)
    ))
}

/// Throws away the input waiting on the console, or says that it could not.
fn discard(handle: HANDLE) -> Result<()> {
    flush(handle).map_err(|error| not_thrown_away(&error))
}

/// Opens the console's output buffer as itself, for writing, with no buffer of ours in between. The
/// command runs only where standard output is that console.
///
/// # Errors
///
/// Returns the error that opening it gave.
pub fn open_output() -> std::io::Result<File> {
    File::options().write(true).open("CONOUT$")
}

/// The console's input modes as they were found. They are put back when this is dropped, and the
/// input still waiting is discarded with them: what was pasted past a line the dialogue read is not
/// for the shell.
pub struct Terminal {
    input: OwnedHandle,
    saved: u32,
}

impl Terminal {
    /// Reads the modes of the console on standard input.
    ///
    /// # Errors
    ///
    /// Returns a terminal failure when the console cannot be reached or its modes cannot be read.
    pub fn hold() -> Result<Self> {
        let input = std::io::stdin()
            .as_handle()
            .try_clone_to_owned()
            .map_err(|error| {
                CliError::Terminal(shown!(
                    "the console could not be reached: {}",
                    Shown::io(&error)
                ))
            })?;
        let mut saved = 0_u32;
        // SAFETY: the handle is open for as long as `input` is, and `saved` is a live `u32`.
        if unsafe { GetConsoleMode(input.as_raw_handle().cast(), &raw mut saved) } == 0 {
            return Err(CliError::Terminal(shown!(
                "the console's modes could not be read: {}",
                Shown::io(&std::io::Error::last_os_error())
            )));
        }
        Ok(Self { input, saved })
    }
}

impl Drop for Terminal {
    fn drop(&mut self) {
        let handle = self.input.as_raw_handle().cast();
        // SAFETY: the handle is open for as long as `self.input` is.
        unsafe {
            SetConsoleMode(handle, self.saved);
            FlushConsoleInputBuffer(handle);
        }
    }
}

/// How long one wait for the console's input lasts before it says that nothing came.
const TURN_MILLISECONDS: u32 = 200;

/// How many input records one read asks the console for.
const RECORDS: usize = 32;

/// How many reads of records one call of [`Prompt::read`] makes at most while the records that
/// arrive hold no character. The bound keeps an endless stream of them from holding off the
/// caller's own checks (a cancelled read, an idle limit).
const RECORD_READS: usize = 64;

/// How many times a record can stand for its character: a held key repeats up to this many times.
const MAX_REPEAT: u16 = 16;

/// The most bytes one read can leave pending: every record at its repeat limit and every character
/// four bytes long. `pending` is made this size before any secret is read, so it never grows: a
/// vector that grows leaves its old allocation behind, with a kit's fragments in it, uncleared.
const PENDING_BOUND: usize = RECORDS * MAX_REPEAT as usize * 4;

/// The input records of one read. The characters of a kit pass through them, so they are cleared
/// when the read ends, however it ends.
struct Clearing<'a>(&'a mut [INPUT_RECORD; RECORDS]);

impl Drop for Clearing<'_> {
    fn drop(&mut self) {
        // SAFETY: a record is plain data, so zero bytes are a valid value of it, and the slice
        // covers the array and nothing else.
        let bytes = unsafe {
            std::slice::from_raw_parts_mut(
                self.0.as_mut_ptr().cast::<u8>(),
                std::mem::size_of_val(self.0),
            )
        };
        bytes.zeroize();
    }
}

/// The console's modes while the kit or an answer is typed: no echo, no line editing, and a read
/// that returns after a fifth of a second with or without input. Processed input stays, so Ctrl-C
/// is still an interrupt.
pub struct Prompt {
    input: OwnedHandle,
    saved: u32,
    restored: bool,
    /// The first half of a character that arrived in two units, until the second comes.
    high: Option<u16>,
    /// What was read and not yet handed on, which clears itself when it is dropped.
    pending: Zeroizing<Vec<u8>>,
}

impl Prompt {
    /// Switches the console on standard input to the modes of the prompt and throws away what was
    /// typed before it.
    ///
    /// # Errors
    ///
    /// Returns a terminal failure when the console cannot be reached or its modes cannot be
    /// changed.
    pub fn enter() -> Result<Self> {
        Self::enter_on(standard_input()?)
    }

    /// As [`Self::enter`], on the console input `input`.
    fn enter_on(input: OwnedHandle) -> Result<Self> {
        Self::enter_with(input, flush)
    }

    /// As [`Self::enter_on`], with `flush` as the way the waiting input is thrown away.
    fn enter_with(
        input: OwnedHandle,
        flush: impl FnOnce(HANDLE) -> std::io::Result<()>,
    ) -> Result<Self> {
        let prompt = Self::silent_on(input)?;
        let handle = prompt.input.as_raw_handle().cast();
        // What was typed before this prompt was shown was echoed, and is not part of the kit. If it
        // cannot be thrown away the prompt is not entered: dropping it puts the modes back.
        flush(handle).map_err(|error| not_thrown_away(&error))?;
        Ok(prompt)
    }

    /// Switches the console on standard input to the modes of the prompt for an answer. What was
    /// typed is left where it is: the question was shown first, so it is the answer.
    ///
    /// # Errors
    ///
    /// Returns a terminal failure when the console cannot be reached or its modes cannot be
    /// changed.
    fn answering() -> Result<Self> {
        Self::silent_on(standard_input()?)
    }

    /// The modes of the prompt, set on the console input `input`.
    fn silent_on(input: OwnedHandle) -> Result<Self> {
        let handle = input.as_raw_handle().cast();
        let mut saved = 0_u32;
        // SAFETY: the handle is open for as long as `input` is, and `saved` is a live `u32`.
        if unsafe { GetConsoleMode(handle, &raw mut saved) } == 0 {
            return Err(modes_not_changed(&std::io::Error::last_os_error()));
        }
        let silent = (saved
            & !(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT | ENABLE_VIRTUAL_TERMINAL_INPUT))
            | ENABLE_PROCESSED_INPUT;
        // SAFETY: the handle is open for as long as `input` is.
        if unsafe { SetConsoleMode(handle, silent) } == 0 {
            return Err(modes_not_changed(&std::io::Error::last_os_error()));
        }
        Ok(Self::holding(input, saved))
    }

    /// A prompt on `input` whose modes are already set and were `saved` before, with room for the
    /// largest read.
    fn holding(input: OwnedHandle, saved: u32) -> Self {
        Self {
            input,
            saved,
            restored: false,
            high: None,
            pending: Zeroizing::new(Vec::with_capacity(PENDING_BOUND)),
        }
    }

    /// Puts the modes back, discarding the input still waiting: what was pasted past the end of the
    /// kit is not for the shell.
    ///
    /// # Errors
    ///
    /// Returns a terminal failure when the modes cannot be put back.
    pub fn leave(&mut self) -> Result<()> {
        self.leave_with(flush)
    }

    /// As [`Self::leave`], with `flush` as the way the waiting input is thrown away.
    fn leave_with(&mut self, flush: impl FnOnce(HANDLE) -> std::io::Result<()>) -> Result<()> {
        if self.restored {
            return Ok(());
        }
        let handle = self.input.as_raw_handle().cast();
        // SAFETY: the handle is open for as long as `self.input` is.
        if unsafe { SetConsoleMode(handle, self.saved) } == 0 {
            // Not marked restored, so dropping this tries once more.
            return Err(CliError::Terminal(shown!(
                "the console's modes could not be put back: {}",
                Shown::io(&std::io::Error::last_os_error())
            )));
        }
        // A prompt whose input cannot be thrown away is not left: dropping it tries once more.
        flush(handle).map_err(|error| not_thrown_away(&error))?;
        self.restored = true;
        Ok(())
    }

    /// Reads what the person typed into `buffer` as text, waiting one turn for it, and returns how
    /// many bytes it holds: none when the turn passed in silence. A key's character is read as it
    /// is typed, not as a line; Ctrl-Z reads as the end of the input.
    ///
    /// # Errors
    ///
    /// Returns the error that waiting for the console or reading it gave.
    pub fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        // A key's release, a modifier key and a change of focus arrive as records with no
        // character, and a paste is made of them as much as of its text. They do not say that the
        // input stopped, so the read goes on in the same turn, and says that nothing came only
        // after a turn in which no record came.
        for _ in 0..RECORD_READS {
            if !self.pending.is_empty() || !self.fill()? {
                break;
            }
        }
        let taken = buffer.len().min(self.pending.len());
        buffer[..taken].copy_from_slice(&self.pending[..taken]);
        self.pending.drain(..taken);
        Ok(taken)
    }

    /// The next character the person typed, waiting one turn for it: none when the turn passed in
    /// silence.
    fn next(&mut self) -> std::io::Result<Option<char>> {
        if self.pending.is_empty() {
            // Records with no character leave it empty: the caller's turn is over, and it asks again.
            self.fill()?;
        }
        let Some(&first) = self.pending.first() else {
            return Ok(None);
        };
        // `pending` holds whole characters, and the first byte of one says how long it is.
        let width = match first {
            0x00..=0x7f => 1,
            0xc0..=0xdf => 2,
            0xe0..=0xef => 3,
            _ => 4,
        };
        let character = self
            .pending
            .get(..width)
            .and_then(|bytes| std::str::from_utf8(bytes).ok())
            .and_then(|text| text.chars().next())
            .unwrap_or(char::REPLACEMENT_CHARACTER);
        let taken = width.min(self.pending.len());
        self.pending.drain(..taken);
        Ok(Some(character))
    }

    /// Reads one answer the way a line is edited at a console: the characters shown as they are
    /// taken, Backspace taking the last one back, Enter ending the line and Ctrl-Z, on an empty
    /// line, ending the input. They are read as input records, as the kit is, so that the console
    /// keeps no history of the line.
    fn line(&mut self) -> std::io::Result<Option<String>> {
        /// An answer is a word; this is more than any answer needs.
        const LONGEST_ANSWER: usize = 4096;

        let mut shown = open_output()?;
        // Made at its largest size, so that it never moves to a new allocation.
        let mut answer = Zeroizing::new(String::with_capacity(LONGEST_ANSWER));
        loop {
            let Some(character) = self.next()? else {
                continue;
            };
            match character {
                '\r' | '\n' => {
                    shown.write_all(b"\r\n")?;
                    return Ok(Some(std::mem::take(&mut *answer)));
                }
                // Ctrl-Z, as `take` makes it.
                '\u{4}' if answer.is_empty() => {
                    shown.write_all(b"\r\n")?;
                    return Ok(None);
                }
                '\u{8}' | '\u{7f}' => {
                    if answer.pop().is_some() {
                        shown.write_all(b"\x08 \x08")?;
                    }
                }
                other if other.is_control() => {}
                other => {
                    if answer.len() + other.len_utf8() > LONGEST_ANSWER {
                        shown.write_all(b"\r\n")?;
                        return Ok(Some(std::mem::take(&mut *answer)));
                    }
                    answer.push(other);
                    shown.write_all(other.encode_utf8(&mut [0_u8; 4]).as_bytes())?;
                }
            }
        }
    }

    /// Waits one turn for the console's input and takes the characters of the key events in it.
    /// Returns whether any record came: none means the turn passed in silence.
    fn fill(&mut self) -> std::io::Result<bool> {
        let handle = self.input.as_raw_handle().cast();
        // SAFETY: the handle is open for as long as `self.input` is.
        match unsafe { WaitForSingleObject(handle, TURN_MILLISECONDS) } {
            WAIT_OBJECT_0 => {}
            WAIT_TIMEOUT => return Ok(false),
            _ => return Err(std::io::Error::last_os_error()),
        }
        // SAFETY: an all-zero record is a valid value of the type, which is plain data.
        let mut array: [INPUT_RECORD; RECORDS] = unsafe { std::mem::zeroed() };
        let records = Clearing(&mut array);
        let mut count = 0_u32;
        // SAFETY: the buffer holds `RECORDS` records, which is what the call is told, and `count`
        // is a live `u32`. The signalled handle has an event, so the call does not wait.
        if unsafe {
            ReadConsoleInputW(
                handle,
                records.0.as_mut_ptr(),
                RECORDS as u32,
                &raw mut count,
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error());
        }
        for record in &records.0[..count as usize] {
            if u32::from(record.EventType) != KEY_EVENT {
                continue;
            }
            // SAFETY: the record is a key event, so the key member of the union is the one set.
            let key = unsafe { record.Event.KeyEvent };
            if key.bKeyDown == 0 {
                continue;
            }
            // SAFETY: the character is a 16-bit unit in either view of the union.
            let unit = unsafe { key.uChar.UnicodeChar };
            for _ in 0..key.wRepeatCount.clamp(1, MAX_REPEAT) {
                self.take(unit);
            }
        }
        Ok(true)
    }

    /// Takes one UTF-16 unit: a surrogate waits for its pair, and Ctrl-Z becomes the byte that
    /// ends a document typed at a terminal.
    fn take(&mut self, unit: u16) {
        let character = match (self.high.take(), unit) {
            (_, 0) => return,
            (None, 0xD800..=0xDBFF) => {
                self.high = Some(unit);
                return;
            }
            (Some(high), 0xDC00..=0xDFFF) => char::decode_utf16([high, unit])
                .next()
                .and_then(std::result::Result::ok),
            (_, 0x1A) => Some('\u{4}'),
            (_, other) => char::from_u32(u32::from(other)),
        };
        let mut encoded = [0_u8; 4];
        self.pending.extend_from_slice(
            character
                .unwrap_or(char::REPLACEMENT_CHARACTER)
                .encode_utf8(&mut encoded)
                .as_bytes(),
        );
    }
}

impl Drop for Prompt {
    fn drop(&mut self) {
        let _ = self.leave();
    }
}

/// Throws away what is waiting on the console's input, so a line typed before a question was shown
/// cannot answer it. Standard input that is not a console is left alone.
///
/// # Errors
///
/// Returns a terminal failure when the input is a console and what waits in it cannot be thrown
/// away.
pub fn discard_typed_ahead() -> Result<()> {
    let handle = std::io::stdin().as_raw_handle().cast();
    let mut mode = 0_u32;
    // SAFETY: the handle is the standard input's, open for the whole process, and `mode` is a live
    // `u32`; the call fails for a handle that is not a console.
    if unsafe { GetConsoleMode(handle, &raw mut mode) } == 0 {
        return Ok(());
    }
    discard(handle)
}

/// Reads one answer from the console on standard input, showing what is typed as it goes: `None` at
/// the end of the input (Ctrl-Z on an empty line).
///
/// The answer is read as input records, as the kit is, and never as a line by the console, which
/// would keep each line in the command history of the window, where a later question could bring
/// it back.
///
/// # Errors
///
/// Returns a terminal failure when the console cannot be reached, read or put back.
pub fn read_line() -> Result<Option<String>> {
    let mut prompt = Prompt::answering()?;
    let line = prompt.line().map_err(|error| {
        CliError::Terminal(shown!(
            "your answer could not be read: {}",
            Shown::io(&error)
        ))
    });
    let left = prompt.leave();
    let line = line?;
    left?;
    Ok(line)
}

#[cfg(test)]
mod tests {
    use std::sync::{Mutex, PoisonError};

    use windows_sys::Win32::System::Console::{
        INPUT_RECORD_0, KEY_EVENT_RECORD, KEY_EVENT_RECORD_0, WriteConsoleInputW,
    };

    use super::*;

    /// The tests that touch the console's input share one console, so they run one at a time.
    static CONSOLE: Mutex<()> = Mutex::new(());

    /// The console's input as a new handle, with write access or without it. Throwing input away
    /// needs write access; reading the modes and changing them needs read access.
    fn console_input(write: bool) -> OwnedHandle {
        File::options()
            .read(true)
            .write(write)
            .open("CONIN$")
            .expect("the test runs on a console")
            .into()
    }

    /// A key event for one UTF-16 unit.
    fn key(down: bool, unit: u16) -> INPUT_RECORD {
        INPUT_RECORD {
            EventType: KEY_EVENT as u16,
            Event: INPUT_RECORD_0 {
                KeyEvent: KEY_EVENT_RECORD {
                    bKeyDown: i32::from(down),
                    wRepeatCount: 1,
                    wVirtualKeyCode: 0,
                    wVirtualScanCode: 0,
                    uChar: KEY_EVENT_RECORD_0 { UnicodeChar: unit },
                    dwControlKeyState: 0,
                },
            },
        }
    }

    fn mode_of(input: &OwnedHandle) -> u32 {
        let mut mode = 0_u32;
        // SAFETY: the handle is open for as long as `input` is, and `mode` is a live `u32`.
        assert_ne!(
            unsafe { GetConsoleMode(input.as_raw_handle().cast(), &raw mut mode) },
            0,
            "the modes are read"
        );
        mode
    }

    /// A prompt is not entered when the console's waiting input cannot be thrown away, and the
    /// console's modes are as they were found. A handle cannot lack only that right, because setting
    /// the modes needs write access too (the system says "permission denied"), so the failure comes
    /// in through the way the input is thrown away.
    #[test]
    fn a_console_whose_waiting_input_cannot_be_thrown_away_is_not_entered() {
        let _alone = CONSOLE.lock().unwrap_or_else(PoisonError::into_inner);
        let input = console_input(true);
        let before = mode_of(&input);
        let refused = Prompt::enter_with(input.try_clone().expect("a copy of the handle"), |_| {
            Err(std::io::Error::from_raw_os_error(5))
        })
        .err()
        .expect("the prompt is not entered");
        assert!(
            refused.to_string().contains("could not be thrown away"),
            "{refused}"
        );
        assert_eq!(mode_of(&input), before, "the modes are as they were found");
    }

    /// A prompt that could not throw the waiting input away is not counted as left, so that
    /// dropping it tries again.
    #[test]
    fn a_prompt_that_could_not_throw_the_waiting_input_away_is_not_counted_as_left() {
        let _alone = CONSOLE.lock().unwrap_or_else(PoisonError::into_inner);
        let input = console_input(true);
        let saved = mode_of(&input);
        let mut prompt = Prompt::holding(input, saved);
        let error = prompt
            .leave_with(|_| Err(std::io::Error::from_raw_os_error(5)))
            .expect_err("leaving is refused");
        assert!(
            error.to_string().contains("could not be thrown away"),
            "{error}"
        );
        assert!(!prompt.restored, "a prompt that kept its input is not left");
    }

    /// A paste after the blank line arrives as key releases and modifier keys that carry no
    /// character, as much as of text. A read that came back with only those has not seen the input
    /// stop: it reads on, and says that nothing came only after a turn with no record at all.
    #[test]
    fn a_read_goes_on_past_records_with_no_character_until_the_input_is_quiet() {
        let _alone = CONSOLE.lock().unwrap_or_else(PoisonError::into_inner);
        let mut prompt = Prompt::enter_on(console_input(true)).expect("a prompt on the console");
        let writer = console_input(true);
        let inject = |records: &[INPUT_RECORD]| {
            let mut written = 0_u32;
            // SAFETY: the handle is open for as long as `writer` is, the records are as many as
            // the call is told, and `written` is a live `u32`.
            let done = unsafe {
                WriteConsoleInputW(
                    writer.as_raw_handle().cast(),
                    records.as_ptr(),
                    records.len() as u32,
                    &raw mut written,
                )
            };
            assert_ne!(done, 0, "the records are written");
            assert_eq!(written as usize, records.len());
        };

        // A key release first, which holds no character, and the text a little later.
        inject(&[key(false, u16::from(b'a'))]);
        let mut buffer = [0_u8; 16];
        std::thread::scope(|scope| {
            scope.spawn(|| {
                std::thread::sleep(std::time::Duration::from_millis(50));
                inject(&[key(true, u16::from(b'x')), key(false, u16::from(b'x'))]);
            });
            let taken = prompt.read(&mut buffer).expect("reads the console");
            assert_eq!(&buffer[..taken], b"x", "the text that followed the release");
        });
        // No record came in a whole turn: the read says so.
        assert_eq!(prompt.read(&mut buffer).expect("reads the console"), 0);
    }

    /// The most one read can bring into a prompt fits the room it was given before any secret was
    /// read, so what it holds never moves to a new allocation and leaves the old one behind.
    #[test]
    fn the_longest_read_fits_the_room_a_prompt_made_before_any_secret() {
        let nowhere: OwnedHandle = File::options()
            .read(true)
            .write(true)
            .open("NUL")
            .expect("opens the null device")
            .into();
        let mut prompt = Prompt::holding(nowhere, 0);
        // There is no console to put back.
        prompt.restored = true;
        assert!(
            prompt.pending.capacity() >= PENDING_BOUND,
            "room is made first"
        );
        let room = (prompt.pending.as_ptr(), prompt.pending.capacity());
        // Every record at its repeat limit, every character four bytes: U+1F600.
        for _ in 0..RECORDS * usize::from(MAX_REPEAT) {
            prompt.take(0xD83D);
            prompt.take(0xDE00);
        }
        assert_eq!(prompt.pending.len(), PENDING_BOUND);
        assert_eq!(
            (prompt.pending.as_ptr(), prompt.pending.capacity()),
            room,
            "what a prompt holds does not move"
        );
    }

    /// The input records of a read hold the kit's characters and are cleared when the read ends.
    #[test]
    fn the_input_records_of_a_read_are_cleared_when_it_ends() {
        let mut array = [key(true, u16::from(b'K')); RECORDS];
        drop(Clearing(&mut array));
        // SAFETY: a record is plain data, and the array is whole and still alive.
        let bytes = unsafe {
            std::slice::from_raw_parts(array.as_ptr().cast::<u8>(), std::mem::size_of_val(&array))
        };
        assert!(
            bytes.iter().all(|byte| *byte == 0),
            "a record still held a character"
        );
    }

    /// Setup declines Windows Error Reporting and installs the filter that ends the process at
    /// once. The test puts both back as it found them.
    #[test]
    fn setup_keeps_the_process_out_of_windows_error_reporting() {
        // SAFETY: the calls read and set this test process's own error mode and filter.
        let before = unsafe { GetErrorMode() };
        keep_out_of_a_dump().expect("the guard takes");
        // SAFETY: as above.
        let (during, filter) = unsafe {
            let during = GetErrorMode();
            let filter = SetUnhandledExceptionFilter(None);
            SetErrorMode(before);
            (during, filter)
        };
        assert_eq!(
            during & SEM_NOGPFAULTERRORBOX,
            SEM_NOGPFAULTERRORBOX,
            "Windows Error Reporting is declined"
        );
        assert_eq!(
            filter.map(|filter| filter as *const () as usize),
            Some(end_at_once as *const () as usize),
            "an unhandled exception ends the process at once"
        );
    }
}
