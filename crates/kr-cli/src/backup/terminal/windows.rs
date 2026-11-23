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
use std::os::windows::io::{AsHandle as _, AsRawHandle as _, OwnedHandle};

use kr_client::shown;
use kr_client::shown::Shown;
use windows_sys::Win32::Foundation::{HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows_sys::Win32::System::Console::{
    ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT, ENABLE_PROCESSED_INPUT, ENABLE_VIRTUAL_TERMINAL_INPUT,
    FlushConsoleInputBuffer, GetConsoleMode, INPUT_RECORD, KEY_EVENT, ReadConsoleInputW,
    ReadConsoleW, SetConsoleMode,
};
use windows_sys::Win32::System::Diagnostics::Debug::{
    EXCEPTION_POINTERS, GetErrorMode, SEM_FAILCRITICALERRORS, SEM_NOGPFAULTERRORBOX,
    SEM_NOOPENFILEERRORBOX, SetErrorMode, SetUnhandledExceptionFilter,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, TerminateProcess, WaitForSingleObject,
};
use zeroize::Zeroizing;

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

/// The failure to change the console's modes.
fn modes_not_changed(error: &std::io::Error) -> CliError {
    CliError::Terminal(shown!(
        "the console's modes could not be changed: {}",
        Shown::io(error)
    ))
}

/// Throws away the input waiting on the console, or says that it could not.
fn discard(handle: HANDLE) -> Result<()> {
    // SAFETY: the caller's handle is open for the length of the call.
    if unsafe { FlushConsoleInputBuffer(handle) } == 0 {
        return Err(CliError::Terminal(shown!(
            "the console's waiting input could not be thrown away: {}",
            Shown::io(&std::io::Error::last_os_error())
        )));
    }
    Ok(())
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

/// The console's modes while the kit is typed: no echo, no line editing, and a read that returns
/// after a fifth of a second with or without input. Processed input stays, so Ctrl-C is still an
/// interrupt.
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
        let input = std::io::stdin()
            .as_handle()
            .try_clone_to_owned()
            .map_err(|error| modes_not_changed(&error))?;
        Self::enter_on(input)
    }

    /// As [`Self::enter`], on the console input `input`.
    fn enter_on(input: OwnedHandle) -> Result<Self> {
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
        let prompt = Self {
            input,
            saved,
            restored: false,
            high: None,
            pending: Zeroizing::new(Vec::new()),
        };
        // What was typed before this prompt was shown was echoed, and is not part of the kit. If it
        // cannot be thrown away the prompt is not entered: dropping it puts the modes back.
        discard(handle)?;
        Ok(prompt)
    }

    /// Puts the modes back, discarding the input still waiting: what was pasted past the end of the
    /// kit is not for the shell.
    ///
    /// # Errors
    ///
    /// Returns a terminal failure when the modes cannot be put back.
    pub fn leave(&mut self) -> Result<()> {
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
        discard(handle)?;
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
        if self.pending.is_empty() {
            self.fill()?;
        }
        let taken = buffer.len().min(self.pending.len());
        buffer[..taken].copy_from_slice(&self.pending[..taken]);
        self.pending.drain(..taken);
        Ok(taken)
    }

    /// Waits one turn for the console's input and takes the characters of the key events in it.
    fn fill(&mut self) -> std::io::Result<()> {
        let handle = self.input.as_raw_handle().cast();
        // SAFETY: the handle is open for as long as `self.input` is.
        match unsafe { WaitForSingleObject(handle, TURN_MILLISECONDS) } {
            WAIT_OBJECT_0 => {}
            WAIT_TIMEOUT => return Ok(()),
            _ => return Err(std::io::Error::last_os_error()),
        }
        // SAFETY: an all-zero record is a valid value of the type, which is plain data.
        let mut records: [INPUT_RECORD; RECORDS] = unsafe { std::mem::zeroed() };
        let mut count = 0_u32;
        // SAFETY: the buffer holds `RECORDS` records, which is what the call is told, and `count`
        // is a live `u32`. The signalled handle has an event, so the call does not wait.
        if unsafe {
            ReadConsoleInputW(handle, records.as_mut_ptr(), RECORDS as u32, &raw mut count)
        } == 0
        {
            return Err(std::io::Error::last_os_error());
        }
        for record in &records[..count as usize] {
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
            for _ in 0..key.wRepeatCount.clamp(1, 16) {
                self.take(unit);
            }
        }
        Ok(())
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

/// Reads one line from the console on standard input, with echo on: `None` at the end of the input
/// (Ctrl-Z) and for a line of nothing.
///
/// # Errors
///
/// Returns the error that reading the console gave.
pub fn read_line() -> std::io::Result<Option<String>> {
    /// An answer is a word; this is more than any answer needs.
    const LONGEST_ANSWER: usize = 4096;

    let handle = std::io::stdin().as_raw_handle().cast();
    let mut units: Zeroizing<Vec<u16>> = Zeroizing::new(Vec::new());
    let mut chunk = Zeroizing::new([0_u16; 256]);
    loop {
        let mut read = 0_u32;
        // SAFETY: the buffer holds 256 units, which is what the call is told, and `read` is a live
        // `u32`. No input control is given.
        if unsafe {
            ReadConsoleW(
                handle,
                chunk.as_mut_ptr().cast(),
                chunk.len() as u32,
                &raw mut read,
                std::ptr::null(),
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error());
        }
        if read == 0 {
            break;
        }
        units.extend_from_slice(&chunk[..read as usize]);
        if units.contains(&0x0A) || units.len() >= LONGEST_ANSWER {
            break;
        }
    }
    // Ctrl-Z ends the input, where a line of text ends at its first line end.
    if units.is_empty() || units.first() == Some(&0x1A) {
        return Ok(None);
    }
    let line = units.split(|unit| *unit == 0x0A).next().unwrap_or_default();
    let line = line.strip_suffix(&[0x0D]).unwrap_or(line);
    Ok(Some(String::from_utf16_lossy(line)))
}

#[cfg(test)]
mod tests {
    use std::sync::{Mutex, PoisonError};

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

    /// A prompt on a console whose input cannot be thrown away is not entered, and the console's
    /// modes are as they were found.
    #[test]
    fn a_console_whose_waiting_input_cannot_be_thrown_away_is_not_entered() {
        let _alone = CONSOLE.lock().unwrap_or_else(PoisonError::into_inner);
        let input = console_input(false);
        let before = mode_of(&input);
        let refused = Prompt::enter_on(input.try_clone().expect("a copy of the handle"))
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
        let input = console_input(false);
        let saved = mode_of(&input);
        let mut prompt = Prompt {
            input,
            saved,
            restored: false,
            high: None,
            pending: Zeroizing::new(Vec::new()),
        };
        let error = prompt.leave().expect_err("leaving is refused");
        assert!(
            error.to_string().contains("could not be thrown away"),
            "{error}"
        );
        assert!(!prompt.restored, "a prompt that kept its input is not left");
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
