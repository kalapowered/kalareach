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
use windows_sys::Win32::System::Console::{
    FlushConsoleInputBuffer, GetConsoleMode, SetConsoleMode,
};
use windows_sys::Win32::System::Diagnostics::Debug::{
    EXCEPTION_POINTERS, GetErrorMode, SEM_FAILCRITICALERRORS, SEM_NOGPFAULTERRORBOX,
    SEM_NOOPENFILEERRORBOX, SetErrorMode, SetUnhandledExceptionFilter,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, TerminateProcess};

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

#[cfg(test)]
mod tests {
    use super::*;

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
