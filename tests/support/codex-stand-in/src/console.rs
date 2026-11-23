//! The Windows console's twin of the Unix terminal's modes.
//!
//! A person's keys reach a program on a console as events, unless the input is asked to carry
//! them as the escape sequences a terminal sends. Reading keys one at a time, unechoed and with
//! the sequences a terminal sends, takes the input mode the pseudo-console of the managed shell
//! offers: line input and echo off, and virtual terminal input on. The output must take the
//! sequences the composer writes, so its virtual terminal processing is on while the keys are read.
//! Both modes are put back when the guard goes.

#![expect(
    unsafe_code,
    reason = "reading and setting a console's modes and size have no safe form"
)]

use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Console::{
    CONSOLE_MODE, CONSOLE_SCREEN_BUFFER_INFO, ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT,
    ENABLE_VIRTUAL_TERMINAL_INPUT, ENABLE_VIRTUAL_TERMINAL_PROCESSING, GetConsoleMode,
    GetConsoleScreenBufferInfo, GetStdHandle, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, SetConsoleMode,
};

/// The modes of the console as they were, put back when this goes.
pub struct Raw {
    input: HANDLE,
    input_mode: CONSOLE_MODE,
    /// The output handle and its mode, where the output is a console too.
    output: Option<(HANDLE, CONSOLE_MODE)>,
}

/// The handle of a standard stream, where the process has one.
fn standard(which: u32) -> Option<HANDLE> {
    // SAFETY: the call reads no memory of ours.
    let handle = unsafe { GetStdHandle(which) };
    (!handle.is_null() && handle != INVALID_HANDLE_VALUE).then_some(handle)
}

/// The mode of a console handle, where the handle is a console's.
fn mode_of(handle: HANDLE) -> Option<CONSOLE_MODE> {
    let mut mode: CONSOLE_MODE = 0;
    // SAFETY: the mode is a local the call fills; a handle that is not a console's fails the call.
    (unsafe { GetConsoleMode(handle, &raw mut mode) } != 0).then_some(mode)
}

impl Raw {
    /// Puts standard input into the mode keys are read in, one at a time, not shown by the
    /// console itself and as the sequences a terminal sends, where it is a console.
    pub fn enter() -> Option<Self> {
        let input = standard(STD_INPUT_HANDLE)?;
        let input_mode = mode_of(input)?;
        // Processed input stays on, as the signal keys stay on in the Unix terminal's mode.
        let keys =
            (input_mode & !(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT)) | ENABLE_VIRTUAL_TERMINAL_INPUT;
        // SAFETY: the handle is the process's own standard input, open for the call.
        if unsafe { SetConsoleMode(input, keys) } == 0 {
            return None;
        }
        let output = standard(STD_OUTPUT_HANDLE).and_then(|handle| {
            let mode = mode_of(handle)?;
            // SAFETY: the handle is the process's own standard output, open for the call.
            (unsafe { SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) } != 0)
                .then_some((handle, mode))
        });
        Some(Self {
            input,
            input_mode,
            output,
        })
    }

    /// How many columns the console's window has, read from the output handle.
    pub fn columns(&self) -> Option<usize> {
        let (output, _) = self.output?;
        // SAFETY: all zeroes is a valid state of the structure, which the call then fills.
        let mut information: CONSOLE_SCREEN_BUFFER_INFO = unsafe { std::mem::zeroed() };
        // SAFETY: the handle is the process's own standard output, open for the call, and the
        // structure is a local.
        if unsafe { GetConsoleScreenBufferInfo(output, &raw mut information) } == 0 {
            return None;
        }
        let window = information.srWindow;
        usize::try_from(i32::from(window.Right) - i32::from(window.Left) + 1).ok()
    }
}

impl Drop for Raw {
    fn drop(&mut self) {
        // SAFETY: the handles are the process's own standard streams, which stay open.
        unsafe {
            SetConsoleMode(self.input, self.input_mode);
            if let Some((output, mode)) = self.output {
                SetConsoleMode(output, mode);
            }
        }
    }
}
