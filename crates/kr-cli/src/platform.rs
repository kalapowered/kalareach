//! The one module in this crate that calls the operating system directly.
//!
//! Two things have no safe interface in the standard library, and no higher-level library exposes
//! them in the form this command needs:
//!
//! * **Ignoring the background-write signal.** A guard that restores a terminal acts from the
//!   background, where changing terminal state is stopped by `SIGTTOU`. Catching the signal is not
//!   enough; the call still fails. The disposition has to be `SIG_IGN`, which needs `signal(2)`.
//! * **Reading and restoring a console's exact mode.** The Windows guard carries the mode words
//!   across a process boundary, which the terminal libraries do not expose.
//!
//! Every such call is wrapped once, here. Nothing else in this crate relaxes the workspace's rule
//! against unsafe code, and each wrapper documents what makes its call sound.

#![expect(
    unsafe_code,
    reason = "signal dispositions and console modes have no safe interface"
)]

/// Ignores the signal that stops a background process from changing the terminal.
///
/// POSIX is explicit: `tcsetattr` from a background process succeeds when `SIGTTOU` is blocked or
/// ignored, and is stopped otherwise. A handler that merely records the signal leaves the call
/// failing, which is why this sets the disposition rather than registering anything.
///
/// # Errors
///
/// Returns the platform's failure when the disposition cannot be set.
#[cfg(unix)]
pub fn ignore_background_write_signal() -> std::io::Result<()> {
    // SAFETY: `SIG_IGN` is a disposition, not a handler function, so nothing runs in a signal
    // context and there is no async-signal-safety obligation to meet. The call has no other
    // effect on this process.
    let previous = unsafe { libc::signal(libc::SIGTTOU, libc::SIG_IGN) };
    if previous == libc::SIG_ERR {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Ignores the signal that stops a background process from changing the terminal.
///
/// Windows has no job-control signal: a process that is not in the foreground can still set its
/// console's mode.
///
/// # Errors
///
/// Never fails.
#[cfg(not(unix))]
pub const fn ignore_background_write_signal() -> std::io::Result<()> {
    Ok(())
}

#[cfg(not(unix))]
pub use console::{ControllingTerminal, SavedModes};

#[cfg(not(unix))]
mod console {
    use std::fs::File;

    use crate::error::{CliError, Result};
    use crate::terminal::{KeyboardState, Probe, RESET_SEQUENCES, TerminalSize};

    /// A handle on this process's console.
    ///
    /// Windows has no controlling terminal and no `termios`. What it has is a console whose input
    /// and output modes are read and set through the console API, and that pair of mode words is
    /// the state a guard restores.
    #[derive(Debug)]
    pub struct ControllingTerminal {
        input: File,
        output: File,
    }

    impl ControllingTerminal {
        /// Opens this process's console.
        ///
        /// # Errors
        ///
        /// Returns [`CliError::NotATerminal`] when this process has no console.
        pub fn open() -> Result<Self> {
            let input = File::options()
                .read(true)
                .write(true)
                .open("CONIN$")
                .map_err(|_| CliError::NotATerminal)?;
            let output = File::options()
                .read(true)
                .write(true)
                .open("CONOUT$")
                .map_err(|_| CliError::NotATerminal)?;
            Ok(Self { input, output })
        }

        /// Returns the console's input handle, which is the one bytes are read from.
        #[must_use]
        pub const fn handle(&self) -> &File {
            &self.input
        }

        /// Returns the console's output handle.
        #[must_use]
        pub const fn output(&self) -> &File {
            &self.output
        }

        /// Reads the console's current modes.
        ///
        /// # Errors
        ///
        /// Returns an error when the console will not answer.
        pub fn modes(&self) -> Result<SavedModes> {
            Ok(SavedModes {
                input: console_mode(&self.input)?,
                output: console_mode(&self.output)?,
            })
        }

        /// Reads the console's size.
        ///
        /// # Errors
        ///
        /// Returns an error when the console will not answer.
        pub fn size(&self) -> Result<TerminalSize> {
            use std::os::windows::io::AsRawHandle as _;

            let mut info = windows_sys::Win32::System::Console::CONSOLE_SCREEN_BUFFER_INFO {
                dwSize: windows_sys::Win32::System::Console::COORD { X: 0, Y: 0 },
                dwCursorPosition: windows_sys::Win32::System::Console::COORD { X: 0, Y: 0 },
                wAttributes: 0,
                srWindow: windows_sys::Win32::System::Console::SMALL_RECT {
                    Left: 0,
                    Top: 0,
                    Right: 0,
                    Bottom: 0,
                },
                dwMaximumWindowSize: windows_sys::Win32::System::Console::COORD { X: 0, Y: 0 },
            };
            let ok = unsafe_free_get_console_screen_buffer_info(
                self.output.as_raw_handle(),
                &raw mut info,
            );
            if !ok {
                return Err(CliError::Terminal(
                    "read the console's size: the console did not answer".to_owned(),
                ));
            }
            let columns = info.srWindow.Right.saturating_sub(info.srWindow.Left) + 1;
            let rows = info.srWindow.Bottom.saturating_sub(info.srWindow.Top) + 1;
            Ok(TerminalSize {
                columns: u16::try_from(columns).unwrap_or(80),
                rows: u16::try_from(rows).unwrap_or(24),
            })
        }

        /// Puts the console into the mode a forwarded terminal needs, and returns what it replaced.
        ///
        /// # Errors
        ///
        /// Returns an error when the modes cannot be read or set.
        pub fn enter_raw_mode(&self) -> Result<SavedModes> {
            use windows_sys::Win32::System::Console::{
                DISABLE_NEWLINE_AUTO_RETURN, ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT,
                ENABLE_PROCESSED_INPUT, ENABLE_VIRTUAL_TERMINAL_INPUT,
                ENABLE_VIRTUAL_TERMINAL_PROCESSING,
            };

            let saved = self.modes()?;
            let raw_input = (saved.input
                & !(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT))
                | ENABLE_VIRTUAL_TERMINAL_INPUT;
            let raw_output =
                saved.output | ENABLE_VIRTUAL_TERMINAL_PROCESSING | DISABLE_NEWLINE_AUTO_RETURN;
            set_console_mode(&self.input, raw_input)?;
            set_console_mode(&self.output, raw_output)?;
            Ok(saved)
        }

        /// Restores saved modes and undoes the modes an application may have left enabled.
        ///
        /// `keyboard` is what this console had negotiated before the attachment began, written
        /// after the entry this attachment pushed comes off.
        ///
        /// # Errors
        ///
        /// Returns an error when the modes cannot be set.
        pub fn restore(&self, saved: &SavedModes, keyboard: Option<&KeyboardState>) -> Result<()> {
            use std::io::Write as _;

            set_console_mode(&self.input, saved.input)?;
            set_console_mode(&self.output, saved.output)?;
            let mut handle = &self.output;
            let _ = handle.write_all(RESET_SEQUENCES);
            if let Some(keyboard) = keyboard {
                let _ = handle.write_all(&keyboard.cleanup_sequences());
            }
            let _ = handle.flush();
            Ok(())
        }

        /// Runs the bounded capability handshake.
        ///
        /// The console host answers neither keyboard query: the Kitty protocol and
        /// `modifyOtherKeys` are terminal protocols, and the console mode has no equivalent to
        /// read. An attachment here therefore has nothing to put back, and the clearing in
        /// [`RESET_SEQUENCES`] is the whole restoration.
        ///
        /// # Errors
        ///
        /// Never fails; the result matches the shape the other platform's answer has.
        pub const fn probe(&self) -> Result<Probe> {
            Ok(Probe::unasked())
        }
    }

    /// A console's complete state: the input mode and the output mode.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct SavedModes {
        /// The console input mode.
        pub input: u32,
        /// The console output mode.
        pub output: u32,
    }

    impl SavedModes {
        /// Returns the state as it already is.
        ///
        /// The console reports its modes as two words, so reading them and saving them are the
        /// same step; the Unix side has to extract its state from a larger structure, which is why
        /// both platforms answer the same call.
        #[must_use]
        pub const fn from_state(modes: &Self) -> Self {
            *modes
        }

        /// Renders the state as one argument.
        #[must_use]
        pub fn encode(&self) -> String {
            format!("{:x}:{:x}", self.input, self.output)
        }

        /// Parses the state back.
        ///
        /// # Errors
        ///
        /// Returns an error when the text is not two hexadecimal words.
        pub fn decode(text: &str) -> Result<Self> {
            let mut parts = text.split(':');
            let mut next = || -> Result<u32> {
                let part = parts.next().ok_or_else(|| {
                    CliError::Terminal("the saved console state is incomplete".to_owned())
                })?;
                u32::from_str_radix(part, 16).map_err(|_| {
                    CliError::Terminal("the saved console state is not hexadecimal".to_owned())
                })
            };
            let modes = Self {
                input: next()?,
                output: next()?,
            };
            if parts.next().is_some() {
                return Err(CliError::Terminal(
                    "the saved console state has more fields than expected".to_owned(),
                ));
            }
            Ok(modes)
        }
    }

    fn console_mode(handle: &File) -> Result<u32> {
        use std::os::windows::io::AsRawHandle as _;

        let mut mode = 0_u32;
        if unsafe_free_get_console_mode(handle.as_raw_handle(), &raw mut mode) {
            Ok(mode)
        } else {
            Err(CliError::Terminal(
                "read the console's mode: the console did not answer".to_owned(),
            ))
        }
    }

    fn set_console_mode(handle: &File, mode: u32) -> Result<()> {
        use std::os::windows::io::AsRawHandle as _;

        if unsafe_free_set_console_mode(handle.as_raw_handle(), mode) {
            Ok(())
        } else {
            Err(CliError::Terminal(
                "set the console's mode: the console refused".to_owned(),
            ))
        }
    }

    // The three console calls this module needs, each wrapped once. The wrappers exist so the
    // pointer handling is in one place rather than at every call site.
    fn unsafe_free_get_console_mode(handle: std::os::windows::raw::HANDLE, mode: *mut u32) -> bool {
        // SAFETY: `handle` comes from an open console file and `mode` points at a live `u32`.
        unsafe { windows_sys::Win32::System::Console::GetConsoleMode(handle.cast(), mode) != 0 }
    }

    fn unsafe_free_set_console_mode(handle: std::os::windows::raw::HANDLE, mode: u32) -> bool {
        // SAFETY: `handle` comes from an open console file.
        unsafe { windows_sys::Win32::System::Console::SetConsoleMode(handle.cast(), mode) != 0 }
    }

    fn unsafe_free_get_console_screen_buffer_info(
        handle: std::os::windows::raw::HANDLE,
        info: *mut windows_sys::Win32::System::Console::CONSOLE_SCREEN_BUFFER_INFO,
    ) -> bool {
        // SAFETY: `handle` comes from an open console file and `info` points at a live structure.
        unsafe {
            windows_sys::Win32::System::Console::GetConsoleScreenBufferInfo(handle.cast(), info)
                != 0
        }
    }
}
