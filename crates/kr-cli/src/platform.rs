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

/// Ends this process the way `signal` would have ended it had nothing handled it: the signal's
/// default action is restored and the signal is sent to this process, so that whatever started it
/// reads a death by that signal and not an exit status.
///
/// Only a process that has caught `signal` and finished what it owed calls this.
#[cfg(unix)]
pub fn end_by_signal(signal: std::os::raw::c_int) -> ! {
    // SAFETY: `SIG_DFL` is a disposition, not a handler function, so nothing runs in a signal
    // context; `raise` sends the signal to this process only.
    unsafe {
        libc::signal(signal, libc::SIG_DFL);
        libc::raise(signal);
    }
    // The signal was blocked or ignored: the conventional status of a process it ended.
    std::process::exit(128 + signal)
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

/// Ends the read `thread` is blocked in on the console, so that the thread goes on to see that it
/// has been asked to stop.
///
/// A read of the console's text cannot be woken by anything else the thread waits on. The call is a
/// request: the thread is not joined after it, because a console that did not honour it would hold
/// the joiner for good. It says whether the system took the request, which it does not for a thread
/// paused between two calls, and which does not say how the read ended: a read can end by itself as
/// the request arrives.
#[cfg(not(unix))]
pub fn cancel_blocked_read<T>(thread: &std::thread::JoinHandle<T>) -> bool {
    use std::os::windows::io::AsRawHandle as _;

    // SAFETY: the handle is the thread's own, kept open by the `JoinHandle` this borrows, and the
    // call only asks the system to end that thread's pending synchronous I/O.
    unsafe {
        windows_sys::Win32::System::IO::CancelSynchronousIo(thread.as_raw_handle().cast()) != 0
    }
}

#[cfg(not(unix))]
pub use console::{ControllingTerminal, SavedModes};

#[cfg(not(unix))]
mod console {
    use std::fs::File;

    use kr_client::shown::Shown;

    use crate::error::{CliError, Result};
    use crate::terminal::{KeyboardState, Probe, RESET_SEQUENCES, ScreenModes, TerminalSize};

    /// A handle on this process's console.
    ///
    /// Windows has no controlling terminal and no `termios`. What it has is a console whose input
    /// and output modes are read and set through the console API, and that pair of mode words is
    /// the state a guard restores.
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

        /// Returns the console's input handle, which is the one bytes are read from. Nothing is
        /// written to it: a console takes written bytes on its output handle.
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
                return Err(CliError::Terminal(Shown::said(
                    "read the console's size: the console did not answer",
                )));
            }
            let columns = info.srWindow.Right.saturating_sub(info.srWindow.Left) + 1;
            let rows = info.srWindow.Bottom.saturating_sub(info.srWindow.Top) + 1;
            Ok(TerminalSize {
                columns: u16::try_from(columns).unwrap_or(80),
                rows: u16::try_from(rows).unwrap_or(24),
            })
        }

        /// Throws away what has been typed and not yet read.
        ///
        /// # Errors
        ///
        /// Returns an error when the console will not do it.
        pub fn discard_input(&self) -> Result<()> {
            use std::os::windows::io::AsRawHandle as _;

            if unsafe_free_flush_console_input(self.input.as_raw_handle()) {
                Ok(())
            } else {
                Err(CliError::Terminal(Shown::said(
                    "discard the console's queued input: the console refused",
                )))
            }
        }

        /// Puts the console into the mode a command that reads bytes needs, and returns what it
        /// replaced.
        ///
        /// Keys come back as the console's own virtual-terminal sequences.
        ///
        /// # Errors
        ///
        /// Returns an error when the modes cannot be read or set. A console whose output mode
        /// cannot be set is given its input mode back first, so a failure leaves it as it was.
        pub fn enter_raw_mode(&self) -> Result<SavedModes> {
            use windows_sys::Win32::System::Console::{
                ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT, ENABLE_PROCESSED_INPUT,
                ENABLE_VIRTUAL_TERMINAL_INPUT,
            };

            self.enter_mode(|saved| {
                (saved & !(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT))
                    | ENABLE_VIRTUAL_TERMINAL_INPUT
            })
        }

        /// What makes this console spell its keys itself: its virtual-terminal input, which turns
        /// the keys into the sequences a terminal sends. It is asked for on the mode the console
        /// has then, and put back with the rest when the attachment ends.
        ///
        /// # Errors
        ///
        /// Returns an error when the console's input handle cannot be duplicated.
        pub fn input_switch(&self) -> Result<crate::attach::InputSwitch> {
            use windows_sys::Win32::System::Console::ENABLE_VIRTUAL_TERMINAL_INPUT;

            let input = self
                .input
                .try_clone()
                .map_err(|error| CliError::Terminal(Shown::io(&error)))?;
            Ok(crate::attach::InputSwitch::new(move || {
                let mode = console_mode(&input)?;
                set_console_mode(&input, mode | ENABLE_VIRTUAL_TERMINAL_INPUT)
            }))
        }

        /// Puts the console into the mode an attachment needs, and returns what it replaced.
        ///
        /// Keys come back as the records the console reports them as, with no translation into
        /// sequences: the session spells them as its terminal asked for.
        ///
        /// # Errors
        ///
        /// As [`Self::enter_raw_mode`].
        pub fn enter_record_mode(&self) -> Result<SavedModes> {
            self.enter_mode(crate::windows::records::record_input_mode)
        }

        /// Sets the input mode `input` makes of the one the console has and the output mode a
        /// forwarded terminal needs.
        fn enter_mode(&self, input: impl FnOnce(u32) -> u32) -> Result<SavedModes> {
            use windows_sys::Win32::System::Console::{
                DISABLE_NEWLINE_AUTO_RETURN, ENABLE_VIRTUAL_TERMINAL_PROCESSING,
            };

            let saved = self.modes()?;
            let raw_output =
                saved.output | ENABLE_VIRTUAL_TERMINAL_PROCESSING | DISABLE_NEWLINE_AUTO_RETURN;
            set_console_mode(&self.input, input(saved.input))?;
            if let Err(error) = set_console_mode(&self.output, raw_output) {
                let _ = set_console_mode(&self.input, saved.input);
                return Err(error);
            }
            Ok(saved)
        }

        /// Restores saved modes and undoes the modes an application may have left enabled.
        ///
        /// `keyboard` is what this console had negotiated before the attachment began, written
        /// back as the state it is, and `screen` is the mouse, cursor and paste state it reported.
        /// A console answers for neither, so both are usually empty here and the reset block is the
        /// whole restoration.
        ///
        /// # Errors
        ///
        /// Returns an error when the modes cannot be set.
        pub fn restore(
            &self,
            saved: &SavedModes,
            keyboard: Option<&KeyboardState>,
            screen: &ScreenModes,
        ) -> Result<()> {
            use std::io::Write as _;

            set_console_mode(&self.input, saved.input)?;
            set_console_mode(&self.output, saved.output)?;
            let mut handle = &self.output;
            let _ = handle.write_all(RESET_SEQUENCES);
            let _ = handle.write_all(&screen.restore_sequences());
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
        /// Returns [`crate::CliError::TerminalProbeFailed`] on a stream a previous probe
        /// contaminated, which is the same refusal the other platform gives: a console that was
        /// never asked anything is still a console whose input may hold a late reply.
        pub fn probe(
            &self,
            context: kr_term::probe::InputContext,
            _profile: Option<&str>,
        ) -> Result<Probe> {
            Probe::unasked(context)
        }

        /// The same answer for a caller with its own questions: this console is asked none of them.
        ///
        /// # Errors
        ///
        /// Returns [`CliError::TerminalProbeFailed`] when a probe has already gone out here.
        pub fn probe_asking(
            &self,
            context: kr_term::probe::InputContext,
            _asked: &[kr_term::probe::ProbeItem],
        ) -> Result<Probe> {
            Probe::unasked(context)
        }

        /// A name for this console that no other console shares while it exists.
        ///
        /// The console host has no device path and no session identifier of the kind a terminal
        /// has, so there is nothing here to name one by. A probe is never sent to it, so nothing
        /// needs the name.
        #[must_use]
        pub const fn identity(&self) -> Option<String> {
            None
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
                    CliError::Terminal(Shown::said("the saved console state is incomplete"))
                })?;
                u32::from_str_radix(part, 16).map_err(|_| {
                    CliError::Terminal(Shown::said("the saved console state is not hexadecimal"))
                })
            };
            let modes = Self {
                input: next()?,
                output: next()?,
            };
            if parts.next().is_some() {
                return Err(CliError::Terminal(Shown::said(
                    "the saved console state has more fields than expected",
                )));
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
            Err(CliError::Terminal(Shown::said(
                "read the console's mode: the console did not answer",
            )))
        }
    }

    fn set_console_mode(handle: &File, mode: u32) -> Result<()> {
        use std::os::windows::io::AsRawHandle as _;

        if unsafe_free_set_console_mode(handle.as_raw_handle(), mode) {
            Ok(())
        } else {
            Err(CliError::Terminal(Shown::said(
                "set the console's mode: the console refused",
            )))
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

    fn unsafe_free_flush_console_input(handle: std::os::windows::raw::HANDLE) -> bool {
        // SAFETY: `handle` comes from an open console file.
        unsafe { windows_sys::Win32::System::Console::FlushConsoleInputBuffer(handle.cast()) != 0 }
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
