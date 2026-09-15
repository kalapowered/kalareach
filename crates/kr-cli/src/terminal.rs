//! The outer terminal: raw mode, size, and the guard that restores it whatever happens.
//!
//! Section 8 is unambiguous: a broken connection cannot leave the user's terminal in raw mode, and
//! the restoration has to survive the attach process being killed. An in-process handler cannot do
//! that, because `SIGKILL` runs no handler at all.
//!
//! So the saved terminal state lives in a **separate process**. Before `kr attach` touches the
//! terminal it starts a small guard and hands it two things: one end of a pipe, and its own handle
//! on the controlling terminal. The guard then blocks on the pipe.
//!
//! * If the attach process exits normally it restores the terminal itself and writes one byte to
//!   the pipe, which tells the guard to leave without acting.
//! * If the attach process dies for any other reason — a crash, `SIGKILL`, the machine running out
//!   of memory — the operating system closes its end of the pipe. The guard's read returns end of
//!   file, and it restores the terminal from the state it is holding.
//!
//! The guard runs in its own session, so it has no controlling terminal of its own and changing
//! the inherited one does not stop it with `SIGTTOU`.
//!
//! What no mechanism can promise is recovery after the terminal emulator itself dies. There is
//! nothing left to restore.

use std::fs::File;

use rustix::termios::{OptionalActions, Termios, Winsize};

use crate::error::{CliError, Result};

/// The escape sequences that undo the modes a full-screen application may have enabled.
///
/// A detach restores the saved terminal modes and then sends these, because an application that
/// was killed never got the chance to turn its own modes off.
pub const RESET_SEQUENCES: &[u8] =
    b"\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l\x1b[?1049l\x1b[?2004l\x1b[?25h\x1b[?1l\x1b>";

/// A handle on this process's controlling terminal.
#[derive(Debug)]
pub struct ControllingTerminal {
    handle: File,
}

impl ControllingTerminal {
    /// Opens the terminal this command is attached to.
    ///
    /// The command's own standard input is preferred, because that is the terminal whose bytes it
    /// forwards and whose modes it changes. `/dev/tty` is the fallback for a command whose input
    /// has been redirected but which still has a controlling terminal.
    ///
    /// # Errors
    ///
    /// Returns [`CliError::NotATerminal`] when neither is a terminal.
    pub fn open() -> Result<Self> {
        use std::os::fd::AsFd as _;

        let standard_input = std::io::stdin();
        if rustix::termios::isatty(&standard_input)
            && let Ok(duplicate) = standard_input.as_fd().try_clone_to_owned()
        {
            return Ok(Self {
                handle: File::from(duplicate),
            });
        }
        let handle = File::options()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .map_err(|_| CliError::NotATerminal)?;
        Ok(Self { handle })
    }

    /// Returns the terminal handle.
    #[must_use]
    pub const fn handle(&self) -> &File {
        &self.handle
    }

    /// Reads the terminal's current modes.
    ///
    /// # Errors
    ///
    /// Returns an error when the modes cannot be read.
    pub fn modes(&self) -> Result<Termios> {
        rustix::termios::tcgetattr(&self.handle)
            .map_err(|error| CliError::Terminal(format!("read the terminal's modes: {error}")))
    }

    /// Reads the terminal's size.
    ///
    /// # Errors
    ///
    /// Returns an error when the size cannot be read.
    pub fn size(&self) -> Result<Winsize> {
        rustix::termios::tcgetwinsize(&self.handle)
            .map_err(|error| CliError::Terminal(format!("read the terminal's size: {error}")))
    }

    /// Puts the terminal into raw mode and returns the modes that were replaced.
    ///
    /// # Errors
    ///
    /// Returns an error when the modes cannot be read or set.
    pub fn enter_raw_mode(&self) -> Result<Termios> {
        let saved = self.modes()?;
        let mut raw = saved.clone();
        raw.make_raw();
        rustix::termios::tcsetattr(&self.handle, OptionalActions::Flush, &raw)
            .map_err(|error| CliError::Terminal(format!("set the terminal's modes: {error}")))?;
        Ok(saved)
    }

    /// Restores saved modes and undoes the modes an application may have left enabled.
    ///
    /// # Errors
    ///
    /// Returns an error when the modes cannot be set.
    pub fn restore(&self, saved: &Termios) -> Result<()> {
        use std::io::Write as _;

        rustix::termios::tcsetattr(&self.handle, OptionalActions::Flush, saved).map_err(
            |error| CliError::Terminal(format!("restore the terminal's modes: {error}")),
        )?;
        let mut handle = &self.handle;
        let _ = handle.write_all(RESET_SEQUENCES);
        let _ = handle.flush();
        Ok(())
    }
}

/// The four mode words of a terminal, in the form the guard is given them.
///
/// The guard reads the terminal's current state for everything else and applies these, so the
/// exact layout of the platform's structure never has to cross a process boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SavedModes {
    /// Input modes.
    pub input: u64,
    /// Output modes.
    pub output: u64,
    /// Control modes.
    pub control: u64,
    /// Local modes, which carry canonical mode and echo.
    pub local: u64,
}

impl SavedModes {
    /// Reads the four words out of a terminal's modes.
    #[must_use]
    #[expect(
        clippy::useless_conversion,
        reason = "the mode words are 32-bit on some platforms and 64-bit on others"
    )]
    pub fn from_termios(modes: &Termios) -> Self {
        Self {
            // The bit widths differ between platforms, so each word is widened to the form the
            // argument carries rather than assumed to be one size.
            input: u64::from(modes.input_modes.bits()),
            output: u64::from(modes.output_modes.bits()),
            control: u64::from(modes.control_modes.bits()),
            local: u64::from(modes.local_modes.bits()),
        }
    }

    /// Writes the four words into a terminal's modes.
    pub fn apply(self, modes: &mut Termios) {
        modes.input_modes = rustix::termios::InputModes::from_bits_retain(self.input as _);
        modes.output_modes = rustix::termios::OutputModes::from_bits_retain(self.output as _);
        modes.control_modes = rustix::termios::ControlModes::from_bits_retain(self.control as _);
        modes.local_modes = rustix::termios::LocalModes::from_bits_retain(self.local as _);
    }

    /// Renders the words as one argument.
    #[must_use]
    pub fn encode(self) -> String {
        format!(
            "{:x}:{:x}:{:x}:{:x}",
            self.input, self.output, self.control, self.local
        )
    }

    /// Parses the words back.
    ///
    /// # Errors
    ///
    /// Returns an error when the text is not four hexadecimal words.
    pub fn decode(text: &str) -> Result<Self> {
        let mut parts = text.split(':');
        let mut next = || -> Result<u64> {
            let part = parts
                .next()
                .ok_or_else(|| CliError::Terminal("the saved modes are incomplete".to_owned()))?;
            u64::from_str_radix(part, 16)
                .map_err(|_| CliError::Terminal("the saved modes are not hexadecimal".to_owned()))
        };
        let modes = Self {
            input: next()?,
            output: next()?,
            control: next()?,
            local: next()?,
        };
        if parts.next().is_some() {
            return Err(CliError::Terminal(
                "the saved modes have more words than expected".to_owned(),
            ));
        }
        Ok(modes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saved_modes_round_trip_through_their_argument_form() {
        let modes = SavedModes {
            input: 0x2b02,
            output: 0x3,
            control: 0x4b00,
            local: 0x5cf,
        };
        assert_eq!(SavedModes::decode(&modes.encode()).expect("decodes"), modes);
    }

    #[test]
    fn malformed_saved_modes_are_refused() {
        assert!(SavedModes::decode("1:2:3").is_err());
        assert!(SavedModes::decode("1:2:3:4:5").is_err());
        assert!(SavedModes::decode("z:2:3:4").is_err());
    }

    #[test]
    fn the_reset_sequences_turn_off_the_modes_an_application_may_have_left() {
        let text = String::from_utf8_lossy(RESET_SEQUENCES);
        for sequence in ["?1000l", "?1006l", "?1049l", "?2004l", "?25h"] {
            assert!(text.contains(sequence), "{sequence} is undone");
        }
    }
}
