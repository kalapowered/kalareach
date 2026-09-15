//! The outer terminal: raw mode, size, and the guard that restores it whatever happens.
//!
//! Section 8 is unambiguous: a broken connection cannot leave the user's terminal in raw mode, and
//! the restoration has to survive the attach process being killed. An in-process handler cannot do
//! that, because `SIGKILL` runs no handler at all.
//!
//! So the saved terminal state lives in a **separate process**. Before `kr attach` touches the
//! terminal it starts a small guard and hands it three things: one end of a release pipe, one end
//! of a readiness pipe, and its own handle on the controlling terminal. The guard reports that it
//! is holding the state, and only then does the attach process change anything.
//!
//! * If the attach process exits normally it restores the terminal itself and writes one byte to
//!   the release pipe, which tells the guard to leave without acting.
//! * If the attach process dies for any other reason — a crash, `SIGKILL`, the machine running out
//!   of memory — the operating system closes its end of the pipe. The guard's read returns end of
//!   file, and it restores the terminal from the state it is holding.
//!
//! # Why the state is carried in full
//!
//! Terminal state is not four mode words. It is the mode words **and** the control characters:
//! which byte is the interrupt, which is end of file, and the two that decide whether a read waits
//! for a line or returns a byte at a time. Restoring the words alone would give back a terminal
//! whose modes look right and whose Ctrl-C does nothing.
//!
//! # Why `SIGTTOU` is ignored rather than caught
//!
//! By the time the guard acts, its process group is in the background. A background process that
//! changes the terminal is stopped by `SIGTTOU`, and *catching* the signal is not enough on this
//! platform: the call still fails. The signal has to be ignored, so the change goes through.
//!
//! What no mechanism can promise is recovery after the terminal emulator itself dies. There is
//! nothing left to restore.

#[cfg(not(unix))]
pub use crate::platform::{ControllingTerminal, SavedModes};
#[cfg(unix)]
pub use unix::{ControllingTerminal, SavedModes};

/// The escape sequences that undo the modes a full-screen application may have enabled.
///
/// A detach restores the saved terminal modes and then sends these, because an application that
/// was killed never got the chance to turn its own modes off.
pub const RESET_SEQUENCES: &[u8] =
    b"\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l\x1b[?1049l\x1b[?2004l\x1b[?25h\x1b[?1l\x1b>";

/// The size of a terminal, in character cells.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TerminalSize {
    /// Columns.
    pub columns: u16,
    /// Rows.
    pub rows: u16,
}

#[cfg(unix)]
mod unix {
    use std::fs::File;

    use rustix::termios::{OptionalActions, SpecialCodeIndex, Termios, Winsize};

    use super::{RESET_SEQUENCES, TerminalSize};
    use crate::error::{CliError, Result};

    /// A handle on this process's controlling terminal.
    #[derive(Debug)]
    pub struct ControllingTerminal {
        handle: File,
    }

    impl ControllingTerminal {
        /// Opens the terminal this command is attached to.
        ///
        /// The command's own standard input is preferred, because that is the terminal whose bytes
        /// it forwards and whose modes it changes. `/dev/tty` is the fallback for a command whose
        /// input has been redirected but which still has a controlling terminal.
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
        pub fn size(&self) -> Result<TerminalSize> {
            let size: Winsize = rustix::termios::tcgetwinsize(&self.handle).map_err(|error| {
                CliError::Terminal(format!("read the terminal's size: {error}"))
            })?;
            Ok(TerminalSize {
                columns: size.ws_col,
                rows: size.ws_row,
            })
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
            rustix::termios::tcsetattr(&self.handle, OptionalActions::Flush, &raw).map_err(
                |error| CliError::Terminal(format!("set the terminal's modes: {error}")),
            )?;
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

    /// The control characters a restoration carries.
    ///
    /// Every one of these is defined on every Unix this host supports, so the list is the same on
    /// both sides of the process boundary and a saved state means the same thing wherever it is
    /// applied. The interrupt, the end of file and the two that decide whether a read waits for a
    /// line are the ones a person notices immediately when they are lost.
    const CARRIED_CODES: [SpecialCodeIndex; 16] = [
        SpecialCodeIndex::VINTR,
        SpecialCodeIndex::VQUIT,
        SpecialCodeIndex::VERASE,
        SpecialCodeIndex::VKILL,
        SpecialCodeIndex::VEOF,
        SpecialCodeIndex::VTIME,
        SpecialCodeIndex::VMIN,
        SpecialCodeIndex::VSTART,
        SpecialCodeIndex::VSTOP,
        SpecialCodeIndex::VSUSP,
        SpecialCodeIndex::VEOL,
        SpecialCodeIndex::VREPRINT,
        SpecialCodeIndex::VDISCARD,
        SpecialCodeIndex::VWERASE,
        SpecialCodeIndex::VLNEXT,
        SpecialCodeIndex::VEOL2,
    ];

    /// A terminal's complete state, in the form the guard is given it.
    ///
    /// The four mode words and every control character. The words alone would restore a terminal
    /// whose modes look right and whose interrupt key does nothing.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct SavedModes {
        /// Input modes.
        pub input: u64,
        /// Output modes.
        pub output: u64,
        /// Control modes.
        pub control: u64,
        /// Local modes, which carry canonical mode and echo.
        pub local: u64,
        /// The control characters, including the interrupt, the end of file, and the two that
        /// decide whether a read waits for a line.
        pub special: Vec<u8>,
    }

    impl SavedModes {
        /// Reads the complete state out of a terminal's modes.
        #[must_use]
        #[expect(
            clippy::useless_conversion,
            reason = "the mode words are 32-bit on some platforms and 64-bit on others"
        )]
        pub fn from_state(modes: &Termios) -> Self {
            Self {
                // The bit widths differ between platforms, so each word is widened to the form the
                // argument carries rather than assumed to be one size.
                input: u64::from(modes.input_modes.bits()),
                output: u64::from(modes.output_modes.bits()),
                control: u64::from(modes.control_modes.bits()),
                local: u64::from(modes.local_modes.bits()),
                special: CARRIED_CODES
                    .iter()
                    .map(|index| modes.special_codes[*index])
                    .collect(),
            }
        }

        /// Writes the complete state back into a terminal's modes.
        pub fn apply(&self, modes: &mut Termios) {
            modes.input_modes = rustix::termios::InputModes::from_bits_retain(self.input as _);
            modes.output_modes = rustix::termios::OutputModes::from_bits_retain(self.output as _);
            modes.control_modes =
                rustix::termios::ControlModes::from_bits_retain(self.control as _);
            modes.local_modes = rustix::termios::LocalModes::from_bits_retain(self.local as _);
            for (index, value) in CARRIED_CODES.iter().zip(self.special.iter()) {
                modes.special_codes[*index] = *value;
            }
        }

        /// Renders the state as one argument.
        #[must_use]
        pub fn encode(&self) -> String {
            let mut text = format!(
                "{:x}:{:x}:{:x}:{:x}:",
                self.input, self.output, self.control, self.local
            );
            for value in &self.special {
                text.push_str(&format!("{value:02x}"));
            }
            text
        }

        /// Parses the state back.
        ///
        /// # Errors
        ///
        /// Returns an error when the text is not four hexadecimal words and a run of control
        /// characters.
        pub fn decode(text: &str) -> Result<Self> {
            let mut parts = text.split(':');
            let mut next = || -> Result<u64> {
                let part = parts.next().ok_or_else(|| {
                    CliError::Terminal("the saved terminal state is incomplete".to_owned())
                })?;
                u64::from_str_radix(part, 16).map_err(|_| {
                    CliError::Terminal("the saved terminal state is not hexadecimal".to_owned())
                })
            };
            let input = next()?;
            let output = next()?;
            let control = next()?;
            let local = next()?;
            let special = parts.next().ok_or_else(|| {
                CliError::Terminal("the saved terminal state has no control characters".to_owned())
            })?;
            if special.len() % 2 != 0 {
                return Err(CliError::Terminal(
                    "the saved control characters are not whole bytes".to_owned(),
                ));
            }
            let mut codes = Vec::with_capacity(special.len() / 2);
            for index in (0..special.len()).step_by(2) {
                let byte = special.get(index..index + 2).ok_or_else(|| {
                    CliError::Terminal("the saved control characters are truncated".to_owned())
                })?;
                codes.push(u8::from_str_radix(byte, 16).map_err(|_| {
                    CliError::Terminal(
                        "the saved control characters are not hexadecimal".to_owned(),
                    )
                })?);
            }
            if parts.next().is_some() {
                return Err(CliError::Terminal(
                    "the saved terminal state has more fields than expected".to_owned(),
                ));
            }
            Ok(Self {
                input,
                output,
                control,
                local,
                special: codes,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn the_saved_state_round_trips_through_its_argument_form() {
        let modes = SavedModes {
            input: 0x2b02,
            output: 0x3,
            control: 0x4b00,
            local: 0x5cf,
            special: vec![4, 3, 0x7f, 0x15, 1, 0],
        };
        assert_eq!(SavedModes::decode(&modes.encode()).expect("decodes"), modes);
    }

    #[cfg(unix)]
    #[test]
    fn the_control_characters_survive_the_round_trip() {
        // The interrupt and the end of file are the point of carrying them: a restoration that
        // dropped these would give back a terminal whose Ctrl-C did nothing.
        let modes = SavedModes {
            input: 1,
            output: 2,
            control: 3,
            local: 4,
            special: vec![4, 3],
        };
        let decoded = SavedModes::decode(&modes.encode()).expect("decodes");
        assert_eq!(decoded.special, vec![4, 3]);
    }

    #[cfg(unix)]
    #[test]
    fn malformed_saved_state_is_refused() {
        assert!(SavedModes::decode("1:2:3").is_err());
        assert!(SavedModes::decode("1:2:3:4:00:5").is_err());
        assert!(SavedModes::decode("z:2:3:4:00").is_err());
        assert!(
            SavedModes::decode("1:2:3:4:0").is_err(),
            "half a control character is not a control character"
        );
    }

    #[test]
    fn the_reset_sequences_turn_off_the_modes_an_application_may_have_left() {
        let text = String::from_utf8_lossy(RESET_SEQUENCES);
        for sequence in ["?1000l", "?1006l", "?1049l", "?2004l", "?25h"] {
            assert!(text.contains(sequence), "{sequence} is undone");
        }
    }
}
