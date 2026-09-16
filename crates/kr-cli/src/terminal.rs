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

/// The escape sequences that undo the modes a session may have left the terminal in.
///
/// A detach restores the saved terminal modes and then sends these, because an application that was
/// killed never got the chance to turn its own modes off. Termios alone is not enough: it does not
/// describe mouse reporting, the alternate screen, bracketed paste, focus reporting or which key
/// encoding the terminal is using, and a person left in one of those has a terminal that behaves
/// like somebody else's.
///
/// The order matters, and the keyboard protocols are why. Each buffer has its own Kitty stack and
/// its own `modifyOtherKeys` level, and a terminal can be left in either buffer, so both are
/// visited: cleared where the terminal is, then in the alternate buffer, then in the primary one it
/// is left in. Entering and leaving the alternate buffer through `?1049` saves and restores the
/// cursor, so the primary screen is not disturbed by the visit. Leaving a terminal in an enhanced key encoding is the failure a
/// person cannot work around: their shell receives escape sequences where it expects characters.
///
/// Clearing is the first half of the answer. The second is [`KeyboardState`]: the outer terminal is
/// *asked* what it had negotiated before the attachment began, and whatever it said is put back
/// after these sequences have cleared what the session left. A person whose own shell had an
/// enhanced encoding gets that encoding back rather than having it taken away.
pub const RESET_SEQUENCES: &[u8] = b"\x1b[<65535u\x1b[>4;0m\x1b[?1049h\x1b[<65535u\x1b[>4;0m\x1b[?1049l\x1b[<65535u\x1b[>4;0m\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1004l\x1b[?1005l\x1b[?1006l\x1b[?1015l\x1b[?1016l\x1b[?2004l\x1b[?2026l\x1b[?7h\x1b[?25h\x1b[?1l\x1b>\x1b[0m\x1b[?69l\x1b[r\x1b(B\x0f";

/// How long the outer terminal is given to answer the keyboard queries.
///
/// The queries end with a primary device attributes request, which every terminal answers, so the
/// answer normally arrives in microseconds. This is the bound for a terminal that answers nothing:
/// an attachment must not sit waiting for one, and a terminal that says nothing has nothing to
/// restore.
pub const KEYBOARD_QUERY_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(250);

/// The keyboard protocols the outer terminal had negotiated before the attachment began.
///
/// Two of them are in use, and neither is readable from termios: the Kitty keyboard protocol keeps
/// a flag set per screen buffer, and xterm's `modifyOtherKeys` keeps a level. A terminal that has
/// been left in either one sends escape sequences where the person's shell expects characters,
/// which is the failure they cannot work around; a terminal that had *chosen* one and had it
/// cleared has lost something it set up. Both are therefore read before anything is changed, and
/// written back on the way out.
///
/// `None` means the terminal did not answer that query, which is how a terminal says it does not
/// implement the protocol. Nothing is then written back for it, and the clearing in
/// [`RESET_SEQUENCES`] stands.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KeyboardState {
    /// The Kitty keyboard-protocol flags the terminal reported.
    pub kitty: Option<u16>,
    /// The `modifyOtherKeys` level the terminal reported.
    pub modify_other_keys: Option<u8>,
}

impl KeyboardState {
    /// A terminal that answered neither query, which is the whole answer on a platform that has
    /// neither protocol to read.
    pub const EMPTY: Self = Self {
        kitty: None,
        modify_other_keys: None,
    };

    /// The queries that ask a terminal what it has negotiated.
    ///
    /// The device-attributes request is last and is the terminator: every terminal answers it, so
    /// its answer is how the reader knows the earlier questions have been answered or ignored,
    /// rather than waiting for a timeout on every attachment.
    pub const QUERIES: &'static [u8] = b"\x1b[?u\x1b[?4m\x1b[c";

    /// Returns whether the terminal answered either query.
    #[must_use]
    pub const fn is_known(&self) -> bool {
        self.kitty.is_some() || self.modify_other_keys.is_some()
    }

    /// Returns the sequences that put a terminal back into this state.
    ///
    /// They follow [`RESET_SEQUENCES`], which has already cleared whatever the session left. The
    /// Kitty form sets the flags to exactly what was read rather than pushing them, because what
    /// is being restored is a state and not a stack entry.
    #[must_use]
    pub fn restore_sequences(&self) -> Vec<u8> {
        let mut out = Vec::new();
        if let Some(flags) = self.kitty {
            out.extend_from_slice(format!("\x1b[={flags};1u").as_bytes());
        }
        if let Some(level) = self.modify_other_keys {
            out.extend_from_slice(format!("\x1b[>4;{level}m").as_bytes());
        }
        out
    }

    /// Reads the state out of a terminal's answers.
    #[must_use]
    pub fn parse(answer: &[u8]) -> Self {
        let mut state = Self::default();
        let mut index = 0;
        while index < answer.len() {
            let Some(start) = answer[index..].iter().position(|byte| *byte == 0x1B) else {
                break;
            };
            let start = index + start;
            let rest = &answer[start..];
            index = start + 1;
            // A control sequence is the introducer, its parameters and one final byte. Both answers
            // are `CSI`, and the final byte says which question was answered.
            let Some(body) = rest.strip_prefix(b"\x1b[") else {
                continue;
            };
            let Some(end) = body
                .iter()
                .position(|byte| byte.is_ascii_alphabetic() || *byte == b'~')
            else {
                continue;
            };
            let parameters = &body[..end];
            match (parameters.first(), body[end]) {
                // `CSI ? flags u` is the Kitty protocol's answer.
                (Some(b'?'), b'u') => {
                    state.kitty = std::str::from_utf8(&parameters[1..])
                        .ok()
                        .and_then(|text| text.parse().ok());
                }
                // `CSI > 4 ; level m` is xterm's answer for `modifyOtherKeys`.
                (Some(b'>'), b'm') => {
                    let mut fields = parameters[1..].split(|byte| *byte == b';');
                    if fields.next() == Some(b"4") {
                        state.modify_other_keys = fields
                            .next()
                            .and_then(|field| std::str::from_utf8(field).ok())
                            .and_then(|text| text.parse().ok());
                    }
                }
                _ => {}
            }
            index = start + 2 + end + 1;
        }
        state
    }

    /// Renders the state as one argument for the guard.
    #[must_use]
    pub fn encode(&self) -> String {
        let field = |value: Option<u64>| match value {
            Some(value) => value.to_string(),
            None => "-".to_owned(),
        };
        format!(
            "{}:{}",
            field(self.kitty.map(u64::from)),
            field(self.modify_other_keys.map(u64::from))
        )
    }

    /// Parses the state back.
    ///
    /// # Errors
    ///
    /// Returns an error when the text is not two fields, each a number or a dash.
    pub fn decode(text: &str) -> crate::error::Result<Self> {
        let mut parts = text.split(':');
        let mut next = |what: &str| -> crate::error::Result<Option<u64>> {
            let part = parts.next().ok_or_else(|| {
                crate::error::CliError::Terminal(format!("the saved {what} state is missing"))
            })?;
            if part == "-" {
                return Ok(None);
            }
            part.parse::<u64>().map(Some).map_err(|_| {
                crate::error::CliError::Terminal(format!("the saved {what} state is not a number"))
            })
        };
        let kitty = next("keyboard")?;
        let modify_other_keys = next("modifyOtherKeys")?;
        if parts.next().is_some() {
            return Err(crate::error::CliError::Terminal(
                "the saved keyboard state has more fields than expected".to_owned(),
            ));
        }
        Ok(Self {
            kitty: kitty.map(|value| u16::try_from(value).unwrap_or(u16::MAX)),
            modify_other_keys: modify_other_keys
                .map(|value| u8::try_from(value).unwrap_or(u8::MAX)),
        })
    }
}

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

    use super::{KEYBOARD_QUERY_TIMEOUT, KeyboardState, RESET_SEQUENCES, TerminalSize};
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
        /// `keyboard` is what this terminal had negotiated before the attachment began. It is
        /// written after the clearing sequences, so what a person set up for themselves comes back
        /// rather than being taken away with what the session left.
        ///
        /// # Errors
        ///
        /// Returns an error when the modes cannot be set.
        pub fn restore(&self, saved: &Termios, keyboard: &KeyboardState) -> Result<()> {
            use std::io::Write as _;

            rustix::termios::tcsetattr(&self.handle, OptionalActions::Flush, saved).map_err(
                |error| CliError::Terminal(format!("restore the terminal's modes: {error}")),
            )?;
            let mut handle = &self.handle;
            let _ = handle.write_all(RESET_SEQUENCES);
            let _ = handle.write_all(&keyboard.restore_sequences());
            let _ = handle.flush();
            Ok(())
        }

        /// Asks the terminal which keyboard protocols it has negotiated.
        ///
        /// The terminal has to be readable a byte at a time for its answer to arrive, so this puts
        /// it into that state for the length of the exchange and puts it back afterwards, before
        /// anything else has touched it. A terminal that answers nothing costs
        /// [`KEYBOARD_QUERY_TIMEOUT`] once, at attach, and has nothing to restore.
        ///
        /// # Errors
        ///
        /// Returns an error when the terminal's modes cannot be read or set.
        pub fn keyboard_state(&self) -> Result<KeyboardState> {
            let saved = self.modes()?;
            let mut asking = saved.clone();
            asking.make_raw();
            // A read that returns what has arrived rather than waiting for a line, with its own
            // bound in tenths of a second, so a terminal that says nothing does not hold the
            // attachment up.
            asking.special_codes[SpecialCodeIndex::VMIN] = 0;
            asking.special_codes[SpecialCodeIndex::VTIME] =
                u8::try_from(KEYBOARD_QUERY_TIMEOUT.as_millis() / 100)
                    .unwrap_or(2)
                    .max(1);
            rustix::termios::tcsetattr(&self.handle, OptionalActions::Flush, &asking).map_err(
                |error| CliError::Terminal(format!("set the terminal's modes: {error}")),
            )?;
            let answer = self.ask(KeyboardState::QUERIES);
            rustix::termios::tcsetattr(&self.handle, OptionalActions::Flush, &saved).map_err(
                |error| CliError::Terminal(format!("restore the terminal's modes: {error}")),
            )?;
            Ok(KeyboardState::parse(&answer))
        }

        /// Writes the queries and reads until the device-attributes answer arrives or time runs out.
        fn ask(&self, queries: &[u8]) -> Vec<u8> {
            use std::io::{Read as _, Write as _};

            let mut handle = &self.handle;
            if handle.write_all(queries).is_err() || handle.flush().is_err() {
                return Vec::new();
            }
            let deadline = std::time::Instant::now() + KEYBOARD_QUERY_TIMEOUT;
            let mut answer = Vec::new();
            let mut buffer = [0_u8; 256];
            while std::time::Instant::now() < deadline {
                match handle.read(&mut buffer) {
                    Ok(0) => {}
                    Ok(read) => {
                        answer.extend_from_slice(&buffer[..read]);
                        // The device-attributes answer is the last of the three, so its arrival
                        // ends the exchange rather than the clock doing it.
                        if answer.last() == Some(&b'c') {
                            break;
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(_) => break,
                }
            }
            answer
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
    fn a_terminals_answers_are_read_back_as_the_state_it_reported() {
        // Both protocols, then the device attributes that end the exchange.
        let state = KeyboardState::parse(b"\x1b[?5u\x1b[>4;2m\x1b[?62;22c");
        assert_eq!(state.kitty, Some(5));
        assert_eq!(state.modify_other_keys, Some(2));
        assert_eq!(
            state.restore_sequences(),
            b"\x1b[=5;1u\x1b[>4;2m".to_vec(),
            "the flags are set to what was read rather than pushed onto the terminal's stack"
        );
    }

    #[test]
    fn a_terminal_that_answers_nothing_leaves_nothing_to_restore() {
        // Only the device attributes: the terminal implements neither protocol, so the clearing in
        // the reset sequences is the whole restoration.
        let state = KeyboardState::parse(b"\x1b[?62;22c");
        assert_eq!(state, KeyboardState::EMPTY);
        assert!(!state.is_known());
        assert!(state.restore_sequences().is_empty());
        assert_eq!(KeyboardState::parse(b""), KeyboardState::EMPTY);
    }

    #[test]
    fn the_keyboard_state_round_trips_through_its_argument_form() {
        for state in [
            KeyboardState::EMPTY,
            KeyboardState {
                kitty: Some(0),
                modify_other_keys: None,
            },
            KeyboardState {
                kitty: Some(31),
                modify_other_keys: Some(2),
            },
        ] {
            assert_eq!(
                KeyboardState::decode(&state.encode()).expect("decodes"),
                state
            );
        }
        assert!(KeyboardState::decode("5").is_err());
        assert!(KeyboardState::decode("5:2:1").is_err());
        assert!(KeyboardState::decode("x:2").is_err());
    }

    #[test]
    fn the_reset_sequences_turn_off_the_modes_an_application_may_have_left() {
        let text = String::from_utf8_lossy(RESET_SEQUENCES);
        for sequence in ["?1000l", "?1006l", "?1049l", "?2004l", "?25h"] {
            assert!(text.contains(sequence), "{sequence} is undone");
        }
    }
}
