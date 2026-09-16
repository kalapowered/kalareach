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
/// These cover the modes an application can leave enabled *other than* the keyboard protocols. Those
/// are given back by [`KEYBOARD_RESTORE_SEQUENCES`], and only by a cleanup that follows an
/// attachment which began forwarding, because only such an attachment could have changed them.
pub const RESET_SEQUENCES: &[u8] = b"\x1b[?1049l\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1004l\x1b[?1005l\x1b[?1006l\x1b[?1015l\x1b[?1016l\x1b[?2004l\x1b[?2026l\x1b[?7h\x1b[?25h\x1b[?1l\x1b>\x1b[0m\x1b[?69l\x1b[r\x1b(B\x0f";

/// The sequence that opens the attachment's own entry in the terminal's keyboard stack.
///
/// It is written once, where the attachment begins forwarding, and it is what makes the outer
/// terminal's keyboard state restorable **without having read it**. The Kitty protocol keeps a
/// stack per screen buffer: pushing saves whatever the terminal had negotiated and sets the flags
/// this attachment starts from, which is none of them, so the session negotiates what it wants from
/// a known baseline. A terminal that does not implement the protocol ignores the sequence.
pub const KEYBOARD_BEGIN_SEQUENCES: &[u8] = b"\x1b[>0u";

/// The sequences that give the keyboard protocols back, in both buffers.
///
/// Each screen buffer has its own Kitty stack and its own `modifyOtherKeys` level, and a terminal
/// can be left in either buffer, so both are visited. Entering and leaving the alternate buffer
/// through `?1049` saves and restores the cursor, so the primary screen is not disturbed by the
/// visit.
///
/// What each buffer gets differs, because what is in them differs. The alternate buffer's stack
/// belongs to whatever ran there, so it is emptied and the level is reset. The primary buffer is
/// where [`KEYBOARD_BEGIN_SEQUENCES`] pushed this attachment's entry, so exactly that entry is
/// popped and the terminal is left with the flags it had before the attachment began, whether or
/// not anything ever read them. `\x1b[>4m` without a level is `modifyOtherKeys` back to the value
/// the terminal itself starts with, which is the only form of that state a terminal can restore
/// on its own.
///
/// They are sent only by a cleanup that follows an attachment which began forwarding, because only
/// then could the session have changed them, and only then was the entry pushed.
pub const KEYBOARD_RESTORE_SEQUENCES: &[u8] =
    b"\x1b[?1049h\x1b[<65535u\x1b[>4m\x1b[?1049l\x1b[<1u\x1b[>4m";

/// The whole probe's deadline.
///
/// Section 8 fixes it at one second for the bounded synchronous handshake, which ends with the
/// device-attributes terminator. A terminal that has not finished answering by then has failed the
/// handshake, and the attachment fails with it rather than forwarding live input on a stream that
/// may still receive a late reply.
pub const PROBE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(1);

/// What a bounded probe of the outer terminal established.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Probe {
    /// The keyboard protocols the terminal reported.
    pub keyboard: KeyboardState,
    /// The bytes that were not part of any answer: what the person typed while the host was asking.
    ///
    /// Section 8 keeps these separate rather than discarding them or letting them pass for replies,
    /// and they are the first input the attachment forwards.
    pub typed: Vec<u8>,
}

impl Probe {
    /// The result of not asking, which is what `--no-probe` chooses.
    #[must_use]
    pub const fn unasked() -> Self {
        Self {
            keyboard: KeyboardState::EMPTY,
            typed: Vec::new(),
        }
    }
}

/// The keyboard protocols the outer terminal had negotiated before the attachment began.
///
/// Two of them are in use, and neither is readable from termios: the Kitty keyboard protocol keeps
/// a flag set per screen buffer, and xterm's `modifyOtherKeys` keeps a level. A terminal that has
/// been left in either one sends escape sequences where the person's shell expects characters,
/// which is the failure they cannot work around.
///
/// Putting the terminal back does not depend on this: the attachment pushes an entry onto the
/// terminal's own keyboard stack before it forwards anything, and the cleanup pops it, which
/// restores a state nothing had to read. What was read is written back after that pop as the exact
/// value the terminal reported, for a terminal whose stack this attachment cannot be sure of.
///
/// `None` means the terminal did not answer that query, which is how a terminal says it does not
/// implement the protocol. Nothing is then written back for it, and the pop stands on its own.
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

    /// Returns the sequences that give the terminal its keyboard protocols back.
    ///
    /// The pop in [`KEYBOARD_RESTORE_SEQUENCES`] does the work, and it does it whether or not
    /// anything was ever read: the attachment's own entry is what it takes off. What was read is
    /// written after it, which corrects the one case the stack cannot: an application inside the
    /// session that pushed an entry of its own and exited without popping it.
    #[must_use]
    pub fn cleanup_sequences(&self) -> Vec<u8> {
        let mut out = Vec::from(KEYBOARD_RESTORE_SEQUENCES);
        out.extend_from_slice(&self.restore_sequences());
        out
    }

    /// Returns the sequences that put a terminal back into this state.
    ///
    /// The Kitty form sets the flags to exactly what was read rather than pushing them, because
    /// what is being restored is a state and not a stack entry.
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

    /// Reads the answers out of what the terminal sent, keeping everything else.
    ///
    /// Returns the state the answers describe, whether the device-attributes terminator was among
    /// them, and the bytes that were not answers at all. That last part is the point: section 8
    /// requires the replies never to enter the application's input and the person's own typing
    /// never to be mistaken for a reply, so this separates the two rather than scanning the stream
    /// afterwards for anything reply-shaped.
    #[must_use]
    pub fn read(answer: &[u8]) -> (Self, bool, Vec<u8>) {
        let mut state = Self::default();
        let mut answered = false;
        let mut typed = Vec::new();
        let mut index = 0;
        while index < answer.len() {
            let rest = &answer[index..];
            let Some(body) = rest.strip_prefix(b"\x1b[") else {
                typed.push(answer[index]);
                index += 1;
                continue;
            };
            let Some(end) = body
                .iter()
                .position(|byte| byte.is_ascii_alphabetic() || *byte == b'~')
            else {
                // An incomplete sequence at the end of what has arrived so far. Nothing is decided
                // about it here; the caller reads again, and whatever is left when the exchange
                // ends is the person's.
                typed.extend_from_slice(rest);
                break;
            };
            let parameters = &body[..end];
            let consumed = match (parameters.first(), body[end]) {
                // `CSI ? flags u` is the Kitty protocol's answer.
                (Some(b'?'), b'u') => {
                    state.kitty = std::str::from_utf8(&parameters[1..])
                        .ok()
                        .and_then(|text| text.parse().ok());
                    true
                }
                // `CSI > 4 ; level m` is xterm's answer for `modifyOtherKeys`.
                (Some(b'>'), b'm') => {
                    let mut fields = parameters[1..].split(|byte| *byte == b';');
                    let matched = fields.next() == Some(b"4");
                    if matched {
                        state.modify_other_keys = fields
                            .next()
                            .and_then(|field| std::str::from_utf8(field).ok())
                            .and_then(|text| text.parse().ok());
                    }
                    matched
                }
                // `CSI ? … c` is the device-attributes answer that ends the exchange.
                (Some(b'?'), b'c') => {
                    answered = true;
                    true
                }
                _ => false,
            };
            if consumed {
                index += 2 + end + 1;
            } else {
                // A sequence this exchange did not ask for is the person's, not an answer.
                typed.extend_from_slice(&rest[..2 + end + 1]);
                index += 2 + end + 1;
            }
        }
        (state, answered, typed)
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

    use super::{
        KEYBOARD_BEGIN_SEQUENCES, KeyboardState, PROBE_DEADLINE, Probe, RESET_SEQUENCES,
        TerminalSize,
    };
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
            // `Now` rather than `Flush`: what the person typed before this moment is theirs, and
            // discarding the terminal's input queue on the way into raw mode would lose it.
            rustix::termios::tcsetattr(&self.handle, OptionalActions::Now, &raw).map_err(
                |error| CliError::Terminal(format!("set the terminal's modes: {error}")),
            )?;
            Ok(saved)
        }

        /// Opens this attachment's entry in the terminal's keyboard stack.
        ///
        /// Written once, where forwarding begins. It is what makes the outer terminal's keyboard
        /// state restorable without having read it, and it is paired with the pop in
        /// [`KeyboardState::cleanup_sequences`].
        pub fn begin_keyboard(&self) {
            use std::io::Write as _;

            let mut handle = &self.handle;
            let _ = handle.write_all(KEYBOARD_BEGIN_SEQUENCES);
            let _ = handle.flush();
        }

        /// Restores saved modes and undoes the modes an application may have left enabled.
        ///
        /// `keyboard` is present once the attachment has begun forwarding, and carries whatever the
        /// outer terminal said it had negotiated. Its presence is what says the keyboard protocols
        /// are this attachment's to put back at all: a cleanup that runs before forwarding began
        /// passes `None` and leaves them alone, because nothing that had happened could have
        /// changed them and nothing had pushed the entry this would pop.
        ///
        /// # Errors
        ///
        /// Returns an error when the modes cannot be set.
        pub fn restore(&self, saved: &Termios, keyboard: Option<&KeyboardState>) -> Result<()> {
            use std::io::Write as _;

            rustix::termios::tcsetattr(&self.handle, OptionalActions::Flush, saved).map_err(
                |error| CliError::Terminal(format!("restore the terminal's modes: {error}")),
            )?;
            let mut handle = &self.handle;
            let _ = handle.write_all(RESET_SEQUENCES);
            if let Some(keyboard) = keyboard {
                let _ = handle.write_all(&keyboard.cleanup_sequences());
            }
            let _ = handle.flush();
            Ok(())
        }

        /// Runs the bounded capability handshake section 8 describes.
        ///
        /// The terminal is asked which keyboard protocols it has negotiated, and the exchange ends
        /// with the device-attributes request every terminal answers. The terminal has to be
        /// readable a byte at a time for its answers to arrive, so this puts it into that state for
        /// the length of the exchange and puts it back afterwards, before anything else has touched
        /// it.
        ///
        /// What the person typed while the host was asking comes back with the answers rather than
        /// being discarded or mistaken for one of them.
        ///
        /// The device-attributes answer is the one reply this exchange requires, and its absence
        /// fails the attach. The keyboard queries are reads of state a terminal may simply not
        /// have: a terminal that implements neither protocol answers neither, and that silence is
        /// its answer rather than a failure. The terminator is what proves it had the chance to
        /// give one, which is why the exchange ends with it rather than with a clock.
        ///
        /// # Errors
        ///
        /// Returns [`CliError::TerminalProbeFailed`] when the terminator does not arrive inside
        /// [`PROBE_DEADLINE`], because the input stream may still receive a late reply and live
        /// forwarding must not begin on one that might. Returns [`CliError::Terminal`] when the
        /// terminal's modes cannot be read or set.
        pub fn probe(&self) -> Result<Probe> {
            let saved = self.modes()?;
            let mut asking = saved.clone();
            asking.make_raw();
            // A read that returns what has arrived rather than waiting for a line, with its own
            // bound in tenths of a second, so the deadline below is the one that decides.
            asking.special_codes[SpecialCodeIndex::VMIN] = 0;
            asking.special_codes[SpecialCodeIndex::VTIME] = 1;
            rustix::termios::tcsetattr(&self.handle, OptionalActions::Now, &asking).map_err(
                |error| CliError::Terminal(format!("set the terminal's modes: {error}")),
            )?;
            let answer = self.ask(KeyboardState::QUERIES);
            // `Now` again, for the same reason: the exchange ends at the terminator, and anything
            // the person typed after it is still in the terminal's queue and is still theirs.
            rustix::termios::tcsetattr(&self.handle, OptionalActions::Now, &saved).map_err(
                |error| CliError::Terminal(format!("restore the terminal's modes: {error}")),
            )?;
            let (keyboard, answered, typed) = KeyboardState::read(&answer);
            if !answered {
                return Err(CliError::TerminalProbeFailed(
                    "the terminal did not finish the capability handshake; attach with --no-probe                      to use the conservative profile without asking it anything"
                        .to_owned(),
                ));
            }
            Ok(Probe { keyboard, typed })
        }

        /// Writes the queries and reads until the device-attributes answer arrives or time runs out.
        fn ask(&self, queries: &[u8]) -> Vec<u8> {
            use std::io::{Read as _, Write as _};

            let mut handle = &self.handle;
            if handle.write_all(queries).is_err() || handle.flush().is_err() {
                return Vec::new();
            }
            let deadline = std::time::Instant::now() + PROBE_DEADLINE;
            let mut answer = Vec::new();
            let mut buffer = [0_u8; 256];
            while std::time::Instant::now() < deadline {
                match handle.read(&mut buffer) {
                    Ok(0) => {}
                    Ok(read) => {
                        answer.extend_from_slice(&buffer[..read]);
                        // The device-attributes answer is the last of the three, so its arrival
                        // ends the exchange rather than the clock doing it.
                        if KeyboardState::read(&answer).1 {
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
        let (state, answered, typed) = KeyboardState::read(b"\x1b[?5u\x1b[>4;2m\x1b[?62;22c");
        assert_eq!(state.kitty, Some(5));
        assert_eq!(state.modify_other_keys, Some(2));
        assert!(answered, "the terminator arrived");
        assert!(typed.is_empty(), "and nothing of it was the person's");
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
        let (state, answered, typed) = KeyboardState::read(b"\x1b[?62;22c");
        assert_eq!(state, KeyboardState::EMPTY);
        assert!(answered);
        assert!(typed.is_empty());
        assert!(!state.is_known());
        assert!(state.restore_sequences().is_empty());
        let (state, answered, typed) = KeyboardState::read(b"");
        assert_eq!(state, KeyboardState::EMPTY);
        assert!(!answered, "and a terminal that said nothing did not finish");
        assert!(typed.is_empty());
    }

    #[test]
    fn what_the_person_typed_during_the_exchange_is_kept_apart_from_the_answers() {
        // Somebody types while the host is asking. Their bytes are theirs: they are not answers,
        // they are not discarded, and a control sequence among them is not mistaken for one.
        let (state, answered, typed) =
            KeyboardState::read(b"\x1b[?5uhel\x1b[Alo\x1b[>4;2m!\x1b[?62;22c");
        assert_eq!(state.kitty, Some(5));
        assert_eq!(state.modify_other_keys, Some(2));
        assert!(answered);
        assert_eq!(typed, b"hel\x1b[Alo!".to_vec());
    }

    #[test]
    fn a_typed_letter_does_not_end_the_exchange() {
        // The exchange ends with the device-attributes answer, which is a control sequence. A
        // person who types the same letter it ends with has not answered anything.
        let (_, answered, typed) = KeyboardState::read(b"c");
        assert!(!answered);
        assert_eq!(typed, b"c".to_vec());
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
        for sequence in ["?1049l", "?1000l", "?1006l", "?2004l", "?25h"] {
            assert!(text.contains(sequence), "{sequence} is undone");
        }
        // The keyboard protocols are not among them, because clearing one this attachment never
        // changed would take away what the person set up for themselves.
        assert!(
            !text.contains("65535u"),
            "the Kitty stack is not cleared here"
        );
        assert!(!text.contains(">4;0m"), "and neither is modifyOtherKeys");
    }

    #[test]
    fn a_terminal_that_was_never_asked_still_gets_its_keyboard_state_back() {
        // Nothing was read, which is what `--no-probe` chooses and what a terminal that answers
        // neither query leaves. The entry this attachment pushed is still popped, so the terminal
        // is left with the flags it had before the attachment began rather than with none.
        let unknown =
            String::from_utf8_lossy(&KeyboardState::EMPTY.cleanup_sequences()).into_owned();
        assert!(
            unknown.contains("\u{1b}[<1u"),
            "this attachment's own stack entry comes off: {unknown:?}"
        );
        assert!(
            !unknown.contains("\u{1b}[>4;0m"),
            "and no level is imposed on a terminal that never reported one: {unknown:?}"
        );
        assert!(
            unknown.contains("\u{1b}[>4m"),
            "modifyOtherKeys goes back to the terminal's own initial value: {unknown:?}"
        );
        assert!(
            !unknown.contains("\u{1b}[="),
            "and nothing is set to a state nobody read: {unknown:?}"
        );
    }

    #[test]
    fn what_a_terminal_reported_is_put_back_after_the_stack_entry_comes_off() {
        let known = KeyboardState {
            kitty: Some(5),
            modify_other_keys: Some(2),
        };
        let cleanup = String::from_utf8_lossy(&known.cleanup_sequences()).into_owned();
        assert!(
            cleanup.contains("?1049h"),
            "the alternate buffer is visited"
        );
        assert_eq!(
            cleanup.matches("\u{1b}[<65535u").count(),
            1,
            "the stack emptied is the alternate buffer's, which belongs to what ran there"
        );
        assert!(
            cleanup.contains("\u{1b}[<1u"),
            "and the primary buffer gives back exactly this attachment's entry: {cleanup:?}"
        );
        assert!(
            cleanup.ends_with("\u{1b}[=5;1u\u{1b}[>4;2m"),
            "with what the terminal itself reported last of all: {cleanup:?}"
        );
    }

    #[test]
    fn forwarding_opens_the_entry_the_cleanup_takes_off() {
        let begin = String::from_utf8_lossy(KEYBOARD_BEGIN_SEQUENCES).into_owned();
        assert_eq!(
            begin, "\u{1b}[>0u",
            "one push, with the flags this attachment starts from: {begin:?}"
        );
        let cleanup =
            String::from_utf8_lossy(&KeyboardState::EMPTY.cleanup_sequences()).into_owned();
        assert_eq!(
            cleanup.matches("\u{1b}[<1u").count(),
            1,
            "and one pop against it: {cleanup:?}"
        );
    }
}
