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

use crate::error::{CliError, Result};

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
/// They begin by leaving the alternate screen, so everything after them lands in the buffer the
/// person is left looking at.
///
/// These cover the modes an application can leave enabled *other than* the keyboard protocols.
/// Those are given back by [`KEYBOARD_RESTORE_SEQUENCES`], and only by a cleanup that follows an
/// attachment which began forwarding, because only such an attachment could have changed them.
/// Leaving a terminal in an enhanced key encoding is the failure a person cannot work around: their
/// shell receives escape sequences where it expects characters.
///
/// The list includes the coordinate system, because a projected attachment installs the session's
/// own: origin mode, the scroll region, the left and right margins, insert mode, the designated
/// character sets. A terminal left in insert mode types over itself, one left inside a region
/// scrolls a strip of the screen, and one left in the graphics set draws lines where the person
/// types letters; none of that is described by termios.
///
/// It ends with the colours, for the same reason. A projection installs the session's own
/// foreground, background, cursor, pointer and selection colours and any indexed colour an
/// application overrode, so the last thing a cleanup does is hand each of those back to the
/// terminal's own configuration.
///
/// What this cannot do is give back a state the terminal had *before* the attachment and never
/// reported. Nothing asks a terminal whether its mouse reporting was on or its cursor was hidden:
/// there is no reply every qualified profile promises, and a question whose answer is optional is
/// not one this command may ask. So these put each of those modes into its documented default,
/// which is the state a terminal is in when nothing has changed it, and the keyboard protocols -
/// the one part a terminal does report - are put back to what it reported.
pub const RESET_SEQUENCES: &[u8] = b"\x1b[?1049l\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1004l\x1b[?1005l\x1b[?1006l\x1b[?1007l\x1b[?1015l\x1b[?1016l\x1b[?2004l\x1b[?2026l\x1b[?7h\x1b[?25h\x1b[?1l\x1b>\x1b[0m\x1b[?69l\x1b[r\x1b[?6l\x1b[4l\x1b[0 q\x1b(B\x1b)B\x0f\x1b]104\x1b\\\x1b]110\x1b\\\x1b]111\x1b\\\x1b]112\x1b\\\x1b]113\x1b\\\x1b]114\x1b\\\x1b]117\x1b\\\x1b]119\x1b\\";

/// The sequence that puts `modifyOtherKeys` back to the value the terminal itself starts with.
///
/// It is the only form of that state a terminal can restore on its own, and it is the whole of what
/// a cleanup writes before the state it read: **KalaReach never operates the terminal's keyboard
/// stack.** The Kitty protocol's stack belongs to whatever was running when this attachment
/// arrived. An entry pushed here could not be taken off reliably - an application inside the
/// session can empty the stack with one sequence, and nothing can ask a terminal how deep its stack
/// is - so a pop written on the way out would take somebody else's entry instead of this
/// attachment's. What the terminal reported is therefore put back as a state, with
/// [`KeyboardState::restore_sequences`], and every stack is left exactly as it was found.
///
/// Sent only by a cleanup that follows an attachment which began forwarding, because only then
/// could the session have changed anything.
pub const KEYBOARD_RESTORE_SEQUENCES: &[u8] = b"\x1b[>4m";

/// The whole probe's deadline.
///
/// Section 8 fixes it at one second for the bounded synchronous handshake, which ends with the
/// device-attributes terminator. A terminal that has not finished answering by then has failed the
/// handshake, and the attachment fails with it rather than forwarding live input on a stream that
/// may still receive a late reply.
pub const PROBE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(1);

/// The questions a declared profile asks, every one of which must be answered.
///
/// Section 8 is exact about this: the exchange "finishes with the qualified DA1 terminator after
/// collecting every requested reply", and "a missing terminator or reply fails that attach
/// attempt". A question whose answer is optional is therefore not a question this command may ask;
/// what it may do is *not ask*, which the specification calls the honest way to not ask.
///
/// So the set follows the profile the terminal declares. Device attributes is in it always, because
/// every qualified terminal answers it and answers it last, which is what makes it the terminator.
/// A terminal that declares itself a Kitty terminal is expected to answer the keyboard query, and
/// one that declares xterm's `modifyOtherKeys` support is expected to answer for its level. Nothing
/// else is asked, because nothing else can be required of a terminal calling itself
/// `xterm-256color`: Terminal.app answers neither colour query, and requiring one would fail every
/// attach there.
#[must_use]
pub fn profile_questions(profile: Option<&str>) -> Vec<kr_term::probe::ProbeItem> {
    use kr_term::probe::ProbeItem;

    let mut asked = Vec::new();
    if let Some(name) = profile {
        let name = name.to_ascii_lowercase();
        if name.contains("kitty") || name.contains("ghostty") {
            asked.push(ProbeItem::KittyKeyboard);
        }
        if name.contains("xterm-kitty") || name == "xterm" {
            asked.push(ProbeItem::ModifyOtherKeys);
        }
    }
    asked.push(ProbeItem::DeviceAttributes);
    asked
}

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
    /// The foreground and background the terminal shared, when it answered the colour queries.
    ///
    /// Section 8 lets an explicit client preference share these during the bounded probe, to be
    /// adopted as the session's initial palette at creation. Whether they are adopted is the
    /// session's decision and not this command's; what a probe does is find out.
    pub palette: Option<(kr_term::palette::Rgb, kr_term::palette::Rgb)>,
    /// The terminal's own identity string, when it answered.
    pub version: Option<String>,
    /// Whether the terminal reported synchronised output.
    pub synchronised_output: bool,
    /// The profile a `--no-probe` attachment chose before anything was written.
    ///
    /// `None` for an attachment that did ask. The choice has to be made before the first byte, and
    /// recording it is how the command can say afterwards that it was.
    pub no_probe: Option<kr_term::probe::NoProbeProfile>,
}

impl Probe {
    /// The result of not asking, which is what `--no-probe` chooses.
    ///
    /// The choice is made **before any probe is sent**, which is the only time it can be made
    /// honestly: calling it afterwards does not unsend the questions and does not make a late reply
    /// disappear. A contaminated stream is therefore refused here as well.
    ///
    /// # Errors
    ///
    /// Returns [`CliError::TerminalProbeFailed`] when a probe has already been sent on this stream.
    pub fn unasked(context: kr_term::probe::InputContext) -> Result<Self> {
        if context == kr_term::probe::InputContext::Contaminated {
            return Err(CliError::TerminalProbeFailed(
                "a probe has already gone out on this terminal, so --no-probe cannot promise that                  no late reply is still coming; start again in a fresh terminal"
                    .to_owned(),
            ));
        }
        Ok(Self {
            keyboard: KeyboardState::EMPTY,
            typed: Vec::new(),
            palette: None,
            version: None,
            synchronised_output: false,
            // The conservative projected profile: it asks the terminal nothing and installs nothing
            // it could not put back. A saved qualified profile would go here instead once one has
            // been recorded for this terminal.
            no_probe: Some(kr_term::probe::NoProbeProfile::ConservativeProjected {
                palette: kr_term::palette::PaletteSource::DarkPreset,
            }),
        })
    }

    /// Builds a probe result from a completed exchange.
    #[must_use]
    pub fn from_outcome(outcome: &kr_term::probe::ProbeOutcome) -> Self {
        use kr_term::probe::{ProbeAnswer, ProbeItem};

        let mut keyboard = KeyboardState::EMPTY;
        if let Some(ProbeAnswer::KittyFlags(flags)) = outcome.answer(ProbeItem::KittyKeyboard) {
            keyboard.kitty = Some(u16::from(*flags));
        }
        if let Some(ProbeAnswer::ModifyOtherKeysLevel(level)) =
            outcome.answer(ProbeItem::ModifyOtherKeys)
        {
            keyboard.modify_other_keys = Some(*level);
        }
        let palette = match (
            outcome.answer(ProbeItem::Foreground),
            outcome.answer(ProbeItem::Background),
        ) {
            (Some(ProbeAnswer::Colour(foreground)), Some(ProbeAnswer::Colour(background))) => {
                Some((*foreground, *background))
            }
            _ => None,
        };
        let version = match outcome.answer(ProbeItem::Version) {
            Some(ProbeAnswer::Version(text)) => Some(text.clone()),
            _ => None,
        };
        // DECRPM statuses one and three are "set"; two and four are "reset", and zero is "not
        // recognised". A terminal that did not answer has not said it supports it.
        let synchronised_output = matches!(
            outcome.answer(ProbeItem::SynchronisedOutput),
            Some(ProbeAnswer::ModeStatus(1 | 3))
        );
        Self {
            keyboard,
            typed: outcome.typed().to_vec(),
            palette,
            version,
            synchronised_output,
            no_probe: None,
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

    /// Returns whether the terminal answered either query.
    #[must_use]
    pub const fn is_known(&self) -> bool {
        self.kitty.is_some() || self.modify_other_keys.is_some()
    }

    /// Returns the sequences that give the terminal its keyboard protocols back.
    ///
    /// The level goes back to the terminal's own initial value and then the state that was read is
    /// written over it, so a terminal that reported nothing is left as it was rather than cleared.
    /// Nothing here touches a stack; see [`KEYBOARD_RESTORE_SEQUENCES`].
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

/// Whether a probe has already gone out on this terminal.
///
/// The answer is a fact about the terminal rather than about this process. Section 8: after a failed
/// probe the stream is not clean, a retry needs a fresh input context, and calling `--no-probe` on
/// the same stream does not purge whatever is still coming. A second `kr attach` in the window
/// where the first one failed is looking at the same stream, so the record has to outlive the
/// process that made it — and no longer than the terminal it is about, which is why it names the
/// terminal's own device and session rather than the window a person is looking at.
#[must_use]
pub fn input_context(terminal: &ControllingTerminal) -> kr_term::probe::InputContext {
    match contamination_marker(terminal) {
        Some(path) if path.exists() => kr_term::probe::InputContext::Contaminated,
        _ => kr_term::probe::InputContext::Clean,
    }
}

/// Records that a probe is going out on this terminal.
///
/// Written before the first question, not after a failure: a process killed in the middle of the
/// exchange runs no error path at all, and the terminal it was asking is exactly the one whose
/// stream may still deliver a reply. [`clear_contamination`] removes it once the terminator has
/// arrived, which is the only thing that proves nothing else is coming.
///
/// Best effort on purpose: a host whose runtime directory cannot be written is a host that cannot
/// record anything, and refusing the attach over that would be refusing it for the wrong reason.
/// What the record buys is the *next* attempt, and its absence costs that attempt nothing it did
/// not already have.
pub fn mark_contaminated(terminal: &ControllingTerminal) {
    let Some(path) = contamination_marker(terminal) else {
        return;
    };
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(&path, b"a probe on this terminal did not finish\n");
}

/// Clears the record, once an exchange has finished and no reply can still be in flight.
///
/// The terminator is what proves that, and nothing else does: the record is written before the
/// first question goes out and removed only here, so a process that died in the middle of asking
/// leaves the record behind for the next attempt to find.
pub fn clear_contamination(terminal: &ControllingTerminal) {
    if let Some(path) = contamination_marker(terminal) {
        let _ = std::fs::remove_file(path);
    }
}

/// The file that records a contaminated terminal, named after the terminal itself.
fn contamination_marker(terminal: &ControllingTerminal) -> Option<std::path::PathBuf> {
    let paths = kr_ipc::paths::HostPaths::discover().ok()?;
    let name = terminal.identity()?;
    Some(
        paths
            .runtime_root()
            .join("probes")
            .join(format!("{name}.contaminated")),
    )
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

    use super::{KeyboardState, Probe, RESET_SEQUENCES, TerminalSize};
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

        /// A name for this terminal that no other terminal shares while it exists.
        ///
        /// The device and the session that owns it. A pseudo-terminal's path is reused by the
        /// operating system, so the path alone would let a new window inherit a record about an old
        /// one; the session identifier is what makes it this terminal.
        #[must_use]
        pub fn identity(&self) -> Option<String> {
            let device = rustix::termios::ttyname(&self.handle, Vec::new()).ok()?;
            let device = device.to_string_lossy().replace(['/', '\\'], "-");
            let session = rustix::termios::tcgetsid(&self.handle).ok()?;
            Some(format!(
                "{}-{}",
                device.trim_start_matches('-'),
                session.as_raw_nonzero()
            ))
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

        /// Restores saved modes and undoes the modes an application may have left enabled.
        ///
        /// `keyboard` is present once the attachment has begun forwarding, and carries whatever the
        /// outer terminal said it had negotiated. Its presence is what says the keyboard protocols
        /// are this attachment's to put back at all: a cleanup that runs before forwarding began
        /// passes `None` and leaves them alone, because nothing that had happened could have
        /// changed them.
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
        pub fn probe(
            &self,
            context: kr_term::probe::InputContext,
            profile: Option<&str>,
        ) -> Result<Probe> {
            use kr_term::probe::ProbeSession;

            // The clock is monotonic and starts at zero, so the one-second deadline is one second
            // of elapsed time whatever the wall clock does while the terminal is being asked.
            let started = std::time::Instant::now();
            let asked = super::profile_questions(profile);
            let (mut session, request) = ProbeSession::start(0, context, &asked)
                .map_err(|error| CliError::TerminalProbeFailed(error.to_string()))?;

            let saved = self.modes()?;
            let mut asking = saved.clone();
            asking.make_raw();
            // A read that returns what has arrived and waits for nothing: no line, and not a
            // tenth of a second either. The deadline is one second for the whole exchange, and a
            // read that waited a tenth of its own could carry the exchange past it; the loop
            // watches the clock between reads instead, so nothing here outlasts the second.
            asking.special_codes[SpecialCodeIndex::VMIN] = 0;
            asking.special_codes[SpecialCodeIndex::VTIME] = 0;
            rustix::termios::tcsetattr(&self.handle, OptionalActions::Now, &asking).map_err(
                |error| CliError::Terminal(format!("set the terminal's modes: {error}")),
            )?;
            // Before the first byte of the first question. From here until the terminator this
            // terminal's stream is one a late reply can arrive on, and a process that dies in
            // between leaves this record as the only thing that knows.
            super::mark_contaminated(self);
            let read = self.ask(&mut session, &request, started);
            let typed = session.typed().to_vec();
            // `Now` again, for the same reason: the exchange ends at the terminator, and anything
            // the person typed after it is still in the terminal's queue and is still theirs.
            rustix::termios::tcsetattr(&self.handle, OptionalActions::Now, &saved).map_err(
                |error| CliError::Terminal(format!("restore the terminal's modes: {error}")),
            )?;
            read?;
            let elapsed = elapsed_ms(started);
            match session.finish(elapsed) {
                Ok(outcome) => {
                    // The terminator arrived, so nothing else is coming and this stream is clean
                    // again.
                    super::clear_contamination(self);
                    let mut probe = Probe::from_outcome(&outcome);
                    // Whatever arrived and was not an answer is the person's, in the order they
                    // typed it. It never entered the terminal's input and it was never mistaken
                    // for a reply.
                    probe.typed = outcome.into_typed();
                    Ok(probe)
                }
                Err(error) => {
                    // The exchange failed. What the person typed during it is still theirs, and the
                    // failure says so: this attach ends, and the bytes go nowhere rather than into
                    // an application that was never given the keys.
                    let _ = typed;
                    Err(CliError::TerminalProbeFailed(format!(
                        "{error}; attach again in a fresh terminal, where no reply to this \
                         exchange can still arrive"
                    )))
                }
            }
        }

        /// Writes the request and reads until the terminator arrives or the deadline passes.
        ///
        /// The bytes it reads never reach the pseudo-terminal: they go to the probe session, which
        /// separates the answers from what the person typed.
        fn ask(
            &self,
            session: &mut kr_term::probe::ProbeSession,
            request: &[u8],
            started: std::time::Instant,
        ) -> Result<()> {
            use std::io::{Read as _, Write as _};

            let mut handle = &self.handle;
            handle
                .write_all(request)
                .and_then(|()| handle.flush())
                .map_err(|error| {
                    CliError::Terminal(format!("ask the terminal what it is: {error}"))
                })?;
            // The write is inside the deadline too. A terminal that cannot take the questions has
            // already spent part of the one second the whole exchange has, and the reads that
            // follow get what is left of it rather than a second of their own.
            if elapsed_ms(started) > kr_term::probe::PROBE_DEADLINE_MS {
                return Ok(());
            }
            let mut buffer = [0_u8; 256];
            loop {
                let elapsed = elapsed_ms(started);
                if elapsed > kr_term::probe::PROBE_DEADLINE_MS {
                    // The session decides what an expired exchange is; this only stops reading.
                    return Ok(());
                }
                // The terminal returns what has arrived and waits for nothing, so the clock is
                // checked between reads and the exchange ends within a millisecond of its
                // deadline. What happens *at* the deadline is the session's decision rather than
                // this loop's: the exchange fails, and it never becomes live forwarding on a
                // stream a late reply could still reach.
                match handle.read(&mut buffer) {
                    // Nothing has arrived yet. A moment's wait, rather than a spin that would
                    // read a thousand times for every answer.
                    Ok(0) => std::thread::sleep(std::time::Duration::from_millis(1)),
                    Ok(read) => {
                        if session
                            .observe(&buffer[..read], elapsed_ms(started))
                            .is_err()
                        {
                            // A malformed answer, or more bytes than an exchange could need. The
                            // session holds the failure; `finish` reports it.
                            return Ok(());
                        }
                        // The terminator ends the exchange rather than the clock doing it.
                        if session.is_complete() {
                            return Ok(());
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(_) => return Ok(()),
                }
            }
        }
    }

    /// Milliseconds since `started`, as the probe session counts them.
    fn elapsed_ms(started: std::time::Instant) -> u64 {
        u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
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
        #[allow(
            clippy::useless_conversion,
            reason = "the mode words are 32-bit on some platforms and 64-bit on others, so the \
                      widening below is a conversion on one of them and nothing on the other"
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

    /// KR-REQ-08.42 and KR-ACC-025: the answers become the state, and the typing stays apart.
    #[test]
    fn a_terminals_answers_are_read_back_as_the_state_it_reported() {
        use kr_term::probe::{InputContext, ProbeSession};

        // A Kitty terminal is expected to answer the keyboard query, so this profile asks it and
        // requires it. The terminator is written last, because its answer is what proves no earlier
        // one is still in flight.
        let asked = profile_questions(Some("xterm-kitty"));
        assert_eq!(
            asked,
            vec![
                kr_term::probe::ProbeItem::KittyKeyboard,
                kr_term::probe::ProbeItem::ModifyOtherKeys,
                kr_term::probe::ProbeItem::DeviceAttributes
            ]
        );
        let (mut session, request) =
            ProbeSession::start(0, InputContext::Clean, &asked).expect("a clean stream");
        assert!(
            request.ends_with(b"\x1b[c"),
            "the device-attributes terminator is written last: {:?}",
            String::from_utf8_lossy(&request)
        );
        // And a terminal that promises nothing beyond the terminator is asked nothing beyond it: a
        // question whose answer may not arrive is a question this command may not ask.
        assert_eq!(
            profile_questions(Some("xterm-256color")),
            vec![kr_term::probe::ProbeItem::DeviceAttributes]
        );
        assert_eq!(
            profile_questions(None),
            vec![kr_term::probe::ProbeItem::DeviceAttributes]
        );

        // Both keyboard protocols, and somebody typing through the middle of the exchange.
        session
            .observe(b"\x1b[?5uhel\x1b[Alo\x1b[>4;2m!\x1b[?62;22c", 5)
            .expect("the answers are well formed");
        let outcome = session.finish(6).expect("the terminator arrived");
        let probe = Probe::from_outcome(&outcome);
        assert_eq!(probe.keyboard.kitty, Some(5));
        assert_eq!(probe.keyboard.modify_other_keys, Some(2));
        assert_eq!(
            probe.keyboard.restore_sequences(),
            b"\x1b[=5;1u\x1b[>4;2m".to_vec(),
            "the flags are set to what was read rather than pushed onto the terminal's stack"
        );
        assert_eq!(
            probe.typed,
            b"hel\x1b[Alo!".to_vec(),
            "and the person's own bytes are theirs, in the order they typed them"
        );
        assert!(probe.no_probe.is_none(), "this attachment did ask");
    }

    /// KR-REQ-08.42: a terminal that never finishes the exchange fails the attach.
    #[test]
    fn a_terminal_that_never_answers_fails_the_attempt() {
        use kr_term::probe::{InputContext, ProbeSession};

        let (mut session, _) = ProbeSession::start(
            0,
            InputContext::Clean,
            &profile_questions(Some("xterm-kitty")),
        )
        .expect("a clean stream");
        // Everything but the terminator. A short grace window cannot prove that all late replies
        // have disappeared, so the absence of the terminator is what fails the attempt.
        session
            .observe(b"\x1b[?5u\x1b[>4;2m", 5)
            .expect("the answers are well formed");
        assert!(
            session.finish(6).is_err(),
            "without the terminator the exchange did not finish"
        );

        let (session, _) = ProbeSession::start(0, InputContext::Clean, &profile_questions(None))
            .expect("a clean stream");
        assert!(
            session
                .finish(kr_term::probe::PROBE_DEADLINE_MS + 1)
                .is_err(),
            "and the one-second bound is a failure rather than a fall back to forwarding"
        );
    }

    /// KR-REQ-08.43 and KR-ACC-025: no-probe is chosen before anything is asked, and never after.
    #[test]
    fn no_probe_is_chosen_before_any_probe_and_never_afterwards() {
        use kr_term::probe::{InputContext, NoProbeProfile, ProbeSession};

        let chosen = Probe::unasked(InputContext::Clean).expect("a clean stream");
        assert_eq!(
            chosen.no_probe,
            Some(NoProbeProfile::ConservativeProjected {
                palette: kr_term::palette::PaletteSource::DarkPreset
            }),
            "the conservative projected profile, which asks the terminal nothing"
        );
        assert_eq!(
            chosen.keyboard,
            KeyboardState::EMPTY,
            "and nothing of the terminal's own is claimed to be known"
        );
        assert!(chosen.palette.is_none());

        // A probe has already gone out on this stream. Calling no-probe now does not unsend the
        // questions, and a late reply would reach the application as keystrokes.
        assert!(
            Probe::unasked(InputContext::Contaminated).is_err(),
            "no-probe after a failed probe is refused rather than treated as clean"
        );
        assert!(
            ProbeSession::start(0, InputContext::Contaminated, &profile_questions(None)).is_err(),
            "and so is a retry on the same stream"
        );
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
    fn a_terminal_that_was_never_asked_is_left_with_the_keyboard_it_already_had() {
        // Nothing was read, which is what `--no-probe` chooses and what a terminal that answers
        // neither query leaves. There is nothing to put back, and nothing of the terminal's own is
        // taken away.
        let unknown =
            String::from_utf8_lossy(&KeyboardState::EMPTY.cleanup_sequences()).into_owned();
        assert_eq!(
            unknown, "\u{1b}[>4m",
            "the level goes back to the terminal's own and nothing else is written"
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
    fn what_a_terminal_reported_is_put_back_without_touching_anybodys_stack() {
        // The stack an application inside the session can empty with one sequence is not this
        // attachment's to operate: a pop written here would take an entry that belongs to whatever
        // was running when this attachment arrived.
        let known = KeyboardState {
            kitty: Some(5),
            modify_other_keys: Some(2),
        };
        let cleanup = String::from_utf8_lossy(&known.cleanup_sequences()).into_owned();
        assert!(
            !cleanup.contains("\u{1b}[<"),
            "nothing is popped: {cleanup:?}"
        );
        assert!(
            !cleanup.contains("\u{1b}[>0u") && !cleanup.contains("\u{1b}[>5u"),
            "and nothing is pushed: {cleanup:?}"
        );
        assert!(
            !cleanup.contains("?1049"),
            "and no buffer is entered to reach a stack: {cleanup:?}"
        );
        assert!(
            cleanup.ends_with("\u{1b}[=5;1u\u{1b}[>4;2m"),
            "what the terminal itself reported is written as the state it is: {cleanup:?}"
        );
    }
}
