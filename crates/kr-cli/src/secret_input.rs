//! Reading a secret one line at a time from a person at a terminal, or from a pipe.
//!
//! A secret is never an argument or an environment variable, because both outlive the command in
//! the shell's history and in the process list. It is typed where nothing is shown, or piped in.
//!
//! The terminal read is one function, [`read_silently`], over a [`SilentConsole`], so the same
//! rules hold on every platform: the console's mode is saved, echo is turned off, one line is read
//! a key at a time, and the saved mode is put back on every way out, a panic included. Ctrl+C and
//! Ctrl+Z are keys here, not signals, so the read can end and restore the mode before the process
//! does. The Unix binding clears the terminal's signal generation for the read; the Windows binding
//! clears processed input and reads key records.

use std::fs::File;
use std::io::Read as _;

use kr_client::shown::Shown;
use kr_crypto::secret::SecretVec;
use kr_protocol::voice_credential::MAX_VOICE_KEY_LEN;
use zeroize::Zeroizing;

use crate::error::{CliError, Result};

/// What one read of a console gives back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unit {
    /// One byte of what was typed. A character outside ASCII arrives as its UTF-8 bytes.
    Byte(u8),
    /// The key that ends a line.
    Enter,
    /// The key that deletes the last character.
    Backspace,
    /// Ctrl+C or Ctrl+Z: the person gave up.
    Cancel,
    /// The console has no more input.
    End,
}

/// The console a secret is typed at.
pub trait SilentConsole {
    /// The console's input mode, in the form it is read and set in.
    type Mode;

    /// Reads the console's current input mode.
    ///
    /// # Errors
    ///
    /// Returns an error when the console will not answer.
    fn mode(&self) -> Result<Self::Mode>;

    /// The mode that reads keys one at a time, shows none of them and turns no key into a signal,
    /// made from the one the console has.
    fn silent(&self, saved: &Self::Mode) -> Self::Mode;

    /// Sets the console's input mode.
    ///
    /// # Errors
    ///
    /// Returns an error when the console refuses the mode.
    fn set_mode(&self, mode: &Self::Mode) -> Result<()>;

    /// Waits for the next key.
    ///
    /// # Errors
    ///
    /// Returns an error when the console cannot be read.
    fn read_unit(&self) -> Result<Unit>;
}

/// Puts the saved mode back when it goes out of scope, however the read ended.
struct Restore<'a, C: SilentConsole> {
    console: &'a C,
    saved: C::Mode,
    done: bool,
}

impl<C: SilentConsole> Restore<'_, C> {
    /// Puts the mode back and says whether it worked. A mode that could not be put back is tried
    /// once more when this is dropped.
    fn restore(&mut self) -> Result<()> {
        if self.done {
            return Ok(());
        }
        self.console.set_mode(&self.saved)?;
        self.done = true;
        Ok(())
    }
}

impl<C: SilentConsole> Drop for Restore<'_, C> {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

/// Reads one line from `console` with nothing shown, and returns it without its line end.
///
/// The key is held in a buffer that clears itself. A line longer than any key is refused as soon
/// as it is, and nothing typed is put in an error.
///
/// # Errors
///
/// Returns a usage error for an empty line, the end of the input or a line longer than any key,
/// a failure for Ctrl+C or Ctrl+Z, and the console's own failure when its mode cannot be read,
/// set or put back.
pub fn read_silently<C: SilentConsole>(console: &C) -> Result<SecretVec> {
    let saved = console.mode()?;
    let silent = console.silent(&saved);
    let mut restore = Restore {
        console,
        saved,
        done: false,
    };
    console.set_mode(&silent)?;
    let typed = type_line(console);
    let left = restore.restore();
    let line = typed?;
    left?;
    Ok(line)
}

/// Reads keys until the line ends.
fn type_line<C: SilentConsole>(console: &C) -> Result<SecretVec> {
    // Room for the longest key and the byte that shows it is too long, so no growth copies what
    // was typed into a buffer that is not cleared.
    let mut line = Zeroizing::new(Vec::with_capacity(MAX_VOICE_KEY_LEN + 1));
    loop {
        match console.read_unit()? {
            Unit::Byte(byte) => {
                line.push(byte);
                if line.len() > MAX_VOICE_KEY_LEN {
                    return Err(too_long());
                }
            }
            Unit::Backspace => {
                // A character is one to four bytes: drop its continuation bytes and then it.
                while line
                    .last()
                    .is_some_and(|byte| byte & 0b1100_0000 == 0b1000_0000)
                {
                    line.pop();
                }
                line.pop();
            }
            Unit::Enter => break,
            Unit::Cancel => {
                return Err(CliError::Other(Shown::said(
                    "key entry was cancelled, so nothing was changed",
                )));
            }
            Unit::End => break,
        }
    }
    finish(line)
}

/// The line that was read, or the refusal when it is empty.
fn finish(line: Zeroizing<Vec<u8>>) -> Result<SecretVec> {
    if line.is_empty() {
        return Err(nothing_entered());
    }
    let mut line = line;
    Ok(SecretVec::new(std::mem::take(&mut *line)))
}

fn nothing_entered() -> CliError {
    CliError::Usage(Shown::said("no key was entered, so nothing was changed"))
}

fn too_long() -> CliError {
    CliError::Usage(Shown::said(
        "what was entered is longer than any key, so nothing was changed",
    ))
}

/// Reads one line from a pipe or a file: the bytes up to the first line feed, without it and
/// without a carriage return before it.
///
/// # Errors
///
/// Returns a usage error for an empty line, the end of the input or a line longer than any key,
/// and the input's own failure when it cannot be read.
pub fn read_line(input: impl std::io::Read) -> Result<SecretVec> {
    let mut line = Zeroizing::new(Vec::with_capacity(MAX_VOICE_KEY_LEN + 2));
    // One byte past a key and one for a carriage return, so a line that is too long is seen
    // without reading what follows it.
    let mut input = input.take(MAX_VOICE_KEY_LEN as u64 + 2);
    let mut byte = Zeroizing::new([0_u8; 1]);
    loop {
        match input.read(&mut byte[..]) {
            Ok(0) => break,
            Ok(_) if byte[0] == b'\n' => break,
            Ok(_) => line.push(byte[0]),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => {
                return Err(CliError::Usage(kr_client::shown!(
                    "standard input could not be read: {}",
                    Shown::io(&error)
                )));
            }
        }
    }
    if line.last() == Some(&b'\r') {
        line.pop();
    }
    if line.len() > MAX_VOICE_KEY_LEN {
        return Err(too_long());
    }
    finish(line)
}

/// A duplicate of this process's standard input, so that what is read never passes through the
/// standard library's own buffer, which is not cleared.
///
/// # Errors
///
/// Returns an error when standard input cannot be duplicated.
fn standard_input() -> Result<File> {
    #[cfg(unix)]
    let duplicate = {
        use std::os::fd::AsFd as _;
        std::io::stdin().as_fd().try_clone_to_owned()
    };
    #[cfg(windows)]
    let duplicate = {
        use std::os::windows::io::AsHandle as _;
        std::io::stdin().as_handle().try_clone_to_owned()
    };
    duplicate.map(File::from).map_err(|error| {
        CliError::Usage(kr_client::shown!(
            "standard input could not be read: {}",
            Shown::io(&error)
        ))
    })
}

/// Reads the secret from standard input: typed at a terminal that shows nothing, or one line of a
/// pipe.
///
/// # Errors
///
/// As [`read_silently`] and [`read_line`].
pub fn read_secret() -> Result<SecretVec> {
    use std::io::IsTerminal as _;

    let input = standard_input()?;
    if !std::io::stdin().is_terminal() {
        return read_line(input);
    }
    crate::report::say(&Shown::said(
        "Type or paste the OpenAI key, then press Enter. Nothing you type is shown.",
    ));
    let typed = read_typed(input);
    // The cursor is where the Enter left it, and the person's next line starts on its own.
    crate::report::say(&Shown::said(""));
    typed
}

#[cfg(unix)]
fn read_typed(terminal: File) -> Result<SecretVec> {
    read_silently(&unix::Terminal { terminal })
}

#[cfg(windows)]
fn read_typed(_input: File) -> Result<SecretVec> {
    read_silently(&windows::Console::open()?)
}

#[cfg(unix)]
mod unix {
    use std::fs::File;

    use kr_client::shown;
    use rustix::termios::{InputModes, LocalModes, OptionalActions, SpecialCodeIndex, Termios};

    use super::{SilentConsole, Unit};
    use crate::error::{CliError, Result};

    /// The terminal standard input is.
    pub struct Terminal {
        pub terminal: File,
    }

    fn failed(error: rustix::io::Errno) -> CliError {
        CliError::Terminal(shown!(
            "the terminal's modes could not be changed: {}",
            crate::shown::errno(error)
        ))
    }

    impl SilentConsole for Terminal {
        type Mode = Termios;

        fn mode(&self) -> Result<Termios> {
            rustix::termios::tcgetattr(&self.terminal).map_err(failed)
        }

        fn silent(&self, saved: &Termios) -> Termios {
            let mut silent = saved.clone();
            // No echo, no line editing, no signal from a key, and no key that the terminal
            // handles itself, so every key reaches this read as the byte it is.
            silent.local_modes.remove(
                LocalModes::ICANON
                    | LocalModes::ECHO
                    | LocalModes::ECHONL
                    | LocalModes::ISIG
                    | LocalModes::IEXTEN,
            );
            silent.input_modes.remove(
                InputModes::ICRNL | InputModes::INLCR | InputModes::IGNCR | InputModes::IXON,
            );
            silent.special_codes[SpecialCodeIndex::VMIN] = 1;
            silent.special_codes[SpecialCodeIndex::VTIME] = 0;
            silent
        }

        fn set_mode(&self, mode: &Termios) -> Result<()> {
            // Waiting for output to drain can be ended by a signal, so the call is asked again. It
            // also discards what was typed ahead, which is not for the shell.
            loop {
                match rustix::termios::tcsetattr(&self.terminal, OptionalActions::Flush, mode) {
                    Ok(()) => return Ok(()),
                    Err(rustix::io::Errno::INTR) => {}
                    Err(error) => return Err(failed(error)),
                }
            }
        }

        fn read_unit(&self) -> Result<Unit> {
            let mut byte = [0_u8; 1];
            loop {
                match rustix::io::read(&self.terminal, &mut byte) {
                    Ok(0) => return Ok(Unit::End),
                    Ok(_) => return Ok(unit(byte[0])),
                    Err(rustix::io::Errno::INTR) => {}
                    Err(error) => {
                        return Err(CliError::Terminal(shown!(
                            "the terminal could not be read: {}",
                            crate::shown::errno(error)
                        )));
                    }
                }
            }
        }
    }

    /// What a byte typed at a terminal that handles none of its keys means.
    pub(super) const fn unit(byte: u8) -> Unit {
        match byte {
            b'\r' | b'\n' => Unit::Enter,
            0x7f | 0x08 => Unit::Backspace,
            // Ctrl+C and Ctrl+Z.
            0x03 | 0x1a => Unit::Cancel,
            // Ctrl+D.
            0x04 => Unit::End,
            other => Unit::Byte(other),
        }
    }
}

/// The Windows console's binding.
#[cfg(windows)]
pub mod windows {
    use std::cell::RefCell;
    use std::collections::VecDeque;

    use windows_sys::Win32::System::Console::{
        ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT, ENABLE_PROCESSED_INPUT,
    };

    use super::{SilentConsole, Unit};
    use crate::error::Result;
    use crate::platform::ControllingTerminal;
    use crate::windows::records::{ConsoleEvent, RecordReader};

    /// The console this process is attached to, read one key record at a time.
    pub struct Console {
        terminal: ControllingTerminal,
        reader: RefCell<Reader>,
    }

    struct Reader {
        records: RecordReader,
        waiting: VecDeque<Unit>,
        /// The first half of a character outside the basic plane whose second half has not come.
        high: Option<u16>,
    }

    impl Console {
        /// Opens this process's console.
        ///
        /// # Errors
        ///
        /// Returns an error when this process has no console.
        pub fn open() -> Result<Self> {
            let terminal = ControllingTerminal::open()?;
            let handle = terminal.handle().try_clone().map_err(|error| {
                crate::error::CliError::Terminal(kr_client::shown!(
                    "the console could not be read: {}",
                    kr_client::shown::Shown::io(&error)
                ))
            })?;
            Ok(Self {
                terminal,
                reader: RefCell::new(Reader {
                    records: RecordReader::over(handle),
                    waiting: VecDeque::new(),
                    high: None,
                }),
            })
        }
    }

    impl SilentConsole for Console {
        type Mode = u32;

        fn mode(&self) -> Result<u32> {
            Ok(self.terminal.modes()?.input)
        }

        fn silent(&self, saved: &u32) -> u32 {
            // Raw: no line editing, no echo and no processing, so Ctrl+C is a key record.
            saved & !(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT)
        }

        fn set_mode(&self, mode: &u32) -> Result<()> {
            self.terminal.set_input_mode(*mode)
        }

        fn read_unit(&self) -> Result<Unit> {
            let mut reader = self.reader.borrow_mut();
            loop {
                if let Some(unit) = reader.waiting.pop_front() {
                    return Ok(unit);
                }
                for event in reader.records.read()? {
                    if let ConsoleEvent::Key(key) = event
                        && key.key_down
                    {
                        reader.take(key.unicode, key.virtual_key);
                    }
                }
            }
        }
    }

    impl Reader {
        /// Turns one key-down record into the units it stands for.
        fn take(&mut self, unicode: u16, virtual_key: u16) {
            const VK_BACK: u16 = 0x08;
            const VK_RETURN: u16 = 0x0d;
            match (unicode, virtual_key) {
                (0x03 | 0x1a, _) => self.waiting.push_back(Unit::Cancel),
                (_, VK_RETURN) | (0x0d | 0x0a, _) => self.waiting.push_back(Unit::Enter),
                (_, VK_BACK) | (0x08, _) => self.waiting.push_back(Unit::Backspace),
                (0, _) => {}
                (unit, _) => {
                    let character = match (self.high.take(), unit) {
                        (_, high @ 0xd800..=0xdbff) => {
                            self.high = Some(high);
                            return;
                        }
                        (Some(high), low @ 0xdc00..=0xdfff) => {
                            char::decode_utf16([high, low]).next().and_then(|c| c.ok())
                        }
                        _ => char::decode_utf16([unit]).next().and_then(|c| c.ok()),
                    };
                    // A half that has no other half is not a character: it is kept as the
                    // replacement character, which no key contains.
                    let character = character.unwrap_or(char::REPLACEMENT_CHARACTER);
                    let mut bytes = [0_u8; 4];
                    for &byte in character.encode_utf8(&mut bytes).as_bytes() {
                        self.waiting.push_back(Unit::Byte(byte));
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::collections::VecDeque;

    /// A console that is a script of what a person does, and a record of the modes set on it.
    struct Fake {
        mode: Cell<u32>,
        keys: RefCell<VecDeque<Result<Unit>>>,
        /// Every mode set, in order.
        set: RefCell<Vec<u32>>,
        /// Makes the nth `set_mode` fail (counting from 1), if any.
        failing_set: Cell<Option<usize>>,
        mode_unreadable: Cell<bool>,
        panic_on_read: Cell<bool>,
    }

    const ECHO_ON: u32 = 0b1011;
    const ECHO_OFF: u32 = 0b0000;

    impl Fake {
        fn typing(text: &str, end: Unit) -> Self {
            let mut keys: VecDeque<Result<Unit>> =
                text.bytes().map(|b| Ok(Unit::Byte(b))).collect();
            keys.push_back(Ok(end));
            Self::with(keys)
        }

        fn with(keys: VecDeque<Result<Unit>>) -> Self {
            Self {
                mode: Cell::new(ECHO_ON),
                keys: RefCell::new(keys),
                set: RefCell::new(Vec::new()),
                failing_set: Cell::new(None),
                mode_unreadable: Cell::new(false),
                panic_on_read: Cell::new(false),
            }
        }
    }

    impl SilentConsole for Fake {
        type Mode = u32;

        fn mode(&self) -> Result<u32> {
            if self.mode_unreadable.get() {
                return Err(CliError::Terminal(Shown::said(
                    "the console did not answer",
                )));
            }
            Ok(self.mode.get())
        }

        fn silent(&self, _saved: &u32) -> u32 {
            ECHO_OFF
        }

        fn set_mode(&self, mode: &u32) -> Result<()> {
            let mut set = self.set.borrow_mut();
            set.push(*mode);
            if self.failing_set.get() == Some(set.len()) {
                return Err(CliError::Terminal(Shown::said(
                    "the console refused the mode",
                )));
            }
            self.mode.set(*mode);
            Ok(())
        }

        fn read_unit(&self) -> Result<Unit> {
            assert!(
                !self.panic_on_read.get(),
                "the console failed under the read"
            );
            assert_eq!(
                self.mode.get(),
                ECHO_OFF,
                "a key is read only with echo off"
            );
            self.keys.borrow_mut().pop_front().unwrap_or(Ok(Unit::End))
        }
    }

    const KEY: &str = "sk-sentinel-0123456789abcdef";

    fn refusal_text(error: &CliError) -> String {
        error.to_string()
    }

    /// C1a: the read clears echo, reads one line and puts the saved mode back after a success, a
    /// cancel, an empty line, the end of the input, a read error, a mode error and a panic, and
    /// no sentence it ends with carries what was typed.
    #[test]
    fn a_silent_console_read_clears_echo_reads_one_line_and_restores_the_mode_on_success_cancel_and_failure()
     {
        // Success: the line without its end, echo off while it was read, the mode back after.
        let console = Fake::typing(KEY, Unit::Enter);
        let line = read_silently(&console).expect("a line is read");
        assert_eq!(line.expose(), KEY.as_bytes());
        assert_eq!(*console.set.borrow(), vec![ECHO_OFF, ECHO_ON]);
        assert_eq!(console.mode.get(), ECHO_ON);

        // Backspace deletes one character, a multi-byte one whole.
        let console = Fake::with(
            "ab\u{e9}"
                .bytes()
                .map(|byte| Ok(Unit::Byte(byte)))
                .chain([Ok(Unit::Backspace), Ok(Unit::Byte(b'c')), Ok(Unit::Enter)])
                .collect(),
        );
        assert_eq!(read_silently(&console).expect("read").expose(), b"abc");

        // Ctrl+C and Ctrl+Z end the read as cancelled, with what was typed not in the answer.
        let console = Fake::typing(KEY, Unit::Cancel);
        let error = read_silently(&console).expect_err("a cancelled read gives no key");
        assert!(refusal_text(&error).contains("cancelled"), "{error}");
        assert!(!refusal_text(&error).contains("sentinel"), "{error}");
        assert_eq!(
            console.mode.get(),
            ECHO_ON,
            "the mode is back after a cancel"
        );

        // An empty line and the end of the input give no key and restore the mode.
        for end in [Unit::Enter, Unit::End] {
            let console = Fake::typing("", end);
            let error = read_silently(&console).expect_err("an empty read gives no key");
            assert!(
                refusal_text(&error).contains("no key was entered"),
                "{error}"
            );
            assert_eq!(console.mode.get(), ECHO_ON);
        }

        // A line longer than any key is refused as it grows.
        let console = Fake::typing(&"k".repeat(MAX_VOICE_KEY_LEN + 1), Unit::Enter);
        let error = read_silently(&console).expect_err("a long line is refused");
        assert!(
            refusal_text(&error).contains("longer than any key"),
            "{error}"
        );
        assert_eq!(console.mode.get(), ECHO_ON);
        // The longest key is taken.
        let console = Fake::typing(&"k".repeat(MAX_VOICE_KEY_LEN), Unit::Enter);
        assert_eq!(
            read_silently(&console).expect("read").expose().len(),
            MAX_VOICE_KEY_LEN
        );

        // A read error ends the read and the mode is back.
        let console = Fake::with(VecDeque::from([
            Ok(Unit::Byte(b'a')),
            Err(CliError::Terminal(Shown::said(
                "the console could not be read",
            ))),
        ]));
        let error = read_silently(&console).expect_err("a failed read gives no key");
        assert!(
            refusal_text(&error).contains("could not be read"),
            "{error}"
        );
        assert_eq!(console.mode.get(), ECHO_ON);

        // A mode that cannot be read: nothing was changed, nothing is set.
        let console = Fake::typing(KEY, Unit::Enter);
        console.mode_unreadable.set(true);
        read_silently(&console).expect_err("an unreadable mode gives no key");
        assert!(console.set.borrow().is_empty());

        // A mode that cannot be set to silent: no key is read and nothing was changed.
        let console = Fake::typing(KEY, Unit::Enter);
        console.failing_set.set(Some(1));
        read_silently(&console).expect_err("a refused silent mode gives no key");
        assert_eq!(console.mode.get(), ECHO_ON);

        // A mode that cannot be put back is an error, even after a good line, and is tried once
        // more when the guard is dropped.
        let console = Fake::typing(KEY, Unit::Enter);
        console.failing_set.set(Some(2));
        let error = read_silently(&console).expect_err("an unrestored mode is a failure");
        assert!(refusal_text(&error).contains("refused the mode"), "{error}");
        assert_eq!(
            *console.set.borrow(),
            vec![ECHO_OFF, ECHO_ON, ECHO_ON],
            "the guard asks again"
        );
        assert_eq!(console.mode.get(), ECHO_ON);

        // A panic under the read puts the mode back.
        let console = Fake::typing(KEY, Unit::Enter);
        console.panic_on_read.set(true);
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = read_silently(&console);
        }));
        assert!(caught.is_err(), "the panic goes on");
        assert_eq!(
            console.mode.get(),
            ECHO_ON,
            "the mode is back after a panic"
        );
    }

    /// A pipe is read as one line: its first line, without the line end, and no more.
    #[test]
    fn a_pipe_is_read_as_one_line_without_its_end() {
        let line = |text: &[u8]| read_line(text).map(|secret| secret.expose().to_vec());
        assert_eq!(line(b"abc\n").expect("read"), b"abc");
        assert_eq!(line(b"abc\r\n").expect("read"), b"abc");
        assert_eq!(line(b"abc").expect("read"), b"abc");
        assert_eq!(line(b"abc\nsecond line\n").expect("read"), b"abc");
        assert!(line(b"").is_err(), "an empty pipe gives no key");
        assert!(line(b"\n").is_err(), "an empty line gives no key");
        let longest = "k".repeat(MAX_VOICE_KEY_LEN);
        assert_eq!(
            line(format!("{longest}\n").as_bytes()).expect("read").len(),
            MAX_VOICE_KEY_LEN
        );
        let error = line(format!("{longest}k\n").as_bytes()).expect_err("too long");
        assert!(error.to_string().contains("longer than any key"), "{error}");
    }

    /// What a byte at a terminal that handles none of its keys means.
    #[cfg(unix)]
    #[test]
    fn a_byte_typed_at_a_raw_terminal_means_what_the_key_does() {
        assert_eq!(unix::unit(b'\r'), Unit::Enter);
        assert_eq!(unix::unit(b'\n'), Unit::Enter);
        assert_eq!(unix::unit(0x7f), Unit::Backspace);
        assert_eq!(unix::unit(0x03), Unit::Cancel);
        assert_eq!(unix::unit(0x1a), Unit::Cancel);
        assert_eq!(unix::unit(0x04), Unit::End);
        assert_eq!(unix::unit(b'x'), Unit::Byte(b'x'));
    }
}
