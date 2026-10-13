//! Reading a recovery kit at the command line.
//!
//! A recovery kit holds the seed that opens every backup, so how it gets into this process is the
//! command's most careful step. It is never an argument, where a process listing and a shell's
//! history would keep it. It comes from one of three places:
//!
//! * a file the person names ([`KitSource::File`]), which has to be a regular file;
//! * standard input when it is not a terminal, such as a pipe;
//! * standard input when it is a terminal (Unix only): one pasted document, with nothing shown, that
//!   ends at the first blank line after its first line, at Ctrl-D, or at the size bound.
//!
//! Every read is made into one buffer of a fixed size that clears itself when it is dropped, from a
//! file made out of a duplicate of descriptor 0 or from the file named, and never through
//! `std::io::Stdin`, whose buffer is private to the standard library and is never cleared. The raw
//! bound is [`RAW_LIMIT`] bytes, so a kit saved by an editor with a byte-order mark and CR LF line
//! ends still reads; a leading mark and the CRs are removed in that buffer, and the kit's own
//! bound ([`kr_client::recovery::MAX_RECOVERY_KIT_BYTES`]) applies to what is left.
//!
//! A read can be cancelled: a pipe is waited on in short turns that look at a flag, and a terminal
//! is read with a short timeout that does the same. When it ends, however it ends, the terminal's
//! modes come back with the input still waiting discarded (`OptionalActions::Flush`), so what was
//! pasted past the end of the kit never reaches the shell or its history. A paste that arrives
//! after that still does; for a paste the size of a kit it is unlikely, and the documentation says
//! so.

use std::fs::File;
use std::io::IsTerminal as _;
#[cfg(unix)]
use std::io::Read as _;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use kr_client::recovery::parse_kit;
use kr_client::shown;
use kr_client::shown::Shown;
use kr_protocol::archive::RecoveryKit;
use zeroize::Zeroizing;

use super::interrupt::{self, Interrupt};
use crate::error::{CliError, Result};

/// The most bytes read before the document is turned away: a kit at its bound, with the byte-order
/// mark and the CR of every line an editor can add.
pub const RAW_LIMIT: usize = 2048;

/// The buffer's size: one byte past the limit, so a document over it is seen as over.
const CAPACITY: usize = RAW_LIMIT + 1;

/// How long a person may leave the terminal prompt without typing before the command gives up.
#[cfg(unix)]
const IDLE_LIMIT: std::time::Duration = std::time::Duration::from_secs(10 * 60);

/// Where a kit is read from.
#[derive(Clone, PartialEq, Eq)]
pub enum KitSource {
    /// A file the person named.
    File(PathBuf),
    /// Standard input: typed at a terminal, or piped.
    Standard,
}

kr_client::debug_as_name!(KitSource);

/// How the kit came in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Entered {
    /// From a file.
    File,
    /// From standard input, which was not a terminal.
    Piped,
    /// Typed or pasted at the terminal.
    Typed,
}

/// A kit that was read, and how.
pub struct KitRead {
    /// The kit, whose checksum holds.
    pub kit: RecoveryKit,
    /// Where it came from.
    pub entered: Entered,
}

kr_client::debug_as_name!(KitRead);

/// Reads the kit from `source`, ending the read cleanly if `interrupt` arrives first.
///
/// # Errors
///
/// Returns a usage failure for a document that is not a recovery kit, a file that is not a regular
/// file, and a terminal prompt where none is offered; a terminal failure when the terminal cannot be
/// read or its modes cannot be changed or put back; and the interrupt's failure when it arrives.
pub async fn read(source: KitSource, interrupt: &mut Interrupt) -> Result<KitRead> {
    if source == KitSource::Standard && !std::io::stdin().is_terminal() {
        // Said before the wait begins, so a script that feeds the kit knows the command is
        // listening, and a person who ran the command by mistake sees what it waits for.
        crate::report::say(&Shown::said(
            "Reading the recovery kit from standard input.",
        ));
    }
    let cancel = Arc::new(AtomicBool::new(false));
    let reader = {
        let cancel = Arc::clone(&cancel);
        tokio::task::spawn_blocking(move || read_blocking(&source, &cancel))
    };
    tokio::pin!(reader);
    tokio::select! {
        done = &mut reader => done.map_err(|error| {
            CliError::Other(shown!("the recovery kit could not be read: {}", Shown::task(&error)))
        })?,
        () = interrupt.arrived() => {
            // The reader owns the buffer that holds the kit. It is waited for, so that buffer is
            // cleared and the terminal is back before this command goes on to say it stopped.
            cancel.store(true, Ordering::SeqCst);
            let _ = (&mut reader).await;
            Err(interrupt::stopped())
        }
    }
}

fn read_blocking(source: &KitSource, cancel: &AtomicBool) -> Result<KitRead> {
    let mut document = Document::new();
    let entered = match source {
        KitSource::File(path) => {
            read_file(path, &mut document)?;
            Entered::File
        }
        KitSource::Standard => read_standard_input(&mut document, cancel)?,
    };
    Ok(KitRead {
        kit: document.into_kit()?,
        entered,
    })
}

/// Puts `question` on the error stream and reads the person's answer: one line from the terminal on
/// standard input, with echo on, or none at the end of the input.
///
/// The read is made on a thread of its own and is not waited for when this future is dropped, so
/// Ctrl-C at a question stops the run at once, however the descriptor behaves: some terminal
/// devices cannot be waited on with a timeout, and a blocking read is not ended by a signal that
/// restarts it. The thread holds nothing but a duplicate of the descriptor and the answer so far,
/// and ends with the process.
///
/// # Errors
///
/// Returns a terminal failure when the answer cannot be read.
pub async fn ask_line(question: &Shown) -> Result<Option<String>> {
    crate::report::say(question);
    let (answer, arrives) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name("answer".to_owned())
        .spawn(move || {
            // Nobody is waiting once the run was stopped, and the answer is not needed then.
            let _ = answer.send(read_answer());
        })
        .map_err(|error| {
            CliError::Terminal(shown!(
                "your answer could not be read: {}",
                Shown::io(&error)
            ))
        })?;
    arrives
        .await
        .map_err(|_| CliError::Terminal(Shown::said("your answer could not be read")))?
}

#[cfg(unix)]
fn read_answer() -> Result<Option<String>> {
    use rustix::event::{PollFd, PollFlags, poll};
    use std::os::fd::AsFd as _;

    /// An answer is a word; this is more than any answer needs.
    const LONGEST_ANSWER: usize = 4096;

    let duplicate = std::io::stdin()
        .as_fd()
        .try_clone_to_owned()
        .map_err(|error| answer_unreadable(&error))?;
    let mut input = File::from(duplicate);
    let mut answer: Vec<u8> = Vec::new();
    let mut chunk = [0_u8; 256];
    // A descriptor that cannot be polled (a terminal device on some systems) is read plainly.
    let mut pollable = true;
    loop {
        if pollable {
            // A descriptor in non-blocking mode is waited for, so the read does not spin.
            let mut waiting = [PollFd::new(&input, PollFlags::IN)];
            match poll(&mut waiting, None) {
                Err(rustix::io::Errno::INTR) => continue,
                Ok(_) => pollable = !waiting[0].revents().contains(PollFlags::NVAL),
                Err(error) => {
                    return Err(CliError::Terminal(shown!(
                        "your answer could not be waited for: {}",
                        crate::shown::errno(error)
                    )));
                }
            }
        }
        match input.read(&mut chunk) {
            Ok(0) => break,
            Ok(taken) => {
                answer.extend_from_slice(&chunk[..taken]);
                if answer.contains(&b'\n') || answer.len() >= LONGEST_ANSWER {
                    break;
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
                ) => {}
            Err(error) => return Err(answer_unreadable(&error)),
        }
    }
    if answer.is_empty() {
        return Ok(None);
    }
    let line = answer
        .split(|byte| *byte == b'\n')
        .next()
        .unwrap_or_default();
    // Text that is not UTF-8 is not yes: a decline, said as one.
    Ok(Some(String::from_utf8_lossy(line).into_owned()))
}

#[cfg(windows)]
fn read_answer() -> Result<Option<String>> {
    Err(CliError::Usage(Shown::said(
        "this build does not ask at a console; run the command with --preview and then with \
         --confirm-plan and the digest it printed",
    )))
}

#[cfg(unix)]
fn answer_unreadable(error: &std::io::Error) -> CliError {
    CliError::Terminal(shown!(
        "your answer could not be read: {}",
        Shown::io(error)
    ))
}

/// What a person is shown of a kit before it is used, with echo on: where it looks, and nothing
/// that opens anything.
#[must_use]
pub fn read_back(kit: &RecoveryKit) -> Vec<Shown> {
    let mut lines = vec![Shown::said(
        "Read a recovery kit whose checksum holds, naming:",
    )];
    for origin in &kit.service_origins {
        lines.push(shown!("  service {}", Shown::address(origin)));
    }
    lines.push(shown!(
        "  backup locator starting {}",
        crate::shown::locator_start(&kit.bundle_locator)
    ));
    lines
}

/* -------------------------------------------------------------------------- */
/* The buffer                                                                  */
/* -------------------------------------------------------------------------- */

/// The document as it is read: one buffer, whole from the first read, cleared when dropped.
struct Document {
    bytes: Zeroizing<Box<[u8]>>,
    len: usize,
}

impl Document {
    fn new() -> Self {
        Self {
            bytes: Zeroizing::new(vec![0_u8; CAPACITY].into_boxed_slice()),
            len: 0,
        }
    }

    fn spare(&mut self) -> &mut [u8] {
        &mut self.bytes[self.len..]
    }

    fn advance(&mut self, taken: usize) {
        self.len += taken;
    }

    const fn full(&self) -> bool {
        self.len == CAPACITY
    }

    /// Adds one byte, and says whether there was room.
    #[cfg(unix)]
    fn push(&mut self, byte: u8) -> bool {
        if self.full() {
            return false;
        }
        self.bytes[self.len] = byte;
        self.len += 1;
        true
    }

    /// Takes the last byte back and clears it.
    #[cfg(unix)]
    fn pop(&mut self) {
        if self.len > 0 {
            self.len -= 1;
            self.bytes[self.len] = 0;
        }
    }

    #[cfg(unix)]
    fn last(&self) -> Option<u8> {
        self.len.checked_sub(1).map(|at| self.bytes[at])
    }

    /// Removes a leading byte-order mark and every CR in place, then reads the kit.
    fn into_kit(mut self) -> Result<RecoveryKit> {
        if self.len > RAW_LIMIT {
            return Err(too_long());
        }
        let mut start = 0;
        if self.bytes[..self.len].starts_with(&[0xEF, 0xBB, 0xBF]) {
            start = 3;
        }
        let mut kept = 0;
        for at in start..self.len {
            let byte = self.bytes[at];
            if byte != b'\r' {
                self.bytes[kept] = byte;
                kept += 1;
            }
        }
        // What was shifted out of place is cleared; the tail is not part of the document.
        for at in kept..self.len {
            self.bytes[at] = 0;
        }
        self.len = kept;
        let text = std::str::from_utf8(&self.bytes[..self.len]).map_err(|_| {
            CliError::Usage(Shown::said("that is not a recovery kit: it is not text"))
        })?;
        parse_kit(text).map_err(|error| CliError::Usage(shown!("{}", error)))
    }
}

fn too_long() -> CliError {
    CliError::Usage(Shown::said(
        "that is not a recovery kit: it is longer than any recovery kit",
    ))
}

/* -------------------------------------------------------------------------- */
/* A file                                                                      */
/* -------------------------------------------------------------------------- */

fn read_file(path: &std::path::Path, document: &mut Document) -> Result<()> {
    let named = crate::shown::named(path);
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    // A pipe with no writer would hold the open for ever. Opened without waiting, it opens, and is
    // then refused for what it is.
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let mut file = options.open(path).map_err(|error| {
        CliError::Usage(shown!(
            "the recovery kit {} could not be opened: {}",
            named,
            Shown::io(&error)
        ))
    })?;
    let is_file = file
        .metadata()
        .map_err(|error| {
            CliError::Usage(shown!(
                "the recovery kit {} could not be inspected: {}",
                named,
                Shown::io(&error)
            ))
        })?
        .is_file();
    if !is_file {
        return Err(CliError::Usage(shown!(
            "{} is not a regular file, and a recovery kit is read only from one; pipe it to \
             standard input instead",
            named
        )));
    }
    read_to_end(&mut file, document)
}

/// Reads until the end of the input or the bound, never growing the buffer.
fn read_to_end(source: &mut impl std::io::Read, document: &mut Document) -> Result<()> {
    while !document.full() {
        match source.read(document.spare()) {
            Ok(0) => break,
            Ok(taken) => document.advance(taken),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(unreadable(&error)),
        }
    }
    Ok(())
}

fn unreadable(error: &std::io::Error) -> CliError {
    CliError::Terminal(shown!(
        "the recovery kit could not be read: {}",
        Shown::io(error)
    ))
}

/* -------------------------------------------------------------------------- */
/* Standard input                                                              */
/* -------------------------------------------------------------------------- */

#[cfg(unix)]
fn read_standard_input(document: &mut Document, cancel: &AtomicBool) -> Result<Entered> {
    use std::os::fd::AsFd as _;

    // A duplicate of descriptor 0, so that what is read never passes through the standard
    // library's own buffer.
    let duplicate = std::io::stdin()
        .as_fd()
        .try_clone_to_owned()
        .map_err(|error| unreadable(&error))?;
    let mut input = File::from(duplicate);
    if rustix::termios::isatty(&input) {
        read_terminal(&input, document, cancel)?;
        Ok(Entered::Typed)
    } else {
        read_stream(&mut input, document, cancel)?;
        Ok(Entered::Piped)
    }
}

/// Reads a pipe or a file on standard input, one read at a time as it becomes readable, looking at
/// the flag between turns.
#[cfg(unix)]
fn read_stream(input: &mut File, document: &mut Document, cancel: &AtomicBool) -> Result<()> {
    use rustix::event::{PollFd, PollFlags, Timespec, poll};

    let turn = Timespec {
        tv_sec: 0,
        tv_nsec: 100_000_000,
    };
    while !document.full() {
        if cancel.load(Ordering::SeqCst) {
            return Err(interrupt::stopped());
        }
        let mut waiting = [PollFd::new(&*input, PollFlags::IN)];
        match poll(&mut waiting, Some(&turn)) {
            Ok(0) => continue,
            Ok(_) => {}
            Err(rustix::io::Errno::INTR) => continue,
            Err(error) => {
                return Err(CliError::Terminal(shown!(
                    "the recovery kit could not be waited for: {}",
                    crate::shown::errno(error)
                )));
            }
        }
        let events = waiting[0].revents();
        if events.contains(PollFlags::NVAL) {
            // A descriptor that cannot be polled is read plainly.
            return read_to_end(input, document);
        }
        // Readable, hung up or in error: one read says which. A hang-up with nothing left reads as
        // the end of the input.
        match input.read(document.spare()) {
            Ok(0) => break,
            Ok(taken) => document.advance(taken),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
                ) => {}
            Err(error) => return Err(unreadable(&error)),
        }
    }
    Ok(())
}

#[cfg(windows)]
fn read_standard_input(document: &mut Document, _cancel: &AtomicBool) -> Result<Entered> {
    use std::io::IsTerminal as _;
    use std::os::windows::io::AsHandle as _;

    if std::io::stdin().is_terminal() {
        return Err(CliError::Usage(Shown::said(
            "this build does not read a recovery kit typed at a console; name it with --kit-file, \
             or pipe it to standard input",
        )));
    }
    let duplicate = std::io::stdin()
        .as_handle()
        .try_clone_to_owned()
        .map_err(|error| unreadable(&error))?;
    let mut input = File::from(duplicate);
    read_to_end(&mut input, document)?;
    Ok(Entered::Piped)
}

/* -------------------------------------------------------------------------- */
/* The terminal                                                                */
/* -------------------------------------------------------------------------- */

/// The terminal's modes while the kit is typed: no echo, no line editing, and a read that returns
/// after two tenths of a second with or without input. `ISIG` stays, so Ctrl-C is still an
/// interrupt.
#[cfg(unix)]
struct Prompt<'a> {
    terminal: &'a File,
    saved: rustix::termios::Termios,
    restored: bool,
}

#[cfg(unix)]
impl<'a> Prompt<'a> {
    fn enter(terminal: &'a File) -> Result<Self> {
        use rustix::termios::{InputModes, LocalModes, OptionalActions, SpecialCodeIndex};

        let failed = |error: rustix::io::Errno| {
            CliError::Terminal(shown!(
                "the terminal's modes could not be changed: {}",
                crate::shown::errno(error)
            ))
        };
        let saved = rustix::termios::tcgetattr(terminal).map_err(failed)?;
        let mut silent = saved.clone();
        silent
            .local_modes
            .remove(LocalModes::ICANON | LocalModes::ECHO | LocalModes::ECHONL);
        // A carriage return stays one, so a CR LF line end can be told from two line ends.
        silent.input_modes.remove(InputModes::ICRNL);
        silent.special_codes[SpecialCodeIndex::VMIN] = 0;
        silent.special_codes[SpecialCodeIndex::VTIME] = 2;
        // What was typed before this prompt was shown was echoed, and is not part of the kit.
        rustix::termios::tcsetattr(terminal, OptionalActions::Flush, &silent).map_err(failed)?;
        Ok(Self {
            terminal,
            saved,
            restored: false,
        })
    }

    /// Puts the modes back, discarding the input still waiting: what was pasted past the end of the
    /// kit is not for the shell.
    fn leave(&mut self) -> Result<()> {
        use rustix::termios::OptionalActions;

        if self.restored {
            return Ok(());
        }
        loop {
            match rustix::termios::tcsetattr(self.terminal, OptionalActions::Flush, &self.saved) {
                Ok(()) => break,
                Err(rustix::io::Errno::INTR) => {}
                // Not marked restored, so dropping this tries once more.
                Err(error) => {
                    return Err(CliError::Terminal(shown!(
                        "the terminal's modes could not be put back: {}",
                        crate::shown::errno(error)
                    )));
                }
            }
        }
        self.restored = true;
        Ok(())
    }
}

#[cfg(unix)]
impl Drop for Prompt<'_> {
    fn drop(&mut self) {
        let _ = self.leave();
    }
}

#[cfg(unix)]
fn read_terminal(terminal: &File, document: &mut Document, cancel: &AtomicBool) -> Result<()> {
    let mut prompt = Prompt::enter(terminal)?;
    crate::report::say(&Shown::said(
        "Paste the recovery kit, then press Enter on an empty line. Nothing you paste is shown.",
    ));
    let typed =
        type_document(terminal, document, cancel).inspect(|()| discard_the_rest(terminal, cancel));
    let left = prompt.leave();
    // The cursor is where the paste left it.
    crate::report::say(&Shown::said(""));
    typed?;
    left
}

/// Reads and throws away what is still arriving after the document ended, until a read finds
/// nothing more or the read is cancelled, so that a paste that comes in more than one piece does
/// not reach the shell.
#[cfg(unix)]
fn discard_the_rest(terminal: &File, cancel: &AtomicBool) {
    let mut chunk = Zeroizing::new([0_u8; 256]);
    // Bounded, so input that never stops cannot hold the command.
    for _ in 0..64 {
        if cancel.load(Ordering::SeqCst) {
            break;
        }
        match rustix::io::read(terminal, &mut chunk[..]) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
    }
}

/// Reads what is typed until the document ends.
#[cfg(unix)]
fn type_document(terminal: &File, document: &mut Document, cancel: &AtomicBool) -> Result<()> {
    let mut chunk = Zeroizing::new([0_u8; 256]);
    let mut typing = Typing::default();
    let mut last_input = std::time::Instant::now();
    loop {
        if cancel.load(Ordering::SeqCst) {
            return Err(interrupt::stopped());
        }
        let taken = match rustix::io::read(terminal, &mut chunk[..]) {
            Ok(taken) => taken,
            Err(rustix::io::Errno::INTR) => continue,
            Err(error) => {
                return Err(CliError::Terminal(shown!(
                    "the recovery kit could not be read: {}",
                    crate::shown::errno(error)
                )));
            }
        };
        if taken == 0 {
            if last_input.elapsed() > IDLE_LIMIT {
                return Err(CliError::Usage(Shown::said(
                    "no recovery kit was typed, so the command stopped waiting",
                )));
            }
            continue;
        }
        last_input = std::time::Instant::now();
        for &byte in &chunk[..taken] {
            if typing.feed(byte, document) == Typed::Finished {
                return Ok(());
            }
        }
    }
}

#[cfg(unix)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum Typed {
    More,
    Finished,
}

/// Where the typing is inside an escape sequence.
#[cfg(unix)]
#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum Escape {
    #[default]
    None,
    Introduced,
    Sequence,
}

/// The minimal line editing the prompt does for itself, with the terminal's own turned off.
#[cfg(unix)]
#[derive(Default)]
struct Typing {
    escape: Escape,
    /// Whether the document has a first line yet.
    started: bool,
    /// Whether the byte before was a carriage return, so a line feed after it ends no second line.
    after_return: bool,
}

#[cfg(unix)]
impl Typing {
    fn feed(&mut self, byte: u8, document: &mut Document) -> Typed {
        match self.escape {
            Escape::Introduced => {
                self.escape = if byte == b'[' {
                    Escape::Sequence
                } else {
                    Escape::None
                };
                return Typed::More;
            }
            Escape::Sequence => {
                if (0x40..=0x7e).contains(&byte) {
                    self.escape = Escape::None;
                }
                return Typed::More;
            }
            Escape::None => {}
        }
        let was_return = std::mem::take(&mut self.after_return);
        match byte {
            0x1b => self.escape = Escape::Introduced,
            // Ctrl-D ends the document where the terminal's own end of input is switched off.
            0x04 => return Typed::Finished,
            0x7f | 0x08 => {
                if document.last().is_some_and(|last| last != b'\n') {
                    document.pop();
                }
            }
            // The line feed of a CR LF line end is the same line end.
            b'\n' if was_return => {}
            b'\n' | b'\r' => {
                self.after_return = byte == b'\r';
                let at_line_start = document.last().is_none_or(|last| last == b'\n');
                if at_line_start {
                    // An empty line after the first ends the document; before it, it is ignored.
                    if self.started {
                        return Typed::Finished;
                    }
                } else {
                    self.started = true;
                    if !document.push(b'\n') {
                        return Typed::Finished;
                    }
                }
            }
            0x00..=0x1f => {}
            other => {
                if !document.push(other) {
                    return Typed::Finished;
                }
            }
        }
        Typed::More
    }
}
