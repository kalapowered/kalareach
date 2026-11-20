//! Reading a recovery kit at the command line.
//!
//! A recovery kit holds the seed that opens every backup, so how it gets into this process is the
//! command's most careful step. It is never an argument, where a process listing and a shell's
//! history would keep it. It comes from one of three places:
//!
//! * a file the person names ([`KitSource::File`]), which has to be a regular file;
//! * standard input when it is not a terminal, such as a pipe;
//! * standard input when it is a terminal (Unix only): one pasted document, with nothing shown,
//!   that ends at the first blank line after its first line, at Ctrl-D, or at the size bound.
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
/// file, and a terminal prompt where none is offered; a terminal failure when the terminal cannot
/// be read or its modes cannot be changed or put back; and the interrupt's failure when it arrives.
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

/// An answer is a word; this is more than any answer needs.
const LONGEST_ANSWER: usize = 4096;

/// Puts `question` on the error stream and reads the person's answer: one line from the terminal on
/// standard input, with echo on, or none at the end of the input.
///
/// What was typed before the question was shown is thrown away, so an answer is to what the person
/// can see.
///
/// On Unix the read is made on a thread of its own and is not waited for when this future is
/// dropped, so Ctrl-C at a question stops the run at once, however the descriptor behaves: some
/// terminal devices cannot be waited on with a timeout, and a blocking read is not ended by a signal
/// that restarts it. The thread holds nothing but a duplicate of the descriptor and the answer so
/// far, and ends with the process. A caller therefore drops the future only to end the run: the
/// thread is still reading, and would take the next line a later question asked for.
///
/// On Windows the read is made on a thread of its own too, and dropping the future ends that
/// thread before it returns: a read of the console is cancelled, again and again for two seconds,
/// so that the caller may then put the console's modes back without a read still under way. A read
/// that the console does not give up in that time ends the command at once with a said reason,
/// since the console's modes cannot be changed under it.
///
/// # Errors
///
/// Returns a terminal failure when the answer cannot be read, and the interrupt's own failure when
/// the person's Ctrl-C ended the read.
#[cfg(unix)]
pub async fn ask_line(question: &Shown) -> Result<Option<String>> {
    discard_typed_ahead();
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

/// See the Unix form's documentation, which says what both do.
///
/// # Errors
///
/// Returns a terminal failure when the answer cannot be read, and the interrupt's own failure when
/// the person's Ctrl-C ended the read.
#[cfg(windows)]
pub async fn ask_line(question: &Shown) -> Result<Option<String>> {
    if let Ok(console) = crate::platform::ControllingTerminal::open() {
        // What was typed before the question was shown is not its answer. A console that refuses
        // is not a reason to stop: the dialogue's own guard says so when it puts the console back.
        let _ = console.discard_input();
    }
    crate::report::say(question);
    let (answer, arrives) = tokio::sync::oneshot::channel();
    let stopped = Arc::new(AtomicBool::new(false));
    let told = Arc::clone(&stopped);
    let thread = std::thread::Builder::new()
        .name("answer".to_owned())
        .spawn(move || {
            let _ = answer.send(read_console_line(&told));
        })
        .map_err(|error| {
            CliError::Terminal(shown!(
                "your answer could not be read: {}",
                Shown::io(&error)
            ))
        })?;
    let mut reader = ReaderGuard {
        thread: Some(thread),
        stopped,
    };
    let answer = arrives
        .await
        .map_err(|_| CliError::Terminal(Shown::said("your answer could not be read")))?;
    // The thread has sent its answer and ends at once.
    reader.finish();
    answer
}

/// How long a stopped reader is given to leave a read of the console.
#[cfg(windows)]
const READER_DEADLINE: std::time::Duration = std::time::Duration::from_secs(2);

/// How often the reader's read is asked again to end.
#[cfg(any(windows, test))]
const CANCEL_EVERY: std::time::Duration = std::time::Duration::from_millis(50);

/// What the system says of a read that was cancelled, or that a Ctrl-C ended.
#[cfg(any(windows, test))]
const OPERATION_ABORTED: i32 = 995;

/// Reads one line through `step`, which fills what it is given and says how much it filled, or
/// says that the input ended with none. The line is read to its end and at most [`LONGEST_ANSWER`]
/// bytes of it are kept, so nothing of it stays on what `step` reads from. A line end of CR LF
/// is one line end. `stopped` is looked at before each read.
///
/// A read that fails as cancelled while `stopped` is set is a reader that was told to stop, and
/// ends with no answer, which nobody waits for; the same failure with `stopped` clear is what a
/// processed Ctrl-C does to a read of the console, and is the interrupt.
#[cfg(any(windows, test))]
fn read_line_through(
    mut step: impl FnMut(&mut [u8]) -> std::io::Result<usize>,
    stopped: &AtomicBool,
) -> Result<Option<String>> {
    let mut answer: Vec<u8> = Vec::new();
    let mut taken_any = false;
    let mut chunk = [0_u8; 256];
    loop {
        if stopped.load(Ordering::SeqCst) {
            return Ok(None);
        }
        match step(&mut chunk) {
            Ok(0) => break,
            Ok(taken) => {
                taken_any = true;
                let line_end = chunk[..taken].iter().position(|byte| *byte == b'\n');
                let room = LONGEST_ANSWER.saturating_sub(answer.len());
                let kept = line_end.unwrap_or(taken).min(room);
                answer.extend_from_slice(&chunk[..kept]);
                if line_end.is_some() {
                    break;
                }
            }
            Err(_) if stopped.load(Ordering::SeqCst) => return Ok(None),
            Err(error) if error.raw_os_error() == Some(OPERATION_ABORTED) => {
                return Err(interrupt::stopped());
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
                ) => {}
            Err(error) => return Err(answer_unreadable(&error)),
        }
    }
    if !taken_any {
        return Ok(None);
    }
    if answer.last() == Some(&b'\r') {
        answer.pop();
    }
    // Text that is not UTF-8 is not yes: a decline, said as one.
    Ok(Some(String::from_utf8_lossy(&answer).into_owned()))
}

/// Reads one line from the console's input.
#[cfg(windows)]
fn read_console_line(stopped: &AtomicBool) -> Result<Option<String>> {
    use std::io::Read as _;

    let mut input = File::options()
        .read(true)
        .open("CONIN$")
        .map_err(|error| answer_unreadable(&error))?;
    read_line_through(|chunk| input.read(chunk), stopped)
}

/// The thread that reads an answer, held so that it is ended before anything changes the console
/// under it.
#[cfg(windows)]
struct ReaderGuard {
    thread: Option<std::thread::JoinHandle<()>>,
    stopped: Arc<AtomicBool>,
}

#[cfg(windows)]
impl ReaderGuard {
    /// Joins a thread that has sent its answer, which it does as it ends.
    fn finish(&mut self) {
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Tells the reader to stop and waits for it to end, asking its read to end again and again, for
/// at most `wait`. It says whether the thread ended.
#[cfg(any(windows, test))]
fn end_the_reader(
    thread: std::thread::JoinHandle<()>,
    stopped: &AtomicBool,
    cancel: &dyn Fn(&std::thread::JoinHandle<()>) -> bool,
    wait: std::time::Duration,
) -> bool {
    stopped.store(true, Ordering::SeqCst);
    let waited = crate::platform::wait_for_a_blocked_reader(
        thread,
        crate::platform::Schedule {
            wait,
            cancel_after: std::time::Duration::ZERO,
            pause: CANCEL_EVERY,
        },
        cancel,
    );
    !waited.still_running
}

#[cfg(windows)]
impl Drop for ReaderGuard {
    fn drop(&mut self) {
        let Some(thread) = self.thread.take() else {
            return;
        };
        let ended = end_the_reader(
            thread,
            &self.stopped,
            &crate::platform::cancel_blocked_read,
            READER_DEADLINE,
        );
        if !ended {
            // The console's modes cannot be put back under a read that is still under way, and
            // the input cannot be thrown away. The command ends here and says so.
            crate::report::say(&Shown::said(
                "the console did not release a read, so the command ends now without putting the \
                 console back",
            ));
            std::process::exit(i32::from(CliError::NotATerminal.exit_code()));
        }
    }
}

/// Throws away what is waiting on a terminal's standard input. It is done before a question is
/// shown, so a line typed before the person could read the question cannot answer it. Standard
/// input that is not a terminal is left alone.
#[cfg(unix)]
fn discard_typed_ahead() {
    use std::os::fd::AsFd as _;

    let input = std::io::stdin();
    if rustix::termios::isatty(input.as_fd()) {
        let _ = rustix::termios::tcflush(input.as_fd(), rustix::termios::QueueSelector::IFlush);
    }
}

#[cfg(unix)]
fn read_answer() -> Result<Option<String>> {
    use rustix::event::{PollFd, PollFlags, poll};
    use std::os::fd::AsFd as _;

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
        // What was typed before this prompt was shown was echoed, and is not part of the kit. The
        // call waits for output to drain, so a signal can end it early; it is asked again.
        loop {
            match rustix::termios::tcsetattr(terminal, OptionalActions::Flush, &silent) {
                Ok(()) => break,
                Err(rustix::io::Errno::INTR) => {}
                Err(error) => return Err(failed(error)),
            }
        }
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

#[cfg(test)]
mod answer_tests {
    //! The reading of one answer and the ending of its reader, through the steps a case gives in
    //! place of the console's read. The real read is `File::read` on `CONIN$`.

    use std::io;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Condvar, Mutex};
    use std::time::{Duration, Instant};

    use kr_client::shown::Said as _;

    use super::{LONGEST_ANSWER, OPERATION_ABORTED, end_the_reader, read_line_through};

    /// A step that gives `bytes` in reads of at most the size the caller offers, then the end of
    /// the input, and counts what it gave.
    fn giving(
        bytes: Vec<u8>,
        given: Arc<AtomicUsize>,
    ) -> impl FnMut(&mut [u8]) -> io::Result<usize> {
        let mut at = 0;
        move |chunk: &mut [u8]| {
            let size = chunk.len().min(bytes.len() - at);
            chunk[..size].copy_from_slice(&bytes[at..at + size]);
            at += size;
            given.fetch_add(size, Ordering::SeqCst);
            Ok(size)
        }
    }

    fn read(bytes: &[u8]) -> (Option<String>, usize) {
        let given = Arc::new(AtomicUsize::new(0));
        let answer = read_line_through(
            giving(bytes.to_vec(), Arc::clone(&given)),
            &AtomicBool::new(false),
        )
        .expect("the line reads");
        (answer, given.load(Ordering::SeqCst))
    }

    /// The Enter key of a console gives CR LF: it is one line end, and the answer has neither.
    #[test]
    fn a_line_that_ends_in_cr_lf_is_the_line_without_its_end() {
        assert_eq!(read(b"yes\r\n"), (Some("yes".to_owned()), 5));
        assert_eq!(read(b"yes\n"), (Some("yes".to_owned()), 4));
        assert_eq!(
            read(b"\r\n"),
            (Some(String::new()), 2),
            "a blank line is an answer"
        );
        assert_eq!(read(b""), (None, 0), "the end of the input is none");
    }

    /// A line over the bound keeps the bound and is read to its end, so that none of it stays on
    /// the handle for the next question.
    #[test]
    fn a_line_over_the_bound_keeps_the_bound_and_leaves_nothing_on_the_handle() {
        let mut typed = vec![b'a'; 10_000];
        typed.extend_from_slice(b"\r\n");
        let (answer, given) = read(&typed);
        assert_eq!(answer.expect("an answer").len(), LONGEST_ANSWER);
        assert_eq!(given, typed.len(), "every byte of the line was taken");
    }

    /// A read that fails as cancelled, with no stop asked for, is the person's Ctrl-C, and is said as
    /// the interrupt; with the stop set it is the reader being told to go, and says nothing.
    #[test]
    fn a_cancelled_read_is_the_interrupt_unless_the_reader_was_told_to_stop() {
        let cancelled = |_: &mut [u8]| Err(io::Error::from_raw_os_error(OPERATION_ABORTED));
        let error =
            read_line_through(cancelled, &AtomicBool::new(false)).expect_err("the interrupt");
        assert_eq!(error.said().as_str(), "stopped before it finished");

        let stop = AtomicBool::new(false);
        let told = |_: &mut [u8]| {
            stop.store(true, Ordering::SeqCst);
            Err(io::Error::from_raw_os_error(OPERATION_ABORTED))
        };
        assert_eq!(read_line_through(told, &stop).expect("no failure"), None);
    }

    /// The console, as the cases model it: a read waits until a cancel arrives while it waits, and a
    /// cancel that arrives when no read waits is missed, as the system's is.
    struct Console {
        state: Mutex<(bool, bool)>,
        changed: Condvar,
    }

    impl Console {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                state: Mutex::new((false, false)),
                changed: Condvar::new(),
            })
        }

        /// A read that waits for a cancel and then fails as cancelled.
        fn read(&self) -> io::Result<usize> {
            let mut state = self.state.lock().expect("the console");
            state.0 = true;
            while !state.1 {
                state = self.changed.wait(state).expect("the console");
            }
            state.0 = false;
            state.1 = false;
            Err(io::Error::from_raw_os_error(OPERATION_ABORTED))
        }

        /// The cancel: whether a read was waiting.
        fn cancel(&self) -> bool {
            let mut state = self.state.lock().expect("the console");
            if state.0 {
                state.1 = true;
                self.changed.notify_all();
                true
            } else {
                false
            }
        }
    }

    fn reader(
        console: &Arc<Console>,
        stopped: &Arc<AtomicBool>,
        before: Duration,
    ) -> std::thread::JoinHandle<()> {
        let (console, stopped) = (Arc::clone(console), Arc::clone(stopped));
        std::thread::spawn(move || {
            std::thread::sleep(before);
            let _ = read_line_through(|_| console.read(), &stopped);
        })
    }

    /// A reader blocked in a read is ended by the cancel, which is asked until it takes.
    #[test]
    fn a_reader_in_a_read_is_ended_by_the_cancel() {
        let console = Console::new();
        let stopped = Arc::new(AtomicBool::new(false));
        let thread = reader(&console, &stopped, Duration::ZERO);
        // The read is under way before the stop.
        while !console.state.lock().expect("the console").0 {
            std::thread::sleep(Duration::from_millis(1));
        }
        let ended = end_the_reader(
            thread,
            &stopped,
            &|_| console.cancel(),
            Duration::from_secs(2),
        );
        assert!(ended, "the reader ended");
    }

    /// A reader that has not started its read when the stop comes sees the stop at its first look
    /// and never reads.
    #[test]
    fn a_reader_that_has_not_started_its_read_never_reads() {
        let console = Console::new();
        let stopped = Arc::new(AtomicBool::new(false));
        let reads = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&reads);
        let (told, waited) = (Arc::clone(&stopped), Arc::clone(&console));
        let thread = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            let _ = read_line_through(
                |_| {
                    counted.fetch_add(1, Ordering::SeqCst);
                    waited.read()
                },
                &told,
            );
        });
        let ended = end_the_reader(
            thread,
            &stopped,
            &|_| console.cancel(),
            Duration::from_secs(2),
        );
        assert!(ended);
        assert_eq!(reads.load(Ordering::SeqCst), 0, "no read was started");
    }

    /// A cancel that comes after the stop was looked at and before the read is in force is missed;
    /// the next one, 50 ms later, takes, and the reader ends within the deadline.
    #[test]
    fn a_cancel_that_misses_a_reader_between_its_look_and_its_read_is_asked_again() {
        let console = Console::new();
        let stopped = Arc::new(AtomicBool::new(false));
        let entered = Arc::new(AtomicBool::new(false));
        let (told, gate, here) = (
            Arc::clone(&stopped),
            Arc::clone(&console),
            Arc::clone(&entered),
        );
        let thread = std::thread::spawn(move || {
            let _ = read_line_through(
                |_| {
                    // Past the look at the stop, before the read: the cancel finds nothing.
                    here.store(true, Ordering::SeqCst);
                    std::thread::sleep(Duration::from_millis(180));
                    gate.read()
                },
                &told,
            );
        });
        while !entered.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(1));
        }
        let asked = AtomicUsize::new(0);
        let started = Instant::now();
        let ended = end_the_reader(
            thread,
            &stopped,
            &|_| {
                asked.fetch_add(1, Ordering::SeqCst);
                console.cancel()
            },
            Duration::from_secs(2),
        );
        assert!(ended, "the reader ended");
        assert!(
            asked.load(Ordering::SeqCst) >= 2,
            "the first cancel missed and was asked again"
        );
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    /// A read that never gives way is left when the deadline is over, and the answer says the
    /// reader did not end: the caller restores nothing and discards nothing then.
    #[test]
    fn a_read_that_never_gives_way_is_left_at_the_deadline() {
        let console = Console::new();
        let stopped = Arc::new(AtomicBool::new(false));
        let thread = reader(&console, &stopped, Duration::ZERO);
        // The read is under way before the stop.
        while !console.state.lock().expect("the console").0 {
            std::thread::sleep(Duration::from_millis(1));
        }
        let ended = end_the_reader(thread, &stopped, &|_| false, Duration::from_millis(300));
        assert!(!ended, "the reader was still in its read");
        // Let the thread go, so that the case leaves nothing behind.
        while !console.cancel() {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}
