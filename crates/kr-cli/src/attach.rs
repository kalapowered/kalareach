//! Attaching a terminal to a session.
//!
//! Direct mode is deliberately dumb: the outer terminal goes into raw mode and its bytes are
//! forwarded in order, unchanged. Nothing is decoded into text and re-encoded, nothing is
//! normalised, no line endings are rewritten and no status bar is installed. When an application
//! turns mouse reporting on, the outer terminal produces those events and they are forwarded; when
//! it turns it off, the terminal's own scrollback behaves normally again.
//!
//! Before any of that the restoration guard is armed, because the terminal must come back even if
//! this process is killed outright. See [`crate::terminal`].

use kr_client::shown;
use kr_client::shown::Shown;
use std::io::Read as _;
use std::process::{Command, Stdio};

use crate::bridge::link::Link;
use kr_protocol::attachment::{
    AttachMode, AttachmentCapability, SessionAttachParams, SessionAttachResult, SessionDetachParams,
};
use kr_protocol::envelope::ActionTarget;
use kr_protocol::error::ErrorCode;
use kr_protocol::hello::{PACKAGE_VERSION, PackageVersion};
use kr_protocol::ids::{ActionId, AttachmentId, SessionEpoch, SessionId};
use kr_protocol::input::{InputAcquireParams, InputAcquireResult};
use kr_protocol::local::LocalBuild;
use kr_protocol::method::Method;
use kr_protocol::recovery::{EventStream, EventsSubscribeParams};
use kr_protocol::scalars::{CanonicalSet, Nullable};
use kr_protocol::session::{Dimensions, DisplayNumber};
use kr_protocol::worker::WorkerDescriptor;

use crate::error::{CliError, Result};
use crate::terminal::{ControllingTerminal, KeyboardState, SavedModes};

/// The byte that tells the guard the terminal has already been restored.
pub const GUARD_RELEASE: u8 = b'R';

/// The byte that introduces the keyboard state the guard is to restore, followed by a line.
///
/// It reaches the guard after it is already armed, because the state can only be read by changing
/// the terminal, and nothing may change the terminal before something is holding what it had.
pub const GUARD_KEYBOARD: u8 = b'K';

/// The byte that introduces the mouse, cursor and paste modes the guard is to restore.
///
/// It arrives with the keyboard state and for the same reason: the values are read by asking the
/// terminal, which is itself a change to it, so nothing can be handed over before the guard is
/// armed. A guard that never hears them puts each mode into its documented default, which is what a
/// terminal that answered nothing is owed.
pub const GUARD_MODES: u8 = b'M';

/// The byte that tells the guard this attachment is about to begin forwarding.
///
/// From that moment the session can change the terminal's keyboard protocols, so the guard owes
/// them back however this attachment ends. It is told before the first byte is forwarded, because a
/// guard that learned it afterwards would have a window in which the terminal was changed and
/// nothing was going to put it back.
pub const GUARD_BEGIN: u8 = b'B';

/// The byte a guard sends once it is holding the terminal's state, and again once it has been told
/// that forwarding is beginning.
pub const GUARD_READY: u8 = b'A';

/// How long the attach process waits for its guard to report that it is armed.
///
/// A guard that is no longer there needs no deadline: its end of the report pipe closes with it, so
/// the read ends at once and the status says how it went. This bounds the other case, a guard that
/// is running and has not answered, and it is set above what starting one actually costs rather
/// than above what the guard does after it has started.
///
/// What it costs, measured. From starting a guard to its byte arriving: 3 to 5 milliseconds for one
/// that has been run before, once reaching 3.1 seconds in forty rounds on a loaded machine, and
/// 0.34 to 3.3 seconds for the **first** run of a newly written copy. Measured again with the spawn
/// separated from the wait, which is the part this bounds: the spawn takes 1 to 5 milliseconds and
/// a first run's wait takes 0.15 to 1.7 seconds, so what a first run costs is spent waiting rather
/// than starting. The likeliest reading of a first run costing more at all is the operating system
/// checking a binary it has not seen before, once, and remembering it afterwards, which would make
/// it every first attach after an install or an upgrade; what is measured is the cost, not the
/// reason for it.
///
/// Two seconds sat inside those readings. The bound is a minute: clear of every one of them by more
/// than an order of magnitude, and still a bound, because a guard that is alive and silent for a
/// minute is not going to answer.
pub const GUARD_ARM_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// How long a report about a guard whose report pipe has closed tries to collect its exit status.
///
/// The pipe closes with the guard's descriptors, a little before the guard can be waited for: the
/// operating system releases the rest of the process in between. That is usually microseconds, and
/// on a loaded machine it can be milliseconds. The bound is for a guard with no status to give, one
/// that closed its end and went on running or that the system is slow to finish; the report then
/// says there was none.
const GUARD_DEPARTURE_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

/// The out-of-process restoration guard.
///
/// It holds the saved terminal state and a handle on the terminal, in a process this one does not
/// control. If this process dies the pipe closes and the guard restores; if this process finishes
/// properly it restores first and releases the guard.
#[derive(Debug)]
pub struct RestorationGuard {
    child: std::process::Child,
    release: Option<std::io::PipeWriter>,
    /// The pipe the guard confirms on: once when it is armed, and once for each thing it is asked
    /// to do to the terminal on this attachment's behalf.
    confirmations: Option<std::io::PipeReader>,
}

impl RestorationGuard {
    /// Arms a guard for this terminal.
    ///
    /// The guard is started before the terminal is touched and **confirms** that it is holding the
    /// state before this call returns. Returning before that confirmation would leave a window in
    /// which the terminal was raw and nothing could put it back.
    ///
    /// # Errors
    ///
    /// Returns an error when the guard cannot be started or does not confirm.
    pub fn arm(
        program: &std::path::Path,
        terminal: &ControllingTerminal,
        saved: &SavedModes,
    ) -> Result<Self> {
        // The guard writes to the terminal through its standard output, so it is given the
        // terminal's output handle; on Windows the input handle takes no written bytes.
        let handle = terminal.output().try_clone().map_err(|error| {
            CliError::Terminal(shown!("duplicate the terminal: {}", Shown::io(&error)))
        })?;
        Self::arm_on_handle(program, handle, saved)
    }

    /// Arms a guard on an open terminal: starts it, waits for its readiness, and stops it when
    /// there is none.
    ///
    /// All of arming is here rather than in [`RestorationGuard::arm`], which only opens the
    /// terminal, because the order matters in a way a test has to be able to reach:
    /// [`RestorationGuard::start`] must have returned, releasing this process's copy of the report
    /// pipe's write end, before anything waits on that pipe.
    fn arm_on_handle(
        program: &std::path::Path,
        terminal: std::fs::File,
        saved: &SavedModes,
    ) -> Result<Self> {
        let mut guard = Self::start(program, terminal, saved)?;
        // The readiness byte. A guard that never sends it is stopped rather than trusted, because
        // the whole point of it is to be holding the state before the terminal changes.
        if let Err(silence) = guard.confirmed() {
            let _ = guard.child.kill();
            let _ = guard.child.wait();
            return Err(CliError::Terminal(shown!(
                "the restoration guard did not report that it was holding the terminal: {}",
                silence
            )));
        }
        Ok(guard)
    }

    /// Starts a guard on a terminal and keeps the ends of its pipes this process needs.
    ///
    /// The `Command` is dropped as soon as the guard is running, and that is load-bearing rather
    /// than tidiness: it is holding this process's copy of the write end of the report pipe, and
    /// while it holds it a guard that has died leaves a pipe that never reaches its end. The read
    /// would then wait out the whole deadline and report a guard that was still running, of a guard
    /// that had already gone.
    fn start(
        program: &std::path::Path,
        terminal: std::fs::File,
        saved: &SavedModes,
    ) -> Result<Self> {
        let (reader, writer) = std::io::pipe().map_err(|error| {
            CliError::Terminal(shown!("create the guard's pipe: {}", Shown::io(&error)))
        })?;
        let (ready_reader, ready_writer) = std::io::pipe().map_err(|error| {
            CliError::Terminal(shown!("create the guard's pipe: {}", Shown::io(&error)))
        })?;
        let mut command = detached(program);
        command
            .arg("--modes")
            .arg(saved.encode())
            .stdin(Stdio::from(reader))
            .stdout(Stdio::from(terminal))
            .stderr(Stdio::from(ready_writer));
        let child = command.spawn().map_err(|error| {
            CliError::Terminal(shown!("start the restoration guard: {}", Shown::io(&error)))
        })?;
        drop(command);
        Ok(Self {
            child,
            release: Some(writer),
            confirmations: Some(ready_reader),
        })
    }

    /// Waits for the guard's next confirmation, and says what happened when there is not one.
    ///
    /// The read happens on a thread because a blocking read for a byte that is not coming would
    /// outlast any deadline this could set. A guard that has left needs no deadline at all: its end
    /// of this pipe closes with it, so the read ends at once and the status says how it went.
    ///
    /// The four ways this can fail are four different faults - a guard that could not start, one
    /// that died holding the terminal, one that is answering something else, and one that is merely
    /// slow - and the caller reports whichever it was rather than one sentence for all of them.
    fn confirmed(&mut self) -> std::result::Result<(), Shown> {
        let Some(reader) = self.confirmations.take() else {
            return Err(Shown::said("its side of the report pipe is already closed"));
        };
        let answer = std::thread::spawn(move || {
            let mut byte = [0_u8; 1];
            let mut reader = reader;
            let read = reader.read(&mut byte);
            (reader, read.map(|count| (count, byte[0])))
        });
        let started = std::time::Instant::now();
        let deadline = started + GUARD_ARM_TIMEOUT;
        while !answer.is_finished() {
            // A guard that has died ends this wait without a clock: its end of the pipe closes with
            // it, the read above returns nothing, and the answer below says it ended. What the
            // deadline bounds is the other case, a guard that is running and has not answered.
            if std::time::Instant::now() >= deadline {
                return Err(shown!(
                    "it was still running and had not answered after {} ms",
                    started.elapsed().as_millis()
                ));
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let Ok((reader, read)) = answer.join() else {
            return Err(Shown::said("the thread reading its report failed"));
        };
        self.confirmations = Some(reader);
        match read {
            Ok((1, byte)) if byte == GUARD_READY => Ok(()),
            Ok((1, byte)) => Err(shown!(
                "it answered byte {} rather than its readiness after {} ms",
                byte,
                started.elapsed().as_millis()
            )),
            // No byte means its end of this pipe is closed, which means the process is gone.
            Ok(_) => Err(shown!(
                "it ended without answering after {} ms{}",
                started.elapsed().as_millis(),
                self.departure()
            )),
            Err(error) => Err(shown!(
                "reading its report failed after {} ms: {}",
                started.elapsed().as_millis(),
                Shown::io(&error)
            )),
        }
    }

    /// How the guard went, for a report about a guard that is no longer answering.
    ///
    /// The guard's end of the report pipe closes before its exit status is there to collect, so a
    /// single look can find a guard that has gone and still has no status. This looks until the
    /// status is there, for at most [`GUARD_DEPARTURE_WAIT`], and says so when it never is.
    fn departure(&mut self) -> Shown {
        let deadline = std::time::Instant::now() + GUARD_DEPARTURE_WAIT;
        loop {
            match self.child.try_wait() {
                Ok(Some(status)) => return shown!(" ({})", status),
                Ok(None) if std::time::Instant::now() < deadline => {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                Ok(None) => {
                    return shown!(
                        " (no status to collect after {} ms)",
                        GUARD_DEPARTURE_WAIT.as_millis()
                    );
                }
                Err(error) => {
                    return shown!(" (its status could not be read: {})", Shown::io(&error));
                }
            }
        }
    }

    /// Tells the guard that this attachment is about to begin forwarding.
    ///
    /// It returns once the guard has recorded it, so forwarding begins after something that
    /// outlives this process owes the keyboard protocols back, and not before.
    ///
    /// # Errors
    ///
    /// Returns an error when the guard does not confirm.
    pub fn begin_keyboard(&mut self) -> Result<()> {
        use std::io::Write as _;

        let Some(writer) = self.release.as_mut() else {
            return Err(CliError::Terminal(Shown::said(
                "the restoration guard is no longer listening",
            )));
        };
        if writer.write_all(&[GUARD_BEGIN, b'\n']).is_err() || writer.flush().is_err() {
            return Err(CliError::Terminal(Shown::said(
                "the restoration guard could not be asked to hold the keyboard state",
            )));
        }
        self.confirmed().map_err(|silence| {
            CliError::Terminal(shown!(
                "the restoration guard did not report that it was holding the keyboard state: \
                 {}",
                silence
            ))
        })
    }

    /// Tells the guard what keyboard protocols this terminal had before the attachment began.
    ///
    /// The guard is armed before anything touches the terminal, and reading this state is itself a
    /// change to it, so the answer arrives here rather than as a starting argument. It is what the
    /// guard writes on its way out, as a state rather than as a stack operation. A guard that never
    /// hears it writes nothing of it, which is what a terminal that was never asked gets.
    pub fn learn_keyboard(&mut self, keyboard: &KeyboardState) {
        self.tell(GUARD_KEYBOARD, &keyboard.encode());
    }

    /// Tells the guard which mouse modes, cursor visibility and paste state this terminal had.
    ///
    /// The same moment and the same reason as [`Self::learn_keyboard`]: reading them is a change to
    /// the terminal, so the guard is armed first and told afterwards. What it writes on its way out
    /// is these values over the documented defaults, so a person whose mouse reporting was on when
    /// the attachment arrived has it back even if this process is killed outright.
    pub fn learn_modes(&mut self, modes: &crate::terminal::ScreenModes) {
        self.tell(GUARD_MODES, &modes.encode());
    }

    /// Sends the guard one line of state.
    fn tell(&mut self, kind: u8, state: &str) {
        use std::io::Write as _;

        if let Some(writer) = self.release.as_mut() {
            let mut line = vec![kind];
            line.extend_from_slice(state.as_bytes());
            line.push(b'\n');
            let _ = writer.write_all(&line);
            let _ = writer.flush();
        }
    }

    /// Releases the guard after the caller has restored the terminal's modes itself.
    ///
    /// The keyboard protocols are still the guard's to write back, so it does that on its way out.
    /// This waits for it to finish, which is what keeps the two halves of the restoration in
    /// order.
    pub fn release(mut self) {
        use std::io::Write as _;

        if let Some(mut writer) = self.release.take() {
            let _ = writer.write_all(&[GUARD_RELEASE]);
            let _ = writer.flush();
        }
        let _ = self.child.wait();
    }

    /// Hands the terminal back to the guard, which restores every part of it.
    ///
    /// For the caller whose own restoration failed, or never happened. Releasing tells the guard
    /// the modes are already back and only the keyboard is owed; this says nothing of the kind, so
    /// the guard puts back the modes, the screen modes and the keyboard, and this waits for it.
    pub fn hand_back(mut self) {
        // Closing the pipe is what the guard reads as the attach process being gone, which is the
        // case it exists for.
        self.release = None;
        let _ = self.child.wait();
    }
}

#[cfg(unix)]
fn detached(program: &std::path::Path) -> Command {
    use std::os::unix::process::CommandExt as _;

    // The guard gets its own process group, so a signal aimed at this command's group — the one a
    // shell sends on Ctrl-C, or on the pipeline's exit — does not reach it. It keeps the
    // controlling terminal, because restoring that terminal is its whole purpose; it ignores the
    // background-write signal rather than being stopped by it.
    let mut command = Command::new(program);
    command.process_group(0);
    command
}

#[cfg(not(unix))]
fn detached(program: &std::path::Path) -> Command {
    Command::new(program)
}

/// A terminal attached to a session.
pub struct Attachment {
    /// The attachment the worker allocated.
    pub attachment_id: AttachmentId,
    /// The input lease, once it has been taken.
    pub lease: Option<InputAcquireResult>,
    /// What the worker said about the attachment.
    pub result: SessionAttachResult,
}

/// Attaches a terminal to a session and takes its input lease.
///
/// Implicit acquisition is available here because this is the local operating-system path: the
/// worker authenticated the caller by peer credentials. A network client cannot assert that.
///
/// # Errors
///
/// Returns the host's refusal, or a transport failure.
pub async fn attach(
    client: &mut impl Link,
    attaching: &Attaching,
    dimensions: Dimensions,
    claim_geometry: bool,
    probe: bool,
) -> Result<Attachment> {
    let mut requested = CanonicalSet::new();
    requested.insert(AttachmentCapability::ObserveTerminal);
    requested.insert(AttachmentCapability::Input);
    if claim_geometry {
        requested.insert(AttachmentCapability::Geometry);
    }
    let params = SessionAttachParams {
        session_id: attaching.session_id,
        mode: AttachMode::Terminal,
        claim_geometry,
        dimensions: Nullable::some(dimensions),
        // The terminal's own declaration of what it is. `--no-probe` withholds it, and the session
        // uses the conservative profile instead of one this terminal has not been asked to
        // confirm.
        terminal_profile_id: Nullable(probe.then(|| std::env::var("TERM").ok()).flatten()),
        requested,
    };
    let result: SessionAttachResult =
        call(client, Method::SessionAttach, attaching.target(), &params).await?;
    let attachment_id = result.attachment.attachment_id;
    // Implicit acquisition, because this is the local operating-system path: the worker
    // authenticated the caller by peer credentials. A network client cannot assert that, and the
    // lease is taken here so the first keystroke does not have to wait for a second exchange.
    //
    // A host that will not let this terminal type is not a failed attach. Section 8 has the host
    // check that a controller can supply the encoding the application reads, and a terminal nobody
    // was allowed to ask about cannot be shown to: the attachment stands, it watches, and the
    // caller is told which of the two it got.
    let lease = match call::<_, InputAcquireResult>(
        client,
        Method::InputAcquire,
        attaching.target(),
        &InputAcquireParams {
            session_id: attaching.session_id,
            attachment_id,
            expected_epoch: Nullable::null(),
        },
    )
    .await
    {
        Ok(lease) => Some(lease),
        Err(CliError::Refused(error))
            if error.code == kr_protocol::error::ErrorCode::InputIncompatible =>
        {
            None
        }
        Err(error) => return Err(error),
    };
    Ok(Attachment {
        attachment_id,
        lease,
        result,
    })
}

/// Refuses a worker whose screens this build cannot be sure to read, before the session is asked
/// for anything.
///
/// A worker outlives an upgrade, so this command can meet a worker of an earlier build, or of a
/// later one. It reads a worker's screens when the worker states, in its answer to the hello, a
/// build whose protocol version shares this build's compatibility level
/// ([`PackageVersion::shares_frames_with`]). A worker that states no build is of a build before
/// that statement. Attaching to either of the others would claim the session's size and its input
/// lease, and then wait on screens this command cannot draw.
///
/// # Errors
///
/// Returns `UNSUPPORTED_SCHEMA`, a refused request, naming both builds, both protocol versions and
/// what to do.
pub fn check_build(stated: Option<&LocalBuild>, display: DisplayNumber) -> Result<()> {
    let worker = match stated {
        Some(build) if build.protocol_version.shares_frames_with(PACKAGE_VERSION) => {
            return Ok(());
        }
        Some(build) => shown!(
            "session {} runs on {} with protocol {}",
            display.get(),
            crate::shown::build_name(&build.build_id),
            version(build.protocol_version)
        ),
        None => shown!(
            "session {} runs on a worker of an earlier build, which does not state its build or \
             its protocol version",
            display.get()
        ),
    };
    Err(CliError::Refused(kr_client::error::refusal(
        ErrorCode::UnsupportedSchema,
        shown!(
            "{}, and this is {} with protocol {}: this kr cannot show a session whose worker \
             speaks another protocol version. Close the session with `kr close {}`, or attach \
             with a kr of the worker's build",
            worker,
            crate::shown::build_name(&crate::build_id()),
            version(PACKAGE_VERSION),
            display.get()
        ),
    )))
}

/// A protocol package version, as a refusal says it.
fn version(version: PackageVersion) -> Shown {
    shown!("{}.{}.{}", version.major, version.minor, version.patch)
}

/// Takes the session's size ownership for this attachment.
///
/// # Errors
///
/// Returns the host's refusal, or a transport failure.
pub async fn take_geometry(
    client: &mut impl Link,
    attaching: &Attaching,
    attachment_id: AttachmentId,
    expected_epoch: kr_protocol::ids::GeometryEpoch,
) -> Result<kr_protocol::attachment::GeometryResult> {
    call(
        client,
        Method::TerminalGeometryTransfer,
        attaching.target(),
        &kr_protocol::attachment::TerminalGeometryTransferParams {
            attachment_id,
            expected_geometry_epoch: expected_epoch,
        },
    )
    .await
}

/// Reports this terminal's new size to the session.
///
/// # Errors
///
/// Returns the host's refusal, or a transport failure.
pub async fn resize(
    client: &mut impl Link,
    attaching: &Attaching,
    params: &kr_protocol::attachment::TerminalResizeParams,
) -> Result<kr_protocol::attachment::GeometryResult> {
    call(client, Method::TerminalResize, attaching.target(), params).await
}

/// Returns the guard executable of this command's own release, which sits beside this one.
///
/// The guard reads the terminal state this command writes, so it has to be of the same release,
/// never the one an update has made current since this command started.
#[must_use]
pub fn guard_program() -> std::path::PathBuf {
    kr_ipc::install::this_process().map_or_else(
        |_| std::path::PathBuf::from("kr-attach-guard"),
        |running| running.own(kr_ipc::install::Program::AttachGuard),
    )
}

/// The variable the integration exports for the command it is about to run.
///
/// One accepted line, one value, set by the shell's own bridge script for that command and for
/// nothing else. It is how `kr detach` with no attachment named says which line it belongs to.
pub const DETACH_TOKEN_VARIABLE: &str = "KR_DETACH_TOKEN";

/// Detaches an attachment of a session.
///
/// `None` presents the capability the line this process runs from was given, which is what
/// `kr detach` inside a root shell means. The host answers from that capability alone, or refuses
/// with `AMBIGUOUS_ATTACHMENT`; this command never picks an attachment itself.
///
/// # Errors
///
/// Returns the host's refusal, or a transport failure.
pub async fn detach_attachment(
    client: &mut impl Link,
    descriptor: &WorkerDescriptor,
    attachment_id: Option<AttachmentId>,
) -> Result<kr_protocol::attachment::SessionDetachResult> {
    call(
        client,
        Method::SessionDetach,
        target(descriptor),
        &SessionDetachParams {
            attachment_id: Nullable(attachment_id),
            // The capability the line this process runs from was given, where there is one. It is
            // what a request that names no attachment is answered from.
            line_token: Nullable(
                attachment_id
                    .is_none()
                    .then(|| std::env::var(DETACH_TOKEN_VARIABLE).ok())
                    .flatten()
                    .filter(|token| !token.is_empty()),
            ),
        },
    )
    .await
}

/// Subscribes an attachment to the session's output.
///
/// # Errors
///
/// Returns the host's refusal, or a transport failure.
pub async fn subscribe(
    client: &mut impl Link,
    session_id: SessionId,
    attachment_id: AttachmentId,
    from_cursor: Option<u64>,
) -> Result<()> {
    let mut streams = CanonicalSet::new();
    streams.insert(EventStream::Output);
    streams.insert(EventStream::SessionState);
    let params = EventsSubscribeParams {
        session_id,
        attachment_id,
        streams,
        from_cursor: Nullable(from_cursor.map(kr_protocol::scalars::U64::new)),
    };
    let outcome = client.request(Method::EventsSubscribe, &params).await?;
    outcome.map(|_| ()).map_err(CliError::Refused)
}

/// What makes a console that reports its keys as records spell them itself.
///
/// The records of a console go to the session as they are, and the session spells them as its
/// terminal asked for. A session whose application has negotiated a keyboard encoding that its
/// spelling of records cannot express refuses them, and the attachment then turns to this: the
/// console's own virtual-terminal input, which spells the keys as a terminal would and which the
/// reader hands on as bytes from then on. The command spells nothing in either case.
///
/// The reader makes the change itself, between two of its reads. Every record it read before is
/// already on its way as the record it is, none is read or turned into bytes after, and the bytes
/// are read only once the console has been asked.
pub struct InputSwitch {
    /// Asks the console to spell its keys.
    ask: std::sync::Arc<dyn Fn() -> Result<()> + Send + Sync>,
    /// The reader, once one that can make the change is running.
    #[cfg(any(not(unix), test))]
    reader: std::sync::Mutex<Option<ReaderLine>>,
}

impl InputSwitch {
    /// A switch that asks the console with `ask`.
    #[must_use]
    pub fn new(ask: impl Fn() -> Result<()> + Send + Sync + 'static) -> Self {
        Self {
            ask: std::sync::Arc::new(ask),
            #[cfg(any(not(unix), test))]
            reader: std::sync::Mutex::new(None),
        }
    }

    /// Asks the console to spell its keys, and from then on the reader hands on bytes.
    ///
    /// # Errors
    ///
    /// Returns why the console would not, and the reader goes on handing on records, or that the
    /// reader did not answer.
    pub fn engage(&self) -> Result<()> {
        #[cfg(any(not(unix), test))]
        if let Some(line) = self
            .reader
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
        {
            return line.ask_the_reader();
        }
        (self.ask)()
    }
}

/// How long a switch waits for the reader to make it. The reader answers between two of its reads,
/// so a wait that long means the reader is gone.
#[cfg(all(not(unix), not(test)))]
const READER_ANSWER_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

/// The same, short enough for a case to wait out.
#[cfg(test)]
const READER_ANSWER_WAIT: std::time::Duration = std::time::Duration::from_millis(300);

/// How many reads in a row the reader makes of a console that has input before it hears a request
/// that has been waiting, so that a console that never stops having input cannot keep one from
/// being heard.
#[cfg(any(not(unix), test))]
const READS_BEFORE_A_REQUEST: u32 = 4;

/// Where a request of the switch is, shared by the switch and the reader.
#[cfg(any(not(unix), test))]
mod request {
    /// Nothing is asked.
    pub const IDLE: u8 = 0;
    /// The switch has asked and the reader has not begun.
    pub const PENDING: u8 = 1;
    /// The reader has begun, and answers.
    pub const TAKEN: u8 = 2;
    /// The switch gave up before the reader began, so the reader does not make the request.
    pub const WITHDRAWN: u8 = 3;
}

/// The switch's end of its conversation with the reader.
#[cfg(any(not(unix), test))]
struct ReaderLine {
    /// Wakes the reader out of its wait for the console, so that it hears the request.
    wake: Box<dyn Fn() + Send + Sync>,
    /// What the reader answers with once it has asked the console.
    answers: std::sync::mpsc::Receiver<Result<()>>,
    /// Where the request is.
    state: std::sync::Arc<std::sync::atomic::AtomicU8>,
}

#[cfg(any(not(unix), test))]
impl ReaderLine {
    /// Has the reader ask the console, and returns what the console said.
    ///
    /// A request the reader has not begun on when the wait ends is withdrawn, so that it does not
    /// take effect after the attachment has been told it failed. One the reader is part way through
    /// is waited for: the console's answer is a call that returns.
    fn ask_the_reader(&self) -> Result<()> {
        use std::sync::atomic::Ordering::SeqCst;

        let gone =
            || CliError::Terminal(shown!("the reader of the console's input did not answer"));
        self.state.store(request::PENDING, SeqCst);
        (self.wake)();
        match self.answers.recv_timeout(READER_ANSWER_WAIT) {
            Ok(answer) => answer,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                if self
                    .state
                    .compare_exchange(request::PENDING, request::WITHDRAWN, SeqCst, SeqCst)
                    .is_ok()
                {
                    Err(gone())
                } else {
                    self.answers
                        .recv_timeout(READER_ANSWER_WAIT)
                        .unwrap_or_else(|_| Err(gone()))
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => Err(gone()),
        }
    }
}

/// The reader's end of that conversation.
#[cfg(any(not(unix), test))]
struct Switching {
    /// Asks the console to spell its keys.
    ask: std::sync::Arc<dyn Fn() -> Result<()> + Send + Sync>,
    /// Where the console's answer goes.
    answers: std::sync::mpsc::Sender<Result<()>>,
    /// Where the request is.
    state: std::sync::Arc<std::sync::atomic::AtomicU8>,
}

/// What ended a wait of the reader.
#[cfg(any(not(unix), test))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Woken {
    /// The stop was made.
    Stop,
    /// The console has input.
    Console,
    /// The switch asked the reader to ask the console.
    Asked,
}

/// A console, as the thread that reads it needs it.
#[cfg(any(not(unix), test))]
pub(crate) trait ConsoleInput {
    /// Waits until the stop is made, the console has input or the switch asks, and says which. The
    /// stop comes first; input the console holds comes before a request unless `requests_first`
    /// says the request has waited long enough.
    fn wait(&mut self, requests_first: bool) -> Result<Woken>;

    /// Reads the key records the console has, as the runs they came in.
    fn keys(&mut self) -> Result<Vec<Vec<kr_term::win32::KeyRecord>>>;

    /// Hands over the first half of a character that was waiting for its second half, if there is
    /// one, so that it is counted with the records the switch drops.
    fn held(&mut self) -> Vec<kr_term::win32::KeyRecord>;

    /// Reads the text the console has spelled as UTF-8, without waiting for more: nothing when what
    /// the console holds makes no text, which it then takes off.
    fn bytes(&mut self) -> std::io::Result<Vec<u8>>;
}

/// Starts the thread that reads `console`, and links it to `switch`.
///
/// `wake` ends the reader's wait so that it hears a request of the switch.
#[cfg(any(not(unix), test))]
fn start_reader<C: ConsoleInput + Send + 'static>(
    mut console: C,
    switch: &InputSwitch,
    wake: Box<dyn Fn() + Send + Sync>,
) -> (
    tokio::sync::mpsc::UnboundedReceiver<TerminalInput>,
    std::thread::JoinHandle<()>,
) {
    let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();
    let (answer_to, answers) = std::sync::mpsc::channel();
    let state = std::sync::Arc::new(std::sync::atomic::AtomicU8::new(request::IDLE));
    let switching = Switching {
        ask: std::sync::Arc::clone(&switch.ask),
        answers: answer_to,
        state: std::sync::Arc::clone(&state),
    };
    *switch
        .reader
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(ReaderLine {
        wake,
        answers,
        state,
    });
    let thread = std::thread::spawn(move || read_console(&mut console, &switching, &sender));
    (receiver, thread)
}

/// Reads `console` until its input ends, a batch has nowhere to go, or the stop is made.
///
/// The console is read as records until the switch asks. The thread then asks the console to spell
/// its keys, between two reads, and reads its text from then on as it comes, none of it turned into
/// anything. A console that would not spell its keys goes on being read as records. The thread is
/// only ever waiting for the console and for the stop together, and reads the console only when it
/// holds text, so the stop has no read to cancel unless the console keeps a record that the test of
/// `key_can_make_text` has not met.
#[cfg(any(not(unix), test))]
fn read_console(
    console: &mut impl ConsoleInput,
    switching: &Switching,
    sender: &tokio::sync::mpsc::UnboundedSender<TerminalInput>,
) {
    use std::sync::atomic::Ordering::SeqCst;

    let mut spelled = false;
    let mut in_a_row = 0_u32;
    loop {
        // A console that keeps having input is read a few times, and then a request that has been
        // waiting goes first.
        let requests_first = in_a_row >= READS_BEFORE_A_REQUEST;
        let woken = console.wait(requests_first);
        in_a_row = if matches!(woken, Ok(Woken::Console)) && !requests_first {
            in_a_row + 1
        } else {
            0
        };
        match woken {
            Ok(Woken::Console) if spelled => match console.bytes() {
                Ok(bytes) if bytes.is_empty() => {}
                Ok(bytes) => {
                    if sender.send(TerminalInput::Bytes(bytes)).is_err() {
                        return;
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => return,
            },
            Ok(Woken::Console) => {
                let Ok(runs) = console.keys() else {
                    return;
                };
                for keys in runs {
                    if sender.send(TerminalInput::Keys(keys)).is_err() {
                        return;
                    }
                }
            }
            Ok(Woken::Asked) => {
                // A request the switch withdrew while it waited is not made. The withdrawal is
                // cleared, unless a newer request has already replaced it.
                if switching
                    .state
                    .compare_exchange(request::PENDING, request::TAKEN, SeqCst, SeqCst)
                    .is_err()
                {
                    let _ = switching.state.compare_exchange(
                        request::WITHDRAWN,
                        request::IDLE,
                        SeqCst,
                        SeqCst,
                    );
                    continue;
                }
                // The half of a character the reader held is the last record it will read, and
                // it is handed on to be dropped with the others and counted.
                let held = console.held();
                if !held.is_empty() && sender.send(TerminalInput::Keys(held)).is_err() {
                    return;
                }
                // A console that already spells its keys is not asked again.
                let answer = if spelled { Ok(()) } else { (switching.ask)() };
                spelled = answer.is_ok();
                // The request is over before its answer can be heard, so that the next one is not
                // taken for this one.
                switching.state.store(request::IDLE, SeqCst);
                let _ = switching.answers.send(answer);
            }
            Ok(Woken::Stop) | Err(_) => return,
        }
    }
}

/// The key and modifiers the console spells a NUL with, as `VkKeyScanW(0)` names them.
///
/// The console keeps a key going down that has no character in its queue and a read of its text
/// passes over it and waits, except for this one: it is what Ctrl+Space and Ctrl+@ come out as.
#[cfg(any(not(unix), test))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NulKey {
    virtual_key: u16,
    shift: bool,
    control: bool,
    alt: bool,
}

#[cfg(any(not(unix), test))]
impl NulKey {
    /// The key `scan` (the answer of `VkKeyScanW(0)`) names: the virtual key in its low byte and
    /// the modifiers in its high one. None where the layout has no such key.
    #[must_use]
    pub(crate) const fn named_by(scan: i16) -> Option<Self> {
        if scan == -1 {
            return None;
        }
        let [low, high] = scan.to_le_bytes();
        Some(Self {
            virtual_key: low as u16,
            shift: high & 1 != 0,
            control: high & 2 != 0,
            alt: high & 4 != 0,
        })
    }
}

/// Whether a key record can make text in a console that spells its keys itself, which is whether a
/// read of that text would return for it and not pass over it and wait.
///
/// A key going down that has a character does. One that has none does only if it is the key a NUL
/// comes out as, with its modifiers; Shift, Ctrl, Alt, the Windows key, the locks, the Apps key, a
/// media key and a dead key are all kept as records the read passes over. A key coming up does not,
/// except an Alt coming up with the character that was composed on the numeric keypad.
#[cfg(any(not(unix), test))]
#[must_use]
pub(crate) fn key_can_make_text(key: &kr_term::win32::KeyRecord, nul: Option<NulKey>) -> bool {
    use kr_term::win32::control_keys::{
        LEFT_ALT_PRESSED, LEFT_CTRL_PRESSED, RIGHT_ALT_PRESSED, RIGHT_CTRL_PRESSED, SHIFT_PRESSED,
    };

    /// The Alt key's virtual key.
    const MENU: u16 = 0x12;
    if !key.key_down {
        return key.virtual_key == MENU && key.unicode != 0;
    }
    if key.unicode != 0 {
        return true;
    }
    nul.is_some_and(|nul| {
        let held = key.control_keys;
        key.virtual_key == nul.virtual_key
            && (!nul.shift || held & SHIFT_PRESSED != 0)
            && (!nul.control || held & (LEFT_CTRL_PRESSED | RIGHT_CTRL_PRESSED) != 0)
            && (!nul.alt || held & (LEFT_ALT_PRESSED | RIGHT_ALT_PRESSED) != 0)
    })
}

/// The UTF-8 of the UTF-16 units a console spelled, with a high surrogate that ended the read kept
/// in `carry` for the read that follows.
///
/// A unit that is no part of a character becomes U+FFFD, as it would anywhere else. A NUL is a NUL.
#[cfg(any(not(unix), test))]
pub(crate) fn utf8_of_console_text(units: &[u16], carry: &mut Option<u16>) -> Vec<u8> {
    let mut all: Vec<u16> = carry.take().into_iter().collect();
    all.extend_from_slice(units);
    if let Some(&last) = all.last()
        && (0xd800..0xdc00).contains(&last)
    {
        *carry = Some(last);
        all.pop();
    }
    char::decode_utf16(all.iter().copied())
        .map(|unit| unit.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect::<String>()
        .into_bytes()
}

/// One read of the terminal's input.
///
/// A terminal emulator hands this command bytes. A Windows console hands it the keys as the console
/// reported them, and turning those into bytes loses what bytes cannot carry, so the two are not
/// the same kind of input and are not made to look alike on the way in.
#[derive(Clone, PartialEq, Eq)]
pub enum TerminalInput {
    /// What the terminal sent, byte for byte.
    Bytes(Vec<u8>),
    /// A run of key records, in the order the console reported them, for the session to spell as
    /// its terminal asked for. Only a Windows console reports keys this way.
    Keys(Vec<kr_term::win32::KeyRecord>),
}

impl std::fmt::Debug for TerminalInput {
    /// Which kind it is and how much it holds, never what: a read is what a person typed.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bytes(bytes) => formatter
                .debug_struct("Bytes")
                .field("len", &bytes.len())
                .finish(),
            Self::Keys(keys) => formatter
                .debug_struct("Keys")
                .field("count", &keys.len())
                .finish(),
        }
    }
}

/// Reads the terminal in a blocking thread and hands batches to the caller.
///
/// The thread ends when the terminal's input does, when a batch has nowhere to go, or when the
/// returned [`InputStop`] is used. Dropping the receiver alone does not end it: the thread sits in
/// a read and takes the next key for itself.
///
/// # Errors
///
/// Never fails on this platform.
#[cfg(unix)]
pub fn spawn_input_reader(
    terminal: std::fs::File,
    _switch: &InputSwitch,
) -> Result<(
    tokio::sync::mpsc::UnboundedReceiver<TerminalInput>,
    InputStop,
)> {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use rustix::event::{PollFd, PollFlags, poll};
    use rustix::io::Errno;

    let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();
    // The thread waits for the terminal and for this pipe at once. Nothing is ever written to the
    // pipe: closing its write end, which `InputStop::stop` does, is what wakes the thread.
    let (woken, wake) = match rustix::pipe::pipe() {
        Ok(ends) => ends,
        Err(_) => {
            // No pipe to wait on: the thread reads as it always did and cannot be woken.
            return Ok((
                receiver,
                InputStop::unstoppable(spawn_blocking_reader(terminal, sender)),
            ));
        }
    };
    // Set by the thread when the terminal cannot be waited for, so that it reads without waiting
    // and cannot be woken either.
    let unwakeable = Arc::new(AtomicBool::new(false));
    let unwakeable_here = Arc::clone(&unwakeable);
    let thread = std::thread::spawn(move || {
        let mut terminal = terminal;
        let mut buffer = vec![0_u8; 8 * 1024];
        loop {
            let mut waiting = [
                PollFd::new(&terminal, PollFlags::IN),
                PollFd::new(&woken, PollFlags::IN),
            ];
            match poll(&mut waiting, None) {
                Ok(_) => {}
                Err(Errno::INTR) => continue,
                Err(_) => break,
            }
            // Asked to stop: the write end is closed.
            if !waiting[1].revents().is_empty() {
                break;
            }
            if waiting[0].revents().contains(PollFlags::NVAL) {
                // A terminal that cannot be waited for (macOS answers a poll of `/dev/tty` at
                // once): the read blocks, and nothing wakes it. Said before the pipe is looked at
                // once more, so that a stop is either seen here or knows the thread cannot be
                // joined.
                unwakeable_here.store(true, Ordering::SeqCst);
                let mut stopped = [PollFd::new(&woken, PollFlags::IN)];
                if matches!(poll(&mut stopped, Some(&rustix::event::Timespec { tv_sec: 0, tv_nsec: 0 })), Ok(n) if n > 0)
                {
                    break;
                }
            } else if waiting[0].revents().is_empty() {
                continue;
            }
            match terminal.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => {
                    if sender
                        .send(TerminalInput::Bytes(buffer[..read].to_vec()))
                        .is_err()
                    {
                        break;
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => break,
            }
        }
    });
    Ok((
        receiver,
        InputStop {
            wake: Some(wake),
            unwakeable,
            thread,
        },
    ))
}

/// Reads the console in a blocking thread and hands the keys to the caller as the records the
/// console reported them in.
///
/// Section 8 puts a Windows console on a different footing from a terminal emulator: what it
/// reports is a record with a virtual key, a scan code, one UTF-16 code unit, whether the key went
/// down or came up, the modifier state and a repeat count, and the session spells it as its
/// terminal asked for. A record that is not a key is not read as input.
///
/// Once `switch` has the console spell its keys itself, the thread reads the console's bytes
/// instead, as a command that reads a terminal does, and hands those on.
///
/// The thread ends when the console's input does, when a batch has nowhere to go, or when the
/// returned [`InputStop`] is used. While it reads records it waits for the console, the switch and
/// the stop together, so the stop does not depend on a read being cancelled.
///
/// # Errors
///
/// Returns an error when the system will not make the events the thread is woken with. No thread is
/// started then: one that could not be stopped would take the next key for itself.
#[cfg(not(unix))]
pub fn spawn_input_reader(
    console: std::fs::File,
    switch: &InputSwitch,
) -> Result<(
    tokio::sync::mpsc::UnboundedReceiver<TerminalInput>,
    InputStop,
)> {
    use std::sync::Arc;

    use crate::windows::records::{RecordReader, WakeEvent};

    let stop = Arc::new(WakeEvent::new()?);
    let asked = Arc::new(WakeEvent::new()?);
    let wake = {
        let asked = Arc::clone(&asked);
        Box::new(move || asked.signal())
    };
    let console = WindowsConsole {
        reader: RecordReader::over(console),
        stop: Arc::clone(&stop),
        asked,
        carry: None,
    };
    let (receiver, thread) = start_reader(console, switch, wake);
    Ok((receiver, InputStop { stop, thread }))
}

/// The Windows console, as the reader thread reads it.
#[cfg(not(unix))]
struct WindowsConsole {
    reader: crate::windows::records::RecordReader,
    /// Set to end the thread.
    stop: std::sync::Arc<crate::windows::records::WakeEvent>,
    /// Set by the switch to have the thread ask the console to spell its keys.
    asked: std::sync::Arc<crate::windows::records::WakeEvent>,
    /// The high surrogate a read of text ended with, for the read that follows.
    carry: Option<u16>,
}

#[cfg(not(unix))]
impl ConsoleInput for WindowsConsole {
    fn wait(&mut self, requests_first: bool) -> Result<Woken> {
        self.reader.wait(&self.stop, &self.asked, requests_first)
    }

    fn keys(&mut self) -> Result<Vec<Vec<kr_term::win32::KeyRecord>>> {
        use crate::windows::records::ReadEvent;

        Ok(self
            .reader
            .read_events()?
            .into_iter()
            .filter_map(|event| match event {
                ReadEvent::Keys(keys) => Some(keys),
                ReadEvent::Console(_) => None,
            })
            .collect())
    }

    fn held(&mut self) -> Vec<kr_term::win32::KeyRecord> {
        self.reader.held()
    }

    fn bytes(&mut self) -> std::io::Result<Vec<u8>> {
        if !self.reader.text_waiting()? {
            return Ok(Vec::new());
        }
        let mut units = [0_u16; 4096];
        let read = self.reader.read_text(&mut units)?;
        Ok(utf8_of_console_text(&units[..read], &mut self.carry))
    }
}

/// The thread that reads `terminal` until its input ends or `sender` has no receiver.
#[cfg(unix)]
fn spawn_blocking_reader(
    terminal: std::fs::File,
    sender: tokio::sync::mpsc::UnboundedSender<TerminalInput>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut terminal = terminal;
        let mut buffer = vec![0_u8; 8 * 1024];
        loop {
            match terminal.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => {
                    if sender
                        .send(TerminalInput::Bytes(buffer[..read].to_vec()))
                        .is_err()
                    {
                        break;
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => break,
            }
        }
    })
}

/// What ends the thread [`spawn_input_reader`] started.
///
/// A command that goes on after an attachment has ended (a window held open on a failure) reads
/// the terminal itself, and must be the only one reading it: a reader left in its read takes the
/// first key, and the command needs a second.
#[cfg(unix)]
pub struct InputStop {
    /// The write end of the pipe the thread also waits on; closing it wakes the thread. None when
    /// no pipe could be made and the thread cannot be woken.
    wake: Option<std::os::fd::OwnedFd>,
    /// Whether the thread found a terminal it cannot wait for and so cannot be woken.
    unwakeable: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// The reading thread.
    thread: std::thread::JoinHandle<()>,
}

#[cfg(unix)]
impl InputStop {
    /// A stop for a thread that cannot be woken.
    fn unstoppable(thread: std::thread::JoinHandle<()>) -> Self {
        Self {
            wake: None,
            unwakeable: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)),
            thread,
        }
    }

    /// Ends the thread, which has ended when this returns, unless it cannot be woken: a thread
    /// blocked in a read of a terminal that cannot be waited for is left to end with the next key,
    /// and is not joined.
    pub fn stop(self) {
        drop(self.wake);
        if !self.unwakeable.load(std::sync::atomic::Ordering::SeqCst) {
            let _ = self.thread.join();
        }
    }
}

/// What ends the thread [`spawn_input_reader`] started.
#[cfg(not(unix))]
pub struct InputStop {
    /// The event the thread also waits on.
    stop: std::sync::Arc<crate::windows::records::WakeEvent>,
    /// The reading thread.
    thread: std::thread::JoinHandle<()>,
}

#[cfg(not(unix))]
impl InputStop {
    /// Wakes the thread, which has ended a moment later: it is waiting for the console and for this
    /// together, and is not part way through a read it cannot leave. A thread that has not ended
    /// after a tenth of a second is in a read of the console that nothing but a cancel ends, and
    /// has that read cancelled, again and again until it has ended or a second has gone. The
    /// console gives the next key to a read that was cancelled, so this is for a thread that would
    /// otherwise go on taking keys.
    pub fn stop(self) {
        self.stop.signal();
        let started = std::time::Instant::now();
        let deadline = started + std::time::Duration::from_secs(1);
        let cancel_from = started + std::time::Duration::from_millis(100);
        while !self.thread.is_finished() && std::time::Instant::now() < deadline {
            if std::time::Instant::now() >= cancel_from {
                crate::platform::cancel_blocked_read(&self.thread);
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }
}

/// What an attachment needs to know of the session it attaches to.
///
/// A session on this host is named by the descriptor its worker published. A session in another
/// environment has no descriptor here, because the worker's endpoint and key are that
/// environment's own, so what the attachment uses is what both have: the session, the environment
/// it is in, and the number a person knows it by.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Attaching {
    /// The session.
    pub session_id: SessionId,
    /// The environment it runs in.
    pub environment_id: kr_protocol::ids::EnvironmentId,
    /// The number a person selects it by inside that environment.
    pub display_number: DisplayNumber,
}

impl From<&WorkerDescriptor> for Attaching {
    fn from(descriptor: &WorkerDescriptor) -> Self {
        Self {
            session_id: descriptor.session_id,
            environment_id: descriptor.environment_id,
            display_number: descriptor.display_number,
        }
    }
}

impl Attaching {
    /// The action target that names this session.
    #[must_use]
    pub fn target(&self) -> ActionTarget {
        ActionTarget {
            environment_id: self.environment_id,
            session_id: Nullable::some(self.session_id),
            session_epoch: Nullable::some(SessionEpoch::V1),
            application_instance_id: Nullable::null(),
            agent_binding_revision: Nullable::null(),
        }
    }
}

/// Returns the action target that names this worker's session.
#[must_use]
pub fn target(descriptor: &WorkerDescriptor) -> ActionTarget {
    Attaching::from(descriptor).target()
}

async fn call<P: serde::Serialize + ?Sized, T: kr_protocol::wire::WireMessage>(
    client: &mut impl Link,
    method: Method,
    target: ActionTarget,
    params: &P,
) -> Result<T> {
    let action_id = ActionId::new(kr_ipc::new_uuid());
    let outcome = client.mutate(method, action_id, target, params).await?;
    let value = outcome.map_err(CliError::Refused)?;
    value.to_typed().map_err(|error| {
        CliError::Other(shown!(
            "the host's answer could not be read: {}",
            Shown::cbor(&error)
        ))
    })
}

#[cfg(all(test, unix))]
mod tests {
    use super::RestorationGuard;
    use crate::terminal::SavedModes;

    /// A guard that leaves without answering is reported at once, with how it left.
    ///
    /// This is about the report pipe rather than the deadline. A `Command` holds this process's own
    /// copy of the write end for as long as it is alive, and while that copy is open a guard that
    /// has already gone leaves a pipe that never reaches its end: the read waits out the whole
    /// bound and then calls that guard "still running". [`RestorationGuard::start`] owns the
    /// `Command` and returns before anything waits, which is what closes it. This goes through the
    /// whole of [`RestorationGuard::arm_on_handle`], which is everything `arm` does but opening the
    /// terminal, so a change that put the waiting back beside the `Command` fails here: the report
    /// then says the guard was still running, where this one says it ended.
    #[test]
    fn a_guard_that_leaves_without_answering_is_reported_without_waiting_out_the_bound() {
        let terminal = std::fs::File::create(
            std::env::temp_dir().join(format!("kalareach-guard-test-{}", std::process::id())),
        )
        .expect("somewhere for the guard's own output to go");
        let saved = SavedModes {
            input: 0,
            output: 0,
            control: 0,
            local: 0,
            special: Vec::new(),
        };

        // `false` takes the arguments it is given, ignores them and exits, which is a guard that
        // never reports readiness.
        let refusal = RestorationGuard::arm_on_handle(
            std::path::Path::new("/usr/bin/false"),
            terminal,
            &saved,
        )
        .expect_err("it exits without answering, so there is nothing to confirm")
        .to_string();

        assert!(
            refusal.contains("ended without answering"),
            "and the attach is told which of the four it was: {refusal}"
        );
        assert!(
            refusal.contains("exit status: 1"),
            "with how the guard left, which `false` leaves as status 1: {refusal}"
        );
    }
}

#[cfg(test)]
mod a_worker_of_another_build {
    use super::check_build;
    use crate::CliError;
    use kr_protocol::error::ErrorCode;
    use kr_protocol::hello::{PACKAGE_VERSION, PackageVersion};
    use kr_protocol::ids::BuildId;
    use kr_protocol::local::LocalBuild;
    use kr_protocol::session::DisplayNumber;

    /// The action the refusal's code calls for.
    const UPDATE: &str = "Update this app or the host: their versions do not agree.";

    fn stated(build_id: &str, protocol_version: PackageVersion) -> LocalBuild {
        LocalBuild {
            build_id: BuildId::new(build_id).expect("a build identifier"),
            protocol_version,
        }
    }

    /// A version of another compatibility level than this build's.
    fn another_level() -> PackageVersion {
        if PACKAGE_VERSION.major == 0 {
            PackageVersion::new(0, PACKAGE_VERSION.minor + 1, 0)
        } else {
            PackageVersion::new(PACKAGE_VERSION.major + 1, 0, 0)
        }
    }

    /// What a refusal says to a person, with its code and its exit status, which are the refused
    /// request's: the sentence, then the direct action its code calls for.
    fn refused(stated: Option<&LocalBuild>) -> String {
        let refusal = check_build(stated, DisplayNumber::new(3)).expect_err("refused");
        assert!(
            matches!(&refusal, CliError::Refused(error) if error.code == ErrorCode::UnsupportedSchema),
            "{refusal}"
        );
        assert_eq!(refusal.code(), ErrorCode::UnsupportedSchema);
        assert_eq!(refusal.exit_code(), 8);
        assert_eq!(
            kr_client::retry::user_action(ErrorCode::UnsupportedSchema).message(),
            UPDATE
        );
        refusal.to_string()
    }

    /// A worker of this build's protocol version is attached to, and so is one whose version is a
    /// patch number apart: a change that takes only the next patch number changes no type.
    #[test]
    fn a_worker_of_this_protocol_version_or_a_patch_number_apart_is_attached_to() {
        let this = LocalBuild::this(BuildId::new("kr-worker/0.1.0").expect("a build identifier"));
        assert!(check_build(Some(&this), DisplayNumber::new(3)).is_ok());
        let patched = stated(
            "kr-worker/0.1.0",
            PackageVersion::new(
                PACKAGE_VERSION.major,
                PACKAGE_VERSION.minor,
                PACKAGE_VERSION.patch + 1,
            ),
        );
        assert!(check_build(Some(&patched), DisplayNumber::new(3)).is_ok());
    }

    /// A worker of another compatibility level is refused, and the refusal names both builds,
    /// both versions and what to do.
    #[test]
    fn a_worker_of_another_protocol_version_is_refused_naming_both_builds() {
        let theirs = another_level();
        assert_eq!(
            refused(Some(&stated("kr-worker/0.1.0", theirs))),
            format!(
                "session 3 runs on kr-worker/0.1.0 with protocol {theirs}, and this is {} with \
                 protocol {PACKAGE_VERSION}: this kr cannot show a session whose worker speaks \
                 another protocol version. Close the session with `kr close 3`, or attach with a \
                 kr of the worker's build\n{UPDATE}",
                crate::build_id().as_str()
            )
        );
    }

    /// A worker that states no build is of a build before the statement, and is refused as one.
    #[test]
    fn a_worker_that_states_no_build_is_refused_as_an_earlier_build() {
        assert_eq!(
            refused(None),
            format!(
                "session 3 runs on a worker of an earlier build, which does not state its build \
                 or its protocol version, and this is {} with protocol {PACKAGE_VERSION}: this kr \
                 cannot show a session whose worker speaks another protocol version. Close the \
                 session with `kr close 3`, or attach with a kr of the worker's build\n{UPDATE}",
                crate::build_id().as_str()
            )
        );
    }

    /// The refusal is a `Shown`: a build identifier is said when it is a program's name and a
    /// release, and any other text a worker states is replaced rather than repeated. The negative
    /// control is the identifier of the test above, which is said.
    #[test]
    fn a_build_identifier_that_is_not_a_name_and_a_release_is_not_repeated() {
        let long = format!("kr-worker/{}1", "1.".repeat(40));
        for text in [
            "kr-worker/0.1.0\u{202e}",
            "kr-worker/0.1.0 with protocol 9.9.9",
            "../kr-worker/0.1.0",
            "Kr-Worker/0.1.0",
            "kr-worker/0.1.0-rc.1",
            "kr-worker/",
            "kr-worker/0..1",
            "1kr/0.1.0",
            "kr-worker",
            long.as_str(),
        ] {
            let said = refused(Some(&stated(text, another_level())));
            assert!(!said.contains(text), "{text:?} is not repeated: {said}");
            assert!(
                said.contains("runs on [a build this kr does not name] with protocol"),
                "{said}"
            );
        }
        let said = refused(Some(&stated("kr-worker/0.1.0", another_level())));
        assert!(
            said.contains("runs on kr-worker/0.1.0 with protocol"),
            "{said}"
        );
    }
}

/// The thread that reads a console, run over a console the case holds both ends of.
#[cfg(test)]
mod reader {
    use std::collections::VecDeque;
    use std::sync::mpsc;
    use std::sync::{Arc, Mutex};

    use kr_client::shown::Shown;
    use kr_term::win32::KeyRecord;
    use tokio::sync::mpsc::UnboundedReceiver;

    use super::{
        ConsoleInput, InputSwitch, NulKey, READS_BEFORE_A_REQUEST, TerminalInput, Woken,
        key_can_make_text, start_reader, utf8_of_console_text,
    };
    use crate::error::{CliError, Result};

    /// What the thread asked of the console, in order.
    type Steps = Arc<Mutex<Vec<&'static str>>>;

    /// A console that answers a wait with what the case sent it, hands over the key records the
    /// case scripted, and hands over the bytes the case sends. A request goes ahead of the input
    /// the console holds only when the reader says it should.
    struct Scripted {
        wakes: mpsc::Receiver<Woken>,
        pending: VecDeque<Woken>,
        /// Holds the reader back from its first wait until the case has queued what it wants.
        start: Option<mpsc::Receiver<()>>,
        keys: VecDeque<Vec<Vec<KeyRecord>>>,
        held: Vec<KeyRecord>,
        bytes: mpsc::Receiver<Vec<u8>>,
        steps: Steps,
    }

    impl ConsoleInput for Scripted {
        fn wait(&mut self, requests_first: bool) -> Result<Woken> {
            if let Some(start) = self.start.take() {
                let _ = start.recv();
            }
            while let Ok(woken) = self.wakes.try_recv() {
                self.pending.push_back(woken);
            }
            if self.pending.is_empty() {
                match self.wakes.recv() {
                    Ok(woken) => self.pending.push_back(woken),
                    Err(_) => return Ok(Woken::Stop),
                }
            }
            let request = requests_first
                .then(|| self.pending.iter().position(|woken| *woken == Woken::Asked))
                .flatten();
            if requests_first {
                self.steps.lock().expect("steps").push("requests first");
            }
            Ok(match request {
                Some(at) => self.pending.remove(at).expect("it is there"),
                None => self.pending.pop_front().expect("something is pending"),
            })
        }

        fn keys(&mut self) -> Result<Vec<Vec<KeyRecord>>> {
            self.steps.lock().expect("steps").push("keys");
            Ok(self.keys.pop_front().unwrap_or_default())
        }

        fn held(&mut self) -> Vec<KeyRecord> {
            std::mem::take(&mut self.held)
        }

        fn bytes(&mut self) -> std::io::Result<Vec<u8>> {
            self.steps.lock().expect("steps").push("bytes");
            Ok(self.bytes.try_recv().unwrap_or_default())
        }
    }

    /// The thread, and the ends of its console the case holds.
    struct Run {
        input: UnboundedReceiver<TerminalInput>,
        switch: InputSwitch,
        wakes: mpsc::Sender<Woken>,
        bytes: mpsc::Sender<Vec<u8>>,
        /// Lets a reader that was held back start.
        go: mpsc::Sender<()>,
        /// Says that the switch has woken the reader.
        woke: mpsc::Receiver<()>,
        steps: Steps,
        thread: std::thread::JoinHandle<()>,
    }

    impl Run {
        /// Starts the thread over a console whose reads of key records are `keys`, in order, which
        /// holds `held` for the switch, and which spells its keys itself when asked if `will_spell`.
        fn started(
            will_spell: bool,
            keys: Vec<Vec<Vec<KeyRecord>>>,
            held: Vec<KeyRecord>,
            wake_reaches_the_reader: bool,
            held_back: bool,
        ) -> Self {
            let (wakes, heard) = mpsc::channel();
            let (bytes, spelled) = mpsc::channel();
            let (go, start) = mpsc::channel();
            let (woke_to, woke) = mpsc::channel();
            let steps: Steps = Arc::default();
            let asked = Arc::clone(&steps);
            let switch = InputSwitch::new(move || {
                asked.lock().expect("steps").push("ask");
                if will_spell {
                    Ok(())
                } else {
                    Err(CliError::Terminal(Shown::said("the console refused")))
                }
            });
            let console = Scripted {
                wakes: heard,
                pending: VecDeque::new(),
                start: held_back.then_some(start),
                keys: keys.into(),
                held,
                bytes: spelled,
                steps: Arc::clone(&steps),
            };
            let wake = {
                let wakes = wakes.clone();
                Box::new(move || {
                    if wake_reaches_the_reader {
                        let _ = wakes.send(Woken::Asked);
                    }
                    let _ = woke_to.send(());
                })
            };
            let (input, thread) = start_reader(console, &switch, wake);
            Self {
                input,
                switch,
                wakes,
                bytes,
                go,
                woke,
                steps,
                thread,
            }
        }

        fn start(will_spell: bool, keys: Vec<Vec<Vec<KeyRecord>>>) -> Self {
            Self::started(will_spell, keys, Vec::new(), true, false)
        }

        /// The console has input to read.
        fn has_input(&self) {
            self.wakes.send(Woken::Console).expect("the reader waits");
        }

        /// The next thing the thread handed on, within ten seconds.
        fn next(&mut self) -> TerminalInput {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            loop {
                match self.input.try_recv() {
                    Ok(read) => return read,
                    Err(_) => {
                        assert!(
                            std::time::Instant::now() < deadline,
                            "the reader handed nothing on in ten seconds"
                        );
                        std::thread::sleep(std::time::Duration::from_millis(1));
                    }
                }
            }
        }

        /// Ends the thread, and returns what it asked of the console.
        fn ends(self) -> Vec<&'static str> {
            let _ = self.wakes.send(Woken::Stop);
            self.thread.join().expect("the reader ended");
            self.steps.lock().expect("steps").clone()
        }
    }

    fn key(code: u16, unicode: u16, key_down: bool) -> KeyRecord {
        KeyRecord {
            virtual_key: code,
            scan_code: 0,
            unicode,
            key_down,
            control_keys: 0,
            repeat: 1,
        }
    }

    /// The reader asks the console to spell its keys between two of its reads. It has handed on as
    /// records every record it read before, reads no record after, and reads the console's text
    /// only once the console has been asked.
    #[test]
    fn the_console_is_asked_between_two_reads_and_its_bytes_are_read_after() {
        let down = key(u16::from(b'A'), u16::from(b'a'), true);
        let up = key(u16::from(b'A'), u16::from(b'a'), false);
        // What a reader of records would get once the console spells its keys: a character of a
        // sequence and nothing of a NUL. A reader that kept reading records would hand this on.
        let records_after = key(0, u16::from(b'z'), true);
        let mut run = Run::start(
            true,
            vec![vec![vec![down]], vec![vec![up]], vec![vec![records_after]]],
        );
        run.has_input();
        run.has_input();
        run.switch.engage().expect("the console spells its keys");
        assert_eq!(run.next(), TerminalInput::Keys(vec![down]));
        assert_eq!(run.next(), TerminalInput::Keys(vec![up]));

        run.bytes.send(b"x".to_vec()).expect("the reader waits");
        run.has_input();
        assert_eq!(run.next(), TerminalInput::Bytes(b"x".to_vec()));
        run.switch
            .engage()
            .expect("a console that spells its keys already is not asked again");

        let steps = run.ends();
        let asked = steps.iter().position(|step| *step == "ask").expect("asked");
        assert_eq!(
            steps[..asked],
            ["keys", "keys"],
            "the records the console held are read before it is asked"
        );
        assert!(
            steps[asked + 1..].iter().all(|step| *step == "bytes"),
            "nothing but bytes is read after it, and it is asked once: {steps:?}"
        );
    }

    /// What the console spells reaches the session as it spelled it: a NUL (Ctrl+Space), a key held
    /// down (the same byte again) and a sequence. A console that has no byte to give hands on
    /// nothing.
    #[test]
    fn the_bytes_a_console_spells_are_handed_on_as_they_are() {
        let mut run = Run::start(true, Vec::new());
        run.switch.engage().expect("the console spells its keys");
        run.has_input();
        let spelled = [0x00, b'a', b'a', b'a', 0x1b, b'[', b'A', 0xc3, 0xa9];
        run.bytes.send(spelled.to_vec()).expect("the reader waits");
        run.has_input();
        assert_eq!(run.next(), TerminalInput::Bytes(spelled.to_vec()));
        run.bytes.send(b"b".to_vec()).expect("the reader waits");
        run.has_input();
        assert_eq!(
            run.next(),
            TerminalInput::Bytes(b"b".to_vec()),
            "nothing was handed on for the input that held no byte"
        );
        run.ends();
    }

    /// A console that would not spell its keys goes on being read as records.
    #[test]
    fn a_console_that_will_not_spell_its_keys_goes_on_being_read_as_records() {
        let down = key(u16::from(b'A'), u16::from(b'a'), true);
        let mut run = Run::start(false, vec![vec![vec![down]]]);
        assert!(run.switch.engage().is_err());
        run.has_input();
        assert_eq!(run.next(), TerminalInput::Keys(vec![down]));
        let steps = run.ends();
        assert!(
            !steps.contains(&"bytes"),
            "no byte was read from a console that did not spell: {steps:?}"
        );
    }

    /// A switch asked of a reader that has ended fails at once and does not wait for it.
    #[test]
    fn a_reader_that_has_ended_cannot_be_asked() {
        let run = Run::start(true, Vec::new());
        run.wakes.send(Woken::Stop).expect("the reader waits");
        let Run { switch, thread, .. } = run;
        thread.join().expect("the reader ended");
        assert!(switch.engage().is_err());
    }

    /// A console that keeps having input is read a few times and then the request that has waited
    /// is heard, before the input that is still there.
    #[test]
    fn a_console_that_never_stops_having_input_cannot_keep_a_request_from_being_heard() {
        let reads = READS_BEFORE_A_REQUEST + 6;
        let run = Run::started(true, Vec::new(), Vec::new(), true, true);
        for _ in 0..reads {
            run.has_input();
        }
        // The request goes in behind all of it, and then the reader is let go.
        std::thread::scope(|scope| {
            let asking = scope.spawn(|| run.switch.engage());
            run.woke.recv().expect("the switch woke the reader");
            run.go.send(()).expect("the reader waits");
            asking
                .join()
                .expect("the switch ended")
                .expect("the request was heard");
        });
        let steps = run.ends();
        let asked = steps.iter().position(|step| *step == "ask").expect("asked");
        assert_eq!(
            steps[..asked]
                .iter()
                .filter(|step| **step == "keys")
                .count(),
            usize::try_from(READS_BEFORE_A_REQUEST).expect("a small number"),
            "the request was heard after that many reads of the console in a row, with input \
             still waiting: {steps:?}"
        );
    }

    /// A request the reader did not begin on in time is withdrawn, so that it does not switch the
    /// console after the attachment has been told it could not.
    #[test]
    fn a_request_that_timed_out_does_not_take_effect_later() {
        // The wake never reaches the reader, as if it were busy with something else.
        let run = Run::started(true, Vec::new(), Vec::new(), false, false);
        assert!(run.switch.engage().is_err(), "nobody answered");
        // The reader hears the wake late.
        run.wakes.send(Woken::Asked).expect("the reader waits");
        let steps = run.ends();
        assert!(
            !steps.contains(&"ask"),
            "the console was asked after the request was withdrawn: {steps:?}"
        );
    }

    /// Requests one after another are each answered: the reader has finished with one before the
    /// answer to it can be heard, so that the next is not taken for it.
    #[test]
    fn requests_one_after_another_are_each_answered() {
        let run = Run::start(true, Vec::new());
        for round in 0..2000 {
            run.switch
                .engage()
                .unwrap_or_else(|error| panic!("request {round} was not answered: {error}"));
        }
        let steps = run.ends();
        assert_eq!(
            steps.iter().filter(|step| **step == "ask").count(),
            1,
            "a console that spells its keys is asked once"
        );
    }

    /// The first half of a character the reader holds when it switches is handed on, to be dropped
    /// and counted with the records already read, and not lost without a trace.
    #[test]
    fn a_half_held_at_the_switch_is_handed_on_to_be_counted() {
        let half = key(0, 0xd83d, true);
        let mut run = Run::started(true, Vec::new(), vec![half], true, false);
        run.switch.engage().expect("the console spells its keys");
        assert_eq!(run.next(), TerminalInput::Keys(vec![half]));
        run.ends();
    }

    /// The text a console spells is UTF-8 whatever the console's code page: a NUL stays, a character
    /// outside the basic plane that a read ends in the middle of is joined with its second half, and
    /// a unit that is no part of a character is replaced.
    #[test]
    fn the_text_a_console_spells_is_utf8() {
        let mut carry = None;
        assert_eq!(
            utf8_of_console_text(&[0x0000, 0x0061, 0x00e9, 0x20ac], &mut carry),
            "\0a\u{e9}\u{20ac}".as_bytes()
        );
        assert_eq!(utf8_of_console_text(&[0x0061, 0xd83d], &mut carry), b"a");
        assert_eq!(carry, Some(0xd83d));
        assert_eq!(
            utf8_of_console_text(&[0xde00, 0x0062], &mut carry),
            "\u{1f600}b".as_bytes()
        );
        assert_eq!(carry, None);
        assert_eq!(
            utf8_of_console_text(&[0xde00], &mut carry),
            "\u{fffd}".as_bytes()
        );
    }

    /// A key going down with no character makes text only if it is the key a NUL comes out as, and a
    /// key coming up makes none unless it is an Alt coming up with a composed character.
    #[test]
    fn only_a_key_the_console_reads_as_text_makes_text() {
        // What the console stores for Ctrl+Space and Ctrl+@ on a US layout: the '2' key, with Ctrl and
        // Shift. `VkKeyScanW(0)` answers 0x0332 there.
        let nul = NulKey::named_by(0x0332);
        assert_eq!(nul.map(|nul| nul.virtual_key), Some(0x32));
        let stored = KeyRecord {
            control_keys: 0x08 | 0x10,
            ..key(0x32, 0, true)
        };
        assert!(key_can_make_text(&stored, nul), "the NUL");
        assert!(
            !key_can_make_text(
                &KeyRecord {
                    control_keys: 0,
                    ..stored
                },
                nul
            ),
            "the same key without its modifiers"
        );
        assert!(
            !key_can_make_text(&stored, None),
            "a layout with no NUL key"
        );
        // Keys the console keeps as records that a read of its text passes over.
        for none in [
            0x10, 0x11, 0x12, 0x5b, 0x14, 0x90, 0x5d, 0x7c, 0xaf, 0xe7, 0xff,
        ] {
            assert!(!key_can_make_text(&key(none, 0, true), nul), "{none:#x}");
        }
        assert!(key_can_make_text(&key(0, 0x61, true), nul), "a character");
        assert!(
            !key_can_make_text(&key(0x41, 0x61, false), nul),
            "a character coming up"
        );
        assert!(
            key_can_make_text(&key(0x12, 0x00e9, false), nul),
            "an Alt coming up with the character composed on the keypad"
        );
        assert!(!key_can_make_text(&key(0x12, 0, false), nul), "an Alt");
    }
}
