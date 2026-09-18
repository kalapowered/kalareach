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

use std::io::Read as _;
use std::process::{Command, Stdio};

use kr_ipc::client::LocalClient;
use kr_protocol::attachment::{
    AttachMode, AttachmentCapability, SessionAttachParams, SessionAttachResult, SessionDetachParams,
};
use kr_protocol::envelope::ActionTarget;
use kr_protocol::ids::{ActionId, AttachmentId, SessionEpoch, SessionId};
use kr_protocol::input::{InputAcquireParams, InputAcquireResult};
use kr_protocol::method::Method;
use kr_protocol::recovery::{EventStream, EventsSubscribeParams};
use kr_protocol::scalars::{CanonicalSet, Nullable};
use kr_protocol::session::Dimensions;
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
        let handle = terminal
            .handle()
            .try_clone()
            .map_err(|error| CliError::Terminal(format!("duplicate the terminal: {error}")))?;
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
            return Err(CliError::Terminal(format!(
                "the restoration guard did not report that it was holding the terminal: {silence}"
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
        let (reader, writer) = std::io::pipe()
            .map_err(|error| CliError::Terminal(format!("create the guard's pipe: {error}")))?;
        let (ready_reader, ready_writer) = std::io::pipe()
            .map_err(|error| CliError::Terminal(format!("create the guard's pipe: {error}")))?;
        let mut command = detached(program);
        command
            .arg("--modes")
            .arg(saved.encode())
            .stdin(Stdio::from(reader))
            .stdout(Stdio::from(terminal))
            .stderr(Stdio::from(ready_writer));
        let child = command
            .spawn()
            .map_err(|error| CliError::Terminal(format!("start the restoration guard: {error}")))?;
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
    fn confirmed(&mut self) -> std::result::Result<(), String> {
        let Some(reader) = self.confirmations.take() else {
            return Err("its side of the report pipe is already closed".to_owned());
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
                return Err(format!(
                    "it was still running and had not answered after {:?}",
                    started.elapsed()
                ));
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let Ok((reader, read)) = answer.join() else {
            return Err("the thread reading its report failed".to_owned());
        };
        self.confirmations = Some(reader);
        match read {
            Ok((1, byte)) if byte == GUARD_READY => Ok(()),
            Ok((1, byte)) => Err(format!(
                "it answered {byte:#04x} rather than its readiness after {:?}",
                started.elapsed()
            )),
            // No byte means its end of this pipe is closed, which means the process is gone.
            Ok(_) => Err(format!(
                "it ended without answering after {:?}{}",
                started.elapsed(),
                self.departure()
            )),
            Err(error) => Err(format!(
                "reading its report failed after {:?}: {error}",
                started.elapsed()
            )),
        }
    }

    /// How the guard went, for a report about a guard that is no longer answering.
    fn departure(&mut self) -> String {
        match self.child.try_wait() {
            Ok(Some(status)) => format!(" ({status})"),
            Ok(None) => String::new(),
            Err(error) => format!(" (its status could not be read: {error})"),
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
            return Err(CliError::Terminal(
                "the restoration guard is no longer listening".to_owned(),
            ));
        };
        if writer.write_all(&[GUARD_BEGIN, b'\n']).is_err() || writer.flush().is_err() {
            return Err(CliError::Terminal(
                "the restoration guard could not be asked to hold the keyboard state".to_owned(),
            ));
        }
        self.confirmed().map_err(|silence| {
            CliError::Terminal(format!(
                "the restoration guard did not report that it was holding the keyboard state: \
                 {silence}"
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
#[derive(Debug)]
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
    client: &mut LocalClient,
    descriptor: &WorkerDescriptor,
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
        session_id: descriptor.session_id,
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
        call(client, Method::SessionAttach, target(descriptor), &params).await?;
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
        target(descriptor),
        &InputAcquireParams {
            session_id: descriptor.session_id,
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

/// Takes the session's size ownership for this attachment.
///
/// # Errors
///
/// Returns the host's refusal, or a transport failure.
pub async fn take_geometry(
    client: &mut LocalClient,
    descriptor: &WorkerDescriptor,
    attachment_id: AttachmentId,
    expected_epoch: kr_protocol::ids::GeometryEpoch,
) -> Result<kr_protocol::attachment::GeometryResult> {
    call(
        client,
        Method::TerminalGeometryTransfer,
        target(descriptor),
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
    client: &mut LocalClient,
    descriptor: &WorkerDescriptor,
    params: &kr_protocol::attachment::TerminalResizeParams,
) -> Result<kr_protocol::attachment::GeometryResult> {
    call(client, Method::TerminalResize, target(descriptor), params).await
}

/// Returns the guard executable that sits beside this one.
#[must_use]
pub fn guard_program() -> std::path::PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(|parent| parent.join("kr-attach-guard")))
        .unwrap_or_else(|| std::path::PathBuf::from("kr-attach-guard"))
}

/// Detaches an attachment of a session, named explicitly.
///
/// # Errors
///
/// Returns the host's refusal, or a transport failure.
pub async fn detach_attachment(
    client: &mut LocalClient,
    descriptor: &WorkerDescriptor,
    attachment_id: AttachmentId,
) -> Result<kr_protocol::attachment::SessionDetachResult> {
    call(
        client,
        Method::SessionDetach,
        target(descriptor),
        &SessionDetachParams { attachment_id },
    )
    .await
}

/// Subscribes an attachment to the session's output.
///
/// # Errors
///
/// Returns the host's refusal, or a transport failure.
pub async fn subscribe(
    client: &mut LocalClient,
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

/// Reads the terminal in a blocking thread and hands batches to the caller.
pub fn spawn_input_reader(
    terminal: std::fs::File,
) -> tokio::sync::mpsc::UnboundedReceiver<Vec<u8>> {
    let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();
    std::thread::spawn(move || {
        let mut terminal = terminal;
        let mut buffer = vec![0_u8; 8 * 1024];
        loop {
            match terminal.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => {
                    if sender.send(buffer[..read].to_vec()).is_err() {
                        break;
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(_) => break,
            }
        }
    });
    receiver
}

/// Returns the action target that names this worker's session.
#[must_use]
pub fn target(descriptor: &WorkerDescriptor) -> ActionTarget {
    ActionTarget {
        environment_id: descriptor.environment_id,
        session_id: Nullable::some(descriptor.session_id),
        session_epoch: Nullable::some(SessionEpoch::V1),
        application_instance_id: Nullable::null(),
        agent_binding_revision: Nullable::null(),
    }
}

async fn call<P: serde::Serialize + ?Sized, T: serde::de::DeserializeOwned + serde::Serialize>(
    client: &mut LocalClient,
    method: Method,
    target: ActionTarget,
    params: &P,
) -> Result<T> {
    let action_id = ActionId::new(kr_ipc::new_uuid());
    let outcome = client.mutate(method, action_id, target, params).await?;
    let value = outcome.map_err(CliError::Refused)?;
    value
        .to_typed()
        .map_err(|error| CliError::Other(error.to_string()))
}

#[cfg(all(test, unix))]
mod tests {
    use super::{GUARD_ARM_TIMEOUT, RestorationGuard};
    use crate::terminal::SavedModes;

    /// A guard that leaves without answering is reported at once, with how it left.
    ///
    /// This is about the report pipe rather than the deadline. A `Command` holds this process's own
    /// copy of the write end for as long as it is alive, and while that copy is open a guard that
    /// has already gone leaves a pipe that never reaches its end: the read waits out the whole
    /// bound and then calls that guard "still running". [`RestorationGuard::start`] owns the
    /// `Command` and returns before anything waits, which is what closes it. This goes through the
    /// whole of [`RestorationGuard::arm_on_handle`], which is everything `arm` does but opening the
    /// terminal, so a change that put the waiting back beside the `Command` fails here.
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
        let started = std::time::Instant::now();
        let refusal = RestorationGuard::arm_on_handle(
            std::path::Path::new("/usr/bin/false"),
            terminal,
            &saved,
        )
        .expect_err("it exits without answering, so there is nothing to confirm")
        .to_string();

        assert!(
            started.elapsed() < GUARD_ARM_TIMEOUT / 4,
            "the report pipe ended with the process rather than waiting out the bound: {:?}",
            started.elapsed()
        );
        assert!(
            refusal.contains("ended without answering"),
            "and the attach is told which of the four it was: {refusal}"
        );
        assert!(
            refusal.contains("exit status"),
            "with how the guard left: {refusal}"
        );
    }
}
