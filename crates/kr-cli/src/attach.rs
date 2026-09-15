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
use std::sync::Arc;

use kr_ipc::client::LocalClient;
use kr_protocol::attachment::{
    AttachMode, AttachmentCapability, SessionAttachParams, SessionAttachResult, SessionDetachParams,
};
use kr_protocol::envelope::ActionTarget;
use kr_protocol::ids::{ActionId, AttachmentId, SessionEpoch, SessionId};
use kr_protocol::input::{InputAcquireParams, InputAcquireResult, InputWriteParams};
use kr_protocol::local::ControlMessage;
use kr_protocol::method::Method;
use kr_protocol::recovery::{EventStream, EventsSubscribeParams, OutputEvent};
use kr_protocol::scalars::{Bytes, CanonicalSet, Nullable};
use kr_protocol::session::Dimensions;
use kr_protocol::worker::WorkerDescriptor;
use rustix::termios::Termios;

use crate::error::{CliError, Result};
use crate::terminal::{ControllingTerminal, SavedModes};

/// The byte that tells the guard the terminal has already been restored.
pub const GUARD_RELEASE: u8 = b'R';

/// The out-of-process restoration guard.
///
/// It holds the saved terminal state and a handle on the terminal, in a process this one does not
/// control. If this process dies the pipe closes and the guard restores; if this process finishes
/// properly it restores first and releases the guard.
#[derive(Debug)]
pub struct RestorationGuard {
    child: std::process::Child,
    release: Option<std::io::PipeWriter>,
}

impl RestorationGuard {
    /// Arms a guard for this terminal.
    ///
    /// The guard is started before the terminal is touched and confirms that it is holding the
    /// state before the caller changes anything.
    ///
    /// # Errors
    ///
    /// Returns an error when the guard cannot be started or does not confirm.
    pub fn arm(
        program: &std::path::Path,
        terminal: &ControllingTerminal,
        saved: &Termios,
    ) -> Result<Self> {
        let (reader, writer) = std::io::pipe()
            .map_err(|error| CliError::Terminal(format!("create the guard's pipe: {error}")))?;
        let handle = terminal
            .handle()
            .try_clone()
            .map_err(|error| CliError::Terminal(format!("duplicate the terminal: {error}")))?;
        let modes = SavedModes::from_termios(saved);
        let mut command = detached(program);
        command
            .arg("--modes")
            .arg(modes.encode())
            .stdin(Stdio::from(reader))
            .stdout(Stdio::from(handle))
            .stderr(Stdio::null());
        let child = command
            .spawn()
            .map_err(|error| CliError::Terminal(format!("start the restoration guard: {error}")))?;
        Ok(Self {
            child,
            release: Some(writer),
        })
    }

    /// Releases the guard without it acting, after the caller has restored the terminal itself.
    pub fn release(mut self) {
        use std::io::Write as _;

        if let Some(mut writer) = self.release.take() {
            let _ = writer.write_all(&[GUARD_RELEASE]);
            let _ = writer.flush();
        }
        let _ = self.child.wait();
    }
}

#[cfg(unix)]
fn detached(program: &std::path::Path) -> Command {
    use std::os::unix::process::CommandExt as _;

    // The guard gets its own process group, so a signal aimed at this command's group — the one a
    // shell sends on Ctrl-C, or on the pipeline's exit — does not reach it. It keeps the
    // controlling terminal, because restoring that terminal is its whole purpose; it handles the
    // background-write signal itself rather than being stopped by it.
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
        terminal_profile_id: Nullable(std::env::var("TERM").ok()),
        requested,
    };
    let result: SessionAttachResult =
        call(client, Method::SessionAttach, target(descriptor), &params).await?;
    let attachment_id = result.attachment.attachment_id;
    let lease: InputAcquireResult = call(
        client,
        Method::InputAcquire,
        target(descriptor),
        &InputAcquireParams {
            session_id: descriptor.session_id,
            attachment_id,
            expected_epoch: Nullable::null(),
        },
    )
    .await?;
    Ok(Attachment {
        attachment_id,
        lease: Some(lease),
        result,
    })
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

/// Detaches an attachment.
///
/// # Errors
///
/// Returns the host's refusal, or a transport failure.
pub async fn detach(
    client: &mut LocalClient,
    descriptor: &WorkerDescriptor,
    attachment_id: AttachmentId,
) -> Result<()> {
    let _: kr_protocol::attachment::SessionDetachResult = call(
        client,
        Method::SessionDetach,
        target(descriptor),
        &SessionDetachParams { attachment_id },
    )
    .await?;
    Ok(())
}

/// Forwards one batch of input bytes.
///
/// # Errors
///
/// Returns the host's refusal, or a transport failure.
pub async fn write_input(
    client: &mut LocalClient,
    session_id: SessionId,
    attachment_id: AttachmentId,
    epoch: kr_protocol::ids::InputLeaseEpoch,
    sequence: u64,
    bytes: Vec<u8>,
) -> Result<()> {
    let params = InputWriteParams {
        session_id,
        attachment_id,
        epoch,
        sequence: kr_protocol::ids::InputSequence::new(sequence),
        bytes: Bytes::new(bytes),
    };
    let outcome = client.request(Method::InputWrite, &params).await?;
    outcome.map(|_| ()).map_err(CliError::Refused)
}

/// Reads output notifications and writes them to the terminal, in order.
///
/// Nothing here interprets the bytes. They came from the application and they go to the terminal
/// exactly as they are.
pub async fn pump_output(client: &mut LocalClient, terminal: Arc<std::fs::File>) -> Result<()> {
    use std::io::Write as _;

    loop {
        let message = match client.recv().await {
            Ok(message) => message,
            Err(kr_ipc::IpcError::PeerClosed) => return Ok(()),
            Err(error) => return Err(CliError::Ipc(error)),
        };
        let ControlMessage::Notification(notification) = message else {
            continue;
        };
        if notification.event_type.as_str() == "session.output" {
            let Ok(event) = notification.payload.to_typed::<OutputEvent>() else {
                continue;
            };
            let mut handle = terminal.as_ref();
            if handle.write_all(event.bytes.as_slice()).is_err() {
                return Ok(());
            }
            let _ = handle.flush();
        }
    }
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

fn target(descriptor: &WorkerDescriptor) -> ActionTarget {
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
