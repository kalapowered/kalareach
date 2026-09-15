//! Attaching a terminal and driving it until the attachment ends.
//!
//! An attach is three things happening at once: bytes from the terminal going to the session, bytes
//! from the session going to the terminal, and a connection that can end at any moment. They run in
//! one loop rather than in tasks that each decide separately when to stop, because every way this
//! ends has to end the *other two* as well. A terminal left in raw mode because one half was still
//! waiting for a keystroke is the failure section 8 names.

use std::sync::Arc;

use kr_ipc::client::LocalClient;
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{InputLeaseEpoch, SessionId};
use kr_protocol::local::ControlMessage;
use kr_protocol::method::Method;
use kr_protocol::session::Dimensions;
use kr_protocol::worker::WorkerDescriptor;

use crate::attach::{Attachment, RestorationGuard};
use crate::error::{CliError, Result};
use crate::terminal::ControllingTerminal;

/// Why an attachment ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AttachOutcome {
    /// The terminal's own input ended, or the user detached.
    Detached,
    /// The session closed while this terminal was attached.
    SessionClosed,
    /// The input lease moved to somebody else.
    LeaseLost,
    /// The connection to the worker ended.
    Disconnected,
    /// Input could not be delivered, and whether it arrived is not known.
    DeliveryUncertain(String),
}

impl AttachOutcome {
    /// Returns the sentence a person is shown.
    #[must_use]
    pub fn detail(&self) -> String {
        match self {
            Self::Detached => "detached".to_owned(),
            Self::SessionClosed => "the session closed".to_owned(),
            Self::LeaseLost => "another attachment took the input lease".to_owned(),
            Self::Disconnected => "the connection to the session ended".to_owned(),
            Self::DeliveryUncertain(detail) => {
                format!("some input may not have reached the session: {detail}")
            }
        }
    }

    /// Returns whether this outcome is a failure the exit code must carry.
    #[must_use]
    pub const fn is_failure(&self) -> bool {
        match self {
            Self::Detached | Self::SessionClosed => false,
            Self::LeaseLost | Self::Disconnected | Self::DeliveryUncertain(_) => true,
        }
    }

    /// Returns the failure this outcome is reported as.
    #[must_use]
    pub fn into_error(self) -> Option<CliError> {
        match self {
            Self::Detached | Self::SessionClosed => None,
            Self::LeaseLost => Some(CliError::Refused(kr_protocol::error::ProtocolError::new(
                ErrorCode::LeaseLost,
                self.detail(),
            ))),
            Self::Disconnected => Some(CliError::HostUnavailable(self.detail())),
            Self::DeliveryUncertain(_) => Some(CliError::Refused(
                kr_protocol::error::ProtocolError::new(ErrorCode::OutcomeUnknown, self.detail()),
            )),
        }
    }
}

/// How an attach presents the session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttachOptions {
    /// Take size ownership for this terminal.
    pub take_geometry: bool,
    /// Skip the outer terminal's capability probe and use the conservative profile.
    pub no_probe: bool,
}

/// Attaches this terminal to a session and drives it until the attachment ends.
///
/// # Errors
///
/// Returns the host's refusal, a terminal failure, or the failure the attachment ended with.
pub async fn run(
    descriptor: &WorkerDescriptor,
    options: AttachOptions,
) -> Result<(AttachOutcome, SessionId)> {
    let terminal = ControllingTerminal::open()?;
    let size = terminal.size()?;
    let dimensions = Dimensions::new(u64::from(size.columns), u64::from(size.rows));
    let mut client = crate::resolve::open_worker(descriptor, crate::build_id()).await?;
    // A terminal attachment claims the session's size. Section 8 makes that the default: a
    // terminal that did not claim it would be shown a projection of somebody else's size, which is
    // exactly what a lone attachment does not need. `--take-geometry` goes further and takes the
    // claim from whoever holds it.
    let attachment: Attachment =
        crate::attach::attach(&mut client, descriptor, dimensions, true, !options.no_probe).await?;
    if options.take_geometry {
        crate::attach::take_geometry(
            &mut client,
            descriptor,
            attachment.attachment_id,
            attachment.result.geometry.epoch,
        )
        .await?;
    }
    let epoch = attachment
        .lease
        .as_ref()
        .map_or(InputLeaseEpoch::new(0), |lease| lease.lease.epoch);

    // From the cursor the attachment was allocated at, not from the beginning of what is retained.
    // Replaying historical bytes into this terminal would replay whatever they contained: a
    // clipboard write, a bell, a query whose answer would arrive at the wrong moment.
    crate::attach::subscribe(
        &mut client,
        descriptor.session_id,
        attachment.attachment_id,
        Some(attachment.result.output_cursor.get()),
    )
    .await?;

    // The guard is armed before the terminal is touched, and it confirms that it is holding the
    // state before this returns, so there is no window in which the terminal is raw and nothing is
    // holding its previous state.
    let saved = terminal.modes()?;
    let guard = RestorationGuard::arm(
        &crate::attach::guard_program(),
        &terminal,
        &crate::terminal::SavedModes::from_state(&saved),
    )?;
    let raw_replaced = terminal.enter_raw_mode()?;

    let handle = Arc::new(
        terminal
            .handle()
            .try_clone()
            .map_err(|error| CliError::Terminal(error.to_string()))?,
    );
    let input_handle = terminal
        .handle()
        .try_clone()
        .map_err(|error| CliError::Terminal(error.to_string()))?;
    let mut input = crate::attach::spawn_input_reader(input_handle);

    // The terminal's size can change while the attachment runs. The session is told, so the
    // application sees the resize the way it would in any other terminal.
    let mut resized = window_changes();
    let outcome = drive(
        &mut client,
        descriptor,
        attachment.attachment_id,
        epoch,
        &mut input,
        &handle,
        &terminal,
        resized.as_mut(),
    )
    .await;

    // The terminal comes back here on every path out of the loop, and the guard is released only
    // once it has.
    terminal.restore(&raw_replaced)?;
    guard.release();
    Ok((outcome, descriptor.session_id))
}

/// Runs the attachment's input, output and connection in one loop.
#[expect(
    clippy::too_many_arguments,
    reason = "an attachment is input, output, connection, terminal and size; the loop needs all of \
              them and splitting it would split the thing that has to end together"
)]
async fn drive(
    client: &mut LocalClient,
    descriptor: &WorkerDescriptor,
    attachment_id: kr_protocol::ids::AttachmentId,
    epoch: InputLeaseEpoch,
    input: &mut tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
    output: &Arc<std::fs::File>,
    terminal: &ControllingTerminal,
    resized: Option<&mut WindowChanges>,
) -> AttachOutcome {
    use std::io::Write as _;

    let session_id = descriptor.session_id;
    let mut resized = resized;

    let mut sequence = 0_u64;
    let mut outstanding: std::collections::BTreeMap<kr_protocol::ids::RequestId, u64> =
        std::collections::BTreeMap::new();
    let mut next_request = 1_u64;
    loop {
        tokio::select! {
            // Biased towards the worker, so output and refusals are seen before more input is sent.
            biased;
            message = client.recv() => {
                match message {
                    Ok(ControlMessage::Notification(notification)) => {
                        if notification.event_type.as_str() == "session.output"
                            && let Ok(event) = notification
                                .payload
                                .to_typed::<kr_protocol::recovery::OutputEvent>()
                        {
                            let mut handle = output.as_ref();
                            if handle.write_all(event.bytes.as_slice()).is_err() {
                                return AttachOutcome::Disconnected;
                            }
                            let _ = handle.flush();
                        }
                        // A resynchronisation marker means this terminal's view of the session is
                        // no longer continuous. The attachment ends rather than drawing bytes that
                        // do not follow the ones before them.
                        if notification.event_type.as_str() == "session.resync" {
                            return AttachOutcome::Disconnected;
                        }
                    }
                    Ok(ControlMessage::Response(response)) => {
                        let Some(sent) = outstanding.remove(&response.request_id) else {
                            continue;
                        };
                        if let kr_protocol::envelope::Outcome::Error(error) = response.outcome {
                            return match error.code {
                                ErrorCode::LeaseLost => AttachOutcome::LeaseLost,
                                ErrorCode::SessionClosed => AttachOutcome::SessionClosed,
                                code => AttachOutcome::DeliveryUncertain(format!(
                                    "{code} at input {sent}: {}",
                                    error.message
                                )),
                            };
                        }
                    }
                    Ok(_) => {}
                    Err(_) => return AttachOutcome::Disconnected,
                }
            }
            () = wait_for_resize(&mut resized) => {
                // The outer terminal changed size. The session is told, so the application is
                // redrawn at the size the person is actually looking at.
                if let Ok(size) = terminal.size() {
                    let params = kr_protocol::attachment::TerminalResizeParams {
                        attachment_id,
                        dimensions: Dimensions::new(
                            u64::from(size.columns),
                            u64::from(size.rows),
                        ),
                        expected_geometry_epoch: kr_protocol::ids::GeometryEpoch::new(0),
                    };
                    // A size change is reported, not insisted on: another attachment may own the
                    // geometry, and this one is then shown that size rather than taking it.
                    let _ = crate::attach::resize(client, descriptor, &params).await;
                }
            }
            bytes = input.recv() => {
                let Some(bytes) = bytes else {
                    // The terminal's own input ended. Nothing is left to forward.
                    return AttachOutcome::Detached;
                };
                let request_id = kr_protocol::ids::RequestId::new(next_request);
                next_request += 1;
                let params = kr_protocol::input::InputWriteParams {
                    session_id,
                    attachment_id,
                    epoch,
                    sequence: kr_protocol::ids::InputSequence::new(sequence),
                    bytes: kr_protocol::scalars::Bytes::new(bytes),
                };
                let Ok(params) = kr_protocol::envelope::ParamsValue::from_typed(&params) else {
                    return AttachOutcome::DeliveryUncertain(
                        "the input could not be encoded".to_owned(),
                    );
                };
                let message = ControlMessage::Request(kr_protocol::envelope::Request {
                    request_id,
                    method: Method::InputWrite.into(),
                    method_version: kr_protocol::method::MethodVersion::V1,
                    params,
                });
                if client.writer().write_message(&message).await.is_err() {
                    // The bytes were handed to a connection that has gone. Whether they arrived
                    // cannot be established from here, and the exit code says so.
                    return AttachOutcome::DeliveryUncertain(
                        "the connection ended while input was being sent".to_owned(),
                    );
                }
                outstanding.insert(request_id, sequence);
                sequence += 1;
            }
        }
    }
}

/// How this platform reports that the terminal changed size.
///
/// Unix delivers a signal. Windows delivers a console input record instead, which arrives on the
/// input stream this loop is already reading, so there is nothing separate to wait on there.
#[cfg(unix)]
pub type WindowChanges = tokio::signal::unix::Signal;

/// How this platform reports that the terminal changed size.
#[cfg(not(unix))]
pub type WindowChanges = std::convert::Infallible;

/// Returns the stream of window-size changes, where the platform has one.
#[cfg(unix)]
fn window_changes() -> Option<WindowChanges> {
    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change()).ok()
}

/// Returns the stream of window-size changes, where the platform has one.
#[cfg(not(unix))]
const fn window_changes() -> Option<WindowChanges> {
    None
}

/// Waits for the next window-size change, or for ever when the platform reports none.
#[cfg(unix)]
async fn wait_for_resize(resized: &mut Option<&mut WindowChanges>) {
    match resized {
        Some(signal) => {
            signal.recv().await;
        }
        None => std::future::pending().await,
    }
}

/// Waits for the next window-size change, or for ever when the platform reports none.
#[cfg(not(unix))]
async fn wait_for_resize(_resized: &mut Option<&mut WindowChanges>) {
    std::future::pending().await
}
