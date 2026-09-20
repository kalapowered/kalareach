//! `kr bridge --stdio`: the destination half of a local process bridge.
//!
//! The helper is started inside the environment it serves, by `wsl.exe --exec` for a WSL
//! distribution or by the container runtime's exec for an enrolled container. It reads the
//! invoker's opening frame, decides whether this bridge may carry the request at all, connects to
//! its own environment's control daemon or session worker through local IPC, and then relays
//! protocol frames in both directions until either side goes away.
//!
//! Three rules decide the admission, and each is refused by name:
//!
//! * **The original ingress must be a locally authenticated one.** Section 3 restricts the
//!   process bridges to locally authenticated command-line invocations and forbids relabelling a
//!   network actor as a local owner on the far side. A remote client reaches this environment
//!   through that environment's own paired endpoint instead.
//! * **A request crosses at most one bridge.** A federated proxy is outside version 1, so a
//!   handshake that says the request has already been bridged is refused rather than chained, and
//!   so is a carried request that would open a bridge of its own. The destination cannot enforce
//!   that second rule for itself: what arrives over this helper's local connection looks like any
//!   other local request, and nothing in it says a bridge was crossed to get there.
//! * **The protocol major must match**, because the frames are carried unchanged.
//!
//! What the helper never does is decide authority. The destination authenticates it by its own
//! operating-system credentials, exactly as it authenticates any other local caller, and the
//! actor envelope the destination builds records that local ingress. Nothing on standard input
//! can widen it, and no environment variable is read for it.

use std::io::{Read, Write};

use kr_ipc::paths::HostPaths;
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::frame::StreamKind;
use kr_protocol::hello::PROTOCOL_VERSION;
use kr_protocol::identity::{BridgeFrame, BridgeHello, BridgeHelloAck, BridgeTarget};
use kr_protocol::scalars::U64;

use crate::bridge::pipe::{self, PipeError};
use crate::error::{CliError, Result};
use crate::resolve;

/// Why a bridge handshake was refused.
///
/// Each becomes one `BridgeFrame::Refused` on standard output and one diagnostic line on standard
/// error. The two carry the same reason, so a log and a caller never disagree about what happened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The first frame was not an opening frame.
    NotAHandshake,
    /// The invoker speaks a protocol major this helper does not.
    ProtocolMajor,
    /// The request did not originally arrive on a locally authenticated ingress.
    RemoteOrigin,
    /// The request has already crossed a bridge.
    AlreadyBridged,
    /// The session target has closed.
    SessionClosed,
}

impl Refusal {
    /// Returns the message sent to the invoker and written to standard error.
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::NotAHandshake => "a bridge begins with its opening frame",
            Self::ProtocolMajor => "this helper does not speak that protocol major",
            Self::RemoteOrigin => {
                "a process bridge carries locally authenticated invocations only; reach this \
                 environment through its own paired endpoint"
            }
            Self::AlreadyBridged => "a request crosses at most one process bridge",
            Self::SessionClosed => "that session is closed",
        }
    }

    /// Returns the protocol error this refusal is sent as.
    #[must_use]
    pub fn as_error(self) -> ProtocolError {
        let code = match self {
            // A shape this helper cannot read and a version it does not implement are schema
            // failures. The two admission rules are authority failures, and both say the same
            // thing, because the difference between them tells a caller nothing it may act on.
            Self::NotAHandshake | Self::ProtocolMajor => ErrorCode::UnsupportedSchema,
            Self::RemoteOrigin | Self::AlreadyBridged => ErrorCode::PermissionDenied,
            Self::SessionClosed => ErrorCode::SessionClosed,
        };
        ProtocolError::new(code, self.message())
    }
}

/// Decides whether this bridge may carry what the opening frame describes.
///
/// # Errors
///
/// Returns the [`Refusal`] to send back, without connecting to anything.
pub fn admit(hello: &BridgeHello) -> std::result::Result<(), Refusal> {
    if hello.protocol_version.major != PROTOCOL_VERSION.major {
        return Err(Refusal::ProtocolMajor);
    }
    if !hello.origin_ingress.may_cross_process_bridge() {
        return Err(Refusal::RemoteOrigin);
    }
    if hello.already_bridged {
        return Err(Refusal::AlreadyBridged);
    }
    Ok(())
}

/// Runs the helper until either side closes.
///
/// `environment` names the environment to serve; without it this installation's own is served. The
/// streams are this process's standard input and output, and diagnostics go to standard error.
///
/// # Errors
///
/// Returns [`CliError::Refused`] when the handshake was refused, and a transport failure when a
/// stream or the local connection fails.
pub async fn run(environment: Option<&str>) -> Result<()> {
    serve(std::io::stdin(), &mut std::io::stdout(), environment).await
}

/// Runs one bridge over the streams given, which is what a test drives.
///
/// The reading side owns its stream because it is read on a thread of its own: standard input is a
/// blocking stream, and reading it on this task would stop the answers coming back from the
/// destination from being written.
///
/// # Errors
///
/// As [`run`].
pub async fn serve(
    input: impl Read + Send + 'static,
    output: &mut impl Write,
    environment: Option<&str>,
) -> Result<()> {
    // One frame at a time, so the reading thread stops at the frame after the one this bridge is
    // still carrying rather than drawing the whole of standard input into memory.
    let (to_relay, mut incoming) = std::sync::mpsc::sync_channel::<Vec<u8>>(1);
    let (wake, mut woken) = tokio::sync::mpsc::channel::<()>(2);
    let reading = std::thread::spawn(move || read_frames(input, &to_relay, &wake));

    let outcome = relay(&mut incoming, &mut woken, output, environment).await;
    // The reading thread holds the input stream. Drop both receivers first: a thread that is
    // handing a frame over waits on one of them, and dropping them unblocks it.
    drop(incoming);
    drop(woken);
    // If the reading thread has already finished (or finishes promptly on EOF), collect its status.
    // If standard input remains open, do not wait indefinitely: dropped receivers mean nothing more
    // will be relayed, and an indefinite join would leave this helper stuck in a blocking read.
    if !reading.is_finished() {
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    let stream = if reading.is_finished() {
        match reading.join() {
            Ok(Ok(()) | Err(PipeError::Closed)) => Ok(()),
            Ok(Err(error)) => Err(transport(&error)),
            Err(_) => Err(CliError::Other(
                "the bridge's reading thread stopped unexpectedly".to_owned(),
            )),
        }
    } else {
        Ok(())
    };
    match (outcome, stream) {
        (Err(error), _) => Err(error),
        (Ok(()), stream) => stream,
    }
}

/// Reads frames from the invoker until the stream ends or the relay stops.
///
/// The payload is handed on exactly as it arrived. A frame this side cannot read is a refusal, and
/// it ends the bridge rather than being skipped: skipping one would leave the destination reading
/// the middle of a message.
fn read_frames(
    mut input: impl Read,
    to_relay: &std::sync::mpsc::SyncSender<Vec<u8>>,
    wake: &tokio::sync::mpsc::Sender<()>,
) -> std::result::Result<(), PipeError> {
    loop {
        let payload = pipe::read_payload(&mut input)?;
        if to_relay.send(payload).is_err() {
            // The relay has stopped. Nothing else will read this stream.
            return Ok(());
        }
        // The relay waits on this rather than polling the blocking channel.
        if wake.blocking_send(()).is_err() {
            return Ok(());
        }
    }
}

/// Connects to the destination and carries frames both ways until either side goes away.
async fn relay(
    incoming: &mut std::sync::mpsc::Receiver<Vec<u8>>,
    woken: &mut tokio::sync::mpsc::Receiver<()>,
    output: &mut impl Write,
    environment: Option<&str>,
) -> Result<()> {
    let hello = match first_frame(incoming, woken).await {
        Some(payload) => match decode_hello(&payload) {
            Ok(hello) => hello,
            Err(refusal) => return refuse(output, refusal),
        },
        // Nothing arrived. An invoker that opens a bridge and closes it has done nothing wrong.
        None => return Ok(()),
    };
    if let Err(refusal) = admit(&hello) {
        return refuse(output, refusal);
    }

    let paths = HostPaths::discover()?;
    let known = resolve::select(&paths, environment)?;
    let (client, role) = match hello.target {
        BridgeTarget::Controller => (
            resolve::open_controller(&known.paths, crate::build_id()).await?,
            kr_protocol::local::LocalRole::Controller,
        ),
        BridgeTarget::Session { session_id } => {
            match resolve::find(
                &paths,
                &resolve::SessionSelector::Identifier(session_id),
                Some(known.environment_id),
            ) {
                Ok((_, descriptor)) => (
                    resolve::open_worker(&descriptor, crate::build_id()).await?,
                    kr_protocol::local::LocalRole::Worker,
                ),
                Err(CliError::UnknownSession(_)) => {
                    if is_destination_session_closed(&known.paths, session_id).await {
                        return refuse(output, Refusal::SessionClosed);
                    }
                    return Err(CliError::UnknownSession(session_id.to_string()));
                }
                Err(other) => return Err(other),
            }
        }
    };
    let (mut reader, mut writer, acknowledgement) = client.into_halves();

    // The acknowledgement carries the destination's own identity, never the invoker's. A caller
    // reading it learns which environment answered, which is the fact a grouped interface has to
    // present beside every action.
    pipe::write_frame(
        output,
        &BridgeFrame::HelloAck(Box::new(BridgeHelloAck {
            protocol_version: acknowledgement.selected_version,
            environment_id: acknowledgement.environment_id,
            os_user: os_user(),
            role,
            connection_id: acknowledgement.connection_id,
            boot_identity: acknowledgement.boot_identity.clone(),
            max_frame_len: U64::new(pipe::max_frame_len() as u64),
            action_window: acknowledgement.action_window,
        })),
    )
    .map_err(|error| transport(&error))?;

    loop {
        tokio::select! {
            arrival = woken.recv() => {
                if arrival.is_none() {
                    // The invoker went away, or its stream failed. Either way this bridge is over.
                    return Ok(());
                }
                let Ok(payload) = incoming.try_recv() else {
                    return Ok(());
                };
                let frame: BridgeFrame = decode_frame(&payload)?;
                match frame {
                    // Carried unchanged: the bytes are what a payload digest was taken over, and
                    // re-encoding them would risk changing what the caller signed for.
                    BridgeFrame::Control(carried) => {
                        // Except for one thing this side has to decide: a request crosses at most
                        // one bridge. The destination will serve what arrives here as an ordinary
                        // local request, so a method that opens a bridge of its own would chain one
                        // behind this helper's back. It is refused here, where the hop is known.
                        if let Some(method) = crosses_again(&carried) {
                            eprintln!("kr bridge: {} opens a bridge of its own", method.as_str());
                            return refuse(output, Refusal::AlreadyBridged);
                        }
                        writer.write_message(&*carried).await.map_err(CliError::Ipc)?;
                    }
                    // A second handshake, an acknowledgement or a refusal on this side of the
                    // bridge is a frame this role does not serve.
                    _ => return refuse(output, Refusal::NotAHandshake),
                }
            }
            answer = reader.read_payload() => match answer {
                Ok(payload) => pipe::write_carried_payload(output, &payload)
                    .map_err(|error| transport(&error))?,
                Err(kr_ipc::IpcError::PeerClosed) => return Ok(()),
                Err(error) => return Err(CliError::Ipc(error)),
            },
        }
    }
}

/// Waits for the invoker's first frame.
async fn first_frame(
    incoming: &mut std::sync::mpsc::Receiver<Vec<u8>>,
    woken: &mut tokio::sync::mpsc::Receiver<()>,
) -> Option<Vec<u8>> {
    woken.recv().await?;
    incoming.try_recv().ok()
}

/// Returns the method a carried frame would run that opens a bridge of its own.
///
/// Section 3 allows a request to cross at most one process bridge, and a federated proxy is outside
/// this version. The destination cannot enforce that for itself: what reaches it over this helper's
/// local connection looks like any other local request, and nothing in it says a bridge was already
/// crossed. So the rule is kept here, at the hop that knows.
fn crosses_again(
    carried: &kr_protocol::envelope::ControlFrame,
) -> Option<kr_protocol::method::Method> {
    use kr_protocol::envelope::ControlFrame;
    use kr_protocol::method::Method;

    let name = match carried {
        ControlFrame::Request(request) => request.method.as_str(),
        ControlFrame::Mutation(mutation) => mutation.method.as_str(),
        _ => return None,
    };
    let method = Method::from_wire(name)?;
    // A refresh of an enrolled environment opens a process bridge to it. Enrolling, forgetting and
    // listing change or read a record and open nothing.
    matches!(method, Method::EnvironmentRefresh).then_some(method)
}

/// Decodes one bridge frame from a payload the reader already bounded.
fn decode_frame(payload: &[u8]) -> Result<BridgeFrame> {
    kr_cbor::from_canonical_slice(payload, &StreamKind::Control.cbor_limits()).map_err(|error| {
        CliError::Other(format!(
            "the bridge stream carried a frame this helper cannot read: {error}"
        ))
    })
}

/// Decodes the opening frame, refusing anything else.
fn decode_hello(payload: &[u8]) -> std::result::Result<BridgeHello, Refusal> {
    match kr_cbor::from_canonical_slice(payload, &StreamKind::Control.cbor_limits()) {
        Ok(BridgeFrame::Hello(hello)) => Ok(*hello),
        Ok(_) | Err(_) => Err(Refusal::NotAHandshake),
    }
}

/// Turns a stream failure into the command's own error.
fn transport(error: &PipeError) -> CliError {
    CliError::Other(format!("the bridge stream failed: {error}"))
}

/// Writes a refusal and reports it.
fn refuse(output: &mut impl Write, refusal: Refusal) -> Result<()> {
    let error = refusal.as_error();
    // Standard error stays diagnostic: the refusal a caller acts on is the frame, and this line is
    // for whoever reads the log.
    eprintln!("kr bridge: {}", refusal.message());
    pipe::write_frame(output, &BridgeFrame::Refused(error.clone()))
        .map_err(|failure| transport(&failure))?;
    Err(CliError::Refused(error))
}

/// Asks the destination environment whether one session has closed.
///
/// Section 3: an old closed session still answers `SESSION_CLOSED`. The only thing that establishes
/// that is the destination's own retained closure record, which its control daemon answers with, so
/// this asks the daemon and reports what it said.
///
/// What is deliberately not evidence is a file on disk. A worker writes a journal for a session
/// while that session is live, so a journal that exists says a session ran here and nothing about
/// whether it ended. Treating one as closure would answer `SESSION_CLOSED` for a session that is
/// still running, which is worse than saying the session is not known: a daemon that cannot be
/// reached has not told this helper anything, and the caller is told exactly that.
async fn is_destination_session_closed(
    paths: &kr_ipc::paths::EnvironmentPaths,
    session_id: kr_protocol::ids::SessionId,
) -> bool {
    let Ok(mut client) = resolve::open_controller(paths, crate::build_id()).await else {
        return false;
    };
    let params = kr_protocol::session::SessionReadParams { session_id };
    match client
        .request(kr_protocol::method::Method::SessionRead, &params)
        .await
    {
        // The record the daemon holds carries the closure when there is one.
        Ok(Ok(payload)) => payload
            .to_typed::<kr_protocol::session::SessionReadResult>()
            .is_ok_and(|result| result.session.closure.is_present()),
        // Or the daemon answers the read with the closure itself.
        Ok(Err(error)) => error.code == ErrorCode::SessionClosed,
        Err(_) => false,
    }
}

/// The operating-system user this helper runs as, as the destination names it.
fn os_user() -> String {
    for variable in ["USER", "LOGNAME", "USERNAME"] {
        if let Ok(value) = std::env::var(variable)
            && !value.is_empty()
        {
            return value;
        }
    }
    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::actor::ActorIngress;
    use kr_protocol::ids::{BuildId, EnvironmentId};
    use kr_protocol::scalars::Uuid;

    fn hello(ingress: ActorIngress) -> BridgeHello {
        BridgeHello {
            protocol_version: PROTOCOL_VERSION,
            build_id: BuildId::new("kr/0.1.0").expect("a build"),
            origin_environment_id: EnvironmentId::new(Uuid::from_bytes([4; 16])),
            origin_ingress: ingress,
            already_bridged: false,
            target: BridgeTarget::Controller,
        }
    }

    #[test]
    fn a_locally_authenticated_invocation_is_admitted() {
        admit(&hello(ActorIngress::LocalIpc)).expect("admitted");
    }

    #[test]
    fn every_other_ingress_is_refused_before_anything_is_connected() {
        for ingress in ActorIngress::ALL
            .iter()
            .copied()
            .filter(|ingress| *ingress != ActorIngress::LocalIpc)
        {
            assert_eq!(
                admit(&hello(ingress)),
                Err(Refusal::RemoteOrigin),
                "{}",
                ingress.as_str()
            );
        }
        assert_eq!(
            Refusal::RemoteOrigin.as_error().code,
            ErrorCode::PermissionDenied
        );
    }

    #[test]
    fn a_second_hop_is_refused_rather_than_chained() {
        let mut chained = hello(ActorIngress::LocalIpc);
        chained.already_bridged = true;
        assert_eq!(admit(&chained), Err(Refusal::AlreadyBridged));
    }

    #[test]
    fn a_protocol_major_this_helper_does_not_speak_is_refused() {
        let mut other = hello(ActorIngress::LocalIpc);
        other.protocol_version = kr_protocol::hello::ProtocolVersion {
            major: PROTOCOL_VERSION.major + 1,
            minor: 0,
        };
        assert_eq!(admit(&other), Err(Refusal::ProtocolMajor));
        assert_eq!(
            Refusal::ProtocolMajor.as_error().code,
            ErrorCode::UnsupportedSchema
        );
    }
}
