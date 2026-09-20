//! Opening a bridge: what may cross it, what is refused before a process starts, and the frames
//! the invoking side carries once one is open.
//!
//! This is the gate section 3 puts on the near side. The process bridges serve locally
//! authenticated command-line invocations only, and **a Windows controller must not route a
//! network actor through one and relabel it a Linux local owner**. A remote client reaches the
//! destination environment through that environment's own paired endpoint, which it has, because
//! each Windows, WSL and enrolled container installation is an independent environment authority.
//!
//! The refusal happens here, before an argument vector is built and before a process exists. The
//! helper on the far side refuses the same handshake again, and neither check makes the other
//! redundant: this one is what a correct invoker does, and that one is what a destination
//! environment can enforce for itself.
//!
//! **Ingress is carried, not recomputed.** The opening frame states the ingress the request
//! originally arrived on. It is always [`ActorIngress::LocalIpc`] once this gate has passed, which
//! is exactly the point: the record on the far side then names where the request entered rather
//! than the local IPC hop the helper made, and there is no arrangement of hops that turns a
//! network device into a local owner.
//!
//! **The environment that answers is the one that was enrolled.** An opening carries the identity
//! the record names, and the acknowledgement is compared against it before a single request
//! crosses. A distribution reinstalled under the same name, or a container recreated under a name
//! that was reused, answers with a different identity and is refused rather than inheriting the
//! enrolment.
//!
//! **Every length is bounded before it is allocated.** Section 9 sets the control-frame maximum
//! and requires large messages to be rejected before allocation. Both directions here take that
//! bound from the frame codec, so a destination cannot make this host reserve memory by declaring
//! a large frame, and an oversized frame ends the bridge rather than being truncated.

use kr_protocol::actor::{ActorEnvelope, ActorIngress};
use kr_protocol::envelope::{ControlFrame, MutationRequest, Request, Response};
use kr_protocol::error::ProtocolError;
use kr_protocol::frame::{FRAME_LENGTH_PREFIX_LEN, FrameCodec, StreamKind};
use kr_protocol::hello::ProtocolVersion;
use kr_protocol::identity::EnvironmentEnrolment;
use kr_protocol::identity::{BridgeFrame, BridgeHello, BridgeHelloAck, BridgeTarget};
use kr_protocol::ids::{BuildId, EnvironmentId, RequestId};
use kr_protocol::local::LocalRole;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::bridge::launch::{self, BridgeCommand, LaunchError};

/// Why this host will not open a bridge for a request, or will not go on using one.
///
/// Each variant is one cause, and each says what happened. A person reading a connection
/// diagnostic has to be able to tell a helper that never started from one that answered as the
/// wrong environment, so no two causes share a message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// The request did not arrive on a locally authenticated ingress.
    ///
    /// It carries the ingress it did arrive on, so a receipt and a log can say what was refused.
    NetworkActor {
        /// Where the request entered this host.
        ingress: ActorIngress,
    },
    /// The request has already crossed a bridge. A federated proxy is outside version 1.
    AlreadyBridged,
    /// The enrolment is not reached by a process bridge, or is incomplete.
    Launch(LaunchError),
    /// The helper could not be started at all.
    NotStarted {
        /// The program this host tried to run.
        program: String,
        /// What the operating system said.
        detail: String,
    },
    /// A stream to or from the helper failed part way through.
    Stream {
        /// What the stream said.
        detail: String,
    },
    /// The helper wrote something this invoker cannot read: a frame past the bound, or one that is
    /// not a canonical bridge frame.
    Unreadable {
        /// What the codec said.
        detail: String,
    },
    /// The helper's first frame was not an acknowledgement.
    NotAnAcknowledgement,
    /// The destination speaks a protocol major this host does not.
    ProtocolMajor {
        /// The major the destination answered with.
        destination: u16,
        /// The major this host speaks.
        invoker: u16,
    },
    /// The destination answered in a role the opening did not ask for.
    WrongRole {
        /// The role the opening asked for.
        expected: LocalRole,
        /// The role that answered.
        answered: LocalRole,
    },
    /// The environment that answered is not the one the enrolment names.
    IdentityMismatch {
        /// The identity the enrolment records.
        enrolled: EnvironmentId,
        /// The identity that answered.
        answered: EnvironmentId,
    },
    /// The destination refused the bridge, in its own words.
    Destination(ProtocolError),
    /// The targeted session has closed.
    SessionClosed,
}

impl core::fmt::Display for Refusal {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NetworkActor { ingress } => write!(
                formatter,
                "a process bridge carries locally authenticated invocations only, and this request \
                 arrived as {}; reach that environment through its own paired endpoint",
                ingress.as_str()
            ),
            Self::AlreadyBridged => {
                formatter.write_str("a request crosses at most one process bridge")
            }
            Self::Launch(error) => write!(formatter, "{error}"),
            Self::NotStarted { program, detail } => {
                write!(formatter, "{program} could not be started: {detail}")
            }
            Self::Stream { detail } => write!(formatter, "the bridge stream failed: {detail}"),
            Self::Unreadable { detail } => write!(
                formatter,
                "the destination wrote a frame this host cannot read: {detail}"
            ),
            Self::NotAnAcknowledgement => formatter
                .write_str("the destination answered the opening frame with something else"),
            Self::ProtocolMajor {
                destination,
                invoker,
            } => write!(
                formatter,
                "the destination speaks protocol major {destination} and this host speaks {invoker}"
            ),
            Self::WrongRole { expected, answered } => write!(
                formatter,
                "the opening asked for the {} and the {} answered",
                expected.as_str(),
                answered.as_str()
            ),
            Self::IdentityMismatch { enrolled, answered } => write!(
                formatter,
                "the enrolment names environment {enrolled} and {answered} answered; enrol the \
                 environment that is installed there rather than reusing this record"
            ),
            Self::Destination(error) => write!(
                formatter,
                "the destination refused the bridge: {}",
                error.message
            ),
            Self::SessionClosed => formatter.write_str("that session is closed"),
        }
    }
}

impl std::error::Error for Refusal {}

impl From<Refusal> for crate::error::ControllerError {
    fn from(refusal: Refusal) -> Self {
        match refusal {
            // The admission refusals are permission failures, and so is a destination that refused
            // the handshake: in each case the answer is that this request may not cross.
            Refusal::NetworkActor { .. }
            | Refusal::AlreadyBridged
            | Refusal::Destination(_)
            | Refusal::IdentityMismatch { .. } => Self::PermissionDenied {
                detail: refusal.to_string(),
            },
            Refusal::SessionClosed => Self::SessionClosed {
                session: "the bridged session".to_owned(),
            },
            // An incomplete enrolment is the caller's own record being wrong.
            Refusal::Launch(_) => Self::InvalidArgument(refusal.to_string()),
            // The rest are this host failing to reach a destination it was told to reach.
            Refusal::NotStarted { .. }
            | Refusal::Stream { .. }
            | Refusal::Unreadable { .. }
            | Refusal::NotAnAcknowledgement
            | Refusal::ProtocolMajor { .. }
            | Refusal::WrongRole { .. } => Self::supervision(refusal.to_string()),
        }
    }
}

/// One bridge this host is ready to open.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Opening {
    /// The command the helper is started with.
    pub command: BridgeCommand,
    /// The identity the enrolment names. The destination has to answer with it.
    pub environment_id: EnvironmentId,
    /// The opening frame written to its standard input.
    pub hello: BridgeHello,
}

/// A bridge that is open: the helper is running and has acknowledged the opening frame.
#[derive(Debug)]
pub struct Invocation {
    /// The running helper.
    child: tokio::process::Child,
    /// The helper's standard input, which carries frames to the destination.
    stdin: tokio::process::ChildStdin,
    /// The helper's standard output, which carries the destination's answers back.
    stdout: tokio::process::ChildStdout,
    /// What the destination acknowledged: its identity, its user, its role and its bounds.
    acknowledgement: BridgeHelloAck,
}

impl Opening {
    /// Starts the helper, exchanges the opening frames and checks what answered.
    ///
    /// The acknowledgement is accepted only when the destination speaks this protocol major,
    /// answers in the role the opening asked for, and names the environment the enrolment records.
    /// The helper is ended when any of those fails, so a refused opening leaves no process behind.
    ///
    /// # Errors
    ///
    /// Returns the [`Refusal`] naming what stopped the bridge: the helper not starting, a stream
    /// failing, a frame this host cannot read, a protocol major, a role, an identity that is not
    /// the enrolled one, or the destination's own refusal, including a closed session.
    pub async fn launch(self) -> Result<Invocation, Refusal> {
        let (child, stdin, stdout, acknowledgement) =
            start_and_acknowledge(&self.command, &self.hello).await?;
        // The enrolment is a record of one installation. An environment that answers with another
        // identity is another installation, whatever name it was reached by: a distribution
        // registered again under the name it had, or a container recreated under a reused one.
        if acknowledgement.environment_id != self.environment_id {
            return Err(Refusal::IdentityMismatch {
                enrolled: self.environment_id,
                answered: acknowledgement.environment_id,
            });
        }
        Ok(Invocation {
            child,
            stdin,
            stdout,
            acknowledgement,
        })
    }
}

/// Asks a destination which environment it is, before there is a record naming it.
///
/// Enrolment is the one caller: the identity is exactly what it is learning, so there is nothing
/// yet to compare the acknowledgement against. Everything else is still checked, and the helper is
/// ended as soon as it has answered, because discovery carries no request.
///
/// # Errors
///
/// As [`Opening::launch`], less the identity check.
pub async fn discover(
    command: &BridgeCommand,
    hello: &BridgeHello,
) -> Result<BridgeHelloAck, Refusal> {
    let (mut child, stdin, stdout, acknowledgement) = start_and_acknowledge(command, hello).await?;
    drop(stdin);
    drop(stdout);
    // The child is killed on drop, and waiting for it here keeps the process from being reaped by
    // the runtime after this function has already returned.
    let _ = child.kill().await;
    Ok(acknowledgement)
}

/// Starts the helper, exchanges the opening frames, and checks the version and the role.
async fn start_and_acknowledge(
    command: &BridgeCommand,
    hello: &BridgeHello,
) -> Result<
    (
        tokio::process::Child,
        tokio::process::ChildStdin,
        tokio::process::ChildStdout,
        BridgeHelloAck,
    ),
    Refusal,
> {
    let mut child = tokio::process::Command::new(&command.program)
        .args(&command.arguments)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        // Section 3 keeps standard error diagnostic. It belongs to whoever ran the command.
        .stderr(std::process::Stdio::inherit())
        // A handshake this host refuses ends the helper with it rather than leaving a distribution
        // or a container process running behind a failed connection.
        .kill_on_drop(true)
        .spawn()
        .map_err(|error| Refusal::NotStarted {
            program: command.program.clone(),
            detail: error.to_string(),
        })?;

    let mut stdin = child.stdin.take().ok_or_else(|| Refusal::NotStarted {
        program: command.program.clone(),
        detail: "its standard input is not a pipe".to_owned(),
    })?;
    let mut stdout = child.stdout.take().ok_or_else(|| Refusal::NotStarted {
        program: command.program.clone(),
        detail: "its standard output is not a pipe".to_owned(),
    })?;

    write_frame(&mut stdin, &BridgeFrame::Hello(Box::new(hello.clone()))).await?;
    let acknowledgement = match read_frame(&mut stdout).await? {
        BridgeFrame::HelloAck(acknowledgement) => *acknowledgement,
        BridgeFrame::Refused(error) => {
            return Err(
                if error.code == kr_protocol::error::ErrorCode::SessionClosed {
                    Refusal::SessionClosed
                } else {
                    Refusal::Destination(error)
                },
            );
        }
        _ => return Err(Refusal::NotAnAcknowledgement),
    };

    let invoker = hello.protocol_version.major;
    if acknowledgement.protocol_version.major != invoker {
        return Err(Refusal::ProtocolMajor {
            destination: acknowledgement.protocol_version.major,
            invoker,
        });
    }
    let expected = match hello.target {
        BridgeTarget::Controller => LocalRole::Controller,
        BridgeTarget::Session { .. } => LocalRole::Worker,
    };
    if acknowledgement.role != expected {
        return Err(Refusal::WrongRole {
            expected,
            answered: acknowledgement.role,
        });
    }
    Ok((child, stdin, stdout, acknowledgement))
}

impl Invocation {
    /// What the destination acknowledged.
    #[must_use]
    pub const fn acknowledgement(&self) -> &BridgeHelloAck {
        &self.acknowledgement
    }

    /// Carries one request to the destination and returns the answer it gave.
    ///
    /// # Errors
    ///
    /// Returns the [`Refusal`] naming the stream, frame or destination failure. A method that the
    /// destination answered with an error is an [`Response`] carrying that error, not a refusal:
    /// the bridge carried it unchanged.
    pub async fn request(&mut self, request: Request) -> Result<Response, Refusal> {
        let request_id = request.request_id;
        self.exchange(
            BridgeFrame::Control(Box::new(ControlFrame::Request(request))),
            request_id,
        )
        .await
    }

    /// Carries one mutation to the destination and returns the answer it gave.
    ///
    /// # Errors
    ///
    /// As [`Self::request`].
    pub async fn mutate(&mut self, mutation: MutationRequest) -> Result<Response, Refusal> {
        let request_id = mutation.request_id;
        self.exchange(
            BridgeFrame::Control(Box::new(ControlFrame::Mutation(Box::new(mutation)))),
            request_id,
        )
        .await
    }

    /// Ends the bridge: the helper's input is closed and the helper is waited for.
    ///
    /// # Errors
    ///
    /// Returns [`Refusal::Stream`] when the helper could not be waited for.
    pub async fn close(mut self) -> Result<(), Refusal> {
        drop(self.stdin);
        self.child
            .wait()
            .await
            .map(|_status| ())
            .map_err(|error| Refusal::Stream {
                detail: error.to_string(),
            })
    }

    /// Writes one frame and reads until the answer to `request_id` arrives.
    ///
    /// Anything else the destination sends in the meantime — an event, a keepalive — is carried
    /// past rather than mistaken for the answer.
    async fn exchange(
        &mut self,
        frame: BridgeFrame,
        request_id: RequestId,
    ) -> Result<Response, Refusal> {
        write_frame(&mut self.stdin, &frame).await?;
        loop {
            match read_frame(&mut self.stdout).await? {
                BridgeFrame::Control(carried) => match *carried {
                    ControlFrame::Response(response) if response.request_id == request_id => {
                        return Ok(response);
                    }
                    _ => continue,
                },
                BridgeFrame::Refused(error) => {
                    return Err(
                        if error.code == kr_protocol::error::ErrorCode::SessionClosed {
                            Refusal::SessionClosed
                        } else {
                            Refusal::Destination(error)
                        },
                    );
                }
                _ => return Err(Refusal::NotAnAcknowledgement),
            }
        }
    }
}

/// Writes one bridge frame and flushes it.
///
/// The codec refuses to encode a frame past the control bound, so an oversized frame never reaches
/// the stream.
async fn write_frame<W: AsyncWrite + Unpin>(
    sink: &mut W,
    frame: &BridgeFrame,
) -> Result<(), Refusal> {
    let bytes = FrameCodec::new(StreamKind::Control)
        .encode_message(frame)
        .map_err(|error| Refusal::Unreadable {
            detail: error.to_string(),
        })?;
    sink.write_all(&bytes)
        .await
        .map_err(|error| Refusal::Stream {
            detail: error.to_string(),
        })?;
    sink.flush().await.map_err(|error| Refusal::Stream {
        detail: error.to_string(),
    })
}

/// Reads one bridge frame.
///
/// The declared length is checked against section 9's control-frame bound *before* a payload
/// buffer exists, so a destination that declares a large frame is refused rather than served with
/// the memory it asked for.
async fn read_frame<R: AsyncRead + Unpin>(source: &mut R) -> Result<BridgeFrame, Refusal> {
    let mut prefix = [0_u8; FRAME_LENGTH_PREFIX_LEN];
    source
        .read_exact(&mut prefix)
        .await
        .map_err(|error| Refusal::Stream {
            detail: error.to_string(),
        })?;
    let declared = FrameCodec::new(StreamKind::Control)
        .decode_length(prefix)
        .map_err(|error| Refusal::Unreadable {
            detail: error.to_string(),
        })?;
    let mut payload = vec![0_u8; declared];
    source
        .read_exact(&mut payload)
        .await
        .map_err(|error| Refusal::Stream {
            detail: error.to_string(),
        })?;
    kr_cbor::from_canonical_slice(&payload, &StreamKind::Control.cbor_limits()).map_err(|error| {
        Refusal::Unreadable {
            detail: error.to_string(),
        }
    })
}

/// Decides whether a request may cross a bridge, and builds what opens it.
///
/// `actor` is the envelope this host constructed for the request. Nothing the caller supplied is
/// read here: the ingress comes from that envelope, which the host built from the connection.
///
/// # Errors
///
/// Returns [`Refusal::NetworkActor`] for a request that did not arrive on a locally authenticated
/// ingress, [`Refusal::AlreadyBridged`] for one that has already crossed a bridge, and
/// [`Refusal::Launch`] when the enrolment names no process bridge or is incomplete.
pub fn open(
    actor: &ActorEnvelope,
    already_bridged: bool,
    enrolment: &EnvironmentEnrolment,
    origin_environment_id: EnvironmentId,
    build_id: BuildId,
    target: BridgeTarget,
) -> Result<Opening, Refusal> {
    if !actor.ingress.may_cross_process_bridge() {
        return Err(Refusal::NetworkActor {
            ingress: actor.ingress,
        });
    }
    if already_bridged {
        return Err(Refusal::AlreadyBridged);
    }
    let command = launch::command(enrolment).map_err(Refusal::Launch)?;
    Ok(Opening {
        command,
        environment_id: enrolment.environment_id,
        hello: BridgeHello {
            protocol_version: kr_protocol::hello::PROTOCOL_VERSION,
            build_id,
            origin_environment_id,
            // Carried, not recomputed. This is where the request entered this host.
            origin_ingress: actor.ingress,
            already_bridged: false,
            target,
        },
    })
}

/// The protocol version this host opens bridges with.
#[must_use]
pub const fn invoker_version() -> ProtocolVersion {
    kr_protocol::hello::PROTOCOL_VERSION
}

#[cfg(test)]
mod tests {
    use super::*;
    use kr_protocol::error::ErrorCode;
    use kr_protocol::frame::FrameError;
    use kr_protocol::identity::EnvironmentAccess;
    use kr_protocol::ids::{ActorId, ConnectionId, ControllerGeneration, DeviceId};
    use kr_protocol::scalars::{Nullable, TimestampMs, Uuid};

    fn enrolment() -> EnvironmentEnrolment {
        EnvironmentEnrolment {
            environment_id: EnvironmentId::new(Uuid::from_bytes([2; 16])),
            access: EnvironmentAccess::WslDistribution,
            label: "ubuntu".to_owned(),
            target: "Ubuntu-24.04".to_owned(),
            os_user: "kala".to_owned(),
            helper_path: "/usr/local/bin/kr".to_owned(),
            clipboard_destination: Nullable::null(),
            approved_at_ms: TimestampMs::new(0),
        }
    }

    fn actor(ingress: ActorIngress) -> ActorEnvelope {
        ActorEnvelope {
            actor_id: ActorId::new("device:1").expect("a principal"),
            ingress,
            device_id: if ingress == ActorIngress::PairedDevice {
                Nullable::some(DeviceId::new(Uuid::from_bytes([5; 16])))
            } else {
                Nullable::null()
            },
            grant_id: Nullable::null(),
            grant_revision: Nullable::null(),
            controller_generation: ControllerGeneration::new(3),
            connection_id: ConnectionId::new(Uuid::from_bytes([6; 16])),
        }
    }

    fn here() -> EnvironmentId {
        EnvironmentId::new(Uuid::from_bytes([1; 16]))
    }

    fn build() -> BuildId {
        BuildId::new("kr/0.1.0").expect("a build")
    }

    #[test]
    fn a_local_invocation_opens_a_bridge_that_carries_its_own_ingress() {
        let opening = open(
            &actor(ActorIngress::LocalIpc),
            false,
            &enrolment(),
            here(),
            build(),
            BridgeTarget::Controller,
        )
        .expect("opened");
        assert_eq!(opening.hello.origin_ingress, ActorIngress::LocalIpc);
        assert_eq!(opening.hello.origin_environment_id, here());
        assert!(!opening.hello.already_bridged);
        assert_eq!(opening.command.program, "wsl.exe");
        // The identity the destination will have to answer with comes from the record, never from
        // the caller.
        assert_eq!(opening.environment_id, enrolment().environment_id);
    }

    #[test]
    fn a_network_actor_never_reaches_a_bridge() {
        for ingress in ActorIngress::ALL
            .iter()
            .copied()
            .filter(|ingress| *ingress != ActorIngress::LocalIpc)
        {
            let refusal = open(
                &actor(ingress),
                false,
                &enrolment(),
                here(),
                build(),
                BridgeTarget::Controller,
            )
            .expect_err("a refusal");
            assert_eq!(refusal, Refusal::NetworkActor { ingress });
            assert!(
                refusal.to_string().contains(ingress.as_str()),
                "the refusal names what arrived: {refusal}"
            );
        }
    }

    #[test]
    fn a_paired_device_is_refused_before_an_argument_vector_exists() {
        // The refusal comes before the enrolment is even read, so a device cannot reach a bridge
        // by naming a record this host would otherwise have started.
        let mut unusable = enrolment();
        unusable.helper_path = String::new();
        let refusal = open(
            &actor(ActorIngress::PairedDevice),
            false,
            &unusable,
            here(),
            build(),
            BridgeTarget::Controller,
        )
        .expect_err("a refusal");
        assert_eq!(
            refusal,
            Refusal::NetworkActor {
                ingress: ActorIngress::PairedDevice
            }
        );
    }

    #[test]
    fn a_request_that_already_crossed_a_bridge_is_not_chained() {
        let refusal = open(
            &actor(ActorIngress::LocalIpc),
            true,
            &enrolment(),
            here(),
            build(),
            BridgeTarget::Controller,
        )
        .expect_err("a refusal");
        assert_eq!(refusal, Refusal::AlreadyBridged);
    }

    #[test]
    fn an_ssh_environment_is_refused_as_a_bridge_rather_than_started() {
        let mut ssh = enrolment();
        ssh.access = EnvironmentAccess::SshHost;
        let refusal = open(
            &actor(ActorIngress::LocalIpc),
            false,
            &ssh,
            here(),
            build(),
            BridgeTarget::Controller,
        )
        .expect_err("a refusal");
        assert_eq!(
            refusal,
            Refusal::Launch(LaunchError::NotAProcessBridge {
                access: EnvironmentAccess::SshHost
            })
        );
    }

    #[tokio::test]
    async fn a_declared_length_past_the_bound_is_refused_before_a_buffer_exists() {
        // One byte past the control-frame payload maximum, and nothing behind it. A reader that
        // allocated first would reserve the memory the destination asked for and then wait for
        // bytes that are not coming.
        for declared in [
            u32::try_from(StreamKind::Control.max_payload_len() + 1).expect("fits"),
            u32::MAX,
        ] {
            let stream = declared.to_be_bytes().to_vec();
            let refusal = read_frame(&mut stream.as_slice())
                .await
                .expect_err("a refusal");
            assert!(
                matches!(&refusal, Refusal::Unreadable { detail }
                    if detail.contains(&StreamKind::Control.max_payload_len().to_string())),
                "{refusal}"
            );
        }
    }

    #[tokio::test]
    async fn a_frame_at_the_bound_is_read_rather_than_refused() {
        // The bound itself is allowed: the refusal is for what exceeds it, not for what reaches it.
        let codec = FrameCodec::new(StreamKind::Control);
        let length = codec
            .decode_length(
                u32::try_from(StreamKind::Control.max_payload_len())
                    .expect("fits")
                    .to_be_bytes(),
            )
            .expect("the maximum is within the bound");
        assert_eq!(length, StreamKind::Control.max_payload_len());
    }

    #[tokio::test]
    async fn a_stream_that_ends_inside_a_frame_is_a_stream_failure_rather_than_a_short_frame() {
        let mut stream = 8_u32.to_be_bytes().to_vec();
        stream.extend_from_slice(&[1, 2, 3]);
        let refusal = read_frame(&mut stream.as_slice())
            .await
            .expect_err("a refusal");
        assert!(matches!(refusal, Refusal::Stream { .. }), "{refusal}");
    }

    #[tokio::test]
    async fn a_zero_length_frame_is_refused() {
        let stream = 0_u32.to_be_bytes().to_vec();
        let refusal = read_frame(&mut stream.as_slice())
            .await
            .expect_err("a refusal");
        assert!(
            matches!(&refusal, Refusal::Unreadable { detail }
                if detail == &FrameError::EmptyPayload.to_string()),
            "{refusal}"
        );
    }

    #[tokio::test]
    async fn a_frame_written_here_is_read_back_whole() {
        let original = BridgeFrame::Refused(ProtocolError::new(ErrorCode::PermissionDenied, "no"));
        let mut buffer: Vec<u8> = Vec::new();
        write_frame(&mut buffer, &original).await.expect("written");
        let read = read_frame(&mut buffer.as_slice()).await.expect("read back");
        assert_eq!(read, original);
    }

    #[test]
    fn every_failure_class_says_something_different() {
        // A diagnostic that named two causes the same way would send whoever reads it to the wrong
        // place. Section 18 asks for connection diagnostics; this is what makes them worth reading.
        let refusals = [
            Refusal::NetworkActor {
                ingress: ActorIngress::PairedDevice,
            },
            Refusal::AlreadyBridged,
            Refusal::Launch(LaunchError::NotAProcessBridge {
                access: EnvironmentAccess::SshHost,
            }),
            Refusal::NotStarted {
                program: "wsl.exe".to_owned(),
                detail: "no such file".to_owned(),
            },
            Refusal::Stream {
                detail: "broken pipe".to_owned(),
            },
            Refusal::Unreadable {
                detail: "not canonical".to_owned(),
            },
            Refusal::NotAnAcknowledgement,
            Refusal::ProtocolMajor {
                destination: 9,
                invoker: invoker_version().major,
            },
            Refusal::WrongRole {
                expected: LocalRole::Controller,
                answered: LocalRole::Worker,
            },
            Refusal::IdentityMismatch {
                enrolled: here(),
                answered: EnvironmentId::new(Uuid::from_bytes([9; 16])),
            },
            Refusal::Destination(ProtocolError::new(
                ErrorCode::PermissionDenied,
                "the destination said no",
            )),
            Refusal::SessionClosed,
        ];
        let mut messages: Vec<String> = refusals.iter().map(ToString::to_string).collect();
        messages.sort();
        let count = messages.len();
        messages.dedup();
        assert_eq!(messages.len(), count, "two refusals read the same");
    }

    #[test]
    fn a_failure_to_reach_a_destination_is_not_reported_as_a_permission_refusal() {
        // A helper that did not start is this host's own failure. Reporting it as a permission
        // refusal would send a person looking for a grant that was never the problem.
        let unreachable: crate::error::ControllerError = Refusal::NotStarted {
            program: "wsl.exe".to_owned(),
            detail: "no such file".to_owned(),
        }
        .into();
        assert!(
            matches!(
                unreachable,
                crate::error::ControllerError::Supervision { .. }
            ),
            "{unreachable:?}"
        );
        let mismatched: crate::error::ControllerError = Refusal::IdentityMismatch {
            enrolled: here(),
            answered: EnvironmentId::new(Uuid::from_bytes([9; 16])),
        }
        .into();
        assert!(
            matches!(
                mismatched,
                crate::error::ControllerError::PermissionDenied { .. }
            ),
            "{mismatched:?}"
        );
        let closed: crate::error::ControllerError = Refusal::SessionClosed.into();
        assert!(
            matches!(closed, crate::error::ControllerError::SessionClosed { .. }),
            "{closed:?}"
        );
    }
}
