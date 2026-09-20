//! Opening a bridge: what may cross it, and what is refused before a process starts.
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

use kr_protocol::actor::{ActorEnvelope, ActorIngress};
use kr_protocol::identity::{BridgeHello, BridgeTarget, EnvironmentEnrolment};
use kr_protocol::ids::{BuildId, EnvironmentId};

use crate::bridge::launch::{self, BridgeCommand, LaunchError};

/// Why this host will not open a bridge for a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
    /// The targeted session has closed.
    SessionClosed,
    /// The destination refused the bridge.
    DestinationRefused,
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
            Self::SessionClosed => formatter.write_str("that session is closed"),
            Self::DestinationRefused => {
                formatter.write_str("the destination helper refused the opening handshake")
            }
        }
    }
}

impl std::error::Error for Refusal {}

impl From<Refusal> for crate::error::ControllerError {
    fn from(refusal: Refusal) -> Self {
        match refusal {
            // Both admission refusals are permission failures, and both say the same thing to the
            // caller. An incomplete enrolment is the caller's own record being wrong.
            Refusal::NetworkActor { .. }
            | Refusal::AlreadyBridged
            | Refusal::DestinationRefused => Self::PermissionDenied {
                detail: refusal.to_string(),
            },
            Refusal::SessionClosed => Self::SessionClosed {
                session: "the bridged session".to_owned(),
            },
            Refusal::Launch(_) => Self::InvalidArgument(refusal.to_string()),
        }
    }
}

/// One bridge this host is ready to open.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Opening {
    /// The command the helper is started with.
    pub command: BridgeCommand,
    /// The opening frame written to its standard input.
    pub hello: BridgeHello,
}

/// An active bridge process that has exchanged handshakes and is ready for frames.
#[derive(Debug)]
pub struct Invocation {
    /// The running helper child process.
    pub child: tokio::process::Child,
    /// Standard input stream to the helper.
    pub stdin: tokio::process::ChildStdin,
    /// Standard output stream from the helper.
    pub stdout: tokio::process::ChildStdout,
    /// The destination's verified acknowledgement.
    pub acknowledgement: kr_protocol::identity::BridgeHelloAck,
}

impl Opening {
    /// Spawns the bridge helper command, writes the opening handshake, reads the response,
    /// and checks the destination acknowledgement.
    ///
    /// # Errors
    ///
    /// Returns [`Refusal`] if the helper refused the handshake or launch failed.
    pub async fn launch(self) -> Result<Invocation, Refusal> {
        let mut command = tokio::process::Command::new(&self.command.program);
        command
            .args(&self.command.arguments)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit());

        let mut child = command.spawn().map_err(|_error| {
            Refusal::Launch(LaunchError::Incomplete(
                kr_protocol::identity::EnrolmentError::EmptyTarget,
            ))
        })?;

        let mut stdin = child.stdin.take().ok_or(Refusal::AlreadyBridged)?;
        let mut stdout = child.stdout.take().ok_or(Refusal::AlreadyBridged)?;

        let hello_frame = kr_protocol::identity::BridgeFrame::Hello(Box::new(self.hello.clone()));
        let encoded = kr_protocol::frame::FrameCodec::new(kr_protocol::frame::StreamKind::Control)
            .encode_message(&hello_frame)
            .map_err(|_| Refusal::AlreadyBridged)?;
        tokio::io::AsyncWriteExt::write_all(&mut stdin, &encoded)
            .await
            .map_err(|_| Refusal::AlreadyBridged)?;
        tokio::io::AsyncWriteExt::flush(&mut stdin)
            .await
            .map_err(|_| Refusal::AlreadyBridged)?;

        let mut prefix = [0_u8; 4];
        tokio::io::AsyncReadExt::read_exact(&mut stdout, &mut prefix)
            .await
            .map_err(|_| Refusal::AlreadyBridged)?;
        let len = u32::from_be_bytes(prefix) as usize;
        if len > kr_protocol::frame::StreamKind::Control.max_payload_len() {
            return Err(Refusal::AlreadyBridged);
        }
        let mut payload = vec![0_u8; len];
        tokio::io::AsyncReadExt::read_exact(&mut stdout, &mut payload)
            .await
            .map_err(|_| Refusal::AlreadyBridged)?;

        let frame: kr_protocol::identity::BridgeFrame = kr_cbor::from_canonical_slice(
            &payload,
            &kr_protocol::frame::StreamKind::Control.cbor_limits(),
        )
        .map_err(|_| Refusal::AlreadyBridged)?;

        match frame {
            kr_protocol::identity::BridgeFrame::HelloAck(ack) => {
                if ack.protocol_version.major != self.hello.protocol_version.major {
                    return Err(Refusal::AlreadyBridged);
                }
                match self.hello.target {
                    BridgeTarget::Controller => {
                        if ack.role != kr_protocol::local::LocalRole::Controller {
                            return Err(Refusal::AlreadyBridged);
                        }
                    }
                    BridgeTarget::Session { .. } => {
                        if ack.role != kr_protocol::local::LocalRole::Worker {
                            return Err(Refusal::AlreadyBridged);
                        }
                    }
                }
                Ok(Invocation {
                    child,
                    stdin,
                    stdout,
                    acknowledgement: *ack,
                })
            }
            kr_protocol::identity::BridgeFrame::Refused(err) => {
                if err.code == kr_protocol::error::ErrorCode::SessionClosed {
                    Err(Refusal::SessionClosed)
                } else {
                    Err(Refusal::DestinationRefused)
                }
            }
            _ => Err(Refusal::AlreadyBridged),
        }
    }
}

impl Invocation {
    /// Writes a request over the bridge and awaits the response.
    ///
    /// # Errors
    ///
    /// Returns the host's error, or a transport failure.
    pub async fn request(
        &mut self,
        request: kr_protocol::envelope::Request,
    ) -> std::result::Result<kr_protocol::envelope::Response, kr_protocol::error::ProtocolError> {
        let request_id = request.request_id;
        let frame = kr_protocol::identity::BridgeFrame::Control(Box::new(
            kr_protocol::envelope::ControlFrame::Request(request),
        ));
        let encoded = kr_protocol::frame::FrameCodec::new(kr_protocol::frame::StreamKind::Control)
            .encode_message(&frame)
            .map_err(|error| {
                kr_protocol::error::ProtocolError::new(
                    kr_protocol::error::ErrorCode::UnsupportedSchema,
                    error.to_string(),
                )
            })?;
        tokio::io::AsyncWriteExt::write_all(&mut self.stdin, &encoded)
            .await
            .map_err(|error| {
                kr_protocol::error::ProtocolError::new(
                    kr_protocol::error::ErrorCode::ResourceUnavailable,
                    error.to_string(),
                )
            })?;
        tokio::io::AsyncWriteExt::flush(&mut self.stdin)
            .await
            .map_err(|error| {
                kr_protocol::error::ProtocolError::new(
                    kr_protocol::error::ErrorCode::ResourceUnavailable,
                    error.to_string(),
                )
            })?;

        loop {
            let mut prefix = [0_u8; 4];
            tokio::io::AsyncReadExt::read_exact(&mut self.stdout, &mut prefix)
                .await
                .map_err(|error| {
                    kr_protocol::error::ProtocolError::new(
                        kr_protocol::error::ErrorCode::ResourceUnavailable,
                        error.to_string(),
                    )
                })?;
            let len = u32::from_be_bytes(prefix) as usize;
            let mut payload = vec![0_u8; len];
            tokio::io::AsyncReadExt::read_exact(&mut self.stdout, &mut payload)
                .await
                .map_err(|error| {
                    kr_protocol::error::ProtocolError::new(
                        kr_protocol::error::ErrorCode::ResourceUnavailable,
                        error.to_string(),
                    )
                })?;
            let frame: kr_protocol::identity::BridgeFrame = kr_cbor::from_canonical_slice(
                &payload,
                &kr_protocol::frame::StreamKind::Control.cbor_limits(),
            )
            .map_err(|error| {
                kr_protocol::error::ProtocolError::new(
                    kr_protocol::error::ErrorCode::UnsupportedSchema,
                    error.to_string(),
                )
            })?;
            match frame {
                kr_protocol::identity::BridgeFrame::Control(carried) => match *carried {
                    kr_protocol::envelope::ControlFrame::Response(resp)
                        if resp.request_id == request_id =>
                    {
                        return Ok(resp);
                    }
                    _ => continue,
                },
                kr_protocol::identity::BridgeFrame::Refused(err) => return Err(err),
                _ => continue,
            }
        }
    }

    /// Writes a mutation over the bridge and awaits the response.
    ///
    /// # Errors
    ///
    /// Returns the host's error, or a transport failure.
    pub async fn mutate(
        &mut self,
        mutation: kr_protocol::envelope::MutationRequest,
    ) -> std::result::Result<kr_protocol::envelope::Response, kr_protocol::error::ProtocolError> {
        let request_id = mutation.request_id;
        let frame = kr_protocol::identity::BridgeFrame::Control(Box::new(
            kr_protocol::envelope::ControlFrame::Mutation(Box::new(mutation)),
        ));
        let encoded = kr_protocol::frame::FrameCodec::new(kr_protocol::frame::StreamKind::Control)
            .encode_message(&frame)
            .map_err(|error| {
                kr_protocol::error::ProtocolError::new(
                    kr_protocol::error::ErrorCode::UnsupportedSchema,
                    error.to_string(),
                )
            })?;
        tokio::io::AsyncWriteExt::write_all(&mut self.stdin, &encoded)
            .await
            .map_err(|error| {
                kr_protocol::error::ProtocolError::new(
                    kr_protocol::error::ErrorCode::ResourceUnavailable,
                    error.to_string(),
                )
            })?;
        tokio::io::AsyncWriteExt::flush(&mut self.stdin)
            .await
            .map_err(|error| {
                kr_protocol::error::ProtocolError::new(
                    kr_protocol::error::ErrorCode::ResourceUnavailable,
                    error.to_string(),
                )
            })?;

        loop {
            let mut prefix = [0_u8; 4];
            tokio::io::AsyncReadExt::read_exact(&mut self.stdout, &mut prefix)
                .await
                .map_err(|error| {
                    kr_protocol::error::ProtocolError::new(
                        kr_protocol::error::ErrorCode::ResourceUnavailable,
                        error.to_string(),
                    )
                })?;
            let len = u32::from_be_bytes(prefix) as usize;
            let mut payload = vec![0_u8; len];
            tokio::io::AsyncReadExt::read_exact(&mut self.stdout, &mut payload)
                .await
                .map_err(|error| {
                    kr_protocol::error::ProtocolError::new(
                        kr_protocol::error::ErrorCode::ResourceUnavailable,
                        error.to_string(),
                    )
                })?;
            let frame: kr_protocol::identity::BridgeFrame = kr_cbor::from_canonical_slice(
                &payload,
                &kr_protocol::frame::StreamKind::Control.cbor_limits(),
            )
            .map_err(|error| {
                kr_protocol::error::ProtocolError::new(
                    kr_protocol::error::ErrorCode::UnsupportedSchema,
                    error.to_string(),
                )
            })?;
            match frame {
                kr_protocol::identity::BridgeFrame::Control(carried) => match *carried {
                    kr_protocol::envelope::ControlFrame::Response(resp)
                        if resp.request_id == request_id =>
                    {
                        return Ok(resp);
                    }
                    _ => continue,
                },
                kr_protocol::identity::BridgeFrame::Refused(err) => return Err(err),
                _ => continue,
            }
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;
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
}
