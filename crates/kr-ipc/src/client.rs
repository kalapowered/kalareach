//! The local client half: connecting, negotiating, verifying and calling.
//!
//! The `kr` command line and the control daemon both reach a worker the same way, so the sequence
//! lives here once rather than twice:
//!
//! 1. Connect to the endpoint. The listener authenticates the caller by peer credentials before it
//!    reads a frame.
//! 2. Negotiate the protocol version.
//! 3. For a worker, challenge it. Thirty-two fresh bytes, checked against the public key in the
//!    descriptor, with every identity field compared to the descriptor as well. Until that
//!    succeeds the endpoint is a path, not a session.
//! 4. Call.
//!
//! A controller additionally answers the worker's own challenge with a generation token, which is
//! what fences the connection that spoke for the previous generation.

use kr_protocol::envelope::{MutationRequest, Outcome, ParamsValue, Request, Response};
use kr_protocol::error::ProtocolError;
use kr_protocol::frame::StreamKind;
use kr_protocol::hello::{PROTOCOL_VERSION, ReceiveLimits};
use kr_protocol::ids::{ActionId, BuildId, RequestId};
use kr_protocol::local::{ControlMessage, LocalClientKind, LocalHello, LocalHelloAck};
use kr_protocol::method::{Method, MethodVersion};
use kr_protocol::scalars::{CanonicalSet, DurationMs, Nullable};
use kr_protocol::worker::{
    ControllerGenerationToken, GenerationAccepted, WorkerDescriptor, WorkerVerifyProof,
};

use crate::endpoint::Connection;
use crate::error::{IpcError, Result};
use crate::framed::{FrameReader, FrameWriter, split};
use crate::paths::Endpoint;
use crate::verify::{check_proof, fresh_challenge};

/// A connected local client.
#[derive(Debug)]
pub struct LocalClient {
    reader: FrameReader,
    writer: FrameWriter,
    acknowledgement: LocalHelloAck,
    generation_challenge: Option<kr_protocol::worker::GenerationChallenge>,
    next_request: u64,
}

impl LocalClient {
    /// Connects to an endpoint and negotiates the protocol version.
    ///
    /// # Errors
    ///
    /// Returns an error when nothing is listening, the peer is refused, or no protocol major is
    /// shared.
    pub async fn connect(
        endpoint: &Endpoint,
        kind: LocalClientKind,
        build_id: BuildId,
    ) -> Result<Self> {
        let connection = Connection::connect(endpoint).await?;
        let (reader, mut writer) = split(connection, StreamKind::Control);
        writer
            .write_message(&ControlMessage::Hello(LocalHello {
                offered_versions: vec![PROTOCOL_VERSION],
                build_id,
                client: kind,
                capabilities: CanonicalSet::new(),
                max_receive: ReceiveLimits::default(),
            }))
            .await?;
        let mut client = Self {
            reader,
            writer,
            acknowledgement: LocalHelloAck {
                selected_version: PROTOCOL_VERSION,
                role: kr_protocol::local::LocalRole::Worker,
                connection_id: kr_protocol::ids::ConnectionId::new(kr_protocol::scalars::Uuid::NIL),
                environment_id: kr_protocol::ids::EnvironmentId::new(
                    kr_protocol::scalars::Uuid::NIL,
                ),
                boot_identity: kr_protocol::identity::BootIdentity {
                    source: kr_protocol::identity::BootIdentitySource::BootTime,
                    value: kr_protocol::scalars::Bytes::new(Vec::new()),
                },
                peer: kr_protocol::local::LocalPeer {
                    uid: kr_protocol::scalars::U64::ZERO,
                    gid: kr_protocol::scalars::U64::ZERO,
                    pid: Nullable::null(),
                },
                action_window_id: kr_protocol::ids::ActionWindowId::new("pending")
                    .expect("a valid window"),
                action_window_expires_at_ms: kr_protocol::scalars::TimestampMs::new(0),
                capabilities: CanonicalSet::new(),
                max_receive: ReceiveLimits::default(),
            },
            generation_challenge: None,
            next_request: 0,
        };
        match client.reader.read_message().await? {
            ControlMessage::HelloAck(acknowledgement) => {
                if acknowledgement.selected_version.major != PROTOCOL_VERSION.major {
                    return Err(IpcError::VersionMismatch {
                        host: PROTOCOL_VERSION.to_string(),
                        offered: acknowledgement.selected_version.to_string(),
                    });
                }
                client.acknowledgement = acknowledgement;
                if kind == LocalClientKind::Controller {
                    // A worker offers its generation challenge as soon as a controller announces
                    // itself, so the nonce is bound to this connection from its first frame. It is
                    // held until the token is presented and used exactly once.
                    match client.reader.read_message().await? {
                        ControlMessage::GenerationChallenge(challenge) => {
                            client.generation_challenge = Some(challenge);
                        }
                        ControlMessage::Response(Response {
                            outcome: Outcome::Error(error),
                            ..
                        }) => {
                            return Err(IpcError::IdentityUnavailable {
                                what: "the worker refused the controller connection",
                                detail: error.to_string(),
                            });
                        }
                        _ => {
                            return Err(IpcError::UnexpectedMessage(
                                "the worker did not offer a generation challenge",
                            ));
                        }
                    }
                }
                Ok(client)
            }
            ControlMessage::Response(Response {
                outcome: Outcome::Error(error),
                ..
            }) => Err(IpcError::IdentityUnavailable {
                what: "the host refused the connection",
                detail: error.to_string(),
            }),
            _ => Err(IpcError::UnexpectedMessage(
                "the host did not acknowledge the hello",
            )),
        }
    }

    /// Returns what the host said about this connection.
    #[must_use]
    pub const fn acknowledgement(&self) -> &LocalHelloAck {
        &self.acknowledgement
    }

    /// Proves the worker behind this endpoint is the one the descriptor names.
    ///
    /// # Errors
    ///
    /// Returns an error when the worker does not answer, the signature does not verify, or an
    /// identity field disagrees with the descriptor.
    pub async fn verify_worker(
        &mut self,
        descriptor: &WorkerDescriptor,
    ) -> Result<WorkerVerifyProof> {
        let challenge = fresh_challenge().map_err(IpcError::from)?;
        self.writer
            .write_message(&ControlMessage::VerifyChallenge(challenge))
            .await?;
        let ControlMessage::VerifyProof(proof) = self.reader.read_message().await? else {
            return Err(IpcError::UnexpectedMessage(
                "the worker did not answer the challenge",
            ));
        };
        check_proof(descriptor, &challenge, &proof).map_err(IpcError::from)?;
        Ok(proof)
    }

    /// Answers the worker's generation challenge.
    ///
    /// # Errors
    ///
    /// Returns an error when the worker does not challenge, or refuses the token.
    pub async fn present_generation(
        &mut self,
        sign: impl FnOnce(&kr_protocol::scalars::Nonce256) -> Result<ControllerGenerationToken>,
    ) -> Result<GenerationAccepted> {
        let challenge = self
            .generation_challenge
            .take()
            .ok_or(IpcError::UnexpectedMessage(
                "the worker did not issue a generation challenge",
            ))?;
        let token = sign(&challenge.nonce)?;
        self.writer
            .write_message(&ControlMessage::GenerationToken(Box::new(token)))
            .await?;
        match self.reader.read_message().await? {
            ControlMessage::GenerationAccepted(accepted) => Ok(accepted),
            ControlMessage::Response(Response {
                outcome: Outcome::Error(error),
                ..
            }) => Err(IpcError::IdentityUnavailable {
                what: "the worker refused the controller generation",
                detail: error.to_string(),
            }),
            _ => Err(IpcError::UnexpectedMessage(
                "the worker did not answer the generation token",
            )),
        }
    }

    /// Calls a read method.
    ///
    /// # Errors
    ///
    /// Returns the host's error, or a transport failure.
    pub async fn request<T: serde::Serialize + ?Sized>(
        &mut self,
        method: Method,
        params: &T,
    ) -> Result<std::result::Result<ParamsValue, ProtocolError>> {
        let request_id = self.next_id();
        let params = ParamsValue::from_typed(params)
            .map_err(|error| IpcError::Frame(kr_protocol::frame::FrameError::Cbor(error)))?;
        self.writer
            .write_message(&ControlMessage::Request(Request {
                request_id,
                method: method.into(),
                method_version: MethodVersion::V1,
                params,
            }))
            .await?;
        self.await_response(request_id).await
    }

    /// Calls a mutation.
    ///
    /// The action identifier is the durable operation identity. Retrying the same identifier with
    /// the same payload returns the same result rather than performing the operation twice.
    ///
    /// # Errors
    ///
    /// Returns the host's error, or a transport failure.
    pub async fn mutate<T: serde::Serialize + ?Sized>(
        &mut self,
        method: Method,
        action_id: ActionId,
        target: kr_protocol::envelope::ActionTarget,
        params: &T,
    ) -> Result<std::result::Result<ParamsValue, ProtocolError>> {
        let request_id = self.next_id();
        let params = ParamsValue::from_typed(params)
            .map_err(|error| IpcError::Frame(kr_protocol::frame::FrameError::Cbor(error)))?;
        self.writer
            .write_message(&ControlMessage::Mutation(MutationRequest {
                request_id,
                method: method.into(),
                method_version: MethodVersion::V1,
                action_id,
                grant_id: Nullable::null(),
                target,
                expected: ParamsValue::empty(),
                action_window_id: self.acknowledgement.action_window_id.clone(),
                requested_ttl_ms: DurationMs::new(kr_protocol::limits::DEFAULT_MUTATION_TTL.get()),
                params,
            }))
            .await?;
        self.await_response(request_id).await
    }

    /// Reads the next message, which may be a notification.
    ///
    /// # Errors
    ///
    /// Returns a transport failure.
    pub async fn recv(&mut self) -> Result<ControlMessage> {
        self.reader.read_message().await
    }

    /// Returns the writing half, for a caller that streams input.
    pub const fn writer(&mut self) -> &mut FrameWriter {
        &mut self.writer
    }

    /// Splits the client into its two halves.
    #[must_use]
    pub fn into_halves(self) -> (FrameReader, FrameWriter, LocalHelloAck) {
        (self.reader, self.writer, self.acknowledgement)
    }

    async fn await_response(
        &mut self,
        request_id: RequestId,
    ) -> Result<std::result::Result<ParamsValue, ProtocolError>> {
        loop {
            match self.reader.read_message().await? {
                ControlMessage::Response(response) if response.request_id == request_id => {
                    return Ok(match response.outcome {
                        Outcome::Ok(value) => Ok(value),
                        Outcome::Error(error) => Err(error),
                    });
                }
                // A notification that arrives while a call is outstanding is not an answer to it.
                ControlMessage::Notification(_) => {}
                _ => {
                    return Err(IpcError::UnexpectedMessage(
                        "the host answered something other than this request",
                    ));
                }
            }
        }
    }

    fn next_id(&mut self) -> RequestId {
        self.next_request += 1;
        RequestId::new(self.next_request)
    }
}
